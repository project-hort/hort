//! Tests for [`ProvenanceMisrejectionRepairUseCase`].
//!
//! The negative tests are the important ones and are written first-class:
//! a repair that can reach a real rejection is worse than no repair, so
//! every shape that *looks* repairable but is not gets its own test
//! naming what it proves.
//!
//! Every fixture drives the **real** listing → predicate → domain →
//! lifecycle path; only the ports are mocked. The queue mock applies no
//! filtering of its own, so a test can hand the use case rows the real
//! listing would never produce (e.g. a `Released` artifact) and prove the
//! decision does not lean on the listing.

use super::*;

use chrono::{DateTime, Duration};
use hort_domain::entities::artifact::Artifact;
use hort_domain::error::DomainError;
use hort_domain::events::{
    ArtifactQuarantined, PersistedEvent, ProvenanceRejected, ProvenanceVerified, RejectionReason,
};
use hort_domain::ports::curation_queue_repository::CurationQueueEntry;
use hort_domain::ports::provenance::{ProvenanceRejectReason, SignerIdentity};
use hort_domain::types::ContentHash;

use crate::use_cases::quarantine_use_case::QuarantineUseCase;
use crate::use_cases::test_support::{
    api_actor, persisted_artifact_rejected, persisted_scan_completed, queue_entry_for,
    sample_artifact, MockArtifactLifecycle, MockArtifactRepository, MockContentReferenceIndex,
    MockCurationQueueRepository, MockEventStore, MockJobsRepository,
    MockPolicyProjectionRepository, MockRepositoryRepository, MockStoragePort,
};

const VALID_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

struct Fixture {
    uc: ProvenanceMisrejectionRepairUseCase,
    events: Arc<MockEventStore>,
    artifacts: Arc<MockArtifactRepository>,
    lifecycle: Arc<MockArtifactLifecycle>,
    queue: Arc<MockCurationQueueRepository>,
}

fn build() -> Fixture {
    let events = Arc::new(MockEventStore::new());
    let artifacts = Arc::new(MockArtifactRepository::new());
    let lifecycle = Arc::new(MockArtifactLifecycle::new(artifacts.clone()));
    let queue = Arc::new(MockCurationQueueRepository::new());
    let uc = ProvenanceMisrejectionRepairUseCase::new(
        crate::event_store_publisher::wrap_for_test(events.clone()),
        artifacts.clone(),
        lifecycle.clone(),
        queue.clone(),
    );
    Fixture {
        uc,
        events,
        artifacts,
        lifecycle,
        queue,
    }
}

// ---------------------------------------------------------------------------
// Stream-event builders
// ---------------------------------------------------------------------------

fn persisted(artifact_id: Uuid, position: u64, event: DomainEvent) -> PersistedEvent {
    PersistedEvent {
        event_id: Uuid::new_v4(),
        stream_id: StreamId::artifact(artifact_id),
        stream_position: position,
        global_position: position,
        event,
        correlation_id: Uuid::new_v4(),
        causation_id: None,
        actor: hort_domain::events::system_actor(),
        event_version: 1,
        stored_at: Utc::now(),
    }
}

fn quarantined(artifact_id: Uuid, position: u64, anchor: DateTime<Utc>) -> PersistedEvent {
    persisted(
        artifact_id,
        position,
        DomainEvent::ArtifactQuarantined(ArtifactQuarantined {
            artifact_id,
            quarantine_window_start: anchor,
        }),
    )
}

fn verified(artifact_id: Uuid, position: u64) -> PersistedEvent {
    persisted(
        artifact_id,
        position,
        DomainEvent::ProvenanceVerified(ProvenanceVerified {
            artifact_id,
            content_hash: VALID_SHA256.parse::<ContentHash>().unwrap(),
            backend: "cosign".into(),
            signer: SignerIdentity {
                issuer: "https://token.actions.githubusercontent.com".into(),
                san: "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main"
                    .into(),
            },
            predicate_type: None,
            cascaded_from: None,
        }),
    )
}

fn provenance_rejected(artifact_id: Uuid, position: u64) -> PersistedEvent {
    persisted(
        artifact_id,
        position,
        DomainEvent::ProvenanceRejected(ProvenanceRejected {
            artifact_id,
            content_hash: VALID_SHA256.parse::<ContentHash>().unwrap(),
            backend: "cosign".into(),
            reason: ProvenanceRejectReason::UntrustedIdentity,
        }),
    )
}

// ---------------------------------------------------------------------------
// Seeding
// ---------------------------------------------------------------------------

/// Seed one artifact (repository row + stream) and return it together
/// with the curation-queue row the listing would produce for it. The
/// caller decides which rows reach the use case via
/// [`MockCurationQueueRepository::set_entries`].
///
/// `stream` receives `(artifact_id, anchor)`; the anchor is two hours in
/// the past, matching the historical population (long past its
/// observation deadline).
fn seed(
    f: &Fixture,
    status: QuarantineStatus,
    stream: impl FnOnce(Uuid, DateTime<Utc>) -> Vec<PersistedEvent>,
) -> (Artifact, CurationQueueEntry) {
    let mut artifact = sample_artifact(status);
    let anchor = Utc::now() - Duration::hours(2);
    artifact.quarantine_window_start = Some(anchor);
    // The pre-amendment provenance arm left the column `None` — that is
    // exactly why `re_evaluate` refuses these artifacts.
    artifact.rejection_reason = None;
    let id = artifact.id;
    f.artifacts.insert(artifact.clone());
    f.events
        .set_stream(&StreamId::artifact(id), stream(id, anchor));
    let entry = queue_entry_for(&artifact, "oci-hosted");
    (artifact, entry)
}

/// The exact three-conjunct state: `Rejected`, **no** `ArtifactRejected`
/// on the stream, and a `ProvenanceVerified` that contradicts the
/// rejection — the signature that landed a second after the verdict ran.
fn seed_stranded(f: &Fixture) -> (Artifact, CurationQueueEntry) {
    seed(f, QuarantineStatus::Rejected, |id, anchor| {
        vec![
            quarantined(id, 0, anchor),
            persisted_scan_completed(id, 0, 1),
            verified(id, 2),
        ]
    })
}

fn repair_request(dry_run: bool) -> RepairRequest {
    RepairRequest {
        dry_run,
        ..RepairRequest::default()
    }
}

// ---------------------------------------------------------------------------
// The positive path
// ---------------------------------------------------------------------------

/// The whole point of this path: an artifact in the exact three-conjunct
/// state is repaired, the repair is recorded as **events** (not a status
/// write), and the ordinary release sweep then releases it.
#[tokio::test]
async fn repairs_the_stranded_state_by_event_and_the_ordinary_sweep_then_releases_it() {
    let f = build();
    let (artifact, entry) = seed_stranded(&f);
    let anchor = artifact.quarantine_window_start.unwrap();
    f.queue.set_entries(vec![entry]);

    let report =
        f.uc.run(repair_request(false), api_actor())
            .await
            .expect("the repair must not itself error");

    assert!(!report.dry_run);
    assert_eq!(report.scanned, 1);
    assert_eq!(report.affected.len(), 1);
    assert_eq!(report.affected[0].artifact_id, artifact.id);
    assert_eq!(report.affected[0].repository_key, "oci-hosted");
    assert!(report.failed.is_empty());

    // The record is the event batch, not a status UPDATE: one atomic
    // commit carrying the audit event and the transition event.
    let transitions = f.lifecycle.committed_transitions();
    assert_eq!(transitions.len(), 1, "exactly one transition committed");
    let (committed, append, _) = &transitions[0];
    assert_eq!(committed.quarantine_status, QuarantineStatus::Quarantined);
    assert_eq!(committed.rejection_reason, None);
    assert_eq!(append.events.len(), 2);
    match &append.events[0].event {
        DomainEvent::ArtifactReEvaluated(e) => {
            assert_eq!(e.trigger, ReEvaluationTrigger::ProvenanceMisrejectionRepair);
            assert_eq!(e.previous_status, QuarantineStatus::Rejected);
            assert_eq!(e.new_status, QuarantineStatus::Quarantined);
            assert_eq!(e.policy_id, NO_POLICY, "no policy was consulted");
        }
        other => panic!("expected ArtifactReEvaluated first, got {other:?}"),
    }
    match &append.events[1].event {
        DomainEvent::ArtifactQuarantined(e) => {
            // Restored, not restarted — the sweep must see an
            // already-elapsed window.
            assert_eq!(e.quarantine_window_start, anchor);
        }
        other => panic!("expected ArtifactQuarantined second, got {other:?}"),
    }
    // The operator's identity rides the envelope, not a payload field.
    assert!(matches!(append.actor, Actor::Api(_)));

    // The score projection is told a Rejected artifact became
    // Quarantined, in the same commit.
    let deltas = f.lifecycle.score_deltas();
    assert_eq!(deltas.len(), 1);
    assert_eq!(deltas[0].0, artifact.repository_id);
    assert_eq!(deltas[0].1.rejected_delta, -1);
    assert_eq!(deltas[0].1.quarantined_delta, 1);

    // --- and now the ordinary sweep takes over -------------------------
    //
    // `MockArtifactLifecycle` writes the repaired artifact back to the
    // artifact repo, so the sweep reads the real post-repair row. The
    // stream already carries the `ProvenanceVerified` the release gate
    // resolves `Cleared` from, plus the clean scan that is the ADR 0007
    // release authority.
    let quarantine_uc = QuarantineUseCase::new(
        f.artifacts.clone(),
        crate::event_store_publisher::wrap_for_test(f.events.clone()),
        Arc::new(MockArtifactLifecycle::new(f.artifacts.clone())),
        Arc::new(MockRepositoryRepository::new()),
        Arc::new(MockPolicyProjectionRepository::new()),
        Arc::new(MockContentReferenceIndex::new()),
        Arc::new(MockStoragePort::new()),
        Arc::new(MockJobsRepository::new()),
    );
    let summary = quarantine_uc
        .release_expired(vec![artifact.id])
        .await
        .expect("release_expired must not error");
    assert_eq!(
        summary.released,
        vec![artifact.id],
        "the repaired artifact must be released by the ordinary sweep — that is what \
         makes the repair an exit rather than a state change to nowhere"
    );
}

/// The scan is narrowed exactly as claimed: `status = Rejected`, the
/// caller's repository filter, the clamped limit, and **no**
/// `rejection_reason_kind` filter (the rows this repairs carry no kind,
/// because the discriminator is projected from the very event conjunct 2
/// asserts is absent).
#[tokio::test]
async fn scan_asks_the_listing_for_rejected_rows_only() {
    let f = build();
    let repo = Uuid::new_v4();
    let _ =
        f.uc.run(
            RepairRequest {
                repository_id: Some(repo),
                limit: 5_000,
                dry_run: true,
            },
            api_actor(),
        )
        .await
        .expect("Ok");
    let filters = f.queue.recorded_filters();
    assert_eq!(filters.len(), 1);
    assert_eq!(filters[0].status, Some(QuarantineStatus::Rejected));
    assert_eq!(filters[0].repository_id, Some(repo));
    assert_eq!(filters[0].rejection_reason_kind, None);
    assert_eq!(
        filters[0].limit, MAX_SCAN_LIMIT,
        "an over-large limit is clamped, never passed through"
    );
}

// ---------------------------------------------------------------------------
// The dry run
// ---------------------------------------------------------------------------

/// A dry run reports the affected set and writes **nothing** — no event,
/// no transition, no score delta — and the artifact row is untouched.
#[tokio::test]
async fn dry_run_reports_without_mutating() {
    let f = build();
    let (artifact, entry) = seed_stranded(&f);
    f.queue.set_entries(vec![entry]);

    let report =
        f.uc.run(repair_request(true), api_actor())
            .await
            .expect("Ok");

    assert!(report.dry_run);
    assert_eq!(report.scanned, 1);
    assert_eq!(
        report
            .affected
            .iter()
            .map(|a| a.artifact_id)
            .collect::<Vec<_>>(),
        vec![artifact.id],
        "a dry run still names the exact set a real run would touch"
    );
    assert!(
        f.lifecycle.committed_transitions().is_empty(),
        "a dry run must commit no transition"
    );
    assert!(
        f.events.appended_batches().is_empty(),
        "a dry run must append no event"
    );
    assert_eq!(
        f.artifacts.get(artifact.id).unwrap().quarantine_status,
        QuarantineStatus::Rejected,
        "a dry run must leave the projection row exactly as it found it"
    );
}

/// The dry run and the real run agree on the affected set — a report the
/// real run would not honour is worse than no report.
#[tokio::test]
async fn dry_run_and_real_run_agree_on_the_affected_set() {
    let f = build();
    let (artifact, entry) = seed_stranded(&f);
    f.queue.set_entries(vec![entry]);

    let dry = f.uc.run(repair_request(true), api_actor()).await.unwrap();
    let real = f.uc.run(repair_request(false), api_actor()).await.unwrap();

    assert_eq!(
        dry.affected
            .iter()
            .map(|a| a.artifact_id)
            .collect::<Vec<_>>(),
        real.affected
            .iter()
            .map(|a| a.artifact_id)
            .collect::<Vec<_>>()
    );
    assert_eq!(real.affected[0].artifact_id, artifact.id);
}

// ---------------------------------------------------------------------------
// The negative tests — what this must NEVER touch
// ---------------------------------------------------------------------------

/// **A genuinely disproven artifact.** Present-but-invalid signature:
/// since the amendment it carries BOTH `ProvenanceRejected` and the
/// `ArtifactRejected` companion. Conjunct 2 fails. This is the test that
/// matters most — a repair that can reach a real rejection is worse than
/// no repair.
#[tokio::test]
async fn leaves_a_disproof_rejected_artifact_untouched() {
    let f = build();
    let (artifact, entry) = seed(&f, QuarantineStatus::Rejected, |id, anchor| {
        vec![
            quarantined(id, 0, anchor),
            provenance_rejected(id, 1),
            persisted_artifact_rejected(id, RejectionReason::Provenance, 2),
        ]
    });
    f.queue.set_entries(vec![entry]);

    let report = f.uc.run(repair_request(false), api_actor()).await.unwrap();

    assert_eq!(report.scanned, 1);
    assert!(
        report.affected.is_empty(),
        "a forged signature is a statement about the artifact and stays terminal"
    );
    assert!(report.failed.is_empty(), "not matching is not a failure");
    assert!(f.lifecycle.committed_transitions().is_empty());
    assert_eq!(
        f.artifacts.get(artifact.id).unwrap().quarantine_status,
        QuarantineStatus::Rejected
    );
}

/// The same shape with a `ProvenanceVerified` ALSO on the stream (a
/// constituent cleared by cascade before its own signature was later
/// disproven). Conjunct 3 holds; conjunct 2 still refuses. This pins that
/// the conjuncts are an AND, not a "verified wins".
#[tokio::test]
async fn leaves_a_disproof_rejected_artifact_untouched_even_with_a_verified_event() {
    let f = build();
    let (artifact, entry) = seed(&f, QuarantineStatus::Rejected, |id, anchor| {
        vec![
            quarantined(id, 0, anchor),
            verified(id, 1),
            provenance_rejected(id, 2),
            persisted_artifact_rejected(id, RejectionReason::Provenance, 3),
        ]
    });
    f.queue.set_entries(vec![entry]);

    let report = f.uc.run(repair_request(false), api_actor()).await.unwrap();
    assert!(report.affected.is_empty());
    assert!(f.lifecycle.committed_transitions().is_empty());
    assert_eq!(
        f.artifacts.get(artifact.id).unwrap().quarantine_status,
        QuarantineStatus::Rejected
    );
}

/// **A CAS-corruption tombstone.** The one shape that passes every
/// `ArtifactRejected`-shaped test *and* carries a `ProvenanceVerified`:
/// `tombstone_from_corruption` drives `Rejected` while appending only
/// `ArtifactCorrupted`, so an `ArtifactRejected`-only conjunct 2 would
/// hand bytes that do not match their content hash back to the release
/// sweep. Refused.
#[tokio::test]
async fn leaves_a_corruption_tombstoned_artifact_untouched() {
    let f = build();
    let (artifact, entry) = seed(&f, QuarantineStatus::Rejected, |id, anchor| {
        vec![
            quarantined(id, 0, anchor),
            // Verified while intact, then found corrupt by the CAS scrub.
            verified(id, 1),
            persisted(
                id,
                2,
                DomainEvent::ArtifactCorrupted(hort_domain::events::ArtifactCorrupted {
                    artifact_id: id,
                    computed_hash: VALID_SHA256.parse::<ContentHash>().unwrap(),
                    expected_hash: VALID_SHA256.parse::<ContentHash>().unwrap(),
                    detected_at: Utc::now(),
                }),
            ),
        ]
    });
    f.queue.set_entries(vec![entry]);

    let report = f.uc.run(repair_request(false), api_actor()).await.unwrap();
    assert!(
        report.affected.is_empty(),
        "corrupt bytes must never be handed back to the release sweep"
    );
    assert!(report.failed.is_empty());
    assert!(f.lifecycle.committed_transitions().is_empty());
    assert_eq!(
        f.artifacts.get(artifact.id).unwrap().quarantine_status,
        QuarantineStatus::Rejected
    );
}

/// **A scan-rejected artifact.** Carries `ArtifactRejected{Scanner}`;
/// conjunct 2 fails. Its exit is `re_evaluate`, which is exactly the
/// check this path must not duplicate.
#[tokio::test]
async fn leaves_a_scan_rejected_artifact_untouched() {
    let f = build();
    let (artifact, entry) = seed(&f, QuarantineStatus::Rejected, |id, anchor| {
        vec![
            quarantined(id, 0, anchor),
            persisted_scan_completed(id, 3, 1),
            persisted_artifact_rejected(id, RejectionReason::Scanner, 2),
            // Even with a verified signature on the stream: the scan
            // verdict is a different axis and this path must not clear it.
            verified(id, 3),
        ]
    });
    f.queue.set_entries(vec![entry]);

    let report = f.uc.run(repair_request(false), api_actor()).await.unwrap();
    assert!(report.affected.is_empty());
    assert!(f.lifecycle.committed_transitions().is_empty());
    assert_eq!(
        f.artifacts.get(artifact.id).unwrap().quarantine_status,
        QuarantineStatus::Rejected
    );
}

/// **A never-signed artifact.** Since the amendment it is `Quarantined`, held
/// indefinitely — the population the amendment created on purpose. Even
/// if the listing hands it over (it never would), conjunct 1 refuses it
/// at the domain's source-state guard, so an unsigned artifact can never
/// be walked back into the release path by this call.
#[tokio::test]
async fn leaves_a_never_signed_held_artifact_untouched() {
    let f = build();
    let (artifact, entry) = seed(&f, QuarantineStatus::Quarantined, |id, anchor| {
        vec![quarantined(id, 0, anchor)]
    });
    f.queue.set_entries(vec![entry]);

    let report = f.uc.run(repair_request(false), api_actor()).await.unwrap();
    assert!(report.affected.is_empty());
    assert!(f.lifecycle.committed_transitions().is_empty());
    assert_eq!(
        f.artifacts.get(artifact.id).unwrap().quarantine_status,
        QuarantineStatus::Quarantined
    );
}

/// **A `Rejected` artifact with no terminal event and no
/// `ProvenanceVerified`.** The shape that passes conjunct 2 but fails
/// conjunct 3: nothing on its stream contradicts the rejection, so
/// repairing it would release an artifact that really was never signed.
#[tokio::test]
async fn leaves_a_rejection_with_no_contradicting_evidence_untouched() {
    let f = build();
    let (artifact, entry) = seed(&f, QuarantineStatus::Rejected, |id, anchor| {
        vec![
            quarantined(id, 0, anchor),
            persisted_scan_completed(id, 0, 1),
        ]
    });
    f.queue.set_entries(vec![entry]);

    let report = f.uc.run(repair_request(false), api_actor()).await.unwrap();
    assert!(
        report.affected.is_empty(),
        "without a ProvenanceVerified there is no contradiction to act on"
    );
    assert!(f.lifecycle.committed_transitions().is_empty());
    assert_eq!(
        f.artifacts.get(artifact.id).unwrap().quarantine_status,
        QuarantineStatus::Rejected
    );
}

/// **A released artifact.** Refused by the source-state guard.
#[tokio::test]
async fn leaves_a_released_artifact_untouched() {
    let f = build();
    let (artifact, entry) = seed(&f, QuarantineStatus::Released, |id, _anchor| {
        vec![verified(id, 0)]
    });
    f.queue.set_entries(vec![entry]);

    let report = f.uc.run(repair_request(false), api_actor()).await.unwrap();
    assert!(report.affected.is_empty());
    assert!(report.failed.is_empty());
    assert!(f.lifecycle.committed_transitions().is_empty());
    assert_eq!(
        f.artifacts.get(artifact.id).unwrap().quarantine_status,
        QuarantineStatus::Released
    );
}

/// A mixed batch: only the stranded artifact moves; its three neighbours
/// are examined and left alone in the same call.
#[tokio::test]
async fn a_mixed_batch_repairs_only_the_stranded_artifact() {
    let f = build();
    let (stranded, stranded_entry) = seed_stranded(&f);
    let (_, disproof) = seed(&f, QuarantineStatus::Rejected, |id, anchor| {
        vec![
            quarantined(id, 0, anchor),
            provenance_rejected(id, 1),
            persisted_artifact_rejected(id, RejectionReason::Provenance, 2),
        ]
    });
    let (_, scan) = seed(&f, QuarantineStatus::Rejected, |id, anchor| {
        vec![
            quarantined(id, 0, anchor),
            persisted_artifact_rejected(id, RejectionReason::Scanner, 1),
        ]
    });
    let (_, unsigned) = seed(&f, QuarantineStatus::Rejected, |id, anchor| {
        vec![quarantined(id, 0, anchor)]
    });
    f.queue
        .set_entries(vec![disproof, stranded_entry, scan, unsigned]);

    let report = f.uc.run(repair_request(false), api_actor()).await.unwrap();

    assert_eq!(report.scanned, 4);
    assert_eq!(
        report
            .affected
            .iter()
            .map(|a| a.artifact_id)
            .collect::<Vec<_>>(),
        vec![stranded.id]
    );
    assert_eq!(f.lifecycle.committed_transitions().len(), 1);
}

// ---------------------------------------------------------------------------
// Bounds and failure handling
// ---------------------------------------------------------------------------

/// The scan bound is reported, never applied silently: a listing that
/// fills its limit sets `scan_cap_hit` so the operator knows to re-run.
#[tokio::test]
async fn a_full_listing_reports_the_scan_cap() {
    let f = build();
    let (_, a) = seed(&f, QuarantineStatus::Rejected, |id, anchor| {
        vec![quarantined(id, 0, anchor)]
    });
    let (_, b) = seed(&f, QuarantineStatus::Rejected, |id, anchor| {
        vec![quarantined(id, 0, anchor)]
    });
    f.queue.set_entries(vec![a, b]);

    let report =
        f.uc.run(
            RepairRequest {
                repository_id: None,
                limit: 2,
                dry_run: true,
            },
            api_actor(),
        )
        .await
        .unwrap();
    assert!(report.scan_cap_hit);

    // One row short of the limit: not capped.
    let report =
        f.uc.run(
            RepairRequest {
                repository_id: None,
                limit: 3,
                dry_run: true,
            },
            api_actor(),
        )
        .await
        .unwrap();
    assert!(!report.scan_cap_hit);
}

/// A zero limit is clamped up rather than silently scanning nothing.
#[tokio::test]
async fn a_zero_limit_is_clamped_to_one() {
    let f = build();
    let _ =
        f.uc.run(
            RepairRequest {
                repository_id: None,
                limit: 0,
                dry_run: true,
            },
            api_actor(),
        )
        .await
        .unwrap();
    assert_eq!(f.queue.recorded_filters()[0].limit, 1);
}

/// Continue-on-error: a per-artifact failure lands in `failed` and the
/// rest of the batch still runs. Successful repairs are not rolled back —
/// events are immutable.
#[tokio::test]
async fn a_per_artifact_failure_does_not_abort_the_batch() {
    let f = build();
    // A listing row whose artifact row was never seeded, so `find_by_id`
    // misses — the listing and the projection disagreeing (a row deleted
    // between the scan and the repair) is exactly the transient this must
    // survive rather than abort on.
    let mut missing = queue_entry_for(&sample_artifact(QuarantineStatus::Rejected), "gone");
    missing.artifact_id = Uuid::new_v4();
    let (stranded, stranded_entry) = seed_stranded(&f);
    f.queue.set_entries(vec![missing.clone(), stranded_entry]);

    let report = f.uc.run(repair_request(false), api_actor()).await.unwrap();

    assert_eq!(report.failed.len(), 1);
    assert_eq!(report.failed[0].0, missing.artifact_id);
    assert_eq!(
        report
            .affected
            .iter()
            .map(|a| a.artifact_id)
            .collect::<Vec<_>>(),
        vec![stranded.id],
        "the rest of the batch still runs"
    );
}

/// A listing failure is an error, not a silent empty report — an empty
/// affected set must never be indistinguishable from "the query failed".
#[tokio::test]
async fn a_listing_failure_propagates() {
    let f = build();
    f.queue
        .fail_next_list(DomainError::Invariant("queue unavailable".into()));
    let err =
        f.uc.run(repair_request(true), api_actor())
            .await
            .expect_err("a failed listing must surface");
    assert!(err.to_string().contains("queue unavailable"));
}

/// A stream-read failure for one artifact is a per-artifact failure, not
/// a silent skip: a repairable artifact must never be dropped from the
/// report because a read failed.
#[tokio::test]
async fn a_stream_read_failure_is_reported_per_artifact() {
    let f = build();
    let (_, entry) = seed_stranded(&f);
    f.queue.set_entries(vec![entry.clone()]);
    f.events
        .fail_next_read_stream(DomainError::Invariant("event store down".into()));

    let report = f.uc.run(repair_request(true), api_actor()).await.unwrap();
    assert!(report.affected.is_empty());
    assert_eq!(report.failed.len(), 1);
    assert_eq!(report.failed[0].0, entry.artifact_id);
    assert!(report.failed[0].1.contains("event store down"));
}

/// The **clearance** read failing is reported too, not read as "no
/// `ProvenanceVerified`". Conjunct 3 is resolved by a second stream read
/// (through the shared release-gate helper); if an infrastructure failure
/// there were treated as "not cleared", a repairable artifact would be
/// dropped from the report with nothing said about it.
#[tokio::test]
async fn a_clearance_read_failure_is_reported_not_read_as_no_evidence() {
    let f = build();
    let (_, entry) = seed_stranded(&f);
    f.queue.set_entries(vec![entry.clone()]);
    // Call 0 is the terminal-event read; call 1 is the clearance read.
    f.events
        .fail_read_stream_at(1, DomainError::Invariant("clearance read failed".into()));

    let report = f.uc.run(repair_request(true), api_actor()).await.unwrap();
    assert!(report.affected.is_empty());
    assert_eq!(report.failed.len(), 1);
    assert_eq!(report.failed[0].0, entry.artifact_id);
    assert!(report.failed[0].1.contains("clearance read failed"));
}

/// An empty scan is a legitimate, reportable outcome — the expected
/// steady state once the population has been drained.
#[tokio::test]
async fn an_empty_population_reports_nothing_to_do() {
    let f = build();
    let report = f.uc.run(repair_request(false), api_actor()).await.unwrap();
    assert_eq!(report.scanned, 0);
    assert!(report.affected.is_empty());
    assert!(report.failed.is_empty());
    assert!(!report.scan_cap_hit);
    assert!(f.lifecycle.committed_transitions().is_empty());
}

/// Idempotence: a second run finds nothing, because the first one moved
/// the artifact out of `Rejected` (and the listing, in production, would
/// no longer return it at all — here the stale row is still fed in and
/// the source-state guard refuses it).
#[tokio::test]
async fn a_second_run_is_a_no_op() {
    let f = build();
    let (_, entry) = seed_stranded(&f);
    f.queue.set_entries(vec![entry]);

    let first = f.uc.run(repair_request(false), api_actor()).await.unwrap();
    assert_eq!(first.affected.len(), 1);

    let second = f.uc.run(repair_request(false), api_actor()).await.unwrap();
    assert!(second.affected.is_empty());
    assert!(second.failed.is_empty());
    assert_eq!(
        f.lifecycle.committed_transitions().len(),
        1,
        "no second append"
    );
}

/// [`RepairRequest`]'s default is the safe one: report, do not mutate.
#[test]
fn the_request_default_is_a_dry_run() {
    let r = RepairRequest::default();
    assert!(r.dry_run);
    assert_eq!(r.limit, DEFAULT_SCAN_LIMIT);
    assert_eq!(r.repository_id, None);
}
