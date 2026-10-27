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
use hort_domain::entities::scan_policy::{
    CompositeVerdictMode, NegligibleAction, ScanEnforcement, ScanPolicyProjection,
    SeverityThreshold,
};
use hort_domain::error::DomainError;
use hort_domain::events::PolicyScope;
use hort_domain::events::{
    ArtifactQuarantined, PersistedEvent, ProvenanceRejected, ProvenanceVerified, RejectionReason,
    StreamId,
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

/// A `ProvenanceRejected` carrying `reason`. The reason is a parameter
/// because conjunct 3's second arm keys on exactly it: `Unsigned` is the
/// one verdict ADR 0039 D1 forbids from being terminal, every other
/// reason is a positive disproof that may be.
fn provenance_rejected(
    artifact_id: Uuid,
    position: u64,
    reason: ProvenanceRejectReason,
) -> PersistedEvent {
    persisted(
        artifact_id,
        position,
        DomainEvent::ProvenanceRejected(ProvenanceRejected {
            artifact_id,
            content_hash: VALID_SHA256.parse::<ContentHash>().unwrap(),
            backend: "cosign".into(),
            reason,
        }),
    )
}

/// The `backend = "(policy)"` shape the pre-D1 `Required`-mode policy
/// mapping wrote: an `Unsigned` rejection that no verifier produced, with
/// no `ArtifactRejected` companion because the provenance axis did not
/// append one yet. This is the stranded population's actual stream.
fn policy_unsigned_rejected(artifact_id: Uuid, position: u64) -> PersistedEvent {
    persisted(
        artifact_id,
        position,
        DomainEvent::ProvenanceRejected(ProvenanceRejected {
            artifact_id,
            content_hash: VALID_SHA256.parse::<ContentHash>().unwrap(),
            backend: "(policy)".into(),
            reason: ProvenanceRejectReason::Unsigned,
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

/// The **second** stranded population: `Rejected`, no `ArtifactRejected`
/// on the stream, **no `ProvenanceVerified` and none ever coming**, and
/// one `ProvenanceRejected{Unsigned}` from the removed policy mapping.
/// The measured shape of the six rows a cosign signature's own
/// `application/vnd.oci.empty.v1+json` config left behind.
fn seed_never_terminal(f: &Fixture) -> (Artifact, CurationQueueEntry) {
    seed(f, QuarantineStatus::Rejected, |id, anchor| {
        vec![
            quarantined(id, 0, anchor),
            persisted_scan_completed(id, 0, 1),
            policy_unsigned_rejected(id, 2),
        ]
    })
}

/// A policy projection repository holding one `provenance_mode:
/// required` policy scoped to `repository_id`.
///
/// Needed wherever a test asserts what the **sweep** does with a
/// repaired artifact: the sweep resolves the provenance leg from the
/// live policy, and an empty projection repository resolves to the
/// default `VerifyIfPresent` ⇒ `NotRequired`, which clears the timer arm
/// for any artifact at all. Only a `Required` repository asks the
/// question "is this artifact verified?", so only a `Required`
/// repository can show the hold.
///
/// `quarantine_duration_secs: 0` keeps the observation window elapsed on
/// the two-hour-old anchor [`seed`] uses, so the candidate is past its
/// deadline exactly as the real sweep's candidacy filter requires.
fn required_provenance_projections(repository_id: Uuid) -> Arc<MockPolicyProjectionRepository> {
    let projections = Arc::new(MockPolicyProjectionRepository::new());
    projections.insert(ScanPolicyProjection {
        policy_id: Uuid::new_v4(),
        name: format!("required-provenance-{}", Uuid::new_v4()),
        scope: PolicyScope::Repository(repository_id),
        severity_threshold: SeverityThreshold::Critical,
        quarantine_duration_secs: 0,
        require_approval: false,
        provenance_mode: ProvenanceMode::Required,
        provenance_backends: vec!["cosign".to_string()],
        provenance_identities: Vec::new(),
        max_artifact_age_secs: None,
        license_policy: serde_json::Value::Null,
        archived: false,
        scan_backends: vec!["trivy".to_string()],
        rescan_interval_hours: 24,
        negligible_action: NegligibleAction::Ignore,
        enforcement: ScanEnforcement::Reject,
        composite_verdict_mode: CompositeVerdictMode::Observed,
        stream_version: 0,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    projections
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
    //
    // The repository is seeded `provenance_mode: required` so the
    // release genuinely comes from `Cleared`. Without the policy the
    // sweep resolves the default `VerifyIfPresent` ⇒ `NotRequired`,
    // which clears the timer arm for any artifact whatever its stream
    // says — so the `ProvenanceVerified` would be doing no work here and
    // this assertion would hold with it deleted. It is also what makes
    // this the exact contrast to the never-terminal arm's hold: same
    // repository mode, different provenance evidence, opposite outcome.
    let quarantine_uc = QuarantineUseCase::new(
        f.artifacts.clone(),
        crate::event_store_publisher::wrap_for_test(f.events.clone()),
        Arc::new(MockArtifactLifecycle::new(f.artifacts.clone())),
        Arc::new(MockRepositoryRepository::new()),
        required_provenance_projections(artifact.repository_id),
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
                artifact_id: None,
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
    assert_eq!(filters[0].artifact_id, None);
}

/// `artifact_id` reaches the listing. The scan has no cursor, so this is
/// the only way an operator gets past the newest page at all — a field
/// accepted here and dropped on the way to the listing would be the
/// accepted-but-inert surface ADR 0015 forbids one layer up.
#[tokio::test]
async fn an_artifact_scoped_request_narrows_the_listing_to_that_artifact() {
    let f = build();
    let artifact = Uuid::new_v4();
    let repo = Uuid::new_v4();
    let _ =
        f.uc.run(
            RepairRequest {
                repository_id: Some(repo),
                artifact_id: Some(artifact),
                limit: 100,
                dry_run: true,
            },
            api_actor(),
        )
        .await
        .expect("Ok");
    let filters = f.queue.recorded_filters();
    assert_eq!(filters.len(), 1);
    assert_eq!(filters[0].artifact_id, Some(artifact));
    assert_eq!(
        filters[0].repository_id,
        Some(repo),
        "the two are a conjunction: naming an artifact does not drop the \
         repository filter, so a mismatched pair returns empty rather \
         than widening to either"
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
            provenance_rejected(id, 1, ProvenanceRejectReason::UntrustedIdentity),
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
            provenance_rejected(id, 2, ProvenanceRejectReason::UntrustedIdentity),
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

/// **A HISTORICAL CAS-corruption tombstone — the important one.**
///
/// `tombstone_from_corruption` now appends an `ArtifactRejected{Corruption}`
/// beside its `ArtifactCorrupted` (ADR 0039's 2026-09-12 amendment, D6),
/// which makes a *new* tombstone classify `Present` and look as though
/// `TerminalRejectionRecord::CorruptionTombstone` had become redundant.
///
/// It has not. The event store is append-only: no change can add a
/// companion to a stream written before it, so every tombstone predating
/// that fix still carries `ArtifactCorrupted` **alone** — the shape seeded
/// here. Without the separate classification it would read as `Absent`,
/// satisfy all three repair conjuncts (it carries a `ProvenanceVerified`
/// from before the corruption was found) and hand bytes that do not match
/// their content hash back to the release sweep. That is the exact hole the
/// variant was added to close, and this test is what proves the fix did not
/// re-open it for the data most likely to be in it. Refused.
#[tokio::test]
async fn leaves_a_historical_corruption_tombstoned_artifact_untouched() {
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

/// **A CURRENT CAS-corruption tombstone** — both events, the shape the
/// entity emits today. Refused too, on conjunct 2's `Present` arm rather
/// than its `CorruptionTombstone` one: the companion makes the rejection a
/// real recorded verdict, which is exactly what `Present` means. The
/// outcome is what matters and it is identical — corrupt bytes stay
/// condemned however the stream spells it.
#[tokio::test]
async fn leaves_a_current_corruption_tombstoned_artifact_untouched() {
    let f = build();
    let (artifact, entry) = seed(&f, QuarantineStatus::Rejected, |id, anchor| {
        vec![
            quarantined(id, 0, anchor),
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
            persisted_artifact_rejected(id, RejectionReason::Corruption, 3),
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

/// **A `Rejected` artifact with no terminal event and no provenance
/// verdict at all.** The shape that passes conjunct 2 but fails both
/// arms of conjunct 3: no `ProvenanceVerified` contradicts the
/// rejection, and no `ProvenanceRejected` is there to be classified
/// never-terminal either — so nothing establishes that this rejection
/// came from the provenance axis in the first place.
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
        "with no provenance evidence either way there is nothing to act on"
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
            provenance_rejected(id, 1, ProvenanceRejectReason::UntrustedIdentity),
            persisted_artifact_rejected(id, RejectionReason::Provenance, 2),
        ]
    });
    let (_, scan) = seed(&f, QuarantineStatus::Rejected, |id, anchor| {
        vec![
            quarantined(id, 0, anchor),
            persisted_artifact_rejected(id, RejectionReason::Scanner, 1),
        ]
    });
    // A `Rejected` row whose stream carries no provenance verdict at
    // all — neither proof is present, so it is left alone.
    let (_, no_verdict) = seed(&f, QuarantineStatus::Rejected, |id, anchor| {
        vec![quarantined(id, 0, anchor)]
    });
    // ...and the second repairable population, in the same batch.
    let (never_terminal, never_terminal_entry) = seed_never_terminal(&f);
    f.queue.set_entries(vec![
        disproof,
        stranded_entry,
        scan,
        no_verdict,
        never_terminal_entry,
    ]);

    let report = f.uc.run(repair_request(false), api_actor()).await.unwrap();

    assert_eq!(report.scanned, 5);
    assert_eq!(
        report
            .affected
            .iter()
            .map(|a| a.artifact_id)
            .collect::<Vec<_>>(),
        vec![stranded.id, never_terminal.id],
        "both arms of conjunct 3 are reached in one pass, and nothing else is"
    );
    assert_eq!(f.lifecycle.committed_transitions().len(), 2);
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
                artifact_id: None,
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
                artifact_id: None,
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
                artifact_id: None,
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

/// A candidate whose stream breached the event cap is reported as failed,
/// not silently skipped and not repaired.
///
/// Both conjuncts below the pairing read the stream, and over a truncated
/// prefix the absence of a terminal `ArtifactRejected` means only "not in
/// the part we reached" — which is the shape that would repair a genuinely
/// rejected artifact back into a releasable state.
#[tokio::test]
async fn a_candidate_whose_stream_breached_the_event_cap_is_reported_as_failed() {
    let f = build();
    let (artifact, entry) = seed(&f, QuarantineStatus::Rejected, |id, anchor| {
        let mut stream = vec![quarantined(id, 0, anchor)];
        stream.extend((1..201).map(|i| persisted_scan_completed(id, 0, i)));
        stream
    });
    f.queue.set_entries(vec![entry]);

    let report = f.uc.run(repair_request(true), api_actor()).await.unwrap();

    assert!(report.affected.is_empty());
    assert_eq!(report.failed.len(), 1);
    assert_eq!(report.failed[0].0, artifact.id);
    assert!(
        report.failed[0].1.contains("200-event cap"),
        "the failure must name the cap it is enforcing; got {}",
        report.failed[0].1
    );
}

/// Conjuncts 2 and 3 are decided from **one** observation of the stream,
/// not two reads of it.
///
/// There is exactly one stream read per candidate — the `ArtifactAtVersion`
/// pairing — and the terminal-rejection record, the provenance clearance
/// and the version the repair's append carries all come out of it. So a
/// failure armed at read index 1 never fires: there is no second read to
/// fail, and the candidate is reported as affected.
///
/// What this closes is not a read-error-handling question (the single read
/// failing is covered above) but an ordering one: with two reads, a
/// `ProvenanceVerified` landing between them would clear conjunct 3 on
/// evidence the terminal-record check never saw, while the append still
/// carried the earlier version — so the repair would commit without
/// conflicting.
#[tokio::test]
async fn both_conjuncts_and_the_version_come_from_one_stream_read() {
    let f = build();
    let (_, entry) = seed_stranded(&f);
    f.queue.set_entries(vec![entry.clone()]);
    // Armed at call index 1 — a second read of the artifact stream. It
    // must never fire.
    f.events
        .fail_read_stream_at(1, DomainError::Invariant("there is no second read".into()));

    let report = f.uc.run(repair_request(true), api_actor()).await.unwrap();
    assert_eq!(
        report
            .affected
            .iter()
            .map(|a| a.artifact_id)
            .collect::<Vec<_>>(),
        vec![entry.artifact_id]
    );
    assert!(report.failed.is_empty());
    assert_eq!(
        f.events.read_stream_call_count(),
        1,
        "the repair must observe the candidate's stream exactly once"
    );
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

// ---------------------------------------------------------------------------
// Conjunct 3's second arm — a verdict that may never be terminal
// ---------------------------------------------------------------------------

/// **The second stranded population, end to end.** `Rejected` with no
/// `ArtifactRejected`, no `ProvenanceVerified`, and one
/// `ProvenanceRejected{Unsigned}`: repaired to `Quarantined` on its
/// original anchor, on the strength of the reason alone.
///
/// And then — the half that makes the arm safe — **the ordinary sweep
/// holds it.** It does not release (no `ProvenanceVerified`, so the
/// provenance leg of a `Required` repository's release gate resolves
/// `Pending`, which denies the timer arm) and it does not re-reject
/// (`Unsigned` has no producer left, and an unsigned verify is
/// `NoAttestation`, which `complete_provenance` answers with no events at
/// all). That hold is ADR 0039 D1's prescribed treatment of an unsigned
/// artifact, and it is what the repair hands the decision back to.
#[tokio::test]
async fn repairs_a_never_terminal_rejection_and_the_ordinary_sweep_then_holds_it() {
    let f = build();
    let (artifact, entry) = seed_never_terminal(&f);
    let anchor = artifact.quarantine_window_start.unwrap();
    f.queue.set_entries(vec![entry]);

    let report = f.uc.run(repair_request(false), api_actor()).await.unwrap();

    assert_eq!(report.scanned, 1);
    assert_eq!(
        report
            .affected
            .iter()
            .map(|a| a.artifact_id)
            .collect::<Vec<_>>(),
        vec![artifact.id],
        "an Unsigned rejection with no ArtifactRejected behind it is D6's illegal state"
    );
    assert!(report.failed.is_empty());

    let transitions = f.lifecycle.committed_transitions();
    assert_eq!(transitions.len(), 1);
    let (committed, append, _) = &transitions[0];
    assert_eq!(committed.quarantine_status, QuarantineStatus::Quarantined);
    assert_eq!(committed.rejection_reason, None);
    assert_eq!(append.events.len(), 2);
    match &append.events[0].event {
        DomainEvent::ArtifactReEvaluated(e) => {
            assert_eq!(e.trigger, ReEvaluationTrigger::ProvenanceMisrejectionRepair);
            assert_eq!(e.previous_status, QuarantineStatus::Rejected);
            assert_eq!(e.new_status, QuarantineStatus::Quarantined);
        }
        other => panic!("expected ArtifactReEvaluated first, got {other:?}"),
    }
    match &append.events[1].event {
        // Never `ArtifactReleased`, and never a restarted window.
        DomainEvent::ArtifactQuarantined(e) => assert_eq!(e.quarantine_window_start, anchor),
        other => panic!("expected ArtifactQuarantined second, got {other:?}"),
    }

    // --- and now the ordinary sweep takes over -------------------------
    let quarantine_uc = QuarantineUseCase::new(
        f.artifacts.clone(),
        crate::event_store_publisher::wrap_for_test(f.events.clone()),
        Arc::new(MockArtifactLifecycle::new(f.artifacts.clone())),
        Arc::new(MockRepositoryRepository::new()),
        required_provenance_projections(artifact.repository_id),
        Arc::new(MockContentReferenceIndex::new()),
        Arc::new(MockStoragePort::new()),
        Arc::new(MockJobsRepository::new()),
    );
    let summary = quarantine_uc
        .release_expired(vec![artifact.id])
        .await
        .expect("release_expired must not error");
    assert_eq!(
        summary.skipped_provenance_pending, 1,
        "the hold is attributed to the provenance leg, which is what denies the timer arm"
    );
    assert!(
        summary.released.is_empty(),
        "an artifact nothing has verified must not be released by the repair's exit — \
         the whole argument for the second arm is that the sweep holds it"
    );
    assert_eq!(
        f.artifacts.get(artifact.id).unwrap().quarantine_status,
        QuarantineStatus::Quarantined,
        "held — neither released nor re-rejected"
    );
}

/// The dry run reaches the second arm too, and still writes nothing: the
/// report an operator reads before mutating must name the same set.
#[tokio::test]
async fn dry_run_lists_a_never_terminal_rejection_without_mutating() {
    let f = build();
    let (artifact, entry) = seed_never_terminal(&f);
    f.queue.set_entries(vec![entry]);

    let report = f.uc.run(repair_request(true), api_actor()).await.unwrap();

    assert!(report.dry_run);
    assert_eq!(
        report
            .affected
            .iter()
            .map(|a| a.artifact_id)
            .collect::<Vec<_>>(),
        vec![artifact.id]
    );
    assert!(f.lifecycle.committed_transitions().is_empty());
    assert!(f.events.appended_batches().is_empty());
    assert_eq!(
        f.artifacts.get(artifact.id).unwrap().quarantine_status,
        QuarantineStatus::Rejected
    );
}

/// **The counter-assertion.** The second arm keys on the `reason`, not
/// on a `ProvenanceRejected` merely being present.
///
/// Every reason other than `Unsigned` is a positive disproof — a
/// signature that is present and wrong — and ADR 0039 D1/D4 permit
/// exactly those to be terminal. The shape seeded here is the one that
/// reaches conjunct 3: a disproof written **before** the D6 companion
/// existed carries its `ProvenanceRejected` alone, so conjunct 2
/// classifies it `Absent`.
///
/// Without this test the arm silently becomes a pass-through — a
/// historical forged-signature rejection walked back into the release
/// path — while every other test in this file stays green.
#[tokio::test]
async fn leaves_a_historical_disproof_with_no_companion_untouched() {
    let f = build();
    for reason in [
        ProvenanceRejectReason::UntrustedIdentity,
        ProvenanceRejectReason::RekorNotFound,
        ProvenanceRejectReason::CertChainInvalid,
        ProvenanceRejectReason::BundleMalformed,
        ProvenanceRejectReason::DigestMismatch,
    ] {
        let (artifact, entry) = seed(&f, QuarantineStatus::Rejected, |id, anchor| {
            vec![
                quarantined(id, 0, anchor),
                persisted_scan_completed(id, 0, 1),
                provenance_rejected(id, 2, reason),
            ]
        });
        f.queue.set_entries(vec![entry]);

        let report = f.uc.run(repair_request(false), api_actor()).await.unwrap();

        assert!(
            report.affected.is_empty(),
            "{reason:?} is a positive disproof and must stay terminal"
        );
        assert!(report.failed.is_empty(), "not matching is not a failure");
        assert_eq!(
            f.artifacts.get(artifact.id).unwrap().quarantine_status,
            QuarantineStatus::Rejected
        );
    }
    assert!(
        f.lifecycle.committed_transitions().is_empty(),
        "no disproof shape may be repaired"
    );

    // The discriminating half, in the same test so the two cannot drift.
    // The stream is byte-for-byte the loop's shape with one field
    // changed — same events, same positions, same backend, only
    // `reason` differs — and it IS repaired. That single-dimension
    // difference is what proves the refusals above come from the reason
    // and not from some other property of the fixture.
    let (unsigned, entry) = seed(&f, QuarantineStatus::Rejected, |id, anchor| {
        vec![
            quarantined(id, 0, anchor),
            persisted_scan_completed(id, 0, 1),
            provenance_rejected(id, 2, ProvenanceRejectReason::Unsigned),
        ]
    });
    f.queue.set_entries(vec![entry]);
    let report = f.uc.run(repair_request(false), api_actor()).await.unwrap();
    assert_eq!(
        report
            .affected
            .iter()
            .map(|a| a.artifact_id)
            .collect::<Vec<_>>(),
        vec![unsigned.id],
        "the only difference from the refused streams above is the reason"
    );
    assert_eq!(
        f.artifacts.get(unsigned.id).unwrap().quarantine_status,
        QuarantineStatus::Quarantined
    );
}

/// **The "only provenance verdict" narrowing.** An `Unsigned` followed by
/// a later disproof is a disproven artifact, not a misrejected one — the
/// later verdict is a statement about the artifact and it stands.
///
/// Asserted in both orders: the scan returns on the first non-`Unsigned`
/// reason it reads, so a disproof *before* the `Unsigned` must refuse
/// too.
#[tokio::test]
async fn leaves_an_unsigned_followed_by_a_disproof_untouched() {
    let f = build();

    let (later, later_entry) = seed(&f, QuarantineStatus::Rejected, |id, anchor| {
        vec![
            quarantined(id, 0, anchor),
            policy_unsigned_rejected(id, 1),
            provenance_rejected(id, 2, ProvenanceRejectReason::DigestMismatch),
        ]
    });
    let (earlier, earlier_entry) = seed(&f, QuarantineStatus::Rejected, |id, anchor| {
        vec![
            quarantined(id, 0, anchor),
            provenance_rejected(id, 1, ProvenanceRejectReason::DigestMismatch),
            policy_unsigned_rejected(id, 2),
        ]
    });
    f.queue.set_entries(vec![later_entry, earlier_entry]);

    let report = f.uc.run(repair_request(false), api_actor()).await.unwrap();

    assert_eq!(report.scanned, 2);
    assert!(
        report.affected.is_empty(),
        "a stream carrying a disproof is not this population, in either order"
    );
    assert!(f.lifecycle.committed_transitions().is_empty());
    for id in [later.id, earlier.id] {
        assert_eq!(
            f.artifacts.get(id).unwrap().quarantine_status,
            QuarantineStatus::Rejected
        );
    }
}

/// A `ProvenanceVerified` on the stream still classifies as the
/// contradiction even when an `Unsigned` sits beside it — the first arm
/// is tested first, exactly as the release gate reads `Cleared`. The
/// outcome is the same either way (both are proofs); what this pins is
/// that the two arms do not fight over a stream carrying both.
#[tokio::test]
async fn an_unsigned_rejection_contradicted_by_a_later_verification_is_repaired() {
    let f = build();
    let (artifact, entry) = seed(&f, QuarantineStatus::Rejected, |id, anchor| {
        vec![
            quarantined(id, 0, anchor),
            persisted_scan_completed(id, 0, 1),
            policy_unsigned_rejected(id, 2),
            // The signature that landed 5.1 s later.
            verified(id, 3),
        ]
    });
    f.queue.set_entries(vec![entry]);

    let report = f.uc.run(repair_request(false), api_actor()).await.unwrap();
    assert_eq!(
        report
            .affected
            .iter()
            .map(|a| a.artifact_id)
            .collect::<Vec<_>>(),
        vec![artifact.id]
    );
    assert_eq!(
        f.artifacts.get(artifact.id).unwrap().quarantine_status,
        QuarantineStatus::Quarantined
    );
}

// ---------------------------------------------------------------------------
// The conjunct-3 resolver, directly
// ---------------------------------------------------------------------------

/// Every arm of [`provenance_rejection_evidence`], over the streams the
/// use-case tests above reach it through — so a refusal that is correct
/// for the wrong reason cannot hide behind an identical report.
#[test]
fn provenance_rejection_evidence_classifies_every_shape() {
    let id = Uuid::new_v4();
    let anchor = Utc::now() - Duration::hours(2);

    // A `ProvenanceVerified` anywhere ⇒ the contradiction, whatever else
    // the stream carries.
    for stream in [
        vec![quarantined(id, 0, anchor), verified(id, 1)],
        vec![
            quarantined(id, 0, anchor),
            policy_unsigned_rejected(id, 1),
            verified(id, 2),
        ],
        vec![
            quarantined(id, 0, anchor),
            provenance_rejected(id, 1, ProvenanceRejectReason::DigestMismatch),
            verified(id, 2),
        ],
    ] {
        assert_eq!(
            provenance_rejection_evidence(&stream),
            ProvenanceRejectionEvidence::Contradicted
        );
    }

    // `Unsigned` alone ⇒ never-terminal. More than one of them is still
    // "only `Unsigned`".
    assert_eq!(
        provenance_rejection_evidence(&[
            quarantined(id, 0, anchor),
            policy_unsigned_rejected(id, 1)
        ]),
        ProvenanceRejectionEvidence::NeverTerminal
    );
    assert_eq!(
        provenance_rejection_evidence(&[
            quarantined(id, 0, anchor),
            policy_unsigned_rejected(id, 1),
            policy_unsigned_rejected(id, 2),
        ]),
        ProvenanceRejectionEvidence::NeverTerminal
    );

    // Any positive disproof ⇒ refused, carrying the reason it read.
    for reason in [
        ProvenanceRejectReason::UntrustedIdentity,
        ProvenanceRejectReason::RekorNotFound,
        ProvenanceRejectReason::CertChainInvalid,
        ProvenanceRejectReason::BundleMalformed,
        ProvenanceRejectReason::DigestMismatch,
    ] {
        assert_eq!(
            provenance_rejection_evidence(&[
                quarantined(id, 0, anchor),
                provenance_rejected(id, 1, reason),
            ]),
            ProvenanceRejectionEvidence::Disproved(reason)
        );
        // Mixed with an `Unsigned`, in both orders: the disproof wins.
        assert_eq!(
            provenance_rejection_evidence(&[
                policy_unsigned_rejected(id, 0),
                provenance_rejected(id, 1, reason),
            ]),
            ProvenanceRejectionEvidence::Disproved(reason)
        );
        assert_eq!(
            provenance_rejection_evidence(&[
                provenance_rejected(id, 0, reason),
                policy_unsigned_rejected(id, 1),
            ]),
            ProvenanceRejectionEvidence::Disproved(reason)
        );
    }

    // No provenance event at all ⇒ no verdict, and an empty stream is the
    // same answer rather than a panic.
    assert_eq!(
        provenance_rejection_evidence(&[quarantined(id, 0, anchor)]),
        ProvenanceRejectionEvidence::NoVerdict
    );
    assert_eq!(
        provenance_rejection_evidence(&[]),
        ProvenanceRejectionEvidence::NoVerdict
    );
}
