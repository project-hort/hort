pub mod api_token_use_case;
pub mod apply_config_use_case;
pub mod artifact_group_use_case;
pub mod artifact_use_case;
pub mod authenticate_use_case;
pub mod cas_scrub_use_case;
pub mod content_reference;
// Curator decisions: `waive` + `block` (single-artifact and
// `BlockTarget::VersionList` with continue-on-error), plus the `list_*`
// reads backing the HTTP / CLI surfaces. See
// `docs/architecture/how-to/curator-workflow.md`.
pub mod curation_use_case;
// Repo-keyed discovery endpoint
// (`GET /api/v1/repositories/{repo_key}/discovery/versions/{package}`).
// Composes the extended `ArtifactRepository::package_version_status`
// (3-tuple, with `quarantine_until`) with `UpstreamMetadataPort::
// list_versions`, overlaying per-version status. Deliberately does NOT
// compose the unified index pipeline
// (`docs/architecture/explanation/index-construction.md`).
pub mod discovery_use_case;
// Admin-only effective-repository-config read surface
// (`GET /api/v1/admin/repositories/:key/effective-config`). Resolves the
// scan-policy leg (repo-scoped > global > `DefaultPolicy`) behind the
// `pub(crate)` `PolicyProjectionRepository` port; the repository row and
// upstream mappings come from their own existing use cases / ports.
pub mod effective_repository_config_use_case;
// Admin-only effective-permissions inspection surface
// (`GET /api/v1/admin/users/:user_id/effective-permissions`).
// The audit-time mitigation for additive-claims operator-discipline
// cost. See `docs/architecture/how-to/operate/claim-based-rbac.md`.
pub mod effective_permissions_use_case;
// `EventStoreRetentionUseCase::archive_terminal_streams`. Seals whole
// terminal / age-gated streams once their audit-retention floor has
// elapsed, routing every seal through the adapter chokepoint (the
// `StreamSealed` tombstone is emitted by the adapter, never
// reimplemented here). Two seal modes; registered with the worker via
// the retention registration seam.
pub mod eventstore_retention_use_case;
pub mod group_reconcile_use_case;
// Shared `IndexFilter` implementations
// (`NonServableStatusFilter` + `IndexModeFilter`) used by the
// per-format unified serve handlers. The
// trait/spine-type definitions they implement live in
// `index_serve` (this module's sibling); `hort-formats::index_serve`
// re-exports them so format-crate consumers have one import path.
pub mod index_filters;
// Format-agnostic index-construction trait skeleton
// (`docs/architecture/explanation/index-construction.md`): `IndexFilter`,
// `IndexBuilder`, `VersionEntry`, `PerVersionPayload`, `BuildContext`.
// Defined here
// (not in `hort-formats`) because the in-`hort-app` filter
// implementations would otherwise need a circular `hort-app →
// hort-formats` edge. `hort-formats::index_serve` is a re-export façade.
pub mod index_serve;
// Quarantine-aware index-serve filter, the
// format-agnostic core (`filter_served_versions`) + the npm reference
// `VersionOrdering` implementation (`NpmSemverOrdering`). Reused
// unchanged for PyPI / Cargo / Maven with their respective
// `VersionOrdering` implementations.
pub mod index_serve_filter;
pub mod ingest_use_case;
// `POST /api/v1/artifacts/:id/rescan` use case.
// Lives in `hort-app` (not `hort-http-admin-security`) per the layered
// architecture: use cases hold the RBAC / conflict-detection /
// enqueue orchestration; the HTTP adapter is a thin wrapper that
// extracts the principal + path and maps `AppError` → `ApiError`.
pub mod manual_rescan_use_case;
pub mod multi_hash;
// The facade the OCI inbound-HTTP crate calls to queue eager ingest of
// an image index's declared children. `AppContext::jobs` is `pub(crate)`
// (ADR 0008), so a format crate reaches the queue through here.
pub mod oci_index_child_enqueue;
// OCI Distribution-Spec `/v2/auth` token exchange. See module-level
// doc.
pub mod oci_token_exchange_use_case;
pub mod pat_cache;
pub mod pat_validation_use_case;
// Admin-only read of the patch-candidate quarantine surface. See
// `docs/architecture/how-to/quarantine-patch-release.md`.
pub mod patch_candidate_use_case;
// Shared active-scan-policy resolver (issue #76, item 1/2) — extracted
// from seven private, byte-identical copies. See module docs.
pub(crate) mod policy_resolution;
pub mod policy_use_case;
// Prefetch trigger `on_dist_tag_move`
// (`docs/architecture/explanation/prefetch-pipeline.md`).
// Stateless planner consumed by the per-format index/metadata serve
// sites (`hort-http-npm`, `hort-http-cargo`); emits
// `hort_prefetch_skipped_total` per skipped version +
// `hort_prefetch_enqueued_total` per planned version. The format crate
// iterates the returned plan and spawns its per-version pull
// (`PullDedup` inside the spawn handles concurrent dedup).
pub mod prefetch_use_case;
// Shared `fire_hot_path_trigger` helper that collapses the
// previously-duplicated per-format hot-path prefetch-trigger pattern
// (npm / pypi / cargo). OCI deliberately keeps its dedicated
// `fire_prefetch_trigger_oci` — the manifest-fetch digest-divergence
// path doesn't match this helper's parse-body-and-pick-newest
// contract.
pub mod prefetch_trigger;
pub mod promotion_use_case;
// `PurgeUseCase::process_expired`, the destructive storage-GC walk.
// Second stage of the two-stage retention split; refuses to run until
// the refcount-reconcile gate reports convergence.
pub mod purge_use_case;
// Shared computation of the transient (non-persisted) `quarantine_deadline`
// / `provenance_hold_indefinite` pair, so the read path and the two ingest
// mint paths cannot report different remaining windows for one artifact.
pub(crate) mod quarantine_hold;
pub mod quarantine_use_case;
pub(crate) mod rejected_reevaluation;
// `RbacResolveUseCase` backing
// `POST /api/v1/admin/rbac/resolve` (the admin what-if resolver:
// IdP groups → claims → effective `(repo, permission)` grants). No IdP
// query, no cache; admin-gated read-only.
pub mod rbac_resolve_use_case;
pub mod ref_use_case;
// The I/O-bearing orchestrator behind
// `POST /api/v1/repositories/{repo_key}/prefetch`. Wraps the pure
// `PrefetchUseCase` planner (unchanged) with repo resolution, RBAC +
// token-kind gates, per-item upstream version resolution, pre-flight
// `package_version_status` checks, and per-item job enqueue via
// `JobsRepository::enqueue_task`. The pure planner stays pure per
// its own module docstring; this is the persistent-job-enqueue
// companion to `fire_hot_path_trigger`.
pub mod self_service_prefetch_use_case;
// `RefcountReconcileUseCase::sweep_drift`.
// Brings the eventually-authoritative `content_references` refcount
// projection back into agreement with `artifacts` + `artifact_metadata`.
// HARD PREREQUISITE for `PurgeUseCase`, whose start-gate
// refuses to run until this sweep has converged at least once.
pub mod refcount_reconcile_use_case;
// Shared referenced-tree-descendant predicate (issue #115 item 3) —
// one definition for BOTH the ingest zero-window anchor carve-out (#46)
// and the provenance orchestrator's `NoAttestation × Required` hold.
pub(crate) mod referenced_descendant;
pub mod repository_access;
pub mod repository_use_case;
// Seed-import cutover path.
// Bulk-registers an operator-supplied dependency set with backdated
// `quarantine_window_start` anchors so the *time* gate is already
// elapsed at import. NOT `ScanWaived`: a dirty scan still rejects.
pub mod seed_import_use_case;
// `RetentionPolicyUseCase`, the
// gitops-authored event-sourced retention-policy create/update/archive
// path (append `RetentionPolicyChanged` + upsert
// `retention_policy_projections`). Mirrors the `PolicyUseCase`
// append-then-upsert shape; archive is terminal (no reactivation).
pub mod retention_policy_use_case;
// `RetentionUseCase::evaluate_policies`.
// The runtime retention evaluator (predicate match + `ArtifactExpired`
// append). Storage GC is `PurgeUseCase`.
pub mod retention_use_case;
// `ProvenanceOrchestrationUseCase`. The worker-side
// `provenance-verify` flow: fetch attestation bundles (OCI Referrers /
// content-reference surface) + the CAS preimage, dispatch each applicable
// `ProvenancePort`, fold to one verdict, apply `complete_provenance`.
// See ADR 0027.
// Shared provenance-clearance cascade machinery (ADR 0039 §11): the
// verify-time subject cascade and the ingest-time late-joiner self-clear
// are two trigger ends of one dependency, so they share one walk.
pub(crate) mod provenance_cascade;
// One-shot, admin-invoked corrective path for the artifacts stranded
// `Rejected` with no `ArtifactRejected` behind them by the defect ADR
// 0039's 2026-09-12 amendment removed. Bounded, historical population —
// see the module docs for why it is an operator surface rather than a
// reconciliation or a task handler.
pub mod provenance_misrejection_repair;
pub mod provenance_orchestration;
pub(crate) mod release_clearance;
pub(crate) mod scan_history;
pub mod scan_orchestration;
// Admin-only read of the scanner_registry worker table, backing
// `GET /api/v1/admin/workers` / `hort admin workers list` (ADR 0000
// "Scanner-registry read side orphaned" — wires the orphaned reader).
pub mod scanner_worker_query_use_case;
// Read-side use case backing
// `GET /api/v1/repositories/:name/security-score` and
// `GET /api/v1/security-score`.
pub mod security_score_use_case;
// Pure-async filter evaluation function. See
// `docs/architecture/explanation/event-notifications.md`.
pub mod subscription_filter;
// `SubscriptionUseCase`. See
// `docs/architecture/explanation/event-notifications.md`.
pub mod subscription_use_case;
pub mod task_use_case;
// Application-layer adapter for the
// `UpstreamIndexCacheInvalidator` domain port. Evicts cached upstream
// packument / simple-index / sparse-index entries when an artifact
// transitions to `Rejected`. Best-effort defense-in-depth cache
// hygiene; the `NonServableStatusFilter` on the next index
// build is the load-bearing close
// (`docs/architecture/explanation/index-construction.md`).
pub mod upstream_index_cache_invalidator;
pub mod user_use_case;
pub mod virtual_resolution;
// PEP 658 `.metadata` read-path use case.
// Resolves the wheel artifact via the visibility-gated
// `find_visible_by_path` hop, gates on the same per-artifact
// quarantine-status filter as the wheel download, looks up the
// `wheel_metadata` ContentReference row, and streams the bytes back
// from CAS. See `docs/architecture/how-to/pypi-pull-through.md`.
pub mod wheel_metadata_use_case;

pub use group_reconcile_use_case::{GroupReconcileUseCase, ReconcileReport};
pub use policy_use_case::{
    AddExclusionCommand, CreatePolicyCommand, FieldChange, PolicyUseCase, RemoveExclusionCommand,
    UpdatePolicyCommand,
};

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

use std::time::Duration as StdDuration;

use uuid::Uuid;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::{PersistedEvent, StreamCategory, StreamId};
use hort_domain::ports::event_store::{
    AppendEvents, AppendResult, EventStore, ExpectedVersion, ReadFrom,
};

use crate::error::{AppError, AppResult};

/// The maximum number of events an artifact stream may hold.
///
/// This is an **enforced, fail-closed bound**, not an estimate of how
/// long a stream gets. It is what makes a single capped
/// `ReadFrom::Start` read of an artifact stream equal to reading the
/// whole stream — the property every consumer of the stream's history
/// silently depends on, and the reason the number is enforced on both
/// sides:
///
/// - **Write side.** [`read_expected_version`] refuses to derive an
///   append version for a stream that already exceeds the cap, so every
///   `ExpectedVersion::Exact` writer is bounded by it. An
///   `ExpectedVersion::Any` append gets no version check from the
///   adapter at all, so such a writer must refuse for itself:
///   `RetentionUseCase::append_expired` is the only *repeatable* one and
///   does. The rest are terminal and single-shot (`ArtifactPurged`,
///   `ArtifactDeleted`, the CAS-corruption tombstone pair) and
///   deliberately do not refuse — they record destructive work that has
///   already happened, they are the last events a stream ever takes, and
///   no reader consults an artifact's stream after its terminal event.
///   A NEW repeatable `Any` writer on [`StreamCategory::Artifact`]
///   without a refusal of its own reopens the breach.
/// - **Read side.** [`read_artifact_stream`] reads `STREAM_EVENT_CAP + 1`
///   events: a read that comes back with at most `STREAM_EVENT_CAP` has
///   provably seen the entire stream, and one that comes back with more
///   refuses to answer rather than hand its caller the oldest prefix.
///
/// An artifact's realistic lifecycle is a few dozen events at most
/// (ingest → quarantine → scan(s) → release/reject → maybe expire →
/// purge), so the bound leaves roughly an order of magnitude of
/// headroom. A stream that reaches it is a bug or abuse, and the
/// resulting freeze — no further event accepted, no decision derived
/// from a read that cannot prove completeness — is the intended
/// fail-closed outcome, not a degradation to work around. Raising the
/// number would only move the point at which the same failure appears.
const STREAM_EVENT_CAP: u64 = 200;

/// Read a bounded artifact stream **in full**, or refuse.
///
/// Every consumer that asks a question about an artifact's whole history
/// — the latest `ScanCompleted` and whether an `ArtifactRejected`
/// followed it, whether an `ArtifactExpired` for a policy is already on
/// the stream, whether a `ProvenanceVerified` exists, what the stream's
/// terminal event is — needs the whole stream. A capped
/// `ReadFrom::Start` read yields the whole stream only while the stream
/// fits inside the cap, and cannot by itself tell the two cases apart:
/// reading `n` events with a budget of `n` proves nothing about what
/// comes after them.
///
/// So this helper reads [`STREAM_EVENT_CAP`] `+ 1` events, making the
/// two cases distinguishable, and refuses the second:
///
/// - at most [`STREAM_EVENT_CAP`] events came back ⇒ the budget was not
///   exhausted, so the read reached the end of the stream — return it;
/// - more came back ⇒ the stream breached the cap and no capped read can
///   prove it saw the tail. Returning the oldest prefix is the defect
///   this refusal exists to prevent: a reverse scan over a truncated
///   prefix turns "the latest X" into "the latest X among the oldest
///   [`STREAM_EVENT_CAP`]", so a superseded scan verdict reads as the
///   current one and a rejection that came after it is invisible.
///
/// The refusal is [`DomainError::Invariant`] and deliberately NOT
/// [`DomainError::Conflict`]: the condition is a breach that re-reading
/// cannot change, and [`append_any_with_conflict_retry`] retries
/// `Conflict` and nothing else — a `Conflict` here would let a
/// retry-wrapped caller spend its entire budget waiting for a stream
/// length to shrink.
pub(crate) async fn read_artifact_stream(
    events: &dyn EventStore,
    stream_id: &StreamId,
) -> AppResult<Vec<PersistedEvent>> {
    if stream_id.category != StreamCategory::Artifact {
        return Err(DomainError::Invariant(format!(
            "read_artifact_stream called on non-artifact stream {stream_id} \
             (category {:?}) — a capped full-stream read is only correct for \
             a stream bounded by STREAM_EVENT_CAP, which today is exclusively \
             the per-artifact lifecycle stream; an unbounded category needs a \
             paged or tail read, not a larger cap",
            stream_id.category
        ))
        .into());
    }

    let stream_events = events
        .read_stream(stream_id, ReadFrom::Start, STREAM_EVENT_CAP + 1)
        .await?;

    if stream_events.len() as u64 > STREAM_EVENT_CAP {
        return Err(DomainError::Invariant(format!(
            "stream {stream_id} exceeds the {STREAM_EVENT_CAP}-event cap — \
             a capped read cannot prove it reached the tail, so no decision \
             is derived from it"
        ))
        .into());
    }

    Ok(stream_events)
}

/// Read a stream's current position and compute the `ExpectedVersion` for
/// the next append.
///
/// When `enforce_cap` is true, returns `DomainError::Conflict` if the stream
/// exceeds [`STREAM_EVENT_CAP`] events.
///
/// # Structural guard (issue #88)
///
/// The read here is a **capped forward-scan**
/// (`read_stream(_, ReadFrom::Start, STREAM_EVENT_CAP + 1)`), which is
/// correct ONLY for a stream that is bounded by design — today,
/// exclusively [`StreamCategory::Artifact`] (`STREAM_EVENT_CAP` is that
/// category's own intended abuse guard: an artifact's lifecycle
/// realistically never approaches a few dozen events, let alone 200).
/// For any OTHER (unbounded) stream category, a stream that has grown
/// past `STREAM_EVENT_CAP + 1` events makes `.last()` return a STALE
/// position instead of the true tail — every subsequent
/// `ExpectedVersion::Exact` append then fails `Conflict` deterministically
/// and permanently (issue #87 was the production instance: the per-user
/// `ApiTokenIssued` stream; issue #88 is the cross-cutting audit that
/// found and fixed every other such caller).
///
/// This function therefore REJECTS any non-`Artifact` `stream_id` up
/// front, before doing any I/O — making "derive a version from this
/// capped read for an unbounded stream" a hard runtime error rather
/// than a silent staleness bug. An unbounded-stream caller must use
/// `ExpectedVersion::Any` + [`append_any_with_conflict_retry`] instead
/// (the append protects no decision made from stream content in every
/// audited case — see `backlog/056-expected-version-capped-read-audit.md`).
///
/// This is a deliberate, narrower alternative to adding a new
/// `EventStore` port method for a true-tail read (the backlog's other
/// suggested option): a port addition would require updating every
/// `EventStore` mock across the workspace (a dozen-plus implementors),
/// for a capability no audited caller actually needs — every unbounded
/// stream in this audit turned out to be decision-free, so `Any` +
/// retry closes the bug with a strictly smaller blast radius.
pub(crate) async fn read_expected_version(
    events: &dyn EventStore,
    stream_id: &StreamId,
    enforce_cap: bool,
) -> AppResult<ExpectedVersion> {
    if stream_id.category != StreamCategory::Artifact {
        return Err(DomainError::Invariant(format!(
            "read_expected_version called on non-artifact stream {stream_id} \
             (category {:?}) — capped forward-scan version derivation is only \
             correct for the bounded per-artifact lifecycle stream; use \
             ExpectedVersion::Any + append_any_with_conflict_retry for any \
             other (unbounded) stream category (issue #88)",
            stream_id.category
        ))
        .into());
    }

    let stream_events = events
        .read_stream(stream_id, ReadFrom::Start, STREAM_EVENT_CAP + 1)
        .await?;

    if enforce_cap && stream_events.len() as u64 > STREAM_EVENT_CAP {
        return Err(DomainError::Conflict(format!(
            "stream {stream_id} exceeds {STREAM_EVENT_CAP}-event cap"
        ))
        .into());
    }

    Ok(match stream_events.last() {
        Some(last) => ExpectedVersion::Exact(last.stream_position),
        None => ExpectedVersion::NoStream,
    })
}

/// Bounded CAS-retry budget shared by every `ExpectedVersion::Any` append
/// that protects no decision made from the target stream's content
/// (issue #87, promoted here for issue #88 — a second and third file
/// needed the identical helper, crossing the 3+ dup rule: see
/// `api_token_use_case.rs`'s original `append_any_with_conflict_retry`,
/// now used by `subscription_use_case.rs` and `ingest_use_case.rs` too).
pub(crate) const EVENT_APPEND_RETRY_ATTEMPTS: u32 = 5;

/// `10ms * 4^(attempt-1)` (10/40/160/640ms across the 4 backoff gaps
/// between 5 attempts) + 0–10ms jitter. Worst-case total sleep is
/// ~850ms + jitter — real headroom vs. issue #62's original ~20ms
/// budget, which issue #87's triage found routinely exhausted under
/// sustained co-writer bursts or elevated DB latency.
pub(crate) fn event_append_backoff(attempt: u32) -> StdDuration {
    let base_ms = 10u64.saturating_mul(4u64.saturating_pow(attempt.saturating_sub(1)));
    let jitter_ms = u64::from(rand::random::<u8>() % 11); // 0..=10ms
    StdDuration::from_millis(base_ms + jitter_ms)
}

/// Bounded CAS-retry for an `ExpectedVersion::Any` append that protects
/// NO decision made from the stream's content (issue #87/#88). Every
/// caller of this helper fits that shape: none inspect the stream's
/// prior events, they only ever needed a version NUMBER for the CAS
/// write — and `ExpectedVersion::Any` means the adapter re-reads the
/// tail itself on each attempt, so a losing `DomainError::Conflict` is
/// resolved by simply re-invoking `append` with a fresh (byte-identical)
/// `AppendEvents`, no client-side expected-version read at all.
///
/// `build` is called once per attempt to produce a fresh `AppendEvents`
/// — callers close over the (already-built-once) event, correlation id,
/// and actor, and just re-package them each call.
///
/// Retries ONLY `DomainError::Conflict`; any other error returns
/// immediately, consuming none of the budget. On exhaustion, returns
/// the final attempt's `DomainError::Conflict` verbatim — the SAME
/// value an unretried single attempt would have produced — so callers
/// can pattern-match `Err(DomainError::Conflict(_))` to detect
/// exhaustion: a `Conflict` can only reach the caller after the retry
/// budget is spent, since every intermediate `Conflict` is absorbed
/// here; `Err(other)` means the very first attempt already failed for a
/// different reason and was never retried.
pub(crate) async fn append_any_with_conflict_retry(
    events: &dyn EventStore,
    attempts: u32,
    backoff: impl Fn(u32) -> StdDuration,
    mut build: impl FnMut() -> AppendEvents,
) -> DomainResult<AppendResult> {
    let mut attempt: u32 = 1;
    loop {
        let batch = build();
        let stream_id = batch.stream_id.clone();
        match events.append(batch).await {
            Ok(result) => return Ok(result),
            Err(DomainError::Conflict(_)) if attempt < attempts => {
                let delay = backoff(attempt);
                tracing::debug!(
                    %stream_id,
                    attempt,
                    attempts,
                    delay_ms = delay.as_millis() as u64,
                    "append conflict — retrying with a fresh append",
                );
                tokio::time::sleep(delay).await;
                attempt += 1;
            }
            Err(err) => return Err(err),
        }
    }
}

/// Verified caller privileges, constructed by the inbound adapter from the
/// authenticated session. Never from request body input.
///
/// This struct ensures privilege checks are explicit parameters, not
/// ambient state (ADR 0001).
///
/// Each `is_*` flag mirrors a `Permission` (or a synthetic role like
/// reviewer): the HTTP edge derives the flag from the caller's resolved
/// permission grants and passes the struct down. Adding a new flag is
/// the standard extension shape — every existing flag follows it.
pub struct CallerPrivileges {
    pub is_admin: bool,
    pub is_reviewer: bool,
    /// Derived at the HTTP edge from the caller
    /// holding `Permission::Curate`. Gates the curation use case
    /// (`waive` / `block` / `list_*`) and is accepted (alongside
    /// `is_admin`) by `PolicyUseCase::{add_exclusion, remove_exclusion}`.
    pub is_curator: bool,
    pub writable_repository_ids: Vec<Uuid>,
}

impl CallerPrivileges {
    /// Require admin privilege. Returns `Forbidden` if not an admin.
    pub fn require_admin(&self) -> AppResult<()> {
        if self.is_admin {
            Ok(())
        } else {
            Err(AppError::Domain(DomainError::Forbidden(
                "admin privilege required".into(),
            )))
        }
    }

    /// Require reviewer privilege. Admins implicitly have reviewer access.
    pub fn require_reviewer(&self) -> AppResult<()> {
        if self.is_reviewer || self.is_admin {
            Ok(())
        } else {
            Err(AppError::Domain(DomainError::Forbidden(
                "reviewer privilege required".into(),
            )))
        }
    }

    /// Require curate **or** admin privilege.
    ///
    /// `Permission::Curate` is the day-to-day decision authority over
    /// quarantined / rejected artifacts and finding-exclusions;
    /// `Permission::Admin` is a strict superset by design (admins can do
    /// everything a curator can, plus more — including `admin_release`
    /// of `ScanIndeterminate` artifacts, which curator cannot).
    /// Accept either authority so an admin is not forced to also carry
    /// the curator permission to perform a curator action.
    ///
    /// Mirrors `require_admin` in shape: returns
    /// `AppError::Domain(DomainError::Forbidden(_))` on denial. The
    /// inbound HTTP layer maps that to 403 via the standard error map.
    pub fn require_curate_or_admin(&self) -> AppResult<()> {
        if self.is_curator || self.is_admin {
            Ok(())
        } else {
            Err(AppError::Domain(DomainError::Forbidden(
                "curate or admin privilege required".into(),
            )))
        }
    }

    /// Require write access to a specific repository. Admins have global write.
    pub fn require_write_access(&self, repo_id: Uuid) -> AppResult<()> {
        if self.is_admin || self.writable_repository_ids.contains(&repo_id) {
            Ok(())
        } else {
            Err(AppError::Domain(DomainError::Forbidden(format!(
                "write access required for repository {repo_id}"
            ))))
        }
    }
}

#[cfg(test)]
mod read_expected_version_tests {
    use std::sync::Arc;

    use hort_domain::events::StreamId;
    use hort_domain::ports::event_store::ExpectedVersion;

    use super::*;
    use crate::use_cases::test_support::*;

    #[tokio::test]
    async fn empty_stream_returns_no_stream() {
        let events = Arc::new(MockEventStore::new());
        let stream_id = StreamId::artifact(Uuid::new_v4());

        let version = read_expected_version(&*events, &stream_id, false)
            .await
            .unwrap();
        assert_eq!(version, ExpectedVersion::NoStream);
    }

    #[tokio::test]
    async fn existing_stream_returns_exact() {
        let events = Arc::new(MockEventStore::new());
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);

        let dummy: Vec<_> = (0..3)
            .map(|i| dummy_persisted_event(&stream_id, artifact_id, i))
            .collect();
        events.set_stream(&stream_id, dummy);

        let version = read_expected_version(&*events, &stream_id, false)
            .await
            .unwrap();
        assert_eq!(version, ExpectedVersion::Exact(2));
    }

    #[tokio::test]
    async fn cap_enforced_rejects_oversized_stream() {
        let events = Arc::new(MockEventStore::new());
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);

        let dummy: Vec<_> = (0..201)
            .map(|i| dummy_persisted_event(&stream_id, artifact_id, i))
            .collect();
        events.set_stream(&stream_id, dummy);

        let err = read_expected_version(&*events, &stream_id, true)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("200-event cap"));
    }

    #[tokio::test]
    async fn cap_not_enforced_allows_oversized_stream() {
        let events = Arc::new(MockEventStore::new());
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);

        // MockEventStore returns up to max_count events, so 201 events
        // with read limit 201 returns all 201 — last position is 200.
        let dummy: Vec<_> = (0..201)
            .map(|i| dummy_persisted_event(&stream_id, artifact_id, i))
            .collect();
        events.set_stream(&stream_id, dummy);

        let version = read_expected_version(&*events, &stream_id, false)
            .await
            .unwrap();
        assert_eq!(version, ExpectedVersion::Exact(200));
    }

    #[tokio::test]
    async fn cap_at_exactly_200_is_allowed() {
        let events = Arc::new(MockEventStore::new());
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);

        let dummy: Vec<_> = (0..200)
            .map(|i| dummy_persisted_event(&stream_id, artifact_id, i))
            .collect();
        events.set_stream(&stream_id, dummy);

        let version = read_expected_version(&*events, &stream_id, true)
            .await
            .unwrap();
        assert_eq!(version, ExpectedVersion::Exact(199));
    }

    /// Issue #88 structural guard: `read_expected_version`'s capped
    /// forward-scan is only a correct version source for the bounded
    /// per-artifact stream. Any other category must be rejected up
    /// front — pinning this is the "fails if a future caller derives a
    /// version from a capped read [on an unbounded stream]" acceptance
    /// criterion. No I/O happens: the mock is never seeded, so a
    /// passing test also proves the guard fires BEFORE the read.
    #[tokio::test]
    async fn rejects_non_artifact_stream_category() {
        let events = Arc::new(MockEventStore::new());
        let stream_id = StreamId::user(Uuid::new_v4());

        let err = read_expected_version(&*events, &stream_id, false)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("non-artifact stream"), "got {err}");
        assert_eq!(
            events.read_stream_call_count(),
            0,
            "the category guard must fire before any read_stream I/O"
        );
    }
}

#[cfg(test)]
mod read_artifact_stream_tests {
    use std::sync::Arc;

    use hort_domain::events::StreamId;

    use super::*;
    use crate::use_cases::test_support::*;

    fn seed(events: &Arc<MockEventStore>, artifact_id: Uuid, count: u64) -> StreamId {
        let stream_id = StreamId::artifact(artifact_id);
        let dummy: Vec<_> = (0..count)
            .map(|i| dummy_persisted_event(&stream_id, artifact_id, i))
            .collect();
        events.set_stream(&stream_id, dummy);
        stream_id
    }

    #[tokio::test]
    async fn empty_stream_reads_as_empty() {
        let events = Arc::new(MockEventStore::new());
        let stream_id = StreamId::artifact(Uuid::new_v4());

        let stream = read_artifact_stream(&*events, &stream_id).await.unwrap();
        assert!(stream.is_empty());
    }

    #[tokio::test]
    async fn short_stream_reads_completely() {
        let events = Arc::new(MockEventStore::new());
        let artifact_id = Uuid::new_v4();
        let stream_id = seed(&events, artifact_id, 3);

        let stream = read_artifact_stream(&*events, &stream_id).await.unwrap();
        assert_eq!(stream.len(), 3);
    }

    /// The boundary that decides "complete": a stream of exactly
    /// [`STREAM_EVENT_CAP`] events is read in full, because the `+ 1`
    /// budget was not exhausted — the read provably saw the tail.
    #[tokio::test]
    async fn stream_at_exactly_the_cap_reads_completely() {
        let events = Arc::new(MockEventStore::new());
        let artifact_id = Uuid::new_v4();
        let stream_id = seed(&events, artifact_id, STREAM_EVENT_CAP);

        let stream = read_artifact_stream(&*events, &stream_id).await.unwrap();
        assert_eq!(stream.len() as u64, STREAM_EVENT_CAP);
        assert_eq!(
            stream.last().unwrap().stream_position,
            STREAM_EVENT_CAP - 1,
            "the last event read must be the stream's true tail"
        );
    }

    /// One event past the cap and the read can no longer prove it reached
    /// the tail, so it refuses instead of handing back the oldest prefix.
    /// This is the whole point: a caller that reverse-scans the prefix
    /// would read a superseded verdict as the current one.
    #[tokio::test]
    async fn stream_past_the_cap_is_refused_not_truncated() {
        let events = Arc::new(MockEventStore::new());
        let artifact_id = Uuid::new_v4();
        let stream_id = seed(&events, artifact_id, STREAM_EVENT_CAP + 1);

        let err = read_artifact_stream(&*events, &stream_id)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("200-event cap"),
            "the refusal must name the cap it is enforcing; got {err}"
        );
    }

    /// A capped full-stream read is only correct for a stream the cap
    /// bounds. Rejecting any other category up front is what keeps a
    /// future unbounded-category caller from silently reading a prefix —
    /// the same guard `read_expected_version` carries for the same reason.
    #[tokio::test]
    async fn rejects_non_artifact_stream_category() {
        let events = Arc::new(MockEventStore::new());
        let stream_id = StreamId::user(Uuid::new_v4());

        let err = read_artifact_stream(&*events, &stream_id)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("non-artifact stream"), "got {err}");
        assert_eq!(
            events.read_stream_call_count(),
            0,
            "the category guard must fire before any read_stream I/O"
        );
    }
}

#[cfg(test)]
mod append_any_with_conflict_retry_tests {
    use std::sync::Arc;

    use chrono::Utc;
    use uuid::Uuid;

    use hort_domain::events::{system_actor, AuthenticationAttempted, DomainEvent, StreamId};
    use hort_domain::ports::event_store::{AppendEvents, EventToAppend, ExpectedVersion};

    use super::*;
    use crate::use_cases::test_support::*;

    fn dummy_event() -> DomainEvent {
        DomainEvent::AuthenticationAttempted(AuthenticationAttempted {
            client_ip: "127.0.0.1".parse().unwrap(),
            result: "local_invalid_credentials".into(),
            external_id_if_decoded: None,
            at: Utc::now(),
        })
    }

    fn no_op_backoff(_attempt: u32) -> StdDuration {
        StdDuration::ZERO
    }

    fn make_batch(stream_id: StreamId, event: DomainEvent, correlation_id: Uuid) -> AppendEvents {
        AppendEvents {
            stream_id,
            expected_version: ExpectedVersion::Any,
            events: vec![EventToAppend::new(event)],
            correlation_id,
            causation_id: None,
            actor: system_actor(),
        }
    }

    /// A single conflict is absorbed transparently — the second attempt
    /// (a fresh, byte-identical `AppendEvents`) succeeds.
    #[tokio::test]
    async fn retries_once_on_conflict() {
        let events = Arc::new(MockEventStore::new());
        events.fail_next_append(DomainError::Conflict("concurrent append".into()));
        let stream_id = StreamId::user(Uuid::new_v4());
        let event = dummy_event();
        let correlation_id = Uuid::new_v4();

        append_any_with_conflict_retry(&*events, 5, no_op_backoff, || {
            make_batch(stream_id.clone(), event.clone(), correlation_id)
        })
        .await
        .expect("a single conflict must be absorbed by the retry loop");

        assert_eq!(
            events.appended_batches().len(),
            1,
            "the winning append must land exactly once, not twice"
        );
    }

    /// Pathological contention — every attempt conflicts. The bounded
    /// loop must exhaust at `attempts` and return the final `Conflict`
    /// verbatim (never masked, never turned into a different variant).
    #[tokio::test]
    async fn exhausts_after_bound_and_returns_final_conflict() {
        let events = Arc::new(MockEventStore::new());
        events.fail_all_appends(DomainError::Conflict("concurrent append".into()));
        let stream_id = StreamId::user(Uuid::new_v4());
        let event = dummy_event();
        let correlation_id = Uuid::new_v4();

        let err = append_any_with_conflict_retry(&*events, 3, no_op_backoff, || {
            make_batch(stream_id.clone(), event.clone(), correlation_id)
        })
        .await
        .expect_err("every attempt conflicting must exhaust the retry budget");

        assert!(matches!(err, DomainError::Conflict(_)), "got {err:?}");
        assert!(events.appended_batches().is_empty());
    }

    /// A non-`Conflict` error fails fast on the FIRST attempt — no
    /// retry, no budget consumed.
    #[tokio::test]
    async fn non_conflict_error_does_not_retry() {
        let events = Arc::new(MockEventStore::new());
        events.fail_next_append(DomainError::Invariant("event store down".into()));
        let stream_id = StreamId::user(Uuid::new_v4());
        let event = dummy_event();
        let correlation_id = Uuid::new_v4();

        let err = append_any_with_conflict_retry(&*events, 5, no_op_backoff, || {
            make_batch(stream_id.clone(), event.clone(), correlation_id)
        })
        .await
        .expect_err("a non-Conflict error must propagate immediately");

        assert!(matches!(err, DomainError::Invariant(_)), "got {err:?}");
        assert!(events.appended_batches().is_empty());
    }

    /// `event_append_backoff`'s documented shape: 10/40/160/640ms
    /// across attempts 1..4, monotonically increasing.
    #[test]
    fn event_append_backoff_matches_documented_schedule() {
        let ms = |d: StdDuration| d.as_millis() as u64;
        assert!((10..=20).contains(&ms(event_append_backoff(1))));
        assert!((40..=50).contains(&ms(event_append_backoff(2))));
        assert!((160..=170).contains(&ms(event_append_backoff(3))));
        assert!((640..=650).contains(&ms(event_append_backoff(4))));
    }
}

#[cfg(test)]
mod caller_privileges_tests {
    use super::*;
    use uuid::Uuid;

    fn admin_privileges() -> CallerPrivileges {
        CallerPrivileges {
            is_admin: true,
            is_reviewer: false,
            is_curator: false,
            writable_repository_ids: vec![],
        }
    }

    fn reviewer_privileges() -> CallerPrivileges {
        CallerPrivileges {
            is_admin: false,
            is_reviewer: true,
            is_curator: false,
            writable_repository_ids: vec![],
        }
    }

    fn curator_privileges() -> CallerPrivileges {
        CallerPrivileges {
            is_admin: false,
            is_reviewer: false,
            is_curator: true,
            writable_repository_ids: vec![],
        }
    }

    fn unprivileged() -> CallerPrivileges {
        CallerPrivileges {
            is_admin: false,
            is_reviewer: false,
            is_curator: false,
            writable_repository_ids: vec![],
        }
    }

    #[test]
    fn require_admin_with_admin() {
        admin_privileges().require_admin().unwrap();
    }

    #[test]
    fn require_admin_without_admin() {
        let err = unprivileged().require_admin().unwrap_err();
        assert!(err.to_string().contains("admin"));
    }

    #[test]
    fn require_reviewer_with_reviewer() {
        reviewer_privileges().require_reviewer().unwrap();
    }

    #[test]
    fn require_reviewer_admin_implies_reviewer() {
        admin_privileges().require_reviewer().unwrap();
    }

    #[test]
    fn require_reviewer_without_privilege() {
        let err = unprivileged().require_reviewer().unwrap_err();
        assert!(err.to_string().contains("reviewer"));
    }

    #[test]
    fn require_write_access_with_matching_repo() {
        let repo_id = Uuid::new_v4();
        let privs = CallerPrivileges {
            is_admin: false,
            is_reviewer: false,
            is_curator: false,
            writable_repository_ids: vec![repo_id],
        };
        privs.require_write_access(repo_id).unwrap();
    }

    #[test]
    fn require_write_access_without_matching_repo() {
        let err = unprivileged()
            .require_write_access(Uuid::new_v4())
            .unwrap_err();
        assert!(err.to_string().contains("write access"));
    }

    #[test]
    fn require_write_access_admin_has_global_write() {
        admin_privileges()
            .require_write_access(Uuid::new_v4())
            .unwrap();
    }

    // -- require_curate_or_admin --------------------------------------------

    /// Curator-only caller is accepted: this is the day-to-day path the
    /// curate role exists to gate (waive / block / finding-exclusion).
    #[test]
    fn require_curate_or_admin_with_curator() {
        curator_privileges().require_curate_or_admin().unwrap();
    }

    /// Admin caller is accepted: `Admin` is a superset of `Curate` by
    /// design; an admin should not need to also carry the curator
    /// permission to perform a curator action.
    #[test]
    fn require_curate_or_admin_with_admin() {
        admin_privileges().require_curate_or_admin().unwrap();
    }

    /// Caller holding both (e.g. operator with both grants) is still
    /// accepted — the OR semantics are short-circuit on either flag.
    #[test]
    fn require_curate_or_admin_with_both() {
        let privs = CallerPrivileges {
            is_admin: true,
            is_reviewer: false,
            is_curator: true,
            writable_repository_ids: vec![],
        };
        privs.require_curate_or_admin().unwrap();
    }

    /// Neither flag set → denial. Mirrors the `require_admin_without_admin`
    /// shape: an `AppError::Domain(DomainError::Forbidden(_))` whose
    /// message mentions the required authority.
    #[test]
    fn require_curate_or_admin_without_either_denies() {
        let err = unprivileged().require_curate_or_admin().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("curate") || msg.contains("admin"),
            "denial message must name the required authority, got: {msg}"
        );
    }

    /// Reviewer privilege alone does NOT confer curator authority:
    /// reviewer is the approval-flow role, curator is the
    /// quarantine / finding-exclusion role — distinct
    /// permissions, distinct grants. A reviewer must not silently
    /// bypass `require_curate_or_admin`.
    #[test]
    fn require_curate_or_admin_reviewer_alone_does_not_pass() {
        let err = reviewer_privileges().require_curate_or_admin().unwrap_err();
        assert!(err.to_string().contains("curate") || err.to_string().contains("admin"));
    }
}
