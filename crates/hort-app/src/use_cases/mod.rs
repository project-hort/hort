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
/// The repository-visibility primitive shared by the
/// `GET /api/v1/events` read gate and the subscription delivery filter.
/// Both consult it; neither re-derives it.
pub mod event_visibility;
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

use hort_domain::entities::artifact::Artifact;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::{PersistedEvent, StreamCategory, StreamId};
use hort_domain::ports::artifact_repository::ArtifactRepository;
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
/// - **Write side.** [`read_unpaired_append_version`] refuses to derive an
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

/// One capped `ReadFrom::Start` read of a bounded artifact stream, plus
/// the one fact a capped read cannot do without: whether its budget was
/// exhausted.
///
/// This is the **only** bounded `EventStore::read_stream` in production
/// code (pinned by the `capped_stream_reads` structural guard). Every
/// question asked of an artifact's stream — the latest `ScanCompleted`
/// and whether an `ArtifactRejected` followed it, whether a
/// `ProvenanceVerified` exists, what version the next append must
/// carry — is answered from a value produced here.
#[derive(Debug)]
struct CappedArtifactRead {
    /// The events the read returned, truncated to the budget.
    events: Vec<PersistedEvent>,
    /// `true` when more than [`STREAM_EVENT_CAP`] events came back: the
    /// budget was exhausted, so neither `events` nor the position derived
    /// from its tail can be trusted to describe the end of the stream.
    over_cap: bool,
}

impl CappedArtifactRead {
    /// The `ExpectedVersion` an append ordered immediately after this
    /// read must carry. `NoStream` for an empty stream, otherwise
    /// `Exact(tail position)`.
    ///
    /// On an over-cap read this is the position of the prefix's last
    /// event, not the stream's true tail — which is why the two version
    /// consumers decide for themselves whether to accept one (see
    /// [`read_unpaired_append_version`]'s `enforce_cap` and
    /// [`OverCapStream`]).
    fn expected_version(&self) -> ExpectedVersion {
        match self.events.last() {
            Some(last) => ExpectedVersion::Exact(last.stream_position),
            None => ExpectedVersion::NoStream,
        }
    }
}

/// Read a bounded artifact stream with overflow detection.
///
/// Rejects any non-[`StreamCategory::Artifact`] `stream_id` before doing
/// any I/O: a capped forward scan is only correct for a stream that is
/// bounded by design, and today that is exclusively the per-artifact
/// lifecycle stream. An unbounded-category caller that derived a version
/// from such a read would get a STALE position the moment the stream
/// passed the budget, and every subsequent `ExpectedVersion::Exact`
/// append would then fail `Conflict` deterministically and permanently
/// (the production instance was the per-user `ApiTokenIssued` stream).
/// Such a caller must use `ExpectedVersion::Any` +
/// [`append_any_with_conflict_retry`] instead — which the audit of every
/// unbounded-stream caller found sufficient, because none of them
/// protects a decision made from the stream's content.
///
/// This is a deliberate, narrower alternative to adding a true-tail read
/// to the `EventStore` port: a port addition would have to be
/// implemented by every mock in the workspace, for a capability no
/// audited caller needs.
async fn capped_artifact_read(
    events: &dyn EventStore,
    stream_id: &StreamId,
) -> AppResult<CappedArtifactRead> {
    if stream_id.category != StreamCategory::Artifact {
        return Err(DomainError::Invariant(format!(
            "capped artifact-stream read called on non-artifact stream \
             {stream_id} (category {:?}) — capped forward-scan version \
             derivation and full-stream reads are only correct for the \
             bounded per-artifact lifecycle stream; use \
             ExpectedVersion::Any + append_any_with_conflict_retry for any \
             other (unbounded) stream category",
            stream_id.category
        ))
        .into());
    }

    let stream_events = events
        .read_stream(stream_id, ReadFrom::Start, STREAM_EVENT_CAP + 1)
        .await?;

    Ok(CappedArtifactRead {
        over_cap: stream_events.len() as u64 > STREAM_EVENT_CAP,
        events: stream_events,
    })
}

/// The refusal an over-cap artifact stream earns when a decision was
/// going to be derived from it.
fn over_cap_refusal(stream_id: &StreamId) -> AppError {
    DomainError::Invariant(format!(
        "stream {stream_id} exceeds the {STREAM_EVENT_CAP}-event cap — \
         a capped read cannot prove it reached the tail, so no decision \
         is derived from it"
    ))
    .into()
}

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
/// So the read underneath reads [`STREAM_EVENT_CAP`] `+ 1` events,
/// making the two cases distinguishable, and this helper refuses the
/// second:
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
///
/// **Reading the stream here and the append version separately is the
/// wrong order when a decision sits between the two.** Use
/// [`ArtifactAtVersion`] for that; see its contract. This helper is for
/// the readers that derive no append from what they read.
pub(crate) async fn read_artifact_stream(
    events: &dyn EventStore,
    stream_id: &StreamId,
) -> AppResult<Vec<PersistedEvent>> {
    let read = capped_artifact_read(events, stream_id).await?;
    if read.over_cap {
        return Err(over_cap_refusal(stream_id));
    }
    Ok(read.events)
}

/// Why a call site derives an append version **without** having read the
/// artifact's stored evidence — the mandatory witness
/// [`read_unpaired_append_version`] takes.
///
/// The pairing ([`ArtifactAtVersion`]) is the normal form for an artifact
/// append, and this type exists so the exception is *stated* rather than
/// merely spelled the same way. Before it, the paired and the unpaired
/// read were one function with one name, and the legitimate unpaired
/// sites were indistinguishable — to a reader and to a structural guard
/// — from a site that had read the evidence and then went looking for a
/// version. Naming the exception is what removes the innocent spelling:
/// a caller holding evidence cannot reach this function without
/// asserting one of the claims below, and none of them is true of it.
///
/// None of the variants is read at runtime. That is the point: it is a
/// declaration by the call site, checked by review and by the reader,
/// not a branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnpairedAppend {
    /// The artifact was minted in this call and its stream does not
    /// exist yet, so there is no stored evidence to pair with: the
    /// genesis event is the stream's first.
    GenesisAppend,
    /// A follow-up append on a stream **this same call** created, whose
    /// content is derived from resolved configuration rather than from
    /// anything on the stream. Nothing a previous writer put there is
    /// read, because there is no previous writer.
    SameCallFollowUp,
    /// Every appended event's content comes from the caller's request.
    /// The stream is not consulted, so there is no decision for the
    /// version to protect beyond "this append is ordered after whatever
    /// is there now".
    CallerSuppliedPayload,
}

/// Read a stream's current position and compute the `ExpectedVersion` for
/// the next append — for an append that protects **no decision read from
/// the stream**, which the caller declares via `unpaired_because`.
///
/// When `enforce_cap` is true, returns `DomainError::Conflict` if the stream
/// exceeds [`STREAM_EVENT_CAP`] events.
///
/// Rejects any non-[`StreamCategory::Artifact`] stream — see
/// [`capped_artifact_read`] for why, and for what an unbounded-stream
/// caller must do instead.
///
/// # This is the exception, not the default
///
/// **This helper is correct only where nothing the append protects was
/// read before it.** The moment a decision is derived from state read
/// earlier — the artifact row, the stream's own events, a findings blob
/// — the version has to be read beside that state, not after it, or the
/// append silently stops protecting the decision. [`ArtifactAtVersion`]
/// is that pairing and carries the full contract; this helper remains
/// for the appends that protect no such decision.
///
/// The name and the [`UnpairedAppend`] witness are load-bearing. A type
/// cannot stop a new site from declining to use it, and a source scan
/// cannot see a stream read that happened in another file — so the thing
/// that has to be impossible is reaching this function *innocently*. A
/// caller that read an artifact's evidence (directly, or through a
/// read-path helper such as
/// [`release_clearance::read_path_provenance_clearance`](crate::use_cases::release_clearance::read_path_provenance_clearance))
/// and then wants a version has to name one of the witness's claims to
/// get one, and each of them is false for it. The same applies to a
/// caller that took a pairing via [`read_artifact_stream_at_version`],
/// discarded its version and came here for a fresh one.
pub(crate) async fn read_unpaired_append_version(
    events: &dyn EventStore,
    stream_id: &StreamId,
    enforce_cap: bool,
    unpaired_because: UnpairedAppend,
) -> AppResult<ExpectedVersion> {
    // Declared by the call site, not consulted here — see
    // `UnpairedAppend`. Named (rather than `_`-prefixed) so the
    // parameter reads as a required argument wherever the signature is
    // shown; discarded here because reading it would turn a declaration
    // into a branch.
    let _ = unpaired_because;
    let read = capped_artifact_read(events, stream_id).await?;

    if enforce_cap && read.over_cap {
        return Err(DomainError::Conflict(format!(
            "stream {stream_id} exceeds {STREAM_EVENT_CAP}-event cap"
        ))
        .into());
    }

    Ok(read.expected_version())
}

/// Read an artifact stream in full **and** the `ExpectedVersion` an
/// append ordered immediately after it must carry — one observation, for
/// a caller that decides from the stream but needs no artifact row.
///
/// This is [`ArtifactAtVersion`] minus the artifact, and it exists for
/// the same reason: deriving the version from a *second* read of the
/// stream the decision came from reopens the window that read closed.
/// Both values come out of one call, so there is no order to get wrong.
/// Refuses an over-cap stream exactly as [`read_artifact_stream`] does —
/// a caller here is deriving a decision from the events, so a prefix is
/// never an acceptable answer.
pub(crate) async fn read_artifact_stream_at_version(
    events: &dyn EventStore,
    stream_id: &StreamId,
) -> AppResult<(Vec<PersistedEvent>, ExpectedVersion)> {
    let read = capped_artifact_read(events, stream_id).await?;
    if read.over_cap {
        return Err(over_cap_refusal(stream_id));
    }
    let expected_version = read.expected_version();
    Ok((read.events, expected_version))
}

/// What an [`ArtifactAtVersion`] pairing does when the stream it read
/// breached [`STREAM_EVENT_CAP`] — i.e. when the read's budget was
/// exhausted and it cannot prove it reached the tail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OverCapStream {
    /// Refuse the pairing with [`DomainError::Conflict`]. For a site
    /// whose append must not even be attempted against a stream of
    /// unknown length.
    Refuse,
    /// Pair anyway, with a version derived from the prefix's tail. The
    /// append that carries it then fails `Conflict` against the true
    /// tail, so the outcome is the same refusal one round trip later —
    /// which is what the sites choosing this already observed before the
    /// pairing existed.
    ///
    /// [`ArtifactAtVersion::evidence`] still refuses: tolerating an
    /// unprovable *version* is fail-closed (the append loses), while
    /// deriving a decision from an unprovable *prefix* is fail-open.
    Tolerate,
}

/// An artifact, the complete event stream it was read with, and the
/// `ExpectedVersion` the next append must carry — **one observation, not
/// a read per question**.
///
/// # The contract
///
/// A site that decides an artifact's lifecycle outcome from stored
/// evidence and commits that decision behind an optimistic append has
/// exactly one correct order: read the expected stream version **beside**
/// the state the decision rests on, then derive, then append.
///
/// Read the version *after* deriving and the append stops protecting the
/// decision. A verdict that committed in the window — a `ScanCompleted`
/// plus the `ArtifactRejected` it drove, an admin release, a curator
/// block — is already contained in the version just read. So the append
/// does **not** conflict, it succeeds, and the paired projection write
/// puts the stale decision's status over the newer one: an artifact
/// released on evidence that a later scan already superseded, or an
/// artifact re-held over a clean verdict that landed after the evidence
/// was read. The window is not theoretical — it is as long as whatever
/// sits between the two reads: a policy and exclusion-set resolution, a
/// findings-blob fetch from CAS, a signature-bundle round trip to an
/// upstream, a per-artifact event append on another stream.
///
/// This type makes that order the only expressible one. The evidence and
/// the version come back from **the same single capped read**, so there
/// is no "before" left to get wrong: a caller holding the evidence
/// necessarily already holds the version that read proves, and a caller
/// that wants fresher evidence has to take a fresh pairing, which moves
/// the version with it. Deriving a decision from an artifact stream read
/// any other way — a bare [`read_artifact_stream`] next to a bare
/// [`read_unpaired_append_version`] — is going around this type, and is the
/// defect it exists to prevent.
///
/// # Error handling is the caller's
///
/// Constructing a pairing can fail (the stream read, the artifact load).
/// What that failure means is deliberately **not** uniform: a
/// single-artifact job propagates it so the dispatcher retries rather
/// than silently dropping a result, while a bulk population pass logs
/// and skips that artifact so one bad row never aborts the pass. Both
/// shapes are correct for their caller; neither belongs here.
#[derive(Debug)]
pub(crate) struct ArtifactAtVersion {
    artifact: Artifact,
    /// The capped read's events, and whether its budget was exhausted —
    /// the pair [`Self::evidence`] needs to refuse honestly.
    read: CappedArtifactRead,
    stream_id: StreamId,
    expected_version: ExpectedVersion,
}

impl ArtifactAtVersion {
    /// Pair a fresh artifact load with its stream version and evidence.
    ///
    /// The version read comes **first**, before the artifact row is
    /// loaded. A concurrent event landing between the two is then in the
    /// loaded artifact but not in the version, so the append loses —
    /// fail-closed. The reverse order is the fail-open one this type
    /// exists to remove.
    pub(crate) async fn load(
        artifacts: &dyn ArtifactRepository,
        events: &dyn EventStore,
        artifact_id: Uuid,
        over_cap: OverCapStream,
    ) -> AppResult<Self> {
        let stream_id = StreamId::artifact(artifact_id);
        let read = Self::read_or_refuse(events, &stream_id, over_cap).await?;
        let artifact = artifacts
            .find_by_id(artifact_id)
            .await
            .map_err(AppError::Domain)?;
        Ok(Self::assemble(artifact, stream_id, read))
    }

    /// Pair an artifact the caller already holds — a row from a bulk
    /// list page — with a stream version and evidence read now.
    ///
    /// The artifact row is as old as the page it came from; the pairing
    /// does not refresh it, because refreshing would change *what* the
    /// site decides. What it does fix is that everything the site reads
    /// for itself from here on — the evidence — shares one observation
    /// with the version its append will carry.
    pub(crate) async fn pair(
        events: &dyn EventStore,
        artifact: Artifact,
        over_cap: OverCapStream,
    ) -> AppResult<Self> {
        let stream_id = StreamId::artifact(artifact.id);
        let read = Self::read_or_refuse(events, &stream_id, over_cap).await?;
        Ok(Self::assemble(artifact, stream_id, read))
    }

    async fn read_or_refuse(
        events: &dyn EventStore,
        stream_id: &StreamId,
        over_cap: OverCapStream,
    ) -> AppResult<CappedArtifactRead> {
        let read = capped_artifact_read(events, stream_id).await?;
        if read.over_cap && over_cap == OverCapStream::Refuse {
            return Err(DomainError::Conflict(format!(
                "stream {stream_id} exceeds {STREAM_EVENT_CAP}-event cap"
            ))
            .into());
        }
        Ok(read)
    }

    fn assemble(artifact: Artifact, stream_id: StreamId, read: CappedArtifactRead) -> Self {
        let expected_version = read.expected_version();
        Self {
            artifact,
            read,
            stream_id,
            expected_version,
        }
    }

    /// The artifact as loaded.
    pub(crate) fn artifact(&self) -> &Artifact {
        &self.artifact
    }

    /// The artifact, mutable — the domain transitions take `&mut self`
    /// and mutate the entity as they produce their event.
    pub(crate) fn artifact_mut(&mut self) -> &mut Artifact {
        &mut self.artifact
    }

    /// The `ExpectedVersion` for an append that commits a decision
    /// derived from [`Self::evidence`] (or from the artifact paired with
    /// it). Carrying it is what makes a verdict committed since the
    /// pairing fail this append instead of being overwritten by it.
    pub(crate) fn expected_version(&self) -> ExpectedVersion {
        self.expected_version
    }

    /// The artifact's stream in full — the evidence any decision at this
    /// site rests on.
    ///
    /// Refuses with [`DomainError::Invariant`] when the stream breached
    /// [`STREAM_EVENT_CAP`], for exactly the reason
    /// [`read_artifact_stream`] refuses: a reverse scan over a truncated
    /// prefix answers about the *oldest* events while looking like an
    /// answer about the latest, so a superseded verdict reads as current.
    /// The refusal holds even under [`OverCapStream::Tolerate`], which
    /// only ever tolerated an unprovable *version*.
    pub(crate) fn evidence(&self) -> AppResult<&[PersistedEvent]> {
        if self.read.over_cap {
            return Err(over_cap_refusal(&self.stream_id));
        }
        Ok(&self.read.events)
    }

    /// The artifact's stream id — the stream an append built from this
    /// pairing must target.
    pub(crate) fn stream_id(&self) -> &StreamId {
        &self.stream_id
    }

    /// Take the artifact back out, dropping the pairing. For the commit
    /// step, which hands the mutated entity to the lifecycle port.
    pub(crate) fn into_artifact(self) -> Artifact {
        self.artifact
    }
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
mod read_unpaired_append_version_tests {
    use std::sync::Arc;

    use hort_domain::events::StreamId;
    use hort_domain::ports::event_store::ExpectedVersion;

    use super::*;
    use crate::use_cases::test_support::*;

    #[tokio::test]
    async fn empty_stream_returns_no_stream() {
        let events = Arc::new(MockEventStore::new());
        let stream_id = StreamId::artifact(Uuid::new_v4());

        let version = read_unpaired_append_version(
            &*events,
            &stream_id,
            false,
            UnpairedAppend::GenesisAppend,
        )
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

        let version = read_unpaired_append_version(
            &*events,
            &stream_id,
            false,
            UnpairedAppend::GenesisAppend,
        )
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

        let err =
            read_unpaired_append_version(&*events, &stream_id, true, UnpairedAppend::GenesisAppend)
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

        let version = read_unpaired_append_version(
            &*events,
            &stream_id,
            false,
            UnpairedAppend::GenesisAppend,
        )
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

        let version =
            read_unpaired_append_version(&*events, &stream_id, true, UnpairedAppend::GenesisAppend)
                .await
                .unwrap();
        assert_eq!(version, ExpectedVersion::Exact(199));
    }

    /// Structural guard: `read_unpaired_append_version`'s capped
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

        let err = read_unpaired_append_version(
            &*events,
            &stream_id,
            false,
            UnpairedAppend::GenesisAppend,
        )
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
    /// the same guard `read_unpaired_append_version` carries for the same
    /// reason.
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

#[cfg(test)]
mod artifact_at_version_tests {
    use std::sync::Arc;

    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::events::StreamId;
    use hort_domain::ports::event_store::ExpectedVersion;

    use super::*;
    use crate::use_cases::test_support::*;

    /// Seed `count` events on `artifact_id`'s stream and return the id.
    fn seed_stream(events: &Arc<MockEventStore>, artifact_id: Uuid, count: u64) -> StreamId {
        let stream_id = StreamId::artifact(artifact_id);
        let dummy: Vec<_> = (0..count)
            .map(|i| dummy_persisted_event(&stream_id, artifact_id, i))
            .collect();
        events.set_stream(&stream_id, dummy);
        stream_id
    }

    fn seeded_artifact(artifacts: &Arc<MockArtifactRepository>) -> Uuid {
        let artifact = sample_artifact(QuarantineStatus::Quarantined);
        let id = artifact.id;
        artifacts.insert(artifact);
        id
    }

    /// The defining property: the artifact, the evidence and the append
    /// version come from **one** observation. One `read_stream` call
    /// serves all three, so there is no window between the evidence a
    /// decision is derived from and the version that protects it.
    #[tokio::test]
    async fn one_read_serves_the_artifact_the_evidence_and_the_version() {
        let events = Arc::new(MockEventStore::new());
        let artifacts = Arc::new(MockArtifactRepository::new());
        let artifact_id = seeded_artifact(&artifacts);
        seed_stream(&events, artifact_id, 3);

        let paired =
            ArtifactAtVersion::load(&*artifacts, &*events, artifact_id, OverCapStream::Tolerate)
                .await
                .unwrap();

        assert_eq!(paired.artifact().id, artifact_id);
        assert_eq!(paired.evidence().unwrap().len(), 3);
        assert_eq!(paired.expected_version(), ExpectedVersion::Exact(2));
        assert_eq!(paired.stream_id(), &StreamId::artifact(artifact_id));
        assert_eq!(
            events.read_stream_call_count(),
            1,
            "two reads would be two observations, which is the defect"
        );
    }

    /// An empty stream pairs as `NoStream` with no evidence.
    #[tokio::test]
    async fn empty_stream_pairs_as_no_stream() {
        let events = Arc::new(MockEventStore::new());
        let artifacts = Arc::new(MockArtifactRepository::new());
        let artifact_id = seeded_artifact(&artifacts);

        let paired =
            ArtifactAtVersion::load(&*artifacts, &*events, artifact_id, OverCapStream::Tolerate)
                .await
                .unwrap();

        assert_eq!(paired.expected_version(), ExpectedVersion::NoStream);
        assert!(paired.evidence().unwrap().is_empty());
    }

    /// The version read comes FIRST, before the artifact row is loaded:
    /// an event landing between the two is then in the artifact but not
    /// in the version, so the append loses — fail-closed. The reverse
    /// order is the fail-open one.
    ///
    /// Observable here as: the stream read has already happened when the
    /// artifact load fails.
    #[tokio::test]
    async fn the_version_is_read_before_the_artifact_row() {
        let events = Arc::new(MockEventStore::new());
        // No artifact seeded → `find_by_id` fails.
        let artifacts = Arc::new(MockArtifactRepository::new());
        let artifact_id = Uuid::new_v4();
        seed_stream(&events, artifact_id, 2);

        let err =
            ArtifactAtVersion::load(&*artifacts, &*events, artifact_id, OverCapStream::Tolerate)
                .await
                .unwrap_err();

        assert!(
            matches!(err, AppError::Domain(DomainError::NotFound { .. })),
            "got {err}"
        );
        assert_eq!(
            events.read_stream_call_count(),
            1,
            "the stream read must already have happened when the load failed"
        );
    }

    /// A read failure surfaces verbatim — what the caller does with it
    /// (propagate or skip) is deliberately not decided here.
    #[tokio::test]
    async fn a_stream_read_failure_surfaces() {
        let events = Arc::new(MockEventStore::new());
        let artifacts = Arc::new(MockArtifactRepository::new());
        let artifact_id = seeded_artifact(&artifacts);
        events.fail_next_read_stream(DomainError::Invariant("event store down".into()));

        let err =
            ArtifactAtVersion::load(&*artifacts, &*events, artifact_id, OverCapStream::Tolerate)
                .await
                .unwrap_err();
        assert!(err.to_string().contains("event store down"));
    }

    /// `pair` takes an artifact the caller already holds (a bulk list
    /// page's row) and reads the stream once for the version and the
    /// evidence. The row is NOT refreshed — refreshing would change what
    /// the site decides.
    #[tokio::test]
    async fn pair_uses_the_callers_row_and_reads_the_stream_once() {
        let events = Arc::new(MockEventStore::new());
        let mut artifact = sample_artifact(QuarantineStatus::Released);
        artifact.name = "from-the-page".into();
        let artifact_id = artifact.id;
        seed_stream(&events, artifact_id, 5);

        let paired = ArtifactAtVersion::pair(&*events, artifact, OverCapStream::Tolerate)
            .await
            .unwrap();

        assert_eq!(paired.artifact().name, "from-the-page");
        assert_eq!(paired.expected_version(), ExpectedVersion::Exact(4));
        assert_eq!(events.read_stream_call_count(), 1);
    }

    /// `Refuse` rejects an over-cap stream at construction, with the
    /// `Conflict` the capping version callers have always produced.
    #[tokio::test]
    async fn refuse_rejects_an_over_cap_stream_with_conflict() {
        let events = Arc::new(MockEventStore::new());
        let artifacts = Arc::new(MockArtifactRepository::new());
        let artifact_id = seeded_artifact(&artifacts);
        seed_stream(&events, artifact_id, STREAM_EVENT_CAP + 1);

        let err =
            ArtifactAtVersion::load(&*artifacts, &*events, artifact_id, OverCapStream::Refuse)
                .await
                .unwrap_err();
        assert!(
            matches!(err, AppError::Domain(DomainError::Conflict(_))),
            "got {err}"
        );
        assert!(err.to_string().contains("200-event cap"));
    }

    /// A stream at exactly the cap is not over it — the `+ 1` budget was
    /// not exhausted, so the read provably reached the tail.
    #[tokio::test]
    async fn a_stream_at_exactly_the_cap_pairs_under_refuse() {
        let events = Arc::new(MockEventStore::new());
        let artifacts = Arc::new(MockArtifactRepository::new());
        let artifact_id = seeded_artifact(&artifacts);
        seed_stream(&events, artifact_id, STREAM_EVENT_CAP);

        let paired =
            ArtifactAtVersion::load(&*artifacts, &*events, artifact_id, OverCapStream::Refuse)
                .await
                .unwrap();
        assert_eq!(
            paired.expected_version(),
            ExpectedVersion::Exact(STREAM_EVENT_CAP - 1)
        );
        assert_eq!(paired.evidence().unwrap().len() as u64, STREAM_EVENT_CAP);
    }

    /// `Tolerate` pairs an over-cap stream — tolerating an unprovable
    /// *version* is fail-closed, since the append loses against the true
    /// tail — but `evidence` still refuses, because deriving a decision
    /// from an unprovable *prefix* is fail-open.
    #[tokio::test]
    async fn tolerate_yields_a_version_but_still_refuses_the_evidence() {
        let events = Arc::new(MockEventStore::new());
        let artifacts = Arc::new(MockArtifactRepository::new());
        let artifact_id = seeded_artifact(&artifacts);
        seed_stream(&events, artifact_id, STREAM_EVENT_CAP + 1);

        let paired =
            ArtifactAtVersion::load(&*artifacts, &*events, artifact_id, OverCapStream::Tolerate)
                .await
                .unwrap();

        assert_eq!(
            paired.expected_version(),
            ExpectedVersion::Exact(STREAM_EVENT_CAP),
            "the prefix's tail — stale against the real stream, so the \
             append loses"
        );
        let err = paired.evidence().unwrap_err();
        assert!(
            matches!(err, AppError::Domain(DomainError::Invariant(_))),
            "got {err}"
        );
        assert!(err.to_string().contains("200-event cap"));
    }

    /// The domain transitions mutate the entity as they produce their
    /// event, and the commit step hands the mutated entity on.
    #[tokio::test]
    async fn the_artifact_is_mutable_and_can_be_taken_back_out() {
        let events = Arc::new(MockEventStore::new());
        let artifacts = Arc::new(MockArtifactRepository::new());
        let artifact_id = seeded_artifact(&artifacts);
        seed_stream(&events, artifact_id, 1);

        let mut paired =
            ArtifactAtVersion::load(&*artifacts, &*events, artifact_id, OverCapStream::Tolerate)
                .await
                .unwrap();
        paired.artifact_mut().quarantine_status = QuarantineStatus::Released;

        let artifact = paired.into_artifact();
        assert_eq!(artifact.id, artifact_id);
        assert_eq!(artifact.quarantine_status, QuarantineStatus::Released);
    }

    /// The category guard fires before any I/O — a capped read is only a
    /// correct version source for the bounded per-artifact stream.
    #[tokio::test]
    async fn pair_rejects_a_non_artifact_stream_before_any_read() {
        let events = Arc::new(MockEventStore::new());
        let err = read_artifact_stream_at_version(&*events, &StreamId::user(Uuid::new_v4()))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("non-artifact stream"), "got {err}");
        assert_eq!(events.read_stream_call_count(), 0);
    }

    /// The artifact-less form of the pairing, for a caller that decides
    /// from the stream alone: both halves from one read.
    #[tokio::test]
    async fn stream_at_version_returns_both_halves_from_one_read() {
        let events = Arc::new(MockEventStore::new());
        let artifact_id = Uuid::new_v4();
        let stream_id = seed_stream(&events, artifact_id, 4);

        let (stream, version) = read_artifact_stream_at_version(&*events, &stream_id)
            .await
            .unwrap();
        assert_eq!(stream.len(), 4);
        assert_eq!(version, ExpectedVersion::Exact(3));
        assert_eq!(events.read_stream_call_count(), 1);
    }

    /// The artifact-less form refuses an over-cap stream outright: its
    /// caller is deriving a decision from the events, so a prefix is
    /// never an acceptable answer and a stale version is not worth
    /// returning beside one.
    #[tokio::test]
    async fn stream_at_version_refuses_an_over_cap_stream() {
        let events = Arc::new(MockEventStore::new());
        let artifact_id = Uuid::new_v4();
        let stream_id = seed_stream(&events, artifact_id, STREAM_EVENT_CAP + 1);

        let err = read_artifact_stream_at_version(&*events, &stream_id)
            .await
            .unwrap_err();
        assert!(
            matches!(err, AppError::Domain(DomainError::Invariant(_))),
            "got {err}"
        );
        assert!(err.to_string().contains("200-event cap"));
    }
}
