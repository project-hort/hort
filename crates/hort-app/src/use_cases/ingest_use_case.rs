use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use chrono::{DateTime, Utc};
use tokio::io::AsyncRead;
use uuid::Uuid;

use hort_domain::entities::artifact::{Artifact, ArtifactMetadata, QuarantineStatus};
use hort_domain::entities::scan_policy::{ProvenanceMode, ScanPolicyProjection};
use hort_domain::error::DomainError;
use hort_domain::events::{
    Actor, ApiActor, ArtifactIngested, ChecksumMismatch, ChecksumVerified, DomainEvent,
    IngestSource, PolicyScope, ScanRequested, StreamId,
};
use hort_domain::policy::curation::{evaluate_curation, CurationOutcome};
use hort_domain::policy::scan::DefaultPolicy;
use hort_domain::ports::artifact_lifecycle::{ArtifactLifecyclePort, IngestEnqueue};
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::content_reference_index::{ContentReference, ContentReferenceIndex};
use hort_domain::ports::curation_rule_repository::CurationRuleRepository;
use hort_domain::ports::event_store::{AppendEvents, EventStore, EventToAppend};

use crate::event_store_publisher::EventStorePublisher;
use hort_domain::ports::format_handler::{FormatHandler, MetadataStrategy};
use hort_domain::ports::jobs_repository::JobsRepository;
use hort_domain::ports::policy_projection_repository::PolicyProjectionRepository;
use hort_domain::ports::repository_repository::RepositoryRepository;
use hort_domain::ports::storage::StoragePort;
use hort_domain::types::checksum::{HashAlgorithm, UpstreamPublishedChecksum};
use hort_domain::types::{ArtifactCoords, ContentHash, PayloadAccess};
use tokio::io::AsyncReadExt;

use crate::error::{AppError, AppResult};
use crate::metrics::{
    emit_policy_evaluation, emit_policy_violations, emit_upstream_checksum, labels,
    policy_decision_point, values, IngestResult, PolicyEvaluationResult, UpstreamChecksumResult,
};
use crate::use_cases::artifact_group_use_case::ArtifactGroupUseCase;
use crate::use_cases::multi_hash::{
    Sha1DigestHandle, Sha1HashingRead, Sha512DigestHandle, Sha512HashingRead,
};
use crate::use_cases::read_expected_version;

/// Request payload for [`IngestUseCase::ingest`].
///
/// Bundled into a struct rather than positional arguments because the
/// parameter list had grown to eight (and was due to grow further for the
/// declared-hash reorder). A struct makes new fields read as first-class
/// concerns at each call site, avoids stacking
/// `#[allow(clippy::too_many_arguments)]` on public APIs, and eliminates
/// the arg-ordering mistakes that long positional lists invite.
///
/// `stream` is deliberately NOT on the struct. `Box<dyn AsyncRead + Send +
/// Unpin>` is not `Clone` and must be consumed by value; keeping it as a
/// separate argument makes that lifecycle explicit.
#[derive(Debug)]
pub struct IngestRequest {
    pub repository_id: Uuid,
    pub coords: ArtifactCoords,
    pub content_type: String,
    /// Seed-import quarantine anchor override.
    ///
    /// When `Some(anchor)`, the `register_by_hash` path appends an
    /// `ArtifactQuarantined` event with `quarantine_window_start =
    /// anchor` after the ingest commit lands. The
    /// `SeedImportUseCase` backdates the anchor so the *computed*
    /// deadline (`anchor + effective_duration`) is
    /// already at or before `now()`; the next sweep / scan-complete
    /// fast path can then release the artifact as soon as a clean
    /// scan lands.
    ///
    /// The `ingest_inner` path does NOT consume this field — every
    /// `ingest_inner` quarantine is policy-driven (operator
    /// `ScanPolicy.quarantineDuration` or
    /// [`DefaultPolicy::quarantine_duration_secs`]). The override is
    /// scoped to `register_by_hash`'s seed-import cutover only.
    ///
    /// `None` for every non-seed-import caller (OCI cross-mount,
    /// `ingest_verified_sha256_published`,
    /// `ingest_verified_sha512`). The field name `*_override` makes
    /// the seed-import semantics explicit at every call site.
    ///
    /// Removal of this field was
    /// re-examined and **rejected** because
    /// `register_existing_cas_blob` is a live consumer; re-propose
    /// removal only after the seed-import anchor path has been
    /// refactored to pass the anchor through `register_by_hash`'s
    /// own signature instead of riding `IngestRequest`.
    pub quarantine_anchor_override: Option<DateTime<Utc>>,
    pub actor: ApiActor,
    /// Optional SHA-1 hex — protocol-echo metadata for npm `dist.shasum`.
    /// Written onto the Artifact row in the same atomic `commit_transition`
    /// as the SHA-256; deliberately absent from the `ArtifactIngested`
    /// event payload.
    pub legacy_sha1: Option<String>,
    /// Optional MD5 hex — protocol-echo metadata (Maven etc.). Same storage
    /// and event-exclusion story as `legacy_sha1`.
    pub legacy_md5: Option<String>,
    /// Caller-declared SHA-256 of the content, when the protocol exposes it
    /// (PyPI multipart `sha256_digest`, cargo `cksum`, npm `dist.integrity`,
    /// Maven `.sha256` sidecar). Used to short-circuit duplicate and
    /// conflict decisions at the `find_by_path` step — before any bytes
    /// flow to storage — so a mismatched-path request cannot create a CAS
    /// orphan. See `docs/architecture/explanation/cas-storage.md`
    /// §"Orphaned content".
    ///
    /// `None` is safe: the path-conflict check still runs **after** `put`
    /// as before, and the duplicate/conflict decision is unchanged
    /// semantically. Setting `Some(hash)` is purely an optimisation and a
    /// safety net.
    pub declared_sha256: Option<ContentHash>,
    /// Format-specific upload-payload metadata, captured at the upload
    /// boundary (e.g. PyPI multipart fields, cargo `PublishMetadata`, npm
    /// packument excerpt). Routed to `ArtifactIngested.metadata` on the
    /// event log and to the `ArtifactMetadata` 1:1 projection row via
    /// `ArtifactLifecyclePort::commit_transition`.
    ///
    /// Opaque JSON — each `FormatHandler` owns its own schema. Defaults to
    /// `Value::Null` for callers that have nothing to persist (proxy
    /// fetches with unreadable bodies, legacy handlers that have not yet
    /// been taught to extract metadata). `#[tracing::instrument(skip)]`
    /// covers the whole request, so this field never leaks into logs.
    ///
    /// Distinct from [`ArtifactCoords::metadata`], which is the opaque
    /// output of `FormatHandler::parse_download_path` and has a different
    /// lifecycle — see the coords type's docstring.
    pub payload_metadata: serde_json::Value,
}

/// Internal context threaded through `ingest_with_verification` so the
/// success path can emit `ChecksumVerified` with the right algorithm
/// and upstream-value labels.
///
/// `sha512_handle` is `Some` for the SHA-512 verification arm
/// (`UpstreamPublished(Sha512)` — npm SRI); `sha1_handle` is `Some` for
/// the SHA-1 transfer-verification *floor* arm
/// (`UpstreamPublished(Sha1)` — the Maven `.sha1` sidecar, ADR 0033). At
/// most one of the two is `Some` (a single algorithm verifies a single
/// ingest). For whichever is set, `ingest_inner` finalises the handle
/// post-put to recover the digest hex of the bytes that flowed through
/// the wrapped stream; the hex is then both compared to `upstream_value`
/// (mismatch → rollback + `Conflict`) and embedded as
/// `ChecksumVerified.computed_value` on the success path. SHA-256 paths
/// leave both handles `None` and `ingest_inner` falls back to using
/// `artifact.sha256_checksum` as the computed value (the storage CAS
/// hash IS the verification hash for the SHA-256 arms).
///
/// Neither handle is ever a CAS key: SHA-512 and SHA-1 are
/// verification-only digests at the ingest boundary; the content-address
/// stays SHA-256 (ADR 0003 / ADR 0033).
#[derive(Clone)]
struct VerificationContext {
    algorithm: HashAlgorithm,
    upstream_value: String,
    sha512_handle: Option<Sha512DigestHandle>,
    sha1_handle: Option<Sha1DigestHandle>,
}

/// Lowercase-hex-encode a byte slice. Used for SHA-512 digest values
/// emitted onto domain events and into Conflict messages — both must
/// match the lowercase-hex convention enforced by
/// `UpstreamPublishedChecksum::new` so a byte-for-byte equality
/// comparison against `upstream_value` is the right comparison.
fn lower_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Request payload for `IngestUseCase::ingest_direct`.
///
/// Mirrors [`IngestRequest`] minus `declared_sha256` — direct uploads
/// without a digest the protocol can verify against. The
/// `declared_sha256`-bearing path belongs to
/// [`VerifiedIngestRequest`]; this type plus `ingest_direct` is what's
/// left when the verification target is absent.
#[derive(Debug)]
pub struct DirectIngestRequest {
    pub repository_id: Uuid,
    pub coords: ArtifactCoords,
    pub content_type: String,
    pub actor: ApiActor,
    pub legacy_sha1: Option<String>,
    pub legacy_md5: Option<String>,
    pub payload_metadata: serde_json::Value,
}

/// Request payload for [`IngestUseCase::register_existing_cas_blob`].
///
/// Bundled into a struct for the same reason [`IngestRequest`] and
/// [`DirectIngestRequest`] are: it keeps the public API off the
/// `clippy::too_many_arguments` `#[allow]` treadmill the
/// [`IngestRequest`] docstring calls out, and makes each field read
/// as a first-class concern at the (five identical) post-coalesce
/// call sites.
///
/// Deliberately omits `declared_sha256`,
/// `quarantine_anchor_override`, `legacy_sha1`, `legacy_md5`: the
/// content is already CAS-present and checksum-verified (ADR 0006), so
/// `content_hash` is authoritative (the delegated
/// [`IngestUseCase::register_by_hash`] ignores `declared_sha256`
/// anyway) and the follower mirrors the leader's no-quarantine /
/// no-legacy-echo proxy-ingest shape.
#[derive(Debug)]
pub struct RegisterExistingCasBlobRequest {
    pub repository_id: Uuid,
    pub coords: ArtifactCoords,
    pub content_type: String,
    pub actor: ApiActor,
    pub payload_metadata: serde_json::Value,
    pub content_hash: ContentHash,
    /// Seed-import cutover path.
    ///
    /// When `Some(anchor)`, after the `ArtifactIngested` commit the
    /// register path appends an `ArtifactQuarantined` event with
    /// `quarantine_window_start = anchor`. The caller backdates the
    /// anchor far enough that the computed deadline
    /// (`anchor + effective_duration`) is already at or
    /// before `now()`, so the next sweep / fast-path can release the
    /// artifact as soon as a clean scan lands. The artifact is
    /// `Quarantined`-but-window-elapsed, **not** `ScanWaived` and
    /// **not** permissive — a dirty scan still transitions to
    /// `Rejected`.
    ///
    /// `None` for every existing caller (OCI cross-mount,
    /// post-coalesce follower) — backwards-compatible.
    pub seed_import_quarantine_anchor: Option<DateTime<Utc>>,
}

/// Request payload for `IngestUseCase::ingest_verified` (ADR 0006).
///
/// Two variants only — `ProtocolNative` and `UpstreamPublished`. The
/// design rejects an `Unverified` variant: the type system records at
/// compile time which paths verify, and "ingest with a digest field
/// but skip the comparison" is unrepresentable. There is no operator
/// opt-in.
///
/// The variant name reflects what the request expresses (verification
/// target present), not the byte source — both pull-through fetches
/// and direct uploads with a client-supplied digest land here.
#[derive(Debug)]
pub enum VerifiedIngestRequest {
    /// Protocol embeds the digest in the request itself — covers OCI
    /// direct upload (digest in URL/header/session), OCI pull-through
    /// (digest from manifest descriptor or upstream
    /// `Docker-Content-Digest` header), AND PyPI direct upload (the
    /// client-declared `sha256_digest` field on the twine legacy upload
    /// form). One verification mechanism for every byte
    /// source whose digest the request carries directly — distinct from
    /// [`Self::UpstreamPublished`], which recovers the digest by parsing
    /// upstream metadata and is therefore pull-through only.
    ProtocolNative {
        repository_id: Uuid,
        coords: ArtifactCoords,
        content_type: String,
        actor: ApiActor,
        payload_metadata: serde_json::Value,
        upstream_digest: ContentHash,
        /// Best-effort upstream publish timestamp.
        /// Format adapters that can extract a publish hint from
        /// upstream metadata or response headers populate this; absent
        /// or unparseable yields `None` and never fails the ingest.
        /// Recorded onto `Artifact.upstream_published_at` audit-only;
        /// use of the value is gated behind
        /// `RepositoryUpstreamMapping.trust_upstream_publish_time`.
        upstream_published_at: Option<DateTime<Utc>>,
        /// The serving `RepositoryUpstreamMapping`'s
        /// `trust_upstream_publish_time` opt-in flag. The
        /// inbound-HTTP adapter that resolved the mapping passes its
        /// value here; **direct uploads** (no serving mapping) pass
        /// `false`. When `true` AND `upstream_published_at.is_some()`,
        /// `ingest_inner` anchors the quarantine window at
        /// `min(upstream_published_at, ingested_at)` (the `min` is the
        /// future-skew clamp); otherwise the anchor stays
        /// `ingested_at`. The bool
        /// collapses the "direct upload vs. pull-through" + "opted-in
        /// vs. not" disambiguation into a single load-bearing signal —
        /// direct uploads always send `false`, so the use case never
        /// has to reason about the request's byte source.
        trust_upstream_publish_time: bool,
    },
    /// Verification target was recovered by parsing upstream metadata
    /// (Cargo `cksum`, PyPI `digests.sha256`, npm `dist.integrity`,
    /// Maven `.sha256`, Helm `digest`, …). Pull-through only — direct
    /// upload does not fetch metadata and does not produce this
    /// variant.
    UpstreamPublished {
        repository_id: Uuid,
        coords: ArtifactCoords,
        content_type: String,
        actor: ApiActor,
        payload_metadata: serde_json::Value,
        upstream_checksum: UpstreamPublishedChecksum,
        /// Best-effort upstream publish timestamp.
        /// Same semantics as the [`Self::ProtocolNative`] arm:
        /// extracted from the metadata body that produced
        /// `upstream_checksum` (npm packument `time[<version>]`, PyPI
        /// `upload_time_iso_8601`) or — for response-header anchored
        /// formats — from the artifact-fetch response. Best-effort:
        /// `None` is fine, never fails the ingest.
        upstream_published_at: Option<DateTime<Utc>>,
        /// Serving `RepositoryUpstreamMapping`'s
        /// `trust_upstream_publish_time` opt-in. The
        /// `UpstreamPublished` arm is **pull-through only** (direct
        /// upload does not parse upstream metadata and never produces
        /// this variant), so the inbound-HTTP caller always has a
        /// serving mapping in scope and threads its flag here. When
        /// `true` AND `upstream_published_at.is_some()`, `ingest_inner`
        /// anchors the quarantine window at
        /// `min(upstream_published_at, ingested_at)`; otherwise the
        /// anchor stays `ingested_at`. See [`Self::ProtocolNative`]
        /// for the full rationale.
        trust_upstream_publish_time: bool,
    },
}

/// Success envelope returned by [`IngestUseCase::ingest`] and
/// [`IngestUseCase::register_by_hash`].
///
/// Carries the persisted `Artifact` alongside `ingested_event_id` — the
/// `EventToAppend::event_id` that the use case threaded through
/// `ArtifactLifecyclePort::commit_transition`. Callers that emit further
/// events in the same composition (the OCI
/// `OciManifestUseCase::put_manifest` is the primary consumer — it issues
/// `ArtifactGroupUseCase::add_member` calls once per manifest member) use
/// this id as the `causation_id` so the event chain resolves to the
/// `ArtifactIngested` event that produced this artifact.
///
/// **Dedup / register-by-hash semantics:** on the dedup path of
/// [`IngestUseCase::ingest`] — same hash at same path, no new event
/// committed — `ingested_event_id` is a freshly-minted `Uuid` that points
/// at no persisted event. The field type is non-optional by design: the
/// downstream causation chain is a best-effort metadata hint, not a
/// correctness primitive, and the OCI `add_member` adapter's
/// same-member-idempotence rule makes a retry-on-dedup
/// semantically a no-op regardless of what the causation_id points at.
#[derive(Debug, Clone)]
pub struct IngestOutcome {
    pub artifact: Artifact,
    pub ingested_event_id: Uuid,
}

/// Map an error returned from the ingest pipeline to an `IngestResult`
/// used as the `result` label of `hort_ingest_total`.
/// Map an [`ApiActor`] to the persisted `Artifact.uploaded_by` column.
///
/// Server-initiated ingest paths (OCI manifest / blob pull-through —
/// see `crates/hort-http-oci/src/blobs.rs::try_upstream_blob_pull` and
/// `crates/hort-http-oci/src/manifests.rs::try_upstream_manifest_pull`)
/// have no human caller and pass `ApiActor { user_id: Uuid::nil() }`
/// as the established system-actor sentinel. The persisted column is
/// `uploaded_by UUID REFERENCES users(id) ON DELETE SET NULL` —
/// nullable, so writing `None` for the sentinel satisfies the FK
/// where writing the literal nil uuid does not (no `users` row owns
/// that id, surfaced as `artifacts_uploaded_by_fkey` in the
/// mirror smoke).
///
/// Real (non-nil) user ids round-trip onto the column verbatim; the
/// audit join on `uploaded_by → users.id` keeps working for human
/// uploads, only proxied content drops the attribution.
fn actor_to_uploaded_by(actor: &ApiActor) -> Option<Uuid> {
    if actor.user_id.is_nil() {
        None
    } else {
        Some(actor.user_id)
    }
}

fn classify_ingest_error(err: &AppError) -> IngestResult {
    match err {
        AppError::Storage(_) => IngestResult::StorageError,
        AppError::Domain(DomainError::Conflict(_)) => IngestResult::Conflict,
        AppError::Domain(DomainError::Validation(_)) => IngestResult::ValidationError,
        AppError::Domain(DomainError::NotFound { entity, .. }) if *entity == "Repository" => {
            IngestResult::RepositoryNotFound
        }
        // All other error variants surface as generic conflict/validation in the
        // current pipeline; classify as ValidationError by default so the
        // ingest_total counter does not silently mis-attribute unexpected errors
        // to a success-adjacent bucket.
        _ => IngestResult::ValidationError,
    }
}

/// Transient flow-control type carrying a metadata-strategy decision from
/// the outer `ingest` dispatch to `ingest_inner`. `Pending` defers the
/// `storage.put` until after dedup checks have cleared so a duplicate
/// re-publish does not orphan a just-written blob in CAS.
enum MetadataDecision {
    /// Full payload stays inline. The `Value` goes into both
    /// `ArtifactIngested.metadata` and `ArtifactMetadata.metadata`.
    Inline(serde_json::Value),
    /// Blob write deferred until after dedup. `bytes` is the
    /// serialised full payload; `summary` is the handler-extracted
    /// subset that will ride inline alongside the `Some(hash)`
    /// produced by the deferred `storage.put`.
    Pending {
        bytes: Vec<u8>,
        summary: serde_json::Value,
    },
}

/// Internal classification of `ingest_inner`'s error path. Replaces
/// the substring discriminator that previously coupled audit-emission
/// to inner `Conflict` message phrasing — a future reword of either
/// the verification-mismatch or path-conflict message would have
/// silently disabled `ChecksumMismatch` emission for the affected arm.
/// The enum makes the discriminator type-driven instead.
enum InnerIngestError {
    /// Verification target (declared SHA-256 or upstream-published
    /// SHA-512) disagreed with the computed hash. The outer layer
    /// emits `ChecksumMismatch` to the repository audit stream using
    /// the typed fields below — the `source` `AppError` is preserved
    /// verbatim so the existing wire-response shape, the
    /// `hort_ingest_total{result=...}` label, and the `classify_ingest_error`
    /// taxonomy see exactly the same value as today.
    VerificationMismatch {
        algorithm: HashAlgorithm,
        upstream_value: String,
        computed_value: String,
        /// The originating `AppError::Domain(Conflict(...))` — preserved
        /// so existing classification / wire-response paths see the
        /// same value as before this refactor.
        source: AppError,
    },
    /// Any other error: path conflict, storage failure, domain error,
    /// curation block, etc. Outer layer propagates without emitting
    /// `ChecksumMismatch`.
    Other(AppError),
}

impl InnerIngestError {
    /// Project back to the underlying `AppError`. Used by callers that
    /// do not consume the `VerificationMismatch` variant for audit
    /// emission — only `ingest_with_verification` does that, gated on
    /// a non-`None` `VerificationContext`. Other callers (the public
    /// `ingest`) still want the existing `AppError`-shaped match arms
    /// for metric classification, so they map back to `AppError` at
    /// the await boundary.
    fn into_app_error(self) -> AppError {
        match self {
            InnerIngestError::VerificationMismatch { source, .. } => source,
            InnerIngestError::Other(err) => err,
        }
    }
}

/// Orchestrates artifact ingestion: store content, emit events, optionally quarantine.
pub struct IngestUseCase {
    storage: Arc<dyn StoragePort>,
    lifecycle: Arc<dyn ArtifactLifecyclePort>,
    artifacts: Arc<dyn ArtifactRepository>,
    repositories: Arc<dyn RepositoryRepository>,
    events: Arc<EventStorePublisher>,
    /// Pre-storage curation gate. The
    /// `IngestUseCase::ingest` first step calls
    /// [`CurationRuleRepository::list_for_repo`] for the inbound
    /// repository and runs
    /// [`hort_domain::policy::curation::evaluate_curation`]. `Block`
    /// outcomes return [`DomainError::CurationBlocked`] before any
    /// CAS or event work; `Warn` outcomes log `tracing::warn!` and
    /// continue; `Allow` is silent. Empty rule lists fast-path to
    /// `Allow` (the evaluator's empty-loop branch).
    curation_rules: Arc<dyn CurationRuleRepository>,
    /// Artifact-group write path. After
    /// `lifecycle.commit_transition` lands the `ArtifactIngested` event,
    /// the ingest hook asks `handler.classify_group_member(...)` whether
    /// the uploaded file belongs to a group; on `Some`, the membership
    /// is routed through this use case's `add_member(...)`. Stays an
    /// `Arc` because a single ingest transaction may recurse through
    /// different code paths that each need the use case by handle.
    group_use_case: Arc<ArtifactGroupUseCase>,
    /// Cardinality safety valve mirroring the `METRICS_INCLUDE_REPOSITORY_LABEL`
    /// env var. When false, every metric emission from this use case sets
    /// `repository = "_all"` ([`values::REPOSITORY_ALL`]) regardless of the
    /// actual repo key.
    include_repository_label: bool,
    /// Per-format operator overrides for the upload-payload metadata size
    /// cap — the third layer of the three-layer cap model (handler
    /// default → per-format env override → global blob cap).
    /// Keyed by `FormatHandler::format_key()` (e.g. `"pypi"`, `"npm"`,
    /// `"cargo"`). When a key is absent, the effective cap falls through
    /// to `handler.metadata_expected_max_bytes()`. Populated from
    /// `METADATA_CAP_BYTES_<FORMAT>` environment variables at startup.
    metadata_caps: HashMap<String, usize>,
    /// Global safety cap on the size of a metadata blob written to CAS
    /// by the HashReference strategy. Populated from
    /// `HORT_METADATA_BLOB_MAX_SIZE` (default 10 MB). `0` means "accept
    /// anything" — a documented escape hatch used primarily by tests
    /// that exercise the CAS round-trip without worrying about ceilings.
    metadata_blob_max_bytes: usize,
    /// Refcount projection writer. Every successful
    /// `ArtifactIngested` commit writes one `kind = "primary_content"`
    /// row pointing at `artifact.sha256_checksum`. HashReference-strategy
    /// ingests additionally write a `kind = "metadata_blob"` row pointing
    /// at the metadata blob hash. Held as the raw port handle (not via
    /// `ContentReferenceUseCase`) because `ContentReferenceUseCase` is
    /// constructed AFTER `IngestUseCase` in the composition root —
    /// `IngestUseCase`'s established pattern is to hold raw port handles
    /// for primitives it must call without authz.
    ///
    /// Failure here is recoverable — the artifact is already
    /// persisted-and-valid; the refcount row is eventual. An operator-
    /// side reconcile sweep catches divergence. We
    /// do NOT abort the ingest on insert failure.
    content_references: Arc<dyn ContentReferenceIndex>,
    /// Ingest-time scan auto-enqueue. When the
    /// inbound artifact's repository matches an active `ScanPolicy`
    /// (repo-scoped takes precedence over `Global`), the ingest path
    /// appends `ScanRequested` atomically alongside `ArtifactIngested`
    /// and `ChecksumVerified`, then inserts a `jobs` row via
    /// [`Self::jobs`] so the worker picks the scan up on its next
    /// poll. When no policy matches, no scan is requested and the
    /// existing ingest behaviour is unchanged.
    policy_projections: Arc<dyn PolicyProjectionRepository>,
    /// Counterpart to [`Self::policy_projections`].
    ///
    /// The release-gating ingest enqueues — the auto-scan (`ScanRequested`)
    /// and the provenance gate (`provenance-verify`) — do **not** go through
    /// this field. They are committed **atomically** with the ingest
    /// transition via
    /// [`ArtifactLifecyclePort::commit_transition_with_enqueues`] (no
    /// event-without-job strand; ADR 0002/0004). This field is retained for
    /// the **best-effort, non-gating** post-commit enqueues — the
    /// `prefetch-dependencies` transitive-cascade hook — which are
    /// deliberately eventually-consistent (a lost cascade row strands
    /// nothing; the next pull re-triggers), so warn-and-continue is the
    /// correct posture for them.
    jobs: Arc<dyn JobsRepository>,
    /// The set of repository-format strings
    /// some registered `ProvenancePort` `applies_to`. Drives the
    /// ingest-time `provenance-verify` enqueue gate: a job is enqueued
    /// **only when** the resolved `ScanPolicy.provenance_mode != Off` AND
    /// `provenance_capable_formats.contains(format)`. Gating on
    /// `mode != Off` alone would enqueue a no-op
    /// `provenance-verify` job for every non-OCI ingest under the default
    /// `VerifyIfPresent` (the Tier-1 cosign verifier applies only to
    /// `"oci"`), which the gate avoids: non-applicable ingests are
    /// genuinely zero-overhead (no row), and the set auto-activates when a
    /// Tier-2 verifier later registers (no migration).
    ///
    /// **Default empty** (set by [`Self::new`]) so the composition root
    /// compiles unchanged until the real capability set is wired via
    /// [`Self::with_provenance_capable_formats`]. An empty set means "no
    /// verifier applies to anything" → no `provenance-verify` is ever
    /// enqueued, which is fail-safe: a `Required` policy on a no-verifier
    /// format is already apply-rejected, and a runtime
    /// mis-registration leaves the artifact `Pending` → never timer-releases
    /// (fail-closed at the release gate).
    provenance_capable_formats: Arc<HashSet<String>>,
}

impl IngestUseCase {
    /// Construct the ingest use case.
    ///
    /// `metadata_blob_max_bytes` is the global safety cap on payloads the
    /// HashReference strategy would otherwise persist to CAS. `0` is
    /// treated as "accept anything" — a documented escape hatch for
    /// tests that must exercise the CAS round-trip without policing
    /// size. Production ingests the same way: the
    /// per-format metadata cap already guards against pathological
    /// inputs before
    /// the strategy dispatch runs.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        storage: Arc<dyn StoragePort>,
        lifecycle: Arc<dyn ArtifactLifecyclePort>,
        artifacts: Arc<dyn ArtifactRepository>,
        repositories: Arc<dyn RepositoryRepository>,
        events: Arc<EventStorePublisher>,
        curation_rules: Arc<dyn CurationRuleRepository>,
        group_use_case: Arc<ArtifactGroupUseCase>,
        include_repository_label: bool,
        metadata_caps: HashMap<String, usize>,
        metadata_blob_max_bytes: usize,
        content_references: Arc<dyn ContentReferenceIndex>,
        policy_projections: Arc<dyn PolicyProjectionRepository>,
        jobs: Arc<dyn JobsRepository>,
    ) -> Self {
        Self {
            storage,
            lifecycle,
            artifacts,
            repositories,
            events,
            curation_rules,
            group_use_case,
            include_repository_label,
            metadata_caps,
            metadata_blob_max_bytes,
            content_references,
            policy_projections,
            jobs,
            // Default empty; the composition root wires the real set via
            // `with_provenance_capable_formats`. Empty = no
            // `provenance-verify` ever enqueued (fail-safe).
            provenance_capable_formats: Arc::new(HashSet::new()),
        }
    }

    /// Install the set of repository-format
    /// strings some registered `ProvenancePort` `applies_to` (Tier-1:
    /// `{"oci"}` for cosign; ADR 0027). Builder-style so the composition
    /// root wires it without changing the [`Self::new`] arg list — and
    /// every existing call site keeps compiling with the default empty set.
    ///
    /// The ingest path consults this set together with the resolved policy
    /// `provenance_mode` to decide whether to enqueue a `provenance-verify`
    /// job: enqueue **iff** `mode != Off` AND the set contains the ingest's
    /// format.
    #[must_use]
    pub fn with_provenance_capable_formats(
        mut self,
        formats: impl IntoIterator<Item = String>,
    ) -> Self {
        self.provenance_capable_formats = Arc::new(formats.into_iter().collect());
        self
    }

    /// Resolve the active `ScanPolicy` (if any)
    /// that applies to `repo_id`. Repo-scoped policies take precedence
    /// over `Global`; a single repo can have at most one repo-scoped
    /// policy active at a time (enforced by
    /// `idx_policy_projections_active_name` from `005_policy.sql`).
    ///
    /// Mirrors `ScanOrchestrationUseCase::resolve_active_policy_for_repo`
    /// — the logic is duplicated rather than shared to keep
    /// `IngestUseCase` and `ScanOrchestrationUseCase` independent at the
    /// API surface (a future refactor could lift the helper into
    /// `crate::policy` if a third caller surfaces).
    async fn resolve_active_policy_for_repo(
        &self,
        repo_id: Uuid,
    ) -> AppResult<Option<ScanPolicyProjection>> {
        let active = self.policy_projections.list_active().await?;
        let mut repo_scoped: Option<ScanPolicyProjection> = None;
        let mut global: Option<ScanPolicyProjection> = None;
        for projection in active {
            match &projection.scope {
                PolicyScope::Repository(id) if *id == repo_id => {
                    repo_scoped = Some(projection);
                }
                PolicyScope::Global if global.is_none() => {
                    global = Some(projection);
                }
                _ => {}
            }
        }
        Ok(repo_scoped.or(global))
    }

    /// Resolve the `repository` metric label. When the repository-label flag
    /// is disabled, returns the [`values::REPOSITORY_ALL`] sentinel; otherwise
    /// returns the provided key or [`values::REPOSITORY_UNKNOWN`] when the
    /// repository could not be resolved.
    fn repo_label(&self, repo_key: Option<&str>) -> String {
        if !self.include_repository_label {
            values::REPOSITORY_ALL.to_string()
        } else {
            repo_key.unwrap_or(values::REPOSITORY_UNKNOWN).to_string()
        }
    }

    /// Compute the effective upload-payload metadata cap for the given
    /// handler, honouring the operator override when present and falling
    /// back to the format-declared expected max otherwise (three-layer
    /// model). The DB absolute ceiling is not enforced here — the
    /// event-payload column's `CHECK` catches that as a defence-in-depth
    /// layer regardless of whatever operator value was configured.
    fn effective_metadata_cap(&self, handler: &dyn FormatHandler) -> usize {
        self.metadata_caps
            .get(handler.format_key())
            .copied()
            .unwrap_or_else(|| handler.metadata_expected_max_bytes())
    }

    /// Serialise `payload_metadata` once and enforce the three-layer cap
    /// (handler default → per-format env override → global blob cap)
    /// against
    /// the handler's effective cap. Returns the serialised bytes (or
    /// `None` for the `Value::Null` fast path) so callers that have
    /// additional work to do on the payload (strategy dispatch inside
    /// [`Self::ingest`]) do not pay a second `serde_json::to_vec` hop.
    ///
    /// On a cap miss, returns
    /// `Err(AppError::Domain(DomainError::Validation(…)))` — the exact
    /// same shape the `ingest` outer would have produced. Metric
    /// emission is NOT performed here; callers that need the
    /// `metadata_too_large` result label on `hort_ingest_total` classify
    /// the error themselves so the counter exit point stays a single
    /// unified site per entry method.
    ///
    /// Shared by [`Self::ingest`] and [`Self::register_by_hash`]: both
    /// paths MUST reject oversized payloads before doing any storage or
    /// event work, so the cap is enforced uniformly regardless of
    /// whether the caller is streaming bytes or registering a
    /// pre-existing CAS object by hash.
    fn enforce_metadata_cap(
        &self,
        handler: &dyn FormatHandler,
        payload_metadata: &serde_json::Value,
    ) -> AppResult<Option<Vec<u8>>> {
        let cap = self.effective_metadata_cap(handler);
        let serialized: Option<Vec<u8>> = if payload_metadata.is_null() {
            None
        } else {
            Some(serde_json::to_vec(payload_metadata).map_err(|e| {
                AppError::Domain(DomainError::Invariant(format!(
                    "payload_metadata JSON serialisation failed: {e}"
                )))
            })?)
        };
        let metadata_bytes = serialized.as_ref().map_or(0, Vec::len);
        if metadata_bytes > cap {
            // Log the cap (public) and format only — never the payload
            // itself and never its actual byte length. Size profiles
            // per package are sensitive; the cap is not.
            tracing::info!(
                format = %handler.format_key(),
                cap,
                "metadata-too-large"
            );
            return Err(AppError::Domain(DomainError::Validation(
                "upload-payload metadata exceeds configured cap".into(),
            )));
        }
        Ok(serialized)
    }

    /// Ingest an artifact into a repository.
    ///
    /// Flow:
    /// 1. Verify repository exists
    /// 2. Store content via CAS → hash + size
    /// 3. Duplicate check by path — idempotent on same hash, conflict on different
    /// 4. Build Artifact entity + emit ArtifactIngested
    /// 5. Quarantine if the resolved policy carries
    ///    `quarantine_duration_secs > 0` — operator `ScanPolicy` wins;
    ///    no policy → `DefaultPolicy::quarantine_duration_secs` (24h)
    ///    fires; operator `0` honoured as the permissive opt-out.
    ///
    /// See [`IngestRequest`] for the shape of `request`. `stream` is a
    /// separate argument because `Box<dyn AsyncRead>` is not `Clone` and
    /// must be consumed by value.
    ///
    /// `legacy_sha1` / `legacy_md5` on the request are **metadata** that
    /// legacy protocols (e.g. npm `shasum`) must echo back to clients. They
    /// are written onto the `Artifact` row in the same atomic
    /// `commit_transition` as the primary `sha256_checksum`, but are
    /// deliberately absent from the `ArtifactIngested` domain event — the
    /// event carries only SHA-256 so cross-format consumers do not need to
    /// reason about legacy hashes. Callers that have no legacy checksum
    /// (PyPI, cargo) pass `None` for both fields.
    #[tracing::instrument(skip(self, request, stream, handler))]
    pub async fn ingest_direct(
        &self,
        request: DirectIngestRequest,
        stream: Box<dyn AsyncRead + Send + Unpin>,
        handler: &dyn FormatHandler,
    ) -> AppResult<IngestOutcome> {
        let DirectIngestRequest {
            repository_id,
            coords,
            content_type,
            actor,
            legacy_sha1,
            legacy_md5,
            payload_metadata,
        } = request;
        // Direct ingest never carries a verification target — that's
        // what `ingest_verified` is for. The internal
        // pipeline keeps the `declared_sha256` parameter so the same
        // helper serves both public entry points.
        let declared_sha256: Option<ContentHash> = None;
        let format = coords.format.to_string();
        let started = Instant::now();

        // Pre-storage curation gate.
        //
        // FIRST step of `ingest`, BEFORE the metadata cap check, so a
        // blocked package never streams a byte to storage and never pays
        // the JSON-serialise hop. Empty rule list (the common case for
        // repos with no curation declared) hits the evaluator's
        // empty-loop fast path and falls through immediately.
        //
        // `Block` returns `DomainError::CurationBlocked`; the per-format
        // inbound HTTP layer maps it to 403 by default and to 404 on
        // pull-through fetch handlers. `Warn` logs `tracing::warn!` and
        // continues — no event emission yet (`CurationApplied` covers
        // the audit surface for v2). `Allow`
        // is silent so the high-volume happy path stays log-free.
        let rules = self
            .curation_rules
            .list_for_repo(repository_id)
            .await
            .map_err(AppError::Domain)?;
        match evaluate_curation(&coords, &rules) {
            CurationOutcome::Allow => {
                // Curation Allow is the high-volume happy path; the
                // counter still ticks (with `result=pass`) so dashboards
                // see the denominator. No `tracing` emission, no
                // violations counter.
                emit_policy_evaluation(
                    policy_decision_point::CURATION,
                    PolicyEvaluationResult::Pass,
                );
            }
            CurationOutcome::Warn { rule_name, reason } => {
                tracing::warn!(
                    rule = %rule_name,
                    reason = %reason,
                    format = %format,
                    name = %coords.name,
                    "curation rule warned at ingest"
                );
                emit_policy_evaluation(
                    policy_decision_point::CURATION,
                    PolicyEvaluationResult::Warn,
                );
                emit_policy_violations(
                    policy_decision_point::CURATION,
                    &[hort_domain::events::PolicyViolation {
                        rule: "curation-warn".to_string(),
                        severity: hort_domain::entities::scan_policy::SeverityThreshold::Low,
                        message: reason,
                        details: serde_json::Value::Null,
                    }],
                );
            }
            CurationOutcome::Block {
                rule_name,
                rule_id,
                reason,
            } => {
                tracing::info!(
                    rule = %rule_name,
                    %rule_id,
                    reason = %reason,
                    format = %format,
                    name = %coords.name,
                    "curation blocked ingest"
                );
                emit_policy_evaluation(
                    policy_decision_point::CURATION,
                    PolicyEvaluationResult::Block,
                );
                emit_policy_violations(
                    policy_decision_point::CURATION,
                    &[hort_domain::events::PolicyViolation {
                        rule: "curation-block".to_string(),
                        severity: hort_domain::entities::scan_policy::SeverityThreshold::High,
                        message: reason.clone(),
                        details: serde_json::Value::Null,
                    }],
                );
                return Err(AppError::Domain(DomainError::CurationBlocked {
                    rule_name,
                    rule_id,
                    reason,
                }));
            }
        }

        // Registration-collision gate (publish path only).
        //
        // `ingest_direct` is the DIRECT-upload/publish path; pull-through
        // goes through `ingest_verified`, where the upstream registry has
        // already enforced its own uniqueness rule — so this gate belongs
        // here, not there. It is FORMAT-DRIVEN: `collision_key` is `Some`
        // only for a format whose registry forbids names that differ solely
        // by a fold the LOOKUP path does not apply. cargo is the only such
        // v1 format (crates.io folds `-`/`_` for registration uniqueness
        // while the index lookup preserves separators); npm (case-sensitive)
        // and pypi (PEP 503 already collapses at the identity layer) return
        // `None` and skip this block with zero behaviour change. Runs before
        // the metadata cap + storage so a collision never streams a byte.
        if let Some(key) = handler.collision_key(&coords.name_as_published) {
            if let Some(existing) = self
                .artifacts
                .find_canonical_name_by_collision_key(repository_id, &key)
                .await
                .map_err(AppError::Domain)?
            {
                // A row sharing the collision key whose canonical name
                // DIFFERS from the one being published is a true collision
                // (`foo_bar` vs an existing `foo-bar`). An equal canonical
                // name is the SAME crate (a new version, or a case variant
                // that already collapsed) — allowed.
                if existing != coords.name {
                    tracing::info!(
                        %repository_id,
                        format = %format,
                        existing_crate = %existing,
                        collision_key = %key,
                        "publish rejected: a crate differing only in \
                         hyphen/underscore already exists in this repository",
                    );
                    return Err(AppError::Domain(DomainError::InvalidState(format!(
                        "a crate differing only in hyphen/underscore already exists \
                         in this repository: '{existing}'"
                    ))));
                }
            }
        }

        // Metadata size cap — middle + operator layer of the three-layer
        // model (see `enforce_metadata_cap`). Runs BEFORE `ingest_inner`
        // so an oversized payload never reaches storage, event append, or
        // the lifecycle port. Rejection is NOT routed through
        // `classify_ingest_error`: that would reclassify a
        // `DomainError::Validation` as `IngestResult::ValidationError`,
        // silently erasing the `metadata_too_large` label. Instead, emit
        // the counter directly here with the correct result label and
        // return an `AppError` carrying a terse message.
        //
        // Serialise the payload once via the shared helper — the returned
        // `Option<Vec<u8>>` is consumed by the HashReference strategy
        // dispatch below. `to_vec` and `to_string` emit compact JSON
        // with identical lengths, so the cap comparison is byte-accurate
        // either way.
        let serialized_metadata: Option<Vec<u8>> =
            match self.enforce_metadata_cap(handler, &payload_metadata) {
                Ok(bytes) => bytes,
                Err(cap_err) => {
                    // Resolve the repository key for the metric label if the
                    // repo exists; fall back to `REPOSITORY_UNKNOWN` otherwise.
                    // A cap miss is a deterministic request-shape decision —
                    // we pay one extra lookup to keep the metric label
                    // bounded and consistent with other ingest-failure
                    // emissions.
                    let repo_key = self
                        .repositories
                        .find_by_id(repository_id)
                        .await
                        .ok()
                        .map(|r| r.key);
                    let elapsed = started.elapsed().as_secs_f64();
                    metrics::counter!(
                        "hort_ingest_total",
                        labels::FORMAT => format.clone(),
                        labels::REPOSITORY => self.repo_label(repo_key.as_deref()),
                        labels::RESULT => IngestResult::MetadataTooLarge.as_str(),
                    )
                    .increment(1);
                    metrics::histogram!(
                        "hort_ingest_duration_seconds",
                        labels::FORMAT => format,
                    )
                    .record(elapsed);
                    return Err(cap_err);
                }
            };
        // Metadata strategy dispatch. The pre-dispatch metadata cap
        // check above has already rejected pathological payloads; the
        // decision here is purely about where the payload-bearing bytes
        // live:
        //   - Inline               → full payload in event + projection row.
        //   - HashReference        → if serialised length ≤ threshold,
        //                            behave like Inline (no CAS round-trip
        //                            for small packuments). Otherwise
        //                            defer the blob put until after the
        //                            dedup checks in `ingest_inner` have
        //                            cleared, so a duplicate re-publish
        //                            does not orphan a just-written CAS
        //                            object (post-review
        //                            hardening — see `MetadataDecision`).
        //                            On the split path, the event +
        //                            projection row carry only the
        //                            handler-extracted summary.
        //
        // The blob-cap rejection reuses the `MetadataTooLarge` IngestResult
        // label — it is the same semantic failure at a different storage
        // layer, and splitting cardinality further buys no dashboard value.
        // The tracing log carries `reason="blob-too-large"` to disambiguate
        // from the pre-dispatch cap (which uses `reason="metadata-too-large"`
        // implicitly via the log message string).
        //
        // `had_payload_metadata` gates whether the strategy counter fires
        // at all — the metric answers "how many ingests used each
        // strategy to persist payload metadata", so callers that passed
        // `Value::Null` (proxy fetches, handlers that have nothing to
        // extract) must not tick the counter. Captured here so
        // `ingest_inner` can consume `payload_metadata` / the decision
        // by value. The actual `strategy_label` is chosen inside
        // `ingest_inner` AFTER dedup clears, because the blob put that
        // determines whether a split really happened is deferred.
        let had_payload_metadata = !payload_metadata.is_null();
        let strategy = handler.metadata_strategy();
        let metadata_decision: MetadataDecision = match strategy {
            MetadataStrategy::Inline => MetadataDecision::Inline(payload_metadata),
            MetadataStrategy::HashReference {
                inline_threshold_bytes,
            } => {
                // Reuse the already-serialised bytes from the cap check
                // above. For `Value::Null` payloads the serialisation
                // was skipped (0 bytes) — they always hit the inline
                // fast path regardless of threshold.
                match serialized_metadata {
                    None => MetadataDecision::Inline(payload_metadata),
                    Some(bytes) if bytes.len() <= inline_threshold_bytes => {
                        // Small enough to inline — no CAS round-trip
                        // needed. Labelled `inline` downstream because
                        // no split happened — the counter answers "how
                        // many ingests split" not "how many declared
                        // HashReference".
                        MetadataDecision::Inline(payload_metadata)
                    }
                    Some(bytes) => {
                        // Blob safety cap. `0` is the documented "accept
                        // anything" escape hatch used by tests; any
                        // non-zero value rejects payloads exceeding it
                        // with the same `metadata_too_large` counter
                        // label as the pre-dispatch metadata cap.
                        if self.metadata_blob_max_bytes > 0
                            && bytes.len() > self.metadata_blob_max_bytes
                        {
                            let repo_key = self
                                .repositories
                                .find_by_id(repository_id)
                                .await
                                .ok()
                                .map(|r| r.key);
                            let elapsed = started.elapsed().as_secs_f64();
                            metrics::counter!(
                                "hort_ingest_total",
                                labels::FORMAT => format.clone(),
                                labels::REPOSITORY => self.repo_label(repo_key.as_deref()),
                                labels::RESULT => IngestResult::MetadataTooLarge.as_str(),
                            )
                            .increment(1);
                            metrics::histogram!(
                                "hort_ingest_duration_seconds",
                                labels::FORMAT => format,
                            )
                            .record(elapsed);
                            // Public info: blob cap. Explicit `reason`
                            // label distinguishes this from the
                            // pre-dispatch `metadata-too-large` log
                            // which shares the counter label but is a
                            // different code path.
                            tracing::info!(
                                format = %handler.format_key(),
                                blob_cap = self.metadata_blob_max_bytes,
                                reason = "blob-too-large",
                                "metadata-blob-too-large"
                            );
                            return Err(AppError::Domain(DomainError::Validation(
                                "upload-payload metadata exceeds blob cap".into(),
                            )));
                        }
                        // Defer the CAS write: compute the handler's
                        // summary now (cheap, pure) and hand the
                        // serialised bytes to `ingest_inner` alongside
                        // it. The blob is only put AFTER dedup clears.
                        let summary = handler.extract_metadata_summary(&payload_metadata);
                        MetadataDecision::Pending { bytes, summary }
                    }
                }
            }
        };

        // Decision log — no payload bytes, no actual sizes (both are
        // tenant-sensitive). `strategy` is the handler's declared mode;
        // `split` reflects whether a blob WILL be written (post-dedup).
        tracing::debug!(
            strategy = ?strategy,
            split = matches!(metadata_decision, MetadataDecision::Pending { .. }),
            format = %handler.format_key(),
            "metadata-strategy-decision"
        );

        // This call site does not consume the typed-variant
        // discriminator: the public `ingest` path does not emit
        // `ChecksumMismatch` to the repository audit stream — only
        // `ingest_with_verification` does that, gated on a non-`None`
        // `VerificationContext`. `ingest_inner` may still return a
        // `VerificationMismatch` here when the caller-supplied
        // `declared_sha256` disagrees with the
        // computed hash, but the only thing the metric path needs is
        // the underlying `AppError`. Project back to `AppError` at
        // the await boundary via `into_app_error` so the existing
        // classification match arms below stay unchanged.
        let result = self
            .ingest_inner(
                repository_id,
                coords,
                stream,
                content_type,
                actor,
                format.clone(),
                legacy_sha1,
                legacy_md5,
                declared_sha256,
                metadata_decision,
                had_payload_metadata,
                handler,
                None,
                // Direct-upload path has no upstream
                // metadata, so the upstream-publish hint is always
                // `None` here. The four format pull-through paths set
                // `Some(_)` via `ingest_with_verification`.
                None,
                // Direct-upload path has no serving
                // `RepositoryUpstreamMapping`, so the per-upstream
                // opt-in cannot apply; pass `false` unconditionally.
                // Pull-through paths thread the flag via
                // `ingest_with_verification`.
                false,
                // Direct uploads are a SEED (never a cascade-internal leaf),
                // so never suppress the seed hook.
                false,
            )
            .await
            .map_err(|(err, repo_key, preclassified)| {
                (err.into_app_error(), repo_key, preclassified)
            });

        // Emit metrics on every exit path. The `repository` label must stay
        // bounded cardinality — use REPOSITORY_UNKNOWN when the repo lookup
        // failed (the sentinel label value is REPOSITORY_UNKNOWN).
        let elapsed = started.elapsed().as_secs_f64();
        let (result_label, repository_label, size_emitted): (&'static str, String, Option<u64>) =
            match &result {
                Ok((artifact, was_duplicate, repo_key, _)) => {
                    let label = if *was_duplicate {
                        IngestResult::Duplicate.as_str()
                    } else {
                        IngestResult::Success.as_str()
                    };
                    (
                        label,
                        self.repo_label(Some(repo_key)),
                        Some(artifact.size_bytes as u64),
                    )
                }
                Err((err, repo_key, preclassified)) => {
                    // When `ingest_inner` has already chosen the metric
                    // label (declared-hash mismatch
                    // is the first consumer), honour it instead
                    // of running the error through `classify_ingest_error`.
                    // Keeps the error-shape-to-label mapping in the
                    // emission site that owns the contextual knowledge.
                    // `IngestResult` is `Copy` so the borrow is cheap to
                    // promote.
                    let ingest_result = preclassified
                        .as_ref()
                        .copied()
                        .unwrap_or_else(|| classify_ingest_error(err));
                    (
                        ingest_result.as_str(),
                        self.repo_label(repo_key.as_deref()),
                        None,
                    )
                }
            };

        metrics::counter!(
            "hort_ingest_total",
            labels::FORMAT => format.clone(),
            labels::REPOSITORY => repository_label,
            labels::RESULT => result_label,
        )
        .increment(1);
        metrics::histogram!(
            "hort_ingest_duration_seconds",
            labels::FORMAT => format.clone(),
        )
        .record(elapsed);
        if let Some(size) = size_emitted {
            metrics::histogram!(
                "hort_ingest_size_bytes",
                labels::FORMAT => format,
            )
            .record(size as f64);
        }

        match result {
            Ok((artifact, _duplicate, _repo_key, ingested_event_id)) => Ok(IngestOutcome {
                artifact,
                ingested_event_id,
            }),
            Err((err, _repo_key, _preclassified)) => Err(err),
        }
    }

    /// Verified-ingest entry point (ADR 0006).
    ///
    /// Two arms:
    ///
    /// - **`ProtocolNative`** — the protocol embeds the digest in the
    ///   request itself (OCI direct upload + pull-through). Compares
    ///   `put_result.hash` against `upstream_digest`.
    /// - **`UpstreamPublished`** — the format handler parsed an
    ///   upstream metadata body to recover the published checksum
    ///   (Cargo `cksum`, PyPI `digests.sha256`, npm `dist.integrity`,
    ///   …). Compares `put_result.hash` (sha256) or
    ///   [`super::multi_hash::Sha512HashingRead::finalize`] (sha512)
    ///   against `upstream_checksum.hex`.
    ///
    /// Mint-after-verify: the `Artifact` row is
    /// minted only on the success path. The mismatch path appends
    /// `ChecksumMismatch` to the repository stream
    /// (`StreamId::repository(repo_id)` — never the artifact stream;
    /// no row was minted), rolls back the CAS blob via
    /// `StoragePort::delete` (guarded by `find_by_checksum` empty so
    /// shared blobs are not corrupted), and returns
    /// `AppError::Domain(DomainError::Conflict(_))`.
    ///
    /// On the success path, `ChecksumVerified` is appended to the
    /// **same `commit_transition` batch** as `ArtifactIngested` —
    /// atomic with the mint. The audit invariant: every artifact
    /// ingested via `ingest_verified` has exactly one
    /// `ChecksumVerified` event in its stream.
    #[tracing::instrument(skip(self, request, stream, handler))]
    pub async fn ingest_verified(
        &self,
        request: VerifiedIngestRequest,
        stream: Box<dyn AsyncRead + Send + Unpin>,
        handler: &dyn FormatHandler,
    ) -> AppResult<IngestOutcome> {
        match request {
            VerifiedIngestRequest::ProtocolNative {
                repository_id,
                coords,
                content_type,
                actor,
                payload_metadata,
                upstream_digest,
                upstream_published_at,
                trust_upstream_publish_time,
            } => {
                // Sha256 (ContentHash) digest comparison — handled by
                // the existing `ingest_inner` declared-hash path.
                self.ingest_verified_sha256(
                    repository_id,
                    coords,
                    content_type,
                    actor,
                    payload_metadata,
                    upstream_digest,
                    HashAlgorithm::Sha256,
                    upstream_published_at,
                    trust_upstream_publish_time,
                    stream,
                    handler,
                )
                .await
            }
            VerifiedIngestRequest::UpstreamPublished {
                repository_id,
                coords,
                content_type,
                actor,
                payload_metadata,
                upstream_checksum,
                upstream_published_at,
                trust_upstream_publish_time,
            } => match upstream_checksum.algorithm() {
                HashAlgorithm::Sha256 => {
                    let digest: ContentHash = upstream_checksum.hex().parse().map_err(|e| {
                        AppError::Domain(DomainError::Validation(format!(
                            "upstream sha256 checksum is not a valid ContentHash: {e}"
                        )))
                    })?;
                    self.ingest_verified_sha256(
                        repository_id,
                        coords,
                        content_type,
                        actor,
                        payload_metadata,
                        digest,
                        HashAlgorithm::Sha256,
                        upstream_published_at,
                        trust_upstream_publish_time,
                        stream,
                        handler,
                    )
                    .await
                }
                HashAlgorithm::Sha512 => {
                    self.ingest_verified_sha512(
                        repository_id,
                        coords,
                        content_type,
                        actor,
                        payload_metadata,
                        upstream_checksum.hex().to_string(),
                        upstream_published_at,
                        trust_upstream_publish_time,
                        stream,
                        handler,
                    )
                    .await
                }
                // The SHA-1 transfer-verification *floor* (Maven `.sha1`
                // sidecar, ADR 0033 — the only universally-available
                // protocol-native digest on Maven Central). Dispatched on
                // the *algorithm*, never the format: any handler emitting
                // an `UpstreamPublished{Sha1}` uses this path. Mirrors the
                // SHA-512 arm — `ingest_verified_sha1` wraps the stream in
                // `Sha1HashingRead`, compares the finalised hex to the
                // upstream value, rolls back the CAS blob + returns
                // `Conflict` on mismatch, and appends `ChecksumVerified`
                // atomically on success. The CAS key stays SHA-256.
                HashAlgorithm::Sha1 => {
                    self.ingest_verified_sha1(
                        repository_id,
                        coords,
                        content_type,
                        actor,
                        payload_metadata,
                        upstream_checksum.hex().to_string(),
                        upstream_published_at,
                        trust_upstream_publish_time,
                        stream,
                        handler,
                    )
                    .await
                }
            },
        }
    }

    /// Narrow create for a pushed cosign
    /// **signature** manifest (a pure Sigstore-bundle referrer). Stores the
    /// manifest in CAS and emits a single `ArtifactIngested` event with
    /// `quarantine_status = None`, and — crucially — does **NOT** enqueue a
    /// scan, does **NOT** enqueue a `provenance-verify` job, and does **NOT**
    /// quarantine.
    ///
    /// **Why this exists, not `ingest_verified`.** Quarantine is an
    /// *observation window* for content whose safety is uncertain at ingest
    /// and resolves over time (a scan or advisory may land afterwards). A
    /// Sigstore signature's validity is **deterministic and immediate** —
    /// there is nothing to observe — so quarantining it is a *category
    /// error*. It happens today only because every manifest rides
    /// `ingest_verified` (which quarantines + scans + provenance-enqueues).
    /// This method is the narrow path the OCI push handler routes a
    /// pure-bundle referrer to instead, after
    /// [`hort_domain::oci::is_pure_sigstore_bundle`] confirms the manifest
    /// carries *nothing but* bundle layers (the anti-scan-evasion guard —
    /// a mixed bundle+`tar+gzip` manifest stays on `ingest_verified`).
    ///
    /// Returns the same [`IngestOutcome`] shape as [`Self::ingest_verified`]
    /// so the caller can thread `ingested_event_id` as the `oci_subject`
    /// content-reference causation and use `artifact.id` as the
    /// `source_artifact_id`.
    ///
    /// `declared_digest` is the manifest's own SHA-256 (the PUT reference /
    /// computed body hash). The manifest is content-addressed: `storage.put`
    /// returns the SHA-256 of what actually arrived, which **must** equal
    /// `declared_digest` — a mismatch is a [`DomainError::Conflict`]
    /// (fail-closed, the same posture the verified path takes on a
    /// declared-digest disagreement). The CAS hash is the OCI digest, so the
    /// Origin-pillar checksum invariant holds without the verification
    /// pipeline.
    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(skip(self, payload_metadata, stream))]
    pub async fn ingest_signature_manifest(
        &self,
        repository_id: Uuid,
        coords: ArtifactCoords,
        content_type: String,
        actor: ApiActor,
        payload_metadata: serde_json::Value,
        declared_digest: ContentHash,
        stream: Box<dyn AsyncRead + Send + Unpin>,
    ) -> AppResult<IngestOutcome> {
        // 1. Store the manifest bytes in CAS. `put` returns the SHA-256 of
        //    what actually arrived.
        let put_result = self
            .storage
            .put(stream)
            .await
            .map_err(|e| AppError::Storage(e.to_string()))?;

        // 2. Content-address check: the stored hash must equal the
        //    manifest's declared digest (fail-closed Conflict on mismatch —
        //    the manifest is content-addressed, a lie about the digest must
        //    not land). Mirrors `ingest_verified`'s declared-digest posture.
        if put_result.hash != declared_digest {
            return Err(AppError::Domain(DomainError::Conflict(format!(
                "signature manifest content hash {} does not match declared digest {}",
                put_result.hash, declared_digest
            ))));
        }

        // 3. Build the referrer-manifest Artifact aggregate — an internal
        //    provenance-bookkeeping artifact, deliberately OUTSIDE the
        //    scan/quarantine/provenance lifecycle (`quarantine_status =
        //    None`, no window).
        let artifact_id = Uuid::new_v4();
        let now = Utc::now();
        let artifact = Artifact {
            id: artifact_id,
            repository_id,
            name: coords.name.clone(),
            name_as_published: coords.name_as_published.clone(),
            version: coords.version.clone(),
            path: coords.path.clone(),
            size_bytes: put_result.size_bytes as i64,
            sha256_checksum: put_result.hash.clone(),
            sha1_checksum: None,
            md5_checksum: None,
            content_type,
            quarantine_status: QuarantineStatus::None,
            rejection_reason: None,
            quarantine_window_start: None,
            quarantine_deadline: None,
            upstream_published_at: None,
            uploaded_by: actor_to_uploaded_by(&actor),
            is_deleted: false,
            created_at: now,
            updated_at: now,
        };

        // 4. Emit `ArtifactIngested` + persist the artifact atomically via
        //    `commit_transition` — the SAME create primitive the verified
        //    path uses. NO `jobs.enqueue_*` (scan / provenance) and NO
        //    quarantine transition: that is the entire point.
        let stream_id = StreamId::artifact(artifact_id);
        let ingested_event_id = Uuid::new_v4();
        let ingested_event = ArtifactIngested {
            artifact_id,
            repository_id,
            name: artifact.name.clone(),
            version: artifact.version.clone(),
            sha256: put_result.hash,
            size_bytes: artifact.size_bytes,
            source: IngestSource::Direct,
            metadata: payload_metadata.clone(),
            metadata_blob: None,
            upstream_published_at: None,
        };

        let artifact_metadata = ArtifactMetadata {
            artifact_id,
            format: coords.format,
            metadata: payload_metadata,
            metadata_blob: None,
            properties: serde_json::Value::Object(Default::default()),
        };

        let expected_version = read_expected_version(&*self.events, &stream_id, true).await?;

        self.lifecycle
            .commit_transition(
                &artifact,
                AppendEvents {
                    stream_id,
                    expected_version,
                    events: vec![EventToAppend {
                        event_id: ingested_event_id,
                        event: DomainEvent::ArtifactIngested(ingested_event),
                    }],
                    correlation_id: Uuid::new_v4(),
                    causation_id: None,
                    actor: Actor::Api(actor),
                },
                Some(artifact_metadata),
            )
            .await
            .map_err(AppError::Domain)?;

        Ok(IngestOutcome {
            artifact,
            ingested_event_id,
        })
    }

    /// Sha256 verification path: shared by `ProtocolNative` and
    /// `UpstreamPublished(Sha256)`. The verification target is a
    /// `ContentHash`; comparison is `put_result.hash == upstream`,
    /// implemented today by the existing `declared_sha256` path of
    /// `ingest_inner`. The mismatch-emission machinery (rollback,
    /// `ChecksumMismatch` on the repository stream, metric tick) lives
    /// uniformly in [`Self::ingest_with_verification`] and is shared
    /// with the SHA-512 arm.
    #[allow(clippy::too_many_arguments)]
    async fn ingest_verified_sha256(
        &self,
        repository_id: Uuid,
        coords: ArtifactCoords,
        content_type: String,
        actor: ApiActor,
        payload_metadata: serde_json::Value,
        upstream_digest: ContentHash,
        algorithm: HashAlgorithm,
        // Best-effort upstream publish timestamp;
        // threaded onto Artifact.upstream_published_at by ingest_inner.
        upstream_published_at: Option<DateTime<Utc>>,
        // Serving mapping's opt-in flag; consumed by
        // ingest_inner's quarantine-anchor resolution.
        trust_upstream_publish_time: bool,
        stream: Box<dyn AsyncRead + Send + Unpin>,
        handler: &dyn FormatHandler,
    ) -> AppResult<IngestOutcome> {
        // Reuse `ingest_direct`'s wiring (curation gate, metadata cap,
        // strategy dispatch) by routing through a thin shim. We need a
        // declared_sha256 to enable the existing verification logic in
        // `ingest_inner`, so we synthesise an `IngestRequest` with the
        // upstream digest as the declared hash.
        let upstream_value = upstream_digest.to_string();

        let req = IngestRequest {
            repository_id,
            coords,
            content_type,
            // Verified-ingest paths never carry a seed-import anchor;
            // policy resolution inside `ingest_inner` drives the
            // quarantine decision.
            quarantine_anchor_override: None,
            actor,
            legacy_sha1: None,
            legacy_md5: None,
            declared_sha256: Some(upstream_digest),
            payload_metadata,
        };

        self.ingest_with_verification(
            req,
            stream,
            handler,
            Some(VerificationContext {
                algorithm,
                upstream_value,
                sha512_handle: None,
                sha1_handle: None,
            }),
            upstream_published_at,
            trust_upstream_publish_time,
        )
        .await
    }

    /// Sha512 verification path. Stream is wrapped in
    /// [`Sha512HashingRead`]; the wrapper's [`Sha512DigestHandle`] is
    /// threaded through `ingest_with_verification` and into
    /// `ingest_inner`, which finalises it post-`storage.put` and
    /// compares the resulting hex to `upstream_value`. The CAS hash
    /// remains SHA-256 (SHA-512 is
    /// verification-only state at the boundary, never persisted as a
    /// primary key — ADR 0003).
    ///
    /// - Mismatch: rollback CAS (guarded by `find_by_checksum` empty so
    ///   shared blobs are not corrupted), append `ChecksumMismatch` to
    ///   `StreamId::repository(repo_id)`, return `Conflict`. **No
    ///   Artifact row is minted** (mint-after-verify).
    /// - Match: mint Artifact, append `ArtifactIngested` and
    ///   `ChecksumVerified { algorithm: Sha512, … }` in the same
    ///   `commit_transition` batch on `StreamId::artifact(artifact_id)`
    ///   — atomic with the mint.
    #[allow(clippy::too_many_arguments)]
    async fn ingest_verified_sha512(
        &self,
        repository_id: Uuid,
        coords: ArtifactCoords,
        content_type: String,
        actor: ApiActor,
        payload_metadata: serde_json::Value,
        upstream_value: String,
        // Best-effort upstream publish timestamp;
        // threaded onto Artifact.upstream_published_at by ingest_inner.
        upstream_published_at: Option<DateTime<Utc>>,
        // Serving mapping's opt-in flag; consumed by
        // ingest_inner's quarantine-anchor resolution.
        trust_upstream_publish_time: bool,
        stream: Box<dyn AsyncRead + Send + Unpin>,
        handler: &dyn FormatHandler,
    ) -> AppResult<IngestOutcome> {
        // Wrap the input stream so SHA-512 is computed incrementally as
        // bytes flow through the wrapper into `storage.put`. The
        // digest handle survives the boxing (the hasher state lives in
        // an `Arc<Mutex<Sha512>>` shared between wrapper and handle);
        // `ingest_inner` finalises the handle post-put to recover the
        // SHA-512 hex without buffering bytes anywhere.
        let wrapped = Sha512HashingRead::new(stream);
        let handle = wrapped.digest_handle();
        let stream: Box<dyn AsyncRead + Send + Unpin> = Box::new(wrapped);

        // The SHA-512 verification arm does NOT use `declared_sha256` —
        // the storage CAS hash (SHA-256) is not the verification target.
        // `declared_sha256: None` lets the SHA-256 short-circuit logic
        // in `ingest_inner` stay inert; the SHA-512 comparison lives on
        // its own branch keyed off `verification.sha512_handle.is_some()`.
        let req = IngestRequest {
            repository_id,
            coords: coords.clone(),
            content_type,
            // SHA-512 verified-ingest path (npm SRI); no seed-import
            // anchor override applies here.
            quarantine_anchor_override: None,
            actor: actor.clone(),
            legacy_sha1: None,
            legacy_md5: None,
            declared_sha256: None,
            payload_metadata,
        };

        self.ingest_with_verification(
            req,
            stream,
            handler,
            Some(VerificationContext {
                algorithm: HashAlgorithm::Sha512,
                upstream_value,
                sha512_handle: Some(handle),
                sha1_handle: None,
            }),
            upstream_published_at,
            trust_upstream_publish_time,
        )
        .await
    }

    /// Sha1 transfer-verification *floor* path (ADR 0033 — the Maven
    /// `.sha1` sidecar, the only universally-available protocol-native
    /// digest on Maven Central). The SHA-1 sibling of
    /// [`Self::ingest_verified_sha512`]: the stream is wrapped in
    /// [`Sha1HashingRead`]; the wrapper's [`Sha1DigestHandle`] is threaded
    /// through `ingest_with_verification` and into `ingest_inner`, which
    /// finalises it post-`storage.put` and compares the resulting hex to
    /// `upstream_value`. The CAS hash remains SHA-256 — SHA-1 is
    /// verification-only state at the boundary, **never** a content-address
    /// (ADR 0003 / ADR 0033). SHA-1 is collision-broken; this floor catches
    /// transport corruption + casual tampering, with TLS (system trust +
    /// `HORT_EXTRA_CA_BUNDLE`) as the real transport-integrity control.
    ///
    /// - Mismatch: rollback CAS (guarded by `find_by_checksum` empty so
    ///   shared blobs are not corrupted), append `ChecksumMismatch` to
    ///   `StreamId::repository(repo_id)`, return `Conflict`. **No
    ///   Artifact row is minted** (mint-after-verify).
    /// - Match: mint Artifact, append `ArtifactIngested` and
    ///   `ChecksumVerified { algorithm: Sha1, … }` in the same
    ///   `commit_transition` batch on `StreamId::artifact(artifact_id)`
    ///   — atomic with the mint.
    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(skip(self, payload_metadata, stream, handler))]
    async fn ingest_verified_sha1(
        &self,
        repository_id: Uuid,
        coords: ArtifactCoords,
        content_type: String,
        actor: ApiActor,
        payload_metadata: serde_json::Value,
        upstream_value: String,
        // Best-effort upstream publish timestamp;
        // threaded onto Artifact.upstream_published_at by ingest_inner.
        upstream_published_at: Option<DateTime<Utc>>,
        // Serving mapping's opt-in flag; consumed by
        // ingest_inner's quarantine-anchor resolution.
        trust_upstream_publish_time: bool,
        stream: Box<dyn AsyncRead + Send + Unpin>,
        handler: &dyn FormatHandler,
    ) -> AppResult<IngestOutcome> {
        // Audit signal (design §8/§12): record that this artifact's
        // transfer was verified against the *weaker* SHA-1 floor — the
        // format-forced acceptance ADR 0033 documents. `info!`, never
        // `err`: the floor verification is a normal, expected path, not an
        // error condition. A mismatch still surfaces as the Conflict +
        // `ChecksumMismatch` audit event below; this log is the
        // floor-was-used breadcrumb.
        tracing::info!(
            repository_id = %repository_id,
            name = %coords.name,
            version = ?coords.version,
            "verifying upstream transfer against the SHA-1 floor (ADR 0033)"
        );

        // Wrap the input stream so SHA-1 is computed incrementally as
        // bytes flow through the wrapper into `storage.put`. The digest
        // handle survives the boxing (the hasher state lives in an
        // `Arc<Mutex<Sha1>>` shared between wrapper and handle);
        // `ingest_inner` finalises the handle post-put to recover the
        // SHA-1 hex without buffering bytes anywhere. Mirrors the SHA-512
        // path exactly.
        let wrapped = Sha1HashingRead::new(stream);
        let handle = wrapped.digest_handle();
        let stream: Box<dyn AsyncRead + Send + Unpin> = Box::new(wrapped);

        // The SHA-1 verification arm does NOT use `declared_sha256` — the
        // storage CAS hash (SHA-256) is not the verification target.
        // `declared_sha256: None` lets the SHA-256 short-circuit logic in
        // `ingest_inner` stay inert; the SHA-1 comparison lives on its own
        // branch keyed off `verification.sha1_handle.is_some()`.
        let req = IngestRequest {
            repository_id,
            coords: coords.clone(),
            content_type,
            // SHA-1 floor verified-ingest path (Maven pull-through); no
            // seed-import anchor override applies here.
            quarantine_anchor_override: None,
            actor: actor.clone(),
            legacy_sha1: None,
            legacy_md5: None,
            declared_sha256: None,
            payload_metadata,
        };

        self.ingest_with_verification(
            req,
            stream,
            handler,
            Some(VerificationContext {
                algorithm: HashAlgorithm::Sha1,
                upstream_value,
                sha512_handle: None,
                sha1_handle: Some(handle),
            }),
            upstream_published_at,
            trust_upstream_publish_time,
        )
        .await
    }

    /// Internal shim that runs `ingest_inner` with the
    /// [`VerificationContext`] threaded through so `ingest_inner` can
    /// inject `ChecksumVerified` into the same `commit_transition`
    /// batch as `ArtifactIngested` — atomic with the
    /// mint. The artifact_id and computed_value are
    /// filled in inline by `ingest_inner` once the row is minted; the
    /// caller supplies only the static parts (algorithm + upstream
    /// value).
    async fn ingest_with_verification(
        &self,
        request: IngestRequest,
        stream: Box<dyn AsyncRead + Send + Unpin>,
        handler: &dyn FormatHandler,
        verification: Option<VerificationContext>,
        // Best-effort upstream publish timestamp; the
        // verified-ingest call sites that constructed `IngestRequest`
        // pass the value extracted from `VerifiedIngestRequest` here.
        // `ingest_inner` writes it onto `Artifact.upstream_published_at`
        // before `commit_transition`. `None` ⇒ ingest-anchored
        // (publish-anchoring is gated on the per-
        // upstream opt-in flag).
        upstream_published_at: Option<DateTime<Utc>>,
        // Serving `RepositoryUpstreamMapping`'s
        // `trust_upstream_publish_time` flag. Threaded into
        // `ingest_inner` which gates the publish-anchored quarantine
        // resolution on it. Direct uploads pass `false`; pull-through
        // paths pass the mapping's value.
        trust_upstream_publish_time: bool,
    ) -> AppResult<IngestOutcome> {
        let IngestRequest {
            repository_id,
            coords,
            content_type,
            // The verified-ingest paths (OCI direct upload, pull-through
            // for OCI/npm/cargo/pypi) never set the seed-import anchor
            // override — they construct `IngestRequest` with this field
            // hard-coded to `None`. `ingest_inner` ignores the field;
            // only the `register_by_hash` consumer below threads it
            // through to stamp the seed-import quarantine event.
            quarantine_anchor_override: _,
            actor,
            legacy_sha1,
            legacy_md5,
            declared_sha256,
            payload_metadata,
        } = request;
        let format = coords.format.to_string();

        // Curation gate (mirror of `ingest_direct`).
        let rules = self
            .curation_rules
            .list_for_repo(repository_id)
            .await
            .map_err(AppError::Domain)?;
        match evaluate_curation(&coords, &rules) {
            CurationOutcome::Allow => {
                emit_policy_evaluation(
                    policy_decision_point::CURATION,
                    PolicyEvaluationResult::Pass,
                );
            }
            CurationOutcome::Warn { rule_name, reason } => {
                tracing::warn!(
                    rule = %rule_name,
                    reason = %reason,
                    format = %format,
                    name = %coords.name,
                    "curation rule warned at verified ingest"
                );
                emit_policy_evaluation(
                    policy_decision_point::CURATION,
                    PolicyEvaluationResult::Warn,
                );
                emit_policy_violations(
                    policy_decision_point::CURATION,
                    &[hort_domain::events::PolicyViolation {
                        rule: "curation-warn".to_string(),
                        severity: hort_domain::entities::scan_policy::SeverityThreshold::Low,
                        message: reason,
                        details: serde_json::Value::Null,
                    }],
                );
            }
            CurationOutcome::Block {
                rule_name,
                rule_id,
                reason,
            } => {
                tracing::info!(
                    rule = %rule_name,
                    %rule_id,
                    reason = %reason,
                    format = %format,
                    name = %coords.name,
                    "curation rule blocked verified ingest"
                );
                emit_policy_evaluation(
                    policy_decision_point::CURATION,
                    PolicyEvaluationResult::Block,
                );
                return Err(AppError::Domain(DomainError::CurationBlocked {
                    rule_name,
                    rule_id,
                    reason,
                }));
            }
        }

        // For verified ingest, we don't dispatch via the metadata
        // strategy / cap / split machinery — verified flows are
        // pull-through and direct upload paths whose payload metadata
        // is compact. Pass `Inline` strategy and the original payload.
        let metadata_decision = MetadataDecision::Inline(payload_metadata.clone());
        let had_payload_metadata = !matches!(payload_metadata, serde_json::Value::Null);

        // A CASCADE-INTERNAL leaf-ingest tags its payload_metadata with
        // `cascade_internal: true` so `ingest_inner` skips the depth-0 seed
        // hook (its parent's depth-carrying child row already walks this
        // artifact). Absent / non-leaf / seed ingests leave it unset →
        // `false` → the seed hook fires as before.
        let suppress_cascade_seed = payload_metadata
            .get("cascade_internal")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);

        // Preserve the audit identity (`coords`, `actor`) for the
        // mismatch-emission path, which runs AFTER `ingest_inner`
        // returns. The algorithm + upstream_value + computed_value
        // come back as typed fields on `InnerIngestError::VerificationMismatch`
        // (we do not parse the inner Conflict
        // message string to recover them). The audit identity still
        // has to be captured pre-call because `coords` and `actor`
        // are moved into `ingest_inner` below.
        let mismatch_audit = verification
            .as_ref()
            .map(|_| (coords.clone(), actor.clone()));

        let verified_metric_target = verification
            .as_ref()
            .map(|_| UpstreamChecksumResult::Verified);
        let result = self
            .ingest_inner(
                repository_id,
                coords,
                stream,
                content_type,
                actor,
                format.clone(),
                legacy_sha1,
                legacy_md5,
                declared_sha256,
                metadata_decision,
                had_payload_metadata,
                handler,
                verification,
                upstream_published_at,
                trust_upstream_publish_time,
                suppress_cascade_seed,
            )
            .await;

        // Emit hort_ingest_total on every exit path — the OCI uploads tests
        // assert this fires for both success and failure. Mirror the
        // shape used by ingest_direct.
        let emit_ingest_total = |result_label: &str, repo_key: Option<&str>| {
            metrics::counter!(
                "hort_ingest_total",
                labels::FORMAT => format.clone(),
                labels::REPOSITORY => self.repo_label(repo_key),
                labels::RESULT => result_label.to_string(),
            )
            .increment(1);
        };

        match result {
            Ok((artifact, was_duplicate, repo_key, ingested_event_id)) => {
                let result_label = if was_duplicate {
                    IngestResult::Duplicate.as_str()
                } else {
                    IngestResult::Success.as_str()
                };
                emit_ingest_total(result_label, Some(&repo_key));
                if verified_metric_target.is_some() {
                    emit_upstream_checksum(&format, UpstreamChecksumResult::Verified);
                }
                Ok(IngestOutcome {
                    artifact,
                    ingested_event_id,
                })
            }
            Err((inner_err, repo_key, preclassified)) => {
                // Verification mismatch emission. A substring
                // discriminator (`msg.contains("computed=")` against
                // the inner `Conflict` message) is deliberately avoided
                // in favour of this typed-enum
                // dispatch: `InnerIngestError::VerificationMismatch`
                // carries algorithm/upstream/computed as first-class
                // fields, and `Other` is everything else (path
                // conflict, storage failure, domain error, curation
                // block, …). Audit-emission is now a type-driven
                // decision, no longer coupled to the wording of the
                // inner Conflict string.
                match inner_err {
                    InnerIngestError::VerificationMismatch {
                        algorithm,
                        upstream_value,
                        computed_value,
                        source,
                    } => {
                        // `source` is the original
                        // `AppError::Domain(Conflict(...))` so
                        // `classify_ingest_error` and the wire-response
                        // shape see the same value as before this
                        // refactor.
                        let ingest_result = preclassified
                            .as_ref()
                            .copied()
                            .unwrap_or_else(|| classify_ingest_error(&source));
                        emit_ingest_total(ingest_result.as_str(), repo_key.as_deref());
                        emit_upstream_checksum(&format, UpstreamChecksumResult::Mismatch);

                        // The audit identity (`coords` + `actor`) was
                        // captured pre-call because `ingest_inner`
                        // consumes `coords` and `actor` by value. The
                        // verification-mismatch arm by definition sees
                        // a non-`None` `verification`, so
                        // `mismatch_audit` is `Some` here — we expect
                        // the pair to be present. If it is somehow
                        // `None` (defensive), skip audit emission and
                        // log; do NOT panic.
                        if let Some((mismatch_coords, mismatch_actor)) = mismatch_audit {
                            let evt = ChecksumMismatch {
                                repository_id,
                                coords: mismatch_coords,
                                format: format.clone(),
                                algorithm,
                                upstream_value: upstream_value.clone(),
                                computed_value,
                            };
                            if let Err(append_err) = self
                                .append_repository_event(
                                    repository_id,
                                    DomainEvent::ChecksumMismatch(evt),
                                    Actor::Api(mismatch_actor),
                                )
                                .await
                            {
                                tracing::warn!(
                                    error = %append_err,
                                    repo_id = %repository_id,
                                    format = %format,
                                    "failed to append ChecksumMismatch to repository stream"
                                );
                            }
                            // `upstream_value` is on the ChecksumMismatch
                            // event for audit; the warn line carries the
                            // labels needed to grep across stream-store and
                            // tracing. NEVER `artifact_id` — none was
                            // minted (mint-after-verify).
                            tracing::warn!(
                                repo_id = %repository_id,
                                format = %format,
                                algorithm = ?algorithm,
                                upstream_value = %upstream_value,
                                "verified ingest rejected: checksum mismatch"
                            );
                        } else {
                            tracing::warn!(
                                repo_id = %repository_id,
                                format = %format,
                                "VerificationMismatch returned without captured audit identity; \
                                 skipping ChecksumMismatch emission"
                            );
                        }
                        Err(source)
                    }
                    InnerIngestError::Other(err) => {
                        let ingest_result = preclassified
                            .as_ref()
                            .copied()
                            .unwrap_or_else(|| classify_ingest_error(&err));
                        emit_ingest_total(ingest_result.as_str(), repo_key.as_deref());
                        Err(err)
                    }
                }
            }
        }
    }

    /// Roll back a freshly-written CAS blob whose verification target
    /// disagreed with the computed hash, but **only if no other
    /// artifact row references the hash**. Shared by the
    /// `declared_sha256` mismatch arm and the
    /// SHA-512 verification arm — both arms have the same
    /// rollback semantics from `crates/hort-domain/src/ports/storage.rs`
    /// lines 55-64: deleting a shared blob would corrupt the
    /// referencing row, so the `find_by_checksum` empty-set guard is
    /// load-bearing.
    ///
    /// Lookup-failure path: a transient `find_by_checksum` error means
    /// we cannot prove the blob is unreferenced, so the rollback is
    /// skipped conservatively (fail-*safe* — never delete a possibly
    /// shared blob). Delete-failure path: same best-effort handling —
    /// the hash is logged and the write is left in place.
    ///
    /// Either skip leaves a content-addressed blob unreferenced. There
    /// is **no orphan reaper**: `CasScrubUseCase` is integrity-only
    /// (re-hash + `Alert`-by-default) and never deletes/reclaims a
    /// blob. The blob accumulates *harmlessly* — content-addressing
    /// means it can never collide with or corrupt a future write, and a
    /// later organic re-upload of the same bytes dedupes straight onto
    /// it. So this is a bounded storage-reclamation residual, not a
    /// correctness, deletion, or divergence risk.
    ///
    /// **Accepted residual.** This
    /// row-less orphan — a `put` that succeeded but whose artifact row /
    /// `content_references` row was never committed — is *not* reclaimed
    /// by storage-GC: `PurgeUseCase::process_expired`
    /// walks expired **artifact rows** and decrements their
    /// `content_references`, so a blob with no row is never enumerated.
    /// A bounded reaper was considered and rejected — it would need a
    /// full-storage walk cross-referenced against `content_references`
    /// plus an age grace-period to avoid racing an in-flight ingest's
    /// not-yet-committed blob (a TOCTOU delete hazard), which is not
    /// justified by a residual that is rare (rollback-delete failure
    /// only), bounded by the failure rate, and collision-free by
    /// construction. The growth bound + operator guidance live in
    /// `docs/architecture/explanation/cas-storage.md` §"Orphaned
    /// content".
    ///
    /// `context_label` carries the originating arm's name into the
    /// `warn!` log line so an operator can grep "which verification
    /// arm tripped this rollback?" without correlating across spans.
    async fn rollback_unreferenced_cas(&self, hash: &ContentHash, context_label: &str) {
        let shared = match self.artifacts.find_by_checksum(hash).await {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(e) => {
                tracing::warn!(
                    %hash,
                    err = ?e,
                    context = %context_label,
                    "find_by_checksum failed during verification rollback; \
                     skipping delete (fail-safe: blob may be shared). \
                     Unreferenced blob accumulates harmlessly; accepted \
                     bounded residual, no reaper"
                );
                true
            }
        };
        if !shared {
            if let Err(e) = self.storage.delete(hash).await {
                tracing::warn!(
                    %hash,
                    err = ?e,
                    context = %context_label,
                    "cas rollback failed on verification mismatch; \
                     unreferenced blob accumulates harmlessly; accepted \
                     bounded residual, no reaper"
                );
            }
        }
    }

    /// Append a single event to a repository-aggregate stream
    /// (verification audit-event helper).
    // pub(crate) for the audit-stream-uncapped regression test
    pub(crate) async fn append_repository_event(
        &self,
        repository_id: Uuid,
        event: DomainEvent,
        actor: Actor,
    ) -> AppResult<()> {
        let stream_id = StreamId::repository(repository_id);
        // Repository streams are long-lived aggregates that accumulate
        // audit events forever. The workspace-wide `STREAM_EVENT_CAP`
        // is calibrated for *artifact* streams (finite lifecycle, ~5–10
        // events). Capping the audit stream silently drops
        // `ChecksumMismatch` events past the 200th — exactly when an
        // audit trail matters most (sustained tampering = many events).
        // The "auditors run … get zero rows by design" invariant
        // requires uncapped emission on the repository aggregate, so
        // this caller passes `enforce_cap=false`.
        let expected_version = read_expected_version(&*self.events, &stream_id, false).await?;
        self.events
            .append(AppendEvents {
                stream_id,
                expected_version,
                events: vec![EventToAppend {
                    event_id: Uuid::new_v4(),
                    event,
                }],
                correlation_id: Uuid::new_v4(),
                causation_id: None,
                actor,
            })
            .await
            .map_err(AppError::Domain)?;
        Ok(())
    }

    /// Inner ingest implementation. Returns
    /// `(artifact, was_duplicate, repo_key, ingested_event_id)` on success
    /// and `(error, Some(repo_key))` on failure once the repository has been
    /// resolved (or `None` when it has not).
    ///
    /// `ingested_event_id` is the `EventToAppend::event_id` committed via
    /// `ArtifactLifecyclePort::commit_transition` on the fresh-ingest path,
    /// and a freshly-minted `Uuid` on the dedup path (see [`IngestOutcome`]
    /// docstring for why the type is non-optional).
    ///
    /// `metadata_decision` is the deferred output of the outer `ingest`
    /// method's strategy dispatch. For Inline-strategy
    /// handlers — and HashReference handlers whose payload stayed under
    /// the inline threshold — the variant is `Inline(full_payload)` and
    /// no blob is written. For HashReference handlers that are actually
    /// splitting, the variant is `Pending { bytes, summary }`: the blob
    /// is put to CAS ONLY AFTER the dedup checks below have cleared, so
    /// a duplicate re-publish does not orphan a just-written CAS
    /// object.
    #[allow(clippy::too_many_arguments)]
    async fn ingest_inner(
        &self,
        repository_id: Uuid,
        coords: ArtifactCoords,
        stream: Box<dyn AsyncRead + Send + Unpin>,
        content_type: String,
        actor: ApiActor,
        format: String,
        legacy_sha1: Option<String>,
        legacy_md5: Option<String>,
        declared_sha256: Option<ContentHash>,
        metadata_decision: MetadataDecision,
        // Whether the caller passed payload
        // metadata at all. Gates emission of
        // `hort_ingest_metadata_strategy_total` — callers with nothing
        // to persist (proxy fetches, `Value::Null` payloads) do NOT
        // tick the counter.
        had_payload_metadata: bool,
        // Consulted post-commit to classify the
        // uploaded file into an artifact group. Passed as
        // `&dyn FormatHandler` (not cloned) — the handler is borrowed
        // for the duration of the call from the outer `ingest`.
        handler: &dyn FormatHandler,
        // When present, `ChecksumVerified` is
        // appended to the same `commit_transition` batch as
        // `ArtifactIngested` — atomic with the mint. The artifact_id
        // and computed_value can only be filled in once `ingest_inner`
        // has minted the row, so the caller passes the static parts
        // (algorithm + upstream value) as `VerificationContext` and
        // `ingest_inner` constructs the full event inline. `None` for
        // the direct-upload path.
        verification: Option<VerificationContext>,
        // Best-effort upstream publish timestamp.
        // Stamped onto `Artifact.upstream_published_at` (audit only)
        // before `commit_transition`; recorded
        // unconditionally. The quarantine-window anchor stays
        // `ingested_at` unless
        // the anchor flips to `min(upstream_published_at, ingested_at)`
        // when the serving mapping's `trust_upstream_publish_time`
        // opt-in (`trust_upstream_publish_time` below) is `true`.
        upstream_published_at: Option<DateTime<Utc>>,
        // Serving `RepositoryUpstreamMapping`'s
        // `trust_upstream_publish_time` opt-in. Gates the
        // publish-anchored quarantine resolution below:
        //
        // - `false` (direct upload OR pull-through with the flag off):
        //   `quarantine_window_start = ingested_at`.
        // - `true` AND `upstream_published_at.is_some()`:
        //   `quarantine_window_start = min(upstream_published_at, ingested_at)`
        //   — the `min` is the future-skew clamp: a claimed
        //   publish time *after* ingest is physically impossible, so a
        //   buggy/malicious upstream cannot extend its own quarantine
        //   into the future via the opt-in.
        // - `true` AND `upstream_published_at.is_none()`: best-effort
        //   degrades to `ingested_at` (no hint, no anchor flip).
        //
        // Direct uploads always pass `false` from the inbound HTTP
        // adapter (no serving mapping in scope), so this single flag
        // collapses the "direct vs pull-through" + "opted-in vs not"
        // disambiguation into a single signal that `ingest_inner`
        // consumes without having to inspect the request's byte source.
        trust_upstream_publish_time: bool,
        // When `true`, skip the post-commit transitive-prefetch
        // *seed* hook (the depth-0 `prefetch-dependencies` enqueue). Set by a
        // CASCADE-INTERNAL `prefetch` leaf-ingest, whose artifact is already
        // walked by its parent's depth-carrying child row; firing the seed
        // hook there would double-walk and reset the cascade depth to 0.
        // Direct uploads + client-pull + self-service ROOT leaves pass
        // `false` (they ARE the seed). Derived from the verified request's
        // `payload_metadata.cascade_internal` in `ingest_with_verification`.
        suppress_cascade_seed: bool,
    ) -> Result<
        (Artifact, bool, String, Uuid),
        (InnerIngestError, Option<String>, Option<IngestResult>),
    > {
        // 1. Verify repository exists. The repo is needed both for the
        // `repository` metric label and for downstream quarantine emission.
        let repo = self
            .repositories
            .find_by_id(repository_id)
            .await
            .map_err(|e| (InnerIngestError::Other(AppError::Domain(e)), None, None))?;
        let repo_key = repo.key.clone();

        // 2. Verify the format matches — a PyPI handler must not ingest into
        // an npm repository. Reject BEFORE `storage.put` so a mismatched
        // request cannot create a CAS orphan. The caller controls both
        // `coords.format` (derived from the route) and the target repo
        // (its key), so the mismatch is a clean `Validation` error.
        if coords.format != repo.format {
            return Err((
                InnerIngestError::Other(AppError::Domain(DomainError::Validation(format!(
                    "format mismatch: repository {} is {}, coords declare {}",
                    repo_key, repo.format, coords.format
                )))),
                Some(repo_key),
                None,
            ));
        }

        // 3. Look up any existing artifact at the same logical path BEFORE
        // writing bytes. When the caller supplies `declared_sha256`, this
        // short-circuits both the dedup and conflict decisions with zero
        // storage I/O — and, critically, a conflict decision no longer
        // requires uploading the content first (the most common source of
        // avoidable orphans). When the caller supplies no declared hash, the
        // existing post-put comparison below still runs as before.
        // See `docs/architecture/explanation/cas-storage.md` §"Orphaned
        // content".
        let existing = self
            .artifacts
            .find_by_path(repository_id, &coords.path)
            .await
            .map_err(|e| {
                (
                    InnerIngestError::Other(AppError::Domain(e)),
                    Some(repo_key.clone()),
                    None,
                )
            })?;

        if let (Some(existing), Some(declared)) = (existing.as_ref(), declared_sha256.as_ref()) {
            if existing.sha256_checksum == *declared {
                tracing::debug!(
                    artifact_id = %existing.id,
                    "deduplicated via declared hash"
                );
                return Ok((existing.clone(), true, repo_key, Uuid::new_v4()));
            }
            return Err((
                InnerIngestError::Other(AppError::Domain(DomainError::Conflict(format!(
                    "path {} already exists with different content (existing={}, declared={})",
                    coords.path, existing.sha256_checksum, declared
                )))),
                Some(repo_key),
                None,
            ));
        }

        // 4. Store content — CAS computes hash + size. Wrap the storage
        // error explicitly so metric classification can distinguish storage
        // failures from domain errors.
        let put_result = self.storage.put(stream).await.map_err(|e| {
            (
                InnerIngestError::Other(AppError::Storage(e.to_string())),
                Some(repo_key.clone()),
                None,
            )
        })?;

        // 5. Post-put duplicate check by path — only reached when the caller
        // supplied no `declared_sha256` (or when `declared_sha256` was set
        // but `find_by_path` returned `None` at step 3, meaning no existing
        // row to compare against). Behaviour unchanged from the original
        // flow.
        if let Some(existing) = existing {
            if existing.sha256_checksum == put_result.hash {
                tracing::debug!(
                    artifact_id = %existing.id,
                    "deduplicated"
                );
                return Ok((existing, true, repo_key, Uuid::new_v4()));
            }
            return Err((
                InnerIngestError::Other(AppError::Domain(DomainError::Conflict(format!(
                    "path {} already exists with different content (existing={}, new={})",
                    coords.path, existing.sha256_checksum, put_result.hash
                )))),
                Some(repo_key),
                None,
            ));
        }

        // 5a. Fresh-insert path: verify the caller-declared hash matches
        // the hash we just computed while streaming to CAS.
        // `declared_sha256` is a client-side integrity
        // contract — the OCI monolithic PUT, PUT finalize, and
        // manifest-digest PUT all depend on this check returning
        // `Conflict` on mismatch.
        //
        // On mismatch: roll back the freshly-written CAS blob via
        // `StoragePort::delete` ONLY IF no other artifact row
        // references the hash. The dedup guard uses
        // `ArtifactRepository::find_by_checksum`; a hit means the hash
        // is shared with another repository (cross-mount, organic
        // re-upload) and deleting would corrupt the referencing row.
        // Rollback failures (backend I/O, port lookup error) log
        // `warn!` and continue — the uncommitted blob is left
        // unreferenced. No orphan reaper exists (`CasScrubUseCase` is
        // integrity-only, never deletes); a content-addressed blob is
        // collision-free so this accumulates harmlessly. This row-less
        // orphan is an accepted bounded residual:
        // storage-GC walks expired artifact
        // rows and does NOT reclaim a blob with no row; a reaper was
        // considered and rejected — see `rollback_unreferenced_cas` docs.
        if let Some(declared) = declared_sha256.as_ref() {
            if *declared != put_result.hash {
                self.rollback_unreferenced_cas(&put_result.hash, "declared_sha256 mismatch")
                    .await;
                let source = AppError::Domain(DomainError::Conflict(format!(
                    "declared sha256 does not match computed hash \
                     (declared={declared}, computed={})",
                    put_result.hash
                )));
                // Typed-variant dispatch: the
                // outer `ingest_with_verification` peels this variant
                // to decide whether to emit `ChecksumMismatch` to the
                // repository audit stream. A string discriminator
                // like `msg.contains("computed=")` would silently
                // disable audit emission on any reword of the inner
                // Conflict message. The `source` field is preserved
                // verbatim so wire-response shape, metric labels, and
                // `classify_ingest_error` taxonomy do not change.
                return Err((
                    InnerIngestError::VerificationMismatch {
                        algorithm: HashAlgorithm::Sha256,
                        upstream_value: declared.to_string(),
                        computed_value: put_result.hash.to_string(),
                        source,
                    },
                    Some(repo_key),
                    Some(IngestResult::DeclaredHashMismatch),
                ));
            }
        }

        // 5b. SHA-512 verification arm. Reached only
        // for the npm SRI path; SHA-256 verification piggybacks on the
        // `declared_sha256` machinery above. Finalising the digest
        // handle here also resets the shared hasher (see
        // `Sha512DigestHandle::finalize` docstring), so the value is
        // captured into a local variable for reuse when constructing
        // `ChecksumVerified` further down.
        let computed_sha512_hex: Option<String> = match verification.as_ref() {
            Some(VerificationContext {
                sha512_handle: Some(handle),
                upstream_value,
                ..
            }) => {
                let computed = lower_hex(&handle.finalize());
                if computed != *upstream_value {
                    self.rollback_unreferenced_cas(&put_result.hash, "sha512 upstream mismatch")
                        .await;
                    let source = AppError::Domain(DomainError::Conflict(format!(
                        "upstream sha512 does not match computed hash \
                         (upstream={upstream_value}, computed={computed})"
                    )));
                    // Typed-variant dispatch. See
                    // the SHA-256 site above for the rationale: outer
                    // layer matches on `VerificationMismatch`, not on
                    // the message string.
                    return Err((
                        InnerIngestError::VerificationMismatch {
                            algorithm: HashAlgorithm::Sha512,
                            upstream_value: upstream_value.clone(),
                            computed_value: computed.clone(),
                            source,
                        },
                        Some(repo_key),
                        Some(IngestResult::DeclaredHashMismatch),
                    ));
                }
                Some(computed)
            }
            _ => None,
        };

        // 5c. SHA-1 transfer-verification *floor* arm (ADR 0033 — the
        // Maven `.sha1` sidecar). The SHA-1 sibling of the SHA-512 arm
        // above; reached only for the `UpstreamPublished(Sha1)` path. The
        // CAS key remains SHA-256 — SHA-1 is the transfer comparison only,
        // never a content-address. Finalising the handle resets the shared
        // hasher (see `Sha1DigestHandle::finalize`), so the value is
        // captured here for reuse when constructing `ChecksumVerified`.
        // At most one of `sha512_handle` / `sha1_handle` is `Some`, so
        // these two arms are mutually exclusive.
        let computed_sha1_hex: Option<String> = match verification.as_ref() {
            Some(VerificationContext {
                sha1_handle: Some(handle),
                upstream_value,
                ..
            }) => {
                let computed = lower_hex(&handle.finalize());
                if computed != *upstream_value {
                    self.rollback_unreferenced_cas(&put_result.hash, "sha1 upstream mismatch")
                        .await;
                    let source = AppError::Domain(DomainError::Conflict(format!(
                        "upstream sha1 does not match computed hash \
                         (upstream={upstream_value}, computed={computed})"
                    )));
                    // Typed-variant dispatch. See
                    // the SHA-256 site above for the rationale: outer
                    // layer matches on `VerificationMismatch`, not on
                    // the message string.
                    return Err((
                        InnerIngestError::VerificationMismatch {
                            algorithm: HashAlgorithm::Sha1,
                            upstream_value: upstream_value.clone(),
                            computed_value: computed.clone(),
                            source,
                        },
                        Some(repo_key),
                        Some(IngestResult::DeclaredHashMismatch),
                    ));
                }
                Some(computed)
            }
            _ => None,
        };

        // Resolve the deferred
        // metadata decision. The blob's `storage.put` happens HERE —
        // AFTER both dedup returns above — so a duplicate re-publish
        // never orphans a fresh CAS object. See `MetadataDecision`
        // docstring.
        let (final_metadata, final_blob, strategy_label): (
            serde_json::Value,
            Option<ContentHash>,
            &'static str,
        ) = match metadata_decision {
            MetadataDecision::Inline(value) => (value, None, values::STRATEGY_INLINE),
            MetadataDecision::Pending { bytes, summary } => {
                let put_result = self
                    .storage
                    .put(Box::new(std::io::Cursor::new(bytes)))
                    .await
                    .map_err(|e| {
                        (
                            InnerIngestError::Other(AppError::Storage(e.to_string())),
                            Some(repo_key.clone()),
                            None,
                        )
                    })?;
                (
                    summary,
                    Some(put_result.hash),
                    values::STRATEGY_HASH_REFERENCE,
                )
            }
        };

        // 4. Build Artifact entity.
        //
        // Retain `coords` by cloning into the
        // Artifact's fields (rather than moving) so the post-commit
        // group-membership hook below can classify against the
        // original coords + path. The clone is cheap relative to the
        // storage round-trip we just completed; the alternative of
        // reconstructing from `artifact` would lose `coords.format`
        // and `coords.metadata` (format is trivially recoverable from
        // `repo.format`; `coords.metadata` — a format-handler opaque
        // blob that `parse_download_path` may have populated — is not).
        let artifact_id = Uuid::new_v4();
        let now = Utc::now();
        let mut artifact = Artifact {
            id: artifact_id,
            repository_id,
            name: coords.name.clone(),
            name_as_published: coords.name_as_published.clone(),
            version: coords.version.clone(),
            path: coords.path.clone(),
            size_bytes: put_result.size_bytes as i64,
            sha256_checksum: put_result.hash.clone(),
            sha1_checksum: legacy_sha1,
            md5_checksum: legacy_md5,
            content_type,
            quarantine_status: QuarantineStatus::None,
            rejection_reason: None,
            quarantine_window_start: None,
            quarantine_deadline: None,
            // Record the upstream-asserted publish
            // hint unconditionally (audit only). Anchor resolution is
            // gated separately on the per-upstream opt-in.
            upstream_published_at,
            uploaded_by: actor_to_uploaded_by(&actor),
            is_deleted: false,
            created_at: now,
            updated_at: now,
        };

        // 5. Emit ArtifactIngested + save artifact.
        let stream_id = StreamId::artifact(artifact_id);
        let correlation_id = Uuid::new_v4();
        // Pre-mint the ArtifactIngested event_id locally so it doubles
        // as the `causation_id` on the post-commit
        // `ArtifactGroupMemberAdded`. The adapter binds
        // this id verbatim (via `EventToAppend`), so the value landed
        // here is the same value persisted in `events.event_id` — the
        // ingest-path causation chain now resolves.
        let artifact_ingested_event_id = Uuid::new_v4();
        // Clone the ApiActor before moving it into `AppendEvents` below —
        // the post-commit group hook needs `Actor::Api(actor.clone())`
        // to thread the same caller identity into `ArtifactGroupMemberAdded`.
        let actor_for_group = actor.clone();

        // Snapshot the metadata-blob hash before it's moved
        // into the projection row below. Used post-commit to write the
        // `kind = "metadata_blob"` refcount row (Some) or skip the
        // metadata-blob refcount write (None).
        let metadata_blob_for_refcount = final_blob.clone();

        let ingested_event = ArtifactIngested {
            artifact_id,
            repository_id,
            name: artifact.name.clone(),
            version: artifact.version.clone(),
            sha256: put_result.hash,
            size_bytes: artifact.size_bytes,
            source: IngestSource::Direct,
            // `final_metadata` is the outer strategy dispatch's output:
            // full payload for Inline, summary for a split HashReference,
            // full payload for HashReference under its inline threshold.
            metadata: final_metadata.clone(),
            // `final_blob` is `Some(hash)` iff the outer dispatch put
            // the full payload to CAS.
            metadata_blob: final_blob.clone(),
            // Record the upstream-asserted
            // publish hint on the *event* alongside the projection
            // (it is written onto `Artifact.upstream_published_at`
            // too; the event is the rebuild source of truth, so
            // both must carry the same value). The opt-in path makes
            // this
            // value load-bearing for `quarantine_window_start`; a
            // projection rebuild that lost the hint would silently
            // shift release authority on every replay.
            upstream_published_at,
        };

        // 1:1 projection row sharing the event's metadata verbatim. The
        // repository's `format` is the authority here — coords.format has
        // already been validated to match at step 2, so either source would
        // yield the same value; repo.format is the documented write site
        // for the projection.
        //
        // `metadata_blob` matches the event's — the projection row is a
        // materialised view of the event stream and must not diverge.
        // Snapshot `repo.format` BEFORE the move
        // into `ArtifactMetadata` below. The post-commit
        // `enqueue_scan` call needs the format string for the jobs
        // row; `RepositoryFormat` is `!Copy` so the move below would
        // make `repo.format` unreachable from here on.
        let scan_enqueue_format = repo.format.to_string();

        let artifact_metadata = ArtifactMetadata {
            artifact_id,
            format: repo.format,
            metadata: final_metadata,
            metadata_blob: final_blob,
            properties: serde_json::Value::Object(Default::default()),
        };

        let expected_version = read_expected_version(&*self.events, &stream_id, true)
            .await
            .map_err(|e| (InnerIngestError::Other(e), Some(repo_key.clone()), None))?;

        let mut events = vec![EventToAppend {
            event_id: artifact_ingested_event_id,
            event: DomainEvent::ArtifactIngested(ingested_event),
        }];
        if let Some(ctx) = verification.as_ref() {
            // For SHA-256 verification, the storage CAS hash IS the
            // verification hash, so `artifact.sha256_checksum` is the
            // computed value. For SHA-512 the value was finalised at step
            // 5b (pinned into `computed_sha512_hex`); for the SHA-1 floor
            // at step 5c (pinned into `computed_sha1_hex`) — both because
            // the streaming hasher cannot be re-read after the boxed
            // stream has been consumed. At most one of the two is `Some`
            // (one algorithm verifies one ingest), so the precedence is
            // unambiguous; SHA-256 is the `None`/`None` fallthrough.
            let computed_value = computed_sha512_hex
                .clone()
                .or_else(|| computed_sha1_hex.clone())
                .unwrap_or_else(|| artifact.sha256_checksum.to_string());
            events.push(EventToAppend {
                event_id: Uuid::new_v4(),
                event: DomainEvent::ChecksumVerified(ChecksumVerified {
                    artifact_id,
                    algorithm: ctx.algorithm,
                    upstream_value: ctx.upstream_value.clone(),
                    computed_value,
                }),
            });
        }

        // Resolve the `ScanPolicy` governing
        // this ingest. A repo-scoped or global operator policy wins;
        // `None` means no operator policy, in which case the hardcoded
        // `DefaultPolicy` applies (see `scan_will_run` below —
        // resolution tier 3). The decision is captured here so the
        // post-commit `enqueue_scan` call sees the same outcome as the
        // appended `ScanRequested` event (no race where the policy is
        // archived between event-append and jobs-row insert).
        let matched_policy: Option<ScanPolicyProjection> = self
            .resolve_active_policy_for_repo(repository_id)
            .await
            .unwrap_or_else(|e| {
                // Policy-lookup failure is non-fatal: log + treat as
                // "no policy applies". The artifact still ingests; an
                // operator can manually rescan once the projection is
                // back. Aborting the ingest on a projection-read
                // failure would make scanning a hard dependency of
                // ingest, which the design explicitly avoids.
                tracing::warn!(
                    artifact_id = %artifact_id,
                    repository_id = %repository_id,
                    error = %e,
                    "ingest: policy_projections.list_active failed; \
                     skipping scan auto-enqueue (artifact still ingests)",
                );
                None
            });
        // Does a scan run for this ingest? A matched
        // operator policy decides via its own `scan_backends` (an empty
        // list = scanning waived by the operator); with no operator
        // policy the hardcoded `DefaultPolicy` applies (`["trivy"]`), so
        // out-of-the-box deployments scan with Trivy. Mirrors the
        // already-correct resolution in `ScanOrchestrationUseCase`.
        let scan_will_run = match matched_policy.as_ref() {
            Some(p) => !p.scan_backends.is_empty(),
            None => !DefaultPolicy::block_on_critical_default_backends().is_empty(),
        };
        if scan_will_run {
            events.push(EventToAppend {
                event_id: Uuid::new_v4(),
                event: DomainEvent::ScanRequested(ScanRequested {
                    artifact_id,
                    // `scanner` is informational on the event payload;
                    // the actual backends resolve at orchestration time
                    // from the resolved policy's `scan_backends`. Use
                    // the operator policy name, or "default" when the
                    // hardcoded `DefaultPolicy` drove the scan, so a
                    // reader of the event log can correlate the request.
                    scanner: matched_policy
                        .as_ref()
                        .map(|p| p.name.clone())
                        .unwrap_or_else(|| "default".to_string()),
                }),
            });
        }

        // Ingest-time job enqueues, committed **atomically** with the
        // transition (ADR 0002/0004 no-strand): `commit_transition_with_enqueues`
        // lands the `ScanRequested` / provenance-gate events, the artifact
        // projection, and these `jobs` rows in one transaction, so a
        // crash/failure can never leave the artifact ingested-but-unscanned
        // (the dual-write strand that previously needed an operator manual
        // rescan to recover). The scan enqueue is idempotent at the adapter
        // (`ON CONFLICT DO NOTHING`); any other enqueue failure aborts the
        // whole ingest (retriable by the client), never a partial commit.
        //
        // Both gates resolve from the same `matched_policy` snapshot the
        // `events` batch above used (no race). `scan_will_run` already decided
        // whether `ScanRequested` is in `events`. The provenance gate mirrors
        // ADR 0027: enqueue iff `mode != Off` AND a registered verifier
        // `applies_to(format)` — gating on `mode != Off` alone would enqueue a
        // no-op for every non-OCI ingest under the default `VerifyIfPresent`
        // (Tier-1 cosign applies only to `"oci"`); the `provenance_capable_formats`
        // set carries exactly the formats some registered port can act on, and
        // the gate auto-activates when a Tier-2 verifier later registers (no
        // migration). An absent policy resolves to the `ProvenanceMode` default
        // (`VerifyIfPresent`).
        let provenance_mode = matched_policy
            .as_ref()
            .map(|p| p.provenance_mode)
            .unwrap_or_default();
        let provenance_will_run = provenance_mode != ProvenanceMode::Off
            && self
                .provenance_capable_formats
                .contains(&scan_enqueue_format);

        let mut enqueues: Vec<IngestEnqueue> = Vec::new();
        if scan_will_run {
            enqueues.push(IngestEnqueue::Scan {
                format: scan_enqueue_format.clone(),
                priority: 0, // default tier for ingest-time enqueue
                trigger_source: "ingest".to_string(),
            });
        }
        if provenance_will_run {
            enqueues.push(IngestEnqueue::ProvenanceVerify {
                priority: 0, // default tier for ingest-time enqueue
                trigger_source: "ingest".to_string(),
            });
        }

        self.lifecycle
            .commit_transition_with_enqueues(
                &artifact,
                AppendEvents {
                    stream_id: stream_id.clone(),
                    expected_version,
                    events,
                    correlation_id,
                    causation_id: None,
                    actor: Actor::Api(actor),
                },
                Some(artifact_metadata),
                &enqueues,
            )
            .await
            .map_err(|e| {
                (
                    InnerIngestError::Other(AppError::Domain(e)),
                    Some(repo_key.clone()),
                    None,
                )
            })?;

        // Refcount projection writes. Run AFTER
        // `commit_transition` succeeds (the artifact is persisted-and-
        // valid by this point). Insert failure is recoverable: the
        // refcount row is eventual; an operator-side reconcile
        // sweep catches any divergence. We do NOT abort the ingest on
        // refcount-insert failure — the artifact is already alive and
        // downloadable, and a missing refcount row only delays GC, it
        // doesn't break correctness.
        //
        // Mirrors the warn shape used by the OCI manifest-PUT
        // content_references insert (see `crates/hort-http-oci/src/
        // manifests_write.rs` near `stage = "content_references_insert"`).
        let now_for_refcount = Utc::now();
        if let Err(e) = self
            .content_references
            .insert(ContentReference {
                source_artifact_id: artifact.id,
                target_content_hash: artifact.sha256_checksum.clone(),
                kind: "primary_content".to_string(),
                metadata: serde_json::Value::Object(serde_json::Map::new()),
                repository_id,
                recorded_at: now_for_refcount,
            })
            .await
        {
            tracing::warn!(
                artifact_id = %artifact.id,
                kind = "primary_content",
                error = %e,
                stage = "content_references_insert",
                "content_references insert failed; refcount eventual — operator reconcile is future work"
            );
        }
        if let Some(blob_hash) = metadata_blob_for_refcount {
            if let Err(e) = self
                .content_references
                .insert(ContentReference {
                    source_artifact_id: artifact.id,
                    target_content_hash: blob_hash,
                    kind: "metadata_blob".to_string(),
                    metadata: serde_json::Value::Object(serde_json::Map::new()),
                    repository_id,
                    recorded_at: now_for_refcount,
                })
                .await
            {
                tracing::warn!(
                    artifact_id = %artifact.id,
                    kind = "metadata_blob",
                    error = %e,
                    stage = "content_references_insert",
                    "content_references insert failed; refcount eventual — operator reconcile is future work"
                );
            }
        }

        // PEP 658 wheel-metadata extraction hook.
        //
        // After `ArtifactIngested` lands and the refcount rows are
        // written, re-read the just-stored content from CAS, hand it to
        // `FormatHandler::extract_wheel_metadata_bytes`,
        // and on a `Some(bytes)` return: stream the bytes into CAS via
        // `StoragePort::put` and link them back to the parent wheel via
        // a `kind = "wheel_metadata"` row on the `content_references`
        // projection.
        //
        // The re-read from CAS is unavoidable: the upstream
        // `storage.put` consumed the inbound stream, and the existing
        // `prefetch-dependencies` task handler establishes the same
        // precedent (read the just-ingested bytes back from CAS by
        // `artifact.sha256_checksum`).
        //
        // **Path-gated** — only `.whl`-suffixed paths invoke the trait
        // method. Sdists, non-PyPI artifacts, and any other path skip
        // the re-read entirely (the default `extract_wheel_metadata_bytes`
        // returns `Ok(None)` anyway, so the only thing avoided is the
        // CAS round-trip cost). This matches the PyPI handler's own
        // first-line `.whl` short-circuit and keeps non-wheel ingests
        // paying zero new I/O.
        //
        // **No new domain event.** The metadata blob is a *derived
        // projection* of the wheel content — re-derivable on demand
        // from `ArtifactIngested` + `content_references`; the event
        // stream deliberately stays lean.
        //
        // **Failure semantics:**
        // - `Ok(None)` (sdist / corrupt wheel / no METADATA member) →
        //   silent no-op; the wheel ingest itself succeeded and
        //   PEP 658 simply does not apply for this artifact.
        // - `Err(DomainError::Validation(_))` (oversized METADATA per
        //   the extractor's 1 MiB cap) → `warn!` + tick
        //   `hort_ingest_total{result="wheel_metadata_extract_failed"}`.
        //   Non-fatal — the wheel ingest stays successful.
        // - `Err(_)` (infrastructure-class) → propagate. This
        //   surfaces the failure to the caller even
        //   though `ArtifactIngested` is already durable; reads as
        //   "the wheel-metadata pipeline did not complete." Same
        //   shape for CAS `storage.put` failure and ContentReference
        //   `insert` failure on the wheel-metadata blob.
        if coords.path.ends_with(".whl") {
            // Re-read the just-ingested content. The 1 MiB cap on
            // METADATA is enforced *inside*
            // `extract_wheel_metadata_bytes` on the
            // ZIP entry's header — the raw wheel bytes here are
            // bounded only by the per-format ingest cap that
            // already applied to the primary `storage.put` above.
            let mut wheel_bytes: Vec<u8> = Vec::new();
            let read_result = match self.storage.get(&artifact.sha256_checksum).await {
                Ok(mut stream) => stream
                    .read_to_end(&mut wheel_bytes)
                    .await
                    .map(|_| ())
                    .map_err(|e| {
                        DomainError::Invariant(format!(
                            "wheel-metadata extract: CAS re-read stream failed: {e}"
                        ))
                    }),
                Err(e) => Err(e),
            };
            match read_result {
                Ok(()) => {
                    let extract = handler
                        .extract_wheel_metadata_bytes(&coords, PayloadAccess::Bytes(&wheel_bytes));
                    match extract {
                        Ok(Some(metadata_bytes)) => {
                            let metadata_len = metadata_bytes.len();
                            // CAS-write the METADATA bytes (idempotent on
                            // identical content per `StoragePort::put` contract).
                            let metadata_hash = match self
                                .storage
                                .put(Box::new(std::io::Cursor::new(metadata_bytes.to_vec())))
                                .await
                            {
                                Ok(put_result) => put_result.hash,
                                Err(e) => {
                                    return Err((
                                        InnerIngestError::Other(AppError::Storage(e.to_string())),
                                        Some(repo_key.clone()),
                                        None,
                                    ));
                                }
                            };
                            // Link to parent wheel — kind="wheel_metadata".
                            // Upsert on `(repo, source, kind)` per the
                            // existing port semantics.
                            if let Err(e) = self
                                .content_references
                                .insert(ContentReference {
                                    source_artifact_id: artifact.id,
                                    target_content_hash: metadata_hash.clone(),
                                    kind: "wheel_metadata".to_string(),
                                    metadata: serde_json::Value::Object(serde_json::Map::new()),
                                    repository_id,
                                    recorded_at: now_for_refcount,
                                })
                                .await
                            {
                                return Err((
                                    InnerIngestError::Other(AppError::Domain(e)),
                                    Some(repo_key.clone()),
                                    None,
                                ));
                            }
                            tracing::info!(
                                artifact_id = %artifact.id,
                                repository_id = %repository_id,
                                metadata_hash = %metadata_hash,
                                metadata_bytes = metadata_len,
                                "wheel_metadata extracted and persisted (PEP 658)"
                            );
                        }
                        Ok(None) => {
                            // Sdist / corrupt wheel / no METADATA member —
                            // silent no-op. Wheel ingest succeeded; PEP 658
                            // is simply not advertised for this artifact.
                        }
                        Err(DomainError::Validation(reason)) => {
                            tracing::warn!(
                                artifact_id = %artifact.id,
                                repository_id = %repository_id,
                                reason = %reason,
                                "wheel_metadata extract failed (validation); \
                                 PEP 658 advertisement unavailable for this wheel"
                            );
                            metrics::counter!(
                                "hort_ingest_total",
                                labels::FORMAT => format.clone(),
                                labels::REPOSITORY => self.repo_label(Some(&repo_key)),
                                labels::RESULT => IngestResult::WheelMetadataExtractFailed.as_str(),
                            )
                            .increment(1);
                        }
                        Err(e) => {
                            return Err((
                                InnerIngestError::Other(AppError::Domain(e)),
                                Some(repo_key.clone()),
                                None,
                            ));
                        }
                    }
                }
                Err(e) => {
                    // Infrastructure-class CAS read failure — propagate.
                    // The `ArtifactIngested` event is durable but the
                    // wheel-metadata extraction pipeline could not run.
                    return Err((
                        InnerIngestError::Other(AppError::Domain(e)),
                        Some(repo_key.clone()),
                        None,
                    ));
                }
            }
        }

        // Post-commit group-membership hook.
        //
        // Runs AFTER `ArtifactIngested` has landed. Crucially, the
        // `ArtifactLifecyclePort::commit_transition` above and the
        // `ArtifactGroupUseCase::add_member` call below are TWO
        // separate transactions. If the group commit fails here, the
        // artifact is already persisted-and-valid; it is just unlinked
        // from any group. We log `warn!` and return `Ok` from `ingest`
        // (the ingest itself succeeded). The group-reconcile sweep heals
        // orphaned-membership artifacts at rest by replaying
        // `ArtifactIngested` events and re-running `classify_group_member`.
        //
        // Do NOT try to merge the two transactions or compensate on
        // failure. Cross-aggregate atomicity is not worth the coupling cost.
        if let Some(membership) = handler.classify_group_member(&coords, &coords.path) {
            let group_result = self
                .group_use_case
                .add_member(
                    repository_id,
                    membership.group_coords.clone(),
                    membership.role.clone(),
                    artifact.id,
                    membership.is_primary,
                    Actor::Api(actor_for_group),
                    correlation_id,
                    Some(artifact_ingested_event_id),
                    Some(&repo_key),
                    &format,
                )
                .await;
            match group_result {
                Ok(()) => tracing::info!(
                    artifact_id = %artifact.id,
                    group_coords_name = %membership.group_coords.name,
                    role = %membership.role,
                    "group membership committed post-ingest"
                ),
                Err(e) => tracing::warn!(
                    artifact_id = %artifact.id,
                    error = %e,
                    "group membership commit failed; artifact ingested but unlinked"
                ),
            }
        }

        // Split-rate observability. Fires ONLY on a
        // successful `commit_transition` that actually carried payload
        // metadata. Placed here — not in the tail metric-emission block —
        // so a failed commit does not tick the counter, and a
        // `Value::Null` payload is filtered out upstream via
        // `had_payload_metadata`. `strategy_label` is a `&'static str`
        // from `values::STRATEGY_*`, enforced at the signature level.
        if had_payload_metadata {
            metrics::counter!(
                "hort_ingest_metadata_strategy_total",
                labels::FORMAT => format.clone(),
                labels::STRATEGY => strategy_label,
            )
            .increment(1);
        }

        tracing::info!(
            %artifact_id,
            %repository_id,
            hash = %artifact.sha256_checksum,
            name = %artifact.name,
            version = ?artifact.version,
            "ingested"
        );

        // 6. Optionally quarantine.
        //
        // Quarantine-by-default (ADR 0007). The matched
        // `ScanPolicy.quarantine_duration_secs` is the single source of
        // truth for the observation-window length; with NO matched
        // policy, [`DefaultPolicy::quarantine_duration_secs`] (24h)
        // fires. The artifact transitions `None → Quarantined` whenever
        // the resolved duration is `> 0`. `Some(0)` on an operator
        // policy is the explicit **permissive** opt-out and is honoured
        // verbatim — it does NOT fall back to the default.
        //
        // **Permissive mode** (operator `quarantine_duration_secs == 0`):
        // skip the quarantine step entirely. The artifact stays in
        // `None` — downloadable per `Artifact::is_downloadable` — and
        // the scan runs concurrently. Bad findings transition the
        // artifact straight to `Rejected` via the relaxed
        // `Artifact::reject_from_scan`. This is the only way to
        // honour `quarantineDuration: 0` literally without forcing a
        // race between the scan and the `release_expired` sweep.
        //
        // `matched_policy.map(...).unwrap_or_else(default)` is shaped
        // to ensure `Some(0)` on an operator policy stays at 0 — only
        // an *absent* policy falls through to the Default.
        let policy_source_is_default = matched_policy.is_none();
        let effective_duration_secs: i64 = matched_policy
            .as_ref()
            .map(|p| p.quarantine_duration_secs)
            .unwrap_or_else(DefaultPolicy::quarantine_duration_secs);

        if effective_duration_secs > 0 {
            // Resolve the quarantine-window anchor
            // (`quarantine_window_start`). Two cases:
            //
            // - **Opt-in fired** — the serving `RepositoryUpstreamMapping`
            //   has `trust_upstream_publish_time = true` AND the format
            //   adapter extracted a non-`None` `upstream_published_at`:
            //   anchor = `min(upstream_published_at, ingested_at)`. The
            //   `min` is the **future-skew clamp** — a claimed
            //   publish time *after* ingest is physically impossible, so
            //   a buggy/malicious upstream cannot extend its own
            //   quarantine into the future via the opt-in.
            // - **Default** — anchor = `ingested_at` (the ingest anchor).
            //   Covers: opt-in `false`, direct upload (always passes
            //   `false`), pull-through with no extractable publish
            //   hint, and a `None` payload value.
            //
            // Invariant: store the **anchor**, never a precomputed
            // deadline. The release sweep and the proxy-503 read
            // path compute the deadline live via
            // `effective_quarantine_deadline(anchor, duration)`, so a
            // later policy edit of `quarantineDuration` takes effect on
            // the existing artifact's window without a backfill
            // migration.
            let (anchor, anchor_clamp_fired): (DateTime<Utc>, bool) = if trust_upstream_publish_time
            {
                match upstream_published_at {
                    Some(upstream_ts) => {
                        let clamped = std::cmp::min(upstream_ts, now);
                        (clamped, upstream_ts > now)
                    }
                    // Opt-in is on, but the format couldn't extract a
                    // hint for this artifact — best-effort degrades
                    // to the ingest anchor.
                    None => (now, false),
                }
            } else {
                (now, false)
            };

            let publish_anchored = trust_upstream_publish_time && upstream_published_at.is_some();

            let quarantine_event = artifact.quarantine(anchor).map_err(|e| {
                (
                    InnerIngestError::Other(AppError::Domain(e)),
                    Some(repo_key.clone()),
                    None,
                )
            })?;

            let expected_version = read_expected_version(&*self.events, &stream_id, true)
                .await
                .map_err(|e| (InnerIngestError::Other(e), Some(repo_key.clone()), None))?;

            self.lifecycle
                .commit_transition(
                    &artifact,
                    AppendEvents {
                        stream_id,
                        expected_version,
                        events: vec![EventToAppend::new(DomainEvent::ArtifactQuarantined(
                            quarantine_event,
                        ))],
                        correlation_id,
                        causation_id: None,
                        actor: hort_domain::events::system_actor(),
                    },
                    None, // metadata was persisted on the preceding ingest transition
                )
                .await
                .map_err(|e| {
                    (
                        InnerIngestError::Other(AppError::Domain(e)),
                        Some(repo_key.clone()),
                        None,
                    )
                })?;

            // Observability for the default-policy fire.
            // Operator-policy-driven quarantines retain their existing
            // log line; the default fire gets a distinct `policy_source`
            // tag so operators can dashboard "how many repos still have
            // no ScanPolicy and are leaning on the default 24h window".
            //
            // The field name is
            // `policy_source`, NOT `source` — the `source`
            // axis is reserved for the *anchor-source* distinction
            // (`ingest` vs `upstream` under `trust_upstream_publish_time`).
            // `policy_source` is the orthogonal policy-origin axis
            // (`default_policy` vs operator-defined).
            if policy_source_is_default {
                tracing::info!(
                    %artifact_id,
                    %repository_id,
                    window_duration_secs = effective_duration_secs,
                    anchor = %anchor,
                    policy_source = "default_policy",
                    "quarantine triggered on ingest (default policy)"
                );
            } else {
                tracing::info!(
                    %artifact_id,
                    anchor = %anchor,
                    window_duration_secs = effective_duration_secs,
                    "quarantine triggered on ingest"
                );
            }

            // Distinct log line on the publish-anchored
            // fire (`trust_upstream_publish_time = true` + a non-`None`
            // `upstream_published_at` consumed). Emitted at `debug!` —
            // the value is rare per-artifact but can be high-volume on
            // busy upstreams; the policy-source log lines above already
            // carry the (resolved) `anchor` for the default observability
            // dashboard. `anchor_source = "upstream_published"` reserves
            // the anchor-source axis; the unchanged ingest-anchored
            // path emits no such log (anchor_source = "ingest"
            // implicitly).
            if publish_anchored {
                tracing::debug!(
                    %artifact_id,
                    %repository_id,
                    upstream_published_at = ?upstream_published_at,
                    ingested_at = %now,
                    chosen_anchor = %anchor,
                    clamp_fired = anchor_clamp_fired,
                    anchor_source = "upstream_published",
                    "quarantine anchor resolved via upstream publish time \
                     (trust_upstream_publish_time opt-in)"
                );
            }

            metrics::counter!(
                "hort_quarantine_triggered_total",
                labels::FORMAT => format,
                labels::REPOSITORY => self.repo_label(Some(&repo_key)),
            )
            .increment(1);
        }

        // Transitive prefetch cascade
        // enqueue hook. Fires per-ingest when the repository's
        // `prefetch_policy.triggers` contains `TransitiveDeps`; enqueues
        // a root `prefetch-dependencies` job that the worker dispatches
        // to `PrefetchDependenciesHandler` to walk the just-
        // ingested artifact's manifest, resolve declared runtime deps,
        // and seed the cascade.
        //
        // The trigger absence (the default `PrefetchPolicy`) is the
        // absence of the enqueue — operators opt in per-repo. Best-
        // effort: enqueue failure logs `warn!` and the ingest's
        // success path is unaffected (the cascade is eventually-
        // consistent — the next pull re-triggers).
        //
        // Mirrors the shape of the `content_references_insert` and
        // group-membership post-hooks above (warn-and-continue, runs
        // strictly after `commit_transition` so a failed commit does
        // not leak a cascade enqueue).
        //
        // `suppress_cascade_seed` is set by a CASCADE-INTERNAL
        // `prefetch` leaf-ingest (trigger_source "prefetch"): the artifact
        // it just ingested is already covered by its parent walk's
        // depth-carrying child `prefetch-dependencies` row, so firing this
        // depth-0 seed hook would double-walk it AND reset the cascade
        // depth to 0 (defeating the transitive_depth / max_descendants
        // caps). Seeds (client pulls, self-service ROOT leaves) leave it
        // `false` so the hook fires as before.
        if !suppress_cascade_seed
            && repo
                .prefetch_policy
                .triggers
                .contains(&hort_domain::entities::repository::PrefetchTrigger::TransitiveDeps)
        {
            let params = serde_json::json!({
                "artifact_id": artifact.id,
                "current_depth": 0u32,
            });
            // `priority = 0` — cascade rows drain after
            // operator/cron work. `trigger_source = "ingest"` — the
            // cascade is event-driven by the ingest; the CHECK in
            // migration 009 lists `ingest` as a valid trigger source.
            match self
                .jobs
                .enqueue_task(
                    "prefetch-dependencies",
                    &params,
                    None, // actor_id: system-driven post-ingest hook
                    0i16,
                    "ingest",
                    None, // non-destructive task — no DB-side idempotency key (ADR 0028)
                )
                .await
            {
                Ok(outcome) => tracing::debug!(
                    artifact_id = %artifact.id,
                    repository_id = %repository_id,
                    ?outcome,
                    "prefetch cascade: enqueued prefetch-dependencies root job",
                ),
                Err(e) => tracing::warn!(
                    artifact_id = %artifact.id,
                    repository_id = %repository_id,
                    error = %e,
                    "prefetch cascade: prefetch-dependencies enqueue failed; \
                     cascade skipped (best-effort — next pull re-triggers)",
                ),
            }
        }

        Ok((artifact, false, repo_key, artifact_ingested_event_id))
    }

    /// Register a pre-existing CAS object into the target repository by
    /// its content hash — no re-streaming, no `declared_sha256`
    /// verification (the hash IS the source of truth).
    ///
    /// Primary consumer is the OCI cross-repo blob mount
    /// (`POST /v2/<name>/blobs/uploads/?mount=<digest>&from=<src>`): the
    /// source repository has already ingested and stored the bytes; the
    /// target repository needs a fresh metadata row + event pointing at
    /// the same `ContentHash`. Future consumers include Phase 4
    /// proxy-fetch promotion and cross-mesh replication.
    ///
    /// ## Authorisation branches
    ///
    /// - `source_repo = Some(src)` —
    ///   `artifacts.find_by_repo_and_checksum(src, &hash)` must return
    ///   an `Artifact`. The repo-scoped port method guarantees the
    ///   returned row belongs to `src`; no caller-side post-filter is
    ///   required (a bare `find_by_checksum` would
    ///   return an arbitrary row when the same SHA-256 lived in
    ///   multiple repos).
    /// - `source_repo = None` — only `storage.exists(&hash)` is checked.
    ///   Caller owns authorisation (Phase 4 proxy fetches, replication,
    ///   promotion — contexts where the authz decision has already been
    ///   made upstream).
    ///
    /// ## Idempotence
    ///
    /// Calling this method twice with the same `(repository_id,
    /// coords.path, existing_hash)` is safe: the second call returns
    /// the previously-committed artifact (same `artifact.id`, freshly-
    /// minted `ingested_event_id`) and emits `hort_ingest_total{result=
    /// "duplicate"}`. Different hash at the same path returns
    /// `DomainError::Conflict`. Mirrors [`Self::ingest`]'s dedup
    /// semantics so retries on a lossy network do not corrupt the
    /// aggregate.
    ///
    /// **Dedup-path `ingested_event_id` caveat.** On the same-path-
    /// same-hash dedup return, the `ingested_event_id` is a freshly-
    /// minted `Uuid` that points at NO persisted event. Callers
    /// threading it as `causation_id` on a downstream emission produce
    /// a standalone event chain — acceptable
    /// (same-member-idempotence on `add_member` makes the retry a
    /// no-op regardless).
    ///
    /// ## Size resolution
    ///
    /// `size_bytes` on the new artifact row is sourced authoritatively:
    /// the `Some(src)` branch uses the repo-scoped artifact's
    /// `size_bytes`; the `None` branch calls `storage.size_of(&hash)`
    /// on the CAS itself. There is no "fall through to 0 when no
    /// artifact row references the hash" path.
    ///
    /// ## Metrics
    ///
    /// `hort_ingest_total` + `hort_ingest_duration_seconds` are emitted on
    /// EVERY exit (success, domain rejection, infrastructure failure).
    /// Success uses `result="registered_by_hash"`; the dedup path uses
    /// `result="duplicate"`; errors are classified via
    /// `classify_ingest_error` so the taxonomy matches
    /// [`Self::ingest`].
    ///
    /// `hort_ingest_size_bytes` is emitted on success with the resolved
    /// size so the histogram covers both streaming ingests and
    /// hash-only registrations.
    ///
    /// ## Non-invocations
    ///
    /// This method does NOT invoke `handler.classify_group_member` —
    /// group attachment for cross-mounted blobs is the caller's
    /// responsibility (OCI composes groups on manifest PUT, not on blob
    /// mount).
    ///
    /// `declared_sha256` on `req` is also ignored; the method's
    /// `existing_hash` parameter is authoritative.
    #[tracing::instrument(skip(self, handler))]
    pub async fn register_by_hash(
        &self,
        req: IngestRequest,
        existing_hash: ContentHash,
        source_repo: Option<Uuid>,
        handler: &dyn FormatHandler,
    ) -> AppResult<IngestOutcome> {
        let format = req.coords.format.to_string();
        let started = Instant::now();

        let result = self
            .register_by_hash_inner(req, existing_hash, source_repo, handler)
            .await;

        // Unified metric-emission exit. Mirrors `ingest`'s contract:
        // EVERY exit (success, dedup, domain reject, infrastructure
        // failure) fires `hort_ingest_total` +
        // `hort_ingest_duration_seconds`. Labels: success →
        // `registered_by_hash`; same-path-same-hash dedup →
        // `duplicate`; metadata cap rejection → `metadata_too_large`
        // (carried via `RegisterError::MetadataTooLarge`); everything
        // else goes through `classify_ingest_error` with the same
        // taxonomy `ingest` uses.
        let elapsed = started.elapsed().as_secs_f64();
        let (result_label, repository_label, size_emitted): (&'static str, String, Option<i64>) =
            match &result {
                Ok(RegisterOutcome::Fresh {
                    artifact, repo_key, ..
                }) => (
                    IngestResult::RegisteredByHash.as_str(),
                    self.repo_label(Some(repo_key)),
                    Some(artifact.size_bytes),
                ),
                Ok(RegisterOutcome::Duplicate { artifact, repo_key }) => (
                    IngestResult::Duplicate.as_str(),
                    self.repo_label(Some(repo_key)),
                    Some(artifact.size_bytes),
                ),
                Err(RegisterError::MetadataTooLarge { repo_key, .. }) => (
                    IngestResult::MetadataTooLarge.as_str(),
                    self.repo_label(repo_key.as_deref()),
                    None,
                ),
                Err(RegisterError::Other { err, repo_key }) => {
                    let ingest_result = classify_ingest_error(err);
                    (
                        ingest_result.as_str(),
                        self.repo_label(repo_key.as_deref()),
                        None,
                    )
                }
            };

        metrics::counter!(
            "hort_ingest_total",
            labels::FORMAT => format.clone(),
            labels::REPOSITORY => repository_label,
            labels::RESULT => result_label,
        )
        .increment(1);
        metrics::histogram!(
            "hort_ingest_duration_seconds",
            labels::FORMAT => format.clone(),
        )
        .record(elapsed);
        if let Some(size) = size_emitted {
            metrics::histogram!(
                "hort_ingest_size_bytes",
                labels::FORMAT => format,
            )
            .record(size as f64);
        }

        match result {
            Ok(RegisterOutcome::Fresh {
                artifact,
                ingested_event_id,
                ..
            }) => Ok(IngestOutcome {
                artifact,
                ingested_event_id,
            }),
            Ok(RegisterOutcome::Duplicate { artifact, .. }) => Ok(IngestOutcome {
                artifact,
                // Dedup path: caller-visible id is a fresh uuid that
                // points at no persisted event. See method docstring.
                ingested_event_id: Uuid::new_v4(),
            }),
            Err(RegisterError::MetadataTooLarge { err, .. }) => Err(err),
            Err(RegisterError::Other { err, .. }) => Err(err),
        }
    }

    /// Idempotently register a per-repo artifact row for content that
    /// is **already present and verified in CAS** — the cross-repo
    /// post-coalesce follower primitive.
    ///
    /// ## Why this exists
    ///
    /// `DedupKey::blob_by_hash` is cross-repo by design: two callers
    /// pulling the same upstream artifact into *different*
    /// repositories share one coalesce window so the upstream is hit
    /// once and the CAS write happens once (the bytes are
    /// content-addressed and checksum-verified inside the leader's
    /// `ingest_verified` — sharing the write is sound). The **leader**
    /// ingests into its own repo and gets its artifact row. A
    /// **follower** that joined that window from a *different* repo
    /// receives only the post-verification `content_hash`; its
    /// post-coalesce repo-scoped lookup
    /// (`ArtifactUseCase::find_in_repo_by_hash(repo, hash)`) returns
    /// `None` because the leader only minted *its* repo's row. Previously
    /// that `None` was mapped to a hard `Internal` and the
    /// follower's pull failed closed. This method is what the
    /// follower calls instead: it idempotently mints the follower's
    /// OWN per-repo row pointing at the already-CAS-present hash.
    ///
    /// ## Reuses the leader's exact primitive — no new event
    ///
    /// This is a thin entrypoint over [`Self::register_by_hash`] with
    /// `source_repo = None`. That is the **same** registration path
    /// the leader's non-concurrent cross-repo dedup already uses (the
    /// established OCI cross-repo blob-mount / Phase-4 proxy-promotion
    /// path): it emits exactly one `ArtifactIngested`
    /// (`IngestSource::Direct`) — the same domain event, no new event
    /// kind, no silent `UPDATE`; the event-sourcing invariant holds
    /// (state change ⇒ domain event). The `None` branch:
    ///
    /// * verifies the bytes are CAS-present via `storage.exists` —
    ///   it does **not** re-fetch from upstream;
    /// * sources `size_bytes` authoritatively via `storage.size_of` —
    ///   it does **not** re-`storage.put`;
    /// * is idempotent: a second/Nth follower (or a retried follower
    ///   after a lossy network) at the same `(repo, path, hash)` hits
    ///   `register_by_hash`'s same-path-same-hash dedup and the
    ///   already-registered row is returned with no second event.
    ///
    /// Genuine failures (CAS-absent content, unknown target repo,
    /// metadata-cap violation, lifecycle/infra errors) propagate from
    /// the delegate unchanged so the calling site's existing error
    /// mapping for real failures is preserved.
    ///
    /// `#[tracing::instrument]` deliberately omits `err` — a follower
    /// fallback that fails is reported by the caller's existing
    /// mapping, not double-logged here. `handler` (not `Debug`) and
    /// `req` (carries opaque caller JSON `payload_metadata` — same
    /// never-logged contract as [`IngestRequest::payload_metadata`])
    /// are skipped, mirroring [`Self::register_by_hash`]'s
    /// `skip(self, handler)`.
    ///
    /// Tracked follow-up (NOT a data-integrity or security risk — do not
    /// block on it): two concurrent same-repo-B
    /// followers cannot create duplicate rows — the DB constraint
    /// `artifacts_repository_id_path_key UNIQUE (repository_id, path)`
    /// (`migrations/003_artifacts_cas.sql`) structurally
    /// prevents it, and the audit-mandated cross-repo case is tested.
    /// The only residual is error-contract polish: the loser of that
    /// same-repo race currently maps the `unique_violation` to a raw
    /// `Internal` (500) rather than a clean `Conflict` / idempotent
    /// re-resolve. Recorded for a future error-mapping
    /// pass; the security/correctness property
    /// holds today regardless.
    #[tracing::instrument(skip(self, req, handler))]
    pub async fn register_existing_cas_blob(
        &self,
        req: RegisterExistingCasBlobRequest,
        handler: &dyn FormatHandler,
    ) -> AppResult<IngestOutcome> {
        let RegisterExistingCasBlobRequest {
            repository_id,
            coords,
            content_type,
            actor,
            payload_metadata,
            content_hash,
            seed_import_quarantine_anchor,
        } = req;

        // Audit (not error): a follower registering its own per-repo
        // row for a coalesced cross-repo hash is a security-relevant
        // state change. Logged at info; the dedup re-entry below stays
        // silent (it commits nothing).
        tracing::info!(
            %repository_id,
            hash = %content_hash,
            "register_existing_cas_blob: follower registering own per-repo row for coalesced cross-repo CAS hash"
        );

        // `source_repo = None` — the caller (the post-coalesce site)
        // has already had its repo authorised by the inbound request
        // pipeline, and there is no guaranteed source artifact row in
        // any repo (the leader may have ingested into a different
        // repo). The `None` branch's `storage.exists` check is the
        // authoritative CAS-presence guard. `declared_sha256` is
        // ignored by `register_by_hash` (the `content_hash` argument
        // is authoritative), so it is left `None` here.
        // The seed-import cutover path threads its
        // backdated `quarantine_window_start`
        // anchor into `register_by_hash` via
        // `IngestRequest.quarantine_anchor_override`. The field is
        // stamped as the artifact's `quarantine_window_start` anchor
        // by `Artifact::quarantine` — backdating it makes the
        // *computed* deadline (`anchor + effective_duration`)
        // already-elapsed, so the next sweep / scan-complete fast path
        // releases as soon as a clean scan lands. `None` for every
        // existing caller (OCI cross-mount, post-coalesce follower) —
        // backwards-compatible.
        //
        // Naming: `quarantine_anchor_override` (formerly
        // `quarantine_until`) — the name states the field's actual
        // semantics: the seed-import quarantine-window anchor
        // (commit 3160f6e9).
        self.register_by_hash(
            IngestRequest {
                repository_id,
                coords,
                content_type,
                quarantine_anchor_override: seed_import_quarantine_anchor,
                actor,
                legacy_sha1: None,
                legacy_md5: None,
                declared_sha256: None,
                payload_metadata,
            },
            content_hash,
            None,
            handler,
        )
        .await
    }

    /// Inner body of [`Self::register_by_hash`]. Returns one of four
    /// outcomes — fresh commit, same-path-same-hash dedup, a metadata
    /// cap rejection (distinguished so the outer can tag the metric
    /// with `metadata_too_large`), or any other classified error — so
    /// the outer method can emit metrics on every exit in a single
    /// site.
    async fn register_by_hash_inner(
        &self,
        req: IngestRequest,
        existing_hash: ContentHash,
        source_repo: Option<Uuid>,
        handler: &dyn FormatHandler,
    ) -> Result<RegisterOutcome, RegisterError> {
        let IngestRequest {
            repository_id,
            coords,
            content_type,
            quarantine_anchor_override,
            actor,
            legacy_sha1,
            legacy_md5,
            declared_sha256: _,
            payload_metadata,
        } = req;

        // Metadata size cap — mirror of `ingest`'s pre-dispatch check.
        // Same cap semantics, same error shape; metric classification
        // is retained as `metadata_too_large` via
        // `RegisterError::MetadataTooLarge`. The repo key is best-
        // effort-looked-up so the `repository` label lands correctly
        // when the repo exists.
        if let Err(err) = self.enforce_metadata_cap(handler, &payload_metadata) {
            let repo_key = self
                .repositories
                .find_by_id(repository_id)
                .await
                .ok()
                .map(|r| r.key);
            return Err(RegisterError::MetadataTooLarge { err, repo_key });
        }

        // Resolve target repo — needed for the `repository` metric label
        // and the format-match check below.
        let repo = match self.repositories.find_by_id(repository_id).await {
            Ok(r) => r,
            Err(e) => {
                return Err(RegisterError::Other {
                    err: AppError::Domain(e),
                    repo_key: None,
                });
            }
        };
        let repo_key = repo.key.clone();

        // Format mismatch — same invariant as `Self::ingest`. Reject
        // before any authorisation or event work; a mis-routed mount is
        // a caller bug, not a security-sensitive state transition.
        if coords.format != repo.format {
            return Err(RegisterError::Other {
                err: AppError::Domain(DomainError::Validation(format!(
                    "format mismatch: repository {} is {}, coords declare {}",
                    repo.key, repo.format, coords.format
                ))),
                repo_key: Some(repo_key),
            });
        }

        // Idempotence guard — same-path dedup. If an artifact already
        // sits at `(repository_id, coords.path)`, we must not emit a
        // second `ArtifactIngested` for the same logical location.
        // Mirror `ingest`'s `find_by_path` guard exactly.
        let existing_at_path = self
            .artifacts
            .find_by_path(repository_id, &coords.path)
            .await
            .map_err(|e| RegisterError::Other {
                err: AppError::Domain(e),
                repo_key: Some(repo_key.clone()),
            })?;
        if let Some(existing) = existing_at_path {
            if existing.sha256_checksum == existing_hash {
                tracing::debug!(
                    artifact_id = %existing.id,
                    "register_by_hash deduplicated via same-path-same-hash"
                );
                return Ok(RegisterOutcome::Duplicate {
                    artifact: existing,
                    repo_key,
                });
            }
            return Err(RegisterError::Other {
                err: AppError::Domain(DomainError::Conflict(format!(
                    "path {} already exists with different content (existing={}, new={})",
                    coords.path, existing.sha256_checksum, existing_hash
                ))),
                repo_key: Some(repo_key),
            });
        }

        // Authorisation + authoritative size resolution.
        //
        // `Some(src)` — repo-scoped lookup closes the multi-repo
        // ambiguity: the port method's `WHERE repository_id
        // = $1 AND checksum_sha256 = $2` guarantees the row belongs to
        // `src` (no caller-side post-filter needed). `None` — stat the
        // CAS itself for an authoritative `size_bytes`; there is no
        // `.unwrap_or(0)` fallback on "no artifact row references this
        // hash".
        let size_bytes: i64 = match source_repo {
            Some(src) => match self
                .artifacts
                .find_by_repo_and_checksum(src, &existing_hash)
                .await
            {
                Ok(Some(a)) => a.size_bytes,
                Ok(None) => {
                    return Err(RegisterError::Other {
                        err: AppError::Domain(DomainError::NotFound {
                            entity: "Artifact",
                            id: existing_hash.to_string(),
                        }),
                        repo_key: Some(repo_key),
                    });
                }
                Err(e) => {
                    return Err(RegisterError::Other {
                        err: AppError::Domain(e),
                        repo_key: Some(repo_key),
                    });
                }
            },
            None => {
                let exists = self.storage.exists(&existing_hash).await.map_err(|e| {
                    RegisterError::Other {
                        err: AppError::Domain(e),
                        repo_key: Some(repo_key.clone()),
                    }
                })?;
                if !exists {
                    return Err(RegisterError::Other {
                        err: AppError::Domain(DomainError::NotFound {
                            entity: "ContentHash",
                            id: existing_hash.to_string(),
                        }),
                        repo_key: Some(repo_key),
                    });
                }
                match self.storage.size_of(&existing_hash).await {
                    Ok(s) => s as i64,
                    // `exists == true` but `size_of == NotFound` is
                    // infrastructure inconsistency (stat raced with a
                    // GC, or the adapter disagrees with itself).
                    // Surface as Invariant — loud, unexpected, not a
                    // user-facing domain error.
                    Err(DomainError::NotFound { .. }) => {
                        return Err(RegisterError::Other {
                            err: AppError::Domain(DomainError::Invariant(format!(
                                "storage.exists(&{existing_hash}) was true but size_of returned NotFound"
                            ))),
                            repo_key: Some(repo_key),
                        });
                    }
                    Err(e) => {
                        return Err(RegisterError::Other {
                            err: AppError::Domain(e),
                            repo_key: Some(repo_key),
                        });
                    }
                }
            }
        };

        // Build the new artifact row + event. Fresh ids — this is a
        // new registration in a new repository, not a duplicate of the
        // source row.
        let artifact_id = Uuid::new_v4();
        let now = Utc::now();
        // Bound `mut` because the seed-import path
        // (`quarantine_anchor_override = Some(backdated_anchor)`)
        // transitions the artifact to `Quarantined` after the
        // `ArtifactIngested` commit lands. Every existing non-seed
        // caller passes `quarantine_anchor_override = None` (see
        // `register_existing_cas_blob` for the post-coalesce
        // follower's `None`, and `hort-http-oci/src/uploads.rs` for the
        // cross-mount path's `None`) — the mut binding is a no-op for
        // them.
        let mut artifact = Artifact {
            id: artifact_id,
            repository_id,
            name: coords.name.clone(),
            name_as_published: coords.name_as_published.clone(),
            version: coords.version.clone(),
            path: coords.path.clone(),
            size_bytes,
            sha256_checksum: existing_hash.clone(),
            sha1_checksum: legacy_sha1,
            md5_checksum: legacy_md5,
            content_type,
            quarantine_status: QuarantineStatus::None,
            rejection_reason: None,
            quarantine_window_start: None,
            quarantine_deadline: None,
            upstream_published_at: None,
            uploaded_by: actor_to_uploaded_by(&actor),
            is_deleted: false,
            created_at: now,
            updated_at: now,
        };

        let stream_id = StreamId::artifact(artifact_id);
        let correlation_id = Uuid::new_v4();
        let ingested_event_id = Uuid::new_v4();
        let ingested_event = ArtifactIngested {
            artifact_id,
            repository_id,
            name: artifact.name.clone(),
            version: artifact.version.clone(),
            sha256: existing_hash,
            size_bytes: artifact.size_bytes,
            source: IngestSource::Direct,
            metadata: payload_metadata.clone(),
            // `register_by_hash` never splits — the bytes-payload is
            // already in CAS owned by the source; the per-artifact
            // payload_metadata stays inline.
            metadata_blob: None,
            // `register_by_hash` mints a per-repo row over
            // a CAS blob that already exists; there is no upstream
            // fetch on this path, so no Last-Modified hint to thread.
            // `None` matches the artifact row above; event + projection
            // stay bit-identical for projection-rebuild semantics.
            upstream_published_at: None,
        };

        let artifact_metadata = ArtifactMetadata {
            artifact_id,
            format: repo.format,
            metadata: payload_metadata,
            metadata_blob: None,
            properties: serde_json::Value::Object(Default::default()),
        };

        let expected_version = read_expected_version(&*self.events, &stream_id, true)
            .await
            .map_err(|e| RegisterError::Other {
                err: e,
                repo_key: Some(repo_key.clone()),
            })?;

        self.lifecycle
            .commit_transition(
                &artifact,
                AppendEvents {
                    stream_id: stream_id.clone(),
                    expected_version,
                    events: vec![EventToAppend {
                        event_id: ingested_event_id,
                        event: DomainEvent::ArtifactIngested(ingested_event),
                    }],
                    correlation_id,
                    causation_id: None,
                    actor: Actor::Api(actor.clone()),
                },
                Some(artifact_metadata),
            )
            .await
            .map_err(|e| RegisterError::Other {
                err: AppError::Domain(e),
                repo_key: Some(repo_key.clone()),
            })?;

        // Seed-import cutover.
        //
        // When `quarantine_anchor_override = Some(anchor)`, the caller
        // (today exclusively `SeedImportUseCase` via
        // `RegisterExistingCasBlobRequest.seed_import_quarantine_anchor`)
        // has backdated the anchor so the *computed* deadline
        // (`anchor + effective_duration`) is already
        // at or before `now()`. We:
        //
        // 1. Transition the in-memory artifact to `Quarantined` with
        //    the backdated anchor (`Artifact::quarantine` sets
        //    `quarantine_window_start = anchor`).
        // 2. Append `ArtifactQuarantined` to the same stream as a
        //    follow-on commit (mirrors `ingest_inner`'s strict-mode
        //    quarantine step at the bottom of step 6).
        //
        // **Not** `ScanWaived`, **not** permissive. A dirty scan still
        // transitions the artifact to `Rejected` via
        // `Artifact::reject_from_scan`; the release authority gate
        // is unchanged. This path stamps only the *time* anchor.
        //
        // Every existing non-seed caller passes
        // `quarantine_anchor_override = None`; the block is a no-op
        // for them.
        if let Some(anchor) = quarantine_anchor_override {
            let quarantine_event =
                artifact
                    .quarantine(anchor)
                    .map_err(|e| RegisterError::Other {
                        err: AppError::Domain(e),
                        repo_key: Some(repo_key.clone()),
                    })?;

            let expected_version = read_expected_version(&*self.events, &stream_id, true)
                .await
                .map_err(|e| RegisterError::Other {
                    err: e,
                    repo_key: Some(repo_key.clone()),
                })?;

            self.lifecycle
                .commit_transition(
                    &artifact,
                    AppendEvents {
                        stream_id,
                        expected_version,
                        events: vec![EventToAppend::new(DomainEvent::ArtifactQuarantined(
                            quarantine_event,
                        ))],
                        correlation_id,
                        causation_id: None,
                        // System actor — the seed-import path is operator-
                        // initiated but the per-artifact follow-on commit
                        // is mechanical bookkeeping (mirrors
                        // `ingest_inner`'s strict-mode quarantine step).
                        actor: hort_domain::events::system_actor(),
                    },
                    None, // metadata was persisted on the preceding ingest transition
                )
                .await
                .map_err(|e| RegisterError::Other {
                    err: AppError::Domain(e),
                    repo_key: Some(repo_key.clone()),
                })?;

            tracing::info!(
                %artifact_id,
                %anchor,
                "seed-import quarantine stamped (backdated anchor)"
            );
        }

        // Refcount projection write. The OCI cross-repo
        // blob mount path takes this branch; the new repository's
        // artifact row needs its own `primary_content` refcount
        // (separate from the source repository's row). No metadata-
        // blob row — `register_by_hash` never splits (the bytes are
        // already in CAS owned by the source). Failure is recoverable
        // — see `ingest_inner` for the same-shape rationale.
        if let Err(e) = self
            .content_references
            .insert(ContentReference {
                source_artifact_id: artifact.id,
                target_content_hash: artifact.sha256_checksum.clone(),
                kind: "primary_content".to_string(),
                metadata: serde_json::Value::Object(serde_json::Map::new()),
                repository_id,
                recorded_at: Utc::now(),
            })
            .await
        {
            tracing::warn!(
                artifact_id = %artifact.id,
                kind = "primary_content",
                error = %e,
                stage = "content_references_insert",
                "content_references insert failed; refcount eventual — operator reconcile is future work"
            );
        }

        tracing::info!(
            %artifact_id,
            %repository_id,
            hash = %artifact.sha256_checksum,
            ?source_repo,
            "registered_by_hash"
        );

        // Transitive prefetch cascade
        // enqueue hook (mirror of `ingest_inner`'s hook). Same
        // contract: gated on `prefetch_policy.triggers.contains(
        // TransitiveDeps)`, best-effort (warn-and-continue), fires
        // after the registration commit lands. Covers the OCI
        // cross-repo blob-mount and any future hash-only registration
        // paths so the cascade is event-driven uniformly across both
        // ingest entry points.
        if repo
            .prefetch_policy
            .triggers
            .contains(&hort_domain::entities::repository::PrefetchTrigger::TransitiveDeps)
        {
            let params = serde_json::json!({
                "artifact_id": artifact.id,
                "current_depth": 0u32,
            });
            match self
                .jobs
                .enqueue_task(
                    "prefetch-dependencies",
                    &params,
                    None,
                    0i16,
                    "ingest",
                    None, // non-destructive task — no DB-side idempotency key (ADR 0028)
                )
                .await
            {
                Ok(outcome) => tracing::debug!(
                    artifact_id = %artifact.id,
                    %repository_id,
                    ?outcome,
                    "prefetch cascade: enqueued prefetch-dependencies root job (register_by_hash path)",
                ),
                Err(e) => tracing::warn!(
                    artifact_id = %artifact.id,
                    %repository_id,
                    error = %e,
                    "prefetch cascade: prefetch-dependencies enqueue failed (register_by_hash); \
                     cascade skipped (best-effort — next pull re-triggers)",
                ),
            }
        }

        Ok(RegisterOutcome::Fresh {
            artifact,
            ingested_event_id,
            repo_key,
        })
    }
}

/// Internal return shape for [`IngestUseCase::register_by_hash_inner`].
/// Lets the outer wrapper distinguish fresh commits from same-path-
/// same-hash dedup hits for metric classification — the dedup path
/// emits `hort_ingest_total{result="duplicate"}`, the fresh path emits
/// `result="registered_by_hash"`.
enum RegisterOutcome {
    Fresh {
        artifact: Artifact,
        ingested_event_id: Uuid,
        repo_key: String,
    },
    Duplicate {
        artifact: Artifact,
        repo_key: String,
    },
}

/// Internal error shape for [`IngestUseCase::register_by_hash_inner`].
///
/// `MetadataTooLarge` is broken out as its own variant so the outer
/// wrapper can tag `hort_ingest_total{result="metadata_too_large"}`
/// directly — routing it through `classify_ingest_error` would
/// reclassify `DomainError::Validation` as `ValidationError` and
/// silently erase the cap-miss label (same reason `ingest`'s outer
/// short-circuits its own cap emission — see the comment above
/// `ingest`'s cap check).
///
/// `Other` carries a classified `AppError`; the outer runs it through
/// `classify_ingest_error` and emits the result label with the
/// standard ingest-error taxonomy.
enum RegisterError {
    MetadataTooLarge {
        err: AppError,
        repo_key: Option<String>,
    },
    Other {
        err: AppError,
        repo_key: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::Utc;
    use metrics::{Key, SharedString};
    use metrics_util::debugging::DebugValue;
    use metrics_util::{CompositeKey, MetricKind};

    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::repository::{Repository, RepositoryFormat};
    use hort_domain::events::DomainEvent;
    use hort_domain::ports::format_handler::GroupMembership;

    use super::*;
    use crate::metrics::capture_metrics;
    use crate::use_cases::test_support::*;

    // -- Metric assertion helpers -------------------------------------------

    type MetricEntry = (
        CompositeKey,
        Option<metrics::Unit>,
        Option<SharedString>,
        DebugValue,
    );

    fn find_metric<'a>(
        entries: &'a [MetricEntry],
        kind: MetricKind,
        metric_name: &str,
        expected_labels: &[(&str, &str)],
    ) -> Option<&'a MetricEntry> {
        entries.iter().find(|(ck, _, _, _)| {
            ck.kind() == kind
                && ck.key().name() == metric_name
                && expected_labels.iter().all(|(k, v)| {
                    ck.key()
                        .labels()
                        .any(|label| label.key() == *k && label.value() == *v)
                })
        })
    }

    /// Assert that the snapshot contains a counter with the given name, labels,
    /// and value. Labels are matched as a superset (all expected labels must
    /// match; extra labels permitted).
    fn assert_counter(
        entries: &[MetricEntry],
        metric_name: &str,
        expected_labels: &[(&str, &str)],
        expected_value: u64,
    ) {
        match find_metric(entries, MetricKind::Counter, metric_name, expected_labels) {
            Some((_, _, _, DebugValue::Counter(got))) => assert_eq!(
                *got, expected_value,
                "counter {metric_name} with {expected_labels:?} had value {got}, expected {expected_value}"
            ),
            Some(_) => panic!("metric {metric_name} is not a counter"),
            None => {
                let names: Vec<&str> = entries.iter().map(|(ck, _, _, _)| ck.key().name()).collect();
                panic!(
                    "expected counter {metric_name} with {expected_labels:?} not found; seen: {names:?}"
                );
            }
        }
    }

    /// Assert that the snapshot contains a histogram with the given name and
    /// labels and that at least one sample was recorded.
    fn assert_histogram_has_sample(
        entries: &[MetricEntry],
        metric_name: &str,
        expected_labels: &[(&str, &str)],
    ) {
        match find_metric(entries, MetricKind::Histogram, metric_name, expected_labels) {
            Some((_, _, _, DebugValue::Histogram(samples))) => assert!(
                !samples.is_empty(),
                "histogram {metric_name} with {expected_labels:?} has no samples"
            ),
            Some(_) => panic!("metric {metric_name} is not a histogram"),
            None => panic!("expected histogram {metric_name} with {expected_labels:?} not found"),
        }
    }

    /// Assert that NO metric in the snapshot has the given name.
    fn assert_metric_absent(entries: &[MetricEntry], metric_name: &str) {
        let found = entries
            .iter()
            .any(|(ck, _, _, _)| ck.key().name() == metric_name);
        assert!(
            !found,
            "metric {metric_name} unexpectedly present in snapshot"
        );
    }

    // Ensure `Key` stays imported — it's implicitly used via `CompositeKey.key()`.
    #[allow(dead_code)]
    fn _suppress_unused_key(_k: Key) {}

    /// Build a permissive global `ScanPolicyProjection`
    /// (`quarantine_duration_secs = 0`) and seed it onto the supplied
    /// projections mock so tests that don't exercise
    /// quarantine-by-default keep a no-quarantine baseline:
    /// no matched policy → Default fires → +1 `ArtifactQuarantined`
    /// transition. Seeding a permissive operator policy honours
    /// `Some(0)` and keeps the no-quarantine ingest path the test
    /// baseline.
    ///
    /// Tests that explicitly want to exercise the Default-policy fire
    /// construct their own use case
    /// without this seed.
    fn permissive_global_policy_projection() -> ScanPolicyProjection {
        use hort_domain::entities::scan_policy::{
            NegligibleAction, ProvenanceMode, SeverityThreshold,
        };
        use hort_domain::events::PolicyScope;
        ScanPolicyProjection {
            policy_id: Uuid::from_u128(0x0046_0002_0000_0000_0000_0000_0000_0001),
            name: "permissive-test-default".to_string(),
            scope: PolicyScope::Global,
            severity_threshold: SeverityThreshold::Critical,
            quarantine_duration_secs: 0, // permissive — no quarantine on ingest
            require_approval: false,
            provenance_mode: ProvenanceMode::VerifyIfPresent,
            provenance_backends: vec!["cosign".to_string()],
            provenance_identities: Vec::new(),
            max_artifact_age_secs: None,
            license_policy: serde_json::Value::Null,
            archived: false,
            scan_backends: vec!["trivy".to_string()],
            rescan_interval_hours: 24,
            negligible_action: NegligibleAction::Ignore,
            stream_version: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// Seed the permissive global policy onto a fresh projections
    /// mock — keeps every existing test that does not explicitly
    /// seed its own policy on the no-quarantine baseline.
    fn seed_permissive_global_policy(projections: &MockPolicyProjectionRepository) {
        projections.insert(permissive_global_policy_projection());
    }

    #[allow(clippy::type_complexity)]
    fn make_use_case() -> (
        IngestUseCase,
        Arc<MockArtifactRepository>,
        Arc<MockEventStore>,
        Arc<MockArtifactLifecycle>,
        Arc<MockStoragePort>,
        Arc<MockRepositoryRepository>,
    ) {
        make_use_case_with_flag(true)
    }

    #[allow(clippy::type_complexity)]
    fn make_use_case_with_flag(
        include_repository_label: bool,
    ) -> (
        IngestUseCase,
        Arc<MockArtifactRepository>,
        Arc<MockEventStore>,
        Arc<MockArtifactLifecycle>,
        Arc<MockStoragePort>,
        Arc<MockRepositoryRepository>,
    ) {
        make_use_case_with_caps(include_repository_label, HashMap::new())
    }

    /// Variant that lets tests supply a specific operator-cap map — the
    /// key handle for the metadata-cap boundary tests, which
    /// pin the effective cap to an exact byte count regardless of the
    /// stub handler's declared max.
    ///
    /// Uses `metadata_blob_max_bytes = 0` (unbounded) — tests that
    /// specifically need to exercise the blob cap use
    /// [`make_use_case_with_caps_and_blob_max`] instead.
    #[allow(clippy::type_complexity)]
    fn make_use_case_with_caps(
        include_repository_label: bool,
        metadata_caps: HashMap<String, usize>,
    ) -> (
        IngestUseCase,
        Arc<MockArtifactRepository>,
        Arc<MockEventStore>,
        Arc<MockArtifactLifecycle>,
        Arc<MockStoragePort>,
        Arc<MockRepositoryRepository>,
    ) {
        make_use_case_with_caps_and_blob_max(include_repository_label, metadata_caps, 0)
    }

    /// Variant that lets tests pin the blob safety cap
    /// (`HORT_METADATA_BLOB_MAX_SIZE`). `0` means
    /// "accept anything" — production defaults to 10 MB via
    /// `Config::from_env`. Tests that exercise the blob-cap
    /// rejection path set an explicit small value here.
    #[allow(clippy::type_complexity)]
    fn make_use_case_with_caps_and_blob_max(
        include_repository_label: bool,
        metadata_caps: HashMap<String, usize>,
        metadata_blob_max_bytes: usize,
    ) -> (
        IngestUseCase,
        Arc<MockArtifactRepository>,
        Arc<MockEventStore>,
        Arc<MockArtifactLifecycle>,
        Arc<MockStoragePort>,
        Arc<MockRepositoryRepository>,
    ) {
        let (uc, artifacts, events, lifecycle, storage, repos, _group_lifecycle) =
            make_use_case_with_group_lifecycle(
                include_repository_label,
                metadata_caps,
                metadata_blob_max_bytes,
            );
        (uc, artifacts, events, lifecycle, storage, repos)
    }

    /// Extended helper: returns the
    /// `MockArtifactGroupLifecyclePort` alongside the other mocks so
    /// post-commit hook tests can assert on (or inject into) the
    /// group-add path. Existing ingest tests keep their 6-tuple shape
    /// via [`make_use_case_with_caps_and_blob_max`].
    #[allow(clippy::type_complexity)]
    fn make_use_case_with_group_lifecycle(
        include_repository_label: bool,
        metadata_caps: HashMap<String, usize>,
        metadata_blob_max_bytes: usize,
    ) -> (
        IngestUseCase,
        Arc<MockArtifactRepository>,
        Arc<MockEventStore>,
        Arc<MockArtifactLifecycle>,
        Arc<MockStoragePort>,
        Arc<MockRepositoryRepository>,
        Arc<MockArtifactGroupLifecyclePort>,
    ) {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let events = Arc::new(MockEventStore::new());
        let lifecycle = Arc::new(MockArtifactLifecycle::new(artifacts.clone()));
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let groups = Arc::new(MockArtifactGroupRepository::new());
        let group_lifecycle = Arc::new(MockArtifactGroupLifecyclePort::new(groups.clone()));
        let group_use_case = Arc::new(ArtifactGroupUseCase::new(
            groups,
            group_lifecycle.clone(),
            include_repository_label,
        ));
        // Empty curation port wired in by
        // default. The existing test suite intentionally never seeds
        // a rule, so the gate hits its empty-rule fast-path and the
        // body of the rest of `ingest` runs unchanged. The
        // gate-coverage tests use the dedicated helper below
        // (`make_use_case_with_curation`).
        let curation_rules = Arc::new(MockCurationRuleRepository::new());
        // Refcount projection mock. The default empty
        // `MockContentReferenceIndex` is fine for every existing test
        // that does not specifically assert on the refcount surface;
        // tests that DO assert use `make_use_case_with_content_refs`.
        let content_references = Arc::new(MockContentReferenceIndex::new());
        // Seed a permissive global policy so tests that don't
        // exercise quarantine-by-default keep
        // a no-quarantine-on-ingest baseline. Tests
        // that exercise the Default-policy fire must construct their
        // own use case via the dedicated helper below (the projections
        // mock there is intentionally empty).
        let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
        seed_permissive_global_policy(&policy_projections);
        let jobs = Arc::new(MockJobsRepository::default());

        let uc = IngestUseCase::new(
            storage.clone(),
            lifecycle.clone(),
            artifacts.clone(),
            repos.clone(),
            crate::event_store_publisher::wrap_for_test(events.clone()),
            curation_rules,
            group_use_case,
            include_repository_label,
            metadata_caps,
            metadata_blob_max_bytes,
            content_references,
            policy_projections,
            jobs,
        );

        (
            uc,
            artifacts,
            events,
            lifecycle,
            storage,
            repos,
            group_lifecycle,
        )
    }

    /// Extended helper that hands the
    /// `MockCurationRuleRepository` back so tests can seed curation
    /// rules against the inbound `repository_id`. Mirrors
    /// [`make_use_case_with_group_lifecycle`] but stops at the
    /// six-tuple shape and adds the curation handle.
    #[allow(clippy::type_complexity)]
    fn make_use_case_with_curation(
        include_repository_label: bool,
    ) -> (
        IngestUseCase,
        Arc<MockArtifactRepository>,
        Arc<MockEventStore>,
        Arc<MockArtifactLifecycle>,
        Arc<MockStoragePort>,
        Arc<MockRepositoryRepository>,
        Arc<MockCurationRuleRepository>,
    ) {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let events = Arc::new(MockEventStore::new());
        let lifecycle = Arc::new(MockArtifactLifecycle::new(artifacts.clone()));
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let groups = Arc::new(MockArtifactGroupRepository::new());
        let group_lifecycle = Arc::new(MockArtifactGroupLifecyclePort::new(groups.clone()));
        let group_use_case = Arc::new(ArtifactGroupUseCase::new(
            groups,
            group_lifecycle,
            include_repository_label,
        ));
        let curation_rules = Arc::new(MockCurationRuleRepository::new());
        let content_references = Arc::new(MockContentReferenceIndex::new());
        // Permissive global policy seed; mirrors
        // `make_use_case_with_group_lifecycle`.
        let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
        seed_permissive_global_policy(&policy_projections);
        let jobs = Arc::new(MockJobsRepository::default());

        let uc = IngestUseCase::new(
            storage.clone(),
            lifecycle.clone(),
            artifacts.clone(),
            repos.clone(),
            crate::event_store_publisher::wrap_for_test(events.clone()),
            curation_rules.clone(),
            group_use_case,
            include_repository_label,
            HashMap::new(),
            0,
            content_references,
            policy_projections,
            jobs,
        );

        (
            uc,
            artifacts,
            events,
            lifecycle,
            storage,
            repos,
            curation_rules,
        )
    }

    /// Extended helper that hands the
    /// `MockContentReferenceIndex` back so tests can assert on the
    /// refcount-projection writes the ingest path performs. Mirrors
    /// [`make_use_case_with_curation`] but with the refcount mock in
    /// the trailing slot.
    #[allow(clippy::type_complexity)]
    fn make_use_case_with_content_refs(
        include_repository_label: bool,
    ) -> (
        IngestUseCase,
        Arc<MockArtifactRepository>,
        Arc<MockEventStore>,
        Arc<MockArtifactLifecycle>,
        Arc<MockStoragePort>,
        Arc<MockRepositoryRepository>,
        Arc<MockContentReferenceIndex>,
    ) {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let events = Arc::new(MockEventStore::new());
        let lifecycle = Arc::new(MockArtifactLifecycle::new(artifacts.clone()));
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let groups = Arc::new(MockArtifactGroupRepository::new());
        let group_lifecycle = Arc::new(MockArtifactGroupLifecyclePort::new(groups.clone()));
        let group_use_case = Arc::new(ArtifactGroupUseCase::new(
            groups,
            group_lifecycle,
            include_repository_label,
        ));
        let curation_rules = Arc::new(MockCurationRuleRepository::new());
        let content_references = Arc::new(MockContentReferenceIndex::new());

        // Permissive global policy seed; mirrors
        // `make_use_case_with_group_lifecycle`.
        let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
        seed_permissive_global_policy(&policy_projections);
        let jobs = Arc::new(MockJobsRepository::default());

        let uc = IngestUseCase::new(
            storage.clone(),
            lifecycle.clone(),
            artifacts.clone(),
            repos.clone(),
            crate::event_store_publisher::wrap_for_test(events.clone()),
            curation_rules,
            group_use_case,
            include_repository_label,
            HashMap::new(),
            0,
            content_references.clone(),
            policy_projections,
            jobs,
        );

        (
            uc,
            artifacts,
            events,
            lifecycle,
            storage,
            repos,
            content_references,
        )
    }

    /// Shared `FormatHandler` instance used by all ingest tests that don't
    /// specifically care about cap behaviour. `format_key = "pypi"` lines
    /// up with `sample_coords().format = Pypi`; the 10 MB max ensures the
    /// default cap path never accidentally triggers `metadata_too_large`
    /// for the small payloads these tests build.
    fn test_handler() -> StubFormatHandler {
        StubFormatHandler::new("pypi").with_max_bytes(10 * 1024 * 1024)
    }

    fn sample_coords() -> ArtifactCoords {
        ArtifactCoords {
            name: "my-package".into(),
            name_as_published: "My_Package".into(),
            version: Some("1.0.0".into()),
            path: "my-package/1.0.0/my-package-1.0.0.tar.gz".into(),
            format: RepositoryFormat::Pypi,
            metadata: serde_json::Value::Null,
        }
    }

    fn content_stream(data: &[u8]) -> Box<dyn AsyncRead + Send + Unpin> {
        Box::new(std::io::Cursor::new(data.to_vec()))
    }

    /// Thin wrapper over [`sample_repository`] that aligns the repository
    /// format with [`sample_coords`] (both Pypi). Every ingest-success path
    /// in this module needs the two to match — without this helper every
    /// test would have to remember `repo.format = RepositoryFormat::Pypi`
    /// after the format-mismatch check was added.
    fn pypi_repository() -> Repository {
        let mut repo = sample_repository();
        repo.format = RepositoryFormat::Pypi;
        repo
    }

    /// Default-shaped [`DirectIngestRequest`] for tests. Fields that
    /// most tests don't care about (content_type, actor, legacy
    /// hashes) get sensible defaults; specific tests override via
    /// struct-update syntax (`DirectIngestRequest { payload_metadata:
    /// ..., ..req(...) }`).
    fn req(repo_id: Uuid) -> DirectIngestRequest {
        DirectIngestRequest {
            repository_id: repo_id,
            coords: sample_coords(),
            content_type: "application/gzip".into(),
            actor: api_actor(),
            legacy_sha1: None,
            legacy_md5: None,
            payload_metadata: serde_json::Value::Null,
        }
    }

    /// Helper for `register_by_hash` tests, which still take the legacy
    /// `IngestRequest` type. `register_by_hash` is a separate use-case
    /// path (cross-mount dedup) —
    /// it has no verification target because the hash is supplied
    /// directly by the caller.
    fn req_legacy(repo_id: Uuid) -> IngestRequest {
        IngestRequest {
            repository_id: repo_id,
            coords: sample_coords(),
            content_type: "application/gzip".into(),
            quarantine_anchor_override: None,
            actor: api_actor(),
            legacy_sha1: None,
            legacy_md5: None,
            declared_sha256: None,
            payload_metadata: serde_json::Value::Null,
        }
    }

    /// Default-shaped [`RegisterExistingCasBlobRequest`] for the
    /// follower-registration tests. Mirrors
    /// [`req_legacy`]'s defaults so the cross-repo path lines up with
    /// the existing `register_by_hash` fixtures.
    fn recb_req(repo_id: Uuid, content_hash: ContentHash) -> RegisterExistingCasBlobRequest {
        RegisterExistingCasBlobRequest {
            repository_id: repo_id,
            coords: sample_coords(),
            content_type: "application/gzip".into(),
            actor: api_actor(),
            payload_metadata: serde_json::Value::Null,
            content_hash,
            // Existing recb tests are not seed-import
            // exercises; quarantine stays untouched (legacy behaviour).
            seed_import_quarantine_anchor: None,
        }
    }

    #[test]
    fn ingest_success() {
        // Pre-construct the repo outside the closure so repo.key is visible
        // to the outer assertion scope without cross-test env-var smuggling.
        let repo = pypi_repository();
        let repo_id = repo.id;
        let repo_key = repo.key.clone();

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, _artifacts, _events, lifecycle, _storage, repos) = make_use_case();
                repos.insert(repo);

                let artifact = uc
                    .ingest_direct(
                        req(repo_id),
                        content_stream(b"hello world"),
                        &test_handler(),
                    )
                    .await
                    .unwrap()
                    .artifact;

                assert_eq!(artifact.repository_id, repo_id);
                assert_eq!(artifact.name, "my-package");
                assert_eq!(artifact.version, Some("1.0.0".into()));
                assert_eq!(artifact.size_bytes, 11);
                assert_eq!(artifact.quarantine_status, QuarantineStatus::None);

                // Verify ArtifactIngested event was emitted.
                let transitions = lifecycle.committed_transitions();
                assert_eq!(transitions.len(), 1);
                assert!(matches!(
                    &transitions[0].1.events[0].event,
                    DomainEvent::ArtifactIngested(_)
                ));
            });
        });

        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_ingest_total",
            &[
                ("format", "pypi"),
                ("repository", repo_key.as_str()),
                ("result", "success"),
            ],
            1,
        );
        assert_histogram_has_sample(
            &entries,
            "hort_ingest_duration_seconds",
            &[("format", "pypi")],
        );
        assert_histogram_has_sample(&entries, "hort_ingest_size_bytes", &[("format", "pypi")]);
        assert_metric_absent(&entries, "hort_quarantine_triggered_total");
    }

    /// `ingest` returns `IngestOutcome` carrying
    /// both the persisted `Artifact` and the `EventToAppend::event_id` the
    /// use case committed for `ArtifactIngested`. Downstream composers
    /// (the OCI manifest-PUT) thread that id as `causation_id`
    /// on subsequent events — the contract is that it equals the id the
    /// adapter persisted, which equals the id the use case minted locally
    /// and handed to `commit_transition`.
    #[test]
    fn ingest_outcome_exposes_artifact_and_ingested_event_id() {
        let repo = pypi_repository();
        let repo_id = repo.id;

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, _storage, repos) = make_use_case();
            repos.insert(repo);

            let outcome = uc
                .ingest_direct(
                    req(repo_id),
                    content_stream(b"hello world"),
                    &test_handler(),
                )
                .await
                .expect("fresh ingest must succeed");

            // Artifact is present and non-nil.
            assert_ne!(outcome.artifact.id, Uuid::nil());
            assert_eq!(outcome.artifact.repository_id, repo_id);

            // `ingested_event_id` equals the exact `EventToAppend::event_id`
            // threaded through `commit_transition`. A future refactor that
            // minted a fresh uuid at the return site (not the append site)
            // would dangle the causation chain — this assertion pins that.
            let transitions = lifecycle.committed_transitions();
            assert_eq!(transitions.len(), 1);
            let appended = &transitions[0].1.events[0];
            assert_ne!(appended.event_id, Uuid::nil());
            assert_eq!(outcome.ingested_event_id, appended.event_id);
        });
    }

    /// Server-initiated ingest (OCI manifest /
    /// blob pull-through) hands `IngestRequest::actor =
    /// ApiActor { user_id: Uuid::nil() }` because there is no human
    /// caller. The persisted artifact's `uploaded_by` column is a
    /// FK → users(id); writing the nil uuid violated the constraint
    /// because no user row owns the nil id, and the e2e mirror smoke
    /// failed with `artifacts_uploaded_by_fkey`. The use case must
    /// treat the nil-uuid `ApiActor` as "system-initiated" and persist
    /// `uploaded_by = NULL` so the FK is satisfied (nullable column,
    /// `ON DELETE SET NULL`).
    ///
    /// Sentinel rationale: introducing a richer `Actor` enum on
    /// `IngestRequest` would touch every caller of `ingest()`. The
    /// nil-uuid sentinel is already established in the pull-through
    /// paths (see `crates/hort-http-oci/src/blobs.rs:512` +
    /// `crates/hort-http-oci/src/manifests.rs::try_upstream_manifest_pull`)
    /// — the use case just needs to honour it on the persistence
    /// boundary.
    #[test]
    fn ingest_with_nil_uuid_actor_persists_uploaded_by_as_null() {
        let repo = pypi_repository();
        let repo_id = repo.id;

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, _lifecycle, _storage, repos) = make_use_case();
            repos.insert(repo);

            let mut request = req(repo_id);
            request.actor = ApiActor {
                user_id: Uuid::nil(),
            };

            let outcome = uc
                .ingest_direct(request, content_stream(b"system-ingested"), &test_handler())
                .await
                .expect("system-actor ingest must succeed");

            assert_eq!(
                outcome.artifact.uploaded_by, None,
                "nil-uuid ApiActor is the system-actor sentinel; \
                 uploaded_by must be NULL so the FK to users(id) is satisfied"
            );
        });
    }

    /// Regression guard for the previous test: a real (non-nil) user id
    /// must still round-trip onto the persisted `uploaded_by`. If a
    /// future refactor of the nil-uuid sentinel started writing `None`
    /// for every actor, this test would fail.
    #[test]
    fn ingest_with_real_user_actor_persists_uploaded_by_as_some_uid() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let user_id = Uuid::new_v4();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, _lifecycle, _storage, repos) = make_use_case();
            repos.insert(repo);

            let mut request = req(repo_id);
            request.actor = ApiActor { user_id };

            let outcome = uc
                .ingest_direct(request, content_stream(b"human-ingested"), &test_handler())
                .await
                .expect("real-user ingest must succeed");

            assert_eq!(
                outcome.artifact.uploaded_by,
                Some(user_id),
                "real-user ApiActor must persist verbatim onto uploaded_by"
            );
        });
    }

    // -- Cargo registration-collision gate ------------------------------------

    /// Build a cargo `DirectIngestRequest` for `name`@`version` with an
    /// explicit canonical cargo path. `name` doubles as the published name.
    fn cargo_req(repo_id: Uuid, name: &str, version: &str) -> DirectIngestRequest {
        let mut request = req(repo_id);
        request.coords = ArtifactCoords {
            name: name.into(),
            name_as_published: name.into(),
            version: Some(version.into()),
            path: format!("crates/{name}/{version}/{name}-{version}.crate"),
            format: RepositoryFormat::Cargo,
            metadata: serde_json::Value::Null,
        };
        request
    }

    fn seed_crate(artifacts: &MockArtifactRepository, repo_id: Uuid, name: &str, version: &str) {
        let mut a = sample_artifact(QuarantineStatus::Released);
        a.repository_id = repo_id;
        a.name = name.into();
        a.name_as_published = name.into();
        a.version = Some(version.into());
        a.path = format!("crates/{name}/{version}/{name}-{version}.crate");
        artifacts.insert(a);
    }

    fn cargo_repo() -> Repository {
        let mut repo = sample_repository();
        repo.format = RepositoryFormat::Cargo;
        repo
    }

    /// (a) Publishing `foo_bar` when `foo-bar` already exists → 409-class
    /// `InvalidState`. The two differ only by `-`/`_`, which crates.io
    /// forbids; the gate rejects before any byte reaches storage.
    #[test]
    fn ingest_direct_rejects_cargo_separator_collision() {
        let repo = cargo_repo();
        let repo_id = repo.id;
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, artifacts, _events, _lifecycle, _storage, repos) = make_use_case();
            repos.insert(repo);
            seed_crate(&artifacts, repo_id, "foo-bar", "1.0.0");

            let handler = StubFormatHandler::new("cargo")
                .with_max_bytes(10 * 1024 * 1024)
                .with_collision_fold();
            let err = uc
                .ingest_direct(
                    cargo_req(repo_id, "foo_bar", "1.0.0"),
                    content_stream(b"crate-bytes"),
                    &handler,
                )
                .await
                .unwrap_err();
            match err {
                AppError::Domain(DomainError::InvalidState(msg)) => {
                    assert!(
                        msg.contains("foo-bar") && msg.contains("hyphen/underscore"),
                        "message must name the existing crate + the rule: {msg}"
                    );
                }
                other => panic!("expected InvalidState collision, got {other:?}"),
            }
        });
    }

    /// (b) Publishing a NEW VERSION of the SAME crate (`foo-bar` 2.0.0 when
    /// `foo-bar` 1.0.0 exists) is NOT a collision — the existing canonical
    /// name equals the new one, so the gate passes and ingest proceeds.
    #[test]
    fn ingest_direct_allows_same_canonical_new_version() {
        let repo = cargo_repo();
        let repo_id = repo.id;
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, artifacts, _events, _lifecycle, _storage, repos) = make_use_case();
            repos.insert(repo);
            seed_crate(&artifacts, repo_id, "foo-bar", "1.0.0");

            let handler = StubFormatHandler::new("cargo")
                .with_max_bytes(10 * 1024 * 1024)
                .with_collision_fold();
            let outcome = uc
                .ingest_direct(
                    cargo_req(repo_id, "foo-bar", "2.0.0"),
                    content_stream(b"crate-v2"),
                    &handler,
                )
                .await;
            assert!(
                outcome.is_ok(),
                "same canonical name (new version) must not be a collision: {outcome:?}"
            );
        });
    }

    /// (c) Publishing a CASE variant (`Foo-Bar`) of an existing `foo-bar`
    /// is allowed — it collapses to the same canonical name. This pins the
    /// load-bearing coupling that the comparison is against the NORMALIZED
    /// `coords.name`: production sets `coords.name = normalize_name(raw)`
    /// (lowercased) while `name_as_published` keeps the raw case. A
    /// regression that compared `name_as_published` (or set `coords.name`
    /// to the raw form) would 409 here — a false positive — while test (b)
    /// still passed. So (c), not (b), is the guard for that coupling.
    #[test]
    fn ingest_direct_allows_case_variant_same_canonical() {
        let repo = cargo_repo();
        let repo_id = repo.id;
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, artifacts, _events, _lifecycle, _storage, repos) = make_use_case();
            repos.insert(repo);
            seed_crate(&artifacts, repo_id, "foo-bar", "1.0.0");

            // Production shape: `name` normalized, `name_as_published` raw.
            let mut request = req(repo_id);
            request.coords = ArtifactCoords {
                name: "foo-bar".into(),              // = normalize_name("Foo-Bar")
                name_as_published: "Foo-Bar".into(), // raw publish name
                version: Some("2.0.0".into()),
                path: "crates/foo-bar/2.0.0/foo-bar-2.0.0.crate".into(),
                format: RepositoryFormat::Cargo,
                metadata: serde_json::Value::Null,
            };

            let handler = StubFormatHandler::new("cargo")
                .with_max_bytes(10 * 1024 * 1024)
                .with_collision_fold();
            let outcome = uc
                .ingest_direct(request, content_stream(b"crate-Foo-Bar"), &handler)
                .await;
            assert!(
                outcome.is_ok(),
                "case-variant republish (same canonical name) must be allowed: {outcome:?}"
            );
        });
    }

    /// (d) A format whose `collision_key` is `None` (the default — npm,
    /// pypi) skips the gate entirely: publishing `foo_bar` alongside an
    /// existing `foo-bar` proceeds, even though they would fold together.
    /// Pins that the gate is keyed on `collision_key`, not hardcoded.
    #[test]
    fn ingest_direct_skips_gate_when_collision_key_is_none() {
        let repo = cargo_repo();
        let repo_id = repo.id;
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, artifacts, _events, _lifecycle, _storage, repos) = make_use_case();
            repos.insert(repo);
            seed_crate(&artifacts, repo_id, "foo-bar", "1.0.0");

            // No `.with_collision_fold()` → collision_key returns None.
            let handler = StubFormatHandler::new("cargo").with_max_bytes(10 * 1024 * 1024);
            let outcome = uc
                .ingest_direct(
                    cargo_req(repo_id, "foo_bar", "1.0.0"),
                    content_stream(b"crate-bytes"),
                    &handler,
                )
                .await;
            assert!(
                outcome.is_ok(),
                "a None collision_key must skip the gate (no rejection): {outcome:?}"
            );
        });
    }

    #[test]
    fn ingest_duplicate_same_hash_returns_existing() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let repo_key = repo.key.clone();

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, _artifacts, _events, _lifecycle, _storage, repos) = make_use_case();
                repos.insert(repo);

                // First ingest.
                let first = uc
                    .ingest_direct(
                        req(repo_id),
                        content_stream(b"hello world"),
                        &test_handler(),
                    )
                    .await
                    .unwrap()
                    .artifact;

                // Second ingest with same content at same path — dedup returns
                // the existing artifact.
                let second = uc
                    .ingest_direct(
                        req(repo_id),
                        content_stream(b"hello world"),
                        &test_handler(),
                    )
                    .await
                    .unwrap()
                    .artifact;

                assert_eq!(first.id, second.id);
            });
        });

        let entries = snap.into_vec();
        // Success on first call + Duplicate on second.
        assert_counter(
            &entries,
            "hort_ingest_total",
            &[
                ("format", "pypi"),
                ("repository", repo_key.as_str()),
                ("result", "success"),
            ],
            1,
        );
        assert_counter(
            &entries,
            "hort_ingest_total",
            &[
                ("format", "pypi"),
                ("repository", repo_key.as_str()),
                ("result", "duplicate"),
            ],
            1,
        );
        assert_histogram_has_sample(
            &entries,
            "hort_ingest_duration_seconds",
            &[("format", "pypi")],
        );
        assert_histogram_has_sample(&entries, "hort_ingest_size_bytes", &[("format", "pypi")]);
    }

    #[test]
    fn ingest_duplicate_different_hash_returns_conflict() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let repo_key = repo.key.clone();

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, _artifacts, _events, _lifecycle, _storage, repos) = make_use_case();
                repos.insert(repo);

                // First ingest.
                uc.ingest_direct(
                    req(repo_id),
                    content_stream(b"hello world"),
                    &test_handler(),
                )
                .await
                .unwrap();

                // Second ingest with different content at same path.
                let err = uc
                    .ingest_direct(
                        req(repo_id),
                        content_stream(b"different content"),
                        &test_handler(),
                    )
                    .await
                    .unwrap_err();

                assert!(err
                    .to_string()
                    .contains("already exists with different content"));
            });
        });

        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_ingest_total",
            &[
                ("format", "pypi"),
                ("repository", repo_key.as_str()),
                ("result", "conflict"),
            ],
            1,
        );
        assert_histogram_has_sample(
            &entries,
            "hort_ingest_duration_seconds",
            &[("format", "pypi")],
        );
    }

    #[test]
    fn ingest_repository_not_found() {
        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, _artifacts, _events, _lifecycle, _storage, _repos) = make_use_case();

                let err = uc
                    .ingest_direct(
                        req(Uuid::new_v4()),
                        content_stream(b"data"),
                        &test_handler(),
                    )
                    .await
                    .unwrap_err();

                assert!(err.to_string().contains("not found"));
            });
        });

        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_ingest_total",
            &[
                ("format", "pypi"),
                ("repository", "unknown"),
                ("result", "repository_not_found"),
            ],
            1,
        );
        assert_histogram_has_sample(
            &entries,
            "hort_ingest_duration_seconds",
            &[("format", "pypi")],
        );
        // No size_bytes on error.
        assert_metric_absent(&entries, "hort_ingest_size_bytes");
    }

    /// coords.format must match repo.format, and the check must fire BEFORE
    /// `storage.put` so a mis-routed request cannot
    /// create a CAS orphan. The `put_call_count` assertion is the
    /// load-bearing check — merely returning `Err` would be satisfied by any
    /// number of later error paths.
    #[test]
    fn ingest_format_mismatch_rejects_before_storage_put() {
        // Repo is npm, coords claim Pypi — a mis-routed request shape.
        let mut repo = sample_repository();
        repo.format = RepositoryFormat::Npm;
        let repo_id = repo.id;
        let repo_key = repo.key.clone();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, _lifecycle, storage, repos) = make_use_case();
            repos.insert(repo);

            // sample_coords() has format = Pypi; repo is Npm above → mismatch.
            let err = uc
                .ingest_direct(
                    req(repo_id),
                    content_stream(b"should never reach storage"),
                    &test_handler(),
                )
                .await
                .unwrap_err();

            // Validation error, not Storage or Conflict.
            assert!(
                matches!(err, AppError::Domain(DomainError::Validation(_))),
                "expected Validation error, got {err:?}"
            );
            let msg = err.to_string();
            assert!(msg.contains("format mismatch"), "unexpected message: {msg}");
            assert!(msg.contains("pypi"), "expected coords format named: {msg}");
            assert!(msg.contains("npm"), "expected repo format named: {msg}");

            // Load-bearing: storage.put was NOT invoked. A return-Err from any
            // later code path would trivially satisfy the error assertion, so
            // this counter is the only proof the short-circuit fired.
            assert_eq!(
                storage.put_call_count(),
                0,
                "storage.put must not be called on format mismatch — orphan prevention"
            );
        });

        // Metric side-check: the failure is classified as ValidationError
        // (see `classify_ingest_error`), and the repository label resolves
        // correctly because the repo WAS looked up successfully — the
        // mismatch is a domain fact about coords, not an unknown repo.
        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, _artifacts, _events, _lifecycle, _storage, repos) = make_use_case();
                let mut repo = sample_repository();
                repo.format = RepositoryFormat::Npm;
                repo.key = repo_key.clone();
                let repo_id = repo.id;
                repos.insert(repo);

                let _ = uc
                    .ingest_direct(req(repo_id), content_stream(b"x"), &test_handler())
                    .await;
            });
        });
        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_ingest_total",
            &[
                ("format", "pypi"),
                ("repository", repo_key.as_str()),
                ("result", "validation_error"),
            ],
            1,
        );
        // No size metric on error (no bytes were stored).
        assert_metric_absent(&entries, "hort_ingest_size_bytes");
    }

    // Quarantine resolution tests.
    //
    // An earlier `ingest_with_quarantine` test exercised a
    // caller-supplied `DirectIngestRequest.quarantine_until` override.
    // That field is gone: the only ingest-time quarantine paths now
    // are policy-driven (operator `ScanPolicy.quarantineDuration`,
    // or `DefaultPolicy::quarantine_duration_secs` on no-policy
    // fallback). The three tests below pin the three resolution
    // cases: default-fires, operator-strict, operator-permissive.

    #[test]
    fn ingest_default_no_policy_quarantines() {
        // No matched ScanPolicy → DefaultPolicy (24h) fires →
        // artifact transitions to Quarantined with
        // `quarantine_window_start = ingested_at`.
        let repo = pypi_repository();
        let repo_id = repo.id;
        let repo_key = repo.key.clone();

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                // make_scan_gated_use_case() does NOT pre-seed a permissive
                // policy — its projections mock is the right fixture
                // for Default-policy-fire assertions.
                let (uc, _artifacts, lifecycle, _storage, repos, _policies, _jobs) =
                    make_scan_gated_use_case();
                repos.insert(repo);

                let before = Utc::now();
                let artifact = uc
                    .ingest_direct(req(repo_id), content_stream(b"x"), &test_handler())
                    .await
                    .unwrap()
                    .artifact;
                let after = Utc::now();

                assert_eq!(artifact.quarantine_status, QuarantineStatus::Quarantined);
                // Anchor is `now` (the ingest time stamped inside
                // `ingest_inner`), NOT a precomputed deadline.
                let anchor = artifact
                    .quarantine_window_start
                    .expect("quarantine_window_start set under Default policy");
                assert!(
                    anchor >= before && anchor <= after,
                    "quarantine anchor {anchor:?} must be the ingest timestamp \
                     (between {before:?} and {after:?})"
                );

                // Two transitions: ArtifactIngested + ArtifactQuarantined.
                let transitions = lifecycle.committed_transitions();
                assert_eq!(transitions.len(), 2);
                assert!(matches!(
                    &transitions[0].1.events[0].event,
                    DomainEvent::ArtifactIngested(_)
                ));
                let q_event = match &transitions[1].1.events[0].event {
                    DomainEvent::ArtifactQuarantined(q) => q,
                    other => panic!("expected ArtifactQuarantined, got {other:?}"),
                };
                // The persisted event must carry the anchor (not the
                // deadline) — the fast-path / sweep both
                // recompute the deadline live from this value.
                assert_eq!(q_event.quarantine_window_start, anchor);
            });
        });

        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_quarantine_triggered_total",
            &[("format", "pypi"), ("repository", repo_key.as_str())],
            1,
        );
    }

    #[test]
    fn ingest_operator_strict_policy_quarantines() {
        // Matched ScanPolicy with quarantine_duration_secs = 7200 (2h)
        // → artifact quarantined; anchor is the ingest timestamp; the
        // duration is NOT persisted (no `quarantine_deadline` on the
        // event).
        let repo = pypi_repository();
        let repo_id = repo.id;
        let repo_key = repo.key.clone();

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, _artifacts, lifecycle, _storage, repos, policies, _jobs) =
                    make_scan_gated_use_case();
                repos.insert(repo);
                let mut strict = global_scan_policy();
                strict.quarantine_duration_secs = 7200;
                policies.insert(strict);

                let before = Utc::now();
                let artifact = uc
                    .ingest_direct(req(repo_id), content_stream(b"x"), &test_handler())
                    .await
                    .unwrap()
                    .artifact;
                let after = Utc::now();

                assert_eq!(artifact.quarantine_status, QuarantineStatus::Quarantined);
                let anchor = artifact
                    .quarantine_window_start
                    .expect("quarantine_window_start set under strict policy");
                assert!(anchor >= before && anchor <= after);

                let transitions = lifecycle.committed_transitions();
                assert_eq!(transitions.len(), 2);
                assert!(matches!(
                    &transitions[1].1.events[0].event,
                    DomainEvent::ArtifactQuarantined(_)
                ));
            });
        });

        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_quarantine_triggered_total",
            &[("format", "pypi"), ("repository", repo_key.as_str())],
            1,
        );
    }

    #[test]
    fn ingest_operator_permissive_zero_stays_permissive() {
        // Matched ScanPolicy with `quarantine_duration_secs = 0`
        // (explicit operator opt-out) → artifact ingests with
        // QuarantineStatus::None; the Default policy must NOT
        // override this. Critical override case — confirms that
        // `Some(0)` is honoured and does not fall through to the
        // 24h default.
        let repo = pypi_repository();
        let repo_id = repo.id;
        let repo_key = repo.key.clone();

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, _artifacts, lifecycle, _storage, repos, policies, _jobs) =
                    make_scan_gated_use_case();
                repos.insert(repo);
                let mut permissive = global_scan_policy();
                permissive.quarantine_duration_secs = 0;
                policies.insert(permissive);

                let artifact = uc
                    .ingest_direct(req(repo_id), content_stream(b"x"), &test_handler())
                    .await
                    .unwrap()
                    .artifact;

                // Critical assertion: an explicit operator zero MUST
                // stay permissive. A regression here would mean an
                // operator's deliberate permissive opt-out got
                // overridden by the Default — the bug whose
                // resolution shape (`map().unwrap_or_else`) is
                // designed to prevent.
                assert_eq!(artifact.quarantine_status, QuarantineStatus::None);
                assert_eq!(artifact.quarantine_window_start, None);

                let transitions = lifecycle.committed_transitions();
                assert_eq!(
                    transitions.len(),
                    1,
                    "permissive policy: only ArtifactIngested, no quarantine"
                );
            });
        });

        let entries = snap.into_vec();
        assert_metric_absent(&entries, "hort_quarantine_triggered_total");
        // Sanity check on the ingest path's success label.
        assert_counter(
            &entries,
            "hort_ingest_total",
            &[
                ("format", "pypi"),
                ("repository", repo_key.as_str()),
                ("result", "success"),
            ],
            1,
        );
    }

    #[test]
    fn ingest_without_quarantine() {
        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, _artifacts, _events, lifecycle, _storage, repos) = make_use_case();
                let repo = pypi_repository();
                let repo_id = repo.id;
                repos.insert(repo);

                let artifact = uc
                    .ingest_direct(
                        req(repo_id),
                        content_stream(b"no quarantine"),
                        &test_handler(),
                    )
                    .await
                    .unwrap()
                    .artifact;

                assert_eq!(artifact.quarantine_status, QuarantineStatus::None);

                // Only one transition: ArtifactIngested.
                let transitions = lifecycle.committed_transitions();
                assert_eq!(transitions.len(), 1);
            });
        });

        // hort_quarantine_triggered_total must NOT fire when no quarantine was requested.
        let entries = snap.into_vec();
        assert_metric_absent(&entries, "hort_quarantine_triggered_total");
    }

    // -- payload_metadata routing ----------------------------------------------

    /// When the caller leaves `payload_metadata` at its default (`Value::Null`),
    /// the event and the `ArtifactMetadata` handed to the lifecycle port must
    /// both reflect that absence. The lifecycle mock records the
    /// `Option<ArtifactMetadata>` as its third tuple element — the test
    /// inspects it directly so a future accidental `None` or stray override
    /// fails here.
    #[test]
    fn ingest_payload_metadata_absent_is_routed_as_null() {
        let repo = pypi_repository();
        let repo_id = repo.id;

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, _storage, repos) = make_use_case();
            repos.insert(repo);

            let artifact = uc
                .ingest_direct(
                    req(repo_id),
                    content_stream(b"no metadata"),
                    &test_handler(),
                )
                .await
                .unwrap()
                .artifact;

            let transitions = lifecycle.committed_transitions();
            assert_eq!(transitions.len(), 1);

            // Event payload carries Value::Null.
            match &transitions[0].1.events[0].event {
                DomainEvent::ArtifactIngested(ev) => {
                    assert_eq!(ev.metadata, serde_json::Value::Null);
                }
                other => panic!("expected ArtifactIngested, got: {other:?}"),
            }

            // The lifecycle port saw Some(ArtifactMetadata) keyed to the
            // artifact_id, with metadata=Null and properties={}. We always
            // pass Some(...) from the use case because the row is 1:1 with
            // the artifact and the projection must stay consistent; the
            // `None` slot is reserved for callers (e.g. quarantine-only
            // transitions) that do not carry metadata.
            let metadata = transitions[0]
                .2
                .as_ref()
                .expect("lifecycle must receive ArtifactMetadata on ingest");
            assert_eq!(metadata.artifact_id, artifact.id);
            assert_eq!(metadata.format, RepositoryFormat::Pypi);
            assert_eq!(metadata.metadata, serde_json::Value::Null);
            assert_eq!(
                metadata.properties,
                serde_json::Value::Object(Default::default())
            );
        });
    }

    /// When the caller supplies a non-trivial payload metadata object, the
    /// exact JSON must flow through to both the `ArtifactIngested` event and
    /// the `ArtifactMetadata` argument on `commit_transition` — no mutation,
    /// no normalisation. The domain treats the payload as opaque.
    #[test]
    fn ingest_payload_metadata_present_is_routed_to_event_and_lifecycle() {
        let repo = pypi_repository();
        let repo_id = repo.id;

        let payload = serde_json::json!({
            "pkg_info": {
                "requires_python": ">=3.8",
                "summary": "A sample package",
            },
            "classifiers": ["License :: OSI Approved", "Programming Language :: Rust"],
        });

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, _storage, repos) = make_use_case();
            repos.insert(repo);

            let artifact = uc
                .ingest_direct(
                    DirectIngestRequest {
                        payload_metadata: payload.clone(),
                        ..req(repo_id)
                    },
                    content_stream(b"with metadata"),
                    &test_handler(),
                )
                .await
                .unwrap()
                .artifact;

            let transitions = lifecycle.committed_transitions();
            assert_eq!(transitions.len(), 1);

            // Event carries the payload verbatim.
            match &transitions[0].1.events[0].event {
                DomainEvent::ArtifactIngested(ev) => {
                    assert_eq!(ev.metadata, payload);
                }
                other => panic!("expected ArtifactIngested, got: {other:?}"),
            }

            // Lifecycle port receives an ArtifactMetadata bound to this
            // artifact, carrying the same payload.
            let metadata = transitions[0]
                .2
                .as_ref()
                .expect("lifecycle must receive ArtifactMetadata on ingest");
            assert_eq!(metadata.artifact_id, artifact.id);
            assert_eq!(metadata.format, RepositoryFormat::Pypi);
            assert_eq!(metadata.metadata, payload);
            assert_eq!(
                metadata.properties,
                serde_json::Value::Object(Default::default())
            );
        });
    }

    // -- Additional coverage for result mapping arms --------------------------

    /// Storage port that always fails `put` — exercises the StorageError arm.
    struct FailingStoragePort;

    impl StoragePort for FailingStoragePort {
        fn put(
            &self,
            _stream: Box<dyn AsyncRead + Send + Unpin>,
        ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<PutResult>>
        {
            Box::pin(async {
                Err(DomainError::Invariant(
                    "storage write failed: disk full".into(),
                ))
            })
        }

        fn get(
            &self,
            _hash: &ContentHash,
        ) -> hort_domain::ports::BoxFuture<
            '_,
            hort_domain::error::DomainResult<Box<dyn AsyncRead + Send + Unpin>>,
        > {
            Box::pin(async {
                Err(DomainError::Invariant(
                    "storage read failed: disk failure".into(),
                ))
            })
        }

        fn get_range(
            &self,
            _hash: &ContentHash,
            _range: hort_domain::types::ByteRange,
        ) -> hort_domain::ports::BoxFuture<
            '_,
            hort_domain::error::DomainResult<Box<dyn AsyncRead + Send + Unpin>>,
        > {
            Box::pin(async { unreachable!("FailingStoragePort.get_range not exercised") })
        }

        fn exists(
            &self,
            _hash: &ContentHash,
        ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<bool>> {
            Box::pin(async { Ok(false) })
        }

        fn size_of(
            &self,
            _hash: &ContentHash,
        ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<u64>> {
            Box::pin(async { Ok(0) })
        }
    }

    use hort_domain::ports::storage::PutResult;

    #[test]
    fn ingest_storage_error_maps_to_storage_error_result() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let repo_key = repo.key.clone();

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let artifacts = Arc::new(MockArtifactRepository::new());
                let events = Arc::new(MockEventStore::new());
                let lifecycle = Arc::new(MockArtifactLifecycle::new(artifacts.clone()));
                let storage: Arc<dyn StoragePort> = Arc::new(FailingStoragePort);
                let repos = Arc::new(MockRepositoryRepository::new());
                let groups = Arc::new(MockArtifactGroupRepository::new());
                let group_lifecycle = Arc::new(MockArtifactGroupLifecyclePort::new(groups.clone()));
                let group_use_case =
                    Arc::new(ArtifactGroupUseCase::new(groups, group_lifecycle, true));
                let curation_rules = Arc::new(MockCurationRuleRepository::new());
                let content_references = Arc::new(MockContentReferenceIndex::new());

                // Permissive global policy seed
                // (the storage-error test asserts only on the error
                // path; the Default-policy fire would never be
                // reached because storage put fails first, but the
                // permissive seed keeps this test on the same
                // resolution path as the rest of the inline tests
                // for consistency).
                let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
                seed_permissive_global_policy(&policy_projections);
                let jobs = Arc::new(MockJobsRepository::default());
                let uc = IngestUseCase::new(
                    storage,
                    lifecycle,
                    artifacts,
                    repos.clone(),
                    crate::event_store_publisher::wrap_for_test(events),
                    curation_rules,
                    group_use_case,
                    true,
                    HashMap::new(),
                    0,
                    content_references,
                    policy_projections,
                    jobs,
                );
                repos.insert(repo);

                let err = uc
                    .ingest_direct(req(repo_id), content_stream(b"anything"), &test_handler())
                    .await
                    .unwrap_err();
                assert!(err.to_string().contains("storage"));
            });
        });

        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_ingest_total",
            &[
                ("format", "pypi"),
                ("repository", repo_key.as_str()),
                ("result", "storage_error"),
            ],
            1,
        );
    }

    // -- declared_sha256 early-decision ------------------------------------

    const SAMPLE_PATH: &str = "my-package/1.0.0/my-package-1.0.0.tar.gz";

    /// Pre-seed a PyPI artifact at `SAMPLE_PATH` with the given SHA-256 so
    /// `find_by_path` returns it. No storage content inserted — the tests
    /// below assert `storage.put` is NEVER called when the path-match
    /// branch short-circuits, so the lack of content is load-bearing.
    fn insert_existing_artifact(
        artifacts: &MockArtifactRepository,
        repo_id: Uuid,
        sha256_hex: &str,
    ) -> Artifact {
        let mut a = sample_artifact(QuarantineStatus::None);
        a.repository_id = repo_id;
        a.name = "my-package".into();
        a.version = Some("1.0.0".into());
        a.path = SAMPLE_PATH.into();
        a.sha256_checksum = sha256_hex.parse().unwrap();
        artifacts.insert(a.clone());
        a
    }

    // The declared-hash branch tests
    // (`ingest_declared_hash_matches_computed_on_fresh_insert_succeeds`,
    // `ingest_declared_hash_mismatch_on_fresh_insert_returns_conflict`,
    // `ingest_declared_hash_mismatch_rolls_back_cas_blob_when_not_referenced`)
    // moved to `ingest_verified` — they exercise the declared-hash
    // verification path owned by `VerifiedIngestRequest::ProtocolNative`.

    // The remaining declared-hash branch tests
    // (`ingest_declared_hash_matches_existing_short_circuits_put` and
    // `ingest_declared_hash_differs_from_existing_early_conflict_no_put`)
    // moved to `ingest_verified` — declared-hash semantics belong on the
    // verification path.

    /// Branch (d) regression: existing row + NO declared hash → fall
    /// through to post-put behaviour. This path is already covered by
    /// `ingest_duplicate_same_hash_returns_existing` and
    /// `ingest_duplicate_different_hash_returns_conflict`; re-assert
    /// explicitly that `put` IS called (because we have no short-circuit
    /// signal without a declared hash), as a regression guard against
    /// accidentally short-circuiting the no-declared-hash path too.
    #[test]
    fn ingest_no_declared_hash_with_existing_row_still_calls_put() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let existing_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, artifacts, _events, _lifecycle, storage, repos) = make_use_case();
            repos.insert(repo);
            insert_existing_artifact(&artifacts, repo_id, existing_hash);

            // declared_sha256 is None (via req()); content bytes differ from
            // the existing hash, so the post-put check should yield Conflict.
            let err = uc
                .ingest_direct(
                    req(repo_id),
                    content_stream(b"different content"),
                    &test_handler(),
                )
                .await
                .unwrap_err();
            assert!(matches!(err, AppError::Domain(DomainError::Conflict(_))));
            assert_eq!(
                storage.put_call_count(),
                1,
                "put MUST run when no declared hash is supplied (no short-circuit possible)"
            );
        });
    }

    // -- legacy checksum parameters -----------------------------------------

    /// The default path — both parameters are `None` — must leave
    /// `sha1_checksum` and `md5_checksum` unset on the persisted artifact.
    /// This guards against accidentally writing `Some("")` or a default hash.
    #[test]
    fn ingest_with_no_legacy_checksums_leaves_fields_none() {
        let repo = pypi_repository();
        let repo_id = repo.id;

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, artifacts, _events, _lifecycle, _storage, repos) = make_use_case();
            repos.insert(repo);

            let artifact = uc
                .ingest_direct(req(repo_id), content_stream(b"payload"), &test_handler())
                .await
                .unwrap()
                .artifact;

            let persisted = artifacts.get(artifact.id).unwrap();
            assert_eq!(persisted.sha1_checksum, None);
            assert_eq!(persisted.md5_checksum, None);
        });
    }

    /// When the caller supplies `legacy_sha1` / `legacy_md5`, those values
    /// must land on the persisted `Artifact` in the same atomic commit as
    /// `sha256_checksum` — no second round-trip, no UPDATE after the event.
    #[test]
    fn ingest_with_legacy_checksums_persists_them_on_artifact() {
        let repo = pypi_repository();
        let repo_id = repo.id;

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, artifacts, _events, _lifecycle, _storage, repos) = make_use_case();
            repos.insert(repo);

            let artifact = uc
                .ingest_direct(
                    DirectIngestRequest {
                        legacy_sha1: Some("1111222233334444555566667777888899990000".into()),
                        legacy_md5: Some("aaaabbbbccccddddeeeeffffgggghhhh".into()),
                        ..req(repo_id)
                    },
                    content_stream(b"payload"),
                    &test_handler(),
                )
                .await
                .unwrap()
                .artifact;

            let persisted = artifacts.get(artifact.id).unwrap();
            assert_eq!(
                persisted.sha1_checksum.as_deref(),
                Some("1111222233334444555566667777888899990000")
            );
            assert_eq!(
                persisted.md5_checksum.as_deref(),
                Some("aaaabbbbccccddddeeeeffffgggghhhh")
            );
        });
    }

    /// The `ArtifactIngested` domain event must never carry the legacy
    /// checksums — they are row metadata for protocol compatibility, not
    /// part of the event contract that cross-format consumers read from.
    /// Regression test guards against a future change that adds them to
    /// the event payload.
    #[test]
    fn ingest_event_payload_does_not_carry_legacy_checksums() {
        let repo = pypi_repository();
        let repo_id = repo.id;

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, _storage, repos) = make_use_case();
            repos.insert(repo);

            uc.ingest_direct(
                DirectIngestRequest {
                    legacy_sha1: Some("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into()),
                    legacy_md5: Some("11223344556677889900aabbccddeeff".into()),
                    ..req(repo_id)
                },
                content_stream(b"with legacy"),
                &test_handler(),
            )
            .await
            .unwrap();

            let transitions = lifecycle.committed_transitions();
            assert_eq!(transitions.len(), 1);
            // The event shape is a hard contract — inspect it directly so any
            // future addition of legacy_sha1/legacy_md5 to ArtifactIngested
            // fails this test.
            match &transitions[0].1.events[0].event {
                DomainEvent::ArtifactIngested(ev) => {
                    // ArtifactIngested has these fields and ONLY these fields
                    // relevant to hashing: `sha256`. It carries no sha1/md5.
                    let _ = ev.sha256.clone();
                }
                other => panic!("expected ArtifactIngested, got: {other:?}"),
            }
        });
    }

    // -- Metadata-cap enforcement ------------------------------------------------
    //
    // The cap is computed in the OUTER `ingest` method before `ingest_inner`.
    // Tests verify:
    //
    // 1. A payload at exactly the cap reaches `ingest_inner` (succeeds).
    // 2. A payload one byte over the cap is rejected without touching
    //    storage or the lifecycle port.
    // 3. Rejection emits `hort_ingest_total{result="metadata_too_large"}` —
    //    NOT `validation_error`. This is the key load-bearing assertion:
    //    if anyone in the future accidentally routes the rejection
    //    through `classify_ingest_error`, the latter would reclassify
    //    `DomainError::Validation` as `ValidationError` and the new
    //    label would silently never fire.
    // 4. The operator override (`metadata_caps` map) takes precedence
    //    over the handler's `metadata_expected_max_bytes()`.

    /// Build an `IngestRequest` whose `payload_metadata.to_string()` has
    /// exactly `target_bytes` bytes. The payload shape is
    /// `{"pad":"aaaa..."}` — the `{"pad":"..."}` wrapper is 10 bytes plus
    /// `target_bytes - 10` filler `a`s, producing a serialised string of
    /// exactly `target_bytes`.
    fn req_with_metadata_bytes(repo_id: Uuid, target_bytes: usize) -> DirectIngestRequest {
        // `to_string()` on a Value serialises without whitespace. The
        // wrapper `{"pad":""}` is 10 bytes; add (target - 10) `a`s inside
        // the string to hit the exact byte count.
        assert!(target_bytes >= 10, "cap test requires at least 10 bytes");
        let filler = "a".repeat(target_bytes - 10);
        let value = serde_json::json!({ "pad": filler });
        let actual = value.to_string().len();
        assert_eq!(
            actual, target_bytes,
            "test harness wrong — generated {actual} bytes, wanted {target_bytes}"
        );
        DirectIngestRequest {
            payload_metadata: value,
            ..req(repo_id)
        }
    }

    #[test]
    fn ingest_payload_metadata_at_cap_is_accepted() {
        let repo = pypi_repository();
        let repo_id = repo.id;

        let mut caps = HashMap::new();
        caps.insert("pypi".to_string(), 128);

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, storage, repos) =
                make_use_case_with_caps(true, caps);
            repos.insert(repo);

            // Handler declared max (10 MB) is deliberately permissive —
            // the operator override (128 bytes) is what matters.
            let handler = StubFormatHandler::new("pypi").with_max_bytes(10 * 1024 * 1024);

            let req_at_cap = req_with_metadata_bytes(repo_id, 128);
            let artifact = uc
                .ingest_direct(req_at_cap, content_stream(b"payload"), &handler)
                .await
                .expect("at-cap payload must succeed")
                .artifact;

            // Reached `ingest_inner`: storage saw a put, lifecycle saw a
            // commit. Without this we'd only prove "didn't return Err",
            // which the cap-bypass regression would satisfy trivially.
            assert_eq!(storage.put_call_count(), 1);
            let transitions = lifecycle.committed_transitions();
            assert_eq!(transitions.len(), 1);
            assert_eq!(transitions[0].0.id, artifact.id);
        });
    }

    #[test]
    fn ingest_payload_metadata_one_byte_over_cap_is_rejected() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let repo_key = repo.key.clone();

        let mut caps = HashMap::new();
        caps.insert("pypi".to_string(), 128);

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, _artifacts, _events, lifecycle, storage, repos) =
                    make_use_case_with_caps(true, caps);
                repos.insert(repo);

                let handler = StubFormatHandler::new("pypi").with_max_bytes(10 * 1024 * 1024);

                let req_over_cap = req_with_metadata_bytes(repo_id, 129);
                let err = uc
                    .ingest_direct(req_over_cap, content_stream(b"payload"), &handler)
                    .await
                    .expect_err("one-byte-over payload must be rejected");

                // Terse validation-shaped error — deliberately does NOT
                // include the cap value or the payload size to avoid
                // leaking tenant-specific package characteristics.
                assert!(
                    matches!(err, AppError::Domain(DomainError::Validation(_))),
                    "expected Domain(Validation), got {err:?}"
                );
                assert!(err.to_string().contains("metadata"));

                // Load-bearing: the cap check fired BEFORE `ingest_inner`
                // — no storage put, no lifecycle commit. Without these
                // checks, a classify-error misclassification still
                // returns Err and the test would pass vacuously.
                assert_eq!(
                    storage.put_call_count(),
                    0,
                    "storage.put must not run on cap rejection"
                );
                assert_eq!(
                    lifecycle.committed_transitions().len(),
                    0,
                    "no lifecycle commit on cap rejection"
                );
            });
        });

        let entries = snap.into_vec();
        // The new label fires with the correct cardinality-bounded
        // repository label.
        assert_counter(
            &entries,
            "hort_ingest_total",
            &[
                ("format", "pypi"),
                ("repository", repo_key.as_str()),
                ("result", "metadata_too_large"),
            ],
            1,
        );
        // Critical regression guard: the cap rejection is NOT routed
        // through `classify_ingest_error`. If it were, the
        // `validation_error` counter would tick instead and the new
        // `metadata_too_large` label would silently never fire.
        assert!(
            find_metric(
                &entries,
                MetricKind::Counter,
                "hort_ingest_total",
                &[("result", "validation_error")],
            )
            .is_none(),
            "validation_error counter ticked — cap rejection leaked into classify_ingest_error"
        );
        // Duration histogram fires on every exit path.
        assert_histogram_has_sample(
            &entries,
            "hort_ingest_duration_seconds",
            &[("format", "pypi")],
        );
        // No size bytes histogram — the payload never reached storage.
        assert_metric_absent(&entries, "hort_ingest_size_bytes");
    }

    /// When no operator override is configured, the effective cap falls
    /// through to `FormatHandler::metadata_expected_max_bytes()`. Here
    /// the stub declares 64 bytes; a 65-byte payload is rejected even
    /// though no env-var override exists.
    #[test]
    fn ingest_cap_falls_through_to_handler_declared_max_when_no_override() {
        let repo = pypi_repository();
        let repo_id = repo.id;

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            // Empty caps map — only the handler's declared value applies.
            let (uc, _artifacts, _events, lifecycle, storage, repos) =
                make_use_case_with_caps(true, HashMap::new());
            repos.insert(repo);

            // Handler declares 64 bytes as its expected max.
            let handler = StubFormatHandler::new("pypi").with_max_bytes(64);

            let req_over = req_with_metadata_bytes(repo_id, 65);
            let err = uc
                .ingest_direct(req_over, content_stream(b"p"), &handler)
                .await
                .expect_err("handler-declared cap must still reject");
            assert!(matches!(err, AppError::Domain(DomainError::Validation(_))));

            assert_eq!(storage.put_call_count(), 0);
            assert_eq!(lifecycle.committed_transitions().len(), 0);
        });
    }

    /// `effective_metadata_cap` returns the operator override when one is
    /// configured for the handler's format key, regardless of the
    /// handler's own declared max. Direct unit test so the precedence
    /// rule is asserted even if nobody exercises it via `ingest` later.
    #[test]
    fn effective_metadata_cap_prefers_operator_override() {
        let mut caps = HashMap::new();
        caps.insert("pypi".to_string(), 42);
        let (uc, _, _, _, _, _) = make_use_case_with_caps(true, caps);

        // Handler declares 10 MB; override says 42. 42 wins.
        let handler = StubFormatHandler::new("pypi").with_max_bytes(10 * 1024 * 1024);
        assert_eq!(uc.effective_metadata_cap(&handler), 42);
    }

    #[test]
    fn effective_metadata_cap_falls_through_when_format_absent_from_map() {
        let mut caps = HashMap::new();
        // Override is keyed to a different format — stays inert for pypi.
        caps.insert("cargo".to_string(), 42);
        let (uc, _, _, _, _, _) = make_use_case_with_caps(true, caps);

        let handler = StubFormatHandler::new("pypi").with_max_bytes(777);
        assert_eq!(uc.effective_metadata_cap(&handler), 777);
    }

    // -- classify_ingest_error direct unit tests ----------------------------
    //
    // Full ingest flow paths to Validation / Forbidden / Invariant errors are
    // not reachable with the current mock set — exercise the classifier
    // directly so every `IngestResult` arm of `classify_ingest_error` is
    // covered (hort-app 100% coverage target).

    #[test]
    fn classify_conflict_domain_error() {
        let err = AppError::Domain(DomainError::Conflict("x".into()));
        assert_eq!(classify_ingest_error(&err), IngestResult::Conflict);
    }

    #[test]
    fn classify_validation_domain_error() {
        let err = AppError::Domain(DomainError::Validation("x".into()));
        assert_eq!(classify_ingest_error(&err), IngestResult::ValidationError);
    }

    #[test]
    fn classify_storage_app_error() {
        let err = AppError::Storage("x".into());
        assert_eq!(classify_ingest_error(&err), IngestResult::StorageError);
    }

    #[test]
    fn classify_repository_not_found_domain_error() {
        let err = AppError::Domain(DomainError::NotFound {
            entity: "Repository",
            id: "id".into(),
        });
        assert_eq!(
            classify_ingest_error(&err),
            IngestResult::RepositoryNotFound
        );
    }

    #[test]
    fn classify_other_not_found_falls_through_to_validation_error() {
        // Generic NotFound for a non-Repository entity (defensive fallback).
        let err = AppError::Domain(DomainError::NotFound {
            entity: "Artifact",
            id: "id".into(),
        });
        assert_eq!(classify_ingest_error(&err), IngestResult::ValidationError);
    }

    #[test]
    fn classify_forbidden_falls_through_to_validation_error() {
        let err = AppError::Domain(DomainError::Forbidden("x".into()));
        assert_eq!(classify_ingest_error(&err), IngestResult::ValidationError);
    }

    #[test]
    fn classify_invariant_falls_through_to_validation_error() {
        let err = AppError::Domain(DomainError::Invariant("x".into()));
        assert_eq!(classify_ingest_error(&err), IngestResult::ValidationError);
    }

    #[test]
    fn classify_repository_app_error_falls_through_to_validation_error() {
        let err = AppError::Repository("x".into());
        assert_eq!(classify_ingest_error(&err), IngestResult::ValidationError);
    }

    /// `classify_ingest_error` MUST NOT have a `MetadataTooLarge` arm —
    /// the outer `ingest` method emits that label directly, outside the
    /// classifier. If a future refactor adds an arm here and removes
    /// the direct emission, the regression shows up as this fallback
    /// returning `MetadataTooLarge` instead of `ValidationError`. Guard
    /// by asserting the current fall-through behaviour.
    #[test]
    fn classify_metadata_validation_still_falls_through_to_validation_error() {
        // The `ingest` method converts its cap rejection into a
        // `Domain(Validation(_))`. Routing that through classify would
        // produce `ValidationError` — which is exactly why the cap emission
        // does NOT go through classify. This test pins the current arm
        // and fails loudly if someone adds a `MetadataTooLarge` arm here
        // without updating the cap-emission path.
        let err = AppError::Domain(DomainError::Validation(
            "upload-payload metadata exceeds configured cap".into(),
        ));
        assert_eq!(classify_ingest_error(&err), IngestResult::ValidationError);
    }

    // -- repo_label: cardinality-safety-valve sentinel ------------------------

    /// `FailingStoragePort` is only used by the `ingest_storage_error_*`
    /// test, which exercises `put`. `get`, `exists`, and `size_of` are
    /// trait-required stubs — exercise them directly so the full
    /// `StoragePort` impl is covered.
    #[test]
    fn failing_storage_port_get_and_exists_stubs_are_exercised() {
        use hort_domain::ports::storage::StoragePort as _;
        let port = FailingStoragePort;
        let hash: ContentHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap();
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            match port.get(&hash).await {
                Err(e) => assert!(e.to_string().contains("storage read failed")),
                Ok(_) => panic!("expected Err from FailingStoragePort::get stub"),
            }
            let exists = port.exists(&hash).await.unwrap();
            assert!(!exists);
            let size = port.size_of(&hash).await.unwrap();
            assert_eq!(size, 0);
        });
    }

    /// When `include_repository_label = false`, the label collapses to
    /// `REPOSITORY_ALL` regardless of the caller-supplied key. This is the
    /// cardinality-safety valve; handler-level tests already cover it
    /// end-to-end, but a direct unit test on `repo_label` keeps
    /// `ingest_use_case.rs:121` in the covered set even when the handler
    /// suite is skipped.
    #[test]
    fn repo_label_collapses_to_all_when_flag_disabled() {
        let (uc_disabled, _, _, _, _, _) = make_use_case_with_flag(false);
        assert_eq!(uc_disabled.repo_label(Some("repo-key")), "_all");
        assert_eq!(uc_disabled.repo_label(None), "_all");

        let (uc_enabled, _, _, _, _, _) = make_use_case_with_flag(true);
        assert_eq!(uc_enabled.repo_label(Some("repo-key")), "repo-key");
        assert_eq!(uc_enabled.repo_label(None), "unknown");
    }

    // -- Metadata-strategy dispatch ----------------------------------------------
    //
    // The outer `ingest` method consults `handler.metadata_strategy()` after
    // the metadata cap check and before `ingest_inner`. Four cells to
    // cover:
    //
    //   Inline                             → blob=None, metadata=full
    //   HashReference under threshold      → blob=None, metadata=full
    //   HashReference over threshold       → blob=Some(h), metadata=summary
    //   HashReference over threshold AND
    //     over blob cap                    → AppError, storage.put NOT called
    //
    // The over-blob-cap path emits `hort_ingest_total{result="metadata_too_large"}`
    // directly — not via `classify_ingest_error`. That's the same label as
    // the pre-dispatch cap (by design — one counter bucket for
    // all metadata-size failures). The tracing log disambiguates via
    // `reason="blob-too-large"`.

    /// Inline-strategy handler under the per-format cap: event and
    /// projection carry the full payload verbatim; `metadata_blob` is
    /// `None` on both. One storage put — the artifact content only, no
    /// metadata blob.
    #[test]
    fn ingest_inline_strategy_does_not_write_metadata_blob() {
        let repo = pypi_repository();
        let repo_id = repo.id;

        let payload = serde_json::json!({ "pad": "a".repeat(100) });

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, storage, repos) = make_use_case();
            repos.insert(repo);

            // Inline is the trait default; `test_handler()` does not
            // override — this is the current production shape for
            // every compiled-in handler.
            let handler = StubFormatHandler::new("pypi").with_max_bytes(10 * 1024 * 1024);
            assert_eq!(handler.metadata_strategy(), MetadataStrategy::Inline);

            uc.ingest_direct(
                DirectIngestRequest {
                    payload_metadata: payload.clone(),
                    ..req(repo_id)
                },
                content_stream(b"payload"),
                &handler,
            )
            .await
            .expect("inline ingest must succeed");

            // One put — the artifact content. No metadata blob put.
            assert_eq!(
                storage.put_call_count(),
                1,
                "inline strategy must not round-trip metadata through CAS"
            );
            let transitions = lifecycle.committed_transitions();
            assert_eq!(transitions.len(), 1);

            // Event carries the full payload, no blob.
            match &transitions[0].1.events[0].event {
                DomainEvent::ArtifactIngested(ev) => {
                    assert_eq!(ev.metadata, payload);
                    assert!(ev.metadata_blob.is_none());
                }
                other => panic!("expected ArtifactIngested, got: {other:?}"),
            }

            // Projection row matches.
            let md = transitions[0].2.as_ref().expect("metadata row present");
            assert_eq!(md.metadata, payload);
            assert!(md.metadata_blob.is_none());
        });
    }

    /// HashReference strategy, payload under the inline threshold: no
    /// CAS round-trip for metadata; the event + projection carry the
    /// full payload verbatim and `metadata_blob` is `None`. This is the
    /// inline-fallback path that keeps small packuments cheap.
    #[test]
    fn ingest_hash_reference_under_threshold_stays_inline() {
        let repo = pypi_repository();
        let repo_id = repo.id;

        // 100-byte payload, 1 KB threshold — well under.
        let payload = serde_json::json!({ "pad": "a".repeat(100) });

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, storage, repos) = make_use_case();
            repos.insert(repo);

            let handler = StubFormatHandler::new("pypi")
                .with_max_bytes(10 * 1024 * 1024)
                .with_strategy(MetadataStrategy::HashReference {
                    inline_threshold_bytes: 1024,
                })
                // Summary sentinel should NOT appear in the event —
                // under-threshold path never calls extract_metadata_summary.
                .with_summary(serde_json::json!({ "sentinel": "must-not-appear" }));

            uc.ingest_direct(
                DirectIngestRequest {
                    payload_metadata: payload.clone(),
                    ..req(repo_id)
                },
                content_stream(b"payload"),
                &handler,
            )
            .await
            .expect("under-threshold ingest must succeed");

            // One put — content only. The metadata blob path was NOT
            // taken because the payload was under the threshold.
            assert_eq!(
                storage.put_call_count(),
                1,
                "under-threshold HashReference must not round-trip metadata through CAS"
            );

            let transitions = lifecycle.committed_transitions();
            assert_eq!(transitions.len(), 1);
            match &transitions[0].1.events[0].event {
                DomainEvent::ArtifactIngested(ev) => {
                    // Full payload, not the sentinel summary.
                    assert_eq!(ev.metadata, payload);
                    assert!(ev.metadata_blob.is_none());
                }
                other => panic!("expected ArtifactIngested, got: {other:?}"),
            }
            let md = transitions[0].2.as_ref().expect("metadata row present");
            assert_eq!(md.metadata, payload);
            assert!(md.metadata_blob.is_none());
        });
    }

    /// HashReference strategy, payload OVER the inline threshold: the
    /// full payload goes to CAS; the event + projection carry the
    /// handler-extracted summary plus a `Some(hash)` reference to the
    /// blob. Two storage puts total — artifact content AND metadata blob.
    #[test]
    fn ingest_hash_reference_over_threshold_splits_payload() {
        let repo = pypi_repository();
        let repo_id = repo.id;

        // Payload comfortably over the 128-byte threshold below.
        let payload = serde_json::json!({ "pad": "a".repeat(500) });
        let serialised = serde_json::to_vec(&payload).unwrap();
        let expected_hash: ContentHash = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&serialised))
                .parse()
                .unwrap()
        };

        let summary = serde_json::json!({ "pad-summary": "x" });

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, storage, repos) = make_use_case();
            repos.insert(repo);

            let handler = StubFormatHandler::new("pypi")
                .with_max_bytes(10 * 1024 * 1024)
                .with_strategy(MetadataStrategy::HashReference {
                    inline_threshold_bytes: 128,
                })
                .with_summary(summary.clone());

            uc.ingest_direct(
                DirectIngestRequest {
                    payload_metadata: payload.clone(),
                    ..req(repo_id)
                },
                content_stream(b"payload"),
                &handler,
            )
            .await
            .expect("over-threshold ingest must succeed");

            // Two puts — artifact content AND the metadata blob.
            assert_eq!(
                storage.put_call_count(),
                2,
                "HashReference split must write metadata blob to CAS"
            );
            // The metadata blob's hash is present in the storage mock —
            // proves the `put` received the full serialised payload
            // (the mock hashes whatever bytes flow through).
            assert!(
                storage.stored_hashes().contains(&expected_hash),
                "expected blob hash {expected_hash} not found among {:?}",
                storage.stored_hashes()
            );

            let transitions = lifecycle.committed_transitions();
            assert_eq!(transitions.len(), 1);
            match &transitions[0].1.events[0].event {
                DomainEvent::ArtifactIngested(ev) => {
                    // Event carries the SUMMARY, not the full payload.
                    assert_eq!(ev.metadata, summary);
                    assert_eq!(ev.metadata_blob, Some(expected_hash.clone()));
                }
                other => panic!("expected ArtifactIngested, got: {other:?}"),
            }
            let md = transitions[0].2.as_ref().expect("metadata row present");
            assert_eq!(md.metadata, summary);
            assert_eq!(md.metadata_blob, Some(expected_hash));
        });
    }

    // -- content_references refcount writes -----------------------------------
    //
    // Every successful `ArtifactIngested` writes one `kind =
    // "primary_content"` row pointing at `artifact.sha256_checksum`.
    // HashReference-strategy ingests additionally write a
    // `kind = "metadata_blob"` row pointing at the metadata-blob hash.
    // Inline / under-threshold-HashReference paths write only the
    // primary_content row.

    /// `ingest_direct` always writes a `primary_content` refcount row
    /// pointing at `artifact.sha256_checksum`.
    #[test]
    fn ingest_direct_writes_primary_content_refcount() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, _storage, repos, content_refs) =
                make_use_case_with_content_refs(true);
            repos.insert(repo);

            uc.ingest_direct(
                req(repo_id),
                content_stream(b"hello-init27"),
                &test_handler(),
            )
            .await
            .expect("ingest_direct must succeed");

            assert_eq!(
                content_refs.entry_count(),
                1,
                "exactly one refcount row per ArtifactIngested when no metadata blob"
            );

            // Validate the row's shape: kind = "primary_content";
            // target = artifact.sha256_checksum.
            let transitions = lifecycle.committed_transitions();
            let artifact = &transitions[0].0;
            let rows = content_refs
                .find_by_target(repo_id, &artifact.sha256_checksum, Some("primary_content"))
                .await
                .unwrap();
            assert_eq!(rows.len(), 1, "exactly one primary_content row");
            assert_eq!(rows[0].source_artifact_id, artifact.id);
            assert_eq!(rows[0].kind, "primary_content");
            assert_eq!(rows[0].target_content_hash, artifact.sha256_checksum);
            assert_eq!(rows[0].repository_id, repo_id);
        });
    }

    /// HashReference path with payload over the inline threshold writes
    /// TWO refcount rows: one `primary_content` pointing at the artifact
    /// content, one `metadata_blob` pointing at the metadata-blob hash.
    #[test]
    fn ingest_with_metadata_blob_writes_two_refcount_rows() {
        let repo = pypi_repository();
        let repo_id = repo.id;

        // Payload comfortably over the 128-byte threshold.
        let payload = serde_json::json!({ "pad": "a".repeat(500) });
        let serialised = serde_json::to_vec(&payload).unwrap();
        let expected_blob_hash: ContentHash = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&serialised))
                .parse()
                .unwrap()
        };
        let summary = serde_json::json!({ "pad-summary": "x" });

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, _storage, repos, content_refs) =
                make_use_case_with_content_refs(true);
            repos.insert(repo);

            let handler = StubFormatHandler::new("pypi")
                .with_max_bytes(10 * 1024 * 1024)
                .with_strategy(MetadataStrategy::HashReference {
                    inline_threshold_bytes: 128,
                })
                .with_summary(summary);

            uc.ingest_direct(
                DirectIngestRequest {
                    payload_metadata: payload,
                    ..req(repo_id)
                },
                content_stream(b"split-payload"),
                &handler,
            )
            .await
            .expect("over-threshold ingest must succeed");

            assert_eq!(
                content_refs.entry_count(),
                2,
                "HashReference split must write two refcount rows: primary_content + metadata_blob"
            );

            let transitions = lifecycle.committed_transitions();
            let artifact = &transitions[0].0;

            let primary_rows = content_refs
                .find_by_target(repo_id, &artifact.sha256_checksum, Some("primary_content"))
                .await
                .unwrap();
            assert_eq!(primary_rows.len(), 1, "one primary_content row");
            assert_eq!(primary_rows[0].source_artifact_id, artifact.id);

            let blob_rows = content_refs
                .find_by_target(repo_id, &expected_blob_hash, Some("metadata_blob"))
                .await
                .unwrap();
            assert_eq!(blob_rows.len(), 1, "one metadata_blob row");
            assert_eq!(blob_rows[0].source_artifact_id, artifact.id);
            assert_eq!(blob_rows[0].kind, "metadata_blob");
            assert_eq!(blob_rows[0].target_content_hash, expected_blob_hash);
        });
    }

    /// Inline (or under-threshold HashReference) ingest writes ONLY the
    /// `primary_content` row — `final_blob` is `None`, so no
    /// `metadata_blob` row is written.
    #[test]
    fn ingest_with_inline_metadata_writes_only_primary_content() {
        let repo = pypi_repository();
        let repo_id = repo.id;

        // Inline strategy with a real (non-null) payload — the inline
        // path writes the payload verbatim into the event/projection
        // and the refcount writer must NOT additionally emit a
        // metadata_blob row.
        let payload = serde_json::json!({ "name": "small", "version": "1.0.0" });

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, _lifecycle, _storage, repos, content_refs) =
                make_use_case_with_content_refs(true);
            repos.insert(repo);

            // Default `test_handler()` declares MetadataStrategy::Inline,
            // so the resolved decision is Inline regardless of payload
            // size.
            uc.ingest_direct(
                DirectIngestRequest {
                    payload_metadata: payload,
                    ..req(repo_id)
                },
                content_stream(b"inline-payload"),
                &test_handler(),
            )
            .await
            .expect("inline ingest must succeed");

            assert_eq!(
                content_refs.entry_count(),
                1,
                "inline path writes exactly one refcount row (primary_content)"
            );
        });
    }

    /// HashReference over inline threshold AND over the blob safety cap:
    /// rejected before `storage.put`, `hort_ingest_total{result="metadata_too_large"}`
    /// increments directly (not via `classify_ingest_error`), and no
    /// lifecycle commit fires.
    #[test]
    fn ingest_hash_reference_over_blob_cap_is_rejected() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let repo_key = repo.key.clone();

        // 500-byte payload; blob cap set to 200 bytes (deliberately
        // lower than the 10 MB default to trigger the rejection).
        let payload = serde_json::json!({ "pad": "a".repeat(500) });

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, _artifacts, _events, lifecycle, storage, repos) =
                    make_use_case_with_caps_and_blob_max(true, HashMap::new(), 200);
                repos.insert(repo);

                let handler = StubFormatHandler::new("pypi")
                    .with_max_bytes(10 * 1024 * 1024)
                    .with_strategy(MetadataStrategy::HashReference {
                        inline_threshold_bytes: 128,
                    });

                let err = uc
                    .ingest_direct(
                        DirectIngestRequest {
                            payload_metadata: payload.clone(),
                            ..req(repo_id)
                        },
                        content_stream(b"payload"),
                        &handler,
                    )
                    .await
                    .expect_err("blob-cap-exceeding ingest must be rejected");

                // Validation-shaped error; terse message, never a byte
                // count or the payload itself.
                assert!(
                    matches!(err, AppError::Domain(DomainError::Validation(_))),
                    "expected Domain(Validation), got {err:?}"
                );

                // Load-bearing: zero storage puts (not content, not
                // metadata blob) and no lifecycle commit. Without these
                // assertions the test would pass vacuously on any Err.
                assert_eq!(
                    storage.put_call_count(),
                    0,
                    "blob-cap rejection must short-circuit before any storage put"
                );
                assert_eq!(
                    lifecycle.committed_transitions().len(),
                    0,
                    "no lifecycle commit on blob-cap rejection"
                );
            });
        });

        let entries = snap.into_vec();
        // The counter tick uses `metadata_too_large` — the same label as
        // the pre-dispatch cap, by design. Splitting the
        // cardinality further would bloat series without dashboard value.
        assert_counter(
            &entries,
            "hort_ingest_total",
            &[
                ("format", "pypi"),
                ("repository", repo_key.as_str()),
                ("result", "metadata_too_large"),
            ],
            1,
        );
        // Regression guard — if a future refactor routes the blob-cap
        // rejection through `classify_ingest_error`, `validation_error`
        // would tick instead and the metadata_too_large label would
        // silently never fire. This matches the pre-dispatch cap test.
        assert!(
            find_metric(
                &entries,
                MetricKind::Counter,
                "hort_ingest_total",
                &[
                    ("format", "pypi"),
                    ("repository", repo_key.as_str()),
                    ("result", "validation_error"),
                ],
            )
            .is_none(),
            "blob-cap rejection must NOT tick validation_error — \
             that would mean it flowed through classify_ingest_error"
        );
    }

    /// Blob cap set to 0 ("accept anything") allows a payload that
    /// would otherwise be rejected. This pins the documented escape
    /// hatch behaviour — useful for tests and for operators who want
    /// to bypass the blob ceiling, and ensures a future `> 0` guard
    /// addition doesn't silently change the zero semantics.
    #[test]
    fn ingest_hash_reference_with_zero_blob_cap_accepts_anything() {
        let repo = pypi_repository();
        let repo_id = repo.id;

        let payload = serde_json::json!({ "pad": "a".repeat(500) });

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, storage, repos) =
                make_use_case_with_caps_and_blob_max(true, HashMap::new(), 0);
            repos.insert(repo);

            let handler = StubFormatHandler::new("pypi")
                .with_max_bytes(10 * 1024 * 1024)
                .with_strategy(MetadataStrategy::HashReference {
                    inline_threshold_bytes: 128,
                });

            uc.ingest_direct(
                DirectIngestRequest {
                    payload_metadata: payload.clone(),
                    ..req(repo_id)
                },
                content_stream(b"payload"),
                &handler,
            )
            .await
            .expect("zero blob cap must accept any payload size");

            // Both puts ran — content and metadata blob.
            assert_eq!(storage.put_call_count(), 2);
            assert_eq!(lifecycle.committed_transitions().len(), 1);
        });
    }

    // -- hort_ingest_metadata_strategy_total ------------------------------------
    //
    // The split-rate counter. One label decision per ingest, decided at
    // dispatch and emitted AFTER a successful `commit_transition` so
    // failures do not tick the counter.
    //
    // Five assertions to cover the contract:
    //   1. Inline-format + real payload     → strategy=inline, count=1
    //   2. HashReference + split            → strategy=hash_reference
    //   3. HashReference under threshold    → strategy=inline (NOT
    //      hash_reference — the counter answers "did this ingest split?",
    //      not "does this format CAN split?")
    //   4. Inline + Value::Null payload     → counter does NOT fire
    //      (nothing to persist → nothing to observe)
    //   5. Failed ingest (storage error)    → counter does NOT fire

    /// Inline handler with a real payload: the counter ticks once with
    /// `strategy=inline`. `had_payload_metadata = true` lets the emission
    /// run; the strategy label reflects what was actually used.
    #[test]
    fn ingest_metadata_strategy_counter_fires_inline_for_inline_handler() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let repo_key = repo.key.clone();

        let payload = serde_json::json!({ "pkg_info": { "summary": "s" } });

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, _artifacts, _events, _lifecycle, _storage, repos) = make_use_case();
                repos.insert(repo);

                let handler = StubFormatHandler::new("pypi").with_max_bytes(10 * 1024 * 1024);
                assert_eq!(handler.metadata_strategy(), MetadataStrategy::Inline);

                uc.ingest_direct(
                    DirectIngestRequest {
                        payload_metadata: payload.clone(),
                        ..req(repo_id)
                    },
                    content_stream(b"payload"),
                    &handler,
                )
                .await
                .expect("inline ingest must succeed");
            });
        });

        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_ingest_metadata_strategy_total",
            &[("format", "pypi"), (labels::STRATEGY, "inline")],
            1,
        );
        // Parallel success tick on hort_ingest_total — the strategy counter
        // does not replace the existing ingest outcome counter, it sits
        // alongside it.
        assert_counter(
            &entries,
            "hort_ingest_total",
            &[
                ("format", "pypi"),
                ("repository", repo_key.as_str()),
                ("result", "success"),
            ],
            1,
        );
    }

    /// HashReference handler with a payload over the inline threshold:
    /// the counter ticks once with `strategy=hash_reference`. This is
    /// the only cell that should ever emit that label — all other
    /// cells emit `inline`.
    #[test]
    fn ingest_metadata_strategy_counter_fires_hash_reference_on_split() {
        let repo = pypi_repository();
        let repo_id = repo.id;

        let payload = serde_json::json!({ "pad": "a".repeat(500) });

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, _artifacts, _events, _lifecycle, _storage, repos) = make_use_case();
                repos.insert(repo);

                let handler = StubFormatHandler::new("pypi")
                    .with_max_bytes(10 * 1024 * 1024)
                    .with_strategy(MetadataStrategy::HashReference {
                        inline_threshold_bytes: 128,
                    })
                    .with_summary(serde_json::json!({ "pad-summary": "x" }));

                uc.ingest_direct(
                    DirectIngestRequest {
                        payload_metadata: payload.clone(),
                        ..req(repo_id)
                    },
                    content_stream(b"payload"),
                    &handler,
                )
                .await
                .expect("split ingest must succeed");
            });
        });

        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_ingest_metadata_strategy_total",
            &[("format", "pypi"), (labels::STRATEGY, "hash_reference")],
            1,
        );
        // And critically NOT the inline label — the dispatch must have
        // taken the HashReference branch.
        assert!(
            find_metric(
                &entries,
                MetricKind::Counter,
                "hort_ingest_metadata_strategy_total",
                &[("format", "pypi"), (labels::STRATEGY, "inline")],
            )
            .is_none(),
            "hash_reference split must not also tick strategy=inline"
        );
    }

    /// HashReference handler whose payload stayed under the threshold:
    /// NO split happened, so the counter ticks with `strategy=inline`
    /// — NOT `hash_reference`. The label tracks what actually occurred,
    /// not what the format CAN do. If this test ever flips to
    /// `hash_reference`, the split-rate dashboard would over-count and
    /// operators would think npm was spilling to CAS far more often
    /// than reality.
    #[test]
    fn ingest_metadata_strategy_counter_fires_inline_when_hash_reference_stays_inline() {
        let repo = pypi_repository();
        let repo_id = repo.id;

        // 100-byte payload under a 1 KB threshold — HashReference's
        // inline fallback path.
        let payload = serde_json::json!({ "pad": "a".repeat(100) });

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, _artifacts, _events, _lifecycle, _storage, repos) = make_use_case();
                repos.insert(repo);

                let handler = StubFormatHandler::new("pypi")
                    .with_max_bytes(10 * 1024 * 1024)
                    .with_strategy(MetadataStrategy::HashReference {
                        inline_threshold_bytes: 1024,
                    });

                uc.ingest_direct(
                    DirectIngestRequest {
                        payload_metadata: payload.clone(),
                        ..req(repo_id)
                    },
                    content_stream(b"payload"),
                    &handler,
                )
                .await
                .expect("under-threshold HashReference must succeed");
            });
        });

        let entries = snap.into_vec();
        // Load-bearing: label is `inline`, NOT `hash_reference`.
        assert_counter(
            &entries,
            "hort_ingest_metadata_strategy_total",
            &[("format", "pypi"), (labels::STRATEGY, "inline")],
            1,
        );
        assert!(
            find_metric(
                &entries,
                MetricKind::Counter,
                "hort_ingest_metadata_strategy_total",
                &[("format", "pypi"), (labels::STRATEGY, "hash_reference")],
            )
            .is_none(),
            "under-threshold HashReference must NOT tick hash_reference — the counter \
             answers 'did this ingest split?', not 'does this format declare split-capable?'"
        );
    }

    /// `payload_metadata = Value::Null` — the default for callers with
    /// nothing to persist (proxy fetches, handlers that have not been
    /// taught to extract). The strategy counter MUST NOT fire: the
    /// metric answers "how many ingests used each strategy to persist
    /// payload metadata", and there was no metadata to persist. This
    /// matches the `hort_ingest_total` success path — a null-metadata
    /// ingest is still a success, it just doesn't contribute to the
    /// strategy histogram.
    #[test]
    fn ingest_metadata_strategy_counter_does_not_fire_when_payload_is_null() {
        let repo = pypi_repository();
        let repo_id = repo.id;

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, _artifacts, _events, _lifecycle, _storage, repos) = make_use_case();
                repos.insert(repo);

                // req() defaults payload_metadata to Value::Null.
                uc.ingest_direct(
                    req(repo_id),
                    content_stream(b"no metadata"),
                    &test_handler(),
                )
                .await
                .expect("null-payload ingest must succeed");
            });
        });

        let entries = snap.into_vec();
        // Counter is entirely absent from the snapshot — not just
        // "present with zero", but no series emitted at all.
        assert_metric_absent(&entries, "hort_ingest_metadata_strategy_total");
    }

    /// Failed ingest: the storage port rejects the artifact-content put.
    /// The commit_transition never runs; the strategy counter therefore
    /// never ticks. Critical invariant — if a future refactor moved the
    /// emission to before commit_transition (e.g. to the tail metric
    /// block alongside hort_ingest_total), failed-but-attempted ingests
    /// would inflate the split-rate dashboard with no actual splits.
    #[test]
    fn ingest_metadata_strategy_counter_does_not_fire_on_failed_ingest() {
        let repo = pypi_repository();
        let repo_id = repo.id;

        let payload = serde_json::json!({ "pkg_info": { "summary": "s" } });

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let artifacts = Arc::new(MockArtifactRepository::new());
                let events = Arc::new(MockEventStore::new());
                let lifecycle = Arc::new(MockArtifactLifecycle::new(artifacts.clone()));
                let storage: Arc<dyn StoragePort> = Arc::new(FailingStoragePort);
                let repos = Arc::new(MockRepositoryRepository::new());
                let groups = Arc::new(MockArtifactGroupRepository::new());
                let group_lifecycle = Arc::new(MockArtifactGroupLifecyclePort::new(groups.clone()));
                let group_use_case =
                    Arc::new(ArtifactGroupUseCase::new(groups, group_lifecycle, true));
                let curation_rules = Arc::new(MockCurationRuleRepository::new());
                let content_references = Arc::new(MockContentReferenceIndex::new());

                // Permissive global policy seed
                // (storage-failure test; permissive keeps the inline
                // test consistent with the centralised helpers).
                let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
                seed_permissive_global_policy(&policy_projections);
                let jobs = Arc::new(MockJobsRepository::default());
                let uc = IngestUseCase::new(
                    storage,
                    lifecycle,
                    artifacts,
                    repos.clone(),
                    crate::event_store_publisher::wrap_for_test(events),
                    curation_rules,
                    group_use_case,
                    true,
                    HashMap::new(),
                    0,
                    content_references,
                    policy_projections,
                    jobs,
                );
                repos.insert(repo);

                let err = uc
                    .ingest_direct(
                        DirectIngestRequest {
                            payload_metadata: payload.clone(),
                            ..req(repo_id)
                        },
                        content_stream(b"anything"),
                        &test_handler(),
                    )
                    .await
                    .expect_err("storage-failing port must produce Err");
                // Sanity: the failure IS a storage error, not something
                // that short-circuited before `put`.
                assert!(matches!(err, AppError::Storage(_)), "got: {err:?}");
            });
        });

        let entries = snap.into_vec();
        // Load-bearing: no strategy counter tick. The success-adjacent
        // counter (`hort_ingest_total{result="storage_error"}`) still
        // ticks — that's the tail-block emission, which is unrelated
        // to the strategy counter.
        assert_metric_absent(&entries, "hort_ingest_metadata_strategy_total");
    }

    // -- blob-orphan regression ------------------------------------------------
    //
    // The blob's `storage.put` MUST be deferred until after both dedup
    // checks have cleared. A duplicate re-publish with a field-reshuffled
    // metadata body (byte-different JSON → CAS dedup misses) would
    // otherwise orphan a fresh blob. See `MetadataDecision` docstring.
    // These two tests guard both dedup short-circuits — via
    // `declared_sha256` (pre-put) and via the post-put path hash.

    // The declared-hash dedup test
    // (`ingest_hash_reference_duplicate_via_declared_sha256_does_not_put_blob`)
    // moved to `ingest_verified` — its semantics belong on the
    // verification path, not the direct-upload path.

    /// Post-put dedup: no declared hash supplied, so the tarball IS
    /// put (that's how this dedup branch discovers the match), but
    /// the metadata blob MUST NOT be put — its write is deferred to
    /// after this check. `put_call_count == 1` (only the tarball),
    /// not 2.
    #[test]
    fn ingest_hash_reference_duplicate_via_post_put_does_not_put_blob() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let content: &[u8] = b"hello world";
        let hash_hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(content))
        };

        let payload = serde_json::json!({ "pad": "a".repeat(4096) });

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, artifacts, _events, _lifecycle, storage, repos) = make_use_case();
            repos.insert(repo);
            let existing = insert_existing_artifact(&artifacts, repo_id, &hash_hex);

            let handler = StubFormatHandler::new("pypi")
                .with_max_bytes(10 * 1024 * 1024)
                .with_strategy(MetadataStrategy::HashReference {
                    inline_threshold_bytes: 1024,
                })
                .with_summary(serde_json::json!({ "pad-summary": "x" }));

            let returned = uc
                .ingest_direct(
                    DirectIngestRequest {
                        // No declared_sha256 — forces the post-put path.
                        payload_metadata: payload,
                        ..req(repo_id)
                    },
                    content_stream(content),
                    &handler,
                )
                .await
                .expect("post-put dedup must succeed")
                .artifact;

            assert_eq!(returned.id, existing.id);

            // Load-bearing: ONLY the tarball was put (the post-put
            // dedup branch requires that to discover the match). The
            // metadata blob was never put, because its write is
            // deferred to AFTER this check. A regression that
            // re-introduces the pre-dedup blob put would make this 2.
            assert_eq!(
                storage.put_call_count(),
                1,
                "post-put dedup must keep blob put deferred — only tarball put, not blob"
            );
        });
    }

    // -----------------------------------------------------------------
    // post-commit group-membership hook
    // -----------------------------------------------------------------
    //
    // Acceptance:
    // - default `None` handler emits NO group events (regression guard);
    // - stub-`Some` handler triggers the expected
    //   ArtifactGroupInitiated + ArtifactGroupMemberAdded commit with
    //   the ingest's correlation_id and `Some(<ArtifactIngested event_id>)`
    //   as causation;
    //   atomicity-boundary rule: a failing group commit must NOT take
    //   the ingest down — the artifact IS persisted and `ingest` returns
    //   Ok (the unlinked artifact is healed by the group-reconcile sweep).
    //
    // These tests deliberately use `make_use_case_with_group_lifecycle`
    // so they can inspect / inject on the mock group port alongside the
    // artifact lifecycle port.

    fn group_coords() -> ArtifactCoords {
        // Canonical group coords per the `GroupMembership` docstring:
        // only identity fields populated; `path` empty, `metadata`
        // Null.  A divergence here (e.g. a non-empty `path`) would
        // create duplicate groups in the registry.
        ArtifactCoords {
            name: "my-package".into(),
            name_as_published: "My_Package".into(),
            version: Some("1.0.0".into()),
            path: String::new(),
            format: RepositoryFormat::Pypi,
            metadata: serde_json::Value::Null,
        }
    }

    #[tokio::test]
    async fn ingest_with_none_handler_emits_no_group_events() {
        // Default `classify_group_member` returns `None` — the hook
        // MUST short-circuit and never call the group port. Regression
        // guard against an accidental default-override.
        let repo = pypi_repository();
        let repo_id = repo.id;

        let (uc, _artifacts, _events, _lifecycle, _storage, repos, group_lifecycle) =
            make_use_case_with_group_lifecycle(true, HashMap::new(), 0);
        repos.insert(repo);

        // StubFormatHandler without `.with_group_membership(...)` —
        // the stub inherits the trait-level `None` default.
        let handler = StubFormatHandler::new("pypi").with_max_bytes(10 * 1024 * 1024);

        uc.ingest_direct(req(repo_id), content_stream(b"hello"), &handler)
            .await
            .unwrap();

        assert_eq!(
            group_lifecycle.commit_call_count(),
            0,
            "None classification must not invoke the group port"
        );
        assert!(group_lifecycle.recorded_commits().is_empty());
    }

    #[tokio::test]
    async fn ingest_with_some_handler_triggers_group_commit_with_correlation_and_causation() {
        // Stub returns `Some(GroupMembership { is_primary: true, ... })`
        // — the ingest hook routes through `ArtifactGroupUseCase::add_member`,
        // which on a fresh group emits `ArtifactGroupInitiated +
        // ArtifactGroupMemberAdded` inside the same lifecycle call.
        let repo = pypi_repository();
        let repo_id = repo.id;

        let (uc, _artifacts, _events, lifecycle, _storage, repos, group_lifecycle) =
            make_use_case_with_group_lifecycle(true, HashMap::new(), 0);
        repos.insert(repo);

        let handler = StubFormatHandler::new("pypi")
            .with_max_bytes(10 * 1024 * 1024)
            .with_group_membership(GroupMembership {
                group_coords: group_coords(),
                role: "sdist".into(),
                is_primary: true,
            });

        uc.ingest_direct(req(repo_id), content_stream(b"hello"), &handler)
            .await
            .unwrap();

        // Exactly ONE group commit on the happy path.
        assert_eq!(group_lifecycle.commit_call_count(), 1);
        let commits = group_lifecycle.recorded_commits();
        assert_eq!(commits.len(), 1);
        let c = &commits[0];

        // First-placement: new_group_id present, Initiated + MemberAdded fire.
        assert!(
            c.new_group_id.is_some(),
            "first add_member to a fresh group must initiate"
        );
        assert_eq!(c.member_role, "sdist");
        // Two events: Initiated then MemberAdded.
        assert_eq!(c.batch.events.len(), 2);
        assert!(matches!(
            c.batch.events[0].event,
            DomainEvent::ArtifactGroupInitiated(_)
        ));
        assert!(matches!(
            c.batch.events[1].event,
            DomainEvent::ArtifactGroupMemberAdded(_)
        ));
        // Stream id targets the ArtifactGroup aggregate.
        assert_eq!(c.batch.stream_id.category, StreamCategory::ArtifactGroup);

        // Causation chain: the group commit's `causation_id` MUST equal
        // the caller-supplied `event_id` of the persisted
        // `ArtifactIngested` event. Since the adapter binds
        // `EventToAppend::event_id` verbatim, that id is what lands in
        // `events.event_id` — so the chain now resolves. Previously the
        // use case minted a separate placeholder UUID and the chain
        // dangled; this assertion is the regression guard.
        let ingest_transitions = lifecycle.committed_transitions();
        assert_eq!(ingest_transitions.len(), 1);
        let ingest_batch = &ingest_transitions[0].1;
        assert_eq!(
            c.batch.correlation_id, ingest_batch.correlation_id,
            "group commit and ArtifactIngested must share correlation_id"
        );
        let causation = c
            .batch
            .causation_id
            .expect("causation_id must be Some(<ArtifactIngested event id>)");
        assert_ne!(causation, Uuid::nil());
        assert_ne!(
            causation, ingest_batch.correlation_id,
            "causation_id is the ArtifactIngested event id, NOT the correlation_id"
        );
        // Two events in the ingest batch: ArtifactIngested then
        // ScanRequested (DefaultPolicy fallback). The
        // causation chain still anchors on events[0] = ArtifactIngested.
        assert_eq!(ingest_batch.events.len(), 2);
        assert!(matches!(
            ingest_batch.events[0].event,
            DomainEvent::ArtifactIngested(_)
        ));
        assert_eq!(
            causation, ingest_batch.events[0].event_id,
            "causation_id must equal the ArtifactIngested EventToAppend::event_id"
        );
    }

    #[tokio::test]
    async fn ingest_continues_when_group_commit_fails() {
        // Atomicity-boundary rule: if the group commit fails AFTER
        // `ArtifactIngested` has landed, `ingest` still returns `Ok` —
        // the artifact is valid, just unlinked. The group-reconcile sweep
        // heals orphans at rest.
        let repo = pypi_repository();
        let repo_id = repo.id;

        let (uc, _artifacts, _events, lifecycle, _storage, repos, group_lifecycle) =
            make_use_case_with_group_lifecycle(true, HashMap::new(), 0);
        repos.insert(repo);
        // Inject a Conflict on the first (and only) group commit call
        // — simulates a primary-role-race loss or any adapter-side
        // Conflict surfaced as `Err(DomainError::Conflict)`.
        group_lifecycle.inject(GroupCommitInjection::Conflict {
            reason: "simulated group commit failure".into(),
        });

        let handler = StubFormatHandler::new("pypi")
            .with_max_bytes(10 * 1024 * 1024)
            .with_group_membership(GroupMembership {
                group_coords: group_coords(),
                role: "sdist".into(),
                is_primary: true,
            });

        let artifact = uc
            .ingest_direct(req(repo_id), content_stream(b"hello"), &handler)
            .await
            .expect("ingest must return Ok even when group commit fails")
            .artifact;

        // ArtifactIngested landed.
        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        assert_eq!(transitions[0].0.id, artifact.id);
        assert!(matches!(
            transitions[0].1.events[0].event,
            DomainEvent::ArtifactIngested(_)
        ));

        // The group port was consulted (attempted commit) but the
        // injection short-circuited before any recorded commit — so
        // `recorded_commits` is empty AND `commit_call_count` is 1.
        assert_eq!(group_lifecycle.commit_call_count(), 1);
        assert!(group_lifecycle.recorded_commits().is_empty());
    }

    // -----------------------------------------------------------------
    // register_by_hash
    // -----------------------------------------------------------------

    /// Valid SHA-256 hex — all-zero is accepted by the validator (64
    /// lowercase hex chars). Used by tests that only care about the
    /// `ContentHash` wrapper, not the underlying bytes.
    const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    /// A second distinct valid SHA-256 hex — the `empty string` hash.
    /// Used alongside [`ZERO_HASH`] when a test needs two mutually
    /// non-matching hashes.
    const EMPTY_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// Insert an artifact in `src_repo_id` with sha256 = `hash_hex` so
    /// `find_by_checksum(hash)` returns `Some(artifact)` whose
    /// `repository_id == src_repo_id`. Used by the `Some(src)` branch
    /// tests to set up source repos.
    fn seed_source_artifact(
        artifacts: &MockArtifactRepository,
        src_repo_id: Uuid,
        hash_hex: &str,
        size_bytes: i64,
    ) -> Artifact {
        let mut a = sample_artifact(QuarantineStatus::None);
        a.repository_id = src_repo_id;
        a.sha256_checksum = hash_hex.parse().unwrap();
        a.size_bytes = size_bytes;
        artifacts.insert(a.clone());
        a
    }

    /// Happy-path: `source_repo = Some(src)` with the source artifact
    /// present in `src` — the method emits `ArtifactIngested` for the
    /// target, propagates the existing size, and labels the metric
    /// `registered_by_hash`.
    #[test]
    fn register_by_hash_some_src_happy_path() {
        let target = pypi_repository();
        let target_id = target.id;
        let target_key = target.key.clone();
        let src_id = Uuid::new_v4();
        let hash: ContentHash = EMPTY_HASH.parse().unwrap();

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, artifacts, _events, lifecycle, _storage, repos) = make_use_case();
                repos.insert(target);
                let src = seed_source_artifact(&artifacts, src_id, EMPTY_HASH, 4242);

                let payload = serde_json::json!({"oci_media_type": "application/vnd.oci.image.manifest.v1+json"});
                let outcome = uc
                    .register_by_hash(
                        IngestRequest {
                            payload_metadata: payload.clone(),
                            ..req_legacy(target_id)
                        },
                        hash.clone(),
                        Some(src_id),
                        &test_handler(),
                    )
                    .await
                    .expect("Some(src) with matching source artifact must succeed");

                // Artifact is new (distinct id from source), scoped to
                // target, carries the source's hash + size.
                assert_ne!(outcome.artifact.id, src.id);
                assert_eq!(outcome.artifact.repository_id, target_id);
                assert_eq!(outcome.artifact.sha256_checksum, hash);
                assert_eq!(outcome.artifact.size_bytes, 4242);

                // Exactly one transition — the ArtifactIngested event.
                // `ingested_event_id` equals the id on the event actually
                // committed (same contract as `ingest`).
                let transitions = lifecycle.committed_transitions();
                assert_eq!(transitions.len(), 1);
                let appended = &transitions[0].1.events[0];
                assert!(matches!(appended.event, DomainEvent::ArtifactIngested(_)));
                assert_eq!(outcome.ingested_event_id, appended.event_id);

                // Metadata round-trips onto the event (and the 1:1
                // projection row handed to the lifecycle port).
                match &appended.event {
                    DomainEvent::ArtifactIngested(ev) => {
                        assert_eq!(ev.metadata, payload);
                        assert_eq!(ev.sha256, hash);
                        assert_eq!(ev.size_bytes, 4242);
                        // Source labelled Direct — the caller is
                        // explicit about using this for cross-mount
                        // style registrations, not proxy fetches.
                        assert!(matches!(ev.source, IngestSource::Direct));
                    }
                    other => panic!("expected ArtifactIngested, got {other:?}"),
                }
                assert_eq!(
                    transitions[0].2.as_ref().unwrap().metadata,
                    payload
                );
            });
        });

        // Metric labelled `registered_by_hash` — the new catalog value.
        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_ingest_total",
            &[
                ("format", "pypi"),
                ("repository", target_key.as_str()),
                ("result", "registered_by_hash"),
            ],
            1,
        );
    }

    /// `source_repo = Some(src)` but `find_by_checksum` returns an
    /// artifact whose `repository_id != src` — the scoping rule must
    /// reject with `NotFound`. This is the OCI cross-mount authz
    /// invariant: the client cannot mount a blob it doesn't own in the
    /// declared `from` repo.
    #[test]
    fn register_by_hash_some_src_foreign_repo_returns_not_found() {
        let target = pypi_repository();
        let target_id = target.id;
        let declared_src_id = Uuid::new_v4();
        let actual_owner_id = Uuid::new_v4();
        assert_ne!(declared_src_id, actual_owner_id);

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, artifacts, _events, lifecycle, _storage, repos) = make_use_case();
            repos.insert(target);

            // The artifact exists — but in a DIFFERENT repo than what
            // the caller declared in `source_repo`.
            let _unrelated = seed_source_artifact(&artifacts, actual_owner_id, EMPTY_HASH, 10);

            let hash: ContentHash = EMPTY_HASH.parse().unwrap();
            let err = uc
                .register_by_hash(
                    req_legacy(target_id),
                    hash,
                    Some(declared_src_id),
                    &test_handler(),
                )
                .await
                .expect_err("foreign-repo source must be rejected");

            assert!(
                matches!(
                    err,
                    AppError::Domain(DomainError::NotFound {
                        entity: "Artifact",
                        ..
                    })
                ),
                "expected NotFound(Artifact), got {err:?}"
            );
            // No event committed — the rejection happens before any
            // lifecycle port call.
            assert!(lifecycle.committed_transitions().is_empty());
        });
    }

    /// `source_repo = None` and `storage.exists(hash) == true` — the
    /// method succeeds without consulting `find_by_checksum`'s authz
    /// assertion. Primary use case: Phase 4 proxy-fetch promotion, where
    /// the caller has already done authz.
    #[test]
    fn register_by_hash_none_with_exists_succeeds() {
        let target = pypi_repository();
        let target_id = target.id;
        let hash: ContentHash = ZERO_HASH.parse().unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, storage, repos) = make_use_case();
            repos.insert(target);
            // Storage has the bytes — exists() returns true. Note we do
            // NOT insert an Artifact row anywhere; the `None` branch
            // does not depend on an existing projection row.
            storage.insert_content(hash.clone(), b"blob bytes".to_vec());

            let outcome = uc
                .register_by_hash(req_legacy(target_id), hash.clone(), None, &test_handler())
                .await
                .expect("None + storage.exists == true must succeed");

            assert_eq!(outcome.artifact.sha256_checksum, hash);
            assert_eq!(outcome.artifact.repository_id, target_id);

            let transitions = lifecycle.committed_transitions();
            assert_eq!(transitions.len(), 1);
            assert!(matches!(
                transitions[0].1.events[0].event,
                DomainEvent::ArtifactIngested(_)
            ));
        });
    }

    /// `source_repo = None` and `storage.exists(hash) == false` — the
    /// method must reject with `NotFound(ContentHash)`. Prevents the
    /// caller from creating an artifact row that points at a hash the
    /// CAS has never seen.
    #[test]
    fn register_by_hash_none_without_exists_returns_not_found() {
        let target = pypi_repository();
        let target_id = target.id;
        let hash: ContentHash = ZERO_HASH.parse().unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, _storage, repos) = make_use_case();
            repos.insert(target);
            // storage.insert_content is NOT called — exists() returns false.

            let err = uc
                .register_by_hash(req_legacy(target_id), hash, None, &test_handler())
                .await
                .expect_err("None + storage.exists == false must fail");

            assert!(
                matches!(
                    err,
                    AppError::Domain(DomainError::NotFound {
                        entity: "ContentHash",
                        ..
                    })
                ),
                "expected NotFound(ContentHash), got {err:?}"
            );
            assert!(lifecycle.committed_transitions().is_empty());
        });
    }

    // -----------------------------------------------------------------
    // register_existing_cas_blob: the cross-repo post-coalesce
    // follower-registration primitive.
    // -----------------------------------------------------------------

    /// Cross-repo two-caller concurrency test.
    ///
    /// Models the scenario where a single upstream artifact is
    /// pulled concurrently into TWO different repositories sharing one
    /// `DedupKey::blob_by_hash` window.
    ///
    /// * The **leader** ingests into repo A — it ends up with a
    ///   repo-A artifact row and the bytes land in CAS.
    /// * The **follower** joined repo A's coalesce window from repo B.
    ///   It receives only the post-verification `content_hash`. Its
    ///   post-coalesce repo-scoped lookup
    ///   `find_in_repo_by_hash(repoB, hash)` returns `None` — there is
    ///   no repo-B row (the leader only minted repo A's).
    ///
    /// Previously the follower's site mapped that `None` to a hard
    /// `Internal` ("post-coalesce artifact lookup found no row") and
    /// the follower's pull failed closed. After the fix the follower calls
    /// [`IngestUseCase::register_existing_cas_blob`] and idempotently
    /// registers its OWN repo-B row pointing at the same CAS hash.
    ///
    /// Asserts: BOTH callers succeed; leader has its repo-A row;
    /// follower ends with a DISTINCT repo-B row (its own
    /// `repository_id`, a new `artifact.id`); both rows carry the same
    /// `sha256_checksum`; the follower path performs ZERO
    /// `storage.put` (content already CAS-present — the whole point).
    #[test]
    fn register_existing_cas_blob_cross_repo_two_caller_follower_gets_own_repo_row() {
        let repo_a = pypi_repository();
        let repo_a_id = repo_a.id;
        let repo_b = pypi_repository();
        let repo_b_id = repo_b.id;
        assert_ne!(repo_a_id, repo_b_id);
        let hash: ContentHash = ZERO_HASH.parse().unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, artifacts, _events, lifecycle, storage, repos) = make_use_case();
            repos.insert(repo_a);
            repos.insert(repo_b);

            // --- Leader: ingest into repo A. Bytes land in CAS, a
            //     repo-A artifact row exists. We model the leader's
            //     completed cross-repo dedup state directly (its own
            //     correctness is covered by the ingest_verified
            //     suite); this test is solely about the FOLLOWER path.
            storage.insert_content(hash.clone(), b"shared upstream bytes".to_vec());
            let mut leader_row = sample_artifact(QuarantineStatus::None);
            leader_row.repository_id = repo_a_id;
            leader_row.sha256_checksum = hash.clone();
            artifacts.insert(leader_row.clone());

            // Sanity: the leader's repo-scoped lookup hits its row;
            // the leader path is unchanged (no follower fallback).
            let leader_resolved = uc
                .register_existing_cas_blob(recb_req(repo_a_id, hash.clone()), &test_handler())
                .await
                .expect("leader: repo-A registration must succeed");
            assert_eq!(leader_resolved.artifact.repository_id, repo_a_id);
            assert_eq!(leader_resolved.artifact.sha256_checksum, hash);

            let put_before_follower = storage.put_call_count();

            // --- Follower: repo B, post-coalesce `None` (no repo-B
            //     row). The site now calls register_existing_cas_blob
            //     instead of erroring.
            let follower = uc
                .register_existing_cas_blob(recb_req(repo_b_id, hash.clone()), &test_handler())
                .await
                .expect(
                    "follower: cross-repo register_existing_cas_blob must succeed, not Internal",
                );

            // Follower owns a DISTINCT repo-B row pointing at the same
            // CAS hash.
            assert_eq!(follower.artifact.repository_id, repo_b_id);
            assert_ne!(
                follower.artifact.id, leader_row.id,
                "follower must mint its OWN row, not alias the leader's"
            );
            assert_eq!(
                follower.artifact.sha256_checksum, hash,
                "follower row must point at the same CAS content hash"
            );

            // The follower path NEVER re-`storage.put`s — the content
            // is already CAS-present (the key cross-repo dedup property).
            assert_eq!(
                storage.put_call_count(),
                put_before_follower,
                "follower registration must not call storage.put"
            );

            // Exactly one new commit for the follower's repo-B row —
            // the same ArtifactIngested event the leader's
            // non-concurrent cross-repo dedup emits.
            let transitions = lifecycle.committed_transitions();
            assert_eq!(
                transitions.len(),
                2,
                "one commit for the leader's resolve, one for the follower's repo-B mint"
            );
            assert!(matches!(
                transitions[1].1.events[0].event,
                DomainEvent::ArtifactIngested(_)
            ));
        });
    }

    /// Idempotent re-entry: a second (or Nth) follower in the SAME
    /// repo B — or a retry of the same follower after a lossy
    /// network — must NOT mint a second row or emit a second event.
    /// `register_existing_cas_blob` returns the already-registered
    /// row (delegates to `register_by_hash`'s same-path-same-hash
    /// dedup). Covers the concurrent-follower / retry arm.
    #[test]
    fn register_existing_cas_blob_is_idempotent_on_repeat() {
        let repo_b = pypi_repository();
        let repo_b_id = repo_b.id;
        let hash: ContentHash = ZERO_HASH.parse().unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, storage, repos) = make_use_case();
            repos.insert(repo_b);
            storage.insert_content(hash.clone(), b"shared upstream bytes".to_vec());

            let first = uc
                .register_existing_cas_blob(recb_req(repo_b_id, hash.clone()), &test_handler())
                .await
                .expect("first follower registration must succeed");

            let second = uc
                .register_existing_cas_blob(recb_req(repo_b_id, hash.clone()), &test_handler())
                .await
                .expect("second concurrent follower / retry must dedup, not fail");

            assert_eq!(
                first.artifact.id, second.artifact.id,
                "idempotent: same repo-B row returned, no second mint"
            );
            assert_eq!(
                lifecycle.committed_transitions().len(),
                1,
                "same-path-same-hash dedup must not emit a second commit"
            );
        });
    }

    /// Error path: content NOT present in CAS → `NotFound(ContentHash)`
    /// (delegated `register_by_hash` `None`-branch `storage.exists`
    /// guard). The follower must never create a row pointing at a
    /// hash the CAS has never seen — this is the fail-closed half of
    /// the cross-repo dedup fix that must be preserved.
    #[test]
    fn register_existing_cas_blob_missing_cas_content_is_not_found() {
        let repo_b = pypi_repository();
        let repo_b_id = repo_b.id;
        let hash: ContentHash = ZERO_HASH.parse().unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, _storage, repos) = make_use_case();
            repos.insert(repo_b);
            // storage.insert_content NOT called — exists() == false.

            let err = uc
                .register_existing_cas_blob(recb_req(repo_b_id, hash), &test_handler())
                .await
                .expect_err("CAS-absent content must fail closed");

            assert!(
                matches!(
                    err,
                    AppError::Domain(DomainError::NotFound {
                        entity: "ContentHash",
                        ..
                    })
                ),
                "expected NotFound(ContentHash), got {err:?}"
            );
            assert!(lifecycle.committed_transitions().is_empty());
        });
    }

    /// Error path: the target repo does not exist → the delegated
    /// `register_by_hash` surfaces the repository `NotFound` (mapped
    /// from `RegisterError::Other`). Confirms the new wrapper does
    /// not swallow the delegate's domain rejections.
    #[test]
    fn register_existing_cas_blob_unknown_repo_propagates_error() {
        let unknown_repo_id = Uuid::new_v4();
        let hash: ContentHash = ZERO_HASH.parse().unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, storage, _repos) = make_use_case();
            // Repo intentionally NOT inserted.
            storage.insert_content(hash.clone(), b"bytes".to_vec());

            let err = uc
                .register_existing_cas_blob(recb_req(unknown_repo_id, hash), &test_handler())
                .await
                .expect_err("unknown target repo must propagate the delegate error");

            assert!(
                matches!(err, AppError::Domain(_)),
                "expected a domain error from the delegate, got {err:?}"
            );
            assert!(lifecycle.committed_transitions().is_empty());
        });
    }

    /// Separate metadata round-trip regression test, structurally
    /// independent of the happy path so a change to the happy path's
    /// metadata handling cannot silently break this contract. The
    /// payload supplied on `IngestRequest` must land verbatim on BOTH
    /// the committed `ArtifactIngested` event AND the
    /// `ArtifactMetadata` projection row handed to the lifecycle port.
    #[test]
    fn register_by_hash_routes_metadata_to_event_and_lifecycle() {
        let target = pypi_repository();
        let target_id = target.id;
        let hash: ContentHash = EMPTY_HASH.parse().unwrap();

        let payload = serde_json::json!({
            "oci_media_type": "application/vnd.oci.image.layer.v1.tar+gzip",
            "oci_mount_from": "dockerhub-mirror",
        });

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, storage, repos) = make_use_case();
            repos.insert(target);
            storage.insert_content(hash.clone(), b"blob bytes".to_vec());

            let _outcome = uc
                .register_by_hash(
                    IngestRequest {
                        payload_metadata: payload.clone(),
                        ..req_legacy(target_id)
                    },
                    hash,
                    None,
                    &test_handler(),
                )
                .await
                .expect("metadata round-trip path must succeed");

            let transitions = lifecycle.committed_transitions();
            assert_eq!(transitions.len(), 1);

            // Event payload carries the exact JSON the caller supplied.
            match &transitions[0].1.events[0].event {
                DomainEvent::ArtifactIngested(ev) => {
                    assert_eq!(ev.metadata, payload);
                    // `metadata_blob` is never set by register_by_hash
                    // — there is no payload to split (no bytes stream).
                    assert!(ev.metadata_blob.is_none());
                }
                other => panic!("expected ArtifactIngested, got {other:?}"),
            }

            // Projection row carries the same payload verbatim.
            let metadata = transitions[0]
                .2
                .as_ref()
                .expect("lifecycle must receive ArtifactMetadata");
            assert_eq!(metadata.metadata, payload);
            assert!(metadata.metadata_blob.is_none());
        });
    }

    // -- register_by_hash hardening regressions --------------------------------
    //
    // Acceptance tests for the repo-scoped-lookup / metadata-cap / metric /
    // dedup / size-resolution hardening of `register_by_hash`. This block
    // drives them from the outside.

    /// `find_by_repo_and_checksum` is repo-scoped, so
    /// `register_by_hash(Some(src))` is not fooled when the same SHA-256
    /// lives on multiple rows across repositories. Seed TWO artifact
    /// rows with an identical hash (one owned by `src`, one owned by an
    /// unrelated repo), call `register_by_hash` with `Some(src_repo)`,
    /// and assert the `src`-owned row was used — via the committed
    /// artifact's `size_bytes` matching the `src` row's size (the
    /// unrelated row was seeded with a distinct size so this assertion
    /// cannot pass by accident). Prior `find_by_checksum` returned an
    /// arbitrary row; this test would fail against the earlier code
    /// whenever the "wrong" row sorted first in the adapter's response.
    #[test]
    fn register_by_hash_some_src_finds_correct_artifact_across_multi_repo_shared_hash() {
        let target = pypi_repository();
        let target_id = target.id;
        let src_id = Uuid::new_v4();
        let unrelated_id = Uuid::new_v4();
        assert_ne!(src_id, unrelated_id);
        let hash: ContentHash = EMPTY_HASH.parse().unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, artifacts, _events, lifecycle, _storage, repos) = make_use_case();
            repos.insert(target);

            // Seed the SAME hash in two repositories with DISTINCT
            // sizes. Prior `find_by_checksum(hash)` would return
            // whichever one happened to land first; the new
            // `find_by_repo_and_checksum(src, hash)` is unambiguous.
            let src_size = 777;
            let unrelated_size = 999;
            let src_artifact = seed_source_artifact(&artifacts, src_id, EMPTY_HASH, src_size);
            let _unrelated =
                seed_source_artifact(&artifacts, unrelated_id, EMPTY_HASH, unrelated_size);

            let outcome = uc
                .register_by_hash(
                    req_legacy(target_id),
                    hash.clone(),
                    Some(src_id),
                    &test_handler(),
                )
                .await
                .expect("Some(src) with matching src artifact must succeed");

            // The new artifact carries the SOURCE's size — not the
            // unrelated row's. Under the old unscoped `find_by_checksum`,
            // this could resolve to either size with non-deterministic
            // ordering.
            assert_eq!(
                outcome.artifact.size_bytes, src_size,
                "register_by_hash must use the SRC-owned row's size, not an unrelated repo's"
            );
            assert_ne!(
                outcome.artifact.size_bytes, unrelated_size,
                "register_by_hash resolved to the wrong row — repo-scoping broke"
            );
            assert_ne!(
                outcome.artifact.id, src_artifact.id,
                "new artifact is a fresh row"
            );

            let transitions = lifecycle.committed_transitions();
            assert_eq!(transitions.len(), 1);
        });
    }

    /// `register_by_hash` must enforce the per-format metadata cap
    /// the same way `ingest` does. Any OCI manifest PUT composing
    /// `register_by_hash` with an oversized `payload_metadata` would
    /// otherwise silently defeat the operator metadata caps.
    #[test]
    fn register_by_hash_rejects_oversized_payload_metadata() {
        let target = pypi_repository();
        let target_id = target.id;
        let target_key = target.key.clone();
        let hash: ContentHash = ZERO_HASH.parse().unwrap();

        // Pin the pypi cap low enough that a tiny JSON payload trips it.
        let mut caps = HashMap::new();
        caps.insert("pypi".to_string(), 5); // 5 bytes — anything non-trivial fails

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, _artifacts, _events, lifecycle, storage, repos) =
                    make_use_case_with_caps(true, caps);
                repos.insert(target);
                storage.insert_content(hash.clone(), b"bytes".to_vec());

                let big = serde_json::json!({"oci_media_type": "application/vnd.oci.image.manifest.v1+json"});
                let err = uc
                    .register_by_hash(
                        IngestRequest {
                            payload_metadata: big,
                            ..req_legacy(target_id)
                        },
                        hash,
                        None,
                        &test_handler(),
                    )
                    .await
                    .expect_err("oversized payload_metadata must be rejected");

                assert!(
                    matches!(err, AppError::Domain(DomainError::Validation(ref m)) if m.contains("metadata exceeds configured cap")),
                    "expected metadata-cap Validation error, got {err:?}"
                );

                // No commit_transition — cap rejection runs before any
                // storage or event work.
                assert!(
                    lifecycle.committed_transitions().is_empty(),
                    "cap rejection must short-circuit before lifecycle commit"
                );
            });
        });

        // Metric tie-in: metric emission must carry the
        // `metadata_too_large` label, not `validation_error`.
        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_ingest_total",
            &[
                ("format", "pypi"),
                ("repository", target_key.as_str()),
                ("result", "metadata_too_large"),
            ],
            1,
        );
    }

    /// Foreign-repo `Some(src)` rejections must emit
    /// `hort_ingest_total` with a classified error label. Under the
    /// pre-fix code the counter was never incremented on this path, so
    /// dashboards would miss every cross-mount authz failure.
    #[test]
    fn register_by_hash_emits_not_found_on_foreign_repo_src() {
        let target = pypi_repository();
        let target_id = target.id;
        let target_key = target.key.clone();
        let declared_src_id = Uuid::new_v4();
        let actual_owner_id = Uuid::new_v4();
        assert_ne!(declared_src_id, actual_owner_id);

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, artifacts, _events, _lifecycle, _storage, repos) = make_use_case();
                repos.insert(target);
                let _unrelated = seed_source_artifact(&artifacts, actual_owner_id, EMPTY_HASH, 10);

                let hash: ContentHash = EMPTY_HASH.parse().unwrap();
                let _ = uc
                    .register_by_hash(
                        req_legacy(target_id),
                        hash,
                        Some(declared_src_id),
                        &test_handler(),
                    )
                    .await;
            });
        });

        let entries = snap.into_vec();
        // `DomainError::NotFound { entity: "Artifact", .. }` falls
        // through `classify_ingest_error` to `ValidationError` — that's
        // the existing taxonomy and the established pattern for non-
        // `Repository` NotFound variants (see `classify_other_not_
        // found_falls_through_to_validation_error`). The point of the
        // test is that the counter fires AT ALL on the failure exit.
        assert_counter(
            &entries,
            "hort_ingest_total",
            &[
                ("format", "pypi"),
                ("repository", target_key.as_str()),
                ("result", "validation_error"),
            ],
            1,
        );
        // duration histogram fires on failure paths too.
        assert_histogram_has_sample(
            &entries,
            "hort_ingest_duration_seconds",
            &[("format", "pypi")],
        );
    }

    /// Pin that `register_by_hash` emits `metadata_too_large` on the
    /// cap-miss path. Structurally independent of the cap-rejection test;
    /// this one is the metric-emission regression witness.
    #[test]
    fn register_by_hash_emits_metadata_too_large_on_cap_violation() {
        let target = pypi_repository();
        let target_id = target.id;
        let target_key = target.key.clone();
        let hash: ContentHash = ZERO_HASH.parse().unwrap();

        let mut caps = HashMap::new();
        caps.insert("pypi".to_string(), 4);

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, _artifacts, _events, _lifecycle, _storage, repos) =
                    make_use_case_with_caps(true, caps);
                repos.insert(target);

                let payload = serde_json::json!({"k": "oversized-for-cap-4"});
                let _ = uc
                    .register_by_hash(
                        IngestRequest {
                            payload_metadata: payload,
                            ..req_legacy(target_id)
                        },
                        hash,
                        None,
                        &test_handler(),
                    )
                    .await;
            });
        });

        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_ingest_total",
            &[
                ("format", "pypi"),
                ("repository", target_key.as_str()),
                ("result", "metadata_too_large"),
            ],
            1,
        );
    }

    /// Infrastructure failure on `lifecycle.commit_transition` must still
    /// tick `hort_ingest_total`. Seeded via the
    /// `MockArtifactLifecycle::fail_next_commit` injection shim so the test
    /// exercises the actual error-path metric emission.
    #[test]
    fn register_by_hash_emits_internal_on_lifecycle_failure() {
        let target = pypi_repository();
        let target_id = target.id;
        let target_key = target.key.clone();
        let hash: ContentHash = ZERO_HASH.parse().unwrap();

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, _artifacts, _events, lifecycle, storage, repos) = make_use_case();
                repos.insert(target);
                storage.insert_content(hash.clone(), b"blob bytes".to_vec());

                // Seed a single failure on the next commit. Any error
                // variant is fine — the point is the outer METRIC path,
                // not the classifier's mapping, which has its own
                // dedicated unit tests further up this module.
                lifecycle
                    .fail_next_commit(DomainError::Invariant("simulated commit failure".into()));

                let err = uc
                    .register_by_hash(req_legacy(target_id), hash, None, &test_handler())
                    .await
                    .expect_err("lifecycle failure must propagate");
                assert!(
                    err.to_string().contains("simulated commit failure"),
                    "unexpected error: {err}"
                );
            });
        });

        let entries = snap.into_vec();
        // `DomainError::Invariant` falls through `classify_ingest_error`
        // to `ValidationError` (see `classify_invariant_falls_through_
        // to_validation_error`). The taxonomy is deliberately reused —
        // no new `internal` label is introduced on the catalog; the
        // assertion here is that the counter fires at all.
        assert_counter(
            &entries,
            "hort_ingest_total",
            &[
                ("format", "pypi"),
                ("repository", target_key.as_str()),
                ("result", "validation_error"),
            ],
            1,
        );
        assert_histogram_has_sample(
            &entries,
            "hort_ingest_duration_seconds",
            &[("format", "pypi")],
        );
    }

    /// Pin the duration histogram emission on the happy path so a future
    /// refactor removing the histogram call fails loudly.
    #[test]
    fn register_by_hash_records_duration_histogram_on_success() {
        let target = pypi_repository();
        let target_id = target.id;
        let hash: ContentHash = ZERO_HASH.parse().unwrap();

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, _artifacts, _events, _lifecycle, storage, repos) = make_use_case();
                repos.insert(target);
                storage.insert_content(hash.clone(), b"x".to_vec());

                uc.register_by_hash(req_legacy(target_id), hash, None, &test_handler())
                    .await
                    .expect("happy path succeeds");
            });
        });
        let entries = snap.into_vec();
        assert_histogram_has_sample(
            &entries,
            "hort_ingest_duration_seconds",
            &[("format", "pypi")],
        );
        // And the size histogram — to match `ingest`'s metric coverage.
        assert_histogram_has_sample(&entries, "hort_ingest_size_bytes", &[("format", "pypi")]);
    }

    /// Pin the "no re-streaming" property of `register_by_hash` with a
    /// direct `put_call_count() == 0` assertion on both success branches.
    /// A future refactor that accidentally adds a `storage.put` call would
    /// fail this test; the existing behavioural assertions would silently
    /// accept the regression.
    #[test]
    fn register_by_hash_some_src_happy_path_never_calls_storage_put() {
        let target = pypi_repository();
        let target_id = target.id;
        let src_id = Uuid::new_v4();
        let hash: ContentHash = EMPTY_HASH.parse().unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, artifacts, _events, _lifecycle, storage, repos) = make_use_case();
            repos.insert(target);
            let _src = seed_source_artifact(&artifacts, src_id, EMPTY_HASH, 4242);

            let _ = uc
                .register_by_hash(req_legacy(target_id), hash, Some(src_id), &test_handler())
                .await
                .expect("Some(src) happy path");

            assert_eq!(
                storage.put_call_count(),
                0,
                "register_by_hash must never call storage.put — load-bearing no-re-streaming property"
            );
        });
    }

    /// Same assertion for the `None` branch. The `storage.exists(&hash)`
    /// check must NOT promote itself to a `put` call regardless of what
    /// the stored bytes are.
    #[test]
    fn register_by_hash_none_with_exists_never_calls_storage_put() {
        let target = pypi_repository();
        let target_id = target.id;
        let hash: ContentHash = ZERO_HASH.parse().unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, _lifecycle, storage, repos) = make_use_case();
            repos.insert(target);
            storage.insert_content(hash.clone(), b"bytes".to_vec());
            // Reset any put count accumulated by insert_content — it
            // doesn't go through `put`, but confirm by reading the
            // counter BEFORE the register_by_hash call.
            let before = storage.put_call_count();

            let _ = uc
                .register_by_hash(req_legacy(target_id), hash, None, &test_handler())
                .await
                .expect("None + exists happy path");

            assert_eq!(
                storage.put_call_count(),
                before,
                "register_by_hash must never call storage.put — None branch"
            );
        });
    }

    /// Two sequential `register_by_hash` calls with the same
    /// `(repository_id, coords.path, hash)` produce exactly ONE
    /// `commit_transition`; the second call returns the existing
    /// artifact's id. Prior code would emit a second `ArtifactIngested`
    /// for the same path — a fan-out that downstream projections and
    /// group-add composers are not prepared for.
    #[test]
    fn register_by_hash_is_idempotent_on_same_path_same_hash() {
        let target = pypi_repository();
        let target_id = target.id;
        let target_key = target.key.clone();
        let hash: ContentHash = ZERO_HASH.parse().unwrap();

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, _artifacts, _events, lifecycle, storage, repos) = make_use_case();
                repos.insert(target);
                storage.insert_content(hash.clone(), b"bytes".to_vec());

                let first = uc
                    .register_by_hash(req_legacy(target_id), hash.clone(), None, &test_handler())
                    .await
                    .expect("first call succeeds");

                let second = uc
                    .register_by_hash(req_legacy(target_id), hash.clone(), None, &test_handler())
                    .await
                    .expect("second call must dedup, not fail");

                // Same artifact row — idempotent on the aggregate id.
                assert_eq!(first.artifact.id, second.artifact.id);

                // Exactly ONE `ArtifactIngested` committed across both
                // calls — the dedup path short-circuits before the
                // lifecycle port.
                let transitions = lifecycle.committed_transitions();
                assert_eq!(
                    transitions.len(),
                    1,
                    "same-path-same-hash dedup must not emit a second commit"
                );
            });
        });

        // Metric side-check — first call is `registered_by_hash`,
        // second is `duplicate` (mirrors `ingest`'s dedup taxonomy).
        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_ingest_total",
            &[
                ("format", "pypi"),
                ("repository", target_key.as_str()),
                ("result", "registered_by_hash"),
            ],
            1,
        );
        assert_counter(
            &entries,
            "hort_ingest_total",
            &[
                ("format", "pypi"),
                ("repository", target_key.as_str()),
                ("result", "duplicate"),
            ],
            1,
        );
    }

    /// Same path, DIFFERENT hash → `DomainError::Conflict`.
    /// The `(repository_id, path)` UNIQUE constraint is honoured by
    /// the idempotence guard; a client mounting a fresh digest onto
    /// the same logical path must be told about the collision up front
    /// (before any authz or storage work) rather than failing at the
    /// database layer mid-commit.
    #[test]
    fn register_by_hash_rejects_same_path_different_hash() {
        let target = pypi_repository();
        let target_id = target.id;
        let first_hash: ContentHash = ZERO_HASH.parse().unwrap();
        let second_hash: ContentHash = EMPTY_HASH.parse().unwrap();
        assert_ne!(first_hash, second_hash);

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, storage, repos) = make_use_case();
            repos.insert(target);
            storage.insert_content(first_hash.clone(), b"first".to_vec());
            storage.insert_content(second_hash.clone(), b"second".to_vec());

            uc.register_by_hash(req_legacy(target_id), first_hash, None, &test_handler())
                .await
                .expect("first placement succeeds");

            let err = uc
                .register_by_hash(req_legacy(target_id), second_hash, None, &test_handler())
                .await
                .expect_err("different hash at same path must conflict");
            assert!(
                matches!(err, AppError::Domain(DomainError::Conflict(_))),
                "expected Conflict, got {err:?}"
            );

            // Only the first commit landed — the conflict rejection
            // did not emit a second event.
            assert_eq!(lifecycle.committed_transitions().len(), 1);
        });
    }

    /// The `None` branch uses the authoritative
    /// `storage.size_of(&hash)` result when no `Artifact` row
    /// references the hash yet (proxy/replication path). Prior
    /// code silently stored `0` via `.unwrap_or(0)` on a missing
    /// artifact row; this test seeds storage with a known byte count
    /// and asserts the committed artifact's `size_bytes` reflects it.
    #[test]
    fn register_by_hash_none_branch_uses_authoritative_size_from_storage() {
        let target = pypi_repository();
        let target_id = target.id;
        let hash: ContentHash = ZERO_HASH.parse().unwrap();
        let expected_size: usize = 37; // arbitrary non-zero, non-power-of-2

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, storage, repos) = make_use_case();
            repos.insert(target);
            // Seed storage at the synthetic `ZERO_HASH`. The mock
            // doesn't require the bytes to actually hash to that value;
            // the test is about `size_of` returning the stored length.
            storage.insert_content(hash.clone(), vec![0u8; expected_size]);

            let outcome = uc
                .register_by_hash(req_legacy(target_id), hash, None, &test_handler())
                .await
                .expect("None branch with stored bytes must succeed");

            assert_eq!(
                outcome.artifact.size_bytes, expected_size as i64,
                "register_by_hash must source size_bytes authoritatively from storage.size_of"
            );
            // Event payload carries the same authoritative size.
            let transitions = lifecycle.committed_transitions();
            assert_eq!(transitions.len(), 1);
            match &transitions[0].1.events[0].event {
                DomainEvent::ArtifactIngested(ev) => {
                    assert_eq!(ev.size_bytes, expected_size as i64);
                }
                other => panic!("expected ArtifactIngested, got {other:?}"),
            }
        });
    }

    /// `register_by_hash`
    /// (the OCI cross-repo blob mount path) writes one
    /// `kind = "primary_content"` row pointing at the artifact's
    /// `sha256_checksum`. No `metadata_blob` row — the path never
    /// splits (the bytes already live in CAS owned by the source
    /// repository). Mirrors `ingest_direct_writes_primary_content_refcount`
    /// in shape but exercises the `register_by_hash_inner` write site.
    #[test]
    fn register_by_hash_writes_primary_content_refcount() {
        let target = pypi_repository();
        let target_id = target.id;
        let target_key = target.key.clone();
        let _ = target_key; // metric assertion not needed here
        let hash: ContentHash = ZERO_HASH.parse().unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, storage, repos, content_refs) =
                make_use_case_with_content_refs(true);
            repos.insert(target);
            // None-source branch: storage has the bytes, exists() ==
            // true. The path that consumes the refcount writer.
            storage.insert_content(hash.clone(), b"already-in-cas".to_vec());

            let outcome = uc
                .register_by_hash(req_legacy(target_id), hash.clone(), None, &test_handler())
                .await
                .expect("register_by_hash None branch must succeed");

            // Exactly one refcount row: primary_content. The path
            // does NOT split metadata, so no metadata_blob row.
            assert_eq!(
                content_refs.entry_count(),
                1,
                "register_by_hash writes exactly one refcount row (primary_content)"
            );

            let transitions = lifecycle.committed_transitions();
            assert_eq!(transitions.len(), 1);
            let artifact = &transitions[0].0;

            let rows = content_refs
                .find_by_target(
                    target_id,
                    &artifact.sha256_checksum,
                    Some("primary_content"),
                )
                .await
                .unwrap();
            assert_eq!(rows.len(), 1, "exactly one primary_content row");
            assert_eq!(rows[0].source_artifact_id, artifact.id);
            assert_eq!(rows[0].kind, "primary_content");
            assert_eq!(rows[0].target_content_hash, hash);
            assert_eq!(rows[0].repository_id, target_id);

            // No metadata_blob row exists for this path.
            let blob_rows = content_refs
                .find_by_target(target_id, &artifact.sha256_checksum, Some("metadata_blob"))
                .await
                .unwrap();
            assert_eq!(
                blob_rows.len(),
                0,
                "register_by_hash never writes metadata_blob"
            );

            // Sanity: the outcome's artifact id matches the row's source.
            assert_eq!(outcome.artifact.id, artifact.id);
        });
    }

    // -- branch coverage for the refcount warn-on-fail arms

    /// Acceptance — coverage gap-fill for the warn-on-fail arm at
    /// `ingest_inner` `primary_content` insert. The refcount projection
    /// is post-commit eventual — when the
    /// projection write fails, the outer `ingest_direct` MUST still
    /// return `Ok` because the artifact is already persisted-and-valid
    /// and is downloadable. The test would fail if a future change
    /// aborts the ingest on insert-failure, which is the design choice
    /// this branch test is here to lock in.
    #[test]
    fn ingest_direct_primary_content_refcount_failure_is_warn_only() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, _storage, repos, content_refs) =
                make_use_case_with_content_refs(true);
            repos.insert(repo);

            // Arm a one-shot insert failure — this is the FIRST insert
            // call for the inline path (only `primary_content`; no
            // metadata blob), so the toggle hits exactly that arm.
            content_refs.fail_next_insert(DomainError::Invariant(
                "synthetic failure: primary_content insert".into(),
            ));

            // The ingest itself must still succeed: the artifact has
            // landed via `commit_transition` before the refcount write
            // is attempted. A future change that turned the warn into
            // an abort would flip this expectation and fail the test.
            uc.ingest_direct(
                req(repo_id),
                content_stream(b"hello-init27-warn-arm"),
                &test_handler(),
            )
            .await
            .expect("ingest_direct must succeed even when refcount insert fails");

            // The artifact transition committed (the rejection-on-fail
            // posture would have produced zero transitions).
            assert_eq!(
                lifecycle.committed_transitions().len(),
                1,
                "ArtifactIngested must still commit when refcount insert fails"
            );

            // No refcount row landed — the failed insert was warned
            // and skipped, not retried. The reconcile sweep
            // is the documented catch-up.
            assert_eq!(
                content_refs.entry_count(),
                0,
                "warn-on-fail must NOT write the row; reconcile is future work"
            );
        });
    }

    /// Acceptance — coverage gap-fill for the warn-on-fail arm at
    /// `ingest_inner` `metadata_blob` insert. Exercises the second
    /// insert call on the HashReference-strategy split path: the
    /// `primary_content` write succeeds, the `metadata_blob` write
    /// fails, and the outer ingest still returns `Ok`. After the
    /// dust settles the projection holds the `primary_content` row
    /// but NOT the `metadata_blob` row — exactly the drift the
    /// reconcile sweep is designed to repair.
    ///
    /// Uses the kind-targeted toggle (`fail_next_insert_for_kind`)
    /// so the failure fires precisely on the metadata_blob call,
    /// without contaminating the preceding primary_content call.
    #[test]
    fn ingest_direct_metadata_blob_refcount_failure_is_warn_only() {
        let repo = pypi_repository();
        let repo_id = repo.id;

        // Payload comfortably over the 128-byte threshold so the
        // HashReference split fires and the second insert call is
        // the metadata_blob arm.
        let payload = serde_json::json!({ "pad": "a".repeat(500) });
        let expected_blob_hash: ContentHash = {
            let serialised = serde_json::to_vec(&payload).unwrap();
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&serialised))
                .parse()
                .unwrap()
        };
        let summary = serde_json::json!({ "pad-summary": "x" });

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, _storage, repos, content_refs) =
                make_use_case_with_content_refs(true);
            repos.insert(repo);

            let handler = StubFormatHandler::new("pypi")
                .with_max_bytes(10 * 1024 * 1024)
                .with_strategy(MetadataStrategy::HashReference {
                    inline_threshold_bytes: 128,
                })
                .with_summary(summary);

            // Arm a kind-targeted failure: the primary_content insert
            // (issued first) passes through; the metadata_blob insert
            // (issued second) consumes the toggle and returns Err.
            content_refs.fail_next_insert_for_kind(
                "metadata_blob",
                DomainError::Invariant("synthetic failure: metadata_blob insert".into()),
            );

            uc.ingest_direct(
                DirectIngestRequest {
                    payload_metadata: payload.clone(),
                    ..req(repo_id)
                },
                content_stream(b"split-payload"),
                &handler,
            )
            .await
            .expect("ingest_direct must succeed even when metadata_blob refcount insert fails");

            // The artifact transition committed — the warn-on-fail
            // arm did not abort the ingest.
            assert_eq!(
                lifecycle.committed_transitions().len(),
                1,
                "ArtifactIngested must still commit when metadata_blob refcount insert fails"
            );

            // Exactly ONE refcount row: the primary_content write
            // landed; the metadata_blob write failed and was
            // skipped. A future change that aborts on
            // metadata_blob-insert-failure would either prevent the
            // ingest commit (zero rows) or leave the primary_content
            // row in a state inconsistent with the partial commit —
            // either branch fails the count assertion below.
            assert_eq!(
                content_refs.entry_count(),
                1,
                "warn-on-fail must leave primary_content row but NOT metadata_blob"
            );

            let transitions = lifecycle.committed_transitions();
            let artifact = &transitions[0].0;

            let primary_rows = content_refs
                .find_by_target(repo_id, &artifact.sha256_checksum, Some("primary_content"))
                .await
                .unwrap();
            assert_eq!(
                primary_rows.len(),
                1,
                "primary_content row landed before the metadata_blob arm fired"
            );

            // Load-bearing: the metadata_blob row is absent. Drift
            // is left for the reconcile sweep to repair.
            let blob_rows = content_refs
                .find_by_target(repo_id, &expected_blob_hash, Some("metadata_blob"))
                .await
                .unwrap();
            assert_eq!(
                blob_rows.len(),
                0,
                "metadata_blob row absent — drift left for reconcile to repair"
            );
        });
    }

    // ------------------------------------------------------------------
    // `extract_wheel_metadata_bytes` ingest hook
    // ------------------------------------------------------------------
    //
    // These tests pin the post-`ArtifactIngested` extract → CAS →
    // ContentReference pipeline added in `ingest_inner`. Each test uses
    // a `.whl`-suffixed `coords.path` to drive the hook's path gate; a
    // sdist test verifies the gate's negative arm.

    /// Path-gated `.whl` filename used by the wheel-metadata ingest-hook
    /// tests.
    /// The hook in `ingest_inner` short-circuits on a non-`.whl`
    /// suffix, so every happy-path / failure-path test must use a
    /// wheel-shaped path. Filename is wheel-spec-shaped but the test
    /// uses synthetic content bytes (the StubFormatHandler is what
    /// drives the extract response).
    const WHEEL_PATH: &str = "my-package/1.0.0/my_package-1.0.0-py3-none-any.whl";

    /// Build a `.whl`-shaped `DirectIngestRequest` for the wheel-metadata
    /// ingest-hook tests. Mirrors [`req`] but pins `coords.path` to a
    /// PEP 427-shaped wheel filename so the post-commit
    /// `coords.path.ends_with(".whl")` gate fires.
    fn req_wheel(repo_id: Uuid) -> DirectIngestRequest {
        DirectIngestRequest {
            repository_id: repo_id,
            coords: ArtifactCoords {
                path: WHEEL_PATH.into(),
                ..sample_coords()
            },
            content_type: "application/zip".into(),
            actor: api_actor(),
            legacy_sha1: None,
            legacy_md5: None,
            payload_metadata: serde_json::Value::Null,
        }
    }

    /// Happy path — a PyPI wheel ingest whose
    /// `FormatHandler::extract_wheel_metadata_bytes` returns
    /// `Ok(Some(bytes))` produces a `wheel_metadata` ContentReference
    /// row pointing at the CAS hash of the extracted METADATA bytes.
    #[test]
    fn ingest_wheel_emits_wheel_metadata_content_reference() {
        let repo = pypi_repository();
        let repo_id = repo.id;

        // Synthetic METADATA bytes — the test does not care about the
        // PEP 566 grammar; the hook just streams them into CAS.
        let metadata_bytes = b"Metadata-Version: 2.1\nName: my-package\nVersion: 1.0.0\n".to_vec();
        let expected_metadata_hash: ContentHash = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&metadata_bytes))
                .parse()
                .unwrap()
        };

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, storage, repos, content_refs) =
                make_use_case_with_content_refs(true);
            repos.insert(repo);

            let handler = StubFormatHandler::new("pypi")
                .with_max_bytes(10 * 1024 * 1024)
                .with_wheel_metadata(WheelMetadataStubBehaviour::EmitBytes(
                    metadata_bytes.clone(),
                ));

            uc.ingest_direct(
                req_wheel(repo_id),
                content_stream(b"fake-wheel-bytes"),
                &handler,
            )
            .await
            .expect("wheel ingest must succeed");

            // Two CAS puts: (1) the wheel content, (2) the
            // extracted METADATA bytes.
            assert_eq!(
                storage.put_call_count(),
                2,
                "wheel CAS put + extracted-metadata CAS put"
            );

            // The METADATA bytes landed in CAS at the expected hash.
            assert!(
                storage.stored_hashes().contains(&expected_metadata_hash),
                "expected metadata hash {expected_metadata_hash} not in CAS; \
                 stored: {:?}",
                storage.stored_hashes()
            );

            // Two ContentReference rows: primary_content + wheel_metadata.
            assert_eq!(
                content_refs.entry_count(),
                2,
                "exactly two ContentReference rows: primary_content + wheel_metadata"
            );

            let transitions = lifecycle.committed_transitions();
            let artifact = &transitions[0].0;

            let wheel_metadata_rows = content_refs
                .find_by_target(repo_id, &expected_metadata_hash, Some("wheel_metadata"))
                .await
                .unwrap();
            assert_eq!(wheel_metadata_rows.len(), 1, "one wheel_metadata row");
            assert_eq!(wheel_metadata_rows[0].kind, "wheel_metadata");
            assert_eq!(wheel_metadata_rows[0].source_artifact_id, artifact.id);
            assert_eq!(
                wheel_metadata_rows[0].target_content_hash, expected_metadata_hash,
                "wheel_metadata row points at the CAS hash of the extracted METADATA"
            );
            assert_eq!(wheel_metadata_rows[0].repository_id, repo_id);
        });
    }

    /// Sdist (non-`.whl` path) ingest skips the hook
    /// entirely: no CAS re-read, no extraction call, no
    /// `wheel_metadata` ContentReference row. The
    /// `coords.path.ends_with(".whl")` gate fires negative.
    #[test]
    fn ingest_sdist_skips_wheel_metadata_hook() {
        let repo = pypi_repository();
        let repo_id = repo.id;

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, _lifecycle, storage, repos, content_refs) =
                make_use_case_with_content_refs(true);
            repos.insert(repo);

            // The stub is armed with EmitBytes — if the hook fired
            // it would write the METADATA blob too. The test proves
            // the gate prevents the call by asserting put_call_count
            // and entry_count below.
            let handler = StubFormatHandler::new("pypi")
                .with_max_bytes(10 * 1024 * 1024)
                .with_wheel_metadata(WheelMetadataStubBehaviour::EmitBytes(
                    b"never-read".to_vec(),
                ));

            // Default `req` uses a .tar.gz (sdist) path.
            uc.ingest_direct(req(repo_id), content_stream(b"sdist-bytes"), &handler)
                .await
                .expect("sdist ingest must succeed");

            // Single CAS put — only the primary wheel/sdist content.
            assert_eq!(
                storage.put_call_count(),
                1,
                "sdist must NOT trigger the wheel-metadata CAS put"
            );

            // Single ContentReference row — primary_content only.
            assert_eq!(
                content_refs.entry_count(),
                1,
                "sdist must NOT produce a wheel_metadata ContentReference"
            );
        });
    }

    /// A wheel-shaped path whose handler returns
    /// `Ok(None)` (corrupt wheel ZIP, no METADATA member) takes the
    /// silent no-op branch: ingest succeeds, no metadata CAS put, no
    /// `wheel_metadata` row, and crucially NO metric tick (the
    /// `wheel_metadata_extract_failed` label fires ONLY on
    /// `Err(Validation)`, not on `Ok(None)`).
    #[test]
    fn ingest_wheel_with_extract_none_is_silent_noop() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let repo_key = repo.key.clone();

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, _artifacts, _events, _lifecycle, storage, repos, content_refs) =
                    make_use_case_with_content_refs(true);
                repos.insert(repo);

                let handler = StubFormatHandler::new("pypi")
                    .with_max_bytes(10 * 1024 * 1024)
                    .with_wheel_metadata(WheelMetadataStubBehaviour::None);

                uc.ingest_direct(
                    req_wheel(repo_id),
                    content_stream(b"corrupt-wheel"),
                    &handler,
                )
                .await
                .expect("wheel ingest must succeed even when extract returns None");

                // Only the primary-content CAS put — no metadata blob.
                assert_eq!(
                    storage.put_call_count(),
                    1,
                    "Ok(None) extract must NOT trigger the metadata CAS put"
                );

                // Only the primary_content ContentReference — no
                // wheel_metadata row.
                assert_eq!(
                    content_refs.entry_count(),
                    1,
                    "Ok(None) extract must NOT produce a wheel_metadata row"
                );
            });
        });

        // Metric assertion: the success result ticks, but
        // wheel_metadata_extract_failed does NOT.
        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_ingest_total",
            &[
                ("format", "pypi"),
                ("repository", repo_key.as_str()),
                ("result", "success"),
            ],
            1,
        );
        // Crucially: no wheel_metadata_extract_failed tick.
        let failed_tick = entries.iter().any(|(ck, _, _, _)| {
            let key = ck.key();
            key.name() == "hort_ingest_total"
                && key
                    .labels()
                    .any(|l| l.key() == "result" && l.value() == "wheel_metadata_extract_failed")
        });
        assert!(
            !failed_tick,
            "Ok(None) must NOT emit wheel_metadata_extract_failed"
        );
    }

    /// Oversized METADATA (handler returns
    /// `Err(DomainError::Validation)`) is non-fatal: the wheel ingest
    /// succeeds, no `wheel_metadata` row is written, and the
    /// `hort_ingest_total{format="pypi", result="wheel_metadata_extract_failed"}`
    /// counter ticks exactly once. The only
    /// production path that surfaces `Err(Validation)` today is the
    /// extractor's 1 MiB cap.
    #[test]
    fn ingest_wheel_with_extract_validation_error_ticks_metric() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let repo_key = repo.key.clone();

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, _artifacts, _events, lifecycle, storage, repos, content_refs) =
                    make_use_case_with_content_refs(true);
                repos.insert(repo);

                let handler = StubFormatHandler::new("pypi")
                    .with_max_bytes(10 * 1024 * 1024)
                    .with_wheel_metadata(WheelMetadataStubBehaviour::Validation(
                        "synthetic oversized METADATA",
                    ));

                uc.ingest_direct(
                    req_wheel(repo_id),
                    content_stream(b"oversized-metadata-wheel"),
                    &handler,
                )
                .await
                .expect(
                    "wheel ingest must remain successful when wheel-metadata extract \
                     fails validation",
                );

                // Wheel ingest itself committed — ArtifactIngested
                // landed on the stream.
                assert_eq!(
                    lifecycle.committed_transitions().len(),
                    1,
                    "ArtifactIngested commits even when wheel-metadata extract validation-fails"
                );

                // Only the primary-content CAS put — no metadata blob.
                assert_eq!(
                    storage.put_call_count(),
                    1,
                    "validation-failed extract must NOT trigger the metadata CAS put"
                );

                // Only the primary_content row — no wheel_metadata row.
                assert_eq!(
                    content_refs.entry_count(),
                    1,
                    "validation-failed extract must NOT produce a wheel_metadata row"
                );
            });
        });

        let entries = snap.into_vec();
        // The success tick is also present (the wheel ingest succeeded).
        assert_counter(
            &entries,
            "hort_ingest_total",
            &[
                ("format", "pypi"),
                ("repository", repo_key.as_str()),
                ("result", "success"),
            ],
            1,
        );
        // Load-bearing: the new label value increments exactly once.
        assert_counter(
            &entries,
            "hort_ingest_total",
            &[
                ("format", "pypi"),
                ("repository", repo_key.as_str()),
                ("result", "wheel_metadata_extract_failed"),
            ],
            1,
        );
    }

    /// A CAS write failure on the extracted-METADATA
    /// blob propagates from the ingest use case. The wheel
    /// `ArtifactIngested` event is durable but the caller sees `Err`;
    /// this reads as "wheel-metadata pipeline did
    /// not complete." No `wheel_metadata` row is written.
    ///
    /// Targets the SECOND put (the wheel-metadata CAS write) via
    /// [`MockStoragePort::fail_put_after_calls`] — `fail_next_put`
    /// would consume on the wheel's primary content put and fail the
    /// wheel ingest itself before the hook runs.
    #[test]
    fn ingest_wheel_metadata_cas_put_failure_propagates_err() {
        let repo = pypi_repository();
        let repo_id = repo.id;

        let metadata_bytes = b"Metadata-Version: 2.1\nName: pkg\nVersion: 1.0.0\n".to_vec();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, storage, repos, content_refs) =
                make_use_case_with_content_refs(true);
            repos.insert(repo);

            let handler = StubFormatHandler::new("pypi")
                .with_max_bytes(10 * 1024 * 1024)
                .with_wheel_metadata(WheelMetadataStubBehaviour::EmitBytes(metadata_bytes));

            // Skip 1 put (the wheel content), fail the next one (the
            // wheel-metadata CAS write).
            storage.fail_put_after_calls(
                1,
                DomainError::Invariant("synthetic CAS failure: wheel_metadata put".into()),
            );

            let err = uc
                .ingest_direct(req_wheel(repo_id), content_stream(b"wheel-bytes"), &handler)
                .await
                .expect_err("wheel-metadata CAS put failure must propagate from ingest_direct");

            assert!(
                matches!(err, AppError::Storage(_)),
                "expected AppError::Storage(_), got {err:?}"
            );

            // ArtifactIngested already committed by the time the
            // wheel-metadata put runs — the event is durable even
            // though `ingest_direct` returned Err.
            assert_eq!(
                lifecycle.committed_transitions().len(),
                1,
                "wheel ArtifactIngested commits before the wheel-metadata put failure"
            );

            // No wheel_metadata row landed.
            let transitions = lifecycle.committed_transitions();
            let artifact = &transitions[0].0;
            let rows = content_refs
                .find_by_target(repo_id, &artifact.sha256_checksum, Some("wheel_metadata"))
                .await
                .unwrap();
            assert!(
                rows.is_empty(),
                "no wheel_metadata row when the CAS put failed"
            );
        });
    }

    /// A ContentReference `insert` failure on the
    /// `wheel_metadata` row propagates from the ingest use case. The
    /// METADATA bytes landed in CAS but the linkage row was not
    /// written; the caller sees `Err`. (The
    /// CAS-orphan blob is reaped by the GC reconcile
    /// sweep — a use-case-side rollback is not required here.)
    #[test]
    fn ingest_wheel_metadata_content_reference_insert_failure_propagates_err() {
        let repo = pypi_repository();
        let repo_id = repo.id;

        let metadata_bytes = b"Metadata-Version: 2.1\nName: pkg\nVersion: 1.0.0\n".to_vec();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, _storage, repos, content_refs) =
                make_use_case_with_content_refs(true);
            repos.insert(repo);

            let handler = StubFormatHandler::new("pypi")
                .with_max_bytes(10 * 1024 * 1024)
                .with_wheel_metadata(WheelMetadataStubBehaviour::EmitBytes(metadata_bytes));

            // Arm a kind-targeted failure: the first insert
            // (`primary_content`) succeeds; the next insert with
            // `kind = "wheel_metadata"` consumes the toggle and
            // returns Err. The `metadata_blob` arm is not in scope
            // because the payload is `Value::Null` (Inline strategy,
            // no blob).
            content_refs.fail_next_insert_for_kind(
                "wheel_metadata",
                DomainError::Invariant("synthetic failure: wheel_metadata insert".into()),
            );

            let err = uc
                .ingest_direct(req_wheel(repo_id), content_stream(b"wheel-bytes"), &handler)
                .await
                .expect_err(
                    "wheel_metadata ContentReference insert failure must propagate from \
                     ingest_direct",
                );

            // Port returns DomainError → wrapped as AppError::Domain.
            assert!(
                matches!(err, AppError::Domain(DomainError::Invariant(_))),
                "expected AppError::Domain(Invariant), got {err:?}"
            );

            // ArtifactIngested is durable; ONLY the wheel_metadata
            // linkage row failed.
            assert_eq!(
                lifecycle.committed_transitions().len(),
                1,
                "wheel ArtifactIngested commits before the wheel_metadata insert failure"
            );

            // Exactly one ContentReference row — primary_content
            // landed before the wheel_metadata arm fired.
            assert_eq!(
                content_refs.entry_count(),
                1,
                "primary_content row landed but wheel_metadata did not"
            );
            let transitions = lifecycle.committed_transitions();
            let artifact = &transitions[0].0;
            let primary_rows = content_refs
                .find_by_target(repo_id, &artifact.sha256_checksum, Some("primary_content"))
                .await
                .unwrap();
            assert_eq!(
                primary_rows.len(),
                1,
                "primary_content insert happened before the wheel_metadata failure"
            );
        });
    }

    /// Acceptance — coverage gap-fill for the warn-on-fail arm at
    /// `register_by_hash_inner` `primary_content` insert. The
    /// `register_by_hash` path takes a single insert call (no
    /// metadata-blob split), so a one-shot toggle cleanly targets the
    /// only refcount write site on this path. Same invariant as the
    /// ingest path: refcount write failure does NOT abort the outer
    /// `register_by_hash`; the artifact is committed, drift is left
    /// for the reconcile sweep.
    #[test]
    fn register_by_hash_refcount_failure_is_warn_only() {
        let target = pypi_repository();
        let target_id = target.id;
        let hash: ContentHash = ZERO_HASH.parse().unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, storage, repos, content_refs) =
                make_use_case_with_content_refs(true);
            repos.insert(target);
            storage.insert_content(hash.clone(), b"already-in-cas".to_vec());

            content_refs.fail_next_insert(DomainError::Invariant(
                "synthetic failure: register_by_hash insert".into(),
            ));

            let outcome = uc
                .register_by_hash(req_legacy(target_id), hash.clone(), None, &test_handler())
                .await
                .expect("register_by_hash must succeed even when refcount insert fails");

            assert_eq!(
                lifecycle.committed_transitions().len(),
                1,
                "ArtifactIngested must still commit on register_by_hash when refcount insert fails"
            );

            // No refcount row landed — the failed insert was warned
            // and skipped. Drift is left for the reconcile sweep.
            assert_eq!(
                content_refs.entry_count(),
                0,
                "warn-on-fail on register_by_hash must NOT write the row"
            );

            // Belt-and-braces: confirm that targeting the artifact's
            // hash returns no rows.
            let rows = content_refs
                .find_by_target(target_id, &outcome.artifact.sha256_checksum, None)
                .await
                .unwrap();
            assert!(
                rows.is_empty(),
                "no refcount rows for the just-registered artifact"
            );
        });
    }

    // -----------------------------------------------------------------------
    // pre-storage curation gate
    // -----------------------------------------------------------------------

    /// Build a curation rule for the gate-coverage tests below.
    fn curation_rule(
        name: &str,
        format: Option<RepositoryFormat>,
        pattern: &str,
        action: hort_domain::entities::curation_rule::CurationRuleAction,
    ) -> hort_domain::entities::curation_rule::CurationRule {
        hort_domain::entities::curation_rule::CurationRule {
            id: Uuid::new_v4(),
            name: name.into(),
            format,
            package_pattern: pattern.into(),
            action,
            reason: format!("reason-{name}"),
            managed_by: hort_domain::entities::managed_by::ManagedBy::GitOps,
            managed_by_digest: Some([0xab; 32]),
        }
    }

    #[test]
    fn curation_no_rules_fast_path_proceeds_to_ingest() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, _storage, repos, _curation) =
                make_use_case_with_curation(true);
            repos.insert(repo);

            let outcome = uc
                .ingest_direct(
                    req(repo_id),
                    content_stream(b"package-bytes"),
                    &test_handler(),
                )
                .await
                .expect("empty curation rules → fast-path Allow → ingest succeeds");

            // Storage + lifecycle moved past the gate.
            assert!(!outcome.artifact.id.is_nil());
            let transitions = lifecycle.committed_transitions();
            assert_eq!(
                transitions.len(),
                1,
                "Allow path must commit exactly one ArtifactIngested transition"
            );
        });
    }

    #[test]
    fn curation_block_rule_returns_curation_blocked_before_storage() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        // The rule's name pattern matches `sample_coords().name = "my-package"`.
        let rule = curation_rule(
            "block-my-package",
            None,
            "my-package",
            hort_domain::entities::curation_rule::CurationRuleAction::Block,
        );
        let expected_rule_id = rule.id;

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, storage, repos, curation) =
                make_use_case_with_curation(true);
            repos.insert(repo);
            curation.set_rules_for_repo(repo_id, vec![rule]);

            let err = uc
                .ingest_direct(
                    req(repo_id),
                    content_stream(b"package-bytes"),
                    &test_handler(),
                )
                .await
                .expect_err("Block rule must return CurationBlocked");

            match err {
                AppError::Domain(DomainError::CurationBlocked {
                    rule_name,
                    rule_id,
                    reason,
                }) => {
                    assert_eq!(rule_name, "block-my-package");
                    assert_eq!(rule_id, expected_rule_id);
                    assert_eq!(reason, "reason-block-my-package");
                }
                other => panic!("expected CurationBlocked, got {other:?}"),
            }

            // Storage must NOT have been touched — the gate runs BEFORE
            // any byte hits CAS.
            assert_eq!(
                storage.put_call_count(),
                0,
                "Block path must short-circuit before storage.put"
            );
            // Lifecycle must NOT have committed an ingestion event.
            assert!(
                lifecycle.committed_transitions().is_empty(),
                "Block path must short-circuit before lifecycle.commit_transition"
            );
        });
    }

    #[test]
    fn curation_warn_rule_logs_and_continues_to_ingest() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let rule = curation_rule(
            "warn-my-package",
            None,
            "my-package",
            hort_domain::entities::curation_rule::CurationRuleAction::Warn,
        );

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, _storage, repos, curation) =
                make_use_case_with_curation(true);
            repos.insert(repo);
            curation.set_rules_for_repo(repo_id, vec![rule]);

            let outcome = uc
                .ingest_direct(
                    req(repo_id),
                    content_stream(b"package-bytes"),
                    &test_handler(),
                )
                .await
                .expect("Warn rule must NOT abort ingest");

            // The artifact must have been ingested — Warn is non-blocking.
            assert!(!outcome.artifact.id.is_nil());
            let transitions = lifecycle.committed_transitions();
            assert_eq!(
                transitions.len(),
                1,
                "Warn path must still commit ArtifactIngested"
            );
        });
    }

    #[test]
    fn curation_allow_rule_short_circuits_subsequent_block_and_proceeds() {
        // Allow-list override semantics: an explicit Allow rule on a
        // specific package must beat a later broader Block rule, mirroring
        // the truth-table case in the domain evaluator's tests.
        let repo = pypi_repository();
        let repo_id = repo.id;
        let allow_rule = curation_rule(
            "allow-my-package",
            None,
            "my-package",
            hort_domain::entities::curation_rule::CurationRuleAction::Allow,
        );
        let block_rule = curation_rule(
            "block-everything",
            None,
            "*",
            hort_domain::entities::curation_rule::CurationRuleAction::Block,
        );

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, _storage, repos, curation) =
                make_use_case_with_curation(true);
            repos.insert(repo);
            // Order matters: allow first.
            curation.set_rules_for_repo(repo_id, vec![allow_rule, block_rule]);

            let outcome = uc
                .ingest_direct(
                    req(repo_id),
                    content_stream(b"package-bytes"),
                    &test_handler(),
                )
                .await
                .expect("Allow override must short-circuit later Block");

            assert!(!outcome.artifact.id.is_nil());
            assert_eq!(lifecycle.committed_transitions().len(), 1);
        });
    }

    /// The curation gate emits the policy-evaluation
    /// counter for every outcome, plus the violations counter on
    /// non-Allow paths. Three sub-cases (Allow/Pass, Warn, Block) keep
    /// the test fixture small.
    #[test]
    fn curation_gate_emits_evaluation_metrics_per_outcome() {
        // -- Block: emits result=block plus rule=curation-block.
        let snap_block = capture_metrics(|| {
            let repo = pypi_repository();
            let repo_id = repo.id;
            let rule = curation_rule(
                "block-my-package",
                None,
                "my-package",
                hort_domain::entities::curation_rule::CurationRuleAction::Block,
            );
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, _artifacts, _events, _lifecycle, _storage, repos, curation) =
                    make_use_case_with_curation(true);
                repos.insert(repo);
                curation.set_rules_for_repo(repo_id, vec![rule]);
                let _ = uc
                    .ingest_direct(
                        req(repo_id),
                        content_stream(b"package-bytes"),
                        &test_handler(),
                    )
                    .await;
            });
        });
        let entries = snap_block.into_vec();
        assert!(
            entries.iter().any(|(ck, _, _, _)| {
                ck.key().name() == "hort_policy_evaluation_total"
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "decision_point" && l.value() == "curation")
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "result" && l.value() == "block")
            }),
            "block outcome must emit decision_point=curation, result=block"
        );
        assert!(
            entries.iter().any(|(ck, _, _, _)| {
                ck.key().name() == "hort_policy_violations_total"
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "rule" && l.value() == "curation-block")
            }),
            "block outcome must emit rule=curation-block"
        );

        // -- Allow: emits result=pass and NO violations.
        let snap_allow = capture_metrics(|| {
            let repo = pypi_repository();
            let repo_id = repo.id;
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, _artifacts, _events, _lifecycle, _storage, repos, _curation) =
                    make_use_case_with_curation(true);
                repos.insert(repo);
                // No rules → CurationOutcome::Allow.
                let _ = uc
                    .ingest_direct(
                        req(repo_id),
                        content_stream(b"package-bytes"),
                        &test_handler(),
                    )
                    .await;
            });
        });
        let entries = snap_allow.into_vec();
        assert!(
            entries.iter().any(|(ck, _, _, _)| {
                ck.key().name() == "hort_policy_evaluation_total"
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "decision_point" && l.value() == "curation")
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "result" && l.value() == "pass")
            }),
            "Allow outcome must emit result=pass"
        );
        assert!(
            !entries.iter().any(|(ck, _, _, _)| {
                ck.key().name() == "hort_policy_violations_total"
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "decision_point" && l.value() == "curation")
            }),
            "Allow outcome must NOT emit a violations counter"
        );
    }

    #[test]
    fn curation_list_for_repo_failure_propagates_as_app_error() {
        // A lookup failure on the curation port must NOT silently fall
        // through to Allow — that would defeat the gate. The use case
        // wraps the DomainError into AppError::Domain and returns it.
        let repo = pypi_repository();
        let repo_id = repo.id;
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, storage, repos, curation) =
                make_use_case_with_curation(true);
            repos.insert(repo);
            curation.fail_next_list_for_repo(DomainError::Invariant("port blew up".into()));

            let err = uc
                .ingest_direct(
                    req(repo_id),
                    content_stream(b"package-bytes"),
                    &test_handler(),
                )
                .await
                .expect_err("port failure must propagate");

            match err {
                AppError::Domain(DomainError::Invariant(msg)) => {
                    assert!(msg.contains("port blew up"));
                }
                other => panic!("expected propagated Invariant, got {other:?}"),
            }

            // Gate failure short-circuits before storage / lifecycle.
            assert_eq!(storage.put_call_count(), 0);
            assert!(lifecycle.committed_transitions().is_empty());
        });
    }

    // ---------------------------------------------------------------------
    // DirectIngestRequest / VerifiedIngestRequest
    // ---------------------------------------------------------------------

    fn sample_actor() -> ApiActor {
        ApiActor {
            user_id: Uuid::new_v4(),
        }
    }

    #[test]
    fn direct_ingest_request_constructs_without_declared_sha256() {
        let req = DirectIngestRequest {
            repository_id: Uuid::new_v4(),
            coords: sample_coords(),
            content_type: "application/x-gzip".into(),
            actor: sample_actor(),
            legacy_sha1: None,
            legacy_md5: None,
            payload_metadata: serde_json::Value::Null,
        };
        assert_eq!(req.coords.name, "my-package");
        assert!(req.legacy_sha1.is_none());
    }

    #[test]
    fn verified_ingest_request_protocol_native_pattern_matches() {
        let digest: ContentHash =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .parse()
                .unwrap();
        let req = VerifiedIngestRequest::ProtocolNative {
            repository_id: Uuid::new_v4(),
            coords: sample_coords(),
            content_type: "application/octet-stream".into(),
            actor: sample_actor(),
            payload_metadata: serde_json::Value::Null,
            upstream_digest: digest.clone(),
            upstream_published_at: None,
            trust_upstream_publish_time: false,
        };
        match req {
            VerifiedIngestRequest::ProtocolNative {
                upstream_digest, ..
            } => assert_eq!(upstream_digest, digest),
            VerifiedIngestRequest::UpstreamPublished { .. } => {
                panic!("expected ProtocolNative variant")
            }
        }
    }

    #[test]
    fn verified_ingest_request_upstream_published_pattern_matches() {
        use hort_domain::types::checksum::HashAlgorithm;
        let cs = UpstreamPublishedChecksum::new(
            HashAlgorithm::Sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        .unwrap();
        let req = VerifiedIngestRequest::UpstreamPublished {
            repository_id: Uuid::new_v4(),
            coords: sample_coords(),
            content_type: "application/octet-stream".into(),
            actor: sample_actor(),
            payload_metadata: serde_json::Value::Null,
            upstream_checksum: cs.clone(),
            upstream_published_at: None,
            trust_upstream_publish_time: false,
        };
        match req {
            VerifiedIngestRequest::UpstreamPublished {
                upstream_checksum, ..
            } => {
                assert_eq!(upstream_checksum, cs);
                assert_eq!(upstream_checksum.algorithm(), HashAlgorithm::Sha256);
            }
            VerifiedIngestRequest::ProtocolNative { .. } => {
                panic!("expected UpstreamPublished variant")
            }
        }
    }

    /// Construction with a Sha512 algorithm requires the matching
    /// 128-char hex; mismatched hex length fails at the
    /// UpstreamPublishedChecksum constructor.
    #[test]
    fn upstream_published_with_wrong_length_hex_for_algorithm_is_rejected() {
        // 64-char (sha256-length) hex with sha512 algorithm.
        let err = UpstreamPublishedChecksum::new(
            HashAlgorithm::Sha512,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    // ---------------------------------------------------------------------
    // IngestUseCase::ingest_verified
    // ---------------------------------------------------------------------

    use hort_domain::events::StreamCategory;

    fn sha256_of(bytes: &[u8]) -> String {
        use sha2::Digest;
        format!("{:x}", sha2::Sha256::digest(bytes))
    }

    /// ProtocolNative: hash matches → success. Asserts that
    /// (a) the artifact is minted, (b) ChecksumVerified is emitted on
    /// the artifact stream, (c) put was called once.
    #[test]
    fn ingest_verified_protocol_native_success_emits_checksum_verified() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let content: &[u8] = b"hello world";
        let hash_hex = sha256_of(content);
        let upstream_digest: ContentHash = hash_hex.parse().unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, storage, repos) = make_use_case();
            repos.insert(repo);

            let req = VerifiedIngestRequest::ProtocolNative {
                repository_id: repo_id,
                coords: sample_coords(),
                content_type: "application/octet-stream".into(),
                actor: api_actor(),
                payload_metadata: serde_json::Value::Null,
                upstream_digest: upstream_digest.clone(),
                upstream_published_at: None,
                trust_upstream_publish_time: false,
            };

            let outcome = uc
                .ingest_verified(req, content_stream(content), &test_handler())
                .await
                .expect("verified ingest should succeed when hashes match");

            assert_eq!(storage.put_call_count(), 1);
            assert_eq!(outcome.artifact.sha256_checksum, upstream_digest);

            // ChecksumVerified appended atomically alongside
            // ArtifactIngested in the same `commit_transition` batch
            // — query the lifecycle mock, not the raw EventStore mock.
            let transitions = lifecycle.committed_transitions();
            assert_eq!(transitions.len(), 1);
            let (_artifact, batch, _meta) = &transitions[0];
            assert_eq!(batch.stream_id.category, StreamCategory::Artifact);
            let kinds: Vec<&str> = batch.events.iter().map(|e| e.event.event_type()).collect();
            assert_eq!(
                kinds,
                vec!["ArtifactIngested", "ChecksumVerified", "ScanRequested"],
                "ingest batch: ArtifactIngested + ChecksumVerified + ScanRequested \
                 (DefaultPolicy fallback), in order",
            );
        });
    }

    /// `VerifiedIngestRequest.upstream_published_at`
    /// threads onto `Artifact.upstream_published_at` at
    /// `commit_transition`. The field is audit-only for anchor
    /// resolution unless the per-upstream opt-in gates
    /// publish-anchoring on. Coverage:
    /// `ProtocolNative` arm carries `Some(ts)` → minted artifact
    /// reflects it.
    #[test]
    fn ingest_verified_records_upstream_published_at_when_provided() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let content: &[u8] = b"hello world";
        let hash_hex = sha256_of(content);
        let upstream_digest: ContentHash = hash_hex.parse().unwrap();
        let published_at: DateTime<Utc> = DateTime::parse_from_rfc3339("2023-05-22T15:12:42Z")
            .unwrap()
            .with_timezone(&Utc);

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, _storage, repos) = make_use_case();
            repos.insert(repo);

            let req = VerifiedIngestRequest::ProtocolNative {
                repository_id: repo_id,
                coords: sample_coords(),
                content_type: "application/octet-stream".into(),
                actor: api_actor(),
                payload_metadata: serde_json::Value::Null,
                upstream_digest: upstream_digest.clone(),
                upstream_published_at: Some(published_at),
                trust_upstream_publish_time: false,
            };

            let outcome = uc
                .ingest_verified(req, content_stream(content), &test_handler())
                .await
                .expect("verified ingest should succeed when hashes match");

            assert_eq!(
                outcome.artifact.upstream_published_at,
                Some(published_at),
                "VerifiedIngestRequest.upstream_published_at \
                 must thread onto Artifact.upstream_published_at"
            );

            // Cross-check the persisted artifact on the lifecycle mock.
            let transitions = lifecycle.committed_transitions();
            assert_eq!(transitions.len(), 1);
            let (persisted, _batch, _meta) = &transitions[0];
            assert_eq!(
                persisted.upstream_published_at,
                Some(published_at),
                "the Artifact passed to commit_transition must carry the \
                 upstream-asserted publish timestamp"
            );
        });
    }

    /// `VerifiedIngestRequest.upstream_published_at`
    /// defaulting to `None` (direct uploads, formats that could not
    /// extract a hint, the verified-paths that haven't been taught to
    /// populate it yet) round-trips onto `Artifact.upstream_published_at`
    /// as `None`. The absent-hint path must NOT fail the ingest.
    #[test]
    fn ingest_verified_records_upstream_published_at_none_when_absent() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let content: &[u8] = b"hello world";
        let hash_hex = sha256_of(content);
        let upstream_digest: ContentHash = hash_hex.parse().unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, _storage, repos) = make_use_case();
            repos.insert(repo);

            let req = VerifiedIngestRequest::ProtocolNative {
                repository_id: repo_id,
                coords: sample_coords(),
                content_type: "application/octet-stream".into(),
                actor: api_actor(),
                payload_metadata: serde_json::Value::Null,
                upstream_digest: upstream_digest.clone(),
                upstream_published_at: None,
                trust_upstream_publish_time: false,
            };

            let outcome = uc
                .ingest_verified(req, content_stream(content), &test_handler())
                .await
                .expect("verified ingest should succeed with absent publish hint");

            assert_eq!(outcome.artifact.upstream_published_at, None);
            let transitions = lifecycle.committed_transitions();
            assert_eq!(transitions.len(), 1);
            assert_eq!(transitions[0].0.upstream_published_at, None);
        });
    }

    /// `UpstreamPublished` arm (the SHA-256 variant —
    /// Cargo / PyPI shape) also threads the publish-time hint onto the
    /// minted artifact. Coverage: confirms the field is plumbed
    /// uniformly across BOTH `VerifiedIngestRequest` variants.
    #[test]
    fn ingest_verified_upstream_published_sha256_records_publish_time() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let content: &[u8] = b"hello world";
        let hash_hex = sha256_of(content);
        let cs = UpstreamPublishedChecksum::new(HashAlgorithm::Sha256, &hash_hex).unwrap();
        let published_at: DateTime<Utc> = DateTime::parse_from_rfc3339("2021-02-20T15:42:16.891Z")
            .unwrap()
            .with_timezone(&Utc);

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, _storage, repos) = make_use_case();
            repos.insert(repo);

            let req = VerifiedIngestRequest::UpstreamPublished {
                repository_id: repo_id,
                coords: sample_coords(),
                content_type: "application/octet-stream".into(),
                actor: api_actor(),
                payload_metadata: serde_json::Value::Null,
                upstream_checksum: cs,
                upstream_published_at: Some(published_at),
                trust_upstream_publish_time: false,
            };

            let outcome = uc
                .ingest_verified(req, content_stream(content), &test_handler())
                .await
                .expect("upstream-published sha256 ingest should succeed");

            assert_eq!(outcome.artifact.upstream_published_at, Some(published_at));
            let transitions = lifecycle.committed_transitions();
            assert_eq!(transitions.len(), 1);
            assert_eq!(transitions[0].0.upstream_published_at, Some(published_at));
        });
    }

    /// Pin that `ArtifactIngested` event payload carries
    /// `upstream_published_at` alongside the projection. The event is
    /// the source of truth for projection rebuild; without this, an
    /// `artifacts`-table rebuild from the event stream would silently
    /// produce `None` for every artifact ingested before the field
    /// landed in the projection. This test pins that the write also
    /// reaches the event payload so the publish-anchoring consumer —
    /// which derives
    /// `quarantine_window_start` from the value — sees the same
    /// number on a rebuild that it saw on the live row.
    #[test]
    fn ingest_verified_records_upstream_published_at_on_event_payload() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let content: &[u8] = b"hello world";
        let hash_hex = sha256_of(content);
        let upstream_digest: ContentHash = hash_hex.parse().unwrap();
        let published_at: DateTime<Utc> = DateTime::parse_from_rfc3339("2024-12-31T23:59:59Z")
            .unwrap()
            .with_timezone(&Utc);

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, _storage, repos) = make_use_case();
            repos.insert(repo);

            let req = VerifiedIngestRequest::ProtocolNative {
                repository_id: repo_id,
                coords: sample_coords(),
                content_type: "application/octet-stream".into(),
                actor: api_actor(),
                payload_metadata: serde_json::Value::Null,
                upstream_digest: upstream_digest.clone(),
                upstream_published_at: Some(published_at),
                trust_upstream_publish_time: false,
            };

            uc.ingest_verified(req, content_stream(content), &test_handler())
                .await
                .expect("verified ingest should succeed when hashes match");

            // The commit goes through `commit_transition`, which records
            // the `AppendEvents` batch (containing the `ArtifactIngested`
            // event) alongside the Artifact projection. Walk the recorded
            // transitions for the event payload — this is the bit
            // (the projection bit was already pinned by
            // the pre-existing sibling test on `Artifact.upstream_published_at`).
            let transitions = lifecycle.committed_transitions();
            assert_eq!(transitions.len(), 1);
            let ingested_payloads: Vec<_> = transitions[0]
                .1
                .events
                .iter()
                .filter_map(|e| match &e.event {
                    DomainEvent::ArtifactIngested(p) => Some(p.upstream_published_at),
                    _ => None,
                })
                .collect();
            assert_eq!(
                ingested_payloads.len(),
                1,
                "expected exactly one ArtifactIngested in the committed batch"
            );
            assert_eq!(
                ingested_payloads[0],
                Some(published_at),
                "ArtifactIngested.upstream_published_at must mirror \
                 Artifact.upstream_published_at so projection-rebuild stays \
                 bit-identical to the live row (required because publish-anchoring \
                 makes the value load-bearing for release authority)"
            );
        });
    }

    /// Same as above but for the `None` case. Pre-existing events
    /// deserialise via `#[serde(default)]` → `None`; this test pins
    /// that newer events also carry `None` cleanly when no upstream
    /// hint is available (direct uploads, format handlers that don't
    /// surface one).
    #[test]
    fn ingest_verified_records_upstream_published_at_none_on_event_payload() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let content: &[u8] = b"hello world";
        let hash_hex = sha256_of(content);
        let upstream_digest: ContentHash = hash_hex.parse().unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, _storage, repos) = make_use_case();
            repos.insert(repo);

            let req = VerifiedIngestRequest::ProtocolNative {
                repository_id: repo_id,
                coords: sample_coords(),
                content_type: "application/octet-stream".into(),
                actor: api_actor(),
                payload_metadata: serde_json::Value::Null,
                upstream_digest: upstream_digest.clone(),
                upstream_published_at: None,
                trust_upstream_publish_time: false,
            };

            uc.ingest_verified(req, content_stream(content), &test_handler())
                .await
                .expect("verified ingest should succeed with absent publish hint");

            let transitions = lifecycle.committed_transitions();
            assert_eq!(transitions.len(), 1);
            let ingested_payloads: Vec<_> = transitions[0]
                .1
                .events
                .iter()
                .filter_map(|e| match &e.event {
                    DomainEvent::ArtifactIngested(p) => Some(p.upstream_published_at),
                    _ => None,
                })
                .collect();
            assert_eq!(ingested_payloads.len(), 1);
            assert_eq!(
                ingested_payloads[0], None,
                "absent hint must round-trip as None on the event payload"
            );
        });
    }

    /// Backward-compat: a pre-existing `ArtifactIngested` event
    /// JSON (without the `upstream_published_at` key) must deserialise
    /// as `None` via `#[serde(default)]`. This pins the forward-compat
    /// contract: an existing event store doesn't need a rewrite when
    /// this field lands, and a projection rebuild over pre-fix events
    /// produces `Artifact.upstream_published_at = None` — matching the
    /// state of those same artifacts' `artifacts` rows (which were
    /// likewise `NULL` before the column existed).
    #[test]
    fn artifact_ingested_pre_fix_json_deserialises_with_none_publish_time() {
        // JSON shape that pre-dates the upstream_published_at field —
        // every persisted ArtifactIngested before this commit looked
        // exactly like this.
        let pre_fix_json = r#"{
            "artifact_id": "00000000-0000-0000-0000-000000000000",
            "repository_id": "00000000-0000-0000-0000-000000000000",
            "name": "pkg",
            "version": "1.0.0",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "size_bytes": 1,
            "source": "Direct",
            "metadata": null,
            "metadata_blob": null
        }"#;
        let event: ArtifactIngested =
            serde_json::from_str(pre_fix_json).expect("pre-fix JSON must still deserialise");
        assert_eq!(
            event.upstream_published_at, None,
            "#[serde(default)] on a new event field must produce None \
             for pre-fix persisted events — otherwise an existing event store \
             would need a rewrite, which is not on the table"
        );
    }

    // ---------------------------------------------------------------------
    // opt-in-gated publish-anchored quarantine window
    //
    // Pins: the per-upstream opt-in + `min` future-skew clamp, and "store
    // the
    // anchor, never the deadline". Six
    // acceptance tests. The fixture is `make_scan_gated_use_case` (no pre-seeded
    // permissive policy) so the `DefaultPolicy`-24h fire actually runs and
    // produces an `ArtifactQuarantined` event for the assertions to walk.
    // ---------------------------------------------------------------------

    /// Opt-in `true` + recent `Some(upstream_published_at)`
    /// (1h before ingest). The resolved anchor is the upstream publish time
    /// (the `min` clamp picks the smaller value; the upstream value is the
    /// smaller, so it wins). The persisted `ArtifactQuarantined` event must
    /// carry the publish-time anchor — that's what the sweep fast-path reads.
    #[test]
    fn ingest_opted_in_recent_upstream_publish_uses_publish_anchor() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let content: &[u8] = b"hello world";
        let hash_hex = sha256_of(content);
        let upstream_digest: ContentHash = hash_hex.parse().unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, lifecycle, _storage, repos, _policies, _jobs) =
                make_scan_gated_use_case();
            repos.insert(repo);

            let before = Utc::now();
            let upstream_ts = before - chrono::Duration::hours(1);

            let req = VerifiedIngestRequest::ProtocolNative {
                repository_id: repo_id,
                coords: sample_coords(),
                content_type: "application/octet-stream".into(),
                actor: api_actor(),
                payload_metadata: serde_json::Value::Null,
                upstream_digest,
                upstream_published_at: Some(upstream_ts),
                trust_upstream_publish_time: true,
            };

            let artifact = uc
                .ingest_verified(req, content_stream(content), &test_handler())
                .await
                .expect("verified ingest must succeed")
                .artifact;

            assert_eq!(artifact.quarantine_status, QuarantineStatus::Quarantined);
            let anchor = artifact
                .quarantine_window_start
                .expect("publish-anchored quarantine must set quarantine_window_start");
            assert_eq!(
                anchor, upstream_ts,
                "anchor must be the upstream publish timestamp (1h before ingest) — the `min` clamp \
                 picks the smaller value; the upstream value is smaller, so it wins"
            );

            // Walk the persisted ArtifactQuarantined event — this is the
            // value the sweep fast-path reads; projection
            // identity follows from the event payload.
            let transitions = lifecycle.committed_transitions();
            let quarantine_batch = transitions
                .iter()
                .find(|(_a, batch, _meta)| {
                    batch
                        .events
                        .iter()
                        .any(|e| matches!(e.event, DomainEvent::ArtifactQuarantined(_)))
                })
                .expect("a quarantine transition must have been committed");
            let q_event = quarantine_batch
                .1
                .events
                .iter()
                .find_map(|e| match &e.event {
                    DomainEvent::ArtifactQuarantined(q) => Some(q),
                    _ => None,
                })
                .unwrap();
            assert_eq!(
                q_event.quarantine_window_start, upstream_ts,
                "ArtifactQuarantined event must carry the publish-time anchor — \
                 projection rebuild from the event stream must produce the same \
                 quarantine_window_start as the live row"
            );
        });
    }

    /// Opt-in `true` + `Some(upstream_published_at)` set
    /// 90 days in the past. The anchor is the upstream publish time (90
    /// days ago). The computed deadline (anchor + 24h default duration)
    /// would already be elapsed — but this path only stores the anchor; the
    /// deadline-elapsed effect (early release / fast-path) is the sweep's
    /// territory. This test pins the anchor exclusively.
    #[test]
    fn ingest_opted_in_long_ago_publish_collapses_window() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let content: &[u8] = b"hello world";
        let hash_hex = sha256_of(content);
        let upstream_digest: ContentHash = hash_hex.parse().unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, lifecycle, _storage, repos, _policies, _jobs) =
                make_scan_gated_use_case();
            repos.insert(repo);

            let before = Utc::now();
            let upstream_ts = before - chrono::Duration::days(90);

            let req = VerifiedIngestRequest::ProtocolNative {
                repository_id: repo_id,
                coords: sample_coords(),
                content_type: "application/octet-stream".into(),
                actor: api_actor(),
                payload_metadata: serde_json::Value::Null,
                upstream_digest,
                upstream_published_at: Some(upstream_ts),
                trust_upstream_publish_time: true,
            };

            let artifact = uc
                .ingest_verified(req, content_stream(content), &test_handler())
                .await
                .expect("verified ingest must succeed")
                .artifact;

            assert_eq!(artifact.quarantine_status, QuarantineStatus::Quarantined);
            let anchor = artifact
                .quarantine_window_start
                .expect("publish-anchored quarantine must set quarantine_window_start");
            assert_eq!(
                anchor, upstream_ts,
                "long-ago upstream publish (90 days) is the anchor verbatim — \
                 the anchor is stored here; the deadline-elapsed effect is the sweep's job"
            );

            let transitions = lifecycle.committed_transitions();
            let q_event = transitions
                .iter()
                .flat_map(|(_a, batch, _m)| batch.events.iter())
                .find_map(|e| match &e.event {
                    DomainEvent::ArtifactQuarantined(q) => Some(q),
                    _ => None,
                })
                .expect("ArtifactQuarantined must be on the stream");
            assert_eq!(q_event.quarantine_window_start, upstream_ts);
        });
    }

    /// The **future-skew clamp**. Opt-in `true` +
    /// `Some(upstream_published_at)` 1h *after* ingest (physically
    /// impossible but a buggy or malicious upstream might send it). The
    /// `min(upstream, ingested)` clamp picks the smaller value (ingest)
    /// — a buggy upstream cannot extend its own quarantine into the
    /// future via the opt-in. The anchor must be the ingest timestamp.
    #[test]
    fn ingest_opted_in_future_skew_clamped_to_ingested_at() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let content: &[u8] = b"hello world";
        let hash_hex = sha256_of(content);
        let upstream_digest: ContentHash = hash_hex.parse().unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, lifecycle, _storage, repos, _policies, _jobs) =
                make_scan_gated_use_case();
            repos.insert(repo);

            let before = Utc::now();
            // 1h in the future — physically impossible.
            let upstream_ts = before + chrono::Duration::hours(1);

            let req = VerifiedIngestRequest::ProtocolNative {
                repository_id: repo_id,
                coords: sample_coords(),
                content_type: "application/octet-stream".into(),
                actor: api_actor(),
                payload_metadata: serde_json::Value::Null,
                upstream_digest,
                upstream_published_at: Some(upstream_ts),
                trust_upstream_publish_time: true,
            };

            let artifact = uc
                .ingest_verified(req, content_stream(content), &test_handler())
                .await
                .expect("verified ingest must succeed")
                .artifact;
            let after = Utc::now();

            assert_eq!(artifact.quarantine_status, QuarantineStatus::Quarantined);
            let anchor = artifact
                .quarantine_window_start
                .expect("quarantine must be set");
            // Anchor must be the ingest timestamp (the `min` clamp
            // picked it because the upstream value was larger). The
            // upstream `+1h` value MUST NOT appear anywhere.
            assert!(
                anchor >= before && anchor <= after,
                "future-skew clamp must pick `ingested_at` ({before:?} .. {after:?}), \
                 not the bogus future upstream value ({upstream_ts:?}); got anchor {anchor:?}"
            );
            assert!(
                anchor < upstream_ts,
                "anchor {anchor:?} must be strictly before the bogus upstream value {upstream_ts:?} — \
                 otherwise the clamp didn't fire"
            );

            let transitions = lifecycle.committed_transitions();
            let q_event = transitions
                .iter()
                .flat_map(|(_a, batch, _m)| batch.events.iter())
                .find_map(|e| match &e.event {
                    DomainEvent::ArtifactQuarantined(q) => Some(q),
                    _ => None,
                })
                .expect("ArtifactQuarantined must be on the stream");
            assert_eq!(
                q_event.quarantine_window_start, anchor,
                "event payload must carry the clamped anchor, not the bogus upstream value"
            );
        });
    }

    /// Opt-in `true` + `None` upstream. Best-effort:
    /// the opt-in is on but the format adapter couldn't extract a hint
    /// for this artifact (an old release with no upload_time, a
    /// response without `Last-Modified`, etc.). Degrades to the ingest
    /// anchor; **never fails the ingest**.
    #[test]
    fn ingest_opted_in_absent_upstream_ts_uses_ingest_anchor() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let content: &[u8] = b"hello world";
        let hash_hex = sha256_of(content);
        let upstream_digest: ContentHash = hash_hex.parse().unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, lifecycle, _storage, repos, _policies, _jobs) =
                make_scan_gated_use_case();
            repos.insert(repo);

            let before = Utc::now();

            let req = VerifiedIngestRequest::ProtocolNative {
                repository_id: repo_id,
                coords: sample_coords(),
                content_type: "application/octet-stream".into(),
                actor: api_actor(),
                payload_metadata: serde_json::Value::Null,
                upstream_digest,
                upstream_published_at: None,
                trust_upstream_publish_time: true,
            };

            let artifact = uc
                .ingest_verified(req, content_stream(content), &test_handler())
                .await
                .expect("verified ingest must succeed — None upstream hint is best-effort")
                .artifact;
            let after = Utc::now();

            assert_eq!(artifact.quarantine_status, QuarantineStatus::Quarantined);
            let anchor = artifact
                .quarantine_window_start
                .expect("quarantine must be set");
            assert!(
                anchor >= before && anchor <= after,
                "absent upstream hint degrades to the ingest anchor ({before:?} .. {after:?}); \
                 got {anchor:?}"
            );

            let transitions = lifecycle.committed_transitions();
            let q_event = transitions
                .iter()
                .flat_map(|(_a, batch, _m)| batch.events.iter())
                .find_map(|e| match &e.event {
                    DomainEvent::ArtifactQuarantined(q) => Some(q),
                    _ => None,
                })
                .expect("ArtifactQuarantined must be on the stream");
            assert_eq!(q_event.quarantine_window_start, anchor);
        });
    }

    /// Opt-in `false` + `Some(upstream_published_at)`.
    /// The recording of `upstream_published_at` onto
    /// `Artifact.upstream_published_at` is **unconditional**;
    /// **use** of the value behind `quarantine_window_start` is gated
    /// on the per-upstream opt-in. With the flag off, the anchor MUST
    /// stay at `ingested_at` regardless of the upstream hint.
    #[test]
    fn ingest_not_opted_in_uses_ingest_anchor_regardless() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let content: &[u8] = b"hello world";
        let hash_hex = sha256_of(content);
        let upstream_digest: ContentHash = hash_hex.parse().unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, lifecycle, _storage, repos, _policies, _jobs) =
                make_scan_gated_use_case();
            repos.insert(repo);

            let before = Utc::now();
            let upstream_ts = before - chrono::Duration::days(30);

            let req = VerifiedIngestRequest::ProtocolNative {
                repository_id: repo_id,
                coords: sample_coords(),
                content_type: "application/octet-stream".into(),
                actor: api_actor(),
                payload_metadata: serde_json::Value::Null,
                upstream_digest,
                upstream_published_at: Some(upstream_ts),
                trust_upstream_publish_time: false,
            };

            let artifact = uc
                .ingest_verified(req, content_stream(content), &test_handler())
                .await
                .expect("verified ingest must succeed")
                .artifact;
            let after = Utc::now();

            assert_eq!(artifact.quarantine_status, QuarantineStatus::Quarantined);
            let anchor = artifact
                .quarantine_window_start
                .expect("quarantine must be set");
            assert!(
                anchor >= before && anchor <= after,
                "anchor must be `ingested_at` ({before:?} .. {after:?}) — \
                 the opt-in is OFF so the upstream value ({upstream_ts:?}) must NOT be used; \
                 got {anchor:?}"
            );

            // Recording vs use — the upstream value still rounds onto
            // `Artifact.upstream_published_at` for audit; only
            // the *anchor consumer* is gated.
            assert_eq!(
                artifact.upstream_published_at,
                Some(upstream_ts),
                "upstream_published_at is recorded unconditionally; \
                 only its consumption as the quarantine anchor is gated by the trust opt-in"
            );

            let transitions = lifecycle.committed_transitions();
            let q_event = transitions
                .iter()
                .flat_map(|(_a, batch, _m)| batch.events.iter())
                .find_map(|e| match &e.event {
                    DomainEvent::ArtifactQuarantined(q) => Some(q),
                    _ => None,
                })
                .expect("ArtifactQuarantined must be on the stream");
            assert_eq!(
                q_event.quarantine_window_start, anchor,
                "event payload must carry the ingest anchor"
            );
        });
    }

    /// Direct upload. The `ingest_direct` path passes
    /// `trust_upstream_publish_time = false` unconditionally
    /// (constructed at the `ingest_inner` call site — direct uploads
    /// have no serving `RepositoryUpstreamMapping`). Anchor is the
    /// ingest timestamp; the operator's trust signal does not apply
    /// because pull-through is not in play.
    #[test]
    fn ingest_direct_upload_uses_ingest_anchor() {
        let repo = pypi_repository();
        let repo_id = repo.id;

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, lifecycle, _storage, repos, _policies, _jobs) =
                make_scan_gated_use_case();
            repos.insert(repo);

            let before = Utc::now();
            let artifact = uc
                .ingest_direct(req(repo_id), content_stream(b"x"), &test_handler())
                .await
                .expect("direct ingest must succeed")
                .artifact;
            let after = Utc::now();

            assert_eq!(artifact.quarantine_status, QuarantineStatus::Quarantined);
            let anchor = artifact
                .quarantine_window_start
                .expect("quarantine must be set");
            assert!(
                anchor >= before && anchor <= after,
                "direct upload always anchors to `ingested_at` ({before:?} .. {after:?}); \
                 got {anchor:?}"
            );

            let transitions = lifecycle.committed_transitions();
            let q_event = transitions
                .iter()
                .flat_map(|(_a, batch, _m)| batch.events.iter())
                .find_map(|e| match &e.event {
                    DomainEvent::ArtifactQuarantined(q) => Some(q),
                    _ => None,
                })
                .expect("ArtifactQuarantined must be on the stream");
            assert_eq!(q_event.quarantine_window_start, anchor);
        });
    }

    /// ProtocolNative: hash mismatch → Conflict, ChecksumMismatch on
    /// repository stream, no artifact row minted, CAS rolled back.
    #[test]
    fn ingest_verified_protocol_native_mismatch_emits_repository_event_and_rolls_back() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let content: &[u8] = b"actual content";

        // upstream_digest is NOT the hash of content.
        let upstream_digest: ContentHash =
            "0000000000000000000000000000000000000000000000000000000000000000"
                .parse()
                .unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, events, lifecycle, storage, repos) = make_use_case();
            repos.insert(repo);

            let req = VerifiedIngestRequest::ProtocolNative {
                repository_id: repo_id,
                coords: sample_coords(),
                content_type: "application/octet-stream".into(),
                actor: api_actor(),
                payload_metadata: serde_json::Value::Null,
                upstream_digest,
                upstream_published_at: None,
                trust_upstream_publish_time: false,
            };

            let err = uc
                .ingest_verified(req, content_stream(content), &test_handler())
                .await
                .expect_err("mismatch must fail");

            assert!(
                matches!(err, AppError::Domain(DomainError::Conflict(_))),
                "expected Conflict, got {err:?}"
            );

            // No artifact row was minted (mint-after-verify) —
            // commit_transition was never called.
            assert!(
                lifecycle.committed_transitions().is_empty(),
                "no commit_transition should run on the mismatch path"
            );

            // Storage rolled back.
            assert_eq!(storage.put_call_count(), 1, "put ran to compute the hash");
            assert_eq!(storage.delete_call_count(), 1, "rollback must delete CAS");

            // ChecksumMismatch on the REPOSITORY stream.
            let batches = events.appended_batches();
            let mismatch_count = batches
                .iter()
                .filter(|b| b.stream_id.category == StreamCategory::Repository)
                .flat_map(|b| b.events.iter())
                .filter(|e| matches!(e.event, DomainEvent::ChecksumMismatch(_)))
                .count();
            assert_eq!(
                mismatch_count, 1,
                "exactly one ChecksumMismatch must land on the repository stream"
            );

            // ChecksumVerified must NOT have fired.
            let verified_count = batches
                .iter()
                .flat_map(|b| b.events.iter())
                .filter(|e| matches!(e.event, DomainEvent::ChecksumVerified(_)))
                .count();
            assert_eq!(
                verified_count, 0,
                "ChecksumVerified must NOT fire on the mismatch path"
            );
        });
    }

    /// UpstreamPublished(Sha256): same shape as ProtocolNative — the
    /// arms differ only in where the verification target came from.
    #[test]
    fn ingest_verified_upstream_published_sha256_success() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let content: &[u8] = b"hello world";
        let hash_hex = sha256_of(content);
        let upstream_checksum =
            UpstreamPublishedChecksum::new(HashAlgorithm::Sha256, hash_hex.clone()).unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _events, lifecycle, storage, repos) = make_use_case();
            repos.insert(repo);

            let req = VerifiedIngestRequest::UpstreamPublished {
                repository_id: repo_id,
                coords: sample_coords(),
                content_type: "application/octet-stream".into(),
                actor: api_actor(),
                payload_metadata: serde_json::Value::Null,
                upstream_checksum,
                upstream_published_at: None,
                trust_upstream_publish_time: false,
            };

            let outcome = uc
                .ingest_verified(req, content_stream(content), &test_handler())
                .await
                .expect("upstream-published sha256 success");

            assert_eq!(storage.put_call_count(), 1);
            assert_eq!(outcome.artifact.sha256_checksum.to_string(), hash_hex);
            // Atomic emission: ChecksumVerified rides in the same
            // commit_transition batch as ArtifactIngested; ScanRequested
            // joins it via the DefaultPolicy fallback (see
            // `docs/architecture/explanation/scanning-pipeline.md`).
            let transitions = lifecycle.committed_transitions();
            assert_eq!(transitions.len(), 1);
            let kinds: Vec<&str> = transitions[0]
                .1
                .events
                .iter()
                .map(|e| e.event.event_type())
                .collect();
            assert_eq!(
                kinds,
                vec!["ArtifactIngested", "ChecksumVerified", "ScanRequested"],
            );
        });
    }

    /// SHA-512 of `content` (hex-encoded, lowercase). Used by the
    /// SHA-512 verification-path tests below to construct correct
    /// upstream-published checksums and to assert against the
    /// `computed_value` recorded in the emitted events.
    fn sha512_of(content: &[u8]) -> String {
        use sha2::Digest;
        format!("{:x}", sha2::Sha512::digest(content))
    }

    /// UpstreamPublished(Sha512) success: the stream is wrapped in
    /// `Sha512HashingRead` so the use case can finalise the SHA-512
    /// after `storage.put` consumes the boxed reader; the finalised
    /// hex must match the upstream value, the artifact row must be
    /// minted, and `ArtifactIngested + ChecksumVerified` must land in
    /// the same `commit_transition` batch on the artifact stream
    /// (ADR 0006 atomic emission rule).
    #[test]
    fn ingest_verified_upstream_published_sha512_success() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let content: &[u8] = b"hello world";
        let sha512_hex = sha512_of(content);
        let sha256_hex = sha256_of(content);
        let upstream_checksum =
            UpstreamPublishedChecksum::new(HashAlgorithm::Sha512, sha512_hex.clone()).unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, artifacts, _events, lifecycle, storage, repos) = make_use_case();
            repos.insert(repo);

            let req = VerifiedIngestRequest::UpstreamPublished {
                repository_id: repo_id,
                coords: sample_coords(),
                content_type: "application/octet-stream".into(),
                actor: api_actor(),
                payload_metadata: serde_json::Value::Null,
                upstream_checksum,
                upstream_published_at: None,
                trust_upstream_publish_time: false,
            };

            let outcome = uc
                .ingest_verified(req, content_stream(content), &test_handler())
                .await
                .expect("sha512 success path");

            // Storage saw the bytes once.
            assert_eq!(storage.put_call_count(), 1);
            assert_eq!(storage.delete_call_count(), 0);

            // CAS hash on the row is the SHA-256 — the
            // CAS key remains SHA-256, SHA-512 is verification-only.
            assert_eq!(outcome.artifact.sha256_checksum.to_string(), sha256_hex);

            // Artifact row was minted — the repo can find it by id.
            let row = artifacts.find_by_id(outcome.artifact.id).await.unwrap();
            assert_eq!(row.id, outcome.artifact.id);

            // Atomic emission: ArtifactIngested + ChecksumVerified land
            // in the same `commit_transition` batch on the artifact
            // stream. The SHA-512 path must mirror the SHA-256 path
            // exactly here — that is the audit invariant.
            let transitions = lifecycle.committed_transitions();
            assert_eq!(transitions.len(), 1);
            let (_artifact, batch, _meta) = &transitions[0];
            assert_eq!(batch.stream_id.category, StreamCategory::Artifact);
            let kinds: Vec<&str> = batch.events.iter().map(|e| e.event.event_type()).collect();
            assert_eq!(
                kinds,
                vec!["ArtifactIngested", "ChecksumVerified", "ScanRequested"],
                "ArtifactIngested + ChecksumVerified + ScanRequested (DefaultPolicy \
                 fallback) must land in the same batch",
            );

            // ChecksumVerified carries the algorithm + finalised hex.
            let verified = batch
                .events
                .iter()
                .find_map(|e| match &e.event {
                    DomainEvent::ChecksumVerified(v) => Some(v.clone()),
                    _ => None,
                })
                .expect("ChecksumVerified must be present");
            assert_eq!(verified.algorithm, HashAlgorithm::Sha512);
            assert_eq!(verified.upstream_value, sha512_hex);
            assert_eq!(verified.computed_value, sha512_hex);
            assert_eq!(verified.artifact_id, outcome.artifact.id);
        });
    }

    /// Lowercase-hex SHA-1 of `content`. Mirrors `sha512_of` for the
    /// SHA-1 transfer-verification *floor* tests (ADR 0033) — used to
    /// construct correct upstream-published checksums and to assert the
    /// `computed_value` recorded in the emitted events.
    fn sha1_of(content: &[u8]) -> String {
        use sha1::Digest;
        format!("{:x}", sha1::Sha1::digest(content))
    }

    /// UpstreamPublished(**Sha1**) success — the SHA-1 transfer floor
    /// (ADR 0033, Maven `.sha1` sidecar). The stream is wrapped in
    /// `Sha1HashingRead` so the use case can finalise the SHA-1 after
    /// `storage.put` consumes the boxed reader; the finalised hex must
    /// match the upstream value, the artifact row must be minted, and
    /// `ArtifactIngested + ChecksumVerified` must land in the same
    /// `commit_transition` batch on the artifact stream (ADR 0006 atomic
    /// emission rule). **Crucially the CAS key stays SHA-256** — SHA-1 is
    /// transfer-verification only, never a content-address.
    #[test]
    fn ingest_verified_upstream_published_sha1_success() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let content: &[u8] = b"hello world";
        let sha1_hex = sha1_of(content);
        let sha256_hex = sha256_of(content);
        let upstream_checksum =
            UpstreamPublishedChecksum::new(HashAlgorithm::Sha1, sha1_hex.clone()).unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, artifacts, _events, lifecycle, storage, repos) = make_use_case();
            repos.insert(repo);

            let req = VerifiedIngestRequest::UpstreamPublished {
                repository_id: repo_id,
                coords: sample_coords(),
                content_type: "application/octet-stream".into(),
                actor: api_actor(),
                payload_metadata: serde_json::Value::Null,
                upstream_checksum,
                upstream_published_at: None,
                trust_upstream_publish_time: false,
            };

            let outcome = uc
                .ingest_verified(req, content_stream(content), &test_handler())
                .await
                .expect("sha1 floor success path");

            // Storage saw the bytes once; no rollback.
            assert_eq!(storage.put_call_count(), 1);
            assert_eq!(storage.delete_call_count(), 0);

            // The CAS hash on the row is the SHA-256 of the bytes — the
            // CAS key remains SHA-256, SHA-1 is verification-only. This is
            // the load-bearing assertion: the floor never becomes a
            // content-address.
            assert_eq!(outcome.artifact.sha256_checksum.to_string(), sha256_hex);
            assert_ne!(
                outcome.artifact.sha256_checksum.to_string(),
                sha1_hex,
                "CAS key must never be the SHA-1 floor value"
            );

            // Artifact row was minted — the repo can find it by id.
            let row = artifacts.find_by_id(outcome.artifact.id).await.unwrap();
            assert_eq!(row.id, outcome.artifact.id);

            // Atomic emission: ArtifactIngested + ChecksumVerified land in
            // the same `commit_transition` batch on the artifact stream.
            let transitions = lifecycle.committed_transitions();
            assert_eq!(transitions.len(), 1);
            let (_artifact, batch, _meta) = &transitions[0];
            assert_eq!(batch.stream_id.category, StreamCategory::Artifact);
            let kinds: Vec<&str> = batch.events.iter().map(|e| e.event.event_type()).collect();
            assert_eq!(
                kinds,
                vec!["ArtifactIngested", "ChecksumVerified", "ScanRequested"],
                "ArtifactIngested + ChecksumVerified + ScanRequested (DefaultPolicy \
                 fallback) must land in the same batch",
            );

            // ChecksumVerified carries the SHA-1 algorithm + finalised hex.
            let verified = batch
                .events
                .iter()
                .find_map(|e| match &e.event {
                    DomainEvent::ChecksumVerified(v) => Some(v.clone()),
                    _ => None,
                })
                .expect("ChecksumVerified must be present");
            assert_eq!(verified.algorithm, HashAlgorithm::Sha1);
            assert_eq!(verified.upstream_value, sha1_hex);
            assert_eq!(
                verified.computed_value, sha1_hex,
                "computed_value records the finalised SHA-1, not the CAS SHA-256"
            );
            assert_eq!(verified.artifact_id, outcome.artifact.id);
        });
    }

    /// UpstreamPublished(**Sha1**) mismatch — the finalised SHA-1
    /// disagrees with the upstream-published hex. `Conflict` must surface,
    /// no artifact row may be minted (mint-after-verify), `ChecksumMismatch`
    /// must land on the **repository** stream, the CAS blob must be rolled
    /// back via `storage.delete`, and `ChecksumVerified` must NOT fire.
    /// Mirrors the SHA-512 mismatch test.
    #[test]
    fn ingest_verified_upstream_published_sha1_mismatch_emits_repository_event_and_rolls_back() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let content: &[u8] = b"actual content";

        // 40 hex chars of zero — structurally valid, but definitely not
        // the SHA-1 of `content`.
        let bad_sha1_hex = "0".repeat(40);
        let upstream_checksum =
            UpstreamPublishedChecksum::new(HashAlgorithm::Sha1, bad_sha1_hex.clone()).unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, artifacts, events, lifecycle, storage, repos) = make_use_case();
            repos.insert(repo);

            let req = VerifiedIngestRequest::UpstreamPublished {
                repository_id: repo_id,
                coords: sample_coords(),
                content_type: "application/octet-stream".into(),
                actor: api_actor(),
                payload_metadata: serde_json::Value::Null,
                upstream_checksum,
                upstream_published_at: None,
                trust_upstream_publish_time: false,
            };

            let err = uc
                .ingest_verified(req, content_stream(content), &test_handler())
                .await
                .expect_err("sha1 floor mismatch must fail");

            assert!(
                matches!(err, AppError::Domain(DomainError::Conflict(_))),
                "expected Conflict, got {err:?}"
            );

            // No artifact row was minted (mint-after-verify).
            assert!(
                lifecycle.committed_transitions().is_empty(),
                "no commit_transition must run on the sha1 mismatch path"
            );

            // Storage put ran (to compute the SHA-256 CAS hash and feed
            // bytes through the SHA-1 hasher), then was rolled back.
            assert_eq!(storage.put_call_count(), 1, "put ran to compute hashes");
            assert_eq!(
                storage.delete_call_count(),
                1,
                "rollback must delete the CAS blob"
            );

            // `ChecksumMismatch` lands on the REPOSITORY stream — no
            // artifact stream because no row was minted.
            let batches = events.appended_batches();
            let mismatch_events: Vec<_> = batches
                .iter()
                .filter(|b| b.stream_id.category == StreamCategory::Repository)
                .flat_map(|b| b.events.iter())
                .filter_map(|e| match &e.event {
                    DomainEvent::ChecksumMismatch(m) => Some(m.clone()),
                    _ => None,
                })
                .collect();
            assert_eq!(
                mismatch_events.len(),
                1,
                "exactly one ChecksumMismatch must land on the repository stream"
            );
            let mm = &mismatch_events[0];
            assert_eq!(mm.algorithm, HashAlgorithm::Sha1);
            assert_eq!(mm.upstream_value, bad_sha1_hex);
            assert_eq!(mm.computed_value, sha1_of(content));
            assert_eq!(mm.repository_id, repo_id);
            assert_eq!(mm.format, "pypi");

            // ChecksumVerified must NOT fire on the mismatch path.
            let verified_count = batches
                .iter()
                .flat_map(|b| b.events.iter())
                .filter(|e| matches!(e.event, DomainEvent::ChecksumVerified(_)))
                .count();
            assert_eq!(
                verified_count, 0,
                "ChecksumVerified must NOT fire on the mismatch path"
            );

            // No artifact row exists — `list_by_repository` returns an
            // empty page (mint-after-verify).
            let page = artifacts
                .list_by_repository(
                    repo_id,
                    hort_domain::types::PageRequest {
                        offset: 0,
                        limit: 100,
                    },
                )
                .await
                .unwrap();
            assert_eq!(
                page.total, 0,
                "no artifact row may be present after mismatch"
            );
        });
    }

    /// UpstreamPublished(Sha512) mismatch: the finalised SHA-512
    /// disagrees with the upstream-published hex — `Conflict` must
    /// surface, no artifact row may be minted (mint-after-verify),
    /// `ChecksumMismatch` must land on the **repository** stream
    /// (`StreamId::repository(repo_id)`), the CAS blob must be rolled
    /// back via `storage.delete`, and `ChecksumVerified` must NOT fire.
    #[test]
    fn ingest_verified_upstream_published_sha512_mismatch_emits_repository_event_and_rolls_back() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let content: &[u8] = b"actual content";

        // 128 hex chars of zero — definitely not the SHA-512 of
        // `content`, but a structurally valid value the constructor
        // accepts.
        let bad_sha512_hex = "0".repeat(128);
        let upstream_checksum =
            UpstreamPublishedChecksum::new(HashAlgorithm::Sha512, bad_sha512_hex.clone()).unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, artifacts, events, lifecycle, storage, repos) = make_use_case();
            repos.insert(repo);

            let req = VerifiedIngestRequest::UpstreamPublished {
                repository_id: repo_id,
                coords: sample_coords(),
                content_type: "application/octet-stream".into(),
                actor: api_actor(),
                payload_metadata: serde_json::Value::Null,
                upstream_checksum,
                upstream_published_at: None,
                trust_upstream_publish_time: false,
            };

            let err = uc
                .ingest_verified(req, content_stream(content), &test_handler())
                .await
                .expect_err("sha512 mismatch must fail");

            assert!(
                matches!(err, AppError::Domain(DomainError::Conflict(_))),
                "expected Conflict, got {err:?}"
            );

            // No artifact row was minted — `commit_transition` was
            // never called (mint-after-verify).
            assert!(
                lifecycle.committed_transitions().is_empty(),
                "no commit_transition must run on the sha512 mismatch path"
            );

            // Storage put ran (to compute the SHA-256 CAS hash and
            // feed bytes through the SHA-512 hasher), then was rolled
            // back via delete.
            assert_eq!(storage.put_call_count(), 1, "put ran to compute hashes");
            assert_eq!(
                storage.delete_call_count(),
                1,
                "rollback must delete the CAS blob"
            );

            // `ChecksumMismatch` lands on the REPOSITORY stream — there
            // is no artifact stream because no row was minted.
            let batches = events.appended_batches();
            let mismatch_events: Vec<_> = batches
                .iter()
                .filter(|b| b.stream_id.category == StreamCategory::Repository)
                .flat_map(|b| b.events.iter())
                .filter_map(|e| match &e.event {
                    DomainEvent::ChecksumMismatch(m) => Some(m.clone()),
                    _ => None,
                })
                .collect();
            assert_eq!(
                mismatch_events.len(),
                1,
                "exactly one ChecksumMismatch must land on the repository stream"
            );
            let mm = &mismatch_events[0];
            assert_eq!(mm.algorithm, HashAlgorithm::Sha512);
            assert_eq!(mm.upstream_value, bad_sha512_hex);
            assert_eq!(mm.computed_value, sha512_of(content));
            assert_eq!(mm.repository_id, repo_id);
            assert_eq!(mm.format, "pypi");

            // ChecksumVerified must NOT fire on the mismatch path.
            let verified_count = batches
                .iter()
                .flat_map(|b| b.events.iter())
                .filter(|e| matches!(e.event, DomainEvent::ChecksumVerified(_)))
                .count();
            assert_eq!(
                verified_count, 0,
                "ChecksumVerified must NOT fire on the mismatch path"
            );

            // No artifact row exists — `list_by_repository` returns
            // an empty page (no row was ever minted, mint-after-verify).
            // Stronger than `find_by_id` on a random UUID because it
            // proves the absence universally rather than for one id.
            let page = artifacts
                .list_by_repository(
                    repo_id,
                    hort_domain::types::PageRequest {
                        offset: 0,
                        limit: 100,
                    },
                )
                .await
                .unwrap();
            assert_eq!(
                page.total, 0,
                "no artifact row may be present after mismatch"
            );
        });
    }

    /// Regression test: `ChecksumMismatch` audit
    /// emission is gated by the typed `InnerIngestError::VerificationMismatch`
    /// variant, NOT by substring-matching `computed=` against the
    /// inner `Conflict` message. The previous discriminator at the
    /// `ingest_with_verification` outer match was
    /// `if msg.contains("computed=")`, which would have silently
    /// disabled audit emission for an entire arm if a future refactor
    /// reworded the inner Conflict message — the wire response and
    /// the `hort_upstream_checksum_total{result=mismatch}` metric would
    /// still fire, but the audit trail would silently break.
    ///
    /// This test pins the audit invariant on the typed variant by
    /// driving a SHA-256 verification mismatch through the public
    /// `ingest_verified` path with a tampered upstream digest, and
    /// asserting:
    ///
    /// 1. Exactly one `ChecksumMismatch` lands on the repository stream
    ///    (no artifact stream — mint-after-verify).
    /// 2. `algorithm = Sha256` — the typed field, not parsed from any
    ///    string.
    /// 3. `computed_value` equals the actual computed SHA-256 of the
    ///    bytes (the field carries the value directly, no parsing).
    /// 4. `upstream_value` equals the declared digest the caller
    ///    supplied.
    ///
    /// Because the assertions read the typed fields and never the
    /// `Display` of the surfaced `AppError`, the test would still pass
    /// after any reword of the inner Conflict message — that is the
    /// post-refactor invariant the test pins.
    #[test]
    fn verified_ingest_emits_mismatch_event_via_typed_variant_not_message_substring() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let content: &[u8] = b"actual content";

        // 64 hex chars of zero — a structurally valid SHA-256 that is
        // definitely not the SHA-256 of `content`. ProtocolNative
        // takes a `ContentHash` (parsed from hex), so any well-formed
        // hex of the right length works.
        let bad_digest: ContentHash =
            "0000000000000000000000000000000000000000000000000000000000000000"
                .parse()
                .unwrap();
        let bad_digest_hex = bad_digest.to_string();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, events, lifecycle, storage, repos) = make_use_case();
            repos.insert(repo);

            let req = VerifiedIngestRequest::ProtocolNative {
                repository_id: repo_id,
                coords: sample_coords(),
                content_type: "application/octet-stream".into(),
                actor: api_actor(),
                payload_metadata: serde_json::Value::Null,
                upstream_digest: bad_digest,
                upstream_published_at: None,
                trust_upstream_publish_time: false,
            };

            let err = uc
                .ingest_verified(req, content_stream(content), &test_handler())
                .await
                .expect_err("sha256 verification mismatch must fail");

            // Surface preserved: the original
            // `AppError::Domain(Conflict(...))` from `ingest_inner`
            // came back unchanged. We DO NOT inspect the `Display`
            // string here — the typed-variant invariant is precisely
            // that the audit emission below cannot depend on it.
            assert!(
                matches!(err, AppError::Domain(DomainError::Conflict(_))),
                "expected Conflict, got {err:?}"
            );

            // Mint-after-verify: no artifact row, no commit_transition.
            assert!(
                lifecycle.committed_transitions().is_empty(),
                "no commit_transition must run on the sha256 mismatch path"
            );

            // Storage put ran once and was rolled back via delete.
            assert_eq!(storage.put_call_count(), 1);
            assert_eq!(storage.delete_call_count(), 1);

            // Exactly one ChecksumMismatch on the repository stream.
            let batches = events.appended_batches();
            let mismatch_events: Vec<_> = batches
                .iter()
                .filter(|b| b.stream_id.category == StreamCategory::Repository)
                .flat_map(|b| b.events.iter())
                .filter_map(|e| match &e.event {
                    DomainEvent::ChecksumMismatch(m) => Some(m.clone()),
                    _ => None,
                })
                .collect();
            assert_eq!(
                mismatch_events.len(),
                1,
                "exactly one ChecksumMismatch must land on the repository stream"
            );
            let mm = &mismatch_events[0];

            // The typed-variant invariants:
            //
            //   - `algorithm` is the typed `HashAlgorithm` field — not
            //     parsed out of any string.
            //   - `computed_value` equals the actual computed SHA-256
            //     of `content` — carried as a typed field, not
            //     extracted via a `computed=` substring search.
            //   - `upstream_value` equals the caller-declared digest.
            //
            // None of these reads depend on the `Display` of the
            // returned `AppError`. A future reword of the inner
            // `Conflict` message would not affect any of them.
            assert_eq!(mm.algorithm, HashAlgorithm::Sha256);
            assert_eq!(mm.computed_value, sha256_of(content));
            assert_eq!(mm.upstream_value, bad_digest_hex);
            assert_eq!(mm.repository_id, repo_id);
            assert_eq!(mm.format, "pypi");
        });
    }

    /// `hort_upstream_checksum_total{format,result=verified}` ticks once
    /// on the SHA-512 success path. Mirrors the SHA-256 emission test
    /// so the metric invariant covers both algorithms.
    #[test]
    fn ingest_verified_sha512_emits_upstream_checksum_metric_on_verified() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let content: &[u8] = b"hello world";
        let sha512_hex = sha512_of(content);

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, _artifacts, _events, _lifecycle, _storage, repos) = make_use_case();
                repos.insert(repo);
                let upstream_checksum =
                    UpstreamPublishedChecksum::new(HashAlgorithm::Sha512, sha512_hex).unwrap();
                let req = VerifiedIngestRequest::UpstreamPublished {
                    repository_id: repo_id,
                    coords: sample_coords(),
                    content_type: "application/octet-stream".into(),
                    actor: api_actor(),
                    payload_metadata: serde_json::Value::Null,
                    upstream_checksum,
                    upstream_published_at: None,

                    trust_upstream_publish_time: false,
                };
                uc.ingest_verified(req, content_stream(content), &test_handler())
                    .await
                    .expect("sha512 success");
            });
        });
        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_upstream_checksum_total",
            &[("format", "pypi"), ("result", "verified")],
            1,
        );
    }

    /// `hort_upstream_checksum_total{format,result=mismatch}` ticks once
    /// on the SHA-512 mismatch path.
    #[test]
    fn ingest_verified_sha512_emits_upstream_checksum_metric_on_mismatch() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let bad_sha512_hex = "0".repeat(128);

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, _artifacts, _events, _lifecycle, _storage, repos) = make_use_case();
                repos.insert(repo);
                let upstream_checksum =
                    UpstreamPublishedChecksum::new(HashAlgorithm::Sha512, bad_sha512_hex).unwrap();
                let req = VerifiedIngestRequest::UpstreamPublished {
                    repository_id: repo_id,
                    coords: sample_coords(),
                    content_type: "application/octet-stream".into(),
                    actor: api_actor(),
                    payload_metadata: serde_json::Value::Null,
                    upstream_checksum,
                    upstream_published_at: None,

                    trust_upstream_publish_time: false,
                };
                let _ = uc
                    .ingest_verified(req, content_stream(b"actual content"), &test_handler())
                    .await;
            });
        });
        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_upstream_checksum_total",
            &[("format", "pypi"), ("result", "mismatch")],
            1,
        );
    }

    /// hort_upstream_checksum_total emits exactly once per arm with the
    /// catalog-canonical labels.
    #[test]
    fn ingest_verified_emits_upstream_checksum_metric() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let content: &[u8] = b"hello world";
        let hash_hex = sha256_of(content);
        let upstream_digest: ContentHash = hash_hex.parse().unwrap();

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, _artifacts, _events, _lifecycle, _storage, repos) = make_use_case();
                repos.insert(repo);
                let req = VerifiedIngestRequest::ProtocolNative {
                    repository_id: repo_id,
                    coords: sample_coords(),
                    content_type: "application/octet-stream".into(),
                    actor: api_actor(),
                    payload_metadata: serde_json::Value::Null,
                    upstream_digest,
                    upstream_published_at: None,

                    trust_upstream_publish_time: false,
                };
                uc.ingest_verified(req, content_stream(content), &test_handler())
                    .await
                    .expect("verified");
            });
        });
        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_upstream_checksum_total",
            &[("format", "pypi"), ("result", "verified")],
            1,
        );
    }

    #[test]
    fn ingest_verified_mismatch_emits_upstream_checksum_metric() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let bad_digest: ContentHash =
            "0000000000000000000000000000000000000000000000000000000000000000"
                .parse()
                .unwrap();

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, _artifacts, _events, _lifecycle, _storage, repos) = make_use_case();
                repos.insert(repo);
                let req = VerifiedIngestRequest::ProtocolNative {
                    repository_id: repo_id,
                    coords: sample_coords(),
                    content_type: "application/octet-stream".into(),
                    actor: api_actor(),
                    payload_metadata: serde_json::Value::Null,
                    upstream_digest: bad_digest,
                    upstream_published_at: None,

                    trust_upstream_publish_time: false,
                };
                let _ = uc
                    .ingest_verified(req, content_stream(b"actual content"), &test_handler())
                    .await;
            });
        });
        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_upstream_checksum_total",
            &[("format", "pypi"), ("result", "mismatch")],
            1,
        );
    }

    /// Audit invariant (ADR 0006): the `repository:<repo_id>`
    /// stream is a long-lived aggregate that accumulates
    /// `ChecksumMismatch` audit events forever. The workspace-wide
    /// `STREAM_EVENT_CAP` (200) is calibrated for *artifact* streams
    /// (finite lifecycle, ~5–10 events). Capping the audit stream would
    /// silently drop mismatch events past the 200th — exactly when an
    /// audit trail matters most (sustained tampering = many events). The
    /// "auditors run … get zero rows by design" invariant requires
    /// uncapped emission on the repository aggregate.
    ///
    /// This test seeds STREAM_EVENT_CAP+1 (201) prior events on a
    /// repository stream — i.e. the stream is *already past* the cap
    /// when the test starts — and then drives 49 more `ChecksumMismatch`
    /// appends through `append_repository_event`, for a total audit
    /// history of STREAM_EVENT_CAP + 50 = 250 events. With
    /// `enforce_cap=true` (the bug), every one of these calls fails
    /// `Conflict("stream … exceeds 200-event cap")` because the cap
    /// gate triggers when stream length is strictly greater than the
    /// cap. With `enforce_cap=false` (the fix), all 49 succeed and the
    /// audit history grows unbounded as the invariant requires.
    #[tokio::test]
    async fn repository_audit_stream_accepts_more_than_stream_event_cap_events() {
        use crate::use_cases::STREAM_EVENT_CAP;
        use hort_domain::events::PersistedEvent;
        use hort_domain::ports::event_store::ReadFrom;

        let repo = pypi_repository();
        let repo_id = repo.id;
        let (uc, _artifacts, events, _lifecycle, _storage, repos) = make_use_case();
        repos.insert(repo);

        // Seed STREAM_EVENT_CAP + 1 (201) prior audit events on the
        // repository stream. The mock's `read_expected_version` reads
        // these via `read_stream`; with 201 events the cap check
        // (`stream_events.len() > STREAM_EVENT_CAP`) trips on every
        // single append when `enforce_cap=true`. The fix is the only
        // thing that lets the next append succeed.
        let stream_id = StreamId::repository(repo_id);
        let prior = STREAM_EVENT_CAP + 1;
        let seeded: Vec<PersistedEvent> = (0..prior)
            .map(|pos| dummy_persisted_event(&stream_id, repo_id, pos))
            .collect();
        events.set_stream(&stream_id, seeded);

        // Drive 49 ChecksumMismatch appends past the cap. With the
        // `enforce_cap=true` bug every call returns `Conflict`; with
        // the fix every call returns `Ok(())`. Total audit history at
        // the end is STREAM_EVENT_CAP + 50 = 250 events.
        let extra = 49_u64;
        for _ in 0..extra {
            let evt = ChecksumMismatch {
                repository_id: repo_id,
                coords: sample_coords(),
                format: "pypi".into(),
                algorithm: HashAlgorithm::Sha256,
                upstream_value: "deadbeef".into(),
                computed_value: "cafef00d".into(),
            };
            uc.append_repository_event(
                repo_id,
                DomainEvent::ChecksumMismatch(evt),
                Actor::Api(api_actor()),
            )
            .await
            .expect("audit-stream append must succeed past STREAM_EVENT_CAP");
        }

        // All `extra` new appends landed on the Repository stream and
        // all are ChecksumMismatch — the audit invariant.
        let appended = events.appended_batches();
        let new_mismatches = appended
            .iter()
            .filter(|b| b.stream_id.category == StreamCategory::Repository)
            .flat_map(|b| b.events.iter())
            .filter(|e| matches!(e.event, DomainEvent::ChecksumMismatch(_)))
            .count() as u64;
        assert_eq!(
            new_mismatches, extra,
            "expected {extra} new ChecksumMismatch appends past the cap"
        );

        // The repository audit history — seeded prior + new appends —
        // totals STREAM_EVENT_CAP + 50 = 250 events, which is strictly
        // past the workspace cap. That an append at this depth was
        // accepted at all is exactly the unbounded-audit invariant.
        let seeded_count = events
            .read_stream(&stream_id, ReadFrom::Start, 1000)
            .await
            .expect("read_stream must not fail")
            .len() as u64;
        assert_eq!(
            seeded_count + new_mismatches,
            STREAM_EVENT_CAP + 50,
            "audit stream must total STREAM_EVENT_CAP + 50 events"
        );
    }

    // ----- Ingest-time scan auto-enqueue ---------------------------------

    /// Build a minimal active `ScanPolicyProjection` with `PolicyScope::Global`.
    /// Mirrors `scan_orchestration_tests::seed_global_policy` — reproduced
    /// inline because importing across the test-module boundary is
    /// awkward and the body is small.
    fn global_scan_policy() -> ScanPolicyProjection {
        use hort_domain::entities::scan_policy::{
            NegligibleAction, ProvenanceMode, SeverityThreshold,
        };
        ScanPolicyProjection {
            policy_id: Uuid::new_v4(),
            name: format!("scan-gated-ingest-test-{}", Uuid::new_v4()),
            scope: PolicyScope::Global,
            severity_threshold: SeverityThreshold::High,
            quarantine_duration_secs: 24 * 3600,
            require_approval: false,
            provenance_mode: ProvenanceMode::VerifyIfPresent,
            provenance_backends: vec!["cosign".to_string()],
            provenance_identities: Vec::new(),
            max_artifact_age_secs: None,
            license_policy: serde_json::Value::Null,
            archived: false,
            scan_backends: vec!["osv".to_string()],
            rescan_interval_hours: 24,
            negligible_action: NegligibleAction::Ignore,
            stream_version: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// Build an `IngestUseCase` wired with an explicit
    /// `MockPolicyProjectionRepository` + `MockJobsRepository` so the
    /// caller can seed an active `ScanPolicy` and assert post-ingest
    /// enqueue calls. Returns the assertion surfaces (`lifecycle` for
    /// committed-events introspection + `policy` + `jobs` for direct
    /// access). Self-contained — does not delegate to the shared
    /// `make_use_case` helpers because none of them expose the policy
    /// + jobs Arcs back to the caller.
    #[allow(clippy::type_complexity)]
    fn make_scan_gated_use_case() -> (
        IngestUseCase,
        Arc<MockArtifactRepository>,
        Arc<MockArtifactLifecycle>,
        Arc<MockStoragePort>,
        Arc<MockRepositoryRepository>,
        Arc<MockPolicyProjectionRepository>,
        Arc<MockJobsRepository>,
    ) {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let events = Arc::new(MockEventStore::new());
        let lifecycle = Arc::new(MockArtifactLifecycle::new(artifacts.clone()));
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let groups = Arc::new(MockArtifactGroupRepository::new());
        let group_lifecycle = Arc::new(MockArtifactGroupLifecyclePort::new(groups.clone()));
        let group_use_case = Arc::new(ArtifactGroupUseCase::new(groups, group_lifecycle, true));
        let curation_rules = Arc::new(MockCurationRuleRepository::new());
        let content_references = Arc::new(MockContentReferenceIndex::new());
        let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
        let jobs = Arc::new(MockJobsRepository::default());

        let uc = IngestUseCase::new(
            storage.clone(),
            lifecycle.clone(),
            artifacts.clone(),
            repos.clone(),
            crate::event_store_publisher::wrap_for_test(events.clone()),
            curation_rules,
            group_use_case,
            true,
            HashMap::new(),
            0,
            content_references,
            policy_projections.clone(),
            jobs.clone(),
        );
        (
            uc,
            artifacts,
            lifecycle,
            storage,
            repos,
            policy_projections,
            jobs,
        )
    }

    #[test]
    fn ingest_verified_with_active_scan_policy_emits_scan_requested_and_enqueues_job() {
        // Happy path: a global ScanPolicy is active → ingest_verified
        // appends `ScanRequested` to the same commit batch as
        // `ArtifactIngested` + `ChecksumVerified` AND calls
        // `JobsRepository::enqueue_scan` with `trigger_source="ingest"`.
        let repo = pypi_repository();
        let repo_id = repo.id;
        let content: &[u8] = b"vulnerable payload";
        let hash_hex = sha256_of(content);
        let upstream_digest: ContentHash = hash_hex.parse().unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, lifecycle, _storage, repos, policy_projections, _jobs) =
                make_scan_gated_use_case();
            repos.insert(repo);
            // Seed a global ScanPolicy. The ingest path's policy
            // resolver picks this up via `list_active`.
            policy_projections.insert(global_scan_policy());

            let req = VerifiedIngestRequest::ProtocolNative {
                repository_id: repo_id,
                coords: sample_coords(),
                content_type: "application/octet-stream".into(),
                actor: sample_actor(),
                payload_metadata: serde_json::Value::Null,
                upstream_digest: upstream_digest.clone(),
                upstream_published_at: None,
                trust_upstream_publish_time: false,
            };

            let outcome = uc
                .ingest_verified(req, content_stream(content), &test_handler())
                .await
                .expect("ingest must succeed with valid upstream digest");

            // Event-side assertion: ScanRequested joins the same
            // commit_transition batch as ArtifactIngested + ChecksumVerified.
            // Since the seeded `global_scan_policy()` carries
            // `quarantine_duration_secs = 24 * 3600` (strict mode), a
            // second `commit_transition` lands the `ArtifactQuarantined`
            // event — the quarantine transition is policy-driven
            // (`quarantine_duration_secs` on the matched policy).
            let transitions = lifecycle.committed_transitions();
            assert_eq!(
                transitions.len(),
                2,
                "two commit_transition calls in strict mode: ingest batch + quarantine batch"
            );
            let kinds_ingest: Vec<&str> = transitions[0]
                .1
                .events
                .iter()
                .map(|e| e.event.event_type())
                .collect();
            assert_eq!(
                kinds_ingest,
                vec!["ArtifactIngested", "ChecksumVerified", "ScanRequested"],
                "ScanRequested must land atomically with the ingest events",
            );
            let kinds_quarantine: Vec<&str> = transitions[1]
                .1
                .events
                .iter()
                .map(|e| e.event.event_type())
                .collect();
            assert_eq!(
                kinds_quarantine,
                vec!["ArtifactQuarantined"],
                "policy-driven quarantine must follow the ingest batch",
            );

            // The scan job is enqueued ATOMICALLY with the transition (no
            // longer a separate jobs-mock call), carrying the right shape.
            // `repository_id`/`content_hash` are taken from the committed
            // artifact, so they cannot drift from the enqueue.
            let scans = lifecycle.scan_enqueues();
            assert_eq!(scans.len(), 1, "exactly one scan enqueue");
            assert_eq!(scans[0].0, outcome.artifact.id);
            assert_eq!(scans[0].1, "pypi");
            assert_eq!(scans[0].3, "ingest");
        });
    }

    /// quarantineDuration-0 permissive mode.
    ///
    /// When a matched `ScanPolicy` carries `quarantine_duration_secs ==
    /// 0`, the artifact ingests downloadable (stays at
    /// `QuarantineStatus::None`) and the scan job is still enqueued.
    /// Bad findings later transition `None → Rejected` via the relaxed
    /// `Artifact::reject_from_scan`. The vulnerability-scan smoke
    /// configures this mode explicitly (`quarantineDuration: 0s` on the
    /// test ScanPolicy) so the released-transition path doesn't depend
    /// on a real wall-clock wait.
    #[test]
    fn ingest_verified_with_policy_quarantine_duration_zero_skips_quarantine_transition() {
        let repo = pypi_repository();
        let repo_id = repo.id;
        let content: &[u8] = b"vulnerable payload";
        let hash_hex = sha256_of(content);
        let upstream_digest: ContentHash = hash_hex.parse().unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, lifecycle, _storage, repos, policy_projections, _jobs) =
                make_scan_gated_use_case();
            repos.insert(repo);
            // Permissive policy: scanBackends set, but no quarantine hold.
            let mut permissive = global_scan_policy();
            permissive.quarantine_duration_secs = 0;
            policy_projections.insert(permissive);

            let req = VerifiedIngestRequest::ProtocolNative {
                repository_id: repo_id,
                coords: sample_coords(),
                content_type: "application/octet-stream".into(),
                actor: sample_actor(),
                payload_metadata: serde_json::Value::Null,
                upstream_digest: upstream_digest.clone(),
                upstream_published_at: None,
                trust_upstream_publish_time: false,
            };

            uc.ingest_verified(req, content_stream(content), &test_handler())
                .await
                .expect("ingest must succeed under permissive policy");

            // Only one commit — no policy-driven quarantine event.
            let transitions = lifecycle.committed_transitions();
            assert_eq!(
                transitions.len(),
                1,
                "permissive mode: ingest commits once; no ArtifactQuarantined event"
            );
            let kinds: Vec<&str> = transitions[0]
                .1
                .events
                .iter()
                .map(|e| e.event.event_type())
                .collect();
            assert_eq!(
                kinds,
                vec!["ArtifactIngested", "ChecksumVerified", "ScanRequested"],
                "ingest batch shape unchanged — only the quarantine batch is skipped",
            );

            // The scan job is still enqueued — permissive mode opts out
            // of the hold, NOT out of scanning.
            assert_eq!(lifecycle.scan_enqueues().len(), 1);
        });
    }

    #[test]
    fn ingest_verified_without_active_scan_policy_enqueues_default_scan() {
        // With NO operator ScanPolicy the hardcoded `DefaultPolicy`
        // applies on TWO axes (ADR 0007):
        //
        //   1. Scan-backend list: `["trivy"]` → ingest appends
        //      `ScanRequested` (scanner = "default") and enqueues a
        //      `kind='scan'` job.
        //   2. Quarantine duration: `86_400` (24h) → ingest commits a
        //      follow-on `ArtifactQuarantined` event —
        //      out-of-the-box deployments are quarantine-by-default.
        //
        // An earlier shape of this test asserted "DefaultPolicy has no
        // quarantine hold" → exactly 1 commit. That clause has been
        // retired; the assertion now mirrors the strict-policy shape
        // (ingest commit + quarantine commit) plus the
        // `scanner="default"` attribution.
        let repo = pypi_repository();
        let repo_id = repo.id;
        let content: &[u8] = b"clean payload";
        let hash_hex = sha256_of(content);
        let upstream_digest: ContentHash = hash_hex.parse().unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, lifecycle, _storage, repos, _policy_projections, _jobs) =
                make_scan_gated_use_case();
            repos.insert(repo);
            // Intentionally NO policy_projections.insert(...) — the
            // Default policy fires on both axes.

            let req = VerifiedIngestRequest::ProtocolNative {
                repository_id: repo_id,
                coords: sample_coords(),
                content_type: "application/octet-stream".into(),
                actor: sample_actor(),
                payload_metadata: serde_json::Value::Null,
                upstream_digest: upstream_digest.clone(),
                upstream_published_at: None,
                trust_upstream_publish_time: false,
            };

            uc.ingest_verified(req, content_stream(content), &test_handler())
                .await
                .expect("ingest must succeed");

            // Default-policy fire: two commits, with the second being
            // the policy-driven `ArtifactQuarantined`.
            let transitions = lifecycle.committed_transitions();
            assert_eq!(
                transitions.len(),
                2,
                "no operator policy: DefaultPolicy fires (ingest batch + quarantine batch)",
            );
            let (_a, ingest_batch, _meta) = &transitions[0];
            let kinds_ingest: Vec<&str> = ingest_batch
                .events
                .iter()
                .map(|e| e.event.event_type())
                .collect();
            assert_eq!(
                kinds_ingest,
                vec!["ArtifactIngested", "ChecksumVerified", "ScanRequested"],
                "ScanRequested must be appended under the DefaultPolicy fallback",
            );
            let scanner = ingest_batch
                .events
                .iter()
                .find_map(|e| match &e.event {
                    DomainEvent::ScanRequested(sr) => Some(sr.scanner.clone()),
                    _ => None,
                })
                .expect("ScanRequested present");
            assert_eq!(
                scanner, "default",
                "scanner attribution is \"default\" when DefaultPolicy fired",
            );

            let kinds_quarantine: Vec<&str> = transitions[1]
                .1
                .events
                .iter()
                .map(|e| e.event.event_type())
                .collect();
            assert_eq!(
                kinds_quarantine,
                vec!["ArtifactQuarantined"],
                "DefaultPolicy (quarantine-by-default, ADR 0007) drives a quarantine transition",
            );

            let scans = lifecycle.scan_enqueues();
            assert_eq!(
                scans.len(),
                1,
                "scan enqueue must run under the DefaultPolicy fallback",
            );
            assert_eq!(scans[0].3, "ingest");
        });
    }

    #[test]
    fn ingest_verified_with_empty_scan_backends_policy_skips_scan() {
        // A matched operator policy with `scan_backends: []` is an
        // explicit scanning waiver: no `ScanRequested`, no enqueue.
        // Distinct from "no policy" (which falls back to DefaultPolicy).
        let repo = pypi_repository();
        let repo_id = repo.id;
        let content: &[u8] = b"clean payload";
        let hash_hex = sha256_of(content);
        let upstream_digest: ContentHash = hash_hex.parse().unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, lifecycle, _storage, repos, policy_projections, _jobs) =
                make_scan_gated_use_case();
            repos.insert(repo);
            // Waiver policy: scanning explicitly disabled, no hold.
            let mut waived = global_scan_policy();
            waived.scan_backends = vec![];
            waived.quarantine_duration_secs = 0;
            policy_projections.insert(waived);

            let req = VerifiedIngestRequest::ProtocolNative {
                repository_id: repo_id,
                coords: sample_coords(),
                content_type: "application/octet-stream".into(),
                actor: sample_actor(),
                payload_metadata: serde_json::Value::Null,
                upstream_digest: upstream_digest.clone(),
                upstream_published_at: None,
                trust_upstream_publish_time: false,
            };

            uc.ingest_verified(req, content_stream(content), &test_handler())
                .await
                .expect("ingest must succeed");

            let transitions = lifecycle.committed_transitions();
            assert_eq!(transitions.len(), 1);
            let (_a, batch, _meta) = &transitions[0];
            let kinds: Vec<&str> = batch.events.iter().map(|e| e.event.event_type()).collect();
            assert_eq!(
                kinds,
                vec!["ArtifactIngested", "ChecksumVerified"],
                "scan_backends:[] is an explicit waiver — no ScanRequested",
            );
            assert!(
                lifecycle.scan_enqueues().is_empty(),
                "enqueue_scan must NOT run when the policy waives scanning",
            );
        });
    }

    // =====================================================================
    // Cascade enqueue post-hook (see
    // `docs/architecture/explanation/prefetch-pipeline.md`)
    // =====================================================================
    //
    // The post-`commit_transition` hook in `ingest_inner` enqueues a
    // root `prefetch-dependencies` job per ingested artifact when
    // `repo.prefetch_policy.triggers` contains `TransitiveDeps`. The
    // tests below pin both directions of the gate: trigger present →
    // exactly one enqueue with the right shape; trigger absent → no
    // enqueue (the inert default).

    fn repo_with_transitive_deps_trigger() -> Repository {
        let mut repo = pypi_repository();
        repo.prefetch_policy = hort_domain::entities::repository::PrefetchPolicy {
            enabled: true,
            triggers: vec![hort_domain::entities::repository::PrefetchTrigger::TransitiveDeps],
            depth: 3,
            transitive_depth: 5,
            max_age_days: None,
            // Production default (ADR 0016).
            max_descendants: hort_domain::entities::repository::PrefetchPolicy::default()
                .max_descendants,
        };
        repo
    }

    #[test]
    fn item_12b_cascade_hook_enqueues_prefetch_dependencies_on_transitive_deps_trigger() {
        let repo = repo_with_transitive_deps_trigger();
        let repo_id = repo.id;

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _lifecycle, _storage, repos, policy_projections, jobs) =
                make_scan_gated_use_case();
            repos.insert(repo);
            // Permissive policy so the ingest's quarantine step
            // doesn't trip the test fixture's mock.
            seed_permissive_global_policy(&policy_projections);

            uc.ingest_direct(req(repo_id), content_stream(b"x"), &test_handler())
                .await
                .expect("ingest");

            let enqueue_calls = jobs.enqueue_calls();
            let cascade_calls: Vec<_> = enqueue_calls
                .iter()
                .filter(|(kind, _, _)| kind == "prefetch-dependencies")
                .collect();
            assert_eq!(
                cascade_calls.len(),
                1,
                "exactly one cascade enqueue per ingest \
                 when TransitiveDeps trigger is configured; got {enqueue_calls:?}"
            );
            // Params shape: {artifact_id, current_depth: 0}.
            let (_kind, params, actor_id) = cascade_calls[0];
            assert!(
                params.get("artifact_id").and_then(|v| v.as_str()).is_some(),
                "params must carry artifact_id; got {params:?}"
            );
            assert_eq!(params["current_depth"], 0);
            assert!(actor_id.is_none(), "cascade hook is system-driven");
        });
    }

    #[test]
    fn item_12b_cascade_hook_silent_when_transitive_deps_trigger_absent() {
        // Default `PrefetchPolicy` has no triggers → no cascade enqueue.
        let repo = pypi_repository();
        let repo_id = repo.id;

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _lifecycle, _storage, repos, policy_projections, jobs) =
                make_scan_gated_use_case();
            repos.insert(repo);
            seed_permissive_global_policy(&policy_projections);

            uc.ingest_direct(req(repo_id), content_stream(b"x"), &test_handler())
                .await
                .expect("ingest");

            let cascade_calls: Vec<_> = jobs
                .enqueue_calls()
                .into_iter()
                .filter(|(kind, _, _)| kind == "prefetch-dependencies")
                .collect();
            assert_eq!(
                cascade_calls.len(),
                0,
                "cascade enqueue MUST be silent when the \
                 TransitiveDeps trigger is absent (the default policy)"
            );
        });
    }

    #[test]
    fn cascade_seed_hook_suppressed_for_cascade_internal_verified_ingest() {
        // A `prefetch` leaf-ingest that is CASCADE-INTERNAL
        // (trigger_source "prefetch") marks `cascade_internal: true` in its
        // payload_metadata. The artifact it ingests is already covered by
        // its parent walk's depth-carrying child `prefetch-dependencies`
        // row, so the per-ingest *seed* hook must NOT fire a second,
        // depth-0 walk — that double-walk (and the depth reset to 0 it
        // causes) is exactly what defeats the transitive_depth /
        // max_descendants caps. Verified path only (the seed hook is
        // suppressed via the `cascade_internal` flag derived in
        // `ingest_with_verification`).
        let repo = repo_with_transitive_deps_trigger();
        let repo_id = repo.id;
        let content: &[u8] = b"x";
        let upstream_digest: ContentHash = sha256_of(content).parse().unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _lifecycle, _storage, repos, policy_projections, jobs) =
                make_scan_gated_use_case();
            repos.insert(repo);
            seed_permissive_global_policy(&policy_projections);

            let req = VerifiedIngestRequest::ProtocolNative {
                repository_id: repo_id,
                coords: sample_coords(),
                content_type: "application/octet-stream".into(),
                actor: api_actor(),
                payload_metadata: serde_json::json!({ "cascade_internal": true }),
                upstream_digest: upstream_digest.clone(),
                upstream_published_at: None,
                trust_upstream_publish_time: false,
            };
            uc.ingest_verified(req, content_stream(content), &test_handler())
                .await
                .expect("verified ingest");

            let cascade_calls: Vec<_> = jobs
                .enqueue_calls()
                .into_iter()
                .filter(|(kind, _, _)| kind == "prefetch-dependencies")
                .collect();
            assert!(
                cascade_calls.is_empty(),
                "a cascade-internal leaf-ingest must NOT fire the per-ingest seed hook \
                 (its parent's child row already walks it); got {cascade_calls:?}",
            );
        });
    }

    #[test]
    fn cascade_seed_hook_fires_for_non_cascade_internal_verified_ingest() {
        // Regression guard: a verified ingest WITHOUT `cascade_internal`
        // (a client pull, or a self-service ROOT leaf with trigger_source
        // "self_service") is a SEED — the per-ingest hook fires the
        // depth-0 cascade exactly as before. Suppression must be opt-in,
        // never the default.
        let repo = repo_with_transitive_deps_trigger();
        let repo_id = repo.id;
        let content: &[u8] = b"x";
        let upstream_digest: ContentHash = sha256_of(content).parse().unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _lifecycle, _storage, repos, policy_projections, jobs) =
                make_scan_gated_use_case();
            repos.insert(repo);
            seed_permissive_global_policy(&policy_projections);

            let req = VerifiedIngestRequest::ProtocolNative {
                repository_id: repo_id,
                coords: sample_coords(),
                content_type: "application/octet-stream".into(),
                actor: api_actor(),
                // No `cascade_internal` key → seed (default).
                payload_metadata: serde_json::Value::Null,
                upstream_digest: upstream_digest.clone(),
                upstream_published_at: None,
                trust_upstream_publish_time: false,
            };
            uc.ingest_verified(req, content_stream(content), &test_handler())
                .await
                .expect("verified ingest");

            let cascade_calls: Vec<_> = jobs
                .enqueue_calls()
                .into_iter()
                .filter(|(kind, _, _)| kind == "prefetch-dependencies")
                .collect();
            assert_eq!(
                cascade_calls.len(),
                1,
                "a non-cascade-internal verified ingest seeds the cascade (depth 0)",
            );
            assert_eq!(cascade_calls[0].1["current_depth"], 0);
        });
    }

    #[test]
    fn item_12b_cascade_hook_enqueue_failure_does_not_abort_ingest() {
        // The cascade is best-effort — an enqueue error logs `warn!`
        // and the ingest succeeds. Mirrors the same pattern the
        // refcount-insert and group-membership hooks use.
        let repo = repo_with_transitive_deps_trigger();
        let repo_id = repo.id;

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, _artifacts, _lifecycle, _storage, repos, policy_projections, jobs) =
                make_scan_gated_use_case();
            repos.insert(repo);
            seed_permissive_global_policy(&policy_projections);
            jobs.fail_next_enqueue(DomainError::Invariant(
                "simulated cascade enqueue failure".into(),
            ));

            // Ingest succeeds even though the cascade enqueue errored.
            let outcome = uc
                .ingest_direct(req(repo_id), content_stream(b"x"), &test_handler())
                .await
                .expect("ingest must succeed even when cascade hook fails");
            assert_ne!(outcome.artifact.id, Uuid::nil());
        });
    }

    // =====================================================================
    // Ingest-time `provenance-verify` enqueue gate (ADR 0027):
    // enqueue iff `provenance_mode != Off` AND a registered verifier
    // applies_to(format). Acceptance: (d) Off → no job; (d2) VerifyIfPresent
    // on a non-OCI format (no applicable port) → no job; (d3)
    // VerifyIfPresent / Required on OCI (cosign applies) → job enqueued.
    // =====================================================================

    /// `make_scan_gated_use_case` variant that wires the provenance-capable
    /// format set (Tier-1: `{"oci"}`) and hands back `policy_projections` +
    /// `jobs` for enqueue assertions.
    #[allow(clippy::type_complexity)]
    fn provenance_make_use_case(
        capable_formats: &[&str],
    ) -> (
        IngestUseCase,
        Arc<MockRepositoryRepository>,
        Arc<MockPolicyProjectionRepository>,
        Arc<MockJobsRepository>,
        Arc<MockArtifactLifecycle>,
    ) {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let events = Arc::new(MockEventStore::new());
        let lifecycle = Arc::new(MockArtifactLifecycle::new(artifacts.clone()));
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let groups = Arc::new(MockArtifactGroupRepository::new());
        let group_lifecycle = Arc::new(MockArtifactGroupLifecyclePort::new(groups.clone()));
        let group_use_case = Arc::new(ArtifactGroupUseCase::new(groups, group_lifecycle, true));
        let curation_rules = Arc::new(MockCurationRuleRepository::new());
        let content_references = Arc::new(MockContentReferenceIndex::new());
        let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
        let jobs = Arc::new(MockJobsRepository::default());

        let uc = IngestUseCase::new(
            storage,
            lifecycle.clone(),
            artifacts,
            repos.clone(),
            crate::event_store_publisher::wrap_for_test(events),
            curation_rules,
            group_use_case,
            true,
            HashMap::new(),
            0,
            content_references,
            policy_projections.clone(),
            jobs.clone(),
        )
        .with_provenance_capable_formats(capable_formats.iter().map(ToString::to_string));

        (uc, repos, policy_projections, jobs, lifecycle)
    }

    /// A provenance policy projection (global scope) at the requested mode.
    fn provenance_policy(mode: ProvenanceMode) -> ScanPolicyProjection {
        use hort_domain::entities::scan_policy::{NegligibleAction, SeverityThreshold};
        ScanPolicyProjection {
            policy_id: Uuid::new_v4(),
            name: format!("prov-test-{}", Uuid::new_v4()),
            scope: PolicyScope::Global,
            severity_threshold: SeverityThreshold::Critical,
            quarantine_duration_secs: 0,
            require_approval: false,
            provenance_mode: mode,
            provenance_backends: vec!["cosign".to_string()],
            provenance_identities: vec![
                hort_domain::entities::scan_policy::SignerIdentityPattern::new(
                    "https://token.actions.githubusercontent.com",
                    "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main",
                )
                .expect("valid identity"),
            ],
            max_artifact_age_secs: None,
            license_policy: serde_json::Value::Null,
            archived: false,
            // Empty scan_backends so the artifact's scan gate doesn't add a
            // ScanRequested/enqueue_scan we'd have to filter past — keeps the
            // assertion focused on the provenance-verify enqueue.
            scan_backends: vec![],
            rescan_interval_hours: 24,
            negligible_action: NegligibleAction::Ignore,
            stream_version: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// OCI-aligned ingest request + repo (coords.format must equal
    /// repo.format).
    fn oci_repo() -> Repository {
        let mut repo = sample_repository();
        repo.format = RepositoryFormat::Oci;
        repo
    }

    fn oci_coords() -> ArtifactCoords {
        ArtifactCoords {
            name: "library/nginx".into(),
            name_as_published: "library/nginx".into(),
            version: Some("1.27.0".into()),
            path: "library/nginx/manifests/1.27.0".into(),
            format: RepositoryFormat::Oci,
            metadata: serde_json::Value::Null,
        }
    }

    fn oci_verified_req(repo_id: Uuid, content: &[u8]) -> VerifiedIngestRequest {
        let hash_hex = sha256_of(content);
        let upstream_digest: ContentHash = hash_hex.parse().unwrap();
        VerifiedIngestRequest::ProtocolNative {
            repository_id: repo_id,
            coords: oci_coords(),
            content_type: "application/vnd.oci.image.manifest.v1+json".into(),
            actor: sample_actor(),
            payload_metadata: serde_json::Value::Null,
            upstream_digest,
            upstream_published_at: None,
            trust_upstream_publish_time: false,
        }
    }

    fn provenance_verify_enqueues(lifecycle: &Arc<MockArtifactLifecycle>) -> usize {
        lifecycle.provenance_verify_enqueue_count()
    }

    /// (d) `Off` policy → no `provenance-verify` job enqueued (even on OCI
    /// with a registered verifier).
    #[test]
    fn off_mode_enqueues_no_provenance_verify_job() {
        let content: &[u8] = b"oci manifest bytes";
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, repos, projections, _jobs, lifecycle) = provenance_make_use_case(&["oci"]);
            let repo = oci_repo();
            let repo_id = repo.id;
            repos.insert(repo);
            projections.insert(provenance_policy(ProvenanceMode::Off));

            uc.ingest_verified(
                oci_verified_req(repo_id, content),
                content_stream(content),
                &StubFormatHandler::new("oci").with_max_bytes(10 * 1024 * 1024),
            )
            .await
            .expect("ingest must succeed");

            assert_eq!(
                provenance_verify_enqueues(&lifecycle),
                0,
                "Off mode must enqueue NO provenance-verify job"
            );
        });
    }

    /// (d2) `VerifyIfPresent` on a non-OCI format (no applicable verifier in
    /// the Tier-1 cosign-only set) → no `provenance-verify` job. Gating on
    /// `mode != Off` alone would enqueue a no-op job for every non-OCI ingest.
    #[test]
    fn verify_if_present_non_oci_enqueues_no_provenance_verify_job() {
        let content: &[u8] = b"pypi sdist bytes";
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            // The capable set is {"oci"} — pypi is NOT in it.
            let (uc, repos, projections, _jobs, lifecycle) = provenance_make_use_case(&["oci"]);
            let repo = pypi_repository();
            let repo_id = repo.id;
            repos.insert(repo);
            projections.insert(provenance_policy(ProvenanceMode::VerifyIfPresent));

            let req = VerifiedIngestRequest::ProtocolNative {
                repository_id: repo_id,
                coords: sample_coords(),
                content_type: "application/gzip".into(),
                actor: sample_actor(),
                payload_metadata: serde_json::Value::Null,
                upstream_digest: sha256_of(content).parse().unwrap(),
                upstream_published_at: None,
                trust_upstream_publish_time: false,
            };
            uc.ingest_verified(req, content_stream(content), &test_handler())
                .await
                .expect("ingest must succeed");

            assert_eq!(
                provenance_verify_enqueues(&lifecycle),
                0,
                "VerifyIfPresent on a non-OCI format (no applicable verifier) must enqueue NO job",
            );
        });
    }

    /// (d3a) `VerifyIfPresent` on OCI (cosign applies) → a
    /// `provenance-verify` job IS enqueued, carrying `params.artifact_id`.
    #[test]
    fn verify_if_present_oci_enqueues_provenance_verify_job() {
        let content: &[u8] = b"oci manifest bytes";
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, repos, projections, _jobs, lifecycle) = provenance_make_use_case(&["oci"]);
            let repo = oci_repo();
            let repo_id = repo.id;
            repos.insert(repo);
            projections.insert(provenance_policy(ProvenanceMode::VerifyIfPresent));

            let outcome = uc
                .ingest_verified(
                    oci_verified_req(repo_id, content),
                    content_stream(content),
                    &StubFormatHandler::new("oci").with_max_bytes(10 * 1024 * 1024),
                )
                .await
                .expect("ingest must succeed");

            // Exactly one provenance-verify enqueue, committed atomically with
            // the transition and bound to the ingested artifact (the adapter
            // folds this artifact_id into the job's `params.artifact_id`).
            assert_eq!(
                lifecycle.provenance_verify_enqueue_artifact_ids(),
                vec![outcome.artifact.id],
                "VerifyIfPresent on OCI (cosign applies) must enqueue exactly one provenance-verify job for the artifact"
            );
        });
    }

    /// (d3b) `Required` on OCI → a `provenance-verify` job IS enqueued.
    #[test]
    fn required_oci_enqueues_provenance_verify_job() {
        let content: &[u8] = b"oci manifest bytes";
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, repos, projections, _jobs, lifecycle) = provenance_make_use_case(&["oci"]);
            let repo = oci_repo();
            let repo_id = repo.id;
            repos.insert(repo);
            projections.insert(provenance_policy(ProvenanceMode::Required));

            uc.ingest_verified(
                oci_verified_req(repo_id, content),
                content_stream(content),
                &StubFormatHandler::new("oci").with_max_bytes(10 * 1024 * 1024),
            )
            .await
            .expect("ingest must succeed");

            assert_eq!(
                provenance_verify_enqueues(&lifecycle),
                1,
                "Required on OCI must enqueue exactly one provenance-verify job"
            );
        });
    }

    /// Default empty capability set (the un-wired composition default) →
    /// no `provenance-verify` job even on OCI with a non-Off mode. Proves
    /// the gate is fail-safe when the real set is not yet configured.
    #[test]
    fn empty_capability_set_enqueues_no_provenance_verify_job() {
        let content: &[u8] = b"oci manifest bytes";
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            // Capable set is EMPTY (the `new()` default — no
            // `with_provenance_capable_formats` call).
            let (uc, repos, projections, _jobs, lifecycle) = provenance_make_use_case(&[]);
            let repo = oci_repo();
            let repo_id = repo.id;
            repos.insert(repo);
            projections.insert(provenance_policy(ProvenanceMode::Required));

            uc.ingest_verified(
                oci_verified_req(repo_id, content),
                content_stream(content),
                &StubFormatHandler::new("oci").with_max_bytes(10 * 1024 * 1024),
            )
            .await
            .expect("ingest must succeed");

            assert_eq!(
                provenance_verify_enqueues(&lifecycle),
                0,
                "an empty capability set must enqueue NO provenance-verify job (fail-safe default)"
            );
        });
    }

    // =====================================================================
    // `ingest_signature_manifest` narrow create (ADR 0027): a pushed
    // cosign signature manifest is NOT quarantined, NOT
    // scanned, NOT provenance-verified. Quarantine is an observation window
    // for time-deferred safety uncertainty; a Sigstore signature's validity
    // is deterministic/immediate, so quarantine is a category error for it.
    // =====================================================================

    /// `ingest_signature_manifest` stores the manifest and commits exactly
    /// one `ArtifactIngested` event with `quarantine_status == None`, and
    /// enqueues NEITHER a scan NOR a provenance-verify job — even when the
    /// active policy is the default (24h quarantine + Trivy scan) and a
    /// provenance verifier applies to the format. This is the whole point of
    /// the narrow path.
    #[test]
    fn ingest_signature_manifest_no_quarantine_no_scan_no_provenance() {
        let content: &[u8] = b"cosign bundle referrer manifest bytes";
        let hash_hex = sha256_of(content);
        let upstream_digest: ContentHash = hash_hex.parse().unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            // Provenance-capable {"oci"} + an EMPTY policy set so the
            // DEFAULT policy (24h quarantine, Trivy scan) and the default
            // ProvenanceMode (VerifyIfPresent) would BOTH fire on the
            // generic path — proving the narrow path actively suppresses
            // all three.
            let (uc, lifecycle, _storage, repos, _projections, jobs) = sig_make_use_case();
            let repo = oci_repo();
            let repo_id = repo.id;
            repos.insert(repo);

            let outcome = uc
                .ingest_signature_manifest(
                    repo_id,
                    oci_coords(),
                    "application/vnd.oci.image.manifest.v1+json".into(),
                    sample_actor(),
                    serde_json::Value::Null,
                    upstream_digest.clone(),
                    content_stream(content),
                )
                .await
                .expect("signature-manifest ingest must succeed");

            // The created artifact is status None (servable immediately).
            assert_eq!(
                outcome.artifact.quarantine_status,
                QuarantineStatus::None,
                "a signature manifest must NOT be quarantined"
            );
            assert_eq!(
                outcome.artifact.sha256_checksum, upstream_digest,
                "the CAS hash must equal the declared manifest digest"
            );

            // Lifecycle: exactly ONE commit (ArtifactIngested) — NO
            // follow-on ArtifactQuarantined batch, and the persisted
            // artifact carries quarantine_status None.
            let transitions = lifecycle.committed_transitions();
            assert_eq!(
                transitions.len(),
                1,
                "exactly one commit_transition — no ArtifactQuarantined follow-on"
            );
            assert_eq!(
                transitions[0].0.quarantine_status,
                QuarantineStatus::None,
                "the persisted artifact must be status None"
            );

            // Neither scan nor provenance enqueued (both ride the atomic
            // lifecycle path now), and no generic task either.
            assert!(
                lifecycle.scan_enqueues().is_empty(),
                "a signature manifest must NOT enqueue a scan job"
            );
            assert_eq!(
                provenance_verify_enqueues(&lifecycle),
                0,
                "a signature manifest must NOT enqueue a provenance-verify job"
            );
            assert!(
                jobs.enqueue_calls().is_empty(),
                "a signature manifest must NOT enqueue any generic task"
            );
        });
    }

    /// Returns the `IngestOutcome.ingested_event_id` of a committed
    /// `ArtifactIngested` so the caller can chain `oci_subject` causation —
    /// matching `ingest_verified`'s `IngestOutcome` return shape.
    #[test]
    fn ingest_signature_manifest_returns_artifact_with_event_id() {
        let content: &[u8] = b"another referrer manifest";
        let upstream_digest: ContentHash = sha256_of(content).parse().unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, lifecycle, _storage, repos, _projections, jobs) =
                sig_make_use_case();
            let repo = oci_repo();
            let repo_id = repo.id;
            repos.insert(repo);

            let outcome = uc
                .ingest_signature_manifest(
                    repo_id,
                    oci_coords(),
                    "application/vnd.oci.image.manifest.v1+json".into(),
                    sample_actor(),
                    serde_json::Value::Null,
                    upstream_digest,
                    content_stream(content),
                )
                .await
                .expect("ingest must succeed");

            assert_ne!(outcome.ingested_event_id, Uuid::nil());

            // Exactly one lifecycle commit, carrying ArtifactIngested only.
            let transitions = lifecycle.committed_transitions();
            assert_eq!(
                transitions.len(),
                1,
                "signature-manifest ingest commits exactly once (no quarantine batch)"
            );
            let kinds: Vec<&str> = transitions[0]
                .1
                .events
                .iter()
                .map(|e| e.event.event_type())
                .collect();
            assert_eq!(
                kinds,
                vec!["ArtifactIngested"],
                "the narrow path emits ArtifactIngested only — no ScanRequested/ChecksumVerified/Quarantined"
            );
            // The minted event_id matches the IngestOutcome.
            assert_eq!(
                transitions[0].1.events[0].event_id,
                outcome.ingested_event_id
            );
            // No jobs of any kind.
            assert!(lifecycle.scan_enqueues().is_empty());
            assert!(jobs.enqueue_calls().is_empty());
        });
    }

    /// A `put`-returned CAS hash that disagrees with the declared digest is
    /// a Conflict — the same fail-closed posture `ingest_verified` takes on
    /// a declared-digest mismatch. (The narrow path still content-addresses
    /// the manifest; a lie about the digest must not land.)
    #[test]
    fn ingest_signature_manifest_digest_mismatch_is_conflict() {
        let content: &[u8] = b"the real manifest bytes";
        // Declare a DIFFERENT digest than the bytes hash to.
        let wrong_digest: ContentHash = ("a".repeat(64)).parse().unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (uc, lifecycle, _storage, repos, _projections, jobs) = sig_make_use_case();
            let repo = oci_repo();
            let repo_id = repo.id;
            repos.insert(repo);

            let err = uc
                .ingest_signature_manifest(
                    repo_id,
                    oci_coords(),
                    "application/vnd.oci.image.manifest.v1+json".into(),
                    sample_actor(),
                    serde_json::Value::Null,
                    wrong_digest,
                    content_stream(content),
                )
                .await
                .expect_err("a declared-digest mismatch must be rejected");
            assert!(
                matches!(err, AppError::Domain(DomainError::Conflict(_))),
                "digest mismatch must surface as Conflict, got {err:?}"
            );

            // Nothing committed, nothing enqueued.
            assert!(lifecycle.committed_transitions().is_empty());
            assert!(lifecycle.scan_enqueues().is_empty());
            assert!(jobs.enqueue_calls().is_empty());
        });
    }

    /// `sig_make_use_case` — empty policy + provenance-capable {"oci"}, so
    /// the DEFAULT policy (24h quarantine + Trivy) and default
    /// ProvenanceMode would BOTH fire on the generic path; the narrow path
    /// must suppress them. Hands back the lifecycle + jobs mocks.
    #[allow(clippy::type_complexity)]
    fn sig_make_use_case() -> (
        IngestUseCase,
        Arc<MockArtifactLifecycle>,
        Arc<MockStoragePort>,
        Arc<MockRepositoryRepository>,
        Arc<MockPolicyProjectionRepository>,
        Arc<MockJobsRepository>,
    ) {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let events = Arc::new(MockEventStore::new());
        let lifecycle = Arc::new(MockArtifactLifecycle::new(artifacts.clone()));
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let groups = Arc::new(MockArtifactGroupRepository::new());
        let group_lifecycle = Arc::new(MockArtifactGroupLifecyclePort::new(groups.clone()));
        let group_use_case = Arc::new(ArtifactGroupUseCase::new(groups, group_lifecycle, true));
        let curation_rules = Arc::new(MockCurationRuleRepository::new());
        let content_references = Arc::new(MockContentReferenceIndex::new());
        let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
        let jobs = Arc::new(MockJobsRepository::default());

        let uc = IngestUseCase::new(
            storage.clone(),
            lifecycle.clone(),
            artifacts,
            repos.clone(),
            crate::event_store_publisher::wrap_for_test(events),
            curation_rules,
            group_use_case,
            true,
            HashMap::new(),
            0,
            content_references,
            policy_projections.clone(),
            jobs.clone(),
        )
        .with_provenance_capable_formats(["oci".to_string()]);

        (uc, lifecycle, storage, repos, policy_projections, jobs)
    }
}
