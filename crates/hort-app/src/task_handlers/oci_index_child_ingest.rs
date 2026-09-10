//! `oci-index-child-ingest` [`TaskHandler`] — the executor that performs the
//! verified upstream ingest of ONE child manifest declared by an OCI image
//! index.
//!
//! # Why the kind exists
//!
//! A pull-through ingest of an image index mints the index artifact and
//! registers one `content_references` row of kind `oci_index_member` per
//! declared child — and then stops. The child manifests are ingested only when
//! a client later asks for one, so a fresh multi-arch base image runs its index
//! quarantine window and its children's windows back to back rather than
//! concurrently, and a base-image bump costs two full observation windows
//! instead of one. A durable `jobs` row per declared child closes that gap: this
//! handler performs, up front, exactly the ingest a later lazy client pull would
//! have performed.
//!
//! # This shortens no quarantine window
//!
//! ADR 0054 derives the quarantine anchor from
//! `ArtifactRepository::first_seen_for_checksum`, inside `IngestUseCase`. A
//! child ingested through this handler therefore receives exactly the anchor a
//! later lazy pull would have given it: a window that would have started
//! tomorrow starts today, and none is made shorter. **Nothing in this handler
//! computes, passes or overrides an anchor**, and nothing may start to — the
//! `VerifiedIngestRequest` it builds carries no
//! `quarantine_anchor_override`-shaped field, and the release predicate
//! (ADR 0007) is untouched: every child still needs its own window AND its own
//! scan verdict. ADR 0043 D4 likewise stands — releasing an index does not
//! release a held child.
//!
//! # Params
//!
//! | field | type | meaning |
//! |---|---|---|
//! | `repository_id` | uuid | the proxy repository the child belongs in |
//! | `requested_name` | string | the **client-facing** name the parent index was requested under, unstripped |
//! | `child_digest` | string | `sha256:…`, from the index's `manifests[].digest` |
//! | `depth` | u32, optional | how deep in a nested-index chain this row sits; absent means [`CHILD_INGEST_ROOT_DEPTH`] |
//!
//! `requested_name` is deliberately the unstripped name and not the upstream
//! one. Re-resolving it through [`UpstreamResolver`] reproduces exactly what a
//! lazy client pull of the same child would do — which is the semantics this
//! whole kind is defined by: *do now what a lazy pull would do later*. A
//! stripped name has no prefix left to longest-prefix-match against, so it
//! could only be resolved through a catch-all mapping: on a multi-upstream
//! proxy whose mappings are all prefix-scoped (`dockerhub/`, `ghcr/`, …) there
//! is none and every child would silently fall back to the lazy path, and where
//! a catch-all coexists with prefixed mappings the child would be fetched
//! through the catch-all even though the parent index came from a prefixed
//! upstream. It is also what keeps the minted child's `Artifact.name` identical
//! to the one the lazy pull path records, so an eagerly ingested child and a
//! lazily ingested one are indistinguishable. Carrying a mapping id or a prefix
//! instead would freeze a resolution that can legitimately change between
//! enqueue and execution.
//!
//! The child's media type is deliberately **not** a param: it is read from the
//! fetch response, so a stale or hand-crafted job row cannot disagree with what
//! upstream actually serves. The response's media type is additionally
//! cross-checked against the fetched body's own shape ([`is_image_index`]), and
//! the **body wins** — those are the bytes that were hashed and stored.
//!
//! # Behaviour, in order
//!
//! 1. Resolve the repository. A repository that no longer exists is a
//!    `Completed` no-op — the index that enqueued this row may be days old.
//! 2. Resolve the upstream mapping by [`UpstreamResolver::resolve`] on the
//!    client-facing `requested_name` — the pull path's own resolution,
//!    longest matching prefix wins, and the stripped upstream name comes back
//!    with the mapping. No matching mapping is likewise a `Completed` no-op.
//! 3. Short-circuit on local presence, scoped to the **target repository**
//!    (`find_by_repo_and_checksum`): ADR 0054 keeps the anchor per row, so a row
//!    in another repository is not this repository's row. A hit returns
//!    `Completed` without touching the network — never re-mint, never re-anchor.
//!    This is also what makes the row safe to run twice.
//! 4. Fetch by digest through [`UpstreamProxy::fetch_manifest`], with an
//!    `accept` list covering both the OCI and the Docker manifest and index
//!    media types.
//! 5. Verify. The response's `declared_digest`, when present, must equal the
//!    requested `child_digest`; the ingest itself is keyed on the requested
//!    digest, so a body whose bytes hash to something else is rejected inside
//!    `ingest_verified` before anything reaches CAS (mint-after-verify).
//! 6. Ingest via [`IngestUseCase::ingest_verified`]. The cached body is read
//!    into memory ONCE and both the ingest and the edge derivation in steps 7–8
//!    consume those bytes — bounded work, not an unbounded buffer: the upstream
//!    adapter already refused anything over its manifest body cap when it wrote
//!    the tempfile, and the body has to be parsed here regardless. Same
//!    reasoning [`super::oci_membership_edge_backfill`] records for the same
//!    artifact class.
//! 7. Register the child's own membership edges. A child image manifest ingested
//!    by this path needs its `oci_config` and `oci_layer` rows or its blobs have
//!    no GC keepalive — the exact defect
//!    [`super::oci_membership_edge_backfill`] exists to repair. The edges are
//!    re-derived through [`FormatHandler::extract_oci_manifest_blob_refs`], as
//!    that handler does.
//! 8. Recurse when the child is itself an index: enumerate its children with
//!    [`index_child_digests`], register the `oci_index_member` rows, and enqueue
//!    one `oci-index-child-ingest` row per grandchild — the whole level in one
//!    [`JobsRepository::enqueue_idempotent_batch`] statement, never a row at a
//!    time, because it is a cohort of up to the per-index child cap and each
//!    row's conflict is the unique index's business rather than this handler's.
//!    Recursion falls out of
//!    the handler enqueueing its own kind, and it is bounded in both directions:
//!    the domain's per-index child cap bounds each level ([`index_child_digests`]
//!    rejects an over-cap index outright rather than truncating it), and
//!    [`MAX_CHILD_INGEST_DEPTH`] bounds the chain of nested indexes. Neither is
//!    operator-visible — both are constants, because a safety bound is not a
//!    trade-off to tune. At the depth cap the member edges are still written and
//!    only the grandchild rows are refused; those grandchildren stay reachable
//!    through the lazy pull path. A cycle (an index naming itself, directly or
//!    transitively) terminates on step 3 well before the cap: the artifact is
//!    already held in the target repository by the time its own row is claimed.
//!
//! # Outcome shape — a child failure never fails the index
//!
//! Every terminal state below is `TaskOutcome::Completed` except the two
//! non-retryable rejections, and the operator-facing signal is the
//! `result_summary` `outcome` field plus the severity of the completion log
//! line. This mirrors
//! [`super::prefetch_ingest::PrefetchIngestHandler`]'s `completion_is_error`
//! rule: a fully-failed unit escalates to ERROR only when its failure was a
//! genuine hard failure rather than an upstream 404.
//!
//! - `repository_missing` / `upstream_mapping_missing` / `already_present` /
//!   `upstream_not_found` — `Completed`, normal severity. An index may
//!   legitimately declare a manifest the upstream no longer serves.
//! - `ingested_depth_capped` — `Completed`, normal severity, with a `warn!`:
//!   the child was minted and its member edges written, but it sat at
//!   [`MAX_CHILD_INGEST_DEPTH`] so its own children were not enqueued.
//!   Refusing to recurse is a bound being enforced, never a failure.
//! - `hard_failure` (network, 5xx, storage, a body that does not verify against
//!   the requested digest) — `Completed`, ERROR severity. Deliberately not a
//!   retrying `Failed`: the child is still reachable through the lazy pull path,
//!   so the only cost of giving up is the ergonomics win, never correctness.
//! - Malformed params, a `child_digest` that is not a `sha256:<64-hex>` OCI
//!   digest, and an upstream-declared digest that disagrees with the requested
//!   one are `Failed { retry: false }` — none can succeed on retry, and the last
//!   is an upstream serving content that does not match a digest the index bound
//!   to it, which is worth a failed row rather than a quiet completion. Nothing
//!   is stored in any of the three.
//!
//! Infrastructure reads that must not be guessed at — the repository load and
//! the local-presence lookup — are `Failed { retry: true }`.
//!
//! # Idempotency
//!
//! The row's dedupe key is the pair (`repository_id`, `child_digest`), composed
//! by [`child_ingest_idempotency_key`] and carried on the `jobs.idempotency_key`
//! partial unique index. The requested name is deliberately not part of the
//! identity: the same content in the same repository is one unit of work
//! however it was reached. Producers compose their params with
//! [`child_ingest_params`] — the pull-through legs through
//! [`crate::use_cases::oci_index_child_enqueue::OciIndexChildEnqueueUseCase`],
//! this handler directly for a grandchild — so the producer→consumer shape has
//! one definition. Step 3 makes a re-run of an already-ingested child a no-op
//! regardless.
//!
//! **The jobs row is the second dedupe layer, not the only one**, which is what
//! makes a terminal row of this kind safe to delete: `jobs.idempotency_key`
//! suppresses a re-enqueue only for as long as the row exists, but step 3's
//! target-repository presence check suppresses the *work* permanently. A swept
//! row that is later re-enqueued therefore short-circuits before it touches the
//! network — a cheap no-op, never a re-fetch and never a re-anchor. Terminal
//! rows of this kind are consequently swept by `prefetch-row-retention-sweep`
//! along with the rest of the pull-through ingest cascade; nothing durable is
//! kept in them.

use std::sync::Arc;

use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use hort_domain::entities::artifact::Artifact;
use hort_domain::entities::repository::{Repository, RepositoryFormat};
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::ApiActor;
use hort_domain::oci::{
    index_child_digests, is_image_index, ManifestBlobRole, DOCKER_MANIFEST_LIST_MEDIA_TYPE,
    OCI_IMAGE_INDEX_MEDIA_TYPE,
};
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::content_reference_index::{ContentReference, ContentReferenceIndex};
use hort_domain::ports::format_handler::FormatHandler;
use hort_domain::ports::jobs_repository::{IdempotentEnqueueRow, JobsRepository};
use hort_domain::ports::repository_repository::RepositoryRepository;
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::upstream_proxy::UpstreamProxy;
use hort_domain::ports::upstream_resolver::UpstreamResolver;
use hort_domain::ports::BoxFuture;
use hort_domain::types::{ArtifactCoords, ContentHash, IdempotencyKey};

use crate::use_cases::ingest_use_case::{IngestUseCase, VerifiedIngestRequest};

use super::oci_membership_edge_backfill::{OCI_CONFIG_KIND, OCI_LAYER_KIND};
use super::prefetch_ingest::is_upstream_not_found;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The `jobs.kind` literal this handler claims. Producers enqueue under the
/// same constant so the producer→consumer kind has one definition.
pub const OCI_INDEX_CHILD_INGEST_KIND: &str = "oci-index-child-ingest";

/// `content_references.kind` written per declared child of an image index —
/// the same literal the manifest-PUT and pull-through register paths write
/// (`hort-http-oci::manifests_write`), which `hort-app` cannot call directly
/// (ADR 0008: format-crate internals are not reachable from the application
/// layer).
const OCI_INDEX_MEMBER_KIND: &str = "oci_index_member";

/// The OCI single-image manifest media type. Spelled out here rather than
/// imported because the OCI inbound-HTTP crate's allowlist is not reachable
/// from `hort-app` (ADR 0008 runs the dependency the other way); the two index
/// media types DO have domain constants and are used from there.
const OCI_IMAGE_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

/// The Docker-schema analogue of [`OCI_IMAGE_MANIFEST_MEDIA_TYPE`].
const DOCKER_MANIFEST_V2_MEDIA_TYPE: &str = "application/vnd.docker.distribution.manifest.v2+json";

/// Content type recorded when the upstream response declares none. Mirrors the
/// fallback the OCI manifest pull-through applies to the same `Option<String>`.
const FALLBACK_MEDIA_TYPE: &str = "application/octet-stream";

/// `jobs.trigger_source` bound on every `oci-index-child-ingest` row. The row
/// exists because an ingest observed an index declaring the child — an
/// unexpectedly high rate here is a runaway index nesting, not a runaway
/// operator. Shared with the pull-through producer
/// ([`crate::use_cases::oci_index_child_enqueue`]) so a row minted by the
/// handler's own recursion is indistinguishable from one minted at a pull leg.
pub(crate) const CHILD_INGEST_TRIGGER_SOURCE: &str = "ingest";

/// `jobs.priority` bound on every `oci-index-child-ingest` row. Eager child
/// ingest is a latency optimisation, never urgent work: it drains behind
/// manual, cron and advisory rows, matching the cascade's priority-0 posture.
pub(crate) const CHILD_INGEST_ENQUEUE_PRIORITY: i16 = 0;

/// The recursion depth a row minted at a pull-through leg carries: the index
/// the client pulled is the root, so the children it declares are level zero.
/// A row whose params omit `depth` is a root-level row — which is what keeps
/// rows minted before the field existed working unchanged.
pub(crate) const CHILD_INGEST_ROOT_DEPTH: u32 = 0;

/// Hard cap on the depth this kind recurses to. A row already at the cap
/// writes its index's member edges and then mints no grandchild rows.
///
/// The domain's per-index child cap bounds ONE level of the fan-out. Without a
/// depth bound, a chain of distinct nested indexes fans out as
/// (per-index cap)ⁿ, so a single client pull of a hostile or merely
/// pathological upstream tree could enqueue an arbitrarily large job tree —
/// priority and worker concurrency bound the rate at which that tree drains,
/// never its size. Real OCI trees nest one level (an index whose children are
/// image manifests), so four costs nothing legitimate and makes the fan-out
/// finite.
///
/// This is a constant and must stay one: it is a safety bound, not a
/// trade-off an operator is equipped to make, so there is deliberately no
/// policy field, no gitops envelope key and no environment variable behind it.
/// Nothing is lost at the cap either — a child that is not eagerly ingested
/// still reaches the repository through the lazy pull path with its own full
/// quarantine window.
const MAX_CHILD_INGEST_DEPTH: u32 = 4;

/// The `Accept` list sent on the child-manifest fetch: both OCI and Docker
/// single-image manifest and index media types, so an upstream that content-
/// negotiates serves whichever shape the child actually is.
fn manifest_accept() -> Vec<String> {
    vec![
        OCI_IMAGE_MANIFEST_MEDIA_TYPE.to_string(),
        OCI_IMAGE_INDEX_MEDIA_TYPE.to_string(),
        DOCKER_MANIFEST_V2_MEDIA_TYPE.to_string(),
        DOCKER_MANIFEST_LIST_MEDIA_TYPE.to_string(),
    ]
}

/// `true` when `media_type` is an image-index / manifest-list media type — the
/// shape that carries `manifests[]` instead of `config` + `layers[]`. Used only
/// to cross-check the upstream's declared type against the body's own shape;
/// the body is authoritative.
fn is_index_media_type(media_type: &str) -> bool {
    media_type == OCI_IMAGE_INDEX_MEDIA_TYPE || media_type == DOCKER_MANIFEST_LIST_MEDIA_TYPE
}

// ---------------------------------------------------------------------------
// Producer→consumer contract
// ---------------------------------------------------------------------------

/// Parsed shape of the `params` JSONB column for an `oci-index-child-ingest`
/// row.
///
/// `pub(crate)` so the producers that enqueue this kind can pin the
/// producer→consumer params contract in their own unit tests — a producer
/// emitting a shape this consumer cannot deserialize would leave every child
/// row failing to parse while the index ingest itself looked healthy.
#[derive(Debug, Deserialize)]
pub(crate) struct OciIndexChildIngestParams {
    /// Proxy repository the child belongs in.
    repository_id: Uuid,
    /// The **client-facing**, unstripped name the parent index was requested
    /// under. Re-resolved here through [`UpstreamResolver`]; see the module
    /// doc for why the stripped upstream name would be the wrong thing to
    /// carry.
    requested_name: String,
    /// `sha256:<64-hex>`, taken verbatim from the parent index's
    /// `manifests[].digest`.
    child_digest: String,
    /// How deep in a nested-index chain this row sits: a row minted at a
    /// pull-through leg is [`CHILD_INGEST_ROOT_DEPTH`], and each recursion
    /// step adds one. Absent means the root, so a row already queued when
    /// the field was introduced parses and behaves exactly as before.
    #[serde(default = "root_depth")]
    depth: u32,
}

/// `serde` default for [`OciIndexChildIngestParams::depth`]: a row that does
/// not carry the field is a root-level row.
fn root_depth() -> u32 {
    CHILD_INGEST_ROOT_DEPTH
}

/// Render a CAS [`ContentHash`] back as the OCI `sha256:<64-hex>` digest
/// reference the protocol (and this kind's `child_digest` param) speaks.
pub(crate) fn oci_digest_ref(hash: &ContentHash) -> String {
    format!("sha256:{}", hash.as_ref())
}

/// Compose the `params` JSON for one `oci-index-child-ingest` row. The single
/// definition of the producer→consumer shape [`OciIndexChildIngestParams`]
/// reads back.
///
/// Takes the child as a [`ContentHash`] rather than a string so a producer
/// cannot mint a row whose `child_digest` the consumer will reject: every
/// producer holds the child as a hash already (the domain's index-child
/// derivation yields hashes, not raw descriptor strings).
pub(crate) fn child_ingest_params(
    repository_id: Uuid,
    requested_name: &str,
    child_digest: &ContentHash,
) -> serde_json::Value {
    child_ingest_params_at_depth(
        repository_id,
        requested_name,
        child_digest,
        CHILD_INGEST_ROOT_DEPTH,
    )
}

/// [`child_ingest_params`] for a row minted by this handler's own recursion,
/// which sits one level deeper than the row that minted it. Private because
/// the recursion is the only producer that is not at the root: a pull-through
/// leg observes the index a client asked for, which is the root by definition.
fn child_ingest_params_at_depth(
    repository_id: Uuid,
    requested_name: &str,
    child_digest: &ContentHash,
    depth: u32,
) -> serde_json::Value {
    json!({
        "repository_id": repository_id,
        "requested_name": requested_name,
        "child_digest": oci_digest_ref(child_digest),
        "depth": depth,
    })
}

/// Compose the `jobs.idempotency_key` for one `oci-index-child-ingest` row:
/// the kind, the target repository and the child digest.
///
/// The key deliberately carries no timestamp and no parent identity. The unit
/// of work is "hold this content in this repository", and a second index
/// declaring the same child asks for work that is either already done or
/// already queued — the `jobs_idempotency_key_uq` partial unique index absorbs
/// it rather than re-fetching the same bytes.
///
/// Infallible by construction: the kind is a lowercase-hyphen literal, a
/// `Uuid`'s `Display` is hex-and-hyphens, and a [`ContentHash`] is 64 lowercase
/// hex characters — every byte is inside the key charset `[A-Za-z0-9-_/:.]`,
/// and the composed length is far under the 256-byte cap. Taking the digest as
/// a hash rather than a string is what makes that true, so there is no
/// unreachable error arm for callers to carry.
pub(crate) fn child_ingest_idempotency_key(
    repository_id: Uuid,
    child_digest: &ContentHash,
) -> IdempotencyKey {
    let raw = format!(
        "{OCI_INDEX_CHILD_INGEST_KIND}:{repository_id}:{}",
        oci_digest_ref(child_digest)
    );
    IdempotencyKey::try_from(raw).expect(
        "kind + Uuid + sha256:<64-hex> is inside the idempotency-key charset and under \
         the length cap — see this function's doc",
    )
}

/// Parse an OCI `sha256:<64-hex>` digest reference into a CAS [`ContentHash`].
/// `None` for any other algorithm or malformed hex — the domain's uniform
/// sha256-only digest handling.
fn parse_child_digest(raw: &str) -> Option<ContentHash> {
    raw.strip_prefix("sha256:")?.parse().ok()
}

/// The `content_type` to record for the ingested child: the upstream's
/// declared media type when it sent one, else the generic fallback the OCI
/// manifest pull-through applies to the same `Option<String>`.
fn resolve_media_type(declared: Option<&str>) -> String {
    declared.map_or_else(|| FALLBACK_MEDIA_TYPE.to_string(), str::to_string)
}

/// Build the `ArtifactCoords` for a child manifest addressed by
/// `(name, digest)`, where `name` is the **client-facing requested name** —
/// the same value `hort-http-oci`'s lazy pull path passes, so an eagerly
/// ingested child and a lazily ingested one carry an identical `Artifact.name`.
///
/// `path = "manifests/sha256:<hex>"` — the same layout
/// `hort-http-oci::coords::oci_manifest_coords` writes, so a later client GET
/// for the same digest resolves this exact row by path. Re-derived here rather
/// than reused because `hort-app` must not depend on `hort-http-oci` (ADR 0008
/// runs the dependency the other way); the prefix is load-bearing in both
/// places, and a divergence would leave the eagerly-ingested child unreachable
/// from the read path.
fn child_manifest_coords(name: &str, digest: &ContentHash) -> ArtifactCoords {
    ArtifactCoords {
        name: name.to_string(),
        name_as_published: name.to_string(),
        version: None,
        path: format!("manifests/sha256:{}", digest.as_ref()),
        format: RepositoryFormat::Oci,
        metadata: serde_json::Value::Null,
    }
}

// ---------------------------------------------------------------------------
// Per-call outcome + counters
// ---------------------------------------------------------------------------

/// The terminal state of one child-ingest attempt. Surfaces as the
/// `result_summary` `outcome` field and decides the completion line's severity
/// — see the module doc's "Outcome shape" section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChildOutcome {
    /// The child was fetched, verified and minted.
    Ingested,
    /// As [`Self::Ingested`], and the child was itself an index sitting at
    /// [`MAX_CHILD_INGEST_DEPTH`]: its `oci_index_member` edges were written
    /// but no grandchild rows were enqueued. Its children stay on the lazy
    /// pull path.
    IngestedDepthCapped,
    /// The target repository already held the content hash; no upstream
    /// request was made and no row was minted or re-anchored.
    AlreadyPresent,
    /// The repository the row names no longer exists.
    RepositoryMissing,
    /// No upstream mapping of the repository prefixes the requested name, so
    /// there is nothing to fetch through.
    UpstreamMappingMissing,
    /// The upstream no longer serves a manifest the index declared.
    UpstreamNotFound,
    /// Network, 5xx, storage, or a body that did not verify against the
    /// requested digest.
    HardFailure,
}

impl ChildOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ingested => "ingested",
            Self::IngestedDepthCapped => "ingested_depth_capped",
            Self::AlreadyPresent => "already_present",
            Self::RepositoryMissing => "repository_missing",
            Self::UpstreamMappingMissing => "upstream_mapping_missing",
            Self::UpstreamNotFound => "upstream_not_found",
            Self::HardFailure => "hard_failure",
        }
    }

    /// Whether the completion line is logged at ERROR. Only a genuine hard
    /// failure escalates; an upstream 404 and every no-op stay at INFO —
    /// mirrors `PrefetchIngestHandler`'s `completion_is_error`.
    fn is_error(self) -> bool {
        matches!(self, Self::HardFailure)
    }
}

/// Per-call counters threaded through the post-ingest membership-edge and
/// recursion work. Every field is best-effort follow-up to an ingest that has
/// already committed, so none of them can fail the call — they exist so an
/// operator reading `result_summary` can tell "nothing to do" from "could not
/// do it".
#[derive(Debug, Default)]
struct ChildSummary {
    /// `true` when the ingested child was itself an image index.
    is_index: bool,
    /// `content_references` rows written for this child (`oci_index_member`
    /// for an index, `oci_config` + `oci_layer` for an image manifest).
    membership_edges_written: u64,
    /// Grandchild rows that inserted.
    grandchildren_enqueued: u64,
    /// Grandchild rows absorbed by the `jobs.idempotency_key` unique index —
    /// the work is already queued or already done.
    grandchildren_deduped: u64,
    /// Grandchild rows that could not be enqueued at all.
    grandchildren_failed: u64,
    /// `true` when the child was an index at [`MAX_CHILD_INGEST_DEPTH`], so
    /// its declared children were deliberately not enqueued.
    depth_capped: bool,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// [`TaskHandler`] for the eager ingest of one index child.
///
/// Constructed at worker composition time with the ports the verified
/// pull-through needs, mirroring
/// [`super::prefetch_ingest::PrefetchIngestHandler`]'s wiring shape and adding
/// what an OCI child additionally requires: the artifact projection (the
/// target-repository presence short-circuit), the content-reference index (the
/// child's own membership edges) and the jobs repository (the grandchild
/// enqueue when the child is itself an index).
pub struct OciIndexChildIngestHandler {
    repositories: Arc<dyn RepositoryRepository>,
    artifacts: Arc<dyn ArtifactRepository>,
    upstream_proxy: Arc<dyn UpstreamProxy>,
    /// The same resolver the rest of the worker uses, so a child resolves
    /// through exactly the mapping a client pull of that child would.
    upstream_resolver: Arc<dyn UpstreamResolver>,
    content_references: Arc<dyn ContentReferenceIndex>,
    jobs: Arc<dyn JobsRepository>,
    /// OCI handler. This kind is OCI-only by design; the composition root wires
    /// the OCI handler in directly rather than threading the full per-format
    /// registry, mirroring
    /// [`super::oci_membership_edge_backfill::OciMembershipEdgeBackfillHandler`].
    oci_handler: Arc<dyn FormatHandler>,
    ingest: Arc<IngestUseCase>,
}

impl OciIndexChildIngestHandler {
    /// Every parameter is a distinct `Arc<dyn Port>` (plus the one use case),
    /// so a mis-ordered call site is a type error rather than a silent
    /// mis-wiring — the positional shape the sibling task-handler constructors
    /// all use.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repositories: Arc<dyn RepositoryRepository>,
        artifacts: Arc<dyn ArtifactRepository>,
        upstream_proxy: Arc<dyn UpstreamProxy>,
        upstream_resolver: Arc<dyn UpstreamResolver>,
        content_references: Arc<dyn ContentReferenceIndex>,
        jobs: Arc<dyn JobsRepository>,
        oci_handler: Arc<dyn FormatHandler>,
        ingest: Arc<IngestUseCase>,
    ) -> Self {
        Self {
            repositories,
            artifacts,
            upstream_proxy,
            upstream_resolver,
            content_references,
            jobs,
            oci_handler,
            ingest,
        }
    }

    /// The whole child-ingest sequence. `Ok(outcome)` is a `Completed` state
    /// (the severity of the completion line follows
    /// [`ChildOutcome::is_error`]); `Err(outcome)` is a terminal
    /// `TaskOutcome::Failed` the caller returns verbatim.
    async fn ingest_child(
        &self,
        parsed: &OciIndexChildIngestParams,
        child_hash: &ContentHash,
        summary: &mut ChildSummary,
    ) -> Result<ChildOutcome, TaskOutcome> {
        let repo = match self.repositories.find_by_id(parsed.repository_id).await {
            Ok(r) => r,
            Err(DomainError::NotFound { .. }) => {
                tracing::info!(
                    repository_id = %parsed.repository_id,
                    child_digest = %parsed.child_digest,
                    "oci-index-child-ingest: repository no longer exists; nothing to ingest",
                );
                return Ok(ChildOutcome::RepositoryMissing);
            }
            Err(err) => {
                return Err(TaskOutcome::fail(
                    format!(
                        "oci-index-child-ingest: repository {} not loadable: {err}",
                        parsed.repository_id
                    ),
                    true,
                ));
            }
        };

        // The pull path's own resolution: longest matching prefix over the
        // repository's mappings, applied to the CLIENT-FACING requested name,
        // yielding the mapping AND the stripped upstream name. Resolving here
        // rather than freezing a mapping id at enqueue time is what makes an
        // eager child ingest do exactly what a lazy client pull of the same
        // child would do at this instant.
        let Some((mapping, upstream_name)) = self
            .upstream_resolver
            .resolve(repo.id, &parsed.requested_name)
        else {
            tracing::info!(
                repository = %repo.key,
                requested_name = %parsed.requested_name,
                child_digest = %parsed.child_digest,
                "oci-index-child-ingest: no upstream mapping prefixes the requested name; \
                 the child stays on the lazy pull path",
            );
            return Ok(ChildOutcome::UpstreamMappingMissing);
        };

        // Scoped to the TARGET repository: ADR 0054 keeps the anchor per row,
        // so the same content held in another repository is not this
        // repository's row and must not suppress the mint here.
        match self
            .artifacts
            .find_by_repo_and_checksum(repo.id, child_hash)
            .await
        {
            Ok(Some(existing)) => {
                tracing::debug!(
                    repository = %repo.key,
                    artifact_id = %existing.id,
                    child_digest = %parsed.child_digest,
                    "oci-index-child-ingest: child already held in the target repository; \
                     no upstream request, no re-mint, no re-anchor",
                );
                return Ok(ChildOutcome::AlreadyPresent);
            }
            Ok(None) => {}
            Err(err) => {
                return Err(TaskOutcome::fail(
                    format!(
                        "oci-index-child-ingest: local-presence lookup for {} failed: {err}",
                        parsed.child_digest
                    ),
                    true,
                ));
            }
        }

        let fetch = match self
            .upstream_proxy
            .fetch_manifest(
                mapping.clone(),
                upstream_name.clone(),
                parsed.child_digest.clone(),
                manifest_accept(),
            )
            .await
        {
            Ok(f) => f,
            Err(err) => {
                if is_upstream_not_found(&err.to_string()) {
                    tracing::info!(
                        repository = %repo.key,
                        upstream_name = %upstream_name,
                        child_digest = %parsed.child_digest,
                        "oci-index-child-ingest: upstream no longer serves this declared child",
                    );
                    return Ok(ChildOutcome::UpstreamNotFound);
                }
                tracing::warn!(
                    error = %err,
                    repository = %repo.key,
                    upstream_name = %upstream_name,
                    child_digest = %parsed.child_digest,
                    "oci-index-child-ingest: fetch_manifest failed",
                );
                return Ok(ChildOutcome::HardFailure);
            }
        };

        let Some(cache_handle) = fetch.cache_handle.as_ref() else {
            tracing::warn!(
                repository = %repo.key,
                child_digest = %parsed.child_digest,
                "oci-index-child-ingest: manifest fetch produced no cached body",
            );
            return Ok(ChildOutcome::HardFailure);
        };

        // The upstream-declared digest must name the child the index bound. A
        // disagreement means the upstream served content under a digest it does
        // not match; refuse before a single byte reaches CAS.
        if let Some(declared) = fetch.declared_digest.as_deref() {
            if !declared
                .trim()
                .eq_ignore_ascii_case(parsed.child_digest.trim())
            {
                crate::project::remove_cached_body(cache_handle).await;
                tracing::error!(
                    repository = %repo.key,
                    upstream_name = %upstream_name,
                    requested_digest = %parsed.child_digest,
                    declared_digest = %declared,
                    "oci-index-child-ingest: upstream-declared digest does not match the \
                     requested child digest; nothing stored",
                );
                return Err(TaskOutcome::fail(
                    format!(
                        "oci-index-child-ingest: upstream declared digest {declared} does not \
                         match the requested child digest {}; nothing stored",
                        parsed.child_digest
                    ),
                    false,
                ));
            }
        }

        let media_type = resolve_media_type(fetch.media_type.as_deref());

        // Read the cached body ONCE, into memory, and let both the ingest and
        // the membership-edge derivation consume those bytes. Bounded work,
        // not an unbounded buffer: the upstream adapter already refused
        // anything over `manifest_cache_max_bytes` when it wrote this
        // tempfile, and the body has to be parsed here regardless — the same
        // reasoning `oci_membership_edge_backfill::read_manifest_bytes`
        // records for the same artifact class. The tempfile's lifecycle ends
        // here; nothing downstream reaches for it again.
        let body = match tokio::fs::read(&cache_handle.path).await {
            Ok(b) => bytes::Bytes::from(b),
            Err(err) => {
                crate::project::remove_cached_body(cache_handle).await;
                tracing::warn!(
                    error = %err,
                    repository = %repo.key,
                    child_digest = %parsed.child_digest,
                    "oci-index-child-ingest: cached manifest body could not be read",
                );
                return Ok(ChildOutcome::HardFailure);
            }
        };
        crate::project::remove_cached_body(cache_handle).await;

        // `upstream_digest` is the requested child digest and NOTHING here
        // supplies a quarantine anchor — `ingest_verified` derives it from
        // `first_seen_for_checksum` (ADR 0054), so this child gets exactly the
        // anchor a later lazy pull would have given it.
        let request = VerifiedIngestRequest::ProtocolNative {
            repository_id: repo.id,
            // The client-facing name, exactly as the lazy pull path's
            // `oci_manifest_coords(name, …)` builds it.
            coords: child_manifest_coords(&parsed.requested_name, child_hash),
            content_type: media_type.clone(),
            actor: ApiActor {
                user_id: Uuid::nil(),
            },
            payload_metadata: json!({
                "oci_source": "upstream",
                "oci_upstream_url": mapping.upstream_url,
                "oci_upstream_name": upstream_name,
                "oci_media_type": media_type,
                "source": "oci_index_child_ingest",
            }),
            upstream_digest: child_hash.clone(),
            upstream_published_at: fetch.last_modified,
            trust_upstream_publish_time: mapping.trust_upstream_publish_time,
        };
        let ingested = match self
            .ingest
            .ingest_verified(
                request,
                Box::new(std::io::Cursor::new(body.clone())),
                self.oci_handler.as_ref(),
            )
            .await
        {
            Ok(o) => o,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    repository = %repo.key,
                    child_digest = %parsed.child_digest,
                    "oci-index-child-ingest: ingest_verified failed; nothing minted",
                );
                return Ok(ChildOutcome::HardFailure);
            }
        };

        self.register_and_recurse(
            &repo,
            parsed,
            &ingested.artifact,
            &media_type,
            &body,
            summary,
        )
        .await;

        Ok(if summary.depth_capped {
            ChildOutcome::IngestedDepthCapped
        } else {
            ChildOutcome::Ingested
        })
    }

    /// Post-ingest follow-up: write the child's own membership edges and, when
    /// the child is itself an index, enqueue one row per grandchild. Every
    /// failure in here is non-fatal — the child manifest is already committed.
    async fn register_and_recurse(
        &self,
        repo: &Repository,
        parsed: &OciIndexChildIngestParams,
        artifact: &Artifact,
        media_type: &str,
        body: &[u8],
        summary: &mut ChildSummary,
    ) {
        // The body's own shape decides which edges to write. The upstream's
        // declared media type is cross-checked against it and disagreement is
        // reported, but the body wins: these are the bytes that were hashed and
        // stored, and a mis-declared `Content-Type` must not misfile the edges.
        let body_is_index = is_image_index(body);
        if is_index_media_type(media_type) != body_is_index {
            tracing::warn!(
                repository = %repo.key,
                artifact_id = %artifact.id,
                child_digest = %parsed.child_digest,
                %media_type,
                body_is_index,
                "oci-index-child-ingest: upstream media type disagrees with the manifest \
                 body's shape; membership edges follow the body",
            );
        }
        summary.is_index = body_is_index;

        if body_is_index {
            let children = match index_child_digests(body) {
                Ok(c) => c,
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        repository = %repo.key,
                        artifact_id = %artifact.id,
                        child_digest = %parsed.child_digest,
                        "oci-index-child-ingest: nested index children not derivable; \
                         no member edges, no grandchild rows",
                    );
                    return;
                }
            };
            // The member edges are membership facts about an artifact that is
            // already committed, so they are written at every depth. Only the
            // grandchild ROWS are bounded — they are what makes the fan-out a
            // tree that can grow without limit.
            let grandchild_depth = parsed.depth.saturating_add(1);
            summary.depth_capped = grandchild_depth > MAX_CHILD_INGEST_DEPTH;
            if summary.depth_capped {
                tracing::warn!(
                    repository = %repo.key,
                    artifact_id = %artifact.id,
                    child_digest = %parsed.child_digest,
                    depth = parsed.depth,
                    max_depth = MAX_CHILD_INGEST_DEPTH,
                    declared_children = children.len(),
                    "oci-index-child-ingest: nested index at the recursion depth cap; \
                     member edges written but no grandchild rows enqueued — those \
                     children stay on the lazy pull path",
                );
            }
            for grandchild in &children {
                self.write_edge(
                    artifact,
                    OCI_INDEX_MEMBER_KIND,
                    grandchild,
                    json!({
                        "child_digest": oci_digest_ref(grandchild),
                        "media_type": media_type,
                    }),
                    summary,
                )
                .await;
            }
            if !summary.depth_capped {
                self.enqueue_grandchildren(repo, parsed, &children, grandchild_depth, summary)
                    .await;
            }
            return;
        }

        let coords = child_manifest_coords(&parsed.requested_name, &artifact.sha256_checksum);
        let refs = match self
            .oci_handler
            .extract_oci_manifest_blob_refs(&coords, &mut &body[..])
        {
            Ok(r) => r,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    repository = %repo.key,
                    artifact_id = %artifact.id,
                    child_digest = %parsed.child_digest,
                    "oci-index-child-ingest: manifest blob references not derivable; \
                     the child's config/layer blobs have no GC keepalive from this row",
                );
                return;
            }
        };
        for blob in &refs {
            let kind = match blob.role {
                ManifestBlobRole::Config => OCI_CONFIG_KIND,
                ManifestBlobRole::Layer => OCI_LAYER_KIND,
            };
            let metadata = json!({
                "digest": oci_digest_ref(&blob.hash),
                "media_type": media_type,
            });
            self.write_edge(artifact, kind, &blob.hash, metadata, summary)
                .await;
        }
    }

    /// Insert one `content_references` row for `artifact` pointing at `hash`
    /// under `kind`. Non-fatal on failure: `content_references` is eventually
    /// authoritative (the refcount-reconcile sweep backstops it) and the
    /// manifest is already committed.
    async fn write_edge(
        &self,
        artifact: &Artifact,
        kind: &str,
        hash: &ContentHash,
        metadata: serde_json::Value,
        summary: &mut ChildSummary,
    ) {
        let row = ContentReference {
            source_artifact_id: artifact.id,
            target_content_hash: hash.clone(),
            kind: kind.to_string(),
            metadata,
            repository_id: artifact.repository_id,
            recorded_at: Utc::now(),
        };
        match self.content_references.insert(row).await {
            Ok(()) => summary.membership_edges_written += 1,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    artifact_id = %artifact.id,
                    kind,
                    target = %hash,
                    "oci-index-child-ingest: content_references insert failed; membership \
                     edge not registered (non-fatal, eventual)",
                );
            }
        }
    }

    /// Enqueue one `oci-index-child-ingest` row per grandchild of the index
    /// this call ingested, in a single statement.
    ///
    /// Batched for the same reason the pull-through legs' enqueue is: this is
    /// a cohort, bounded only by the domain's per-index child cap, and a
    /// per-row entry point would mean that many round-trips and that many
    /// conflicts surfaced and swallowed one at a time. Rows the
    /// `jobs.idempotency_key` unique index absorbs simply do not come back
    /// with an id — the dedupe key doing its job, not a failure. A statement
    /// error is non-fatal and leaves every grandchild on the lazy pull path.
    async fn enqueue_grandchildren(
        &self,
        repo: &Repository,
        parsed: &OciIndexChildIngestParams,
        grandchildren: &[ContentHash],
        depth: u32,
        summary: &mut ChildSummary,
    ) {
        if grandchildren.is_empty() {
            return;
        }
        // A grandchild inherits its parent's requested name: it is reached
        // through the same client-facing coordinate, so it must resolve
        // through the same mapping. It does NOT inherit the depth — it sits
        // one level deeper, which is what the depth cap counts.
        let rows: Vec<IdempotentEnqueueRow> = grandchildren
            .iter()
            .map(|grandchild| IdempotentEnqueueRow {
                kind: OCI_INDEX_CHILD_INGEST_KIND.to_string(),
                params: child_ingest_params_at_depth(
                    repo.id,
                    &parsed.requested_name,
                    grandchild,
                    depth,
                ),
                priority: CHILD_INGEST_ENQUEUE_PRIORITY,
                trigger_source: CHILD_INGEST_TRIGGER_SOURCE.to_string(),
                idempotency_key: child_ingest_idempotency_key(repo.id, grandchild),
            })
            .collect();
        match self.jobs.enqueue_idempotent_batch(&rows).await {
            Ok(inserted) => {
                summary.grandchildren_enqueued += inserted.len() as u64;
                summary.grandchildren_deduped += (rows.len() - inserted.len()) as u64;
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    repository = %repo.key,
                    child_digest = %parsed.child_digest,
                    declared_children = rows.len(),
                    "oci-index-child-ingest: grandchild enqueue failed; those grandchildren \
                     stay on the lazy pull path",
                );
                // All-or-nothing: the statement either inserts the cohort or
                // inserts none of it, so every grandchild is a failure here.
                summary.grandchildren_failed += rows.len() as u64;
            }
        }
    }
}

impl TaskHandler for OciIndexChildIngestHandler {
    fn kind(&self) -> &'static str {
        OCI_INDEX_CHILD_INGEST_KIND
    }

    #[tracing::instrument(skip(self, params))]
    fn run<'a>(
        &'a self,
        params: &'a serde_json::Value,
        _ctx: TaskContext,
    ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
        Box::pin(async move {
            let parsed: OciIndexChildIngestParams = match serde_json::from_value(params.clone()) {
                Ok(p) => p,
                Err(err) => {
                    return Ok(TaskOutcome::fail(
                        format!("oci-index-child-ingest params JSON invalid: {err}"),
                        false,
                    ));
                }
            };
            let Some(child_hash) = parse_child_digest(&parsed.child_digest) else {
                return Ok(TaskOutcome::fail(
                    format!(
                        "oci-index-child-ingest: child_digest {:?} is not a sha256:<64-hex> \
                         OCI digest",
                        parsed.child_digest
                    ),
                    false,
                ));
            };

            let mut summary = ChildSummary::default();
            let outcome = match self.ingest_child(&parsed, &child_hash, &mut summary).await {
                Ok(o) => o,
                Err(failed) => return Ok(failed),
            };

            // A grandchild that could not be enqueued falls back to the lazy
            // pull path, which is correct but not free: that child's
            // quarantine window no longer starts until a client asks for it.
            // The count reaches `result_summary` regardless; this line is what
            // puts the degradation in front of an operator watching severity.
            if summary.grandchildren_failed > 0 {
                tracing::warn!(
                    repository_id = %parsed.repository_id,
                    requested_name = %parsed.requested_name,
                    child_digest = %parsed.child_digest,
                    grandchildren_failed = summary.grandchildren_failed,
                    grandchildren_enqueued = summary.grandchildren_enqueued,
                    "oci-index-child-ingest: grandchild rows could not be enqueued; eager \
                     ingest degraded to the lazy pull path for those children",
                );
            }

            if outcome.is_error() {
                tracing::error!(
                    repository_id = %parsed.repository_id,
                    requested_name = %parsed.requested_name,
                    child_digest = %parsed.child_digest,
                    depth = parsed.depth,
                    outcome = outcome.as_str(),
                    is_index = summary.is_index,
                    membership_edges_written = summary.membership_edges_written,
                    grandchildren_enqueued = summary.grandchildren_enqueued,
                    "oci-index-child-ingest complete",
                );
            } else {
                tracing::info!(
                    repository_id = %parsed.repository_id,
                    requested_name = %parsed.requested_name,
                    child_digest = %parsed.child_digest,
                    depth = parsed.depth,
                    outcome = outcome.as_str(),
                    is_index = summary.is_index,
                    membership_edges_written = summary.membership_edges_written,
                    grandchildren_enqueued = summary.grandchildren_enqueued,
                    "oci-index-child-ingest complete",
                );
            }

            Ok(TaskOutcome::Completed {
                result_summary: json!({
                    "repository_id":            parsed.repository_id,
                    "requested_name":           parsed.requested_name,
                    "child_digest":             parsed.child_digest,
                    "depth":                    parsed.depth,
                    "outcome":                  outcome.as_str(),
                    "is_index":                 summary.is_index,
                    "membership_edges_written": summary.membership_edges_written,
                    "grandchildren_enqueued":   summary.grandchildren_enqueued,
                    "grandchildren_deduped":    summary.grandchildren_deduped,
                    "grandchildren_failed":     summary.grandchildren_failed,
                }),
            })
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap as StdHashMap;

    use chrono::{DateTime, TimeZone};
    use hort_domain::entities::artifact::{Artifact, QuarantineStatus};
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::repository::Repository;
    use hort_domain::events::system_actor;
    use hort_domain::oci::{ManifestBlobRef, OCI_IMAGE_INDEX_MEDIA_TYPE};
    use hort_domain::ports::jobs_repository::{JobRow, JobStatus, KindFields};
    use hort_domain::ports::repository_upstream_mapping_repository::{
        RepositoryUpstreamMapping, UpstreamAuth,
    };
    use hort_domain::ports::upstream_proxy::ManifestFetch;

    use crate::use_cases::artifact_group_use_case::ArtifactGroupUseCase;
    use crate::use_cases::test_support::{
        sample_repository, MockArtifactGroupLifecyclePort, MockArtifactGroupRepository,
        MockArtifactLifecycle, MockArtifactRepository, MockContentReferenceIndex,
        MockCurationRuleRepository, MockEventStore, MockJobsRepository,
        MockPolicyProjectionRepository, MockRepositoryRepository, MockStoragePort,
        MockUpstreamProxy, MockUpstreamResolver, OciMembershipEdgesStubBehaviour,
        StubFormatHandler,
    };

    const IMAGE_MANIFEST_MEDIA_TYPE: &str = OCI_IMAGE_MANIFEST_MEDIA_TYPE;

    // ---------- fixtures ------------------------------------------------

    fn test_job_row() -> JobRow {
        let now = DateTime::<Utc>::from_timestamp(0, 0).expect("epoch");
        JobRow {
            id: Uuid::nil(),
            kind: OCI_INDEX_CHILD_INGEST_KIND.to_string(),
            status: JobStatus::Running,
            params: Some(serde_json::Value::Null),
            actor_id: None,
            priority: CHILD_INGEST_ENQUEUE_PRIORITY,
            trigger_source: CHILD_INGEST_TRIGGER_SOURCE.to_string(),
            attempts: 1,
            created_at: now,
            updated_at: now,
            completed_at: None,
            last_error: None,
            result_summary: None,
            kind_fields: KindFields::Other,
        }
    }

    fn make_context() -> TaskContext {
        TaskContext {
            task_job_id: Uuid::nil(),
            actor: system_actor(),
            correlation_id: Uuid::nil(),
            job_row: test_job_row(),
        }
    }

    fn deterministic_sha(seed: u32) -> ContentHash {
        let s = format!("{seed:064x}");
        s.parse().expect("64-hex sha")
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(bytes))
    }

    fn oci_repo() -> Repository {
        let mut r = sample_repository();
        r.key = "mirror".into();
        r.format = RepositoryFormat::Oci;
        r
    }

    fn mapping_for(repo_id: Uuid, path_prefix: &str) -> RepositoryUpstreamMapping {
        let now = Utc::now();
        RepositoryUpstreamMapping {
            id: Uuid::new_v4(),
            repository_id: repo_id,
            path_prefix: path_prefix.to_string(),
            upstream_url: "https://registry.example".into(),
            upstream_name_prefix: None,
            upstream_auth: UpstreamAuth::Anonymous,
            secret_ref: None,
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
            insecure_upstream_url: false,
            trust_upstream_publish_time: false,
            mtls_cert_ref: None,
            mtls_key_ref: None,
            ca_bundle_ref: None,
            pinned_cert_sha256: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// An image-index body declaring `children`, and a single-image manifest
    /// body. Both are real JSON so the domain's structural probes
    /// (`is_image_index` / `index_child_digests`) see what production would.
    fn index_body(children: &[ContentHash]) -> Vec<u8> {
        let manifests: Vec<serde_json::Value> = children
            .iter()
            .map(|c| {
                json!({
                    "mediaType": IMAGE_MANIFEST_MEDIA_TYPE,
                    "digest": format!("sha256:{}", c.as_ref()),
                    "size": 7,
                })
            })
            .collect();
        json!({
            "schemaVersion": 2,
            "mediaType": OCI_IMAGE_INDEX_MEDIA_TYPE,
            "manifests": manifests,
        })
        .to_string()
        .into_bytes()
    }

    fn image_manifest_body() -> Vec<u8> {
        json!({
            "schemaVersion": 2,
            "mediaType": IMAGE_MANIFEST_MEDIA_TYPE,
            "config": { "digest": format!("sha256:{}", deterministic_sha(0xC0FF_EE00).as_ref()) },
            "layers": [ { "digest": format!("sha256:{}", deterministic_sha(0xDEC0_0001).as_ref()) } ],
        })
        .to_string()
        .into_bytes()
    }

    fn config_and_layer_refs(n_layers: u32) -> Vec<ManifestBlobRef> {
        let mut out = vec![ManifestBlobRef {
            hash: deterministic_sha(0xC0FF_EE00),
            role: ManifestBlobRole::Config,
        }];
        for i in 0..n_layers {
            out.push(ManifestBlobRef {
                hash: deterministic_sha(0xDEC0_0000 + i),
                role: ManifestBlobRole::Layer,
            });
        }
        out
    }

    /// The mock set behind one handler, kept so a test can seed inputs and
    /// read observations back after `run`.
    struct Fixture {
        handler: OciIndexChildIngestHandler,
        repos: Arc<MockRepositoryRepository>,
        artifacts: Arc<MockArtifactRepository>,
        proxy: Arc<MockUpstreamProxy>,
        resolver: Arc<MockUpstreamResolver>,
        refs: Arc<MockContentReferenceIndex>,
        jobs: Arc<MockJobsRepository>,
        repo: Repository,
    }

    /// Build a fully-wired handler over a real `IngestUseCase` and empty
    /// mocks, with the repository + its catch-all mapping already seeded.
    /// `edges` pins what the OCI `FormatHandler` stub derives from a
    /// single-image manifest body.
    async fn fixture(edges: OciMembershipEdgesStubBehaviour) -> Fixture {
        fixture_with_prefix(edges, "").await
    }

    /// As [`fixture`] but with the repository's ONLY upstream mapping scoped
    /// to `mapping_prefix`. With a non-empty prefix the resolver matches only
    /// a requested name that carries it — which is the multi-upstream proxy
    /// shape a catch-all-only lookup could not serve.
    async fn fixture_with_prefix(
        edges: OciMembershipEdgesStubBehaviour,
        mapping_prefix: &str,
    ) -> Fixture {
        let repo = oci_repo();
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());
        let resolver = Arc::new(MockUpstreamResolver::new());
        resolver.insert(mapping_for(repo.id, mapping_prefix));

        let artifacts = Arc::new(MockArtifactRepository::new());
        let proxy = Arc::new(MockUpstreamProxy::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let jobs = Arc::new(MockJobsRepository::default());

        let events = Arc::new(MockEventStore::new());
        let lifecycle = Arc::new(MockArtifactLifecycle::new(artifacts.clone()));
        let storage = Arc::new(MockStoragePort::new());
        let groups = Arc::new(MockArtifactGroupRepository::new());
        let group_lifecycle = Arc::new(MockArtifactGroupLifecyclePort::new(groups.clone()));
        let group_uc = Arc::new(ArtifactGroupUseCase::new(groups, group_lifecycle, true));
        let curation_rules = Arc::new(MockCurationRuleRepository::new());
        let policies = Arc::new(MockPolicyProjectionRepository::new());

        let ingest = Arc::new(IngestUseCase::new(
            storage,
            lifecycle,
            artifacts.clone(),
            repos.clone(),
            crate::event_store_publisher::wrap_for_test(events),
            curation_rules,
            group_uc,
            true,
            StdHashMap::new(),
            0,
            refs.clone(),
            policies,
            jobs.clone(),
        ));

        let oci_handler: Arc<dyn FormatHandler> =
            Arc::new(StubFormatHandler::new("oci").with_oci_membership_edges(edges));

        let handler = OciIndexChildIngestHandler::new(
            repos.clone(),
            artifacts.clone(),
            proxy.clone(),
            resolver.clone(),
            refs.clone(),
            jobs.clone(),
            oci_handler,
            ingest,
        );
        Fixture {
            handler,
            repos,
            artifacts,
            proxy,
            resolver,
            refs,
            jobs,
            repo,
        }
    }

    /// The consumer-shaped params for `child_digest`. Spelled out rather than
    /// routed through [`child_ingest_params`] because several tests need a
    /// `child_digest` the producer helper cannot express (a `sha512:` digest,
    /// a hash the proxy was never seeded with).
    fn params(repo_id: Uuid, child_digest: &str) -> serde_json::Value {
        params_named(repo_id, "library/nginx", child_digest)
    }

    /// [`params`] with an explicit client-facing requested name, for the
    /// prefix-scoped-mapping cases. Carries NO `depth` key — the root-level
    /// shape a pull-through leg mints, which every test that does not care
    /// about the depth bound uses.
    fn params_named(repo_id: Uuid, requested_name: &str, child_digest: &str) -> serde_json::Value {
        json!({
            "repository_id": repo_id,
            "requested_name": requested_name,
            "child_digest": child_digest,
        })
    }

    /// [`params`] for a row sitting `depth` levels into a nested-index chain.
    fn params_at_depth(repo_id: Uuid, child_digest: &str, depth: u32) -> serde_json::Value {
        let mut v = params(repo_id, child_digest);
        v["depth"] = json!(depth);
        v
    }

    /// Seed the upstream fixture for `body` at its own digest and return the
    /// `sha256:<hex>` reference the params carry.
    fn seed_child(
        proxy: &MockUpstreamProxy,
        body: &[u8],
        media_type: &str,
        declared_digest: Option<String>,
    ) -> String {
        seed_child_at(
            proxy,
            "",
            "library/nginx",
            body,
            media_type,
            declared_digest,
        )
    }

    /// [`seed_child`] against an explicit `(path_prefix, upstream_name)` pair
    /// — the coordinates the resolver hands the proxy once a prefix-scoped
    /// mapping has stripped the requested name.
    fn seed_child_at(
        proxy: &MockUpstreamProxy,
        path_prefix: &str,
        upstream_name: &str,
        body: &[u8],
        media_type: &str,
        declared_digest: Option<String>,
    ) -> String {
        let digest = format!("sha256:{}", sha256_hex(body));
        proxy.insert_manifest(
            path_prefix,
            upstream_name,
            &digest,
            ManifestFetch {
                bytes: body.to_vec(),
                media_type: media_type.to_string(),
                declared_digest,
                last_modified: None,
            },
        );
        digest
    }

    /// The rows of the one and only cohort the recursion enqueued. The
    /// statement-count assertion lives here so every caller pins "one
    /// statement per nested index", not only the test that says so by name.
    fn single_cohort(jobs: &MockJobsRepository) -> Vec<IdempotentEnqueueRow> {
        let calls = jobs.idempotent_batch_calls();
        assert_eq!(
            calls.len(),
            1,
            "the recursion must issue exactly one enqueue statement per nested index",
        );
        calls.into_iter().next().expect("one cohort")
    }

    /// No row reached the queue by EITHER entry point — the batched one the
    /// recursion uses, or the per-row one it must never fall back to.
    fn assert_no_rows_enqueued(jobs: &MockJobsRepository) {
        assert!(jobs.idempotent_batch_calls().is_empty());
        assert!(jobs.enqueue_calls().is_empty());
    }

    fn completed(outcome: TaskOutcome) -> serde_json::Value {
        match outcome {
            TaskOutcome::Completed { result_summary } => result_summary,
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    // =====================================================================
    // kind() + the pure helpers
    // =====================================================================

    #[tokio::test]
    async fn kind_returns_oci_index_child_ingest() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Edges(Vec::new())).await;
        assert_eq!(f.handler.kind(), OCI_INDEX_CHILD_INGEST_KIND);
        assert_eq!(f.handler.kind(), "oci-index-child-ingest");
    }

    /// The kind must be a valid `jobs.kind` value — i.e. present in the SQL
    /// CHECK's Rust-side mirror. Without this a row of this kind would be
    /// rejected at INSERT with a 23514 that no mock-based test can see.
    #[test]
    fn kind_is_a_member_of_event_task_kinds() {
        use hort_domain::events::EVENT_TASK_KINDS;
        assert!(
            EVENT_TASK_KINDS.contains(&OCI_INDEX_CHILD_INGEST_KIND),
            "{OCI_INDEX_CHILD_INGEST_KIND} MUST appear in EVENT_TASK_KINDS",
        );
    }

    /// Handler-enqueued only: there is no operator-invoke surface, so the
    /// kind must stay OUT of the admin-invokable set.
    #[test]
    fn kind_is_not_admin_invokable() {
        use hort_domain::events::ADMIN_INVOKABLE_TASK_KINDS;
        assert!(
            !ADMIN_INVOKABLE_TASK_KINDS.contains(&OCI_INDEX_CHILD_INGEST_KIND),
            "{OCI_INDEX_CHILD_INGEST_KIND} is handler-enqueued only and must not be \
             admin-invokable",
        );
    }

    #[test]
    fn parse_child_digest_accepts_sha256_and_rejects_everything_else() {
        let hex = "a".repeat(64);
        assert_eq!(
            parse_child_digest(&format!("sha256:{hex}"))
                .expect("valid")
                .as_ref(),
            hex.as_str()
        );
        assert!(parse_child_digest(&format!("sha512:{}", "a".repeat(128))).is_none());
        assert!(parse_child_digest("sha256:not-valid-hex").is_none());
        assert!(parse_child_digest("").is_none());
    }

    #[test]
    fn child_manifest_coords_use_the_manifests_prefix_and_oci_format() {
        let hash = deterministic_sha(7);
        let c = child_manifest_coords("library/nginx", &hash);
        assert_eq!(c.path, format!("manifests/sha256:{}", hash.as_ref()));
        assert_eq!(c.name, "library/nginx");
        assert_eq!(c.name_as_published, "library/nginx");
        assert_eq!(c.version, None);
        assert!(c.metadata.is_null());
        assert!(matches!(c.format, RepositoryFormat::Oci));
    }

    #[test]
    fn child_ingest_params_round_trip_through_the_consumer_shape() {
        let repo_id = Uuid::new_v4();
        let hash = deterministic_sha(0xB0B);
        let value = child_ingest_params(repo_id, "dockerhub/library/nginx", &hash);
        let parsed: OciIndexChildIngestParams =
            serde_json::from_value(value).expect("the producer shape must deserialize");
        assert_eq!(parsed.repository_id, repo_id);
        assert_eq!(parsed.requested_name, "dockerhub/library/nginx");
        assert_eq!(parsed.child_digest, oci_digest_ref(&hash));
        assert_eq!(
            parse_child_digest(&parsed.child_digest).expect("consumer parses it back"),
            hash,
            "the producer can only mint a digest the consumer accepts",
        );
        assert_eq!(
            parsed.depth, CHILD_INGEST_ROOT_DEPTH,
            "a pull-through leg observes the index a client asked for, which is the root",
        );
    }

    /// A row whose params carry no `depth` — every row minted before the
    /// field existed — parses as a root-level row rather than failing.
    #[test]
    fn params_without_a_depth_field_parse_as_the_root_level() {
        let parsed: OciIndexChildIngestParams = serde_json::from_value(json!({
            "repository_id": Uuid::new_v4(),
            "requested_name": "library/nginx",
            "child_digest": oci_digest_ref(&deterministic_sha(1)),
        }))
        .expect("a row without `depth` must still deserialize");
        assert_eq!(parsed.depth, CHILD_INGEST_ROOT_DEPTH);
        assert_eq!(root_depth(), CHILD_INGEST_ROOT_DEPTH);
    }

    /// The recursion's producer helper carries the depth it was given, so a
    /// grandchild row is minted one level below its parent.
    #[test]
    fn child_ingest_params_at_depth_round_trips_the_depth() {
        let repo_id = Uuid::new_v4();
        let hash = deterministic_sha(0xD3D);
        let value = child_ingest_params_at_depth(repo_id, "library/nginx", &hash, 3);
        let parsed: OciIndexChildIngestParams =
            serde_json::from_value(value).expect("the producer shape must deserialize");
        assert_eq!(parsed.depth, 3);
        assert_eq!(parsed.repository_id, repo_id);
    }

    #[test]
    fn idempotency_key_is_kind_repo_and_digest() {
        let repo_id = Uuid::new_v4();
        let hash = deterministic_sha(0xC0C);
        let key = child_ingest_idempotency_key(repo_id, &hash);
        assert_eq!(
            key.as_str(),
            format!("oci-index-child-ingest:{repo_id}:{}", oci_digest_ref(&hash))
        );
        // Two repositories asking for the same content are distinct units of
        // work — ADR 0054 anchors per row, so they must not collapse.
        let other = child_ingest_idempotency_key(Uuid::new_v4(), &hash);
        assert_ne!(key.as_str(), other.as_str());
        // …and two children in one repository are distinct too.
        let sibling = child_ingest_idempotency_key(repo_id, &deterministic_sha(0xD0D));
        assert_ne!(key.as_str(), sibling.as_str());
    }

    #[test]
    fn resolve_media_type_falls_back_when_upstream_declares_none() {
        assert_eq!(
            resolve_media_type(Some(IMAGE_MANIFEST_MEDIA_TYPE)),
            IMAGE_MANIFEST_MEDIA_TYPE
        );
        assert_eq!(resolve_media_type(None), FALLBACK_MEDIA_TYPE);
    }

    #[test]
    fn is_index_media_type_recognises_both_index_shapes_only() {
        assert!(is_index_media_type(OCI_IMAGE_INDEX_MEDIA_TYPE));
        assert!(is_index_media_type(DOCKER_MANIFEST_LIST_MEDIA_TYPE));
        assert!(!is_index_media_type(IMAGE_MANIFEST_MEDIA_TYPE));
        assert!(!is_index_media_type(DOCKER_MANIFEST_V2_MEDIA_TYPE));
    }

    #[test]
    fn manifest_accept_covers_both_schemas_and_both_shapes() {
        let accept = manifest_accept();
        for expected in [
            OCI_IMAGE_MANIFEST_MEDIA_TYPE,
            OCI_IMAGE_INDEX_MEDIA_TYPE,
            DOCKER_MANIFEST_V2_MEDIA_TYPE,
            DOCKER_MANIFEST_LIST_MEDIA_TYPE,
        ] {
            assert!(
                accept.iter().any(|a| a == expected),
                "Accept list is missing {expected}",
            );
        }
    }

    #[test]
    fn child_outcome_labels_and_severity_are_exhaustive() {
        for (outcome, label, is_error) in [
            (ChildOutcome::Ingested, "ingested", false),
            (
                ChildOutcome::IngestedDepthCapped,
                "ingested_depth_capped",
                false,
            ),
            (ChildOutcome::AlreadyPresent, "already_present", false),
            (ChildOutcome::RepositoryMissing, "repository_missing", false),
            (
                ChildOutcome::UpstreamMappingMissing,
                "upstream_mapping_missing",
                false,
            ),
            (ChildOutcome::UpstreamNotFound, "upstream_not_found", false),
            (ChildOutcome::HardFailure, "hard_failure", true),
        ] {
            assert_eq!(outcome.as_str(), label);
            assert_eq!(outcome.is_error(), is_error, "severity for {label}");
        }
    }

    // =====================================================================
    // Param validation — non-retryable rejections
    // =====================================================================

    #[tokio::test]
    async fn run_with_unparseable_params_fails_without_retry() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Edges(Vec::new())).await;
        let outcome = f
            .handler
            .run(&json!({ "repository_id": "not-a-uuid" }), make_context())
            .await
            .expect("Ok");
        match outcome {
            TaskOutcome::Failed { retry, reason } => {
                assert!(!retry, "a malformed params row can never succeed on retry");
                assert!(reason.contains("params JSON invalid"), "{reason}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_with_non_sha256_child_digest_fails_without_retry() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Edges(Vec::new())).await;
        let outcome = f
            .handler
            .run(
                &params(f.repo.id, &format!("sha512:{}", "a".repeat(128))),
                make_context(),
            )
            .await
            .expect("Ok");
        match outcome {
            TaskOutcome::Failed { retry, reason } => {
                assert!(!retry);
                assert!(reason.contains("sha256:<64-hex>"), "{reason}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    // =====================================================================
    // Resolution no-ops — Completed, normal severity
    // =====================================================================

    #[tokio::test]
    async fn run_with_missing_repository_completes_as_a_no_op() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Edges(Vec::new())).await;
        let digest = format!("sha256:{}", "d".repeat(64));
        let summary = completed(
            f.handler
                .run(&params(Uuid::new_v4(), &digest), make_context())
                .await
                .expect("Ok"),
        );
        assert_eq!(summary["outcome"], "repository_missing");
        assert_eq!(f.refs.entry_count(), 0);
        assert_no_rows_enqueued(&f.jobs);
    }

    #[tokio::test]
    async fn run_with_unloadable_repository_fails_with_retry() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Edges(Vec::new())).await;
        f.repos
            .fail_next_find_by_id(DomainError::Invariant("simulated pool exhaustion".into()));
        let digest = format!("sha256:{}", "d".repeat(64));
        let outcome = f
            .handler
            .run(&params(f.repo.id, &digest), make_context())
            .await
            .expect("Ok");
        match outcome {
            TaskOutcome::Failed { retry, reason } => {
                assert!(retry, "an infrastructure read must be retried, not guessed");
                assert!(reason.contains("not loadable"), "{reason}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_with_no_mapping_prefixing_the_requested_name_completes_as_a_no_op() {
        // The repository's only mapping is scoped to `dockerhub/`, and the
        // row asks for a name that does not carry that prefix — nothing to
        // fetch through.
        let f = fixture_with_prefix(
            OciMembershipEdgesStubBehaviour::Edges(Vec::new()),
            "dockerhub/",
        )
        .await;
        let digest = format!("sha256:{}", "d".repeat(64));
        let summary = completed(
            f.handler
                .run(&params(f.repo.id, &digest), make_context())
                .await
                .expect("Ok"),
        );
        assert_eq!(summary["outcome"], "upstream_mapping_missing");
        assert_eq!(f.resolver.entry_count(), 1, "the mapping set is unchanged");
    }

    /// A multi-upstream proxy whose mappings are ALL prefix-scoped has no
    /// catch-all. Resolving the client-facing requested name is what keeps
    /// eager child ingest working there instead of silently falling back to
    /// the lazy path for every child.
    #[tokio::test]
    async fn run_with_a_prefix_scoped_mapping_only_still_ingests_the_child() {
        let f = fixture_with_prefix(
            OciMembershipEdgesStubBehaviour::Edges(config_and_layer_refs(1)),
            "dockerhub/",
        )
        .await;
        let body = image_manifest_body();
        // The proxy is keyed on the STRIPPED name the resolver returns, so a
        // catch-all-shaped lookup would miss it entirely.
        let digest = seed_child_at(
            &f.proxy,
            "dockerhub/",
            "library/nginx",
            &body,
            IMAGE_MANIFEST_MEDIA_TYPE,
            None,
        );
        let summary = completed(
            f.handler
                .run(
                    &params_named(f.repo.id, "dockerhub/library/nginx", &digest),
                    make_context(),
                )
                .await
                .expect("Ok"),
        );
        assert_eq!(summary["outcome"], "ingested");

        let minted = f
            .artifacts
            .find_by_repo_and_checksum(f.repo.id, &sha256_hex(&body).parse().expect("sha"))
            .await
            .expect("query")
            .expect("minted");
        assert_eq!(
            minted.name, "dockerhub/library/nginx",
            "the eagerly-ingested child records the SAME client-facing name a lazy \
             pull of the same child would record",
        );
    }

    // =====================================================================
    // Local-presence short-circuit
    // =====================================================================

    #[tokio::test]
    async fn run_with_child_already_in_target_repo_makes_no_upstream_request() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Edges(
            config_and_layer_refs(1),
        ))
        .await;
        let body = image_manifest_body();
        let hash: ContentHash = sha256_hex(&body).parse().expect("sha");
        let digest = format!("sha256:{}", hash.as_ref());
        // Deliberately NOT seeded on the proxy: any upstream call would be an
        // unseeded-fixture error and the outcome would not be
        // `already_present`.
        f.artifacts.insert(held_manifest(f.repo.id, &hash, &digest));

        let summary = completed(
            f.handler
                .run(&params(f.repo.id, &digest), make_context())
                .await
                .expect("Ok"),
        );
        assert_eq!(summary["outcome"], "already_present");
        assert_eq!(
            summary["membership_edges_written"], 0,
            "an already-held child writes nothing — no re-mint, no re-anchor"
        );
        assert_eq!(f.refs.entry_count(), 0);
        assert_no_rows_enqueued(&f.jobs);
    }

    /// The presence check is scoped to the TARGET repository: the same
    /// content held elsewhere is a different row with a different anchor
    /// (ADR 0054) and must not suppress the mint here.
    #[tokio::test]
    async fn run_with_child_held_only_in_another_repo_still_ingests() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Edges(
            config_and_layer_refs(1),
        ))
        .await;
        let body = image_manifest_body();
        let hash: ContentHash = sha256_hex(&body).parse().expect("sha");
        let digest = seed_child(&f.proxy, &body, IMAGE_MANIFEST_MEDIA_TYPE, None);
        f.artifacts
            .insert(held_manifest(Uuid::new_v4(), &hash, &digest));

        let summary = completed(
            f.handler
                .run(&params(f.repo.id, &digest), make_context())
                .await
                .expect("Ok"),
        );
        assert_eq!(summary["outcome"], "ingested");
    }

    #[tokio::test]
    async fn run_with_failing_presence_lookup_fails_with_retry() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Edges(Vec::new())).await;
        f.artifacts
            .fail_next_find_by_repo_and_checksum(DomainError::Invariant("simulated".into()));
        let digest = format!("sha256:{}", "d".repeat(64));
        let outcome = f
            .handler
            .run(&params(f.repo.id, &digest), make_context())
            .await
            .expect("Ok");
        match outcome {
            TaskOutcome::Failed { retry, reason } => {
                assert!(retry);
                assert!(reason.contains("local-presence lookup"), "{reason}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    // =====================================================================
    // Upstream fetch outcomes
    // =====================================================================

    /// An index may legitimately declare a manifest the upstream no longer
    /// serves: normal severity, no escalation.
    #[tokio::test]
    async fn run_with_upstream_404_completes_without_escalating() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Edges(Vec::new())).await;
        // Unseeded fixture — the mock's default is an
        // `upstream:not_found:…`-sentinel error.
        let digest = format!("sha256:{}", "e".repeat(64));
        let summary = completed(
            f.handler
                .run(&params(f.repo.id, &digest), make_context())
                .await
                .expect("Ok"),
        );
        assert_eq!(summary["outcome"], "upstream_not_found");
        assert_eq!(f.refs.entry_count(), 0);
    }

    #[tokio::test]
    async fn run_with_upstream_5xx_escalates_as_a_hard_failure() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Edges(Vec::new())).await;
        f.proxy.fail_next_manifest_with(DomainError::Invariant(
            "upstream:upstream_5xx:mock 503".into(),
        ));
        let digest = format!("sha256:{}", "e".repeat(64));
        let summary = completed(
            f.handler
                .run(&params(f.repo.id, &digest), make_context())
                .await
                .expect("Ok"),
        );
        assert_eq!(
            summary["outcome"], "hard_failure",
            "a 5xx is a genuine hard failure, distinct from an upstream 404"
        );
        assert!(
            ChildOutcome::HardFailure.is_error(),
            "the completion line for a hard failure escalates to ERROR"
        );
    }

    #[tokio::test]
    async fn run_with_no_cached_body_is_a_hard_failure() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Edges(Vec::new())).await;
        let body = image_manifest_body();
        let digest = seed_child(&f.proxy, &body, IMAGE_MANIFEST_MEDIA_TYPE, None);
        f.proxy.next_manifest_yields_no_cache_handle();
        let summary = completed(
            f.handler
                .run(&params(f.repo.id, &digest), make_context())
                .await
                .expect("Ok"),
        );
        assert_eq!(summary["outcome"], "hard_failure");
    }

    #[tokio::test]
    async fn run_with_unreadable_cached_body_is_a_hard_failure() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Edges(Vec::new())).await;
        let body = image_manifest_body();
        let digest = seed_child(&f.proxy, &body, IMAGE_MANIFEST_MEDIA_TYPE, None);
        f.proxy.next_manifest_yields_unreadable_cache_handle();
        let summary = completed(
            f.handler
                .run(&params(f.repo.id, &digest), make_context())
                .await
                .expect("Ok"),
        );
        assert_eq!(summary["outcome"], "hard_failure");
        assert_eq!(f.artifacts.snapshot_all().len(), 0, "nothing was minted");
    }

    // =====================================================================
    // Digest verification
    // =====================================================================

    #[tokio::test]
    async fn run_with_declared_digest_mismatch_fails_and_stores_nothing() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Edges(Vec::new())).await;
        let body = image_manifest_body();
        let digest = seed_child(
            &f.proxy,
            &body,
            IMAGE_MANIFEST_MEDIA_TYPE,
            Some(format!("sha256:{}", "f".repeat(64))),
        );
        let outcome = f
            .handler
            .run(&params(f.repo.id, &digest), make_context())
            .await
            .expect("Ok");
        match outcome {
            TaskOutcome::Failed { retry, reason } => {
                assert!(
                    !retry,
                    "the same upstream content will mismatch again — retrying cannot help"
                );
                assert!(reason.contains("does not match"), "{reason}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        assert_eq!(
            f.artifacts.snapshot_all().len(),
            0,
            "a digest mismatch must never reach CAS"
        );
        assert_eq!(f.refs.entry_count(), 0);
    }

    /// A matching declared digest passes the check (and the comparison is
    /// insensitive to header casing).
    #[tokio::test]
    async fn run_with_matching_declared_digest_ingests() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Edges(
            config_and_layer_refs(1),
        ))
        .await;
        let body = image_manifest_body();
        let hex = sha256_hex(&body);
        let digest = format!("sha256:{hex}");
        f.proxy.insert_manifest(
            "",
            "library/nginx",
            &digest,
            ManifestFetch {
                bytes: body.clone(),
                media_type: IMAGE_MANIFEST_MEDIA_TYPE.to_string(),
                declared_digest: Some(format!("SHA256:{}", hex.to_uppercase())),
                last_modified: None,
            },
        );
        let summary = completed(
            f.handler
                .run(&params(f.repo.id, &digest), make_context())
                .await
                .expect("Ok"),
        );
        assert_eq!(summary["outcome"], "ingested");
    }

    /// The ingest is keyed on the REQUESTED digest, so a body whose bytes
    /// hash to something else is rejected inside `ingest_verified` — the
    /// mint-after-verify guarantee. Here the upstream declares nothing, so
    /// the header check cannot catch it and only the ingest can.
    #[tokio::test]
    async fn run_with_body_that_does_not_hash_to_the_requested_digest_stores_nothing() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Edges(Vec::new())).await;
        let requested = format!("sha256:{}", "a".repeat(64));
        f.proxy.insert_manifest(
            "",
            "library/nginx",
            &requested,
            ManifestFetch {
                bytes: image_manifest_body(),
                media_type: IMAGE_MANIFEST_MEDIA_TYPE.to_string(),
                declared_digest: None,
                last_modified: None,
            },
        );
        let summary = completed(
            f.handler
                .run(&params(f.repo.id, &requested), make_context())
                .await
                .expect("Ok"),
        );
        assert_eq!(summary["outcome"], "hard_failure");
        assert_eq!(
            f.artifacts.snapshot_all().len(),
            0,
            "mint-after-verify: a non-matching body mints no row"
        );
    }

    // =====================================================================
    // Happy path — single-image child
    // =====================================================================

    #[tokio::test]
    async fn run_ingests_an_image_manifest_child_with_its_config_and_layer_edges() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Edges(
            config_and_layer_refs(2),
        ))
        .await;
        let body = image_manifest_body();
        let digest = seed_child(&f.proxy, &body, IMAGE_MANIFEST_MEDIA_TYPE, None);

        let summary = completed(
            f.handler
                .run(&params(f.repo.id, &digest), make_context())
                .await
                .expect("Ok"),
        );
        assert_eq!(summary["outcome"], "ingested");
        assert_eq!(summary["is_index"], false);
        assert_eq!(
            summary["membership_edges_written"], 3,
            "one config edge plus one per layer"
        );
        assert_eq!(summary["grandchildren_enqueued"], 0);

        let minted = f
            .artifacts
            .find_by_repo_and_checksum(f.repo.id, &sha256_hex(&body).parse().expect("sha"))
            .await
            .expect("query")
            .expect("the child manifest row is minted in the target repository");
        assert_eq!(
            minted.path,
            format!("manifests/sha256:{}", sha256_hex(&body)),
            "the row must be reachable by the digest path a later client GET uses"
        );
        assert!(
            f.refs
                .find_by_source_and_kind(f.repo.id, minted.id, OCI_CONFIG_KIND)
                .await
                .expect("query")
                .is_some(),
            "the config blob needs its GC keepalive"
        );
        assert!(f
            .refs
            .find_by_source_and_kind(f.repo.id, minted.id, OCI_LAYER_KIND)
            .await
            .expect("query")
            .is_some());
    }

    /// Nothing in this handler computes or overrides a quarantine anchor —
    /// the minted row carries whatever `ingest_verified` derived (ADR 0054).
    #[tokio::test]
    async fn run_mints_the_child_quarantined_without_supplying_an_anchor() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Edges(
            config_and_layer_refs(0),
        ))
        .await;
        let body = image_manifest_body();
        let digest = seed_child(&f.proxy, &body, IMAGE_MANIFEST_MEDIA_TYPE, None);
        // A content hash hort has never seen: `first_seen_for_checksum`
        // returns `None`, so the anchor is the mint instant — a FULL window,
        // exactly what a later lazy pull would have produced.
        completed(
            f.handler
                .run(&params(f.repo.id, &digest), make_context())
                .await
                .expect("Ok"),
        );
        let minted = f
            .artifacts
            .find_by_repo_and_checksum(f.repo.id, &sha256_hex(&body).parse().expect("sha"))
            .await
            .expect("query")
            .expect("minted");
        assert!(
            matches!(minted.quarantine_status, QuarantineStatus::Quarantined),
            "the eagerly-ingested child is held, exactly like a lazily-pulled one",
        );
        // A held row necessarily carries an anchor — the window it is held
        // for is measured from it. Unwrapping rather than tolerating `None`
        // is what makes the "not backdated" claim load-bearing: an absent
        // anchor would satisfy any is-not-backdated predicate vacuously.
        let start = minted
            .quarantine_window_start
            .expect("a Quarantined row carries the anchor its window is measured from");
        assert!(
            start >= minted.created_at - chrono::Duration::seconds(5),
            "the anchor must not be backdated by this handler",
        );
    }

    #[tokio::test]
    async fn run_records_the_upstream_declared_media_type_on_the_minted_row() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Edges(
            config_and_layer_refs(0),
        ))
        .await;
        let body = image_manifest_body();
        // The upstream declares the generic type rather than a manifest one.
        // The handler records it verbatim (the `Some` arm of
        // `resolve_media_type`) and still ingests; the `None` arm is pinned
        // by `resolve_media_type_falls_back_when_upstream_declares_none`.
        let digest = seed_child(&f.proxy, &body, FALLBACK_MEDIA_TYPE, None);
        let summary = completed(
            f.handler
                .run(&params(f.repo.id, &digest), make_context())
                .await
                .expect("Ok"),
        );
        assert_eq!(summary["outcome"], "ingested");
        let minted = f
            .artifacts
            .find_by_repo_and_checksum(f.repo.id, &sha256_hex(&body).parse().expect("sha"))
            .await
            .expect("query")
            .expect("minted");
        assert_eq!(minted.content_type, FALLBACK_MEDIA_TYPE);
    }

    /// A `FormatHandler` that cannot derive the blob set leaves the child
    /// ingested but un-edged — logged, never fatal.
    #[tokio::test]
    async fn run_with_underivable_blob_refs_still_ingests_but_writes_no_edges() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Validation(
            "corrupt manifest",
        ))
        .await;
        let body = image_manifest_body();
        let digest = seed_child(&f.proxy, &body, IMAGE_MANIFEST_MEDIA_TYPE, None);
        let summary = completed(
            f.handler
                .run(&params(f.repo.id, &digest), make_context())
                .await
                .expect("Ok"),
        );
        assert_eq!(summary["outcome"], "ingested");
        assert_eq!(summary["membership_edges_written"], 0);
    }

    /// A failed `content_references` insert is non-fatal — the manifest is
    /// already committed and the index is eventually authoritative.
    #[tokio::test]
    async fn run_with_failing_edge_insert_still_completes_as_ingested() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Edges(
            config_and_layer_refs(0),
        ))
        .await;
        let body = image_manifest_body();
        let digest = seed_child(&f.proxy, &body, IMAGE_MANIFEST_MEDIA_TYPE, None);
        f.refs.fail_next_insert_for_kind(
            OCI_CONFIG_KIND,
            DomainError::Invariant("simulated oci_config insert failure".into()),
        );
        let summary = completed(
            f.handler
                .run(&params(f.repo.id, &digest), make_context())
                .await
                .expect("Ok"),
        );
        assert_eq!(summary["outcome"], "ingested");
        assert_eq!(summary["membership_edges_written"], 0);
    }

    // =====================================================================
    // Nested index — one enqueue per grandchild
    // =====================================================================

    #[tokio::test]
    async fn run_with_index_child_enqueues_one_row_per_grandchild() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Edges(Vec::new())).await;
        let grandchildren = [deterministic_sha(1), deterministic_sha(2)];
        let body = index_body(&grandchildren);
        let digest = seed_child(&f.proxy, &body, OCI_IMAGE_INDEX_MEDIA_TYPE, None);

        let summary = completed(
            f.handler
                .run(&params(f.repo.id, &digest), make_context())
                .await
                .expect("Ok"),
        );
        assert_eq!(summary["outcome"], "ingested");
        assert_eq!(summary["is_index"], true);
        assert_eq!(
            summary["membership_edges_written"], 2,
            "one oci_index_member row per declared grandchild"
        );
        assert_eq!(summary["grandchildren_enqueued"], 2);
        assert_eq!(summary["grandchildren_deduped"], 0);
        assert_eq!(summary["grandchildren_failed"], 0);

        let cohort = single_cohort(&f.jobs);
        assert_eq!(cohort.len(), 2);
        for (row, grandchild) in cohort.iter().zip(grandchildren.iter()) {
            assert_eq!(
                row.kind, OCI_INDEX_CHILD_INGEST_KIND,
                "recursion by own kind"
            );
            assert_eq!(row.priority, CHILD_INGEST_ENQUEUE_PRIORITY);
            assert_eq!(row.trigger_source, CHILD_INGEST_TRIGGER_SOURCE);
            let expected = format!("sha256:{}", grandchild.as_ref());
            assert_eq!(row.params["child_digest"], expected);
            assert_eq!(
                row.params["requested_name"], "library/nginx",
                "the grandchild inherits its parent's client-facing name",
            );
            assert_eq!(
                row.params["repository_id"],
                serde_json::json!(f.repo.id),
                "the grandchild lands in the same repository",
            );
            assert_eq!(
                row.idempotency_key,
                child_ingest_idempotency_key(f.repo.id, grandchild),
                "every grandchild row carries the (repository, child digest) dedupe key",
            );
        }

        // The index itself gets the member edges, and NOT config/layer ones.
        let minted = f
            .artifacts
            .find_by_repo_and_checksum(f.repo.id, &sha256_hex(&body).parse().expect("sha"))
            .await
            .expect("query")
            .expect("index row minted");
        assert!(f
            .refs
            .find_by_source_and_kind(f.repo.id, minted.id, OCI_INDEX_MEMBER_KIND)
            .await
            .expect("query")
            .is_some());
        assert!(f
            .refs
            .find_by_source_and_kind(f.repo.id, minted.id, OCI_CONFIG_KIND)
            .await
            .expect("query")
            .is_none());
    }

    #[tokio::test]
    async fn run_with_duplicate_grandchild_enqueue_counts_it_as_deduped() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Edges(Vec::new())).await;
        let grandchild = deterministic_sha(1);
        let body = index_body(std::slice::from_ref(&grandchild));
        let digest = seed_child(&f.proxy, &body, OCI_IMAGE_INDEX_MEDIA_TYPE, None);
        f.jobs.seed_idempotent_key_present(
            child_ingest_idempotency_key(f.repo.id, &grandchild)
                .as_str()
                .to_string(),
        );

        let summary = completed(
            f.handler
                .run(&params(f.repo.id, &digest), make_context())
                .await
                .expect("Ok"),
        );
        assert_eq!(summary["grandchildren_enqueued"], 0);
        assert_eq!(
            summary["grandchildren_deduped"], 1,
            "the dedupe key doing its job is not a failure"
        );
        assert_eq!(summary["grandchildren_failed"], 0);
    }

    #[tokio::test]
    async fn run_with_failing_grandchild_enqueue_counts_it_as_failed_but_completes() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Edges(Vec::new())).await;
        let body = index_body(&[deterministic_sha(1)]);
        let digest = seed_child(&f.proxy, &body, OCI_IMAGE_INDEX_MEDIA_TYPE, None);
        f.jobs
            .fail_next_idempotent_batch(DomainError::Invariant("simulated enqueue failure".into()));

        let summary = completed(
            f.handler
                .run(&params(f.repo.id, &digest), make_context())
                .await
                .expect("Ok"),
        );
        assert_eq!(summary["outcome"], "ingested");
        assert_eq!(summary["grandchildren_failed"], 1);
        assert_eq!(
            summary["membership_edges_written"], 1,
            "the member edge still lands — only the enqueue failed"
        );
    }

    /// An index declaring more children than the domain's per-index cap is
    /// REFUSED by `index_child_digests`, never truncated. The child manifest
    /// itself still ingests; it simply contributes no member edges and no
    /// grandchild rows — an over-cap index must not be silently accepted with
    /// a partial child set.
    #[tokio::test]
    async fn run_with_over_cap_index_children_writes_no_edges_and_no_rows() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Edges(Vec::new())).await;
        let over_cap: Vec<ContentHash> = (0..1_025u32).map(deterministic_sha).collect();
        let body = index_body(&over_cap);
        let digest = seed_child(&f.proxy, &body, OCI_IMAGE_INDEX_MEDIA_TYPE, None);

        let summary = completed(
            f.handler
                .run(&params(f.repo.id, &digest), make_context())
                .await
                .expect("Ok"),
        );
        assert_eq!(summary["outcome"], "ingested");
        assert_eq!(summary["is_index"], true);
        assert_eq!(summary["membership_edges_written"], 0);
        assert_eq!(summary["grandchildren_enqueued"], 0);
        assert!(f.jobs.idempotent_batch_calls().is_empty());
    }

    /// An index whose every child descriptor uses a non-CAS digest algorithm
    /// is still structurally an index — `manifests[]` is non-empty — but
    /// yields no enumerable children. No statement is issued for an empty
    /// cohort: an `INSERT … VALUES` with no rows is not a query worth
    /// sending, and a recorded empty cohort would read as "the recursion ran"
    /// when nothing did.
    #[tokio::test]
    async fn run_with_an_index_of_only_non_sha256_children_issues_no_statement() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Edges(Vec::new())).await;
        let body = json!({
            "schemaVersion": 2,
            "mediaType": OCI_IMAGE_INDEX_MEDIA_TYPE,
            "manifests": [ { "digest": format!("sha512:{}", "a".repeat(128)), "size": 7 } ],
        })
        .to_string()
        .into_bytes();
        let digest = seed_child(&f.proxy, &body, OCI_IMAGE_INDEX_MEDIA_TYPE, None);

        let summary = completed(
            f.handler
                .run(&params(f.repo.id, &digest), make_context())
                .await
                .expect("Ok"),
        );
        assert_eq!(summary["outcome"], "ingested");
        assert_eq!(summary["is_index"], true);
        assert_eq!(summary["membership_edges_written"], 0);
        assert_eq!(summary["grandchildren_enqueued"], 0);
        assert_no_rows_enqueued(&f.jobs);
    }

    // =====================================================================
    // Depth bound — the fan-out is a finite tree
    // =====================================================================

    /// A row that carries no depth is a root-level row: its grandchildren are
    /// enqueued one level deeper, and nothing about the root path changes.
    #[tokio::test]
    async fn a_root_level_row_enqueues_its_grandchildren_one_level_deeper() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Edges(Vec::new())).await;
        let body = index_body(&[deterministic_sha(1)]);
        let digest = seed_child(&f.proxy, &body, OCI_IMAGE_INDEX_MEDIA_TYPE, None);

        let summary = completed(
            f.handler
                .run(&params(f.repo.id, &digest), make_context())
                .await
                .expect("Ok"),
        );
        assert_eq!(summary["outcome"], "ingested");
        assert_eq!(
            summary["depth"], CHILD_INGEST_ROOT_DEPTH,
            "an absent depth param is the root level",
        );
        assert_eq!(summary["grandchildren_enqueued"], 1);

        assert_eq!(
            single_cohort(&f.jobs)[0].params["depth"],
            CHILD_INGEST_ROOT_DEPTH + 1
        );
    }

    /// One level below the cap still recurses, and the row it mints carries
    /// exactly the cap — so the cap is inclusive of rows that exist, and it
    /// is the NEXT level that is refused.
    #[tokio::test]
    async fn a_row_one_level_below_the_cap_still_enqueues_at_the_cap() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Edges(Vec::new())).await;
        let body = index_body(&[deterministic_sha(1)]);
        let digest = seed_child(&f.proxy, &body, OCI_IMAGE_INDEX_MEDIA_TYPE, None);

        let summary = completed(
            f.handler
                .run(
                    &params_at_depth(f.repo.id, &digest, MAX_CHILD_INGEST_DEPTH - 1),
                    make_context(),
                )
                .await
                .expect("Ok"),
        );
        assert_eq!(summary["outcome"], "ingested");
        assert_eq!(summary["grandchildren_enqueued"], 1);
        assert_eq!(
            single_cohort(&f.jobs)[0].params["depth"],
            MAX_CHILD_INGEST_DEPTH,
            "the deepest row the recursion ever mints sits AT the cap",
        );
    }

    /// At the cap the chain stops: the index itself is still ingested and its
    /// member edges still written, but no grandchild row is minted. The run
    /// completes under its own outcome label rather than failing — the
    /// refused children stay reachable through the lazy pull path.
    #[tokio::test]
    async fn an_index_at_the_depth_cap_writes_edges_but_enqueues_no_grandchildren() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Edges(Vec::new())).await;
        let grandchildren = [deterministic_sha(1), deterministic_sha(2)];
        let body = index_body(&grandchildren);
        let digest = seed_child(&f.proxy, &body, OCI_IMAGE_INDEX_MEDIA_TYPE, None);

        let summary = completed(
            f.handler
                .run(
                    &params_at_depth(f.repo.id, &digest, MAX_CHILD_INGEST_DEPTH),
                    make_context(),
                )
                .await
                .expect("Ok"),
        );
        assert_eq!(
            summary["outcome"], "ingested_depth_capped",
            "refusing to recurse is a completion with its own label, never a failure",
        );
        assert_eq!(summary["depth"], MAX_CHILD_INGEST_DEPTH);
        assert_eq!(summary["is_index"], true);
        assert_eq!(
            summary["membership_edges_written"], 2,
            "the member edges are membership facts about a committed artifact and are \
             written at every depth — only the job rows are bounded",
        );
        assert_eq!(summary["grandchildren_enqueued"], 0);
        assert_eq!(summary["grandchildren_deduped"], 0);
        assert_eq!(summary["grandchildren_failed"], 0);
        assert!(
            f.jobs.idempotent_batch_calls().is_empty(),
            "the depth cap is what makes the fan-out finite; nothing may be enqueued",
        );

        // The index itself IS held — the cap bounds the recursion, not the
        // ingest of the manifest the row names.
        let minted = f
            .artifacts
            .find_by_repo_and_checksum(f.repo.id, &sha256_hex(&body).parse().expect("sha"))
            .await
            .expect("query")
            .expect("the index at the cap is still minted");
        assert!(f
            .refs
            .find_by_source_and_kind(f.repo.id, minted.id, OCI_INDEX_MEMBER_KIND)
            .await
            .expect("query")
            .is_some());
    }

    /// A row past the cap — a stale row from a deploy with a larger cap, or a
    /// hand-crafted one — is capped too: the comparison is `>`, not `==`.
    #[tokio::test]
    async fn an_index_past_the_depth_cap_is_capped_the_same_way() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Edges(Vec::new())).await;
        let body = index_body(&[deterministic_sha(1)]);
        let digest = seed_child(&f.proxy, &body, OCI_IMAGE_INDEX_MEDIA_TYPE, None);

        let summary = completed(
            f.handler
                .run(
                    &params_at_depth(f.repo.id, &digest, MAX_CHILD_INGEST_DEPTH + 7),
                    make_context(),
                )
                .await
                .expect("Ok"),
        );
        assert_eq!(summary["outcome"], "ingested_depth_capped");
        assert_no_rows_enqueued(&f.jobs);
    }

    /// The cap applies to the recursion only. A single-image child at the cap
    /// has no children to refuse, so it completes as a plain `ingested`.
    #[tokio::test]
    async fn an_image_manifest_at_the_depth_cap_is_not_labelled_depth_capped() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Edges(
            config_and_layer_refs(1),
        ))
        .await;
        let body = image_manifest_body();
        let digest = seed_child(&f.proxy, &body, IMAGE_MANIFEST_MEDIA_TYPE, None);

        let summary = completed(
            f.handler
                .run(
                    &params_at_depth(f.repo.id, &digest, MAX_CHILD_INGEST_DEPTH),
                    make_context(),
                )
                .await
                .expect("Ok"),
        );
        assert_eq!(summary["outcome"], "ingested");
        assert_eq!(summary["membership_edges_written"], 2);
    }

    /// A cycle terminates on the local-presence short-circuit: once the index
    /// is held, its own row is a no-op rather than a re-fetch.
    #[tokio::test]
    async fn run_twice_for_the_same_child_is_a_no_op_the_second_time() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Edges(
            config_and_layer_refs(1),
        ))
        .await;
        let body = image_manifest_body();
        let digest = seed_child(&f.proxy, &body, IMAGE_MANIFEST_MEDIA_TYPE, None);

        let first = completed(
            f.handler
                .run(&params(f.repo.id, &digest), make_context())
                .await
                .expect("Ok"),
        );
        assert_eq!(first["outcome"], "ingested");

        let second = completed(
            f.handler
                .run(&params(f.repo.id, &digest), make_context())
                .await
                .expect("Ok"),
        );
        assert_eq!(
            second["outcome"], "already_present",
            "a re-run must not re-mint or re-anchor"
        );
    }

    // =====================================================================
    // Media-type / body-shape cross-check — the body wins
    // =====================================================================

    #[tokio::test]
    async fn run_with_media_type_disagreeing_with_the_body_follows_the_body() {
        let f = fixture(OciMembershipEdgesStubBehaviour::Edges(
            config_and_layer_refs(1),
        ))
        .await;
        // An index body served under a single-image media type: the edges
        // must be `oci_index_member`, not `oci_config`/`oci_layer`.
        let body = index_body(&[deterministic_sha(1)]);
        let digest = seed_child(&f.proxy, &body, IMAGE_MANIFEST_MEDIA_TYPE, None);

        let summary = completed(
            f.handler
                .run(&params(f.repo.id, &digest), make_context())
                .await
                .expect("Ok"),
        );
        assert_eq!(summary["is_index"], true, "the body's shape decides");
        assert_eq!(summary["grandchildren_enqueued"], 1);

        let minted = f
            .artifacts
            .find_by_repo_and_checksum(f.repo.id, &sha256_hex(&body).parse().expect("sha"))
            .await
            .expect("query")
            .expect("minted");
        assert!(f
            .refs
            .find_by_source_and_kind(f.repo.id, minted.id, OCI_INDEX_MEMBER_KIND)
            .await
            .expect("query")
            .is_some());
        assert!(
            f.refs
                .find_by_source_and_kind(f.repo.id, minted.id, OCI_CONFIG_KIND)
                .await
                .expect("query")
                .is_none(),
            "a mis-declared Content-Type must not misfile the edges"
        );
    }

    // ---------- local doubles -------------------------------------------

    /// Synthesise a manifest row already held in `repo_id` at `hash`.
    fn held_manifest(repo_id: Uuid, hash: &ContentHash, digest: &str) -> Artifact {
        let now = Utc::now();
        Artifact {
            id: Uuid::new_v4(),
            repository_id: repo_id,
            name: "library/nginx".into(),
            name_as_published: "library/nginx".into(),
            version: None,
            path: format!("manifests/{digest}"),
            size_bytes: 0,
            sha256_checksum: hash.clone(),
            sha1_checksum: None,
            md5_checksum: None,
            content_type: IMAGE_MANIFEST_MEDIA_TYPE.into(),
            quarantine_status: QuarantineStatus::Quarantined,
            rejection_reason: None,
            quarantine_window_start: Some(Utc.timestamp_opt(0, 0).unwrap()),
            quarantine_deadline: None,
            deleted_at: None,
            upstream_published_at: None,
            uploaded_by: None,
            created_at: now,
            updated_at: now,
        }
    }
}
