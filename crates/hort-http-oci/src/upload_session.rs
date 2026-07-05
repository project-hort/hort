//! OCI three-phase blob upload — session state machine.
//!
//! [`initiate`] creates a new session row in
//! [`hort_domain::ports::ephemeral_store::EphemeralStore`] and returns
//! the client-visible `session_id`. `append_chunk` (PATCH) and
//! `finalize` (PUT) extend this module over the same record shape.
//!
//! See `docs/architecture/how-to/oci-pull-through.md` for the OCI
//! registry design, upload lifecycle, and auth-discovery handshake.
//!
//! # Why free functions (not a use case)
//!
//! The upload-session state machine is **format-specific HTTP
//! coordination**, not an application-layer concern. It composes over
//! the generic [`hort_app::use_cases::ingest_use_case::IngestUseCase`]
//! (the only application layer primitive it touches) and the workspace-
//! wide [`EphemeralStore`] port.  Putting a `OciUploadSessionUseCase`
//! in `hort-app` would leak OCI vocabulary into the format-agnostic
//! application layer (ADR 0008).
//!
//! # Key-space convention
//!
//! `stateful_upload:oci_v2:{session_id}`. The OCI prefix was bumped
//! from `oci` to `oci_v2` so new postcard-encoded records never share
//! key-space with legacy bincode-encoded records — the latter expire
//! via TTL during the deploy window. Other formats (Maven chunked PUT,
//! Git LFS batch transfer) reuse the
//! `stateful_upload:{format}:{session_id}` layout via [`session_key`]
//! with their own format token; they were never on the bincode path so
//! they keep their bare format names (`maven`, `lfs`, …).
//!
//! # Session record value
//!
//! Encoded as `postcard` bytes (`bincode 2.0` was RUSTSEC-2025-0141
//! unmaintained and replaced).  JSON would work but adds parser overhead
//! and wire-size noise for a fixed-shape internal adapter payload; the
//! field set is under the crate's control and no foreign tool reads it.
//! `session_id` is the key, not a field on the value.
//!
//! The record carries a `version: u64` field for optimistic-concurrency
//! CAS on PATCH appends. The `EphemeralStore` port's own CAS version counter is
//! opaque from this module's perspective; mirroring it inside the
//! encoded record gives callers a self-describing "what
//! expected_version do I pass to `compare_and_swap`?" primitive
//! without widening the port trait with a `get_with_version`.
//! Every successful CAS bumps the record's `version` by one in step
//! with the port's own bump, so the two remain identical by
//! construction.
//!
//! # Wire-format stability
//!
//! `postcard` encodes struct fields in declaration order with no
//! field tags. Adding, removing, or reordering fields on
//! [`UploadSessionRecord`] is a breaking wire-format change. The
//! migration strategy is **drain-via-TTL**: bump the
//! [`session_key`] prefix (currently `stateful_upload:oci_v2:`) to
//! `oci_v3:` etc. on the next breaking change, and let in-flight
//! sessions expire via the session max-age
//! ([`OCI_SESSION_MAX_AGE_SECS`]).  No dual-format reader exists; old
//! keys are unreachable from new code.

use std::time::{Duration, Instant};

use bytes::Bytes;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::Instrument;
use uuid::Uuid;

use hort_app::error::{AppError, AppResult};
use hort_app::use_cases::ingest_use_case::{IngestOutcome, VerifiedIngestRequest};
use hort_domain::error::DomainError;
use hort_domain::events::ApiActor;
use hort_domain::types::ContentHash;
use hort_formats::oci::OciFormatHandler;
use hort_http_core::context::AppContext;
use hort_http_core::upload_session_cap::{self, AdmitOutcome};

use super::coords::oci_blob_coords;

/// The stateful-upload format token this adapter passes to the generic
/// per-`(repo, principal)` cap primitive
/// ([`hort_http_core::upload_session_cap`]). It is the cap-set keyspace
/// segment (`upload_sessions:oci:…`) and the `format` metric label on the
/// cap-rejection / reconcile-prune counters.
const OCI_CAP_FORMAT: &str = "oci";

// ---------------------------------------------------------------------------
// TTL / max-age
// ---------------------------------------------------------------------------

/// Default upload-session max-age, in seconds. Threaded through
/// `hort-server::Config` as `HORT_OCI_SESSION_MAX_AGE_SECS` onto
/// [`OciHttpConfig::session_max_age_secs`]; the constant is the fallback
/// when a caller constructs a bare `OciHttpConfig::default()`.
///
/// The one-hour ceiling matches the Docker Registry v2 reference
/// implementation and gives humans enough time to retry a
/// multi-gigabyte push over a flaky link without GC'ing the session out
/// from under them. It serves a dual role for the live session set:
///
/// - the TTL applied on every set write (backstop — the whole
///   `(repo, principal)` set self-expires if idle for this long);
/// - the age-prune threshold on admit — a member older than this is
///   reclaimed on the next admit, so an abandoned session can never pin
///   the cap past this window.
pub const OCI_SESSION_MAX_AGE_SECS: u64 = 3600;

/// Bounded `Retry-After` advisory (seconds) returned on a cap-exceeded
/// `429`. The cap is a transient live-count, not a per-session hold —
/// abandoned members age out on the next admit — so the client should
/// retry soon, NOT wait the full session max-age. A short fixed value
/// keeps a well-behaved client's back-off tight without inviting a
/// tight-loop retry storm.
pub const OCI_CAP_RETRY_AFTER_SECS: i64 = 15;

// ---------------------------------------------------------------------------
// Key
// ---------------------------------------------------------------------------

/// Build the `EphemeralStore` key for a stateful-upload session.
///
/// Convention is caller-enforced so the `EphemeralStore` port stays
/// key-agnostic; no adapter ever parses or prefix-strips the key.
/// Shape is `stateful_upload:{token}:{session_id}` where `{token}`
/// is the value of [`format_token`] applied to `format`.
///
/// The OCI token is `oci_v2` (not `oci`) so legacy bincode-encoded
/// records never enter the postcard decoder's path. See [`format_token`]
/// for the per-format mapping.
pub fn session_key(format: &str, session_id: Uuid) -> String {
    let token = format_token(format);
    format!("stateful_upload:{token}:{session_id}")
}

/// Resolve a logical format name (`oci`, `maven`, `lfs`, …) to the
/// versioned key-space token used in [`session_key`].
///
/// The indirection exists because the OCI session record's wire format
/// changed from `bincode 2.0` to `postcard` and the key-space had to
/// fork so old records do not meet the new decoder. Future wire-format
/// breaks bump the suffix again (`oci_v3`, …); other formats follow the
/// same rule when they migrate. Logical format strings (`"oci"`,
/// `"maven"`) stay stable — only the key-space token changes.
pub fn format_token(format: &str) -> &str {
    match format {
        "oci" => "oci_v2",
        // Other formats have not (yet) had a wire-format break —
        // the bare format name doubles as the key-space token.
        other => other,
    }
}

// ---------------------------------------------------------------------------
// Record
// ---------------------------------------------------------------------------

/// Value stored under a session key.
///
/// `DateTime<Utc>` isn't trivially encodable in `postcard`'s no_std
/// path, so `created_at_unix_millis` holds the epoch timestamp in
/// milliseconds — enough precision for GC scheduling and idempotency-
/// window reasoning without pulling `chrono`'s serde feature into this
/// crate.  `repository_id_bytes` and `principal_id_bytes` store UUIDs
/// as 16 raw bytes for the same reason — keeps the `serde` impl
/// trivial and the wire format compact.  Callers interact with the
/// logical view via [`UploadSessionRecord::new`] and the
/// `repository_id()` / `principal_id()` accessors; the byte fields
/// stay internal.
///
/// `session_id` is the key, not a field here.  The `EphemeralStore`
/// version counter is opaque from the caller's point of view and lives
/// beside the record on the backend.
///
/// `principal_id_bytes` allows finalize / cleanup paths to release the
/// per-`(repo, principal)` live-session set member without re-querying
/// the originating request. Sessions are max-age-bounded; a deployment
/// that introduces this field handles the transient deploy-window
/// decode failures via the existing `Invariant` mapping — the session
/// set naturally age-prunes even when a few sessions skip the release.
///
/// # Wire-format invariant
///
/// `postcard` encodes fields in declaration order with no field
/// tags. Reordering, adding, or removing fields is a breaking
/// change. The drain-via-TTL migration covers the bincode → postcard
/// switch; future schema breaks MUST bump the [`session_key`] prefix
/// the same way (`oci_v3`, …) and let in-flight sessions expire under
/// the legacy prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct UploadSessionRecord {
    pub repository_id_bytes: [u8; 16],
    pub bytes_received: u64,
    pub created_at_unix_millis: i64,
    /// In-record mirror of the [`EphemeralStore`] CAS version counter.
    /// Set to `1` on `initiate` (matching the store's contract that
    /// `put_if_absent` yields version `1`); bumped by exactly one on
    /// every successful CAS from `append_chunk` + `finalize`. Callers
    /// decode the record, read `version`, pass it as `expected_version`
    /// to `compare_and_swap`, and — on success — write back a record
    /// with `version: old + 1` so subsequent PATCHes see the mirror
    /// that matches the store's new counter.
    pub version: u64,
    /// The principal that opened the session. Used by finalize /
    /// cleanup paths to release the per-`(repo, principal)` live-session
    /// set member.
    pub principal_id_bytes: [u8; 16],
}

impl UploadSessionRecord {
    /// Build a new record from logical UUIDs + bytes-received
    /// counter.  Factor-helper for test clarity — callers avoid
    /// touching `repository_id_bytes` / `principal_id_bytes`
    /// directly.
    ///
    /// `version` is caller-supplied so tests can seed records at any
    /// point in their lifecycle.  Production callers use `new_initial`
    /// on initiate.
    pub(crate) fn new(
        repository_id: Uuid,
        bytes_received: u64,
        created_at_unix_millis: i64,
        version: u64,
        principal_id: Uuid,
    ) -> Self {
        Self {
            repository_id_bytes: *repository_id.as_bytes(),
            bytes_received,
            created_at_unix_millis,
            version,
            principal_id_bytes: *principal_id.as_bytes(),
        }
    }

    /// Construct the initial-state record for a freshly initiated
    /// session.  `version = 1` matches the `EphemeralStore` contract
    /// that `put_if_absent` yields version `1`.
    pub(crate) fn new_initial(
        repository_id: Uuid,
        created_at_unix_millis: i64,
        principal_id: Uuid,
    ) -> Self {
        Self::new(repository_id, 0, created_at_unix_millis, 1, principal_id)
    }

    /// Logical view of the repository id.
    pub(crate) fn repository_id(&self) -> Uuid {
        Uuid::from_bytes(self.repository_id_bytes)
    }

    /// Logical view of the principal id.
    pub(crate) fn principal_id(&self) -> Uuid {
        Uuid::from_bytes(self.principal_id_bytes)
    }
}

/// Serialise an `UploadSessionRecord` to `Bytes` for `EphemeralStore`.
///
/// `postcard::to_allocvec` is the codec; it writes a compact,
/// varint-prefixed representation driven by the type's
/// `serde::Serialize` impl. Returns `DomainError::Invariant` on encode
/// failure — postcard's allocating writer can only fail on OOM or a
/// serializer error (non-supported type), neither of which is a
/// validation concern.
pub(crate) fn encode_record(record: &UploadSessionRecord) -> Result<Bytes, DomainError> {
    let bytes = postcard::to_allocvec(record).map_err(|e| {
        DomainError::Invariant(format!("upload-session record postcard-encode failed: {e}"))
    })?;
    Ok(Bytes::from(bytes))
}

/// Deserialise an `UploadSessionRecord` from `EphemeralStore`-retrieved
/// `Bytes`.  Returns `DomainError::Invariant` on a malformed payload —
/// only possible if an adapter stored bytes that weren't produced by
/// [`encode_record`] (corruption or manual operator poke). Legacy
/// bincode-encoded records are unreachable from this function: the
/// `oci_v2` key-prefix keeps them in a disjoint key-space until they
/// expire via the 1-hour session TTL.
#[allow(dead_code)]
pub(crate) fn decode_record(bytes: &[u8]) -> Result<UploadSessionRecord, DomainError> {
    postcard::from_bytes(bytes).map_err(|e| {
        DomainError::Invariant(format!("upload-session record postcard-decode failed: {e}"))
    })
}

// ---------------------------------------------------------------------------
// initiate
// ---------------------------------------------------------------------------

/// Return envelope of [`initiate`].
///
/// `initial_version = 1` is returned explicitly for parity with the
/// `EphemeralStore::compare_and_swap` contract — the compare_and_swap callers feed this
/// back in as `expected_version` on the first PATCH / PUT.  Encoding
/// the "first version is 1" invariant at the type level would be
/// over-specified — the port trait documents the same guarantee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitiateOutcome {
    pub session_id: Uuid,
    pub initial_version: u64,
}

/// Outcome of [`initiate`]: either a freshly-created session or a
/// cap-rejection that the HTTP adapter must map to `429 Too Many
/// Requests`.
///
/// The cap rejection is a distinct variant (not folded into
/// [`AppError`] as `SessionCapExceeded`) because the cap is an
/// HTTP-level rate-limit policy, not a domain-level invariant
/// breach. Keeping the variant out of `AppError` avoids
/// re-classifying every existing error mapper in the OCI handler
/// stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitiateResult {
    /// Session created. Caller emits the 202 + `Location` /
    /// `Docker-Upload-UUID` / `Range: 0-0` envelope.
    Created(InitiateOutcome),
    /// Per-`(repo, principal)` cap exceeded. Caller emits 429 with
    /// the OCI `TOOMANYREQUESTS` envelope.
    CapExceeded,
    /// The cap reconcile CAS loop exhausted its retry budget under
    /// pathological write contention — a TRANSIENT condition, not a
    /// cap breach. Caller emits `503 Service Unavailable` + a short
    /// `Retry-After` (the same `OCI_CAP_RETRY_AFTER_SECS` the 429
    /// path uses) so the client retries soon. No session was created
    /// and no cap-rejection metric was emitted.
    Contended,
}

/// Initiate a three-phase OCI blob upload.
///
/// Generates a fresh random v4 `session_id`, writes an empty
/// `UploadSessionRecord` under `stateful_upload:oci_v2:<session_id>` via
/// [`EphemeralStore::put_if_absent`], emits the `created` count on
/// `hort_stateful_upload_sessions_total`, and returns the session id for
/// the handler to serve in the `Location` header.
///
/// `_actor` is accepted for API parity with the PATCH/PUT handlers
/// (which use it on causation/audit events); initiate does not persist
/// an event until finalize, so the actor stays unused here. The
/// signature is part of the public contract and the PUT/PATCH handlers
/// carry the actor through to `add_member` / `register_by_hash`.
///
/// On `put_if_absent` returning `Ok(false)` (key already present —
/// cosmically unlikely under random v4 UUIDs) we surface a
/// `DomainError::Invariant` rather than retrying with a fresh UUID.
/// A collision here means either a UUID-generation bug or a duplicate
/// call with the same id we don't control — silently retrying would
/// mask the underlying bug.
///
/// `#[tracing::instrument(skip(ctx))]` keeps the large `AppContext`
/// out of the span; `err` is deliberately not set because the caller
/// handles the error-to-HTTP mapping and the info-level span is the
/// right audit signal.
pub async fn initiate(
    ctx: &AppContext,
    repo_id: Uuid,
    actor: ApiActor,
    max_sessions_per_principal: u32,
    session_max_age: Duration,
) -> AppResult<InitiateResult> {
    initiate_inner(
        ctx,
        repo_id,
        actor,
        max_sessions_per_principal,
        session_max_age,
    )
    .instrument(tracing::info_span!(
        "oci_upload_session_initiate",
        repository_id = %repo_id,
    ))
    .await
}

/// Inner body of [`initiate`].  Separate function so the instrument
/// span can `skip` the whole `AppContext` via the outer wrapper —
/// `#[tracing::instrument]` as an attribute on `async fn` with `&Ctx`
/// arguments doesn't compose cleanly with the workspace's free-fn
/// convention.
async fn initiate_inner(
    ctx: &AppContext,
    repo_id: Uuid,
    actor: ApiActor,
    max_sessions_per_principal: u32,
    session_max_age: Duration,
) -> AppResult<InitiateResult> {
    let principal_id = actor.user_id;

    // Mint the session id first — the reconcile-admit atomically adds
    // it to the live set. Generating it up front lets the set carry the
    // real member id rather than a placeholder.
    let session_id = Uuid::new_v4();

    // Resolve the repository metric label ONCE. It is threaded into the
    // cap primitive's reconcile-prune metric AND reused below for this
    // adapter's own cap-rejection / `created` counters — a single
    // repository lookup per initiate instead of two. Matches
    // `IngestUseCase::repo_label` semantics: falls back to `_all` when
    // the lookup fails (operator-disabled label, repo deleted between
    // the authz extractor and this call, …).
    let repo_label = resolve_repo_label(ctx, repo_id).await;

    // Reconcile-and-admit against the generic live session-set cap
    // primitive ([`hort_http_core::upload_session_cap`]). The set is
    // authoritative for the cap: it age-prunes abandoned members on
    // every admit, and — critically — a cap rejection performs NO
    // write, so it never refreshes the set TTL. Those two properties
    // keep an abandoned-upload retry storm from pinning the cap: an
    // unfinalized, un-`DELETE`d session ages out of the set and a
    // rejection cannot extend its lifetime.
    match upload_session_cap::admit(
        ctx,
        OCI_CAP_FORMAT,
        repo_id,
        &repo_label,
        principal_id,
        session_id,
        max_sessions_per_principal,
        session_max_age,
    )
    .await?
    {
        AdmitOutcome::Admitted => {}
        AdmitOutcome::OverCap => {
            // Cap rejection — info-level (privilege denial), NOT error.
            // No `actor_id` / `user_id` in the metric labels — both are
            // forbidden cardinality vectors per the catalog. The
            // primitive returns the outcome; this adapter owns the 429
            // envelope and the `format="oci"`-labelled rejection metric.
            tracing::info!(
                target: "hort::oci::upload_session",
                repository_id = %repo_id,
                cap = max_sessions_per_principal,
                "OCI upload-session create rejected: per-(repo, principal) cap exceeded",
            );
            metrics::counter!(
                "hort_upload_session_cap_rejections_total",
                "format" => OCI_CAP_FORMAT,
                "repo" => repo_label.clone(),
                "result" => "over_cap",
            )
            .increment(1);
            return Ok(InitiateResult::CapExceeded);
        }
        AdmitOutcome::Contended => {
            // Pathological CAS contention exhausted the reconcile retry
            // budget — a TRANSIENT condition, not a cap breach. Surface
            // 503 + short Retry-After so the client retries soon; the
            // cap stays fail-closed (never fail-open). `warn!` (not
            // `error!`): the request did not succeed, but nothing is
            // broken and no infra error occurred. Deliberately NO
            // cap-rejection metric — this is a status, not a rejection,
            // and the `over_cap` counter must stay a clean cap-pressure
            // signal.
            tracing::warn!(
                target: "hort::oci::upload_session",
                repository_id = %repo_id,
                "OCI upload-session create deferred: cap reconcile contended (transient)",
            );
            return Ok(InitiateResult::Contended);
        }
    }

    let record =
        UploadSessionRecord::new_initial(repo_id, Utc::now().timestamp_millis(), principal_id);
    let bytes = encode_record(&record).map_err(AppError::from)?;
    let key = session_key("oci", session_id);

    let created = ctx
        .ephemeral_durable
        .put_if_absent(&key, bytes, session_max_age)
        .await
        .map_err(AppError::from)?;
    if !created {
        tracing::error!(
            session_id = %session_id,
            "duplicate upload-session ID — UUID collision or repeated put_if_absent"
        );
        // Roll back the cap-set admit we just took — leaving the member
        // would burn a slot without producing a real session.
        upload_session_cap::release(
            ctx,
            OCI_CAP_FORMAT,
            repo_id,
            principal_id,
            session_id,
            session_max_age,
        )
        .await;
        return Err(AppError::from(DomainError::Invariant(
            "upload-session key already present".into(),
        )));
    }

    metrics::counter!(
        "hort_stateful_upload_sessions_total",
        "format" => "oci",
        "repository" => repo_label,
        "result" => "created",
    )
    .increment(1);

    Ok(InitiateResult::Created(InitiateOutcome {
        session_id,
        initial_version: 1,
    }))
}

/// Resolve the `repository` label value for metric emission.
///
/// Delegates to
/// [`RepositoryAccessUseCase::metric_label`](hort_app::use_cases::repository_access::RepositoryAccessUseCase::metric_label)
/// so the cardinality-sentinel rule lives in one place. The use case
/// applies the `include_repository_label` toggle and falls back to a
/// sentinel on a lookup miss (`unknown` when the toggle is on, `_all`
/// when off).
async fn resolve_repo_label(ctx: &AppContext, repo_id: Uuid) -> String {
    ctx.repository_access_use_case.metric_label(repo_id).await
}

// ---------------------------------------------------------------------------
// append_chunk (PATCH)
// ---------------------------------------------------------------------------

/// Inclusive `(start, end)` byte range parsed from a `Content-Range`
/// header (`bytes <start>-<end>`). Wrapper type so the three-tuple of
/// `(start, end, body_length)` on [`append_chunk`] doesn't silently
/// swap positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentRange {
    pub start: u64,
    pub end: u64,
}

/// An optional trailing body folded into a finalize `PUT` (or a `PATCH`
/// chunk): the byte stream, an optional `Content-Range`, and an optional
/// declared length — `None` = `Transfer-Encoding: chunked` (RFC 7230 §3.3.2),
/// streamed and bounded in-stream by the publish-body cap.
pub(crate) type TrailingBody = (
    Box<dyn AsyncRead + Send + Unpin>,
    Option<ContentRange>,
    Option<u64>,
);

impl ContentRange {
    /// Span width — `end - start + 1` because the range is inclusive
    /// on both ends per the OCI spec.
    pub fn span(&self) -> u64 {
        // `end < start` is rejected by the parser before this type is
        // constructed.  A saturating_sub here would mask an arithmetic
        // bug elsewhere; trust the invariant and use plain subtraction.
        self.end - self.start + 1
    }
}

/// Append a chunk of bytes to an in-flight OCI blob upload session.
///
/// Composes three outbound ports under one optimistic-concurrency CAS
/// window:
///
/// 1. `ctx.ephemeral_durable.get(session_key("oci", session_id))` — loads the
///    [`UploadSessionRecord`]; missing / decode-failed / tenant-mismatch
///    each surface as [`DomainError::NotFound`] so the HTTP adapter can
///    emit the spec's anti-enumeration `BLOB_UPLOAD_UNKNOWN`.
/// 2. Validates the `Content-Range` against the session's progress and
///    the caller-supplied `max_bytes` cap.  Each kind of mismatch
///    surfaces as a distinct [`AppError`] variant so the adapter can
///    emit the right status code (416 / 400 / 413).
/// 3. `ctx.stateful_upload_staging.append(session_id, stream)` — appends
///    the body bytes to staging.  Non-retryable; a failure on this step
///    leaves the session's `bytes_received` unchanged (we haven't CASed
///    yet).
/// 4. `ctx.ephemeral_durable.compare_and_swap(key, record.version, new_record,
///    TTL)` — atomic bump + TTL slide.  A CAS miss means a concurrent
///    PATCH won; we surface [`DomainError::Conflict`] so the adapter
///    emits `400 BLOB_UPLOAD_INVALID`.
///
/// # Tenant isolation
///
/// The `repo_id` argument is the write-authorised repository resolved
/// from the request's `:repo_key` path param.  The session's stored
/// `repository_id` MUST match.  Mismatch maps to
/// [`DomainError::NotFound`] (not `Forbidden`) — anti-enumeration:
/// the session UUID must not reveal whether it belongs to another repo.
///
/// # Hash deferral
///
/// This function DOES NOT compute the SHA-256 of the chunk.  Hashing
/// happens once on finalize via `StoragePort::put`, which is
/// the workspace-wide CAS invariant.  Attempting to hash chunks here
/// would re-implement the incremental-hash pattern in a worse spot
/// (the adapter can't participate in a multi-chunk digest without a
/// hasher-per-session state), and the wire protocol does not carry a
/// chunk-level digest.
///
/// # Metric emission
///
/// Every error path (RangeInvalid, BodyLengthMismatch, SizeExceeded,
/// tenant-mismatch NotFound, CAS-miss Conflict, decode-failure
/// Invariant, staging-failure Invariant, ephemeral-failure Invariant)
/// emits `hort_stateful_upload_sessions_total{format="oci",
/// repository=<label>, result="aborted"}` exactly once.  Success does
/// NOT emit — the catalog reserves `created`/`aborted`/`finalized` and
/// a per-chunk `progressed` variant would inflate cardinality without
/// useful operator signal.
#[tracing::instrument(skip(ctx, stream), fields(repository_id = %repo_id))]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn append_chunk(
    ctx: &AppContext,
    session_id: Uuid,
    content_range: Option<ContentRange>,
    stream: Box<dyn AsyncRead + Send + Unpin>,
    body_length: u64,
    max_bytes: u64,
    repo_id: Uuid,
    session_max_age: Duration,
) -> AppResult<UploadSessionRecord> {
    let key = session_key("oci", session_id);
    let result = append_chunk_core(
        ctx,
        session_id,
        &key,
        content_range,
        stream,
        Some(body_length),
        max_bytes,
        repo_id,
        session_max_age,
    )
    .await;
    emit_abort_on_err(ctx, repo_id, &result).await;
    result
}

/// Streaming variant for a PATCH that carries **no** `Content-Length`
/// (`Transfer-Encoding: chunked` — RFC 7230 §3.3.2 forbids sending both a
/// `Content-Length` and a `Transfer-Encoding`). The body is bounded
/// in-stream by `max_bytes` inside [`append_chunk_core`]; the actual bytes
/// landed are authoritative (no declared length to cross-check).
#[tracing::instrument(skip(ctx, stream), fields(repository_id = %repo_id))]
pub(crate) async fn append_chunk_streaming(
    ctx: &AppContext,
    session_id: Uuid,
    content_range: Option<ContentRange>,
    stream: Box<dyn AsyncRead + Send + Unpin>,
    max_bytes: u64,
    repo_id: Uuid,
    session_max_age: Duration,
) -> AppResult<UploadSessionRecord> {
    let key = session_key("oci", session_id);
    let result = append_chunk_core(
        ctx,
        session_id,
        &key,
        content_range,
        stream,
        None,
        max_bytes,
        repo_id,
        session_max_age,
    )
    .await;
    emit_abort_on_err(ctx, repo_id, &result).await;
    result
}

/// On any unrecoverable `append_chunk*` error, emit `aborted` exactly
/// once. Kept out of the core so every error-producing `?` funnels through
/// the same metric site. Success is deliberately silent.
async fn emit_abort_on_err(
    ctx: &AppContext,
    repo_id: Uuid,
    result: &AppResult<UploadSessionRecord>,
) {
    if result.is_err() {
        let repo_label = resolve_repo_label(ctx, repo_id).await;
        metrics::counter!(
            "hort_stateful_upload_sessions_total",
            "format" => "oci",
            "repository" => repo_label,
            "result" => "aborted",
        )
        .increment(1);
    }
}

#[allow(clippy::too_many_arguments)]
async fn append_chunk_core(
    ctx: &AppContext,
    session_id: Uuid,
    key: &str,
    content_range: Option<ContentRange>,
    stream: Box<dyn AsyncRead + Send + Unpin>,
    body_length: Option<u64>,
    max_bytes: u64,
    repo_id: Uuid,
    session_max_age: Duration,
) -> AppResult<UploadSessionRecord> {
    // --- Cheap pre-I/O check when the client supplied an explicit range.
    // A width-vs-body-length mismatch fails loud here before we touch
    // outbound ports; staging never grows from a body that disagreed
    // with the header, so no partial-append repair path is needed.
    // When the range is absent (containers/image, skopeo, podman send
    // chunks without `Content-Range`) we synthesise it after loading
    // the session record below.
    if let (Some(range), Some(len)) = (content_range.as_ref(), body_length) {
        if range.span() != len {
            return Err(AppError::BodyLengthMismatch);
        }
    }

    // --- Load + decode the session.
    let stored = ctx
        .ephemeral_durable
        .get(key)
        .await
        .map_err(AppError::from)?
        .ok_or(AppError::Domain(DomainError::NotFound {
            entity: "OciUploadSession",
            id: session_id.to_string(),
        }))?;
    let record = decode_record(&stored).map_err(AppError::from)?;

    // --- Tenant isolation — anti-enumeration: surface as NotFound
    // (same envelope the "session doesn't exist" branch produced).
    if record.repository_id() != repo_id {
        tracing::info!(
            session_id = %session_id,
            requested_repo = %repo_id,
            session_repo = %record.repository_id(),
            "OCI upload PATCH rejected: session belongs to a different repository"
        );
        return Err(AppError::Domain(DomainError::NotFound {
            entity: "OciUploadSession",
            id: session_id.to_string(),
        }));
    }

    // --- Validate the client-supplied range's START against session
    // state (an append must land at the current offset). The range END is
    // only meaningful with a declared length; when the length is absent
    // (streaming) the actual bytes landed define it. An absent range is
    // "append at current offset" — the unique meaningful interpretation,
    // matching GHCR / Harbor / zot and the Docker Registry V2 reference.
    if let Some(ref range) = content_range {
        if range.start != record.bytes_received {
            return Err(AppError::RangeInvalid {
                current: record.bytes_received,
            });
        }
    }

    let new_total = match body_length {
        // Declared-length path (Content-Length present; the transport
        // frames the body to exactly `len` bytes). Pre-flight the size cap,
        // then cross-check staging landed exactly the declared count.
        Some(len) => {
            // `checked_add` guards a pathological overflow before the
            // comparison; a silent wrap would emit the wrong error code.
            let projected = record
                .bytes_received
                .checked_add(len)
                .ok_or(AppError::SizeExceeded)?;
            if projected > max_bytes {
                return Err(AppError::SizeExceeded);
            }
            let new_total = ctx
                .stateful_upload_staging
                .append(session_id, stream)
                .await
                .map_err(AppError::from)?;
            // Staging-port invariant: a disagreement means the body
            // short-read (client hung up / lied about Content-Length) or an
            // adapter bug. Either way the session is inconsistent with the
            // declared length — `Invariant` → 500. A naive `Conflict` would
            // invite endless retries of the same corrupt PATCH.
            if new_total != record.bytes_received + len {
                tracing::warn!(
                    session_id = %session_id,
                    expected = record.bytes_received + len,
                    actual = new_total,
                    "staging append byte count disagreed with declared body length"
                );
                return Err(AppError::Domain(DomainError::Invariant(
                    "staging append byte count disagreed with declared body length".into(),
                )));
            }
            new_total
        }
        // Streaming path (no Content-Length — `Transfer-Encoding: chunked`).
        // The transport does not bound the body, so bound the read at the
        // cap: `take(headroom)` (headroom = remaining cap + 1) truncates, so
        // staging never grows past `max_bytes + 1`, and a body that reaches
        // the +1 trips the post-append cap check. Actual bytes landed are
        // authoritative — there is no declared length to cross-check.
        None => {
            let headroom = max_bytes
                .saturating_sub(record.bytes_received)
                .saturating_add(1);
            let bounded: Box<dyn AsyncRead + Send + Unpin> = Box::new(stream.take(headroom));
            let new_total = ctx
                .stateful_upload_staging
                .append(session_id, bounded)
                .await
                .map_err(AppError::from)?;
            if new_total > max_bytes {
                return Err(AppError::SizeExceeded);
            }
            new_total
        }
    };

    // --- CAS bump.  `new_record.version = record.version + 1` keeps
    // the in-record mirror in lock-step with the store's own counter
    // after a successful `compare_and_swap`.
    let new_record = UploadSessionRecord {
        bytes_received: new_total,
        version: record.version + 1,
        ..record
    };
    let new_bytes = encode_record(&new_record).map_err(AppError::from)?;
    let cas_outcome = ctx
        .ephemeral_durable
        .compare_and_swap(key, record.version, new_bytes, session_max_age)
        .await
        .map_err(AppError::from)?;
    match cas_outcome {
        Some(_new_store_version) => Ok(new_record),
        None => {
            // Concurrent PATCH bumped the version underneath us. The
            // spec-compliant response is 400 `BLOB_UPLOAD_INVALID`.
            // Surface as Conflict; the HTTP adapter translates.
            tracing::info!(
                session_id = %session_id,
                expected_version = record.version,
                "OCI upload PATCH CAS miss: concurrent PATCH won"
            );
            Err(AppError::Domain(DomainError::Conflict(
                "upload session version stale".into(),
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// finalize (PUT)
// ---------------------------------------------------------------------------

/// Finalize an in-flight OCI blob upload session.
///
/// Composes the optional trailing PATCH + the generic
/// [`IngestUseCase::ingest`] + session / staging cleanup into a single
/// free function so the HTTP handler in [`super::uploads`] stays a thin
/// extractor-to-response wrapper.
///
/// # Ordering and crash recovery
///
/// Cleanup strictly follows:
///
/// 1. `ctx.ingest_use_case.ingest(...)` — the **commit boundary**. The
///    CAS blob + `ArtifactIngested` event either both exist or neither
///    does from the client's perspective. `IngestUseCase::ingest`
///    guarantees that on a declared-hash mismatch the freshly-written
///    CAS blob is rolled back before returning `Err(Conflict)`, so no
///    orphan survives this step.
/// 2. `ctx.ephemeral_durable.delete(session_key)` — drop the in-flight session
///    row from the ephemeral store so subsequent PATCH/PUT on the same
///    UUID hit the `BLOB_UPLOAD_UNKNOWN` path.
/// 3. `ctx.stateful_upload_staging.delete(session_id)` — drop the
///    staging file.
///
/// Crash windows:
///
/// - **Before step 1 completes:** the CAS blob + event commit are
///   atomic at the use-case boundary (either both land or neither),
///   and the client sees an error. The session + staging are still
///   live; the next PATCH/PUT from the client either succeeds (new
///   content, same session) or the GC sweep reaps on TTL expiry.
/// - **Between steps 1 and 2:** the ingest event + CAS blob are
///   committed but the session key lingers. The session TTL expires
///   on its own; the GC sweep is belt-and-braces. A client retry on
///   the same session UUID finds stale state but the artifact is
///   already durable so the retry is a no-op at the registry level.
/// - **Between steps 2 and 3:** the session is gone but the staging
///   file orphans. The GC sweep reaps staging by mtime age.
/// - **Digest-mismatch path:** the CAS blob rollback is performed
///   *inside* `IngestUseCase::ingest`. This function's only
///   responsibility is to additionally drop the session + staging so
///   a retried PUT with a correct digest starts fresh.
///
/// Cleanup failures on steps 2–3 log `warn!` and fall through —
/// returning a 500 after a successful ingest would lie about the
/// artifact's state. GC reaps the orphan.
///
/// # Metrics
///
/// - Success: `hort_stateful_upload_sessions_total{result="finalized"}`
///   counter +1, `hort_stateful_upload_session_bytes` histogram observes
///   the session's final byte count, `hort_stateful_upload_finalize_duration_seconds`
///   histogram observes wall-clock from entry to return.
/// - Digest mismatch: `hort_stateful_upload_sessions_total{result="aborted"}`
///   counter +1, still records the duration histogram (observers care
///   about the time spent on failing finalizes too — slow digest
///   mismatches indicate a flaky client pipeline).
/// - `IngestUseCase::ingest` emits its own `hort_ingest_total{format="oci"}`
///   terminal counter. We do NOT double-emit.
#[tracing::instrument(skip(ctx, trailing_body), fields(repository_id = %repo_id))]
#[allow(clippy::too_many_arguments)]
pub async fn finalize(
    ctx: &AppContext,
    session_id: Uuid,
    declared_digest: ContentHash,
    trailing_body: Option<TrailingBody>,
    actor: ApiActor,
    repo_id: Uuid,
    name: &str,
    max_bytes: u64,
    session_max_age: Duration,
) -> AppResult<IngestOutcome> {
    let started = Instant::now();
    let result = finalize_core(
        ctx,
        session_id,
        declared_digest,
        trailing_body,
        actor,
        repo_id,
        name,
        max_bytes,
        session_max_age,
    )
    .await;

    // Emit terminal metrics on every exit path. Success → `finalized`
    // counter + bytes histogram. Conflict (digest mismatch) → `aborted`.
    // Other errors are infra-level and do NOT tick the session counter
    // — the `hort_ingest_total` emission inside `IngestUseCase::ingest`
    // is the authoritative signal for those. The duration histogram
    // covers every exit path so operators can dashboard both success
    // and failure latencies.
    let repo_label = resolve_repo_label(ctx, repo_id).await;
    let elapsed = started.elapsed().as_secs_f64();
    match &result {
        Ok(outcome) => {
            metrics::counter!(
                "hort_stateful_upload_sessions_total",
                "format" => "oci",
                "repository" => repo_label.clone(),
                "result" => "finalized",
            )
            .increment(1);
            metrics::histogram!(
                "hort_stateful_upload_session_bytes",
                "format" => "oci",
                "repository" => repo_label.clone(),
            )
            .record(outcome.artifact.size_bytes as f64);
        }
        Err(AppError::Domain(DomainError::Conflict(_))) => {
            metrics::counter!(
                "hort_stateful_upload_sessions_total",
                "format" => "oci",
                "repository" => repo_label.clone(),
                "result" => "aborted",
            )
            .increment(1);
        }
        Err(_) => {
            // Infra / transient error — no session-level terminal
            // counter emission. `hort_ingest_total` inside the use case
            // already labels these, and surfacing a duplicate
            // `aborted` here would double-count every retryable
            // EphemeralStore hiccup.
        }
    }
    metrics::histogram!(
        "hort_stateful_upload_finalize_duration_seconds",
        "format" => "oci",
        "repository" => repo_label,
    )
    .record(elapsed);

    result
}

#[allow(clippy::too_many_arguments)]
async fn finalize_core(
    ctx: &AppContext,
    session_id: Uuid,
    declared_digest: ContentHash,
    trailing_body: Option<TrailingBody>,
    actor: ApiActor,
    repo_id: Uuid,
    name: &str,
    max_bytes: u64,
    session_max_age: Duration,
) -> AppResult<IngestOutcome> {
    let key = session_key("oci", session_id);

    // --- Tenant isolation (early). Same envelope shape as PATCH: load
    // the session, decode, match repo; mismatch → anti-enumeration
    // `NotFound { OciUploadSession }` which the handler maps to 404
    // `BLOB_UPLOAD_UNKNOWN`. Surfacing the check here — before any
    // optional trailing-body append — keeps the PUT isolation story
    // identical to PATCH without relying on `append_chunk` to do it
    // as a side effect (the body may be absent, in which case we'd
    // never have reached that check).
    let initial = ctx
        .ephemeral_durable
        .get(&key)
        .await
        .map_err(AppError::from)?
        .ok_or(AppError::Domain(DomainError::NotFound {
            entity: "OciUploadSession",
            id: session_id.to_string(),
        }))?;
    let initial_record = decode_record(&initial).map_err(AppError::from)?;
    if initial_record.repository_id() != repo_id {
        tracing::info!(
            session_id = %session_id,
            requested_repo = %repo_id,
            session_repo = %initial_record.repository_id(),
            "OCI upload PUT rejected: session belongs to a different repository"
        );
        return Err(AppError::Domain(DomainError::NotFound {
            entity: "OciUploadSession",
            id: session_id.to_string(),
        }));
    }
    // Capture the principal that owns this session so the cleanup
    // paths below can release the right per-`(repo, principal)`
    // live-session set member.
    let session_principal_id = initial_record.principal_id();

    // --- Optional trailing body. `append_chunk` re-verifies the
    // session + tenant + version on its own CAS path and synthesises
    // an absent `Content-Range` from the loaded record — both PATCH
    // and the two-phase finalize PUT share that policy. We accept the
    // duplicate lookup for a single extra EphemeralStore `get` (the
    // PATCH path is the dominant one — the zero-body PUT is the cheap
    // corner case). Propagating the error unchanged lets the handler
    // emit the same 400/413/416 envelope it emits for a raw PATCH.
    if let Some((stream, content_range, body_length)) = trailing_body {
        // Mirror the PATCH path: a declared length takes the cross-checked
        // `append_chunk`; an absent length (a `Transfer-Encoding: chunked` PUT
        // body — RFC 7230 §3.3.2 forbids Content-Length alongside chunked TE)
        // streams via `append_chunk_streaming`, bounded in-stream by the cap.
        match body_length {
            Some(len) => {
                append_chunk(
                    ctx,
                    session_id,
                    content_range,
                    stream,
                    len,
                    max_bytes,
                    repo_id,
                    session_max_age,
                )
                .await?;
            }
            None => {
                append_chunk_streaming(
                    ctx,
                    session_id,
                    content_range,
                    stream,
                    max_bytes,
                    repo_id,
                    session_max_age,
                )
                .await?;
            }
        }
    }

    // --- Open staging. If the session exists but staging does not,
    // that's an invariant breach: `append_chunk` + `initiate` always
    // leave these two halves consistent. The GC sweep is the only
    // legitimate mechanism that could race a finalize and
    // remove staging underneath it — we surface `Invariant` so the
    // handler returns 500 and the operator sees the loud log. The
    // error mapping intentionally turns a `NotFound { entity:
    // "stateful_upload_staging" }` into an `Invariant` rather than
    // re-using the `BLOB_UPLOAD_UNKNOWN` envelope — the session is
    // present (we just decoded it) so the client's upload is not
    // "unknown"; something server-side is wrong.
    let staging_reader = match ctx.stateful_upload_staging.stream_read(session_id).await {
        Ok(r) => r,
        Err(DomainError::NotFound { .. }) => {
            tracing::warn!(
                session_id = %session_id,
                "OCI upload PUT: session row present but staging missing — \
                 GC race or adapter inconsistency"
            );
            return Err(AppError::Domain(DomainError::Invariant(
                "upload session present but staging bytes missing".into(),
            )));
        }
        Err(e) => return Err(AppError::from(e)),
    };

    // --- Compose VerifiedIngestRequest. Chunked upload finalize is
    // OCI-direct; the digest comes from the finalize URL/session.
    // ProtocolNative carries it; `ingest_verified` compares the
    // streamed content's computed hash (ADR 0006), rolls back the CAS
    // blob on mismatch, and returns Conflict — mapped to 400
    // DIGEST_INVALID by the PUT handler.
    let req = VerifiedIngestRequest::ProtocolNative {
        repository_id: repo_id,
        coords: oci_blob_coords(name, &declared_digest),
        content_type: "application/octet-stream".into(),
        actor,
        payload_metadata: serde_json::Value::Null,
        upstream_digest: declared_digest.clone(),
        upstream_published_at: None,
        // Chunked upload finalize is OCI-direct: no serving
        // `RepositoryUpstreamMapping`, opt-in cannot apply.
        trust_upstream_publish_time: false,
    };

    let ingest_result = ctx
        .ingest_use_case
        .ingest_verified(req, staging_reader, &OciFormatHandler)
        .await;

    // --- Branch on the ingest outcome. Cleanup is best-effort in
    // both branches: session-delete + staging-delete failures log
    // `warn!` and return the original result unchanged.
    match ingest_result {
        Ok(outcome) => {
            cleanup_session_and_staging(
                ctx,
                &key,
                session_id,
                repo_id,
                session_principal_id,
                session_max_age,
            )
            .await;
            Ok(outcome)
        }
        Err(AppError::Domain(DomainError::Conflict(msg))) => {
            // Digest mismatch — the CAS blob has already been rolled
            // back by `IngestUseCase::ingest`. Drop session + staging
            // so a retried PUT with a matching digest starts fresh,
            // then propagate `Conflict` for the handler to map to
            // 400 `DIGEST_INVALID`.
            cleanup_session_and_staging(
                ctx,
                &key,
                session_id,
                repo_id,
                session_principal_id,
                session_max_age,
            )
            .await;
            Err(AppError::Domain(DomainError::Conflict(msg)))
        }
        Err(other) => {
            // Any other error (repo gone, storage I/O, event-store
            // append failure, …). Best-effort cleanup — the session
            // is almost certainly garbage at this point; leaving it
            // live would block a retry on the same `digest` query
            // parameter with a BLOB_UPLOAD_INVALID on the next CAS
            // version bump. If cleanup itself fails, the original
            // error is what the operator needs to see.
            cleanup_session_and_staging(
                ctx,
                &key,
                session_id,
                repo_id,
                session_principal_id,
                session_max_age,
            )
            .await;
            Err(other)
        }
    }
}

/// Best-effort cleanup of the session row + staging file in the order
/// mandated by the finalize ordering rules above: ephemeral store
/// first (clients observing a stale session see `BLOB_UPLOAD_UNKNOWN`
/// immediately), staging second.
///
/// The cleanup is also where the per-`(repo, principal)` live-session
/// set member is released. The release is best-effort: an
/// infrastructure failure logs `warn!` and the set self-heals via the
/// next admit's age-prune / TTL. Four release paths funnel through here
/// (finalize success, declared-hash Conflict, other infra errors, and
/// the DELETE-cancel route); each corresponds to exactly one prior
/// admit in `initiate`. A double-release (the member already absent) is
/// a no-op, so the set stays balanced across the realistic hot paths.
///
/// Each leg logs `warn!` on failure and continues so the caller can
/// still surface the ingest result (success or Conflict) to the
/// client. The GC sweep picks up anything left behind.
async fn cleanup_session_and_staging(
    ctx: &AppContext,
    key: &str,
    session_id: Uuid,
    repo_id: Uuid,
    principal_id: Uuid,
    session_max_age: Duration,
) {
    if let Err(e) = ctx.ephemeral_durable.delete(key).await {
        tracing::warn!(
            session_id = %session_id,
            err = ?e,
            "OCI finalize: EphemeralStore delete failed; session will TTL out"
        );
    }
    if let Err(e) = ctx.stateful_upload_staging.delete(session_id).await {
        tracing::warn!(
            session_id = %session_id,
            err = ?e,
            "OCI finalize: staging delete failed; GC sweep will reap orphan"
        );
    }
    // Release the per-`(repo, principal)` cap slot via the generic
    // primitive.
    upload_session_cap::release(
        ctx,
        OCI_CAP_FORMAT,
        repo_id,
        principal_id,
        session_id,
        session_max_age,
    )
    .await;
}

/// Cancel an in-flight OCI blob upload session (DELETE-cancel route).
///
/// Loads + tenant-checks the session, then runs the shared
/// [`cleanup_session_and_staging`] — dropping the session row, the
/// staging bytes, AND releasing the live-session set member. Gives a
/// well-behaved client an immediate slot release rather than waiting
/// for the session to age out.
///
/// Tenant isolation mirrors PATCH / PUT: a session bound to a different
/// repository surfaces as anti-enumeration `NotFound { OciUploadSession }`
/// (→ 404 `BLOB_UPLOAD_UNKNOWN`), never leaking that a session for that
/// UUID exists elsewhere. A missing / TTL-expired session is likewise
/// `NotFound`. `#[tracing::instrument]` without `err` — the handler
/// owns the error-to-HTTP mapping.
#[tracing::instrument(skip(ctx), fields(repository_id = %repo_id))]
pub async fn cancel(
    ctx: &AppContext,
    session_id: Uuid,
    repo_id: Uuid,
    session_max_age: Duration,
) -> AppResult<()> {
    let key = session_key("oci", session_id);
    let stored = ctx
        .ephemeral_durable
        .get(&key)
        .await
        .map_err(AppError::from)?
        .ok_or(AppError::Domain(DomainError::NotFound {
            entity: "OciUploadSession",
            id: session_id.to_string(),
        }))?;
    let record = decode_record(&stored).map_err(AppError::from)?;
    if record.repository_id() != repo_id {
        tracing::info!(
            session_id = %session_id,
            requested_repo = %repo_id,
            session_repo = %record.repository_id(),
            "OCI upload DELETE rejected: session belongs to a different repository"
        );
        return Err(AppError::Domain(DomainError::NotFound {
            entity: "OciUploadSession",
            id: session_id.to_string(),
        }));
    }
    cleanup_session_and_staging(
        ctx,
        &key,
        session_id,
        repo_id,
        record.principal_id(),
        session_max_age,
    )
    .await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use hort_app::use_cases::test_support::sample_repository;
    use hort_domain::error::DomainResult;
    use hort_domain::ports::ephemeral_store::EphemeralStore;
    use hort_domain::ports::BoxFuture;
    use hort_http_core::test_support::build_mock_ctx;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshot};
    use metrics_util::{CompositeKey, MetricKind};

    // -------------------- Harness --------------------

    /// Default session max-age used across the tests that don't
    /// exercise age-pruning. One hour matches the production default;
    /// the age-prune tests pass a short value explicitly.
    const TEST_MAX_AGE: Duration = Duration::from_secs(OCI_SESSION_MAX_AGE_SECS);

    /// Legacy test alias for the seeding-write TTL. The old code used a
    /// single hardcoded `OCI_SESSION_TTL`; seeding writes in the tests
    /// only need *some* live TTL, so the max-age default stands in.
    const OCI_SESSION_TTL: Duration = TEST_MAX_AGE;

    fn api_actor() -> ApiActor {
        ApiActor {
            user_id: Uuid::new_v4(),
        }
    }

    fn run<F, T>(f: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    type MetricEntry = (
        CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    );

    fn capture<T, F>(f: F) -> (Snapshot, T)
    where
        F: FnOnce() -> T,
    {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let out = metrics::with_local_recorder(&recorder, f);
        (snapshotter.snapshot(), out)
    }

    fn find_counter<'a>(
        entries: &'a [MetricEntry],
        name: &str,
        expected: &[(&str, &str)],
    ) -> Option<&'a DebugValue> {
        entries.iter().find_map(|(ck, _, _, dv)| {
            if ck.kind() != MetricKind::Counter || ck.key().name() != name {
                return None;
            }
            let ok = expected
                .iter()
                .all(|(k, v)| ck.key().labels().any(|l| l.key() == *k && l.value() == *v));
            ok.then_some(dv)
        })
    }

    // -------------------- Failing EphemeralStore stub --------------------

    /// Minimal `EphemeralStore` that fails every call with
    /// `DomainError::Invariant("boom")`.  Only the ports `initiate`
    /// actually touches need realistic behaviour — the rest default to
    /// the same error so accidental extra calls fail loud.  Tracks
    /// `put_if_absent` invocations so the test can prove the failure
    /// surfaced on the intended port (and not, e.g., on `get`).
    struct FailingEphemeral {
        put_if_absent_calls: AtomicUsize,
    }
    impl FailingEphemeral {
        fn new() -> Self {
            Self {
                put_if_absent_calls: AtomicUsize::new(0),
            }
        }
    }
    impl EphemeralStore for FailingEphemeral {
        fn get(&self, _key: &str) -> BoxFuture<'_, DomainResult<Option<Bytes>>> {
            Box::pin(async { Err(DomainError::Invariant("boom".into())) })
        }
        fn put(
            &self,
            _key: &str,
            _value: Bytes,
            _ttl: Duration,
        ) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Err(DomainError::Invariant("boom".into())) })
        }
        fn put_if_absent(
            &self,
            _key: &str,
            _value: Bytes,
            _ttl: Duration,
        ) -> BoxFuture<'_, DomainResult<bool>> {
            self.put_if_absent_calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Err(DomainError::Invariant("boom".into())) })
        }
        fn compare_and_swap(
            &self,
            _key: &str,
            _expected_version: u64,
            _new_value: Bytes,
            _ttl: Duration,
        ) -> BoxFuture<'_, DomainResult<Option<u64>>> {
            Box::pin(async { Err(DomainError::Invariant("boom".into())) })
        }
        fn delete(&self, _key: &str) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Err(DomainError::Invariant("boom".into())) })
        }
        fn extend_ttl(&self, _key: &str, _ttl: Duration) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Err(DomainError::Invariant("boom".into())) })
        }
    }

    /// Collision-forcing stub for the SESSION-RECORD `put_if_absent`
    /// branch in `initiate_inner`. The cap-set admit runs first, so the
    /// stub is key-aware: the `upload_sessions:` cap-set key's
    /// `put_if_absent` succeeds (`Ok(true)`) on the first iteration so
    /// the admit is granted, and the `stateful_upload:` session-record
    /// key's `put_if_absent` always collides (`Ok(false)`) — exercising
    /// the "duplicate session key" branch without a real UUID collision
    /// and without the admit loop mistaking the record collision for
    /// cap contention.
    struct AlwaysCollidingEphemeral;
    impl EphemeralStore for AlwaysCollidingEphemeral {
        fn get(&self, _key: &str) -> BoxFuture<'_, DomainResult<Option<Bytes>>> {
            Box::pin(async { Ok(None) })
        }
        fn put(
            &self,
            _key: &str,
            _value: Bytes,
            _ttl: Duration,
        ) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn put_if_absent(
            &self,
            key: &str,
            _value: Bytes,
            _ttl: Duration,
        ) -> BoxFuture<'_, DomainResult<bool>> {
            // Cap-set key is granted so the admit succeeds first-try;
            // the session-record key collides so `initiate_inner` hits
            // its duplicate-key Invariant branch.
            let granted = key.starts_with("upload_sessions:");
            Box::pin(async move { Ok(granted) })
        }
        fn compare_and_swap(
            &self,
            _key: &str,
            _expected_version: u64,
            _new_value: Bytes,
            _ttl: Duration,
        ) -> BoxFuture<'_, DomainResult<Option<u64>>> {
            Box::pin(async { Ok(None) })
        }
        fn delete(&self, _key: &str) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn extend_ttl(&self, _key: &str, _ttl: Duration) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    /// Contention-forcing stub for the cap-admit reconcile loop. `get`
    /// always presents an empty set (`None`) and `put_if_absent` on the
    /// cap-set key always loses the create race (`Ok(false)`), so the
    /// admit re-reads → re-puts → loses forever until the bounded retry
    /// budget exhausts → [`AdmitOutcome::Contended`] →
    /// [`InitiateResult::Contended`]. Distinct from
    /// `AlwaysCollidingEphemeral` (which GRANTS the cap-set key): this
    /// stub never lets the admit succeed.
    struct AlwaysContendedEphemeral;
    impl EphemeralStore for AlwaysContendedEphemeral {
        fn get(&self, _key: &str) -> BoxFuture<'_, DomainResult<Option<Bytes>>> {
            Box::pin(async { Ok(None) })
        }
        fn put(&self, _k: &str, _v: Bytes, _t: Duration) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn put_if_absent(
            &self,
            _k: &str,
            _v: Bytes,
            _t: Duration,
        ) -> BoxFuture<'_, DomainResult<bool>> {
            // Perpetual create-race loss — never admitted.
            Box::pin(async { Ok(false) })
        }
        fn compare_and_swap(
            &self,
            _k: &str,
            _e: u64,
            _v: Bytes,
            _t: Duration,
        ) -> BoxFuture<'_, DomainResult<Option<u64>>> {
            Box::pin(async { Ok(None) })
        }
        fn delete(&self, _k: &str) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn extend_ttl(&self, _k: &str, _t: Duration) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    /// Build an `AppContext` whose `ephemeral_durable` field is
    /// swapped for `replacement`. Local to this test module — the
    /// stable `hort-http-core::test_support` helpers don't (yet) expose
    /// a `with_ephemeral` because no production caller needs it.
    ///
    /// OCI upload-session machinery reads from `ephemeral_durable`
    /// (the `stateful_upload:` and `upload_sessions:` keyspaces are
    /// registered as Durable; see the `ephemeral_keyspace_exhaustive`
    /// guard). The test stub is wired into the durable slot only; the
    /// evictable slot retains the default in-memory mock from
    /// `build_mock_ctx`, which is unused on OCI's hot path.
    ///
    /// `build_mock_ctx` hands back an `Arc<AppContext>` with
    /// `strong_count == 1` (the `MockPorts` siblings are Arc clones of
    /// the port adapters, not of the context itself) so
    /// `Arc::try_unwrap` is infallible here.  A panic would be a
    /// test-harness bug worth surfacing loud.
    fn ctx_with_ephemeral(replacement: Arc<dyn EphemeralStore>) -> Arc<AppContext> {
        let handle = PrometheusBuilder::new().build_recorder().handle();
        let (base, _mocks) = build_mock_ctx(handle);
        let mut base = Arc::try_unwrap(base).unwrap_or_else(|_| {
            panic!(
                "ctx_with_ephemeral: build_mock_ctx must return a sole Arc owner — \
                 a future change that clones the Arc before return breaks this helper"
            )
        });
        // `AppContext`'s data ports are `pub(crate)` (ADR 0008) so
        // the `..base` struct-update syntax is unreachable across
        // crates. Mutating the `pub ephemeral_*` fields in place is
        // equivalent and keeps the helper's intent intact.
        base.ephemeral_durable = replacement;
        Arc::new(base)
    }

    // -------------------- session_key --------------------

    #[test]
    fn session_key_has_stateful_upload_oci_v2_prefix() {
        // The OCI session-key prefix was bumped from
        // `stateful_upload:oci:` to `stateful_upload:oci_v2:` so
        // legacy bincode-encoded records never enter the postcard
        // decoder's path. Old keys expire via the 1-hour
        // `OCI_SESSION_TTL`; no dual-format reader exists.
        let sid = Uuid::new_v4();
        let key = session_key("oci", sid);
        assert!(key.starts_with("stateful_upload:oci_v2:"));
        assert!(!key.starts_with("stateful_upload:oci:"));
        assert!(key.ends_with(&sid.to_string()));
    }

    #[test]
    fn session_key_format_is_variable_per_caller() {
        // Documents that the `format` prefix is purely convention-level:
        // Maven / LFS callers in future items reuse this helper with
        // their own format string.  Regression guard against a
        // hardcoded "oci".
        let sid = Uuid::new_v4();
        let oci = session_key("oci", sid);
        let maven = session_key("maven", sid);
        assert_ne!(oci, maven);
        assert!(maven.starts_with("stateful_upload:maven:"));
    }

    // -------------------- encode/decode round-trip --------------------

    #[test]
    fn record_round_trips_via_postcard() {
        // `bincode 2.0` (RUSTSEC-2025-0141, unmaintained) was replaced
        // by `postcard`. The wire format is NOT byte-stable across
        // schema reorders: postcard encodes struct fields in declaration
        // order with no field tags, so swapping field order or changing
        // a type breaks decode of in-flight session records. The
        // drain-via-TTL migration covers the swap (old keys expire
        // under the legacy `stateful_upload:oci:` prefix), but FUTURE
        // field reorders need a fresh prefix bump too. Do not reorder
        // `UploadSessionRecord` fields without that bump.
        let repo = Uuid::new_v4();
        let principal = Uuid::new_v4();
        // Seed non-trivial values so the round-trip proves every field
        // survives encode/decode.
        let record = UploadSessionRecord::new(repo, 12_345, 1_700_000_000_000, 7, principal);
        let bytes = encode_record(&record).unwrap();
        let decoded = decode_record(&bytes).unwrap();
        assert_eq!(decoded, record);
        assert_eq!(decoded.repository_id(), repo);
        assert_eq!(decoded.principal_id(), principal);
        assert_eq!(decoded.version, 7);
    }

    #[test]
    fn record_round_trip_preserves_all_fields_at_extremes() {
        // Schema-evolution sanity: every field populated with a
        // boundary value (max u64, min/max i64, all-ones / all-zero
        // UUID bytes) so a future reorder or type change is caught
        // by the round-trip even when default-shaped values would
        // accidentally line up.
        let record = UploadSessionRecord {
            repository_id_bytes: [0xff; 16],
            bytes_received: u64::MAX,
            created_at_unix_millis: i64::MIN,
            version: u64::MAX,
            principal_id_bytes: [0x00; 16],
        };
        let bytes = encode_record(&record).unwrap();
        let decoded = decode_record(&bytes).unwrap();
        assert_eq!(decoded, record);
    }

    #[test]
    fn old_prefix_records_are_invisible_to_new_decoder_path() {
        // Drain-via-TTL migration assertion.
        // A record stored under the LEGACY prefix
        // (`stateful_upload:oci:{session_id}`) is unreachable from
        // the new code path, which queries the V2 prefix
        // (`stateful_upload:oci_v2:{session_id}`). The old key
        // expires via the 1-hour session TTL; the new code never
        // attempts to decode it. This test asserts the key-space
        // separation directly: no bytes are shared, no dual-format
        // reader is wired up, and a hostile or stale entry under
        // the old prefix is a `None` result on the new lookup.
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, _mocks) = build_mock_ctx(handle);
            let sid = Uuid::new_v4();
            // Manually plant a value under the legacy v1 prefix.
            let legacy_key = format!("stateful_upload:oci:{sid}");
            ctx.ephemeral_durable
                .put(
                    &legacy_key,
                    Bytes::from_static(b"legacy-bincode-payload"),
                    OCI_SESSION_TTL,
                )
                .await
                .unwrap();
            // The new code-path key for the same session id is
            // distinct and resolves to `None`.
            let new_key = session_key("oci", sid);
            assert_ne!(legacy_key, new_key);
            assert!(new_key.contains(":oci_v2:"));
            assert!(ctx.ephemeral_durable.get(&new_key).await.unwrap().is_none());
        });
    }

    #[test]
    fn new_initial_starts_at_version_1_with_zero_bytes() {
        // `put_if_absent` → store counter = 1; the in-record mirror
        // must match.
        let repo = Uuid::new_v4();
        let principal = Uuid::new_v4();
        let record = UploadSessionRecord::new_initial(repo, 1_700_000_000_000, principal);
        assert_eq!(record.version, 1);
        assert_eq!(record.bytes_received, 0);
        assert_eq!(record.repository_id(), repo);
        assert_eq!(record.principal_id(), principal);
    }

    #[test]
    fn decode_garbage_bytes_returns_invariant_error() {
        // Truncated / non-postcard bytes surface as Invariant —
        // never silently coerced to a default record. Three 0xff
        // bytes are too short to satisfy the fixed-size byte
        // arrays at the head of the record (16 bytes for the
        // repository UUID); postcard detects the unexpected EOF.
        let err = decode_record(&[0xff, 0xff, 0xff]).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    // -------------------- initiate — happy path --------------------

    /// Cap used by the existing initiate tests. Set high enough that
    /// the cap branch never fires; the dedicated cap tests below pass
    /// a lower value to exercise the rejection path.
    const TEST_HIGH_CAP: u32 = 1_000;

    /// Extract the success outcome or panic with a descriptive
    /// message — keeps the existing tests readable while honouring
    /// the new `InitiateResult` enum return type.
    fn unwrap_created(r: AppResult<InitiateResult>) -> InitiateOutcome {
        match r {
            Ok(InitiateResult::Created(o)) => o,
            Ok(InitiateResult::CapExceeded) => {
                panic!("expected Created, got CapExceeded — test misconfigured the cap");
            }
            Ok(InitiateResult::Contended) => {
                panic!("expected Created, got Contended — test induced cap-reconcile contention");
            }
            Err(e) => panic!("expected Created, got Err({e:?})"),
        }
    }

    #[test]
    fn initiate_writes_session_to_ephemeral_store() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let mut repo = sample_repository();
            let repo_id = repo.id;
            repo.key = "myrepo".into();
            mocks.repositories.insert(repo);

            let outcome = unwrap_created(
                initiate(&ctx, repo_id, api_actor(), TEST_HIGH_CAP, TEST_MAX_AGE).await,
            );
            assert_eq!(outcome.initial_version, 1);

            // Seeded record must be retrievable via the port.
            let key = session_key("oci", outcome.session_id);
            let stored = ctx
                .ephemeral_durable
                .get(&key)
                .await
                .unwrap()
                .expect("session record must be present after initiate");
            let decoded = decode_record(&stored).unwrap();
            assert_eq!(decoded.repository_id(), repo_id);
            assert_eq!(decoded.bytes_received, 0);
            assert_eq!(
                decoded.version, 1,
                "initiate must seed version=1 to mirror the EphemeralStore CAS counter"
            );
            assert!(
                decoded.created_at_unix_millis > 0,
                "created_at should be a real timestamp"
            );
        });
    }

    #[test]
    fn initiate_emits_created_metric_with_repo_key_label() {
        let (snap, _outcome) = capture(|| {
            run(async {
                let handle = PrometheusBuilder::new().build_recorder().handle();
                let (ctx, mocks) = build_mock_ctx(handle);
                let mut repo = sample_repository();
                let repo_id = repo.id;
                repo.key = "myrepo".into();
                mocks.repositories.insert(repo);

                unwrap_created(
                    initiate(&ctx, repo_id, api_actor(), TEST_HIGH_CAP, TEST_MAX_AGE).await,
                )
            })
        });
        let entries = snap.into_vec();
        let v = find_counter(
            &entries,
            "hort_stateful_upload_sessions_total",
            &[
                ("format", "oci"),
                ("repository", "myrepo"),
                ("result", "created"),
            ],
        )
        .expect(
            "hort_stateful_upload_sessions_total{format=oci,repository=myrepo,result=created} absent",
        );
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
    }

    // -------------------- initiate — failure paths --------------------

    #[test]
    fn initiate_propagates_ephemeral_store_failure_and_emits_no_metric() {
        let failing = Arc::new(FailingEphemeral::new());
        let failing_trait: Arc<dyn EphemeralStore> = failing.clone();

        let (snap, result) = capture(|| {
            run(async {
                let ctx = ctx_with_ephemeral(failing_trait);
                initiate(
                    &ctx,
                    Uuid::new_v4(),
                    api_actor(),
                    TEST_HIGH_CAP,
                    TEST_MAX_AGE,
                )
                .await
            })
        });
        let err = result.expect_err("failing ephemeral must surface an error");
        match err {
            AppError::Domain(DomainError::Invariant(msg)) => assert!(msg.contains("boom")),
            other => panic!("expected Domain(Invariant), got {other:?}"),
        }
        // No metric must fire — `created` is reserved for successful
        // sessions only.
        let entries = snap.into_vec();
        assert!(
            find_counter(
                &entries,
                "hort_stateful_upload_sessions_total",
                &[("format", "oci"), ("result", "created")]
            )
            .is_none(),
            "metric must NOT fire on infrastructure failure"
        );
    }

    #[test]
    fn initiate_surfaces_invariant_on_key_collision_and_does_not_retry() {
        // Forced `Ok(false)` from `put_if_absent` → Invariant error,
        // no retry with a fresh UUID.  Exercises the "cosmically
        // impossible but the port requires a branch" path.
        let (snap, result) = capture(|| {
            run(async {
                let ctx = ctx_with_ephemeral(Arc::new(AlwaysCollidingEphemeral));
                initiate(
                    &ctx,
                    Uuid::new_v4(),
                    api_actor(),
                    TEST_HIGH_CAP,
                    TEST_MAX_AGE,
                )
                .await
            })
        });
        let err = result.expect_err("collision must surface as Invariant");
        assert!(matches!(err, AppError::Domain(DomainError::Invariant(_))));
        let entries = snap.into_vec();
        assert!(
            find_counter(
                &entries,
                "hort_stateful_upload_sessions_total",
                &[("format", "oci"), ("result", "created")]
            )
            .is_none(),
            "no metric on collision"
        );
    }

    #[test]
    fn initiate_returns_contended_when_cap_reconcile_exhausts_retry_budget() {
        // M1 regression: pathological cap-set CAS contention (every
        // create race lost) must surface as `InitiateResult::Contended`
        // — a TRANSIENT status the handler maps to 503 + short
        // Retry-After — NOT an `Err` (which the handler maps to 500),
        // and NOT a `CapExceeded` (429, a real cap breach). No
        // cap-rejection metric fires for contention.
        let (snap, result) = capture(|| {
            run(async {
                let ctx = ctx_with_ephemeral(Arc::new(AlwaysContendedEphemeral));
                initiate(
                    &ctx,
                    Uuid::new_v4(),
                    api_actor(),
                    TEST_HIGH_CAP,
                    TEST_MAX_AGE,
                )
                .await
            })
        });
        let out = result.expect("cap-reconcile contention is a transient outcome, never an Err");
        assert!(
            matches!(out, InitiateResult::Contended),
            "perpetual cap-set CAS contention must surface as Contended, got {out:?}"
        );
        // Contention is a status, not a cap rejection — the over_cap
        // counter must stay clean.
        let entries = snap.into_vec();
        assert!(
            find_counter(
                &entries,
                "hort_upload_session_cap_rejections_total",
                &[("result", "over_cap")]
            )
            .is_none(),
            "Contended must NOT emit the cap-rejection metric"
        );
    }

    // -------------------- initiate — label-flag off --------------------

    #[test]
    fn initiate_emits_all_sentinel_when_repository_label_disabled() {
        use hort_http_core::test_support::build_mock_ctx_with_label_flag;
        let (snap, _) = capture(|| {
            run(async {
                let handle = PrometheusBuilder::new().build_recorder().handle();
                let (ctx, mocks) = build_mock_ctx_with_label_flag(handle, false);
                let mut repo = sample_repository();
                let repo_id = repo.id;
                repo.key = "myrepo".into();
                mocks.repositories.insert(repo);
                unwrap_created(
                    initiate(&ctx, repo_id, api_actor(), TEST_HIGH_CAP, TEST_MAX_AGE).await,
                )
            })
        });
        let entries = snap.into_vec();
        assert!(
            find_counter(
                &entries,
                "hort_stateful_upload_sessions_total",
                &[("repository", "_all")]
            )
            .is_some(),
            "label-off deployments must use the _all sentinel"
        );
    }

    // -------------------- initiate — per-(repo, principal) cap --------------------
    // The per-`(repo, principal)` cap is consumed atomically via
    // `EphemeralStore::try_increment_counter` so concurrent open-session
    // requests cannot race past the configured maximum.

    fn principal_actor(user_id: Uuid) -> ApiActor {
        ApiActor { user_id }
    }

    /// Drive `initiate` repeatedly with a fixed cap and count
    /// successful sessions vs cap rejections. Used by the cap-
    /// behaviour tests to express invariants like "cap-1 rejections
    /// after cap successes".
    async fn open_n_sessions(
        ctx: &AppContext,
        repo_id: Uuid,
        actor: &ApiActor,
        cap: u32,
        n: usize,
    ) -> (usize, usize) {
        let mut created = 0usize;
        let mut rejected = 0usize;
        for _ in 0..n {
            match initiate(ctx, repo_id, actor.clone(), cap, TEST_MAX_AGE)
                .await
                .unwrap()
            {
                InitiateResult::Created(_) => created += 1,
                InitiateResult::CapExceeded => rejected += 1,
                InitiateResult::Contended => {
                    panic!("open_n_sessions saw Contended — the harness never induces contention")
                }
            }
        }
        (created, rejected)
    }

    #[test]
    fn initiate_rejects_after_cap_with_cap_exceeded() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let mut repo = sample_repository();
            let repo_id = repo.id;
            repo.key = "myrepo".into();
            mocks.repositories.insert(repo);

            let actor = principal_actor(Uuid::new_v4());
            let cap: u32 = 32;
            // First `cap` attempts succeed.
            let (created, rejected) =
                open_n_sessions(&ctx, repo_id, &actor, cap, cap as usize).await;
            assert_eq!(created, cap as usize);
            assert_eq!(rejected, 0);
            // The next attempt must be rejected with CapExceeded.
            let next = initiate(&ctx, repo_id, actor, cap, TEST_MAX_AGE)
                .await
                .unwrap();
            assert!(
                matches!(next, InitiateResult::CapExceeded),
                "33rd request must surface as CapExceeded, got {next:?}",
            );
        });
    }

    #[test]
    fn initiate_emits_over_cap_metric_with_format_and_repo_label() {
        // The OCI adapter emits the RENAMED generic cap-rejection metric
        // `hort_upload_session_cap_rejections_total` carrying the
        // `format="oci"` label alongside `repo` + `result`. No
        // `principal_id` / `actor_id` (the architect catalog forbids
        // them as cardinality vectors).
        let (snap, _) = capture(|| {
            run(async {
                let handle = PrometheusBuilder::new().build_recorder().handle();
                let (ctx, mocks) = build_mock_ctx(handle);
                let mut repo = sample_repository();
                let repo_id = repo.id;
                repo.key = "myrepo".into();
                mocks.repositories.insert(repo);

                let actor = principal_actor(Uuid::new_v4());
                let cap: u32 = 2;
                // Fill the cap then attempt once more to force a
                // single rejection.
                let _ = open_n_sessions(&ctx, repo_id, &actor, cap, cap as usize).await;
                let _ = initiate(&ctx, repo_id, actor, cap, TEST_MAX_AGE)
                    .await
                    .unwrap();
            })
        });
        let entries = snap.into_vec();
        let v = find_counter(
            &entries,
            "hort_upload_session_cap_rejections_total",
            &[
                ("format", "oci"),
                ("repo", "myrepo"),
                ("result", "over_cap"),
            ],
        )
        .expect(
            "hort_upload_session_cap_rejections_total{format=oci,repo=myrepo,result=over_cap} \
             absent on rejection",
        );
        assert!(matches!(v, DebugValue::Counter(n) if *n >= 1));
    }

    #[test]
    fn initiate_cap_metric_does_not_carry_principal_label() {
        // Hard guard: the architect catalog forbids `principal_id` /
        // `user_id` / `actor_id` as metric labels (cardinality bomb).
        // This test asserts the absence by scanning every
        // `hort_upload_session_cap_rejections_total` series's label keys.
        let (snap, _) = capture(|| {
            run(async {
                let handle = PrometheusBuilder::new().build_recorder().handle();
                let (ctx, mocks) = build_mock_ctx(handle);
                let mut repo = sample_repository();
                let repo_id = repo.id;
                repo.key = "myrepo".into();
                mocks.repositories.insert(repo);
                let actor = principal_actor(Uuid::new_v4());
                let _ = open_n_sessions(&ctx, repo_id, &actor, 1, 1).await;
                let _ = initiate(&ctx, repo_id, actor, 1, TEST_MAX_AGE)
                    .await
                    .unwrap();
            })
        });
        let entries = snap.into_vec();
        for (ck, _, _, _) in &entries {
            if ck.kind() == MetricKind::Counter
                && ck.key().name() == "hort_upload_session_cap_rejections_total"
            {
                for label in ck.key().labels() {
                    assert_ne!(
                        label.key(),
                        "principal_id",
                        "cap metric MUST NOT carry principal_id label"
                    );
                    assert_ne!(
                        label.key(),
                        "user_id",
                        "cap metric MUST NOT carry user_id label"
                    );
                    assert_ne!(
                        label.key(),
                        "actor_id",
                        "cap metric MUST NOT carry actor_id label"
                    );
                }
            }
        }
    }

    #[test]
    fn freeing_one_session_via_finalize_unblocks_next_initiate() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let mut repo = sample_repository();
            repo.format = hort_domain::entities::repository::RepositoryFormat::Oci;
            let repo_id = repo.id;
            repo.key = "myrepo".into();
            mocks.repositories.insert(repo);

            let actor = principal_actor(Uuid::new_v4());
            let cap: u32 = 2;

            // Fill the cap.
            let s1 = match initiate(&ctx, repo_id, actor.clone(), cap, TEST_MAX_AGE)
                .await
                .unwrap()
            {
                InitiateResult::Created(o) => o.session_id,
                _ => panic!(),
            };
            let _s2 = match initiate(&ctx, repo_id, actor.clone(), cap, TEST_MAX_AGE)
                .await
                .unwrap()
            {
                InitiateResult::Created(o) => o.session_id,
                _ => panic!(),
            };

            // Cap reached — next is rejected.
            assert!(matches!(
                initiate(&ctx, repo_id, actor.clone(), cap, TEST_MAX_AGE)
                    .await
                    .unwrap(),
                InitiateResult::CapExceeded
            ));

            // Stream a 1-byte chunk into s1 via the production
            // append_chunk path (matches what a real client does on
            // a chunked push). Then finalize with the matching
            // SHA-256 — the cleanup path inside `finalize` drops the
            // session AND decrements the cap counter.
            let payload = b"x".to_vec();
            let hash: ContentHash = sha256_hex(&payload).parse().unwrap();
            let range = ContentRange { start: 0, end: 0 };
            append_chunk(
                &ctx,
                s1,
                Some(range),
                cursor_of(&payload),
                payload.len() as u64,
                10 * 1024 * 1024,
                repo_id,
                TEST_MAX_AGE,
            )
            .await
            .expect("append_chunk must succeed");
            let _ = finalize(
                &ctx,
                s1,
                hash,
                None,
                actor.clone(),
                repo_id,
                "library/nginx",
                10 * 1024 * 1024,
                TEST_MAX_AGE,
            )
            .await
            .expect("finalize must succeed and free a cap slot");

            // After freeing one slot, a fresh initiate must succeed.
            let next = initiate(&ctx, repo_id, actor, cap, TEST_MAX_AGE)
                .await
                .unwrap();
            assert!(
                matches!(next, InitiateResult::Created(_)),
                "freeing one session via finalize must unblock the next initiate"
            );
        });
    }

    #[test]
    fn finalize_conflict_path_also_decrements_cap_counter() {
        // Cancel-equivalent path: declared digest mismatches the
        // streamed content. `IngestUseCase::ingest` rolls back the CAS
        // blob AND the cap counter is decremented via the shared
        // `cleanup_session_and_staging` helper.
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let mut repo = sample_repository();
            repo.format = hort_domain::entities::repository::RepositoryFormat::Oci;
            let repo_id = repo.id;
            repo.key = "myrepo".into();
            mocks.repositories.insert(repo);

            let actor = principal_actor(Uuid::new_v4());
            let cap: u32 = 1;

            // Fill the cap.
            let s1 = match initiate(&ctx, repo_id, actor.clone(), cap, TEST_MAX_AGE)
                .await
                .unwrap()
            {
                InitiateResult::Created(o) => o.session_id,
                _ => panic!(),
            };
            // Cap is full — next initiate is rejected.
            assert!(matches!(
                initiate(&ctx, repo_id, actor.clone(), cap, TEST_MAX_AGE)
                    .await
                    .unwrap(),
                InitiateResult::CapExceeded
            ));

            // Append a chunk + finalize with the WRONG digest.
            let payload = b"abc".to_vec();
            let range = ContentRange { start: 0, end: 2 };
            append_chunk(
                &ctx,
                s1,
                Some(range),
                cursor_of(&payload),
                payload.len() as u64,
                10 * 1024 * 1024,
                repo_id,
                TEST_MAX_AGE,
            )
            .await
            .unwrap();
            let wrong: ContentHash =
                "0000000000000000000000000000000000000000000000000000000000000000"
                    .parse()
                    .unwrap();
            let err = finalize(
                &ctx,
                s1,
                wrong,
                None,
                actor.clone(),
                repo_id,
                "library/nginx",
                10 * 1024 * 1024,
                TEST_MAX_AGE,
            )
            .await
            .expect_err("digest mismatch must surface as Conflict");
            assert!(matches!(err, AppError::Domain(DomainError::Conflict(_))));

            // After the Conflict-path cleanup, the cap slot is free
            // again — the next initiate must succeed.
            let next = initiate(&ctx, repo_id, actor, cap, TEST_MAX_AGE)
                .await
                .unwrap();
            assert!(
                matches!(next, InitiateResult::Created(_)),
                "Conflict cleanup must decrement the cap counter"
            );
        });
    }

    #[test]
    fn cap_is_isolated_per_principal_in_the_same_repo() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let mut repo = sample_repository();
            let repo_id = repo.id;
            repo.key = "myrepo".into();
            mocks.repositories.insert(repo);

            let actor_a = principal_actor(Uuid::new_v4());
            let actor_b = principal_actor(Uuid::new_v4());
            let cap: u32 = 2;

            // A fills its cap.
            let _ = open_n_sessions(&ctx, repo_id, &actor_a, cap, cap as usize).await;
            assert!(matches!(
                initiate(&ctx, repo_id, actor_a, cap, TEST_MAX_AGE)
                    .await
                    .unwrap(),
                InitiateResult::CapExceeded
            ));

            // B is unaffected.
            let result = initiate(&ctx, repo_id, actor_b, cap, TEST_MAX_AGE)
                .await
                .unwrap();
            assert!(
                matches!(result, InitiateResult::Created(_)),
                "principal A at cap MUST NOT block principal B"
            );
        });
    }

    #[test]
    fn cap_is_isolated_per_repo_for_the_same_principal() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let mut repo_x = sample_repository();
            repo_x.key = "x".into();
            let repo_x_id = repo_x.id;
            let mut repo_y = sample_repository();
            repo_y.key = "y".into();
            let repo_y_id = repo_y.id;
            mocks.repositories.insert(repo_x);
            mocks.repositories.insert(repo_y);

            let actor = principal_actor(Uuid::new_v4());
            let cap: u32 = 2;

            // Fill cap on repo X.
            let _ = open_n_sessions(&ctx, repo_x_id, &actor, cap, cap as usize).await;
            assert!(matches!(
                initiate(&ctx, repo_x_id, actor.clone(), cap, TEST_MAX_AGE)
                    .await
                    .unwrap(),
                InitiateResult::CapExceeded
            ));

            // Same principal in repo Y is unaffected.
            let result = initiate(&ctx, repo_y_id, actor, cap, TEST_MAX_AGE)
                .await
                .unwrap();
            assert!(
                matches!(result, InitiateResult::Created(_)),
                "principal at cap in repo X MUST NOT block them in repo Y"
            );
        });
    }

    // -------------------- session-set age-prune (leak reclaim) --------------
    //
    // The generic cap primitive's own unit tests (admit / release /
    // age-prune / CAS-race / over-cap / per-format keyspace isolation)
    // live in `hort-http-core::upload_session_cap`. The tests here
    // exercise the OCI adapter's INTEGRATION with the primitive — that
    // `initiate` admits, and `finalize` / `cancel` release — through the
    // public OCI entry points, observing the cap set only via its
    // public key ([`upload_session_cap::session_set_key`]) so no private
    // decoder is touched from this crate.

    /// Cap-format string this adapter uses with the generic primitive.
    const CAP_FORMAT: &str = "oci";

    /// True when the per-`(oci, repo, principal)` cap set key is present
    /// (i.e. at least one live member). The primitive drops the key when
    /// the set empties, so absence == zero live members. Test-only
    /// observability that stays on the primitive's PUBLIC key surface.
    async fn cap_set_present(ctx: &AppContext, repo_id: Uuid, principal_id: Uuid) -> bool {
        let key = upload_session_cap::session_set_key(CAP_FORMAT, repo_id, principal_id);
        ctx.ephemeral_durable.get(&key).await.unwrap().is_some()
    }

    #[test]
    fn abandoned_sessions_age_out_and_reclaim_to_zero() {
        // Acceptance: abandoned sessions (opened, never finalized, no
        // DELETE) are reclaimed once they exceed the session max-age —
        // the next admit prunes them and the live count returns toward
        // 0. Driven via a tiny max-age + a real sleep so the abandoned
        // members are genuinely past the age threshold.
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let mut repo = sample_repository();
            let repo_id = repo.id;
            repo.key = "myrepo".into();
            mocks.repositories.insert(repo);

            let actor = principal_actor(Uuid::new_v4());
            let principal_id = actor.user_id;
            let cap: u32 = 3;
            // Very short max-age so abandoned members age out quickly.
            let short = Duration::from_millis(40);

            // Fill the cap with abandoned sessions (initiate only — no
            // finalize, no DELETE).
            let (created, rejected) = {
                let mut c = 0;
                let mut r = 0;
                for _ in 0..cap {
                    match initiate(&ctx, repo_id, actor.clone(), cap, short)
                        .await
                        .unwrap()
                    {
                        InitiateResult::Created(_) => c += 1,
                        InitiateResult::CapExceeded => r += 1,
                        InitiateResult::Contended => panic!("unexpected Contended in cap fill"),
                    }
                }
                (c, r)
            };
            assert_eq!(created, cap as usize);
            assert_eq!(rejected, 0);
            let _ = principal_id; // (cap state observed behaviourally below)
                                  // Cap is full — a fresh admit is rejected right now.
            assert!(matches!(
                initiate(&ctx, repo_id, actor.clone(), cap, short)
                    .await
                    .unwrap(),
                InitiateResult::CapExceeded
            ));

            // Let the abandoned members age past the max-age.
            tokio::time::sleep(Duration::from_millis(80)).await;

            // The next admit prunes ALL aged-out members and succeeds —
            // the abandoned-session leak is reclaimed on the next admit.
            let next = initiate(&ctx, repo_id, actor, cap, short).await.unwrap();
            assert!(
                matches!(next, InitiateResult::Created(_)),
                "aged-out abandoned sessions must be reclaimed on the next admit"
            );
        });
    }

    #[test]
    fn retry_storm_of_abandoned_admits_does_not_permanently_pin_the_cap() {
        // Acceptance: a retry storm of abandoned admits must NOT
        // monotonically pin the cap. The old counter refreshed its TTL
        // on every increment and never idled out; the set model prunes
        // by member age, so once members age past the max-age, admits
        // succeed again even under continuous retry pressure.
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let mut repo = sample_repository();
            let repo_id = repo.id;
            repo.key = "myrepo".into();
            mocks.repositories.insert(repo);

            let actor = principal_actor(Uuid::new_v4());
            let cap: u32 = 2;
            let short = Duration::from_millis(30);

            // Storm: keep hammering initiate. Early attempts fill the
            // cap, later ones are rejected — and crucially, a rejection
            // performs NO write, so it never refreshes the set TTL / the
            // members' age. (This is the structural leak fix.)
            let mut saw_rejection = false;
            for _ in 0..cap * 4 {
                if let InitiateResult::CapExceeded =
                    initiate(&ctx, repo_id, actor.clone(), cap, short)
                        .await
                        .unwrap()
                {
                    saw_rejection = true;
                }
            }
            assert!(
                saw_rejection,
                "the storm must have hit the cap at least once"
            );

            // Wait past the max-age — the abandoned members age out.
            tokio::time::sleep(Duration::from_millis(60)).await;

            // Admits succeed again: the cap was NOT permanently pinned.
            let after = initiate(&ctx, repo_id, actor, cap, short).await.unwrap();
            assert!(
                matches!(after, InitiateResult::Created(_)),
                "after the abandoned members age out, admits must succeed again — \
                 a retry storm must not permanently pin the cap"
            );
        });
    }

    // -------------------- DELETE-cancel release --------------------

    #[test]
    fn cancel_releases_session_set_member_and_cleans_staging() {
        // Explicit DELETE-cancel releases the set member (immediate slot
        // free) and drops the session row + staging bytes.
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let mut repo = sample_repository();
            repo.format = hort_domain::entities::repository::RepositoryFormat::Oci;
            let repo_id = repo.id;
            repo.key = "myrepo".into();
            mocks.repositories.insert(repo);

            let actor = principal_actor(Uuid::new_v4());
            let principal_id = actor.user_id;
            let cap: u32 = 1;

            // Fill the cap, PATCH a byte so staging exists.
            let sid = match initiate(&ctx, repo_id, actor.clone(), cap, TEST_MAX_AGE)
                .await
                .unwrap()
            {
                InitiateResult::Created(o) => o.session_id,
                _ => panic!(),
            };
            let payload = b"z".to_vec();
            append_chunk(
                &ctx,
                sid,
                Some(ContentRange { start: 0, end: 0 }),
                cursor_of(&payload),
                1,
                10 * 1024 * 1024,
                repo_id,
                TEST_MAX_AGE,
            )
            .await
            .unwrap();
            assert!(
                cap_set_present(&ctx, repo_id, principal_id).await,
                "the cap set must hold the live member before cancel"
            );
            // Cap full — next initiate rejected.
            assert!(matches!(
                initiate(&ctx, repo_id, actor.clone(), cap, TEST_MAX_AGE)
                    .await
                    .unwrap(),
                InitiateResult::CapExceeded
            ));

            // Cancel — releases exactly one member, drops session + staging.
            cancel(&ctx, sid, repo_id, TEST_MAX_AGE).await.unwrap();
            assert!(
                !cap_set_present(&ctx, repo_id, principal_id).await,
                "cancel must release the set member (set drops when empty)"
            );
            assert!(
                ctx.ephemeral_durable
                    .get(&session_key("oci", sid))
                    .await
                    .unwrap()
                    .is_none(),
                "cancel must drop the session row"
            );
            assert!(
                mocks.stateful_upload_staging.bytes_for(sid).is_none(),
                "cancel must drop the staging bytes"
            );

            // Slot is free again.
            assert!(matches!(
                initiate(&ctx, repo_id, actor, cap, TEST_MAX_AGE)
                    .await
                    .unwrap(),
                InitiateResult::Created(_)
            ));
        });
    }

    #[test]
    fn cancel_unknown_session_is_not_found() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, _mocks) = build_mock_ctx(handle);
            let err = cancel(&ctx, Uuid::new_v4(), Uuid::new_v4(), TEST_MAX_AGE)
                .await
                .expect_err("unknown session must error");
            assert!(matches!(
                err,
                AppError::Domain(DomainError::NotFound {
                    entity: "OciUploadSession",
                    ..
                })
            ));
        });
    }

    #[test]
    fn cancel_wrong_repo_is_not_found_for_tenant_isolation() {
        // Anti-enumeration: cancelling a session bound to a different
        // repo surfaces as NotFound, never leaking that it exists.
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, _mocks) = build_mock_ctx(handle);
            let repo_a = Uuid::new_v4();
            let repo_b = Uuid::new_v4();
            let sid = Uuid::new_v4();
            seed_session(&ctx, sid, repo_a, 0, 1).await;

            let err = cancel(&ctx, sid, repo_b, TEST_MAX_AGE)
                .await
                .expect_err("tenant mismatch must error");
            assert!(matches!(
                err,
                AppError::Domain(DomainError::NotFound {
                    entity: "OciUploadSession",
                    ..
                })
            ));
            // The session row for repo_a MUST still exist (we refused
            // before cleanup).
            assert!(ctx
                .ephemeral_durable
                .get(&session_key("oci", sid))
                .await
                .unwrap()
                .is_some());
        });
    }

    #[test]
    fn finalize_and_cancel_each_release_exactly_once() {
        // Finalize success and explicit DELETE-cancel each release
        // exactly one slot — no double-release / underflow across the
        // finalize + cancel mix. Proven behaviourally against a cap of
        // 2: filling the cap, releasing via finalize, and confirming
        // EXACTLY one slot reopens (not zero, not two) each time.
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let mut repo = sample_repository();
            repo.format = hort_domain::entities::repository::RepositoryFormat::Oci;
            let repo_id = repo.id;
            repo.key = "myrepo".into();
            mocks.repositories.insert(repo);

            let actor = principal_actor(Uuid::new_v4());
            let principal_id = actor.user_id;
            let cap: u32 = 2;

            // Open two sessions — the cap is now full.
            let s1 = match initiate(&ctx, repo_id, actor.clone(), cap, TEST_MAX_AGE)
                .await
                .unwrap()
            {
                InitiateResult::Created(o) => o.session_id,
                _ => panic!(),
            };
            let s2 = match initiate(&ctx, repo_id, actor.clone(), cap, TEST_MAX_AGE)
                .await
                .unwrap()
            {
                InitiateResult::Created(o) => o.session_id,
                _ => panic!(),
            };
            assert!(cap_set_present(&ctx, repo_id, principal_id).await);
            assert!(matches!(
                initiate(&ctx, repo_id, actor.clone(), cap, TEST_MAX_AGE)
                    .await
                    .unwrap(),
                InitiateResult::CapExceeded
            ));

            // Finalize s1. Exactly one slot must reopen: the next initiate
            // succeeds (proves ≥1 freed), but a SECOND one must be
            // rejected (proves EXACTLY 1 freed, since s2 is still live).
            let payload = b"x".to_vec();
            let hash: ContentHash = sha256_hex(&payload).parse().unwrap();
            append_chunk(
                &ctx,
                s1,
                Some(ContentRange { start: 0, end: 0 }),
                cursor_of(&payload),
                1,
                10 * 1024 * 1024,
                repo_id,
                TEST_MAX_AGE,
            )
            .await
            .unwrap();
            finalize(
                &ctx,
                s1,
                hash,
                None,
                actor.clone(),
                repo_id,
                "library/nginx",
                10 * 1024 * 1024,
                TEST_MAX_AGE,
            )
            .await
            .unwrap();
            let s3 = match initiate(&ctx, repo_id, actor.clone(), cap, TEST_MAX_AGE)
                .await
                .unwrap()
            {
                InitiateResult::Created(o) => o.session_id,
                other => panic!("finalize must free exactly one slot, got {other:?}"),
            };
            assert!(
                matches!(
                    initiate(&ctx, repo_id, actor.clone(), cap, TEST_MAX_AGE)
                        .await
                        .unwrap(),
                    InitiateResult::CapExceeded
                ),
                "finalize must free EXACTLY one slot — cap is full again (s2 + s3)"
            );

            // Cancel s2 (the last of the original pair) — one slot reopens.
            cancel(&ctx, s2, repo_id, TEST_MAX_AGE).await.unwrap();
            assert!(matches!(
                initiate(&ctx, repo_id, actor.clone(), cap, TEST_MAX_AGE)
                    .await
                    .unwrap(),
                InitiateResult::Created(_)
            ));

            // Re-cancel s1 (finalized, row gone) and s2 (already
            // cancelled) — both surface NotFound; neither underflows the
            // set. s3 is still live, so the set key must persist.
            cancel(&ctx, s1, repo_id, TEST_MAX_AGE)
                .await
                .expect_err("re-cancel of a finalized session is NotFound (row gone)");
            cancel(&ctx, s2, repo_id, TEST_MAX_AGE)
                .await
                .expect_err("re-cancel of a cancelled session is NotFound (row gone)");
            let _ = s3;
            assert!(
                cap_set_present(&ctx, repo_id, principal_id).await,
                "double-cancel must not underflow / drop the set while s3 + the last \
                 admit are still live"
            );
        });
    }

    // -------------------- reconcile-prune metric (adapter integration) ---
    //
    // The primitive's own prune-metric unit tests (pruned / none result,
    // format label, cardinality guard) live in
    // `hort-http-core::upload_session_cap`. This adapter-level test only
    // confirms that a routine OCI `initiate` propagates the renamed
    // generic metric with the `format="oci"` label attached.

    #[test]
    fn initiate_emits_reconcile_metric_with_format_and_repo_label() {
        // A clean admit (no aged-out members) emits the renamed generic
        // reconcile-prune metric with `result=none` and the OCI format
        // label.
        let (snap, _) = capture(|| {
            run(async {
                let handle = PrometheusBuilder::new().build_recorder().handle();
                let (ctx, mocks) = build_mock_ctx(handle);
                let mut repo = sample_repository();
                let repo_id = repo.id;
                repo.key = "myrepo".into();
                mocks.repositories.insert(repo);
                let actor = principal_actor(Uuid::new_v4());
                let _ = initiate(&ctx, repo_id, actor, 4, TEST_MAX_AGE)
                    .await
                    .unwrap();
            })
        });
        let entries = snap.into_vec();
        assert!(
            find_counter(
                &entries,
                "hort_upload_session_reconcile_pruned_total",
                &[("format", "oci"), ("repo", "myrepo"), ("result", "none")],
            )
            .is_some(),
            "a clean OCI admit must emit the renamed reconcile metric with format=oci"
        );
    }

    #[test]
    fn concurrent_initiates_never_over_admit_past_cap() {
        // The CAS-race SAFETY invariant (concurrent admits never
        // over-admit past the cap under single-key contention) is a
        // property of the generic primitive and is proven directly at
        // that layer in
        // `hort-http-core::upload_session_cap::concurrent_admits_never_over_admit_past_cap`.
        // At the OCI adapter level we assert the same behaviour through
        // the public `initiate` entry point, without reaching into the
        // primitive's private set decoder.
        //
        // Multi-thread runtime so the spawned tasks genuinely race.
        let (created, rejected, errored) = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let handle = PrometheusBuilder::new().build_recorder().handle();
                let (ctx, mocks) = build_mock_ctx(handle);
                let mut repo = sample_repository();
                let repo_id = repo.id;
                repo.key = "myrepo".into();
                mocks.repositories.insert(repo);
                let actor = principal_actor(Uuid::new_v4());
                let cap: u32 = 8;
                let contenders = 12u32; // > cap so some are rejected
                let mut handles = Vec::with_capacity(contenders as usize);
                for _ in 0..contenders {
                    let ctx_ref = ctx.clone();
                    let actor_clone = actor.clone();
                    handles.push(tokio::spawn(async move {
                        initiate(&ctx_ref, repo_id, actor_clone, cap, TEST_MAX_AGE).await
                    }));
                }
                let mut created = 0usize;
                let mut rejected = 0usize;
                // Transient non-admits: an infra `Err` OR an
                // `InitiateResult::Contended` (retry-budget exhaustion).
                let mut errored = 0usize;
                for h in handles {
                    match h.await.unwrap() {
                        Ok(InitiateResult::Created(_)) => created += 1,
                        Ok(InitiateResult::CapExceeded) => rejected += 1,
                        Ok(InitiateResult::Contended) | Err(_) => errored += 1,
                    }
                }
                (created, rejected, errored)
            });
        // SAFETY: never over-admit past the cap.
        assert!(
            created <= 8,
            "must never admit more than the cap, got {created}"
        );
        // Every attempt is accounted for (created / rejected / transient).
        assert_eq!(
            created + rejected + errored,
            12,
            "every attempt must resolve"
        );
        // At least the cap-many admits succeed (moderate contention is
        // comfortably within the retry budget — no transient errors
        // expected here, but the assertion tolerates them if the CI box
        // is pathologically slow).
        assert_eq!(
            created, 8,
            "cap-many admits must succeed under moderate contention"
        );
    }

    // -------------------- append_chunk --------------------

    /// Fixed principal id used by the PATCH/finalize tests that do not
    /// exercise the per-`(repo, principal)` cap. Cap tests pass their
    /// own principal id explicitly.
    fn synthetic_principal_id() -> Uuid {
        Uuid::from_u128(0xC0FFEE_u128)
    }

    /// Seed a session in the ephemeral store with given bytes_received +
    /// version.  Mirrors the shape `initiate` writes so `append_chunk`
    /// against the seeded key behaves identically to a production-path
    /// re-entrant PATCH.
    async fn seed_session(
        ctx: &AppContext,
        session_id: Uuid,
        repo_id: Uuid,
        bytes_received: u64,
        version: u64,
    ) {
        let record = UploadSessionRecord::new(
            repo_id,
            bytes_received,
            1_700_000_000_000,
            version,
            synthetic_principal_id(),
        );
        let bytes = encode_record(&record).unwrap();
        let key = session_key("oci", session_id);
        // `put` overwrites unconditionally; that's fine for seeding.
        // The store's own version counter bumps with each put, but the
        // in-record `version` field is what `append_chunk` consults.
        ctx.ephemeral_durable
            .put(&key, bytes, OCI_SESSION_TTL)
            .await
            .unwrap();
    }

    fn cursor_of(content: &[u8]) -> Box<dyn AsyncRead + Send + Unpin> {
        Box::new(std::io::Cursor::new(content.to_vec()))
    }

    #[test]
    fn append_chunk_streaming_no_length_appends_actual_bytes() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let mut repo = sample_repository();
            repo.key = "myrepo".into();
            let repo_id = repo.id;
            mocks.repositories.insert(repo);

            let session_id = Uuid::new_v4();
            seed_session(&ctx, session_id, repo_id, 0, 1).await;

            // No declared length (Transfer-Encoding: chunked) and no range —
            // exactly buildah's streaming PATCH shape.
            let content = b"hello world".to_vec();
            let out = append_chunk_streaming(
                &ctx,
                session_id,
                None,
                cursor_of(&content),
                1_000_000,
                repo_id,
                TEST_MAX_AGE,
            )
            .await
            .expect("streaming append must succeed without Content-Length");
            assert_eq!(out.bytes_received, content.len() as u64);
            assert_eq!(out.version, 2);
            let staged = mocks.stateful_upload_staging.bytes_for(session_id).unwrap();
            assert_eq!(staged, content);
        });
    }

    #[test]
    fn append_chunk_streaming_over_cap_rejects_and_bounds_staging() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let mut repo = sample_repository();
            repo.key = "myrepo".into();
            let repo_id = repo.id;
            mocks.repositories.insert(repo);

            let session_id = Uuid::new_v4();
            seed_session(&ctx, session_id, repo_id, 0, 1).await;

            // A streaming body over the cap: the bounded `take(max_bytes+1)`
            // truncates and the post-append check rejects — staging never
            // grows unbounded even though no length was declared.
            let content = vec![0u8; 100];
            let err = append_chunk_streaming(
                &ctx,
                session_id,
                None,
                cursor_of(&content),
                16,
                repo_id,
                TEST_MAX_AGE,
            )
            .await
            .expect_err("a streaming body over the cap must be rejected");
            assert!(matches!(err, AppError::SizeExceeded));
            let staged = mocks
                .stateful_upload_staging
                .bytes_for(session_id)
                .map(|b| b.len())
                .unwrap_or(0);
            assert!(
                staged <= 17,
                "staging must be bounded to max_bytes+1, got {staged}"
            );
        });
    }

    #[test]
    fn append_chunk_happy_path_bumps_version_and_appends_bytes() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let mut repo = sample_repository();
            repo.key = "myrepo".into();
            let repo_id = repo.id;
            mocks.repositories.insert(repo);

            let session_id = Uuid::new_v4();
            seed_session(&ctx, session_id, repo_id, 0, 1).await;

            let content = b"hello world".to_vec();
            let range = ContentRange {
                start: 0,
                end: content.len() as u64 - 1,
            };
            let out = append_chunk(
                &ctx,
                session_id,
                Some(range),
                cursor_of(&content),
                content.len() as u64,
                1_000_000,
                repo_id,
                TEST_MAX_AGE,
            )
            .await
            .expect("happy-path append must succeed");
            assert_eq!(out.bytes_received, content.len() as u64);
            assert_eq!(
                out.version, 2,
                "version must bump from initial 1 to 2 after one PATCH"
            );

            // Staging actually received the bytes.
            let staged = mocks.stateful_upload_staging.bytes_for(session_id).unwrap();
            assert_eq!(staged, content);

            // EphemeralStore got the new record (the in-record version
            // mirrors the store's own bump).
            let key = session_key("oci", session_id);
            let stored = ctx.ephemeral_durable.get(&key).await.unwrap().unwrap();
            let decoded = decode_record(&stored).unwrap();
            assert_eq!(decoded.bytes_received, content.len() as u64);
            assert_eq!(decoded.version, 2);
        });
    }

    #[test]
    fn append_chunk_unknown_session_returns_not_found() {
        let (snap, result) = capture(|| {
            run(async {
                let handle = PrometheusBuilder::new().build_recorder().handle();
                let (ctx, _mocks) = build_mock_ctx(handle);
                let session_id = Uuid::new_v4(); // never seeded
                let range = ContentRange { start: 0, end: 0 };
                append_chunk(
                    &ctx,
                    session_id,
                    Some(range),
                    cursor_of(b"x"),
                    1,
                    1_000_000,
                    Uuid::new_v4(),
                    TEST_MAX_AGE,
                )
                .await
            })
        });
        let err = result.expect_err("missing session must surface an error");
        assert!(matches!(
            err,
            AppError::Domain(DomainError::NotFound {
                entity: "OciUploadSession",
                ..
            })
        ));
        // `aborted` metric must fire.
        let entries = snap.into_vec();
        assert!(
            find_counter(
                &entries,
                "hort_stateful_upload_sessions_total",
                &[("format", "oci"), ("result", "aborted")]
            )
            .is_some(),
            "aborted metric absent on unknown-session error"
        );
    }

    #[test]
    fn append_chunk_wrong_repo_is_not_found_for_tenant_isolation() {
        let (snap, result) = capture(|| {
            run(async {
                let handle = PrometheusBuilder::new().build_recorder().handle();
                let (ctx, mocks) = build_mock_ctx(handle);
                let repo_a_id = Uuid::new_v4();
                let repo_b_id = Uuid::new_v4();
                // Only repo_a_id's session is seeded.
                let session_id = Uuid::new_v4();
                seed_session(&ctx, session_id, repo_a_id, 0, 1).await;
                let _ = mocks; // unused here — no real repos needed

                let range = ContentRange { start: 0, end: 0 };
                // Caller tries to PATCH against repo_b_id.
                append_chunk(
                    &ctx,
                    session_id,
                    Some(range),
                    cursor_of(b"x"),
                    1,
                    1_000_000,
                    repo_b_id,
                    TEST_MAX_AGE,
                )
                .await
            })
        });
        let err = result.expect_err("tenant-mismatch must error");
        // Anti-enumeration: same envelope as "session doesn't exist".
        // NEVER `Forbidden`.
        assert!(
            matches!(
                err,
                AppError::Domain(DomainError::NotFound {
                    entity: "OciUploadSession",
                    ..
                })
            ),
            "tenant-mismatch must surface as NotFound, got {err:?}"
        );
        let entries = snap.into_vec();
        assert!(find_counter(
            &entries,
            "hort_stateful_upload_sessions_total",
            &[("format", "oci"), ("result", "aborted")]
        )
        .is_some());
    }

    #[test]
    fn append_chunk_range_mismatch_returns_range_invalid_with_current() {
        let (snap, result) = capture(|| {
            run(async {
                let handle = PrometheusBuilder::new().build_recorder().handle();
                let (ctx, mocks) = build_mock_ctx(handle);
                let mut repo = sample_repository();
                repo.key = "myrepo".into();
                let repo_id = repo.id;
                mocks.repositories.insert(repo);
                let session_id = Uuid::new_v4();
                // session has 100 bytes already
                seed_session(&ctx, session_id, repo_id, 100, 1).await;

                let range = ContentRange { start: 50, end: 99 };
                append_chunk(
                    &ctx,
                    session_id,
                    Some(range),
                    cursor_of(&[0u8; 50]),
                    50,
                    1_000_000,
                    repo_id,
                    TEST_MAX_AGE,
                )
                .await
            })
        });
        let err = result.expect_err("range mismatch must error");
        match err {
            AppError::RangeInvalid { current } => {
                assert_eq!(current, 100, "current must reflect session bytes_received");
            }
            other => panic!("expected RangeInvalid, got {other:?}"),
        }
        let entries = snap.into_vec();
        assert!(find_counter(
            &entries,
            "hort_stateful_upload_sessions_total",
            &[("format", "oci"), ("result", "aborted")]
        )
        .is_some());
    }

    #[test]
    fn append_chunk_body_length_mismatch_returns_error() {
        let (snap, result) = capture(|| {
            run(async {
                let handle = PrometheusBuilder::new().build_recorder().handle();
                let (ctx, mocks) = build_mock_ctx(handle);
                let mut repo = sample_repository();
                repo.key = "myrepo".into();
                let repo_id = repo.id;
                mocks.repositories.insert(repo);
                let session_id = Uuid::new_v4();
                seed_session(&ctx, session_id, repo_id, 0, 1).await;

                // Content-Range says 100 bytes but body_length is 99.
                let range = ContentRange { start: 0, end: 99 };
                append_chunk(
                    &ctx,
                    session_id,
                    Some(range),
                    cursor_of(&[0u8; 99]),
                    99,
                    1_000_000,
                    repo_id,
                    TEST_MAX_AGE,
                )
                .await
            })
        });
        let err = result.expect_err("body-length mismatch must error");
        assert!(matches!(err, AppError::BodyLengthMismatch));
        let entries = snap.into_vec();
        assert!(find_counter(
            &entries,
            "hort_stateful_upload_sessions_total",
            &[("format", "oci"), ("result", "aborted")]
        )
        .is_some());
    }

    #[test]
    fn append_chunk_size_exceeded_returns_error() {
        let (snap, result) = capture(|| {
            run(async {
                let handle = PrometheusBuilder::new().build_recorder().handle();
                let (ctx, mocks) = build_mock_ctx(handle);
                let mut repo = sample_repository();
                repo.key = "myrepo".into();
                let repo_id = repo.id;
                mocks.repositories.insert(repo);
                let session_id = Uuid::new_v4();
                // Cap=100, existing=50, chunk=60 → 110 > 100.
                seed_session(&ctx, session_id, repo_id, 50, 1).await;
                let range = ContentRange {
                    start: 50,
                    end: 109,
                };
                append_chunk(
                    &ctx,
                    session_id,
                    Some(range),
                    cursor_of(&[0u8; 60]),
                    60,
                    100,
                    repo_id,
                    TEST_MAX_AGE,
                )
                .await
            })
        });
        let err = result.expect_err("size-exceeded must error");
        assert!(matches!(err, AppError::SizeExceeded));
        let entries = snap.into_vec();
        assert!(find_counter(
            &entries,
            "hort_stateful_upload_sessions_total",
            &[("format", "oci"), ("result", "aborted")]
        )
        .is_some());
    }

    #[test]
    fn append_chunk_cas_miss_returns_conflict() {
        // Seed a session at version=1, then race a second put that
        // bumps the store's version to 2 WITHOUT updating the record's
        // in-record version field.  This simulates a concurrent PATCH
        // that won: when `append_chunk` then calls CAS with
        // `expected_version = 1` (from the record it just read), the
        // store's counter is higher → CAS miss.
        let (snap, result) = capture(|| {
            run(async {
                let handle = PrometheusBuilder::new().build_recorder().handle();
                let (ctx, mocks) = build_mock_ctx(handle);
                let mut repo = sample_repository();
                repo.key = "myrepo".into();
                let repo_id = repo.id;
                mocks.repositories.insert(repo);
                let session_id = Uuid::new_v4();
                seed_session(&ctx, session_id, repo_id, 0, 1).await;

                // Second put → store version bumps to 2; in-record
                // field still says version=1.
                let record = UploadSessionRecord::new(
                    repo_id,
                    0,
                    1_700_000_000_000,
                    1,
                    synthetic_principal_id(),
                );
                let bytes = encode_record(&record).unwrap();
                let key = session_key("oci", session_id);
                ctx.ephemeral_durable
                    .put(&key, bytes, OCI_SESSION_TTL)
                    .await
                    .unwrap();

                let range = ContentRange { start: 0, end: 2 };
                append_chunk(
                    &ctx,
                    session_id,
                    Some(range),
                    cursor_of(b"abc"),
                    3,
                    1_000_000,
                    repo_id,
                    TEST_MAX_AGE,
                )
                .await
            })
        });
        let err = result.expect_err("CAS miss must error");
        assert!(
            matches!(err, AppError::Domain(DomainError::Conflict(_))),
            "CAS miss must surface as Conflict, got {err:?}"
        );
        let entries = snap.into_vec();
        assert!(find_counter(
            &entries,
            "hort_stateful_upload_sessions_total",
            &[("format", "oci"), ("result", "aborted")]
        )
        .is_some());
    }

    #[test]
    fn append_chunk_decode_failure_surfaces_invariant() {
        // Seed garbage bytes under the session key — decode fails,
        // caller sees `Invariant`.  Proves corruption doesn't silently
        // coerce into a `NotFound`.
        let (snap, result) = capture(|| {
            run(async {
                let handle = PrometheusBuilder::new().build_recorder().handle();
                let (ctx, _mocks) = build_mock_ctx(handle);
                let session_id = Uuid::new_v4();
                let key = session_key("oci", session_id);
                ctx.ephemeral_durable
                    .put(
                        &key,
                        Bytes::from_static(&[0xff, 0xff, 0xff]),
                        OCI_SESSION_TTL,
                    )
                    .await
                    .unwrap();

                let range = ContentRange { start: 0, end: 2 };
                append_chunk(
                    &ctx,
                    session_id,
                    Some(range),
                    cursor_of(b"abc"),
                    3,
                    1_000_000,
                    Uuid::new_v4(),
                    TEST_MAX_AGE,
                )
                .await
            })
        });
        let err = result.expect_err("decode failure must error");
        assert!(
            matches!(err, AppError::Domain(DomainError::Invariant(_))),
            "decode failure must surface as Invariant, got {err:?}"
        );
        let entries = snap.into_vec();
        assert!(find_counter(
            &entries,
            "hort_stateful_upload_sessions_total",
            &[("format", "oci"), ("result", "aborted")]
        )
        .is_some());
    }

    #[test]
    fn append_chunk_success_emits_no_aborted_metric() {
        // Mirror of the happy-path test, but specifically asserts that
        // on a successful PATCH NO `aborted` metric fires.  Separate
        // test because the happy-path above emphasises the byte-count
        // invariant; this one pins the catalog contract "only three
        // terminal states are counted, and success is not an `aborted`."
        let (snap, _) = capture(|| {
            run(async {
                let handle = PrometheusBuilder::new().build_recorder().handle();
                let (ctx, mocks) = build_mock_ctx(handle);
                let mut repo = sample_repository();
                repo.key = "myrepo".into();
                let repo_id = repo.id;
                mocks.repositories.insert(repo);
                let session_id = Uuid::new_v4();
                seed_session(&ctx, session_id, repo_id, 0, 1).await;

                let range = ContentRange { start: 0, end: 2 };
                append_chunk(
                    &ctx,
                    session_id,
                    Some(range),
                    cursor_of(b"abc"),
                    3,
                    1_000_000,
                    repo_id,
                    TEST_MAX_AGE,
                )
                .await
                .unwrap();
            })
        });
        let entries = snap.into_vec();
        assert!(
            find_counter(
                &entries,
                "hort_stateful_upload_sessions_total",
                &[("format", "oci"), ("result", "aborted")]
            )
            .is_none(),
            "success path must NOT emit an `aborted` metric"
        );
    }

    // -------------------- finalize --------------------

    /// Compute the sha256 hex of `content`. Lives in the test module
    /// because the production code never needs to hash anything outside
    /// of `StoragePort::put`.
    fn sha256_hex(content: &[u8]) -> String {
        use sha2::Digest;
        format!("{:x}", sha2::Sha256::digest(content))
    }

    /// Seed a session and pre-stage `chunks` bytes into it via the
    /// production `append_chunk` path. Returns the final
    /// `UploadSessionRecord` (version + bytes_received) so tests can
    /// feed a correct trailing Content-Range to `finalize`.
    async fn seed_session_with_bytes(
        ctx: &AppContext,
        repo_id: Uuid,
        chunks: &[u8],
    ) -> (Uuid, UploadSessionRecord) {
        let session_id = Uuid::new_v4();
        seed_session(ctx, session_id, repo_id, 0, 1).await;
        if chunks.is_empty() {
            // `append_chunk` requires a non-empty body; callers that
            // want to finalize a 0-byte blob skip this helper and
            // `finalize` directly against the freshly-initiated row.
            let record = decode_record(
                &ctx.ephemeral_durable
                    .get(&session_key("oci", session_id))
                    .await
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            return (session_id, record);
        }
        let range = ContentRange {
            start: 0,
            end: chunks.len() as u64 - 1,
        };
        let new_record = append_chunk(
            ctx,
            session_id,
            Some(range),
            cursor_of(chunks),
            chunks.len() as u64,
            10 * 1024 * 1024,
            repo_id,
            TEST_MAX_AGE,
        )
        .await
        .unwrap();
        (session_id, new_record)
    }

    #[test]
    fn finalize_clean_commits_ingest_and_deletes_session_and_staging() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let mut repo = sample_repository();
            repo.key = "myrepo".into();
            repo.format = hort_domain::entities::repository::RepositoryFormat::Oci;
            let repo_id = repo.id;
            mocks.repositories.insert(repo);

            let content = b"finalize me".to_vec();
            let hash: ContentHash = sha256_hex(&content).parse().unwrap();
            let (session_id, _rec) = seed_session_with_bytes(&ctx, repo_id, &content).await;

            let outcome = finalize(
                &ctx,
                session_id,
                hash.clone(),
                None,
                api_actor(),
                repo_id,
                "library/nginx",
                10 * 1024 * 1024,
                TEST_MAX_AGE,
            )
            .await
            .expect("clean finalize must succeed");

            // Artifact row exists in the mock with the expected size.
            assert_eq!(outcome.artifact.size_bytes as usize, content.len());
            assert_eq!(outcome.artifact.sha256_checksum, hash);

            // Session row is gone.
            let key = session_key("oci", session_id);
            assert!(ctx.ephemeral_durable.get(&key).await.unwrap().is_none());
            // Staging file is gone.
            assert!(mocks
                .stateful_upload_staging
                .bytes_for(session_id)
                .is_none());
        });
    }

    #[test]
    fn finalize_tenant_mismatch_returns_not_found_and_does_not_touch_staging() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let mut repo = sample_repository();
            repo.format = hort_domain::entities::repository::RepositoryFormat::Oci;
            let repo_id = repo.id;
            mocks.repositories.insert(repo);

            // Session belongs to repo_id; caller passes a different UUID.
            let content = b"abc".to_vec();
            let hash: ContentHash = sha256_hex(&content).parse().unwrap();
            let (session_id, _) = seed_session_with_bytes(&ctx, repo_id, &content).await;

            let other_repo = Uuid::new_v4();
            let err = finalize(
                &ctx,
                session_id,
                hash.clone(),
                None,
                api_actor(),
                other_repo,
                "x",
                10 * 1024 * 1024,
                TEST_MAX_AGE,
            )
            .await
            .expect_err("tenant mismatch must error");
            assert!(
                matches!(
                    err,
                    AppError::Domain(DomainError::NotFound {
                        entity: "OciUploadSession",
                        ..
                    })
                ),
                "expected NotFound(OciUploadSession), got {err:?}"
            );

            // Staging MUST still exist — we refused before touching
            // the ingest path, so the legitimate tenant's own PUT can
            // still succeed.
            assert!(mocks
                .stateful_upload_staging
                .bytes_for(session_id)
                .is_some());
            // Session row MUST still exist.
            let key = session_key("oci", session_id);
            assert!(ctx.ephemeral_durable.get(&key).await.unwrap().is_some());
        });
    }

    #[test]
    fn finalize_digest_mismatch_returns_conflict_and_cleans_up_everything() {
        // Critical invariant: `IngestUseCase::ingest` rolls back the
        // CAS blob on digest mismatch; this test additionally asserts
        // that the session + staging are dropped AND that no Artifact
        // row was committed.
        let (snap, _) = capture(|| {
            run(async {
                let handle = PrometheusBuilder::new().build_recorder().handle();
                let (ctx, mocks) = build_mock_ctx(handle);
                let mut repo = sample_repository();
                repo.key = "myrepo".into();
                repo.format = hort_domain::entities::repository::RepositoryFormat::Oci;
                let repo_id = repo.id;
                mocks.repositories.insert(repo);

                let content = b"real bytes".to_vec();
                let (session_id, _) = seed_session_with_bytes(&ctx, repo_id, &content).await;

                // Declare a hash that does NOT match the content.
                let wrong: ContentHash =
                    "0000000000000000000000000000000000000000000000000000000000000000"
                        .parse()
                        .unwrap();

                let err = finalize(
                    &ctx,
                    session_id,
                    wrong,
                    None,
                    api_actor(),
                    repo_id,
                    "library/nginx",
                    10 * 1024 * 1024,
                    TEST_MAX_AGE,
                )
                .await
                .expect_err("digest mismatch must error");
                assert!(
                    matches!(err, AppError::Domain(DomainError::Conflict(_))),
                    "mismatch must surface as Conflict, got {err:?}"
                );

                // Session gone.
                let key = session_key("oci", session_id);
                assert!(ctx.ephemeral_durable.get(&key).await.unwrap().is_none());
                // Staging gone.
                assert!(mocks
                    .stateful_upload_staging
                    .bytes_for(session_id)
                    .is_none());
                // No artifact committed — the lifecycle port is the
                // commit boundary; zero transitions means zero rows
                // AND zero events.
                assert_eq!(
                    mocks.lifecycle.committed_transitions().len(),
                    0,
                    "declared-hash mismatch MUST NOT commit a lifecycle transition \
                     (if this fails, the CAS rollback in IngestUseCase::ingest is broken)"
                );
            })
        });
        // `aborted` metric fires on Conflict.
        let entries = snap.into_vec();
        assert!(
            find_counter(
                &entries,
                "hort_stateful_upload_sessions_total",
                &[("format", "oci"), ("result", "aborted")]
            )
            .is_some(),
            "digest mismatch must emit `aborted` on hort_stateful_upload_sessions_total"
        );
        // `finalized` must NOT fire.
        assert!(
            find_counter(
                &entries,
                "hort_stateful_upload_sessions_total",
                &[("format", "oci"), ("result", "finalized")]
            )
            .is_none(),
            "digest mismatch must NOT emit `finalized`"
        );
    }

    #[test]
    fn finalize_emits_finalized_counter_and_bytes_histogram_on_success() {
        let (snap, _) = capture(|| {
            run(async {
                let handle = PrometheusBuilder::new().build_recorder().handle();
                let (ctx, mocks) = build_mock_ctx(handle);
                let mut repo = sample_repository();
                repo.key = "myrepo".into();
                repo.format = hort_domain::entities::repository::RepositoryFormat::Oci;
                let repo_id = repo.id;
                mocks.repositories.insert(repo);

                let content = b"hello metric".to_vec();
                let hash: ContentHash = sha256_hex(&content).parse().unwrap();
                let (session_id, _) = seed_session_with_bytes(&ctx, repo_id, &content).await;

                finalize(
                    &ctx,
                    session_id,
                    hash,
                    None,
                    api_actor(),
                    repo_id,
                    "library/nginx",
                    10 * 1024 * 1024,
                    TEST_MAX_AGE,
                )
                .await
                .unwrap();
            })
        });
        let entries = snap.into_vec();
        assert!(
            find_counter(
                &entries,
                "hort_stateful_upload_sessions_total",
                &[
                    ("format", "oci"),
                    ("repository", "myrepo"),
                    ("result", "finalized"),
                ]
            )
            .is_some(),
            "finalized counter absent on success"
        );
        // Bytes histogram present (exact value coverage is in the
        // bytes-value assertion further below — here we just pin the
        // catalog contract that the series exists with the right
        // labels).
        let bytes_present = entries.iter().any(|(ck, _, _, _)| {
            ck.kind() == MetricKind::Histogram
                && ck.key().name() == "hort_stateful_upload_session_bytes"
                && ck
                    .key()
                    .labels()
                    .any(|l| l.key() == "format" && l.value() == "oci")
                && ck
                    .key()
                    .labels()
                    .any(|l| l.key() == "repository" && l.value() == "myrepo")
        });
        assert!(
            bytes_present,
            "hort_stateful_upload_session_bytes histogram absent on success"
        );
        // Duration histogram present.
        let dur_present = entries.iter().any(|(ck, _, _, _)| {
            ck.kind() == MetricKind::Histogram
                && ck.key().name() == "hort_stateful_upload_finalize_duration_seconds"
        });
        assert!(
            dur_present,
            "hort_stateful_upload_finalize_duration_seconds histogram absent"
        );
    }

    #[test]
    fn finalize_with_trailing_body_drains_chunk_before_ingest() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let mut repo = sample_repository();
            repo.key = "myrepo".into();
            repo.format = hort_domain::entities::repository::RepositoryFormat::Oci;
            let repo_id = repo.id;
            mocks.repositories.insert(repo);

            // Seed session with `first`, finalize with `trailing` —
            // total content hashes to sha256(first || trailing).
            let first = b"first-chunk".to_vec();
            let trailing = b"trailing-bytes".to_vec();
            let full: Vec<u8> = first.iter().chain(trailing.iter()).copied().collect();
            let hash: ContentHash = sha256_hex(&full).parse().unwrap();

            let (session_id, _) = seed_session_with_bytes(&ctx, repo_id, &first).await;

            let range = ContentRange {
                start: first.len() as u64,
                end: (first.len() + trailing.len()) as u64 - 1,
            };
            let outcome = finalize(
                &ctx,
                session_id,
                hash.clone(),
                Some((
                    cursor_of(&trailing),
                    Some(range),
                    Some(trailing.len() as u64),
                )),
                api_actor(),
                repo_id,
                "library/nginx",
                10 * 1024 * 1024,
                TEST_MAX_AGE,
            )
            .await
            .expect("finalize with trailing body must succeed");

            assert_eq!(outcome.artifact.size_bytes as usize, full.len());
            assert_eq!(outcome.artifact.sha256_checksum, hash);
        });
    }

    #[test]
    fn finalize_unknown_session_returns_not_found() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, _mocks) = build_mock_ctx(handle);
            let hash: ContentHash =
                "1111111111111111111111111111111111111111111111111111111111111111"
                    .parse()
                    .unwrap();
            let err = finalize(
                &ctx,
                Uuid::new_v4(), // never initiated
                hash,
                None,
                api_actor(),
                Uuid::new_v4(),
                "library/nginx",
                10 * 1024 * 1024,
                TEST_MAX_AGE,
            )
            .await
            .expect_err("unknown session must error");
            assert!(
                matches!(
                    err,
                    AppError::Domain(DomainError::NotFound {
                        entity: "OciUploadSession",
                        ..
                    })
                ),
                "unknown session must surface as NotFound(OciUploadSession), got {err:?}"
            );
        });
    }

    #[test]
    fn finalize_with_session_but_missing_staging_returns_invariant() {
        // Seed the session row in the ephemeral store but NEVER write
        // any staging bytes. The stream_read path hits NotFound
        // which the finalize function maps to `Invariant`. This is
        // the "GC sweep raced us" branch.
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let mut repo = sample_repository();
            repo.format = hort_domain::entities::repository::RepositoryFormat::Oci;
            let repo_id = repo.id;
            mocks.repositories.insert(repo);

            let session_id = Uuid::new_v4();
            seed_session(&ctx, session_id, repo_id, 0, 1).await;
            // No append — staging is empty per the mock's semantics
            // (`bytes_for` → None).

            let hash: ContentHash =
                "2222222222222222222222222222222222222222222222222222222222222222"
                    .parse()
                    .unwrap();
            let err = finalize(
                &ctx,
                session_id,
                hash,
                None,
                api_actor(),
                repo_id,
                "x",
                10 * 1024 * 1024,
                TEST_MAX_AGE,
            )
            .await
            .expect_err("session+missing-staging must error");
            assert!(
                matches!(err, AppError::Domain(DomainError::Invariant(_))),
                "missing staging must surface as Invariant, got {err:?}"
            );
        });
    }
}
