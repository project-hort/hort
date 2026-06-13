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
//! The record now carries a `version: u64` field (Item 2 — PATCH
//! append). The `EphemeralStore` port's own CAS version counter is
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
//! sessions expire via the 1-hour [`OCI_SESSION_TTL`].  No dual-
//! format reader exists; old keys are unreachable from new code.

use std::time::{Duration, Instant};

use bytes::Bytes;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncRead;
use tracing::Instrument;
use uuid::Uuid;

use hort_app::error::{AppError, AppResult};
use hort_app::use_cases::ingest_use_case::{IngestOutcome, VerifiedIngestRequest};
use hort_domain::error::DomainError;
use hort_domain::events::ApiActor;
use hort_domain::types::ContentHash;
use hort_formats::oci::OciFormatHandler;
use hort_http_core::context::AppContext;

use super::coords::oci_blob_coords;

// ---------------------------------------------------------------------------
// TTL
// ---------------------------------------------------------------------------

/// Default upload-session TTL.  Per backlog, `HORT_OCI_SESSION_MAX_AGE_SECS`
/// will thread this through `hort-server::Config` (tracked in the OCI
/// pull-through backlog); until then the hardcoded one-hour ceiling is
/// adequate — it matches the Docker Registry v2 reference implementation
/// and gives humans enough time to retry a multi-gigabyte push over a
/// flaky link without GC'ing the session out from under them.
///
/// TODO(oci-session-max-age): replace with a value threaded from
/// `AppContext`/`hort-server::Config` and honour
/// `HORT_OCI_SESSION_MAX_AGE_SECS`.
pub const OCI_SESSION_TTL: Duration = Duration::from_secs(3600);

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

/// Build the `EphemeralStore` key for the per-`(repo, principal)`
/// outstanding-session counter.
///
/// Key shape is `oci:session_count:{repo_id}:{principal_id}`. Stable across
/// process restarts (every component is a UUID's `Display` form), so
/// counters reseat naturally when a Redis-backed deployment recycles
/// the registry binary while an attacker's session pool is still in
/// flight. The `oci:` prefix keeps this counter out of the
/// `stateful_upload:` namespace consumed by [`session_key`] —
/// individual session rows and the aggregate counter never collide.
pub fn session_count_key(repo_id: Uuid, principal_id: Uuid) -> String {
    format!("oci:session_count:{repo_id}:{principal_id}")
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
/// `principal_id_bytes` allows finalize / cleanup paths to decrement
/// the per-`(repo, principal)` outstanding-session counter without
/// re-querying the originating request. Sessions are TTL-bounded
/// (1 hour); a deployment that introduces this field handles the
/// transient deploy-window decode failures via the existing
/// `Invariant` mapping — the cap counter naturally TTL-cleans even
/// when a few sessions skip the decrement.
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
    /// cleanup paths to decrement the per-`(repo, principal)` cap
    /// counter.
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
/// `EphemeralStore::compare_and_swap` contract — Items 2/3 feed this
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
    /// Session created. Caller emits the §2.10 202 + `Location` /
    /// `Docker-Upload-UUID` / `Range: 0-0` envelope.
    Created(InitiateOutcome),
    /// Per-`(repo, principal)` cap exceeded. Caller emits 429 with
    /// the OCI `TOOMANYREQUESTS` envelope.
    CapExceeded,
}

/// Initiate a three-phase OCI blob upload.
///
/// Generates a fresh random v4 `session_id`, writes an empty
/// `UploadSessionRecord` under `stateful_upload:oci_v2:<session_id>` via
/// [`EphemeralStore::put_if_absent`], emits the `created` count on
/// `hort_stateful_upload_sessions_total`, and returns the session id for
/// the handler to serve in the `Location` header.
///
/// `_actor` is accepted for API parity with Items 2/3 (which will use
/// it on causation/audit events); Item 1 does not persist an event
/// until finalize, so the actor stays unused here.  Intentional — the
/// signature is part of the public contract and Items 2/3 will carry
/// the actor through to `add_member` / `register_by_hash`.
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
) -> AppResult<InitiateResult> {
    initiate_inner(ctx, repo_id, actor, max_sessions_per_principal)
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
) -> AppResult<InitiateResult> {
    let principal_id = actor.user_id;

    // Atomic increment-and-cap. The atomic primitive on
    // `EphemeralStore` closes the TOCTOU race a non-atomic
    // `get + check + put` would leave open: 33 concurrent open-session
    // requests for the same `(repo, principal)` against a cap of 32
    // yield exactly 32 successful increments and 1 `Ok(None)` rejection
    // — never 33 successes.
    //
    // The counter's TTL is `OCI_SESSION_TTL` and is refreshed on
    // every increment. With this shape the counter naturally drops
    // when the principal stops creating sessions for a session-TTL
    // window, bounding leakage if a finalize / cancel path skips a
    // decrement (the worst case is a counter that floats slightly
    // high until the next idle period).
    let counter_key = session_count_key(repo_id, principal_id);
    let cap_outcome = ctx
        .ephemeral_durable
        .try_increment_counter(
            &counter_key,
            max_sessions_per_principal as u64,
            OCI_SESSION_TTL,
        )
        .await
        .map_err(AppError::from)?;
    if cap_outcome.is_none() {
        // Cap rejection — info-level (privilege denial), NOT error.
        // No `actor_id` / `user_id` in the metric labels — both are
        // forbidden cardinality vectors per the catalog.
        let repo_label = resolve_repo_label(ctx, repo_id).await;
        tracing::info!(
            target: "hort::oci::upload_session",
            repository_id = %repo_id,
            cap = max_sessions_per_principal,
            "OCI upload-session create rejected: per-(repo, principal) cap exceeded",
        );
        metrics::counter!(
            "hort_oci_session_cap_rejections_total",
            "repo" => repo_label,
            "result" => "over_cap",
        )
        .increment(1);
        return Ok(InitiateResult::CapExceeded);
    }

    let session_id = Uuid::new_v4();
    let record =
        UploadSessionRecord::new_initial(repo_id, Utc::now().timestamp_millis(), principal_id);
    let bytes = encode_record(&record).map_err(AppError::from)?;
    let key = session_key("oci", session_id);

    let created = ctx
        .ephemeral_durable
        .put_if_absent(&key, bytes, OCI_SESSION_TTL)
        .await
        .map_err(AppError::from)?;
    if !created {
        tracing::error!(
            session_id = %session_id,
            "duplicate upload-session ID — UUID collision or repeated put_if_absent"
        );
        // Roll back the cap-counter increment we just took — leaving
        // it would burn a slot without producing a real session.
        decrement_session_count(ctx, repo_id, principal_id).await;
        return Err(AppError::from(DomainError::Invariant(
            "upload-session key already present".into(),
        )));
    }

    // Resolve the repository key for the metric label.  Matches
    // `IngestUseCase::repo_label` semantics: fall back to `_all` when
    // the lookup fails (operator-disabled label, repo deleted between
    // the authz extractor and this call, …).
    let repo_label = resolve_repo_label(ctx, repo_id).await;
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

/// Decrement the per-`(repo, principal)` outstanding-session counter.
///
/// Best-effort: an infrastructure-level error on the decrement is
/// logged at `warn!` but does NOT propagate to the caller. The counter
/// has TTL `OCI_SESSION_TTL` so a leaked slot self-heals after the
/// longest possible session lifetime.
///
/// Underflow guard: when the stored counter is already at 0 (or
/// absent — the TTL elapsed), the decrement is a no-op and a
/// `warn!` event is emitted. Underflow indicates a bug (a release
/// path firing without a matching create), not an attack — but the
/// counter MUST stay non-negative so future cap checks read a sane
/// value.
async fn decrement_session_count(ctx: &AppContext, repo_id: Uuid, principal_id: Uuid) {
    let key = session_count_key(repo_id, principal_id);
    let stored = match ctx.ephemeral_durable.get(&key).await {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!(
                target: "hort::oci::upload_session",
                repository_id = %repo_id,
                error = %err,
                "OCI session-cap decrement: ephemeral get failed; counter will TTL out",
            );
            return;
        }
    };
    // Counter already dropped (TTL elapsed). Nothing to decrement;
    // the cap state is consistent with "no outstanding sessions"
    // already.
    let Some(value) = stored else {
        return;
    };
    let Ok(s) = std::str::from_utf8(&value) else {
        tracing::warn!(
            target: "hort::oci::upload_session",
            repository_id = %repo_id,
            "OCI session-cap decrement: counter has non-utf8 bytes; leaving \
             counter alone (TTL will reap)",
        );
        return;
    };
    let Ok(current) = s.parse::<u64>() else {
        tracing::warn!(
            target: "hort::oci::upload_session",
            repository_id = %repo_id,
            "OCI session-cap decrement: counter is non-numeric; leaving \
             counter alone (TTL will reap)",
        );
        return;
    };
    if current == 0 {
        // Underflow: a release path fired without a matching create.
        // Indicates a bug, not an attack. The counter stays at 0 so
        // subsequent cap checks see the correct state.
        tracing::warn!(
            target: "hort::oci::upload_session",
            repository_id = %repo_id,
            "OCI session-cap decrement attempted on zero counter — \
             release path fired without a matching create (bug, not attack); \
             counter clamped at 0",
        );
        return;
    }
    let new_value = current - 1;
    if new_value == 0 {
        // Cleanest representation of "no outstanding sessions" is
        // to drop the key. The next increment recreates it via
        // `try_increment_counter` taking the absent-key branch.
        // `delete` is idempotent so a TTL race is harmless.
        if let Err(err) = ctx.ephemeral_durable.delete(&key).await {
            tracing::warn!(
                target: "hort::oci::upload_session",
                repository_id = %repo_id,
                error = %err,
                "OCI session-cap decrement: delete failed; counter will TTL out",
            );
        }
        return;
    }
    // Concurrent decrements are rare (cap-bounded) and the
    // counter's TTL re-anchors on every write. The CAS-based
    // race-freedom we get on increment is not strictly required on
    // decrement — a lost decrement just leaves the counter higher
    // than reality, which TTL repairs.
    let new_bytes = Bytes::from(format!("{new_value}").into_bytes());
    if let Err(err) = ctx
        .ephemeral_durable
        .put(&key, new_bytes, OCI_SESSION_TTL)
        .await
    {
        tracing::warn!(
            target: "hort::oci::upload_session",
            repository_id = %repo_id,
            error = %err,
            "OCI session-cap decrement: put failed; counter will TTL out",
        );
    }
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
// append_chunk (Item 2 — PATCH)
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

impl ContentRange {
    /// Span width — `end - start + 1` because the range is inclusive
    /// on both ends per OCI spec §2.3.
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
///    emit the right §2.8 status code (416 / 400 / 413).
/// 3. `ctx.stateful_upload_staging.append(session_id, stream)` — appends
///    the body bytes to staging.  Non-retryable; a failure on this step
///    leaves the session's `bytes_received` unchanged (we haven't CASed
///    yet).
/// 4. `ctx.ephemeral_durable.compare_and_swap(key, record.version, new_record,
///    TTL)` — atomic bump + TTL slide.  A CAS miss means a concurrent
///    PATCH won; we surface [`DomainError::Conflict`] so the adapter
///    emits `400 BLOB_UPLOAD_INVALID` per §2.8.
///
/// # Tenant isolation
///
/// The `repo_id` argument is the write-authorised repository resolved
/// from the request's `:repo_key` path param.  The session's stored
/// `repository_id` MUST match.  Mismatch maps to
/// [`DomainError::NotFound`] (not `Forbidden`) — the design doc's
/// anti-enumeration stance in §2.9 item 9.
///
/// # Hash deferral
///
/// This function DOES NOT compute the SHA-256 of the chunk.  Hashing
/// happens once on finalize (Item 3) via `StoragePort::put`, which is
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
pub(crate) async fn append_chunk(
    ctx: &AppContext,
    session_id: Uuid,
    content_range: Option<ContentRange>,
    stream: Box<dyn AsyncRead + Send + Unpin>,
    body_length: u64,
    max_bytes: u64,
    repo_id: Uuid,
) -> AppResult<UploadSessionRecord> {
    let key = session_key("oci", session_id);

    let result = append_chunk_core(
        ctx,
        session_id,
        &key,
        content_range,
        stream,
        body_length,
        max_bytes,
        repo_id,
    )
    .await;

    // On any unrecoverable error, emit `aborted` exactly once.  Kept
    // outside the core so every error-producing `?` funnels through the
    // same metric site.  Success is deliberately silent.
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

    result
}

#[allow(clippy::too_many_arguments)]
async fn append_chunk_core(
    ctx: &AppContext,
    session_id: Uuid,
    key: &str,
    content_range: Option<ContentRange>,
    stream: Box<dyn AsyncRead + Send + Unpin>,
    body_length: u64,
    max_bytes: u64,
    repo_id: Uuid,
) -> AppResult<UploadSessionRecord> {
    // --- Cheap pre-I/O check when the client supplied an explicit range.
    // A width-vs-body-length mismatch fails loud here before we touch
    // outbound ports; staging never grows from a body that disagreed
    // with the header, so no partial-append repair path is needed.
    // When the range is absent (containers/image, skopeo, podman send
    // chunks without `Content-Range`) we synthesise it after loading
    // the session record below.
    if let Some(ref range) = content_range {
        if range.span() != body_length {
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

    // --- Synthesise an absent Content-Range from the session offset.
    // The OCI v1.1 spec recommends `Content-Range` on chunked PATCH
    // but the dominant client implementation (containers/image, used
    // by skopeo, podman, buildah) and the Docker Registry V2 reference
    // omit it.  Treating an absent range as "append at current offset"
    // is the unique meaningful interpretation and matches GHCR / Harbor
    // / zot behaviour.  The strict `start == record.bytes_received`
    // check below still applies and surfaces as RangeInvalid when an
    // explicit (and incorrect) range is supplied.
    let content_range = content_range.unwrap_or_else(|| ContentRange {
        start: record.bytes_received,
        end: record
            .bytes_received
            .saturating_add(body_length)
            .saturating_sub(1),
    });

    // --- Validate Content-Range against session state.
    if content_range.start != record.bytes_received {
        return Err(AppError::RangeInvalid {
            current: record.bytes_received,
        });
    }

    // --- Size cap.  `checked_add` guards a pathological overflow
    // before the comparison; falling through to a silent wrap would
    // emit the wrong error code under very adversarial inputs.
    let projected = record
        .bytes_received
        .checked_add(body_length)
        .ok_or(AppError::SizeExceeded)?;
    if projected > max_bytes {
        return Err(AppError::SizeExceeded);
    }

    // --- Append via staging.  Returns the new TOTAL byte count after
    // the append (not the chunk length).
    let new_total = ctx
        .stateful_upload_staging
        .append(session_id, stream)
        .await
        .map_err(AppError::from)?;

    // Staging-port invariant: the returned total must equal
    // `bytes_received + body_length`.  A disagreement means either the
    // body stream short-read (client hung up mid-chunk — the client
    // lied about Content-Length) or an adapter bug.  Either way the
    // session state is now inconsistent with the client's declared
    // Content-Range and the safe response is `Invariant` → 500 via
    // the OCI `Internal` envelope.  A naive `Conflict` here would
    // invite clients to retry the same corrupt PATCH indefinitely.
    if new_total != record.bytes_received + body_length {
        tracing::warn!(
            session_id = %session_id,
            expected = record.bytes_received + body_length,
            actual = new_total,
            "staging append byte count disagreed with declared body length"
        );
        return Err(AppError::Domain(DomainError::Invariant(
            "staging append byte count disagreed with declared body length".into(),
        )));
    }

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
        .compare_and_swap(key, record.version, new_bytes, OCI_SESSION_TTL)
        .await
        .map_err(AppError::from)?;
    match cas_outcome {
        Some(_new_store_version) => Ok(new_record),
        None => {
            // Concurrent PATCH bumped the version underneath us.  Per
            // §2.8 the spec-compliant response is 400
            // `BLOB_UPLOAD_INVALID`.  Surface as Conflict; the HTTP
            // adapter translates.
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
// finalize (Item 3 — PUT)
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
///   content, same session) or the GC sweep (Item 15) reaps on TTL
///   expiry.
/// - **Between steps 1 and 2:** the ingest event + CAS blob are
///   committed but the session key lingers. The session TTL expires
///   on its own; the GC sweep (Item 15) is belt-and-braces. A client
///   retry on the same session UUID finds stale state but the artifact
///   is already durable so the retry is a no-op at the registry level.
/// - **Between steps 2 and 3:** the session is gone but the staging
///   file orphans. Item 15 sweeps staging by mtime age and reaps.
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
    trailing_body: Option<(Box<dyn AsyncRead + Send + Unpin>, Option<ContentRange>, u64)>,
    actor: ApiActor,
    repo_id: Uuid,
    name: &str,
    max_bytes: u64,
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
    trailing_body: Option<(Box<dyn AsyncRead + Send + Unpin>, Option<ContentRange>, u64)>,
    actor: ApiActor,
    repo_id: Uuid,
    name: &str,
    max_bytes: u64,
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
    // paths below can decrement the right per-`(repo, principal)` cap
    // counter.
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
        append_chunk(
            ctx,
            session_id,
            content_range,
            stream,
            body_length,
            max_bytes,
            repo_id,
        )
        .await?;
    }

    // --- Open staging. If the session exists but staging does not,
    // that's an invariant breach: `append_chunk` + `initiate` always
    // leave these two halves consistent. Item 15's GC sweep is the
    // only legitimate mechanism that could race a finalize and
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
            cleanup_session_and_staging(ctx, &key, session_id, repo_id, session_principal_id).await;
            Ok(outcome)
        }
        Err(AppError::Domain(DomainError::Conflict(msg))) => {
            // Digest mismatch — the CAS blob has already been rolled
            // back by `IngestUseCase::ingest`. Drop session + staging
            // so a retried PUT with a matching digest starts fresh,
            // then propagate `Conflict` for the handler to map to
            // 400 `DIGEST_INVALID`.
            cleanup_session_and_staging(ctx, &key, session_id, repo_id, session_principal_id).await;
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
            cleanup_session_and_staging(ctx, &key, session_id, repo_id, session_principal_id).await;
            Err(other)
        }
    }
}

/// Best-effort cleanup of the session row + staging file in the order
/// mandated by the finalize ordering rules above: ephemeral store
/// first (clients observing a stale session see `BLOB_UPLOAD_UNKNOWN`
/// immediately), staging second.
///
/// The cleanup is also where the per-`(repo, principal)`
/// outstanding-session counter is decremented. The decrement is
/// best-effort: an infrastructure failure on the counter write logs
/// `warn!` and the counter self-heals via TTL. Three release paths
/// funnel through here (finalize success, declared-hash Conflict, and
/// other infra errors); each one corresponds to exactly one prior
/// increment in `initiate`, so the counter stays balanced across the
/// realistic hot paths.
///
/// Each leg logs `warn!` on failure and continues so the caller can
/// still surface the ingest result (success or Conflict) to the
/// client. The GC sweep (Item 15) picks up anything left behind.
async fn cleanup_session_and_staging(
    ctx: &AppContext,
    key: &str,
    session_id: Uuid,
    repo_id: Uuid,
    principal_id: Uuid,
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
    // Release the per-`(repo, principal)` cap slot.
    decrement_session_count(ctx, repo_id, principal_id).await;
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

    /// Collision-forcing stub: always returns `Ok(false)` from
    /// `put_if_absent` to exercise the "duplicate key" branch in
    /// `initiate_inner` without depending on a real UUID collision.
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
            _key: &str,
            _value: Bytes,
            _ttl: Duration,
        ) -> BoxFuture<'_, DomainResult<bool>> {
            Box::pin(async { Ok(false) })
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

    /// Build an `AppContext` whose `ephemeral_durable` field is
    /// swapped for `replacement`. Local to this test module — the
    /// stable `hort-http-core::test_support` helpers don't (yet) expose
    /// a `with_ephemeral` because no production caller needs it.
    ///
    /// OCI upload-session machinery reads from `ephemeral_durable`
    /// (the `stateful_upload:` and `oci:session_count:` keyspaces are
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
        // `AppContext`'s data ports are `pub(crate)` (ADR 0008 §4) so
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

            let outcome = unwrap_created(initiate(&ctx, repo_id, api_actor(), TEST_HIGH_CAP).await);
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

                unwrap_created(initiate(&ctx, repo_id, api_actor(), TEST_HIGH_CAP).await)
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
                initiate(&ctx, Uuid::new_v4(), api_actor(), TEST_HIGH_CAP).await
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
                initiate(&ctx, Uuid::new_v4(), api_actor(), TEST_HIGH_CAP).await
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
                unwrap_created(initiate(&ctx, repo_id, api_actor(), TEST_HIGH_CAP).await)
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
            match initiate(ctx, repo_id, actor.clone(), cap).await.unwrap() {
                InitiateResult::Created(_) => created += 1,
                InitiateResult::CapExceeded => rejected += 1,
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
            let next = initiate(&ctx, repo_id, actor, cap).await.unwrap();
            assert!(
                matches!(next, InitiateResult::CapExceeded),
                "33rd request must surface as CapExceeded, got {next:?}",
            );
        });
    }

    #[test]
    fn initiate_emits_over_cap_metric_with_repo_label() {
        // The cap-rejection metric MUST carry only `repo` and
        // `result` labels — no `principal_id`, no `actor_id` (the
        // architect catalog forbids them as cardinality vectors).
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
                let _ = initiate(&ctx, repo_id, actor, cap).await.unwrap();
            })
        });
        let entries = snap.into_vec();
        let v = find_counter(
            &entries,
            "hort_oci_session_cap_rejections_total",
            &[("repo", "myrepo"), ("result", "over_cap")],
        )
        .expect(
            "hort_oci_session_cap_rejections_total{repo=myrepo,result=over_cap} absent on rejection",
        );
        assert!(matches!(v, DebugValue::Counter(n) if *n >= 1));
    }

    #[test]
    fn initiate_cap_metric_does_not_carry_principal_label() {
        // Hard guard: the architect catalog forbids `principal_id` /
        // `user_id` / `actor_id` as metric labels (cardinality bomb).
        // This test asserts the absence by scanning every
        // `hort_oci_session_cap_rejections_total` series's label keys.
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
                let _ = initiate(&ctx, repo_id, actor, 1).await.unwrap();
            })
        });
        let entries = snap.into_vec();
        for (ck, _, _, _) in &entries {
            if ck.kind() == MetricKind::Counter
                && ck.key().name() == "hort_oci_session_cap_rejections_total"
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
            let s1 = match initiate(&ctx, repo_id, actor.clone(), cap).await.unwrap() {
                InitiateResult::Created(o) => o.session_id,
                _ => panic!(),
            };
            let _s2 = match initiate(&ctx, repo_id, actor.clone(), cap).await.unwrap() {
                InitiateResult::Created(o) => o.session_id,
                _ => panic!(),
            };

            // Cap reached — next is rejected.
            assert!(matches!(
                initiate(&ctx, repo_id, actor.clone(), cap).await.unwrap(),
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
            )
            .await
            .expect("finalize must succeed and free a cap slot");

            // After freeing one slot, a fresh initiate must succeed.
            let next = initiate(&ctx, repo_id, actor, cap).await.unwrap();
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
            let s1 = match initiate(&ctx, repo_id, actor.clone(), cap).await.unwrap() {
                InitiateResult::Created(o) => o.session_id,
                _ => panic!(),
            };
            // Cap is full — next initiate is rejected.
            assert!(matches!(
                initiate(&ctx, repo_id, actor.clone(), cap).await.unwrap(),
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
            )
            .await
            .expect_err("digest mismatch must surface as Conflict");
            assert!(matches!(err, AppError::Domain(DomainError::Conflict(_))));

            // After the Conflict-path cleanup, the cap slot is free
            // again — the next initiate must succeed.
            let next = initiate(&ctx, repo_id, actor, cap).await.unwrap();
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
                initiate(&ctx, repo_id, actor_a, cap).await.unwrap(),
                InitiateResult::CapExceeded
            ));

            // B is unaffected.
            let result = initiate(&ctx, repo_id, actor_b, cap).await.unwrap();
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
                initiate(&ctx, repo_x_id, actor.clone(), cap).await.unwrap(),
                InitiateResult::CapExceeded
            ));

            // Same principal in repo Y is unaffected.
            let result = initiate(&ctx, repo_y_id, actor, cap).await.unwrap();
            assert!(
                matches!(result, InitiateResult::Created(_)),
                "principal at cap in repo X MUST NOT block them in repo Y"
            );
        });
    }

    #[test]
    fn extra_decrement_clamps_at_zero_without_panicking() {
        // Underflow guard: a release path fires without a matching
        // create. The counter must clamp at 0 — never underflow into
        // a high `u64::MAX`.
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, _mocks) = build_mock_ctx(handle);
            let repo_id = Uuid::new_v4();
            let principal_id = Uuid::new_v4();

            // No prior increments — counter is absent.
            decrement_session_count(&ctx, repo_id, principal_id).await;

            // Increment to 1, then decrement twice. The second is
            // the underflow case. After it, the counter must read as
            // "absent" (or 0) — never as `u64::MAX`.
            let key = session_count_key(repo_id, principal_id);
            let _ = ctx
                .ephemeral_durable
                .try_increment_counter(&key, 32, OCI_SESSION_TTL)
                .await
                .unwrap();
            decrement_session_count(&ctx, repo_id, principal_id).await; // 0 → key dropped
            decrement_session_count(&ctx, repo_id, principal_id).await; // attempted underflow

            // The counter is absent — `get` returns None, NOT a
            // u64::MAX representation.
            assert!(ctx.ephemeral_durable.get(&key).await.unwrap().is_none());

            // Subsequent cap checks see the correct state — the cap
            // is fully available.
            let actor = principal_actor(principal_id);
            // Need a repo for the metric label; mock the bare
            // counter-key path is enough since `initiate` only reads
            // the repo via the metric helper.
            // The cap of 1 means the first initiate must succeed.
            let result = initiate(&ctx, repo_id, actor, 1).await.unwrap();
            assert!(
                matches!(result, InitiateResult::Created(_)),
                "after underflow clamp, the cap state is healthy: \
                 first initiate must succeed",
            );
        });
    }

    #[test]
    fn concurrent_initiates_race_free_at_cap_boundary() {
        // 33 concurrent attempts against a cap of 32 yield exactly
        // 32 successes and 1 rejection — never 33, never fewer than
        // 32. The atomic `try_increment_counter` primitive in the
        // memory adapter holds the read-check-write window under a
        // per-key mutex; the default trait impl's CAS-loop also
        // converges, but the memory adapter's override is what
        // production sees on `Memory` deployments and what the
        // contract test below pins.
        //
        // Multi-thread runtime so the spawned tasks genuinely run in
        // parallel and can race on the per-key mutex.
        let outcome = tokio::runtime::Builder::new_multi_thread()
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
                let cap: u32 = 32;
                let mut handles = Vec::with_capacity((cap + 1) as usize);
                for _ in 0..(cap + 1) {
                    let ctx_ref = ctx.clone();
                    let actor_clone = actor.clone();
                    handles.push(tokio::spawn(async move {
                        initiate(&ctx_ref, repo_id, actor_clone, cap).await
                    }));
                }
                let mut created = 0usize;
                let mut rejected = 0usize;
                for h in handles {
                    match h.await.unwrap().unwrap() {
                        InitiateResult::Created(_) => created += 1,
                        InitiateResult::CapExceeded => rejected += 1,
                    }
                }
                (created, rejected)
            });
        assert_eq!(
            outcome,
            (32, 1),
            "33 concurrent initiates against cap 32 must yield exactly 32 successes + 1 rejection",
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
                Some((cursor_of(&trailing), Some(range), trailing.len() as u64)),
                api_actor(),
                repo_id,
                "library/nginx",
                10 * 1024 * 1024,
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
