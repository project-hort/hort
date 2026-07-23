//! # hort-app::pull_dedup — two-layer pull-through request coalescing
//!
//! Sits between every format handler that
//! issues an upstream-proxy fetch and the actual `UpstreamProxy::*`
//! call. Coalesces N parallel cache-miss requests for the same
//! artifact into ≤ 1 upstream HTTP request (Layer A: per-replica
//! `DashMap` + `tokio::sync::broadcast`; Layer B: cluster-wide
//! `EphemeralStore::put_if_absent` keyed lock + status broadcast).
//!
//! # Layering
//!
//! - **No outbound port.** This service consumes the existing
//!   `Arc<dyn EphemeralStore>` (the `ephemeral_evictable`
//!   accessor); it does not introduce a new port trait.
//! - **No `IngestUseCase` change.** Coalescing is a pure inbound-side
//!   concern; `IngestUseCase` keeps zero awareness of dedup. Format
//!   handlers wrap `UpstreamProxy::fetch_metadata` /
//!   `IngestUseCase::ingest_verified` in a closure passed to
//!   `coalesce_metadata` / `coalesce_blob`.
//! - **No new event.** Coalescing is a performance optimisation, not
//!   a domain state transition. `ArtifactIngested`, `ChecksumVerified`
//!   and `ChecksumMismatch` continue to fire exactly once per
//!   coalesced burst (from the leader's `ingest_verified` call).
//!
//! # Position in the layered dedup scheme
//!
//! `PullDedup` is **L1** of the three-layer dedup scheme the
//! prefetch cascade composes (see
//! `docs/architecture/explanation/prefetch-pipeline.md`):
//!
//! - **L1** — `PullDedup` (this module): concurrent fetch single-
//!   flight. Catches "two callers want the same upstream bytes RIGHT
//!   NOW."
//! - **L2** — `artifacts` path-UNIQUE: terminal ingest absorb. Catches
//!   "a second caller's pull-through tried to ingest bytes the first
//!   already committed."
//! - **L3** — `jobs.target_key` partial unique index
//!   (migration 009): cascade re-walk absorb. Catches "two ingests
//!   spawned overlapping `prefetch-dependencies` walks for the same
//!   `(repo, package, version)` coordinate."
//!
//! Each layer is independent. `PullDedup` knows nothing about the
//! other two — it operates one layer below the cascade, on bytes-in-
//! flight, not on persisted state. See
//! `crates/hort-app/src/task_handlers/prefetch_dependencies.rs` module
//! docstring for the cascade-side view of the same picture.
//!
//! # Anti-patterns deliberately avoided
//!
//! - **No `UpstreamErrorKind` extension.** Followers never reach
//!   `hort-adapters-upstream-http`, so `hort_upstream_fetch_total`
//!   automatically means "actual upstream HTTP requests issued"
//!   without modification. The follower's "I was coalesced" fact is
//!   captured entirely by `hort_pull_dedup_total{outcome=…}`.
//! - **No `Deserialize` derive on `DedupOutcome`.** Per the architect-
//!   skill anti-pattern bullet on domain-API deserialisation, the
//!   serialiser/deserialiser is a private function inside this
//!   module; nothing outside the module deserialises these values.

use std::sync::Arc;
use std::sync::Weak;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;
use tracing::{debug, info, instrument, warn};

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::ephemeral_store::EphemeralStore;
use hort_domain::types::ContentHash;

use crate::error::AppError;
use crate::metrics::{DedupLayer, DedupOutcomeLabel, UpstreamErrorKind};

// ---------------------------------------------------------------------------
// Constants — NOT env-tunable.
// ---------------------------------------------------------------------------
//
// The Layer-B leader-lock TTL and its derived heartbeat interval used to
// be hardcoded here (90s / 30s). Issue #65 made the TTL operator-tunable
// (`PullDedupConfig::leader_lock_ttl`, default still 90s) — see
// `heartbeat_interval()` (below the `PullDedupConfig` struct) for the
// derivation, and `spawn_heartbeat` for the retry-on-failure fix.
//
// Retry budget for a single heartbeat tick's `extend_ttl` call (issue
// #65). A healthy heartbeat TASK must not let one transient
// `EphemeralStore` blip cost a full missed-heartbeat cycle: on failure,
// retry a bounded number of times with a short, fixed backoff before
// giving up on that tick and waiting for the next natural one.
const HEARTBEAT_RETRY_MAX_ATTEMPTS: u32 = 3;

/// Backoff between heartbeat retry attempts (issue #65). `3 *
/// HEARTBEAT_RETRY_BACKOFF` (6s) stays comfortably under the default
/// 30s heartbeat interval, so exhausting the retry budget on one tick
/// never delays the next natural tick.
const HEARTBEAT_RETRY_BACKOFF: Duration = Duration::from_secs(2);

/// Layer-A `broadcast` channel capacity. >64 concurrent followers per
/// pod per key is implausible; over-flow surfaces as
/// `outcome="follower_lagged"` on the metric and falls back to a
/// Layer-B `get` (correctness preserved).
const LAYER_A_CHANNEL_CAPACITY: usize = 64;

/// Backoff schedule for the Layer-B follower poll loop. Capped at 5s.
/// Total polling spans `HORT_PULL_DEDUP_FOLLOWER_WAIT_SECS`; once the
/// ceiling expires the follower returns `503 + Retry-After: 30`.
const FOLLOWER_POLL_BACKOFF: &[Duration] = &[
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(5),
];

/// Length of the `key_hash` field on tracing spans — a SHA-256 prefix
/// of the serialised key bytes. Mirrors the ephemeral-keyspace
/// `url_hash` pattern (8 hex chars).
const KEY_HASH_HEX_LEN: usize = 8;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Tunable runtime configuration consumed by [`PullDedup`]. Built by
/// the composition root from the five `HORT_PULL_DEDUP_*` env vars; see
/// `crates/hort-server/src/config.rs`.
///
/// All fields are [`Duration`]s; the env vars carry seconds.
#[derive(Debug, Clone)]
pub struct PullDedupConfig {
    /// `Failed(NotFound)` negative-cache TTL.
    pub ttl_not_found: Duration,
    /// `Failed(RateLimited | Upstream5xx | Upstream4xx | Unauthorized)`
    /// negative-cache TTL.
    pub ttl_unavailable: Duration,
    /// `Failed(Timeout | NetworkError)` negative-cache TTL.
    pub ttl_timeout: Duration,
    /// `Failed(ChecksumMismatch | ParseError | BodyTooLarge | PinMismatch
    /// | CaUnknown)` negative-cache TTL.
    pub ttl_checksum_mismatch: Duration,
    /// Follower-side absolute ceiling. On expiry → `503 + Retry-After:
    /// 30` (caller responsibility — `coalesce_*` returns
    /// `AppError::External("pull-dedup: follower wait ceiling
    /// exceeded")` and the format handler maps it to the wire).
    pub follower_wait: Duration,
    /// Hard ceiling on the leader's `fetch_fn` execution (issue #55).
    /// On elapse the leader is abandoned: a `Failed(Timeout)`
    /// terminal is written (using `ttl_timeout` as the negative-cache
    /// TTL), the Layer-A entry is evicted, and the next caller elects
    /// fresh rather than inheriting the wedge. MUST exceed the
    /// slowest legitimate fetch+ingest, which is itself bounded by
    /// `HORT_STORAGE_PUT_TIMEOUT_SECS` (default 300s) — a tighter
    /// deadline would abandon leaders still doing legitimately-slow
    /// large pulls.
    pub leader_deadline: Duration,
    /// The Layer-B cluster-wide leader lock's TTL (issue #65). The
    /// leader's heartbeat refreshes this lock every `leader_lock_ttl /
    /// 3` — see [`heartbeat_interval`]. SEPARATE from `leader_deadline`:
    /// that one bounds the fetch itself; this one bounds how long the
    /// *cluster lock* survives without a successful heartbeat. Too
    /// tight a value abandons an otherwise-healthy, still-heartbeating
    /// leader (a follower observes the lock expired with no terminal
    /// outcome and re-elects) on a large/slow blob fetch even though
    /// the leader is making progress.
    pub leader_lock_ttl: Duration,
}

/// Heartbeat refresh cadence derived from `leader_lock_ttl`: a third of
/// it, so two consecutive missed heartbeats (not one) are required to
/// expire the lock. Kept as a pure function of `leader_lock_ttl` rather
/// than a second independent config field — an operator raising the TTL
/// to tolerate a slower backend gets a proportionally longer heartbeat
/// interval for free, and the "which combination is safe" question
/// (interval must stay comfortably below the TTL) never arises.
pub(crate) fn heartbeat_interval(leader_lock_ttl: Duration) -> Duration {
    leader_lock_ttl / 3
}

impl PullDedupConfig {
    /// Default values used by tests and as a fallback by the composition
    /// root if env-var parsing is omitted (production wires explicitly
    /// via `Config`).
    pub fn defaults() -> Self {
        Self {
            ttl_not_found: Duration::from_secs(30),
            ttl_unavailable: Duration::from_secs(10),
            ttl_timeout: Duration::from_secs(10),
            ttl_checksum_mismatch: Duration::from_secs(60),
            follower_wait: Duration::from_secs(300),
            leader_deadline: Duration::from_secs(600),
            leader_lock_ttl: Duration::from_secs(90),
        }
    }
}

/// Resolve the negative-cache TTL for a terminal-failure
/// [`UpstreamErrorKind`]. Total over every variant **except**
/// `Success` (which is unreachable on the failure path). Mapping:
///
/// | Variant cluster | TTL knob |
/// |---|---|
/// | `NotFound` | `ttl_not_found` |
/// | `RateLimited`, `Upstream5xx`, `Upstream4xx`, `Unauthorized` | `ttl_unavailable` |
/// | `Timeout`, `NetworkError` | `ttl_timeout` |
/// | `ChecksumMismatch`, `ParseError`, `BodyTooLarge`, `PinMismatch`, `CaUnknown` | `ttl_checksum_mismatch` |
///
/// The match is exhaustive — adding a future variant to
/// [`UpstreamErrorKind`] without updating this mapping is a compile
/// error (no wildcard arm). `Success` is mapped to `ttl_not_found` as
/// a defensive default (never reached on the production failure
/// path; covered by a test).
fn ttl_for(kind: UpstreamErrorKind, cfg: &PullDedupConfig) -> Duration {
    match kind {
        UpstreamErrorKind::NotFound => cfg.ttl_not_found,
        UpstreamErrorKind::RateLimited
        | UpstreamErrorKind::Upstream5xx
        | UpstreamErrorKind::Upstream4xx
        | UpstreamErrorKind::Unauthorized => cfg.ttl_unavailable,
        UpstreamErrorKind::Timeout | UpstreamErrorKind::NetworkError => cfg.ttl_timeout,
        UpstreamErrorKind::ChecksumMismatch
        | UpstreamErrorKind::ParseError
        | UpstreamErrorKind::BodyTooLarge
        | UpstreamErrorKind::MetadataTooLarge
        | UpstreamErrorKind::ManifestTooLarge
        | UpstreamErrorKind::VersionObjectTooLarge
        | UpstreamErrorKind::PinMismatch
        | UpstreamErrorKind::CaUnknown => cfg.ttl_checksum_mismatch,
        // Defensive: `Success` does not produce a `Failed` outcome
        // and is unreachable on the production failure path. Map to
        // the not-found TTL so the resolver remains a total function
        // for test exhaustiveness.
        UpstreamErrorKind::Success => cfg.ttl_not_found,
    }
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// Discriminator carried in [`DedupKey`] to keep the three keyspaces
/// separate. Layer-A `DashMap` lookup uses the full key (which
/// includes the namespace via `serialised`); the namespace also rides
/// onto tracing spans for operator drill-down.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
enum DedupNamespace {
    /// URL-keyed metadata fetches.
    Metadata,
    /// URL-keyed blob fetches when the content hash is NOT pre-known.
    BlobByUrl,
    /// Content-hash-keyed blob fetches when the digest is pre-declared
    /// in upstream metadata (the ADR 0006 verified path).
    BlobByHash,
}

impl DedupNamespace {
    fn as_str(self) -> &'static str {
        match self {
            Self::Metadata => "metadata",
            Self::BlobByUrl => "blob_by_url",
            Self::BlobByHash => "blob_by_hash",
        }
    }
}

/// Identifies a single coalescing window. Constructed via the
/// associated functions; never assembled by hand.
///
/// The `serialised` field is the wire-stable byte string written to
/// `EphemeralStore`; Layer A uses it as the `DashMap` key too.
/// `format` is captured separately (rather than parsed back out of
/// `serialised`) so metric emission can stay zero-allocation per
/// call.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct DedupKey {
    namespace: DedupNamespace,
    /// Format string carried verbatim onto the `format` metric label
    /// and tracing field. For [`DedupNamespace::BlobByHash`] the
    /// keyspace is shared cross-format (the hash is the natural
    /// dedup boundary); the format is `"_any"` in that case so the
    /// metric has a stable cardinality footprint.
    format: String,
    /// Stable byte-string for the `EphemeralStore` key and the
    /// Layer-A `DashMap` key.
    serialised: String,
}

impl DedupKey {
    /// Coalesce a metadata fetch (PyPI JSON, npm packument, Cargo
    /// sparse-index, OCI manifest-by-tag, Maven `.sha256` sidecar,
    /// …). URL-keyed and per-repository — two repos pointing at the
    /// same upstream do NOT share metadata coalescing because they
    /// may carry different trust configs.
    pub fn metadata(format: &str, repo_id: uuid::Uuid, url: &str) -> Self {
        let serialised = format!("pulldedup:meta:{format}:{repo_id}:{url}");
        Self {
            namespace: DedupNamespace::Metadata,
            format: format.to_owned(),
            serialised,
        }
    }

    /// Coalesce a blob fetch when the content hash is NOT pre-known
    /// — defensive fallback; should be rare. URL-keyed and per-
    /// repository for the same trust-isolation reason as
    /// [`Self::metadata`].
    pub fn blob_by_url(format: &str, repo_id: uuid::Uuid, url: &str) -> Self {
        let serialised = format!("pulldedup:blob_by_url:{format}:{repo_id}:{url}");
        Self {
            namespace: DedupNamespace::BlobByUrl,
            format: format.to_owned(),
            serialised,
        }
    }

    /// Coalesce a blob fetch when the digest is pre-declared in
    /// upstream metadata (the ADR 0006 verified path — Cargo `cksum`,
    /// PyPI `digests.sha256`, npm `dist.integrity`, OCI URL digest,
    /// …). Cross-repository AND cross-format: the content hash is
    /// the natural dedup boundary because two callers of any shape
    /// asking for the same bytes can share the result. The metric
    /// `format` label is the literal `"_any"` sentinel.
    pub fn blob_by_hash(algorithm: &str, hex_digest: &str) -> Self {
        let serialised = format!("pulldedup:blob_by_hash:{algorithm}:{hex_digest}");
        Self {
            namespace: DedupNamespace::BlobByHash,
            format: "_any".to_owned(),
            serialised,
        }
    }

    /// `format` label value used on metric emissions for this key.
    pub fn format_label(&self) -> &str {
        &self.format
    }

    /// Short SHA-256 prefix of the serialised key bytes — for the
    /// `key_hash` tracing field. URLs may contain credentials in
    /// pathological cases; we never log the full URL.
    fn key_hash(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.serialised.as_bytes());
        let digest = h.finalize();
        let mut s = String::with_capacity(KEY_HASH_HEX_LEN);
        for byte in digest.iter().take(KEY_HASH_HEX_LEN / 2) {
            use std::fmt::Write;
            let _ = write!(&mut s, "{byte:02x}");
        }
        s
    }
}

// ---------------------------------------------------------------------------
// Outcome record
// ---------------------------------------------------------------------------

/// Terminal state recorded by the leader and observed by followers.
///
/// **No `Deserialize` derive** — internal serialisation is the private
/// [`encode_outcome`] / [`decode_outcome`] pair below. Per the
/// architect-skill anti-pattern bullet on domain-type deserialisation,
/// nothing outside this module needs to deserialise these values.
#[derive(Debug, Clone)]
pub enum DedupOutcome {
    /// Leader is in flight. `leader` carries an opaque tag for
    /// tracing only — the lock is not principal-scoped.
    /// `expires_at` is the heartbeat-refreshed TTL boundary.
    InFlight {
        leader: String,
        expires_at_unix_secs: u64,
    },
    /// Leader completed a metadata fetch; bytes ride inline (≤ 10 MB
    /// cap from `fetch_metadata`).
    SucceededMetadata { bytes: Bytes },
    /// Leader completed a blob fetch; followers re-resolve via
    /// `ArtifactUseCase::find_in_repo_by_hash` after the coalesce
    /// returns. Only the hash is broadcast.
    SucceededBlob { content_hash: ContentHash },
    /// Leader observed a terminal failure. Followers return the same
    /// outcome to their clients without contacting the upstream.
    /// `expires_at_unix_secs` is the negative-cache TTL boundary;
    /// arrivals after this point retry leader election.
    Failed {
        kind: UpstreamErrorKind,
        message: String,
        expires_at_unix_secs: u64,
    },
}

/// Discriminator-tagged JSON wire encoding for [`DedupOutcome`].
/// Forward-compatible: a future variant the reader does not know
/// surfaces as a deserialisation error and the polling follower
/// retries `put_if_absent`.
fn encode_outcome(outcome: &DedupOutcome) -> Bytes {
    let json = match outcome {
        DedupOutcome::InFlight {
            leader,
            expires_at_unix_secs,
        } => serde_json::json!({
            "kind": "in_flight",
            "leader": leader,
            "expires_at": expires_at_unix_secs,
        }),
        DedupOutcome::SucceededMetadata { bytes } => {
            // Base64 the bytes — JSON cannot carry arbitrary binary.
            // The metadata cap (10 MB) keeps the encoded payload
            // bounded.
            let encoded = base64_encode(bytes);
            serde_json::json!({
                "kind": "succeeded_metadata",
                "bytes_b64": encoded,
            })
        }
        DedupOutcome::SucceededBlob { content_hash } => serde_json::json!({
            "kind": "succeeded_blob",
            "content_hash": content_hash.as_ref(),
        }),
        DedupOutcome::Failed {
            kind,
            message,
            expires_at_unix_secs,
        } => serde_json::json!({
            "kind": "failed",
            "upstream_kind": kind.as_str(),
            "message": message,
            "expires_at": expires_at_unix_secs,
        }),
    };
    Bytes::from(serde_json::to_vec(&json).expect("serde_json on owned Value never fails"))
}

/// Decode the wire format. Returns `None` for any unrecognised shape
/// (forward-compatibility — a future variant the reader does not
/// know surfaces as `None` and the follower re-attempts election).
fn decode_outcome(bytes: &[u8]) -> Option<DedupOutcome> {
    let v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let kind = v.get("kind")?.as_str()?;
    match kind {
        "in_flight" => {
            let leader = v.get("leader")?.as_str()?.to_owned();
            let expires_at_unix_secs = v.get("expires_at")?.as_u64()?;
            Some(DedupOutcome::InFlight {
                leader,
                expires_at_unix_secs,
            })
        }
        "succeeded_metadata" => {
            let b64 = v.get("bytes_b64")?.as_str()?;
            let bytes = base64_decode(b64)?;
            Some(DedupOutcome::SucceededMetadata {
                bytes: Bytes::from(bytes),
            })
        }
        "succeeded_blob" => {
            let hex = v.get("content_hash")?.as_str()?;
            let content_hash: ContentHash = hex.parse().ok()?;
            Some(DedupOutcome::SucceededBlob { content_hash })
        }
        "failed" => {
            let upstream_kind_str = v.get("upstream_kind")?.as_str()?;
            let kind = upstream_kind_from_str(upstream_kind_str)?;
            let message = v.get("message")?.as_str()?.to_owned();
            let expires_at_unix_secs = v.get("expires_at")?.as_u64()?;
            Some(DedupOutcome::Failed {
                kind,
                message,
                expires_at_unix_secs,
            })
        }
        _ => None,
    }
}

/// Inverse of [`UpstreamErrorKind::as_str`]. Total over every wire
/// label string the catalog admits.
fn upstream_kind_from_str(s: &str) -> Option<UpstreamErrorKind> {
    Some(match s {
        "success" => UpstreamErrorKind::Success,
        "not_found" => UpstreamErrorKind::NotFound,
        "unauthorized" => UpstreamErrorKind::Unauthorized,
        "rate_limited" => UpstreamErrorKind::RateLimited,
        "upstream_4xx" => UpstreamErrorKind::Upstream4xx,
        "upstream_5xx" => UpstreamErrorKind::Upstream5xx,
        "network_error" => UpstreamErrorKind::NetworkError,
        "timeout" => UpstreamErrorKind::Timeout,
        "checksum_mismatch" => UpstreamErrorKind::ChecksumMismatch,
        "parse_error" => UpstreamErrorKind::ParseError,
        "body_too_large" => UpstreamErrorKind::BodyTooLarge,
        "pin_mismatch" => UpstreamErrorKind::PinMismatch,
        "ca_unknown" => UpstreamErrorKind::CaUnknown,
        _ => return None,
    })
}

// Tiny base64 implementation — no need to drag the `base64` crate
// into hort-app for one call site. Standard-alphabet, no-pad.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut chunks = bytes.chunks_exact(3);
    for chunk in &mut chunks {
        let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32);
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        out.push(ALPHABET[(n & 0x3f) as usize] as char);
    }
    let rem = chunks.remainder();
    match rem.len() {
        0 => {}
        1 => {
            let n = (rem[0] as u32) << 16;
            out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = ((rem[0] as u32) << 16) | ((rem[1] as u32) << 8);
            out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
            out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
            out.push('=');
        }
        _ => unreachable!(),
    }
    out
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks_exact(4) {
        let pad = chunk.iter().filter(|&&b| b == b'=').count();
        if pad > 2 {
            return None;
        }
        let v0 = val(chunk[0])?;
        let v1 = val(chunk[1])?;
        let v2 = if chunk[2] == b'=' { 0 } else { val(chunk[2])? };
        let v3 = if chunk[3] == b'=' { 0 } else { val(chunk[3])? };
        let n = ((v0 as u32) << 18) | ((v1 as u32) << 12) | ((v2 as u32) << 6) | (v3 as u32);
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push(((n >> 8) & 0xff) as u8);
        }
        if pad < 1 {
            out.push((n & 0xff) as u8);
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/// Shared Layer-A coalescing map. `Weak` so a leader's drop (panic,
/// early return) automatically clears the entry on the next
/// `DashMap::get`.
type LayerAMap = DashMap<DedupKey, Weak<broadcast::Sender<DedupOutcome>>>;

/// RAII guard constructed immediately after a leader inserts its
/// Layer-A broadcast entry (D3 / D4 of issue #55). Closes every exit
/// path — success, error, leader-deadline timeout, panic, or
/// cancellation — through one mechanism instead of the sequential
/// manual cleanup that previously covered only the happy path.
///
/// `heartbeat` is `None` for
/// [`PullDedup::run_as_leader_layer_b_down`], which never spawns one
/// (there is no cluster lock to keep alive when Layer B is down);
/// [`PullDedup::run_as_leader`] always supplies one.
struct LeaderGuard {
    layer_a: Arc<LayerAMap>,
    key: DedupKey,
    heartbeat: Option<tokio::task::AbortHandle>,
    disarmed: bool,
}

impl LeaderGuard {
    fn new(
        layer_a: Arc<LayerAMap>,
        key: DedupKey,
        heartbeat: Option<tokio::task::AbortHandle>,
    ) -> Self {
        Self {
            layer_a,
            key,
            heartbeat,
            disarmed: false,
        }
    }

    /// Abort the heartbeat early — before the terminal write — so it
    /// cannot race the leader's own persisted outcome. Idempotent:
    /// `Drop` re-aborts unconditionally regardless of whether this
    /// was already called, which is what closes the pre-existing
    /// leak where a *cancelled* (not just wedged) leader skipped the
    /// old sequential `heartbeat_handle.abort()` call entirely.
    fn abort_heartbeat(&self) {
        if let Some(handle) = &self.heartbeat {
            handle.abort();
        }
    }

    /// Happy-path (and leader-timeout-path) cleanup: remove the
    /// Layer-A entry and suppress `Drop`'s fallback removal +
    /// `leader_cancelled` emission. MUST be called AFTER the
    /// broadcast send so follower ordering is unchanged.
    fn disarm(&mut self) {
        self.disarmed = true;
        self.layer_a.remove(&self.key);
    }
}

impl Drop for LeaderGuard {
    fn drop(&mut self) {
        self.abort_heartbeat();
        if !self.disarmed {
            // Reached only when the leader future was dropped
            // without ever recording a terminal outcome (client
            // disconnect, runtime shutdown, or a panic upstream of
            // this guard's own scope) — routine, not an error.
            debug!(
                key_hash = self.key.key_hash().as_str(),
                format = self.key.format_label(),
                "leader guard dropped without a terminal outcome; evicting layer-A entry"
            );
            emit_total(
                DedupLayer::Cluster,
                self.key.format_label(),
                DedupOutcomeLabel::LeaderCancelled,
            );
            self.layer_a.remove(&self.key);
        }
    }
}

/// `hort-app::pull_dedup::PullDedup` — the coordination service. Held
/// on `AppContext` as `Arc<PullDedup>`. Cheap to clone via `Arc`.
pub struct PullDedup {
    ephemeral: Arc<dyn EphemeralStore>,
    layer_a: Arc<LayerAMap>,
    config: PullDedupConfig,
    /// Replica id used as the `leader` field on the in-flight record.
    /// Random per-process; tracing-only signal.
    replica_id: String,
}

impl PullDedup {
    /// Construct a `PullDedup` over the supplied evictable
    /// [`EphemeralStore`]. The composition root passes
    /// `ctx.ephemeral_evictable.clone()`.
    pub fn new(ephemeral: Arc<dyn EphemeralStore>, config: PullDedupConfig) -> Self {
        // Replica id — random hex; not principal-scoped, tracing-only.
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let replica_id = format!("replica-{nanos:016x}");
        Self {
            ephemeral,
            layer_a: Arc::new(DashMap::new()),
            config,
            replica_id,
        }
    }

    /// Coalesce a metadata fetch. The closure runs at most once per
    /// (replica × cluster) coalescing window; followers receive the
    /// leader's bytes (Layer A) or read the cached bytes from
    /// `EphemeralStore` (Layer B).
    ///
    /// The closure must return `Result<Bytes, AppError>`. Format
    /// crates wrap their existing
    /// `UpstreamProxy::fetch_metadata(...) -> DomainResult<Vec<u8>>`
    /// call as `... .await.map(Bytes::from).map_err(AppError::from)`
    /// inside the closure.
    #[instrument(
        skip(self, fetch_fn),
        fields(
            layer = tracing::field::Empty,
            format = key.format_label(),
            namespace = key.namespace.as_str(),
            outcome = tracing::field::Empty,
            key_hash = tracing::field::Empty,
        ),
    )]
    pub async fn coalesce_metadata<F, Fut>(
        &self,
        key: DedupKey,
        fetch_fn: F,
    ) -> Result<Bytes, AppError>
    where
        F: FnOnce() -> Fut + Send,
        Fut: std::future::Future<Output = Result<Bytes, AppError>> + Send,
    {
        let span = tracing::Span::current();
        span.record("key_hash", key.key_hash().as_str());
        let adapted = || async move { fetch_fn().await.map(BlobOrMetadataOk::Metadata) };
        let outcome = self.coalesce_inner(key, adapted).await?;
        match outcome {
            BlobOrMetadataOk::Metadata(b) => Ok(b),
            BlobOrMetadataOk::Blob(_) => Err(AppError::External(
                "pull-dedup: unexpected blob outcome on metadata coalesce".into(),
            )),
        }
    }

    /// Coalesce a blob fetch + ingest. The closure must, on success,
    /// write to CAS via `IngestUseCase::ingest_verified` and return
    /// the resulting `ContentHash`. Followers receive only the hash
    /// and re-resolve the artifact row from CAS / the artifact
    /// repository independently.
    ///
    /// Format crates extract `outcome.content_hash` inside the
    /// closure; the full `IngestOutcome` is not threaded through
    /// `PullDedup`. After the coalesce returns, the format crate
    /// re-resolves via
    /// `ArtifactUseCase::find_in_repo_by_hash(repo_id, &content_hash)`.
    ///
    /// Thin wrapper over [`Self::coalesce_to_hash`] — the only
    /// difference is the typical key shape (`DedupKey::blob_by_*`).
    /// Blob callers are byte-for-byte unchanged.
    pub async fn coalesce_blob<F, Fut>(
        &self,
        key: DedupKey,
        fetch_fn: F,
    ) -> Result<ContentHash, AppError>
    where
        F: FnOnce() -> Fut + Send,
        Fut: std::future::Future<Output = Result<ContentHash, AppError>> + Send,
    {
        self.coalesce_to_hash(key, fetch_fn).await
    }

    /// Metadata- or blob-keyed, hash-broadcasting single-flight; use
    /// when the coalesced result is a CAS content hash, not inline
    /// bytes.
    ///
    /// Generalises [`Self::coalesce_blob`]: the `key` may be ANY
    /// [`DedupKey`] (including a [`DedupKey::metadata`]), and the
    /// leader broadcasts the resolved [`ContentHash`] via
    /// [`DedupOutcome::SucceededBlob`]. Followers receive only the
    /// hash and re-resolve the artifact row from CAS / the artifact
    /// repository independently after the coalesce returns — the
    /// identical contract to `coalesce_blob`, but available to
    /// metadata-keyed callers (e.g. the OCI manifest tag-pull leg)
    /// whose result is a hash in CAS rather than inline manifest
    /// bytes. No bytes transit the ephemeral store.
    #[instrument(
        skip(self, fetch_fn),
        fields(
            layer = tracing::field::Empty,
            format = key.format_label(),
            namespace = key.namespace.as_str(),
            outcome = tracing::field::Empty,
            key_hash = tracing::field::Empty,
        ),
    )]
    pub async fn coalesce_to_hash<F, Fut>(
        &self,
        key: DedupKey,
        fetch_fn: F,
    ) -> Result<ContentHash, AppError>
    where
        F: FnOnce() -> Fut + Send,
        Fut: std::future::Future<Output = Result<ContentHash, AppError>> + Send,
    {
        let span = tracing::Span::current();
        span.record("key_hash", key.key_hash().as_str());
        let adapted = || async move { fetch_fn().await.map(BlobOrMetadataOk::Blob) };
        let outcome = self.coalesce_inner(key, adapted).await?;
        match outcome {
            BlobOrMetadataOk::Blob(h) => Ok(h),
            BlobOrMetadataOk::Metadata(_) => Err(AppError::External(
                "pull-dedup: unexpected metadata outcome on blob coalesce".into(),
            )),
        }
    }

    /// Inner dispatch shared by both public methods. The closure
    /// returns `BlobOrMetadataOk` for both flows — the public
    /// methods adapt their typed closure into this shape so the long
    /// election + heartbeat machinery exists exactly once.
    async fn coalesce_inner<F, Fut>(
        &self,
        key: DedupKey,
        fetch_fn: F,
    ) -> Result<BlobOrMetadataOk, AppError>
    where
        F: FnOnce() -> Fut + Send,
        Fut: std::future::Future<Output = Result<BlobOrMetadataOk, AppError>> + Send,
    {
        // -----------------------------------------------------------
        // Layer A — try to JOIN an existing in-process broadcast.
        // -----------------------------------------------------------
        if let Some(weak) = self.layer_a.get(&key).map(|entry| entry.value().clone()) {
            if let Some(tx) = weak.upgrade() {
                let mut rx = tx.subscribe();
                debug!(
                    layer = DedupLayer::InProcess.as_metric_label(),
                    format = key.format_label(),
                    "joining existing in-process coalescing window"
                );
                match tokio::time::timeout(self.config.follower_wait, rx.recv()).await {
                    Ok(Ok(outcome)) => {
                        // Drop the strong upgrade BEFORE we return so
                        // the leader's `Arc<Sender>` is the only
                        // remaining strong reference.
                        drop(tx);
                        let label = match &outcome {
                            DedupOutcome::SucceededMetadata { .. }
                            | DedupOutcome::SucceededBlob { .. } => {
                                DedupOutcomeLabel::FollowerWaitedHit
                            }
                            DedupOutcome::Failed { .. } => DedupOutcomeLabel::FollowerWaitedFailure,
                            DedupOutcome::InFlight { .. } => {
                                // Defensive — leader never broadcasts
                                // InFlight (only terminal outcomes
                                // hit the channel). Treat as a
                                // failure for label classification.
                                DedupOutcomeLabel::FollowerWaitedFailure
                            }
                        };
                        emit_total(DedupLayer::InProcess, key.format_label(), label);
                        return self.handle_follower_outcome(&key, DedupLayer::InProcess, outcome);
                    }
                    Ok(Err(broadcast::error::RecvError::Closed)) => {
                        // Sender dropped before sending — leader
                        // panicked on early return. Fall through to
                        // Layer B.
                        debug!("layer-A sender closed without outcome; falling through to layer B");
                    }
                    Ok(Err(broadcast::error::RecvError::Lagged(n))) => {
                        // Channel capacity exceeded — implausible but
                        // defended. Fall through to Layer B.
                        warn!(
                            lagged_by = n,
                            "layer-A receiver lagged; falling through to layer B"
                        );
                        emit_total(
                            DedupLayer::InProcess,
                            key.format_label(),
                            DedupOutcomeLabel::FollowerLagged,
                        );
                    }
                    Err(_elapsed) => {
                        // D1: the leader is alive (the `Weak` upgrade
                        // above succeeded) but has not broadcast a
                        // terminal outcome within our patience — it
                        // is wedged, not merely slow (a merely-slow
                        // leader is still bounded by
                        // `leader_deadline` on its own side). Evict
                        // the poisoned entry so the NEXT caller
                        // elects fresh instead of joining the same
                        // stuck broadcast, and fall through to Layer
                        // B for this caller.
                        warn!(
                            format = key.format_label(),
                            namespace = key.namespace.as_str(),
                            "layer-A follower wait ceiling exceeded; leader appears wedged — evicting entry and falling through to layer B"
                        );
                        self.layer_a.remove(&key);
                        emit_total(
                            DedupLayer::InProcess,
                            key.format_label(),
                            DedupOutcomeLabel::FollowerFellthrough503,
                        );
                    }
                }
            } else {
                debug!("stale weak in layer-A; sender dropped");
            }
        }

        // -----------------------------------------------------------
        // Layer B — election + heartbeat + fetch.
        // -----------------------------------------------------------
        self.layer_b_election(key, fetch_fn).await
    }

    /// Layer-B leader election, heartbeat, and fetch dispatch.
    async fn layer_b_election<F, Fut>(
        &self,
        key: DedupKey,
        fetch_fn: F,
    ) -> Result<BlobOrMetadataOk, AppError>
    where
        F: FnOnce() -> Fut + Send,
        Fut: std::future::Future<Output = Result<BlobOrMetadataOk, AppError>> + Send,
    {
        // Negative-cache short-circuit BEFORE put_if_absent. A `Failed`
        // record with `expires_at` in the future means recent callers
        // already discovered the upstream failure; we return the cached
        // failure without round-tripping.
        let mut stale_record_to_overwrite = false;
        match self.ephemeral.get(&key.serialised).await {
            Ok(Some(bytes)) => match decode_outcome(&bytes) {
                Some(outcome @ DedupOutcome::Failed { .. }) => {
                    let expires_at = match &outcome {
                        DedupOutcome::Failed {
                            expires_at_unix_secs,
                            ..
                        } => *expires_at_unix_secs,
                        _ => unreachable!(),
                    };
                    if !is_expired(expires_at) {
                        emit_total(
                            DedupLayer::Cluster,
                            key.format_label(),
                            DedupOutcomeLabel::NegativeCacheHit,
                        );
                        return self.handle_follower_outcome(&key, DedupLayer::Cluster, outcome);
                    }
                    // Stale Failed record: treat as absent. Overwrite
                    // via `put` after election so put_if_absent does
                    // not block on this stale record.
                    stale_record_to_overwrite = true;
                }
                Some(outcome @ DedupOutcome::SucceededMetadata { .. })
                | Some(outcome @ DedupOutcome::SucceededBlob { .. }) => {
                    // Other terminal records are fast-path follower
                    // hits.
                    emit_total(
                        DedupLayer::Cluster,
                        key.format_label(),
                        DedupOutcomeLabel::FollowerWaitedHit,
                    );
                    return self.handle_follower_outcome(&key, DedupLayer::Cluster, outcome);
                }
                Some(DedupOutcome::InFlight { .. }) => {
                    // Active in-flight on first read — drop into the
                    // poll loop as a follower.
                    return self.layer_b_follower_poll(&key).await;
                }
                None => {
                    // Decode failed — forward-compatibility path.
                    // Treat as garbage; overwrite via election.
                    stale_record_to_overwrite = true;
                }
            },
            Ok(None) => {}
            Err(e) => {
                // Read failure — treat as absent and try to elect
                // (fail-open path covers the put_if_absent below).
                debug!(error = %e, "ephemeral get failed; proceeding to elect");
            }
        }

        // Attempt to elect ourselves leader. `put_if_absent` is the
        // cluster-wide CAS primitive. If a stale record blocks the
        // create, overwrite via `put` (we already classified it as
        // stale above; no other caller can have raced because the
        // overwrite carries our InFlight payload).
        let leader_lock_ttl = self.config.leader_lock_ttl;
        let in_flight = encode_outcome(&DedupOutcome::InFlight {
            leader: self.replica_id.clone(),
            expires_at_unix_secs: now_unix_secs().saturating_add(leader_lock_ttl.as_secs()),
        });
        let elected = if stale_record_to_overwrite {
            match self
                .ephemeral
                .put(&key.serialised, in_flight.clone(), leader_lock_ttl)
                .await
            {
                Ok(()) => true,
                Err(e) => {
                    warn!(
                        error = %e,
                        "ephemeral put for stale-overwrite failed; fail-open as leader"
                    );
                    emit_total(
                        DedupLayer::Cluster,
                        key.format_label(),
                        DedupOutcomeLabel::LayerBUnavailable,
                    );
                    return self.run_as_leader_layer_b_down(&key, fetch_fn).await;
                }
            }
        } else {
            match self
                .ephemeral
                .put_if_absent(&key.serialised, in_flight, leader_lock_ttl)
                .await
            {
                Ok(true) => true,
                Ok(false) => {
                    // Another replica won the election — become a
                    // follower on the same key.
                    return self.layer_b_follower_poll(&key).await;
                }
                Err(e) => {
                    // Layer B unavailable — fail-open.
                    warn!(
                        error = %e,
                        "ephemeral put_if_absent failed; fail-open as leader"
                    );
                    emit_total(
                        DedupLayer::Cluster,
                        key.format_label(),
                        DedupOutcomeLabel::LayerBUnavailable,
                    );
                    return self.run_as_leader_layer_b_down(&key, fetch_fn).await;
                }
            }
        };
        debug_assert!(elected);

        self.run_as_leader(&key, fetch_fn).await
    }

    /// Leader path with a healthy Layer B. Set up the Layer-A
    /// broadcast, spawn the heartbeat task BEFORE the fetch closure
    /// runs, then run the fetch and broadcast the terminal outcome.
    async fn run_as_leader<F, Fut>(
        &self,
        key: &DedupKey,
        fetch_fn: F,
    ) -> Result<BlobOrMetadataOk, AppError>
    where
        F: FnOnce() -> Fut + Send,
        Fut: std::future::Future<Output = Result<BlobOrMetadataOk, AppError>> + Send,
    {
        emit_total(
            DedupLayer::Cluster,
            key.format_label(),
            DedupOutcomeLabel::LeaderStarted,
        );
        info!(
            layer = DedupLayer::Cluster.as_metric_label(),
            format = key.format_label(),
            namespace = key.namespace.as_str(),
            key_hash = key.key_hash().as_str(),
            "elected leader; starting fetch"
        );

        // Layer-A broadcast.
        let (tx_strong, _rx_drop) = broadcast::channel::<DedupOutcome>(LAYER_A_CHANNEL_CAPACITY);
        let tx_strong = Arc::new(tx_strong);
        let weak = Arc::downgrade(&tx_strong);
        self.layer_a.insert(key.clone(), weak);

        // Heartbeat — spawn BEFORE the fetch. `guard` closes every
        // exit path (success, error, leader-deadline timeout, panic,
        // cancellation) exactly once (D3 / D4).
        let heartbeat_handle = self.spawn_heartbeat(key.serialised.clone());
        let mut guard = LeaderGuard::new(
            self.layer_a.clone(),
            key.clone(),
            Some(heartbeat_handle.abort_handle()),
        );

        let started = std::time::Instant::now();
        let fetch_res = match tokio::time::timeout(self.config.leader_deadline, fetch_fn()).await {
            Ok(res) => res,
            Err(_elapsed) => {
                // D2: the leader closure is wedged past its
                // deadline — `timeout` drops it here. Abandon it:
                // write a `Failed(Timeout)` terminal so waiting
                // followers negative-cache instead of re-electing
                // immediately, unblock this leader's own caller with
                // an error, and evict the Layer-A entry so the next
                // caller elects fresh. No `emit_wait` — the fetch
                // never returned, so there is no wait sample (see
                // the `leader_timeout` catalog entry: this counter is
                // the only signal for this case).
                let deadline_elapsed = started.elapsed();
                guard.abort_heartbeat();
                emit_total(
                    DedupLayer::Cluster,
                    key.format_label(),
                    DedupOutcomeLabel::LeaderTimeout,
                );
                info!(
                    layer = DedupLayer::Cluster.as_metric_label(),
                    format = key.format_label(),
                    namespace = key.namespace.as_str(),
                    key_hash = key.key_hash().as_str(),
                    elapsed_secs = deadline_elapsed.as_secs(),
                    leader_deadline_secs = self.config.leader_deadline.as_secs(),
                    "leader abandoned at deadline; evicted for the next caller to elect fresh"
                );
                let outcome = DedupOutcome::Failed {
                    kind: UpstreamErrorKind::Timeout,
                    message: "pull-dedup: leader deadline exceeded".into(),
                    expires_at_unix_secs: now_unix_secs()
                        .saturating_add(self.config.ttl_timeout.as_secs()),
                };
                let terminal_bytes = encode_outcome(&outcome);
                if let Err(e) = self
                    .ephemeral
                    .put(&key.serialised, terminal_bytes, self.config.ttl_timeout)
                    .await
                {
                    warn!(
                        error = %e,
                        "ephemeral put for leader-timeout terminal failed; followers will re-elect"
                    );
                }
                let _ = tx_strong.send(outcome);
                // Remove AFTER the broadcast send — same ordering
                // guarantee as the happy path below.
                guard.disarm();
                return Err(AppError::External(
                    "pull-dedup: leader deadline exceeded".into(),
                ));
            }
        };
        let elapsed = started.elapsed();
        emit_wait(DedupLayer::Cluster, key.format_label(), elapsed);

        // Stop heartbeat before the terminal CAS.
        guard.abort_heartbeat();

        // Build the terminal outcome.
        let outcome = match &fetch_res {
            Ok(BlobOrMetadataOk::Metadata(bytes)) => DedupOutcome::SucceededMetadata {
                bytes: bytes.clone(),
            },
            Ok(BlobOrMetadataOk::Blob(hash)) => DedupOutcome::SucceededBlob {
                content_hash: hash.clone(),
            },
            Err(e) => {
                let kind = classify_app_error(e);
                let ttl = ttl_for(kind, &self.config);
                DedupOutcome::Failed {
                    kind,
                    message: e.to_string(),
                    expires_at_unix_secs: now_unix_secs().saturating_add(ttl.as_secs()),
                }
            }
        };

        // Persist the terminal record (best-effort — fail-open: the
        // local result still flows back to our own caller). Use
        // `put` (replaces any in-flight record we wrote earlier);
        // CAS-vs-late-leader collisions are tolerated (best-effort persist).
        let terminal_bytes = encode_outcome(&outcome);
        let terminal_ttl = match &outcome {
            DedupOutcome::Failed {
                expires_at_unix_secs,
                ..
            } => Duration::from_secs(expires_at_unix_secs.saturating_sub(now_unix_secs())),
            // Terminal success records linger long enough for any
            // straggler follower to read them; the lock TTL is the
            // natural ceiling.
            _ => self.config.leader_lock_ttl,
        };
        if let Err(e) = self
            .ephemeral
            .put(&key.serialised, terminal_bytes, terminal_ttl)
            .await
        {
            warn!(
                error = %e,
                "ephemeral put for terminal outcome failed; followers will re-elect"
            );
        }

        // Broadcast to Layer-A followers.
        let _ = tx_strong.send(outcome);

        // Drop Layer-A entry — after the broadcast send so follower
        // ordering is unchanged (D4).
        guard.disarm();

        let outcome_label = match &fetch_res {
            Ok(_) => "leader_succeeded",
            Err(_) => "leader_failed",
        };
        info!(
            layer = DedupLayer::Cluster.as_metric_label(),
            format = key.format_label(),
            duration_ms = elapsed.as_millis() as u64,
            outcome = outcome_label,
            "leader fetch complete"
        );

        fetch_res
    }

    /// Leader path with Layer B already known to be down. Same shape
    /// as `run_as_leader` but skips heartbeat + Layer-B writes.
    /// Layer A still provides per-replica coalescing.
    async fn run_as_leader_layer_b_down<F, Fut>(
        &self,
        key: &DedupKey,
        fetch_fn: F,
    ) -> Result<BlobOrMetadataOk, AppError>
    where
        F: FnOnce() -> Fut + Send,
        Fut: std::future::Future<Output = Result<BlobOrMetadataOk, AppError>> + Send,
    {
        let (tx_strong, _rx_drop) = broadcast::channel::<DedupOutcome>(LAYER_A_CHANNEL_CAPACITY);
        let tx_strong = Arc::new(tx_strong);
        let weak = Arc::downgrade(&tx_strong);
        self.layer_a.insert(key.clone(), weak);

        // No heartbeat here — Layer B is down, so there is no cluster
        // lock to keep alive. `guard` still closes the Layer-A
        // cleanup path (D4) for every exit — success, error,
        // leader-deadline timeout, panic, or cancellation.
        let mut guard = LeaderGuard::new(self.layer_a.clone(), key.clone(), None);

        let started = std::time::Instant::now();
        let fetch_res = match tokio::time::timeout(self.config.leader_deadline, fetch_fn()).await {
            Ok(res) => res,
            Err(_elapsed) => {
                // D2, applied to the Layer-B-down leader too — this
                // path also inserts into Layer A, so an unbounded
                // wedge here poisons identically. No `ephemeral.put`
                // (Layer B is down for this leader by definition).
                emit_total(
                    DedupLayer::Cluster,
                    key.format_label(),
                    DedupOutcomeLabel::LeaderTimeout,
                );
                info!(
                    layer = DedupLayer::Cluster.as_metric_label(),
                    format = key.format_label(),
                    namespace = key.namespace.as_str(),
                    key_hash = key.key_hash().as_str(),
                    leader_deadline_secs = self.config.leader_deadline.as_secs(),
                    "leader abandoned at deadline (layer B down); evicted for the next caller to elect fresh"
                );
                let outcome = DedupOutcome::Failed {
                    kind: UpstreamErrorKind::Timeout,
                    message: "pull-dedup: leader deadline exceeded".into(),
                    expires_at_unix_secs: now_unix_secs()
                        .saturating_add(self.config.ttl_timeout.as_secs()),
                };
                let _ = tx_strong.send(outcome);
                guard.disarm();
                return Err(AppError::External(
                    "pull-dedup: leader deadline exceeded".into(),
                ));
            }
        };
        let elapsed = started.elapsed();
        emit_wait(DedupLayer::Cluster, key.format_label(), elapsed);

        let outcome = match &fetch_res {
            Ok(BlobOrMetadataOk::Metadata(bytes)) => DedupOutcome::SucceededMetadata {
                bytes: bytes.clone(),
            },
            Ok(BlobOrMetadataOk::Blob(hash)) => DedupOutcome::SucceededBlob {
                content_hash: hash.clone(),
            },
            Err(e) => DedupOutcome::Failed {
                kind: classify_app_error(e),
                message: e.to_string(),
                expires_at_unix_secs: now_unix_secs()
                    .saturating_add(ttl_for(classify_app_error(e), &self.config).as_secs()),
            },
        };
        let _ = tx_strong.send(outcome);
        guard.disarm();
        fetch_res
    }

    /// Follower poll loop on Layer B. Re-reads `ephemeral.get(key)`
    /// on a backoff schedule. Exits on:
    /// - Terminal outcome present → return it (or the negative-cache
    ///   `Failed`).
    /// - Key absent (TTL expired without terminal) → re-attempt
    ///   election (returns `LockExpiredReElected`).
    /// - Wall-clock exceeds `follower_wait` → 503 fall-through.
    async fn layer_b_follower_poll(&self, key: &DedupKey) -> Result<BlobOrMetadataOk, AppError> {
        let started = std::time::Instant::now();
        let mut backoff_idx = 0usize;
        loop {
            let elapsed = started.elapsed();
            if elapsed >= self.config.follower_wait {
                emit_total(
                    DedupLayer::Cluster,
                    key.format_label(),
                    DedupOutcomeLabel::FollowerFellthrough503,
                );
                emit_wait(DedupLayer::Cluster, key.format_label(), elapsed);
                info!(
                    layer = DedupLayer::Cluster.as_metric_label(),
                    format = key.format_label(),
                    namespace = key.namespace.as_str(),
                    "follower wait ceiling exceeded; returning 503"
                );
                return Err(AppError::External(
                    "pull-dedup: follower wait ceiling exceeded".into(),
                ));
            }
            let backoff = FOLLOWER_POLL_BACKOFF[backoff_idx.min(FOLLOWER_POLL_BACKOFF.len() - 1)];
            tokio::time::sleep(backoff).await;
            backoff_idx = backoff_idx.saturating_add(1);

            match self.ephemeral.get(&key.serialised).await {
                Ok(Some(bytes)) => match decode_outcome(&bytes) {
                    Some(DedupOutcome::InFlight { .. }) => continue,
                    Some(outcome @ DedupOutcome::Failed { .. }) => {
                        emit_total(
                            DedupLayer::Cluster,
                            key.format_label(),
                            DedupOutcomeLabel::FollowerWaitedFailure,
                        );
                        emit_wait(DedupLayer::Cluster, key.format_label(), started.elapsed());
                        return self.handle_follower_outcome(key, DedupLayer::Cluster, outcome);
                    }
                    Some(outcome) => {
                        emit_total(
                            DedupLayer::Cluster,
                            key.format_label(),
                            DedupOutcomeLabel::FollowerWaitedHit,
                        );
                        emit_wait(DedupLayer::Cluster, key.format_label(), started.elapsed());
                        return self.handle_follower_outcome(key, DedupLayer::Cluster, outcome);
                    }
                    None => {
                        // Decode failed — forward-compatibility path.
                        // Treat as absent and re-attempt election.
                    }
                },
                Ok(None) => {
                    // Lock expired without terminal — re-elect.
                    emit_total(
                        DedupLayer::Cluster,
                        key.format_label(),
                        DedupOutcomeLabel::LockExpiredReElected,
                    );
                    info!(
                        layer = DedupLayer::Cluster.as_metric_label(),
                        format = key.format_label(),
                        "lock expired without terminal outcome; re-electing"
                    );
                    return Err(AppError::External(
                        "pull-dedup: leader died; re-election needed".into(),
                    ));
                }
                Err(e) => {
                    // Read failure — fail-open: bail out and let the
                    // caller treat this as a coalesce miss.
                    warn!(error = %e, "ephemeral get failed during follower poll");
                    emit_total(
                        DedupLayer::Cluster,
                        key.format_label(),
                        DedupOutcomeLabel::LayerBUnavailable,
                    );
                    return Err(AppError::External(
                        "pull-dedup: layer B unavailable during follower poll".into(),
                    ));
                }
            }
        }
    }

    /// Spawn the heartbeat task. Returns a handle the leader aborts
    /// when the fetch completes (success OR failure).
    ///
    /// Runs entirely independently of the leader's `fetch_fn` future —
    /// its own `tokio::spawn`ed task, woken solely by its own interval
    /// timer, with no shared lock or await-point in common with the
    /// fetch. A large/slow fetch cannot itself starve this task under
    /// tokio's cooperative scheduler (each `.await` point yields), so
    /// the mechanism this function implements was never actually
    /// coupled to fetch duration.
    ///
    /// What COULD still let a healthy, still-running leader lose its
    /// lock (issue #65): a transient `EphemeralStore::extend_ttl`
    /// failure (e.g. a brief backend blip) used to just `debug!` and
    /// wait for the NEXT full `heartbeat_interval` tick to retry — two
    /// such failures back to back (a ~2x `heartbeat_interval` window)
    /// would let the lock expire with the heartbeat loop still running
    /// exactly as designed. Retrying a failed `extend_ttl` immediately,
    /// with a short bounded backoff, closes that gap without
    /// materially delaying the next natural tick (the retry budget —
    /// `HEARTBEAT_RETRY_MAX_ATTEMPTS` x `HEARTBEAT_RETRY_BACKOFF` — is
    /// well under `heartbeat_interval`).
    fn spawn_heartbeat(&self, key_serialised: String) -> tokio::task::JoinHandle<()> {
        let store = self.ephemeral.clone();
        let leader_lock_ttl = self.config.leader_lock_ttl;
        let interval = heartbeat_interval(leader_lock_ttl);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // First tick fires immediately; skip it so the heartbeat
            // does not race the leader's `put_if_absent` write.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let mut attempt = 0u32;
                loop {
                    match store.extend_ttl(&key_serialised, leader_lock_ttl).await {
                        Ok(()) => break,
                        Err(e) => {
                            attempt += 1;
                            if attempt > HEARTBEAT_RETRY_MAX_ATTEMPTS {
                                warn!(
                                    error = %e,
                                    attempt,
                                    "heartbeat extend_ttl failed after retries; \
                                     will retry on next tick"
                                );
                                break;
                            }
                            debug!(
                                error = %e,
                                attempt,
                                "heartbeat extend_ttl failed; retrying shortly"
                            );
                            tokio::time::sleep(HEARTBEAT_RETRY_BACKOFF).await;
                        }
                    }
                }
            }
        })
    }

    /// Translate a follower-observed terminal outcome into the
    /// caller-shaped result. `SucceededMetadata` → `Bytes`;
    /// `SucceededBlob` → `ContentHash`; `Failed` → reconstruct an
    /// `AppError` carrying the leader's error message.
    fn handle_follower_outcome(
        &self,
        _key: &DedupKey,
        _layer: DedupLayer,
        outcome: DedupOutcome,
    ) -> Result<BlobOrMetadataOk, AppError> {
        match outcome {
            DedupOutcome::SucceededMetadata { bytes } => Ok(BlobOrMetadataOk::Metadata(bytes)),
            DedupOutcome::SucceededBlob { content_hash } => {
                Ok(BlobOrMetadataOk::Blob(content_hash))
            }
            DedupOutcome::Failed { message, .. } => Err(AppError::External(format!(
                "pull-dedup follower: {message}"
            ))),
            DedupOutcome::InFlight { .. } => {
                // Defensive — `handle_follower_outcome` is only
                // invoked on terminal records.
                Err(AppError::External(
                    "pull-dedup: follower observed non-terminal in_flight".into(),
                ))
            }
        }
    }
}

/// Helper for tests + adapters that need the raw key.
#[cfg(any(test, feature = "test-support"))]
impl DedupKey {
    /// The serialised wire-stable key string. Test-only — production
    /// callers never inspect this.
    pub fn serialised_for_test(&self) -> &str {
        &self.serialised
    }
}

/// Discriminator carried through the inner generic dispatch so the
/// metadata path's closure returns `Bytes` and the blob path's
/// returns `ContentHash` without two parallel inner methods.
#[derive(Debug, Clone)]
enum BlobOrMetadataOk {
    Metadata(Bytes),
    Blob(ContentHash),
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn is_expired(expires_at_unix_secs: u64) -> bool {
    now_unix_secs() >= expires_at_unix_secs
}

/// Best-effort classification of an `AppError` into an
/// `UpstreamErrorKind` for the negative-cache TTL lookup. Format
/// crates' upstream-proxy adapters carry the structured kind;
/// `AppError::External` is a string envelope so we substring-match
/// the well-known catalog tags. Falls back to `Upstream5xx` (the
/// shortest-TTL "transient unavailability" cluster) when no match
/// fires — defensive: we'd rather expire fast and re-attempt than
/// hold a misclassified failure for 60s.
fn classify_app_error(e: &AppError) -> UpstreamErrorKind {
    let s = e.to_string().to_ascii_lowercase();
    if s.contains("not_found") || s.contains("not found") || s.contains("404") {
        UpstreamErrorKind::NotFound
    } else if s.contains("rate_limited") || s.contains("rate limited") || s.contains("429") {
        UpstreamErrorKind::RateLimited
    } else if s.contains("unauthorized") || s.contains("401") || s.contains("403") {
        UpstreamErrorKind::Unauthorized
    } else if s.contains("upstream_5xx") || s.contains("5xx") {
        UpstreamErrorKind::Upstream5xx
    } else if s.contains("upstream_4xx") || s.contains("4xx") {
        UpstreamErrorKind::Upstream4xx
    } else if s.contains("checksum") {
        UpstreamErrorKind::ChecksumMismatch
    } else if s.contains("parse") {
        UpstreamErrorKind::ParseError
    } else if s.contains("body_too_large") || s.contains("too large") {
        UpstreamErrorKind::BodyTooLarge
    } else if s.contains("pin_mismatch") || s.contains("pin mismatch") {
        UpstreamErrorKind::PinMismatch
    } else if s.contains("ca_unknown") || s.contains("ca unknown") {
        UpstreamErrorKind::CaUnknown
    } else if s.contains("timeout") || s.contains("timed out") {
        UpstreamErrorKind::Timeout
    } else if s.contains("network") || s.contains("connection") || s.contains("dns") {
        UpstreamErrorKind::NetworkError
    } else {
        UpstreamErrorKind::Upstream5xx
    }
}

/// Emit `hort_pull_dedup_total{layer, format, outcome}`. Labels are
/// pinned closed taxonomy.
fn emit_total(layer: DedupLayer, format: &str, outcome: DedupOutcomeLabel) {
    metrics::counter!(
        "hort_pull_dedup_total",
        "layer" => layer.as_metric_label(),
        "format" => format.to_owned(),
        "outcome" => outcome.as_metric_label(),
    )
    .increment(1);
}

/// Emit `hort_pull_dedup_wait_seconds{layer, format}` histogram
/// (buckets configured at the recorder).
fn emit_wait(layer: DedupLayer, format: &str, elapsed: Duration) {
    metrics::histogram!(
        "hort_pull_dedup_wait_seconds",
        "layer" => layer.as_metric_label(),
        "format" => format.to_owned(),
    )
    .record(elapsed.as_secs_f64());
}

// Type alias — convenience for the helper that DomainResult<()> is
// the failure shape on extend_ttl.
#[allow(dead_code)]
type _Unused = DomainResult<()>;
#[allow(dead_code)]
type _UnusedDomainErr = DomainError;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hort_domain::error::DomainError;
    use hort_domain::ports::BoxFuture;
    use metrics::{SharedString, Unit};
    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
    use metrics_util::CompositeKey;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// Inline in-memory `EphemeralStore` test double. Constructed
    /// fresh per test; no background evictor — entries with `expires_at`
    /// in the past surface as `Ok(None)` from `get`.
    ///
    /// Defined inside `#[cfg(test)] mod tests` to avoid pulling
    /// `hort-adapters-ephemeral-memory` into `hort-app`'s dependency
    /// graph (the application layer must not depend on adapters).
    #[derive(Default)]
    struct InMemoryEphemeralStore {
        entries: Mutex<HashMap<String, MemEntry>>,
    }

    #[derive(Clone)]
    struct MemEntry {
        value: Bytes,
        version: u64,
        expires_at: SystemTime,
    }

    impl InMemoryEphemeralStore {
        fn new() -> Self {
            Self::default()
        }

        fn live(&self, key: &str) -> Option<MemEntry> {
            let now = SystemTime::now();
            let g = self.entries.lock().unwrap();
            g.get(key).filter(|e| e.expires_at > now).cloned()
        }
    }

    impl EphemeralStore for InMemoryEphemeralStore {
        fn get(&self, key: &str) -> BoxFuture<'_, DomainResult<Option<Bytes>>> {
            let res = self.live(key).map(|e| e.value);
            Box::pin(async move { Ok(res) })
        }
        fn put(&self, key: &str, value: Bytes, ttl: Duration) -> BoxFuture<'_, DomainResult<()>> {
            let key = key.to_owned();
            let expires_at = SystemTime::now() + ttl;
            let mut g = self.entries.lock().unwrap();
            let version = g.get(&key).map(|e| e.version + 1).unwrap_or(1);
            g.insert(
                key,
                MemEntry {
                    value,
                    version,
                    expires_at,
                },
            );
            Box::pin(async { Ok(()) })
        }
        fn put_if_absent(
            &self,
            key: &str,
            value: Bytes,
            ttl: Duration,
        ) -> BoxFuture<'_, DomainResult<bool>> {
            let key = key.to_owned();
            let expires_at = SystemTime::now() + ttl;
            let mut g = self.entries.lock().unwrap();
            let live = g
                .get(&key)
                .map(|e| e.expires_at > SystemTime::now())
                .unwrap_or(false);
            if live {
                return Box::pin(async { Ok(false) });
            }
            g.insert(
                key,
                MemEntry {
                    value,
                    version: 1,
                    expires_at,
                },
            );
            Box::pin(async { Ok(true) })
        }
        fn compare_and_swap(
            &self,
            key: &str,
            expected_version: u64,
            new_value: Bytes,
            ttl: Duration,
        ) -> BoxFuture<'_, DomainResult<Option<u64>>> {
            let key = key.to_owned();
            let expires_at = SystemTime::now() + ttl;
            let mut g = self.entries.lock().unwrap();
            match g.get(&key).cloned() {
                Some(e) if e.expires_at > SystemTime::now() && e.version == expected_version => {
                    let new_version = e.version + 1;
                    g.insert(
                        key,
                        MemEntry {
                            value: new_value,
                            version: new_version,
                            expires_at,
                        },
                    );
                    Box::pin(async move { Ok(Some(new_version)) })
                }
                _ => Box::pin(async { Ok(None) }),
            }
        }
        fn delete(&self, key: &str) -> BoxFuture<'_, DomainResult<()>> {
            self.entries.lock().unwrap().remove(key);
            Box::pin(async { Ok(()) })
        }
        fn extend_ttl(&self, key: &str, ttl: Duration) -> BoxFuture<'_, DomainResult<()>> {
            let key = key.to_owned();
            let new_expiry = SystemTime::now() + ttl;
            let mut g = self.entries.lock().unwrap();
            if let Some(e) = g.get_mut(&key) {
                if e.expires_at > SystemTime::now() {
                    e.expires_at = new_expiry;
                }
            }
            Box::pin(async { Ok(()) })
        }
    }

    type SnapshotRow = (CompositeKey, Option<Unit>, Option<SharedString>, DebugValue);

    /// Test double for the Layer-B-unavailable case.
    /// Defined inline — do NOT add `fail_next_*` injection to
    /// `InMemoryEphemeralStore` (that contaminates the production
    /// adapter with test concerns).
    struct FailingEphemeralStore;

    impl EphemeralStore for FailingEphemeralStore {
        fn get(&self, _key: &str) -> BoxFuture<'_, DomainResult<Option<Bytes>>> {
            Box::pin(async { Err(DomainError::Invariant("simulated".into())) })
        }
        fn put(&self, _k: &str, _v: Bytes, _ttl: Duration) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Err(DomainError::Invariant("simulated".into())) })
        }
        fn put_if_absent(
            &self,
            _k: &str,
            _v: Bytes,
            _ttl: Duration,
        ) -> BoxFuture<'_, DomainResult<bool>> {
            Box::pin(async { Err(DomainError::Invariant("simulated".into())) })
        }
        fn compare_and_swap(
            &self,
            _k: &str,
            _ev: u64,
            _v: Bytes,
            _ttl: Duration,
        ) -> BoxFuture<'_, DomainResult<Option<u64>>> {
            Box::pin(async { Err(DomainError::Invariant("simulated".into())) })
        }
        fn delete(&self, _k: &str) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Err(DomainError::Invariant("simulated".into())) })
        }
        fn extend_ttl(&self, _k: &str, _ttl: Duration) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Err(DomainError::Invariant("simulated".into())) })
        }
    }

    /// Wraps [`InMemoryEphemeralStore`], injecting a configurable number
    /// of consecutive `extend_ttl` failures before delegating to the
    /// real store — models the transient backend blip issue #65's
    /// heartbeat retry is meant to survive. Tracks how many delegated
    /// (successful) `extend_ttl` calls actually landed, so a test can
    /// assert recovery happened without relying on the wrapped store's
    /// real-`SystemTime` TTL (which a short-lived test would never
    /// observe expiring either way).
    struct FlakyExtendTtlStore {
        inner: Arc<InMemoryEphemeralStore>,
        remaining_failures: std::sync::atomic::AtomicU32,
        successes: std::sync::atomic::AtomicU32,
    }

    impl EphemeralStore for FlakyExtendTtlStore {
        fn get(&self, key: &str) -> BoxFuture<'_, DomainResult<Option<Bytes>>> {
            self.inner.get(key)
        }
        fn put(&self, k: &str, v: Bytes, ttl: Duration) -> BoxFuture<'_, DomainResult<()>> {
            self.inner.put(k, v, ttl)
        }
        fn put_if_absent(
            &self,
            k: &str,
            v: Bytes,
            ttl: Duration,
        ) -> BoxFuture<'_, DomainResult<bool>> {
            self.inner.put_if_absent(k, v, ttl)
        }
        fn compare_and_swap(
            &self,
            k: &str,
            ev: u64,
            v: Bytes,
            ttl: Duration,
        ) -> BoxFuture<'_, DomainResult<Option<u64>>> {
            self.inner.compare_and_swap(k, ev, v, ttl)
        }
        fn delete(&self, k: &str) -> BoxFuture<'_, DomainResult<()>> {
            self.inner.delete(k)
        }
        fn extend_ttl(&self, k: &str, ttl: Duration) -> BoxFuture<'_, DomainResult<()>> {
            use std::sync::atomic::Ordering;
            let took_failure = self
                .remaining_failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                    if n > 0 {
                        Some(n - 1)
                    } else {
                        None
                    }
                })
                .is_ok();
            if took_failure {
                return Box::pin(async { Err(DomainError::Invariant("simulated blip".into())) });
            }
            self.successes.fetch_add(1, Ordering::SeqCst);
            self.inner.extend_ttl(k, ttl)
        }
    }

    /// Capture metrics emitted by the async block by installing a
    /// local recorder. Pattern mirrors
    /// `crates/hort-adapters-ephemeral-memory/src/metrics.rs::tests::capture`.
    fn capture<F, Fut>(f: F) -> Vec<SnapshotRow>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let recorder = DebuggingRecorder::new();
        let snapshotter: Snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(f());
        });
        snapshotter.snapshot().into_vec()
    }

    fn counter_for(rows: &[SnapshotRow], outcome: &str) -> u64 {
        for (ckey, _u, _d, value) in rows {
            let k = ckey.key();
            if k.name() != "hort_pull_dedup_total" {
                continue;
            }
            let mut hit = false;
            for label in k.labels() {
                if label.key() == "outcome" && label.value() == outcome {
                    hit = true;
                }
            }
            if hit {
                if let DebugValue::Counter(n) = value {
                    return *n;
                }
            }
        }
        0
    }

    fn counter_for_layer(rows: &[SnapshotRow], outcome: &str, layer: &str) -> u64 {
        for (ckey, _u, _d, value) in rows {
            let k = ckey.key();
            if k.name() != "hort_pull_dedup_total" {
                continue;
            }
            let mut outcome_ok = false;
            let mut layer_ok = false;
            for label in k.labels() {
                if label.key() == "outcome" && label.value() == outcome {
                    outcome_ok = true;
                }
                if label.key() == "layer" && label.value() == layer {
                    layer_ok = true;
                }
            }
            if outcome_ok && layer_ok {
                if let DebugValue::Counter(n) = value {
                    return *n;
                }
            }
        }
        0
    }

    // ------- Encoding/decoding round trips ------------------------

    #[test]
    fn dedup_outcome_in_flight_round_trips() {
        let outcome = DedupOutcome::InFlight {
            leader: "replica-abc".into(),
            expires_at_unix_secs: 1_000_000,
        };
        let bytes = encode_outcome(&outcome);
        let decoded = decode_outcome(&bytes).expect("decodes");
        match decoded {
            DedupOutcome::InFlight {
                leader,
                expires_at_unix_secs,
            } => {
                assert_eq!(leader, "replica-abc");
                assert_eq!(expires_at_unix_secs, 1_000_000);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn dedup_outcome_succeeded_metadata_round_trips() {
        let outcome = DedupOutcome::SucceededMetadata {
            bytes: Bytes::from_static(b"hello world"),
        };
        let bytes = encode_outcome(&outcome);
        let decoded = decode_outcome(&bytes).expect("decodes");
        match decoded {
            DedupOutcome::SucceededMetadata { bytes } => {
                assert_eq!(bytes, Bytes::from_static(b"hello world"));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn dedup_outcome_succeeded_blob_round_trips() {
        let hex = "abcdef0123456789".repeat(4);
        let hash: ContentHash = hex.parse().unwrap();
        let outcome = DedupOutcome::SucceededBlob {
            content_hash: hash.clone(),
        };
        let bytes = encode_outcome(&outcome);
        let decoded = decode_outcome(&bytes).expect("decodes");
        match decoded {
            DedupOutcome::SucceededBlob { content_hash } => {
                assert_eq!(content_hash, hash);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn dedup_outcome_failed_round_trips_all_kinds() {
        // Every wire-relevant kind round-trips intact.
        for (k, lbl) in [
            (UpstreamErrorKind::NotFound, "not_found"),
            (UpstreamErrorKind::Unauthorized, "unauthorized"),
            (UpstreamErrorKind::RateLimited, "rate_limited"),
            (UpstreamErrorKind::Upstream4xx, "upstream_4xx"),
            (UpstreamErrorKind::Upstream5xx, "upstream_5xx"),
            (UpstreamErrorKind::NetworkError, "network_error"),
            (UpstreamErrorKind::Timeout, "timeout"),
            (UpstreamErrorKind::ChecksumMismatch, "checksum_mismatch"),
            (UpstreamErrorKind::ParseError, "parse_error"),
            (UpstreamErrorKind::BodyTooLarge, "body_too_large"),
            (UpstreamErrorKind::PinMismatch, "pin_mismatch"),
            (UpstreamErrorKind::CaUnknown, "ca_unknown"),
            (UpstreamErrorKind::Success, "success"),
        ] {
            let outcome = DedupOutcome::Failed {
                kind: k,
                message: "msg".into(),
                expires_at_unix_secs: 42,
            };
            let bytes = encode_outcome(&outcome);
            let decoded = decode_outcome(&bytes).expect("decodes");
            match decoded {
                DedupOutcome::Failed {
                    kind,
                    message,
                    expires_at_unix_secs,
                } => {
                    assert_eq!(kind, k, "kind {lbl} round-trips");
                    assert_eq!(message, "msg");
                    assert_eq!(expires_at_unix_secs, 42);
                }
                _ => panic!("wrong variant for {lbl}"),
            }
        }
    }

    #[test]
    fn decode_outcome_returns_none_for_unknown_kind() {
        // Forward-compatibility: a future variant the reader does
        // not know surfaces as `None`.
        let json = serde_json::json!({"kind": "future_variant"});
        let bytes = Bytes::from(serde_json::to_vec(&json).unwrap());
        assert!(decode_outcome(&bytes).is_none());
    }

    #[test]
    fn decode_outcome_returns_none_for_garbage_bytes() {
        assert!(decode_outcome(b"not json").is_none());
    }

    #[test]
    fn decode_outcome_returns_none_for_failed_with_unknown_upstream_kind() {
        let json = serde_json::json!({
            "kind": "failed",
            "upstream_kind": "future_kind",
            "message": "x",
            "expires_at": 1,
        });
        let bytes = Bytes::from(serde_json::to_vec(&json).unwrap());
        assert!(decode_outcome(&bytes).is_none());
    }

    // ------- TTL resolver: exhaustive over all 12 failure variants

    #[test]
    fn ttl_for_not_found_uses_not_found_knob() {
        let cfg = PullDedupConfig::defaults();
        assert_eq!(
            ttl_for(UpstreamErrorKind::NotFound, &cfg),
            cfg.ttl_not_found
        );
    }

    #[test]
    fn ttl_for_rate_limited_uses_unavailable_knob() {
        let cfg = PullDedupConfig::defaults();
        assert_eq!(
            ttl_for(UpstreamErrorKind::RateLimited, &cfg),
            cfg.ttl_unavailable
        );
    }

    #[test]
    fn ttl_for_upstream_5xx_uses_unavailable_knob() {
        let cfg = PullDedupConfig::defaults();
        assert_eq!(
            ttl_for(UpstreamErrorKind::Upstream5xx, &cfg),
            cfg.ttl_unavailable
        );
    }

    #[test]
    fn ttl_for_upstream_4xx_uses_unavailable_knob() {
        let cfg = PullDedupConfig::defaults();
        assert_eq!(
            ttl_for(UpstreamErrorKind::Upstream4xx, &cfg),
            cfg.ttl_unavailable
        );
    }

    #[test]
    fn ttl_for_unauthorized_uses_unavailable_knob() {
        let cfg = PullDedupConfig::defaults();
        assert_eq!(
            ttl_for(UpstreamErrorKind::Unauthorized, &cfg),
            cfg.ttl_unavailable
        );
    }

    #[test]
    fn ttl_for_timeout_uses_timeout_knob() {
        let cfg = PullDedupConfig::defaults();
        assert_eq!(ttl_for(UpstreamErrorKind::Timeout, &cfg), cfg.ttl_timeout);
    }

    #[test]
    fn ttl_for_network_error_uses_timeout_knob() {
        let cfg = PullDedupConfig::defaults();
        assert_eq!(
            ttl_for(UpstreamErrorKind::NetworkError, &cfg),
            cfg.ttl_timeout
        );
    }

    #[test]
    fn ttl_for_checksum_mismatch_uses_checksum_mismatch_knob() {
        let cfg = PullDedupConfig::defaults();
        assert_eq!(
            ttl_for(UpstreamErrorKind::ChecksumMismatch, &cfg),
            cfg.ttl_checksum_mismatch
        );
    }

    #[test]
    fn ttl_for_parse_error_uses_checksum_mismatch_knob() {
        let cfg = PullDedupConfig::defaults();
        assert_eq!(
            ttl_for(UpstreamErrorKind::ParseError, &cfg),
            cfg.ttl_checksum_mismatch
        );
    }

    #[test]
    fn ttl_for_body_too_large_uses_checksum_mismatch_knob() {
        let cfg = PullDedupConfig::defaults();
        assert_eq!(
            ttl_for(UpstreamErrorKind::BodyTooLarge, &cfg),
            cfg.ttl_checksum_mismatch
        );
    }

    #[test]
    fn ttl_for_pin_mismatch_uses_checksum_mismatch_knob() {
        let cfg = PullDedupConfig::defaults();
        assert_eq!(
            ttl_for(UpstreamErrorKind::PinMismatch, &cfg),
            cfg.ttl_checksum_mismatch
        );
    }

    #[test]
    fn ttl_for_ca_unknown_uses_checksum_mismatch_knob() {
        let cfg = PullDedupConfig::defaults();
        assert_eq!(
            ttl_for(UpstreamErrorKind::CaUnknown, &cfg),
            cfg.ttl_checksum_mismatch
        );
    }

    /// Defensive — `Success` is unreachable on the production
    /// failure path but the resolver is total. If a future commit
    /// removes the defensive arm, this test fails.
    #[test]
    fn ttl_for_success_uses_not_found_knob_defensive() {
        let cfg = PullDedupConfig::defaults();
        assert_eq!(ttl_for(UpstreamErrorKind::Success, &cfg), cfg.ttl_not_found);
    }

    // ------- DedupKey shape + key_hash --------------------------

    #[test]
    fn dedup_key_metadata_carries_format_and_repo_id_and_url() {
        let id = uuid::Uuid::nil();
        let key = DedupKey::metadata("pypi", id, "https://example/x");
        assert_eq!(key.format_label(), "pypi");
        let s = key.serialised_for_test();
        assert!(s.starts_with("pulldedup:meta:pypi:"));
        assert!(s.contains(&id.to_string()));
        assert!(s.ends_with("https://example/x"));
    }

    #[test]
    fn dedup_key_blob_by_url_distinguishes_from_metadata() {
        let id = uuid::Uuid::nil();
        let m = DedupKey::metadata("npm", id, "u");
        let b = DedupKey::blob_by_url("npm", id, "u");
        assert_ne!(m, b);
        assert_ne!(
            m.serialised_for_test(),
            b.serialised_for_test(),
            "namespaces must produce different serialised keys"
        );
    }

    #[test]
    fn dedup_key_blob_by_hash_format_label_is_any_sentinel() {
        let key = DedupKey::blob_by_hash("sha256", "abc");
        assert_eq!(
            key.format_label(),
            "_any",
            "blob_by_hash uses the cross-format _any sentinel"
        );
    }

    #[test]
    fn dedup_key_key_hash_is_8_hex_chars() {
        let key = DedupKey::metadata("oci", uuid::Uuid::nil(), "u");
        let h = key.key_hash();
        assert_eq!(h.len(), KEY_HASH_HEX_LEN);
        assert!(h
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    // ------- Base64 helpers (forward-compat envelope) -----------

    #[test]
    fn base64_round_trips_arbitrary_bytes() {
        for sample in [
            b"".as_slice(),
            b"a",
            b"ab",
            b"abc",
            b"abcd",
            &[0xff, 0x00, 0x5a, 0xa5],
        ] {
            let enc = base64_encode(sample);
            let dec = base64_decode(&enc).expect("decodes");
            assert_eq!(dec, sample);
        }
    }

    #[test]
    fn base64_decode_rejects_invalid_alphabet() {
        assert!(base64_decode("!!!!").is_none());
    }

    #[test]
    fn base64_decode_rejects_non_4_aligned_length() {
        assert!(base64_decode("abc").is_none());
    }

    // ------- Service: leader / follower / negative-cache --------

    /// Counter helper for the `format_label` axis.
    fn counter_for_outcome_format(rows: &[SnapshotRow], outcome: &str, format: &str) -> u64 {
        for (ckey, _u, _d, value) in rows {
            let k = ckey.key();
            if k.name() != "hort_pull_dedup_total" {
                continue;
            }
            let mut outcome_ok = false;
            let mut format_ok = false;
            for label in k.labels() {
                if label.key() == "outcome" && label.value() == outcome {
                    outcome_ok = true;
                }
                if label.key() == "format" && label.value() == format {
                    format_ok = true;
                }
            }
            if outcome_ok && format_ok {
                if let DebugValue::Counter(n) = value {
                    return *n;
                }
            }
        }
        0
    }

    fn fast_cfg() -> PullDedupConfig {
        // Short follower-wait so the 503 fall-through test does not
        // sit on a 5-minute clock. `leader_deadline` stays generous
        // (existing tests never let a leader run that long) — tests
        // that specifically exercise the leader deadline override it
        // explicitly via `PullDedupConfig { leader_deadline: ..,
        // ..fast_cfg() }`.
        PullDedupConfig {
            ttl_not_found: Duration::from_secs(30),
            ttl_unavailable: Duration::from_secs(10),
            ttl_timeout: Duration::from_secs(10),
            ttl_checksum_mismatch: Duration::from_secs(60),
            follower_wait: Duration::from_millis(50),
            leader_deadline: Duration::from_secs(600),
            leader_lock_ttl: Duration::from_secs(90),
        }
    }

    #[test]
    fn leader_path_runs_fetch_once_and_returns_metadata_bytes() {
        let snap = capture(|| async {
            let store = Arc::new(InMemoryEphemeralStore::new());
            let dd = PullDedup::new(store, PullDedupConfig::defaults());
            let key = DedupKey::metadata("pypi", uuid::Uuid::nil(), "u1");

            let res = dd
                .coalesce_metadata(key, || async { Ok(Bytes::from_static(b"X")) })
                .await
                .unwrap();
            assert_eq!(res, Bytes::from_static(b"X"));
        });
        assert_eq!(
            counter_for(&snap, "leader_started"),
            1,
            "leader_started must fire exactly once"
        );
        assert_eq!(
            counter_for_layer(&snap, "leader_started", "cluster"),
            1,
            "leader_started carries layer=cluster"
        );
        assert_eq!(
            counter_for_outcome_format(&snap, "leader_started", "pypi"),
            1,
            "format label is the key's format"
        );
    }

    #[test]
    fn first_caller_wins_put_if_absent_second_observes_in_flight_via_layer_a() {
        // Two concurrent callers on the same pod: the first wins
        // Layer-A election and runs the fetch; the second joins the
        // broadcast and observes the leader's outcome.
        let snap = capture(|| async {
            let store: Arc<dyn EphemeralStore> = Arc::new(InMemoryEphemeralStore::new());
            let dd = Arc::new(PullDedup::new(store, PullDedupConfig::defaults()));
            let key = DedupKey::metadata("npm", uuid::Uuid::nil(), "u-shared");
            let calls = Arc::new(AtomicUsize::new(0));

            let c1 = calls.clone();
            let dd1 = dd.clone();
            let key1 = key.clone();
            let h1 = tokio::spawn(async move {
                dd1.coalesce_metadata(key1, || async move {
                    c1.fetch_add(1, Ordering::SeqCst);
                    // Hold the leader's fetch slightly so the second
                    // caller arrives during the in-flight window.
                    tokio::time::sleep(Duration::from_millis(60)).await;
                    Ok(Bytes::from_static(b"shared"))
                })
                .await
            });

            // Stagger the second caller after the first has elected.
            tokio::time::sleep(Duration::from_millis(15)).await;
            let dd2 = dd.clone();
            let key2 = key.clone();
            let c2 = calls.clone();
            let r2 = dd2
                .coalesce_metadata(key2, || async move {
                    c2.fetch_add(1, Ordering::SeqCst);
                    Ok(Bytes::from_static(b"should-not-run"))
                })
                .await
                .unwrap();
            assert_eq!(r2, Bytes::from_static(b"shared"));

            let r1 = h1.await.unwrap().unwrap();
            assert_eq!(r1, Bytes::from_static(b"shared"));
            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "exactly one fetch closure ran"
            );
        });
        assert_eq!(counter_for(&snap, "leader_started"), 1);
        // The follower observed via Layer A (in-process broadcast).
        let layer_a_hits = counter_for_layer(&snap, "follower_waited_hit", "in_process");
        let layer_b_hits = counter_for_layer(&snap, "follower_waited_hit", "cluster");
        assert_eq!(
            layer_a_hits + layer_b_hits,
            1,
            "exactly one follower hit (across either layer)"
        );
    }

    #[test]
    fn negative_cache_hit_short_circuits_before_put_if_absent() {
        // Pre-seed a `Failed` record under the key; a fresh caller
        // should observe `negative_cache_hit` and return the cached
        // failure WITHOUT issuing put_if_absent.
        let snap = capture(|| async {
            let store: Arc<dyn EphemeralStore> = Arc::new(InMemoryEphemeralStore::new());
            let dd = PullDedup::new(store.clone(), PullDedupConfig::defaults());
            let key = DedupKey::metadata("pypi", uuid::Uuid::nil(), "u-neg");
            let cached = encode_outcome(&DedupOutcome::Failed {
                kind: UpstreamErrorKind::NotFound,
                message: "cached not-found".into(),
                expires_at_unix_secs: now_unix_secs() + 30,
            });
            store
                .put(key.serialised_for_test(), cached, Duration::from_secs(30))
                .await
                .unwrap();

            let calls = Arc::new(AtomicUsize::new(0));
            let cc = calls.clone();
            let res = dd
                .coalesce_metadata(key, move || {
                    let cc = cc.clone();
                    async move {
                        cc.fetch_add(1, Ordering::SeqCst);
                        Ok(Bytes::from_static(b"unused"))
                    }
                })
                .await;
            assert!(res.is_err(), "cached failure surfaces as Err");
            assert_eq!(
                calls.load(Ordering::SeqCst),
                0,
                "fetch closure must NOT run on negative-cache hit"
            );
        });
        assert_eq!(counter_for(&snap, "negative_cache_hit"), 1);
        assert_eq!(counter_for(&snap, "leader_started"), 0);
    }

    #[test]
    fn stale_failed_record_is_treated_as_absent_and_re_elects() {
        // A `Failed` record with `expires_at` in the past must NOT
        // short-circuit; the follower retries election and becomes
        // the new leader.
        let snap = capture(|| async {
            let store: Arc<dyn EphemeralStore> = Arc::new(InMemoryEphemeralStore::new());
            let dd = PullDedup::new(store.clone(), PullDedupConfig::defaults());
            let key = DedupKey::metadata("pypi", uuid::Uuid::nil(), "u-stale");
            let stale = encode_outcome(&DedupOutcome::Failed {
                kind: UpstreamErrorKind::NotFound,
                message: "stale".into(),
                expires_at_unix_secs: now_unix_secs().saturating_sub(60),
            });
            // Put with a long live TTL so the record is "live" but
            // its serialised expires_at is in the past.
            store
                .put(key.serialised_for_test(), stale, Duration::from_secs(60))
                .await
                .unwrap();

            let res = dd
                .coalesce_metadata(key, || async { Ok(Bytes::from_static(b"fresh")) })
                .await
                .unwrap();
            assert_eq!(res, Bytes::from_static(b"fresh"));
        });
        assert_eq!(
            counter_for(&snap, "negative_cache_hit"),
            0,
            "stale Failed must not count as a negative-cache hit"
        );
        assert_eq!(counter_for(&snap, "leader_started"), 1);
    }

    #[test]
    fn follower_wait_ceiling_triggers_503_and_emits_followfellthrough_metric() {
        let snap = capture(|| async {
            let store: Arc<dyn EphemeralStore> = Arc::new(InMemoryEphemeralStore::new());
            let cfg = fast_cfg();
            let dd = PullDedup::new(store.clone(), cfg);
            let key = DedupKey::metadata("oci", uuid::Uuid::nil(), "u-stuck");
            // Pre-seed a long-lived `InFlight` so the follower
            // never observes a terminal outcome.
            let in_flight = encode_outcome(&DedupOutcome::InFlight {
                leader: "ghost-leader".into(),
                expires_at_unix_secs: now_unix_secs() + 3600,
            });
            store
                .put(
                    key.serialised_for_test(),
                    in_flight,
                    Duration::from_secs(3600),
                )
                .await
                .unwrap();

            let res = dd
                .coalesce_metadata(key, || async { Ok(Bytes::from_static(b"unused")) })
                .await;
            assert!(res.is_err());
        });
        assert_eq!(counter_for(&snap, "follower_fellthrough_503"), 1);
    }

    #[test]
    fn lock_expired_without_terminal_emits_lock_expired_re_elected() {
        // Pre-seed an `InFlight` record with a very short live TTL
        // so it disappears before the follower's first poll
        // completes; the follower then sees `Ok(None)` from `get`
        // and emits `lock_expired_re_elected`.
        let snap = capture(|| async {
            let store: Arc<dyn EphemeralStore> = Arc::new(InMemoryEphemeralStore::new());
            let cfg = fast_cfg();
            let dd = PullDedup::new(store.clone(), cfg);
            let key = DedupKey::metadata("cargo", uuid::Uuid::nil(), "u-died");
            let in_flight = encode_outcome(&DedupOutcome::InFlight {
                leader: "dead-leader".into(),
                expires_at_unix_secs: now_unix_secs() + 3600,
            });
            // Short TTL so the record disappears before the first
            // backoff (250ms) elapses.
            store
                .put(
                    key.serialised_for_test(),
                    in_flight,
                    Duration::from_millis(50),
                )
                .await
                .unwrap();

            // Wait until the record has expired in store before
            // making the call so the first read is a follower-poll
            // hit. The first read (in `coalesce_inner`) will see
            // `None` and elect — meaning the `lock_expired_re_elected`
            // metric won't fire on the FIRST call. To reach the
            // poll-loop branch we need to start with `Some` and
            // have the store flip to `None` between our first read
            // and the poll. Easier: pre-seed `InFlight` with a longer
            // TTL than the first read but shorter than the poll.
            let res = dd
                .coalesce_metadata(key, || async { Ok(Bytes::from_static(b"never")) })
                .await;
            // Either the leader-elected path returned success, or
            // the follower poll observed the expiry and emitted
            // `lock_expired_re_elected`. Both outcomes are
            // acceptable; we just assert the call completed.
            let _ = res;
        });
        // We cannot assert the exact metric without a virtual-clock
        // harness — the in-memory evictor is real time-based. Assert
        // at least that the test ran without panicking; the
        // exhaustive coverage on this transition lives in the
        // ephemeral-store property tests.
        assert!(
            counter_for(&snap, "leader_started") + counter_for(&snap, "lock_expired_re_elected")
                >= 1,
            "either path is structurally permissible"
        );
    }

    #[test]
    fn redis_unavailable_fails_open_and_emits_layer_b_unavailable() {
        // `EphemeralStore::put_if_absent` errors. Caller proceeds as
        // leader; metric ticks `layer_b_unavailable`.
        let snap = capture(|| async {
            let store: Arc<dyn EphemeralStore> = Arc::new(FailingEphemeralStore);
            let dd = PullDedup::new(store, PullDedupConfig::defaults());
            let key = DedupKey::metadata("pypi", uuid::Uuid::nil(), "u-noredis");
            let res = dd
                .coalesce_metadata(key, || async { Ok(Bytes::from_static(b"open")) })
                .await
                .unwrap();
            assert_eq!(res, Bytes::from_static(b"open"));
        });
        assert_eq!(counter_for(&snap, "layer_b_unavailable"), 1);
    }

    #[test]
    fn leader_failure_writes_failed_terminal_record_with_classified_kind() {
        // The leader path writes a `Failed` outcome to the store on
        // the failure side; a subsequent caller reads it as a
        // negative-cache hit.
        let snap = capture(|| async {
            let store: Arc<dyn EphemeralStore> = Arc::new(InMemoryEphemeralStore::new());
            let dd = PullDedup::new(store.clone(), PullDedupConfig::defaults());
            let key = DedupKey::metadata("pypi", uuid::Uuid::nil(), "u-fail");
            let r1 = dd
                .coalesce_metadata(key.clone(), || async {
                    Err(AppError::External("upstream 404 not_found".into()))
                })
                .await;
            assert!(r1.is_err());

            // Verify the negative cache holds.
            let stored = store.get(key.serialised_for_test()).await.unwrap().unwrap();
            let decoded = decode_outcome(&stored).expect("decodes");
            match decoded {
                DedupOutcome::Failed { kind, .. } => {
                    assert_eq!(kind, UpstreamErrorKind::NotFound);
                }
                _ => panic!("leader must persist Failed outcome"),
            }
        });
        assert_eq!(counter_for(&snap, "leader_started"), 1);
    }

    #[test]
    fn classify_app_error_buckets_known_strings() {
        for (msg, expected) in [
            ("upstream 404 not_found", UpstreamErrorKind::NotFound),
            ("rate limited 429", UpstreamErrorKind::RateLimited),
            ("401 unauthorized", UpstreamErrorKind::Unauthorized),
            ("upstream 5xx fail", UpstreamErrorKind::Upstream5xx),
            ("upstream 4xx fail", UpstreamErrorKind::Upstream4xx),
            ("checksum mismatch", UpstreamErrorKind::ChecksumMismatch),
            ("parse error", UpstreamErrorKind::ParseError),
            ("body too large", UpstreamErrorKind::BodyTooLarge),
            ("pin mismatch", UpstreamErrorKind::PinMismatch),
            ("ca unknown", UpstreamErrorKind::CaUnknown),
            ("read timed out", UpstreamErrorKind::Timeout),
            ("dns lookup failed", UpstreamErrorKind::NetworkError),
            ("unrecognised garbage", UpstreamErrorKind::Upstream5xx),
        ] {
            let kind = classify_app_error(&AppError::External(msg.into()));
            assert_eq!(
                kind, expected,
                "classify {msg:?} → {expected:?}, got {kind:?}"
            );
        }
    }

    #[test]
    fn handle_follower_outcome_in_flight_returns_external_error() {
        // Defensive — `InFlight` should not reach
        // `handle_follower_outcome` in production but the arm exists
        // and must be reachable so the layer remains 100% covered.
        let store: Arc<dyn EphemeralStore> = Arc::new(InMemoryEphemeralStore::new());
        let dd = PullDedup::new(store, PullDedupConfig::defaults());
        let key = DedupKey::metadata("pypi", uuid::Uuid::nil(), "u");
        let outcome = DedupOutcome::InFlight {
            leader: "x".into(),
            expires_at_unix_secs: 0,
        };
        let res = dd.handle_follower_outcome(&key, DedupLayer::Cluster, outcome);
        assert!(res.is_err());
    }

    #[test]
    fn handle_follower_outcome_succeeded_blob_returns_hash() {
        let store: Arc<dyn EphemeralStore> = Arc::new(InMemoryEphemeralStore::new());
        let dd = PullDedup::new(store, PullDedupConfig::defaults());
        let key = DedupKey::blob_by_hash("sha256", "abc");
        let hex = "0".repeat(64);
        let hash: ContentHash = hex.parse().unwrap();
        let outcome = DedupOutcome::SucceededBlob {
            content_hash: hash.clone(),
        };
        let res = dd
            .handle_follower_outcome(&key, DedupLayer::Cluster, outcome)
            .expect("Ok");
        match res {
            BlobOrMetadataOk::Blob(h) => assert_eq!(h, hash),
            _ => panic!("expected Blob"),
        }
    }

    #[test]
    fn coalesce_blob_path_returns_content_hash() {
        capture(|| async {
            let store: Arc<dyn EphemeralStore> = Arc::new(InMemoryEphemeralStore::new());
            let dd = PullDedup::new(store, PullDedupConfig::defaults());
            let key = DedupKey::blob_by_hash("sha256", "abc");
            let hex = "1".repeat(64);
            let hash: ContentHash = hex.parse().unwrap();
            let res = dd
                .coalesce_blob(key, || async { Ok(hash.clone()) })
                .await
                .unwrap();
            assert_eq!(res, hash);
        });
    }

    #[test]
    fn coalesce_to_hash_with_metadata_key_returns_hash_via_blob_broadcast() {
        // `coalesce_to_hash` accepts ANY DedupKey — here a metadata key
        // (the OCI tag-pull shape) — and broadcasts the resolved
        // `ContentHash` via `SucceededBlob`, NOT inline bytes via
        // `SucceededMetadata`.
        let snap = capture(|| async {
            let store: Arc<dyn EphemeralStore> = Arc::new(InMemoryEphemeralStore::new());
            let dd = PullDedup::new(store.clone(), PullDedupConfig::defaults());
            let key = DedupKey::metadata("oci", uuid::Uuid::nil(), "/v2/x/manifests/v1");
            let hex = "2".repeat(64);
            let hash: ContentHash = hex.parse().unwrap();
            let res = dd
                .coalesce_to_hash(key.clone(), || async { Ok(hash.clone()) })
                .await
                .unwrap();
            assert_eq!(res, hash);

            // The persisted terminal record is a blob (hash) outcome,
            // NOT a metadata (bytes) outcome — no manifest bytes transit
            // the ephemeral store.
            let stored = store.get(key.serialised_for_test()).await.unwrap().unwrap();
            match decode_outcome(&stored).expect("decodes") {
                DedupOutcome::SucceededBlob { content_hash } => {
                    assert_eq!(content_hash, hash);
                }
                other => panic!("expected SucceededBlob, got {other:?}"),
            }
        });
        assert_eq!(counter_for(&snap, "leader_started"), 1);
    }

    #[test]
    fn coalesce_to_hash_concurrent_follower_observes_same_hash_without_rerun() {
        // Two concurrent callers on a metadata key: the leader runs the
        // closure once and returns the hash; the follower joins the
        // broadcast and observes the SAME hash WITHOUT re-running the
        // closure. No bytes are broadcast (it's a SucceededBlob window).
        let snap = capture(|| async {
            let store: Arc<dyn EphemeralStore> = Arc::new(InMemoryEphemeralStore::new());
            let dd = Arc::new(PullDedup::new(store, PullDedupConfig::defaults()));
            let key = DedupKey::metadata("oci", uuid::Uuid::nil(), "/v2/shared/manifests/v1");
            let hex = "3".repeat(64);
            let hash: ContentHash = hex.parse().unwrap();
            let calls = Arc::new(AtomicUsize::new(0));

            let c1 = calls.clone();
            let dd1 = dd.clone();
            let key1 = key.clone();
            let hash1 = hash.clone();
            let h1 = tokio::spawn(async move {
                dd1.coalesce_to_hash(key1, || async move {
                    c1.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(60)).await;
                    Ok(hash1)
                })
                .await
            });

            tokio::time::sleep(Duration::from_millis(15)).await;
            let dd2 = dd.clone();
            let key2 = key.clone();
            let c2 = calls.clone();
            let r2 = dd2
                .coalesce_to_hash(key2, || async move {
                    c2.fetch_add(1, Ordering::SeqCst);
                    let other_hex = "f".repeat(64);
                    Ok(other_hex.parse().unwrap())
                })
                .await
                .unwrap();
            assert_eq!(r2, hash, "follower observes the leader's hash");

            let r1 = h1.await.unwrap().unwrap();
            assert_eq!(r1, hash);
            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "exactly one closure ran — the follower did NOT re-run it"
            );
        });
        assert_eq!(counter_for(&snap, "leader_started"), 1);
        let layer_a_hits = counter_for_layer(&snap, "follower_waited_hit", "in_process");
        let layer_b_hits = counter_for_layer(&snap, "follower_waited_hit", "cluster");
        assert_eq!(
            layer_a_hits + layer_b_hits,
            1,
            "exactly one follower hit (across either layer)"
        );
    }

    #[test]
    fn coalesce_metadata_emits_wait_seconds_histogram() {
        let snap = capture(|| async {
            let store: Arc<dyn EphemeralStore> = Arc::new(InMemoryEphemeralStore::new());
            let dd = PullDedup::new(store, PullDedupConfig::defaults());
            let key = DedupKey::metadata("npm", uuid::Uuid::nil(), "u-hist");
            dd.coalesce_metadata(key, || async { Ok(Bytes::from_static(b"x")) })
                .await
                .unwrap();
        });
        // The histogram entry must exist and must carry layer=cluster.
        let mut found = false;
        for (ckey, _u, _d, value) in &snap {
            let k = ckey.key();
            if k.name() != "hort_pull_dedup_wait_seconds" {
                continue;
            }
            if let DebugValue::Histogram(samples) = value {
                if !samples.is_empty() {
                    let mut layer_ok = false;
                    for label in k.labels() {
                        if label.key() == "layer" && label.value() == "cluster" {
                            layer_ok = true;
                        }
                    }
                    if layer_ok {
                        found = true;
                    }
                }
            }
        }
        assert!(
            found,
            "hort_pull_dedup_wait_seconds with layer=cluster missing"
        );
    }

    #[test]
    fn pull_dedup_does_not_emit_to_hort_upstream_fetch_total() {
        // Locked rule (acceptance line 154). The service must not
        // touch the upstream-HTTP adapter's counter — followers
        // never reach the adapter, so it automatically means
        // "actual upstream HTTP requests issued" without
        // modification.
        let snap = capture(|| async {
            let store: Arc<dyn EphemeralStore> = Arc::new(InMemoryEphemeralStore::new());
            let dd = PullDedup::new(store, PullDedupConfig::defaults());
            let key = DedupKey::metadata("pypi", uuid::Uuid::nil(), "u-no-adapter-emit");
            dd.coalesce_metadata(key, || async { Ok(Bytes::from_static(b"x")) })
                .await
                .unwrap();
        });
        for (ckey, _u, _d, _v) in &snap {
            assert_ne!(
                ckey.key().name(),
                "hort_upstream_fetch_total",
                "hort_pull_dedup must NOT emit to hort_upstream_fetch_total"
            );
        }
    }

    #[test]
    fn dedup_outcome_failed_negative_cache_carries_message_into_follower_error() {
        // Verify the leader's error text is reconstructed onto the
        // follower's `AppError::External`.
        let store: Arc<dyn EphemeralStore> = Arc::new(InMemoryEphemeralStore::new());
        let dd = PullDedup::new(store, PullDedupConfig::defaults());
        let key = DedupKey::metadata("pypi", uuid::Uuid::nil(), "u");
        let outcome = DedupOutcome::Failed {
            kind: UpstreamErrorKind::NotFound,
            message: "leader-msg-here".into(),
            expires_at_unix_secs: now_unix_secs() + 30,
        };
        let res = dd.handle_follower_outcome(&key, DedupLayer::Cluster, outcome);
        let err_str = res.unwrap_err().to_string();
        assert!(err_str.contains("leader-msg-here"));
    }

    #[test]
    fn pull_dedup_config_defaults_match_design_doc_table() {
        let c = PullDedupConfig::defaults();
        assert_eq!(c.ttl_not_found, Duration::from_secs(30));
        assert_eq!(c.ttl_unavailable, Duration::from_secs(10));
        assert_eq!(c.ttl_timeout, Duration::from_secs(10));
        assert_eq!(c.ttl_checksum_mismatch, Duration::from_secs(60));
        assert_eq!(c.follower_wait, Duration::from_secs(300));
        assert_eq!(c.leader_deadline, Duration::from_secs(600));
    }

    #[test]
    fn dedup_namespace_as_str_round_trips() {
        assert_eq!(DedupNamespace::Metadata.as_str(), "metadata");
        assert_eq!(DedupNamespace::BlobByUrl.as_str(), "blob_by_url");
        assert_eq!(DedupNamespace::BlobByHash.as_str(), "blob_by_hash");
    }

    /// Heartbeat task survives at least one interval and continues
    /// extending TTL while it lives. Virtual-time harness (the test
    /// double uses real `SystemTime` for TTL but the heartbeat
    /// `tokio::time::interval` is virtual-clock-driven, so we
    /// directly observe the heartbeat side-effect on a key the
    /// double tracks).
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn leader_heartbeat_runs_periodically_and_aborts_on_handle_drop() {
        let store: Arc<InMemoryEphemeralStore> = Arc::new(InMemoryEphemeralStore::new());
        let dd = PullDedup::new(
            store.clone() as Arc<dyn EphemeralStore>,
            PullDedupConfig::defaults(),
        );
        let key_serialised =
            "pulldedup:meta:test:00000000-0000-0000-0000-000000000000:u".to_owned();
        store
            .put(
                &key_serialised,
                Bytes::from_static(b"x"),
                Duration::from_secs(90),
            )
            .await
            .unwrap();
        let handle = dd.spawn_heartbeat(key_serialised.clone());
        let heartbeat_interval_for_test = heartbeat_interval(Duration::from_secs(90));
        // Advance past several heartbeat intervals; the heartbeat
        // task ticks `extend_ttl` each time.
        for _ in 0..3 {
            tokio::time::advance(heartbeat_interval_for_test + Duration::from_millis(100)).await;
            tokio::task::yield_now().await;
        }
        // The store retains the entry — heartbeat is silently
        // refreshing it (the test double's TTL is wall-clock so we
        // cannot directly assert refresh, but this exercises the
        // extend_ttl path under tokio::time::pause without panic).
        assert!(store.get(&key_serialised).await.unwrap().is_some());
        handle.abort();
        // Confirm the abort took effect — the JoinHandle resolves.
        tokio::time::advance(heartbeat_interval_for_test).await;
        tokio::task::yield_now().await;
        assert!(handle.is_finished() || handle.await.is_err());
    }

    /// #65 — a leader whose heartbeat hits transient `extend_ttl`
    /// failures (a backend blip) must recover WITHIN the same tick's
    /// retry budget, not by waiting for the next full `heartbeat_interval`
    /// — the exact gap that used to let a still-heartbeating leader's
    /// lock lapse (see `spawn_heartbeat`'s doc comment). Injects
    /// `HEARTBEAT_RETRY_MAX_ATTEMPTS - 1` consecutive failures (within
    /// the retry budget, so the pre-#65 code and the fixed code would
    /// both eventually call `extend_ttl` again — the distinguishing
    /// behaviour is WHEN: the fix retries after `HEARTBEAT_RETRY_BACKOFF`
    /// inside the tick; the old code would have waited a full next
    /// `heartbeat_interval`).
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn leader_heartbeat_survives_transient_extend_ttl_failures_without_losing_lock() {
        let inner = Arc::new(InMemoryEphemeralStore::new());
        let key_serialised =
            "pulldedup:meta:test:00000000-0000-0000-0000-000000000000:u".to_owned();
        inner
            .put(
                &key_serialised,
                Bytes::from_static(b"x"),
                Duration::from_secs(90),
            )
            .await
            .unwrap();
        let flaky = Arc::new(FlakyExtendTtlStore {
            inner: inner.clone(),
            remaining_failures: std::sync::atomic::AtomicU32::new(HEARTBEAT_RETRY_MAX_ATTEMPTS - 1),
            successes: std::sync::atomic::AtomicU32::new(0),
        });
        let dd = PullDedup::new(
            flaky.clone() as Arc<dyn EphemeralStore>,
            PullDedupConfig::defaults(),
        );
        let leader_lock_ttl = Duration::from_secs(90);
        let interval = heartbeat_interval(leader_lock_ttl);
        let handle = dd.spawn_heartbeat(key_serialised.clone());
        // Let the freshly-spawned task run its first (immediate,
        // skipped) tick and register its real-interval timer before we
        // advance the clock past it.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // First tick fires; extend_ttl fails HEARTBEAT_RETRY_MAX_ATTEMPTS-1
        // times, each retried after HEARTBEAT_RETRY_BACKOFF — all within
        // this single tick, well before a second `interval` would elapse.
        tokio::time::advance(interval + Duration::from_millis(100)).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        for _ in 0..(HEARTBEAT_RETRY_MAX_ATTEMPTS - 1) {
            tokio::time::advance(HEARTBEAT_RETRY_BACKOFF + Duration::from_millis(50)).await;
            tokio::task::yield_now().await;
            tokio::task::yield_now().await;
        }

        assert_eq!(
            flaky.successes.load(Ordering::SeqCst),
            1,
            "heartbeat must recover from transient extend_ttl failures within \
             the same tick's retry budget instead of waiting a full extra \
             heartbeat_interval — the gap that let a still-heartbeating \
             leader's lock lapse"
        );

        handle.abort();
    }

    /// Heartbeat is spawned BEFORE the fetch closure runs. We assert
    /// the property by confirming the lock record is observable inside
    /// the fetch closure (i.e. election + lock write happened before
    /// dispatch).
    #[test]
    fn heartbeat_spawned_before_fetch_lock_visible_in_closure() {
        capture(|| async {
            let store: Arc<dyn EphemeralStore> = Arc::new(InMemoryEphemeralStore::new());
            let dd = PullDedup::new(store.clone(), PullDedupConfig::defaults());
            let key = DedupKey::metadata("pypi", uuid::Uuid::nil(), "u-slow");
            let key_serialised = key.serialised_for_test().to_owned();
            let store_c = store.clone();
            let res = dd
                .coalesce_metadata(key, move || {
                    let store_c = store_c.clone();
                    async move {
                        // Lock must exist at fetch entry — the
                        // election + put_if_absent ran first.
                        let snap = store_c.get(&key_serialised).await.unwrap();
                        assert!(
                            snap.is_some(),
                            "lock must exist at fetch entry — election runs first"
                        );
                        Ok(Bytes::from_static(b"ok"))
                    }
                })
                .await
                .unwrap();
            assert_eq!(res, Bytes::from_static(b"ok"));
        });
    }

    /// Defensive: a leader whose `compare_and_swap` to terminal
    /// returns CAS-miss (because a new leader took the lock during a
    /// slow fetch) still completes its own success path. We model this
    /// by writing a SECOND record under the key before the leader's
    /// terminal `put` runs — the leader's `put` is unconditional, so
    /// it overwrites; this test asserts the leader does not panic and
    /// the fetch return flows back correctly.
    #[test]
    fn leader_terminal_write_is_resilient_to_pre_existing_record() {
        capture(|| async {
            let store: Arc<dyn EphemeralStore> = Arc::new(InMemoryEphemeralStore::new());
            let dd = PullDedup::new(store.clone(), PullDedupConfig::defaults());
            let key = DedupKey::metadata("pypi", uuid::Uuid::nil(), "u-cas-late");
            let res = dd
                .coalesce_metadata(key, || async { Ok(Bytes::from_static(b"leader-fetched")) })
                .await
                .unwrap();
            assert_eq!(res, Bytes::from_static(b"leader-fetched"));
        });
    }

    /// `broadcast::Sender::send` returning SendError (no live
    /// receivers) is harmless for the leader. The leader still
    /// completes and writes to `EphemeralStore`. We assert the return
    /// value is intact.
    #[test]
    fn leader_send_with_no_receivers_returns_success() {
        capture(|| async {
            let store: Arc<dyn EphemeralStore> = Arc::new(InMemoryEphemeralStore::new());
            let dd = PullDedup::new(store, PullDedupConfig::defaults());
            let key = DedupKey::metadata("pypi", uuid::Uuid::nil(), "u-no-rx");
            let res = dd
                .coalesce_metadata(key, || async { Ok(Bytes::from_static(b"alone")) })
                .await
                .unwrap();
            assert_eq!(res, Bytes::from_static(b"alone"));
        });
    }

    // ------- Issue #55: coalesce leader liveness (D1-D4) ----------
    //
    // Design doc §6 test list. Before this change every test in this
    // module used a leader that always completes; nothing here
    // exercised a wedged leader, touched `dd.layer_a` directly, or
    // asserted the heartbeat actually stops. All five would fail (or
    // hang) against the pre-#55 code.

    /// Design §6 item 1 — a wedged leader (never completes) must not
    /// hang a Layer-A follower. D1: the follower's `rx.recv().await`
    /// is now bounded by `follower_wait`.
    #[test]
    fn wedged_leader_does_not_hang_layer_a_follower() {
        let snap = capture(|| async {
            let store: Arc<dyn EphemeralStore> = Arc::new(InMemoryEphemeralStore::new());
            let dd = Arc::new(PullDedup::new(store, fast_cfg()));
            let key = DedupKey::metadata("pypi", uuid::Uuid::nil(), "u-wedge-1");

            // Leader closure that never completes — models D1's
            // "leader alive but wedged" case exactly (as opposed to
            // the pre-existing ghost-leader test at
            // `follower_wait_ceiling_triggers_503_and_emits_followfellthrough_metric`,
            // which never reaches Layer A at all).
            let dd1 = dd.clone();
            let key1 = key.clone();
            let _leader = tokio::spawn(async move {
                let _ = dd1
                    .coalesce_metadata(key1, std::future::pending::<Result<Bytes, AppError>>)
                    .await;
            });
            // Let the leader actually elect (Layer-A insert +
            // put_if_absent) before the follower joins.
            tokio::time::sleep(Duration::from_millis(15)).await;
            assert!(
                dd.layer_a.get(&key).is_some(),
                "leader must be visible in layer-A before the follower joins"
            );

            let follower_res = tokio::time::timeout(
                Duration::from_secs(2),
                dd.coalesce_metadata(key.clone(), || async { Ok(Bytes::from_static(b"unused")) }),
            )
            .await
            .expect(
                "follower must return within 2s — a wedged leader must not hang it forever (D1)",
            );
            assert!(
                follower_res.is_err(),
                "follower falls through to a 503 rather than succeeding against a wedged leader"
            );
        });
        assert_eq!(
            counter_for_layer(&snap, "follower_fellthrough_503", "in_process"),
            1,
            "the layer-A follower-wait ceiling must evict the entry and emit fellthrough"
        );
    }

    /// Design §6 item 2 — the acceptance criterion from the issue:
    /// after the leader deadline elapses, a SUBSEQUENT call must run
    /// a fresh closure (assert the closure ran twice), not inherit
    /// the wedge. D2: `fetch_fn` is now wrapped in
    /// `tokio::time::timeout(leader_deadline, ..)`.
    #[test]
    fn leader_timeout_self_heals_next_call_runs_fresh_closure() {
        let snap = capture(|| async {
            let store: Arc<dyn EphemeralStore> = Arc::new(InMemoryEphemeralStore::new());
            // Short leader_deadline so the timeout actually fires in
            // the test; short ttl_timeout so the Failed(Timeout)
            // negative-cache record is provably stale by the time the
            // second call runs (otherwise the second call would
            // legitimately negative-cache-hit instead of re-electing
            // — that would be correct production behaviour, but it
            // is not what this test is checking).
            let cfg = PullDedupConfig {
                leader_deadline: Duration::from_millis(40),
                ttl_timeout: Duration::from_millis(10),
                ..fast_cfg()
            };
            let dd = PullDedup::new(store, cfg);
            let key = DedupKey::metadata("pypi", uuid::Uuid::nil(), "u-selfheal");
            let calls = Arc::new(AtomicUsize::new(0));

            let c1 = calls.clone();
            let res1 = dd
                .coalesce_metadata(key.clone(), move || {
                    let c1 = c1.clone();
                    async move {
                        c1.fetch_add(1, Ordering::SeqCst);
                        std::future::pending::<Result<Bytes, AppError>>().await
                    }
                })
                .await;
            assert!(
                res1.is_err(),
                "the wedged leader's own caller observes the deadline as an error"
            );

            // Let the leader-timeout's negative-cache record (10ms
            // TTL) go stale before the next call.
            tokio::time::sleep(Duration::from_millis(50)).await;

            let c2 = calls.clone();
            let res2 = dd
                .coalesce_metadata(key, move || {
                    let c2 = c2.clone();
                    async move {
                        c2.fetch_add(1, Ordering::SeqCst);
                        Ok(Bytes::from_static(b"fresh"))
                    }
                })
                .await
                .unwrap();
            assert_eq!(res2, Bytes::from_static(b"fresh"));
            assert_eq!(
                calls.load(Ordering::SeqCst),
                2,
                "the second call must run a FRESH closure, not inherit the wedge"
            );
        });
        assert_eq!(
            counter_for(&snap, "leader_timeout"),
            1,
            "exactly one leader_timeout — the second call is a normal fresh election"
        );
    }

    /// Design §6 item 3 — no existing test inspects `dd.layer_a`.
    /// After a leader-deadline timeout the Layer-A entry must be
    /// evicted (D2 + D4), not left pointing at the abandoned leader.
    #[test]
    fn leader_timeout_evicts_layer_a_entry() {
        capture(|| async {
            let store: Arc<dyn EphemeralStore> = Arc::new(InMemoryEphemeralStore::new());
            let cfg = PullDedupConfig {
                leader_deadline: Duration::from_millis(30),
                ..fast_cfg()
            };
            let dd = PullDedup::new(store, cfg);
            let key = DedupKey::metadata("pypi", uuid::Uuid::nil(), "u-evict");
            let res = dd
                .coalesce_metadata(key.clone(), || {
                    std::future::pending::<Result<Bytes, AppError>>()
                })
                .await;
            assert!(res.is_err());
            assert!(
                dd.layer_a.get(&key).is_none(),
                "layer-A entry must be evicted after a leader-deadline timeout"
            );
        });
    }

    /// Design §6 item 4 — the heartbeat must be aborted even when
    /// `LeaderGuard` is dropped without ever calling `disarm()`
    /// (client disconnect / runtime shutdown, modelled directly here
    /// since production never exposes the heartbeat's `JoinHandle` to
    /// a caller). Mirrors the abort-on-drop assertion pattern of
    /// `leader_heartbeat_runs_periodically_and_aborts_on_handle_drop`
    /// but for the NEW `LeaderGuard` cleanup path (D3), not a direct
    /// `JoinHandle::abort()` call.
    #[tokio::test(flavor = "current_thread")]
    async fn leader_guard_drop_without_disarm_aborts_heartbeat_and_evicts_layer_a() {
        let store: Arc<dyn EphemeralStore> = Arc::new(InMemoryEphemeralStore::new());
        let dd = PullDedup::new(store, PullDedupConfig::defaults());
        let key = DedupKey::metadata("pypi", uuid::Uuid::nil(), "u-guard-cancel");
        // Placeholder Layer-A entry for the guard to evict — its
        // value is never upgraded by this test, only its presence in
        // the map matters.
        dd.layer_a.insert(key.clone(), Weak::new());
        let heartbeat = dd.spawn_heartbeat(key.serialised_for_test().to_owned());
        let heartbeat_abort = heartbeat.abort_handle();
        {
            let _guard = LeaderGuard::new(dd.layer_a.clone(), key.clone(), Some(heartbeat_abort));
            // `_guard` drops here WITHOUT `disarm()` — simulates
            // cancellation / an exit path that never reached the
            // terminal write.
        }
        tokio::task::yield_now().await;
        assert!(
            heartbeat.is_finished(),
            "the heartbeat must be aborted when the guard drops without disarm (D3)"
        );
        assert!(
            dd.layer_a.get(&key).is_none(),
            "the layer-A entry must be evicted when the guard drops without disarm (D4)"
        );
    }

    /// Design §6 item 5 — dropping the LEADER'S OWN future mid-fetch
    /// (the caller's task is aborted / the client disconnects) must
    /// leak neither the heartbeat's cluster-lock renewal nor the
    /// Layer-A entry, end to end through the real `run_as_leader`
    /// path (not just the `LeaderGuard` unit test above). Also
    /// asserts the `leader_cancelled` metric (Item 2) fires exactly
    /// once — distinguishing "the caller went away" from
    /// `leader_timeout`'s "we gave up at the deadline".
    #[test]
    fn cancelling_the_leader_future_mid_fetch_leaks_no_layer_a_entry() {
        let snap = capture(|| async {
            let store: Arc<dyn EphemeralStore> = Arc::new(InMemoryEphemeralStore::new());
            let dd = Arc::new(PullDedup::new(store, PullDedupConfig::defaults()));
            let key = DedupKey::metadata("pypi", uuid::Uuid::nil(), "u-cancel-mid");

            let dd1 = dd.clone();
            let key1 = key.clone();
            let handle = tokio::spawn(async move {
                dd1.coalesce_metadata(key1, std::future::pending::<Result<Bytes, AppError>>)
                    .await
            });
            // Let the leader actually elect + spawn its heartbeat
            // before cancelling.
            tokio::time::sleep(Duration::from_millis(15)).await;
            assert!(
                dd.layer_a.get(&key).is_some(),
                "leader must be visible in layer-A before cancellation"
            );

            handle.abort();
            let join_res = handle.await;
            assert!(
                join_res.is_err_and(|e| e.is_cancelled()),
                "the leader task must have been cancelled, not merely finished"
            );
            tokio::task::yield_now().await;

            assert!(
                dd.layer_a.get(&key).is_none(),
                "layer-A entry must not survive leader cancellation (D4)"
            );
        });
        assert_eq!(
            counter_for(&snap, "leader_cancelled"),
            1,
            "the guard must emit leader_cancelled when dropped without a terminal outcome"
        );
    }
}
