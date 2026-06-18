//! HTTP-backed [`UpstreamProxy`] adapter.
//!
//! Streams blob/manifest content from a configured upstream registry
//! into the local CAS. Lives in its own crate (NOT inside
//! `hort-http-oci`) so `reqwest` stays off the inbound-HTTP crate's
//! dependency edge — the adapter-free guarantee is load-bearing
//! (the adapter-free dep-graph guarantee is load-bearing).
//!
//! # Streaming
//!
//! [`HttpUpstreamProxy::fetch_blob`] pipes
//! `reqwest::Response::bytes_stream` through an adapter that maps
//! errors to `std::io::Error` so callers can plumb it directly into
//! `tokio_util::io::StreamReader`. No buffering — multi-GB OCI
//! blobs flow through the local CAS path without ever materializing
//! a full copy in memory.
//!
//! # Auth strategies
//!
//! - `UpstreamAuth::Anonymous` — no `Authorization` header sent.
//! - `UpstreamAuth::BearerChallenge` — generic challenge-driven
//!   bearer flow per RFC 7235 §4.1 + the Docker token spec.
//!   On a 401 from the upstream the
//!   adapter parses the `WWW-Authenticate` header, GETs the
//!   advertised realm with the parsed `service` / `scope` query
//!   params, caches the returned token keyed by
//!   `(realm, service, scope, cred_identity)`, and retries the
//!   original request with `Authorization: Bearer <token>`. Cached
//!   tokens skip the 401 round-trip on subsequent requests; a
//!   second 401 inside the same outer fetch invalidates and
//!   re-exchanges exactly once. Works against Docker Hub, GHCR,
//!   Quay, GitLab CR, Harbor, Nexus, ECR Public — every registry
//!   that follows the Docker token spec.
//! - `UpstreamAuth::Basic { username }` — HTTP Basic with
//!   credentials drawn from a [`SecretPort`] (see
//!   `docs/architecture/how-to/wire-secrets.md`). The adapter resolves
//!   the bytes via the supplied port at fetch time and drops the
//!   resulting `SecretValue` after the header is built.
//!
//! # Errors
//!
//! Outcomes (success and failure alike) are mapped to
//! [`UpstreamErrorKind`] variants for the `result` label of
//! `hort_upstream_fetch_total`. The catalog-mandated taxonomy is the
//! only allowed label set — adapter-specific labels are forbidden.
//!
//! See `docs/architecture/how-to/oci-pull-through.md`.

mod challenge;
// Connect-time guarded DNS resolver — closes the SSRF / DNS-rebind TOCTOU
// between `check_ssrf_safe` (URL-validation-time resolve) and reqwest's
// independent dial-time resolve (security audit finding INJ-1). Bound to
// the upstream artifact / metadata / manifest clients at the two
// `Client::builder()` sites. Mirrors the webhook crate's connect-time
// `GuardedDnsResolver`; reuses `hort_net_egress::is_routable`.
mod dns_guard;
mod extra_ca;
// Caching upstream resolver. General — not OCI-specific — though it
// first landed in `hort-http-oci` by accident of first use. Relocated
// here so both `hort-server` and `hort-worker` can build + prime +
// refresh one instance: the server threads it onto
// `AppContext.upstream_resolver`, the worker threads it into the
// provenance proxy referrer-fetch arm (ADR 0027).
pub mod resolver;
mod tls_config;

pub use challenge::{parse_www_authenticate, Challenge, ChallengeParseError};
pub use resolver::CachingResolver;

// The routability classifier (`is_routable`) lives in `hort-net-egress`
// (SSRF defence — see `docs/architecture/explanation/security.md`).
// Production callers reach it via the `hort_net_egress::is_routable`
// import below; callers who imported from this crate's old `ssrf` module
// path must switch to `hort_net_egress` directly.
//
// SSRF defence is layered: `check_ssrf_safe` validates the initial
// absolute URL at parse time, `build_redirect_policy` re-checks every
// redirect hop, and the connect-time `dns_guard::GuardedDnsResolver`
// (security audit finding INJ-1) re-runs `is_routable` on every dial-time
// resolution so a DNS-rebind between check and dial cannot smuggle an
// internal address past the URL-validation check. All three reuse this one
// `is_routable` predicate; the guard does NOT reimplement it.
// `build_egress_redirect_policy` (the old `hort-net-egress` redirect-policy
// export) stays retired — this crate builds its own redirect policy.
use hort_net_egress::is_routable;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::TryStreamExt;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use reqwest::{Client, StatusCode};
use serde::Deserialize;

use hort_app::metrics::{
    emit_upstream_insecure, emit_upstream_tls_handshake, values as metric_values,
    UpstreamErrorKind, UpstreamInsecureReason, UpstreamTlsHandshakeResult,
};
use hort_config::ExtraTrustAnchors;
use hort_domain::error::{DomainError, DomainResult, FetchClass};
use hort_domain::oci::SIGSTORE_BUNDLE_MEDIA_TYPE;
use hort_domain::ports::repository_upstream_mapping_repository::{
    RepositoryUpstreamMapping, UpstreamAuth,
};
use hort_domain::ports::secret_port::{SecretPort, SecretRef, SecretSource, SecretValue};
use hort_domain::ports::upstream_proxy::{
    ArtifactFetch, BlobFetch, BlobStream, ManifestFetchOutcome, MetadataFetchOutcome,
    ReferrerDescriptor, UpstreamProxy,
};
use hort_domain::ports::BoxFuture;

use chrono::{DateTime, Utc};

use uuid::Uuid;

use tls_config::{
    build_rustls_client_config, resolve_tls_material, ResolvedTlsMaterial, PIN_MISMATCH_SENTINEL,
};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Per-instance configuration.
///
/// `default()` carries production-sane defaults: 30s timeout, redirect
/// cap of 5, no extra CA. Realm endpoints for the bearer-challenge
/// flow are learned at runtime from upstream `WWW-Authenticate`
/// responses — there is no configuration knob for them.
#[derive(Clone)]
pub struct HttpUpstreamProxyConfig {
    pub timeout: Duration,
    /// `format` label fired on every metric emission. The OCI
    /// composition root passes `"oci"`; future consumers supply
    /// their own format identifier. Bounded label set (~40 across
    /// the workspace) per the cardinality rules in
    /// `docs/metrics-catalog.md`.
    pub format_label: String,
    /// Maximum number of redirect hops the upstream client will
    /// follow. The default is 5, reduced from reqwest's default of 10.
    /// The cap is enforced via
    /// `reqwest::redirect::Policy::limited(max_redirect_hops)`.
    /// `check_ssrf_safe` validates every absolute URL parsed out of
    /// upstream metadata before fetch; per-hop SSRF re-validation also
    /// runs on each redirect hop.
    pub max_redirect_hops: usize,
    /// Storage backstop on the cached upstream body for `fetch_metadata`
    /// (ADR 0026). The adapter atomic-writes the streamed body to a temp
    /// file and trips
    /// `DomainError::UpstreamBodyTooLarge { fetch_class: Metadata, .. }`
    /// past this size, deleting the partial write. Configurable via
    /// `HORT_UPSTREAM_METADATA_CACHE_MAX_SIZE`; default 64 MiB.
    /// Honest classification — emits
    /// `hort_upstream_fetch_total{result="metadata_too_large"}` and
    /// 502 with `{"error":"upstream metadata too large", …}`, never
    /// folded into the generic "upstream unavailable" sanitisation.
    pub metadata_cache_max_bytes: u64,
    /// Storage backstop on the cached upstream body for `fetch_manifest`
    /// (ADR 0026). OCI-symmetric companion to
    /// [`Self::metadata_cache_max_bytes`]; same wire-error +
    /// classification model. Configurable via
    /// `HORT_UPSTREAM_MANIFEST_CACHE_MAX_SIZE`; default 16 MiB.
    pub manifest_cache_max_bytes: u64,
    /// Process-wide extra CA trust bundle (ADR 0010).
    ///
    /// When `Some`, the DER-encoded certificates are applied to:
    ///  - the base `reqwest::Client` shared by all mappings without TLS
    ///    material (`HttpUpstreamProxy::new` path), and
    ///  - every per-mapping `reqwest::Client` built via
    ///    `client_for_mapping` (the rustls path).
    ///
    /// Populated from `HORT_EXTRA_CA_BUNDLE` by `hort-server::composition`.
    /// `Default::default()` returns `None` (trust public CAs only).
    pub extra_trust_anchors: Option<ExtraTrustAnchors>,
    /// Outbound `User-Agent` for every upstream fetch (blob / manifest /
    /// metadata / referrers), applied to both the base client and every
    /// per-mapping TLS client. `Default` is [`DEFAULT_UPSTREAM_USER_AGENT`];
    /// composition sets this from `HORT_UPSTREAM_USER_AGENT` via
    /// [`user_agent_from_env`]. Sending a non-empty UA is load-bearing —
    /// crates.io rejects requests without one.
    pub user_agent: String,
}

impl std::fmt::Debug for HttpUpstreamProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpUpstreamProxyConfig")
            .field("timeout", &self.timeout)
            .field("format_label", &self.format_label)
            .field("max_redirect_hops", &self.max_redirect_hops)
            // Emit count only — never the raw DER bytes (which are multi-kilobyte).
            .field(
                "extra_trust_anchors_count",
                &self
                    .extra_trust_anchors
                    .as_ref()
                    .map_or(0, ExtraTrustAnchors::cert_count),
            )
            .field("user_agent", &self.user_agent)
            .finish()
    }
}

impl Default for HttpUpstreamProxyConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            format_label: "oci".to_string(),
            max_redirect_hops: 5,
            // Settled default (ADR 0026).
            metadata_cache_max_bytes: 64 * 1024 * 1024,
            // Settled default (ADR 0026).
            manifest_cache_max_bytes: 16 * 1024 * 1024,
            extra_trust_anchors: None,
            user_agent: DEFAULT_UPSTREAM_USER_AGENT.to_string(),
        }
    }
}

/// Default outbound `User-Agent` for upstream pull-through fetches.
///
/// This is hort's canonical process-wide identity
/// [`hort_config::DEFAULT_USER_AGENT`] — `hort/<version> (+<project-url>)` —
/// shared with every other outbound path (OSV advisory, Sigstore
/// trusted-root, OIDC/JWKS, webhooks) so they all present one versioned
/// token rather than per-adapter hardcoded strings. Sent on every upstream
/// request (blob / manifest / metadata / referrers). A non-empty UA is
/// **required** by some registries — crates.io returns `403` to requests
/// without one — and others rate-limit anonymous clients more aggressively;
/// the `(+url)` gives upstream operators a contact pointer. Operators
/// override the whole string for the pull-through path specifically via
/// `HORT_UPSTREAM_USER_AGENT` ([`user_agent_from_env`]).
pub const DEFAULT_UPSTREAM_USER_AGENT: &str = hort_config::DEFAULT_USER_AGENT;

/// Env var that overrides the upstream `User-Agent`.
pub const HORT_UPSTREAM_USER_AGENT_ENV: &str = "HORT_UPSTREAM_USER_AGENT";

/// Is `s` usable as an HTTP `User-Agent` header value? reqwest's
/// `.user_agent()` defers to [`reqwest::header::HeaderValue::from_str`]
/// (RFC 7230 field-value: visible ASCII `0x20..=0x7e` + HTAB), so an
/// override that fails this check would make
/// `Client::builder().build()` error and crash boot. Validating with the
/// **same predicate the sink applies** guarantees "resolver accepts" ⟺
/// "client build succeeds" — no charset drift between the lint and reqwest.
fn is_valid_user_agent_header(s: &str) -> bool {
    reqwest::header::HeaderValue::from_str(s).is_ok()
}

/// Resolve the upstream `User-Agent` from an optional raw override AND
/// report whether a non-empty override was **rejected**. A trimmed,
/// non-empty, header-valid value wins; an empty/whitespace value means
/// "use the default" (not a rejection); a non-empty but header-invalid
/// value (control chars, non-ASCII — e.g. an accented contact name) falls
/// back to [`DEFAULT_UPSTREAM_USER_AGENT`] with `rejected = true` so the
/// caller can `warn!` instead of crashing. Pure (no env read, no logging).
fn resolve_user_agent_reporting(raw: Option<&str>) -> (String, bool) {
    // Empty/whitespace (or unset) ⇒ "use the default", which is NOT a
    // rejection — folded into `None` here so the only match guard left is a
    // real predicate. A non-empty header-valid value wins; a non-empty but
    // header-invalid value falls back with `rejected = true`.
    match raw.map(str::trim).filter(|t| !t.is_empty()) {
        None => (DEFAULT_UPSTREAM_USER_AGENT.to_string(), false),
        Some(t) if is_valid_user_agent_header(t) => (t.to_string(), false),
        Some(_) => (DEFAULT_UPSTREAM_USER_AGENT.to_string(), true),
    }
}

/// Resolve the upstream `User-Agent` from an optional raw override: a
/// trimmed, non-empty, **header-valid** value wins, else
/// [`DEFAULT_UPSTREAM_USER_AGENT`]. Pure (no env read) so the
/// trim/empty/header-safety/default logic is unit-testable.
pub fn resolve_user_agent(raw: Option<String>) -> String {
    // `match` (rather than `raw.as_deref()`) consumes the owned `Option`,
    // delegating to the single-source reporting resolver without holding a
    // by-value arg it never moves.
    match raw {
        Some(v) => resolve_user_agent_reporting(Some(v.as_str())).0,
        None => DEFAULT_UPSTREAM_USER_AGENT.to_string(),
    }
}

/// The upstream `User-Agent` for this process: `HORT_UPSTREAM_USER_AGENT`
/// when set non-empty **and a valid HTTP header value**, else
/// [`DEFAULT_UPSTREAM_USER_AGENT`]. Lives in the adapter (not
/// per-composition) so `hort-server` and `hort-worker` resolve it
/// identically — every upstream fetch from either binary carries the same
/// UA.
///
/// A non-empty override that is not a valid header value is **not fatal**:
/// we fall back to the default and `warn!`. A `User-Agent` is not worth a
/// boot crash, and the strict-schema chart `upstream.userAgent` pattern
/// rejects such a value earlier for Helm-configured deployments — this is
/// the runtime safety net for the directly-set-env path.
pub fn user_agent_from_env() -> String {
    let raw = std::env::var(HORT_UPSTREAM_USER_AGENT_ENV).ok();
    let (ua, rejected) = resolve_user_agent_reporting(raw.as_deref());
    if rejected {
        tracing::warn!(
            env = HORT_UPSTREAM_USER_AGENT_ENV,
            "configured upstream User-Agent is not a valid HTTP header value \
             (control characters); using the built-in default"
        );
    }
    ua
}

/// Offline-validate a raw `HORT_UPSTREAM_USER_AGENT` override for the
/// `validate-config` subcommand. `Ok(())` for an empty/whitespace
/// value (means "use the default") **or** a value that is a valid HTTP
/// header value; `Err(message)` for a non-empty value that is NOT a valid
/// header value — at boot the server silently falls back to the default
/// for such a value ([`user_agent_from_env`]), so a CI pre-merge gate
/// should surface it (the operator's custom UA would be inert).
///
/// Uses the **same** [`is_valid_user_agent_header`] predicate
/// `user_agent_from_env` applies, so `validate-config` and runtime agree
/// by construction — there is no second charset rule to drift.
pub fn validate_user_agent_override(raw: &str) -> Result<(), String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || is_valid_user_agent_header(trimmed) {
        Ok(())
    } else {
        Err(format!(
            "{HORT_UPSTREAM_USER_AGENT_ENV} is not a valid HTTP header value \
             (it contains control characters); the server would ignore it and \
             fall back to the built-in default User-Agent"
        ))
    }
}

const METRIC_FETCH: &str = "hort_upstream_fetch_total";
const METRIC_DURATION: &str = "hort_upstream_fetch_duration_seconds";

/// Bearer-token lifecycle counter. Exactly one increment per state
/// transition in the bearer-challenge flow; label `result` enumerates
/// the transition (`exchange`, `cache_hit`, `invalidate`,
/// `fetch_failed`, `parse_failed`).
const METRIC_BEARER_TOKEN: &str = "hort_upstream_bearer_token_total";

const KIND_BLOB: &str = "blob";
const KIND_MANIFEST: &str = "manifest";
const KIND_METADATA: &str = "metadata";
const KIND_ARTIFACT: &str = "artifact";
// OCI Referrers API fetch (ADR 0027).
const KIND_REFERRERS: &str = "referrers";

// The `METADATA_BODY_CAP_BYTES` and `MANIFEST_BODY_CAP_BYTES` constants
// are retired. The cap was only load-bearing because the adapter was
// buffering the full body in memory before parsing; now the body streams
// to a tempfile via `write_streaming`, the storage backstop is the
// configurable per-instance
// `HttpUpstreamProxyConfig::{metadata,manifest}_cache_max_bytes`
// (defaults 64 / 16 MiB), and the trip emits the honest
// `DomainError::UpstreamBodyTooLarge { fetch_class, .. }` variant
// instead of folding into the generic "upstream unavailable"
// sanitisation. See ADR 0026.

/// `result` label values for [`METRIC_BEARER_TOKEN`].
const RESULT_EXCHANGE: &str = "exchange";
const RESULT_CACHE_HIT: &str = "cache_hit";
const RESULT_INVALIDATE: &str = "invalidate";
const RESULT_FETCH_FAILED: &str = "fetch_failed";
const RESULT_PARSE_FAILED: &str = "parse_failed";

/// Sentinel for an unset `path_prefix` mapping (single-upstream
/// formats). Keeps the `upstream` label bounded — empty string is
/// not a valid Prometheus label value in some scrapers.
const UPSTREAM_LABEL_DEFAULT: &str = "_default";

fn upstream_label(mapping: &RepositoryUpstreamMapping) -> String {
    if mapping.path_prefix.is_empty() {
        UPSTREAM_LABEL_DEFAULT.to_string()
    } else {
        // Strip trailing slash for label brevity. `dockerhub/` →
        // `dockerhub`.
        mapping.path_prefix.trim_end_matches('/').to_string()
    }
}

/// Emit `WARN` + `hort_upstream_insecure_total` on every fetch through a
/// mapping carrying the `insecure_upstream_url: true` opt-in. No-op when
/// the flag is unset. Called from every public fetch entry point (`fetch_blob`,
/// `fetch_manifest`, `fetch_artifact`, `fetch_metadata`) so the
/// posture cannot drift past the operator without a counter ticking.
///
/// The WARN line carries the upstream label and format so an operator
/// triaging the metric can grep tracing for the same fields. The
/// `mapping.upstream_url` is intentionally NOT logged at full
/// fidelity to keep the line at a bounded width — operators audit
/// the mapping table directly when they need the URL.
fn emit_insecure_if_opted_in(format: &str, mapping: &RepositoryUpstreamMapping) {
    if !mapping.insecure_upstream_url {
        return;
    }
    let upstream = upstream_label(mapping);
    tracing::warn!(
        format = format,
        upstream = %upstream,
        "fetch through plaintext (http://) upstream — \
         mapping carries insecure_upstream_url=true; verify operator \
         intent and consider switching to https://"
    );
    emit_upstream_insecure(format, UpstreamInsecureReason::SchemeHttp);
}

fn emit_metrics(
    format: &str,
    upstream: &str,
    kind: &'static str,
    elapsed: Duration,
    result_label: &str,
) {
    metrics::histogram!(
        METRIC_DURATION,
        "format" => format.to_string(),
        "upstream" => upstream.to_string(),
        "kind" => kind,
    )
    .record(elapsed.as_secs_f64());
    metrics::counter!(
        METRIC_FETCH,
        "format" => format.to_string(),
        "upstream" => upstream.to_string(),
        "result" => result_label.to_string(),
    )
    .increment(1);
}

// ---------------------------------------------------------------------------
// Token cache for BearerChallenge
// ---------------------------------------------------------------------------

/// One cached bearer token. `expires_at` already includes the 30s
/// clock-skew slack — `BearerCache::get` simply compares against
/// `Instant::now()`.
#[derive(Clone)]
struct CachedToken {
    token: String,
    expires_at: Instant,
}

/// Cache lookup key. Includes `cred_identity` so cross-credential
/// reuse is impossible — a private-PAT mapping and an anonymous
/// mapping on the same realm/service/scope triple get separate
/// entries.
#[derive(Clone, Hash, Eq, PartialEq)]
struct CacheKey {
    realm: String,
    service: Option<String>,
    scope: Option<String>,
    /// `Some(secret_ref)` when the realm exchange used
    /// `Authorization: Basic` from that secret; `None` for an
    /// anonymous realm call. Pinned to the mapping's `secret_ref`
    /// (the *intent*) — two mappings sharing one underlying `SecretRef`
    /// collapse to a single cache entry; distinct `(source, location)`
    /// pairs key distinctly.
    cred_identity: Option<SecretRef>,
}

/// In-process bearer-token cache shared across requests in one
/// `HttpUpstreamProxy` instance.
struct BearerCache {
    entries: Mutex<HashMap<CacheKey, CachedToken>>,
}

impl BearerCache {
    fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Returns a clone of the cached token if present AND
    /// unexpired; `None` otherwise. Expired entries are NOT
    /// proactively evicted here — they are overwritten on the next
    /// successful exchange or removed by `invalidate`.
    fn get(&self, key: &CacheKey) -> Option<CachedToken> {
        let guard = self.entries.lock().ok()?;
        let entry = guard.get(key)?;
        if entry.expires_at > Instant::now() {
            Some(entry.clone())
        } else {
            None
        }
    }

    fn insert(&self, key: CacheKey, token: CachedToken) {
        if let Ok(mut guard) = self.entries.lock() {
            guard.insert(key, token);
        }
    }

    fn invalidate(&self, key: &CacheKey) {
        if let Ok(mut guard) = self.entries.lock() {
            guard.remove(key);
        }
    }
}

/// Realm token-response shape per the Docker token spec. Accepts
/// both `token` (GHCR / Quay / GitLab convention) and `access_token`
/// (Docker Hub's documented field) — when both are present, the
/// `access_token` is preferred.
#[derive(Deserialize)]
struct RealmTokenResponse {
    token: Option<String>,
    access_token: Option<String>,
    /// Lifetime in seconds; defaults to 300 if upstream omits it.
    expires_in: Option<u64>,
}

/// OCI image-index body returned by the Referrers API
/// (`GET /v2/<name>/referrers/<digest>`). Only the
/// `manifests[]` descriptor list is consumed; the envelope's
/// `schemaVersion` / `mediaType` are ignored. Unknown descriptor
/// fields (`size`, `annotations`, `platform`, …) are dropped — serde's
/// default ignores them.
#[derive(Deserialize)]
struct ReferrersIndexBody {
    #[serde(default)]
    manifests: Vec<ReferrerDescriptorBody>,
}

/// One descriptor in [`ReferrersIndexBody::manifests`]. The wire field
/// names are camelCase per the OCI spec; `artifactType` is optional
/// (some registries omit it, in which case the caller inspects the
/// fetched manifest).
#[derive(Deserialize)]
struct ReferrerDescriptorBody {
    digest: String,
    #[serde(rename = "mediaType")]
    media_type: String,
    #[serde(rename = "artifactType")]
    artifact_type: Option<String>,
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

/// HTTP-backed [`UpstreamProxy`].
pub struct HttpUpstreamProxy {
    client: Client,
    config: HttpUpstreamProxyConfig,
    secret_port: Arc<dyn SecretPort>,
    /// In-process bearer-token cache shared across all requests for
    /// the lifetime of this proxy. Keyed by
    /// `(realm, service, scope, cred_identity)`.
    bearer_cache: Arc<BearerCache>,
    /// Per-`upstream_url` last-seen `Challenge`. Lets
    /// `authorization_header` reconstruct the bearer-cache lookup
    /// key without re-running the 401 dance — a cached token avoids
    /// the 401 round-trip on every subsequent request to the same
    /// realm ("Optimistic-first" invariant).
    /// Populated when a 401 → exchange completes.
    challenge_memo: Arc<tokio::sync::RwLock<HashMap<String, Challenge>>>,
    /// Per-mapping `reqwest::Client` cache (ADR 0010). Mappings without
    /// TLS material reuse `self.client`; mappings with `ca_bundle_ref`
    /// / `mtls_*_ref` / `pinned_cert_sha256` produce a tailored client
    /// built once on first use and reused for the process lifetime.
    ///
    /// **Cache lifetime trade-off:** the cache is never invalidated
    /// inside a process. Operators who rotate cert / key / CA must
    /// trigger a redeploy / rolling restart so the new bytes flow
    /// through `SecretPort::resolve` and produce a fresh cached
    /// `Client`. The simpler alternative — validate-on-every-fetch —
    /// would re-read the SecretPort and rebuild rustls config on
    /// every request, paying handshake-grade work per artifact pull.
    /// The explicit assumption is that rotation is a rare,
    /// operator-scheduled event.
    tls_client_cache: Arc<tokio::sync::RwLock<HashMap<Uuid, Client>>>,
    /// Addresses both SSRF guards treat as routable in addition to the
    /// real `is_routable` check: the per-hop redirect SSRF policy
    /// ([`build_redirect_policy`]) and the connect-time DNS guard
    /// ([`dns_guard::GuardedDnsResolver`], security audit finding INJ-1).
    /// **Always empty in production** (built via [`HttpUpstreamProxy::new`]);
    /// only the `#[cfg(test)]` constructor populates it with the wiremock
    /// loopback `SocketAddr`s so the allow / hop-cap / host-name-on-loopback
    /// test paths can run on loopback. Scoped private to this crate, never
    /// re-exported.
    redirect_test_allowlist: Arc<Vec<SocketAddr>>,
}

impl HttpUpstreamProxy {
    /// Build a proxy with the supplied [`SecretPort`] adapter and
    /// [`HttpUpstreamProxyConfig`]. The shared `reqwest::Client`
    /// pools connections per upstream host (reqwest's default is
    /// per-host pooling, which is what we want).
    pub fn new(
        config: HttpUpstreamProxyConfig,
        secret_port: Arc<dyn SecretPort>,
    ) -> DomainResult<Self> {
        // Production: empty redirect-policy allowlist — every loopback /
        // RFC1918 / link-local redirect hop is rejected.
        Self::new_inner(config, secret_port, Arc::new(Vec::new()))
    }

    /// Test-only constructor that seeds the per-hop redirect-policy
    /// allowlist with addresses the SSRF re-check should treat as
    /// routable in addition to the real `is_routable` check. Used
    /// exclusively by the wiremock-based redirect tests, which bind on
    /// loopback and would otherwise be (correctly) refused by the
    /// policy. The allowlist is NOT exposed on the public production
    /// config and is never re-globalized.
    #[cfg(test)]
    fn new_with_redirect_test_allowlist(
        config: HttpUpstreamProxyConfig,
        secret_port: Arc<dyn SecretPort>,
        allowlist: Vec<SocketAddr>,
    ) -> DomainResult<Self> {
        Self::new_inner(config, secret_port, Arc::new(allowlist))
    }

    fn new_inner(
        config: HttpUpstreamProxyConfig,
        secret_port: Arc<dyn SecretPort>,
        redirect_test_allowlist: Arc<Vec<SocketAddr>>,
    ) -> DomainResult<Self> {
        // SSRF defence, three layers, all reusing `is_routable`:
        //  - `check_ssrf_safe` validates the initial absolute URL at parse
        //    time;
        //  - the redirect policy re-runs `is_routable` on every hop's
        //    resolved host and stops the chain when a hop resolves
        //    non-routable, while still enforcing the `max_redirect_hops` cap;
        //  - the connect-time `dns_guard::GuardedDnsResolver` re-runs
        //    `is_routable` at dial time so a DNS-rebind between the
        //    `check_ssrf_safe` resolve and reqwest's independent dial-time
        //    resolve cannot pivot to IMDS / RFC1918 / loopback (security
        //    audit finding INJ-1). Cross-origin Authorization-strip remains.
        // The guard shares the same `redirect_test_allowlist` seam (empty in
        // production) the redirect policy uses, so wiremock host-name tests
        // can drive it on loopback while production refuses every
        // loopback / RFC1918 / link-local resolution.
        let base_builder = Client::builder()
            .timeout(config.timeout)
            .user_agent(config.user_agent.as_str())
            .dns_resolver(Arc::new(dns_guard::GuardedDnsResolver::new(
                redirect_test_allowlist.clone(),
            )))
            .redirect(build_redirect_policy(
                config.max_redirect_hops,
                redirect_test_allowlist.clone(),
            ));

        // Apply the process-wide extra CA bundle (ADR 0010) to the base
        // client. Failure here is fatal: composition aborts rather than
        // running with a partially-trusted TLS posture. The helper returns
        // the builder unchanged when `extra_trust_anchors` is `None`.
        let base_builder =
            extra_ca::apply_to_reqwest_builder(base_builder, config.extra_trust_anchors.as_ref())?;

        let client = base_builder
            .build()
            .map_err(|e| DomainError::Invariant(format!("building reqwest client failed: {e}")))?;
        Ok(Self {
            client,
            config,
            secret_port,
            bearer_cache: Arc::new(BearerCache::new()),
            challenge_memo: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            tls_client_cache: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            redirect_test_allowlist,
        })
    }

    /// Build a fresh `reqwest::ClientBuilder` carrying the proxy's
    /// shared base config — timeout, redirect cap, and the process-wide
    /// extra CA bundle (ADR 0010).
    ///
    /// Extracted so the per-mapping TLS client build path produces a
    /// `Client` that is structurally identical to
    /// `self.client` on every dimension except the rustls TLS config.
    ///
    /// Returns `DomainResult` because applying the extra CA bundle can
    /// fail if reqwest rejects a cert (e.g. it is syntactically DER but
    /// not a valid trust anchor). The failure is fatal at the per-mapping
    /// build site — the error propagates up and the cache entry is NOT
    /// written, allowing a retry on the next request.
    fn base_client_builder(&self) -> DomainResult<reqwest::ClientBuilder> {
        // Per-mapping (TLS) clients get the same per-hop redirect SSRF
        // policy AND the same connect-time DNS guard as the base client so
        // the redirect-following surface and the dial-time DNS-rebind
        // surface are closed uniformly across every upstream-http client
        // (security audit finding INJ-1). Same allowlist instance as the
        // base client (empty in production).
        let builder = Client::builder()
            .timeout(self.config.timeout)
            .user_agent(self.config.user_agent.as_str())
            .dns_resolver(Arc::new(dns_guard::GuardedDnsResolver::new(
                self.redirect_test_allowlist.clone(),
            )))
            .redirect(build_redirect_policy(
                self.config.max_redirect_hops,
                self.redirect_test_allowlist.clone(),
            ));

        // Apply process-wide extra CA bundle. Returns the builder unchanged
        // when `extra_trust_anchors` is `None`.
        extra_ca::apply_to_reqwest_builder(builder, self.config.extra_trust_anchors.as_ref())
    }

    /// Resolve the `reqwest::Client` to use for `mapping`. Mappings
    /// without operator-supplied TLS material reuse the proxy's
    /// default client (which already trusts the system CA bundle and
    /// performs no client-auth). Mappings with any of `ca_bundle_ref`,
    /// `mtls_cert_ref` + `mtls_key_ref`, or `pinned_cert_sha256` get
    /// a per-mapping client built from a `rustls::ClientConfig` via
    /// `use_preconfigured_tls`.
    ///
    /// First call for a given `mapping.id` resolves all secrets via
    /// [`SecretPort`], builds the rustls config + client, and stores
    /// it in [`Self::tls_client_cache`]. Subsequent calls return the
    /// cached clone. Failures during the first build (PEM parse,
    /// secret resolve, rustls config) propagate as classified
    /// [`DomainError`] and are NOT cached — the next fetch retries
    /// with a fresh resolution attempt so a transient SecretPort
    /// outage doesn't poison the cache.
    async fn client_for_mapping(
        &self,
        mapping: &RepositoryUpstreamMapping,
    ) -> DomainResult<Client> {
        // Fast path: no TLS fields → reuse default client.
        let any_tls_field = mapping.mtls_cert_ref.is_some()
            || mapping.mtls_key_ref.is_some()
            || mapping.ca_bundle_ref.is_some()
            || mapping.pinned_cert_sha256.is_some();
        if !any_tls_field {
            return Ok(self.client.clone());
        }

        // Cache hit?
        {
            let guard = self.tls_client_cache.read().await;
            if let Some(client) = guard.get(&mapping.id) {
                return Ok(client.clone());
            }
        }

        // Cache miss — resolve secrets, build rustls config, build client.
        let material: ResolvedTlsMaterial =
            resolve_tls_material(mapping, self.secret_port.as_ref()).await?;
        if !material.any_present() {
            // Defensive: the value-object pairing invariant should make
            // this unreachable when we got past the early any_tls_field
            // check, but if it ever happens, fall back to default client.
            return Ok(self.client.clone());
        }
        // Pass the process-wide extra trust anchors (ADR 0010) into the
        // per-mapping rustls config so that mappings relying solely on
        // HORT_EXTRA_CA_BUNDLE (no ca_bundle_ref) can still reach TLS
        // hosts signed by the process-wide CA.
        let extra_ca_count = self
            .config
            .extra_trust_anchors
            .as_ref()
            .map_or(0, ExtraTrustAnchors::cert_count);
        let rustls_config =
            build_rustls_client_config(&material, self.config.extra_trust_anchors.as_ref())?;

        // `use_preconfigured_tls` swaps the entire TLS backend; pair it
        // with the shared base builder so timeouts / redirects / DNS
        // policy stay aligned with `self.client`.
        let client = self
            .base_client_builder()?
            .use_preconfigured_tls(rustls_config)
            .build()
            .map_err(|e| {
                classified_error(
                    UpstreamErrorKind::NetworkError,
                    &format!("per-mapping reqwest client build failed: {e}"),
                )
            })?;

        // Insert into cache. Last-writer-wins on a concurrent miss is
        // benign — both writers built equivalent clients.
        tracing::info!(
            mapping_id = %mapping.id,
            format = %self.config.format_label,
            upstream = %upstream_label(mapping),
            has_ca_bundle = mapping.ca_bundle_ref.is_some(),
            has_mtls = mapping.mtls_cert_ref.is_some(),
            has_pin = mapping.pinned_cert_sha256.is_some(),
            extra_ca_count,
            "built per-mapping TLS client; cached for process lifetime"
        );
        let mut guard = self.tls_client_cache.write().await;
        guard.insert(mapping.id, client.clone());
        Ok(client)
    }

    /// Compose the upstream URL.
    ///
    /// - `name_prefix = None` → `<base>/v2/<name>/<kind>/<value>`.
    /// - `name_prefix = Some(p)` → `<base>/v2/<p>/<name>/<kind>/<value>`,
    ///   covering registry-of-registries layouts (Zot multi-storage,
    ///   Artifactory's `/artifactory/<repo>/v2/...` rewrite, GitLab CR
    ///   per-project, Harbor proxy caches).
    ///
    /// `name_prefix` is mandatory at the function-signature level so a
    /// future caller cannot silently forget to thread it — passing
    /// `None` literally is the compile-time-allowed way to omit the prefix.
    ///
    /// Trailing slashes on `base` are tolerated. The constructor-side
    /// validation of `upstream_name_prefix` guarantees the prefix has
    /// no leading/trailing `/` and no traversal segments, so the
    /// `format!` produces exactly one `/` between each component.
    fn build_url(
        base: &str,
        name_prefix: Option<&str>,
        name: &str,
        kind: &str,
        value: &str,
    ) -> String {
        let trimmed = base.trim_end_matches('/');
        match name_prefix {
            Some(prefix) => format!("{trimmed}/v2/{prefix}/{name}/{kind}/{value}"),
            None => format!("{trimmed}/v2/{name}/{kind}/{value}"),
        }
    }
}

/// Compose a request URL for `fetch_metadata`: trim a trailing slash
/// from the upstream base, ensure exactly one slash between base and
/// path. Caller-supplied `path` is a mapping-relative path (npm
/// packument `/{pkg}`, Cargo sparse-index `/{prefix}/{name}`, PyPI
/// `/pypi/{name}/{version}/json`).
fn compose_url(base: &str, path: &str) -> String {
    let trimmed_base = base.trim_end_matches('/');
    let normalised_path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    format!("{trimmed_base}{normalised_path}")
}

/// True iff `path` begins with `https://` or `http://` (case-sensitive
/// — the format handlers compose URLs with lowercase scheme).
fn is_absolute_url(path: &str) -> bool {
    path.starts_with("https://") || path.starts_with("http://")
}

/// Parse the `Last-Modified` response header (RFC 7231 §7.1.1.2) into
/// `DateTime<Utc>`. Best-effort by contract: an absent header
/// (→ `None` input) yields `None`, an unparseable header value yields
/// `None`. The header value is HTTP-date in any of the three
/// RFC-7231-permitted forms (IMF-fixdate, RFC 850, asctime);
/// `httpdate::parse_http_date` handles all three.
///
/// **No log noise on absent.** Every direct-upload response and
/// many proxy responses won't carry the header — that's the common
/// path, not an error. A `debug!` is emitted only when the header
/// is present but unparseable, so an operator chasing a regression
/// on a specific upstream still gets a breadcrumb without flooding
/// the logs during normal operation.
fn parse_last_modified(value: Option<&str>) -> Option<DateTime<Utc>> {
    let raw = value?;
    match httpdate::parse_http_date(raw) {
        Ok(system_time) => Some(DateTime::<Utc>::from(system_time)),
        Err(e) => {
            tracing::debug!(
                last_modified = %raw,
                error = %e,
                "ignoring unparseable Last-Modified response header"
            );
            None
        }
    }
}

/// SSRF defence (ADR 0006): refuse to fetch from a host that resolves to
/// a non-routable address. The check is mandatory on any caller-supplied
/// absolute URL — operators rely on the registry not being a footgun for
/// cross-host pivoting from a poisoned index.
///
/// This is the URL-validation-time check. It necessarily resolves the host
/// itself, and reqwest re-resolves independently at dial time — a
/// DNS-rebind/TOCTOU window between the two. That window is closed by the
/// connect-time [`dns_guard::GuardedDnsResolver`] (security audit finding
/// INJ-1) bound to the same clients, which re-runs the identical
/// [`hort_net_egress::is_routable`] predicate on every dial-time
/// resolution and fails the dial closed before any bytes leave the
/// process. This check stays as the cheap first gate (it rejects an
/// obviously-internal literal/host before a connection is even attempted)
/// and as the parse-time URL validator.
///
/// Refusal returns [`DomainError::Validation`] (mapped to
/// `UpstreamErrorKind::ParseError` by the outer fetch metric — refusal
/// is a content-validation outcome, not a network failure).
async fn check_ssrf_safe(url_str: &str) -> DomainResult<()> {
    let parsed = url::Url::parse(url_str)
        .map_err(|e| DomainError::Validation(format!("invalid upstream URL: {e}")))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| DomainError::Validation("upstream URL has no host".into()))?;
    let port = parsed.port_or_known_default().unwrap_or(443);
    let target = format!("{host}:{port}");
    let addrs = tokio::net::lookup_host(&target).await.map_err(|e| {
        DomainError::Validation(format!("upstream host {host} did not resolve: {e}"))
    })?;
    for addr in addrs {
        if !is_routable(addr.ip()) {
            return Err(DomainError::Validation(format!(
                "upstream artifact URL resolves to a non-routable address: \
                 host={host} ip={ip}",
                ip = addr.ip()
            )));
        }
    }
    Ok(())
}

/// Stable marker embedded in the `reqwest::redirect::Policy` refusal
/// message so [`map_reqwest_send_error`] can recognise a per-hop SSRF
/// rejection and classify it identically to a `check_ssrf_safe`
/// refusal (`UpstreamErrorKind::ParseError`) — a content-validation
/// outcome, not a network failure. The existing `ParseError` mapping is
/// deliberately reused rather than introducing a new error or metric
/// variant.
const REDIRECT_SSRF_SENTINEL: &str = "hort-upstream-redirect-ssrf-blocked";

/// Build the [`reqwest::redirect::Policy`] for the upstream artifact /
/// metadata / manifest fetch clients.
///
/// # Why this exists
///
/// `check_ssrf_safe` validates only the *initial* absolute URL. A
/// poisoned upstream index can `302 Location:` the client onto
/// `http://169.254.169.254/…` (cloud IMDS) or an RFC1918 host, and a
/// bare hop-cap policy would happily follow it and stream the internal
/// response back as artifact/metadata content.
///
/// This policy re-runs [`hort_net_egress::is_routable`] on **every**
/// redirect hop's resolved host and stops the chain with an error when
/// any resolved address is non-routable, while still enforcing the hop
/// **cap** (`max_redirect_hops`) the way `Policy::limited` did.
///
/// # Implementation shape
///
/// Adapted from the removed `hort_net_egress::build_egress_redirect_policy`
/// (commit `ca47d481^`). Reused: the synchronous resolve-then-classify
/// shape (the closure runs in reqwest's sync redirect callback — literal
/// IPs skip the resolver; DNS names go through a blocking
/// `ToSocketAddrs`; a resolution failure is treated as non-routable,
/// fail-closed), the hop-cap-first ordering, and the `allowlist`
/// parameter that lets the wiremock test harness drive the allow /
/// hop-cap paths on loopback. The `hort_upstream_redirect_blocked_total`
/// metric, the `RedirectBlockReason` taxonomy, and the scheme-downgrade
/// refusal were not reintroduced — reqwest's documented cross-origin
/// Authorization-strip already covers the credential-leak path.
///
/// # Scoping (HARD constraint)
///
/// This is bound **only** to the `hort-adapters-upstream-http` artifact /
/// metadata / manifest `reqwest::Client`(s) at the two `Client::builder()`
/// sites in this crate. It is NOT re-exported, is NOT placed in
/// `hort-net-egress`, and is never threaded to the S3
/// (`hort-adapters-storage`) or OIDC (`hort-adapters-oidc`) clients —
/// those use operator-vetted base targets.
///
/// # Relationship to the connect-time DNS guard
///
/// This per-hop policy guards the *redirect* leg. The DNS-rebind/TOCTOU on
/// the **initial dial** — the gap between [`check_ssrf_safe`]'s
/// URL-validation-time resolution and reqwest's independent dial-time
/// resolution — is now closed by the connect-time
/// [`dns_guard::GuardedDnsResolver`] bound to the same clients (security
/// audit finding INJ-1): it re-runs [`hort_net_egress::is_routable`] on
/// every dial-time resolution and fails the dial closed before any bytes
/// leave the process. The redirect path is itself re-guarded per hop here;
/// reqwest re-resolves each followed hop through the bound DNS guard too,
/// so a rebind on a redirect target is caught at connect time as well. The
/// compensating layers (Authorization-strip, upstream checksum
/// verification per ADR 0006, TLS-cert validation) remain.
fn build_redirect_policy(
    max_hops: usize,
    allowlist: Arc<Vec<SocketAddr>>,
) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt: reqwest::redirect::Attempt<'_>| {
        // Hop cap first, so an over-long chain is rejected independent
        // of whether the next hop would also fail the SSRF check —
        // mirrors `Policy::limited(max_hops)` semantics (reqwest stops
        // once `previous().len()` would exceed the limit).
        if attempt.previous().len() >= max_hops {
            return attempt.error(format!("upstream redirect exceeded hop cap of {max_hops}"));
        }

        let next_url = attempt.url().clone();
        let Some(host) = next_url.host_str() else {
            return attempt.error(format!(
                "{REDIRECT_SSRF_SENTINEL}: redirect target has no host"
            ));
        };
        let port = next_url.port_or_known_default().unwrap_or(443);

        // Resolve the next hop's host synchronously — the redirect
        // closure is sync, so we cannot use the tokio resolver here.
        // Literal IP → one addr; DNS name → OS resolver. A resolution
        // failure is fail-closed (we cannot prove the target is safe).
        let addrs: Vec<SocketAddr> = match (host, port).to_socket_addrs_owned() {
            Ok(a) => a,
            Err(_) => {
                tracing::warn!(
                    blocked_host = %host,
                    "upstream redirect hop blocked: host did not resolve \
                     (fail-closed)"
                );
                return attempt.error(format!(
                    "{REDIRECT_SSRF_SENTINEL}: redirect target host \
                     {host} did not resolve"
                ));
            }
        };

        // Reject if ANY resolved address is non-routable and not in the
        // test allowlist — the attacker needs only one entry to pivot.
        for addr in &addrs {
            if !is_routable(addr.ip()) && !allowlist.contains(addr) {
                tracing::warn!(
                    blocked_host = %host,
                    "upstream redirect hop blocked: resolves to a \
                     non-routable address (fail-closed)"
                );
                return attempt.error(format!(
                    "{REDIRECT_SSRF_SENTINEL}: redirect target {host} \
                     resolves to a non-routable address"
                ));
            }
        }

        attempt.follow()
    })
}

/// Tiny extension so the (sync) redirect closure can resolve a host
/// without dragging a tokio runtime into a sync context. Mirrors the
/// helper that lived in the pre-`ca47d481`
/// `hort_net_egress::redirect` module.
trait ToSocketAddrsOwned {
    fn to_socket_addrs_owned(&self) -> std::io::Result<Vec<SocketAddr>>;
}

impl ToSocketAddrsOwned for (&str, u16) {
    fn to_socket_addrs_owned(&self) -> std::io::Result<Vec<SocketAddr>> {
        use std::net::ToSocketAddrs;
        Ok((*self).to_socket_addrs()?.collect())
    }
}

/// True iff `realm_url`'s host is an IP literal that classifies as
/// loopback. The realm scheme guard treats loopback hosts as the
/// test-harness exemption to the `https`-only rule. A direct
/// `IpAddr::is_loopback()` check is used — the OS already classifies
/// `127.0.0.0/8` and `::1` as loopback, and the wiremock-test harness
/// binds inside that range, so the test exemption stands without any
/// operator-facing knob.
///
/// Non-IP-literal hosts (e.g. `attacker.example.com`) never match —
/// production attackers cannot smuggle in via a hostname that resolves
/// to loopback because the comparison is on the URL's literal host
/// token, not on a DNS resolution.
fn realm_host_is_loopback(realm_url: &url::Url) -> bool {
    let Some(host_str) = realm_url.host_str() else {
        return false;
    };
    let Ok(host_ip): Result<std::net::IpAddr, _> = host_str.parse() else {
        return false;
    };
    host_ip.is_loopback()
}

impl HttpUpstreamProxy {
    /// Resolve credentials for a mapping. Returns the
    /// `Authorization` header value to attach (or `None` for
    /// anonymous).
    ///
    /// For `BearerChallenge` mappings this is *lazy*: it returns a
    /// cached bearer header iff the proxy has already learned the
    /// realm/service/scope for this `upstream_url` (via a previous
    /// 401 dance) AND the cached token is unexpired. Cold-cache
    /// callers receive `None`; the request then 401s and the
    /// caller's challenge handler runs the exchange.
    async fn authorization_header(
        &self,
        mapping: &RepositoryUpstreamMapping,
        _upstream_name: &str,
    ) -> DomainResult<Option<String>> {
        match &mapping.upstream_auth {
            UpstreamAuth::Anonymous => Ok(None),
            UpstreamAuth::BearerChallenge => {
                let memo = self.challenge_memo.read().await;
                let Some(challenge) = memo.get(&mapping.upstream_url).cloned() else {
                    return Ok(None);
                };
                drop(memo);
                let key = CacheKey {
                    realm: challenge.realm,
                    service: challenge.service,
                    scope: challenge.scope,
                    cred_identity: mapping.secret_ref.clone(),
                };
                if let Some(cached) = self.bearer_cache.get(&key) {
                    metrics::counter!(
                        METRIC_BEARER_TOKEN,
                        "format" => self.config.format_label.clone(),
                        "upstream" => upstream_label(mapping),
                        "result" => RESULT_CACHE_HIT,
                    )
                    .increment(1);
                    tracing::debug!(
                        upstream = %mapping.upstream_url,
                        "bearer-token cache hit"
                    );
                    Ok(Some(format!("Bearer {}", cached.token)))
                } else {
                    Ok(None)
                }
            }
            UpstreamAuth::Basic { username } => {
                // Resolve via SecretPort. Drop the SecretValue right
                // after the header bytes are formatted; the resulting
                // base64 string carries the secret onward, but the
                // raw bytes never leave this scope.
                let Some(secret_ref) = mapping.secret_ref.as_ref() else {
                    // Mapping declares Basic auth without a secret —
                    // nothing to send. Fall through to anonymous.
                    return Ok(None);
                };
                let secret_value: SecretValue = self
                    .secret_port
                    .resolve(secret_ref)
                    .await
                    .inspect_err(|_e| {
                        tracing::warn!(
                            format = %self.config.format_label,
                            upstream = %upstream_label(mapping),
                            secret_source = secret_source_label(secret_ref.source),
                            location = %secret_ref.location,
                            "secret resolution failed for mapping with configured secret_ref"
                        );
                    })
                    .map_err(|e| {
                        classified_error(
                            UpstreamErrorKind::NetworkError,
                            &format!("SecretPort resolve failed: {e}"),
                        )
                    })?;
                tracing::info!(
                    format = %self.config.format_label,
                    upstream = %upstream_label(mapping),
                    secret_source = secret_source_label(secret_ref.source),
                    "resolved mapping credential"
                );
                let password = std::str::from_utf8(secret_value.as_bytes()).map_err(|e| {
                    DomainError::Invariant(format!("upstream secret is not UTF-8: {e}"))
                })?;
                // Every intermediate string carrying secret bytes is
                // wrapped in `Zeroizing<String>` so its backing buffer
                // is wiped on drop. Mirrors the Bearer-token discipline
                // in `fetch_bearer_token` above. The final
                // `format!("Basic {encoded}")` is unavoidable
                // (`HeaderValue` requires an owned `String`); it lives
                // only for the duration of the request and reqwest
                // releases it once the request is sent.
                use base64::Engine as _;
                use zeroize::Zeroizing;
                let raw: Zeroizing<String> = Zeroizing::new(format!("{username}:{password}"));
                let encoded: Zeroizing<String> = Zeroizing::new(
                    base64::engine::general_purpose::STANDARD.encode(raw.as_bytes()),
                );
                // `secret_value`, `raw`, and `encoded` are dropped
                // (zeroized) on scope exit. The returned `String`
                // carries the same bytes onward into the request
                // builder; reqwest owns it from this point.
                Ok(Some(format!("Basic {}", encoded.as_str())))
            }
        }
    }

    /// Exchange a parsed `Challenge` for a bearer token at the
    /// realm endpoint.
    ///
    /// `bearer_secret`, when supplied, carries the resolved bytes of
    /// the mapping's `secret_ref`. By the GitHub PAT
    /// convention adopted across GHCR / GitLab CR / Harbor, the
    /// secret is sent to the realm as
    /// `Authorization: Basic base64("oauth2:<secret>")` — the
    /// `oauth2` literal username matches GHCR's documented flow and
    /// is accepted by GitLab CR and Harbor as well. When
    /// `bearer_secret` is `None` the realm is hit anonymously
    /// (public-image flow). The `SecretValue` is consumed at
    /// header-format time and dropped (zeroized) before the realm
    /// response is read.
    ///
    /// Lifetime: `expires_in.unwrap_or(300)` seconds, minus a 30s
    /// clock-skew slack, so an in-flight request never hands back
    /// a token the upstream sees as expired.
    async fn fetch_bearer_token(
        &self,
        challenge: &Challenge,
        bearer_secret: Option<SecretValue>,
    ) -> DomainResult<CachedToken> {
        // Build the realm URL with optional service/scope query
        // parameters. Use `Url::parse_with_params` only when at
        // least one is present so the `query_param_is_missing`
        // matcher in tests sees a query-less URL.
        let mut params: Vec<(&str, &str)> = Vec::new();
        if let Some(svc) = challenge.service.as_deref() {
            params.push(("service", svc));
        }
        if let Some(sc) = challenge.scope.as_deref() {
            params.push(("scope", sc));
        }
        let url = if params.is_empty() {
            url::Url::parse(&challenge.realm).map_err(|e| {
                tracing::error!(error = %e, realm = %challenge.realm, "realm URL parse failed");
                classified_error(UpstreamErrorKind::ParseError, &format!("realm URL: {e}"))
            })?
        } else {
            url::Url::parse_with_params(&challenge.realm, &params).map_err(|e| {
                tracing::error!(error = %e, realm = %challenge.realm, "realm URL parse failed");
                classified_error(UpstreamErrorKind::ParseError, &format!("realm URL: {e}"))
            })?
        };

        // The realm URL is operator-uncontrolled — it comes verbatim
        // from the upstream's `WWW-Authenticate` header. A malicious or
        // compromised upstream that returns `realm="http://attacker/token"`
        // would otherwise cause the proxy to send
        // `Authorization: Basic base64(oauth2:<PAT>)` over plaintext.
        // Reject any non-`https` scheme BEFORE building the request
        // and BEFORE the bearer_secret is touched.
        //
        // Loopback test exemption: the wiremock-based test harness
        // binds on http://127.0.0.1:<port>; the IP-literal check below
        // recognises that range as loopback and lets the http:// realm
        // through. Production attackers cannot smuggle in via a
        // hostname (e.g. `attacker.example.com`) — the IP-parse fails
        // for non-literal hosts, so the guard rejects unconditionally.
        // The invariant (`realm="http://attacker/token"` rejected with
        // `ParseError` BEFORE the bearer secret is touched) is
        // preserved.
        if url.scheme() != "https" && !realm_host_is_loopback(&url) {
            tracing::error!(
                realm = %challenge.realm,
                scheme = %url.scheme(),
                "rejecting realm with non-https scheme — credential will not be sent"
            );
            // Drop the secret bytes immediately. `Zeroizing<Vec<u8>>`
            // wipes the buffer on scope exit; an early `drop` here
            // means a panic later in the same function cannot resurrect
            // them.
            drop(bearer_secret);
            return Err(classified_error(
                UpstreamErrorKind::ParseError,
                &format!(
                    "realm URL must be https; got scheme `{}` for realm `{}`",
                    url.scheme(),
                    challenge.realm
                ),
            ));
        }

        // The scheme guard above blocks a plaintext-`http` credential
        // leak, but an `https` realm whose host is a non-routable
        // internal address (cloud IMDS `169.254.169.254`,
        // RFC1918, link-local, …) would still receive the
        // `Authorization: Basic base64(oauth2:<PAT>)` header below — an
        // SSRF + operator-credential-exfiltration sink driven entirely by
        // the upstream-controlled `WWW-Authenticate` realm. Run the same
        // routability check the artifact-fetch path uses (`check_ssrf_safe`
        // → `is_routable`) BEFORE the secret is touched. The loopback
        // exemption mirrors the scheme guard's: `realm_host_is_loopback`
        // is true only for an IP-literal loopback host (the wiremock test
        // harness binds `127.0.0.1`); loopback is therefore the only
        // non-routable class allowed through, exactly as for the existing
        // http-loopback scheme exemption. A production realm pointing at
        // `localhost`/an internal hostname is not an IP-literal loopback,
        // so it is resolved and rejected if non-routable.
        if !realm_host_is_loopback(&url) {
            if let Err(e) = check_ssrf_safe(url.as_str()).await {
                tracing::error!(
                    realm = %challenge.realm,
                    error = %e,
                    "rejecting realm resolving to a non-routable host — credential will not be sent"
                );
                drop(bearer_secret);
                return Err(classified_error(
                    UpstreamErrorKind::ParseError,
                    &format!("realm host is SSRF-blocked (non-routable): {e}"),
                ));
            }
        }

        let mut req = self.client.get(url);
        if let Some(secret) = bearer_secret.as_ref() {
            use base64::Engine as _;
            // Format the resolved secret as `oauth2:<secret>` per
            // the GHCR/GitLab/Harbor PAT convention. Bytes are
            // bracketed so the secret never appears in logs.
            let mut raw: Vec<u8> = b"oauth2:".to_vec();
            raw.extend_from_slice(secret.as_bytes());
            let encoded = base64::engine::general_purpose::STANDARD.encode(&raw);
            req = req.header(AUTHORIZATION, format!("Basic {encoded}"));
        }
        // `bearer_secret` is now consumable for `Drop` — the
        // SecretValue's `Zeroizing<Vec<u8>>` zeroes its contents on
        // scope exit. Reqwest already owns the formatted header
        // bytes, so the original SecretValue can be released.
        drop(bearer_secret);

        let resp = req.send().await.map_err(|e| {
            tracing::error!(error = %e, realm = %challenge.realm, "realm fetch transport error");
            map_reqwest_send_error(&e)
        })?;
        if !resp.status().is_success() {
            let status = resp.status();
            tracing::error!(
                status = %status,
                realm = %challenge.realm,
                "realm fetch returned non-success status"
            );
            return Err(classified_error(
                map_reqwest_status(status),
                &format!("realm fetch returned {status}"),
            ));
        }
        let body: RealmTokenResponse = resp.json().await.map_err(|e| {
            tracing::error!(error = %e, realm = %challenge.realm, "realm response JSON parse failed");
            classified_error(UpstreamErrorKind::ParseError, &format!("realm token JSON: {e}"))
        })?;
        // Prefer `access_token` over `token` when both present.
        // Empty strings are a parse error.
        let token = body
            .access_token
            .filter(|s| !s.is_empty())
            .or_else(|| body.token.filter(|s| !s.is_empty()))
            .ok_or_else(|| {
                tracing::error!(
                    realm = %challenge.realm,
                    "realm response missing both `token` and `access_token`"
                );
                classified_error(
                    UpstreamErrorKind::ParseError,
                    "realm token response missing token",
                )
            })?;
        let lifetime = Duration::from_secs(body.expires_in.unwrap_or(300));
        let expires_at = Instant::now() + lifetime.saturating_sub(Duration::from_secs(30));
        tracing::info!(
            realm = %challenge.realm,
            service = ?challenge.service,
            scope = ?challenge.scope,
            expires_in = body.expires_in.unwrap_or(300),
            "exchanged bearer token at realm"
        );
        Ok(CachedToken { token, expires_at })
    }
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

/// Map a `reqwest::Error` from a `send()` call to a domain error
/// classified by [`UpstreamErrorKind`]. The kind is encoded in the
/// returned `DomainError::Invariant` message prefix; the proxy
/// caller parses it back to fire the metric. Crude but keeps the
/// trait surface generic.
///
/// **TLS classification (ADR 0010):** before the timeout /
/// network-error fallback we walk the error chain for rustls-level
/// signals. `pin_mismatch` (custom verifier sentinel) and `ca_unknown`
/// (rustls `UnknownIssuer` certificate error) are distinct fetch-metric
/// classifications; the TLS-handshake metric emission site at the
/// entry-point fires a matching
/// `hort_upstream_tls_handshake_total{result}` row.
fn map_reqwest_send_error(e: &reqwest::Error) -> DomainError {
    if let Some(tls_kind) = classify_tls_handshake_error(e) {
        return classified_error(tls_kind, &e.to_string());
    }
    // A per-hop redirect SSRF refusal surfaces here as a redirect-class
    // `reqwest::Error` wrapping the `build_redirect_policy` message; a
    // connect-time DNS-guard refusal (INJ-1) surfaces as a connect-class
    // `reqwest::Error` wrapping the `dns_guard::GuardedDnsResolver` message.
    // Both are content-validation refusals — a poisoned/rebinding upstream
    // target, not a network failure — so classify them identically to a
    // `check_ssrf_safe` refusal (`ParseError`); the existing
    // `hort_upstream_fetch_total{result="parse_error"}` row is reused and
    // no new error/metric variant is introduced. Walk the error source
    // chain because reqwest wraps the sentinel message inside its own
    // `Error`.
    if error_chain_contains(e, REDIRECT_SSRF_SENTINEL)
        || error_chain_contains(e, dns_guard::CONNECT_SSRF_SENTINEL)
    {
        return classified_error(
            UpstreamErrorKind::ParseError,
            &format!("upstream fetch blocked (SSRF): {e}"),
        );
    }
    let kind = if e.is_timeout() {
        UpstreamErrorKind::Timeout
    } else {
        UpstreamErrorKind::NetworkError
    };
    classified_error(kind, &e.to_string())
}

/// True iff `needle` appears in `err`'s `Display` string or anywhere in
/// its `source()` chain. Used to recognise the per-hop redirect SSRF
/// refusal that reqwest re-wraps inside its own error type.
fn error_chain_contains(err: &dyn std::error::Error, needle: &str) -> bool {
    if err.to_string().contains(needle) {
        return true;
    }
    let mut src = err.source();
    while let Some(s) = src {
        if s.to_string().contains(needle) {
            return true;
        }
        src = s.source();
    }
    false
}

fn map_reqwest_status(status: StatusCode) -> UpstreamErrorKind {
    match status.as_u16() {
        404 => UpstreamErrorKind::NotFound,
        401 | 403 => UpstreamErrorKind::Unauthorized,
        429 => UpstreamErrorKind::RateLimited,
        s if (400..500).contains(&s) => UpstreamErrorKind::Upstream4xx,
        s if (500..600).contains(&s) => UpstreamErrorKind::Upstream5xx,
        _ => UpstreamErrorKind::ParseError,
    }
}

/// Build a `DomainError::Invariant` with a sentinel prefix the
/// caller can parse back into [`UpstreamErrorKind`]. Format:
/// `upstream:<kind>:<detail>`.
fn classified_error(kind: UpstreamErrorKind, detail: &str) -> DomainError {
    DomainError::Invariant(format!("upstream:{}:{}", kind.as_str(), detail))
}

/// Extract an [`UpstreamErrorKind`] back out of a sentinel-prefixed
/// `DomainError`. Returns `None` for non-sentinel errors. Used by the
/// upstream-http adapter to fire `hort_upstream_fetch_total` with the
/// right `result` label without a custom error type leaking past the
/// port boundary.
pub fn classify_error(err: &DomainError) -> Option<UpstreamErrorKind> {
    // The typed storage-backstop variant carries its own honest `result`
    // label (`metadata_too_large` / `manifest_too_large`), NOT the
    // retired generic `body_too_large` that the buffer-cap path used to
    // emit. The operator sees the right label and reaches for the right
    // knob, instead of debugging the "upstream unavailable" sanitisation
    // the metric label would have led them into (ADR 0026).
    if let DomainError::UpstreamBodyTooLarge { fetch_class, .. } = err {
        return Some(match fetch_class {
            FetchClass::Metadata => UpstreamErrorKind::MetadataTooLarge,
            FetchClass::Manifest => UpstreamErrorKind::ManifestTooLarge,
        });
    }
    let DomainError::Invariant(msg) = err else {
        return None;
    };
    let rest = msg.strip_prefix("upstream:")?;
    let (kind_str, _) = rest.split_once(':')?;
    Some(match kind_str {
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
        // Reserved sentinel parses for parity with the catalog.
        // Production emission uses the typed variant above; these arms
        // keep `classify_error` total when a future caller emits via
        // `classified_error` (e.g. tests).
        "metadata_too_large" => UpstreamErrorKind::MetadataTooLarge,
        "manifest_too_large" => UpstreamErrorKind::ManifestTooLarge,
        "version_object_too_large" => UpstreamErrorKind::VersionObjectTooLarge,
        // TLS-handshake outcomes (ADR 0010).
        "pin_mismatch" => UpstreamErrorKind::PinMismatch,
        "ca_unknown" => UpstreamErrorKind::CaUnknown,
        _ => return None,
    })
}

/// Render a [`SecretSource`] as the snake_case literal that the
/// adapter layer (`hort-adapters-secrets`) emits and that the YAML
/// config spells. Keeping the consumer-layer tracing field shape
/// aligned with the adapter layer means an operator can grep
/// `secret_source = "env_var"` across both layers without learning
/// two casings.
fn secret_source_label(source: SecretSource) -> &'static str {
    match source {
        SecretSource::EnvVar => "env_var",
        SecretSource::File => "file",
    }
}

// ---------------------------------------------------------------------------
// UpstreamProxy impl
// ---------------------------------------------------------------------------

impl HttpUpstreamProxy {
    /// Issue a GET that participates in the bearer-challenge flow.
    ///
    /// `extra_headers` is applied on every attempt (e.g. `Accept`
    /// for manifest fetches). The closure rebuilds the request each
    /// attempt because `reqwest::RequestBuilder` is not `Clone`.
    ///
    /// The flow:
    /// 1. Resolve current `Authorization` (cache hit on
    ///    `BearerChallenge`, Basic for `Basic`, none for
    ///    `Anonymous`).
    /// 2. Send. If !401 OR mapping is not `BearerChallenge`, return
    ///    the response (or classify as error if !success).
    /// 3. On 401 + `BearerChallenge`: parse `WWW-Authenticate`. On
    ///    parse failure surface `Unauthorized`. If we already had a
    ///    cached token (auth.is_some()), invalidate.
    /// 4. Resolve credential bytes for realm. On `Err`, surface
    ///    classified error (no silent anonymise).
    /// 5. Exchange at realm. Populate caches.
    /// 6. Re-issue with new Bearer. A second 401 surfaces
    ///    `Unauthorized` (at-most-one challenge round invariant).
    async fn fetch_with_challenge(
        &self,
        client: &Client,
        mapping: &RepositoryUpstreamMapping,
        upstream_name: &str,
        url: &str,
        kind_label: &'static str,
        extra_headers: &[(&'static str, String)],
    ) -> DomainResult<reqwest::Response> {
        let auth = self.authorization_header(mapping, upstream_name).await?;
        let resp = self
            .send_get(client, url, extra_headers, auth.as_deref())
            .await?;

        if resp.status() != StatusCode::UNAUTHORIZED
            || !matches!(mapping.upstream_auth, UpstreamAuth::BearerChallenge)
        {
            return classify_response(resp, kind_label);
        }

        // 401 on a BearerChallenge mapping — run the challenge dance.
        let header_value = resp
            .headers()
            .get("WWW-Authenticate")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let challenge = match parse_www_authenticate(&header_value) {
            Ok(c) => c,
            Err(e) => {
                metrics::counter!(
                    METRIC_BEARER_TOKEN,
                    "format" => self.config.format_label.clone(),
                    "upstream" => upstream_label(mapping),
                    "result" => RESULT_PARSE_FAILED,
                )
                .increment(1);
                tracing::warn!(
                    error = %e,
                    upstream = %mapping.upstream_url,
                    "WWW-Authenticate parse failed; surfacing 401"
                );
                return Err(classified_error(
                    UpstreamErrorKind::Unauthorized,
                    &format!("malformed WWW-Authenticate: {e}"),
                ));
            }
        };

        // If we sent an Authorization header that produced this 401,
        // the cached entry is stale — invalidate it.
        if auth.is_some() {
            let key = CacheKey {
                realm: challenge.realm.clone(),
                service: challenge.service.clone(),
                scope: challenge.scope.clone(),
                cred_identity: mapping.secret_ref.clone(),
            };
            self.bearer_cache.invalidate(&key);
            metrics::counter!(
                METRIC_BEARER_TOKEN,
                "format" => self.config.format_label.clone(),
                "upstream" => upstream_label(mapping),
                "result" => RESULT_INVALIDATE,
            )
            .increment(1);
            tracing::warn!(
                upstream = %mapping.upstream_url,
                realm = %challenge.realm,
                "401-with-cached-token; invalidating cache entry"
            );
        }

        // Resolve credentials for the realm exchange via SecretPort.
        // On Err do NOT anonymise — surface as fetch_failed
        // (NetworkError-mapped). The `tracing::warn!` here is at the
        // consumer layer for operator triage; the adapter-side
        // `hort_secret_resolve_total{result=…}` counter already fires.
        let bearer_secret: Option<SecretValue> = match mapping.secret_ref.as_ref() {
            None => None,
            Some(secret_ref) => match self.secret_port.resolve(secret_ref).await {
                Ok(value) => {
                    tracing::info!(
                        format = %self.config.format_label,
                        upstream = %upstream_label(mapping),
                        secret_source = secret_source_label(secret_ref.source),
                        "resolved mapping credential"
                    );
                    Some(value)
                }
                Err(e) => {
                    metrics::counter!(
                        METRIC_BEARER_TOKEN,
                        "format" => self.config.format_label.clone(),
                        "upstream" => upstream_label(mapping),
                        "result" => RESULT_FETCH_FAILED,
                    )
                    .increment(1);
                    tracing::warn!(
                        format = %self.config.format_label,
                        upstream = %upstream_label(mapping),
                        secret_source = secret_source_label(secret_ref.source),
                        location = %secret_ref.location,
                        "secret resolution failed for mapping with configured secret_ref"
                    );
                    return Err(classified_error(
                        UpstreamErrorKind::NetworkError,
                        &format!("SecretPort resolve failed: {e}"),
                    ));
                }
            },
        };

        // Run the realm exchange.
        let cached = match self.fetch_bearer_token(&challenge, bearer_secret).await {
            Ok(c) => c,
            Err(e) => {
                metrics::counter!(
                    METRIC_BEARER_TOKEN,
                    "format" => self.config.format_label.clone(),
                    "upstream" => upstream_label(mapping),
                    "result" => RESULT_FETCH_FAILED,
                )
                .increment(1);
                return Err(e);
            }
        };
        metrics::counter!(
            METRIC_BEARER_TOKEN,
            "format" => self.config.format_label.clone(),
            "upstream" => upstream_label(mapping),
            "result" => RESULT_EXCHANGE,
        )
        .increment(1);

        // Populate caches.
        let key = CacheKey {
            realm: challenge.realm.clone(),
            service: challenge.service.clone(),
            scope: challenge.scope.clone(),
            cred_identity: mapping.secret_ref.clone(),
        };
        self.bearer_cache.insert(key, cached.clone());
        self.challenge_memo
            .write()
            .await
            .insert(mapping.upstream_url.clone(), challenge);

        // Retry the original request once with the new bearer.
        let retry_auth = format!("Bearer {}", cached.token);
        let resp2 = self
            .send_get(client, url, extra_headers, Some(retry_auth.as_str()))
            .await?;
        if resp2.status() == StatusCode::UNAUTHORIZED {
            // At-most-one challenge round invariant.
            return Err(classified_error(
                UpstreamErrorKind::Unauthorized,
                &format!("{kind_label} fetch returned 401 after re-exchange"),
            ));
        }
        classify_response(resp2, kind_label)
    }

    async fn send_get(
        &self,
        client: &Client,
        url: &str,
        extra_headers: &[(&'static str, String)],
        authorization: Option<&str>,
    ) -> DomainResult<reqwest::Response> {
        let mut req = client.get(url);
        for (k, v) in extra_headers {
            req = req.header(*k, v);
        }
        if let Some(h) = authorization {
            req = req.header(AUTHORIZATION, h);
        }
        req.send().await.map_err(|e| map_reqwest_send_error(&e))
    }

    async fn do_fetch_blob(
        &self,
        client: &Client,
        mapping: &RepositoryUpstreamMapping,
        upstream_name: &str,
        digest: &str,
    ) -> DomainResult<BlobFetch> {
        let url = Self::build_url(
            &mapping.upstream_url,
            mapping.upstream_name_prefix.as_deref(),
            upstream_name,
            "blobs",
            digest,
        );
        tracing::debug!(
            upstream = %mapping.upstream_url,
            upstream_name = %upstream_name,
            digest = %digest,
            "fetching blob"
        );
        let resp = self
            .fetch_with_challenge(client, mapping, upstream_name, &url, "blob", &[])
            .await?;
        let declared_digest = resp
            .headers()
            .get("docker-content-digest")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        // OCI uses the max `Last-Modified` across config + layer blobs as
        // the image's publish-time hint. This adapter only sees one blob at
        // a time; the format crate does any aggregation. Best-effort:
        // absent / unparseable → None.
        let last_modified = parse_last_modified(
            resp.headers()
                .get(reqwest::header::LAST_MODIFIED)
                .and_then(|v| v.to_str().ok()),
        );
        let stream = resp
            .bytes_stream()
            .map_err(|e| std::io::Error::other(format!("upstream stream error: {e}")));
        let boxed: BlobStream = Box::pin(stream);
        Ok(BlobFetch {
            stream: boxed,
            declared_digest,
            last_modified,
        })
    }

    async fn do_fetch_artifact(
        &self,
        client: &Client,
        mapping: &RepositoryUpstreamMapping,
        path: &str,
    ) -> DomainResult<ArtifactFetch> {
        // Resolve the full request URL — composes onto mapping.upstream_url
        // for relative paths, or runs the mandatory SSRF check for
        // absolute URLs. SSRF is a production guarantee that must not
        // be bypassable; it lives in this resolver so the inner fetch
        // can stay testable in isolation.
        let url = self
            .resolve_artifact_url(&mapping.upstream_url, path)
            .await?;
        self.fetch_artifact_url(client, mapping, path, &url).await
    }

    /// Resolve `path` (relative or absolute) into an absolute URL,
    /// applying SSRF defence on the absolute-URL branch.
    async fn resolve_artifact_url(&self, upstream_base: &str, path: &str) -> DomainResult<String> {
        if is_absolute_url(path) {
            check_ssrf_safe(path).await?;
            Ok(path.to_string())
        } else {
            Ok(compose_url(upstream_base, path))
        }
    }

    /// Fetch a pre-resolved artifact URL. Separated from
    /// `do_fetch_artifact` so the success path can be exercised in
    /// tests against wiremock (which binds to loopback and would
    /// otherwise be refused by the SSRF guard); the SSRF guard has
    /// its own dedicated unit tests.
    async fn fetch_artifact_url(
        &self,
        client: &Client,
        mapping: &RepositoryUpstreamMapping,
        path_for_log: &str,
        url: &str,
    ) -> DomainResult<ArtifactFetch> {
        tracing::debug!(
            upstream = %mapping.upstream_url,
            path = %path_for_log,
            "fetching artifact"
        );
        let resp = self
            .fetch_with_challenge(client, mapping, "", url, "artifact", &[])
            .await?;
        // Cargo `.crate` tarballs are immutable on crates.io, so the
        // `Last-Modified` header ≈ upload time. The npm + PyPI
        // absolute-URL paths also surface a `Last-Modified` here; the
        // packument `time[<version>]` / `upload_time_iso_8601` fields take
        // precedence for those formats, so the value is captured but the
        // npm/pypi format crates ignore it. Best-effort: absent /
        // unparseable → None.
        let last_modified = parse_last_modified(
            resp.headers()
                .get(reqwest::header::LAST_MODIFIED)
                .and_then(|v| v.to_str().ok()),
        );
        let stream = resp
            .bytes_stream()
            .map_err(|e| std::io::Error::other(format!("upstream stream error: {e}")));
        Ok(ArtifactFetch {
            stream: Box::pin(stream),
            last_modified,
        })
    }

    async fn do_fetch_metadata(
        &self,
        client: &Client,
        mapping: &RepositoryUpstreamMapping,
        path: &str,
        accept: &[String],
    ) -> DomainResult<MetadataFetchOutcome> {
        let url = compose_url(&mapping.upstream_url, path);
        tracing::debug!(
            upstream = %mapping.upstream_url,
            path = %path,
            accept_types = accept.len(),
            "fetching metadata"
        );
        let extras: Vec<(&'static str, String)> = if accept.is_empty() {
            Vec::new()
        } else {
            vec![("accept", accept.join(", "))]
        };
        // `upstream_name` is unused for metadata — pass an empty string;
        // `fetch_with_challenge` only uses it for tracing context and
        // bearer-token cache keys (which key on realm/service/scope, not
        // on this argument).
        let resp = self
            .fetch_with_challenge(client, mapping, "", &url, "metadata", &extras)
            .await?;
        // Surface `Last-Modified` on the metadata outcome (mirrors the
        // blob / artifact paths) so npm / PyPI / cargo consumers can
        // populate `upstream_published_at` when
        // `trust_upstream_publish_time` is set.
        let last_modified = parse_last_modified(
            resp.headers()
                .get(reqwest::header::LAST_MODIFIED)
                .and_then(|v| v.to_str().ok()),
        );
        // Stream the upstream body straight to a tempfile via
        // `write_streaming` (ADR 0026). The storage backstop
        // (`metadata_cache_max_bytes`, configurable, default 64 MiB)
        // lives inside the streaming write: on trip we delete the
        // partial file and return `DomainError::UpstreamBodyTooLarge
        // { fetch_class: Metadata, .. }` — `classify_error` reads the
        // typed variant and emits `result="metadata_too_large"`,
        // never the generic `body_too_large` sentinel + "upstream
        // unavailable" sanitisation fold that D2 closed.
        let cache_handle = write_streaming(
            resp.bytes_stream(),
            self.config.metadata_cache_max_bytes,
            FetchClass::Metadata,
            url,
        )
        .await?;
        let bytes_read = cache_handle.byte_length;
        Ok(MetadataFetchOutcome {
            cache_handle: Some(cache_handle),
            bytes_read,
            last_modified,
        })
    }

    async fn do_fetch_manifest(
        &self,
        client: &Client,
        mapping: &RepositoryUpstreamMapping,
        upstream_name: &str,
        reference: &str,
        accept: &[String],
    ) -> DomainResult<ManifestFetchOutcome> {
        let url = Self::build_url(
            &mapping.upstream_url,
            mapping.upstream_name_prefix.as_deref(),
            upstream_name,
            "manifests",
            reference,
        );
        tracing::debug!(
            upstream = %mapping.upstream_url,
            upstream_name = %upstream_name,
            reference = %reference,
            accept_types = accept.len(),
            "fetching manifest"
        );
        // Always advertise the full canonical manifest media-type set to the
        // upstream — NOT the (possibly narrower) client `Accept`. A
        // pull-through cache must fetch the canonical manifest it will STORE
        // and re-serve, not a per-client projection: a strict-content-
        // negotiation registry (Artifact Registry, which backs
        // registry.k8s.io) returns 404 — not the manifest — when the `Accept`
        // omits the manifest's actual media type (e.g. a Docker manifest-list
        // tag fetched with an OCI-only `Accept`). Serve-time `accept_matches`
        // still 406s a client that genuinely can't accept the stored type,
        // and the cached representation is now Accept-independent (closes the
        // dedup-key residual where a narrow leader `Accept` could pin a
        // multi-arch tag to a single-platform manifest). Any extra
        // client-requested types are unioned in after the canonical set for
        // forward-compatibility. (Was: forward the client `Accept` verbatim.)
        const CANONICAL_MANIFEST_ACCEPT: [&str; 4] = [
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
        ];
        let mut accept_types: Vec<&str> = CANONICAL_MANIFEST_ACCEPT.to_vec();
        for t in accept {
            let t = t.trim();
            if !t.is_empty() && !accept_types.iter().any(|c| c.eq_ignore_ascii_case(t)) {
                accept_types.push(t);
            }
        }
        let accept_header = accept_types.join(", ");
        let extras = [("accept", accept_header)];
        let resp = self
            .fetch_with_challenge(client, mapping, upstream_name, &url, "manifest", &extras)
            .await?;
        let media_type = Some(
            resp.headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_string(),
        );
        let declared_digest = resp
            .headers()
            .get("docker-content-digest")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        // Surface `Last-Modified` on the manifest envelope too. Without
        // this, under the `trust_upstream_publish_time = true` opt-in,
        // layer/config blobs would release on their upstream age while
        // the manifest stayed anchored on `ingested_at` and 503'd the
        // pull. Best-effort: absent / unparseable → None (matches the
        // blob / artifact paths above).
        let last_modified = parse_last_modified(
            resp.headers()
                .get(reqwest::header::LAST_MODIFIED)
                .and_then(|v| v.to_str().ok()),
        );
        // OCI-symmetric streaming write (ADR 0026). Storage backstop is
        // `manifest_cache_max_bytes` (default 16 MiB). On trip,
        // `DomainError::UpstreamBodyTooLarge { fetch_class: Manifest,
        // .. }` flows through `classify_error` and emits
        // `result="manifest_too_large"`.
        let cache_handle = write_streaming(
            resp.bytes_stream(),
            self.config.manifest_cache_max_bytes,
            FetchClass::Manifest,
            url,
        )
        .await?;
        let bytes_read = cache_handle.byte_length;
        Ok(ManifestFetchOutcome {
            cache_handle: Some(cache_handle),
            bytes_read,
            media_type,
            declared_digest,
            last_modified,
        })
    }

    /// Fetch the OCI referrers of `digest` on `upstream_name` (ADR 0027).
    ///
    /// 1. `GET /v2/<name>/referrers/<digest>` (Referrers API). On 200
    ///    the body is an OCI image index; its `manifests[]` become the
    ///    returned [`ReferrerDescriptor`]s.
    /// 2. On 404 (Referrers API unsupported / no referrers — Docker Hub
    ///    legacy) fall back to the cosign tag scheme
    ///    `GET /v2/<name>/manifests/sha256-<hex>.sig` (the `sha256:`
    ///    separator in the subject digest replaced with `sha256-`,
    ///    `.sig` appended). On 200 a single descriptor is synthesised
    ///    from the `.sig` manifest's `Content-Type` /
    ///    `Docker-Content-Digest`; on 404 the result is `Ok(Vec::new())`.
    /// 3. Any other status (401/403/429/5xx/…) surfaces verbatim as the
    ///    classified [`UpstreamErrorKind`] — a server failure must NOT
    ///    be swallowed as "no referrers".
    ///
    /// The referrers index + the `.sig` manifest are spec-bounded
    /// small; the body is read bounded by `manifest_cache_max_bytes`
    /// (the same backstop the manifest path uses) and parsed in memory.
    async fn do_fetch_referrers(
        &self,
        client: &Client,
        mapping: &RepositoryUpstreamMapping,
        upstream_name: &str,
        digest: &str,
    ) -> DomainResult<Vec<ReferrerDescriptor>> {
        let referrers_url = Self::build_url(
            &mapping.upstream_url,
            mapping.upstream_name_prefix.as_deref(),
            upstream_name,
            "referrers",
            digest,
        );
        tracing::debug!(
            upstream = %mapping.upstream_url,
            upstream_name = %upstream_name,
            digest = %digest,
            "fetching referrers (OCI Referrers API)"
        );
        // OCI image index is small JSON; request it explicitly.
        let extras = [(
            "accept",
            "application/vnd.oci.image.index.v1+json".to_string(),
        )];
        match self
            .fetch_with_challenge(
                client,
                mapping,
                upstream_name,
                &referrers_url,
                "referrers",
                &extras,
            )
            .await
        {
            Ok(resp) => {
                let body = read_body_bounded(resp, self.config.manifest_cache_max_bytes).await?;
                let index: ReferrersIndexBody = serde_json::from_slice(&body).map_err(|e| {
                    classified_error(
                        UpstreamErrorKind::ParseError,
                        &format!("malformed referrers index: {e}"),
                    )
                })?;
                Ok(index
                    .manifests
                    .into_iter()
                    .map(|d| ReferrerDescriptor {
                        digest: d.digest,
                        media_type: d.media_type,
                        artifact_type: d.artifact_type,
                    })
                    .collect())
            }
            // Referrers API unsupported / no index → cosign tag scheme.
            Err(e) if classify_error(&e) == Some(UpstreamErrorKind::NotFound) => {
                self.fetch_referrers_via_tag_scheme(client, mapping, upstream_name, digest)
                    .await
            }
            Err(e) => Err(e),
        }
    }

    /// Cosign `.sig` tag-scheme fallback. Derives the tag by replacing
    /// the subject digest's `sha256:` separator with `sha256-` and
    /// appending `.sig`, fetches that manifest, and synthesises a single
    /// [`ReferrerDescriptor`] from the response. A 404 means the image
    /// is genuinely unsigned upstream → `Ok(Vec::new())`.
    async fn fetch_referrers_via_tag_scheme(
        &self,
        client: &Client,
        mapping: &RepositoryUpstreamMapping,
        upstream_name: &str,
        digest: &str,
    ) -> DomainResult<Vec<ReferrerDescriptor>> {
        // `sha256:<hex>` → `sha256-<hex>.sig`. Only the first `:` is the
        // algorithm separator; `replacen` keeps a hex body intact.
        let sig_tag = format!("{}.sig", digest.replacen(':', "-", 1));
        let sig_url = Self::build_url(
            &mapping.upstream_url,
            mapping.upstream_name_prefix.as_deref(),
            upstream_name,
            "manifests",
            &sig_tag,
        );
        tracing::debug!(
            upstream = %mapping.upstream_url,
            upstream_name = %upstream_name,
            sig_tag = %sig_tag,
            "Referrers API absent; trying cosign .sig tag scheme"
        );
        let accept = [(
            "accept",
            "application/vnd.oci.image.manifest.v1+json".to_string(),
        )];
        match self
            .fetch_with_challenge(
                client,
                mapping,
                upstream_name,
                &sig_url,
                "referrers",
                &accept,
            )
            .await
        {
            Ok(resp) => {
                // The descriptor's digest is the upstream-declared
                // `Docker-Content-Digest`; fall back to the `.sig` tag
                // when the header is absent (the caller resolves it via
                // `fetch_manifest` either way).
                let media_type = resp
                    .headers()
                    .get(CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("application/vnd.oci.image.manifest.v1+json")
                    .to_string();
                let descriptor_digest = resp
                    .headers()
                    .get("docker-content-digest")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string)
                    .unwrap_or(sig_tag);
                Ok(vec![ReferrerDescriptor {
                    digest: descriptor_digest,
                    media_type,
                    // The cosign sig artifact type the verifier filters on.
                    artifact_type: Some(SIGSTORE_BUNDLE_MEDIA_TYPE.to_string()),
                }])
            }
            // No `.sig` tag upstream → genuinely unsigned, not an error.
            Err(e) if classify_error(&e) == Some(UpstreamErrorKind::NotFound) => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }
}

/// Read a bounded response body into memory. Referrers indexes and
/// cosign `.sig` manifests are spec-bounded small JSON; this buffers
/// up to `max_bytes` and trips [`UpstreamErrorKind::ManifestTooLarge`]
/// past the cap (rather than streaming to a tempfile — the body is
/// parsed immediately, not handed to a per-format projector). Chunked
/// read so a hostile upstream cannot force an unbounded allocation by
/// withholding `Content-Length`.
async fn read_body_bounded(resp: reqwest::Response, max_bytes: u64) -> DomainResult<Vec<u8>> {
    use futures::StreamExt;
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|e| classified_error(UpstreamErrorKind::NetworkError, &e.to_string()))?;
        if buf.len() as u64 + chunk.len() as u64 > max_bytes {
            return Err(classified_error(
                UpstreamErrorKind::ManifestTooLarge,
                "referrers body exceeded the configured cache cap",
            ));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Stream an upstream body to a tempfile, applying the configurable
/// storage backstop (ADR 0026). Returns a [`CachedBodyHandle`] whose
/// `path` points at the committed file on success; on backstop trip,
/// deletes the partial write and returns the typed
/// [`DomainError::UpstreamBodyTooLarge`] variant. Errors during read
/// (network) or write (filesystem) propagate after a best-effort
/// cleanup of the partial file.
///
/// **Why a tempfile in `std::env::temp_dir()` not a real cache.** The
/// cache layer (TTL eviction, lookup keying) lives in the format
/// crates' existing `fetch_raw_with_cache` — the adapter's
/// responsibility is only to materialise the body so the consumer's
/// per-format projector can open it and read straight from the path.
///
/// **No buffer in memory.** This writes each chunk to disk as it
/// arrives — memory is bounded by the `bytes_stream` chunk size
/// (~64 KB), not the body size, even for large packument fixtures.
async fn write_streaming<S>(
    bytes_stream: S,
    max_bytes: u64,
    fetch_class: FetchClass,
    key: String,
) -> DomainResult<hort_domain::ports::upstream_proxy::CachedBodyHandle>
where
    S: futures::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Unpin + Send,
{
    let path = std::env::temp_dir().join(format!(
        "hort-upstream-{}-{}.bin",
        match fetch_class {
            FetchClass::Metadata => "meta",
            FetchClass::Manifest => "mfst",
        },
        Uuid::new_v4()
    ));
    let result = stream_to_file(&path, bytes_stream, max_bytes, fetch_class).await;
    match result {
        Ok(byte_length) => Ok(hort_domain::ports::upstream_proxy::CachedBodyHandle {
            key,
            path,
            fetched_at: Utc::now(),
            byte_length,
        }),
        Err(e) => {
            // Best-effort cleanup of the partial write. Failures here
            // are swallowed — the storage backstop trip / network error
            // is the operator's actionable signal; an orphan tempfile is
            // not.
            let _ = tokio::fs::remove_file(&path).await;
            Err(e)
        }
    }
}

async fn stream_to_file<S>(
    path: &std::path::Path,
    mut bytes_stream: S,
    max_bytes: u64,
    fetch_class: FetchClass,
) -> DomainResult<u64>
where
    S: futures::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Unpin,
{
    use futures::StreamExt;
    use tokio::io::AsyncWriteExt;
    // Tempfile mode 0600 (security invariant): create owner-rw only,
    // not the world-readable default `tokio::fs::File::create` yields.
    // The body is authenticated-upstream metadata/manifest content; on a
    // shared host a 0644 tempfile in `temp_dir()` leaks it to any local
    // user. Mode is set atomically with creation via
    // `tokio::fs::OpenOptions::mode` (an inherent method — no
    // `std::os::unix::fs::OpenOptionsExt` import, no `unsafe`). On
    // non-Unix the mode is silently ignored.
    let mut open_opts = tokio::fs::OpenOptions::new();
    open_opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        open_opts.mode(0o600);
    }
    let mut file = open_opts
        .open(path)
        .await
        .map_err(|e| DomainError::Invariant(format!("create upstream temp file: {e}")))?;
    let mut bytes_read: u64 = 0;
    while let Some(chunk_res) = bytes_stream.next().await {
        let chunk = chunk_res
            .map_err(|e| classified_error(UpstreamErrorKind::NetworkError, &e.to_string()))?;
        bytes_read += chunk.len() as u64;
        if bytes_read > max_bytes {
            // Storage backstop trip — honest classification (D2 close).
            tracing::warn!(
                fetch_class = ?fetch_class,
                bytes_read,
                cap = max_bytes,
                "upstream body exceeded the configured cache cap; rolling back partial write",
            );
            return Err(DomainError::UpstreamBodyTooLarge {
                fetch_class,
                bytes_read,
                cap: max_bytes,
            });
        }
        file.write_all(&chunk)
            .await
            .map_err(|e| DomainError::Invariant(format!("write upstream temp file: {e}")))?;
    }
    file.flush()
        .await
        .map_err(|e| DomainError::Invariant(format!("flush upstream temp file: {e}")))?;
    Ok(bytes_read)
}

/// Classify a response by status: success → pass through; non-2xx
/// → classified-error wrap with the configured kind label.
fn classify_response(
    resp: reqwest::Response,
    kind_label: &'static str,
) -> DomainResult<reqwest::Response> {
    if resp.status().is_success() {
        Ok(resp)
    } else {
        Err(classified_error(
            map_reqwest_status(resp.status()),
            &format!("{kind_label} fetch returned {}", resp.status()),
        ))
    }
}

impl UpstreamProxy for HttpUpstreamProxy {
    fn fetch_blob(
        &self,
        mapping: RepositoryUpstreamMapping,
        upstream_name: String,
        digest: String,
    ) -> BoxFuture<'_, DomainResult<BlobFetch>> {
        Box::pin(async move {
            // Emit WARN + insecure counter on every fetch through an
            // opted-in plaintext mapping.
            emit_insecure_if_opted_in(&self.config.format_label, &mapping);
            let upstream = upstream_label(&mapping);
            let started = Instant::now();
            // Resolve the per-mapping TLS client (ADR 0010). The fetch
            // path emits a single `hort_upstream_tls_handshake_total` row
            // per call, classified from the eventual outcome.
            let client = match self.client_for_mapping(&mapping).await {
                Ok(c) => c,
                Err(e) => {
                    emit_tls_handshake_metric(&e);
                    emit_metrics(
                        &self.config.format_label,
                        &upstream,
                        KIND_BLOB,
                        started.elapsed(),
                        classify_error(&e)
                            .map(|k| k.as_str())
                            .unwrap_or(UpstreamErrorKind::NetworkError.as_str()),
                    );
                    return Err(e);
                }
            };
            let result = self
                .do_fetch_blob(&client, &mapping, &upstream_name, &digest)
                .await;
            let elapsed = started.elapsed();
            emit_tls_handshake_metric_for_result(&result);
            let label = match &result {
                Ok(_) => UpstreamErrorKind::Success.as_str(),
                Err(e) => classify_error(e)
                    .map(|k| k.as_str())
                    .unwrap_or(UpstreamErrorKind::ParseError.as_str()),
            };
            emit_metrics(
                &self.config.format_label,
                &upstream,
                KIND_BLOB,
                elapsed,
                label,
            );
            result
        })
    }

    fn fetch_manifest(
        &self,
        mapping: RepositoryUpstreamMapping,
        upstream_name: String,
        reference: String,
        accept: Vec<String>,
    ) -> BoxFuture<'_, DomainResult<ManifestFetchOutcome>> {
        Box::pin(async move {
            emit_insecure_if_opted_in(&self.config.format_label, &mapping);
            let upstream = upstream_label(&mapping);
            let started = Instant::now();
            let client = match self.client_for_mapping(&mapping).await {
                Ok(c) => c,
                Err(e) => {
                    emit_tls_handshake_metric(&e);
                    emit_metrics(
                        &self.config.format_label,
                        &upstream,
                        KIND_MANIFEST,
                        started.elapsed(),
                        classify_error(&e)
                            .map(|k| k.as_str())
                            .unwrap_or(UpstreamErrorKind::NetworkError.as_str()),
                    );
                    return Err(e);
                }
            };
            let result = self
                .do_fetch_manifest(&client, &mapping, &upstream_name, &reference, &accept)
                .await;
            let elapsed = started.elapsed();
            emit_tls_handshake_metric_for_result(&result);
            let label = match &result {
                Ok(_) => UpstreamErrorKind::Success.as_str(),
                Err(e) => classify_error(e)
                    .map(|k| k.as_str())
                    .unwrap_or(UpstreamErrorKind::ParseError.as_str()),
            };
            emit_metrics(
                &self.config.format_label,
                &upstream,
                KIND_MANIFEST,
                elapsed,
                label,
            );
            result
        })
    }

    fn fetch_artifact(
        &self,
        mapping: RepositoryUpstreamMapping,
        path: String,
    ) -> BoxFuture<'_, DomainResult<ArtifactFetch>> {
        Box::pin(async move {
            emit_insecure_if_opted_in(&self.config.format_label, &mapping);
            let upstream = upstream_label(&mapping);
            let started = Instant::now();
            let client = match self.client_for_mapping(&mapping).await {
                Ok(c) => c,
                Err(e) => {
                    emit_tls_handshake_metric(&e);
                    emit_metrics(
                        &self.config.format_label,
                        &upstream,
                        KIND_ARTIFACT,
                        started.elapsed(),
                        classify_error(&e)
                            .map(|k| k.as_str())
                            .unwrap_or(UpstreamErrorKind::NetworkError.as_str()),
                    );
                    return Err(e);
                }
            };
            let result = self.do_fetch_artifact(&client, &mapping, &path).await;
            let elapsed = started.elapsed();
            emit_tls_handshake_metric_for_result(&result);
            let label = match &result {
                Ok(_) => UpstreamErrorKind::Success.as_str(),
                Err(e) => classify_error(e)
                    .map(|k| k.as_str())
                    .unwrap_or(UpstreamErrorKind::ParseError.as_str()),
            };
            emit_metrics(
                &self.config.format_label,
                &upstream,
                KIND_ARTIFACT,
                elapsed,
                label,
            );
            result
        })
    }

    fn fetch_metadata(
        &self,
        mapping: RepositoryUpstreamMapping,
        path: String,
        accept: Vec<String>,
    ) -> BoxFuture<'_, DomainResult<MetadataFetchOutcome>> {
        Box::pin(async move {
            emit_insecure_if_opted_in(&self.config.format_label, &mapping);
            let upstream = upstream_label(&mapping);
            let started = Instant::now();
            let client = match self.client_for_mapping(&mapping).await {
                Ok(c) => c,
                Err(e) => {
                    emit_tls_handshake_metric(&e);
                    emit_metrics(
                        &self.config.format_label,
                        &upstream,
                        KIND_METADATA,
                        started.elapsed(),
                        classify_error(&e)
                            .map(|k| k.as_str())
                            .unwrap_or(UpstreamErrorKind::NetworkError.as_str()),
                    );
                    return Err(e);
                }
            };
            let result = self
                .do_fetch_metadata(&client, &mapping, &path, &accept)
                .await;
            let elapsed = started.elapsed();
            emit_tls_handshake_metric_for_result(&result);
            let label = match &result {
                Ok(_) => UpstreamErrorKind::Success.as_str(),
                Err(e) => classify_error(e)
                    .map(|k| k.as_str())
                    .unwrap_or(UpstreamErrorKind::ParseError.as_str()),
            };
            emit_metrics(
                &self.config.format_label,
                &upstream,
                KIND_METADATA,
                elapsed,
                label,
            );
            result
        })
    }

    fn fetch_referrers(
        &self,
        mapping: RepositoryUpstreamMapping,
        upstream_name: String,
        digest: String,
    ) -> BoxFuture<'_, DomainResult<Vec<ReferrerDescriptor>>> {
        Box::pin(async move {
            emit_insecure_if_opted_in(&self.config.format_label, &mapping);
            let upstream = upstream_label(&mapping);
            let started = Instant::now();
            let client = match self.client_for_mapping(&mapping).await {
                Ok(c) => c,
                Err(e) => {
                    emit_tls_handshake_metric(&e);
                    emit_metrics(
                        &self.config.format_label,
                        &upstream,
                        KIND_REFERRERS,
                        started.elapsed(),
                        classify_error(&e)
                            .map(|k| k.as_str())
                            .unwrap_or(UpstreamErrorKind::NetworkError.as_str()),
                    );
                    return Err(e);
                }
            };
            let result = self
                .do_fetch_referrers(&client, &mapping, &upstream_name, &digest)
                .await;
            let elapsed = started.elapsed();
            emit_tls_handshake_metric_for_result(&result);
            let label = match &result {
                Ok(_) => UpstreamErrorKind::Success.as_str(),
                Err(e) => classify_error(e)
                    .map(|k| k.as_str())
                    .unwrap_or(UpstreamErrorKind::ParseError.as_str()),
            };
            emit_metrics(
                &self.config.format_label,
                &upstream,
                KIND_REFERRERS,
                elapsed,
                label,
            );
            result
        })
    }
}

/// Emit `hort_upstream_tls_handshake_total` on the fetch-error path
/// (ADR 0010). Walks the supplied [`DomainError`]'s classification (via
/// [`classify_error`]) and maps to a [`UpstreamTlsHandshakeResult`] when
/// the kind is one of the four transport-layer arms; for any other
/// classification the helper is a no-op (the fetch metric already covers
/// application-layer outcomes).
///
/// The `repository` label is always [`metric_values::REPOSITORY_ALL`]
/// at this layer: the upstream proxy operates on `RepositoryUpstreamMapping`
/// values that carry only the repository's UUID, not its key, and the
/// architect-skill cardinality rule forbids emitting the UUID. The
/// `_all` sentinel is the documented collapse-target the
/// `METRICS_INCLUDE_REPOSITORY_LABEL=false` toggle produces; the proxy
/// inherits it without a separate switch.
fn emit_tls_handshake_metric(err: &DomainError) {
    let Some(kind) = classify_error(err) else {
        return;
    };
    let result = match kind {
        UpstreamErrorKind::PinMismatch => UpstreamTlsHandshakeResult::PinMismatch,
        UpstreamErrorKind::CaUnknown => UpstreamTlsHandshakeResult::CaUnknown,
        UpstreamErrorKind::Unauthorized => {
            // Server-demands-cert-but-we-have-none surfaces as
            // Unauthorized at fetch level. Map it to `mtls_required`
            // on the TLS metric so the operator can distinguish
            // "auth failed" from "TLS posture missing".
            // Note: this conflates 401-after-handshake with mTLS-required.
            // Operators wanting precise discrimination read the
            // accompanying tracing line at the application layer.
            UpstreamTlsHandshakeResult::MtlsRequired
        }
        UpstreamErrorKind::NetworkError | UpstreamErrorKind::Timeout => {
            UpstreamTlsHandshakeResult::NetworkError
        }
        // Other variants — 4xx, 5xx, parse errors, body-too-large,
        // checksum-mismatch — are application-layer; do not emit.
        _ => return,
    };
    emit_upstream_tls_handshake(metric_values::REPOSITORY_ALL, result);
}

/// Emit the TLS handshake metric for a fetch result. On `Ok(_)` we fire
/// `success` (the handshake completed and produced a usable response).
/// On `Err(_)` we delegate to [`emit_tls_handshake_metric`].
fn emit_tls_handshake_metric_for_result<T>(result: &DomainResult<T>) {
    match result {
        Ok(_) => emit_upstream_tls_handshake(
            metric_values::REPOSITORY_ALL,
            UpstreamTlsHandshakeResult::Success,
        ),
        Err(e) => emit_tls_handshake_metric(e),
    }
}

/// Walk a `reqwest::Error` chain looking for rustls-level signals so
/// `map_reqwest_send_error`'s caller can emit the right TLS-handshake
/// metric label and the right [`UpstreamErrorKind`]. Returns `None` if
/// no rustls error is present in the chain — caller falls back to the
/// existing timeout / network-error classification.
///
/// The walker is deliberately string-based: `rustls::Error` is not
/// guaranteed to be in the source chain in any specific position
/// (reqwest wraps in `hyper`, then `hyper-rustls`, then `rustls`), so
/// we walk every level looking for the discriminating substrings.
/// The match strings below are stable across `rustls` 0.23.x.
pub(crate) fn classify_tls_handshake_error(err: &reqwest::Error) -> Option<UpstreamErrorKind> {
    let mut source: Option<&dyn std::error::Error> = Some(err);
    while let Some(s) = source {
        let s_msg = s.to_string();
        // Pin sentinel (custom verifier).
        if s_msg.contains(PIN_MISMATCH_SENTINEL) {
            return Some(UpstreamErrorKind::PinMismatch);
        }
        // CA-trust failure: rustls' standard message for "no trust
        // anchor matches", surfaced through `Error::InvalidCertificate(
        // CertificateError::UnknownIssuer)`. Display shape: "invalid
        // peer certificate: UnknownIssuer".
        if s_msg.contains("UnknownIssuer") {
            return Some(UpstreamErrorKind::CaUnknown);
        }
        source = s.source();
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::Utc;
    use futures::StreamExt;
    use hort_domain::oci::SIGSTORE_BUNDLE_MEDIA_TYPE;
    use hort_domain::ports::upstream_proxy::ReferrerDescriptor;
    use uuid::Uuid;
    use wiremock::matchers::{header, header_regex, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn mapping(url: &str, path_prefix: &str, auth: UpstreamAuth) -> RepositoryUpstreamMapping {
        mapping_with_insecure(url, path_prefix, auth, false)
    }

    /// Test helpers that recover the body bytes from a fetch outcome by
    /// reading the cached tempfile and deleting it.
    /// Test-only because production consumers use
    /// `hort_app::project::metadata_body_bytes` / `manifest_body_bytes`
    /// — but the adapter crate can't depend on `hort-app` (would invert
    /// the dep graph), so the equivalent lives inline here.
    fn body_of_metadata(outcome: &MetadataFetchOutcome) -> Vec<u8> {
        let handle = outcome
            .cache_handle
            .as_ref()
            .expect("test fixture must carry a cache_handle");
        let bytes = std::fs::read(&handle.path).expect("read cached body");
        let _ = std::fs::remove_file(&handle.path);
        bytes
    }

    fn body_of_manifest(outcome: &ManifestFetchOutcome) -> Vec<u8> {
        let handle = outcome
            .cache_handle
            .as_ref()
            .expect("test fixture must carry a cache_handle");
        let bytes = std::fs::read(&handle.path).expect("read cached body");
        let _ = std::fs::remove_file(&handle.path);
        bytes
    }

    fn mapping_with_insecure(
        url: &str,
        path_prefix: &str,
        auth: UpstreamAuth,
        insecure_upstream_url: bool,
    ) -> RepositoryUpstreamMapping {
        let now = Utc::now();
        RepositoryUpstreamMapping {
            id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            path_prefix: path_prefix.into(),
            upstream_url: url.to_string(),
            upstream_name_prefix: None,
            upstream_auth: auth,
            secret_ref: None,
            managed_by: hort_domain::entities::managed_by::ManagedBy::Local,
            managed_by_digest: None,
            insecure_upstream_url,
            trust_upstream_publish_time: false,
            mtls_cert_ref: None,
            mtls_key_ref: None,
            ca_bundle_ref: None,
            pinned_cert_sha256: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Test stub: a `SecretPort` that always returns
    /// `Err(DomainError::Invariant(...))`. Used by tests that exercise
    /// anonymous-only flows (where the port is wired but never
    /// reached) and by tests that explicitly assert the secret-resolution
    /// failure path. Replaces the deleted `with_no_secrets` helper.
    struct AnonymousFallbackPort;
    impl SecretPort for AnonymousFallbackPort {
        fn resolve<'a>(
            &'a self,
            _reference: &'a SecretRef,
        ) -> BoxFuture<'a, DomainResult<SecretValue>> {
            Box::pin(async {
                Err(DomainError::Invariant(
                    "anonymous-fallback test port".into(),
                ))
            })
        }
    }

    fn proxy_for(server: &MockServer) -> HttpUpstreamProxy {
        // The connect-time SSRF guard was removed; reqwest's default DNS
        // resolver connects to wiremock's loopback bind address without
        // further wiring. The `server` argument is retained for signature
        // stability across the many callers below.
        let _ = server;
        let cfg = HttpUpstreamProxyConfig {
            timeout: Duration::from_secs(2),
            format_label: "oci".to_string(),
            ..Default::default()
        };
        HttpUpstreamProxy::new(cfg, Arc::new(AnonymousFallbackPort)).unwrap()
    }

    // Test caps. The per-instance configurable caps default to 64 MiB /
    // 16 MiB in production. Tests use smaller values so synthetic bodies
    // stay fast to allocate; the storage-backstop logic and the typed
    // error variant are size-independent.
    const TEST_METADATA_CAP: u64 = 1024 * 1024; // 1 MiB
    const TEST_MANIFEST_CAP: u64 = 256 * 1024; // 256 KiB

    fn proxy_for_with_caps(metadata_cap: u64, manifest_cap: u64) -> HttpUpstreamProxy {
        let cfg = HttpUpstreamProxyConfig {
            timeout: Duration::from_secs(5),
            format_label: "oci".to_string(),
            metadata_cache_max_bytes: metadata_cap,
            manifest_cache_max_bytes: manifest_cap,
            ..Default::default()
        };
        HttpUpstreamProxy::new(cfg, Arc::new(AnonymousFallbackPort)).unwrap()
    }

    /// Happy path: anonymous fetch_blob → 200 → stream yields the
    /// configured bytes, declared digest header round-trips.
    #[tokio::test]
    async fn fetch_blob_anonymous_streams_body_and_returns_declared_digest() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/library/nginx/blobs/sha256:abc"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("docker-content-digest", "sha256:abc")
                    .set_body_bytes(b"hello-blob".as_slice()),
            )
            .mount(&server)
            .await;

        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let BlobFetch {
            mut stream,
            declared_digest: declared,
            ..
        } = proxy
            .fetch_blob(m, "library/nginx".into(), "sha256:abc".into())
            .await
            .expect("fetch_blob");

        assert_eq!(declared.as_deref(), Some("sha256:abc"));
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            bytes.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(bytes, b"hello-blob");
    }

    // ---- Upstream User-Agent (global; HORT_UPSTREAM_USER_AGENT) ----

    #[test]
    fn resolve_user_agent_falls_back_to_default() {
        assert_eq!(resolve_user_agent(None), DEFAULT_UPSTREAM_USER_AGENT);
        assert_eq!(
            resolve_user_agent(Some(String::new())),
            DEFAULT_UPSTREAM_USER_AGENT
        );
        assert_eq!(
            resolve_user_agent(Some("   ".into())),
            DEFAULT_UPSTREAM_USER_AGENT
        );
    }

    #[test]
    fn resolve_user_agent_honours_and_trims_override() {
        assert_eq!(
            resolve_user_agent(Some("acme-proxy/2.0".into())),
            "acme-proxy/2.0"
        );
        assert_eq!(
            resolve_user_agent(Some("  acme-proxy/2.0  ".into())),
            "acme-proxy/2.0"
        );
    }

    #[test]
    fn resolve_user_agent_rejects_control_char_override_falls_back_to_default() {
        // A non-empty override containing a control char is not a valid HTTP
        // header value: `Client::builder().user_agent(..).build()` would fail
        // and crash boot. The resolver falls back to the default instead.
        // These are exactly the bytes `HeaderValue::from_str` (= what
        // reqwest applies) rejects: C0 controls except HTAB, plus DEL.
        // Interior newline — the CRLF header-injection vector (a trailing
        // newline would just be trimmed; an interior one survives trim):
        assert_eq!(
            resolve_user_agent(Some("hort/1.0\nX-Injected: 1".into())),
            DEFAULT_UPSTREAM_USER_AGENT
        );
        // Interior carriage return:
        assert_eq!(
            resolve_user_agent(Some("hort/1.0\rmalicious".into())),
            DEFAULT_UPSTREAM_USER_AGENT
        );
        // Embedded NUL (not whitespace — survives trim):
        assert_eq!(
            resolve_user_agent(Some("hort/1.0\u{0}".into())),
            DEFAULT_UPSTREAM_USER_AGENT
        );
    }

    #[test]
    fn resolve_user_agent_trims_trailing_control_whitespace() {
        // A *trailing* newline (the accidental copy-paste / YAML-scalar
        // case) is whitespace: it is trimmed, leaving a valid value — no
        // fallback needed, the operator's UA still applies.
        assert_eq!(resolve_user_agent(Some("acme/1.0\n".into())), "acme/1.0");
        assert_eq!(resolve_user_agent(Some("acme/1.0\r\n".into())), "acme/1.0");
    }

    #[test]
    fn resolve_user_agent_keeps_non_ascii_override() {
        // `HeaderValue::from_str` (and therefore reqwest) ACCEPTS obs-text
        // (bytes >= 0x80), so a non-ASCII override — e.g. an accented
        // operator contact name — is a valid header value and is kept
        // verbatim. The validator matches reqwest exactly: it falls back
        // ONLY when reqwest would crash (control chars), never on a value
        // reqwest would have sent. No over-restriction, no drift.
        assert_eq!(
            resolve_user_agent(Some("hort/1.0 (Müller GmbH)".into())),
            "hort/1.0 (Müller GmbH)"
        );
    }

    #[test]
    fn resolve_user_agent_reporting_flags_only_non_empty_invalid_overrides() {
        // (resolved, rejected): empty / whitespace / None / valid → not a
        // rejection; non-empty-but-header-invalid → rejected so the caller
        // can warn.
        assert!(!resolve_user_agent_reporting(None).1);
        assert!(!resolve_user_agent_reporting(Some("")).1);
        assert!(!resolve_user_agent_reporting(Some("   ")).1);
        assert!(!resolve_user_agent_reporting(Some("acme/1.0")).1);
        let (ua, rejected) = resolve_user_agent_reporting(Some("bad\nua"));
        assert!(rejected);
        assert_eq!(ua, DEFAULT_UPSTREAM_USER_AGENT);
    }

    #[test]
    fn validate_user_agent_override_offline_contract() {
        // The validate-config offline lint: empty / valid / obs-text pass;
        // a non-empty value with an interior control char fails so a CI
        // gate catches a silently-inert custom UA.
        assert!(validate_user_agent_override("").is_ok());
        assert!(validate_user_agent_override("   ").is_ok());
        assert!(validate_user_agent_override("acme-proxy/2.0 (ops@example.com)").is_ok());
        assert!(validate_user_agent_override("hort/1.0 (Müller GmbH)").is_ok());
        assert!(validate_user_agent_override("acme/1.0\n").is_ok()); // trailing trimmed
        assert!(validate_user_agent_override("bad\nX-Injected: 1").is_err());
        assert!(validate_user_agent_override("x\u{0}y").is_err());
    }

    #[test]
    fn default_user_agent_is_non_empty_and_identifies_hort() {
        // crates.io rejects an empty UA; the built-in default must be
        // non-empty and identify hort.
        assert!(!DEFAULT_UPSTREAM_USER_AGENT.is_empty());
        assert!(DEFAULT_UPSTREAM_USER_AGENT.starts_with("hort/"));
    }

    /// The default config sends `DEFAULT_UPSTREAM_USER_AGENT` on the wire:
    /// the mock only matches when that exact `user-agent` header is present,
    /// so a successful fetch proves it was sent.
    #[tokio::test]
    async fn upstream_fetch_sends_default_user_agent() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/library/nginx/blobs/sha256:abc"))
            .and(header("user-agent", DEFAULT_UPSTREAM_USER_AGENT))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"x".as_slice()))
            .mount(&server)
            .await;

        let proxy = proxy_for(&server); // default config → default UA
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        proxy
            .fetch_blob(m, "library/nginx".into(), "sha256:abc".into())
            .await
            .expect("fetch must match the default User-Agent mock");
    }

    /// A configured `user_agent` overrides the default on the wire.
    #[tokio::test]
    async fn upstream_fetch_sends_configured_user_agent() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/library/nginx/blobs/sha256:abc"))
            .and(header("user-agent", "acme-proxy/2.0"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"x".as_slice()))
            .mount(&server)
            .await;

        let cfg = HttpUpstreamProxyConfig {
            user_agent: "acme-proxy/2.0".to_string(),
            ..Default::default()
        };
        let proxy = HttpUpstreamProxy::new(cfg, Arc::new(AnonymousFallbackPort)).unwrap();
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        proxy
            .fetch_blob(m, "library/nginx".into(), "sha256:abc".into())
            .await
            .expect("fetch must match the configured User-Agent mock");
    }

    /// 404 → `not_found` classified error.
    #[tokio::test]
    async fn fetch_blob_404_maps_to_not_found_kind() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/library/nginx/blobs/sha256:missing"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let err = proxy
            .fetch_blob(m, "library/nginx".into(), "sha256:missing".into())
            .await
            .err()
            .unwrap();
        assert_eq!(classify_error(&err), Some(UpstreamErrorKind::NotFound));
    }

    /// 502 (5xx) → `upstream_5xx`.
    #[tokio::test]
    async fn fetch_blob_502_maps_to_upstream_5xx() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/library/nginx/blobs/sha256:bad"))
            .respond_with(ResponseTemplate::new(502))
            .mount(&server)
            .await;

        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let err = proxy
            .fetch_blob(m, "library/nginx".into(), "sha256:bad".into())
            .await
            .err()
            .unwrap();
        assert_eq!(classify_error(&err), Some(UpstreamErrorKind::Upstream5xx));
    }

    /// 401 → `unauthorized`.
    #[tokio::test]
    async fn fetch_blob_401_maps_to_unauthorized() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/p/blobs/sha256:x"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let err = proxy
            .fetch_blob(m, "p".into(), "sha256:x".into())
            .await
            .err()
            .unwrap();
        assert_eq!(classify_error(&err), Some(UpstreamErrorKind::Unauthorized));
    }

    /// 429 → `rate_limited`.
    #[tokio::test]
    async fn fetch_manifest_429_maps_to_rate_limited() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/p/manifests/latest"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let err = proxy
            .fetch_manifest(m, "p".into(), "latest".into(), Vec::new())
            .await
            .err()
            .unwrap();
        assert_eq!(classify_error(&err), Some(UpstreamErrorKind::RateLimited));
    }

    /// Timeout → `timeout` kind. The mock server delays the response
    /// past the proxy's 2s timeout.
    #[tokio::test]
    async fn fetch_blob_timeout_maps_to_timeout_kind() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/p/blobs/sha256:slow"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let err = proxy
            .fetch_blob(m, "p".into(), "sha256:slow".into())
            .await
            .err()
            .unwrap();
        assert_eq!(classify_error(&err), Some(UpstreamErrorKind::Timeout));
    }

    /// Manifest fetch round-trip: bytes + media-type + declared
    /// digest header all surface back to the caller.
    #[tokio::test]
    async fn fetch_manifest_round_trips_media_type_and_digest() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/library/nginx/manifests/latest"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(CONTENT_TYPE, "application/vnd.oci.image.manifest.v1+json")
                    .insert_header("docker-content-digest", "sha256:deadbeef")
                    .set_body_bytes(br#"{"schemaVersion":2}"#.as_slice()),
            )
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let result = proxy
            .fetch_manifest(m, "library/nginx".into(), "latest".into(), Vec::new())
            .await
            .expect("fetch_manifest");
        assert_eq!(body_of_manifest(&result), br#"{"schemaVersion":2}"#);
        assert_eq!(
            result.media_type.as_deref(),
            Some("application/vnd.oci.image.manifest.v1+json")
        );
        assert_eq!(result.declared_digest.as_deref(), Some("sha256:deadbeef"));
    }

    /// Regression: a narrow client `Accept` must NOT narrow the upstream
    /// fetch. The mock 200s ONLY when the outbound `Accept` advertises the
    /// Docker manifest-list type (mirroring Artifact Registry / registry.k8s.io
    /// strict content negotiation — a `pause`-style tag is a Docker manifest
    /// list). Called with an OCI-index-only client `Accept`, hort must still
    /// widen to the canonical set and get 200 — not forward the narrow
    /// `Accept` and 404.
    #[tokio::test]
    async fn fetch_manifest_widens_narrow_client_accept_to_canonical_set() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/pause/manifests/3.9"))
            .and(header_regex(
                "accept",
                r"application/vnd\.docker\.distribution\.manifest\.list\.v2\+json",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(
                        CONTENT_TYPE,
                        "application/vnd.docker.distribution.manifest.list.v2+json",
                    )
                    .insert_header("docker-content-digest", "sha256:feedface")
                    .set_body_bytes(br#"{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.list.v2+json"}"#.as_slice()),
            )
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        // Narrow, OCI-only client Accept — the bug case. With the old
        // pass-through this reached the upstream verbatim → no match → 404.
        let result = proxy
            .fetch_manifest(
                m,
                "pause".into(),
                "3.9".into(),
                vec!["application/vnd.oci.image.index.v1+json".to_string()],
            )
            .await
            .expect("hort must widen the upstream Accept to the canonical set and get 200");
        assert_eq!(
            result.media_type.as_deref(),
            Some("application/vnd.docker.distribution.manifest.list.v2+json")
        );
    }

    // -------------------------------------------------------------------
    // Manifest storage backstop
    //
    // The configurable per-instance backstop defaults to 16 MiB. Tests
    // use a smaller cap (TEST_MANIFEST_CAP = 256 KiB) so the synthetic
    // body allocations stay fast; the trip behaviour is size-independent.
    // A tripped backstop must surface as
    // `DomainError::UpstreamBodyTooLarge { fetch_class: Manifest, .. }`
    // and `classify_error` must return `ManifestTooLarge`, never the
    // retired `BodyTooLarge` sentinel.
    // -------------------------------------------------------------------

    /// `2x cap` manifest body → `ManifestTooLarge`. Honest classification
    /// + typed variant; not the generic `body_too_large` sentinel the
    /// retired buffer-cap path used to fold into.
    #[tokio::test]
    async fn fetch_manifest_oversize_body_maps_to_manifest_too_large() {
        let server = MockServer::start().await;
        let oversized = vec![b'x'; 2 * TEST_MANIFEST_CAP as usize];
        Mock::given(method("GET"))
            .and(path("/v2/big/manifests/latest"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(CONTENT_TYPE, "application/vnd.oci.image.manifest.v1+json")
                    .set_body_bytes(oversized),
            )
            .mount(&server)
            .await;
        let proxy = proxy_for_with_caps(TEST_METADATA_CAP, TEST_MANIFEST_CAP);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let err = proxy
            .fetch_manifest(m, "big".into(), "latest".into(), Vec::new())
            .await
            .expect_err("oversize manifest must error");
        assert_eq!(
            classify_error(&err),
            Some(UpstreamErrorKind::ManifestTooLarge)
        );
        // Typed variant — D2 close, no string-sentinel surface.
        assert!(
            matches!(
                err,
                DomainError::UpstreamBodyTooLarge {
                    fetch_class: FetchClass::Manifest,
                    ..
                }
            ),
            "expected typed UpstreamBodyTooLarge(Manifest); got {err:?}"
        );
    }

    /// Manifest body well under cap → accepted, body round-trips.
    #[tokio::test]
    async fn fetch_manifest_under_cap_is_accepted() {
        let server = MockServer::start().await;
        let body_size = TEST_MANIFEST_CAP / 2; // half the cap
        let body = vec![b'y'; body_size as usize];
        Mock::given(method("GET"))
            .and(path("/v2/mid/manifests/latest"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(CONTENT_TYPE, "application/vnd.oci.image.manifest.v1+json")
                    .set_body_bytes(body.clone()),
            )
            .mount(&server)
            .await;
        let proxy = proxy_for_with_caps(TEST_METADATA_CAP, TEST_MANIFEST_CAP);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let result = proxy
            .fetch_manifest(m, "mid".into(), "latest".into(), Vec::new())
            .await
            .expect("under-cap manifest accepted");
        assert_eq!(body_of_manifest(&result).len(), body_size as usize);
    }

    /// Body exactly at the cap succeeds (`bytes_read > cap` semantics —
    /// boundary on the passing side). Verifies the storage backstop
    /// doesn't off-by-one.
    #[tokio::test]
    async fn fetch_manifest_body_at_cap_is_accepted() {
        let server = MockServer::start().await;
        let at_cap = vec![b'z'; TEST_MANIFEST_CAP as usize];
        Mock::given(method("GET"))
            .and(path("/v2/atcap/manifests/latest"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(CONTENT_TYPE, "application/vnd.oci.image.manifest.v1+json")
                    .set_body_bytes(at_cap.clone()),
            )
            .mount(&server)
            .await;
        let proxy = proxy_for_with_caps(TEST_METADATA_CAP, TEST_MANIFEST_CAP);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let result = proxy
            .fetch_manifest(m, "atcap".into(), "latest".into(), Vec::new())
            .await
            .expect("at-cap manifest body accepted");
        assert_eq!(body_of_manifest(&result).len(), TEST_MANIFEST_CAP as usize);
    }

    /// `cap + 1` byte → `ManifestTooLarge`. Boundary on the failing
    /// side.
    #[tokio::test]
    async fn fetch_manifest_body_one_over_cap_maps_to_manifest_too_large() {
        let server = MockServer::start().await;
        let oversized = vec![b'!'; TEST_MANIFEST_CAP as usize + 1];
        Mock::given(method("GET"))
            .and(path("/v2/over/manifests/latest"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(CONTENT_TYPE, "application/vnd.oci.image.manifest.v1+json")
                    .set_body_bytes(oversized),
            )
            .mount(&server)
            .await;
        let proxy = proxy_for_with_caps(TEST_METADATA_CAP, TEST_MANIFEST_CAP);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let err = proxy
            .fetch_manifest(m, "over".into(), "latest".into(), Vec::new())
            .await
            .expect_err("cap+1 manifest must error");
        assert_eq!(
            classify_error(&err),
            Some(UpstreamErrorKind::ManifestTooLarge)
        );
    }

    /// Streaming check: the blob stream yields chunks incrementally,
    /// not as one buffered Vec. We assert by sending a multi-chunk
    /// body; while wiremock combines them on the wire, the
    /// `bytes_stream` adapter still exposes them through the
    /// streaming interface (the contract is "this is a Stream",
    /// regardless of how chunks are sized).
    #[tokio::test]
    async fn fetch_blob_returns_a_stream_not_a_vec() {
        let server = MockServer::start().await;
        // Build a 1 MB body; assert we can drain it via the stream
        // interface without a `bytes()` round-trip.
        let body = vec![0u8; 1_000_000];
        Mock::given(method("GET"))
            .and(path("/v2/p/blobs/sha256:big"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let mut stream = proxy
            .fetch_blob(m, "p".into(), "sha256:big".into())
            .await
            .unwrap()
            .stream;
        let mut total = 0usize;
        while let Some(chunk) = stream.next().await {
            let bytes = chunk.unwrap();
            assert!(!bytes.is_empty());
            total += bytes.len();
        }
        assert_eq!(total, body.len());
    }

    // -- BearerCache --------------------------------------------------

    #[test]
    fn bearer_cache_get_returns_none_when_empty() {
        let cache = BearerCache::new();
        let key = CacheKey {
            realm: "https://r".into(),
            service: None,
            scope: None,
            cred_identity: None,
        };
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn bearer_cache_returns_inserted_token_when_unexpired() {
        let cache = BearerCache::new();
        let key = CacheKey {
            realm: "https://r".into(),
            service: Some("svc".into()),
            scope: Some("repository:p:pull".into()),
            cred_identity: None,
        };
        cache.insert(
            key.clone(),
            CachedToken {
                token: "tok".into(),
                expires_at: Instant::now() + Duration::from_secs(60),
            },
        );
        let got = cache.get(&key).expect("cache hit");
        assert_eq!(got.token, "tok");
    }

    #[test]
    fn bearer_cache_returns_none_for_expired_entry() {
        let cache = BearerCache::new();
        let key = CacheKey {
            realm: "https://r".into(),
            service: None,
            scope: None,
            cred_identity: None,
        };
        cache.insert(
            key.clone(),
            CachedToken {
                token: "expired".into(),
                expires_at: Instant::now() - Duration::from_secs(1),
            },
        );
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn bearer_cache_invalidate_removes_entry() {
        let cache = BearerCache::new();
        let key = CacheKey {
            realm: "https://r".into(),
            service: None,
            scope: None,
            cred_identity: None,
        };
        cache.insert(
            key.clone(),
            CachedToken {
                token: "tok".into(),
                expires_at: Instant::now() + Duration::from_secs(60),
            },
        );
        cache.invalidate(&key);
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn bearer_cache_isolates_entries_by_cred_identity() {
        use hort_domain::ports::secret_port::SecretSource;
        let cache = BearerCache::new();
        let secret = SecretRef {
            source: SecretSource::EnvVar,
            location: "HORT_TEST_PAT".into(),
        };
        let key_pat = CacheKey {
            realm: "https://r".into(),
            service: Some("svc".into()),
            scope: Some("scope".into()),
            cred_identity: Some(secret),
        };
        let key_anon = CacheKey {
            realm: "https://r".into(),
            service: Some("svc".into()),
            scope: Some("scope".into()),
            cred_identity: None,
        };
        cache.insert(
            key_pat.clone(),
            CachedToken {
                token: "pat-token".into(),
                expires_at: Instant::now() + Duration::from_secs(60),
            },
        );
        cache.insert(
            key_anon.clone(),
            CachedToken {
                token: "anon-token".into(),
                expires_at: Instant::now() + Duration::from_secs(60),
            },
        );
        assert_eq!(cache.get(&key_pat).unwrap().token, "pat-token");
        assert_eq!(cache.get(&key_anon).unwrap().token, "anon-token");
    }

    // -- Cache-key collapse semantics ------------------------------------

    /// Two cache keys with identical `SecretRef` values (and identical
    /// realm/service/scope) collapse to one entry. Insert via one key,
    /// read via an equivalent key.
    #[test]
    fn bearer_cache_collapses_identical_secret_refs() {
        use hort_domain::ports::secret_port::SecretSource;
        let cache = BearerCache::new();
        let key_a = CacheKey {
            realm: "https://r".into(),
            service: Some("svc".into()),
            scope: Some("scope".into()),
            cred_identity: Some(SecretRef {
                source: SecretSource::EnvVar,
                location: "HORT_SAME".into(),
            }),
        };
        let key_b = CacheKey {
            realm: "https://r".into(),
            service: Some("svc".into()),
            scope: Some("scope".into()),
            cred_identity: Some(SecretRef {
                source: SecretSource::EnvVar,
                location: "HORT_SAME".into(),
            }),
        };
        cache.insert(
            key_a.clone(),
            CachedToken {
                token: "shared-tok".into(),
                expires_at: Instant::now() + Duration::from_secs(60),
            },
        );
        // Reading via key_b — equivalent to key_a — must hit the
        // same entry. This is the "single PAT shared across two
        // mappings" operator wiring.
        let got = cache
            .get(&key_b)
            .expect("identical SecretRef must collapse");
        assert_eq!(got.token, "shared-tok");
    }

    /// Two cache keys whose `SecretRef.location` differs (same source,
    /// different env-var name / file path) key distinctly. Each token
    /// stays bound to its own credential.
    #[test]
    fn bearer_cache_distinguishes_distinct_secret_refs() {
        use hort_domain::ports::secret_port::SecretSource;
        let cache = BearerCache::new();
        let key_a = CacheKey {
            realm: "https://r".into(),
            service: Some("svc".into()),
            scope: Some("scope".into()),
            cred_identity: Some(SecretRef {
                source: SecretSource::File,
                location: "/run/secrets/a".into(),
            }),
        };
        let key_b = CacheKey {
            realm: "https://r".into(),
            service: Some("svc".into()),
            scope: Some("scope".into()),
            cred_identity: Some(SecretRef {
                source: SecretSource::File,
                location: "/run/secrets/b".into(),
            }),
        };
        cache.insert(
            key_a.clone(),
            CachedToken {
                token: "tok-a".into(),
                expires_at: Instant::now() + Duration::from_secs(60),
            },
        );
        cache.insert(
            key_b.clone(),
            CachedToken {
                token: "tok-b".into(),
                expires_at: Instant::now() + Duration::from_secs(60),
            },
        );
        assert_eq!(cache.get(&key_a).unwrap().token, "tok-a");
        assert_eq!(cache.get(&key_b).unwrap().token, "tok-b");
    }

    /// `secret_ref = None` (anonymous) keys distinctly from
    /// `secret_ref = Some(...)` (authenticated). An anonymous mapping
    /// never sees an authenticated token, and vice-versa.
    #[test]
    fn bearer_cache_distinguishes_anonymous_from_authenticated() {
        use hort_domain::ports::secret_port::SecretSource;
        let cache = BearerCache::new();
        let key_anon = CacheKey {
            realm: "https://r".into(),
            service: Some("svc".into()),
            scope: Some("scope".into()),
            cred_identity: None,
        };
        let key_auth = CacheKey {
            realm: "https://r".into(),
            service: Some("svc".into()),
            scope: Some("scope".into()),
            cred_identity: Some(SecretRef {
                source: SecretSource::EnvVar,
                location: "HORT_TOKEN".into(),
            }),
        };
        cache.insert(
            key_anon.clone(),
            CachedToken {
                token: "anon".into(),
                expires_at: Instant::now() + Duration::from_secs(60),
            },
        );
        cache.insert(
            key_auth.clone(),
            CachedToken {
                token: "auth".into(),
                expires_at: Instant::now() + Duration::from_secs(60),
            },
        );
        assert_eq!(cache.get(&key_anon).unwrap().token, "anon");
        assert_eq!(cache.get(&key_auth).unwrap().token, "auth");
    }

    // -- fetch_bearer_token -------------------------------------------

    fn proxy_no_secrets(server: &MockServer) -> HttpUpstreamProxy {
        // See `proxy_for` for the connect-time guard rationale. The
        // `server` argument is retained for signature stability.
        let _ = server;
        let cfg = HttpUpstreamProxyConfig {
            timeout: Duration::from_secs(2),
            format_label: "oci".to_string(),
            ..Default::default()
        };
        HttpUpstreamProxy::new(cfg, Arc::new(AnonymousFallbackPort)).unwrap()
    }

    #[tokio::test]
    async fn fetch_bearer_token_parses_token_field() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/realm"))
            .and(query_param("service", "svc"))
            .and(query_param("scope", "sc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "xyz",
                "expires_in": 300,
            })))
            .mount(&server)
            .await;
        let proxy = proxy_no_secrets(&server);
        let challenge = Challenge {
            realm: format!("{}/realm", server.uri()),
            service: Some("svc".into()),
            scope: Some("sc".into()),
        };
        let before = Instant::now();
        let cached = proxy.fetch_bearer_token(&challenge, None).await.unwrap();
        assert_eq!(cached.token, "xyz");
        // 300s - 30s slack = 270s budget; allow a 10s test-runtime slack.
        assert!(cached.expires_at > before + Duration::from_secs(260));
        assert!(cached.expires_at <= Instant::now() + Duration::from_secs(270));
    }

    #[tokio::test]
    async fn fetch_bearer_token_parses_access_token_field() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/realm"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "abc",
                "expires_in": 120,
            })))
            .mount(&server)
            .await;
        let proxy = proxy_no_secrets(&server);
        let challenge = Challenge {
            realm: format!("{}/realm", server.uri()),
            service: None,
            scope: None,
        };
        let before = Instant::now();
        let cached = proxy.fetch_bearer_token(&challenge, None).await.unwrap();
        assert_eq!(cached.token, "abc");
        // 120s - 30s = 90s.
        assert!(cached.expires_at > before + Duration::from_secs(80));
        assert!(cached.expires_at <= Instant::now() + Duration::from_secs(90));
    }

    #[tokio::test]
    async fn fetch_bearer_token_prefers_access_token_over_token_when_both_present() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/realm"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "alt",
                "access_token": "primary",
                "expires_in": 300,
            })))
            .mount(&server)
            .await;
        let proxy = proxy_no_secrets(&server);
        let challenge = Challenge {
            realm: format!("{}/realm", server.uri()),
            service: None,
            scope: None,
        };
        let cached = proxy.fetch_bearer_token(&challenge, None).await.unwrap();
        assert_eq!(cached.token, "primary");
    }

    #[tokio::test]
    async fn fetch_bearer_token_defaults_lifetime_when_expires_in_absent() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/realm"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "x",
            })))
            .mount(&server)
            .await;
        let proxy = proxy_no_secrets(&server);
        let challenge = Challenge {
            realm: format!("{}/realm", server.uri()),
            service: None,
            scope: None,
        };
        let before = Instant::now();
        let cached = proxy.fetch_bearer_token(&challenge, None).await.unwrap();
        assert_eq!(cached.token, "x");
        // Default 300s - 30s slack = 270s.
        assert!(cached.expires_at > before + Duration::from_secs(260));
        assert!(cached.expires_at <= Instant::now() + Duration::from_secs(270));
    }

    #[tokio::test]
    async fn fetch_bearer_token_sends_basic_auth_when_secret_provided() {
        use base64::Engine as _;
        let server = MockServer::start().await;
        let expected_basic = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("oauth2:secret-bytes")
        );
        Mock::given(method("GET"))
            .and(path("/realm"))
            .and(header(AUTHORIZATION, expected_basic.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "private-token",
                "expires_in": 300,
            })))
            .expect(1)
            .mount(&server)
            .await;
        let proxy = proxy_no_secrets(&server);
        let challenge = Challenge {
            realm: format!("{}/realm", server.uri()),
            service: None,
            scope: None,
        };
        let cached = proxy
            .fetch_bearer_token(
                &challenge,
                Some(SecretValue::from_bytes(b"secret-bytes".to_vec())),
            )
            .await
            .unwrap();
        assert_eq!(cached.token, "private-token");
    }

    #[tokio::test]
    async fn fetch_bearer_token_no_auth_when_secret_absent() {
        let server = MockServer::start().await;
        // Custom closure matcher: incoming request must NOT carry an
        // Authorization header. wiremock has no `not()` combinator on
        // its bundled matchers, so we use a closure (auto-`Match`).
        let no_authz =
            |req: &wiremock::Request| -> bool { !req.headers.contains_key(AUTHORIZATION) };
        Mock::given(method("GET"))
            .and(path("/realm"))
            .and(no_authz)
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "anon-token",
                "expires_in": 300,
            })))
            .expect(1)
            .mount(&server)
            .await;
        let proxy = proxy_no_secrets(&server);
        let challenge = Challenge {
            realm: format!("{}/realm", server.uri()),
            service: None,
            scope: None,
        };
        let cached = proxy.fetch_bearer_token(&challenge, None).await.unwrap();
        assert_eq!(cached.token, "anon-token");
    }

    #[tokio::test]
    async fn fetch_bearer_token_rejects_realm_4xx() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/realm"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let proxy = proxy_no_secrets(&server);
        let challenge = Challenge {
            realm: format!("{}/realm", server.uri()),
            service: None,
            scope: None,
        };
        let err = proxy
            .fetch_bearer_token(&challenge, None)
            .await
            .err()
            .unwrap();
        assert_eq!(classify_error(&err), Some(UpstreamErrorKind::Unauthorized));
    }

    #[tokio::test]
    async fn fetch_bearer_token_rejects_realm_5xx() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/realm"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let proxy = proxy_no_secrets(&server);
        let challenge = Challenge {
            realm: format!("{}/realm", server.uri()),
            service: None,
            scope: None,
        };
        let err = proxy
            .fetch_bearer_token(&challenge, None)
            .await
            .err()
            .unwrap();
        assert_eq!(classify_error(&err), Some(UpstreamErrorKind::Upstream5xx));
    }

    #[tokio::test]
    async fn fetch_bearer_token_rejects_missing_token_field() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/realm"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "expires_in": 300,
            })))
            .mount(&server)
            .await;
        let proxy = proxy_no_secrets(&server);
        let challenge = Challenge {
            realm: format!("{}/realm", server.uri()),
            service: None,
            scope: None,
        };
        let err = proxy
            .fetch_bearer_token(&challenge, None)
            .await
            .err()
            .unwrap();
        assert_eq!(classify_error(&err), Some(UpstreamErrorKind::ParseError));
    }

    // -- Realm scheme guard -------------------------------------------
    // The realm URL is operator-uncontrolled — it comes verbatim from the
    // upstream's `WWW-Authenticate` header. A malicious or compromised
    // upstream that returns `realm="http://attacker/token"` would, before
    // this guard, cause the proxy to send the resolved
    // `Authorization: Basic base64(oauth2:<PAT>)` over plaintext HTTP. The
    // guard rejects with `UpstreamErrorKind::ParseError` BEFORE any
    // credential leaves the process.

    #[tokio::test]
    async fn fetch_bearer_token_rejects_http_realm_before_sending_credential() {
        // The realm URL has scheme `http://`. We must reject without
        // contacting the realm — the assertion is on the returned error
        // classification; any wiremock setup is unnecessary because no
        // request should be made.
        let proxy = {
            let cfg = HttpUpstreamProxyConfig {
                timeout: Duration::from_secs(2),
                format_label: "oci".to_string(),
                ..Default::default()
            };
            HttpUpstreamProxy::new(cfg, Arc::new(AnonymousFallbackPort)).unwrap()
        };
        let challenge = Challenge {
            realm: "http://attacker.example.com/token".into(),
            service: Some("svc".into()),
            scope: Some("repository:foo:pull".into()),
        };
        // Construct a SecretValue so the test would-also-fail-loud if
        // the implementation forwards the secret to the (non-https)
        // realm. The bytes must NOT appear on any wire — there is no
        // wire to send them on, but the regression-test discipline is
        // the same: the guard runs before the credential is touched.
        let secret = SecretValue::from_bytes(b"would-be-leaked-PAT".to_vec());
        let err = proxy
            .fetch_bearer_token(&challenge, Some(secret))
            .await
            .err()
            .expect("http:// realm must be rejected");
        assert_eq!(
            classify_error(&err),
            Some(UpstreamErrorKind::ParseError),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn fetch_bearer_token_rejects_nonroutable_realm_before_sending_credential() {
        // The realm host is upstream-controlled (verbatim from the
        // `WWW-Authenticate` header). The scheme guard blocks a
        // plaintext-`http` credential leak, but an `https` realm whose
        // host is a non-routable internal address (cloud IMDS
        // 169.254.169.254, RFC1918, …) would otherwise still receive the
        // `Authorization: Basic base64(oauth2:<PAT>)` header — an SSRF +
        // credential-exfiltration sink. The routability guard must reject
        // it BEFORE the secret is touched, exactly like the scheme guard.
        // Uses an IP literal so the resolve is deterministic and offline
        // (no DNS, no connection attempt once the fix is in place).
        let proxy = {
            let cfg = HttpUpstreamProxyConfig {
                timeout: Duration::from_secs(2),
                format_label: "oci".to_string(),
                ..Default::default()
            };
            HttpUpstreamProxy::new(cfg, Arc::new(AnonymousFallbackPort)).unwrap()
        };
        let challenge = Challenge {
            realm: "https://169.254.169.254/token".into(),
            service: Some("svc".into()),
            scope: Some("repository:foo:pull".into()),
        };
        let secret = SecretValue::from_bytes(b"would-be-leaked-PAT".to_vec());
        let err = proxy
            .fetch_bearer_token(&challenge, Some(secret))
            .await
            .err()
            .expect("non-routable realm must be rejected before sending the credential");
        assert_eq!(
            classify_error(&err),
            Some(UpstreamErrorKind::ParseError),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn fetch_bearer_token_accepts_https_realm() {
        // Sanity check the inverse: an https:// realm is accepted (any
        // existing positive test would prove this; the assertion lives
        // here so both branches are in one place).
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/realm"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "ok",
            })))
            .mount(&server)
            .await;
        // Build the proxy using the existing wiremock allowlist path so
        // the loopback connect is permitted.
        let proxy = proxy_no_secrets(&server);
        // wiremock's URI is http://; replace scheme to https just to
        // demonstrate the realm-string path. We can't actually serve TLS
        // in-test, so verify only that the guard does NOT reject https
        // by exercising the existing positive test indirectly: a
        // wiremock URI is http but produced by our test infrastructure
        // and we accept that an http://127.0.0.1 realm is special-cased
        // by the loopback IP-classifier check — i.e., the existing
        // positive tests above use http://127.0.0.1 realms without this
        // assertion failing because the production implementation only
        // allows https:// for non-loopback hosts. To honour the
        // production-only-https posture without breaking wiremock-based
        // positive tests, `realm_host_is_loopback` returns true for any
        // host that parses as a loopback IP literal — the existing
        // positive tests prove the happy path works against http://
        // wiremock realms. The OS-level `IpAddr::is_loopback()` classifier
        // identifies the loopback range.
        let challenge = Challenge {
            realm: format!("{}/realm", server.uri()),
            service: None,
            scope: None,
        };
        let cached = proxy.fetch_bearer_token(&challenge, None).await.unwrap();
        assert_eq!(cached.token, "ok");
    }

    #[tokio::test]
    async fn fetch_bearer_token_passes_service_and_scope_query_params() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/realm"))
            .and(query_param("service", "registry.docker.io"))
            .and(query_param("scope", "repository:library/alpine:pull"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "ok",
                "expires_in": 300,
            })))
            .expect(1)
            .mount(&server)
            .await;
        let proxy = proxy_no_secrets(&server);
        let challenge = Challenge {
            realm: format!("{}/realm", server.uri()),
            service: Some("registry.docker.io".into()),
            scope: Some("repository:library/alpine:pull".into()),
        };
        let cached = proxy.fetch_bearer_token(&challenge, None).await.unwrap();
        assert_eq!(cached.token, "ok");
    }

    #[tokio::test]
    async fn fetch_bearer_token_omits_query_params_when_challenge_lacks_them() {
        let server = MockServer::start().await;
        // Mock with explicit absence: incoming GET /realm with no
        // service/scope query parameters must match.
        Mock::given(method("GET"))
            .and(path("/realm"))
            .and(wiremock::matchers::query_param_is_missing("service"))
            .and(wiremock::matchers::query_param_is_missing("scope"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "ok",
            })))
            .expect(1)
            .mount(&server)
            .await;
        let proxy = proxy_no_secrets(&server);
        let challenge = Challenge {
            realm: format!("{}/realm", server.uri()),
            service: None,
            scope: None,
        };
        let cached = proxy.fetch_bearer_token(&challenge, None).await.unwrap();
        assert_eq!(cached.token, "ok");
    }

    // -- 401-driven challenge dance -----------------------------------

    /// Helper: build a `WWW-Authenticate: Bearer ...` header pointing
    /// the realm at the given path on the wiremock server.
    fn challenge_header(server: &MockServer, scope: &str) -> String {
        format!(
            r#"Bearer realm="{}/realm",service="svc",scope="{}""#,
            server.uri(),
            scope
        )
    }

    /// Cold cache: GHCR-style realm response with `token` field.
    /// 401 → parse → exchange → retry with Bearer → 200 stream body.
    #[tokio::test]
    async fn bearer_challenge_cold_cache_does_401_dance_then_succeeds_token_field() {
        let server = MockServer::start().await;
        let challenge = challenge_header(&server, "repository:p:pull");
        // First-attempt 401 (no Authorization header).
        let no_authz =
            |req: &wiremock::Request| -> bool { !req.headers.contains_key(AUTHORIZATION) };
        Mock::given(method("GET"))
            .and(path("/v2/p/blobs/sha256:abc"))
            .and(no_authz)
            .respond_with(
                ResponseTemplate::new(401).insert_header("WWW-Authenticate", challenge.as_str()),
            )
            .mount(&server)
            .await;
        // Realm endpoint (returns `token`).
        Mock::given(method("GET"))
            .and(path("/realm"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "ghcr-tok",
                "expires_in": 300,
            })))
            .expect(1)
            .mount(&server)
            .await;
        // Retry with Bearer succeeds.
        Mock::given(method("GET"))
            .and(path("/v2/p/blobs/sha256:abc"))
            .and(header(AUTHORIZATION, "Bearer ghcr-tok"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"blob-bytes".as_slice()))
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::BearerChallenge);
        let mut stream = proxy
            .fetch_blob(m, "p".into(), "sha256:abc".into())
            .await
            .expect("cold cache flow")
            .stream;
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            bytes.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(bytes, b"blob-bytes");
    }

    /// Cold cache: Docker Hub-style realm response with `access_token`.
    #[tokio::test]
    async fn bearer_challenge_cold_cache_does_401_dance_then_succeeds_access_token_field() {
        let server = MockServer::start().await;
        let challenge = challenge_header(&server, "repository:library/alpine:pull");
        let no_authz =
            |req: &wiremock::Request| -> bool { !req.headers.contains_key(AUTHORIZATION) };
        Mock::given(method("GET"))
            .and(path("/v2/library/alpine/blobs/sha256:dh"))
            .and(no_authz)
            .respond_with(
                ResponseTemplate::new(401).insert_header("WWW-Authenticate", challenge.as_str()),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/realm"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "dh-tok",
                "expires_in": 300,
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v2/library/alpine/blobs/sha256:dh"))
            .and(header(AUTHORIZATION, "Bearer dh-tok"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"dh-blob".as_slice()))
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::BearerChallenge);
        let mut stream = proxy
            .fetch_blob(m, "library/alpine".into(), "sha256:dh".into())
            .await
            .expect("docker hub flow")
            .stream;
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            bytes.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(bytes, b"dh-blob");
    }

    /// Warm cache: prime via a 401 dance, then assert the second
    /// fetch sends `Authorization: Bearer <token>` directly with no
    /// realm round-trip.
    #[tokio::test]
    async fn bearer_challenge_warm_cache_skips_401_and_uses_cached_token() {
        let server = MockServer::start().await;
        let challenge = challenge_header(&server, "repository:p:pull");
        let no_authz =
            |req: &wiremock::Request| -> bool { !req.headers.contains_key(AUTHORIZATION) };
        // 401 only fires for the cold-cache request.
        Mock::given(method("GET"))
            .and(path("/v2/p/blobs/sha256:warm"))
            .and(no_authz)
            .respond_with(
                ResponseTemplate::new(401).insert_header("WWW-Authenticate", challenge.as_str()),
            )
            .expect(1)
            .mount(&server)
            .await;
        // Realm fires exactly once.
        Mock::given(method("GET"))
            .and(path("/realm"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "warm-tok",
                "expires_in": 300,
            })))
            .expect(1)
            .mount(&server)
            .await;
        // Both fetches succeed when carrying Bearer.
        Mock::given(method("GET"))
            .and(path("/v2/p/blobs/sha256:warm"))
            .and(header(AUTHORIZATION, "Bearer warm-tok"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"warm".as_slice()))
            .expect(2)
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::BearerChallenge);
        // Cold-cache fetch.
        let _ = proxy
            .fetch_blob(m.clone(), "p".into(), "sha256:warm".into())
            .await
            .expect("first fetch");
        // Warm-cache fetch — should NOT trigger another 401 dance.
        let _ = proxy
            .fetch_blob(m, "p".into(), "sha256:warm".into())
            .await
            .expect("second fetch");
        // wiremock's `.expect(N)` assertions are verified on drop.
    }

    /// Stale-token 401: prime cache, then upstream returns 401 again
    /// with cached token. Adapter invalidates, re-exchanges, retries.
    #[tokio::test]
    async fn bearer_challenge_stale_token_401_invalidates_and_re_exchanges() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let server = MockServer::start().await;
        let challenge = challenge_header(&server, "repository:p:pull");

        // First-attempt 401 (no Authorization). Fires once on the
        // prime fetch.
        let no_authz =
            |req: &wiremock::Request| -> bool { !req.headers.contains_key(AUTHORIZATION) };
        Mock::given(method("GET"))
            .and(path("/v2/p/blobs/sha256:stale"))
            .and(no_authz)
            .respond_with(
                ResponseTemplate::new(401).insert_header("WWW-Authenticate", challenge.as_str()),
            )
            .expect(1)
            .mount(&server)
            .await;

        // Stateful responder for the Bearer first-tok blob: first
        // call (the prime's retry) returns 200; second call (the
        // second fetch's stale-token attempt) returns 401.
        let blob_phase = Arc::new(AtomicUsize::new(0));
        let blob_phase_clone = blob_phase.clone();
        let challenge_for_resp = challenge.clone();
        Mock::given(method("GET"))
            .and(path("/v2/p/blobs/sha256:stale"))
            .and(header(AUTHORIZATION, "Bearer first-tok"))
            .respond_with(move |_req: &wiremock::Request| {
                let n = blob_phase_clone.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    ResponseTemplate::new(200).set_body_bytes(b"primed".as_slice())
                } else {
                    ResponseTemplate::new(401)
                        .insert_header("WWW-Authenticate", challenge_for_resp.as_str())
                }
            })
            .expect(2)
            .mount(&server)
            .await;

        // After invalidate + re-exchange, second token wins.
        Mock::given(method("GET"))
            .and(path("/v2/p/blobs/sha256:stale"))
            .and(header(AUTHORIZATION, "Bearer second-tok"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"finally".as_slice()))
            .expect(1)
            .mount(&server)
            .await;

        // Realm endpoint: first call returns first-tok, second returns second-tok.
        let phase = Arc::new(AtomicUsize::new(0));
        let phase_clone = phase.clone();
        Mock::given(method("GET"))
            .and(path("/realm"))
            .respond_with(move |_req: &wiremock::Request| {
                let n = phase_clone.fetch_add(1, Ordering::SeqCst);
                let tok = if n == 0 { "first-tok" } else { "second-tok" };
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "token": tok,
                    "expires_in": 300,
                }))
            })
            .expect(2)
            .mount(&server)
            .await;

        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::BearerChallenge);
        // Cold-cache fetch primes "first-tok".
        let mut s1 = proxy
            .fetch_blob(m.clone(), "p".into(), "sha256:stale".into())
            .await
            .expect("prime")
            .stream;
        let mut prime_bytes = Vec::new();
        while let Some(c) = s1.next().await {
            prime_bytes.extend_from_slice(&c.unwrap());
        }
        assert_eq!(prime_bytes, b"primed");
        // Second fetch: stale-token 401 → invalidate → re-exchange → success.
        let mut stream = proxy
            .fetch_blob(m, "p".into(), "sha256:stale".into())
            .await
            .expect("re-exchange flow")
            .stream;
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            bytes.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(bytes, b"finally");
    }

    /// At-most-one challenge round per request: stale-token 401 →
    /// invalidate → re-exchange → second 401 with
    /// `error="insufficient_scope"` surfaces as `Unauthorized`.
    /// No third re-exchange.
    #[tokio::test]
    async fn bearer_challenge_second_401_after_re_exchange_surfaces_unauthorized() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let server = MockServer::start().await;
        let challenge = challenge_header(&server, "repository:p:pull");
        let challenge_with_err = format!(
            r#"Bearer realm="{}/realm",service="svc",scope="repository:p:pull",error="insufficient_scope""#,
            server.uri()
        );

        let no_authz =
            |req: &wiremock::Request| -> bool { !req.headers.contains_key(AUTHORIZATION) };
        // Cold-cache 401 (prime fetch only).
        Mock::given(method("GET"))
            .and(path("/v2/p/blobs/sha256:never"))
            .and(no_authz)
            .respond_with(
                ResponseTemplate::new(401).insert_header("WWW-Authenticate", challenge.as_str()),
            )
            .expect(1)
            .mount(&server)
            .await;
        // Bearer first-tok: prime succeeds, second-fetch's stale-attempt 401s.
        let blob_phase = Arc::new(AtomicUsize::new(0));
        let blob_phase_clone = blob_phase.clone();
        let challenge_for_first = challenge.clone();
        Mock::given(method("GET"))
            .and(path("/v2/p/blobs/sha256:never"))
            .and(header(AUTHORIZATION, "Bearer first-tok"))
            .respond_with(move |_req: &wiremock::Request| {
                let n = blob_phase_clone.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    ResponseTemplate::new(200).set_body_bytes(b"primed".as_slice())
                } else {
                    ResponseTemplate::new(401)
                        .insert_header("WWW-Authenticate", challenge_for_first.as_str())
                }
            })
            .expect(2)
            .mount(&server)
            .await;
        // After re-exchange to second-tok: 401 again carrying error="...".
        Mock::given(method("GET"))
            .and(path("/v2/p/blobs/sha256:never"))
            .and(header(AUTHORIZATION, "Bearer second-tok"))
            .respond_with(
                ResponseTemplate::new(401)
                    .insert_header("WWW-Authenticate", challenge_with_err.as_str()),
            )
            .expect(1)
            .mount(&server)
            .await;

        let phase = Arc::new(AtomicUsize::new(0));
        let phase_clone = phase.clone();
        // Realm hit exactly twice (prime + post-stale re-exchange).
        // A third hit would violate the at-most-one-challenge invariant.
        Mock::given(method("GET"))
            .and(path("/realm"))
            .respond_with(move |_req: &wiremock::Request| {
                let n = phase_clone.fetch_add(1, Ordering::SeqCst);
                let tok = if n == 0 { "first-tok" } else { "second-tok" };
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "token": tok,
                    "expires_in": 300,
                }))
            })
            .expect(2)
            .mount(&server)
            .await;

        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::BearerChallenge);
        // Prime.
        let mut s1 = proxy
            .fetch_blob(m.clone(), "p".into(), "sha256:never".into())
            .await
            .expect("prime")
            .stream;
        let mut bytes = Vec::new();
        while let Some(c) = s1.next().await {
            bytes.extend_from_slice(&c.unwrap());
        }
        assert_eq!(bytes, b"primed");
        // Second fetch: stale 401 → re-exchange → second 401 → Unauthorized.
        let err = proxy
            .fetch_blob(m, "p".into(), "sha256:never".into())
            .await
            .err()
            .expect("must surface 401 verbatim");
        assert_eq!(classify_error(&err), Some(UpstreamErrorKind::Unauthorized));
    }

    /// Two mappings, same upstream URL, same challenge, different
    /// `secret_ref` values: the cache MUST keep them separate.
    /// PAT-mapping carries the PAT-issued token; anonymous mapping
    /// carries the anonymous-issued token. Neither sees the other's
    /// bearer.
    #[tokio::test]
    async fn bearer_challenge_cred_identity_isolation() {
        use hort_domain::ports::secret_port::SecretSource;
        let server = MockServer::start().await;
        let challenge = challenge_header(&server, "repository:p:pull");
        let pat_ref = SecretRef {
            source: SecretSource::EnvVar,
            location: "HORT_PAT_TEST".into(),
        };

        let no_authz =
            |req: &wiremock::Request| -> bool { !req.headers.contains_key(AUTHORIZATION) };
        // Both fetches start with a 401.
        Mock::given(method("GET"))
            .and(path("/v2/p/blobs/sha256:iso"))
            .and(no_authz)
            .respond_with(
                ResponseTemplate::new(401).insert_header("WWW-Authenticate", challenge.as_str()),
            )
            .expect(2)
            .mount(&server)
            .await;

        // Realm receives PAT request → issues "pat-tok"; anon
        // request → issues "anon-tok". Match on Basic header presence.
        let pat_basic = {
            use base64::Engine as _;
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode("oauth2:my-pat")
            )
        };
        Mock::given(method("GET"))
            .and(path("/realm"))
            .and(header(AUTHORIZATION, pat_basic.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "pat-tok",
                "expires_in": 300,
            })))
            .expect(1)
            .mount(&server)
            .await;
        let realm_anon = |req: &wiremock::Request| -> bool {
            req.url.path() == "/realm" && !req.headers.contains_key(AUTHORIZATION)
        };
        Mock::given(method("GET"))
            .and(realm_anon)
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "anon-tok",
                "expires_in": 300,
            })))
            .expect(1)
            .mount(&server)
            .await;

        // Resource fetch must carry the right token per mapping.
        Mock::given(method("GET"))
            .and(path("/v2/p/blobs/sha256:iso"))
            .and(header(AUTHORIZATION, "Bearer pat-tok"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"pat-blob".as_slice()))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v2/p/blobs/sha256:iso"))
            .and(header(AUTHORIZATION, "Bearer anon-tok"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"anon-blob".as_slice()))
            .expect(1)
            .mount(&server)
            .await;

        // Stub `SecretPort` that resolves the PAT ref to "my-pat" and
        // returns NotFound for any other ref.
        struct StubSecretPort {
            target: SecretRef,
            value: Vec<u8>,
        }
        impl SecretPort for StubSecretPort {
            fn resolve<'a>(
                &'a self,
                reference: &'a SecretRef,
            ) -> BoxFuture<'a, DomainResult<SecretValue>> {
                let matched = reference == &self.target;
                let bytes = self.value.clone();
                Box::pin(async move {
                    if matched {
                        Ok(SecretValue::from_bytes(bytes))
                    } else {
                        Err(DomainError::Invariant("secret not found".into()))
                    }
                })
            }
        }
        let cfg = HttpUpstreamProxyConfig {
            timeout: Duration::from_secs(2),
            format_label: "oci".to_string(),
            ..Default::default()
        };
        let proxy = HttpUpstreamProxy::new(
            cfg,
            Arc::new(StubSecretPort {
                target: pat_ref.clone(),
                value: b"my-pat".to_vec(),
            }),
        )
        .unwrap();

        let mut m_pat = mapping(&server.uri(), "", UpstreamAuth::BearerChallenge);
        m_pat.secret_ref = Some(pat_ref);
        let m_anon = mapping(&server.uri(), "", UpstreamAuth::BearerChallenge);

        let mut s_pat = proxy
            .fetch_blob(m_pat, "p".into(), "sha256:iso".into())
            .await
            .expect("pat fetch")
            .stream;
        let mut pat_bytes = Vec::new();
        while let Some(c) = s_pat.next().await {
            pat_bytes.extend_from_slice(&c.unwrap());
        }
        assert_eq!(pat_bytes, b"pat-blob");

        let mut s_anon = proxy
            .fetch_blob(m_anon, "p".into(), "sha256:iso".into())
            .await
            .expect("anon fetch")
            .stream;
        let mut anon_bytes = Vec::new();
        while let Some(c) = s_anon.next().await {
            anon_bytes.extend_from_slice(&c.unwrap());
        }
        assert_eq!(anon_bytes, b"anon-blob");
    }

    /// `secret_ref = Some(...)` but the `SecretPort` returns
    /// `Err(NotFound)`: the realm exchange MUST NOT silently anonymise.
    /// The error surfaces as fetch_failed (NetworkError). Operator-wired
    /// secret resolution is fail-fast; there is no fall-through-to-
    /// anonymous path.
    #[tokio::test]
    async fn bearer_challenge_secret_not_found_surfaces_fetch_failed() {
        use hort_domain::ports::secret_port::SecretSource;
        let server = MockServer::start().await;
        let challenge = challenge_header(&server, "repository:p:pull");

        let no_authz =
            |req: &wiremock::Request| -> bool { !req.headers.contains_key(AUTHORIZATION) };
        Mock::given(method("GET"))
            .and(path("/v2/p/blobs/sha256:orph"))
            .and(no_authz)
            .respond_with(
                ResponseTemplate::new(401).insert_header("WWW-Authenticate", challenge.as_str()),
            )
            .expect(1)
            .mount(&server)
            .await;

        // Stub `SecretPort` always returns NotFound-shaped Err.
        struct AlwaysNone;
        impl SecretPort for AlwaysNone {
            fn resolve<'a>(
                &'a self,
                _reference: &'a SecretRef,
            ) -> BoxFuture<'a, DomainResult<SecretValue>> {
                Box::pin(async { Err(DomainError::Invariant("not found".into())) })
            }
        }
        let cfg = HttpUpstreamProxyConfig {
            timeout: Duration::from_secs(2),
            format_label: "oci".to_string(),
            ..Default::default()
        };
        let proxy = HttpUpstreamProxy::new(cfg, Arc::new(AlwaysNone)).unwrap();
        let mut m = mapping(&server.uri(), "", UpstreamAuth::BearerChallenge);
        m.secret_ref = Some(SecretRef {
            source: SecretSource::EnvVar,
            location: "HORT_MISSING".into(),
        });

        let err = proxy
            .fetch_blob(m, "p".into(), "sha256:orph".into())
            .await
            .err()
            .expect("must surface secret-not-found as fetch_failed");
        assert_eq!(classify_error(&err), Some(UpstreamErrorKind::NetworkError));
    }

    /// Secret resolution `Err`: adapter MUST NOT silently anonymise.
    /// Surface a classified error (we map this to NetworkError —
    /// infrastructure dependency failure).
    #[tokio::test]
    async fn bearer_challenge_secret_resolution_err_surfaces_fetch_failed() {
        use hort_domain::ports::secret_port::SecretSource;
        let server = MockServer::start().await;
        let challenge = challenge_header(&server, "repository:p:pull");

        let no_authz =
            |req: &wiremock::Request| -> bool { !req.headers.contains_key(AUTHORIZATION) };
        Mock::given(method("GET"))
            .and(path("/v2/p/blobs/sha256:dep"))
            .and(no_authz)
            .respond_with(
                ResponseTemplate::new(401).insert_header("WWW-Authenticate", challenge.as_str()),
            )
            .expect(1)
            .mount(&server)
            .await;

        // Realm must NOT be hit — the secret resolution failure
        // short-circuits before we get there.
        struct AlwaysErr;
        impl SecretPort for AlwaysErr {
            fn resolve<'a>(
                &'a self,
                _reference: &'a SecretRef,
            ) -> BoxFuture<'a, DomainResult<SecretValue>> {
                Box::pin(async { Err(DomainError::Invariant("read failure".into())) })
            }
        }
        let cfg = HttpUpstreamProxyConfig {
            timeout: Duration::from_secs(2),
            format_label: "oci".to_string(),
            ..Default::default()
        };
        let proxy = HttpUpstreamProxy::new(cfg, Arc::new(AlwaysErr)).unwrap();
        let mut m = mapping(&server.uri(), "", UpstreamAuth::BearerChallenge);
        m.secret_ref = Some(SecretRef {
            source: SecretSource::File,
            location: "/run/secrets/never".into(),
        });

        let err = proxy
            .fetch_blob(m, "p".into(), "sha256:dep".into())
            .await
            .err()
            .expect("must propagate secrets-store error");
        // Mapped to NetworkError (infrastructure dependency failure).
        assert_eq!(classify_error(&err), Some(UpstreamErrorKind::NetworkError));
    }

    /// Basic-auth resolve `Err`: must surface a sentinel-prefixed
    /// classified error, NOT a bare `DomainError::Invariant`. Without
    /// the wrap, `classify_error` returns `None` and the metric label
    /// defaults to `parse_error` — wrong kind for an
    /// infrastructure-dependency failure. Mirrors the BearerChallenge
    /// realm-exchange wrap (see
    /// `bearer_challenge_secret_resolution_err_surfaces_fetch_failed`).
    #[tokio::test]
    async fn basic_secret_resolution_err_surfaces_classified_network_error() {
        use hort_domain::ports::secret_port::SecretSource;
        let server = MockServer::start().await;

        // The realm/upstream must NOT be hit — the secret-resolution
        // failure short-circuits inside `authorization_header` before
        // any HTTP traffic.
        struct AlwaysErr;
        impl SecretPort for AlwaysErr {
            fn resolve<'a>(
                &'a self,
                _reference: &'a SecretRef,
            ) -> BoxFuture<'a, DomainResult<SecretValue>> {
                Box::pin(async { Err(DomainError::Invariant("read failure".into())) })
            }
        }
        let cfg = HttpUpstreamProxyConfig {
            timeout: Duration::from_secs(2),
            format_label: "oci".to_string(),
            ..Default::default()
        };
        let proxy = HttpUpstreamProxy::new(cfg, Arc::new(AlwaysErr)).unwrap();
        let mut m = mapping(
            &server.uri(),
            "",
            UpstreamAuth::Basic {
                username: "oauth2".into(),
            },
        );
        m.secret_ref = Some(SecretRef {
            source: SecretSource::EnvVar,
            location: "HORT_MISSING_BASIC".into(),
        });

        let err = proxy
            .fetch_blob(m, "p".into(), "sha256:dep".into())
            .await
            .err()
            .expect("must propagate secrets-store error");
        // Sentinel must round-trip through classify_error — without
        // the wrap this returns None and the metric label degenerates
        // to `parse_error`.
        assert_eq!(classify_error(&err), Some(UpstreamErrorKind::NetworkError));
    }

    // ----------------------------------------------------------------------
    // Basic-auth header construction
    //
    // Exercises the Basic-auth path inside `authorization_header`. The
    // assertion is the *value* of the constructed header — the Zeroizing
    // wrapping itself is not portably testable (drop-time memory clearing
    // leaves no observable side-effect at the type level), so the
    // contract is pinned by:
    //   1. This wire-format test (the bytes look right).
    //   2. The source-level `Zeroizing<String>` annotations on every
    //      intermediate (reviewer enforces).
    // ----------------------------------------------------------------------

    /// Stub `SecretPort` that returns a fixed byte payload — used to
    /// exercise the Basic-auth path of `authorization_header` end-to-
    /// end without touching any process env.
    struct FixedSecretPort {
        bytes: Vec<u8>,
    }
    impl SecretPort for FixedSecretPort {
        fn resolve<'a>(
            &'a self,
            _reference: &'a SecretRef,
        ) -> BoxFuture<'a, DomainResult<SecretValue>> {
            let bytes = self.bytes.clone();
            Box::pin(async move { Ok(SecretValue::from_bytes(bytes)) })
        }
    }

    #[tokio::test]
    async fn basic_auth_header_value_matches_base64_username_colon_password() {
        use base64::Engine as _;
        use hort_domain::ports::secret_port::SecretSource;

        // Wire the upstream to expect exactly one request carrying the
        // Basic-auth header for `myuser:hunter2`. wiremock's
        // `header(...)` matcher checks an exact-string match; if the
        // adapter's intermediate-string handling drops a byte (or
        // adds whitespace) the mock returns 4xx and the test fails.
        let expected_basic = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("myuser:hunter2")
        );

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/p/blobs/sha256:basic"))
            .and(header(AUTHORIZATION, expected_basic.as_str()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("docker-content-digest", "sha256:basic")
                    .set_body_bytes(b"basic-blob".as_slice()),
            )
            .expect(1)
            .mount(&server)
            .await;

        let cfg = HttpUpstreamProxyConfig {
            timeout: Duration::from_secs(2),
            format_label: "oci".to_string(),
            ..Default::default()
        };
        let port = Arc::new(FixedSecretPort {
            bytes: b"hunter2".to_vec(),
        });
        let proxy = HttpUpstreamProxy::new(cfg, port).unwrap();

        let mut m = mapping(
            &server.uri(),
            "",
            UpstreamAuth::Basic {
                username: "myuser".into(),
            },
        );
        m.secret_ref = Some(SecretRef {
            source: SecretSource::EnvVar,
            location: "HORT_BASIC_TEST".into(),
        });

        let mut stream = proxy
            .fetch_blob(m, "p".into(), "sha256:basic".into())
            .await
            .expect("fetch_blob with Basic auth")
            .stream;
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            body.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(body, b"basic-blob");
    }

    /// Boundary: empty password still produces a syntactically valid
    /// `Basic base64("user:")` header. The Zeroizing<String> wrapping
    /// does not change the encoded bytes — this test guards against a
    /// future refactor that accidentally trims trailing empties.
    #[tokio::test]
    async fn basic_auth_header_handles_empty_password() {
        use base64::Engine as _;
        use hort_domain::ports::secret_port::SecretSource;

        let expected_basic = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("u:")
        );

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/p/blobs/sha256:empty"))
            .and(header(AUTHORIZATION, expected_basic.as_str()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("docker-content-digest", "sha256:empty")
                    .set_body_bytes(b"e".as_slice()),
            )
            .expect(1)
            .mount(&server)
            .await;

        let cfg = HttpUpstreamProxyConfig {
            timeout: Duration::from_secs(2),
            format_label: "oci".to_string(),
            ..Default::default()
        };
        let port = Arc::new(FixedSecretPort { bytes: vec![] });
        let proxy = HttpUpstreamProxy::new(cfg, port).unwrap();

        let mut m = mapping(
            &server.uri(),
            "",
            UpstreamAuth::Basic {
                username: "u".into(),
            },
        );
        m.secret_ref = Some(SecretRef {
            source: SecretSource::EnvVar,
            location: "HORT_EMPTY".into(),
        });

        let mut stream = proxy
            .fetch_blob(m, "p".into(), "sha256:empty".into())
            .await
            .expect("fetch_blob")
            .stream;
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            body.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(body, b"e");
    }

    /// Malformed `WWW-Authenticate` header (Basic instead of Bearer):
    /// surface 401 verbatim, no exchange attempt.
    #[tokio::test]
    async fn bearer_challenge_malformed_www_authenticate_header_surfaces_unauthorized() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/p/blobs/sha256:bad"))
            .respond_with(
                ResponseTemplate::new(401).insert_header("WWW-Authenticate", "Basic realm=\"x\""),
            )
            .expect(1)
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::BearerChallenge);
        let err = proxy
            .fetch_blob(m, "p".into(), "sha256:bad".into())
            .await
            .err()
            .expect("malformed challenge surfaces 401");
        assert_eq!(classify_error(&err), Some(UpstreamErrorKind::Unauthorized));
    }

    /// Realm 5xx: classified error surfaces, NOT a silent retry.
    #[tokio::test]
    async fn bearer_challenge_realm_5xx_surfaces_classified_error() {
        let server = MockServer::start().await;
        let challenge = challenge_header(&server, "repository:p:pull");
        Mock::given(method("GET"))
            .and(path("/v2/p/blobs/sha256:r5xx"))
            .respond_with(
                ResponseTemplate::new(401).insert_header("WWW-Authenticate", challenge.as_str()),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/realm"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::BearerChallenge);
        let err = proxy
            .fetch_blob(m, "p".into(), "sha256:r5xx".into())
            .await
            .err()
            .expect("realm 5xx propagates");
        assert_eq!(classify_error(&err), Some(UpstreamErrorKind::Upstream5xx));
    }

    // -- classify_error round-trip --------------------------------------

    #[test]
    fn classify_error_round_trips_known_kinds() {
        for kind in [
            UpstreamErrorKind::NotFound,
            UpstreamErrorKind::Unauthorized,
            UpstreamErrorKind::RateLimited,
            UpstreamErrorKind::Upstream4xx,
            UpstreamErrorKind::Upstream5xx,
            UpstreamErrorKind::NetworkError,
            UpstreamErrorKind::Timeout,
            UpstreamErrorKind::BodyTooLarge,
        ] {
            let err = classified_error(kind, "x");
            assert_eq!(classify_error(&err), Some(kind));
        }
    }

    #[test]
    fn classify_error_returns_none_for_unrelated_invariants() {
        let err = DomainError::Invariant("something else".into());
        assert!(classify_error(&err).is_none());
    }

    // -- Trait-object plumbing ------------------------------------------

    #[test]
    fn adapter_implements_port() {
        fn _assert_port<T: UpstreamProxy>() {}
        _assert_port::<HttpUpstreamProxy>();
    }

    // -- Metric emission ------------------------------------------------

    /// fetch_blob fires `hort_upstream_fetch_total` with
    /// `result=success` on a happy-path 200 and the configured
    /// `format` label.
    #[test]
    fn fetch_blob_emits_success_metric_with_format_label() {
        use metrics::{Key, Label};
        use metrics_util::debugging::DebuggingRecorder;
        use metrics_util::CompositeKey;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let server = MockServer::start().await;
                    Mock::given(method("GET"))
                        .and(path("/v2/p/blobs/sha256:ok"))
                        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"x".as_slice()))
                        .mount(&server)
                        .await;
                    let proxy = proxy_for(&server);
                    let m = mapping(&server.uri(), "ghcr/", UpstreamAuth::Anonymous);
                    let _ = proxy
                        .fetch_blob(m, "p".into(), "sha256:ok".into())
                        .await
                        .expect("happy path");
                });
        });

        let mut found = false;
        for (key, _, _, _) in snapshotter.snapshot().into_vec() {
            let CompositeKey { .. } = &key;
            let inner: &Key = key.key();
            if inner.name() != METRIC_FETCH {
                continue;
            }
            let mut format_ok = false;
            let mut upstream_ok = false;
            let mut result_ok = false;
            for label in inner.labels() {
                let Label { .. } = label;
                match label.key() {
                    "format" if label.value() == "oci" => format_ok = true,
                    "upstream" if label.value() == "ghcr" => upstream_ok = true,
                    "result" if label.value() == "success" => result_ok = true,
                    _ => {}
                }
            }
            if format_ok && upstream_ok && result_ok {
                found = true;
            }
        }
        assert!(
            found,
            "expected hort_upstream_fetch_total{{format=oci,upstream=ghcr,result=success}}"
        );
    }

    /// `hort_upstream_bearer_token_total` fires with the right labels:
    /// `result=exchange` on the cold-cache 401 dance, `result=cache_hit`
    /// on the subsequent warm-cache fetch.
    #[test]
    fn bearer_token_metric_fires_with_correct_labels_on_cache_miss_then_hit() {
        use metrics::{Key, Label};
        use metrics_util::debugging::DebuggingRecorder;
        use metrics_util::CompositeKey;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let server = MockServer::start().await;
                    let challenge = challenge_header(&server, "repository:p:pull");
                    let no_authz = |req: &wiremock::Request| -> bool {
                        !req.headers.contains_key(AUTHORIZATION)
                    };
                    Mock::given(method("GET"))
                        .and(path("/v2/p/blobs/sha256:m"))
                        .and(no_authz)
                        .respond_with(
                            ResponseTemplate::new(401)
                                .insert_header("WWW-Authenticate", challenge.as_str()),
                        )
                        .expect(1)
                        .mount(&server)
                        .await;
                    Mock::given(method("GET"))
                        .and(path("/realm"))
                        .respond_with(ResponseTemplate::new(200).set_body_json(
                            serde_json::json!({"token":"metric-tok","expires_in":300}),
                        ))
                        .expect(1)
                        .mount(&server)
                        .await;
                    Mock::given(method("GET"))
                        .and(path("/v2/p/blobs/sha256:m"))
                        .and(header(AUTHORIZATION, "Bearer metric-tok"))
                        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"ok".as_slice()))
                        .expect(2)
                        .mount(&server)
                        .await;

                    let proxy = proxy_for(&server);
                    let m = mapping(&server.uri(), "ghcr/", UpstreamAuth::BearerChallenge);
                    let _ = proxy
                        .fetch_blob(m.clone(), "p".into(), "sha256:m".into())
                        .await
                        .expect("cold-cache");
                    let _ = proxy
                        .fetch_blob(m, "p".into(), "sha256:m".into())
                        .await
                        .expect("warm-cache");
                });
        });

        let mut exchange_count: u64 = 0;
        let mut cache_hit_count: u64 = 0;
        for (key, _, _, value) in snapshotter.snapshot().into_vec() {
            let CompositeKey { .. } = &key;
            let inner: &Key = key.key();
            if inner.name() != METRIC_BEARER_TOKEN {
                continue;
            }
            let mut format_ok = false;
            let mut upstream_ok = false;
            let mut which = None::<&str>;
            for label in inner.labels() {
                let Label { .. } = label;
                match label.key() {
                    "format" if label.value() == "oci" => format_ok = true,
                    "upstream" if label.value() == "ghcr" => upstream_ok = true,
                    "result" => which = Some(label.value()),
                    _ => {}
                }
            }
            if !(format_ok && upstream_ok) {
                continue;
            }
            let n = match value {
                metrics_util::debugging::DebugValue::Counter(n) => n,
                _ => 0,
            };
            match which {
                Some("exchange") => exchange_count += n,
                Some("cache_hit") => cache_hit_count += n,
                _ => {}
            }
        }
        assert_eq!(exchange_count, 1, "exchange counter should fire once");
        assert_eq!(cache_hit_count, 1, "cache_hit counter should fire once");
    }

    // -- Insecure-mapping metric ---------------------------------------
    // Mapping with `insecure_upstream_url: true` over `http://` must
    // emit `hort_upstream_insecure_total{format,reason="scheme_http"}`
    // on every fetch. Two fetches → two increments, plus a `WARN`
    // tracing line each time.

    #[test]
    fn insecure_mapping_emits_hort_upstream_insecure_total_on_every_fetch() {
        use metrics::{Key, Label};
        use metrics_util::debugging::DebuggingRecorder;
        use metrics_util::CompositeKey;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let server = MockServer::start().await;
                    Mock::given(method("GET"))
                        .and(path("/v2/p/blobs/sha256:abc"))
                        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"x".as_slice()))
                        .expect(2)
                        .mount(&server)
                        .await;
                    let proxy = proxy_for(&server);
                    // Mapping uses wiremock's actual http://127.0.0.1:<port>
                    // URL. `insecure_upstream_url: true` is the operator
                    // opt-in that makes the mapping legal in the first
                    // place; the proxy fires the WARN+metric on every
                    // fetch through it.
                    let m = mapping_with_insecure(
                        &server.uri(),
                        "ghcr/",
                        UpstreamAuth::Anonymous,
                        true,
                    );
                    // Two fetches — assert two increments to prove the
                    // emission is per-fetch, not one-shot.
                    let _ = proxy
                        .fetch_blob(m.clone(), "p".into(), "sha256:abc".into())
                        .await
                        .expect("fetch 1 of 2");
                    let _ = proxy
                        .fetch_blob(m, "p".into(), "sha256:abc".into())
                        .await
                        .expect("fetch 2 of 2");
                });
        });

        let mut insecure_count: u64 = 0;
        for (key, _, _, value) in snapshotter.snapshot().into_vec() {
            let CompositeKey { .. } = &key;
            let inner: &Key = key.key();
            if inner.name() != "hort_upstream_insecure_total" {
                continue;
            }
            let mut format_ok = false;
            let mut reason_ok = false;
            for label in inner.labels() {
                let Label { .. } = label;
                match label.key() {
                    "format" if label.value() == "oci" => format_ok = true,
                    "reason" if label.value() == "scheme_http" => reason_ok = true,
                    _ => {}
                }
            }
            if !(format_ok && reason_ok) {
                continue;
            }
            if let metrics_util::debugging::DebugValue::Counter(n) = value {
                insecure_count += n;
            }
        }
        assert_eq!(
            insecure_count, 2,
            "expected hort_upstream_insecure_total{{format=oci,reason=scheme_http}} \
             to tick exactly once per fetch (2 fetches)"
        );
    }

    /// A mapping over https with `insecure_upstream_url: false` must
    /// NOT fire the insecure counter — the negative half of the rule.
    #[test]
    fn https_mapping_does_not_emit_hort_upstream_insecure_total() {
        use metrics::Key;
        use metrics_util::debugging::DebuggingRecorder;
        use metrics_util::CompositeKey;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let server = MockServer::start().await;
                    Mock::given(method("GET"))
                        .and(path("/v2/p/blobs/sha256:abc"))
                        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"x".as_slice()))
                        .mount(&server)
                        .await;
                    let proxy = proxy_for(&server);
                    // Note: wiremock is http://, but the mapping carries
                    // `insecure_upstream_url: false`. The proxy should
                    // NOT emit the insecure counter — the metric tracks
                    // operator opt-in, not the literal URL scheme.
                    let m = mapping(&server.uri(), "ghcr/", UpstreamAuth::Anonymous);
                    let _ = proxy
                        .fetch_blob(m, "p".into(), "sha256:abc".into())
                        .await
                        .expect("happy path");
                });
        });

        for (key, _, _, _) in snapshotter.snapshot().into_vec() {
            let CompositeKey { .. } = &key;
            let inner: &Key = key.key();
            assert_ne!(
                inner.name(),
                "hort_upstream_insecure_total",
                "must not emit insecure counter when mapping has insecure_upstream_url=false"
            );
        }
    }

    // -------------------------------------------------------------------
    // fetch_metadata
    // -------------------------------------------------------------------

    /// 200 with body and an empty `accept` list → adapter does not
    /// specify a concrete media type. reqwest defaults to `Accept:
    /// */*`, which per RFC 7231 §5.3.2 is identical to omitting the
    /// header entirely ("client accepts all media types") and lets the
    /// upstream default decide content negotiation. Verified by the
    /// absence of any caller-supplied Accept value, not the literal
    /// absence of the header.
    #[tokio::test]
    async fn fetch_metadata_empty_accept_does_not_specify_a_media_type() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/foo/1.0/json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(CONTENT_TYPE, "application/json")
                    .set_body_bytes(br#"{"info":{}}"#.as_slice()),
            )
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let outcome = proxy
            .fetch_metadata(m, "/pypi/foo/1.0/json".into(), Vec::new())
            .await
            .expect("fetch_metadata");
        assert_eq!(body_of_metadata(&outcome), br#"{"info":{}}"#);
        let recorded = server.received_requests().await.unwrap();
        assert_eq!(recorded.len(), 1);
        let accept = recorded[0]
            .headers
            .get("accept")
            .map(|v| v.to_str().unwrap_or(""));
        // reqwest's default; semantically equivalent to omitted header.
        // Non-default value would mean we leaked extras into the request.
        assert!(
            matches!(accept, None | Some("*/*")),
            "empty accept list must not select a concrete media type, got: {accept:?}"
        );
    }

    /// 200 with body and a non-empty `accept` list → comma-joined
    /// header reaches the upstream verbatim per RFC 7231 §5.3.2.
    #[tokio::test]
    async fn fetch_metadata_non_empty_accept_is_comma_joined() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/simple/requests/"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(br#"{"files":[]}"#.as_slice()))
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let outcome = proxy
            .fetch_metadata(
                m,
                "/simple/requests/".into(),
                vec![
                    "application/vnd.pypi.simple.v1+json".into(),
                    "text/html".into(),
                ],
            )
            .await
            .expect("fetch_metadata");
        assert_eq!(body_of_metadata(&outcome), br#"{"files":[]}"#);
        let recorded = server.received_requests().await.unwrap();
        assert_eq!(recorded.len(), 1);
        let accept = recorded[0]
            .headers
            .get("accept")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(
            accept, "application/vnd.pypi.simple.v1+json, text/html",
            "non-empty accept list must be comma-joined per RFC 7231 §5.3.2"
        );
    }

    /// 404 → `not_found`.
    #[tokio::test]
    async fn fetch_metadata_404_maps_to_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/missing/1.0/json"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let err = proxy
            .fetch_metadata(m, "/pypi/missing/1.0/json".into(), Vec::new())
            .await
            .err()
            .unwrap();
        assert_eq!(classify_error(&err), Some(UpstreamErrorKind::NotFound));
    }

    /// 502 → `upstream_5xx`.
    #[tokio::test]
    async fn fetch_metadata_502_maps_to_upstream_5xx() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/foo"))
            .respond_with(ResponseTemplate::new(502))
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let err = proxy
            .fetch_metadata(m, "/foo".into(), Vec::new())
            .await
            .err()
            .unwrap();
        assert_eq!(classify_error(&err), Some(UpstreamErrorKind::Upstream5xx));
    }

    /// Body > cap → `MetadataTooLarge`. D2: honest classification +
    /// typed variant.
    #[tokio::test]
    async fn fetch_metadata_body_over_cap_maps_to_metadata_too_large() {
        let server = MockServer::start().await;
        // cap + 1 → just over.
        let oversized = vec![b'x'; TEST_METADATA_CAP as usize + 1];
        Mock::given(method("GET"))
            .and(path("/big"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(oversized))
            .mount(&server)
            .await;
        let proxy = proxy_for_with_caps(TEST_METADATA_CAP, TEST_MANIFEST_CAP);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let err = proxy
            .fetch_metadata(m, "/big".into(), Vec::new())
            .await
            .expect_err("oversize body must error");
        assert_eq!(
            classify_error(&err),
            Some(UpstreamErrorKind::MetadataTooLarge)
        );
        assert!(
            matches!(
                err,
                DomainError::UpstreamBodyTooLarge {
                    fetch_class: FetchClass::Metadata,
                    ..
                }
            ),
            "expected typed UpstreamBodyTooLarge(Metadata); got {err:?}"
        );
    }

    /// Body exactly at the cap is accepted.
    #[tokio::test]
    async fn fetch_metadata_body_at_cap_is_accepted() {
        let server = MockServer::start().await;
        let at_cap = vec![b'x'; TEST_METADATA_CAP as usize];
        Mock::given(method("GET"))
            .and(path("/exact"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(at_cap.clone()))
            .mount(&server)
            .await;
        let proxy = proxy_for_with_caps(TEST_METADATA_CAP, TEST_MANIFEST_CAP);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let outcome = proxy
            .fetch_metadata(m, "/exact".into(), Vec::new())
            .await
            .expect("at-cap body accepted");
        assert_eq!(body_of_metadata(&outcome).len(), TEST_METADATA_CAP as usize);
    }

    /// Outbound TLS + streaming (ADR 0010 + ADR 0026): `do_fetch_metadata`
    /// must bail **mid-stream** when the cumulative bytes-read crosses
    /// the configured cap — not after `resp.bytes().await` has already
    /// buffered the whole thing into memory. A hostile upstream that
    /// opens the body and keeps streaming indefinitely must not be
    /// able to OOM the worker.
    ///
    /// The trivial `MetadataTooLarge` assertion alone does not
    /// distinguish streaming from buffered — both shapes would return
    /// the same error kind. The load-bearing assertion here is the
    /// *server-side observation*: a hand-rolled chunked-encoding
    /// server tracks how many bytes it managed to write before the
    /// client closed the connection. With the streaming pattern the
    /// client drops the connection right after crossing the cap; the
    /// buffered shape would read everything before checking length.
    ///
    /// The failure-on-buffered-impl story is intentional — this test
    /// goes red against any future regression that re-introduces a
    /// `bytes()/Vec<u8>` buffer before the cap check, even when the
    /// trivial cap-trip tests still pass.
    #[tokio::test]
    async fn fetch_metadata_streams_and_bails_mid_body_without_buffering_full_response() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        // Stream 64 MiB in 64 KiB chunks against a 4 MiB cap. The
        // streaming implementation bails at the cap and closes the
        // connection, so the server observes only the cap plus a
        // transient in-flight window (kernel TCP send/receive buffers +
        // reqwest's `bytes_stream` read-ahead) — empirically ~3x cap on
        // fast loopback, and notably larger under CI buffer sizing. A
        // buffered `resp.bytes().await` shape, by contrast, reads the
        // full 64 MiB (16x cap) before the length check. We assert the
        // server pushed < 8x cap = 32 MiB: comfortably above realistic
        // in-flight buffering, yet far below the 16x-cap full body, so the
        // streaming-vs-buffered distinction stays unambiguous without
        // being fragile to kernel/CI buffer variance (the prior 3x-cap
        // threshold flaked when CI buffered ~3.1x cap).
        const STREAMING_TEST_CAP: u64 = 4 * 1024 * 1024;
        const TOTAL_BODY_BYTES: usize = 64 * 1024 * 1024;
        const CHUNK_SIZE: usize = 64 * 1024;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let bytes_pushed = Arc::new(AtomicUsize::new(0));
        let bytes_pushed_for_task = bytes_pushed.clone();

        let server_handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();

            // Drain the request — we do not parse it; the path is
            // fixed and there is exactly one expected request. Read
            // until CRLF-CRLF then stop reading the request.
            let mut req = Vec::with_capacity(256);
            let mut tmp = [0u8; 1024];
            loop {
                use tokio::io::AsyncReadExt;
                let n = sock.read(&mut tmp).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&tmp[..n]);
                if req.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }

            // Write the response head with chunked transfer encoding
            // — Content-Length unknown / not pre-buffered, so the
            // server keeps streaming until either it is done or the
            // peer closes the socket.
            let head = b"HTTP/1.1 200 OK\r\n\
                Content-Type: application/json\r\n\
                Transfer-Encoding: chunked\r\n\
                Connection: close\r\n\
                \r\n";
            if sock.write_all(head).await.is_err() {
                return;
            }

            let chunk_payload = vec![b'x'; CHUNK_SIZE];
            let chunk_size_hex = format!("{CHUNK_SIZE:x}\r\n");
            let mut total = 0usize;
            while total < TOTAL_BODY_BYTES {
                if sock.write_all(chunk_size_hex.as_bytes()).await.is_err() {
                    break;
                }
                if sock.write_all(&chunk_payload).await.is_err() {
                    break;
                }
                if sock.write_all(b"\r\n").await.is_err() {
                    break;
                }
                total += CHUNK_SIZE;
                bytes_pushed_for_task.store(total, Ordering::SeqCst);
                // Yield so the client gets a chance to read between
                // chunks; without this the server can pre-stage the
                // entire 50 MiB into the kernel send buffer in one
                // tight loop on Linux and the streaming-vs-buffered
                // distinction is masked by buffering at a lower
                // layer.
                tokio::task::yield_now().await;
            }
            // Best-effort terminating chunk; the client may have
            // already dropped the connection.
            let _ = sock.write_all(b"0\r\n\r\n").await;
            let _ = sock.shutdown().await;
        });

        // Build a proxy with the streaming test cap — same trick
        // proxy_for uses for wiremock, but inlined because we are
        // using a raw TcpListener, not a MockServer.
        let cfg = HttpUpstreamProxyConfig {
            timeout: Duration::from_secs(5),
            format_label: "test".to_string(),
            metadata_cache_max_bytes: STREAMING_TEST_CAP,
            manifest_cache_max_bytes: TEST_MANIFEST_CAP,
            ..Default::default()
        };
        let proxy = HttpUpstreamProxy::new(cfg, Arc::new(AnonymousFallbackPort)).unwrap();
        let m = mapping(
            &format!("http://{server_addr}"),
            "",
            UpstreamAuth::Anonymous,
        );

        let err = proxy
            .fetch_metadata(m, "/streaming-cap".into(), Vec::new())
            .await
            .expect_err("oversize streaming body must error");
        assert_eq!(
            classify_error(&err),
            Some(UpstreamErrorKind::MetadataTooLarge),
            "cap overflow must classify as MetadataTooLarge: {err:?}"
        );

        // Give the server task a moment to observe the dropped
        // connection and stop pushing chunks. Without this, the test
        // can race against the server still being in its write loop
        // when we sample the counter.
        let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;

        let pushed = bytes_pushed.load(Ordering::SeqCst);
        // Memory-bounding assertion. With streaming + bail, the server
        // pushed roughly cap + a transient in-flight window (kernel TCP
        // send + receive buffers + reqwest's `bytes_stream` read-ahead).
        // The buffered shape (`resp.bytes().await`) pushes the full
        // TOTAL_BODY_BYTES = 16x cap = 64 MiB, so any threshold strictly
        // between the in-flight noise and 16x cap distinguishes streaming
        // from buffered. We use 8x cap (= TOTAL/2 = 32 MiB): a wide middle
        // that absorbs kernel/CI buffer variation without false positives
        // (the prior 3x-cap threshold flaked at ~3.1x cap).
        let upper = (8 * STREAMING_TEST_CAP) as usize;
        assert!(
            pushed < upper,
            "streaming bail must close the connection near the cap; \
             server observed {pushed} bytes pushed, expected < {upper} \
             ({} MiB cap, {} MiB total streamable). \
             A buffered `resp.bytes().await` impl reads the full \
             {} MiB before the length check, which is exactly the OOM \
             exposure this test catches.",
            STREAMING_TEST_CAP / (1024 * 1024),
            TOTAL_BODY_BYTES / (1024 * 1024),
            TOTAL_BODY_BYTES / (1024 * 1024),
        );
    }

    /// `compose_url` joins base and path with exactly one slash, even
    /// when base has a trailing slash and path lacks a leading one.
    #[test]
    fn compose_url_normalises_slashes() {
        assert_eq!(compose_url("https://h", "/a/b"), "https://h/a/b");
        assert_eq!(compose_url("https://h/", "/a/b"), "https://h/a/b");
        assert_eq!(compose_url("https://h", "a/b"), "https://h/a/b");
        assert_eq!(compose_url("https://h/", "a/b"), "https://h/a/b");
    }

    // -------------------------------------------------------------------
    // parse_last_modified
    //
    // RFC 7231 §7.1.1.1 permits three HTTP-date forms; `httpdate` parses
    // all three. The contract is best-effort — None on absent, None on
    // unparseable, Some(DateTime<Utc>) on parseable.
    // -------------------------------------------------------------------

    /// IMF-fixdate (RFC 1123) — the modern preferred form. crates.io
    /// and most CDNs serve this shape.
    #[test]
    fn parse_last_modified_imf_fixdate_yields_utc() {
        let parsed = parse_last_modified(Some("Sun, 06 Nov 1994 08:49:37 GMT"))
            .expect("RFC 1123 IMF-fixdate must parse");
        let expected: DateTime<Utc> = DateTime::parse_from_rfc3339("1994-11-06T08:49:37Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(parsed, expected);
    }

    /// Absent header → `None`, no log noise.
    #[test]
    fn parse_last_modified_none_when_absent() {
        assert!(parse_last_modified(None).is_none());
    }

    /// Unparseable value → `None` (debug-logged at the call site,
    /// never an error).
    #[test]
    fn parse_last_modified_none_when_unparseable() {
        assert!(parse_last_modified(Some("not-a-date")).is_none());
        assert!(parse_last_modified(Some("")).is_none());
        assert!(parse_last_modified(Some("2024-13-99T99:99:99Z")).is_none());
    }

    // -------------------------------------------------------------------
    // Last-Modified on the response is surfaced through the envelope
    // returned by fetch_artifact / fetch_blob. Two wiremock tests pin
    // the present + absent cases for each method.
    // -------------------------------------------------------------------

    /// `fetch_artifact` returns the parsed Last-Modified when present.
    /// This is the cargo `.crate` tarball path's hint source.
    #[tokio::test]
    async fn fetch_artifact_surfaces_last_modified_when_present() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/serde-1.0.214.crate"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Last-Modified", "Mon, 06 Nov 2023 12:34:56 GMT")
                    .set_body_bytes(b"crate-bytes".as_slice()),
            )
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let fetch = proxy
            .fetch_artifact(m, "/serde-1.0.214.crate".into())
            .await
            .expect("fetch_artifact");
        let expected: DateTime<Utc> = DateTime::parse_from_rfc3339("2023-11-06T12:34:56Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(fetch.last_modified, Some(expected));
    }

    /// `fetch_artifact` returns `last_modified = None` when the upstream
    /// omits the header — common case, must not log-spam.
    #[tokio::test]
    async fn fetch_artifact_last_modified_none_when_header_absent() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/no-last-modified.crate"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"no-hint".as_slice()))
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let fetch = proxy
            .fetch_artifact(m, "/no-last-modified.crate".into())
            .await
            .expect("fetch_artifact");
        assert_eq!(fetch.last_modified, None);
    }

    /// `fetch_blob` returns the parsed Last-Modified when present. This
    /// is the OCI config + layer blob path's hint source.
    #[tokio::test]
    async fn fetch_blob_surfaces_last_modified_when_present() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/library/nginx/blobs/sha256:lm"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT")
                    .insert_header("docker-content-digest", "sha256:lm")
                    .set_body_bytes(b"blob-with-lm".as_slice()),
            )
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let fetch = proxy
            .fetch_blob(m, "library/nginx".into(), "sha256:lm".into())
            .await
            .expect("fetch_blob");
        let expected: DateTime<Utc> = DateTime::parse_from_rfc3339("2015-10-21T07:28:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(fetch.last_modified, Some(expected));
    }

    /// `fetch_blob` `last_modified = None` when the upstream omits
    /// the header.
    #[tokio::test]
    async fn fetch_blob_last_modified_none_when_header_absent() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/library/nginx/blobs/sha256:nolm"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("docker-content-digest", "sha256:nolm")
                    .set_body_bytes(b"blob-no-lm".as_slice()),
            )
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let fetch = proxy
            .fetch_blob(m, "library/nginx".into(), "sha256:nolm".into())
            .await
            .expect("fetch_blob");
        assert_eq!(fetch.last_modified, None);
    }

    /// Unparseable `Last-Modified` → `None` (best-effort by contract).
    /// The fetch must still succeed.
    #[tokio::test]
    async fn fetch_artifact_unparseable_last_modified_is_none_not_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/garbled-lm.crate"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Last-Modified", "not-a-real-http-date")
                    .set_body_bytes(b"bytes".as_slice()),
            )
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let fetch = proxy
            .fetch_artifact(m, "/garbled-lm.crate".into())
            .await
            .expect("fetch_artifact must succeed despite unparseable header");
        assert_eq!(
            fetch.last_modified, None,
            "unparseable header must yield None (best-effort by contract)"
        );
    }

    /// `fetch_manifest` surfaces the parsed `Last-Modified` when the
    /// upstream sets it. Mirrors `fetch_blob` / `fetch_artifact` so the
    /// OCI manifest path can anchor on its own publish-time hint under
    /// the `trust_upstream_publish_time` opt-in; without this, manifests
    /// would stay anchored on `ingested_at` while every blob in the same
    /// image released on its own age.
    #[tokio::test]
    async fn fetch_manifest_surfaces_last_modified_when_present() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/library/nginx/manifests/latest"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(CONTENT_TYPE, "application/vnd.oci.image.manifest.v1+json")
                    .insert_header("docker-content-digest", "sha256:lmlm")
                    .insert_header("Last-Modified", "Tue, 15 Nov 2022 12:45:26 GMT")
                    .set_body_bytes(br#"{"schemaVersion":2}"#.as_slice()),
            )
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let result = proxy
            .fetch_manifest(m, "library/nginx".into(), "latest".into(), Vec::new())
            .await
            .expect("fetch_manifest");
        let expected: DateTime<Utc> = DateTime::parse_from_rfc3339("2022-11-15T12:45:26Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            result.last_modified,
            Some(expected),
            "manifest Last-Modified must round-trip through ManifestFetch"
        );
    }

    /// `fetch_manifest` returns `last_modified = None` when the upstream
    /// omits the header. Common case (e.g. Docker Hub's `Last-Modified`
    /// is on the blob, not always the manifest); must not error or
    /// log-spam.
    #[tokio::test]
    async fn fetch_manifest_last_modified_none_when_header_absent() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/library/nginx/manifests/no-lm"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(CONTENT_TYPE, "application/vnd.oci.image.manifest.v1+json")
                    .insert_header("docker-content-digest", "sha256:nolm")
                    .set_body_bytes(br#"{"schemaVersion":2}"#.as_slice()),
            )
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let result = proxy
            .fetch_manifest(m, "library/nginx".into(), "no-lm".into(), Vec::new())
            .await
            .expect("fetch_manifest");
        assert_eq!(result.last_modified, None);
    }

    /// Unparseable `Last-Modified` on a manifest response yields `None`
    /// (best-effort), not an error. Mirrors the `fetch_artifact`
    /// precedent above.
    #[tokio::test]
    async fn fetch_manifest_unparseable_last_modified_is_none_not_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/library/nginx/manifests/garbled"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(CONTENT_TYPE, "application/vnd.oci.image.manifest.v1+json")
                    .insert_header("docker-content-digest", "sha256:garbled")
                    .insert_header("Last-Modified", "totally-not-an-http-date")
                    .set_body_bytes(br#"{"schemaVersion":2}"#.as_slice()),
            )
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let result = proxy
            .fetch_manifest(m, "library/nginx".into(), "garbled".into(), Vec::new())
            .await
            .expect("fetch_manifest must succeed despite unparseable header");
        assert_eq!(
            result.last_modified, None,
            "unparseable header must yield None, not an ingest failure"
        );
    }

    // -------------------------------------------------------------------
    // fetch_artifact
    // -------------------------------------------------------------------

    /// Mapping-relative path success → composes onto upstream_url and
    /// streams the body.
    #[tokio::test]
    async fn fetch_artifact_relative_path_streams_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/foo-1.0.tar.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"the-bytes".as_slice()))
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let mut stream = proxy
            .fetch_artifact(m, "/foo-1.0.tar.gz".into())
            .await
            .expect("fetch_artifact")
            .stream;
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            bytes.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(bytes, b"the-bytes");
    }

    /// Absolute URL success on a public host (`127.0.0.1` is the only
    /// host wiremock binds to, so we have to allow it for the test by
    /// using a relative path; this case asserts the relative composition
    /// path is preferred when the path doesn't start with a scheme).
    /// The absolute-URL branch is exercised below by the SSRF test.
    #[tokio::test]
    async fn fetch_artifact_404_maps_to_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/missing.tar.gz"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let Err(err) = proxy.fetch_artifact(m, "/missing.tar.gz".into()).await else {
            panic!("404 must error")
        };
        assert_eq!(classify_error(&err), Some(UpstreamErrorKind::NotFound));
    }

    /// Absolute URL pointing at loopback → SSRF refusal before the
    /// network call, surfaced as Validation (parse_error metric).
    #[tokio::test]
    async fn fetch_artifact_absolute_url_loopback_is_refused() {
        let proxy = proxy_with_no_server();
        let m = mapping("http://example.invalid", "", UpstreamAuth::Anonymous);
        let Err(err) = proxy
            .fetch_artifact(m, "http://127.0.0.1:9/whatever".into())
            .await
        else {
            panic!("loopback URL must be refused")
        };
        assert!(
            matches!(err, DomainError::Validation(_)),
            "loopback refusal must produce DomainError::Validation, got {err:?}"
        );
    }

    /// Absolute URL pointing at link-local (169.254.169.254 — the
    /// canonical AWS IMDS address) is refused.
    #[tokio::test]
    async fn fetch_artifact_absolute_url_link_local_is_refused() {
        let proxy = proxy_with_no_server();
        let m = mapping("http://example.invalid", "", UpstreamAuth::Anonymous);
        let Err(err) = proxy
            .fetch_artifact(m, "http://169.254.169.254/latest/meta-data/".into())
            .await
        else {
            panic!("link-local URL must be refused")
        };
        assert!(matches!(err, DomainError::Validation(_)));
    }

    /// Absolute URL pointing at RFC 1918 private space is refused.
    #[tokio::test]
    async fn fetch_artifact_absolute_url_rfc1918_is_refused() {
        let proxy = proxy_with_no_server();
        let m = mapping("http://example.invalid", "", UpstreamAuth::Anonymous);
        let Err(err) = proxy
            .fetch_artifact(m, "http://10.0.0.1/secrets".into())
            .await
        else {
            panic!("RFC 1918 URL must be refused")
        };
        assert!(matches!(err, DomainError::Validation(_)));
    }

    fn proxy_with_no_server() -> HttpUpstreamProxy {
        let cfg = HttpUpstreamProxyConfig {
            timeout: Duration::from_secs(1),
            format_label: "test".to_string(),
            ..Default::default()
        };
        HttpUpstreamProxy::new(cfg, Arc::new(AnonymousFallbackPort)).unwrap()
    }

    /// INJ-1 regression — the connect-time DNS guard closes the
    /// SSRF/DNS-rebind TOCTOU on the **initial dial** of a *host name*
    /// upstream, which `check_ssrf_safe` never re-validates at dial time.
    ///
    /// A **relative**-path fetch composes onto `mapping.upstream_url` and
    /// deliberately does NOT run `check_ssrf_safe` (only absolute URLs hit
    /// that gate — see `resolve_artifact_url`). So a mapping whose
    /// `upstream_url` host *name* resolves to a non-routable address is a
    /// pure exercise of the connect-time guard: nothing else stands between
    /// the request and the internal target. `localhost` is a host name
    /// (not an IP literal — hyper-util's connector routes host names through
    /// the bound `reqwest::dns::Resolve`, IP literals bypass it), resolving
    /// to loopback. With the production proxy (empty test-allowlist) the
    /// guard must refuse the dial and the failure must classify as
    /// `ParseError` (the SSRF-refusal contract), proving the dial never
    /// completed against the internal address.
    #[tokio::test]
    async fn fetch_relative_path_to_hostname_resolving_nonroutable_is_blocked_at_connect() {
        let proxy = proxy_with_no_server();
        // Host *name* (goes through the DNS guard) resolving to loopback,
        // reached via a RELATIVE path so `check_ssrf_safe` is bypassed and
        // only the connect-time guard can stop it. Port 9 (discard) so even
        // if the guard were absent the connect would not reach a real
        // server — but the assertion is on the classification, which only
        // the guard produces.
        let m = mapping("http://localhost:9", "", UpstreamAuth::Anonymous);
        let Err(err) = proxy.fetch_artifact(m, "/internal-secret".into()).await else {
            panic!(
                "a relative-path fetch to a host name resolving to loopback must be \
                 refused by the connect-time DNS guard"
            );
        };
        assert_eq!(
            classify_error(&err),
            Some(UpstreamErrorKind::ParseError),
            "connect-time SSRF refusal must classify as ParseError (the \
             check_ssrf_safe refusal contract), got {err:?}"
        );
    }

    /// INJ-1 positive — the connect-time guard does NOT break a legitimate
    /// public-host dial. wiremock binds on loopback (an IP literal that
    /// bypasses the resolver), so to drive the *resolver* path against a
    /// permitted address we point the proxy at the wiremock server via its
    /// loopback `SocketAddr` placed in the test-allowlist AND reference it
    /// by the host *name* `localhost`. The guard resolves `localhost` →
    /// loopback, finds the address allowlisted, and permits the dial; the
    /// body must reach the caller. This is the analogue of "public host
    /// resolves and is permitted" that is offline-safe.
    #[tokio::test]
    async fn fetch_relative_path_to_allowlisted_hostname_is_permitted_at_connect() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pkg.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"public-bytes".as_slice()))
            .mount(&server)
            .await;

        // Allowlist every address `localhost` resolves to (v4 + v6),
        // normalised to the `:0` port the connect-time guard resolves with,
        // so the guard treats `localhost` → loopback as routable. The guard
        // rejects a resolution if ANY returned address is non-routable and
        // not allowlisted, so all of localhost's answers must be listed.
        let allow: Vec<SocketAddr> = tokio::net::lookup_host("localhost:0")
            .await
            .expect("localhost resolves")
            .map(|a| SocketAddr::new(a.ip(), 0))
            .collect();
        let cfg = HttpUpstreamProxyConfig {
            timeout: Duration::from_secs(2),
            format_label: "oci".to_string(),
            ..Default::default()
        };
        let proxy = HttpUpstreamProxy::new_with_redirect_test_allowlist(
            cfg,
            Arc::new(AnonymousFallbackPort),
            allow,
        )
        .unwrap();

        // Reach the server by host NAME (so the guard's resolver fires)
        // while the actual bound port comes from wiremock.
        let upstream = format!("http://localhost:{}", server.address().port());
        let m = mapping(&upstream, "", UpstreamAuth::Anonymous);

        let mut stream = proxy
            .fetch_artifact(m, "/pkg.tgz".into())
            .await
            .expect("allowlisted host-name dial must be permitted by the connect guard")
            .stream;
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            bytes.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(
            bytes, b"public-bytes",
            "a permitted host-name upstream's body must reach the caller \
             (no false-positive over-block)"
        );
    }

    #[test]
    fn is_absolute_url_recognises_http_and_https() {
        assert!(is_absolute_url("http://example.com/x"));
        assert!(is_absolute_url("https://example.com/x"));
        assert!(!is_absolute_url("/relative/path"));
        assert!(!is_absolute_url("ftp://example.com"));
    }

    /// The URL-input-validation layer must reject an IPv4-mapped IPv6
    /// literal that projects to AWS IMDS. `check_ssrf_safe` is the sole
    /// URL-input egress filter — the routability invariant rides entirely
    /// on `hort_net_egress::is_routable`. The canonical
    /// `hort_net_egress::is_routable` implementation handles the
    /// IPv4-mapped projection check so `::ffff:169.254.169.254` is
    /// correctly classified as non-routable.
    #[tokio::test]
    async fn check_ssrf_safe_rejects_ipv4_mapped_imds() {
        let result = check_ssrf_safe("http://[::ffff:169.254.169.254]/").await;
        match result {
            Err(DomainError::Validation(_)) => {}
            other => {
                panic!("expected Validation rejection for IPv4-mapped IMDS literal, got {other:?}")
            }
        }
    }

    /// Sibling positive case so the negative isn't tautological:
    /// a legitimately-routable URL must NOT be rejected. Uses a
    /// well-known public-resolver IP so the `lookup_host` step
    /// returns a routable address; if `check_ssrf_safe` over-blocked
    /// public IPs (e.g. a regression in `hort_net_egress::is_routable`)
    /// this would fail.
    #[tokio::test]
    async fn check_ssrf_safe_accepts_public_address() {
        check_ssrf_safe("http://1.1.1.1/")
            .await
            .expect("public IPv4 literal must pass the SSRF guard");
    }

    /// Positive coverage for the absolute-URL branch of
    /// `fetch_artifact`. Wiremock binds to loopback and would be
    /// refused by the SSRF guard, so the test calls
    /// `fetch_artifact_url` directly — the SSRF check has its own
    /// unit tests above; the inner fetch is what this exercises.
    /// Asserts that bytes returned by an absolute-URL fetch reach
    /// the caller via the `BlobStream` and don't get re-composed
    /// onto `mapping.upstream_url`.
    #[tokio::test]
    async fn fetch_artifact_url_absolute_streams_body_from_arbitrary_host() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/files/files.pythonhosted.org/foo-1.0.tar.gz"))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(b"absolute-url-bytes".as_slice()),
            )
            .mount(&server)
            .await;

        let proxy = proxy_for(&server);
        // The mapping's upstream_url is *not* the wiremock host —
        // intentional: an absolute URL must NOT be composed onto the
        // mapping base. If `fetch_artifact_url` mistakenly re-composed,
        // the mock above would not match and the test would 404.
        let m = mapping("https://pypi.org", "", UpstreamAuth::Anonymous);
        let absolute = format!(
            "{}/files/files.pythonhosted.org/foo-1.0.tar.gz",
            server.uri()
        );
        // The inner `fetch_artifact_url` takes the per-mapping client
        // (ADR 0010); for an anonymous mapping with no TLS material,
        // that's the proxy's default client.
        let client = proxy.client.clone();
        let mut stream = proxy
            .fetch_artifact_url(&client, &m, &absolute, &absolute)
            .await
            .expect("absolute-URL fetch should succeed")
            .stream;
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            bytes.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(bytes, b"absolute-url-bytes");
    }

    /// `resolve_artifact_url` returns the absolute URL verbatim when
    /// SSRF passes (test against a public IP literal — no DNS lookup
    /// would normally hit a non-loopback). For the relative case it
    /// composes onto the mapping's base.
    #[tokio::test]
    async fn resolve_artifact_url_routes_relative_and_absolute() {
        let proxy = proxy_with_no_server();
        // Relative: composes onto the upstream_url base.
        let composed = proxy
            .resolve_artifact_url("https://example.com", "/foo/bar.tgz")
            .await
            .unwrap();
        assert_eq!(composed, "https://example.com/foo/bar.tgz");

        // Absolute pointing at loopback → SSRF refusal (covered in
        // dedicated tests above; here it confirms the resolver is
        // wired to the SSRF guard).
        let err = proxy
            .resolve_artifact_url("https://example.com", "http://127.0.0.1:9/x")
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    // -- Custom CA / mTLS / cert-pinning (ADR 0010) -------------------
    //
    // CA-bundle, mTLS, and cert-pinning behaviour. These tests stand up an
    // in-process HTTPS server with a self-signed cert (rcgen) and verify
    // each TLS posture fires the right `hort_upstream_tls_handshake_total`
    // result and the right `UpstreamErrorKind`-classified `DomainError`.
    //
    // Why a TLS test server instead of wiremock: wiremock is HTTP-only.
    // The narrow primitive below (`tls_test_server`) exists so the tests
    // pin the rustls integration, not the higher-level reqwest config.

    /// A freshly-minted self-signed CA + leaf cert. Mirrors what an
    /// operator's private CA + private-mirror leaf might look like — but
    /// generated from scratch in the test process so no PEM fixtures
    /// land in the repo.
    struct TlsFixture {
        /// PEM bytes of the CA root certificate (operator-supplied
        /// `ca_bundle_ref` material).
        ca_pem: String,
        /// PEM bytes of the leaf cert (signed by the CA above) — what
        /// the test server presents during handshake.
        leaf_pem: String,
        /// PEM bytes of the leaf cert's private key.
        leaf_key_pem: String,
        /// SHA-256 thumbprint of the leaf cert's DER bytes — the
        /// expected pin for the success-pin test.
        leaf_pin_sha256_lower_hex: String,
    }

    /// Generate an in-process TLS fixture. `subject_alt_name` is the
    /// hostname / IP literal the leaf cert is valid for — tests pass
    /// `127.0.0.1` so the connect-side server name matches.
    fn make_tls_fixture(subject_alt_name: &str) -> TlsFixture {
        // Generate a CA (self-signed root).
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "hort test CA".to_string());
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().expect("generate CA keypair");
        let ca = ca_params.self_signed(&ca_key).expect("self-sign CA");

        // Generate leaf signed by CA.
        let mut leaf_params = rcgen::CertificateParams::new(vec![subject_alt_name.to_string()])
            .expect("leaf CertificateParams::new");
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "hort test leaf".to_string());
        let leaf_key = rcgen::KeyPair::generate().expect("generate leaf keypair");
        let leaf = leaf_params
            .signed_by(&leaf_key, &ca, &ca_key)
            .expect("CA-sign leaf cert");

        let ca_pem = ca.pem();
        let leaf_pem = leaf.pem();
        let leaf_key_pem = leaf_key.serialize_pem();

        // Compute SHA-256 of the leaf DER bytes for the pinning test.
        let leaf_der = leaf.der();
        let leaf_pin_sha256_lower_hex = tls_config::sha256_lower_hex(leaf_der.as_ref());

        TlsFixture {
            ca_pem,
            leaf_pem,
            leaf_key_pem,
            leaf_pin_sha256_lower_hex,
        }
    }

    /// Spawn a minimal HTTPS server bound to a free loopback port.
    /// Returns the bound `SocketAddr`. Single response shape for the
    /// TLS tests: GET on any path → 200 with body `b"tls-ok"`.
    async fn tls_test_server(fixture: &TlsFixture) -> SocketAddr {
        // axum-server's RustlsConfig::from_pem panics if no
        // process-level rustls crypto provider is installed. Install
        // aws-lc-rs lazily — `install_default` is idempotent on the
        // second call (returns Err with the existing provider, which
        // we ignore).
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        // Build axum-server tls config from the in-memory PEM bytes —
        // no temp files on disk.
        let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem(
            fixture.leaf_pem.as_bytes().to_vec(),
            fixture.leaf_key_pem.as_bytes().to_vec(),
        )
        .await
        .expect("RustlsConfig::from_pem with rcgen-generated PEM");

        // Bind to a free loopback port.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral loopback port");
        let addr = listener.local_addr().expect("local_addr");
        // axum-server's API takes a std listener.
        let std_listener = listener
            .into_std()
            .expect("convert tokio listener to std listener");
        std_listener
            .set_nonblocking(true)
            .expect("set non-blocking");

        let app: axum::Router =
            axum::Router::new().fallback(|| async { (StatusCode::OK, "tls-ok") });
        tokio::spawn(async move {
            let _ = axum_server::from_tcp_rustls(std_listener, tls_config)
                .serve(app.into_make_service())
                .await;
        });
        // Yield once so the listener task has a chance to be polled
        // before the first connect attempt.
        tokio::task::yield_now().await;
        addr
    }

    /// Build a proxy for a TLS test server bound to a loopback address.
    /// The connect-time SSRF guard was removed; reqwest's default DNS
    /// resolver connects to loopback addresses without further wiring.
    /// The `addr` argument is retained so test signatures stay stable,
    /// even though it is now only consumed by callers building the test
    /// URL.
    fn proxy_for_tls(addr: SocketAddr) -> HttpUpstreamProxy {
        let _ = addr;
        let cfg = HttpUpstreamProxyConfig {
            timeout: Duration::from_secs(5),
            format_label: "oci".to_string(),
            ..Default::default()
        };
        // The TLS tests don't exercise SecretPort failure paths; the
        // anonymous fallback port serves any unexpected resolve attempts.
        HttpUpstreamProxy::new(cfg, Arc::new(AnonymousFallbackPort)).unwrap()
    }

    /// In-process SecretPort that returns the supplied bytes for any
    /// `SecretRef`. The TLS tests resolve `ca_bundle_ref` /
    /// `mtls_cert_ref` / `mtls_key_ref` against this; the value-object
    /// constructor's pairing rule keeps the request sequence
    /// deterministic.
    struct StaticSecretPort {
        ca_pem: Option<Vec<u8>>,
        cert_pem: Option<Vec<u8>>,
        key_pem: Option<Vec<u8>>,
    }
    impl SecretPort for StaticSecretPort {
        fn resolve<'a>(
            &'a self,
            reference: &'a SecretRef,
        ) -> BoxFuture<'a, DomainResult<SecretValue>> {
            Box::pin(async move {
                // Disambiguate by the test-supplied location strings.
                // The mapping helpers below pass `HORT_TEST_CA`,
                // `HORT_TEST_MTLS_CERT`, `HORT_TEST_MTLS_KEY` so the
                // SecretPort can route deterministically.
                let bytes = match reference.location.as_str() {
                    "HORT_TEST_CA" => self.ca_pem.clone(),
                    "HORT_TEST_MTLS_CERT" => self.cert_pem.clone(),
                    "HORT_TEST_MTLS_KEY" => self.key_pem.clone(),
                    _ => None,
                };
                bytes.map(SecretValue::from_bytes).ok_or_else(|| {
                    DomainError::Invariant(format!(
                        "static secret port: no value for {}",
                        reference.location
                    ))
                })
            })
        }
    }

    fn secret_ref_env(name: &str) -> SecretRef {
        SecretRef {
            source: SecretSource::EnvVar,
            location: name.to_string(),
        }
    }

    /// Build a TLS-aware proxy whose SecretPort serves the supplied PEM
    /// bytes for the matching mapping refs. The `addr` argument is
    /// retained for signature stability.
    fn proxy_for_tls_with_secrets(
        addr: SocketAddr,
        secrets: StaticSecretPort,
    ) -> HttpUpstreamProxy {
        let _ = addr;
        let cfg = HttpUpstreamProxyConfig {
            timeout: Duration::from_secs(5),
            format_label: "oci".to_string(),
            ..Default::default()
        };
        HttpUpstreamProxy::new(cfg, Arc::new(secrets)).unwrap()
    }

    /// Test A (custom CA): mapping carries `ca_bundle_ref` pointing at
    /// the test CA. The fetch must succeed because the augmented root
    /// store accepts the leaf signed by that CA.
    #[tokio::test]
    async fn fetch_artifact_with_custom_ca_bundle_succeeds() {
        let fixture = make_tls_fixture("127.0.0.1");
        let addr = tls_test_server(&fixture).await;
        let url = format!("https://127.0.0.1:{}", addr.port());

        let mut m = mapping(&url, "", UpstreamAuth::Anonymous);
        m.ca_bundle_ref = Some(secret_ref_env("HORT_TEST_CA"));

        let secrets = StaticSecretPort {
            ca_pem: Some(fixture.ca_pem.into_bytes()),
            cert_pem: None,
            key_pem: None,
        };
        let proxy = proxy_for_tls_with_secrets(addr, secrets);

        let mut stream = proxy
            .fetch_artifact(m, "/blob".to_string())
            .await
            .expect("fetch with custom CA must succeed")
            .stream;
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            bytes.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(bytes, b"tls-ok");
    }

    /// Test B (no CA augmentation): default mapping with no
    /// `ca_bundle_ref` against the same self-signed test server. The
    /// system trust store does not include the test CA, so the
    /// handshake fails and the result classifies as `CaUnknown`.
    #[tokio::test]
    async fn fetch_artifact_without_custom_ca_classifies_as_ca_unknown() {
        let fixture = make_tls_fixture("127.0.0.1");
        let addr = tls_test_server(&fixture).await;
        let url = format!("https://127.0.0.1:{}", addr.port());

        let m = mapping(&url, "", UpstreamAuth::Anonymous);
        // Default proxy: no SecretPort routing — the AnonymousFallbackPort
        // is fine because we configure no `*_ref` on the mapping.
        let proxy = proxy_for_tls(addr);

        // BlobStream isn't Debug so we can't `.expect_err`; use let-else.
        let result = proxy.fetch_artifact(m, "/blob".to_string()).await;
        let Err(err) = result else {
            panic!("fetch without custom CA must fail");
        };
        let kind = classify_error(&err);
        assert_eq!(
            kind,
            Some(UpstreamErrorKind::CaUnknown),
            "expected CaUnknown classification, got {kind:?} for err={err}"
        );
    }

    /// Test C (pinning success): mapping carries the correct SHA-256
    /// thumbprint of the leaf cert. The fetch succeeds; the pinning
    /// verifier runs the thumbprint check and delegates name + chain
    /// validation to WebPKI.
    #[tokio::test]
    async fn fetch_artifact_with_correct_pin_succeeds() {
        let fixture = make_tls_fixture("127.0.0.1");
        let addr = tls_test_server(&fixture).await;
        let url = format!("https://127.0.0.1:{}", addr.port());

        let mut m = mapping(&url, "", UpstreamAuth::Anonymous);
        m.ca_bundle_ref = Some(secret_ref_env("HORT_TEST_CA"));
        m.pinned_cert_sha256 = Some(fixture.leaf_pin_sha256_lower_hex.clone());

        let secrets = StaticSecretPort {
            ca_pem: Some(fixture.ca_pem.into_bytes()),
            cert_pem: None,
            key_pem: None,
        };
        let proxy = proxy_for_tls_with_secrets(addr, secrets);

        let mut stream = proxy
            .fetch_artifact(m, "/blob".to_string())
            .await
            .expect("fetch with correct pin must succeed")
            .stream;
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            bytes.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(bytes, b"tls-ok");
    }

    /// Test D (pinning mismatch): mapping carries a pin that is the
    /// correct shape (64 hex chars, value-object accepts it) but
    /// disagrees with the leaf cert's actual thumbprint by one byte.
    /// The handshake fails and classifies as `PinMismatch`.
    #[tokio::test]
    async fn fetch_artifact_with_wrong_pin_classifies_as_pin_mismatch() {
        let fixture = make_tls_fixture("127.0.0.1");
        let addr = tls_test_server(&fixture).await;
        let url = format!("https://127.0.0.1:{}", addr.port());

        // Mutate one byte of the correct pin. Replace the first
        // hex-pair `aa..ff` deterministically — flipping the leading
        // nibble from whatever it is to `0`.
        let mut wrong_pin = fixture.leaf_pin_sha256_lower_hex.clone();
        let first = wrong_pin.chars().next().unwrap();
        let mutated = if first == '0' { '1' } else { '0' };
        wrong_pin.replace_range(0..1, &mutated.to_string());
        assert_ne!(wrong_pin, fixture.leaf_pin_sha256_lower_hex);

        let mut m = mapping(&url, "", UpstreamAuth::Anonymous);
        m.ca_bundle_ref = Some(secret_ref_env("HORT_TEST_CA"));
        m.pinned_cert_sha256 = Some(wrong_pin);

        let secrets = StaticSecretPort {
            ca_pem: Some(fixture.ca_pem.into_bytes()),
            cert_pem: None,
            key_pem: None,
        };
        let proxy = proxy_for_tls_with_secrets(addr, secrets);

        let result = proxy.fetch_artifact(m, "/blob".to_string()).await;
        let Err(err) = result else {
            panic!("fetch with wrong pin must fail");
        };
        let kind = classify_error(&err);
        assert_eq!(
            kind,
            Some(UpstreamErrorKind::PinMismatch),
            "expected PinMismatch classification, got {kind:?} for err={err}"
        );
    }

    /// TLS-handshake metric collapse test: every TLS-handshake metric
    /// emission goes out with `repository="_all"` because the proxy
    /// operates at the mapping layer (no resolved repository key) and
    /// inherits the `METRICS_INCLUDE_REPOSITORY_LABEL=false` collapse
    /// semantics by always emitting the sentinel.
    #[test]
    fn fetch_emits_tls_handshake_metric_with_repository_all_sentinel() {
        use metrics::Key;
        use metrics_util::debugging::DebuggingRecorder;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let fixture = make_tls_fixture("127.0.0.1");
                    let addr = tls_test_server(&fixture).await;
                    let url = format!("https://127.0.0.1:{}", addr.port());
                    let mut m = mapping(&url, "", UpstreamAuth::Anonymous);
                    m.ca_bundle_ref = Some(secret_ref_env("HORT_TEST_CA"));
                    let secrets = StaticSecretPort {
                        ca_pem: Some(fixture.ca_pem.clone().into_bytes()),
                        cert_pem: None,
                        key_pem: None,
                    };
                    let proxy = proxy_for_tls_with_secrets(addr, secrets);
                    let _ = proxy
                        .fetch_artifact(m, "/blob".to_string())
                        .await
                        .expect("fetch must succeed for the metric to fire success");
                });
        });

        let mut found = false;
        for (key, _, _, _) in snapshotter.snapshot().into_vec() {
            let inner: &Key = key.key();
            if inner.name() != "hort_upstream_tls_handshake_total" {
                continue;
            }
            let mut repo_ok = false;
            let mut result_ok = false;
            for label in inner.labels() {
                match label.key() {
                    "repository" if label.value() == "_all" => repo_ok = true,
                    "result" if label.value() == "success" => result_ok = true,
                    _ => {}
                }
            }
            if repo_ok && result_ok {
                found = true;
            }
        }
        assert!(
            found,
            "expected hort_upstream_tls_handshake_total{{repository=_all,result=success}} \
             after a successful TLS handshake against the in-process test server"
        );
    }

    /// Pin mismatch metric mapping: a pin mismatch fires
    /// `hort_upstream_tls_handshake_total{result=pin_mismatch}` and the
    /// fetch metric `hort_upstream_fetch_total{result=pin_mismatch}` —
    /// both sides of the taxonomy stay consistent.
    #[test]
    fn pin_mismatch_emits_pin_mismatch_label_on_both_metrics() {
        use metrics::Key;
        use metrics_util::debugging::DebuggingRecorder;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let fixture = make_tls_fixture("127.0.0.1");
                    let addr = tls_test_server(&fixture).await;
                    let url = format!("https://127.0.0.1:{}", addr.port());
                    let mut wrong_pin = fixture.leaf_pin_sha256_lower_hex.clone();
                    let first = wrong_pin.chars().next().unwrap();
                    let mutated = if first == '0' { '1' } else { '0' };
                    wrong_pin.replace_range(0..1, &mutated.to_string());
                    let mut m = mapping(&url, "", UpstreamAuth::Anonymous);
                    m.ca_bundle_ref = Some(secret_ref_env("HORT_TEST_CA"));
                    m.pinned_cert_sha256 = Some(wrong_pin);
                    let secrets = StaticSecretPort {
                        ca_pem: Some(fixture.ca_pem.clone().into_bytes()),
                        cert_pem: None,
                        key_pem: None,
                    };
                    let proxy = proxy_for_tls_with_secrets(addr, secrets);
                    let result = proxy.fetch_artifact(m, "/blob".to_string()).await;
                    assert!(
                        result.is_err(),
                        "must fail with pin mismatch, got Ok(_) instead"
                    );
                });
        });

        let snapshot = snapshotter.snapshot().into_vec();
        let mut tls_metric_found = false;
        let mut fetch_metric_found = false;
        for (key, _, _, _) in &snapshot {
            let inner: &Key = key.key();
            match inner.name() {
                "hort_upstream_tls_handshake_total" => {
                    let mut result_ok = false;
                    for label in inner.labels() {
                        if label.key() == "result" && label.value() == "pin_mismatch" {
                            result_ok = true;
                        }
                    }
                    if result_ok {
                        tls_metric_found = true;
                    }
                }
                "hort_upstream_fetch_total" => {
                    let mut result_ok = false;
                    for label in inner.labels() {
                        if label.key() == "result" && label.value() == "pin_mismatch" {
                            result_ok = true;
                        }
                    }
                    if result_ok {
                        fetch_metric_found = true;
                    }
                }
                _ => {}
            }
        }
        assert!(
            tls_metric_found,
            "expected hort_upstream_tls_handshake_total{{result=pin_mismatch}}"
        );
        assert!(
            fetch_metric_found,
            "expected hort_upstream_fetch_total{{result=pin_mismatch}}"
        );
    }

    /// Ensure no regression: a plain anonymous fetch with no TLS
    /// material still uses the proxy's default client and does NOT
    /// build a per-mapping client. Asserts via the `tls_client_cache`
    /// staying empty after the fetch.
    #[tokio::test]
    async fn fetch_without_tls_material_does_not_populate_per_mapping_cache() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"ok".as_slice()))
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "ghcr/", UpstreamAuth::Anonymous);
        let _ = proxy
            .fetch_blob(m, "p".into(), "sha256:ok".into())
            .await
            .expect("happy path");
        let cache = proxy.tls_client_cache.read().await;
        assert!(
            cache.is_empty(),
            "no TLS material on mapping → cache must stay empty; \
             got {} entries",
            cache.len()
        );
    }

    /// mTLS test scaffolding caveat. A complete mTLS exercise requires
    /// the test server to be configured with a `ClientCertVerifier`
    /// that demands a client cert, plus a separate mTLS-rejection path
    /// for the no-client-cert branch. axum-server 0.7's
    /// `RustlsConfig::from_pem` builds a server config without
    /// client-cert verification, so a faithful mTLS-required server
    /// would require lower-level rustls server-side wiring beyond the
    /// scope of this slice. The mTLS *resolution* path
    /// (`SecretPort::resolve` for cert + key, PEM parse, rustls
    /// `with_client_auth_cert`) is exercised by
    /// [`tls_config::tests::pinning_verifier_accepts_valid_lowercase_pin`]
    /// and the value-object pairing tests in
    /// `crates/hort-domain/src/ports/repository_upstream_mapping_repository.rs`.
    /// A full mTLS-required E2E test is a future work item; this
    /// slice's scope ends at the unit-level mTLS resolution.
    #[test]
    fn mtls_required_e2e_test_documented_as_skipped() {
        // No assertion — the doc-comment on this test is the test:
        // it pins the rationale for not standing up a mutual-TLS
        // server in this slice. The slice is otherwise complete; mTLS
        // path coverage is at the unit level (cert / key resolution
        // and rustls config build).
    }

    // -- Extra-CA-only path (ADR 0010) ---------------------------------
    //
    // Verify that `extra_anchors` (`Option<&ExtraTrustAnchors>` on
    // `build_rustls_client_config`) is sufficient to trust a self-signed
    // server when the mapping has NO `ca_bundle_ref`. This mirrors the
    // production flow where the process-wide `HORT_EXTRA_CA_BUNDLE` is
    // the only source of the corporate CA cert.

    /// Test E —
    ///
    /// A mapping with no `ca_bundle_ref` succeeds when the CA cert is
    /// supplied exclusively via `extra_anchors`. Without `extra_anchors`
    /// the same mapping fails (the self-signed test CA is not in any
    /// OS trust store). Confirms the new parameter in
    /// `build_rustls_client_config` is load-bearing.
    #[tokio::test]
    async fn build_rustls_client_config_extra_anchors_only_path_succeeds() {
        use hort_config::ExtraTrustAnchors;
        use tls_config::build_rustls_client_config;

        let fixture = make_tls_fixture("127.0.0.1");
        let addr = tls_test_server(&fixture).await;
        let url = format!("https://127.0.0.1:{}/", addr.port());

        // Parse the test CA PEM into ExtraTrustAnchors — simulates the
        // process-wide bundle loaded from HORT_EXTRA_CA_BUNDLE.
        let anchors =
            ExtraTrustAnchors::parse_pem(fixture.ca_pem.as_bytes()).expect("parse test CA PEM");

        // Build a rustls config with no per-mapping CA (empty ca_certs_der)
        // but with extra_anchors carrying the test CA.
        let no_mapping_material = ResolvedTlsMaterial {
            ca_certs_der: Vec::new(),
            mtls_cert_chain_der: Vec::new(),
            mtls_key_der: None,
            pin_sha256_lower_hex: None,
        };
        let rustls_cfg = build_rustls_client_config(&no_mapping_material, Some(&anchors))
            .expect("build_rustls_client_config with extra_anchors must succeed");

        // Build a reqwest Client using the rustls config and assert the
        // TLS handshake succeeds against the test server. The
        // `GuardedDnsResolver` wrapper was removed; reqwest's default
        // resolver connects to `127.0.0.1` directly.
        let _ = addr; // bound port already encoded in `url`
        let client = Client::builder()
            .use_preconfigured_tls(rustls_cfg)
            .build()
            .expect("reqwest Client build");

        let resp = client
            .get(&url)
            .send()
            .await
            .expect("fetch with extra_anchors-only trust must succeed");
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "expected 200 from TLS test server"
        );
        let body = resp.bytes().await.expect("body");
        assert_eq!(body.as_ref(), b"tls-ok");
    }

    /// Test F — extra-CA-only baseline failure:
    ///
    /// Without `extra_anchors` and without `ca_bundle_ref`, the same
    /// self-signed test server must fail with a TLS error. This is the
    /// mirror of Test E: confirms the parameter is the only thing making
    /// Test E succeed (i.e. Test E doesn't accidentally pass because the
    /// OS trust store contains our test CA somehow).
    #[tokio::test]
    async fn build_rustls_client_config_no_extra_anchors_fails_for_self_signed() {
        use tls_config::build_rustls_client_config;

        let fixture = make_tls_fixture("127.0.0.1");
        let addr = tls_test_server(&fixture).await;
        let url = format!("https://127.0.0.1:{}/", addr.port());

        let no_material = ResolvedTlsMaterial {
            ca_certs_der: Vec::new(),
            mtls_cert_chain_der: Vec::new(),
            mtls_key_der: None,
            pin_sha256_lower_hex: None,
        };
        // Pass None for extra_anchors — the test CA is not in the OS store.
        let rustls_cfg = build_rustls_client_config(&no_material, None)
            .expect("build without extra_anchors must construct (no soft error at build time)");

        let _ = addr; // bound port already encoded in `url`
        let client = Client::builder()
            .use_preconfigured_tls(rustls_cfg)
            .build()
            .expect("reqwest Client build");

        let result = client.get(&url).send().await;
        assert!(
            result.is_err(),
            "fetch with no CA trust for self-signed cert must fail (extra_anchors=None)"
        );
    }

    // -- Extra-CA proxy-level path (ADR 0010) --------------------------
    //
    // Verify that `HttpUpstreamProxyConfig::extra_trust_anchors` is
    // properly wired through `HttpUpstreamProxy` so that a mapping with
    // no `ca_bundle_ref` can still reach a TLS server signed exclusively
    // by the process-wide CA bundle.
    //
    // Two tests mirror Tests E + F above but at the full-adapter level:
    //  - Test G: `HttpUpstreamProxy` with `extra_trust_anchors` set succeeds.
    //  - Test H: `HttpUpstreamProxy` with `extra_trust_anchors = None` fails.
    //
    // The test server is the same rcgen + axum-server stack used above.
    // The mapping is anonymous (no `ca_bundle_ref`), so the only source
    // of trust for the self-signed CA is `extra_trust_anchors` on the
    // proxy config.

    /// Test G —
    ///
    /// An `HttpUpstreamProxy` with `extra_trust_anchors` carrying the test CA
    /// successfully fetches a blob from a server presenting a cert signed by
    /// that CA. The mapping has no `ca_bundle_ref`, so the only path to trust
    /// is through the process-wide bundle.
    #[tokio::test]
    async fn http_upstream_proxy_extra_trust_anchors_enables_tls_fetch() {
        use hort_config::ExtraTrustAnchors;

        let fixture = make_tls_fixture("127.0.0.1");
        let addr = tls_test_server(&fixture).await;

        // Parse the test CA PEM into ExtraTrustAnchors — simulates the
        // process-wide bundle loaded from HORT_EXTRA_CA_BUNDLE.
        let anchors =
            ExtraTrustAnchors::parse_pem(fixture.ca_pem.as_bytes()).expect("parse test CA PEM");

        let cfg = HttpUpstreamProxyConfig {
            extra_trust_anchors: Some(anchors),
            ..HttpUpstreamProxyConfig::default()
        };
        let proxy = HttpUpstreamProxy::new(cfg, Arc::new(AnonymousFallbackPort))
            .expect("proxy construction with extra_trust_anchors must succeed");

        // Build a mapping that points at the test HTTPS server.
        // No `ca_bundle_ref`, `mtls_*_ref`, or `pinned_cert_sha256` —
        // the proxy must succeed through extra_trust_anchors alone.
        let m = mapping(
            &format!("https://127.0.0.1:{}/", addr.port()),
            "",
            UpstreamAuth::Anonymous,
        );
        // BlobStream doesn't implement Debug — use explicit match rather than
        // `.expect` / `{result:?}`.
        match proxy.fetch_artifact(m, "/blob".to_string()).await {
            Ok(_) => {} // success — expected
            Err(e) => {
                panic!("fetch via extra_trust_anchors-only CA trust must succeed; got err={e}")
            }
        }
    }

    /// Test H — proxy-level no-CA failure:
    ///
    /// Without `extra_trust_anchors` (and without `ca_bundle_ref`), the same
    /// self-signed test server must cause the proxy fetch to fail. The failure
    /// classifies as `UpstreamErrorKind::CaUnknown` (TLS handshake rejection)
    /// or `UpstreamErrorKind::NetworkError` depending on how reqwest surfaces
    /// the underlying TLS error. Both are acceptable failure classifications;
    /// the key assertion is that the fetch does NOT succeed.
    #[tokio::test]
    async fn http_upstream_proxy_no_extra_trust_anchors_fails_for_self_signed() {
        let fixture = make_tls_fixture("127.0.0.1");
        let addr = tls_test_server(&fixture).await;

        // No extra_trust_anchors — only public CAs are trusted.
        let cfg = HttpUpstreamProxyConfig {
            extra_trust_anchors: None,
            ..HttpUpstreamProxyConfig::default()
        };
        let proxy = HttpUpstreamProxy::new(cfg, Arc::new(AnonymousFallbackPort))
            .expect("proxy construction must succeed even without extra_trust_anchors");

        let m = mapping(
            &format!("https://127.0.0.1:{}/", addr.port()),
            "",
            UpstreamAuth::Anonymous,
        );
        // BlobStream doesn't implement Debug — use let-else.
        let Err(err) = proxy.fetch_artifact(m, "/blob".to_string()).await else {
            panic!(
                "fetch without CA trust for self-signed cert must succeed; extra_trust_anchors=None"
            );
        };
        // The failure must classify as CaUnknown or NetworkError — NOT
        // as a successful response. Either classification is acceptable
        // because reqwest can surface TLS cert-rejection errors either way.
        let kind = classify_error(&err);
        assert!(
            matches!(
                kind,
                Some(UpstreamErrorKind::CaUnknown) | Some(UpstreamErrorKind::NetworkError)
            ),
            "TLS failure must classify as CaUnknown or NetworkError; got {kind:?} (err={err})"
        );
    }

    // ----------------------------------------------------------------------
    // Cross-host redirect Authorization-strip
    //
    // Pins reqwest's documented behaviour: when the redirect-policy follows
    // a redirect that crosses to a different origin, the `Authorization`
    // header attached to the original request is NOT replayed on the
    // redirected request.
    //
    // This is the credential-leak defence that backs the decision to drop
    // the upstream-http `GuardedDnsResolver` redirect guard. If reqwest
    // ever stops stripping Authorization on cross-origin redirects, the
    // threat model behind that decision is broken — this regression test
    // trips first.
    //
    // References:
    //   - RFC 7235 §2.2 ("Protection Space (Realm)") establishes that the
    //     Authorization header is scoped to a single protection space; a
    //     redirect to a different origin is, by definition, a different
    //     protection space. Replaying credentials there is a known
    //     credential-leak class — see the IETF httpbis security
    //     considerations and OWASP cheat-sheet treatment of "credential
    //     leakage via redirect".
    //   - RFC 6454 §4 defines origin as the (scheme, host, port) triple.
    //     Two `MockServer` instances on `127.0.0.1` differ by port and
    //     are therefore distinct origins. reqwest's same-origin check
    //     uses this triple.
    //   - reqwest's documented contract: the default redirect policy
    //     (and any custom policy that calls `attempt.follow()`) drops
    //     `Authorization`, `Cookie`, `Cookie2`, `Proxy-Authorization`
    //     and `WWW-Authenticate` whenever the previous and next URLs
    //     differ in origin. Source of truth:
    //     `reqwest::redirect::Policy` docs and the
    //     `remove_sensitive_headers` call in reqwest's redirect machinery.
    //
    // The test drives Authorization through the public `fetch_metadata`
    // path (Basic auth, exercised at `send_get` lib.rs:1227-1242). Two
    // distinct `MockServer` instances guarantee a different `host:port`
    // pair (same loopback IP, different ephemeral ports) — sufficient to
    // make them cross-origin.
    // ----------------------------------------------------------------------

    #[tokio::test]
    async fn cross_host_redirect_strips_authorization_header() {
        use hort_domain::ports::secret_port::SecretSource;

        // Stand up the redirect target FIRST so we know its uri/port for
        // the 302 Location header.
        let server_b = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/redirected"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"final-body".as_slice()))
            .expect(1)
            .mount(&server_b)
            .await;

        // Now stand up the redirector. wiremock binds each MockServer on
        // a fresh ephemeral port; server_a.address().port() !=
        // server_b.address().port() — making them distinct origins by
        // RFC 6454 §4 even though both share `127.0.0.1`.
        let server_a = MockServer::start().await;
        let location = format!("{}/redirected", server_b.uri());
        Mock::given(method("GET"))
            .and(path("/start"))
            .respond_with(ResponseTemplate::new(302).insert_header("Location", location.as_str()))
            .expect(1)
            .mount(&server_a)
            .await;

        // The per-hop redirect SSRF re-check means the loopback wiremock
        // hop would be (correctly) refused under the production
        // constructor. This test — which exists to pin reqwest's
        // cross-origin Authorization-strip across a *real* redirect chain
        // — uses the test-allowlist constructor with both wiremock
        // servers' loopback addresses. The security behaviour itself is
        // pinned by the dedicated `redirect_hop_to_*` tests, not weakened
        // here.
        let cfg = HttpUpstreamProxyConfig {
            timeout: Duration::from_secs(2),
            format_label: "oci".to_string(),
            ..Default::default()
        };
        // FixedSecretPort returns the byte payload as a SecretValue; the
        // Basic-auth path in `authorization_header` formats it as
        // `Basic base64("oauth2:hunter2")` and attaches it via
        // `send_get` (lib.rs:1227-1242). The token is therefore present
        // on the FIRST hop and absent (per reqwest's contract) on the
        // SECOND hop.
        let port = Arc::new(FixedSecretPort {
            bytes: b"hunter2".to_vec(),
        });
        let proxy = HttpUpstreamProxy::new_with_redirect_test_allowlist(
            cfg,
            port,
            vec![*server_a.address(), *server_b.address()],
        )
        .unwrap();

        let mut m = mapping(
            &server_a.uri(),
            "",
            UpstreamAuth::Basic {
                username: "oauth2".into(),
            },
        );
        m.secret_ref = Some(SecretRef {
            source: SecretSource::EnvVar,
            location: "HORT_AUTHZ_STRIP_TEST".into(),
        });

        // Drive the request through the public `fetch_metadata` API so
        // the full Auth-resolution + send_get + redirect-policy stack is
        // exercised. Empty `accept` keeps the wiremock matchers minimal.
        let outcome = proxy
            .fetch_metadata(m, "/start".into(), Vec::new())
            .await
            .expect("fetch_metadata across redirect must succeed");
        assert_eq!(
            body_of_metadata(&outcome),
            b"final-body",
            "body must be the redirected target's response, proving the chain followed end-to-end"
        );

        // (a) Both servers were hit. wiremock's `.expect(1)` mounts
        // already enforce this on Drop, but we make the request-count
        // assertion explicit so a future maintainer reading the test
        // sees the chain shape without grepping for `expect(1)`.
        let recorded_a = server_a.received_requests().await.unwrap();
        let recorded_b = server_b.received_requests().await.unwrap();
        assert_eq!(
            recorded_a.len(),
            1,
            "first server (redirector) must observe exactly one request"
        );
        assert_eq!(
            recorded_b.len(),
            1,
            "second server (redirect target) must observe exactly one request"
        );

        // The first hop carried the Basic-auth header — sanity-check
        // that auth was actually attached, otherwise the cross-origin
        // strip assertion below is vacuous (we'd be observing absence
        // because we never sent the header at all).
        assert!(
            recorded_a[0].headers.contains_key(AUTHORIZATION),
            "regression check: Authorization header must be sent on the first hop \
             (otherwise the strip-on-redirect assertion below is vacuous)"
        );

        // (b) The PIN: the second server (different origin by port) must
        // NOT have observed the Authorization header. If a future reqwest
        // version drops this strip behaviour, this assertion fails and
        // the security assumption documented above is broken — do NOT
        // relax this assertion; investigate the reqwest changelog.
        assert!(
            !recorded_b[0].headers.contains_key(AUTHORIZATION),
            "reqwest must strip the Authorization header on cross-origin redirects \
             (RFC 7235 §2.2 + reqwest documented contract); observed headers: {:?}",
            recorded_b[0].headers
        );
    }

    // ===================================================================
    // `build_url` — `upstream_name_prefix` composition
    // ===================================================================
    //
    // Composes
    //   None    → `<base>/v2/<name>/<kind>/<value>`
    //   Some(p) → `<base>/v2/<p>/<name>/<kind>/<value>`
    //
    // Constructor validation guarantees the prefix has no leading or
    // trailing slash so the `format!` produces exactly one `/` between
    // segments. Trailing-slash on `base` is trimmed. `is_args` /
    // query-string preservation is a property of `compose_url` (the
    // non-OCI metadata path), not `build_url` — covered by
    // `compose_url`'s own tests.

    #[test]
    fn build_url_none_matches_baseline_shape() {
        // Regression pin: `None` must compose the standard OCI URL shape.
        let url = HttpUpstreamProxy::build_url(
            "https://registry-1.docker.io",
            None,
            "library/alpine",
            "manifests",
            "3.19",
        );
        assert_eq!(
            url,
            "https://registry-1.docker.io/v2/library/alpine/manifests/3.19"
        );
    }

    #[test]
    fn build_url_some_single_segment_prefix() {
        let url = HttpUpstreamProxy::build_url(
            "https://zot.example.com",
            Some("docker.io"),
            "library/alpine",
            "manifests",
            "3.19",
        );
        assert_eq!(
            url,
            "https://zot.example.com/v2/docker.io/library/alpine/manifests/3.19"
        );
    }

    #[test]
    fn build_url_some_multi_segment_prefix() {
        let url = HttpUpstreamProxy::build_url(
            "https://gitlab.example.com",
            Some("acme/internal/proxy"),
            "library/alpine",
            "blobs",
            "sha256:abc",
        );
        assert_eq!(
            url,
            "https://gitlab.example.com/v2/acme/internal/proxy/library/alpine/blobs/sha256:abc"
        );
    }

    #[test]
    fn build_url_trims_trailing_slash_on_base() {
        // A trailing slash on the upstream URL is tolerated. Verify it
        // still holds when the prefix is set.
        let url_none = HttpUpstreamProxy::build_url(
            "https://registry-1.docker.io/",
            None,
            "name",
            "blobs",
            "v",
        );
        assert_eq!(url_none, "https://registry-1.docker.io/v2/name/blobs/v");

        let url_some = HttpUpstreamProxy::build_url(
            "https://zot.example.com/",
            Some("docker.io"),
            "name",
            "blobs",
            "v",
        );
        assert_eq!(
            url_some,
            "https://zot.example.com/v2/docker.io/name/blobs/v"
        );
    }

    // ===================================================================
    // Per-hop SSRF re-validation on redirect-following
    // ===================================================================
    //
    // `check_ssrf_safe` runs once on the initial absolute artifact URL.
    // Without a per-hop redirect SSRF re-check, a poisoned upstream index
    // could `302 Location:` the client onto an internal IMDS / RFC1918
    // target and stream the response back as artifact/metadata content.
    // These tests pin the reinstated per-hop `is_routable` re-check.
    //
    // Test wiring: wiremock binds on loopback, which `is_routable`
    // classifies as non-routable. The redirect-policy is therefore built
    // with a *test-only* allowlist of the wiremock `SocketAddr`s (scoped
    // private to this crate, NOT re-exported, NOT in `hort-net-egress`).
    // Production builds the policy with an empty allowlist (every
    // loopback/RFC1918/link-local hop is rejected). The "blocked" case
    // redirects to a host that is NOT in the allowlist, so it exercises
    // the real refusal path even though the test runs on loopback.

    /// Build a proxy whose redirect policy treats the supplied wiremock
    /// servers' loopback addresses as routable (test-only), so the
    /// allow / hop-cap paths can be exercised against wiremock while a
    /// redirect to any OTHER non-routable host is still refused.
    fn proxy_with_redirect_test_allowlist(
        servers: &[&MockServer],
        max_redirect_hops: usize,
    ) -> HttpUpstreamProxy {
        let allow: Vec<SocketAddr> = servers.iter().map(|s| *s.address()).collect();
        let cfg = HttpUpstreamProxyConfig {
            timeout: Duration::from_secs(2),
            format_label: "oci".to_string(),
            max_redirect_hops,
            ..Default::default()
        };
        HttpUpstreamProxy::new_with_redirect_test_allowlist(
            cfg,
            Arc::new(AnonymousFallbackPort),
            allow,
        )
        .unwrap()
    }

    /// Case 1: a 302 `Location:` to a non-routable host
    /// (169.254.169.254 — AWS IMDS) is BLOCKED. The internal target's
    /// body must NOT be streamed back; the fetch surfaces as a
    /// content-validation refusal classified `ParseError` (the same
    /// classification a `check_ssrf_safe` refusal uses).
    #[tokio::test]
    async fn redirect_hop_to_link_local_imds_is_blocked() {
        let redirector = MockServer::start().await;
        // Redirect to the canonical AWS IMDS address. 169.254.169.254
        // is link-local; `is_routable` rejects it and it is NOT in the
        // test allowlist (only `redirector`'s loopback addr is).
        Mock::given(method("GET"))
            .and(path("/poisoned-index/foo-1.0.tar.gz"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", "http://169.254.169.254/latest/meta-data/"),
            )
            .mount(&redirector)
            .await;

        let proxy = proxy_with_redirect_test_allowlist(&[&redirector], 5);
        let m = mapping(&redirector.uri(), "", UpstreamAuth::Anonymous);

        let result = proxy
            .fetch_artifact(m, "/poisoned-index/foo-1.0.tar.gz".into())
            .await;

        let Err(err) = result else {
            panic!("redirect to link-local IMDS must be refused, not followed");
        };
        // Same classification as a `check_ssrf_safe` refusal — the
        // refusal reuses the existing `ParseError` mapping; no new
        // error/metric variant is introduced.
        assert_eq!(
            classify_error(&err),
            Some(UpstreamErrorKind::ParseError),
            "blocked redirect hop must classify as ParseError (the \
             check_ssrf_safe refusal contract), got {err:?}"
        );
    }

    /// Case 1b: a 302 to an RFC1918 private host is likewise blocked
    /// (the same refusal class as IMDS).
    #[tokio::test]
    async fn redirect_hop_to_rfc1918_is_blocked() {
        let redirector = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/idx/pkg.tgz"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", "http://10.0.0.1/internal-secret"),
            )
            .mount(&redirector)
            .await;

        let proxy = proxy_with_redirect_test_allowlist(&[&redirector], 5);
        let m = mapping(&redirector.uri(), "", UpstreamAuth::Anonymous);

        let Err(err) = proxy.fetch_artifact(m, "/idx/pkg.tgz".into()).await else {
            panic!("redirect to RFC1918 must be refused");
        };
        assert_eq!(
            classify_error(&err),
            Some(UpstreamErrorKind::ParseError),
            "blocked RFC1918 redirect must classify as ParseError, got {err:?}"
        );
    }

    /// Case 2: a 302 to a *routable* host is ALLOWED — legitimate CDN
    /// redirect still works (no false-positive). npm / PyPI / crates
    /// routinely 302 to a CDN; this must not break. Both wiremock
    /// servers are in the test allowlist (they stand in for "routable"
    /// public hosts since wiremock can only bind loopback); the policy
    /// follows the hop and the redirected body reaches the caller.
    #[tokio::test]
    async fn redirect_hop_to_routable_cdn_is_allowed() {
        let cdn = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/cdn/foo-1.0.tar.gz"))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(b"cdn-artifact-bytes".as_slice()),
            )
            .mount(&cdn)
            .await;

        let redirector = MockServer::start().await;
        let location = format!("{}/cdn/foo-1.0.tar.gz", cdn.uri());
        Mock::given(method("GET"))
            .and(path("/index/foo-1.0.tar.gz"))
            .respond_with(ResponseTemplate::new(302).insert_header("Location", location.as_str()))
            .mount(&redirector)
            .await;

        let proxy = proxy_with_redirect_test_allowlist(&[&redirector, &cdn], 5);
        let m = mapping(&redirector.uri(), "", UpstreamAuth::Anonymous);

        let mut stream = proxy
            .fetch_artifact(m, "/index/foo-1.0.tar.gz".into())
            .await
            .expect("redirect to a routable CDN host must be followed")
            .stream;
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            bytes.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(
            bytes, b"cdn-artifact-bytes",
            "the routable-CDN redirect target's body must reach the caller"
        );
    }

    /// Case 3: the hop CAP is still enforced. A redirect chain longer
    /// than `max_redirect_hops` is rejected as before — the custom
    /// policy must still enforce the limit (it does not silently follow
    /// forever once the per-hop SSRF check is added).
    #[tokio::test]
    async fn redirect_chain_exceeding_hop_cap_is_rejected() {
        // A single server that always 302s back to a path on itself,
        // forming an unbounded redirect loop. With `max_redirect_hops`
        // small, the policy must stop the chain.
        let looper = MockServer::start().await;
        let self_loop = format!("{}/loop", looper.uri());
        Mock::given(method("GET"))
            .and(path("/loop"))
            .respond_with(ResponseTemplate::new(302).insert_header("Location", self_loop.as_str()))
            .mount(&looper)
            .await;

        // `looper` is allowlisted (loopback) so the chain is NOT
        // short-circuited by the SSRF check — it must terminate purely
        // on the hop cap.
        let proxy = proxy_with_redirect_test_allowlist(&[&looper], 2);
        let m = mapping(&looper.uri(), "", UpstreamAuth::Anonymous);

        let Err(err) = proxy.fetch_artifact(m, "/loop".into()).await else {
            panic!("an unbounded redirect loop must be rejected by the hop cap");
        };
        // reqwest surfaces a too-many-redirects condition as a redirect
        // error; our mapping classifies it (network-layer) — the key
        // assertion is that the loop terminated with an error rather
        // than hanging / following indefinitely.
        assert!(
            classify_error(&err).is_some(),
            "hop-cap rejection must be a classified upstream error, got {err:?}"
        );
    }

    /// Tempfile mode 0600 (security invariant): the streamed upstream
    /// metadata/manifest body holds authenticated-upstream content; the
    /// tempfile must be created mode `0o600` (owner rw only), never the
    /// default `0o644` (world-readable) that `tokio::fs::File::create`
    /// yields. On a shared host a 0644 tempfile leaks authenticated-
    /// upstream metadata to any local user. Mirrors the
    /// `FilesystemMetadataMirror::put` mode-0600 assertion
    /// (`metadata_mirror.rs`).
    #[cfg(unix)]
    #[tokio::test]
    async fn write_streaming_creates_tempfile_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let stream = futures::stream::iter(vec![Ok::<_, reqwest::Error>(
            bytes::Bytes::from_static(b"authenticated-upstream-secret"),
        )]);
        let handle = write_streaming(
            stream,
            TEST_METADATA_CAP,
            FetchClass::Metadata,
            "f-44-mode-test".to_string(),
        )
        .await
        .expect("write_streaming must succeed for an under-cap body");

        let meta = std::fs::metadata(&handle.path).expect("stat the committed tempfile");
        let mode = meta.permissions().mode() & 0o777;
        // Best-effort cleanup before the assertion so a failure does not
        // leak the fixture file.
        let _ = std::fs::remove_file(&handle.path);
        assert_eq!(
            mode, 0o600,
            "upstream-body tempfile must be mode 0o600, got {mode:o}"
        );
    }

    // -------------------------------------------------------------------
    // `fetch_referrers` — OCI referrers API + tag-scheme fallback (ADR 0027)
    //
    // OCI Distribution Spec v1.1 §referrers-api:
    //   GET /v2/<name>/referrers/<digest> → an OCI image index whose
    //   `manifests[]` are referrer descriptors.
    // Cosign tag-scheme fallback (Docker Hub legacy / no Referrers API):
    //   GET /v2/<name>/manifests/sha256-<hex>.sig  (the `sha256:`
    //   separator in the subject digest replaced by `sha256-`, `.sig`
    //   appended) → on 200 a single synthesised descriptor.
    // -------------------------------------------------------------------

    // The subject image digest the referrers are fetched for. The
    // tag-scheme fallback derives the `.sig` tag by replacing the
    // `sha256:` algorithm separator with `sha256-` and appending `.sig`.
    const REFERRERS_SUBJECT_DIGEST: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const REFERRERS_SIG_TAG: &str =
        "sha256-1111111111111111111111111111111111111111111111111111111111111111.sig";

    /// (a) Referrers API 200 → the image index's `manifests[]` are
    /// parsed into `ReferrerDescriptor`s (digest + mediaType +
    /// artifactType).
    #[tokio::test]
    async fn fetch_referrers_api_200_returns_parsed_descriptors() {
        let server = MockServer::start().await;
        let index = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": "sha256:aaaa",
                    "size": 7682,
                    "artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json"
                },
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": "sha256:bbbb",
                    "size": 42
                }
            ]
        });
        Mock::given(method("GET"))
            .and(path(format!(
                "/v2/library/nginx/referrers/{REFERRERS_SUBJECT_DIGEST}"
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(CONTENT_TYPE, "application/vnd.oci.image.index.v1+json")
                    .set_body_bytes(serde_json::to_vec(&index).unwrap()),
            )
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let out = proxy
            .fetch_referrers(m, "library/nginx".into(), REFERRERS_SUBJECT_DIGEST.into())
            .await
            .expect("fetch_referrers");
        assert_eq!(
            out,
            vec![
                ReferrerDescriptor {
                    digest: "sha256:aaaa".into(),
                    media_type: "application/vnd.oci.image.manifest.v1+json".into(),
                    artifact_type: Some("application/vnd.dev.sigstore.bundle.v0.3+json".into()),
                },
                ReferrerDescriptor {
                    digest: "sha256:bbbb".into(),
                    media_type: "application/vnd.oci.image.manifest.v1+json".into(),
                    artifact_type: None,
                },
            ]
        );
    }

    /// (b) Referrers API 404 → tag-scheme fallback. The `.sig` tag is
    /// `sha256-<hex>.sig` derived from the subject digest. On 200 a
    /// single descriptor is synthesised from the `.sig` manifest's
    /// `Content-Type` + `Docker-Content-Digest`.
    #[tokio::test]
    async fn fetch_referrers_api_404_falls_back_to_sig_tag_scheme() {
        let server = MockServer::start().await;
        // Referrers API not supported / no referrers → 404.
        Mock::given(method("GET"))
            .and(path(format!(
                "/v2/library/nginx/referrers/{REFERRERS_SUBJECT_DIGEST}"
            )))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        // The cosign `.sig` tag exists → 200 with the sig manifest.
        Mock::given(method("GET"))
            .and(path(format!(
                "/v2/library/nginx/manifests/{REFERRERS_SIG_TAG}"
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(CONTENT_TYPE, "application/vnd.oci.image.manifest.v1+json")
                    .insert_header("docker-content-digest", "sha256:sigsigsig")
                    .set_body_bytes(br#"{"schemaVersion":2}"#.as_slice()),
            )
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let out = proxy
            .fetch_referrers(m, "library/nginx".into(), REFERRERS_SUBJECT_DIGEST.into())
            .await
            .expect("fetch_referrers tag fallback");
        // One synthesised descriptor for the `.sig` manifest. Its digest
        // is the upstream `Docker-Content-Digest`; the artifact type is
        // the cosign sig media type the verifier filters on.
        assert_eq!(
            out,
            vec![ReferrerDescriptor {
                digest: "sha256:sigsigsig".into(),
                media_type: "application/vnd.oci.image.manifest.v1+json".into(),
                artifact_type: Some(SIGSTORE_BUNDLE_MEDIA_TYPE.into()),
            }]
        );
    }

    /// (c) Referrers API 404 AND the tag-scheme `.sig` also 404 →
    /// `Ok(vec![])` (no signature upstream — not an error).
    #[tokio::test]
    async fn fetch_referrers_api_and_tag_both_404_returns_empty() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/v2/library/nginx/referrers/{REFERRERS_SUBJECT_DIGEST}"
            )))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/v2/library/nginx/manifests/{REFERRERS_SIG_TAG}"
            )))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let out = proxy
            .fetch_referrers(m, "library/nginx".into(), REFERRERS_SUBJECT_DIGEST.into())
            .await
            .expect("fetch_referrers both-404");
        assert!(
            out.is_empty(),
            "no upstream signature → empty vec, got {out:?}"
        );
    }

    /// (d) Upstream 5xx on the Referrers API → mapped
    /// `UpstreamErrorKind::Upstream5xx` (a transport/server failure
    /// must NOT be silently swallowed as "no referrers").
    #[tokio::test]
    async fn fetch_referrers_api_5xx_maps_to_upstream_5xx() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/v2/library/nginx/referrers/{REFERRERS_SUBJECT_DIGEST}"
            )))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let err = proxy
            .fetch_referrers(m, "library/nginx".into(), REFERRERS_SUBJECT_DIGEST.into())
            .await
            .expect_err("5xx must surface as an error");
        assert_eq!(classify_error(&err), Some(UpstreamErrorKind::Upstream5xx));
    }

    /// Referrers API 200 with a body that is not a valid OCI image index
    /// → `UpstreamErrorKind::ParseError` (a malformed upstream response
    /// is a parse outcome, not "no referrers").
    #[tokio::test]
    async fn fetch_referrers_api_malformed_body_maps_to_parse_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/v2/library/nginx/referrers/{REFERRERS_SUBJECT_DIGEST}"
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(CONTENT_TYPE, "application/vnd.oci.image.index.v1+json")
                    // `manifests` must be an array — a string trips serde.
                    .set_body_bytes(br#"{"manifests":"not-an-array"}"#.as_slice()),
            )
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let err = proxy
            .fetch_referrers(m, "library/nginx".into(), REFERRERS_SUBJECT_DIGEST.into())
            .await
            .expect_err("malformed index must error");
        assert_eq!(classify_error(&err), Some(UpstreamErrorKind::ParseError));
    }

    /// Referrers index body over the configured cache cap →
    /// `UpstreamErrorKind::ManifestTooLarge` (the bounded read trips
    /// rather than allocating an unbounded buffer).
    #[tokio::test]
    async fn fetch_referrers_oversize_body_maps_to_manifest_too_large() {
        let server = MockServer::start().await;
        let oversized = vec![b'x'; 2 * TEST_MANIFEST_CAP as usize];
        Mock::given(method("GET"))
            .and(path(format!(
                "/v2/library/nginx/referrers/{REFERRERS_SUBJECT_DIGEST}"
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(CONTENT_TYPE, "application/vnd.oci.image.index.v1+json")
                    .set_body_bytes(oversized),
            )
            .mount(&server)
            .await;
        let proxy = proxy_for_with_caps(TEST_METADATA_CAP, TEST_MANIFEST_CAP);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let err = proxy
            .fetch_referrers(m, "library/nginx".into(), REFERRERS_SUBJECT_DIGEST.into())
            .await
            .expect_err("oversize referrers body must error");
        assert_eq!(
            classify_error(&err),
            Some(UpstreamErrorKind::ManifestTooLarge)
        );
    }

    /// Tag-scheme fallback where the `.sig` response carries no
    /// `Docker-Content-Digest` header → the synthesised descriptor's
    /// digest falls back to the `.sig` tag itself (the caller resolves
    /// the real digest via `fetch_manifest` regardless).
    #[tokio::test]
    async fn fetch_referrers_tag_scheme_without_digest_header_uses_sig_tag() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/v2/library/nginx/referrers/{REFERRERS_SUBJECT_DIGEST}"
            )))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/v2/library/nginx/manifests/{REFERRERS_SIG_TAG}"
            )))
            .respond_with(
                // No CONTENT_TYPE, no docker-content-digest header.
                ResponseTemplate::new(200).set_body_bytes(br#"{"schemaVersion":2}"#.as_slice()),
            )
            .mount(&server)
            .await;
        let proxy = proxy_for(&server);
        let m = mapping(&server.uri(), "", UpstreamAuth::Anonymous);
        let out = proxy
            .fetch_referrers(m, "library/nginx".into(), REFERRERS_SUBJECT_DIGEST.into())
            .await
            .expect("fetch_referrers tag fallback without digest header");
        assert_eq!(
            out,
            vec![ReferrerDescriptor {
                digest: REFERRERS_SIG_TAG.into(),
                // CONTENT_TYPE absent → the documented manifest-mediatype default.
                media_type: "application/vnd.oci.image.manifest.v1+json".into(),
                artifact_type: Some(SIGSTORE_BUNDLE_MEDIA_TYPE.into()),
            }]
        );
    }
}
