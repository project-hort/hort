//! Cached Sigstore trust root + its refresh-window bookkeeping.
//!
//! The verify path is **offline**: a stored Sigstore bundle
//! carries its own Fulcio cert chain (with SCT) + Rekor inclusion proof /
//! SignedEntryTimestamp, and the adapter validates that material against a
//! **cached trust root** (Fulcio CA certs + Rekor/CT-log public keys). The
//! trust root is refreshed periodically via TUF — *not* per verify. This
//! module owns that cached material and the "is it loaded and within its
//! refresh window?" predicate `health_check` consults.
//!
//! The trust root is **injectable**: [`CachedTrustRoot::from_trusted_root_json`]
//! parses a Sigstore `trusted_root.json` (the standard TUF target) fully
//! offline, and tests build one from a crafted fixture. The only live HTTP
//! is the periodic refresh ([`refresh_trusted_root_json`]), which fetches
//! the `trusted_root.json` bytes with an ADR 0010-compliant client and feeds
//! them back through `from_trusted_root_json`.

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use hort_config::ExtraTrustAnchors;
use hort_domain::error::{DomainError, DomainResult};
use sigstore::trust::sigstore::SigstoreTrustRoot;

use crate::extra_ca;

/// Build an owned [`SigstoreTrustRoot`] from a `trusted_root.json`
/// payload, fully offline. Shared by [`CachedTrustRoot`] construction
/// (validation) and the per-verify path (which needs a fresh **owned**
/// root because `sigstore::Verifier::new` consumes its `TrustRoot` by
/// value and `SigstoreTrustRoot` is not `Clone`).
pub(crate) fn parse_trusted_root(data: &[u8]) -> DomainResult<SigstoreTrustRoot> {
    SigstoreTrustRoot::from_trusted_root_json_unchecked(data).map_err(|e| {
        DomainError::Invariant(format!(
            "provenance-sigstore: trust root JSON is not parseable: {e}"
        ))
    })
}

/// Default maximum age of a loaded trust root before `health_check`
/// considers it stale. Sigstore's public-good TUF metadata has a short
/// expiry; a day is a conservative refresh window that still keeps a
/// worker bootable across a transient TUF outage. The composition root
/// can override this.
pub const DEFAULT_REFRESH_WINDOW_HOURS: i64 = 24;

/// A minimal but structurally-valid `trusted_root.json` for tests across
/// the crate. It parses (so `from_trusted_root_json` succeeds) but carries
/// no Fulcio certs — sufficient for trust-root *loading* + freshness tests
/// and for proving a real bundle does **not** spuriously verify against an
/// empty root. The richer real bundle lives under `tests/fixtures/`.
#[cfg(test)]
pub(crate) fn minimal_trusted_root_json() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
        "tlogs": [],
        "certificateAuthorities": [],
        "ctlogs": [],
        "timestampAuthorities": []
    }))
    .expect("serialize minimal trusted root")
}

/// The cached, offline-usable Sigstore trust root plus the bookkeeping
/// `health_check` needs to assert it is "loaded and within its refresh
/// window" **without** probing live Rekor/Fulcio.
#[derive(Clone, Debug)]
pub struct CachedTrustRoot {
    /// The raw `trusted_root.json` bytes. `Arc` so the adapter clones the
    /// handle cheaply; a future refresh swaps a new one in. The verify
    /// path parses a fresh **owned** [`SigstoreTrustRoot`] from these bytes
    /// per call (`sigstore::Verifier::new` consumes its `TrustRoot` by
    /// value and the root is not `Clone`); the parse is offline + cheap.
    trusted_root_json: Arc<Vec<u8>>,
    /// When this trust root was last (re)loaded — drives the staleness
    /// check. Set at construction; a refresh produces a new value.
    loaded_at: DateTime<Utc>,
    /// How long a loaded trust root stays "fresh" for `health_check`.
    refresh_window: Duration,
}

impl CachedTrustRoot {
    /// Build a cached trust root from a Sigstore `trusted_root.json`
    /// payload, fully **offline** (no network, no TUF metadata-chain
    /// fetch). The bytes are the standard TUF `trusted_root` target —
    /// produced either by a prior [`refresh_trusted_root_json`] fetch
    /// (production) or a committed fixture (tests).
    ///
    /// `loaded_at` is "now" and `refresh_window` defaults to
    /// [`DEFAULT_REFRESH_WINDOW_HOURS`].
    ///
    /// # Errors
    /// `DomainError::Invariant` if the payload is not a parseable
    /// `trusted_root.json` (`BundleMalformed`-shaped at the adapter
    /// boundary, but this is a *trust-root* load error, surfaced at
    /// construction / refresh, never on a per-verify path).
    pub fn from_trusted_root_json(data: &[u8]) -> DomainResult<Self> {
        Self::from_trusted_root_json_with_window(
            data,
            Duration::hours(DEFAULT_REFRESH_WINDOW_HOURS),
        )
    }

    /// As [`from_trusted_root_json`](Self::from_trusted_root_json) with an
    /// explicit refresh window (the composition root sets the deployed
    /// value; tests pin a deterministic one).
    pub fn from_trusted_root_json_with_window(
        data: &[u8],
        refresh_window: Duration,
    ) -> DomainResult<Self> {
        // Validate at construction so a bad payload fails the refresh /
        // boot path, never a per-verify call. The parsed root is dropped;
        // the verify path re-parses an owned one from the stored bytes.
        let _validated = parse_trusted_root(data)?;
        Ok(Self {
            trusted_root_json: Arc::new(data.to_vec()),
            loaded_at: Utc::now(),
            refresh_window,
        })
    }

    /// Parse a fresh **owned** [`SigstoreTrustRoot`] from the cached bytes
    /// for one offline verification. Cheap (in-memory JSON parse, no
    /// network). The payload was already validated at construction, so a
    /// parse error here is an internal invariant violation.
    pub(crate) fn build_sigstore_trust_root(&self) -> DomainResult<SigstoreTrustRoot> {
        parse_trusted_root(&self.trusted_root_json)
    }

    /// Whether the trust root is still within its refresh window relative
    /// to `now`. `health_check` consults this — a stale trust root means
    /// the worker must not boot a verifier.
    pub fn is_fresh_at(&self, now: DateTime<Utc>) -> bool {
        now.signed_duration_since(self.loaded_at) <= self.refresh_window
    }

    /// Convenience wrapper over [`is_fresh_at`](Self::is_fresh_at) at the
    /// wall clock now.
    pub fn is_fresh(&self) -> bool {
        self.is_fresh_at(Utc::now())
    }
}

/// Periodic TUF trust-root refresh — the **only** live HTTP in this
/// adapter (ADR 0027). Fetches the Sigstore `trusted_root.json` from
/// `trusted_root_url` over an **ADR 0010-compliant** client
/// (`reqwest::Client::builder()` + the vendored
/// [`extra_ca::apply_to_reqwest_builder`]; honours `HORT_EXTRA_CA_BUNDLE`,
/// no `Client::new()`, no `*_INSECURE_TLS`) and returns the bytes for
/// [`CachedTrustRoot::from_trusted_root_json`].
///
/// **Residual (ADR 0010 / TUF) — flagged, not silently claimed:** this
/// fetches the already-resolved `trusted_root.json` *target* over a
/// controlled TLS client; it does **not** perform the full TUF
/// metadata-chain signature verification (root → timestamp → snapshot →
/// targets) that `sigstore`'s built-in `SigstoreTrustRoot::new` does via
/// `tough`. That built-in path is deliberately avoided because it builds
/// its HTTP client with `reqwest::Client::new()` (the exact ADR 0010
/// anti-pattern) and cannot be handed our `apply_to_reqwest_builder`
/// client. The trade-off — controlled-TLS fetch of the resolved target vs.
/// full TUF-chain verification — is the documented residual; closing it
/// needs either an upstream `sigstore` API to inject the TUF HTTP client
/// or a `tough`-based fetch wired through `apply_to_reqwest_builder`. The
/// **verify path is unaffected and stays fully offline** regardless.
///
/// # Errors
/// `DomainError::Invariant` if the client cannot be built, the fetch
/// fails, or the response is a non-2xx / unreadable body. The error is
/// surfaced to the *refresh* caller; it never reaches a verify.
pub async fn refresh_trusted_root_json(
    trusted_root_url: &str,
    extra_ca_anchors: Option<&ExtraTrustAnchors>,
    request_timeout: std::time::Duration,
) -> DomainResult<Vec<u8>> {
    let builder = reqwest::Client::builder()
        .timeout(request_timeout)
        .user_agent(hort_config::DEFAULT_USER_AGENT);
    let builder = extra_ca::apply_to_reqwest_builder(builder, extra_ca_anchors)?;
    let client = builder.build().map_err(|e| {
        DomainError::Invariant(format!(
            "provenance-sigstore: failed to build trust-root refresh client: {e}"
        ))
    })?;

    let resp = client.get(trusted_root_url).send().await.map_err(|e| {
        DomainError::Invariant(format!(
            "provenance-sigstore: trust-root refresh fetch failed: {e}"
        ))
    })?;
    let resp = resp.error_for_status().map_err(|e| {
        DomainError::Invariant(format!(
            "provenance-sigstore: trust-root refresh returned error status: {e}"
        ))
    })?;
    let bytes = resp.bytes().await.map_err(|e| {
        DomainError::Invariant(format!(
            "provenance-sigstore: trust-root refresh body read failed: {e}"
        ))
    })?;
    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_trusted_root_json_parses_minimal_root() {
        let root = CachedTrustRoot::from_trusted_root_json(&minimal_trusted_root_json())
            .expect("minimal trusted root parses");
        // A freshly-loaded root is fresh.
        assert!(root.is_fresh());
    }

    #[test]
    fn from_trusted_root_json_rejects_garbage() {
        let err = CachedTrustRoot::from_trusted_root_json(b"not json at all")
            .expect_err("garbage must not parse");
        match err {
            DomainError::Invariant(msg) => {
                assert!(msg.contains("trust root JSON"), "msg: {msg}");
            }
            other => panic!("expected Invariant, got {other:?}"),
        }
    }

    #[test]
    fn freshly_loaded_root_is_fresh_stale_root_is_not() {
        let root = CachedTrustRoot::from_trusted_root_json_with_window(
            &minimal_trusted_root_json(),
            Duration::hours(1),
        )
        .expect("parse");

        let loaded = root.loaded_at;
        // Within the window → fresh.
        assert!(root.is_fresh_at(loaded + Duration::minutes(59)));
        // Exactly at the window boundary → still fresh (<=).
        assert!(root.is_fresh_at(loaded + Duration::hours(1)));
        // Past the window → stale.
        assert!(!root.is_fresh_at(loaded + Duration::hours(1) + Duration::seconds(1)));
    }

    #[test]
    fn cached_trust_root_clone_shares_inner() {
        let root =
            CachedTrustRoot::from_trusted_root_json(&minimal_trusted_root_json()).expect("parse");
        let cloned = root.clone();
        // Both observe the same loaded_at (cheap Arc clone, no reload).
        assert_eq!(root.loaded_at, cloned.loaded_at);
    }

    #[test]
    fn build_sigstore_trust_root_reparses_from_cached_bytes() {
        let root =
            CachedTrustRoot::from_trusted_root_json(&minimal_trusted_root_json()).expect("parse");
        // A fresh owned root is parseable from the cached bytes (offline).
        root.build_sigstore_trust_root()
            .expect("re-parse from cached bytes succeeds");
    }

    #[tokio::test]
    async fn refresh_trusted_root_json_fetches_over_controlled_client() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let body = minimal_trusted_root_json();
        Mock::given(method("GET"))
            .and(path("/trusted_root.json"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
            .mount(&server)
            .await;

        let url = format!("{}/trusted_root.json", server.uri());
        let fetched = refresh_trusted_root_json(&url, None, std::time::Duration::from_secs(5))
            .await
            .expect("refresh fetch succeeds");
        assert_eq!(fetched, body);
        // The fetched bytes build a CachedTrustRoot (end-to-end refresh →
        // load).
        CachedTrustRoot::from_trusted_root_json(&fetched).expect("loads");
    }

    #[tokio::test]
    async fn refresh_trusted_root_json_surfaces_http_error_status() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let url = format!("{}/trusted_root.json", server.uri());
        let err = refresh_trusted_root_json(&url, None, std::time::Duration::from_secs(5))
            .await
            .expect_err("503 must surface an error");
        match err {
            DomainError::Invariant(msg) => {
                assert!(msg.contains("error status"), "msg: {msg}");
            }
            other => panic!("expected Invariant, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn refresh_trusted_root_json_surfaces_connection_failure() {
        // An unroutable port → connection refused → fetch error.
        let err = refresh_trusted_root_json(
            "http://127.0.0.1:1/trusted_root.json",
            None,
            std::time::Duration::from_millis(500),
        )
        .await
        .expect_err("connection failure must surface an error");
        assert!(matches!(err, DomainError::Invariant(_)));
    }
}
