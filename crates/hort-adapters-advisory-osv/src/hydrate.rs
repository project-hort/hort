//! Full-record hydration for advisory ids returned by
//! `/v1/querybatch`.
//!
//! ## Why this exists
//!
//! `/v1/querybatch` answers "which advisories affect this package" and
//! nothing more: each `vulns[]` entry carries only `id` and `modified`.
//! It has no `severity[]` array, no `database_specific`, no
//! `affected[]`. Deriving a severity straight off that record therefore
//! finds nothing to derive from and lands on the fail-closed `Critical`
//! fallback for *every* advisory, with a NULL CVSS score — the CVSS
//! vector scorer never sees a vector and is inert.
//!
//! `GET /v1/vulns/{id}` returns the same record fully populated. This
//! module resolves each distinct id to that full record before severity
//! derivation runs, so the fail-closed `Critical` is reserved for
//! advisories that genuinely carry no score.
//!
//! ## Invariants
//!
//! - **One request per distinct `(id, modified)` pair per query**, not
//!   one per (component, advisory) pair. Several components sharing an
//!   advisory cost one fetch between them.
//! - **Cached on `(id, modified)`.** `modified` is the invalidation
//!   signal OSV itself hands back, so a record is re-fetched exactly
//!   when OSV changed it — see [`crate::cache::vuln_cache_key_hash`].
//! - **Fail soft.** Every failure mode (network, non-2xx, malformed
//!   body, unsafe id, cache error) degrades to "no hydrated record for
//!   this id", never to a failed scan. The caller then derives severity
//!   from the abbreviated record, which is exactly the pre-hydration
//!   behaviour. Degradation is visible on
//!   `hort_advisory_hydration_total{result="failed"}` rather than
//!   silent.
//! - **Fail closed on top of failing soft.** An unhydrated advisory is
//!   unscored and so still lands on `Critical`. Hydration removes
//!   *manufactured* unscored findings; it does not relax the rule that
//!   handles real ones.

use std::collections::BTreeMap;
use std::time::Duration;

use bytes::Bytes;

use hort_app::metrics::{emit_advisory_hydration, AdvisoryHydrationResult};
use hort_domain::ports::ephemeral_store::EphemeralStore;

use crate::cache::{build_vuln_cache_key, vuln_cache_key_hash};
use crate::osv_types::OsvVuln;

/// Identity of one advisory record as `querybatch` reports it. Owned
/// because the map outlives the borrow of the batch response.
pub(crate) type VulnKey = (String, Option<String>);

/// Hydrated records for one query, keyed by the `(id, modified)` pair
/// they were resolved from. An id absent from the map failed hydration
/// and must fall back to its abbreviated record.
pub(crate) type HydratedRecords = BTreeMap<VulnKey, OsvVuln>;

/// Everything the hydration pass needs from the adapter. Grouped into a
/// struct so the entry point keeps a two-argument signature rather than
/// six positional parameters.
pub(crate) struct HydrationContext<'a> {
    pub http: &'a reqwest::Client,
    /// Base URL of the single-record endpoint — the id is appended as a
    /// path segment. Configurable alongside the querybatch and bulk
    /// endpoints; never hardcoded at the call site.
    pub vulns_url: &'a str,
    pub cache: &'a dyn EphemeralStore,
    pub cache_ttl: Duration,
}

/// Resolve every distinct `(id, modified)` in `keys` to its full OSV
/// record.
///
/// Returns only the ids that resolved. Ids that failed are simply
/// absent — the caller treats absence as "use the abbreviated record",
/// which is the fail-soft contract.
pub(crate) async fn hydrate_records(
    ctx: &HydrationContext<'_>,
    keys: &[VulnKey],
) -> HydratedRecords {
    let mut out = HydratedRecords::new();
    for key in keys {
        // Requests are issued sequentially. OSV publishes no per-IP
        // concurrency budget we are tuning against, and a scan's
        // distinct-advisory count is small (single digits to low tens);
        // sequential keeps the failure accounting one-to-one with the
        // counter and avoids a burst against a third-party API.
        if let Some(record) = hydrate_one(ctx, &key.0, key.1.as_deref()).await {
            out.insert(key.clone(), record);
        }
    }
    out
}

/// Resolve one id, consulting the cache first. `None` means hydration
/// failed and the caller must fall back.
async fn hydrate_one(
    ctx: &HydrationContext<'_>,
    id: &str,
    modified: Option<&str>,
) -> Option<OsvVuln> {
    if let Some(cached) = cache_lookup(ctx, id, modified).await {
        emit_advisory_hydration(AdvisoryHydrationResult::CacheHit);
        return Some(cached);
    }

    let body = match fetch_record(ctx, id).await {
        Ok(body) => body,
        Err(reason) => {
            emit_advisory_hydration(AdvisoryHydrationResult::Failed);
            tracing::warn!(
                vulnerability_id = %id,
                reason = %reason,
                "osv adapter: advisory hydration failed; \
                 severity for this advisory falls back to the unscored fail-closed default"
            );
            return None;
        }
    };

    let record: OsvVuln = match serde_json::from_str(&body) {
        Ok(record) => record,
        Err(e) => {
            emit_advisory_hydration(AdvisoryHydrationResult::Failed);
            tracing::warn!(
                vulnerability_id = %id,
                error = %e,
                "osv adapter: advisory hydration returned a malformed record; \
                 severity for this advisory falls back to the unscored fail-closed default"
            );
            return None;
        }
    };

    cache_store(ctx, id, modified, &body).await;
    emit_advisory_hydration(AdvisoryHydrationResult::Fetched);
    Some(record)
}

/// Read a hydrated record out of the cache. Any error — transport,
/// corrupt entry — reads as a miss: the cache is evictable and
/// re-fetching is always the correct recovery.
async fn cache_lookup(
    ctx: &HydrationContext<'_>,
    id: &str,
    modified: Option<&str>,
) -> Option<OsvVuln> {
    let key = build_vuln_cache_key(id, modified);
    let bytes = match ctx.cache.get(&key).await {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return None,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "osv adapter: hydrated-record cache read failed; refetching"
            );
            return None;
        }
    };
    match serde_json::from_slice::<OsvVuln>(&bytes) {
        Ok(record) => Some(record),
        Err(e) => {
            tracing::warn!(
                error = %e,
                cache_key = %key,
                "osv adapter: dropping corrupted hydrated-record cache entry"
            );
            None
        }
    }
}

/// Cache the raw response body. Storing the body rather than a
/// re-serialised struct keeps the entry byte-identical to what OSV
/// served, so a later widening of [`OsvVuln`] reads fields out of
/// already-cached entries instead of needing a cache flush.
///
/// A write failure is logged and swallowed — the record is already in
/// hand for this scan, and the only cost is a re-fetch next time.
async fn cache_store(ctx: &HydrationContext<'_>, id: &str, modified: Option<&str>, body: &str) {
    // The literal prefix at the `put` call site is load-bearing for the
    // `ephemeral_keyspace_exhaustive` guard — it statically resolves the
    // registered keyspace from the `format!` in the same fn as the
    // `.put`. See `cache::vuln_cache_key_hash`'s rustdoc.
    let key = format!("advisory:osv:vuln:{}", vuln_cache_key_hash(id, modified));
    if let Err(e) = ctx
        .cache
        .put(&key, Bytes::from(body.as_bytes().to_vec()), ctx.cache_ttl)
        .await
    {
        tracing::warn!(
            error = %e,
            "osv adapter: hydrated-record cache write failed; record still used for this scan"
        );
    }
}

/// `GET {vulns_url}/{id}` → response body. `Err` carries a short reason
/// for the warn log; the caller turns it into a fail-soft skip.
async fn fetch_record(ctx: &HydrationContext<'_>, id: &str) -> Result<String, String> {
    let url = record_url(ctx.vulns_url, id)?;
    let resp = ctx
        .http
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("upstream returned status {status}"));
    }
    resp.text()
        .await
        .map_err(|e| format!("failed to read body: {e}"))
}

/// Build the single-record URL, rejecting any id that is not safe to
/// splice into a path.
///
/// OSV ids are drawn from `[A-Za-z0-9._-]` (`GHSA-…`, `RUSTSEC-…`,
/// `CVE-…`, `PYSEC-…`, `GO-…`). Refusing anything else keeps a `/` or
/// `?` in a malformed upstream payload from redirecting the request at
/// a different path or smuggling a query string, and costs nothing on
/// well-formed data.
fn record_url(base: &str, id: &str) -> Result<String, String> {
    if id.is_empty() {
        return Err("empty advisory id".to_string());
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err("advisory id contains characters unsafe for a URL path".to_string());
    }
    Ok(format!("{}/{}", base.trim_end_matches('/'), id))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use futures::future::FutureExt;
    use hort_domain::error::{DomainError, DomainResult};

    // -----------------------------------------------------------------------
    // A scriptable `EphemeralStore` — the cache-degradation branches are
    // unreachable through the in-memory store, which never errors and
    // never holds a corrupt entry.
    // -----------------------------------------------------------------------

    #[derive(Default)]
    struct ScriptedStore {
        /// What `get` returns: `Ok(None)` (miss), `Ok(Some(bytes))`, or
        /// `Err`.
        get_result: Option<DomainResult<Option<Bytes>>>,
        fail_put: bool,
        puts: Mutex<Vec<String>>,
    }

    impl ScriptedStore {
        fn miss() -> Self {
            Self::default()
        }
        fn returning(bytes: &[u8]) -> Self {
            Self {
                get_result: Some(Ok(Some(Bytes::from(bytes.to_vec())))),
                ..Self::default()
            }
        }
        fn erroring() -> Self {
            Self {
                get_result: Some(Err(DomainError::Invariant("redis down".into()))),
                ..Self::default()
            }
        }
        fn failing_put() -> Self {
            Self {
                fail_put: true,
                ..Self::default()
            }
        }
    }

    impl EphemeralStore for ScriptedStore {
        fn get(&self, _key: &str) -> futures::future::BoxFuture<'_, DomainResult<Option<Bytes>>> {
            let scripted = match &self.get_result {
                None => Ok(None),
                Some(Ok(v)) => Ok(v.clone()),
                Some(Err(e)) => Err(DomainError::Invariant(e.to_string())),
            };
            async move { scripted }.boxed()
        }

        fn put(
            &self,
            key: &str,
            _value: Bytes,
            _ttl: Duration,
        ) -> futures::future::BoxFuture<'_, DomainResult<()>> {
            self.puts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(key.to_string());
            let fail = self.fail_put;
            async move {
                if fail {
                    Err(DomainError::Invariant("redis write refused".into()))
                } else {
                    Ok(())
                }
            }
            .boxed()
        }

        fn put_if_absent(
            &self,
            _key: &str,
            _value: Bytes,
            _ttl: Duration,
        ) -> futures::future::BoxFuture<'_, DomainResult<bool>> {
            async { Ok(true) }.boxed()
        }

        fn compare_and_swap(
            &self,
            _key: &str,
            _expected_version: u64,
            _value: Bytes,
            _ttl: Duration,
        ) -> futures::future::BoxFuture<'_, DomainResult<Option<u64>>> {
            async { Ok(Some(1)) }.boxed()
        }

        fn delete(&self, _key: &str) -> futures::future::BoxFuture<'_, DomainResult<()>> {
            async { Ok(()) }.boxed()
        }

        fn try_increment_counter(
            &self,
            _key: &str,
            _limit: u64,
            _ttl: Duration,
        ) -> futures::future::BoxFuture<'_, DomainResult<Option<u64>>> {
            async { Ok(Some(1)) }.boxed()
        }

        fn extend_ttl(
            &self,
            _key: &str,
            _ttl: Duration,
        ) -> futures::future::BoxFuture<'_, DomainResult<()>> {
            async { Ok(()) }.boxed()
        }
    }

    /// A context whose HTTP client points nowhere reachable, so any
    /// fetch attempt fails fast. Tests that expect a cache hit assert on
    /// the returned record; tests that expect a cache miss assert on the
    /// fetch failure.
    fn ctx_for<'a>(store: &'a ScriptedStore, http: &'a reqwest::Client) -> HydrationContext<'a> {
        HydrationContext {
            http,
            // Port 1 refuses immediately — no network, no wait.
            vulns_url: "http://127.0.0.1:1/v1/vulns",
            cache: store,
            cache_ttl: Duration::from_secs(60),
        }
    }

    fn unreachable_client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("client")
    }

    #[tokio::test]
    async fn cached_record_is_returned_without_a_fetch() {
        let store = ScriptedStore::returning(br#"{"id":"GHSA-x","summary":"cached"}"#);
        let http = unreachable_client();
        let ctx = ctx_for(&store, &http);

        let got = hydrate_records(&ctx, &[("GHSA-x".to_string(), Some("m1".to_string()))]).await;

        let record = got
            .get(&("GHSA-x".to_string(), Some("m1".to_string())))
            .expect("cache hit resolves without touching the unreachable endpoint");
        assert_eq!(record.summary.as_deref(), Some("cached"));
    }

    #[tokio::test]
    async fn cache_read_error_degrades_to_a_fetch_rather_than_failing() {
        let store = ScriptedStore::erroring();
        let http = unreachable_client();
        let ctx = ctx_for(&store, &http);

        // The fetch then fails too (nothing is listening), so the id is
        // simply absent — the point is that the cache error did not
        // short-circuit into an error return.
        let got = hydrate_records(&ctx, &[("GHSA-x".to_string(), None)]).await;
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn corrupt_cache_entry_is_dropped_rather_than_trusted() {
        let store = ScriptedStore::returning(b"not json at all");
        let http = unreachable_client();
        let ctx = ctx_for(&store, &http);

        let got = hydrate_records(&ctx, &[("GHSA-x".to_string(), None)]).await;
        assert!(
            got.is_empty(),
            "a corrupt entry must read as a miss, not as a record"
        );
    }

    #[tokio::test]
    async fn cache_miss_with_unreachable_endpoint_yields_no_record() {
        let store = ScriptedStore::miss();
        let http = unreachable_client();
        let ctx = ctx_for(&store, &http);

        let got = hydrate_records(&ctx, &[("GHSA-x".to_string(), None)]).await;
        assert!(got.is_empty());
        assert!(
            store
                .puts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty(),
            "nothing was fetched, so nothing may be cached"
        );
    }

    #[tokio::test]
    async fn unsafe_id_is_rejected_before_any_request_is_built() {
        let store = ScriptedStore::miss();
        let http = unreachable_client();
        let ctx = ctx_for(&store, &http);

        let got = hydrate_records(&ctx, &[("../../admin".to_string(), None)]).await;
        assert!(got.is_empty());
    }

    /// A cache write failure costs a re-fetch next time and nothing
    /// else — the record is already in hand for this query.
    #[tokio::test]
    async fn cache_write_failure_does_not_lose_the_fetched_record() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/v1/vulns/GHSA-x"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_string(r#"{"id":"GHSA-x","summary":"fetched"}"#)
                    .insert_header("content-type", "application/json"),
            )
            .mount(&server)
            .await;

        let store = ScriptedStore::failing_put();
        let http = unreachable_client();
        let vulns_url = format!("{}/v1/vulns", server.uri());
        let ctx = HydrationContext {
            http: &http,
            vulns_url: &vulns_url,
            cache: &store,
            cache_ttl: Duration::from_secs(60),
        };

        let got = hydrate_records(&ctx, &[("GHSA-x".to_string(), None)]).await;
        let record = got
            .get(&("GHSA-x".to_string(), None))
            .expect("record survives a failed cache write");
        assert_eq!(record.summary.as_deref(), Some("fetched"));

        let puts = store
            .puts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(puts.len(), 1);
        assert!(
            puts[0].starts_with("advisory:osv:vuln:"),
            "hydrated records live in the registered evictable keyspace: {}",
            puts[0]
        );
    }

    /// Non-2xx is a fail-soft skip, not an error return.
    #[tokio::test]
    async fn non_success_status_yields_no_record() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/v1/vulns/GHSA-gone"))
            .respond_with(wiremock::ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let store = ScriptedStore::miss();
        let http = unreachable_client();
        let vulns_url = format!("{}/v1/vulns", server.uri());
        let ctx = HydrationContext {
            http: &http,
            vulns_url: &vulns_url,
            cache: &store,
            cache_ttl: Duration::from_secs(60),
        };

        let got = hydrate_records(&ctx, &[("GHSA-gone".to_string(), None)]).await;
        assert!(got.is_empty());
    }

    // -----------------------------------------------------------------------
    // record_url — the id-shape guard
    // -----------------------------------------------------------------------

    #[test]
    fn record_url_appends_id_as_path_segment() {
        let url = record_url("https://api.osv.dev/v1/vulns", "RUSTSEC-2023-0071")
            .expect("well-formed id");
        assert_eq!(url, "https://api.osv.dev/v1/vulns/RUSTSEC-2023-0071");
    }

    #[test]
    fn record_url_tolerates_trailing_slash_on_base() {
        let url = record_url("https://api.osv.dev/v1/vulns/", "GHSA-xxxx").expect("well-formed id");
        assert_eq!(url, "https://api.osv.dev/v1/vulns/GHSA-xxxx");
    }

    #[test]
    fn record_url_accepts_the_full_osv_id_alphabet() {
        for id in [
            "GHSA-jfh8-c2jp-5v3q",
            "RUSTSEC-2023-0071",
            "CVE-2021-44228",
            "PYSEC-2022-42969",
            "GO-2022-0646",
            "OSV-2020-744",
            "a.b_c-1",
        ] {
            assert!(
                record_url("https://x/v1/vulns", id).is_ok(),
                "id `{id}` must be accepted"
            );
        }
    }

    #[test]
    fn record_url_rejects_empty_id() {
        let err = record_url("https://x/v1/vulns", "").expect_err("empty id must be rejected");
        assert!(err.contains("empty"), "{err}");
    }

    #[test]
    fn record_url_rejects_path_traversal_and_query_smuggling() {
        // A malformed upstream payload must not be able to steer the
        // request off the single-record endpoint.
        for bad in [
            "../../admin",
            "GHSA/../../x",
            "GHSA?x=1",
            "GHSA#frag",
            "a b",
        ] {
            let err = record_url("https://x/v1/vulns", bad)
                .expect_err("unsafe id `{bad}` must be rejected");
            assert!(err.contains("unsafe"), "{err}");
        }
    }
}
