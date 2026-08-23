//! OSV.dev `AdvisoryPort` adapter.
//!
//! `OsvAdvisoryAdapter` implements [`AdvisoryPort`](hort_domain::ports::advisory::AdvisoryPort)
//! against OSV.dev's `/v1/querybatch` endpoint, with a per-component
//! cache backed by the [`EphemeralStore`](hort_domain::ports::ephemeral_store::EphemeralStore)
//! port.
//!
//! `querybatch` answers only "which advisory ids affect this package" —
//! each entry it returns carries `id` and `modified` and nothing else.
//! Every id is therefore resolved to its full `/v1/vulns/{id}` record
//! before a `Finding` is built, so severity derivation sees the CVSS
//! vector; see [`hydrate`] for the caching, deduplication and fail-soft
//! rules of that pass.
//!
//! Cache entries are namespaced under the `advisory:osv:` keyspace
//! prefix and routed to the **evictable** Redis instance — losing the cache
//! forces a re-fetch from `api.osv.dev`, which is the correct fallback.
//! The `advisory:osv:` prefix is registered in
//! `hort_app::ephemeral_keyspace::KEYSPACE_REGISTRY` (see the
//! `ephemeral_keyspace_exhaustive` guard).

mod bulk;
mod cache;
mod ecosystem;
mod extra_ca;
mod hydrate;
pub(crate) mod ingest_metrics;
mod osv_types;
mod severity;

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::future::BoxFuture;
use futures::FutureExt;
use serde::{Deserialize, Serialize};

use hort_app::metrics::{
    emit_advisory_diff, emit_advisory_query, observe_advisory_diff_duration,
    AdvisoryDiffResult as AdvisoryDiffMetricResult, AdvisoryQueryResult,
};
use hort_config::ExtraTrustAnchors;
use hort_domain::entities::scan_policy::SeverityThreshold;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::advisory::{AdvisoryDiffResult, AdvisoryPort};
use hort_domain::ports::ephemeral_store::EphemeralStore;
use hort_domain::types::{
    collapse_alias_groups, is_informational_class, Ecosystem, Finding, SbomComponent, SeverityBasis,
};

use crate::bulk::{osv_label_to_ecosystem, pull_one_ecosystem, BulkFetchErrorKind};
use crate::ingest_metrics::emit_advisory_ingest_count;

use crate::cache::{build_cache_key, cache_key_hash};
use crate::ecosystem::osv_ecosystem_for;
use osv_types::{OsvBatchRequest, OsvBatchResponse, OsvPackage, OsvQuery, OsvVuln};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Static configuration for [`OsvAdvisoryAdapter`].
///
/// `Default` fills the v1 OSV endpoint, a one-hour cache TTL, a
/// 30-second per-request timeout, and the OSV-documented batch size of
/// 100. Callers override any field as needed; the composition root
/// builds this from `Config` envvars.
#[derive(Debug, Clone)]
pub struct OsvAdvisoryConfig {
    /// Full URL of the OSV `querybatch` endpoint. Default:
    /// `https://api.osv.dev/v1/querybatch`.
    pub osv_batch_url: String,
    /// Base URL of the OSV single-record endpoint. The advisory id is
    /// appended as a path segment (`<osv_vulns_url>/<id>`) to hydrate
    /// the full record behind each id `querybatch` returns. Default:
    /// `https://api.osv.dev/v1/vulns`.
    pub osv_vulns_url: String,
    /// TTL applied to every cache write. Default: 1 hour.
    pub cache_ttl: Duration,
    /// Per-HTTP-request timeout passed to `reqwest::ClientBuilder`.
    /// Default: 30 seconds.
    pub request_timeout: Duration,
    /// OSV batch chunk size. Default: 100 (the OSV documented limit).
    /// `None` falls back to the default.
    pub batch_size: Option<usize>,
    /// Base URL of the per-ecosystem `osv-vulnerabilities` archive
    /// host (the `pull_diff_since` bulk path). Each configured ecosystem
    /// is fetched from `<bulk_url>/<ECO>/all.zip`. Default:
    /// `https://osv-vulnerabilities.storage.googleapis.com`.
    pub bulk_url: String,
    /// Ecosystems the watch tick pulls per invocation. Each entry must
    /// match an OSV bulk-archive path segment verbatim (`"npm"`,
    /// `"PyPI"`, `"crates.io"`, `"Maven"`, `"Go"`, `"RubyGems"`,
    /// `"NuGet"`, `"Packagist"`, `"Hex"`, `"Pub"`, `"Conda"`).
    pub ecosystems: Vec<String>,
}

impl Default for OsvAdvisoryConfig {
    fn default() -> Self {
        Self {
            osv_batch_url: "https://api.osv.dev/v1/querybatch".to_string(),
            osv_vulns_url: "https://api.osv.dev/v1/vulns".to_string(),
            cache_ttl: Duration::from_secs(3600),
            request_timeout: Duration::from_secs(30),
            batch_size: None,
            bulk_url: "https://osv-vulnerabilities.storage.googleapis.com".to_string(),
            ecosystems: vec![
                "npm".to_string(),
                "PyPI".to_string(),
                "crates.io".to_string(),
                "Maven".to_string(),
                "Go".to_string(),
                "RubyGems".to_string(),
                "NuGet".to_string(),
                "Packagist".to_string(),
            ],
        }
    }
}

const DEFAULT_BATCH_SIZE: usize = 100;

// ---------------------------------------------------------------------------
// Cached payload shape
// ---------------------------------------------------------------------------

/// Wire shape of one cache entry — a JSON-serialised list of findings
/// for one (eco, name, version) triple. Empty list is a meaningful
/// answer ("we asked OSV, no advisories"). The blob is JSON rather
/// than `postcard` because the entries are short, the volume is
/// small, and JSON makes Redis-side debugging trivial.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedAdvisoryFindings {
    findings: Vec<Finding>,
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

/// Outbound adapter implementing [`AdvisoryPort`] against OSV.dev with
/// `EphemeralStore`-backed caching.
pub struct OsvAdvisoryAdapter {
    http: reqwest::Client,
    osv_batch_url: String,
    /// Base URL of the single-record endpoint used by the hydration
    /// pass. See [`OsvAdvisoryConfig::osv_vulns_url`].
    osv_vulns_url: String,
    cache: Arc<dyn EphemeralStore>,
    cache_ttl: Duration,
    batch_size: usize,
    /// Base URL for the bulk-diff path. Per-ecosystem archives live at
    /// `<bulk_url>/<ECO>/all.zip`.
    bulk_url: String,
    /// Configured ecosystems for the bulk-diff path. Pre-resolved into
    /// `(label, Ecosystem)` pairs at construction so the watch tick
    /// can iterate without repeating the lookup. Unrecognised labels
    /// from `OsvAdvisoryConfig` are dropped at construction with a
    /// `tracing::warn!` so the operator-visible error surface is at
    /// startup time, not on the first watch tick.
    bulk_ecosystems: Vec<(String, Ecosystem)>,
}

impl OsvAdvisoryAdapter {
    /// Construct an adapter from config + an `EphemeralStore` handle.
    ///
    /// `extra_ca_anchors` is forwarded to the local `apply_to_reqwest_builder`
    /// helper so corporate CA bundles configured via
    /// `HORT_EXTRA_CA_BUNDLE` are honoured here as for every other
    /// outbound TLS path. Every adapter that opens TLS must build via
    /// `reqwest::Client::builder()` (ADR 0010).
    pub fn new(
        config: OsvAdvisoryConfig,
        cache: Arc<dyn EphemeralStore>,
        extra_ca_anchors: Option<&ExtraTrustAnchors>,
    ) -> DomainResult<Self> {
        let builder = reqwest::Client::builder()
            .timeout(config.request_timeout)
            .user_agent(hort_config::DEFAULT_USER_AGENT);
        let builder = extra_ca::apply_to_reqwest_builder(builder, extra_ca_anchors)?;
        let http = builder.build().map_err(|e| {
            DomainError::Invariant(format!("osv adapter: failed to build HTTP client: {e}"))
        })?;

        // Pre-resolve configured ecosystem labels into `(label, Ecosystem)`
        // pairs. Drop unrecognised labels — operator-visible warning at
        // startup is preferable to a silent miss on the first watch tick.
        let mut bulk_ecosystems: Vec<(String, Ecosystem)> = Vec::new();
        for label in &config.ecosystems {
            match osv_label_to_ecosystem(label) {
                Some(eco) => bulk_ecosystems.push((label.clone(), eco)),
                None => tracing::warn!(
                    label = %label,
                    "osv adapter: dropping unsupported bulk ecosystem label"
                ),
            }
        }

        Ok(Self {
            http,
            osv_batch_url: config.osv_batch_url,
            osv_vulns_url: config.osv_vulns_url,
            cache,
            cache_ttl: config.cache_ttl,
            batch_size: config.batch_size.unwrap_or(DEFAULT_BATCH_SIZE),
            bulk_url: config.bulk_url,
            bulk_ecosystems,
        })
    }

    // -----------------------------------------------------------------------
    // Cache helpers — the SBOM-keyed routing logic.
    //
    // The cache stores per-component results: `cache[advisory:osv:hash(eco,
    // name, version)] = JSON([Finding, …])`. Empty lists are valid cached
    // answers ("we asked OSV, no findings").
    // -----------------------------------------------------------------------

    async fn cache_lookup(&self, key: &str) -> DomainResult<Option<Vec<Finding>>> {
        match self.cache.get(key).await? {
            None => Ok(None),
            Some(bytes) => {
                // A foreign / corrupted cache entry: drop and refetch
                // rather than fail. The cache is evictable; treating
                // the corrupt entry as a miss is the natural recovery.
                match serde_json::from_slice::<CachedAdvisoryFindings>(&bytes) {
                    Ok(parsed) => Ok(Some(parsed.findings)),
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            cache_key = %key,
                            "osv adapter: dropping corrupted cache entry"
                        );
                        Ok(None)
                    }
                }
            }
        }
    }

    async fn cache_store(
        &self,
        eco: &str,
        name: &str,
        version: Option<&str>,
        findings: &[Finding],
    ) -> DomainResult<()> {
        let payload = CachedAdvisoryFindings {
            findings: findings.to_vec(),
        };
        let bytes = serde_json::to_vec(&payload).map_err(|e| {
            DomainError::Invariant(format!("osv adapter: cache encode failed: {e}"))
        })?;
        // The literal prefix at the put call site is load-bearing for the
        // `ephemeral_keyspace_exhaustive` guard — it statically resolves
        // the registered keyspace from the `format!("advisory:osv:{}", …)`
        // in the same fn as the `.put`. See `cache::cache_key_hash`'s
        // rustdoc.
        let key = format!("advisory:osv:{}", cache_key_hash(eco, name, version));
        self.cache
            .put(&key, Bytes::from(bytes), self.cache_ttl)
            .await
    }

    // -----------------------------------------------------------------------
    // OSV batch HTTP call.
    // -----------------------------------------------------------------------

    async fn post_batch(&self, queries: Vec<OsvQuery>) -> DomainResult<OsvBatchResponse> {
        let req_body = OsvBatchRequest { queries };
        let resp = match self
            .http
            .post(&self.osv_batch_url)
            .json(&req_body)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                // Classify transport-layer failure into `timeout` vs
                // `network_error` for `hort_advisory_query_total`
                // (see `docs/metrics-catalog.md`).
                // `reqwest::Error::is_timeout` covers per-request
                // deadlines (the `OsvAdvisoryConfig::request_timeout`
                // budget); everything else (DNS, TCP, TLS) collapses to
                // `network_error`.
                let result = if e.is_timeout() {
                    AdvisoryQueryResult::Timeout
                } else {
                    AdvisoryQueryResult::NetworkError
                };
                emit_advisory_query(result);
                return Err(DomainError::Invariant(format!(
                    "osv adapter: batch request failed: {e}"
                )));
            }
        };

        if !resp.status().is_success() {
            let status = resp.status();
            // Classify HTTP error into `upstream_4xx` / `upstream_5xx`
            // so the operator can split client-side misuse (4xx) from
            // upstream-failure (5xx) on dashboards.
            let result = if status.is_server_error() {
                AdvisoryQueryResult::Upstream5xx
            } else {
                AdvisoryQueryResult::Upstream4xx
            };
            emit_advisory_query(result);
            return Err(DomainError::Invariant(format!(
                "osv adapter: batch request returned status {status}"
            )));
        }

        // Use `text()` then `from_str` so we control the error path —
        // a malformed response body surfaces as `DomainError::Validation`,
        // which is the contract the wiremock test pins.
        let body = resp.text().await.map_err(|e| {
            DomainError::Invariant(format!("osv adapter: failed to read batch body: {e}"))
        })?;

        let parsed: OsvBatchResponse = serde_json::from_str(&body).map_err(|e| {
            DomainError::Validation(format!("osv adapter: malformed batch response: {e}"))
        })?;
        Ok(parsed)
    }

    // -----------------------------------------------------------------------
    // Full-record hydration.
    // -----------------------------------------------------------------------

    /// Resolve every distinct `(id, modified)` across the whole batch
    /// result to its full `/v1/vulns/{id}` record.
    ///
    /// Deduplication happens here rather than inside the hydration
    /// module so the "one request per distinct id per query" bound is
    /// visible at the call site that owns the query. Twenty components
    /// sharing one transitive dependency's advisory cost one request,
    /// not twenty.
    async fn hydrate_batch_records(
        &self,
        fetched: &[(PreparedComponent<'_>, Vec<OsvVuln>)],
    ) -> hydrate::HydratedRecords {
        let mut distinct: Vec<hydrate::VulnKey> = Vec::new();
        for (_comp, vulns) in fetched {
            for v in vulns {
                if v.id.is_empty() {
                    // An id-less record cannot be hydrated and cannot
                    // be cached; it will fail `Finding::validate()`
                    // downstream regardless.
                    continue;
                }
                let key = (v.id.clone(), v.modified.clone());
                if !distinct.contains(&key) {
                    distinct.push(key);
                }
            }
        }
        if distinct.is_empty() {
            return hydrate::HydratedRecords::new();
        }
        let ctx = hydrate::HydrationContext {
            http: &self.http,
            vulns_url: &self.osv_vulns_url,
            cache: self.cache.as_ref(),
            cache_ttl: self.cache_ttl,
        };
        hydrate::hydrate_records(&ctx, &distinct).await
    }

    // -----------------------------------------------------------------------
    // OSV vuln → Finding conversion.
    // -----------------------------------------------------------------------

    fn vuln_to_finding(component: &PreparedComponent<'_>, vuln: OsvVuln) -> Finding {
        // One OSV record can describe several packages across several
        // ecosystems. A per-component finding must only read the
        // `affected[]` entries that belong to *its* package, or it
        // would report another package's fixed versions and another
        // package's informational class against this purl.
        let affected = affected_for_component(&vuln.id, component, &vuln.affected);

        // Informational discriminator: store the raw OSV
        // `database_specific.informational` value verbatim (the fact),
        // taking the vuln-level marker if present else the first
        // matching `affected[].database_specific.informational`. The
        // boolean interpretation and the severity routing derive from it
        // via the domain recognizer `is_informational_class` — a
        // recognised RustSec class (`unmaintained` / `unsound` /
        // `notice`) marks an informational advisory: a maintenance
        // signal published without a CVSS score by design, not a scored
        // vulnerability.
        //
        // Real RustSec OSV records carry this marker under
        // `affected[].database_specific.informational`, so the
        // affected-level read is the load-bearing one. The vuln-level
        // read is retained as belt-and-suspenders for any feed that
        // places the marker there. A record that reached here straight
        // off `/v1/querybatch` (hydration unavailable) has no
        // `affected[]` at all, so neither read finds anything and the
        // finding falls through to the SUP-4 fail-closed fallback below.
        let informational_class: Option<String> = vuln
            .database_specific
            .as_ref()
            .and_then(|ds| ds.informational.clone())
            .or_else(|| {
                affected.iter().find_map(|aff| {
                    aff.database_specific
                        .as_ref()
                        .and_then(|ds| ds.informational.clone())
                })
            });
        let informational = informational_class
            .as_deref()
            .is_some_and(is_informational_class);

        // Severity precedence: the computed CVSS v3.0/v3.1 base score of
        // any `severity[].score` vector that parses as a full Base Metric
        // Group (highest signal — a direct spec computation); else the
        // numeric or label string in `database_specific.severity`; else
        // fail-closed fallback to the HIGHEST tier `Critical` (SUP-4). A
        // vector the `cvss` crate cannot parse (CVSS v2/v4, Temporal
        // metrics mixed into the Base group, or the array simply absent —
        // `querybatch` does not always return one) contributes nothing and
        // the mapper falls through to `database_specific`. A finding whose
        // severity we cannot determine must still block under the default
        // Critical threshold rather than slip under it — unified with the
        // scanner-osv and trivy adapters.
        //
        // An informational advisory carries no score by design and rides
        // the non-enforcing negligible lane (keyed on
        // `Finding::is_informational`, not on `severity`). Its `severity` is
        // cosmetic, so map it to the lowest tier rather than the SUP-4
        // Critical fail-closed fallback.
        let cvss_score = vuln
            .severity
            .iter()
            .filter_map(|sv| sv.score.as_deref())
            .find_map(severity::cvss_vector_base_score);
        // The severity we could actually *read*. `None` means no reading
        // was possible at all, so the `Critical` below is a floor rather
        // than an assessment — `severity_basis` records which, so the
        // cross-backend merge can prefer a better-informed sibling for the
        // same advisory (ADR 0059).
        let assessed_severity = cvss_score
            .and_then(severity::cvss_score_to_severity)
            .or_else(|| {
                vuln.database_specific
                    .as_ref()
                    .and_then(|ds| ds.severity.as_deref())
                    .and_then(severity::label_to_severity)
            })
            .or(if informational {
                Some(SeverityThreshold::Low)
            } else {
                None
            });
        let severity = assessed_severity.unwrap_or(SeverityThreshold::Critical);
        let severity_basis = match assessed_severity {
            Some(_) => SeverityBasis::Assessed,
            None => SeverityBasis::Unassessed,
        };

        // Title: prefer the one-line summary; else the long-form
        // details; else the vuln id (so the field is never empty).
        let title = vuln
            .summary
            .clone()
            .or_else(|| vuln.details.clone())
            .unwrap_or_else(|| vuln.id.clone());

        let mut fixed_versions: Vec<String> = affected
            .iter()
            .flat_map(|a| a.ranges.iter())
            .flat_map(|r| r.events.iter())
            .filter_map(|e| e.fixed.clone())
            .collect();
        // Cap to MAX_FIXED_VERSIONS (32). Out-of-spec records get
        // truncated; `Finding::validate()` would reject anyway, so
        // truncate proactively to keep the per-finding blob bounded.
        fixed_versions.truncate(32);

        // references: deduped URL list from `references[].url`, plus any
        // CVE-shaped aliases (so operators see the CVE id even when the
        // primary id is GHSA), plus the canonical OSV vulnerability page.
        // Cap at 32 — the canonical page is reserved a slot at the end.
        //
        // Parity with the scanner adapter at
        // `crates/hort-adapters-scanner-osv/src/parse.rs:301..336`. The two
        // `OsvVuln` types are crate-private with different field
        // surfaces, so the block is duplicated rather than extracted —
        // extraction would force a public alias-handling type. Keep the
        // two blocks structurally identical; if you change one, change
        // the other and update both cross-reference comments.
        let mut references: Vec<String> = Vec::new();
        for r in &vuln.references {
            if !r.url.is_empty() && !references.contains(&r.url) {
                references.push(r.url.clone());
                if references.len() >= 31 {
                    // leave room for the canonical OSV page
                    break;
                }
            }
        }
        for alias in &vuln.aliases {
            // OSV publishes CVE / GHSA / OSV ids as aliases. Surface them as
            // human-readable URLs where possible — the NVD entry for CVEs,
            // the OSV page for everything else. Cheap and pure (no I/O).
            let alias_url = if alias.starts_with("CVE-") {
                format!("https://nvd.nist.gov/vuln/detail/{alias}")
            } else {
                format!("https://osv.dev/vulnerability/{alias}")
            };
            if !references.contains(&alias_url) {
                references.push(alias_url);
                if references.len() >= 31 {
                    break;
                }
            }
        }
        if !vuln.id.is_empty() {
            let osv_page = format!("https://osv.dev/vulnerability/{}", vuln.id);
            if !references.iter().any(|r| r == &osv_page) {
                // If we still have room, append; otherwise replace the last.
                if references.len() >= 32 {
                    references.pop();
                }
                references.push(osv_page);
            }
        }

        // aliases: dedup-trimmed copy of `vuln.aliases`. Parity with
        // the scanner adapter at
        // `crates/hort-adapters-scanner-osv/src/parse.rs` — OSV primaries
        // on GHSA / OSV-* with the CVE in `aliases`; the exclusion matcher
        // checks both so a CVE-keyed exclusion clears a GHSA-keyed finding.
        // Same case-insensitive dedup + hard cap as the scanner adapter.
        let mut aliases: Vec<String> = Vec::new();
        for a in &vuln.aliases {
            let trimmed = a.trim();
            if trimmed.is_empty() {
                continue;
            }
            if aliases.iter().any(|x| x.eq_ignore_ascii_case(trimmed)) {
                continue;
            }
            aliases.push(trimmed.to_string());
            if aliases.len() >= 16 {
                break;
            }
        }

        Finding {
            purl: component.purl.to_string(),
            vulnerability_id: vuln.id,
            severity,
            cvss_score,
            title,
            fixed_versions,
            source_scanner: "osv".to_string(),
            references,
            aliases,
            informational_class,
            severity_basis,
        }
    }
}

// ---------------------------------------------------------------------------
// AdvisoryPort impl
// ---------------------------------------------------------------------------

impl AdvisoryPort for OsvAdvisoryAdapter {
    fn query<'a>(
        &'a self,
        components: &'a [SbomComponent],
    ) -> BoxFuture<'a, DomainResult<Vec<Finding>>> {
        async move {
            // Materialise the prepared component list — those whose
            // ecosystem OSV covers and whose name is non-empty. The
            // `index` field is the position in `components` so the
            // batch-response ordering can be reconciled.
            let prepared = prepare_components(components);

            if prepared.is_empty() {
                return Ok(Vec::new());
            }

            // Per-component cache lookup. Misses go into `to_fetch`
            // alongside their cache key (so we can write back after
            // the batch returns).
            let mut findings: Vec<Finding> = Vec::new();
            let mut to_fetch: Vec<(PreparedComponent<'a>, String)> = Vec::new();

            for comp in &prepared {
                let key = build_cache_key(comp.osv_eco, comp.name, comp.version);
                match self.cache_lookup(&key).await? {
                    Some(cached) => {
                        // `hort_advisory_query_total{result=cache_hit}`
                        // ticks once per component short-circuited on
                        // the EphemeralStore cache. Distinct from
                        // `cache_miss` so the operator can see the
                        // hit-rate split independently of upstream
                        // health.
                        emit_advisory_query(AdvisoryQueryResult::CacheHit);
                        findings.extend(cached);
                    }
                    None => {
                        // `hort_advisory_query_total{result=cache_miss}`
                        // ticks once per missed component, fired BEFORE
                        // the upstream call regardless of the upstream's
                        // eventual outcome. The upstream tick (success
                        // attribution to cache_miss; failure to one of
                        // upstream_4xx / upstream_5xx / network_error /
                        // timeout) lands later — together they form
                        // the cache → upstream funnel.
                        emit_advisory_query(AdvisoryQueryResult::CacheMiss);
                        to_fetch.push((comp.clone(), key));
                    }
                }
            }

            // No misses → all answers came from cache. Collapse anyway:
            // entries written before alias-group collapsing shipped hold
            // one finding per mirror record, and they stay readable until
            // the cache TTL expires them.
            if to_fetch.is_empty() {
                return Ok(collapse_alias_groups(findings));
            }

            // Chunk misses into `batch_size` batches and POST each. The
            // batches run sequentially; OSV imposes a per-batch limit
            // but no documented per-IP concurrency limit we are
            // tuning against.
            //
            // The abbreviated records are collected across ALL batches
            // before anything is converted to a `Finding`, because the
            // hydration pass that follows must issue one request per
            // distinct advisory id for the whole query. Hydrating
            // per-batch would re-fetch an advisory that spans a chunk
            // boundary, and hydrating per-component would re-fetch it
            // once per component that shares it.
            let mut fetched: Vec<(PreparedComponent<'a>, Vec<OsvVuln>)> =
                Vec::with_capacity(to_fetch.len());
            for chunk in to_fetch.chunks(self.batch_size) {
                let queries: Vec<OsvQuery> = chunk
                    .iter()
                    .map(|(comp, _key)| OsvQuery {
                        package: OsvPackage {
                            name: comp.name.to_string(),
                            ecosystem: comp.osv_eco.to_string(),
                        },
                        version: comp.version.map(str::to_string),
                    })
                    .collect();

                let response = self.post_batch(queries).await?;
                let results = response.results;

                // OSV's `results[i]` corresponds to `queries[i]`. If
                // the response is shorter than the batch (the OSV API
                // docs say it shouldn't be, but we tolerate),
                // empty-pad missing entries so the index remains
                // valid.
                for (i, (comp, _key)) in chunk.iter().enumerate() {
                    let result_for_comp = results.get(i).cloned().unwrap_or_default();
                    fetched.push((comp.clone(), result_for_comp.vulns));
                }
            }

            // Replace each abbreviated record with its full
            // `/v1/vulns/{id}` record so severity derivation has a CVSS
            // vector to work from. Ids that fail to hydrate keep their
            // abbreviated record and stay unscored — hence Critical.
            let hydrated = self.hydrate_batch_records(&fetched).await;

            for (comp, vulns) in fetched {
                let comp_findings: Vec<Finding> = vulns
                    .into_iter()
                    .map(|v| {
                        let record = hydrated
                            .get(&(v.id.clone(), v.modified.clone()))
                            .cloned()
                            .unwrap_or(v);
                        Self::vuln_to_finding(&comp, record)
                    })
                    .collect();

                // Write the per-component result to the cache —
                // including the empty-vec case ("we asked, none").
                self.cache_store(comp.osv_eco, comp.name, comp.version, &comp_findings)
                    .await?;

                findings.extend(comp_findings);
            }

            // OSV returns a RustSec advisory and its GitHub-reviewed GHSA
            // mirror as separate records in the same response, and the
            // mirror frequently carries neither a severity nor an
            // informational marker — so it lowers to the SUP-4 fail-closed
            // `Critical` and would otherwise shadow the sibling that
            // actually carries the advisory's metadata. The cross-backend
            // merge cannot reconcile them: they have different advisory
            // ids. Collapse mutually-aliased findings to their
            // best-informed member here, once, over the whole result set
            // — cache hits included (ADR 0059).
            Ok(collapse_alias_groups(findings))
        }
        .boxed()
    }

    fn pull_diff_since<'a>(
        &'a self,
        since: chrono::DateTime<chrono::Utc>,
    ) -> BoxFuture<'a, DomainResult<AdvisoryDiffResult>> {
        async move {
            let mut entries: Vec<hort_domain::ports::advisory::AdvisoryEntry> = Vec::new();
            let mut all_ecosystems_ok = true;
            for (label, eco) in &self.bulk_ecosystems {
                // Bracket the per-ecosystem call for the
                // `hort_advisory_diff_duration_seconds{ecosystem}` histogram
                // and emit `hort_advisory_diff_processed_total{ecosystem,
                // result}` at this I/O boundary. Duration brackets exactly
                // the fetch + parse, mirroring the `observe_scan_duration`
                // shape.
                let started = std::time::Instant::now();
                let outcome =
                    pull_one_ecosystem(&self.http, &self.bulk_url, label, eco.clone(), since).await;
                observe_advisory_diff_duration(label, started.elapsed().as_secs_f64());
                match outcome {
                    Ok(mut got) => {
                        emit_advisory_diff(label, AdvisoryDiffMetricResult::Ok);
                        // Per-ecosystem advisory ingest count vs expected
                        // floor (NIS2 Art. 21(2)(f) efficacy). Uses bounded
                        // `category` label (not raw ecosystem string) to
                        // keep cardinality fixed.
                        emit_advisory_ingest_count(label, got.len() as u64);
                        tracing::info!(
                            ecosystem = %label,
                            new_advisories = got.len(),
                            "advisory diff processed"
                        );
                        entries.append(&mut got);
                    }
                    Err(e) => {
                        all_ecosystems_ok = false;
                        let result = match e.kind {
                            BulkFetchErrorKind::FetchError => AdvisoryDiffMetricResult::FetchError,
                            BulkFetchErrorKind::ParseError => AdvisoryDiffMetricResult::ParseError,
                            BulkFetchErrorKind::Timeout => AdvisoryDiffMetricResult::Timeout,
                        };
                        emit_advisory_diff(label, result);
                        tracing::warn!(
                            feed = "osv",
                            ecosystem = %label,
                            error = %e.message,
                            "advisory diff fetch failed; will retry next invocation"
                        );
                    }
                }
            }
            Ok(AdvisoryDiffResult {
                entries,
                all_ecosystems_ok,
            })
        }
        .boxed()
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// One component prepared for OSV — borrowed from the input slice with
/// the OSV ecosystem string already resolved. Built by
/// `prepare_components`. `Clone` is cheap (all fields are borrows or
/// `&str`).
#[derive(Debug, Clone)]
struct PreparedComponent<'a> {
    name: &'a str,
    version: Option<&'a str>,
    osv_eco: &'static str,
    purl: &'a str,
}

/// Select the `affected[]` entries of one OSV record that describe
/// `component`'s package.
///
/// A hydrated record covers every package the advisory touches — for a
/// cross-ecosystem GHSA that can be a dozen entries. Reading all of
/// them into a per-purl finding would attribute another package's
/// `fixed_versions` (and another package's informational class) to this
/// component.
///
/// The fallback keys on "cannot discriminate", not "did not match": every
/// entry is returned unfiltered only when *no* entry in `affected[]`
/// carries a `package` block at all (an abbreviated record with no
/// `affected[]`, or entries OSV omitted the field on). That keeps a
/// single-package record whose `package` field OSV omitted working
/// exactly as it did before, rather than silently losing its fixed
/// versions to an over-strict match.
///
/// When entries *do* carry `package` blocks and none of them match this
/// component, the empty selection is returned instead of falling back.
/// Every `package`-bearing entry is a discriminator OSV chose to publish;
/// trusting it when it discriminates cleanly against this component (and
/// only falling back when it can't discriminate at all) is what keeps a
/// foreign package's `informational` marker from silently suppressing a
/// real vulnerability on this component — losing that entry's remediation
/// advice is an acceptable cost, inheriting its informational class is not.
fn affected_for_component<'v>(
    vuln_id: &str,
    component: &PreparedComponent<'_>,
    affected: &'v [osv_types::OsvAffected],
) -> Vec<&'v osv_types::OsvAffected> {
    let matched: Vec<&osv_types::OsvAffected> = affected
        .iter()
        .filter(|aff| {
            let Some(pkg) = aff.package.as_ref() else {
                return false;
            };
            let name_matches = pkg
                .name
                .as_deref()
                // OSV normalises package names per ecosystem (PyPI
                // lowercases, for one) so the label it echoes back can
                // differ in case from the name in the SBOM.
                .is_some_and(|n| n.eq_ignore_ascii_case(component.name));
            let eco_matches = pkg.ecosystem.as_deref().is_some_and(|e| {
                // OSV qualifies some ecosystems with a release suffix
                // (`Debian:11`, `Alpine:v3.14`). None of the ecosystems
                // this adapter queries carry one, so compare on the
                // segment before the colon and stay correct either way.
                e.split(':').next().unwrap_or(e) == component.osv_eco
            });
            name_matches && eco_matches
        })
        .collect();

    if !matched.is_empty() {
        return matched;
    }

    let any_entry_names_a_package = affected.iter().any(|aff| aff.package.is_some());
    if any_entry_names_a_package {
        tracing::debug!(
            vuln_id = %vuln_id,
            component = %component.name,
            "osv adapter: affected[] entries name packages but none match this component"
        );
        Vec::new()
    } else {
        affected.iter().collect()
    }
}

/// Filter the input slice down to the components OSV can resolve and
/// project them into [`PreparedComponent`] in input order.
///
/// Components dropped:
/// - empty `name` (OSV rejects them);
/// - ecosystem not OSV-supported (`Helm`, `OciImage`, `Unknown`).
fn prepare_components(components: &[SbomComponent]) -> Vec<PreparedComponent<'_>> {
    let mut out = Vec::with_capacity(components.len());
    for comp in components {
        if comp.name.is_empty() {
            tracing::debug!(purl = %comp.purl, "osv adapter: skipping empty-name component");
            continue;
        }
        let Some(eco) = osv_ecosystem_for(&comp.ecosystem) else {
            tracing::debug!(
                purl = %comp.purl,
                ecosystem = ?comp.ecosystem,
                "osv adapter: skipping unsupported ecosystem"
            );
            continue;
        };
        out.push(PreparedComponent {
            name: comp.name.as_str(),
            version: comp.version.as_deref(),
            osv_eco: eco,
            purl: comp.purl.as_str(),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// Public re-exports
// ---------------------------------------------------------------------------

// Re-export adapter and config; everything else stays crate-private to
// preserve refactor latitude.
pub use crate::OsvAdvisoryAdapter as Adapter;

#[cfg(test)]
mod tests {
    use super::*;
    use hort_domain::types::Ecosystem;

    fn comp(name: &str, version: Option<&str>, eco: Ecosystem) -> SbomComponent {
        SbomComponent {
            purl: format!("pkg:test/{name}@{}", version.unwrap_or("none")),
            name: name.to_string(),
            version: version.map(str::to_string),
            ecosystem: eco,
            licenses: vec![],
            direct_dependency: false,
        }
    }

    #[test]
    fn prepare_components_keeps_supported_ecosystems_in_order() {
        let inputs = vec![
            comp("lodash", Some("4.17.20"), Ecosystem::Npm),
            comp("requests", Some("2.31.0"), Ecosystem::PyPI),
        ];
        let prepared = prepare_components(&inputs);
        assert_eq!(prepared.len(), 2);
        assert_eq!(prepared[0].name, "lodash");
        assert_eq!(prepared[0].osv_eco, "npm");
        assert_eq!(prepared[1].name, "requests");
        assert_eq!(prepared[1].osv_eco, "PyPI");
    }

    #[test]
    fn prepare_components_drops_unknown_ecosystem() {
        let inputs = vec![
            comp("foo", Some("1.0"), Ecosystem::Unknown("rare".into())),
            comp("bar", Some("1.0"), Ecosystem::Npm),
        ];
        let prepared = prepare_components(&inputs);
        assert_eq!(prepared.len(), 1);
        assert_eq!(prepared[0].name, "bar");
    }

    #[test]
    fn prepare_components_drops_helm_and_oci_image() {
        let inputs = vec![
            comp("chart", Some("1"), Ecosystem::Helm),
            comp("image", Some("1"), Ecosystem::OciImage),
        ];
        let prepared = prepare_components(&inputs);
        assert!(prepared.is_empty());
    }

    #[test]
    fn prepare_components_drops_empty_name() {
        let inputs = vec![comp("", Some("1.0"), Ecosystem::Npm)];
        let prepared = prepare_components(&inputs);
        assert!(prepared.is_empty());
    }

    #[test]
    fn vuln_to_finding_uses_database_specific_severity() {
        let prepared = PreparedComponent {
            name: "lodash",
            version: Some("4.17.20"),
            osv_eco: "npm",
            purl: "pkg:npm/lodash@4.17.20",
        };
        let vuln = OsvVuln {
            id: "GHSA-xxxx".to_string(),
            summary: Some("RCE in lodash".to_string()),
            database_specific: Some(osv_types::OsvDatabaseSpecific {
                severity: Some("HIGH".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let finding = OsvAdvisoryAdapter::vuln_to_finding(&prepared, vuln);
        assert_eq!(finding.severity, SeverityThreshold::High);
        assert_eq!(finding.vulnerability_id, "GHSA-xxxx");
        assert_eq!(finding.title, "RCE in lodash");
        assert_eq!(finding.purl, "pkg:npm/lodash@4.17.20");
        assert_eq!(finding.source_scanner, "osv");
        // Canonical OSV page is always present.
        assert!(finding
            .references
            .iter()
            .any(|r| r.contains("osv.dev/vulnerability/GHSA-xxxx")));
    }

    /// `/v1/querybatch` never returns a severity — the property that
    /// makes hydration load-bearing rather than an optimisation.
    ///
    /// The record below is the *complete* shape that endpoint returns
    /// for an advisory: an id and a `modified` timestamp. Run straight
    /// through the mapper it is unscored, and an unscored finding fails
    /// closed to `Critical` (SUP-4) with a NULL score. That is correct
    /// for a genuinely unscored advisory and wrong for every advisory
    /// OSV *did* score, which is why the ids from a querybatch response
    /// are hydrated to their full records before reaching this mapper.
    ///
    /// A future edit that adds a `severity` array or a
    /// `database_specific` block to this fixture is not a richer test —
    /// it is a test of a wire shape the endpoint does not send.
    #[test]
    fn querybatch_shaped_record_is_unscored_because_querybatch_carries_no_severity() {
        let prepared = PreparedComponent {
            name: "rsa",
            version: Some("0.9.6"),
            osv_eco: "crates.io",
            purl: "pkg:cargo/rsa@0.9.6",
        };
        let querybatch_record = OsvVuln {
            id: "RUSTSEC-2023-0071".to_string(),
            modified: Some("2026-04-25T06:45:06.122559Z".to_string()),
            ..Default::default()
        };
        assert!(
            querybatch_record.severity.is_empty()
                && querybatch_record.database_specific.is_none()
                && querybatch_record.affected.is_empty(),
            "the querybatch wire shape has no severity signal of any kind"
        );

        let finding = OsvAdvisoryAdapter::vuln_to_finding(&prepared, querybatch_record);
        assert_eq!(finding.cvss_score, None);
        assert_eq!(finding.severity, SeverityThreshold::Critical);
    }

    #[test]
    fn vuln_to_finding_computes_marvin_vector_to_medium() {
        // Real `/v1/vulns/RUSTSEC-2023-0071` record (the Marvin
        // timing-oracle advisory on the `rsa` crate) — the HYDRATED
        // shape, verified against api.osv.dev. `querybatch` returns none
        // of this; see
        // `querybatch_shaped_record_is_unscored_because_querybatch_carries_no_severity`
        // for the shape that endpoint actually sends. There is no
        // `database_specific.severity` here, only the CVSS vector, so
        // the base score (5.9) must be computed from it, banding to
        // Medium.
        let prepared = PreparedComponent {
            name: "rsa",
            version: Some("0.9.6"),
            osv_eco: "crates.io",
            purl: "pkg:cargo/rsa@0.9.6",
        };
        let vuln = OsvVuln {
            id: "RUSTSEC-2023-0071".to_string(),
            severity: vec![osv_types::OsvSeverity {
                score: Some("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N".to_string()),
                kind: Some("CVSS_V3".to_string()),
            }],
            ..Default::default()
        };
        let finding = OsvAdvisoryAdapter::vuln_to_finding(&prepared, vuln);
        assert_eq!(finding.cvss_score, Some(5.9));
        assert_eq!(finding.severity, SeverityThreshold::Medium);
    }

    #[test]
    fn vuln_to_finding_cvss_vector_bands_boundaries() {
        let prepared = PreparedComponent {
            name: "x",
            version: Some("1"),
            osv_eco: "npm",
            purl: "pkg:npm/x@1",
        };

        let critical_vuln = OsvVuln {
            id: "OSV-C".to_string(),
            severity: vec![osv_types::OsvSeverity {
                score: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H".to_string()),
                kind: Some("CVSS_V3".to_string()),
            }],
            ..Default::default()
        };
        let f = OsvAdvisoryAdapter::vuln_to_finding(&prepared, critical_vuln);
        assert_eq!(f.cvss_score, Some(10.0));
        assert_eq!(f.severity, SeverityThreshold::Critical);

        let low_vuln = OsvVuln {
            id: "OSV-L".to_string(),
            severity: vec![osv_types::OsvSeverity {
                score: Some("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N".to_string()),
                kind: Some("CVSS_V3".to_string()),
            }],
            ..Default::default()
        };
        let f = OsvAdvisoryAdapter::vuln_to_finding(&prepared, low_vuln);
        assert_eq!(f.cvss_score, Some(1.8));
        assert_eq!(f.severity, SeverityThreshold::Low);
    }

    #[test]
    fn vuln_to_finding_prefers_cvss_vector_over_database_specific_label() {
        // The computed vector score is the highest-signal source: it must
        // win over a (deliberately contradictory) `database_specific`
        // label.
        let prepared = PreparedComponent {
            name: "x",
            version: Some("1"),
            osv_eco: "npm",
            purl: "pkg:npm/x@1",
        };
        let vuln = OsvVuln {
            id: "OSV-1".to_string(),
            severity: vec![osv_types::OsvSeverity {
                score: Some("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N".to_string()),
                kind: Some("CVSS_V3".to_string()),
            }],
            database_specific: Some(osv_types::OsvDatabaseSpecific {
                severity: Some("CRITICAL".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let finding = OsvAdvisoryAdapter::vuln_to_finding(&prepared, vuln);
        assert_eq!(finding.cvss_score, Some(5.9));
        assert_eq!(finding.severity, SeverityThreshold::Medium);
    }

    #[test]
    fn vuln_to_finding_falls_back_to_label_when_vector_unparseable() {
        // A vector the `cvss` crate cannot parse as a Base Metric Group
        // (here: malformed) contributes nothing; the mapper falls through
        // to `database_specific.severity`.
        let prepared = PreparedComponent {
            name: "x",
            version: Some("1"),
            osv_eco: "npm",
            purl: "pkg:npm/x@1",
        };
        let vuln = OsvVuln {
            id: "OSV-1".to_string(),
            severity: vec![osv_types::OsvSeverity {
                score: Some("CVSS:3.1/GARBAGE".to_string()),
                kind: Some("CVSS_V3".to_string()),
            }],
            database_specific: Some(osv_types::OsvDatabaseSpecific {
                severity: Some("HIGH".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let finding = OsvAdvisoryAdapter::vuln_to_finding(&prepared, vuln);
        assert_eq!(finding.cvss_score, None);
        assert_eq!(finding.severity, SeverityThreshold::High);
    }

    #[test]
    fn vuln_to_finding_malformed_vector_and_no_label_still_critical_fail_closed() {
        // SUP-4 pinned alongside the pre-existing fail-closed test: a
        // malformed CVSS vector with no `database_specific.severity` to
        // fall back to must still fail CLOSED to Critical, not silently
        // read as "unscored" in a way that could be mistaken for a lower
        // tier.
        let prepared = PreparedComponent {
            name: "x",
            version: Some("1"),
            osv_eco: "npm",
            purl: "pkg:npm/x@1",
        };
        let vuln = OsvVuln {
            id: "OSV-1".to_string(),
            severity: vec![osv_types::OsvSeverity {
                score: Some("CVSS:3.1/GARBAGE".to_string()),
                kind: Some("CVSS_V3".to_string()),
            }],
            ..Default::default()
        };
        let finding = OsvAdvisoryAdapter::vuln_to_finding(&prepared, vuln);
        assert_eq!(finding.cvss_score, None);
        assert_eq!(finding.severity, SeverityThreshold::Critical);
    }

    #[test]
    fn vuln_to_finding_falls_back_to_critical_when_severity_absent_fail_closed() {
        // SUP-4: a finding whose severity cannot be determined fails
        // CLOSED to the highest tier (`Critical`) so it still trips the
        // default Critical block threshold rather than slipping under it.
        let prepared = PreparedComponent {
            name: "x",
            version: Some("1"),
            osv_eco: "npm",
            purl: "pkg:npm/x@1",
        };
        let vuln = OsvVuln {
            id: "OSV-1".to_string(),
            ..Default::default()
        };
        let finding = OsvAdvisoryAdapter::vuln_to_finding(&prepared, vuln);
        assert_eq!(finding.severity, SeverityThreshold::Critical);
        // Title falls back to the vuln id when summary/details are absent.
        assert_eq!(finding.title, "OSV-1");
    }

    #[test]
    fn vuln_to_finding_informational_marker_stores_class_and_skips_critical_fallback() {
        // A vuln-level `database_specific.informational` naming a recognised
        // RustSec class is stored verbatim as `informational_class`;
        // `is_informational()` derives true and its cosmetic severity maps to
        // Low rather than the SUP-4 Critical fail-closed fallback — the
        // finding rides the non-enforcing negligible lane.
        let prepared = PreparedComponent {
            name: "proc-macro-error2",
            version: Some("2.0.1"),
            osv_eco: "crates.io",
            purl: "pkg:cargo/proc-macro-error2@2.0.1",
        };
        let vuln = OsvVuln {
            id: "RUSTSEC-2026-0173".to_string(),
            database_specific: Some(osv_types::OsvDatabaseSpecific {
                informational: Some("unmaintained".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let finding = OsvAdvisoryAdapter::vuln_to_finding(&prepared, vuln);
        assert_eq!(finding.informational_class.as_deref(), Some("unmaintained"));
        assert!(finding.is_informational());
        assert_eq!(finding.severity, SeverityThreshold::Low);
    }

    #[test]
    fn vuln_to_finding_affected_level_informational_marker_stores_class_and_skips_critical_fallback(
    ) {
        // Real RustSec OSV records place `informational` under
        // `affected[].database_specific.informational`, NOT at the
        // vulnerability level. Such a record (no CVSS) must lower to a
        // finding whose `informational_class` is the raw value, with a
        // non-Critical (Low) severity, riding the non-enforcing negligible
        // lane rather than the SUP-4 Critical fail-closed fallback. See
        // `crates/hort-adapters-scanner-osv/tests/fixtures/informational_unmaintained.json`.
        let prepared = PreparedComponent {
            name: "proc-macro-error2",
            version: Some("2.0.1"),
            osv_eco: "crates.io",
            purl: "pkg:cargo/proc-macro-error2@2.0.1",
        };
        let vuln = OsvVuln {
            id: "RUSTSEC-2026-0173".to_string(),
            affected: vec![osv_types::OsvAffected {
                database_specific: Some(osv_types::OsvDatabaseSpecific {
                    informational: Some("unmaintained".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        let finding = OsvAdvisoryAdapter::vuln_to_finding(&prepared, vuln);
        assert_eq!(finding.informational_class.as_deref(), Some("unmaintained"));
        assert!(finding.is_informational());
        assert_ne!(finding.severity, SeverityThreshold::Critical);
        assert_eq!(finding.severity, SeverityThreshold::Low);
    }

    #[test]
    fn vuln_to_finding_unscored_non_informational_still_critical_fail_closed() {
        // ADR 0007 regression guard: an unscored finding whose
        // `database_specific.informational` is absent (or not a recognised
        // class) must still hit the SUP-4 Critical fail-closed fallback. Here
        // `database_specific` is present but carries only an unrecognised
        // informational value and no severity label — the raw value is stored
        // as a fact, but `is_informational()` is false.
        let prepared = PreparedComponent {
            name: "x",
            version: Some("1"),
            osv_eco: "npm",
            purl: "pkg:npm/x@1",
        };
        let vuln = OsvVuln {
            id: "OSV-1".to_string(),
            database_specific: Some(osv_types::OsvDatabaseSpecific {
                informational: Some("some-future-class".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let finding = OsvAdvisoryAdapter::vuln_to_finding(&prepared, vuln);
        assert_eq!(
            finding.informational_class.as_deref(),
            Some("some-future-class")
        );
        assert!(!finding.is_informational());
        assert_eq!(finding.severity, SeverityThreshold::Critical);
    }

    // -----------------------------------------------------------------------
    // affected_for_component — per-package attribution on hydrated records
    // -----------------------------------------------------------------------

    fn affected_with_package(eco: &str, name: &str, fixed: &str) -> osv_types::OsvAffected {
        osv_types::OsvAffected {
            package: Some(osv_types::OsvAffectedPackage {
                name: Some(name.to_string()),
                ecosystem: Some(eco.to_string()),
            }),
            ranges: vec![osv_types::OsvRange {
                events: vec![osv_types::OsvRangeEvent {
                    fixed: Some(fixed.to_string()),
                }],
            }],
            ..Default::default()
        }
    }

    fn npm_lodash() -> PreparedComponent<'static> {
        PreparedComponent {
            name: "lodash",
            version: Some("4.17.20"),
            osv_eco: "npm",
            purl: "pkg:npm/lodash@4.17.20",
        }
    }

    #[test]
    fn affected_for_component_selects_only_the_matching_package() {
        let affected = vec![
            affected_with_package("PyPI", "other", "9.9.9"),
            affected_with_package("npm", "lodash", "4.17.21"),
        ];
        let picked = affected_for_component("OSV-1", &npm_lodash(), &affected);
        assert_eq!(picked.len(), 1);
        assert_eq!(
            picked[0].ranges[0].events[0].fixed.as_deref(),
            Some("4.17.21")
        );
    }

    #[test]
    fn affected_for_component_matches_package_name_case_insensitively() {
        // OSV normalises PyPI names to lowercase; the SBOM may carry the
        // distribution's own casing.
        let component = PreparedComponent {
            name: "Flask",
            version: Some("2.0.0"),
            osv_eco: "PyPI",
            purl: "pkg:pypi/Flask@2.0.0",
        };
        let affected = vec![affected_with_package("PyPI", "flask", "2.0.1")];
        let picked = affected_for_component("OSV-1", &component, &affected);
        assert_eq!(picked.len(), 1);
    }

    #[test]
    fn affected_for_component_ignores_the_osv_ecosystem_release_suffix() {
        let affected = vec![affected_with_package("npm:2024", "lodash", "4.17.21")];
        let picked = affected_for_component("OSV-1", &npm_lodash(), &affected);
        assert_eq!(
            picked.len(),
            1,
            "a `:release` suffix must not defeat the match"
        );
    }

    #[test]
    fn affected_for_component_returns_nothing_when_entries_discriminate_and_none_match() {
        // Same name, wrong ecosystem: the entry carries a `package` block
        // and simply does not match, so the discrimination is trusted and
        // the selection stays empty rather than falling back to the
        // unfiltered list.
        let affected = vec![affected_with_package("PyPI", "lodash", "9.9.9")];
        let picked = affected_for_component("OSV-1", &npm_lodash(), &affected);
        assert!(
            picked.is_empty(),
            "an entry that discriminates and does not match must not fall back"
        );
    }

    #[test]
    fn affected_for_component_falls_back_when_no_entry_names_a_package() {
        // A record whose `affected[]` entries carry no `package` block
        // must keep working exactly as it did before per-package
        // attribution existed.
        let affected = vec![osv_types::OsvAffected {
            ranges: vec![osv_types::OsvRange {
                events: vec![osv_types::OsvRangeEvent {
                    fixed: Some("2.0.0".into()),
                }],
            }],
            ..Default::default()
        }];
        let picked = affected_for_component("OSV-1", &npm_lodash(), &affected);
        assert_eq!(picked.len(), 1);
    }

    #[test]
    fn affected_for_component_returns_empty_for_an_abbreviated_record() {
        // The `/v1/querybatch` shape: no `affected[]` at all.
        let picked = affected_for_component("OSV-1", &npm_lodash(), &[]);
        assert!(picked.is_empty());
    }

    #[test]
    fn vuln_to_finding_does_not_inherit_a_foreign_non_matching_entrys_informational_class() {
        // The regression the narrowed fallback closes: a record with a
        // non-matching entry carrying an informational class must not mark
        // this component's finding informational, because the entry names
        // a package and it isn't this one.
        let vuln = OsvVuln {
            id: "GHSA-foreign-informational".to_string(),
            affected: vec![osv_types::OsvAffected {
                package: Some(osv_types::OsvAffectedPackage {
                    name: Some("other".into()),
                    ecosystem: Some("PyPI".into()),
                }),
                database_specific: Some(osv_types::OsvDatabaseSpecific {
                    informational: Some("unmaintained".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        let finding = OsvAdvisoryAdapter::vuln_to_finding(&npm_lodash(), vuln);
        assert!(
            finding.informational_class.is_none(),
            "a non-matching entry's informational class must not leak onto this finding"
        );
    }

    #[test]
    fn vuln_to_finding_reads_the_informational_marker_of_the_matching_package() {
        // A multi-package record must not attribute another package's
        // informational class to this purl — that would route a real
        // vulnerability onto the non-enforcing negligible lane.
        let vuln = OsvVuln {
            id: "GHSA-multi".to_string(),
            affected: vec![
                osv_types::OsvAffected {
                    package: Some(osv_types::OsvAffectedPackage {
                        name: Some("other".into()),
                        ecosystem: Some("crates.io".into()),
                    }),
                    database_specific: Some(osv_types::OsvDatabaseSpecific {
                        informational: Some("unmaintained".to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                osv_types::OsvAffected {
                    package: Some(osv_types::OsvAffectedPackage {
                        name: Some("lodash".into()),
                        ecosystem: Some("npm".into()),
                    }),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let finding = OsvAdvisoryAdapter::vuln_to_finding(&npm_lodash(), vuln);
        assert!(
            finding.informational_class.is_none(),
            "the other package's informational class must not leak onto this finding"
        );
        assert_eq!(finding.severity, SeverityThreshold::Critical);
    }

    #[test]
    fn vuln_to_finding_extracts_fixed_versions_from_affected_ranges() {
        let prepared = PreparedComponent {
            name: "x",
            version: Some("1"),
            osv_eco: "npm",
            purl: "pkg:npm/x@1",
        };
        let vuln = OsvVuln {
            id: "OSV-2".into(),
            affected: vec![osv_types::OsvAffected {
                ranges: vec![osv_types::OsvRange {
                    events: vec![osv_types::OsvRangeEvent {
                        fixed: Some("2.0.0".into()),
                    }],
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        let finding = OsvAdvisoryAdapter::vuln_to_finding(&prepared, vuln);
        assert_eq!(finding.fixed_versions, vec!["2.0.0".to_string()]);
    }

    #[test]
    fn vuln_to_finding_surfaces_aliases_as_reference_urls() {
        // L5 parity test — the scanner adapter at
        // `crates/hort-adapters-scanner-osv/src/parse.rs:301..336` surfaces
        // `OsvVuln.aliases` as human-readable reference URLs (NVD for CVEs,
        // OSV for everything else). The advisory adapter must do the same so
        // operators see the CVE id when the primary record is a GHSA.
        let prepared = PreparedComponent {
            name: "lodash",
            version: Some("4.17.20"),
            osv_eco: "npm",
            purl: "pkg:npm/lodash@4.17.20",
        };
        let vuln = OsvVuln {
            id: "GHSA-zzzz-zzzz-zzzz".to_string(),
            aliases: vec![
                "CVE-2024-XXXX".to_string(),
                "GHSA-yyyy-yyyy-yyyy".to_string(),
            ],
            ..Default::default()
        };
        let finding = OsvAdvisoryAdapter::vuln_to_finding(&prepared, vuln);
        assert!(
            finding
                .references
                .iter()
                .any(|r| r == "https://nvd.nist.gov/vuln/detail/CVE-2024-XXXX"),
            "CVE alias must surface as NVD url, got {:?}",
            finding.references
        );
        assert!(
            finding
                .references
                .iter()
                .any(|r| r == "https://osv.dev/vulnerability/GHSA-yyyy-yyyy-yyyy"),
            "non-CVE alias must surface as OSV url, got {:?}",
            finding.references
        );
        // Canonical OSV page for the primary id is still present.
        assert!(
            finding
                .references
                .iter()
                .any(|r| r == "https://osv.dev/vulnerability/GHSA-zzzz-zzzz-zzzz"),
            "canonical OSV page must still be present, got {:?}",
            finding.references
        );
    }

    #[test]
    fn osv_advisory_config_default_uses_v1_querybatch_endpoint() {
        let cfg = OsvAdvisoryConfig::default();
        assert_eq!(cfg.osv_batch_url, "https://api.osv.dev/v1/querybatch");
        assert_eq!(cfg.osv_vulns_url, "https://api.osv.dev/v1/vulns");
        assert_eq!(cfg.cache_ttl, Duration::from_secs(3600));
        assert_eq!(cfg.request_timeout, Duration::from_secs(30));
        assert_eq!(cfg.batch_size, None);
    }

    /// `OsvAdvisoryConfig::default` ships the documented bulk-feed URL
    /// and the eight ecosystems the default config pins.
    #[test]
    fn osv_advisory_config_default_carries_bulk_url_and_default_ecosystems() {
        let cfg = OsvAdvisoryConfig::default();
        assert_eq!(
            cfg.bulk_url,
            "https://osv-vulnerabilities.storage.googleapis.com"
        );
        assert_eq!(
            cfg.ecosystems,
            vec![
                "npm",
                "PyPI",
                "crates.io",
                "Maven",
                "Go",
                "RubyGems",
                "NuGet",
                "Packagist",
            ]
        );
    }

    /// Constructor drops unsupported ecosystem labels (operator-visible
    /// warning at startup) instead of failing or silently passing them
    /// through to the watch tick where they'd 404 every fetch.
    #[tokio::test]
    async fn new_drops_unsupported_ecosystem_labels() {
        use hort_adapters_ephemeral_memory::InMemoryEphemeralStore;
        use std::sync::Arc;
        let cache: Arc<dyn EphemeralStore> = Arc::new(InMemoryEphemeralStore::new());
        let cfg = OsvAdvisoryConfig {
            ecosystems: vec!["npm".into(), "Helm".into(), "PyPI".into()],
            ..OsvAdvisoryConfig::default()
        };
        let adapter = OsvAdvisoryAdapter::new(cfg, cache, None).expect("constructor Ok");
        // Helm dropped — only npm + PyPI survive.
        assert_eq!(adapter.bulk_ecosystems.len(), 2);
        assert_eq!(adapter.bulk_ecosystems[0].0, "npm");
        assert_eq!(adapter.bulk_ecosystems[0].1, Ecosystem::Npm);
        assert_eq!(adapter.bulk_ecosystems[1].0, "PyPI");
        assert_eq!(adapter.bulk_ecosystems[1].1, Ecosystem::PyPI);
    }

    // -----------------------------------------------------------------------
    // pull_diff_since — per-ecosystem metric emission
    // -----------------------------------------------------------------------

    /// Build a minimal in-memory zip with the OSV bulk record shape so
    /// `pull_one_ecosystem` returns Ok and the adapter ticks
    /// `hort_advisory_diff_processed_total{ecosystem, result="ok"}`.
    fn build_minimal_npm_archive() -> Vec<u8> {
        let body = serde_json::json!({
            "id": "GHSA-test",
            "modified": "1970-01-01T00:33:20Z",
            "affected": [{
                "package": { "ecosystem": "npm", "name": "lodash" },
                "versions": ["4.17.20"]
            }]
        })
        .to_string();
        hort_formats::archive_bounds::build_zip_bytes(&[("GHSA-test.json", body.as_str())])
    }

    /// Happy path: per-ecosystem fetch succeeds → emit
    /// `hort_advisory_diff_processed_total{ecosystem="npm", result="ok"}`
    /// AND `hort_advisory_diff_duration_seconds{ecosystem="npm"}`.
    #[test]
    fn pull_diff_since_emits_ok_result_and_duration_for_each_ecosystem() {
        use hort_adapters_ephemeral_memory::InMemoryEphemeralStore;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use metrics_util::MetricKind;
        use std::sync::Arc;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let server = wiremock::MockServer::start().await;
                    wiremock::Mock::given(wiremock::matchers::method("GET"))
                        .and(wiremock::matchers::path("/npm/all.zip"))
                        .respond_with(
                            wiremock::ResponseTemplate::new(200)
                                .set_body_bytes(build_minimal_npm_archive())
                                .insert_header("content-type", "application/zip"),
                        )
                        .mount(&server)
                        .await;

                    let cache: Arc<dyn EphemeralStore> = Arc::new(InMemoryEphemeralStore::new());
                    let cfg = OsvAdvisoryConfig {
                        bulk_url: server.uri(),
                        ecosystems: vec!["npm".into()],
                        ..OsvAdvisoryConfig::default()
                    };
                    let adapter =
                        OsvAdvisoryAdapter::new(cfg, cache, None).expect("constructor Ok");

                    adapter
                        .pull_diff_since(chrono::Utc::now() - chrono::Duration::days(7))
                        .await
                        .expect("pull_diff_since Ok");
                });
        });

        let snap = snapshotter.snapshot().into_vec();

        // Counter.
        let counter = snap.iter().find(|(ck, _, _, _)| {
            ck.kind() == MetricKind::Counter
                && ck.key().name() == "hort_advisory_diff_processed_total"
                && ck
                    .key()
                    .labels()
                    .any(|l| l.key() == "ecosystem" && l.value() == "npm")
                && ck
                    .key()
                    .labels()
                    .any(|l| l.key() == "result" && l.value() == "ok")
        });
        let (key, _, _, value) =
            counter.expect("hort_advisory_diff_processed_total{npm, ok} must fire");
        match value {
            DebugValue::Counter(n) => assert_eq!(*n, 1),
            other => panic!("expected Counter, got {other:?}"),
        }
        for forbidden in &["artifact_id", "purl", "vulnerability_id", "package_name"] {
            assert!(
                !key.key().labels().any(|l| l.key() == *forbidden),
                "forbidden label `{forbidden}` must not appear",
            );
        }

        // Histogram.
        let histo = snap.iter().find(|(ck, _, _, _)| {
            ck.kind() == MetricKind::Histogram
                && ck.key().name() == "hort_advisory_diff_duration_seconds"
                && ck
                    .key()
                    .labels()
                    .any(|l| l.key() == "ecosystem" && l.value() == "npm")
        });
        let (_, _, _, hvalue) = histo.expect("duration histogram must fire");
        match hvalue {
            DebugValue::Histogram(samples) => {
                assert!(!samples.is_empty(), "at least one duration sample");
            }
            other => panic!("expected Histogram, got {other:?}"),
        }
    }

    /// Error variants: `fetch_error` for HTTP 5xx, `parse_error` for
    /// invalid zip body. Each ecosystem maps the per-ecosystem error
    /// kind to the corresponding `result` label exactly once.
    #[test]
    fn pull_diff_since_emits_fetch_error_on_500_and_parse_error_on_invalid_zip() {
        use hort_adapters_ephemeral_memory::InMemoryEphemeralStore;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use metrics_util::MetricKind;
        use std::sync::Arc;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let server = wiremock::MockServer::start().await;
                    // npm — HTTP 500 → fetch_error
                    wiremock::Mock::given(wiremock::matchers::method("GET"))
                        .and(wiremock::matchers::path("/npm/all.zip"))
                        .respond_with(wiremock::ResponseTemplate::new(500))
                        .mount(&server)
                        .await;
                    // PyPI — invalid zip → parse_error
                    wiremock::Mock::given(wiremock::matchers::method("GET"))
                        .and(wiremock::matchers::path("/PyPI/all.zip"))
                        .respond_with(
                            wiremock::ResponseTemplate::new(200)
                                .set_body_bytes(b"not-a-zip".to_vec()),
                        )
                        .mount(&server)
                        .await;

                    let cache: Arc<dyn EphemeralStore> = Arc::new(InMemoryEphemeralStore::new());
                    let cfg = OsvAdvisoryConfig {
                        bulk_url: server.uri(),
                        ecosystems: vec!["npm".into(), "PyPI".into()],
                        ..OsvAdvisoryConfig::default()
                    };
                    let adapter =
                        OsvAdvisoryAdapter::new(cfg, cache, None).expect("constructor Ok");

                    adapter
                        .pull_diff_since(chrono::Utc::now() - chrono::Duration::days(7))
                        .await
                        .expect("pull_diff_since itself returns Ok even on per-ecosystem failure");
                });
        });

        let snap = snapshotter.snapshot().into_vec();

        // npm → fetch_error
        let npm_err = snap.iter().find(|(ck, _, _, _)| {
            ck.kind() == MetricKind::Counter
                && ck.key().name() == "hort_advisory_diff_processed_total"
                && ck
                    .key()
                    .labels()
                    .any(|l| l.key() == "ecosystem" && l.value() == "npm")
                && ck
                    .key()
                    .labels()
                    .any(|l| l.key() == "result" && l.value() == "fetch_error")
        });
        let (_, _, _, v) = npm_err.expect("npm/fetch_error must fire");
        assert!(matches!(v, DebugValue::Counter(1)));

        // PyPI → parse_error
        let pypi_err = snap.iter().find(|(ck, _, _, _)| {
            ck.kind() == MetricKind::Counter
                && ck.key().name() == "hort_advisory_diff_processed_total"
                && ck
                    .key()
                    .labels()
                    .any(|l| l.key() == "ecosystem" && l.value() == "PyPI")
                && ck
                    .key()
                    .labels()
                    .any(|l| l.key() == "result" && l.value() == "parse_error")
        });
        let (_, _, _, v) = pypi_err.expect("PyPI/parse_error must fire");
        assert!(matches!(v, DebugValue::Counter(1)));
    }
}
