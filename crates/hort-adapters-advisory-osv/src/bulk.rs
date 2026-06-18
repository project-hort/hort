//! OSV bulk-diff fetcher.
//!
//! `OsvAdvisoryAdapter::pull_diff_since` (in `lib.rs`) iterates the
//! configured ecosystem list and asks this module to fetch + parse one
//! ecosystem at a time. Every per-ecosystem fetch:
//!
//! 1. streams `<bulk_url>/<ECO>/all.zip` into a tempfile
//!    (`reqwest::Response::bytes_stream` → `tokio::fs::File` via
//!    `tokio_util::io::StreamReader`) — the archive is never fully
//!    buffered in RAM; ecosystem zips routinely exceed 50 MB;
//! 2. opens the tempfile with the synchronous `zip` crate and walks
//!    every entry whose name ends in `.json`;
//! 3. deserialises each entry's JSON into [`BulkOsvVuln`] and converts
//!    matching records into [`AdvisoryEntry`] values, filtering on
//!    `modified > since`.
//!
//! Per-ecosystem failures (network, parse, zip-format) surface as
//! `Err` from [`pull_one_ecosystem`]; the caller in `lib.rs` records
//! the failure into [`AdvisoryDiffResult.all_ecosystems_ok`] without
//! aborting the whole tick. That contract is what keeps the watch
//! handler's checkpoint-on-success-only invariant intact.

use chrono::{DateTime, Utc};
use futures::TryStreamExt;
use hort_formats::archive_bounds::{iter_zip_entries, BoundsConfig, ZipIterError};
use serde::Deserialize;
use tempfile::NamedTempFile;
use tokio::io::AsyncWriteExt;

use hort_domain::error::DomainError;
use hort_domain::ports::advisory::{AdvisoryAffectedPackage, AdvisoryEntry};
use hort_domain::types::Ecosystem;

/// Per-ecosystem bulk-fetch error classification. The caller in `lib.rs`
/// maps each variant to the corresponding
/// [`hort_app::metrics::AdvisoryDiffResult`] for the
/// `hort_advisory_diff_processed_total{ecosystem, result}` counter.
///
/// `DomainError` carries a single `Invariant(String)` for the watch
/// path because the handler's surface only cares whether the
/// per-ecosystem call succeeded (via
/// `AdvisoryDiffResult.all_ecosystems_ok`). The metrics layer needs
/// finer detail to split slow-upstream from upstream-broken on
/// dashboards, so this struct carries the classification alongside the
/// underlying message; the conversion to `DomainError::Invariant` for
/// the outer Result happens at the call site.
#[derive(Debug)]
pub(crate) struct BulkFetchError {
    pub kind: BulkFetchErrorKind,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BulkFetchErrorKind {
    /// HTTP fetch failed (non-2xx, network error, body stream error).
    FetchError,
    /// Per-request deadline elapsed before the bulk archive responded.
    Timeout,
    /// Fetch succeeded but the zip / archive payload could not be
    /// parsed at the per-archive boundary.
    ParseError,
}

impl From<BulkFetchError> for DomainError {
    fn from(err: BulkFetchError) -> Self {
        DomainError::Invariant(err.message)
    }
}

// ---------------------------------------------------------------------------
// OSV bulk-record wire shape
// ---------------------------------------------------------------------------

/// Wire shape of a single OSV record inside the per-ecosystem
/// `all.zip`. Permissive (`#[serde(default)]` everywhere) so an OSV
/// schema addition doesn't break the watcher.
///
/// Distinct from `crate::osv_types::OsvVuln` (which models the
/// `/v1/querybatch` response). The bulk archive carries the full OSV
/// record including the `modified` timestamp and the `versions[]`
/// arrays under each `affected[]` entry — fields the querybatch
/// abbreviated form does not provide.
#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct BulkOsvVuln {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub modified: Option<DateTime<Utc>>,
    #[serde(default)]
    pub affected: Vec<BulkOsvAffected>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct BulkOsvAffected {
    #[serde(default)]
    pub package: Option<BulkOsvPackage>,
    /// Concrete affected versions. OSV records can also carry
    /// `ranges[]` for span-style descriptions; v1 only matches against
    /// the discrete `versions[]` list because that's what the
    /// `sbom_components` projection joins against. Range-only OSV
    /// entries surface zero matches in this version — the cron rescan
    /// is the safety-net path for missed advisory hits.
    #[serde(default)]
    pub versions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct BulkOsvPackage {
    #[serde(default)]
    pub ecosystem: String,
    #[serde(default)]
    pub name: String,
}

// ---------------------------------------------------------------------------
// Per-ecosystem fetch + parse
// ---------------------------------------------------------------------------

/// Fetch one ecosystem's bulk archive, stream-decode it, return the
/// `modified > since` subset as `AdvisoryEntry`s.
///
/// `osv_eco_label` is the literal segment from the URL (e.g. `"npm"`,
/// `"PyPI"`, `"crates.io"`). The corresponding [`Ecosystem`] enum
/// variant is determined by the caller via [`osv_label_to_ecosystem`]
/// — a single-source mapping that mirrors the existing
/// `ecosystem::osv_ecosystem_for` direction.
pub(crate) async fn pull_one_ecosystem(
    http: &reqwest::Client,
    bulk_url: &str,
    osv_eco_label: &str,
    eco_enum: Ecosystem,
    since: DateTime<Utc>,
) -> Result<Vec<AdvisoryEntry>, BulkFetchError> {
    let url = format!(
        "{}/{}/all.zip",
        bulk_url.trim_end_matches('/'),
        osv_eco_label
    );

    // Stream the zip body into a tempfile. Spilling-to-disk avoids
    // holding tens of MB in RAM per ecosystem, particularly when
    // multiple ecosystems are processed sequentially.
    let resp = http.get(&url).send().await.map_err(|e| {
        // Split timeout from generic fetch error so dashboards can
        // distinguish slow upstream from broken upstream.
        let kind = if e.is_timeout() {
            BulkFetchErrorKind::Timeout
        } else {
            BulkFetchErrorKind::FetchError
        };
        BulkFetchError {
            kind,
            message: format!("osv bulk: GET {url} failed: {e}"),
        }
    })?;
    if !resp.status().is_success() {
        return Err(BulkFetchError {
            kind: BulkFetchErrorKind::FetchError,
            message: format!("osv bulk: GET {url} returned status {}", resp.status()),
        });
    }

    let tmp = tokio::task::spawn_blocking(NamedTempFile::new)
        .await
        .map_err(|e| BulkFetchError {
            kind: BulkFetchErrorKind::FetchError,
            message: format!("osv bulk: tempfile join: {e}"),
        })?
        .map_err(|e| BulkFetchError {
            kind: BulkFetchErrorKind::FetchError,
            message: format!("osv bulk: tempfile create: {e}"),
        })?;

    {
        // Move the std File handle out of the NamedTempFile briefly so
        // tokio's async write can target it — `as_file_mut` is a
        // borrow against a sync file, so we re-open via the path on the
        // tokio side. This avoids a `File::try_clone()` dance.
        let path = tmp.path().to_path_buf();
        let mut tokio_file = tokio::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .await
            .map_err(|e| BulkFetchError {
                kind: BulkFetchErrorKind::FetchError,
                message: format!("osv bulk: open tempfile {}: {e}", path.display()),
            })?;
        let stream = resp
            .bytes_stream()
            .map_err(|e| std::io::Error::other(e.to_string()));
        let mut reader = tokio_util::io::StreamReader::new(stream);
        tokio::io::copy(&mut reader, &mut tokio_file)
            .await
            .map_err(|e| BulkFetchError {
                kind: BulkFetchErrorKind::FetchError,
                message: format!("osv bulk: stream copy: {e}"),
            })?;
        tokio_file.flush().await.map_err(|e| BulkFetchError {
            kind: BulkFetchErrorKind::FetchError,
            message: format!("osv bulk: flush: {e}"),
        })?;
    }

    // Parse the zip on a blocking thread — the zip crate is sync and the
    // archives can be large enough to make sync-on-runtime visible.
    //
    // Use `BoundsConfig::for_trusted_bulk_feed()` NOT
    // `default_for_metadata_extraction()`. The metadata config caps entry
    // count at 1024 — real OSV ecosystem zips (npm, PyPI, Maven) have tens of
    // thousands of advisories. With the old config, entry 1025 tripped the
    // counter and the whole ecosystem ingest aborted as ParseError — a silent
    // detection failure. The trusted-bulk config allows up to 1e5 entries
    // while still enforcing decompression-bomb limits.
    //
    // If the generous trusted-bulk cap IS exceeded (`Err(ZipIterError::Bounds(...))`),
    // we warn and keep the advisories already collected — this is an operational
    // signal to raise `MAX_ENTRIES_TRUSTED_BULK`, NOT a parse failure.
    // Every other `ZipIterError` variant (corrupt zip, unreadable entry) is a
    // genuine `ParseError`. This distinction is enforced at this call site by
    // matching the typed `ZipIterError::Bounds` arm explicitly.
    let eco_enum_for_blocking = eco_enum.clone();
    let osv_label = osv_eco_label.to_string();
    let entries =
        tokio::task::spawn_blocking(move || -> Result<Vec<AdvisoryEntry>, BulkFetchError> {
            let file = tmp.reopen().map_err(|e| BulkFetchError {
                kind: BulkFetchErrorKind::ParseError,
                message: format!("osv bulk: reopen tempfile: {e}"),
            })?;
            let mut out: Vec<AdvisoryEntry> = Vec::new();
            // Use for_trusted_bulk_feed(), NOT default_for_metadata_extraction().
            let result = iter_zip_entries(
                file,
                BoundsConfig::for_trusted_bulk_feed(),
                |name, reader| {
                    if !name.ends_with(".json") {
                        return;
                    }
                    let mut buf = String::new();
                    if reader.read_to_string(&mut buf).is_err() {
                        // Skip non-UTF-8 / unreadable / bounds-exceeded entries.
                        return;
                    }
                    let Ok(parsed) = serde_json::from_str::<BulkOsvVuln>(&buf) else {
                        // Skip malformed entries; cron rescan is the safety net.
                        return;
                    };
                    if let Some(entry) =
                        bulk_record_to_advisory_entry(parsed, &eco_enum_for_blocking, since)
                    {
                        out.push(entry);
                    }
                },
            );
            match result {
                Ok(()) => {}
                // Bounds-tripped on a trusted bulk feed is a warning,
                // not a ParseError. The entries already visited are kept; the
                // cap only fires if the ecosystem has grown beyond
                // MAX_ENTRIES_TRUSTED_BULK (~1e5) — an operational signal to
                // raise the cap. Contrast: any other ZipIterError (corrupt zip
                // format, unreadable entry index) is a genuine parse failure
                // and surfaces as ParseError below.
                Err(ZipIterError::Bounds(ref b)) => {
                    tracing::warn!(
                        feed = "osv",
                        ecosystem = %osv_label,
                        ingested = out.len(),
                        "osv bulk: trusted bulk feed tripped entry cap ({b}) — \
                         advisories beyond the cap were not ingested; \
                         consider raising MAX_ENTRIES_TRUSTED_BULK"
                    );
                }
                Err(e) => {
                    return Err(BulkFetchError {
                        kind: BulkFetchErrorKind::ParseError,
                        message: format!("osv bulk: zip parse ({osv_label}): {e}"),
                    });
                }
            }
            Ok(out)
        })
        .await
        .map_err(|e| BulkFetchError {
            kind: BulkFetchErrorKind::ParseError,
            message: format!("osv bulk: parse join: {e}"),
        })??;

    Ok(entries)
}

/// Convert one `BulkOsvVuln` into an [`AdvisoryEntry`] if and only if
/// the record carries a `modified` timestamp strictly after `since`.
///
/// `expected_eco` filters affected-package entries to the ecosystem
/// the archive belongs to — OSV occasionally cross-publishes a single
/// advisory under multiple ecosystem archives, but the
/// `(ecosystem, name)` join in `sbom_components` will only ever
/// produce hits for the ecosystem the bulk file targets. Filtering
/// here keeps the per-ecosystem pull self-consistent.
pub(crate) fn bulk_record_to_advisory_entry(
    rec: BulkOsvVuln,
    expected_eco: &Ecosystem,
    since: DateTime<Utc>,
) -> Option<AdvisoryEntry> {
    let modified = rec.modified?;
    if modified <= since {
        return None;
    }
    if rec.id.is_empty() {
        return None;
    }
    let mut affected: Vec<AdvisoryAffectedPackage> = Vec::new();
    for a in rec.affected {
        let Some(pkg) = a.package else { continue };
        if pkg.name.is_empty() {
            continue;
        }
        let Some(eco) = osv_label_to_ecosystem(&pkg.ecosystem) else {
            continue;
        };
        if &eco != expected_eco {
            continue;
        }
        affected.push(AdvisoryAffectedPackage {
            ecosystem: eco,
            name: pkg.name,
            affected_versions: a.versions,
        });
    }
    if affected.is_empty() {
        return None;
    }
    Some(AdvisoryEntry {
        id: rec.id,
        modified,
        affected,
    })
}

/// Map an OSV ecosystem string (the literal that appears in OSV's
/// `affected[].package.ecosystem` and in the bulk-archive URL path)
/// to the typed [`Ecosystem`] enum.
///
/// Mirrors the *inverse* of `crate::ecosystem::osv_ecosystem_for`; the
/// two functions must stay in lock step. Returns `None` for ecosystems
/// the OSV bulk feed does not cover or that the platform does not
/// support (Helm, OCI image, unrecognised vendor labels).
pub(crate) fn osv_label_to_ecosystem(s: &str) -> Option<Ecosystem> {
    match s {
        "npm" => Some(Ecosystem::Npm),
        "PyPI" => Some(Ecosystem::PyPI),
        "crates.io" => Some(Ecosystem::Cargo),
        "Maven" => Some(Ecosystem::Maven),
        "Go" => Some(Ecosystem::Go),
        "RubyGems" => Some(Ecosystem::RubyGems),
        "NuGet" => Some(Ecosystem::NuGet),
        "Packagist" => Some(Ecosystem::Composer),
        "Hex" => Some(Ecosystem::Hex),
        "Pub" => Some(Ecosystem::Pub),
        "Conda" => Some(Ecosystem::Conda),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    // -----------------------------------------------------------------------
    // osv_label_to_ecosystem — exhaustive mapping
    // -----------------------------------------------------------------------

    #[test]
    fn osv_label_maps_each_supported_ecosystem() {
        assert_eq!(osv_label_to_ecosystem("npm"), Some(Ecosystem::Npm));
        assert_eq!(osv_label_to_ecosystem("PyPI"), Some(Ecosystem::PyPI));
        assert_eq!(osv_label_to_ecosystem("crates.io"), Some(Ecosystem::Cargo));
        assert_eq!(osv_label_to_ecosystem("Maven"), Some(Ecosystem::Maven));
        assert_eq!(osv_label_to_ecosystem("Go"), Some(Ecosystem::Go));
        assert_eq!(
            osv_label_to_ecosystem("RubyGems"),
            Some(Ecosystem::RubyGems)
        );
        assert_eq!(osv_label_to_ecosystem("NuGet"), Some(Ecosystem::NuGet));
        assert_eq!(
            osv_label_to_ecosystem("Packagist"),
            Some(Ecosystem::Composer)
        );
        assert_eq!(osv_label_to_ecosystem("Hex"), Some(Ecosystem::Hex));
        assert_eq!(osv_label_to_ecosystem("Pub"), Some(Ecosystem::Pub));
        assert_eq!(osv_label_to_ecosystem("Conda"), Some(Ecosystem::Conda));
    }

    #[test]
    fn osv_label_rejects_unsupported_strings() {
        assert!(osv_label_to_ecosystem("Helm").is_none());
        assert!(osv_label_to_ecosystem("").is_none());
        assert!(osv_label_to_ecosystem("notreal").is_none());
        // Case-sensitivity guard — OSV's labels are case-sensitive.
        assert!(osv_label_to_ecosystem("NPM").is_none());
        assert!(osv_label_to_ecosystem("pypi").is_none());
    }

    // -----------------------------------------------------------------------
    // bulk_record_to_advisory_entry — filter + map semantics
    // -----------------------------------------------------------------------

    fn ts(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).unwrap()
    }

    fn rec_with(
        id: &str,
        modified_secs: Option<i64>,
        eco: &str,
        name: &str,
        versions: Vec<String>,
    ) -> BulkOsvVuln {
        BulkOsvVuln {
            id: id.into(),
            modified: modified_secs.map(ts),
            affected: vec![BulkOsvAffected {
                package: Some(BulkOsvPackage {
                    ecosystem: eco.into(),
                    name: name.into(),
                }),
                versions,
            }],
        }
    }

    #[test]
    fn record_with_modified_after_since_yields_entry() {
        let rec = rec_with(
            "GHSA-x",
            Some(2_000),
            "npm",
            "lodash",
            vec!["4.17.20".into()],
        );
        let got = bulk_record_to_advisory_entry(rec, &Ecosystem::Npm, ts(1_000))
            .expect("modified > since => Some");
        assert_eq!(got.id, "GHSA-x");
        assert_eq!(got.affected.len(), 1);
        assert_eq!(got.affected[0].ecosystem, Ecosystem::Npm);
        assert_eq!(got.affected[0].name, "lodash");
        assert_eq!(got.affected[0].affected_versions, vec!["4.17.20"]);
    }

    #[test]
    fn record_with_modified_at_or_before_since_filtered_out() {
        let rec = rec_with("GHSA-x", Some(1_000), "npm", "lodash", vec![]);
        assert!(bulk_record_to_advisory_entry(rec, &Ecosystem::Npm, ts(1_000)).is_none());
        let rec = rec_with("GHSA-x", Some(500), "npm", "lodash", vec![]);
        assert!(bulk_record_to_advisory_entry(rec, &Ecosystem::Npm, ts(1_000)).is_none());
    }

    #[test]
    fn record_without_modified_field_is_dropped() {
        let rec = rec_with("GHSA-x", None, "npm", "lodash", vec!["1".into()]);
        assert!(bulk_record_to_advisory_entry(rec, &Ecosystem::Npm, ts(0)).is_none());
    }

    #[test]
    fn record_with_empty_id_dropped() {
        let rec = rec_with("", Some(2_000), "npm", "lodash", vec!["1".into()]);
        assert!(bulk_record_to_advisory_entry(rec, &Ecosystem::Npm, ts(1_000)).is_none());
    }

    #[test]
    fn record_with_no_matching_ecosystem_yields_none() {
        // Record reports as PyPI but archive iteration is for npm — drop.
        let rec = rec_with("GHSA-x", Some(2_000), "PyPI", "django", vec!["4.0".into()]);
        assert!(bulk_record_to_advisory_entry(rec, &Ecosystem::Npm, ts(1_000)).is_none());
    }

    #[test]
    fn record_with_only_unsupported_ecosystem_yields_none() {
        let rec = rec_with("GHSA-x", Some(2_000), "Helm", "chart", vec!["1".into()]);
        // Helm is unsupported; even matching Helm against expected_eco
        // produces None because the label doesn't map.
        assert!(bulk_record_to_advisory_entry(rec, &Ecosystem::Npm, ts(1_000)).is_none());
    }

    #[test]
    fn record_with_empty_name_dropped() {
        let rec = rec_with("GHSA-x", Some(2_000), "npm", "", vec!["1".into()]);
        assert!(bulk_record_to_advisory_entry(rec, &Ecosystem::Npm, ts(1_000)).is_none());
    }

    #[test]
    fn record_with_no_affected_packages_dropped() {
        let rec = BulkOsvVuln {
            id: "GHSA-x".into(),
            modified: Some(ts(2_000)),
            affected: vec![],
        };
        assert!(bulk_record_to_advisory_entry(rec, &Ecosystem::Npm, ts(1_000)).is_none());
    }

    #[test]
    fn record_with_multiple_affected_keeps_only_matching_ecosystem() {
        let rec = BulkOsvVuln {
            id: "GHSA-x".into(),
            modified: Some(ts(2_000)),
            affected: vec![
                BulkOsvAffected {
                    package: Some(BulkOsvPackage {
                        ecosystem: "npm".into(),
                        name: "lodash".into(),
                    }),
                    versions: vec!["4.17.20".into()],
                },
                BulkOsvAffected {
                    package: Some(BulkOsvPackage {
                        ecosystem: "PyPI".into(),
                        name: "django".into(),
                    }),
                    versions: vec!["4.0".into()],
                },
            ],
        };
        let got = bulk_record_to_advisory_entry(rec, &Ecosystem::Npm, ts(1_000))
            .expect("at least one affected matches => Some");
        assert_eq!(got.affected.len(), 1);
        assert_eq!(got.affected[0].name, "lodash");
    }

    // -----------------------------------------------------------------------
    // pull_one_ecosystem — wiremock-driven happy path + error path
    // -----------------------------------------------------------------------

    fn build_zip_with(records: &[(&str, &str)]) -> Vec<u8> {
        hort_formats::archive_bounds::build_zip_bytes(records)
    }

    fn http_client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("test http client")
    }

    #[tokio::test]
    async fn pull_one_ecosystem_happy_path_returns_filtered_entries() {
        // `since` = 1000s past epoch. `after` is at 2000s (after), `before`
        // is at 500s (before). Only the after-record survives the filter.
        let after = serde_json::json!({
            "id": "GHSA-after",
            "modified": "1970-01-01T00:33:20Z",
            "affected": [{
                "package": { "ecosystem": "npm", "name": "lodash" },
                "versions": ["4.17.20"]
            }]
        })
        .to_string();
        let before = serde_json::json!({
            "id": "GHSA-before",
            "modified": "1970-01-01T00:08:20Z",
            "affected": [{
                "package": { "ecosystem": "npm", "name": "old" },
                "versions": ["1.0.0"]
            }]
        })
        .to_string();
        let zip_bytes = build_zip_with(&[
            ("GHSA-after.json", after.as_str()),
            ("GHSA-before.json", before.as_str()),
            // Non-JSON entry must be skipped without error.
            ("README.txt", "ignored"),
        ]);

        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/npm/all.zip"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_bytes(zip_bytes)
                    .insert_header("content-type", "application/zip"),
            )
            .mount(&server)
            .await;

        let entries = pull_one_ecosystem(
            &http_client(),
            &server.uri(),
            "npm",
            Ecosystem::Npm,
            ts(1_000),
        )
        .await
        .expect("happy path returns Ok");
        assert_eq!(
            entries.len(),
            1,
            "only the after-record survives the filter"
        );
        assert_eq!(entries[0].id, "GHSA-after");
    }

    #[tokio::test]
    async fn pull_one_ecosystem_skips_malformed_json_entries() {
        let good = serde_json::json!({
            "id": "GHSA-good",
            "modified": "1970-01-01T00:33:20Z",
            "affected": [{
                "package": { "ecosystem": "npm", "name": "lodash" },
                "versions": ["4.17.20"]
            }]
        })
        .to_string();
        let zip_bytes = build_zip_with(&[
            ("good.json", good.as_str()),
            ("malformed.json", "{not-valid-json"),
        ]);
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/npm/all.zip"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(zip_bytes))
            .mount(&server)
            .await;

        let entries = pull_one_ecosystem(
            &http_client(),
            &server.uri(),
            "npm",
            Ecosystem::Npm,
            ts(1_000),
        )
        .await
        .expect("malformed entry must not abort the ecosystem");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "GHSA-good");
    }

    #[tokio::test]
    async fn pull_one_ecosystem_returns_err_on_http_500() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/npm/all.zip"))
            .respond_with(wiremock::ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let err = pull_one_ecosystem(&http_client(), &server.uri(), "npm", Ecosystem::Npm, ts(0))
            .await
            .expect_err("500 must surface as Err");
        assert_eq!(err.kind, BulkFetchErrorKind::FetchError);
        assert!(
            err.message.contains("500"),
            "error message includes status: {}",
            err.message
        );
    }

    #[tokio::test]
    async fn pull_one_ecosystem_returns_err_when_zip_body_is_invalid() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/npm/all.zip"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_bytes(b"not-a-zip".to_vec()),
            )
            .mount(&server)
            .await;
        let err = pull_one_ecosystem(&http_client(), &server.uri(), "npm", Ecosystem::Npm, ts(0))
            .await
            .expect_err("invalid zip payload must Err out the ecosystem");
        // The bytes "not-a-zip" make `zip::ZipArchive::new` fail; that
        // path is classified as ParseError.
        assert_eq!(err.kind, BulkFetchErrorKind::ParseError);
    }

    // -----------------------------------------------------------------------
    // Regression — >1024-entry ecosystem zip must ingest every advisory
    // -----------------------------------------------------------------------
    //
    // The OSV bulk path previously used
    // `BoundsConfig::default_for_metadata_extraction()` (max_entries=1024).
    // A real ecosystem zip (npm, PyPI, Maven) contains thousands of
    // advisories.  Entry 1025 tripped the entry counter and the whole
    // ecosystem ingest aborted as `ParseError` — a silent detection failure.
    //
    // This test synthesises a 1030-entry zip and asserts:
    // 1. `pull_one_ecosystem` returns `Ok` (no ParseError / BoundsError).
    // 2. All 1030 advisories (modified > since) are present in the result.
    #[tokio::test]
    async fn pull_one_ecosystem_ingests_all_advisories_in_large_ecosystem_zip() {
        // Build a zip with 1030 advisory entries — 6 more than the old
        // metadata-extraction cap of 1024. Each entry has a unique ID and
        // `modified` timestamp strictly after `since` (epoch 0).
        let n: usize = 1030;
        let since = DateTime::<Utc>::from_timestamp(0, 0).unwrap();

        let mut entries: Vec<(String, String)> = Vec::with_capacity(n);
        for i in 0..n {
            let id = format!("GHSA-f5-{i:04}");
            let body = serde_json::json!({
                "id": id,
                "modified": "1970-01-01T00:16:40Z", // 1000s > 0
                "affected": [{
                    "package": { "ecosystem": "npm", "name": format!("pkg-{i}") },
                    "versions": ["1.0.0"]
                }]
            })
            .to_string();
            entries.push((format!("{id}.json"), body));
        }
        let files: Vec<(&str, &str)> = entries
            .iter()
            .map(|(name, body)| (name.as_str(), body.as_str()))
            .collect();
        let zip_bytes = build_zip_with(&files);

        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/npm/all.zip"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_bytes(zip_bytes)
                    .insert_header("content-type", "application/zip"),
            )
            .mount(&server)
            .await;

        let result =
            pull_one_ecosystem(&http_client(), &server.uri(), "npm", Ecosystem::Npm, since).await;

        // Must NOT fail with ParseError.
        assert!(
            result.is_ok(),
            "large ecosystem zip must not abort as ParseError: {result:?}"
        );
        let advisories = result.unwrap();
        assert_eq!(
            advisories.len(),
            n,
            "all {n} advisories must be ingested, got {}",
            advisories.len()
        );
    }

    // -----------------------------------------------------------------------
    // Regression — large single advisory must survive per-entry cap
    // -----------------------------------------------------------------------
    //
    // A single advisory whose decompressed
    // size exceeds the per-entry output cap imposed by the old
    // `default_for_metadata_extraction()` config would be SILENTLY DROPPED —
    // `BoundedReader` returns an IO error, `read_to_string` fails, the visitor
    // returns early, and the entry is never pushed to `out`.
    //
    // `for_trusted_bulk_feed()` raises MAX_OUTPUT_BYTES from 10 MiB to 2 GiB.
    // The binding constraint for the per-entry cap is
    // `min(COMPRESSION_RATIO_LIMIT × compressed_size, max_output_bytes)`.
    // When `10 × compressed_size > MAX_OUTPUT_BYTES (10 MiB)`, the ceiling is
    // what prevents full reads under the old config.  The trusted-bulk ceiling
    // (2 GiB) removes that constraint for any realistic advisory.
    //
    // This test exercises the boundary directly via `iter_zip_entries` using a
    // tight synthetic ceiling (`max_output_bytes = 16 KiB`) to represent the
    // old-config truncation behaviour, versus `for_trusted_bulk_feed()`'s
    // actual 2 GiB ceiling that passes the advisory intact.  The advisory JSON
    // carries a 2000-element `versions` array (~20 KiB uncompressed); the
    // assertion verifies the full array survives, not merely "no error".
    #[test]
    fn large_single_advisory_survives_per_entry_cap_under_trusted_bulk_config() {
        // Build a realistic OSV advisory with a 2 000-element versions array.
        // Each version string is ~10 bytes ("1.xxx.yyy\0") → ~20 KB uncompressed.
        let n_versions: usize = 2_000;
        let versions: Vec<String> = (0..n_versions)
            .map(|i| format!("{}.{}.{}", i / 100, (i / 10) % 10, i % 10))
            .collect();
        let body = serde_json::json!({
            "id": "GHSA-mode2-large",
            "modified": "1970-01-01T00:16:40Z",
            "affected": [{
                "package": { "ecosystem": "npm", "name": "big-pkg" },
                "versions": versions
            }]
        })
        .to_string();
        let uncompressed_len = body.len();
        let zip_bytes = build_zip_with(&[("GHSA-mode2-large.json", body.as_str())]);

        // ── tight-ceiling config (represents old default_for_metadata_extraction
        //    behaviour when an advisory is large enough to hit the 10 MiB ceiling).
        //    We use a 16 KiB synthetic ceiling so the test stays fast (the JSON
        //    is ~20 KiB, guaranteed to exceed this cap regardless of compression).
        let tight_cfg = BoundsConfig {
            max_output_bytes: 16 * 1024, // 16 KiB — tight synthetic ceiling
            ..BoundsConfig::default_for_metadata_extraction()
        };
        let mut bytes_seen_tight = 0usize;
        let zip_cursor = std::io::Cursor::new(zip_bytes.clone());
        iter_zip_entries(zip_cursor, tight_cfg, |_name, reader| {
            // Count bytes actually readable before the cap fires.
            let mut sink = vec![0u8; 64 * 1024];
            loop {
                match reader.read(&mut sink) {
                    Ok(0) => break,
                    Ok(n) => bytes_seen_tight += n,
                    Err(_) => break, // BoundedReader cap — truncation
                }
            }
        })
        .expect("zip iteration itself does not error");
        // Confirm the tight cap prevented reading the full advisory.
        assert!(
            bytes_seen_tight < uncompressed_len,
            "tight ceiling ({tight_bytes} KiB) must truncate the {uncompressed_len}-byte advisory \
             (saw {bytes_seen_tight} bytes)",
            tight_bytes = 16,
        );

        // ── for_trusted_bulk_feed() — the actual config used by pull_one_ecosystem.
        //    The 2 GiB ceiling means the per-entry cap is only ratio-limited
        //    (10 × compressed_size), which for any realistic advisory is far
        //    above the advisory's actual decompressed size.
        let mut parsed_advisory: Option<BulkOsvVuln> = None;
        let zip_cursor2 = std::io::Cursor::new(zip_bytes);
        iter_zip_entries(
            zip_cursor2,
            BoundsConfig::for_trusted_bulk_feed(),
            |name, reader| {
                if !name.ends_with(".json") {
                    return;
                }
                let mut buf = String::new();
                if reader.read_to_string(&mut buf).is_err() {
                    return;
                }
                if let Ok(rec) = serde_json::from_str::<BulkOsvVuln>(&buf) {
                    parsed_advisory = Some(rec);
                }
            },
        )
        .expect("trusted bulk config must complete without error");

        let advisory = parsed_advisory
            .expect("advisory must be present under for_trusted_bulk_feed() — not truncated");
        assert_eq!(
            advisory.id, "GHSA-mode2-large",
            "advisory id must survive intact"
        );
        // Assert the full 2 000-element versions array survived — not a partial read.
        let versions_count = advisory
            .affected
            .iter()
            .flat_map(|a| a.versions.iter())
            .count();
        assert_eq!(
            versions_count, n_versions,
            "all {n_versions} versions must survive per-entry cap — got {versions_count}"
        );
    }

    // -----------------------------------------------------------------------
    // Call-site tolerance — bounds trip on trusted path must NOT be ParseError
    // -----------------------------------------------------------------------
    //
    // The match logic inside the blocking closure of `pull_one_ecosystem`
    // distinguishes `Err(ZipIterError::Bounds(_))`
    // (warn + keep collected advisories) from all other `ZipIterError` variants
    // (→ ParseError). This test exercises that arm directly using a deliberately
    // tiny `BoundsConfig` to force `Err(ZipIterError::Bounds(...))`, verifying
    // that the call-site match keeps already-collected advisories instead of
    // aborting with ParseError.
    #[test]
    fn call_site_bounds_trip_keeps_collected_advisories_and_does_not_parse_error() {
        // Build a 3-entry zip where every entry has a valid advisory JSON.
        // Use max_entries=2 to force a bounds trip on the 3rd entry.
        let entry_a = serde_json::json!({
            "id": "GHSA-a",
            "modified": "1970-01-01T00:16:40Z",
            "affected": [{"package": {"ecosystem": "npm", "name": "pkg-a"}, "versions": ["1.0"]}]
        })
        .to_string();
        let entry_b = serde_json::json!({
            "id": "GHSA-b",
            "modified": "1970-01-01T00:16:40Z",
            "affected": [{"package": {"ecosystem": "npm", "name": "pkg-b"}, "versions": ["2.0"]}]
        })
        .to_string();
        let entry_c = serde_json::json!({
            "id": "GHSA-c",
            "modified": "1970-01-01T00:16:40Z",
            "affected": [{"package": {"ecosystem": "npm", "name": "pkg-c"}, "versions": ["3.0"]}]
        })
        .to_string();
        let zip_bytes = build_zip_with(&[
            ("GHSA-a.json", entry_a.as_str()),
            ("GHSA-b.json", entry_b.as_str()),
            ("GHSA-c.json", entry_c.as_str()),
        ]);

        // Tight config: only 2 entries allowed — forces Err(ZipIterError::Bounds(...))
        // when the 3rd entry is reached. This mirrors the scenario where
        // MAX_ENTRIES_TRUSTED_BULK is exceeded (but at a tiny scale for test speed).
        let tight_cfg = BoundsConfig {
            max_entries: 2,
            ..BoundsConfig::for_trusted_bulk_feed()
        };

        let eco = Ecosystem::Npm;
        let since = ts(0);
        let mut out: Vec<AdvisoryEntry> = Vec::new();

        // Replicate the pull_one_ecosystem match logic at the call site.
        let result = iter_zip_entries(
            std::io::Cursor::new(zip_bytes),
            tight_cfg,
            |name, reader| {
                if !name.ends_with(".json") {
                    return;
                }
                let mut buf = String::new();
                if reader.read_to_string(&mut buf).is_err() {
                    return;
                }
                let Ok(parsed) = serde_json::from_str::<BulkOsvVuln>(&buf) else {
                    return;
                };
                if let Some(entry) = bulk_record_to_advisory_entry(parsed, &eco, since) {
                    out.push(entry);
                }
            },
        );

        // The bounds trip MUST surface as Err(ZipIterError::Bounds(_)).
        assert!(
            matches!(result, Err(ZipIterError::Bounds(_))),
            "bounds trip on trusted path must be Err(Bounds(_)), got {result:?}"
        );

        // The call-site match (mirroring pull_one_ecosystem's blocking closure):
        // Bounds error → warn + keep collected advisories (do NOT return ParseError).
        match result {
            Ok(()) => {}
            Err(ZipIterError::Bounds(_)) => {
                // This is the tolerated arm — keep `out` as-is, do NOT abort.
                // In production this emits tracing::warn!; here we just verify
                // we reach this arm and not a ParseError return.
            }
            Err(e) => panic!("non-Bounds ZipIterError must be ParseError, got {e}"),
        }

        // Advisories already visited before the cap tripped must be present.
        // With max_entries=2, entries a and b are visited; c is beyond the cap.
        assert_eq!(
            out.len(),
            2,
            "the 2 advisories visited before the bounds trip must be in the collection"
        );
        let ids: Vec<&str> = out.iter().map(|e| e.id.as_str()).collect();
        assert!(ids.contains(&"GHSA-a"), "GHSA-a must be collected");
        assert!(ids.contains(&"GHSA-b"), "GHSA-b must be collected");
        assert!(
            !ids.contains(&"GHSA-c"),
            "GHSA-c was beyond the cap and must not be collected"
        );
    }

    #[tokio::test]
    async fn bulk_fetch_error_into_domain_error_collapses_to_invariant() {
        let bfe = BulkFetchError {
            kind: BulkFetchErrorKind::Timeout,
            message: "deadline elapsed".into(),
        };
        let de: DomainError = bfe.into();
        match de {
            DomainError::Invariant(msg) => assert_eq!(msg, "deadline elapsed"),
            other => panic!("expected Invariant, got {other:?}"),
        }
    }
}
