//! PyPI `IndexBuilder` impls — the PyPI side of the Source → Filter →
//! Builder pipeline (see explanation/index-construction.md,
//! design doc §2.1 / §2.3 / §2.6).
//!
//! PyPI's simple index emits **two content types** off the same
//! per-version data:
//!
//! - PEP 503 HTML — anchors of the form
//!   `<a href="…/{filename}#sha256=…" data-requires-python="…">{filename}</a>`.
//! - PEP 691 JSON — `files[]` rows of the form
//!   `{ "filename": …, "url": …, "hashes": {"sha256": …}, "requires-python": … }`.
//!
//! Per design doc §2.3 the trait stays content-type-agnostic and PyPI
//! ships **two distinct builder impls** ([`PypiHtmlIndexBuilder`] and
//! [`PypiJsonIndexBuilder`]); the per-format serve handler picks one
//! based on the request's `Accept` header via `SimpleIndexFormat::from_accept`.
//! The alternative (adding a `content_type` field to [`BuildContext`] +
//! runtime branching inside a single builder) was explicitly rejected:
//! builder selection is a handler-tier decision.
//!
//! # What the builders emit
//!
//! Both consume the same [`PypiVersionPayload`]. Each entry's payload
//! carries a `Vec<PypiVersionFile>` (one row per sdist / wheel); the
//! builder emits one wire entry per file:
//!
//! - **`PypiHtmlIndexBuilder`** — PEP 503 document with one `<a>` per
//!   file, sandwiched between a static header (`<!DOCTYPE>` + `<title>
//!   Links for {package_name}</title>` + `<h1>Links for {package_name}
//!   </h1>`) and footer (`</body></html>`).
//! - **`PypiJsonIndexBuilder`** — PEP 691 document with
//!   `meta.api-version = "1.1"` (PEP 700 — required for the
//!   `versions[]` field), `name`, `files[]`, and a sorted `versions[]`
//!   array (sorted by the per-call [`BuildContext::ordering`] so the
//!   PEP 440-max is last — uv / modern pip read it that way).
//!
//! # `dist-tags.latest` regression-equivalent (PEP 440 ordering)
//!
//! PyPI has no `dist-tags`; the analogue is the bare `pip install`
//! resolution target, which pip computes from the served file set
//! (max PEP 440 version among the surviving anchors / `files[]`
//! rows). The builder does **not** emit an explicit "latest" pointer
//! — pip derives it from the served set — but the JSON arm orders
//! `versions[]` semantically (PEP 440) so the last element IS the
//! resolved-latest. The HTML arm emits anchors in source order; pip
//! traverses all of them.
//!
//! # URL construction
//!
//! Both builders compose per-file URLs as
//! `{base_url}/{filename}` where `base_url` is the per-call
//! [`BuildContext::base_url`] (already includes `/pypi/{repo_key}/
//! simple/{normalized_name}` — the per-format serve handler composes
//! it before invoking the builder). The builder is content-type-
//! agnostic about `base_url`; it just concatenates with `/`. Hashes
//! travel in the URL fragment (HTML — PEP 503) or the dedicated
//! `hashes` object (JSON — PEP 691).
//!
//! # Why two impls instead of an arm on one impl
//!
//! Design §2.3 explicit instruction. Splitting also keeps the
//! per-content-type emission cost honest: the HTML arm pays string
//! concatenation; the JSON arm pays a `serde_json::Value` build +
//! `serde_json::to_vec`. Each is the right tool for its wire shape.
//!
//! # Tests
//!
//! Builder tests (this module) cover every branch on `entries` for
//! both impls: empty set, single-version single-file, multi-file
//! within a version (sdist + wheel), absent `hash_sha256`, absent
//! `requires_python`, multi-version ordering. Source-adapter tests
//! live in `hort-http-pypi/src/index_source.rs`; F-25 anti-enumeration
//! tests live in `hort-http-pypi/src/serve.rs`.

use bytes::Bytes;
use hort_app::use_cases::index_serve::{
    BuildContext, IndexBuilder, PerVersionPayload, VersionEntry,
};

pub use hort_app::use_cases::index_serve::{PypiVersionFile, PypiVersionPayload};

// ---------------------------------------------------------------------------
// HTML builder — PEP 503
// ---------------------------------------------------------------------------

/// PyPI `IndexBuilder` emitting **PEP 503 HTML** (`text/html`).
///
/// Stateless; per-format serve handler constructs an instance per
/// request (cheap — unit struct). Mirrors
/// [`crate::npm::index::NpmIndexBuilder`]'s shape.
#[derive(Debug, Default, Clone, Copy)]
pub struct PypiHtmlIndexBuilder;

impl IndexBuilder for PypiHtmlIndexBuilder {
    fn build(&self, ctx: BuildContext<'_>, entries: Vec<VersionEntry>) -> Bytes {
        let mut html = format!(
            "<!DOCTYPE html>\n<html>\n<head>\
             <meta name=\"pypi:repository-version\" content=\"1.0\"/>\
             <title>Links for {pkg}</title></head>\n<body>\n\
             <h1>Links for {pkg}</h1>\n",
            pkg = ctx.package_name,
        );

        for entry in &entries {
            // Cross-format mis-tag defence: a Npm/Cargo payload should
            // never reach the PyPI builder. Skip with a structured
            // warn (degraded body, never a panic).
            let PerVersionPayload::Pypi(payload) = &entry.payload else {
                tracing::warn!(
                    version = %entry.version,
                    "pypi html index builder: skipping VersionEntry with non-Pypi payload \
                     (cross-format mis-tag — should be unreachable)",
                );
                continue;
            };
            for file in &payload.files {
                // URL shape: `{base_url}/{filename}{#sha256=...}`.
                // PEP 503 places the hash in the URL fragment;
                // `requires-python` rides as a `data-` attribute.
                let mut href = format!(
                    "{base}/{filename}",
                    base = ctx.base_url,
                    filename = file.filename,
                );
                if let Some(hash) = file.hash_sha256.as_ref() {
                    href.push_str("#sha256=");
                    href.push_str(hash);
                }
                let requires_python_attr = match file.requires_python.as_ref() {
                    Some(rp) => format!(" data-requires-python=\"{}\"", html_escape_attr(rp)),
                    None => String::new(),
                };
                // PEP 658 `data-dist-info-metadata`. Emitted as
                // `sha256=<hex>` only when the source populated
                // `metadata_hash` (a wheel with a `wheel_metadata`
                // ContentReference row OR a proxy entry whose upstream
                // advertised PEP 658). Sdists, legacy un-backfilled
                // wheels, and any wheel whose ContentReference lookup
                // failed → `None` → attribute OMITTED (the earlier
                // unconditional `="true"` was incorrect for sdists,
                // which PEP 658 explicitly excludes).
                let metadata_attr = match file.metadata_hash.as_ref() {
                    Some(h) => format!(" data-dist-info-metadata=\"sha256={h}\""),
                    None => String::new(),
                };
                html.push_str(&format!(
                    "<a href=\"{href}\"{requires_python_attr}{metadata_attr}>\
                     {filename}</a>\n",
                    filename = file.filename,
                ));
            }
        }
        html.push_str("</body>\n</html>\n");

        Bytes::from(html)
    }
}

/// Escape a string for use inside an HTML double-quoted attribute
/// value. Covers the five characters the HTML5 spec names for
/// attribute contexts.
fn html_escape_attr(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

// ---------------------------------------------------------------------------
// JSON builder — PEP 691
// ---------------------------------------------------------------------------

/// PyPI `IndexBuilder` emitting **PEP 691 JSON**
/// (`application/vnd.pypi.simple.v1+json`).
///
/// `meta.api-version = "1.1"` because PEP 700 added the `versions[]`
/// field and modern pip / uv assert on it. Sorted by the per-call
/// [`BuildContext::ordering`] so the last element is the PEP 440-max.
#[derive(Debug, Default, Clone, Copy)]
pub struct PypiJsonIndexBuilder;

impl IndexBuilder for PypiJsonIndexBuilder {
    fn build(&self, ctx: BuildContext<'_>, entries: Vec<VersionEntry>) -> Bytes {
        let mut files: Vec<serde_json::Value> = Vec::new();
        for entry in &entries {
            // Cross-format mis-tag defence: see HTML arm above for
            // the rationale.
            let PerVersionPayload::Pypi(payload) = &entry.payload else {
                tracing::warn!(
                    version = %entry.version,
                    "pypi json index builder: skipping VersionEntry with non-Pypi payload \
                     (cross-format mis-tag — should be unreachable)",
                );
                continue;
            };
            for file in &payload.files {
                let url = format!(
                    "{base}/{filename}",
                    base = ctx.base_url,
                    filename = file.filename,
                );
                let mut row = serde_json::Map::new();
                row.insert(
                    "filename".to_string(),
                    serde_json::Value::String(file.filename.clone()),
                );
                row.insert("url".to_string(), serde_json::Value::String(url));
                // hashes — emit the sha256 sub-object only when the
                // source supplied one (no empty-string / `null`
                // emission, matching the npm builder's
                // omit-on-absent convention for the same reason).
                if let Some(hash) = file.hash_sha256.as_ref() {
                    let mut hashes = serde_json::Map::new();
                    hashes.insert(
                        "sha256".to_string(),
                        serde_json::Value::String(hash.clone()),
                    );
                    row.insert("hashes".to_string(), serde_json::Value::Object(hashes));
                } else {
                    // PEP 691 requires `hashes` — emit an empty object
                    // when no hash was supplied.
                    row.insert(
                        "hashes".to_string(),
                        serde_json::Value::Object(serde_json::Map::new()),
                    );
                }
                // PEP 691 `dist-info-metadata`:
                // `Some(hash)` → `{"sha256": "<hex>"}` ("available +
                // integrity known"). `None` → `false` ("not available")
                // — used for sdists, un-backfilled wheels, and any
                // wheel whose ContentReference lookup failed. Per
                // PEP 691, `false` is the correct value when no metadata
                // file exists; pip falls back to whole-wheel download.
                let dim_value = match file.metadata_hash.as_ref() {
                    Some(h) => {
                        let mut sub = serde_json::Map::new();
                        sub.insert(
                            "sha256".to_string(),
                            serde_json::Value::String(h.to_string()),
                        );
                        serde_json::Value::Object(sub)
                    }
                    None => serde_json::Value::Bool(false),
                };
                row.insert("dist-info-metadata".to_string(), dim_value);
                if let Some(rp) = file.requires_python.as_ref() {
                    row.insert(
                        "requires-python".to_string(),
                        serde_json::Value::String(rp.clone()),
                    );
                }
                files.push(serde_json::Value::Object(row));
            }
        }

        // versions[] — derived from the entries' `version` field, in
        // post-filter order, then sorted by the per-call ordering so
        // the PEP 440-max is last. `BTreeSet` would give lexicographic
        // order, which is wrong for PEP 440 (`1.10 < 1.9` lex; the
        // reverse holds semantically).
        let mut versions: Vec<String> = entries
            .iter()
            .map(|e| e.version.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        versions.sort_by(|a, b| ctx.ordering.compare(a, b));

        let body = serde_json::json!({
            "meta": { "api-version": "1.1" },
            "name": ctx.package_name,
            "files": files,
            "versions": versions,
        });

        // Infallible serialise: all keys are owned `String`; all
        // values are `Value::String` / `Value::Object` / `Value::Bool`
        // / `Value::Array`. Matches the npm builder's `expect`
        // pattern.
        let bytes =
            serde_json::to_vec(&body).expect("PypiJsonIndexBuilder serialises owned values only");
        Bytes::from(bytes)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use hort_app::use_cases::index_serve_filter::Pep440Ordering;
    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::repository::IndexMode;

    use super::*;

    fn entry(version: &str, files: Vec<PypiVersionFile>) -> VersionEntry {
        VersionEntry {
            version: version.to_string(),
            status: Some(QuarantineStatus::Released),
            payload: PerVersionPayload::Pypi(PypiVersionPayload { files }),
        }
    }

    fn file(
        filename: &str,
        hash_sha256: Option<&str>,
        requires_python: Option<&str>,
    ) -> PypiVersionFile {
        PypiVersionFile {
            filename: filename.to_string(),
            hash_sha256: hash_sha256.map(str::to_string),
            requires_python: requires_python.map(str::to_string),
            metadata_hash: None,
        }
    }

    /// Variant of [`file`] that pre-populates `metadata_hash` (the PEP
    /// 658 advertisement source). Used by the per-builder PEP 658
    /// emission tests.
    fn file_with_metadata_hash(
        filename: &str,
        hash_sha256: Option<&str>,
        requires_python: Option<&str>,
        metadata_hash_hex: &str,
    ) -> PypiVersionFile {
        let metadata_hash: hort_domain::types::ContentHash =
            metadata_hash_hex.parse().expect("valid sha256 hex");
        PypiVersionFile {
            filename: filename.to_string(),
            hash_sha256: hash_sha256.map(str::to_string),
            requires_python: requires_python.map(str::to_string),
            metadata_hash: Some(metadata_hash),
        }
    }

    /// Stable PEP 658 hash fixture — the SHA-256 of the empty input.
    /// Lets every PEP-658 emission test share the same wire string.
    const METADATA_HASH_HEX: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn build_html(entries: Vec<VersionEntry>, package: &str, base: &str) -> String {
        let bytes = PypiHtmlIndexBuilder.build(
            BuildContext {
                package_name: package,
                base_url: base,
                index_mode: IndexMode::ReleasedOnly,
                ordering: &Pep440Ordering,
            },
            entries,
        );
        String::from_utf8(bytes.to_vec()).expect("builder emits valid UTF-8")
    }

    fn build_json(entries: Vec<VersionEntry>, package: &str, base: &str) -> serde_json::Value {
        let bytes = PypiJsonIndexBuilder.build(
            BuildContext {
                package_name: package,
                base_url: base,
                index_mode: IndexMode::ReleasedOnly,
                ordering: &Pep440Ordering,
            },
            entries,
        );
        serde_json::from_slice(&bytes).expect("builder emits valid JSON")
    }

    // -----------------------------------------------------------------
    // HTML — empty set
    // -----------------------------------------------------------------

    #[test]
    fn html_empty_entries_produces_well_formed_empty_document() {
        let html = build_html(Vec::new(), "requests", "/pypi/m/simple/requests");
        assert!(html.contains("<title>Links for requests</title>"));
        assert!(html.contains("<h1>Links for requests</h1>"));
        assert!(html.contains("</body>"));
        // No anchor present.
        assert!(!html.contains("<a "));
    }

    // -----------------------------------------------------------------
    // HTML — single version single file with all fields
    // -----------------------------------------------------------------

    #[test]
    fn html_single_file_emits_anchor_with_sha256_fragment_and_requires_python() {
        let f = file(
            "requests-2.31.0-py3-none-any.whl",
            Some("abc123def"),
            Some(">=3.7"),
        );
        let html = build_html(
            vec![entry("2.31.0", vec![f])],
            "requests",
            "/pypi/m/simple/requests",
        );
        assert!(
            html.contains(
                "<a href=\"/pypi/m/simple/requests/requests-2.31.0-py3-none-any.whl#sha256=abc123def\""
            ),
            "anchor must embed base_url + filename + sha256 fragment: {html}"
        );
        // `>` is HTML-escaped to `&gt;` per html_escape_attr.
        assert!(
            html.contains("data-requires-python=\"&gt;=3.7\""),
            "requires-python attribute must render HTML-escaped: {html}"
        );
        // `metadata_hash = None` (default in `file()`) → no PEP 658
        // attribute.
        assert!(
            !html.contains("data-dist-info-metadata"),
            "metadata_hash=None must omit the PEP 658 attribute: {html}"
        );
    }

    // -----------------------------------------------------------------
    // HTML — absent hash → no fragment; absent requires-python → no
    // attribute
    // -----------------------------------------------------------------

    #[test]
    fn html_absent_hash_omits_sha256_fragment() {
        let f = file("requests-2.31.0.tar.gz", None, None);
        let html = build_html(
            vec![entry("2.31.0", vec![f])],
            "requests",
            "/pypi/m/simple/requests",
        );
        assert!(
            !html.contains("#sha256="),
            "absent hash must NOT emit sha256 URL fragment: {html}"
        );
        assert!(
            !html.contains("data-requires-python"),
            "absent requires-python must NOT emit data-* attr: {html}"
        );
        // The filename anchor still renders.
        assert!(html.contains("requests-2.31.0.tar.gz"));
    }

    // -----------------------------------------------------------------
    // HTML — multiple files per version (sdist + wheel) emit one
    // anchor each
    // -----------------------------------------------------------------

    #[test]
    fn html_multi_file_version_emits_one_anchor_per_file() {
        let entry = entry(
            "2.31.0",
            vec![
                file("requests-2.31.0.tar.gz", Some("h1"), None),
                file(
                    "requests-2.31.0-py3-none-any.whl",
                    Some("h2"),
                    Some(">=3.7"),
                ),
            ],
        );
        let html = build_html(vec![entry], "requests", "/pypi/m/simple/requests");
        assert!(html.contains("requests-2.31.0.tar.gz#sha256=h1"));
        assert!(
            html.contains("requests-2.31.0-py3-none-any.whl#sha256=h2"),
            "wheel anchor must render alongside sdist anchor: {html}"
        );
        // Two anchors total.
        assert_eq!(html.matches("<a ").count(), 2);
    }

    // -----------------------------------------------------------------
    // HTML — HTML-escapes the `requires_python` attribute value
    // -----------------------------------------------------------------

    #[test]
    fn html_escapes_attribute_special_chars_in_requires_python() {
        let f = file("evil-1.0.tar.gz", None, Some(">=3.7,<\"x\"&'y'"));
        let html = build_html(vec![entry("1.0", vec![f])], "evil", "/pypi/m/simple/evil");
        assert!(html.contains("&quot;"));
        assert!(html.contains("&amp;"));
        assert!(html.contains("&#39;"));
        assert!(
            !html.contains("data-requires-python=\">=3.7,<\""),
            "raw < or \" must not leak through"
        );
    }

    // -----------------------------------------------------------------
    // JSON — empty set
    // -----------------------------------------------------------------

    #[test]
    fn json_empty_entries_emits_pep700_shape_with_empty_arrays() {
        let json = build_json(Vec::new(), "requests", "/pypi/m/simple/requests");
        assert_eq!(json["meta"]["api-version"].as_str().unwrap(), "1.1");
        assert_eq!(json["name"].as_str().unwrap(), "requests");
        assert!(json["files"].as_array().unwrap().is_empty());
        assert!(json["versions"].as_array().unwrap().is_empty());
    }

    // -----------------------------------------------------------------
    // JSON — single file, all fields
    // -----------------------------------------------------------------

    #[test]
    fn json_single_file_emits_full_row_with_hashes_and_requires_python() {
        let f = file(
            "requests-2.31.0-py3-none-any.whl",
            Some("abc123def"),
            Some(">=3.7"),
        );
        let json = build_json(
            vec![entry("2.31.0", vec![f])],
            "requests",
            "/pypi/m/simple/requests",
        );
        let row = &json["files"][0];
        assert_eq!(
            row["filename"].as_str().unwrap(),
            "requests-2.31.0-py3-none-any.whl"
        );
        assert_eq!(
            row["url"].as_str().unwrap(),
            "/pypi/m/simple/requests/requests-2.31.0-py3-none-any.whl"
        );
        assert_eq!(row["hashes"]["sha256"].as_str().unwrap(), "abc123def");
        assert_eq!(row["requires-python"].as_str().unwrap(), ">=3.7");
        // `metadata_hash = None` (default in `file()`) → PEP 691
        // "no metadata available" (`"dist-info-metadata": false`).
        assert_eq!(
            row["dist-info-metadata"],
            serde_json::Value::Bool(false),
            "metadata_hash=None must emit `dist-info-metadata: false`: {row}"
        );
        // versions[] carries the single version.
        let versions = json["versions"].as_array().unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].as_str().unwrap(), "2.31.0");
    }

    // -----------------------------------------------------------------
    // JSON — absent hash → empty `hashes{}` object; absent
    // requires-python → key absent
    // -----------------------------------------------------------------

    #[test]
    fn json_absent_hash_emits_empty_hashes_object_and_omits_requires_python() {
        let f = file("requests-2.31.0.tar.gz", None, None);
        let json = build_json(
            vec![entry("2.31.0", vec![f])],
            "requests",
            "/pypi/m/simple/requests",
        );
        let row = &json["files"][0];
        let hashes = row["hashes"].as_object().unwrap();
        assert!(
            hashes.is_empty(),
            "absent hash must emit an empty hashes{{}} object"
        );
        assert!(
            row.get("requires-python").is_none(),
            "absent requires-python must NOT be emitted: {row:?}"
        );
    }

    // -----------------------------------------------------------------
    // JSON — multiple files within a single version → multiple rows
    // -----------------------------------------------------------------

    #[test]
    fn json_multi_file_version_emits_one_row_per_file() {
        let entry = entry(
            "2.31.0",
            vec![
                file("requests-2.31.0.tar.gz", Some("h1"), None),
                file(
                    "requests-2.31.0-py3-none-any.whl",
                    Some("h2"),
                    Some(">=3.7"),
                ),
            ],
        );
        let json = build_json(vec![entry], "requests", "/pypi/m/simple/requests");
        let files = json["files"].as_array().unwrap();
        assert_eq!(files.len(), 2);
    }

    // -----------------------------------------------------------------
    // JSON — versions[] is sorted by PEP 440, NOT lex. Pins ordering
    // hooked correctly.
    // -----------------------------------------------------------------

    #[test]
    fn json_versions_array_sorted_pep440_not_lex() {
        let entries = vec![
            entry("1.9", vec![file("p-1.9.tar.gz", None, None)]),
            entry("1.10", vec![file("p-1.10.tar.gz", None, None)]),
            entry("1.2", vec![file("p-1.2.tar.gz", None, None)]),
        ];
        let json = build_json(entries, "p", "/pypi/m/simple/p");
        let versions: Vec<&str> = json["versions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        // Under PEP 440: 1.2 < 1.9 < 1.10 (since "10" > "9" numerically,
        // not lexicographically — lex would put 1.10 before 1.9 because
        // "10" < "9" character-wise).
        assert_eq!(
            versions,
            vec!["1.2", "1.9", "1.10"],
            "versions[] must be sorted under PEP 440, not lex"
        );
    }

    // -----------------------------------------------------------------
    // JSON — versions array dedupes (a version with multiple files
    // appears once, not once per file)
    // -----------------------------------------------------------------

    #[test]
    fn json_versions_array_dedupes_one_entry_per_version() {
        let entry = entry(
            "2.31.0",
            vec![
                file("requests-2.31.0.tar.gz", None, None),
                file("requests-2.31.0-py3-none-any.whl", None, None),
            ],
        );
        let json = build_json(vec![entry], "requests", "/pypi/m/simple/requests");
        let versions = json["versions"].as_array().unwrap();
        assert_eq!(
            versions.len(),
            1,
            "a version with multiple files appears once in versions[]: {versions:?}",
        );
    }

    // -----------------------------------------------------------------
    // URL construction comes ONLY from base_url + filename, never
    // leaks an upstream host (mirrors npm builder's equivalent pin).
    // -----------------------------------------------------------------

    #[test]
    fn json_url_construction_uses_base_url_and_filename_never_raw_upstream() {
        let f = file("requests-2.31.0.tar.gz", Some("h"), None);
        let json = build_json(
            vec![entry("2.31.0", vec![f])],
            "requests",
            "http://localhost/pypi/m/simple/requests",
        );
        let url = json["files"][0]["url"].as_str().unwrap();
        assert_eq!(
            url,
            "http://localhost/pypi/m/simple/requests/requests-2.31.0.tar.gz"
        );
        assert!(
            !url.contains("files.pythonhosted.org"),
            "URL must NOT carry any upstream-host bytes: {url}"
        );
    }

    #[test]
    fn html_url_construction_uses_base_url_and_filename_never_raw_upstream() {
        let f = file("requests-2.31.0.tar.gz", Some("h"), None);
        let html = build_html(
            vec![entry("2.31.0", vec![f])],
            "requests",
            "http://localhost/pypi/m/simple/requests",
        );
        assert!(
            html.contains(
                "http://localhost/pypi/m/simple/requests/requests-2.31.0.tar.gz#sha256=h"
            ),
            "anchor must embed base_url + filename: {html}",
        );
        assert!(
            !html.contains("files.pythonhosted.org"),
            "anchor must NOT carry any upstream-host bytes: {html}"
        );
    }

    // -----------------------------------------------------------------
    // Top-level `name` reflects BuildContext.package_name verbatim
    // (drift-resilience pin — mirrors the npm builder's equivalent).
    // -----------------------------------------------------------------

    #[test]
    fn json_top_level_name_reflects_build_context_verbatim() {
        let f = file("legacy_name-1.0.tar.gz", None, None);
        let json = build_json(
            vec![entry("1.0", vec![f])],
            "legacy_name",
            "/pypi/m/simple/legacy_name",
        );
        assert_eq!(json["name"].as_str().unwrap(), "legacy_name");
    }

    #[test]
    fn html_top_level_title_reflects_build_context_verbatim() {
        let f = file("legacy_name-1.0.tar.gz", None, None);
        let html = build_html(
            vec![entry("1.0", vec![f])],
            "legacy_name",
            "/pypi/m/simple/legacy_name",
        );
        assert!(html.contains("<title>Links for legacy_name</title>"));
        assert!(html.contains("<h1>Links for legacy_name</h1>"));
    }

    // -----------------------------------------------------------------
    // Cross-format mis-tag — feeding a Npm payload to a Pypi builder
    // is skipped with a warn (the entry vanishes from the output but
    // the builder does NOT panic). Defence-in-depth.
    // -----------------------------------------------------------------

    #[test]
    fn html_cross_format_mistag_npm_payload_is_skipped() {
        use hort_app::use_cases::index_serve::NpmVersionPayload;
        let npm_payload = NpmVersionPayload {
            name_as_published: "npm-foreign".into(),
            tarball_basename: "npm-foreign-1.0.0.tgz".into(),
            integrity: None,
            shasum: "x".into(),
        };
        let mistagged = VersionEntry {
            version: "1.0.0".into(),
            status: Some(QuarantineStatus::Released),
            payload: PerVersionPayload::Npm(npm_payload),
        };
        let html = build_html(vec![mistagged], "requests", "/pypi/m/simple/requests");
        // Anchor is NOT emitted — npm payload skipped.
        assert!(!html.contains("npm-foreign"));
    }

    #[test]
    fn json_cross_format_mistag_npm_payload_is_skipped() {
        use hort_app::use_cases::index_serve::NpmVersionPayload;
        let npm_payload = NpmVersionPayload {
            name_as_published: "npm-foreign".into(),
            tarball_basename: "npm-foreign-1.0.0.tgz".into(),
            integrity: None,
            shasum: "x".into(),
        };
        let mistagged = VersionEntry {
            version: "1.0.0".into(),
            status: Some(QuarantineStatus::Released),
            payload: PerVersionPayload::Npm(npm_payload),
        };
        let json = build_json(vec![mistagged], "requests", "/pypi/m/simple/requests");
        // `files[]` is empty (npm payload skipped); `versions[]` still
        // carries the entry's version (the version derivation runs off
        // the spine, not the payload).
        assert!(json["files"].as_array().unwrap().is_empty());
        let versions = json["versions"].as_array().unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].as_str().unwrap(), "1.0.0");
    }

    // -----------------------------------------------------------------
    // PEP 658 emission tests (HTML)
    //
    // `data-dist-info-metadata` is emitted as `sha256=<hex>` only
    // when the source populated `metadata_hash`. Sdists never carry
    // it (PEP 658 is wheels-only per the spec).
    // -----------------------------------------------------------------

    #[test]
    fn html_wheel_with_metadata_hash_emits_pep658_attribute() {
        let f = file_with_metadata_hash(
            "example-1.0.0-py3-none-any.whl",
            Some("aaaa"),
            None,
            METADATA_HASH_HEX,
        );
        let html = build_html(
            vec![entry("1.0.0", vec![f])],
            "example",
            "/pypi/m/simple/example",
        );
        let expected = format!("data-dist-info-metadata=\"sha256={METADATA_HASH_HEX}\"");
        assert!(
            html.contains(&expected),
            "wheel with Some(hash) must advertise PEP 658 sha256: {html}"
        );
    }

    #[test]
    fn html_wheel_without_metadata_hash_omits_pep658_attribute() {
        // `None` → attribute OMITTED, NOT `="true"`.
        let f = file("example-1.0.0-py3-none-any.whl", Some("aaaa"), None);
        let html = build_html(
            vec![entry("1.0.0", vec![f])],
            "example",
            "/pypi/m/simple/example",
        );
        assert!(
            !html.contains("data-dist-info-metadata"),
            "wheel with metadata_hash=None must NOT emit any PEP 658 \
             attribute (pip falls back to whole-wheel download): {html}"
        );
    }

    #[test]
    fn html_sdist_omits_pep658_attribute_even_when_metadata_hash_set() {
        // PEP 658 is wheels-only per the spec. The builder is
        // payload-agnostic about file type — the source is responsible
        // for never populating `metadata_hash` on a sdist row. But
        // even if a misbehaved source did, sdists in the wild don't
        // declare a `.dist-info/METADATA` file the endpoint could
        // serve, so the attribute is meaningless. Defence-in-depth
        // would skip it; in this codebase the source ALWAYS leaves
        // sdists with `None` (Item 6's HostedPypiSource batched
        // lookup keys on the wheel-only ContentReference rows), so
        // the no-attribute branch is what fires for sdists in
        // production. Test the production path: sdist with default
        // None → no attribute.
        let f = file("example-1.0.0.tar.gz", Some("aaaa"), None);
        let html = build_html(
            vec![entry("1.0.0", vec![f])],
            "example",
            "/pypi/m/simple/example",
        );
        assert!(
            !html.contains("data-dist-info-metadata"),
            "sdist must NOT advertise PEP 658 (wheels-only per spec): {html}"
        );
    }

    // -----------------------------------------------------------------
    // PEP 658 emission tests (JSON)
    // -----------------------------------------------------------------

    #[test]
    fn json_wheel_with_metadata_hash_emits_dist_info_metadata_object() {
        let f = file_with_metadata_hash(
            "example-1.0.0-py3-none-any.whl",
            Some("aaaa"),
            None,
            METADATA_HASH_HEX,
        );
        let json = build_json(
            vec![entry("1.0.0", vec![f])],
            "example",
            "/pypi/m/simple/example",
        );
        let row = &json["files"][0];
        // PEP 691 — `"dist-info-metadata": {"sha256": "<hex>"}`
        // shape. Not `true`, not `false`, not the integer 1 — the
        // exact JSON object.
        let dim = row.get("dist-info-metadata").expect("field present");
        let obj = dim.as_object().expect("dist-info-metadata is an object");
        assert_eq!(
            obj.get("sha256").and_then(|v| v.as_str()),
            Some(METADATA_HASH_HEX),
            "expected sha256 in dist-info-metadata: {row}"
        );
    }

    #[test]
    fn json_wheel_without_metadata_hash_emits_dist_info_metadata_false() {
        // Per PEP 691 — `false` is the wire shape for "no metadata
        // file available."
        let f = file("example-1.0.0-py3-none-any.whl", Some("aaaa"), None);
        let json = build_json(
            vec![entry("1.0.0", vec![f])],
            "example",
            "/pypi/m/simple/example",
        );
        let row = &json["files"][0];
        assert_eq!(
            row["dist-info-metadata"],
            serde_json::Value::Bool(false),
            "wheel without metadata_hash must emit `dist-info-metadata: false`: {row}"
        );
    }

    #[test]
    fn json_sdist_emits_dist_info_metadata_false() {
        // Sdists' production-path source always leaves `metadata_hash
        // = None` (PEP 658 is wheels-only; the source's batched
        // ContentReference lookup never returns rows for sdists). The
        // builder therefore emits `false` for every sdist row, by
        // construction.
        let f = file("example-1.0.0.tar.gz", Some("aaaa"), None);
        let json = build_json(
            vec![entry("1.0.0", vec![f])],
            "example",
            "/pypi/m/simple/example",
        );
        let row = &json["files"][0];
        assert_eq!(
            row["dist-info-metadata"],
            serde_json::Value::Bool(false),
            "sdist must emit `dist-info-metadata: false` (PEP 658 is wheels-only): {row}"
        );
    }
}
