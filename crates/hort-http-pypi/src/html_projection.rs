//! PyPI PEP 503 HTML simple-index projector (ADR 0026).
//!
//! The serve path caches a representation-independent
//! [`PypiSimpleIndexProjection`] for BOTH simple-index arms. The PEP 691
//! JSON arm already has a streaming
//! [`PypiSimpleIndexProjector`](hort_formats::pypi::projection::PypiSimpleIndexProjector);
//! this module adds the HTML arm. PyPI simple-index bodies are small
//! (~110 KB max in practice), so a streaming HTML parser is NOT
//! warranted — the projector buffers the body and runs the EXISTING
//! anchor-regex extraction the legacy
//! [`crate::index_source::parse_html_to_entries`]
//! used, producing the SAME [`PypiSimpleFile`] rows the JSON projector
//! emits. (The legacy `parse_html_to_entries` produced
//! `Vec<VersionEntry>` directly; here we produce the projection so it
//! round-trips through the cache, and the unified
//! [`crate::index_source::projection_to_entries`] maps it to entries for
//! either arm.)
//!
//! **Fail-closed (B5).** A body that exceeds `max_bytes`, or one that is
//! not valid UTF-8, is rejected as [`DomainError::Validation`] →
//! `parse_error` (NOT the network bucket). Individual unparseable anchors
//! degrade to "skipped" (the same non-fatal behaviour the legacy parser
//! had) — a single broken `<a>` must not blank the whole index.

use std::sync::LazyLock;

use regex::Regex;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::upstream_proxy::MetadataProjector;
use hort_formats::pypi::projection::{PypiSimpleFile, PypiSimpleIndexProjection};

/// Dedicated whole-body cap (2 MiB) for the buffered HTML simple-index
/// parse. PEP 503 HTML cannot be projected without materialising the body
/// (the anchor regex needs the whole string), so an unbounded read is an
/// OOM sink on a malicious/compromised upstream. PyPI simple-index bodies
/// are ~110 KB in practice; 2 MiB is generous headroom while still
/// bounding the buffer.
///
/// **Why a dedicated const, not the per-version-object knob
/// (`HORT_UPSTREAM_PROJECTOR_VERSION_OBJECT_MAX_SIZE`):** that knob is a
/// streaming-JSON per-value cap; an operator may legitimately raise it for
/// a large npm version object. Riding it here would silently enlarge this
/// HTML-body OOM surface as a side effect. This cap is fixed and
/// independent so the "bodies are small" assumption is *enforced*, not
/// coupled to an unrelated setting.
pub(crate) const HTML_SIMPLE_INDEX_MAX_BYTES: u64 = 2 * 1024 * 1024;

// Anchor + attribute regexes — the SAME set the legacy
// `index_source::parse_html_to_entries` used (kept here so the HTML arm
// projects to `PypiSimpleIndexProjection` instead of `VersionEntry`).
static FULL_ANCHOR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?s)<a\s+([^>]*)>(.*?)</a>"#).unwrap());
static HREF_ATTR_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"href="([^"]*)""#).unwrap());
static REQUIRES_PYTHON_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"data-requires-python="([^"]*)""#).unwrap());
static DIST_INFO_METADATA_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"data-dist-info-metadata="sha256=([a-f0-9]{64})""#).unwrap());

/// HTML simple-index projector. Buffers the body (PyPI simple-index
/// bodies are ~110 KB) and runs the anchor-regex extraction. Carries a
/// hard whole-body cap so an over-cap body fails closed (B5); production
/// always wires [`HTML_SIMPLE_INDEX_MAX_BYTES`] (2 MiB) — see
/// [`Self::with_default_cap`]. The `max_bytes` parameter exists so tests
/// can exercise the boundary at a small size.
pub(crate) struct HtmlSimpleIndexProjector {
    max_bytes: u64,
}

impl HtmlSimpleIndexProjector {
    pub(crate) fn new(max_bytes: u64) -> Self {
        Self { max_bytes }
    }

    /// The production constructor: a fixed 2 MiB whole-body cap
    /// ([`HTML_SIMPLE_INDEX_MAX_BYTES`]), independent of the configurable
    /// per-version-object knob. Every non-test caller uses this.
    pub(crate) fn with_default_cap() -> Self {
        Self::new(HTML_SIMPLE_INDEX_MAX_BYTES)
    }
}

impl MetadataProjector for HtmlSimpleIndexProjector {
    type Projection = PypiSimpleIndexProjection;

    fn project<R: std::io::Read>(self, mut reader: R) -> DomainResult<PypiSimpleIndexProjection> {
        use std::io::Read as _;
        // Buffer with a hard cap. `take(max_bytes + 1)` lets us detect an
        // over-cap body deterministically (read one byte past the cap).
        let mut buf = Vec::new();
        let limit = self.max_bytes.saturating_add(1);
        reader
            .by_ref()
            .take(limit)
            .read_to_end(&mut buf)
            .map_err(|e| DomainError::Validation(format!("pypi HTML simple-index read: {e}")))?;
        if buf.len() as u64 > self.max_bytes {
            return Err(DomainError::Validation(format!(
                "pypi HTML simple-index body exceeds the per-format cap of {} bytes",
                self.max_bytes
            )));
        }

        // Fail-closed on non-UTF-8 (B5): a binary/garbage body is a
        // content fault, not a "zero versions" answer.
        let html = std::str::from_utf8(&buf).map_err(|e| {
            DomainError::Validation(format!("pypi HTML simple-index not UTF-8: {e}"))
        })?;

        let mut files: Vec<PypiSimpleFile> = Vec::new();
        for caps in FULL_ANCHOR_RE.captures_iter(html) {
            let attrs = &caps[1];
            let Some(href_caps) = HREF_ATTR_RE.captures(attrs) else {
                continue;
            };
            let href = href_caps.get(1).map_or("", |m| m.as_str());
            if href.is_empty() {
                continue;
            }

            // Split the `#sha256=...` fragment from the URL path.
            let (url_path, fragment) = match href.find('#') {
                Some(pos) => (&href[..pos], &href[pos + 1..]),
                None => (href, ""),
            };
            let filename = url_path.rsplit('/').next().unwrap_or(url_path).to_string();
            if filename.is_empty() {
                continue;
            }

            // Hash: only the `sha256=` fragment form (PEP 503 §URL).
            let sha256 = fragment.strip_prefix("sha256=").map(str::to_string);

            let requires_python = REQUIRES_PYTHON_RE
                .captures(attrs)
                .and_then(|c| c.get(1))
                .map(|m| html_unescape_attr(m.as_str()));

            // PEP 658 advertisement — keep the upstream's
            // `data-dist-info-metadata="sha256=<hex>"` so the rebuilt
            // index still advertises the hash. Stored as the hex string
            // (the consumer parses it to a `ContentHash`).
            let metadata_sha256 = DIST_INFO_METADATA_RE
                .captures(attrs)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_string());

            files.push(PypiSimpleFile {
                filename: Some(filename),
                // HTML anchors carry no genuine upstream `url` field (the
                // filename is what the rebuilt index needs); leave `None`.
                url: None,
                sha256,
                requires_python,
                metadata_sha256,
            });
        }

        Ok(PypiSimpleIndexProjection { files })
    }
}

/// HTML un-escape — the inverse of `html_escape_attr` in
/// `hort-formats::pypi::index`. Mirrors the legacy
/// `index_source::html_unescape_attr`: the builder emits HTML-escaped
/// attribute values, so parsing upstream HTML must un-escape to recover
/// the original PEP 503 `requires-python` string. Conservative — any
/// unrecognised entity passes through verbatim.
fn html_unescape_attr(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const CAP: u64 = 2 * 1024 * 1024;

    fn project(body: &[u8]) -> DomainResult<PypiSimpleIndexProjection> {
        HtmlSimpleIndexProjector::new(CAP).project(Cursor::new(body))
    }

    #[test]
    fn projects_anchor_filename_sha256_requires_python_metadata() {
        let html = r#"<!DOCTYPE html><html><body>
            <a href="https://files.pythonhosted.org/packages/ab/foo-1.0.0-py3-none-any.whl#sha256=abc123"
               data-requires-python="&gt;=3.8"
               data-dist-info-metadata="sha256=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff">foo-1.0.0-py3-none-any.whl</a>
            </body></html>"#;
        let p = project(html.as_bytes()).unwrap();
        assert_eq!(p.files.len(), 1);
        let f = &p.files[0];
        assert_eq!(f.filename.as_deref(), Some("foo-1.0.0-py3-none-any.whl"));
        assert_eq!(f.sha256.as_deref(), Some("abc123"));
        assert_eq!(f.requires_python.as_deref(), Some(">=3.8"));
        assert_eq!(
            f.metadata_sha256.as_deref(),
            Some("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
        );
        // HTML carries no genuine upstream url field.
        assert!(f.url.is_none());
    }

    #[test]
    fn skips_anchors_without_href_or_filename() {
        let html = r#"
            <a>no href</a>
            <a href="">empty</a>
            <a href="https://h/dir/">trailing slash basename empty</a>
            <a href="https://h/good-1.0.tar.gz#sha256=deadbeef">good</a>
        "#;
        let p = project(html.as_bytes()).unwrap();
        assert_eq!(p.files.len(), 1);
        assert_eq!(p.files[0].filename.as_deref(), Some("good-1.0.tar.gz"));
        assert_eq!(p.files[0].sha256.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn empty_html_yields_empty_projection() {
        let p = project(b"<html><body>no anchors</body></html>").unwrap();
        assert!(p.files.is_empty());
    }

    #[test]
    fn over_cap_body_fails_closed_validation() {
        // B5 — an over-cap body is a content fault → Validation, not a
        // silent empty answer.
        let projector = HtmlSimpleIndexProjector::new(64);
        let body = vec![b'a'; 256];
        let err = projector
            .project(Cursor::new(body))
            .expect_err("over-cap body");
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn non_utf8_body_fails_closed_validation() {
        // B5 — invalid UTF-8 is a content fault → Validation.
        let err = project(&[0xff, 0xfe, 0x00, 0x01]).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn body_at_cap_boundary_accepted() {
        // Exactly `max_bytes` is accepted (the over-cap check is `>`).
        let projector = HtmlSimpleIndexProjector::new(40);
        let body = b"<a href=\"https://h/a.whl\">a</a>".to_vec(); // < 40 bytes
        let p = projector.project(Cursor::new(body)).expect("at-cap body");
        assert_eq!(p.files.len(), 1);
    }

    #[test]
    fn default_cap_is_two_mib_and_enforced() {
        // The PRODUCTION cap is a fixed 2 MiB (independent of the
        // configurable per-version-object knob) — backs the "bodies are
        // small" assumption with a hard, dedicated bound. A body one byte
        // over fails closed.
        assert_eq!(HTML_SIMPLE_INDEX_MAX_BYTES, 2 * 1024 * 1024);
        let body = vec![b'a'; (HTML_SIMPLE_INDEX_MAX_BYTES + 1) as usize];
        let err = HtmlSimpleIndexProjector::with_default_cap()
            .project(Cursor::new(body))
            .expect_err("a body one byte over the 2 MiB default cap must fail closed");
        assert!(matches!(err, DomainError::Validation(_)));
    }
}
