//! PyPI streaming projectors (see ADR 0026).
//!
//! Streaming `Visitor::visit_seq` over the PEP 691 `files[]` array in
//! the simple-index endpoint.
//!
//! **Shape note.** The consumer that drives the serve path —
//! `ProxyPypiSource::fetch` — fetches the PEP 691 simple-index `files[]`
//! array shape. The `releases{}` map shape (matching PyPI's
//! `/pypi/<pkg>/json` endpoint) lives in `prefetch_ingest`. Same
//! architectural pattern (DTO with `IgnoredAny`, custom `Visitor`,
//! per-value cap via `CountingReader`); the streamed container here is
//! a seq rather than a map.
//!
//! # Two distinct PyPI upstream endpoints, two projectors
//!
//! PyPI proxying touches TWO upstream shapes, and this module carries a
//! projector for each:
//!
//! - [`PypiSimpleIndexProjector`] — the **simple-index** endpoint
//!   (`/simple/{name}/`), PEP 691 JSON `files[]`. Drives the serve path
//!   (`ProxyPypiSource::fetch`).
//! - [`PypiVersionJsonProjector`] — the **per-version** endpoint
//!   (`/pypi/{normalized}/{version}/json`), the project JSON API's
//!   `urls[]` array. This is the ONLY upstream source of the
//!   `digests.sha256` (upstream checksum, see ADR 0006 §7), the absolute
//!   genuine upstream file `url`, and the per-file
//!   `upload_time_iso_8601`. Drives the tarball-pull
//!   (`try_upstream_file_pull`) and prefetch (`prefetch_pypi_version`).

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::de::{Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::upstream_proxy::{CountingReader, MetadataProjector};

/// Project-out shape returned by [`PypiSimpleIndexProjector`].
///
/// Derives `Serialize`/`Deserialize` so the PyPI serve path can cache the
/// **projection** in the ephemeral store instead of the raw simple-index
/// body. The raw body lives in the
/// [`MetadataMirrorStore`](hort_domain::ports::metadata_mirror_store);
/// the projection round-trips through serde. Both the PEP 503 HTML arm
/// (projected via the regex `parse_html_to_entries` path) and the PEP
/// 691 JSON arm (projected via this projector) produce this SAME
/// representation-independent projection, so the serve cache is unified
/// to one format-independent key.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PypiSimpleIndexProjection {
    pub files: Vec<PypiSimpleFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PypiSimpleFile {
    pub filename: Option<String>,
    pub url: Option<String>,
    /// `hashes.sha256` — load-bearing for upstream-checksum verification
    /// (see ADR 0006 §7).
    pub sha256: Option<String>,
    pub requires_python: Option<String>,
    /// `dist-info-metadata.sha256` — PEP 658 hash advertisement. The
    /// simple-index JSON shape carries it as a nested
    /// `{"sha256": "<hex>"}` map; the projector flattens.
    pub metadata_sha256: Option<String>,
}

/// Streaming projector instance. Carries the per-file cap (§10.3
/// default 2 MiB).
pub struct PypiSimpleIndexProjector {
    per_value_object_max_bytes: u64,
    /// Set `true` iff a per-file-object cap trip aborted the projection
    /// (vs. a generic malformed-JSON parse error). The consumer grabs
    /// the handle via [`Self::cap_trip_flag`] before `project` consumes
    /// `self`, then emits
    /// `hort_upstream_fetch_total{result="version_object_too_large"}` on
    /// a trip.
    cap_tripped: Arc<AtomicBool>,
}

impl PypiSimpleIndexProjector {
    pub fn new(per_value_object_max_bytes: u64) -> Self {
        Self {
            per_value_object_max_bytes,
            cap_tripped: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Shared handle to the per-file cap-trip flag. See
    /// [`crate::npm::projection::NpmPackumentProjector::cap_trip_flag`].
    pub fn cap_trip_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cap_tripped)
    }
}

impl MetadataProjector for PypiSimpleIndexProjector {
    type Projection = PypiSimpleIndexProjection;
    fn project<R: std::io::Read>(self, reader: R) -> DomainResult<PypiSimpleIndexProjection> {
        let counting = CountingReader::new(reader);
        let counter = counting.counter();
        let mut de = serde_json::Deserializer::from_reader(counting);
        let visitor = TopVisitor {
            counter,
            cap: self.per_value_object_max_bytes,
            cap_tripped: Arc::clone(&self.cap_tripped),
        };
        de.deserialize_map(visitor)
            .map_err(|e| DomainError::Validation(format!("pypi simple-index parse: {e}")))
    }
}

struct TopVisitor {
    counter: Arc<AtomicU64>,
    cap: u64,
    cap_tripped: Arc<AtomicBool>,
}

impl<'de> Visitor<'de> for TopVisitor {
    type Value = PypiSimpleIndexProjection;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a PEP 691 PyPI simple-index JSON object")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut files: Vec<PypiSimpleFile> = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "files" => {
                    files = map.next_value_seed(FilesSeed {
                        counter: Arc::clone(&self.counter),
                        cap: self.cap,
                        cap_tripped: Arc::clone(&self.cap_tripped),
                    })?;
                }
                _ => {
                    let _: IgnoredAny = map.next_value()?;
                }
            }
        }
        Ok(PypiSimpleIndexProjection { files })
    }
}

struct FilesSeed {
    counter: Arc<AtomicU64>,
    cap: u64,
    cap_tripped: Arc<AtomicBool>,
}

impl<'de> serde::de::DeserializeSeed<'de> for FilesSeed {
    type Value = Vec<PypiSimpleFile>;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_seq(FilesVisitor {
            counter: self.counter,
            cap: self.cap,
            cap_tripped: self.cap_tripped,
        })
    }
}

struct FilesVisitor {
    counter: Arc<AtomicU64>,
    cap: u64,
    cap_tripped: Arc<AtomicBool>,
}

impl<'de> Visitor<'de> for FilesVisitor {
    type Value = Vec<PypiSimpleFile>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the PyPI simple-index `files[]` array")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut out = Vec::new();
        // Per-file-object cap. Sample the `CountingReader` byte counter
        // before and after each element so the delta approximates that
        // element's wire size (the same tight-enough approximation the
        // npm `versions{}` map visitor uses). PEP 691 file entries are
        // ~1 KB in practice, far under the 2 MiB default, so the cap
        // is non-load-bearing on legitimate bodies.
        loop {
            let before = self.counter.load(Ordering::Relaxed);
            let Some(file) = seq.next_element_seed(FileEntrySeed)? else {
                break;
            };
            let after = self.counter.load(Ordering::Relaxed);
            let delta = after.saturating_sub(before);
            if delta > self.cap {
                self.cap_tripped.store(true, Ordering::Relaxed);
                return Err(serde::de::Error::custom(format!(
                    "pypi file-object too large: bytes_read={delta}, cap={cap}",
                    cap = self.cap,
                )));
            }
            out.push(file);
        }
        Ok(out)
    }
}

struct FileEntrySeed;

impl<'de> serde::de::DeserializeSeed<'de> for FileEntrySeed {
    type Value = PypiSimpleFile;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        let wire = FileWire::deserialize(deserializer)?;
        // PEP 691 admits three shapes for `dist-info-metadata`:
        //   - `{"sha256": "<hex>"}` — extract the hash;
        //   - `true` — "available, no integrity" — discard;
        //   - `false` / absent — no metadata — discard.
        // Treating `dist_info_metadata` as a raw `Value` lets the
        // projector accepts all three without failing the whole-body
        // parse.
        let metadata_sha256 = wire
            .dist_info_metadata
            .as_ref()
            .and_then(|v| v.get("sha256"))
            .and_then(|s| s.as_str())
            .map(str::to_string);
        Ok(PypiSimpleFile {
            filename: wire.filename,
            url: wire.url,
            sha256: wire.hashes.as_ref().and_then(|h| h.sha256.clone()),
            requires_python: wire.requires_python,
            metadata_sha256,
        })
    }
}

#[derive(Deserialize)]
struct FileWire {
    filename: Option<String>,
    url: Option<String>,
    hashes: Option<HashesWire>,
    #[serde(rename = "requires-python")]
    requires_python: Option<String>,
    #[serde(rename = "dist-info-metadata")]
    dist_info_metadata: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct HashesWire {
    sha256: Option<String>,
}

// ===========================================================================
// Per-version JSON projector — `/pypi/{name}/{version}/json`
// ===========================================================================

/// Project-out shape returned by [`PypiVersionJsonProjector`] for the
/// PyPI per-version JSON API (`/pypi/{normalized}/{version}/json`).
///
/// This endpoint is DISTINCT from the simple-index (`/simple/{name}/`):
/// it is the ONLY source of the per-file `digests.sha256` (upstream
/// checksum, see ADR 0006 §7), the absolute genuine upstream file `url`,
/// and the per-file `upload_time_iso_8601`. The tarball-pull orchestrator
/// (`try_upstream_file_pull`) recovers all three from this projection —
/// no raw body required.
///
/// `Serialize`/`Deserialize` so the consumer can round-trip the
/// projection through the `PullDedup::coalesce_metadata` window (the
/// closure returns the serialized projection so followers receive the
/// small projection, not the raw per-version JSON body).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PypiVersionJsonProjection {
    pub files: Vec<PypiVersionFileInfo>,
}

impl PypiVersionJsonProjection {
    /// Find the `urls[]` entry whose `filename` matches `filename`
    /// exactly (no case-folding — wheels/sdists are case-sensitive on
    /// disk; PEP 503 normalisation applies to project names, not
    /// filenames). Mirrors the lookup `parse_upstream_checksum` /
    /// `extract_upstream_file_url` / `extract_upstream_publish_time`
    /// performed against the raw body.
    pub fn file_for(&self, filename: &str) -> Option<&PypiVersionFileInfo> {
        self.files
            .iter()
            .find(|f| f.filename.as_deref() == Some(filename))
    }
}

/// One per-file entry projected out of a PyPI per-version JSON `urls[]`
/// array.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PypiVersionFileInfo {
    /// `urls[i].filename` — the distribution filename (wheel or sdist).
    pub filename: Option<String>,
    /// `urls[i].url` — the absolute genuine upstream file URL. Captured
    /// verbatim; the `https://` guard is enforced by the consumer
    /// (mirroring `extract_upstream_file_url`).
    pub url: Option<String>,
    /// `urls[i].digests.sha256` — load-bearing for upstream-checksum
    /// verification (see ADR 0006). Captured verbatim (lowercased at
    /// verification time via the audited `parse_upstream_checksum`).
    pub sha256: Option<String>,
    /// `urls[i].upload_time_iso_8601` — upstream publish timestamp. Parsed
    /// to a UTC datetime at projection time; an unparseable / missing
    /// value is `None` (best-effort, never fails the projection).
    pub upload_time: Option<DateTime<Utc>>,
}

/// Streaming projector for the PyPI per-version JSON API body. Carries
/// the per-file-object cap (§10.3 default 2 MiB), like
/// [`PypiSimpleIndexProjector`].
pub struct PypiVersionJsonProjector {
    per_value_object_max_bytes: u64,
    cap_tripped: Arc<AtomicBool>,
}

impl PypiVersionJsonProjector {
    pub fn new(per_value_object_max_bytes: u64) -> Self {
        Self {
            per_value_object_max_bytes,
            cap_tripped: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Shared handle to the per-file cap-trip flag. See
    /// [`PypiSimpleIndexProjector::cap_trip_flag`].
    pub fn cap_trip_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cap_tripped)
    }
}

impl MetadataProjector for PypiVersionJsonProjector {
    type Projection = PypiVersionJsonProjection;
    fn project<R: std::io::Read>(self, reader: R) -> DomainResult<PypiVersionJsonProjection> {
        let counting = CountingReader::new(reader);
        let counter = counting.counter();
        let mut de = serde_json::Deserializer::from_reader(counting);
        let visitor = VersionTopVisitor {
            counter,
            cap: self.per_value_object_max_bytes,
            cap_tripped: Arc::clone(&self.cap_tripped),
        };
        de.deserialize_map(visitor)
            .map_err(|e| DomainError::Validation(format!("pypi per-version JSON parse: {e}")))
    }
}

struct VersionTopVisitor {
    counter: Arc<AtomicU64>,
    cap: u64,
    cap_tripped: Arc<AtomicBool>,
}

impl<'de> Visitor<'de> for VersionTopVisitor {
    type Value = PypiVersionJsonProjection;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a PyPI per-version JSON API object")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut files: Vec<PypiVersionFileInfo> = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "urls" => {
                    files = map.next_value_seed(UrlsSeed {
                        counter: Arc::clone(&self.counter),
                        cap: self.cap,
                        cap_tripped: Arc::clone(&self.cap_tripped),
                    })?;
                }
                _ => {
                    let _: IgnoredAny = map.next_value()?;
                }
            }
        }
        Ok(PypiVersionJsonProjection { files })
    }
}

struct UrlsSeed {
    counter: Arc<AtomicU64>,
    cap: u64,
    cap_tripped: Arc<AtomicBool>,
}

impl<'de> serde::de::DeserializeSeed<'de> for UrlsSeed {
    type Value = Vec<PypiVersionFileInfo>;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_seq(UrlsVisitor {
            counter: self.counter,
            cap: self.cap,
            cap_tripped: self.cap_tripped,
        })
    }
}

struct UrlsVisitor {
    counter: Arc<AtomicU64>,
    cap: u64,
    cap_tripped: Arc<AtomicBool>,
}

impl<'de> Visitor<'de> for UrlsVisitor {
    type Value = Vec<PypiVersionFileInfo>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the PyPI per-version JSON `urls[]` array")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut out = Vec::new();
        // Per-file-object cap (mirrors `FilesVisitor`): sample the
        // `CountingReader` byte counter before/after each element so the
        // delta approximates that element's wire size. Defence-in-depth;
        // PyPI per-version `urls[]` entries are ~1 KB in practice.
        loop {
            let before = self.counter.load(Ordering::Relaxed);
            let Some(file) = seq.next_element_seed(UrlEntrySeed)? else {
                break;
            };
            let after = self.counter.load(Ordering::Relaxed);
            let delta = after.saturating_sub(before);
            if delta > self.cap {
                self.cap_tripped.store(true, Ordering::Relaxed);
                return Err(serde::de::Error::custom(format!(
                    "pypi per-version url-object too large: bytes_read={delta}, cap={cap}",
                    cap = self.cap,
                )));
            }
            out.push(file);
        }
        Ok(out)
    }
}

struct UrlEntrySeed;

impl<'de> serde::de::DeserializeSeed<'de> for UrlEntrySeed {
    type Value = PypiVersionFileInfo;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        let wire = UrlWire::deserialize(deserializer)?;
        // Parse `upload_time_iso_8601` to a UTC datetime at projection
        // time. Best-effort: an unparseable string degrades to `None`,
        // never failing the whole-body projection.
        let upload_time = wire
            .upload_time_iso_8601
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc));
        Ok(PypiVersionFileInfo {
            filename: wire.filename,
            url: wire.url,
            sha256: wire.digests.as_ref().and_then(|d| d.sha256.clone()),
            upload_time,
        })
    }
}

#[derive(Deserialize)]
struct UrlWire {
    filename: Option<String>,
    url: Option<String>,
    digests: Option<DigestsWire>,
    upload_time_iso_8601: Option<String>,
}

#[derive(Deserialize)]
struct DigestsWire {
    sha256: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn project(body: &[u8]) -> DomainResult<PypiSimpleIndexProjection> {
        PypiSimpleIndexProjector::new(2 * 1024 * 1024).project(Cursor::new(body))
    }

    #[test]
    fn empty_files_yields_empty_projection() {
        let p = project(br#"{"files":[],"meta":{}}"#).unwrap();
        assert!(p.files.is_empty());
    }

    #[test]
    fn files_round_trip_filename_url_sha256_requires_python() {
        let body = br#"{
            "files": [
                {
                    "filename": "foo-1.0.0-py3-none-any.whl",
                    "url": "https://files.pythonhosted.org/packages/.../foo-1.0.0-py3-none-any.whl",
                    "hashes": {"sha256": "abc123"},
                    "requires-python": ">=3.8"
                }
            ]
        }"#;
        let p = project(body).unwrap();
        assert_eq!(p.files.len(), 1);
        let f = &p.files[0];
        assert_eq!(f.filename.as_deref(), Some("foo-1.0.0-py3-none-any.whl"));
        assert!(f.url.as_ref().unwrap().contains("foo-1.0.0"));
        assert_eq!(f.sha256.as_deref(), Some("abc123"));
        assert_eq!(f.requires_python.as_deref(), Some(">=3.8"));
    }

    #[test]
    fn dist_info_metadata_sha256_round_trip() {
        // PEP 658 advertisement — I-3 analogue for PyPI.
        let body = br#"{
            "files": [{
                "filename": "x-1.0-py3-none-any.whl",
                "dist-info-metadata": {"sha256": "deadbeef"}
            }]
        }"#;
        let p = project(body).unwrap();
        assert_eq!(p.files[0].metadata_sha256.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn ignored_root_fields_skip() {
        let body = br#"{
            "meta": {"api-version": "1.0"},
            "name": "foo",
            "versions": ["1.0.0"],
            "files": [{"filename": "x.whl"}]
        }"#;
        let p = project(body).unwrap();
        assert_eq!(p.files.len(), 1);
    }

    #[test]
    fn malformed_returns_validation() {
        let err = project(br#"{"files": INVALID}"#).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn per_file_object_cap_trips_and_sets_flag() {
        // I-6 — a single oversize file object trips the per-value cap;
        // the flag is set so the consumer emits
        // `version_object_too_large` rather than folding into a generic
        // parse failure.
        let huge = "x".repeat(8 * 1024);
        let body = format!(r#"{{"files":[{{"filename":"x.whl","url":"u","_pad":"{huge}"}}]}}"#);
        let projector = PypiSimpleIndexProjector::new(4 * 1024);
        let flag = projector.cap_trip_flag();
        let err = projector
            .project(Cursor::new(body.as_bytes()))
            .expect_err("oversize file object");
        assert!(matches!(err, DomainError::Validation(msg) if msg.contains("too large")));
        assert!(
            flag.load(Ordering::Relaxed),
            "per-file cap trip must set the cap-trip flag"
        );
    }

    #[test]
    fn small_files_pass_under_cap_without_tripping_flag() {
        let body =
            br#"{"files":[{"filename":"a.whl","url":"u1"},{"filename":"b.whl","url":"u2"}]}"#;
        let projector = PypiSimpleIndexProjector::new(2 * 1024 * 1024);
        let flag = projector.cap_trip_flag();
        let p = projector.project(Cursor::new(&body[..])).expect("project");
        assert_eq!(p.files.len(), 2);
        assert!(
            !flag.load(Ordering::Relaxed),
            "files under the cap must not trip the flag"
        );
    }

    // ----------------------------------------------------------------------
    // Per-version JSON projector (see ADR 0026)
    // ----------------------------------------------------------------------

    fn project_version(body: &[u8]) -> DomainResult<PypiVersionJsonProjection> {
        PypiVersionJsonProjector::new(2 * 1024 * 1024).project(Cursor::new(body))
    }

    #[test]
    fn version_json_round_trips_filename_url_sha256_upload_time() {
        // All three load-bearing fields project off the `urls[]` entry:
        // url, digests.sha256, upload_time_iso_8601.
        let body = br#"{
            "info": {"name": "foo"},
            "urls": [
                {
                    "filename": "foo-1.0.0-py3-none-any.whl",
                    "url": "https://files.pythonhosted.org/packages/ab/cd/foo-1.0.0-py3-none-any.whl",
                    "digests": {"sha256": "abc123", "md5": "ignored"},
                    "upload_time_iso_8601": "2024-01-02T03:04:05.123456Z"
                }
            ]
        }"#;
        let p = project_version(body).unwrap();
        assert_eq!(p.files.len(), 1);
        let f = &p.files[0];
        assert_eq!(f.filename.as_deref(), Some("foo-1.0.0-py3-none-any.whl"));
        assert_eq!(
            f.url.as_deref(),
            Some("https://files.pythonhosted.org/packages/ab/cd/foo-1.0.0-py3-none-any.whl")
        );
        assert_eq!(f.sha256.as_deref(), Some("abc123"));
        let dt = f.upload_time.expect("upload_time parsed");
        assert_eq!(dt.to_rfc3339(), "2024-01-02T03:04:05.123456+00:00");
    }

    #[test]
    fn version_json_file_for_matches_exact_filename() {
        // A release has multiple `urls[]` entries (sdist + wheels); the
        // lookup MUST filename-match exactly, not pick the first entry.
        let body = br#"{
            "urls": [
                {"filename": "foo-1.0.tar.gz", "url": "https://h/foo-1.0.tar.gz", "digests": {"sha256": "sdist256"}},
                {"filename": "foo-1.0-py3-none-any.whl", "url": "https://h/foo-1.0-py3-none-any.whl", "digests": {"sha256": "wheel256"}}
            ]
        }"#;
        let p = project_version(body).unwrap();
        let wheel = p.file_for("foo-1.0-py3-none-any.whl").expect("wheel entry");
        assert_eq!(wheel.sha256.as_deref(), Some("wheel256"));
        let sdist = p.file_for("foo-1.0.tar.gz").expect("sdist entry");
        assert_eq!(sdist.sha256.as_deref(), Some("sdist256"));
        assert!(p.file_for("foo-9.9.tar.gz").is_none());
    }

    #[test]
    fn version_json_unparseable_upload_time_degrades_to_none() {
        // Best-effort: an unparseable timestamp must not fail the whole
        // projection (mirrors the retired `extract_upstream_publish_time`).
        let body = br#"{
            "urls": [{"filename": "x.whl", "url": "https://h/x.whl", "digests": {"sha256": "h"}, "upload_time_iso_8601": "not-a-date"}]
        }"#;
        let p = project_version(body).unwrap();
        assert_eq!(p.files.len(), 1);
        assert!(p.files[0].upload_time.is_none());
        // The other fields still project.
        assert_eq!(p.files[0].sha256.as_deref(), Some("h"));
    }

    #[test]
    fn version_json_md5_only_digest_yields_none_sha256() {
        // A legacy md5-only release projects with `sha256: None`; the
        // consumer's audited checksum path rejects it as Validation.
        let body = br#"{
            "urls": [{"filename": "x.whl", "url": "https://h/x.whl", "digests": {"md5": "deadbeef"}}]
        }"#;
        let p = project_version(body).unwrap();
        assert_eq!(p.files.len(), 1);
        assert!(p.files[0].sha256.is_none());
    }

    #[test]
    fn version_json_empty_urls_yields_empty_projection() {
        let p = project_version(br#"{"urls": [], "info": {}}"#).unwrap();
        assert!(p.files.is_empty());
    }

    #[test]
    fn version_json_ignored_root_fields_skip() {
        let body = br#"{
            "info": {"name": "foo", "summary": "x"},
            "last_serial": 123,
            "vulnerabilities": [],
            "urls": [{"filename": "x.whl", "url": "https://h/x.whl", "digests": {"sha256": "h"}}]
        }"#;
        let p = project_version(body).unwrap();
        assert_eq!(p.files.len(), 1);
    }

    #[test]
    fn version_json_malformed_returns_validation() {
        let err = project_version(br#"{"urls": NOPE}"#).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn version_json_per_file_object_cap_trips_and_sets_flag() {
        let huge = "x".repeat(8 * 1024);
        let body = format!(
            r#"{{"urls":[{{"filename":"x.whl","url":"https://h/x.whl","_pad":"{huge}"}}]}}"#
        );
        let projector = PypiVersionJsonProjector::new(4 * 1024);
        let flag = projector.cap_trip_flag();
        let err = projector
            .project(Cursor::new(body.as_bytes()))
            .expect_err("oversize url object");
        assert!(matches!(err, DomainError::Validation(msg) if msg.contains("too large")));
        assert!(
            flag.load(Ordering::Relaxed),
            "per-file cap trip must set the cap-trip flag"
        );
    }
}
