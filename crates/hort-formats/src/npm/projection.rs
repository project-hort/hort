//! npm packument streaming projector (see ADR 0026).
//!
//! Reads the packument with `serde_json::Deserializer::from_reader`,
//! declares DTOs that name only the fields hort needs, and lets serde's
//! `deserialize_ignored_any` consume every other JSON token without
//! allocating. Memory bound during projection is the sum of the
//! emitted `NpmVersionEntry`s, not the body size.
//!
//! Refs:
//!  - serde.rs/stream-array.html (`Visitor::visit_map` streaming pattern,
//!    adapted to a JSON object instead of an array).
//!  - serde.rs/ignored-any.html (the skip-without-allocating mechanism).
//!  - ADR 0026 streaming projection contract.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::de::{Deserializer, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Serialize};

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::upstream_proxy::{CountingReader, MetadataProjector};

use crate::npm::NPM_INSTALL_V1_MANIFEST_KEYS;

// ---------------------------------------------------------------------------
// Projection — what consumers see
// ---------------------------------------------------------------------------

/// Project-out shape returned by [`NpmPackumentProjector`].
///
/// Fields are exactly what `ProxyNpmSource::fetch` +
/// `fire_prefetch_trigger_npm` need from a packument — including the
/// install-v1 abbreviated-metadata whitelist per version; everything else
/// (`readme`, `_attachments`, `description`, `maintainers`, …) is
/// streamed past the deserializer without allocating.
///
/// Derives `Serialize`/`Deserialize` so the npm consumer can cache the
/// projection (not the raw body) in the ephemeral store. The projection
/// is the small Redis value; the raw body lives in the
/// `MetadataMirrorStore`. No logic change — the derives only let the
/// existing fields round-trip through serde.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NpmProjection {
    pub dist_tag_latest: Option<String>,
    pub versions: Vec<NpmVersionEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpmVersionEntry {
    pub version: String,
    /// Per-version `name` field (validated against the npm allowlist by
    /// the consumer in `ProxyNpmSource::fetch`; the projector does not
    /// allowlist — it surfaces whatever upstream sent for the consumer
    /// to filter).
    pub name_as_published: Option<String>,
    /// `dist.tarball` — full upstream URL. Preserved verbatim; the cache
    /// layer holds the raw upstream body for the tarball-orchestrator
    /// round-trip.
    pub tarball: Option<String>,
    /// `dist.integrity` — npm SRI ("sha512-<base64>"). Load-bearing for
    /// upstream-checksum verification (see ADR 0006 §7).
    pub integrity: Option<String>,
    /// `dist.shasum` — legacy hex SHA-1 (kept on the surface for
    /// downstream consumers; not authoritative).
    pub shasum: Option<String>,
    /// `time{<version>}` — upstream publish timestamp. Populated from
    /// the sibling `time{}` map after deserialize.
    pub published_at: Option<DateTime<Utc>>,
    /// The install-v1 abbreviated-metadata field set
    /// ([`NPM_INSTALL_V1_MANIFEST_KEYS`]), captured verbatim from the
    /// upstream per-version object. Empty when upstream published none
    /// of them.
    ///
    /// `#[serde(default)]` is load-bearing: cache frames written before
    /// this field existed carry no `manifest` key, and must decode into
    /// an empty map. Failing the decode instead would turn every
    /// pre-existing entry into a cold-cache miss plus a warn on a rolling
    /// deploy.
    #[serde(default)]
    pub manifest: serde_json::Map<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Projector trait impl
// ---------------------------------------------------------------------------

/// Streaming projector instance. Carries the per-version-object cap
/// (default 2 MiB; configurable via
/// `HORT_UPSTREAM_PROJECTOR_VERSION_OBJECT_MAX_SIZE`).
pub struct NpmPackumentProjector {
    per_version_object_max_bytes: u64,
    /// Set `true` iff a per-version-object cap trip aborted the
    /// projection — as opposed to a generic malformed-JSON parse error.
    /// The consumer grabs the handle via [`Self::cap_trip_flag`] BEFORE
    /// calling `project` (which consumes `self`) so it can emit
    /// `hort_upstream_fetch_total{result="version_object_too_large"}`
    /// instead of treating the trip as an opaque parse failure.
    cap_tripped: Arc<AtomicBool>,
}

impl NpmPackumentProjector {
    pub fn new(per_version_object_max_bytes: u64) -> Self {
        Self {
            per_version_object_max_bytes,
            cap_tripped: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Shared handle to the per-version-object cap-trip flag. Grab this
    /// before `project` (which consumes `self`); after `project` returns
    /// `Err`, a `true` value means the error is a cap trip
    /// (`version_object_too_large`), not a generic parse failure.
    pub fn cap_trip_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cap_tripped)
    }
}

impl MetadataProjector for NpmPackumentProjector {
    type Projection = NpmProjection;
    fn project<R: std::io::Read>(self, reader: R) -> DomainResult<NpmProjection> {
        // Wrap in `CountingReader` so the inner `versions{}` visitor
        // can sample `bytes_consumed()` before/after `next_value` and
        // enforce the per-version-object cap without re-buffering.
        let counting = CountingReader::new(reader);
        let counter = counting.counter();
        let mut de = serde_json::Deserializer::from_reader(counting);
        let visitor = TopVisitor {
            counter,
            cap: self.per_version_object_max_bytes,
            cap_tripped: Arc::clone(&self.cap_tripped),
        };
        de.deserialize_map(visitor)
            .map_err(|e| DomainError::Validation(format!("npm packument parse: {e}")))
    }
}

// ---------------------------------------------------------------------------
// Top-level visitor — walks the packument object, projecting only the
// three fields hort cares about; everything else passes through
// `IgnoredAny` (which consumes JSON tokens without allocating).
// ---------------------------------------------------------------------------

struct TopVisitor {
    counter: Arc<AtomicU64>,
    cap: u64,
    cap_tripped: Arc<AtomicBool>,
}

impl<'de> Visitor<'de> for TopVisitor {
    type Value = NpmProjection;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an npm packument object")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<NpmProjection, A::Error> {
        let mut dist_tags: Option<DistTagsWire> = None;
        let mut versions: Vec<NpmVersionEntry> = Vec::new();
        let mut time_map: Option<HashMap<String, DateTime<Utc>>> = None;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "dist-tags" => {
                    dist_tags = map.next_value()?;
                }
                "versions" => {
                    versions = map.next_value_seed(VersionsSeed {
                        counter: Arc::clone(&self.counter),
                        cap: self.cap,
                        cap_tripped: Arc::clone(&self.cap_tripped),
                    })?;
                }
                "time" => {
                    // serde_json's `Option<HashMap>` accepts both
                    // missing and null; we materialise into a real
                    // map below.
                    time_map = map.next_value::<Option<HashMap<String, DateTime<Utc>>>>()?;
                }
                _ => {
                    // Skip-without-allocating per
                    // `serde.rs/ignored-any.html`.
                    let _: IgnoredAny = map.next_value()?;
                }
            }
        }
        let time_map = time_map.unwrap_or_default();
        for v in &mut versions {
            v.published_at = time_map.get(&v.version).copied();
        }
        Ok(NpmProjection {
            dist_tag_latest: dist_tags.and_then(|dt| dt.latest),
            versions,
        })
    }
}

// ---------------------------------------------------------------------------
// `versions{}` map streaming — DeserializeSeed so the inner visitor
// receives the per-version-object cap context.
// ---------------------------------------------------------------------------

struct VersionsSeed {
    counter: Arc<AtomicU64>,
    cap: u64,
    cap_tripped: Arc<AtomicBool>,
}

impl<'de> serde::de::DeserializeSeed<'de> for VersionsSeed {
    type Value = Vec<NpmVersionEntry>;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_map(VersionsVisitor {
            counter: self.counter,
            cap: self.cap,
            cap_tripped: self.cap_tripped,
        })
    }
}

struct VersionsVisitor {
    counter: Arc<AtomicU64>,
    cap: u64,
    cap_tripped: Arc<AtomicBool>,
}

impl<'de> Visitor<'de> for VersionsVisitor {
    type Value = Vec<NpmVersionEntry>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the npm packument `versions{}` map")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut out = Vec::new();
        while let Some(version) = map.next_key::<String>()? {
            let before = self.counter.load(Ordering::Relaxed);
            let wire: VersionWire = map.next_value()?;
            let after = self.counter.load(Ordering::Relaxed);
            // Per-version-object cap. The delta is an approximation (the
            // deserializer's internal buffering means the counter may
            // advance ahead of the value boundary), but it is monotonic
            // in body size and tight enough for a 2 MiB-default cap
            // whose threshold is many orders of magnitude above the
            // per-version median.
            let delta = after.saturating_sub(before);
            if delta > self.cap {
                // Cap trip — flag it so the consumer emits
                // `version_object_too_large` rather than folding into
                // a generic parse failure.
                self.cap_tripped.store(true, Ordering::Relaxed);
                return Err(serde::de::Error::custom(format!(
                    "npm version-object too large: version=`{version}`, bytes_read={delta}, \
                     cap={cap}",
                    cap = self.cap,
                )));
            }
            out.push(NpmVersionEntry {
                version,
                name_as_published: wire.name,
                tarball: wire.dist.as_ref().and_then(|d| d.tarball.clone()),
                integrity: wire.dist.as_ref().and_then(|d| d.integrity.clone()),
                shasum: wire.dist.and_then(|d| d.shasum),
                published_at: None, // filled by outer visitor after time{} merges
                manifest: wire.manifest,
            });
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Wire DTOs — sparse on purpose; every field omitted here is consumed
// by serde's `deserialize_ignored_any` without allocating.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct DistTagsWire {
    latest: Option<String>,
}

/// Per-version object DTO. `name` + `dist` feed the tarball / checksum
/// path; the install-v1 whitelist
/// ([`NPM_INSTALL_V1_MANIFEST_KEYS`]) is captured verbatim into
/// `manifest`. Every other key (`description`, `scripts`,
/// `devDependencies`, `readme`, …) is consumed by `IgnoredAny` without
/// allocating, so the projection's memory bound stays the whitelist, not
/// the version object.
///
/// Hand-written `Deserialize` rather than a derive because the captured
/// key set is a runtime slice, not a fixed list of struct fields — a
/// derive would force one `Option<Value>` field per whitelist entry and
/// split the whitelist's definition across two places.
struct VersionWire {
    name: Option<String>,
    dist: Option<DistWire>,
    manifest: serde_json::Map<String, serde_json::Value>,
}

impl<'de> Deserialize<'de> for VersionWire {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(VersionWireVisitor)
    }
}

struct VersionWireVisitor;

impl<'de> Visitor<'de> for VersionWireVisitor {
    type Value = VersionWire;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an npm packument per-version object")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<VersionWire, A::Error> {
        let mut name = None;
        let mut dist = None;
        let mut manifest = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "name" => name = map.next_value()?,
                "dist" => dist = map.next_value()?,
                k if NPM_INSTALL_V1_MANIFEST_KEYS.contains(&k) => {
                    let value: serde_json::Value = map.next_value()?;
                    manifest.insert(key, value);
                }
                _ => {
                    let _: IgnoredAny = map.next_value()?;
                }
            }
        }
        Ok(VersionWire {
            name,
            dist,
            manifest,
        })
    }
}

#[derive(Deserialize)]
struct DistWire {
    tarball: Option<String>,
    integrity: Option<String>,
    shasum: Option<String>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn project(body: &[u8], cap: u64) -> DomainResult<NpmProjection> {
        let projector = NpmPackumentProjector::new(cap);
        projector.project(Cursor::new(body))
    }

    #[test]
    fn empty_versions_yields_empty_projection() {
        let body = br#"{"versions":{}}"#;
        let p = project(body, 2 * 1024 * 1024).expect("project");
        assert!(p.versions.is_empty());
        assert!(p.dist_tag_latest.is_none());
    }

    #[test]
    fn dist_tag_latest_round_trips() {
        let body = br#"{"dist-tags":{"latest":"1.2.3"},"versions":{}}"#;
        let p = project(body, 2 * 1024 * 1024).expect("project");
        assert_eq!(p.dist_tag_latest.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn dist_tarball_integrity_round_trip_pins_init44_f11_invariant() {
        // `dist.tarball` must reach the consumer unmodified.
        let body = br#"{
            "versions": {
                "1.0.0": {
                    "name": "foo",
                    "dist": {
                        "tarball": "https://registry.example.com/foo/-/foo-1.0.0.tgz",
                        "integrity": "sha512-abc",
                        "shasum": "deadbeef"
                    }
                }
            }
        }"#;
        let p = project(body, 2 * 1024 * 1024).expect("project");
        assert_eq!(p.versions.len(), 1);
        let v = &p.versions[0];
        assert_eq!(v.version, "1.0.0");
        assert_eq!(v.name_as_published.as_deref(), Some("foo"));
        assert_eq!(
            v.tarball.as_deref(),
            Some("https://registry.example.com/foo/-/foo-1.0.0.tgz")
        );
        assert_eq!(v.integrity.as_deref(), Some("sha512-abc"));
        assert_eq!(v.shasum.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn time_map_populates_published_at_on_each_version() {
        // `time{<version>}` must surface so the trust_upstream_publish_time
        // opt-in is not silently degraded.
        let body = br#"{
            "versions": {
                "1.0.0": {"name":"foo","dist":{"tarball":"u"}},
                "2.0.0": {"name":"foo","dist":{"tarball":"u"}}
            },
            "time": {
                "1.0.0": "2024-01-01T00:00:00Z",
                "2.0.0": "2024-06-15T12:30:00Z"
            }
        }"#;
        let p = project(body, 2 * 1024 * 1024).expect("project");
        let v1 = p.versions.iter().find(|v| v.version == "1.0.0").unwrap();
        let v2 = p.versions.iter().find(|v| v.version == "2.0.0").unwrap();
        assert!(v1.published_at.is_some());
        assert!(v2.published_at.is_some());
        assert!(v1.published_at.unwrap() < v2.published_at.unwrap());
    }

    #[test]
    fn ignored_fields_are_skipped_without_allocating_into_projection() {
        let body = br#"{
            "readme": "this is a very long readme that we do not allocate",
            "_attachments": {"foo.tgz": "binary blob"},
            "description": "irrelevant to the projection",
            "maintainers": [{"name":"alice"}],
            "versions": {
                "1.0.0": {"name":"foo","dist":{"tarball":"u","integrity":"sha512-x"}}
            }
        }"#;
        let p = project(body, 2 * 1024 * 1024).expect("project");
        assert_eq!(p.versions.len(), 1);
        // The projection has no `readme` / `description` / … fields; the
        // typed DTO is the only definition. Demonstrate via the
        // round-trip — we got the dist fields back, ergo the readme
        // didn't break the parse.
        assert_eq!(p.versions[0].tarball.as_deref(), Some("u"));
        assert_eq!(p.versions[0].integrity.as_deref(), Some("sha512-x"));
    }

    #[test]
    fn install_v1_whitelist_is_captured_verbatim_and_absent_keys_stay_absent() {
        // Every whitelist key present at the source reaches the entry
        // unaltered; non-whitelist per-version fields (`scripts`,
        // `devDependencies`, `description`) do NOT; and a whitelist key
        // the source omitted is absent rather than null.
        let body = br#"{
            "versions": {
                "1.0.0": {
                    "name": "foo",
                    "description": "not served",
                    "scripts": {"test": "jest"},
                    "devDependencies": {"jest": "^29.0.0"},
                    "dependencies": {"bar": "^2.0.0"},
                    "peerDependencies": {"react": ">=18"},
                    "peerDependenciesMeta": {"react": {"optional": true}},
                    "engines": {"node": ">=20"},
                    "os": ["linux"],
                    "cpu": ["x64"],
                    "bin": {"foo": "./cli.js"},
                    "deprecated": "use bar instead",
                    "hasInstallScript": true,
                    "dist": {"tarball": "https://r.example/foo/-/foo-1.0.0.tgz"}
                }
            }
        }"#;
        let p = project(body, 2 * 1024 * 1024).expect("project");
        let m = &p.versions[0].manifest;
        assert_eq!(
            m.get("dependencies"),
            Some(&serde_json::json!({"bar": "^2.0.0"}))
        );
        assert_eq!(
            m.get("peerDependencies"),
            Some(&serde_json::json!({"react": ">=18"}))
        );
        assert_eq!(
            m.get("peerDependenciesMeta"),
            Some(&serde_json::json!({"react": {"optional": true}}))
        );
        assert_eq!(m.get("engines"), Some(&serde_json::json!({"node": ">=20"})));
        assert_eq!(m.get("os"), Some(&serde_json::json!(["linux"])));
        assert_eq!(m.get("cpu"), Some(&serde_json::json!(["x64"])));
        assert_eq!(m.get("bin"), Some(&serde_json::json!({"foo": "./cli.js"})));
        assert_eq!(
            m.get("deprecated"),
            Some(&serde_json::json!("use bar instead"))
        );
        assert_eq!(m.get("hasInstallScript"), Some(&serde_json::json!(true)));
        // Out of contract — never captured.
        assert!(!m.contains_key("scripts"));
        assert!(!m.contains_key("devDependencies"));
        assert!(!m.contains_key("description"));
        // Whitelist keys the source omitted are absent, not null.
        assert!(!m.contains_key("optionalDependencies"));
        assert!(!m.contains_key("funding"));
        assert!(!m.contains_key("libc"));
        assert!(!m.contains_key("directories"));
        assert!(!m.contains_key("bundledDependencies"));
    }

    #[test]
    fn version_with_no_whitelist_keys_projects_an_empty_manifest() {
        let body = br#"{"versions":{"1.0.0":{"name":"foo","dist":{"tarball":"u"}}}}"#;
        let p = project(body, 2 * 1024 * 1024).expect("project");
        assert!(p.versions[0].manifest.is_empty());
    }

    #[test]
    fn pre_widening_serialized_entry_decodes_to_an_empty_manifest() {
        // A projection frame written before `manifest` existed carries no
        // such key. `#[serde(default)]` must make it decode to an empty
        // map — a decode failure here would turn every cached entry into
        // a cold-cache miss plus a warn on a rolling deploy.
        let frame = br#"{
            "dist_tag_latest": "1.0.0",
            "versions": [{
                "version": "1.0.0",
                "name_as_published": "foo",
                "tarball": "https://r.example/foo/-/foo-1.0.0.tgz",
                "integrity": "sha512-abc",
                "shasum": "deadbeef",
                "published_at": null
            }]
        }"#;
        let p: NpmProjection = serde_json::from_slice(frame).expect("pre-widening frame decodes");
        assert_eq!(p.dist_tag_latest.as_deref(), Some("1.0.0"));
        assert_eq!(p.versions.len(), 1);
        assert!(p.versions[0].manifest.is_empty());
        // The rest of the entry still derives unchanged.
        assert_eq!(p.versions[0].integrity.as_deref(), Some("sha512-abc"));
        assert_eq!(p.versions[0].shasum.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn malformed_json_returns_validation_error() {
        let body = br#"{"versions": INVALID}"#;
        let err = project(body, 2 * 1024 * 1024).expect_err("malformed");
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn per_version_object_cap_trips_on_oversize_value() {
        // Single version object > cap → error. Synthesise a
        // version with a huge `_extra_field` (skipped via
        // IgnoredAny but its tokens still flow through CountingReader
        // and count against the per-value cap, which is the right
        // shape: a malicious upstream that buries the same kind of
        // payload anywhere inside one version trips the same cap).
        let huge_value = "x".repeat(8 * 1024);
        let body = format!(
            r#"{{"versions":{{"1.0.0":{{"name":"foo","_pad":"{huge_value}",
                                          "dist":{{"tarball":"u"}}}}}}}}"#
        );
        // Cap at 4 KiB → 8 KiB padding alone trips it.
        let err = project(body.as_bytes(), 4 * 1024).expect_err("oversize value");
        assert!(matches!(err, DomainError::Validation(msg) if msg.contains("too large")));
    }

    #[test]
    fn cap_trip_sets_flag_but_malformed_json_does_not() {
        // The consumer keys the `version_object_too_large` metric on this
        // flag, so a cap trip must set it and a generic parse failure
        // must NOT.
        let huge = "x".repeat(8 * 1024);
        let body = format!(
            r#"{{"versions":{{"1.0.0":{{"name":"foo","_pad":"{huge}",
                                          "dist":{{"tarball":"u"}}}}}}}}"#
        );
        let projector = NpmPackumentProjector::new(4 * 1024);
        let flag = projector.cap_trip_flag();
        projector
            .project(Cursor::new(body.as_bytes()))
            .expect_err("oversize value");
        assert!(
            flag.load(Ordering::Relaxed),
            "per-version cap trip must set the cap-trip flag"
        );

        // Malformed JSON is a parse failure, not a cap trip — flag stays false.
        let projector = NpmPackumentProjector::new(2 * 1024 * 1024);
        let flag = projector.cap_trip_flag();
        projector
            .project(Cursor::new(&b"{\"versions\": INVALID}"[..]))
            .expect_err("malformed");
        assert!(
            !flag.load(Ordering::Relaxed),
            "malformed JSON must NOT set the cap-trip flag"
        );
    }
}
