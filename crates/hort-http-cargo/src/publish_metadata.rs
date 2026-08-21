//! Cargo publish-body metadata ⇄ sparse-index entry document.
//!
//! Two halves of one wire contract, deliberately co-located so the
//! write shape and the read shape cannot drift apart:
//!
//! - [`PublishMetadata`] — the JSON object cargo sends in the publish
//!   frame (`PUT /api/v1/crates/new`), projected onto
//!   [`PublishMetadata::to_index_metadata`], the document persisted as
//!   the artifact's `payload_metadata`.
//! - [`StoredIndexFields`] — the same document read back by the hosted
//!   [`IndexSource`](crate::index_source::HostedCargoSource) when it
//!   builds a served sparse-index line.
//!
//! # The publish body is NOT the index entry
//!
//! The registry-web-API publish object and the registry-index entry
//! are two different schemas that happen to share most field names.
//! The cargo index-format reference enumerates the differences; the
//! three that matter here:
//!
//! - **`version_req` → `req`.** The requirement field is renamed.
//! - **Renames invert.** In the publish body `name` is the *original*
//!   package name and `explicit_name_in_toml` is the aliased name; in
//!   the index `name` is the *aliased* name and `package` carries the
//!   original ("The index places the aliased name in the name field,
//!   and the original package name in the package field").
//! - **`cksum` is the registry's to compute** — "The publish API does
//!   not specify the checksum, it must be computed by the registry
//!   before adding to the index." The stored document therefore never
//!   carries a checksum: the CAS SHA-256 on the artifact row is the
//!   only authority, and a `cksum` key here would be an invitation to
//!   serve a client-supplied digest.
//!
//! Features carrying the extended syntax (namespaced `dep:` and weak
//! `pkg?/feat`) are split out into `features2` with `v: 2`, per the
//! index format's split rule. Cargo merges the two maps on read; a
//! cargo that predates the extended syntax skips the entry instead of
//! failing to parse a feature list it cannot understand.
//!
//! Publish-body fields that exist only to populate a registry's
//! website — `description`, `readme`, `keywords`, `categories`,
//! `badges`, … — are dropped: the index has no place for them, and
//! `readme` alone carries the crate's entire README text, which would
//! bloat every metadata row for data no served document reads. The one
//! exception is `license`, which is the SPDX expression
//! `CargoFormatHandler::extract_sbom` reads to license the SBOM
//! components it derives from `deps`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The subset of cargo's publish-body JSON object that reaches a
/// served index entry (plus `license`, which reaches the SBOM).
///
/// Unknown fields are ignored — cargo sends many more and the set
/// grows over releases. Every field except `name` / `vers` is
/// optional: a body that omits `deps` / `features` entirely is a
/// dependency-free crate, not an error.
#[derive(Debug, Deserialize)]
pub(crate) struct PublishMetadata {
    /// Crate name, pre-normalisation. Validated by the caller against
    /// the cargo grammar before any of this is used.
    pub(crate) name: String,
    /// Crate version, pre-normalisation. Validated by the caller.
    pub(crate) vers: String,
    #[serde(default)]
    deps: Vec<PublishDep>,
    /// Feature name → enabled features/dependencies. `BTreeMap` so the
    /// stored document (and therefore the served line) is byte-stable
    /// across publishes of identical input.
    #[serde(default)]
    features: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    links: Option<String>,
    #[serde(default)]
    rust_version: Option<String>,
    #[serde(default)]
    license: Option<String>,
}

/// One entry of the publish body's `deps` array.
///
/// `version_req` is required — it is the field the index's `req` is
/// built from, and a dependency without a requirement cannot be
/// resolved by any client. The rest default to the values the index
/// format assigns to an absent field, so a hand-rolled publisher that
/// omits them still yields a spec-shaped entry.
#[derive(Debug, Deserialize)]
struct PublishDep {
    name: String,
    version_req: String,
    #[serde(default)]
    features: Vec<String>,
    #[serde(default)]
    optional: bool,
    /// Absent means "default features enabled" — the Cargo.toml
    /// default and the index format's documented fallback.
    #[serde(default = "default_true")]
    default_features: bool,
    #[serde(default)]
    target: Option<String>,
    /// `"normal"` / `"build"` / `"dev"`. Absent or `null` means
    /// `"normal"`; the emitted entry always names a kind explicitly.
    #[serde(default)]
    kind: Option<String>,
    /// Index URL of the registry this dependency comes from. `null`
    /// means "the current registry" in BOTH schemas, so it passes
    /// through untranslated — cargo has already collapsed a
    /// same-registry dependency to `null` before sending the body.
    #[serde(default)]
    registry: Option<String>,
    /// The aliased name when the dependency is renamed in Cargo.toml.
    /// Becomes the index entry's `name`; the original `name` moves to
    /// `package`.
    #[serde(default)]
    explicit_name_in_toml: Option<String>,
}

fn default_true() -> bool {
    true
}

/// A `deps` entry in index shape.
#[derive(Debug, Serialize)]
struct IndexDep {
    name: String,
    req: String,
    features: Vec<String>,
    optional: bool,
    default_features: bool,
    target: Option<String>,
    kind: String,
    registry: Option<String>,
    package: Option<String>,
}

/// The document persisted as an artifact's `payload_metadata` and read
/// back by the hosted index source.
///
/// Deliberately absent: `cksum` (the CAS hash is the authority) and
/// `yanked` (a mutable per-version state, not a publish-time fact).
#[derive(Debug, Serialize)]
struct IndexMetadata {
    name: String,
    vers: String,
    deps: Vec<IndexDep>,
    features: BTreeMap<String, Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    features2: Option<BTreeMap<String, Vec<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    v: Option<u32>,
    links: Option<String>,
    rust_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    license: Option<String>,
}

/// True when a feature's value list uses the extended feature syntax:
/// a namespaced dependency (`dep:serde`) or a weak dependency feature
/// (`chrono?/serde`). Such features belong in `features2`, never in
/// `features`.
fn uses_extended_syntax(values: &[String]) -> bool {
    values
        .iter()
        .any(|v| v.starts_with("dep:") || v.contains("?/"))
}

impl PublishMetadata {
    /// Project the publish body onto the sparse-index entry document.
    pub(crate) fn to_index_metadata(&self) -> serde_json::Value {
        let deps = self
            .deps
            .iter()
            .map(|dep| {
                // A renamed dependency swaps roles between the two
                // schemas: publish `name` is the real package, index
                // `name` is what the manifest calls it.
                let (name, package) = match &dep.explicit_name_in_toml {
                    Some(alias) => (alias.clone(), Some(dep.name.clone())),
                    None => (dep.name.clone(), None),
                };
                IndexDep {
                    name,
                    req: dep.version_req.clone(),
                    features: dep.features.clone(),
                    optional: dep.optional,
                    default_features: dep.default_features,
                    target: dep.target.clone(),
                    kind: dep.kind.clone().unwrap_or_else(|| "normal".to_string()),
                    registry: dep.registry.clone(),
                    package,
                }
            })
            .collect();

        let mut features: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut features2: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (feature, values) in &self.features {
            let target = if uses_extended_syntax(values) {
                &mut features2
            } else {
                &mut features
            };
            target.insert(feature.clone(), values.clone());
        }
        // `v: 2` announces the presence of `features2` and nothing
        // else, so it is emitted only when the split produced one —
        // a crate with no extended-syntax feature stays a v1 entry
        // that every cargo since 1.19 reads.
        let (features2, v) = if features2.is_empty() {
            (None, None)
        } else {
            (Some(features2), Some(2))
        };

        let doc = IndexMetadata {
            name: self.name.clone(),
            vers: self.vers.clone(),
            deps,
            features,
            features2,
            v,
            links: self.links.clone(),
            rust_version: self.rust_version.clone(),
            license: self.license.clone(),
        };
        // Infallible: every field is a String / bool / u32 / Vec /
        // BTreeMap with String keys — none of serde_json's failure
        // modes (non-string map key, NaN) is constructible here.
        serde_json::to_value(doc).expect("index metadata serialises owned JSON-safe types only")
    }
}

/// The index-entry fields the hosted source reads back out of a
/// stored metadata document.
///
/// Every field degrades to the value the source emitted before any
/// metadata was persisted, so a row written by an older ingest (or by
/// a non-publish path such as a seed import, whose document has none
/// of these keys) serves exactly the entry it served then: empty
/// `deps`, empty `features`, no `v` / `features2`, null `links` /
/// `rust_version`.
#[derive(Debug)]
pub(crate) struct StoredIndexFields {
    pub(crate) deps: serde_json::Value,
    pub(crate) features: serde_json::Value,
    pub(crate) features2: Option<serde_json::Value>,
    pub(crate) v: Option<u32>,
    pub(crate) links: Option<String>,
    pub(crate) rust_version: Option<String>,
}

impl Default for StoredIndexFields {
    fn default() -> Self {
        Self {
            deps: serde_json::Value::Array(Vec::new()),
            features: serde_json::Value::Object(serde_json::Map::new()),
            features2: None,
            v: None,
            links: None,
            rust_version: None,
        }
    }
}

impl StoredIndexFields {
    /// Read the index-entry fields out of a stored metadata document.
    ///
    /// Each field is type-checked before it is accepted: a stored
    /// document whose `deps` is not an array (or `features` not an
    /// object) falls back to the empty default rather than emitting a
    /// line no cargo client can parse. The serve path is the last
    /// place that can keep a malformed row from becoming a malformed
    /// wire document.
    pub(crate) fn from_stored(stored: &serde_json::Value) -> Self {
        let deps = stored
            .get("deps")
            .filter(|v| v.is_array())
            .cloned()
            .unwrap_or_else(|| serde_json::Value::Array(Vec::new()));
        let features = stored
            .get("features")
            .filter(|v| v.is_object())
            .cloned()
            .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));
        let features2 = stored.get("features2").filter(|v| v.is_object()).cloned();
        let v = stored
            .get("v")
            .and_then(serde_json::Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            // The index format requires `v >= 2` wherever `features2`
            // is present. Deriving the floor here means no stored
            // document can produce an entry that advertises the
            // extended map without the schema version that makes a
            // client look for it.
            .or_else(|| features2.as_ref().map(|_| 2));

        Self {
            deps,
            features,
            features2,
            v,
            links: string_field(stored, "links"),
            rust_version: string_field(stored, "rust_version"),
        }
    }
}

fn string_field(stored: &serde_json::Value, key: &str) -> Option<String> {
    stored
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A publish body shaped like the cargo reference's worked
    /// example, extended with the cases the translation has to get
    /// right: a renamed dependency, a target/dev dependency, a
    /// kind-less dependency, and a cross-registry dependency.
    fn fixture_body() -> &'static str {
        r#"{
            "name": "hort-http-core",
            "vers": "0.11.0",
            "deps": [
                {
                    "name": "hort-app",
                    "version_req": "=0.11.0",
                    "features": ["test-support"],
                    "optional": false,
                    "default_features": true,
                    "target": null,
                    "kind": "normal",
                    "registry": null,
                    "explicit_name_in_toml": null
                },
                {
                    "name": "rand",
                    "version_req": "^0.8",
                    "features": [],
                    "optional": true,
                    "default_features": false,
                    "target": "cfg(windows)",
                    "kind": "dev",
                    "registry": "https://github.com/rust-lang/crates.io-index",
                    "explicit_name_in_toml": "random"
                },
                {
                    "name": "kindless",
                    "version_req": "1"
                }
            ],
            "features": {
                "default": ["metrics"],
                "metrics": ["dep:metrics-util"],
                "chrono-serde": ["chrono?/serde"]
            },
            "authors": ["Alice <a@example.com>"],
            "description": "ignored",
            "readme": "a very long readme",
            "keywords": [],
            "categories": [],
            "license": "MIT OR Apache-2.0",
            "badges": {},
            "links": "libfoo",
            "rust_version": "1.94",
            "cksum": "client-supplied-and-ignored"
        }"#
    }

    fn parse(body: &str) -> PublishMetadata {
        serde_json::from_str(body).expect("fixture parses")
    }

    fn index_doc(body: &str) -> serde_json::Value {
        parse(body).to_index_metadata()
    }

    #[test]
    fn version_req_becomes_req() {
        let doc = index_doc(fixture_body());
        assert_eq!(doc["deps"][0]["req"], "=0.11.0");
        assert!(
            doc["deps"][0].get("version_req").is_none(),
            "the publish-side field name must not survive into the index entry"
        );
    }

    #[test]
    fn same_registry_dependency_keeps_null_registry() {
        let doc = index_doc(fixture_body());
        assert!(
            doc["deps"][0]["registry"].is_null(),
            "null means `current registry` in both schemas — pass through"
        );
        assert_eq!(
            doc["deps"][1]["registry"], "https://github.com/rust-lang/crates.io-index",
            "a cross-registry dependency keeps its index URL"
        );
    }

    #[test]
    fn renamed_dependency_swaps_name_and_package() {
        let doc = index_doc(fixture_body());
        assert_eq!(
            doc["deps"][1]["name"], "random",
            "index `name` is the aliased name"
        );
        assert_eq!(
            doc["deps"][1]["package"], "rand",
            "index `package` is the original package name"
        );
        assert!(
            doc["deps"][1].get("explicit_name_in_toml").is_none(),
            "the publish-side rename field must not survive"
        );
    }

    #[test]
    fn unrenamed_dependency_has_null_package() {
        let doc = index_doc(fixture_body());
        assert!(doc["deps"][0]["package"].is_null());
    }

    #[test]
    fn dependency_flags_and_target_are_carried_through() {
        let doc = index_doc(fixture_body());
        assert_eq!(
            doc["deps"][0]["features"],
            serde_json::json!(["test-support"])
        );
        assert_eq!(doc["deps"][0]["optional"], false);
        assert_eq!(doc["deps"][0]["default_features"], true);
        assert!(doc["deps"][0]["target"].is_null());
        assert_eq!(doc["deps"][0]["kind"], "normal");

        assert_eq!(doc["deps"][1]["optional"], true);
        assert_eq!(doc["deps"][1]["default_features"], false);
        assert_eq!(doc["deps"][1]["target"], "cfg(windows)");
        assert_eq!(doc["deps"][1]["kind"], "dev");
    }

    #[test]
    fn absent_dependency_fields_take_the_index_format_defaults() {
        let doc = index_doc(fixture_body());
        let kindless = &doc["deps"][2];
        assert_eq!(kindless["kind"], "normal", "absent kind defaults to normal");
        assert_eq!(
            kindless["default_features"], true,
            "absent default_features defaults to true"
        );
        assert_eq!(kindless["optional"], false);
        assert_eq!(kindless["features"], serde_json::json!([]));
        assert!(kindless["target"].is_null());
        assert!(kindless["registry"].is_null());
        assert!(kindless["package"].is_null());
    }

    #[test]
    fn extended_syntax_features_split_into_features2_with_v2() {
        let doc = index_doc(fixture_body());
        assert_eq!(
            doc["features"],
            serde_json::json!({"default": ["metrics"]}),
            "plain features stay in `features`"
        );
        assert_eq!(
            doc["features2"],
            serde_json::json!({
                "metrics": ["dep:metrics-util"],
                "chrono-serde": ["chrono?/serde"],
            }),
            "namespaced (`dep:`) and weak (`?/`) features move to `features2`"
        );
        assert_eq!(doc["v"], 2);
    }

    #[test]
    fn crate_without_extended_features_stays_a_v1_entry() {
        let doc = index_doc(
            r#"{"name":"plain","vers":"1.0.0","features":{"default":["extras"],"extras":["rand/simd_support"]}}"#,
        );
        assert_eq!(
            doc["features"],
            serde_json::json!({"default": ["extras"], "extras": ["rand/simd_support"]}),
            "`pkg/feat` is the OLD syntax and stays in `features`"
        );
        assert!(doc.get("features2").is_none());
        assert!(doc.get("v").is_none());
    }

    #[test]
    fn client_supplied_checksum_is_never_stored() {
        let doc = index_doc(fixture_body());
        assert!(
            doc.get("cksum").is_none(),
            "the CAS hash is the only checksum authority"
        );
        assert!(
            doc.get("yanked").is_none(),
            "yank is per-version mutable state, not a publish-time fact"
        );
    }

    #[test]
    fn website_only_publish_fields_are_dropped_but_license_is_kept() {
        let doc = index_doc(fixture_body());
        for dropped in ["readme", "description", "authors", "keywords", "badges"] {
            assert!(
                doc.get(dropped).is_none(),
                "`{dropped}` has no place in an index entry"
            );
        }
        assert_eq!(doc["license"], "MIT OR Apache-2.0");
        assert_eq!(doc["links"], "libfoo");
        assert_eq!(doc["rust_version"], "1.94");
        assert_eq!(doc["name"], "hort-http-core");
        assert_eq!(doc["vers"], "0.11.0");
    }

    #[test]
    fn minimal_publish_body_yields_an_empty_but_valid_entry() {
        let doc = index_doc(r#"{"name":"mycrate","vers":"0.1.0"}"#);
        assert_eq!(doc["deps"], serde_json::json!([]));
        assert_eq!(doc["features"], serde_json::json!({}));
        assert!(doc["links"].is_null());
        assert!(doc["rust_version"].is_null());
        assert!(doc.get("license").is_none());
    }

    #[test]
    fn dependency_without_version_req_fails_to_parse() {
        let err = serde_json::from_str::<PublishMetadata>(
            r#"{"name":"c","vers":"1.0.0","deps":[{"name":"d","kind":"normal"}]}"#,
        );
        assert!(
            err.is_err(),
            "a dependency with no requirement cannot be resolved by any client — \
             the publish must fail rather than serve an unusable entry"
        );
    }

    #[test]
    fn wrong_typed_field_fails_to_parse() {
        assert!(
            serde_json::from_str::<PublishMetadata>(
                r#"{"name":"c","vers":"1.0.0","features":{"a":"not-a-list"}}"#
            )
            .is_err(),
            "operator-relevant metadata that cannot be understood fails the publish loudly"
        );
    }

    // -- read-back ------------------------------------------------------

    #[test]
    fn stored_document_round_trips_through_the_read_back() {
        let doc = index_doc(fixture_body());
        let fields = StoredIndexFields::from_stored(&doc);
        assert_eq!(fields.deps, doc["deps"]);
        assert_eq!(fields.features, doc["features"]);
        assert_eq!(fields.features2, Some(doc["features2"].clone()));
        assert_eq!(fields.v, Some(2));
        assert_eq!(fields.links.as_deref(), Some("libfoo"));
        assert_eq!(fields.rust_version.as_deref(), Some("1.94"));
    }

    #[test]
    fn absent_metadata_reads_back_as_the_pre_metadata_entry() {
        for stored in [
            serde_json::Value::Null,
            serde_json::json!({}),
            serde_json::json!({"source": "seed-import"}),
        ] {
            let fields = StoredIndexFields::from_stored(&stored);
            assert_eq!(fields.deps, serde_json::json!([]));
            assert_eq!(fields.features, serde_json::json!({}));
            assert!(fields.features2.is_none());
            assert!(fields.v.is_none());
            assert!(fields.links.is_none());
            assert!(fields.rust_version.is_none());
        }
    }

    #[test]
    fn mistyped_stored_fields_degrade_to_the_defaults() {
        let stored = serde_json::json!({
            "deps": "not-an-array",
            "features": ["not-an-object"],
            "features2": 7,
            "v": "two",
            "links": 3,
            "rust_version": false,
        });
        let fields = StoredIndexFields::from_stored(&stored);
        assert_eq!(fields.deps, serde_json::json!([]));
        assert_eq!(fields.features, serde_json::json!({}));
        assert!(fields.features2.is_none());
        assert!(fields.v.is_none());
        assert!(fields.links.is_none());
        assert!(fields.rust_version.is_none());
    }

    #[test]
    fn features2_without_v_reads_back_with_the_schema_version_floor() {
        let stored = serde_json::json!({"features2": {"a": ["dep:b"]}});
        let fields = StoredIndexFields::from_stored(&stored);
        assert_eq!(
            fields.v,
            Some(2),
            "a served entry must never advertise features2 without `v`"
        );
    }

    #[test]
    fn out_of_range_schema_version_degrades_to_none() {
        let stored = serde_json::json!({"v": u64::from(u32::MAX) + 1});
        assert!(StoredIndexFields::from_stored(&stored).v.is_none());
    }

    #[test]
    fn default_read_back_matches_the_pre_metadata_entry() {
        let fields = StoredIndexFields::default();
        assert_eq!(fields.deps, serde_json::json!([]));
        assert_eq!(fields.features, serde_json::json!({}));
        assert!(fields.features2.is_none());
        assert!(fields.v.is_none());
        assert!(fields.links.is_none());
        assert!(fields.rust_version.is_none());
    }

    // -- SBOM -----------------------------------------------------------

    /// The stored document is what the scanner reads at scan time. Its
    /// index-shaped `deps` is the branch
    /// `CargoFormatHandler::extract_sbom` already implements, so a
    /// cargo publish now yields a component-bearing SBOM without any
    /// scanner-side change.
    #[test]
    fn stored_metadata_yields_an_sbom_with_components() {
        use hort_domain::entities::repository::RepositoryFormat;
        use hort_domain::ports::format_handler::FormatHandler;
        use hort_domain::types::{ArtifactCoords, PayloadAccess};
        use hort_formats::cargo::CargoFormatHandler;

        let coords = ArtifactCoords {
            name: "hort-http-core".to_string(),
            name_as_published: "hort-http-core".to_string(),
            version: Some("0.11.0".to_string()),
            path: "crates/hort-http-core/0.11.0/hort-http-core-0.11.0.crate".to_string(),
            format: RepositoryFormat::Cargo,
            metadata: index_doc(fixture_body()),
        };

        let sbom = CargoFormatHandler
            .extract_sbom(&coords, &coords.metadata, PayloadAccess::Bytes(&[]))
            .expect("extraction succeeds")
            .expect("cargo produces an SBOM");

        let names: Vec<&str> = sbom.components.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["hort-app", "random", "kindless"]);
        let hort_app = &sbom.components[0];
        assert_eq!(hort_app.version.as_deref(), Some("0.11.0"));
        assert_eq!(hort_app.purl, "pkg:cargo/hort-app@0.11.0");
        assert!(hort_app.direct_dependency);
        assert_eq!(
            hort_app.licenses,
            vec!["MIT OR Apache-2.0".to_string()],
            "the publish body's license expression licenses the components"
        );
        assert!(
            !sbom.components[1].direct_dependency,
            "an optional dependency is not a direct dependency"
        );
    }
}
