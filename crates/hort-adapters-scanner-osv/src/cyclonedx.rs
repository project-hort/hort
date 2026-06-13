//! `Sbom` → CycloneDX 1.5 JSON serialiser. Pure; no I/O.
//!
//! Reference: <https://cyclonedx.org/docs/1.5/json/>.
//!
//! osv-scanner accepts CycloneDX (and SPDX) JSON. We pick CycloneDX
//! because it is closer to OSV's own component model (`bom-ref`, `purl`)
//! and the encoded surface area is small — osv-scanner reads the
//! `purl` of each `library` component and ignores everything else.
//!
//! The minimal CycloneDX 1.5 envelope osv-scanner consumes:
//!
//! ```text
//! {
//!   "bomFormat": "CycloneDX",
//!   "specVersion": "1.5",
//!   "version": 1,
//!   "components": [
//!     { "type": "library", "bom-ref": "<purl>", "name": "<n>",
//!       "version": "<v>", "purl": "<purl>" }
//!   ]
//! }
//! ```
//!
//! We deliberately skip `metadata.timestamp`, `metadata.tools`,
//! top-level `vulnerabilities`, and `dependencies` — all optional and
//! unconsumed by osv-scanner. This keeps the JSON small and the
//! serialiser surface minimal.
//!
//! Components whose ecosystem osv-scanner cannot match
//! (`Ecosystem::Helm`, `Ecosystem::OciImage`, `Ecosystem::Unknown`) are
//! filtered out before serialisation. They contribute no scan signal
//! and would only bloat the input.

use hort_domain::types::{Ecosystem, Sbom, SbomComponent};
use serde_json::{Map, Value};

/// Build the CycloneDX 1.5 JSON envelope for `sbom`. Filters out
/// components whose ecosystem osv-scanner cannot match.
///
/// When `sbom.subject` is `Some`, this function:
/// 1. Emits a `metadata.component` describing the subject — the
///    standards-pure way to declare "this BOM is about X" (CycloneDX
///    1.5 §4.4). Emitted regardless of whether `osv-scanner` can match
///    the subject's ecosystem: `metadata.component` is informational,
///    not the scannable surface.
/// 2. Duplicates the subject into `components[]` so `osv-scanner` (and
///    other CycloneDX consumers that scan only `components[]`) can
///    detect vulnerabilities on the artifact itself. This duplication
///    is the de-facto interop convention (Syft, cyclonedx-npm,
///    cyclonedx-bom all follow it). Without it, a leaf package with no
///    declared dependencies produces an empty `components[]` and
///    osv-scanner reports "found 0 packages". The subject duplication
///    is still subject to the ecosystem filter — a Helm-charts subject
///    cannot be scanned by osv-scanner and is filtered out of
///    `components[]` while remaining in `metadata.component`.
///
/// The returned value is a `serde_json::Value` so the caller controls
/// the bytes (`serde_json::to_vec_pretty` vs `to_vec`); the temp-file
/// writer uses the compact form.
pub(crate) fn build_cyclonedx_json(sbom: &Sbom) -> Value {
    let mut skipped = 0usize;
    let subject_component = sbom.subject.as_ref().map(component_to_json);

    // Capacity hint: deps + (subject duplicated into components[] when present).
    let mut components: Vec<Value> =
        Vec::with_capacity(sbom.components.len() + usize::from(sbom.subject.is_some()));

    // Subject goes first so consumers reading components[] in order see
    // the "what is this BOM about" entry before its deps.
    if let Some(subject) = &sbom.subject {
        if ecosystem_supported(&subject.ecosystem) {
            components.push(component_to_json(subject));
        } else {
            // Subject's ecosystem isn't one osv-scanner can match. We
            // still emit metadata.component above (informational) but
            // skip it in components[] to mirror the dep filter and
            // avoid sending unmatchable entries to the scanner.
            skipped += 1;
        }
    }
    for comp in &sbom.components {
        if !ecosystem_supported(&comp.ecosystem) {
            skipped += 1;
            continue;
        }
        components.push(component_to_json(comp));
    }
    if skipped > 0 {
        // Single emit, not per-component — debug-only, summary form.
        tracing::debug!(
            scanner = "osv",
            skipped_components = skipped,
            "osv adapter: filtered out components with ecosystems osv-scanner cannot match"
        );
    }

    let mut envelope = Map::new();
    envelope.insert("bomFormat".into(), Value::String("CycloneDX".into()));
    envelope.insert("specVersion".into(), Value::String("1.5".into()));
    envelope.insert("version".into(), Value::Number(1.into()));
    if let Some(meta_component) = subject_component {
        let mut meta = Map::new();
        meta.insert("component".into(), meta_component);
        envelope.insert("metadata".into(), Value::Object(meta));
    }
    envelope.insert("components".into(), Value::Array(components));
    Value::Object(envelope)
}

/// `true` for ecosystems osv-scanner can match against (npm, PyPI,
/// crates.io, Maven, Go, RubyGems, NuGet, Packagist, Hex, Pub, Conda).
/// `false` for `Helm`, `OciImage`, and the `Unknown(_)` escape hatch.
fn ecosystem_supported(eco: &Ecosystem) -> bool {
    matches!(
        eco,
        Ecosystem::Npm
            | Ecosystem::PyPI
            | Ecosystem::Cargo
            | Ecosystem::Maven
            | Ecosystem::Go
            | Ecosystem::RubyGems
            | Ecosystem::NuGet
            | Ecosystem::Composer
            | Ecosystem::Hex
            | Ecosystem::Pub
            | Ecosystem::Conda
    )
}

/// Encode one component as a CycloneDX `component` object.
///
/// Field shape:
/// - `type`: always `"library"` — osv-scanner ignores other types and
///   the SBOM model only emits library components today.
/// - `bom-ref`: the component's PURL — the canonical identity. Same
///   string as `purl`; CycloneDX requires `bom-ref` to be unique inside
///   the document and PURL is naturally unique per component.
/// - `name`: the component name as parsed from the manifest.
/// - `version`: emitted only when `Some(_)`; CycloneDX permits absent
///   `version` for unversioned references.
/// - `purl`: the canonical PURL — what osv-scanner reads to determine
///   ecosystem and match against advisories.
fn component_to_json(c: &SbomComponent) -> Value {
    let mut obj = Map::new();
    obj.insert("type".into(), Value::String("library".into()));
    obj.insert("bom-ref".into(), Value::String(c.purl.clone()));
    obj.insert("name".into(), Value::String(c.name.clone()));
    if let Some(v) = &c.version {
        obj.insert("version".into(), Value::String(v.clone()));
    }
    obj.insert("purl".into(), Value::String(c.purl.clone()));
    Value::Object(obj)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn npm_lodash() -> SbomComponent {
        SbomComponent {
            purl: "pkg:npm/lodash@4.17.20".into(),
            name: "lodash".into(),
            version: Some("4.17.20".into()),
            ecosystem: Ecosystem::Npm,
            licenses: vec!["MIT".into()],
            direct_dependency: true,
        }
    }

    #[test]
    fn empty_sbom_yields_well_formed_envelope_with_empty_components_array() {
        let sbom = Sbom {
            subject: None,
            components: vec![],
        };
        let v = build_cyclonedx_json(&sbom);
        assert_eq!(v["bomFormat"], "CycloneDX");
        assert_eq!(v["specVersion"], "1.5");
        assert_eq!(v["version"], 1);
        let comps = v["components"].as_array().expect("components is array");
        assert!(comps.is_empty(), "empty SBOM produces empty components");
    }

    #[test]
    fn single_npm_component_serialises_with_canonical_shape() {
        let sbom = Sbom {
            subject: None,
            components: vec![npm_lodash()],
        };
        let v = build_cyclonedx_json(&sbom);
        let comps = v["components"].as_array().expect("components is array");
        assert_eq!(comps.len(), 1);
        let c = &comps[0];
        assert_eq!(c["type"], "library");
        assert_eq!(c["bom-ref"], "pkg:npm/lodash@4.17.20");
        assert_eq!(c["name"], "lodash");
        assert_eq!(c["version"], "4.17.20");
        assert_eq!(c["purl"], "pkg:npm/lodash@4.17.20");
    }

    #[test]
    fn bom_ref_equals_purl() {
        let sbom = Sbom {
            subject: None,
            components: vec![npm_lodash()],
        };
        let v = build_cyclonedx_json(&sbom);
        let c = &v["components"][0];
        assert_eq!(c["bom-ref"], c["purl"]);
    }

    #[test]
    fn component_with_none_version_emits_no_version_key() {
        let sbom = Sbom {
            subject: None,
            components: vec![SbomComponent {
                purl: "pkg:cargo/anyhow".into(),
                name: "anyhow".into(),
                version: None,
                ecosystem: Ecosystem::Cargo,
                licenses: vec![],
                direct_dependency: true,
            }],
        };
        let v = build_cyclonedx_json(&sbom);
        let c = &v["components"][0];
        assert!(
            c.get("version").is_none(),
            "version key must be absent when SbomComponent.version is None: {c:#?}"
        );
        // Sanity: the rest of the canonical keys are still present.
        assert_eq!(c["type"], "library");
        assert_eq!(c["purl"], "pkg:cargo/anyhow");
    }

    #[test]
    fn unsupported_ecosystems_are_filtered_out_and_supported_ones_retained() {
        let sbom = Sbom {
            subject: None,
            components: vec![
                npm_lodash(),
                SbomComponent {
                    purl: "pkg:helm/nginx-ingress@4.0.0".into(),
                    name: "nginx-ingress".into(),
                    version: Some("4.0.0".into()),
                    ecosystem: Ecosystem::Helm,
                    licenses: vec![],
                    direct_dependency: true,
                },
                SbomComponent {
                    purl: "pkg:oci/postgres@latest".into(),
                    name: "postgres".into(),
                    version: Some("latest".into()),
                    ecosystem: Ecosystem::OciImage,
                    licenses: vec![],
                    direct_dependency: true,
                },
                SbomComponent {
                    purl: "pkg:exotic/foo@1.0".into(),
                    name: "foo".into(),
                    version: Some("1.0".into()),
                    ecosystem: Ecosystem::Unknown("rare".into()),
                    licenses: vec![],
                    direct_dependency: true,
                },
                SbomComponent {
                    purl: "pkg:pypi/requests@2.31.0".into(),
                    name: "requests".into(),
                    version: Some("2.31.0".into()),
                    ecosystem: Ecosystem::PyPI,
                    licenses: vec![],
                    direct_dependency: true,
                },
            ],
        };
        let v = build_cyclonedx_json(&sbom);
        let comps = v["components"].as_array().expect("components is array");
        // Three filtered (Helm + OciImage + Unknown), two retained
        // (Npm + PyPI).
        assert_eq!(comps.len(), 2, "got: {comps:#?}");
        let names: Vec<&str> = comps.iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"lodash"), "lodash missing: {names:?}");
        assert!(names.contains(&"requests"), "requests missing: {names:?}");
        assert!(
            !names.contains(&"nginx-ingress"),
            "Helm component must be filtered"
        );
        assert!(
            !names.contains(&"postgres"),
            "OCI image component must be filtered"
        );
        assert!(
            !names.contains(&"foo"),
            "Unknown ecosystem component must be filtered"
        );
    }

    /// When `Sbom::subject` is `Some`, the CycloneDX output MUST include
    /// `metadata.component` describing the subject. This is the
    /// standards-pure half of the fix (the v1 implementation emitted no
    /// `metadata` envelope at all).
    #[test]
    fn subject_emitted_as_metadata_component() {
        let sbom = Sbom {
            subject: Some(npm_lodash()),
            components: vec![],
        };
        let v = build_cyclonedx_json(&sbom);
        let meta_comp = v
            .get("metadata")
            .and_then(|m| m.get("component"))
            .expect("metadata.component must be present when subject is Some");
        assert_eq!(meta_comp["type"], "library");
        assert_eq!(meta_comp["name"], "lodash");
        assert_eq!(meta_comp["version"], "4.17.20");
        assert_eq!(meta_comp["purl"], "pkg:npm/lodash@4.17.20");
    }

    /// When `Sbom::subject` is `Some`, the subject MUST also appear in
    /// `components[]`. osv-scanner (and
    /// other CycloneDX-consuming scanners) only scan `components[]`;
    /// `metadata.component` is treated as informational. Without this
    /// duplication, a leaf package (no deps) had `components: []` and
    /// produced zero findings. The duplication is the de-facto interop
    /// convention used by Syft, cyclonedx-npm, cyclonedx-bom, etc.
    #[test]
    fn subject_also_included_in_components_array() {
        let sbom = Sbom {
            subject: Some(npm_lodash()),
            components: vec![],
        };
        let v = build_cyclonedx_json(&sbom);
        let comps = v["components"].as_array().expect("components is array");
        assert_eq!(
            comps.len(),
            1,
            "subject must be duplicated into components[]: {comps:#?}"
        );
        assert_eq!(comps[0]["name"], "lodash");
        assert_eq!(comps[0]["purl"], "pkg:npm/lodash@4.17.20");
    }

    /// With subject AND dependencies, both appear in `components[]`
    /// (subject first, then deps).
    #[test]
    fn subject_and_dependencies_both_emitted_into_components_array() {
        let dep = SbomComponent {
            purl: "pkg:npm/lodash.merge@4.6.0".into(),
            name: "lodash.merge".into(),
            version: Some("4.6.0".into()),
            ecosystem: Ecosystem::Npm,
            licenses: vec![],
            direct_dependency: true,
        };
        let sbom = Sbom {
            subject: Some(npm_lodash()),
            components: vec![dep],
        };
        let v = build_cyclonedx_json(&sbom);
        let comps = v["components"].as_array().expect("components is array");
        assert_eq!(comps.len(), 2);
        let names: Vec<&str> = comps.iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"lodash"), "subject missing: {names:?}");
        assert!(names.contains(&"lodash.merge"), "dep missing: {names:?}");
    }

    /// When `subject` is None, the output preserves the v1 shape:
    /// no `metadata` envelope, and `components[]` is just the deps.
    /// Important for backward compatibility with consumers that may
    /// rely on the absence of `metadata` to detect "subject unknown".
    #[test]
    fn no_subject_means_no_metadata_envelope() {
        let sbom = Sbom {
            subject: None,
            components: vec![npm_lodash()],
        };
        let v = build_cyclonedx_json(&sbom);
        assert!(
            v.get("metadata").is_none(),
            "metadata envelope must be omitted when subject is None: {v:#?}"
        );
        let comps = v["components"].as_array().expect("components is array");
        assert_eq!(comps.len(), 1, "subject=None must not inflate components");
    }

    /// Subject with an osv-scanner-unsupported ecosystem (e.g. Helm,
    /// OciImage) is filtered out of `components[]` to match the
    /// existing filter behaviour. `metadata.component` still carries
    /// it — that field is informational and doesn't drive scanning.
    #[test]
    fn unsupported_subject_ecosystem_is_filtered_from_components_but_kept_in_metadata() {
        let helm_subject = SbomComponent {
            purl: "pkg:helm/nginx@4.0.0".into(),
            name: "nginx".into(),
            version: Some("4.0.0".into()),
            ecosystem: Ecosystem::Helm,
            licenses: vec![],
            direct_dependency: true,
        };
        let sbom = Sbom {
            subject: Some(helm_subject),
            components: vec![],
        };
        let v = build_cyclonedx_json(&sbom);
        assert!(
            v.get("metadata").is_some(),
            "metadata.component carries the subject regardless of ecosystem support"
        );
        let comps = v["components"].as_array().expect("components is array");
        assert!(
            comps.is_empty(),
            "Helm subject must not enter components[] (osv-scanner can't scan it)"
        );
    }

    #[test]
    fn ecosystem_supported_recognises_all_named_variants() {
        for eco in [
            Ecosystem::Npm,
            Ecosystem::PyPI,
            Ecosystem::Cargo,
            Ecosystem::Maven,
            Ecosystem::Go,
            Ecosystem::RubyGems,
            Ecosystem::NuGet,
            Ecosystem::Composer,
            Ecosystem::Hex,
            Ecosystem::Pub,
            Ecosystem::Conda,
        ] {
            assert!(ecosystem_supported(&eco), "expected supported: {eco:?}");
        }
        for eco in [
            Ecosystem::Helm,
            Ecosystem::OciImage,
            Ecosystem::Unknown("x".into()),
        ] {
            assert!(!ecosystem_supported(&eco), "expected unsupported: {eco:?}");
        }
    }
}
