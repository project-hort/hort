//! SBOM domain types — the format-agnostic shape carried between
//! `FormatHandler::extract_sbom` and `ScannerPort::scan` /
//! `AdvisoryPort::query`.
//!
//! Pure value types: zero I/O, zero allocation beyond the obvious owned
//! `String` / `Vec` fields. `Sbom`, `SbomComponent`, `Ecosystem` derive
//! `Serialize` so adapters can render them outward (e.g. the OSV scanner
//! emits the SBOM as a CycloneDX JSON document for the external tool).
//! They deliberately do NOT derive `Deserialize`: no current production
//! code path reconstructs an SBOM from JSON — adapters take `&Sbom` /
//! `&[SbomComponent]` by reference, and `findings_blob` carries
//! `Vec<Finding>` not `Sbom`. The standing precedent locks the absence
//! of `DeserializeOwned` at compile time (see the test below).
//!
//! `PayloadAccess<'a>` is the input-access knob for `extract_sbom`. It
//! is NOT serialisable — it carries either a borrowed byte slice or a
//! type-erased streaming reader. The manual `Debug` impl prints only
//! the variant tag and the byte count for `Bytes`; the streaming
//! variant prints `<read-stream>` so logged Debug output never leaks
//! payload content.
//!
//! See `docs/architecture/explanation/scanning-pipeline.md`.

use std::fmt;
use std::io::Read;

use serde::Serialize;

// ---------------------------------------------------------------------------
// Sbom / SbomComponent / Ecosystem
// ---------------------------------------------------------------------------

/// Top-level SBOM container — the format-agnostic shape a
/// `FormatHandler::extract_sbom` impl produces from an ingested payload.
///
/// `subject` is the CycloneDX `metadata.component` — the artifact the
/// BOM describes (lodash@4.17.20 itself, not its dependencies). `None`
/// for formats whose handler can't determine a subject (opaque payload,
/// no coords). Producers SHOULD populate it for any format with an
/// identifiable artifact-under-scan; consumers that need to query
/// advisories or scanners across "the artifact and its deps" iterate
/// `subject.iter().chain(components.iter())`.
///
/// `components` is the CycloneDX `components[]` array — what the
/// subject contains/depends on. Empty for leaf packages with no
/// manifest-declared dependencies; the trait impl returns `None` for
/// genuinely opaque formats and
/// `Some(Sbom { subject: …, components: vec![] })` for "manifest exists
/// but lists no dependencies".
///
/// **Why `subject` is separate from `components`**:
/// a previous shape exposed only `components: Vec<_>` and
/// each format handler emitted just dependencies. CycloneDX
/// distinguishes the subject (`metadata.component`) from the components
/// it lists, and most real-world tools (osv-scanner, Grype, Trivy
/// sbom-mode) scan `components[]` and treat `metadata.component` as
/// informational. The OSV adapter's `build_cyclonedx_json` writes
/// `metadata.component` from `subject` AND duplicates the subject into
/// the emitted `components[]` (the de-facto interop convention) so
/// leaf packages with no deps are still scannable. Without the
/// duplication, lodash@4.17.20 (a leaf utility with zero deps) had a
/// `components: []` SBOM and osv-scanner returned 0 findings — the
/// failure mode the v2 vulnerability-scan smoke caught.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Sbom {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<SbomComponent>,
    pub components: Vec<SbomComponent>,
}

impl Sbom {
    /// All components in this BOM, materialised as an owned vector —
    /// the subject first (when present) and every entry in
    /// `components` second.
    ///
    /// Use this when downstream code needs to act on every package the
    /// BOM describes: advisory enrichment, the `sbom_components`
    /// projection write, anything that asks "which packages are in
    /// this artifact?". Materialising as `Vec` is intentional — the
    /// consumers in question expect `&[SbomComponent]` (contiguous
    /// slice) and would otherwise have to collect themselves.
    ///
    /// For pure iteration use `subject.iter().chain(components.iter())`
    /// directly and avoid the clone.
    pub fn all_components_owned(&self) -> Vec<SbomComponent> {
        let mut out =
            Vec::with_capacity(self.components.len() + usize::from(self.subject.is_some()));
        if let Some(subject) = &self.subject {
            out.push(subject.clone());
        }
        out.extend(self.components.iter().cloned());
        out
    }
}

/// One component entry inside an [`Sbom`]. PURL is the canonical
/// identity used to correlate scanner findings against the SBOM
/// (`Finding.purl == SbomComponent.purl`). `licenses` carries SPDX
/// identifiers when the source manifest exposes them; empty otherwise.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SbomComponent {
    pub purl: String,
    pub name: String,
    pub version: Option<String>,
    pub ecosystem: Ecosystem,
    pub licenses: Vec<String>,
    pub direct_dependency: bool,
}

/// Recognised ecosystems plus an `Unknown(String)` escape hatch for
/// formats whose manifest exposes a string ecosystem identifier we do
/// not have a typed variant for. The variant set mirrors the
/// `pkg:<type>` PURL types the v1 scanner pipeline supports.
//
// Default tagged-enum form chosen for serde shape — the `Unknown(String)`
// variant serialises cleanly as `{"Unknown":"…"}` without custom rename
// rules. Tested in `ecosystem_unknown_serde_serialises_using_default_tagged_form`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Ecosystem {
    Npm,
    PyPI,
    Cargo,
    Maven,
    Go,
    RubyGems,
    NuGet,
    Composer,
    Hex,
    Pub,
    Conda,
    Helm,
    OciImage,
    /// Format had a manifest but no recognised ecosystem mapping.
    Unknown(String),
}

// ---------------------------------------------------------------------------
// PayloadAccess
// ---------------------------------------------------------------------------

/// Input-access mode for [`FormatHandler::extract_sbom`](crate::ports::format_handler).
///
/// Most format handlers reconstruct the SBOM from
/// `ArtifactIngested.metadata` (already extracted at ingest time) and
/// never touch the payload — they ignore this argument. Handlers that
/// need raw bytes (Maven JAR inspection, OCI layer walking) request
/// them via [`PayloadAccess::Bytes`] (small artifacts already in
/// memory) or [`PayloadAccess::ReadStream`] (streaming over large
/// content).
///
/// Not `Serialize` / `Deserialize` — the variants carry a borrowed
/// slice and a type-erased reader. The manual `Debug` impl prints the
/// variant tag plus the byte count for `Bytes`; the stream variant
/// prints `<read-stream>` so the payload content cannot leak through
/// `tracing::debug!("{:?}", payload)`.
pub enum PayloadAccess<'a> {
    /// Already-loaded payload bytes — used when the artifact is small
    /// enough to materialise in memory.
    Bytes(&'a [u8]),
    /// Streaming reader — used for payloads too large to buffer.
    ReadStream(Box<dyn Read + Send + 'a>),
}

impl fmt::Debug for PayloadAccess<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PayloadAccess::Bytes(b) => f
                .debug_tuple("Bytes")
                .field(&format_args!("{} bytes", b.len()))
                .finish(),
            PayloadAccess::ReadStream(_) => f
                .debug_tuple("ReadStream")
                .field(&format_args!("<read-stream>"))
                .finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- Sbom / SbomComponent / Ecosystem (serialise-only) ---------------
    //
    // These types deliberately do NOT derive `Deserialize`.
    // The serialise side covers the only production need
    // — adapters render the SBOM outward (e.g. the OSV scanner emits
    // CycloneDX JSON). The compile-time lock at the bottom of this
    // module enforces the absence of any inbound deserialisation path.

    #[test]
    fn sbom_serialises_one_component_with_named_ecosystem() {
        let sbom = Sbom {
            subject: None,
            components: vec![SbomComponent {
                purl: "pkg:npm/lodash@4.17.21".into(),
                name: "lodash".into(),
                version: Some("4.17.21".into()),
                ecosystem: Ecosystem::Npm,
                licenses: vec!["MIT".into()],
                direct_dependency: true,
            }],
        };
        let json = serde_json::to_value(&sbom).unwrap();
        assert_eq!(json["components"][0]["purl"], "pkg:npm/lodash@4.17.21");
        assert_eq!(json["components"][0]["ecosystem"], "Npm");
        assert_eq!(json["components"][0]["direct_dependency"], true);
    }

    #[test]
    fn sbom_serialises_unknown_ecosystem() {
        let sbom = Sbom {
            subject: None,
            components: vec![SbomComponent {
                purl: "pkg:exotic/foo@1.0".into(),
                name: "foo".into(),
                version: Some("1.0".into()),
                ecosystem: Ecosystem::Unknown("custom".into()),
                licenses: vec![],
                direct_dependency: false,
            }],
        };
        let json = serde_json::to_value(&sbom).unwrap();
        assert_eq!(json["components"][0]["ecosystem"]["Unknown"], "custom");
    }

    #[test]
    fn sbom_serialises_when_empty() {
        let sbom = Sbom {
            subject: None,
            components: vec![],
        };
        let json = serde_json::to_string(&sbom).unwrap();
        assert_eq!(json, r#"{"components":[]}"#);
    }

    /// `metadata.component` (CycloneDX) — when `subject` is `Some`, the
    /// rendered JSON includes a `subject` field describing the artifact
    /// the BOM is about. This is the slot that lets `osv-scanner` (and
    /// other CycloneDX consumers) detect vulnerabilities on the artifact
    /// itself, not just on its dependencies. The previous shape — a
    /// flat `components: Vec<SbomComponent>` with no subject — couldn't
    /// express the subject distinctly, and `cyclonedx.rs` emitted
    /// neither `metadata.component` nor the subject inside
    /// `components[]`. Result: a leaf package (no deps) produced an
    /// SBOM with an empty `components[]`, osv-scanner scanned nothing,
    /// and the vulnerability-scan smoke for lodash@4.17.20 (CVE-2021-23337)
    /// failed with "found 0 packages".
    #[test]
    fn sbom_serialises_with_subject_field_when_present() {
        let sbom = Sbom {
            subject: Some(SbomComponent {
                purl: "pkg:npm/lodash@4.17.20".into(),
                name: "lodash".into(),
                version: Some("4.17.20".into()),
                ecosystem: Ecosystem::Npm,
                licenses: vec!["MIT".into()],
                direct_dependency: true,
            }),
            components: vec![],
        };
        let json = serde_json::to_value(&sbom).unwrap();
        assert_eq!(json["subject"]["purl"], "pkg:npm/lodash@4.17.20");
        assert_eq!(json["subject"]["name"], "lodash");
        assert_eq!(json["subject"]["ecosystem"], "Npm");
    }

    /// `Sbom::all_components_owned` includes the subject (when
    /// present) as the FIRST entry, then every component in
    /// `components`. Downstream consumers (advisory enrichment, the
    /// `sbom_components` projection write) iterate this list to
    /// resolve "every package the BOM describes".
    #[test]
    fn all_components_owned_returns_subject_first_then_components() {
        let subject = SbomComponent {
            purl: "pkg:npm/lodash@4.17.20".into(),
            name: "lodash".into(),
            version: Some("4.17.20".into()),
            ecosystem: Ecosystem::Npm,
            licenses: vec![],
            direct_dependency: true,
        };
        let dep = SbomComponent {
            purl: "pkg:npm/lodash.merge@4.6.0".into(),
            name: "lodash.merge".into(),
            version: Some("4.6.0".into()),
            ecosystem: Ecosystem::Npm,
            licenses: vec![],
            direct_dependency: true,
        };
        let sbom = Sbom {
            subject: Some(subject.clone()),
            components: vec![dep.clone()],
        };
        let all = sbom.all_components_owned();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0], subject, "subject must be first");
        assert_eq!(all[1], dep);
    }

    /// `all_components_owned` returns the components verbatim when
    /// `subject` is None. Important for backward compatibility with
    /// callers that previously passed `sbom.components.as_slice()`.
    #[test]
    fn all_components_owned_without_subject_returns_components_verbatim() {
        let dep = SbomComponent {
            purl: "pkg:npm/foo@1.0.0".into(),
            name: "foo".into(),
            version: Some("1.0.0".into()),
            ecosystem: Ecosystem::Npm,
            licenses: vec![],
            direct_dependency: true,
        };
        let sbom = Sbom {
            subject: None,
            components: vec![dep.clone()],
        };
        let all = sbom.all_components_owned();
        assert_eq!(all, vec![dep]);
    }

    /// Serialising an `Sbom` with `subject: None` MUST NOT emit a
    /// `"subject":null` key. Two reasons:
    /// 1. Pre-existing serde fixtures and tests in this crate (and the
    ///    adapters that consume `Sbom`) expect the bare
    ///    `{"components":[…]}` envelope and would regress.
    /// 2. `None` is a structural absence ("the format handler couldn't
    ///    determine a subject", e.g. an opaque payload). Emitting
    ///    `"subject":null` confuses CycloneDX-aware consumers into
    ///    believing the producer asserted "no subject" rather than
    ///    "subject unknown".
    #[test]
    fn sbom_subject_field_omitted_when_none() {
        let sbom = Sbom {
            subject: None,
            components: vec![SbomComponent {
                purl: "pkg:npm/dep@1.0.0".into(),
                name: "dep".into(),
                version: Some("1.0.0".into()),
                ecosystem: Ecosystem::Npm,
                licenses: vec![],
                direct_dependency: true,
            }],
        };
        let json = serde_json::to_string(&sbom).unwrap();
        assert!(
            !json.contains("\"subject\""),
            "Sbom JSON must omit `subject` key when None; got: {json}"
        );
    }

    #[test]
    fn sbom_component_serialises_with_no_version() {
        let comp = SbomComponent {
            purl: "pkg:cargo/anyhow".into(),
            name: "anyhow".into(),
            version: None,
            ecosystem: Ecosystem::Cargo,
            licenses: vec!["MIT".into(), "Apache-2.0".into()],
            direct_dependency: true,
        };
        let json = serde_json::to_value(&comp).unwrap();
        assert!(json["version"].is_null());
        assert_eq!(json["licenses"][0], "MIT");
        assert_eq!(json["licenses"][1], "Apache-2.0");
    }

    #[test]
    fn sbom_component_serialises_with_multiple_licenses_and_transitive() {
        let comp = SbomComponent {
            purl: "pkg:pypi/requests@2.31.0".into(),
            name: "requests".into(),
            version: Some("2.31.0".into()),
            ecosystem: Ecosystem::PyPI,
            licenses: vec!["Apache-2.0".into(), "BSD-3-Clause".into()],
            direct_dependency: false,
        };
        let json = serde_json::to_value(&comp).unwrap();
        assert_eq!(json["version"], "2.31.0");
        assert_eq!(json["ecosystem"], "PyPI");
        assert_eq!(json["direct_dependency"], false);
    }

    // ----- Ecosystem variant equality --------------------------------------

    #[test]
    fn ecosystem_unknown_equality_holds() {
        assert_eq!(
            Ecosystem::Unknown("a".into()),
            Ecosystem::Unknown("a".into())
        );
        assert_ne!(
            Ecosystem::Unknown("a".into()),
            Ecosystem::Unknown("b".into())
        );
        assert_ne!(Ecosystem::Unknown("a".into()), Ecosystem::Npm);
    }

    #[test]
    fn ecosystem_named_variants_are_distinct() {
        assert_ne!(Ecosystem::Npm, Ecosystem::PyPI);
        assert_ne!(Ecosystem::Cargo, Ecosystem::Maven);
        assert_ne!(Ecosystem::Go, Ecosystem::RubyGems);
        assert_ne!(Ecosystem::NuGet, Ecosystem::Composer);
        assert_ne!(Ecosystem::Hex, Ecosystem::Pub);
        assert_ne!(Ecosystem::Conda, Ecosystem::Helm);
        assert_ne!(Ecosystem::OciImage, Ecosystem::Npm);
    }

    #[test]
    fn ecosystem_unknown_serde_serialises_using_default_tagged_form() {
        // The default tagged-enum form serialises Unknown("custom") as
        // {"Unknown":"custom"}. We don't customise rename rules — the
        // shape is what serde produces by default and we lock it in
        // with this test so a future "tweak the rename" change is a
        // visible regression.
        let e = Ecosystem::Unknown("custom".into());
        let json = serde_json::to_string(&e).unwrap();
        assert_eq!(json, r#"{"Unknown":"custom"}"#);
    }

    #[test]
    fn ecosystem_named_variant_serialises_as_bare_name() {
        // Named variants default-serialise as their bare name.
        let e = Ecosystem::Npm;
        let json = serde_json::to_string(&e).unwrap();
        assert_eq!(json, "\"Npm\"");
    }

    #[test]
    fn ecosystem_all_named_variants_serialise() {
        // Cover every named variant so the 100% coverage target on
        // hort-domain isn't blown by an untouched match arm hidden in
        // the derived serialiser.
        for (e, expected) in [
            (Ecosystem::Npm, "\"Npm\""),
            (Ecosystem::PyPI, "\"PyPI\""),
            (Ecosystem::Cargo, "\"Cargo\""),
            (Ecosystem::Maven, "\"Maven\""),
            (Ecosystem::Go, "\"Go\""),
            (Ecosystem::RubyGems, "\"RubyGems\""),
            (Ecosystem::NuGet, "\"NuGet\""),
            (Ecosystem::Composer, "\"Composer\""),
            (Ecosystem::Hex, "\"Hex\""),
            (Ecosystem::Pub, "\"Pub\""),
            (Ecosystem::Conda, "\"Conda\""),
            (Ecosystem::Helm, "\"Helm\""),
            (Ecosystem::OciImage, "\"OciImage\""),
        ] {
            let json = serde_json::to_string(&e).unwrap();
            assert_eq!(json, expected);
        }
    }

    // ----- Compile-time lock: no `Deserialize` -----------------------------
    //
    // Standing no-`Deserialize` precedent. Domain types must not be
    // reconstructible from arbitrary JSON unless a current production
    // code path requires it. `Sbom`, `SbomComponent`, and `Ecosystem`
    // have no such path: adapters take them by reference (`&Sbom`,
    // `&[SbomComponent]`) and the only event-store JSONB payload that
    // carries scan output is `findings_blob`, which holds `Vec<Finding>`
    // not `Sbom`. The macro below expands to a `const _` block that
    // fails to compile if any `Deserialize<'de>` impl is later added.
    static_assertions::assert_not_impl_any!(Sbom: serde::de::DeserializeOwned);
    static_assertions::assert_not_impl_any!(SbomComponent: serde::de::DeserializeOwned);
    static_assertions::assert_not_impl_any!(Ecosystem: serde::de::DeserializeOwned);

    // ----- PayloadAccess ---------------------------------------------------

    #[test]
    fn payload_access_bytes_constructs_and_debug_prints_byte_count() {
        let buf: &[u8] = b"";
        let p = PayloadAccess::Bytes(buf);
        let rendered = format!("{p:?}");
        assert!(
            rendered.contains("Bytes"),
            "Debug output should name the variant: {rendered}"
        );
        assert!(
            rendered.contains("0 bytes"),
            "Debug output should report byte count: {rendered}"
        );
    }

    #[test]
    fn payload_access_bytes_debug_reports_nonzero_byte_count() {
        let buf: &[u8] = b"hello world";
        let p = PayloadAccess::Bytes(buf);
        let rendered = format!("{p:?}");
        assert!(rendered.contains("11 bytes"), "got: {rendered}");
    }

    #[test]
    fn payload_access_read_stream_constructs_and_debug_does_not_leak_content() {
        // Construct a stream with sentinel bytes; assert Debug output
        // contains neither the bytes nor any decoded form. The Debug
        // contract says streaming payload content stays out of logs.
        let sentinel: &[u8] = b"SECRET-SENTINEL-DO-NOT-LEAK";
        let stream: Box<dyn Read + Send + '_> = Box::new(sentinel);
        let p = PayloadAccess::ReadStream(stream);
        let rendered = format!("{p:?}");
        assert!(
            rendered.contains("ReadStream"),
            "Debug output should name the variant: {rendered}"
        );
        assert!(
            !rendered.contains("SECRET-SENTINEL"),
            "Debug output must not leak stream content: {rendered}"
        );
        assert!(
            rendered.contains("read-stream"),
            "Debug output should mark stream variant: {rendered}"
        );
    }
}
