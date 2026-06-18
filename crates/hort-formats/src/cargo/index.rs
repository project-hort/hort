//! Cargo `IndexBuilder` — third concrete `IndexBuilder` impl in the
//! unified Source → Filter → Builder pipeline
//! (see explanation/index-construction.md).
//!
//! - [`CargoVersionPayload`] (re-exported from
//!   [`hort_app::use_cases::index_serve`] — defined there for the same
//!   dep-graph reason that `NpmVersionPayload` / `PypiVersionPayload`
//!   live in `hort-app`) — the per-version data the builder consumes.
//! - [`CargoIndexBuilder`] — the [`IndexBuilder`] impl that emits the
//!   cargo sparse-index NDJSON document from a `Vec<VersionEntry>`
//!   whose entries' payload is `PerVersionPayload::Cargo(CargoVersionPayload)`.
//!
//! # What the builder emits
//!
//! Given `entries` post-filter, the builder produces one NDJSON line
//! per entry. Each line is a flat JSON object terminated with `\n`,
//! per RFC 2789 / the cargo registry spec:
//!
//! ```text
//! {"name":"<name>","vers":"<vers>","deps":[...],"cksum":"<sha256>",
//!  "features":{...},"yanked":<bool>,"links":<string|null>,
//!  "rust_version":<string|null>}\n
//! ```
//!
//! The `v` (schema version) and `features2` (v2-extra features map)
//! keys are emitted only when the payload supplies a `Some(...)`
//! value — matching the upstream-fidelity contract (cargo clients
//! perform version-resolution against this body; carrying `null`
//! v2-extras for hosted lines that never had them would diverge
//! from the upstream wire shape).
//!
//! # NDJSON ordering policy
//!
//! Cargo's sparse-index spec does NOT require a canonical line order;
//! cargo clients perform version-resolution against the served set
//! regardless of order. **However**, the unified builder sorts by
//! `vers` using [`BuildContext::ordering`] (`CargoSemverOrdering`,
//! aliased to `NpmSemverOrdering`) for two reasons:
//!
//! 1. **Bit-stable responses across runs.** A proxy receiving the
//!    same upstream NDJSON twice produces byte-identical responses,
//!    which makes CI / mirror-equivalence checks tractable. Insertion
//!    order from `list_by_raw_name` depends on adapter iteration order
//!    (HashMap-backed in mocks; whatever the PostgreSQL covering index
//!    returns in prod) — neither stable.
//! 2. **Operator-facing introspection.** Browsing the served NDJSON
//!    by hand is easier when versions appear in semver order.
//!
//! The ordering is **load-bearing for the dist-tag synthesis** in
//! the prefetch trigger (no native `dist-tags.latest` in cargo —
//! the helper synthesises max-by-`CargoSemverOrdering` over the
//! parsed version set). The builder's same ordering keeps the
//! served-document's natural reading consistent with that synthesis.
//!
//! Empty served set produces an empty body (zero NDJSON lines). The
//! unified handler maps an empty hosted result set to 404 before
//! reaching the builder; the empty-body path is reachable only on
//! the proxy branch (a parsed-empty upstream NDJSON).
//!
//! # Yanked semantics
//!
//! Cargo clients honour `yanked: true` orthogonally to quarantine:
//! a yanked version is still resolvable for version ranges that
//! already pin it, but new lockfile generations skip it. The filter
//! pipeline does NOT filter on `yanked` — yanked versions pass through
//! with their `yanked: true` field intact, by design.
//! Quarantine (`NonServableStatusFilter`) and yanking are different
//! concerns and must not collapse: a hosted operator can mark a
//! version `yanked` without quarantining its bytes, and quarantining
//! a never-yanked version must not flip `yanked` to true (clients
//! would interpret that differently).
//!
//! # `cksum` invariant
//!
//! Per the cargo spec `cksum` is mandatory — every NDJSON line MUST
//! carry a 64-hex-character SHA-256. The hosted source populates it
//! from `Artifact.sha256_checksum` (always present in v2). The
//! proxy source preserves the upstream-supplied `cksum`. The builder
//! emits the field as-is; an empty string would produce a
//! syntactically-valid line that cargo clients reject at resolve
//! time — exactly the failure mode the legacy `unwrap_or("")` fallback
//! had. We preserve that semantic to avoid introducing a new error mode.
//!
//! # URL construction (not a builder concern)
//!
//! Cargo's `dl` URL is published in `config.json`
//! (`hort-http-cargo/src/lib.rs::config_json`); per-version download
//! URLs are derived by cargo clients from `dl` + the resolved
//! (name, version) pair. The sparse-index NDJSON does NOT carry
//! per-version download URLs (unlike npm's `dist.tarball` or PyPI's
//! `<a href>`). So [`BuildContext::base_url`] is **unused** by the
//! cargo builder; it is part of the [`BuildContext`] shape but
//! agreed across format builders to be the format-tier choice. The
//! npm builder uses it; the cargo builder does not.
//!
//! # Tests
//!
//! Builder tests (this module) cover every branch on `entries`:
//! empty set (empty body), single-version set (all
//! [`CargoVersionPayload`] fields rendered), multi-version set
//! (semver-sorted lines via `CargoSemverOrdering`), `yanked: true`
//! preservation, optional-field omission (`v` and `features2`
//! `None` → key absent), optional-field emission (`Some` → key
//! present with the supplied value). Source-adapter tests live in
//! `hort-http-cargo/src/index_source.rs`; anti-enumeration tests live
//! in `hort-http-cargo/src/serve.rs`.

use bytes::Bytes;
use hort_app::use_cases::index_serve::{
    BuildContext, IndexBuilder, PerVersionPayload, VersionEntry,
};

pub use hort_app::use_cases::index_serve::CargoVersionPayload;

/// Cargo `IndexBuilder` — emits the sparse-index NDJSON body from a
/// post-filter `Vec<VersionEntry>`.
///
/// Stateless; the per-format serve handler constructs an instance per
/// request (cheap — it's a unit struct). The [`IndexBuilder`] trait
/// contract is "stateless wire-shape emitter"; this matches.
///
/// # Panics
///
/// Never panics on a well-formed input. A `VersionEntry` carrying a
/// non-`Cargo` `PerVersionPayload` variant is the only ill-formed
/// shape; the builder skips such entries with a structured `warn!`
/// and emits a degraded body (the entry is simply absent from the
/// NDJSON). This is a defence-in-depth posture against a
/// hypothetical future source adapter that mis-tags its payloads;
/// today the only constructible variant from a cargo source is
/// `Cargo`, so the warn arm is unreachable on the production hot
/// path. Pinning it behind a warn rather than a `panic!` keeps the
/// serve-time error mode at degraded-packument rather than panic.
#[derive(Debug, Default, Clone, Copy)]
pub struct CargoIndexBuilder;

impl IndexBuilder for CargoIndexBuilder {
    fn build(&self, ctx: BuildContext<'_>, entries: Vec<VersionEntry>) -> Bytes {
        // Sort by `vers` using the per-call ordering (CargoSemverOrdering
        // = NpmSemverOrdering — see hort-app::use_cases::index_serve_filter).
        // The cargo spec does not require a canonical order, but the
        // unified builder pins one for bit-stable proxy responses and
        // human-readable hosted output (see module-level rustdoc).
        let mut sorted: Vec<VersionEntry> = entries;
        sorted.sort_by(|a, b| ctx.ordering.compare(&a.version, &b.version));

        let mut out = String::new();
        for entry in &sorted {
            // Cross-format mis-tag defence. The closed-sum is enforced
            // at the use-case layer, not the builder layer — match arms
            // for `Npm` / `Pypi` are technically reachable. Skip with a
            // structured warn (drop the mis-tagged entry — the cargo
            // builder cannot synthesise NDJSON fields from a non-Cargo
            // payload: npm's has no `cksum`, PyPI's has no `vers`).
            let PerVersionPayload::Cargo(payload) = &entry.payload else {
                tracing::warn!(
                    version = %entry.version,
                    "cargo sparse-index builder: skipping VersionEntry with non-Cargo payload \
                     (cross-format mis-tag — should be unreachable)",
                );
                continue;
            };

            // Compose the per-line JSON object. Order of insertion into
            // a `serde_json::Map` is preserved on emission (the
            // `preserve_order` feature is default-off on serde_json, but
            // for stability across the test fixtures we insert in a
            // canonical order so a future serde_json default change
            // does not silently shuffle the wire bytes — even though no
            // cargo client keys on object key order).
            let mut obj = serde_json::Map::new();
            obj.insert(
                "name".to_string(),
                serde_json::Value::String(payload.name_as_published.clone()),
            );
            obj.insert(
                "vers".to_string(),
                serde_json::Value::String(payload.vers.clone()),
            );
            obj.insert("deps".to_string(), payload.deps.clone());
            obj.insert(
                "cksum".to_string(),
                serde_json::Value::String(payload.cksum.clone()),
            );
            obj.insert("features".to_string(), payload.features.clone());
            obj.insert(
                "yanked".to_string(),
                serde_json::Value::Bool(payload.yanked),
            );
            // `links` and `rust_version` are emitted as JSON `null` on
            // `None` (matching the cargo sparse-index spec).
            obj.insert(
                "links".to_string(),
                match &payload.links {
                    Some(s) => serde_json::Value::String(s.clone()),
                    None => serde_json::Value::Null,
                },
            );
            obj.insert(
                "rust_version".to_string(),
                match &payload.rust_version {
                    Some(s) => serde_json::Value::String(s.clone()),
                    None => serde_json::Value::Null,
                },
            );
            // `v` and `features2` are omitted entirely on `None` per
            // the upstream-fidelity contract — emitting them as `null`
            // for hosted lines that never had them would diverge from
            // the upstream wire shape.
            if let Some(v) = payload.v {
                obj.insert(
                    "v".to_string(),
                    serde_json::Value::Number(serde_json::Number::from(v)),
                );
            }
            if let Some(f2) = &payload.features2 {
                obj.insert("features2".to_string(), f2.clone());
            }

            // `serde_json::to_string` on a `serde_json::Map` containing
            // owned `Value::{String, Bool, Number, Object, Array, Null}`
            // values is infallible (no `f64::NAN`, no non-string keys).
            let line = serde_json::to_string(&serde_json::Value::Object(obj))
                .expect("CargoIndexBuilder serialises owned Value types only");
            out.push_str(&line);
            out.push('\n');
        }

        // `base_url` is intentionally unused — see module rustdoc.
        let _ = ctx.base_url;
        let _ = ctx.package_name;
        let _ = ctx.index_mode;

        Bytes::from(out.into_bytes())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use hort_app::use_cases::index_serve_filter::{CargoSemverOrdering, NpmSemverOrdering};
    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::repository::IndexMode;

    use super::*;

    fn entry(version: &str, payload: CargoVersionPayload) -> VersionEntry {
        VersionEntry {
            version: version.to_string(),
            status: Some(QuarantineStatus::Released),
            payload: PerVersionPayload::Cargo(payload),
        }
    }

    fn minimal_payload(name: &str, vers: &str, cksum: &str) -> CargoVersionPayload {
        CargoVersionPayload {
            name_as_published: name.to_string(),
            vers: vers.to_string(),
            cksum: cksum.to_string(),
            deps: serde_json::json!([]),
            features: serde_json::json!({}),
            yanked: false,
            links: None,
            rust_version: None,
            v: None,
            features2: None,
        }
    }

    fn build(entries: Vec<VersionEntry>) -> String {
        let bytes = CargoIndexBuilder.build(
            BuildContext {
                package_name: "serde",
                base_url: "https://example.test/cargo/m",
                index_mode: IndexMode::ReleasedOnly,
                ordering: &NpmSemverOrdering, // CargoSemverOrdering alias
            },
            entries,
        );
        String::from_utf8(bytes.to_vec()).expect("NDJSON is UTF-8")
    }

    fn parse_lines(body: &str) -> Vec<serde_json::Value> {
        body.lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("each line must be JSON"))
            .collect()
    }

    // -----------------------------------------------------------------
    // 1. Empty served set → empty body (zero NDJSON lines).
    //    The unified handler maps an empty hosted result set to 404
    //    before reaching the builder; the empty-body path is reachable
    //    only on the proxy branch (a parsed-empty upstream NDJSON).
    // -----------------------------------------------------------------

    #[test]
    fn empty_entries_produces_empty_body() {
        let body = build(Vec::new());
        assert!(
            body.is_empty(),
            "empty entries must produce an empty NDJSON body, got: {body:?}"
        );
    }

    // -----------------------------------------------------------------
    // 2. Single-version set — all required NDJSON fields render
    //    correctly. Pins the per-field emission contract for the
    //    hosted-emission shape (deps=[], features={}, yanked=false,
    //    links/rust_version=null).
    // -----------------------------------------------------------------

    #[test]
    fn single_version_emits_full_ndjson_line_with_all_required_fields() {
        let cksum = "a".repeat(64);
        let p = minimal_payload("serde", "1.0.0", &cksum);
        let body = build(vec![entry("1.0.0", p)]);
        // One line, terminated with `\n`.
        assert!(body.ends_with('\n'), "NDJSON line must be `\\n`-terminated");
        let lines = parse_lines(&body);
        assert_eq!(lines.len(), 1);
        let v = &lines[0];
        assert_eq!(v["name"].as_str().unwrap(), "serde");
        assert_eq!(v["vers"].as_str().unwrap(), "1.0.0");
        assert_eq!(v["cksum"].as_str().unwrap(), cksum);
        assert!(v["deps"].as_array().unwrap().is_empty());
        assert!(v["features"].as_object().unwrap().is_empty());
        assert!(!v["yanked"].as_bool().unwrap());
        assert!(v["links"].is_null());
        assert!(v["rust_version"].is_null());
        assert!(
            v.get("v").is_none(),
            "`v` MUST be omitted on None (upstream-fidelity contract): {v}"
        );
        assert!(
            v.get("features2").is_none(),
            "`features2` MUST be omitted on None (upstream-fidelity contract): {v}"
        );
    }

    // -----------------------------------------------------------------
    // 3. Multi-version semver — lines ordered by `vers` per the
    //    builder's policy (sort by CargoSemverOrdering). Pins the
    //    ordering hooked correctly and the lex-vs-semver distinction
    //    (1.10.0 > 1.9.0 semver, not lex).
    // -----------------------------------------------------------------

    #[test]
    fn multi_version_lines_sorted_by_cargo_semver_ordering_not_lex() {
        let entries = vec![
            entry(
                "1.10.0",
                minimal_payload("serde", "1.10.0", &"b".repeat(64)),
            ),
            entry("1.2.0", minimal_payload("serde", "1.2.0", &"c".repeat(64))),
            entry("1.9.0", minimal_payload("serde", "1.9.0", &"a".repeat(64))),
        ];
        let body = build(entries);
        let lines = parse_lines(&body);
        let versions: Vec<&str> = lines.iter().map(|l| l["vers"].as_str().unwrap()).collect();
        // Lex order would be [1.10.0, 1.2.0, 1.9.0]; semver order is
        // [1.2.0, 1.9.0, 1.10.0]. The builder takes CargoSemverOrdering
        // from BuildContext, so this proves the ordering reaches the
        // builder correctly.
        assert_eq!(
            versions,
            vec!["1.2.0", "1.9.0", "1.10.0"],
            "lines must be sorted by CargoSemverOrdering, not lex"
        );
    }

    // -----------------------------------------------------------------
    // 4. Yanked semantics — yanked: true is preserved in the served
    //    line. Pins that yanked is orthogonal to quarantine and the
    //    builder does not drop yanked entries.
    // -----------------------------------------------------------------

    #[test]
    fn yanked_versions_preserved_in_ndjson_with_yanked_true() {
        let mut p = minimal_payload("serde", "1.0.0", &"a".repeat(64));
        p.yanked = true;
        let body = build(vec![entry("1.0.0", p)]);
        let lines = parse_lines(&body);
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0]["yanked"].as_bool().unwrap(),
            "yanked: true must survive the builder (yanked is orthogonal to quarantine)"
        );
    }

    // -----------------------------------------------------------------
    // 5. Proxy-mirror full payload — all optional fields populated
    //    (links, rust_version, v=2, features2) round-trip through the
    //    builder. Pins the upstream-fidelity contract for the proxy
    //    branch (cargo clients perform version-resolution against
    //    this body, so the full key set must survive).
    // -----------------------------------------------------------------

    #[test]
    fn full_payload_all_optional_fields_round_trip_through_builder() {
        let cksum = "f".repeat(64);
        let payload = CargoVersionPayload {
            name_as_published: "complex-crate".into(),
            vers: "2.0.0".into(),
            cksum: cksum.clone(),
            deps: serde_json::json!([{
                "name": "tokio",
                "req": "^1",
                "features": [],
                "optional": false,
                "default_features": true,
                "target": null,
                "kind": "normal"
            }]),
            features: serde_json::json!({"default": ["std"], "std": []}),
            yanked: false,
            links: Some("z".into()),
            rust_version: Some("1.65".into()),
            v: Some(2),
            features2: Some(serde_json::json!({"weak-dep": ["dep:tokio?/full"]})),
        };
        let body = build(vec![entry("2.0.0", payload)]);
        let lines = parse_lines(&body);
        let v = &lines[0];
        assert_eq!(v["name"].as_str().unwrap(), "complex-crate");
        assert_eq!(v["vers"].as_str().unwrap(), "2.0.0");
        assert_eq!(v["cksum"].as_str().unwrap(), cksum);
        assert_eq!(v["deps"].as_array().unwrap().len(), 1);
        assert_eq!(
            v["deps"][0]["name"].as_str().unwrap(),
            "tokio",
            "upstream deps array must survive verbatim"
        );
        assert!(!v["yanked"].as_bool().unwrap());
        assert_eq!(v["links"].as_str().unwrap(), "z");
        assert_eq!(v["rust_version"].as_str().unwrap(), "1.65");
        assert_eq!(
            v["v"].as_u64().unwrap(),
            2,
            "v=2 (features2 schema) must survive verbatim"
        );
        assert!(
            v["features2"].is_object(),
            "features2 must survive as an object"
        );
        assert_eq!(
            v["features2"]["weak-dep"]
                .as_array()
                .unwrap()
                .first()
                .unwrap()
                .as_str()
                .unwrap(),
            "dep:tokio?/full"
        );
    }

    // -----------------------------------------------------------------
    // 6. NDJSON line termination — every line, even the last, is
    //    `\n`-terminated. Pins the cargo sparse-index wire convention.
    // -----------------------------------------------------------------

    #[test]
    fn every_ndjson_line_terminated_with_newline() {
        let entries = vec![
            entry("1.0.0", minimal_payload("serde", "1.0.0", &"a".repeat(64))),
            entry("1.1.0", minimal_payload("serde", "1.1.0", &"b".repeat(64))),
        ];
        let body = build(entries);
        let line_breaks: usize = body.matches('\n').count();
        assert_eq!(
            line_breaks, 2,
            "two entries → exactly two `\\n` terminators (cargo NDJSON shape): {body:?}"
        );
        assert!(
            body.ends_with('\n'),
            "the last line must be `\\n`-terminated"
        );
    }

    // -----------------------------------------------------------------
    // 7. Stored canonical name preserved — `name_as_published` carries
    //    the stored form (drift case), not the BuildContext's
    //    package_name. Mirrors the npm builder's drift-resilience
    //    test arm.
    // -----------------------------------------------------------------

    #[test]
    fn name_as_published_preserved_under_drift() {
        // Drift case: BuildContext.package_name is the request-route
        // form ("drift-crate") but the stored artifact's name is
        // "Legacy-Crate" (mixed case — impossible under current
        // normalise, but reachable for artifacts ingested under an
        // older plugin).
        let p = minimal_payload("Legacy-Crate", "0.1.0", &"a".repeat(64));
        let body = build(vec![entry("0.1.0", p)]);
        let lines = parse_lines(&body);
        assert_eq!(
            lines[0]["name"].as_str().unwrap(),
            "Legacy-Crate",
            "drift-stored name must survive — builder uses name_as_published, not BuildContext.package_name"
        );
    }

    // -----------------------------------------------------------------
    // 8. CargoSemverOrdering type-alias smoke — proves the type
    //    alias's underlying constructor is interchangeable. Useful
    //    documentation pin that the cargo crate may use either name.
    // -----------------------------------------------------------------

    #[test]
    fn cargo_semver_ordering_is_npm_semver_ordering_alias() {
        // Construct via the alias and the underlying name; both must
        // produce the same ordering decision.
        let alias: CargoSemverOrdering = NpmSemverOrdering;
        let underlying = NpmSemverOrdering;
        use hort_app::use_cases::index_serve_filter::VersionOrdering;
        assert_eq!(
            alias.compare("1.2.0", "1.10.0"),
            underlying.compare("1.2.0", "1.10.0")
        );
    }

    // -----------------------------------------------------------------
    // 9. Cross-format mis-tag defence — a non-Cargo payload is skipped
    //    with a warn, not panicked. Mirrors the npm builder's same arm.
    // -----------------------------------------------------------------

    #[test]
    fn non_cargo_payload_is_skipped_not_panicked() {
        use hort_app::use_cases::index_serve::NpmVersionPayload;

        // Construct a deliberately mis-tagged entry — an Npm payload
        // riding the Cargo builder. The builder must skip rather than
        // panic (defence-in-depth for a hypothetical future source
        // that mis-tags its payloads). One well-formed entry plus the
        // mis-tagged one verifies the survivor still emits.
        let good_entry = entry("1.0.0", minimal_payload("serde", "1.0.0", &"a".repeat(64)));
        let bad_entry = VersionEntry {
            version: "9.9.9".to_string(),
            status: Some(QuarantineStatus::Released),
            payload: PerVersionPayload::Npm(NpmVersionPayload {
                name_as_published: "wrong-format".into(),
                tarball_basename: "ignored.tgz".into(),
                integrity: None,
                shasum: "".into(),
            }),
        };
        let body = build(vec![good_entry, bad_entry]);
        let lines = parse_lines(&body);
        assert_eq!(
            lines.len(),
            1,
            "mis-tagged entry must be skipped; only the well-formed cargo line remains"
        );
        assert_eq!(lines[0]["vers"].as_str().unwrap(), "1.0.0");
    }

    // -----------------------------------------------------------------
    // 10. base_url and package_name are NOT consumed — pinned by
    //     contract. The cargo sparse-index NDJSON does not carry per-
    //     version download URLs (unlike npm `dist.tarball` / PyPI
    //     `<a href>`), so the builder ignores `BuildContext.base_url`
    //     and `BuildContext.package_name`. Pin this so a future
    //     regression that accidentally consumed base_url surfaces
    //     immediately.
    // -----------------------------------------------------------------

    #[test]
    fn base_url_and_package_name_unused_by_cargo_builder() {
        let p = minimal_payload("serde", "1.0.0", &"a".repeat(64));
        // Build twice with wildly different base_urls / package_names;
        // the output must be byte-identical.
        let mk = |base: &str, pkg: &str| {
            let bytes = CargoIndexBuilder.build(
                BuildContext {
                    package_name: pkg,
                    base_url: base,
                    index_mode: IndexMode::ReleasedOnly,
                    ordering: &NpmSemverOrdering,
                },
                vec![entry("1.0.0", p.clone())],
            );
            String::from_utf8(bytes.to_vec()).unwrap()
        };
        let a = mk("https://a.example/", "different-name-1");
        let b = mk("http://localhost:9999/anything", "different-name-2");
        assert_eq!(
            a, b,
            "cargo NDJSON must NOT depend on BuildContext.base_url or .package_name"
        );
    }
}
