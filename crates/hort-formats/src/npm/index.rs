//! npm `IndexBuilder` — the reference implementation for the Source →
//! Filter → Builder pipeline (see explanation/index-construction.md).
//!
//! This module ships the npm-side of the pipeline:
//!
//! - [`NpmVersionPayload`] (re-exported from
//!   [`hort_app::use_cases::index_serve`] — defined there for dep-graph
//!   reasons, see that module's "Dep direction" note) — the per-version
//!   data the builder consumes.
//! - [`NpmIndexBuilder`] — the [`IndexBuilder`] impl that emits the
//!   packument JSON from a `Vec<VersionEntry>` whose entries' payload
//!   is `PerVersionPayload::Npm(NpmVersionPayload)`.
//!
//! # What the builder emits
//!
//! Given `entries` post-filter, the builder produces the npm packument
//! wire shape:
//!
//! ```json
//! {
//!   "name": "<package_name>",
//!   "versions": {
//!     "<v>": {
//!       "name": "<NpmVersionPayload.name_as_published>",
//!       "version": "<v>",
//!       "dist": {
//!         "tarball": "<base_url>/npm/<repo_key derived from base_url+pkg>/<name>/-/<basename>",
//!         "shasum":  "<sha1-hex>",
//!         "integrity": "<sri>"   // present iff payload.integrity.is_some()
//!       },
//!       // …plus each install-v1 whitelist key the payload's `manifest`
//!       // carries (`dependencies`, `engines`, `deprecated`, …), verbatim.
//!       // A key the source did not publish is simply absent.
//!     },
//!     ...
//!   },
//!   "dist-tags": { "latest": "<served-max>" }   // omitted when entries is empty
//! }
//! ```
//!
//! # `dist-tags.latest` invariant
//!
//! `dist-tags.latest` must point at the **resolved-latest of the
//! served set, excluding pre-releases** — i.e. the max over `entries`
//! per [`BuildContext::ordering`] whose
//! [`VersionOrdering::is_prerelease`](hort_app::use_cases::index_serve_filter::VersionOrdering::is_prerelease)
//! is `false`, computed *after* the filter pipeline. This mirrors the
//! npm ecosystem contract: a pre-release is never `latest` while any
//! release is served, so a bare `npm i`/`pnpm add` never installs a
//! canary. If every served entry is a pre-release, `latest` falls back
//! to the pre-release max (a pre-release-only package still gets a
//! usable tag) — the builder sees only post-filter entries, so this
//! fallback IS the served-max in that case. An empty served set
//! produces a packument with empty `versions{}` and **no `dist-tags`
//! block at all** — a client following an absent `latest` falls back to
//! its lockfile or fails the same way as "nothing servable".
//!
//! # URL construction
//!
//! The full `dist.tarball` URL is
//! `{base_url}/<name_as_published>/-/<tarball_basename>` where
//! `base_url` is the per-call [`BuildContext::base_url`] (already
//! includes `/npm/{repo_key}` — the per-format serve handler composes
//! it before invoking the builder). The builder is content-type-
//! agnostic about `base_url`; it just concatenates with `/`.
//!
//! Per-version `name` is the [`NpmVersionPayload::name_as_published`]
//! field — npm permits a published `name` different from the route
//! (drift-resilience on hosted; arbitrary upstream-declared names on
//! proxy), so this is preserved verbatim. The hosted source uses
//! `Artifact.name` (the stored normalised form); the proxy source
//! uses upstream's per-version `name` after the canonical
//! [`validate_npm_name`](crate::npm::validate_npm_name) check.
//!
//! # Why the per-version field set is a whitelist
//!
//! The unified packument carries exactly what [`NpmVersionPayload`]
//! declares: the `name`/`version`/`dist` triple plus
//! [`NPM_INSTALL_V1_MANIFEST_KEYS`](crate::npm::NPM_INSTALL_V1_MANIFEST_KEYS)
//! — the npm registry API's abbreviated-metadata (install-v1) field set,
//! which is what an installer needs to resolve a dependency tree. Full
//! packument equality is deliberately not the target: no `time`, no
//! `maintainers`, no `bugs`, no README, no `scripts`, no
//! `devDependencies`. Carrying arbitrary upstream extras would need a
//! passthrough-blob escape hatch on the closed payload sum that is the
//! spine of the format-agnostic pipeline; a fixed whitelist keeps the
//! served surface a contract both sources can satisfy verbatim.
//!
//! # Tests
//!
//! Builder tests (this module) cover every branch on `entries`:
//! empty set (no `versions{}` keys, no `dist-tags`), single-version
//! set (all four `NpmVersionPayload` fields rendered), multi-version
//! set (semver-correct `dist-tags.latest`), and the URL-construction
//! check (`dist.tarball` is built from `base_url + payload.tarball_basename`,
//! NOT from any copied upstream URL — the rewriter cannot leak a raw
//! upstream URL through the builder).
//!
//! Source-adapter tests live in `hort-http-npm/src/index_source.rs`
//! (they need `AppContext` + mocks and so cannot live in `hort-formats`).
//! Anti-enumeration tests live in `hort-http-npm/src/serve.rs`
//! (the unified handler is the anti-enumeration assertion site).

use bytes::Bytes;
use hort_app::use_cases::index_serve::{
    BuildContext, IndexBuilder, PerVersionPayload, VersionEntry, VersionOrdering,
};

pub use hort_app::use_cases::index_serve::NpmVersionPayload;

/// Resolve `dist-tags.latest` over a **post-filter served** set: the
/// max non-prerelease version per `ordering`, falling back to the
/// unfiltered max only when every served entry is a prerelease.
/// `None` for an empty served set — the wire-equivalent of "nothing
/// servable" (no `dist-tags` block in the packument, 404 on the
/// abbreviated per-version `latest` route).
///
/// This is the single definition of the npm ecosystem's "a pre-release
/// never wins `latest` while a release is served" contract
/// (see the module docs above); [`NpmIndexBuilder::build`] and the
/// abbreviated per-version/tag route (`hort-http-npm::serve`) both
/// call it so the invariant cannot drift between the two callers.
pub fn resolve_served_latest<'a>(
    entries: &'a [VersionEntry],
    ordering: &dyn VersionOrdering,
) -> Option<&'a str> {
    entries
        .iter()
        .map(|e| e.version.as_str())
        .filter(|v| !ordering.is_prerelease(v))
        .max_by(|a, b| ordering.compare(a, b))
        .or_else(|| {
            entries
                .iter()
                .map(|e| e.version.as_str())
                .max_by(|a, b| ordering.compare(a, b))
        })
}

/// Compose the per-version JSON object shared by the full packument
/// builder and the abbreviated per-version route: `name`, `version`,
/// `dist`, then the install-v1 manifest whitelist the payload carries,
/// merged in verbatim. A whitelist key is never `name`/`version`/`dist`,
/// so the merge cannot displace the triple.
/// `None` for a non-`Npm` payload (cross-format mis-tag — see
/// [`NpmIndexBuilder::build`]'s panics section).
pub fn version_entry_json(base_url: &str, entry: &VersionEntry) -> Option<serde_json::Value> {
    let PerVersionPayload::Npm(payload) = &entry.payload else {
        return None;
    };

    let tarball_url = format!(
        "{base_url}/{name}/-/{basename}",
        name = payload.name_as_published,
        basename = payload.tarball_basename,
    );
    let mut dist = serde_json::Map::new();
    dist.insert(
        "tarball".to_string(),
        serde_json::Value::String(tarball_url),
    );
    dist.insert(
        "shasum".to_string(),
        serde_json::Value::String(payload.shasum.clone()),
    );
    if let Some(sri) = payload.integrity.as_ref() {
        dist.insert(
            "integrity".to_string(),
            serde_json::Value::String(sri.clone()),
        );
    }

    let mut out = serde_json::Map::with_capacity(3 + payload.manifest.len());
    out.insert(
        "name".to_string(),
        serde_json::Value::String(payload.name_as_published.clone()),
    );
    out.insert(
        "version".to_string(),
        serde_json::Value::String(entry.version.clone()),
    );
    out.insert("dist".to_string(), serde_json::Value::Object(dist));
    for (key, value) in &payload.manifest {
        out.insert(key.clone(), value.clone());
    }
    Some(serde_json::Value::Object(out))
}

/// npm `IndexBuilder` — emits the packument JSON from a post-filter
/// `Vec<VersionEntry>`.
///
/// Stateless; the per-format serve handler constructs an instance per
/// request (cheap — it's a unit struct). The Item-1 [`IndexBuilder`]
/// trait contract is "stateless wire-shape emitter"; this matches.
///
/// # Panics
///
/// Never panics on a well-formed input. A `VersionEntry` carrying a
/// non-`Npm` `PerVersionPayload` variant is the only ill-formed
/// shape; the builder skips such entries with a structured `warn!`
/// and emits a degraded packument (the entry is simply absent from
/// `versions{}`). This is a defence-in-depth posture against a
/// hypothetical future source adapter that mis-tags its payloads;
/// today the only constructible variant is `Npm`, so the warn arm
/// is unreachable on the production hot path. Pinning it behind a
/// warn rather than a `panic!` keeps the serve-time error mode the
/// same as `rewrite_packument`'s parse-failure passthrough.
#[derive(Debug, Default, Clone, Copy)]
pub struct NpmIndexBuilder;

impl IndexBuilder for NpmIndexBuilder {
    fn build(&self, ctx: BuildContext<'_>, entries: Vec<VersionEntry>) -> Bytes {
        // Pre-compute the served-max over the post-filter entries.
        // `dist-tags.latest` points here. A pre-release never wins
        // while a release is served: take the max over non-prerelease
        // entries first, falling back to the unfiltered max only when
        // the served set is all-prerelease (still non-empty). An empty
        // served set produces no `dist-tags` block (the wire-equivalent
        // of "no servable latest").
        let latest: Option<&str> = resolve_served_latest(&entries, ctx.ordering);

        let mut versions = serde_json::Map::new();
        for entry in &entries {
            // Cross-format mis-tag defence: a Pypi/Cargo payload
            // should never reach the npm builder, but the closed-sum is
            // enforced at the use-case layer not at the builder layer,
            // so the match arm is reachable in principle. Skip with a
            // structured warn (degraded packument, never a panic).
            match version_entry_json(ctx.base_url, entry) {
                Some(v) => {
                    versions.insert(entry.version.clone(), v);
                }
                None => {
                    tracing::warn!(
                        version = %entry.version,
                        "npm packument builder: skipping VersionEntry with non-Npm payload \
                         (cross-format mis-tag — should be unreachable)",
                    );
                }
            }
        }

        let mut packument = serde_json::Map::new();
        packument.insert(
            "name".to_string(),
            serde_json::Value::String(ctx.package_name.to_string()),
        );
        packument.insert("versions".to_string(), serde_json::Value::Object(versions));
        // Empty entries → no `dist-tags` block. Mirrors the
        // Wire-shape for "nothing servable": no dist-tags block. The
        // client falls back to lockfile-or-error.
        if let Some(v) = latest {
            let mut dist_tags = serde_json::Map::new();
            dist_tags.insert(
                "latest".to_string(),
                serde_json::Value::String(v.to_string()),
            );
            packument.insert(
                "dist-tags".to_string(),
                serde_json::Value::Object(dist_tags),
            );
        }

        // `serde_json::to_vec` on a `serde_json::Map` is infallible
        // (no non-string keys, no `f64::NAN` floats — the input is
        // built entirely from `Value::String` and `Value::Object`).
        // `expect` documents the invariant.
        let bytes = serde_json::to_vec(&serde_json::Value::Object(packument))
            .expect("NpmIndexBuilder serialises owned String / Object values only");
        Bytes::from(bytes)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use hort_app::use_cases::index_serve_filter::NpmSemverOrdering;
    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::repository::IndexMode;

    use super::*;

    fn entry(version: &str, payload: NpmVersionPayload) -> VersionEntry {
        VersionEntry {
            version: version.to_string(),
            status: Some(QuarantineStatus::Released),
            payload: PerVersionPayload::Npm(payload),
        }
    }

    fn payload(
        name: &str,
        basename: &str,
        integrity: Option<&str>,
        shasum: &str,
    ) -> NpmVersionPayload {
        NpmVersionPayload {
            name_as_published: name.to_string(),
            tarball_basename: basename.to_string(),
            integrity: integrity.map(str::to_string),
            shasum: shasum.to_string(),
            manifest: serde_json::Map::new(),
        }
    }

    fn build(entries: Vec<VersionEntry>, package: &str, base: &str) -> serde_json::Value {
        let bytes = NpmIndexBuilder.build(
            BuildContext {
                package_name: package,
                base_url: base,
                index_mode: IndexMode::ReleasedOnly,
                ordering: &NpmSemverOrdering,
            },
            entries,
        );
        serde_json::from_slice(&bytes).expect("builder emits valid JSON")
    }

    // -----------------------------------------------------------------
    // 1. Empty served set → packument with empty `versions{}` and NO
    //    `dist-tags` block.
    // -----------------------------------------------------------------

    #[test]
    fn empty_entries_produces_packument_with_empty_versions_and_no_dist_tags() {
        let json = build(Vec::new(), "express", "https://r.example/npm/m");
        assert_eq!(json["name"].as_str().unwrap(), "express");
        assert!(
            json["versions"].as_object().unwrap().is_empty(),
            "empty entries must produce an empty versions{{}} object"
        );
        assert!(
            json.get("dist-tags").is_none(),
            "empty entries must NOT emit a dist-tags block (dist-tags.latest regression guard)"
        );
    }

    // -----------------------------------------------------------------
    // 2. Single-version set — all four NpmVersionPayload fields render
    //    correctly. Pins the per-field emission contract.
    // -----------------------------------------------------------------

    #[test]
    fn single_version_emits_full_dist_block_with_all_fields() {
        let p = payload(
            "express",
            "express-1.0.0.tgz",
            Some("sha512-aGVsbG8="),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        );
        let json = build(
            vec![entry("1.0.0", p)],
            "express",
            "https://r.example/npm/m",
        );
        let v = &json["versions"]["1.0.0"];
        assert_eq!(v["name"].as_str().unwrap(), "express");
        assert_eq!(v["version"].as_str().unwrap(), "1.0.0");
        assert_eq!(
            v["dist"]["tarball"].as_str().unwrap(),
            "https://r.example/npm/m/express/-/express-1.0.0.tgz",
            "dist.tarball must be built from base_url + name_as_published + tarball_basename"
        );
        assert_eq!(
            v["dist"]["shasum"].as_str().unwrap(),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(v["dist"]["integrity"].as_str().unwrap(), "sha512-aGVsbG8=");
        assert_eq!(json["dist-tags"]["latest"].as_str().unwrap(), "1.0.0");
    }

    #[test]
    fn manifest_whitelist_merges_alongside_the_name_version_dist_triple() {
        let mut p = payload("express", "express-1.0.0.tgz", None, "abc123");
        p.manifest = crate::npm::extract_install_v1_manifest(&serde_json::json!({
            "name": "express",
            "dependencies": {"body-parser": "^1.20.0"},
            "engines": {"node": ">=18"},
            "deprecated": "moved to @express/core",
            "scripts": {"test": "mocha"},
        }));
        let json = build(
            vec![entry("1.0.0", p)],
            "express",
            "https://r.example/npm/m",
        );
        let v = &json["versions"]["1.0.0"];
        // The triple survives the merge.
        assert_eq!(v["name"].as_str().unwrap(), "express");
        assert_eq!(v["version"].as_str().unwrap(), "1.0.0");
        assert_eq!(
            v["dist"]["tarball"].as_str().unwrap(),
            "https://r.example/npm/m/express/-/express-1.0.0.tgz"
        );
        // Whitelist keys ride alongside it, verbatim.
        assert_eq!(
            v["dependencies"],
            serde_json::json!({"body-parser": "^1.20.0"})
        );
        assert_eq!(v["engines"], serde_json::json!({"node": ">=18"}));
        assert_eq!(v["deprecated"].as_str().unwrap(), "moved to @express/core");
        // Out-of-contract keys never reach the wire.
        assert!(v.get("scripts").is_none());
        // Absent whitelist keys are absent, not null.
        assert!(v.get("os").is_none());
        assert!(v.get("optionalDependencies").is_none());
    }

    #[test]
    fn empty_manifest_emits_exactly_the_name_version_dist_triple() {
        let p = payload("express", "express-1.0.0.tgz", None, "abc123");
        let json = build(
            vec![entry("1.0.0", p)],
            "express",
            "https://r.example/npm/m",
        );
        let mut keys: Vec<&str> = json["versions"]["1.0.0"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["dist", "name", "version"]);
    }

    // -----------------------------------------------------------------
    // 3. `integrity = None` — the key is OMITTED, not emitted as null.
    //    Mirrors the npm convention (`dist.integrity` absent on legacy
    //    sources rather than `null`).
    // -----------------------------------------------------------------

    #[test]
    fn absent_integrity_omits_the_key_rather_than_emitting_null() {
        let p = payload("hosted-pkg", "hosted-pkg-1.0.0.tgz", None, "abc123");
        let json = build(
            vec![entry("1.0.0", p)],
            "hosted-pkg",
            "https://r.example/npm/m",
        );
        let dist = &json["versions"]["1.0.0"]["dist"];
        assert!(
            dist.get("integrity").is_none(),
            "absent integrity must be omitted, NOT emitted as null"
        );
        assert_eq!(dist["shasum"].as_str().unwrap(), "abc123");
        assert!(
            dist["tarball"].as_str().is_some(),
            "tarball must still emit when integrity is absent"
        );
    }

    // -----------------------------------------------------------------
    // 4. Multi-version semver — `dist-tags.latest` is the semver-max,
    //    not the lex-max. Pins NpmSemverOrdering hooked correctly.
    // -----------------------------------------------------------------

    #[test]
    fn dist_tags_latest_is_semver_max_not_lex_max() {
        let entries = vec![
            entry("1.9.0", payload("p", "p-1.9.0.tgz", None, "a")),
            entry("1.10.0", payload("p", "p-1.10.0.tgz", None, "b")),
            entry("1.2.0", payload("p", "p-1.2.0.tgz", None, "c")),
        ];
        let json = build(entries, "p", "https://r.example/npm/m");
        // Lex-max would pick "1.9.0" (> "1.10.0" in lex order); semver
        // picks "1.10.0". The builder must take the ordering from
        // BuildContext, so this proves NpmSemverOrdering reaches the
        // builder correctly.
        assert_eq!(
            json["dist-tags"]["latest"].as_str().unwrap(),
            "1.10.0",
            "dist-tags.latest must use NpmSemverOrdering, not lex"
        );
        // All three versions must appear in versions{}.
        let versions = json["versions"].as_object().unwrap();
        assert_eq!(versions.len(), 3);
        assert!(versions.contains_key("1.2.0"));
        assert!(versions.contains_key("1.9.0"));
        assert!(versions.contains_key("1.10.0"));
    }

    // -----------------------------------------------------------------
    // 4b. dist-tags.latest excludes a semver-greater prerelease while a
    //     release is served — the npm ecosystem contract that a bare
    //     `npm i`/`pnpm add` never installs a canary.
    // -----------------------------------------------------------------

    #[test]
    fn dist_tags_latest_excludes_prerelease_when_release_is_served() {
        let entries = vec![
            entry("1.2.8", payload("p", "p-1.2.8.tgz", None, "a")),
            entry(
                "1.3.0-canary.0",
                payload("p", "p-1.3.0-canary.0.tgz", None, "b"),
            ),
        ];
        let json = build(entries, "p", "https://r.example/npm/m");
        assert_eq!(
            json["dist-tags"]["latest"].as_str().unwrap(),
            "1.2.8",
            "a prerelease must never win latest while a release is served, \
             even though it is semver-greater"
        );
        let versions = json["versions"].as_object().unwrap();
        assert!(
            versions.contains_key("1.3.0-canary.0"),
            "the prerelease is still SERVED, only excluded from dist-tags.latest"
        );
    }

    #[test]
    fn dist_tags_latest_falls_back_to_prerelease_max_when_all_prerelease() {
        let entries = vec![
            entry("1.0.0-alpha.1", payload("p", "p-a1.tgz", None, "a")),
            entry("1.0.0-alpha.2", payload("p", "p-a2.tgz", None, "b")),
        ];
        let json = build(entries, "p", "https://r.example/npm/m");
        assert_eq!(
            json["dist-tags"]["latest"].as_str().unwrap(),
            "1.0.0-alpha.2",
            "an all-prerelease served set still gets a usable latest tag"
        );
    }

    #[test]
    fn dist_tags_latest_build_metadata_only_version_treated_as_release() {
        let entries = vec![
            entry("1.0.0+build.5", payload("p", "p-b5.tgz", None, "a")),
            entry("1.0.0-rc.1", payload("p", "p-rc1.tgz", None, "b")),
        ];
        let json = build(entries, "p", "https://r.example/npm/m");
        assert_eq!(
            json["dist-tags"]["latest"].as_str().unwrap(),
            "1.0.0+build.5",
            "build metadata alone is not a prerelease; it must beat an actual \
             prerelease for latest"
        );
    }

    // -----------------------------------------------------------------
    // 5. Scoped package — name_as_published carries the `@scope/pkg`
    //    form and the URL embeds it verbatim. Matches the npm
    //    public-registry convention and the existing local-CAS
    //    handler's emission shape.
    // -----------------------------------------------------------------

    #[test]
    fn scoped_package_emits_unencoded_scope_in_tarball_url() {
        let p = payload("@types/node", "node-20.0.0.tgz", Some("sha512-yyy"), "def");
        let json = build(
            vec![entry("20.0.0", p)],
            "@types/node",
            "https://r.example/npm/m",
        );
        let v = &json["versions"]["20.0.0"];
        assert_eq!(v["name"].as_str().unwrap(), "@types/node");
        assert_eq!(
            v["dist"]["tarball"].as_str().unwrap(),
            "https://r.example/npm/m/@types/node/-/node-20.0.0.tgz",
            "scoped tarball URL must carry the `@scope/pkg` segment unencoded"
        );
    }

    // -----------------------------------------------------------------
    // 6. URL construction comes ONLY from base_url + payload, NEVER
    //    leaks a raw upstream URL through. Pins the architectural
    //    contract: the builder is the URL-construction site, not the
    //    rewriter. (If a future regression had the source adapter
    //    stash an upstream URL in some payload field and the builder
    //    emitted it, this test catches it — no upstream-shape value
    //    survives the builder.)
    // -----------------------------------------------------------------

    #[test]
    fn url_construction_uses_base_url_and_basename_never_raw_upstream() {
        // basename is just `pkg-1.0.0.tgz`; the test pins that the
        // emitted URL is base_url + name + "/-/" + basename, with NO
        // upstream host like "registry.npmjs.org" leaking through.
        let p = payload("p", "p-1.0.0.tgz", None, "x");
        let json = build(vec![entry("1.0.0", p)], "p", "http://localhost/npm/m");
        let url = json["versions"]["1.0.0"]["dist"]["tarball"]
            .as_str()
            .unwrap();
        assert_eq!(url, "http://localhost/npm/m/p/-/p-1.0.0.tgz");
        assert!(
            !url.contains("registry.npmjs.org"),
            "URL must NOT carry any upstream-host bytes: {url}"
        );
    }

    // -----------------------------------------------------------------
    // 7. Top-level `name` always reflects BuildContext.package_name
    //    verbatim, even when the per-version `name_as_published`
    //    diverges (drift-era hosted artifact case).
    // -----------------------------------------------------------------

    #[test]
    fn top_level_name_reflects_build_context_not_per_version_name() {
        // The drift case: request was for "drift-pkg" but the stored
        // artifact's name is "legacy-name". The hosted source supplies
        // BuildContext.package_name = stored canonical name
        // ("legacy-name"); the top-level `name` reflects that.
        let p = payload("legacy-name", "legacy-name-1.0.0.tgz", None, "x");
        let json = build(
            vec![entry("1.0.0", p)],
            "legacy-name",
            "https://r.example/npm/m",
        );
        assert_eq!(json["name"].as_str().unwrap(), "legacy-name");
        assert_eq!(
            json["versions"]["1.0.0"]["name"].as_str().unwrap(),
            "legacy-name"
        );
        assert_eq!(
            json["versions"]["1.0.0"]["dist"]["tarball"]
                .as_str()
                .unwrap(),
            "https://r.example/npm/m/legacy-name/-/legacy-name-1.0.0.tgz"
        );
    }

    // -----------------------------------------------------------------
    // `resolve_served_latest` — direct unit tests for the extracted
    // helper (the builder's `dist-tags.latest` derivation, and the
    // abbreviated per-version route's `latest` resolution, both call
    // this one definition).
    // -----------------------------------------------------------------

    #[test]
    fn resolve_served_latest_release_mix_excludes_prerelease() {
        let entries = vec![
            entry("1.2.8", payload("p", "p-1.2.8.tgz", None, "a")),
            entry(
                "1.3.0-canary.0",
                payload("p", "p-1.3.0-canary.0.tgz", None, "b"),
            ),
        ];
        assert_eq!(
            resolve_served_latest(&entries, &NpmSemverOrdering),
            Some("1.2.8"),
            "a prerelease must never win latest while a release is served"
        );
    }

    #[test]
    fn resolve_served_latest_all_prerelease_falls_back_to_prerelease_max() {
        let entries = vec![
            entry("1.0.0-alpha.1", payload("p", "p-a1.tgz", None, "a")),
            entry("1.0.0-alpha.2", payload("p", "p-a2.tgz", None, "b")),
        ];
        assert_eq!(
            resolve_served_latest(&entries, &NpmSemverOrdering),
            Some("1.0.0-alpha.2"),
            "an all-prerelease served set still resolves a usable latest"
        );
    }

    #[test]
    fn resolve_served_latest_empty_set_is_none() {
        assert_eq!(resolve_served_latest(&[], &NpmSemverOrdering), None);
    }
}
