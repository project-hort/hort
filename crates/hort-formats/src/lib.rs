//! # hort-formats — Format Module Host
//!
//! **Status (v1): the WASM host below is a *planned* (post-v1) target, NOT
//! wired today** — there is no `wasmtime` in the build and no
//! `$WASM_PLUGIN_DIR` loading. Format handlers are currently compiled-in
//! Rust structs behind the `FormatHandler` trait (see "Compiled-in handlers"
//! below and ADR 0005). The sections that follow describe the intended WASM
//! design and are written in the future tense.
//!
//! *(Planned)* Loads deploy-time WASM format modules from `$WASM_PLUGIN_DIR`,
//! introspects their capability group declarations via the module manifest,
//! and dispatches format-specific operations (parse coords, generate index,
//! verify checksum, handle stateful protocol) to the appropriate module.
//!
//! Depends on: hort-domain (FormatPort trait, capability group types), hort-app
//! Used by:    each hort-http-<format> crate (constructs its own
//!             FormatHandler) and hort-server::composition (reconcile CLI)
//!
//! ## Capability groups
//!
//! Each WASM module declares which groups it implements in its manifest:
//! - Core (all formats): parse_coords, build_index, verify_upstream_checksum
//! - SimpleIndex: generate_index
//! - SignedIndex: generate_unsigned_index (host signs with repo key)
//! - MultiFileArtifact: classify_group_member, build_artifact_logical_path, resolve_mutable_version
//!   (realised today via the `classify_group_member`→`ArtifactGroup` push model;
//!   Maven/Gradle is the shipped instance — see ADR 0032. The earlier
//!   `file_group_key, artifact_is_complete` sketch is stale.)
//! - StatefulUpload: handle_request (OCI, Git LFS — full HTTP request/response)
//!
//! Modules in groups 1–4 receive no I/O capabilities beyond function arguments.
//! Modules in group 5 (StatefulUpload) receive a session store import scoped
//! to their own sessions within a single repository.
//!
//! ## Compiled-in handlers
//!
//! Format handlers are currently compiled-in Rust structs behind the
//! `FormatHandler` trait boundary (see explanation/format-handlers.md + ADR 0005).
//! Migration to deploy-time WASM modules is planned.
//!
//! ## Hot reload *(planned)*
//!
//! Once the WASM host ships, modules will be reloaded from disk on SIGHUP
//! without restarting the process: the host re-reads manifests and
//! re-registers routes for any changed modules. (Not implemented in v1.)

pub mod archive_bounds;
pub mod cargo;
// Format-agnostic index-construction trait skeleton (`IndexFilter`,
// `IndexBuilder`, `VersionEntry`, `PerVersionPayload`, `BuildContext`).
// Per-format builder modules live in npm/index.rs, pypi/index.rs,
// cargo/index.rs. See explanation/index-construction.md.
pub mod index_serve;
// Maven / Gradle format handler: GA:V identity, path build/parse, multi-file
// group classification (pom/jar/sources/javadoc/module), and SNAPSHOT
// mutable-version resolution. Gradle is served by the same handler (Maven
// layout + GMM `.module` member). See explanation/format-handlers.md + the
// Maven design doc; ADR 0005 (MultiFileArtifact) / ADR 0032 / ADR 0033.
pub mod maven;
pub mod npm;
pub mod oci;
pub mod pypi;
pub(crate) mod range_resolvers;
pub(crate) mod sbom_helpers;
// Shared streaming-port helpers for the `FormatHandler` body methods
// (`parse_upstream_checksum`, `extract_upstream_versions`,
// `extract_dependency_specs`). See ADR 0026.
pub(crate) mod stream_helpers;

// Cross-crate test fixtures for archive construction. Gated by the
// `test-support` feature so downstream test consumers (`hort-http-pypi`,
// `hort-adapters-advisory-osv`, …) can pull wheel-ZIP / OSV-ZIP builders
// without taking a direct `zip` dep — `deny.toml`'s `[bans]
// wrappers = ["hort-formats"]` rule for `zip` enforces this at the
// dep-tree level.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

#[cfg(test)]
mod scan_kind_classification_tests {
    //! `FormatHandler::scan_kind` classification guard.
    //!
    //! DB-free, network-free, sub-second structural guard over how each
    //! shipped format handler classifies its stored rows for content
    //! scanning — in the spirit of `version_discovery_participation` /
    //! `retention_registration_guard`, but in-crate rather than a `tests/`
    //! target: it needs nothing outside `hort-formats`, so living here lets
    //! it share the `test_support` row fixture and count toward the crate's
    //! `--lib` coverage. Its siblings below (the inherited-default guards)
    //! are the same shape.
    //!
    //! ## Why this guard exists
    //!
    //! `scan_kind` is the single point where "what are these bytes" is
    //! decided, and a scanner adapter cannot second-guess it: the whole
    //! materialisation — the file name a Java archive keeps, whether a
    //! payload is extracted, whether a scanner is invoked at all — follows
    //! from the answer. A misclassification is therefore silent: the scan
    //! still runs, still completes, and still writes a verdict; only the
    //! *evidence* behind that verdict is gone. Nothing in the type system
    //! catches that, so the classification is pinned here.
    //!
    //! ## What it asserts
    //!
    //! 1. **Exhaustiveness over [`ArtifactKind`].** [`representative_row`] is
    //!    a `match` with **no `_` arm**: every variant names a shipped
    //!    handler and a real stored path that must classify as it. A variant
    //!    added in `hort-domain` fails to COMPILE until it is consciously
    //!    placed — either with a producing handler, or as a kind no shipped
    //!    handler produces.
    //! 2. **Real stored-path shapes.** The paths are the ones the handlers'
    //!    own `build_artifact_logical_path` produces, not invented strings.
    //! 3. **Nothing claims a kind it cannot materialise.** A handler must
    //!    never claim a container the adapter has no extraction for — the
    //!    long-tail PyPI sdist containers (`.zip`, `.tar.bz2`, `.egg`) are
    //!    the live case, and they must classify as `Other`.

    use crate::cargo::CargoFormatHandler;
    use crate::maven::MavenFormatHandler;
    use crate::npm::NpmFormatHandler;
    use crate::oci::OciFormatHandler;
    use crate::pypi::PyPiFormatHandler;
    use crate::test_support::artifact_row_at;
    use hort_domain::ports::format_handler::FormatHandler;
    use hort_domain::types::ArtifactKind;

    fn handler(key: &str) -> Box<dyn FormatHandler> {
        match key {
            "maven" => Box::new(MavenFormatHandler),
            "npm" => Box::new(NpmFormatHandler),
            "cargo" => Box::new(CargoFormatHandler),
            "pypi" => Box::new(PyPiFormatHandler),
            "oci" => Box::new(OciFormatHandler),
            other => panic!("no handler registered in this guard for key {other}"),
        }
    }

    /// The `(handler key, stored path)` that must classify as `kind`.
    ///
    /// Exhaustive over [`ArtifactKind`] on purpose — **no `_` wildcard arm**.
    /// Every variant is produced by a shipped handler today; a future variant
    /// that no handler produces belongs here as a compile-forced decision
    /// (return `None` and extend the caller), not as a silent wildcard.
    fn representative_row(kind: ArtifactKind) -> (&'static str, &'static str) {
        match kind {
            ArtifactKind::MavenJar => (
                "maven",
                "org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar",
            ),
            ArtifactKind::MavenPom => (
                "maven",
                "org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.pom",
            ),
            ArtifactKind::NpmTarball => ("npm", "lodash/-/lodash-4.17.21.tgz"),
            ArtifactKind::CargoCrate => ("cargo", "crates/tokio/1.35.1/tokio-1.35.1.crate"),
            ArtifactKind::PyWheel => ("pypi", "simple/urllib3/urllib3-1.26.4-py2.py3-none-any.whl"),
            ArtifactKind::PySdist => ("pypi", "simple/urllib3/urllib3-1.26.4.tar.gz"),
            ArtifactKind::OciBlob => (
                "oci",
                "blobs/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            ArtifactKind::OciManifest => (
                "oci",
                "manifests/sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
            // A checksum sidecar: a real Maven row with no analyser.
            ArtifactKind::Other => ("maven", "com/example/lib/1.0.0/lib-1.0.0.jar.sha1"),
        }
    }

    /// Every [`ArtifactKind`], for iteration. Kept next to
    /// [`representative_row`] so the two are edited together; the match there
    /// is what makes forgetting one a compile error.
    const ALL_KINDS: &[ArtifactKind] = &[
        ArtifactKind::MavenJar,
        ArtifactKind::MavenPom,
        ArtifactKind::NpmTarball,
        ArtifactKind::CargoCrate,
        ArtifactKind::PyWheel,
        ArtifactKind::PySdist,
        ArtifactKind::OciBlob,
        ArtifactKind::OciManifest,
        ArtifactKind::Other,
    ];

    #[test]
    fn every_artifact_kind_has_a_shipped_handler_that_produces_it() {
        for kind in ALL_KINDS {
            let (key, path) = representative_row(*kind);
            let got = handler(key).scan_kind(&artifact_row_at(path));
            assert_eq!(
                got, *kind,
                "{key} handler classified {path} as {got} — expected {kind}"
            );
        }
    }

    /// Further real stored paths per handler, beyond the one representative
    /// each kind needs: the rest of the Java-archive extension set, a scoped
    /// npm name, and every path shape that must land on `Other`.
    #[test]
    fn additional_stored_path_shapes_classify_as_expected() {
        let cases: &[(&str, &str, ArtifactKind)] = &[
            // The Java-archive extension set Trivy's JAR analyser claims.
            (
                "maven",
                "com/example/app/1.0.0/app-1.0.0.war",
                ArtifactKind::MavenJar,
            ),
            (
                "maven",
                "com/example/app/1.0.0/app-1.0.0.ear",
                ArtifactKind::MavenJar,
            ),
            (
                "maven",
                "com/example/app/1.0.0/app-1.0.0.par",
                ArtifactKind::MavenJar,
            ),
            // A classifier does not change the container.
            (
                "maven",
                "com/example/lib/1.0.0/lib-1.0.0-sources.jar",
                ArtifactKind::MavenJar,
            ),
            // Maven rows with no analyser: a Gradle module descriptor, an
            // Android archive, the A-level metadata document.
            (
                "maven",
                "com/example/lib/1.0.0/lib-1.0.0.module",
                ArtifactKind::Other,
            ),
            (
                "maven",
                "com/example/lib/1.0.0/lib-1.0.0.aar",
                ArtifactKind::Other,
            ),
            (
                "maven",
                "com/example/lib/maven-metadata.xml",
                ArtifactKind::Other,
            ),
            // npm: a scoped package keeps the `.tgz` container.
            (
                "npm",
                "@scope/pkg/-/pkg-1.0.0.tgz",
                ArtifactKind::NpmTarball,
            ),
            // Long-tail PyPI sdist containers the materialiser has no
            // extraction for. Claiming `PySdist` here would turn a clean
            // refusal into an extraction failure.
            ("pypi", "simple/legacy/legacy-1.0.zip", ArtifactKind::Other),
            (
                "pypi",
                "simple/legacy/legacy-1.0.tar.bz2",
                ArtifactKind::Other,
            ),
            (
                "pypi",
                "simple/legacy/legacy-1.0-py3.7.egg",
                ArtifactKind::Other,
            ),
            // OCI: a tag-addressed manifest is still a manifest.
            ("oci", "manifests/v1.2.3", ArtifactKind::OciManifest),
        ];
        for (key, path, expected) in cases {
            let got = handler(key).scan_kind(&artifact_row_at(path));
            assert_eq!(
                got, *expected,
                "{key} handler classified {path} as {got} — expected {expected}"
            );
        }
    }

    /// A format with no registered handler inherits the trait default, and
    /// the default is the refusal, not a guess. Pinned through a
    /// no-overrides stand-in so the assertion is about the trait default.
    #[test]
    fn unclaimed_formats_inherit_the_other_classification() {
        struct NoOverrides;
        impl FormatHandler for NoOverrides {
            fn format_key(&self) -> &str {
                "generic"
            }
            fn parse_download_path(
                &self,
                _path: &str,
            ) -> hort_domain::error::DomainResult<hort_domain::types::ArtifactCoords> {
                Err(hort_domain::error::DomainError::Validation("n/a".into()))
            }
            fn normalize_name(&self, name: &str) -> String {
                name.to_string()
            }
        }
        assert_eq!(
            NoOverrides.scan_kind(&artifact_row_at("anything/at/all.jar")),
            ArtifactKind::Other
        );
    }
}

#[cfg(test)]
mod classify_group_member_default_tests {
    //! Regression guard: the three compiled-in format handlers (PyPI,
    //! cargo, npm) MUST inherit the trait-level default of
    //! [`FormatHandler::classify_group_member`]. That default returns
    //! `None`, which preserves their single-file artifact behaviour
    //! bit-for-bit — no groups, no stray `ArtifactGroupInitiated` events
    //! emitted at ingest time. An accidental override here would start
    //! creating groups for every upload across these formats, silently
    //! changing the event stream.
    use hort_domain::entities::repository::RepositoryFormat;
    use hort_domain::ports::format_handler::FormatHandler;
    use hort_domain::types::ArtifactCoords;

    use crate::cargo::CargoFormatHandler;
    use crate::npm::NpmFormatHandler;
    use crate::pypi::PyPiFormatHandler;

    fn coords_for(format: RepositoryFormat, path: &str) -> ArtifactCoords {
        ArtifactCoords {
            name: "pkg".into(),
            name_as_published: "pkg".into(),
            version: Some("1.0.0".into()),
            path: path.into(),
            format,
            metadata: serde_json::Value::Null,
        }
    }

    #[test]
    fn pypi_handler_inherits_default_none() {
        let c = coords_for(RepositoryFormat::Pypi, "pkg/1.0.0/pkg-1.0.0.tar.gz");
        assert!(PyPiFormatHandler
            .classify_group_member(&c, &c.path)
            .is_none());
    }

    #[test]
    fn cargo_handler_inherits_default_none() {
        let c = coords_for(RepositoryFormat::Cargo, "pkg/1.0.0/download");
        assert!(CargoFormatHandler
            .classify_group_member(&c, &c.path)
            .is_none());
    }

    #[test]
    fn npm_handler_inherits_default_none() {
        let c = coords_for(RepositoryFormat::Npm, "pkg/-/pkg-1.0.0.tgz");
        assert!(NpmFormatHandler
            .classify_group_member(&c, &c.path)
            .is_none());
    }
}

#[cfg(test)]
mod resolve_mutable_version_default_tests {
    //! Regression guard: the three compiled-in format handlers (PyPI,
    //! cargo, npm) MUST inherit the trait-level default of
    //! [`FormatHandler::resolve_mutable_version`]. That default returns
    //! `Ok(None)` — these formats publish only immutable versions, so a
    //! version request is always already concrete and never gets rewritten.
    //! Maven SNAPSHOT is the only v1 implementer. An accidental override
    //! here would start resolving (and silently redirecting) version
    //! requests for formats that have no mutable-version concept.
    use hort_domain::ports::format_handler::FormatHandler;

    use crate::cargo::CargoFormatHandler;
    use crate::npm::NpmFormatHandler;
    use crate::pypi::PyPiFormatHandler;

    #[test]
    fn pypi_handler_inherits_default_none() {
        let r =
            PyPiFormatHandler.resolve_mutable_version("pkg-1.0.0.tar.gz", &["pkg-1.0.0.tar.gz"]);
        assert!(matches!(r, Ok(None)));
    }

    #[test]
    fn cargo_handler_inherits_default_none() {
        let r = CargoFormatHandler
            .resolve_mutable_version("pkg/1.0.0/download", &["pkg/1.0.0/download"]);
        assert!(matches!(r, Ok(None)));
    }

    #[test]
    fn npm_handler_inherits_default_none() {
        let r = NpmFormatHandler
            .resolve_mutable_version("pkg/-/pkg-1.0.0.tgz", &["pkg/-/pkg-1.0.0.tgz"]);
        assert!(matches!(r, Ok(None)));
    }
}

#[cfg(test)]
mod maven_overrides_multifile_defaults_tests {
    //! Counterpart guard to the `*_default_tests` modules above: the Maven
    //! handler is the ONE v1 format that MUST OVERRIDE the MultiFileArtifact
    //! trait members ([`FormatHandler::classify_group_member`] and
    //! [`FormatHandler::resolve_mutable_version`]) rather than inherit their
    //! inert defaults. If a refactor accidentally deleted Maven's overrides,
    //! the default `None`/`Ok(None)` would silently disable Maven grouping
    //! and SNAPSHOT resolution — these tests pin that the overrides are live.
    use hort_domain::ports::format_handler::FormatHandler;
    use hort_domain::types::ArtifactCoords;

    use crate::maven::{MavenFormatHandler, MAVEN_KIND_FILE, MAVEN_PATH_KIND_KEY};

    #[test]
    fn maven_overrides_classify_group_member() {
        // A jar file IS classified as a group member (override is live).
        let path = "com/example/foo/1.0/foo-1.0.jar";
        let coords = ArtifactCoords {
            name: "com.example:foo".into(),
            name_as_published: "com.example:foo".into(),
            version: Some("1.0".into()),
            path: path.into(),
            format: hort_domain::entities::repository::RepositoryFormat::Maven,
            metadata: serde_json::json!({ MAVEN_PATH_KIND_KEY: MAVEN_KIND_FILE }),
        };
        let m = MavenFormatHandler
            .classify_group_member(&coords, path)
            .expect("maven must classify a jar as a group member");
        assert_eq!(m.role, "jar");
        assert!(m.is_primary);
    }

    #[test]
    fn maven_overrides_resolve_mutable_version() {
        // A SNAPSHOT request resolves to a timestamped build (override live).
        let avail = ["com/example/foo/1.0-SNAPSHOT/foo-1.0-20231201.120000-1.jar"];
        let refs: Vec<&str> = avail.to_vec();
        let got = MavenFormatHandler
            .resolve_mutable_version("com/example/foo/1.0-SNAPSHOT/foo-1.0-SNAPSHOT.jar", &refs)
            .unwrap();
        assert_eq!(got, Some(avail[0].to_string()));
    }
}
