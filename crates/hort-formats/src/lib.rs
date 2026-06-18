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
//! - MultiFileArtifact: file_group_key, artifact_is_complete, resolve_mutable_version
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
