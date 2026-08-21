# 134 — Streaming lockfile extraction and the per-crate closure walk

Issue: #191, spec §2 D1+D2 (the spec lives in the issue description).
**Read first:** `crates/hort-formats/src/cargo.rs` (`extract_dependency_specs`,
the tarball walk), `crates/hort-formats/src/sbom_helpers.rs`,
`crates/hort-formats/src/stream_helpers.rs`, the cargo lockfile format
(v3/v4 TOML — the official cargo book section is the authority).

Pure machinery in `hort-formats`, no orchestration changes here:

1. **Streaming extraction** of `{name}-{version}/Cargo.lock` from a `.crate`
   gzip-tarball via `&mut dyn Read` (generalise the existing walk; ADR 0026 —
   no whole-body buffering; the `streaming_metadata_port` guard must stay
   green). A `.crate` without a lockfile yields `None`, never an error.
2. **Closure walk**: pure function `(parsed lockfile, crate name, version) →
   Vec<ResolvedComponent { name, version, checksum: Option }>` — start at the
   published crate's `[[package]]` node, walk `dependencies` edges
   transitively, dedup.
3. **Known subtlety to resolve and declare:** a workspace member's lockfile
   node lists its dev-dependency edges too; the published manifest does not
   ship path-only dev-deps. Options: seed the first hop from the stored
   index-shape deps (#188 — they carry `kind`, so dev edges are excludable)
   and walk transitively from there, or accept the dev-dep over-approximation
   with a comment. Pick with the objectively-better discipline and declare
   the choice in the report.
4. Registry-path packages only; path/git-sourced lockfile entries without a
   registry version are skipped and counted (one metric).

**Acceptance:** table-driven tests over a workspace fixture lockfile
(transitive, build-dep, dev-dep, duplicate-version, path-dep cases); the
absent-lockfile path; no I/O in the closure walk; `cargo test --workspace`
green; coverage ≥ 85 % on the crate.
