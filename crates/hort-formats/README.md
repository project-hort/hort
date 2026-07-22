# hort-formats — Format Module Host

## Layer

Formats/WASM (planned) — depends on `hort-domain` and `hort-app`. Requires
>= 85% coverage (WASM host tests).

## Responsibility

**Status (v1): the WASM host is a planned, post-v1 target, not wired
today.** There is no `wasmtime` in the build and no `$WASM_PLUGIN_DIR`
loading — format handlers are currently compiled-in Rust structs behind the
`FormatHandler` trait (`CargoFormatHandler`, `NpmFormatHandler`,
`PyPiFormatHandler`, `MavenFormatHandler`; ADR 0005). The crate's own
module doc describes the intended WASM design in future tense; treat that
as a design target, not current behavior, when writing anything that
depends on this crate. It also hosts the shared archive-extraction bounds
helper (`archive_bounds`) and the ADR 0026 streaming-metadata helpers
(`stream_helpers`) consumed by every compiled-in handler's
`parse_upstream_checksum` / `extract_upstream_versions` /
`extract_dependency_specs` methods.

## Ports

- **Implements:** `FormatHandler` (per compiled-in handler:
  `CargoFormatHandler`, `NpmFormatHandler`, `PyPiFormatHandler`,
  `MavenFormatHandler`).
- **Consumes:** none beyond the domain/app types each handler operates on.

## Key types

- `cargo`, `npm`, `oci`, `pypi`, `maven` — public modules, one per
  compiled-in handler.
- `archive_bounds::{BoundsConfig, BoundedReader, EntryCounter,
  iter_zip_entries, read_tar_gz_entry}` — the mandated, bounded route for
  all ZIP/gzip-tar extraction workspace-wide (decompression-bomb defense:
  output/ratio/entry-count caps).
- `stream_helpers` — shared streaming-port helpers backing the ADR 0026
  `&mut dyn Read` `FormatHandler` body methods.
- Planned (not yet built): capability-group taxonomy — Core, SimpleIndex,
  SignedIndex, MultiFileArtifact (realised today via
  `classify_group_member` -> `ArtifactGroup`, Maven/Gradle is the shipped
  instance, ADR 0032), StatefulUpload (OCI/Git LFS).

## Rules

- This is the only crate in the workspace permitted to depend on
  `zip`/`flate2`/`tar` directly (`deny.toml [bans] wrappers =
  ["hort-formats"]`); any other crate extracting an archive must go through
  `archive_bounds`, never those crates directly.
- Do not describe the WASM host as shipped/wired in any doc that references
  this crate — it is explicitly a post-v1 target per the crate's own module
  doc.
