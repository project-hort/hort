# 0005 — WASM format modules with a capability-group taxonomy

- **Status:** Accepted
- **Enforced by:** format handlers are dispatched through `hort-formats` behind a `FormatPort`; the per-format index path runs through the `IndexBuilder` spine (`crates/hort-formats/src/index_serve.rs`, re-exporting `hort_app::use_cases::index_serve`). The capability taxonomy is documented in the architect skill and is the planned WIT boundary for deploy-time WASM modules.
- **Supersedes:** —

## Context

The system supports 18+ package formats. A single flat handler interface cannot capture their structural differences: npm/PyPI/Cargo are simple-index pull-through; Maven and Go ship multiple files per artifact; Debian/RPM require signed indices; OCI and Git LFS are stateful chunked-upload protocols. Compiling every format into the server binary also makes adding or updating a format a full release.

## Decision

Format handlers are **modules selected by a capability taxonomy**, with deploy-time **WASM** as the target boundary. Each format declares which **capability groups** it implements:

- **Core** (all formats): `parse_coords`, `build_index`, `verify_upstream_checksum`.
- **SimpleIndex** (npm, PyPI, Cargo, …): realised by the `IndexBuilder` + `BuildContext` spine in `hort-formats`/`hort-app`.
- **SignedIndex** (Debian, RPM), **MultiFileArtifact** (Maven, Go), **ProtocolNativeIntegrity** (OCI), **StatefulUpload** (OCI blob upload, Git LFS), **VersionDiscovery** (npm, PyPI, Cargo).

**Realisation note (MultiFileArtifact — shipped).** MultiFileArtifact is realised today via the `classify_group_member` → `GroupMembership` → `ArtifactGroup` **push model** on the compiled-in `FormatHandler` trait (each uploaded file is classified post-commit and pushed to the group aggregate, bottom-up), NOT the original `{artifact_files, primary_file, …}` sketch above. **Maven/Gradle is the shipped instance** ([ADR 0032](0032-maven-gradle-multi-file-handler.md)): its realised members are `classify_group_member`, `build_artifact_logical_path`, and `resolve_mutable_version`, all WIT-mappable as written (strings + `list<string>`; no format structs cross the boundary). WASM remains the future target boundary — the realised members map cleanly onto it.

**Realisation note (VersionDiscovery — shipped, issue #58).** Discovering a format's upstream-published versions and resolving their download URLs, split off `FormatHandler` into its own `VersionDiscovery` trait (`crates/hort-domain/src/ports/format_handler.rs`) with **eight members**: `extract_upstream_versions`, `upstream_metadata_path`, `upstream_metadata_accept`, `resolve_range_max`, `download_config_path`, `compose_download_url_from_config`, `resolve_download_url_from_metadata`, `extract_dependency_specs`. Realised the same way MultiFileArtifact is — a compiled-in trait, not yet WASM — but via an **accessor**, not a push model: `FormatHandler::version_discovery(&self) -> Option<&dyn VersionDiscovery>` (default `None`). A format either implements the whole group or inherits `None`; there is no per-method opt-in and no `capabilities() -> &[Group]` flag (a flag can disagree with reality — a format could declare the group and still inherit no-op defaults, reproducing the exact problem this accessor closes, with extra ceremony). **npm, Cargo, and PyPI are the shipped instances** — each participates in a strict subset of the eight members (cargo 6, npm 5, pypi 5; the remaining members return the same inert value the group's `FormatHandler`-level defaults used to supply before extraction, preserved exactly, not filled in — closing that spread is a follow-on, not part of this initiative). OCI, Maven, and Helm do not implement the trait at all and inherit the accessor's `None`. All eight members are WIT-mappable as written (strings, `list<string>`, and a small opaque-body streaming-reader shape; no format structs cross the boundary) — a WASM module either exports a `version-discovery` interface or it does not, which is exactly what an optional trait plus a `None`-default accessor maps onto; eight defaulted no-op methods on one flat interface did not map onto anything a module author could reason about, and fixing that ambiguity before the WIT boundary freezes was this initiative's motivation (an ADR 0005 amendment landing after the freeze would be a breaking change for every module author).

**`resolve_mutable_version` belongs to MultiFileArtifact, not VersionDiscovery.** This mis-assignment is the concrete mistake #58's own first design pass made — and the argument for the split in the first place: on a flat interface there is no way to tell which capability a method serves, so getting one wrong from inspection alone is easy. `resolve_mutable_version` resolves a mutable (re-deployable) version request to a concrete immutable stored path; its only production consumer is `hort-http-maven/src/lib.rs`'s Maven SNAPSHOT resolution, and it is already realised as a MultiFileArtifact member (see the realisation note above) — it stayed on `FormatHandler` unmoved by this initiative.

WASM modules run in a wasmtime sandbox, receive only declared capabilities, and reach all I/O (storage, event log) exclusively through host-provided ports — never direct network/filesystem/DB access. Stateful-upload protocols (OCI, Git LFS) may remain compiled-in (Tier C) where the request/response Core interface cannot model them.

## Consequences

- A format's complexity is explicit in its declared groups; a flat "implement everything" interface is rejected.
- Formats become deploy-time artifacts loaded from `$WASM_PLUGIN_DIR`, hot-reloadable on SIGHUP, without rebuilding the server. *(planned — handlers are currently compiled-in behind the `FormatHandler` trait; WASM loading is a post-v1 target)*
- The sandbox is the security boundary: a format module cannot do I/O the host did not grant.
- Modelling a stateful-upload protocol (OCI/Git LFS) with a flat Core interface is an anti-pattern — it needs the `StatefulUpload` group or a compiled-in adapter.

## Alternatives considered

- **One flat `FormatHandler` trait for every format.** Rejected: cannot express signed-index, multi-file, or stateful-upload differences without a lowest-common-denominator interface that lies about capabilities.
- **All formats compiled into the binary forever.** Rejected: ties every format change to a server release and forfeits the sandbox isolation WASM provides. (Tier C compiled-in is the bounded exception, not the rule.)

## References

- `crates/hort-formats/` — WASM host, dispatch, `src/index_serve.rs`.
- `crates/hort-app/src/use_cases/index_serve.rs` — the `IndexBuilder` spine.
- The architect skill → Format Capability Taxonomy and WIT sketch.
