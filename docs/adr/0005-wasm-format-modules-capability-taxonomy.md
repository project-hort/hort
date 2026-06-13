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
- **SignedIndex** (Debian, RPM), **MultiFileArtifact** (Maven, Go), **ProtocolNativeIntegrity** (OCI), **StatefulUpload** (OCI blob upload, Git LFS).

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
