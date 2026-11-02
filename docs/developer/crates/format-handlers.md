# Extend a registry format

hort supports multiple artifact protocols through **compiled-in** format logic and per-format HTTP handlers. This guide is for contributors adding or changing a format; it is **not** a runtime plugin installation guide.

## Choose the right extension boundary

- **Coordinate parsing and normalization:** `crates/hort-formats/`, implementing the domain `FormatHandler` contract.
- **HTTP protocol behavior:** `crates/hort-http-{format}/`, using application use cases for repository and artifact access.
- **Shared HTTP facilities:** `crates/hort-http-core/`.
- **Composition and route mounting:** `crates/hort-server/`.

A format may need several endpoints and metadata representations. Do not assume that a generic HTTP route is sufficient to implement an ecosystem's publish and download contracts.

## Trace a working format before extending one

Start with Cargo, whose format implementation lives under `crates/hort-formats/src/cargo.rs` and whose HTTP adapter is `crates/hort-http-cargo/`. Review the existing protocol tests before changing parsing rules. For formats with multiple related files per coordinate, compare the Maven implementation under `crates/hort-formats/src/maven/` and `crates/hort-http-maven/`.

## Implementation workflow

1. Read the official package protocol specification and define the required operations.
2. Implement and test format-specific coordinate parsing and normalization in `hort-formats`.
3. Add the inbound HTTP handler crate. Keep it independent of PostgreSQL and storage adapter crates.
4. Call application use cases rather than reading database or artifact ports directly from request handlers; authorization and visibility belong in those use cases.
5. Register the crate in the workspace and wire its routes in `hort-server`.
6. Add unit, protocol and client-level tests for publish, download, malformed input and authorization boundaries.
7. Update operator documentation only for behavior that users can actually configure and operate.

## API stability

`FormatHandler` is a Rust trait used by hort's codebase, **not** a promise of a stable external plugin ABI. There is no documented mechanism for installing a new format handler into a running server without compiling it into hort.

For comprehensive technical detail, consult the [format-handler implementation source](https://github.com/project-hort/hort/blob/main/docs/architecture/how-to/add-a-format-handler.md) and [format-handler explanation](https://github.com/project-hort/hort/blob/main/docs/architecture/explanation/format-handlers.md). Those source documents can contain historical or future design context; verify current code before implementing a change.
