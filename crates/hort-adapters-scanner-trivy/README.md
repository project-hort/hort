# hort-adapters-scanner-trivy — Trivy CLI Scanner Adapter

## Layer

Outbound adapter — no `hort-app` dependency (leaf adapter over
`hort-domain`, plus the `StoragePort` trait object it's handed to read
artifact bytes). Requires >= 85% coverage.

## Responsibility

CLI-backed scanner: pulls artifact bytes via `StoragePort::get`,
materialises them into a `tempfile::TempDir` in the shape the analyzers
expect for that `ArtifactKind`, runs `trivy <fs|rootfs> --format json
--quiet <dir>`, and parses the output into `Vec<Finding>`. Owns its
workspace/tempdir lifecycle including panic/error cleanup.

The layout **and** the subcommand come from the kind: Trivy's coverage
matrix runs post-build analyzers (Java archives, wheels/eggs, a
`package.json` under `node_modules`) only under the Image and Rootfs
targets, and pre-build ones (`pom.xml`, lockfiles) only under Filesystem
and Repository. `src/workspace.rs` holds the table; a mismatch there is
silent — the analyzer simply never runs.

## Ports

- **Implements:** `ScannerPort` (`TrivyAdapter`).
- **Consumes:** `StoragePort` as an injected collaborator (to read the
  bytes it scans) — not implemented by this crate, just depended on.

## Key types

- `TrivyAdapter`.
- `TrivyConfig`.
- `parse_findings_from_json`.

## Rules

- Mirrors the OSV adapter's pattern: the optional `trivy-cli` Cargo feature
  gates integration tests against a real `trivy` binary and is off by
  default for CI environments lacking it.
