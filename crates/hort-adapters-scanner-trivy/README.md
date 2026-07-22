# hort-adapters-scanner-trivy — Trivy Filesystem Scanner Adapter

## Layer

Outbound adapter — no `hort-app` dependency (leaf adapter over
`hort-domain`, plus the `StoragePort` trait object it's handed to read
artifact bytes). Requires >= 85% coverage.

## Responsibility

Filesystem-mode scanner: pulls artifact bytes via `StoragePort::get`,
writes them to a `tempfile::TempDir`, runs `trivy fs --format json --quiet
<dir>`, and parses the output into `Vec<Finding>`. Owns its
workspace/tempdir lifecycle including panic/error cleanup.

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
