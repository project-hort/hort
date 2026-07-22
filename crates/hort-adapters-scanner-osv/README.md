# hort-adapters-scanner-osv — OSV-Scanner SBOM Adapter

## Layer

Outbound adapter — no `hort-app` dependency (leaf adapter over
`hort-domain`). Requires >= 85% coverage.

## Responsibility

SBOM-mode vulnerability scanner: serializes the artifact's `Sbom` to
CycloneDX 1.5 JSON, shells out to `osv-scanner scan source --format json
--sbom <path>`, and parses the JSON output into `Vec<Finding>`. Does not
touch the artifact's content bytes — SBOM-only.

## Ports

- **Implements:** `ScannerPort` (`OsvScannerAdapter`).
- **Consumes:** none — leaf adapter; I/O is subprocess + tempfile, not
  network or database.

## Key types

- `OsvScannerAdapter`.
- `OsvScannerConfig`.
- `parse_findings_from_json`.

## Rules

- The optional `osv-scanner-cli` Cargo feature gates integration tests
  against a real `osv-scanner` binary and is off by default, so CI without
  the binary installed stays green.
