# 135 — Thread the stored payload into scan-time SBOM extraction

Issue: #191, spec §2 D1+D3. Depends on item 134.
**Read first:** `crates/hort-app/src/use_cases/scan_orchestration.rs`
(`try_extract_sbom`, `coords_for_artifact`),
`crates/hort-domain/src/ports/format_handler.rs` (`extract_sbom`,
`PayloadAccess`), `crates/hort-adapters-scanner-trivy/src/lib.rs` (the
payload-at-scan precedent), `crates/hort-formats/src/cargo.rs`.

1. Scan orchestration streams the artifact's stored bytes from `StoragePort`
   (it holds `sha256_checksum`) into `extract_sbom`'s `PayloadAccess` slot
   for formats that consume payload — cargo first. Keep the empty-payload
   call for formats that do not (no behaviour change elsewhere).
2. Cargo `extract_sbom` three-way branch:
   - payload yields a lockfile closure → subject + resolved components at
     exact versions (item 134's walk);
   - no lockfile in payload → **subject-only** (never the declared-deps
     branch: range-floor components are the proven false-positive machine —
     production evidence on #187);
   - the declared-deps branch remains for the metadata shapes where versions
     are real (proxy/index paths).
3. One metric distinguishing the three outcomes per scan.
4. ADR 0026 discipline: the payload flows as a stream end to end; no
   buffered body. The `streaming_metadata_port` guard stays green.

**Acceptance:** handler/orchestration tests for all three branches (mock
storage feeding a fixture `.crate`); a rescan of a pre-existing artifact
(no stored resolved data) produces a resolved-component SBOM — the
retroactivity property; `hort-app` coverage 100 % on touched code.
