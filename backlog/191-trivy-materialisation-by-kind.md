# 191 — Trivy adapter: materialise the artifact the way Trivy's analyzers expect; "no analyzer matched" is not "clean"

**Issue:** #264, item 2 of 2 · **Branch:** `agent/264-trivy-materialisation` · design-heavy.

## Governing decisions

ADR 0007 (fail-closed: a scan that produced no verdict must not release), ADR 0056/0034
(scan verdict at the gate, record vs reject), CLAUDE.md anti-pattern "accepted at apply,
inert at runtime". `QuarantineStatus::ScanIndeterminate` already exists as the fail-closed
"no verdict" state — reuse it, do not invent a new one.

## The defect

`prepare_workspace_with_cap` writes the CAS bytes to `"{content_hash}.bin"` and
`scan_argv` runs `trivy fs <dir>`. Trivy selects analyzers by file name/extension and does
not open archives in `fs` mode; a `.bin` file matches nothing, the report has no
`Results`, and the empty finding list is booked as a clean scan for every format.

## Change

1. **Format-aware scan target (domain port).** `ScannerPort::scan` takes a `ScanTarget`
   instead of a bare hash:
   ```rust
   pub struct ScanTarget<'a> {
       pub content_hash: &'a ContentHash,
       pub format: &'a str,               // handler key: oci|npm|cargo|pypi|maven
       pub coords: &'a ArtifactCoords,    // name/version(/classifier) for a natural file name
       pub kind: ArtifactKind,            // what the bytes are: MavenJar|MavenPom|NpmTarball|CargoCrate|PyWheel|PySdist|OciLayer|OciConfig|OciManifest|Other
   }
   ```
   The orchestrator already holds artifact, format key and coords (`scan_orchestration.rs`
   ~400 and ~732); `kind` comes from a new `FormatHandler::scan_kind(&Artifact) ->
   ArtifactKind` (default `Other`), implemented per handler from what it already knows
   (Maven path extension, OCI media type, npm/cargo/pypi payload type). OSV ignores the new
   fields (it scans the SBOM).
2. **Materialisation per kind (Trivy adapter, `workspace.rs`).**
   - `MavenJar` (`.jar/.war/.ear/.par`): write as `<artifactId>-<version>.<ext>` — Trivy's
     JAR analyzer keys on the extension.
   - `MavenPom`: write as `pom.xml` (Trivy's pom analyzer).
   - `PyWheel` (zip) / `PySdist` (tar.gz): extract into the workspace (`.dist-info/METADATA`,
     `PKG-INFO`).
   - `NpmTarball` (tar.gz) / `CargoCrate` (tar.gz): extract; Trivy will find `package.json`
     / `Cargo.toml` only (licenses, no vulnerability detection without a lockfile) — this
     is the honest result and feeds #259's map as "no".
   - `OciLayer` (tar / tar+gzip / zstd per media type): extract as a rootfs into the
     workspace and scan with `trivy rootfs <dir>` (OS packages + language files);
     `OciConfig` / `OciManifest`: not scannable content → outcome `NotApplicable`
     (below), never a Trivy invocation.
   - `Other`: as today (`.bin`) but with outcome `NotApplicable`.
   - **Extraction bounds, fail-closed:** existing size cap on input; additionally a cap on
     extracted bytes, on entry count, a decompression-ratio cap, path-traversal rejection
     (no `..`, no absolute paths, no symlink/hardlink targets outside the workspace —
     reject the archive, do not skip the entry), permissions stripped. A bound hit ⇒
     `UnusableArchive` ⇒ `ScanIndeterminate`.
3. **"No analyzer matched" is a distinct outcome.** Extend the scanner result so the
   orchestrator can tell "Trivy analysed the target and found nothing" (`Results` present,
   possibly empty vulnerabilities) from "Trivy had nothing to analyse" (no `Results` /
   `NotApplicable` / `UnusableArchive`). The latter maps to
   `QuarantineStatus::ScanIndeterminate` with a `warn!` naming format×backend — the same
   fail-closed hold the scan axis already uses for an absent verdict. **Human decision
   to confirm before dispatch:** this makes a Trivy-only policy on an npm/cargo
   repository hold every artifact indeterminate (they never had a real scan) — which is
   exactly what #259's apply-linter will reject up front; until #259 lands, the hold is
   the fail-closed posture ADR 0007 prescribes, and the alternative (keep booking it as
   clean) is the defect itself.
4. **Evidence tests, one per "yes" cell** (adapter crate, `#[ignore]`-free but gated on
   a `TRIVY_BIN` env like the existing timeout test, plus fixture archives under
   `tests/fixtures/`): JAR with `log4j-core 2.14.1` ⇒ CVE-2021-44228; wheel with a known
   advisory (e.g. `urllib3 1.26.4` ⇒ CVE-2021-33503); a minimal OCI layer tar containing
   `/var/lib/dpkg/status` with a known-vulnerable package version; npm tarball and cargo
   crate ⇒ `Results` present, zero vulnerabilities (documents the "no" cells). Unit
   tests for every extraction bound (traversal, ratio, entry count, symlink).
5. **Docs:** `docs/architecture/explanation/scanning-pipeline.md` — materialisation
   table per kind, the `NotApplicable ⇒ ScanIndeterminate` rule, the honest per-format
   coverage; `docs/metrics-catalog.md` if a new outcome label is added.
6. **CHANGELOG** `### Fixed`: Trivy scans now analyse the artifact's actual content
   (JARs, wheels, OCI layers); a scan with nothing analysable no longer counts as clean.

## Must not change

- OSV adapter behaviour; SBOM extraction; the record/reject gate semantics; policy schema.
- No new operator knob.

## Acceptance

- Item 190's scenario green; the per-kind evidence tests green with a real `trivy`.
- `hort-domain`/`hort-app` 100 % on touched branches; adapter ≥ 85 %.
- A `.bin`-style target can no longer produce a "clean" verdict (unit test on the outcome
  mapping).
- Worker image unchanged (Trivy binary already present); `trivy rootfs` needs no DB beyond
  what `fs` uses.
