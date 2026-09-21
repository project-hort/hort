# 214 — Scanner capability map consumers: apply-time linter row, orchestrator consult, coverage table

**Issue:** #259 (item 2 of 2) · **Branch:** `agent/259-scan-capability-map` (continues item 213)
**Governing decisions:** ADR 0015 (apply-time rejection of an accepted-but-inert field — this row is that decision applied to `scan_backends`), ADR 0007 (fail-closed hold for an unassessed surface). No new ADR.

## What to build

### 1. Apply-time linter — new row in `StaticConfigValidator`

`crates/hort-app/src/lint/static_validate.rs`. Add a `LinterRule` variant (reject + metric, the row-6b/row-7 shape) and a row **"7c — scan-backend capability"**, evaluated inside the existing `for env in &desired.scan_policies` pass next to row 7 (`repo_format_by_name` is already built there). The record it reads is `hort_app::scanning::scan_backend_applies_to` / `any_scan_backend_applies_to` (item 213) — a compiled-in fact, read directly like `KNOWN_SCAN_BACKENDS` is; **no** injected set, so the offline `validate-config` CLI, `gitops_boot` and the harness cannot drift (the row always runs).

**Unit of evaluation — the effective pairing per repository, not the declared scope.** Runtime resolution is repo-scoped policy wins over global (`policy_resolution.rs`); a global policy therefore never reaches a repository that has its own scoped policy. Lint what the runtime will do: for each declared repository, resolve its effective `ScanPolicy` (scoped if one exists, else the global one, else none) and check each of its `scan_backends` against the repository's format. This is the one deliberate difference from row 7 (which lints the declared scope) — state it in the row's doc comment with the reason. An unresolved scope repository name is left to the scope-existence validator (row 7 precedent).

Two rejection shapes, both hard errors (`report.errors`), one finding per (policy, repository, backend), deterministic order:

- **backend does not analyse the format** (`!scan_backend_applies_to(b, f) && any_scan_backend_applies_to(f)`): `ScanPolicy \`{name}\`: scanBackends entry \`{b}\` cannot analyse repository \`{repo}\` (format \`{f}\`) — static scanner capability map; \`{b}\` produces no verdict for any {f} artifact, so this pairing would accept at apply and analyse nothing at runtime. Use a backend that covers {f} ({list of applicable backends}), remove \`{b}\` from this policy, or scope a separate policy to this repository. Coverage per format: docs/architecture/explanation/scanning-pipeline.md.`
- **no scanner covers the format** (`!any_scan_backend_applies_to(f)`): `ScanPolicy \`{name}\`: repository \`{repo}\` (format \`{f}\`) has no compiled-in scanner coverage — every {f} artifact would record a not-applicable assessment, never a scan. Waive scanning explicitly for it (\`scanBackends: []\` in a policy scoped to \`{repo}\`) or exclude it from this policy's scope.`

An empty `scan_backends` list (the explicit waiver) never triggers the row. Format string comparison: canonicalise the repository's declared `format:` the same way the composition root maps a `RepositoryFormat` onto its handler key (find the existing alias→handler mapping the server uses; do not add a second one). Tests: both shapes on scoped and global policies; global policy + overridden repository passes; `[]` passes; every existing staging/dogfood pairing passes (`ttrekkbar-maven`×trivy, `hort-crates`×osv, `npm-scan`×osv+trivy, `docker-io`×trivy, `maven-proxy`×osv). The offline CLI (`crates/hort-server/src/cli/validate_config.rs`) gets one test showing the row fires there too.

### 2. In-repo gitops trees — sweep with the new row

Run the offline validator (`hort validate-config`, or the `alpha_fixtures` guard test + a scratch test per tree) over **every** in-repo tree: `scripts/alpha-fixtures/gitops-config/`, `deploy/compose/example-config/`, `deploy/compose/s3/config/`, `deploy/ansible/files/gitops/`, and the host-test scripts that apply policies inline (`scripts/host-tests/test-scan-informational-multibackend.sh` applies `[trivy, osv]` on a cargo proxy — it stays valid only if item 213 kept `trivy × cargo` "yes"; otherwise re-point it at a format both backends cover, e.g. npm or pypi, keeping its purpose (both backends, informational)).

Known hit: `scripts/alpha-fixtures/gitops-config/base/policies/20-default-scan-policy.yaml` is **global `[trivy, osv]`** over npm/pypi/cargo/oci repositories → rejected on `osv × oci`. Fix it the way the map says: global `[trivy]`, plus scoped policies adding `osv` where it applies (npm, pypi, cargo — same threshold/duration/approval/provenance settings; keep the runbook's `event-stream@3.3.6` expectation, which needs `osv` on the npm repos). Keep every fixture's modelled intent; list each change in the report with the row's message that drove it.

### 3. Orchestrator — consult the map before invoking

`crates/hort-app/src/use_cases/scan_orchestration.rs`, in the per-backend loop (`run_scan`, after the `self.scanners.get(backend)` lookup at :450): if `!scanner.applies_to(&job.format)`, **do not invoke** the backend. Record an abstention instead, choosing the arm by the same two-flavour rule as the linter:
- another known backend covers the format ⇒ `NotAnalysable::NoAnalyzerMatched` (a pairing mismatch — gates, per the enum's own doc) + `warn!` naming `scanner`, `format`, `kind`, and "capability map: this backend does not analyse this format; the policy (or the built-in default `[trivy]`) is inert for this repository — configure a covering backend or waive scanning explicitly" + `emit_scan_failure(ScanFailureResult::InertPairing, backend)` (new variant, label `result="inert_pairing"`, on the existing `hort_scan_record_outcome_failures_total` family — no new metric);
- no known backend covers the format ⇒ `NotAnalysable::NotApplicable` at `debug!` (today's outcome for a kind-`Other` artifact, reached without spawning a scanner).

This covers the spec's "default without policy warns" (`default_scan_backends`, the worker's healthy-backend list) and any stale pre-linter policy still in the DB, through one code path. Tests in `scan_orchestration_tests.rs`: default `[trivy]` on an SBOM-only format that Trivy does not cover (use a mock whose `applies_to` says no) ⇒ hold, warn, metric label; `[trivy, osv]` on OCI where the mock `osv` does not apply and `trivy` analyses ⇒ Trivy's verdict, osv never invoked; format nobody covers ⇒ `not_applicable` assessment. 100 % coverage on `hort-app` stands.

### 4. Docs

- `docs/architecture/explanation/scanning-pipeline.md`: replace **"Honest per-format coverage"** with **"The scanner capability map"** — the backend × format table with, per "yes" cell, *what is covered* (own identity / declared dependencies / which kinds; e.g. Trivy×npm: the package's own `name@version` only; Trivy×cargo: binary crates with `Cargo.lock` only, library crates hold; Trivy×maven: JAR coordinates via `trivy-java-db`, POM declared dependencies with literal versions; Trivy×pypi: `dist-info` own identity; Trivy×oci: OS package databases and shipped lockfiles; osv×{npm,cargo,pypi,maven}: the payload SBOM, ADR 0056) **and the evidence** (test name; E2E scenario; staging observation where one exists). The npm row currently says "**no**" — that predates the `node_modules/<name>/` relocation and is wrong; fix it. Add a short paragraph: rule for a "yes" cell; apply-time rejection of a "no" cell (row 7c) and the explicit waiver; runtime consult for the default path. Link from the "Nothing analysable" section.
- `docs/architecture/reference/` — if the apply-time linter rows are catalogued there (grep "Row 7b"), add row 7c with both messages.
- `CHANGELOG.md` `[Unreleased]`: `### Added` — scanner capability map + apply-time rejection of inert `scanBackends` pairings (name the two shapes, and the alpha-fixture consequence for operators with a global `[trivy, osv]` policy over OCI repositories: split it); `### Fixed` — `osv` no longer returns a clean verdict without an SBOM (`not_applicable` instead).

### Not in this item

No new policy option. No change to which formats have SBOMs (a Maven/OCI SBOM source is other work). No warning tier for partially-covered cells (docs carry that).

## Acceptance

- A policy pairing a backend with a format it does not analyse is rejected at apply (both shapes), with the pairing, the reason and the alternatives in the message; the scoped-override case passes; `[]` passes; every current staging/dogfood pairing passes.
- Every in-repo gitops tree validates under the new row; each fixture change is listed with its driving message.
- The orchestrator never invokes a backend on a format it does not apply to; an inert pairing holds with `warn!` + `result="inert_pairing"`; an uncovered format records `not_applicable` without spawning a scanner.
- Docs table complete with evidence per cell; CHANGELOG entries present.
- Gate green (fmt, clippy `-D warnings`, `cargo test --workspace`, `cargo-audit audit --deny warnings`, `cargo deny check`); `hort-app` at 100 %; no issue numbers in code comments.
