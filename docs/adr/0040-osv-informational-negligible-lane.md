# 0040 — OSV informational advisories ride the negligible lane, operator-steered

- **Status:** Accepted
- **Enforced by:** the osv scanner + advisory adapters map a finding whose OSV `database_specific.informational` class is recognised (`unmaintained` / `unsound` / `notice`) onto `Finding.informational_class` and skip the Critical fail-closed fallback; `Finding::is_informational()` + `hort_domain::types::is_informational_class` (the single recogniser) route such findings to the `SeveritySummary.negligible` tier, which `policy::threshold` / `policy::cve` never enforce. `ScanPolicy.negligible_action` (`Ignore` default / `Warn` / `Block`) gates them in `evaluate_scan_result`; the gitops apply-linter validates the enum. A finding with no CVSS **and** no recognised informational class still falls through to `Critical` (ADR 0007 preserved). Covered by the adapters' fixture/parse tests, `policy::scan` negligible_action tests, and the `scan_findings` round-trip.
- **Supersedes:** —

## Context

The osv adapters lowered any unscored finding to `Critical` (the "SUP-4" fail-closed fallback) and never read the OSV `database_specific.informational` field. A RustSec *informational* advisory — `unmaintained` / `unsound` / `notice`, which by design carry no CVSS — was therefore rejected as if Critical. The canonical case: `proc-macro-error2` / `RUSTSEC-2026-0173` ("unmaintained") quarantined-then-rejected on a pull-through registry. The project's own `cargo-audit` / `cargo-deny` gate, by contrast, risk-accepts that same advisory as a notice ("unmaintained != vulnerable") — the registry was stricter on its consumers than hort is on itself. The non-enforcing `negligible` tier already existed end-to-end (`SeveritySummary.negligible`, the threshold/cve walks that skip it) but had no way to produce a finding on it.

## Decision

1. **Informational advisories are non-vulnerabilities, handled on the negligible lane.** A recognised OSV `informational` class routes to the negligible tier instead of the Critical fallback. `SeverityThreshold` stays a four-variant enum (no `Negligible`): "informational" is a property of the *finding* and a *policy* knob, not a settable block threshold.
2. **Operator-steered per policy** via `ScanPolicy.negligible_action`: `Ignore` (default — never block; matches the dogfood gate), `Warn` (record a `PolicyEvaluated` observation, non-blocking), `Block` (reject — refuse unmaintained/unsound dependencies). Enforced in the evaluator, validated at gitops apply.
3. **Persist the fact, derive the interpretation.** `Finding` carries the raw OSV class string (`informational_class: Option<String>`), persisted through the `scan_findings` projection. `is_informational()` and the negligible routing are derived at decision time, so a re-evaluation — and any future per-class policy — re-derives under the *current* config rather than a frozen boolean. `negligible_action = Block` therefore survives an exclusion-triggered re-evaluation instead of silently releasing.
4. **Fail-closed is preserved for genuinely-unscored vulnerabilities.** No CVSS **and** no recognised informational class → `Critical` (ADR 0007). The carve-out fires only on the trusted advisory-DB classification, never on artifact-supplied data — so it is not a Gate-2-style untrusted-input relaxation.

## Consequences

- Informational advisories no longer block by default; the registry's posture matches the project's own supply-chain gate.
- Operators who want to refuse unmaintained/unsound dependencies set `negligibleAction: block`.
- A new OSV informational class is persisted verbatim (the fact); teaching `is_informational_class` to recognise it later is a code change that re-derives correctly on the next evaluation — no data migration.
- The `scan_findings.informational_class` column lives in the `009_scan_jobs_and_findings.sql` baseline (folded into the `CREATE TABLE scan_findings` per ADR 0022's pre-1.0 baseline-reset amendment).

## Alternatives considered

- **Per-advisory exclusions instead of a type knob.** Rejected as the general mechanism: exclusions are per-CVE-ID risk acceptances; the over-block is a *type* (informational) issue that one knob handles for the whole class. Exclusions remain available for specific findings.
- **Persist the derived boolean.** Rejected — it freezes the interpretation and defeats config-respect (per-class policy, re-evaluation). Persist the class; derive the rest.
- **Add `SeverityThreshold::Negligible`.** Rejected — `threshold.rs` deliberately has no such variant ("negligible never blocks"); a settable "block-negligible" threshold is nonsensical. The knob is `negligible_action`.

## References

- `crates/hort-adapters-scanner-osv/`, `crates/hort-adapters-advisory-osv/` — adapters reading `database_specific.informational`.
- `crates/hort-domain/src/types/finding.rs` — `informational_class`, `is_informational`, `is_informational_class`.
- `crates/hort-domain/src/policy/{scan,threshold,cve}.rs` — `negligible_action` enforcement + the negligible-skipping threshold walk.
- `migrations/009_scan_jobs_and_findings.sql` — `scan_findings.informational_class`.
- [0007](0007-fail-closed-quarantine-release-predicate.md) (fail-closed release — preserved), [0022](0022-pre-1.0-edit-existing-migrations.md) (append-only migrations from 0.9.5).
- `docs/architecture/how-to/curator-workflow.md` — `negligibleAction` operator reference.
