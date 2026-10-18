# 260 — Reject the three operator fields that are accepted and never enforced

**Issue:** #334 · **Branch:** `agent/334-struktur-332`
**Governing decisions:** ADR 0015 — a policy field accepted at apply and
inert at runtime is a hard block; the structural close is an apply-time
linter rejection pointing the operator at the missing enforcement, and
`max_age_days` (`LinterRule::PrefetchMaxAgeDaysNotImplemented`) is the
canonical exemplar. The alternative model — removing the surface — is not
chosen here.

## Why

The apply-time linter is one of four enforcement mechanisms the audit found
correct where it runs and never carried to new surface. It has a rule for
`max_age_days` and for `UnusedFor`; three further fields of exactly the same
shape have none. Each is accepted, stored, visible to an auditor, and
without effect:

| Field | Where it dies |
|---|---|
| `ScanPolicy.licensePolicy` | `hort-domain/src/policy/scan.rs:290-299` always calls `evaluate_license_policy(&[], …)`. The evaluator only compares supplied license strings (`policy/license.rs:91-163`), so a well-formed `{"denied_licenses":["GPL-3.0"],"action":"Block"}` sees zero licenses, produces zero violations, and the scan stays clean whatever the artifact's licence is. Apply stores it (`apply_config_use_case.rs:1660,1714`); the how-to tells operators it decides which findings are enforcement-worthy (`docs/architecture/how-to/declare-gitops-config.md:655-656`). |
| `Exclusion` scope | `hort-domain/src/policy/exclusion.rs:79-95` filters on `is_active`, `cve_matches` and `matches_coords` and never reads `ex.scope` — it could not, because `ArtifactCoords` carries no repository id. Everything in front works: the HTTP layer accepts `ScopeDto::Repository`, the event records it, the projection stores it. So a CVE exclusion scoped to R1 on a **global** policy also clears that CVE in R2. |
| `ArtifactRepository.virtualMembers[].format` | Cross-spec validation requires each member to exist and not be virtual but never compares its format with the virtual's (`crates/hort-config/src/desired.rs:363-418`); the virtual-shape validator only checks the virtual's own format (`crates/hort-config/src/repository.rs:611-663`); runtime `resolve_members` rechecks Read and type, not format (`virtual_resolution.rs:89-128`). A lower-trust PyPI hosted member can then own a name inside an npm virtual. |

These are S9b-3, S4-1 and F14-3. Severity is not what puts them together —
the shape is. An operator sets a risk-significant value and makes a
threat-model decision on the assumption that the field is load-bearing.

## What to do

One `LinterRule` per field, following `PrefetchMaxAgeDaysNotImplemented`
exactly: reject any value that is not the inert default, with a message
that says the control is not implemented and that the configuration must
not rely on it. Read `crates/hort-app/src/lint/static_validate.rs` first —
the rule enum documents the row order, the metric split and why row 9 is
appended last; a new row has to respect all three.

**Correction, 2026-10-03 (after the first implementation).** The first
pass refused a repository-scoped exclusion on **removal** as well as on
creation, which left a stored row that could not be retired through the
API while it went on clearing its CVE globally. That is backwards:
removing such a row is the *tightening* direction — it stops suppressing a
finding — and there is no safety argument for blocking a tightening
action. The use case was already deliberately permissive so the gitops
applier could drain the same row, so the refusal protected nothing and
only cost the operator without gitops access a database touch.

**The rule is: refuse the write, allow the removal, and inform about the
real reach.** Corrected on this branch.

**The exclusion scope is the one that needs care, and it is not only a
GitOps field.** Exclusions also enter through `PolicyUseCase` directly from
the HTTP writer, outside the desired-tree lint. A linter row alone would
close the declared path and leave the API path open — which is the same
mistake one layer down. Both writers must refuse a non-global scope.

**This item also carries an obligation inherited from unit 263.**
`ExclusionsApplier::resolve_scope`
(`crates/hort-app/src/gitops/event_sourced.rs:455`) panics on a repository
name it cannot resolve, exactly as the ScanPolicy resolver did before 263
fixed it — a Stage-3 abort, not a rejection, so `is_park_eligible` never
sees it and the pod crashloops with Stages 1 and 2 written. 263
deliberately did **not** add a reference rule for it, because rejecting
every non-global exclusion scope here is strictly stronger and would make
such a rule dead on arrival.

So: **whatever this item does, that panic must end up unreachable**, and
a test must say so. If the disposition ever changes from "reject the
scope" to "implement the scope", the reference rule 263 did not write
becomes required — it is the sibling of
`push_scan_policy_scope_reference_errors` and takes about ten lines.
Until this item lands, the panic is live on a one-character operator typo.

**One existing test asserts the defect as correct**
(`quarantine_use_case.rs:3759-3812` pins a Block policy with no licence
input to a clean `ScanCompleted`). It is not evidence; change it.

## Explicitly out of scope

- **Making any of the three fields work.** No SBOM or licence extraction, no
  repository id threaded into `ArtifactCoords`, no format compatibility
  model for virtual members. This item removes a false assurance; it does
  not deliver the capability.
- No change to the inert default's behaviour — a bundle that does not set
  the field must apply exactly as before.
- No new metric beyond the per-rule counter the exemplar already emits.
- No migration, and no rewriting of stored exclusions that already carry a
  repository scope. They stop being accepted on the next apply or API call;
  what to do with existing rows is a question for #334, not a silent
  rewrite here.

## Acceptance

- For each of the three fields: an apply with the field set fails, an apply
  with it absent or at its inert default succeeds, each proven by a test.
- A `POST` creating a repository-scoped exclusion through the HTTP writer is
  refused with the same wording as the apply path. **`DELETE` is not** —
  see the correction below.
- The licence test that pinned the inert result now asserts the rejection.
- The three rejection messages name the field and say what is missing, so
  an operator reading one does not retry with a different value.
- The step-15 linter coverage matrix is carried forward in
  `docs/architecture/` with the three new rows, so the next surface does not
  pass the same spot unseen.
- No doc page still describes any of the three as effective; the how-to
  line on `licensePolicy` is corrected.
- Gate green: `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace`, `cargo-audit audit
  -D warnings`, `cargo-deny check`.
