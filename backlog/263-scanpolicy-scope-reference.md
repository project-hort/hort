# 263 — A ScanPolicy scoped to an undeclared repository must be rejected, not panic

**Issue:** #334 · **Branch:** `agent/334-struktur-332`
**Governing decisions:** the third structural result of the audit — the
apply pipeline validates in stages and writes between them, so every
reachable refusal belongs before the first write (see
`backlog/259-preflight-rejection-completeness.md`).

## Why

A `ScanPolicy` whose `scope` names a repository no envelope declares passes
the whole pre-write validation and then **panics** in Stage 2. Measured:

```
scan policy scope: {Repository: {repository: "not-declared"}},
no ArtifactRepository envelope of that name

preflight_validate → Ok(())
apply              → panic at apply_config_use_case.rs:1838
  "INVARIANT: ScanPolicy references repository name 'not-declared' that is
   not in repo_id_by_name — pipeline must populate the map from
   DesiredState before dispatching scan-policy applies"
```

`resolve_scope` (`crates/hort-app/src/use_cases/apply_config_use_case.rs:1834-1845`)
reads `repo_id_by_name`, which `collect_repo_id_by_name` builds from the
**declared** repositories only, and panics on a miss — on the stated
assumption that the cross-spec validator rejected it first. **It does
not.** `crates/hort-config/src/desired.rs` carries `DanglingReference`
rules for RetentionPolicy scope, UpstreamMapping → repository, Exclusion →
ScanPolicy and PermissionGrant → repository / ServiceAccount, and none for
a ScanPolicy's own `scope: Repository(name)`.

This is the audit's **F15-2**, which was derived rather than demonstrated
("no separate crash reproduction was run"). The reproduction changes how it
should be read: it is not a late *rejection* but a late *abort*. A panic is
not a `GitopsBootError`, so `is_park_eligible` never sees it — the pod
crashloops, and it does so **after Stage 1 has written**. The trigger is a
typo in a scope name.

## What to do

Add the missing sibling rule. `push_retention_policy_scope_reference_errors`
(`desired.rs:1280`) is the exact model, and it is registered at `:425`,
directly beside `push_scan_policy_scope_duplicates` at `:424` — so
`ScanPolicy` already has a scope rule there; it is a *reference* rule that
is missing, not a place to put one.

Follow that model including its details: one `DanglingReference` per
offending value naming it, and skip a scope that does not deserialize
because the per-spec validator already reported that envelope.

Then correct `resolve_scope`'s comment. It asserts a guarantee that did not
exist; once the rule is in place the assertion becomes true, and the
comment should name the rule that makes it true rather than "the
cross-spec validator" in the abstract.

**Leave the panic in place.** With the rule present it becomes what its
text claims to be — an invariant assertion on a state the admission
boundary has already excluded. Converting it to an error would add an
unreachable branch to a crate held to 100% coverage.

## Explicitly out of scope

- The two sibling gaps found in the same inventory —
  `subject.userId` that is not a UUID (named inside F15-1) and an
  `upstreamUrl` that passes the prefix check but has no host — are
  recorded on #332 and are not fixed here.
- No change to what a valid scope resolves to, and no change to
  `collect_repo_id_by_name`.
- No new linter row and no metric: this is a row-0 cross-spec reference
  rule, the same class as the four that already exist.

## Acceptance

- A bundle whose `ScanPolicy.scope.repository` names an undeclared
  repository is rejected by `validate` with a `DanglingReference` naming
  the policy, the field and the missing repository — and the same bundle
  is rejected identically by the boot preflight and by
  `hort-server validate-config`.
- Applying that bundle writes **nothing**: proven with the positive-control
  shape unit 259 established, so "nothing written" cannot pass vacuously.
- A bundle that declares the repository still applies unchanged.
- `resolve_scope`'s comment names the rule that makes its assertion true.
- The per-stage agreement test from unit 259
  (`every_rejecting_apply_stage_is_rejected_pre_write`) still passes, and
  this stage is represented in its corpus.
- Gate green: `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace`, `cargo-audit
  audit -D warnings`, `cargo-deny check`.
