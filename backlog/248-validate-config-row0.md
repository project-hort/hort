# 248 — `validate-config` runs no row-0 rule, and says the opposite

**Issue:** #304 · **Branch:** `agent/304-validate-config-row0`
**Governing decisions:** ADR 0015 (apply-time rejection; the offline gate is
its early warning) · #299 (the find and the probe).

## Why

`hort-server validate-config` is the offline gate — where an operator learns
about a bad envelope **before** it reaches a cluster. It runs **no** row-0 rule.

`validate_tree` (`crates/hort-server/src/cli/validate_config.rs`) calls
`DesiredState::parse_files`, which is parse-only, then
`StaticConfigValidator::validate`. **`DesiredState::validate()` is never
called** — and outside `validate_against` it is called nowhere in the binary at
all. `validate_against` needs a `CurrentSnapshot` the offline CLI cannot build.

So offline runs neither the per-spec rules (`validate_repository`,
`validate_permission_grant`, `validate_scan_policy`,
`validate_retention_policy`, `validate_exclusion`, …) nor the cross-doc rules
(`push_duplicates` per kind, `push_init14_reference_errors`,
`push_retention_policy_scope_reference_errors`, `push_upstream_mapping_*`, …).

Validating clean today, failing at apply: a blank `metadata.name`; a
`PermissionGrant` whose `repository` names nothing declared; two envelopes with
the same `(kind, name)`; a `RetentionPolicy` scope naming an undeclared
repository; a structurally invalid `spec.predicate` such as `{AgeExceeds: 0}`.

**Demonstrated, not inferred.** A probe during #299 drove `validate_tree` over
a tree holding two envelopes only that layer rejects and got
`config validation OK`, exit 0.

## The damage is the claim, not the gap

Three places say the opposite, so a reader concludes the coverage exists:

1. the step-3 comment in `validate_tree` — *"parse + per-envelope domain
   validate + cross-validate (row 0)"*; `parse_files` does none of that;
2. the failure branch prints *"parse / cross-validate error(s)"*;
3. the CLI's honesty footer names only rows 1 and 4 as missing.

A gate that checks less than it documents is worse than one that openly checks
less: the operator relies on it, and the first sign of the mistake is a pod
parked not-ready at boot instead of a red pipeline.

## Two facts that make this smaller than it looks

Both established rather than assumed:

- **`DesiredState::validate()` is snapshot-free.** `validate_against` starts
  with `let mut errors = match self.validate() { … }` and only its *additional*
  rules need the snapshot. So the CLI can call it directly.
- **Every tree this repository ships is already validated against it** — by
  three guard tests that do exactly what the CLI does not:
  `crates/hort-config/tests/alpha_fixtures.rs:53`,
  `…/public_deploy_gitops_tree.rs:83`, `…/compose_example_config_tree.rs:73`,
  each calling `state.validate()` after `parse_files`. So this change cannot
  turn an in-repo tree red, and the pattern to copy already exists in-tree.

The transition risk is therefore confined to operator-authored trees outside
this repository — which fail at apply today anyway.

## To decide

- **The message.** A tree that was green yesterday goes red. It deserves to,
  but the error has to make clear that the gate got stricter rather than that
  the tree broke. That wording is the decision, not the call site.
- **The footer.** The three false claims go in the same change. If a gap stays
  open deliberately, the footer names it — completely, not partially, which is
  how this one hid.

## Acceptance

- Each of the five trees above is rejected with exit code 1, one test each.
- A parity test: what the apply path rejects in row 0, the offline CLI rejects
  too — through a **shared source**, not two maintained lists. Two lists is how
  the next divergence starts.
- The three claims in `validate_config.rs` match the behaviour afterwards.
- The remaining uncovered rows are named in the footer, completely.
- Gate green.

## Explicitly not in this item

- No new validation rule. This makes existing rules reachable.
- No change to `validate_against` or to the apply path's ordering.
- No change to the three in-repo guard tests; they are the precedent, not the
  target.
