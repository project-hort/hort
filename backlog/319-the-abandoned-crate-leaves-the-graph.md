# 319 — The abandoned crate leaves the graph, and the proof is a tree query

**Issue:** #347 · **Branch:** `agent/347-yaml-parser-ohne-verlassenes-transliterat`
**Depends on:** 318 (the swap, with the harness green).

The ticket's goal is not a green gate — it is that the abandoned component is
gone. This unit is where that becomes checkable.

## What to do

1. **Remove `serde_yaml_ng`** from every `Cargo.toml` that names it
   (`hort-config`, `hort-app`, `hort-server` — re-measure), including the
   `dev-dependency` that unit 316's harness used.
2. **Remove the differential harness** in the same commit. Its purpose was the
   migration; keeping it would mean keeping a dependency on the abandoned crate
   to test the crate that replaced it. Unit 317's six semantic tests **stay** —
   they pin behaviour, not a comparison.
3. **Prove the graph.** `cargo tree -i unsafe-libyaml -e normal` must report
   nothing, and the report carries that command and its output verbatim. Do the
   same for `unsafe-libyaml-norway`, so a later well-meaning swap to the
   renamed fork is visibly a regression rather than a green gate.
4. **`cargo audit` and `cargo deny` must both be green again** — and green
   because the crate is gone, with **no** entry added to `.cargo/audit.toml` or
   `deny.toml`. If an ignore appears in this change, the ticket failed.
5. **The duplicate `serde-saphyr` stays, and is not papered over.** After the
   swap the lock carries kube's `0.0.29` beside our `1.3.0`;
   `multiple-versions = "warn"` makes that a visible warning and `skip` stays
   `[]`. Do **not** add a skip entry to silence it — the warning is the honest
   record that an upstream pins a pre-1.0 line. State the warning verbatim in
   the report.
6. **Regenerate the attribution** (`scripts/regenerate-attribution.sh`) and
   commit `THIRD-PARTY-LICENSES.{md,json}` in the same change: the dependency
   graph moved, so the committed attribution is stale by definition. Regenerate
   and commit — never run the check in between (it reverts a regeneration).
   `cargo-about` lives in the sandbox's cargo home and may be missing after a
   volume prune; install it before starting rather than discovering it at the
   end.

## Acceptance

- `grep -rn "serde_yaml_ng\|unsafe-libyaml" --include=Cargo.toml --include=*.rs crates/`
  is empty.
- `cargo tree -i unsafe-libyaml -e normal` and the same for
  `unsafe-libyaml-norway`: both empty, both quoted in the report.
- `cargo audit -D warnings` and `cargo deny check` green, with no new ignore
  entry anywhere — the diff of `.cargo/audit.toml` and `deny.toml` is empty.
- Attribution regenerated and committed in this change; the crate count moves
  and the report says by how much.
- Unit 317's six tests still green; the differential harness is gone.
- Gate: this is the last unit, so the **architect** runs the full gate
  (including `audit`, `deny` and attribution) on the finished tree before the
  MR. This unit still runs the unit gate, one-shot capture, judged by output.
