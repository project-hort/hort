# 0049 — Regenerate third-party attribution on ANY dependency change, in the same change

- **Status:** Accepted
- **Enforced by:** authoring-time discipline (this ADR + the architect-guide
  anti-pattern checklist + `CLAUDE.md` → *Pre-push Quality Checklist*) backed by
  `scripts/check-attribution.sh` on **release-relevant** pipelines
  (`security:attribution-sync`, scoped to tags + `main`/`release/*` + MRs
  targeting them — [ADR 0047](0047-dual-license-generated-attribution.md), issue
  #30). The gate is fail-closed at every release boundary, but it no longer runs
  on feature/`develop` pipelines, so the discipline is the *first* line of
  defence and this ADR makes it explicit.
- **Supersedes:** —
- **Relates:** [0047](0047-dual-license-generated-attribution.md) (generated,
  CI-verified attribution embedded via `include_str!`); issue #30 (the
  `security:attribution-sync` release-relevant rescope that removed the per-MR
  check); issue #28 / commit `994e88ee` (the spin bump that triggered this);
  issue #31 (the re-audit that surfaced the gap); issue #33 (the `beta.4`
  release whose tag pipeline failed on the inherited staleness).

## Context

`THIRD-PARTY-LICENSES.{md,json}` are **generated** from the compiled dependency
graph (`cargo-about`, `scripts/regenerate-attribution.sh`) and **committed** at
the repo root, embedded into the shipped binaries via `include_str!` (ADR 0047).
They are correct only if regenerated whenever the graph changes.

Originally `security:attribution-sync` ran on every code-touching pipeline
(`.rules-code-changed`), so a dependency change that forgot to regenerate
attribution failed CI immediately — the gate *was* the reminder. Issue #30
**rescoped** that job to release-relevant pipelines only (tags, `main`/`release/*`
pushes, and MRs targeting them), because attribution is a property of the shipped
artifact and a Renovate dep-bump MR would otherwise fail deterministically on
stale attribution it did not itself cause. That rescope is correct for its stated
goal (a stale attribution still cannot *ship* — the promotion MR / release pushes
/ tags all re-verify), **but it removed the early, per-MR feedback loop.**

The removed feedback loop was load-bearing without anyone recording that it was.
Concretely: the `spin 0.9.8 → 0.9.9` bump (#28, `994e88ee`) changed the graph and
was merged to `develop` **without** regenerating attribution; nothing on the
`develop` line re-runs the check, so the staleness sat latent until the next
release-relevant pipeline — the `v0.9.9-beta.4` tag (#33) — failed on it. The
`#28` re-audit (#31) cleared the bump as "correct remediation" without verifying
attribution regen, and cleared the #30 rescope as "adheres" without recording that
it shifts an authoring-time obligation onto the developer. The two decisions are
individually fine and jointly created a silent gap. This is the canonical
"re-validate an inherited rationale when the threat surface changes" failure: #28
relied on a per-MR check that #30 had already removed.

## Decision

**ANY change to the compiled dependency graph MUST regenerate
`THIRD-PARTY-LICENSES.{md,json}` (`scripts/regenerate-attribution.sh`) and commit
them in the SAME change / MR.**

"Any change to the dependency graph" includes, non-exhaustively:

- a version bump (`Cargo.toml` dep edit, a release **workspace-version** bump is
  exempt — it does not change third-party crates, verified by the graph diff),
- `cargo update` (targeted `-p <crate>` or workspace `-w`),
- adding or removing a dependency or a feature that pulls new crates,
- any `Cargo.lock` change that adds/removes/re-versions a **non-workspace** crate.

Procedure (host has no toolchain by design — run in the project sandbox):

```
sbx -C <repo> exec -- ./scripts/regenerate-attribution.sh
git add THIRD-PARTY-LICENSES.md THIRD-PARTY-LICENSES.json
sbx -C <repo> exec -- ./scripts/check-attribution.sh   # must pass before push
```

`check-attribution.sh` regenerates and diffs against the **committed** files, so
stage/commit the regeneration **before** running it (it restores the working tree
to `HEAD` after its comparison).

For a **release cut**, attribution regeneration is part of the cut, committed in
the same commit as the version + lockfile bump — a release tag must never be
pushed with stale attribution (its pipeline runs `attribution-sync` and will fail).

## Consequences

- The `security:attribution-sync` gate stays release-scoped (ADR 0047 / #30
  unchanged) — this ADR does **not** re-widen it. The gate remains the fail-closed
  backstop; this ADR makes the authoring-time step the first line of defence so the
  backstop is never the *first* time staleness is discovered.
- A dependency-changing MR that omits the attribution regen is a **review hard
  block** (architect-guide anti-pattern; `CLAUDE.md` pre-push checklist). The
  reviewer checks that any `Cargo.lock` non-workspace-crate delta is accompanied by
  a `THIRD-PARTY-LICENSES.{md,json}` regeneration.
- A release-workspace-version-only bump (`X.Y.Z-dev → X.Y.Z-<pre>`) does not change
  third-party crates, so it does not by itself require an attribution change — but
  the cut must still `check-attribution` to confirm the graph is unchanged (a
  concurrent dep drift would surface here).
- **Automated dependency bots (Renovate) do not regenerate attribution.** This
  rule's "authoring-time discipline" assumes a human (or the cockpit) authors the
  change; a Renovate/Dependabot MR bumps `Cargo.lock` with **no** attribution regen
  and, because Renovate targets `develop` (`renovate.json` `baseBranches`) and
  `attribution-sync` does not run on `develop`-targeting MRs (#30), merging one
  **re-stales `develop`** exactly as the `spin` bump did — the highest-frequency
  trigger of this bug. Until the durable fix lands, **every Renovate dep MR is a
  merge-time obligation**: regenerate attribution before merging it. The durable
  fix (Renovate `postUpgradeTasks` running `scripts/regenerate-attribution.sh` so
  the regeneration rides the same MR, which additionally needs the command
  allowlisted in the self-hosted Renovate runner's `allowedPostUpgradeCommands` and
  `cargo-about` present there) is groomed as **backlog/033**. Note: `renovate.json`
  is read from the **default branch (`main`)**, so that fix only takes effect after
  a `develop → main` promotion.

## Alternatives considered

- **Re-widen `attribution-sync` to every pipeline (revert #30).** Rejected: it
  reintroduces the exact deterministic-failure-on-Renovate-MRs problem #30 fixed.
  The authoring-time rule plus the release-boundary gate covers the risk without
  that cost.
- **Leave it as script-header guidance only.** Rejected: that guidance already
  existed and was not followed (#28), precisely because the CI reminder that used
  to enforce it had been removed. A standing decision the cockpit and reviewer
  follow is the structural close.
- **A pre-commit hook that regenerates attribution.** Rejected for now: the host is
  toolchain-free by design (regeneration runs in the sandbox), so a local hook
  cannot run it uniformly; the review check + release-cut step are the reliable
  enforcement points.
