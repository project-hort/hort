# 033 — Renovate must regenerate third-party attribution in its dependency MRs

- **Source:** GitLab issue #31 audit thread / #33 (surfaced while grooming ADR 0049); prompted by the #20 Renovate Dependency Dashboard.
- **Type:** chore (CI/supply-chain) + **infra dependency** (self-hosted Renovate runner config).
- **Model hint:** **small** for the repo `renovate.json` change; the runner-side allowlist is an **operator/infra** step (escalate — not in-repo).
- **Reviewable unit:** one directive for the repo change; the runner config is tracked separately (see Escalation).

## Problem

ADR 0049 requires that **any** dependency-graph change regenerate
`THIRD-PARTY-LICENSES.{md,json}` in the same change. Renovate is the
**highest-frequency** dependency-change source and does **not** do this: a
Renovate MR bumps `Cargo.lock` with no attribution regen. Because
`renovate.json` sets `baseBranches: ["develop"]` and #30 scoped
`security:attribution-sync` off `develop`-targeting MRs, **merging a Renovate dep
MR re-stales `develop`** — the exact failure mode the `spin 0.9.8 → 0.9.9` bump
(#28) caused, but recurring on every routine bump. `attribution-sync` then fails
at the next release-relevant pipeline (as it did for `v0.9.9-beta.4`, #33).

Until this is fixed, **every Renovate dep MR carries a merge-time obligation**:
regenerate attribution before merging (ADR 0049 Consequences).

## Approach — durable fix

1. **Repo (`renovate.json`):** add `postUpgradeTasks` that runs
   `scripts/regenerate-attribution.sh` so the regenerated attribution rides the
   same Renovate MR (commit `THIRD-PARTY-LICENSES.{md,json}` alongside the
   `Cargo.lock` bump). Scope it to Rust/`Cargo.lock`-affecting managers.
   - Remember: `renovate.json` is read from the **default branch (`main`)**, so
     this only takes effect after a `develop → main` promotion (the repo's own
     `description` note records this).
2. **Verify** with a forced Renovate dep MR (unlimit one rate-limited entry on
   #20, e.g. `serde_json` / `tokio`) that the resulting MR includes a
   `THIRD-PARTY-LICENSES.*` change and `check-attribution` passes on it.

## Escalation (infra — cannot be done from the repo alone)

`postUpgradeTasks` requires the self-hosted Renovate runner to:
- allowlist the command in `allowedPostUpgradeCommands` (a global/runner config,
  NOT `renovate.json` — Renovate ignores repo-level `allowedPostUpgradeCommands`
  for security), and
- have `cargo-about` (+ a Rust toolchain) available in the runner image.

Both are **operator-side** on the Renovate deployment (the `group_144_bot`
runner), outside this repo. **Open/reference an `agent:escalation` for the
runner change**; without it the `postUpgradeTasks` block is inert and the
merge-time manual obligation (ADR 0049) remains the only enforcement.

## Acceptance

- `renovate.json` (once on `main`) makes Renovate commit regenerated attribution
  in the same MR for Cargo dependency changes; a forced Renovate MR proves it.
- If the runner allowlist/toolchain is unavailable, ADR 0049's merge-time manual
  regen is documented as the interim enforcement and the infra gap is escalated.

## Out of scope

- The Dependabot side (`.github/dependabot.yml`) — GitHub Dependabot manages only
  `.github/workflows` here (`renovate.json` disables the `github-actions`
  manager); it does not bump Cargo deps, so it does not touch attribution.
