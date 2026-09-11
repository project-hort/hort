# 180 — say that staging rolls on tags, and stop promising it rolls on develop

**Issue:** #232 · **Branch:** `agent/232-staging-tag-only` · single item.

## Problem

ADR 0048 D3 states that staging is continuous and multi-source, deploying
from `develop`, from `test/*` alpha branches, and from `main`. The `develop`
half cannot happen: `build-images:*` and `helm:lint-and-publish` are
restricted to semver tags, `main`, and `release/*`, so `develop` publishes
no image and no chart. Staging is chart-driven, so there is nothing for it
to roll.

**This item changes documentation only.** The deployment path is sound and
stays as it is; the decision (recorded on #232) is to correct the contract,
not to build a develop publish.

## Why this is not cosmetic

Agents act on written contracts. This one has already cost a verifier round:
a UAT was dispatched naming a `develop` short-sha, came back `PENDING`, and
the verifier's entirely reasonable advice was to re-dispatch once `develop`
published something newer — an event that cannot occur. The verifier holds
the only cluster credential, so its rounds are the expensive ones.

The most load-bearing edit is **not** D3 itself but the resting-state
parenthetical, which is what an agent reads before dispatching.

## What to change

**1. ADR 0048 D3** — staging deploys from published artifacts: alpha tags
cut off `develop` via a `test/vX.Y.Z-alpha.N` branch, and `main`. Remove the
claim that `develop` itself deploys.

**2. ADR 0048's resting-state wording** — it currently describes an issue as
resting in `ready-for-staging` *"(merged to `develop`, on staging)"*. The
parenthetical is false. State what the label means under the tag-only model:
**merged to `develop` and eligible for the next alpha**, explicitly not
reachable on staging. `in-uat` is entered only once an alpha exists that
contains the change.

**3. The decision index row for 0048** in
`docs/adr/0000-historical-decisions-index.md` repeats "Staging is
continuous/multi-source (develop + test/* + main)". Correct it with the ADR,
or the index contradicts the decision it indexes.

**4. `docs/glossary.md`** — any wording implying a `ready-for-staging` issue
is reachable on staging gets the same correction.

Record in the ADR that **alpha cadence is on demand** — cut when there is
something worth verifying, no schedule and no cron. Prefer cutting one after
a risky change lands rather than waiting for several to accumulate, for the
bisection reason below.

## Two consequences that belong in the ADR, not only in the issue

**Tag provenance must be verified, not assumed.** A tag can predate the
change it is supposed to carry — that is how a beta once shipped without its
feature. Before a UAT for an issue is dispatched against alpha *X*, *X*'s
commit must be confirmed to contain that issue's merge
(`git merge-base --is-ancestor`). Under batched alphas this is the normal
check, not an edge case.

**Batching costs bisection granularity.** One alpha usually carries several
issues, so a failing UAT does not immediately identify the cause. That is
ordinary release testing and accepted — but it is a chosen trade-off, and it
is the reason to tag after a risky change rather than only when work has
piled up.

## Scope boundary

The auto-agents workflow protocol is platform-side and not in this
repository. Do not look for it and do not invent a local copy. The
project-local meaning of these states is defined in ADR 0048, which is where
a reader of this repository looks.

## Read first

- `docs/adr/0048-release-branch-staging-strategy.md` — D3 at the
  "Staging is continuous and multi-source" heading, and the resting-state
  paragraph naming `ready-for-staging`.
- `docs/adr/0000-historical-decisions-index.md` — the 0048 row.
- `docs/glossary.md` — the `ready-for-staging` / `in-uat` mentions.
- `.gitlab-ci.yml` — the `rules:` on `build-images:*` and
  `helm:lint-and-publish`, which are the ground truth being described.

## Acceptance

- No document in the repository states or implies that staging deploys from
  `develop`.
- ADR 0048 states what `ready-for-staging` means under the tag-only model,
  and that `in-uat` requires an alpha containing the change.
- The decision index row agrees with the amended ADR.
- The tag-provenance check and the bisection trade-off are recorded in the
  ADR.
- Docs only: `git diff --stat` shows no `.rs`, no `.gitlab-ci.yml`, no chart
  change.
