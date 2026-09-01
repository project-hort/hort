# 156 — drop the cargo ecosystem from dependabot.yml

**Issue:** #224 · **Branch:** `agent/224-dependabot-cargo` · **One reviewable unit (one MR).**

## Problem

GitHub dependabot's cargo version-update PRs structurally cannot pass two
gates working as designed: `hort-deps-gate` (a bumped version the vetted
index never served is RED — "quarantine never yields a green gate") and
`attribution-sync` (dependabot bumps `Cargo.lock` without regenerating
`THIRD-PARTY-LICENSES.{md,json}`). Cargo bumps flow exclusively through the
GitLab Renovate batch choreography (warm → quarantine window → merge →
attribution regen in the same flow).

## Task

1. `.github/dependabot.yml`: remove the entire `package-ecosystem: "cargo"`
   block (including its RustCrypto `ignore:` list — that concern lives in
   the GitLab-side #199 wave now). In its place, a comment stating the
   invariant: cargo bumps flow through the GitLab Renovate choreography
   because the vetted-index gate and the attribution-regen rule require the
   coordinated flow; a standalone cargo bump PR structurally cannot pass
   `hort-deps-gate` or `attribution-sync`. GitHub security ALERTS remain
   config-independent; docker/github-actions/compose ecosystems stay.
2. No other file. No CHANGELOG entry (repo-meta config, not user-facing —
   consistent with prior dependabot.yml-only changes).

## Acceptance

- Diff = `.github/dependabot.yml` only; cargo block gone, other three
  ecosystems byte-identical; invariant comment in place.
- Valid YAML (`python3 -c 'import yaml,sys; yaml.safe_load(open(".github/dependabot.yml"))'`
  or equivalent).
- Comment discipline: invariants only (no issue refs; the gate names are
  the durable anchors).

## Governing decisions

Vetted-index gate design (S1, docs/ci/hort-quarantine-integration.md) ·
en-bloc dependency plan (GitLab Renovate is the single cargo entry point) ·
attribution regen rule (dep-graph change ⇒ regen in the same change).
