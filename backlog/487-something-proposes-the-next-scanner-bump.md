# 487 — something proposes the next scanner bump

**Issue:** #463 · **Branch:** `agent/463-scanner-versions`. **After units 485
and 486**, so the mechanism is written against pins that are already current.

## Why this unit exists

The two scanner pins fell six and four minor versions behind, and the reason is
structural rather than inattention: **nothing watches them.** The `ARG` pins in
`docker/Dockerfile.worker` carry no Renovate annotation, and `renovate.json`
disables the `github-actions` manager because Dependabot owns
`.github/workflows`. A comment cannot hold this invariant; a manager can.

## What to do

Add `customManagers` entries to `renovate.json` for `ARG TRIVY_VERSION` and
`ARG OSV_SCANNER_VERSION`, with `datasource=github-releases` against the
upstream repositories.

**And then answer the question that decides whether this is useful**: can the
four SHA-256 checksums travel with the version bump? If they cannot, a Renovate
MR arrives with a new version and stale checksums, the verified download fails,
and the MR can never go green — a mechanism that reliably produces red MRs is
worse than none, because it trains everyone to ignore it.

Two honest outcomes, and the unit picks one with its reasoning:

- **The checksums can be covered** — by a `customManager` that also updates
  them, or by a build that derives them from an upstream `SHA256SUMS` the
  bump makes available, as long as ADR 0006 still holds: the value is pinned
  where it is used, not fetched at build time without a pin.
- **They cannot** — then say so plainly, and make the mechanism's output
  something a human finishes: a Renovate MR that bumps the version and a
  statement in the dashboard entry that the checksums must be updated before
  it can merge. That is still better than silence, but it must be stated so
  nobody mistakes a red MR for a broken pipeline.

Also decide what happens to the workflow pins while `github-actions` stays
disabled: either they are covered another way, or the unit records that they
depend on Dependabot and names the file that configures it.

## Acceptance

- A mechanism exists that **proposes** a bump for both `ARG` pins, demonstrated
  rather than asserted — a dry run, a config validation, or the first MR it
  produces.
- The checksum question is answered in the report with the reasoning, not left
  open.
- `renovate.json` stays valid; the existing disabled-manager decision and its
  comment survive, including the note that Renovate reads the config from the
  default branch so the change takes effect only after a promotion to `main`.

## Not in scope

Enabling the `github-actions` manager, or changing the division of labour
between Renovate and Dependabot. Both are standing decisions with their reason
recorded in `renovate.json`.
