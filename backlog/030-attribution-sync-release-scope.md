# 030 — scope `security:attribution-sync` to release-relevant pipelines

- **Source:** GitLab issue #30 (direction confirmed by maintainer 2026-07-14)
- **Type:** chore (CI) — `.gitlab-ci.yml` only
- **Model hint:** **small** — one job's `rules:` block; CI-correctness-sensitive (verify with CI-lint).
- **Reviewable unit:** one directive.

## Problem

`security:attribution-sync` regenerates `THIRD-PARTY-LICENSES.{md,json}` with
`cargo-about` and diffs against the committed files (ADR 0047). Post-#24 it carries
`<<: *rules-code-changed`, so it runs on **any** MR/branch pipeline touching a code
path. A Renovate MR bumps `Cargo.lock` → changes the dep graph → the committed
attribution is now stale → the job **fails deterministically** on every dep-bump MR,
even though that MR is not shipping anything.

## Direction (confirmed by the maintainer)

Attribution is a property of the **shipped artifact** (embedded into the binaries via
`include_str!`), so verify it at **release-relevant** pipelines, not on every MR.
**Minimal, attribution-sync-only** re-scope — do **not** touch `security:cargo-audit` /
`cargo-deny` / `advisory-sync` (they keep `.rules-code-changed`; that broader
security-stage reconciliation is out of scope here). The Renovate `postUpgradeTasks`
regenerate-on-bump idea is a **separate optional follow-up**, not part of this.

## Change

In `.gitlab-ci.yml`, replace `security:attribution-sync`'s `<<: *rules-code-changed`
with an explicit release-relevant `rules:` block (mirrors the
`quality:no-plans-on-default-branch` MR-target pattern already in the file):

```yaml
  rules:
    - if: $CI_COMMIT_TAG
    - if: $CI_COMMIT_BRANCH == "main"
    - if: $CI_COMMIT_BRANCH =~ /^release\//
    - if: $CI_PIPELINE_SOURCE == "merge_request_event" && $CI_MERGE_REQUEST_TARGET_BRANCH_NAME =~ /^(main|release\/)/
```

Runs on: tags, `main`/`release/*` branch pushes, and MRs **targeting** `main`/`release/*`
(the `develop → main` promotion + maintenance-release MRs). Does **not** run on: feature/
Renovate MRs, MRs targeting `develop`, or ordinary `develop` pushes. No `changes:` filter
on the release arms — we always want attribution verified before a release build.

## Why this is safe

A stale attribution still **cannot ship**: the promotion MR to `main`, `main`/`release/*`
pushes, and every `v*` tag all re-verify it before any public artifact is built. Only
internal, non-shipping pipelines stop running it. (Alpha/staging builds off `develop` are
internal-only per ADR 0048; the promotion MR catches any drift before public release.)

## Out of scope

- `security:cargo-audit` / `cargo-deny` / `advisory-sync` gating (unchanged).
- Renovate `postUpgradeTasks` auto-regeneration (separate optional follow-up).
- Any change to what `attribution-sync` *does* (only when it runs).

## Acceptance criteria

1. `security:attribution-sync` runs on tags, `main`/`release/*` branches, and MRs
   targeting `main`/`release/*`; it does **not** run on feature/Renovate MRs, develop-
   targeting MRs, or `develop` pushes.
2. The `develop → main` promotion MR still runs it (stale attribution can't ship).
3. No other security job's gating changed.
4. `.gitlab-ci.yml` remains CI-lint-valid.

## Verification (for the cockpit report)

- Before/after of the `security:attribution-sync` `rules:` block.
- Rule-evaluation reasoning across: a Renovate/feature MR (→ **skipped**), an MR targeting
  `main` (→ **runs**), a `develop` push (→ **skipped**), a `main` push / `v*` tag (→ **runs**).
- CI-lint the file if possible (`gitlab-ci-local`); the architect will run the GitLab
  CI-lint API on landing.
- No `.rs` changed → Rust gate N/A.
