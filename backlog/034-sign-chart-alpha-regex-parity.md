# 034 — `helm:sign-chart` tag regex omits `alpha` (parity gap re-opened after #25)

- **Source:** GitLab issue #34 (beta.5 cut) escalation; regression against #25 alpha-routing (`40d8b4b9`).
- **Type:** chore (CI) — **repo-side fix**, but its *effect* is coupled to the Vault/protected-tag infra escalation on #34.
- **Model hint:** **small** — one-line `.gitlab-ci.yml` rule regex.
- **Reviewable unit:** one MR (this branch, `fix/sign-chart-alpha-regex-parity`).

## Problem

`helm:sign-chart` (added to `develop` in `437d4f23`, "ci: sign the Helm chart
with the first-party Transit key") gates on
`$CI_COMMIT_TAG =~ /^v[0-9]+\.[0-9]+\.[0-9]+(-(rc|beta)\.[0-9]+)?$/` — it
**omits `alpha`**. It landed *after* #25 (`40d8b4b9`) widened the other
release-tag jobs (`build-images:hort-server`/`-worker`, `helm:lint-and-publish`)
to `(alpha|rc|beta)`, so it re-opened for this one job the exact gap #25 closed:
when the internal `alpha.N` scheme starts at the next base version
(`0.9.10-alpha.N` / `1.0.0-alpha.N`), `helm:sign-chart` will be **silently
skipped** (no rule match, no failure) → an **unsigned chart with no signal**.
`release:sbom` uses `/^v[0-9]+\.[0-9]+\.[0-9]+/` (no suffix anchor) and already
matches alpha, so only this one job has the gap.

## Fix (in this branch)

`.gitlab-ci.yml` `helm:sign-chart` rule regex `(-(rc|beta)\.[0-9]+)?` →
`(-(alpha|rc|beta)\.[0-9]+)?`, with a comment tying it to #25 so it isn't
re-narrowed. Tag-suffix set is now identical across every release-tag job.

## Coupling — DO NOT merge ahead of the Vault decision (#34 escalation)

This regex fix only makes `helm:sign-chart` *run* on `alpha`/pre-release tags; it
does **not** make it *succeed*. The job currently **fails** on any pre-release
tag because the `first-party-hort` Vault OIDC role binds `ref_protected` and a
pre-release tag (`v0.9.9-beta.5`) is **not a protected ref** (`ref_protected:
false` → Vault denies). See the #34 `agent:escalation`:

> either protect the `v0.9.9-beta.*` / `v*` tag pattern in GitLab, or widen the
> `first-party-hort` Vault role's bound claims to accept pre-release-tag pipelines.

So merging this regex fix **before** the Vault/protected-tag fix would only
convert alpha's *silent skip* into a *loud failure* (arguably better — a signal
beats silence — but it will red every alpha pipeline until Vault is fixed). Land
this **with or after** the infra fix, or land it now with eyes open that alpha
signing stays red until the Vault side is done. Reviewer's call.

## Acceptance

- `helm:sign-chart`'s rule regex matches `alpha`/`rc`/`beta` pre-release tags,
  identical to the other release-tag jobs (`grep` shows one uniform suffix set).
- The Vault/protected-tag prerequisite is recorded (this file + #34) so signing
  actually *succeeds* on pre-release tags once infra lands.

## Out of scope

- The Vault role binding / GitLab protected-tag config (operator/infra — #34
  `agent:escalation`).
