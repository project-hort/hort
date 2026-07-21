# 038 — `gha-ci` federated identity: positive `environment` scoping (fix `multiple_sa_match`)

**Issue:** #64
**Design doc section:** decision recorded on issue #64 (option C — positive disjoint scoping)
**Read first:** `deploy/ansible/files/gitops/auth/service-accounts/gha-ci.yaml`,
`deploy/ansible/files/gitops/auth/service-accounts/gha-release.yaml`,
`.github/workflows/ci.yml`, `.github/workflows/feature-ci.yml`

## Problem

`gha-ci` is scoped to bare `{repository: project-hort/hort}` — it matches **any** GitHub
OIDC token from the repo, in any context. `gha-release` is `{repository, environment:
release}`. Because SA matching is subset-based, an `environment: release` token satisfies
**both** SAs → the federated exchange fails closed on `multiple_sa_match` → 401. This blocks
every release-publish path (`hort-publish`, `mirror-to-hort-oci`, `mirror-to-hort-base`,
`publish-chart-registry-hort-rs`) whenever `HORT_PROXY_ENABLED == 'true'`.

## Fix (option C — best-practice positive disjoint scoping)

Give the CI identity its own positive discriminator instead of leaving it context-wild, so
the two identities are disjoint **by construction** (the industry norm for GH-Actions OIDC
federation; no absence/negation matching — see #64 discussion). The discriminator is a
**non-gating `ci` deployment environment**.

1. **Narrow the SA claim** — `gha-ci.yaml` federated claims become:
   ```yaml
   claims:
     repository: project-hort/hort
     environment: ci
   ```
   Replace the "intentionally repo-scope only" NOTE comment with a short note that the
   identity is now scoped to the non-gating `ci` environment so it is disjoint from
   `gha-release` (fixes `multiple_sa_match`, #64).

2. **Tag every `gha-ci`-authenticating job** with `environment: ci`. Exhaustive list
   (jobs that call `./.github/actions/hort-auth` — or the inline `/auth/exchange` — **without**
   an environment today):
   - `ci.yml`: `hort-deps-gate`, `check-rust`, `test-backend-unit`, `coverage`,
     `test-backend-integration`
   - `feature-ci.yml`: `build-and-prefetch`

   Add `environment: ci` at job level (a bare `environment: ci`, no `url`, no protection).

**Do NOT touch** the four release jobs — they already carry `environment: release` and must
keep matching `gha-release`. Verified during grooming that **no** release job relies on the
`gha-ci` identity: the mirror jobs use `cosign copy` (ghcr → registry.hort.rs, no hort proxy
pull); `hort-publish` uses `cargo publish --no-verify` (no dep compilation → no pull-through
fetch; the hort-crates index read is `gha-release`'s own concern). So narrowing `gha-ci`
breaks no publish path.

## Invariant (the one correctness pairing — must be atomic in one commit)

The claim-narrow (step 1) and the job-tagging (step 2) are a **matched pair**. If the claim
requires `environment: ci` but a CI job is left un-tagged, that job's token carries **no**
`environment` claim → it matches **neither** SA → `no_sa_match` → 401. Land both in the same
change; do not split.

## Precondition (operator / Tom — flagged on #64, not a code task)

A GitHub `ci` **deployment environment with no protection rules** must exist (or be allowed to
auto-create on first reference). Non-gating by design — it exists only to stamp the
`environment: ci` claim, adds no reviewers/branch gate.

## Acceptance

- `gha-ci.yaml` claims are `{repository: project-hort/hort, environment: ci}`; the stale
  "repo-scope only" NOTE is replaced.
- All six jobs above declare `environment: ci`; no release job changed.
- Gitops fixtures still parse: `cargo test --workspace` green (the gitops-tree parse /
  `alpha_fixtures` guards must pass with the narrowed claim).
- `cargo fmt --check` / `clippy` clean (no Rust changed, but run the gate).
- YAML lints clean.

## Out of scope (recommended follow-on, Tom's call — see #64)

A **structural guard** that rejects pairwise subset-overlapping federated claim-sets per issuer
at gitops apply (so a future SA can't silently reintroduce `multiple_sa_match`) is the durable
close, matching the project's apply-time-linter pattern. Deliberately **not** bundled here to
keep this fix config-only per the approved scope; tracked separately if Tom wants it.

### Starter prompt

```
/hort-architect

Implement backlog item 038 (issue #64) on branch agent/64-gha-ci-environment-scope.
Config-only, no Rust. Read gha-ci.yaml, gha-release.yaml, ci.yml, feature-ci.yml first.
Narrow gha-ci's federated claims to {repository: project-hort/hort, environment: ci} and add
`environment: ci` to exactly these jobs: ci.yml {hort-deps-gate, check-rust,
test-backend-unit, coverage, test-backend-integration} and feature-ci.yml {build-and-prefetch}.
Do NOT touch the four environment: release jobs. The claim-narrow and job-tagging are one
atomic commit (an un-tagged CI job would match neither SA → no_sa_match 401). Run
`cargo test --workspace` + `cargo fmt --check` + `cargo clippy` and confirm the gitops-fixture
guards still pass. Report per the handover protocol.
```
