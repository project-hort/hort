# 0048 — Release, branch, and staging strategy: `develop` → `test/*-alpha.N` → `main`

- **Status:** Accepted
- **Enforced by:** this is primarily a **documented process** decision — its home is
  `RELEASING.md`, `docs/glossary.md`, and the CLAUDE.md *Releases* section, which this
  ADR governs. The one mechanised part is the alpha-tag build/publish routing: the
  `build-images:hort-server` / `build-images:hort-worker` / `helm:lint-and-publish`
  tag regex in `.gitlab-ci.yml` matches `alpha` (so an internal `v…-alpha.N` tag
  builds/publishes to the **internal** `${REGISTRY}`), while `.github/workflows/docker-publish.yml`
  **excludes** `alpha` from the public ghcr publish (so internal alphas never leak).
  There is no runtime code gate; the trunk-cleanliness rule (no version-bump commit on
  `develop`/`main`) is a review discipline, not a hook.
- **Supersedes:** —
- **Relates:** [0047](0047-dual-license-generated-attribution.md) (public image/chart
  publish surface); the auto-agents workflow states (`ready-for-staging` / `in-uat` /
  `closed`) whose resting-state semantics this records for hort. Source decision:
  issue #25 + the maintainer's 2026-07-13 clarifications.

## Context

The auto-agents workflow models `ready-for-staging → in-uat → closed` as **resting
states decoupled from `main` promotion**: `main` is a deliberate, version-fixed public
release, so an issue whose work is merged to `develop` rests in `ready-for-staging` /
`in-uat` and is closed in a batch when a release is cut — it is *not* blocked merely
because `main` has not moved. hort had no ADR recording the project-specific mechanics
that sit under this (branch names, staging sources, pre-release naming), so the
architect and future contributors lacked one shared model; `RELEASING.md` and the
CLAUDE.md *Releases* section described only the throwaway-tag pre-release mechanism.

The maintainer set the policy (issue #25, clarified 2026-07-13):

- The existing **throwaway-branch pre-release-tag mechanism is kept** — not replaced.
- Internal pre-releases are **renamed `beta`/`rc` → `alpha`** (they are internal test
  builds; semver orders `alpha < beta < rc`, leaving room for a future *public*
  `beta`/`rc` track).
- **Hard requirement:** the version-bump commits for those internal builds **must not
  land on `develop` or `main`**.
- Staging is **continuous and multi-source**, and it deploys from the **Helm chart +
  images** — so an internal alpha tag **must** build and publish those artifacts, but
  to the **internal** registry only (never public).

## Decision

### D1 — Branch model: `develop` → `test/vX.Y.Z-alpha.N` (throwaway) → `main`

`develop` is the integration trunk. An internal pre-release is a version-bump commit cut
on a **`test/vX.Y.Z-alpha.N`** branch **off `develop`**, tagged `vX.Y.Z-alpha.N`. The
branch **is pushed** (so staging/CI can deploy it) but is **never merged back** — its
version-bump commit must not appear on `develop` or `main`. `main` is the public
release: a deliberate, version-fixed `develop → main` promotion MR (human-approved),
tagged `vX.Y.Z` with no pre-release suffix.

### D2 — Naming: `alpha` for internal test builds

Internal pre-releases are named `alpha.N`, not `beta.N` / `rc.N`. Because semver orders
`alpha < beta < rc`, this reserves `beta`/`rc` for a possible future **public**
pre-release track without collision. `alpha` = purely internal.

### D3 — Staging is continuous and multi-source

The staging/test environment deploys from `develop`, from `test/*` pre-release branches,
and from `main`. There is always a current artifact to deploy; staging is not gated on a
`main` cut.

### D4 — Alpha artifacts are internal-only, but they ARE built

An `alpha` tag builds container images **and** a Helm chart (staging deploys from them),
published to the **internal** registry (`${REGISTRY}` / registry.hort.rs, via GitLab CI's
`build-images:*` + `helm:lint-and-publish`). They are **never** published to the public
ghcr: the GitHub `docker-publish.yml` public publish **excludes** `alpha` tags. `beta` /
`rc` / final-release behaviour is unchanged on both sides. This is the concrete meaning
of "internal-only": internal registry yes, public registry no.

### D5 — Workflow resting states

`ready-for-staging → in-uat → closed` are resting states decoupled from `main`
promotion. An issue rests in `ready-for-staging` (merged to `develop`, on staging) or
`in-uat` until a release; a single `develop → main` promotion may close many such issues
at once. Issues auto-close only on merge to the default branch (`main`), so a fix's
`Closes #…` references belong on the promotion MR, not the feature MR into `develop`.

## Consequences

- Staging always has a deployable artifact (develop / test-branch / main), independent
  of release cadence.
- Internal alpha builds never leak to the public registry; the public ghcr surface stays
  final + (future) beta/rc only.
- `develop` and `main` keep a clean history: no per-alpha version-bump commits. Trade-off:
  alpha tags live off `develop`'s line, so `git describe` from `develop` will not find
  them — acceptable for ephemeral internal builds (mirrors the existing beta-tag
  trade-off already noted in the CLAUDE.md *Releases* section).
- The trunk-cleanliness rule (D1) and the internal-only rule (D4) are enforced by review
  + the CI routing respectively, not by a runtime gate; a future regression guard could
  assert the tag-regex split if drift becomes a risk.

## Alternatives considered

- **Replace the throwaway-tag mechanism with a merged, long-lived release-branch model.**
  Rejected: the maintainer explicitly chose to keep the existing mechanism; a merged
  model would put version-bump commits on the trunk, which D1 forbids.
- **Publish alpha images/charts publicly too (single publish path).** Rejected: alpha is
  internal-only by policy; the fail-safe default is to exclude alpha from the public
  publish, not to broaden it.
- **Keep `beta` naming for internal builds.** Rejected: reserving `beta`/`rc` for a
  future public track is cheap now and avoids a later rename collision.

## References

- `RELEASING.md` (pre-release + promotion mechanics — amended to this model)
- `docs/glossary.md` (`staging`, `UAT`, `alpha build` / `test/*` branch, `release`,
  and the `ready-for-staging` vs `in-uat` vs `closed` distinction)
- CLAUDE.md *Releases* / *Docker image tags* sections
- Issue #25 (decision source) and its 2026-07-13 clarifications
