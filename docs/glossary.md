# Glossary

Definitional terms used across hort's release, branch, and workflow docs.
Each entry links to [ADR 0048](adr/0048-release-branch-staging-strategy.md),
which is the authority for the release/branch/staging model these terms
describe.

### Alpha build (`test/*` branch)

An internal-only pre-release: a version-bump commit cut on a
`test/vX.Y.Z-alpha.N` branch off `develop`, tagged `vX.Y.Z-alpha.N`. The
branch is **pushed** (so staging/CI can deploy it) but is **never merged
back** — its version-bump commit must not land on `develop` or `main`. An
alpha tag builds container images and a Helm chart, published to the
**internal** registry only (never the public ghcr). See
[ADR 0048](adr/0048-release-branch-staging-strategy.md) D1, D2, D4.

### Closed

The terminal state of an issue. Issues auto-close only on merge to the
default branch (`main`) — a final release's promotion MR closes every
issue whose fix already rested in `ready-for-staging` or `in-uat`, often
many at once. See [ADR 0048](adr/0048-release-branch-staging-strategy.md) D5.

### In-UAT

A resting state for an issue whose fix is in User Acceptance Testing on
staging, decoupled from a `main` release cut. See [UAT](#uat) and
[ADR 0048](adr/0048-release-branch-staging-strategy.md) D5.

### Ready-for-staging

A resting state for an issue whose fix has merged to `develop` and is
live on staging, awaiting UAT or a release. Not blocked merely because
`main` hasn't moved — `develop`, `test/*` alpha branches, and `main` are
all deployable to staging independently of release cadence. See
[ADR 0048](adr/0048-release-branch-staging-strategy.md) D3, D5.

### Release (`main`)

`main` is hort's public release line: a deliberate, version-fixed
`develop → main` promotion MR, tagged `vX.Y.Z` with no pre-release
suffix. A single promotion can batch-close many issues that had been
resting in `ready-for-staging` / `in-uat`. See
[ADR 0048](adr/0048-release-branch-staging-strategy.md) D1, D5.

### Staging

hort's continuous, multi-source test environment. It deploys from
`develop`, from `test/*` alpha pre-release branches, and from `main` — so
there is always a current deployable artifact, independent of whether a
release has been cut. See
[ADR 0048](adr/0048-release-branch-staging-strategy.md) D3.

### UAT

User Acceptance Testing: manual verification on staging before a fix is
considered release-ready. An issue rests `in-uat` until a release, rather
than being blocked on one. See [ADR 0048](adr/0048-release-branch-staging-strategy.md) D5.
