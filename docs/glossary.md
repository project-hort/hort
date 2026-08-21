# Glossary

Definitional terms used across hort's release, branch, workflow, and auth
docs. Most entries link to [ADR 0048](adr/0048-release-branch-staging-strategy.md),
the authority for the release/branch/staging model those terms describe;
the auth-domain entries link to the ADR or how-to that is authoritative for
them instead.

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

### Enforcement mode

A `ScanPolicy` field (`enforcement: reject | record`) deciding what a
**blocking scan verdict does** to the artifact — as distinct from the
knobs that decide *which* findings are blocking (`severityThreshold`,
`licensePolicy`, `negligibleAction`). Under `reject` (the default, and
the behaviour of any policy that omits the field) a blocking verdict
transitions the artifact to `Rejected`. Under `record` the scan still
runs and the findings, the per-finding rows and the
`PolicyEvaluated(Fail)` verdict are all persisted exactly as they would
be under `reject` — only the `ArtifactRejected` transition is withheld,
so publication proceeds and blocking at retrieval is left to a later,
explicit policy tightening. `record` un-gates the **scan** axis alone:
provenance, curation and the observation window are unaffected, and a
recorded verdict releases under its own `ScanRecorded` authority rather
than a widened `ScanSucceeded`. Changing the field re-judges the
existing population in both directions. See
[ADR 0007](adr/0007-fail-closed-quarantine-release-predicate.md) and
[ADR 0041](adr/0041-continuous-scan-policy-enforcement.md), and
[declare-gitops-config.md](architecture/how-to/declare-gitops-config.md)
`kind: ScanPolicy`.

### Global grant

A `PermissionGrant` whose `spec.repository` field is omitted, so it
authorizes its `permission` across every repository the deployment
serves rather than one named repository — the RBAC evaluator treats a
grant with no repository scope as matching every scope checked against
it. See [declare-gitops-config.md](architecture/how-to/declare-gitops-config.md)
`kind: PermissionGrant`.

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

### Session-gated

Describes an endpoint whose authorization requires a caller to present
a specific *kind* of token, independent of the permissions that token
carries. The self-service prefetch trigger is the canonical example:
it accepts a `CliSession` or `ServiceAccount` token but rejects a `Pat`
outright, before its `Permission::Read ∧ Permission::Prefetch` check
ever runs. See
[mint-operator-tokens-without-idp.md](architecture/how-to/mint-operator-tokens-without-idp.md)
and [ADR 0013](adr/0013-idp-authoritative-cli-sessions.md).

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
