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
staging, decoupled from a `main` release cut. Entered only once an alpha tag
has been cut whose commit is confirmed (`git merge-base --is-ancestor`) to
contain the issue's merge — not merely once some alpha exists. See
[UAT](#uat) and [ADR 0048](adr/0048-release-branch-staging-strategy.md) D5.

### Ready-for-staging

A resting state for an issue whose fix has merged to `develop` and is
eligible for the next alpha cut — explicitly **not yet reachable on
staging**, since `develop` merges alone publish nothing for staging to
deploy. Not blocked merely because `main` hasn't moved: alpha cadence is
on demand, and `test/*` alpha tags and `main` are what actually deploy to
staging. See [ADR 0048](adr/0048-release-branch-staging-strategy.md) D3, D5.

### Release (`main`)

`main` is hort's public release line: a deliberate, version-fixed
`develop → main` promotion MR, tagged `vX.Y.Z` with no pre-release
suffix. A single promotion can batch-close many issues that had been
resting in `ready-for-staging` / `in-uat`. See
[ADR 0048](adr/0048-release-branch-staging-strategy.md) D1, D5.

### Scanner capability map

Which vulnerability-scanner backend can produce a verdict for which
repository format. Each backend owns its own row
(`ScannerPort::applies_to` — `trivy` answers from the artifact kinds it
can materialise, `osv` from the formats whose handler exposes an SBOM);
`hort_app::scanning::scan_backend_applies_to` is the static mirror the
apply path reads, because the server constructs no scanner adapters and
so has nobody to ask, and a parity guard in `hort-worker` — the one
crate holding both the real adapters and the handler registry — asserts
the two never disagree.

The map is **binary**, and a cell is "yes" only where a test exists in
which a known-vulnerable fixture of that format, materialised by that
backend, yields at least one finding. Materialisation alone is not
evidence: bytes that reach a scanner no analyzer claims produce the
*absence* of a verdict, which is exactly the inert pairing the map
exists to name. What a "yes" covers varies per cell (Trivy on an npm
tarball sees the package's own identity but not its declared dependency
ranges; on a `.crate`, only a shipped `Cargo.lock`) and is described in
the documentation rather than encoded as a third state — a "partial"
warning on nearly every non-OCI cell would be noise. The canonical "no"
is `osv` × `oci`: an OCI blob has no SBOM source, so that pairing
analyses nothing while reading, in a policy, as a second scan authority.

Two consumers read the record. **Apply-time**, the linter rejects a
`ScanPolicy.scanBackends` entry paired with a repository format it
cannot analyse — evaluated on the *effective* pairing, since a
repo-scoped policy wins over a global one, so a global policy is never
linted against a repository that declares its own. **At scan time**, the
orchestrator consults the map before invoking a backend, which covers
what apply-time rejection cannot reach (the built-in default backend
list, and a policy predating the rule); a backend that does not apply is
never invoked, and the abstention recorded in its place gates or not
according to whether any other backend covers the format.

The scan-axis counterpart of the provenance capability set
(`TIER1_PROVENANCE_CAPABLE_FORMATS`, `ProvenancePort::applies_to`). The
per-cell table with evidence is in
[the scanning-pipeline page](architecture/explanation/scanning-pipeline.md#the-scanner-capability-map).
See [ADR 0015](adr/0015-apply-time-linter-inert-fields-and-naming.md) (a field
accepted at apply must be load-bearing at runtime or rejected at apply)
and [ADR 0007](adr/0007-fail-closed-quarantine-release-predicate.md).

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

hort's test environment. It deploys from published artifacts only:
`test/*` alpha pre-release tags and `main` — never from bare `develop`
merges, since `develop` publishes no image or chart. It is not gated on a
`main` cut, but it is gated on the next (on-demand) alpha. See
[ADR 0048](adr/0048-release-branch-staging-strategy.md) D3.

### UAT

User Acceptance Testing: manual verification on staging before a fix is
considered release-ready. An issue rests `in-uat` until a release, rather
than being blocked on one. See [ADR 0048](adr/0048-release-branch-staging-strategy.md) D5.
