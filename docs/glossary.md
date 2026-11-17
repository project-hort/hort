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

### Catalog weight (`live_primary_content_bytes`)

What a repository's **served catalog** weighs: `size_bytes` summed over
the *distinct* contents its live artifact rows name, each content counted
once however many rows name it. Reported per repository by
`GET /api/v1/admin/inventory`, and named at length because it is **not**
disk usage. It is not additive across repositories (one stored content
can be held by several of them, so adding the figures double-counts it
and there is no per-repository physical ownership to report instead), it
omits CAS-resident metadata and every other kind of referenced content,
and it is not reclaimable space (a deleted artifact leaves the figure
while its bytes stay resident until refcount-gated collection). Compare a
repository against itself over time — that is what a retention
before/after needs; do not plan capacity with it. The distinctness is on
the **hash**, never on the size: two different contents can be exactly
the same length. See [Rows are not bytes](#rows-are-not-bytes),
[ADR 0054](adr/0054-content-level-age-evidence-anchors-quarantine.md) and
[using-hort-cli-with-admin-ops.md](architecture/how-to/using-hort-cli-with-admin-ops.md).

### Closed

The terminal state of an issue. Issues auto-close only on merge to the
default branch (`main`) — a final release's promotion MR closes every
issue whose fix already rested in `ready-for-staging` or `in-uat`, often
many at once. See [ADR 0048](adr/0048-release-branch-staging-strategy.md) D5.

### Composed filesystem (of an OCI image)

The filesystem an operator actually runs: the image's layers applied **in
manifest order**, with each layer's additions overlaying what is below it and
its whiteout markers removing entries from it. It is the subject of a
filesystem finding, and it is not reconstructible from the layers assessed
individually — a later layer both adds packages an earlier one cannot be read
for and removes packages an earlier one carries. See
[ADR 0064](adr/0064-a-filesystem-finding-is-about-the-composed-filesystem.md)
and [Layer chain ID](#layer-chain-id-chainid).

### Composite verdict mode (`compositeVerdictMode`) — retired

A former `ScanPolicy` field (`compositeVerdictMode: observed | promoted`)
deciding whether a composed OCI image's scan verdict decided its
**manifest's** release. It is **retired**: the composed verdict now decides
unconditionally, and a policy envelope declaring either value is refused at
gitops apply. `observed`, the shipped default, withheld that authority —
which left the composition assessed and recorded while deciding nothing, and
a constituent hort could not analyse in isolation holding its manifest with
no deadline and no authority that could ever clear it. What `promoted`
granted is what the pipeline now does for every policy: the composition's
findings **are** the manifest row's and reach the release gate under the
ordinary predicate, a composition that could not be produced is an absent
verdict that holds the manifest `scan_indeterminate`, an image index and an
artifact manifest stay non-gating for want of a composition to gate on, and
an OCI blob's own filesystem findings no longer decide its release. See
[ADR 0064](adr/0064-a-filesystem-finding-is-about-the-composed-filesystem.md)
D2, the migration notice in
[`CHANGELOG.md`](../CHANGELOG.md), and
[*The composed image is the scan unit*](architecture/explanation/scanning-pipeline.md#the-composed-image-is-the-scan-unit).
Distinct from [enforcement mode](#enforcement-mode), which decides what a
blocking verdict *does* and is **not** retired.

### Curator (`Permission::Curate`)

The domain's decision authority over held artifacts: waiving a hold,
blocking an artifact, re-evaluating one, and managing finding exclusions.
Distinct in *kind* from `Permission::Admin`, which carries the technical and
operative actions (gitops status, effective config, the provenance-misrejection
repair) — a verdict about an artifact is a curation decision, a structurally
invalid state being withdrawn is not. `Admin` is a superset of `Curate` at the
gate (`CurateOrAdminPrincipal` admits either), so an admin never needs an
explicit curate grant.

**A curator is not necessarily an IdP user.** The sanctioned shape of a
maintainer's named curator credential is a PAT-only `kind: ServiceAccount` with
a standalone `curate` grant (`maintainer-curator` in the deployed gitops
config), so `TokenKind::ServiceAccount` does **not** mean "a pipeline". What
keeps automation out of domain decisions is the grant an operator does *not*
make — [ADR 0055](adr/0055-write-authorized-hold-read-generalised.md) rejected a
`curate` grant for CI — not a token-kind check.

### Enforcement mode

A `ScanPolicy` field (`enforcement: reject | record`) deciding what a
**blocking scan verdict does** to the artifact — as distinct from the
knobs that decide *which* findings are blocking (`severityThreshold`,
`negligibleAction`; **not** `licensePolicy`, which decides nothing and
is refused at apply — see
[the linter-row matrix](architecture/reference/apply-time-linter-rows.md)). Under `reject` (the default, and
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
existing population in both directions. Orthogonal to
[composite verdict mode](#composite-verdict-mode-compositeverdictmode),
which decides *whose* analysis the blocking verdict came from — and which
`record` does not fully disarm: `record` withholds a transition over a
finding list, and a promoted composition's *absence* has no finding list,
so it still holds the manifest. See
[ADR 0007](adr/0007-fail-closed-quarantine-release-predicate.md) and
[ADR 0041](adr/0041-continuous-scan-policy-enforcement.md), and
[declare-gitops-config.md](architecture/how-to/declare-gitops-config.md)
`kind: ScanPolicy`.

### Filesystem finding (vs. byte finding)

The line that decides **which artifact's verdict a scan finding feeds**. A
*byte* finding is a statement that holds of the bytes however they are
composed — a leaked key, malware — and keeps condemning the artifact it was
found in. A *filesystem* finding is a statement about a composed tree — "this
package is installed and vulnerable" — and is carried by the
[composed filesystem](#composed-filesystem-of-an-oci-image), not by the layer
it was observed in; on the layer it is **evidence**, with the constituent
digest and path recorded as attribution. Today every finding class hort
consumes is of the second kind.

Each finding carries which kind it is, in memory only, assembled by the
two layers that each know one half: the scanner adapter states which
section of its report the finding came out of, and the application layer
places that claim against the artifact's role (its format handler's
artifact kind) — so a layer's filesystem claim is distinguishable from
a composed image's. The claim loses its authority over a layer only
where the policy's
[composite verdict mode](#composite-verdict-mode-compositeverdictmode)
has promoted the composition's verdict; a finding read back out of the
stored findings blob states nothing and keeps the authority it has
today, which is what keeps the loosening away from the already-rejected
estate. See
[ADR 0064](adr/0064-a-filesystem-finding-is-about-the-composed-filesystem.md)
D2, D4 and D6.

### Global grant

A `PermissionGrant` whose `spec.repository` field is omitted, so it
authorizes its `permission` across every repository the deployment
serves rather than one named repository — the RBAC evaluator treats a
grant with no repository scope as matching every scope checked against
it. See [declare-gitops-config.md](architecture/how-to/declare-gitops-config.md)
`kind: PermissionGrant`.

### Held set (held pending signature)

The artifacts the release gate is holding **because an attestation it
requires has not arrived**: `quarantined`, past the end of their
observation window, under an effective `provenanceMode: required`, with
no verified attestation recorded. A repository that resolves no policy
has no deadline, so its artifacts are not in the set.

Distinct from the three populations it is routinely confused with: an
artifact still *inside* its window (young, not held), a `Rejected`
artifact (a terminal verdict on the scan, curation or provenance axis —
see [Terminal](#terminal-quarantine-status)) and a
`scan_indeterminate` one. The hold is **indefinite** by decision: no
timer resolves it, because no value a timer could carry is better than
"wait". That decision is argued on the ground that the set and *its
age* are visible, which is what the held-set overview
(`GET /api/v1/admin/retention/{overview,held}`) exists to be. Split for
operator action into the two
[held-set buckets](#held-set-bucket-constituent--in-own-right). See
[ADR 0039](adr/0039-keyed-provenance-verification.md) D4 and
[curator-workflow.md](architecture/how-to/curator-workflow.md) §10.

### Held-pending-signature candidate

One row of the held-set **aggregate**, and the name is a precision
rather than a hedge. The aggregate resolves the policy and the window
expiry in SQL and stops: the provenance clearance verdict has exactly one
implementation in hort, and a second copy inside a counting query is how
two computations of one rule drift apart. So the count is a declared
**superset** — it can include an artifact cleared moments ago and not
yet swept — and the API field, the query and the docs all say
`held_pending_signature_candidates` rather than naming it as the gate's
decision. The drill-down beside it resolves every row through the one
authority and *is* exact. See
[curator-workflow.md](architecture/how-to/curator-workflow.md) §10.3.

### Held-set bucket (`constituent` / `in_own_right`)

The two halves of a repository's [held set](#held-set-held-pending-signature),
split because the operator action differs rather than for presentation.
A **`constituent`** is a config or layer blob whose only inbound
`content_references` edges are its parent manifest's: a blob cannot carry
its own attestation, so there is nothing to wait for on that row and the
thing to fix is the parent. An **`in_own_right`** artifact could still
acquire an attestation of its own. The rule has one definition in Rust
(`is_parent_gated_blob_constituent_kinds`), whose two kind lists reach
the aggregate as query parameters so SQL forms only the boolean; a
DB-backed parity test drives both paths over the same kind sets. Not the
same concept as a [signature constituent](#signature-constituent), which
is a blob of a *signature* manifest. See
[ADR 0039](adr/0039-keyed-provenance-verification.md) and
[curator-workflow.md](architecture/how-to/curator-workflow.md) §10.1.

### In-UAT

A resting state for an issue whose fix is in User Acceptance Testing on
staging, decoupled from a `main` release cut. Entered only once an alpha tag
has been cut whose commit is confirmed (`git merge-base --is-ancestor`) to
contain the issue's merge — not merely once some alpha exists. See
[UAT](#uat) and [ADR 0048](adr/0048-release-branch-staging-strategy.md) D5.

### Indeterminate provenance

A provenance verdict that **could not be carried out** — the trust root
held no usable key, the attestation material was never obtained, or a
dispatched verifier returned no verdict
(`ProvenanceOutcome::Indeterminate`, with one `IndeterminateReason` per
cause). Nothing about the artifact was established, so nothing was
disproved and nothing may terminalise: under `provenanceMode: required`
the artifact is **held** `Quarantined` (reported `held_indeterminate`),
and under the permissive modes it runs its normal window and releases
(reported `allowed_indeterminate`). The failure is on *hort's* side,
which is the whole reason the state exists — a publisher's artifact must
not go terminal because an operator misprovisioned a key or a network
call failed. See [ADR 0039](adr/0039-keyed-provenance-verification.md)'s
2026-10-14 amendment, D9/D11.

**It is not `ScanIndeterminate`, and the two must not be read as a pair.**
Different axis (provenance vs. scan), different verdict: an indeterminate
*provenance* verdict writes no status at all — the artifact keeps whatever
hold it was in — while `ScanIndeterminate` is one of the two
[terminal](#terminal-quarantine-status) quarantine statuses, so an artifact
in it is neither delivered nor advertised. Both are held rather than
concluded, and both are lifted by the axis reaching a verdict rather than
by a clock. Neither implies the other, and an artifact can be in one,
both, or neither. The `held_` /
`allowed_` prefixes on the provenance reporting values are what keep the
two apart in an operator's dashboard; the shared word is an accident of
English, not a shared concept.

### Layer chain ID (`chainID`)

The OCI image spec's identifier for a filesystem **state**, as distinct from a
layer: `chainID(n) = sha256(chainID(n-1) + " " + diffID(n))`, with a single
layer's chain ID being its own `diffID`. It exists because a filesystem state
is identified by an **ordered prefix** of layers, not by a layer — which is
the spec's own statement that a layer blob, although it exists independently
and may appear at a different position in another image, does not *function*
independently. Container runtimes key their local storage on it. Cited in
[ADR 0064](adr/0064-a-filesystem-finding-is-about-the-composed-filesystem.md).

### Manual release

An `ArtifactReleased` a human authorized — `released_by ∈ {Admin, Curator}` —
as opposed to an **automatic** release, where the system did:
`Timer` (the observation window elapsed and the axes cleared) or
`PolicyReEvaluation` (a policy change re-judged the stored evidence). The
partition is load-bearing rather than descriptive: a manual release carries
`released_by_user_id` + a justification (≤ 512 bytes, mandatory) and outweighs a
later blocking scan verdict, while an automatic one is re-blocked by it.
`PolicyReEvaluation` counts as automatic deliberately — the policy did not
absolve the artifact, it re-judged it under the evidence of the day.

Curation re-blocks either kind: the protection is scan-axis-wide, not
axis-wide.

A manual release is bounded by what the curator's instrument can reach, not by
severity. Comparing an artifact's content hash against the publisher's own
release page answers the question a signature answers, so a curator may release
across the scan, curation and provenance axes — including a missing or
disproved signature. It cannot reach a **corruption** tombstone: there the
stored bytes do not match the content hash naming them, so no external
attestation confirms anything and `VerifyingReader` fails the read regardless.

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

### Rows are not bytes

The reason every artifact-population figure hort reports carries a
**distinct-content count** beside its row count. Content is stored by
hash, so several artifact rows routinely point at one set of bytes: the
first real retention dry run on a live instance reported 3 647 rows
against 3 608 distinct contents. Neither number is reclaimable storage —
the row count is not bytes, and the distinct-content count is not bytes
you would get back either, because a held artifact's content may still be
referenced by something being kept. What a disposal would free is
answered by the content's reference count. See
[ADR 0003](adr/0003-streaming-enforced-cas.md),
[ADR 0054](adr/0054-content-level-age-evidence-anchors-quarantine.md) and
[curator-workflow.md](architecture/how-to/curator-workflow.md) §10.4.

### Scan unit

The artifact a scan verdict is **about**, which is not always the artifact
whose bytes were read. For an OCI image it is the **image manifest**: the
config and ordered layers are materialised as an OCI layout and scanned as one
image, and the verdict lands on the manifest. A layer is still scanned and
still produces findings, but on the filesystem axis those are evidence rather
than a verdict (see [Filesystem finding](#filesystem-finding-vs-byte-finding)).
An image index is not a scan unit for package findings — it binds references
and no runnable filesystem — and keeps its not-applicable assessment.
Whether the composition's verdict decides the manifest's release is the
policy's
[composite verdict mode](#composite-verdict-mode-compositeverdictmode). See
[ADR 0064](adr/0064-a-filesystem-finding-is-about-the-composed-filesystem.md)
D1, D5 and D6.

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

### Signature constituent

The blobs a **signature manifest** itself references — for cosign/Sigstore
that is the `{}` config blob and the signature payload. A signature
constituent can never acquire an attestation of its own, because nothing
signs a signature, so it is not on the provenance axis.

Under `provenance_mode: required` it is cleared instead by **the signature
that verified its subject**: at its own `provenance-verify`, an inbound
`content_references` row nominates a candidate parent, that parent's bytes
must be a pure signature manifest whose config/layer set contains this
digest, and the verifier must accept that manifest's bundle over the
subject the manifest's own `subject` descriptor names. On success the
constituent receives a real cascaded `ProvenanceVerified` whose
`cascaded_from` is the **signature manifest**. The authority is the
verifier's verdict, never the pusher's declaration — a blob has one
artifact row per `(repository, blobs/sha256:<hex>)`, so a clearance keyed
on a declaration would serve an unsigned layer to every consumer of the
repository. Every failure direction (unreadable or unparseable parent, a
parent that is not a pure signature manifest, a digest the parent's bytes
do not bind, no `subject` descriptor — the legacy tag-scheme `.sig` shape
— an unreadable subject preimage, a bundle the verifier does not accept, a
verifier error, or no candidate parent) leaves exactly the hold the
artifact already had.

Distinct from the constituents of the signed *subject* (an image's config
and layers), which inherit their subject's clearance through the two
trigger ends of the §11 cascade. See
[ADR 0039](adr/0039-keyed-provenance-verification.md) §8, §11 and D8.

### Staging

hort's test environment. It deploys from published artifacts only:
`test/*` alpha pre-release tags and `main` — never from bare `develop`
merges, since `develop` publishes no image or chart. It is not gated on a
`main` cut, but it is gated on the next (on-demand) alpha. See
[ADR 0048](adr/0048-release-branch-staging-strategy.md) D3.

### Terminal (quarantine status)

Said of an artifact hort will not deliver and will not advertise:
`Rejected` (a verdict was rendered against the bytes) and
`ScanIndeterminate` (ADR 0007's fail-closed state for a scan that reached
no verdict). Neither is exited by the passage of time — no timer releases
either, and the predicate decides what a surface may say about the
artifact, not that its case can never be reopened.

The two differ in how they are exited, and the difference is the subject
of the verdict. `Rejected` records a statement about the artifact, so its
exit is a deliberate act: the curator's manual release, or a policy loosen
that re-judges the stored findings. `ScanIndeterminate` records a
statement about hort's own coverage, so it is a **hold**: the
stranded-rescan sweep re-picks it unattended, and a verdict that is
reached supersedes the absent one — a non-blocking verdict returns the
artifact to `Quarantined` where the ordinary release sweep decides, a
blocking one condemns it to `Rejected` (ADR 0007, "A reached verdict
supersedes an absent one"). The curator's manual release reaches it too.

`Quarantined` is the contrast and is **not** terminal, even when its hold
has no self-resolving deadline (an artifact awaiting a signature, or one
whose provenance check hort could not carry out — see
[indeterminate provenance](#indeterminate-provenance)): its
evaluation is still outstanding. The distinction decides whether a
referenced blob counts as present on a manifest PUT and whether a manifest
stays deliverable. **Absence** is a third thing again: content with no
catalog row is "not local yet" — the ordinary state of a cold pull-through
reference — not a concluded lifecycle.

The one definition in code is
`hort_domain::entities::artifact::QuarantineStatus::is_terminal`, whose
rustdoc carries the derivation; it is deliberately status-only, so it never
consults the transient `provenance_hold_indefinite` flag. See
[ADR 0007](adr/0007-fail-closed-quarantine-release-predicate.md),
[ADR 0039](adr/0039-keyed-provenance-verification.md) §10 and
[ADR 0043](adr/0043-oci-image-index-support.md).

### UAT

User Acceptance Testing: manual verification on staging before a fix is
considered release-ready. An issue rests `in-uat` until a release, rather
than being blocked on one. See [ADR 0048](adr/0048-release-branch-staging-strategy.md) D5.
