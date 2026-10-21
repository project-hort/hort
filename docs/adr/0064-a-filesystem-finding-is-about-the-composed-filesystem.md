# 0064 — A filesystem finding is a finding about the composed filesystem

- **Status:** Accepted
- **Amends:** [0007](0007-fail-closed-quarantine-release-predicate.md) — an
  image manifest leaves its "no package surface by construction" list, the
  reason given for the rootfs-empty mapping is replaced (the mapping itself
  stands), and the code-level definition of a non-gating abstention becomes
  `NotAnalysable::gates_release` answering `false` rather than the
  `NotApplicable` variant alone, since `UnsupportedContainer` joins it on a
  constituent under a promoted composite verdict. [0043](0043-oci-image-index-support.md) — its per-layer
  consumption-safety argument becomes per-composition on the filesystem axis;
  the conclusion is unchanged. Both ADRs carry the amended text in place.
- **Enforced by:** the composite scan unit's completeness precondition — a
  manifest with an unresolved constituent receives no verdict — and
  `Finding::may_condemn_artifact` / `NotAnalysable::gates_release`, the two
  predicates that carry the per-axis split of release authority described in
  D2. Both are in place. Which side of D2's line a finding is on is
  `FindingStatement`, assembled by the two layers that each know one half: the
  scanner adapter states the report section it read, and the application layer
  places that claim against the artifact's kind. That it is answered in one
  place is held by
  `crates/hort-app/tests/condemning_rule_is_single_sourced.rs`.
- **Relates to:**
  [0039](0039-keyed-provenance-verification.md) §11 (the subject → constituent
  cascade, examined and not mirrored) ·
  [0062](0062-never-advertise-what-you-will-not-serve.md) (closure withholding,
  unchanged — and the conflict a per-layer filesystem verdict creates with it
  disappears under this decision) ·
  [0054](0054-content-level-age-evidence-anchors-quarantine.md) (quarantine
  anchoring, untouched and no claim made on it).

## Context

Every OCI row is scanned on its own: a layer as a root filesystem, a manifest
and a config as "not applicable". That is defensible per row and wrong about
the thing an operator runs.

The gap was measured, not inferred. On a real multi-layer image, the base layer
carried `/etc/os-release` and produced 240 findings; the next layer carried a
**complete package database with 25 more packages** and produced **zero**,
because without an OS marker in that same layer the scanner recognises no
operating system and never runs the package check. Both scans ran in the same
pass, 0.5 s apart, against the same advisory data. Twenty-five packages
carrying 92 advisories were never assessed. That image was rejected anyway — by
accident of provenance, because the vulnerable package happened to be
*inherited* rather than *installed*. An ordinary `RUN apt-get install` of the
same vulnerability would have passed.

Two written premises stand behind that, and the measurement refutes both.

**A module-level derivation**
(`crates/hort-adapters-scanner-trivy/src/workspace.rs:26-27`):

> *"Hort has no container image to scan, so the choice for every row is
> `rootfs` or `fs`."*

Hort holds the manifest, the config and every layer, and the manifest bytes
name them in order. The material has always been present; it was never
assembled.

**And a clarification in [ADR 0007](0007-fail-closed-quarantine-release-predicate.md)**:

> *"a `rootfs`-target scan that comes back empty is 'not applicable', not
> unassessed. Trivy's `rootfs` target runs every OS-package, language and
> binary analyzer over the *whole* materialised tree, so an empty result there
> is those analyzers agreeing the tree carries no package surface at all."*

The justifying sentence is false. The OS-package analyzer does **not** run over
a tree that carries a package database but no OS marker — it is skipped for
want of an identity. The code implements the clarification faithfully
(`crates/hort-adapters-scanner-trivy/src/lib.rs:570,606-608`;
`NotApplicable` does not gate, `crates/hort-domain/src/ports/scanner.rs:68-76`),
so a package-bearing layer with no identity reaches release as a completed
"not applicable" — measured, not inferred: a fixture layer carrying a
three-package dpkg database and no `/etc/os-release` produces `Metadata.OS:
none` and **zero `Results` entries**, which is exactly the branch that maps to
the non-gating `NotApplicable`.

**The constituents are not necessarily local.** A manifest's digest binds the
*references*, not hort's possession of the bytes. Pull-through registers digest
edges with no existence check — `crates/hort-http-oci/src/manifests_write.rs:2088`
says so in as many words — and blob warming is best effort.

### The composed-image scan is the industry norm; the per-layer-only model is ours

This decision is new to *hort's* record, not to the field, and the ADR should
not read as if it were. Scanning the assembled image is what every comparable
tool does: `trivy image` (including `--input` against a local OCI layout) is
Trivy's primary mode and `rootfs` its secondary one, and Grype, Clair, Docker
Scout, Snyk and Anchore all assess the composed image. Registry-side scanning
works the same way — Harbor, Quay, ECR, GCP Artifact Registry and ACR all scan
per image manifest. Per-layer *attribution* of a finding is common and is
exactly what D4 below specifies; a per-layer *verdict as the only assessment*
is not a pattern any of them use.

Two things follow. The unit choice needs no justification from novelty — it is
the ordinary one, and hort arrived at the unusual one through a module-level
derivation rather than a decision. And where hort stays unusual on purpose —
it gates individual blob pulls, which registry scanners generally do not — the
accepted residual under *Consequences* is the price of that strictness, not a
hole in the standard model.

### Why this is a new decision and not an amendment

[0039](0039-keyed-provenance-verification.md) §11 and
[0062](0062-never-advertise-what-you-will-not-serve.md) both already derive a
*parent's* property from its constituents' — a clearance that flows down, a
terminal status that withholds upward. Both are faithful to the same shape: the
parent is a function of its parts.

A filesystem finding is the first axis where that shape does not hold. The
package set of a composed image is **not** a function of its layers'
individually assessed package sets: a later layer adds packages the earlier one
cannot be read for, and removes packages the earlier one carries. No
composition of per-constituent verdicts reconstructs it. That inversion is what
no existing decision covers, and it is why this is an ADR rather than an
amendment to one.

## Decision

**The unit of filesystem assessment for an OCI image is the image manifest. A
constituent's isolated scan produces evidence; the composition produces the
verdict.**

**D1 — The image manifest is scanned as a composed image.** It is materialised
as an OCI layout from its config and its ordered layers and handed to the
scanner as one image.

The constituent set and its order come from the **manifest bytes in CAS, never
from the `content_references` edges** — the same source
[0039](0039-keyed-provenance-verification.md) §11 and
[0062](0062-never-advertise-what-you-will-not-serve.md) already chose for the
same reason ("edges nominate and the bytes decide"), with the manifest bytes
additionally carrying the **order**, which the edges do not store at all. That
much is derived, not newly decided.

The **parse must be strict**, which the existing primitive is not:
`manifest_blob_refs` silently skips a descriptor whose digest is absent,
malformed, or not SHA-256 (`crates/hort-domain/src/oci.rs:405-412,462-479`).
For a clearance cascade that is the safe direction — a skipped constituent is
one that does not get cleared. For a scan input it is the dangerous one: a
strict subset would be analysed and reported as the image. Every declared
descriptor is accounted for, unknown media types are named rather than dropped,
the config's `rootfs.diff_ids` are checked against the layer set, and foreign /
non-distributable layers are an explicit withhold.

**Completeness is a precondition of a verdict, and the two repository kinds
reach it differently.** On a **hosted** push nothing extra is needed: the PUT
path already refuses a manifest whose config or layers do not resolve to a
deliverable same-repo row (`MANIFEST_BLOB_UNKNOWN`,
`crates/hort-http-oci/src/manifests_write.rs:55-69`), which is the OCI push
order the spec requires — blobs first, manifest last. Every constituent is in
CAS at the moment the manifest commits, so the composite scan fetches nothing.

On a **pull-through** manifest hort must acquire the constituents itself. Its
layers are registered by digest with no existence check, deliberately
(`crates/hort-http-oci/src/manifests_write.rs:2088-2098`), and the client pull
that would warm them begins with the manifest the verdict gates. So for proxy
repositories — and only there — hort fetches layers no client has asked for.

A constituent that is missing, unreadable, of an unsupported media type, or
over the whole-image budget yields **no verdict** — never a partial layout,
never a clean verdict over a subset. A returned report is not by itself evidence that the expected
inventory was examined, and an incomplete composite must not be laundered by a
second backend's success: today the fail-closed partition is reached only when
*no* backend produced a verdict
(`crates/hort-app/src/use_cases/scan_orchestration.rs:613-620`).

**No verdict and no further attempt are different things, and acquisition is
what makes the difference load-bearing.** This applies ADR 0007's standing
distinction — a scan that could not be carried out leaves the artifact where it
was and is tried again, rather than becoming a statement about the artifact —
to the axis that did not yet have it. While nothing fetched, every unassembled
composition could take one non-retryable value, because the only causes
available were statements about the image: it declares more constituents
or more bytes than hort will assemble, or a constituent is simply not here.
Acquisition adds causes that are about *availability* — an upstream that is
down, rate-limiting or slow; a storage backend that does not answer — and for
an estate that proxies those are the routine case, not the exception.
Collapsing them into the same value as "this image is 40 GiB" is wrong in the
direction that matters: it turns a momentary hiccup into a permanent-looking
absence of assessment, and an absence of assessment is what the release gate
reads. So the refusal carries which of the two it is:

- **Deterministic**, no further attempt — over the byte budget, over the
  constituent count, a repository with no configured upstream to acquire from,
  a digest the upstream does not have, bytes that fail verification, a
  constituent still absent once acquisition has run, an unsupported layer
  media type. Re-running reads the same facts.
- **Transient**, retried — the upstream was unreachable, timed out,
  rate-limited or returned a retryable status; storage did not answer; a phase
  exceeded its wall clock. Re-running may well succeed.

A transient refusal is routed through the path the scan job **already** has for
a retryable backend failure, and that job's existing attempt budget is its
bound: a transient classification never means unbounded attempts, and no
parallel retry mechanism exists. Exhausting the budget lands back on the
deterministic outcome — still no verdict, and now also no more tries — so the
composite path can never reach the retry-exhausted arm that transitions an
artifact, which is what keeps it free of release authority (D6). The
classification is read off the upstream port's own error vocabulary and off the
typed storage error, never off a rendered message.

**D2 — A constituent's isolated filesystem findings are evidence, not the
verdict.** The layer scan keeps running and keeps recording what it sees; what
changes is that its filesystem findings no longer carry release authority for
the layer. [ADR 0007](0007-fail-closed-quarantine-release-predicate.md) already
separated those two things — *"findings are evidence, the verdict is the
decision"* — and this decision answers the question that amendment left open
for composed artifacts: **whose** policy verdict decides. For a filesystem
finding, the composition's.

The argument is that per-layer condemnation has no remaining benefit once D1
exists, and one concrete harm. Benefit: every package in the composed image is
already caught by the composite scan — strictly more than the per-layer scans
caught, which is the measurement. Harm: a package an upper layer deletes
condemns the lower layer, and
[0062](0062-never-advertise-what-you-will-not-serve.md) then withholds a
manifest whose composite verdict is clean
(`crates/hort-app/src/use_cases/manifest_deliverability.rs:206-234`). Keeping
both verdicts means keeping a disagreement in which the wrong one wins.

**Scope: only statements whose truth depends on the composition move.** The
line is whether what the scan says is about *the bytes* or about *the resulting
filesystem*, and it governs the **absence** of an assessment exactly as it
governs a finding. "I have no decoder for this container" is not a statement
that the layer's bytes are dangerous — the composition decodes them, and
`tar+zstd` is the measured case — so it belongs to the composition and must not
gate the constituent. "This archive tripped an extraction bound" or "an entry
tried to escape the workspace" *is* about the bytes and keeps gating. Today
both reach `NotAnalysable::UnusableArchive`
(`crates/hort-adapters-scanner-trivy/src/workspace.rs:739-741,674`), which
gates, so a `tar+zstd` layer is terminal standing alone and
[0062](0062-never-advertise-what-you-will-not-serve.md) withholds every image
binding it — including one this decision's composite scan reads without
difficulty. Separating those two reasons is part of making D2 take effect, not
a later tidy-up.

On the finding side the same line runs: "this blob carries a leaked key" or
"these bytes are malware" is true of the layer however it is composed, and such
a finding keeps gating its own artifact. "This package is installed and
vulnerable" is true only of a composed tree, and moves. Today every finding
class hort consumes is of the second kind — the report parser reads only
`Vulnerabilities`
(`crates/hort-adapters-scanner-trivy/src/parse.rs:72`) — so D2 currently moves
all of them; the line is drawn now so that a later secret or malware backend is
not silently disarmed by this decision.

The layer's own release is unchanged and needs **no new authority**: it still
releases on its own `ScanCompleted` under authority 1, exactly as today. ADR
0007's release predicate is untouched by this decision.

**D3 — A layer's OS identity comes only from that layer's own verified
bytes.** Never borrowed from a referencing manifest, a sibling layer, a
repository default, or the first image that happened to reference it. What is
stored is the identity's **evidence and confidence with the scan**, never an
image-derived identity written onto the layer row. This follows from the
decision above — a borrowed identity would make the layer row assert something
about a composition it is not — and it is stated separately because it
forecloses the one shortcut that looks cheaper than D1: seeding
`/etc/os-release` into a layer's scan workspace from the layer that has it.

**D4 — The composite verdict stays on the manifest.** Each finding records the
constituent digest and path it came from, as attribution, without changing that
constituent's status. [0039](0039-keyed-provenance-verification.md) §11's
cascade does not transfer: it cascades a *clearance* whose signature covers the
exact bytes of every constituent, and clearing is monotone where condemning is
not. Under D2 there is in any case no per-constituent filesystem verdict left
for a cascade to overwrite.

**D5 — For an image index, each platform manifest is a scan unit; the index
carries no composite finding and retains its not-applicable assessment.** An
index binds references, not a runnable filesystem
([0043](0043-oci-image-index-support.md)), so there is nothing to compose. Its
own generic-manifest lifecycle, including its own scan assessment and release
authority, is unchanged.

**D6 — Order the rollout, and let the operator promote it.** Two different
hazards, two different controls.

*The loosening direction needs ordering.* D2 removes a condemnation that is
blocking images today. If it lands before the composite verdict carries
authority, an image becomes pullable with nothing having assessed it. So a
constituent's filesystem findings may stop gating **only under a policy that
has promoted the composite verdict** — the loosening follows the authority and
never precedes it.

That condition is about the **policy**, not about a per-constituent lookup to
the manifests above it, and the difference matters in both directions. For a
layer of an image it is the same statement: under a promoted policy a manifest
is either assessed or held, so there is no promoted, deliverable image whose
filesystem went unexamined, and the obligation has somewhere to move to. For a
blob that is **not** part of an image — an OCI artifact's layer, or a blob
nothing in the registry references — nothing takes the obligation over, and
nothing should. A package-vulnerability finding is a statement about an
installed package tree that runs; such a blob has none, so a finding read out
of it is a statement about nothing. hort assesses it today only because every
tar-shaped blob is materialised as a root filesystem — correct for an image
layer, a coincidence for anything else, and a gate that fires only when an
artifact happens to be a tar *and* happens to contain a manifest some analyzer
recognises is not a control. The loosening removes a coincidence, not a
safeguard.

A per-constituent walk to the binding manifest would also not deliver what its
wording promises. On a push the layer blobs are ingested, and their scans
enqueued, before the manifest exists; the walk would find no parent for the
whole push population, hold the layer, and reinstate exactly the terminal hold
this decision exists to remove — non-deterministically, by job ordering.

*The tightening direction needs an operator.* A composite verdict adds
rejections across an existing estate — on the measured image alone, 92
previously unassessed advisories. The reason it must be readable before it is
enforcing is not the finding count: `Rejected` is terminal and **the periodic
rescan never revisits it** — the candidate queries admit `released` / NULL and
`quarantined` only
(`crates/hort-adapters-postgres/src/rescan_candidates.rs:124-125,256`) — so a
wrong verdict from a new analysis path on its first production run leaves an
estate only an explicit operator re-evaluation can recover. A new pipeline
whose first act can be irreversible is the thing to avoid; the rejections
themselves are the point.

It is therefore a **manifest-scoped shadow assessment carrying no release
authority**, promoted by the operator against named criteria: baseline
completion and coverage, error and indeterminate rates, incremental findings
and the images they affect, false-positive review, and capacity.

**Constituents already terminally rejected on filesystem findings are not
un-rejected automatically.** D2 governs what a *new* assessment gates; it does
not reach a row whose verdict is already terminal, and the periodic rescan does
not revisit `Rejected`. Recovering the existing estate is operator-driven,
through the curation re-evaluation
(`POST /api/v1/admin/curation/quarantine/{artifact_id}/reevaluate`,
`crates/hort-http-core/src/handlers/admin/curation/mod.rs:70-75`) — and it is
right that it is: automatically un-rejecting a population with no fresh
assessment is exactly the hazard that disqualified `ScanEnforcement::Record`
below. The same ordering applies as for the loosening direction: a constituent
is re-evaluated only once the manifests binding it carry a completed composite
assessment.

**Already-released manifests need no backfill mechanism.** The rescan candidate
query filters on status and staleness and has no kind or media-type predicate
(`crates/hort-adapters-postgres/src/rescan_candidates.rs:100-140`), so a
released manifest is already in the pool: its next ordinary rescan runs the
composite. Building a backfill would be a second mechanism for what the
existing one does, and the verdict carries no authority until promoted
anyway.

Explicitly **not** `ScanEnforcement::Record`. That is a resolved policy-scope
mode, not a manifest-scoped observation setting: it withholds `ArtifactRejected`
for every blocking verdict in its scope, and switching a scope from `reject` to
`record` re-evaluates the already-rejected population to released with no
rescan — a test pins exactly that
(`crates/hort-app/src/use_cases/policy_use_case.rs:6084-6124`). Using it here
would release the images quarantine had correctly rejected in exchange for
observing the new ones.

## Consequences

- **The false positive is removed for everything assessed after promotion.** A
  package a later layer deletes no longer condemns anything: the layer's
  finding is evidence and the composition it is absent from is clean. The
  **existing** rejected estate is not swept along — `Rejected` is terminal and
  the rescan does not revisit it, so those manifests stay withheld until an
  operator re-evaluates the constituent (D6). The claim is about new
  assessments, not about yesterday's.
- **Accepted residual: a file that a composition removes is still served in the
  raw layer blob.** Under D2 that blob is no longer refused for it. The bytes
  are not runnable on their own, and any composition hort holds is itself a
  scan unit under D1, so the exposure is to a client who addresses the blob by
  digest and composes it outside hort — the same boundary ADR 0043's per-layer
  argument always had. Closing it would require the blob request to carry image
  context, which the OCI protocol does not give it
  (`crates/hort-http-oci/src/blobs.rs:433-446,608-620`). This is a decision,
  not a gap.
- **ADR 0007's release predicate is untouched.** No eighth authority, no
  cross-stream release: a layer still releases on its own `ScanCompleted`.
- **Fewer hosted pushes are refused at the boundary.** The PUT path rejects a
  manifest whose constituent sits in a terminal state
  (`crates/hort-http-oci/src/manifests_write.rs:60-63`). Under D2 a layer is no
  longer terminalised by a filesystem finding, so a push that fails today with
  `MANIFEST_BLOB_UNKNOWN` because of a condemned base layer succeeds and the
  manifest receives its own composite verdict — which is the right place for
  the refusal to be decided.
- **The same package now appears on a constituent row and on the image row,
  and it is counted once.** D2 settles which: release-relevant aggregates are
  taken from the verdict-bearing artifact — the manifest — and a constituent's
  rows are evidence reachable from that finding's attribution, never a second
  observation. Counting both would report one image's one vulnerability as
  two, and the per-scan deduplication in
  `crates/hort-app/src/use_cases/scan_orchestration.rs` is within a scan, not
  across artifact rows.
- **A composite scan reads every layer of an image rather than one blob.** For
  a hosted push the bytes are already in CAS, so the cost is reading them; for
  a cold pull-through manifest hort additionally fetches them from upstream
  before any client asks. The whole-image byte, entry, disk and time budget is
  a new bound; today's 8 GiB copy and 4 GiB extraction limits are per artifact.
- **Quarantine anchoring is neither lengthened nor shortened**, and this
  decision makes no claim that a manifest's age measures its composition's
  exposure — a manifest seen long ago can have constituents fetched today.
  Whether a parent's window is an adequate proxy when its constituents are
  younger is a pre-existing question for
  [0054](0054-content-level-age-evidence-anchors-quarantine.md), neither
  introduced nor answered here.

## Amendments this decision carries

Both are applied in place in the amended records; they are listed here so a
reader of this decision knows what moved with it.

1. **[ADR 0007](0007-fail-closed-quarantine-release-predicate.md), §"The scan
   axis covers artifacts with a scannable surface"** — an OCI image manifest
   leaves the "no package surface by construction" list: it has the only
   package surface that describes what runs. And the rootfs-empty
   clarification's justification is replaced: an empty `rootfs` report is not
   the analyzers agreeing there is no surface, it is a surface whose assessment
   belongs to the composition. The mapping itself stands — without it a layer
   never reaches a release authority of its own — and no eighth authority is
   added. Third, the code-level definition of a non-gating abstention becomes
   `NotAnalysable::gates_release` answering `false` rather than the
   `NotApplicable` variant alone: `UnsupportedContainer` joins it on a
   constituent under a promoted composite verdict, for the same
   "assessed elsewhere" reason, so the predicate now reads the artifact's
   kind and the resolved `compositeVerdictMode` alongside the reason.
2. **[ADR 0043](0043-oci-image-index-support.md)** — its per-layer
   consumption-safety argument becomes per-composition on the filesystem axis,
   and its "degenerate but consistent with how single-image manifests are
   already scanned" comparison is corrected: that is now true only of an index.
   The conclusion survives — each platform child is a composition and is gated
   as one.

## Not decided here

- **Whether the same reasoning holds for the other formats.** An installed npm
  or Python tree is also a composition that hort never assembles, so the
  question has the same shape — but the analysis unit differs per format and
  the measurement behind this decision says nothing about them. Out of scope
  deliberately, not by omission.
- **Whether a parent's observation window is an adequate exposure proxy when
  its constituents are younger** — pre-existing, belongs to
  [0054](0054-content-level-age-evidence-anchors-quarantine.md), neither
  introduced nor worsened here (see *Consequences*).
- **How large the composite actually is.** Measurement 3 below — cold
  pull-through timing, whole-image size and entry counts, scan time, scratch
  disk, worker concurrency — is open and needs a real image; the fixtures that
  settled measurement 1 were synthetic and small.

## Alternatives considered

**Plant the OS marker into each layer's workspace.** Rejected: it needs the
same cross-artifact read as D1, and it makes the layer row assert an identity
no scan of those bytes established (D3).

**Mirror [0039](0039-keyed-provenance-verification.md) §11's cascade onto the
scan axis.** Rejected under D4.

**Add the composite verdict and keep the per-layer filesystem verdict.**
Rejected — this was the first draft of this ADR. It leaves two verdicts that
can disagree about the same image with the wrong one winning, keeps clean
images unpullable, and pushes the resolution into a later decision about
contextual blob authorization that D2 makes unnecessary.

**Ship under `ScanEnforcement::Record`.** Rejected under D6: it un-rejects the
population it is pointed at.

## To be measured before implementation

1. ~~Against the deployed Trivy version: a real ordered OCI layout versus
   isolated `rootfs` scans, over package installs, removals, whiteouts and
   opaque whiteouts.~~ **Measured 2026-10-19 against Trivy 0.70.0, the pinned
   version (`docker/Dockerfile.worker`); the materialisation D1 chose is
   sound.** On a hand-built OCI layout, `trivy image --input` applies layers in
   manifest order, resolves whiteouts (`.wh.<name>`) and opaque whiteouts
   (`.wh..wh..opq`), and derives the OS identity from the **composed** tree: a
   two-layer fixture whose upper layer carried a three-package dpkg database
   and **no** `/etc/os-release` reported `debian 12.5` and all three packages,
   while that same upper layer scanned alone as a `rootfs` reported
   `Metadata.OS: none` and **zero `Results` entries**. A later layer that drops
   a package from the database, deletes it by whiteout, or hides the directory
   by opaque whiteout removes it from the composite inventory in all three
   shapes. The scanner composed `tar`, `tar+gzip` and `tar+zstd` layers
   identically, and it decides by **content** rather than by the declared media
   type: a layer declaring an unrecognised type but carrying plain tar bytes
   composed normally, while one declaring `tar+gzip` over bytes that were not
   gzip failed the whole run rather than returning a short inventory.
2. How many currently-rejected artifacts are layers condemned for a package
   their composition removes — the size of the false positive D2 retires.
3. Cold proxy manifest-to-blob timing, missing-blob frequency, whole-image size
   and entry counts, scan time, scratch disk and worker concurrency under
   bounded worst cases.
4. Blob-first-then-manifest, a layer shared across two compositions with
   different OS contexts, unsupported compression and media types, and a
   successful secondary backend alongside an incomplete composite.
