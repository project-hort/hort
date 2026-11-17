# 420 — The composite is the only verdict, and only a layer is a filesystem

**Issue:** #428 · **Branch:** `agent/428-the-composite-is-the-only-verdict` ·
item 1 of 1, in **two ordered halves** that may land together but never in
the other order.

**Governing decisions:** ADR 0064 D2 (a constituent's isolated filesystem
findings are evidence, not the verdict) and **D6** (the sequencing rule: *"the
loosening follows the authority and never precedes it"*), ADR 0062 (never
advertise what you will not serve), ADR 0016 (the cross-opt-in matrix — the
linter row that moves). **This retires an operator surface, so it carries a
migration note — and it also needs an ADR amendment.** D2 is what this item
implements; **D6 is not.** D6 wrote its rule down as the per-policy posture
this item retires (*"a constituent's filesystem findings may stop gating only
under a policy that has promoted the composite verdict"*), and ADR 0007's
`gates_release` clause restates it, so the unconditional verdict contradicts
both as written. The *principle* D6 states survives untouched and the hazard it
names is closed structurally instead — row 18 refuses an OCI-scoped
`ScanPolicy` with no scan backends at gitops apply, which runs at boot — but
substituting a different mechanism for the one a decision names is an
amendment, not an implementation detail. The maintainer confirmed the change of
wording on 2026-11-10; it is ADR 0064's `## Amendment (2026-11-10, issue #428)`
section, with D6, the header summary, the ADR 0007 cross-amendment entry and
ADR 0007 §"The scan axis covers artifacts with a scannable surface" amended in
place.

## The property

**A package-vulnerability finding is a statement about an installed package
tree that runs.** A blob that is not part of an image has none, so a finding
read out of it is, in ADR 0064 D6's own words, *"a statement about
nothing"* — and hort reads one today *"only because every tar-shaped blob is
materialised as a root filesystem — correct for an image layer, a coincidence
for anything else."*

## Why the resulting hold is a defect and not protection

`manifest_deliverability.rs:88-92` explains why a **quarantined** constituent
does not withhold its manifest:

> *"It does not propagate a `Quarantined` constituent. **A hold means "not
> yet", the client's own blob fetch already answers it with the deadline**,
> and propagating it would change the answer for every fresh push …"*

The justification rests on a hold being **temporary and deadline-bearing**.
For an unanalysable layer it is permanent and deadline-less, so: **the
manifest is served, the blob refused, and the deadline never arrives.** That
is the situation ADR 0062 exists to prevent, reached through the one case
0062 deliberately does not propagate. ADR 0064 D2 names the same thing as
per-layer condemnation's *one concrete harm*: 0062 withholding a manifest
*"whose composite verdict is clean"*.

## Half 1 — `CompositeVerdictMode` is retired; the composite is always authoritative

`Observed` is the **current default** and is migration scaffolding: *"the
composed image is assessed and the assessment is recorded as an observation,
with no release authority."*

**An earlier draft of this item claimed it protects against nothing that
needs protecting. An outside review proved that false, with two concrete
counterexamples — and promotion is therefore NOT safe until both are
closed.** This is the item's central correction; the anchors are the
review's.

**(a) A non-image OCI artifact *does* reach an absent-verdict hold.** The
claim rested on *"not a composed image"* being `Settled` and never assessed.
It is — but **the classification is never reached** for these: an SBOM
referrer is accepted by the OCI PUT path and enqueued for scanning
(`crates/hort-http-oci/src/manifests_write.rs:4082-4119`), its
`application/spdx+json` layer fails the strict parser's **tar-only
media-type check** (`crates/hort-domain/src/oci.rs:600-607,1213-1236`), and
that check runs **before config acquisition**
(`crates/hort-app/src/use_cases/composite_scan.rs:261-291`) — so the
config-based non-image classification at `:447-456` never runs. The outcome
is `Deterministic`, then `Absent` under promotion, and the manifest is marked
`scan_indeterminate` when all units abstain. A mixed signature/tar referrer
is accepted and scanned too, **so a shortcut on `artifactType` or on one
layer's media type is unsafe.**

**(b) hort accepts images it can never assess.** The manifest write parser
accepts up to **1023** layers plus config
(`crates/hort-http-oci/src/manifests_write.rs:1842-1899`), while the
composition counts manifest + config + layers against a budget of **256**
(`crates/hort-domain/src/oci.rs:775-787,979-990`). A valid **255-layer**
image is therefore accepted and then refused deterministically **before the
config is read** (`constituent_acquisition.rs:404-414`). Promotion turns an
image the registry accepts into a permanently absent verdict. The same
accepted-versus-assessable gap exists at the **8 GiB** aggregate bound.

**(c) The deterministic set is larger than this item said** — it also
includes unsupported layer containers, malformed descriptors, config/manifest
arity mismatch and upstream refusal
(`composite_scan.rs:395-461`; `constituent_acquisition.rs:815-836`).
Refusing an *incomplete image* fail-closed is right; calling a producible
artifact manifest an incomplete image, or accepting an image the permanent
scan budget can never assess, is not.

**So half 1 now owes two preconditions:** classify a non-image artifact
manifest **from its config, before** the image-only layer/openability check
and before the whole-image budget refusals; and align admission with the
assessment limits. The second was a product decision and it is now taken.

### Correction: "classify from the config before the layer check" needs a seam, and the parse already names it

As written, precondition (a) cannot be done literally. The order is fixed by a
dependency: `strict_manifest_nomination` is what *produces* the nomination
(`composite_scan.rs:261`), and `acquisition.begin` + `acquire_config`
(`:266-281`) need that nomination to know which config blob to acquire. The
config therefore cannot be read before the strict parse runs — and the comment
at `:273-276` says why that order must not be reversed: *"a cold pull-through
manifest's [config] is not [here], and reading it before acquiring it is how
the composition came to be refused as unresolvable for every such manifest."*

**So the change is a seam inside the strict parse, not a reordering of the
phases.** The parse's per-layer loop (`oci.rs:1213-1241`) does two different
things in one pass:

1. **descriptor faults** — a missing `mediaType`, a non-strict digest →
   `MalformedDescriptor`. These need no config and must stay where they are.
2. **openability** — `layer_media_type_is_openable(media_type)` →
   `UnsupportedLayer` (`:1232-1237`). This is the image-only check, and it is
   what refuses an SBOM or signature referrer before anything looks at the
   config.

**The code already argues for exactly this split**, in the comment sitting
between them (`:1226-1231`): *"A descriptor fault is a statement about the
manifest; an unopenable container is a statement about what the scanner reads
out of the composed layout."* A statement about the composed layout belongs
after the config has established that a composed layout is what this artifact
*is*. Moving the openability refusal to after `complete_with_config`
(`composite_scan.rs:290`) is that sentence applied, not a new rule.

Note that the config descriptor is parsed **before** the layer loop
(`oci.rs:~1195-1211`), so the nomination has everything acquisition needs
without the openability verdict — which is what makes the seam cheap.

**Acceptance stays as written**; this fixes only the instruction, which named
an impossible order. The run must still show the two referrer shapes reaching
neither an assessment nor a hold.

### Maintainer decision (2026-11-09): refuse at admission

Asked which way the 255-layer and over-8-GiB cases go — assess them, or
refuse them at admission — the maintainer chose **refuse at admission**:
*"A"*. The reasoning put to him and accepted: an accepted artifact that can
never be assessed is a state only a curator override can leave, which is the
dead end this project has already rejected once; a refusal at admission is
honest and immediately visible, a permanently stuck accepted image is not.

**The two numbers, measured.** The gap is not a judgement call about where a
limit should sit; it is two independently-chosen constants that were never
compared:

- **admission** — `MAX_MANIFEST_BLOBS = 1024`
  (`crates/hort-domain/src/oci.rs:404`), counting `config` **plus**
  `layers[]` together, rejecting (never truncating) above it. Its doc says it
  *"mirrors the write-path `MAX_BLOB_REFERENCES` cap (`hort-http-oci`
  `manifests_write.rs`)"*, so the write path carries a second copy of the
  same number;
- **assessment** — `MAX_IMAGE_LAYOUT_BLOBS = 256` (`:787`) and
  `MAX_IMAGE_LAYOUT_BYTES = 8 GiB` (`:773`), both private `const`s reached
  only through `ImageBudget::default_for_composite_scan` (`:849-855`).

So admission admits **four times** what assessment can ever compose.

### Correction (2026-11-10, re-verified before dispatch): there are **three** numbers, and the one named "admission" above is not it

The census above is wrong about which constant is the admission gate, and the
difference changes what "one declaration both read" may touch.

**#1 — the admission gate.** `MAX_BLOB_REFERENCES = 1024`
(`crates/hort-http-oci/src/manifests_write.rs:195`, enforced at `:1889`).
This is what refuses a manifest PUT. Its stated purpose is **the cost of N
`find_in_repo_by_hash` lookups** in `resolve_referenced_blobs`, enforced at
parse time *"so the resolution loop is never entered for an over-cap
manifest"*. It says **nothing** about assessability — so the item's "never
compared" claim is true of the pair that matters. Better still, its own
justification argues for the change: *"A real-world OCI image carries tens of
layers; 1024 is two orders of magnitude past observed maxima."* Lowering it to
the assessment budget costs nothing the code itself believes is real.

**#2 — not admission.** `MAX_MANIFEST_BLOBS = 1024`
(`crates/hort-domain/src/oci.rs:404`; refusals at `:489` and `:1190`) bounds
what `manifest_blob_refs` / `manifest_blob_digests` **return**, *"so a
pathological manifest cannot force the provenance cascade to hold an unbounded
reference set"*. Its doc says it **mirrors** #1.

**#3 — the assessment budget.** `MAX_IMAGE_LAYOUT_BLOBS = 256` (`:787`) and
`MAX_IMAGE_LAYOUT_BYTES = 8 GiB` (`:773`), reached only through
`ImageBudget::default_for_composite_scan` (`:849-855`).

**So the single declaration is between #1 and #3 — and #2 must not follow #1
down.** Two reasons, both load-bearing:

- The relation **#2-vs-#3 is already deliberate and pinned.**
  `MAX_IMAGE_LAYOUT_BLOBS`'s doc argues 256 deliberately *"refus[es] the shape
  the strict parse admits as well-formed (up to `MAX_MANIFEST_BLOBS`
  descriptors)"*, adding *"that the parse accepts such a manifest is a
  statement about the manifest being describable, not about hort agreeing to
  assemble it"* — and the test
  `the_shipped_budget_is_the_whole_images_and_not_a_blobs` (`oci.rs:3917-3930`)
  pins `budget.max_blobs < MAX_MANIFEST_BLOBS`. **Leave #2 at 1024 and that
  test stays green untouched.** Collapsing all three to one number would make
  it false by construction and delete the only thing holding that relation.
- **The cascade reads manifests it did not admit.** #2 runs over
  already-stored manifests and pull-through-registered ones, so lowering it
  would begin refusing provenance resolution for legacy manifests carrying
  257–1024 blobs — a behaviour change on existing data, on an axis the cutover
  below does not cover. Those manifests were admitted under the old cap and
  must stay readable.

**Therefore #2's doc sentence is corrected, not honoured.** "Mirrors the
write-path `MAX_BLOB_REFERENCES` cap" stops being true the moment #1 derives
from #3, and a comment asserting a mirror that no longer exists is worse than
no comment. Rewrite it to say what the number now is: a bound sized to **read**
what was admitted under any past cap, deliberately not tracking the admission
gate downward.

**And requirement 3 above is already half met.** The count refusal is
*already* OCI-conformant and already names both numbers — it lands as
`MANIFEST_INVALID` carrying *"manifest references {N} blobs; max is {M}"*. So
do not rewrite it: keep its text and let the number it prints move. What is
new is the **byte** refusal, which must match that shape — same error code,
same "actual, then bound" phrasing.

**What the decision requires, and the shape matters more than the number.**

1. **The assessment budget becomes the authority and admission derives from
   it** — one declaration, read by both, rather than a third number that
   agrees today. This project's own pattern (`https_rule_is_single_sourced`,
   `GC_PROTECTED_QUARANTINE_STATUSES`) is a single definition plus a guard
   that the readers still read it; a pair of `const`s that merely happen to
   match is how these two came apart in the first place. Note that the two
   caps count the same thing — `config` + `layers[]` — which is what makes
   one declaration honest rather than a coincidence of units.
2. **The byte bound gets an admission-side check at all.** There is none
   today. A manifest declares `layers[].size`, so the sum is checkable
   without fetching a byte; the digest verification on the subsequent blob
   fetches is what keeps a lying size from buying anything.
3. **The refusal is operator-legible**: an OCI-conformant error on the
   manifest PUT naming the bound and the actual count, not a bare 400. A
   bound an operator cannot read from the refusal is a silent wall — the
   failure mode ADR 0062 exists to prevent on the serve side, and this is its
   admission-side dual.
4. **The pull-through path refuses too.** An upstream image above the bound
   becomes **unmirrorable**, and that is the accepted cost of the decision
   rather than an oversight; say it in the docs where an operator configures
   an upstream, not only in the error.
5. **The existing estate is named, not fixed here.** Lowering admission from
   1024 to the assessment budget does not retract manifests already stored
   between those bounds, and re-pushing one would now fail. Those are exactly
   the artifacts half 1's cutover reassessment has to reach, so state the
   overlap instead of leaving two halves of one population to two sections.

Prod has promoted these policies already (`hort-base-scan`,
`hort-oci-scan`), which means the gap above is **live there**, not
hypothetical.

**And the cutover is not prospective-only.** Promotion in the current call
graph applies to new scans: an already-released manifest with no successful
composite assessment **stays released** until a new scan is driven, and the
ordinary sweep is interval-gated and limited to released/NULL status
(`crates/hort-adapters-postgres/src/rescan_candidates.rs:135-150`). Retiring
the mode without an existing-estate plan therefore **leaves an unassessed
population pullable after the nominal cutover** — the opposite failure from
the permanent hold, and just as real. The cutover must reassess existing
released manifests without a successful composite verdict, and existing
`scan_indeterminate` constituents, **including the completed no-verdict jobs
#427 creates**.

**Two things land with it:**

- **The apply-time linter row moves, and the review named where.** Keep the
  rejection, but evaluate it over **effective OCI policy scope** in
  `hort-app`'s static validator — reject an effective policy with
  `scanBackends: []` **when it governs an OCI repository**, using the
  validator's existing declared-repository map and repo-scoped-over-global
  resolver (`crates/hort-app/src/lint/static_validate.rs:986-1021,1315-1334`).
  A blanket per-envelope ban in `hort-config` would **remove the supported
  explicit scan waiver for non-OCI scopes** (`crates/hort-config/src/desired.rs:4795-4805`),
  and the existing capability row skips empty lists deliberately, so this is
  a **separate rule beside it** (`static_validate.rs:1233-1258`). Deleting
  the row outright would admit an OCI waiver that returns before composition
  (`scan_orchestration.rs:593-605,943-961`). Update the linter reference
  table and the fixed metric rule list. **This rule does not repair already
  persisted OCI waivers — that is part of the cutover check.**
- **A migration note.** For any installation on the default, the upgrade
  changes behaviour: filesystem findings decide at the composite level rather
  than per layer. That is the direction D2 calls correct, and an operator
  must be able to read that it happened.

### Correction (2026-11-10): the mode cannot be fully retired in one release — ADR 0030 decides the shape

*"This retires an operator surface, so it carries a migration note rather than
an ADR amendment"* understates what this retirement is. Measured before
dispatch:

- `composite_verdict_mode` is a **real column** —
  `policy_projections.composite_verdict_mode text DEFAULT 'observed' NOT NULL`
  plus a CHECK constraint, added by
  `migrations/033_scan_policy_composite_verdict_mode.sql:44-51`;
- it is also a **wire field of the event-sourced policy** —
  `PolicyField::CompositeVerdictMode` is encoded and decoded in
  `crates/hort-domain/src/entities/scan_policy_fold.rs:166-167,234-235`;
- the surface spans **58 files** across `crates/` and `docs/`, the largest at 48
  occurrences, including seven documents and two ADRs.

**So ADR 0030's expand/contract governs, and it is not a note — it is the
sequencing.** `migrations/CONTRACTIONS.toml` states the rule: *"a contraction
ships only in a release strictly AFTER the last release whose code referenced
the identifier. Expand and contract never share a release."*
`expand_contract_guard` enforces it by requiring the workspace version to
exceed the entry's `reference_removed_in`, **and** by rejecting a
still-referenced identifier in `crates/*/src`.

**This issue therefore must not drop the column.** What it does instead:

1. the code stops reading the mode wherever a decision is made, and the
   composite verdict carries release authority unconditionally;
2. the operator surface refuses a document that still sets the field, naming
   the retirement;
3. **No `CONTRACTIONS.toml` entry here either** — corrected 2026-11-10 after
   reading the guard. Every entry carries a `migration = "<file>.sql"` field
   naming a real file, and `expand_contract_guard` is red when an entry names a
   migration that does not exist (`red_when_an_entry_names_a_migration_that_does_not_exist`;
   the message is *"entry names migration …, which does not exist"*). So the
   entry cannot precede its DDL. The entry and the migration land **together**,
   in the later release, with `reference_removed_in = "0.17.4"` — which is also
   what `red_when_contraction_ships_in_the_release_that_removed_the_reference`
   and `red_when_reference_removed_in_is_a_pre_release` require (a plain
   `X.Y.Z`, strictly below the shipping version). What this issue owes is the
   **migration note** recording that the DDL is outstanding;
4. **the column stays, unread.** The DDL that drops it and its CHECK constraint
   ships in the release *after*. That is not a deferral, it is the policy — and
   attempting it here turns `expand_contract_guard` red.

**And the event schema keeps the field permanently.** Historical
`PolicyUpdated` events carry `composite_verdict_mode` forever, so the fold must
keep decoding it or a replay of an old stream breaks.
`PolicyField::CompositeVerdictMode` becomes a **tolerated, inert historical
field**, not a deleted variant — and that tolerance needs its own test, because
*"the field is retired"* and *"a replay of a months-old policy stream still
folds"* are different claims and only the second one protects a running
installation.

**Acceptance criterion 1 is qualified accordingly.** "Gone from the policy
surface" means gone from the **operator** surface and from **every decision**.
It does not mean gone from the event schema, and it does not mean the column is
dropped here.

**One thing this does not relax.** Accepting the field at apply while nothing
reads it is exactly the *"policy field accepted at apply, inert at runtime"*
hard block. So the apply-time refusal and the stop-reading change must reach
`develop` **together** — which they do, because this issue is one MR. Splitting
them across directives is fine; splitting them across merges is not.

## Half 2 — only an image layer is materialised as a root filesystem

Scope the tar materialisation to image layers instead of every tar-shaped
blob.

**The order is binding: half 2 must not precede half 1.** Under `Observed`,
half 2 would leave **nothing** gating a filesystem finding — the composite
recorded without authority, the layers no longer judged — which is verbatim
D6's hazard: *"an image becomes pullable with nothing having assessed it."*
Either half 1 first, or both in one change.

**This half cannot be decided from the blob's bytes, and that is the finding
that reshapes it.** The format handler deliberately classifies **every** blob
as `OciBlob`, because the layer role exists only in a later manifest
descriptor (`crates/hort-formats/src/oci.rs:45-65`), and the workspace turns
every tar-shaped `OciBlob` into a rootfs
(`crates/hort-adapters-scanner-trivy/src/workspace.rs:461-463,983-997`). **A
blob is ingested and scanned before its manifest exists** (ADR 0064:304-308).

So "only an image layer is materialised" is **not** a classification the
initial blob scan can make — and an absent parent at ingest is **not** proof
the blob is not a layer. Note also that ADR 0064 D2 explicitly **keeps** the
layer evidence scan (`:204-211`); this half is about when a *rootfs
materialisation* is warranted, not about abolishing layer evidence.

**Therefore this half must name *when* a manifest-confirmed layer gets its
evidence scan** — i.e. the point at which the role becomes known — rather
than trying to decide the role at initial ingest. Name the call sites and any
other consumer that reads a filesystem out of a non-layer blob today.

## Explicitly not in scope

The `NothingAnalysable → Failed` misclassification and its endless
re-enqueue — that is **#427**. Its *code review* is independent of this one.
Its **rollout is not**, and an earlier wording here said the opposite: #427
alone turns a wasteful retry loop into a durable, deadline-less hold, because
the interval sweep admits only `released`/NULL
(`crates/hort-adapters-postgres/src/rescan_candidates.rs:138-139`) and
`select_stranded` — the only query reaching `scan_indeterminate` (`:299`) —
requires `last_job.status = 'failed' OR IS NULL` (`:301`). A completed
no-verdict job therefore has **no automatic selection signal at all**. #427's
own item carries the same correction; the cutover bullet below is the half
that repairs it, which is why that population is named there explicitly. No change to release logic beyond the above. **No new
configuration surface** — this item removes one and must not add another.

## Alternatives already cleared, so they are not re-proposed

- **Dummy scanners per media type** — `Analysed(vec![])` is documented as *"a
  clean verdict and carries release authority"*, so a dummy would assert
  cleanliness, with authority, for something nobody looked at. Strictly worse
  than the hold it replaces.
- **A suitable scanner for every artifact a repo can hold** — answers the
  wrong question: there is nothing to analyse *in principle*.
- **A special case in the stranded sweep** — treats the symptom at the
  selection while the misclassification stands (#427 fixes the fact instead).
- **Keeping the mode as a permanent precondition** — the ordering is
  satisfied by construction once promotion is unconditional, so the switch
  would express a condition that is trivially true.

## Acceptance

- `CompositeVerdictMode` is gone from the policy surface; the composite
  verdict carries release authority unconditionally. A policy document that
  still sets the field is **refused at apply with a message naming the
  retirement**, not silently ignored.
- The `promoted` × `scanBackends: []` interaction is still rejected at apply,
  from its new home, with its own test. The reference table
  (`docs/architecture/reference/apply-time-linter-rows.md`) is updated in the
  same change.
- A non-image OCI artifact is **not** assessed and **not** held, asserted
  with **the accepted SBOM referrer fixture and a mixed signature/tar
  referrer** — the two shapes the review showed reach an absent-verdict hold
  today. A fixture that only exercises a Helm chart does not cover this.
- A **255-layer** image and an **over-8-GiB** image are **refused at
  admission** (maintainer decision, 2026-11-09), never
  accepted-then-permanently-held. One test per bound, each asserting the
  refusal names the bound and the actual count; plus a test at the boundary
  itself, since both existing caps are inclusive and off-by-one here means
  refusing a composable image.
- **The admission bound is derived from the assessment budget, in one
  declaration both read** — asserted by a test that moves the budget and
  watches admission follow, not by two constants that agree. The write path's
  own copy (`MAX_BLOB_REFERENCES`) is reconciled in the same change.
- The byte bound is checked at admission from the manifest's declared
  `layers[].size` sum, with a test that an over-bound manifest is refused
  before any blob is fetched.
- The pull-through path refuses on the same bound, with a test, and the
  operator-facing consequence — an upstream image above the bound cannot be
  mirrored — is documented where an upstream is configured.
- The deterministic refusals still hold their manifest fail-closed; one test
  per case (unparseable, absent, permanently-absent constituent).
- A tar-shaped blob that is **not** an image layer is no longer materialised
  as a root filesystem, and an image layer still is. Both directions
  asserted.
- A previously stranded, permanently-held layer blob becomes deliverable
  through its manifest — and **this is reached by the cutover's reassessment
  of existing rows, not by the new-scan rule alone.** The review established
  that changing only the new-scan rule cannot meet this criterion, because no
  sweep selects a completed no-verdict job or a `scan_indeterminate`
  artifact.
- The cutover reassesses existing released manifests with no successful
  composite verdict **and** existing `scan_indeterminate` constituents
  **and** #427's completed no-verdict jobs. Asserted on each population.
- The migration note exists and states what changes for an installation on
  today's default.
- Gate green; no uncovered added lines; no ticket numbers in code comments.
