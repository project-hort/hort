# 461 — the referrers list belongs to the name that was asked

**Issue:** #459 · **Branch:** `agent/459-oci-namespace-identity` · Unit 2 of 6.
**Supersedes** `backlog/428-the-list-belongs-to-the-name-that-was-asked.md`, which asked the question before the namespace was decided.

## Why unit 460 does not already fix this

460 scopes identity through the **path**. The referrers index does not read a
path: `content_references` is keyed
`(repository_id, source_artifact_id, target_content_hash, kind)`
(`migrations/013_content_references_multivalue_pk.sql:81`) and the handler asks
`find_by_visible_target(repo_key, &target_hash, Some("oci_subject"), actor)`
(`crates/hort-http-oci/src/referrers.rs:226`). The query is **hash**-keyed,
so it crosses every name in the hort repository no matter what the path says.

**One narrowing is owed: each referrer must itself live in the asked name.** A
signature pushed under `other/thing` must not appear in `library/nginx`'s list.

That is the spec's own rule, not an inference from hort's namespace model.
*Listing Referrers*: **"Each descriptor is of an image manifest or index in the
same `<name>` namespace with a `subject` field that specifies the value of
`<digest>`."** The namespace that scopes the list is the **referrer's**, and
the subject's is not mentioned.

The subject's namespace is deliberately **not** narrowed — that was this item's
decision 4, which was wrong and is recorded there with both halves of the
error.

## Where the name comes from

After 460 the source artifact's own `path` carries its name, and the handler
already hydrates every candidate's `Artifact` (`referrers.rs:274`, the call at
`:279`, through `find_visible_by_id`). So the referrer's name is derivable from
data the handler already holds, with no new query, no new column and no schema
change. Which of the three available copies to read, and why, is decision 2
below.

## Four things this item left open, decided before dispatch

Unit 460 landed (`9d292bd2`, in `develop` at `31eeb002`) and answering these is
what that landing changed.

### 1. Where the filter goes: the handler, after hydration

`ContentReference` carries `source_artifact_id`, `target_content_hash`, `kind`,
`metadata`, `repository_id`, `recorded_at`
(`crates/hort-domain/src/ports/content_reference_index.rs:184-206`) — the
referrer's **name is not on the edge at all**. So there is no column to pass a
predicate to; narrowing in SQL would mean teaching a format-neutral port an OCI
path shape, which is the layering 460's own fallback design deliberately kept
out of PostgreSQL ("a format-neutral exact-path store").

This has to be said explicitly because `ContentReference::kind` carries the
instruction *"Read-side filters pass this through to the adapter's SQL
predicate — do NOT post-filter in application code"* (`:196-198`), and a
reviewer will read the name filter as violating it. It does not, and the
distinction is the point: `kind` **is** an indexed column on the edge, so
post-filtering it would discard an index the query could have used. A
referrer's name is on a different table and is not a column anywhere, so there
is no index to forgo. Put that distinction in the code beside the filter, not
only in the report.

Cost: referrer counts per subject are single digits in practice (signatures,
SBOMs, attestations), so hydrating a row that is then dropped is not the route
ADR 0062 was protecting. Say in the report how many hydrations a worst-case
list does.

### 2. Where the name comes from: the path, through the domain parser

`hort_domain::oci::parse_oci_artifact_path(&artifact.path)` and its `name`
field. **Not** `Artifact.name`, and **not** unit 430's projected `name` key on
the edge (`crates/hort-http-oci/src/manifests_write.rs:1633`).

All three hold a name; only one of them is the identity the read resolved
through. `Artifact.name` and the projected key are stored copies, and a stored
copy of a fact that is also in the key is a second source of truth that can
disagree with it — which is exactly what this issue exists to remove one level
up. Removing the projected key is unit 464's cleanup; **not reading it is this
unit's job**.

### 3. A legacy name-free referrer stays listed under every name

A row written before 460 has `blobs/sha256:<hex>` / `manifests/sha256:<hex>`,
so `parse_oci_artifact_path` yields `name: None` — the row's namespace is
genuinely **unknown**, which the specification already says in those words
(`docs/architecture/reference/oci-namespace-and-identity.md`, Conformance).

It is listed under every asked name, unchanged from today, and unit 464's
migration is what completes the narrowing. The alternative — attributing it to
`Artifact.name`, the first push's name — would give a definite answer that is
sometimes wrong, and being wrong here means an existing signature **disappears**
from the list for the name a client is verifying under. A deferral a reader can
see beats a silent regression in signature verification. This is the same
posture the maintainer already read and accepted for 460: legacy rows keep the
old behaviour until they are rewritten.

So it is a **documented** behaviour with its own test, not an accident of the
`Option` being `None`. State it at the filter.

### 4. There is no subject narrowing — corrected 2026-11-22, after the first run

This decision was wrong twice over, and the unit that implemented it caught
both halves. It is recorded rather than quietly replaced, because the first
implementation shipped the mistake and the test that now forbids it is the only
thing stopping the next unit from re-adding it.

**Factually wrong.** I wrote that the endpoint already resolved the subject
through 460's scoped-then-legacy lookup. It never resolved the subject at all:
the handler went from digest parse straight to the hash-keyed edge query
(`crates/hort-http-oci/src/referrers.rs`, step 3). There was nothing to inherit.

**Wrong in substance**, for two independent reasons:

- **The schema.** The edge's target is `target_content_hash`
  (`migrations/013_content_references_multivalue_pk.sql:81`) — a content hash,
  never a namespaced row. *Which name the subject is in* is not a property the
  referrers index carries, so requiring it invents a constraint the data model
  does not have.
- **The protocol, and hort's own deliberate choice.** `oci_subject` is
  deliberately **not** gated on the subject existing, and the code says why:
  *"the OCI Referrers flow lets a referrer be pushed for a subject this
  repository has not got, and the handler has always minted that referrer —
  gating it would refuse a legitimate push"*
  (`crates/hort-http-oci/src/manifests_write.rs`, the `oci_subject` paragraph).
  A subject-existence check on the **read** side makes that accepted push
  invisible: the push succeeds and the referrer never appears until the subject
  is ingested. The Distribution Spec requires a pushed manifest with a valid
  `subject` to be discoverable in the list, and ADR 0011 puts the spec above
  both the implementation and my acceptance criteria.

**And the narrowing is complete without it.** A referrer pushed under another
name is dropped by its own path, which is decision 1's filter; that alone closes
the defect this unit exists for. The subject check added a query per request
(plus its legacy fallback) and bought nothing but the spec violation.

## Acceptance

- A signature pushed under `library/nginx` with a subject in `library/nginx`
  appears in `library/nginx`'s referrers list. The same signature does **not**
  appear in `other/thing`'s list for the same digest, and `other/thing`'s answer
  is `200` with an empty `manifests` array — not `404`, which would make the
  omission an enumeration oracle (the handler's step 7 comment already states
  that rule; keep it true).
- A referrer under the asked name is listed **even when its subject is not held
  in this hort repository at all**, and even when the subject exists only under
  another name. This is the spec-mandated discoverability of a pushed referrer
  and it is the test that forbids re-adding a subject-existence gate; see
  decision 4.
- A subject digest that exists only under another name answers `200` with
  whatever referrers live in the **asked** name — normally an empty list, but
  empty because no referrer is in that name, never because the subject is
  elsewhere.
- The projected `name` key on the edge is **not** read by the handler; assert
  that a row whose projected `name` disagrees with its path is listed according
  to the **path**. That test is the one that stops the redundant key from
  quietly becoming authoritative again. Assert the same against
  `Artifact.name`, for the same reason.
- A referrer whose path is the legacy name-free shape is listed under the asked
  name **and** under a different name, with the test naming it as the expand
  window's documented behaviour rather than as a gap.
- The existing ADR 0062 terminal-omission behaviour and the withheld-census
  debug line are unchanged.
- The change adds no uncovered lines (intersect the diff's added line numbers
  with `cargo llvm-cov --show-missing-lines`, per touched file).

## Not in this unit

What the list may **withhold** — the spec's *Enabling the Referrers API* item 3
`MUST` against ADR 0062's terminal omission and ADR 0055's audience reservation
— is `backlog/429-what-the-list-may-withhold.md` and waits on a maintainer
decision. This unit changes *which name* a row belongs to, never *whether* a row
may be hidden.

## Census provenance

Every line number above was re-measured against `develop` at `31eeb002`
(2026-11-22), after unit 460 merged. The citations the item was written with all
held; what needed adding were the four decisions above, each of which only
became answerable once 460 landed. Decision 4 was then **corrected after the
first implementation run** measured it — see that section.
