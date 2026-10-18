# 0062 — Hort advertises nothing it will not serve

- **Status:** Accepted
- **Narrows:** [0043](0043-oci-image-index-support.md) — its "why a released
  index over a held/rejected child is safe (load-bearing)" argument, for
  **terminal** verdicts only; it stands unchanged for a *held* child. ADR 0043
  carries a dated one-line pointer here, and the argument lives in this record
  rather than there.
- **Enforced by:** `QuarantineStatus::is_terminal`
  (`crates/hort-domain/src/entities/artifact.rs`) — the single wildcard-free
  definition of the line decision 3 draws — and, for the
  construct-the-document shape, the shared index pipeline's universal
  `NonServableStatusFilter`, whose per-entry truth table is in the module docs
  of `crates/hort-app/src/use_cases/index_filters.rs` (cited, not restated).
  On the OCI paths the manifest write path refuses a terminal reference; the
  read path's constituent half is this issue's enforcement unit and **had not
  landed when this ADR was accepted** — stated so the record is not read as
  describing shipped behaviour. It has since landed for the manifest route
  (`hort_app::use_cases::manifest_deliverability`, closure from the bytes) and
  for the two OCI list surfaces (`hort_app::use_cases::list_deliverability`
  behind the referrers index and `tags/list`, closure from the membership
  projection — decision 2b). The per-format enforcement map belongs to the
  architect skill (ADR 0024, `.claude/commands/hort-architect.md`), which a
  reviewer re-reads; one in an ADR is stale at the next rename.
- **Relates:** [0007](0007-fail-closed-quarantine-release-predicate.md) (the
  fail-closed release predicate, which stays per artifact),
  [0015](0015-apply-time-linter-inert-fields-and-naming.md) (`IndexMode` is
  not extended and no knob is added),
  [0021](0021-read-handler-anonymous-by-default.md) /
  [0045](0045-oci-read-challenge-before-anti-enum.md) (repository
  anti-enumeration — untouched, see below),
  [0039](0039-keyed-provenance-verification.md) §10 / §11 and
  [0055](0055-write-authorized-hold-read-generalised.md) (the
  write-authorized hold-read and the provenance cascade, both untouched),
  [0024](0024-architect-skill-as-enforcement-index.md) (the enforcement
  index, where the per-format proof lives). Source decision: issue #342, the
  human's confirmation of 2026-10-13.

## Context

A client resolves a name, a version or a reference against a document before it
asks for any bytes. Hort serves such documents in two structurally different
forms, and until this decision it answered the same question differently
depending on which form the client happened to meet.

Where hort builds the document, the rule has held since the shared index
pipeline existed, and it holds under every index mode: an entry whose status
hort knows to be non-servable is dropped before the document is built.

The OCI paths did not hold it: a manifest's delivery was gated on its own
status, its constituents were never consulted, and ADR 0043 argued that
posture explicitly on the ground that consumption safety is enforced per child
and per layer. Measured on the pushes that opened issue #342, six of seven
manifests were accepted over an already terminally rejected layer, and all
five that were then delivered carried `released` beside a `rejected` layer — a
push reporting success and a pull answering "not found".

One codebase holding two postures, with a client's experience decided by which
format it happens to use, is what this record settles.

## Decision

### 1. The rule

**Hort advertises nothing it will not serve.**

"Advertise" means a **resolution document** in the sense ADR 0055 already
gives the term: the document a client reads to learn that something exists and
what its bytes hash to, before it asks for the bytes. It is not the refusal a
caller receives when they ask for a named thing directly, and it is not a
diagnostic or administrative surface that reports a status — ADR 0055 governs
those, where *why* something is withheld is information rather than access.

### 2. The enforcement shape follows from the kind of document, not from taste

- Where hort **constructs** the document — an npm packument, a PyPI simple
  index, Cargo index lines, a Maven `maven-metadata.xml` — hort chooses the
  entries, so the non-servable entry is **omitted**. What the client receives
  is still a complete, valid answer to the question it asked; it simply does
  not name something hort would refuse.
- Where the document is **immutable content-addressed bytes** hort cannot
  rewrite — an OCI manifest or image index — the **document is refused**.
  Omission is not available, and that is a property of the document rather
  than a preference: the digest is the identity, so dropping an entry yields
  different bytes, a different digest, and therefore not the document that was
  asked for. The client verifies that digest itself, and a signature over it
  (ADR 0027 / ADR 0039) is a signature over exactly those bytes.
- Refusal binds both ends of such a document's life: one hort will not deliver
  is also one it does not mint. That is the same rule one step earlier, not a
  second rule.

This ADR decides nothing about a version hort has **never ingested**. That
tier is neither servable nor non-servable but unknown, it is the ordinary
state of a cold pull-through, and which modes advertise it is `IndexMode`'s
question under ADR 0015's naming discipline — untouched here.

### 2b. Where the answer is *read from* follows the document's input cost

Deciding that an entry is non-servable requires resolving what it binds —
its closure — and the source of that resolution is not one choice for the
whole system. It follows from what the document's reader is already
holding, and the two answers are deliberate rather than an inconsistency
to tidy away:

- **The reader already holds the bytes.** A manifest `GET` has the
  document in hand before it can serve it, so deriving the closure from
  those bytes costs nothing, and consulting the `content_references`
  membership projection instead would buy a second source of truth for
  free. ADR 0039 settles which one wins when they can disagree: edges
  *nominate*, the bytes decide.
- **The reader holds no bytes.** A list surface — the OCI referrers
  index, `tags/list` — names N manifests it has not read. The same
  derivation there is N round trips and one CAS-read tree per entry, and
  a list has no acceptable fail-closed answer when a per-entry budget
  blows: refusing one manifest is proportionate, refusing a whole
  `tags/list` is not. So a list resolves the closure from the membership
  projection, in one statement, with zero CAS reads.

**The projection's weakness, dated.** A manifest row minted before the
2026-10-07 amendment to ADR 0043 — the one that moved the OCI membership
edges into the claiming artifact's own transaction — can carry incomplete
edges, and the `oci-membership-edge-backfill` task exists to repair
exactly those. An incomplete edge set makes a list surface
**under**-report: the entry stays listed and the subsequent pull refuses
it, which is the behaviour that preceded the rule — so no regression, and
it fails **open** rather than hiding something the registry would have
served. The converse cannot happen, because an edge is written only from
a complete resolution of what a document declares, so the projection
cannot nominate a constituent a document does not bind.

This is why a surface's enforcement shape (decision 2) and its closure
authority are two separate questions. A future surface answers the first
from whether hort builds the document and the second from whether its
reader already holds the bytes; neither answer implies the other.

### 3. The line runs between a verdict and a wait, and it is one line for every format

- A **terminal** verdict — `Rejected` or `ScanIndeterminate`, the class
  `QuarantineStatus::is_terminal` names, whose exit is a deliberate act and
  never the passage of time — means **never**. It is never advertised, in
  either shape, in any format.
- A **hold** — `Quarantined`, including a hold with no self-resolving deadline
  — means **not yet**. The client is told to come back, and every format keeps
  the behaviour it has today, the write-authorized hold-read's metadata
  exemption (ADR 0055, generalising ADR 0039 §10) included and unchanged.
- **This narrows ADR 0043 for terminal verdicts only.** Its per-child,
  per-layer argument stands for a held child: the per-leaf `503` *is* the "not
  yet" answer, and an index above it is honest. It does not stand for a
  terminal one, where "never" is already known at the moment the index is
  served, and advertising it spends a client's pull and an operator's
  diagnosis on an answer the registry already had. The narrowing claims
  nothing beyond that: the fail-closed release predicate stays satisfied **per
  artifact** (ADR 0007), and the provenance cascade (ADR 0039 §11) is
  untouched.

**Repository anti-enumeration is untouched.** ADR 0021 and ADR 0045 decide
what a caller may learn about repositories and names its read authority does
not reach — per-resource visibility as the only read gate, and the
challenge-before-anti-enumeration ordering on OCI. This record decides what an
**authorized** resolution document may contain, one gate later, and nothing
here widens what an unauthorized caller sees.

## Consequences

**A surface that does not hold the rule is a defect against this ADR, not an
exception to it.** The rule is stated over the *kind* of document precisely so
that it reaches a surface nobody enumerated: every document hort serves that a
client resolves against is in scope, and the shape it must take follows from
whether hort builds it. Closing such a surface is enforcement work, not a
decision to re-take.

**The answer is coarser where the bytes are immutable.** A refused index is one
answer about a whole image where the per-leaf model gave an answer per layer.
That is the price of a document hort cannot edit, and the price is paid in
precision of the refusal — never in what is served.

**Deliverability is not a property of a document's own row.** It depends on the
current status of the things the document names, so it changes in both
directions without the document's own bytes or status changing: a rescan that
terminally rejects a layer withdraws a manifest that was deliverable a moment
earlier, and a deliberate act that re-judges that layer restores it.

## Alternatives considered

**Rewrite the immutable document** — strip the terminal entry from an index and
serve the remainder. Rejected: the bytes are the identity. A client asked for a
digest, verifies that digest, and may hold a signature over it; serving
something else under that name is a worse failure than refusing.

**Extend OCI's per-leaf posture to the built documents** — advertise
everything, refuse per leaf, everywhere. Rejected: it is the posture the index
pipeline's default exists to avoid, and it makes every resolution a gamble the
client pays for at download time.

**Treat a hold like a verdict and refuse both.** Rejected: it answers "never"
to a question whose answer is "not yet", and it withdraws the one read the
write-authorized hold-read exists for — a publisher resolving what it has just
pushed in order to sign it (ADR 0055, ADR 0039 §10).

**Make it a per-repository knob.** Rejected (ADR 0015): this is an invariant,
not a posture. The one operator knob in this area, `IndexMode`, already exists,
decides a different question (the never-ingested tier), and is not extended.

## References

- Issue #342; backlog item 296 — this record's commission and its scope.
- `crates/hort-app/src/use_cases/index_filters.rs` — the
  construct-the-document shape and its per-entry truth table.
- `crates/hort-app/src/use_cases/manifest_deliverability.rs` and
  `crates/hort-app/src/use_cases/list_deliverability.rs` — decision 2b's two
  closure authorities, each carrying its own cost argument; the Postgres
  census statement in
  `crates/hort-adapters-postgres/src/list_deliverability.rs` carries the dated
  legacy-edge weakness at the query.
- `docs/glossary.md`, "Terminal (quarantine status)" — decision 3's
  vocabulary, already in place and unchanged here.
- [ADR 0043](0043-oci-image-index-support.md) — the narrowed argument, with
  its dated pointer back to here.
