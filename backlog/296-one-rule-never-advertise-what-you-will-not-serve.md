# 296 — ADR 0062: never advertise what you will not serve, in every format

**Issue:** #342 · **Branch:** `agent/342-referenced-blob-deliverability`
**Governing decisions:** ADR 0007 (fail-closed release), ADR 0043 (the
OCI per-leaf argument this ADR narrows), ADR 0015 (`IndexMode` naming and the
no-inert-field discipline), ADR 0021 / ADR 0045 (repository anti-enumeration,
**not** reopened), ADR 0055 (the diagnosability clause this unit applies rather
than decides), ADR 0039 §10 (grant-based visibility widening), ADR 0024 (the
architect guide is the enforcement index, which is where the per-format map
belongs).

**This is the first deliverable of the issue, and it is what makes 293, 294 and
295 unambiguous.** Human decision (2026-10-10): the ADR must make this
technically correct, stable and unambiguous, **comprehensively for every
affected format**, and read performance is explicitly secondary to those three.

**Scope of the document, decided 2026-10-11 (architect).** The 2026-10-10
commission stands — **one** cross-format decision, not a scatter of per-ADR
amendments. What changed is how much of it the ADR itself carries. An ADR sets
strategic direction; a design detail that derives from a more general standing
decision does not get its own record, and a per-format code map in an ADR is a
promise the next rename breaks. So this ADR decides **three** things and
nothing else, and the detail is written where it is maintained — beside the
mechanism, and in the enforcement index ADR 0024 already designates. Nothing is
dropped: "technically correct, stable and unambiguous, comprehensively for every
affected format" is still the standard; only the location of the per-format
proof moves.

## What is true today — measured, and it is not what the OCI ADR assumes

**The rule already exists and is already the default — in every format that
builds its own index.** `IndexMode` (`crates/hort-domain/src/entities/repository.rs`)
drives the shared Source → Filter → Builder index pipeline
(`hort-app/src/use_cases/index_serve.rs` + `index_filters.rs`), which npm,
PyPI, Cargo and Maven all construct their served documents through. Its
default, `ReleasedOnly`, is documented as build-safe-by-construction: "the
served index lists only versions Hort holds in a servable status, so a range /
bare install / `latest` resolution can **never resolve to a version that would
`503` on download**".

And the terminal case is not mode-dependent: `index_filters.rs` states
"`Rejected` and `ScanIndeterminate` are terminal verdicts and stay" dropped,
with the mode table dropping them under **both** `ReleasedOnly` **and**
`IncludePending`, and the predicate at `:125` returning `false` for both
statuses.

**So no index mode, in any list-building format, advertises a terminally-held
version. The OCI manifest path is the only place in hort that does** — it gates
on the manifest's own status and never consults its constituents. ADR 0043's
section "Why a released index over a held/rejected child is safe (load-bearing)"
argues the opposite posture for OCI, and that section is the exception in this
codebase, not the rule.

## What to do — the ADR decides three things

Write **ADR 0062** (confirm the number is free before writing; 0063 is taken).
It is short on purpose.

1. **The rule, in one sentence:** hort never advertises content it will not
   serve.
2. **The two enforcement shapes, which follow from the document and not from
   taste:**
   - where hort **constructs** the document (npm packument, PyPI simple index,
     Cargo index lines, Maven `maven-metadata.xml`), the non-servable entries
     are **omitted** — this is `IndexMode` and it already holds;
   - where the document is **immutable content** hort cannot rewrite (an OCI
     manifest or index, whose bytes are content-addressed), the document is
     **refused**, because omission is impossible.
3. **The terminal/held line, once, for all formats** — and with it the
   narrowing of ADR 0043. A **terminal** verdict (`Rejected`,
   `ScanIndeterminate`) is "never" and is never advertised. A **hold**
   (`Quarantined`, including one with no self-resolving deadline) is "not yet":
   the client is told to come back, and the existing per-format behaviour
   stands — including ADR 0043's per-leaf argument, which survives **for
   holds** and is narrowed only for terminal states. ADR 0043's load-bearing
   section therefore gains a **dated one-line narrowing** pointing here; it is
   not re-argued there. ADR 0021 / 0045 are untouched, and ADR 0062 says so in
   one sentence so this is not read as a loosening of repository
   anti-enumeration.

That is the whole ADR. It carries no per-format code map, no authority
mechanics, no cap arithmetic and no envelope table.

## What does NOT go in the ADR — and where each piece goes instead

Each of these was a decision point in this item's first draft. Each is either
already decided by a standing ADR or is a mechanism whose derivation belongs at
the mechanism. Write the derivation **where the mechanism is**, in the unit
named, and say in that unit's report where it landed.

- **The per-format enforcement map with code citations** → the architect guide
  (`.claude/commands/hort-architect.md`), as an enforcement row in the
  anti-patterns index. ADR 0024 makes the guide the enforcement index; a code
  map in an ADR rots at the next rename, and the guide is re-read on every
  review. The index-pipeline half is already documented in `index_filters.rs`'s
  module docs — cite it, do not copy it. **Unit 294** adds the row.
- **Authority: the content's own bytes plus the catalog's statuses, never the
  `content_references` edge projection** → already written in ADR 0039: edges
  *nominate*, the bytes decide, and the projection is demonstrably repairable
  rather than guaranteed (`oci_membership_edge_backfill` exists for rows minted
  before the write path carried its edges). This is an application of a
  standing decision, not a new one. The subordinated read cost (human,
  2026-10-10: correct, stable and unambiguous before read performance) is
  recorded in the rustdoc of the predicate **unit 293** introduces, so a later
  reader cannot "optimise" it back into a projection read without reading why
  it is not one.
- **Transitivity and the existing breadth/depth caps** (`MAX_INDEX_CHILDREN`,
  `MAX_BLOB_REFERENCES`, the index-child depth cap), and what happens at a cap:
  a closure that cannot be fully resolved is **not** a licence to serve. That
  is ADR 0007's fail-closed predicate applied to a closure walk — derivable, so
  it is pinned by a test and stated in the walker's rustdoc in **unit 294**,
  not in the ADR.
- **Absence is not a hold.** A named constituent with no catalog row is "not
  local yet" — the normal state of a pull-through document — and must keep
  answering as it does today. This is the one place where a fail-closed reflex
  gives the wrong answer and would break every cold pull-through, so it is a
  **test with that name** plus a rustdoc sentence in **units 293 and 294**. A
  behavioural invariant a test can hold does not need a record.
- **The answer model for 295** → ADR 0055 already carries it: *"Resolvability
  is gated by this qualifier; diagnosability is not. Why a version cannot be
  resolved is information, not access, and every byte route is free to say so
  to any caller holding `Read`"* — and it explicitly records that OCI's
  anti-enumeration answer and npm's named reasons **both** satisfy the rule.
  Changing OCI's format-specific choice is therefore a design decision inside a
  standing decision, not an ADR case. **One exception** needs ADR text: the
  human's decision D7 (2026-10-10) sets the audience at **the read gate** —
  whoever could read the artifact if it were not blocked learns why, including
  an anonymous caller on a public repository — which widens ADR 0055's wording
  "any caller holding `Read`". That becomes a **dated clarification in ADR
  0055**, in the idiom that ADR already uses ("Clarified 2026-09-17 — …"), and
  the architect brings its wording to the human separately. The per-format
  envelope mapping (OCI `DENIED`; npm, PyPI, Cargo, Maven in their own shapes),
  the measured delivery constraint behind the status-code choice and its limit
  (a hold stays `503` because that is the correct semantic, so only the
  terminal case gains a distinguishable code) are **unit 295**'s rustdoc and
  tests.

## Explicitly out of scope

- Implementation. 293 (write path), 294 (OCI read path), 295 (the explicit
  reason) are the enforcement units; this one decides.
- Any new operator knob. `IndexMode` already exists and is not extended here.
- Re-implementing a format that already complies.
- Re-arguing ADR 0043's per-leaf safety model. It is narrowed for terminal
  verdicts and otherwise stands.

## Acceptance

- ADR 0062 exists, is listed in `docs/adr/0000-historical-decisions-index.md`
  with a one-line index row, and carries exactly the three decisions above plus
  the one sentence on ADR 0021 / 0045. A reviewer can read it in under five
  minutes.
- ADR 0043's load-bearing section carries the dated one-line narrowing pointing
  at ADR 0062, and nothing else changes in that ADR.
- ADR 0055 carries the dated clarification of the diagnosability audience
  (the read gate, anonymous included where the gate admits one), in its
  existing "Clarified …" idiom, with the wording confirmed by the human before
  it is written.
- Nothing in ADR 0062 is a per-format code citation, a cap number, or an
  envelope table; each of those is named in the "where it goes instead" list
  above with the unit that carries it.
- `docs/glossary.md` gains nothing new beyond the two entries this issue
  already added, or the ADR explains the new term it needs.
- Gate: docs-only — no `crates/`, no `Cargo.*`, no `migrations/`. Per the gate
  economy run `cargo audit` + `cargo deny check` and the markdown/ADR-index
  checks only; say in the report that the test suite was skipped and why.
