# 409 — The span measures time in the state, not the age of the content

**Issue:** #288 · **Branch:** `agent/288-the-span-measures-time-in-the-state` ·
item 1 of 2. **Inert on landing**: it adds a resolver and nothing consumes it
until item 2.

**Governing decisions:** ADR 0054 (`quarantine_window_start` is the earliest
*content* anchor and an explicit approximation of elapsed ecosystem
exposure), ADR 0002 (the stream is the record), #281 D1 (the span exists at
all). No ADR text changes in this item.

## Why this is its own item, and first

Item 2 opens four locks that today refuse to let a held artifact expire. If
the span it opens them for is computed from the wrong anchor, the result is
**not** a failed test — it is artifacts expiring the moment they are
rejected. So the anchor is built, tested and merged **before** anything
consumes it, and this item is inert on its own: nothing calls the resolver
until item 2 does.

## The property

**A span over a held artifact measures how long it has been in that state,
never how old its content is.**

`quarantine_window_start` is the *earliest content anchor*: ingest time,
upstream publication time, or the zero-window exception for descendants —
whichever is earlier (`crates/hort-app/src/use_cases/ingest_use_case.rs`, the
window-start derivation), and ADR 0054 describes it in as many words as an
approximation of "elapsed ecosystem exposure". A **retroactive rejection
keeps it** (`crates/hort-domain/src/entities/artifact.rs`, the retroactive
block path).

Put together: a two-year-old artifact rejected five minutes ago would be
**instantly past any span expressed against that anchor**. Under a 30-day
span it would be purged the same afternoon it was first judged. That is the
single defect that would make the whole exception unsafe, and it is invisible
in any test whose fixture creates the artifact and rejects it in the same
second — which is what a hand-written fixture naturally does.

## What to build

**A resolver that answers "when did this artifact enter its current held
state?" from the event stream.**

The entry event is on the stream: the latest `ArtifactRejected` for a
rejected artifact, the corresponding entry event for `quarantined` and
`scan_indeterminate`.

**Correction, after implementation (2026-11-09).** This item originally named
a SQL `LATERAL` as the shape to follow, mirroring the curation queue's
rejection-reason projection. **That was wrong, and the implementation's
declared deviation is accepted.** The resolver is a **pure fold in
`hort-domain` over a stream the consumer already holds** — no port, no
adapter, no SQL, no `EventStore::read_stream` call. Three verified reasons:

- `RetentionUseCase::evaluate_one` **already reads the full artifact stream
  unconditionally** for every candidate, before the idempotency check, the
  freshness signal and the finding-age anchor
  (`crates/hort-app/src/use_cases/retention_use_case.rs:387`, whose own
  comment says *"One full read of the artifact stream serves every decision
  below"*). The entry event is therefore already in the caller's hand at the
  point item 2 needs it, and a `LATERAL` would re-read the same `events`
  table for data already in memory. Removing a round-trip the design's
  structure forces is CLAUDE.md's own example of "objectively better".
- The `LATERAL`'s one structural advantage — being joined into the candidate
  enumeration — is **unavailable** here: `list_candidates(batch_size, after,
  now)` takes no policy, and the state opt-in is per-`RetentionPolicy`, so
  the enumeration cannot know whether an artifact's state is opted in. The
  decision has to be made in the evaluator, which is where the stream is.
- A SQL `CASE` would re-type a Rust enum. The curation queue's own `LATERAL`
  is the cautionary case: it needed a dedicated DB-free guard
  (`sql_case_covers_every_rejection_reason_variant`, referenced at
  `curation_queue_repository.rs:57,149,259`) for exactly that reason. A
  wildcard-free domain mapping makes a fourth held state a compile error with
  no guard to maintain.

**Fail-safe, explicitly:** an artifact whose entry event cannot be found has
**no span**, and therefore never expires. Not "falls back to
`quarantine_window_start`", not "treated as old" — *no span*. The fallback
that looks harmless is exactly the one that reintroduces the defect above,
because the absent event and the old content coincide precisely in the
population at risk (artifacts whose streams predate the event being written).

**Do not touch `quarantine_window_start`,** its derivation, or any existing
reader of it. It remains correct for what it is: the content anchor the
release gate uses. This item adds a second, differently-named quantity beside
it, and the name must make the difference unmissable at every call site —
these two numbers being confusable is the whole hazard.

## Acceptance

- For an artifact rejected today whose content is a year old, the resolver
  answers "entered the state today". **This is the test that decides whether
  the span exists**; write it first, with the content anchor and the state
  entry deliberately far apart.
- For each of the three held statuses, the resolver finds the entry event the
  status corresponds to, and a status change moves the answer.
- An artifact with no discoverable entry event yields **no span**, and the
  test asserts the absence rather than a value.
- Nothing in the release gate, the candidate reader, the evaluator or the
  purge behaves differently after this item — asserted, not assumed: the
  resolver has no production caller yet.
- DB-backed tests carry `#[serial(hort_pg_db)]`; the change adds no uncovered
  lines; no ticket numbers in code comments.
