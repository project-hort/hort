# 385 — Doubles that match production, in both directions

**Issue:** #411 · **Branch:** `agent/411-doubles-that-match-production` ·
single item, three parts.

**Governing decisions:** `CLAUDE.md` → *A test double that round-trips must
refuse what production refuses*, and ADR 0008 (the dependency graph) for where
part (a)'s fix has to live. No ADR change.

Verified against `develop` `bc092fd5`; line numbers are from that tree.

The rule exists because an event the double accepts and the adapter rejects is
an event no producer can write, so a test standing on one proves a behaviour
production cannot show. Two doubles break it in **opposite** directions: one
accepts more than production, the other shows less.

## a) The double checks one of two conditions and claims both

`MockEventStore::append` (`crates/hort-app/src/use_cases/test_support.rs:2649`)
calls `validate()` on every event of every batch, and its own comment justifies
that by saying the production adapter does it in `validate_and_serialize`.

`validate_and_serialize`
(`crates/hort-adapters-postgres/src/event_store.rs:1427-1444`) does **two**
things: `event.validate()?` **and** a 64 KB cap on the serialised event
(`MAX_EVENT_JSON_BYTES = 65_536`, `:95`), refused with
*"serialized event {type} exceeds 64 KB limit ({size} bytes)"*. The double took
the first half. The comment names the function that contains both, so the
justification grew and the check did not.

**Why this cannot be fixed by adding a number to the double.** The cap is a
private `const` in `hort-adapters-postgres`, and `hort-app` must not depend on
an adapter (ADR 0008 — the dep graph is load-bearing). So a second copy of
`65_536` in the double is the only *local* fix available, and a second copy is
what this whole ticket is about.

**The cap is a domain rule sitting in an adapter.** Its own doc comment says so:
*"the 64 KB cap catches anything future event types might slip through"* — it is
a validation policy about events, not a Postgres limit (a `jsonb` column has no
64 KB bound). So: **lift the rule into `hort-domain`**, beside `validate()`,
and have both the adapter and the double consume that one definition. The
double then refuses the same input with the same error, because there is only
one rule to refuse with.

Keep the adapter's behaviour identical — same error variant, same message —
because that message is what an operator sees.

## b) The double accepts a paired write and shows one half

`MockArtifactLifecycle` (`test_support.rs:2829`) accepts commits without making
their events visible to a later `read_stream`. Visibility exists only through
`with_commit_visible_events` (`:3008`) — **opt-in**, while production has no
opt-out: the adapter writes the row and the events in **one** commit.

Two independent units hit this on 2026-11-03: #404 needed the opt-in to see
what a second mint attempt reads, and #400's hold event needed it so a second
verify sees the previous hold.

**Impact.** A test asserting "after the commit X reads nothing" or "X appends
again" passes because the double returns nothing — not because the code does
not do it. That is the mirror image of (a): there a test proves something over
material production never produces, here over an **absence** production never
shows. Both times the premise is in the double and not in the test, and both
times reading the test does not reveal it.

**Build: make the pairing the default.** A double that accepts a paired
production write serves both halves or refuses the call. `with_commit_visible_events`
becomes unnecessary, or becomes the exception with its reason stated. This
reaches every test that builds the double — which is the point, and is why an
opt-in was not enough: it only ever reached the tests that already knew about
it.

Expect fallout and treat it as the finding: a test that was green **only**
because the commit was invisible is exactly what this change is for. Name each
one in the report. Do not weaken the default to keep a test green.

Both doubles are used by **eight** crates each (re-measured 2026-11-04:
`grep -rl '<name>' crates/ --include='*.rs'`, aggregated per crate), so the
blast radius is wide and shallow.

## c) A third candidate in the same family — confirm or discard first

From review pass 2, **not re-verified**: a rejected mock commit might leave
content-reference edges behind. On today's tree `commit_transition` checks
before inserting (`test_support.rs:3336`, with the failure checks ahead of the
inserts), so the ordering holds there. The two siblings are the open question:
`commit_transition_with_enqueues` (`:3447`) and `commit_transition_with_score`
(`:3503`).

**The first step of this unit is to confirm or discard (c), and to report the
result either way.** A discarded candidate is a good outcome, not a missing
one.

## Also: the rule's own text

`CLAUDE.md`'s passage covers validity and not visibility. Extend it with the
visibility half — *a double that accepts a paired production write serves both
halves or refuses the call* — and correct the crate count it carries while in
there (**eight**, not nine, for `MockEventStore`).

## Acceptance

1. An event whose serialised form exceeds the cap is refused by the double with
   the same error the adapter returns — shown by a test.
2. The cap and its message have **one** definition, consumed by both the
   adapter and the double. No second numeric literal anywhere.
3. The adapter's observable behaviour is unchanged: same error variant, same
   text, same boundary (`>` the cap, not `>=`).
4. A commit through the double is visible to a later `read_stream` without a
   test asking for it — shown by a test that does **not** use the opt-in.
5. Every test that had to change is named in the report with the reason it was
   green before. A test that only passed because the commit was invisible is a
   finding, not an adjustment.
6. (c) is confirmed and fixed, or discarded with its reason.
7. `CLAUDE.md` states both halves of the rule and the corrected count.

## Read first

- `crates/hort-app/src/use_cases/test_support.rs:2440-2700` — `MockEventStore`,
  its `append` and the comment that states the rule it half-implements.
- `crates/hort-app/src/use_cases/test_support.rs:2829-3010, 3336-3560` —
  `MockArtifactLifecycle`, the opt-in, and the three commit methods.
- `crates/hort-adapters-postgres/src/event_store.rs:1400-1450` —
  `validate_and_serialize`, both of its checks and the message.
- `CLAUDE.md` → *A test double that round-trips must refuse what production
  refuses*.
