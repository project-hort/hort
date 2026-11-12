# 410 — The locks open together, or not at all

**Issue:** #288 · **Branch:** `agent/288-the-span-measures-time-in-the-state` ·
item 2 of 2. **Depends on item 1** — it consumes the state-entry resolver.

**Governing decisions:** #281 D1 (the exception is decided), ADR 0007
(invariant 1 — **changed here**, not circumvented), ADR 0039 D4 (the
indefinite hold and operator-confirmed disposal — **changed here**), ADR 0054
(one spot assumes a purge removes the last row), ADR 0012/0037 (authority via
grants). **This item amends ADR text; the issue carries `no-auto-merge` for
that reason.**

## The property

**An artifact in a held state expires only when a policy says that state may
expire, and only after the span has run in that state — and the purge checks
the authority of the expiry decision, never the bare status.**

## The locks, with their current anchors — **five, not four**

**Corrected 2026-11-09 after an outside review of this approach.** This item
said four. The review derived the census from the code instead of checking
the list, and found a fifth artifact-level gate plus a sixth veto of a
different kind. That matters more than a miscount: **opening four of five
leaves one shut**, and an operator then sees a policy that declares an
exception against a system that silently does not honour it — worse than
opening none.

Every line reference in the issue has rotted; these are verified on `develop`
at `bdc502d1`:

0. **The `ranked` CTE is a separate effective gate** — the one this item
   missed. `retention_candidate_reader.rs:285-301` filters status a second
   time, and `JOIN ranked rk ON rk.id = a.id` (`:316-319`) **drops a held row
   even if the `page` CTE is widened**. Its meaning is also distinct: it ranks
   *usable siblings only* for `KeepLastN`
   (`crates/hort-domain/src/ports/retention_candidate_reader.rs:64-89`).
   So widening the page alone changes nothing, and widening both naively
   would let a held candidate occupy a `KeepLastN` slot it must not hold.
   Preserve the usable-sibling meaning and change the inner join / decoder so
   a held candidate can reach age evaluation **without** taking a slot
   (`retention_candidate_reader.rs:197-235,285-319`).

1. **The candidate reader's `page` CTE filters before any predicate** — the SQL at
   `crates/hort-adapters-postgres/src/retention_candidate_reader.rs:273`,
   bound from `gc_protected_quarantine_status_names`
   (`crates/hort-adapters-postgres/src/lib.rs:153` over the constant at
   `:146`), contract stated at `retention_candidate_reader.rs:78-79`.
2. **The evaluator re-checks** — `evaluate_one` at
   `crates/hort-app/src/use_cases/retention_use_case.rs:350-370`: a
   `Quarantined` arm and a `Rejected | ScanIndeterminate` arm, both logging
   with the `inv1:` prefix and returning `EvalStep::SkippedProtected`.
3. **The pending-purge reader filters** —
   `crates/hort-adapters-postgres/src/purge_gc.rs`, contract at `:18`.
4. **The purge asserts it a third time** — `PendingPurge::is_gc_protected`,
   documented at `crates/hort-app/src/use_cases/purge_use_case.rs:74-115`,
   reported as `skipped_protected` vs `skipped_protected_under_lock`
   (`:206-207`).

**They must open together.** This is measured, not argued: the first real
retention dry run (2026-11-08) reported `evaluated: 4036` and
`skipped_protected: **0**` — zero because lock 1 excluded the protected rows
in SQL before lock 2 could ever see one. Open lock 1 alone and lock 2 starts
refusing and that counter jumps; open locks 1–3 and the purge refuses with a
warning.

**And lock 4 must not simply go away.** It is the defence against the
accidental case. The correct shape is that the authority hangs on the
**expiry decision** — the artifact reached `ArtifactExpired` through a policy
that explicitly includes these states — and the purge checks *that* rather
than the bare status. **How the authority travels from the policy into the
purge is the core of this item**, not a detail. Lock 4's existing reporting
split (`skipped_protected` / `skipped_protected_under_lock`) is where the
refusal of an unauthorised pending row lands; it does not need inventing.

**`quarantine_status` is one of four protection facts**, not the only one
(`purge_gc.rs:85` names them). Opening this lock must not loosen the other
three — a test pins that a tag-targeted artifact is still protected after
this item.

## A sixth veto, of a different kind — and one thing not to touch

**The evaluator's `(policy_id, artifact_id)` idempotency test**
(`retention_use_case.rs:378-399`) is not a status gate but it vetoes exactly
this case. Held states are re-enterable — item 1 established that against the
transition table — so an **ordinary** expiry by policy P, followed by a fresh
rejection before the purge runs, stops P from recording a new held-state
expiry. **An old ordinary event must not authorise that new occupancy at
purge.** Let a later held occupancy record a new authorised expiry despite an
older expiry by the same policy.

**Do not open the SQL gates by removing the three statuses from
`GC_PROTECTED_QUARANTINE_STATUSES`.** That constant also drives refcount
repair (`crates/hort-adapters-postgres/refcount_reconcile.rs:173-182,220-229`)
and the **hash-level** protected-claimant query (`purge_gc.rs:451-479`), and
those protect *shared bytes* — not the candidacy of the artifact being
expired. After a successful preparation the target row is retired
(`purge_use_case.rs:86-93`), so that query's `deleted_at IS NULL` already
excludes the target while still protecting a *different* live held claimant
of the same content. Both safeguards stay.

## What to build

1. **A state opt-in on the `RetentionPolicy` spec**, default empty,
   validated at apply time.

   **"Has an age predicate" is not a sufficient condition, and this item said
   it was.** The review's sharpest finding, with three parts:

   - **`AgeExceeds` measures `artifact.created_at`, not held-state entry**
     (`crates/hort-domain/src/retention/evaluate.rs:169-176`;
     `retention_use_case.rs:490-512`) — the exact content-anchor conflation
     item 1 exists to prevent. An opted-in policy's age bound must be
     **re-anchored to the state-entry event**.
   - **`HasFindingDetectedFor` measures vulnerability age**
     (`evaluate.rs:201-211`), not time in the state.
   - **An `Or` can carry an age predicate and still match immediately**:
     `Composite(Or, [AgeExceeds(30 days), HasFindingAboveSeverity(…)])`
     satisfies "has an age predicate" and matches at once through the
     severity arm, and the existing validator accepts `Or` while validating
     children individually (`predicate.rs:173-197`).

   **So the condition is: a positive held-state age bound on *every*
   successful branch**, re-anchored to the state entry, and a policy whose
   predicate can match a held artifact without one is rejected at apply.
   `UnusedFor` is already rejected at apply while its download anchor is
   absent (`apply_config_use_case.rs:748-751`) — the same shape.

   **And default-empty is decision-inert but not operationally inert.** If
   the shared candidate query is widened unconditionally, held rows consume
   bounded pages and increment per-policy evaluation and skipped counters
   (`retention_candidate_reader.rs:270-279`;
   `task_handlers/retention_evaluate.rs:174-185`;
   `retention_use_case.rs:274-320`). **Keep the old enumeration when no
   active policy opts in**, and for a mixed run retain the evaluator's
   per-policy skip. The old wording — **an opt-in without an age predicate is rejected
   at apply**, so "delete immediately" cannot arise by omission.
2. **The span resolved from item 1's state-entry resolver** — called on the
   stream `evaluate_one` **already read**, not from a new read. Item 1
   deliberately added no port and no SQL because that read already happens
   (`retention_use_case.rs:387`); re-adding one would reintroduce the
   round-trip its deviation removed. Note the ordering constraint this
   inherits: the four locks' status check sits **before** the stream read
   (the `inv1:` arms), so opening lock 2 must leave a held artifact reaching
   the read, or the resolver has nothing to read. The span is never taken
   from
   `quarantine_window_start`. No entry event ⇒ no span ⇒ no expiry.
3. **The authority is an additive, immutable snapshot on `ArtifactExpired`,
   and it must identify *this occupancy*.** The review confirmed the
   authority is constructible — the evaluator holds the policy and the full
   stream when it appends (`retention_use_case.rs:387-399,694-717`), and the
   purge adapter already reads `ArtifactExpired` JSON for `KeepLastN`
   (`purge_gc.rs:258-285`) and re-reads protection facts under the artifact
   row lock before its first destructive statement (`:823-884,918-945`). So
   no new service and no lookup of a policy that may since have changed.

   **But `opted_in: true` or the status name is not enough.** The same held
   state can be re-entered, and item 1's resolver returns state and timestamp
   but **not the entry event's stream position**. Carry the **entry event's
   stream position** alongside the opted-in status, and require the current
   status *and* the latest entry event to match at the locked preparation.
   Otherwise **an expiry recorded for an earlier rejection can purge a new
   rejection before its span has elapsed.** A legacy event without the
   snapshot supplies **no** held-state authority.

   Check authority **before** creating the worklist: the existing-worklist
   path deliberately resumes after the first destructive preparation without
   repeating the status guard (`purge_gc.rs:887-906`), so a late check would
   make a crash retry strand an already-prepared purge.

4. **`ArtifactExpired` needs a payload discriminator** — a held-state expiry
   is currently indistinguishable from an ordinary one, and that is a
   behaviour question rather than an audit-presentation one. The payload has
   no held-state field (`artifact_events.rs:1430-1452`), and its decision
   readers are the evaluator's `policy_id` idempotency check
   (`retention_use_case.rs:391-399`) and purge's work-item membership plus
   `KeepLastN` reason check (`purge_gc.rs:278-285,687-707`). Other readers
   classify the same type for subscriptions and repository disclosure, and
   the events API serialises the whole payload — none decides purge
   eligibility, but without a discriminator none of them can tell a
   policy-authorised evidence expiry from an ordinary one either. **Preserve
   the event type**, make the distinction additive in the payload, and let
   historical events decode as carrying no held-state authority.

5. **The old lock 4 wiring**, with lock 4's
   protection against the accidental case intact and still covered by a test:
   an artifact that reaches the pending state without such authority is
   refused.
6. **Amend ADR 0007 and ADR 0039, and the one spot in ADR 0054 — within
   these bounds.** The review could not rule on the amendments because this
   item supplies no replacement text and does not reproduce #281 D1's bounds;
   that is fair, and the **wording goes to the maintainer before it lands**
   regardless. It did delimit the minimum consistent edit, and these bounds
   are now binding on the wording:

   - **ADR 0007 keeps** its status-gated downloads and its six-authority
     *release* predicate (`docs/adr/0007-…:13-27`) untouched. Only the
     scanner-recovery and descendant-hold promises (`:43-52,79-83`) need the
     qualification that an independently authorised retention policy may
     dispose of the artifact after time in that held state.
   - **ADR 0039 D4 keeps** the absence of a signing deadline. What changes is
     its categorical exclusion of retention and its operator-only disposal
     claim (`docs/adr/0039-…:776-784,820-846`) — and D4 **already** names an
     explicit retention rule as the answer if storage cost becomes
     load-bearing (`:839-846`).
   - **A blanket time-based end to the provenance hold, or an automatic
     release or rejection, licenses more than was decided.** That is the
     failure mode here — an amendment that permits more than #281 D1, not a
     missing one.
   - **ADR 0054's last-row note** (`:110-116`) already describes a last-row
     purge's conservative effect; any clarification must leave that effect
     unchanged.

   ADR 0039
   calls the hold indefinite, enumerates its exits exhaustively, says
   retention is not one of them, and grounds it in disposal being
   "operator-confirmed and never automatically". ADR 0007 promises
   self-healing after scanner recovery and holding a descendant until cascade
   or admin release. Both promises change. ADR 0054 has a spot that assumes a
   purge removes the last row. **The amendments are part of this MR, not
   follow-up work** — an ADR that still forbids what the code does is the
   defect this project has had to fix twice this week.
7. **Correct #244.** Its item 2 is already marked superseded; the overview
   becomes the preview of what the span will take.

## Acceptance

- **Without the state opt-in, nothing changes**: all three states stay locked
  at all four places. A test pins this, and it is the most important test in
  the item.
- With the opt-in and an elapsed span, an artifact in such a state expires
  and is purged.
- **The span measures time in the state**: an artifact rejected yesterday
  whose content is a year old does **not** expire under a 30-day span. This
  case decides whether the span exists at all.
- An artifact reaching the pending state without policy authority is still
  refused by the purge — lock 4 remains effective.
- A tag-targeted artifact is still protected: the other three protection
  facts are untouched.
- **Every** successful branch of an opted-in policy's predicate carries a
  positive held-state age bound, re-anchored to the state-entry event, and a
  policy that can match a held artifact without one is rejected at apply.
  The test that decides this is an `Or` whose other arm matches immediately
  (`Composite(Or, [AgeExceeds(30d), HasFindingAboveSeverity(…)])`) — "has an
  age predicate" must not pass it.
- With no active policy opted in, the **old enumeration** runs: no held row
  consumes a page slot and no per-policy counter moves. Asserted on the
  counters, not only on the absence of expiry.
- A held candidate reaches age evaluation **without** occupying a `KeepLastN`
  slot, and the usable-sibling meaning of the rank is preserved.
- `ArtifactExpired` carries an additive held-state discriminator **and** the
  entry event's stream position; the locked preparation requires the current
  status and latest entry event to match it, and a legacy event without the
  snapshot authorises nothing. The decisive test: an expiry recorded for an
  earlier rejection must **not** purge a later rejection whose own span has
  not elapsed.
- A later held occupancy can record a new authorised expiry despite an older
  expiry by the same policy.
- Authority is checked **before** the worklist is created, so a crash retry
  cannot strand an already-prepared purge.
- The ADR amendments are in the MR.
- DB-backed tests carry `#[serial(hort_pg_db)]`; the change adds no uncovered
  lines; no ticket numbers in code comments.
