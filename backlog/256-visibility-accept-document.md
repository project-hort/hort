# 256 — The late-commit gap is accepted; say what a consumer can do about it

**Issue:** #309 · **Branch:** `agent/309-visibility-accept-document`
**Governing decisions:** ADR 0061 (store-driven notification delivery — it
names this residual and defers the close to this decision) · ADR 0004 (the
`EventStore` port) · the human's decision of 2026-09-30, quoted below.

## Why

`events.global_position` is a `nextval` evaluated at **INSERT** while the row
becomes visible at **COMMIT**, so a transaction holding the lower position can
commit after a reader has already passed it. A cursor that is a bare
high-water mark never sees it again. ADR 0061 measured the rate — 0.13% to
0.95% of appends stranded at two to eight concurrent writers — and left the
close to this decision.

**The decision is to accept the gap and state it honestly, not to close it in
code.** The human, 2026-09-30: *"Option d für #309 ist akzeptiert."*

Two findings preceded that decision and belong in the durable record:

1. **The naive `xmin` horizon is unsound.** Four append paths
   (`ref_lifecycle::{move_ref, retire_ref}`,
   `artifact_group_lifecycle::{commit_member_added, commit_member_removed}`)
   write their projection before the event, holding a low transaction id
   against a high position. Transaction-id order and position order are not
   coupled, so a horizon may conclude nothing from one about the other.
   `an_xmin_horizon_does_not_close_the_late_commit_race` pins this against a
   live database.
2. **A sound sampled horizon exists and is worse.** Sampling the sequence
   value together with the oldest running transaction, and releasing the
   sampled value only once every transaction running at that sample has
   concluded, is correct — and trades a 0.5–1.9% partial loss for an
   **unbounded total stall**: one long-open transaction, read-only in the safe
   variant, freezes delivery completely. That is the worse failure mode.

**And the loss is detectable**, which is what makes accepting it defensible
rather than merely cheap. Both positions are already on the wire — in the
`GET /api/v1/events` DTO and in the webhook and NATS payloads — so nothing new
has to be exposed for a consumer to use any of this:

- **A gap in `global_position` is visible but ambiguous.** The sequence is not
  transactional: a rolled-back append burns its number permanently, so gaps
  occur in normal operation. A gap is a sound *trigger* for a second query and
  never a verdict.
- **A gap in `stream_position` is exact.** Per stream it is 0-based and
  gapless — the adapter derives it as tail + 1 inside the append transaction
  and the unique index `(stream_id, stream_position)` is the serialiser, so a
  hole cannot occur. A consumer tracking the last position per `stream_id`
  detects a skipped event with certainty, and a first sighting of a stream at
  a position above 0 is the same signal. Two limits, both of which must be
  stated: a subscription carrying an `event_types` filter sees holes by
  design and cannot use this at all; and a skipped event that was its
  stream's last is never revealed, because no successor arrives.
- **Re-reading a trailing window is exact.** Re-read `(H − Δ, H]` over the
  `(stream_category, global_position)` index and compare against what was
  already handled; anything appearing in a window already passed is precisely
  a late committer. It is a bounded index range scan, and it costs nothing
  semantically because delivery is already at-least-once with duplicates — a
  consumer may simply re-handle the window rather than remember it. Δ must
  exceed the longest write transaction; ADR 0061 establishes that bound as
  `lock_timeout`, 120 s on the worker pools.

The documentation says none of this today, and one bullet actively misleads.
Under *Loss and degradation stay observable*, the page offers
`GET /api/v1/events` as the reconciliation mechanism — "checkpointing on
`global_position` and treating re-delivered positions as no-ops" — while that
surface inherits exactly the same gap. A consumer following the page as
written cannot recover the event the page tells them they can.

## What to do

Documentation and the decision record. **No behaviour change, no new knob, no
code path.**

1. **`docs/adr/0061-store-driven-notification-delivery.md`**, section *The
   residual, and why it is not closed here*. It currently says the exact
   reader-side fix is "Deferred to that decision". Replace that deferral with
   the decision that was taken and why, folding in the two findings above:
   the `xmin` horizon rejected on evidence, the sampled horizon rejected for
   the unbounded stall, and the detectability that makes acceptance
   defensible. Keep the existing measurement table and the write-side
   alternatives — they remain the record of what was considered. State
   plainly that the position model does **not** change, so `global_position`
   and `next_after` keep their meaning.

2. **`docs/architecture/explanation/event-notifications.md`.** Two edits:
   - Correct the reconcile bullet. It must no longer present the pull surface
     as recovery for this class of loss, because it shares the defect.
   - Tell a consumer that needs completeness what to actually do. Give the
     three detectors above with their limits stated honestly, including that
     an `event_types`-filtered subscription cannot use `stream_position`
     contiguity. Name Δ's floor and where it comes from rather than leaving
     the reader to guess a number.
   Write it for the external consumer the page is addressed to — a
   replication relay, a SIEM shipper, an SBOM indexer — not for a maintainer.

3. **The two tests in
   `crates/hort-adapters-postgres/tests/event_delivery_visibility.rs`** read
   today as an open defect. After this decision they are the pinned statement
   of accepted behaviour. Give each a doc comment saying so and naming
   **ADR 0061** as the decision — an ADR reference, never an issue number.

4. **Sweep for any other completeness claim that this makes false.** At least
   `docs/architecture/reference/event-taxonomy.md` and the module
   documentation of `crates/hort-http-events/src/handler.rs`. Report what you
   checked, including the files where you found nothing to change.

## Explicitly out of scope

- **No trailing-window lag in the dispatcher.** It was offered to the human
  alongside option (d) and was not taken. Do not add it, do not prepare the
  ground for it, and do not leave a TODO pointing at it.
- No change to `global_position`, `next_after`, or any wire shape.
- No new ADR — ADR 0061 already owns this residual, and amending the owner
  beats adding a second record of the same thing.
- No behaviour change, no new configuration, no new metric.

## Acceptance

- ADR 0061 no longer defers the reader-side question; it records the decision,
  both rejected horizons with their reasons, and the detectability.
- The explanation page no longer offers the pull surface as recovery for a
  late-commit skip, and a consumer reading it can implement detection without
  reading the source.
- Both tests carry a doc comment naming ADR 0061 as the decision they pin.
- No file under `crates/*/src`, `migrations/` or `deploy/` changes except the
  test doc comments in step 3.
- Gate green: `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace`, `cargo-audit audit
  -D warnings`, `cargo-deny check`.
