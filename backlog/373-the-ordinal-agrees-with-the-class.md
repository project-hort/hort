# 373 — The ordinal agrees with the class

**Issue:** #399 · **Branch:** `agent/399-reassignment` · item 2 of 4.

The behaviour change ADR 0066 D8 says ships on its own. Unit 363 introduced
the vocabulary and deliberately kept every number where it was; item 372 gives
the last producer that names a number a trigger source so it stops. This unit
makes the numbers agree with the classes.

## What holds

`task_tier.rs`'s own header states it, and a test asserts it rather than
apologising for it:

```
tier_and_ordinal_disagree_today      (crates/hort-domain/src/types/task_tier.rs:645)
  classify("scan", "ingest")  == Interactive   and  queue_priority == 0
  classify("scan", "cron")    == Bulk          and  queue_priority >  0
  queue_priority("quarantine-release-sweep", "cron") == queue_priority("scan", "cron")
```

So an ingest scan — the most waited-on work in the system — carries the lowest
rank, cron rescans that nobody waits on outrank it, and the release sweep ties
with the flood it is supposed to outrank, which is how `created_at ASC` came
to resolve that tie against the sweep. The module says the change that removes
this has to delete that assertion. This is that change.

## The outcome

**`queue_priority` derives the ordinal from the tier**, so the two faces of
`TaskTier` cannot disagree again. The within-class separations that exist
today are facts about volume and must survive the move:

- the manual rescan outranks other `'manual'` rows (an operator is reading
  that answer, the admin invoke is bookkeeping);
- the `seed-import` subcommand's own row outranks the scans it then enqueues;
- the clearance verify outranks the ingest-time verify backlog (item 372).

So the shape is: the tier decides the band, and a small, documented
within-band offset expresses volume. No producer names either number
(ADR 0066 D6).

**`CLEARANCE_GATING_VERIFY_PRIORITY` stops existing here.** Unit 372 left it
`pub` in `task_tier.rs` with no production consumer: it is the recorded
pre-change number, read only by the two clearance producers' tests to prove
their ordinal did not move. Once this unit derives every ordinal from the tier,
that number is part of the band arithmetic and a separate constant for it is
cruft. Remove it, and move those two tests onto whatever the band arithmetic
makes the clearance ordinal — they are asserting "the row's rank is the one the
table decides", which survives the move.

`tier_and_ordinal_disagree_today` is **deleted** and replaced by its
counterpart: an assertion that for every `(kind, trigger_source)` pair the
tables know, the ordinal order and the tier order agree. That assertion must
be exhaustive over `TriggerSource::ALL` rather than a list of examples, so a
future literal cannot be given a number that contradicts its class.

## The two things to get right, both about rows that already exist

1. **The ordinal space is shared with rows an older binary wrote.** ADR 0066
   D7 makes the *classification* safe across a mixed fleet — it is derived, so
   an old row classifies correctly. The *ordinal* is not derived: it is on the
   row, and the claim SQL orders by it. So choose the numbers such that the
   transition cannot invert a waited-on path: a row an old binary wrote at the
   cron ordinal must not outrank a new client-waited row. State explicitly
   what happens to the rows already queued at upgrade time, and keep it
   bounded — they drain, they do not need a migration (D7 again: no backfill).
2. **What the column default means.** `SCHEMA_DEFAULT_PRIORITY` is the `jobs`
   column default, so it is the number a producer that sets nothing gets. It
   must not be the top band: an unclassified row must not be able to displace
   a client-waited one. It is allowed to end up the lowest band, because the
   per-class reservation that follows (next unit) keys on the **tier** — which
   is derived from `(kind, trigger_source)` and not from the ordinal — so a
   row at the default is still protected by its class.

## Acceptance

1. `tier_and_ordinal_disagree_today` is gone, and in its place an exhaustive
   assertion over `TriggerSource::ALL` that ordinal order and tier order
   agree for every pair the tables know.
2. The three within-class separations above are each asserted by name, so a
   future simplification that flattens them fails here.
3. A test that states the upgrade property: a row carrying an ordinal from the
   previous scheme does not outrank a freshly enqueued client-waited row.
   Derive the old numbers in the test rather than importing them, so deleting
   the old constants does not make it vacuous.
4. **No migration and no backfill** — if the change appears to need either,
   stop and report: that contradicts ADR 0066 D7 and means the ordinal was
   treated as stored state.
5. The reported stall's shape is asserted end to end at the SQL level: with a
   backlog of bulk rows pending and one client-waited row newer than all of
   them, the client-waited row is claimed. This is the test the issue exists
   for, and it is **not** yet non-displacement (that is the next unit) — here
   it holds because the ordinal finally says the right thing.
6. `CHANGELOG.md`: one entry — queued work is ranked by who waits on it, so
   scheduled maintenance no longer outranks the publish and release paths.

## Not in this item

- **Non-displacement** (ADR 0066 D4): the per-class reservation at both points
  where capacity is allocated. This unit fixes the ranking; a flood at the
  same rank can still occupy the whole batch, which is exactly why D4 exists
  and why it is its own unit.
- The starvation audit's reach and the alert path (D5).
- The shares themselves, which the ADR leaves to the deployment.
