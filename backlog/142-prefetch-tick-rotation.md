# 142 — prefetch_tick cross-tick rotation: no repo or package is page-1-locked out

Issue: #212.

`crates/hort-app/src/task_handlers/prefetch_tick.rs` has three nested caps
and no cross-tick cursor. Two are real defects; the third was verified sound
during grooming:

1. `MAX_REPOS_PER_TICK = 1000` — step 1 is a page-1 read of repositories,
   every tick. > 1000 prefetch-enabled repos ⇒ the rest are never visited.
2. `MAX_PACKAGES_PER_REPO = 1000` — step 3 reads page 1 of
   `list_distinct_names` (byte-stable ordering) and stops. The doc comment
   claims "a repo with more packages walks across multiple ticks" — no
   mechanism for that exists; names past 1000 are never prefetch-refreshed.
3. `MAX_PREFETCHES_PER_TICK = 5000` — **sound, do not redesign**: the budget
   check compares `prefetches_enqueued`, which counts only rows actually
   inserted by `enqueue_prefetch_batch` (`ids.len()`); `ON CONFLICT
   (target_key)` dedupes tally separately in `prefetches_deduped` and consume
   no budget, so the walk self-advances past an already-enqueued head for
   free. Keep the semantics; restructure only as far as the rotation in 1/2
   requires.

**Governing decisions:** the quarantine-release-sweep rotation precedent ·
the `retention_candidate_reader` keyset precedent (`after` cursor +
`ORDER BY id`) as the in-repo model · ADR 0030 (schema changes additive
only, if any).

## Read first

- `crates/hort-app/src/task_handlers/prefetch_tick.rs` — the whole walk,
  the caps, the summary (`prefetches_planned/enqueued/deduped`,
  `budget_exhausted`), the doc comments to correct.
- `crates/hort-adapters-postgres/src/retention_candidate_reader.rs` — the
  keyset model to mirror.
- The repository-listing and `list_distinct_names` port methods the tick
  calls (follow to their adapters) — both need an `after`-cursor variant (or
  equivalent) with a stable total order.
- `crates/hort-app/src/use_cases/test_support.rs` — the mock harness for
  handler tests.

## Confirmed design

**Cross-tick keyset resume, persisted in the tick's own task state.** The
tick persists a cursor — last-visited `(repository_id, package_name)` — and
each tick resumes the walk strictly after it, wrapping to the start when the
end is reached. Storage: the task params/state row of the recurring
`prefetch-tick` job (the tick already owns durable state there); NOT a new
table, NOT a column on `repositories`. Semantics:

- Repos are walked in a stable total order (`ORDER BY id`), packages within
  a repo in `list_distinct_names`' byte-stable order, resuming `after` the
  cursor.
- Budget exhaustion (`budget_exhausted`) saves the cursor at the exact
  stopping point; the next tick continues there — the current
  restart-at-page-1 behavior is what this item removes.
- A completed full traversal wraps the cursor to the beginning (fairness
  across cycles; a fresh repo/package is picked up on the next wrap at the
  latest).
- A cursor pointing at a since-deleted repo/name degrades gracefully: keyset
  `>` comparison simply resumes at the next existing entry.

**Doc-comment truth:** the corrected comments state the actual walk
semantics — full traversal of R repos × N names completes within a bounded,
stated number of ticks (budget-limited), and what the cursor
persists/wraps. The false "walks across multiple ticks" claim is replaced by
the mechanism that now makes it true.

**Bound statement (part of the doc comment):** with budget B = 5000 and
total plannable work W, a full traversal completes in ⌈W / B⌉ ticks; caps 1
and 2 become per-tick page sizes of the rotation rather than hard visibility
ceilings.

## Acceptance

- Fixture with > `MAX_REPOS_PER_TICK` prefetch-enabled repos: every repo is
  visited within a bounded number of simulated ticks (test drives the
  handler repeatedly, asserts full coverage + wrap).
- Fixture with one repo carrying > `MAX_PACKAGES_PER_REPO` names: every name
  is visited across ticks; the tick after budget exhaustion resumes at the
  saved cursor, not at page 1.
- Budget semantics unchanged: dedupes still consume no budget (existing
  tests keep passing).
- Summary gains the cursor position (or an equivalent progress field) so an
  operator can see the walk advancing.
- Comment discipline: invariants only, no issue refs.
