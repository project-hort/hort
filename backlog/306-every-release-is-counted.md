# 306 — Every release is counted, and every manual decision is listed

**Issue:** #345 · **Branch:** `agent/345-curation-owns-the-manual-release`
**Governing decisions:** `docs/metrics-catalog.md` is the canonical metric
contract (a label value that exists in code and not in the catalog is a defect
in one of the two).

**Depends on item 304** — with one manual path left, the counter has one place
to be emitted from.

## What is true today — measured

Two counters, and neither counts every release:

- `emit_release` (`quarantine_use_case.rs:82`) is called **only** in
  `quarantine_use_case.rs`: twice on the timer path (`:688`, `:2052`) and once
  on the admin path (`:1760`). **A curator waive increments nothing on
  `hort_quarantine_released_total`** — the curation path emits
  `hort_curation_decisions_total` instead.
- `docs/metrics-catalog.md:1344` documents `reason ∈ timer, admin,
  policy_re_evaluation`, which matches the code and is therefore *consistent*
  — and both are consistently blind to the curator half.
- The decision log is the mirror image:
  `curation_decisions_repository.rs:13` discriminates
  `event_data->'data'->>'released_by' = 'Curator'`, so an admin release never
  appears in `GET /api/v1/admin/curation/decisions`.

Neither is a defect today — the curator how-to names the event stream as the
complete reconstruction — but both are costs of the two paths, and after item
304 there is one path to fix them at.

## What to do

1. **The manual release increments `hort_quarantine_released_total`** with
   `reason = "curator"`. Add `values::REASON_CURATOR` beside the three existing
   constants (`crates/hort-app/src/metrics.rs:209`–`:213`) and call
   `emit_release` from the one manual path. A counter named
   `quarantine_released_total` that misses a release kind is the kind of
   half-truth an operator builds an alert on.
2. **Update the catalog row** (`metrics-catalog.md:1344`) to
   `reason ∈ timer, curator, policy_re_evaluation` — `admin` leaves the live
   set with item 304's removal, but say in the report that **historical series
   keep the label value**, so a dashboard query over a long range still sees it.
3. **The two Grafana panel descriptions** that enumerate the values —
   `deploy/observability/grafana/dashboards/hort-operational.json:1969` and
   `hort-performance.json:954` — name the new set. The `sum by (reason)`
   queries need no change.
4. **Pin the decision log's completeness with a test, not with prose.** After
   item 304 every manual release writes `released_by = Curator`, so the
   listing's discriminator is complete by construction. Add the test that says
   so: a manual release of a `ScanIndeterminate` artifact appears in
   `list_decisions`. That is the assertion that would have caught the old
   asymmetry, and it is cheap now that it holds.
5. **Leave `hort_curation_decisions_total` alone.** It counts decisions
   (waive / block / exclude / unexclude), not releases; the two counters answer
   different questions and merging them would lose the block and exclusion
   arms.

## Explicitly out of scope

- New metrics, new labels beyond the one reason value, and any alerting rule.
- The `hort_curation_decisions_total` label set.
- Backfilling historical series.

## Acceptance

- A curator waive increments `hort_quarantine_released_total{reason="curator"}`
  — asserted in the use-case test, the way the existing release-metric tests do
  it.
- `docs/metrics-catalog.md`'s row and the two dashboard descriptions agree with
  the live label set, and the report states that `admin` remains in historical
  series.
- A manual release from `ScanIndeterminate` appears in
  `CurationUseCase::list_decisions`.
- Gate: the **unit gate**, one-shot capture:
  `bash handover/gate-unit.sh -p <the crates this unit touches>` — check, fmt,
  clippy and those crates' tests, with a full per-step log under
  `handover/gatelogs/`. Judge by the output, not the rc, and quote the test
  totals. Do **not** run `cargo test --workspace`, `cargo audit`, `cargo deny`
  or the attribution script: together they take 15–25 minutes, longer than a
  worker's foreground tool window, so the harness backgrounds them and the run
  ends with the gate killed and the report lost. The architect runs the full
  gate on the same tree before any MR; a red workspace-wide step becomes a new
  directive, not an in-run fix. Write the report before exiting.
