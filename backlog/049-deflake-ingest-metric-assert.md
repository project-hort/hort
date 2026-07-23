# 049 — #79: de-flake the E2E ingest-metric assertion (release-gate flake)

**Issue:** #79
**Read first:** `scripts/native-tests/lib/common.sh` (`assert_metric_ingest`, ~L50-66 — the
single point-in-time scrape that flakes), `scripts/native-tests/scenarios/clients/pypi.sh`
(assert ordering), sibling scenarios (npm/cargo/maven) for the passing contrast,
`crates/hort-http-pypi/src/simple_index.rs` (#72's Mode-2 background prefetch — the async
ingest the assert may race).

## Problem (release-gating, evidenced)

`clients/pypi` intermittently fails `assert_metric_ingest pypi` — the helper does ONE
`/metrics` scrape and greps for `hort_ingest_total{format="pypi",result="success"}`. The
v0.9.13 final release attempt 1 failed exactly here (whole publish chain skipped, 0 assets);
the identical commit passed on re-run. Classic completion-vs-scrape timing race — plausibly
widened by #72 (the ReleasedOnly cold-index bootstrap makes the first pypi ingest a
**background** prefetch task, so the moment of counter increment shifted later relative to
the scenario's client-visible success).

## Fix

1. **De-flake the shared helper:** `assert_metric_ingest` polls `/metrics` with a bounded
   retry (e.g. every 2 s up to ~60 s; constants near the helper, consistent with the suite's
   existing wait/retry idioms — check `lib/common.sh` for an existing poll helper to reuse)
   and fails only on timeout. Every scenario using it benefits; passing runs get no slower
   (first poll hits).
2. **Check the pypi scenario's assert ordering vs #72:** if the scenario asserts the metric
   at a point where the ingest is only *enqueued* (background prefetch) rather than
   completed, ensure a completion-anchored step precedes it (e.g. the artifact download
   succeeding — which the scenario already exercises — or reorder so the metric assert
   follows the confirmed ingest). If #72 legitimately changed first-fetch metric semantics,
   align the scenario to the new contract and say so in the report.
3. **Sweep for siblings:** any other single-scrape metric assertion in the suite gets the
   same poll treatment ONLY if it's the same shape (don't gold-plate; name what you left).

## Acceptance

- `assert_metric_ingest` retries bounded, fails only on timeout; shellcheck-clean like the
  rest of `lib/`.
- pypi scenario's assert ordering is verified sound against #72's async bootstrap (or fixed).
- Full gate green (`cargo test --workspace` — no `.rs` expected; the native-tests scenario
  contract lint if one exists).
- NOTE: the E2E itself can't run in the sandbox (no docker/compose) — reason the change
  from source, state that plainly in the report (as prior E2E directives did).

### Starter prompt

```
/hort-architect

Implement backlog item 049 (issue #79) on branch agent/79-deflake-ingest-metric. IMPORTANT:
verify `git branch --show-current` before every commit — never develop. De-flake
assert_metric_ingest in scripts/native-tests/lib/common.sh (bounded poll instead of a single
scrape, reuse the suite's wait idiom), verify clients/pypi.sh's assert ordering against
#72's background-prefetch ingest (reorder/anchor if racy), and apply the same poll only to
same-shaped single-scrape metric asserts (name anything left as-is). E2E can't run in the
sandbox — reason from source and say so. Full gate; report per the handover protocol.
```
