# 216 — Pin the gitops apply metric's render, and make the smoke say what it saw

**Issue:** #277 · **Branch:** `agent/277-gitops-metric-render`
**Governing decisions:** ADR 0052 (scoped `/metrics` read). No new decision — this
closes an observability gap and a diagnostic gap, it does not change what is measured.

## Why

The `gitops/gitops` smoke failed on the GitHub native-tokens lane while the boot apply
had demonstrably **succeeded**. From that run's server log, one process, no restart:

```
12:22:09.950  gitops boot: starting
12:22:10.215  save_managed (gitops apply)      <- last of 41
12:22:10.242  gitops apply complete            created=144
12:22:10.295  admin /metrics listening
```

`classify_and_emit_apply_metric` (`crates/hort-server/src/gitops_boot.rs:138`, `:593`)
runs unconditionally right after that and increments
`hort_gitops_apply_total{result="ok"}`; the recorder is installed far earlier
(`crates/hort-server/src/cli/serve.rs:172`, the boot follows at `:291`). The scrape at
**12:25:55** returned HTTP 200 and carried `hort_gitops_objects_total` — emitted in the
*same 250 ms window* by `hort-app` — but not `hort_gitops_apply_total`. One `metrics`
version in the lockfile (0.24.6), so there is no second facade; only one apply ran, so
the object counter is not from a later reconcile.

Nothing in the repository pins either fact: `git grep hort_gitops_apply_total` finds the
emission, a comment and the smoke — no test asserts it ever reaches a render. And the
smoke cannot tell "absent" from "present with a different result label", because
`metrics_scrape_diag` reports only the HTTP status.

## Scope

1. **Pin the render in-repo** (`crates/hort-server`, unit test, no DB, no network). Using
   the in-repo precedent for recorder-scoped tests — `PrometheusBuilder::new().build_recorder()`
   plus `metrics::with_local_recorder`, as `crates/hort-server/src/http.rs:514` does —
   emit the boot-apply metric for a successful apply and render the handle. Assert the
   rendered text contains a line that the smoke's own predicate would match, i.e.
   `hort_gitops_apply_total{...result="ok"...} N` with `N >= 1`. Add the failure-label
   counterpart (one of `parse_error` / `validation_error` / `apply_error`) so the test
   also pins that a failed apply renders a **different label**, not nothing.
   Reach the metric through the smallest honest surface: if
   `classify_and_emit_apply_metric` must become `pub(crate)` for the test, that is
   fine; do **not** restructure the boot path to make it testable.
   If this test **fails**, stop: the defect is in the emission/render path itself, the
   rest of this item is moot, and the report must say so with the rendered text.
2. **Make the smoke report what it actually saw.** In
   `scripts/native-tests/scenarios/gitops/gitops.sh` and the shared helper
   `metrics_scrape_diag` (`scripts/native-tests/lib/common.sh`): on failure, include the
   HTTP status (as today) **plus** the byte and line count of the body and every
   `hort_gitops_`-prefixed line, or an explicit "no hort_gitops_* lines in body" when
   there are none. Keep it bounded — cap the dump (say 40 lines) so a runaway body
   cannot bury the log. The point is that the next failure distinguishes the three
   cases without a re-run: metric absent, metric present under another label, body
   truncated.
3. **Correct the failure wording.** `metric absent or zero` asserts more than the check
   can know; state what was searched for and what was found.

## Explicitly not

- No change to what is emitted, to label values, or to the metrics catalog.
- No change to the boot path's behaviour, no new metric.
- Do not "fix" the smoke by relaxing the assertion or extending the 15 s bound: the
  apply completes in ~300 ms, so a longer wait would only hide the question.

## Acceptance

- A `hort-server` test fails if `hort_gitops_apply_total{result="ok"}` stops reaching a
  Prometheus render, and a second one pins the failure-label shape.
- A failing gitops smoke prints the `hort_gitops_*` lines it saw (or their absence) plus
  the body size, bounded.
- The report states plainly whether point 1's test passed on the first run — that single
  fact decides where the defect lives.
- Gate green: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, `cargo-audit audit --deny warnings`, `cargo deny check`;
  `bash -n` on both touched shell files.
