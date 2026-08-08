# 084 — #130: base-lane residuals — posture-aware metrics call-site sweep + required-multilayer hold-read rework

**Issue:** #130 (release gate; final item). The 2026-08-08 base-lane gate run
(develop@fb17b3e8, triage on the issue) left exactly two residual failure
classes; both are harness-side, zero production code. One reviewable unit.

## Class 1 — metrics call sites missed by the item-079 rework (2 scenarios)

Directive 070 gated the token threading and verified the
`assert_metric_ingest` call sites — but two OTHER metrics-consumer shapes
hard-fail (or silently mask) when the base lane runs with `METRICS_TOKEN`
empty:

- `scenarios/gitops/gitops.sh` — its own metrics-reachability probe treats
  the (now inevitable) 401 as FAIL ("metrics endpoint responds :: … HTTP 401").
- `scenarios/proxy/oci-mirror.sh` — before/after
  `hort_upstream_fetch_total{result=success}` delta scrapes read a 401 as
  value `0` (masked), so the Δ asserts fail while every pull PASSes.

**Work:**
1. Grep-driven inventory FIRST: every direct `/metrics` scrape in
   `scripts/native-tests/` outside `assert_metric_ingest` (`grep -rn
   'METRICS_URL\|:9090/metrics' scenarios/ lib/`), listed in the report — no
   third class may remain.
2. Apply the posture rule to every hit: with `METRICS_TOKEN` empty →
   note-and-skip the metrics assertion (same semantics/wording family as
   `assert_metric_ingest`'s unset branch); with a token present → non-2xx is
   a loud FAIL carrying the HTTP status (no masking a scrape failure as
   value 0 — extend the shared scrape helper, or introduce one in
   `lib/common.sh` if the call sites are bespoke curls).
3. Scenario pass/fail accounting: a skipped metrics assert must not flip a
   scenario's overall result (gitops smoke must PASS on the base lane when
   its non-metrics asserts pass).

## Class 2 — `proxy-required-multilayer.sh` anonymous cold GET (same class item 080 fixed)

Step 1 (`:206-221`) is a deliberately **anonymous** cold index GET expecting
200; the designed hold answers 503 (+`Retry-After`). Mirror the now-merged
zero-window shape (`proxy-multiarch-zero-window.sh` on this branch's base —
read it first; it is the template):

1. New anonymous step asserting **503 + `Retry-After` present + body code
   `UNAVAILABLE`** (the hold's regression pin; performs the cold ingest).
2. The existing index/child GETs become authenticated (legacy mode:
   `DEV_TOKEN` — already fetched at `:190`; native mode: the svc token the
   scenario mints) → 200 via the write-authorized hold-read exemption.
3. Downstream constituent-hold/clearing asserts unchanged unless an
   expectation is directly falsified by the auth change — if one is, STOP on
   that assert and report rather than adjusting it silently.

**Merge-coordination note:** `proxy-required-multilayer.sh` was also touched
on `agent/133-native-lane-gate` (item 081: mint-helper call sites +
negative pin, commit `aaf6545c`, different region of the file). This branch
is cut from develop, which does NOT contain that change — do not try to
incorporate it; the #133 branch rebases later.

## Scope / acceptance

- Zero `crates/` changes; zero `deploy/` changes; `run.sh` untouched;
  `lib/common.sh` only for the shared scrape-helper semantics of Class 1.
- `bash -n` on every touched script; full pre-push suite (expected Rust
  no-op; run anyway).
- Acceptance vehicle (for the human's rerun): plain
  `run.sh --hort=compose` — expected FULLY green; overlay-lane behavior
  unchanged.

**Model hint:** sonnet.
