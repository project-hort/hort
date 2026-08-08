# 095 — E2E stack: scale hort-worker replicas — serial scan pipeline is the release-throughput floor

**Issue:** #135 (acceptance-blocking rider #2) · **Branch:** `agent/135-late-joiner-clearance` · **Scope:** harness only (compose file + run.sh)

## Problem (third acceptance red, evidence chain)

With the bounded-await guard in place (backlog 094), steps 9a/9b still
timed out at 120s/90s. The remaining floor is server-side scan
throughput, not client behavior:

- `ScanTaskHandler` is registered with `max_concurrency = 1` per worker
  replica — BY DESIGN ("parallelism via replicas",
  `crates/hort-worker/src/composition.rs`). Trivy invocations are
  CPU/IO-heavy; intra-process parallelism is deliberately not the axis.
- The compose stack runs exactly ONE `hort-worker` replica, so all scan
  jobs serialize at one-per-invocation (~10s effective cadence observed
  across runs: run 1's late-joiner frontier completed in ~209s for ~23
  artifacts; run 3's 9a+9b spent a combined ~210s and still did not
  finish — identical throughput despite the guard removing the
  client-side await tax, which isolates the floor to the scan pipeline).
- Under `Required`, release of a cleared late joiner happens at scan
  completion (inline fast path), so scan cadence IS release cadence:
  ~23 serial scans ≈ 200–230s — structurally above any per-step budget
  satisfying the ±20s / no-300s-waits directives.

The fix honors the designed scaling axis instead of changing code:
run more worker replicas in the E2E stack.

## Change (two files, harness-only)

1. `deploy/compose/docker-compose.yml`, `hort-worker` service: REMOVE the
   `container_name: hort-worker` line (fixed names block `--scale`; all
   tooling addresses the SERVICE name, which is unaffected). Extend the
   service's header comment: scan concurrency is 1 per replica by design;
   the E2E runner scales replicas so serial trivy runtime stays off the
   release critical path. No other change to the service (mem/cpu caps
   are per-container caps, not reservations — unchanged).
2. `scripts/native-tests/run.sh`: when the worker profile is enabled
   (`NEED_WORKER=1`), append `--scale hort-worker=${HORT_E2E_WORKER_REPLICAS:-4}`
   to the `docker compose … up -d --build` invocation. Document the knob
   in the header usage comment. No scale arg when the worker profile is
   off (compose errors on scaling a profile-inactive service).

Expected effect: ~23 scan jobs across 4 replicas ≈ 6 serial waves ≈
60–90s wall, overlapped with 9a's pull loop → 9a green within its 120s
budget, 9b within 90s. Budgets unchanged.

## Acceptance

- `bash -n` clean on run.sh; harness-only diff (exactly the two files).
- If docker CLI is available in the sandbox: `docker compose -f
  deploy/compose/docker-compose.yml config -q` parse check; otherwise a
  note in the report (the YAML edit is a line removal + comment).
- Tom's retest: NO rebuild (worker image unchanged; compose starts N
  replicas of the same image).
