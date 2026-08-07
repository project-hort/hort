# 073 — #130 classes A+C: base-compose bearer-transport opt-in + harness diagnosability + provenance poll bound

**Issue:** #130 (E2E gate triage; class A + C directions human-confirmed on the issue,
2026-08-07). Class B (the two 503 cold-pull failures) is explicitly OUT — it stays
open on #130 pending evidence.

**Read first:** the root-cause comment on #130;
`crates/hort-http-core/src/middleware/auth.rs` (`pat_over_http_decision`, the 426
gate — context only, DO NOT change product code);
`deploy/compose/docker-compose.yml` `hort-server` env (`HORT_METRICS_PUBLIC_BIND`'s
DANGER-comment shape at ~:243-258, and the overlay precedents
`docker-compose.native-tokens.yml:42` / `docker-compose.federation.yml:70`);
`scripts/native-tests/lib/common.sh:104-118` (`assert_metric_ingest`);
`scripts/native-tests/scenarios/gitops/gitops.sh:24-32`;
`scripts/native-tests/scenarios/quarantine/provenance-push-then-sign.sh` (the 300s
`bounded_poll` in step 6/6).

## Work

1. **Base compose transport opt-in (class A fix):** add
   `HORT_BEARER_ALLOW_OVER_HTTP: "true"` to the `hort-server` service environment in
   `deploy/compose/docker-compose.yml`, with a DANGER comment in the same shape as
   its neighbor `HORT_METRICS_PUBLIC_BIND` (dev/CI only; plaintext-HTTP compose stack;
   PAT-shaped bearers — the minted `read_metrics` scrape token — are otherwise
   refused 426 pre-auth; production MUST leave it unset; boot warns + sets the
   `hort_unsafe_config_active{kind="pat_over_http"}` gauge). Check whether
   `hort-worker` in the same file needs it too (only if the worker serves/consumes
   PAT-authenticated HTTP — verify, don't assume). Leave the two overlays' existing
   settings untouched (redundant-but-harmless once base has it — note in the report).
2. **Harness diagnosability:** rework the two scrape call sites that discard curl's
   error so the FAIL message carries the real signal:
   - `assert_metric_ingest` (`lib/common.sh`): capture HTTP status and curl exit
     (`-w '%{http_code}'`-style, no `-f`-swallowing) and include both in the fail
     text, e.g. `... returned HTTP 426 (curl exit 0)`. Keep the existing
     METRICS_URL/METRICS_TOKEN skip semantics byte-identical.
   - `gitops.sh` metrics probe: same treatment.
   - Sweep for any other `curl -sf ... "$METRICS_URL" 2>/dev/null` site in
     `scripts/native-tests/` and treat it identically (the second grep site in
     `assert_metric_ingest`'s metric-content predicate included, if it can mask
     status).
3. **Provenance negative poll bound (class C fix):** in
   `provenance-push-then-sign.sh` step 6/6, raise the `bounded_poll` timeout from
   300s to **450s** with a one-line comment stating the invariant: the bound must
   exceed one full sweep-ticker interval (compose ticker: 5 min) plus job latency,
   else phase offset alone can time out a healthy stack. Do not change the fixture's
   `quarantineDuration` or the ticker cadence.

## Scope / acceptance

- **No production Rust code changes.** Compose fixture + harness shell only.
- Gate: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, `cargo audit --deny warnings`, `cargo deny check` (all
  unchanged code — the gate is cheap insurance the tree is untouched), plus
  `bash -n` on every edited shell file.
- **Honest verification note for the report:** the sandbox has no docker daemon, so
  the compose E2E cannot run there. Acceptance evidence is (a) `bash -n` + a diff
  review against this item, and (b) the human's local
  `./scripts/native-tests/run.sh --hort=compose --group clients --keep` run
  (expected: the three `ingest metric` FAILs and the gitops metrics FAIL flip to
  PASS) — state this explicitly rather than claiming E2E verification.
- Comments state invariants only — no issue numbers/provenance.

**Model hint:** sonnet (three small mechanical edits; the discipline point is NOT
touching product code).
