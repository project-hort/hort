# 079 — #130 corrective: restore base-compose legacy posture; posture-aware metrics assertions

**Issue:** #130 (release-blocker — the develop acceptance run cannot boot).
**Status:** item 1 (compose revert) SHIPPED (`065ef56b`, report 069). Items 2+
re-specified below after report 069's STOP — the original federation-scrape
design was infeasible; this revision replaces it.

## Context

The class-A layer-2/3 fixes (!348 `HORT_BEARER_ALLOW_OVER_HTTP`, !351
`HORT_NATIVE_TOKENS_ENABLED`) bolted native-token *consume* onto the base
compose stack. That was wrong twice over: `HORT_NATIVE_TOKENS_ENABLED=true`
hard-requires an OCI signing key at config parse (`OciTokenSigningKeyMissing`
— the boot failure on develop@1a820ea8), and with a key present it flips the
anonymous `/v2` challenge from `Basic` to `Bearer` — the posture change
`deploy/compose/docker-compose.yml`'s sibling overlay
`docker-compose.native-tokens.yml` deliberately isolates. Item 1 reverted both
env entries; the base stack is back on its designed legacy posture.

## Why the original items 2-5 (federation scrape) were dropped

Report 069 verified in code that **every** path by which a bearer exercises the
`metrics-scraper` ServiceAccount's `read_metrics` grant requires
`HORT_NATIVE_TOKENS_ENABLED=true` server-side:

- SA federation (`federatedIdentities`) is consumed via
  `POST /api/v1/auth/exchange`, which *mints an `hort_svc_*` native token*
  (`exchange.rs`, `pat_validation_use_case.rs:787`) — validating it needs the
  native validator, and the exchange endpoint itself boot-gates on the flag
  (`ConfigError::TokenExchangeRequiresNativeTokens`, `config.rs:2393-2408`).
- A directly-presented Keycloak JWT resolves via the primary OIDC path to a
  JIT-provisioned *human/claims* principal — never to the SA's backing user —
  and an unscoped non-admin `Claims`-subject `read_metrics` grant is
  hard-rejected by the apply-time `wildcard-repo-non-admin` linter rule.
  Overriding that rule is a security-posture relaxation we will not make for
  a test-stack convenience (and would be terrible pedagogy in example-config).

**Decision (architect):** the metrics-content assertion power belongs to the
**native-tokens overlay lane** — that posture is the production shape
(registry.hort.rs) and the PAT scrape is its native mechanism; it was proven
green in the 2026-08-08 overlay run. The base (legacy-posture) lane skips the
metrics-content assertions **with an explicit note**, via the skip path
`assert_metric_ingest` already defines for "no `read_metrics` bearer
available". Making the overlay lane an official second gate lane is #133's
scope.

## Work (revision — replaces the original items 2-5)

1. **`scripts/native-tests/run.sh` — posture-aware metrics-token threading.**
   In compose mode, call `mint_metrics_token` (and hard-fail on mint failure)
   ONLY when `native-tokens` is among the active `--compose-overlay` values
   (the `OVERLAYS` array). Otherwise set `IN_METRICS_TOKEN=""` and log one
   clear harness-level note, e.g.: `metrics-content assertions skip on the
   legacy-posture base stack (no native-token validator) — run with
   --compose-overlay=native-tokens to assert them`. Rationale text should
   state the invariant (PAT consume requires the native-token validator),
   not issue numbers. External mode stays exactly as-is
   (`METRICS_TOKEN` passthrough).
   Downstream, `assert_metric_ingest`'s existing `METRICS_TOKEN unset →
   note + return 0` branch does the per-scenario skipping — do NOT change
   `lib/common.sh` semantics (with URL+token present, non-2xx stays a hard
   FAIL; that is deliberate).
2. **Comment/doc truth pass (small, targeted).**
   - `mint_metrics_token`'s comment block in `run.sh` still says compose mode
     "always" mints — align it with the overlay-gated reality.
   - `grep -n METRICS_TOKEN scripts/native-tests/README.md TESTING.md
     docs/architecture/how-to/operate/metrics-scraper-service-account.md` and
     fix ONLY statements the change falsifies (e.g. "compose mode always has
     … access to mint it"). Add one sentence where the harness lanes are
     described: metrics-content assertions run in the native-tokens overlay
     lane; the base lane skips them with a note.
3. **No other changes.** ZERO edits under `crates/`, zero to
   `docker-compose.native-tokens.yml` (it already carries flag + key +
   transport opt-in and stays the metrics-asserting lane), zero to
   `example-config/` (the metrics-scraper SA + grant stay as-is — they are
   the overlay lane's identity), zero to `lib/common.sh`.

## Scope / acceptance

- After this change: `run.sh --hort=compose` (base lane) must proceed past
  harness setup without minting, and every `assert_metric_ingest` call site
  takes the "METRICS_TOKEN unset" note path — no metrics-related FAILs.
  `run.sh --hort=compose --compose-overlay=native-tokens` behaves exactly as
  today (mint mandatory + fail-loud, assertions armed).
- Gate: full pre-push suite (fmt, clippy -D warnings, `cargo test --workspace`
  with and without `DATABASE_URL`, audit, deny) — expected Rust no-op; run
  anyway.

**Model hint:** sonnet (small, precisely bounded shell + doc change).
