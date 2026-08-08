# 083 — #133 item 3: native-tokens lane as an official second E2E gate + close the host-tests seam

**Issue:** #133. Dispatched LAST — the lane turns required only once items
081+082 make it green-capable.

**Context:** the base compose lane is the legacy-posture gate; metrics-content
assertions deliberately skip there and are armed only under the native-tokens
overlay (#130 item 079 decision, recorded on that issue). Production
(registry.hort.rs) runs the native posture — the release gate should exercise
it. Separately, `scripts/host-tests/test-rescanning.sh` mints AND consumes an
`hort_svc_*` token against the bare base stack, whose posture has no native
validator — a latent contradiction of the same family (noted on #130).

**Read first:** `.github/workflows/e2e.yml` (current single-lane invocation +
its `workflow_call` role in `release.yml`); `scripts/native-tests/README.md`
lane documentation (touched by directive 070); `scripts/host-tests/run.sh` +
`test-rescanning.sh` stack preflight (`compose_available`, the "bring it up
with" hint); `test-gitops-machine-identity.sh` (already overlay-riding — the
counter-example).

## Work

1. **`e2e.yml` second lane**: a job/step running
   `./scripts/native-tests/run.sh --hort=compose --compose-overlay=native-tokens`
   on the same triggers as the base lane, required (not allow_failure). Keep
   the two lanes as separate jobs so a failure names its posture. Mind
   runner-capacity/timeout doubling — if the workflow has a global timeout,
   size it for two stack cycles.
2. **Ceremony docs**: TESTING.md (and RELEASING.md's local-E2E step if it
   names the command) list BOTH lanes as the pre-push/local gate pair.
3. **`test-rescanning.sh` seam**: its preflight must detect the missing
   native-token posture and refuse loudly, naming the overlay
   (`docker compose -f … -f deploy/compose/docker-compose.native-tokens.yml up -d`)
   — or compose the overlay itself if that fits the script's existing
   stack-management style. Header comment updated to state the invariant
   (svc-token consume requires the native-token validator).

## Scope / acceptance

- No `crates/` changes; no scenario changes; no compose-file changes.
- Acceptance: both lanes green in CI on a develop merge (the item lands only
  after 081+082); `test-rescanning.sh` without the overlay fails fast with
  the explicit message; with it, reaches its normal flow.
- Full pre-push suite (expected Rust no-op).

**Model hint:** sonnet.
