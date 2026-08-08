# 093 — proxy-required-multilayer: authenticated warm pass before the anonymous `--all` acceptance poll

**Issue:** #135 · **Branch:** `agent/135-late-joiner-clearance` · **Scope:** test harness only (one scenario file)

## Problem (evidence-backed, 2026-08-08 acceptance run)

Step 9 of `scripts/native-tests/scenarios/quarantine/proxy-required-multilayer.sh`
lets the **anonymous** `skopeo copy --all` poll itself drive the foreign-platform
cold pulls. skopeo aborts every attempt at the FIRST held artifact (503), so the
ingest frontier advances ~one artifact per poll cycle (~10s: upstream fetch +
sweep-tick alignment). The image's foreign platforms total ~23 late joiners
(4 child manifests + 19 blobs), so full-tree availability costs 300–450s against
the 240s budget — a structural timeout, independent of server correctness.

The run's DB proved the server side works: every late joiner ingested during the
poll self-cleared and released (the #135 late-joiner clearance functioning
exactly as designed); the last blob landed at 18:16:09 and the poll expired
~18:16:30. The only never-released rows are the cosign signature's own two
blobs, which are outside the `--all` tree (design question parked separately).

## Change

Split step 9 in the scenario:

- **9a — authenticated warm pass (new):** ONE `skopeo copy --all` with
  `--src-creds "${PUSH_USER}:${PUSH_SECRET}"` (write-authorized ⇒ hold-read
  exemption serves held constituents), wrapped in `bounded_poll` with a **120s**
  budget / 5s interval to shield transient upstream flakes. This is the
  late-joiner **ingest vehicle**: every foreign platform arrives AFTER the
  subject's verify — the exact seam the late-joiner clearance covers — and each
  self-clears at its own quarantine commit. Assert success (`pass`/`fail` pair).
- **9b — anonymous release acceptance (existing poll, tightened):** the current
  anonymous `skopeo copy --all` bounded_poll, budget reduced from
  `$WINDOW_WAIT_SECS` to a new `ANON_PULL_WAIT_SECS` default **90** (override
  via env like the other knobs). After 9a it waits only on clearance + release
  sweep ticks; expected green ≤ ~30s.

Update the step-9 header comment to state the two-phase contract and WHY the
anonymous poll cannot be the cold-pull driver (first-503 abort ⇒ serial
frontier). Steps 0–8 and 10 stay untouched; `WINDOW_WAIT_SECS` keeps its
remaining consumers.

## Acceptance

- `bash -n` clean; harness-only diff (this one file).
- Full run on the branch: PASS=17 FAIL=0 with step 9a green in one-to-few
  attempts and 9b green within ~2 sweep ticks; total scenario runtime
  predictable within ±20s.
