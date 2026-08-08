# 087 — #130: constituents before the sign — the cascade is one-shot at verify time

**Issue:** #130 (final residual, round 4 — step 9 timed out at 420s too;
budget theory refuted, root cause corrected on the issue).

## Root cause (code-verified)

`cascade_clearance` walks the signed subject's constituent digests ONCE, at
verify time, and clears only rows that exist at that moment (`cascade_one` on
a missing row: warn + skip, best-effort). A constituent ingested AFTER the
subject's verify never receives clearance: its own verify (if any) reads only
its own clearance state — there is no parent-lookup self-clear — and the
sweep's expiry backstop deliberately skips parent-gated blob constituents
("clearance comes from the parent's cascade"). Stranded Pending+held; the
only documented healer is a re-sign (the verify skip path's cascade
re-drive). Item 086 moved the forcing GETs after the sign, so config/layer
rows race background warming for existence at cascade time — whichever rows
lose stay held, the full-tree anonymous pull can never succeed, and step 9
fails at ANY budget (runs 5 and 6, deterministically).

The realistic client flow is also the correct one: a proxy client pulls
index → child manifest → blobs, and the CI signer signs afterwards. The
constituents must simply be ingested BEFORE the sign — which is where item
085 had them; item 086 moved them because the sign then overran the policy's
30s window. Both constraints are real; the window must be sized for both.

## Work (one commit)

1. **Policy** — `deploy/compose/example-config/policies/oci-provenance-proxy-e2e-required.yaml`:
   `quarantineDuration: 30s` → `120s`. Update the adjacent comment ("A 30s
   window is long enough…") to state the corrected sizing rationale: the
   window is the signing deadline AND must also cover the client's constituent
   pulls (which must complete before the sign so the one-shot verify cascade
   finds every row); 120s covers pulls (~30-60s incl. docker.io) + sign with
   margin, while staying short enough for the release sweep within a smoke
   run.
2. **Scenario** — `scripts/native-tests/scenarios/quarantine/proxy-required-multilayer.sh`:
   - Move the forcing-GET block BACK to between the authenticated child GET
     and the cosign sign (revert the item-086 move). Rewrite its comment to
     carry the corrected invariant pair: (a) constituents must exist before
     the sign because the verify cascade is one-shot over rows present at
     verify time (late rows strand until a re-sign); (b) everything between
     ingest and sign eats the observation window, so the window is sized
     (120s) to fit pulls + sign. Renumber steps accordingly.
   - `QUARANTINE_DURATION_SQL` → `interval '120 seconds'` and its comment's
     literal reference (`30s` → `120s`).
   - Step-9/8 budget: keep `PROVENANCE_WINDOW_WAIT_SECS` default at 420 but
     re-derive in its comment: worst case ≈ (window end ~T+120 − Verified
     ~T+70) + 300s tick + processing ≈ ~360-400s → 420 holds; bump to 480
     ONLY if your derivation shows 420 short — show the arithmetic in the
     report either way.
3. Nothing else. No lib, no other scenario, no `crates/`.

## Scope / acceptance

- Gate per the harness-only rule: `bash -n` on the scenario;
  `git diff --name-only` cited in the report (must show exactly the two
  files); example-config revalidated via the offline `validate-config`
  invocation (report 069's command); `cargo-audit audit --deny warnings` +
  `cargo deny check` (one-shot capture idiom). NO fmt/clippy/test — the diff
  is harness/config-only.
- Report: the final step sequence, the rewritten forcing-block comment
  verbatim, the budget derivation.
- Acceptance vehicle: the human's plain pull-only `run.sh --hort=compose`.

**Model hint:** sonnet.
