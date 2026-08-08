# 086 — #130: move the constituent forcing-GETs after the sign (the 30s window is the signing deadline)

**Issue:** #130 (final residual, round 3 — `quarantine/proxy-required-multilayer`,
now failing at the cosign sign step with an anonymous-HEAD 404).

## Root cause (confirmed on the issue)

`oci-provenance-proxy-e2e`'s ScanPolicy sets `quarantineDuration: 30s` — and
under `provenanceMode: required` that window end IS the signing deadline: the
sweep's S4 final provenance verify terminally rejects a still-unsigned subject
(`Rejected{Unsigned}`, by design — the same behavior push-then-sign's [6/6]
pins), after which the manifest is hidden as `MANIFEST_UNKNOWN` (404 — the
rejected-read shape). Item 085's "Step 2b" forcing-GETs (eight sequential
cold blob pull-throughs) sit BETWEEN ingest and sign, pushing the sign past
the 30s deadline into the sweep-tick lottery; the previous run signed at
~T+10s and was deterministically safe. An early ingest-time verify is NOT the
issue — an unsigned subject maps to `HeldPendingSignature` (S1 hold), never
terminal; only the window-end S4 decision is terminal.

## Work

1. In `scripts/native-tests/scenarios/quarantine/proxy-required-multilayer.sh`,
   move the entire "Step 2b: force constituent ingest" block to AFTER the
   cosign sign step (current Step 3) — the sign needs nothing from the
   constituents; steps 4-6 (which consume the rows) still run after the
   forcing block. Renumber/rename the step labels accordingly (sign becomes
   the step right after the authenticated child GET, exactly the timing the
   passing run proved).
2. Update the moved block's comment to state BOTH invariants: (a) the forcing
   GETs exist to remove the race against best-effort background warming;
   (b) they must come AFTER the sign because the policy's observation window
   is the signing deadline — anything inserted between ingest and sign eats
   into it (this scenario's window is deliberately short, 30s, to keep the
   release-wait cheap).
3. Nothing else: no policy change, no other scenario, no lib change.

## Scope / acceptance

- One file, `bash -n` clean; full pre-push suite (pure shell change — run
  once each, capturing log + exit in the same invocation:
  `<cmd> > /tmp/gate-<name>.log 2>&1; echo "EXIT=$?"` — cite the EXIT lines
  and tails; do NOT re-run a suite that already reported green).
- Acceptance vehicle: the human's plain `run.sh --hort=compose`.

**Model hint:** sonnet (single-file reorder with a documented invariant).
