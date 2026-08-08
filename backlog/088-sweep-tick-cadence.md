## Requirement (Tom, Matrix 2026-08-08 — verbatim spec)

> Ich erwarte, dass wir das Laufzeitverhalten solch simpler Tests auf 20 Sekunden genau vorhersagen können. Und Wartezeiten von 300 Sekunden und mehr sind zu lange. Das sollte sich durch Anpassung der Hort-Test-Konfig halbieren lassen.

## Analysis

Every 300s+ wait in the compose E2E lane traces to ONE constant: the `hort-sweep-ticker` loop enqueues the quarantine-release sweep every **300s** (hardcoded `sleep` in `deploy/compose/docker-compose.yml`). Release latency after an artifact becomes eligible is therefore U(0,300)s — unpredictable by construction and the sole reason `proxy-required-multilayer` needs a 420s step-9 budget. The compose stack is dev/CI-only (helm/ansible deployments schedule their own tickers), so the cadence is free to change.

With a **30s tick**: release waits collapse to `(window remainder) + ≤30s + processing` — for the provenance-proxy scenario ≈ 60–130s bounded, predictable to ~±30s (the residual variance beyond that is docker.io pull speed, outside our config). That meets "halve 300s+" with headroom; honest caveat on the ±20s goal: tick quantization + upstream I/O put the achievable per-scenario prediction band at ~±30s.

**One scenario is destabilized by a fast cadence and must be hardened:** `proxy-multiarch-zero-window` asserts its zero-window child satisfies the sweep's eligibility predicate `status='quarantined' AND deadline passed` — a fast tick can legitimately RELEASE the child mid-scenario, which proves the predicate *more* strongly but fails the literal assert. The assert becomes released-OR-eligible.

## Item (backlog/088, single reviewable unit)

1. `deploy/compose/docker-compose.yml` sweep-ticker: parameterize the interval (`SWEEP_TICK_SECS`, default **30**) with a comment stating this is the dev/CI cadence knob (production schedules its own ticker).
2. `proxy-multiarch-zero-window.sh`: eligibility assert → released-or-eligible, comment stating why either outcome proves the carve-out.
3. `proxy-required-multilayer.sh`: re-derive the wait budget for the 30s cadence (expected default ≈ 240s with 2× margin; show arithmetic), update the derivation comment.
4. Grep-driven inventory: any other scenario asserting "still quarantined" mid-run against a repo whose window can close during the scenario — report the inventory; harden only genuinely exposed asserts (24h-window repos are safe by construction).

Zero production code. E2E-gated → handed over branch-first per the new process; MR only after Tom's green run.
