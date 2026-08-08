# 085 — #130: bounded_poll capture-poisoning + constituent-ingest warming race

**Issue:** #130 (final residual — `quarantine/proxy-required-multilayer`, the
only red scenario in the 2026-08-08 rerun). Root cause fully confirmed on the
issue; three links, all harness-side, zero production code:

1. **Trigger:** the config-blob artifacts row missed `find_artifact_id`'s 60s
   poll once — constituent rows are produced by best-effort background blob
   warming (`prefetch.rs`, fired on the child-manifest digest GET) with no
   retry; the poll races it.
2. **Poisoning:** `bounded_poll`'s timeout line goes through `log()` to
   **stdout** (`lib/common.sh:71`, `log()` at `:31`). `find_artifact_id` runs
   inside `$( )`, so the timeout text became the captured "artifact id".
3. **Silent death:** the poisoned value passed the `[ -n ]` guard, printed in
   the PASS line, then hit `WHERE id = '<garbage>'` — psql's error went to
   `psql_one`'s `2>/dev/null` and `set -euo pipefail` (common.sh:10) killed
   the scenario with no fail detail and no scenario summary.

## Work

1. **`lib/common.sh` — `bounded_poll` messages to stderr.** The timeout line
   (and any future message this helper emits) must go to stderr so no
   command-substitution capture can ever ingest it. Grep for other `log`
   calls reachable inside `$( )` captures in the lib helpers; route any such
   diagnostic to stderr the same way (report the inventory — expected: just
   this one, but verify).
2. **`find_artifact_id` UUID validation — BOTH scenarios**
   (`proxy-required-multilayer.sh`, `proxy-multiarch-zero-window.sh` carry
   the identical pattern; the latter is latent, not yet bitten): validate the
   captured value is UUID-shaped before returning
   (`[[ "$id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]`
   or empty-out), so garbage can never satisfy downstream guards — defense in
   depth even with (1) fixed.
3. **Deterministic constituent ingest** (`proxy-required-multilayer.sh`):
   after the authenticated child-manifest GET, explicitly GET the config blob
   and every layer blob through the proxy
   (`/v2/<name>/blobs/<digest>` — the cold pull-through ingests
   synchronously regardless of whether the response is 200 or a designed
   hold-503, exactly like the step-0 index GET). Do not assert the statuses
   of these forcing GETs beyond "curl completed"; they exist to remove the
   race against best-effort warming. Keep the 60s polls as backstop.
   The sibling zero-window scenario needs NO forcing GETs (its asserts only
   need index + child manifest, which its own GETs already ingest) — do not
   add them there.

## Scope / acceptance

- Zero `crates/` changes, zero `deploy/` changes, `run.sh` untouched.
- `bash -n` on all touched scripts; full pre-push suite (expected Rust
  no-op; run anyway).
- Report: the stderr-routing inventory from (1); the exact forcing-GET block
  from (3); confirmation the zero-window scenario got ONLY the uuid guard.
- Acceptance vehicle: the human's plain `run.sh --hort=compose` — expected
  FULLY green (this is the last red scenario).

**Model hint:** sonnet.
