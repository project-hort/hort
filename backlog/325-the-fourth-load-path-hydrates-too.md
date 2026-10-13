# 325 — The fourth load path hydrates too, and the default-on await stops lying twice

**Issue:** #342 · **Branch:** `agent/342-referenced-blob-deliverability`
**Found by the 295 run (2026-10-13), measured, and verified by the architect.**
Sequenced next — it completes item 324, which closed three of four load paths.

**Governing decisions:** ADR 0039 D5 (the hold whose window elapsed advertises
no deadline — the half of this gap the tree already records), ADR 0039 D6 (the
illegal state the un-hydrated path false-alarms on), ADR 0008 (unchanged: the
format crate keeps reading a field). No new decision.

## What is true today — measured 2026-10-13 at `0a511e09`

Item 324 hydrated the three `find_visible_*` / `find_in_repo_by_hash` load
paths. **It did not hydrate the fourth**, and the fourth is on by default:

1. `ArtifactUseCase::get_by_id`
   (`crates/hort-app/src/use_cases/artifact_use_case.rs:240-242`) is a bare
   row read — `Ok(self.artifacts.find_by_id(id).await?)`, no hydration.
2. `blobs.rs`'s bounded-await poll loop re-reads through exactly that
   (`crates/hort-http-oci/src/blobs.rs:314`) and assigns the result to
   `current`, so the row it returns when the bound is exhausted is
   un-hydrated.
3. `HORT_OCI_PULLTHROUGH_RELEASE_WAIT_SECS` defaults to **10**
   (`crates/hort-server/src/config.rs:2909-2916` — "Absent or empty env var →
   10 seconds"), so the path is live in a default deployment. `0` disables it,
   but nobody has to set anything for this to be reachable.

So a cold pull-through blob, held `Quarantined` with an elapsed window, whose
own scan **rejects** it inside the bound, reaches the refusal arm as an
un-hydrated row. The 295 run measured the answer with a throwaway probe:

```
status=403 Forbidden
body={"errors":[{"code":"DENIED","message":"artifact is rejected",
       "detail":{"subject":"sha256:e6d6a729…"}}]}
```

**Two defects in that one answer:**

- **The axis is missing from a refusal that has one.** The stream carries
  `scanner`; the caller is handed the axis-less form.
- **The `tracing::error!` is a false alarm.** It claims ADR 0039 D6's illegal
  state — "Rejected with nothing on the stream to audit it by" — when nothing
  is wrong with the artifact at all; the axis was simply never looked up. That
  is verbatim the failure item 324's own decision table exists to prevent:
  fire on every healthy rejection and bury the one real violation.

**And this is the most likely way an operator meets a rejected blob** — a layer
blocked mid-`docker pull` on a pull-through repository is the scenario the
original reporter described, which makes the axis-less answer and the false
`error!` land exactly where the whole issue was aimed.

**The tree already predicted this fix, for the other half of the same gap.**
`DEFAULT_QUARANTINE_RETRY_AFTER_SECS`'s doc
(`crates/hort-http-oci/src/quarantine.rs:52-58`) names the same site for the
**hold** side: *"`blobs.rs`'s bounded-await poll loop, which re-reads through
`ArtifactUseCase::get_by_id` — a deliberately plain row read that does not
hydrate — and returns that row when the bound is exhausted. Only reachable for
a window that has ALREADY elapsed, which is the state whose honest computed
header is the useless `Retry-After: 1` the clamp below produces; **the two
belong to one fix**, not to this constant."* This unit is that one fix.

## What to build

**Route `get_by_id` through the hydration the other three load paths use.**
`hydrate_quarantine_deadline` already sets all three transient fields —
`quarantine_deadline`, `provenance_hold_indefinite`, and (since 324) the
rejection axis — so one change closes both halves of the recorded gap.

**The blast radius is one call site, measured:** `ArtifactUseCase::get_by_id`
has exactly **one** production caller in the workspace, `blobs.rs:314`. Every
other `get_by_id` hit belongs to a different use case (`repository_use_case`,
`user_use_case`) or to a test. So this is not a broad behavioural change
wearing a small diff.

**Decided, so you do not have to re-open them:**

- **Hydrate inside `get_by_id`, not at the call site.** The contract to match
  is the other three load paths': a caller gets an artifact whose transient
  fields are resolved. Fixing the loop alone would leave the next `get_by_id`
  caller with the same trap, and the method's own name promises a loaded
  artifact.
- **Keep 324's D2 and D3 exactly.** `Rejected`-only for the axis; a failed or
  over-cap stream read degrades to no-axis plus `warn!` and never propagates;
  the D6 `error!` fires only when the read succeeded and found no
  `ArtifactRejected`. You are extending the reach of that logic, not revising
  it.
- **Do not widen the loop's access check or its fail-safe semantics.** The
  per-poll authorization and the bound's fallback behaviour stay as they are.
  The only change is that the row the loop hands back is hydrated.

**Then correct the two docs that record the gap as open:**

- `quarantine.rs:52-58`'s second bullet — it currently describes the
  un-hydrated read as a standing reason the constant exists. Rewrite it to say
  the path now hydrates, and keep the constant's *other* justification (the
  anchor-less row) intact.
- `get_by_id`'s own rustdoc, which says only "Get an artifact by ID" and
  should name what it resolves, as the sibling loaders do.

## Explicitly out of scope

- Any wire change. The 403/axis shape landed in 295 and does not move; this
  unit makes an existing answer correct on one more path.
- The other three load paths, which 324 already covers.
- Denormalising `rejection_reason` onto the projection — still a schema change
  to buy a read on a refusal path.
- The `ScanIndeterminate` status-code divergence (collector).
- Items 322 / 323.

## Acceptance

- A `Rejected` artifact reached through `get_by_id` carries its axis, derived
  from the stream — asserted at the use-case level over a **seeded stream**.
- **The 295 run's probe becomes a committed test**: a cold pull-through blob
  held `Quarantined` with an elapsed window, rejected inside the bound, with a
  healthy `ArtifactRejected` on its stream, answers `403` **with** the axis and
  logs **no** `error!`. Mirror the existing
  `get_blob_quarantined_elapsed_window_releases_within_bound_returns_200`
  fixture. This test is the deliverable — the defect was invisible precisely
  because nothing exercised this path with a terminal status.
- The D6 `error!` still fires for a genuinely reason-less `Rejected` artifact
  on this path, so the detector is not merely silenced.
- **CORRECTED 2026-10-13 after the run measured it — this acceptance line had
  the hold half backwards.** It said the bound's fallback "no longer answers
  the useless `Retry-After: 1`". It never did: an un-hydrated row carries
  `quarantine_deadline: None`, so `check_quarantine` took the
  `.unwrap_or(DEFAULT_QUARANTINE_RETRY_AFTER_SECS)` arm and answered a flat
  **3600** (`crates/hort-http-oci/src/quarantine.rs:61`). Hydrating this path
  therefore **introduces** the clamped `1` rather than removing it, and that is
  **accepted as correct**:
  - the path is reachable *only* with the window already elapsed, so the
    remaining window is always ≤ 0 and there is no honest positive value —
    `3600` is the one answer that cannot be right, telling a client to wait an
    hour for a scan that finishes in 1–5 s;
  - ADR 0039 D5's objection to `Retry-After: 1` was about the **indefinite**
    hold — *"the thing it waits for is an external event"*, i.e. one second at
    a time **forever**. That case is separately and correctly handled here,
    because `provenance_hold_indefinite` is hydrated on this path too and
    suppresses the header entirely. D5 is honoured, not violated.
  - a client honouring `1` re-enters a bounded await of up to 10 s, so the real
    cycle is ~11 s rather than a tight spin.

  So the acceptance is: the bound's 503 carries a header derived from the row's
  own window and **never** the deadline-unknown `3600`, and an indefinite hold
  on this path carries **no** header at all.
- `quarantine.rs`'s two `Retry-After` tests stay green; if their expectations
  must change because this path now hydrates, say so explicitly and argue it
  rather than editing them quietly.
- `capped_stream_reads` green with no new budget site.
- Gate: the **unit gate** — `bash handover/gate-unit.sh -p hort-app
  -p hort-http-oci -p hort-http-core`, judged by output, never by the rc.
- No composition change of its own, but it ships on the branch that goes to
  the human for the compose E2E.
