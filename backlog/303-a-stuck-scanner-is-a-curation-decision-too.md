# 303 — A stuck scanner is a curation decision too

**Issue:** #345 · **Branch:** `agent/345-curation-owns-the-manual-release`
**Governing decisions:** ADR 0007 (the release predicate), ADR 0025 (a state
precondition answers 409, not 500).

**Depends on item 302** — the widening is the recorded decision's
implementation; without the confirmed ADR text this unit does not build.
**It is the precondition for item 304**: remove the admin route before this
lands and `ScanIndeterminate` has no manual exit at all.

## What is true today

The curator's release is bounded to one source state and the admin's to two:

```
QuarantineEvent::ReleaseCuratorWaiver => match state {
    Quarantined => Allowed(&[Released]),
    NoneSt | Released | Rejected | ScanIndeterminate => Forbidden,
},
QuarantineEvent::ReleaseGeneral => match state {
    Quarantined => Allowed(&[Released]),
    ScanIndeterminate => Allowed(&[Released]),
    NoneSt | Released | Rejected => Forbidden,
},
```
(`crates/hort-domain/src/entities/quarantine_transitions.rs:203`–`:211`, with
the declarative rows at `:379` and `:385`.)

`Artifact::release` picks between the two events on the `(reason, authority)`
pair (`crates/hort-domain/src/entities/artifact.rs:959`–`:964`) and its guard
comment states the narrowing, as does `ReleaseAuthorization::CuratorWaiver`'s
rustdoc (`:329`–`:337`).

## What to do

1. **`ReleaseCuratorWaiver` accepts `ScanIndeterminate`.** One table row; the
   declarative `QuarantineTransitionRow` set gains the matching entry so the two
   representations stay in step (that pairing is what the table's own tests
   check).
2. **Rewrite the three rationales that argued the bound**, with the argument
   that replaces them — a curator who may override a *known* severe finding may
   also act when *no* finding exists yet, so the narrowing did not protect the
   greater power, it split one power across two roles. The three places are the
   source-state guard comment (`artifact.rs:952`–`:958`), `CuratorWaiver`'s
   rustdoc, and the transition event's doc (`quarantine_transitions.rs:38`).
3. **`Rejected` stays forbidden for both.** Terminal is terminal; the exit for a
   rejection is `re_evaluate`, and nothing in this ticket touches it.
4. **Do not merge the two `QuarantineEvent` variants yet.** After item 304 the
   `ReleaseGeneral`/`ReleaseCuratorWaiver` split carries only the timer and
   policy-re-evaluation arms against the curator arm; whether that collapses to
   one variant is item 304's call, made with the pairing table in front of it.
   Leaving it here would mean two units editing the same table.

## Explicitly out of scope

- Removing the admin route (item 304) — this unit only makes the curator path
  able to do what the admin path does.
- The provenance axis: a `Pending` provenance clearance still does not block an
  explicit manual release, exactly as today (the AND-precondition is on the
  timer arm alone).

## Acceptance

- A `(Curator, CuratorWaiver)` release from `ScanIndeterminate` succeeds and
  emits `ArtifactReleased{released_by: Curator}` with attribution.
- The same release from `Rejected` still fails with `DomainError::InvalidState`
  (409, ADR 0025) — not `Invariant`.
- The declarative transition rows and the `match` agree: the table's existing
  consistency test passes without being edited.
- Non-vacuity: revert the one row and show the new test red.
- Gate: the **unit gate**, one-shot capture:
  `bash handover/gate-unit.sh -p <the crates this unit touches>` — check, fmt,
  clippy and those crates' tests, with a full per-step log under
  `handover/gatelogs/`. Judge by the output, not the rc, and quote the test
  totals. Do **not** run `cargo test --workspace`, `cargo audit`, `cargo deny`
  or the attribution script: together they take 15–25 minutes, longer than a
  worker's foreground tool window, so the harness backgrounds them and the run
  ends with the gate killed and the report lost. The architect runs the full
  gate on the same tree before any MR; a red workspace-wide step becomes a new
  directive, not an in-run fix. Write the report before exiting.
