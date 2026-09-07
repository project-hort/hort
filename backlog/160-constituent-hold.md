# 160 — Provenance: constituents are held, never self-rejected as `Unsigned`

**Contract:** this file. Governing decisions: ADR 0027/0039 (§11 cascade +
late-joiner), ADR 0043 (per-child gating, cleared via subject), ADR 0007
(fail-closed = hold when evidence cannot exist yet), ADR 0016 (interaction
matrix entry — amendment authorized by the human's spec approval on the
originating issue, 2026-09-03), ADR 0015 (apply-time floor considered and
rejected: it moves the race, it does not remove it).

## The defect

`complete_provenance` under `ProvenanceMode::Required` holds a
`NoAttestation` result only while `window_open || is_referenced_descendant`
(`crates/hort-app/src/use_cases/provenance_orchestration.rs`, the
referenced-tree-descendant hold). A constituent — an OCI config/layer blob —
never carries its own attestation (cosign signs the top-level digest only);
it is cleared by its subject's cascade or by the late-joiner self-clear, both
of which need the subject to exist. When the observation window closes
before the client has pushed the manifest (a 1 s window vs. a multi-second
push), neither disjunct holds and the arm resolves to terminal
`Rejected{Unsigned}` (`rejection_reason = None`) — unreachable by `reevaluate`
(scan-clearable only), `waive` (Quarantined only), the admin override
(`ReleaseGeneral` forbids `Rejected`) and the cascade
(`CascadeProvenanceClearance` forbids `Rejected`). Servability of a correctly
signed image then depends on the client's push order. `Rejected` stays
terminal — that invariant is not touched; the fix is to never enter it for a
constituent on missing-subject evidence.

## Change

1. **Constituent classification from the artifact's own identity, not from
   DB edges.** Add `FormatHandler::is_provenance_constituent(&Artifact) ->
   bool` (default `false`); the OCI handler returns `true` for blob rows
   (`blobs/sha256:…` path / config+layer media types), `false` for manifests
   and indexes (subjects). Edges (`content_references`) stay what they are:
   nominations, never clearance authority (ADR 0039 §11).
2. **Hold predicate.** In the `NoAttestation × Required` arm:
   `window_open || is_referenced_descendant || is_constituent` ⇒ hold
   (`Quarantined`, outcome label `held_pending_subject`). The terminal
   `Rejected{Unsigned}` arm is reached only by **subjects** with a closed
   window and no signature — unchanged semantics, unchanged tests.
3. **Release of a held constituent is subject-driven only:** the existing
   verify-time cascade and the existing late-joiner self-clear. No new
   release authority (ADR 0007 list unchanged). The window-expiry backstop
   (S4) re-enters the same arm and holds again — it must not terminalize a
   constituent.
4. **No orphan timer.** A constituent whose subject never arrives stays held
   (serves nothing — held bytes never leave quarantine) and ages out via
   retention like any held row. A timer would be a second window with the
   same race.
5. **Observability.** `held_pending_subject` as its own outcome label on the
   provenance metrics/log line so held-vs-verified is measurable (today the
   losing side is a silent terminal).
6. **ADR 0016 matrix.** Add the row `provenance_mode: required` ×
   `quarantine_duration_secs` shorter than a client push → *dissolved by
   this change for constituents; for subjects it shortens the observation
   window as the operator asked*. Prose only; no linter rule.
7. **Docs.** `docs/architecture/how-to/curator-workflow.md` (or the
   provenance how-to): state that constituents are never terminally
   unsigned on their own and what `held_pending_subject` means; note that
   a short window on a `required` scope shortens only the subject's window.

## Tests (100 % on new hort-domain / hort-app branches)

- constituent + `Required` + closed window + no edges + no attestation ⇒
  `Quarantined`, outcome `held_pending_subject`, no `ProvenanceRejected`.
- then subject verifies ⇒ cascade clears the constituent (existing cascade
  test extended with the pre-held constituent).
- constituent ingested after subject verified ⇒ late-joiner clears it
  (existing path, unchanged, asserted).
- subject + `Required` + closed window + no signature ⇒ still
  `Rejected{Unsigned}` (pins that subject semantics did not move).
- S4 backstop on a held constituent ⇒ still held, never terminal.
- non-OCI format ⇒ `is_provenance_constituent` false ⇒ behaviour unchanged.
- E2E `scripts/native-tests/scenarios/quarantine/provenance-push-then-sign.sh`
  stays green (both legs); add a leg (or a unit-level equivalent) with the
  window set below push duration proving the image is servable after
  signing regardless of push order.

## Out of scope

Blob DELETE API / repair tooling for stranded rows (#90 decision stands);
making `Rejected` non-terminal for provenance reasons (rejected alternative:
it would weaken the invariant every other path relies on); eager child
ingest for proxied indexes (#229).

## Acceptance

A signed image pushed under `provenance_mode: required` with
`quarantine_duration_secs: 1` is servable once manifest + signature arrive,
for any push order; no `ProvenanceRejected{Unsigned}` is ever emitted for a
constituent; subject semantics unchanged; ADR 0016 row + docs landed; full
gate green.
