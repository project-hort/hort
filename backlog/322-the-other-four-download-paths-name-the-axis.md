# 322 — The other four download paths name the axis, and stop promising a deadline they do not have

**Issue:** #342 · **Branch:** `agent/342-referenced-blob-deliverability`
**Sequenced after item 295**, which establishes the posture and lands the ADR
0055 clarification. This unit applies it; it decides nothing.
**And after item 324**: the axis is `None` on every read path until 324
hydrates it (`mappers.rs:324` hardcodes it; the read-path hydration skips every
non-`Quarantined` status). Measured 2026-10-13 — this unit's axis half is
blocked by the same single cause as 295's, and 324 unblocks all three at one
site.

**Governing decisions:** ADR 0055 (as clarified by 295 — a reason is owed to
whoever the read gate admits), **ADR 0039 D5** (a hold with no self-resolving
deadline advertises no deadline). No new decision here.

## What is true today — measured 2026-10-13

Two separate gaps on the same four download paths. Neither is a status-code
change: all four already answer `403` for `Rejected` and `503` for
`Quarantined`.

**(1) The 403 does not say which axis condemned the artifact.** Each sends a
fixed `{"error": "artifact is rejected"}`:

- `crates/hort-http-cargo/src/lib.rs:464-470`
- `crates/hort-http-npm/src/lib.rs:503-509`
- `crates/hort-http-pypi/src/lib.rs:718-724`
- `crates/hort-http-maven/src/lib.rs:533-539` (`non_servable_response`, shared
  by a file and its sidecar — see its doc comment)

**(2) All four promise a `Retry-After` on a hold that has no deadline.** The
only production reader of `Artifact.provenance_hold_indefinite` in the whole
workspace is `crates/hort-http-oci/src/quarantine.rs:93`. These four compute
`Retry-After` as `(deadline - now).num_seconds().max(1)` with a `"3600"`
fallback and never suppress it:

- `crates/hort-http-cargo/src/lib.rs:447-454`
- `crates/hort-http-maven/src/lib.rs:515-522`
- the npm and PyPI equivalents in the same shape (measure the exact lines; the
  `.unwrap_or_else(|| "3600".to_string())` is the marker)

So an artifact held indefinitely on a missing provenance signature answers
`Retry-After: 3600` — or, once its window has elapsed, `Retry-After: 1`
forever, because of the `.max(1)` clamp. That is verbatim the failure ADR 0039
D5 removed from OCI: *"Advertising `Retry-After: 1` there … tells a
well-behaved client to come back one second later, forever."* It survived
outside OCI because the fix was applied at one call site instead of to the
concept.

## What to do

1. **Add the axis to the 403 body** on all four paths, from
   `RejectionReason::wire_kind()`
   (`crates/hort-domain/src/events/artifact_events.rs:1153-1165`) and from
   nowhere else. `Artifact.rejection_reason` is already on the entity each
   handler holds — no new read, no port, no use-case change.
   - `rejection_reason: None` on a `Rejected` artifact is ADR 0039 D6's
     illegal state: answer 403 with no axis and log at `error`. Do not invent
     an `unknown` token.
   - Do **not** publish `Curator { curator_id }` or
     `CurationRetroactive { rule_id }`. Those are a person and a rule, not a
     diagnosis.
2. **Suppress `Retry-After` when `provenance_hold_indefinite`** on all four.
   **CORRECTED 2026-10-13 — this step used to add "and say in the body what the
   hold waits for", which contradicted the very lines it told the implementer
   to mirror.** `crates/hort-http-oci/src/quarantine.rs:100-103` states the
   opposite in as many words: *"the two holds are indistinguishable on the wire
   beyond the presence of the header, so quarantine state stays opaque to the
   client — only 'try again later', or nothing at all, is exposed"*, and its
   test pins the message as identical to the timed hold's. The clause is
   **withdrawn**, and the reasoning is the same one that withdrew "the policy"
   from the rejection body in item 295 §(c): a *rejection* is a verdict the
   caller needs in order to stop searching, whereas a *hold* leaves the
   caller's action identical either way, and the header already carries the
   actionable part. Naming what the hold waits for would hand an anonymous
   reader "this repository runs provenance_mode: Required" — operator
   configuration, for no action the client can take differently. So: the body
   is byte-identical for both holds and the absent header is the only
   difference on the wire. Mirror
   `hort-http-oci/src/quarantine.rs:86-103` — do not re-derive the rule, and
   do not copy the computation a fifth time if a shared helper is the obvious
   close. **If you reach for a shared helper, it belongs where the four can
   see it** (`hort-http-core`), not duplicated per crate; ADR 0008 allows that
   dependency and the four already take it.
3. **Give each of the four the test OCI already has.** Port
   `quarantine.rs::provenance_held_past_window_is_503_with_no_retry_after` and
   `hold_inside_its_window_keeps_its_retry_after` in each crate's own shape:
   an indefinite hold has no header, an in-window hold keeps its computed one.
   Four formats silently diverged from a fail-closed rule for want of exactly
   these two tests.
4. **One commit per format**, so each is reviewable on its own.

## Explicitly out of scope

- OCI. Item 295 owns it and `quarantine.rs` is already correct.
- PyPI's PEP 658 `.metadata` route — item 323; it needs a use-case change.
- **The `ScanIndeterminate` status-code divergence.** These four answer 403 for
  it; OCI answers 503 `UNAVAILABLE` (`hort-http-oci/src/error.rs:280, 314`).
  One is wrong. It is a defect in its own right, it is recorded on the
  collector, and it is **not** this unit's — do not unify it here.
- Any new endpoint, header, or operator surface.

## Acceptance

- Each of the four 403 bodies names the axis, sourced from `wire_kind()`; a
  test per format asserts the token for a `Scanner`, a `Curator` and a
  `Provenance` rejection, and that no uuid and no CVE identifier appears.
- `rejection_reason: None` answers 403 with no axis and logs at `error`.
- Each of the four answers 503 with **no** `Retry-After` when
  `provenance_hold_indefinite`, and keeps its computed header otherwise, each
  pinned by its own two tests.
- If a shared helper was introduced, it has exactly one definition and the
  four call it; if it was not, the report says why four copies were the better
  answer.
- OCI's behaviour is bit-identical to before this unit.
- Gate: the **unit gate** — `bash handover/gate-unit.sh -p hort-http-cargo
  -p hort-http-npm -p hort-http-pypi -p hort-http-maven` plus `hort-http-core`
  if a helper landed there, judged by its output and never by the rc.
- No ingest/provenance/quarantine **composition** change here, so this unit
  does not itself gate on the compose E2E — but it ships on the same branch as
  295, which does.
