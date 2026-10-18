# 323 — The `.metadata` route stops hiding a verdict, and un-pins the test that said it should

**Issue:** #342 · **Branch:** `agent/342-referenced-blob-deliverability`
**Sequenced after item 295**, whose ADR 0055 clarification is the authority for
this change.
**And after item 324**: the axis is `None` on every read path until 324
hydrates it (`mappers.rs:324` hardcodes it; the read-path hydration skips every
non-`Quarantined` status). Measured 2026-10-13 — this unit's axis half is
blocked by the same single cause as 295's, and 324 unblocks all three at one
site. **This unit reverses a documented, test-pinned decision** — it is
not a bug fix, and its report must read as a reversal with its argument.
**And after item 322**, which built the function this unit answers through.

**Governing decisions:** ADR 0055 as clarified by 295 (the audience is the read
gate), **ADR 0021 / ADR 0045** (repository anti-enumeration — untouched),
ADR 0008 (the use case owns the state; the format crate cannot reach past it),
ADR 0039 D5/D6 (the hold with no deadline; the rejection with no axis).

## What is true today — measured 2026-10-13

PyPI's PEP 658 `.metadata` route answers a plain **404** for `Rejected` and for
`ScanIndeterminate`, and it does so because the **use case** flattens the state
before the handler ever sees it:

- `crates/hort-app/src/use_cases/wheel_metadata_use_case.rs:233-248` — the
  `Rejected | ScanIndeterminate` arm returns
  `AppError::Domain(DomainError::NotFound { entity: "Artifact", .. })`, with
  the rationale inline: *"**404, not 403** — anti-enumeration for the metadata
  surface; the wheel's existence stays hidden."*
- `WheelMetadataServeOutcome` (`:117-127`) models exactly two states,
  `Available` and `Quarantined { quarantine_deadline }`. Its doc comment
  (`:110-116`) is explicit that the third is deliberately *not* a variant:
  *"Collapsing those onto one `NotFound` envelope is the anti-enumeration
  property the test matrix pins."*
- The pinning tests are
  `serve_rejected_wheel_returns_notfound_not_forbidden` (`:515`, whose
  assertion at `:537` reads *"rejected wheel `.metadata` must return Artifact
  NotFound for anti-enumeration"*) and
  `serve_scan_indeterminate_wheel_returns_notfound` (`:544`), which pins the
  same posture for the other terminal status.
- The handler consequence is at
  `crates/hort-http-pypi/src/metadata_endpoint.rs:272-295`, whose own comment
  records that by the time it runs it cannot tell a rejected wheel from a
  legacy un-backfilled one — both arrive as `NotFound`.

ADR 0055 records this as a legitimate format-specific choice
(`docs/adr/0055-write-authorized-hold-read-generalised.md:51-64`: "Both choices
satisfy this qualifier").

## Why it changes anyway

295's confirmed clarification says the set entitled to a reason is *whoever
could read the artifact if it were not withheld*. The argument does not
distinguish a byte route from a metadata route: on a repository whose read gate
admits the caller, the wheel's existence is **already** disclosed by the simple
index that listed it, and the `.metadata` 404 therefore hides nothing except
the verdict. The "the wheel's existence stays hidden" rationale is true only
for a caller the read gate refuses — and such a caller never reaches this arm,
because the repository challenge fires first (ADR 0021 / 0045, untouched).

So the inline rationale is not wrong; it is **scoped to a caller who is no
longer the one arriving here**. That is the reversal, and it is the same
reversal 295 makes in OCI. Leaving this route alone would mean a consumer whose
`pip install` is blocked gets a reason from the wheel download and silence from
the metadata route — the inconsistency ADR 0055's clarification exists to end.

## The invariant this unit installs, and why it is the whole design

**A wheel's `.metadata` must answer whatever the wheel itself answers, for
every parent status.** Not "a similar envelope" — the same answer, because the
two routes serve the same artifact and a caller who gets `403 rejected` from
one and `404` from the other learns only that the two were written on
different days.

That invariant has a precedent in this codebase that 322 deliberately
preserved: Maven's sidecar route keeps a three-line wrapper around the shared
gate *specifically* so a file GET and its sidecar GET cannot diverge
(design §11). `.metadata` is to a wheel what a sidecar is to a Maven file.

And 322 built the function that makes the invariant structural rather than
aspirational: `hort_http_core::artifact_gate::non_servable_response(&Artifact)
-> Option<Response>` (`crates/hort-http-core/src/artifact_gate.rs:141`), which
is exhaustive over `QuarantineStatus` **with no wildcard arm** and is now the
single answer for all four download routes, PyPI's included
(`crates/hort-http-pypi/src/lib.rs:695`). It already carries:

- `Rejected` → 403 naming the axis from `RejectionReason::wire_kind()`, with
  the D6 `error!` and no `axis` field when the axis is absent;
- `Quarantined` → 503, `Retry-After` from its window, **suppressed** for an
  indefinite provenance hold (D5), body identical either way;
- `ScanIndeterminate` → 403, terminal, no window.

So this unit does not add a variant per status and does not patch a fifth
`Retry-After` site. **It deletes the flattening and calls that function.**

## What to do

1. **Stop flattening in the use case.** `serve`'s non-servable path returns the
   loaded `Artifact` to the handler instead of a `NotFound` error or a
   status-specific variant. Two variants, not four:
   `Available(MetadataBlob)` and a non-servable case carrying the artifact.
   `Quarantined { quarantine_deadline }` goes away with the rest — the artifact
   carries the hydrated deadline *and* `provenance_hold_indefinite`
   (`artifact_use_case.rs:799` sets both), which is more than the variant
   carried. Keep a log line on the refusal if you want one; the `info!` there
   today is fine to keep or to re-word, but it is no longer an
   "anti-enumeration envelope".

2. **Render it through the one gate.** Both match sites in
   `metadata_endpoint.rs` (`:210` and `render_outcome` at `:412`) call
   `non_servable_response`. `build_quarantined_response` (`:446-452`) is then
   dead — **delete it**, do not patch it. That is the fifth `Retry-After` site
   unit 322 reported it could not reach from the format crate, and this is the
   fix: the D5 rule ends up with exactly one production implementation in the
   workspace rather than two that must be kept in step.

3. **Keep the legacy-no-metadata-row case a 404.** It genuinely is "no such
   metadata", not a verdict. The handler's `(2a)` arm
   (`metadata_endpoint.rs:272-295`) reasons by elimination from `NotFound` and
   that elimination stops being true — rewrite it to say what it now knows,
   and test that a rejected wheel and a legacy un-backfilled wheel are
   **distinguishable** on the wire.

4. **Change the pinning tests, do not bypass them.**
   `serve_rejected_wheel_returns_notfound_not_forbidden` (`:515`) and
   `serve_scan_indeterminate_wheel_returns_notfound` (`:544`) assert the old
   posture. Rewrite both to assert the new one, and leave a `///` on each saying what it pins and why the
   previous assertion was correct for its own scope. A test deleted silently is
   how the next person re-introduces the collapse.

5. **`ScanIndeterminate` is in scope here, and this is a correction to an
   earlier revision of this item** which told you to leave it. It said so on
   the grounds that the status code for that state is an open cross-format
   question — which it is: the four formats answer 403 and OCI answers 503, and
   that defect is recorded and **not** yours. But that question is 403-vs-503.
   The question on *this* route is verdict-vs-404, which is the concealment the
   whole unit reverses, and ADR 0055's own text names both terminal verdicts
   together (`:51-64`). Answering through the gate settles it correctly and for
   free: the metadata route inherits whatever the download route answers, now
   and after the cross-format defect is fixed.

6. **Say in ADR 0055 that this posture moved.** 295 lands the clarification
   paragraph; this unit updates the per-format map at `:51-64` so the ADR no
   longer records PyPI `.metadata` as a 404 route. One or two sentences, in
   that passage's existing form — not a new ADR.

7. **One commit for the reversal, one for the stale comment.**
   `crates/hort-server/src/composition.rs` (~line 2869) justifies wiring
   `with_artifact_stream_events` as *"so the **OCI** 503 sites can drop a
   `Retry-After`…"*. After 322 that is true of every content route, and after
   this unit of the metadata route too. One word, its own commit.

## Explicitly out of scope

- The simple index and the `hort.held[]` packument enumeration. Unchanged.
- Repository-level anti-enumeration. A caller the read gate refuses sees
  exactly what it sees today, and the ADR 0021 / 0045 regression groups must
  pass untouched.
- **The cross-format `ScanIndeterminate` status code** (403 in the four
  formats, 503 in OCI). Recorded defect, not this unit's — and answering
  through the gate means this route never has to take a position on it.
- The wheel-metadata backfill task.

## Acceptance

- **The invariant is tested as an invariant**, not as four separate assertions:
  for each non-servable parent status, the `.metadata` route's status code,
  `Retry-After` presence and body are those of the wheel-download route for the
  same artifact. If you can express that as one test over the statuses, do.
- A rejected wheel's `.metadata` answers 403 naming the axis to every caller
  the read gate admits; a legacy un-backfilled wheel still answers 404; a test
  asserts both and asserts they are distinguishable.
- An indefinite provenance hold on the parent wheel answers 503 with **no**
  `Retry-After`; an in-window hold keeps its computed header.
- `build_quarantined_response` no longer exists, and no second copy of the
  axis-token mapping or the D5 suppression rule exists in `hort-http-pypi`.
- Both pinning tests (`:515`, `:544`) assert the new posture and document the
  reversal; no test was deleted to make room. The *repository*-level
  anti-enumeration test in the same file (`:477`, "expected Repository
  NotFound") is untouched and still passes — that one is ADR 0021 / 0045 and
  is not what this unit reverses.
- ADR 0021 / 0045 regression groups green, untouched.
- ADR 0055's per-format passage no longer lists PyPI `.metadata` among the
  404 routes.
- No uuid and no CVE identifier in any body, over a corpus including the two
  uuid-carrying `RejectionReason` variants.
- A negative control: revert the production change and every new test fails.
- Gate: the **unit gate** — `bash handover/gate-unit.sh -p hort-app
  -p hort-http-pypi -p hort-http-core -p hort-server`, judged by its output and
  never by the rc. Measure whether anything else needs adding.
- This changes a serve path's composition, so it ships on the branch handed to
  the human for the compose E2E before any merge request.
