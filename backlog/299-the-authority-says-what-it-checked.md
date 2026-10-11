# 299 — The release authority says what it actually checked

**Issue:** #344 · **Branch:** `agent/344-scan-verdict-release-authority`
**Governing decisions:** ADR 0007 (the authority set and the
`(reason, authority)` pairing). **Touches the ADR's authority enumeration** —
the amendment is discussed before it is written; do not write it in this item
unless the architect has handed you the confirmed text.

**Depends on items 297 and 298.**

## What is true today

`ReleaseAuthorization` has no value for the case this ticket is about. The two
candidates both assert something else:

- **`ScanSucceeded`** means "the scan found nothing". The code says so twice:
  `resolve_release_authority` mints it only for `finding_count == 0`
  (`quarantine_use_case.rs:1448`), and the fast path's comment states that this
  authority *"asserts `finding_count == 0`"* (`:499`–`:501`).
- **`ScanRecorded`** is bound to `enforcement: record` — "the verdict is
  recorded rather than gating" — and says nothing about an enforcing scope.

So an artifact that was **evaluated** and whose findings **do not block** has no
honest authority to be released under. The fast path takes `ScanSucceeded`
anyway, and `Artifact::release`
(`crates/hort-domain/src/entities/artifact.rs:946`) does not check the claim —
it validates the source state and the `(reason, authority)` pairing and
otherwise takes the enum as a verified fact. The result is an
`ArtifactReleased` whose authority label reads "scan clean, no findings" over
an artifact with findings, at the very site whose comment requires that "the
release event and the `authority` log field say honestly which one released the
artifact".

## Where the authority actually surfaces — measured, and not where this item first said

`ArtifactReleased` carries three fields (`artifact_id`, `released_by`,
`released_by_user_id`, `justification` —
`crates/hort-domain/src/events/artifact_events.rs:509`) and the authority is
**not** one of them; the event's own doc says the authority is the one "paired
with it at the call site". The metric `hort_quarantine_released_total` is
labelled by **reason**, not authority (`emit_release`, `:82`). So the token
reaches exactly three places:

- `Artifact::release`'s `(reason, authority)` pairing table — the domain's
  decision, where a false claim is a false *premise*, not a false record;
- `release_authority_label` (`:67`), whose own doc calls it "the static
  authority-kind label for the timer-release `info!` line";
- that `info!` line (`:2005`) and the fast path's (`:648`).

**The durable audit answer is the stream, and item 297 already completed it:**
`ScanCompleted` (with its finding count) → `PolicyEvaluated{Pass}` → 
`ArtifactReleased{Timer}`. Server logs rotate in hours; the stream does not.
This item is therefore about the domain's premise and the live signal, **not**
about repairing a persisted record — and it must not add a field to
`ArtifactReleased` to make one.

## What to do

1. **Add the missing value** for "evaluated under the active policy, nothing
   blocking": **`ScanCleared`**, label `scan_cleared`. The name is the
   architect's decision (recorded on #344, 2026-10-11) and it follows the
   predicate item 298 introduced — `ScanStanding::Clears` is already this
   tree's word for exactly this fact, so the authority wears the vocabulary of
   the function that computes it rather than a second one. Rejected:
   `ScanBelowThreshold` (claims a severity comparison, while a `Pass` can also
   come from a license or blocked-class rule — the token would assert more
   than the predicate checks; it stays the *prose* phrasing in the ADR),
   `ScanNonBlocking` (describes the findings, not the decision, and has no
   counterpart in the tree's vocabulary), `ScanPolicyPassed` (collides with
   both `PolicyEvaluated` from the promotion gate and the existing
   `PolicyReEvaluation` authority). `ScanSucceeded` keeps its narrower meaning
   unchanged.
   Its rustdoc states the evidence (latest `ScanCompleted` + a
   `PolicyEvaluated{Pass}` after it, findings permitted) and the distinction
   from both siblings: `ScanSucceeded` asserts an empty finding list,
   `ScanRecorded` asserts the operator declared the verdict non-gating.
2. **Both paths use it for that case** — the fast path stops reaching for
   `ScanSucceeded` when findings exist, and the sweep (item 298) emits the new
   value. One case, one label, both callers.
3. **Pair it like its siblings**: `ReleaseReason::Timer` accepts it in
   `Artifact::release`'s pairing table, the log-label mapping
   (`release_authority_label`, around `:67`) gains its row, and the
   exhaustive matches over the authority set are updated **without** a wildcard
   arm — a future value must stay a compile error, which is how this set is
   maintained today.
4. **Do not widen `ScanSucceeded` instead.** That is the cheap move and it is
   the wrong one: it would produce correct releases and permanently false audit
   records, which is the half of this defect that outlives the hang.
5. **Say what an operator sees.** The new value appears in the `authority`
   field of the two release log lines and in `release_authority_label`'s
   mapping. The report names those sites **and** states the durable path — the
   stream triple above — so an operator whose logs have already rotated knows
   where the answer lives. Do **not** add the authority to `ArtifactReleased`;
   that is a separate decision about the event shape and is not in this item.

## Explicitly out of scope

- The ADR text (handed over separately, discussed first).
- Re-blocking (item 300) and the fixture/cross-table (item 301).
- Any change to `ScanWaived` / `ScanRecorded` / `CuratorWaiver` semantics.

## Acceptance

- An artifact released with non-blocking findings is authorized by the **new**
  value on both the sweep and the fast path, and a clean artifact is still
  authorized by `ScanSucceeded`. Assert the authority where it exists — the
  resolver's return value and the pairing table — not on the event, which does
  not carry it.
- The durable record for the same artifact still reads
  `ScanCompleted` → `PolicyEvaluated{Pass}` → `ArtifactReleased{Timer}`: one
  test reads the stream and pins that triple, so the audit answer is covered by
  a test rather than by a log line that rotates.
- The authority set's exhaustive matches carry no wildcard arm after the
  change; adding a sixth value is still a compile error. Demonstrate it (a
  temporary variant, build, revert) and say so in the report.
- The log-label mapping has a row for the new value, and
  `release_authority_label_maps_every_arm` (the test enumerating the live
  authorities) covers it.
- Gate: full local gate, one-shot capture, foreground, report before exit.
