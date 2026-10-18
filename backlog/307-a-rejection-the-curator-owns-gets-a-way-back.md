# 307 — A rejection on an axis the curator owns gets a way back

**Issue:** #345 · **Branch:** `agent/345-curation-owns-the-manual-release`
**Governing decisions:** ADR 0007 (the release predicate), ADR 0041 (the
re-judgement model and invariant #6 — a scan re-judgement never clears a
provenance rejection), ADR 0039's 2026-09-12 amendment (only a positive
disproof may be terminal), ADR 0003 (read verification — why a corruption
tombstone is not releasable), ADR 0025 (a state precondition answers 409).

**Depends on items 302 and 303.** The ADR wording in 302 covers this unit too;
303 establishes that the curator's source-state set is the one that grows.

## What is true today

Six events reach `Rejected`, on four axes — scan
(`RejectFromScan`, `RejectFromScanPolicyRetroactive`), curation
(`BlockByCurator`, `RejectFromRetroactiveCuration`), provenance
(`CompleteProvenance`) and corruption (`TombstoneFromCorruption`) — and
`Rejected` has exactly **one** exit: `ReEvaluate`
(`quarantine_transitions.rs:221`, `Rejected → {Quarantined, Released}`).

That exit admits only two of the seven rejection reasons:

```rust
pub fn is_scan_clearable(reason: Option<&RejectionReason>) -> bool {
    match reason {
        Some(RejectionReason::Scanner) | Some(RejectionReason::ScanPolicyRetroactive) => true,
        Some(RejectionReason::Admin)
        | Some(RejectionReason::Curator { .. })
        | Some(RejectionReason::CurationRetroactive { .. })
        | Some(RejectionReason::Provenance)
        | Some(RejectionReason::Corruption)
        | None => false,
    }
}
```
(`crates/hort-domain/src/entities/artifact.rs:1711`.)

And it clears a rejection only when the **re-judged evidence** no longer blocks
— it is not an override. So, measured:

- a scan rejection whose findings still block has **no** exit;
- **a curator's own block has no exit at all** — `Curator { .. }` is not
  scan-clearable and no operator surface reverses it. A curator can block and
  cannot unblock;
- a provenance rejection has no exit (that is #342's item 292, in flight);
- a corruption tombstone has no exit, and that is correct.

The human's decision (2026-10-11) was argued from the premise *"ein Kurator,
der bekannte schwere Befunde überschreiben kann"* — and an artifact with known
blocking findings is `Rejected`, not `Quarantined`. The premise therefore
describes a capability that does not exist yet; this unit is what makes it
true.

## What to do

1. **The manual release accepts `Rejected` on every axis except corruption:**
   `Scanner`, `ScanPolicyRetroactive`, `Curator { .. }`,
   `CurationRetroactive { .. }` **and `Provenance`**. `Corruption` stays
   refused.
   - **Provenance is overridable** (decided 2026-10-11, after the maintainer
     tested the opposite position and withdrew it). The reasoning is what
     settles it: what a curator verifies out of band — this content hash
     against the publisher's own release page — answers exactly the question a
     signature answers. Both sub-cases follow. A third party who attached a
     broken signature to a genuine artifact leaves the bytes genuine and the
     hash comparison confirms it (that is audit finding S10-1, today a
     no-exit availability gap); an attacker who modified the artifact and
     signed it with their own key fails that same comparison, so the curator
     does not override. The check is the instrument in both directions.
     **ADR 0041's invariant #6(a) is not touched**: it bars a *scan
     re-judgement* from clearing a provenance rejection, and a curator override
     is not a re-judgement — which is precisely why item 2's second predicate,
     rather than a widened `is_scan_clearable`, is the right shape.
   - **Corruption is refused permanently**, and the reason is now sharp: the
     curator's instrument cannot help there. The stored bytes do not match the
     content hash that names them, so whatever the publisher attests, the bytes
     hort holds are not those bytes — the comparison can confirm nothing, and
     `VerifyingReader` fails the read regardless (ADR 0003's read-verification
     amendment). That is the difference between a risky override and a
     meaningless one.
2. **A second predicate, not a widened one.** `is_scan_clearable` answers *"can
   a re-judgement of the evidence clear this?"*; this unit needs *"may a human
   on the curation axis override this?"*. Two different questions — a new
   sibling predicate beside it, exhaustive and wildcard-free over
   `RejectionReason`, so a future eighth reason is a compile error in both.
   Widening `is_scan_clearable` instead would let a *policy re-evaluation*
   silently clear a curator's block, which ADR 0041's invariant #6 shape
   forbids.
3. **The domain reads the reason it already holds.** `rejection_reason` is a
   field on the aggregate (`artifact.rs:137`), so `Artifact::release` consults
   it directly for the `Rejected` source state — no stream read, no new
   parameter resolved by the app layer. Keep the existing
   `ProvenanceClearance` / `CurationClearance` parameters untouched.
4. **The release clears the rejection.** On a successful override,
   `rejection_reason` returns to `None`, the way `re_evaluate` already does it
   (`:1437`) — a `Released` artifact carrying a stale rejection reason is an
   illegal state, and the next policy pass would read it.
5. **Refusals answer 409, not 500** (ADR 0025): an operator can POST a waive
   against any artifact, so a refused axis is a caller-reachable state
   precondition — `DomainError::InvalidState`, and the message names the axis
   so the operator learns *why* rather than *that*.
6. **`RejectionReason::Admin` needs no path.** Every mint of it in the tree is
   inside `mod tests` (`event_store.rs`, from the `mod tests` at `:1448`); no
   production path writes it, which is consistent with the decision that admin
   does not make domain verdicts. Leave it in the enum (append-only) and say so
   in the report; do not add an override arm for it.
7. **Retire the two comments that promise a corruption escape hatch.**
   `artifact.rs:1859`–`:1861` ("The escape hatch for a false positive is the
   admin release (e.g. the operator restored the blob from a known-good
   backup)") and `artifact_events.rs:1078`–`:1080` say the same of
   `RejectionReason::Corruption`. Both are **already false** — `release`
   refuses `Rejected` outright today — and this unit makes them permanently
   false, because the corruption tombstone is the one axis the override does
   not reach. Replace them with what is true: the comparison a curator can
   perform confirms nothing about bytes that disagree with the hash naming
   them, and `VerifyingReader` fails that read regardless (ADR 0003).
   Re-measure both line numbers.
8. **The operator guide for the override is this unit's, and so is the
   corruption-recovery sentence.** Two things depend on it:
   - `curator-workflow.md` currently says the guide *"gains the procedure when
     that capability lands"* (`:419` after item 302; re-measure). That promise
     is this unit's to keep: the `Rejected` row of §4's state table becomes a
     procedure — which axes a waive reaches, what the justification must
     record, and that corruption never yields.
   - `cas-storage.md`'s corruption row is **already corrected** — item 304 did
     it while sweeping the removed route, and it now states the accurate rule
     and the recovery: `rejected` is not a release source state, a re-scan says
     nothing about the wrong bytes, and *"recovering a false positive means
     re-ingesting the restored blob"*. Re-read that row before writing
     anything, keep it consistent with whatever this unit lands, and do **not**
     re-litigate it. What is still missing is only the counterpart on the
     curator's side: this unit's override reaches three axes and the guide must
     say that corruption is the fourth and is never one of them.
9. **ADR 0025 needs a dated one-liner when this lands.** Its `:30` reads
   "neither `admin_release` nor curator-waive exits [`rejected`]", which this
   unit falsifies. Item 302's amendment pre-empts the contradiction in ADR
   0007's prose, but ADR 0025 itself is untouched; add the dated line there
   pointing at ADR 0007's one-authority amendment. Nothing else in ADR 0025
   changes — its 409 contract is unaffected.

## Explicitly out of scope

- Anything in #342. Items 291/292 work the same axis from the other end (the
  signature constituents' exemption and the legacy population's repair); this
  unit adds the curator's override and must not re-derive their predicates.
- `re_evaluate`'s own eligibility guard — untouched, including its refusal of
  non-scan reasons. Two questions, two predicates.
- Re-blocking after an override: #344's unit 4 already protects a manually
  released artifact from a later scan verdict, which is the correct reading
  here too (the curator decided with the findings in view).
- Any widening of **who** may release.

## Acceptance

- A `(Curator, CuratorWaiver)` release succeeds from `Rejected` for each of the
  five overridable reasons and is refused with `InvalidState` for `Corruption`
  — one test per reason, driven from a table so a new reason cannot be
  forgotten.
- The released artifact's `rejection_reason` is `None` afterwards, asserted on
  the aggregate.
- `is_scan_clearable` is unchanged, and `re_evaluate` still refuses a
  `Curator { .. }` rejection — pinned, because the cheap implementation is to
  widen that predicate and this unit must not.
- Both predicates are wildcard-free: add a temporary eighth `RejectionReason`,
  show two compile errors, revert, and report it.
- A curator's own block can be undone by the same curator and by another one;
  the `ArtifactReleased` carries the releasing curator's id and justification.
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
