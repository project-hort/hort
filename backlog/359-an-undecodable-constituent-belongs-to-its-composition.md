# 359 — An undecodable constituent belongs to its composition, for every abstention that says so

**Issue:** #390 · **Branch:** `agent/390-constituent-abstention-conformance` · single item.

## This is a conformance gap, not an open design question

**ADR 0064 D2 already decided it**, and states the criterion in one sentence:

> *"The line is whether what the scan says is about **the bytes** or about **the
> resulting filesystem**, and it governs the **absence** of an assessment
> exactly as it governs a finding. 'I have no decoder for this container' is not
> a statement that the layer's bytes are dangerous — the composition decodes
> them — so it belongs to the composition and must not gate the constituent.
> 'This archive tripped an extraction bound' or 'an entry tried to escape the
> workspace' is about the bytes and keeps gating."*

`NotAnalysable::gates_release`
(`crates/hort-domain/src/ports/scanner.rs:415-428`) implements that rule for
**one** abstention reason and not for its twin:

```rust
Self::NotApplicable => false,
Self::UnsupportedContainer => {
    !(kind.is_composition_constituent()
        && composite_verdict.carries_release_authority())
}
Self::UnusableArchive | Self::NoAnalyzerMatched | Self::IncompleteComposition => true,
```

`NoAnalyzerMatched` is "no analyzer claimed this" — an absence of analysis, not
a claim about the bytes. By D2's criterion it belongs on the carve-out side, and
it is on the gating side.

`ScanAssessment::NotApplicable` names this exact population as one of the two it
serves (`crates/hort-domain/src/events/artifact_events.rs:248-264`): *"a surface
that is not this artifact's to assess — an OCI layer this adapter has no decoder
for, under a policy that has promoted the composite verdict … (ADR 0064 D2)"*.
So the intended destination for these rows already exists and already returns
`Completed`; `NoAnalyzerMatched` simply cannot reach it.

## Measured consequence (#390, live instance)

A `library/sonarqube` manifest released while four of its layer blobs sit
`scan_indeterminate` with `last_scan_at = NULL` and terminal `failed` scan jobs,
error `trivy=no_analyzer_matched` for `kind oci_blob`. The manifest serves
`200`, the layers serve `503`. A client that resolves the manifest and fetches
its layers fails on an artifact hort reports as `released`.

## The change

**Give `NoAnalyzerMatched` the same arm as `UnsupportedContainer`** — the
existing `is_composition_constituent() && carries_release_authority()`
condition, unchanged.

**Keep that condition. Do not make the carve-out unconditional.** Under
`compositeVerdictMode: observed` the composite verdict carries no release
authority, so handing a constituent's unanalysability "to the composition"
would hand it to something that decides nothing, and the layer would release
with nobody having assessed it. The condition is what makes the hand-off
meaningful, and ADR 0064 D1 does not make the composite verdict authoritative
on its own — `observed`/`promoted` remains the authority switch.

`IncompleteComposition` and `UnusableArchive` **keep gating** in this unit. The
first is a statement about the composition itself; the second is discussed
below.

## What this does NOT do, and say it in the MR

**It does not free the reported instance's blobs by itself.** That instance runs
`observed` on all 31 active policies. After this change those four layers still
hold, because there is still no authority to inherit from — the operator must
also set `compositeVerdictMode: promoted` on the policy. The code change makes
that configuration *work*; the configuration makes the image pullable. Shipping
this while implying otherwise would send the reporter back to the same 503.

## Declared, separable, and not in this unit

ADR 0064 D2's own text names a second conformance gap in the same sentence:

> *"Today both reach `NotAnalysable::UnusableArchive`
> (`crates/hort-adapters-scanner-trivy/src/workspace.rs:739-741,674`), which
> gates, so a `tar+zstd` layer is terminal standing alone."*

So `UnusableArchive` conflates "no decoder for this compression" (must not gate)
with "extraction bound tripped / entry escaped the workspace" (must gate). That
needs the variant split into two reasons plus a trivy-adapter change, which is a
larger unit than extending one arm. **Leave it. Report that you left it.** It is
the same rule and it deserves its own run.

## Tests — the existing coverage cannot see this, and that is the interesting part

Both gaps are measured; fix both.

1. **`scripts/native-tests/scenarios/quarantine/trivy-oci-not-applicable.sh`
   cannot reach the gating path.** Its fixture policy is `enforcement: record`,
   chosen deliberately so release assertions do not depend on today's CVEs —
   and under `record` no verdict gates at all. Its synthetic package-less layer
   also yields `NotApplicable`, the arm that already does not gate, never
   `NoAnalyzerMatched`. So it proves every row gets a completed assessment, not
   that a **gating** repository releases the image.

   Add a scenario (or a second fixture repo beside `oci-trivy-e2e`) with
   `enforcement: reject` **and** `compositeVerdictMode: promoted`, over an image
   carrying a layer that yields `no_analyzer_matched`. Assert the layer blob
   returns **200** after release. Confirm in the report that this test **fails
   before the change** — that is the proof the unit exists.

2. **`scripts/native-tests/scenarios/quarantine/proxy-required-multilayer.sh`
   fetches every layer blob and throws the status away.** Step 3 issues
   `GET …/blobs/sha256:<layer>` with `-o /dev/null` and `|| true`, under an
   honest comment: *"Statuses are deliberately NOT asserted beyond curl
   completed — this is a forcing step, not an assertion."* It is the exact
   request that 503s in production, and it yields no signal.

   Leave the forcing step a forcing step — it runs before release on purpose.
   Add **one** assertion after the release poll: fetch a layer blob and require
   `200`. A forcing GET that discards its status looks like coverage in an
   inventory and is none.

## Acceptance

- `NoAnalyzerMatched` on a composition constituent under a verdict with release
  authority does not gate; everything else about the arm is unchanged.
- The exhaustive match stays exhaustive with no wildcard, and each arm's answer
  stays stated rather than inherited — the enum's own doc requires it.
- `IncompleteComposition` and `UnusableArchive` still gate; a test pins that, so
  the change cannot be read as "abstentions stopped gating".
- The new E2E fails before the change and passes after; stated as such in the
  report.
- `proxy-required-multilayer.sh` asserts a layer blob `200` after release.
- `CHANGELOG.md`: one `### Fixed` line. An operator can observe this — a
  released image becomes pullable — and the entry must say that it requires
  `compositeVerdictMode: promoted` to take effect, since that is the operator
  action.
- `docs/adr/0064-*.md` is **not** edited. This unit conforms to it; it decides
  nothing new. If you believe the ADR is wrong, say so in the report and change
  nothing.
