# 154 — re-tighten quality:sonar (remove allow_failure)

**Issue:** #220 · **Branch:** `agent/220-sonar-complexity` · Item 2 of 2 (dispatched only after the architect has confirmed the item-153 branch-pipeline sonar verdict is green; one MR carries both items).

## Problem

`quality:sonar` runs advisory (`allow_failure: true`) — the deliberate
interim posture from the gate-read-back work, parked until the gate
baseline is green. Item 153 removes the findings; this item closes the
loop.

## Precondition (architect-verified, evidence in the issue)

The branch pipeline for the item-153 push shows, in its
`quality:sonar-findings` log: quality gate `OK` (or at minimum: zero
`rust:S3776` findings and no failing condition attributable to the
refactored set). Without that evidence this item is NOT dispatched.

## Task

1. `.gitlab-ci.yml` `quality:sonar`: remove `allow_failure: true` and
   replace the advisory-posture comment with the tightened invariant: the
   gate verdict now blocks — a red gate means the change is not done; the
   findings job (`quality:sonar-findings`, unchanged, still
   `allow_failure: true` + `when: always`) names what to fix.
2. `docs/ci/README.md`: update the Sonar section's advisory-posture
   paragraph to the tightened state (keep the description of the findings
   job and the clippy import unchanged).
3. `CHANGELOG.md`: fold into/extend the existing `[Unreleased]` sonar
   bullet (or one new `### Changed` line) — the gate is now blocking.

## Acceptance

- `quality:sonar` has no `allow_failure`; comment states the blocking
  invariant; docs match.
- CI lint API validation by the architect at review (harness-only diff:
  `.gitlab-ci.yml`, docs, CHANGELOG — gate per harness-only economy:
  `bash -n` n/a, diff-proof + audit/deny).
- Comment discipline: invariants only.

## Governing decisions

#219 D1 (this IS the deliberate re-tighten that decision parked) · the
token-expiry consideration stays covered: a dead token now fails the
pipeline loudly again, and the findings job explains it as an auth failure
— that is the intended posture once the gate is load-bearing.
