# 101 — Build-source selection per pipeline type, internal warm, release switch

**Issue:** #139 (items D, E) · **Branch:** `agent/139-instance-parameterisation` · **Scope:** `.gitlab-ci.yml`
**Depends on:** backlog 099 (the `HORT_BUILD_URL` / `HORT_WARM_URL` split must exist first)

## Why this item does NOT flip the default

The target is: feature and develop pipelines build against the internal
instance, release pipelines can switch to the public one. Both depend on
conditions that cannot be verified from this repository:

- the internal `cargo-virtual` must serve the **whole** locked set — under
  `released_only` an unwarmed or still-quarantined version is invisible, and a
  build resolving against it fails exactly as `test:lint` did when the proxy
  variable was set prematurely;
- the internal instance must have the `gitlab` issuer, the `gitlab-ci` service
  account and its read grant applied.

So this item ships the **mechanism** and leaves activation to one operator
variable, with today's values as the defaults. Flipping it becomes a deliberate
act taken *after* `prefetch:verify` reports the internal instance serves the
lock — not a side effect of merging.

## Change

**D — build source selectable per pipeline type.**

- The build source resolves from a variable whose default is unchanged
  (public). Provide the per-pipeline-type wiring — feature/develop vs release —
  so switching is a value change, not a structural edit.
- **Add an internal warm.** A build source can only serve what it has been
  warmed with, so warming the internal instance is a precondition of ever
  switching, not a later nicety. Reuse the existing warm job shape with the
  build-source URL as its target; keep it `allow_failure: true` and gated the
  same way, so it is inert until the instance is reachable and authorised.
- Document, next to the variable, the exact precondition for flipping it:
  a green `prefetch:verify` against that instance.

**E — release switch.** A variable letting a release pipeline select the public
instance as its build source, honouring the same default-unchanged rule and the
same readiness precondition.

## Acceptance

- Defaults unchanged ⇒ green pipeline identical to today's behaviour; this is
  the primary proof.
- The selection logic is demonstrated at shell level for each pipeline type
  (feature / develop / release, switch on and off) rather than by mutating a
  live pipeline.
- The internal warm job is present and inert with the current configuration
  (it must not fail a pipeline when the internal instance rejects it).
- Every new variable carries an inline comment stating what flipping it
  requires.
