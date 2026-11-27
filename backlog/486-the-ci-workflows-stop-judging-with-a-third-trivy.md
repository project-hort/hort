# 486 — the CI workflows stop judging with a third Trivy version

**Issue:** #463 · **Branch:** `agent/463-scanner-versions`. **After unit 485**,
which sets the version this one follows.

## What is wrong

`.github/workflows/scheduled-container-scan.yml` and
`.github/workflows/docker-publish.yml` pin `trivy:0.69.3`. That is a third
independent consumer, behind both the worker container and the Ansible path, so
our CI container scan currently judges our images with an older ruleset than
the scanner that gates artifacts at runtime.

## What to do

Point both at the same version unit 485 chose, and leave a single place that
says what that version is if the workflows can reference one. If they cannot —
GitHub workflow syntax has no shared variable across files without a reusable
workflow or an input — then say so and keep the two literals, because two
honest literals a guard can check beat one clever indirection that drifts
silently.

**Then consider whether a guard is owed.** `scripts/check-osv-scanner-version.sh`
exists because two osv pins must agree; after this unit there are two Trivy
pins that must agree with a third place. Decide whether to extend that script
to Trivy or add a sibling, and say why — including "no guard, because unit 487's
mechanism will propose the bump" if that is the honest answer.

## Acceptance

- Neither workflow names a Trivy version other than the one unit 485 set.
- If a guard is added, it fails when the pins disagree — demonstrated by making
  them disagree in a scratch copy and watching it fail.
- `bash scripts/run-shell-guards.sh` is run and its exit code reported; **2 is
  not a pass**, it means a guard could not run here.

## Not in scope

Changing what the workflows scan, their schedule, or their failure thresholds.
