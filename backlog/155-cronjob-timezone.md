# 155 — chart CronJobs: shared `spec.timeZone` (default Etc/UTC)

**Issue:** #223 · **Branch:** `agent/223-cronjob-timezone` · **One reviewable unit (one MR).**

## Problem

None of the chart's 18 CronJob templates set `spec.timeZone`, so Kubernetes
interprets every `schedule:` in the kube-controller-manager's local
timezone. Field-observed during the scan-row-retention first-fire check:
`0 3 * * *` (template comment: "daily at 03:00 UTC") fired at 01:00 UTC
(= 03:00 Europe/Berlin). The comments promise UTC; the behavior is
cluster-dependent.

## Task

1. **One shared value** `scheduledTasks.timeZone`, default `"Etc/UTC"`, in
   `values.yaml` (comment: applies to every chart CronJob; changing it
   shifts ALL schedules; IANA name required, stable in Kubernetes ≥ 1.27) —
   and in `values.schema.json` (type string, non-empty).
2. **Every CronJob template** (all 18 `templates/cronjob-*.yaml`, including
   `cronjob-noop.yaml`) gains
   `timeZone: {{ .Values.scheduledTasks.timeZone | quote }}` directly under
   `schedule:`. No per-job override (a job needing a different zone can
   argue for one when it exists — YAGNI).
3. **Comment truth pass, scoped:** where a template comment states a
   wall-clock time ("daily at 03:00 UTC"), it is now actually true — no
   text change needed; where a comment states a time WITHOUT a zone, append
   "(scheduledTasks.timeZone, default UTC)" only if the comment is
   otherwise misleading. Do not rewrite unrelated comment prose.
4. **Template-test coverage**: extend the helm-template-test suite
   (whatever `quality:helm-template-test` runs) with one check asserting
   every rendered CronJob carries `timeZone: Etc/UTC` by default and that
   an override value renders through — mirroring the suite's existing
   per-resource assertion style. This doubles as the guard against a new
   CronJob template forgetting the field.
5. `CHANGELOG.md`: one `### Fixed` bullet under `[Unreleased]` (chart
   CronJob schedules now anchored to UTC by default instead of
   controller-local time; operators relying on the old local-time behavior
   set `scheduledTasks.timeZone`).

## Behavior-change note (for the MR description, not a blocker)

On clusters whose controller TZ is not UTC, all schedules shift (here:
2h later in wall-clock UTC terms — e.g. the sweeps move from 01:00 UTC to
03:00 UTC). Daily/15-min jobs are all idempotent sweeps/ticks; a one-time
shift is harmless. The `values.yaml` comment carries this.

## Acceptance

- All 18 templates render `timeZone`; template test pins it (default +
  override); schema accepts the value; `helm lint` clean (via the
  established template-test job path).
- Harness-only diff (chart + CHANGELOG) — gate per harness-only economy
  (template tests run via their script if locally runnable, else noted;
  audit/deny; diff-proof).
- Comment discipline: invariants only.

## Governing decisions

Chart comment-truth convention (`quality:chart-and-rust-pin-sync` house
rule) · Kubernetes CronJob `timeZone` (stable ≥ 1.27, cluster requirement
met) · #216 first-fire evidence (the observed 2h offset).
