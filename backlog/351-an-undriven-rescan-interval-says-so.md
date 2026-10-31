# 351 — An undriven rescan interval says so, and names the switch

**Issue:** #388 · **Branch:** `agent/388-scan-obligation`
**Governing decisions:** ADR 0015 (a policy field is enforced or rejected at
apply — the `max_age_days` exemplar) · ADR 0048 (what staging deploys) ·
the project rule that a scanner must deliver the threat level the repository's
configuration declares.

## What is true today

`rescanIntervalHours` is **not** inert in the code. Its consumer exists and is
correct: `crates/hort-adapters-postgres/src/rescan_candidates.rs:112-141`
reads `COALESCE(p.rescan_interval_hours, $3)`, defaults to 24 h, and filters
`> 0`.

What is missing is the **driver**. That query runs only when the
`cron-rescan-tick` task runs, and the chart does not schedule it:

```yaml
# deploy/helm/hort-server/values.yaml:1937-1940
cronRescanTick:
  executionPath: admin-task
  enabled: false
  schedule: "*/5 * * * *"
```

Measured on the reporting instance: every ScanPolicy carries
`rescanIntervalHours: 24`, no `cron-rescan-tick` CronJob is deployed, and the
job kind has run **once, three weeks ago**.

## Why this is a defect

This is not the ADR 0015 shape in the strict sense — the consuming use case
does enforce the field. It is the same harm by a different route: an operator
reads `rescanIntervalHours: 24`, concludes that advisories landing tomorrow
will be matched against yesterday's artifacts, and makes a threat-model
decision on it. In the default deployment that does not happen, and nothing
says so. A repository comment in this tree describes the posture as
"surviving the ingest scan AND the 24h rescan", which the default deployment
does not deliver.

Combined with #388 §1 (a failed ingest scan never retried) the instance had
no automatic path to a second scan at all.

**What is *not* the defect:** that the tick is off by default. That is a
deliberate choice (see *The change*). The defect is that choosing it costs an
operator a declared behaviour and nothing tells them.

## What the interval does and does not cover

`select_eligible` selects **released or null-status** artifacts
(`crates/hort-adapters-postgres/src/rescan_candidates.rs:133-149`). Artifacts
stranded by a failed scan job are a *separate*, failed-job-driven query
(`:265-277`), and the interval does not re-scan terminally rejected or
indeterminate ones at all. So the promise this unit makes reachable is "a
released artifact is re-scanned every N hours", not a universal rescan. Say
that in the values documentation; do not promise more than the selector does.

## The change

**The chart default stays `false`.** Decided by the issue owner on
2026-10-31: *"cronRescanTick bleibt optional. Wer es braucht, schaltet es
ein."* So this unit does not touch any deployment, and the silent-gap risk is
closed by saying so rather than by changing what operators get.

That makes the warning the whole unit, and it has to be actionable rather than
merely true:

When any active ScanPolicy carries a non-zero `rescan_interval_hours` and no
`cron-rescan-tick` has completed within a generous multiple of the shortest
such interval, the server warns — **once per boot**, naming:

- the shortest configured interval and which policy carries it,
- the age of the last completed `cron-rescan-tick`, or that there is none,
- **the value to set**: `scheduledTasks.cronRescanTick.enabled`. An operator
  reading this line must not have to go looking for the switch.

The warning is a statement about reachability, not a verdict on the
configuration: an operator who deliberately runs without the tick is not
misconfigured, they have made a choice, and the line tells them what the
choice costs rather than scolding them for it.

**Not an apply-time rejection.** ADR 0015's shape — reject a field the
consumer ignores — does not fit here: the consumer exists and enforces the
field correctly. Rejecting `rescanIntervalHours` would break configurations
that are right, and the gap is in the *deployment*, which gitops apply cannot
see. This is the one case in that family where the honest close is a runtime
statement rather than a refusal.

## Stop making the promise — the classified census

Approved by the owner on 2026-10-31 ("Wenn das dann insgesamt dann konsistent
ist, ja, stelle das so um"), and the condition *is* the work: the claim is in
ten places and **a blanket sweep would damage the correct ones**. Classified
by hand:

**Claims the behaviour happens — must change:**

| Site | What it says |
|---|---|
| `crates/hort-domain/src/policy/scan.rs:180-181` | "out-of-the-box deployments rescan artifacts every 24 hours" |
| `crates/hort-domain/src/policy/scan.rs:790` | the same claim, in a test comment |
| `crates/hort-config/src/scan_policy.rs:929` | the same claim again |
| `crates/hort-adapters-postgres/src/rescan_candidates.rs:224` | "out-of-the-box deployments with zero `ScanPolicy` rows **still get stranded artifacts recovered**" |
| `docs/architecture/explanation/scanning-pipeline.md:931-936` | the strongest: "even if every feed went silent, **every released artifact still gets re-adjudicated** on its policy's cadence" |
| `docs/architecture/how-to/recover-stranded-artifacts.md:57` | "drives the routine interval-based rescan" |
| `docs/architecture/reference/server-and-worker-configuration.md:415` | "stay ahead of routine cron rescans" |

The corrected form is the same in each: the interval governs the **cadence**
when the tick is scheduled. It is not a statement about what a default
deployment does.

**Correct as written — must NOT be swept.** These describe the default *value*
or the query's *scope*, not that anything runs:
`crates/hort-config/src/scan_policy.rs:201` (the YAML default),
`crates/hort-adapters-postgres/src/rescan_candidates.rs:15` (why
`quarantine_status IS NULL` is admitted),
`crates/hort-adapters-postgres/tests/rescan_candidates.rs:502`,
`crates/hort-domain/src/ports/jobs_repository.rs:185` ("Routine background
drain" — a trigger-source description).

**Already correct and the model for the rest:**
`docs/architecture/reference/helm-chart.md:324` — scheduled tasks are "off —
enable it only when you need rescanning".

**Exempt:** `CHANGELOG.md:2290`. The changelog is a record of what was said at
the time, not a document to bring up to date.

**The value itself does not move.** `DefaultPolicy::rescan_interval_hours()`
stays 24: migration 005's `DEFAULT 24` and the YAML deserializer's
`default = "default_rescan_interval_hours"` both refer back to it, and an
operator who *has* scheduled the tick would otherwise lose their rescan. Only
the claim goes.

## What the census found: §3 and §1 are coupled

`select_stranded` — the selector that re-picks an artifact left behind by a
failed scan job — has **exactly one production caller**:
`CronRescanTickHandler::run` (`crates/hort-app/src/task_handlers/cron_rescan_tick.rs:195`).
The same optional tick.

So unit 349's promise that a stranded artifact "becomes eligible for the
stranded-rescan selector" is true, and in a deployment without the tick
nothing drives that eligibility either. The two findings are one situation: a
scan that strands has no automatic recovery **and** no notice. That is the
case this unit's warning exists for, and it is why the warning must name the
switch rather than merely report a gap.

It is also recoverable by one operator action rather than a code change:
`POST /api/v1/admin/tasks/cron-rescan-tick` is a routed admin task
(`crates/hort-http-admin-tasks/src/lib.rs:84`), so an operator can drain the
stranded set once without scheduling anything.

## Acceptance

1. With a policy at `rescanIntervalHours: 24` and no completed tick in the
   window, the warning fires **once per boot**, naming the interval, the
   policy, the age of the last completed tick (or its absence), and the
   chart value to set.
2. With the tick running inside the window, no warning fires.
3. `rescanIntervalHours: 0` means "no rescan" and produces no warning — it is
   a declaration, not a gap.
4. The default `helm template` still renders **no** `cron-rescan-tick`
   CronJob. The owner's decision is an acceptance criterion, not a comment:
   a change that enables it by default fails this unit.
5. `deploy/helm/hort-server/values.yaml` states, on the `cronRescanTick`
   block, that **both** `rescanIntervalHours` and the stranded-artifact
   recovery are inert without it, and names the one-shot
   `POST /api/v1/admin/tasks/cron-rescan-tick` for draining once without
   scheduling.
6. Every site in the "must change" census above is corrected, and every site
   in the "must NOT be swept" list is **unchanged** — asserted by the review,
   not by a grep for the phrase. A blanket find-and-replace fails this unit.
7. No changelog entry: nothing an operator running hort can observe changes.
   (If the warning is considered observable, one line under `### Changed`
   naming it is acceptable — but the default is unchanged, so there is no
   upgrade action to describe.)

## Out of scope

- The rescan query itself. It is correct.
- Any change to what a rescan does once driven.
- The reported instance's deployment. A coverage gap there is a config change
  to propose, never a finding against the code.
- Enabling the tick by default. Decided against; see *The change*.

## What the independent review changed

`codex/gpt-6-sol` confirmed the driver claim — the only production caller of
`select_eligible` is `CronRescanTickHandler::run`
(`crates/hort-app/src/task_handlers/cron_rescan_tick.rs:169-194`), registered
by the worker, with no boot, sweep or admin path reaching it directly (the
admin route enqueues the tick, which then calls it). It also flagged that
"consumed correctly" needed the scope qualifier now stated above.
