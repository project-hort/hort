# Recover stalled scans

An artifact can remain quarantined if its initial scan could not run because scanner processes were unavailable or failing. This is different from an **indeterminate scan result**: a scanner that ran but produced unclassifiable output requires curator review.

## Identify the failure

1. Check `hort-worker` health, logs, resources, and availability of its configured scanner executables.
2. Confirm whether the artifact is still quarantined and whether recent scan jobs failed.
3. If exposed in your version, monitor `hort_cron_rescan_stranded_eligible_artifacts`: a sustained positive value suggests stranded artifacts awaiting another scan attempt.

Do not lift quarantine just because an external scanner service was temporarily unavailable.

## Restore automatic recovery

Restore the worker and scanner dependencies first. The `cron-rescan-tick` maintenance task selects quarantined artifacts whose most recent scan failed from an execution error and for which no scan job is in flight. When the task runs, it requeues scans. Verify that your deployment **actually schedules** this maintenance task; the worker alone does not substitute for the scheduler.

Monitor job completion and the artifact status. A successful rescan follows the normal release policy; findings can still block release.

## Request an individual rescan

If you need to trigger a scan before the next maintenance tick, and your identity has the necessary permission on the repository, use:

```bash
hort-cli admin rescan <artifact-id>
```

Alternatively, an authorized client can call `POST /api/v1/artifacts/<artifact-id>/rescan`. An artifact's eligibility and authorization are checked by the service. Do **not** insert scan jobs directly into PostgreSQL as a routine recovery procedure.

## When a rescan is not enough

A terminal `scan_indeterminate` result is **not** the same as scanner execution failure; refer it to an authorized curator and your documented review process. Check [Scanning & governance](scanning-governance.md) and [Monitoring & troubleshooting](monitoring.md).
