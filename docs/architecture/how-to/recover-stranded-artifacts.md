# Recovering stranded artifacts

This guide is for operators who need to confirm whether artifacts are
**stranded** behind a scanner outage, and how to recover them — both the
automatic path (usually all you need) and the manual, **non-admin**
fallback for deployments with no IdP/Dex connector.

The quarantine state model and the fail-closed release predicate are
documented in
[ADR 0007](../../adr/0007-fail-closed-quarantine-release-predicate.md);
this guide covers the resilience mechanism issue #6 added on top of it.

---

## 1. What "stranded" means

An artifact's **initial** scan can fail for two structurally different
reasons:

- **The scan couldn't run at all** — every configured scanner backend
  errored (unreachable, crashed, timed out). This is a
  **scanner-execution / infrastructure failure**: transient, and
  recoverable once the scanner comes back.
- **The scan ran but the result was ambiguous** — the scanner executed
  and produced output hort could not parse or classify. This is a
  **terminal** failure under ADR 0007: the artifact transitions to
  `scan_indeterminate`, is never auto-rescanned, and only exits via
  admin override or post-exclusion policy re-evaluation.

Before issue #6, both failure modes collapsed onto the same outcome: on
retry exhaustion (`HORT_SCANNER_MAX_ATTEMPTS`, default 5), the artifact
went terminal `scan_indeterminate` either way. A scanner outage during
ingest therefore **permanently stranded** every artifact pulled during
it — `quarantine_status='quarantined'`, no release authority, and
nothing re-scanned it — until an operator manually intervened.

Issue #6 splits the two cases. A scanner-execution failure that
exhausts retries now leaves the artifact **exactly where it was**:
still `quarantine_status='quarantined'`, downloads still blocked (the
status is the gate — ADR 0007), but with a persisted "last scan
errored" fact (`jobs.status='failed'` on its most recent `kind='scan'`
row). **This is the "stranded" state this guide is about.** A
genuinely-ambiguous scan result still goes to the unchanged, terminal
`scan_indeterminate` path — that is not what this guide covers; see
[the curator workflow guide](curator-workflow.md) for recovering an
artifact in that state.

**No new release authority was added.** A recovered scan releases the
artifact via the existing `ScanSucceeded` authority (or rejects it on
findings) — this mechanism only gives the scan another chance to
actually run. It does not release anything on a timer.

## 2. The sweep self-heals — usually no action needed

The `cron-rescan-tick` task (the same k8s CronJob / admin-task that
drives the routine interval-based rescan, default schedule `*/5 * * *
*`) also re-picks stranded artifacts every tick, via
`RescanCandidatesRepository::select_stranded`: `quarantine_status='quarantined'`
artifacts whose last scan errored and have no in-flight `kind='scan'`
job. Once the scanner is back, the very next tick re-enqueues a fresh
scan for every stranded artifact — no operator action required. The
recovered scan releases the artifact normally (`ScanSucceeded`) or
rejects it on findings; nothing about the release predicate is
special-cased for a recovered stranded artifact.

### Confirming whether you currently have stranded artifacts

- **Metric**: `hort_cron_rescan_stranded_eligible_artifacts` (gauge, no
  labels) — set every tick to the stranded-candidate count. Sustained
  `> 0` means artifacts are stuck behind a scanner outage; a healthy
  scanner drains this to zero as the sweep re-enqueues each one. See
  `docs/metrics-catalog.md` → *Rescan and advisory watch*.
- **Logs**: `cron rescan tick: re-enqueued a stranded artifact` (`info!`,
  per artifact) fires whenever the sweep re-enqueues one — the
  `artifact_id` field gives you the per-artifact audit trail.
- **Admin API**: `GET /api/v1/admin/tasks?kind=scan&status=failed` lists
  the `kind='scan'` jobs sitting in `failed` status — cross-reference
  against `GET /api/v1/admin/quarantine/patch-candidates` or a direct
  artifact lookup to confirm `quarantine_status='quarantined'`. Requires
  `Permission::Admin`.

## 3. Manual recovery — the non-admin operator path

If you don't want to wait for the next tick (or the CronJob is
disabled), you can trigger a rescan directly. Two paths exist,
depending on what authority you have:

### 3a. Non-admin — `POST /api/v1/artifacts/:id/rescan`

This is the **supported, non-admin path**, including on a **Dex-off
deployment** (`registry.hort.rs`-style, no IdP connector configured).
It requires only `Permission::Write` on the artifact's parent
repository — the same permission that already gates uploads to that
repository. A Write grant is reachable without any OIDC/Dex round-trip:
a claim-based `PermissionGrant` targeting a service account (see
[declare-gitops-config.md](declare-gitops-config.md)) plus a
service-account bearer token (see
[rotating-service-account-tokens.md](rotating-service-account-tokens.md)
for how those tokens are issued) is enough.

```bash
hort-cli admin rescan <artifact-id>
# or directly:
curl -sS -X POST "$HORT_URL/api/v1/artifacts/$ARTIFACT_ID/rescan" \
  -H "Authorization: Bearer $TOKEN"
```

Response: `{ "task_job_id": "<uuid>" }` — poll
`GET /api/v1/admin/tasks/<task_job_id>` (admin-tier) or wait for the
next scan-completion notification to see the outcome.

This endpoint already refuses to double-enqueue: if the artifact has
an in-flight `kind='scan'` job, it returns `409 Conflict` with the
existing job id instead of creating a duplicate. A stranded artifact
(no in-flight job — its last attempt already failed terminally) is
always a valid rescan target.

### 3b. Admin — the raw `enqueue_scan` insert (legacy fallback)

Before issue #6, the only way to un-strand an artifact was a direct
`jobs` table insert via an admin DB session — this required admin-tier
auth, which is unavailable on a Dex-off deploy without the DSN-gated
`bootstrap-session` break-glass path (see
[Recipe B in the admin-identity guide](deploy/admin-identity-and-dex.md)).
**Prefer 3a above** — it needs only `Permission::Write`, not admin, and
goes through the same audited use case (`ManualRescanUseCase`) the
production rescan-now button uses. The raw-insert path remains only as
a last resort if the HTTP surface itself is unreachable.

## 4. What does NOT recover a stranded artifact

- **A genuinely `scan_indeterminate` artifact is not touched by any of
  the above.** That status is terminal by design (ADR 0007) — recover
  it via admin override (`POST /api/v1/admin/quarantine/:artifact_id/release`,
  admin-tier only — curator-waive is intentionally narrower and does
  not reach `ScanIndeterminate`) or post-exclusion policy
  re-evaluation. See [the curator workflow guide](curator-workflow.md).
- **Waiting past `quarantine_until` does nothing on its own.** The
  release predicate has no timer-only authority (ADR 0007); a stranded
  artifact only releases once a scan actually succeeds.
