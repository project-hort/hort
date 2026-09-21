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

---

## 5. A different strand: artifacts wrongly `rejected` on the provenance axis

Everything above is about the **scan** axis. There is one historical
population stranded on the **provenance** axis, and it needs a different
tool.

### What happened

Before [ADR 0039](../../adr/0039-keyed-provenance-verification.md)'s
2026-09-12 amendment, an artifact under `provenanceMode: required` whose
signature had not yet reached hort when the verify ran was driven
**terminal**: `quarantine_status = 'rejected'`, `rejection_reason` left
NULL, and — because the provenance axis did not write one — **no
`ArtifactRejected` event on its stream**. With cosign the signer must
resolve the subject manifest before it can attach a signature to it, so
the verdict running first is the *normal* ordering: the signature landed
a moment later and a `ProvenanceVerified` was appended to the very same
stream.

The artifact is therefore condemned by a verdict its own stream
contradicts. The amendment stopped this happening (a missing signature
now **holds** indefinitely instead of rejecting), but it did not move the
artifacts already in that state — and **none of the ordinary exits
reaches them**:

- `POST /api/v1/admin/curation/quarantine/:id/reevaluate` answers
  `{"outcome":"still_rejected"}` and writes nothing. Its eligibility
  guard admits only a *scan-clearable* rejection, and that refusal is
  correct: a scan re-judgement must never clear a provenance rejection.
- `release` / `waive` do not apply — their source-state guard admits only
  `quarantined` / `scan_indeterminate`.
- Re-pushing produces no ingest: the content is already present, so the
  push is a no-op.

### Confirming whether you have any

```bash
# Rejected rows whose rejection reason is null — no ArtifactRejected
# behind the status. Requires Permission::Curate or Permission::Admin.
curl -s -H "Authorization: Bearer $TOKEN" \
  "$HORT_URL/api/v1/admin/curation/queue?status=rejected" \
  | jq '.entries[] | select(.rejection_reason_kind == null)'
```

A row with a non-null `rejection_reason_kind` is a **real** rejection and
is not part of this population. A null one is *probably* in it but not
necessarily — a CAS-corruption tombstone written by an older Hort also
shows null (a current one shows `corruption`, since the tombstone now
records its own rejection event), and the repair refuses those; the dry
run below is what tells you which is which. `?reason=provenance` lists the opposite
group — artifacts a *positive disproof* rejected (signature present and
invalid), which are terminal by design and stay that way.

### The repair — dry run first

```bash
# 1. DRY RUN (the default: an absent body, or a body without `dry_run`,
#    never mutates). Reports exactly what a real run would touch.
curl -s -XPOST -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$HORT_URL/api/v1/admin/quarantine/provenance-misrejections/repair" | jq

# 2. Read the `affected` list. When you are satisfied it is the set you
#    expect, run it for real.
curl -s -XPOST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"dry_run": false}' \
  "$HORT_URL/api/v1/admin/quarantine/provenance-misrejections/repair" | jq
```

Optional body fields: `repository_id` (narrow the scan to one
repository) and `limit` (how many `rejected` rows to examine; clamped to
500). If the response has `"scan_cap_hit": true`, there may be more rows
beyond the bound — re-run, optionally per repository, until it is
`false`.

**Requires `Permission::Admin`, not `Permission::Curate`.** This is not a
curation decision — it withdraws a structurally invalid rejection — and
per [ADR 0038](../../adr/0038-admin-identity-model.md) service accounts
are strictly non-admin, so it cannot be driven from a pipeline. A human
operator with an IdP-assumed admin session runs it.

### What it will and will not touch

It repairs an artifact only when **all three** hold:

1. `quarantine_status = 'rejected'`;
2. its stream records **no terminal condemnation** — no
   `ArtifactRejected` (every real rejection writes one) and no
   `ArtifactCorrupted` (the CAS integrity tombstone reaches `rejected`
   without writing an `ArtifactRejected`, so it needs naming separately);
   and
3. a `ProvenanceVerified` **is** on its stream — without this, an
   artifact that really was never signed would be released.

So it leaves alone: an artifact rejected by a *positive disproof*
(present-but-invalid signature — it carries both `ProvenanceRejected` and
`ArtifactRejected`), a scan-rejected artifact, a curator- or
admin-blocked one, an artifact tombstoned because its stored bytes do not
match their content hash, a never-signed artifact still held
`quarantined`, and anything already released.

### What happens after

A repaired artifact goes back to `quarantined` with its **original**
observation-window anchor — restored, not restarted — and an
`ArtifactReEvaluated` + `ArtifactQuarantined` pair is appended to its
stream (the repair is recorded as events; the status is only the
projection). The ordinary release sweep picks it up on its next tick and
applies the live scan, curation and provenance gates. Because the
`ProvenanceVerified` that made it repairable is the same event the
release gate reads, the provenance conjunct clears and the artifact
releases normally.

OCI tags pointing at a repaired manifest need no separate action: a tag
resolves through the manifest, so it becomes servable when the manifest
does.

The repair is idempotent — a second run finds nothing, because the first
one moved the artifact out of `rejected`.
