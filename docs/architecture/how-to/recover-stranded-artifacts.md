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

An artifact's **initial** scan can fail for three structurally different
reasons:

- **The scan couldn't run at all** — every configured scanner backend
  errored (unreachable, crashed, timed out, or returned output hort
  could not parse). This is a **scanner-execution / infrastructure
  failure**: transient, and recoverable once the scanner comes back.
- **The scan ran and answered that there was nothing to analyse** —
  every configured backend executed and none of them examined the
  artifact: no analyzer matched its kind, or the payload was an archive
  the adapter refused to materialise. The artifact transitions to
  `scan_indeterminate`. Under ADR 0007 that is a **hold, not a dead
  end** — a verdict that is reached supersedes the absent one, so a
  non-blocking verdict returns the artifact to `quarantined` and the
  ordinary release sweep decides from there, while a blocking one
  condemns it. The curator's manual release and post-exclusion policy
  re-evaluation reach it as well.
- **The scan never got as far as having something to assess** — an OCI
  image manifest whose **composition** could not be produced within the
  job's attempt budget, because a store or the repository's upstream did
  not answer. The artifact is held `quarantined`, not
  `scan_indeterminate`, and that is deliberate: `scan_indeterminate` is
  the one withheld state no caller's hold-read reaches, write-granted
  included, so on a pull-through repository it would withhold the very
  client pull that drives the absent layers into CAS. The job row is
  `failed`, so the sweep below re-asks. This is the shape of a
  `hort_scan_record_outcome_failures_total{result="composition_not_produced"}`
  tick, and in a permissive (`quarantineDuration: 0`) repository the hold
  is *taken* by this path rather than inherited — see §6.

**They differ in what is owed, and that is what this guide is about.**
The first and the third are owed another scan attempt — the scan never
ran, or never got far enough to assess anything, so running it again is
the fix, and hort records that with a **`failed`** `kind='scan'` row and
re-drives it on the next tick. The second is owed nothing *immediately*:
it ran and reported, so its row **completes**, and re-running the
identical scan on the next tick would only repeat the identical answer.

What it is owed is a re-ask on a longer cadence, and the sweep gives it
one — once its resolved rescan interval has elapsed (§2a), because the
cause can go away without anything emitting an event to say so. So
removing the cause (§4) is what makes that re-ask produce a verdict
rather than the same abstention; a manual rescan (§3) only gets the
answer sooner than the interval would. §2 below covers all three
populations; §2a is the second one specifically.

Before issue #6, both failure modes collapsed onto the same outcome: on
retry exhaustion (`HORT_SCANNER_MAX_ATTEMPTS`, default 6), the artifact
went terminal `scan_indeterminate` either way. A scanner outage during
ingest therefore **permanently stranded** every artifact pulled during
it — `quarantine_status='quarantined'`, no release authority, and
nothing re-scanned it — until an operator manually intervened.

Issue #6 splits the two cases. A scanner-execution failure that
exhausts retries now leaves the artifact **exactly where it was**:
still `quarantine_status='quarantined'`, downloads still blocked (the
status is the gate — ADR 0007), but with a persisted "last scan
errored" fact (`jobs.status='failed'` on its most recent `kind='scan'`
row). **This is the "stranded" state this guide is about**, and that
`failed` row is both its definition and its discovery key.

A scan that **answered** "nothing to analyse" goes to the
`scan_indeterminate` path and leaves a **`completed`** row instead. ADR
0007's "A reached verdict supersedes an absent one" still holds for it —
a reached verdict is accepted and decides the artifact — but the
stranded sweep is not what delivers one: `select_stranded` requires the
most recent `kind='scan'` job to be `failed` or absent, so a completed
row takes the artifact out of it. That is deliberate. A deterministic
abstention re-answers the same way on every attempt, so re-enqueueing it
every tick spent batch capacity to re-record one fact forever, and
`jobs.status='failed'` claimed an error that never happened. This
population is listed and recovered by the mechanisms in §4, not by the
sweep in §2.

**No new release authority was added.** A recovered scan releases the
artifact via the existing `ScanSucceeded` authority (or rejects it on
findings) — this mechanism only gives the scan another chance to
actually run. It does not release anything on a timer.

## 2. The sweep self-heals — once the tick is scheduled

The `cron-rescan-tick` task (the same k8s CronJob / admin-task that
drives the routine interval-based rescan when it is scheduled, default
schedule `*/5 * * * *`) also re-picks stranded artifacts every tick, via
`RescanCandidatesRepository::select_stranded`: `quarantine_status IN
('quarantined', 'scan_indeterminate')`
artifacts whose last scan errored — or that have no `kind='scan'` job at
all, or that are held with no verdict and were last asked longer ago
than their resolved rescan interval (§2a) — and have no in-flight
`kind='scan'`
job. Once the scanner is back, the very next tick re-enqueues a fresh
scan for every stranded artifact — no operator action required. The
recovered scan releases the artifact normally (`ScanSucceeded`) or
rejects it on findings; nothing about the release predicate is
special-cased for a recovered stranded artifact.

**The tick is opt-in, so "no action required" presumes you scheduled
it.** `scheduledTasks.cronRescanTick.enabled` defaults to `false`, and
that one task is the only production caller of *both*
`select_stranded` and the interval-based `select_eligible` — so on a
deployment without it, nothing in this section happens on its own and
no metric moves to say so. Two ways out, and they are different
choices rather than alternatives to the same thing:

- **Schedule it** — `scheduledTasks.cronRescanTick.enabled=true` — and
  the self-healing above is what you get from then on.
- **Drain once without scheduling anything** —
  `POST /api/v1/admin/tasks/cron-rescan-tick` (or
  `hort-cli admin task invoke cron-rescan-tick`). One tick, one pass
  over the stranded set; nothing recurs.

`hort-server` logs the gap once per boot and sets
`hort_rescan_drive_undriven` when an active policy declares a non-zero
`rescanIntervalHours` and no tick has completed in the window, so an
undriven deployment is discoverable without reading this guide first.

### Confirming whether you currently have stranded artifacts

- **Metric**: `hort_cron_rescan_stranded_eligible_artifacts` (gauge, no
  labels) — set every tick to the stranded-candidate count. Sustained
  `> 0` means artifacts are stuck behind a scanner outage; a healthy
  scanner drains this to zero as the sweep re-enqueues each one. See
  `docs/metrics-catalog.md` → *Rescan and advisory watch*.
- **Logs**: `cron rescan tick: re-enqueued an artifact no sweep would
  otherwise reach` (`info!`, per artifact) fires whenever the sweep
  re-enqueues one — the `artifact_id` field gives you the per-artifact
  audit trail and the `source` field says which predicate found it
  (`stranded` or `composite_unassessed`; the routine `interval` source
  is deliberately silent per artifact).
- **Admin API**: `GET /api/v1/admin/tasks?kind=scan&status=failed` lists
  the `kind='scan'` jobs sitting in `failed` status — cross-reference
  against `GET /api/v1/admin/quarantine/patch-candidates` or a direct
  artifact lookup to confirm `quarantine_status='quarantined'`. The task
  listing requires `Permission::Admin`; the patch-candidate listing
  requires `Permission::Curate` or `Permission::Admin` — it is the read
  that grounds the manual release, which the curator owns (ADR 0007).

  **This listing is the stranded population and only it.** A scan that
  answered "nothing to analyse" completed its row, so it is absent
  here — by design: this listing is keyed on the **job's** status, and
  that scan answered. The sweep reaches such an artifact by its own
  predicate instead (§2a). Use
  `GET /api/v1/admin/curation/queue?status=scan_indeterminate`
  (`Permission::Curate` or `Permission::Admin`) to list artifacts held
  without a verdict whatever the reason, and the
  `hort_scan_jobs_total{result="nothing_analysable"}` counter to see the
  abstentions happening. A metric sustained above zero there is a
  repository paired with backends that cannot adjudicate its format —
  a `scanBackends` fix, not a scanner outage.

## 2a. The same tick is the existing-estate reassessment

A change to what a *new* scan concludes repairs nothing already stored,
and three populations have no other selection signal at all. The
`cron-rescan-tick` task is where they are reached, which is why an
**upgrade** can be a reason to drive this tick even on a deployment with
no scanner outage and no interest in interval rescanning.

The three sources the tick drives, and which population each exists for:

| Source | Population | Why nothing else reaches it |
|---|---|---|
| `select_eligible` | live artifacts whose policy interval elapsed | the routine case |
| `select_stranded` | the two holds whose scan errored or was never requested, **and** an artifact held `scan_indeterminate` whose last scan request is older than its resolved rescan interval | a `scan_indeterminate` artifact is outside `select_eligible`'s statuses entirely. The second half matters because a scan in which every backend ran and reported *nothing to analyse* produces a **completed** job: a predicate reading only the job's status cannot see the artifact it left held |
| `select_composite_unassessed` | live OCI **image manifests** with no composite assessment on record | they are serving, so `select_stranded` does not apply; their own evidence may be minutes old, so `select_eligible`'s interval does not either — while the evidence was reached under a rule in which a composed image's verdict carried no release authority |

**What drives it on an upgrade.** Nothing automatic: the chart ships
`scheduledTasks.cronRescanTick.enabled: false`, so either schedule the
tick or drive it by hand:

```bash
hort-cli admin task invoke cron-rescan-tick
```

**The bound, and how to resume.** One invocation selects at most
`BATCH_SIZE = 1000` rows **per source** and enqueues one scan each —
there is no unbounded burst and no long-running pass. Repeat the
invocation while the counts in the task's `result_summary` are non-zero:

```json
{ "eligible": 0, "stranded_eligible": 4, "composite_unassessed": 37, "enqueued": 41 }
```

Each population leaves its own predicate as it is reassessed, so the
counts fall monotonically and the reassessment terminates without any
cursor to keep:

- a hold whose reassessment reaches a verdict leaves
  `scan_indeterminate` (ADR 0007, *a reached verdict supersedes an absent
  one*) and the ordinary release gate decides from there;
- a hold whose reassessment reaches **no** verdict again stays held, and
  the resolved rescan interval is what keeps the question from being
  re-asked every five minutes — the artifact's shape and the backend's
  analysers are both fixed, so there is nothing to gain from asking
  sooner. The §1 third case is the exception, and deliberately so: an
  unproduced composition leaves a `failed` job row, which
  `select_stranded`'s first arm re-picks on every tick with no interval
  — there the thing that refused is an upstream or a store, which is
  precisely what *does* change between ticks;
- a manifest's reassessment records a composite assessment whatever it
  concluded, which is what takes it out of the third source.

Watch `hort_cron_rescan_composite_unassessed_artifacts` and
`hort_cron_rescan_stranded_eligible_artifacts` drain to zero if you
prefer metrics to the summary.

**What the reassessment does not do.** It drives a scan; the live gate
decides. In particular a **released** artifact whose reassessment
reaches no verdict stays released — `released` is terminal and
`fail_scan_indeterminate` is forbidden from it (ADR 0007), so an absent
verdict cannot un-release something. What the reassessment does deliver
for that population is the recorded composite assessment, and a
rejection where the composite verdict blocks.

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
existing job id instead of creating a duplicate. **Only an in-flight
job refuses it** — the previous job's result is not consulted, so both
populations from §1 are valid targets: a stranded artifact whose last
attempt failed terminally, and an artifact whose last scan completed
having found nothing to analyse. For the second this is the instrument
to reach for once the cause is removed (§4), since no sweep selects it.

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

- **The sweep, if the abstention is deterministic.** Everything in §2
  gives the scan another chance to run; none of it changes what the scan
  says. A `scan_indeterminate` artifact whose backends abstain about its
  kind would re-answer the same way every time, so its scan job
  completed and `select_stranded` does not select it at all — the sweep
  is not a slow exit for this population, it is not an exit. What moves
  it is **removing the cause** (a `ScanPolicy` change: a backend that
  can analyse the format, or
  `compositeVerdictMode: promoted` where that is the right call) and
  then a rescan — §3a's `POST /api/v1/artifacts/:id/rescan` reaches it,
  since a completed last job is not an in-flight one — after which the
  verdict lands and the release sweep decides. The curator's
  manual release is the immediate exit
  (`hort-cli curation waive artifact <artifact_id> --justification '…'`,
  or `POST /api/v1/admin/curation/quarantine/:artifact_id/waive`), which
  reaches `ScanIndeterminate` as well as `Quarantined`: one authority
  owns the manual release, and what it requires is the source state
  rather than a second permission tier. The gate is
  `Permission::Curate` OR `Permission::Admin`, so an admin credential
  works too. Post-exclusion policy re-evaluation is another. See
  [the curator workflow guide](curator-workflow.md).
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
`ArtifactRejected` event on its stream**. That rejection recorded
`reason = Unsigned`, which is a statement about *a point in time*, not
about the artifact: ADR 0039 **D1** holds that such a verdict may never
be terminal. Two shapes of artifact were left stranded by it.

**The signature arrived moments later.** With cosign the signer must
resolve the subject manifest before it can attach a signature to it, so
the verdict running first is the *normal* ordering: the signature landed
a moment later and a `ProvenanceVerified` was appended to the very same
stream. The artifact is condemned by a verdict its own stream
contradicts.

**The signature can never arrive.** A descriptor that is itself *part of*
a signature receives no signature of its own, ever — the
`application/vnd.oci.empty.v1+json` config every cosign signature
carries (the two-byte `{}`) is the canonical case. No contradicting
event will ever appear on its stream, so the rejection is invalid on its
own terms rather than by contradiction. This shape is the more damaging
one in practice: the manifest mint refuses any signature manifest that
binds a terminally-rejected descriptor, so a single stranded `{}` blob
stops **every** signing pipeline pushing to that repository.

The amendment stopped both happening (a missing signature now **holds**
indefinitely instead of rejecting), but it did not move the artifacts
already in that state — and **none of the ordinary exits reaches them**:

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
repository), `artifact_id` (narrow it to one artifact) and `limit` (how
many `rejected` rows to examine; clamped to 500). Supplied together,
`repository_id` and `artifact_id` are a conjunction — a mismatched pair
returns nothing rather than widening to either.

If the response has `"scan_cap_hit": true`, there may be more rows beyond
the bound. **Narrowing is what reaches them, not repetition:** the scan is
ordered newest-first and has no cursor, so repeating the same request
returns the same rows — and a dry run changes nothing, so it cannot
produce its own next page. Narrow by `repository_id`, or by `artifact_id`
for an artifact the queue listing above already named.

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
3. its provenance evidence shows the rejection was **never entitled to
   be terminal** — either of:
   - a `ProvenanceVerified` **is** on its stream (the rejection is
     contradicted outright); or
   - the only provenance verdict on its stream is a `ProvenanceRejected`
     whose reason is `Unsigned` — the verdict ADR 0039 D1 forbids from
     ever being terminal, and the shape for which no contradiction can
     ever arrive.

   A **positive disproof** on the stream (a signature present and wrong,
   any reason other than `Unsigned`) is terminal by design and refuses
   here, including when an `Unsigned` rejection precedes it. So does a
   stream carrying no provenance verdict at all: nothing there
   establishes that the artifact was rejected on the provenance axis.

So it leaves alone: an artifact rejected by a *positive disproof*
(present-but-invalid signature — whether or not it carries the
`ArtifactRejected` companion), a scan-rejected artifact, a curator- or
admin-blocked one, an artifact tombstoned because its stored bytes do not
match their content hash, a never-signed artifact still held
`quarantined`, and anything already released.

### What happens after

A repaired artifact goes back to `quarantined` with its **original**
observation-window anchor — restored, not restarted — and an
`ArtifactReEvaluated` + `ArtifactQuarantined` pair is appended to its
stream (the repair is recorded as events; the status is only the
projection). The ordinary release sweep picks it up on its next tick and
applies the live scan, curation and provenance gates. **The repair never
releases anything itself** — it hands the decision back to the sweep, and
what the sweep then does depends on which arm matched:

- **Contradicted by a `ProvenanceVerified`:** that is the same event the
  release gate reads, so the provenance conjunct clears and the artifact
  releases normally on the next tick.
- **An `Unsigned` rejection with no verification:** the artifact
  **holds** at `quarantined`. On a `provenanceMode: required` repository
  the provenance gate reads `pending`, which denies release, and nothing
  re-rejects it — that is ADR 0039 D1's prescribed treatment of an
  unsigned artifact, and the hold is the correct resting state rather
  than a failed repair. It leaves the hold the way D1 intends: its own
  signature arriving and verifying, or — for a signature's own
  constituents, which can never carry one — the parent manifest's
  provenance-clearance cascade, which the terminal `rejected` status was
  precisely what blocked.

  **This is what unblocks the signing pipeline.** The descriptor no
  longer being terminally rejected is all the manifest mint needs; it
  refuses a *terminal* reference, not a held one.

OCI tags pointing at a repaired manifest need no separate action: a tag
resolves through the manifest, so it becomes servable when the manifest
does.

The repair is idempotent — a second run finds nothing, because the first
one moved the artifact out of `rejected`.

---

## 6. A third strand: artifacts held in a permissive (`quarantineDuration: 0`) repository

The two strands above are about an artifact whose *verdict* never
arrived. This one is about an artifact whose *window* no longer exists.

`quarantineDuration: 0` — permissive mode — is a supported posture: it
collapses [ADR 0007](../../adr/0007-fail-closed-quarantine-release-predicate.md)'s
time gate and leaves the fail-closed scan gate in place (see
[the curator workflow guide](curator-workflow.md) §5). Under it ingest
never quarantines at all, so in steady state a permissive repository
holds nothing. Two things nevertheless put an artifact into the hold of
a repository that is permissive *now*:

- **The window was longer when the artifact was ingested** and an
  operator has since shortened it to `0`. Changing `quarantineDuration`
  re-judges nothing (it is not a re-evaluation trigger — see the curator
  guide's §6) and nothing moves `quarantine_window_start` once it is
  stamped, so the artifact keeps the anchor it was ingested under.
- **A corrective path returned it to the hold.** The §5 repair is the
  one that exists today, and it returns the artifact on its **original**
  anchor — restored, not restarted.
- **A scan took the hold because it had nothing to assess.** An OCI image
  manifest whose composition could not be produced within the scan job's
  attempt budget is quarantined by the scan path itself (§1's third
  bullet), anchored at the artifact's ingest instant. Under
  `quarantineDuration: 0` the resulting window is already elapsed, which
  is the recognition shape below — and correctly so: the hold is waiting
  on a verdict, not on time, and nothing releases an artifact with no
  scan-axis authority however long its window has been over.

### Recognition shape

Three facts together:

1. `quarantine_status = 'quarantined'`;
2. `release_attempt_at IS NULL`; and
3. a **resolved** `quarantineDuration` of `0` for the artifact's
   repository — `GET /api/v1/admin/repositories/:key/effective-config`
   → `.scan_policy.quarantine_duration_secs`. Resolution is repo-scoped
   policy → global policy → built-in default, so the repository's own
   YAML is not the whole answer.

(2) is the discriminating fact. The release sweep stamps
`release_attempt_at` on **every** candidate it hands to the release gate,
released and held alike, so a `NULL` means the sweep never *considered*
the row — not that it considered it and the gates held it. The column is
not on an API surface; read it from the row:

```sql
SELECT id, quarantine_status, quarantine_window_start, release_attempt_at
  FROM artifacts
 WHERE repository_id = '<repository-uuid>'
   AND quarantine_status = 'quarantined'
   AND deleted_at IS NULL;
```

Confirm the sweep is actually running before reading anything into a
`NULL`: a deployment whose sweep CronJob is disabled shows `NULL` for
every held artifact in every repository, which is a different problem
with a different fix.

### It self-heals, and there is no backfill to run

Release-sweep candidacy selects by **deadline**, never by current policy.
A zero window is a window of zero *length*, not an absent one: its cutoff
is `now`, so every artifact a permissive repository still holds is past
its deadline and is selected on the next tick. What happens to each one
then is the ordinary per-artifact decision — the scan-axis release
authority (ADR 0007) and the provenance clearance
([ADR 0027](../../adr/0027-artifact-provenance-verification.md)) — exactly
as for a candidate from any other repository. Permissive mode buys an
artifact no authority it did not already have; it only makes it a
candidate.

Before 0.14.0 the sweep dropped a repository whose resolved window was
`0` from candidacy altogether, which left its held artifacts with no exit
at all — the anchor never moves, so the only recovery was a per-artifact
curator waive. **0.14.0 and later selects by deadline, and the heal is a
property of that query rather than of a migration**: a population that
accumulated under an older release drains on the next sweep tick exactly
like a freshly-arrived one. There is no backfill step to run and nothing
to look for in `migrations/`.

The tick is the `quarantine-release-sweep` CronJob
(`scheduledTasks.quarantineReleaseSweep`, **default enabled**, default
schedule `*/5 * * * *`). It has no admin-task HTTP route, so draining
once off-schedule means running its own command against the runtime DSN:
`hort-server enqueue-quarantine-release-sweep`.
