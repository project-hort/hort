# Enable admin-task CronJobs (`scheduledTasks.adminTasksEnabled`)

This guide is for operators turning on `scheduledTasks.adminTasksEnabled:
true` — the umbrella toggle that renders the svc-token bootstrap Job plus
the `executionPath: admin-task` CronJobs (`staging-sweep`,
`cron-rescan-tick`, `advisory-watch-tick`, `service-account-rotation`,
`noop`, `replay-seen-prune`, `scanner-registry-prune`,
`eventstore-checkpoint`, `verify-event-chain`, and the destructive
trio). It covers the **gitops prerequisite** the chart deliberately
does not provision, the **two ways getting it wrong fails**, and the
**destructive-task caveat**.

For the full rendered-resource matrix and hook ordering see
[`helm-chart.md`](../../reference/helm-chart.md) §3/§4. For every
`scheduledTasks.*` key see
[`values-reference.md`](values-reference.md).

---

## 1. Why a prerequisite exists

`adminTasksEnabled: true` renders a post-install/post-upgrade hook Job
(`<release>-svc-token-bootstrap`) that mints a `cronjob-tasks`
service-account token and writes it into the `<release>-svc-token` Secret
every admin-task CronJob mounts as `HORT_TOKEN`. Minting that token
requires a **pre-existing** gitops `ServiceAccount` and a backing
`PermissionGrant` — the chart never creates either. This is deliberate:
service-account authority flows through the operator's audited gitops
apply path, not through a Helm template
([ADR 0037](../../../adr/0037-gitops-service-account-grant.md),
[ADR 0044](../../../adr/0044-service-accounts-identity-only.md)). The chart's
job is to fail loudly when the prerequisite is missing and to document it
clearly — not to write into your gitops tree.

---

## 2. Prerequisite gitops — declare the `ServiceAccount` and its grant

Before running `helm upgrade`/`helm install` with
`scheduledTasks.adminTasksEnabled: true`, add both of the following
envelopes to your `gitopsConfig` (or the equivalent files under
`$HORT_CONFIG_DIR` if you author gitops outside the chart's inline
`gitopsConfig` map — see
[`declare-gitops-config.md`](../declare-gitops-config.md)):

```yaml
apiVersion: project-hort.de/v1
kind: ServiceAccount
metadata: { name: cronjob-tasks }
spec: {}
---
apiVersion: project-hort.de/v1
kind: PermissionGrant
metadata: { name: cronjob-tasks-admin_task_invoke }
spec:
  subject: { kind: serviceAccount, name: cronjob-tasks }
  permission: admin_task_invoke        # global (no repository:)
```

Notes on the exact shape:

- `spec: {}` on the `ServiceAccount` is correct here — `cronjob-tasks` is
  neither federated nor rotated; it is the "identity only, minted by
  `hort-server admin issue-svc-token`" case
  ([`declare-gitops-config.md`](../declare-gitops-config.md) `kind:
  ServiceAccount`, the "neither" shape).
- The `PermissionGrant.metadata.name` is
  `cronjob-tasks-admin_task_invoke` — an **underscore**, not a dash,
  because it mirrors the permission's `Display` form
  (`Permission::AdminTaskInvoke` renders as `admin_task_invoke`). This is
  the exact name the CLI's `--require-authority` preflight and the
  chart's `NOTES.txt` print; keep it verbatim so the object you see in
  the failure message is the object you already applied, not a
  fuzzy-matched near-miss.
- The grant omits `repository:` — it must be **global** authority. A
  repository-scoped grant does not back the `AdminTaskInvoke` check the
  bootstrap performs at global scope, and the preflight will still fail
  (see §4.2).
- If you already mint the `cronjob-tasks` identity's token some other
  way (or want a narrower/renamed name), the SA `metadata.name` and the
  bootstrap Job's `--name=cronjob-tasks` argument must match exactly —
  the chart does not expose a values knob to rename it.

Apply this gitops change (commit + whatever your apply mechanism is —
restart the Deployment / re-run `helm upgrade` to force a re-read of the
`gitopsConfig` ConfigMap) **before** flipping `adminTasksEnabled` to
`true`, or in the same change if your pipeline applies gitops and rolls
the chart together.

---

## 3. Enable the toggle

```yaml
scheduledTasks:
  adminTasksEnabled: true
  # then each task's own `enabled` (see values-reference.md for the
  # per-task defaults — most default off; replaySeenPrune defaults on
  # once this umbrella is on).
```

```bash
helm upgrade hort oci://${REGISTRY}/${IMAGE_PREFIX}/charts/hort-server \
  --version <chart-version> -n hort \
  -f values.yaml
```

Also required (unrelated to the gitops prerequisite, but easy to miss):
`postgres.admin.existingSecret` must be set — the bootstrap Job mints the
token under the admin DSN — and CronJob pods need an in-cluster network
path to the `hort-server` Service.

---

## 4. The two failure modes and how to diagnose them

### 4.1 Service account absent — the hook fails loudly

**Symptom:** `helm install`/`helm upgrade` reports a failed hook (and, if
you run with `--atomic` or under Flux `HelmRelease` remediation, the
release rolls back). The failure is buried in a completed-then-failed
Job, not in the `helm` CLI output itself.

**Spot it:**

```bash
kubectl --namespace <ns> get jobs -l hort-server.io/job=svc-token-bootstrap
kubectl --namespace <ns> logs job/<release>-svc-token-bootstrap -c issue-token
```

The `issue-token` init container's log ends with:

```
service account "cronjob-tasks" not found — define it as a ServiceAccount in
gitops and apply before issuing its token (grants flow through the audited
apply path, ADR 0012).
```

**Fix:** add the `ServiceAccount` envelope from §2 to your gitops config,
apply it (and, if the SA row does not exist yet at all, the
`PermissionGrant` beside it — apply both together per §2), then re-run
`helm upgrade` (or `helm rollback` and retry) so the hook Job re-runs.
The Job's `helm.sh/hook-delete-policy: before-hook-creation,hook-succeeded`
means the failed Job and its pod stay in the namespace until you retry, so
the `kubectl logs` command above still works however long after the failure
you reach for it — and the retried install/upgrade then cleans the failed
Job up automatically, so you do not need to delete it by hand first.

### 4.2 Grant absent — previously silent, now caught at install

**Prior behaviour (before this preflight existed):** `issue-svc-token`
minted the token successfully — it never checked the grants table at
mint time. The install **succeeded**, the Secret was written, and every
admin-task CronJob then **403'd at every tick** with no install-time
signal at all. The only way to notice was a CronJob failure alert (if you
had one) hours or days later.

**Current behaviour:** the bootstrap Job's `issue-token` init container
now passes `--require-authority`. `issue-svc-token` resolves the SA, then
verifies — via the same `RbacEvaluator` the runtime authorizes every
request with — that each declared permission (`admin_task_invoke`) is
backed by a live grant at **global** scope. If it is not, the command
`bail!`s **before writing any token**, and the hook Job fails exactly as
in §4.1, but with a different message:

```bash
kubectl --namespace <ns> logs job/<release>-svc-token-bootstrap -c issue-token
```

```
service account "cronjob-tasks" exists but has no grant for permission(s):
admin_task_invoke — the token would mint but the corresponding admin-task
CronJob(s) would be denied (403) at run time. Add the following to your
gitopsConfig and re-apply:

  apiVersion: project-hort.de/v1
  kind: PermissionGrant
  metadata: { name: cronjob-tasks-admin_task_invoke }
  spec:
    subject: { kind: serviceAccount, name: cronjob-tasks }
    permission: admin_task_invoke        # global (no repository:)
```

**Fix:** apply the `PermissionGrant` YAML printed in the message (it is
identical to the one in §2 — copy-paste it verbatim) and re-run `helm
upgrade`. If you already have a `cronjob-tasks` token minted from before
this preflight existed and CronJobs have been silently 403ing, applying
the grant is sufficient — the runtime's `RbacEvaluator` re-reads grants
live on every request, so the fix takes effect without rotating the
token. You do not need `scheduledTasks.rotateSvcToken: true` for this
case (that flag forces a *new token*, not a grant re-check).

A grant an operator later **revokes** is also caught: the preflight runs
on every hook invocation (every `helm upgrade`, not just first install),
so a revoked grant surfaces as a hook failure on the next routine
upgrade rather than staying silent until a CronJob alert fires.

---

## 5. Destructive tasks — one authority per object destroyed

`retention-evaluate`, `retention-purge`, and `eventstore-archive` are the
**destructive trio** — the retention-purge task deletes CAS blobs and
decrements refcounts, and eventstore-archive truncates/archives the audit
stream. In addition to `Permission::AdminTaskInvoke`, invoking one of
these requires a **destructive permission**, and which one depends on what
the task destroys:

| Task | Destroys | Permission |
|---|---|---|
| `retention-evaluate` (execute mode) | artifact content (appends the `ArtifactExpired` the purge acts on) | `destroy_content` |
| `retention-purge` | artifact content (the CAS bytes) | `destroy_content` |
| `eventstore-archive` | the audit record itself — authentication audit, download audit, token use | `destroy_record` |

The split is by **what is destroyed**, not by purpose: an artifact's removal
leaves a record behind by design (`ArtifactPurged` stays on the stream),
while nothing reconstructs a deleted audit record. So an identity trusted to
reclaim storage is not thereby trusted to cut audit history, and holding one
of the two permissions never authorises the other's task.

**That asymmetry decides which of these can be automated**, and it is the
thing to read §5 for. `destroy_content` may be held by a machine identity —
the job's own service account, §5.3 — so the two retention kinds are
automatable on an explicit, audited grant rather than a documented
break-glass. `destroy_record` may not be held by one at all, at five
independent enforcement points (§5.4), so `eventstore-archive` has only the
manual path.

**Being an admin does not confer either permission.** Both are *orthogonal*
to `admin`: an admin caller falls through the admin short-circuit to the
ordinary grant scan for them, so an interactive admin invoking
`retention-purge` is answered `403` until a grant exists for their identity.
See §5.1 for the grant to apply. This is a hard architectural line, not a
configuration gap:

> **Storage reclamation depends on `retention-purge` running.** Its name
> understates its job: the sweep releases the bytes of *every* retired
> artifact, whether a retention policy expired it or a caller deleted it
> through the registry API (an OCI manifest `DELETE`, today). It is the
> only path that does so. Leaving it disabled — the shipped default,
> deliberately, because it is the most destructive of the three — means a
> registry with no retention policy at all still never reclaims the
> storage behind its deletes. Run it by hand on the cadence your capacity
> planning needs, per the CliSession flow below.

- The three destructive CronJob templates ship `enabled: false`. Do not flip
  one on expecting the bootstrap svc-token to work as shipped — it declares
  `admin_task_invoke` and nothing else, so the CronJob fails every run with
  `destructive task kind "retention-purge" requires Permission::destroy_content
  in addition to Permission::AdminTaskInvoke`.
- **The two content-side kinds can be made to run unattended; the archive
  cannot.** `destroy_content` is grantable to a machine identity — §5.3 is the
  recipe. `destroy_record` is not, at any of five independent points, so
  `eventstore-archive` has only the manual path below. §5.4 is why.

The one exception is `retention-evaluate` with `{"mode":"dry_run"}`, which
records nothing and therefore needs only `Permission::AdminTaskInvoke`. The
gate follows the **invocation**, not the kind, and the mode defaults to
`execute` when the request body omits it — so every invocation shown below,
and the shipped CronJob, still needs `destroy_content`.

To run a destructive task by hand, use an admin CliSession from an operator
workstation, with the grant from §5.1 in place for that identity:

```bash
hort-cli auth login --admin
hort-cli admin task invoke retention-purge
```

See [`using-hort-cli-with-admin-ops.md`](../using-hort-cli-with-admin-ops.md)
for the `--admin` login flow and its ≤15 min session cap. The session cap
bounds the *credential*; the grant is standing until you remove it, so treat
the grant — not the login — as the thing to review.

**Do not** attempt to work around this by pointing the destructive
CronJobs' `HORT_TOKEN` at a hand-minted admin Secret. The chart has no
values knob for repointing those templates (their `secretKeyRef` is
hardcoded to the bootstrap Secret), and wiring one is explicitly deferred
to a future cron-proposes/admin-confirms approval workflow, not a supported
workaround. For the two content-side kinds the supported unattended route is
§5.3 — grant the job's own identity `destroy_content` — and for
`eventstore-archive` it is the manual path above.

### 5.1 The grant an operator must apply

Both permissions arrive the only way any authority does: an explicit
`kind: PermissionGrant` through the audited apply path
([ADR 0012](../../../adr/0012-claim-based-rbac-claimless-static-tokens.md)).
Neither is implied by `admin`, so this step is **required** before an
interactive admin can run a destructive task.

Bind it to the **identity**, not to a claim:

```yaml
apiVersion: project-hort.de/v1
kind: PermissionGrant
metadata:
  name: retention-operator-destroy-content
spec:
  subject:
    kind: user
    # The `users.id` of the operator who runs retention by hand. Read it
    # from `hort-cli admin user list` (or the whoami of that session).
    userId: 0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0
  permission: destroy_content
  # No `repository:` -> global. Admin-task invocation is a global
  # capability; a repo-scoped destructive grant authorises nothing,
  # because the gate asks at `repository = None`.
```

Two things about this shape are load-bearing, and both are consequences of
how the authority is re-checked:

- **A claims-subject grant does not survive the execution re-check.** Before
  a queued destructive row reaches its handler the worker rebuilds the
  requester from the `users` row, which carries no IdP-resolved claims — only
  the synthetic `admin` claim, and only while `is_admin` is true. A
  destructive grant bound to any other claim therefore passes the `POST` and
  is refused at execution, every time, with
  `… or it is bound to a claim this execution cannot re-derive` in
  `last_error`. Bind to `kind: user` (or, for a machine identity,
  `kind: serviceAccount`, which resolves to a `User` subject at apply).
- **The apply-time linter rejects this shape by default, and that is the
  secure default rather than a bug.** A global `User`-subject grant of an
  admin-class permission is the privilege-escalation shape
  `direct-user-grant-without-justification` exists to catch, and both
  destructive permissions are classified admin-class. Relax it deliberately,
  in config that lands in the gitops tree and shows up in the apply diff:

  ```yaml
  apiVersion: project-hort.de/v1
  kind: PermissionGrantLintConfig
  metadata:
    name: rbac-lint
  spec:
    ruleOverrides:
      directUserGrant: warn       # default reject (high-privilege arm)
  ```

  See [`claim-based-rbac.md`](../operate/claim-based-rbac.md) §5 for the
  full rule table and what each downgrade costs.

To take the authority away, remove the grant and re-apply. That stops the
identity's *next* invocation after the evaluator's refresh (a 30-second
poll by default), and stops a destructive row it has **already** queued
immediately, because the execution re-check reads the grant repository
directly — see §5.2.

### 5.2 The authority is re-checked again when the job runs

Accepting a destructive invocation does not confer the authority to
execute it. The `POST` enqueues a `jobs` row; the worker claims it some
time later, and **before calling the handler it re-checks the requester
named on that row against the live authority state**. If the authority no
longer holds, the handler is never called — nothing is deleted or
archived — and the row becomes a terminal `failed` job whose
`last_error` names the cause, e.g.:

```text
destructive task refused at execution: the requester does not hold
Permission::destroy_content — the grant was revoked before execution, or it
is bound to a claim this execution cannot re-derive
```

Read it off the row or the worker log:

```bash
hort-cli admin task get <job-id>
kubectl --namespace <ns> logs deploy/<release>-worker | grep 'refusing to execute'
```

**What this means in practice — plan for it before you revoke anything:**

- **Revoking an identity's destructive authority also stops the
  destructive work it has already queued.** On the supported path (§5)
  that identity is the admin who ran `hort-cli admin task invoke` by
  hand, so the purge they queued minutes ago stops too — not only their
  next attempt. It reaches a *scheduled* run for the same reason: the
  k8s CronJobs invoke through the same operator surface as a human
  (`hort-cli admin task invoke …` → `POST /api/v1/admin/tasks/…`), so if
  a deployment ever drives a destructive kind on a schedule under an
  admin-authenticated identity, revoking that identity stops the nightly
  run — silently as far as the CronJob pod is concerned, because the
  pod's `POST` already succeeded. **Storage reclamation stops with it**
  (see the callout above). Look for the terminal `failed` jobs rows, not
  for a CronJob failure.
- **Three revocations have this effect**, and they are the three the
  registry persists: `users.is_active = false`, removing the
  `admin_task_invoke` `PermissionGrant`, and removing the destructive
  `PermissionGrant` (`destroy_content` / `destroy_record`). Demoting the
  user (`users.is_admin = false`) also removes their `admin_task_invoke`
  if they held it only through the admin short-circuit.
- **The destructive grant must be reachable from the persisted identity.**
  The re-check rebuilds the requester from the `users` row, which carries no
  IdP-resolved claims — only the synthetic `admin` claim, and only while
  `is_admin` is true. So a `kind: user` (or `kind: serviceAccount`) grant
  survives the wait, and a grant bound to any other claim passes the `POST`
  and is refused here every time. §5.1 is the shape to apply; this is why it
  binds to the identity.
- **An unreachable database is not a revocation.** If the authority
  tables cannot be read, the job is held rather than condemned: the
  handler still does not run, the row keeps its retry budget, and the
  next claim re-asks. Only once the budget is spent does it become a
  terminal row.
- **A refused job still holds the day's single-flight claim**, so
  restoring the authority is not enough to make it run today. Every
  destructive invocation takes a server-derived per-UTC-day idempotency
  claim at enqueue
  ([ADR 0028](../../../adr/0028-destructive-task-idempotency.md)), and
  that claim is not scoped to a status — it survives the terminal row.
  Re-invoking the same kind the same day therefore returns `200` with
  the **refused** job's id instead of enqueuing a fresh one. Recovering
  inside the day is the same explicit, audited path as for any other
  failed destructive job: `DELETE FROM jobs WHERE id = <refused-id>`,
  then re-invoke. Otherwise the next day's run picks it up.

The re-check applies to the destructive invocations only — a
`retention-evaluate` dry run, and every non-destructive kind, is
unaffected and pays nothing for it.

### 5.3 Letting the job's own identity run the retention pair

`destroy_content` is grantable to a **machine identity**, which is what makes
the retention CronJobs automatable rather than a documented break-glass. The
reason is the asymmetry the split is named for: an artifact's removal leaves a
record behind by design (`ArtifactPurged` stays on the stream), so an identity
trusted to reclaim storage has not been trusted with anything unobservable.

Three steps, and **all three are required** — the first two alone leave a token
that answers `403` on every tick:

**(1) Grant it, to the identity, through the audited apply path.** The grant
names the service account; apply resolves it to
`GrantSubject::User(backing_user_id)`, so it is identity-bound and survives the
execution re-check of §5.2:

```yaml
apiVersion: project-hort.de/v1
kind: PermissionGrant
metadata:
  name: cronjob-tasks-destroy-content
spec:
  subject:
    kind: serviceAccount
    name: cronjob-tasks
  permission: destroy_content
  # No `repository:` -> global. The destructive gate asks at
  # `repository = None`, so a repo-scoped destructive grant authorises
  # nothing.
```

Unlike §5.1's `kind: user` form this needs **no linter downgrade**: a
`serviceAccount`-subject grant takes the provenance exemption and passes at the
secure default. That asymmetry is deliberate guidance — a standing destructive
authority should be bound to one declared identity, not to whoever currently
carries a claim.

**(2) Declare it in the mint.** The capability is a separate declaration from
the grant, and effective authority is `grants ∩ cap`:

- **Helm** — add it to the `cronjob-tasks` entry of
  `scheduledTasks.svcTokens[].permissions`. The entry's always-on
  `--require-authority` preflight then fails the bootstrap Job loudly at
  install time if step 1 is missing, instead of minting a token that `403`s on
  every tick.
- **Ansible** — add it to `hort_timers_token_permissions` (the shipped default
  in the `hort_timers` role already carries it, alongside the matching grant in
  `deploy/ansible/files/gitops/auth/grants/`).

**(3) Rotate the token — the step that is easy to miss.** A svc-token's
capability is **frozen at mint**
([ADR 0012](../../../adr/0012-claim-based-rbac-claimless-static-tokens.md)), and
`cronjob-tasks` is a **PAT-only** ServiceAccount: its gitops envelope has no
`fallbackRotation` block, so the rotation reconciler never visits it and **no
interval re-snapshots the cap for you**. An existing token therefore keeps the
old cap while both declarations read correctly. The failure mode is quiet and
has cost a diagnosis round before — the grant is live in the database, the
evaluator sees it, and the endpoint still answers `403`, which reads as an
authorization defect rather than a stale credential.

Read which side is at fault before changing anything. `permissions` is the
**frozen cap**; `effective_grants` is `grants ∩ claims ∩ cap`:

```bash
# As the identity itself (HORT_TOKEN=<the mounted svc-token>):
hort-cli auth status --output json     # `.permissions` == the frozen cap
```

A `destroy_content` missing from `.permissions` while the grant is applied is
the frozen cap, not the grant table — and the server says so itself on a
cap-leg denial for a ServiceAccount principal: *"a grant added afterwards only
enters the cap on the next exchange or rotation."* Then converge it:

```bash
# Helm: set the entry's `rotate: true` for one upgrade, then back to false.
helm upgrade … --set 'scheduledTasks.svcTokens[0].rotate=true'

# Ansible: set `hort_timers_token_rotate: true` for one deploy, then back.

# Or directly, on the host, with operator DSN access:
hort-server admin issue-svc-token --name cronjob-tasks \
  --permission admin_task_invoke --permission destroy_content \
  --rotate --output file:/etc/hort/tasks-token
```

Re-running that command converges to the same state, so it is safe to repeat.
Without `--rotate` it is a no-op on an existing token and the cap stays stale,
which is exactly the trap. It does invalidate the previous token, which is why
it is opt-in rather than unconditional.

Enabling the CronJobs after that is a separate, deliberate decision —
`scheduledTasks.retentionEvaluate.enabled` / `.retentionPurge.enabled`, or the
`hort_timers` task entries — and they stay `false` in this repository. The
capability gap is what §5.3 closes; whether to run the sweep on a schedule is a
capacity-and-retention judgement, and `retention-purge` is the most destructive
of the three.

### 5.4 Why `eventstore-archive` keeps only the manual path

`destroy_record` is **not grantable to a service account** — not to
`cronjob-tasks`, not to a dedicated one. The archive seals audit streams
(authentication audit, download audit, token use) and **nothing reconstructs a
sealed stream**, so an unattended identity holding standing authority over it is
not what was decided: the retention pair's "the record survives the removal"
argument is exactly what does not hold here.

That is fail-closed at five independent points, not a convention a future edit
can drift past:

1. **Apply-parse** — `validate_permission_grant` rejects a
   `serviceAccount`-subject grant of it, naming why and what to grant instead.
2. **The apply linter** — an SA-owned `User`-subject grant of it is denied the
   provenance exemption and rejects like a hand-authored escalation. This is the
   point that reaches the shape (1) cannot see: a hand-written
   `subject: { kind: user }` naming the SA's own backing user never passes
   through the `serviceAccount` arm at all.
3. **`issue-svc-token`** — refuses it as a `--permission`, before any database
   work, so it never reaches a token cap.
4. **The admin-task authorization gate** — refuses a
   `TokenKind::ServiceAccount` caller, *before* consulting grants. Points 1–3
   refuse a **form of declaration**; this one refuses the **identity**, which is
   what was decided. It is load-bearing precisely because (2)'s rule is
   downgradable to `Pass` in operator config.
5. **The worker's pre-handler re-check** — refuses a queued row whose requester
   is `users.is_service_account`. A `jobs` row carries no credential, so this
   layer reads the persisted identity instead of a token kind.

So there is nothing to provision: adding it to an `svcTokens` entry fails the
bootstrap Job, and declaring the grant fails the apply. Run it as a human
identity holding the grant, per §5.1 and the CliSession flow in §5. If a
deployment genuinely needs scheduled audit-stream archival, that is a new
decision about unattended destructive authority — the cron-proposes /
admin-confirms approval workflow named above is where it belongs, not a wider
credential.

---

## 6. Verify

```bash
# Bootstrap hook completed.
kubectl --namespace <ns> get job -l hort-server.io/job=svc-token-bootstrap

# Secret exists and is mounted correctly.
kubectl --namespace <ns> get secret <release>-svc-token

# Admin-task CronJobs are scheduled (not necessarily fired yet).
kubectl --namespace <ns> get cronjob -l app.kubernetes.io/instance=<release>

# After the next scheduled tick, confirm a run succeeded.
kubectl --namespace <ns> get pods -l hort-server.io/job=<task-name> \
  --sort-by=.metadata.creationTimestamp
kubectl --namespace <ns> logs <most-recent-pod>
```

A healthy first run logs the invoked task kind and exits 0. A `403`/
`Forbidden` in the CronJob pod log after the bootstrap Job itself
succeeded means the grant check passed at *bootstrap* time but the task
kind you enabled needs *additional* authority the bootstrap doesn't
check for you — the destructive trio (§5) is the only case where this
applies today.

---

## 7. Troubleshooting quick reference

| Symptom | Cause | Fix |
|---|---|---|
| Bootstrap hook Job fails, log ends `service account "cronjob-tasks" not found` | No gitops `ServiceAccount` envelope | Add the `ServiceAccount` from §2, apply, re-run `helm upgrade` (§4.1) |
| Bootstrap hook Job fails, log ends `has no grant for permission(s): admin_task_invoke` | `ServiceAccount` exists but no backing global `PermissionGrant` | Add the `PermissionGrant` YAML printed in the error, apply, re-run `helm upgrade` (§4.2) |
| Bootstrap hook Job fails, log ends `exists but is not a service account` | A user named `sa:cronjob-tasks` already exists and is not a service account (naming collision) | Rename the `ServiceAccount` envelope, or resolve the collision on the existing user row |
| Admin-task CronJob pod exits non-zero with `Permission::AdminTaskInvoke required` | Grant exists but is repository-scoped, or targets the wrong subject | Re-check the grant is `subject: {kind: serviceAccount, name: cronjob-tasks}` with **no** `repository:` field |
| Retention CronJob (if enabled) fails with `requires Permission::destroy_content` | The svc-token's **frozen cap** does not carry it — either the mint never declared it, or the declaration changed and the token was not rotated | Walk §5.3's three steps; check `hort-cli auth status --output json`'s `.permissions` (the frozen cap) before touching the grant table |
| `eventstore-archive` CronJob (if force-enabled) fails with `requires Permission::destroy_record`, or with `which a ServiceAccount may not hold` | Expected and not provisionable — `destroy_record` is refused to a machine identity at five points (§5.4) | Leave disabled; run by hand as a human identity holding the grant (§5.1, §5) |
| An **admin** is answered `403` on `admin task invoke retention-purge` with `requires Permission::destroy_content` | Expected — neither destructive permission is implied by `admin` | Apply the grant in §5.1 for that identity |
| A destructive task reports success at invoke time but nothing was purged/archived, and `hort-cli admin task get` shows a `failed` row whose `last_error` starts `destructive task refused at execution` | The requester's authority was revoked between enqueue and execution — demoted, deactivated, or either of its grants removed (§5.2). If `last_error` continues `the requester is a service account, which may not hold`, the row was enqueued for a machine identity against an authority no machine identity holds (§5.4) | Restore the authority (or use an identity that still holds it). The refused row is terminal, is not retried, and still owns the day's idempotency claim — so to re-run inside the same day, delete that row first (§5.2) |
| Same shape but `last_error` starts `destructive task authority could not be re-checked` | The authority tables could not be read; the job was held, not refused | Fix database reachability — the row re-asks on its next claim until its retry budget is spent |
| Routine `helm upgrade` starts failing with the grant-missing message after previously succeeding | The `PermissionGrant` was removed/revoked from gitops since the last upgrade | Re-add the grant, or intentionally leave `adminTasksEnabled: false` if admin tasks are no longer wanted |

---

## See also

- [`helm-chart.md`](../../reference/helm-chart.md) — full rendered-resource
  matrix, hook ordering, and the admin-task CronJob list.
- [`values-reference.md`](values-reference.md) — every `scheduledTasks.*`
  key.
- [`declare-gitops-config.md`](../declare-gitops-config.md) — the
  `ServiceAccount` and `PermissionGrant` envelope reference in full.
- [`rotating-service-account-tokens.md`](../rotating-service-account-tokens.md)
  — the sibling fallback-PAT-rotation path for service accounts that need
  a periodically refreshed token (different mechanism from the
  one-shot bootstrap token this guide covers).
- [`using-hort-cli-with-admin-ops.md`](../using-hort-cli-with-admin-ops.md)
  — the `--admin` CLI session flow needed for destructive tasks.
- [ADR 0012](../../../adr/0012-claim-based-rbac-claimless-static-tokens.md),
  [ADR 0037](../../../adr/0037-gitops-service-account-grant.md),
  [ADR 0038](../../../adr/0038-admin-identity-model.md),
  [ADR 0044](../../../adr/0044-service-accounts-identity-only.md) — the
  standing decisions behind the claimless-static-token / gitops-authority
  / admin-identity model this guide operationalises.
