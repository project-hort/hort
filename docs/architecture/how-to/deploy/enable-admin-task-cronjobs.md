# Enable admin-task CronJobs (`scheduledTasks.adminTasksEnabled`)

This guide is for operators turning on `scheduledTasks.adminTasksEnabled:
true` — the umbrella toggle that renders the svc-token bootstrap Job plus
the `executionPath: admin-task` CronJobs (`staging-sweep`,
`cron-rescan-tick`, `advisory-watch-tick`, `service-account-rotation`,
`noop`, `replay-seen-prune`, `scanner-registry-prune`,
`verify-event-chain`, and the destructive trio). It covers the
**gitops prerequisite** the chart deliberately does
not provision, the **two ways getting it wrong fails**, and the
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
apiVersion: project-hort.de/v1beta1
kind: ServiceAccount
metadata: { name: cronjob-tasks }
spec: {}
---
apiVersion: project-hort.de/v1beta1
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
The Job's `helm.sh/hook-delete-policy: before-hook-creation` means a
retried install/upgrade cleans up the failed Job automatically — you do
not need to delete it by hand first.

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

  apiVersion: project-hort.de/v1beta1
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

## 5. Destructive tasks — docs-only, never via the bootstrap svc-token

`retention-evaluate`, `retention-purge`, and `eventstore-archive` are the
**destructive trio** — the retention-purge task deletes CAS blobs and
decrements refcounts, and eventstore-archive truncates/archives the audit
stream. In addition to `Permission::AdminTaskInvoke`, invoking one of
these requires the caller to carry the `task:destructive` **claim**. This
is a hard architectural line, not a configuration gap:

- Service-account tokens (the `cronjob-tasks` bootstrap svc-token
  included) are **claimless by construction** — `authenticate_pat`
  resolves no IdP claims for a native token. A claimless caller can never
  satisfy `task:destructive`, no matter what permissions it is granted.
- The three destructive CronJob templates ship `enabled: false` and stay
  that way. Do not flip them on expecting the bootstrap svc-token to
  work — the CronJob will fail every run with `destructive task kind
  "retention-purge" requires the "task:destructive" claim in addition to
  Permission::AdminTaskInvoke`.

To run a destructive task, use a **fresh IdP-backed admin CliSession** by
hand, from an operator workstation — never a static token:

```bash
hort-cli auth login --admin
hort-cli admin task invoke retention-purge
```

A full admin session short-circuits the `task:destructive` claim check
(an admin already holds every authority), so no separate `ClaimMapping`
is needed for this path. See
[`using-hort-cli-with-admin-ops.md`](../using-hort-cli-with-admin-ops.md)
for the `--admin` login flow and its ≤15 min session cap.

**Do not** attempt to work around this by pointing the destructive
CronJobs' `HORT_TOKEN` at a hand-minted `task:destructive`-carrying
Secret — the chart has no values knob for that today (the destructive
templates' `secretKeyRef` is hardcoded to the bootstrap Secret), and
wiring one is explicitly deferred to a future
cron-proposes/admin-confirms approval workflow, not a supported
workaround. Run the destructive kinds by hand until that workflow ships.

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
| Destructive CronJob (if force-enabled) fails with `requires the "task:destructive" claim` | Expected — destructive kinds can never run under the claimless bootstrap svc-token | Leave disabled; run by hand per §5 |
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
