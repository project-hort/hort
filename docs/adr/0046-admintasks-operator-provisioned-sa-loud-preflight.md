# 0046 — `adminTasksEnabled` installs are operator-provisioned + loud-preflight, not chart-provisioned

- **Status:** Accepted
- **Enforced by:** the opt-in `issue-svc-token --require-authority` flag and its
  `check_require_authority` / `unbacked_authority_message` helpers
  (`crates/hort-server/src/cli/admin.rs`), which the svc-token bootstrap Job
  passes (`deploy/helm/hort-server/templates/svc-token-bootstrap-job.yaml`); the
  gitops-prerequisite text in `deploy/helm/hort-server/values.yaml`
  (`scheduledTasks.adminTasksEnabled`) and `templates/NOTES.txt`; and the how-to
  `docs/architecture/how-to/deploy/enable-admin-task-cronjobs.md`. Regression
  tests: `check_require_authority_*` and `unbacked_authority_message_*` in
  `admin.rs`; the Helm render is covered by `scripts/test-helm-templates.sh`.
- **Supersedes:** —
- **Relates:** [0037](0037-gitops-service-account-grant.md) (the
  `serviceAccount`-subject grant this preflight verifies is present),
  [0044](0044-service-accounts-identity-only.md) (authority = grants ∩ cap,
  enforced live — the basis for verifying a backing grant rather than the mint
  cap), [0038](0038-admin-identity-model.md) (§4: destructive kinds need a fresh
  admin claim, never a static token — the basis for destructive-tasks-docs-only),
  [0012](0012-claim-based-rbac-claimless-static-tokens.md) (SA authority is
  operator-declared grants through the audited apply path, never chart-injected).

## Context

An `adminTasksEnabled: true` Helm install renders a post-install/post-upgrade
hook Job that mints a `cronjob-tasks` service-account token
(`issue-svc-token --name=cronjob-tasks --permission=admin_task_invoke`) into the
Secret every `executionPath: admin-task` CronJob mounts as `HORT_TOKEN`. That
mint depends on two operator-supplied gitops objects the chart neither ships nor
validates: the `cronjob-tasks` `ServiceAccount` and a **global**
`admin_task_invoke` `PermissionGrant` targeting it. Getting the prerequisite
wrong failed two ways, both poor:

- **SA absent** → `issue-svc-token` bails; the failure surfaces only as an
  opaque "hook failed" (and, under `helm --atomic` / Flux remediation, a full
  rollback).
- **Grant absent** → the token mints successfully (the mint never consults the
  grants table; the token's *cap* is the declared permission set, and real
  authority is `grants ∩ cap` computed live at each request). The install
  **succeeds**, then every admin-task CronJob 403s at every tick with **no
  install-time signal at all**.

Auto-provisioning the SA + grant from the chart was considered and rejected (see
Alternatives): SA authority is deliberately operator-declared through the audited
gitops apply path (ADR 0012/0037/0044), the chart's gitops delivery surface is a
single operator-owned ConfigMap keyspace with no clobber-free seam for
chart-authored documents, and a "destructive-authority SA" is both impossible
(native SA tokens are claimless — ADR 0012) and forbidden (ADR 0038 §4).

## Decision

**The chart does not provision the admin-task gitops `ServiceAccount` or its
grant. It makes the prerequisite loud and documented instead: a `--require-authority`
preflight fails the install with an actionable message when the SA *or* its
backing grant is missing, and the operator docs carry the copy-paste gitops.
Destructive CronJobs remain disabled-by-default and docs-only.**

### D1 — `issue-svc-token --require-authority` verifies the backing grant

An opt-in `--require-authority` flag, after the SA is resolved and **before**
minting, verifies every declared `--permission` is backed by a live grant on the
SA's backing user at **global** scope (`repository = None`), using the same
`RbacEvaluator::authorize_granted` grants-leg the runtime authorizes each request
with — not a hand-rolled query. Any unbacked permission `bail!`s before any token
is written, naming all unbacked permissions and printing the exact copy-paste
`PermissionGrant` YAML. The grants-leg is checked in isolation because the token's
cap equals the just-declared permissions (so the cap leg the runtime AND-composes
is guaranteed-true for them); the one leg that can fail is the grant. Default
(flag unset) behaviour is unchanged — no new query runs.

### D2 — The bootstrap Job passes `--require-authority`

The svc-token bootstrap hook Job's init container passes the flag, so the
previously-**silent** grant-absent case (CronJobs 403 hours later) becomes a
**loud install-time** hook failure with the fix in the message. Because the
preflight runs on every hook invocation (every `helm upgrade`, not just first
install), a grant an operator later revokes also resurfaces on the next routine
upgrade rather than staying silent. The SA-absent case keeps its existing
`resolve_svc_user` bail. Neither is a *provisioning* step — the chart never writes
gitops.

### D3 — Destructive CronJobs stay disabled-by-default, docs-only

`retention-evaluate`, `retention-purge`, `eventstore-archive` require the
`task:destructive` claim, satisfiable only by a fresh IdP-backed admin session
and never by the claimless bootstrap svc-token (ADR 0038 §4). They ship
`enabled: false` and stay so; this decision only improves their warnings
(`values.yaml`, `NOTES.txt`, the how-to). The hardcoded destructive-CronJob
`HORT_TOKEN` secretKeyRef (no values knob for an operator-supplied
`task:destructive` Secret) and the cron-proposes/admin-confirms approval workflow
are **deferred** to the ADR 0038 follow-on 1 (which needs its own security
co-review) — not introduced here.

## Consequences

- A misconfigured `adminTasksEnabled` install now fails at install time with a
  copy-paste fix, for **both** the SA-absent and the grant-absent case — never a
  silent CronJob 403 discovered days later. This is the "clear, actionable
  pre-flight error" arm of issue #21's acceptance.
- The operator keeps full ownership of their gitops tree; the chart writes no
  gitops document into it, so there is no chart-vs-operator key-namespace clobber.
- Applying the missing grant fixes a running deployment without rotating the
  token — the runtime `RbacEvaluator` re-reads grants live per request. Operators
  do not need `rotateSvcToken: true` for the grant-absent recovery.
- A negligible sub-second window exists where the bootstrap hook could read the
  grants table between the boot-time apply's service-account write and its
  permission-grant write; it is a strict sub-window of the pre-existing
  SA-absent race, is only reachable during the server's one-shot boot apply, and
  self-heals via the Job's in-retry plus the documented "re-run `helm upgrade`".
- The authority model is untouched: no SA gains admin, no static token carries
  `task:destructive`, and the preflight only *reads* grants using the runtime's
  own evaluator.

## Alternatives considered

- **Have the chart provision the `cronjob-tasks` SA + grant as chart-authored
  gitops documents** (issue #21's headline proposal). Rejected: SA authority is
  operator-declared through the audited apply path (ADR 0012/0037/0044), and the
  chart's gitops delivery is a single operator-owned ConfigMap keyspace
  (`gitopsConfig` → one ConfigMap → `HORT_CONFIG_DIR`) with no clobber-free seam
  for chart-owned documents. Provisioning would either share the operator's key
  namespace (convention-only clobber safety) or require a second projected
  ConfigMap — writing into the operator's declarative surface either way. The
  operator decided their gitops stays operator-owned; the loud preflight + docs
  meet the acceptance without the chart touching gitops.
- **Auto-provision a destructive-authority SA behind an opt-in.** Rejected as
  both impossible and forbidden: a native SA token is claimless
  (`authenticate_pat`), so it can never carry `task:destructive`; and an admin/
  destructive SA is rejected three ways (ADR 0038 §4). Destructive housekeeping's
  durable answer is the cron-proposes/admin-confirms approval workflow follow-on.
- **A verification endpoint / dry-run invoke over HTTP instead of a CLI flag.**
  Rejected: the bootstrap Job already runs `issue-svc-token` against the DB with
  the SA resolved in hand; reusing the runtime `RbacEvaluator` there is one grant
  read with no new surface, versus a network round-trip and a new endpoint.
- **Make `--require-authority` the default for `issue-svc-token`.** Rejected: the
  CLI is general-purpose and an operator may legitimately mint a cap before
  applying its grant (order-of-operations), or in flows where the grant is scoped
  differently. The flag is opt-in; the bootstrap Job — which has a fixed,
  known-correct expectation — sets it.

## References

- `crates/hort-server/src/cli/admin.rs` — `IssueSvcTokenArgs::require_authority`,
  `check_require_authority`, `unbacked_authority_message`, `resolve_svc_user`.
- `crates/hort-app/src/rbac.rs` — `RbacEvaluator::authorize_granted` (the
  grants-leg the preflight reuses).
- `deploy/helm/hort-server/templates/svc-token-bootstrap-job.yaml`,
  `deploy/helm/hort-server/values.yaml`, `deploy/helm/hort-server/templates/NOTES.txt`.
- `docs/architecture/how-to/deploy/enable-admin-task-cronjobs.md` — the operator
  prerequisite + failure diagnosis this decision documents.
- [0037](0037-gitops-service-account-grant.md),
  [0038](0038-admin-identity-model.md),
  [0044](0044-service-accounts-identity-only.md),
  [0012](0012-claim-based-rbac-claimless-static-tokens.md).
