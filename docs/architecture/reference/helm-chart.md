# Reference — the `hort-server` Helm chart

Operator reference for the chart at `deploy/helm/hort-server/`. It covers
the **chart structure**: what Kubernetes objects it renders and under
which conditions, the install-time validation rules, Helm hook
ordering, what each workload actually runs, the probes, and the
chart-vs-binary caveats that bite operators.

This page is deliberately **not** a per-key `values.yaml` walkthrough —
that already exists:

| For… | See |
|---|---|
| Per-key `values.yaml` reference (type, default, security cross-walk, examples) | [values-reference.md](../how-to/deploy/values-reference.md) |
| The binary env vars these values render into (defaults, interlocks) | [server & worker configuration](./server-and-worker-configuration.md) |
| Step-by-step install playbook | [install.md](../how-to/deploy/install.md) |
| Edge / TLS-termination overlays | [examples-overlays.md](../how-to/deploy/examples-overlays.md) |
| Security control cross-walk | [security-hardening-checklist.md](../how-to/deploy/security-hardening-checklist.md) |

> **Authority.** Ground truth is the chart itself —
> `deploy/helm/hort-server/{Chart.yaml,values.yaml,values.schema.json,templates/}`.
> Where this page and the chart disagree, the chart wins and this page
> is the bug; fix it in the same change.

---

## 1. Chart metadata

| Field | Value |
|---|---|
| `apiVersion` | `v2` |
| `name` | `hort-server` |
| `type` | `application` |
| `version` (chart) | `1.0.0-rc.14` |
| `appVersion` (binary) | `1.0.0-rc.14` — chart and binary are versioned together |
| `kubeVersion` | `>=1.27.0-0` (1.27 = `RuntimeDefault` seccomp, restricted PSS baseline, native `topologySpreadConstraints` v1) |
| Subcharts / dependencies | none |
| Annotations | `artifacthub.io/license: MIT` |

The chart deploys **two** workloads from **two** images: `hort-server`
(the HTTP edge, `image.*`) and `hort-worker` (the scanner-bundled job
dispatcher, `worker.image.*`, **disabled by default**). It ships **no
Ingress / Gateway / HTTPRoute** — the operator owns the edge.

---

## 2. Topology & required values

The schema permits exactly two consistent topologies and blocks the
inconsistent middle:

| | Single-replica | HA |
|---|---|---|
| `replicaCount` | `1` (default) | `>= 2` |
| `storage.backend` | `filesystem` (RWO PVC) | `s3` (**forced** by schema) |
| `ephemeralStore.backend` | `memory` (default) | `redis` (**forced** by schema) |

Minimum required values for any install (schema-enforced at
`helm install` — see [§5](#5-installtime-validation)):

| Key | Why |
|---|---|
| `publicBaseUrl` | Canonical URL the edge terminates; must match `^https?://.+`. |
| `auth.oidc.issuerUrl` + `auth.oidc.audience` | Required when `auth.provider=oidc` (the default). |
| `postgres.app.existingSecret` | Runtime DSN as `hort_app_role` (DML only). |
| `postgres.admin.existingSecret` | DDL DSN as `hort_admin` (migrate Job only — never on the Deployment). |
| `storage.s3.{endpoint,bucket,existingSecret}` | Required when `storage.backend=s3`. |
| `ephemeralStore.redis.{url\|existingSecret}` | Required when `ephemeralStore.backend=redis`. |
| `worker.rotation.publicRegistryHost` | Required when `scheduledTasks.serviceAccountRotation.enabled=true` (the single rotation toggle). |

---

## 3. Rendered-resource matrix

Default install (`helm install` with only the required values set)
renders everything in the **Always** rows plus the two default-enabled
`executionPath: dsn-direct` CronJobs — **scrub** and
**quarantine-release-sweep**. All `executionPath: admin-task` CronJobs (and
the svc-token bootstrap Job + RBAC) stay off until
`scheduledTasks.adminTasksEnabled=true`.

| Resource (template) | Rendered when | Purpose |
|---|---|---|
| ConfigMap (`configmap.yaml`) | **Always** | gitops config mounted at `/etc/hort-server/config` (`HORT_CONFIG_DIR`). |
| Deployment — server (`deployment.yaml`) | **Always** | runs `hort-server serve`. |
| Service, ClusterIP (`service.yaml`) | **Always** | fronts the `http` port (and `metrics` port iff `metrics.bindAddr` non-empty). |
| Job — migrate (`job-migrate.yaml`) | **Always** (pre-install/pre-upgrade hook) | `hort-server migrate` under the admin DSN. |
| ServiceAccount — server (`serviceaccount.yaml`) | `serviceAccount.create` (default **true**) | identity for server pods + scrub CronJob. |
| PVC (`pvc.yaml`) | `storage.backend=filesystem` **and** `storage.filesystem.pvc.enabled` (default true) | CAS data volume; annotated `helm.sh/resource-policy: keep`. |
| CronJob — scrub (`cronjob-scrub.yaml`) | `scheduledTasks.scrub.enabled` (default **true**) | `hort-server scrub` CAS integrity sweep. **`executionPath: dsn-direct`: gated by `scheduledTasks.scrub.enabled` alone — not by `scheduledTasks.adminTasksEnabled`.** |
| PodDisruptionBudget (`pdb.yaml`) | `replicaCount > 1` **OR** `podDisruptionBudget.enabled` | `minAvailable` guard. |
| NetworkPolicy (`networkpolicy.yaml`) | `networkPolicy.enabled` (default false) | Ingress+Egress policy for server pods. |
| ServiceMonitor (`servicemonitor.yaml`) | `metrics.serviceMonitor.enabled` (hard-fails render if `metrics.bindAddr` empty) | Prometheus-operator scrape. |
| Deployment — worker (`worker-deployment.yaml`) | `worker.enabled` | multi-kind poll-loop dispatcher (scanners + rescan/advisory/sweep/noop). |
| ConfigMap — worker (`worker-configmap.yaml`) | `worker.enabled` | non-secret worker env. |
| ServiceAccount — worker (`worker-serviceaccount.yaml`) | `worker.enabled` **and** `worker.serviceAccount.create` | identity for worker pods. |
| Role+RoleBinding ×N — rotation (`svc-rotation-rbac.yaml`) | `worker.enabled` **and** `scheduledTasks.serviceAccountRotation.enabled` (the single rotation toggle) **and** each entry in `worker.rotation.targetNamespaces` | one pair **per namespace**; lets the worker SA write `dockerconfigjson` Secrets. |
| Job — svc-token bootstrap (`svc-token-bootstrap-job.yaml`) | `scheduledTasks.adminTasksEnabled` (post-install/post-upgrade hook) | mints the `hort_svc_*` token, writes the `<fullname>-svc-token` Secret. |
| SA+Role+RoleBinding — bootstrap (`svc-bootstrap-rbac.yaml`) | `scheduledTasks.adminTasksEnabled` | lets the bootstrap Job create/patch that Secret. |
| CronJob — staging-sweep (`cronjob-staging-sweep.yaml`) | `scheduledTasks.adminTasksEnabled` **and** `scheduledTasks.stagingSweep.enabled` | `hort-cli admin task invoke staging-sweep`. |
| CronJob — cron-rescan-tick (`cronjob-cron-rescan-tick.yaml`) | `scheduledTasks.adminTasksEnabled` **and** `scheduledTasks.cronRescanTick.enabled` | `hort-cli admin task invoke cron-rescan-tick`. |
| CronJob — advisory-watch-tick (`cronjob-advisory-watch-tick.yaml`) | `scheduledTasks.adminTasksEnabled` **and** `scheduledTasks.advisoryWatchTick.enabled` | `hort-cli admin task invoke advisory-watch-tick`. |
| CronJob — service-account-rotation (`cronjob-service-account-rotation.yaml`) | `scheduledTasks.adminTasksEnabled` **and** `scheduledTasks.serviceAccountRotation.enabled` | `hort-cli admin task invoke service-account-rotation`. |
| CronJob — noop (`cronjob-noop.yaml`) | `scheduledTasks.adminTasksEnabled` **and** `scheduledTasks.noop.enabled` | `hort-cli admin task invoke noop` heartbeat. |
| CronJob — quarantine-release-sweep (`cronjob-quarantine-release-sweep.yaml`) | `scheduledTasks.quarantineReleaseSweep.enabled` (default **true**) | `executionPath: dsn-direct` — `hort-server enqueue-quarantine-release-sweep`; not gated by `adminTasksEnabled`. |
| CronJobs — prefetch-tick / prefetch-row-retention-sweep / wheel-metadata-backfill | each task's own `scheduledTasks.<task>.enabled` (all default **false**) | `executionPath: dsn-direct` — `hort-server enqueue-<task>`; not gated by `adminTasksEnabled`. |
| CronJobs — retention-evaluate / retention-purge / eventstore-archive / eventstore-checkpoint / replay-seen-prune (default **true**) / verify-event-chain | `scheduledTasks.adminTasksEnabled` **and** the task's own `scheduledTasks.<task>.enabled` | `executionPath: admin-task` (`verify-event-chain` runs `hort-server verify-event-chain` directly but shares the `adminTasksEnabled` gate). |
| Job — helm test (`tests/test-connection.yaml`) | only under `helm test` (test hook) | busybox `wget` poll of `/healthz`. |

The `<fullname>-svc-token` **Secret** is created at run time by the
bootstrap Job's `kubectl apply` — it is **not** a chart template and
does not appear in `helm template` output.

---

## 4. Helm hooks, install ordering & workload wiring

Only three templates carry `helm.sh/hook` annotations:

| Job | Hook | Weight | Delete policy |
|---|---|---|---|
| migrate (`<fullname>-migrate`) | `pre-install,pre-upgrade` | `-5` | `before-hook-creation,hook-succeeded` |
| svc-token bootstrap (`<fullname>-svc-token-bootstrap`) | `post-install,post-upgrade` | `5` | `before-hook-creation` |
| test-connection | `test` | — | `before-hook-creation,hook-succeeded` |

**Ordering guarantee:** migrate Job (`pre-install`, w=-5) → all
non-hook resources incl. server Deployment + bootstrap RBAC (w=0) →
svc-token bootstrap Job (`post-install`, w=5). Net effect: the schema
is migrated **before** the server serves; the service-account row and
its RBAC exist before the token bootstrap runs; CronJobs are created in
the main phase but only fire on schedule, by which time the bootstrap
Job has populated the `-svc-token` Secret they mount. The migrate Job
runs under the namespace `default` ServiceAccount on purpose — as a
pre-install hook it precedes the SA template.

**What each workload runs** (`hort-server` / `hort-worker` / `hort-cli`):

| Workload | Effective command |
|---|---|
| Deployment — server | `hort-server serve` (`args: ["serve"]`) |
| Deployment — worker | `hort-worker` (image entrypoint = dispatcher default; no args) |
| Job — migrate | `hort-server migrate` (`args: ["migrate"]`) under the **admin** DSN |
| Job — svc-token bootstrap | init: `hort-server admin issue-svc-token --name=cronjob-tasks --permission=admin_task_invoke --output=file:/run/bootstrap/token`; main: `kubectl apply` of the Secret (image `scheduledTasks.svcTokenKubectlImage`, default `bitnamilegacy/kubectl:1.30`) |
| CronJob — scrub | `hort-server scrub [--sample-fraction <scheduledTasks.scrub.samplingRate>] [--concurrency <scheduledTasks.scrub.concurrency>]` |
| CronJobs — staging-sweep / cron-rescan-tick / advisory-watch-tick / service-account-rotation / noop | `hort-cli admin task invoke <kind> --idempotency-key-window minute`; env `HORT_SERVER=http://<fullname>:<service.httpPort>`, `HORT_TOKEN` from the `<fullname>-svc-token` Secret |

All five `hort-cli` CronJobs use `concurrencyPolicy: Forbid`. The
Idempotency-Key window is minute-granular, which makes a **5-minute
period the practical floor** for any `schedule:` you set on the
admin-task CronJobs.

---

## 4a. Probes

**Server Deployment** — all three are `httpGet` on port name `http`:

| Probe | Path | initialDelay | period | timeout | failureThreshold |
|---|---|---|---|---|---|
| liveness | `/healthz` | 10 | 15 | 3 | 5 |
| readiness | `/readyz` | 5 | 5 | 2 | 3 |
| startup | `/healthz` | 0 | 5 | 2 | 60 (~300 s cold-boot budget for OIDC/JWKS warmup) |

`terminationGracePeriodSeconds` = `shutdown.gracefulSeconds + 30`.

**Worker Deployment** — one `exec` liveness probe, no readiness/startup
(it serves no traffic):

| Probe | Command | initialDelay | period | timeout | failureThreshold |
|---|---|---|---|---|---|
| liveness | `hort-worker healthcheck` | 10 | 30 | 3 | 3 |

`hort-worker healthcheck` verifies env parse + a single Postgres
`SELECT 1` (internal budget 2.5 s, pool-acquire 2 s — both kept below
the 3 s probe timeout). Worker `terminationGracePeriodSeconds` is a
fixed `45`.

---

## 5. Install-time validation

`values.schema.json` (JSON Schema draft-07) rejects a bad
`helm install`/`upgrade` **before** anything reaches the cluster.

### Strict schema — unknown keys fail

`additionalProperties: false` is set on the **top-level object and every
nested object block the chart owns the shape of**. An unknown, mistyped,
or **retired** key fails `helm install`/`helm template` with
`Additional property <key> is not allowed`, instead of being silently
accepted and ignored (the pre-078 worst-case: an operator sets a value
that has no effect and never finds out). This catches typos
(`worker.scanner.osvv`), top-level slips (`replicaCountt`), and every
pre-078 retired key — `apiBindAddr` (now `api.bindAddr`),
`worker.scanner.osvScanner` (now `worker.scanner.osv`),
`http.ociUploadTimeoutSeconds` (now `oci.uploadTimeoutSeconds`), the old
`cronJobs.*` tree (now `scheduledTasks.*`). Free-form passthrough blocks
the operator owns the shape of — `resources`, `probes.*`, `affinity`,
`nodeSelector`, the `*SecurityContext` blocks, `gitopsConfig`, and the
verbatim Kubernetes arrays (`extraEnv`, `extraVolumes`,
`networkPolicy.ingress`, …) — stay permissive: the strict lint guards the
chart's own config keys, not arbitrary pod-spec content. The regression
is locked by the `test-values-strict-schema-typo.yaml` fixture in
`scripts/test-helm-templates.sh` (the render MUST fail on the typo
keys).

### Always-required keys

Root: `publicBaseUrl`, `auth`, `postgres`, `storage`,
`ephemeralStore`, `replicaCount`. Plus `auth.provider`;
`postgres.app.existingSecret`; `postgres.admin.existingSecret`;
`storage.backend`; `ephemeralStore.backend`.

### Conditional invariant rules

Each rule surfaces the misconfiguration at install time instead of as a
server boot-crash loop.

| Trigger | Then required / forbidden | Prevents |
|---|---|---|
| `replicaCount >= 2` | `ephemeralStore.backend == redis` | split-brain sessions/locks across pods with per-pod memory stores. |
| `replicaCount >= 2` | `storage.backend == s3` | multiple pods racing one RWO PVC that cannot multi-attach. |
| `auth.provider == oidc` | `auth.oidc.issuerUrl` + `auth.oidc.audience` (non-empty) | booting with an unusable JWT validator. |
| `auth.tokenExchange.enabled` | `auth.provider == oidc` + `auth.tokenExchange.cliClientId` | enabling the exchange endpoint with no upstream OIDC / CLI client. |
| `auth.tokenExchange.enabled` | `auth.nativeTokens.enabled == true` + `signingKey.existingSecret` + `signingKey.secretKey` | exchange minting `hort_cli_*` tokens whose validator only wires when native tokens are on (binary `ConfigError::TokenExchangeRequiresNativeTokens`). |
| `storage.backend == s3` | `storage.s3.endpoint` + `storage.s3.bucket` + `storage.s3.existingSecret` (non-empty) | an S3 client that cannot be constructed. |
| `storage.s3.sseMode == sse-kms` | `storage.s3.sseKmsKeyArn` (non-empty) | SSE-KMS writes failing at runtime with no key ARN. |
| `ephemeralStore.backend == redis` | exactly one of `redis.url` / `redis.existingSecret` (`oneOf`) | redis with no connection string, or an ambiguous double source. |
| redis + per-class `evictable*` set | exactly one of `evictableUrl` / `evictableExistingSecret` | ambiguous evictable-class source. |
| redis + per-class `durable*` set | exactly one of `durableUrl` / `durableExistingSecret` | ambiguous durable-class source. |
| redis + a per-class override set **and** both main `redis.url` and `redis.existingSecret` empty | **install always rejected** (unsatisfiable) | the un-overridden class having no fallback URL. |
| `scheduledTasks.serviceAccountRotation.enabled` (the single rotation toggle) | `scheduledTasks.adminTasksEnabled == true` (rule 9a) | the rotation CronJob silently not rendering — it is an `executionPath: admin-task` template that renders only under the umbrella. |
| `scheduledTasks.serviceAccountRotation.enabled` | `worker.enabled == true` **and** `worker.rotation.publicRegistryHost` (non-empty) (rule 9b) | a worker that cannot rotate (no worker deployed) or a `dockerconfigjson.auths` map with nowhere to point. |

> The schema header says "eight rules"; the file actually encodes ~12
> conditional constructs (the count above) — the description is stale,
> the rules are not.

### Template-level guards (fail at `helm template`/render, not in the schema)

| Condition | Failure |
|---|---|
| `scheduledTasks.serviceAccountRotation.enabled`, `worker.rotation.publicRegistryHost` empty | `worker.rotation.publicRegistryHost is required when scheduledTasks.serviceAccountRotation.enabled=true` (the `required` template function; schema rule 9b rejects the same shape earlier). |
| `metrics.serviceMonitor.enabled`, `metrics.bindAddr` empty | `metrics.serviceMonitor.enabled=true requires metrics.bindAddr …` |

> The pre-existing two-place rotation switch was collapsed into the single
> `scheduledTasks.serviceAccountRotation.enabled` toggle and the cross-field
> half-set checks were moved from a bespoke `fail`-based template helper into
> the schema rules 9a/9b above — so a half-set rotation config is now rejected
> by `values.schema.json` (the uniform validation style) rather than a template
> `fail`.

---

## 6. Binary-default sentinels

Several numeric/string chart values use a sentinel meaning "let the
binary pick". Leave them at the sentinel unless you have a measured
reason; the binary defaults are the supported ones.

| Value | Sentinel | Resolves to |
|---|---|---|
| `http.maxInflight` | `0` | binary default `512` |
| `http.maxInflightPerIp` | `0` | binary default `32` |
| `http.publishBodyMaxSize` | `""` | binary default `300Mi` |
| `oci.maxSessionsPerPrincipal` | `0` | binary default `32` |
| `scheduledTasks.scrub.samplingRate` | `""` | `1.0` (scrub every blob) |
| `scheduledTasks.scrub.concurrency` | `""` | `4` |
| `metrics.bindAddr` | `""` | `/metrics` mounted on the main `:8080` router (dev only) |
| `image.tag` / `worker.image.tag` | `""` | `Chart.appVersion` |

See the [server & worker configuration reference](./server-and-worker-configuration.md)
for what each rendered env var does and its boot-time interlocks.

---

## 7. Scheduled tasks & worker — operator notes

All periodic tasks live under `scheduledTasks.*`; each
carries an `executionPath` attribute. `worker.enabled` and
`scheduledTasks.adminTasksEnabled` are **both off by default**; neither is
required for a functioning registry. Enable them only when you need
scanning, rescanning, advisory-watch, staging-sweep, retention, or
service-account rotation.

- **`executionPath: dsn-direct` tasks** (`scrub`, `quarantineReleaseSweep`,
  `prefetchTick`, `prefetchRowRetentionSweep`, `wheelMetadataBackfill`) run
  a `hort-server` subcommand with the runtime DSN only — no svc-token, no
  bootstrap Job — and are gated **solely by their own `enabled`**, never by
  `adminTasksEnabled`. `scrub` + `quarantineReleaseSweep` default **on**.
- **`executionPath: admin-task` tasks** (everything else) invoke `hort-cli
  admin task invoke <kind>` with the `<release>-svc-token` PAT and are gated
  by **both** `scheduledTasks.adminTasksEnabled` (the master toggle, which
  also renders the svc-token bootstrap Job + RBAC) **and** the task's own
  `enabled`. All default **off** except `replaySeenPrune` (default on once
  the master toggle is flipped). `verifyEventChain` is the one hybrid: it
  shares the `adminTasksEnabled` gate but runs `hort-server
  verify-event-chain` directly (no PAT).
- **Worker prerequisites:** `worker.enabled=true` requires the
  scanner-bundled `worker.image`. Do not set `worker.workerIdOverride`
  together with `worker.replicas > 1` (the per-pod random suffix is
  what keeps worker identities distinct).
- **Admin-task prerequisites:** `scheduledTasks.adminTasksEnabled=true`
  also needs `postgres.admin.existingSecret` (the bootstrap Job mints the
  SA token under the admin DSN) and an in-cluster network path from
  CronJob pods to the hort-server Service.
- **Rotation single toggle:**
  `scheduledTasks.serviceAccountRotation.enabled` is the **single**
  source-of-truth switch — it drives both the CronJob and the worker-side
  wiring (env + per-namespace RBAC). There is no separate
  `worker.rotation.enabled`. When it is on, the schema requires
  `scheduledTasks.adminTasksEnabled=true`, `worker.enabled=true`, and a
  non-empty `worker.rotation.publicRegistryHost` (rules 9a/9b); a half-set
  config fails at `helm install`. `worker.rotation.{targetNamespaces,
  publicRegistryHost}` are the worker-side **parameters** of that toggle.

---

## 8. Chart-vs-binary caveats

The chart schema is intentionally a superset in a few places; these are
the gaps an operator can fall into:

- **The retired `auth.provider: basic` is rejected at the schema, not
  just the binary.** The `basic` provider was removed
  end-to-end (see `docs/auth-catalog.md` Entry 8). The schema enum is now
  `{oidc,disabled}`, so `provider:
  basic` fails `helm install` on the enum check; and because the strict
  schema sets `additionalProperties: false` on the
  `auth` block, the retired `auth.basic.*` sub-block is **also** rejected
  (`Additional property basic is not allowed`) — there is no longer a
  schema-superset gap for `basic`. Use `oidc`, or `disabled` with
  `nativeTokens.enabled: true` (see
  [server & worker configuration §interlocks](./server-and-worker-configuration.md#hort-server--validation--interlocks)).
- **`storage.s3.region` is rendered as `AWS_REGION` but is not a
  schema-required S3 key.** Only `endpoint`, `bucket`,
  `existingSecret` are schema-required for the S3 backend; omitting
  `region` passes `helm install` and then fails at server boot. Set it
  whenever `storage.backend=s3`.
- **`scheduledTasks.scrub.enabled` defaults to `true`.** A default install
  runs a daily CAS-scrub CronJob (`0 3 * * *`). This is intended
  defence-in-depth; disable it explicitly
  (`scheduledTasks.scrub.enabled=false`) only if you have an external
  integrity backstop.
- **The `-svc-token` Secret is runtime-created.** It will not exist
  until the post-install bootstrap Job has run; CronJobs that mount it
  are created earlier but only fire on schedule, so the ordering holds
  on a clean install. On a chart `upgrade` that first enables
  `scheduledTasks.adminTasksEnabled`, the bootstrap Job (post-upgrade hook)
  populates it.

---

## See also

- [Per-key `values.yaml` reference](../how-to/deploy/values-reference.md)
- [Server & worker configuration reference](./server-and-worker-configuration.md)
- [Install playbook](../how-to/deploy/install.md)
- [Edge / TLS overlays](../how-to/deploy/examples-overlays.md)
- [Provision the two Postgres roles](../how-to/deploy/postgres-roles.md)
- [Security hardening checklist](../how-to/deploy/security-hardening-checklist.md)
- [Wire secrets](../how-to/wire-secrets.md) · [Declare gitops config](../how-to/declare-gitops-config.md)
