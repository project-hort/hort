#!/usr/bin/env bash
#
# scripts/test-helm-templates.sh — Helm chart render-assertion suite.
#
# Every render pins `--namespace default`: `helm template` otherwise
# inherits the kube-context/HELM_NAMESPACE namespace, and
# `.Release.Namespace` reaches rendered output (the svc-bootstrap
# RoleBinding subject), so an unpinned render is environment-dependent —
# byte-assertions and goldens must never depend on where the suite runs.
#
# Renders every `test-values-*.yaml` fixture in `deploy/helm/hort-server/`
# via `helm template` and asserts that each fixture produces the
# expected presence / absence of feature-gated lines in the rendered
# manifest. The fixtures themselves were added per-feature (basic, ha,
# extra-ca-*) and previously had no automated runner — operators caught
# breakage only by re-rendering the chart manually after a template
# edit. This script closes that gap.
#
# Run by:
#   - CI (chart-template-tests job in `.github/workflows/ci.yml`)
#   - locally before pushing chart changes
#
# Implementation: pure bash + helm + grep. Per-fixture assertions live
# in the `expectations()` block below; add a row when you add a fixture.
# Format: `<fixture>|<grep -cE pattern>|<expected count>|<human label>`.
#
# An expected count of `0` is a forbidden-line assertion ("the
# HORT_EXTRA_CA_BUNDLE env must NOT render when both fields are unset"),
# any positive integer is an exact-match assertion.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
chart_dir="${repo_root}/deploy/helm/hort-server"

if ! command -v helm >/dev/null 2>&1; then
    echo "error: helm CLI not on PATH" >&2
    echo "       install via https://helm.sh/docs/intro/install/" >&2
    exit 2
fi

if [[ ! -d "${chart_dir}" ]]; then
    echo "error: ${chart_dir} not found" >&2
    exit 2
fi

# Per-fixture expectations.
#
# When you add a new test-values-*.yaml fixture, append a row here. If
# the fixture exercises a feature gate (env var conditional, volume
# block, etc.), assert both the positive case (expected count > 0) and
# the negative case (expected count == 0 in a sibling fixture). The
# point of the suite is to lock the rendering states, not to spot-check
# one of them.
expectations() {
    cat <<'EOF'
test-values-extra-ca-with-cm.yaml|HORT_EXTRA_CA_BUNDLE|2|Recipe A: env var rendered on BOTH server + worker (auto-mount source set ⇒ env set)
test-values-extra-ca-with-cm.yaml|extra-ca-bundle|15|Recipe A: server mount+vol (2) + worker mount+vol (2) + scrub mount+vol (2) + quarantineReleaseSweep mount+vol (2) + scanRowRetentionSweep mount+vol (2) + prefetchRowRetentionSweep mount+vol (2) + jobsRowRetentionSweep mount+vol (2) + checksum annotation (1)
test-values-extra-ca-with-cm.yaml|defaultMode: 0444|7|Recipe A: read-only 0444 ConfigMap volume on server + worker + scrub + quarantineReleaseSweep + scanRowRetentionSweep + prefetchRowRetentionSweep + jobsRowRetentionSweep
test-values-extra-ca-with-cm.yaml|checksum/extra-ca-bundle:|1|Pod-template checksum annotation rendered for the ConfigMap source
test-values-extra-ca-unset.yaml|HORT_EXTRA_CA_BUNDLE|0|env var NOT rendered when no auto-mount source set
test-values-extra-ca-unset.yaml|extra-ca-bundle|0|volume NOT rendered when no auto-mount source set
test-values-extra-ca-unset.yaml|checksum/extra-ca-bundle:|0|annotation NOT rendered when extraCaBundle unset
test-values-extra-ca-unset.yaml|defaultMode: 0444|0|extra-CA volume not rendered → no defaultMode
test-values-extra-ca-path-only.yaml|HORT_EXTRA_CA_BUNDLE|0|manual recipe: chart sets NO env (no auto-mount source ⇒ no chart-set env; operator sets it via extraEnv)
test-values-extra-ca-path-only.yaml|extra-ca-bundle|0|manual recipe: chart mounts NOTHING (no dangling volumeMount — the prior path-only cronjob volumeMount bug is fixed)
test-values-extra-ca-path-only.yaml|checksum/extra-ca-bundle:|0|annotation NOT rendered when no auto-mount source is set
test-values-extra-ca-with-secret.yaml|HORT_EXTRA_CA_BUNDLE|2|Recipe A-Secret: env var rendered on BOTH server + worker (secretName auto-mount ⇒ env set), symmetric with configMapName
test-values-extra-ca-with-secret.yaml|extra-ca-bundle|14|Recipe A-Secret: server mount+vol (2) + worker mount+vol (2) + scrub mount+vol (2) + quarantineReleaseSweep mount+vol (2) + scanRowRetentionSweep mount+vol (2) + prefetchRowRetentionSweep mount+vol (2) + jobsRowRetentionSweep mount+vol (2); NO checksum annotation (Secret path)
test-values-extra-ca-with-secret.yaml|defaultMode: 0444|7|Recipe A-Secret: read-only 0444 Secret volume on server + worker + scrub + quarantineReleaseSweep + scanRowRetentionSweep + prefetchRowRetentionSweep + jobsRowRetentionSweep
test-values-extra-ca-with-secret.yaml|checksum/extra-ca-bundle:|0|Recipe A-Secret: no checksum annotation for the Secret source (Secret updates propagate via Kubernetes, not via helm-upgrade re-render)
test-values-extra-ca-with-secret.yaml|corporate-ca-bundle-secret|7|Recipe A-Secret: the Secret name renders in the volume secretName on server + worker + scrub + quarantineReleaseSweep + scanRowRetentionSweep + prefetchRowRetentionSweep + jobsRowRetentionSweep
test-values-worker-extra-ca-recipe-b.yaml|HORT_EXTRA_CA_BUNDLE|1|manual recipe: ONLY the operator-supplied worker.extraEnv sets the env (chart sets none; server has no extraEnv ⇒ 0 there)
test-values-worker-extra-ca-recipe-b.yaml|extra-ca-bundle|0|manual recipe: NO chart-managed extra-ca-bundle volume/mount
test-values-worker-extra-ca-recipe-b.yaml|recipe-b-worker-ca|2|operator-supplied worker.extraVolumes name renders as both volumeMount and volume
test-values-worker-extra-ca-recipe-b.yaml|my-corporate-ca-secret|1|operator-supplied Secret name renders in the worker volume block
test-values-token-exchange-happy.yaml|HORT_TOKEN_EXCHANGE_ENABLED|1|HORT_TOKEN_EXCHANGE_ENABLED rendered when tokenExchange.enabled
test-values-token-exchange-happy.yaml|HORT_NATIVE_TOKENS_ENABLED|1|HORT_NATIVE_TOKENS_ENABLED rendered when nativeTokens.enabled (gate satisfied)
test-values-token-exchange-happy.yaml|HORT_OCI_TOKEN_SIGNING_KEY\b|1|HORT_OCI_TOKEN_SIGNING_KEY rendered via secretKeyRef
test-values-token-exchange-happy.yaml|HORT_OCI_TOKEN_SIGNING_KEY_PREV|1|HORT_OCI_TOKEN_SIGNING_KEY_PREV rendered when prevExistingSecret set (rotation window)
test-values-ephemeral-split.yaml|HORT_REDIS_URL_EVICTABLE|2|evictable env var rendered inline on BOTH server + worker (the worker's OSV advisory cache reads the evictable store — worker-deployment.yaml requires it; durable stays server-only)
test-values-ephemeral-split.yaml|HORT_REDIS_URL_DURABLE|1|durable env var rendered inline (server only — the worker does not wire the durable store)
test-values-ephemeral-split.yaml|redis://evict:pw@redis-evict:6379/0|2|evictable URL rendered as literal value on server + worker
test-values-ephemeral-split.yaml|redis://dur:pw@redis-dur:6379/0|1|durable URL rendered as literal value
test-values-ephemeral-secret-split.yaml|HORT_REDIS_URL_EVICTABLE|2|evictable env var rendered (via secretKeyRef) on BOTH server + worker (the worker's OSV advisory cache reads the evictable store)
test-values-ephemeral-secret-split.yaml|HORT_REDIS_URL_DURABLE|1|durable env var rendered (via secretKeyRef) — server only (worker does not wire the durable store)
test-values-ephemeral-secret-split.yaml|name: "hort-redis-evictable"|2|evictable secretKeyRef points at the configured Secret on server + worker
test-values-ephemeral-secret-split.yaml|key: "EVICTABLE_URL"|2|evictable secretKeyRef uses the configured key on server + worker
test-values-ephemeral-secret-split.yaml|name: "hort-redis-durable"|1|durable secretKeyRef points at the configured Secret
test-values-ephemeral-secret-split.yaml|key: "DURABLE_URL"|1|durable secretKeyRef uses the configured key
test-values-rotation.yaml|name: .*-service-account-rotation|1|rotation CronJob renders from the SINGLE toggle scheduledTasks.serviceAccountRotation.enabled (under scheduledTasks.adminTasksEnabled)
test-values-rotation.yaml|name: hort-server-rotation-|6|per-namespace Role + RoleBinding render for both target namespaces (2 namespaces × 3 name refs each — Role metadata.name + RoleBinding metadata.name + RoleBinding roleRef.name)
test-values-rotation.yaml|HORT_K8S_SECRET_WRITER_ENABLED|1|the SINGLE toggle scheduledTasks.serviceAccountRotation.enabled ALSO drives the worker-side wiring — HORT_K8S_SECRET_WRITER_ENABLED renders on the worker (no separate worker.rotation.enabled)
test-values-cronjobs.yaml|^kind: CronJob$|16|sixteen CronJobs render — the eleven scheduledTasks.adminTasksEnabled-gated admin-task entries (noop, staging-sweep, cron-rescan-tick, advisory-watch-tick, eventstore-checkpoint, replay-seen-prune, scanner-registry-prune, retention-evaluate, retention-purge, eventstore-archive, verify-event-chain — the last now default-on, ADR 0057) PLUS the always-on dsn-direct quarantineReleaseSweep (gated on scheduledTasks.quarantineReleaseSweep.enabled, default true) PLUS the always-on dsn-direct CAS scrub (gated on scheduledTasks.scrub.enabled, default true) PLUS the always-on dsn-direct scanRowRetentionSweep (gated on scheduledTasks.scanRowRetentionSweep.enabled, default true) PLUS the always-on dsn-direct prefetchRowRetentionSweep (gated on scheduledTasks.prefetchRowRetentionSweep.enabled, now default true: its terminal oci-index-child-ingest rows accrue on any OCI proxy repository with no per-repo opt-in, so a default-off sweep left them retained permanently — the same day-one-rows argument that has scanRowRetentionSweep shipping enabled). PLUS the always-on dsn-direct jobsRowRetentionSweep (gated on scheduledTasks.jobsRowRetentionSweep.enabled, default true: it is the horizon for every jobs.kind the two kind-specific sweeps do not reach, and the scheduled kinds it covers leave terminal rows on any deployment from day one — staging-sweep alone at ~288/day — so the same day-one-rows argument applies). wheelMetadataBackfill stays default-disabled (a one-shot retrofit, not an accruing-row sweep) and does NOT count.
test-values-cronjobs.yaml|name: hort-server-cron-rescan-tick$|1|cron-rescan-tick CronJob renders with conventional release-name suffix
test-values-cronjobs.yaml|name: hort-server-advisory-watch-tick$|1|advisory-watch-tick CronJob renders with conventional release-name suffix
test-values-cronjobs.yaml|name: hort-server-staging-sweep$|1|staging-sweep CronJob renders with conventional release-name suffix
test-values-cronjobs.yaml|name: hort-server-noop$|1|noop CronJob renders with conventional release-name suffix
test-values-cronjobs.yaml|name: hort-server-retention-evaluate$|1|retention-evaluate CronJob renders with conventional release-name suffix
test-values-cronjobs.yaml|name: hort-server-retention-purge$|1|retention-purge CronJob renders with conventional release-name suffix
test-values-cronjobs.yaml|name: hort-server-eventstore-archive$|1|eventstore-archive CronJob renders with conventional release-name suffix
test-values-cronjobs.yaml|^                - retention-evaluate$|1|retention-evaluate CronJob invokes the correct hort-cli task kind
test-values-cronjobs.yaml|^                - retention-purge$|1|retention-purge CronJob invokes the correct hort-cli task kind
test-values-cronjobs.yaml|^                - eventstore-archive$|1|eventstore-archive CronJob invokes the correct hort-cli task kind
test-values-cronjobs.yaml|^                - day$|3|exactly the three retention CronJobs carry --idempotency-key-window day (<UTC-date>:<kind> contract; cron-rescan/svc-rotation use minute)
test-values-cronjobs.yaml|^  concurrencyPolicy: Forbid$|16|every CronJob (incl. the 3 retention + the always-on quarantineReleaseSweep + the always-on scrub + the always-on scanRowRetentionSweep + the always-on jobsRowRetentionSweep + the now-default-on prefetchRowRetentionSweep + scanner-registry-prune + the now-default-on verify-event-chain, ADR 0057) sets concurrencyPolicy: Forbid (single-active layer 1; worker semaphore is layer 2)
test-values-cronjobs.yaml|name: hort-server-job-bootstrap-egress$|1|additive Job-scoped bootstrap-egress NetworkPolicy renders when networkPolicy.enabled (chart default true)
test-values-cronjobs.yaml|^kind: NetworkPolicy$|2|BOTH the app-pod NetworkPolicy and the additive Job-scoped policy render with the chart-default networkPolicy.enabled: true
test-values-networkpolicy-off.yaml|^kind: NetworkPolicy$|0|networkPolicy.enabled=false disables BOTH NetworkPolicies (app-pod AND the additive Job-scoped one)
test-values-networkpolicy-off.yaml|name: hort-server-job-bootstrap-egress$|0|the Job-scoped policy does NOT render when networkPolicy.enabled=false
test-values-cronjobs.yaml|name: HORT_STATEFUL_UPLOAD_STAGING_DIR$|1|HORT_STATEFUL_UPLOAD_STAGING_DIR env rendered unconditionally for storage.backend=filesystem (chart↔binary staging contract)
test-values-cronjobs.yaml|^              value: /var/lib/hort-server/staging/stateful-upload$|1|the staging dir points at a subdir of the already-mounted writable `staging` emptyDir (filesystem backend)
test-values-ha.yaml|name: HORT_STATEFUL_UPLOAD_STAGING_DIR$|1|HORT_STATEFUL_UPLOAD_STAGING_DIR env rendered unconditionally for storage.backend=s3
test-values-ha.yaml|^              value: /var/lib/hort-server/staging/stateful-upload$|1|the staging dir points at the writable `staging` emptyDir subdir under S3 backend
test-values-local-bringup.yaml|HORT_NATIVE_TOKENS_ENABLED|1|minimal-setup recipe (provider=disabled + nativeTokens.enabled): the native-token validator env renders; also the valid-keys GREEN counterpart to the test-values-strict-schema-typo.yaml strict-schema regression (this fixture's keys are all enumerated ⇒ it renders, the typo fixture's are not ⇒ it fails)
test-values-networkpolicy-off.yaml|HORT_NATIVE_TOKENS_ENABLED|1|the escape-hatch fixture uses the supported provider=disabled + nativeTokens minimal-setup shape (renders under the strict schema)
test-values-worker-metrics.yaml|HORT_WORKER_METRICS_BIND|1|worker.metrics.enabled sets the /metrics scrape-listener bind on the worker Deployment (inline env, 0.0.0.0:<port>)
test-values-worker-metrics.yaml|containerPort: 9090|2|worker.metrics.enabled exposes the named `metrics` containerPort on the worker Deployment (the worker otherwise has no inbound HTTP surface)
test-values-worker-metrics.yaml|^kind: NetworkPolicy$|3|the additive `-worker-metrics` NetworkPolicy renders ALONGSIDE the chart-default app-pod + Job-scoped policies (networkPolicy.enabled default true)
test-values-worker-metrics.yaml|name: hort-server-worker-metrics$|1|the worker-scoped scrape NetworkPolicy renders with the conventional release-name suffix
test-values-worker-metrics.yaml|^        - port: 9090$|1|the worker NetworkPolicy's single Ingress rule admits the configured scrapers to the metrics port (the additive scrape allowance)
test-values-worker-metrics.yaml|app.kubernetes.io/component: worker|7|the `-worker-metrics` NetworkPolicy adds exactly 2 `component: worker` lines (metadata label + podSelector) — selecting ONLY worker pods — on top of the 5 the worker Deployment/ConfigMap/ServiceAccount already carry
test-values-worker-metrics-worker-disabled.yaml|HORT_WORKER_METRICS_BIND|0|worker.enabled=false renders NO worker Deployment at all, so the /metrics bind env never renders despite worker.metrics.enabled=true left set — directive 118 rev2's fixed gap
test-values-worker-metrics-worker-disabled.yaml|^kind: NetworkPolicy$|0|worker.enabled=false with networkPolicy.enabled=false renders NO NetworkPolicy at all — the worker-scoped scrape policy stays skipped (no worker pod to protect) and the app-pod/Job policies stay off via the explicit networkPolicy.enabled=false, so this combination must NOT trip the worker-metrics fail guard
test-values-worker-metrics-worker-disabled.yaml|app.kubernetes.io/component: worker|0|worker.enabled=false renders NO worker-labelled resource at all (Deployment, ConfigMap, ServiceAccount, NetworkPolicy) — worker.metrics.enabled=true is inert with no worker pod to attach a listener to
test-values-dex.yaml|hort-server.io/component: dex|6|auth.dex.enabled renders the Dex sidecar trio (ConfigMap + Service + Deployment) — 6 component-label lines: ConfigMap metadata (1) + Service metadata + podSelector (2) + Deployment metadata + selector + pod-template (3)
test-values-dex.yaml|ghcr.io/dexidp/dex|1|auth.dex.enabled renders the Dex Deployment with the configured Dex image
test-values-dex.yaml|/etc/dex/config.yaml|1|the Dex Deployment serves the mounted config (dex serve /etc/dex/config.yaml)
test-values-dex.yaml|value: "https://registry.example.com/dex"|6|auth.dex.enabled overrides HORT_OIDC_ISSUER_URL to auth.dex.issuerUrl on the server Deployment AND the five DSN-direct runtimeEnv CronJobs (scrub + quarantineReleaseSweep + scanRowRetentionSweep + prefetchRowRetentionSweep + jobsRowRetentionSweep)
test-values-dex.yaml|^ +value: "hort-cli"$|6|auth.dex.enabled overrides HORT_OIDC_AUDIENCE to auth.dex.cliClientId (Dex mints the cli-flow token; its aud is the Dex client id, NOT auth.oidc.audience) — on the server Deployment AND the five DSN-direct runtimeEnv CronJobs; mirrors the issuer override and the Ansible flavor
test-values-token-exchange-happy.yaml|hort-server.io/component: dex|0|auth.dex.enabled default false ⇒ NO Dex sidecar renders (negative counterpart to test-values-dex.yaml)
test-values-svc-tokens-multi.yaml|name: issue-token$|1|two-entry svcTokens: exactly one bare `issue-token` init container (the first, backward-compatible entry)
test-values-svc-tokens-multi.yaml|name: issue-token-uat-smoke$|1|two-entry svcTokens: the second entry gets its own suffixed init container
test-values-svc-tokens-multi.yaml|^            - --name=cronjob-tasks$|1|two-entry svcTokens: first entry's identity name reaches issue-svc-token
test-values-svc-tokens-multi.yaml|^            - --name=uat-smoke$|1|two-entry svcTokens: second entry's identity name reaches issue-svc-token
test-values-svc-tokens-multi.yaml|^            - --output=file:/run/bootstrap/token$|1|two-entry svcTokens: first entry keeps the pre-list flat output path
test-values-svc-tokens-multi.yaml|^            - --output=file:/run/bootstrap/uat-smoke.token$|1|two-entry svcTokens: second entry gets its own output path (no clobbering on the shared emptyDir)
test-values-svc-tokens-multi.yaml|^      - hort-server-svc-token$|1|two-entry svcTokens: first entry's EMPTY secretName defaults correctly to the backward-compatible bare name, and the RBAC Role's resourceNames carries it
test-values-svc-tokens-multi.yaml|^      - uat-smoke-svc-token$|1|two-entry svcTokens: second entry's EXPLICIT secretName is respected verbatim, and the RBAC Role's resourceNames carries it
test-values-svc-tokens-rotate-entry.yaml|^            - --rotate$|1|per-entry rotate:true on only the second entry reaches ONLY that entry's init container as --rotate
test-values-svc-tokens-rotate-global.yaml|^            - --rotate$|2|blanket scheduledTasks.rotateSvcToken=true reaches EVERY entry's init container as --rotate, even with no per-entry rotate set
test-values-svc-tokens-repository.yaml|^            - --repository=maven-proxy$|1|per-entry repository:maven-proxy on only the second entry reaches ONLY that entry's init container as --repository
test-values-svc-tokens-repository.yaml|repository=maven-proxy|1|exactly one entry declares repository — the first (unscoped) entry renders NO --repository flag at all
test-values-svc-tokens-authority-repository.yaml|^            - --require-authority=maven-proxy$|1|per-entry authorityRepository:maven-proxy on only the second entry reaches ONLY that entry's init container as --require-authority=<scope>
test-values-svc-tokens-authority-repository.yaml|^            - --require-authority$|1|the first entry (neither field set) still renders the bare --require-authority — the byte-compatible default is unaffected
test-values-svc-tokens-authority-repository.yaml|^            - --repository=|0|the second entry's cap stays global (no --repository flag at all) even though its preflight is scoped — proving cap width and preflight scope are independent knobs
test-values.yaml|helm.sh/hook-weight: "-10"|2|both pre-pull DaemonSets (server + worker) render at weight -10, strictly before the migrate hook's -5 (prePull.enabled + worker.enabled default true)
test-values.yaml|helm.sh/hook-weight: "-9"|1|the pre-pull wait/cleanup Job renders at weight -9 — between the DaemonSets (-10) and the migrate hook (-5)
test-values.yaml|^kind: DaemonSet$|2|both prepull DaemonSets (server + worker) render by default
test-values-prepull-disabled.yaml|prepull|0|prePull.enabled=false renders NEITHER DaemonSet, NOR the wait Job, NOR its RBAC (all four resource names contain "prepull")
test-values-prepull-disabled.yaml|^kind: NetworkPolicy$|2|prePull.enabled=false has no effect on the unrelated NetworkPolicy pair (still networkPolicy.enabled default true)
EOF
}

# Template-scoped expectations — like expectations() but rendered via
# `--show-only` so the assertion targets one template's output instead
# of the whole multi-template render. Use this when the full-render grep
# would also match an unrelated `readOnly`/pattern hit in a different
# template (e.g. the worker Deployment's CAS mount vs. the scrub
# CronJob's own readOnly mounts). Format:
# `<fixture>|<template path, relative to the chart dir>|<grep -cE pattern>|<expected count>|<human label>`.
scoped_expectations() {
    cat <<'EOF'
test-values-cronjobs.yaml|templates/worker-deployment.yaml|readOnly: true|0|worker's CAS data mount renders WITHOUT readOnly (the worker writes scan-finding + prefetch-ingest blobs)
test-values-cronjobs.yaml|templates/worker-deployment.yaml|mountPath: /var/lib/hort-server/cas|1|worker's CAS data mount still renders (filesystem backend)
test-values-ha.yaml|templates/deployment.yaml|app.kubernetes.io/component: server|2|server Deployment's spec.selector.matchLabels carries the component discriminator (1) alongside the existing pod-template label (1) — matchLabels stays a subset of the pod labels
test-values-ha.yaml|templates/worker-deployment.yaml|app.kubernetes.io/component: worker|3|worker Deployment's spec.selector.matchLabels carries the component discriminator (1) alongside the Deployment metadata label (1) + pod-template label (1)
test-values-ha.yaml|templates/pdb.yaml|app.kubernetes.io/component: server|1|the server-only PDB's selector.matchLabels carries the component discriminator so it no longer also matches worker pods, which have no PDB of their own
test-values-cronjobs.yaml|templates/networkpolicy-migrate-job.yaml|^      app\.kubernetes\.io/name: hort-server$|1|the Job-egress policy's podSelector.matchLabels carries this release's name label (6-space indent — the policy's own metadata labels sit at 4, so this pattern sees the SELECTOR alone)
test-values-cronjobs.yaml|templates/networkpolicy-migrate-job.yaml|^      app\.kubernetes\.io/instance: hort-server$|1|the Job-egress policy's podSelector.matchLabels carries this release's instance label — without it the unrestricted-egress allowance reaches any pod in the namespace that sets an hort-server.io/job label, and a neighbouring release's Jobs too
test-values-cronjobs.yaml|templates/networkpolicy-migrate-job.yaml|^      - key: hort-server\.io/job$|1|the Job-egress policy's podSelector still ANDs the hort-server.io/job Exists clause onto the release scope — that clause alone is what keeps the app Deployment pods (same release labels, no job key) out of the allowance
test-values.yaml|templates/prepull-daemonset.yaml|ghcr.io/project-hort/hort-server:|1|the server pre-pull DaemonSet's init container pulls the SAME image repository as the server Deployment
test-values.yaml|templates/prepull-daemonset.yaml|args: \["--version"\]|1|the init container forces the pull via the no-op --version command (no new binary surface)
test-values.yaml|templates/prepull-worker-daemonset.yaml|ghcr.io/project-hort/hort-worker:|1|the worker pre-pull DaemonSet's init container pulls the SAME image repository as the worker Deployment
test-values.yaml|templates/prepull-job.yaml|rollout status daemonset/.*-prepull-server|1|the wait Job blocks on the server pre-pull DaemonSet's rollout before it can succeed
test-values.yaml|templates/prepull-job.yaml|rollout status daemonset/.*-prepull-worker|1|the wait Job blocks on the worker pre-pull DaemonSet's rollout before it can succeed
test-values-prepull-nodeselector.yaml|templates/prepull-daemonset.yaml|server-pool|1|the server pre-pull DaemonSet inherits the top-level nodeSelector (same placement as the server Deployment)
test-values-prepull-nodeselector.yaml|templates/prepull-daemonset.yaml|worker-pool|0|the server pre-pull DaemonSet does NOT inherit the worker's nodeSelector
test-values-prepull-nodeselector.yaml|templates/prepull-worker-daemonset.yaml|worker-pool|1|the worker pre-pull DaemonSet inherits worker.nodeSelector (same placement as the worker Deployment)
test-values-prepull-nodeselector.yaml|templates/prepull-worker-daemonset.yaml|server-pool|0|the worker pre-pull DaemonSet does NOT inherit the top-level (server) nodeSelector
test-values.yaml|templates/prepull-rbac.yaml|helm.sh/hook: pre-install,pre-upgrade|3|all three pre-pull RBAC resources (ServiceAccount, Role, RoleBinding) are hook resources — a regular (non-hook) resource is only applied AFTER hooks complete, which is exactly the ordering bug this fixes
test-values.yaml|templates/prepull-rbac.yaml|helm.sh/hook-weight: "-11"|3|all three pre-pull RBAC resources render at weight -11 — strictly before the pre-pull DaemonSets (-10) and the wait Job (-9), so the ServiceAccount exists before anything that needs it
test-values.yaml|templates/prepull-rbac.yaml|helm.sh/hook-delete-policy: before-hook-creation$|3|all three pre-pull RBAC resources use before-hook-creation ONLY — pinning the failure mode: adding hook-succeeded here would delete the ServiceAccount before the weight -9 Job ever runs (non-workload kinds "succeed" the instant they're created)
test-values.yaml|templates/prepull-rbac.yaml|hook-succeeded|0|none of the three pre-pull RBAC resources may carry hook-succeeded in their delete-policy (see row above for why)
EOF
}

# Byte-equivalence pin: rendering `scheduledTasks.svcTokens` at its
# DEFAULT (the single pre-list `cronjob-tasks` identity) must be
# byte-for-byte identical to the golden fixtures captured from the
# chart BEFORE the list refactor — an explicit acceptance criterion,
# not a best-effort match. Format:
# `<fixture>|<template path, relative to the chart dir>|<golden file, relative to the chart dir>|<human label>`.
golden_checks() {
    cat <<'EOF'
test-values-cronjobs.yaml|templates/svc-token-bootstrap-job.yaml|testdata/svc-token-bootstrap-job.golden.yaml|default single-identity svc-token-bootstrap Job renders byte-identical to the pre-list golden fixture
test-values-cronjobs.yaml|templates/svc-bootstrap-rbac.yaml|testdata/svc-bootstrap-rbac.golden.yaml|default single-identity svc-bootstrap RBAC renders byte-identical to the pre-list golden fixture
EOF
}

# Per-fixture render-failure expectations.
#
# Some fixtures exist specifically to exercise install-block schema
# rules — `helm template` against them MUST FAIL and the error
# output must contain a recognisable substring. Format:
# `<fixture>|<grep -E pattern that MUST appear in stderr>|<human label>`.
expect_render_failure() {
    cat <<'EOF'
test-values-ephemeral-broken.yaml|ephemeralStore.redis|per-class override set but main URL/secret empty must fail schema validation
test-values-token-exchange-broken.yaml|nativeTokens|tokenExchange.enabled=true with nativeTokens.enabled=false must fail schema validation (chart-level mirror of ConfigError::TokenExchangeRequiresNativeTokens)
test-values-rotation-half-on.yaml|scheduledTasks.adminTasksEnabled|the single rotation toggle scheduledTasks.serviceAccountRotation.enabled=true WITHOUT the scheduledTasks.adminTasksEnabled umbrella is a silent half-on — schema rule 9a must reject it at helm template
test-values-extra-ca-both-sources.yaml|extraCaBundle|configMapName AND secretName both set is mutually exclusive — schema oneOf + validateSources must fail the render
test-values-strict-schema-typo.yaml|[Aa]dditional propert|the strict schema (additionalProperties:false on the top-level + every nested block) must REJECT mistyped / retired keys (replicaCountt, apiBindAddr, http.ociUploadTimeoutSeconds, worker.scanner.osvScanner, worker.scanner.osvv) at helm template instead of silently ignoring them
test-values-worker-metrics-no-scrapers.yaml|scrapeFrom|worker.metrics.enabled=true with an empty scrapeFrom must be rejected — an empty NetworkPolicy `from: []` means ALL sources (fail-OPEN) per the k8s spec, so the schema's `if enabled then scrapeFrom minItems 1` rule must fail the render rather than open the metrics port cluster-wide
test-values-worker-metrics-no-networkpolicy.yaml|worker.metrics.enabled=true with networkPolicy.enabled=false|worker.metrics.enabled=true with networkPolicy.enabled=false is the one combination nothing else rejects — the listener turns on with no NetworkPolicy protecting it at all — so worker-networkpolicy.yaml's unconditional `fail` guard must reject it at helm template, naming both values
test-values-dex-broken.yaml|auth.dex.issuerUrl|auth.dex.enabled=true with an empty auth.dex.issuerUrl must fail schema validation — the chart points HORT_OIDC_ISSUER_URL at Dex so an empty issuer is rejected at render time
test-values-svc-tokens-repository-typo.yaml|[Aa]dditional propert|a mistyped scheduledTasks.svcTokens[].repository key (repositroy) must fail schema validation — additionalProperties:false on the svcTokens item schema, mirroring the top-level strict-schema typo fixture
EOF
}

# Generic per-CronJob `spec.timeZone` check.
#
# Unlike `expectations()` above (which pins an exact match count), this
# does NOT hard-code how many CronJob templates the chart has — it
# derives the expected count from the SAME render by counting
# `kind: CronJob` documents, then asserts the `timeZone:` value shows up
# once per CronJob document. A future `templates/cronjob-*.yaml` that
# forgets to set `timeZone` under `schedule:` lowers the timeZone count
# below the CronJob count and fails this check with no fixture-file edit
# required — the opposite of a hard-coded template-name enumeration,
# which a new template would silently bypass.
# Format: `<fixture>|<expected timeZone value>|<human label>`.
cronjob_timezone_checks() {
    cat <<'EOF'
test-values-cronjob-timezone.yaml|Etc/UTC|every rendered CronJob carries the chart-default scheduledTasks.timeZone
test-values-cronjob-timezone-override.yaml|America/Los_Angeles|an overridden scheduledTasks.timeZone reaches every rendered CronJob (no per-job override exists)
EOF
}

# Pod-selector scope checks for the additive Job-egress NetworkPolicy.
#
# That policy grants UNRESTRICTED egress (`to: []`), so *who it selects*
# is a security boundary rather than a detail, and both halves of the
# boundary need an assertion:
#
#   - Too wide and the allowance leaks. A `podSelector` that tested only
#     whether the `hort-server.io/job` label KEY exists hands unrestricted
#     egress to any pod in the namespace willing to set one label of its
#     own choosing — including to a principal who may label a Pod but may
#     not touch NetworkPolicies. A grep for that label key passes at
#     every scope, which is exactly why a key-shaped assertion cannot
#     hold this.
#   - Too narrow and `helm install` bricks. The allowance exists for the
#     pre-install migrate hook Job, which must reach Postgres before the
#     app pod (and its deny-all egress policy) exist. A selector no
#     legitimate Job pod matches fails at install time, not here —
#     swapping `hort-server.selectorLabels` for `hort-server.labels` in
#     the selector is one word and does precisely that.
#
# So this check DERIVES both sides from the same render instead of
# pinning literals: it reads the policy's `podSelector` and each named
# pod template's own pod-template labels, then evaluates one against the
# other. `satisfies` rows must be selected by the policy, `excluded`
# rows must not be. A selector whose `matchLabels` carry no release
# identity fails outright, and the `excluded` rows fail if the `Exists`
# clause is dropped — so neither clause can go missing with this green.
#
# Format:
# `<fixture>|<policy template>|<pod template>|satisfies|excluded|<human label>`.
selector_scope_checks() {
    cat <<'EOF'
test-values-cronjobs.yaml|templates/networkpolicy-migrate-job.yaml|templates/job-migrate.yaml|satisfies|the pre-install migrate Job — the pod this whole carve-out exists for — is still selected by the release-scoped policy
test-values-cronjobs.yaml|templates/networkpolicy-migrate-job.yaml|templates/svc-token-bootstrap-job.yaml|satisfies|the svc-token-bootstrap Job, which needs Postgres + the kube-apiserver while the app-pod deny-all is already active, is still selected
test-values-cronjobs.yaml|templates/networkpolicy-migrate-job.yaml|templates/prepull-job.yaml|satisfies|the pre-pull wait Job, which talks to the kube-apiserver before the Deployment exists, is still selected
test-values-cronjobs.yaml|templates/networkpolicy-migrate-job.yaml|templates/cronjob-scrub.yaml|satisfies|a scheduled CronJob's pod template is still selected — its labels nest a level deeper than a Job's, so this covers the CronJob shape too
test-values-cronjobs.yaml|templates/networkpolicy-migrate-job.yaml|templates/deployment.yaml|excluded|the app Deployment pods carry the SAME release labels as the Jobs and are kept out by the hort-server.io/job Exists clause alone — their deny-all egress must stay untouched
test-values-cronjobs.yaml|templates/networkpolicy-migrate-job.yaml|templates/worker-deployment.yaml|excluded|same for the worker pods: release labels present, no job key, so no unrestricted-egress allowance
EOF
}

failed=0
checked_fixtures=()

while IFS='|' read -r fixture pattern expected_count label; do
    [[ -z "${fixture}" ]] && continue
    fixture_path="${chart_dir}/${fixture}"

    if [[ ! -f "${fixture_path}" ]]; then
        echo "FAIL: fixture missing: ${fixture}" >&2
        failed=$((failed + 1))
        continue
    fi

    # Render once per fixture (cache the output across multiple
    # assertions on the same fixture).
    rendered_var="rendered_$(echo "${fixture}" | tr '.-' '__')"
    if [[ -z "${!rendered_var:-}" ]]; then
        if ! rendered=$(helm template hort-server "${chart_dir}" --namespace default -f "${fixture_path}" 2>&1); then
            echo "FAIL: helm template failed for ${fixture}:" >&2
            echo "${rendered}" | sed 's/^/    /' >&2
            failed=$((failed + 1))
            checked_fixtures+=("${fixture}")
            continue
        fi
        printf -v "${rendered_var}" '%s' "${rendered}"
        checked_fixtures+=("${fixture}")
    fi

    actual_count=$(printf '%s\n' "${!rendered_var}" | grep -cE "${pattern}" || true)

    if [[ "${actual_count}" -ne "${expected_count}" ]]; then
        echo "FAIL: ${fixture} → ${label}" >&2
        echo "    pattern: ${pattern}" >&2
        echo "    expected: ${expected_count} match(es)" >&2
        echo "    actual:   ${actual_count} match(es)" >&2
        failed=$((failed + 1))
    else
        echo "PASS: ${fixture} → ${label} (${actual_count} match(es))"
    fi
done < <(expectations)

# Process scoped expectations (see scoped_expectations() above) — each
# row renders only the named template via `--show-only` and asserts a
# pattern's match count within that template alone.
while IFS='|' read -r fixture tmpl pattern expected_count label; do
    [[ -z "${fixture}" ]] && continue
    fixture_path="${chart_dir}/${fixture}"

    if [[ ! -f "${fixture_path}" ]]; then
        echo "FAIL: fixture missing: ${fixture}" >&2
        failed=$((failed + 1))
        continue
    fi

    if ! rendered=$(helm template hort-server "${chart_dir}" --namespace default -f "${fixture_path}" --show-only "${tmpl}" 2>&1); then
        echo "FAIL: helm template --show-only ${tmpl} failed for ${fixture}:" >&2
        echo "${rendered}" | sed 's/^/    /' >&2
        failed=$((failed + 1))
        checked_fixtures+=("${fixture}")
        continue
    fi
    checked_fixtures+=("${fixture}")

    actual_count=$(printf '%s\n' "${rendered}" | grep -cE "${pattern}" || true)

    if [[ "${actual_count}" -ne "${expected_count}" ]]; then
        echo "FAIL: ${fixture} (${tmpl}) → ${label}" >&2
        echo "    pattern: ${pattern}" >&2
        echo "    expected: ${expected_count} match(es)" >&2
        echo "    actual:   ${actual_count} match(es)" >&2
        failed=$((failed + 1))
    else
        echo "PASS: ${fixture} (${tmpl}) → ${label} (${actual_count} match(es))"
    fi
done < <(scoped_expectations)

# Process render-failure expectations — fixtures that MUST fail to
# render (typically because they exercise an install-block schema
# rule). For each row, run `helm template` and assert it returns
# non-zero AND the error output contains the expected pattern.
while IFS='|' read -r fixture pattern label; do
    [[ -z "${fixture}" ]] && continue
    fixture_path="${chart_dir}/${fixture}"

    if [[ ! -f "${fixture_path}" ]]; then
        echo "FAIL: render-failure fixture missing: ${fixture}" >&2
        failed=$((failed + 1))
        continue
    fi

    if rendered_ok=$(helm template hort-server "${chart_dir}" --namespace default -f "${fixture_path}" 2>&1); then
        echo "FAIL: ${fixture} → ${label}" >&2
        echo "    expected helm template to FAIL (install-block) but it rendered successfully" >&2
        failed=$((failed + 1))
        checked_fixtures+=("${fixture}")
        continue
    fi

    # rendered_ok holds the stderr+stdout from the failed render.
    # Bounded: an install-blocked `helm template` render fails fast and
    # emits a short validation error, not a full chart render.
    if printf '%s\n' "${rendered_ok}" | grep -qE "${pattern}"; then
        echo "PASS: ${fixture} → ${label} (failed with expected pattern)"
        checked_fixtures+=("${fixture}")
    else
        echo "FAIL: ${fixture} → ${label}" >&2
        echo "    pattern: ${pattern}" >&2
        echo "    error output did not contain the expected pattern. Output was:" >&2
        printf '%s\n' "${rendered_ok}" | sed 's/^/    /' >&2
        failed=$((failed + 1))
        checked_fixtures+=("${fixture}")
    fi
done < <(expect_render_failure)

# Every version-bearing byte in these manifests derives from Chart.yaml's
# `version`/`appVersion` (chart label, app-version label, and the default
# image tag, which falls back to appVersion when image.tag is unset) — none
# of it is structural. Golden files pin rendering STRUCTURE, not the release
# number in flight when they were captured, so both sides of the diff go
# through this same substitution before comparing. Every other byte stays
# pinned verbatim.
normalize_chart_version() {
    sed -E \
        -e 's/(helm\.sh\/chart: hort-server-)[0-9][^ ]*/\1VERSION/' \
        -e 's/(app\.kubernetes\.io\/version: ")[^"]*/\1VERSION/' \
        -e 's#(image: "[^"]*/hort-server:)[^"]*#\1VERSION#'
}

# Process golden-file byte-equivalence checks (see golden_checks() above).
while IFS='|' read -r fixture tmpl golden label; do
    [[ -z "${fixture}" ]] && continue
    fixture_path="${chart_dir}/${fixture}"
    golden_path="${chart_dir}/${golden}"

    if [[ ! -f "${fixture_path}" ]]; then
        echo "FAIL: golden-check fixture missing: ${fixture}" >&2
        failed=$((failed + 1))
        continue
    fi
    if [[ ! -f "${golden_path}" ]]; then
        echo "FAIL: golden-check golden file missing: ${golden}" >&2
        failed=$((failed + 1))
        continue
    fi

    if ! rendered=$(helm template hort-server "${chart_dir}" --namespace default -f "${fixture_path}" --show-only "${tmpl}" 2>&1); then
        echo "FAIL: helm template --show-only ${tmpl} failed for ${fixture}:" >&2
        echo "${rendered}" | sed 's/^/    /' >&2
        failed=$((failed + 1))
        continue
    fi

    if diff_out=$(diff -u --label "${golden}" --label "rendered:${tmpl}" \
        <(normalize_chart_version <"${golden_path}") \
        <(printf '%s\n' "${rendered}" | normalize_chart_version)); then
        echo "PASS: ${fixture} → ${label}"
    else
        echo "FAIL: ${fixture} → ${label}" >&2
        echo "    rendered ${tmpl} does not byte-match ${golden}:" >&2
        printf '%s\n' "${diff_out}" | sed 's/^/    /' >&2
        failed=$((failed + 1))
    fi
done < <(golden_checks)

# Process the generic CronJob timeZone checks (see cronjob_timezone_checks()
# above): count CronJob documents and timeZone occurrences in the SAME
# render and assert they match, rather than pinning either count.
while IFS='|' read -r fixture expected_tz label; do
    [[ -z "${fixture}" ]] && continue
    fixture_path="${chart_dir}/${fixture}"

    if [[ ! -f "${fixture_path}" ]]; then
        echo "FAIL: fixture missing: ${fixture}" >&2
        failed=$((failed + 1))
        continue
    fi

    if ! rendered=$(helm template hort-server "${chart_dir}" --namespace default -f "${fixture_path}" 2>&1); then
        echo "FAIL: helm template failed for ${fixture}:" >&2
        echo "${rendered}" | sed 's/^/    /' >&2
        failed=$((failed + 1))
        checked_fixtures+=("${fixture}")
        continue
    fi
    checked_fixtures+=("${fixture}")

    cronjob_count=$(printf '%s\n' "${rendered}" | grep -cE '^kind: CronJob$' || true)
    timezone_count=$(printf '%s\n' "${rendered}" | grep -cF "timeZone: \"${expected_tz}\"" || true)

    if [[ "${cronjob_count}" -eq 0 ]]; then
        echo "FAIL: ${fixture} → ${label}" >&2
        echo "    fixture rendered NO CronJob documents — nothing was checked" >&2
        failed=$((failed + 1))
    elif [[ "${cronjob_count}" -ne "${timezone_count}" ]]; then
        echo "FAIL: ${fixture} → ${label}" >&2
        echo "    kind: CronJob documents: ${cronjob_count}" >&2
        echo "    timeZone: \"${expected_tz}\" occurrences: ${timezone_count}" >&2
        echo "    at least one rendered CronJob is missing the expected timeZone" >&2
        failed=$((failed + 1))
    else
        echo "PASS: ${fixture} → ${label} (${cronjob_count}/${cronjob_count} CronJobs)"
    fi
done < <(cronjob_timezone_checks)

# Print the `key: value` entries of the first `<block>:` mapping at or
# below the first line matching `<after>`: the lines strictly more
# indented than the block header, up to the first line that is not.
# Indentation-based, not a YAML parser — the suite has only helm and
# coreutils in CI, and it reads chart-rendered output whose shape these
# same assertions pin.
yaml_block_entries() {
    local after="$1" block="$2"
    awk -v after="${after}" -v block="${block}" '
        state == 0 && $0 ~ after { state = 1 }
        state == 1 && $0 ~ "^[[:space:]]*" block ":[[:space:]]*$" {
            match($0, /^[[:space:]]*/)
            indent = RLENGTH
            state = 2
            next
        }
        state == 2 {
            if ($0 ~ /^[[:space:]]*(#|$)/) next
            match($0, /^[[:space:]]*/)
            if (RLENGTH <= indent) { state = 3; next }
            entry = $0
            sub(/^[[:space:]]+/, "", entry)
            if (entry ~ /^-/) next
            print entry
        }
    '
}

# Print the label keys of the `podSelector.matchExpressions` entries
# whose operator is `Exists` (the rendered form is a `- key: <k>` line
# followed by an `operator: <op>` line).
selector_exists_keys() {
    awk '
        state == 0 && $0 ~ /^[[:space:]]*podSelector:[[:space:]]*$/ { state = 1; next }
        state == 1 && $0 ~ /^[[:space:]]*matchExpressions:[[:space:]]*$/ {
            match($0, /^[[:space:]]*/)
            indent = RLENGTH
            state = 2
            next
        }
        state == 2 {
            if ($0 ~ /^[[:space:]]*(#|$)/) next
            match($0, /^[[:space:]]*/)
            if (RLENGTH <= indent) { state = 3; next }
            if ($0 ~ /key:[[:space:]]*[^[:space:]]/) {
                pending = $0
                sub(/^.*key:[[:space:]]*/, "", pending)
            }
            if ($0 ~ /operator:[[:space:]]*Exists[[:space:]]*$/ && pending != "") {
                print pending
                pending = ""
            }
        }
    '
}

# Process the derived pod-selector scope checks (see
# selector_scope_checks() above): render the policy and the pod template
# from the same fixture, then evaluate the rendered `podSelector`
# against the rendered pod labels.
while IFS='|' read -r fixture policy_tmpl pod_tmpl verdict label; do
    [[ -z "${fixture}" ]] && continue
    fixture_path="${chart_dir}/${fixture}"

    if [[ ! -f "${fixture_path}" ]]; then
        echo "FAIL: fixture missing: ${fixture}" >&2
        failed=$((failed + 1))
        continue
    fi

    render_failed=0
    for tmpl in "${policy_tmpl}" "${pod_tmpl}"; do
        if ! out=$(helm template hort-server "${chart_dir}" --namespace default -f "${fixture_path}" --show-only "${tmpl}" 2>&1); then
            echo "FAIL: helm template --show-only ${tmpl} failed for ${fixture}:" >&2
            echo "${out}" | sed 's/^/    /' >&2
            render_failed=1
            break
        fi
        if [[ "${tmpl}" == "${policy_tmpl}" ]]; then
            policy_rendered="${out}"
        else
            pod_rendered="${out}"
        fi
    done
    checked_fixtures+=("${fixture}")
    if [[ "${render_failed}" -eq 1 ]]; then
        failed=$((failed + 1))
        continue
    fi

    match_labels=$(printf '%s\n' "${policy_rendered}" | yaml_block_entries '^[[:space:]]*podSelector:[[:space:]]*$' 'matchLabels')
    exists_keys=$(printf '%s\n' "${policy_rendered}" | selector_exists_keys)
    pod_labels=$(printf '%s\n' "${pod_rendered}" | yaml_block_entries '^[[:space:]]*template:[[:space:]]*$' 'labels')

    # The selector must carry a release identity at all. This is the
    # assertion whose absence let an existence-only selector ship: the
    # policy grants unrestricted egress, so without these labels it
    # selects any pod in the namespace carrying one label of its own
    # choosing, and a neighbouring release's Job pods besides.
    scope_ok=1
    for required in 'app\.kubernetes\.io/name' 'app\.kubernetes\.io/instance'; do
        # Bounded: match_labels holds one podSelector's matchLabels block —
        # the same handful of 63-char Kubernetes label lines, far under the
        # 64 KiB pipe buffer.
        if ! printf '%s\n' "${match_labels}" | grep -qE "^${required}: .+"; then
            echo "FAIL: ${fixture} (${policy_tmpl}) → podSelector.matchLabels carries no ${required//\\/}" >&2
            scope_ok=0
        fi
    done
    # An empty pod-label set would make every `excluded` row pass for
    # the wrong reason, so refuse to grade on one.
    if [[ -z "${pod_labels}" ]]; then
        echo "FAIL: ${fixture} (${pod_tmpl}) → no pod-template labels extracted; the scope check would be vacuous" >&2
        scope_ok=0
    fi
    if [[ "${scope_ok}" -eq 0 ]]; then
        echo "    the policy grants unrestricted egress (to: []), so its selector scope is load-bearing" >&2
        echo "    rendered podSelector.matchLabels:" >&2
        printf '%s\n' "${match_labels}" | sed 's/^/        /' >&2
        echo "    rendered pod-template labels (${pod_tmpl}):" >&2
        printf '%s\n' "${pod_labels}" | sed 's/^/        /' >&2
        failed=$((failed + 1))
        continue
    fi

    # Evaluate the selector: every matchLabel must be present verbatim
    # and every `Exists` key must be present at all.
    unmet=""
    while IFS= read -r entry; do
        [[ -z "${entry}" ]] && continue
        # Bounded: pod_labels holds one pod template's rendered labels. A
        # Kubernetes label is a 63-char key plus a 63-char value and a pod
        # template carries a handful, so this producer cannot approach the
        # 64 KiB pipe buffer that makes `| grep -q` lossy under pipefail.
        if ! printf '%s\n' "${pod_labels}" | grep -qxF "${entry}"; then
            unmet="${unmet}        missing matchLabel: ${entry}"$'\n'
        fi
    done <<<"${match_labels}"
    while IFS= read -r key; do
        [[ -z "${key}" ]] && continue
        # Bounded: as above — pod_labels is one pod template's label block,
        # so the producer finishes writing long before grep -q can exit.
        if ! printf '%s\n' "${pod_labels}" | grep -qE "^$(printf '%s' "${key}" | sed 's/[.[\*^$]/\\&/g'): "; then
            unmet="${unmet}        missing Exists key: ${key}"$'\n'
        fi
    done <<<"${exists_keys}"

    case "${verdict}" in
        satisfies)
            if [[ -z "${unmet}" ]]; then
                echo "PASS: ${fixture} (${policy_tmpl} vs ${pod_tmpl}) → ${label}"
            else
                echo "FAIL: ${fixture} (${policy_tmpl} vs ${pod_tmpl}) → ${label}" >&2
                echo "    the pod template is NOT selected by the policy:" >&2
                printf '%s' "${unmet}" >&2
                echo "    rendered pod-template labels:" >&2
                printf '%s\n' "${pod_labels}" | sed 's/^/        /' >&2
                failed=$((failed + 1))
            fi
            ;;
        excluded)
            if [[ -n "${unmet}" ]]; then
                echo "PASS: ${fixture} (${policy_tmpl} vs ${pod_tmpl}) → ${label}"
            else
                echo "FAIL: ${fixture} (${policy_tmpl} vs ${pod_tmpl}) → ${label}" >&2
                echo "    the pod template IS selected by the policy, which must not happen" >&2
                echo "    rendered podSelector.matchLabels:" >&2
                printf '%s\n' "${match_labels}" | sed 's/^/        /' >&2
                echo "    rendered podSelector Exists keys:" >&2
                printf '%s\n' "${exists_keys}" | sed 's/^/        /' >&2
                failed=$((failed + 1))
            fi
            ;;
        *)
            echo "FAIL: ${fixture} (${policy_tmpl} vs ${pod_tmpl}) → unknown verdict '${verdict}'; use satisfies or excluded" >&2
            failed=$((failed + 1))
            ;;
    esac
done < <(selector_scope_checks)

# Catch fixtures that have no expectations row — silently rendering
# without any assertion is a regression magnet (someone adds a fixture,
# forgets to add an assertion, the runner happily passes).
declare -A asserted
for f in "${checked_fixtures[@]}"; do
    asserted["${f}"]=1
done
unasserted=()
while IFS= read -r -d '' fixture_path; do
    name="$(basename "${fixture_path}")"
    # Skip the historical baseline files that predate this runner; they
    # are not feature-gated and have no assertion-worthy lines.
    case "${name}" in
        test-values-basic.yaml|test-values-ha.yaml|test-values.yaml) continue ;;
    esac
    if [[ -z "${asserted[${name}]:-}" ]]; then
        unasserted+=("${name}")
    fi
done < <(find "${chart_dir}" -maxdepth 1 -name 'test-values-*.yaml' -print0)

if [[ "${#unasserted[@]}" -gt 0 ]]; then
    echo "FAIL: fixtures with no expectations row in this script:" >&2
    for f in "${unasserted[@]}"; do
        echo "    ${f}" >&2
    done
    echo "    add an entry to expectations() above so the rendering state is locked." >&2
    failed=$((failed + 1))
fi

if [[ "${failed}" -gt 0 ]]; then
    echo >&2
    echo "${failed} chart-template assertion(s) failed." >&2
    exit 1
fi

echo "all chart-template assertions passed."
