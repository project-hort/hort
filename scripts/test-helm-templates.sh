#!/usr/bin/env bash
#
# scripts/test-helm-templates.sh — Helm chart render-assertion suite.
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
test-values-extra-ca-with-cm.yaml|extra-ca-bundle|9|Recipe A: server mount+vol (2) + worker mount+vol (2) + scrub mount+vol (2) + quarantineReleaseSweep mount+vol (2) + checksum annotation (1)
test-values-extra-ca-with-cm.yaml|defaultMode: 0444|4|Recipe A: read-only 0444 ConfigMap volume on server + worker + scrub + quarantineReleaseSweep
test-values-extra-ca-with-cm.yaml|checksum/extra-ca-bundle:|1|Pod-template checksum annotation rendered for the ConfigMap source
test-values-extra-ca-unset.yaml|HORT_EXTRA_CA_BUNDLE|0|env var NOT rendered when no auto-mount source set
test-values-extra-ca-unset.yaml|extra-ca-bundle|0|volume NOT rendered when no auto-mount source set
test-values-extra-ca-unset.yaml|checksum/extra-ca-bundle:|0|annotation NOT rendered when extraCaBundle unset
test-values-extra-ca-unset.yaml|defaultMode: 0444|0|extra-CA volume not rendered → no defaultMode
test-values-extra-ca-path-only.yaml|HORT_EXTRA_CA_BUNDLE|0|manual recipe: chart sets NO env (no auto-mount source ⇒ no chart-set env; operator sets it via extraEnv)
test-values-extra-ca-path-only.yaml|extra-ca-bundle|0|manual recipe: chart mounts NOTHING (no dangling volumeMount — the prior path-only cronjob volumeMount bug is fixed)
test-values-extra-ca-path-only.yaml|checksum/extra-ca-bundle:|0|annotation NOT rendered when no auto-mount source is set
test-values-extra-ca-with-secret.yaml|HORT_EXTRA_CA_BUNDLE|2|Recipe A-Secret: env var rendered on BOTH server + worker (secretName auto-mount ⇒ env set), symmetric with configMapName
test-values-extra-ca-with-secret.yaml|extra-ca-bundle|8|Recipe A-Secret: server mount+vol (2) + worker mount+vol (2) + scrub mount+vol (2) + quarantineReleaseSweep mount+vol (2); NO checksum annotation (Secret path)
test-values-extra-ca-with-secret.yaml|defaultMode: 0444|4|Recipe A-Secret: read-only 0444 Secret volume on server + worker + scrub + quarantineReleaseSweep
test-values-extra-ca-with-secret.yaml|checksum/extra-ca-bundle:|0|Recipe A-Secret: no checksum annotation for the Secret source (Secret updates propagate via Kubernetes, not via helm-upgrade re-render)
test-values-extra-ca-with-secret.yaml|corporate-ca-bundle-secret|4|Recipe A-Secret: the Secret name renders in the volume secretName on server + worker + scrub + quarantineReleaseSweep
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
test-values-cronjobs.yaml|^kind: CronJob$|11|eleven CronJobs render — the nine scheduledTasks.adminTasksEnabled-gated admin-task entries (noop, staging-sweep, cron-rescan-tick, advisory-watch-tick, eventstore-checkpoint, replay-seen-prune, retention-evaluate, retention-purge, eventstore-archive) PLUS the always-on dsn-direct quarantineReleaseSweep (gated on scheduledTasks.quarantineReleaseSweep.enabled, default true) PLUS the always-on dsn-direct CAS scrub (gated on scheduledTasks.scrub.enabled, default true). wheelMetadataBackfill stays default-disabled and does NOT count.
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
test-values-cronjobs.yaml|^  concurrencyPolicy: Forbid$|11|every CronJob (incl. the 3 retention + the always-on quarantineReleaseSweep + the always-on scrub) sets concurrencyPolicy: Forbid (single-active layer 1; worker semaphore is layer 2)
test-values-cronjobs.yaml|name: hort-server-job-bootstrap-egress$|1|additive Job-scoped bootstrap-egress NetworkPolicy renders when networkPolicy.enabled (chart default true)
test-values-cronjobs.yaml|^kind: NetworkPolicy$|2|BOTH the app-pod NetworkPolicy and the additive Job-scoped policy render with the chart-default networkPolicy.enabled: true
test-values-cronjobs.yaml|key: hort-server.io/job|1|the Job-scoped policy selects by the hort-server.io/job label Exists (never the app pods)
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
test-values-strict-schema-typo.yaml|Additional property|the strict schema (additionalProperties:false on the top-level + every nested block) must REJECT mistyped / retired keys (replicaCountt, apiBindAddr, http.ociUploadTimeoutSeconds, worker.scanner.osvScanner, worker.scanner.osvv) at helm template instead of silently ignoring them
test-values-worker-metrics-no-scrapers.yaml|scrapeFrom|worker.metrics.enabled=true with an empty scrapeFrom must be rejected — an empty NetworkPolicy `from: []` means ALL sources (fail-OPEN) per the k8s spec, so the schema's `if enabled then scrapeFrom minItems 1` rule must fail the render rather than open the metrics port cluster-wide
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
        if ! rendered=$(helm template hort-server "${chart_dir}" -f "${fixture_path}" 2>&1); then
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

    if rendered_ok=$(helm template hort-server "${chart_dir}" -f "${fixture_path}" 2>&1); then
        echo "FAIL: ${fixture} → ${label}" >&2
        echo "    expected helm template to FAIL (install-block) but it rendered successfully" >&2
        failed=$((failed + 1))
        checked_fixtures+=("${fixture}")
        continue
    fi

    # rendered_ok holds the stderr+stdout from the failed render.
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
