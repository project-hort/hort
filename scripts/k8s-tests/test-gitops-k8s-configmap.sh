#!/usr/bin/env bash
# Smoke test: gitops boot loads files from a Kubernetes ConfigMap mount.
#
# WHY THIS TEST EXISTS
#
# The chart's `gitopsConfig:` value renders a ConfigMap; the
# Deployment mounts it at `HORT_CONFIG_DIR` (`/etc/hort-server/config`).
# Kubernetes projects ConfigMap volume mounts through a two-level
# symlink atomic-update pattern (`..data` → `..<timestamp>/`, then
# top-level keys as symlinks into `..data/`). The binary's gitops
# boot walker MUST follow those symlinks; commit 243c9b0 fixed a
# regression where it didn't, surfacing as `files_loaded: 0` against
# a correctly-projected mount.
#
# `scripts/native-tests/scenarios/gitops/gitops.sh` runs against
# `deploy/compose/docker-compose.yml`, which mounts a regular directory —
# no symlinks, no projection-shape coverage. This script is the
# kind-cluster sibling that exercises the production-shape mount.
#
# WHAT THIS TEST ASSERTS
#
#   1. The runtime pod's gitops-boot tracing line reports
#      `files_loaded: N` with N > 0.
#   2. The apply-succeeded tracing line is present
#      (`gitops boot: apply succeeded`).
#   3. (Optional, when METRICS_URL is set) the
#      `hort_gitops_apply_total{result="ok"}` counter is non-zero.
#
# Failure mode this catches (regression of commit 243c9b0):
#   `gitops boot: directory walk complete files_loaded=0`
#
# WHAT THIS TEST DOES NOT DO
#
# It does not stand up the kind cluster, install Postgres, build /
# load images, or `helm install` the chart. The operator runs that prep
# first; this script is invoked AFTER `kubectl rollout status deploy/...`
# reports the runtime pod is Ready.
#
# USAGE
#
#   ./test-gitops-k8s-configmap.sh \
#       [--release hort-server] \
#       [--namespace hort] \
#       [--kubeconfig /path/to/config] \
#       [--context my-cluster]
#
# Cluster targeting (most-specific wins; standard kubectl rules):
#   1. `--kubeconfig PATH` flag — exports KUBECONFIG for the run.
#   2. `KUBECONFIG=...` env var on the script invocation.
#   3. `~/.kube/config` (kubectl default).
#
#   Within the chosen kubeconfig:
#   1. `--context NAME` flag — pinned to every kubectl call.
#   2. The kubeconfig's `current-context`.
#
# Why explicit cluster targeting matters: operators commonly have
# `kubectl` configured against a default cluster that is NOT the
# hort-server test cluster. With no `--kubeconfig` / `--context` and
# no `KUBECONFIG` env override, the script would happily probe the
# wrong cluster — which at best surfaces as "no Running pod matched
# selector" against the wrong namespace, and at worst times out
# against an unreachable cluster.
#
# Or call after a helm install verify step:
#
#   helm install hort-server deploy/helm/hort-server/ \
#       -f my-values.yaml \
#       --set 'gitopsConfig.auth/admins\.yaml=...' \
#       --set 'gitopsConfig.repositories/npm-public\.yaml=...'
#   kubectl rollout status deploy/hort-server-hort-server --timeout=120s
#   KUBECONFIG=/path/to/cluster.kubeconfig \
#     ./scripts/k8s-tests/test-gitops-k8s-configmap.sh
#
# EXAMPLE GITOPSCONFIG (paste into your operator values.yaml to
# exercise the projection layout — two top-level subdirs gives the
# walker two visible symlinks to follow):
#
#   gitopsConfig:
#     "auth/admins.yaml": |
#       apiVersion: project-hort.de/v1beta1
#       kind: GroupMapping
#       metadata:
#         name: admins
#       spec:
#         group: hort-admins
#         role: admin
#     "repositories/npm-public.yaml": |
#       apiVersion: project-hort.de/v1beta1
#       kind: ArtifactRepository
#       metadata:
#         name: npm-public
#       spec:
#         name: "npm Public Mirror"
#         format: npm
#         type: proxy
#         storage:
#           backend: filesystem
#           path: /var/lib/hort-server/cas/npm-public
#         proxy:
#           upstreamUrl: "https://registry.npmjs.org"
#         isPublic: true
#         replicationPriority: immediate

set -euo pipefail

RELEASE="hort-server"
NAMESPACE="hort"
METRICS_URL="${METRICS_URL:-}"
KUBECONFIG_OVERRIDE=""
CONTEXT_OVERRIDE=""

while (( $# )); do
    case "$1" in
        --release)    RELEASE="$2";            shift 2 ;;
        --namespace)  NAMESPACE="$2";          shift 2 ;;
        --kubeconfig) KUBECONFIG_OVERRIDE="$2"; shift 2 ;;
        --context)    CONTEXT_OVERRIDE="$2";   shift 2 ;;
        --help|-h)
            sed -n '1,/^set -euo pipefail/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "unknown arg: $1" >&2
            exit 2
            ;;
    esac
done

# Apply --kubeconfig as KUBECONFIG export so child kubectl
# invocations inherit it (more reliable than threading
# `--kubeconfig=PATH` through every call). The export is local to
# this script's process tree.
if [[ -n "$KUBECONFIG_OVERRIDE" ]]; then
    if [[ ! -f "$KUBECONFIG_OVERRIDE" ]]; then
        echo "FAIL: --kubeconfig path does not exist: $KUBECONFIG_OVERRIDE"
        exit 1
    fi
    export KUBECONFIG="$KUBECONFIG_OVERRIDE"
fi

# Wrapper so every kubectl invocation in the script picks up the
# --context flag uniformly. Bash arrays handle the empty case
# cleanly: with CONTEXT_OVERRIDE unset, KUBECTL_CTX_OPTS expands to
# zero arguments and the wrapper degrades to a plain `kubectl` call.
KUBECTL_CTX_OPTS=()
if [[ -n "$CONTEXT_OVERRIDE" ]]; then
    KUBECTL_CTX_OPTS=(--context "$CONTEXT_OVERRIDE")
fi
kc() { kubectl "${KUBECTL_CTX_OPTS[@]}" "$@"; }

echo "==> gitops K8s-ConfigMap projection smoke"
echo "    release:    $RELEASE"
echo "    namespace:  $NAMESPACE"

# ---- 0. Preflight checks ---------------------------------------------------
# Catch the obvious "this won't work" cases up-front with explicit
# error messages instead of letting later commands fail in
# confusing ways (e.g. `kubectl: command not found` swallowed by a
# `2>/dev/null` on a downstream invocation).

if ! command -v kubectl >/dev/null 2>&1; then
    echo "FAIL: kubectl not found in PATH"
    echo "      install kubectl: https://kubernetes.io/docs/tasks/tools/#kubectl"
    exit 1
fi

# Resolve and print the kubeconfig path actually in effect. With
# --kubeconfig set this is KUBECONFIG_OVERRIDE; otherwise whatever
# the env var or kubectl default points at. The print is critical
# for the "configured against another cluster" failure mode — an
# operator scanning the output sees the path and recognises it as
# wrong.
KCFG_PATH="${KUBECONFIG:-$HOME/.kube/config}"
echo "    kubeconfig: $KCFG_PATH"

# Print the context being targeted — either the --context override
# or the kubeconfig's current-context. Operators spotting "wrong
# context" failures recognise it here before the script wastes time
# probing the wrong cluster.
if [[ -n "$CONTEXT_OVERRIDE" ]]; then
    CTX="$CONTEXT_OVERRIDE"
else
    CTX="$(kc config current-context 2>/dev/null || true)"
    if [[ -z "$CTX" ]]; then
        echo "FAIL: no current kubeconfig context"
        echo "      kubeconfig: $KCFG_PATH"
        echo "      Pick a context explicitly:"
        echo "          $0 --context <name>"
        echo "      or set kubectl's default:"
        echo "          kubectl config use-context <name>"
        echo "      Available contexts in this kubeconfig:"
        kc config get-contexts -o name 2>/dev/null \
            | sed 's/^/          /' || echo "          (none — kubeconfig empty?)"
        exit 1
    fi
fi
echo "    context:    $CTX"

# Confirm the API server is reachable. `kubectl version` makes a
# round-trip so we catch unreachable-cluster cases here rather than
# as a hung kubectl-get below.
if ! kc version --request-timeout=5s >/dev/null 2>&1; then
    echo "FAIL: cannot reach the Kubernetes API server"
    echo "      kubeconfig: $KCFG_PATH"
    echo "      context:    $CTX"
    echo "      Try: kubectl --context $CTX cluster-info"
    exit 1
fi

# Namespace must exist; an absent namespace produces empty
# `get pod` output that's indistinguishable from "no matching pod"
# without this check.
if ! kc get namespace "$NAMESPACE" >/dev/null 2>&1; then
    echo "FAIL: namespace '$NAMESPACE' does not exist on context '$CTX'"
    echo "      Available namespaces:"
    kc get namespace -o name | sed 's|^namespace/|        |'
    echo "      Override with --namespace <name>."
    exit 1
fi

# ---- 1. Locate the runtime pod ----------------------------------------------
# `kubectl logs` against the Deployment grabs from one of its pods,
# but during a recent rollout there can be old pods carrying stale
# logs. Pin to a single Ready pod by selector + status filter so the
# log scan is deterministic.
POD="$(
    kc --namespace "$NAMESPACE" get pod \
        -l "app.kubernetes.io/name=hort-server,app.kubernetes.io/instance=$RELEASE" \
        --field-selector=status.phase=Running \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true
)"

if [[ -z "$POD" ]]; then
    echo "FAIL: no Running pod matched selector"
    echo "      app.kubernetes.io/name=hort-server"
    echo "      app.kubernetes.io/instance=$RELEASE"
    echo "      in namespace '$NAMESPACE' on context '$CTX'"
    echo
    echo "What IS in the namespace right now:"
    kc --namespace "$NAMESPACE" get pods --show-labels 2>&1 \
        | sed 's/^/    /' || true
    echo
    echo "If the release name is not 'hort-server', re-run with:"
    echo "    $0 --release <name> --namespace $NAMESPACE"
    echo "Or check rollout status:"
    echo "    kubectl --context $CTX --namespace $NAMESPACE rollout status deploy/${RELEASE}-hort-server"
    exit 1
fi
echo "    pod:        $POD"

# ---- 2. Scan boot logs for the gitops walk + apply lines --------------------
LOGS="$(kc --namespace "$NAMESPACE" logs "$POD" --container hort-server)"

# 2a. Walk-complete line — the regression target. Format from
#     gitops_boot.rs:
#         tracing::info!(
#             config_dir = %config_dir.display(),
#             files_loaded = files.len(),
#             "gitops boot: directory walk complete"
#         );
#     The tracing layer renders this with `files_loaded=N` (no space)
#     in pretty mode and `"files_loaded":N` in JSON mode; the regex
#     covers both.
WALK_LINE="$(grep -E 'gitops boot: directory walk complete' <<<"$LOGS" | tail -1 || true)"
if [[ -z "$WALK_LINE" ]]; then
    echo "FAIL: no 'gitops boot: directory walk complete' log line"
    echo "      The boot apply may not have run — check HORT_CONFIG_DIR"
    echo "      is wired in the Deployment (it should be '/etc/hort-server/config')"
    echo "      and that the chart's gitopsConfig values are non-empty."
    exit 1
fi

FILES_LOADED="$(grep -oE 'files_loaded["= ]*([0-9]+)' <<<"$WALK_LINE" | grep -oE '[0-9]+$' || true)"
if [[ -z "$FILES_LOADED" ]]; then
    echo "FAIL: could not parse files_loaded from log line"
    echo "      raw line: $WALK_LINE"
    exit 1
fi

if [[ "$FILES_LOADED" -lt 1 ]]; then
    echo "FAIL: files_loaded=$FILES_LOADED — the walker found ZERO"
    echo "      YAML files under HORT_CONFIG_DIR. This is the exact"
    echo "      symptom of the K8s ConfigMap-projection regression"
    echo "      (commit 243c9b0). Verify:"
    echo "       1. The chart was installed with a non-empty gitopsConfig:"
    echo "            helm get values $RELEASE -n $NAMESPACE | grep -A20 gitopsConfig"
    echo "       2. The ConfigMap was rendered with the expected keys:"
    echo "            kubectl -n $NAMESPACE get cm ${RELEASE}-hort-server-config -o yaml"
    echo "       3. The mount projects them inside the pod:"
    echo "            kubectl -n $NAMESPACE exec $POD -- ls -la /etc/hort-server/config/"
    echo "          You should see top-level entries (symlinks) for each"
    echo "          subdirectory key in gitopsConfig."
    echo "       4. The binary contains the symlink-following fix —"
    echo "          image SHA must include commit 243c9b0 or later."
    exit 1
fi
echo "    PASS files_loaded=$FILES_LOADED (> 0)"

# 2b. Apply-succeeded line — confirms the per-envelope writes
#     reached the DB and the apply transaction committed.
if ! grep -qE 'gitops boot: apply succeeded' <<<"$LOGS"; then
    echo "FAIL: walk completed but no 'gitops boot: apply succeeded' line"
    echo "      Apply may have failed mid-flight; scan logs for"
    echo "      'gitops boot: parse failed' or 'apply failed' near"
    echo "      the walk-complete line."
    echo
    echo "Tail of pod logs for triage:"
    echo "$LOGS" | tail -40
    exit 1
fi
echo "    PASS apply succeeded"

# ---- 3. Optional metric scrape ---------------------------------------------
# When the operator's deployment exposes /metrics with admin auth,
# scrape and assert hort_gitops_apply_total{result="ok"} ticked. The
# chart binds /metrics to the loopback dedicated listener by default
# (metrics.bindAddr: "127.0.0.1:9090"), so this only runs when the
# caller has wired a port-forward / service-monitor / sidecar that
# exposes the surface.
if [[ -n "$METRICS_URL" ]]; then
    echo "==> Optional metric scrape: $METRICS_URL"
    SCRAPE="$(curl -fsS "$METRICS_URL" || true)"
    if [[ -z "$SCRAPE" ]]; then
        echo "    SKIP: METRICS_URL set but scrape returned empty"
        echo "          (auth gate? port-forward not running?)"
    else
        OK_LINE="$(
            grep -E '^hort_gitops_apply_total\{[^}]*result="ok"[^}]*\} ' <<<"$SCRAPE" | tail -1 || true
        )"
        if [[ -z "$OK_LINE" ]]; then
            echo "FAIL: hort_gitops_apply_total{result=\"ok\"} not present"
            echo "      Apply may have run but not emitted the metric."
            exit 1
        fi
        OK_VALUE="$(awk '{print $NF}' <<<"$OK_LINE")"
        echo "    PASS hort_gitops_apply_total{result=\"ok\"} = $OK_VALUE"
    fi
fi

echo "==> All assertions passed."
