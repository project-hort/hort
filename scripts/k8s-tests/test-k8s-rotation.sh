#!/usr/bin/env bash
# ServiceAccount fallback PAT-rotation e2e smoke against a real kind
# (Kubernetes-in-Docker) cluster.
#
# This test is NOT part of the default smoke profile — it requires kind +
# kubectl + helm + docker and ~5 minutes of runtime (~30 s kind cluster
# spin-up, ~60 s Helm install, ~120 s for the rotation CronJob to tick).
# Run on demand:
#   ./scripts/k8s-tests/test-k8s-rotation.sh
# Run directly:
#   bash scripts/k8s-tests/test-k8s-rotation.sh
#
# What it validates (end-to-end):
#
#  1. The Helm chart renders + installs in a real cluster with rotation
#     enabled. Per-namespace RBAC (templates/svc-rotation-rbac.yaml)
#     binds the hort-worker SA to each `worker.rotation.targetNamespaces`
#     entry with verbs `get,list,create,update,patch` on `secrets`.
#  2. The rotation CronJob (`scheduledTasks.serviceAccountRotation.enabled =
#     true`) is created and runs on the configured schedule.
#  3. The CronJob's Job fires `hort-cli admin task service-account-rotation`,
#     which triggers `ServiceAccountRotationHandler::run` in the
#     hort-worker. The handler mints a fresh token and upserts the target
#     Secret in the namespace declared by
#     `ServiceAccount.spec.fallbackRotation.targetSecret.namespace`.
#  4. The resulting managed Secret carries the canonical labels
#     (`project-hort.de/managed-by=hort-worker`, `project-hort.de/service-account=<sa-name>`,
#     `project-hort.de/token-id=<uuid>`) plus the canonical annotation
#     `project-hort.de/last-rotated=<rfc3339>` (annotation rather than label
#     because RFC 3339 timestamps contain `:`, which k8s forbids in
#     label values), and the data field shape matches the declared
#     format (dockerconfigjson: `.dockerconfigjson` key with
#     `auths.<host>.password` populated).
#
# This test is intentionally NOT CI-required: the existing CI lane doesn't
# have a kind cluster, and the runtime budget exceeds the smoke-profile
# target. It exists for local operator verification and for a future
# addition of kind to CI.
#
# Per CLAUDE.md memory rule: host ports in the 25xxx range.

set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-hort-init39-rotation-test}"
NAMESPACE="${NAMESPACE:-hort-server}"
TARGET_NAMESPACE="${TARGET_NAMESPACE:-ci-system}"
SA_NAME="${SA_NAME:-ci-pypi-pusher}"
SECRET_NAME="${SECRET_NAME:-ci-hort-token}"
PUBLIC_REGISTRY_HOST="${PUBLIC_REGISTRY_HOST:-registry.kind.local}"
ROTATION_TIMEOUT_SECS="${ROTATION_TIMEOUT_SECS:-90}"
# Postgres image, pulled by the kind node (proven reachable). Override
# only to pin a different tag; a host-only tag will not resolve since
# the node pulls it itself.
POSTGRES_IMAGE="${POSTGRES_IMAGE:-postgres:16-alpine}"
# Readiness budget for the ephemeral postgres pod. The previous bare
# 60s was tight on a machine that had just done a 5–15 min hort-worker
# build (cold disk cache, busy CPU); raised + made overridable so a
# slow-but-healthy start is not misreported as a failure.
POSTGRES_READY_TIMEOUT_SECS="${POSTGRES_READY_TIMEOUT_SECS:-150}"
KEEP_CLUSTER="${KEEP_CLUSTER:-}"

CHART_DIR="${CHART_DIR:-deploy/helm/hort-server}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

WORK_DIR=""

# Throwaway kubeconfig pinned to the kind cluster. Exported into the
# environment so EVERY downstream kubectl + helm invocation targets this
# cluster only — the operator's normal `~/.kube/config` is never read or
# touched, and a stray `kubectl config use-context X` in another terminal
# cannot redirect this script's destructive operations to a different
# cluster.
KIND_KUBECONFIG=""

cleanup() {
    if [ -n "${KEEP_CLUSTER}" ]; then
        echo "--keep flag set: skipping cluster teardown."
        echo "Cluster name: ${CLUSTER_NAME}"
        echo "To delete: kind delete cluster --name ${CLUSTER_NAME}"
        if [ -n "${KIND_KUBECONFIG}" ] && [ -f "${KIND_KUBECONFIG}" ]; then
            echo "Kubeconfig:   ${KIND_KUBECONFIG}"
            echo "To use:       export KUBECONFIG=${KIND_KUBECONFIG}"
        fi
    else
        if command -v kind >/dev/null 2>&1; then
            if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
                echo "Deleting kind cluster ${CLUSTER_NAME}..."
                kind delete cluster --name "${CLUSTER_NAME}" >/dev/null 2>&1 || true
            fi
        fi
        if [ -n "${KIND_KUBECONFIG}" ] && [ -f "${KIND_KUBECONFIG}" ]; then
            rm -f "${KIND_KUBECONFIG}"
        fi
    fi
    if [ -n "${WORK_DIR}" ] && [ -d "${WORK_DIR}" ]; then
        rm -rf "${WORK_DIR}"
    fi
}
trap cleanup EXIT INT TERM

# --clean does cleanup-only — same behaviour as the trap above.
if [ "${1:-}" = "--clean" ]; then
    echo "Cleanup-only mode. The EXIT trap will tidy the workspace and cluster."
    exit 0
fi

# --keep skips the cluster teardown so the operator can poke at the
# rendered manifests / Secrets after the test exits.
# --rebuild forces a docker build for both images even if they already
# exist in the local docker daemon.
REBUILD_IMAGES=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --keep)    KEEP_CLUSTER="1"; shift ;;
        --rebuild) REBUILD_IMAGES="1"; shift ;;
        *)         break ;;
    esac
done

# -- Preflight ---------------------------------------------------------

require() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "MISSING: '$cmd' not found in PATH."
        echo
        echo "Install hints (Linux):"
        echo "  kubectl: https://kubernetes.io/docs/tasks/tools/"
        echo "  helm:    https://helm.sh/docs/intro/install/"
        echo "  docker:  https://docs.docker.com/get-docker/"
        exit 2
    fi
}

# kind is a single static Go binary — auto-downloaded to a cache dir if
# absent, so operators don't need to pre-install it. Docker still has to
# be installed and running (kind orchestrates docker, doesn't replace it).
KIND_VERSION="${KIND_VERSION:-v0.27.0}"
# Version-scoped dir so the binary inside can keep the canonical name `kind`
# (otherwise `command -v kind` post-PATH-prepend wouldn't find it).
KIND_CACHE_DIR="${TMPDIR:-/tmp}/hort-kind-cache/${KIND_VERSION}"
KIND_BIN="${KIND_CACHE_DIR}/kind"

ensure_kind() {
    if command -v kind >/dev/null 2>&1; then
        return 0
    fi
    if [ ! -x "${KIND_BIN}" ]; then
        case "$(uname -s)" in
            Linux)  kind_os="linux" ;;
            Darwin) kind_os="darwin" ;;
            *)      echo "MISSING: unsupported OS '$(uname -s)' for kind auto-install."; exit 2 ;;
        esac
        case "$(uname -m)" in
            x86_64|amd64) kind_arch="amd64" ;;
            arm64|aarch64) kind_arch="arm64" ;;
            *)            echo "MISSING: unsupported arch '$(uname -m)' for kind auto-install."; exit 2 ;;
        esac
        mkdir -p "${KIND_CACHE_DIR}"
        echo "==> kind not on PATH — downloading ${KIND_VERSION} (${kind_os}/${kind_arch}) to ${KIND_BIN}"
        curl -fsSL -o "${KIND_BIN}" \
            "https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-${kind_os}-${kind_arch}"
        chmod +x "${KIND_BIN}"
    fi
    export PATH="${KIND_CACHE_DIR}:${PATH}"
}

echo "==> Preflight: checking required binaries..."
ensure_kind
require kind
require kubectl
require helm
require docker

if ! docker info >/dev/null 2>&1; then
    echo "MISSING: docker daemon not reachable."
    echo "Start Docker (or its replacement: podman, colima, etc.) and re-run."
    exit 2
fi

echo "==> Preflight: OK (kind + kubectl + helm + docker available)."

# -- Cluster setup -----------------------------------------------------
#
# We write the kind cluster's credentials to a throwaway KUBECONFIG file
# and export it for the rest of the script. This isolates the smoke from
# the operator's normal kubeconfig: no merge, no current-context change,
# no risk of a parallel `kubectl config use-context X` redirecting our
# destructive kubectl operations.

KIND_KUBECONFIG="$(mktemp -t hort-init39-kubeconfig.XXXXXX)"
export KUBECONFIG="${KIND_KUBECONFIG}"

echo "==> Creating kind cluster ${CLUSTER_NAME}..."
echo "    KUBECONFIG=${KIND_KUBECONFIG} (throwaway — operator's ~/.kube/config untouched)"
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    echo "Cluster ${CLUSTER_NAME} already exists — deleting first for a clean run."
    kind delete cluster --name "${CLUSTER_NAME}" >/dev/null
fi

kind create cluster --name "${CLUSTER_NAME}" --kubeconfig "${KIND_KUBECONFIG}" --wait 60s

# Sanity: the freshly-minted kubeconfig should point at the kind cluster
# we just created. Refuse to proceed if the current-context is anything
# else (defence-in-depth — kind populates this correctly but we don't
# want to discover a config-merge surprise mid-deploy).
CURRENT_CONTEXT="$(kubectl config current-context 2>/dev/null || true)"
if [ "${CURRENT_CONTEXT}" != "kind-${CLUSTER_NAME}" ]; then
    echo "REFUSING: KUBECONFIG current-context is '${CURRENT_CONTEXT}', expected 'kind-${CLUSTER_NAME}'."
    echo "Aborting before any destructive operation."
    exit 3
fi

kubectl cluster-info >/dev/null

# -- Image build + load ------------------------------------------------
#
# We need TWO local images inside the cluster: hort-server (also runs
# hort-cli) and hort-worker (separate Deployment, bundles Trivy +
# osv-scanner). The smoke targets uncommitted / unpublished changes,
# so the script BUILDS them from the repo's Dockerfiles instead of
# pulling from a registry.
#
# Behaviour per image:
#   - present in local docker AND --rebuild not set ⇒ reuse, just
#     kind-load it
#   - missing OR --rebuild set ⇒ docker build, then kind-load
#
# Build time on a cold cache is ~5–15 min for hort-worker (Trivy +
# osv-scanner + Rust release build); hort-server is faster. Repeated
# runs hit the layer cache and are near-instant.
#
# Default repo/tag matches the chart's `image.repository` shape with a
# `:dev` tag. Override via env vars to test against a specific local
# tag (e.g. one your IDE produces).

HORT_SERVER_IMAGE_REPO="${HORT_SERVER_IMAGE_REPO:-${HORT_IMAGE_REPO:-hort/hort-server}}"
HORT_SERVER_IMAGE_TAG="${HORT_SERVER_IMAGE_TAG:-${HORT_IMAGE_TAG:-dev}}"
HORT_WORKER_IMAGE_REPO="${HORT_WORKER_IMAGE_REPO:-hort/hort-worker}"
HORT_WORKER_IMAGE_TAG="${HORT_WORKER_IMAGE_TAG:-${HORT_SERVER_IMAGE_TAG}}"

ensure_image_in_cluster() {
    local repo="$1"
    local tag="$2"
    local dockerfile="$3"
    local image="${repo}:${tag}"

    local need_build=""
    if [ -n "${REBUILD_IMAGES}" ]; then
        need_build="rebuild requested"
    elif ! docker image inspect "${image}" >/dev/null 2>&1; then
        need_build="image absent from local docker"
    fi

    if [ -n "${need_build}" ]; then
        if [ ! -f "${REPO_ROOT}/${dockerfile}" ]; then
            echo "MISSING: ${REPO_ROOT}/${dockerfile} does not exist." >&2
            echo "Cannot build '${image}'. Provide the image manually or pass --rebuild after a checkout that has it." >&2
            exit 2
        fi
        echo "    building ${image} (${need_build})..."
        echo "    Dockerfile: ${dockerfile}"
        # `docker build` output goes to stderr — preserve it so a real
        # build failure (compile error, etc.) is visible.
        (cd "${REPO_ROOT}" && docker build -t "${image}" -f "${dockerfile}" .)
    fi

    echo "    loading ${image} into kind cluster..."
    kind load docker-image "${image}" --name "${CLUSTER_NAME}" >/dev/null
}

echo "==> Building + loading images into the kind cluster (hort-server + hort-worker)..."
ensure_image_in_cluster "${HORT_SERVER_IMAGE_REPO}" "${HORT_SERVER_IMAGE_TAG}" "docker/Dockerfile.hort-server"
ensure_image_in_cluster "${HORT_WORKER_IMAGE_REPO}" "${HORT_WORKER_IMAGE_TAG}" "docker/Dockerfile.worker"

echo "==> Server image: ${HORT_SERVER_IMAGE_REPO}:${HORT_SERVER_IMAGE_TAG}"
echo "==> Worker image: ${HORT_WORKER_IMAGE_REPO}:${HORT_WORKER_IMAGE_TAG}"

# Back-compat aliases used by the values heredoc below.
HORT_IMAGE_REPO="${HORT_SERVER_IMAGE_REPO}"
HORT_IMAGE_TAG="${HORT_SERVER_IMAGE_TAG}"

# -- Postgres bootstrap ------------------------------------------------
#
# The hort-server chart does NOT provision its own postgres — it requires
# `postgres.app.existingSecret` and `postgres.admin.existingSecret`
# pointing at operator-provided secrets. For this smoke we deploy a
# minimal single-pod postgres alongside hort-server and create the two
# existing-secret refs the chart consumes. This is a smoke-test
# postgres — no persistence, no HA, no backups — adequate for a 5-min
# rotation test.

kubectl create namespace "${NAMESPACE}" >/dev/null 2>&1 || true
kubectl create namespace "${TARGET_NAMESPACE}" >/dev/null 2>&1 || true

echo "==> Deploying ephemeral postgres for the smoke..."
kubectl -n "${NAMESPACE}" apply -f - <<EOF >/dev/null
apiVersion: v1
kind: Secret
metadata:
  name: hort-postgres-bootstrap
type: Opaque
stringData:
  POSTGRES_USER: hort
  POSTGRES_PASSWORD: hort-smoke-test
  POSTGRES_DB: hort
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
  labels: { app: postgres }
spec:
  replicas: 1
  selector: { matchLabels: { app: postgres } }
  template:
    metadata: { labels: { app: postgres } }
    spec:
      containers:
        - name: postgres
          # Pulled by the kind node (proven reachable: run 1 pulled this
          # fine). NOT host-kind-loaded — substituting a possibly-stale
          # host-cached image for the node-pulled one correlated with a
          # postgres CrashLoopBackOff regression, so that path was reverted.
          image: ${POSTGRES_IMAGE}
          envFrom:
            - secretRef: { name: hort-postgres-bootstrap }
          ports:
            - containerPort: 5432
          readinessProbe:
            exec: { command: ["pg_isready", "-U", "hort", "-d", "hort"] }
            initialDelaySeconds: 2
            periodSeconds: 2
---
apiVersion: v1
kind: Service
metadata: { name: postgres }
spec:
  selector: { app: postgres }
  ports: [{ port: 5432, targetPort: 5432 }]
EOF

# Wait for postgres to be ready before installing hort-server. On
# timeout, dump pod state + describe + events BEFORE the EXIT trap
# deletes the cluster — a bare `kubectl wait` failure here was
# previously as unactionable as a CrashLoopBackOff with no logs
# (ImagePull vs. resource/disk pressure vs. a too-tight deadline are
# indistinguishable without this).
echo "    waiting for postgres pod (timeout ${POSTGRES_READY_TIMEOUT_SECS}s)..."
if ! kubectl -n "${NAMESPACE}" wait --for=condition=ready pod \
        -l app=postgres --timeout="${POSTGRES_READY_TIMEOUT_SECS}s" >/dev/null; then
    echo "FAIL: postgres pod not Ready within ${POSTGRES_READY_TIMEOUT_SECS}s." >&2
    echo
    echo "--- pods (postgres) ---"
    kubectl -n "${NAMESPACE}" get pods -l app=postgres -o wide 2>/dev/null || true
    echo
    echo "--- describe (postgres) ---"
    kubectl -n "${NAMESPACE}" describe pod -l app=postgres 2>/dev/null | tail -60 || true
    echo
    echo "--- recent events (last 30) ---"
    kubectl -n "${NAMESPACE}" get events \
        --sort-by=.lastTimestamp 2>/dev/null | tail -30 || true
    echo
    # A crash-looping container's exit reason is in its stderr, NOT in
    # describe/events (which only show that it restarts). Capture both
    # the current and the --previous logs — the previous invocation's
    # output is lost on the next restart otherwise.
    echo "--- logs (postgres, current) ---"
    kubectl -n "${NAMESPACE}" logs -l app=postgres \
        --all-containers --tail=120 2>&1 || true
    echo
    echo "--- logs (postgres, --previous) ---"
    kubectl -n "${NAMESPACE}" logs -l app=postgres \
        --all-containers --previous --tail=120 2>/dev/null || true
    echo
    echo "Hint: read the postgres logs above for the exit reason." >&2
    echo "      'ErrImagePull'/'ImagePullBackOff' in events ⇒ node could not" >&2
    echo "      pull ${POSTGRES_IMAGE}; 'OOMKilled'/'Pending' ⇒ host resource/" >&2
    echo "      disk starvation; container Started-then-exited ⇒ a postgres" >&2
    echo "      startup error (see stderr). Re-run with --keep to inspect live." >&2
    exit 1
fi

# Create the two existing-secret refs the chart's schema requires. Both
# carry the same DSN — the chart distinguishes "app" (DML-only) from
# "admin" (DDL); the smoke uses the same superuser for both since we're
# not exercising the least-privilege split.
kubectl -n "${NAMESPACE}" create secret generic hort-postgres-app \
    --from-literal=DATABASE_URL='postgres://hort:hort-smoke-test@postgres:5432/hort' \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "${NAMESPACE}" create secret generic hort-postgres-admin \
    --from-literal=DATABASE_URL='postgres://hort:hort-smoke-test@postgres:5432/hort' \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null

# -- Dex IdP admin-password Secret (pre-helm) --------------------------
#
# The IdP is Dex (the chart's optional sidecar), not the retired no-IdP
# `HORT_AUTH_PROVIDER=disabled` + local-admin-bootstrap path (the
# `admin bootstrap` CLI is retired; steady-state human admin is OIDC ->
# CliSession). Dex's staticPasswords admin needs a bcrypt password hash,
# supplied via this k8s Secret (referenced from the Helm values'
# auth.dex.staticAdmin.passwordHashSecret). The chart does NOT generate it.
#
# NOTE (groups caveat — not exercised here): Dex's staticPasswords DB does
# not attach `groups` to the issued token, so this static admin does NOT
# resolve the hort-admins -> admin ClaimMapping. That is fine for THIS
# smoke: the rotation CronJob authenticates with a native `hort_svc_*`
# token (nativeTokens, below), not an admin OIDC token — Dex's role here is
# only to satisfy the OIDC boot contract with a real IdP. A
# group-bearing admin needs a group-capable connector (LDAP / mock); see
# the compose tier / docs/plans for the worked example.
#
# bcrypt hash of the smoke admin password (pinned, smoke-only). Computed in
# the cluster-independent way `htpasswd` would, but without requiring
# htpasswd on the host: python's bcrypt if present, else a known-good hash
# for the pinned password.
DEX_ADMIN_PASSWORD="${DEX_ADMIN_PASSWORD:-smoke-admin-password}"
echo "==> Creating the Dex admin-password Secret (OIDC IdP)..."
DEX_ADMIN_HASH="$(python3 - "$DEX_ADMIN_PASSWORD" <<'PY' 2>/dev/null || true
import sys
try:
    import bcrypt
    print(bcrypt.hashpw(sys.argv[1].encode(), bcrypt.gensalt(rounds=10)).decode())
except Exception:
    pass
PY
)"
if [ -z "$DEX_ADMIN_HASH" ]; then
    # Fallback: a precomputed bcrypt hash of "smoke-admin-password" (cost 10).
    # Only valid when DEX_ADMIN_PASSWORD is left at its default; a custom
    # password requires python-bcrypt (or htpasswd) on the host.
    if [ "$DEX_ADMIN_PASSWORD" != "smoke-admin-password" ]; then
        echo "MISSING: python3 'bcrypt' needed to hash a custom DEX_ADMIN_PASSWORD." >&2
        echo "Install it (pip install bcrypt) or leave DEX_ADMIN_PASSWORD unset." >&2
        exit 2
    fi
    DEX_ADMIN_HASH='$2b$10$ZFx4vf73x.yQgM2JA8f/cOZuU3A1NnLywsbaU0Y69kjsmGaYIvlKu'
fi
kubectl -n "${NAMESPACE}" create secret generic hort-dex-admin \
    --from-literal=passwordHash="${DEX_ADMIN_HASH}" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
echo "    Dex admin-password Secret hort-dex-admin created/updated."

# -- OCI / native-token signing key ----
#
# The chart's `auth.nativeTokens.enabled=true` path requires an ed25519
# signing key (used by both the OCI Distribution `/v2/auth` JWT-minting
# path AND, more importantly here, the native-PAT validator that
# authenticates the rotation CronJob's `Bearer hort_svc_*` token).
#
# Without native tokens, `HORT_AUTH_PROVIDER=disabled` only authenticates
# humans via HTTP Basic against a local admin row — there is no path
# for a service-account token to reach an admin endpoint. The chart's
# rotation flow needs the service-account inbound auth path, so the
# smoke turns native tokens ON. The composition root sees
# `disabled + native-tokens=true` and wires `AuthContext::LocalOnly`.
#
# The key is generated fresh per smoke run via openssl genpkey; no
# state persists between runs. Mode 0600 on the local copy; the
# Kubernetes Secret stores the PEM bytes verbatim and is consumed
# via `secretKeyRef` by the hort-server Deployment.
echo "==> Generating ed25519 signing key for native tokens..."
# Initialise the shared scratch dir once and reuse it for both the
# signing key and the helm values file. The cleanup trap (set near
# the top of the script) only knows about a single `WORK_DIR`, so a
# fresh `mktemp -d` here would leak the signing-key tempdir even
# when the trap runs.
WORK_DIR="$(mktemp -d)"
SIGNING_KEY_PATH="${WORK_DIR}/hort-oci-token-signing-key.pem"
if ! command -v openssl >/dev/null 2>&1; then
    echo "MISSING: openssl is required to generate the smoke signing key." >&2
    echo "Install it via your distro's package manager and re-run." >&2
    exit 2
fi
openssl genpkey -algorithm ed25519 -out "${SIGNING_KEY_PATH}" 2>/dev/null
chmod 0600 "${SIGNING_KEY_PATH}"

kubectl -n "${NAMESPACE}" create secret generic hort-oci-signing-key \
    --from-file=hort-oci-token-signing-key.pem="${SIGNING_KEY_PATH}" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
echo "    signing-key Secret hort-oci-signing-key created/updated."

# -- Helm install ------------------------------------------------------

VALUES_FILE="${WORK_DIR}/values.yaml"
cat >"${VALUES_FILE}" <<EOF
image:
  repository: ${HORT_SERVER_IMAGE_REPO}
  tag: ${HORT_SERVER_IMAGE_TAG}
  # Never — the image was kind-loaded above; pulling would fail (the
  # tag may only exist in the local docker daemon, not in any registry
  # the kind nodes can reach).
  pullPolicy: Never

# In-cluster postgres deployed above. Plaintext HTTP — this is a
# smoke test on a private kind cluster, not a production install.
publicBaseUrl: "http://hort-server.${NAMESPACE}.svc.cluster.local"
requireHttps: false

postgres:
  app:
    existingSecret: hort-postgres-app
    secretKey: DATABASE_URL
  admin:
    existingSecret: hort-postgres-admin
    secretKey: DATABASE_URL

# Auth: provider=oidc with the chart's optional Dex IdP sidecar (the
# recommended shape — OIDC, not the retired no-IdP disabled+local-admin
# path). The chart wires HORT_OIDC_ISSUER_URL to auth.dex.issuerUrl, which
# here is the in-cluster Dex Service (the Dex discovery doc advertises the
# same host for both iss and jwks_uri, satisfying hort-server's same-host
# JWKS binding). The rotation CronJob still authenticates with a native
# \`Bearer hort_svc_*\` token (nativeTokens, below) — Dex's role is only to
# satisfy the OIDC boot contract with a real IdP; this smoke does not need
# an admin OIDC token (and Dex's staticPasswords admin would not carry the
# hort-admins group anyway — see the hort-dex-admin Secret note above).
auth:
  provider: oidc
  oidc:
    # Overridden by auth.dex.issuerUrl when dex.enabled (the chart points
    # HORT_OIDC_ISSUER_URL at Dex); kept non-empty for schema validity.
    issuerUrl: "http://hort-server-dex.${NAMESPACE}.svc.cluster.local:5556/dex"
    audience: "hort-server"
    groupsClaim: "groups"
  dex:
    enabled: true
    # In-cluster Dex Service URL — reachable from the hort-server pod, and
    # the iss/JWKS host hort-server validates against.
    issuerUrl: "http://hort-server-dex.${NAMESPACE}.svc.cluster.local:5556/dex"
    adminGroup: "hort-admins"
    staticAdmin:
      passwordHashSecret: "hort-dex-admin"
      passwordHashSecretKey: "passwordHash"
  nativeTokens:
    enabled: true
    signingKey:
      existingSecret: hort-oci-signing-key
      secretKey: hort-oci-token-signing-key.pem

# The smoke runs hort-server with plaintext HTTP inside the kind
# cluster. The PAT-over-HTTP gate refuses native tokens on unencrypted
# connections; an in-cluster smoke is the canonical case where the
# operator (here, the smoke script) deliberately accepts plaintext
# between sibling pods. \`HORT_BEARER_ALLOW_OVER_HTTP=true\` is the
# documented override.
extraEnv:
  - name: HORT_BEARER_ALLOW_OVER_HTTP
    value: "true"

storage:
  backend: filesystem

ephemeralStore:
  backend: memory

# The chart ships a fail-closed NetworkPolicy that is ON by default
# and renders a deny-all (ingress AND egress) when no allow rules are
# supplied — by design, the operator MUST populate the allow lists
# (see values.yaml networkPolicy comments). This smoke validates PAT
# rotation, NOT the network posture, so it uses the chart's documented
# escape hatch and opts out. Without
# this, the rotation CronJob's hort-cli egress to hort-server:8080 and the
# worker's egress to Postgres are both denied (connect-timeout +
# worker CrashLoopBackOff) — the whole chart is network-isolated.
networkPolicy:
  enabled: false

worker:
  enabled: true
  image:
    repository: ${HORT_WORKER_IMAGE_REPO}
    tag: ${HORT_WORKER_IMAGE_TAG}
    pullPolicy: Never
  # Rotation is enabled by the SINGLE
  # toggle scheduledTasks.serviceAccountRotation.enabled (below). There
  # is no worker.rotation.enabled any more — worker.rotation.* carries
  # only the worker-side PARAMETERS.
  rotation:
    targetNamespaces:
      - "${TARGET_NAMESPACE}"
    publicRegistryHost: "${PUBLIC_REGISTRY_HOST}"

scheduledTasks:
  adminTasksEnabled: true
  # \`scheduledTasks.svcTokenKubectlImage\` is left at the chart default
  # (\`bitnamilegacy/kubectl:1.30\`) — exercises the same path operators
  # take. If the smoke needs to test a specific minor version, override
  # here.
  serviceAccountRotation:
    enabled: true
    # Every minute — within the rotation poll budget below.
    schedule: "*/1 * * * *"

# Gitops config bootstrap: declare the ServiceAccount the rotation
# handler will mint Secrets for. No OidcIssuer needed — federation is
# NOT exercised here; rotation runs in the worker via the system-mint
# path.
gitopsConfig:
  # ConfigMap data keys must match [-._a-zA-Z0-9]+ — no slashes. The
  # parser (ApplyConfigUseCase) walks the whole config dir and dispatches
  # by each envelope's \`kind:\` field, so the key shape is only for
  # human organisation; the dotted form here is equivalent to a
  # repositories/pypi-internal.yaml + service-accounts/${SA_NAME}.yaml
  # pair in a flat layout. Repository apply runs before ServiceAccount
  # apply within a single gitops pass (ApplyConfigUseCase::apply order
  # — apply_repository_rows then apply_service_accounts), so a single
  # envelope batch covers the SA's \`repositories:\` reference below.
  "repository.pypi-internal.yaml": |
    apiVersion: project-hort.de/v1beta1
    kind: ArtifactRepository
    metadata:
      name: pypi-internal
    spec:
      name: "PyPI Internal"
      description: "Hosted PyPI for the rotation smoke"
      format: pypi
      type: hosted
      storage:
        backend: filesystem
        path: /var/lib/hort-server/cas/pypi-internal
      isPublic: false
      replicationPriority: local_only
  "service-account.${SA_NAME}.yaml": |
    apiVersion: project-hort.de/v1beta1
    kind: ServiceAccount
    metadata:
      name: ${SA_NAME}
    spec:
      role: developer
      repositories:
        - pypi-internal
      federatedIdentities: []
      fallbackRotation:
        targetSecret:
          name: ${SECRET_NAME}
          namespace: ${TARGET_NAMESPACE}
          format: dockerconfigjson
        rotationInterval: 6h
        validity: 24h
EOF

echo "==> Installing hort-server chart with rotation enabled..."
cd "${REPO_ROOT}"

# Diagnostic dump invoked on any helm install failure (timeout, probe
# failure, image pull error, …). Surfaces the pod state + recent logs +
# the namespace's events so the smoke caller doesn't have to manually
# kubectl-dig.
#
# A pod is "unhealthy" iff it isn't in phase Succeeded AND it doesn't
# have ALL containers Ready. CrashLoopBackOff pods are phase=Running
# with containerStatuses[*].ready=false — they MUST be in this set or
# the smoke's first failure mode hides itself.
dump_diagnostics() {
    echo
    echo "==> Helm install failed — collecting diagnostics from namespace ${NAMESPACE}"
    echo
    echo "--- pods ---"
    kubectl -n "${NAMESPACE}" get pods -o wide 2>/dev/null || true
    echo
    echo "--- unhealthy-pod describes + logs ---"
    while IFS= read -r pod; do
        echo
        echo "### kubectl describe pod ${pod}"
        kubectl -n "${NAMESPACE}" describe pod "${pod}" 2>/dev/null | tail -50 || true
        echo
        echo "### kubectl logs ${pod} (last 120 lines, all containers)"
        kubectl -n "${NAMESPACE}" logs "${pod}" --all-containers --tail=120 2>/dev/null || true
        # Previous container's logs hold the crash output a
        # CrashLoopBackOff loop loses on the next restart. Prefix each
        # line so the two streams don't blur together.
        echo
        echo "### kubectl logs ${pod} --previous (last 120 lines, all containers)"
        kubectl -n "${NAMESPACE}" logs "${pod}" --all-containers --previous --tail=120 2>/dev/null \
            | sed 's/^/[previous] /' || true
    done < <(unhealthy_pods)
    echo
    echo "--- recent events (last 40) ---"
    kubectl -n "${NAMESPACE}" get events \
        --sort-by=.lastTimestamp 2>/dev/null | tail -40 || true
}

# Emit one pod name per line for any pod that's not visibly healthy:
#   - phase != Succeeded (skip completed Jobs)
#   - AND (phase != Running OR any container's ready==false)
# Using jq when available for the second predicate; falling back to
# `kubectl get pods` column parsing otherwise.
unhealthy_pods() {
    if command -v jq >/dev/null 2>&1; then
        kubectl -n "${NAMESPACE}" get pods -o json 2>/dev/null \
            | jq -r '.items[]
                | select(.status.phase != "Succeeded")
                | select(
                    .status.phase != "Running"
                    or ((.status.containerStatuses // []) | length == 0)
                    or ((.status.containerStatuses // []) | any(.ready == false))
                  )
                | .metadata.name'
    else
        # Fallback: parse `READY` column (`x/y`) — pod is unhealthy
        # when x != y AND status != Completed.
        kubectl -n "${NAMESPACE}" get pods --no-headers 2>/dev/null \
            | awk '$3 != "Completed" && $2 !~ /^([0-9]+)\/\1$/ {print $1}'
    fi
}

if ! helm upgrade --install hort-server "${CHART_DIR}" \
        --namespace "${NAMESPACE}" \
        --values "${VALUES_FILE}" \
        --wait \
        --timeout 5m; then
    dump_diagnostics
    exit 1
fi

echo "==> Helm install completed."

# -- Wait + assert ------------------------------------------------------

echo "==> Waiting up to ${ROTATION_TIMEOUT_SECS}s for the rotation CronJob to populate ${TARGET_NAMESPACE}/${SECRET_NAME}..."
ROTATED=""
for i in $(seq 1 "${ROTATION_TIMEOUT_SECS}"); do
    MANAGED_BY="$(kubectl get secret -n "${TARGET_NAMESPACE}" "${SECRET_NAME}" \
        -o jsonpath='{.metadata.labels.hort\.io/managed-by}' 2>/dev/null || true)"
    if [ "${MANAGED_BY}" = "hort-worker" ]; then
        ROTATED="1"
        break
    fi
    sleep 1
done

if [ -z "${ROTATED}" ]; then
    echo "FAIL: Secret ${TARGET_NAMESPACE}/${SECRET_NAME} did not appear with label \
project-hort.de/managed-by=hort-worker within ${ROTATION_TIMEOUT_SECS}s."
    echo
    echo "Diagnostics:"
    kubectl get all -n "${NAMESPACE}" || true
    kubectl get cronjob -n "${NAMESPACE}" -o wide || true
    kubectl get jobs -n "${NAMESPACE}" -o wide || true
    echo
    echo "--- per-pod logs (last 200, all containers) ---"
    # Earlier diagnostic attempts used label selectors that silently
    # matched zero pods (e.g. `app.kubernetes.io/component=server` is
    # never set on the hort-server Deployment, only on the worker). To
    # avoid that failure mode entirely, iterate every pod in the
    # namespace and dump each one's logs under an explicit header so a
    # selector miss can't swallow the only data point that explains a
    # 5xx from hort-cli or worker.
    for pod in $(kubectl -n "${NAMESPACE}" get pods -o name 2>/dev/null); do
        echo
        echo "### ${pod}"
        kubectl -n "${NAMESPACE}" logs "${pod}" \
            --all-containers --tail=200 2>&1 || true
        # CrashLoopBackOff or RunContainerError pods lose their current
        # invocation's logs to the next restart. Pull --previous so the
        # most-recent failure's stderr is preserved.
        prev="$(kubectl -n "${NAMESPACE}" logs "${pod}" \
            --all-containers --previous --tail=200 2>/dev/null || true)"
        if [ -n "${prev}" ]; then
            echo "### ${pod} (previous container)"
            echo "${prev}"
        fi
    done
    exit 1
fi

echo "==> Secret rotated successfully (label project-hort.de/managed-by=hort-worker present)."

# -- Label assertions ---------------------------------------------------

assert_label() {
    local label_key="$1"
    local expected="$2"
    local got
    got="$(kubectl get secret -n "${TARGET_NAMESPACE}" "${SECRET_NAME}" \
        -o jsonpath="{.metadata.labels.${label_key}}" 2>/dev/null || true)"
    if [ "${got}" != "${expected}" ]; then
        echo "FAIL: Secret label '${label_key//\\/}' = '${got}', expected '${expected}'."
        exit 1
    fi
    echo "  ${label_key//\\/} = ${got}"
}

assert_label_regex() {
    local label_key="$1"
    local regex="$2"
    local got
    got="$(kubectl get secret -n "${TARGET_NAMESPACE}" "${SECRET_NAME}" \
        -o jsonpath="{.metadata.labels.${label_key}}" 2>/dev/null || true)"
    if ! echo "${got}" | grep -qE "${regex}"; then
        echo "FAIL: Secret label '${label_key//\\/}' = '${got}', does not match regex '${regex}'."
        exit 1
    fi
    echo "  ${label_key//\\/} = ${got}  (matches ${regex})"
}

assert_annotation_regex() {
    # Annotations rather than labels because k8s label values must
    # match `(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?`, which
    # excludes `:` — and every RFC 3339 timestamp carries at least
    # two of them. The reconciler writes `project-hort.de/last-rotated` into
    # `metadata.annotations` for this reason.
    local annot_key="$1"
    local regex="$2"
    local got
    got="$(kubectl get secret -n "${TARGET_NAMESPACE}" "${SECRET_NAME}" \
        -o jsonpath="{.metadata.annotations.${annot_key}}" 2>/dev/null || true)"
    if ! echo "${got}" | grep -qE "${regex}"; then
        echo "FAIL: Secret annotation '${annot_key//\\/}' = '${got}', does not match regex '${regex}'."
        exit 1
    fi
    echo "  ${annot_key//\\/} = ${got}  (matches ${regex})"
}

echo "==> Asserting canonical labels + annotation..."
assert_label "hort\.io/managed-by" "hort-worker"
assert_label "hort\.io/service-account" "${SA_NAME}"
# UUID v4 — relaxed regex (any UUID shape).
assert_label_regex "hort\.io/token-id" "^[0-9a-fA-F-]{36}$"
# RFC 3339 timestamp — accept any well-formed instance. Stored on
# annotations (see assert_annotation_regex docstring).
assert_annotation_regex "hort\.io/last-rotated" "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"

# -- Data assertions ---------------------------------------------------

echo "==> Asserting Secret data shape (dockerconfigjson)..."
TYPE="$(kubectl get secret -n "${TARGET_NAMESPACE}" "${SECRET_NAME}" \
    -o jsonpath='{.type}' 2>/dev/null || true)"
if [ "${TYPE}" != "kubernetes.io/dockerconfigjson" ]; then
    echo "FAIL: Secret type = '${TYPE}', expected 'kubernetes.io/dockerconfigjson'."
    exit 1
fi
echo "  type = ${TYPE}"

DOCKERCONFIG_B64="$(kubectl get secret -n "${TARGET_NAMESPACE}" "${SECRET_NAME}" \
    -o jsonpath='{.data.\.dockerconfigjson}' 2>/dev/null || true)"
if [ -z "${DOCKERCONFIG_B64}" ]; then
    echo "FAIL: Secret data missing '.dockerconfigjson' field."
    exit 1
fi

# Decode and check `.auths.<host>.password` is non-empty.
DOCKERCONFIG_JSON="$(echo "${DOCKERCONFIG_B64}" | base64 -d)"
PASSWORD="$(echo "${DOCKERCONFIG_JSON}" | python3 -c "
import json, sys
d = json.load(sys.stdin)
auths = d.get('auths', {})
host = '${PUBLIC_REGISTRY_HOST}'
entry = auths.get(host, {})
print(entry.get('password', ''))
")"
if [ -z "${PASSWORD}" ]; then
    echo "FAIL: dockerconfigjson auths.${PUBLIC_REGISTRY_HOST}.password is empty."
    echo "Raw dockerconfigjson: ${DOCKERCONFIG_JSON}"
    exit 1
fi
echo "  dockerconfigjson.auths.${PUBLIC_REGISTRY_HOST}.password = <${#PASSWORD} chars>"

# -- Summary -----------------------------------------------------------

echo
echo "===================================================================="
echo "PASS — kind-cluster ServiceAccount rotation e2e"
echo "===================================================================="
echo
echo "Cluster:       ${CLUSTER_NAME}"
echo "Namespace:     ${NAMESPACE}"
echo "Target ns:     ${TARGET_NAMESPACE}"
echo "Secret:        ${SECRET_NAME}"
echo "Registry host: ${PUBLIC_REGISTRY_HOST}"
echo
exit 0
