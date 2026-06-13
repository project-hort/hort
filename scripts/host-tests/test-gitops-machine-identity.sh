#!/usr/bin/env bash
# Federation branch e2e smoke (self-owned stack).
#
# Validates the federation path on POST /api/v1/auth/exchange end-to-end
# against a stack THIS SCRIPT owns. Earlier revisions ran a host-side
# python JWKS server and soft-SKIPped when the exchange endpoint was
# absent — which made the test green-by-skip (it never actually proved
# federation worked) and leaked an orphaned python process onto the JWKS
# port so repeat runs failed deterministically. This revision removes
# both failure modes:
#
#   * The issuer is a compose-network nginx service serving OIDC
#     discovery + JWKS over TLS (plaintext issuerUrl is hard-rejected;
#     hort-server trusts the CA via HORT_EXTRA_CA_BUNDLE). No
#     host-side server, so nothing to orphan.
#   * The stack is brought up with token-exchange + its hard companion
#     requirements (native tokens, an Ed25519 signing key,
#     HORT_OIDC_CLI_CLIENT_ID) via deploy/compose/docker-compose.federation.yml,
#     and the OidcIssuer + ServiceAccount envelopes are seeded into the
#     gitops config tree so boot-time apply registers them
#     (gitops apply is boot-time only — "restart-to-apply").
#   * The exchange + negative-claim assertions HARD-FAIL. The only
#     soft skip left is "docker not installed" (exit 2, operator skip),
#     matching the k8s-rotation smoke's convention.
#
# DESTRUCTIVE: this test owns the `hort` compose project. It runs
# `compose down -v` before AND after (unless --keep) — any hort stack
# you have up for other smokes WILL be torn down. The v2 stack is
# ephemeral by design (tmpfs postgres), so this is safe but noisy.
#
# Runtime ~90-180s (keycloak realm import gate + image start). NOT in
# the default smoke profile. Run on demand:
#   ./scripts/host-tests/test-gitops-machine-identity.sh
#   bash scripts/host-tests/test-gitops-machine-identity.sh
#
# Flags / env:
#   --clean        teardown only (compose down -v), then exit 0
#   --keep         leave the stack up after a successful run
#   FED_REBUILD=1  pass --build to compose up (rebuild hort-server image
#                  from source; default reuses the existing image —
#                  its binary already carries the federation handler)
#
# Per CLAUDE.md memory rule: host ports stay in the 25xxx range
# (inherited from the base compose: 25080 api, 25090 metrics).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

BASE_COMPOSE="$REPO_ROOT/deploy/compose/docker-compose.yml"
FED_COMPOSE="$REPO_ROOT/deploy/compose/docker-compose.federation.yml"
EXAMPLE_CONFIG="$REPO_ROOT/deploy/compose/example-config"

REGISTRY_URL="${REGISTRY_URL:-http://localhost:25080}"
METRICS_URL="${METRICS_URL:-http://localhost:25090/metrics}"
COMPOSE_NETWORK="${COMPOSE_NETWORK:-hort_default}"
ISSUER_HOST="fed-issuer"
ISSUER_PORT="8443"
ISSUER_URL="https://${ISSUER_HOST}:${ISSUER_PORT}"
HEALTH_TIMEOUT_SECS="${HEALTH_TIMEOUT_SECS:-240}"

KEEP_STACK=""
CLEAN_ONLY=""
WORK_DIR=""

COMPOSE=(docker compose -f "$BASE_COMPOSE" -f "$FED_COMPOSE")

FAIL=0
PASSED=0
declare -a FAILURES=()

assert_pass() { PASSED=$((PASSED + 1)); echo "  PASS: $1"; }
assert_fail() {
    FAIL=$((FAIL + 1))
    FAILURES+=("$1: $2")
    echo "  FAIL: $1 — $2"
}

dump_stack_diagnostics() {
    echo
    echo "==> Stack diagnostics"
    "${COMPOSE[@]}" ps 2>/dev/null || true
    echo "--- hort-server (last 120) ---"
    "${COMPOSE[@]}" logs --tail=120 hort-server 2>/dev/null || true
    echo "--- fed-issuer (last 40) ---"
    "${COMPOSE[@]}" logs --tail=40 fed-issuer 2>/dev/null || true
}

cleanup() {
    if [ -n "${KEEP_STACK}" ] && [ -z "${CLEAN_ONLY}" ]; then
        echo "--keep set: leaving the hort stack up."
        echo "  Tear down with: ${COMPOSE[*]} down -v"
    else
        echo "==> Tearing down the hort stack (compose down -v)..."
        "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
    fi
    if [ -n "${WORK_DIR}" ] && [ -d "${WORK_DIR}" ]; then
        rm -rf "${WORK_DIR}"
    fi
}
trap cleanup EXIT INT TERM

while [ "$#" -gt 0 ]; do
    case "$1" in
        --clean) CLEAN_ONLY="1"; shift ;;
        --keep)  KEEP_STACK="1"; shift ;;
        *)       echo "Unknown arg: $1" >&2; exit 64 ;;
    esac
done

# -- Preflight ---------------------------------------------------------
# docker missing → operator skip (exit 2), matching test-k8s-rotation.sh
# and the native-test harness contract. Everything else is a hard
# prerequisite (a real failure if absent on a machine that has docker).

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    echo "SKIP: docker not available — federation smoke requires a docker daemon."
    exit 2
fi

if [ -n "${CLEAN_ONLY}" ]; then
    echo "Cleanup-only mode."
    "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
    trap - EXIT INT TERM
    echo "Done."
    exit 0
fi

for bin in openssl python3 jq curl; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        echo "FATAL: required binary '$bin' not found" >&2
        exit 2
    fi
done
if ! python3 -c "import cryptography" >/dev/null 2>&1; then
    echo "FATAL: python3 'cryptography' module required (JWT mint + JWKS build)" >&2
    exit 2
fi
if [ ! -d "${EXAMPLE_CONFIG}" ]; then
    echo "FATAL: ${EXAMPLE_CONFIG} not found — cannot seed gitops config" >&2
    exit 2
fi

WORK_DIR="$(mktemp -d -t hort-init39-fed-XXXX)"
TLS_DIR="${WORK_DIR}/tls"
SIGN_DIR="${WORK_DIR}/sign"
WEBROOT="${WORK_DIR}/webroot"
CONFIG_DIR="${WORK_DIR}/config"
mkdir -p "${TLS_DIR}" "${SIGN_DIR}" "${WEBROOT}/.well-known" \
         "${CONFIG_DIR}/oidc-issuers" "${CONFIG_DIR}/service-accounts"

# -- Phase 1: crypto material -----------------------------------------

echo "[1/7] Generating CA + issuer TLS cert, Ed25519 signing key, JWT key..."

# CA + leaf for the issuer. SAN must carry `fed-issuer` (the in-network
# host hort-server connects to) plus localhost for any ad-hoc host probe.
# serverAuth EKU + CA:FALSE on the leaf so rustls/webpki accepts it.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out "${TLS_DIR}/ca.key" 2>/dev/null
openssl req -x509 -new -key "${TLS_DIR}/ca.key" -days 2 \
    -subj "/CN=hort-fed-test-ca" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -out "${TLS_DIR}/ca.crt" 2>/dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out "${TLS_DIR}/issuer.key" 2>/dev/null
openssl req -new -key "${TLS_DIR}/issuer.key" -subj "/CN=${ISSUER_HOST}" \
    -out "${TLS_DIR}/issuer.csr" 2>/dev/null
openssl x509 -req -in "${TLS_DIR}/issuer.csr" \
    -CA "${TLS_DIR}/ca.crt" -CAkey "${TLS_DIR}/ca.key" -CAcreateserial \
    -days 2 -out "${TLS_DIR}/issuer.crt" \
    -extfile <(printf 'subjectAltName=DNS:%s,DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' "${ISSUER_HOST}") \
    2>/dev/null

# Ed25519 signing key for native tokens (HORT_OCI_TOKEN_SIGNING_KEY_FILE).
# 0644, NOT 0600: the hort-server image is distroless and runs as the
# non-root uid 65532 (see the base compose's cas-init comment). A
# bind-mounted file keeps its host owner/mode inside the container, so
# a 0600 file owned by the host user is unreadable by uid 65532 —
# hort-server boot-fails with "cannot read signing key file: Permission
# denied". This is an ephemeral per-run smoke key, never a real secret.
openssl genpkey -algorithm ed25519 -out "${SIGN_DIR}/signing-key.pem" 2>/dev/null
chmod 0644 "${SIGN_DIR}/signing-key.pem"

# RSA-2048 key the issuer signs JWTs with; JWKS derived from the pub.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out "${WORK_DIR}/jwt-sign.pem" 2>/dev/null
openssl rsa -in "${WORK_DIR}/jwt-sign.pem" -pubout \
    -out "${WORK_DIR}/jwt-sign.pub" 2>/dev/null

python3 - "$WORK_DIR" <<'PYEOF' > "${WEBROOT}/jwks.json"
import base64, json, sys
from cryptography.hazmat.primitives import serialization
work = sys.argv[1]
with open(f"{work}/jwt-sign.pub", "rb") as f:
    pub = serialization.load_pem_public_key(f.read())
n = pub.public_numbers()
def b64url(i):
    raw = i.to_bytes((i.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
print(json.dumps({"keys": [{
    "kty": "RSA", "kid": "test-key-1", "use": "sig", "alg": "RS256",
    "n": b64url(n.n), "e": b64url(n.e),
}]}))
PYEOF

cat > "${WEBROOT}/.well-known/openid-configuration" <<EOF
{
  "issuer": "${ISSUER_URL}",
  "jwks_uri": "${ISSUER_URL}/jwks.json",
  "response_types_supported": ["id_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"]
}
EOF

cat > "${WORK_DIR}/issuer.conf" <<EOF
server {
    listen ${ISSUER_PORT} ssl;
    server_name ${ISSUER_HOST};
    ssl_certificate     /etc/nginx/tls/issuer.crt;
    ssl_certificate_key /etc/nginx/tls/issuer.key;
    root /srv/issuer;
    location / {
        default_type application/json;
        try_files \$uri =404;
    }
}
EOF

# -- Phase 2: seed the gitops config tree -----------------------------

echo "[2/7] Seeding gitops config (example-config + OidcIssuer + ServiceAccount)..."
cp -r "${EXAMPLE_CONFIG}/." "${CONFIG_DIR}/"

cat > "${CONFIG_DIR}/oidc-issuers/federation-test-issuer.yaml" <<EOF
apiVersion: project-hort.de/v1beta1
kind: OidcIssuer
metadata:
  name: federation-test-issuer
spec:
  issuerUrl: ${ISSUER_URL}
  audiences: [hort-server]
  jwksRefreshInterval: 1m
  allowedAlgorithms: [RS256]
EOF

cat > "${CONFIG_DIR}/service-accounts/ci-federation-test.yaml" <<EOF
apiVersion: project-hort.de/v1beta1
kind: ServiceAccount
metadata:
  name: ci-federation-test
spec:
  role: developer
  repositories: [pypi-internal]
  federatedIdentities:
    - issuer: federation-test-issuer
      claims:
        repository: my-org/my-repo
        environment: production
EOF

# -- Phase 3: bring up the self-owned stack ---------------------------

# Everything hort-server (uid 65532) reads via bind mount must be
# traversable + readable regardless of the invoking shell's umask.
# a+rX = read for files, read+traverse for dirs; harmless for the
# nginx-read TLS material too.
chmod -R a+rX "${CONFIG_DIR}" "${TLS_DIR}" "${SIGN_DIR}" "${WEBROOT}" \
              "${WORK_DIR}/issuer.conf"

export HORT_FED_CONFIG_DIR="${CONFIG_DIR}"
export HORT_FED_SIGNING_KEY="${SIGN_DIR}/signing-key.pem"
export HORT_FED_CA_BUNDLE="${TLS_DIR}/ca.crt"
export HORT_FED_ISSUER_WEBROOT="${WEBROOT}"
export HORT_FED_ISSUER_NGINX_CONF="${WORK_DIR}/issuer.conf"
export HORT_FED_ISSUER_TLS_CRT="${TLS_DIR}/issuer.crt"
export HORT_FED_ISSUER_TLS_KEY="${TLS_DIR}/issuer.key"

echo "[3/7] Pre-clean + bringing up the hort stack with token-exchange enabled..."
"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
if ! "${COMPOSE[@]}" up -d ${FED_REBUILD:+--build}; then
    dump_stack_diagnostics
    assert_fail "stack-up" "compose up failed"
    echo; echo "== federation smoke =="; echo "  passed: ${PASSED}"; echo "  failed: ${FAIL}"
    exit 1
fi

# -- Phase 4: readiness gates -----------------------------------------

echo "[4/7] Waiting for hort-server health (<=${HEALTH_TIMEOUT_SECS}s; keycloak realm-import gate)..."
HEALTHY=""
for _ in $(seq 1 "${HEALTH_TIMEOUT_SECS}"); do
    if curl -fsS -m 3 "${REGISTRY_URL}/healthz" >/dev/null 2>&1; then
        HEALTHY="1"; break
    fi
    sleep 1
done
if [ -z "${HEALTHY}" ]; then
    dump_stack_diagnostics
    assert_fail "hort-server-healthy" "no 200 from ${REGISTRY_URL}/healthz within ${HEALTH_TIMEOUT_SECS}s"
    echo; echo "== federation smoke =="; echo "  passed: ${PASSED}"; echo "  failed: ${FAIL}"
    exit 1
fi
assert_pass "hort-server-healthy"

echo "    verifying the issuer is reachable in-network (TLS + CA trust)..."
ISSUER_OK=""
for _ in $(seq 1 30); do
    if docker run --rm --network "${COMPOSE_NETWORK}" \
        -v "${TLS_DIR}/ca.crt:/ca.crt:ro" curlimages/curl:8.10.1 \
        curl -fsS -m 3 --cacert /ca.crt \
        "${ISSUER_URL}/.well-known/openid-configuration" >/dev/null 2>&1; then
        ISSUER_OK="1"; break
    fi
    sleep 1
done
if [ -z "${ISSUER_OK}" ]; then
    dump_stack_diagnostics
    assert_fail "issuer-reachable-in-network" "fed-issuer discovery doc not fetchable over TLS from the compose network"
    echo; echo "== federation smoke =="; echo "  passed: ${PASSED}"; echo "  failed: ${FAIL}"
    exit 1
fi
assert_pass "issuer-reachable-in-network"

# -- JWT mint helper ---------------------------------------------------

mint_jwt() {
    # $1 sub  $2 repository-claim  $3 environment-claim  $4 exp-offset-secs
    python3 - "$WORK_DIR" "$ISSUER_URL" "$1" "$2" "$3" "${4:-600}" <<'PYEOF'
import base64, json, sys, time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
work, iss, sub, repository, environment, exp_off = sys.argv[1:7]
with open(f"{work}/jwt-sign.pem", "rb") as f:
    key = serialization.load_pem_private_key(f.read(), password=None)
def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
hdr = {"alg": "RS256", "typ": "JWT", "kid": "test-key-1"}
now = int(time.time())
payload = {
    "iss": iss, "sub": sub, "aud": "hort-server",
    "iat": now, "exp": now + int(exp_off), "nbf": now - 5,
    "jti": f"smoke-{sub}-{now}",
    "repository": repository, "environment": environment,
}
hb = b64url(json.dumps(hdr, separators=(",", ":")).encode())
pb = b64url(json.dumps(payload, separators=(",", ":")).encode())
sig = key.sign(f"{hb}.{pb}".encode(), padding.PKCS1v15(), hashes.SHA256())
print(f"{hb}.{pb}.{b64url(sig)}")
PYEOF
}

exchange() {
    # $1 jwt → prints "HTTP_CODE<newline>BODY"
    curl -sS -m 10 -o - -w '\n%{http_code}' -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
        --data-urlencode "subject_token=$1" \
        --data-urlencode "subject_token_type=urn:ietf:params:oauth:token-type:jwt" \
        --data-urlencode "client_id=smoke-federation" \
        "${REGISTRY_URL}/api/v1/auth/exchange" 2>/dev/null
}

metric_count() {
    # $1 result-label → integer count for kind="federated_jwt"
    curl -fsS -m 5 "${METRICS_URL}" 2>/dev/null \
        | awk -v r="result=\"$1\"" '
            /^hort_token_exchange_total\{/ && /kind="federated_jwt"/ && index($0, r) {
                print $NF; found=1
            }
            END { if (!found) print 0 }' \
        | tail -1
}

# -- Phase 5: matching JWT → exchange succeeds (HARD) ------------------

echo "[5/7] Exchanging a matching JWT for an hort-server bearer..."
MATCH_JWT="$(mint_jwt "repo:my-org/my-repo:ref:refs/heads/main" "my-org/my-repo" "production" 600)"
RESP="$(exchange "${MATCH_JWT}")"
CODE="$(printf '%s' "${RESP}" | tail -1)"
BODY="$(printf '%s' "${RESP}" | sed '$d')"

if [ "${CODE}" = "200" ]; then
    assert_pass "exchange-http-200"
else
    assert_fail "exchange-http-200" "got HTTP ${CODE}; body: ${BODY:0:300}"
fi

BEARER="$(printf '%s' "${BODY}" | jq -r '.access_token // empty' 2>/dev/null || true)"
ISSUED_TYPE="$(printf '%s' "${BODY}" | jq -r '.issued_token_type // empty' 2>/dev/null || true)"
EXPIRES_IN="$(printf '%s' "${BODY}" | jq -r '.expires_in // empty' 2>/dev/null || true)"

case "${BEARER}" in
    hort_svc_*) assert_pass "bearer-is-hort_svc" ;;
    *)        assert_fail "bearer-is-hort_svc" "access_token not hort_svc_-shaped: '${BEARER:0:16}'" ;;
esac

if [ "${ISSUED_TYPE}" = "urn:ietf:params:oauth:token-type:access_token" ]; then
    assert_pass "issued-token-type"
else
    assert_fail "issued-token-type" "got '${ISSUED_TYPE}'"
fi

# validity = min(1h, jwt.exp - now) → ~600s; allow clock/processing drift.
if [[ "${EXPIRES_IN}" =~ ^[0-9]+$ ]] && [ "${EXPIRES_IN}" -ge 540 ] && [ "${EXPIRES_IN}" -le 600 ]; then
    assert_pass "expires-in-capped-to-jwt-exp"
else
    assert_fail "expires-in-capped-to-jwt-exp" "expected 540-600, got '${EXPIRES_IN}'"
fi

if [ "$(metric_count success)" -ge 1 ]; then
    assert_pass "metric-federated_jwt-success"
else
    assert_fail "metric-federated_jwt-success" 'hort_token_exchange_total{kind="federated_jwt",result="success"} not >=1'
fi

# -- Phase 6: pypi publish with the federated bearer (soft-skip) ------
# Not a federation assertion — twine is frequently absent on dev boxes.
# Publishing IS the GitLab/CI use case, so we exercise it when we can.

echo "[6/7] Publishing a pypi artifact with the federated bearer..."
if [ -n "${BEARER:-}" ] && [[ "${BEARER}" == hort_svc_* ]] \
   && command -v twine >/dev/null 2>&1 && python3 -c "import build" >/dev/null 2>&1; then
    PKG="${WORK_DIR}/pkg"
    mkdir -p "${PKG}/init39_smoke"
    echo "__version__='0.0.1'" > "${PKG}/init39_smoke/__init__.py"
    cat > "${PKG}/pyproject.toml" <<EOF
[build-system]
requires = ["setuptools>=61"]
build-backend = "setuptools.build_meta"
[project]
name = "init39-smoke"
version = "0.0.1"
description = "federation e2e artifact"
EOF
    if (cd "${PKG}" && python3 -m build --wheel >/dev/null 2>&1) \
       && WHEEL="$(ls "${PKG}"/dist/*.whl 2>/dev/null | head -1)" && [ -n "${WHEEL}" ]; then
        if TWINE_USERNAME="__token__" TWINE_PASSWORD="${BEARER}" \
            twine upload --non-interactive \
            --repository-url "${REGISTRY_URL}/pypi/pypi-internal/" "${WHEEL}" >/dev/null 2>&1; then
            assert_pass "pypi-upload-with-federated-bearer"
        else
            assert_fail "pypi-upload-with-federated-bearer" "twine upload returned non-zero"
        fi
    else
        echo "  SKIP: pypi-upload (wheel build unavailable)"
    fi
else
    echo "  SKIP: pypi-upload (twine / python-build not installed — not a federation assertion)"
fi

# -- Phase 7: non-matching claims → deny (HARD) -----------------------

echo "[7/7] Negative case: non-matching claims must be denied..."
NEG_JWT="$(mint_jwt "repo:my-org/my-repo:ref:refs/heads/main" "WRONG/repo" "production" 600)"
NEG_RESP="$(exchange "${NEG_JWT}")"
NEG_CODE="$(printf '%s' "${NEG_RESP}" | tail -1)"
NEG_BODY="$(printf '%s' "${NEG_RESP}" | sed '$d')"

if [ "${NEG_CODE}" = "401" ]; then
    assert_pass "negative-http-401"
else
    assert_fail "negative-http-401" "expected 401, got ${NEG_CODE}; body: ${NEG_BODY:0:300}"
fi

if [ "$(metric_count no_sa_match)" -ge 1 ]; then
    assert_pass "metric-federated_jwt-no_sa_match"
else
    NEG_DESC="$(printf '%s' "${NEG_BODY}" | jq -r '.error_description // empty' 2>/dev/null || true)"
    if printf '%s' "${NEG_DESC}" | grep -qi "no ServiceAccount matches"; then
        assert_pass "metric-federated_jwt-no_sa_match"
    else
        assert_fail "metric-federated_jwt-no_sa_match" \
            "no no_sa_match metric and body not the no_sa_match deny: ${NEG_DESC:-<empty>}"
    fi
fi

# -- Summary -----------------------------------------------------------

echo
echo "===================================================================="
echo "Federation smoke (self-owned stack)"
echo "===================================================================="
echo "  passed: ${PASSED}"
echo "  failed: ${FAIL}"
if [ "${FAIL}" -gt 0 ]; then
    echo "Failures:"
    printf '  - %s\n' "${FAILURES[@]}"
    dump_stack_diagnostics
    exit 1
fi
echo "PASS — federation exchange + negative deny verified end-to-end."
exit 0
