#!/usr/bin/env bash
# cosign sign + verify round-trip against hort-server (Init 11 Item 14).
#
# Generates an ephemeral keypair, pushes an image, signs it with the
# private key, verifies with the public key. Idempotency: signs twice
# and asserts the Referrers response stays well-formed OCI
# image-index JSON. Cosign's signing path itself drives the OCI
# Referrers API write side (Item 4) and the read side (Item 13).
#
# Why explicit-key (keyless-OFF):
#   Sigstore's keyless flow depends on Fulcio + Rekor + an OIDC
#   issuer reachable from CI. Generating a keypair on-the-fly with
#   `cosign generate-key-pair` keeps this smoke fully offline-capable
#   apart from the registry write itself.
#
# Why SKIP-on-missing-cosign:
#   cosign is not always available in CI sidecars. The local-OCI
#   phase (Item 5) already covers the core registry path; this
#   smoke is additive Phase-5 acceptance for the Referrers API.
#   Mirrors the SKIP-on-prereq idiom used by test-oci-mirror.sh.
#
# Deferred: will become a scenarios/provenance/* scenario once cosign and a
# provenance overlay land; not currently run by the runner.
#
# Env (defaults):
#   REGISTRY_URL          http://hort-server:8080
#   REPO_KEY              oci-e2e
#   SOURCE_IMAGE          ghcr.io/oci-playground/hello-world:latest
#   TEST_IMAGE_NAME       cosign-testimg  (distinct from skopeo smoke)
#   TEST_TAG              v0
#   KEYCLOAK_TOKEN_URL    http://keycloak:8080/realms/hort/protocol/openid-connect/token
#   KEYCLOAK_CLIENT_ID    hort-server
#   KEYCLOAK_CLIENT_SECRET hort-server-secret-dev-only
#   KEYCLOAK_USER         dev-user (developer role — write grant)
#   KEYCLOAK_PASS         dev

set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://hort-server:8080}"
# Strip scheme so cosign / skopeo's docker:// transport gets host:port only.
REGISTRY_HOST="${REGISTRY_URL#http://}"
REGISTRY_HOST="${REGISTRY_HOST#https://}"

REPO_KEY="${REPO_KEY:-oci-e2e}"
TEST_IMAGE_NAME="${TEST_IMAGE_NAME:-cosign-testimg}"
TEST_TAG="${TEST_TAG:-v0}"
SOURCE_IMAGE="${SOURCE_IMAGE:-ghcr.io/oci-playground/hello-world:latest}"

KEYCLOAK_TOKEN_URL="${KEYCLOAK_TOKEN_URL:-http://keycloak:8080/realms/hort/protocol/openid-connect/token}"
KEYCLOAK_CLIENT_ID="${KEYCLOAK_CLIENT_ID:-hort-server}"
KEYCLOAK_CLIENT_SECRET="${KEYCLOAK_CLIENT_SECRET:-hort-server-secret-dev-only}"
KEYCLOAK_USER="${KEYCLOAK_USER:-dev-user}"
KEYCLOAK_PASS="${KEYCLOAK_PASS:-dev}"

DEST_IMAGE="${REGISTRY_HOST}/${REPO_KEY}/${TEST_IMAGE_NAME}:${TEST_TAG}"

echo "==> v2 OCI cosign sign+verify smoke"
echo "Registry:     ${REGISTRY_URL}"
echo "Repo key:     ${REPO_KEY}"
echo "Source:       ${SOURCE_IMAGE}"
echo "Destination:  ${DEST_IMAGE}"
echo ""

# ---------------------------------------------------------------------
# [1/9] Tool prereqs.
#
# cosign is the load-bearing dep; if it's missing we SKIP rather than
# FAIL — same idiom as test-oci-mirror.sh. skopeo is required for the
# image push (we don't want a docker daemon dep on this path); curl is
# required for the auth + Referrers GET.
# ---------------------------------------------------------------------
echo "[1/9] Checking tool prereqs..."
if ! command -v cosign >/dev/null 2>&1; then
    echo "SKIP: cosign not installed, skipping cosign smoke"
    exit 0
fi
command -v skopeo >/dev/null 2>&1 || { echo "FAIL: skopeo missing in image" >&2; exit 1; }
command -v curl   >/dev/null 2>&1 || { echo "FAIL: curl missing in image" >&2; exit 1; }
COSIGN_VERSION="$(cosign version 2>/dev/null | grep -i 'GitVersion' | head -1 || true)"
echo "  cosign:  ${COSIGN_VERSION:-version-unknown}"
echo "  skopeo:  $(skopeo --version 2>/dev/null | head -1)"

# ---------------------------------------------------------------------
# [2/9] Fetch developer JWT from Keycloak (ROPC). Mirrors
# test-oci-skopeo.sh line-for-line so failures here look identical
# in CI logs across the two phases.
# ---------------------------------------------------------------------
echo ""
echo "[2/9] Fetching dev-user token from Keycloak (${KEYCLOAK_TOKEN_URL})..."
TOKEN_BODY=$(curl -sf -X POST "$KEYCLOAK_TOKEN_URL" \
    -d grant_type=password \
    -d "client_id=${KEYCLOAK_CLIENT_ID}" \
    -d "client_secret=${KEYCLOAK_CLIENT_SECRET}" \
    -d "username=${KEYCLOAK_USER}" \
    -d "password=${KEYCLOAK_PASS}")
DEV_TOKEN=$(printf '%s' "$TOKEN_BODY" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
if [ -z "${DEV_TOKEN:-}" ]; then
    echo "FAIL: empty access_token from Keycloak" >&2
    echo "  response: $TOKEN_BODY" >&2
    exit 1
fi
echo "  got dev token (${#DEV_TOKEN} chars)"

DEST_CREDS="${KEYCLOAK_USER}:${DEV_TOKEN}"

# ---------------------------------------------------------------------
# [3/9] Push the test image. Use a distinct image name from the
# skopeo smoke (cosign-testimg vs testimg) so the two phases can
# run in any order without colliding on the manifest digest.
# ---------------------------------------------------------------------
echo ""
echo "[3/9] Push: ${SOURCE_IMAGE} -> docker://${DEST_IMAGE}"
skopeo copy \
    --insecure-policy \
    --dest-tls-verify=false \
    --dest-creds "$DEST_CREDS" \
    "docker://${SOURCE_IMAGE}" \
    "docker://${DEST_IMAGE}"

# Inspect the pushed digest. cosign signs by digest internally even
# when given a tag, but we need the raw digest string for the
# Referrers API GET in step [8/9].
PUSHED_DIGEST=$(skopeo inspect \
    --tls-verify=false \
    --creds "$DEST_CREDS" \
    --format '{{.Digest}}' \
    "docker://${DEST_IMAGE}")
echo "  pushed digest: $PUSHED_DIGEST"

# ---------------------------------------------------------------------
# [4/9] Generate the ephemeral signing keypair.
#
# cosign refuses to write keys with an empty passphrase unless the
# COSIGN_PASSWORD env var is set (an explicit acknowledgement that
# the key is unencrypted on disk). For a smoke test that runs in a
# disposable tempdir, that's exactly what we want.
# ---------------------------------------------------------------------
echo ""
echo "[4/9] Generate ephemeral cosign keypair"
KEYDIR=$(mktemp -d)
trap 'rm -rf "$KEYDIR"' EXIT
echo "  keydir: $KEYDIR"
(
    cd "$KEYDIR"
    COSIGN_PASSWORD="" cosign generate-key-pair
)
[ -f "${KEYDIR}/cosign.key" ] || { echo "FAIL: cosign.key not generated" >&2; exit 1; }
[ -f "${KEYDIR}/cosign.pub" ] || { echo "FAIL: cosign.pub not generated" >&2; exit 1; }

# Cosign needs registry credentials to write the signature manifest.
# COSIGN_DOCKER_MEDIA_TYPES is unset (we want OCI media types — the
# default in cosign >= 2.0). DOCKER_CONFIG points at a one-shot auth
# file so we don't pollute the user's ~/.docker/config.json.
export DOCKER_CONFIG="${KEYDIR}/docker"
mkdir -p "$DOCKER_CONFIG"
# Build a docker config with the bearer-as-password Basic auth string
# the registry expects (mirrors test-oci-skopeo.sh's --dest-creds path).
AUTH_B64=$(printf '%s' "$DEST_CREDS" | base64 -w0 2>/dev/null || printf '%s' "$DEST_CREDS" | base64 | tr -d '\n')
cat > "${DOCKER_CONFIG}/config.json" <<EOF
{
  "auths": {
    "${REGISTRY_HOST}": {
      "auth": "${AUTH_B64}"
    }
  }
}
EOF

# ---------------------------------------------------------------------
# [5/9] First sign.
#
# --tlog-upload=false  : disables Rekor (no transparency log running
#                        in CI; the keyless trust model is N/A here).
# --allow-insecure-registry : registry is plain-HTTP on localhost.
# --yes                : skip the interactive "are you sure?" prompt.
# ---------------------------------------------------------------------
echo ""
echo "[5/9] First sign: cosign sign --key cosign.key ${DEST_IMAGE}"
COSIGN_PASSWORD="" cosign sign \
    --key "${KEYDIR}/cosign.key" \
    --tlog-upload=false \
    --allow-insecure-registry \
    --yes \
    "${DEST_IMAGE}"
echo "  ok: first signature pushed"

# ---------------------------------------------------------------------
# [6/9] Verify (first).
#
# --insecure-ignore-tlog is the read-side counterpart to
# --tlog-upload=false. Without it cosign would refuse to verify
# because the signature has no Rekor inclusion proof.
# ---------------------------------------------------------------------
echo ""
echo "[6/9] Verify (first): cosign verify --key cosign.pub ${DEST_IMAGE}"
COSIGN_PASSWORD="" cosign verify \
    --key "${KEYDIR}/cosign.pub" \
    --insecure-ignore-tlog \
    --allow-insecure-registry \
    "${DEST_IMAGE}" \
    > /dev/null
echo "  ok: first verify succeeded"

# ---------------------------------------------------------------------
# [7/9] Second sign — the idempotency check.
#
# Cosign's signing protocol creates a NEW referring manifest on each
# invocation (each signature is its own descriptor in the Referrers
# response). The registry MUST keep the response well-formed; a buggy
# implementation might double-write, corrupt JSON, or 500 on the
# duplicate. This is the load-bearing assertion for Item 14.
# ---------------------------------------------------------------------
echo ""
echo "[7/9] Second sign (idempotency): cosign sign --key cosign.key ${DEST_IMAGE}"
COSIGN_PASSWORD="" cosign sign \
    --key "${KEYDIR}/cosign.key" \
    --tlog-upload=false \
    --allow-insecure-registry \
    --yes \
    "${DEST_IMAGE}"
echo "  ok: second signature pushed"

# ---------------------------------------------------------------------
# [8/9] Verify (second) AND Referrers API integrity check.
#
# cosign verify on its own confirms at least one valid signature
# exists. We then hit the Referrers API directly to confirm the
# response is OCI-image-index JSON with a manifests array — that's
# Item 13's contract, and the second sign must not have broken it.
# ---------------------------------------------------------------------
echo ""
echo "[8/9] Verify (second) + Referrers API integrity"
COSIGN_PASSWORD="" cosign verify \
    --key "${KEYDIR}/cosign.pub" \
    --insecure-ignore-tlog \
    --allow-insecure-registry \
    "${DEST_IMAGE}" \
    > /dev/null
echo "  ok: second verify succeeded"

REFERRERS_PATH="/v2/${REPO_KEY}/${TEST_IMAGE_NAME}/referrers/${PUSHED_DIGEST}"
REFERRERS_BODY=$(curl -sf \
    -H "Authorization: Bearer ${DEV_TOKEN}" \
    -H "Accept: application/vnd.oci.image.index.v1+json" \
    "${REGISTRY_URL}${REFERRERS_PATH}")

if [ -z "$REFERRERS_BODY" ]; then
    echo "FAIL: empty Referrers response" >&2
    exit 1
fi

# Parse + assert. Use jq when available (clearer error messages); fall
# back to grep for the two structural checks we actually care about:
#   - mediaType == "application/vnd.oci.image.index.v1+json"
#   - manifests is an array
if command -v jq >/dev/null 2>&1; then
    MEDIA_TYPE=$(printf '%s' "$REFERRERS_BODY" | jq -r '.mediaType // ""')
    MANIFESTS_TYPE=$(printf '%s' "$REFERRERS_BODY" | jq -r '.manifests | type')
    if [ "$MEDIA_TYPE" != "application/vnd.oci.image.index.v1+json" ]; then
        echo "FAIL: Referrers mediaType = '${MEDIA_TYPE}' (expected application/vnd.oci.image.index.v1+json)" >&2
        echo "  body: ${REFERRERS_BODY}" >&2
        exit 1
    fi
    if [ "$MANIFESTS_TYPE" != "array" ]; then
        echo "FAIL: Referrers .manifests is type '${MANIFESTS_TYPE}' (expected array)" >&2
        echo "  body: ${REFERRERS_BODY}" >&2
        exit 1
    fi
    MANIFESTS_LEN=$(printf '%s' "$REFERRERS_BODY" | jq -r '.manifests | length')
    echo "  ok: Referrers index well-formed (manifests.length=${MANIFESTS_LEN})"
else
    # Fallback: a hard-dep on jq for one assertion is silly. The
    # simple greps below cover the same structural invariants.
    if ! printf '%s' "$REFERRERS_BODY" | \
        grep -q '"mediaType"[[:space:]]*:[[:space:]]*"application/vnd.oci.image.index.v1+json"'; then
        echo "FAIL: Referrers mediaType not application/vnd.oci.image.index.v1+json" >&2
        echo "  body: ${REFERRERS_BODY}" >&2
        exit 1
    fi
    if ! printf '%s' "$REFERRERS_BODY" | \
        grep -q '"manifests"[[:space:]]*:[[:space:]]*\['; then
        echo "FAIL: Referrers .manifests is not an array" >&2
        echo "  body: ${REFERRERS_BODY}" >&2
        exit 1
    fi
    echo "  ok: Referrers index well-formed (jq-less check passed)"
fi

# ---------------------------------------------------------------------
# [9/9] Cleanup. The trap on EXIT also catches early-exit paths.
# ---------------------------------------------------------------------
echo ""
echo "[9/9] Cleanup"
rm -rf "$KEYDIR"
trap - EXIT

echo ""
echo "==> OK"
