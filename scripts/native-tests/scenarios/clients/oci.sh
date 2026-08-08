#!/usr/bin/env bash
# requires: egress
# OCI scenario: skopeo copy round-trip — push to hort, pull back to oci-archive,
# assert digest round-trip equality (CAS guarantee).
#
# Pulls SOURCE_IMAGE from ghcr.io (no Docker Hub rate-limit); needs internet egress.

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"

REPO_KEY="${OCI_REPO_KEY:-oci-e2e}"
# Strip scheme so skopeo's docker:// transport gets host:port only.
REGISTRY_HOST="${HORT_URL#http://}"
REGISTRY_HOST="${REGISTRY_HOST#https://}"

SOURCE_IMAGE="${SOURCE_IMAGE:-ghcr.io/oci-playground/hello-world:latest}"
TEST_IMAGE_NAME="${TEST_IMAGE_NAME:-testimg}"
TEST_TAG="${TEST_TAG:-v0}"

DEST_IMAGE="${REGISTRY_HOST}/${REPO_KEY}/${TEST_IMAGE_NAME}:${TEST_TAG}"
PULLED_ARCHIVE="/tmp/oci-pulled-${TEST_IMAGE_NAME}.tar"

log "==> OCI Native Client Test (skopeo)"
log "Registry:    ${HORT_URL}"
log "Repo key:    ${REPO_KEY}"
log "Source:      ${SOURCE_IMAGE}"
log "Destination: ${DEST_IMAGE}"

# Check prerequisites
command -v skopeo >/dev/null 2>&1 || skip "skopeo not found"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"; rm -f "$PULLED_ARCHIVE"' EXIT

# -----------------------------------------------------------------------------
# Credential mode: legacy (Basic / IdP-JWT) vs native tokens.
# -----------------------------------------------------------------------------
# Under the `native-tokens` compose overlay every `/v2/*` request runs the real
# Distribution-Spec token dance, and the /v2/auth mint validates the Basic
# password strictly as a native PAT (dev-user's Keycloak JWT can never
# complete it) -- so push and pull-back ride the oci-e2e-ci service account
# instead (gitops: service-accounts/oci-e2e-ci.yaml +
# auth/oci-e2e-ci-{read,write}.yaml). Legacy (no overlay): dev-user's Keycloak
# JWT, unchanged.
NATIVE_TOKENS=0
case " ${HORT_COMPOSE_OVERLAYS:-} " in
    *" native-tokens "*) NATIVE_TOKENS=1 ;;
esac

if [ "$NATIVE_TOKENS" = "1" ]; then
    log "[auth] native-token mode: admin-minting an hort_svc_* token for service account oci-e2e-ci"
    SVC_TOKEN="$(mint_svc_token oci-e2e-ci "$REPO_KEY" read,write)" || {
        fail "admin-mint oci-e2e-ci svc token" "mint_svc_token failed -- see stderr diagnostics above"; summary; }
    DEST_CREDS="oci-e2e-ci:${SVC_TOKEN}"
    log "[auth] svc token minted; push+pull ride the oci-e2e-ci service account"
else
    DEV_TOKEN="$(fetch_token dev-user dev)"
    [ -n "$DEV_TOKEN" ] || fail "fetch dev-user token" "empty response from Keycloak"
    DEST_CREDS="dev-user:${DEV_TOKEN}"
    log "[auth] legacy mode: fetched DEV_TOKEN from Keycloak"
fi

# ---- Test 1: push ----
log "==> [1/3] Push: ${SOURCE_IMAGE} -> docker://${DEST_IMAGE}"
if skopeo copy \
      --insecure-policy \
      --dest-tls-verify=false \
      --dest-creds "$DEST_CREDS" \
      "docker://${SOURCE_IMAGE}" \
      "docker://${DEST_IMAGE}" 2>&1; then
  pass "skopeo push to hort succeeded"
else
  fail "skopeo push" "skopeo copy exited non-zero"
fi

# ---- Test 2: inspect pushed digest ----
log "==> [2/3] Inspect pushed manifest digest..."
PUSHED="$(skopeo inspect \
    --tls-verify=false \
    --creds "$DEST_CREDS" \
    --format '{{.Digest}}' \
    "docker://${DEST_IMAGE}" 2>/dev/null || true)"
if [ -n "$PUSHED" ]; then
  log "  pushed digest: $PUSHED"
  pass "inspect pushed digest succeeded"
else
  fail "inspect pushed digest" "skopeo inspect returned empty digest"
fi

# ---- Test 3: pull back + digest round-trip assertion ----
log "==> [3/3] Pull: docker://${DEST_IMAGE} -> oci-archive:${PULLED_ARCHIVE}"
rm -f "$PULLED_ARCHIVE"
if skopeo copy \
      --insecure-policy \
      --src-tls-verify=false \
      --src-creds "$DEST_CREDS" \
      "docker://${DEST_IMAGE}" \
      "oci-archive:${PULLED_ARCHIVE}" 2>&1; then
  PULLED="$(skopeo inspect --format '{{.Digest}}' "oci-archive:${PULLED_ARCHIVE}" 2>/dev/null || true)"
  log "  pulled digest: $PULLED"
  if [ "$PUSHED" = "$PULLED" ]; then
    pass "digest round-trip: pushed == pulled == $PUSHED"
  else
    fail "digest round-trip mismatch" "pushed=$PUSHED pulled=$PULLED"
  fi
else
  fail "skopeo pull" "skopeo copy to oci-archive exited non-zero"
fi

summary
