#!/usr/bin/env bash
# requires: egress
# Capability regression: a NON-ADMIN reader pulls a PRIVATE OCI repo.
#
# Closes the original C-trace gap (the gha-ci shape the suite never drove): a
# repo-scoped reader identity, holding ONLY an explicit, repo-scoped Read grant
# on a PRIVATE repo (isPublic: false), must be able to pull it end to end —
# proving the capability model authorizes a non-admin claims-subject reader (an
# OIDC user whose resolved claims match the grant — NOT a serviceAccount-subject
# grant) on a private repo. The differential is what proves it is the GRANT
# doing the work:
#
#   1. SEED   (dev-user, holds Write on oci-private-e2e): push an image.
#   2. PULL   (reader-user, Read grant) -> MUST SUCCEED  (capability granted).
#   3. ANON   (no credentials)          -> MUST FAIL     (private repo denies
#              the unauthenticated caller — it is not an open repo).
#   4. WRITE  (reader-user, push)       -> MUST FAIL 403 (Read grant != Write —
#              the grant is capability-precise, not blanket access).
#
# The base compose stack runs OCI auth as HTTP Basic (native /v2/auth token
# exchange is off by default — only the federation overlay enables it), so the
# capability is exercised exactly as a real client does it: an OIDC bearer in
# the Basic password slot, authorized against the reader's repo-scoped Read
# grant. Seeds from ghcr.io (no Docker Hub rate-limit); needs egress.

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"

REPO_KEY="${OCI_PRIVATE_REPO_KEY:-oci-private-e2e}"
REGISTRY_HOST="${HORT_URL#http://}"
REGISTRY_HOST="${REGISTRY_HOST#https://}"

SOURCE_IMAGE="${SOURCE_IMAGE:-ghcr.io/oci-playground/hello-world:latest}"
TEST_IMAGE_NAME="${TEST_IMAGE_NAME:-privimg}"
TEST_TAG="${TEST_TAG:-v0}"

DEST_IMAGE="${REGISTRY_HOST}/${REPO_KEY}/${TEST_IMAGE_NAME}:${TEST_TAG}"

log "==> OCI private-repo reader-pull regression (skopeo)"
log "Registry:    ${HORT_URL}"
log "Repo key:    ${REPO_KEY} (private)"
log "Image:       ${DEST_IMAGE}"

command -v skopeo >/dev/null 2>&1 || skip "skopeo not found"

# --- tokens -----------------------------------------------------------------
DEV_TOKEN="$(fetch_token dev-user dev)"
[ -n "$DEV_TOKEN" ] || fail "fetch dev-user token" "empty response from IdP"
READER_TOKEN="$(fetch_token reader-user reader)"
[ -n "$READER_TOKEN" ] || fail "fetch reader-user token" "empty response from IdP"
# Abort early if either token is missing — the rest is meaningless.
if [ "$_FAIL" -gt 0 ]; then summary; fi
log "[auth] dev-user (write) + reader-user (read-only, group hort-readers) tokens fetched"

# --- Step 1: seed the private repo as dev-user ------------------------------
log "==> [1/4] Seed: push ${SOURCE_IMAGE} -> ${DEST_IMAGE} (as dev-user)"
if skopeo copy \
      --insecure-policy \
      --dest-tls-verify=false \
      --dest-creds "dev-user:${DEV_TOKEN}" \
      "docker://${SOURCE_IMAGE}" \
      "docker://${DEST_IMAGE}" 2>&1; then
  pass "seed push to the private repo succeeded"
else
  fail "seed push" "skopeo copy exited non-zero (egress? dev write grant?)"
  summary
fi

# --- Step 2: reader pull MUST SUCCEED (the capability proof) -----------------
log "==> [2/4] Pull as reader-user (Read grant) must SUCCEED"
PULLED=""
if PULLED="$(skopeo inspect \
      --tls-verify=false \
      --creds "reader-user:${READER_TOKEN}" \
      --format '{{.Digest}}' \
      "docker://${DEST_IMAGE}" 2>/dev/null)" && [ -n "$PULLED" ]; then
  pass "reader-user resolved the PRIVATE repo via its Read grant (digest ${PULLED})"
else
  fail "reader pull" "reader-user could not pull the private repo it holds a Read grant on"
fi

# --- Step 3: anonymous pull MUST FAIL (private repo) ------------------------
log "==> [3/4] Anonymous pull must FAIL (repo is private, not open)"
if skopeo inspect \
      --tls-verify=false \
      --format '{{.Digest}}' \
      "docker://${DEST_IMAGE}" >/dev/null 2>&1; then
  fail "anonymous pull on private repo" "an unauthenticated caller pulled a PRIVATE repo"
else
  pass "anonymous caller is denied the private repo"
fi

# --- Step 4: reader WRITE MUST FAIL (Read grant != Write) -------------------
# Capability precision: the same reader token that PULLS must NOT be able to
# PUSH — the grant is scoped to Read.
log "==> [4/4] Reader push must FAIL (Read grant is not Write)"
if skopeo copy \
      --insecure-policy \
      --dest-tls-verify=false \
      --dest-creds "reader-user:${READER_TOKEN}" \
      "docker://${SOURCE_IMAGE}" \
      "docker://${REGISTRY_HOST}/${REPO_KEY}/reader-should-not-push:v0" >/dev/null 2>&1; then
  fail "reader push" "a Read-only grant was allowed to PUSH (capability not scoped to Read)"
else
  pass "reader-user is denied WRITE on the private repo (grant is Read-scoped)"
fi

summary
