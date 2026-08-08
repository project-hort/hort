#!/usr/bin/env bash
# requires: egress db
# Capability regression: a NON-ADMIN reader pulls a PRIVATE OCI repo, AND the
# read-path challenge-before-anti-enumeration contract holds (issue #19,
# docs/plans/oci-read-challenge-and-token-parity.md D1/D2).
#
# Closes the original C-trace gap (the gha-ci shape the suite never drove): a
# repo-scoped reader identity, holding ONLY an explicit, repo-scoped Read grant
# on a PRIVATE repo (isPublic: false), must be able to pull it end to end —
# proving the capability model authorizes a non-admin reader on a private repo
# via a grant precise to Read (Write stays denied). It also proves the D1/D2
# read-path fix: an unauthenticated read of a private repo now gets a 401 +
# `WWW-Authenticate` challenge instead of a bare 404 (so a lazy-challenge
# client — containerd, kubelet — actually gets a chance to present its
# imagePullSecret), and that the challenge is byte-identical (status + scheme)
# for a genuinely nonexistent repo (the anti-enumeration uniformity ADR 0021
# requires).
#
#   0. PROBE   GET /v2/ (anonymous) -> capture the deployed WWW-Authenticate
#              scheme. This is the ONLY fork point: every credential choice
#              and assertion below adapts to THIS value alone (no separate
#              HORT_COMPOSE_OVERLAYS branch) — exactly how a real client
#              discovers the mode.
#   1. SEED    (push-role identity, holds Write on oci-private-e2e): push an
#              image.
#   2. PULL    (read-role identity, Read grant) -> MUST SUCCEED (capability
#              granted).
#   3. CHALLENGE curl-level assertions (issue #19 / D1-D2, see below).
#   4. ANON    (no credentials)          -> MUST FAIL     (private repo denies
#              the unauthenticated caller — it is not an open repo).
#   5. WRITE   (read-role identity, push) -> MUST FAIL 403 (Read grant != Write
#              — the grant is capability-precise, not blanket access).
#
# -----------------------------------------------------------------------------
# CREDENTIALS ARE MODE-DEPENDENT, NOT JUST THE CHALLENGE-FLOW ASSERTIONS.
# -----------------------------------------------------------------------------
# Once native tokens are on, `GET /v2/` (and every other unauthenticated
# `/v2/*` request, per D1) challenges Bearer, so skopeo's own auto-discovery
# always drives its authenticated requests through the real `/v2/auth` mint —
# which validates the Basic password strictly as a native PAT (D5/ADR 0036).
# A claims-subject OIDC identity (dev-user / reader-user, the legacy-mode
# principals) can never complete that mint, so steps 1/2/5 need native
# `hort_svc_*` credentials under the Bearer scheme, not merely the new step-3
# curl checks. Two dedicated service accounts back this, mirroring the
# already-established provenance-ci pattern
# (scripts/native-tests/scenarios/quarantine/provenance-push-then-sign.sh):
#   - `oci-private-e2e-writer` (write-only grant) — push role, step 1.
#   - `oci-private-e2e-reader` (read-only grant)  — pull role, steps 2/3/5.
# Both are inert in legacy (no-overlay) mode: the SA rows exist, nothing
# mints for them, and the scenario keeps using dev-user/reader-user's OIDC
# tokens exactly as before. The mode probe (step 0) is the single switch.
#
# -----------------------------------------------------------------------------
# STEP 3 — CHALLENGE-FLOW ASSERTIONS (curl-level, mode-adaptive)
# -----------------------------------------------------------------------------
# Runs right after step 1, reusing the image it just seeded. Asserts, via raw
# `curl` (not skopeo — skopeo's own auto-discovery would hide exactly the
# defect this proves fixed):
#
#   (a) [step 0] GET /v2/ (anonymous) challenges with a scheme — Bearer under
#       the native-tokens overlay, Basic otherwise.
#   (b) an unauthenticated GET *and* HEAD of the just-seeded PRIVATE manifest
#       returns 401 with the SAME scheme as (a) — previously a bare 404 with
#       NO challenge at all (issue #19): a lazy-challenge client (containerd's
#       resolver, kubelet) never pings /v2/ first, so it never got a chance to
#       present its imagePullSecret.
#   (c) an unauthenticated GET of a repo that does not exist AT ALL (not just
#       a missing image inside an existing repo) returns the IDENTICAL
#       status + scheme as (b) — the anti-enumeration uniformity ADR 0021
#       requires: {private-existing, nonexistent} must stay indistinguishable
#       to an anonymous caller.
#   (d) the challenge flow then completes with a valid reader credential, in
#       the mode-appropriate way, and the read succeeds (200):
#         - Basic mode: reuses the SAME reader-user OIDC credential step [2]
#           already proved reads the private repo (Basic-as-JWT, validated
#           directly with no mint round-trip) — an IdP JWT can NEVER complete
#           the native `/v2/auth` mint, so it is the mode-appropriate
#           credential here, not a coincidence.
#         - Native mode: drives the REAL Distribution-Spec dance with the
#           already-minted `oci-private-e2e-reader` token: `Basic
#           <svc-token>` -> `/v2/auth` -> `Bearer <jwt>` -> GET -> 200.

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
MANIFEST_URL="${HORT_URL}/v2/${REPO_KEY}/${TEST_IMAGE_NAME}/manifests/${TEST_TAG}"
# A repo_key never declared in gitops — genuinely nonexistent, not merely an
# unknown image inside an existing repo (those two collapse to the SAME
# anonymous 401 for a DIFFERENT reason: repo-level visibility is checked
# before image resolution, so they wouldn't isolate the "nonexistent repo"
# row of the D1 table on their own).
NONEXISTENT_URL="${HORT_URL}/v2/zzz-nonexistent-repo-oci-private-pull-e2e/img/manifests/latest"

log "==> OCI private-repo reader-pull regression (skopeo) + challenge-flow assertions (curl)"
log "Registry:    ${HORT_URL}"
log "Repo key:    ${REPO_KEY} (private)"
log "Image:       ${DEST_IMAGE}"

command -v skopeo >/dev/null 2>&1 || skip "skopeo not found"

# --- curl-level helpers (challenge-flow assertions, steps 0 + 3) -----------

# http_status_get/head <url> -> HTTP status code only, "000" on a curl-level
# failure (network/timeout) rather than aborting the scenario under
# `set -euo pipefail`.
http_status_get() { curl -s -o /dev/null -w '%{http_code}' "$1" 2>/dev/null || echo 000; }
http_status_head() { curl -s -o /dev/null -w '%{http_code}' -I "$1" 2>/dev/null || echo 000; }

# www_auth_scheme_get/head <url> -> lowercased first token of the
# `WWW-Authenticate` response header (e.g. "bearer"/"basic"), empty string if
# absent or on a curl-level failure. Mirrors the `docker-content-digest`
# header-extraction idiom used elsewhere in this suite
# (provenance-push-then-sign.sh): `curl ... | tr -d '\r' | awk -F': ' ... || true`
# — the trailing `|| true` keeps a transient curl failure from aborting the
# whole scenario under `pipefail` (the pipeline's exit status would otherwise
# be curl's).
www_auth_scheme_get() {
  curl -sS -o /dev/null -D - "$1" 2>/dev/null | tr -d '\r' \
    | awk -F': ' 'tolower($1)=="www-authenticate"{print tolower($2); exit}' \
    | awk '{print $1}' || true
}
www_auth_scheme_head() {
  curl -sSI "$1" 2>/dev/null | tr -d '\r' \
    | awk -F': ' 'tolower($1)=="www-authenticate"{print tolower($2); exit}' \
    | awk '{print $1}' || true
}

# =============================================================================
# Step 0: probe GET /v2/ (anonymous) for the deployed WWW-Authenticate scheme.
# =============================================================================
log "==> [0/5] Probe GET /v2/ (anonymous) for the deployed WWW-Authenticate scheme"
V2_STATUS="$(http_status_get "${HORT_URL}/v2/")"
V2_SCHEME="$(www_auth_scheme_get "${HORT_URL}/v2/")"
if [ "$V2_STATUS" = "401" ] && { [ "$V2_SCHEME" = "bearer" ] || [ "$V2_SCHEME" = "basic" ]; }; then
  pass "GET /v2/ (anonymous) -> 401 + WWW-Authenticate: ${V2_SCHEME} (deployed mode)"
else
  fail "probe GET /v2/ for challenge scheme" \
       "status=${V2_STATUS} scheme='${V2_SCHEME}' (want 401 + bearer|basic) -- cannot determine mode, aborting"
  summary
fi
MODE="$V2_SCHEME"

# --- credentials, mode-appropriate (see the header comment) -----------------
DEV_TOKEN="$(fetch_token dev-user dev)"
[ -n "$DEV_TOKEN" ] || fail "fetch dev-user token" "empty response from IdP"
READER_TOKEN="$(fetch_token reader-user reader)"
[ -n "$READER_TOKEN" ] || fail "fetch reader-user token" "empty response from IdP"
# Abort early if either token is missing — the rest is meaningless.
if [ "$_FAIL" -gt 0 ]; then summary; fi

if [ "$MODE" = "bearer" ]; then
  # Native mode: the /v2/auth mint validates the Basic password strictly as a
  # native PAT (D5/ADR 0036) -- dev-user/reader-user's IdP JWTs can never
  # complete it, so push/pull ride dedicated serviceAccount-subject
  # identities instead (gitops: service-accounts/oci-private-e2e-{writer,
  # reader}.yaml + auth/oci-private-e2e-{writer,reader}-{write,read}.yaml).
  WRITER_SVC_TOKEN="$(mint_svc_token oci-private-e2e-writer "$REPO_KEY" write)" || {
      fail "admin-mint oci-private-e2e-writer svc token" "mint_svc_token failed -- see stderr diagnostics above"; summary; }
  READER_SVC_TOKEN="$(mint_svc_token oci-private-e2e-reader "$REPO_KEY" read)" || {
      fail "admin-mint oci-private-e2e-reader svc token" "mint_svc_token failed -- see stderr diagnostics above"; summary; }
  PUSH_CREDS="oci-private-e2e-writer:${WRITER_SVC_TOKEN}"
  PULL_CREDS="oci-private-e2e-reader:${READER_SVC_TOKEN}"
  log "[auth] native-token mode: admin-minted hort_svc_* tokens for oci-private-e2e-writer (push) + oci-private-e2e-reader (pull)"
else
  PUSH_CREDS="dev-user:${DEV_TOKEN}"
  PULL_CREDS="reader-user:${READER_TOKEN}"
  log "[auth] legacy mode: dev-user (write) + reader-user (read-only, group hort-readers) OIDC tokens"
fi

# --- Step 1: seed the private repo (push-role identity) ---------------------
log "==> [1/5] Seed: push ${SOURCE_IMAGE} -> ${DEST_IMAGE} (push-role identity)"
if skopeo copy \
      --insecure-policy \
      --dest-tls-verify=false \
      --dest-creds "$PUSH_CREDS" \
      "docker://${SOURCE_IMAGE}" \
      "docker://${DEST_IMAGE}" 2>&1; then
  pass "seed push to the private repo succeeded"
else
  fail "seed push" "skopeo copy exited non-zero (egress? write grant?)"
  summary
fi

# --- Step 2: reader pull MUST SUCCEED (the capability proof) -----------------
log "==> [2/5] Pull as the read-role identity (Read grant) must SUCCEED"
PULLED=""
if PULLED="$(skopeo inspect \
      --tls-verify=false \
      --creds "$PULL_CREDS" \
      --format '{{.Digest}}' \
      "docker://${DEST_IMAGE}" 2>/dev/null)" && [ -n "$PULLED" ]; then
  pass "read-role identity resolved the PRIVATE repo via its Read grant (digest ${PULLED})"
else
  fail "reader pull" "the read-role identity could not pull the private repo it holds a Read grant on"
fi

# =============================================================================
# Step 3: challenge-flow assertions (curl-level) — see the header comment.
# =============================================================================
log "==> [3/5] Challenge-flow assertions: 401 uniformity + completion"

log "  -- unauthenticated GET of the seeded PRIVATE manifest -> 401 + matching scheme"
PRIV_GET_STATUS="$(http_status_get "$MANIFEST_URL")"
PRIV_GET_SCHEME="$(www_auth_scheme_get "$MANIFEST_URL")"
if [ "$PRIV_GET_STATUS" = "401" ] && [ "$PRIV_GET_SCHEME" = "$MODE" ]; then
  pass "anonymous GET of the private manifest -> 401 + ${MODE} challenge (not a bare 404 -- issue #19 fix)"
else
  fail "anonymous GET private manifest -> 401 + matching challenge" \
       "status=${PRIV_GET_STATUS} scheme='${PRIV_GET_SCHEME}' (want 401 + ${MODE})"
fi

log "  -- unauthenticated HEAD of the seeded PRIVATE manifest -> 401 + matching scheme"
PRIV_HEAD_STATUS="$(http_status_head "$MANIFEST_URL")"
PRIV_HEAD_SCHEME="$(www_auth_scheme_head "$MANIFEST_URL")"
if [ "$PRIV_HEAD_STATUS" = "401" ] && [ "$PRIV_HEAD_SCHEME" = "$MODE" ]; then
  pass "anonymous HEAD of the private manifest -> 401 + ${MODE} challenge"
else
  fail "anonymous HEAD private manifest -> 401 + matching challenge" \
       "status=${PRIV_HEAD_STATUS} scheme='${PRIV_HEAD_SCHEME}' (want 401 + ${MODE})"
fi

log "  -- unauthenticated GET of a NONEXISTENT repo -> identical to the private-existing case"
NONE_STATUS="$(http_status_get "$NONEXISTENT_URL")"
NONE_SCHEME="$(www_auth_scheme_get "$NONEXISTENT_URL")"
if [ "$NONE_STATUS" = "$PRIV_GET_STATUS" ] && [ "$NONE_SCHEME" = "$PRIV_GET_SCHEME" ]; then
  pass "anonymous GET of a nonexistent repo == private-existing case (status=${NONE_STATUS}, scheme=${NONE_SCHEME}; anti-enumeration uniformity, ADR 0021)"
else
  fail "nonexistent-repo anonymous GET matches private-existing case" \
       "nonexistent: status=${NONE_STATUS} scheme='${NONE_SCHEME}' vs private-existing: status=${PRIV_GET_STATUS} scheme='${PRIV_GET_SCHEME}'"
fi

log "  -- complete the challenge flow with a reader credential (${MODE} mode) -> 200"
CHALLENGE_GET_STATUS="000"
if [ "$MODE" = "bearer" ]; then
  # Native mode: drive the REAL Distribution-Spec dance against /v2/auth with
  # the already-minted reader SA token (Basic <svc-token> -> Bearer <jwt>).
  MINTED_JWT="$(curl -sS -u "$PULL_CREDS" \
      "${HORT_URL}/v2/auth?service=${REGISTRY_HOST}&scope=repository:${REPO_KEY}/${TEST_IMAGE_NAME}:pull" \
      2>/dev/null | jq -r '.token // empty')"
  if [ -z "$MINTED_JWT" ]; then
    fail "mint OCI capability JWT (/v2/auth, native mode)" "GET /v2/auth (Basic svc-token) returned no token"
  else
    CHALLENGE_GET_STATUS="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${MINTED_JWT}" "$MANIFEST_URL" 2>/dev/null || echo 000)"
  fi
else
  # Basic mode: the native /v2/auth mint validates the Basic password
  # strictly as a native PAT -- a claims-subject OIDC identity can NEVER
  # complete it, so the mode-appropriate credential here is the SAME
  # reader-user OIDC bearer step [2/5] already proved reads the private repo.
  CHALLENGE_GET_STATUS="$(curl -s -o /dev/null -w '%{http_code}' -u "$PULL_CREDS" "$MANIFEST_URL" 2>/dev/null || echo 000)"
fi
if [ "$CHALLENGE_GET_STATUS" = "200" ]; then
  pass "challenge flow completes: a valid reader credential after the 401 -> 200 (${MODE} mode)"
else
  fail "challenge flow completion -> 200" "got HTTP ${CHALLENGE_GET_STATUS} after presenting a valid reader credential (${MODE} mode)"
fi

# --- Step 4: anonymous pull MUST FAIL (private repo) ------------------------
log "==> [4/5] Anonymous pull must FAIL (repo is private, not open)"
if skopeo inspect \
      --tls-verify=false \
      --format '{{.Digest}}' \
      "docker://${DEST_IMAGE}" >/dev/null 2>&1; then
  fail "anonymous pull on private repo" "an unauthenticated caller pulled a PRIVATE repo"
else
  pass "anonymous caller is denied the private repo"
fi

# --- Step 5: reader WRITE MUST FAIL (Read grant != Write) -------------------
# Capability precision: the same read-role identity that PULLS must NOT be
# able to PUSH — the grant is scoped to Read.
log "==> [5/5] Reader push must FAIL (Read grant is not Write)"
if skopeo copy \
      --insecure-policy \
      --dest-tls-verify=false \
      --dest-creds "$PULL_CREDS" \
      "docker://${SOURCE_IMAGE}" \
      "docker://${REGISTRY_HOST}/${REPO_KEY}/reader-should-not-push:v0" >/dev/null 2>&1; then
  fail "reader push" "a Read-only grant was allowed to PUSH (capability not scoped to Read)"
else
  pass "read-role identity is denied WRITE on the private repo (grant is Read-scoped)"
fi

summary
