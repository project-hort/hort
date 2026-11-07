#!/usr/bin/env bash
# requires: egress
# OCI manifest DELETE by digest — the manifest goes, the blobs stay.
#
# `DELETE /v2/<repo>/<name>/manifests/<ref>` had no end-to-end exercise at all:
# the endpoint is destructive, authz-gated on its own permission, and the
# ordering inside it (artifact lifecycle delete FIRST, content-reference sweep
# second) is what decides whether the manifest's blobs survive. Unit tests
# against mocks were the only thing standing behind it.
#
# This scenario covers the DIGEST branch only. A tag reference routes through
# `RefUseCase::retire` — retiring a tag is not deleting an artifact, and
# folding it in would put two subjects in one scenario.
#
#   [1] skopeo push a small image to the fixture repo.
#   [2] Resolve its manifest digest; GET the manifest by that digest (200) and
#       record a LAYER blob digest from the body — after the delete the
#       manifest is gone and the body can never be read again.
#   [3] DELETE /v2/<repo>/<name>/manifests/<digest> -> 202. Not 200: OCI
#       clients treat the two alike here, but the spec prefers 202 for
#       asynchronous cleanup semantics.
#   [4] The IDENTICAL GET from [2] -> 404 MANIFEST_UNKNOWN. Same URL, same
#       credential, so the pair says the manifest went away rather than that
#       the read was never authorised.
#   [5] GET /v2/<repo>/<name>/blobs/<layer-digest> -> 200, non-empty. This is
#       the assertion the whole scenario exists for: the layer bytes belong to
#       the CAS and are the garbage collector's business, not the manifest
#       delete's (ADR 0003). A manifest delete that took its layers with it
#       would shred every other image sharing them.
#
# Authority: the delete is gated on `Permission::Delete` (`DeleteRepoAccess`),
# NOT `Permission::Write` — a write grant does not authorise it. Both lanes
# therefore drive a NON-ADMIN identity holding an explicit `delete` grant:
# a role-name short-circuit on an `admin` claim would make the 202 prove
# nothing about the grant. See the auth/ fixtures named in the credential
# block below.
#
# Pulls SOURCE_IMAGE from ghcr.io (no Docker Hub rate-limit); needs egress.

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"

if [ "${HORT_TEST_DEBUG:-0}" = "1" ]; then
    set -x
fi

# Dedicated fixture repo (deploy/compose/example-config/repositories/
# oci-delete-e2e.yaml + policies/oci-delete-e2e-permissive.yaml). Deliberately
# not oci-e2e: three other scenarios share that one, and granting it `delete`
# would hand them a permission they do not need while leaving this scenario's
# 202 unable to say which grant carried it.
REPO_KEY="${OCI_DELETE_REPO_KEY:-oci-delete-e2e}"

# Strip scheme so skopeo's docker:// transport gets host:port only.
REGISTRY_HOST="${HORT_URL#http://}"
REGISTRY_HOST="${REGISTRY_HOST#https://}"

SOURCE_IMAGE="${SOURCE_IMAGE:-ghcr.io/oci-playground/hello-world:latest}"
IMG="${TEST_IMAGE_NAME:-deltestimg}"
TAG="${TEST_TAG:-v0}"
DEST_IMAGE="${REGISTRY_HOST}/${REPO_KEY}/${IMG}:${TAG}"

# Both single-manifest media types: hort negotiates the stored media type
# against `Accept` and answers 406 on a mismatch, so a one-type header would
# turn a Docker-schema push into a spurious failure.
OCI_MANIFEST_MEDIA="application/vnd.oci.image.manifest.v1+json"
DOCKER_MANIFEST_MEDIA="application/vnd.docker.distribution.manifest.v2+json"
MANIFEST_ACCEPT="${OCI_MANIFEST_MEDIA}, ${DOCKER_MANIFEST_MEDIA}"

log "==> OCI manifest-DELETE-by-digest test (the manifest goes, the blobs stay)"
log "Registry:    ${HORT_URL}"
log "Repo key:    ${REPO_KEY} (permissive ScanPolicy; serves immediately)"
log "Source:      ${SOURCE_IMAGE}"
log "Destination: ${DEST_IMAGE}"

command -v skopeo >/dev/null 2>&1 || skip "skopeo not found in client image"

BLOB_BODY="$(mktemp)"
trap 'rm -f "$BLOB_BODY"' EXIT

# -----------------------------------------------------------------------------
# Credential mode: legacy (Basic / IdP-JWT) vs native tokens.
# -----------------------------------------------------------------------------
# Under the `native-tokens` compose overlay every `/v2/*` request runs the real
# Distribution-Spec token dance, and the /v2/auth mint validates the Basic
# password strictly as a native PAT (dev-user's Keycloak JWT can never
# complete it) -- so the push rides the oci-delete-e2e-ci service account
# (gitops: service-accounts/oci-delete-e2e-ci.yaml +
# auth/oci-delete-e2e-ci-{read,write,delete}.yaml). The delete and the two
# GETs are raw curl rather than skopeo's auto-negotiated transport, so they
# need an already-minted capability JWT; it is scoped `pull,delete` because
# the handler needs BOTH -- `DeleteRepoAccess` authorises the request on
# `Permission::Delete`, and `delete_by_digest` then resolves the manifest
# through `ArtifactUseCase::find_visible_by_path`, which enforces Read.
#
# Legacy (no overlay): dev-user's Keycloak JWT, used directly as the bearer.
# dev-user resolves to claims [developer, ci-pusher] and carries no `admin`
# claim, so its authority here is exactly
# auth/dev-{read,write,delete}-oci-delete-e2e.yaml.
NATIVE_TOKENS=0
case " ${HORT_COMPOSE_OVERLAYS:-} " in
    *" native-tokens "*) NATIVE_TOKENS=1 ;;
esac

# mint_cap_jwt <repo-key> <image-name> <actions> — mint a capability JWT
# scoped to <actions> on one image via the real /v2/auth exchange (Basic
# <svc-token>). Prints the JWT. Mirrors quarantine/oci-image-index.sh.
mint_cap_jwt() {
    curl -sS -u "oci-delete-e2e-ci:${SVC_TOKEN}" \
        "${HORT_URL}/v2/auth?service=${REGISTRY_HOST}&scope=repository:$1/$2:$3" \
        2>/dev/null | jq -r '.token // empty'
}

if [ "$NATIVE_TOKENS" = "1" ]; then
    log "[auth] native-token mode: admin-minting an hort_svc_* token for service account oci-delete-e2e-ci"
    # `delete` in the declared cap is itself gated: `run_issuance_gates`
    # refuses to mint a permission the subject does not hold, so this mint
    # already depends on auth/oci-delete-e2e-ci-delete.yaml.
    SVC_TOKEN="$(mint_svc_token oci-delete-e2e-ci "$REPO_KEY" read,write,delete)" || {
        fail "admin-mint oci-delete-e2e-ci svc token" "mint_svc_token failed -- see stderr diagnostics above"; summary; }
    DEST_CREDS="oci-delete-e2e-ci:${SVC_TOKEN}"
    IDENTITY="serviceAccount oci-delete-e2e-ci (non-admin by construction, ADR 0038)"
    log "[auth] svc token minted; the push rides the SA via skopeo's own token dance"
else
    DEV_TOKEN="$(fetch_token dev-user dev)"
    [ -n "$DEV_TOKEN" ] || { fail "fetch dev-user token" "empty response from Keycloak"; summary; }
    DEST_CREDS="dev-user:${DEV_TOKEN}"
    BEARER="$DEV_TOKEN"
    IDENTITY="dev-user (claims [developer, ci-pusher]; no admin claim)"
    log "[auth] legacy mode: fetched DEV_TOKEN from Keycloak (dev-user holds read+write+delete on ${REPO_KEY})"
fi
log "[auth] delete identity: ${IDENTITY}"

MANIFEST_URL_BASE="${HORT_URL}/v2/${REPO_KEY}/${IMG}/manifests"

# ---- [1/5] push the image ----
log "==> [1/5] skopeo copy docker://${SOURCE_IMAGE} -> docker://${DEST_IMAGE}"
if skopeo copy \
      --insecure-policy \
      --dest-tls-verify=false \
      --dest-creds "$DEST_CREDS" \
      "docker://${SOURCE_IMAGE}" \
      "docker://${DEST_IMAGE}" 2>&1 | sed 's/^/    /'; then
    pass "push to ${REPO_KEY} succeeded (the manifest this scenario deletes now exists)"
else
    fail "skopeo push" "skopeo copy -> ${DEST_IMAGE} exited non-zero; nothing to delete"
    summary
fi

# The capability JWT is minted HERE rather than beside the svc token above:
# the /v2/auth mint's TTL is minutes by design (it is a short-lived
# capability, not a session), and everything that presents it — the two
# manifest GETs, the DELETE, the blob GET — happens after the push. Minting
# before a slow image push would spend that TTL on the one leg that does not
# need it (skopeo negotiates its own token for the push).
if [ "$NATIVE_TOKENS" = "1" ]; then
    BEARER="$(mint_cap_jwt "$REPO_KEY" "$IMG" pull,delete)"
    [ -n "$BEARER" ] || { fail "mint pull,delete-scoped capability JWT (${REPO_KEY})" \
        "GET /v2/auth (Basic <svc-token>, scope …:pull,delete) returned no token"; summary; }
    log "[auth] minted a pull,delete-scoped capability JWT for ${REPO_KEY}/${IMG}"
fi

# ---- [2/5] resolve the manifest digest, then record a LAYER blob digest ----
# Order matters: the layer digest has to be read out of the manifest body
# BEFORE the delete. Afterwards the manifest is gone and the body is
# unrecoverable, so a scenario that deleted first would have nothing left to
# check the CAS guarantee against.
log "==> [2/5] Resolve manifest digest + record a layer blob digest"
MANIFEST_DIGEST="$(skopeo inspect \
    --tls-verify=false \
    --creds "$DEST_CREDS" \
    --format '{{.Digest}}' \
    "docker://${DEST_IMAGE}" 2>/dev/null || true)"
if [ -n "$MANIFEST_DIGEST" ]; then
    log "  manifest digest: ${MANIFEST_DIGEST}"
    pass "resolved the pushed manifest digest"
else
    fail "resolve manifest digest" "skopeo inspect returned no digest for ${DEST_IMAGE}"
    summary
fi

MANIFEST_RESP="$(curl -sS -w '\n%{http_code}' \
    -H "Authorization: Bearer ${BEARER}" \
    -H "Accept: ${MANIFEST_ACCEPT}" \
    "${MANIFEST_URL_BASE}/${MANIFEST_DIGEST}" 2>/dev/null || true)"
MANIFEST_CODE="${MANIFEST_RESP##*$'\n'}"
MANIFEST_BODY="${MANIFEST_RESP%$'\n'*}"
if [ "$MANIFEST_CODE" = "200" ]; then
    pass "GET /manifests/<digest> before the delete -> 200 (the baseline [4/5] is compared against)"
else
    fail "GET /manifests/<digest> before the delete -> 200" \
         "got HTTP ${MANIFEST_CODE} -- $(printf '%s' "$MANIFEST_BODY" | head -c 300)"
    summary
fi

LAYER_DIGEST="$(printf '%s' "$MANIFEST_BODY" | jq -r '.layers[0].digest // empty' 2>/dev/null || true)"
if [ -n "$LAYER_DIGEST" ]; then
    log "  layer blob digest: ${LAYER_DIGEST}"
    pass "recorded a layer blob digest from the live manifest body"
else
    fail "record a layer blob digest" \
         "the served manifest carried no .layers[0].digest (mediaType '$(printf '%s' "$MANIFEST_BODY" | jq -r '.mediaType // "<none>"' 2>/dev/null || true)'). An index-shaped push would land here: this scenario pushes a single-platform image on purpose -- override SOURCE_IMAGE with one if the default has become multi-arch-only"
    summary
fi

BLOB_URL="${HORT_URL}/v2/${REPO_KEY}/${IMG}/blobs/${LAYER_DIGEST}"

# ---- [3/5] DELETE the manifest by digest -> 202 ----
# 202 and not 200: the handler answers ACCEPTED because the spec prefers it
# for asynchronous cleanup semantics (OCI clients treat the two alike here).
log "==> [3/5] DELETE ${MANIFEST_URL_BASE}/${MANIFEST_DIGEST}"
DELETE_RESP="$(curl -sS -w '\n%{http_code}' -X DELETE \
    -H "Authorization: Bearer ${BEARER}" \
    "${MANIFEST_URL_BASE}/${MANIFEST_DIGEST}" 2>/dev/null || true)"
DELETE_CODE="${DELETE_RESP##*$'\n'}"
DELETE_BODY="${DELETE_RESP%$'\n'*}"
if [ "$DELETE_CODE" = "202" ]; then
    pass "DELETE /manifests/<digest> -> 202 Accepted (authorised by the repo's delete grant, not its write grant)"
else
    fail "DELETE /manifests/<digest> -> 202" \
         "got HTTP ${DELETE_CODE} -- $(printf '%s' "$DELETE_BODY" | head -c 300). A 401/403 means the delete grant did not carry it (DeleteRepoAccess runs against Permission::Delete, so a write grant is not enough); a 200 means the handler stopped preferring 202 for asynchronous cleanup"
    summary
fi

# ---- [4/5] the manifest is gone: same GET -> 404 MANIFEST_UNKNOWN ----
log "==> [4/5] GET the same digest again (must be gone)"
GONE_RESP="$(curl -sS -w '\n%{http_code}' \
    -H "Authorization: Bearer ${BEARER}" \
    -H "Accept: ${MANIFEST_ACCEPT}" \
    "${MANIFEST_URL_BASE}/${MANIFEST_DIGEST}" 2>/dev/null || true)"
GONE_CODE="${GONE_RESP##*$'\n'}"
GONE_BODY="${GONE_RESP%$'\n'*}"
if [ "$GONE_CODE" = "404" ]; then
    pass "GET /manifests/<digest> after the delete -> 404 (the manifest is gone; same URL + credential as the 200 in [2/5])"
else
    fail "GET /manifests/<digest> after the delete -> 404" \
         "got HTTP ${GONE_CODE} -- $(printf '%s' "$GONE_BODY" | head -c 300). A 200 means the delete reported 202 without removing anything"
fi
GONE_ERR="$(printf '%s' "$GONE_BODY" | jq -r '.errors[0].code // empty' 2>/dev/null || true)"
if [ "$GONE_ERR" = "MANIFEST_UNKNOWN" ]; then
    pass "the 404 carries the spec envelope code MANIFEST_UNKNOWN"
else
    fail "404 envelope code is MANIFEST_UNKNOWN" \
         "got '${GONE_ERR:-<none>}' -- a deleted manifest must read as a spec-shaped miss to an OCI client"
fi

# ---- [5/5] the layer blob STILL resolves ----
# The point of the whole scenario. `ArtifactUseCase::delete` is an
# event-sourced soft delete of the MANIFEST artifact, and the sweep that
# follows drops the manifest's content-reference edges -- neither touches the
# layer's CAS bytes, which other images may share and which only the storage
# GC is allowed to reclaim (ADR 0003). If this goes 404/503, a manifest delete
# has started destroying content it does not own.
log "==> [5/5] GET ${BLOB_URL} (the layer must survive the manifest)"
BLOB_CODE="$(curl -sS -o "$BLOB_BODY" -w '%{http_code}' \
    -H "Authorization: Bearer ${BEARER}" \
    "$BLOB_URL" 2>/dev/null || echo 000)"
BLOB_BYTES="$(wc -c <"$BLOB_BODY" | tr -d '[:space:]')"
if [ "$BLOB_CODE" != "200" ]; then
    fail "layer blob survives the manifest delete" \
         "got HTTP ${BLOB_CODE} for ${LAYER_DIGEST} (${BLOB_BYTES} bytes read) -- the manifest delete must not reach the layer bytes: they are CAS content, possibly shared with other images, and only storage GC may reclaim them"
elif [ "${BLOB_BYTES:-0}" -gt 0 ]; then
    pass "GET /blobs/<layer-digest> after the manifest delete -> 200, ${BLOB_BYTES} bytes (the CAS kept the content)"
else
    fail "surviving layer blob serves its bytes" \
         "HTTP 200 with a 0-byte body for ${LAYER_DIGEST} -- the row outlived the bytes"
fi

summary
