#!/usr/bin/env bash
# requires: egress
# OCI image-index / manifest-list push — the regression gate for issue #15.
#
# Before this initiative hort rejected an image-index PUT with
# `MANIFEST_INVALID` ("manifest list / index not yet supported"), so a
# `skopeo copy --all` of a multi-arch image (or any push-then-sign of an
# index-shaped image, issue #13) failed. The E2E never exercised an
# index-shaped push, so the gap shipped. This scenario is that missing gate:
# it pushes a genuine multi-arch OCI image index and asserts the index PUT is
# ACCEPTED, HEAD-by-index-digest works, the index is SERVED with the correct
# index Content-Type, and — under a quarantine hold — the write-authorized
# manifest HEAD is exempted (200) while the content GET stays held (503) and an
# anonymous HEAD is held (503).
#
# Two hosted OCI repos, two phases:
#
#   A) oci-e2e (permissive, quarantineDuration 0s) — the plain hosted path:
#        [A1] skopeo copy --all <multi-arch src> -> :v0  — index PUT accepted
#             (was MANIFEST_INVALID); children pushed before the index.
#        [A2] resolve the index (top-level) digest — the digest cosign would
#             sign for an index-shaped push-then-sign.
#        [A3] write-authorized HEAD /manifests/<index-digest> -> 200/exists.
#        [A4] GET /manifests/<index-digest> -> 200, Content-Type is an index
#             media-type (application/vnd.oci.image.index.v1+json or the Docker
#             manifest-list sibling), Docker-Content-Digest echoes the digest.
#
#   B) oci-quarantine-e2e (24h hold) — the issue-#13 exemption on an INDEX:
#        [B1] skopeo copy --all <multi-arch src> -> :v0  — index PUT accepted,
#             held on ingest.
#        [B2] resolve the index digest from a write-authorized HEAD-by-tag
#             Docker-Content-Digest header (a GET is 503 under the hold, so we
#             cannot skopeo-inspect it — mirror the header trick the #14
#             push-then-sign scenario uses).
#        [B3] write-authorized HEAD-by-index-digest -> 200 (the existence-probe
#             exemption, so a signer's cosign preflight can resolve the index
#             digest and attach a signature).
#        [B4] write-authorized GET-by-index-digest -> 503 (the content hold is
#             intact; the exemption released only the existence probe).
#        [B5] anonymous HEAD-by-index-digest -> 503 (the exemption is
#             write-authorized only).
#
# Multi-arch source (needs egress). ghcr.io/stefanprodan/podinfo is a genuine
# OCI image index (mediaType application/vnd.oci.image.index.v1+json), so the
# strict index Content-Type is exercised; override MULTI_SRC for a Docker
# manifest list. Pulls from ghcr.io (no Docker Hub rate-limit).

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"

if [ "${HORT_TEST_DEBUG:-0}" = "1" ]; then
    set -x
fi

# Permissive hosted repo (serves immediately; quarantineDuration 0s) and the
# 24h-hold repo. dev-user carries [developer, ci-pusher] -> write on both
# (deploy/compose/example-config/auth/dev-write-oci-e2e.yaml,
#  dev-write-oci-quarantine-e2e.yaml).
REPO_OPEN="${OCI_INDEX_OPEN_REPO_KEY:-oci-e2e}"
REPO_HOLD="${OCI_INDEX_HOLD_REPO_KEY:-oci-quarantine-e2e}"

# A genuine multi-arch image index. Default is an OCI image index so [A4] sees
# `application/vnd.oci.image.index.v1+json`; the assertion also accepts the
# Docker manifest-list sibling for a manifest-list source.
MULTI_SRC="${MULTI_SRC:-ghcr.io/stefanprodan/podinfo:latest}"

OCI_INDEX_MEDIA="application/vnd.oci.image.index.v1+json"
DOCKER_LIST_MEDIA="application/vnd.docker.distribution.manifest.list.v2+json"

# Strip scheme so skopeo's docker:// transport gets host:port only.
REGISTRY_HOST="${HORT_URL#http://}"
REGISTRY_HOST="${REGISTRY_HOST#https://}"

IMG="idxtestimg"
DEST_OPEN="${REGISTRY_HOST}/${REPO_OPEN}/${IMG}:v0"
DEST_HOLD="${REGISTRY_HOST}/${REPO_HOLD}/${IMG}:v0"

log "==> OCI image-index push test (skopeo copy --all) — issue #15 regression gate"
log "Registry    : ${HORT_URL}"
log "Open repo   : ${REPO_OPEN} (permissive; serves immediately)"
log "Hold repo   : ${REPO_HOLD} (24h quarantine hold)"
log "Multi-arch  : ${MULTI_SRC}"

command -v skopeo >/dev/null 2>&1 || skip "skopeo not found in client image"

# dev-user is the write-authorized pusher (mirrors the other OCI scenarios).
DEV_TOKEN="$(fetch_token dev-user dev)"
[ -n "$DEV_TOKEN" ] || { fail "fetch dev-user token" "empty response from Keycloak"; summary; }
DEST_CREDS="dev-user:${DEV_TOKEN}"
log "[auth] fetched DEV_TOKEN from Keycloak (dev-user write-authorized for ${REPO_OPEN} + ${REPO_HOLD})"

# code_of <method> <bearer|""> <url> — HTTP status of a HEAD (-I) or GET.
# `--head` on a HEAD so curl doesn't wait for a body; an empty bearer means an
# anonymous request (no Authorization header).
code_of() {
    local method="$1" bearer="$2" url="$3"
    local -a auth=()
    [ -n "$bearer" ] && auth=(-H "Authorization: Bearer ${bearer}")
    if [ "$method" = "HEAD" ]; then
        curl -s -o /dev/null -w '%{http_code}' -I \
            -H "Accept: ${OCI_INDEX_MEDIA}, ${DOCKER_LIST_MEDIA}" \
            "${auth[@]}" "$url" 2>/dev/null || echo 000
    else
        curl -s -o /dev/null -w '%{http_code}' \
            -H "Accept: ${OCI_INDEX_MEDIA}, ${DOCKER_LIST_MEDIA}" \
            "${auth[@]}" "$url" 2>/dev/null || echo 000
    fi
}

# head_digest <bearer> <manifests-ref-url> — Docker-Content-Digest of a
# write-authorized HEAD. Works under a hold (the write-auth HEAD is exempted),
# so it resolves the index digest without a GET.
head_digest() {
    curl -sSI -H "Authorization: Bearer $1" \
        -H "Accept: ${OCI_INDEX_MEDIA}, ${DOCKER_LIST_MEDIA}" \
        "$2" 2>/dev/null \
        | tr -d '\r' | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}'
}

# =============================================================================
# PHASE A — permissive hosted repo (oci-e2e): PUT accepted + HEAD + served
# =============================================================================

# ---- [A1] push the image INDEX (--all): the index PUT must be accepted ----
log "==> [A1] skopeo copy --all docker://${MULTI_SRC} -> docker://${DEST_OPEN}"
if skopeo copy --all \
      --insecure-policy \
      --dest-tls-verify=false \
      --dest-creds "$DEST_CREDS" \
      "docker://${MULTI_SRC}" \
      "docker://${DEST_OPEN}" 2>&1 | sed 's/^/    /'; then
    pass "image-index PUT accepted on ${REPO_OPEN} (was MANIFEST_INVALID before issue #15)"
else
    fail "image-index PUT accepted" \
         "skopeo copy --all -> ${DEST_OPEN} exited non-zero — the index PUT was rejected (the #15 regression: 'manifest list / index not yet supported')"
    summary
fi

# ---- [A2] resolve the top-level INDEX digest (what cosign would sign) ----
# The Docker-Content-Digest of a write-authorized HEAD-by-tag is the top-level
# index digest (skopeo pushed `--all`, so the tag points at the index, not a
# platform child). This is the same header trick the #14 push-then-sign
# scenario uses, and it works under a hold too (used again in [B2]).
OPEN_DIGEST="$(head_digest "$DEV_TOKEN" \
    "${HORT_URL}/v2/${REPO_OPEN}/${IMG}/manifests/v0")"
[ -n "$OPEN_DIGEST" ] || { fail "resolve index digest (${REPO_OPEN})" \
    "the write-authorized HEAD-by-tag returned no Docker-Content-Digest for the pushed index"; summary; }
log "[A2] index digest on ${REPO_OPEN} = ${OPEN_DIGEST}"

# ---- [A3] write-authorized HEAD-by-index-digest -> 200 ----
A3_CODE="$(code_of HEAD "$DEV_TOKEN" \
    "${HORT_URL}/v2/${REPO_OPEN}/${IMG}/manifests/${OPEN_DIGEST}")"
if [ "$A3_CODE" = "200" ]; then
    pass "write-authorized HEAD /manifests/<index-digest> -> 200 (index exists + resolvable by digest)"
else
    fail "HEAD-by-index-digest -> 200" \
         "got HTTP ${A3_CODE} on ${REPO_OPEN} (a served index must be HEAD-resolvable by its own digest)"
fi

# ---- [A4] GET-by-index-digest -> 200 with an index Content-Type ----
log "==> [A4] GET /manifests/<index-digest> -> served with an index Content-Type"
HDRS="$(curl -sSI -H "Authorization: Bearer ${DEV_TOKEN}" \
    -H "Accept: ${OCI_INDEX_MEDIA}, ${DOCKER_LIST_MEDIA}" \
    "${HORT_URL}/v2/${REPO_OPEN}/${IMG}/manifests/${OPEN_DIGEST}" 2>/dev/null | tr -d '\r')"
A4_CODE="$(printf '%s\n' "$HDRS" | awk 'NR==1{print $2}')"
A4_CT="$(printf '%s\n' "$HDRS" | awk -F': ' 'tolower($1)=="content-type"{print $2}')"
A4_DCD="$(printf '%s\n' "$HDRS" | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}')"
if [ "$A4_CODE" = "200" ]; then
    pass "GET /manifests/<index-digest> -> 200 (index served by digest)"
else
    fail "GET-by-index-digest -> 200" "got HTTP ${A4_CODE} on ${REPO_OPEN} (a released index must be servable by digest)"
fi
case "$A4_CT" in
    "$OCI_INDEX_MEDIA"|"$DOCKER_LIST_MEDIA")
        pass "index Content-Type preserved: ${A4_CT}" ;;
    *)
        fail "index Content-Type" \
             "served Content-Type '${A4_CT:-<none>}' is not an image-index media-type (expected ${OCI_INDEX_MEDIA} or ${DOCKER_LIST_MEDIA}) — the index media-type was mislabeled on serve" ;;
esac
if [ "$A4_DCD" = "$OPEN_DIGEST" ]; then
    pass "Docker-Content-Digest echoes the index digest (${A4_DCD})"
else
    fail "Docker-Content-Digest = index digest" "header '${A4_DCD:-<none>}' != requested '${OPEN_DIGEST}'"
fi

# =============================================================================
# PHASE B — quarantine hold (oci-quarantine-e2e): HEAD exempt, GET held
# =============================================================================

# ---- [B1] push the INDEX to the hold repo: PUT accepted, then held ----
log "==> [B1] skopeo copy --all docker://${MULTI_SRC} -> docker://${DEST_HOLD}"
if skopeo copy --all \
      --insecure-policy \
      --dest-tls-verify=false \
      --dest-creds "$DEST_CREDS" \
      "docker://${MULTI_SRC}" \
      "docker://${DEST_HOLD}" 2>&1 | sed 's/^/    /'; then
    pass "image-index PUT accepted on ${REPO_HOLD} (write path ungated by the hold; index held on ingest)"
else
    fail "image-index PUT accepted (hold repo)" \
         "skopeo copy --all -> ${DEST_HOLD} exited non-zero (a hosted index PUT to a quarantining repo must still be accepted)"
    summary
fi

# ---- [B2] resolve the index digest via the write-authorized HEAD-by-tag ----
# A GET/inspect is 503 under the hold, so use the Docker-Content-Digest of the
# write-authorized HEAD-by-tag (the existence-probe exemption serves it).
HOLD_DIGEST="$(head_digest "$DEV_TOKEN" \
    "${HORT_URL}/v2/${REPO_HOLD}/${IMG}/manifests/v0")"
[ -n "$HOLD_DIGEST" ] || { fail "resolve index digest (${REPO_HOLD})" \
    "write-authorized HEAD-by-tag returned no Docker-Content-Digest for the held index"; summary; }
log "[B2] held index digest on ${REPO_HOLD} = ${HOLD_DIGEST}"

# ---- [B3] write-authorized HEAD-by-index-digest -> 200 (exemption) ----
B3_CODE="$(code_of HEAD "$DEV_TOKEN" \
    "${HORT_URL}/v2/${REPO_HOLD}/${IMG}/manifests/${HOLD_DIGEST}")"
if [ "$B3_CODE" = "200" ]; then
    pass "write-authorized HEAD /manifests/<index-digest> on HELD index -> 200 (existence-probe exemption; signer can attach)"
else
    fail "write-authorized HEAD on held index -> 200" \
         "got HTTP ${B3_CODE} (the write-authorized manifest-HEAD exemption must report exists on a held INDEX, exactly as for a single manifest — the issue-#13 exemption on an index)"
fi

# ---- [B4] write-authorized GET-by-index-digest -> 503 (content hold) ----
B4_CODE="$(code_of GET "$DEV_TOKEN" \
    "${HORT_URL}/v2/${REPO_HOLD}/${IMG}/manifests/${HOLD_DIGEST}")"
if [ "$B4_CODE" = "503" ]; then
    pass "write-authorized GET /manifests/<index-digest> on HELD index -> 503 (content hold intact; only the existence probe was exempted)"
else
    fail "write-authorized GET on held index -> 503" \
         "got HTTP ${B4_CODE} (the HEAD existence exemption must NEVER extend to the content GET, even for the write-authorized principal)"
fi

# ---- [B5] anonymous HEAD-by-index-digest -> 503 (exemption is write-only) ----
B5_CODE="$(code_of HEAD "" \
    "${HORT_URL}/v2/${REPO_HOLD}/${IMG}/manifests/${HOLD_DIGEST}")"
if [ "$B5_CODE" = "503" ]; then
    pass "anonymous HEAD /manifests/<index-digest> on HELD index -> 503 (the existence exemption is write-authorized only)"
else
    fail "anonymous HEAD on held index -> 503" \
         "got HTTP ${B5_CODE} (a non-writer/anonymous HEAD on a held index must stay 503; the exemption is write-authorized only)"
fi

summary
