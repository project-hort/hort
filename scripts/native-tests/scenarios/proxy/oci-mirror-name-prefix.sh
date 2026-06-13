#!/usr/bin/env bash
# requires: egress
# Outbound `upstream_name_prefix` scenario (OPTIONAL — opt-in via env).
#
# Drives a skopeo manifest pull through an hort-server UpstreamMapping
# carrying `upstreamNamePrefix: <p>`. The mapping points at a
# path-prefixed upstream — a registry whose layout puts an extra segment
# between `/v2/` and `<name>` (Zot multi-storage, Artifactory rewrite,
# GitLab CR per-project URLs, Harbor proxy caches). With the field set,
# hort-server splices `<p>` into the outbound URL so the upstream sees
# a normal, spec-compliant OCI request.
#
# Acceptance: the manifest bytes returned through hort-server match the
# manifest bytes from a direct pull of the same image against the
# upstream Docker Hub, after canonicalisation via python3 json.
#
# Opt-in: set HORT_INIT37_PREFIXED_UPSTREAM_URL + HORT_INIT37_PREFIX to
# enable. Without those env vars the script prints SKIP and exits 77.

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"

if [ -z "${HORT_INIT37_PREFIXED_UPSTREAM_URL:-}" ] || [ -z "${HORT_INIT37_PREFIX:-}" ]; then
    skip "upstream_name_prefix smoke requires HORT_INIT37_PREFIXED_UPSTREAM_URL + HORT_INIT37_PREFIX — see script header for the fixture shape"
fi

HORT_INIT37_IMAGE="${HORT_INIT37_IMAGE:-library/alpine}"
HORT_INIT37_TAG="${HORT_INIT37_TAG:-3.19}"
HORT_INIT37_REPO_KEY="${HORT_INIT37_REPO_KEY:-oci-init37-prefix-e2e}"
DIRECT_UPSTREAM_URL="${DIRECT_UPSTREAM_URL:-https://registry-1.docker.io}"

# Strip scheme so skopeo's docker:// transport gets host:port only.
REGISTRY_HOST="${HORT_URL#http://}"
REGISTRY_HOST="${REGISTRY_HOST#https://}"

THROUGH_REF="docker://${REGISTRY_HOST}/${HORT_INIT37_REPO_KEY}/${HORT_INIT37_IMAGE}:${HORT_INIT37_TAG}"
DIRECT_HOST="${DIRECT_UPSTREAM_URL#http://}"
DIRECT_HOST="${DIRECT_HOST#https://}"
DIRECT_REF="docker://${DIRECT_HOST}/${HORT_INIT37_IMAGE}:${HORT_INIT37_TAG}"

log "==> Outbound upstream_name_prefix scenario"
log "   hort-server repo key   : ${HORT_INIT37_REPO_KEY}"
log "   hort-server through ref: ${THROUGH_REF}"
log "   direct control ref     : ${DIRECT_REF}"
log "   prefixed upstream URL  : ${HORT_INIT37_PREFIXED_UPSTREAM_URL}"
log "   prefix segment(s)      : ${HORT_INIT37_PREFIX}"

# The repository and UpstreamMapping must already exist (gitops-applied
# from $HORT_CONFIG_DIR before hort-server bound). We don't POST them
# at runtime — the gitops apply is the writer.

# ---- Step 1: fetch manifest THROUGH hort-server ----
log "==> Fetching manifest through hort-server..."
through_manifest="$(skopeo inspect --raw --tls-verify=false "${THROUGH_REF}" \
    | python3 -c "import sys, json; print(json.dumps(json.loads(sys.stdin.read()), sort_keys=True, separators=(',', ':')))")"

# ---- Step 2: fetch manifest DIRECTLY from upstream (control) ----
log "==> Fetching manifest directly from ${DIRECT_HOST}..."
direct_manifest="$(skopeo inspect --raw "${DIRECT_REF}" \
    | python3 -c "import sys, json; print(json.dumps(json.loads(sys.stdin.read()), sort_keys=True, separators=(',', ':')))")"

# ---- Step 3: canonicalised JSON equality assertion ----
# Canonicalised-JSON comparison tolerates insignificant whitespace
# differences between registries. Pinning the manifest digest would be
# tighter but upstream registries occasionally rewrap manifests as they
# age; the canonicalised-JSON form is the operational sweet spot.
if [ "${through_manifest}" = "${direct_manifest}" ]; then
    pass "through-hort-server manifest matches direct upstream"
else
    fail "manifest mismatch through prefixed upstream" "through and direct canonicalised manifests differ"
    log "--- through hort-server (first 512 bytes) ---"
    printf '%s' "${through_manifest}" | head -c 512 >&2
    log ""
    log "--- direct upstream (first 512 bytes) ---"
    printf '%s' "${direct_manifest}" | head -c 512 >&2
    log ""
fi

summary
