#!/usr/bin/env bash
# requires: egress worker db compose
# Provenance hold-until-signed — the push-then-sign round-trip (issue #13).
#
# This is the first REAL-VERIFIER worker->release-gate provenance E2E (ADR 0000
# open-items register, "Combined real-verifier provenance E2E"). It drives the
# canonical CI flow end to end against a HOSTED OCI repo governed by a
# `provenanceMode: required` + `provenanceBackends: [cosign-key]` ScanPolicy, and
# asserts the four states the hold-until-signed lifecycle promises:
#
#   [1] PUSH (unsigned)      — a keyed `required` image is HELD, not rejected:
#                               * an anonymous manifest GET/pull -> 503 (held,
#                                 not consumable);
#                               * a WRITE-authorized manifest HEAD -> 200/exists
#                                 (the existence-probe exemption, so the signer's
#                                 cosign preflight can resolve the digest and
#                                 ATTACH the signature). GET stays 503 for all.
#   [2] SIGN                  — `cosign sign --key <keyed> --registry-referrers-mode=oci-1-1
#                               <ref>@<digest>` attaches a subject-linked referrer.
#                               hort re-verifies the SUBJECT image (S3), emits
#                               `ProvenanceVerified`, clearance -> Cleared.
#   [3] RELEASE               — once the quarantine window elapses AND provenance
#                               is Cleared, the image RELEASES and PULLS.
#   [4] NEGATIVE (never-sign) — a second image is pushed and never signed; at
#                               `quarantineDuration` expiry the backstop (S4)
#                               makes the TERMINAL decision -> `ProvenanceRejected
#                               {Unsigned}`; the manifest then returns 404
#                               (MANIFEST_UNKNOWN), not 503.
#
# -----------------------------------------------------------------------------
# COSIGN HEAD-vs-GET FINDING (design doc §2 S2, Item 8 acceptance) — READ THIS.
# -----------------------------------------------------------------------------
# The design (§2 S2) ASSUMES keyed `cosign sign` needs only the manifest HEAD to
# resolve the subject digest before it PUTs the signature manifest, and Item 3
# therefore exempts ONLY a write-authorized manifest HEAD from the quarantine
# 503 (GET stays 503 for every caller during the hold). This scenario is the
# check on that assumption:
#
#   * If step [2] SUCCEEDS with only the HEAD exemption in place, the assumption
#     holds — keyed cosign sign resolves via HEAD, and Item 3's manifest-HEAD
#     exemption is sufficient. (Expected.)
#   * If step [2] FAILS because cosign issues a manifest GET during signing
#     (observable as a 503 on `GET /v2/<repo>/manifests/<digest>` in the cosign
#     output, NOT a HEAD), then the HEAD-only exemption is INSUFFICIENT: Item 3
#     must be extended to a WRITE-AUTHORIZED manifest GET (still narrower than
#     serving the manifest to all callers). File that as a FAST-FOLLOW to Item 3
#     — do NOT widen the exemption inside this scenario.
#
# When this scenario runs in CI, its pass/fail on step [2] IS the empirical
# answer. Until then the HEAD-only assumption is a CI-validated OPEN point,
# recorded here and in ADR 0000.
#
# -----------------------------------------------------------------------------
# WHY THIS MAY SELF-SKIP on the current compose stack.
# -----------------------------------------------------------------------------
# Running the round-trip for real needs three things the base harness does not
# ship yet, so the scenario `skip`s (exit 77 — NEVER a false pass) when any is
# absent rather than faking a result:
#
#   * `cosign` + `buildah` in the client image (Dockerfile.client carries skopeo,
#     not cosign/buildah today);
#   * a keyed cosign signing key pair — the private key to sign with, and its
#     public key mounted into the worker (`HORT_COSIGN_PUBLIC_KEYS_FILE` /
#     values `cosign.publicKeysFile`) so the worker REGISTERS the `cosign-key`
#     backend (ADR 0039). The base compose worker has no cosign env, so
#     `cosign-key` is not registered there;
#   * a hosted OCI repo + ScanPolicy with `provenanceMode: required` +
#     `provenanceBackends: [cosign-key]` and a SHORT `quarantineDuration` (so the
#     window elapses within a smoke run) in the mounted gitops config.
#
# The env contract below lets a CI job that provisions these point the scenario
# at them; absent them, it skips. Skopeo (present) does the push/pull legs;
# cosign does only the signing leg.

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"

if [ "${HORT_TEST_DEBUG:-0}" = "1" ]; then
    set -x
fi

# -----------------------------------------------------------------------------
# Env contract (CI provisioner overrides; sensible defaults otherwise)
# -----------------------------------------------------------------------------
# Repo governed by required+cosign-key. Default matches the fixture name a CI
# provisioner is expected to add to the mounted gitops config.
REPO_KEY="${PROVENANCE_REPO_KEY:-oci-provenance-e2e}"
# Keyed cosign private key to SIGN with (cosign --key). Its PUBLIC half must be
# the one the worker loaded to register `cosign-key`, or the verify will Reject.
COSIGN_KEY="${COSIGN_KEY:-}"
# cosign needs a password for a file-based key; empty for a keyless-file setup.
export COSIGN_PASSWORD="${COSIGN_PASSWORD:-}"
# Source image to push (ghcr.io — no Docker Hub rate limit). Small is fine.
SOURCE_IMAGE="${SOURCE_IMAGE:-ghcr.io/oci-playground/hello-world:latest}"
# How long the scenario is willing to wait for the window to elapse + the
# release/expiry sweep to run. The gitops policy's quarantineDuration MUST be
# <= this for the release/reject legs to complete in-run.
WINDOW_WAIT_SECS="${PROVENANCE_WINDOW_WAIT_SECS:-180}"

# Strip scheme so skopeo/cosign's docker:// transport gets host:port only.
REGISTRY_HOST="${HORT_URL#http://}"
REGISTRY_HOST="${REGISTRY_HOST#https://}"

SIGNED_NAME="${SIGNED_NAME:-provsigned}"
UNSIGNED_NAME="${UNSIGNED_NAME:-provunsigned}"
DEST_SIGNED="${REGISTRY_HOST}/${REPO_KEY}/${SIGNED_NAME}:v1"
DEST_UNSIGNED="${REGISTRY_HOST}/${REPO_KEY}/${UNSIGNED_NAME}:v1"
PULLED_ARCHIVE="/tmp/prov-pulled-${SIGNED_NAME}.tar"

log "==> Provenance hold-until-signed round-trip (push-then-sign, keyed)"
log "Registry : ${HORT_URL}"
log "Repo key : ${REPO_KEY} (expected: provenanceMode=required, provenanceBackends=[cosign-key])"
log "Source   : ${SOURCE_IMAGE}"

# ---- Tool + config availability -> self-skip (never a false pass) ----
command -v skopeo >/dev/null 2>&1 || skip "skopeo not found in client image"
command -v cosign >/dev/null 2>&1 || \
    skip "cosign not in client image — provision cosign + a keyed key + a required/cosign-key repo, then re-run (see header)"
[ -n "$COSIGN_KEY" ] || \
    skip "COSIGN_KEY unset — no keyed cosign private key to sign with (its public half must be the worker's registered cosign-key)"

trap 'rm -f "$PULLED_ARCHIVE"' EXIT

# dev-user is the write-authorized pusher/signer (mirrors the other OCI
# scenarios). The public half of COSIGN_KEY must match the worker's registered
# key or step [2] will Reject instead of Verify.
DEV_TOKEN="$(fetch_token dev-user dev)"
[ -n "$DEV_TOKEN" ] || fail "fetch dev-user token" "empty response from Keycloak"
[ -n "$DEV_TOKEN" ] || summary
DEST_CREDS="dev-user:${DEV_TOKEN}"
log "[auth] fetched DEV_TOKEN from Keycloak (dev-user write-authorized for ${REPO_KEY})"

# =============================================================================
# [1/6] PUSH (unsigned) — accepted, held (write path ungated by the hold)
# =============================================================================
log "==> [1/6] Push ${SOURCE_IMAGE} -> docker://${DEST_SIGNED} (to-be-signed)"
if skopeo copy \
      --insecure-policy --dest-tls-verify=false \
      --dest-creds "$DEST_CREDS" \
      "docker://${SOURCE_IMAGE}" "docker://${DEST_SIGNED}" >/dev/null 2>&1; then
    pass "push of the to-be-signed image accepted (write path ungated; image held under required)"
else
    fail "push to required+cosign-key repo" \
         "skopeo copy -> ${DEST_SIGNED} exited non-zero (a hosted push under required must still be accepted, then HELD)"
    summary
fi

# Resolve the pushed digest (cosign signs <ref>@<digest>, not the tag).
DIGEST="$(skopeo inspect --tls-verify=false --creds "$DEST_CREDS" \
    "docker://${DEST_SIGNED}" 2>/dev/null | jq -r '.Digest // empty')"
if [ -z "$DIGEST" ]; then
    # skopeo inspect issues a manifest GET; under the hold that is 503 (correct).
    # Fall back to the Docker-Content-Digest header of a write-authorized HEAD,
    # which the exemption serves.
    DIGEST="$(curl -sSI -H "Authorization: Bearer ${DEV_TOKEN}" \
        "${HORT_URL}/v2/${REPO_KEY}/${SIGNED_NAME}/manifests/v1" 2>/dev/null \
        | tr -d '\r' | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}')"
fi
[ -n "$DIGEST" ] || { fail "resolve pushed digest" "neither skopeo inspect nor a write-authorized HEAD returned a digest"; summary; }
log "[digest] pushed manifest digest = ${DIGEST}"

# =============================================================================
# [2/6] HELD — anonymous manifest pull 503; write-authorized manifest HEAD 200
# =============================================================================
log "==> [2/6] Assert HELD: anonymous manifest GET -> 503, write-authorized HEAD -> exists"

ANON_GET_CODE="$(curl -s -o /dev/null -w '%{http_code}' \
    "${HORT_URL}/v2/${REPO_KEY}/${SIGNED_NAME}/manifests/${DIGEST}" 2>/dev/null || echo 000)"
if [ "$ANON_GET_CODE" = "503" ]; then
    pass "anonymous manifest GET on held image -> 503 (not consumable)"
else
    fail "anonymous manifest GET -> 503" "got HTTP ${ANON_GET_CODE} (a held required image must 503 to pullers)"
fi

WRITE_HEAD_CODE="$(curl -s -o /dev/null -w '%{http_code}' -I \
    -H "Authorization: Bearer ${DEV_TOKEN}" \
    "${HORT_URL}/v2/${REPO_KEY}/${SIGNED_NAME}/manifests/${DIGEST}" 2>/dev/null || echo 000)"
if [ "$WRITE_HEAD_CODE" = "200" ]; then
    pass "write-authorized manifest HEAD on held image -> 200/exists (existence-probe exemption; signer can attach)"
else
    fail "write-authorized manifest HEAD -> 200" \
         "got HTTP ${WRITE_HEAD_CODE} (the write-authorized manifest-HEAD exemption must report exists so cosign can preflight)"
fi

# =============================================================================
# [3/6] SIGN — cosign sign --key --registry-referrers-mode=oci-1-1 <ref>@<digest>
# =============================================================================
# THE HEAD-vs-GET check: this runs with ONLY the manifest-HEAD exemption in
# place. If cosign also needs a manifest GET it will 503 here — capture cosign's
# output so a reviewer can see whether the blocked op was a HEAD or a GET.
log "==> [3/6] cosign sign --key ... --registry-referrers-mode=oci-1-1 ${DEST_SIGNED%:*}@${DIGEST}"
export COSIGN_DOCKER_MEDIA_TYPES=1
SIGN_OUT=""
SIGN_RC=0
SIGN_OUT="$(cosign sign --yes \
    --key "$COSIGN_KEY" \
    --registry-referrers-mode=oci-1-1 \
    --registry-username=dev-user \
    --registry-password="$DEV_TOKEN" \
    --allow-insecure-registry \
    "${REGISTRY_HOST}/${REPO_KEY}/${SIGNED_NAME}@${DIGEST}" 2>&1)" || SIGN_RC=$?
if [ "$SIGN_RC" -eq 0 ]; then
    pass "cosign sign (keyed, oci referrers) succeeded — the manifest-HEAD exemption was sufficient for signing"
    log "[HEAD-vs-GET] cosign signed with only the write-authorized manifest-HEAD exemption in place -> Item 3's HEAD-only exemption is sufficient (assumption CONFIRMED)."
else
    log "[cosign output]"; printf '%s\n' "$SIGN_OUT" | sed 's/^/    /'
    if printf '%s' "$SIGN_OUT" | grep -Eqi 'GET .*/manifests/.*503|503 .*manifests'; then
        fail "cosign sign under HEAD-only exemption" \
             "cosign issued a manifest GET (503) during signing -> Item 3's HEAD-only exemption is INSUFFICIENT; FAST-FOLLOW: extend it to a write-authorized manifest GET (see header). HEAD-vs-GET finding: GET REQUIRED."
    else
        fail "cosign sign (keyed, oci referrers)" \
             "cosign exited ${SIGN_RC}; see output above (not obviously a manifest-GET 503 — inspect the cosign error)"
    fi
    summary
fi

# =============================================================================
# [4/6] VERIFIED — worker re-verifies the subject (S3) -> ProvenanceVerified
# =============================================================================
log "==> [4/6] Await ProvenanceVerified on the subject image (worker S3 re-verify)"
# The subject artifact id is resolved by content hash = the pushed digest hex.
DIGEST_HEX="${DIGEST#sha256:}"
if bounded_poll \
        "ProvenanceVerified for ${SIGNED_NAME}@${DIGEST}" \
        "$WINDOW_WAIT_SECS" \
        "[ -n \"\$(psql_one \"SELECT 1 FROM events e JOIN artifacts a ON e.stream_id = 'artifact-' || a.id::text WHERE a.checksum_sha256 = '${DIGEST_HEX}' AND e.event_type = 'ProvenanceVerified' LIMIT 1;\")\" ]" \
        5; then
    pass "ProvenanceVerified emitted for the signed subject image (real-verifier clearance)"
else
    fail "ProvenanceVerified for the signed image" \
         "no ProvenanceVerified event for checksum ${DIGEST_HEX} within ${WINDOW_WAIT_SECS}s — signature not linked (referrers mode?) or public key mismatch"
fi

# =============================================================================
# [5/6] RELEASE — after the window + Cleared, the image pulls
# =============================================================================
log "==> [5/6] Await release + pull of the signed image (window elapsed + Cleared)"
rm -f "$PULLED_ARCHIVE"
if bounded_poll \
        "signed image pullable" \
        "$WINDOW_WAIT_SECS" \
        "skopeo copy --insecure-policy --src-tls-verify=false --src-creds '${DEST_CREDS}' 'docker://${DEST_SIGNED}' 'oci-archive:${PULLED_ARCHIVE}'" \
        5; then
    pass "signed image released and pulled after the quarantine window (Cleared + timer gate satisfied)"
else
    fail "signed image releases + pulls" \
         "the signed+cleared image never became pullable within ${WINDOW_WAIT_SECS}s (window or provenance gate not satisfied)"
fi

# =============================================================================
# [6/6] NEGATIVE — never-signed image -> terminal Rejected{Unsigned} at expiry
# =============================================================================
log "==> [6/6] NEGATIVE: push an image, never sign it -> terminal Rejected{Unsigned} at window expiry"
if skopeo copy \
      --insecure-policy --dest-tls-verify=false \
      --dest-creds "$DEST_CREDS" \
      "docker://${SOURCE_IMAGE}" "docker://${DEST_UNSIGNED}" >/dev/null 2>&1; then
    log "  pushed never-to-be-signed image ${DEST_UNSIGNED}"
else
    fail "push never-signed image" "skopeo copy -> ${DEST_UNSIGNED} exited non-zero"
    summary
fi

# At window expiry the release sweep enqueues a final provenance-verify with
# window_open=false; complete_provenance then emits ProvenanceRejected{Unsigned}
# and the manifest transitions from 503 (held) to 404 (MANIFEST_UNKNOWN).
if bounded_poll \
        "never-signed manifest -> 404 (terminal Rejected{Unsigned})" \
        "$WINDOW_WAIT_SECS" \
        "[ \"\$(curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer ${DEV_TOKEN}' '${HORT_URL}/v2/${REPO_KEY}/${UNSIGNED_NAME}/manifests/v1' 2>/dev/null)\" = '404' ]" \
        5; then
    pass "never-signed image is terminally Rejected{Unsigned} at window expiry (manifest -> 404, not 503)"
else
    LAST_CODE="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${DEV_TOKEN}" \
        "${HORT_URL}/v2/${REPO_KEY}/${UNSIGNED_NAME}/manifests/v1" 2>/dev/null || echo 000)"
    fail "never-signed image -> terminal Rejected{Unsigned}" \
         "manifest still HTTP ${LAST_CODE} after ${WINDOW_WAIT_SECS}s (expected 404; the expiry backstop should have made the terminal Unsigned decision)"
fi

summary
