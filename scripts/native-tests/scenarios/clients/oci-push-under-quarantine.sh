#!/usr/bin/env bash
# requires: egress
# OCI push-under-quarantine — regression for the push-blocking quarantine gate
# (fix: blob-existence HEAD must not 503 a write-authorized push).
#
# The `oci-quarantine-e2e` repo carries a deliberately QUARANTINING ScanPolicy
# (24h hold), so every pushed blob is held in `Quarantined`. The pre-flight
# `HEAD /v2/<repo>/<name>/blobs/<digest>` that an OCI pusher (skopeo, docker
# push) issues to dedup before upload is a WRITE-path precondition, not a
# download — it must report 200 (exists), not 503, or the push aborts. Before
# the fix the dedup HEAD reused the pull-path quarantine 503, so a re-push of
# already-quarantined blobs (the production symptom) failed.
#
#   [1] Push image -> :v0          — write path accepts; blobs quarantined.
#   [2] Re-push same image -> :v1  — skopeo HEADs every (now-Quarantined) blob
#                                    to dedup; MUST succeed (the fix).
#   [3] Pull :v0                   — MUST fail: the content hold is intact; the
#                                    fix released only the existence probe, the
#                                    held bytes are never served (GET stays 503).
#
# Pulls SOURCE_IMAGE from ghcr.io (no Docker Hub rate-limit); needs egress.

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"

REPO_KEY="${OCI_QUARANTINE_REPO_KEY:-oci-quarantine-e2e}"
# Strip scheme so skopeo's docker:// transport gets host:port only.
REGISTRY_HOST="${HORT_URL#http://}"
REGISTRY_HOST="${REGISTRY_HOST#https://}"

SOURCE_IMAGE="${SOURCE_IMAGE:-ghcr.io/oci-playground/hello-world:latest}"
TEST_IMAGE_NAME="${TEST_IMAGE_NAME:-qtestimg}"

DEST_V0="${REGISTRY_HOST}/${REPO_KEY}/${TEST_IMAGE_NAME}:v0"
DEST_V1="${REGISTRY_HOST}/${REPO_KEY}/${TEST_IMAGE_NAME}:v1"
PULLED_ARCHIVE="/tmp/oci-quarantine-pulled-${TEST_IMAGE_NAME}.tar"

log "==> OCI Push-Under-Quarantine Test (skopeo)"
log "Registry:  ${HORT_URL}"
log "Repo key:  ${REPO_KEY} (quarantining ScanPolicy)"
log "Source:    ${SOURCE_IMAGE}"

command -v skopeo >/dev/null 2>&1 || skip "skopeo not found"

trap 'rm -f "$PULLED_ARCHIVE"' EXIT

# dev-user carries [developer, ci-pusher] → write on ${REPO_KEY}
# (deploy/compose/example-config/auth/dev-write-oci-quarantine-e2e.yaml).
DEV_TOKEN="$(fetch_token dev-user dev)"
[ -n "$DEV_TOKEN" ] || fail "fetch dev-user token" "empty response from Keycloak"
DEST_CREDS="dev-user:${DEV_TOKEN}"
log "[auth] fetched DEV_TOKEN from Keycloak (dev-user is write-authorized for ${REPO_KEY})"

# ---- [1/3] First push: quarantines the blobs on ingest ----
log "==> [1/3] Push ${SOURCE_IMAGE} -> docker://${DEST_V0}"
if skopeo copy \
      --insecure-policy \
      --dest-tls-verify=false \
      --dest-creds "$DEST_CREDS" \
      "docker://${SOURCE_IMAGE}" \
      "docker://${DEST_V0}" 2>&1; then
  pass "initial push to quarantining repo succeeded (write path ungated; blobs ingested + quarantined)"
else
  fail "initial push" "skopeo copy -> ${DEST_V0} exited non-zero (a hosted push to a quarantining repo must still be accepted)"
fi

# ---- [2/3] Re-push the same image to a second tag (shared blobs) ----
# Every blob is now Quarantined. skopeo issues a pre-flight HEAD per blob to
# dedup. Without the fix that HEAD 503s and this push aborts; with the fix it
# reports 200 (exists), uploads are skipped, and the manifest PUT completes.
log "==> [2/3] Re-push (dedup against quarantined blobs) -> docker://${DEST_V1}"
if skopeo copy \
      --insecure-policy \
      --dest-tls-verify=false \
      --dest-creds "$DEST_CREDS" \
      "docker://${SOURCE_IMAGE}" \
      "docker://${DEST_V1}" 2>&1; then
  pass "re-push of shared quarantined blobs succeeded — push-dedup HEAD reported exists, not 503"
else
  fail "re-push under quarantine" \
       "dedup blob HEAD on a quarantined blob 503'd, aborting the push (the regression). If the blocked request is a manifest HEAD rather than a blob HEAD, the same write-authorized-existence exemption is needed on the manifest read path."
fi

# ---- [3/3] Content hold still in force: pulling :v0 must fail ----
# The fix releases only the write-authorized existence probe (HEAD); the held
# bytes are never served. A pull (manifest / blob GET) must still be blocked.
log "==> [3/3] Pull docker://${DEST_V0} -> oci-archive (must be blocked)"
rm -f "$PULLED_ARCHIVE"
if skopeo copy \
      --insecure-policy \
      --src-tls-verify=false \
      --src-creds "$DEST_CREDS" \
      "docker://${DEST_V0}" \
      "oci-archive:${PULLED_ARCHIVE}" >/dev/null 2>&1; then
  fail "quarantine content hold" "pull of a quarantined image SUCCEEDED — held content was served (the HEAD existence exemption must never extend to the content GET)"
else
  pass "quarantined image is not pullable — content hold intact (only the write-authorized existence probe was released)"
fi

summary
