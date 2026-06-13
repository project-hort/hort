#!/bin/sh
# cosign-sign.sh -- Sign a container image by digest.
# Usage: cosign-sign.sh <image> <digest>
#
# Honors SIGNING_MODE (default keyless):
#   keyless   — Sigstore/Fulcio/Rekor via the ambient SIGSTORE_ID_TOKEN
#               (GitLab id_token); no key material on disk.
#   vault-key — offline key /tmp/cosign.key + COSIGN_PASSWORD, no Rekor
#               (set up by cosign-setup.sh).
#   none      — no-op.
set -e

IMAGE="$1"
DIGEST="$2"
SIGNING_MODE="${SIGNING_MODE:-keyless}"

if [ -z "$IMAGE" ] || [ -z "$DIGEST" ]; then
  echo "Usage: cosign-sign.sh <image> <digest>" >&2
  exit 1
fi

case "${SIGNING_MODE}" in
  none)
    echo "SIGNING_MODE=none — skipping signature for ${IMAGE}@${DIGEST}"
    exit 0
    ;;
  keyless)
    cosign sign --yes --registry-referrers-mode=legacy \
      -a "ci.commit=${CI_COMMIT_SHA}" -a "ci.project=${CI_PROJECT_PATH}" \
      "${IMAGE}@${DIGEST}"
    ;;
  vault-key)
    cosign sign --key /tmp/cosign.key --yes \
      --new-bundle-format=false --use-signing-config=false \
      --tlog-upload=false --registry-referrers-mode=legacy \
      -a "ci.commit=${CI_COMMIT_SHA}" -a "ci.project=${CI_PROJECT_PATH}" \
      "${IMAGE}@${DIGEST}"
    ;;
  *)
    echo "ERROR: unknown SIGNING_MODE=${SIGNING_MODE} (expected vault-key|keyless|none)" >&2
    exit 1
    ;;
esac

echo "SIGNED (${SIGNING_MODE}): ${IMAGE}@${DIGEST}"
