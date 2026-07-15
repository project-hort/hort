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

# cosign v3 gates --registry-referrers-mode=oci-1-1 (the OCI 1.1 referrers
# carriage ADR 0039 §9 requires so a hosted hort repo resolves signatures via
# the referrers API, not legacy .sig tags) behind COSIGN_EXPERIMENTAL=1;
# without it cosign errors out before any registry call.
export COSIGN_EXPERIMENTAL=1

case "${SIGNING_MODE}" in
  none)
    echo "SIGNING_MODE=none — skipping signature for ${IMAGE}@${DIGEST}"
    exit 0
    ;;
  keyless)
    # oci-1-1 referrers (not legacy .sig tags): a hosted hort repo resolves
    # signatures via the OCI 1.1 referrers API. cosign v3 already emits the
    # Sigstore v0.3 bundle by default here (no --new-bundle-format=false).
    cosign sign --yes --registry-referrers-mode=oci-1-1 \
      -a "ci.commit=${CI_COMMIT_SHA}" -a "ci.project=${CI_PROJECT_PATH}" \
      "${IMAGE}@${DIGEST}"
    ;;
  vault-key)
    # Keyed, offline (no transparency log) signature that hort's Tier-1
    # verifier accepts: cosign v3 emits the Sigstore v0.3 bundle by default
    # (NOT the legacy simplesigning of --new-bundle-format=false), and
    # oci-1-1 referrers are required for hosted repos (hort resolves the
    # signature via the referrers API, not a legacy .sig tag).
    # --use-signing-config=false + --tlog-upload=false keep it offline/no-Rekor.
    cosign sign --key /tmp/cosign.key --yes \
      --use-signing-config=false --tlog-upload=false \
      --registry-referrers-mode=oci-1-1 \
      -a "ci.commit=${CI_COMMIT_SHA}" -a "ci.project=${CI_PROJECT_PATH}" \
      "${IMAGE}@${DIGEST}"
    ;;
  *)
    echo "ERROR: unknown SIGNING_MODE=${SIGNING_MODE} (expected vault-key|keyless|none)" >&2
    exit 1
    ;;
esac

echo "SIGNED (${SIGNING_MODE}): ${IMAGE}@${DIGEST}"
