#!/bin/sh
# cosign-setup.sh -- Install cosign and (for vault-key signing) fetch the
# signing key from Vault/OpenBao.
#
# SOURCE this script (`. cosign-setup.sh`, NOT `bash cosign-setup.sh`) in a
# before_script: vault-key mode exports COSIGN_PASSWORD, which must survive
# into the job shell (a child process would discard it, leaving the encrypted
# key undecryptable at sign time).
#
# Modes (SIGNING_MODE, default keyless):
#   keyless   — install cosign only (Sigstore signs via SIGSTORE_ID_TOKEN).
#   vault-key — install cosign, fetch the offline key + password from Vault.
#   none      — the caller should not source this script at all.
#
# Inputs:
#   SIGNING_MODE                signing strategy (default: keyless)
#   REGISTRY                    registry host for the cosign login (image jobs)
#   REGISTRY_USER / _PASSWORD   resolved registry creds (image jobs); falls
#                               back to the /secrets/zot mount when unset
#   vault-key mode also requires (all install-specific — no portable default):
#     VAULT_ADDR                Vault/OpenBao base URL                 (required)
#     VAULT_ID_TOKEN            GitLab OIDC token (id_tokens in .gitlab-ci.yml)
#     VAULT_JWT_ROLE            JWT auth role bound to this project    (required)
#     VAULT_COSIGN_SECRET_PATH  KV path of the signing key            (required)
#     VAULT_LOGIN_PATH          JWT login path (default: v1/auth/gitlab/login)
set -e

SIGNING_MODE="${SIGNING_MODE:-keyless}"
COSIGN_VERSION="${COSIGN_VERSION:-3.0.4}"

echo "[cosign-setup] Starting setup (SIGNING_MODE=${SIGNING_MODE})..."

# --- install jq + cosign (needed for both vault-key and keyless) -----------
echo "[cosign-setup] Installing jq..."
command -v jq >/dev/null 2>&1 || { dnf install -y -q jq 2>/dev/null || apk add --no-cache jq 2>/dev/null || apt-get install -y -qq jq 2>/dev/null; }
echo "[cosign-setup] jq installed: $(jq --version)"

echo "[cosign-setup] Downloading cosign v${COSIGN_VERSION}..."
curl -sSfL "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64" \
  -o /usr/local/bin/cosign && chmod +x /usr/local/bin/cosign
echo "[cosign-setup] cosign installed: $(cosign version 2>&1 | head -1)"

# --- vault-key: fetch the offline signing key from Vault -------------------
if [ "${SIGNING_MODE}" = "vault-key" ]; then
  # The Vault role and secret layout are install-specific — require them, with
  # no hardcoded defaults. Only the JWT login path keeps a conventional
  # default (the standard GitLab-JWT auth mount), overridable per install.
  VAULT_LOGIN_PATH="${VAULT_LOGIN_PATH:-v1/auth/gitlab/login}"

  if [ -z "${VAULT_ADDR}" ]; then
    echo "[cosign-setup] ERROR: VAULT_ADDR is not set (required for SIGNING_MODE=vault-key)"
    exit 1
  fi
  if [ -z "${VAULT_ID_TOKEN}" ]; then
    echo "[cosign-setup] ERROR: VAULT_ID_TOKEN is not set — check id_tokens config in .gitlab-ci.yml"
    exit 1
  fi
  if [ -z "${VAULT_JWT_ROLE}" ]; then
    echo "[cosign-setup] ERROR: VAULT_JWT_ROLE is not set (required for SIGNING_MODE=vault-key)"
    exit 1
  fi
  if [ -z "${VAULT_COSIGN_SECRET_PATH}" ]; then
    echo "[cosign-setup] ERROR: VAULT_COSIGN_SECRET_PATH is not set (required for SIGNING_MODE=vault-key)"
    exit 1
  fi
  echo "[cosign-setup] VAULT_ADDR=${VAULT_ADDR}"
  echo "[cosign-setup] VAULT_JWT_ROLE=${VAULT_JWT_ROLE}"

  # The `if !` wrapper is load-bearing: under `set -e` a bare
  # `VAR=$(curl ...)` that exits non-zero (a transport/TLS/DNS failure — e.g.
  # PLATFORM_CA_PATH not trusted) would terminate the script HERE, making the
  # error handling below unreachable. That is exactly how a missing-CA failure
  # manifested: the script died silently right after "Authenticating to
  # Vault...". The `if` condition context suppresses `set -e` for the curl so
  # we can report it; `-sS` keeps curl quiet on success but prints transport
  # errors (captured via 2>&1).
  echo "[cosign-setup] Authenticating to Vault..."
  if ! VAULT_RESPONSE=$(curl -sS --request POST \
    --data "{\"jwt\": \"${VAULT_ID_TOKEN}\", \"role\": \"${VAULT_JWT_ROLE}\"}" \
    "${VAULT_ADDR}/${VAULT_LOGIN_PATH}" 2>&1); then
    echo "[cosign-setup] ERROR: Vault login curl failed (transport/TLS/DNS)"
    echo "[cosign-setup] URL: ${VAULT_ADDR}/${VAULT_LOGIN_PATH}"
    echo "[cosign-setup] curl output: ${VAULT_RESPONSE}"
    exit 1
  fi
  VAULT_TOKEN=$(echo "$VAULT_RESPONSE" | jq -r '.auth.client_token')
  if [ -z "$VAULT_TOKEN" ] || [ "$VAULT_TOKEN" = "null" ]; then
    echo "[cosign-setup] ERROR: Failed to authenticate to Vault"
    echo "[cosign-setup] Response: $(echo "$VAULT_RESPONSE" | jq -r '.errors // empty')"
    exit 1
  fi
  echo "[cosign-setup] Vault authentication successful"

  echo "[cosign-setup] Fetching signing key from Vault..."
  if ! COSIGN_SECRETS=$(curl -sS --header "X-Vault-Token: ${VAULT_TOKEN}" \
    "${VAULT_ADDR}/${VAULT_COSIGN_SECRET_PATH}" 2>&1); then
    echo "[cosign-setup] ERROR: Failed to fetch signing key from Vault"
    exit 1
  fi
  echo "$COSIGN_SECRETS" | jq -r '.data.data.private_key' > /tmp/cosign.key
  # Assign then export separately: `export VAR=$(...)` word-splits the
  # substitution (assignment context does not), which would truncate a
  # password containing whitespace.
  COSIGN_PASSWORD=$(echo "$COSIGN_SECRETS" | jq -r '.data.data.password')
  export COSIGN_PASSWORD

  if [ ! -s /tmp/cosign.key ]; then
    echo "[cosign-setup] ERROR: Signing key is empty"
    exit 1
  fi
  echo "[cosign-setup] Signing key fetched successfully"
fi

# --- cosign registry login (image push signing) ---------------------------
# Both vault-key and keyless push signatures to the registry and need a login.
# Resolve creds env-first, mount-fallback (same precedence as
# .resolve-registry-creds). Login only when creds are resolvable AND a registry
# is set — the SBOM blob-signing job resolves no creds and pushes nothing, so
# it skips this cleanly under both modes without aborting under `set -e`.
if [ -z "${REGISTRY_USER:-}" ] && [ -r /secrets/zot/username ]; then
  REGISTRY_USER="$(cat /secrets/zot/username)"
  REGISTRY_PASSWORD="$(cat /secrets/zot/password)"
fi
if [ -n "${REGISTRY_USER:-}" ] && [ -n "${REGISTRY:-}" ]; then
  echo "[cosign-setup] Logging cosign into ${REGISTRY}..."
  cosign login -u "${REGISTRY_USER}" -p "${REGISTRY_PASSWORD}" "${REGISTRY}"
else
  echo "[cosign-setup] Skipping cosign registry login (no creds/registry — blob-signing only)"
fi

echo "[cosign-setup] Setup complete"
