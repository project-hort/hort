#!/usr/bin/env bash
# requires: egress worker db compose
# Provenance hold-until-signed — the push-then-sign round-trip (issue #13).
#
# This is the first REAL-VERIFIER worker->release-gate provenance E2E (ADR 0000
# open-items register, "Combined real-verifier provenance E2E"). It drives the
# canonical CI flow end to end against a HOSTED OCI repo governed by a
# `provenanceMode: required` + `provenanceBackends: [cosign-key]` ScanPolicy, and
# asserts the four states the hold-until-signed lifecycle promises.
#
# The push is an IMAGE INDEX (multi-arch, `skopeo copy --all`), not a single
# manifest: cosign signs the top-level index digest, so this exercises the real
# index-shaped push-then-sign (issue #15). A single-manifest push returns 200
# and gives false confidence — that the index PUT never failed — which is the
# exact gap issue #15 closed. The digest cosign signs is the index digest.
#
#   [1] PUSH (unsigned)      — a keyed `required` image is HELD, not rejected.
#                               The repo is PRIVATE (isPublic:false), so read
#                               visibility gates BEFORE the artifact-level hold:
#                               * an anonymous manifest GET/pull -> 401 + a
#                                 `WWW-Authenticate` challenge (denied by
#                                 visibility, ADR 0045); the hold's 503 is never
#                                 observable anonymously on a private repo;
#                               * a WRITE-authorized manifest HEAD -> 200/exists
#                                 (the hold-read exemption, so the signer's
#                                 cosign preflight can resolve the digest and
#                                 ATTACH the signature).
#   [2] SIGN                  — `cosign sign --key <keyed> --registry-referrers-mode=oci-1-1
#                               <ref>@<digest>` attaches a subject-linked referrer.
#                               hort re-verifies the SUBJECT image (S3), emits
#                               `ProvenanceVerified`, clearance -> Cleared.
#   [3] RELEASE               — once the quarantine window elapses AND provenance
#                               is Cleared, the image RELEASES and PULLS.
#   [4] NEGATIVE (never-sign) — a second image (a DISTINCT digest — same bytes
#                               would CAS-dedup to the signed artifact) is
#                               pushed and never signed; at `quarantineDuration`
#                               expiry the backstop (S4) makes the TERMINAL
#                               decision -> `ProvenanceRejected{Unsigned}`.
#                               On a PRIVATE repo an anonymous manifest GET is
#                               401 throughout (visibility, not the hold), so
#                               held and terminal are indistinguishable
#                               anonymously; the terminal decision is observed
#                               via the emitted `ProvenanceRejected` domain
#                               event, exactly as [4/6] observes
#                               `ProvenanceVerified`.
#
# -----------------------------------------------------------------------------
# COSIGN RESOLVES THE SUBJECT BY GET (ADR 0039 §10).
# -----------------------------------------------------------------------------
# Keyed `cosign sign` resolves the subject manifest by a `GET manifests/<digest>`
# (not only a `HEAD`) before it attaches the signature manifest. The manifest
# hold exemption therefore covers a write-authorized manifest HEAD AND GET, so a
# held subject is signable: the manifest is metadata (config + layer digests),
# not runnable content; the layer blobs keep their HEAD-only probe, so no
# runnable bytes leave quarantine and a non-writer / anonymous read stays 503.
# Step [3] below runs the sign for real against that widened exemption and
# asserts the full round-trip (sign -> re-verify -> release -> pull) completes.
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
# Defaults to the committed test-only fixture keypair whose public half the
# compose worker mounts (deploy/compose/example-config/provenance/cosign.pub);
# $FIXTURES is set by the native-tests runner (=/work/fixtures). A CI job with a
# different keypair overrides COSIGN_KEY.
COSIGN_KEY="${COSIGN_KEY:-${FIXTURES:-}/cosign/cosign.key}"
# cosign needs a password for a file-based key; empty for a keyless-file setup.
export COSIGN_PASSWORD="${COSIGN_PASSWORD:-}"
# Source image to push — a genuine multi-arch IMAGE INDEX (ghcr.io, no Docker
# Hub rate limit). Pushed with `skopeo copy --all` so the tag resolves to the
# top-level index digest, and cosign signs THAT index digest (issue #15:
# index-shaped push-then-sign). ghcr.io/stefanprodan/podinfo is an OCI image
# index (mediaType application/vnd.oci.image.index.v1+json).
SOURCE_IMAGE="${SOURCE_IMAGE:-ghcr.io/stefanprodan/podinfo:latest}"
# The never-signed image for the [6/6] negative leg MUST have a DIFFERENT
# digest than SOURCE_IMAGE: storage is content-addressed, so pushing the same
# bytes under a second name dedups to the SAME artifact — and once the signed
# leg's signature verifies THAT digest, the "unsigned" name serves the
# already-released artifact (a cosign signature covers the digest, not the
# name; 200 there is the registry being correct, not a hold bypass). A pinned
# older podinfo tag is likewise a multi-arch OCI image index.
UNSIGNED_SOURCE_IMAGE="${UNSIGNED_SOURCE_IMAGE:-ghcr.io/stefanprodan/podinfo:6.5.0}"
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
[ -f "$COSIGN_KEY" ] || \
    skip "keyed cosign private key '$COSIGN_KEY' not found (expected the committed fixture at \$FIXTURES/cosign/cosign.key, or a CI-provided COSIGN_KEY)"

trap 'rm -f "$PULLED_ARCHIVE"' EXIT

# -----------------------------------------------------------------------------
# Credential mode: legacy (Basic / IdP-JWT) vs native tokens.
# -----------------------------------------------------------------------------
# Under the `native-tokens` compose overlay (HORT_COMPOSE_OVERLAYS carries the
# runner's --compose-overlay list; export it yourself in external mode) the
# stack advertises the `WWW-Authenticate: Bearer realm=…/v2/auth` challenge and
# every OCI client runs the real Distribution-Spec token dance. The /v2/auth
# handler validates the Basic password strictly as a NATIVE token
# (PatValidationUseCase) — a Keycloak JWT in that slot 401s — and the OCI
# capability surface resolves User-subject grants only (claims stay empty,
# ADR 0036), so the pusher/signer is the `provenance-ci` PAT-only service
# account (gitops example-config), admin-minted here via the REST surface.
# The decisive property this mode exercises: cosign scopes its subject read as
# `pull`, so the presented capability JWT carries a READ-ONLY cap while the
# SA's grants carry write — the exact shape the granted-authority hold-read
# exemption (ADR 0039 §10, issue #13) keys on. The hold probes below ride a
# pull-scoped capability JWT explicitly, so a cap-keyed regression 503s them.
#
# Legacy (no overlay): dev-user's Keycloak JWT as the Basic password / bearer
# (mirrors the other OCI scenarios) — this mode must stay green too.
NATIVE_TOKENS=0
case " ${HORT_COMPOSE_OVERLAYS:-} " in
    *" native-tokens "*) NATIVE_TOKENS=1 ;;
esac

# mint_cap_jwt <image-name> <actions> — mint a capability JWT scoped to
# <actions> on one image via the real /v2/auth exchange (Basic <svc-token>).
# Prints the JWT. The pull-scoped caps carry the issue-#13 shape (read-only
# cap, write-granted identity).
mint_cap_jwt() {
    curl -sS -u "provenance-ci:${SVC_TOKEN}" \
        "${HORT_URL}/v2/auth?service=${REGISTRY_HOST}&scope=repository:${REPO_KEY}/$1:$2" \
        2>/dev/null | jq -r '.token // empty'
}

# assert_pull_cap_grants_pull <jwt> <image-name> — the issue-#5 core. Decode the
# capability JWT payload (middle segment, base64url) and assert its access[]
# carries {type:repository, name:REPO_KEY/<image>, actions ⊇ [pull]}. On this
# PRIVATE repo the provenance-ci read grant is LOAD-BEARING: without it the
# /v2/auth mint would narrow the requested `pull` scope to an EMPTY access[]
# (write does not imply read; permissions are flat), and cosign's subject
# preflight would have nothing to authorize against. An empty/pull-less access[]
# is the regression this closes — fail loudly with the decoded access[].
assert_pull_cap_grants_pull() {
    local jwt="$1" image="$2" payload json has_pull
    payload="$(printf '%s' "$jwt" | cut -d. -f2)"
    json="$(printf '%s' "$payload" | python3 -c '
import base64, sys
seg = sys.stdin.read().strip()
seg += "=" * (-len(seg) % 4)
sys.stdout.write(base64.urlsafe_b64decode(seg).decode("utf-8"))
' 2>/dev/null || true)"
    if [ -z "$json" ]; then
        fail "decode /v2/auth capability JWT access[]" \
             "could not base64url-decode the JWT payload segment of the pull-scoped mint"
        return
    fi
    has_pull="$(printf '%s' "$json" | jq -r --arg n "${REPO_KEY}/${image}" \
        '[.access[]? | select(.type=="repository" and .name==$n) | .actions[]?] | index("pull") // empty' \
        2>/dev/null || true)"
    if [ -n "$has_pull" ]; then
        pass "/v2/auth pull-scoped mint carries access[] {repository ${REPO_KEY}/${image} : pull} — the private-repo read grant is load-bearing (issue #5)"
    else
        fail "/v2/auth pull-scoped access[] grants pull on the PRIVATE repo (issue #5)" \
             "decoded access[] lacked a repository/${REPO_KEY}/${image}:pull entry — the read grant is not backing the cap. access[] = $(printf '%s' "$json" | jq -c '.access // []' 2>/dev/null || echo '<undecodable>')"
    fi
}

if [ "$NATIVE_TOKENS" = "1" ]; then
    log "[auth] native-token mode: admin-minting an hort_svc_* token for service account provenance-ci"
    ADMIN_TOKEN="$(fetch_token admin admin)"
    [ -n "$ADMIN_TOKEN" ] || { fail "fetch admin token" "empty response from Keycloak"; summary; }
    SA_UID="$(psql_one "SELECT id FROM users WHERE username='sa:provenance-ci';")"
    [ -n "$SA_UID" ] || { fail "resolve provenance-ci backing user" \
        "no users row 'sa:provenance-ci' — gitops service-accounts/provenance-ci.yaml not applied?"; summary; }
    SVC_TOKEN="$(curl -sS -X POST \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
        -d "{\"name\":\"provenance-e2e-$(date +%s)\",\"declared_permissions\":[\"read\",\"write\"],\"expires_in_days\":1}" \
        "${HORT_URL}/api/v1/admin/users/${SA_UID}/tokens" 2>/dev/null | jq -r '.token // empty')"
    [ -n "$SVC_TOKEN" ] || { fail "admin-mint provenance-ci svc token" \
        "POST /api/v1/admin/users/${SA_UID}/tokens returned no token"; summary; }
    PUSH_USER="provenance-ci"; PUSH_SECRET="$SVC_TOKEN"
    # The hold probes ([2/6]) ride a PULL-scoped capability JWT — the
    # issue-#13 shape: read-only cap, write-granted identity.
    HOLD_BEARER="$(mint_cap_jwt "$SIGNED_NAME" pull)"
    [ -n "$HOLD_BEARER" ] || { fail "mint pull-scoped capability JWT" \
        "GET /v2/auth (Basic <svc-token>, scope …:pull) returned no token"; summary; }
    # issue-#5 core: on the PRIVATE repo the minted pull-scoped cap must actually
    # GRANT pull (the read grant is load-bearing). Assert its access[] here.
    assert_pull_cap_grants_pull "$HOLD_BEARER" "$SIGNED_NAME"
    log "[auth] svc token minted; hold probes ride a pull-scoped /v2/auth capability JWT"
else
    # The public half of COSIGN_KEY must match the worker's registered key or
    # step [3] will Reject instead of Verify.
    DEV_TOKEN="$(fetch_token dev-user dev)"
    [ -n "$DEV_TOKEN" ] || fail "fetch dev-user token" "empty response from Keycloak"
    [ -n "$DEV_TOKEN" ] || summary
    PUSH_USER="dev-user"; PUSH_SECRET="$DEV_TOKEN"; HOLD_BEARER="$DEV_TOKEN"
    log "[auth] legacy mode: fetched DEV_TOKEN from Keycloak (dev-user write-authorized for ${REPO_KEY})"
fi
DEST_CREDS="${PUSH_USER}:${PUSH_SECRET}"

# push_source_index <dest-ref> [<src-ref>] — `skopeo copy --all` a multi-arch
# source (default SOURCE_IMAGE) to a hosted dest, with a bounded retry. The
# pull leg reaches out to a public registry (ghcr.io) for four per-arch images;
# a cold-cache pull occasionally drops a blob mid-copy (transient egress, not a
# Hort defect), and skopeo is not idempotent-resumable on that failure. Three
# attempts make the source pull deterministic without masking a genuine PUT
# rejection (the #15 regression): on a real MANIFEST_INVALID the dest PUT fails
# every attempt. Returns skopeo's last exit status. Runs under
# `set -euo pipefail`, so the `if` consumes each non-final failure's status.
push_source_index() {
    local dest="$1" src="${2:-$SOURCE_IMAGE}" attempt rc=1
    for attempt in 1 2 3; do
        # `|| rc=$?` captures skopeo's real exit under `set -e` (a bare failing
        # command in an `if` would leave `$?`=0 for the whole compound). rc reset
        # to 0 first so a success leaves it 0.
        rc=0
        skopeo copy --all --insecure-policy --dest-tls-verify=false \
              --dest-creds "$DEST_CREDS" \
              "docker://${src}" "docker://${dest}" >/dev/null 2>&1 || rc=$?
        [ "$rc" -eq 0 ] && break
        log "  [push retry] skopeo copy --all ${src} -> ${dest} failed (attempt ${attempt}/3, rc=${rc}); retrying"
        sleep 3
    done
    return "$rc"
}

# =============================================================================
# [1/6] PUSH (unsigned) — accepted, held (write path ungated by the hold)
# =============================================================================
log "==> [1/6] Push --all ${SOURCE_IMAGE} -> docker://${DEST_SIGNED} (to-be-signed image INDEX)"
if push_source_index "$DEST_SIGNED"; then
    pass "push of the to-be-signed image INDEX accepted (index PUT ungated; was MANIFEST_INVALID before issue #15; held under required)"
else
    fail "index push to required+cosign-key repo" \
         "skopeo copy --all -> ${DEST_SIGNED} exited non-zero after retries (a hosted index PUT under required must still be accepted, then HELD — a rejected index PUT is the #15 regression)"
    summary
fi

# Resolve the pushed digest (cosign signs <ref>@<digest>, not the tag).
# `skopeo inspect` issues a manifest GET, which the hold answers with 503 — an
# EXPECTED non-zero exit. common.sh runs the scenario under `set -euo pipefail`,
# so the failing command substitution must be neutralised with `|| true` or
# errexit aborts the script before the write-authorized-HEAD fallback below can
# run (that fallback is the whole point: the HEAD exemption serves the digest
# while GET stays 503).
DIGEST="$(skopeo inspect --tls-verify=false --creds "$DEST_CREDS" \
    "docker://${DEST_SIGNED}" 2>/dev/null | jq -r '.Digest // empty' || true)"
if [ -z "$DIGEST" ]; then
    # Fall back to the Docker-Content-Digest header of a write-authorized HEAD,
    # which the existence-probe exemption serves (200) even under the hold.
    # Capture the FULL status line + headers (no `2>/dev/null` discard) so a
    # failed resolve surfaces the actual HTTP status/headers instead of an
    # opaque empty string — issue #41 died here with the response thrown away.
    HOLD_HEAD_RESP="$(curl -sS -I -H "Authorization: Bearer ${HOLD_BEARER}" \
        "${HORT_URL}/v2/${REPO_KEY}/${SIGNED_NAME}/manifests/v1" 2>&1 || true)"
    DIGEST="$(printf '%s' "$HOLD_HEAD_RESP" | tr -d '\r' \
        | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}')"
fi
if [ -z "$DIGEST" ]; then
    log "[diag #41] write-authorized HEAD-by-tag on ${SIGNED_NAME} (/manifests/v1) returned no Docker-Content-Digest."
    log "[diag #41] HOLD_BEARER len=${#HOLD_BEARER}; full HEAD status line + headers follow:"
    printf '%s\n' "${HOLD_HEAD_RESP:-<no response captured>}" | sed 's/^/[diag #41]   /'
    fail "resolve pushed digest" \
         "neither skopeo inspect nor a write-authorized HEAD returned a digest (actual HTTP status/headers logged above under [diag #41])"
    summary
fi
log "[digest] pushed manifest digest = ${DIGEST}"

# =============================================================================
# [2/6] HELD (PRIVATE) — anonymous manifest read 401; write-authorized HEAD 200
# =============================================================================
log "==> [2/6] Assert PRIVATE+HELD: anonymous manifest GET -> 401 challenge, write-authorized HEAD/GET -> exists"

# PRIVATE repo (isPublic:false): an anonymous (no-credential) read is denied by
# VISIBILITY before any artifact-level hold check, so it never observes the
# hold's 503 — it gets 401 + a `WWW-Authenticate` challenge (ADR 0045). Native
# tokens advertise `Bearer realm=…/v2/auth`; legacy (Basic) advertises
# `Basic realm="hort"`. The status is 401 either way; the challenge SCHEME is
# the mode-aware bit (asserted for native mode below).
ANON_HDRS="$(curl -sS -o /dev/null -D - \
    "${HORT_URL}/v2/${REPO_KEY}/${SIGNED_NAME}/manifests/${DIGEST}" 2>/dev/null || true)"
ANON_GET_CODE="$(printf '%s' "$ANON_HDRS" | tr -d '\r' | awk 'toupper($1) ~ /^HTTP/ {print $2; exit}')"
[ -n "$ANON_GET_CODE" ] || ANON_GET_CODE=000
if [ "$ANON_GET_CODE" = "401" ]; then
    pass "anonymous manifest GET on held PRIVATE image -> 401 (denied by visibility, ADR 0045 challenge; the hold's 503 is not observable anonymously)"
else
    fail "anonymous manifest GET -> 401 (private repo)" \
         "got HTTP ${ANON_GET_CODE} (a private repo must deny an anonymous read with 401 + a challenge before the hold check, ADR 0045)"
fi
if [ "$NATIVE_TOKENS" = "1" ]; then
    if printf '%s' "$ANON_HDRS" | tr -d '\r' | grep -qiE '^WWW-Authenticate:.*Bearer'; then
        pass "anonymous denial advertises a Bearer challenge (native-token mode, ADR 0045 D1)"
    else
        fail "anonymous 401 advertises Bearer (native mode)" \
             "no 'WWW-Authenticate: Bearer' header on the anonymous denial (ADR 0045 D1 mode-aware challenge selector)"
    fi
fi

# In native-token mode HOLD_BEARER is a PULL-scoped capability JWT of the
# write-granted provenance-ci SA — the exemption must key on the identity's
# granted write authority, not the token's read-only cap (ADR 0039 §10,
# issue #13). In legacy mode it is dev-user's IdP JWT (None-cap principal).
WRITE_HEAD_CODE="$(curl -s -o /dev/null -w '%{http_code}' -I \
    -H "Authorization: Bearer ${HOLD_BEARER}" \
    "${HORT_URL}/v2/${REPO_KEY}/${SIGNED_NAME}/manifests/${DIGEST}" 2>/dev/null || echo 000)"
if [ "$WRITE_HEAD_CODE" = "200" ]; then
    pass "write-granted manifest HEAD on held image -> 200/exists (hold-read exemption; signer can preflight)"
else
    fail "write-granted manifest HEAD -> 200" \
         "got HTTP ${WRITE_HEAD_CODE} (the granted-write manifest hold-read exemption must report exists so cosign can preflight; under native tokens a pull-scoped cap must not veto it)"
fi

# Keyed cosign resolves the subject by GET too (ADR 0039 §10): a write-granted
# manifest GET of the held subject SERVES (200), so the sign in [3] can resolve
# the subject. The manifest is metadata, not runnable content; layer bytes stay
# held (the anonymous read above is denied 401 by visibility, layer blobs stay
# HEAD-only for a credentialed reader).
WRITE_GET_CODE="$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer ${HOLD_BEARER}" \
    "${HORT_URL}/v2/${REPO_KEY}/${SIGNED_NAME}/manifests/${DIGEST}" 2>/dev/null || echo 000)"
if [ "$WRITE_GET_CODE" = "200" ]; then
    pass "write-granted manifest GET on held image -> 200/serves (hold-read exemption; keyed cosign resolves the subject by GET)"
else
    fail "write-granted manifest GET -> 200" \
         "got HTTP ${WRITE_GET_CODE} (ADR 0039 §10: a write-granted GET of a held manifest must SERVE so keyed cosign can resolve the subject before signing; under native tokens the pull-scoped cap must not veto held-visibility)"
fi

# =============================================================================
# [3/6] SIGN — cosign sign --key --registry-referrers-mode=oci-1-1 <ref>@<digest>
# =============================================================================
# hort ships its OWN reference keyed-signing script at .gitlab/ci/cosign-sign.sh
# (bundled into the client image as /usr/local/bin/hort-cosign-sign.sh). Its
# vault-key branch is the exact `cosign sign` invocation hort's CI signs
# releases with; issue #18 fixed that flag set (oci-1-1 referrers + the default
# Sigstore v0.3 DSSE bundle, dropping the legacy `--registry-referrers-mode=legacy`
# / `--new-bundle-format=false`). This step proves that flag set produces a
# signature hort's OWN provenance gate accepts.
#
# The sign runs the flags INLINE rather than shelling out to the reference
# script, because that script is intentionally transport-agnostic: it carries NO
# `--allow-http-registry` / `--allow-insecure-registry` / `--registry-username|
# password`. In real CI those are handled out of band (a valid-cert HTTPS
# registry + `cosign login` in cosign-setup.sh). The compose harness registry is
# plaintext HTTP over a PRIVATE repo, so the sign MUST add `--allow-http-registry`
# + explicit creds — and adding an HTTP/insecure-registry toggle to the
# production signing script would reintroduce exactly the `*_INSECURE_TLS`-shaped
# knob the project forbids (ADR 0010; the supported internal-cert path is CA
# trust, not skip-verify). So the harness carries ONLY those transport flags
# inline while pinning the SECURITY-relevant flags to the reference script by
# EQUIVALENCE (asserted just below), and `shellcheck` covers the script itself.
REF_SIGNER="/usr/local/bin/hort-cosign-sign.sh"
if [ -x "$REF_SIGNER" ]; then
    # Extract the vault-key case body, dropping COMMENT lines — the branch's
    # explanatory comments name the removed legacy flags ("NOT …
    # --new-bundle-format=false"), which would false-positive the regression
    # grep below; only the actual `cosign sign` invocation must be checked.
    REF_VAULT_BLOCK="$(awk '/vault-key\)/{f=1} f && $1 !~ /^#/{print} /;;/{if(f)exit}' "$REF_SIGNER")"
    REF_OK=1
    for flag in '--registry-referrers-mode=oci-1-1' '--use-signing-config=false' \
                '--tlog-upload=false' '--key /tmp/cosign.key'; do
        printf '%s' "$REF_VAULT_BLOCK" | grep -qF -- "$flag" || REF_OK=0
    done
    # The issue-#18 regression flags must be GONE from the reference script.
    if printf '%s' "$REF_VAULT_BLOCK" | grep -qE -- '--new-bundle-format=false|--registry-referrers-mode=legacy'; then
        REF_OK=0
    fi
    if [ "$REF_OK" = "1" ]; then
        pass "reference signer ${REF_SIGNER} vault-key flags match the keyed-sign flags hort's gate accepts (issue #18: oci-1-1 referrers + default v0.3 bundle, no legacy flags)"
    else
        fail "reference signer flag set (issue #18)" \
             "vault-key branch of ${REF_SIGNER} lacks an expected keyed-sign flag (oci-1-1 referrers, --use-signing-config=false, --tlog-upload=false, --key /tmp/cosign.key) or still carries a removed legacy flag"
    fi
else
    fail "reference signer bundled in client image" \
         "${REF_SIGNER} missing/not executable (Dockerfile.client must COPY .gitlab/ci/cosign-sign.sh)"
fi

# Keyed cosign resolves the subject by GET (ADR 0039 §10); the widened manifest
# hold-read exemption serves that GET to the write-authorized signer, so the
# sign must COMPLETE against the held subject. Capture cosign's output so a
# reviewer can see the exact blocked op if it ever regresses.
log "==> [3/6] cosign sign --key ... --registry-referrers-mode=oci-1-1 ${DEST_SIGNED%:*}@${DIGEST}"
export COSIGN_DOCKER_MEDIA_TYPES=1
# cosign v3 still gates `--registry-referrers-mode=oci-1-1` (the subject-based
# OCI 1.1 referrers carriage ADR 0039 §9 REQUIRES for hosted keyed signing)
# behind COSIGN_EXPERIMENTAL=1; without it cosign errors out before any registry
# call. The operator running `cosign v3.0.4` sets the same flag.
export COSIGN_EXPERIMENTAL=1
SIGN_OUT=""
SIGN_RC=0
SIGN_OUT="$(cosign sign --yes \
    --key "$COSIGN_KEY" \
    --registry-referrers-mode=oci-1-1 \
    --registry-username="$PUSH_USER" \
    --registry-password="$PUSH_SECRET" \
    --allow-insecure-registry \
    --allow-http-registry \
    "${REGISTRY_HOST}/${REPO_KEY}/${SIGNED_NAME}@${DIGEST}" 2>&1)" || SIGN_RC=$?
if [ "$SIGN_RC" -eq 0 ]; then
    pass "cosign sign (keyed, oci referrers) succeeded — the write-authorized manifest HEAD-and-GET hold-read exemption served the subject to the signer"
else
    log "[cosign output]"; printf '%s\n' "$SIGN_OUT" | sed 's/^/    /'
    if printf '%s' "$SIGN_OUT" | grep -Eqi 'GET .*/manifests/.*503|503 .*manifests'; then
        fail "cosign sign hold-read exemption regressed" \
             "cosign got a 503 on a manifest GET during signing -> the write-authorized manifest hold-read exemption (ADR 0039 §10) is not serving the held subject to the signer; the exemption regressed to HEAD-only"
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
        "skopeo copy --all --insecure-policy --src-tls-verify=false --src-creds '${DEST_CREDS}' 'docker://${DEST_SIGNED}' 'oci-archive:${PULLED_ARCHIVE}'" \
        5; then
    pass "signed image index released and pulled after the quarantine window (Cleared + timer gate satisfied)"
else
    fail "signed image releases + pulls" \
         "the signed+cleared image never became pullable within ${WINDOW_WAIT_SECS}s (window or provenance gate not satisfied)"
fi

# =============================================================================
# [6/6] NEGATIVE — never-signed image -> terminal Rejected{Unsigned} at expiry
# =============================================================================
log "==> [6/6] NEGATIVE: push an image INDEX (distinct digest), never sign it -> terminal Rejected{Unsigned} at window expiry"
# Distinct-digest source (UNSIGNED_SOURCE_IMAGE) — same-bytes would CAS-dedup
# to the signed leg's already-released artifact (see the env-contract comment).
if push_source_index "$DEST_UNSIGNED" "$UNSIGNED_SOURCE_IMAGE"; then
    log "  pushed never-to-be-signed image index ${UNSIGNED_SOURCE_IMAGE} -> ${DEST_UNSIGNED}"
else
    fail "push never-signed image index" "skopeo copy --all ${UNSIGNED_SOURCE_IMAGE} -> ${DEST_UNSIGNED} exited non-zero"
    summary
fi

# Resolve the never-signed image's digest via a WRITE-authorized manifest HEAD
# (the hold-read exemption serves it while held) so the terminal decision can be
# observed by content hash below. In native-token mode the write authority rides
# a fresh pull-scoped capability JWT for THIS image (the SIGNED-image HOLD_BEARER
# is scoped to a different name); in legacy mode dev-user's repo-wide grant
# covers it directly.
UNSIGNED_HOLD_BEARER="$HOLD_BEARER"
[ "$NATIVE_TOKENS" = "1" ] && UNSIGNED_HOLD_BEARER="$(mint_cap_jwt "$UNSIGNED_NAME" pull)"
UNSIGNED_DIGEST="$(curl -sSI -H "Authorization: Bearer ${UNSIGNED_HOLD_BEARER}" \
    "${HORT_URL}/v2/${REPO_KEY}/${UNSIGNED_NAME}/manifests/v1" 2>/dev/null \
    | tr -d '\r' | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}' || true)"
[ -n "$UNSIGNED_DIGEST" ] || { fail "resolve never-signed digest" \
    "write-authorized HEAD of ${UNSIGNED_NAME} returned no Docker-Content-Digest (needed to observe its terminal ProvenanceRejected)"; summary; }
UNSIGNED_DIGEST_HEX="${UNSIGNED_DIGEST#sha256:}"
log "[digest] never-signed manifest digest = ${UNSIGNED_DIGEST}"

# PRIVATE repo: an anonymous read is denied by VISIBILITY (401), whether the
# image is HELD or terminally Rejected — the 503->404 transition the public
# variant watched is not observable anonymously. Assert the visibility denial…
ANON_UNSIGNED_CODE="$(curl -sS -o /dev/null -w '%{http_code}' \
    "${HORT_URL}/v2/${REPO_KEY}/${UNSIGNED_NAME}/manifests/v1" 2>/dev/null || echo 000)"
if [ "$ANON_UNSIGNED_CODE" = "401" ]; then
    pass "never-signed PRIVATE image denies anonymous reads with 401 (visibility, ADR 0045 — held and terminal are indistinguishable anonymously on a private repo)"
else
    fail "never-signed image anonymous read -> 401 (private repo)" \
         "got HTTP ${ANON_UNSIGNED_CODE} (a private repo must 401 an anonymous read before the hold/terminal check, ADR 0045; 200 would mean an unsigned image is being served)"
fi

# …and observe the TERMINAL Rejected{Unsigned} decision via the emitted domain
# event, exactly as [4/6] observes ProvenanceVerified. At window expiry the
# release sweep enqueues a final provenance-verify with window_open=false and
# complete_provenance emits ProvenanceRejected{Unsigned}. The event is the
# authoritative, mode-independent signal (no token-expiry window, and no
# anonymous 503->404 transition to watch on a private repo).
if bounded_poll \
        "never-signed manifest -> terminal ProvenanceRejected{Unsigned}" \
        "$WINDOW_WAIT_SECS" \
        "[ -n \"\$(psql_one \"SELECT 1 FROM events e JOIN artifacts a ON e.stream_id = 'artifact-' || a.id::text WHERE a.checksum_sha256 = '${UNSIGNED_DIGEST_HEX}' AND e.event_type = 'ProvenanceRejected' LIMIT 1;\")\" ]" \
        5; then
    pass "never-signed image is terminally Rejected{Unsigned} at window expiry (ProvenanceRejected event emitted, not released)"
else
    fail "never-signed image -> terminal Rejected{Unsigned}" \
         "no ProvenanceRejected event for checksum ${UNSIGNED_DIGEST_HEX} within ${WINDOW_WAIT_SECS}s (the expiry backstop should have made the terminal Unsigned decision)"
fi

summary
