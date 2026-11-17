#!/usr/bin/env bash
# requires: egress worker db compose
# Proxy pull-through x provenance_mode:Required, multi-layer image — the
# regression E2E for a defect in the `NoAttestation x Required` hold.
#
# ---------------------------------------------------------------------------
# THE DEFECT AND WHAT THIS PINS.
# ---------------------------------------------------------------------------
# `Artifact::complete_provenance`'s NoAttestation x Required arm once only
# HELD (stayed Quarantined, no terminal decision) while the artifact's own
# observation window was still open. Back then a referenced-tree descendant
# waived that window unconditionally, so for a proxy-pulled tree every
# constituent — the platform-specific child manifest, its config blob, its
# layer blobs — had a closed window from the instant it was ingested, and the
# OLD code TERMINALLY REJECTED it as `Unsigned` before the parent index (the
# actual signable subject) ever got a chance to be signed.
#
# The window is no longer part of that decision at all. ADR 0039 D1/D3
# (2026-09-12) removed the enumeration: an absent attestation holds EVERY
# shape unconditionally — independent of the artifact's position in the tree
# and of whether its subject is ever signed — because an absent attestation
# states where the evidence was at one instant, which nothing terminal can
# rest on. Only a signature that is present, readable and invalid is
# terminal. A held constituent clears later via cascade
# (`cascade_provenance_clearance`, ADR 0039 §11) once the subject verifies.
# So the hold this scenario drives no longer depends on the window, and the
# window assertions in Step 7 are about the RELEASE TIMER (ADR 0007), which
# is a separate axis that also has to be satisfied before anything serves.
#
# This scenario drives that composition for real: pull a genuine multi-layer
# OCI image INDEX through a `provenance_mode: Required` PROXY repo, sign the
# INDEX (the real subject), and assert:
#   (a) the pull EVENTUALLY SUCCEEDS (subject verifies, cascade clears the
#       child manifest + its config/layer blobs, every quarantine window
#       elapses, the whole tree becomes anonymously pullable);
#   (b) NONE of the constituents (child manifest, config blob, every layer
#       blob) EVER emits `ProvenanceRejected` — the exact defect signature
#       the unconditional hold fixed (pre-fix, each would have terminally
#       rejected as Unsigned within moments of ingest, long before this
#       scenario's later assertions even run).
#
# ---------------------------------------------------------------------------
# MODEL SCENARIOS COMBINED, NOT REINVENTED.
# ---------------------------------------------------------------------------
# - Proxy pull-through mechanics (cold GET by tag -> resolve a linux/amd64
#   child by digest -> GET the child -> content_references edge assertions
#   -> quarantine_window_start differential) are
#   scenarios/quarantine/proxy-multiarch-zero-window.sh's pattern.
# - Keyed cosign signing mechanics (env-var contract, tool-availability
#   self-skip, the committed test keypair, dual native-token/legacy auth,
#   `cosign sign --key --registry-referrers-mode=oci-1-1`, the
#   ProvenanceVerified poll) are
#   scenarios/quarantine/provenance-push-then-sign.sh's pattern.
# Unlike that script, this repo is PUBLIC (isPublic:true, like
# oci-proxy-quarantine-e2e) — the private-repo visibility x hold interaction
# (ADR 0045) is already covered there; this scenario stays focused on the
# proxy x Required x descendant-hold composition. The FIRST-touch cold index
# GET (Step 0) is the fetch that performs the ingest, and — mirroring
# proxy-multiarch-zero-window.sh's own Step 0 — the designed proxy read path
# never hands that fetch's caller the freshly-ingested, still-quarantined
# manifest even though it is the one that populated it: an anonymous caller
# gets 503 + Retry-After + an UNAVAILABLE body, not the manifest. Every
# subsequent manifest READ (index re-GET, child GET) authenticates with the
# credential already fetched below (PUSH_USER/PUSH_SECRET) and relies on the
# write-authorized hold-read exemption (ADR 0039 §10) to see the held
# content — the same exemption the cosign sign step's own subject-resolution
# GET needs, so signing needs no separate credential dance.
#
# ---------------------------------------------------------------------------
# WHY A NEW REPO+POLICY+SA, NOT A REUSE.
# ---------------------------------------------------------------------------
# ScanPolicy scope is 1:1 per-repository (see
# oci-provenance-proxy-e2e-required.yaml's header): oci-provenance-e2e is
# hosted-push-only (no upstream mapping — cannot proxy-pull), and
# oci-proxy-quarantine-e2e's policy is provenanceMode:off and load-bearing
# for the sibling descendant-window scenario
# (quarantine/proxy-multiarch-zero-window.sh). So this adds ONE new repository
# + upstream mapping + policy + a per-repo service account + its
# PermissionGrants (write, read) + a per-repo dev-user write grant — the same
# fixture multiplication provenance-push-then-sign.sh's own repo needed,
# mirrored rather than invented (see each new file's own header comment).
#
# ---------------------------------------------------------------------------
# WHY redis:7-alpine, WHY LENGTH ASSERTED AT RUNTIME NOT HARDCODED.
# ---------------------------------------------------------------------------
# `redis:7-alpine` is a genuine Docker Hub multi-arch image INDEX with
# multiple layers per platform child. The layer COUNT is never assumed —
# `.layers | length` is asserted `>= 2` against the manifest hort actually
# served, so a future upstream retag that collapses to a single layer fails
# loudly instead of silently testing nothing (same discipline as
# proxy-multiarch-zero-window.sh's digest-not-count assertions).
#
# ---------------------------------------------------------------------------
# WHY THIS MAY SELF-SKIP — see provenance-push-then-sign.sh's identical note.
# ---------------------------------------------------------------------------
# Same three preconditions (cosign+buildah in the client image, a keyed
# signing keypair, a required+cosign-key repo in the mounted gitops config) —
# this item's gitops config supplies the third; the first two are a CI
# provisioner concern this item's directive explicitly does not touch.

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"

if [ "${HORT_TEST_DEBUG:-0}" = "1" ]; then
    set -x
fi

# -----------------------------------------------------------------------------
# Env contract (CI provisioner overrides; sensible defaults otherwise)
# -----------------------------------------------------------------------------
REPO_KEY="${PROVENANCE_PROXY_REPO_KEY:-oci-provenance-proxy-e2e}"
COSIGN_KEY="${COSIGN_KEY:-${FIXTURES:-}/cosign/cosign.key}"
export COSIGN_PASSWORD="${COSIGN_PASSWORD:-}"
IMAGE="${IMAGE:-redis:7-alpine}"
RESOLVER_REFRESH_GUESS="${RESOLVER_REFRESH_GUESS:-8}"
# The repository policy's quarantine window, in seconds — the literal
# `quarantineDuration: 120s` in
# deploy/compose/example-config/policies/oci-provenance-proxy-e2e-required.yaml.
# Hardcoded rather than resolved from `policy_projections` (mirrors
# proxy-multiarch-zero-window.sh, which hardcodes its own policy's 24h for the
# identical reason: the `scope` column is jsonb keyed by repository NAME, not a
# `repository_id` foreign key, so a dynamic lookup would need the same
# scope-resolution logic the application layer already owns — out of scope for
# a scenario script to reimplement).
#
# ONE definition with TWO consumers: Step 7's window assertions and Step
# 9b-i's release budget below. Change the policy's duration and both follow.
QUARANTINE_DURATION_SECS=120
#
# Step 8 budget (await ProvenanceVerified on the signed index). Deliberately
# NOT window-bound: `cosign sign` has already returned by the time this wait
# starts, so what is outstanding is the worker claiming the provenance-verify
# job and running one keyed verification — seconds in practice. 240s is a
# generous ceiling against a backed-up worker queue, not a window computation.
# The window arithmetic belongs to Steps 9a and 9b-i, the two waits in this
# scenario that sit behind a quarantine window.
WINDOW_WAIT_SECS="${PROVENANCE_WINDOW_WAIT_SECS:-240}"
#
# Step 9b-i budget — await the INDEX row's release. Step 7 asserts the index
# carries the FULL window (`quarantine_window_start == created_at`, anchored
# on the Step 0 cold ingest: the index is not a content_references target, so
# the descendant carve-out is not even evaluated for it), and release lands on
# the first quarantine-release-sweep pass AFTER that window closes. The budget
# is therefore the whole window + one full sweep-tick interval (a window closing
# just after a tick fired waits for the next one) + the job-claim/release work
# behind that tick.
#
# FASTER MUST NOT BE WORSE. The elapsed time between Step 0 and this wait is
# deliberately NOT subtracted from the window. That time is window the clock
# has already burned, so subtracting it shrinks the budget as the earlier steps
# get faster — a budget that holds only because the steps before it were slow.
# Summing against the WHOLE window makes the worst case "this wait starts at
# the instant of ingest", which no future speed-up of Steps 0-9a can beat. (The
# 90s this step used to get assumed that gap was >= ~45s. Two lanes that ran
# Steps 0-9a in ~15s timed out 14-15s BEFORE the window had even closed, with
# hort holding the index exactly as ADR 0007 requires — same commit, green on
# a slower machine, red on a faster one.)
#
# The sweep cadence the budget must assume. This scenario cannot OBSERVE the
# server's cadence — the compose ticker's SWEEP_TICK_SECS is not passed into
# the client container — so budget against the compose file's own default of
# 15s, the slower of the two values a compose run uses
# (scripts/native-tests/run.sh lowers it to 5s at `up` time). A stack whose
# release sweep runs less often than this needs INDEX_RELEASE_WAIT_SECS raised.
RELEASE_SWEEP_TICK_BUDGET_SECS=15
# Job claim + release commit + projection behind the releasing tick: observed
# 10-40s on compose, budgeted well past that on purpose. It is the only term in
# the sum that is an OBSERVATION rather than a configured bound (the window is
# the policy's own number, the tick is the compose file's), so it is where this
# budget's margin belongs — and the margin has to be real slack, because the
# sum deliberately refuses to count the elapsed time before the wait.
RELEASE_PROCESSING_BUDGET_SECS=105
INDEX_RELEASE_WAIT_SECS="${INDEX_RELEASE_WAIT_SECS:-$(( QUARANTINE_DURATION_SECS + RELEASE_SWEEP_TICK_BUDGET_SECS + RELEASE_PROCESSING_BUDGET_SECS ))}"
#
# Step 9b-ii budget — the anonymous `--all` pull, which runs only after 9a
# proved every constituent BLOB served and 9b-i proved the index released.
# Nothing behind this leg is window-bound, and the reason is the ORDERING
# rather than any constituent's window being short: 9a cannot succeed until
# each blob in the tree has released, which means each blob's own window has
# already closed — and every blob here is minted after the manifest that
# names it (the `oci_config` / `oci_layer` edge commits in that manifest's
# own transition, and nothing in this scenario GETs a blob before its
# manifest), so every constituent manifest's window closed earlier still.
# The most one can owe by this point is a sweep tick on an already-eligible
# row. (Each constituent DOES carry a window of its own: its
# referencing parent is held when it is minted, so the ADR 0007 carve-out's
# inherited-trust condition is unmet and no window is waived. 9a is where
# that time is spent; see its budget below.) What remains here is a warm pull
# from local storage. Keeping this budget SHORT is what makes a timeout here
# mean "clearance or cascade" and never "the window".
ANON_PULL_WAIT_SECS="${ANON_PULL_WAIT_SECS:-60}"
#
# Step 9a budget — the AUTHENTICATED `--all` warm pass.
#
# Sized against the CONSTITUENT CLEARANCE TAIL, not against a round
# number, because the exemption this step leans on does not reach what
# the step actually downloads. ADR 0039 §10's hold-read exemption is
# MANIFEST-only: a granted-Write caller may GET a held manifest body so
# a subject image can be signed, and `skopeo copy --all` does get every
# manifest in the tree that way. Its BLOB content does not come with it
# — `get_blob_quarantined_write_authorized_caller_still_returns_503`
# pins that ("only the HEAD existence probe is released; content
# download stays held"), and serving held blob content would defeat the
# quarantine. So this pull completes only once every CONSTITUENT blob
# has actually RELEASED, which means its own scan clearing, its own
# observation window closing, and a sweep tick.
#
# That tail scales with the SIZE OF THE TREE — one scan per constituent
# — so it is not RELEASE_PROCESSING_BUDGET_SECS, which budgets the
# release work behind a single artifact's tick (observed 10-40s) and
# would be reused here far outside what it was measured for.
#
# THE WINDOW IS INSIDE THIS BUDGET, NOT ADDED TO IT. A constituent is
# minted while its referencing parent is still held, so ADR 0007's
# carve-out does not apply to it and it carries a full
# QUARANTINE_DURATION_SECS window of its own (Step 7 asserts exactly
# that). The window and the scan both start at that mint, so what
# release waits for is the LATER of the two, not their sum — and the
# window is 120s against a 240s clearance tail, i.e. strictly inside a
# budget that already had to cover the scan. That holds even for a
# constituent this very step drives in, whose window therefore starts
# after the wait did: 120s of window + a sweep tick + the release work
# behind it is still inside the sum below. Raising the policy's duration
# past CONSTITUENT_CLEARANCE_BUDGET_SECS would change that, and is where
# this number would have to be re-derived.
#
# FASTER MUST NOT BE WORSE, the same rule 9b-i states: the elapsed time
# before this wait is deliberately NOT subtracted, so the worst case is
# "this pass starts at the instant of the Step 0 ingest" and no future
# speed-up of Steps 0-8 can beat it. (The bare `120` this step used to
# carry failed exactly that way: a run whose Steps 0-8 took 9.8s reached
# its deadline 20.4s before the last constituent released, with every
# byte already in CAS since 28.6s — the tree was ingested and hort was
# holding it exactly as ADR 0007 requires.)
CONSTITUENT_CLEARANCE_BUDGET_SECS=240
WARM_PASS_WAIT_SECS="${WARM_PASS_WAIT_SECS:-$(( CONSTITUENT_CLEARANCE_BUDGET_SECS + RELEASE_SWEEP_TICK_BUDGET_SECS ))}"

REGISTRY_HOST="${HORT_URL#http://}"
REGISTRY_HOST="${REGISTRY_HOST#https://}"

OCI_INDEX_MEDIA="application/vnd.oci.image.index.v1+json"
DOCKER_LIST_MEDIA="application/vnd.docker.distribution.manifest.list.v2+json"
OCI_MANIFEST_MEDIA="application/vnd.oci.image.manifest.v1+json"
DOCKER_MANIFEST_MEDIA="application/vnd.docker.distribution.manifest.v2+json"

command -v jq >/dev/null 2>&1 || skip "jq not found"
command -v curl >/dev/null 2>&1 || skip "curl not found"
command -v skopeo >/dev/null 2>&1 || skip "skopeo not found in client image"
command -v cosign >/dev/null 2>&1 || \
    skip "cosign not in client image — provision cosign + a keyed key + this item's required/cosign-key repo, then re-run (see header)"
[ -n "$COSIGN_KEY" ] || \
    skip "COSIGN_KEY unset — no keyed cosign private key to sign with (its public half must be the worker's registered cosign-key)"
[ -f "$COSIGN_KEY" ] || \
    skip "keyed cosign private key '$COSIGN_KEY' not found (expected the committed fixture at \$FIXTURES/cosign/cosign.key, or a CI-provided COSIGN_KEY)"

IMAGE_REPO="${IMAGE%%:*}"
IMAGE_TAG="${IMAGE##*:}"
case "$IMAGE_REPO" in
    */*) IMAGE_PATH="${IMAGE_REPO}" ;;
    *)   IMAGE_PATH="library/${IMAGE_REPO}" ;;
esac
BASE_URL="${HORT_URL}/v2/${REPO_KEY}/dockerhub/${IMAGE_PATH}"
PULLED_ARCHIVE="/tmp/prov-proxy-pulled-$$.tar"
WARM_ARCHIVE="/tmp/prov-proxy-warm-$$.tar"
trap 'rm -f "$PULLED_ARCHIVE" "$WARM_ARCHIVE" "${ANON_HEADERS:-}" "${ANON_BODY:-}" "${INDEX_HEADERS:-}" "${INDEX_BODY:-}" "${CHILD_HEADERS:-}" "${CHILD_BODY:-}"' EXIT

log "==> Proxy pull-through x provenance_mode:Required, multi-layer image"
log "Registry : ${HORT_URL}"
log "Repo key : ${REPO_KEY} (expected: provenanceMode=required, provenanceBackends=[cosign-key])"
log "Image    : ${IMAGE} (${IMAGE_PATH})"

# -----------------------------------------------------------------------------
# Credential mode for the authenticated manifest reads (Steps 1-2) and the
# SIGN step (mirrors provenance-push-then-sign.sh's dual native-token/legacy
# auth) — the repo is public, so only the write-authorized hold-read
# exemption needs a credential at all; the cold-ingest GET (Step 0) stays
# anonymous.
# -----------------------------------------------------------------------------
NATIVE_TOKENS=0
case " ${HORT_COMPOSE_OVERLAYS:-} " in
    *" native-tokens "*) NATIVE_TOKENS=1 ;;
esac

if [ "$NATIVE_TOKENS" = "1" ]; then
    log "[auth] native-token mode: admin-minting an hort_svc_* token for service account provenance-proxy-ci"
    SVC_TOKEN="$(mint_svc_token provenance-proxy-ci "$REPO_KEY" read,write)" || {
        fail "admin-mint provenance-proxy-ci svc token" "mint_svc_token failed -- see stderr diagnostics above"; summary; }
    PUSH_USER="provenance-proxy-ci"; PUSH_SECRET="$SVC_TOKEN"
    log "[auth] svc token minted for the sign step"

    # --- Negative regression pin (native mode only) -------------------------
    # A deliberate GLOBAL mint (no repository_ids) for the same repo-scoped
    # SA must be denied: `run_issuance_gates`'s `None` branch
    # (crates/hort-app/src/use_cases/api_token_use_case.rs:2212-2223)
    # requires each declared permission to be held GLOBALLY, and
    # provenance-proxy-ci only ever holds a per-repo grant on REPO_KEY --
    # "a per-repo-only grantee CANNOT mint a global token, only a per-repo
    # one." This pins that invariant at the E2E tier: the admin-mint-without-
    # scope path this scenario used to take (and which silently swallowed
    # its own failure) is now the deliberately-tested negative case, not the
    # happy path.
    NEG_ADMIN_TOKEN="$(fetch_token admin admin)"
    [ -n "$NEG_ADMIN_TOKEN" ] || fail "fetch admin token (negative-mint pin)" "empty response from Keycloak"
    NEG_SA_UID="$(psql_one "SELECT id FROM users WHERE username='sa:provenance-proxy-ci';")"
    [ -n "$NEG_SA_UID" ] || fail "resolve provenance-proxy-ci backing user (negative-mint pin)" \
        "no users row 'sa:provenance-proxy-ci'"
    if [ -n "$NEG_ADMIN_TOKEN" ] && [ -n "$NEG_SA_UID" ]; then
        NEG_RESP="$(curl -sS -w '\n%{http_code}' -X POST \
            -H "Authorization: Bearer ${NEG_ADMIN_TOKEN}" -H 'Content-Type: application/json' \
            -d "{\"name\":\"provenance-proxy-e2e-negative-$(date +%s)\",\"declared_permissions\":[\"read\",\"write\"],\"expires_in_days\":1}" \
            "${HORT_URL}/api/v1/admin/users/${NEG_SA_UID}/tokens" 2>/dev/null)"
        NEG_HTTP_CODE="${NEG_RESP##*$'\n'}"
        NEG_BODY="${NEG_RESP%$'\n'*}"
        NEG_ERROR="$(printf '%s' "$NEG_BODY" | jq -r '.error // empty' 2>/dev/null || true)"
        if [ "$NEG_HTTP_CODE" = "403" ] && [ "$NEG_ERROR" = "cap_exceeds_authority" ]; then
            pass "deliberate global mint for repo-scoped SA provenance-proxy-ci -> 403 cap_exceeds_authority (issuance invariant pinned)"
        else
            fail "negative global-mint pin for provenance-proxy-ci" \
                "want HTTP 403 {\"error\":\"cap_exceeds_authority\",...}, got HTTP ${NEG_HTTP_CODE}: $(printf '%s' "$NEG_BODY" | head -c 300)"
        fi
    fi
else
    DEV_TOKEN="$(fetch_token dev-user dev)"
    [ -n "$DEV_TOKEN" ] || fail "fetch dev-user token" "empty response from Keycloak"
    [ -n "$DEV_TOKEN" ] || summary
    PUSH_USER="dev-user"; PUSH_SECRET="$DEV_TOKEN"
    log "[auth] legacy mode: fetched DEV_TOKEN from Keycloak (dev-user write-authorized for ${REPO_KEY})"
fi

# ---------------------------------------------------------------------
# Preflight: the resolver cache picks up gitops-applied upstream mappings
# on its own refresh cadence (mirrors proxy-multiarch-zero-window.sh).
# ---------------------------------------------------------------------
log ""
log "--- Preflight: waiting up to ${RESOLVER_REFRESH_GUESS}s for the resolver cache"
sleep "${RESOLVER_REFRESH_GUESS}"

# ---------------------------------------------------------------------
# Step 0: ANONYMOUS cold-pull of the INDEX by tag. This is the triggering
# fetch — it performs the cold ingest — and the designed proxy read path
# never hands an unprivileged caller the freshly-ingested, still-quarantined
# manifest: the response is 503 with a Retry-After header and an
# UNAVAILABLE error body, not the manifest itself (mirrors
# proxy-multiarch-zero-window.sh's Step 0 — the regression pin for the hold).
# ---------------------------------------------------------------------
log ""
log "--- Step 0: ANONYMOUS GET the index by tag (cold ingest; must hold, not serve)"

ANON_HEADERS="$(mktemp)"
ANON_BODY="$(mktemp)"

ANON_CODE="$(curl -sS -o "$ANON_BODY" -D "$ANON_HEADERS" -w '%{http_code}' \
    -H "Accept: ${OCI_INDEX_MEDIA}, ${DOCKER_LIST_MEDIA}" \
    "${BASE_URL}/manifests/${IMAGE_TAG}" 2>/dev/null || echo 000)"
if [ "$ANON_CODE" = "503" ]; then
    pass "ANONYMOUS GET index by tag -> 503 (quarantined; cold ingest performed)"
else
    fail "ANONYMOUS GET index by tag -> 503" "got HTTP ${ANON_CODE} (egress? upstream reachable? gitops applied?)"
    summary
fi

if grep -qi '^retry-after:' "$ANON_HEADERS"; then
    pass "ANONYMOUS 503 carries a Retry-After header"
    # Logged, not asserted: the value is the window LEFT, measured from the
    # derived anchor (ADR 0054 — the minimum over the age sources), so an
    # inherited anchor legitimately shortens it. Expect at most 120
    # (the repo's quarantineDuration) and never a flat 3600, which was the
    # deadline-unknown fallback this response used to fall back on because
    # nothing on the ingest path hydrated the transient deadline.
    log "  INFO: Retry-After = $(grep -i '^retry-after:' "$ANON_HEADERS" | tr -d '\r' | awk '{print $2}') (expected <= 120, never 3600)"
else
    fail "ANONYMOUS 503 carries a Retry-After header" "no Retry-After header in response"
fi

ANON_ERROR_CODE="$(jq -r '.errors[0].code // empty' "$ANON_BODY" 2>/dev/null)"
if [ "$ANON_ERROR_CODE" = "UNAVAILABLE" ]; then
    pass "ANONYMOUS 503 body errors[0].code == UNAVAILABLE"
else
    fail "ANONYMOUS 503 body errors[0].code == UNAVAILABLE" "got '${ANON_ERROR_CODE:-<empty>}'"
fi

# ---------------------------------------------------------------------
# Step 1: AUTHENTICATED re-GET of the INDEX by tag — the write-authorized
# hold-read exemption (ADR 0039 §10) serves the already-quarantined index to
# the credential fetched above (PUSH_USER/PUSH_SECRET).
# ---------------------------------------------------------------------
log ""
log "--- Step 1: AUTHENTICATED GET the index by tag (write-authorized hold-read)"

INDEX_HEADERS="$(mktemp)"
INDEX_BODY="$(mktemp)"

INDEX_CODE="$(curl -sS -o "$INDEX_BODY" -D "$INDEX_HEADERS" -w '%{http_code}' \
    -H "Authorization: Bearer ${PUSH_SECRET}" \
    -H "Accept: ${OCI_INDEX_MEDIA}, ${DOCKER_LIST_MEDIA}" \
    "${BASE_URL}/manifests/${IMAGE_TAG}" 2>/dev/null || echo 000)"
if [ "$INDEX_CODE" = "200" ]; then
    pass "AUTHENTICATED GET index by tag -> 200 (write-authorized hold-read exemption)"
else
    fail "AUTHENTICATED GET index by tag -> 200" "got HTTP ${INDEX_CODE}"
    summary
fi

INDEX_DIGEST="$(tr -d '\r' < "$INDEX_HEADERS" | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2; exit}')"
if [ -n "$INDEX_DIGEST" ]; then
    pass "index resolved: Docker-Content-Digest=${INDEX_DIGEST}"
else
    fail "index Docker-Content-Digest header present" "no header on the index response"
    summary
fi
INDEX_HASH="${INDEX_DIGEST#sha256:}"

CHILD_DIGEST="$(jq -r '.manifests[]? | select(.platform.architecture=="amd64" and .platform.os=="linux") | .digest' "$INDEX_BODY" 2>/dev/null | head -1)"
if [ -n "$CHILD_DIGEST" ]; then
    pass "resolved linux/amd64 child manifest digest: ${CHILD_DIGEST}"
else
    fail "resolve linux/amd64 child digest from served index" \
        "no .manifests[] entry with platform.architecture=amd64, platform.os=linux"
    summary
fi
CHILD_HASH="${CHILD_DIGEST#sha256:}"

# ---------------------------------------------------------------------
# Step 2: AUTHENTICATED pull of the child manifest BY DIGEST — the
# write-authorized hold-read exemption again (the child is also still
# quarantined).
# ---------------------------------------------------------------------
log ""
log "--- Step 2: AUTHENTICATED GET the child manifest by digest"

CHILD_HEADERS="$(mktemp)"
CHILD_BODY="$(mktemp)"

CHILD_CODE="$(curl -sS -o "$CHILD_BODY" -D "$CHILD_HEADERS" -w '%{http_code}' \
    -H "Authorization: Bearer ${PUSH_SECRET}" \
    -H "Accept: ${OCI_MANIFEST_MEDIA}, ${DOCKER_MANIFEST_MEDIA}" \
    "${BASE_URL}/manifests/${CHILD_DIGEST}" 2>/dev/null || echo 000)"
if [ "$CHILD_CODE" = "200" ]; then
    pass "AUTHENTICATED GET child manifest by digest -> 200 (write-authorized hold-read exemption)"
else
    fail "AUTHENTICATED GET child manifest by digest -> 200" "got HTTP ${CHILD_CODE}"
    summary
fi

CONFIG_DIGEST="$(jq -r '.config.digest // empty' "$CHILD_BODY" 2>/dev/null)"
LAYER_COUNT="$(jq -r '.layers | length' "$CHILD_BODY" 2>/dev/null || echo 0)"
if [ -n "$CONFIG_DIGEST" ] && [ "$LAYER_COUNT" -ge 2 ] 2>/dev/null; then
    pass "child manifest carries a config digest and ${LAYER_COUNT} layers (>= 2, verified at runtime — the item's multi-layer requirement)"
else
    fail "resolve child .config.digest and >= 2 .layers[]" \
        "config='${CONFIG_DIGEST:-<empty>}' layers=${LAYER_COUNT:-0} (expected >= 2 — try a different IMAGE if the upstream tag changed shape)"
    summary
fi
CONFIG_HASH="${CONFIG_DIGEST#sha256:}"
mapfile -t LAYER_DIGESTS < <(jq -r '.layers[].digest' "$CHILD_BODY" 2>/dev/null)
LAYER_HASHES=()
for d in "${LAYER_DIGESTS[@]}"; do LAYER_HASHES+=("${d#sha256:}"); done
log "  child config digest = ${CONFIG_DIGEST}"
log "  child layer digests = ${LAYER_DIGESTS[*]}"

# ---------------------------------------------------------------------
# Step 3: force constituent ingest — explicit GET of the config blob and
# every layer blob through the proxy, run BEFORE the sign (Step 4), never
# after it. Two invariants converge on this ordering:
#   (a) the verify cascade walks the signed subject's constituent digests
#       ONCE, at verify time, and clears only rows that exist at that
#       moment (a missing row is a warn-and-skip, best-effort). A
#       constituent ingested AFTER the subject's verify never receives
#       clearance — there is no parent-lookup self-clear, and the sweep's
#       expiry backstop deliberately skips parent-gated constituents — so
#       it strands Pending+held until a re-sign re-drives the cascade. The
#       constituents must therefore already exist when the sign's verify
#       runs: a direct blob GET performs the SAME synchronous cold-pull
#       ingest as Step 0's index GET regardless of whether the response is
#       200 or a designed hold-503, so by the time this loop returns every
#       constituent row exists for the cascade to find;
#   (b) everything placed between ingest and sign is time this scenario's
#       later window-bound waits have to absorb. There is no protocol
#       DEADLINE on the sign — ADR 0039 D1/D3 holds an unattested artifact
#       indefinitely rather than rejecting it when a window closes, so a
#       late sign delays release instead of forfeiting it. What a late sign
#       costs is budget: Steps 9a and 9b-i are sized against a whole
#       window each (see their definitions at the top of this file), and
#       the policy's 120s is chosen to cover these constituent pulls
#       (~30-60s incl. docker.io) plus the sign while staying short enough
#       that the release sweep completes inside a smoke run.
# Statuses are deliberately NOT asserted beyond "curl completed" — this is a
# forcing step, not an assertion; the 60s polls in Step 6/8 stay as a
# backstop. Every status here is legitimately a hold-503 or a 200 depending
# on where the window and the cascade have got to, which is why asserting
# one of them would be asserting the clock. The SAME request IS asserted
# once the tree has released, in Step 9c — a forcing GET that discards its
# status looks like layer-blob coverage in an inventory and is none.
# ---------------------------------------------------------------------
log ""
log "--- Step 3: force constituent ingest (config blob + every layer blob)"

curl -sS -o /dev/null \
    -H "Authorization: Bearer ${PUSH_SECRET}" \
    "${BASE_URL}/blobs/sha256:${CONFIG_HASH}" 2>/dev/null || true
for h in "${LAYER_HASHES[@]}"; do
    curl -sS -o /dev/null \
        -H "Authorization: Bearer ${PUSH_SECRET}" \
        "${BASE_URL}/blobs/sha256:${h}" 2>/dev/null || true
done
log "  forcing GETs issued for config blob + ${#LAYER_HASHES[@]} layer blob(s)"

# ---------------------------------------------------------------------
# Step 4: SIGN the index (the real subject) — cosign sign --key
# --registry-referrers-mode=oci-1-1 against the SAME repo namespace the
# image was proxy-pulled into (confirmed: cosign-key verification resolves
# referrers repo-scoped-first, landing an upstream-fetched referrer back
# into the same local index — a directly-pushed referrer is found the same
# way). Signing after the constituents are forced in (Step 3) satisfies
# invariant (a) above — the verify cascade needs every constituent row to
# already exist — while still giving the worker's cascade wall-clock ahead
# of this scenario's later assertions.
# ---------------------------------------------------------------------
log ""
log "--- Step 4: cosign sign --key ... --registry-referrers-mode=oci-1-1 ${REPO_KEY}/dockerhub/${IMAGE_PATH}@${INDEX_DIGEST}"
export COSIGN_DOCKER_MEDIA_TYPES=1
export COSIGN_EXPERIMENTAL=1
SIGN_OUT=""
SIGN_RC=0
# `--use-signing-config=false --tlog-upload=false`: this scenario's subject is
# a PROXY-PULLED upstream image, so its index digest is identical on every
# run — signing it against the public sigstore transparency log asks that log
# to accept an equivalent
# entry twice, and the second ask is a `409 createLogEntryConflict` that fails
# the lane. Nothing here needs the log: hort's keyed verifier consults no
# Rekor proof at all (`hort-adapters-provenance-cosign-key`: "no Fulcio chain,
# Rekor proof, SCT, or trust root — strictly more offline"), and what this
# scenario asserts is hort's referrer and quarantine behaviour. Dropping the
# upload also removes a public-network dependency from a compose run that is
# otherwise self-contained. The two flags are a PAIR -- cosign v3 refuses
# `--tlog-upload=false` on its own with "not supported with --signing-config
# or --use-signing-config" -- which is why `.gitlab/ci/cosign-sign.sh:47-50`
# passes both and says so in its own comment.
SIGN_OUT="$(cosign sign --yes \
    --key "$COSIGN_KEY" \
    --use-signing-config=false --tlog-upload=false \
    --registry-referrers-mode=oci-1-1 \
    --registry-username="$PUSH_USER" \
    --registry-password="$PUSH_SECRET" \
    --allow-insecure-registry \
    --allow-http-registry \
    "${REGISTRY_HOST}/${REPO_KEY}/dockerhub/${IMAGE_PATH}@${INDEX_DIGEST}" 2>&1)" || SIGN_RC=$?
if [ "$SIGN_RC" -eq 0 ]; then
    pass "cosign sign (keyed, oci referrers) succeeded against the proxy-pulled subject"
else
    log "[cosign output]"; printf '%s\n' "$SIGN_OUT" | sed 's/^/    /'
    # Bounded: SIGN_OUT is cosign's own progress/status output for a single
    # sign call, a handful of lines.
    if printf '%s' "$SIGN_OUT" | grep -Eqi 'GET .*/manifests/.*503|503 .*manifests'; then
        fail "cosign sign hold-read exemption on a proxy-pulled subject" \
             "cosign got a 503 on a manifest GET during signing -> the write-authorized manifest hold-read exemption (ADR 0039 §10) is not serving the held, proxy-pulled subject to the signer"
    else
        fail "cosign sign (keyed, oci referrers) against a proxy-pulled subject" \
             "cosign exited ${SIGN_RC}; see output above"
    fi
    summary
fi

# ---------------------------------------------------------------------
# Step 5: resolve repository + artifact ids via psql (defence-in-depth poll,
# mirrors proxy-multiarch-zero-window.sh's find_artifact_id).
# ---------------------------------------------------------------------
log ""
log "--- Step 5: resolve repository + artifact ids via psql"

REPO_ID="$(psql_one "SELECT id FROM repositories WHERE key = '${REPO_KEY}';")"
if [ -z "$REPO_ID" ]; then
    fail "resolve repository id for ${REPO_KEY}" \
        "no row in repositories — is deploy/compose/example-config/repositories/oci-provenance-proxy-e2e.yaml mounted and gitops apply succeeding?"
    summary
fi
pass "repository resolved (id=${REPO_ID})"

find_artifact_id() {
    local hash="$1" label="$2" id=""
    bounded_poll "artifact ${label} (sha256:${hash}) ingested" 60 \
        "[ -n \"\$(psql_one \"SELECT id FROM artifacts WHERE repository_id = '${REPO_ID}' AND checksum_sha256 = '${hash}';\")\" ]" \
        2 || true
    id="$(psql_one "SELECT id FROM artifacts WHERE repository_id = '${REPO_ID}' AND checksum_sha256 = '${hash}';")"
    # defense in depth: a captured id must be UUID-shaped or downstream
    # `[ -n ]`/WHERE-clause guards could be satisfied by garbage — never
    # return anything else, even with the poll's own output routed away.
    if [[ ! "$id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
        id=""
    fi
    printf '%s' "$id"
}

INDEX_ID="$(find_artifact_id "$INDEX_HASH" "index")"
CHILD_ID="$(find_artifact_id "$CHILD_HASH" "child manifest")"
CONFIG_ID="$(find_artifact_id "$CONFIG_HASH" "config blob")"
[ -n "$INDEX_ID" ] || { fail "resolve index artifact row" "no artifacts row for checksum_sha256='${INDEX_HASH}'"; summary; }
[ -n "$CHILD_ID" ] || { fail "resolve child artifact row" "no artifacts row for checksum_sha256='${CHILD_HASH}'"; summary; }
[ -n "$CONFIG_ID" ] || { fail "resolve config artifact row" "no artifacts row for checksum_sha256='${CONFIG_HASH}' — neither Step 3's forcing GET nor the eager index-child ingest put this blob in the repository"; summary; }
pass "index artifact id=${INDEX_ID}, child artifact id=${CHILD_ID}, config artifact id=${CONFIG_ID}"

LAYER_IDS=()
for h in "${LAYER_HASHES[@]}"; do
    lid="$(find_artifact_id "$h" "layer blob")"
    [ -n "$lid" ] || { fail "resolve layer artifact row" "no artifacts row for checksum_sha256='${h}' — neither Step 3's forcing GET nor the eager index-child ingest put this blob in the repository"; summary; }
    LAYER_IDS+=("$lid")
done
pass "all ${#LAYER_IDS[@]} layer artifact rows resolved"

# ---------------------------------------------------------------------
# Step 6: content_references edges — the pull-through edge-write half of the
# composition this scenario exercises, and the INPUT to the carve-out's
# condition Step 7 then evaluates (targets specific digests, never a count —
# the eager index-child ingest legitimately adds rows for every other
# platform in the index).
# ---------------------------------------------------------------------
log ""
log "--- Step 6: content_references edges"

assert_edge() {
    local source_id="$1" target_hash="$2" kind="$3" label="$4" row
    bounded_poll "content_references ${label}" 30 \
        "[ \"\$(psql_one \"SELECT count(*) FROM content_references WHERE repository_id = '${REPO_ID}' AND source_artifact_id = '${source_id}' AND target_content_hash = '${target_hash}' AND kind = '${kind}';\")\" = '1' ]" \
        2 || true
    row="$(psql_one "SELECT count(*) FROM content_references WHERE repository_id = '${REPO_ID}' AND source_artifact_id = '${source_id}' AND target_content_hash = '${target_hash}' AND kind = '${kind}';")"
    if [ "$row" = "1" ]; then
        pass "content_references: ${label} (kind=${kind}) edge present"
    else
        fail "content_references ${label} (kind=${kind}) edge" "count=${row:-0}"
    fi
}

assert_edge "$INDEX_ID" "$CHILD_HASH" "oci_index_member" "index -> child"
assert_edge "$CHILD_ID" "$CONFIG_HASH" "oci_config" "child -> config blob"
for i in "${!LAYER_HASHES[@]}"; do
    assert_edge "$CHILD_ID" "${LAYER_HASHES[$i]}" "oci_layer" "child -> layer[$i] blob"
done

# ---------------------------------------------------------------------
# Step 7: sanity — every row in this tree carries a FULL observation window.
# The index because it is nobody's `content_references` target; every
# constituent because it IS one but its referencing parent was still held
# when it was minted, so ADR 0007's carve-out ("the carve-out is conditional
# on inherited trust") has no released parent to inherit from and does not
# apply. There is nothing provenance-related in this step: the
# `NoAttestation x Required` hold stopped consulting the window at ADR 0039
# D1/D3 and holds every shape unconditionally. What this step pins is the
# RELEASE TIMER the later waits are sized against.
# ---------------------------------------------------------------------
log ""
log "--- Step 7: quarantine_window_start — a full window on the index AND on every constituent"

# `== created_at` is the FULL-window expectation only while these bytes are
# COLD to this hort. ADR 0054 anchors a non-descendant on the earliest
# observation of its own content across ALL repositories
# (`first_seen_for_checksum`, a live `MIN(created_at)` over the rows sharing
# the checksum), and `created_at` is that minimum only when no earlier
# observation exists. redis:7-alpine is this suite's only user of this image
# — no other scenario pulls it, and this repository is its own fixture — so
# the precondition holds; it is asserted rather than assumed, because a
# future scenario pulling redis:7-alpine would otherwise turn a correct
# derivation into an unexplained failure of the line below. (The
# cross-repository warm case is covered deliberately, by
# quarantine/proxy-multiarch-zero-window.sh's index, whose bytes proxy/
# oci-mirror.sh pulls earlier in the same run.)
index_is_cold="$(psql_one "SELECT (created_at = (SELECT MIN(created_at) FROM artifacts WHERE checksum_sha256 = '${INDEX_HASH}')) FROM artifacts WHERE id = '${INDEX_ID}';")"
if [ "$index_is_cold" = "t" ]; then
    pass "index bytes are cold: this row IS hort's earliest observation of checksum ${INDEX_HASH} (so a full window anchors at created_at)"
else
    fail "index bytes are cold (this row is the earliest observation of its checksum)" \
        "got '${index_is_cold}' (expected t) — another repository already held ${IMAGE}'s index, so ADR 0054 correctly anchors this row on that earlier observation; this scenario needs cold content, so give it a fixture image no other scenario pulls"
fi

index_full_window="$(psql_one "SELECT (quarantine_window_start = created_at) FROM artifacts WHERE id = '${INDEX_ID}';")"
if [ "$index_full_window" = "t" ]; then
    pass "index: quarantine_window_start == created_at (full window — not a content_references target, and no earlier observation to anchor on)"
else
    fail "index quarantine_window_start == created_at" "got '${index_full_window}' (expected t)"
fi

# Built from QUARANTINE_DURATION_SECS, the single definition of this policy's
# window at the top of this file (which also carries the reason it is a literal
# rather than a `policy_projections` lookup). Shared so these assertions and
# Step 9b-i's release budget cannot disagree about how long the window is.
QUARANTINE_DURATION_SQL="interval '${QUARANTINE_DURATION_SECS} seconds'"

# A constituent's window, in two parts: the PREMISE and then the window.
#
# The premise is that the constituent was minted while its referencing parent
# was still inside the parent's OWN observation window. Nothing in this
# repository can release a row before its window closes — `Artifact::release`
# needs a timer authority as well as its scan and provenance clearance, and no
# curator waive is issued anywhere in this scenario — so a constituent minted
# inside its parent's window was minted against a parent that was NOT
# `Released`, which is exactly the condition ADR 0007's carve-out requires and
# does not get. It is asserted rather than assumed for the same reason the
# index's coldness is asserted above: in a run slow enough for the parent's
# 120s window to close before its constituents are minted, the carve-out WOULD
# legitimately apply and the window assertion below would read as a regression
# it is not.
#
# The window itself is then stated as the invariant, not as `created_at`:
# ADR 0054 anchors on the earliest observation of the row's own content across
# all repositories, and `created_at` is that minimum only while the bytes are
# cold. Covering both cases here needs no second coldness premise, and the
# reduction is logged so a reader of a passing run can see which it was.
assert_full_window_constituent() {
    local id="$1" hash="$2" parent_id="$3" label="$4" parent_label="$5"
    local minted_inside_parent_window anchored_on_evidence first_seen own_created waived

    minted_inside_parent_window="$(psql_one "SELECT (c.created_at < p.quarantine_window_start + ${QUARANTINE_DURATION_SQL}) \
        FROM artifacts c, artifacts p WHERE c.id = '${id}' AND p.id = '${parent_id}';")"
    if [ "$minted_inside_parent_window" = "t" ]; then
        pass "${label}: minted inside its ${parent_label}'s own observation window, so that parent was not Released at the time (the carve-out's inherited-trust condition is unmet)"
    else
        fail "${label} minted inside its ${parent_label}'s own observation window" \
            "got '${minted_inside_parent_window:-<null>}' (expected t) — this run took longer than the ${QUARANTINE_DURATION_SECS}s window to get from the parent's mint to this constituent's, so the parent may legitimately have been Released first and this constituent may legitimately have inherited the carve-out. That is a slow-run fixture condition, not a defect; the window assertion below is only meaningful under this premise"
    fi

    first_seen="$(psql_one "SELECT replace(MIN(created_at)::text, ' ', 'T') FROM artifacts WHERE checksum_sha256 = '${hash}';")"
    own_created="$(psql_one "SELECT replace(created_at::text, ' ', 'T') FROM artifacts WHERE id = '${id}';")"
    anchored_on_evidence="$(psql_one "SELECT (quarantine_window_start = \
        (SELECT MIN(created_at) FROM artifacts WHERE checksum_sha256 = '${hash}')) \
        FROM artifacts WHERE id = '${id}';")"
    if [ "$anchored_on_evidence" = "t" ]; then
        if [ "$first_seen" = "$own_created" ]; then
            pass "${label}: quarantine_window_start == created_at — no earlier observation of these bytes exists, so a full window anchors at its own mint"
        else
            pass "${label}: quarantine_window_start == the earliest observation of its own bytes (${first_seen}), made before this row — a full window on ADR 0054 age evidence"
        fi
    else
        waived="$(psql_one "SELECT (quarantine_window_start = created_at - ${QUARANTINE_DURATION_SQL}) FROM artifacts WHERE id = '${id}';")"
        if [ "$waived" = "t" ]; then
            fail "${label} quarantine_window_start == MIN(created_at) over artifacts sharing checksum ${hash}" \
                "this row is anchored at created_at - duration: it WAIVED its observation window while its ${parent_label} was still held. That is the unconditional referenced-tree-descendant carve-out ADR 0007's inherited-trust amendment retired (own created_at=${own_created})"
        else
            fail "${label} quarantine_window_start == MIN(created_at) over artifacts sharing checksum ${hash}" \
                "got '${anchored_on_evidence:-<null>}' (expected t), and it is not the retired waiver's value either: first_seen=${first_seen} own created_at=${own_created}"
        fi
    fi
}
assert_full_window_constituent "$CHILD_ID" "$CHILD_HASH" "$INDEX_ID" "child manifest" "parent index"
assert_full_window_constituent "$CONFIG_ID" "$CONFIG_HASH" "$CHILD_ID" "config blob" "parent child manifest"
for i in "${!LAYER_IDS[@]}"; do
    assert_full_window_constituent "${LAYER_IDS[$i]}" "${LAYER_HASHES[$i]}" "$CHILD_ID" "layer[$i] blob" "parent child manifest"
done

# ---------------------------------------------------------------------
# Step 8: await ProvenanceVerified on the SIGNED SUBJECT (the index) — the
# real-verifier clearance the whole chain hangs off.
# ---------------------------------------------------------------------
log ""
log "--- Step 8: await ProvenanceVerified on the signed index"
if bounded_poll \
        "ProvenanceVerified for index sha256:${INDEX_HASH}" \
        "$WINDOW_WAIT_SECS" \
        "[ -n \"\$(psql_one \"SELECT 1 FROM events WHERE stream_id = 'artifact-${INDEX_ID}' AND event_type = 'ProvenanceVerified' LIMIT 1;\")\" ]" \
        5; then
    pass "ProvenanceVerified emitted for the signed index subject"
else
    fail "ProvenanceVerified for the signed index" \
         "no ProvenanceVerified event for checksum ${INDEX_HASH} within ${WINDOW_WAIT_SECS}s (signature not linked — referrers mode? public key mismatch?)"
fi

# ---------------------------------------------------------------------
# Step 9 — three-phase contract: 9a ingests, 9b-i waits out the window,
# 9b-ii pulls.
#
# `--all` forces every platform child of the index through pull-through.
# Steps 0-3 only drive ONE platform subtree by hand, but they are not the
# only thing that ingests: the index's own pull enqueues an
# `oci-index-child-ingest` row per declared child, and this scenario
# `requires: worker`, so in the normal case a worker has already ingested
# every other platform child and warmed its blobs by the time the sign
# runs. Whatever that path did not complete (a jobs-table failure, an
# upstream 404 on a layer, the nested-index depth cap) arrives here
# instead, as a LATE JOINER — after the subject was already verified, so
# it gets no cascade and self-clears at its own quarantine commit against
# the signed index's bytes (child manifests directly; their config/layer
# blobs via the root behind their cascade-cleared parent). This step is
# correct either way, which is why it does not assert which of the two
# happened.
#
# 9a is the ingest vehicle: an AUTHENTICATED `--all` warm pass. Write
# authorization carries the ADR 0039 §10 hold-read exemption for every
# MANIFEST in the tree, so the walk is never blocked on resolving one;
# each blob it then requests is pulled through and ingested even when
# the response to that request is the 503 of a fresh hold. That is what
# makes this the ingest vehicle, and it is all this step relies on.
#
# It is NOT exempt from the holds themselves. Blob CONTENT stays held
# from every caller, write-granted included, so the copy only COMPLETES
# once each constituent has released on its own clearance plus a sweep
# tick. The budget is sized for that tail (WARM_PASS_WAIT_SECS); do not
# re-describe this step as reading held constituents.
#
# 9b proves the actual acceptance criterion: an ANONYMOUS `--all` pull
# succeeds end-to-end once every constituent has cleared and released.
# The anonymous poll cannot be the thing that DRIVES those cold pulls:
# skopeo aborts the whole copy at the FIRST held (503) artifact, so an
# anonymous-only poll advances the ingest frontier by ~one artifact per
# retry — a serial crawl that is unbounded against any fixed budget, not
# a slow-but-finite wait. 9a removes that dependency.
#
# What is left after 9a is TWO different waits, which is why 9b is itself
# two steps. Every row in this tree carries a full observation window —
# the index because it is nobody's target, each constituent because its
# referencing parent was still held when it was minted and so there was
# no inherited trust to waive it (Step 7). What differs is WHEN each
# window started: the index's at Step 0, each constituent's at its own
# mint shortly after, so the index's is the first to close and every
# constituent's closes later. 9a is therefore where the window time is
# actually spent — a blob does not serve until it releases, so 9a cannot
# finish until every constituent window has closed, which is already past
# the index's. 9b-i then confirms the index ROW released, against the
# database rather than the registry; 9b-ii pulls. Folding them back
# together would reinstate a single budget that has to cover a 120s
# window while its wording blames clearance — which is what it did, and
# the diagnosis it produced was of a cascade defect that was not there.
# ---------------------------------------------------------------------
log ""
log "--- Step 9a: authenticated warm pass (late-joiner ingest vehicle)"
rm -f "$WARM_ARCHIVE"
if bounded_poll \
        "signed image pullable (authenticated warm pass)" \
        "$WARM_PASS_WAIT_SECS" \
        "skopeo copy --all --insecure-policy --src-tls-verify=false --src-creds '${PUSH_USER}:${PUSH_SECRET}' 'docker://${REGISTRY_HOST}/${REPO_KEY}/dockerhub/${IMAGE_PATH}@${INDEX_DIGEST}' 'oci-archive:${WARM_ARCHIVE}'" \
        5; then
    pass "authenticated --all warm pass ingested every foreign platform (hold-read exemption honored; each late joiner self-cleared at its own quarantine commit)"
else
    fail "authenticated warm pass ingests every foreign platform" \
         "the signed index never became fully (--all) authenticated-pullable within ${WARM_PASS_WAIT_SECS}s, a budget that covers the later of a constituent's whole ${QUARANTINE_DURATION_SECS}s observation window and its whole clearance tail, measured from this step's own start — so neither the elapsed time before this step, nor the index's own window, nor a constituent's window is an available explanation. Write authority exempts the MANIFEST reads only; what this pass waits on is every constituent BLOB releasing. Look at the scan path: a constituent whose scan never completed, or a foreign platform that never ingested at all (compare count(*) on artifacts in this repository against the index's .manifests[] children)."
fi
rm -f "$WARM_ARCHIVE"

# ---------------------------------------------------------------------
# Step 9b-i: await the INDEX row's release — the window leg.
#
# Split out of the pull below because the two legs wait on different
# things, and a reader of a failing run has to be able to tell which one
# gave out. Step 7 asserted the index carries a FULL window, started at
# the Step 0 ingest, and until it elapses NOTHING anonymous can be served,
# which is hort behaving correctly (ADR 0007), not a defect. Every
# constituent carries a full window too; the index's is simply the one
# that STARTED first, so it is the first to close and 9a (which cannot
# finish until every constituent blob has released, i.e. until every
# later-starting window has also closed) has in practice already outlasted
# it. What is normally left here is the release SWEEP acting on the index
# row, not the clock — the budget still counts a whole window, because a
# budget that leaned on 9a running first would silently become wrong the
# moment these steps were reordered.
#
# The database is what is polled, not the registry, because a 503 from an
# anonymous pull cannot distinguish "the window has not closed" from
# "clearance never came" — and reading the first as the second is how a
# timeout here gets diagnosed as a cascade defect that is not present.
# See INDEX_RELEASE_WAIT_SECS at the top of this file for why its budget
# is big enough no matter how fast Steps 0-9a ran.
# ---------------------------------------------------------------------
log ""
log "--- Step 9b-i: await the index row's release (full ${QUARANTINE_DURATION_SECS}s window + release sweep, budget ${INDEX_RELEASE_WAIT_SECS}s)"
INDEX_RELEASED=0
if bounded_poll \
        "index artifact ${INDEX_ID} released" \
        "$INDEX_RELEASE_WAIT_SECS" \
        "[ \"\$(psql_one \"SELECT quarantine_status FROM artifacts WHERE id = '${INDEX_ID}';\")\" = 'released' ]" \
        5; then
    INDEX_RELEASED=1
    pass "index released: its full quarantine window elapsed and the release sweep acted on it"
else
    INDEX_STATE="$(psql_one "SELECT COALESCE(quarantine_status::text,'null') FROM artifacts WHERE id = '${INDEX_ID}';" || true)"
    fail "index releases once its full quarantine window elapses" \
         "THE WINDOW LEG, not the clearance leg: quarantine_status='${INDEX_STATE:-<row gone>}' for the index after ${INDEX_RELEASE_WAIT_SECS}s, a budget that covers the full ${QUARANTINE_DURATION_SECS}s window from this artifact's own ingest plus the release sweep behind it — so the window running late is not an available explanation. If Step 8 passed, the signature verified and this is the release SWEEP not acting: look at the sweep ticker and the jobs table, not at the cascade or at late joiners."
fi

# ---------------------------------------------------------------------
# Step 9b-ii: the ANONYMOUS `--all` pull — the acceptance criterion
# itself. Runs only once 9b-i has proved the window closed, which is what
# makes the failure wording below TRUE rather than merely plausible: with
# the index released, a timeout here really is clearance, cascade or a
# late joiner, and cannot be the window.
# ---------------------------------------------------------------------
log ""
log "--- Step 9b-ii: anonymous FULL-index pull (release acceptance after warm pass)"
rm -f "$PULLED_ARCHIVE"
if [ "$INDEX_RELEASED" = "1" ]; then
    if bounded_poll \
            "signed image pullable (anonymous)" \
            "$ANON_PULL_WAIT_SECS" \
            "skopeo copy --all --insecure-policy --src-tls-verify=false 'docker://${REGISTRY_HOST}/${REPO_KEY}/dockerhub/${IMAGE_PATH}@${INDEX_DIGEST}' 'oci-archive:${PULLED_ARCHIVE}'" \
            5; then
        pass "release acceptance after warm pass: the signed+cleared multi-arch index pulled anonymously in full (Cleared + timer gate satisfied for every platform, late joiners included)"
    else
        fail "release acceptance after warm pass: signed index pulls anonymously with --all" \
             "the signed index did not become fully (--all) anonymously pullable within ${ANON_PULL_WAIT_SECS}s of its OWN release. The window is not the explanation — 9b-i proved it closed — so this is cascade, LATE-JOINER clearance, or the release sweep still owing a constituent whose own window has already closed."
    fi
else
    log "  NOTE: Step 9b-ii not attempted — the index row never released, so an anonymous --all pull cannot succeed, and running it would report a clearance failure for a window that never closed (see Step 9b-i)."
fi

# ---------------------------------------------------------------------
# Step 9c: a LAYER BLOB, fetched by digest, answers 200.
#
# Step 3 issues exactly this request as a forcing GET and throws the status
# away, on purpose — at that point in the lifecycle a hold-503 is the
# designed answer. Here the tree has released (9b-ii pulled it anonymously in
# full), so the status is no longer about the clock and the request is the
# one a client actually makes: resolve a manifest, then fetch the layers it
# names. A released image whose layer blob answers 503 is an image hort
# reports as deliverable and does not deliver, and the only thing that
# notices is the client. Asserted ANONYMOUSLY, so a write-authorized
# hold-read exemption cannot stand in for a release.
#
# One blob, not the whole set: 9b-ii already pulled every constituent of every
# platform: this assertion exists to put a status code on the layer-blob
# route rather than to re-walk the tree.
# ---------------------------------------------------------------------
log ""
log "--- Step 9c: ANONYMOUS GET a released layer blob by digest (must serve)"

LAYER_BLOB_CODE="$(curl -sS -o /dev/null -w '%{http_code}' \
    "${BASE_URL}/blobs/sha256:${LAYER_HASHES[0]}" 2>/dev/null || echo 000)"
if [ "$LAYER_BLOB_CODE" = "200" ]; then
    pass "ANONYMOUS GET layer blob sha256:${LAYER_HASHES[0]} -> 200 (a released image's layers are deliverable)"
else
    fail "ANONYMOUS GET a released layer blob -> 200" \
         "got HTTP ${LAYER_BLOB_CODE} for ${BASE_URL}/blobs/sha256:${LAYER_HASHES[0]}. 503 means the layer row is still held while the manifest that names it serves — check artifacts.quarantine_status and last_scan_at for that blob: 'scan_indeterminate' with a NULL last_scan_at is a scan that abstained and fell to the fail-closed hold."
fi

# ---------------------------------------------------------------------
# Step 10 [Acceptance (b), THE regression pin]: no constituent — child
# manifest, config blob, any layer blob — EVER emitted ProvenanceRejected.
# By this point the full lifecycle (sign -> verify -> cascade -> release ->
# pull) has completed or timed out, so if the pre-Item-3 defect were present
# the terminal Rejected{Unsigned} decision would already have landed (it
# fired within moments of ingest, well before this poll).
# ---------------------------------------------------------------------
log ""
log "--- Step 10: THE regression pin — no constituent ever rejected"

# Queried by artifact id (stream_id = 'artifact-<id>'), not checksum —
# checksum alone is not repository-scoped, and an unrelated fixture
# elsewhere could in principle share a content-addressed digest.
assert_never_rejected() {
    local id="$1" label="$2" row
    row="$(psql_one "SELECT 1 FROM events WHERE stream_id = 'artifact-${id}' AND event_type = 'ProvenanceRejected' LIMIT 1;")"
    if [ -z "$row" ]; then
        pass "${label}: no ProvenanceRejected ever emitted (the unconditional hold-not-reject held)"
    else
        fail "${label}: no ProvenanceRejected ever emitted" \
             "found a ProvenanceRejected event for artifact ${id} — the NoAttestation x Required hold (ADR 0039 D1/D3: an absent attestation holds every shape) did not fire; this constituent terminally rejected instead of holding for cascade clearance"
    fi
}
assert_never_rejected "$INDEX_ID" "index (control — the signed subject itself must not reject)"
assert_never_rejected "$CHILD_ID" "child manifest"
assert_never_rejected "$CONFIG_ID" "config blob"
for i in "${!LAYER_IDS[@]}"; do
    assert_never_rejected "${LAYER_IDS[$i]}" "layer[$i] blob"
done

summary
