#!/usr/bin/env bash
# Claim-based-RBAC event-delivery regression smoke.
#
# Regression test for group-derived roles flowing to the dispatcher AND
# the pin for the invariant that long-lived static tokens carry no
# non-admin claims. Two scenarios, one stack:
#
#   POSITIVE: a NON-admin OIDC user whose IdP groups
#     map (via claim_mappings) to claims [developer, team-alpha], holding
#     a Claims-subject PermissionGrant of Read on pypi-alpha, creates an
#     OwnedByActor subscription. Its persisted snapshot_claims MUST be
#     exactly [developer, team-alpha]; a matching artifact event MUST be
#     delivered to the webhook receiver within 5s.
#   NEGATIVE (pins §6 invariant 1): the SAME user creates a subscription
#     via a PAT (not OIDC). snapshot_claims MUST be []; a matching event
#     MUST NOT be delivered within 5s — the PAT path never consults
#     claim_mappings, so the OwnedByActor scope resolves to nothing.
#
# Opt-in: gated behind HORT_E2E_NOTIFICATIONS=1 (mirrors the template's
# opt-in posture). Default e2e profile does NOT run this smoke.
#
# Exit codes:
#   0 — every assertion passed (or opt-in env var not set)
#   1 — at least one assertion failed
#   2 — environment unmet (docker/deps unavailable, stack unreachable)
#
# Debug: HORT_TEST_DEBUG=1 toggles `set -x`. --keep leaves the stack up;
# --clean tears the stack down and exits.

set -euo pipefail

if [ "${HORT_E2E_NOTIFICATIONS:-0}" != "1" ]; then
    echo "SKIP: claim-based-RBAC notifications smoke is opt-in"
    echo "      set HORT_E2E_NOTIFICATIONS=1 to enable"
    exit 0
fi

if [ "${HORT_TEST_DEBUG:-0}" = "1" ]; then
    set -x
fi

# -----------------------------------------------------------------------------
# Paths + constants
# -----------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

BASE_COMPOSE="$REPO_ROOT/deploy/compose/docker-compose.yml"
EXAMPLE_CONFIG="$REPO_ROOT/deploy/compose/example-config"

# Inherited from the base compose port mapping (25xxx range per the
# developer-machine memory rule).
API_URL="${API_URL:-http://localhost:25080}"
METRICS_URL="${METRICS_URL:-http://localhost:25090/metrics}"

# Keycloak: shipped by the base compose (realm hort). ROPC
# direct-grant is enabled on the confidential `hort-server` client, same
# idiom test-pypi.sh uses. Host port 25082; in-network http://keycloak:8080.
KEYCLOAK_HOST_URL="${KEYCLOAK_HOST_URL:-http://localhost:25082}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-hort}"
KEYCLOAK_TOKEN_URL="${KEYCLOAK_HOST_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token"
KEYCLOAK_ADMIN_URL="${KEYCLOAK_HOST_URL}/admin/realms/${KEYCLOAK_REALM}"
KC_CLIENT_ID="${KC_CLIENT_ID:-hort-server}"
KC_CLIENT_SECRET="${KC_CLIENT_SECRET:-hort-server-secret-dev-only}"
KC_BOOTSTRAP_ADMIN="${KC_BOOTSTRAP_ADMIN:-admin}"
KC_BOOTSTRAP_PASSWORD="${KC_BOOTSTRAP_PASSWORD:-admin}"

# The compose docker network the webhook receiver attaches to so
# hort-server can reach it by container name (no SSRF carve-out needed —
# a same-network container DNS name is routable, unlike 127.0.0.1).
COMPOSE_NETWORK="${COMPOSE_NETWORK:-hort_default}"

# Test fixture identities (seeded by this script — they are NOT
# in the shipped realm.json / example-config; the script owns them).
RBAC_USER="${RBAC_USER:-rbac-dev-user}"
RBAC_PASSWORD="${RBAC_PASSWORD:-rbac-dev-pass}"
IDP_GROUP_A="developers-team"
IDP_GROUP_B="team-alpha"
CLAIM_DEV="developer"
CLAIM_TEAM="team-alpha"
RBAC_REPO="${RBAC_REPO:-pypi-alpha}"

READY_TIMEOUT_SECS="${READY_TIMEOUT_SECS:-240}"
DELIVERY_WAIT_SECS="${DELIVERY_WAIT_SECS:-5}"

RECEIVER_NAME="hort-init40-webhook-receiver"
RECEIVER_PORT="8099"
WEBHOOK_SECRET="init40-rbac-smoke-secret-not-real"

WORK_DIR=""
TOKEN_FILE=""
KEEP_STACK=""
CLEAN_ONLY=""

COMPOSE_OVERRIDE=""
COMPOSE=(docker compose -f "$BASE_COMPOSE")

PASSED=0
FAIL=0
declare -a FAILURES=()

# -----------------------------------------------------------------------------
# Logging + assertion helpers (mirrors test-notifications.sh)
# -----------------------------------------------------------------------------

log() { printf '%s\n' "$*"; }

assert_pass() {
    PASSED=$((PASSED + 1))
    log "  PASS: $1"
}
assert_fail() {
    FAIL=$((FAIL + 1))
    FAILURES+=("$1 :: $2")
    printf '  FAIL: %s :: %s\n' "$1" "$2" >&2
}

dump_stack_diagnostics() {
    log ""
    log "==> Stack diagnostics"
    "${COMPOSE[@]}" ps 2>/dev/null || true
    log "--- hort-server (last 120) ---"
    "${COMPOSE[@]}" logs --tail=120 hort-server 2>/dev/null || true
}

cleanup() {
    local ec=$?
    log ""
    log "==> cleanup"
    docker rm -f "$RECEIVER_NAME" >/dev/null 2>&1 || true
    if [ -n "$KEEP_STACK" ] && [ -z "$CLEAN_ONLY" ]; then
        log "--keep set: leaving the hort stack up."
        log "  Tear down with: ${COMPOSE[*]} down -v"
    else
        log "==> Tearing down the hort stack (compose down -v)..."
        "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
    fi
    if [ -n "$TOKEN_FILE" ]; then
        rm -f "$TOKEN_FILE" 2>/dev/null || true
    fi
    if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
        rm -rf "$WORK_DIR"
    fi
    return "$ec"
}
trap cleanup EXIT INT TERM

while [ "$#" -gt 0 ]; do
    case "$1" in
        --clean) CLEAN_ONLY="1"; shift ;;
        --keep)  KEEP_STACK="1"; shift ;;
        *)       echo "Unknown arg: $1" >&2; exit 64 ;;
    esac
done

# -----------------------------------------------------------------------------
# Preflight
# -----------------------------------------------------------------------------

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    echo "SKIP: docker not available — claim-based-RBAC smoke requires a docker daemon."
    exit 2
fi

if [ -n "$CLEAN_ONLY" ]; then
    echo "Cleanup-only mode."
    "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
    docker rm -f "$RECEIVER_NAME" >/dev/null 2>&1 || true
    trap - EXIT INT TERM
    echo "Done."
    exit 0
fi

for bin in curl jq python3; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        echo "FATAL: required binary '$bin' not found" >&2
        exit 2
    fi
done

if [ ! -d "$EXAMPLE_CONFIG" ]; then
    echo "FATAL: $EXAMPLE_CONFIG not found — cannot seed gitops config" >&2
    exit 2
fi

WORK_DIR="$(mktemp -d -t hort-init40-rbac-XXXX)"
TOKEN_FILE="$WORK_DIR/admin-token.txt"
CONFIG_DIR="$WORK_DIR/config"
mkdir -p "$CONFIG_DIR"

log "==> claim-based-RBAC event-delivery smoke"
log "api      : $API_URL"
log "keycloak : $KEYCLOAK_HOST_URL (realm $KEYCLOAK_REALM)"
log "repo     : $RBAC_REPO"
log "workdir  : $WORK_DIR"
log ""

# -----------------------------------------------------------------------------
# Phase 1 — seed the gitops config tree (ClaimMapping + PermissionGrant)
# -----------------------------------------------------------------------------
#
# Mirrors the test-gitops-machine-identity.sh pattern: copy the shipped
# example-config tree into a per-run scratch dir, add the RBAC
# fixtures, and remount via a generated compose override so the tracked
# deploy/compose/example-config/ tree is never modified. gitops apply is
# boot-time only ("restart-to-apply"), so these must be in place BEFORE
# the stack comes up.

log "--> [1/9] seed gitops config (example-config + ClaimMapping + PermissionGrant + repo)"

cp -r "$EXAMPLE_CONFIG/." "$CONFIG_DIR/"
mkdir -p "$CONFIG_DIR/auth" "$CONFIG_DIR/repositories"

# A hosted repo for the Claims-subject grant to target. Mirrors the
# shipped pypi-e2e.yaml shape exactly.
cat > "$CONFIG_DIR/repositories/${RBAC_REPO}.yaml" <<EOF
apiVersion: project-hort.de/v1beta1
kind: ArtifactRepository
metadata:
  name: ${RBAC_REPO}
spec:
  name: "PyPI Alpha (RBAC smoke)"
  description: "Hosted PyPI repo used by scripts/host-tests/test-notifications-rbac.sh"
  format: pypi
  type: hosted
  storage:
    backend: filesystem
    path: /var/lib/hort-server/cas/${RBAC_REPO}
  isPublic: false
  replicationPriority: local_only
EOF

# ClaimMapping: both IdP groups resolve to BOTH claims (the
# [developer, team-alpha] additive-claims set the grant requires). One
# CRD per (idp_group, claim) tuple — flat additive model.
cat > "$CONFIG_DIR/auth/init40-claim-mappings.yaml" <<EOF
apiVersion: project-hort.de/v1beta1
kind: ClaimMapping
metadata:
  name: developers-team-to-developer
spec:
  idpGroup: ${IDP_GROUP_A}
  claim: ${CLAIM_DEV}
---
apiVersion: project-hort.de/v1beta1
kind: ClaimMapping
metadata:
  name: developers-team-to-team-alpha
spec:
  idpGroup: ${IDP_GROUP_A}
  claim: ${CLAIM_TEAM}
---
apiVersion: project-hort.de/v1beta1
kind: ClaimMapping
metadata:
  name: team-alpha-to-developer
spec:
  idpGroup: ${IDP_GROUP_B}
  claim: ${CLAIM_DEV}
---
apiVersion: project-hort.de/v1beta1
kind: ClaimMapping
metadata:
  name: team-alpha-to-team-alpha
spec:
  idpGroup: ${IDP_GROUP_B}
  claim: ${CLAIM_TEAM}
EOF

# Claims-subject PermissionGrant: requires the additive set
# [developer, team-alpha]; grants Read on the seeded repo.
cat > "$CONFIG_DIR/auth/init40-claims-grant.yaml" <<EOF
apiVersion: project-hort.de/v1beta1
kind: PermissionGrant
metadata:
  name: init40-claims-read-${RBAC_REPO}
spec:
  requiredClaims: [${CLAIM_DEV}, ${CLAIM_TEAM}]
  permissions: [read]
  repositories: [${RBAC_REPO}]
EOF

# Generated compose override: remount the scratch config tree at
# /etc/hort/config (last-file-wins on that mount target; cas volume +
# everything else inherited from the base file).
COMPOSE_OVERRIDE="$WORK_DIR/docker-compose.rbac-override.yml"
cat > "$COMPOSE_OVERRIDE" <<EOF
services:
  hort-server:
    volumes:
      - cas:/var/lib/hort-server/cas
      - ${CONFIG_DIR}:/etc/hort/config:ro
EOF
COMPOSE=(docker compose -f "$BASE_COMPOSE" -f "$COMPOSE_OVERRIDE")

# hort-server (uid 65532, distroless) reads the bind mount — make it
# traversable+readable regardless of the invoking shell's umask.
chmod -R a+rX "$CONFIG_DIR"

assert_pass "gitops config tree seeded (claim_mappings + claims-grant + ${RBAC_REPO})"

# -----------------------------------------------------------------------------
# Phase 2 — bring up the stack
# -----------------------------------------------------------------------------

log ""
log "--> [2/9] bringing up the hort stack (claim-based RBAC config applied at boot)"

"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
if ! "${COMPOSE[@]}" up -d; then
    dump_stack_diagnostics
    assert_fail "stack-up" "compose up failed"
    log ""
    log "==> Summary: $PASSED passed, $((FAIL + 1)) failed"
    exit 1
fi

HEALTHY=""
for _ in $(seq 1 "$READY_TIMEOUT_SECS"); do
    if curl -fsS -m 3 "$API_URL/healthz" >/dev/null 2>&1; then
        HEALTHY="1"; break
    fi
    sleep 1
done
if [ -z "$HEALTHY" ]; then
    dump_stack_diagnostics
    assert_fail "hort-server-healthy" "no 200 from $API_URL/healthz within ${READY_TIMEOUT_SECS}s"
    log ""
    log "==> Summary: $PASSED passed, $((FAIL + 1)) failed"
    exit 1
fi
assert_pass "hort-server healthy ($API_URL/healthz)"

# -----------------------------------------------------------------------------
# Phase 3 — seed the non-admin OIDC user + IdP groups in Keycloak
# -----------------------------------------------------------------------------
#
# Idiom from scripts/sso-e2e/setup-keycloak.sh: a master-realm admin
# token drives the Keycloak admin API. We create the two IdP groups,
# the non-admin user, set its password, and join it to both groups so
# the `groups` claim in its access token is [developers-team, team-alpha].

log ""
log "--> [3/9] seed Keycloak: non-admin user '$RBAC_USER' in groups [$IDP_GROUP_A, $IDP_GROUP_B]"

KC_ADMIN_TOKEN="$(curl -sS -m 10 \
    "$KEYCLOAK_HOST_URL/realms/master/protocol/openid-connect/token" \
    -d "grant_type=password" \
    -d "client_id=admin-cli" \
    -d "username=$KC_BOOTSTRAP_ADMIN" \
    --data-urlencode "password=$KC_BOOTSTRAP_PASSWORD" \
    2>/dev/null | jq -r '.access_token // empty')"

if [ -z "$KC_ADMIN_TOKEN" ]; then
    assert_fail "keycloak-admin-token" "could not obtain Keycloak master admin token"
    log ""
    log "==> Summary: $PASSED passed, $((FAIL + 1)) failed"
    exit 1
fi
assert_pass "obtained Keycloak master admin token"

kc_admin() {
    # $1 method  $2 path  [$3 json-body]
    local method="$1" path="$2" body="${3:-}"
    if [ -n "$body" ]; then
        curl -sS -m 10 -o /dev/null -w '%{http_code}' \
            -X "$method" "$KEYCLOAK_ADMIN_URL$path" \
            -H "Authorization: Bearer $KC_ADMIN_TOKEN" \
            -H "Content-Type: application/json" \
            -d "$body" 2>/dev/null || echo "000"
    else
        curl -sS -m 10 \
            -X "$method" "$KEYCLOAK_ADMIN_URL$path" \
            -H "Authorization: Bearer $KC_ADMIN_TOKEN" \
            2>/dev/null || echo ""
    fi
}

# Groups (idempotent — 201 created or 409 already-exists are both fine).
for grp in "$IDP_GROUP_A" "$IDP_GROUP_B"; do
    code="$(kc_admin POST "/groups" "{\"name\":\"$grp\"}")"
    case "$code" in
        201|409) ;;
        *) assert_fail "keycloak-group-$grp" "create group returned $code" ;;
    esac
done

# User (idempotent on 409). credentials inline so no separate reset call.
USER_BODY="$(jq -nc \
    --arg u "$RBAC_USER" --arg p "$RBAC_PASSWORD" \
    '{username:$u, enabled:true, email:($u+"@example.test"),
      emailVerified:true, firstName:"RBAC", lastName:"Dev",
      credentials:[{type:"password", value:$p, temporary:false}]}')"
code="$(kc_admin POST "/users" "$USER_BODY")"
case "$code" in
    201|409) assert_pass "keycloak user '$RBAC_USER' present (HTTP $code)" ;;
    *) assert_fail "keycloak-user" "create user returned $code" ;;
esac

USER_JSON="$(kc_admin GET "/users?username=$RBAC_USER&exact=true")"
KC_USER_ID="$(printf '%s' "$USER_JSON" | jq -r '.[0].id // empty')"
if [ -z "$KC_USER_ID" ]; then
    assert_fail "keycloak-user-id" "could not resolve user id for $RBAC_USER"
    log ""
    log "==> Summary: $PASSED passed, $((FAIL + 1)) failed"
    exit 1
fi

GROUPS_JSON="$(kc_admin GET "/groups")"
for grp in "$IDP_GROUP_A" "$IDP_GROUP_B"; do
    gid="$(printf '%s' "$GROUPS_JSON" | jq -r --arg n "$grp" '.[] | select(.name==$n) | .id' | head -1)"
    if [ -z "$gid" ]; then
        assert_fail "keycloak-group-id-$grp" "could not resolve group id"
        continue
    fi
    code="$(kc_admin PUT "/users/$KC_USER_ID/groups/$gid" '{}')"
    case "$code" in
        204|201|409) ;;
        *) assert_fail "keycloak-join-$grp" "join group returned $code" ;;
    esac
done
assert_pass "user joined to [$IDP_GROUP_A, $IDP_GROUP_B] (groups claim populated)"

# -----------------------------------------------------------------------------
# Phase 4 — start the in-network webhook receiver
# -----------------------------------------------------------------------------
#
# A tiny stdlib http.server in a python container on the compose network.
# hort-server reaches it by container name (RECEIVER_NAME) — a routable
# DNS name, so the SSRF guard does not block it (unlike a loopback /
# RFC-1918 literal). Every received POST is appended to a log file we
# tail to count deliveries.

log ""
log "--> [4/9] start in-network webhook receiver ($RECEIVER_NAME:$RECEIVER_PORT)"

RECEIVER_SCRIPT="$WORK_DIR/receiver.py"
cat > "$RECEIVER_SCRIPT" <<'PYEOF'
import http.server
import sys

HITS = "/tmp/hits.log"


class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else b""
        with open(HITS, "ab") as f:
            f.write(b"HIT " + self.path.encode() + b" " + str(length).encode() + b"\n")
            f.write(body + b"\n")
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_args):
        pass


open(HITS, "wb").close()
port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
http.server.HTTPServer(("0.0.0.0", port), H).serve_forever()
PYEOF

docker rm -f "$RECEIVER_NAME" >/dev/null 2>&1 || true
docker run -d --rm \
    --name "$RECEIVER_NAME" \
    --network "$COMPOSE_NETWORK" \
    -v "$RECEIVER_SCRIPT:/receiver.py:ro" \
    python:3.12-alpine \
    python3 /receiver.py "$RECEIVER_PORT" >/dev/null 2>&1 || true

RECEIVER_OK=""
for _ in $(seq 1 30); do
    if docker run --rm --network "$COMPOSE_NETWORK" curlimages/curl:8.10.1 \
        curl -fsS -m 3 "http://$RECEIVER_NAME:$RECEIVER_PORT/" >/dev/null 2>&1; then
        RECEIVER_OK="1"; break
    fi
    sleep 1
done
if [ -z "$RECEIVER_OK" ]; then
    assert_fail "webhook-receiver-up" "receiver not reachable in-network within 30s"
    log ""
    log "==> Summary: $PASSED passed, $((FAIL + 1)) failed"
    exit 1
fi
WEBHOOK_URL="http://$RECEIVER_NAME:$RECEIVER_PORT/hook"
assert_pass "webhook receiver reachable at $WEBHOOK_URL (routable name; SSRF guard not tripped)"

receiver_hits() {
    docker exec "$RECEIVER_NAME" sh -c 'grep -c "^HIT " /tmp/hits.log 2>/dev/null || echo 0' \
        2>/dev/null | tr -d '[:space:]'
}
receiver_reset() {
    docker exec "$RECEIVER_NAME" sh -c ': > /tmp/hits.log' >/dev/null 2>&1 || true
}

# -----------------------------------------------------------------------------
# Helpers: OIDC ROPC login, PAT mint, subscription create, snapshot read,
#          event trigger
# -----------------------------------------------------------------------------

# Non-interactive OIDC login (RFC 6749 §4.3 resource-owner password
# grant) against the confidential hort-server client — same idiom as
# test-pypi.sh's fetch_token. Returns the access_token.
oidc_login() {
    curl -sS -m 15 -X POST "$KEYCLOAK_TOKEN_URL" \
        -d "grant_type=password" \
        -d "client_id=$KC_CLIENT_ID" \
        -d "client_secret=$KC_CLIENT_SECRET" \
        -d "username=$RBAC_USER" \
        --data-urlencode "password=$RBAC_PASSWORD" \
        -d "scope=openid" \
        2>/dev/null | jq -r '.access_token // empty'
}

# Admin service-account token (same idiom as test-notifications.sh
# phase 1) — used to mint the user's PAT and to publish the matching
# artifact event into the (non-public) repo.
mint_admin_token() {
    "${COMPOSE[@]}" exec -T hort-server \
        /usr/local/bin/hort-server admin issue-svc-token \
        --name="init40-rbac-admin-$RANDOM" \
        --permission=admin \
        --output=stdout 2>/dev/null || true
}

# Create a subscription as the bearer in $1; echo the new subscription id.
create_subscription() {
    local bearer="$1" name="$2"
    local payload
    payload="$(jq -nc --arg n "$name" --arg url "$WEBHOOK_URL" --arg s "$WEBHOOK_SECRET" '{
        name: $n,
        target: { kind: "webhook", url: $url, secret: $s },
        filter: {
            categories: ["artifact"],
            event_types: { kind: "all" },
            repositories: { kind: "owned_by_actor" }
        }
    }')"
    curl -sS -m 15 -X POST "$API_URL/api/v1/subscriptions" \
        -H "Authorization: Bearer $bearer" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>/dev/null
}

# Read persisted snapshot_claims for a subscription id, as a sorted
# JSON array string. psql is invoked via `docker compose exec postgres`
# (the base compose ships postgres without a host port) — same idiom as
# test-gitops-policies.sh.
snapshot_claims_of() {
    local sub_id="$1"
    "${COMPOSE[@]}" exec -T postgres \
        psql -U registry -d artifact_registry -tAX -c \
        "SELECT COALESCE(to_json(ARRAY(SELECT unnest(snapshot_claims) ORDER BY 1)), '[]')
           FROM subscriptions WHERE id = '$sub_id';" \
        2>/dev/null | tr -d '[:space:]'
}

# Fire a matching artifact event: publish a tiny package into $RBAC_REPO
# via the admin token so an ArtifactIngested (category=artifact) lands.
# The subscription's OwnedByActor scope resolves through the seeded
# Read grant for the positive path; the PAT path resolves to nothing.
fire_matching_event() {
    local admin_bearer="$1"
    local pkg="init40-rbac-$RANDOM"
    local sdist="$WORK_DIR/${pkg}-0.0.1.tar.gz"
    # Minimal but well-formed sdist; the upload handler emits
    # ArtifactIngested on accept regardless of payload richness.
    printf 'init40 rbac smoke payload\n' > "$WORK_DIR/payload.txt"
    tar -czf "$sdist" -C "$WORK_DIR" payload.txt 2>/dev/null || true
    curl -sS -m 20 -o /dev/null \
        -X POST "$API_URL/$RBAC_REPO/" \
        -H "Authorization: Bearer $admin_bearer" \
        -F ":action=file_upload" \
        -F "name=$pkg" \
        -F "version=0.0.1" \
        -F "content=@$sdist;filename=${pkg}-0.0.1.tar.gz" \
        2>/dev/null || true
}

# -----------------------------------------------------------------------------
# Phase 5 — POSITIVE: OIDC user, mapped claims, Claims-grant → delivery
# -----------------------------------------------------------------------------
#
# A non-admin OIDC user whose IdP groups map to [developer, team-alpha]
# holds a Claims-subject Read grant on $RBAC_REPO. The subscription's
# snapshot_claims MUST capture exactly that set; a matching event MUST
# be delivered within DELIVERY_WAIT_SECS.

log ""
log "--> [5/9] POSITIVE: OIDC login as non-admin '$RBAC_USER'"

OIDC_TOKEN="$(oidc_login)"
if [ -z "$OIDC_TOKEN" ]; then
    assert_fail "oidc-login" "ROPC login for $RBAC_USER returned no access_token"
else
    assert_pass "OIDC ROPC login succeeded (non-admin user)"
fi

ADMIN_TOKEN="$(mint_admin_token)"
if [ -z "$ADMIN_TOKEN" ]; then
    assert_fail "admin-token" "hort-server admin issue-svc-token returned empty"
    log ""
    log "==> Summary: $PASSED passed, $((FAIL + 1)) failed"
    exit 1
fi
install -m 0600 /dev/null "$TOKEN_FILE"
printf '%s' "$ADMIN_TOKEN" > "$TOKEN_FILE"

log ""
log "--> [6/9] POSITIVE: create OwnedByActor subscription via OIDC bearer"

POS_RESP="$(create_subscription "$OIDC_TOKEN" "init40-positive-$RANDOM")"
POS_SUB_ID="$(printf '%s' "$POS_RESP" | jq -r '.id // empty' 2>/dev/null || true)"

if [ -n "$POS_SUB_ID" ]; then
    assert_pass "subscription created via OIDC (id=$POS_SUB_ID)"
else
    assert_fail "positive-subscription-create" "no id in response: $POS_RESP"
fi

if [ -n "$POS_SUB_ID" ]; then
    POS_SNAP="$(snapshot_claims_of "$POS_SUB_ID")"
    EXPECTED_SNAP='["developer","team-alpha"]'
    if [ "$POS_SNAP" = "$EXPECTED_SNAP" ]; then
        assert_pass "persisted snapshot_claims == $EXPECTED_SNAP"
    else
        assert_fail \
            "positive-snapshot-claims" \
            "expected $EXPECTED_SNAP, got '$POS_SNAP'"
    fi
fi

log ""
log "--> [7/9] POSITIVE: fire matching artifact event, expect delivery <=${DELIVERY_WAIT_SECS}s"

receiver_reset
fire_matching_event "$ADMIN_TOKEN"

POS_DELIVERED=""
for _ in $(seq 1 "$DELIVERY_WAIT_SECS"); do
    if [ "$(receiver_hits)" -ge 1 ] 2>/dev/null; then
        POS_DELIVERED="1"; break
    fi
    sleep 1
done
if [ -n "$POS_DELIVERED" ]; then
    assert_pass "webhook received the matching event within ${DELIVERY_WAIT_SECS}s"
else
    assert_fail \
        "positive-delivery" \
        "no webhook hit within ${DELIVERY_WAIT_SECS}s (claims-grant did not authorise OwnedByActor scope)"
fi

# -----------------------------------------------------------------------------
# Phase 6 — NEGATIVE: same user, PAT-created subscription → NO delivery
# -----------------------------------------------------------------------------
#
# Pins §6 invariant 1: a PAT carries zero non-admin claims (the PAT
# path never consults claim_mappings). The SAME non-admin user creating
# a subscription via a PAT gets snapshot_claims == [] — so the
# OwnedByActor scope resolves to nothing and the matching event MUST
# NOT be delivered.

log ""
log "--> [8/9] NEGATIVE: mint a PAT for '$RBAC_USER', create subscription via PAT"

# Admin mints a non-admin PAT bound to the same backing user. The
# assertion that matters is the snapshot + non-delivery, not the mint
# path details.
PAT_RESP="$(curl -sS -m 15 -X POST "$API_URL/api/v1/admin/tokens" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$(jq -nc --arg u "$RBAC_USER" \
        '{username:$u, name:"init40-rbac-pat", permission:"read"}')" \
    2>/dev/null || true)"
USER_PAT="$(printf '%s' "$PAT_RESP" | jq -r '.token // .secret // empty' 2>/dev/null || true)"

if [ -z "$USER_PAT" ]; then
    assert_fail "pat-mint" "could not mint a PAT for $RBAC_USER: $PAT_RESP"
    log ""
    log "==> Summary: $PASSED passed, $((FAIL + 1)) failed"
    exit 1
fi
assert_pass "minted a non-admin PAT for $RBAC_USER"

NEG_RESP="$(create_subscription "$USER_PAT" "init40-negative-$RANDOM")"
NEG_SUB_ID="$(printf '%s' "$NEG_RESP" | jq -r '.id // empty' 2>/dev/null || true)"

if [ -n "$NEG_SUB_ID" ]; then
    assert_pass "subscription created via PAT (id=$NEG_SUB_ID)"
else
    assert_fail "negative-subscription-create" "no id in response: $NEG_RESP"
fi

if [ -n "$NEG_SUB_ID" ]; then
    NEG_SNAP="$(snapshot_claims_of "$NEG_SUB_ID")"
    if [ "$NEG_SNAP" = "[]" ]; then
        assert_pass "persisted snapshot_claims == [] (§6 invariant 1: PAT carries no claims)"
    else
        assert_fail \
            "negative-snapshot-claims" \
            "expected [], got '$NEG_SNAP' — PAT path leaked claim_mappings"
    fi
fi

log ""
log "--> [9/9] NEGATIVE: fire matching event, expect NO delivery within ${DELIVERY_WAIT_SECS}s"

receiver_reset
fire_matching_event "$ADMIN_TOKEN"

sleep "$DELIVERY_WAIT_SECS"
NEG_HITS="$(receiver_hits)"
if [ "$NEG_HITS" = "0" ]; then
    assert_pass "no webhook delivery for the PAT-created subscription (snapshot empty → OwnedByActor resolves to nothing)"
else
    assert_fail \
        "negative-no-delivery" \
        "expected 0 hits, got $NEG_HITS — PAT subscription delivered an event it must not"
fi

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------

log ""
log "==> Summary: $PASSED passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then
    log ""
    log "Failures:"
    for f in "${FAILURES[@]}"; do
        log "  - $f"
    done
    exit 1
fi
exit 0
