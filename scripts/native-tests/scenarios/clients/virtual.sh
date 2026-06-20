#!/usr/bin/env bash
# requires:
# Virtual (aggregated) repository scenario (ADR 0031). Drives a real npm
# client against `npm-virt-e2e`, a `type: virtual` repo aggregating a
# PRIVATE hosted member (`npm-virt-internal`, highest priority) + the public
# proxy (`npm-public`). Asserts the end-to-end wiring:
#
#   1. merged index + first-authoritative download — a package published to
#      the private member is installable THROUGH the virtual (by a caller who
#      can read the member);
#   2. write-rejection — a publish to the virtual is rejected (read-only
#      aggregator), observed as an admin (global write reaches the repo-type
#      guard; a non-writer would 403 at the authz gate first);
#   3. no private-member leak — an anonymous read of the virtual does NOT
#      surface the private member's package.
#
# Deterministic + egress-free: the private member OWNS `@hort-virt/*`, so
# name-level pinning excludes the public proxy for that name (the proxy's
# upstream is never consulted). The dependency-confusion pinning logic itself
# is exhaustively covered at the unit/integration layer (hort-app
# `aggregate_virtual_index`/`resolve_download` + the per-format crate tests).

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"

MEMBER_KEY="${NPM_VIRT_MEMBER_KEY:-npm-virt-internal}"
VIRTUAL_KEY="${NPM_VIRT_KEY:-npm-virt-e2e}"
MEMBER_REGISTRY="${HORT_URL%/}/npm/${MEMBER_KEY}/"
VIRTUAL_REGISTRY="${HORT_URL%/}/npm/${VIRTUAL_KEY}/"
PKG="@hort-virt/private-pkg"
TEST_VERSION="1.0.$(date +%s)"

log "==> Virtual (aggregated) repository test (ADR 0031)"
log "Member (private): $MEMBER_REGISTRY"
log "Virtual:          $VIRTUAL_REGISTRY"
log "Package:          ${PKG}@${TEST_VERSION}"

DEV_TOKEN="$(fetch_token dev-user dev)"
[ -n "$DEV_TOKEN" ] || fail "fetch dev-user token" "empty response from Keycloak"
ADMIN_TOKEN="$(fetch_token admin admin)"
[ -n "$ADMIN_TOKEN" ] || fail "fetch admin token" "empty response from Keycloak"
log "[auth] fetched DEV_TOKEN (read+write npm-virt-internal) + ADMIN_TOKEN (global write)"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
cd "$WORK_DIR" || { fail "cd into WORK_DIR" "$WORK_DIR"; summary; }

mkdir -p pkg
cat > pkg/package.json << EOF
{
  "name": "$PKG",
  "version": "$TEST_VERSION",
  "description": "Private package for the virtual-repo E2E",
  "main": "index.js",
  "license": "MIT"
}
EOF
cat > pkg/index.js << EOF
module.exports = { hello: function () { return "Hello from the private member!"; } };
EOF

HORT_HOST_PATH="${HORT_URL#http*://}"
HORT_HOST_PATH="${HORT_HOST_PATH%%/*}"

# ---- Step 0: publish the package to the PRIVATE MEMBER directly ----
# The virtual is read-only; the package is seeded into its member, then read
# back THROUGH the virtual. dev-user has write on npm-virt-internal.
log "==> Publishing ${PKG}@${TEST_VERSION} to the private member..."
(
  cd pkg || exit 2
  npm config set "@hort-virt:registry" "$MEMBER_REGISTRY"
  npm config set "//${HORT_HOST_PATH}/npm/${MEMBER_KEY}/:_authToken" "$DEV_TOKEN"
  npm publish --access public
) 2>&1 | tail -5
# shellcheck disable=SC2181
if [ "${PIPESTATUS[0]:-1}" -eq 0 ]; then
  pass "publish to private member succeeded"
else
  fail "publish to private member" "npm publish exited non-zero"
fi

# ---- Test 1: merged index + first-authoritative download THROUGH the virtual ----
# A dev who can read the private member installs the package via the virtual
# registry. This exercises the virtual packument merge (proxy pinned out for
# the owned name → deterministic, no egress) AND the first-authoritative
# tarball download.
log "==> [1/3] Installing ${PKG} THROUGH the virtual (dev)..."
mkdir -p consume
(
  cd consume || exit 2
  npm init -y >/dev/null 2>&1
  npm config set "@hort-virt:registry" "$VIRTUAL_REGISTRY"
  npm config set "//${HORT_HOST_PATH}/npm/${VIRTUAL_KEY}/:_authToken" "$DEV_TOKEN"
  npm install "${PKG}@${TEST_VERSION}"
) 2>&1 | tail -5
if [ "${PIPESTATUS[0]:-1}" -eq 0 ] &&
   [ -f "consume/node_modules/${PKG}/package.json" ]; then
  pass "install through virtual succeeded (merged index + authoritative download)"
else
  fail "install through virtual" "npm install via the virtual registry failed"
fi

# ---- Test 2: write-rejection (read-only aggregator) ----
# A publish to the virtual must be rejected. Observed as ADMIN: global write
# clears the authz gate, so the request reaches the repo-type guard and gets
# the 400 "virtual repositories are read-only" envelope. (A non-writer would
# 403 at the authz gate first, never reaching the guard.)
log "==> [2/3] Publish to the virtual must be rejected (admin)..."
STATUS=$(curl -sS -o /dev/null -w '%{http_code}' \
    -X PUT "${VIRTUAL_REGISTRY}${PKG}" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{}')
if [ "$STATUS" = "400" ]; then
  pass "publish to virtual -> 400 (read-only aggregator)"
else
  fail "publish to virtual expected 400" "got $STATUS"
fi

# ---- Test 3: no private-member leak to an anonymous caller ----
# The virtual is public; the member is private. An anonymous read of the
# virtual must NOT surface the private member's package — resolve_members
# skips a member the caller cannot Read (ADR 0031 / ADR 0021), and the public
# proxy has no `@hort-virt/*`, so the packument is a 404.
log "==> [3/3] Anonymous read of the virtual must not leak the private package..."
STATUS=$(curl -sS -o /dev/null -w '%{http_code}' \
    "${VIRTUAL_REGISTRY}@hort-virt/private-pkg")
if [ "$STATUS" = "404" ]; then
  pass "anonymous read of private package via virtual -> 404 (no leak)"
else
  fail "anonymous read expected 404 (no leak)" "got $STATUS"
fi

summary
