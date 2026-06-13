#!/usr/bin/env bash
# requires:
# npm scenario: push (npm publish) and pull (npm install) operations.

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"

REPO_KEY="${NPM_REPO_KEY:-npm-e2e}"
NPM_REGISTRY="${HORT_URL%/}/npm/${REPO_KEY}/"
TEST_VERSION="1.0.$(date +%s)"

log "==> NPM Native Client Test"
log "Registry: $NPM_REGISTRY"
log "Version:  $TEST_VERSION"

# Fetch tokens via the shared lib
DEV_TOKEN="$(fetch_token dev-user dev)"
[ -n "$DEV_TOKEN" ]    || fail "fetch dev-user token"    "empty response from Keycloak"

READER_TOKEN="$(fetch_token reader-user reader)"
[ -n "$READER_TOKEN" ] || fail "fetch reader-user token" "empty response from Keycloak"

log "[auth] fetched DEV_TOKEN + READER_TOKEN from Keycloak"

# Generate test package
log "==> Generating test package..."
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

cd "$WORK_DIR" || { fail "cd into WORK_DIR" "$WORK_DIR"; summary; }

cat > package.json << EOF
{
  "name": "@test/native-package",
  "version": "$TEST_VERSION",
  "description": "Test package for native client E2E testing",
  "main": "index.js",
  "author": "Test Author",
  "license": "MIT"
}
EOF

cat > index.js << EOF
module.exports = {
  hello: function() {
    return "Hello from @test/native-package!";
  },
  version: "$TEST_VERSION"
};
EOF

# Configure npm registry.
#
# Switch auth from legacy Basic (_auth) to bearer (_authToken). npm
# emits `Authorization: Bearer <value>` for `_authToken`, which is the
# form the middleware validates as a registry JWT. Any pre-existing Basic
# configs must be cleared first so npm does not combine them.
NPM_HOST_PATH="${NPM_REGISTRY#http*://}"
log "==> Configuring npm registry..."
npm config set registry "$NPM_REGISTRY"
npm config delete "//${NPM_HOST_PATH}:_auth"     2>/dev/null || true
npm config delete "//${NPM_HOST_PATH}:_password" 2>/dev/null || true
npm config delete "//${NPM_HOST_PATH}:username"  2>/dev/null || true
npm config set "//${NPM_HOST_PATH}:_authToken" "$DEV_TOKEN"

# ---- Test 1: npm publish ----
log "==> [1/4] Publishing package with npm..."
if npm publish --access public 2>&1 | tail -5 || npm publish 2>&1 | tail -5; then
  pass "npm publish succeeded"
else
  fail "npm publish" "npm publish exited non-zero"
fi

# ---- Test 2: npm install + verify ----
log "==> [2/4] Installing package with npm..."
mkdir -p "$WORK_DIR/test-install"
cd "$WORK_DIR/test-install" || { fail "cd into test-install" "$WORK_DIR/test-install"; summary; }
npm init -y >/dev/null 2>&1
if npm install "@test/native-package@$TEST_VERSION" 2>&1 | tail -5; then
  OUTPUT="$(node -e "const pkg = require('@test/native-package'); console.log(pkg.hello());")"
  if [ "$OUTPUT" = "Hello from @test/native-package!" ]; then
    pass "npm install + node require succeeded"
  else
    fail "npm install output" "expected 'Hello from @test/native-package!' got '$OUTPUT'"
  fi
else
  fail "npm install" "npm install exited non-zero"
fi

# ---- Negative assertions ----
#
# The publish handler resolves the actor + runs authorize() BEFORE
# parsing the publish body, so a minimal JSON body is fine — we only
# care about the status code.

log "[auth] negative test 1/2: publish without credentials must 401"
STATUS=$(curl -sS -o /dev/null -w '%{http_code}' \
    -X PUT "${NPM_REGISTRY}denied" \
    -H 'Content-Type: application/json' \
    -d '{}')
if [ "$STATUS" = "401" ]; then
  pass "no-auth npm publish -> 401"
else
  fail "no-auth npm publish expected 401" "got $STATUS"
fi

log "[auth] negative test 2/2: publish with reader token must 403"
STATUS=$(curl -sS -o /dev/null -w '%{http_code}' \
    -X PUT "${NPM_REGISTRY}denied" \
    -H "Authorization: Bearer $READER_TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{}')
if [ "$STATUS" = "403" ]; then
  pass "reader-token npm publish -> 403"
else
  fail "reader-token npm publish expected 403" "got $STATUS"
fi

assert_metric_ingest npm
summary
