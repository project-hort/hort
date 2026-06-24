#!/usr/bin/env bash
# requires:
# Virtual (aggregated) PyPI repository scenario (ADR 0031). Drives a real pip /
# twine client against `pypi-virt-e2e`, a `type: virtual` repo aggregating a
# PRIVATE hosted member (`pypi-internal`, highest priority) + the public proxy
# (`pypi-public`). Mirrors the npm `clients/virtual.sh`. Asserts the end-to-end
# wiring:
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
# Egress-free happy path: the private member OWNS `hort-virt-private-pkg`, so
# name-level pinning excludes the public proxy for that name (pypi.org is never
# consulted on the authenticated install). The dependency-confusion pinning
# logic itself is exhaustively covered at the unit/integration layer (hort-app
# `aggregate_virtual_index`/`resolve_download` + the per-format crate tests).
# Test 3 (anonymous) may fall through to the proxy because the private member
# is skipped for a caller without Read; it is bounded with `--max-time` and
# asserts NON-LEAK (the private version must not appear), so it holds whether
# or not the harness has egress.

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"

command -v python3 >/dev/null || skip "python3 not found"
command -v pip3    >/dev/null || skip "pip3 not found"
command -v twine   >/dev/null || skip "twine not found"

MEMBER_KEY="${PYPI_VIRT_MEMBER_KEY:-pypi-internal}"
VIRTUAL_KEY="${PYPI_VIRT_KEY:-pypi-virt-e2e}"
MEMBER_UPLOAD_URL="${HORT_URL%/}/pypi/${MEMBER_KEY}/"
VIRTUAL_BASE="${HORT_URL%/}/pypi/${VIRTUAL_KEY}"
# Distribution name (PEP 503 normalised: lowercase, single dashes). The
# private member owns this name → the public proxy is pinned out for it.
PKG="hort-virt-private-pkg"
# Import/module name (underscores).
MODULE="hort_virt_private_pkg"
TEST_VERSION="1.0.$(date +%s)"

log "==> Virtual (aggregated) PyPI repository test (ADR 0031)"
log "Member (private): $MEMBER_UPLOAD_URL"
log "Virtual:          ${VIRTUAL_BASE}/"
log "Package:          ${PKG}==${TEST_VERSION}"

DEV_TOKEN="$(fetch_token dev-user dev)"
[ -n "$DEV_TOKEN" ] || fail "fetch dev-user token" "empty response from Keycloak"
ADMIN_TOKEN="$(fetch_token admin admin)"
[ -n "$ADMIN_TOKEN" ] || fail "fetch admin token" "empty response from Keycloak"
log "[auth] fetched DEV_TOKEN (read+write pypi-internal) + ADMIN_TOKEN (global write)"

# Split HORT_URL into scheme / host:port / host for the pip index URL (which
# carries the bearer token in the userinfo slot) and --trusted-host.
HORT_SCHEME="${HORT_URL%%://*}"
HORT_REST="${HORT_URL#*://}"
HORT_HOSTPORT="${HORT_REST%%/*}"
HORT_HOST="${HORT_HOSTPORT%%:*}"

WORK_DIR="$(mktemp -d)"
VENV_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR" "$VENV_DIR"' EXIT
cd "$WORK_DIR" || { fail "cd into WORK_DIR" "$WORK_DIR"; summary; }

mkdir -p "src/${MODULE}"
cat > pyproject.toml << EOF
[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "$PKG"
version = "$TEST_VERSION"
description = "Private package for the PyPI virtual-repo E2E"
requires-python = ">=3.8"
EOF
cat > "src/${MODULE}/__init__.py" << EOF
__version__ = "$TEST_VERSION"
def hello():
    return "Hello from the private member!"
EOF

log "==> Building package..."
python3 -m build --wheel --sdist 2>&1 | tail -3

# ---- Step 0: publish to the PRIVATE MEMBER directly ----
# The virtual is read-only; the package is seeded into its member, then read
# back THROUGH the virtual. dev-user has write on pypi-internal. Twine emits
# HTTP Basic only; the auth middleware treats the Basic password as a bearer
# shim when the username is `__token__`.
log "==> Publishing ${PKG}==${TEST_VERSION} to the private member..."
if TWINE_USERNAME="__token__" TWINE_PASSWORD="$DEV_TOKEN" \
   twine upload --repository-url "$MEMBER_UPLOAD_URL" dist/* 2>&1 | tail -5; then
  pass "publish to private member succeeded"
else
  fail "publish to private member" "twine upload exited non-zero"
fi

# ---- Test 1: merged index + first-authoritative download THROUGH the virtual ----
# A dev who can read the private member installs the package via the virtual
# index. Exercises the virtual simple-index merge (proxy pinned out for the
# owned name → deterministic, no egress) AND the first-authoritative file
# download. The bearer rides the index URL userinfo; pip reuses it for the
# same-host file fetch.
log "==> [1/3] Installing ${PKG} THROUGH the virtual (dev)..."
VENV="$VENV_DIR/v"
python3 -m venv "$VENV"
VIRTUAL_INDEX_URL="${HORT_SCHEME}://__token__:${DEV_TOKEN}@${HORT_HOSTPORT}/pypi/${VIRTUAL_KEY}/simple/"
if "$VENV/bin/pip" install \
      --index-url "$VIRTUAL_INDEX_URL" \
      --trusted-host "$HORT_HOST" \
      "${PKG}==${TEST_VERSION}" 2>&1 | tail -5 \
   && "$VENV/bin/python" -c \
      "from ${MODULE} import hello; assert hello() == 'Hello from the private member!'"; then
  pass "install through virtual succeeded (merged index + authoritative download)"
else
  fail "install through virtual" "pip install via the virtual index failed"
fi

# ---- Test 2: write-rejection (read-only aggregator) ----
# A publish to the virtual must be rejected. Observed as ADMIN: global write
# clears the authz gate, so the request reaches `reject_write_to_virtual` and
# gets the 400 "virtual repositories are read-only" envelope. (A non-writer
# would 403 at the authz gate first, never reaching the guard.) The upload
# handler resolves the actor + authorize BEFORE multipart parsing, so a dummy
# body is fine — we only care about the status code.
log "==> [2/3] Publish to the virtual must be rejected (admin)..."
STATUS=$(curl -sS -o /dev/null -w '%{http_code}' \
    -X POST "${VIRTUAL_BASE}/" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -F ':action=file_upload' \
    -F 'protocol_version=1' \
    -F 'name=denied' \
    -F 'version=0.0.1' \
    -F 'content=@/dev/null;filename=denied-0.0.1.tar.gz')
if [ "$STATUS" = "400" ]; then
  pass "publish to virtual -> 400 (read-only aggregator)"
else
  fail "publish to virtual expected 400" "got $STATUS"
fi

# ---- Test 3: no private-member leak to an anonymous caller ----
# The virtual is public; the member is private. An anonymous read of the
# virtual simple index must NOT surface the private member's package —
# resolve_members skips a member the caller cannot Read (ADR 0031 / ADR 0021).
# For an anon caller the private member is skipped, so the name is unowned and
# the read may fall through to the public proxy; that is bounded with
# --max-time and the assertion is NON-LEAK (the unique private version must not
# appear), which holds whether or not the proxy/egress answers.
log "==> [3/3] Anonymous read of the virtual must not leak the private package..."
ANON_RESP=$(curl -sS --max-time 30 -w $'\n%{http_code}' \
    "${VIRTUAL_BASE}/simple/${PKG}/" 2>/dev/null || true)
ANON_STATUS=$(printf '%s' "$ANON_RESP" | tail -n1)
ANON_INDEX=$(printf '%s' "$ANON_RESP" | sed '$d')
if printf '%s' "$ANON_INDEX" | grep -q "$TEST_VERSION"; then
  fail "anonymous read leaked the private package" \
       "version $TEST_VERSION present in the anonymous virtual index (status $ANON_STATUS)"
else
  pass "anonymous read of private package via virtual does not leak (status $ANON_STATUS)"
fi

summary
