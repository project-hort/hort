#!/usr/bin/env bash
# scripts/test-fail2ban-regex.sh
#
# Regression test for the hort-nginx-auth fail2ban filter.
#
# Tests that:
#   - 401 responses on ANY path are matched (would trigger a ban)
#   - 403 responses on ANY path are matched (would trigger a ban)
#   - 200 responses are NOT matched (no false positives on anonymous reads)
#
# Usage:
#   ./scripts/test-fail2ban-regex.sh
#
# Requirements:
#   fail2ban-regex must be installed (part of the fail2ban package).
#   On Debian/Ubuntu: sudo apt-get install -y fail2ban
#
# CI/host-gating note:
#   This script requires fail2ban to be installed on the machine running it.
#   It is NOT runnable on a bare CI runner without fail2ban installed.
#   Options for CI integration:
#     1. Add a CI job that installs fail2ban and runs this script
#        (e.g. in .github/workflows or .gitlab-ci.yml).
#     2. Run it post-provisioning on the target host:
#          ssh debian@registry.hort.rs ./scripts/test-fail2ban-regex.sh
#   The Ansible provisioning run deploys the filter to the target — running
#   this script there after provisioning gives the authoritative validation.
#
# Exit codes:
#   0 — all assertions passed
#   1 — one or more assertions failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FILTER="${REPO_ROOT}/deploy/ansible/roles/fail2ban/templates/hort-nginx-auth.conf.j2"

# ── Prerequisite check ────────────────────────────────────────────────────────

if ! command -v fail2ban-regex &>/dev/null; then
    echo "ERROR: fail2ban-regex not found." >&2
    echo "Install fail2ban: sudo apt-get install -y fail2ban" >&2
    echo "" >&2
    echo "This test is CI/host-gated: it requires fail2ban to be installed." >&2
    echo "See the CI/host-gating note in this script for integration options." >&2
    exit 1
fi

# ── Sample log lines ──────────────────────────────────────────────────────────
#
# nginx combined log format:
#   $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
#   "$http_referer" "$http_user_agent"
#
# SHOULD MATCH (401/403 on any path) ──────────────────────────────────────────

MATCH_LINES=(
    # 401 on OCI auth challenge (docker login)
    '1.2.3.4 - - [21/Jun/2026:10:00:00 +0000] "GET /v2/ HTTP/1.1" 401 0 "-" "docker/24.0"'
    # 403 on admin API (wrong token)
    '5.6.7.8 - - [21/Jun/2026:11:00:00 +0000] "POST /api/v1/admin/tokens HTTP/1.1" 403 162 "-" "curl/7.88"'
    # 401 on Maven path (brute-force probe of a non-path-allowlisted endpoint)
    '9.10.11.12 - - [21/Jun/2026:12:00:00 +0000] "GET /maven/com/example/foo/1.0/foo-1.0.jar HTTP/1.1" 401 0 "-" "mvn/3.9"'
    # 403 on Keycloak/realms path (probe of auth infrastructure)
    '2.3.4.5 - - [21/Jun/2026:13:00:00 +0000] "GET /realms/hort/protocol/openid-connect/auth HTTP/1.1" 403 0 "-" "python-requests/2.31"'
    # 401 on token exchange endpoint
    '3.4.5.6 - - [21/Jun/2026:14:00:00 +0000] "POST /api/v1/auth/exchange HTTP/1.1" 401 85 "-" "hort-cli/0.9"'
)

# SHOULD NOT MATCH (200 on anonymous reads — no false positives) ───────────────

NO_MATCH_LINES=(
    # 200 on anonymous OCI manifest read (public pull-through)
    '1.2.3.4 - - [21/Jun/2026:10:00:00 +0000] "GET /v2/hort-oci/manifests/latest HTTP/1.1" 200 1234 "-" "crane/0.19"'
    # 200 on anonymous PyPI simple index read
    '9.10.11.12 - - [21/Jun/2026:12:00:00 +0000] "GET /pypi/simple/requests/ HTTP/1.1" 200 4096 "-" "pip/23.0"'
    # 200 on Cargo sparse index read
    '7.8.9.10 - - [21/Jun/2026:15:00:00 +0000] "GET /crates/index/config.json HTTP/1.1" 200 256 "-" "cargo/1.79"'
    # 200 on npm package metadata read
    '11.12.13.14 - - [21/Jun/2026:16:00:00 +0000] "GET /npm/hort-npm/some-package HTTP/1.1" 200 8192 "-" "npm/10.0"'
)

# ── Helpers ───────────────────────────────────────────────────────────────────

TMPLOG="$(mktemp /tmp/test-fail2ban-XXXXXX.log)"
trap 'rm -f "${TMPLOG}"' EXIT

PASS=0
FAIL=0

run_regex_check() {
    local line="$1"
    local logfile="$2"
    # fail2ban-regex exits 0 whether or not lines matched; we parse its output.
    fail2ban-regex "${logfile}" "${FILTER}" 2>&1
}

assert_matches() {
    local desc="$1"
    local line="$2"
    echo "${line}" > "${TMPLOG}"
    local output
    output="$(run_regex_check "${line}" "${TMPLOG}")"
    # fail2ban-regex reports "Lines: 1 lines, X ignored, Y matched, Z missed"
    local matched
    matched="$(echo "${output}" | grep -E "^Lines:" | grep -oP '\d+ matched' | grep -oP '\d+')"
    if [[ "${matched:-0}" -ge 1 ]]; then
        echo "  PASS [matches]  ${desc}"
        PASS=$((PASS + 1))
    else
        echo "  FAIL [expected match but got 0]  ${desc}"
        echo "       Line: ${line}"
        FAIL=$((FAIL + 1))
    fi
}

assert_no_match() {
    local desc="$1"
    local line="$2"
    echo "${line}" > "${TMPLOG}"
    local output
    output="$(run_regex_check "${line}" "${TMPLOG}")"
    local matched
    matched="$(echo "${output}" | grep -E "^Lines:" | grep -oP '\d+ matched' | grep -oP '\d+')"
    if [[ "${matched:-0}" -eq 0 ]]; then
        echo "  PASS [no match] ${desc}"
        PASS=$((PASS + 1))
    else
        echo "  FAIL [false positive — expected no match]  ${desc}"
        echo "       Line: ${line}"
        FAIL=$((FAIL + 1))
    fi
}

# ── Run assertions ────────────────────────────────────────────────────────────

echo "=== hort-nginx-auth fail2ban regex regression test ==="
echo "Filter: ${FILTER}"
echo ""

echo "-- Lines that SHOULD match (401/403 → would trigger ban) --"
for line in "${MATCH_LINES[@]}"; do
    desc="${line:0:80}..."
    assert_matches "${desc}" "${line}"
done

echo ""
echo "-- Lines that SHOULD NOT match (200 → no false positive) --"
for line in "${NO_MATCH_LINES[@]}"; do
    desc="${line:0:80}..."
    assert_no_match "${desc}" "${line}"
done

echo ""
echo "=== Results: ${PASS} passed, ${FAIL} failed ==="

if [[ "${FAIL}" -gt 0 ]]; then
    exit 1
fi
exit 0
