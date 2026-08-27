#!/usr/bin/env bash
#
# scripts/ci/github-oidc-hort-token.sh — mint a FRESH hort bearer inside a
# GitHub Actions job: request a new OIDC id-token from the runner, exchange
# it at hort's /api/v1/auth/exchange, print the raw bearer to stdout.
#
# Usage:
#   scripts/ci/github-oidc-hort-token.sh <hort-base-url> <audience>
#
# Environment (provided by the GitHub runner when `permissions: id-token:
# write` is set on the job):
#   ACTIONS_ID_TOKEN_REQUEST_URL / ACTIONS_ID_TOKEN_REQUEST_TOKEN
#
# Why this exists: the federated exchange mints a NON-refreshable bearer
# capped at min(1h, id-token exp − now) — a deliberate blast-radius bound
# that must not be widened. A long-running step (the topological crates
# publish) therefore re-MINTS instead of holding one token: the runner
# hands out fresh id-tokens on demand for the whole job lifetime, so a
# caller can invoke this script per unit of work. Everything except the
# bearer goes to stderr; the exchange response body is never printed (it
# carries the token — mirrors the hort-auth action's masking discipline).
#
# The exchange call shape is the same wire contract as the "Exchange OIDC
# token for hort bearer token" step in .github/actions/hort-auth/action.yml
# (RFC 8693 form-encoded, subject_token_type=jwt → the federation branch).
# A change to that contract changes both call sites together.

set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $(basename "$0") <hort-base-url> <audience>" >&2
  exit 2
fi

hort_url="$1"
audience="$2"

: "${ACTIONS_ID_TOKEN_REQUEST_URL:?not running under a GitHub job with id-token permission}"
: "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:?not running under a GitHub job with id-token permission}"

oidc_token="$(curl -sSf \
  -H "Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${audience}" \
  | jq -r '.value // empty')"
if [[ -z "${oidc_token}" ]]; then
  echo "error: GitHub OIDC id-token request returned no value (body omitted)" >&2
  exit 1
fi

response="$(curl -sSf \
  -X POST "${hort_url}/api/v1/auth/exchange" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  --data-urlencode "subject_token=${oidc_token}" \
  --data-urlencode "subject_token_type=urn:ietf:params:oauth:token-type:jwt")"

token="$(echo "${response}" | jq -r '.access_token // empty')"
if [[ -z "${token}" ]]; then
  echo "error: hort token exchange returned no access_token (body omitted)" >&2
  exit 1
fi

printf '%s' "${token}"
