#!/usr/bin/env bash
#
# scripts/ci/publish-crates.sh — publish the workspace's first-party crates
# to a hort cargo registry, skipping the ones already published.
#
# Usage:
#   scripts/ci/publish-crates.sh <hort-base-url> <repo-key>
#
# Environment:
#   HORT_TOKEN                        bearer for the index reads (see the
#                                     check script for why it is wanted)
#   HORT_PUBLISH_PROPAGATION_SLEEP    seconds to wait after each upload
#                                     (default 10)
#   HORT_TOKEN_REFRESH_CMD            optional: a command that prints a
#                                     FRESH raw bearer to stdout. When set,
#                                     it runs before EVERY publish attempt
#                                     and the result replaces HORT_TOKEN
#                                     and the CARGO_REGISTRIES_*_TOKEN
#                                     vars cargo reads. The federated
#                                     exchange mints non-refreshable
#                                     bearers capped at ≤1h by design, and
#                                     a full topological publish can
#                                     outlive one — so a long loop
#                                     re-mints per crate instead of
#                                     holding a single token. Unset: the
#                                     ambient token is used unchanged.
#
# Exits 0 when every crate in the publish set is present in the registry at
# the workspace version — whether this run uploaded it or found it already
# there. Any `cargo publish` failure aborts immediately, non-zero.
#
# ── Resumability, and the trap under it ─────────────────────────────────────
#
# An upload is irreversible: a published version can be yanked but never
# replaced or withdrawn. So a run that fails partway leaves real crates
# behind, and cargo refuses to republish them — which used to make the whole
# tag unrepeatable, because a re-run died on the first already-uploaded
# crate and the ones that never made it could not ship at that version.
#
# Each crate is therefore checked against the registry index BEFORE its
# attempt, and skipped when its exact version is already there. The check is
# an index lookup, not an interpretation of cargo's behaviour, and that
# distinction is the point rather than a detail:
#
#   * Cargo's refusal is client-side and its wording is not a contract.
#   * By the time cargo has exited, "refused to republish" and "the upload
#     failed" are the same non-zero status — indistinguishable.
#
# A loop that continued past a failing `cargo publish` would therefore turn
# every genuine failure into a silent skip and ship a release with crates
# missing. That is strictly worse than failing loudly, so this script never
# does it: `set -e` stays in force across the publish call, and the only
# thing that may skip a crate is a positive index observation made first.
#
# A version already in the index is immutable and content-addressed, so
# continuing past it is safe. That argument extends to nothing else — in
# particular not to an upload hort rejected as a same-path-different-hash
# conflict, which means the packaged bytes changed between attempts and is a
# stop-and-think condition, not something to skip past.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $# -ne 2 ]]; then
  echo "usage: $(basename "$0") <hort-base-url> <repo-key>" >&2
  exit 2
fi

hort_url="$1"
repo_key="$2"
propagation_sleep="${HORT_PUBLISH_PROPAGATION_SLEEP:-10}"

# Re-mint the bearer for the next publish attempt. cargo sends the registry
# token verbatim, so it is wrapped as HTTP Basic with a dummy username —
# the exact shape the hort-auth action writes (`Basic base64("x:" + raw)`);
# both registries share the one session token (per-repo RBAC decides).
# The repo-key var name follows cargo's env transform (uppercase, `-`→`_`).
refresh_token() {
  [[ -n "${HORT_TOKEN_REFRESH_CMD:-}" ]] || return 0
  local fresh b64 key_var
  fresh="$(bash -c "${HORT_TOKEN_REFRESH_CMD}")"
  if [[ -z "${fresh}" ]]; then
    echo "error: HORT_TOKEN_REFRESH_CMD produced an empty token" >&2
    return 1
  fi
  b64="$(printf 'x:%s' "${fresh}" | base64 -w0)"
  if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
    echo "::add-mask::${fresh}"
    echo "::add-mask::${b64}"
  fi
  export HORT_TOKEN="${fresh}"
  key_var="CARGO_REGISTRIES_$(printf '%s' "${repo_key}" | tr '[:lower:]-' '[:upper:]_')_TOKEN"
  export "${key_var}=Basic ${b64}"
  export CARGO_REGISTRIES_HORT_TOKEN="Basic ${b64}"
}

publish_crate() {
  local crate_path="$1"
  refresh_token
  echo "Publishing ${crate_path} ..."
  cargo publish \
    --no-verify \
    --registry "${repo_key}" \
    --manifest-path "${crate_path}/Cargo.toml"
  # Allow the sparse index to propagate the new entry before the next
  # dependent crate's publish resolves it.
  sleep "${propagation_sleep}"
}

order="$("${script_dir}/publishable-crates-in-order.sh")"
echo "Publish order (derived from the workspace manifests):"
echo "${order}" | awk -F'\t' '{ printf "  %s (%s %s)\n", $1, $2, $3 }'

published=0
skipped=0
while IFS=$'\t' read -r crate_path name version; do
  if "${script_dir}/crate-version-in-index.sh" \
       "${hort_url}" "${repo_key}" "${name}" "${version}"; then
    echo "Skipping ${crate_path} — ${name} ${version} is already published."
    skipped=$((skipped + 1))
    continue
  fi
  publish_crate "${crate_path}"
  published=$((published + 1))
done <<< "${order}"

echo "Publish complete — ${published} uploaded, ${skipped} already present."
