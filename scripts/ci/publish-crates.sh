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

publish_crate() {
  local crate_path="$1"
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
