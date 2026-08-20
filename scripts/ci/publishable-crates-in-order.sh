#!/usr/bin/env bash
#
# scripts/ci/publishable-crates-in-order.sh — derive the published crate
# set and its publish order from the workspace manifests.
#
# Usage: scripts/ci/publishable-crates-in-order.sh [workspace-root]
#   (default: the repo root inferred from this script's location)
#
# Prints one crate directory per line, relative to the workspace root, in
# an order where every crate's intra-workspace dependencies come before it
# — the order `cargo publish` requires, since each crate resolves its
# dependencies through the registry and a dependency has to be indexed
# before its dependent is uploaded.
#
# The set is whatever `[package] publish` says: a member is published
# unless its manifest sets `publish = false`. Nothing here is
# hand-maintained, so neither the set nor the order can drift from the
# manifests the way a comment in the release workflow did.
#
# Two conditions are hard errors rather than silent output, because both
# produce a release that fails partway through with some crates already
# uploaded and unwithdrawable:
#
#   * a published crate depending on an unpublished workspace member —
#     the published manifest keeps that dependency (optional ones
#     included) and nothing in the registry can satisfy it;
#   * a dependency cycle among published crates — no order exists.
#
# `--no-deps` keeps this to a manifest read: cargo performs no dependency
# resolution and touches no registry index, so the script is safe to run
# in a job that has already activated source replacement.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="${1:-$(cd "${script_dir}/../.." && pwd)}"

if [[ ! -f "${root}/Cargo.toml" ]]; then
  echo "error: ${root}/Cargo.toml not found" >&2
  exit 2
fi

# One record per workspace member:
#   <name> <TAB> <dir-relative-to-root> <TAB> <published:0|1> <TAB> <space-separated intra-workspace deps>
#
# Dev-dependencies are excluded: cargo drops a path-only dev dependency
# from the published manifest entirely, so it constrains neither the set
# nor the order. Optional and build dependencies are included — both are
# retained in the published manifest and must resolve.
members="$(
  cargo metadata --format-version 1 --no-deps --manifest-path "${root}/Cargo.toml" \
  | jq -r --arg root "${root}/" '
      [.packages[] | .name] as $members
      | .packages[]
      | . as $pkg
      | [
          $pkg.name,
          ($pkg.manifest_path | sub("^" + $root; "") | sub("/Cargo\\.toml$"; "")),
          (if $pkg.publish == [] then "0" else "1" end),
          ([ $pkg.dependencies[]
             | select(.kind != "dev")
             | .name
             | select(IN($members[]))
           ] | unique | join(" "))
        ]
      | @tsv
    '
)"

declare -A dir_of published_of deps_of
while IFS=$'\t' read -r name dir published deps; do
  dir_of["${name}"]="${dir}"
  published_of["${name}"]="${published}"
  deps_of["${name}"]="${deps}"
done <<< "${members}"

# Dependency closure. Checked before ordering so the message names the
# offending edge rather than an unresolvable graph.
violations=()
for name in "${!published_of[@]}"; do
  [[ "${published_of[${name}]}" == "1" ]] || continue
  for dep in ${deps_of[${name}]}; do
    if [[ "${published_of[${dep}]}" == "0" ]]; then
      violations+=("${name} -> ${dep}")
    fi
  done
done
if [[ ${#violations[@]} -gt 0 ]]; then
  {
    echo "error: published crates depend on members marked \`publish = false\`."
    echo "       The published manifest keeps the dependency and the registry cannot satisfy it."
    echo "       Publish the dependency too, or remove the edge:"
    printf '         %s\n' "${violations[@]}"
  } >&2
  exit 1
fi

# Kahn's algorithm, emitting ready crates in name order so the output is
# byte-identical across runs.
declare -A emitted
remaining=()
for name in "${!published_of[@]}"; do
  [[ "${published_of[${name}]}" == "1" ]] && remaining+=("${name}")
done

while [[ ${#remaining[@]} -gt 0 ]]; do
  ready=()
  for name in $(printf '%s\n' "${remaining[@]}" | sort); do
    blocked=0
    for dep in ${deps_of[${name}]}; do
      # Only published dependencies constrain the order; the closure check
      # above has already established there are no unpublished ones.
      if [[ "${published_of[${dep}]}" == "1" && -z "${emitted[${dep}]:-}" ]]; then
        blocked=1
        break
      fi
    done
    [[ ${blocked} -eq 0 ]] && ready+=("${name}")
  done

  if [[ ${#ready[@]} -eq 0 ]]; then
    {
      echo "error: dependency cycle among published crates — no publish order exists."
      echo "       Unresolved:"
      printf '         %s\n' "${remaining[@]}"
    } >&2
    exit 1
  fi

  for name in "${ready[@]}"; do
    emitted["${name}"]=1
    echo "${dir_of[${name}]}"
  done

  next=()
  for name in "${remaining[@]}"; do
    [[ -z "${emitted[${name}]:-}" ]] && next+=("${name}")
  done
  remaining=("${next[@]+"${next[@]}"}")
done
