#!/usr/bin/env bash
#
# scripts/ci/lib-cargo-sparse-index.sh — shared cargo sparse-index helpers.
#
# SOURCE this file; do not execute it. It defines functions and sets no
# options, so it inherits the caller's `set -euo pipefail`:
#
#   source "$(dirname "${BASH_SOURCE[0]}")/lib-cargo-sparse-index.sh"
#
# Every script that addresses a crate in a sparse index needs the same
# prefix rule, and a second copy of it is a silent-drift hazard: a wrong
# path yields a 404, which reads exactly like "this version is not
# published" — the answer both callers are asking for. One definition
# means one place to be right.

# Sparse-index path for a crate name (RFC 2789), lowercased:
#
#   1 char  -> 1/{n}
#   2 chars -> 2/{n}
#   3 chars -> 3/{n[0]}/{n}
#   else    -> {n[0:2]}/{n[2:4]}/{n}
#
# Prints the path with no leading or trailing slash.
cargo_sparse_index_path() {
  local n len
  n=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  len=${#n}
  if [ "${len}" -eq 1 ]; then
    printf '1/%s' "${n}"
  elif [ "${len}" -eq 2 ]; then
    printf '2/%s' "${n}"
  elif [ "${len}" -eq 3 ]; then
    printf '3/%s/%s' "${n:0:1}" "${n}"
  else
    printf '%s/%s/%s' "${n:0:2}" "${n:2:2}" "${n}"
  fi
}
