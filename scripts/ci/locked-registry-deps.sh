#!/usr/bin/env bash
#
# scripts/ci/locked-registry-deps.sh — enumerate the LOCKED registry deps.
#
# Usage: scripts/ci/locked-registry-deps.sh [path/to/Cargo.lock]
#   (default: Cargo.lock at the repo root)
#
# Prints one "name version" pair per line, one per [[package]] block whose
# `source` is a registry (`registry+...`). Path-dep workspace members have no
# `source` line at all and are correctly skipped.
#
# Deliberately does NOT use `cargo metadata`: a caller that has already
# activated source replacement (hort-auth wrote .cargo/config.toml before
# this runs) would have `cargo metadata` resolve through the very vetted
# index this preflight exists to check — hitting the same serial one-miss
# failure the preflight replaces. Parsing Cargo.lock directly sidesteps
# that entirely; no cargo invocation, no index.
#
# Single implementation, shared by .github/workflows/release.yml's preflight
# step and the GitLab `prefetch:warm` / `prefetch:verify` jobs.

set -euo pipefail

lockfile="${1:-Cargo.lock}"

if [[ ! -f "${lockfile}" ]]; then
  echo "error: ${lockfile} not found" >&2
  exit 2
fi

# Cargo.lock has no trailing blank line after the LAST [[package]] block, so
# the per-block flush on the next `[[package]]` marker never fires for it —
# the END block flushes that final pending record.
awk '
  /^\[\[package\]\]$/ {
    if (name != "" && source ~ /^registry\+/) print name, version
    name = ""; version = ""; source = ""
    next
  }
  /^name = / { name = $0; sub(/^name = "/, "", name); sub(/"$/, "", name); next }
  /^version = / { version = $0; sub(/^version = "/, "", version); sub(/"$/, "", version); next }
  /^source = / { source = $0; sub(/^source = "/, "", source); sub(/"$/, "", source); next }
  END {
    if (name != "" && source ~ /^registry\+/) print name, version
  }
' "${lockfile}"
