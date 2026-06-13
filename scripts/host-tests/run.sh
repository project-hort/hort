#!/usr/bin/env bash
# shellcheck shell=bash
# Host-side runner for scripts/host-tests/.
#
# Runs each test-*.sh in sequence on the host (NOT containerized).
# Each script manages its own stack lifecycle; this runner just invokes them.
#
# Exit codes:
#   0 — all scripts passed (or skipped)
#   1 — at least one script failed
#
# Usage:
#   bash scripts/host-tests/run.sh [--list]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Collect test scripts in a stable order.
mapfile -t SCRIPTS < <(find "$SCRIPT_DIR" -maxdepth 1 -name 'test-*.sh' | sort)

# --list: just print the scripts and exit.
if [[ "${1:-}" == "--list" ]]; then
    for s in "${SCRIPTS[@]}"; do
        echo "$(basename "$s")"
    done
    exit 0
fi

pass=0
skip=0
fail=0

for script in "${SCRIPTS[@]}"; do
    name="$(basename "$script")"
    set +e
    bash "$script"
    rc=$?
    set -e
    if [[ $rc -eq 0 ]]; then
        echo "PASS  $name"
        (( pass += 1 )) || true
    elif [[ $rc -eq 2 ]]; then
        echo "SKIP  $name"
        (( skip += 1 )) || true
    else
        echo "FAIL  $name  (exit $rc)"
        (( fail += 1 )) || true
    fi
done

echo ""
echo "Results: ${pass} passed, ${skip} skipped, ${fail} failed"

if [[ $fail -gt 0 ]]; then
    exit 1
fi
