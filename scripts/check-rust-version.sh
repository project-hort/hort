#!/usr/bin/env bash
#
# scripts/check-rust-version.sh — Rust toolchain version lockstep gate.
#
# Asserts that three independent Rust-toolchain declarations stay in
# lockstep at the minor-version level:
#
#   1. `Cargo.toml` `[workspace.package].rust-version` — the workspace
#      MSRV. Source of truth (also referenced by `.clippy.toml`'s
#      `msrv` key).
#   2. `docker/Dockerfile.hort-server` `ARG RUST_VERSION=...` — the
#      production container's builder image pin.
#   3. `rust-toolchain.toml` `[toolchain].channel` — the per-checkout
#      rustup pin every local developer + CI workflow auto-honors.
#
# Drift between any two is silent in `cargo audit`, invisible in
# normal `cargo build` output (the project just runs against whichever
# toolchain wins the override race), and only catchable by a CI lint
# like this one. The gap that motivated extending the check from a
# 2-way to a 3-way comparison was real: between 2026-05-10 17:42 and
# 17:45, two commits 3 minutes apart added `rust-toolchain.toml`
# pinning 1.88 and then bumped Cargo+Dockerfile to 1.94 — leaving
# rust-toolchain.toml silently downgrading every developer to 1.88
# until alpha-testing-runbook setup surfaced it 15 days later.
#
# Comparison is at MAJOR.MINOR level: a Cargo MSRV of "1.94" matches
# a toolchain pin of "1.94.0" matches a Dockerfile pin of "1.94". A
# patch-level mismatch (e.g. "1.94.0" vs "1.94.1") is tolerated —
# patches are implementation detail, not part of the MSRV contract.
# A minor-level mismatch (e.g. "1.93" vs "1.94") is the failure.
#
# Run by:
#   - the `build-images` GitLab pipeline stage
#   - locally before pushing changes to any of the three files
#
# No external TOML / Dockerfile parser. All three inputs are tiny and
# regular; bash + grep is enough and avoids enlarging the supply
# chain just for one lint.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cargo_toml="${repo_root}/Cargo.toml"
dockerfile="${repo_root}/docker/Dockerfile.hort-server"
toolchain_toml="${repo_root}/rust-toolchain.toml"

for f in "${cargo_toml}" "${dockerfile}" "${toolchain_toml}"; do
    if [[ ! -f "$f" ]]; then
        echo "error: $f not found" >&2
        exit 2
    fi
done

# Normalise an `X.Y(.Z)?` version string to its MAJOR.MINOR prefix.
# A Cargo MSRV of "1.94" and a toolchain pin of "1.94.0" both
# normalise to "1.94"; "1.94.1" also normalises to "1.94" (patch is
# implementation detail). Drift at the minor level is the failure
# mode we catch.
normalize_minor() {
    echo "$1" | cut -d. -f1,2
}

# Extract `rust-version = "X.Y(.Z)?"` from `[workspace.package]`.
# The pattern matches the right-hand side without quotes; head -n1
# guards against accidental duplicates (cargo would already reject
# them, but the script should not silently pick the second).
cargo_pin=$(
    grep -E '^[[:space:]]*rust-version[[:space:]]*=' "${cargo_toml}" \
        | grep -oE '"[0-9]+\.[0-9]+(\.[0-9]+)?"' \
        | tr -d '"' \
        | head -n1
)

# Extract the default value of `ARG RUST_VERSION=...` from the
# Dockerfile. Same regex shape as the cargo extraction so the values
# are directly comparable.
dockerfile_pin=$(
    grep -E '^ARG[[:space:]]+RUST_VERSION[[:space:]]*=' "${dockerfile}" \
        | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' \
        | head -n1
)

# Extract `channel = "X.Y(.Z)?"` from `[toolchain]`. The file is
# small enough that we don't strictly need the section-anchor — the
# only `channel = ...` line in a well-formed rust-toolchain.toml is
# the one under `[toolchain]`. head -n1 still defends against
# accidental duplicates.
toolchain_pin=$(
    grep -E '^[[:space:]]*channel[[:space:]]*=' "${toolchain_toml}" \
        | grep -oE '"[0-9]+\.[0-9]+(\.[0-9]+)?"' \
        | tr -d '"' \
        | head -n1
)

if [[ -z "${cargo_pin}" ]]; then
    echo "error: could not extract rust-version from ${cargo_toml}" >&2
    exit 2
fi
if [[ -z "${dockerfile_pin}" ]]; then
    echo "error: could not extract ARG RUST_VERSION default from ${dockerfile}" >&2
    exit 2
fi
if [[ -z "${toolchain_pin}" ]]; then
    echo "error: could not extract channel from ${toolchain_toml}" >&2
    exit 2
fi

cargo_mm=$(normalize_minor "${cargo_pin}")
dockerfile_mm=$(normalize_minor "${dockerfile_pin}")
toolchain_mm=$(normalize_minor "${toolchain_pin}")

if [[ "${cargo_mm}" == "${dockerfile_mm}" && "${cargo_mm}" == "${toolchain_mm}" ]]; then
    echo "Rust toolchain pin sync: OK (Cargo.toml=${cargo_pin}, Dockerfile.hort-server=${dockerfile_pin}, rust-toolchain.toml=${toolchain_pin})"
    exit 0
fi

echo "Rust toolchain pin mismatch (compared at MAJOR.MINOR level):" >&2
printf '  %-40s = %s  (normalised: %s)\n' "Cargo.toml [workspace.package].rust-version" "${cargo_pin}" "${cargo_mm}" >&2
printf '  %-40s = %s  (normalised: %s)\n' "docker/Dockerfile.hort-server ARG RUST_VERSION" "${dockerfile_pin}" "${dockerfile_mm}" >&2
printf '  %-40s = %s  (normalised: %s)\n' "rust-toolchain.toml [toolchain].channel" "${toolchain_pin}" "${toolchain_mm}" >&2
echo "" >&2
echo "Update all three so they match at MAJOR.MINOR. Cargo.toml's pin is" >&2
echo "the source of truth (workspace MSRV, also referenced by" >&2
echo ".clippy.toml); the Dockerfile's ARG default and the rust-toolchain.toml" >&2
echo "channel both track it." >&2
exit 1
