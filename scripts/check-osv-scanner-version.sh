#!/usr/bin/env bash
#
# scripts/check-osv-scanner-version.sh — osv-scanner version lockstep gate.
#
# Asserts that the two independent osv-scanner version pins stay identical:
#
#   1. `docker/Dockerfile.worker` `ARG OSV_SCANNER_VERSION=...` — the version
#      baked into the worker container; the version the osv adapter
#      (`hort-adapters-scanner-osv`) is built and tested against.
#   2. `deploy/ansible/roles/hort_systemd/defaults/main.yml`
#      `hort_systemd_osv_version: "..."` — the version the native (non-k8s)
#      deploy downloads and installs on the host.
#
# Why this matters: the osv adapter invokes the v2 CLI
# (`osv-scanner scan source --format json --sbom <path>`). A v1.x binary has
# no `scan source` subcommand, so every scan exits non-zero, no artifact ever
# earns release authority, and the pull-through registry serves nothing
# (everything quarantines forever). Drift between the container pin (moved to
# v2) and the native pin (left on v1.9.1) is exactly that failure, and it is
# invisible to `helm template`, `cargo build`, and the Ansible lint — only a
# lint like this catches it.
#
# Comparison is EXACT (full version): the native binary must be the same
# osv-scanner the adapter was tested against, so even a patch difference is a
# drift worth flagging.
#
# Run by:
#   - the GitLab `quality:chart-and-rust-pin-sync` job
#   - locally before pushing changes to either file
#
# No external TOML/YAML/Dockerfile parser — both inputs are tiny and regular;
# bash + grep is enough and avoids enlarging the supply chain for one lint.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
dockerfile="${repo_root}/docker/Dockerfile.worker"
role_defaults="${repo_root}/deploy/ansible/roles/hort_systemd/defaults/main.yml"

for f in "${dockerfile}" "${role_defaults}"; do
    if [[ ! -f "$f" ]]; then
        echo "error: $f not found" >&2
        exit 2
    fi
done

# `ARG OSV_SCANNER_VERSION=2.3.8` → 2.3.8
dockerfile_pin=$(
    grep -E '^ARG[[:space:]]+OSV_SCANNER_VERSION[[:space:]]*=' "${dockerfile}" \
        | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' \
        | head -n1
)

# `hort_systemd_osv_version: "2.3.8"` → 2.3.8
role_pin=$(
    grep -E '^[[:space:]]*hort_systemd_osv_version[[:space:]]*:' "${role_defaults}" \
        | grep -oE '"[0-9]+\.[0-9]+(\.[0-9]+)?"' \
        | tr -d '"' \
        | head -n1
)

if [[ -z "${dockerfile_pin}" ]]; then
    echo "error: could not extract ARG OSV_SCANNER_VERSION default from ${dockerfile}" >&2
    exit 2
fi
if [[ -z "${role_pin}" ]]; then
    echo "error: could not extract hort_systemd_osv_version from ${role_defaults}" >&2
    exit 2
fi

if [[ "${dockerfile_pin}" == "${role_pin}" ]]; then
    echo "osv-scanner pin sync: OK (Dockerfile.worker=${dockerfile_pin}, hort_systemd_osv_version=${role_pin})"
    exit 0
fi

echo "osv-scanner version pin mismatch:" >&2
printf '  %-52s = %s\n' "docker/Dockerfile.worker ARG OSV_SCANNER_VERSION" "${dockerfile_pin}" >&2
printf '  %-52s = %s\n' "hort_systemd/defaults hort_systemd_osv_version" "${role_pin}" >&2
echo "" >&2
echo "Set both to the same osv-scanner release. The osv adapter uses the v2" >&2
echo "'scan source' CLI; a native binary on a different (especially v1.x)" >&2
echo "version fails every scan and strands all proxied artifacts in quarantine." >&2
exit 1
