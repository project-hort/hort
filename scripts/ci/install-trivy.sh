#!/usr/bin/env bash
# Install the Trivy CLI at the version this repository already pins.
#
# The pin lives in exactly ONE place — `docker/Dockerfile.worker`'s
# `ARG TRIVY_VERSION` and its per-arch `ARG TRIVY_SHA256_*` — because the
# worker image ships that same binary as its scan backend. This script READS
# that pin rather than restating it: a second copy of a version number is a
# copy that drifts, and a CI gate running a different scanner than the product
# ships is a gate whose verdict nobody can reproduce against a release.
#
# The tarball is checksum-verified before anything is installed, which is the
# rule the Dockerfile stage states for itself: an external download is verified
# against a value pinned at the call site, never trusted on transport alone. A
# silently-substituted scanner binary changes the verdict a gate publishes.
#
# Idempotent: a `trivy` already on PATH at the pinned version is a no-op, so
# repeated calls inside one job cost nothing.
#
# Inputs (all optional):
#   TRIVY_INSTALL_DIR   where to install (default /usr/local/bin)
#
# Requires: curl, tar, sha256sum.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
dockerfile="${root}/docker/Dockerfile.worker"
install_dir="${TRIVY_INSTALL_DIR:-/usr/local/bin}"

if [[ ! -r "${dockerfile}" ]]; then
    echo "install-trivy: cannot read the version pin: ${dockerfile} is missing" >&2
    exit 1
fi

# Read one `ARG <name>=<value>` line. A pin that cannot be read is fatal on
# purpose: continuing with a default would install an unpinned scanner, and
# "the ARG was renamed" has to surface here rather than as a mystery verdict.
read_pinned_arg() {
    local name="$1" value=""
    # No `| head`: under `set -o pipefail` a reader that exits first can turn
    # the producer's SIGPIPE into the pipeline's status. Take the first match
    # in the shell instead.
    value="$(sed -n "s/^ARG ${name}=\\([^[:space:]]*\\)[[:space:]]*\$/\\1/p" "${dockerfile}")"
    value="${value%%$'\n'*}"
    if [[ -z "${value}" ]]; then
        echo "install-trivy: no 'ARG ${name}=' in ${dockerfile#"${root}/"} — the pin this script reads has moved or been renamed" >&2
        exit 1
    fi
    printf '%s' "${value}"
}

version="$(read_pinned_arg TRIVY_VERSION)"

# Aqua Security's release asset names are not the arch strings uname reports,
# and each arch has its own pinned checksum — map both from one case.
machine="$(uname -m)"
case "${machine}" in
    x86_64)        asset="Linux-64bit"; sha256="$(read_pinned_arg TRIVY_SHA256_AMD64)" ;;
    aarch64|arm64) asset="Linux-ARM64"; sha256="$(read_pinned_arg TRIVY_SHA256_ARM64)" ;;
    *)
        echo "install-trivy: unsupported machine '${machine}' (the pinned checksums cover amd64 and arm64)" >&2
        exit 1
        ;;
esac

# Already installed at the pinned version? `trivy --version` prints
# "Version: <x.y.z>" first. Match the FILE, never a pipe into grep -q.
if command -v trivy > /dev/null 2>&1; then
    probe="$(mktemp)"
    trivy --version > "${probe}" 2>&1 || true
    if grep -qxF "Version: ${version}" "${probe}"; then
        echo "install-trivy: trivy ${version} already present at $(command -v trivy) — no-op"
        rm -f -- "${probe}"
        exit 0
    fi
    echo "install-trivy: replacing $(head -n 1 "${probe}") with the pinned ${version}"
    rm -f -- "${probe}"
fi

# The upstream asset is a .tar.gz and `tar` is not guaranteed in every job
# image this runs in (the buildah image ships curl and coreutils, which the
# cosign setup already relies on, but tar is a separate package). Bootstrap it
# the way .gitlab/ci/cosign-setup.sh bootstraps jq — try each package manager,
# then fail with a readable message rather than an opaque "tar: not found" from
# inside a security gate that blocks the release path.
if ! command -v tar > /dev/null 2>&1; then
    echo "install-trivy: tar is absent — installing it"
    dnf install -y -q tar 2> /dev/null ||
        apk add --no-cache tar 2> /dev/null ||
        { apt-get update -qq && apt-get install -y -qq tar; } 2> /dev/null ||
        true
fi
if ! command -v tar > /dev/null 2>&1; then
    echo "install-trivy: tar is absent and could not be installed; the Trivy release asset is a .tar.gz and cannot be unpacked." >&2
    exit 1
fi

workdir="$(mktemp -d)"
trap 'rm -rf -- "${workdir}"' EXIT

url="https://github.com/aquasecurity/trivy/releases/download/v${version}/trivy_${version}_${asset}.tar.gz"
echo "install-trivy: fetching ${url}"
if ! curl -fsSL --connect-timeout 15 --max-time 300 "${url}" -o "${workdir}/trivy.tar.gz"; then
    echo "install-trivy: download failed — this is the scan failing to install, not a CVE verdict." >&2
    echo "install-trivy: the job needs HTTPS egress to github.com (the same reach cosign-setup.sh already uses)." >&2
    exit 1
fi

echo "${sha256}  ${workdir}/trivy.tar.gz" > "${workdir}/trivy.sha256"
if ! sha256sum -c "${workdir}/trivy.sha256"; then
    echo "install-trivy: checksum mismatch against the pin in ${dockerfile#"${root}/"}." >&2
    echo "install-trivy: either the pinned checksum is stale for ${version}, or the bytes are not the bytes the product ships." >&2
    exit 1
fi

tar -xzf "${workdir}/trivy.tar.gz" -C "${workdir}" trivy
install -m 0755 "${workdir}/trivy" "${install_dir}/trivy"
installed="$(mktemp)"
"${install_dir}/trivy" --version > "${installed}" 2>&1 || true
echo "install-trivy: installed $(sed -n '1p' "${installed}") at ${install_dir}/trivy"
rm -f -- "${installed}"
