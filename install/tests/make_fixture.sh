#!/bin/sh
# install/tests/make_fixture.sh — builds a fake release tree + releases JSON under $1
# for the CURRENT platform (so the installer's detect_platform finds a matching asset).
# Everything is staged under $1; nothing is written to /tmp (parallel-safe, self-cleaning).
set -eu
root="$1"
rel="$root/releases/download/v9.9.9-beta.1"
mkdir -p "$rel" "$root/repos/project-hort/hort"

# Asset name for THIS platform — mirrors install.sh detect_platform().
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$os" in linux) os=linux ;; darwin) os=darwin ;; *) echo "make_fixture: unsupported OS $os" >&2; exit 1 ;; esac
arch="$(uname -m)"
case "$arch" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) echo "make_fixture: unsupported arch $arch" >&2; exit 1 ;; esac
asset="hort-cli-${os}-${arch}"

# Fake binary, packed as the expected archive name (staged under $root).
printf 'fake-binary\n' > "$root/$asset"
( cd "$root" && tar -czf "$rel/${asset}.tar.gz" "$asset" )
rm -f "$root/$asset"

# Portable SHA-256 sidecar (bare archive name so `sha -c` resolves it from cwd).
( cd "$rel" \
    && if command -v sha256sum >/dev/null 2>&1; then sha256sum "${asset}.tar.gz" > "${asset}.tar.gz.sha256"
       else shasum -a 256 "${asset}.tar.gz" > "${asset}.tar.gz.sha256"; fi )

# Empty bundle (cosign is stubbed in tests).
: > "$rel/${asset}.tar.gz.bundle"

# GitHub-style releases API response (array, first entry wins).
printf '[{"tag_name":"v9.9.9-beta.1","prerelease":true}]\n' > "$root/repos/project-hort/hort/releases"
