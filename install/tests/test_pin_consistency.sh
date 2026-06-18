#!/bin/sh
# Anti-drift guard: installer verify params must match the canonical how-to; cosign pin >= v3.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
root="$here/.."
howto="$root/../docs/architecture/how-to/release-verification.md"
fail=0
check() { grep -qF "$1" "$2" || { echo "DRIFT: '$1' missing from $2"; fail=1; }; }
# identity regexp + issuer must be present, verbatim, in BOTH scripts
for f in "$root/install-cli.sh" "$root/install-cli.ps1"; do
  check 'https://github.com/project-hort/.*' "$f"
  check 'https://token.actions.githubusercontent.com' "$f"
done
# and the canonical how-to must carry the same identity regexp
check 'project-hort/.*' "$howto"
# cosign pin must be >= v3
grep -qE '^COSIGN_VERSION=v[3-9]' "$root/cosign.pin" || { echo "DRIFT: cosign.pin COSIGN_VERSION is not >= v3"; fail=1; }
if [ "$fail" = 0 ]; then echo "PASS: pin/identity consistency"; else exit 1; fi
