#!/usr/bin/env bash
#
# scripts/populate-dl-archive.sh — populate hort.rs's permanent /dl/ version
# archive (issue #77).
#
# For each published (non-draft) `v*` GitHub release, downloads the
# hort-cli-* assets into `<dl_root>/<tag>/` — but ONLY if that directory
# does not already exist. Once a tag is populated it is never re-fetched,
# re-verified, or overwritten (append-only / immutable — the design
# contract in backlog/050). Every asset is verified (SHA-256 + cosign
# signature) BEFORE being placed: downloads land in a temporary staging
# directory first, and only a directory whose every asset verified cleanly
# is renamed into `<dl_root>/<tag>/` — a verification failure never leaves
# a partially-populated, half-trusted tag directory behind (fail-closed
# backfill, matching install-cli.sh's own "verify before install, nothing
# on failure" posture).
#
# Regenerates `<dl_root>/index.html` (a static, newest-first version index)
# at the end, listing every tag present in `<dl_root>` — both freshly
# populated ones and ones already there from a prior run. This overwrites
# the placeholder `dl/index.html` scripts/build-site.sh's hort.rs build
# writes (see scripts/site/generate.py::write_dl_placeholder for why that
# placeholder exists — this script's real index is what a deployed host
# actually serves once it has run at least once).
#
# Cosign verify-blob parameters mirror install/install-cli.sh's
# `cosign_verify` exactly (also documented in install/README.md's "Verify
# parameters" table) — a binary this script would place must pass the
# identical check the installer itself runs.
#
# Requires: curl, jq, sha256sum (or shasum), and — unless --dry-run — a
# trusted `cosign` (>= v3.0, matching install/cosign.pin's pinned version)
# already on PATH. Unlike install-cli.sh, this script does NOT bootstrap
# cosign itself: it runs on an operator-controlled deploy host, not an
# arbitrary end-user machine, so requiring a pre-installed, operator-vetted
# cosign is the simpler and equally safe choice — see
# deploy/ansible/roles/website/README (or its task comments) for the
# operator-facing prerequisite note.
#
# Usage:
#   scripts/populate-dl-archive.sh <dl_root> [--dry-run]
#
# --dry-run: reports which tags are missing from <dl_root> (i.e. would be
# downloaded) without touching the network for asset content or writing
# anything — safe to run with no cosign installed and (aside from the one
# releases-list API call) without real release assets present.

set -euo pipefail

GH_REPO="project-hort/hort"
API="${HORT_API:-https://api.github.com}"
DL_BASE="https://github.com/${GH_REPO}/releases/download"
# Mirrors install/install-cli.sh's COSIGN_IDENTITY_REGEXP / COSIGN_OIDC_ISSUER.
COSIGN_IDENTITY_REGEXP='https://github.com/project-hort/.*'
COSIGN_OIDC_ISSUER='https://token.actions.githubusercontent.com'
# Mirrors .github/workflows/build-binaries.yml's release matrix for the
# hort-cli binary specifically (hort-server/hort-worker are not part of
# this archive — backlog/050 scopes /dl/ to "the CLI release archives").
PLATFORMS_TAR="linux-amd64 linux-arm64 darwin-amd64 darwin-arm64"
PLATFORMS_EXE="windows-amd64"

usage() {
  cat <<'EOF'
Usage: populate-dl-archive.sh <dl_root> [--dry-run]

  <dl_root>   directory to populate (e.g. /var/www/hort.rs/dl)
  --dry-run   report missing tags only; no network fetch of assets, no writes
EOF
}

if [ $# -lt 1 ] || [ "$1" = "--help" ]; then
  usage
  exit "$([ "${1:-}" = "--help" ] && echo 0 || echo 1)"
fi
DL_ROOT="$1"
shift
DRY_RUN=0
if [ "${1:-}" = "--dry-run" ]; then DRY_RUN=1; fi

command -v curl >/dev/null 2>&1 || { echo "error: curl is required" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "error: jq is required" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then
  SHA="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SHA="shasum -a 256"
else
  echo "error: sha256sum or shasum is required" >&2
  exit 1
fi
if [ "$DRY_RUN" -eq 0 ]; then
  command -v cosign >/dev/null 2>&1 || {
    echo "error: cosign is required (see install/cosign.pin for the pinned version this repo trusts; pass --dry-run to skip this check)" >&2
    exit 1
  }
fi

mkdir -p "$DL_ROOT"

api_get() {
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" "$1"
  else
    curl -fsSL "$1"
  fi
}

echo "==> Listing published releases for ${GH_REPO}"
TAGS=()
page=1
while :; do
  resp="$(api_get "${API}/repos/${GH_REPO}/releases?per_page=100&page=${page}")"
  count="$(printf '%s' "$resp" | jq 'length')"
  [ "$count" -eq 0 ] && break
  while IFS= read -r tag; do
    TAGS+=("$tag")
  done < <(printf '%s' "$resp" | jq -r '.[] | select(.draft == false) | .tag_name')
  page=$((page + 1))
done
echo "  found ${#TAGS[@]} published release(s)"

asset_names() {
  # Emits the expected hort-cli asset filenames for one release (the
  # archive/exe itself; .sha256 and .bundle sidecars are fetched
  # alongside each in verify_and_stage).
  local p
  for p in $PLATFORMS_TAR; do printf 'hort-cli-%s.tar.gz\n' "$p"; done
  for p in $PLATFORMS_EXE; do printf 'hort-cli-%s.exe\n' "$p"; done
}

# verify_and_stage <tag> <staging-dir> — downloads + verifies every asset
# for <tag> into <staging-dir>. Returns non-zero (aborting the tag) on any
# verification failure; a missing asset for a platform that release didn't
# ship is a WARNING (older releases may not cover every platform), not a
# failure — only a present-but-unverifiable asset fails the tag. Sets
# VERIFIED_COUNT (a plain, non-local assignment so the caller can read it)
# to the number of assets that actually verified, so a release with ZERO
# hort-cli assets at all (pre-dates the CLI being part of the release
# matrix) can be told apart from one that genuinely verified.
verify_and_stage() {
  local tag="$1" staging="$2" base="${DL_BASE}/${tag}" asset
  VERIFIED_COUNT=0
  while IFS= read -r asset; do
    if ! curl -fsSL "${base}/${asset}" -o "${staging}/${asset}" 2>/dev/null; then
      echo "    note: ${asset} not published for ${tag} (skipping this platform)"
      rm -f "${staging}/${asset}"
      continue
    fi
    echo "    fetched ${asset}"
    if ! curl -fsSL "${base}/${asset}.sha256" -o "${staging}/${asset}.sha256" 2>/dev/null; then
      echo "    ERROR: ${asset} present but its .sha256 is missing — aborting ${tag}" >&2
      return 1
    fi
    if ! curl -fsSL "${base}/${asset}.bundle" -o "${staging}/${asset}.bundle" 2>/dev/null; then
      echo "    ERROR: ${asset} present but its .bundle is missing — aborting ${tag}" >&2
      return 1
    fi
    if ! ( cd "$staging" && $SHA -c "${asset}.sha256" >/dev/null 2>&1 ); then
      echo "    ERROR: SHA-256 verification failed for ${asset} — aborting ${tag}" >&2
      return 1
    fi
    if ! cosign verify-blob \
        --certificate-oidc-issuer="$COSIGN_OIDC_ISSUER" \
        --certificate-identity-regexp="$COSIGN_IDENTITY_REGEXP" \
        --bundle "${staging}/${asset}.bundle" "${staging}/${asset}" >/dev/null 2>&1; then
      echo "    ERROR: cosign verification failed for ${asset} — aborting ${tag}" >&2
      return 1
    fi
    echo "    verified ${asset} (sha256 + cosign)"
    VERIFIED_COUNT=$((VERIFIED_COUNT + 1))
  done < <(asset_names)
}

new_count=0
skipped_existing=0
for tag in "${TAGS[@]}"; do
  if [ -d "${DL_ROOT}/${tag}" ]; then
    skipped_existing=$((skipped_existing + 1))
    continue
  fi
  echo "==> ${tag}: not yet archived"
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "  (dry-run) would download + verify + place ${tag}"
    continue
  fi
  staging="$(mktemp -d)"
  if verify_and_stage "$tag" "$staging"; then
    if [ "$VERIFIED_COUNT" -eq 0 ]; then
      # No hort-cli assets exist for this tag at all (pre-dates the CLI
      # joining the release matrix) -- nothing to archive. Do NOT place an
      # empty dl/<tag>/: it would show up in the version index pointing at
      # nothing downloadable. Not placing it also means a future run can
      # re-check it (cheap: a handful of 404s) in case that ever changes,
      # rather than an immutable empty placeholder freezing the gap forever.
      rmdir "$staging" 2>/dev/null || rm -rf "$staging"
      echo "  ${tag}: no hort-cli assets published for this release — skipped (not placed)"
      continue
    fi
    # Atomic placement: a directory whose every asset verified is renamed
    # into place in one step — no reader (or re-run of this script) ever
    # observes a partially-populated dl/<tag>/.
    mv "$staging" "${DL_ROOT}/${tag}"
    new_count=$((new_count + 1))
    echo "  ${tag}: verified and placed (${VERIFIED_COUNT} asset(s))"
  else
    echo "  ${tag}: verification FAILED — NOT placed (staging left at ${staging} for inspection)" >&2
  fi
done
echo "==> ${new_count} new version(s) populated, ${skipped_existing} already present (untouched)"

if [ "$DRY_RUN" -eq 1 ]; then
  echo "(dry-run: skipping index regeneration)"
  exit 0
fi

echo "==> Regenerating ${DL_ROOT}/index.html"
{
  printf '<!doctype html><html lang="en"><head><meta charset="utf-8">'
  printf '<title>hort-cli downloads — hort.rs</title>'
  printf '<link rel="stylesheet" href="../assets/style.css"></head><body>'
  printf '<h1>hort-cli release archive</h1>'
  printf '<p>Permanent, immutable per-version download archive. See <a href="../index.html">hort.rs</a> for the recommended one-line installer.</p>'
  printf '<ul>\n'
  # Newest first. `sort -V` orders vX.Y.Z / vX.Y.Z-rc.N reasonably (it is
  # not a full semver comparator, but published tags are well-formed).
  find "$DL_ROOT" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' \
    | sort -Vr \
    | while IFS= read -r tag; do
        printf '<li><a href="%s/">%s</a></li>\n' "$tag" "$tag"
      done
  printf '</ul></body></html>\n'
} > "${DL_ROOT}/index.html"
echo "  wrote ${DL_ROOT}/index.html"
