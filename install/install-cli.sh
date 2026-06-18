#!/bin/sh
# hort-cli installer (Linux & macOS). Fail-closed: cosign-verified or no install.
#   curl -fsSL https://hort.rs/install-cli.sh | sh
#   curl -fsSL https://hort.rs/install-cli.sh | sh -s -- --version v1.0.0 --dir ~/bin
set -eu

main() {
  GH_REPO="project-hort/hort"
  COSIGN_IDENTITY_REGEXP='https://github.com/project-hort/.*'
  COSIGN_OIDC_ISSUER='https://token.actions.githubusercontent.com'
  API="${HORT_API:-https://api.github.com}"
  DL_BASE="${HORT_DL_BASE:-https://github.com/${GH_REPO}/releases/download}"
  PIN_URL="${HORT_PIN_URL:-https://hort.rs/cosign.pin}"

  version="${HORT_VERSION:-}"
  install_dir="${HORT_INSTALL_DIR:-$HOME/.local/bin}"
  add_to_path=0

  while [ $# -gt 0 ]; do
    case "$1" in
      --version) [ $# -ge 2 ] || die "--version requires a value"; version="$2"; shift 2;;
      --dir) [ $# -ge 2 ] || die "--dir requires a value"; install_dir="$2"; shift 2;;
      --add-to-path) add_to_path=1; shift;;
      --help) usage; exit 0;;
      *) die "unknown option: $1 (try --help)";;
    esac
  done

  need_cmd uname; need_cmd tar; need_cmd mkdir; need_cmd mv; need_cmd chmod
  dl_tool
  sha_tool

  asset="hort-cli-$(detect_platform)"
  [ -n "$version" ] || version="$(resolve_latest)"
  archive="${asset}.tar.gz"

  tmp="$(mktemp -d)"
  [ -n "$tmp" ] || die "could not create temp dir"
  trap 'rm -rf "$tmp"' EXIT INT TERM
  base="${DL_BASE}/${version}"

  say "downloading ${archive} (${version})"
  fetch "${base}/${archive}"        "${tmp}/${archive}"
  fetch "${base}/${archive}.sha256" "${tmp}/${archive}.sha256"
  fetch "${base}/${archive}.bundle" "${tmp}/${archive}.bundle"

  say "verifying SHA-256"
  verify_sha256 "${tmp}" "${archive}"

  say "verifying cosign signature (fail-closed)"
  cosign_verify "${tmp}/${archive}" "${tmp}/${archive}.bundle"

  say "installing to ${install_dir}/hort-cli"
  tar -xzf "${tmp}/${archive}" -C "$tmp"
  [ -f "${tmp}/${asset}" ] || die "archive did not contain ${asset}"
  mkdir -p "$install_dir"
  chmod +x "${tmp}/${asset}"
  mv -f "${tmp}/${asset}" "${install_dir}/hort-cli"

  path_hint "$install_dir"
  # The `|| echo` fallback keeps the success line readable even if the freshly
  # installed binary can't exec here (e.g. a cross-arch install); verification already passed.
  say "installed: $("${install_dir}/hort-cli" --version 2>/dev/null || echo 'hort-cli') -> ${install_dir}/hort-cli — verified"
}

usage() {
  cat <<'EOF'
hort-cli installer
  --version <vX.Y.Z>   install a specific release (default: latest, prerelease-aware until 1.0)
  --dir <path>         install location (default: ~/.local/bin)
  --add-to-path        append the install dir to your shell profile (default: print instructions)
  --help               this help
Env: HORT_VERSION, HORT_INSTALL_DIR, GITHUB_TOKEN (avoids API rate limits).
There is intentionally no skip-verify option.
EOF
}

say() { printf 'hort install: %s\n' "$1" >&2; }
die() { printf 'hort install: ERROR: %s\n' "$1" >&2; exit 1; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

DL=""
dl_tool() {
  if command -v curl >/dev/null 2>&1; then DL=curl
  elif command -v wget >/dev/null 2>&1; then DL=wget
  else die "need curl or wget"
  fi
}

fetch() {
  if [ "$DL" = curl ]; then
    curl -fsSL "$1" -o "$2" || die "download failed: $1"
  else
    wget -qO "$2" "$1" || die "download failed: $1"
  fi
}

api_get() {
  if [ "$DL" = curl ]; then
    if [ -n "${GITHUB_TOKEN:-}" ]; then
      curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" "$1"
    else
      curl -fsSL "$1"
    fi
  else
    if [ -n "${GITHUB_TOKEN:-}" ]; then
      wget -qO- --header="Authorization: Bearer ${GITHUB_TOKEN}" "$1"
    else
      wget -qO- "$1"
    fi
  fi
}

SHA=""
sha_tool() {
  if command -v sha256sum >/dev/null 2>&1; then SHA="sha256sum"
  elif command -v shasum >/dev/null 2>&1; then SHA="shasum -a 256"
  else die "need sha256sum or shasum"
  fi
}

# verify_sha256 <dir> <archive-filename>
# Runs checksum verification from inside <dir> so relative paths in the .sha256 file work.
verify_sha256() {
  _dir="$1"; _file="$2"
  # sha256sum -c expects the checksum file's paths to be relative to cwd
  ( cd "$_dir" && $SHA -c "${_file}.sha256" >/dev/null 2>&1 ) \
    || die "SHA-256 verification failed — aborting, nothing installed"
}

detect_platform() {
  os="$(uname -s)"; arch="$(uname -m)"
  case "$os" in
    Linux)  os=linux;;
    Darwin) os=darwin;;
    *)      die "unsupported OS: $os (use cargo install / build from source)";;
  esac
  case "$arch" in
    x86_64|amd64)   arch=amd64;;
    aarch64|arm64)  arch=arm64;;
    *)               die "unsupported arch: $arch (use cargo install / build from source)";;
  esac
  printf '%s-%s' "$os" "$arch"
}

resolve_latest() {
  body="$(api_get "${API}/repos/${GH_REPO}/releases?per_page=1")" \
    || die "could not query releases — set HORT_VERSION=vX.Y.Z"
  tag="$(printf '%s\n' "$body" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
  [ -n "$tag" ] || die "no release found (rate-limited? export GITHUB_TOKEN, or pass --version)"
  printf '%s' "$tag"
}

cosign_verify() {
  _blob="$1"; _bundle="$2"
  # No verification bypass exists in the shipped script. Tests stub cosign by putting a
  # fake `cosign` on PATH (see install/tests/), so this real path always runs.
  # shellcheck disable=SC2034  # intentional: tests can override the regexp via env
  # _HORT_INTERNAL_TEST_BAD_IDENTITY (INFRA-15): a CI-test-only knob — leading
  # underscore marks it internal; it is NOT for operators and is deliberately
  # absent from --help. It only swaps in a NON-matching signer identity, which
  # makes verification STRICTER (fail-closed); it can never weaken or bypass
  # verify. Used by the real-cosign negative CI test.
  [ "${_HORT_INTERNAL_TEST_BAD_IDENTITY:-}" = "1" ] && COSIGN_IDENTITY_REGEXP='https://github.com/definitely-not-project-hort/.*'
  cosign_bin="$(ensure_cosign)"
  "$cosign_bin" verify-blob \
    --certificate-oidc-issuer="$COSIGN_OIDC_ISSUER" \
    --certificate-identity-regexp="$COSIGN_IDENTITY_REGEXP" \
    --bundle "$_bundle" "$_blob" >/dev/null 2>&1 \
    || die "cosign signature verification failed — aborting, nothing installed"
}

ensure_cosign() {
  if command -v cosign >/dev/null 2>&1 && cosign_ok "$(command -v cosign)"; then
    command -v cosign; return
  fi
  # Bootstrap pinned cosign: fetch pin file, verify hash, use it
  pin_file="${tmp}/cosign.pin"
  fetch "$PIN_URL" "$pin_file" || die "could not fetch cosign pin from ${PIN_URL}"
  cv="$(sed -n 's/^COSIGN_VERSION=//p' "$pin_file")"
  plat="$(detect_platform)"
  key="COSIGN_SHA256_$(printf '%s' "$plat" | tr '-' '_')"
  want="$(sed -n "s/^${key}=//p" "$pin_file")"
  if [ -z "$cv" ] || [ -z "$want" ]; then die "cosign pin malformed (missing ${key} or COSIGN_VERSION)"; fi
  cb="${tmp}/cosign"
  fetch "https://github.com/sigstore/cosign/releases/download/${cv}/cosign-${plat}" "$cb"
  got="$(cd "$tmp" && $SHA cosign | awk '{print $1}')"
  [ "$got" = "$want" ] || die "bootstrapped cosign hash mismatch (expected $want got $got) — aborting"
  chmod +x "$cb"
  printf '%s' "$cb"
}

cosign_ok() {
  v="$("$1" version 2>/dev/null | sed -n 's/.*GitVersion:[[:space:]]*v\{0,1\}\([0-9][0-9.]*\).*/\1/p' | head -1)"
  case "$v" in
    3.*|4.*|5.*|6.*|7.*|8.*|9.*|[1-9][0-9].*) return 0;;
    *) return 1;;
  esac
}

path_hint() {
  case ":${PATH}:" in *":$1:"*) return 0;; esac
  if [ "$add_to_path" = 1 ]; then
    rc="${HOME}/.profile"
    [ -n "${ZSH_VERSION:-}" ] && rc="${HOME}/.zshrc"
    # shellcheck disable=SC2016  # $PATH must be written literally into the profile, not expanded now
    printf '\nexport PATH="%s:$PATH"\n' "$1" >> "$rc"
    say "added ${1} to PATH in ${rc} — open a new shell to pick it up"
  else
    say "NOTE: ${1} is not on your PATH. Add it:  export PATH=\"${1}:\$PATH\""
  fi
}

main "$@"
