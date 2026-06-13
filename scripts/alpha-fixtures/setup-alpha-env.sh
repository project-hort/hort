#!/usr/bin/env bash
#
# Set up the local alpha-testing environment for the v2 binaries
# (hort-server + hort-worker + hort-cli). See
# `docs/architecture/how-to/alpha-testing-runbook.md` for the runbook
# this environment supports.
#
# Idempotent: safe to re-run. Each install step checks for an existing
# usable version first and skips if found.
#
# === Installs (under user home — no sudo) ===========================
#
#   ~/.nvm/                          nvm (Node version manager)
#   ~/.nvm/versions/node/...         Node + npm (LTS by default)
#   <project>/.alpha-venv/           Python venv with twine + build
#   ~/.local/bin/crane               OCI registry CLI
#   ~/.local/bin/trivy               Trivy scanner
#   ~/.local/bin/osv-scanner         OSV vulnerability scanner
#
# === Verifies (does NOT install; fails fast if absent) ==============
#
#   docker, docker compose v2
#   cargo (Rust toolchain >= 1.94)
#   curl
#   jq
#   python3 (>= 3.11)
#
# === Required network reachability ==================================
#
#   raw.githubusercontent.com    nvm + trivy install scripts
#   github.com / objects.gh...   release asset downloads
#   nodejs.org                   Node binaries (via nvm)
#   registry.npmjs.org           npm install of fixture deps (later)
#   pypi.org                     pip install twine + build
#
# === Env overrides ==================================================
#
#   NVM_VERSION              nvm release tag        default: v0.40.1
#   NODE_VERSION             nvm install argument   default: lts/*
#   TRIVY_VERSION            empty = latest         default: empty
#   CRANE_VERSION            "" or vX.Y.Z           default: empty (latest)
#   OSV_SCANNER_VERSION      "" or vX.Y.Z           default: empty (latest)
#
# === Exit codes =====================================================
#
#   0   all good
#   10  required tool missing (docker / cargo / curl / jq / python3)
#   20  install failed (network, archive corrupt, etc.)
#   30  platform unsupported (only Linux + macOS, x86_64 + arm64)
#

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$HERE/../.." && pwd)"

NVM_VERSION="${NVM_VERSION:-v0.40.1}"
NODE_VERSION="${NODE_VERSION:-lts/*}"
TRIVY_VERSION="${TRIVY_VERSION:-}"
CRANE_VERSION="${CRANE_VERSION:-}"
OSV_SCANNER_VERSION="${OSV_SCANNER_VERSION:-}"

LOCAL_BIN="$HOME/.local/bin"
VENV_DIR="$PROJECT_ROOT/.alpha-venv"

# Color helpers — disabled when stdout is not a TTY.
if [[ -t 1 ]]; then
    C_OK=$'\033[0;32m' ; C_INFO=$'\033[0;36m' ; C_WARN=$'\033[0;33m'
    C_ERR=$'\033[0;31m' ; C_OFF=$'\033[0m'
else
    C_OK= ; C_INFO= ; C_WARN= ; C_ERR= ; C_OFF=
fi

step()  { printf '%s==>%s %s\n' "$C_INFO" "$C_OFF" "$*"; }
ok()    { printf '%s  ✓%s %s\n' "$C_OK" "$C_OFF" "$*"; }
warn()  { printf '%s  !%s %s\n' "$C_WARN" "$C_OFF" "$*"; }
fail()  { printf '%s  ✗ %s%s\n' "$C_ERR" "$*" "$C_OFF" >&2; }

# ---------------------------------------------------------------------------
# 1. Platform detection
# ---------------------------------------------------------------------------

step "Detecting platform"

UNAME_S="$(uname -s)"
UNAME_M="$(uname -m)"

case "$UNAME_S" in
    Linux)
        CRANE_OS=Linux       ; TRIVY_INSTALL_OS=Linux  ; OSV_OS=linux
        ;;
    Darwin)
        CRANE_OS=Darwin      ; TRIVY_INSTALL_OS=macOS  ; OSV_OS=darwin
        ;;
    *)
        fail "Unsupported OS: $UNAME_S (Linux + macOS only)"
        exit 30
        ;;
esac

case "$UNAME_M" in
    x86_64|amd64)
        CRANE_ARCH=x86_64    ; OSV_ARCH=amd64
        ;;
    aarch64|arm64)
        CRANE_ARCH=arm64     ; OSV_ARCH=arm64
        ;;
    *)
        fail "Unsupported arch: $UNAME_M (x86_64 + arm64 only)"
        exit 30
        ;;
esac

ok "Platform: ${UNAME_S} ${UNAME_M}"

# ---------------------------------------------------------------------------
# 2. Verify required tools
# ---------------------------------------------------------------------------

step "Verifying required tools (docker, docker compose, cargo, curl, jq, python3)"

require() {
    local name="$1"
    local hint="$2"
    if ! command -v "$name" >/dev/null 2>&1; then
        fail "$name not found on PATH. $hint"
        return 1
    fi
    ok "$name → $(command -v "$name")"
}

missing=0
require docker  "Install Docker Engine 25+ (https://docs.docker.com/engine/install/)" || missing=1
require cargo   "Install Rust via rustup (https://rustup.rs)" || missing=1
require curl    "Install via your distro package manager" || missing=1
require jq      "Install via your distro package manager" || missing=1
require python3 "Install Python 3.11+ via your distro package manager or pyenv" || missing=1
require openssl "Install via your distro package manager (used to mint the Ed25519 OCI signing key)" || missing=1

# docker compose v2 is a docker subcommand, not a separate binary.
if ! docker compose version >/dev/null 2>&1; then
    fail "docker compose v2 not available (need Docker 25+ with the compose plugin)"
    missing=1
else
    ok "docker compose → $(docker compose version --short)"
fi

# Rust version sanity (CLAUDE.md MSRV is 1.94).
if command -v cargo >/dev/null 2>&1; then
    cargo_version="$(cargo --version | awk '{print $2}')"
    cargo_minor="$(echo "$cargo_version" | cut -d. -f2)"
    if [[ "$cargo_minor" -lt 94 ]]; then
        warn "cargo $cargo_version is older than MSRV 1.94 — runbook builds may fail. Run \`rustup update stable\`."
    fi
fi

# Python version sanity (3.11+).
if command -v python3 >/dev/null 2>&1; then
    py_version="$(python3 --version 2>&1 | awk '{print $2}')"
    py_major="$(echo "$py_version" | cut -d. -f1)"
    py_minor="$(echo "$py_version" | cut -d. -f2)"
    if [[ "$py_major" -lt 3 ]] || [[ "$py_major" -eq 3 && "$py_minor" -lt 11 ]]; then
        warn "python3 $py_version is older than 3.11 — pip + twine flows in §7.2 may misbehave."
    fi
fi

if [[ $missing -ne 0 ]]; then
    fail "One or more required tools missing. Install them and re-run this script."
    exit 10
fi

# ---------------------------------------------------------------------------
# 3. ~/.local/bin on PATH
# ---------------------------------------------------------------------------

mkdir -p "$LOCAL_BIN"

local_bin_on_path=1
case ":$PATH:" in
    *:"$LOCAL_BIN":*) ok "$LOCAL_BIN is on PATH" ;;
    *)
        warn "$LOCAL_BIN is NOT on PATH — installed tools won't be found until you fix this."
        warn "Add to your shell rc (~/.bashrc or ~/.zshrc):"
        warn "    export PATH=\"\$HOME/.local/bin:\$PATH\""
        local_bin_on_path=0
        ;;
esac

# ---------------------------------------------------------------------------
# 4. nvm + Node LTS
# ---------------------------------------------------------------------------

step "Installing / verifying nvm + Node ($NODE_VERSION)"

if [[ ! -s "$HOME/.nvm/nvm.sh" ]]; then
    step "  Fetching nvm $NVM_VERSION install script"
    if ! curl -fsSL "https://raw.githubusercontent.com/nvm-sh/nvm/${NVM_VERSION}/install.sh" | PROFILE=/dev/null bash; then
        fail "nvm install failed"
        exit 20
    fi
else
    ok "nvm already present at $HOME/.nvm"
fi

# Source nvm so we can drive it from this shell. nvm.sh is non-strict
# and references undefined vars; relax our `set -u` for the source.
set +u
# shellcheck source=/dev/null
. "$HOME/.nvm/nvm.sh"
set -u

# Install + alias the requested Node version. `nvm install` is
# idempotent — if already installed, it just selects.
step "  nvm install $NODE_VERSION"
nvm install "$NODE_VERSION" >/dev/null
nvm alias default "$NODE_VERSION" >/dev/null

node_path="$(nvm which "$NODE_VERSION")"
node_version="$("$node_path" --version)"
npm_path="$(dirname "$node_path")/npm"
npm_version="$("$npm_path" --version)"
ok "node $node_version → $node_path"
ok "npm $npm_version  → $npm_path"

# Materialise an .nvmrc in the project root if absent — lets future
# `nvm use` in this directory pick the right Node automatically.
if [[ ! -f "$PROJECT_ROOT/.nvmrc" ]]; then
    echo "$NODE_VERSION" > "$PROJECT_ROOT/.nvmrc"
    ok "Wrote $PROJECT_ROOT/.nvmrc ($NODE_VERSION)"
fi

# ---------------------------------------------------------------------------
# 5. Python venv with twine + build
# ---------------------------------------------------------------------------

step "Setting up Python venv at .alpha-venv (twine + build)"

if [[ ! -x "$VENV_DIR/bin/python" ]]; then
    python3 -m venv "$VENV_DIR"
    ok "Created venv at $VENV_DIR"
else
    ok "venv already exists at $VENV_DIR"
fi

# Upgrade pip + install twine + build into the venv.
# Suppress noisy output unless install fails.
set +u
# shellcheck source=/dev/null
. "$VENV_DIR/bin/activate"
set -u

if ! pip install --quiet --upgrade pip; then
    fail "pip self-upgrade failed inside venv"
    exit 20
fi
if ! pip install --quiet twine build; then
    fail "pip install twine + build failed inside venv"
    exit 20
fi

ok "pip:   $(pip --version | head -c 60)"
ok "twine: $(twine --version 2>&1 | head -1 | head -c 60)"
ok "build: $(pip show build | grep '^Version:' | awk '{print $2}')"

deactivate

# ---------------------------------------------------------------------------
# 6. crane (OCI CLI)
# ---------------------------------------------------------------------------

step "Installing crane to $LOCAL_BIN"

if "$LOCAL_BIN/crane" version >/dev/null 2>&1; then
    ok "crane already present: $("$LOCAL_BIN/crane" version 2>&1 | head -1)"
elif command -v crane >/dev/null 2>&1; then
    ok "crane already on PATH at $(command -v crane); skipping local install"
else
    crane_tag_path="latest/download"
    [[ -n "$CRANE_VERSION" ]] && crane_tag_path="download/$CRANE_VERSION"
    crane_url="https://github.com/google/go-containerregistry/releases/${crane_tag_path}/go-containerregistry_${CRANE_OS}_${CRANE_ARCH}.tar.gz"
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN
    if ! curl -fsSL -o "$tmp/crane.tgz" "$crane_url"; then
        fail "Failed to download crane from $crane_url"
        exit 20
    fi
    # The archive contains crane + gcrane + krane at the top level.
    # We only want crane.
    tar -xzf "$tmp/crane.tgz" -C "$tmp" crane
    install -m 0755 "$tmp/crane" "$LOCAL_BIN/crane"
    rm -rf "$tmp"
    trap - RETURN
    ok "crane installed: $("$LOCAL_BIN/crane" version 2>&1 | head -1)"
fi

# ---------------------------------------------------------------------------
# 7. trivy (CVE scanner)
# ---------------------------------------------------------------------------

step "Installing trivy to $LOCAL_BIN"

if "$LOCAL_BIN/trivy" --version >/dev/null 2>&1; then
    ok "trivy already present: $("$LOCAL_BIN/trivy" --version 2>&1 | head -1)"
elif command -v trivy >/dev/null 2>&1; then
    ok "trivy already on PATH at $(command -v trivy); skipping local install"
else
    # The official Aqua install script supports a `-b <dir>` flag for
    # non-root installs to a user-controlled directory. Without an
    # explicit version it installs the latest stable release.
    install_args=("-b" "$LOCAL_BIN")
    [[ -n "$TRIVY_VERSION" ]] && install_args+=("$TRIVY_VERSION")
    if ! curl -sfL "https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh" \
            | sh -s -- "${install_args[@]}"; then
        fail "trivy install script failed"
        exit 20
    fi
    ok "trivy installed: $("$LOCAL_BIN/trivy" --version 2>&1 | head -1)"
fi

# ---------------------------------------------------------------------------
# 8. osv-scanner
# ---------------------------------------------------------------------------

step "Generating Ed25519 OCI signing key"

# Native-token auth (HORT_NATIVE_TOKENS_ENABLED=true) requires an Ed25519
# PKCS#8 PEM signing key. hort-server refuses to start without one. The
# alpha tester runs hort-server in --enable-native-tokens mode (the
# PAT-only auth path), so the key must exist before the first boot.
# Idempotent: skips if the file already exists with non-zero size.

DATA_ALPHA="$PROJECT_ROOT/data/alpha"
SIGNING_KEY="$DATA_ALPHA/oci-signing-key.pem"

mkdir -p "$DATA_ALPHA"
if [[ -s "$SIGNING_KEY" ]]; then
    ok "OCI signing key already exists at $SIGNING_KEY"
else
    if ! openssl genpkey -algorithm Ed25519 -out "$SIGNING_KEY" 2>/dev/null; then
        fail "openssl genpkey failed — is openssl installed?"
        exit 20
    fi
    chmod 0600 "$SIGNING_KEY"
    ok "Wrote $SIGNING_KEY (PKCS#8 PEM, 0600)"
fi

step "Installing osv-scanner to $LOCAL_BIN"

if "$LOCAL_BIN/osv-scanner" --version >/dev/null 2>&1; then
    ok "osv-scanner already present: $("$LOCAL_BIN/osv-scanner" --version 2>&1 | head -1)"
elif command -v osv-scanner >/dev/null 2>&1; then
    ok "osv-scanner already on PATH at $(command -v osv-scanner); skipping local install"
else
    osv_tag_path="latest/download"
    [[ -n "$OSV_SCANNER_VERSION" ]] && osv_tag_path="download/$OSV_SCANNER_VERSION"
    osv_url="https://github.com/google/osv-scanner/releases/${osv_tag_path}/osv-scanner_${OSV_OS}_${OSV_ARCH}"
    if ! curl -fsSL -o "$LOCAL_BIN/osv-scanner" "$osv_url"; then
        fail "Failed to download osv-scanner from $osv_url"
        exit 20
    fi
    chmod 0755 "$LOCAL_BIN/osv-scanner"
    ok "osv-scanner installed: $("$LOCAL_BIN/osv-scanner" --version 2>&1 | head -1)"
fi

# ---------------------------------------------------------------------------
# 9. Activation hint
# ---------------------------------------------------------------------------

cat <<EOF

$C_OK✓ Alpha environment setup complete.$C_OFF

In every new terminal for the alpha run, source the three pieces:

    # 1. nvm + Node
    source ~/.nvm/nvm.sh && nvm use

    # 2. Python venv
    source $VENV_DIR/bin/activate

    # 3. hort env vars (database URL, storage path, etc.)
    source $PROJECT_ROOT/scripts/alpha-fixtures/alpha.env

EOF

if [[ "$local_bin_on_path" -eq 0 ]]; then
    cat <<EOF
$C_WARN!$C_OFF and the ONE-TIME PATH fix (you do not have $LOCAL_BIN on PATH today):

    echo 'export PATH="\$HOME/.local/bin:\$PATH"' >> ~/.bashrc   # or ~/.zshrc
    exec \$SHELL -l                                              # reload shell

EOF
fi

cat <<EOF
Then walk the runbook:

    docs/architecture/how-to/alpha-testing-runbook.md

Next step (after sourcing the three above):

    docker compose -f $PROJECT_ROOT/scripts/alpha-fixtures/compose-deps.yml up -d
    cargo build --release -p hort-server -p hort-worker -p hort-cli

EOF
