#!/usr/bin/env bash
#
# scripts/regenerate-attribution.sh — regenerate the committed third-party
# attribution artifacts.
#
# Runs `cargo about generate` twice (once per handlebars template under
# `about/`) over the shipped-binary dependency graph and writes:
#
#   - THIRD-PARTY-LICENSES.md    (human-readable, `hort-attribution`'s
#                                  AttributionFormat::Text)
#   - THIRD-PARTY-LICENSES.json  ([{name,version,url,spdx,license_text}],
#                                  AttributionFormat::Json)
#
# Both are committed at the repo root and embedded into `hort-attribution`
# via `include_str!` (crates/hort-attribution/src/lib.rs) — every binary's
# `attribution` subcommand prints one of them verbatim. Run this after any
# dependency change that could alter the graph, and commit the result in the
# same PR (the CI gate, scripts/check-attribution.sh, fails the build if the
# committed files and a fresh regeneration diverge).
#
# `about.toml`'s `accepted` list must stay identical to `deny.toml`'s
# `[licenses] allow` list — `cargo deny check licenses` is the inbound gate
# that keeps every dependency's license inside that set; this script does
# not re-verify the parity itself (scripts/check-attribution.sh does).
#
# Requires `cargo-about` (`cargo install cargo-about --locked --features cli`,
# or `cargo binstall --no-confirm --locked cargo-about`). Not vendored —
# it is a dev/CI-time tool, not a workspace dependency.
#
# The JSON template emits an unconditional trailing comma after every kept
# array element (handlebars has no way to look ahead past crates filtered
# out mid-loop — see about/THIRD-PARTY-LICENSES.json.hbs's header comment),
# so this script strips the one dangling comma before the closing `]` with
# `sed -z` after generation.
#
# Some upstream crates (e.g. `tryhard`) bundle a LICENSE file with CRLF line
# endings, which cargo-about copies into the license text verbatim. The repo
# has no `.gitattributes` override, so `core.autocrlf=input` normalizes those
# to LF the moment the file is `git add`ed — meaning a byte-for-byte fresh
# regeneration would otherwise never match the committed file, permanently
# tripping the CI staleness gate (scripts/check-attribution.sh) on nothing
# more than line-ending normalization. Both generated files are normalized
# to LF here so the script's own output is already what git would commit,
# on any OS.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "${repo_root}"

# `cargo binstall` installs cargo-about into $CARGO_HOME/bin. CI (GitLab)
# overrides CARGO_HOME to the project-local .cargo for caching, and that bin
# dir is not on PATH — `cargo about` still resolves it as a subcommand, but the
# presence check below uses PATH. Prepend $CARGO_HOME/bin so it is findable.
export PATH="${CARGO_HOME:-${HOME}/.cargo}/bin:${PATH}"

if ! command -v cargo-about >/dev/null 2>&1; then
    echo "error: cargo-about not found on PATH." >&2
    echo "  install: cargo install cargo-about --locked --features cli" >&2
    exit 2
fi

md_out="${repo_root}/THIRD-PARTY-LICENSES.md"
json_out="${repo_root}/THIRD-PARTY-LICENSES.json"

echo "regenerating ${md_out}..." >&2
cargo about generate \
    --workspace \
    --locked \
    -c "${repo_root}/about.toml" \
    -o "${md_out}" \
    "${repo_root}/about/THIRD-PARTY-LICENSES.md.hbs"
sed -i 's/\r$//' "${md_out}"

echo "regenerating ${json_out}..." >&2
cargo about generate \
    --workspace \
    --locked \
    -c "${repo_root}/about.toml" \
    -o "${json_out}" \
    "${repo_root}/about/THIRD-PARTY-LICENSES.json.hbs"

# Strip the single dangling trailing comma before the closing `]` (see the
# header comment above and the template's own comment for why it's there).
# Anchored on "comma, optional whitespace, `]`, optional whitespace, end of
# file" so it can only ever match the real closing bracket, not a coincidental
# ",  ]"-shaped substring inside some crate's license text.
sed -z -i 's/,\([[:space:]]*\][[:space:]]*\)$/\1/' "${json_out}"

if ! python3 -m json.tool "${json_out}" >/dev/null; then
    echo "error: generated ${json_out} is not valid JSON" >&2
    exit 1
fi

echo "done." >&2
