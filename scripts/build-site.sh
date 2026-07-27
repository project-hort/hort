#!/usr/bin/env bash
#
# scripts/build-site.sh — build hort's static sites (issues #78, #77).
#
# Generates site/dist/<fqdn>/ (gitignored) for each site:
#   - project-hort.de: a landing page whose factual content (pillars,
#     supported formats) is extracted from the root README.md at build
#     time, plus an operator-docs section generated from
#     docs/architecture/{how-to,reference,tutorial}.
#   - hort.rs: a CLI landing page extracted from
#     docs/architecture/how-to/install-cli.md, CLI user docs (that file +
#     cli-completions.md + using-hort-cli-with-admin-ops.md +
#     crates/hort-cli/README.md), and the installer scripts
#     (install-cli.sh, install-cli.ps1, cosign.pin) copied verbatim to
#     their exact published apex paths. dl/index.html is a placeholder here
#     — the real permanent version archive is populated separately,
#     host-side, by scripts/populate-dl-archive.sh (see
#     deploy/ansible/roles/website/ for why).
#
# Single source of truth, no hand-copied second corpus. Inter-doc .md links
# are rewritten to site-relative paths (in-scope for the SAME site), the
# sibling site's live absolute URL (in-scope for the OTHER site), or the
# canonical GitHub blob/tree URL (out of scope for both, e.g. ADRs). A
# link-check runs at the end of each site's build and fails on any broken
# internal link, heading anchor, or external-asset reference.
#
# The generator (scripts/site/generate.py + mdconv.py + linkcheck.py) is a
# small, dependency-free Python 3 stdlib script — no pandoc, no pip
# packages, no npm-ecosystem SSG with a floating lockfile. See
# scripts/site/generate.py's module docstring for the full rationale.
#
# Usage:
#   scripts/build-site.sh                       # builds both sites into site/dist/
#   scripts/build-site.sh --site hort.rs         # builds only hort.rs
#   scripts/build-site.sh --site project-hort.de --dist DIR
#
# Requires only python3 (3.8+; uses no third-party modules).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is required to build the site (no other dependency is)" >&2
  exit 1
fi

python3 scripts/site/generate.py "$@"
