#!/usr/bin/env bash
#
# scripts/build-site.sh — build the project-hort.de static site (issue #78).
#
# Generates site/dist/ (gitignored): a landing page whose factual content
# (pillars, supported formats) is extracted from the root README.md at build
# time, plus an operator-docs section generated from
# docs/architecture/{how-to,reference,tutorial} — single source of truth,
# no hand-copied second corpus. Inter-doc .md links are rewritten to site
# paths (or to the canonical GitHub blob URL for out-of-scope references,
# e.g. ADRs); a link-check runs at the end and fails the build on any
# broken internal link or heading anchor.
#
# The generator (scripts/site/generate.py + mdconv.py + linkcheck.py) is a
# small, dependency-free Python 3 stdlib script — no pandoc, no pip
# packages, no npm-ecosystem SSG with a floating lockfile. See
# scripts/site/generate.py's module docstring for the full rationale.
#
# Usage:
#   scripts/build-site.sh            # builds into site/dist/
#   scripts/build-site.sh --dist DIR # builds into an alternate directory
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
