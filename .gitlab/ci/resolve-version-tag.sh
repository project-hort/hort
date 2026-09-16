#!/bin/sh
# resolve-version-tag.sh -- Resolve VERSION_TAG and PUSH_LATEST for an
# image-build job.
#
# SOURCE this script (`. resolve-version-tag.sh`, NOT `sh resolve-version-tag.sh`):
# it sets VERSION_TAG and PUSH_LATEST in the caller's shell, which a child
# process could not do. Run it under the caller's own `set -euo pipefail`;
# it does not set shell options itself.
#
# Shared by build-images:hort-server and build-images:hort-worker so the tag
# policy is expressed once instead of twice.
#
# Inputs (CI predefined variables):
#   CI_COMMIT_TAG          set on a tag pipeline
#   CI_COMMIT_BRANCH       set on a branch pipeline
#   CI_COMMIT_SHORT_SHA    short commit SHA, used as the branch-build tag
#
# Outputs:
#   VERSION_TAG    the tag to push the image under
#   PUSH_LATEST    "true" or "false" -- whether to additionally push :latest

PUSH_LATEST="false"
if [ -n "${CI_COMMIT_TAG:-}" ]; then
  VERSION_TAG="${CI_COMMIT_TAG#v}"
  case "${VERSION_TAG}" in
    # A SemVer pre-release is exactly a version carrying a `-` after the
    # patch level (alpha, beta, rc, and whatever comes next). Matching that
    # shape -- instead of enumerating known suffixes -- means a new
    # pre-release kind can never silently fall through to :latest the way
    # -alpha once did when only -rc/-beta were excluded.
    *-*) PUSH_LATEST="false" ;;
    *)   PUSH_LATEST="true"  ;;
  esac
elif [ "${CI_COMMIT_BRANCH:-}" = "main" ]; then
  VERSION_TAG="${CI_COMMIT_SHORT_SHA}"
  PUSH_LATEST="true"
else
  # release/* branches: SHA tag only.
  VERSION_TAG="${CI_COMMIT_SHORT_SHA}"
  PUSH_LATEST="false"
fi
