#!/usr/bin/env bash
#
# scripts/check-values-comments.sh — Helm values.yaml comment-coverage gate.
#
# Asserts that every top-level key in `deploy/helm/hort-server/values.yaml`
# carries at least one `#`-comment line above it. Operators read this
# file directly when overriding chart defaults; an un-commented top-level
# key means a knob whose intent is undocumented at the source.
#
# Soft check: keys whose name corresponds to a security-relevant knob should
# also carry a cross-reference comment so the security-audit pedigree is
# visible to the operator. Soft warnings only — they go to stdout, not
# stderr, and never fail the script.
#
# Run by:
#   - CI
#   - locally before pushing chart changes
#
# Implementation: pure bash + awk. The chart's values.yaml is small
# (<400 lines) and the parsing rules are trivial: a "top-level key" is a
# line that begins in column 0 with `[a-zA-Z]`, ends in `:`, and is not
# inside a multiline `|` / `>` block. yq is not used — the CI image
# does not ship it and pulling it in just for this lint enlarges the
# supply-chain surface the gate is meant to guard, mirroring the
# rationale in `scripts/check-advisory-sync.sh`.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
values_yaml="${repo_root}/deploy/helm/hort-server/values.yaml"

if [[ ! -f "${values_yaml}" ]]; then
    echo "error: ${values_yaml} not found" >&2
    exit 2
fi

# Walk the file once. For every top-level key (column-0, ends with `:`),
# count the contiguous `#` comment lines immediately above it. Emit two
# streams on stdout, separated by tabs:
#
#   FAIL <key> <line>           — zero comment lines above the key
#   WARN <key> <line>           — looks like an HORT_* var but no ADR/HORT_
#                                 cross-reference in the comment block
#
# We also tolerate blank lines between the comment block and the key:
# `# comment\n\nkey:` still counts as commented (the blank is a paragraph
# break, not a missing comment).
#
# `awk` is preferred over a multi-pass shell loop: it processes the file
# in one stream and keeps state cleanly.
parse_output=$(awk '
    BEGIN {
        # Reset comment buffer + flag. comment_block carries the most
        # recent contiguous comment text; comment_lines is its line count.
        comment_block = ""
        comment_lines = 0
    }

    # A `#`-prefixed line (possibly with leading whitespace stripped to
    # column 0): part of the active comment block. We accept indented
    # `#` too because some chart authors indent comments under a parent
    # — the lint is per-top-level-key only, so we only care about
    # column-0 comments above column-0 keys, but tolerating the rest
    # keeps the parse forgiving.
    /^[[:space:]]*#/ {
        comment_block = comment_block "\n" $0
        comment_lines += 1
        next
    }

    # A blank line between comment and key — keep the comment buffer
    # alive (paragraph break, not block end).
    /^[[:space:]]*$/ {
        next
    }

    # Top-level key: column-0 letter, ends with `:` (possibly with a
    # value after). This filters out indented sub-keys (which are not
    # in scope for this lint) and the few multi-line YAML constructs
    # the chart does not use.
    /^[a-zA-Z][a-zA-Z0-9_]*:/ {
        # Extract the key name (everything before `:`).
        key = $0
        sub(/:.*$/, "", key)

        if (comment_lines == 0) {
            print "FAIL\t" key "\t" NR
        } else {
            # Soft check: if the key name is a security-relevant knob,
            # require the comment block to carry a cross-reference (ADR
            # number or HORT_* env-var name). The heuristic is
            # conservative — only flag keys whose name is an explicit
            # security-audit subject (api.*, requireHttps,
            # trustedProxyCidrs, http.*, metrics.*, auth.lockout.*,
            # shutdown.*, secrets.*). At top level the name itself is
            # the signal.
            hort_like = 0
            if (key == "api")                     hort_like = 1
            if (key == "requireHttps")            hort_like = 1
            if (key == "trustedProxyCidrs")       hort_like = 1
            if (key == "http")                    hort_like = 1
            if (key == "metrics")                 hort_like = 1
            if (key == "shutdown")                hort_like = 1
            if (key == "secrets")                 hort_like = 1

            if (hort_like) {
                if (index(comment_block, "ADR") == 0 \
                    && index(comment_block, "HORT_") == 0) {
                    print "WARN\t" key "\t" NR
                }
            }
        }

        # Reset the comment buffer for the next key.
        comment_block = ""
        comment_lines = 0
        next
    }

    # Anything else (indented sub-keys, list items, multi-line
    # continuations) breaks the contiguous comment block.
    {
        comment_block = ""
        comment_lines = 0
    }
' "${values_yaml}")

# Split parse_output into FAIL and WARN streams.
fail_lines=$(echo "${parse_output}" | grep -E '^FAIL\b' || true)
warn_lines=$(echo "${parse_output}" | grep -E '^WARN\b' || true)

# Soft warnings — emit on stdout, do NOT fail.
if [[ -n "${warn_lines}" ]]; then
    echo "values-comments lint: soft warnings (security cross-reference suggested):"
    while IFS=$'\t' read -r _ key line; do
        echo "    - ${key} (values.yaml:${line}): comment block does not carry an ADR or HORT_ cross-reference"
    done <<< "${warn_lines}"
    echo ""
fi

# Hard failures — emit on stderr, exit 1.
if [[ -n "${fail_lines}" ]]; then
    echo "values-comments lint: top-level keys without comment blocks:" >&2
    while IFS=$'\t' read -r _ key line; do
        echo "    - ${key} (values.yaml:${line})" >&2
    done <<< "${fail_lines}"
    echo "" >&2
    echo "Every top-level key in deploy/helm/hort-server/values.yaml must" >&2
    echo "carry at least one '#'-comment line immediately above it." >&2
    echo "Operators read this file directly to discover knobs." >&2
    exit 1
fi

# All top-level keys commented; report the count for sanity.
key_count=$(grep -cE '^[a-zA-Z][a-zA-Z0-9_]*:' "${values_yaml}" || true)
echo "values-comments lint: OK (${key_count} top-level key(s) commented in deploy/helm/hort-server/values.yaml)"
exit 0
