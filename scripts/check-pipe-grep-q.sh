#!/usr/bin/env bash
#
# scripts/check-pipe-grep-q.sh — rejects an unannotated pipe into
# `grep -q` / `grep -Eq` (or any other `-*q*` variant) under scripts/.
#
# `<producer> | grep -q PATTERN` under `set -o pipefail` misreports "no
# match" once PATTERN's first hit lands before <producer> has finished
# writing a body bigger than the pipe buffer (64 KiB): grep -q exits at
# its first match, the still-writing producer takes SIGPIPE, and
# pipefail promotes that exit to the pipeline's status —
# indistinguishable from a genuine no-match. The fix is
# scripts/native-tests/lib/common.sh's capture_match, which fetches a
# body into a temp file once and matches the FILE, never the pipe.
#
# The predicate (all must hold; any hit -> FAIL):
#
#   Every occurrence of `| grep -<flags containing q>` in a
#   scripts/**/*.sh CODE line (a line whose content before the first `#`
#   still carries the shape — a comment-only line legitimately discussing
#   this pattern, such as this header, is exempt) must have a line
#   containing the literal text "Bounded:" somewhere in the 10 lines
#   immediately above it, justifying why that specific producer can
#   never exceed the pipe buffer. A pipe with no such note is rejected.
#
# Run by:
#   - `.gitlab-ci.yml`                      (quality:pipe-grep-q-guard)
#   - locally before pushing scripts/ changes
#
# Implementation: pure bash, no external grep/sed pipeline of its own (so
# the gate cannot trip its own predicate) — repo-root-relative,
# idempotent, fast. Mirrors the house style of
# scripts/check-g1-attestation-gate.sh / scripts/check-advisory-sync.sh.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "${repo_root}"

pipe_re='\| *grep -[A-Za-z]*q'
lookback=10
fail_count=0

while IFS= read -r -d '' file; do
    mapfile -t file_lines < "$file"
    n=${#file_lines[@]}
    for ((i = 0; i < n; i++)); do
        line="${file_lines[$i]}"
        code_part="${line%%#*}"
        if [[ "$code_part" =~ $pipe_re ]]; then
            annotated=0
            for ((back = 1; back <= lookback && i - back >= 0; back++)); do
                if [[ "${file_lines[$((i - back))]}" == *"Bounded:"* ]]; then
                    annotated=1
                    break
                fi
            done
            if [ "$annotated" -eq 0 ]; then
                echo "FAIL: ${file}:$((i + 1)): pipe into grep -q under pipefail, not annotated" >&2
                echo "      ${line}" >&2
                echo "      fix: convert to scripts/native-tests/lib/common.sh's capture_match" >&2
                echo "           (fetch the body into a temp file, match the file), or add a" >&2
                echo "           'Bounded: <why>' comment within ${lookback} lines above explaining" >&2
                echo "           why this producer can never exceed the pipe buffer." >&2
                fail_count=$((fail_count + 1))
            fi
        fi
    done
done < <(find scripts -name '*.sh' -type f -print0)

if [ "$fail_count" -gt 0 ]; then
    echo "" >&2
    echo "pipe-grep-q-guard: FAIL — ${fail_count} unannotated pipe(s) into grep -q under pipefail." >&2
    exit 1
fi

echo "pipe-grep-q-guard: OK (every pipe into grep -q under scripts/ is either converted to capture_match or annotated bounded)."
exit 0
