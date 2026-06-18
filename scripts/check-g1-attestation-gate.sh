#!/usr/bin/env bash
#
# scripts/check-g1-attestation-gate.sh — roadmap gate G1 attestation predicate.
#
# The concrete machine-readable G1 predicate (see docs/compliance/ for the
# governance home). Gate G1 governs whether a `docs/compliance/` tamper-resistant-
# logging / GDPR Art. 17(3)(b) attestation may publish the audit-log-tamper-
# evidence claim. The claim is honest ONLY when the relevant telemetry rows
# are catalogued and their named regression tests exist — AND the wording
# stays at the "tamper-EVIDENT" bar (never the unqualified
# "tamper-proof"/"tamper-resistant" self-claim).
#
# The predicate (all must hold; any failure → non-zero exit):
#
#   (a) docs/metrics-catalog.md catalogues BOTH the audit-chain telemetry row
#       `hort_event_chain_verify_total` AND the advisory-ingest telemetry row
#       `hort_advisory_ingest_count` (the G1 metric pair).
#
#   (b) The named regression tests are present BY NAME in
#       their source files (the test-inventory check):
#         audit-chain: tampered_row_fails_verification
#                (crates/hort-adapters-postgres/src/event_store.rs)
#              verify_tampered_row_is_broken
#                (crates/hort-server/src/cli/verify_event_chain.rs)
#         advisory-ingest: iter_zip_entries_trusted_bulk_config_completes_all_for_large_archive
#                (crates/hort-formats/src/archive_bounds.rs)
#       Presence is asserted with a `grep -q "fn <name>"` — the suite is
#       NOT executed (this gate is a fast doc/inventory predicate, no
#       cargo build, mirroring the other scripts/check-*.sh gates).
#
#   (c) IF any file under docs/compliance/ actually PUBLISHES the
#       audit-log tamper-evidence self-attestation (recognised by an
#       audit-chain self-claim marker: a "tamper-{proof,resistant,
#       evident}" word co-occurring with a chain-mechanism token such
#       as "hash chain" / "signed checkpoint" / "offline verifier" /
#       "verify-event-chain" / "hort_event_chain"), THEN:
#         - (a) ∧ (b) must hold (already enforced above), AND
#         - that file MUST contain the qualified "tamper-evident"
#           form, AND MUST NOT contain the unqualified self-claim
#           "tamper-proof" or "tamper-resistant" (honesty caveat —
#           the gate's whole reason to exist: don't publish a claim
#           stronger than the delivered property).
#       A compliance file that only cites the NIS2 *legal mandate*
#       wording ("…interpret this as a tamper-resistant logging
#       mandate") with NO audit-chain self-claim marker is the
#       pre-attestation state — sub-check (c) is then vacuously
#       satisfied (the gate still enforces (a) ∧ (b) unconditionally).
#       This discriminator is necessary because `docs/metrics-
#       catalog.md` itself, and the present `docs/compliance/GDPR.md`,
#       legitimately quote the NIS2 "tamper-resistant logging"
#       *requirement* without claiming hort meets it via the
#       chain — that descriptive use must not false-positive the gate.
#
# Run by:
#   - `.github/workflows/ci.yml`            (g1-attestation-gate job)
#   - `.gitlab-ci.yml`                      (lint:g1-attestation-gate)
#   - locally before pushing compliance/catalog/audit-chain changes
#
# Implementation: pure bash + grep + test. No cargo, no DB, no network;
# repo-root-relative; idempotent; fast. Mirrors the house style of
# scripts/check-advisory-sync.sh / scripts/check-values-comments.sh.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "${repo_root}"

catalog="docs/metrics-catalog.md"
compliance_dir="docs/compliance"

fail() {
    echo "G1-attestation-gate: FAIL — $1" >&2
    echo "" >&2
    echo "  Gate: G1 attestation predicate (see docs/compliance/ for the governance home)." >&2
    exit 1
}

# ---------------------------------------------------------------------
# (a) Both G1 telemetry rows present in the metrics catalogue.
# ---------------------------------------------------------------------
if [[ ! -f "${catalog}" ]]; then
    fail "${catalog} not found (cannot verify the G1 telemetry rows)"
fi

# A "row" = the metric name appears inside a Markdown table cell
# (leading "| \`<name>\`"). Matching the back-ticked name in a table row
# avoids matching prose mentions of the metric elsewhere in the file.
catalog_has_row() {
    # $1 = metric name
    grep -Eq "^\|[[:space:]]*\`$1\`" "${catalog}"
}

if ! catalog_has_row "hort_event_chain_verify_total"; then
    fail "telemetry row \`hort_event_chain_verify_total\` missing from ${catalog}"
fi
if ! catalog_has_row "hort_advisory_ingest_count"; then
    fail "telemetry row \`hort_advisory_ingest_count\` missing from ${catalog}"
fi

# ---------------------------------------------------------------------
# (b) Named regression tests present by name in their source files.
# ---------------------------------------------------------------------
# Each entry: "<test fn name>|<source file>". Presence only — the suite
# is never executed by this gate.
named_tests=(
    "tampered_row_fails_verification|crates/hort-adapters-postgres/src/event_store.rs"
    "verify_tampered_row_is_broken|crates/hort-server/src/cli/verify_event_chain.rs"
    "iter_zip_entries_trusted_bulk_config_completes_all_for_large_archive|crates/hort-formats/src/archive_bounds.rs"
)

for entry in "${named_tests[@]}"; do
    fn_name="${entry%%|*}"
    src_file="${entry##*|}"
    if [[ ! -f "${src_file}" ]]; then
        fail "regression-test source ${src_file} not found (test \`${fn_name}\`)"
    fi
    # Anchor to a REAL definition line (optional indent / `pub` / `async`,
    # then `fn <name>` followed by `(` or `<` or whitespace). A line
    # starting with `//`/`///`/`*` (commented-out or doc) cannot match
    # the start-anchored `fn` token, so a test deleted-into-a-comment no
    # longer satisfies the predicate (post-review NIT).
    if ! grep -Eq "^[[:space:]]*(pub[[:space:]]+)?(async[[:space:]]+)?fn[[:space:]]+${fn_name}[[:space:](<]" "${src_file}"; then
        fail "named regression test \`fn ${fn_name}\` not found (as a real definition) in ${src_file}"
    fi
done

# ---------------------------------------------------------------------
# (c) Conditional wording guard on a published audit-chain self-attestation.
# ---------------------------------------------------------------------
# Chain-mechanism tokens that mark a *self-attestation* of the delivered
# property (as opposed to a descriptive cite of the NIS2 legal mandate).
chain_marker_re='tamper-evident|hash chain|signed checkpoint|offline verifier|verify-event-chain|hort_event_chain'
# The unqualified self-claim form is forbidden in a published attestation.
# Only an *affirmative* self-claim is forbidden; a *negated/disclaimer*
# use is the honest wording (the verbatim reference text is
# "It is **tamper-evident, not tamper-proof**" — that MUST pass), and a
# descriptive cite of the NIS2 *legal mandate* ("a tamper-resistant
# logging mandate", "the tamper-resistance requirement") is not a
# self-claim either. The detector strips, line-by-line, ONLY a
# **sanctioned-disclaimer allowlist** where a negation/comparison
# *directly governs* the forbidden token (post-review SHOULD-FIX: a wide
# negator-within-40-chars proximity blacklist false-passed an affirmative
# claim that merely contained an incidental negator — e.g. "there is no
# doubt the audit log is tamper-proof"). Sanctioned forms:
#   - the verbatim "tamper-evident, not tamper-{proof,resistant}";
#   - `not`/`never` directly governing the token (≤2 short intervening
#     words: "not tamper-proof", "is not yet tamper-proof");
#   - `rather than`/`instead of` (being) the token;
#   - the fixed NIS2-mandate descriptive phrases (separate re, below).
# `no`/`nor`/`neither`/`n't` are NOT honest-disclaimer markers on their
# own and are deliberately dropped. Anything still containing the bare
# token after stripping is an affirmative self-claim → FAIL. A tight
# allowlist may false-FAIL an unusual honest phrasing; that is the safe
# direction for a gate whose purpose is blocking over-strong attestation
# (the operator rephrases to the verbatim "tamper-evident, not tamper-proof"
# form, which is the wording they should publish anyway).
forbidden_token_re='tamper-proof|tamper-resistant'
negator_re='tamper-evident,?[[:space:]]+not[[:space:]]+(tamper-proof|tamper-resistant)|\b(not|never)[[:space:]]+([a-z]+[[:space:]]+){0,2}(tamper-proof|tamper-resistant)|\b(rather[[:space:]]+than|instead[[:space:]]+of)[[:space:]]+(being[[:space:]]+)?(tamper-proof|tamper-resistant)'
mandate_phrase_re='tamper-resistant logging mandate|the tamper-resistance requirement|interpret this as a tamper-resistant'

attestation_files=()
if [[ -d "${compliance_dir}" ]]; then
    # NUL-safe enumeration of regular files under docs/compliance/.
    while IFS= read -r -d '' f; do
        attestation_files+=("${f}")
    done < <(find "${compliance_dir}" -type f -print0)
fi

for f in "${attestation_files[@]}"; do
    has_tamper_word=0
    grep -Eq 'tamper-proof|tamper-resistant|tamper-evident' "${f}" && has_tamper_word=1
    [[ "${has_tamper_word}" -eq 0 ]] && continue   # no tamper wording at all

    has_chain_marker=0
    grep -Eiq "${chain_marker_re}" "${f}" && has_chain_marker=1
    if [[ "${has_chain_marker}" -eq 0 ]]; then
        # tamper word(s) but no audit-chain self-claim marker → this file
        # only cites the NIS2 legal mandate, not hort's own
        # delivered property. Pre-attestation state: (c) vacuous.
        continue
    fi

    # This file publishes an audit-chain self-attestation. Enforce the
    # honesty caveat: the qualified form MUST be present and the
    # unqualified self-claim MUST be absent.
    if ! grep -q 'tamper-evident' "${f}"; then
        fail "${f} publishes an audit-chain attestation but does not use \
the qualified \"tamper-evident\" wording (honesty caveat)."
    fi
    # Per-line scan: drop honest negated/disclaimer uses and the fixed
    # NIS2-mandate descriptive phrases, then see if a bare affirmative
    # self-claim token survives. `grep -niE` gives "<lineno>:<text>".
    bad_lines=""
    while IFS= read -r numbered; do
        [[ -z "${numbered}" ]] && continue
        stripped="$(printf '%s' "${numbered}" \
            | sed -E "s/${negator_re}//Ig" \
            | sed -E "s/${mandate_phrase_re}//Ig")"
        if printf '%s' "${stripped}" | grep -Eiq "${forbidden_token_re}"; then
            bad_lines+="${numbered}"$'\n'
        fi
    done < <(grep -niE "${forbidden_token_re}" "${f}" || true)

    if [[ -n "${bad_lines}" ]]; then
        fail "$(printf '%s publishes an audit-chain attestation with an affirmative unqualified self-claim "tamper-proof"/"tamper-resistant" — the delivered property is tamper-EVIDENT; only a negated/disclaimer or NIS2-mandate-citation use is honest:\n%s' "${f}" "$(printf '%s' "${bad_lines}" | head -5)")"
    fi
done

echo "G1-attestation-gate: OK (catalog telemetry rows present; named regression tests present; docs/compliance attestation wording within the tamper-evident bar)."
exit 0
