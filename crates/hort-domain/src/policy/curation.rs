//! Pre-storage curation evaluator.
//!
//! `evaluate_curation` is the pure decision function the
//! [`crate::ports::curation_rule_repository::CurationRuleRepository`]-fed
//! ingest gate calls before bytes touch CAS. First-match-wins over a
//! repository's curation rule list, returning a [`CurationOutcome`] that
//! the application layer translates into a tracing event and (for the
//! `Block` arm) a [`crate::error::DomainError::CurationBlocked`] return.
//!
//! ## Match algorithm
//!
//! For each rule in declaration order:
//!
//! 1. **Format gate** —
//!    - `rule.format == None` (the YAML `any` keyword) → continue to
//!      pattern check.
//!    - `rule.format == Some(f)` → continue iff `coords.format == f`.
//!
//!    `ArtifactCoords::format` is already a typed
//!    [`crate::entities::repository::RepositoryFormat`]
//!    (retyped from `String`); no parse is needed at the
//!    evaluator boundary. An earlier draft described a
//!    [`std::str::FromStr`] hop because an older draft of `ArtifactCoords`
//!    carried `format: String` — that branch is unreachable and the
//!    "defensive passthrough on parse failure" clause collapses to the
//!    no-op rule-mismatch path.
//!
//! 2. **Pattern gate** — glob-style `*`-matcher (see below) of
//!    `rule.package_pattern` against `coords.name`. Match → return the
//!    rule's action; mismatch → continue to the next rule.
//!
//! After every rule has been checked without a match, return
//! [`CurationOutcome::Allow`].
//!
//! ## Action mapping
//!
//! - [`CurationRuleAction::Block`] → [`CurationOutcome::Block`] —
//!   `IngestUseCase::ingest` aborts with `DomainError::CurationBlocked`.
//! - [`CurationRuleAction::Warn`] → [`CurationOutcome::Warn`] —
//!   ingest continues; the application layer logs `tracing::warn!`.
//! - [`CurationRuleAction::Allow`] → [`CurationOutcome::Allow`] — the
//!   matched rule is an explicit allow-list override (escape hatch for a
//!   broader `Block` rule). Returning `Allow` immediately preserves
//!   first-match-wins semantics: a later `Block` cannot revisit a package
//!   the operator already whitelisted.
//!
//! ## Pattern matcher
//!
//! Reuses the policy/exclusion convention of an inline
//! `*`-only glob — `*` matches any (possibly empty) substring; every
//! other character is literal. No character classes, no anchors. `globset`
//! is not pulled into `hort-domain` because the matcher requirement is the
//! same shape as exclusion's, and a second tiny matcher beats a heavyweight
//! glob/regex dependency in the domain crate.
//!
//! ### Defensive passthrough on malformed patterns
//!
//! The matcher cannot fail to compile (every byte sequence is a legal
//! `*`-glob), so there is no compile-error branch to guard. The
//! defensive-`Allow`-on-compile-error posture is preserved in spirit:
//! any matcher that returns
//! `false` for a given `(pattern, name)` pair simply continues to the next
//! rule, which collapses to `Allow` if no rule matches. The gitops
//! apply-time spec validation rejects empty / over-long patterns at YAML
//! load, so a runtime "malformed pattern" is unreachable in practice.

use uuid::Uuid;

use crate::entities::curation_rule::{CurationRule, CurationRuleAction};
use crate::types::ArtifactCoords;

// ---------------------------------------------------------------------------
// Shared first-match-wins helper
// ---------------------------------------------------------------------------

/// Returns the first rule (in declaration order) whose format predicate
/// AND package-pattern predicate both match `coords`. Returns `None`
/// when no rule matches.
///
/// This is the shared core of [`evaluate_curation`] (ingest gate) and
/// [`evaluate_curation_retroactive`] (apply-pipeline retroactive
/// pass) — promoted out of `evaluate_curation`'s
/// loop body so both decision points iterate identically. Each entry
/// point maps the matched rule's [`CurationRuleAction`] to its own
/// outcome enum at the call site.
fn first_matching_rule<'a>(
    coords: &ArtifactCoords,
    rules: &'a [CurationRule],
) -> Option<&'a CurationRule> {
    rules.iter().find(|rule| {
        format_matches(rule, coords) && pattern_matches(&rule.package_pattern, &coords.name)
    })
}

// ---------------------------------------------------------------------------
// CurationOutcome
// ---------------------------------------------------------------------------

/// Result of [`evaluate_curation`].
///
/// `Block` carries the matched rule's `id` so the audit-event hook in
/// item 7 (`StreamCategory::Curation` + `CurationApplied`) can stamp the
/// rule ID without re-resolving by name. `Warn` does not carry the id
/// today because no event is emitted at ingest in v1 (per backlog: "v1
/// does NOT emit CurationApplied events at ingest time"); the rule name
/// is sufficient for the `tracing::warn!` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CurationOutcome {
    /// No rule matched, or the matched rule was an explicit
    /// allow-list override. Ingest proceeds without tracing emission.
    Allow,
    /// A rule with action `Warn` matched. Ingest proceeds; the
    /// application layer logs `tracing::warn!` with `rule_name` and
    /// `reason`.
    Warn { rule_name: String, reason: String },
    /// A rule with action `Block` matched. Ingest aborts; the
    /// application layer returns
    /// [`crate::error::DomainError::CurationBlocked`] carrying the
    /// same `rule_name`, `rule_id`, and `reason`.
    Block {
        rule_name: String,
        rule_id: Uuid,
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// evaluate_curation
// ---------------------------------------------------------------------------

/// Decide whether the artifact identified by `coords` may be ingested
/// under the given `rules`.
///
/// First-match-wins in the order rules appear in the slice. Caller
/// typically passes the output of
/// [`crate::ports::curation_rule_repository::CurationRuleRepository::list_for_repo`]
/// directly — the repository materialises rules in their gitops-declared
/// order via the `repository_curation_rules` junction.
///
/// Empty `rules` → fast-path [`CurationOutcome::Allow`] (the loop body
/// never runs).
pub fn evaluate_curation(coords: &ArtifactCoords, rules: &[CurationRule]) -> CurationOutcome {
    match first_matching_rule(coords, rules) {
        None => CurationOutcome::Allow,
        Some(rule) => match rule.action {
            CurationRuleAction::Block => CurationOutcome::Block {
                rule_name: rule.name.clone(),
                rule_id: rule.id,
                reason: rule.reason.clone(),
            },
            CurationRuleAction::Warn => CurationOutcome::Warn {
                rule_name: rule.name.clone(),
                reason: rule.reason.clone(),
            },
            CurationRuleAction::Allow => CurationOutcome::Allow,
        },
    }
}

// ---------------------------------------------------------------------------
// RetroactiveCurationOutcome
// ---------------------------------------------------------------------------

/// Result of [`evaluate_curation_retroactive`].
///
/// Returned during the apply-pipeline pass over previously-active
/// artifacts. The outcome distinguishes from
/// [`CurationOutcome`] in two ways:
///
/// 1. **`Warn` carries `rule_id`.** The retroactive path emits a
///    `CurationApplied { trigger: Retroactive, action: Warn, rule_id, ... }`
///    event on the per-repo curation stream — the rule id is required
///    on the wire, unlike the ingest-time `Warn` which only logs.
/// 2. **No explicit `Allow` value carrying rule context.** A retroactive
///    `Allow` is indistinguishable from "no rule matched" — both mean
///    "do nothing" — so the variant collapses to `NoChange`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetroactiveCurationOutcome {
    /// No rule matched, or the matched rule was `Allow`. No events
    /// emitted; no state transition.
    NoChange,
    /// A `Warn` rule matched. Emit `CurationApplied { action: Warn,
    /// trigger: Retroactive, ... }` on the per-repo curation stream.
    /// Artifact state is NOT changed — `Warn` is informational.
    RetroWarn {
        rule_name: String,
        reason: String,
        rule_id: Uuid,
    },
    /// A `Block` rule matched. Emit `CurationApplied { action: Block,
    /// trigger: Retroactive, ... }` on the per-repo curation stream
    /// AND `ArtifactRejected { rejected_by: CurationRetroactive {
    /// rule_id }, reason }` on the artifact's stream — atomically.
    RetroBlock {
        rule_name: String,
        reason: String,
        rule_id: Uuid,
    },
}

// ---------------------------------------------------------------------------
// evaluate_curation_retroactive
// ---------------------------------------------------------------------------

/// Decide what retroactive transition (if any) applies to an artifact
/// already-active in a repository whose curation rule set just changed.
///
/// First-match-wins over `rules` — the same iteration as
/// [`evaluate_curation`], shared via [`first_matching_rule`]. This is
/// the load-bearing property: an artifact whose ingest passed under the
/// old rule set must not be reachable under a different decision than
/// the post-apply ingest gate would have produced. The shared helper
/// keeps the two evaluators in lockstep.
///
/// `CurationRule` has no expiry, so this evaluator takes no `now`
/// parameter — every rule is in force for the duration of the apply.
///
/// Empty `rules` → fast-path [`RetroactiveCurationOutcome::NoChange`].
pub fn evaluate_curation_retroactive(
    coords: &ArtifactCoords,
    rules: &[CurationRule],
) -> RetroactiveCurationOutcome {
    match first_matching_rule(coords, rules) {
        None => RetroactiveCurationOutcome::NoChange,
        Some(rule) => match rule.action {
            CurationRuleAction::Block => RetroactiveCurationOutcome::RetroBlock {
                rule_name: rule.name.clone(),
                reason: rule.reason.clone(),
                rule_id: rule.id,
            },
            CurationRuleAction::Warn => RetroactiveCurationOutcome::RetroWarn {
                rule_name: rule.name.clone(),
                reason: rule.reason.clone(),
                rule_id: rule.id,
            },
            CurationRuleAction::Allow => RetroactiveCurationOutcome::NoChange,
        },
    }
}

/// Returns `true` when the rule's format predicate accepts `coords.format`.
///
/// `rule.format == None` is the YAML `any` keyword — match every format.
/// `Some(f)` restricts to artifacts whose typed
/// [`crate::entities::repository::RepositoryFormat`] equals `f`.
fn format_matches(rule: &CurationRule, coords: &ArtifactCoords) -> bool {
    match &rule.format {
        None => true,
        Some(f) => *f == coords.format,
    }
}

/// Tiny `*`-only glob matcher. Mirrors the exclusion-evaluator
/// matcher — `*` matches any (possibly empty)
/// substring; every other character is literal.
fn pattern_matches(pattern: &str, name: &str) -> bool {
    matches_inner(pattern.as_bytes(), name.as_bytes())
}

fn matches_inner(pattern: &[u8], name: &[u8]) -> bool {
    if pattern.is_empty() {
        return name.is_empty();
    }
    if pattern[0] == b'*' {
        for split in 0..=name.len() {
            if matches_inner(&pattern[1..], &name[split..]) {
                return true;
            }
        }
        return false;
    }
    if name.is_empty() {
        return false;
    }
    if pattern[0] != name[0] {
        return false;
    }
    matches_inner(&pattern[1..], &name[1..])
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::curation_rule::CurationRule;
    use crate::entities::managed_by::ManagedBy;
    use crate::entities::repository::RepositoryFormat;

    fn coords(name: &str, format: RepositoryFormat) -> ArtifactCoords {
        ArtifactCoords {
            name: name.into(),
            name_as_published: name.into(),
            version: Some("1.0.0".into()),
            path: format!("dist/{name}/{name}-1.0.0.tgz"),
            format,
            metadata: serde_json::Value::Null,
        }
    }

    fn rule(
        name: &str,
        format: Option<RepositoryFormat>,
        pattern: &str,
        action: CurationRuleAction,
    ) -> CurationRule {
        CurationRule {
            id: Uuid::new_v4(),
            name: name.into(),
            format,
            package_pattern: pattern.into(),
            action,
            reason: format!("reason-for-{name}"),
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0xab; 32]),
        }
    }

    // ---- empty rules / no-match base case ---------------------------------

    #[test]
    fn empty_rules_returns_allow() {
        let c = coords("xz-utils", RepositoryFormat::Pypi);
        assert_eq!(evaluate_curation(&c, &[]), CurationOutcome::Allow);
    }

    #[test]
    fn no_rule_matches_returns_allow() {
        let c = coords("xz-utils", RepositoryFormat::Pypi);
        let rules = [
            rule(
                "block-event-stream",
                None,
                "event-stream",
                CurationRuleAction::Block,
            ),
            rule(
                "block-leftpad",
                Some(RepositoryFormat::Npm),
                "left-pad",
                CurationRuleAction::Block,
            ),
        ];
        assert_eq!(evaluate_curation(&c, &rules), CurationOutcome::Allow);
    }

    // ---- format gate ------------------------------------------------------

    #[test]
    fn any_format_rule_matches_any_format() {
        let r = rule("block-xz", None, "xz-*", CurationRuleAction::Block);
        for fmt in [
            RepositoryFormat::Pypi,
            RepositoryFormat::Npm,
            RepositoryFormat::Cargo,
            RepositoryFormat::Oci,
        ] {
            let label = format!("{fmt:?}");
            let c = coords("xz-utils", fmt);
            match evaluate_curation(&c, std::slice::from_ref(&r)) {
                CurationOutcome::Block { rule_name, .. } => assert_eq!(rule_name, "block-xz"),
                other => panic!("expected Block for format {label}, got {other:?}"),
            }
        }
    }

    #[test]
    fn format_specific_rule_matches_only_that_format() {
        let r = rule(
            "block-pypi-xz",
            Some(RepositoryFormat::Pypi),
            "xz-*",
            CurationRuleAction::Block,
        );
        // Same package name, different format — the rule does not fire.
        let c_npm = coords("xz-utils", RepositoryFormat::Npm);
        assert_eq!(
            evaluate_curation(&c_npm, std::slice::from_ref(&r)),
            CurationOutcome::Allow
        );
        // Pypi → fires.
        let c_pypi = coords("xz-utils", RepositoryFormat::Pypi);
        assert!(matches!(
            evaluate_curation(&c_pypi, std::slice::from_ref(&r)),
            CurationOutcome::Block { .. }
        ));
    }

    // ---- pattern gate -----------------------------------------------------

    #[test]
    fn pattern_exact_string_matches() {
        let r = rule(
            "block-event-stream",
            None,
            "event-stream",
            CurationRuleAction::Block,
        );
        let c = coords("event-stream", RepositoryFormat::Npm);
        assert!(matches!(
            evaluate_curation(&c, std::slice::from_ref(&r)),
            CurationOutcome::Block { .. }
        ));
        // Substring is NOT a match — the matcher requires complete
        // string equivalence under the `*` glob rules.
        let c2 = coords("event-stream-fork", RepositoryFormat::Npm);
        assert_eq!(
            evaluate_curation(&c2, std::slice::from_ref(&r)),
            CurationOutcome::Allow
        );
    }

    #[test]
    fn pattern_star_suffix_matches_prefix_family() {
        let r = rule("block-xz-family", None, "xz-*", CurationRuleAction::Block);
        let c = coords("xz-utils", RepositoryFormat::Pypi);
        assert!(matches!(
            evaluate_curation(&c, std::slice::from_ref(&r)),
            CurationOutcome::Block { .. }
        ));
        let c_no = coords("lzma", RepositoryFormat::Pypi);
        assert_eq!(
            evaluate_curation(&c_no, std::slice::from_ref(&r)),
            CurationOutcome::Allow
        );
    }

    #[test]
    fn pattern_lone_star_matches_any_name() {
        let r = rule("warn-everything", None, "*", CurationRuleAction::Warn);
        for name in ["a", "left-pad", "django", "example-with-dashes"] {
            let c = coords(name, RepositoryFormat::Generic);
            match evaluate_curation(&c, std::slice::from_ref(&r)) {
                CurationOutcome::Warn { rule_name, .. } => {
                    assert_eq!(rule_name, "warn-everything");
                }
                other => panic!("expected Warn for {name}, got {other:?}"),
            }
        }
    }

    // ---- first-match-wins -------------------------------------------------

    #[test]
    fn first_match_wins_block_before_warn() {
        let rules = [
            rule("block-xz", None, "xz-*", CurationRuleAction::Block),
            rule("warn-xz", None, "xz-*", CurationRuleAction::Warn),
        ];
        let c = coords("xz-utils", RepositoryFormat::Pypi);
        match evaluate_curation(&c, &rules) {
            CurationOutcome::Block { rule_name, .. } => assert_eq!(rule_name, "block-xz"),
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn first_match_wins_warn_before_block() {
        let rules = [
            rule("warn-xz", None, "xz-*", CurationRuleAction::Warn),
            rule("block-xz", None, "xz-*", CurationRuleAction::Block),
        ];
        let c = coords("xz-utils", RepositoryFormat::Pypi);
        match evaluate_curation(&c, &rules) {
            CurationOutcome::Warn { rule_name, .. } => assert_eq!(rule_name, "warn-xz"),
            other => panic!("expected Warn, got {other:?}"),
        }
    }

    #[test]
    fn first_match_wins_allow_override_skips_later_block() {
        // An explicit Allow rule on a specific package short-circuits a
        // later broader Block — the operator's allow-list semantics from
        // the prior curation design.
        let rules = [
            rule(
                "allow-xz-utils-stable",
                None,
                "xz-utils",
                CurationRuleAction::Allow,
            ),
            rule("block-xz-family", None, "xz-*", CurationRuleAction::Block),
        ];
        let c = coords("xz-utils", RepositoryFormat::Pypi);
        assert_eq!(evaluate_curation(&c, &rules), CurationOutcome::Allow);
    }

    #[test]
    fn first_match_wins_skips_to_next_rule_on_format_mismatch() {
        // First rule is format-specific and does NOT match — second rule
        // (any-format) does, so the outcome is the second rule's.
        let rules = [
            rule(
                "block-pypi-xz",
                Some(RepositoryFormat::Pypi),
                "xz-*",
                CurationRuleAction::Block,
            ),
            rule("warn-any-xz", None, "xz-*", CurationRuleAction::Warn),
        ];
        let c = coords("xz-utils", RepositoryFormat::Npm);
        match evaluate_curation(&c, &rules) {
            CurationOutcome::Warn { rule_name, .. } => assert_eq!(rule_name, "warn-any-xz"),
            other => panic!("expected Warn, got {other:?}"),
        }
    }

    #[test]
    fn first_match_wins_skips_to_next_rule_on_pattern_mismatch() {
        // First rule's pattern does NOT match coords.name; the loop
        // advances to the second rule which does match.
        let rules = [
            rule("block-django", None, "django", CurationRuleAction::Block),
            rule("warn-flask", None, "flask", CurationRuleAction::Warn),
        ];
        let c = coords("flask", RepositoryFormat::Pypi);
        match evaluate_curation(&c, &rules) {
            CurationOutcome::Warn { rule_name, .. } => assert_eq!(rule_name, "warn-flask"),
            other => panic!("expected Warn, got {other:?}"),
        }
    }

    // ---- Block carries id + reason ----------------------------------------

    #[test]
    fn block_carries_rule_id_and_reason() {
        let r = rule("block-xz", None, "xz-*", CurationRuleAction::Block);
        let expected_id = r.id;
        let expected_reason = r.reason.clone();
        let c = coords("xz-utils", RepositoryFormat::Pypi);
        match evaluate_curation(&c, std::slice::from_ref(&r)) {
            CurationOutcome::Block {
                rule_name,
                rule_id,
                reason,
            } => {
                assert_eq!(rule_name, "block-xz");
                assert_eq!(rule_id, expected_id);
                assert_eq!(reason, expected_reason);
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn warn_carries_rule_name_and_reason() {
        let r = rule(
            "warn-event-stream",
            None,
            "event-stream",
            CurationRuleAction::Warn,
        );
        let expected_reason = r.reason.clone();
        let c = coords("event-stream", RepositoryFormat::Npm);
        match evaluate_curation(&c, std::slice::from_ref(&r)) {
            CurationOutcome::Warn { rule_name, reason } => {
                assert_eq!(rule_name, "warn-event-stream");
                assert_eq!(reason, expected_reason);
            }
            other => panic!("expected Warn, got {other:?}"),
        }
    }

    // ---- Defensive: empty pattern only matches empty name -----------------

    #[test]
    fn empty_pattern_matches_only_empty_name() {
        // The gitops YAML admission validates package_pattern non-empty
        // at apply time, so this is unreachable in practice — but the
        // matcher must still terminate sensibly. Verifies the inner
        // matcher's base case and confirms the defensive-passthrough
        // posture: an unmatched (non-empty) name → Allow.
        let r = rule("block-empty", None, "", CurationRuleAction::Block);
        let c = coords("anything", RepositoryFormat::Generic);
        assert_eq!(
            evaluate_curation(&c, std::slice::from_ref(&r)),
            CurationOutcome::Allow
        );

        let c_empty = coords("", RepositoryFormat::Generic);
        match evaluate_curation(&c_empty, std::slice::from_ref(&r)) {
            CurationOutcome::Block { rule_name, .. } => assert_eq!(rule_name, "block-empty"),
            other => panic!("expected Block on empty-name match, got {other:?}"),
        }
    }

    // ---- evaluate_curation_retroactive ------------------------------------

    #[test]
    fn retro_empty_rules_returns_no_change() {
        let c = coords("xz-utils", RepositoryFormat::Pypi);
        assert_eq!(
            evaluate_curation_retroactive(&c, &[]),
            RetroactiveCurationOutcome::NoChange
        );
    }

    #[test]
    fn retro_no_match_returns_no_change() {
        let c = coords("xz-utils", RepositoryFormat::Pypi);
        let rules = [rule(
            "block-event-stream",
            None,
            "event-stream",
            CurationRuleAction::Block,
        )];
        assert_eq!(
            evaluate_curation_retroactive(&c, &rules),
            RetroactiveCurationOutcome::NoChange
        );
    }

    #[test]
    fn retro_match_allow_returns_no_change() {
        let c = coords("xz-utils", RepositoryFormat::Pypi);
        let rules = [rule(
            "allow-xz",
            None,
            "xz-utils",
            CurationRuleAction::Allow,
        )];
        assert_eq!(
            evaluate_curation_retroactive(&c, &rules),
            RetroactiveCurationOutcome::NoChange
        );
    }

    #[test]
    fn retro_match_warn_returns_retro_warn() {
        let r = rule("warn-xz", None, "xz-*", CurationRuleAction::Warn);
        let expected_id = r.id;
        let expected_reason = r.reason.clone();
        let c = coords("xz-utils", RepositoryFormat::Pypi);
        match evaluate_curation_retroactive(&c, std::slice::from_ref(&r)) {
            RetroactiveCurationOutcome::RetroWarn {
                rule_name,
                reason,
                rule_id,
            } => {
                assert_eq!(rule_name, "warn-xz");
                assert_eq!(reason, expected_reason);
                assert_eq!(rule_id, expected_id);
            }
            other => panic!("expected RetroWarn, got {other:?}"),
        }
    }

    #[test]
    fn retro_match_block_returns_retro_block() {
        let r = rule("block-xz", None, "xz-*", CurationRuleAction::Block);
        let expected_id = r.id;
        let expected_reason = r.reason.clone();
        let c = coords("xz-utils", RepositoryFormat::Pypi);
        match evaluate_curation_retroactive(&c, std::slice::from_ref(&r)) {
            RetroactiveCurationOutcome::RetroBlock {
                rule_name,
                reason,
                rule_id,
            } => {
                assert_eq!(rule_name, "block-xz");
                assert_eq!(reason, expected_reason);
                assert_eq!(rule_id, expected_id);
            }
            other => panic!("expected RetroBlock, got {other:?}"),
        }
    }

    #[test]
    fn retro_first_match_wins_block_before_warn() {
        let rules = [
            rule("block-xz", None, "xz-*", CurationRuleAction::Block),
            rule("warn-xz", None, "xz-*", CurationRuleAction::Warn),
        ];
        let c = coords("xz-utils", RepositoryFormat::Pypi);
        match evaluate_curation_retroactive(&c, &rules) {
            RetroactiveCurationOutcome::RetroBlock { rule_name, .. } => {
                assert_eq!(rule_name, "block-xz");
            }
            other => panic!("expected RetroBlock, got {other:?}"),
        }
    }

    #[test]
    fn retro_first_match_wins_allow_overrides_later_block() {
        // Mirror of the ingest-gate test: an explicit Allow rule earlier
        // in the slice short-circuits a later Block. Retroactive
        // evaluation must collapse this to NoChange — the allow-list
        // wins, the artifact stays as-is.
        let rules = [
            rule(
                "allow-xz-utils-stable",
                None,
                "xz-utils",
                CurationRuleAction::Allow,
            ),
            rule("block-xz-family", None, "xz-*", CurationRuleAction::Block),
        ];
        let c = coords("xz-utils", RepositoryFormat::Pypi);
        assert_eq!(
            evaluate_curation_retroactive(&c, &rules),
            RetroactiveCurationOutcome::NoChange
        );
    }

    #[test]
    fn retro_first_match_wins_skips_format_mismatch() {
        let rules = [
            rule(
                "block-pypi-xz",
                Some(RepositoryFormat::Pypi),
                "xz-*",
                CurationRuleAction::Block,
            ),
            rule("warn-any-xz", None, "xz-*", CurationRuleAction::Warn),
        ];
        let c = coords("xz-utils", RepositoryFormat::Npm);
        match evaluate_curation_retroactive(&c, &rules) {
            RetroactiveCurationOutcome::RetroWarn { rule_name, .. } => {
                assert_eq!(rule_name, "warn-any-xz");
            }
            other => panic!("expected RetroWarn, got {other:?}"),
        }
    }

    /// Decision parity: the shared `first_matching_rule` helper guarantees
    /// `evaluate_curation` and `evaluate_curation_retroactive` agree on
    /// which rule fires for the same `(coords, rules)` input. This test
    /// is the regression guard against the two evaluators diverging in
    /// future edits.
    #[test]
    fn retro_and_ingest_evaluators_agree_on_first_match() {
        let rules = [
            rule(
                "allow-django",
                Some(RepositoryFormat::Pypi),
                "django",
                CurationRuleAction::Allow,
            ),
            rule(
                "warn-flask",
                Some(RepositoryFormat::Pypi),
                "flask",
                CurationRuleAction::Warn,
            ),
            rule("block-xz", None, "xz-*", CurationRuleAction::Block),
        ];

        // django + pypi → Allow / NoChange
        let c1 = coords("django", RepositoryFormat::Pypi);
        assert_eq!(evaluate_curation(&c1, &rules), CurationOutcome::Allow);
        assert_eq!(
            evaluate_curation_retroactive(&c1, &rules),
            RetroactiveCurationOutcome::NoChange
        );

        // flask + pypi → Warn / RetroWarn (same rule_name)
        let c2 = coords("flask", RepositoryFormat::Pypi);
        let ingest = evaluate_curation(&c2, &rules);
        let retro = evaluate_curation_retroactive(&c2, &rules);
        let CurationOutcome::Warn {
            rule_name: ingest_name,
            ..
        } = ingest
        else {
            panic!("expected ingest Warn, got {ingest:?}");
        };
        let RetroactiveCurationOutcome::RetroWarn {
            rule_name: retro_name,
            ..
        } = retro
        else {
            panic!("expected retro Warn, got {retro:?}");
        };
        assert_eq!(ingest_name, retro_name);

        // xz-utils + npm → Block / RetroBlock (same rule_name + rule_id)
        let c3 = coords("xz-utils", RepositoryFormat::Npm);
        let ingest = evaluate_curation(&c3, &rules);
        let retro = evaluate_curation_retroactive(&c3, &rules);
        let CurationOutcome::Block {
            rule_name: ingest_name,
            rule_id: ingest_id,
            ..
        } = ingest
        else {
            panic!("expected ingest Block, got {ingest:?}");
        };
        let RetroactiveCurationOutcome::RetroBlock {
            rule_name: retro_name,
            rule_id: retro_id,
            ..
        } = retro
        else {
            panic!("expected retro Block, got {retro:?}");
        };
        assert_eq!(ingest_name, retro_name);
        assert_eq!(ingest_id, retro_id);
    }

    #[test]
    fn retro_outcome_clone_and_eq() {
        let a = RetroactiveCurationOutcome::NoChange;
        let b = a.clone();
        assert_eq!(a, b);

        let id = Uuid::new_v4();
        let w1 = RetroactiveCurationOutcome::RetroWarn {
            rule_name: "r".into(),
            reason: "x".into(),
            rule_id: id,
        };
        let w2 = w1.clone();
        assert_eq!(w1, w2);

        let bl1 = RetroactiveCurationOutcome::RetroBlock {
            rule_name: "r".into(),
            reason: "x".into(),
            rule_id: id,
        };
        let bl2 = bl1.clone();
        assert_eq!(bl1, bl2);

        assert_ne!(a, w1);
        assert_ne!(w1, bl1);
    }

    // ---- Outcome derives --------------------------------------------------

    #[test]
    fn outcome_clone_and_eq() {
        let a = CurationOutcome::Allow;
        let b = a.clone();
        assert_eq!(a, b);

        let w1 = CurationOutcome::Warn {
            rule_name: "r".into(),
            reason: "x".into(),
        };
        let w2 = w1.clone();
        assert_eq!(w1, w2);

        let id = Uuid::new_v4();
        let bl1 = CurationOutcome::Block {
            rule_name: "r".into(),
            rule_id: id,
            reason: "x".into(),
        };
        let bl2 = bl1.clone();
        assert_eq!(bl1, bl2);

        // Cross-variant inequality.
        assert_ne!(a, w1);
        assert_ne!(w1, bl1);
    }
}
