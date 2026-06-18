//! `kind: PermissionGrantLintConfig` schema, parser, and per-spec
//! validation (ADR 0012 — additive-claims RBAC).
//!
//! ## Why this kind exists
//!
//! The apply-config grant linter (`hort_app::lint::permission_grants`)
//! ships with a secure-by-default `reject` posture and an *operator
//! opt-out* surface (`LintConfig.single_claim_allowlist` + per-rule
//! downgrade actions). This module supplies the **doc-faithful gitops
//! surface**: the schema + per-envelope validation only. The
//! apply-ordering and composition wiring that make a resolved config
//! effective lives in `ApplyConfigUseCase`.
//!
//! ## Singleton kind
//!
//! Every other gitops kind is list/instance (a `Vec<Envelope<…>>` in
//! [`crate::desired::DesiredState`]). `PermissionGrantLintConfig` is
//! the **first singleton** — there is at most one envelope
//! cluster-wide. A second envelope is a *named* apply-time validation
//! error ([`crate::error::ValidationError::SingletonConflict`]), never
//! a silent last-wins. The singleton-count check is enforced at the
//! [`crate::desired::DesiredState`] layer (where multiple files are
//! absorbed); this module's [`validate_lint_config`] enforces the
//! per-envelope rules.
//!
//! ## Downgrade-only
//!
//! A rule's design-default action is the **ceiling**. This surface may
//! only *relax* a rule (`reject` → `warn` / `pass`); an override that
//! restates the default (or would raise strictness) is rejected as a
//! no-op-that-must-be-explicit: an operator must not believe they
//! hardened something they did not, and a no-op override is dead config
//! that should be removed, not silently accepted.
//!
//! No env-var path, no global `warn` switch — the only escape hatch is
//! this explicit, diff-visible, audited envelope.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::envelope::{Envelope, Kind};
use crate::error::{ParseError, ValidationError};

/// Operator-facing rule action, the gitops mirror of
/// `hort_app::lint::RuleAction`.
///
/// Carried as its own enum (not the `hort-app` type) because `hort-config`
/// is the zero-I/O leaf crate and must never depend on `hort-app`
/// (`hort-app` already depends on `hort-config`; the reverse edge would be
/// a dependency cycle — see `repository.rs` module doc). The
/// `From<&PermissionGrantLintConfigSpec> for LintConfig` conversion
/// therefore lives in `hort-app`, where both types are reachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleActionSpec {
    /// The rule does not fire / the operator opted this shape out.
    Pass,
    /// Flagged; the apply continues, CI surfaces it.
    Warn,
    /// The apply fails strict-atomic.
    Reject,
}

impl RuleActionSpec {
    /// Strictness rank — `Reject` (2) > `Warn` (1) > `Pass` (0). Used
    /// by the downgrade-only validator: an override is accepted only
    /// when it is *strictly looser* than the rule's design default.
    fn rank(self) -> u8 {
        match self {
            Self::Pass => 0,
            Self::Warn => 1,
            Self::Reject => 2,
        }
    }
}

/// Per-rule downgrade knobs — the gitops mirror of
/// `hort_app::lint::RuleOverrides`.
///
/// Only the three rules with a tunable action are present;
/// `claim-name-collision` is fixed at `reject` (no downgrade knob)
/// and is deliberately absent from this struct. A present field
/// may only *downgrade* its rule (validated in
/// [`validate_lint_config`]); absent ⇒ the secure design default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleOverridesSpec {
    /// Downgrade for `single-claim-grant` (applies to grants whose
    /// sole claim is not allowlisted). Design default: `reject`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub single_claim_grant: Option<RuleActionSpec>,
    /// Downgrade for `direct-user-grant-without-justification`'s
    /// high-privilege arm. Design default: `reject` (the low-privilege
    /// arm is hard-coded `warn` and has no knob).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_user_grant: Option<RuleActionSpec>,
    /// Downgrade for `wildcard-repo-non-admin`. Design default:
    /// `reject`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wildcard_repo_non_admin: Option<RuleActionSpec>,
}

/// Shape of a `kind: PermissionGrantLintConfig` YAML body.
///
/// Carries the **full** `LintConfig` opt-out surface — the allowlist
/// **and** the per-rule downgrade actions — not allowlist-only. An
/// allowlist-only kind would re-create the same defect. `camelCase` +
/// `deny_unknown_fields` so a typo surfaces
/// immediately rather than silently coercing to a default (the same
/// footgun-free posture every other spec carries).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionGrantLintConfigSpec {
    /// Claims explicitly blessed as legitimate single-claim grants. A
    /// `single-claim-grant` whose sole claim is in this list
    /// downgrades to `pass` **for that claim only** — the per-claim
    /// opt-out, not a global `warn`. Empty by default (secure: every
    /// single-claim grant rejects until allowlisted). Each entry must
    /// be a syntactically valid claim name and must NOT be a reserved
    /// name (`admin` / `service_account` / `cli_session`) — see
    /// [`validate_lint_config`].
    #[serde(default)]
    pub single_claim_allowlist: Vec<String>,
    /// Per-rule downgrade. Absent ⇒ the secure default for that rule.
    /// A rule may only be *downgraded* (`reject` → `warn` / `pass`);
    /// the validator rejects an override that restates or raises
    /// strictness (no-op; must be explicit).
    #[serde(default)]
    pub rule_overrides: RuleOverridesSpec,
}

/// Reserved claim names an allowlist entry must NOT be.
///
/// Broader than `hort_app::lint::RESERVED_CLAIM_NAMES` (which is
/// `{service_account, cli_session}` for the *claim-name-collision*
/// rule — `admin` is excluded there because mapping an IdP group to
/// `admin` is the OIDC-admin onboarding path). Allowlisting is a
/// different surface: blessing a **single-claim** grant whose claim is
/// `admin` would turn an unscoped `admin` claims-grant into a passing
/// wildcard-admin escalation, the exact privileged-escalation shape
/// the linter exists to block. `service_account` / `cli_session` are
/// token-kind discriminators that must never be claims at all. All
/// three are therefore forbidden allowlist entries.
pub const RESERVED_ALLOWLIST_NAMES: &[&str] = &["admin", "service_account", "cli_session"];

/// A claim name is *syntactically valid* iff it is non-blank after
/// trimming and contains no internal ASCII whitespace.
///
/// This mirrors the de-facto contract every other claim surface in the
/// crate enforces: `parse_claim_mapping` rejects a blank `claim`, and
/// `validate_permission_grant` rejects a blank `required[*]` entry. A
/// claim name carrying embedded whitespace would never match a JWT
/// `groups` entry verbatim (`hort-app::rbac::resolve_claims` compares
/// exactly), so an allowlist entry like `"team alpha"` is dead config
/// and an operator footgun — rejected loudly here rather than silently
/// never matching.
fn is_syntactically_valid_claim_name(name: &str) -> bool {
    let trimmed = name.trim();
    !trimmed.is_empty() && !trimmed.chars().any(|c| c.is_ascii_whitespace())
}

/// `true` iff `name` is a reserved allowlist name (case-insensitive,
/// trim-tolerant — mirrors `evaluate_claim_name_collision`'s matching
/// so the two reserved-name surfaces agree).
fn is_reserved_allowlist_name(name: &str) -> bool {
    RESERVED_ALLOWLIST_NAMES
        .iter()
        .any(|r| r.eq_ignore_ascii_case(name.trim()))
}

/// Parse one `PermissionGrantLintConfig` envelope.
///
/// Mirrors the per-kind parser shape (`parse_retention_policy` etc.):
/// deserialize the envelope, defensively re-check the `kind` discriminant
/// (a wrong-kind body that happens to deserialize is rejected rather
/// than silently mis-absorbed), and reject an empty `metadata.name`.
pub fn parse_lint_config(
    _path: &Path,
    bytes: &[u8],
) -> Result<Envelope<PermissionGrantLintConfigSpec>, ParseError> {
    let env: Envelope<PermissionGrantLintConfigSpec> = serde_yaml_ng::from_slice(bytes)?;
    if env.kind != Kind::PermissionGrantLintConfig {
        return Err(ParseError::UnknownKind {
            got: env.kind.to_string(),
            valid: &["PermissionGrantLintConfig"],
        });
    }
    if env.metadata.name.is_empty() {
        return Err(ParseError::EmptyMetadataName);
    }
    Ok(env)
}

/// Per-spec validation (rule 1 — the singleton-count — is enforced at
/// the [`crate::desired::DesiredState`] absorb layer because this kind
/// is an `Option`, not a `Vec`):
///
/// 2. Every `single_claim_allowlist` entry is a syntactically valid
///    claim name and is not a reserved name
///    ([`RESERVED_ALLOWLIST_NAMES`]).
/// 3. Every present `rule_overrides` entry only *relaxes* its rule —
///    an override that restates (no-op) or raises strictness above the
///    design default (`reject` for all three tunable rules) is
///    rejected. "Must be explicit": a no-op override is dead config
///    and an operator could wrongly believe they hardened something.
///
/// Returns every violation (boot collects one complete list).
pub fn validate_lint_config(env: &Envelope<PermissionGrantLintConfigSpec>) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    if env.metadata.name.trim().is_empty() {
        errors.push(ValidationError::Invalid {
            kind: Kind::PermissionGrantLintConfig,
            name: env.metadata.name.clone(),
            detail: "metadata.name must not be blank".into(),
        });
    }

    for entry in &env.spec.single_claim_allowlist {
        if !is_syntactically_valid_claim_name(entry) {
            errors.push(ValidationError::Invalid {
                kind: Kind::PermissionGrantLintConfig,
                name: env.metadata.name.clone(),
                detail: format!(
                    "singleClaimAllowlist entry `{entry}` is not a syntactically \
                     valid claim name (must be non-blank and contain no whitespace)"
                ),
            });
        } else if is_reserved_allowlist_name(entry) {
            errors.push(ValidationError::Invalid {
                kind: Kind::PermissionGrantLintConfig,
                name: env.metadata.name.clone(),
                detail: format!(
                    "singleClaimAllowlist entry `{entry}` is a reserved name \
                     (one of: {}) — allowlisting it would bless a \
                     wildcard-admin / token-kind escalation shape the linter \
                     exists to block",
                    RESERVED_ALLOWLIST_NAMES.join(", ")
                ),
            });
        }
    }

    // Downgrade-only: every tunable rule's design default is `reject`. An override is accepted only when it is *strictly
    // looser* than `reject` (i.e. `warn` or `pass`). A `reject`
    // override is a no-op that must be explicit (removed, not silently
    // accepted); anything ranked >= the default would raise strictness
    // and is rejected for the same reason.
    let ov = &env.spec.rule_overrides;
    push_override_error_if_not_relaxing(
        env,
        "ruleOverrides.singleClaimGrant",
        ov.single_claim_grant,
        &mut errors,
    );
    push_override_error_if_not_relaxing(
        env,
        "ruleOverrides.directUserGrant",
        ov.direct_user_grant,
        &mut errors,
    );
    push_override_error_if_not_relaxing(
        env,
        "ruleOverrides.wildcardRepoNonAdmin",
        ov.wildcard_repo_non_admin,
        &mut errors,
    );

    errors
}

/// The design-default action for every tunable rule. All three
/// (`single-claim-grant`, the high-privilege arm of
/// `direct-user-grant-without-justification`, `wildcard-repo-non-admin`)
/// default to `reject`; the override may only relax below this.
const DESIGN_DEFAULT_CEILING: RuleActionSpec = RuleActionSpec::Reject;

/// Push an [`ValidationError::Invalid`] when a present override does
/// not *strictly* relax its rule below the design default. An
/// absent override is the secure default and is always fine. An
/// override equal to the default is a no-op-that-must-be-explicit
/// (rejected); a stricter one would raise strictness (rejected).
fn push_override_error_if_not_relaxing(
    env: &Envelope<PermissionGrantLintConfigSpec>,
    field: &str,
    override_action: Option<RuleActionSpec>,
    errors: &mut Vec<ValidationError>,
) {
    let Some(action) = override_action else {
        return; // absent ⇒ secure default; nothing to validate
    };
    if action.rank() >= DESIGN_DEFAULT_CEILING.rank() {
        errors.push(ValidationError::Invalid {
            kind: Kind::PermissionGrantLintConfig,
            name: env.metadata.name.clone(),
            detail: format!(
                "{field} only permits *downgrading* a rule (reject → warn / pass); \
                 an override that restates or raises strictness is a no-op and must \
                 be removed, not declared — drop the field to keep the secure default"
            ),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn p() -> PathBuf {
        PathBuf::from("test.yaml")
    }

    fn yaml(name: &str, body: &str) -> String {
        format!(
            "apiVersion: project-hort.de/v1beta1\nkind: PermissionGrantLintConfig\n\
             metadata:\n  name: {name}\nspec:{body}"
        )
    }

    // -- parse / round-trip -------------------------------------------------

    #[test]
    fn parse_minimal_empty_spec_round_trips() {
        // Absent allowlist + absent overrides ⇒ the secure default
        // (every relevant grant shape rejects). A minimal envelope is
        // valid and parses to empty defaults.
        let env = parse_lint_config(&p(), yaml("lint", " {}").as_bytes()).unwrap();
        assert!(env.spec.single_claim_allowlist.is_empty());
        assert_eq!(env.spec.rule_overrides, RuleOverridesSpec::default());
        assert!(validate_lint_config(&env).is_empty());
    }

    #[test]
    fn parse_serialize_parse_round_trip_preserves_full_shape() {
        let body = "
  singleClaimAllowlist:
    - team-alpha
    - platform-readers
  ruleOverrides:
    singleClaimGrant: warn
    wildcardRepoNonAdmin: pass
";
        let env = parse_lint_config(&p(), yaml("lint", body).as_bytes()).unwrap();
        assert_eq!(
            env.spec.single_claim_allowlist,
            vec!["team-alpha".to_string(), "platform-readers".to_string()]
        );
        assert_eq!(
            env.spec.rule_overrides.single_claim_grant,
            Some(RuleActionSpec::Warn)
        );
        assert_eq!(
            env.spec.rule_overrides.wildcard_repo_non_admin,
            Some(RuleActionSpec::Pass)
        );
        assert_eq!(env.spec.rule_overrides.direct_user_grant, None);
        assert!(validate_lint_config(&env).is_empty());

        // Round-trip: serialize the parsed envelope back to YAML and
        // re-parse — the full shape must survive intact.
        let serialized = serde_yaml_ng::to_string(&env).unwrap();
        let reparsed = parse_lint_config(&p(), serialized.as_bytes()).unwrap();
        assert_eq!(reparsed, env);
    }

    #[test]
    fn parse_rejects_unknown_field() {
        let body = "
  singleClaimAllowlist: []
  bogus: 1
";
        let err = parse_lint_config(&p(), yaml("lint", body).as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
    }

    #[test]
    fn parse_rejects_unknown_override_field() {
        let body = "
  ruleOverrides:
    claimNameCollision: pass
";
        // `claim-name-collision` has no knob — its key must not exist
        // (deny_unknown_fields on RuleOverridesSpec catches it).
        let err = parse_lint_config(&p(), yaml("lint", body).as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
    }

    #[test]
    fn parse_rejects_wrong_kind() {
        let doc = "apiVersion: project-hort.de/v1beta1\nkind: ScanPolicy\n\
                   metadata:\n  name: x\nspec: {}\n";
        let err = parse_lint_config(&p(), doc.as_bytes()).unwrap_err();
        assert!(matches!(
            err,
            ParseError::UnknownKind { .. } | ParseError::Yaml(_)
        ));
    }

    #[test]
    fn parse_rejects_empty_metadata_name() {
        let doc = "apiVersion: project-hort.de/v1beta1\nkind: PermissionGrantLintConfig\n\
                   metadata:\n  name: ''\nspec: {}\n";
        let err = parse_lint_config(&p(), doc.as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::EmptyMetadataName));
    }

    #[test]
    fn parse_rejects_unknown_rule_action_value() {
        let body = "
  ruleOverrides:
    singleClaimGrant: lenient
";
        let err = parse_lint_config(&p(), yaml("lint", body).as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
    }

    // -- validate: allowlist syntactic validity (reject path 2a) -----------

    #[test]
    fn validate_rejects_blank_allowlist_entry() {
        let body = "
  singleClaimAllowlist:
    - '   '
";
        let env = parse_lint_config(&p(), yaml("lint", body).as_bytes()).unwrap();
        let errs = validate_lint_config(&env);
        assert!(
            errs.iter()
                .any(|e| e.to_string().contains("not a syntactically")),
            "expected a syntactic-validity error, got {errs:?}"
        );
    }

    #[test]
    fn validate_rejects_allowlist_entry_with_internal_whitespace() {
        let body = "
  singleClaimAllowlist:
    - 'team alpha'
";
        let env = parse_lint_config(&p(), yaml("lint", body).as_bytes()).unwrap();
        let errs = validate_lint_config(&env);
        assert!(
            errs.iter()
                .any(|e| e.to_string().contains("not a syntactically")),
            "an embedded-whitespace claim never matches a JWT group verbatim — \
             must be rejected, got {errs:?}"
        );
    }

    // -- validate: reserved allowlist name (reject path 2b) ----------------

    #[test]
    fn validate_rejects_reserved_admin_allowlist_entry() {
        let body = "
  singleClaimAllowlist:
    - admin
";
        let env = parse_lint_config(&p(), yaml("lint", body).as_bytes()).unwrap();
        let errs = validate_lint_config(&env);
        assert!(
            errs.iter().any(|e| e.to_string().contains("reserved name")),
            "allowlisting `admin` blesses a wildcard-admin escalation — must \
             reject, got {errs:?}"
        );
    }

    #[test]
    fn validate_rejects_reserved_service_account_allowlist_entry() {
        let body = "
  singleClaimAllowlist:
    - service_account
";
        let env = parse_lint_config(&p(), yaml("lint", body).as_bytes()).unwrap();
        let errs = validate_lint_config(&env);
        assert!(errs.iter().any(|e| e.to_string().contains("reserved name")));
    }

    #[test]
    fn validate_rejects_reserved_cli_session_allowlist_entry_case_insensitive() {
        let body = "
  singleClaimAllowlist:
    - '  CLI_Session '
";
        let env = parse_lint_config(&p(), yaml("lint", body).as_bytes()).unwrap();
        let errs = validate_lint_config(&env);
        assert!(
            errs.iter().any(|e| e.to_string().contains("reserved name")),
            "reserved-name match is case-insensitive + trim, got {errs:?}"
        );
    }

    #[test]
    fn validate_accepts_ordinary_allowlist_entry() {
        let body = "
  singleClaimAllowlist:
    - team-alpha
    - platform.read
";
        let env = parse_lint_config(&p(), yaml("lint", body).as_bytes()).unwrap();
        assert!(validate_lint_config(&env).is_empty());
    }

    // -- validate: downgrade-only (reject path 3) --------------------------

    #[test]
    fn validate_accepts_relaxing_override() {
        // reject → warn and reject → pass are the legitimate
        // downgrades; both must validate cleanly.
        let body = "
  ruleOverrides:
    singleClaimGrant: warn
    directUserGrant: pass
    wildcardRepoNonAdmin: warn
";
        let env = parse_lint_config(&p(), yaml("lint", body).as_bytes()).unwrap();
        assert!(validate_lint_config(&env).is_empty());
    }

    #[test]
    fn validate_rejects_strictness_raising_override() {
        // `reject` is the design default ceiling; an explicit `reject`
        // override is a no-op that must be removed, not declared
        // ("no-op but must be explicit").
        let body = "
  ruleOverrides:
    singleClaimGrant: reject
";
        let env = parse_lint_config(&p(), yaml("lint", body).as_bytes()).unwrap();
        let errs = validate_lint_config(&env);
        assert!(
            errs.iter()
                .any(|e| e.to_string().contains("only permits *downgrading*")),
            "an override restating/raising the design default must be rejected, \
             got {errs:?}"
        );
    }

    #[test]
    fn validate_rejects_raising_override_on_each_tunable_rule() {
        for body in [
            "\n  ruleOverrides:\n    singleClaimGrant: reject\n",
            "\n  ruleOverrides:\n    directUserGrant: reject\n",
            "\n  ruleOverrides:\n    wildcardRepoNonAdmin: reject\n",
        ] {
            let env = parse_lint_config(&p(), yaml("lint", body).as_bytes()).unwrap();
            let errs = validate_lint_config(&env);
            assert!(
                errs.iter()
                    .any(|e| e.to_string().contains("only permits *downgrading*")),
                "every tunable rule must reject a non-relaxing override; body={body} \
                 errs={errs:?}"
            );
        }
    }

    #[test]
    fn validate_rejects_blank_metadata_name() {
        // `metadata.name` is non-empty (parse gate) but whitespace-only
        // slips past `is_empty()` — caught by the trim check.
        let doc = "apiVersion: project-hort.de/v1beta1\nkind: PermissionGrantLintConfig\n\
                   metadata:\n  name: '   '\nspec: {}\n";
        let env = parse_lint_config(&p(), doc.as_bytes()).unwrap();
        let errs = validate_lint_config(&env);
        assert!(errs
            .iter()
            .any(|e| e.to_string().contains("metadata.name must not be blank")));
    }

    #[test]
    fn validate_collects_every_violation() {
        // One bad allowlist entry + one raising override → two errors
        // in one pass (boot wants the complete list).
        let body = "
  singleClaimAllowlist:
    - admin
  ruleOverrides:
    wildcardRepoNonAdmin: reject
";
        let env = parse_lint_config(&p(), yaml("lint", body).as_bytes()).unwrap();
        let errs = validate_lint_config(&env);
        assert_eq!(errs.len(), 2, "expected both violations, got {errs:?}");
    }

    // -- RuleActionSpec rank (downgrade ordering invariant) ----------------

    #[test]
    fn rule_action_rank_orders_pass_warn_reject() {
        assert!(RuleActionSpec::Pass.rank() < RuleActionSpec::Warn.rank());
        assert!(RuleActionSpec::Warn.rank() < RuleActionSpec::Reject.rank());
    }
}
