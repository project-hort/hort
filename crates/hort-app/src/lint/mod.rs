//! Apply-config linter.
//!
//! The additive-claims RBAC model deliberately trades
//! *server-enforced* "every grant has both legs" for operator
//! discipline. This linter is the **load-bearing**
//! mitigation for that trade — not optional polish. A security
//! audit found the original `warn`-default
//! posture non-mitigating: a secure-by-default control (CRA Annex I
//! Part I (1)) must not require an operator opt-*in*. The defaults
//! therefore **reject**; the only escape hatch is an explicit,
//! audited operator opt-*out* (allowlist / per-rule downgrade in
//! gitops config, itself visible in the apply diff) — never an
//! env-var and never a global `warn` switch.
//!
//! The linter runs inside
//! [`ApplyConfigUseCase::apply_permission_grants`](crate::use_cases::apply_config_use_case)
//! over the fully-built desired grant set (envelope grants ∪
//! SA-owned `User`-subject grants) plus the desired `claim_mappings`,
//! *before* the whole-partition `save_managed` commit. Any `Reject`
//! outcome fails the entire apply with
//! `AppError::Domain(DomainError::Validation(_))` — strict-atomic,
//! before any audit event lands.

pub mod permission_grants;
pub mod static_validate;

pub use permission_grants::{lint_permission_grants, LintConfig, LintOutcome, RuleAction};
pub use static_validate::{
    LintFinding, LinterRule, StaticConfigValidator, StaticLintReport, WarnContext,
};

use hort_config::DesiredState;

/// Resolve the effective permission-grant [`LintConfig`] for a `desired`
/// state, given the composition-root `base` config (the secure default
/// unless the root opted out via `with_lint_config`). This is the
/// **pure core** of the resolution the apply pipeline runs in
/// [`crate::use_cases::apply_config_use_case::ApplyConfigUseCase::resolve_effective_lint_config`];
/// it is shared between apply and the offline
/// [`StaticConfigValidator`]'s row-8 so the two cannot
/// drift.
///
/// Resolution (identical to apply):
/// - `> 1` declared `PermissionGrantLintConfig` envelope (a singleton
///   conflict that `validate_against` already hard-rejected upstream) ⇒
///   the secure [`LintConfig::default`] — never a last-wins of an
///   operator opt-out.
/// - no `PermissionGrantLintConfig` envelope ⇒ `base.clone()` (a missing
///   kind is **not** a downgrade — §6 invariant 1).
/// - exactly one envelope ⇒ the config its spec maps to
///   (`LintConfig::from(&env.spec)`).
///
/// Pure: no I/O, no `tracing`. The apply caller wraps this and adds its
/// own audit `info!`/`warn!` side-effects so the resolution stays
/// single-sourced while apply's observability is preserved.
pub(crate) fn resolve_effective_lint_config(
    base: &LintConfig,
    desired: &DesiredState,
) -> LintConfig {
    if desired.lint_config_sources.len() > 1 {
        return LintConfig::default();
    }
    match desired.lint_config.as_ref() {
        None => base.clone(),
        Some(env) => LintConfig::from(&env.spec),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hort_config::envelope::{ApiVersion, Kind, Metadata};
    use hort_config::lint_config::{PermissionGrantLintConfigSpec, RuleOverridesSpec};
    use std::path::PathBuf;

    fn lint_env(
        allowlist: &[&str],
    ) -> hort_config::envelope::Envelope<PermissionGrantLintConfigSpec> {
        hort_config::envelope::Envelope {
            api_version: ApiVersion::V1Beta1,
            kind: Kind::PermissionGrantLintConfig,
            metadata: Metadata {
                name: "rbac-lint".into(),
            },
            spec: PermissionGrantLintConfigSpec {
                single_claim_allowlist: allowlist.iter().map(|s| (*s).to_string()).collect(),
                rule_overrides: RuleOverridesSpec::default(),
            },
        }
    }

    /// No declared `PermissionGrantLintConfig` envelope ⇒ the resolver
    /// returns the composition-root `base` verbatim (a missing kind is not
    /// a downgrade — §6 invariant 1).
    #[test]
    fn shared_resolver_absent_kind_returns_base() {
        let base = LintConfig {
            single_claim_allowlist: vec!["boot-blessed".into()],
            ..LintConfig::default()
        };
        let desired = DesiredState::default();
        assert_eq!(resolve_effective_lint_config(&base, &desired), base);
    }

    /// Exactly one declared envelope ⇒ the config its spec maps to (the
    /// desired-derived config), independent of `base`.
    #[test]
    fn shared_resolver_single_envelope_returns_desired_derived() {
        let base = LintConfig::default();
        let desired = DesiredState {
            lint_config: Some(lint_env(&["team-alpha"])),
            lint_config_sources: vec![PathBuf::from("rbac-lint.yaml")],
            ..Default::default()
        };
        let resolved = resolve_effective_lint_config(&base, &desired);
        assert_eq!(resolved.single_claim_allowlist, vec!["team-alpha"]);
    }

    /// `> 1` declared envelope ⇒ the secure default (never a last-wins of
    /// an operator opt-out), regardless of `base` / the envelope contents.
    #[test]
    fn shared_resolver_multiple_sources_returns_secure_default() {
        let base = LintConfig {
            single_claim_allowlist: vec!["boot-blessed".into()],
            rule_overrides: permission_grants::RuleOverrides {
                single_claim_grant: Some(RuleAction::Pass),
                ..permission_grants::RuleOverrides::default()
            },
        };
        let desired = DesiredState {
            lint_config: Some(lint_env(&["team-alpha"])),
            lint_config_sources: vec![PathBuf::from("a.yaml"), PathBuf::from("b.yaml")],
            ..Default::default()
        };
        assert_eq!(
            resolve_effective_lint_config(&base, &desired),
            LintConfig::default()
        );
    }
}
