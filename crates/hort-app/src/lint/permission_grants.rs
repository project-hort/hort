//! The four v1 apply-config lint rules and their `LintConfig`.
//!
//! | Rule | Trigger | Default action |
//! |---|---|---|
//! | `single-claim-grant` | `Claims` grant, `required.len() == 1`, claim ∉ `single_claim_allowlist` | **reject** (allowlist is the opt-out) |
//! | `direct-user-grant-without-justification` | `User` grant not SA-owned (provenance = the v1 justification signal; see `lint_permission_grants` doc) | **reject** when `permission == Admin` OR (`repository_id IS NULL` AND `permission ∈ ADMIN_CLASS ∪ {Write, Delete}`); else **warn** |
//! | `wildcard-repo-non-admin` | `Claims` grant, `repository_id IS NULL`, `permission != Admin` | **reject** |
//! | `claim-name-collision` | `claim_mappings` row's claim collides with a reserved name | **reject** |
//!
//! Secure-by-default: [`LintConfig::default`] encodes the reject
//! posture. An operator may only *downgrade* a rule via explicit,
//! audited gitops config (visible in the apply diff) — there is no
//! env-var and no global `warn` switch — the posture rejects by default;
//! operators allowlist known-good shapes.

use std::collections::HashSet;

use hort_domain::entities::rbac::{ClaimMapping, GrantSubject, Permission, PermissionGrant};
use uuid::Uuid;

use crate::metrics::{emit_apply_config_linter, LinterResult};

/// Reserved claim names the `claim-name-collision` rule forbids a
/// `claim_mappings` row from resolving to.
///
/// **Why `admin` is not in the reserved set (recorded divergence).**
/// An earlier draft of the rule table listed
/// "(`admin`, `service_account`, …)". Taken literally that rejects
/// **every** `claim_mappings` row resolving to `admin` — but the
/// operationally load-bearing OIDC-admin path *defines*
/// `is_admin = resolved.iter().any(|c| c == "admin")`, i.e. the
/// operator declaring an IdP-admin-group → `admin` mapping is the
/// **documented, required** way an OIDC user becomes admin (the only
/// synthetic claim allowed is the `admin` claim). Treating `admin`
/// as collision-forbidden would make the primary admin-onboarding
/// path un-configurable. The genuine footgun the rule
/// protects against is mapping a group onto a **token-kind
/// discriminator** (`service_account` / `cli_session` — token-kind
/// strings must *never* be claims). `admin`
/// is therefore deliberately **excluded** from the reserved set.
///
/// Not operator-tunable: the collision rule has no downgrade knob
/// (always `reject`).
pub const RESERVED_CLAIM_NAMES: &[&str] = &["service_account", "cli_session"];

/// Permissions conferring admin-class authority. A wildcard
/// (repository-unscoped) direct `User` grant of any of these is a
/// privilege-escalation shape. Maintained set — a new
/// `Permission` variant must be classified here (admin-class) or left
/// out (ordinary); the exhaustiveness guard test below enforces that
/// every variant is consciously classified.
const ADMIN_CLASS_PERMISSIONS: &[Permission] = &[
    Permission::Admin,
    Permission::AdminTaskInvoke,
    Permission::Curate,
    Permission::Prefetch,
];

/// True when `p` confers admin-class authority (see
/// [`ADMIN_CLASS_PERMISSIONS`]).
fn is_admin_class(p: Permission) -> bool {
    ADMIN_CLASS_PERMISSIONS.contains(&p)
}

// Stable, fixed v1 rule keys. `&'static str` so the metric `rule`
// label cardinality is compile-time bounded.
const RULE_SINGLE_CLAIM: &str = "single-claim-grant";
const RULE_DIRECT_USER: &str = "direct-user-grant-without-justification";
const RULE_WILDCARD_REPO: &str = "wildcard-repo-non-admin";
const RULE_CLAIM_COLLISION: &str = "claim-name-collision";

/// The action a rule takes when it fires for a given grant.
///
/// `Pass` = the rule did not trigger for this grant (or an allowlist
/// opt-out applies). `Warn` = flagged, apply continues, CI surfaces
/// it. `Reject` = the apply fails strict-atomic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    Pass,
    Warn,
    Reject,
}

impl RuleAction {
    fn as_linter_result(self) -> LinterResult {
        match self {
            Self::Pass => LinterResult::Pass,
            Self::Warn => LinterResult::Warn,
            Self::Reject => LinterResult::Reject,
        }
    }
}

/// Operator-tunable strictness knobs. **Defaults encode the
/// secure-by-default reject posture**; every field is an opt-*out*,
/// never an opt-in.
///
/// Loaded from operator gitops config at composition time. The
/// production constructor path
/// ([`ApplyConfigUseCase::new`](crate::use_cases::apply_config_use_case::ApplyConfigUseCase::new))
/// defaults this to [`LintConfig::default`] — i.e. an apply with **no
/// operator config at all** rejects single-claim grants and wildcard
/// privilege-escalation grant shapes.
///
/// An operator downgrade is itself a config mutation: it lands in the
/// gitops repo, is visible in the apply diff, and is therefore
/// audited. This is the intended (and only) escape hatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintConfig {
    /// Claims explicitly blessed as legitimate single-claim grants.
    /// A `single-claim-grant` whose sole claim is in this list
    /// downgrades to `Pass` **for that claim only** — it is the
    /// per-claim opt-*out*, not a global `warn`. Empty by default
    /// (secure: every single-claim grant rejects until allowlisted).
    pub single_claim_allowlist: Vec<String>,

    /// Per-rule action *ceiling* override. Present keys may only
    /// **downgrade** a rule's effective action (`Reject` → `Warn` /
    /// `Pass`, `Warn` → `Pass`); a value that would *escalate* a
    /// rule above its computed default is ignored (the stricter of
    /// {computed default, override} wins — an operator cannot weaken
    /// the floor by mis-stating an override, and cannot accidentally
    /// make a rule stricter than the audited design either; the
    /// design table is the ceiling, the override is a documented
    /// relaxation). Absent → the rule's computed default applies.
    ///
    /// Not exhaustive over the rule set: `claim-name-collision` has
    /// no downgrade (always `reject`).
    pub rule_overrides: RuleOverrides,
}

/// Per-rule downgrade knobs (subset of the four rules — only the
/// three with a tunable action; `claim-name-collision` is fixed).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuleOverrides {
    /// Downgrade for `single-claim-grant` (applies to grants whose
    /// claim is NOT allowlisted; an allowlisted claim is already
    /// `Pass` before this is consulted).
    pub single_claim_grant: Option<RuleAction>,
    /// Downgrade for `direct-user-grant-without-justification`'s
    /// high-privilege arm (the low-privilege arm is already `Warn`).
    pub direct_user_grant: Option<RuleAction>,
    /// Downgrade for `wildcard-repo-non-admin`.
    pub wildcard_repo_non_admin: Option<RuleAction>,
}

/// Pure mapping from the gitops spec
/// ([`hort_config::lint_config::RuleActionSpec`]) to the domain
/// [`RuleAction`].
///
/// Lives in `hort-app` (not `hort-config`) deliberately: `hort-app` depends
/// on `hort-config`, never the reverse (`hort-config`'s only path
/// dependency is `hort-domain`). Implementing `From` in `hort-config`
/// would require an `hort-config → hort-app` edge — a dependency cycle and
/// the architect "no new crate-dependency edge" anti-pattern.
impl From<hort_config::lint_config::RuleActionSpec> for RuleAction {
    fn from(spec: hort_config::lint_config::RuleActionSpec) -> Self {
        use hort_config::lint_config::RuleActionSpec;
        match spec {
            RuleActionSpec::Pass => Self::Pass,
            RuleActionSpec::Warn => Self::Warn,
            RuleActionSpec::Reject => Self::Reject,
        }
    }
}

/// Pure mapping from the gitops spec
/// ([`hort_config::lint_config::PermissionGrantLintConfigSpec`]) to the
/// domain [`LintConfig`] the linter consumes.
///
/// This is a faithful 1:1 data mirror — it does **not** re-run the
/// downgrade-only policy (`hort-config`'s `validate_lint_config` owns
/// that, run before apply; duplicating it here would be a silent
/// second policy surface). An empty spec maps to
/// [`LintConfig::default`] (the secure posture), preserving the
/// invariant that a missing kind is not a downgrade.
///
/// Borrows the spec (`&Spec`) rather than consuming it so the apply
/// pipeline can keep the parsed envelope for diff/audit.
impl From<&hort_config::lint_config::PermissionGrantLintConfigSpec> for LintConfig {
    fn from(spec: &hort_config::lint_config::PermissionGrantLintConfigSpec) -> Self {
        Self {
            single_claim_allowlist: spec.single_claim_allowlist.clone(),
            rule_overrides: RuleOverrides {
                single_claim_grant: spec.rule_overrides.single_claim_grant.map(RuleAction::from),
                direct_user_grant: spec.rule_overrides.direct_user_grant.map(RuleAction::from),
                wildcard_repo_non_admin: spec
                    .rule_overrides
                    .wildcard_repo_non_admin
                    .map(RuleAction::from),
            },
        }
    }
}

impl Default for LintConfig {
    /// Secure-by-default: empty allowlist, no downgrades. An apply with
    /// this config rejects every single-claim grant, every wildcard
    /// non-admin claims grant, every unjustified high-privilege
    /// direct-user grant, and every reserved-name claim collision.
    fn default() -> Self {
        Self {
            single_claim_allowlist: Vec::new(),
            rule_overrides: RuleOverrides::default(),
        }
    }
}

impl LintConfig {
    /// Every tunable rule downgraded to `Pass`. **Not a production
    /// posture** — this is the explicit operator opt-*out* taken to
    /// its extreme, used by reconcile-mechanics test harnesses that
    /// exercise grant diff/idempotence and must not be perturbed by
    /// the linter (the exact analogue of
    /// `UpstreamHostAllowlist::Disabled` in the apply-config tests).
    /// `claim-name-collision` still rejects (no downgrade knob),
    /// so harnesses must not declare a reserved-name mapping.
    /// The production composition root never calls this — it
    /// constructs through `ApplyConfigUseCase::new` →
    /// [`LintConfig::default`] (secure-by-default).
    #[cfg(test)]
    pub fn permissive_for_tests() -> Self {
        Self {
            single_claim_allowlist: Vec::new(),
            rule_overrides: RuleOverrides {
                single_claim_grant: Some(RuleAction::Pass),
                direct_user_grant: Some(RuleAction::Pass),
                wildcard_repo_non_admin: Some(RuleAction::Pass),
            },
        }
    }

    /// Apply an operator downgrade: the effective action is the
    /// **stricter** of the computed default and the override (so a
    /// missing/looser override never weakens the floor below the
    /// design ceiling, and an over-strict override is clamped to the
    /// design default). `None` override → the computed default.
    fn downgrade(default: RuleAction, override_action: Option<RuleAction>) -> RuleAction {
        match override_action {
            None => default,
            Some(o) => strictest(default, o),
        }
    }
}

/// Rank for "stricter of": `Reject` > `Warn` > `Pass`. An operator
/// override can only *relax* a rule (the design table is the
/// ceiling), so we always keep the stricter of the two — an override
/// claiming a *stricter* action than the design default is clamped
/// to the default, and a relaxing override is honoured.
fn strictest(a: RuleAction, b: RuleAction) -> RuleAction {
    fn rank(x: RuleAction) -> u8 {
        match x {
            RuleAction::Pass => 0,
            RuleAction::Warn => 1,
            RuleAction::Reject => 2,
        }
    }
    // The design default is the ceiling; the override may only lower
    // it. Therefore the effective action is min(default, override) —
    // but never below the override's relaxation. Concretely: keep the
    // *looser* of the two only when the override is the looser one,
    // and never let an override raise above the default.
    if rank(b) < rank(a) {
        b
    } else {
        a
    }
}

/// A single rule firing against a single grant or claim-mapping row.
/// Carries only audit-safe scalars — **no claim names** (claim names
/// are operator-authored topology, never logged or surfaced; counts
/// only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintViolation {
    /// Fixed v1 rule key (`&'static str` — bounded metric label).
    pub rule: &'static str,
    /// The action this firing resolved to (`Warn` or `Reject`;
    /// `Pass` is never a violation).
    pub action: RuleAction,
}

/// Outcome of one full linter pass over the desired grant +
/// claim-mapping set.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LintOutcome {
    /// Every `Warn` / `Reject` firing, in evaluation order. A `Reject`
    /// presence is what makes [`LintOutcome::rejected`] true.
    pub violations: Vec<LintViolation>,
}

impl LintOutcome {
    /// True when at least one rule rejected — the apply must fail.
    pub fn rejected(&self) -> bool {
        self.violations
            .iter()
            .any(|v| v.action == RuleAction::Reject)
    }
}

/// Run the four v1 lint rules over the fully-built desired grant set
/// and the desired `claim_mappings`, emitting
/// `hort_apply_config_linter_total{rule, result}` once per (grant|row,
/// rule) evaluation.
///
/// `sa_owned_user_ids` is the set of backing-user ids of
/// ServiceAccount-owned `User`-subject grants (the legitimate
/// direct-user path — auto-synthesised from `desired.service_accounts`,
/// not operator-hand-declared escalations). The
/// `direct-user-grant-without-justification` rule treats SA-owned
/// `User` grants as **justified by provenance** and exempts them; an
/// operator-hand-declared `GrantSubjectSpec::User` envelope grant
/// whose user-id is NOT in this set is a privilege-escalation shape
/// and triggers the rule.
///
/// **As-built reconciliation (recorded divergence).**
/// An earlier draft phrased the rule as "a `User(_)` grant has no
/// `managed_by_digest` annotation explaining the override". In the
/// as-built apply path *every* gitops-declared grant is written with
/// `managed_by_digest = Some(spec_hash)` unconditionally (it is the
/// diff-stability digest, not a justification signal), so keying the
/// rule on `managed_by_digest.is_none()` makes it dead for gitops
/// grants — which contradicts the rule's entire purpose (catching
/// unjustified direct-admin grants slipping through gitops review).
/// v1's `PermissionGrantSpec` carries no justification field. The
/// faithful reading of the rule's intent is therefore: the
/// *justification* for a direct-`User` grant is **provenance** —
/// auto-synthesised SA-owned grants are the legitimate path and are
/// exempt; a bare operator-declared `User` grant has no justification
/// mechanism in v1 and is exactly the shape the rule wants blocked.
///
/// Pure over its inputs (no I/O) — the caller
/// ([`apply_permission_grants`](crate::use_cases::apply_config_use_case))
/// owns the strict-atomic abort: if [`LintOutcome::rejected`] is true
/// it returns `AppError::Domain(DomainError::Validation(_))` *before*
/// the permission-grant `save_managed`, so no grant row and no
/// `PermissionGrantApplied` event lands.
///
/// Observability: each `Warn` logs `tracing::warn!` and
/// each `Reject` logs `tracing::error!`, both with the rule key, the
/// `repository_id` (when grant-scoped), and a *count* of required
/// claims — never the claim names themselves.
pub fn lint_permission_grants(
    grants: &[PermissionGrant],
    claim_mappings: &[ClaimMapping],
    sa_owned_user_ids: &HashSet<Uuid>,
    cfg: &LintConfig,
) -> LintOutcome {
    let mut outcome = LintOutcome::default();

    for grant in grants {
        evaluate_single_claim_grant(grant, cfg, &mut outcome);
        evaluate_wildcard_repo_non_admin(grant, cfg, &mut outcome);
        evaluate_direct_user_grant(grant, sa_owned_user_ids, cfg, &mut outcome);
    }

    for mapping in claim_mappings {
        evaluate_claim_name_collision(mapping, &mut outcome);
    }

    outcome
}

/// `single-claim-grant` — a `Claims` grant requiring exactly one
/// claim looks like a role-only / org-only grant (the precise shape
/// the dropped structural model would have caught at the schema). It
/// rejects by default; an operator blesses a known-good single claim
/// by adding it to `single_claim_allowlist` (per-claim opt-out).
fn evaluate_single_claim_grant(
    grant: &PermissionGrant,
    cfg: &LintConfig,
    outcome: &mut LintOutcome,
) {
    let GrantSubject::Claims(required) = &grant.subject else {
        return; // rule only applies to Claims subjects
    };
    if required.len() != 1 {
        emit_and_record(RULE_SINGLE_CLAIM, RuleAction::Pass, grant, outcome);
        return;
    }
    let claim = &required[0];
    if cfg.single_claim_allowlist.iter().any(|c| c == claim) {
        // Per-claim opt-out: this specific claim is operator-blessed.
        emit_and_record(RULE_SINGLE_CLAIM, RuleAction::Pass, grant, outcome);
        return;
    }
    let action = LintConfig::downgrade(RuleAction::Reject, cfg.rule_overrides.single_claim_grant);
    emit_and_record(RULE_SINGLE_CLAIM, action, grant, outcome);
}

/// `wildcard-repo-non-admin` — a `Claims` grant with `repository_id
/// IS NULL` and a non-`Admin` permission is an effectively
/// instance-wide write/read/delete grant. Reject by default.
fn evaluate_wildcard_repo_non_admin(
    grant: &PermissionGrant,
    cfg: &LintConfig,
    outcome: &mut LintOutcome,
) {
    let is_claims = matches!(grant.subject, GrantSubject::Claims(_));
    let triggers =
        is_claims && grant.repository_id.is_none() && grant.permission != Permission::Admin;
    if !triggers {
        // Only emit a Pass for Claims subjects the rule could have
        // applied to — a User subject is out of this rule's domain
        // entirely (no metric noise for inapplicable shapes).
        if is_claims {
            emit_and_record(RULE_WILDCARD_REPO, RuleAction::Pass, grant, outcome);
        }
        return;
    }
    let action = LintConfig::downgrade(
        RuleAction::Reject,
        cfg.rule_overrides.wildcard_repo_non_admin,
    );
    emit_and_record(RULE_WILDCARD_REPO, action, grant, outcome);
}

/// `direct-user-grant-without-justification` — a `User`-subject grant
/// that is **not** SA-owned (the legitimate, auto-
/// synthesised direct-user path). Provenance is the v1 justification
/// signal (see [`lint_permission_grants`] for the as-built
/// reconciliation: every gitops grant carries a `managed_by_digest`,
/// so it cannot be the discriminator). An SA-owned grant is exempt
/// (justified by provenance → `Pass`). An operator-hand-declared bare
/// `User` grant rejects when high-privilege (`Admin` always, or a
/// wildcard-repo grant of any [`ADMIN_CLASS_PERMISSIONS`] member —
/// `AdminTaskInvoke`/`Curate`/`Prefetch` — or wildcard-repo
/// write/delete) and warns otherwise (break-glass / low-priv direct
/// grants remain non-blocking). A *repo-scoped* admin-class grant
/// stays `Warn`: the reject is scoped to the wildcard case.
fn evaluate_direct_user_grant(
    grant: &PermissionGrant,
    sa_owned_user_ids: &HashSet<Uuid>,
    cfg: &LintConfig,
    outcome: &mut LintOutcome,
) {
    let GrantSubject::User(uid) = &grant.subject else {
        return; // rule only applies to User subjects
    };
    if sa_owned_user_ids.contains(uid) {
        // Justified by provenance: this `User` grant was synthesised
        // from a declared `ServiceAccount`, not a hand-written
        // escalation. The SA apply path (+ its apply-time validation,
        // incl. the no-admin-SA rule) is the audited gate here.
        emit_and_record(RULE_DIRECT_USER, RuleAction::Pass, grant, outcome);
        return;
    }
    let high_privilege = grant.permission == Permission::Admin
        || (grant.repository_id.is_none()
            && (is_admin_class(grant.permission)
                || matches!(grant.permission, Permission::Write | Permission::Delete)));
    let action = if high_privilege {
        LintConfig::downgrade(RuleAction::Reject, cfg.rule_overrides.direct_user_grant)
    } else {
        // Low-privilege unjustified direct grant: warn, never reject
        // (break-glass / low-priv direct grants remain non-blocking).
        // The low-priv arm has no downgrade knob: it is already the
        // loosest non-pass action.
        RuleAction::Warn
    };
    emit_and_record(RULE_DIRECT_USER, action, grant, outcome);
}

/// `claim-name-collision` — a `claim_mappings` row resolving an IdP
/// group onto a reserved name (`admin`, `service_account`). Always
/// `reject` (no downgrade knob).
fn evaluate_claim_name_collision(mapping: &ClaimMapping, outcome: &mut LintOutcome) {
    let collides = RESERVED_CLAIM_NAMES
        .iter()
        .any(|r| r.eq_ignore_ascii_case(mapping.claim.trim()));
    let action = if collides {
        RuleAction::Reject
    } else {
        RuleAction::Pass
    };
    emit_apply_config_linter(RULE_CLAIM_COLLISION, action.as_linter_result());
    match action {
        RuleAction::Pass => {}
        RuleAction::Warn => {
            // Unreachable for this rule (no warn arm) — kept for
            // exhaustiveness; if a future tuning adds one this is the
            // log site.
            tracing::warn!(
                rule = RULE_CLAIM_COLLISION,
                "apply-config linter: claim-name-collision warned"
            );
            outcome.violations.push(LintViolation {
                rule: RULE_CLAIM_COLLISION,
                action,
            });
        }
        RuleAction::Reject => {
            tracing::error!(
                rule = RULE_CLAIM_COLLISION,
                "apply-config linter: claim_mappings row resolves to a reserved \
                 claim name — apply rejected (privilege-escalation footgun)"
            );
            outcome.violations.push(LintViolation {
                rule: RULE_CLAIM_COLLISION,
                action,
            });
        }
    }
}

/// Emit the metric for one (grant, rule) evaluation and, for a
/// non-`Pass` action, log and record the violation. **Never logs claim
/// names** — only the rule key, the `repository_id` (when
/// grant-scoped), and the required-claims *count*.
fn emit_and_record(
    rule: &'static str,
    action: RuleAction,
    grant: &PermissionGrant,
    outcome: &mut LintOutcome,
) {
    emit_apply_config_linter(rule, action.as_linter_result());
    let required_claims_count = match &grant.subject {
        GrantSubject::Claims(c) => c.len(),
        GrantSubject::User(_) => 0,
    };
    match action {
        RuleAction::Pass => {}
        RuleAction::Warn => {
            tracing::warn!(
                rule,
                repository_id = ?grant.repository_id,
                required_claims_count,
                "apply-config linter: grant flagged (non-blocking)"
            );
            outcome.violations.push(LintViolation { rule, action });
        }
        RuleAction::Reject => {
            tracing::error!(
                rule,
                repository_id = ?grant.repository_id,
                required_claims_count,
                "apply-config linter: grant rejected — gitops apply will fail"
            );
            outcome.violations.push(LintViolation { rule, action });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use hort_domain::entities::managed_by::ManagedBy;
    use uuid::Uuid;

    // --- hort-config spec → LintConfig conversion ---------------------------
    // The conversion lives HERE (hort-app), not in hort-config: hort-app
    // depends on hort-config, never the reverse (cargo tree confirmed —
    // hort-config's only path dep is hort-domain). A From in hort-config
    // would need an hort-config→hort-app edge = dependency cycle. So the
    // spec type is reachable here while the domain type stays put;
    // no new crate-dependency edge is introduced.

    #[test]
    fn from_spec_maps_allowlist_and_relaxing_overrides() {
        use hort_config::lint_config::{
            PermissionGrantLintConfigSpec, RuleActionSpec, RuleOverridesSpec,
        };
        let spec = PermissionGrantLintConfigSpec {
            single_claim_allowlist: vec!["team-alpha".into(), "platform".into()],
            rule_overrides: RuleOverridesSpec {
                single_claim_grant: Some(RuleActionSpec::Warn),
                direct_user_grant: Some(RuleActionSpec::Pass),
                wildcard_repo_non_admin: None,
            },
        };
        let cfg = LintConfig::from(&spec);
        assert_eq!(cfg.single_claim_allowlist, vec!["team-alpha", "platform"]);
        assert_eq!(
            cfg.rule_overrides.single_claim_grant,
            Some(RuleAction::Warn)
        );
        assert_eq!(cfg.rule_overrides.direct_user_grant, Some(RuleAction::Pass));
        assert_eq!(cfg.rule_overrides.wildcard_repo_non_admin, None);
    }

    #[test]
    fn from_default_spec_equals_lint_config_default() {
        // An empty spec (absent allowlist + absent overrides) maps to
        // the secure default — a missing kind is NOT a downgrade.
        // This preserves the invariant that absent kind ⇒ default.
        use hort_config::lint_config::PermissionGrantLintConfigSpec;
        let cfg = LintConfig::from(&PermissionGrantLintConfigSpec::default());
        assert_eq!(cfg, LintConfig::default());
    }

    #[test]
    fn from_spec_maps_reject_override_verbatim() {
        // The conversion is a pure data mapping — it does NOT re-run
        // the downgrade-only policy (that is hort-config's
        // validate_lint_config, run before apply). A `reject` value
        // round-trips so the conversion stays a faithful 1:1 mirror;
        // policy enforcement is not silently duplicated here.
        use hort_config::lint_config::{PermissionGrantLintConfigSpec, RuleActionSpec};
        let spec = PermissionGrantLintConfigSpec {
            single_claim_allowlist: Vec::new(),
            rule_overrides: hort_config::lint_config::RuleOverridesSpec {
                single_claim_grant: Some(RuleActionSpec::Reject),
                ..Default::default()
            },
        };
        let cfg = LintConfig::from(&spec);
        assert_eq!(
            cfg.rule_overrides.single_claim_grant,
            Some(RuleAction::Reject)
        );
    }

    /// Run the linter with NO SA-owned exemptions (the common case —
    /// the rule under test is not the direct-user provenance one).
    fn lint(
        grants: &[PermissionGrant],
        mappings: &[ClaimMapping],
        cfg: &LintConfig,
    ) -> LintOutcome {
        lint_permission_grants(grants, mappings, &HashSet::new(), cfg)
    }

    /// Run the linter with an explicit SA-owned-user-id exemption set.
    fn lint_sa(
        grants: &[PermissionGrant],
        sa_owned: &HashSet<Uuid>,
        cfg: &LintConfig,
    ) -> LintOutcome {
        lint_permission_grants(grants, &[], sa_owned, cfg)
    }

    fn claims_grant(
        required: &[&str],
        permission: Permission,
        repository_id: Option<Uuid>,
    ) -> PermissionGrant {
        PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::Claims(required.iter().map(|s| (*s).to_string()).collect()),
            repository_id,
            permission,
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0xab; 32]),
            created_at: Utc::now(),
        }
    }

    /// A `User`-subject grant with a fixed user-id so the test can
    /// add it to (or omit it from) the SA-owned exemption set.
    fn user_grant_for(
        uid: Uuid,
        permission: Permission,
        repository_id: Option<Uuid>,
    ) -> PermissionGrant {
        PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::User(uid),
            repository_id,
            permission,
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0xab; 32]),
            created_at: Utc::now(),
        }
    }

    /// Bare hand-declared `User` grant (fresh uid, never SA-owned).
    fn user_grant(permission: Permission, repository_id: Option<Uuid>) -> PermissionGrant {
        user_grant_for(Uuid::new_v4(), permission, repository_id)
    }

    fn claim_mapping(claim: &str) -> ClaimMapping {
        ClaimMapping {
            id: Uuid::new_v4(),
            idp_group: "some-idp-group".into(),
            claim: claim.into(),
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0xcd; 32]),
        }
    }

    // --- single-claim-grant ------------------------------------------------

    #[test]
    fn single_claim_grant_rejects_by_default() {
        let g = claims_grant(&["team-alpha"], Permission::Read, Some(Uuid::new_v4()));
        let out = lint(&[g], &[], &LintConfig::default());
        assert!(
            out.rejected(),
            "a non-allowlisted single-claim grant must reject by default"
        );
        assert_eq!(out.violations[0].rule, RULE_SINGLE_CLAIM);
        assert_eq!(out.violations[0].action, RuleAction::Reject);
    }

    #[test]
    fn single_claim_grant_allowlisted_claim_passes() {
        let g = claims_grant(&["team-alpha"], Permission::Read, Some(Uuid::new_v4()));
        let cfg = LintConfig {
            single_claim_allowlist: vec!["team-alpha".into()],
            ..LintConfig::default()
        };
        let out = lint(&[g], &[], &cfg);
        assert!(
            !out.rejected(),
            "an allowlisted single claim is the per-claim opt-out → pass"
        );
        assert!(out.violations.is_empty());
    }

    #[test]
    fn single_claim_grant_multi_claim_passes() {
        let g = claims_grant(
            &["developer", "team-alpha"],
            Permission::Write,
            Some(Uuid::new_v4()),
        );
        let out = lint(&[g], &[], &LintConfig::default());
        // The single-claim rule passes (len != 1); the grant is
        // repo-scoped so the wildcard rule also passes.
        assert!(!out.rejected());
        assert!(out.violations.is_empty());
    }

    #[test]
    fn single_claim_grant_operator_downgrade_to_warn() {
        let g = claims_grant(&["team-alpha"], Permission::Read, Some(Uuid::new_v4()));
        let cfg = LintConfig {
            rule_overrides: RuleOverrides {
                single_claim_grant: Some(RuleAction::Warn),
                ..RuleOverrides::default()
            },
            ..LintConfig::default()
        };
        let out = lint(&[g], &[], &cfg);
        assert!(
            !out.rejected(),
            "explicit operator downgrade → warn, not reject"
        );
        assert_eq!(out.violations[0].action, RuleAction::Warn);
    }

    #[test]
    fn operator_override_cannot_escalate_above_design_default() {
        // The low-privilege direct-user arm's design default is Warn.
        // An override claiming Reject must be clamped to Warn (the
        // design table is the ceiling; overrides only relax). A
        // repo-scoped Read direct-user grant is the low-priv arm.
        let g = user_grant(Permission::Read, Some(Uuid::new_v4()));
        let cfg = LintConfig {
            rule_overrides: RuleOverrides {
                direct_user_grant: Some(RuleAction::Reject),
                ..RuleOverrides::default()
            },
            ..LintConfig::default()
        };
        let out = lint(&[g], &[], &cfg);
        // Low-priv arm is hard-coded Warn and never consults the
        // override; the high-priv arm's override would also clamp.
        assert!(!out.rejected());
        assert_eq!(out.violations[0].action, RuleAction::Warn);
    }

    // --- wildcard-repo-non-admin ------------------------------------------

    #[test]
    fn wildcard_repo_non_admin_write_rejects() {
        let g = claims_grant(&["developer", "ops"], Permission::Write, None);
        let out = lint(&[g], &[], &LintConfig::default());
        assert!(out.rejected());
        assert!(out
            .violations
            .iter()
            .any(|v| v.rule == RULE_WILDCARD_REPO && v.action == RuleAction::Reject));
    }

    #[test]
    fn wildcard_repo_admin_passes() {
        let g = claims_grant(&["admins", "platform"], Permission::Admin, None);
        let out = lint(&[g], &[], &LintConfig::default());
        assert!(
            !out.rejected(),
            "a wildcard *admin* claims grant is allowed"
        );
        assert!(out.violations.is_empty());
    }

    #[test]
    fn wildcard_repo_repo_scoped_passes() {
        let g = claims_grant(
            &["developer", "ops"],
            Permission::Write,
            Some(Uuid::new_v4()),
        );
        let out = lint(&[g], &[], &LintConfig::default());
        assert!(!out.rejected());
        assert!(out.violations.is_empty());
    }

    #[test]
    fn wildcard_repo_operator_downgrade_to_warn() {
        let g = claims_grant(&["developer", "ops"], Permission::Write, None);
        let cfg = LintConfig {
            rule_overrides: RuleOverrides {
                wildcard_repo_non_admin: Some(RuleAction::Warn),
                ..RuleOverrides::default()
            },
            ..LintConfig::default()
        };
        let out = lint(&[g], &[], &cfg);
        assert!(!out.rejected());
        assert!(out
            .violations
            .iter()
            .any(|v| v.rule == RULE_WILDCARD_REPO && v.action == RuleAction::Warn));
    }

    // --- direct-user-grant-without-justification --------------------------
    // Justification = SA-provenance (see the `lint_permission_grants`
    // doc reconciliation). A bare hand-declared `User` grant (uid not
    // in the SA-owned set) is unjustified.

    #[test]
    fn direct_user_admin_unjustified_rejects() {
        let g = user_grant(Permission::Admin, None);
        let out = lint(&[g], &[], &LintConfig::default());
        assert!(out.rejected());
        assert!(out
            .violations
            .iter()
            .any(|v| v.rule == RULE_DIRECT_USER && v.action == RuleAction::Reject));
    }

    #[test]
    fn direct_user_wildcard_write_unjustified_rejects() {
        let g = user_grant(Permission::Write, None);
        let out = lint(&[g], &[], &LintConfig::default());
        assert!(out.rejected());
    }

    #[test]
    fn direct_user_wildcard_delete_unjustified_rejects() {
        let g = user_grant(Permission::Delete, None);
        let out = lint(&[g], &[], &LintConfig::default());
        assert!(out.rejected());
    }

    #[test]
    fn direct_user_low_privilege_unjustified_warns() {
        let g = user_grant(Permission::Read, None);
        let out = lint(&[g], &[], &LintConfig::default());
        assert!(
            !out.rejected(),
            "low-privilege unjustified direct grant warns, not rejects"
        );
        assert_eq!(out.violations[0].rule, RULE_DIRECT_USER);
        assert_eq!(out.violations[0].action, RuleAction::Warn);
    }

    #[test]
    fn direct_user_repo_scoped_write_unjustified_warns() {
        // Repo-scoped write is NOT the high-privilege arm (wildcard is).
        let g = user_grant(Permission::Write, Some(Uuid::new_v4()));
        let out = lint(&[g], &[], &LintConfig::default());
        assert!(!out.rejected());
        assert_eq!(out.violations[0].action, RuleAction::Warn);
    }

    #[test]
    fn direct_user_sa_owned_admin_is_exempt() {
        // The legitimate SA-owned path: a `User` grant whose uid
        // is SA-owned is justified by provenance → Pass, even at
        // Admin permission.
        let sa_uid = Uuid::new_v4();
        let g = user_grant_for(sa_uid, Permission::Admin, None);
        let mut sa_owned = HashSet::new();
        sa_owned.insert(sa_uid);
        let out = lint_sa(&[g], &sa_owned, &LintConfig::default());
        assert!(
            !out.rejected(),
            "an SA-owned User grant is justified by provenance"
        );
        assert!(out.violations.is_empty());
    }

    #[test]
    fn direct_user_non_sa_owned_admin_still_rejects_with_sa_set_present() {
        // A hand-declared admin grant for a *different* uid is NOT
        // exempted just because some SA-owned ids exist.
        let sa_uid = Uuid::new_v4();
        let hand_uid = Uuid::new_v4();
        let g = user_grant_for(hand_uid, Permission::Admin, None);
        let mut sa_owned = HashSet::new();
        sa_owned.insert(sa_uid);
        let out = lint_sa(&[g], &sa_owned, &LintConfig::default());
        assert!(out.rejected());
    }

    #[test]
    fn direct_user_high_priv_operator_downgrade_to_warn() {
        let g = user_grant(Permission::Admin, None);
        let cfg = LintConfig {
            rule_overrides: RuleOverrides {
                direct_user_grant: Some(RuleAction::Warn),
                ..RuleOverrides::default()
            },
            ..LintConfig::default()
        };
        let out = lint(&[g], &[], &cfg);
        assert!(!out.rejected());
        assert_eq!(out.violations[0].action, RuleAction::Warn);
    }

    // --- wildcard direct-User grants of admin-class permissions ------------
    // AdminTaskInvoke / Curate / Prefetch were added after the high_privilege
    // predicate was written. A wildcard (repository_id IS NULL) hand-declared
    // `User` grant of any of them is admin-class authority and must Reject
    // (matching the existing Admin treatment), not slip through as a Warn.

    #[test]
    fn direct_user_wildcard_admin_task_invoke_unjustified_rejects() {
        let g = user_grant(Permission::AdminTaskInvoke, None);
        let out = lint(&[g], &[], &LintConfig::default());
        assert!(
            out.rejected(),
            "a wildcard direct-User AdminTaskInvoke grant is admin-class \
             authority — must reject"
        );
        assert!(out
            .violations
            .iter()
            .any(|v| v.rule == RULE_DIRECT_USER && v.action == RuleAction::Reject));
    }

    #[test]
    fn direct_user_wildcard_curate_unjustified_rejects() {
        let g = user_grant(Permission::Curate, None);
        let out = lint(&[g], &[], &LintConfig::default());
        assert!(
            out.rejected(),
            "a wildcard direct-User Curate grant is admin-class authority — must reject"
        );
    }

    #[test]
    fn direct_user_wildcard_prefetch_unjustified_rejects() {
        let g = user_grant(Permission::Prefetch, None);
        let out = lint(&[g], &[], &LintConfig::default());
        assert!(
            out.rejected(),
            "a wildcard direct-User Prefetch grant is admin-class authority — must reject"
        );
    }

    #[test]
    fn direct_user_repo_scoped_admin_class_warns() {
        // The reject is scoped to the WILDCARD case: a repo-scoped
        // admin-class direct grant stays Warn (do not over-reach beyond the
        // design). This pins the wildcard scoping.
        let g = user_grant(Permission::Curate, Some(Uuid::new_v4()));
        let out = lint(&[g], &[], &LintConfig::default());
        assert!(
            !out.rejected(),
            "a repo-scoped admin-class direct grant stays Warn, not Reject"
        );
        assert_eq!(out.violations[0].rule, RULE_DIRECT_USER);
        assert_eq!(out.violations[0].action, RuleAction::Warn);
    }

    #[test]
    fn direct_user_sa_owned_admin_class_is_exempt() {
        // Provenance exemption holds for admin-class perms too: an SA-owned
        // wildcard admin-class `User` grant is justified by provenance
        // → Pass (mirrors `direct_user_sa_owned_admin_is_exempt`).
        let sa_uid = Uuid::new_v4();
        let g = user_grant_for(sa_uid, Permission::AdminTaskInvoke, None);
        let mut sa_owned = HashSet::new();
        sa_owned.insert(sa_uid);
        let out = lint_sa(&[g], &sa_owned, &LintConfig::default());
        assert!(
            !out.rejected(),
            "an SA-owned admin-class User grant is justified by provenance"
        );
        assert!(out.violations.is_empty());
    }

    /// RT-2 exhaustiveness guard. The `match` below has **no** `_` wildcard
    /// arm: a future new `Permission` variant fails to COMPILE this test
    /// until it is consciously classified admin-class or ordinary — that is
    /// the point (closes the RT-2 root for the linter's `high_privilege`
    /// predicate, so no new permission can silently fall through to the
    /// low-privilege Warn arm).
    #[test]
    fn every_permission_variant_is_classified() {
        for p in [
            Permission::Read,
            Permission::Write,
            Permission::Delete,
            Permission::Admin,
            Permission::AdminTaskInvoke,
            Permission::Curate,
            Permission::Prefetch,
        ] {
            // Exhaustive, no-wildcard classification. Cross-check against the
            // production `is_admin_class` helper so the two cannot drift.
            let expected_admin_class = match p {
                Permission::Admin
                | Permission::AdminTaskInvoke
                | Permission::Curate
                | Permission::Prefetch => true,
                Permission::Read | Permission::Write | Permission::Delete => false,
            };
            assert_eq!(
                is_admin_class(p),
                expected_admin_class,
                "{p} classification drifted from the exhaustive guard"
            );
        }
    }

    // --- claim-name-collision --------------------------------------------

    #[test]
    fn claim_name_collision_service_account_rejects() {
        let m = claim_mapping("service_account");
        let out = lint(&[], &[m], &LintConfig::default());
        assert!(out.rejected());
        assert_eq!(out.violations[0].rule, RULE_CLAIM_COLLISION);
        assert_eq!(out.violations[0].action, RuleAction::Reject);
    }

    #[test]
    fn claim_name_collision_cli_session_rejects() {
        let m = claim_mapping("cli_session");
        let out = lint(&[], &[m], &LintConfig::default());
        assert!(out.rejected());
    }

    #[test]
    fn claim_name_collision_admin_is_allowed() {
        // An IdP-admin-group → `admin` mapping is the documented
        // OIDC-admin onboarding path. `admin` is deliberately NOT in
        // the reserved set.
        let m = claim_mapping("admin");
        let out = lint(&[], &[m], &LintConfig::default());
        assert!(
            !out.rejected(),
            "mapping a group to `admin` is the documented OIDC-admin path — must pass"
        );
        assert!(out.violations.is_empty());
    }

    #[test]
    fn claim_name_collision_case_insensitive_rejects() {
        let m = claim_mapping("  Service_Account ");
        let out = lint(&[], &[m], &LintConfig::default());
        assert!(
            out.rejected(),
            "reserved-name match is case-insensitive + trim"
        );
    }

    #[test]
    fn claim_name_collision_ordinary_claim_passes() {
        let m = claim_mapping("team-alpha");
        let out = lint(&[], &[m], &LintConfig::default());
        assert!(!out.rejected());
        assert!(out.violations.is_empty());
    }

    #[test]
    fn claim_name_collision_has_no_downgrade_knob() {
        // Even with every downgrade set, the collision rule still
        // rejects (no operator escape hatch).
        let m = claim_mapping("service_account");
        let cfg = LintConfig {
            single_claim_allowlist: vec!["service_account".into()],
            rule_overrides: RuleOverrides {
                single_claim_grant: Some(RuleAction::Pass),
                direct_user_grant: Some(RuleAction::Pass),
                wildcard_repo_non_admin: Some(RuleAction::Pass),
            },
        };
        let out = lint(&[], &[m], &cfg);
        assert!(out.rejected());
    }

    // --- mixed / pass cases ----------------------------------------------

    #[test]
    fn clean_grant_set_passes_with_default_config() {
        // Multi-claim repo-scoped grant + SA-owned (justified by
        // provenance) direct grant + ordinary claim mappings — the
        // legitimate gitops shape.
        let sa_uid = Uuid::new_v4();
        let grants = vec![
            claims_grant(
                &["developer", "team-alpha"],
                Permission::Write,
                Some(Uuid::new_v4()),
            ),
            user_grant_for(sa_uid, Permission::Read, Some(Uuid::new_v4())),
        ];
        let mut sa_owned = HashSet::new();
        sa_owned.insert(sa_uid);
        let mappings = vec![claim_mapping("developer"), claim_mapping("team-alpha")];
        let out = lint_permission_grants(&grants, &mappings, &sa_owned, &LintConfig::default());
        assert!(!out.rejected());
        assert!(out.violations.is_empty());
    }

    #[test]
    fn lint_outcome_rejected_only_on_reject_action() {
        let mut o = LintOutcome::default();
        assert!(!o.rejected());
        o.violations.push(LintViolation {
            rule: RULE_DIRECT_USER,
            action: RuleAction::Warn,
        });
        assert!(!o.rejected(), "a warn-only outcome is not a rejection");
        o.violations.push(LintViolation {
            rule: RULE_WILDCARD_REPO,
            action: RuleAction::Reject,
        });
        assert!(o.rejected());
    }

    #[test]
    fn metric_fires_per_evaluation_with_rule_and_result() {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            let g = claims_grant(&["solo"], Permission::Read, None);
            let _ = lint(&[g], &[], &LintConfig::default());
        });
        let metrics = snapshotter.snapshot().into_vec();
        let linter: Vec<_> = metrics
            .iter()
            .filter(|(k, _, _, _)| k.key().name() == "hort_apply_config_linter_total")
            .collect();
        // A wildcard non-admin single-claim grant evaluates both the
        // single-claim rule and the wildcard rule (both reject).
        assert!(
            linter.len() >= 2,
            "expected one emission per (grant, rule) evaluation, got {}",
            linter.len()
        );
        for (key, _, _, value) in &linter {
            let labels: Vec<_> = key.key().labels().collect();
            assert!(
                labels.iter().any(|l| l.key() == "rule"),
                "every emission carries a `rule` label"
            );
            assert!(
                labels.iter().any(|l| l.key() == "result"),
                "every emission carries a `result` label"
            );
            assert!(matches!(value, DebugValue::Counter(_)));
        }
    }
}
