//! `StaticConfigValidator` — the snapshot-free subset of the gitops
//! apply-time validation/lint pass, extracted as a **pure** value.
//!
//! # Why this exists
//!
//! The apply pipeline ([`ApplyConfigUseCase::run_pre_write_validation`])
//! runs a sequence of config checks before the first managed-write. Some
//! depend on the current-state snapshot or the live worker registry and
//! are kept inline on the apply path; the rest are **desired-only**
//! functions of static deployment facts. This struct holds exactly those
//! static facts and runs exactly those checks, so the same logic can be
//! reused by the offline `hort-server validate-config` command **without**
//! drifting from what apply enforces — the no-drift guarantee. The struct
//! cannot hold a snapshot or a port, so the snapshot-free invariant is
//! *structural*, not conventional.
//!
//! # Purity contract
//!
//! [`StaticConfigValidator::validate`] runs the rows **in apply's row
//! order**, **collecting all findings** — no early return, no metric
//! emission, no `tracing`. The caller owns surfacing:
//!
//! - **apply** ([`crate::use_cases::apply_config_use_case`]) walks the
//!   report and, on the **first rule with error findings**, emits that
//!   rule's `hort_apply_config_linter_total` metric (where the rule has
//!   one — see [`LinterRule::metric_rule`]) once per finding, then aborts
//!   with that rule's `AppError::Domain(DomainError::Validation(_))`.
//!   Warnings are non-aborting. This reproduces the historical
//!   first-failing-row-aborts behaviour byte-identically.
//! - the **validate-config CLI** may surface every finding at once
//!   (collect-all — strictly more information, same reject *set*).
//!
//! Each [`LintFinding`] carries the [`LinterRule`] that produced it (not
//! a bare string) precisely so the apply caller can emit the per-rule
//! metric; the validator itself emits nothing.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;

use chrono::Utc;
use hort_config::envelope::Envelope;
use hort_config::permission_grant::GrantSubjectSpec;
use hort_config::scan_policy::ScanPolicySpec;
use hort_config::scope::ScopeSpec;
use hort_config::DesiredState;
use hort_domain::entities::managed_by::ManagedBy;
use hort_domain::entities::rbac::{ClaimMapping, GrantSubject, Permission, PermissionGrant};
use hort_domain::entities::scan_policy::{
    ProvenanceConfigError, ProvenanceConfigWarning, ProvenanceMode, ScanPolicyProjection,
    SeverityThreshold,
};
use hort_domain::events::PolicyScope;
use uuid::Uuid;

use crate::lint::{LintConfig, RuleAction};
// The ScanPolicy wire->domain provenance mappers are shared
// with apply via `hort_app::provenance` (single source, no duplication).
use crate::provenance::{provenance_identities_from_spec, provenance_mode_from_spec};
use crate::storage_backend::EffectiveStorageBackend;
use crate::use_cases::apply_config_use_case::service_account_permission_for_role;

/// `rule` label value for
/// `hort_apply_config_linter_total` emitted when
/// `trust_upstream_publish_time = true` collides with a resolved
/// `ScanPolicy.scan_backends.is_empty()`. The metric is emitted once
/// per offending `RepositoryUpstreamMapping`. Catalog entry update
/// ships in the same PR (`docs/metrics-catalog.md` —
/// `hort_apply_config_linter_total` row).
///
/// Single source of truth shared between [`LinterRule::metric_rule`] and
/// the apply caller's emission site (no duplicated
/// string literal).
pub(crate) const RULE_TRUST_UPSTREAM_PUBLISH_TIME_REQUIRES_SCAN_BACKENDS: &str =
    "trust_upstream_publish_time_requires_scan_backends";

/// `rule` label value for
/// `hort_apply_config_linter_total` emitted when a `PrefetchPolicy`
/// envelope carries a non-`None` `max_age_days`. The field is accepted
/// at apply but the planner ignores it; the linter closes the
/// accepted-but-inert anti-pattern on its canonical exemplar. One
/// increment per offending `PrefetchPolicy`. Catalog entry update ships
/// in the same PR (`docs/metrics-catalog.md`).
///
/// Single source of truth shared between [`LinterRule::metric_rule`] and
/// the apply caller's emission site.
pub(crate) const RULE_PREFETCH_MAX_AGE_DAYS_NOT_IMPLEMENTED: &str =
    "prefetch_max_age_days_not_implemented";

/// The snapshot-free apply-config lint rules.
///
/// The discriminant is carried on every [`LintFinding`] so the apply
/// caller can emit `hort_apply_config_linter_total{rule,result}` for the
/// rules that have a metric (see [`Self::metric_rule`]) and reproduce the
/// historical first-failing-row abort.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinterRule {
    /// Row 2 — `ServiceAccount.federatedIdentities[].issuer` cross-kind FK
    /// against `desired.oidc_issuers`. Reject (no metric today).
    SaIssuerFk,
    /// Row 3 — under-constrained `federatedIdentities[]`.
    /// Advisory warning (no metric, never aborts).
    UnderConstrainedFederatedIdentities,
    /// Row 5 — `trust_upstream_publish_time = true` × resolved
    /// `scan_backends:[]` cross-opt-in collapse. Reject + metric.
    TrustUpstreamPublishTimeRequiresScanBackends,
    /// Row 6 — accepted-but-inert `PrefetchPolicy.max_age_days`.
    /// Reject + metric.
    PrefetchMaxAgeDaysNotImplemented,
    /// Row 7 — provenance-config linter: backend/identity
    /// domain rules + the apply-only no-verifier-format rule (reject) and
    /// the `verify_if_present`-without-identities advisory (warn). No
    /// metric today.
    ProvenanceConfig,
    /// Row 7b — per-repo `storage.backend` ≠ the deployment's effective
    /// global backend. Reject (no metric today).
    RepoStorageBackendMismatch,
    /// Row 8 — the permission-grant linter
    /// ([`crate::lint::lint_permission_grants`]) run **offline** for the
    /// `validate-config` CLI. Reject *or* warn,
    /// depending on the underlying [`crate::lint::RuleAction`]. Emits
    /// **no** `hort_apply_config_linter_total` metric from the validator:
    /// apply keeps its own (load-bearing) emission on the
    /// real port-built desired set, and the CLI is metric-free — so
    /// [`Self::metric_rule`] returns `None` here.
    PermissionGrant,
}

impl LinterRule {
    /// The `rule` label value `crate::metrics::emit_apply_config_linter`
    /// takes for this rule, or `None` for rules that emit **no**
    /// `hort_apply_config_linter_total` metric today.
    ///
    /// Only the cross-opt-in collapse and the inert-field rejects tick the
    /// counter on the apply path; every other rule emits no linter metric
    /// (verified against `apply_config_use_case::run_pre_write_validation`
    /// — `SaIssuerFk`, `UnderConstrainedFederatedIdentities`, `ProvenanceConfig`,
    /// and `RepoStorageBackendMismatch` have no `emit_apply_config_linter` call). The
    /// returned string is the **same** const the apply caller's emission
    /// site uses (single source of truth — no duplicated literal).
    pub fn metric_rule(&self) -> Option<&'static str> {
        match self {
            Self::TrustUpstreamPublishTimeRequiresScanBackends => {
                Some(RULE_TRUST_UPSTREAM_PUBLISH_TIME_REQUIRES_SCAN_BACKENDS)
            }
            Self::PrefetchMaxAgeDaysNotImplemented => {
                Some(RULE_PREFETCH_MAX_AGE_DAYS_NOT_IMPLEMENTED)
            }
            Self::SaIssuerFk
            | Self::UnderConstrainedFederatedIdentities
            | Self::ProvenanceConfig
            | Self::RepoStorageBackendMismatch
            // Row 8 — the offline grant linter emits no validator metric
            // (apply keeps its :2772 emission; the CLI is metric-free).
            | Self::PermissionGrant => None,
        }
    }
}

/// Structured fields for an advisory **warning**, carrying the typed values
/// the apply path emits as `tracing::warn!` STRUCTURED fields (operator log /
/// SIEM pipelines key on them). The validator is the single
/// source of these facts; apply formats them for its `warn!` channel and the
/// CLI prints the flat [`LintFinding::message`], so neither channel loses
/// information. `None` on every error finding and on row-8 grant-lint warnings
/// (which carry no structured fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WarnContext {
    /// Row 3 — an under-constrained `federatedIdentities[]` entry.
    /// Mirrors the original apply
    /// `warn!(service_account, federated_identity_index, issuer, "…— {detail}")`.
    UnderConstrainedFederatedIdentities {
        /// The owning `ServiceAccount.metadata.name`.
        service_account: String,
        /// 0-based index into `spec.federatedIdentities`.
        federated_identity_index: usize,
        /// The `issuer` reference of the offending FI.
        issuer: String,
        /// The detector's core message (the `{}` the apply log template fills).
        detail: String,
    },
    /// Row 7 — a `provenanceMode: verify_if_present` policy with no
    /// `provenanceIdentities`. Mirrors the original apply `warn!(policy, "…")`.
    ProvenanceVerifyIfPresent {
        /// The offending `ScanPolicy.metadata.name`.
        policy: String,
    },
}

/// A single lint finding tagged with the [`LinterRule`] that produced
/// it. The `rule` is the same discriminant
/// `crate::metrics::emit_apply_config_linter` consumes (via
/// [`LinterRule::metric_rule`]); the CLI just prints `message`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintFinding {
    /// The rule that produced this finding.
    pub rule: LinterRule,
    /// The fully-rendered operator-facing message — the exact string the apply
    /// path historically put in its `Validation` error (errors), or the text
    /// the CLI prints (warnings). For warnings with a [`Self::warn_context`],
    /// the apply path emits the structured fields instead of this flat string.
    pub message: String,
    /// Structured fields for the apply-path `warn!` on advisory warnings (rows
    /// 3 and 7); `None` for errors and for findings with no structured context.
    /// The CLI ignores this and prints [`Self::message`].
    pub warn_context: Option<WarnContext>,
}

impl LintFinding {
    /// A hard-reject finding (no structured warn context).
    fn error(rule: LinterRule, message: String) -> Self {
        Self {
            rule,
            message,
            warn_context: None,
        }
    }

    /// An advisory finding. `warn_context` carries the apply-path structured
    /// `warn!` fields (rows 3 / 7) or `None` (row 8, which has none).
    fn warning(rule: LinterRule, message: String, warn_context: Option<WarnContext>) -> Self {
        Self {
            rule,
            message,
            warn_context,
        }
    }
}

/// The collected output of [`StaticConfigValidator::validate`]. Errors
/// are hard-reject findings (apply aborts on the first rule with any);
/// warnings are advisory (apply emits them but does not abort).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StaticLintReport {
    /// Hard-reject findings, in apply's row order.
    pub errors: Vec<LintFinding>,
    /// Advisory findings, in apply's row order.
    pub warnings: Vec<LintFinding>,
}

/// The snapshot-free apply-config validator. Holds only **static**
/// deployment facts — no ports, no `CurrentSnapshot`, no `EnvSnapshot`.
pub struct StaticConfigValidator {
    /// Row 7 — the set of repository-format strings some registered
    /// `ProvenancePort` covers (Tier-1 = `{"oci"}`). A `Required`
    /// provenance policy resolving to a format absent from this set is a
    /// hard reject (no verifier ⇒ the artifact would stay `Pending`
    /// forever).
    provenance_capable_formats: Arc<HashSet<String>>,
    /// Row 7b — the deployment's effective global storage backend kind.
    /// `None` ⇒ row 7b is skipped (the apply harness / a composition that
    /// did not opt in); the CLI always supplies `Some`.
    effective_storage_backend: Option<EffectiveStorageBackend>,
    /// Row 8 — opt-in permission-grant linter. `None`
    /// (the [`Self::new`] default) ⇒ row 8 is **skipped**, so the apply
    /// path's `validate()` call never runs it (apply keeps its own
    /// load-bearing grant-lint gate + metric on the real port-built
    /// desired set). `Some(base)` ⇒ row 8 runs offline (the CLI path,
    /// via [`Self::with_grant_lint_base`]), with `base` the
    /// composition-root `LintConfig` (the secure default unless the root
    /// opted out) that the desired state's `PermissionGrantLintConfig`
    /// resolves on top of — identical to apply's resolution. The grant
    /// linter emits **no** metric from here (a [`metrics::NoopRecorder`]
    /// swallows them — validator purity; the CLI is metric-free).
    grant_lint_base: Option<LintConfig>,
}

impl StaticConfigValidator {
    /// Construct the validator from the static facts the composition root
    /// holds. `effective_storage_backend = None` skips row 7b exactly as
    /// the apply path does when the builder was never called.
    ///
    /// Row 8 (the permission-grant linter) is **off** by default
    /// (`grant_lint_base = None`) — the apply path constructs through
    /// this `new` and so its `validate()` does **not** run row 8 (apply
    /// owns its own grant-lint gate + metric on the real port-built
    /// desired set; running it twice would double-lint). The offline CLI
    /// opts in via [`Self::with_grant_lint_base`].
    pub fn new(
        provenance_capable_formats: Arc<HashSet<String>>,
        effective_storage_backend: Option<EffectiveStorageBackend>,
    ) -> Self {
        Self {
            provenance_capable_formats,
            effective_storage_backend,
            grant_lint_base: None,
        }
    }

    /// Enable row 8 (the offline permission-grant linter)
    /// with `base` as the composition-root `LintConfig` (the
    /// secure [`LintConfig::default`] unless the root opted out via
    /// `with_lint_config`). The offline CLI calls this so
    /// [`Self::validate`] reproduces apply's row-8 verdict without a DB;
    /// the apply path never calls it (its own gate stays the authority).
    ///
    /// Builder, not a `new` argument, so the apply call site
    /// (`StaticConfigValidator::new(..)`) is unchanged and keeps row 8
    /// disabled by construction.
    pub fn with_grant_lint_base(mut self, base: LintConfig) -> Self {
        self.grant_lint_base = Some(base);
        self
    }

    /// Run every snapshot-free check over `desired`, **in apply's row
    /// order**, collecting all findings. Pure — no ports, no DB, no
    /// `EnvSnapshot`, no metric or `tracing` emission. The caller owns
    /// surfacing (see the module docs).
    pub fn validate(&self, desired: &DesiredState) -> StaticLintReport {
        let mut report = StaticLintReport::default();

        // Row 2 — SA→issuer cross-kind FK (desired-only; the historical
        // `snapshot` arg was already unused — it lints against
        // `desired.oidc_issuers`).
        for message in validate_service_account_issuer_fk(desired) {
            report
                .errors
                .push(LintFinding::error(LinterRule::SaIssuerFk, message));
        }

        // Row 3 — under-constrained federatedIdentities advisory. The
        // `message` is the FULLY-RENDERED line the CLI prints; the
        // `warn_context` carries the typed fields the apply path re-emits as
        // structured `warn!` fields (service_account / federated_identity_index
        // / issuer), byte-identically to the original.
        for env in &desired.service_accounts {
            for finding in hort_config::detect_under_constrained_federated_identities(env) {
                report.warnings.push(LintFinding::warning(
                    LinterRule::UnderConstrainedFederatedIdentities,
                    format!(
                        "gitops apply: under-constrained federatedIdentities — {}",
                        finding.message
                    ),
                    Some(WarnContext::UnderConstrainedFederatedIdentities {
                        service_account: finding.service_account.clone(),
                        federated_identity_index: finding.index,
                        issuer: finding.issuer.clone(),
                        detail: finding.message.clone(),
                    }),
                ));
            }
        }

        // Row 5 — trust_upstream_publish_time × scan_backends:[].
        for err in hort_config::desired::validate_trust_upstream_publish_time_against_scan_backends(
            desired,
        ) {
            report.errors.push(LintFinding::error(
                LinterRule::TrustUpstreamPublishTimeRequiresScanBackends,
                err.to_string(),
            ));
        }

        // Row 6 — accepted-but-inert PrefetchPolicy.max_age_days.
        for err in hort_config::desired::validate_prefetch_max_age_days_not_implemented(desired) {
            report.errors.push(LintFinding::error(
                LinterRule::PrefetchMaxAgeDaysNotImplemented,
                err.to_string(),
            ));
        }

        // Row 7 — provenance-config linter.
        self.collect_provenance_config(desired, &mut report);

        // Row 7b — per-repo vs global storage-backend mismatch.
        for message in self.collect_repo_storage_backend_mismatch(desired) {
            report.errors.push(LintFinding::error(
                LinterRule::RepoStorageBackendMismatch,
                message,
            ));
        }

        // Row 8 — the offline permission-grant linter.
        // Skipped entirely on the apply path (`grant_lint_base = None`);
        // run only when the CLI opted in via `with_grant_lint_base`.
        if let Some(base) = self.grant_lint_base.as_ref() {
            self.collect_permission_grants(base, desired, &mut report);
        }

        report
    }

    /// Row 8 — run the permission-grant
    /// linter ([`crate::lint::lint_permission_grants`]) **offline**,
    /// reproducing apply's grant verdict without a DB.
    ///
    /// The apply stage (`apply_permission_grants`) builds the desired
    /// grant set by resolving repository / service-account references to
    /// their **DB ids** and synthesising the SA-owned `User`-subject
    /// grants. The grant rules, however, read only `grant.subject`
    /// (`Claims(sorted)` / `User(uid)`), `grant.repository_id.is_none()`,
    /// `grant.permission`, and `sa_owned_user_ids` membership — **never**
    /// any id *value*. So the verdict is invariant to which concrete
    /// UUIDs the DB would have assigned: this method replicates the
    /// expansion with **placeholder** ids (a fixed non-nil repo id when a
    /// grant is repo-scoped; a deterministic per-SA backing-user id), and
    /// the only consistency requirement — that an SA-owned grant's
    /// `User(uid)` matches an entry in `sa_owned_user_ids` — is preserved
    /// by threading the *same* synthetic id into both.
    ///
    /// The [`LintConfig`] is resolved via the shared
    /// [`crate::lint::resolve_effective_lint_config`] — byte-identical to
    /// apply's resolution (single-sourced, no drift).
    ///
    /// Metric-free: the linter emits `hort_apply_config_linter_total`
    /// internally; we run it under a [`metrics::NoopRecorder`] so **no**
    /// series escapes — the validator is pure and the CLI is metric-free.
    /// The apply path keeps its own emission on its own call site.
    fn collect_permission_grants(
        &self,
        base: &LintConfig,
        desired: &DesiredState,
        report: &mut StaticLintReport,
    ) {
        // A fixed, non-nil placeholder repository id. The rules only test
        // `repository_id.is_none()`; the value is never read, so one
        // stable id for every repo-scoped grant is faithful.
        let placeholder_repo_id = Uuid::from_u128(0x6961_6161_0000_0000_0000_0000_0000_0001);

        let mut grants: Vec<PermissionGrant> = Vec::new();
        let mut sa_owned_user_ids: HashSet<Uuid> = HashSet::new();

        // (a) envelope-declared grants — mirrors apply's branch (a).
        for env in &desired.permission_grants {
            // `validate_permission_grant` (row 0 / parse) already gated
            // the permission string, so `from_str` is provably reachable
            // only on a valid value here; fall back to `Read` for totality
            // (matching `PermissionGrantSpec::diff_identity`'s accepted
            // unreachable default) rather than introducing a row-8 error
            // for input row 0 already rejects.
            let permission = Permission::from_str(&env.spec.permission).unwrap_or(Permission::Read);
            // Apply resolves `Some(name)` to the repo's DB id; offline we
            // only need `Some(_)` vs `None` (an unresolved name is row 0's
            // cross-validate concern, not row 8's).
            let repository_id = env.spec.repository.as_ref().map(|_| placeholder_repo_id);
            let subject = match &env.spec.subject {
                GrantSubjectSpec::Claims { required } => {
                    let mut sorted = required.clone();
                    sorted.sort();
                    GrantSubject::Claims(sorted)
                }
                // A malformed userId is row 0's concern (apply errors on
                // it, but cross-validate / parse runs first); offline,
                // a non-UUID string yields a fresh placeholder uid — it is
                // never SA-owned, so it lints exactly as a bare hand-
                // declared direct-user grant, which is the faithful verdict.
                GrantSubjectSpec::User { user_id } => GrantSubject::User(
                    Uuid::parse_str(user_id.trim()).unwrap_or_else(|_| Uuid::new_v4()),
                ),
            };
            grants.push(synthetic_grant(subject, repository_id, permission));
        }

        // (b) ServiceAccount-owned `User`-subject grants —
        // mirrors apply's branch (b). Apply reads the SA's `backing_user_id`
        // from the DB; offline we synthesise a *deterministic per-SA* id
        // and thread it into BOTH the grant subject and `sa_owned_user_ids`,
        // so the `direct-user-grant-without-justification` exemption fires
        // exactly as it does on the apply path.
        for env in &desired.service_accounts {
            // `service_account_permission_for_role` is the same code-
            // expansion apply uses; an unknown role is row 0's concern
            // (the SA aggregate pass rejects it) so we skip rather than
            // emit a row-8 finding.
            let Ok(permission) = service_account_permission_for_role(&env.spec.role) else {
                continue;
            };
            let backing_user_id = synthetic_sa_backing_user_id(&env.metadata.name);
            sa_owned_user_ids.insert(backing_user_id);
            for _repo_name in &env.spec.repositories {
                grants.push(synthetic_grant(
                    GrantSubject::User(backing_user_id),
                    Some(placeholder_repo_id),
                    permission,
                ));
            }
        }

        // claim_mappings — the `claim-name-collision` rule reads only
        // `claim`; every other field is a placeholder (matches apply's
        // minimal projection).
        let claim_mappings: Vec<ClaimMapping> = desired
            .claim_mappings
            .iter()
            .map(|env| ClaimMapping {
                id: Uuid::new_v4(),
                idp_group: env.spec.idp_group.clone(),
                claim: env.spec.claim.clone(),
                managed_by: ManagedBy::GitOps,
                managed_by_digest: None,
            })
            .collect();

        // Resolve the effective config exactly as apply does (shared
        // pure core — no drift).
        let effective_cfg = crate::lint::resolve_effective_lint_config(base, desired);

        // Run the linter with NO observable side-effects, so the validator
        // stays pure:
        //  - a `NoopRecorder` swallows the `hort_apply_config_linter_total`
        //    series the linter emits internally (the CLI is metric-free);
        //  - a `NoSubscriber` swallows the linter's internal
        //    `tracing::error!("apply-config linter: grant rejected — gitops
        //    apply will fail", repository_id = …)` per-reject lines. Those are
        //    apply-path operator feedback; on the offline validate path they
        //    would (a) duplicate the clean `LintFinding` the CLI prints and
        //    (b) leak this row's synthetic placeholder `repository_id` —
        //    meaningless to an operator. The CLI surfaces every finding via
        //    the returned `outcome`, so suppressing the linter's own logging
        //    loses nothing. (Apply's own :2772 gate keeps both — untouched.)
        let outcome =
            tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
                metrics::with_local_recorder(&metrics::NoopRecorder, || {
                    crate::lint::lint_permission_grants(
                        &grants,
                        &claim_mappings,
                        &sa_owned_user_ids,
                        &effective_cfg,
                    )
                })
            });

        for violation in &outcome.violations {
            let message = format!(
                "permission-grant linter rule `{}` {}",
                violation.rule,
                match violation.action {
                    RuleAction::Reject =>
                        "rejected this grant/claim-mapping \
                         (secure-by-default — relax via an explicit, \
                         audited operator LintConfig downgrade)",
                    RuleAction::Warn => "flagged this grant/claim-mapping (non-blocking)",
                    // `lint_permission_grants` never records a `Pass`
                    // violation, so this arm is unreachable; kept for
                    // totality.
                    RuleAction::Pass => "passed",
                }
            );
            // Row-8 grant-lint findings carry no structured warn fields (the
            // CLI prints `message`; apply never surfaces them — its own :2772
            // gate is the authority), so `warn_context` is `None`.
            match violation.action {
                RuleAction::Reject => report
                    .errors
                    .push(LintFinding::error(LinterRule::PermissionGrant, message)),
                RuleAction::Warn => report.warnings.push(LintFinding::warning(
                    LinterRule::PermissionGrant,
                    message,
                    None,
                )),
                RuleAction::Pass => {}
            }
        }
    }

    /// Row 7 — collect provenance-config findings (errors + the
    /// `verify_if_present`-without-identities warning), in the same
    /// per-policy sub-order the apply path evaluates: the domain hook
    /// (`NonOffWithoutBackends` → `RequiredWithoutIdentities`, plus the
    /// warn) first, then the apply-only `Required`-no-verifier rule.
    ///
    /// Collect-all: unlike the apply path (which aborts on the first
    /// violation within the row), this pushes every policy's findings so
    /// the CLI can surface them all. The apply caller still aborts on the
    /// first error finding — preserving the historical single-message
    /// reject.
    fn collect_provenance_config(&self, desired: &DesiredState, report: &mut StaticLintReport) {
        let repo_format_by_name: HashMap<&str, &str> = desired
            .repositories
            .iter()
            .map(|r| (r.metadata.name.as_str(), r.spec.format.as_str()))
            .collect();

        for env in &desired.scan_policies {
            let policy_name = env.metadata.name.as_str();
            let mode = provenance_mode_from_spec(&env.spec.provenance_mode);

            // (1) Domain hook — backend/identity rules + the warn.
            match provenance_projection_for_lint(env, mode).validate_provenance_config() {
                Err(ProvenanceConfigError::NonOffWithoutBackends) => {
                    report.errors.push(LintFinding::error(
                        LinterRule::ProvenanceConfig,
                        format!(
                            "ScanPolicy `{policy_name}`: provenanceMode `{mode}` requires a \
                             non-empty `provenanceBackends` — with no verifier backend the mode \
                             is inert. Set `provenanceBackends: [cosign]` or `provenanceMode: off`."
                        ),
                    ));
                }
                Err(ProvenanceConfigError::RequiredWithoutIdentities) => {
                    report.errors.push(LintFinding::error(
                        LinterRule::ProvenanceConfig,
                        format!(
                            "ScanPolicy `{policy_name}`: provenanceMode `required` with an empty \
                             `provenanceIdentities` would accept ANY signer (the any-signer \
                             footgun). Declare at least one allowed `{{issuer, san}}` pattern."
                        ),
                    ));
                }
                Ok(warnings) => {
                    for w in warnings {
                        match w {
                            ProvenanceConfigWarning::VerifyIfPresentWithoutIdentities => {
                                // CLI message folds the policy name in (so the
                                // printed line names it); the `warn_context`
                                // carries `policy` as the structured field the
                                // apply path re-emits byte-identically to the
                                // original `warn!(policy = …, "…")` (review L1).
                                report.warnings.push(LintFinding::warning(
                                    LinterRule::ProvenanceConfig,
                                    format!(
                                        "gitops apply: ScanPolicy provenanceMode \
                                         `verify_if_present` with empty `provenanceIdentities` — \
                                         tampering is detected (a forged/untrusted signature is \
                                         rejected) but no signer is pinned. Often intended; \
                                         declare `provenanceIdentities` to enforce which signer \
                                         is trusted. (policy: `{policy_name}`)"
                                    ),
                                    Some(WarnContext::ProvenanceVerifyIfPresent {
                                        policy: policy_name.to_string(),
                                    }),
                                ));
                            }
                        }
                    }
                }
            }

            // (2) Apply-only rule — `Required` on a no-verifier format.
            if mode == ProvenanceMode::Required {
                if let Some(format) =
                    self.first_uncovered_required_format(&env.spec.scope, &repo_format_by_name)
                {
                    report.errors.push(LintFinding::error(
                        LinterRule::ProvenanceConfig,
                        format!(
                            "ScanPolicy `{policy_name}`: provenanceMode `required` resolves to \
                             repository format `{format}`, which has no registered provenance \
                             verifier (static backend→format capability map; Tier 1 covers `oci` \
                             via cosign). A `required` policy on a no-verifier format leaves \
                             artifacts `Pending` forever (never timer-releasing). Use \
                             `provenanceMode: verify_if_present`/`off`, or scope this policy to an \
                             OCI repository — npm/PyPI/cargo/Maven verifiers are not yet implemented."
                        ),
                    ));
                }
            }
        }
    }

    /// Row 7 helper — the first repository format a `Required` policy
    /// scope resolves to that is absent from
    /// [`Self::provenance_capable_formats`] (no verifier), or `None` when
    /// every applicable format is covered.
    ///
    /// - `Repository(name)` → that one repository's format (an
    ///   unresolved name is left to the scope-existence validator and
    ///   treated as "covered" here so this linter does not double-report
    ///   it).
    /// - `Global` → every declared repository's format; the first
    ///   uncovered one (deterministic order) is reported.
    fn first_uncovered_required_format<'a>(
        &self,
        scope: &ScopeSpec,
        repo_format_by_name: &HashMap<&'a str, &'a str>,
    ) -> Option<&'a str> {
        match scope {
            ScopeSpec::Repository(r) => repo_format_by_name
                .get(r.repository.as_str())
                .copied()
                .filter(|format| !self.provenance_capable_formats.contains(*format)),
            ScopeSpec::Global => {
                let mut uncovered: Vec<&str> = repo_format_by_name
                    .values()
                    .copied()
                    .filter(|format| !self.provenance_capable_formats.contains(*format))
                    .collect();
                uncovered.sort_unstable();
                uncovered.into_iter().next()
            }
        }
    }

    /// Row 7b — collect per-repo `storage.backend` mismatches against the
    /// deployment's effective global backend. `None` slot ⇒ no findings
    /// (the cross-check is skipped, identical to the apply path). An
    /// omitted `storage:` block inherits the global backend by
    /// construction, so only a *supplied* backend can disagree.
    ///
    /// Collect-all: unlike the apply path (which aborts on the first
    /// mismatch), this returns every mismatch. The apply caller still
    /// aborts on the first.
    fn collect_repo_storage_backend_mismatch(&self, desired: &DesiredState) -> Vec<String> {
        let Some(eff) = self.effective_storage_backend else {
            return Vec::new();
        };
        let expected = eff.as_spec_str();
        let mut messages = Vec::new();
        for env in &desired.repositories {
            let Some(storage) = env.spec.storage.as_ref() else {
                continue;
            };
            let got = storage.backend.as_str();
            if got != expected {
                messages.push(format!(
                    "ArtifactRepository `{}`: storage.backend `{got}` differs from \
                     the deployment's effective global storage backend `{expected}`. \
                     Per-repository storage backend routing is NOT supported in v2 \
                     — blob placement is the single global storage adapter. Set \
                     storage.backend to `{expected}` (the deployment's backend), or \
                     omit the per-repo `storage:` block entirely to inherit the \
                     deployment backend (the block is \
                     optional, so the omit remedy is actually parseable); \
                     per-repository storage routing is a known future work item.",
                    env.metadata.name
                ));
            }
        }
        messages
    }
}

/// Row 2 — `ServiceAccount.federatedIdentities[].issuer` cross-kind FK
/// against the *post-apply* set of OidcIssuers, which is exactly
/// `desired.oidc_issuers` (a snapshot issuer
/// being deleted by omission must NOT satisfy the FK). Returns one
/// rendered error string per violation; the caller joins them into a
/// single `DomainError::Validation`.
///
/// Desired-only — the historical apply helper took an unused `_snapshot`
/// argument; this pure form drops it.
fn validate_service_account_issuer_fk(desired: &DesiredState) -> Vec<String> {
    let declared_issuers: HashSet<&str> = desired
        .oidc_issuers
        .iter()
        .map(|e| e.metadata.name.as_str())
        .collect();
    let mut errors = Vec::new();
    for env in &desired.service_accounts {
        for (idx, fi) in env.spec.federated_identities.iter().enumerate() {
            if !declared_issuers.contains(fi.issuer.as_str()) {
                errors.push(format!(
                    "ServiceAccount `{}` references unknown OidcIssuer `{}` via \
                     spec.federatedIdentities[{idx}].issuer — declare a kind: OidcIssuer \
                     with metadata.name `{}` or correct the reference",
                    env.metadata.name, fi.issuer, fi.issuer
                ));
            }
        }
    }
    errors
}

/// Row 8 — build one synthetic [`PermissionGrant`] for
/// the offline linter. `id` / `created_at` / `managed_by_digest` are
/// placeholders: the grant rules read only `subject`, `repository_id`'s
/// `is_none()`, and `permission`, so these fields never influence the
/// verdict.
fn synthetic_grant(
    subject: GrantSubject,
    repository_id: Option<Uuid>,
    permission: Permission,
) -> PermissionGrant {
    PermissionGrant {
        id: Uuid::new_v4(),
        subject,
        repository_id,
        permission,
        managed_by: ManagedBy::GitOps,
        managed_by_digest: None,
        created_at: Utc::now(),
    }
}

/// Row 8 — a stable synthetic backing-user id for a
/// ServiceAccount, derived deterministically from its name. Only its
/// *consistency* matters: the same id is threaded into both the SA-owned
/// grant's `User(uid)` subject and the `sa_owned_user_ids` exemption set,
/// so the linter's provenance exemption fires exactly as on the apply
/// path (where it would be the SA's real DB `backing_user_id`). A v5 UUID
/// over a fixed namespace keeps distinct SAs distinct and is stable
/// across runs.
fn synthetic_sa_backing_user_id(sa_name: &str) -> Uuid {
    // Fixed, arbitrary namespace UUID for SA-backing-user synthesis.
    const NS: Uuid = Uuid::from_u128(0x5341_4f57_4e45_4400_0000_0000_0000_0001);
    Uuid::new_v5(&NS, sa_name.as_bytes())
}

/// Build the transient [`ScanPolicyProjection`] the
/// domain provenance hook consumes. Only the three provenance fields are
/// load-bearing (the hook reads no others); every other field is a
/// placeholder.
fn provenance_projection_for_lint(
    env: &Envelope<ScanPolicySpec>,
    mode: ProvenanceMode,
) -> ScanPolicyProjection {
    let now = Utc::now();
    ScanPolicyProjection {
        policy_id: Uuid::nil(),
        name: env.metadata.name.clone(),
        scope: PolicyScope::Global,
        severity_threshold: SeverityThreshold::High,
        quarantine_duration_secs: 0,
        require_approval: env.spec.require_approval,
        provenance_mode: mode,
        provenance_backends: env.spec.provenance_backends.clone(),
        provenance_identities: provenance_identities_from_spec(&env.spec.provenance_identities),
        max_artifact_age_secs: None,
        license_policy: serde_json::Value::Null,
        archived: false,
        scan_backends: Vec::new(),
        rescan_interval_hours: 0,
        stream_version: 0,
        created_at: now,
        updated_at: now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Test-only now that the provenance mappers moved to `crate::provenance`:
    // `SignerIdentitySpec` is referenced only by fixtures.
    use hort_config::envelope::{ApiVersion, Kind, Metadata};
    use hort_config::oidc_issuer::OidcIssuerSpec;
    use hort_config::repository::{RepositorySpec, StorageSpec};
    use hort_config::scan_policy::SignerIdentitySpec;
    use hort_config::scope::RepositoryScope;
    use hort_config::service_account::{FederatedIdentitySpec, ServiceAccountSpec};
    use hort_config::upstream_mapping::UpstreamMappingSpec;
    use hort_domain::entities::repository::IndexMode;
    use std::collections::BTreeMap;

    fn formats(items: &[&str]) -> Arc<HashSet<String>> {
        Arc::new(items.iter().map(|s| (*s).to_string()).collect())
    }

    fn oci_validator() -> StaticConfigValidator {
        StaticConfigValidator::new(formats(&["oci"]), None)
    }

    // ---- envelope builders (mirror the apply test-module shapes) ------

    fn repo_env(name: &str, format: &str) -> Envelope<RepositorySpec> {
        Envelope {
            api_version: ApiVersion::V1Beta1,
            kind: Kind::ArtifactRepository,
            metadata: Metadata { name: name.into() },
            spec: RepositorySpec {
                name: name.into(),
                description: None,
                format: format.into(),
                repo_type: "proxy".into(),
                storage: Some(StorageSpec {
                    backend: "filesystem".into(),
                    path: format!("/data/{name}"),
                }),
                proxy: Some(hort_config::repository::ProxySpec {
                    upstream_url: "https://example.com".into(),
                    index_upstream_url: None,
                }),
                virtual_members: None,
                is_public: true,
                download_audit_enabled: false,
                index_mode: IndexMode::default(),
                prefetch_policy: hort_domain::entities::repository::PrefetchPolicy::default(),
                quota_bytes: None,
                replication_priority: "immediate".into(),
                promotion: None,
                curation_rules: None,
            },
        }
    }

    fn oidc_issuer_env(name: &str) -> Envelope<OidcIssuerSpec> {
        Envelope {
            api_version: ApiVersion::V1Beta1,
            kind: Kind::OidcIssuer,
            metadata: Metadata { name: name.into() },
            spec: OidcIssuerSpec {
                issuer_url: format!("https://{name}.example.com"),
                audiences: vec!["hort-server".into()],
                jwks_refresh_interval: "1h".into(),
                allowed_algorithms: vec!["RS256".into()],
                require_jti: true,
            },
        }
    }

    /// An SA whose single FI references `issuer` with a repository +
    /// environment claim (well-constrained — no under-constrained warning).
    fn sa_env_well_constrained(name: &str, issuer: &str) -> Envelope<ServiceAccountSpec> {
        let mut claims = BTreeMap::new();
        claims.insert("repository".to_string(), "my-org/my-repo".to_string());
        claims.insert("environment".to_string(), "production".to_string());
        Envelope {
            api_version: ApiVersion::V1Beta1,
            kind: Kind::ServiceAccount,
            metadata: Metadata { name: name.into() },
            spec: ServiceAccountSpec {
                role: "developer".into(),
                repositories: vec![],
                federated_identities: vec![FederatedIdentitySpec {
                    issuer: issuer.into(),
                    claims,
                }],
                fallback_rotation: None,
            },
        }
    }

    /// An SA whose single FI references `issuer` with ONLY a repository
    /// claim (under-constrained — the Class-1 warning shape).
    fn sa_env_under_constrained(name: &str, issuer: &str) -> Envelope<ServiceAccountSpec> {
        let mut claims = BTreeMap::new();
        claims.insert("repository".to_string(), "my-org/my-repo".to_string());
        Envelope {
            api_version: ApiVersion::V1Beta1,
            kind: Kind::ServiceAccount,
            metadata: Metadata { name: name.into() },
            spec: ServiceAccountSpec {
                role: "developer".into(),
                repositories: vec![],
                federated_identities: vec![FederatedIdentitySpec {
                    issuer: issuer.into(),
                    claims,
                }],
                fallback_rotation: None,
            },
        }
    }

    fn upstream_mapping_env(
        name: &str,
        repository: &str,
        upstream_url: &str,
        trust_pt: bool,
    ) -> Envelope<UpstreamMappingSpec> {
        Envelope {
            api_version: ApiVersion::V1Beta1,
            kind: Kind::UpstreamMapping,
            metadata: Metadata { name: name.into() },
            spec: UpstreamMappingSpec {
                repository: repository.into(),
                path_prefix: "pkg/".into(),
                upstream_url: upstream_url.into(),
                upstream_name_prefix: None,
                auth: hort_config::upstream_mapping::UpstreamAuthSpec {
                    r#type: "anonymous".into(),
                    username: None,
                },
                secret_ref: None,
                insecure_upstream_url: false,
                trust_upstream_publish_time: trust_pt,
                mtls_cert_ref: None,
                mtls_key_ref: None,
                ca_bundle_ref: None,
                pinned_cert_sha256: None,
            },
        }
    }

    fn scan_policy_repo_scope(
        name: &str,
        repository: &str,
        mode: &str,
        provenance_backends: Vec<&str>,
        provenance_identities: Vec<SignerIdentitySpec>,
        scan_backends: Vec<&str>,
    ) -> Envelope<ScanPolicySpec> {
        Envelope {
            api_version: ApiVersion::V1Beta1,
            kind: Kind::ScanPolicy,
            metadata: Metadata { name: name.into() },
            spec: ScanPolicySpec {
                scope: ScopeSpec::Repository(RepositoryScope {
                    repository: repository.into(),
                }),
                severity_threshold: "high".into(),
                quarantine_duration: "24h".into(),
                require_approval: true,
                provenance_mode: mode.into(),
                provenance_backends: provenance_backends
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
                provenance_identities,
                max_artifact_age: Some("90d".into()),
                license_policy: serde_json::json!({"allowed": ["MIT"]}),
                scan_backends: scan_backends.into_iter().map(str::to_string).collect(),
                rescan_interval_hours: 24,
            },
        }
    }

    fn sample_identity_spec() -> SignerIdentitySpec {
        SignerIdentitySpec {
            issuer: "https://token.actions.githubusercontent.com".into(),
            san: "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main"
                .into(),
        }
    }

    // ---- metric_rule() -------------------------------------------------

    #[test]
    fn metric_rule_is_some_only_for_trust_pt_and_prefetch() {
        assert_eq!(
            LinterRule::TrustUpstreamPublishTimeRequiresScanBackends.metric_rule(),
            Some(RULE_TRUST_UPSTREAM_PUBLISH_TIME_REQUIRES_SCAN_BACKENDS)
        );
        assert_eq!(
            LinterRule::PrefetchMaxAgeDaysNotImplemented.metric_rule(),
            Some(RULE_PREFETCH_MAX_AGE_DAYS_NOT_IMPLEMENTED)
        );
        assert_eq!(LinterRule::SaIssuerFk.metric_rule(), None);
        assert_eq!(
            LinterRule::UnderConstrainedFederatedIdentities.metric_rule(),
            None
        );
        assert_eq!(LinterRule::ProvenanceConfig.metric_rule(), None);
        assert_eq!(LinterRule::RepoStorageBackendMismatch.metric_rule(), None);
    }

    // ---- clean desired -------------------------------------------------

    #[test]
    fn clean_desired_yields_empty_report() {
        let desired = DesiredState::default();
        let report = oci_validator().validate(&desired);
        assert!(report.errors.is_empty(), "no errors: {:?}", report.errors);
        assert!(
            report.warnings.is_empty(),
            "no warnings: {:?}",
            report.warnings
        );
    }

    // ---- row 2: SA issuer FK ------------------------------------------

    #[test]
    fn sa_issuer_fk_violation_is_reported() {
        let desired = DesiredState {
            // SA references an issuer that is NOT declared.
            service_accounts: vec![sa_env_well_constrained("ci", "missing-idp")],
            ..Default::default()
        };
        let report = oci_validator().validate(&desired);
        assert_eq!(report.errors.len(), 1);
        assert_eq!(report.errors[0].rule, LinterRule::SaIssuerFk);
        assert!(report.errors[0].message.contains("ci"));
        assert!(report.errors[0].message.contains("missing-idp"));
    }

    #[test]
    fn sa_issuer_fk_satisfied_when_issuer_declared() {
        let desired = DesiredState {
            oidc_issuers: vec![oidc_issuer_env("github-actions")],
            service_accounts: vec![sa_env_well_constrained("ci", "github-actions")],
            ..Default::default()
        };
        let report = oci_validator().validate(&desired);
        assert!(
            report
                .errors
                .iter()
                .all(|f| f.rule != LinterRule::SaIssuerFk),
            "no SA-issuer-FK error expected: {:?}",
            report.errors
        );
    }

    // ---- row 3: under-constrained FI warning --------------------------

    #[test]
    fn under_constrained_fi_is_a_warning_not_an_error() {
        let desired = DesiredState {
            oidc_issuers: vec![oidc_issuer_env("github-actions")],
            service_accounts: vec![sa_env_under_constrained("ci-loose", "github-actions")],
            ..Default::default()
        };
        let report = oci_validator().validate(&desired);
        assert!(report.errors.is_empty(), "errors: {:?}", report.errors);
        assert_eq!(report.warnings.len(), 1);
        assert_eq!(
            report.warnings[0].rule,
            LinterRule::UnderConstrainedFederatedIdentities
        );
        let msg = &report.warnings[0].message;
        // The fully-rendered apply log line: the prefix + the detector
        // message (carries SA name, issuer, and the risk detail).
        assert!(msg.contains("under-constrained federatedIdentities"));
        assert!(msg.contains("ci-loose"));
        assert!(msg.contains("github-actions"));
        assert!(msg.contains("discriminating"));
    }

    #[test]
    fn well_constrained_fi_emits_no_warning() {
        let desired = DesiredState {
            oidc_issuers: vec![oidc_issuer_env("github-actions")],
            service_accounts: vec![sa_env_well_constrained("ci-tight", "github-actions")],
            ..Default::default()
        };
        let report = oci_validator().validate(&desired);
        assert!(
            report.warnings.is_empty(),
            "well-constrained FI: {:?}",
            report.warnings
        );
    }

    // ---- row 5: trust_pt × scan_backends:[] ---------------------------

    #[test]
    fn trust_pt_with_empty_scan_backends_is_reported() {
        let desired = DesiredState {
            repositories: vec![repo_env("oci-mirror", "oci")],
            upstream_mappings: vec![upstream_mapping_env(
                "m1",
                "oci-mirror",
                "https://registry-1.docker.io",
                true,
            )],
            scan_policies: vec![scan_policy_repo_scope(
                "p1",
                "oci-mirror",
                "off",
                vec![],
                vec![],
                vec![], // scan waived → collapse
            )],
            ..Default::default()
        };
        let report = oci_validator().validate(&desired);
        let hits: Vec<_> = report
            .errors
            .iter()
            .filter(|f| f.rule == LinterRule::TrustUpstreamPublishTimeRequiresScanBackends)
            .collect();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].message.contains("oci-mirror"));
        assert!(hits[0].message.contains("p1"));
    }

    #[test]
    fn trust_pt_with_scanner_is_not_reported() {
        let desired = DesiredState {
            repositories: vec![repo_env("oci-mirror", "oci")],
            upstream_mappings: vec![upstream_mapping_env(
                "m1",
                "oci-mirror",
                "https://registry-1.docker.io",
                true,
            )],
            scan_policies: vec![scan_policy_repo_scope(
                "p1",
                "oci-mirror",
                "off",
                vec![],
                vec![],
                vec!["trivy"], // scanner runs → no collapse
            )],
            ..Default::default()
        };
        let report = oci_validator().validate(&desired);
        assert!(
            report
                .errors
                .iter()
                .all(|f| f.rule != LinterRule::TrustUpstreamPublishTimeRequiresScanBackends),
            "no collapse error expected: {:?}",
            report.errors
        );
    }

    // ---- row 6: prefetch max_age_days ---------------------------------

    #[test]
    fn prefetch_max_age_days_is_reported() {
        let mut repo = repo_env("npm-proxy", "npm");
        repo.spec.prefetch_policy.max_age_days = Some(90);
        let desired = DesiredState {
            repositories: vec![repo],
            ..Default::default()
        };
        let report = oci_validator().validate(&desired);
        let hits: Vec<_> = report
            .errors
            .iter()
            .filter(|f| f.rule == LinterRule::PrefetchMaxAgeDaysNotImplemented)
            .collect();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].message.contains("npm-proxy"));
        assert!(hits[0].message.contains("maxAgeDays"));
    }

    // ---- row 7: provenance config -------------------------------------

    #[test]
    fn provenance_required_on_no_verifier_format_is_reported() {
        let desired = DesiredState {
            repositories: vec![repo_env("npm-proxy", "npm")],
            scan_policies: vec![scan_policy_repo_scope(
                "p-req-npm",
                "npm-proxy",
                "required",
                vec!["cosign"],
                vec![sample_identity_spec()],
                vec!["trivy"],
            )],
            ..Default::default()
        };
        let report = oci_validator().validate(&desired);
        let hits: Vec<_> = report
            .errors
            .iter()
            .filter(|f| f.rule == LinterRule::ProvenanceConfig)
            .collect();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].message.contains("npm"));
        assert!(hits[0].message.contains("p-req-npm"));
    }

    #[test]
    fn provenance_non_off_with_empty_backends_is_reported() {
        let desired = DesiredState {
            repositories: vec![repo_env("oci-proxy", "oci")],
            scan_policies: vec![scan_policy_repo_scope(
                "p-no-backends",
                "oci-proxy",
                "verify_if_present",
                vec![],
                vec![sample_identity_spec()],
                vec!["trivy"],
            )],
            ..Default::default()
        };
        let report = oci_validator().validate(&desired);
        let hits: Vec<_> = report
            .errors
            .iter()
            .filter(|f| f.rule == LinterRule::ProvenanceConfig)
            .collect();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].message.contains("p-no-backends"));
        assert!(hits[0].message.contains("provenanceBackends"));
    }

    #[test]
    fn provenance_required_with_empty_identities_is_reported() {
        let desired = DesiredState {
            repositories: vec![repo_env("oci-proxy", "oci")],
            scan_policies: vec![scan_policy_repo_scope(
                "p-req-no-ids",
                "oci-proxy",
                "required",
                vec!["cosign"],
                vec![],
                vec!["trivy"],
            )],
            ..Default::default()
        };
        let report = oci_validator().validate(&desired);
        let hits: Vec<_> = report
            .errors
            .iter()
            .filter(|f| f.rule == LinterRule::ProvenanceConfig)
            .collect();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].message.contains("p-req-no-ids"));
        assert!(hits[0].message.contains("provenanceIdentities"));
    }

    #[test]
    fn provenance_verify_if_present_without_identities_is_a_warning() {
        let desired = DesiredState {
            repositories: vec![repo_env("oci-proxy", "oci")],
            scan_policies: vec![scan_policy_repo_scope(
                "p-verify-no-ids",
                "oci-proxy",
                "verify_if_present",
                vec!["cosign"],
                vec![],
                vec!["trivy"],
            )],
            ..Default::default()
        };
        let report = oci_validator().validate(&desired);
        assert!(report.errors.is_empty(), "errors: {:?}", report.errors);
        let hits: Vec<_> = report
            .warnings
            .iter()
            .filter(|f| f.rule == LinterRule::ProvenanceConfig)
            .collect();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].message.contains("p-verify-no-ids"));
        assert!(hits[0].message.contains("verify_if_present"));
    }

    #[test]
    fn provenance_global_required_reports_first_uncovered_format() {
        let desired = DesiredState {
            repositories: vec![
                repo_env("oci-proxy", "oci"),
                repo_env("cargo-proxy", "cargo"),
            ],
            scan_policies: vec![Envelope {
                api_version: ApiVersion::V1Beta1,
                kind: Kind::ScanPolicy,
                metadata: Metadata {
                    name: "p-global".into(),
                },
                spec: ScanPolicySpec {
                    scope: ScopeSpec::Global,
                    severity_threshold: "high".into(),
                    quarantine_duration: "24h".into(),
                    require_approval: true,
                    provenance_mode: "required".into(),
                    provenance_backends: vec!["cosign".into()],
                    provenance_identities: vec![sample_identity_spec()],
                    max_artifact_age: Some("90d".into()),
                    license_policy: serde_json::json!({"allowed": ["MIT"]}),
                    scan_backends: vec!["trivy".into()],
                    rescan_interval_hours: 24,
                },
            }],
            ..Default::default()
        };
        let report = oci_validator().validate(&desired);
        let hits: Vec<_> = report
            .errors
            .iter()
            .filter(|f| f.rule == LinterRule::ProvenanceConfig)
            .collect();
        assert_eq!(hits.len(), 1);
        // cargo is the uncovered format (oci is covered).
        assert!(hits[0].message.contains("cargo"));
    }

    #[test]
    fn provenance_repository_scope_unresolved_name_is_treated_as_covered() {
        // A Required policy scoped to a repository that is NOT declared:
        // the name does not resolve, so this linter treats it as covered
        // (the scope-existence validator owns that error) — no
        // provenance error from this rule.
        let desired = DesiredState {
            repositories: vec![repo_env("oci-proxy", "oci")],
            scan_policies: vec![scan_policy_repo_scope(
                "p-dangling",
                "does-not-exist",
                "required",
                vec!["cosign"],
                vec![sample_identity_spec()],
                vec!["trivy"],
            )],
            ..Default::default()
        };
        let report = oci_validator().validate(&desired);
        assert!(
            report
                .errors
                .iter()
                .all(|f| f.rule != LinterRule::ProvenanceConfig),
            "dangling scope must not produce a provenance error: {:?}",
            report.errors
        );
    }

    // ---- row 7b: storage backend mismatch -----------------------------

    #[test]
    fn storage_backend_mismatch_reported_when_backend_some() {
        let mut repo = repo_env("s3-on-fs", "oci");
        repo.spec.storage.as_mut().unwrap().backend = "s3".into();
        let desired = DesiredState {
            repositories: vec![repo],
            ..Default::default()
        };
        let v = StaticConfigValidator::new(
            formats(&["oci"]),
            Some(EffectiveStorageBackend::Filesystem),
        );
        let report = v.validate(&desired);
        let hits: Vec<_> = report
            .errors
            .iter()
            .filter(|f| f.rule == LinterRule::RepoStorageBackendMismatch)
            .collect();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].message.contains("s3"));
        assert!(hits[0].message.contains("filesystem"));
    }

    #[test]
    fn storage_backend_matching_is_not_reported() {
        let repo = repo_env("fs-on-fs", "oci"); // backend = filesystem
        let desired = DesiredState {
            repositories: vec![repo],
            ..Default::default()
        };
        let v = StaticConfigValidator::new(
            formats(&["oci"]),
            Some(EffectiveStorageBackend::Filesystem),
        );
        let report = v.validate(&desired);
        assert!(
            report
                .errors
                .iter()
                .all(|f| f.rule != LinterRule::RepoStorageBackendMismatch),
            "matching backend: {:?}",
            report.errors
        );
    }

    #[test]
    fn storage_backend_none_skips_row_7b() {
        // backend = s3 per repo, but the validator was built with None →
        // row 7b is skipped entirely (the apply-harness behaviour).
        let mut repo = repo_env("s3-unchecked", "oci");
        repo.spec.storage.as_mut().unwrap().backend = "s3".into();
        let desired = DesiredState {
            repositories: vec![repo],
            ..Default::default()
        };
        let report = oci_validator().validate(&desired); // None backend
        assert!(
            report.errors.is_empty(),
            "None backend must skip row 7b: {:?}",
            report.errors
        );
    }

    #[test]
    fn storage_backend_omitted_block_not_reported() {
        let mut repo = repo_env("omitted", "oci");
        repo.spec.storage = None;
        let desired = DesiredState {
            repositories: vec![repo],
            ..Default::default()
        };
        let v = StaticConfigValidator::new(formats(&["oci"]), Some(EffectiveStorageBackend::S3));
        let report = v.validate(&desired);
        assert!(
            report.errors.is_empty(),
            "omitted storage inherits — no mismatch: {:?}",
            report.errors
        );
    }

    // ---- collect-all: no early return ---------------------------------

    #[test]
    fn multiple_failing_rows_all_collected_in_row_order() {
        // Build a desired that trips: row 2 (SA→missing issuer), row 5
        // (trust_pt × scan_backends:[]), row 6 (max_age_days), row 7
        // (provenance Required on npm), row 7b (s3 on filesystem deploy).
        let mut npm_repo = repo_env("npm-proxy", "npm");
        npm_repo.spec.prefetch_policy.max_age_days = Some(90);
        npm_repo.spec.storage.as_mut().unwrap().backend = "s3".into();

        let desired = DesiredState {
            repositories: vec![npm_repo],
            // SA referencing an undeclared issuer (row 2) AND
            // under-constrained (row 3 warning).
            service_accounts: vec![sa_env_under_constrained("ci-loose", "missing-idp")],
            upstream_mappings: vec![upstream_mapping_env(
                "m1",
                "npm-proxy",
                "https://npm.example.com",
                true,
            )],
            scan_policies: vec![scan_policy_repo_scope(
                "p-req-npm",
                "npm-proxy",
                "required",
                vec!["cosign"],
                vec![sample_identity_spec()],
                vec![], // scan waived → row 5 collapse too
            )],
            ..Default::default()
        };
        let v = StaticConfigValidator::new(
            formats(&["oci"]),
            Some(EffectiveStorageBackend::Filesystem),
        );
        let report = v.validate(&desired);

        // Errors collected for every failing row — proves no early return.
        let rules: Vec<LinterRule> = report.errors.iter().map(|f| f.rule).collect();
        assert!(rules.contains(&LinterRule::SaIssuerFk), "{rules:?}");
        assert!(
            rules.contains(&LinterRule::TrustUpstreamPublishTimeRequiresScanBackends),
            "{rules:?}"
        );
        assert!(
            rules.contains(&LinterRule::PrefetchMaxAgeDaysNotImplemented),
            "{rules:?}"
        );
        assert!(rules.contains(&LinterRule::ProvenanceConfig), "{rules:?}");
        assert!(
            rules.contains(&LinterRule::RepoStorageBackendMismatch),
            "{rules:?}"
        );

        // And in apply's row order: SaIssuerFk before trust_pt before
        // prefetch before provenance before storage-backend.
        let pos = |want: LinterRule| rules.iter().position(|r| *r == want).unwrap();
        assert!(
            pos(LinterRule::SaIssuerFk)
                < pos(LinterRule::TrustUpstreamPublishTimeRequiresScanBackends)
        );
        assert!(
            pos(LinterRule::TrustUpstreamPublishTimeRequiresScanBackends)
                < pos(LinterRule::PrefetchMaxAgeDaysNotImplemented)
        );
        assert!(
            pos(LinterRule::PrefetchMaxAgeDaysNotImplemented) < pos(LinterRule::ProvenanceConfig)
        );
        assert!(pos(LinterRule::ProvenanceConfig) < pos(LinterRule::RepoStorageBackendMismatch));

        // The under-constrained FI warning is still collected.
        assert!(report
            .warnings
            .iter()
            .any(|f| f.rule == LinterRule::UnderConstrainedFederatedIdentities));
    }

    // ---- row 8: permission-grant linter -------------------------------

    use hort_config::claim_mapping::ClaimMappingSpec;
    use hort_config::lint_config::{
        PermissionGrantLintConfigSpec, RuleActionSpec, RuleOverridesSpec,
    };
    use hort_config::permission_grant::{GrantSubjectSpec, PermissionGrantSpec};

    /// A validator with row 8 ENABLED at the secure-default base config.
    fn grant_lint_validator() -> StaticConfigValidator {
        StaticConfigValidator::new(formats(&["oci"]), None)
            .with_grant_lint_base(LintConfig::default())
    }

    fn claims_grant_env(
        name: &str,
        required: &[&str],
        permission: &str,
        repository: Option<&str>,
    ) -> Envelope<PermissionGrantSpec> {
        Envelope {
            api_version: ApiVersion::V1Beta1,
            kind: Kind::PermissionGrant,
            metadata: Metadata { name: name.into() },
            spec: PermissionGrantSpec {
                subject: GrantSubjectSpec::Claims {
                    required: required.iter().map(|s| (*s).to_string()).collect(),
                },
                permission: permission.into(),
                repository: repository.map(Into::into),
            },
        }
    }

    fn user_grant_env(
        name: &str,
        user_id: &str,
        permission: &str,
        repository: Option<&str>,
    ) -> Envelope<PermissionGrantSpec> {
        Envelope {
            api_version: ApiVersion::V1Beta1,
            kind: Kind::PermissionGrant,
            metadata: Metadata { name: name.into() },
            spec: PermissionGrantSpec {
                subject: GrantSubjectSpec::User {
                    user_id: user_id.into(),
                },
                permission: permission.into(),
                repository: repository.map(Into::into),
            },
        }
    }

    fn claim_mapping_env(name: &str, idp_group: &str, claim: &str) -> Envelope<ClaimMappingSpec> {
        Envelope {
            api_version: ApiVersion::V1Beta1,
            kind: Kind::ClaimMapping,
            metadata: Metadata { name: name.into() },
            spec: ClaimMappingSpec {
                idp_group: idp_group.into(),
                claim: claim.into(),
            },
        }
    }

    /// A `ServiceAccount` envelope (role `developer` ⇒ Write) granting
    /// over `repos`.
    fn sa_env_with_repos(name: &str, role: &str, repos: &[&str]) -> Envelope<ServiceAccountSpec> {
        Envelope {
            api_version: ApiVersion::V1Beta1,
            kind: Kind::ServiceAccount,
            metadata: Metadata { name: name.into() },
            spec: ServiceAccountSpec {
                role: role.into(),
                repositories: repos.iter().map(|s| (*s).into()).collect(),
                federated_identities: vec![],
                fallback_rotation: None,
            },
        }
    }

    fn grant_findings(report: &StaticLintReport) -> usize {
        report
            .errors
            .iter()
            .chain(report.warnings.iter())
            .filter(|f| f.rule == LinterRule::PermissionGrant)
            .count()
    }

    /// (a) A single-claim grant rejects (no allowlist).
    #[test]
    fn row8_single_claim_grant_rejects() {
        let desired = DesiredState {
            permission_grants: vec![claims_grant_env(
                "solo",
                &["team-alpha"],
                "read",
                Some("repo-x"),
            )],
            ..Default::default()
        };
        let report = grant_lint_validator().validate(&desired);
        assert!(report
            .errors
            .iter()
            .any(|f| f.rule == LinterRule::PermissionGrant));
        // The message names the underlying rule key.
        assert!(report
            .errors
            .iter()
            .any(|f| f.rule == LinterRule::PermissionGrant
                && f.message.contains("single-claim-grant")));
    }

    /// (b) A wildcard-repo (repository: None) non-admin Claims grant rejects.
    #[test]
    fn row8_wildcard_repo_non_admin_rejects() {
        let desired = DesiredState {
            permission_grants: vec![claims_grant_env(
                "everywhere",
                &["developer", "ops"],
                "write",
                None,
            )],
            ..Default::default()
        };
        let report = grant_lint_validator().validate(&desired);
        assert!(report
            .errors
            .iter()
            .any(|f| f.rule == LinterRule::PermissionGrant
                && f.message.contains("wildcard-repo-non-admin")));
    }

    /// (c) An unjustified direct-User high-privilege (wildcard Admin) grant
    /// rejects.
    #[test]
    fn row8_unjustified_high_priv_direct_user_rejects() {
        let uid = Uuid::new_v4().to_string();
        let desired = DesiredState {
            permission_grants: vec![user_grant_env("god-mode", &uid, "admin", None)],
            ..Default::default()
        };
        let report = grant_lint_validator().validate(&desired);
        assert!(report
            .errors
            .iter()
            .any(|f| f.rule == LinterRule::PermissionGrant
                && f.message
                    .contains("direct-user-grant-without-justification")));
    }

    /// (d) A reserved-claim-name collision rejects.
    #[test]
    fn row8_reserved_claim_collision_rejects() {
        let desired = DesiredState {
            claim_mappings: vec![claim_mapping_env("bad", "ops-group", "service_account")],
            ..Default::default()
        };
        let report = grant_lint_validator().validate(&desired);
        assert!(report
            .errors
            .iter()
            .any(|f| f.rule == LinterRule::PermissionGrant
                && f.message.contains("claim-name-collision")));
    }

    /// (e) An SA-owned direct-User grant is NOT rejected — the synthetic
    /// backing_user_id is threaded into both the grant subject and the
    /// sa_owned set, so the provenance exemption fires (proves the
    /// placeholder id threading is consistent). Without the threading this
    /// would reject as an unjustified high-priv direct-user grant.
    #[test]
    fn row8_sa_owned_direct_user_grant_is_exempt() {
        let desired = DesiredState {
            // role developer ⇒ Write; the SA owns a repo-scoped grant.
            service_accounts: vec![sa_env_with_repos("ci-bot", "developer", &["repo-x"])],
            ..Default::default()
        };
        let report = grant_lint_validator().validate(&desired);
        assert_eq!(
            grant_findings(&report),
            0,
            "SA-owned grant must be exempt (provenance): {:?}",
            report.errors
        );
    }

    /// (f) A clean grant set produces no row-8 findings: a multi-claim
    /// repo-scoped grant + an SA-owned grant + ordinary claim mappings.
    #[test]
    fn row8_clean_set_no_findings() {
        let desired = DesiredState {
            permission_grants: vec![claims_grant_env(
                "scoped-write",
                &["developer", "team-alpha"],
                "write",
                Some("repo-x"),
            )],
            service_accounts: vec![sa_env_with_repos("ci-bot", "reader", &["repo-x"])],
            claim_mappings: vec![claim_mapping_env("m1", "dev-group", "developer")],
            ..Default::default()
        };
        let report = grant_lint_validator().validate(&desired);
        assert_eq!(
            grant_findings(&report),
            0,
            "clean set must produce no row-8 findings: {:?}",
            report
        );
    }

    /// With `grant_lint_base = None` (the apply / `new` default), row 8
    /// produces NO findings even for a grant set that WOULD reject — proving
    /// the apply path's `validate()` never double-lints grants.
    #[test]
    fn row8_disabled_by_default_produces_no_findings() {
        let desired = DesiredState {
            permission_grants: vec![claims_grant_env("solo", &["team-alpha"], "read", None)],
            claim_mappings: vec![claim_mapping_env("bad", "g", "service_account")],
            ..Default::default()
        };
        // `oci_validator()` is built via `new` ⇒ grant_lint_base = None.
        let report = oci_validator().validate(&desired);
        assert_eq!(
            grant_findings(&report),
            0,
            "row 8 must be off when grant_lint_base is None: {:?}",
            report.errors
        );
    }

    /// An operator downgrade in the desired `PermissionGrantLintConfig`
    /// reaches row 8 — a wildcard-repo-non-admin grant downgraded to `warn`
    /// lands as a warning, not an error (proves the resolver is consulted).
    #[test]
    fn row8_operator_downgrade_lands_as_warning() {
        let lint_env = Envelope {
            api_version: ApiVersion::V1Beta1,
            kind: Kind::PermissionGrantLintConfig,
            metadata: Metadata {
                name: "rbac-lint".into(),
            },
            spec: PermissionGrantLintConfigSpec {
                single_claim_allowlist: Vec::new(),
                rule_overrides: RuleOverridesSpec {
                    wildcard_repo_non_admin: Some(RuleActionSpec::Warn),
                    ..RuleOverridesSpec::default()
                },
            },
        };
        let desired = DesiredState {
            permission_grants: vec![claims_grant_env(
                "everywhere",
                &["developer", "ops"],
                "write",
                None,
            )],
            lint_config: Some(lint_env),
            ..Default::default()
        };
        let report = grant_lint_validator().validate(&desired);
        assert!(
            report
                .errors
                .iter()
                .all(|f| f.rule != LinterRule::PermissionGrant),
            "downgraded rule must not be an error: {:?}",
            report.errors
        );
        assert!(report
            .warnings
            .iter()
            .any(|f| f.rule == LinterRule::PermissionGrant
                && f.message.contains("wildcard-repo-non-admin")));
    }

    /// Metric-suppression: running `validate()` with row 8 enabled INSIDE
    /// a `DebuggingRecorder` records ZERO `hort_apply_config_linter_total`
    /// series — the local `NoopRecorder` swallowed every emission the grant
    /// linter makes internally, so the CLI path emits no metric.
    #[test]
    fn row8_emits_no_linter_metric() {
        use metrics_util::debugging::DebuggingRecorder;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            // A grant set that fires multiple rules (single-claim +
            // wildcard) — the linter would emit several series if not
            // suppressed.
            let desired = DesiredState {
                permission_grants: vec![claims_grant_env("solo", &["team-alpha"], "read", None)],
                claim_mappings: vec![claim_mapping_env("bad", "g", "service_account")],
                ..Default::default()
            };
            let report = grant_lint_validator().validate(&desired);
            // Sanity: row 8 DID run (so the suppression is meaningful).
            assert!(
                report
                    .errors
                    .iter()
                    .any(|f| f.rule == LinterRule::PermissionGrant),
                "row 8 must have produced findings for this corpus"
            );
        });
        let metrics = snapshotter.snapshot().into_vec();
        let linter: Vec<_> = metrics
            .iter()
            .filter(|(k, _, _, _)| k.key().name() == "hort_apply_config_linter_total")
            .collect();
        assert!(
            linter.is_empty(),
            "the validator's row 8 must emit NO hort_apply_config_linter_total \
             series (NoopRecorder suppression), got {}",
            linter.len()
        );
    }
}
