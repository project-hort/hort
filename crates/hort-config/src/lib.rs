//! Gitops configuration parsing for hort.
//!
//! Zero-I/O library: takes parsed bytes, produces validated objects
//! and a diff. File-walking and persistence live in `hort-server` and
//! `hort-app` respectively. See
//! `docs/architecture/how-to/declare-gitops-config.md` for the
//! operator-facing schema.
//!
//! The `PermissionGrant`, `CurationRule`, `ScanPolicy`, and `Exclusion`
//! kinds round out the surface. The first two reuse the CRUD diff
//! machinery; the latter two are event-sourced and run through the
//! `ApplyEventSourcedKind` trait (out of scope for this crate).
//!
//! The RBAC model is additive-claims (ADR 0012): there are no
//! `RoleSpec` / `GroupMappingSpec` kinds; `ClaimMappingSpec` maps an
//! IdP group to a claim, and `PermissionGrantSpec` carries a sum-typed
//! subject.
//!
//! Dependency rule: this crate must never reach for `tokio`, `tracing`,
//! `sqlx`, `axum`, or `reqwest`. Anything that needs those belongs in
//! the boot caller, the apply use case, or the adapter layer.

pub mod claim_mapping;
pub mod curation_rule;
pub mod desired;
pub mod diff;
pub mod envelope;
pub mod error;
pub mod exclusion;
pub mod extra_ca;
pub mod interpolate;
pub mod lint_config;
pub mod oidc_issuer;
pub mod permission_grant;
pub mod repository;
pub mod retention_policy;
pub mod scan_policy;
pub mod scope;
pub mod service_account;
pub mod upstream_mapping;
pub mod user_agent;

pub use claim_mapping::{parse_claim_mapping, ClaimMappingSpec};
pub use curation_rule::{parse_curation_rule, validate_curation_rule, CurationRuleSpec};
pub use desired::{DesiredState, EnvAuthProvider, EnvSnapshot, EnvelopeKey};
pub use diff::{
    diff, spec_digest_claim_mapping, spec_digest_curation_rule, spec_digest_oidc_issuer,
    spec_digest_permission_grant, spec_digest_repository, spec_digest_service_account,
    spec_digest_upstream_mapping, ApplyPlan, CurrentClaimMapping, CurrentCurationRule,
    CurrentOidcIssuer, CurrentPermissionGrant, CurrentRepository, CurrentServiceAccount,
    CurrentSnapshot, CurrentUpstreamMapping, KindPlan,
};
pub use envelope::{ApiVersion, Envelope, Kind, Metadata};
pub use error::{ParseError, ParseErrors, ValidationError, ValidationErrors};
pub use exclusion::{parse_exclusion, validate_exclusion, ExclusionSpec};
pub use extra_ca::{ExtraCaParseError, ExtraTrustAnchors};
pub use interpolate::interpolate;
pub use lint_config::{
    parse_lint_config, validate_lint_config, PermissionGrantLintConfigSpec, RuleActionSpec,
    RuleOverridesSpec, RESERVED_ALLOWLIST_NAMES,
};
pub use oidc_issuer::{parse_oidc_issuer, validate_oidc_issuer, OidcIssuerSpec};
pub use permission_grant::{
    parse_permission_grant, validate_permission_grant, GrantIdentity, GrantSubjectSpec,
    PermissionGrantSpec,
};
pub use repository::{
    parse_repository, validate_repository, ProxySpec, RepositorySpec, StorageSpec,
};
pub use retention_policy::{
    parse_retention_policy, validate_retention_policy, RetentionPolicySpec,
};
pub use scan_policy::{parse_scan_policy, validate_scan_policy, ScanPolicySpec};
pub use scope::{RepositoryScope, ScopeSpec};
pub use service_account::{
    detect_under_constrained_federated_identities, parse_service_account, validate_service_account,
    FallbackRotationSpec, FederatedIdentitySpec, ServiceAccountSpec, TargetSecretSpec,
    UnderConstrainedFederatedIdentity,
};
pub use upstream_mapping::{
    parse_upstream_mapping, validate_upstream_mapping, UpstreamAuthSpec, UpstreamMappingSpec,
};
pub use user_agent::DEFAULT_USER_AGENT;
