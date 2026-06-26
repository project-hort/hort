//! `kind: PermissionGrant` schema, parser, and per-spec validation
//! (additive-claims model — see ADR 0012).
//!
//! A `PermissionGrant` carries a **sum-typed subject** mirroring
//! `hort_domain::entities::rbac::GrantSubject`:
//!
//! - `subject: { kind: claims, required: [developer, team-alpha] }` —
//!   the caller must possess every listed claim (subset match against
//!   the resolved `principal.claims`).
//! - `subject: { kind: user, userId: "<uuid>" }` — direct user-id
//!   binding (service accounts, one-off escalations); bypasses the
//!   claim mechanism entirely.
//! - `subject: { kind: serviceAccount, name: "maintainer-dev" }` — a
//!   gitops-spec sugar that names a declared `ServiceAccount`. The apply
//!   pipeline resolves it to the domain
//!   `GrantSubject::User(<sa.backing_user_id>)` (SA aggregate lookup by
//!   name), so the **domain `GrantSubject` taxonomy is unchanged** (still
//!   `Claims | User`; ADR 0012's two-variant closure is preserved — this
//!   is an authoring convenience that compiles down to `User`). An SA's
//!   backing-user UUID is minted at apply (`Uuid::new_v4()` in
//!   `ensure_backing_user`) and therefore unknowable when authoring, so
//!   naming the SA is the only way to express global / curate /
//!   admin_task_invoke authority for a service account in gitops (the
//!   `ServiceAccount` envelope itself is repo-scoped only — see ADR 0037,
//!   spec §9).
//!
//! One CRD declares exactly one grant: one `subject`, one
//! `permission`, and an optional single `repository`. The domain
//! `PermissionGrant` row carries one permission and one optional
//! repository; bundling is expressed at the operator-side YAML-templating
//! layer, not via array expansion in the spec.
//!
//! # Diff identity
//!
//! Identity is subject-dependent (see [`PermissionGrantSpec::diff_identity`]):
//! `(sorted required_claims, repository, permission)` for a `Claims`
//! subject; `(user_id, repository, permission)` for a `User` subject;
//! `(sa_name, repository, permission)` for an as-yet-unresolved
//! `ServiceAccount` subject (the apply pipeline rewrites it to the
//! `User` identity once the SA's backing user exists). `metadata.name`
//! is operator-cosmetic and does NOT participate in identity. The
//! apply/diff layers (`crate::diff`) consume
//! [`PermissionGrantSpec::diff_identity`].

use std::str::FromStr;

use hort_domain::entities::rbac::Permission;
use serde::{Deserialize, Serialize};

use crate::envelope::{Envelope, Kind};
use crate::error::{ParseError, ValidationError};

/// The subject a `PermissionGrant` binds to — the gitops mirror of
/// `hort_domain::entities::rbac::GrantSubject`.
///
/// Internally tagged on `kind` so the YAML reads
/// `subject: { kind: claims, required: [...] }` /
/// `subject: { kind: user, userId: "<uuid>" }` /
/// `subject: { kind: serviceAccount, name: "..." }`. `userId` is carried
/// as a string here (the spec layer is reference-resolving only — the
/// apply pipeline parses it to a `Uuid`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum GrantSubjectSpec {
    /// Subset-match against the caller's resolved claims. `required`
    /// must contain at least one entry (an empty set would be an
    /// unintended wildcard — rejected by `validate_permission_grant`
    /// and by the `claims_nonempty` DB CHECK).
    Claims { required: Vec<String> },
    /// Direct user-id binding. `userId` is an unresolved string here;
    /// the apply pipeline parses it to a `Uuid`.
    #[serde(rename_all = "camelCase")]
    User { user_id: String },
    /// Gitops-spec sugar naming a declared `ServiceAccount`. The apply
    /// pipeline resolves `name` to the SA's backing-user UUID and
    /// materialises the grant as the domain
    /// `GrantSubject::User(<sa.backing_user_id>)` — the **domain
    /// taxonomy stays two-variant** (`Claims | User`; ADR 0012). Cross-spec
    /// validation (`crate::desired`) enforces that a `ServiceAccount` of
    /// this `name` is declared, mirroring the `repository`-reference
    /// check. Resolves to the same row shape an equivalent `User`-subject
    /// grant would, so it diffs identically (no SA name leaks into the
    /// diff identity). See ADR 0037 / spec §9.
    ServiceAccount { name: String },
}

/// Shape of a `kind: PermissionGrant` YAML body.
///
/// `subject` is the sum-typed claims-or-user binding. `permission` is a
/// single `read | write | delete | admin` string, validated via
/// `Permission::FromStr` in `validate_permission_grant`. `repository`
/// is optional — `None` is a global grant (every repo); `Some(name)`
/// scopes the grant to one declared `ArtifactRepository`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionGrantSpec {
    /// Claims / user / serviceAccount subject. `Claims` and `User`
    /// mirror `hort_domain::entities::rbac::GrantSubject` directly;
    /// `ServiceAccount { name }` is a gitops-spec sugar the apply
    /// pipeline resolves to `GrantSubject::User(backing_user_id)`.
    pub subject: GrantSubjectSpec,
    /// One of `read | write | delete | admin`. Validated via
    /// `Permission::FromStr`.
    pub permission: String,
    /// Optional `ArtifactRepository.metadata.name` reference. `None`
    /// is a global grant; `Some(name)` scopes to that repo. Cross-spec
    /// validation enforces existence of the referenced repository.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
}

/// Subject-dependent diff/upsert identity for a grant.
///
/// `Claims` grants key off `(sorted required_claims, repository,
/// permission)`; `User` grants key off `(user_id, repository,
/// permission)`. The arms are disjoint by construction (one
/// envelope yields exactly one identity), so a single enum captures
/// them without ambiguity.
///
/// A `ServiceAccount`-subject grant *resolves* to a [`GrantIdentity::User`]
/// (keyed on the resolved `backing_user_id`) the moment the SA exists —
/// the apply pipeline rewrites the subject to `User` before the cosmetic
/// diff plan compares against the current rows, so a re-apply is a no-op.
/// The [`GrantIdentity::ServiceAccount`] arm below exists only for the
/// transient first-apply window when the SA's backing user has not yet
/// been minted (so `name → uuid` cannot resolve): it keys on the SA name
/// so the fresh grant classifies as `create` exactly once. It never
/// matches a current `User`-subject row (no SA name leaks into a
/// persisted grant — the row is always `User(backing_user_id)`), which is
/// the intended behaviour for a not-yet-created SA grant. See ADR 0037.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GrantIdentity {
    /// `(sorted required_claims, repository, permission)`.
    Claims {
        required: Vec<String>,
        repository: Option<String>,
        permission: Permission,
    },
    /// `(user_id, repository, permission)`.
    User {
        user_id: String,
        repository: Option<String>,
        permission: Permission,
    },
    /// `(sa_name, repository, permission)` — the transient
    /// first-apply identity of an unresolved `ServiceAccount`-subject
    /// grant (see the type doc). Disjoint from `User` by construction
    /// (a persisted row is never `ServiceAccount`-keyed).
    ServiceAccount {
        sa_name: String,
        repository: Option<String>,
        permission: Permission,
    },
}

impl PermissionGrantSpec {
    /// The subject-dependent diff identity for this grant.
    ///
    /// Invariant: only callable after [`validate_permission_grant`] has
    /// returned an empty error list — `permission` is then guaranteed
    /// to parse. An invalid permission falls back to a deterministic
    /// `Permission::Read` placeholder so the function is total (the
    /// `unwrap_or` is provably unreachable after
    /// `validate_permission_grant`, so the fallback is a totality
    /// default, not a gap); the apply layer never sees invalid input
    /// because validation gates it first.
    pub fn diff_identity(&self) -> GrantIdentity {
        let permission = Permission::from_str(&self.permission).unwrap_or(Permission::Read);
        let repository = self.repository.clone();
        match &self.subject {
            GrantSubjectSpec::Claims { required } => {
                let mut required = required.clone();
                required.sort();
                GrantIdentity::Claims {
                    required,
                    repository,
                    permission,
                }
            }
            GrantSubjectSpec::User { user_id } => GrantIdentity::User {
                user_id: user_id.clone(),
                repository,
                permission,
            },
            GrantSubjectSpec::ServiceAccount { name } => GrantIdentity::ServiceAccount {
                sa_name: name.clone(),
                repository,
                permission,
            },
        }
    }
}

/// Parse one `PermissionGrant` envelope.
pub fn parse_permission_grant(
    _path: &std::path::Path,
    bytes: &[u8],
) -> Result<Envelope<PermissionGrantSpec>, ParseError> {
    let env: Envelope<PermissionGrantSpec> = serde_yaml_ng::from_slice(bytes)?;
    if env.kind != Kind::PermissionGrant {
        return Err(ParseError::UnknownKind {
            got: env.kind.to_string(),
            valid: &["PermissionGrant"],
        });
    }
    if env.metadata.name.is_empty() {
        return Err(ParseError::EmptyMetadataName);
    }
    Ok(env)
}

/// Per-spec validation. Confirms `permission` parses through
/// `Permission::FromStr`; the subject is well-formed (a `Claims`
/// subject has a non-empty `required` set with no blank entries; a
/// `User` subject has a non-blank `userId`); `repository` (when
/// present) is non-blank; plus the standard non-blank-name guard.
///
/// The `repository` reference is checked cross-spec in
/// `crate::desired::validate`.
pub fn validate_permission_grant(env: &Envelope<PermissionGrantSpec>) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    if env.metadata.name.trim().is_empty() {
        errors.push(ValidationError::Invalid {
            kind: Kind::PermissionGrant,
            name: env.metadata.name.clone(),
            detail: "metadata.name must not be blank".into(),
        });
    }

    match &env.spec.subject {
        GrantSubjectSpec::Claims { required } => {
            if required.is_empty() {
                errors.push(ValidationError::Invalid {
                    kind: Kind::PermissionGrant,
                    name: env.metadata.name.clone(),
                    detail: "subject.required must contain at least one claim \
                             (an empty set is an unintended wildcard)"
                        .into(),
                });
            }
            for claim in required {
                if claim.trim().is_empty() {
                    errors.push(ValidationError::Invalid {
                        kind: Kind::PermissionGrant,
                        name: env.metadata.name.clone(),
                        detail: "subject.required[*] must not be blank".into(),
                    });
                }
            }
        }
        GrantSubjectSpec::User { user_id } => {
            if user_id.trim().is_empty() {
                errors.push(ValidationError::Invalid {
                    kind: Kind::PermissionGrant,
                    name: env.metadata.name.clone(),
                    detail: "subject.userId must not be blank".into(),
                });
            }
        }
        GrantSubjectSpec::ServiceAccount { name } => {
            // Per-spec: a non-blank reference. Existence of the named
            // ServiceAccount is checked cross-spec in `crate::desired`
            // (it surfaces as a `DanglingReference`), mirroring the
            // `spec.repository` reference check — a per-spec validator
            // sees one envelope at a time and cannot resolve it.
            if name.trim().is_empty() {
                errors.push(ValidationError::Invalid {
                    kind: Kind::PermissionGrant,
                    name: env.metadata.name.clone(),
                    detail: "subject.name (serviceAccount) must not be blank".into(),
                });
            }
            // ADR 0038: service accounts are strictly non-admin — no
            // exception, including on the standalone-grant axis. The
            // §9 `serviceAccount`-subject grant resolves to a
            // `GrantSubject::User(backing_user_id)`, so without this
            // gate an operator could author a `serviceAccount` subject
            // with `permission: admin` and have it apply as a real
            // global Admin grant (while the identical hand-rolled
            // `User`-subject row is rejected by the linter). This is
            // the earliest + clearest gate; the `hort-app` apply-config
            // linter's scoped provenance exemption is defense-in-depth.
            if matches!(
                Permission::from_str(&env.spec.permission),
                Ok(Permission::Admin)
            ) {
                errors.push(ValidationError::Invalid {
                    kind: Kind::PermissionGrant,
                    name: env.metadata.name.clone(),
                    detail: "spec.permission: a serviceAccount subject may not hold 'admin' \
                             — service accounts are strictly non-admin (ADR 0038)"
                        .into(),
                });
            }
        }
    }

    if Permission::from_str(&env.spec.permission).is_err() {
        // The diagnostic surface the operator sees on an unknown
        // permission. Must enumerate every `Permission::FromStr`
        // variant — a stale list is dishonest tooling, not a feature.
        // See test `unknown_permission_diagnostic_lists_every_variant`.
        errors.push(ValidationError::UnknownEnumValue {
            field: "spec.permission",
            got: env.spec.permission.clone(),
            expected: vec![
                "read",
                "write",
                "delete",
                "admin",
                "admin_task_invoke",
                "curate",
            ],
        });
    }

    if let Some(repo) = env.spec.repository.as_ref() {
        if repo.trim().is_empty() {
            errors.push(ValidationError::Invalid {
                kind: Kind::PermissionGrant,
                name: env.metadata.name.clone(),
                detail: "spec.repository must be omitted for a global grant; \
                         an empty string is not the same"
                    .into(),
            });
        }
    }

    errors
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
            "apiVersion: project-hort.de/v1beta1\nkind: PermissionGrant\nmetadata:\n  name: {name}\nspec:{body}"
        )
    }

    // ---- Claims subject ---------------------------------------------------

    #[test]
    fn parse_claims_subject_scoped_grant_round_trip() {
        let body = "
  subject: { kind: claims, required: [developer, team-alpha] }
  permission: write
  repository: pypi-alpha
";
        let env = parse_permission_grant(&p(), yaml("dev-write-pypi", body).as_bytes()).unwrap();
        assert_eq!(
            env.spec.subject,
            GrantSubjectSpec::Claims {
                required: vec!["developer".into(), "team-alpha".into()]
            }
        );
        assert_eq!(env.spec.permission, "write");
        assert_eq!(env.spec.repository.as_deref(), Some("pypi-alpha"));
        assert!(validate_permission_grant(&env).is_empty());

        match env.spec.diff_identity() {
            GrantIdentity::Claims {
                required,
                repository,
                permission,
            } => {
                // sorted
                assert_eq!(required, vec!["developer", "team-alpha"]);
                assert_eq!(repository.as_deref(), Some("pypi-alpha"));
                assert_eq!(permission, Permission::Write);
            }
            other => panic!("expected Claims identity, got {other:?}"),
        }
    }

    #[test]
    fn diff_identity_sorts_required_claims() {
        // Two envelopes declaring the same claim set in different YAML
        // order must produce the same identity (apply replay = no-op).
        let body_a = "
  subject: { kind: claims, required: [team-alpha, developer] }
  permission: read
";
        let body_b = "
  subject: { kind: claims, required: [developer, team-alpha] }
  permission: read
";
        let a = parse_permission_grant(&p(), yaml("a", body_a).as_bytes()).unwrap();
        let b = parse_permission_grant(&p(), yaml("b", body_b).as_bytes()).unwrap();
        assert_eq!(a.spec.diff_identity(), b.spec.diff_identity());
    }

    #[test]
    fn parse_claims_global_grant_omits_repository() {
        let body = "
  subject: { kind: claims, required: [admin] }
  permission: admin
";
        let env = parse_permission_grant(&p(), yaml("admin-global", body).as_bytes()).unwrap();
        assert!(env.spec.repository.is_none());
        assert!(validate_permission_grant(&env).is_empty());
        match env.spec.diff_identity() {
            GrantIdentity::Claims {
                repository,
                permission,
                ..
            } => {
                assert!(repository.is_none());
                assert_eq!(permission, Permission::Admin);
            }
            other => panic!("expected Claims identity, got {other:?}"),
        }
    }

    // ---- User subject -----------------------------------------------------

    #[test]
    fn parse_user_subject_round_trip() {
        let body = "
  subject: { kind: user, userId: 11111111-2222-3333-4444-555555555555 }
  permission: write
  repository: pypi-prod
";
        let env = parse_permission_grant(&p(), yaml("sa-write-prod", body).as_bytes()).unwrap();
        assert_eq!(
            env.spec.subject,
            GrantSubjectSpec::User {
                user_id: "11111111-2222-3333-4444-555555555555".into()
            }
        );
        assert!(validate_permission_grant(&env).is_empty());
        match env.spec.diff_identity() {
            GrantIdentity::User {
                user_id,
                repository,
                permission,
            } => {
                assert_eq!(user_id, "11111111-2222-3333-4444-555555555555");
                assert_eq!(repository.as_deref(), Some("pypi-prod"));
                assert_eq!(permission, Permission::Write);
            }
            other => panic!("expected User identity, got {other:?}"),
        }
    }

    // ---- ServiceAccount subject (ADR 0037 / spec §9) ----------------------

    #[test]
    fn parse_service_account_subject_round_trip() {
        let body = "
  subject: { kind: serviceAccount, name: maintainer-dev }
  permission: read
";
        let env = parse_permission_grant(&p(), yaml("sa-global-read", body).as_bytes()).unwrap();
        assert_eq!(
            env.spec.subject,
            GrantSubjectSpec::ServiceAccount {
                name: "maintainer-dev".into()
            }
        );
        assert_eq!(env.spec.permission, "read");
        // Global grant (no repository) — the audited operator path.
        assert!(env.spec.repository.is_none());
        // Per-spec validation passes (cross-spec SA-existence is
        // checked in `crate::desired`, not here).
        assert!(validate_permission_grant(&env).is_empty());

        match env.spec.diff_identity() {
            GrantIdentity::ServiceAccount {
                sa_name,
                repository,
                permission,
            } => {
                assert_eq!(sa_name, "maintainer-dev");
                assert!(repository.is_none());
                assert_eq!(permission, Permission::Read);
            }
            other => panic!("expected ServiceAccount identity, got {other:?}"),
        }
    }

    #[test]
    fn parse_service_account_subject_repo_scoped_curate_round_trip() {
        // The non-read/write authority a `ServiceAccount` envelope cannot
        // express: curate, here repo-scoped.
        let body = "
  subject: { kind: serviceAccount, name: maintainer-curator }
  permission: curate
  repository: oci-prod
";
        let env = parse_permission_grant(&p(), yaml("curator-grant", body).as_bytes()).unwrap();
        assert_eq!(
            env.spec.subject,
            GrantSubjectSpec::ServiceAccount {
                name: "maintainer-curator".into()
            }
        );
        assert!(validate_permission_grant(&env).is_empty());
        match env.spec.diff_identity() {
            GrantIdentity::ServiceAccount {
                sa_name,
                repository,
                permission,
            } => {
                assert_eq!(sa_name, "maintainer-curator");
                assert_eq!(repository.as_deref(), Some("oci-prod"));
                assert_eq!(permission, Permission::Curate);
            }
            other => panic!("expected ServiceAccount identity, got {other:?}"),
        }
    }

    #[test]
    fn parse_service_account_subject_admin_task_invoke_validates() {
        // `admin_task_invoke` is a non-admin authority an SA envelope
        // cannot grant — only a standalone serviceAccount grant can.
        let body = "
  subject: { kind: serviceAccount, name: cronjob-sa }
  permission: admin_task_invoke
";
        let env = parse_permission_grant(&p(), yaml("cron-task", body).as_bytes()).unwrap();
        assert!(validate_permission_grant(&env).is_empty());
    }

    #[test]
    fn validate_rejects_service_account_subject_admin_permission() {
        // ADR 0038: a serviceAccount subject may not hold `admin`. The
        // §9 SA-subject grant resolves to a `GrantSubject::User`, so
        // without this gate a `serviceAccount` + `permission: admin`
        // would apply as a real global Admin grant. Hard-rejected at
        // the per-spec validator (the earliest, clearest gate).
        let body = "
  subject: { kind: serviceAccount, name: cronjob-sa }
  permission: admin
";
        let env = parse_permission_grant(&p(), yaml("sa-admin", body).as_bytes()).unwrap();
        let errors = validate_permission_grant(&env);
        assert!(
            errors.iter().any(|e| e
                .to_string()
                .contains("serviceAccount subject may not hold 'admin'")),
            "serviceAccount + permission: admin must be a validation error: {errors:?}"
        );
    }

    #[test]
    fn validate_accepts_service_account_subject_non_admin_permissions() {
        // The reject is scoped to `admin` ONLY — every other permission
        // a serviceAccount subject may legitimately hold (notably
        // `admin_task_invoke` for the cronjob SA, plus `curate`/`read`/
        // `write`/`delete`) must still validate cleanly. Guards against
        // over-rejecting legitimate SA grants.
        for perm in ["admin_task_invoke", "curate", "read", "write", "delete"] {
            let body = format!(
                "
  subject: {{ kind: serviceAccount, name: cronjob-sa }}
  permission: {perm}
"
            );
            let env = parse_permission_grant(&p(), yaml("sa-grant", &body).as_bytes()).unwrap();
            let errors = validate_permission_grant(&env);
            assert!(
                errors.is_empty(),
                "serviceAccount + permission: {perm} must validate cleanly: {errors:?}"
            );
        }
    }

    #[test]
    fn parse_service_account_subject_rejects_unknown_field() {
        let body = "
  subject: { kind: serviceAccount, name: x, bogus: 1 }
  permission: read
";
        let err = parse_permission_grant(&p(), yaml("g", body).as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
        assert!(err.to_string().contains("bogus"));
    }

    #[test]
    fn validate_rejects_blank_service_account_name() {
        let body = "
  subject: { kind: serviceAccount, name: '   ' }
  permission: read
";
        let env = parse_permission_grant(&p(), yaml("g", body).as_bytes()).unwrap();
        let errors = validate_permission_grant(&env);
        assert!(errors
            .iter()
            .any(|e| e.to_string().contains("subject.name (serviceAccount)")));
    }

    #[test]
    fn service_account_subject_diff_identity_is_name_repo_perm_idempotent() {
        // Same SA name / repo / permission ⇒ same transient identity
        // (replay = no-op before the SA's backing user resolves).
        let body = "
  subject: { kind: serviceAccount, name: maintainer-dev }
  permission: read
";
        let a = parse_permission_grant(&p(), yaml("a", body).as_bytes()).unwrap();
        let b = parse_permission_grant(&p(), yaml("b", body).as_bytes()).unwrap();
        // metadata.name differs (a vs b) but does not participate in identity.
        assert_eq!(a.spec.diff_identity(), b.spec.diff_identity());
    }

    // ---- Parse rejects ----------------------------------------------------

    #[test]
    fn parse_rejects_unknown_field() {
        let body = "
  subject: { kind: claims, required: [developer] }
  permission: read
  bogus: 1
";
        let err = parse_permission_grant(&p(), yaml("g", body).as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
        assert!(err.to_string().contains("bogus"));
    }

    #[test]
    fn parse_rejects_missing_subject() {
        let body = "
  permission: read
";
        let err = parse_permission_grant(&p(), yaml("g", body).as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
    }

    #[test]
    fn parse_rejects_missing_permission() {
        let body = "
  subject: { kind: claims, required: [developer] }
";
        let err = parse_permission_grant(&p(), yaml("g", body).as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
    }

    #[test]
    fn parse_rejects_legacy_role_field() {
        // The legacy `role:` form is intentionally NOT supported.
        // `deny_unknown_fields` makes it a parse error rather than a
        // silently-ignored field.
        let body = "
  role: developer
  permission: read
";
        let err = parse_permission_grant(&p(), yaml("g", body).as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
    }

    #[test]
    fn parse_rejects_legacy_plural_permissions_field() {
        let body = "
  subject: { kind: claims, required: [developer] }
  permissions: [read, write]
";
        let err = parse_permission_grant(&p(), yaml("g", body).as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
    }

    #[test]
    fn parse_rejects_unknown_subject_kind() {
        let body = "
  subject: { kind: group, groupId: x }
  permission: read
";
        let err = parse_permission_grant(&p(), yaml("g", body).as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
    }

    #[test]
    fn parse_rejects_unknown_field_inside_subject() {
        let body = "
  subject: { kind: claims, required: [developer], bogus: 1 }
  permission: read
";
        let err = parse_permission_grant(&p(), yaml("g", body).as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
    }

    // ---- Validation rejects ----------------------------------------------

    #[test]
    fn validate_rejects_empty_required_claims() {
        let body = "
  subject: { kind: claims, required: [] }
  permission: read
";
        let env = parse_permission_grant(&p(), yaml("g", body).as_bytes()).unwrap();
        let errors = validate_permission_grant(&env);
        assert!(errors
            .iter()
            .any(|e| e.to_string().contains("at least one claim")));
    }

    #[test]
    fn validate_rejects_blank_claim_entry() {
        let body = "
  subject: { kind: claims, required: ['   '] }
  permission: read
";
        let env = parse_permission_grant(&p(), yaml("g", body).as_bytes()).unwrap();
        let errors = validate_permission_grant(&env);
        assert!(errors
            .iter()
            .any(|e| e.to_string().contains("subject.required[*]")));
    }

    #[test]
    fn validate_rejects_blank_user_id() {
        let body = "
  subject: { kind: user, userId: '   ' }
  permission: read
";
        let env = parse_permission_grant(&p(), yaml("g", body).as_bytes()).unwrap();
        let errors = validate_permission_grant(&env);
        assert!(errors
            .iter()
            .any(|e| e.to_string().contains("subject.userId")));
    }

    #[test]
    fn validate_rejects_unknown_permission() {
        let body = "
  subject: { kind: claims, required: [developer] }
  permission: publish
";
        let env = parse_permission_grant(&p(), yaml("g", body).as_bytes()).unwrap();
        let errors = validate_permission_grant(&env);
        assert!(errors.iter().any(|e| matches!(
            e,
            ValidationError::UnknownEnumValue { field, got, .. }
                if *field == "spec.permission" && got == "publish"
        )));
    }

    /// The validator's `expected` literal list (the diagnostic surface
    /// the operator sees on an unknown permission) must enumerate every
    /// real variant. A future variant addition must extend this list —
    /// the test pins it.
    #[test]
    fn unknown_permission_diagnostic_lists_every_variant() {
        let body = "
  subject: { kind: claims, required: [developer] }
  permission: publish
";
        let env = parse_permission_grant(&p(), yaml("g", body).as_bytes()).unwrap();
        let errors = validate_permission_grant(&env);
        let expected_list: Vec<&'static str> = errors
            .iter()
            .find_map(|e| match e {
                ValidationError::UnknownEnumValue {
                    field, expected, ..
                } if *field == "spec.permission" => Some(expected.clone()),
                _ => None,
            })
            .expect("UnknownEnumValue for spec.permission must be present");
        for want in [
            "read",
            "write",
            "delete",
            "admin",
            "admin_task_invoke",
            "curate",
        ] {
            assert!(
                expected_list.contains(&want),
                "expected list must contain `{want}`: {expected_list:?}"
            );
        }
    }

    /// Validation must accept every `Permission` variant that
    /// `Permission::FromStr` accepts. The test name reflects "every variant"
    /// rather than pinning a count, so the next variant addition tightens
    /// this in one spot rather than racing the in-file `expected` literal.
    #[test]
    fn validate_accepts_every_permission_variant() {
        for perm in [
            "read",
            "write",
            "delete",
            "admin",
            "admin_task_invoke",
            "curate",
        ] {
            let body = format!(
                "
  subject: {{ kind: claims, required: [developer] }}
  permission: {perm}
"
            );
            let env = parse_permission_grant(&p(), yaml("g", &body).as_bytes()).unwrap();
            let errors = validate_permission_grant(&env);
            assert!(
                errors.is_empty(),
                "permission `{perm}` must validate cleanly: {errors:?}"
            );
        }
    }

    /// Regression pin: a YAML `permission: delete` round-trips through
    /// `Permission::FromStr` to the `Permission::Delete` variant,
    /// the same invariant `DeleteRepoAccess::authorize` depends on.
    #[test]
    fn parse_permission_delete_round_trips_to_permission_delete_variant() {
        let body = "
  subject: { kind: claims, required: [deleter] }
  permission: delete
  repository: oci-prod
";
        let env = parse_permission_grant(&p(), yaml("oci-deleter-grant", body).as_bytes()).unwrap();
        assert_eq!(env.spec.permission, "delete");
        assert!(validate_permission_grant(&env).is_empty());
        match env.spec.diff_identity() {
            GrantIdentity::Claims { permission, .. } => {
                assert_eq!(permission, Permission::Delete);
            }
            other => panic!("expected Claims identity, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_blank_repository_string() {
        let body = "
  subject: { kind: claims, required: [developer] }
  permission: read
  repository: '   '
";
        let env = parse_permission_grant(&p(), yaml("g", body).as_bytes()).unwrap();
        let errors = validate_permission_grant(&env);
        assert!(errors
            .iter()
            .any(|e| e.to_string().contains("spec.repository")));
    }

    #[test]
    fn parse_rejects_empty_metadata_name() {
        let body = "
  subject: { kind: claims, required: [developer] }
  permission: read
";
        let yaml_doc = format!(
            "apiVersion: project-hort.de/v1beta1\nkind: PermissionGrant\nmetadata:\n  name: ''\nspec:{body}"
        );
        let err = parse_permission_grant(&p(), yaml_doc.as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::EmptyMetadataName));
    }
}
