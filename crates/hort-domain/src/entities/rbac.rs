use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::managed_by::ManagedBy;
use crate::error::DomainError;

// ---------------------------------------------------------------------------
// Permission
// ---------------------------------------------------------------------------

/// Coarse-grained permission label attached to role grants.
///
/// Every variant mirrors a value of the canonical `permission_type`
/// enum in `migrations/001_users_roles_rbac.sql` (extended by the
/// later `ALTER TYPE ... ADD VALUE` migrations). They are used
/// throughout the authorization
/// pipeline: stored on `PermissionGrant` rows, checked against the caller's
/// resolved role set by the evaluator, and surfaced in the
/// `hort_authz_decisions_total{permission=...}` metric.
///
/// Serialization is case-insensitive on parse and lowercase on display so
/// the YAML / JSON / metric-label surfaces all share one spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    Read,
    Write,
    Delete,
    Admin,
    /// Single coarse permission that gates every `POST /api/v1/admin/tasks/{kind}`
    /// call. No per-kind granularity; all task kinds share this one permission so
    /// operators can grant or revoke admin-task invocation without listing kinds.
    /// DB enum literal: `'admin_task_invoke'`.
    AdminTaskInvoke,
    /// Curator role — confers day-to-day decision authority
    /// over quarantined / rejected artifacts and finding-exclusions, without
    /// elevating to `Admin`. Gates `CurationUseCase::{waive, block, list_queue,
    /// list_decisions, list_exclusions}` and is accepted (alongside `Admin`) on
    /// `PolicyUseCase::{add_exclusion, remove_exclusion}`. DB enum literal:
    /// `'curate'`. Granted via the existing audited `ApplyConfigUseCase` apply
    /// path — no new admin endpoint, no grant back door. See
    /// `docs/architecture/how-to/curator-workflow.md`.
    Curate,
    /// Self-service prefetch authority — gates the
    /// `POST /api/v1/repositories/{repo_key}/prefetch` endpoint that allows
    /// a CLI-session caller to enqueue a self-service prefetch against a
    /// repo's configured upstream. Required **in addition to**
    /// `Permission::Read` on the repo (`Read ∧ Prefetch` is the
    /// authority shape; explicit separate grant, not implied by `Write` —
    /// see `docs/architecture/explanation/prefetch-pipeline.md`).
    /// DB enum literal: `'prefetch'`. Discovery (`GET .../discovery/...`)
    /// uses `Permission::Read` alone; this variant is the *amplification*
    /// gate exclusively. Granted via the existing audited gitops apply
    /// path — no new admin endpoint.
    Prefetch,
    /// Gates the Prometheus scrape endpoint (`GET /metrics`). Global —
    /// the exposition is process-wide, never repo-scoped. DB enum literal:
    /// `'read_metrics'`. Granted via the audited `ApplyConfigUseCase` apply
    /// path to a dedicated scraper `ServiceAccount` (non-admin). Orthogonal
    /// to `Admin` — an admin caller does not implicitly hold this grant, and
    /// a scraper does not implicitly hold admin authority. See issue #113
    /// and `docs/adr/0052-scoped-metrics-read-capability.md`, the standing
    /// decision record for this capability.
    ReadMetrics,
    /// Authority to invoke an admin task that destroys **artifact
    /// content** — `retention-purge`, and `retention-evaluate` in
    /// execute mode (which appends the `ArtifactExpired` the purge acts
    /// on). Required **in addition to**
    /// [`Permission::AdminTaskInvoke`]; the two-factor AND is the
    /// authority shape, and a dry-run `retention-evaluate` destroys
    /// nothing and needs neither. DB enum literal:
    /// `'destroy_content'`. Granted via the audited
    /// `ApplyConfigUseCase` apply path. Orthogonal to `Admin` — an
    /// admin caller does not implicitly hold this grant (see
    /// [`ADMIN_ORTHOGONAL_PERMISSIONS`]).
    ///
    /// **Named for the object destroyed, not the purpose.** Artifact
    /// content is the thing itself and the record of its removal
    /// survives by design (`ArtifactPurged` stays on the stream), which
    /// is what separates this authority from
    /// [`Permission::DestroyRecord`]. A purpose label
    /// ("housekeeping") moves, and the next destructive operation
    /// someone files under it would inherit the authority.
    DestroyContent,
    /// Authority to invoke an admin task that destroys the **record**
    /// of what happened — `eventstore-archive`, which seals and
    /// archives audit streams: authentication audit, download audit,
    /// token use. Required **in addition to**
    /// [`Permission::AdminTaskInvoke`]. DB enum literal:
    /// `'destroy_record'`. Granted via the audited
    /// `ApplyConfigUseCase` apply path. Orthogonal to `Admin` — an
    /// admin caller does not implicitly hold this grant (see
    /// [`ADMIN_ORTHOGONAL_PERMISSIONS`]).
    ///
    /// **Deliberately not the same authority as
    /// [`Permission::DestroyContent`].** Nothing reconstructs a deleted
    /// audit record, so an identity trusted to reclaim storage is not
    /// thereby trusted to cut audit history; the two are split by what
    /// is destroyed, which is why "does this authority cover it?"
    /// answers itself from the object rather than from a label.
    DestroyRecord,
}

/// The permissions the synthetic `admin` claim does **not** imply —
/// the admin-orthogonal set, declared once.
///
/// A member of this set is held only through an explicit
/// [`PermissionGrant`]: an admin principal falls through the
/// evaluator's admin short-circuit to the ordinary grant scan for it,
/// and surfaces it on every read surface exactly as a non-admin would.
/// Everything *not* in this set stays implied by `Admin`.
///
/// **Four readers, and the fourth is why this is a declaration rather
/// than four `!=` comparisons.** `RbacEvaluator::user_grants_authorize`
/// (the request-time gate), `RbacEvaluator::effective_grants` (the
/// `is_global_admin` marker carve-out, which the whoami self-view, the
/// per-user endpoint and the what-if resolver all read),
/// `RbacEvaluator::derive_cli_session_cap` (the admin branch, which
/// must not let an unheld orthogonal permission ride along into a
/// derived CLI-session cap) and the whoami global-admin projection
/// (which renders one cell per member). A reader that misses a member
/// produces a *surface disagreement* — the evaluator denying an admin
/// while another surface still reports the authority as held — so the
/// set is declared here, next to the enum, and read from here.
///
/// Membership is a decision about the authority, not about its
/// implementation: a permission belongs here when an admin holding it
/// implicitly would defeat the point of having it (a scrape identity
/// that is not an operator; a destructive authority nobody decided to
/// confer).
pub const ADMIN_ORTHOGONAL_PERMISSIONS: &[Permission] = &[
    Permission::ReadMetrics,
    Permission::DestroyContent,
    Permission::DestroyRecord,
];

/// The permissions a **machine identity may never hold**, each paired
/// with the reason — declared once, so the points that refuse them
/// cannot come to refuse different sets.
///
/// A service account's authority is otherwise exactly its explicit
/// `serviceAccount`-subject grants (ADR 0037), so this set is the one
/// place that says "not this one, whatever the grant says". It is the
/// *identity* answer and deliberately not a *declaration-form* answer:
/// a grant naming an SA's backing user through a direct
/// [`GrantSubject::User`] subject is syntactically ordinary, so the
/// refusal has to be reachable from a caller as well as from an
/// envelope.
///
/// **Five readers, and that is why the reason travels with the
/// member.** Three refuse a *declaration* — `hort-config`'s
/// `validate_permission_grant` at apply-parse, the apply linter's
/// SA-provenance exemption (`lint::permission_grants`), and
/// `hort-server admin issue-svc-token` on the mint path — and two
/// refuse an *identity at runtime*: the admin-task authorization gate
/// (`TaskUseCase::authorize_kind`, which sees the caller's
/// `TokenKind::ServiceAccount` credential) and the execution-time
/// re-authorization of a queued row
/// (`DestructiveTaskReauthorizer`, which sees the persisted
/// `users.is_service_account` identity instead, because no credential
/// is persisted on a `jobs` row). Each composes its own surface's
/// wording around the shared reason rather than restating why.
///
/// Membership is a decision about standing machine authority: a
/// permission belongs here when an unattended identity holding it is
/// not what was decided, however carefully the grant was authored.
/// `Permission::DestroyContent` deliberately does **not** belong —
/// reclaiming artifact storage is exactly the scheduled housekeeping a
/// machine identity exists for, and `ArtifactPurged` stays on the
/// stream behind it.
pub const SERVICE_ACCOUNT_FORBIDDEN_PERMISSIONS: &[(Permission, &str)] = &[
    (
        Permission::Admin,
        "service accounts are strictly non-admin (ADR 0038) — express scoped authority as \
         `serviceAccount`-subject grants instead, run admin operations as an IdP-assumed \
         human admin, and reach the first admin through the DSN-gated \
         `hort-server admin bootstrap-session`",
    ),
    (
        Permission::DestroyRecord,
        "`eventstore-archive` destroys the audit record itself — authentication audit, \
         download audit, token use — and nothing reconstructs a sealed stream, so no \
         unattended identity is given standing authority over it. Grant `destroy_content` \
         for the retention tasks, which a machine identity may hold, and run \
         `eventstore-archive` by hand as a human identity that holds `destroy_record`",
    ),
];

impl Permission {
    /// `true` when `self` is in [`ADMIN_ORTHOGONAL_PERMISSIONS`] — the
    /// one predicate every reader of the admin-orthogonal set calls.
    #[must_use]
    pub fn is_admin_orthogonal(self) -> bool {
        ADMIN_ORTHOGONAL_PERMISSIONS.contains(&self)
    }

    /// `Some(reason)` when a service account may never hold `self` —
    /// the one lookup every reader of
    /// [`SERVICE_ACCOUNT_FORBIDDEN_PERMISSIONS`] calls.
    ///
    /// The reason is returned rather than a bare `bool` because every
    /// refusal point has an operator on the other end of it who is
    /// trying to automate something: "may not hold this" without "and
    /// here is what to automate instead" sends them looking for a
    /// wider credential, which is the outcome the refusal exists to
    /// prevent.
    #[must_use]
    pub fn service_account_refusal(self) -> Option<&'static str> {
        SERVICE_ACCOUNT_FORBIDDEN_PERMISSIONS
            .iter()
            .find(|(p, _)| *p == self)
            .map(|(_, reason)| *reason)
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => f.write_str("read"),
            Self::Write => f.write_str("write"),
            Self::Delete => f.write_str("delete"),
            Self::Admin => f.write_str("admin"),
            Self::AdminTaskInvoke => f.write_str("admin_task_invoke"),
            Self::Curate => f.write_str("curate"),
            Self::Prefetch => f.write_str("prefetch"),
            Self::ReadMetrics => f.write_str("read_metrics"),
            Self::DestroyContent => f.write_str("destroy_content"),
            Self::DestroyRecord => f.write_str("destroy_record"),
        }
    }
}

impl FromStr for Permission {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // NB: `FromStr` is a NON-exhaustive match (the compiler will NOT force
        // a new arm when a new `Permission` variant is added). When adding a
        // variant, the corresponding `"<literal>"` arm MUST be added here
        // explicitly, or gitops `PermissionGrant` parsing silently breaks.
        match s.to_lowercase().as_str() {
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            "delete" => Ok(Self::Delete),
            "admin" => Ok(Self::Admin),
            "admin_task_invoke" => Ok(Self::AdminTaskInvoke),
            "curate" => Ok(Self::Curate),
            "prefetch" => Ok(Self::Prefetch),
            "read_metrics" => Ok(Self::ReadMetrics),
            "destroy_content" => Ok(Self::DestroyContent),
            "destroy_record" => Ok(Self::DestroyRecord),
            _ => Err(DomainError::Validation(format!("unknown permission: {s}"))),
        }
    }
}

// ---------------------------------------------------------------------------
// GrantSubject
// ---------------------------------------------------------------------------

/// The subject a [`PermissionGrant`] binds to (ADR 0012).
///
/// Authorization uses an **additive-claims** model: a grant either
/// requires a *set of claims* the caller must all possess, or binds
/// directly to a single user id (service accounts and one-off privilege
/// escalations). The subject taxonomy is **closed at two variants**:
/// adding a third kind is a design change to the authorization model,
/// not a local edit.
///
/// - [`GrantSubject::Claims`] — set-membership match. The grant is
///   satisfied when every claim in the set is a subset of the caller's
///   resolved `principal.claims`. The empty set is a schema error
///   (`claims_nonempty` CHECK in `001_users_roles_rbac.sql`) — it would
///   mean "no claim requirements", an unintended wildcard.
/// - [`GrantSubject::User`] — identity match against
///   `principal.user_id`. Bypasses the claim mechanism entirely; this is
///   how service accounts express their authority (ADR 0018).
///
/// Intentionally NOT `Serialize`/`Deserialize`: like the carrying
/// [`PermissionGrant`], the subject is server-constructed from validated
/// gitops config or the adapter, never deserialised from request input.
#[derive(Debug, Clone, PartialEq)]
pub enum GrantSubject {
    /// Subset-match against `principal.claims`. Non-empty by construction
    /// (DB CHECK + apply-time linter enforce `len() >= 1`).
    Claims(Vec<String>),
    /// Identity-match against `principal.user_id`.
    User(Uuid),
}

// ---------------------------------------------------------------------------
// PermissionGrant
// ---------------------------------------------------------------------------

/// A single `(subject, permission, repository?)` grant row (ADR 0012).
///
/// `repository_id = None` means the grant is global — the subject carries
/// the permission for every repository. `repository_id = Some(_)` scopes
/// the grant to a single repository. Evaluation logic lives in
/// `hort-app::rbac::RbacEvaluator::authorize`: a `Claims(_)` subject is
/// satisfied when its claim set is a subset of `principal.claims`; a
/// `User(_)` subject is satisfied when it equals `principal.user_id`.
///
/// Grants carry a `managed_by` discriminator. Gitops-declared grants are
/// written via the managed-write port and identified across applies by a
/// subject-dependent diff key
/// (`(sorted required_claims, repository_id, permission)` for `Claims`;
/// `(user_id, repository_id, permission)` for `User`).
///
/// Intentionally NOT `Serialize`/`Deserialize`: the grant is
/// server-constructed from validated gitops config or the postgres
/// adapter, never deserialised from request input. Digesting for the
/// gitops diff happens at the adapter/apply layer, so the domain type
/// carries no serde derives, in line with the other server-constructed
/// authz types.
#[derive(Debug, Clone, PartialEq)]
pub struct PermissionGrant {
    pub id: Uuid,
    pub subject: GrantSubject,
    pub repository_id: Option<Uuid>,
    pub permission: Permission,
    pub managed_by: ManagedBy,
    pub managed_by_digest: Option<[u8; 32]>,
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// ClaimMapping
// ---------------------------------------------------------------------------

/// Declarative mapping from an IdP group-claim string to a registry
/// **claim name** (ADR 0012).
///
/// The IdP supplies a flat `groups` claim; operators declare which group
/// names map to which claim names; the server resolves a caller's claim
/// set by flattening the `groups` claim against the `claim_mappings`
/// table (`hort-app::rbac::resolve_claims`). `ClaimMapping` is the **only**
/// source of resolved claim names — code paths must not invent claim
/// names at runtime (ADR 0012). The single synthetic exception is
/// the `admin` claim derived from `user.is_admin=true`.
///
/// The standard managed-write semantics apply: the gitops
/// apply pipeline writes `managed_by = 'gitops'` rows with a digest;
/// `managed_by_digest` is the SHA-256 of the canonicalised spec, non-
/// `None` only for `ManagedBy::GitOps` rows (DB CHECK mirrors this).
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimMapping {
    pub id: Uuid,
    pub idp_group: String,
    pub claim: String,
    pub managed_by: ManagedBy,
    pub managed_by_digest: Option<[u8; 32]>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Permission ---------------------------------------------------------

    #[test]
    fn permission_display_lowercase() {
        assert_eq!(Permission::Read.to_string(), "read");
        assert_eq!(Permission::Write.to_string(), "write");
        assert_eq!(Permission::Delete.to_string(), "delete");
        assert_eq!(Permission::Admin.to_string(), "admin");
        assert_eq!(Permission::AdminTaskInvoke.to_string(), "admin_task_invoke");
        assert_eq!(Permission::Curate.to_string(), "curate");
        assert_eq!(Permission::Prefetch.to_string(), "prefetch");
        assert_eq!(Permission::ReadMetrics.to_string(), "read_metrics");
        assert_eq!(Permission::DestroyContent.to_string(), "destroy_content");
        assert_eq!(Permission::DestroyRecord.to_string(), "destroy_record");
    }

    #[test]
    fn permission_from_str_roundtrip() {
        for name in &[
            "read",
            "write",
            "delete",
            "admin",
            "admin_task_invoke",
            "curate",
            "prefetch",
            "read_metrics",
            "destroy_content",
            "destroy_record",
        ] {
            let parsed: Permission = name.parse().unwrap();
            assert_eq!(parsed.to_string(), *name);
        }
    }

    #[test]
    fn permission_from_str_case_insensitive() {
        let cases = [
            ("READ", Permission::Read),
            ("Read", Permission::Read),
            ("read", Permission::Read),
            ("WRITE", Permission::Write),
            ("Delete", Permission::Delete),
            ("ADMIN", Permission::Admin),
            ("ADMIN_TASK_INVOKE", Permission::AdminTaskInvoke),
            ("Admin_Task_Invoke", Permission::AdminTaskInvoke),
            ("admin_task_invoke", Permission::AdminTaskInvoke),
            ("CURATE", Permission::Curate),
            ("Curate", Permission::Curate),
            ("curate", Permission::Curate),
            ("PREFETCH", Permission::Prefetch),
            ("Prefetch", Permission::Prefetch),
            ("prefetch", Permission::Prefetch),
            ("READ_METRICS", Permission::ReadMetrics),
            ("Read_Metrics", Permission::ReadMetrics),
            ("read_metrics", Permission::ReadMetrics),
            ("DESTROY_CONTENT", Permission::DestroyContent),
            ("Destroy_Content", Permission::DestroyContent),
            ("destroy_content", Permission::DestroyContent),
            ("DESTROY_RECORD", Permission::DestroyRecord),
            ("Destroy_Record", Permission::DestroyRecord),
            ("destroy_record", Permission::DestroyRecord),
        ];
        for (input, expected) in cases {
            let parsed: Permission = input.parse().unwrap();
            assert_eq!(parsed, expected, "failed on input {input}");
        }
    }

    #[test]
    fn permission_from_str_unknown_is_validation_error() {
        let result: Result<Permission, DomainError> = "publish".parse();
        match result {
            Err(DomainError::Validation(msg)) => {
                assert!(
                    msg.contains("publish"),
                    "validation message should include the bad input, got: {msg}"
                );
            }
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    #[test]
    fn permission_copy() {
        let a = Permission::Write;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn permission_admin_task_invoke_copy_and_eq() {
        let a = Permission::AdminTaskInvoke;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn permission_curate_copy_and_eq() {
        let a = Permission::Curate;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn permission_prefetch_copy_and_eq() {
        let a = Permission::Prefetch;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn permission_read_metrics_copy_and_eq() {
        let a = Permission::ReadMetrics;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn permission_read_metrics_serde_round_trip() {
        let json = serde_json::to_string(&Permission::ReadMetrics).expect("serialize");
        let back: Permission = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, Permission::ReadMetrics);
    }

    #[test]
    fn permission_destroy_content_copy_and_eq() {
        let a = Permission::DestroyContent;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn permission_destroy_record_copy_and_eq() {
        let a = Permission::DestroyRecord;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn permission_destructive_variants_serde_round_trip() {
        for perm in [Permission::DestroyContent, Permission::DestroyRecord] {
            let json = serde_json::to_string(&perm).expect("serialize");
            let back: Permission = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, perm);
        }
    }

    #[test]
    fn permission_destroy_content_and_destroy_record_are_distinct() {
        // The whole point of the split: an identity holding one does not
        // hold the other, so the two must never compare equal (a copy-paste
        // of the same variant into both arms of a mapping would).
        assert_ne!(Permission::DestroyContent, Permission::DestroyRecord);
    }

    #[test]
    fn permission_exhaustive_match() {
        // Force a compile error if a new variant is added without updating
        // this test. Update this test and the match arms above when adding
        // variants.
        for perm in [
            Permission::Read,
            Permission::Write,
            Permission::Delete,
            Permission::Admin,
            Permission::AdminTaskInvoke,
            Permission::Curate,
            Permission::Prefetch,
            Permission::ReadMetrics,
            Permission::DestroyContent,
            Permission::DestroyRecord,
        ] {
            let _display = perm.to_string();
            let _roundtrip: Permission = _display.parse().unwrap();
            assert_eq!(_roundtrip, perm);
        }
    }

    // -- ADMIN_ORTHOGONAL_PERMISSIONS ---------------------------------------

    /// The declared set, classified variant by variant with a
    /// **no-wildcard** match, so adding a `Permission` without deciding
    /// whether `Admin` implies it is a compile error here rather than a
    /// silent "yes, it does" at four reading sites.
    #[test]
    fn every_permission_is_consciously_classified_against_the_admin_short_circuit() {
        for perm in [
            Permission::Read,
            Permission::Write,
            Permission::Delete,
            Permission::Admin,
            Permission::AdminTaskInvoke,
            Permission::Curate,
            Permission::Prefetch,
            Permission::ReadMetrics,
            Permission::DestroyContent,
            Permission::DestroyRecord,
        ] {
            let expected_orthogonal = match perm {
                // Held only through an explicit grant: a scrape identity
                // is not an operator, and a destructive authority is one
                // somebody decided to confer.
                Permission::ReadMetrics
                | Permission::DestroyContent
                | Permission::DestroyRecord => true,
                // Implied by `Admin`, unchanged.
                Permission::Read
                | Permission::Write
                | Permission::Delete
                | Permission::Admin
                | Permission::AdminTaskInvoke
                | Permission::Curate
                | Permission::Prefetch => false,
            };
            assert_eq!(
                perm.is_admin_orthogonal(),
                expected_orthogonal,
                "{perm} classification drifted from the exhaustive guard"
            );
        }
    }

    /// `Admin` itself can never be orthogonal to itself — the
    /// short-circuit would deny the permission it is the short-circuit
    /// for, which is unreachable-authority, not a tightening.
    #[test]
    fn admin_is_not_admin_orthogonal() {
        assert!(!Permission::Admin.is_admin_orthogonal());
        assert!(!ADMIN_ORTHOGONAL_PERMISSIONS.contains(&Permission::Admin));
    }

    /// The predicate is the set — nothing re-states membership.
    #[test]
    fn is_admin_orthogonal_reads_the_declared_set() {
        for perm in ADMIN_ORTHOGONAL_PERMISSIONS {
            assert!(
                perm.is_admin_orthogonal(),
                "{perm} is declared orthogonal but the predicate disagrees"
            );
        }
        assert_eq!(
            ADMIN_ORTHOGONAL_PERMISSIONS.len(),
            3,
            "a change to the declared set is a change to four readers at once —              see the const's doc comment"
        );
    }

    // -- SERVICE_ACCOUNT_FORBIDDEN_PERMISSIONS ------------------------------

    /// The declared set, classified variant by variant with a
    /// **no-wildcard** match, so adding a `Permission` without deciding
    /// whether a machine identity may hold it is a compile error here
    /// rather than a silent "yes, it may" at five refusal points.
    #[test]
    fn every_permission_is_consciously_classified_against_machine_identity() {
        for perm in [
            Permission::Read,
            Permission::Write,
            Permission::Delete,
            Permission::Admin,
            Permission::AdminTaskInvoke,
            Permission::Curate,
            Permission::Prefetch,
            Permission::ReadMetrics,
            Permission::DestroyContent,
            Permission::DestroyRecord,
        ] {
            let expected_forbidden = match perm {
                // No unattended identity holds instance-wide authority
                // (ADR 0038), and none gets standing authority to cut
                // audit history nothing reconstructs.
                Permission::Admin | Permission::DestroyRecord => true,
                // Every machine-holdable permission, including
                // `DestroyContent`: scheduled storage reclamation is
                // what a machine identity is for, and `ArtifactPurged`
                // stays on the stream behind it.
                Permission::Read
                | Permission::Write
                | Permission::Delete
                | Permission::AdminTaskInvoke
                | Permission::Curate
                | Permission::Prefetch
                | Permission::ReadMetrics
                | Permission::DestroyContent => false,
            };
            assert_eq!(
                perm.service_account_refusal().is_some(),
                expected_forbidden,
                "{perm} classification drifted from the exhaustive guard"
            );
        }
    }

    /// The lookup is the set — nothing re-states membership — and every
    /// member carries a non-empty reason, because every refusal point
    /// renders it to an operator who is trying to automate something.
    #[test]
    fn service_account_refusal_reads_the_declared_set() {
        for (perm, reason) in SERVICE_ACCOUNT_FORBIDDEN_PERMISSIONS {
            assert_eq!(
                perm.service_account_refusal(),
                Some(*reason),
                "{perm} is declared forbidden but the lookup disagrees"
            );
            assert!(
                !reason.trim().is_empty(),
                "{perm}'s refusal carries no reason"
            );
        }
        assert_eq!(
            SERVICE_ACCOUNT_FORBIDDEN_PERMISSIONS.len(),
            2,
            "a change to the declared set is a change to five refusal points at once \
             — see the const's doc comment"
        );
    }

    /// The two halves of the destructive split are on opposite sides of
    /// this set, and that asymmetry is the decision — not an accident of
    /// how the list was typed. A set holding both would make the shipped
    /// `cronjob-tasks` retention grant unprovisionable; a set holding
    /// neither would hand a scheduled job standing authority to seal
    /// audit streams.
    #[test]
    fn the_destructive_split_straddles_the_machine_identity_refusal() {
        assert!(
            Permission::DestroyContent
                .service_account_refusal()
                .is_none(),
            "a machine identity must be able to hold destroy_content"
        );
        let record = Permission::DestroyRecord
            .service_account_refusal()
            .expect("destroy_record must be refused to a machine identity");
        // The reason names *why* and what to automate instead — "no"
        // alone sends an operator looking for a wider credential, which
        // is the outcome the refusal exists to prevent.
        assert!(
            record.contains("nothing reconstructs a sealed stream"),
            "the reason must name why: {record}"
        );
        assert!(
            record.contains("destroy_content"),
            "the reason must name what to automate instead: {record}"
        );
    }

    /// Admin-orthogonality and machine-identity refusal are different
    /// questions and the two sets are deliberately not nested:
    /// `read_metrics` is orthogonal to `admin` yet perfectly holdable by
    /// a scraper SA, and `admin` is refused to a machine identity while
    /// being the one permission that can never be orthogonal to itself.
    #[test]
    fn the_two_declarations_are_independent() {
        assert!(Permission::ReadMetrics.is_admin_orthogonal());
        assert!(Permission::ReadMetrics.service_account_refusal().is_none());
        assert!(!Permission::Admin.is_admin_orthogonal());
        assert!(Permission::Admin.service_account_refusal().is_some());
    }

    // -- GrantSubject -------------------------------------------------------

    #[test]
    fn grant_subject_claims_clone_eq() {
        let a = GrantSubject::Claims(vec!["developer".into(), "team-alpha".into()]);
        let b = a.clone();
        assert_eq!(a, b);
        match &a {
            GrantSubject::Claims(c) => assert_eq!(c, &["developer", "team-alpha"]),
            GrantSubject::User(_) => panic!("expected Claims"),
        }
    }

    #[test]
    fn grant_subject_user_clone_eq() {
        let uid = Uuid::from_u128(0x99);
        let a = GrantSubject::User(uid);
        let b = a.clone();
        assert_eq!(a, b);
        match a {
            GrantSubject::User(u) => assert_eq!(u, uid),
            GrantSubject::Claims(_) => panic!("expected User"),
        }
    }

    #[test]
    fn grant_subject_claims_and_user_are_distinct() {
        let claims = GrantSubject::Claims(vec!["admin".into()]);
        let user = GrantSubject::User(Uuid::nil());
        assert_ne!(claims, user);
    }

    // -- PermissionGrant ----------------------------------------------------

    fn sample_grant(repository_id: Option<Uuid>, permission: Permission) -> PermissionGrant {
        PermissionGrant {
            id: Uuid::nil(),
            subject: GrantSubject::Claims(vec!["developer".into()]),
            repository_id,
            permission,
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn permission_grant_global_has_no_repository() {
        let grant = sample_grant(None, Permission::Read);
        assert!(grant.repository_id.is_none());
        assert_eq!(grant.permission, Permission::Read);
    }

    #[test]
    fn permission_grant_repo_scoped_carries_repository() {
        let repo_id = Uuid::from_u128(0x1234);
        let grant = sample_grant(Some(repo_id), Permission::Write);
        assert_eq!(grant.repository_id, Some(repo_id));
        assert_eq!(grant.permission, Permission::Write);
    }

    #[test]
    fn permission_grant_clone_eq() {
        let a = sample_grant(Some(Uuid::from_u128(42)), Permission::Delete);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn permission_grant_claims_subject_round_trips() {
        let grant = sample_grant(None, Permission::Read);
        match grant.subject {
            GrantSubject::Claims(c) => assert_eq!(c, vec!["developer".to_string()]),
            GrantSubject::User(_) => panic!("expected Claims subject"),
        }
    }

    #[test]
    fn permission_grant_user_subject_round_trips() {
        let uid = Uuid::from_u128(0xBEEF);
        let grant = PermissionGrant {
            subject: GrantSubject::User(uid),
            ..sample_grant(None, Permission::Admin)
        };
        match grant.subject {
            GrantSubject::User(u) => assert_eq!(u, uid),
            GrantSubject::Claims(_) => panic!("expected User subject"),
        }
    }

    #[test]
    fn permission_grant_managed_by_gitops_carries_digest() {
        let grant = PermissionGrant {
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0xcd; 32]),
            ..sample_grant(None, Permission::Read)
        };
        assert_eq!(grant.managed_by, ManagedBy::GitOps);
        assert_eq!(grant.managed_by_digest, Some([0xcd; 32]));
    }

    // -- ClaimMapping -------------------------------------------------------

    #[test]
    fn claim_mapping_construction() {
        let mapping = ClaimMapping {
            id: Uuid::from_u128(0x1),
            idp_group: "hort-admins".into(),
            claim: "admin".into(),
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
        };
        assert_eq!(mapping.idp_group, "hort-admins");
        assert_eq!(mapping.claim, "admin");
        assert_eq!(mapping.managed_by, ManagedBy::Local);
        assert!(mapping.managed_by_digest.is_none());
    }

    #[test]
    fn claim_mapping_clone_eq() {
        let a = ClaimMapping {
            id: Uuid::from_u128(0x2),
            idp_group: "team-alpha".into(),
            claim: "developer".into(),
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn claim_mapping_managed_by_gitops_carries_digest() {
        let mapping = ClaimMapping {
            id: Uuid::from_u128(0x3),
            idp_group: "g".into(),
            claim: "admin".into(),
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0xab; 32]),
        };
        assert_eq!(mapping.managed_by, ManagedBy::GitOps);
        assert_eq!(mapping.managed_by_digest, Some([0xab; 32]));
    }
}
