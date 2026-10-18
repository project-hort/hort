//! Outbound port for atomic authority-row-plus-audit-event commits
//! (ADR 0012 / ADR 0018).
//!
//! Each call persists both the authority rows and the audit events that
//! attest the mutation in a single transaction. The rows stay CRUD —
//! they are not event-sourced, and the events are not a second source
//! of truth for them. What the single transaction buys is the one
//! property a CRUD-plus-audit pair cannot get any other way: an append
//! failure (or a process termination) can no longer leave a grant, a
//! claim mapping, an issuer, an upstream mapping or a service account
//! **active with nothing in the authorization stream attesting it**.
//! The retry cannot repair that
//! state either — the next apply derives its events from the prior
//! rows, which already contain the change, so it emits nothing.
//!
//! # Read ports stay where they are
//!
//! The read surfaces live on
//! [`super::permission_grant_repository::PermissionGrantRepository`],
//! [`super::claim_mapping_repository::ClaimMappingRepository`],
//! [`super::oidc_issuer_repository::OidcIssuerRepository`],
//! [`super::repository_upstream_mapping_repository::RepositoryUpstreamMappingRepository`]
//! and [`super::service_account_repository::ServiceAccountRepository`].
//! The read/write split is the same one
//! [`super::ref_lifecycle::RefLifecyclePort`] makes against
//! `RefRegistryPort`: consumers that only read stay independent of the
//! transactional-write path.
//!
//! Four of those five are now **read-only traits**: the grant, claim
//! mapping, issuer and service-account ports carry no write method at
//! all, so an apply branch that tries to write one of those rows
//! outside this transaction does not compile. That is the structural
//! posture `AppContext`'s `pub(crate)` fields take against a format
//! crate — a closed finding is not left reachable by convention.
//! `RepositoryUpstreamMappingRepository` keeps its non-gitops
//! `upsert` / `delete` pair (the `managed_by = 'local'` admin CRUD
//! surface, which carries no audit event and no gitops provenance);
//! its gitops-partition write is here.
//!
//! # Two load-bearing rules — do not deviate
//!
//! 1. **The adapter MUST NEVER mutate or re-serialise the caller's
//!    [`AppendEvents`].** The use case owns the prior-vs-desired diff
//!    and builds the batches; the adapter appends them verbatim under a
//!    committed transaction or rolls back. This is the same
//!    pass-through contract
//!    [`super::artifact_group_lifecycle::ArtifactGroupLifecyclePort`]
//!    states: pattern-matching on event variants to patch a payload
//!    couples the adapter to every variant's shape.
//! 2. **A multi-stream batch list commits as ONE unit.** A grant
//!    reconcile routes its events per row to
//!    `StreamCategory::Repository(r)` (repo-scoped grant) or
//!    `StreamCategory::Authorization` (global grant), so one reconcile
//!    legitimately spans several streams; an upstream-mapping apply
//!    is repo-scoped on every row, so it spans one stream per
//!    repository it touches. `batches` is therefore a
//!    `Vec<AppendEvents>` rather than a single batch, and an
//!    implementation MUST append every element in the same transaction
//!    as the rows: a list that fails part-way must leave **no** stream
//!    audited, never some audited and some not.
//!
//! Because the transaction lives inside the adapter and the
//! application layer sees only this port, the hexagon stays intact and
//! [`super::event_store::EventStore::append`] does not grow a
//! transaction parameter (ADR 0007 — the event-store port stays
//! backend-agnostic).

use uuid::Uuid;

use crate::entities::oidc_issuer::OidcIssuer;
use crate::entities::rbac::{ClaimMapping, PermissionGrant};
use crate::entities::service_account::ServiceAccount;
use crate::error::DomainResult;
use crate::ports::event_store::AppendEvents;
use crate::ports::repository_upstream_mapping_repository::RepositoryUpstreamMapping;

use super::BoxFuture;

// ---------------------------------------------------------------------------
// OidcIssuerChange
// ---------------------------------------------------------------------------

/// The write intent handed to
/// [`AuthorityLifecyclePort::commit_oidc_issuers`].
///
/// Unlike grants and claim mappings — whose adapters reconcile a whole
/// gitops partition from one authoritative set — `oidc_issuers` is
/// written per row, so the intent carries the two row operations the
/// apply plan produced. Bundling them in a named struct keeps the
/// method at three parameters and mirrors
/// [`super::artifact_group_lifecycle::GroupMemberCommit`], the
/// established shape for "several decisions the use case already made,
/// handed to the adapter as one write intent".
///
/// Both vectors may be empty; an implementation given an empty change
/// and an empty batch list commits nothing.
/// `PartialEq` but not `Eq` — [`OidcIssuer`] itself derives only
/// `PartialEq`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct OidcIssuerChange {
    /// Issuers to write, keyed on `name` by the adapter's upsert. The
    /// use case has already resolved each row's surrogate id (reusing
    /// an existing row's id where the name is already present) so the
    /// audit `issuer_id` matches the row.
    pub upserts: Vec<OidcIssuer>,
    /// Issuer `name`s to delete. Deleting a name that no longer exists
    /// is a no-op, not an error — the apply diff is the only caller and
    /// a re-apply after a manual `DELETE` must not fail.
    pub deletes: Vec<String>,
}

// ---------------------------------------------------------------------------
// UpstreamMappingCommit
// ---------------------------------------------------------------------------

/// The write intent handed to
/// [`AuthorityLifecyclePort::commit_upstream_mappings`].
///
/// Same per-row shape as [`OidcIssuerChange`] — the apply plan upserts
/// the mappings it declares and deletes the gitops rows that fell out
/// of the desired state, rather than handing the adapter one
/// authoritative set to reconcile against. The name follows
/// [`super::artifact_group_lifecycle::GroupMemberCommit`] rather than
/// `OidcIssuerChange`'s `…Change` suffix because
/// [`crate::events::UpstreamMappingChange`] already names the
/// per-row change *kind* carried in the audit event, and the apply
/// branch has both in scope.
///
/// Both vectors may be empty; an implementation given an empty commit
/// and an empty batch list commits nothing.
/// No `PartialEq` — [`RepositoryUpstreamMapping`] derives only `Debug`
/// and `Clone`.
#[derive(Debug, Clone, Default)]
pub struct UpstreamMappingCommit {
    /// Mappings to write, keyed on `(repository_id, path_prefix)` by
    /// the adapter's upsert. The use case has already resolved each
    /// row's surrogate id against that identity (reusing the existing
    /// row's id, which the `ON CONFLICT` update preserves) so the audit
    /// `mapping_id` matches the row. Every element must be
    /// `managed_by = GitOps` and carry `managed_by_digest`.
    pub upserts: Vec<RepositoryUpstreamMapping>,
    /// Primary keys of gitops-managed rows to delete. A non-gitops row
    /// at that id is left alone (the adapter's `managed_by = 'gitops'`
    /// predicate), and an id that no longer exists is a no-op.
    pub deletes: Vec<Uuid>,
}

// ---------------------------------------------------------------------------
// ServiceAccountCommit
// ---------------------------------------------------------------------------

/// The write intent handed to
/// [`AuthorityLifecyclePort::commit_service_accounts`].
///
/// Shaped exactly like [`OidcIssuerChange`]: per-row upserts plus
/// deletes by the `name` that is the aggregate's natural identity.
///
/// **The backing `users` row is deliberately not part of this intent.**
/// `apply_service_accounts` ensures `username = "sa:" || name` exists
/// before it builds the aggregate, through `UserRepository`, and that
/// write stays outside the transaction. It has to: the FK from
/// `service_accounts.backing_user_id` means the user row must be
/// durable before the SA row references it. And it is safe, because an
/// orphan backing user confers nothing — `apply_permission_grants`
/// materialises `GrantSubject::User(backing_user_id)` rows only for
/// service accounts in the desired set, resolved from the persisted SA
/// aggregate, so a users row whose SA rolled back has no grant, no
/// token and no authority. The next apply finds it by username, reuses
/// its id, and re-emits the same `ServiceAccountCreated`.
///
/// Both vectors may be empty; an implementation given an empty commit
/// and an empty batch list commits nothing.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ServiceAccountCommit {
    /// Aggregates to write, keyed on `name` by the adapter's upsert.
    /// Each carries the SA row plus its `federated_identities` and
    /// optional `fallback_rotation` sub-aggregate; the adapter replaces
    /// the sub-rows wholesale (ADR 0018).
    pub upserts: Vec<ServiceAccount>,
    /// Service-account `name`s to delete. The sub-aggregate rows go
    /// with them via CASCADE; the backing `users` row stays (shared
    /// infrastructure the apply path never deletes).
    pub deletes: Vec<String>,
}

// ---------------------------------------------------------------------------
// AuthorityLifecyclePort
// ---------------------------------------------------------------------------

/// Outbound port for atomic authority write operations.
///
/// One method per authority write, each taking the desired rows **and**
/// the audit batches to append, and committing both or neither. The
/// shape mirrors
/// [`super::artifact_lifecycle::ArtifactLifecyclePort::commit_transition`]:
/// borrowed desired state (the use case keeps ownership of the set it
/// diffed) plus owned batches (the adapter consumes them).
pub trait AuthorityLifecyclePort: Send + Sync {
    /// Atomically reconcile the gitops-managed `permission_grants`
    /// partition to `desired` and append `batches`.
    ///
    /// The reconcile semantics are unchanged from the port method this
    /// replaced at the call site: in one transaction every
    /// `managed_by = 'gitops'` row whose subject-dependent identity
    /// (`(sorted required_claims, repository_id, permission)` for
    /// `Claims`; `(user_id, repository_id, permission)` for `User`) is
    /// absent from `desired` is deleted, and every row in `desired` is
    /// written. An empty `desired` revokes the whole gitops partition.
    /// Every element must carry `managed_by_digest`.
    ///
    /// `batches` is the per-stream audit batch list the use case built
    /// from its prior-vs-desired diff (one `PermissionGrantApplied` per
    /// added-or-changed row, one `PermissionGrantRevoked` per removed
    /// row). It may be empty — an unchanged replay reconciles without
    /// emitting anything, and the reconcile still runs.
    fn commit_permission_grants<'a>(
        &'a self,
        desired: &'a [PermissionGrant],
        batches: Vec<AppendEvents>,
    ) -> BoxFuture<'a, DomainResult<()>>;

    /// Atomically reconcile the gitops-managed `claim_mappings`
    /// partition to `desired` and append `batches`.
    ///
    /// Same whole-partition contract as
    /// [`Self::commit_permission_grants`], keyed on the
    /// `(idp_group, claim)` UNIQUE identity. An empty `desired` revokes
    /// every gitops-managed mapping; every element must carry
    /// `managed_by_digest`.
    fn commit_claim_mappings<'a>(
        &'a self,
        desired: &'a [ClaimMapping],
        batches: Vec<AppendEvents>,
    ) -> BoxFuture<'a, DomainResult<()>>;

    /// Atomically apply `change` to `oidc_issuers` and append
    /// `batches`.
    ///
    /// Issuer rows are **trust anchors** (ADR 0018): a serving
    /// validator reads the repository at validation time, so a
    /// surviving replica acts on the new trust state the moment the row
    /// commits. That is precisely why the attesting
    /// `OidcIssuerCreated` / `OidcIssuerUpdated` / `OidcIssuerDeleted`
    /// event must not be able to land separately.
    ///
    /// Upserts are applied before deletes, matching the apply plan's
    /// own order.
    fn commit_oidc_issuers<'a>(
        &'a self,
        change: &'a OidcIssuerChange,
        batches: Vec<AppendEvents>,
    ) -> BoxFuture<'a, DomainResult<()>>;

    /// Atomically apply `change` to the gitops-managed
    /// `repository_upstream_mappings` rows and append `batches`.
    ///
    /// An upstream mapping is an authority row because it names the
    /// **upstream a proxy repository will trust and fetch from**, with
    /// its credential reference and its TLS material: a mapping that
    /// commits unattested is a changed trust anchor the authorization
    /// stream is silent about. Every mutation is repo-scoped (the row
    /// carries a non-NULL `repository_id`), so one apply routes its
    /// `RepositoryUpstreamMappingChanged` events to one stream per
    /// repository touched — and the whole list commits as one unit
    /// (rule 2 above). The pre-port shape appended one
    /// `EventStore::append` per stream after each row had already
    /// committed on its own, so a part-way failure left some
    /// repositories' mappings live and unattested and others audited.
    ///
    /// Upserts are applied before deletes, matching the apply plan's
    /// own order.
    fn commit_upstream_mappings<'a>(
        &'a self,
        change: &'a UpstreamMappingCommit,
        batches: Vec<AppendEvents>,
    ) -> BoxFuture<'a, DomainResult<()>>;

    /// Atomically apply `change` to the `service_accounts` aggregate
    /// rows and append `batches`.
    ///
    /// A service account is a **federated-identity trust anchor**
    /// (ADR 0018): its `federated_identities[].claims` decide which
    /// JWTs from a trusted issuer may assume it, and the federation
    /// handler reads the aggregate at assume time. So the row and its
    /// attesting `ServiceAccountCreated` / `ServiceAccountUpdated` /
    /// `ServiceAccountDeleted` event must not be able to land
    /// separately. Each upsert replaces the aggregate's sub-rows
    /// wholesale, which is why the adapter runs several statements per
    /// element — all inside the one transaction.
    ///
    /// Upserts are applied before deletes, matching the apply plan's
    /// own order.
    fn commit_service_accounts<'a>(
        &'a self,
        change: &'a ServiceAccountCommit,
        batches: Vec<AppendEvents>,
    ) -> BoxFuture<'a, DomainResult<()>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that `AuthorityLifecyclePort` is
    /// dyn-compatible — the apply pipeline holds it as
    /// `Arc<dyn AuthorityLifecyclePort>` at composition.
    #[test]
    fn port_is_dyn_compatible() {
        // Compile-time: resolves only if the trait is dyn-compatible.
        // Runtime: the size_of call executes in the test body so the
        // line is covered.
        let _ = size_of::<&dyn AuthorityLifecyclePort>();
    }

    /// An empty [`OidcIssuerChange`] is constructible via `Default` and
    /// carries no row operation — the shape the apply branch passes
    /// when its plan is empty.
    #[test]
    fn oidc_issuer_change_default_is_empty() {
        let change = OidcIssuerChange::default();
        assert!(change.upserts.is_empty());
        assert!(change.deletes.is_empty());
        assert_eq!(
            change,
            OidcIssuerChange {
                upserts: Vec::new(),
                deletes: Vec::new(),
            }
        );
    }

    /// Same for [`UpstreamMappingCommit`]. Asserted field-by-field
    /// rather than against a literal: [`RepositoryUpstreamMapping`]
    /// derives no `PartialEq`, so neither does the commit.
    #[test]
    fn upstream_mapping_commit_default_is_empty() {
        let commit = UpstreamMappingCommit::default();
        assert!(commit.upserts.is_empty());
        assert!(commit.deletes.is_empty());
        // `Debug` + `Clone` are part of the intent's contract (the
        // adapter logs the shape; the apply branch keeps ownership).
        assert!(format!("{:?}", commit.clone()).contains("UpstreamMappingCommit"));
    }

    /// Same for [`ServiceAccountCommit`].
    #[test]
    fn service_account_commit_default_is_empty() {
        let commit = ServiceAccountCommit::default();
        assert!(commit.upserts.is_empty());
        assert!(commit.deletes.is_empty());
        assert_eq!(
            commit.clone(),
            ServiceAccountCommit {
                upserts: Vec::new(),
                deletes: Vec::new(),
            }
        );
        assert!(format!("{commit:?}").contains("ServiceAccountCommit"));
    }
}
