//! Execution-time re-authorization of a destructive admin task.
//!
//! Acceptance does not confer authority. The enqueue path checks
//! `Permission::AdminTaskInvoke` **plus** the
//! [`DESTRUCTIVE_TASK_CLAIM`] once, against the principal that made the
//! request ([`TaskUseCase::authorize_kind`](crate::use_cases::TaskUseCase::authorize_kind)).
//! A `jobs` row then sits in the queue for however long the backlog,
//! the poll interval and the per-kind semaphore take, and the handler
//! that eventually runs it carries no principal at all — the dispatcher
//! synthesises `Actor::Internal(InternalActor::Timer)` and
//! `RetentionPurgeHandler` ignores even that. So authority granted at
//! 09:00 was spent at 09:10 whatever happened in between: take someone's
//! destructive authority away and the purge they queued still deleted
//! bytes.
//!
//! This module closes that window. [`DestructiveTaskReauthorizer`] is
//! consulted by [`TaskDispatcher`](crate::task_dispatcher::TaskDispatcher)
//! **before** a handler is invoked, and a refusal means the handler is
//! never called — nothing is destroyed, and the row lands terminal with
//! a reason an operator can read.
//!
//! # What "the same claim the enqueue required" means here
//!
//! The decision reuses the enqueue's own primitives, in the enqueue's
//! own order, so the two cannot drift:
//!
//! - [`task_invocation_is_destructive`] decides whether the check
//!   applies at all — the same per-invocation classifier the enqueue
//!   gate and the ADR 0028 idempotency key read, not a parallel list.
//!   A `retention-evaluate` dry run destroys nothing and is therefore
//!   not re-checked.
//! - [`RbacEvaluator::authorize`] for `Permission::AdminTaskInvoke` and
//!   [`RbacEvaluator::claims_satisfy`] for the claim, over an evaluator
//!   built from a **live** `PermissionGrantRepository::list_all` read —
//!   the same per-tick-evaluator pattern `ServiceAccountRotationHandler`
//!   uses, because the worker's composition-root evaluator is
//!   deliberately empty.
//!
//! # The execution-time principal, and why it can only subtract
//!
//! A `jobs` row persists the requester's **identity** (`actor_id`), not
//! their credential and not their resolved claim set. So the principal
//! rebuilt here carries exactly the authority the registry still has on
//! disk:
//!
//! - `claims` = the synthetic `admin` claim iff `users.is_admin` is
//!   still true, via the same [`add_admin_claim_if_admin`] every other
//!   principal-build path calls. A claim that was resolved from the
//!   IdP's `groups` claim through `claim_mappings` at authentication
//!   (ADR 0012) is **not** re-derivable without that session: nothing
//!   persists a user's groups, by design.
//! - `token_cap` = `None`, because the credential is not persisted
//!   either.
//!
//! Both omissions are safe in the only direction that matters. The cap
//! leg of [`RbacEvaluator::authorize`] is an AND, so dropping the cap
//! can only *widen* — but every row that exists already passed the
//! enqueue with its cap applied, so widening here cannot admit an
//! invocation the enqueue refused. The claim set, conversely, only ever
//! *narrows*: a requester who held the claim through an IdP group is
//! refused here. That is the fail-closed direction, and it is the one
//! this check exists to take — an execution carrying authority the
//! registry can no longer see is precisely what "acceptance does not
//! confer authority" forbids. The practical consequence, which belongs
//! in operator docs rather than only here: destructive tasks must be
//! invoked by a principal whose destructive authority is persisted,
//! i.e. an `admin` user.
//!
//! # Refusal versus unavailability
//!
//! The two are not the same fact and do not get the same outcome:
//!
//! - A **refusal** ([`ReauthorizationVerdict::Refused`]) is an authority
//!   answer: the requester does not hold what this invocation needs,
//!   right now. Trying again cannot change it, so the dispatcher records
//!   it as a terminal failure.
//! - An **unavailability** ([`ReauthorizationVerdict::Unavailable`]) is
//!   the absence of an answer: the users table or the grant set could
//!   not be read. It is still fail-closed — the handler does not run and
//!   nothing is destroyed — but a database flap says nothing about
//!   authority, so the row keeps its attempt budget and the next claim
//!   re-asks. This mirrors `ServiceAccountRotationHandler`'s treatment
//!   of a failed grant read.
//!
//! Neither outcome releases the invocation's per-UTC-day single-flight
//! claim (ADR 0028). That claim lives on the `jobs` row's
//! `idempotency_key` and the `jobs_idempotency_key_uq` index is **not**
//! status-scoped, so a refused row still owns the day: re-invoking the
//! same kind after restoring the authority returns the refused row's id
//! rather than enqueuing a fresh one, and recovering inside the day
//! means deleting that row — the same explicit, audited path every
//! other failed destructive job already has. Releasing the claim on a
//! refusal would be the wrong fix: the claim exists so a destructive
//! sweep cannot re-fire within a day, and a refusal is not evidence
//! that it did not.

use std::slice;
use std::sync::Arc;

use chrono::Utc;

use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::rbac::Permission;
use hort_domain::entities::user::User;
use hort_domain::error::DomainError;
use hort_domain::events::{task_invocation_is_destructive, DESTRUCTIVE_TASK_CLAIM};
use hort_domain::ports::jobs_repository::JobRow;
use hort_domain::ports::permission_grant_repository::PermissionGrantRepository;
use hort_domain::ports::user_repository::UserRepository;

use crate::rbac::{add_admin_claim_if_admin, RbacEvaluator};

/// Shared opening of every refusal reason, so an operator (or a log
/// query) can find all of them with one string and tell an authority
/// refusal apart from a handler's own failure in `jobs.last_error`.
pub const REFUSAL_PREFIX: &str = "destructive task refused at execution";

/// Shared opening of every unavailability reason. Distinct from
/// [`REFUSAL_PREFIX`] because the two mean different things to an
/// operator: one says "this will never run as queued", the other says
/// "this did not run yet".
pub const UNAVAILABLE_PREFIX: &str = "destructive task authority could not be re-checked";

/// The verdict on whether a claimed `jobs` row may proceed to its
/// handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReauthorizationVerdict {
    /// Run the handler. Either the invocation is not destructive (the
    /// overwhelming majority of rows, which pay nothing for this
    /// check), or the requester's authority still holds.
    Authorized,
    /// Do not run the handler, and do not try again: the requester's
    /// authority does not hold. `reason` names the cause and is what
    /// lands in `jobs.last_error`.
    Refused { reason: String },
    /// Do not run the handler, but the answer is unknown rather than
    /// negative — re-ask on the next claim.
    Unavailable { reason: String },
}

/// Re-checks a destructive invocation's requester against the live
/// authority state, immediately before execution.
///
/// Holds only outbound ports, so it composes the same way every other
/// `hort-app` collaborator does and is testable against the shared mock
/// harness. The RBAC view is built per call, not cached: a cache would
/// reintroduce the staleness window this exists to close.
pub struct DestructiveTaskReauthorizer {
    users: Arc<dyn UserRepository>,
    grants: Arc<dyn PermissionGrantRepository>,
}

impl DestructiveTaskReauthorizer {
    pub fn new(users: Arc<dyn UserRepository>, grants: Arc<dyn PermissionGrantRepository>) -> Self {
        Self { users, grants }
    }

    /// Decide whether `job` may proceed to its handler.
    ///
    /// `params` is the value the dispatcher will hand the handler (the
    /// row's `params`, or JSON `null` when the column is SQL NULL), so
    /// the classification sees exactly what will run rather than a
    /// second reading of the row.
    ///
    /// Returns [`ReauthorizationVerdict::Authorized`] without any I/O
    /// for every non-destructive invocation — one pure classifier call.
    /// That is deliberate: the price of a late refusal is only justified
    /// where execution is irreversible, and the ordinary kinds
    /// (`scan`, `noop`, the sweep ticks, a `retention-evaluate` dry run)
    /// must not acquire two database reads per row.
    pub async fn authorize_execution(
        &self,
        job: &JobRow,
        params: &serde_json::Value,
    ) -> ReauthorizationVerdict {
        // 1. Does this invocation destroy anything? Same per-invocation
        //    classifier as the enqueue gate. An unclassifiable row (a
        //    `mode` string outside the closed vocabulary, which the
        //    enqueue's param validation rejects and only an out-of-band
        //    write could produce) is refused rather than guessed at: we
        //    cannot say what authority it needs, so we cannot say it
        //    holds it. The params are fixed on the row, so a retry
        //    would reach the same dead end.
        let destructive = match task_invocation_is_destructive(&job.kind, params) {
            Ok(destructive) => destructive,
            Err(err) => {
                return refuse(format!(
                    "{REFUSAL_PREFIX}: the invocation could not be classified as destructive or \
                     not ({err}), so the authority it requires cannot be determined"
                ));
            }
        };
        if !destructive {
            return ReauthorizationVerdict::Authorized;
        }

        // 2. An unnamed requester has no authority to re-check. Only
        //    `TaskUseCase::enqueue` produces rows of these kinds and it
        //    always passes `Some(actor.user_id)`, so this arm is not
        //    reachable through the application; the column is nullable
        //    for the kinds that genuinely have no human behind them
        //    (ingest-spawned scans, cron ticks, prefetch children).
        //    It stays fail-closed regardless, because `Option<Uuid>` is
        //    what the row type offers and an out-of-band INSERT is not
        //    bound by the application's call shape.
        let Some(actor_id) = job.actor_id else {
            return refuse(format!(
                "{REFUSAL_PREFIX}: the jobs row names no requester, so there is no authority to \
                 re-check before destroying anything"
            ));
        };

        // 3. The requester's live identity. A missing row is an
        //    authority answer (nobody holds anything); any other read
        //    error is the absence of an answer.
        let user = match self.users.find_by_id(actor_id).await {
            Ok(user) => user,
            Err(DomainError::NotFound { .. }) => {
                return refuse(format!(
                    "{REFUSAL_PREFIX}: the requesting identity {actor_id} no longer resolves to a \
                     user"
                ));
            }
            Err(err) => {
                return unavailable(format!(
                    "{UNAVAILABLE_PREFIX}: the requesting identity {actor_id} could not be read \
                     ({err}); nothing ran"
                ));
            }
        };
        // Deactivation is honoured on every live authentication path
        // (`authenticate_cli_session`, `validate_pat`), so a queued
        // destructive job must honour it too — otherwise deactivating
        // an account stops its next request and not the irreversible
        // work it already queued.
        if !user.is_active {
            return refuse(format!(
                "{REFUSAL_PREFIX}: the requester's account was deactivated before execution"
            ));
        }

        // 4. The live grant set, as its own evaluator. The worker's
        //    composition-root evaluator is deliberately empty, so
        //    reading grants here is the only way to see the authority
        //    as it stands now.
        let grants = match self.grants.list_all().await {
            Ok(grants) => grants,
            Err(err) => {
                return unavailable(format!(
                    "{UNAVAILABLE_PREFIX}: the permission-grant set could not be read ({err}); \
                     nothing ran"
                ));
            }
        };
        let rbac = RbacEvaluator::new(grants);
        let principal = execution_time_principal(&user);

        // 5. The enqueue's two factors, in the enqueue's order, through
        //    the enqueue's evaluator methods.
        if !rbac.authorize(&principal, Permission::AdminTaskInvoke, None) {
            return refuse(format!(
                "{REFUSAL_PREFIX}: the requester no longer holds Permission::AdminTaskInvoke — it \
                 was revoked before execution"
            ));
        }
        if !rbac.claims_satisfy(&principal, slice::from_ref(&DESTRUCTIVE_TASK_CLAIM)) {
            return refuse(format!(
                "{REFUSAL_PREFIX}: the requester's {DESTRUCTIVE_TASK_CLAIM:?} claim was revoked \
                 before execution"
            ));
        }

        ReauthorizationVerdict::Authorized
    }
}

fn refuse(reason: String) -> ReauthorizationVerdict {
    ReauthorizationVerdict::Refused { reason }
}

fn unavailable(reason: String) -> ReauthorizationVerdict {
    ReauthorizationVerdict::Unavailable { reason }
}

/// Rebuild the requester as a principal carrying exactly the authority
/// the registry still holds for them.
///
/// See the module docs for why `claims` is at most the synthetic `admin`
/// claim and why `token_cap` is `None` — and for why both can only make
/// this check narrower than the enqueue's, never wider.
fn execution_time_principal(user: &User) -> CallerPrincipal {
    let mut claims = Vec::new();
    add_admin_claim_if_admin(&mut claims, user.is_admin);
    CallerPrincipal {
        user_id: user.id,
        external_id: user
            .external_id
            .clone()
            .unwrap_or_else(|| user.id.to_string()),
        username: user.username.clone(),
        email: user.email.clone(),
        claims,
        // No credential is persisted on the row, so there is no token
        // kind to name. `None` is the same value every non-token
        // principal-build path uses.
        token_kind: None,
        issued_at: Utc::now(),
        token_cap: None,
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};
    use uuid::Uuid;

    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::rbac::{GrantSubject, PermissionGrant};
    use hort_domain::entities::user::AuthProvider;
    use hort_domain::error::DomainResult;
    use hort_domain::ports::jobs_repository::{JobStatus, KindFields};
    use hort_domain::ports::BoxFuture;

    use crate::use_cases::test_support::{MockPermissionGrantRepository, MockUserRepository};

    use super::*;

    // -----------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------

    fn user(id: Uuid, is_admin: bool, is_active: bool) -> User {
        User {
            id,
            username: "requester".into(),
            email: "requester@example.test".into(),
            auth_provider: AuthProvider::Oidc,
            external_id: Some("oidc:requester".into()),
            display_name: None,
            is_active,
            is_admin,
            is_service_account: false,
            last_login_at: None,
            created_at: DateTime::<Utc>::UNIX_EPOCH,
            updated_at: DateTime::<Utc>::UNIX_EPOCH,
        }
    }

    fn invoke_grant(subject: GrantSubject) -> PermissionGrant {
        PermissionGrant {
            id: Uuid::new_v4(),
            subject,
            repository_id: None,
            permission: Permission::AdminTaskInvoke,
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
            created_at: DateTime::<Utc>::UNIX_EPOCH,
        }
    }

    fn row(kind: &str, actor_id: Option<Uuid>, params: serde_json::Value) -> JobRow {
        JobRow {
            id: Uuid::new_v4(),
            kind: kind.into(),
            status: JobStatus::Running,
            params: Some(params),
            actor_id,
            priority: 20,
            trigger_source: "manual".into(),
            attempts: 1,
            created_at: DateTime::<Utc>::UNIX_EPOCH,
            updated_at: DateTime::<Utc>::UNIX_EPOCH,
            completed_at: None,
            last_error: None,
            result_summary: None,
            kind_fields: KindFields::Other,
        }
    }

    /// Build a reauthorizer over the shared mocks, seeded with one user
    /// and one grant set.
    fn reauthorizer(
        seeded_user: Option<User>,
        grants: Vec<PermissionGrant>,
    ) -> DestructiveTaskReauthorizer {
        let users = Arc::new(MockUserRepository::new());
        if let Some(u) = seeded_user {
            users.insert(u);
        }
        let grant_repo = Arc::new(MockPermissionGrantRepository::new());
        grant_repo.seed(grants);
        DestructiveTaskReauthorizer::new(users, grant_repo)
    }

    /// A `UserRepository` whose reads fail with an infrastructure error
    /// rather than `NotFound` — the one distinction the shared mock
    /// cannot express, and the one that decides terminal versus
    /// retryable.
    struct FailingUsers;

    impl UserRepository for FailingUsers {
        fn find_by_id(&self, _id: Uuid) -> BoxFuture<'_, DomainResult<User>> {
            Box::pin(async {
                Err(DomainError::Invariant(
                    "database error: users read failed".into(),
                ))
            })
        }
        fn find_by_username(&self, _u: &str) -> BoxFuture<'_, DomainResult<Option<User>>> {
            unreachable!("the reauthorizer only resolves by id")
        }
        fn find_by_email(&self, _e: &str) -> BoxFuture<'_, DomainResult<Option<User>>> {
            unreachable!("the reauthorizer only resolves by id")
        }
        fn list(
            &self,
            _page: hort_domain::types::PageRequest,
        ) -> BoxFuture<'_, DomainResult<hort_domain::types::Page<User>>> {
            unreachable!("the reauthorizer only resolves by id")
        }
        fn save(&self, _user: &User) -> BoxFuture<'_, DomainResult<()>> {
            unreachable!("the reauthorizer never writes")
        }
        fn delete(&self, _id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
            unreachable!("the reauthorizer never writes")
        }
        fn find_by_external_id(
            &self,
            _p: AuthProvider,
            _e: &str,
        ) -> BoxFuture<'_, DomainResult<Option<User>>> {
            unreachable!("the reauthorizer only resolves by id")
        }
        fn upsert_on_login(&self, _user: &User) -> BoxFuture<'_, DomainResult<User>> {
            unreachable!("the reauthorizer never writes")
        }
    }

    /// A `PermissionGrantRepository` whose snapshot read fails.
    struct FailingGrants;

    impl PermissionGrantRepository for FailingGrants {
        fn list_all(&self) -> BoxFuture<'_, DomainResult<Vec<PermissionGrant>>> {
            Box::pin(async {
                Err(DomainError::Invariant(
                    "database error: grant read failed".into(),
                ))
            })
        }
        fn list_managed_by_gitops(&self) -> BoxFuture<'_, DomainResult<Vec<PermissionGrant>>> {
            unreachable!("the reauthorizer reads the full snapshot")
        }
    }

    fn refusal_reason(verdict: &ReauthorizationVerdict) -> &str {
        match verdict {
            ReauthorizationVerdict::Refused { reason } => reason,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    fn unavailable_reason(verdict: &ReauthorizationVerdict) -> &str {
        match verdict {
            ReauthorizationVerdict::Unavailable { reason } => reason,
            other => panic!("expected an unavailability, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // The normal case
    // -----------------------------------------------------------------

    /// An admin requester whose authority is unchanged still runs. The
    /// `admin` claim short-circuits the claim requirement exactly as it
    /// does at enqueue, so no separate `task:destructive` grant is
    /// needed for this path.
    #[tokio::test]
    async fn an_admin_requester_whose_authority_still_holds_is_authorized() {
        let actor = Uuid::new_v4();
        let reauth = reauthorizer(Some(user(actor, true, true)), Vec::new());

        let verdict = reauth
            .authorize_execution(
                &row("retention-purge", Some(actor), serde_json::json!({})),
                &serde_json::json!({}),
            )
            .await;

        assert_eq!(verdict, ReauthorizationVerdict::Authorized);
    }

    /// The two legs are independent, and a grant satisfies only one of
    /// them. A non-admin requester holding `AdminTaskInvoke` through a
    /// live `User`-subject grant — the shape a gitops-granted service
    /// account or operator has — passes the permission leg and is still
    /// refused on the claim, because no grant confers a claim (ADR 0012
    /// keeps the two taxonomies apart). Pinned by asserting *which* leg
    /// the refusal names: a future change that collapsed the claim leg
    /// into the permission leg would otherwise pass unnoticed.
    #[tokio::test]
    async fn a_user_subject_grant_satisfies_the_permission_leg_but_not_the_claim_leg() {
        let actor = Uuid::new_v4();
        let reauth = reauthorizer(
            Some(user(actor, false, true)),
            vec![invoke_grant(GrantSubject::User(actor))],
        );

        let verdict = reauth
            .authorize_execution(
                &row("eventstore-archive", Some(actor), serde_json::json!({})),
                &serde_json::json!({}),
            )
            .await;

        let reason = refusal_reason(&verdict);
        assert!(
            reason.contains("task:destructive") && reason.contains("revoked before execution"),
            "the refusal must name the claim leg, not the permission leg: {reason}"
        );
    }

    // -----------------------------------------------------------------
    // The gap itself
    // -----------------------------------------------------------------

    /// The defect this module exists for: the requester held the claim
    /// when the row was enqueued and does not hold it now. Nothing runs.
    #[tokio::test]
    async fn a_requester_demoted_after_enqueue_is_refused() {
        let actor = Uuid::new_v4();
        // Demotion is `is_admin = false`: the synthetic `admin` claim is
        // the only destructive authority the registry persists, so
        // losing it is losing the claim.
        let reauth = reauthorizer(Some(user(actor, false, true)), Vec::new());

        let verdict = reauth
            .authorize_execution(
                &row("retention-purge", Some(actor), serde_json::json!({})),
                &serde_json::json!({}),
            )
            .await;

        assert!(refusal_reason(&verdict).starts_with(REFUSAL_PREFIX));
    }

    /// `AdminTaskInvoke` revoked while the row waited. The refusal names
    /// the permission, not the claim — the two remediations differ.
    #[tokio::test]
    async fn a_requester_whose_permission_was_revoked_is_refused_naming_the_permission() {
        let actor = Uuid::new_v4();
        // Non-admin, no grants at all: the permission leg fails first,
        // so its reason is the one reported.
        let reauth = reauthorizer(Some(user(actor, false, true)), Vec::new());

        let verdict = reauth
            .authorize_execution(
                &row("retention-purge", Some(actor), serde_json::json!({})),
                &serde_json::json!({}),
            )
            .await;

        let reason = refusal_reason(&verdict);
        assert!(
            reason.contains("Permission::AdminTaskInvoke"),
            "expected the permission leg to be named: {reason}"
        );
    }

    /// Deactivation stops a queued destructive job, matching what it
    /// already does to the account's next request.
    #[tokio::test]
    async fn a_deactivated_requester_is_refused() {
        let actor = Uuid::new_v4();
        let reauth = reauthorizer(Some(user(actor, true, false)), Vec::new());

        let verdict = reauth
            .authorize_execution(
                &row("retention-purge", Some(actor), serde_json::json!({})),
                &serde_json::json!({}),
            )
            .await;

        assert!(refusal_reason(&verdict).contains("deactivated before execution"));
    }

    // -----------------------------------------------------------------
    // Fail-closed on an unresolvable requester
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn a_row_with_no_requester_is_refused() {
        let reauth = reauthorizer(None, Vec::new());

        let verdict = reauth
            .authorize_execution(
                &row("retention-purge", None, serde_json::json!({})),
                &serde_json::json!({}),
            )
            .await;

        assert!(refusal_reason(&verdict).contains("names no requester"));
    }

    #[tokio::test]
    async fn a_requester_whose_user_row_is_gone_is_refused() {
        let actor = Uuid::new_v4();
        let reauth = reauthorizer(None, Vec::new());

        let verdict = reauth
            .authorize_execution(
                &row("retention-purge", Some(actor), serde_json::json!({})),
                &serde_json::json!({}),
            )
            .await;

        let reason = refusal_reason(&verdict);
        assert!(
            reason.contains(&actor.to_string()) && reason.contains("no longer resolves to a user"),
            "the refusal must name the unresolvable identity: {reason}"
        );
    }

    // -----------------------------------------------------------------
    // Unavailability is not a refusal
    // -----------------------------------------------------------------

    /// A users-table read failure leaves authority unknown. Fail-closed
    /// (the handler does not run) but re-askable, because a database
    /// flap is not a revocation.
    #[tokio::test]
    async fn an_unreadable_users_table_is_unavailable_not_refused() {
        let actor = Uuid::new_v4();
        let grants = Arc::new(MockPermissionGrantRepository::new());
        let reauth = DestructiveTaskReauthorizer::new(Arc::new(FailingUsers), grants);

        let verdict = reauth
            .authorize_execution(
                &row("retention-purge", Some(actor), serde_json::json!({})),
                &serde_json::json!({}),
            )
            .await;

        assert!(unavailable_reason(&verdict).contains("could not be read"));
    }

    #[tokio::test]
    async fn an_unreadable_grant_set_is_unavailable_not_refused() {
        let actor = Uuid::new_v4();
        let users = Arc::new(MockUserRepository::new());
        users.insert(user(actor, true, true));
        let reauth = DestructiveTaskReauthorizer::new(users, Arc::new(FailingGrants));

        let verdict = reauth
            .authorize_execution(
                &row("retention-purge", Some(actor), serde_json::json!({})),
                &serde_json::json!({}),
            )
            .await;

        assert!(
            unavailable_reason(&verdict).contains("permission-grant set could not be read"),
            "an admin requester must not be waved through a grant read the check could not make"
        );
    }

    // -----------------------------------------------------------------
    // Only the destructive invocations pay
    // -----------------------------------------------------------------

    /// A non-destructive kind is authorized without touching either
    /// port. The mocks are seeded with nothing and the user does not
    /// exist, so a verdict of `Authorized` is only reachable by the
    /// classifier short-circuit.
    #[tokio::test]
    async fn a_non_destructive_kind_is_authorized_without_any_authority_read() {
        let reauth =
            DestructiveTaskReauthorizer::new(Arc::new(FailingUsers), Arc::new(FailingGrants));

        for kind in ["noop", "scan", "staging-sweep", "cron-rescan-tick"] {
            let verdict = reauth
                .authorize_execution(
                    &row(kind, Some(Uuid::new_v4()), serde_json::json!({})),
                    &serde_json::json!({}),
                )
                .await;
            assert_eq!(
                verdict,
                ReauthorizationVerdict::Authorized,
                "kind {kind:?} is not destructive and must not be re-checked"
            );
        }
    }

    /// A `retention-evaluate` **dry run** destroys nothing, so it is not
    /// re-checked — the same split `task_invocation_is_destructive`
    /// draws for the enqueue gate and the idempotency key. Its execute
    /// counterpart, including the defaulted mode, is.
    #[tokio::test]
    async fn retention_evaluate_is_re_checked_per_mode_not_per_kind() {
        let reauth =
            DestructiveTaskReauthorizer::new(Arc::new(FailingUsers), Arc::new(FailingGrants));

        let dry_run = serde_json::json!({ "mode": "dry_run" });
        assert_eq!(
            reauth
                .authorize_execution(
                    &row("retention-evaluate", Some(Uuid::new_v4()), dry_run.clone()),
                    &dry_run
                )
                .await,
            ReauthorizationVerdict::Authorized,
            "an observation destroys nothing and must not pay for the re-check"
        );

        for params in [
            serde_json::json!({ "mode": "execute" }),
            // The shipped CronJob posts `{}`; the mode defaults to
            // execute, so the default is re-checked too.
            serde_json::json!({}),
        ] {
            let verdict = reauth
                .authorize_execution(
                    &row("retention-evaluate", Some(Uuid::new_v4()), params.clone()),
                    &params,
                )
                .await;
            assert_ne!(
                verdict,
                ReauthorizationVerdict::Authorized,
                "retention-evaluate with params {params} executes and must be re-checked"
            );
        }
    }

    /// An invocation whose mode string is outside the closed vocabulary
    /// cannot be classified, so its authority requirement is unknown.
    /// Refused, not retried — the params are fixed on the row.
    #[tokio::test]
    async fn an_unclassifiable_invocation_is_refused() {
        let actor = Uuid::new_v4();
        let reauth = reauthorizer(Some(user(actor, true, true)), Vec::new());
        let params = serde_json::json!({ "mode": "nonsense" });

        let verdict = reauth
            .authorize_execution(
                &row("retention-evaluate", Some(actor), params.clone()),
                &params,
            )
            .await;

        assert!(refusal_reason(&verdict).contains("could not be classified"));
    }

    // -----------------------------------------------------------------
    // The rebuilt principal
    // -----------------------------------------------------------------

    /// The principal carries the live `admin` bit and nothing the row
    /// does not persist: no credential cap, no token kind.
    #[test]
    fn the_execution_time_principal_carries_only_persisted_authority() {
        let id = Uuid::new_v4();
        let admin = execution_time_principal(&user(id, true, true));
        assert_eq!(admin.user_id, id);
        assert_eq!(admin.claims, vec!["admin".to_string()]);
        assert!(admin.token_cap.is_none(), "no credential is persisted");
        assert!(admin.token_kind.is_none(), "no credential is persisted");
        assert_eq!(admin.external_id, "oidc:requester");

        let plain = execution_time_principal(&user(id, false, true));
        assert!(
            plain.claims.is_empty(),
            "a claim resolved from an IdP session is not re-derivable here"
        );
    }

    /// A user row with no `external_id` (the local-auth shape) falls
    /// back to the id rather than panicking or inventing one.
    #[test]
    fn a_principal_without_an_external_id_falls_back_to_the_user_id() {
        let id = Uuid::new_v4();
        let mut u = user(id, true, true);
        u.external_id = None;
        assert_eq!(execution_time_principal(&u).external_id, id.to_string());
    }
}
