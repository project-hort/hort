//! Subscription-filter evaluation pure function.
//!
//! Implements the 5-step delivery-time filter contract (see
//! `docs/architecture/explanation/event-notifications.md`):
//!
//! 1. **Category match.** `event.stream_id.category ∈ filter.categories`.
//! 2. **Event-type match.** `EventTypeFilter::matches` against the event.
//! 3. **Repository scope.** Structural check against
//!    `EventTypeKind::repository_id(&event.event)`. Events without a
//!    repository association fall through to step 4 unconditionally for
//!    `OwnedByActor` / `All`, and are rejected outright for `Some(_)`.
//! 4. **Live authz.** `RbacEvaluator::authorize(owner, perm, repo)` — the
//!    owner's *current* grants intersected with the stored filter scope.
//!    `OwnedByActor` / `Some(_)` check `Permission::Read`; `All` checks
//!    `Permission::Admin`. Events without a repository association skip
//!    this step **unless** the event's category is privileged
//!    (`StreamCategory::requires_admin` — the `ADMIN_CATEGORIES` set
//!    `{Policy, Admin, Authorization, User, AuthAttempts}`): such an
//!    event is delivered only if the synthesised owner principal
//!    *currently* satisfies `Permission::Admin`. This dispatch-time
//!    gate is the
//!    load-bearing leg that prevents privileged-event leakage by
//!    re-deriving privileged-category authority against live owner
//!    state rather than trusting the `snapshot_claims` floor (a
//!    PATCH-via-PAT `["admin"]`-elevated snapshot cannot retroactively
//!    unlock a category the owner is not *currently* admin for; the
//!    dispatcher's `synthesise_principal` strips any stale snapshot
//!    `"admin"` so this re-check is authoritative). The category
//!    predicate is the single hoisted `hort-domain`
//!    `StreamCategory::requires_admin` (`hort-app` must not
//!    re-encode the set nor import `hort-http-events`).
//! 5. **Named predicates.** `NamedPredicate` is an empty enum in v1, so
//!    the loop body is the canonical exhaustive empty match
//!    (`match *predicate {}`). The hook stays so future v1.x variants
//!    AND-compose without changing the dispatcher loop.
//!
//! **Authorization is live, not snapshotted** (§4 prose, §11 invariant 3).
//! Filter scope is the upper bound; the owner's current grants are the
//! floor. The dispatcher loads one `RbacEvaluator` snapshot per delivery
//! batch (Item 6b) and passes it down via [`FilterContext`] so every
//! per-event check sees a consistent evaluator without re-loading.
//!
//! No `tracing` — filter evaluation runs once per `(subscription, event)`
//! pair on the dispatcher hot path; per-event log records would tank
//! throughput. The dispatcher emits aggregate counters; per-event match
//! decisions are not log-worthy.

use std::sync::Arc;

use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::rbac::Permission;
use hort_domain::entities::subscription::{
    EventTypeKind, NamedPredicate, RepositoryScope, SubscriptionFilter,
};
use hort_domain::events::PersistedEvent;
use hort_domain::ports::repository_repository::RepositoryRepository;

use crate::rbac::RbacEvaluator;

/// Resolved-once context the dispatcher carries through a delivery batch.
///
/// The dispatcher (Item 6b) loads `rbac.load()` once per batch — the same
/// pattern [`crate::use_cases::subscription_use_case::SubscriptionUseCase::create`]
/// uses — and reborrows the `RbacEvaluator` into every per-event
/// [`matches`] call. The [`RepositoryRepository`] port is held but not
/// consulted in v1: it exists as the forward-compat hook for future
/// `NamedPredicate` variants that need to reach for repository metadata.
pub struct FilterContext<'a> {
    /// Single `rbac.load()` snapshot per delivery batch. Live re-loads
    /// happen between batches, not within them.
    pub rbac: &'a RbacEvaluator,
    /// Forward-compat hook. v1 ships zero `NamedPredicate` variants, so
    /// the field is held but never consulted. Future predicate variants
    /// that need repository metadata reach for it through this port.
    pub repositories: &'a Arc<dyn RepositoryRepository>,
    /// Owner principal resolved against the current evaluator. The
    /// dispatcher constructs this once per delivery batch from the
    /// owner's `User` row + the evaluator's role resolution so the
    /// `authorize` call shape matches the one used at creation time.
    pub owner_principal: &'a CallerPrincipal,
}

/// Evaluate a subscription filter against a persisted event.
///
/// Returns `true` if the event should be delivered to the subscription;
/// `false` otherwise. Short-circuits on the first failing step per the
/// §4 contract. See the module-level docs for the evaluation order.
pub async fn matches(
    filter: &SubscriptionFilter,
    event: &PersistedEvent,
    ctx: &FilterContext<'_>,
) -> bool {
    // Step 1 — category match.
    if !filter.categories.contains(&event.stream_id.category) {
        return false;
    }

    // Step 2 — event-type match (delegates to the closed-enum impl on
    // `EventTypeFilter`).
    if !filter.event_types.matches(event) {
        return false;
    }

    // Step 3 — repository scope (structural). `EventTypeKind::repository_id`
    // is the exhaustive closed-enum extractor; events without a repo
    // association return `None`.
    let event_repo = EventTypeKind::repository_id(&event.event);

    let repo_for_authz: Option<uuid::Uuid> = match (&filter.repositories, event_repo) {
        // OwnedByActor: any event with a repo association proceeds to
        // step 4's authz check; events without a repo association fall
        // through (no per-repo restriction to apply).
        (RepositoryScope::OwnedByActor, repo) => repo,
        // Some(allowed) with event in the allow-list: proceed.
        (RepositoryScope::Some(allowed), Some(repo_id)) if allowed.contains(&repo_id) => {
            Some(repo_id)
        }
        // Some(allowed) with event outside the allow-list, or no repo
        // association: hard reject. An explicit allow-list cannot match
        // an event that has no repo association.
        (RepositoryScope::Some(_), _) => return false,
        // All: admin-scope; structurally passes. Step 4 re-verifies the
        // owner still holds Admin.
        (RepositoryScope::All, repo) => repo,
    };

    // Step 4 — live authz. Filter scope is the upper bound; the owner's
    // current grants are the floor.
    //
    // - `repo_for_authz = None` → the event has no repo association.
    //   An unconditional authz skip here would be a
    //   privileged-category hole: a `None`-repo event whose category is
    //   privileged (`StreamCategory::requires_admin` — the
    //   `ADMIN_CATEGORIES` set) is delivered ONLY if the synthesised
    //   owner principal *currently* satisfies `Permission::Admin`. This
    //   re-derives authority against live owner state, never trusting
    //   the `snapshot_claims` floor (the dispatcher's
    //   `synthesise_principal` strips any stale snapshot `"admin"` so a
    //   PATCH-via-PAT-elevated, owner-no-longer-admin subscription
    //   delivers nothing privileged — closed by construction).
    //   Non-privileged `None`-repo categories keep the
    //   pass-through. The category predicate is the
    //   single hoisted `hort-domain` `StreamCategory::requires_admin`
    //   (`hort-app` does not re-encode the set nor import
    //   `hort-http-events`).
    // - `RepositoryScope::All` + `Some(_)` → admin scope; require global
    //   `Permission::Admin`. Repo is not used for the authz check (admin
    //   is global).
    // - everything else with `Some(repo)` → require `Permission::Read`
    //   on that repo.
    //
    // **Type-not-category** admin gate.
    // Some privileged event *types* ride a non-admin stream category:
    // `PermissionGrant{Applied,Revoked}` / `RepositoryUpstreamMappingChanged`
    // route to `StreamCategory::Repository` when repo-scoped (so the
    // `(_, None)` category re-check never fires — they have `Some(repo)`),
    // and `ArtifactDownloaded` is repo-associated on `DownloadAudit` (so the
    // None-repo re-check never sees it). The two domain predicates classify
    // the type irrespective of category; when either is `true` the event is
    // delivered ONLY to an owner who *currently* satisfies `Permission::Admin`
    // — folded into the existing `authz_ok`/`return false` denial path below
    // so the same dispatch-deny machinery (and `SubscriptionDisabled` /
    // failure accounting) applies. Mirrors the live-authority
    // posture (never trusts `snapshot_claims`).
    let type_requires_admin =
        event.event.is_authorization_model_mutation() || event.event.is_privileged_audit();

    let base_authz_ok = match (&filter.repositories, repo_for_authz) {
        (_, None) => {
            // Privileged-category re-check.
            // `event.stream_id.category` is the authoritative
            // category for the gate — the same field step 1 matched.
            if event.stream_id.category.requires_admin() {
                ctx.rbac
                    .authorize(ctx.owner_principal, Permission::Admin, None)
            } else {
                true
            }
        }
        (RepositoryScope::All, Some(_)) => {
            ctx.rbac
                .authorize(ctx.owner_principal, Permission::Admin, None)
        }
        (_, Some(repo)) => ctx
            .rbac
            .authorize(ctx.owner_principal, Permission::Read, Some(repo)),
    };

    // Type-based admin requirement (F-39 + F-37) is strictly additive to the
    // category/scope decision: an authorization-model-mutation or
    // privileged-audit type must additionally clear a live `Permission::Admin`
    // check regardless of the carrying stream's category (both the `(_, None)`
    // and `(_, Some(repo))` arms above).
    let authz_ok = base_authz_ok
        && (!type_requires_admin
            || ctx
                .rbac
                .authorize(ctx.owner_principal, Permission::Admin, None));
    if !authz_ok {
        return false;
    }

    // Step 5 — named predicates. v1 enum is empty → the vec is always
    // empty in practice → this loop is a no-op. Wired exhaustively so
    // a future variant AND-composes via the existing branch.
    for predicate in &filter.named_predicates {
        if !evaluate_named_predicate(predicate, event, ctx).await {
            return false;
        }
    }

    true
}

/// Evaluate a single named predicate against the event.
///
/// v1 ships zero variants of [`NamedPredicate`]; the function body is
/// the canonical exhaustive empty match over an uninhabited enum
/// (compile-time-checked). Future variants extend here.
async fn evaluate_named_predicate(
    predicate: &NamedPredicate,
    _event: &PersistedEvent,
    _ctx: &FilterContext<'_>,
) -> bool {
    match *predicate {}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::Utc;
    use uuid::Uuid;

    use hort_domain::entities::caller::CallerPrincipal;
    use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
    use hort_domain::entities::subscription::{
        EventTypeFilter, EventTypeKind, RepositoryScope, SubscriptionFilter,
    };
    use hort_domain::events::{
        Actor, ApiActor, ArtifactIngested, DomainEvent, FilterSummary, PersistedEvent,
        RepositoryScopeKind, StreamCategory, StreamId, SubscriptionCreated, TargetKindWire,
    };
    use hort_domain::ports::repository_repository::RepositoryRepository;
    use hort_domain::types::ContentHash;

    use super::*;
    use crate::rbac::RbacEvaluator;
    use crate::use_cases::test_support::MockRepositoryRepository;

    // -- Helpers -----------------------------------------------------------

    /// Build a principal carrying the given strings as its resolved
    /// **claim set** (ADR 0012 — there is no separate
    /// `groups` + `roles` pair).
    fn principal_with_roles(user_id: Uuid, roles: &[&str]) -> CallerPrincipal {
        CallerPrincipal {
            user_id,
            external_id: "test:sub".into(),
            username: "tester".into(),
            email: "tester@example.com".into(),
            claims: roles.iter().map(|s| (*s).to_string()).collect(),
            token_kind: None,
            issued_at: Utc::now(),
            token_cap: None,
        }
    }

    fn empty_eval() -> RbacEvaluator {
        RbacEvaluator::new(Vec::new())
    }

    /// Evaluator where a `Claims([role_name])`-subject grant carries
    /// `Read` on `repo_id` (claim-based subject model —
    /// a single required claim, no role→grant indirection).
    fn eval_with_repo_read(role_name: &str, repo_id: Uuid) -> RbacEvaluator {
        RbacEvaluator::new(vec![PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::Claims(vec![role_name.to_string()]),
            repository_id: Some(repo_id),
            permission: Permission::Read,
            created_at: Utc::now(),
            managed_by: hort_domain::entities::managed_by::ManagedBy::Local,
            managed_by_digest: None,
        }])
    }

    fn repos() -> Arc<dyn RepositoryRepository> {
        Arc::new(MockRepositoryRepository::new())
    }

    /// Build a `PersistedEvent` carrying an `ArtifactIngested` payload —
    /// the canonical test case for "event has a `repository_id`".
    fn ingested_event(stream_id: StreamId, repo_id: Uuid) -> PersistedEvent {
        PersistedEvent {
            event_id: Uuid::new_v4(),
            stream_id,
            stream_position: 0,
            global_position: 1,
            event: DomainEvent::ArtifactIngested(ArtifactIngested {
                artifact_id: Uuid::new_v4(),
                repository_id: repo_id,
                name: "pkg".into(),
                version: Some("1.0.0".into()),
                sha256: "a".repeat(64).parse::<ContentHash>().unwrap(),
                size_bytes: 1,
                source: hort_domain::events::IngestSource::Direct,
                metadata: serde_json::Value::Null,
                metadata_blob: None,
                upstream_published_at: None,
            }),
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(ApiActor {
                user_id: Uuid::new_v4(),
            }),
            event_version: 1,
            stored_at: Utc::now(),
        }
    }

    /// Build a `PersistedEvent` on the user stream with a
    /// `SubscriptionCreated` payload — canonical "event has no
    /// repository association" fixture.
    fn subscription_created_event(owner_user_id: Uuid) -> PersistedEvent {
        PersistedEvent {
            event_id: Uuid::new_v4(),
            stream_id: StreamId::user(owner_user_id),
            stream_position: 0,
            global_position: 1,
            event: DomainEvent::SubscriptionCreated(SubscriptionCreated {
                subscription_id: Uuid::new_v4(),
                owner_user_id,
                target_kind: TargetKindWire::Webhook,
                filter_summary: FilterSummary {
                    categories: vec!["user".into()],
                    event_type_count: 0,
                    repository_scope_kind: RepositoryScopeKind::OwnedByActor,
                    predicate_hash: [0; 32],
                },
                snapshot_claims_count: 0,
                at: Utc::now(),
            }),
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(ApiActor {
                user_id: owner_user_id,
            }),
            event_version: 1,
            stored_at: Utc::now(),
        }
    }

    /// Build a `PersistedEvent` on the global authorization stream with
    /// a `ClaimMappingApplied` payload — canonical "privileged-category
    /// (`StreamCategory::Authorization` ∈ `ADMIN_CATEGORIES`) event with
    /// `repository_id = None`" fixture (the dispatch-time
    /// privileged-category gate's locus).
    fn claim_mapping_applied_event() -> PersistedEvent {
        use hort_domain::events::ClaimMappingApplied;
        PersistedEvent {
            event_id: Uuid::new_v4(),
            stream_id: StreamId::authorization(),
            stream_position: 0,
            global_position: 1,
            event: DomainEvent::ClaimMappingApplied(ClaimMappingApplied {
                mapping_id: Uuid::new_v4(),
                idp_group: "engineering".into(),
                claim: "developer".into(),
            }),
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(ApiActor {
                user_id: Uuid::new_v4(),
            }),
            event_version: 1,
            stored_at: Utc::now(),
        }
    }

    /// Filter selecting the privileged `Authorization` category with
    /// `OwnedByActor` scope — the shape a poisoned-snapshot subscription
    /// would carry to attempt RBAC-mutation exfiltration (F-3 / F-37).
    fn authorization_owned_filter() -> SubscriptionFilter {
        SubscriptionFilter {
            categories: vec![StreamCategory::Authorization],
            event_types: EventTypeFilter::All,
            repositories: RepositoryScope::OwnedByActor,
            named_predicates: vec![],
        }
    }

    /// `OwnedByActor` filter accepting any artifact event.
    fn owned_artifact_filter() -> SubscriptionFilter {
        SubscriptionFilter {
            categories: vec![StreamCategory::Artifact],
            event_types: EventTypeFilter::All,
            repositories: RepositoryScope::OwnedByActor,
            named_predicates: vec![],
        }
    }

    // -- Step 1: category match -------------------------------------------

    #[tokio::test]
    async fn rejects_event_whose_category_not_in_filter() {
        let eval = empty_eval();
        let repos_arc = repos();
        let user_id = Uuid::new_v4();
        let principal = principal_with_roles(user_id, &[]);
        let ctx = FilterContext {
            rbac: &eval,
            repositories: &repos_arc,
            owner_principal: &principal,
        };

        // Filter wants Artifact only; event is on the User stream.
        let filter = SubscriptionFilter {
            categories: vec![StreamCategory::Artifact],
            event_types: EventTypeFilter::All,
            repositories: RepositoryScope::OwnedByActor,
            named_predicates: vec![],
        };
        let event = subscription_created_event(user_id);

        assert!(!matches(&filter, &event, &ctx).await);
    }

    #[tokio::test]
    async fn accepts_event_whose_category_is_in_filter() {
        let repo_id = Uuid::new_v4();
        let eval = eval_with_repo_read("dev", repo_id);
        let repos_arc = repos();
        let principal = principal_with_roles(Uuid::new_v4(), &["dev"]);
        let ctx = FilterContext {
            rbac: &eval,
            repositories: &repos_arc,
            owner_principal: &principal,
        };

        let filter = owned_artifact_filter();
        let event = ingested_event(StreamId::artifact(Uuid::new_v4()), repo_id);

        assert!(matches(&filter, &event, &ctx).await);
    }

    // -- Step 2: event-type match -----------------------------------------

    #[tokio::test]
    async fn rejects_when_event_type_filter_is_some_and_event_is_not_in_set() {
        let repo_id = Uuid::new_v4();
        let eval = eval_with_repo_read("dev", repo_id);
        let repos_arc = repos();
        let principal = principal_with_roles(Uuid::new_v4(), &["dev"]);
        let ctx = FilterContext {
            rbac: &eval,
            repositories: &repos_arc,
            owner_principal: &principal,
        };

        // Filter wants ArtifactPromoted only; event is ArtifactIngested.
        let filter = SubscriptionFilter {
            categories: vec![StreamCategory::Artifact],
            event_types: EventTypeFilter::Some(vec![EventTypeKind::ArtifactPromoted]),
            repositories: RepositoryScope::OwnedByActor,
            named_predicates: vec![],
        };
        let event = ingested_event(StreamId::artifact(Uuid::new_v4()), repo_id);

        assert!(!matches(&filter, &event, &ctx).await);
    }

    #[tokio::test]
    async fn accepts_when_event_type_filter_is_all() {
        let repo_id = Uuid::new_v4();
        let eval = eval_with_repo_read("dev", repo_id);
        let repos_arc = repos();
        let principal = principal_with_roles(Uuid::new_v4(), &["dev"]);
        let ctx = FilterContext {
            rbac: &eval,
            repositories: &repos_arc,
            owner_principal: &principal,
        };

        let filter = owned_artifact_filter();
        let event = ingested_event(StreamId::artifact(Uuid::new_v4()), repo_id);

        assert!(matches(&filter, &event, &ctx).await);
    }

    #[tokio::test]
    async fn accepts_when_event_type_filter_is_some_and_event_is_in_set() {
        let repo_id = Uuid::new_v4();
        let eval = eval_with_repo_read("dev", repo_id);
        let repos_arc = repos();
        let principal = principal_with_roles(Uuid::new_v4(), &["dev"]);
        let ctx = FilterContext {
            rbac: &eval,
            repositories: &repos_arc,
            owner_principal: &principal,
        };

        let filter = SubscriptionFilter {
            categories: vec![StreamCategory::Artifact],
            event_types: EventTypeFilter::Some(vec![EventTypeKind::ArtifactIngested]),
            repositories: RepositoryScope::OwnedByActor,
            named_predicates: vec![],
        };
        let event = ingested_event(StreamId::artifact(Uuid::new_v4()), repo_id);

        assert!(matches(&filter, &event, &ctx).await);
    }

    // -- Step 3: repository scope -----------------------------------------

    #[tokio::test]
    async fn owned_by_actor_with_event_no_repo_association_falls_through_to_authz_skip() {
        // ArtifactQuarantined carries no repository association and its
        // category (`Artifact`) is NON-privileged. OwnedByActor + no
        // repo + non-privileged category → step 4 skip → matches, even
        // for an empty (non-admin) principal. (The `User`-stream
        // `SubscriptionCreated` event is NOT a usable fixture here: `User` ∈
        // `ADMIN_CATEGORIES`, so that path requires admin — the
        // privileged variant is covered by
        // `privileged_category_none_repo_event_not_delivered_to_non_admin_owner`.
        // The no-repo-skip *mechanic* this test documents holds only
        // for non-privileged categories, so the fixture uses one.)
        use hort_domain::events::ArtifactQuarantined;
        let eval = empty_eval();
        let repos_arc = repos();
        let user_id = Uuid::new_v4();
        let principal = principal_with_roles(user_id, &[]);
        let ctx = FilterContext {
            rbac: &eval,
            repositories: &repos_arc,
            owner_principal: &principal,
        };

        let filter = SubscriptionFilter {
            categories: vec![StreamCategory::Artifact],
            event_types: EventTypeFilter::All,
            repositories: RepositoryScope::OwnedByActor,
            named_predicates: vec![],
        };
        let event = PersistedEvent {
            event_id: Uuid::new_v4(),
            stream_id: StreamId::artifact(Uuid::new_v4()),
            stream_position: 0,
            global_position: 1,
            event: DomainEvent::ArtifactQuarantined(ArtifactQuarantined {
                artifact_id: Uuid::new_v4(),
                quarantine_window_start: Utc::now(),
            }),
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(ApiActor {
                user_id: Uuid::new_v4(),
            }),
            event_version: 1,
            stored_at: Utc::now(),
        };

        assert!(matches(&filter, &event, &ctx).await);
    }

    #[tokio::test]
    async fn some_filter_ids_event_in_allowed_set_proceeds() {
        let repo_a = Uuid::new_v4();
        let eval = eval_with_repo_read("dev", repo_a);
        let repos_arc = repos();
        let principal = principal_with_roles(Uuid::new_v4(), &["dev"]);
        let ctx = FilterContext {
            rbac: &eval,
            repositories: &repos_arc,
            owner_principal: &principal,
        };

        let filter = SubscriptionFilter {
            categories: vec![StreamCategory::Artifact],
            event_types: EventTypeFilter::All,
            repositories: RepositoryScope::Some(vec![repo_a]),
            named_predicates: vec![],
        };
        let event = ingested_event(StreamId::artifact(Uuid::new_v4()), repo_a);

        assert!(matches(&filter, &event, &ctx).await);
    }

    #[tokio::test]
    async fn some_filter_ids_event_outside_allowed_set_rejected() {
        let repo_a = Uuid::new_v4();
        let repo_b = Uuid::new_v4();
        let eval = eval_with_repo_read("dev", repo_b);
        let repos_arc = repos();
        let principal = principal_with_roles(Uuid::new_v4(), &["dev"]);
        let ctx = FilterContext {
            rbac: &eval,
            repositories: &repos_arc,
            owner_principal: &principal,
        };

        let filter = SubscriptionFilter {
            categories: vec![StreamCategory::Artifact],
            event_types: EventTypeFilter::All,
            repositories: RepositoryScope::Some(vec![repo_a]),
            named_predicates: vec![],
        };
        // Event is for repo_b, but the filter only allows repo_a.
        let event = ingested_event(StreamId::artifact(Uuid::new_v4()), repo_b);

        assert!(!matches(&filter, &event, &ctx).await);
    }

    #[tokio::test]
    async fn some_filter_ids_event_with_no_repo_rejected() {
        // SubscriptionCreated has no repo association; Some(_) is an
        // explicit per-repo filter that cannot match an event without
        // a repo association.
        let eval = empty_eval();
        let repos_arc = repos();
        let user_id = Uuid::new_v4();
        let principal = principal_with_roles(user_id, &[]);
        let ctx = FilterContext {
            rbac: &eval,
            repositories: &repos_arc,
            owner_principal: &principal,
        };

        let filter = SubscriptionFilter {
            categories: vec![StreamCategory::User],
            event_types: EventTypeFilter::All,
            repositories: RepositoryScope::Some(vec![Uuid::new_v4()]),
            named_predicates: vec![],
        };
        let event = subscription_created_event(user_id);

        assert!(!matches(&filter, &event, &ctx).await);
    }

    #[tokio::test]
    async fn all_scope_event_with_repo_proceeds_to_admin_authz_check() {
        // Admin principal — `admin` short-circuit in user_grants_authorize
        // gives Permission::Admin.
        let eval = empty_eval();
        let repos_arc = repos();
        let principal = principal_with_roles(Uuid::new_v4(), &["admin"]);
        let ctx = FilterContext {
            rbac: &eval,
            repositories: &repos_arc,
            owner_principal: &principal,
        };

        let filter = SubscriptionFilter {
            categories: vec![StreamCategory::Artifact],
            event_types: EventTypeFilter::All,
            repositories: RepositoryScope::All,
            named_predicates: vec![],
        };
        let event = ingested_event(StreamId::artifact(Uuid::new_v4()), Uuid::new_v4());

        assert!(matches(&filter, &event, &ctx).await);
    }

    #[tokio::test]
    async fn all_scope_event_without_repo_skips_authz() {
        // RepositoryScope::All + a NON-privileged (`Artifact`) event
        // without repo association → step 4 skipped → matches even
        // though the principal has no roles. (The `User`-stream
        // `SubscriptionCreated` event is NOT a usable fixture: `User` ∈
        // `ADMIN_CATEGORIES`, so a non-admin owner is gated on
        // that path — see
        // `privileged_category_none_repo_event_not_delivered_to_non_admin_owner`.
        // The no-repo-skip mechanic this test documents holds for
        // non-privileged categories, so the fixture uses one.)
        use hort_domain::events::ArtifactQuarantined;
        let eval = empty_eval();
        let repos_arc = repos();
        let user_id = Uuid::new_v4();
        let principal = principal_with_roles(user_id, &[]);
        let ctx = FilterContext {
            rbac: &eval,
            repositories: &repos_arc,
            owner_principal: &principal,
        };

        let filter = SubscriptionFilter {
            categories: vec![StreamCategory::Artifact],
            event_types: EventTypeFilter::All,
            repositories: RepositoryScope::All,
            named_predicates: vec![],
        };
        let event = PersistedEvent {
            event_id: Uuid::new_v4(),
            stream_id: StreamId::artifact(Uuid::new_v4()),
            stream_position: 0,
            global_position: 1,
            event: DomainEvent::ArtifactQuarantined(ArtifactQuarantined {
                artifact_id: Uuid::new_v4(),
                quarantine_window_start: Utc::now(),
            }),
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(ApiActor {
                user_id: Uuid::new_v4(),
            }),
            event_version: 1,
            stored_at: Utc::now(),
        };

        assert!(matches(&filter, &event, &ctx).await);
    }

    // -- Step 4: live authz -----------------------------------------------

    #[tokio::test]
    async fn rejects_when_owner_lacks_read_on_event_repo() {
        let repo_a = Uuid::new_v4();
        let repo_b = Uuid::new_v4();
        // Owner has Read on repo_a only; event is for repo_b.
        let eval = eval_with_repo_read("dev", repo_a);
        let repos_arc = repos();
        let principal = principal_with_roles(Uuid::new_v4(), &["dev"]);
        let ctx = FilterContext {
            rbac: &eval,
            repositories: &repos_arc,
            owner_principal: &principal,
        };

        let filter = owned_artifact_filter();
        let event = ingested_event(StreamId::artifact(Uuid::new_v4()), repo_b);

        assert!(!matches(&filter, &event, &ctx).await);
    }

    #[tokio::test]
    async fn accepts_when_owner_has_read_on_event_repo() {
        let repo_a = Uuid::new_v4();
        let eval = eval_with_repo_read("dev", repo_a);
        let repos_arc = repos();
        let principal = principal_with_roles(Uuid::new_v4(), &["dev"]);
        let ctx = FilterContext {
            rbac: &eval,
            repositories: &repos_arc,
            owner_principal: &principal,
        };

        let filter = owned_artifact_filter();
        let event = ingested_event(StreamId::artifact(Uuid::new_v4()), repo_a);

        assert!(matches(&filter, &event, &ctx).await);
    }

    #[tokio::test]
    async fn all_scope_rejects_when_owner_not_admin() {
        // RepositoryScope::All + event with repo association requires
        // global Permission::Admin. A `dev`-role principal with only
        // Read does NOT satisfy Admin.
        let repo_a = Uuid::new_v4();
        let eval = eval_with_repo_read("dev", repo_a);
        let repos_arc = repos();
        let principal = principal_with_roles(Uuid::new_v4(), &["dev"]);
        let ctx = FilterContext {
            rbac: &eval,
            repositories: &repos_arc,
            owner_principal: &principal,
        };

        let filter = SubscriptionFilter {
            categories: vec![StreamCategory::Artifact],
            event_types: EventTypeFilter::All,
            repositories: RepositoryScope::All,
            named_predicates: vec![],
        };
        let event = ingested_event(StreamId::artifact(Uuid::new_v4()), repo_a);

        assert!(!matches(&filter, &event, &ctx).await);
    }

    #[tokio::test]
    async fn all_scope_accepts_when_owner_is_admin() {
        // Admin role short-circuits to true for every Permission/repo,
        // including the Admin check used for RepositoryScope::All.
        let eval = empty_eval();
        let repos_arc = repos();
        let principal = principal_with_roles(Uuid::new_v4(), &["admin"]);
        let ctx = FilterContext {
            rbac: &eval,
            repositories: &repos_arc,
            owner_principal: &principal,
        };

        let filter = SubscriptionFilter {
            categories: vec![StreamCategory::Artifact],
            event_types: EventTypeFilter::All,
            repositories: RepositoryScope::All,
            named_predicates: vec![],
        };
        let event = ingested_event(StreamId::artifact(Uuid::new_v4()), Uuid::new_v4());

        assert!(matches(&filter, &event, &ctx).await);
    }

    #[tokio::test]
    async fn live_authz_uses_current_grants_not_stored_snapshot() {
        // The same `filter` + same `event` + same `principal` evaluated
        // against two different evaluator snapshots produces different
        // decisions. The dispatcher (Item 6b) reloads `rbac.load()`
        // between batches, so revoking a grant takes effect within the
        // auth cache TTL — this test documents that property.
        let repo_a = Uuid::new_v4();
        let principal = principal_with_roles(Uuid::new_v4(), &["dev"]);
        let repos_arc = repos();

        let filter = owned_artifact_filter();
        let event = ingested_event(StreamId::artifact(Uuid::new_v4()), repo_a);

        // Snapshot 1: owner has Read on repo_a — matches.
        let eval_granted = eval_with_repo_read("dev", repo_a);
        let ctx_granted = FilterContext {
            rbac: &eval_granted,
            repositories: &repos_arc,
            owner_principal: &principal,
        };
        assert!(matches(&filter, &event, &ctx_granted).await);

        // Snapshot 2: same role, no grants on repo_a — does not match.
        let eval_revoked = empty_eval();
        let ctx_revoked = FilterContext {
            rbac: &eval_revoked,
            repositories: &repos_arc,
            owner_principal: &principal,
        };
        assert!(!matches(&filter, &event, &ctx_revoked).await);
    }

    // -- Step 5: named predicates -----------------------------------------

    #[tokio::test]
    async fn empty_named_predicates_vec_short_circuits_true() {
        // Explicit assertion: `named_predicates: vec![]` does not flip
        // the outcome from a step-4-pass. v1 ships zero variants so
        // this is the only reachable state.
        let repo_a = Uuid::new_v4();
        let eval = eval_with_repo_read("dev", repo_a);
        let repos_arc = repos();
        let principal = principal_with_roles(Uuid::new_v4(), &["dev"]);
        let ctx = FilterContext {
            rbac: &eval,
            repositories: &repos_arc,
            owner_principal: &principal,
        };

        let filter = SubscriptionFilter {
            categories: vec![StreamCategory::Artifact],
            event_types: EventTypeFilter::All,
            repositories: RepositoryScope::OwnedByActor,
            // Empty — the v1 contract.
            named_predicates: vec![],
        };
        let event = ingested_event(StreamId::artifact(Uuid::new_v4()), repo_a);

        assert!(matches(&filter, &event, &ctx).await);
    }

    #[tokio::test]
    async fn named_predicate_evaluation_is_compile_time_exhaustive() {
        // v1 `NamedPredicate` is `enum NamedPredicate {}` — uninhabited.
        // We cannot construct a value to exercise the loop body; the
        // empty `match *predicate {}` inside `evaluate_named_predicate`
        // is checked at compile time. This test exists to document the
        // contract: if a v1.x variant ever lands, this assertion (and
        // a matching positive/negative pair) must be updated.
        //
        // No runtime work — the assertion is "the previous test still
        // passes with an empty vec". Kept as a documentation anchor.
        let v: Vec<NamedPredicate> = vec![];
        assert!(v.is_empty());
    }

    // -- Cross-cutting ----------------------------------------------------

    #[tokio::test]
    async fn user_lifecycle_event_gated_by_admin_for_non_admin_owner_delivered_for_admin() {
        // SubscriptionCreated on the User stream with no repository
        // association. Filter selects `User` (∈ `ADMIN_CATEGORIES`) +
        // `All` + `OwnedByActor`. An unconditional no-repo skip at
        // step 4 would deliver this to ANY owner —
        // exactly the leak the gate closes (a non-admin streaming the
        // instance's user-lifecycle history off-box). The
        // privileged-category re-check gates it on live owner
        // `Permission::Admin`:
        //   - non-admin owner (empty principal) → NOT delivered
        //   - admin owner → delivered (no regression for legitimate
        //     admin subscriptions)
        let repos_arc = repos();
        let user_id = Uuid::new_v4();
        let filter = SubscriptionFilter {
            categories: vec![StreamCategory::User],
            event_types: EventTypeFilter::All,
            repositories: RepositoryScope::OwnedByActor,
            named_predicates: vec![],
        };
        let event = subscription_created_event(user_id);

        // Non-admin owner — privileged-category event blocked.
        let eval = empty_eval();
        let non_admin = principal_with_roles(user_id, &[]);
        let ctx_non_admin = FilterContext {
            rbac: &eval,
            repositories: &repos_arc,
            owner_principal: &non_admin,
        };
        assert!(
            !matches(&filter, &event, &ctx_non_admin).await,
            "non-admin owner must NOT receive User-category lifecycle \
             events (dispatch-time privileged-category gate)"
        );

        // Admin owner — legitimate admin subscription still delivers.
        let admin = principal_with_roles(user_id, &["admin"]);
        let ctx_admin = FilterContext {
            rbac: &eval,
            repositories: &repos_arc,
            owner_principal: &admin,
        };
        assert!(
            matches(&filter, &event, &ctx_admin).await,
            "admin owner must still receive User-category lifecycle events"
        );
    }

    // -- Dispatch-time privileged-category gate ----------------------------

    /// F-37 gate mechanic (filter leg). A subscription whose snapshot was
    /// elevated to `["admin"]` via the §5.5 PATCH-via-PAT path but whose
    /// owner is **not currently admin** synthesises (in
    /// `dispatcher::synthesise_principal`) an owner principal with the
    /// stale `"admin"` neutralised — i.e. `claims = []`. A privileged
    /// `Authorization`-category event (`repository_id = None`) MUST NOT be
    /// delivered: step 4's `(_, None)` arm re-checks `Permission::Admin`
    /// against the synthesised owner for `ADMIN_CATEGORIES` events, and a
    /// non-admin owner with no admin grant fails it. Pre-fix the
    /// unconditional `(_, None) => true` delivered it → this is the
    /// canonical red.
    #[tokio::test]
    async fn privileged_category_none_repo_event_not_delivered_to_non_admin_owner() {
        let eval = empty_eval();
        let repos_arc = repos();
        // Non-admin owner principal: no `"admin"` claim (stale snapshot
        // `"admin"` is stripped at synthesis — see dispatcher.rs).
        let principal = principal_with_roles(Uuid::new_v4(), &["developer"]);
        let ctx = FilterContext {
            rbac: &eval,
            repositories: &repos_arc,
            owner_principal: &principal,
        };

        let filter = authorization_owned_filter();
        let event = claim_mapping_applied_event();

        assert!(
            !matches(&filter, &event, &ctx).await,
            "privileged-category None-repo event must NOT reach a \
             non-admin owner (F-3 dispatch-leg / F-37)"
        );
    }

    /// No-regression: a privileged-category `None`-repo event IS
    /// delivered when the synthesised owner principal currently
    /// satisfies `Permission::Admin` (live admin owner — the legitimate
    /// admin-subscription path).
    #[tokio::test]
    async fn privileged_category_none_repo_event_delivered_to_admin_owner() {
        let eval = empty_eval();
        let repos_arc = repos();
        // Admin owner — `add_admin_claim_if_admin` produced `["admin"]`
        // from the live `is_admin=true` bit.
        let principal = principal_with_roles(Uuid::new_v4(), &["admin"]);
        let ctx = FilterContext {
            rbac: &eval,
            repositories: &repos_arc,
            owner_principal: &principal,
        };

        let filter = authorization_owned_filter();
        let event = claim_mapping_applied_event();

        assert!(
            matches(&filter, &event, &ctx).await,
            "admin owner must still receive privileged-category events \
             (no regression for legitimate admin subscriptions)"
        );
    }

    /// Live-authz parity with the read path: an owner who held admin at
    /// create but had it revoked (synthesised principal now carries no
    /// `"admin"`, no admin grant) stops receiving privileged-category
    /// events on the next dispatch — exactly the read-path behaviour.
    #[tokio::test]
    async fn privileged_category_delivery_stops_when_owner_admin_revoked() {
        let repos_arc = repos();
        let principal = principal_with_roles(Uuid::new_v4(), &["developer"]);

        let filter = authorization_owned_filter();
        let event = claim_mapping_applied_event();

        // Snapshot 1: owner still admin → delivered.
        let admin_principal = principal_with_roles(principal.user_id, &["admin"]);
        let eval = empty_eval();
        let ctx_admin = FilterContext {
            rbac: &eval,
            repositories: &repos_arc,
            owner_principal: &admin_principal,
        };
        assert!(matches(&filter, &event, &ctx_admin).await);

        // Snapshot 2: admin revoked (synthesised principal re-derives the
        // `"admin"` claim from the now-false live bit → absent) → the
        // very next dispatch stops delivering.
        let eval2 = empty_eval();
        let ctx_revoked = FilterContext {
            rbac: &eval2,
            repositories: &repos_arc,
            owner_principal: &principal,
        };
        assert!(
            !matches(&filter, &event, &ctx_revoked).await,
            "privileged delivery must stop once owner admin is revoked \
             (live-authz parity with the read path)"
        );
    }

    // -- Authorization-model events gate on event TYPE,
    //    not stream CATEGORY. The locus: privileged
    //    event TYPES that ride a NON-admin stream category because they are
    //    repo-associated, so neither the `(_, None)` category re-check nor
    //    the per-repo `Read` check gates them.

    /// Build a repo-scoped `PermissionGrantApplied` event on the
    /// `StreamCategory::Repository` stream — a privileged-type leak shape. The
    /// category is non-admin and the payload carries `Some(repo)`, so
    /// pre-fix a `Read`-on-`repo` owner cleared the `(_, Some(repo))` arm
    /// and received the grant topology.
    fn repo_scoped_permission_grant_event(repo_id: Uuid) -> PersistedEvent {
        use hort_domain::entities::rbac::Permission as DomainPermission;
        use hort_domain::events::{GrantSubjectRecord, PermissionGrantApplied};
        PersistedEvent {
            event_id: Uuid::new_v4(),
            stream_id: StreamId::repository(repo_id),
            stream_position: 0,
            global_position: 1,
            event: DomainEvent::PermissionGrantApplied(PermissionGrantApplied {
                grant_id: Uuid::new_v4(),
                subject: GrantSubjectRecord::Claims {
                    required: vec!["developer".into()],
                },
                permission: DomainPermission::Read,
                repository_id: Some(repo_id),
            }),
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(ApiActor {
                user_id: Uuid::new_v4(),
            }),
            event_version: 1,
            stored_at: Utc::now(),
        }
    }

    /// Build a repo-scoped `RepositoryUpstreamMappingChanged` event on the
    /// `StreamCategory::Repository` stream — the other privileged-type
    /// leak shape.
    fn repo_scoped_upstream_mapping_event(repo_id: Uuid) -> PersistedEvent {
        use hort_domain::events::{RepositoryUpstreamMappingChanged, UpstreamMappingChange};
        PersistedEvent {
            event_id: Uuid::new_v4(),
            stream_id: StreamId::repository(repo_id),
            stream_position: 0,
            global_position: 1,
            event: DomainEvent::RepositoryUpstreamMappingChanged(
                RepositoryUpstreamMappingChanged {
                    mapping_id: Uuid::new_v4(),
                    repository_id: repo_id,
                    change: UpstreamMappingChange::Updated,
                    previous_secret_ref: Some("env_var:OLD".into()),
                    new_secret_ref: Some("env_var:NEW".into()),
                    previous_url: Some("https://registry-1.docker.io".into()),
                    new_url: Some("https://registry-1.docker.io".into()),
                },
            ),
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(ApiActor {
                user_id: Uuid::new_v4(),
            }),
            event_version: 1,
            stored_at: Utc::now(),
        }
    }

    /// Build an `ArtifactDownloaded` event on the `DownloadAudit` stream —
    /// the privileged-audit leak shape. It is repo-associated
    /// (`Some(repo)`), so the None-repo admin re-check never sees it.
    fn download_audit_event(repo_id: Uuid) -> PersistedEvent {
        use hort_domain::events::{ArtifactDownloaded, DownloadActor};
        let date = Utc::now().date_naive();
        PersistedEvent {
            event_id: Uuid::new_v4(),
            stream_id: StreamId::download_audit(repo_id, date),
            stream_position: 0,
            global_position: 1,
            event: DomainEvent::ArtifactDownloaded(ArtifactDownloaded {
                artifact_id: Uuid::new_v4(),
                repository_id: repo_id,
                content_hash: "a".repeat(64).parse::<ContentHash>().unwrap(),
                actor: DownloadActor::Anonymous,
                occurred_at: Utc::now(),
            }),
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(ApiActor {
                user_id: Uuid::new_v4(),
            }),
            event_version: 1,
            stored_at: Utc::now(),
        }
    }

    /// `OwnedByActor` filter accepting any `Repository`-category event.
    fn owned_repository_filter() -> SubscriptionFilter {
        SubscriptionFilter {
            categories: vec![StreamCategory::Repository],
            event_types: EventTypeFilter::All,
            repositories: RepositoryScope::OwnedByActor,
            named_predicates: vec![],
        }
    }

    /// `OwnedByActor` filter accepting any `DownloadAudit`-category event.
    fn owned_download_audit_filter() -> SubscriptionFilter {
        SubscriptionFilter {
            categories: vec![StreamCategory::DownloadAudit],
            event_types: EventTypeFilter::All,
            repositories: RepositoryScope::OwnedByActor,
            named_predicates: vec![],
        }
    }

    /// F-39: a `Read`-only owner on `repo` must NOT receive a repo-scoped
    /// `PermissionGrantApplied` even though the carrying `Repository`
    /// category is non-admin and the owner holds `Read` on the repo. Pre-fix
    /// the `(_, Some(repo))` arm's `Read` check passed → leak.
    #[tokio::test]
    async fn read_only_owner_denied_repo_scoped_permission_grant() {
        let repo_id = Uuid::new_v4();
        let eval = eval_with_repo_read("dev", repo_id);
        let repos_arc = repos();
        let principal = principal_with_roles(Uuid::new_v4(), &["dev"]);
        let ctx = FilterContext {
            rbac: &eval,
            repositories: &repos_arc,
            owner_principal: &principal,
        };

        let filter = owned_repository_filter();
        let event = repo_scoped_permission_grant_event(repo_id);

        assert!(
            !matches(&filter, &event, &ctx).await,
            "Read-only owner must NOT receive repo-scoped grant topology (F-39)"
        );
    }

    /// F-39: same for `RepositoryUpstreamMappingChanged`.
    #[tokio::test]
    async fn read_only_owner_denied_repo_scoped_upstream_mapping_change() {
        let repo_id = Uuid::new_v4();
        let eval = eval_with_repo_read("dev", repo_id);
        let repos_arc = repos();
        let principal = principal_with_roles(Uuid::new_v4(), &["dev"]);
        let ctx = FilterContext {
            rbac: &eval,
            repositories: &repos_arc,
            owner_principal: &principal,
        };

        let filter = owned_repository_filter();
        let event = repo_scoped_upstream_mapping_event(repo_id);

        assert!(
            !matches(&filter, &event, &ctx).await,
            "Read-only owner must NOT receive upstream-mapping topology (F-39)"
        );
    }

    /// F-37: a `Read`-only owner on `repo` must NOT receive an
    /// `ArtifactDownloaded` download-audit fact for `repo` (it is
    /// repo-associated, escaping the None-repo re-check).
    #[tokio::test]
    async fn read_only_owner_denied_download_audit_event() {
        let repo_id = Uuid::new_v4();
        let eval = eval_with_repo_read("dev", repo_id);
        let repos_arc = repos();
        let principal = principal_with_roles(Uuid::new_v4(), &["dev"]);
        let ctx = FilterContext {
            rbac: &eval,
            repositories: &repos_arc,
            owner_principal: &principal,
        };

        let filter = owned_download_audit_filter();
        let event = download_audit_event(repo_id);

        assert!(
            !matches(&filter, &event, &ctx).await,
            "Read-only owner must NOT receive download-audit telemetry (F-37)"
        );
    }

    /// F-39 no-regression: an admin owner IS delivered the repo-scoped
    /// `PermissionGrantApplied` (legitimate admin subscription).
    #[tokio::test]
    async fn admin_owner_receives_repo_scoped_permission_grant() {
        let repo_id = Uuid::new_v4();
        let eval = empty_eval();
        let repos_arc = repos();
        let principal = principal_with_roles(Uuid::new_v4(), &["admin"]);
        let ctx = FilterContext {
            rbac: &eval,
            repositories: &repos_arc,
            owner_principal: &principal,
        };

        let filter = owned_repository_filter();
        let event = repo_scoped_permission_grant_event(repo_id);

        assert!(
            matches(&filter, &event, &ctx).await,
            "admin owner must still receive repo-scoped grant events (no regression)"
        );
    }

    /// F-37 no-regression: an admin owner IS delivered the
    /// `ArtifactDownloaded` download-audit fact.
    #[tokio::test]
    async fn admin_owner_receives_download_audit_event() {
        let repo_id = Uuid::new_v4();
        let eval = empty_eval();
        let repos_arc = repos();
        let principal = principal_with_roles(Uuid::new_v4(), &["admin"]);
        let ctx = FilterContext {
            rbac: &eval,
            repositories: &repos_arc,
            owner_principal: &principal,
        };

        let filter = owned_download_audit_filter();
        let event = download_audit_event(repo_id);

        assert!(
            matches(&filter, &event, &ctx).await,
            "admin owner must still receive download-audit events (no regression)"
        );
    }

    /// No-regression: an ordinary repo-scoped lifecycle event
    /// (`ArtifactIngested`) on the same non-admin `Repository`-category
    /// path STILL flows to a `Read`-only owner — the type gate is precise
    /// (only auth-model-mutation / privileged-audit types are blocked).
    #[tokio::test]
    async fn read_only_owner_still_receives_ordinary_repository_event() {
        let repo_id = Uuid::new_v4();
        let eval = eval_with_repo_read("dev", repo_id);
        let repos_arc = repos();
        let principal = principal_with_roles(Uuid::new_v4(), &["dev"]);
        let ctx = FilterContext {
            rbac: &eval,
            repositories: &repos_arc,
            owner_principal: &principal,
        };

        // ArtifactIngested is neither auth-model-mutation nor
        // privileged-audit; on the Repository stream + Read scope it flows.
        let filter = owned_repository_filter();
        let event = ingested_event(StreamId::repository(repo_id), repo_id);

        assert!(
            matches(&filter, &event, &ctx).await,
            "ordinary repo events must still flow to a Read owner (no regression)"
        );
    }

    /// No-regression for the non-privileged `None`-repo edge: an
    /// `Artifact`-category event with no repository association
    /// (`StreamCategory::Artifact` ∉ `ADMIN_CATEGORIES`) keeps the
    /// pre-fix `(_, None) => true` behaviour — delivered without an
    /// admin re-check, even to a non-admin owner with no claims.
    #[tokio::test]
    async fn non_privileged_category_none_repo_event_unchanged_for_non_admin() {
        use hort_domain::events::ArtifactQuarantined;
        let eval = empty_eval();
        let repos_arc = repos();
        let principal = principal_with_roles(Uuid::new_v4(), &[]);
        let ctx = FilterContext {
            rbac: &eval,
            repositories: &repos_arc,
            owner_principal: &principal,
        };

        // ArtifactQuarantined on the Artifact stream — a
        // non-`ADMIN_CATEGORIES` category whose `repository_id`
        // extractor returns `None`.
        let event = PersistedEvent {
            event_id: Uuid::new_v4(),
            stream_id: StreamId::artifact(Uuid::new_v4()),
            stream_position: 0,
            global_position: 1,
            event: DomainEvent::ArtifactQuarantined(ArtifactQuarantined {
                artifact_id: Uuid::new_v4(),
                quarantine_window_start: Utc::now(),
            }),
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(ApiActor {
                user_id: Uuid::new_v4(),
            }),
            event_version: 1,
            stored_at: Utc::now(),
        };

        let filter = SubscriptionFilter {
            categories: vec![StreamCategory::Artifact],
            event_types: EventTypeFilter::All,
            repositories: RepositoryScope::OwnedByActor,
            named_predicates: vec![],
        };

        assert!(
            matches(&filter, &event, &ctx).await,
            "non-privileged None-repo events keep the existing pass-through"
        );
    }
}
