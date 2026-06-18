//! `SubscriptionUseCase`.
//!
//! CRUD orchestration for subscription rows plus the lifecycle audit
//! events on the owner's user stream. See
//! `docs/architecture/explanation/event-notifications.md` for:
//! - validation (name / description / NATS subject / webhook URL);
//! - the authz table + token-cap interaction at creation;
//! - the invariants: closed-enum filter, high-volume exclusion,
//!   subscription owner is User (cap captured at creation as explicit
//!   `RepositoryScope::Some(ids)` list), webhook SSRF at issuance.
//!
//! # Layering
//!
//! - All outbound I/O flows through `Arc<dyn _>` port traits — no adapter
//!   imports.
//! - Validation helpers live in `hort_domain::entities::subscription` (pure
//!   Rust, zero I/O).
//! - The `WebhookTargetGuard` port encapsulates the single-shot DNS-
//!   resolution + `is_routable` check (adapter-implemented); the
//!   use case never imports `hort_net_egress` directly.
//!
//! # Tracing
//!
//! Every public method carries `#[tracing::instrument(skip(self, ...))]`
//! — **NO `#[instrument(err)]`** per CLAUDE.md observability rule:
//! denials are audit signals (`tracing::info!`), not errors. SSRF
//! denials log the URL host but NEVER the resolved IPs (topology
//! disclosure).

use std::sync::Arc;

use arc_swap::ArcSwap;
use chrono::Utc;
use uuid::Uuid;

use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::rbac::Permission;
use hort_domain::entities::subscription::{
    validate_description, validate_name, validate_nats_subject, validate_webhook_url,
    DisableReason, EventTypeFilter, RepositoryScope, SsrfBlockReason, Subscription,
    SubscriptionDenialReason, SubscriptionFailure, SubscriptionFilter, SubscriptionId,
    SubscriptionState, SubscriptionTarget,
};
use hort_domain::error::DomainError;
use hort_domain::events::{
    system_actor, ApiActor, DomainEvent, FilterSummary, RepositoryScopeKind, StreamCategory,
    StreamId, SubscriptionCreated, SubscriptionCreationDenied, SubscriptionDeleted,
    SubscriptionDisabled, SubscriptionPaused, SubscriptionResumed, SubscriptionUpdated,
    TargetKindWire,
};
use hort_domain::ports::event_store::{AppendEvents, EventStore, EventToAppend};
use hort_domain::ports::repository_repository::RepositoryRepository;
use hort_domain::ports::subscription_repository::SubscriptionRepository;
use hort_domain::ports::user_repository::UserRepository;
use hort_domain::ports::webhook_target_guard::WebhookTargetGuard;
use hort_domain::types::{Page, PageRequest};

use crate::error::AppError;
use crate::event_store_publisher::EventStorePublisher;
use crate::metrics::{emit_ssrf_block, ssrf_reason_label};
use crate::rbac::RbacEvaluator;
use crate::use_cases::read_expected_version;

// ---------------------------------------------------------------------------
// SubscriptionUseCaseConfig
// ---------------------------------------------------------------------------

/// Composition-root configuration for the use case.
///
/// Both flags are operator-set via env vars (`HORT_WEBHOOK_ALLOW_PLAINTEXT`,
/// `HORT_WEBHOOK_ALLOW_NONROUTABLE_TARGETS`) in the composition
/// root, which is also responsible for setting
/// `hort_unsafe_config_active{kind=...}` gauges at boot when either is on.
///
/// **Intentionally not `Deserialize`.** Composition is the only writer;
/// accepting wire input would let an attacker forge a config that disables
/// the SSRF check on a per-request basis. Plain `Default` derives the
/// "secure by default" zero value (both flags off).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SubscriptionUseCaseConfig {
    /// `HORT_WEBHOOK_ALLOW_PLAINTEXT` — when `true`, `http://` URLs are
    /// accepted at issuance. Default `false`.
    pub allow_plaintext_webhooks: bool,
    /// `HORT_WEBHOOK_ALLOW_NONROUTABLE_TARGETS` — when `true`, the
    /// [`WebhookTargetGuard`] check is skipped entirely (BOTH the host
    /// check AND the metric emission). Default `false`.
    pub allow_nonroutable_webhook_targets: bool,
}

// ---------------------------------------------------------------------------
// CreateSubscriptionRequest / UpdateSubscriptionRequest
// ---------------------------------------------------------------------------

/// Use-case-facing request struct for `SubscriptionUseCase::create`.
///
/// The HTTP layer has its own DTO that deserialises wire
/// input; this struct is the validated domain shape and is constructed by
/// the handler after wire-side parsing. Deliberately **not**
/// `Deserialize` — see [`SubscriptionUseCaseConfig`] for the rationale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSubscriptionRequest {
    pub name: String,
    pub description: Option<String>,
    pub target: SubscriptionTarget,
    pub filter: SubscriptionFilter,
}

/// Use-case-facing request struct for `SubscriptionUseCase::update`.
///
/// Outer `Option` semantics: `None` means "leave the field unchanged".
/// For `description`, the inner `Option` means "set to `NULL`" vs
/// "set to `Some(text)`".
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UpdateSubscriptionRequest {
    pub name: Option<String>,
    pub description: Option<Option<String>>,
    pub target: Option<SubscriptionTarget>,
    pub filter: Option<SubscriptionFilter>,
    pub state: Option<SubscriptionState>,
}

// ---------------------------------------------------------------------------
// SubscriptionError
// ---------------------------------------------------------------------------

/// Typed errors surfaced by [`SubscriptionUseCase`]. Mapped to HTTP
/// envelopes by the handler crate.
///
/// **`InvalidWebhookUrl` is intentionally absent** from this enum — the
/// HTTP layer parses the URL into [`url::Url`] before constructing
/// [`CreateSubscriptionRequest`], so the use case cannot reach an
/// unparseable URL. The corresponding
/// [`SubscriptionDenialReason::InvalidWebhookUrl`] variant exists in the
/// domain for HTTP-layer rejection paths to emit; the use case itself
/// never produces it.
#[derive(Debug, thiserror::Error)]
pub enum SubscriptionError {
    /// 400 — filter requested high-volume event type that is excluded
    /// from subscriptions.
    #[error("filter requested unsupported event type: {0:?}")]
    UnsupportedEventType(hort_domain::entities::subscription::EventTypeKind),

    /// 403 — caller lacks `Read` on at least one repo in
    /// `RepositoryScope::Some(...)`. `unauthorized` lists the offending
    /// ids; non-existent repos collapse into this list so the response
    /// never leaks existence-vs-permission distinction.
    #[error("caller is not authorized to read all listed repositories")]
    RepoNotAuthorised { unauthorized: Vec<Uuid> },

    /// 403 — `RepositoryScope::All` requested by a non-admin caller.
    #[error("admin scope requires Permission::Admin")]
    AdminScopeRequiresAdmin,

    /// 403 — `RepositoryScope::All` requested via a repo-capped token.
    #[error("admin scope cannot be created via a repo-capped token")]
    AdminScopeRequiresUncappedToken,

    /// 400 — `RepositoryScope::OwnedByActor` via a repo-capped token.
    /// `cap_ids` is the cap snapshot so the response can instruct the
    /// caller to re-submit with `Some(cap_ids)`.
    #[error("repository scope must be explicit when authenticated via a repo-capped token")]
    RepoScopeMustBeExplicit { cap_ids: Vec<Uuid> },

    /// 403 — `Some(filter_ids)` not a subset of `token_cap.repository_ids`.
    #[error("repository scope exceeds token cap")]
    RepoScopeExceedsTokenCap { offending: Vec<Uuid> },

    /// 400 — webhook URL is `http://` and
    /// `allow_plaintext_webhooks = false`.
    #[error("plaintext webhook URLs are disabled by composition-root config")]
    PlaintextWebhookDisallowed,

    /// 400 — [`WebhookTargetGuard`] check failed.
    #[error("webhook target is not routable: {ssrf_block_reason:?}")]
    WebhookTargetNotRoutable { ssrf_block_reason: SsrfBlockReason },

    /// 400 — NATS subject grammar / wildcard rejection.
    #[error("invalid NATS subject")]
    InvalidNatsSubject,

    /// 409 — `(owner_user_id, name)` collision.
    #[error("duplicate subscription name")]
    DuplicateName,

    /// 400 — name length / description length / scheme-mismatch from
    /// `validate_webhook_url` (the non-plaintext branch — e.g. `ftp://`).
    #[error("validation error: {0}")]
    Validation(String),

    /// 404 — subscription id unknown.
    #[error("subscription not found")]
    SubscriptionNotFound,

    /// 403 — caller is neither owner nor admin.
    #[error("not authorized")]
    NotAuthorized,

    /// 5xx infrastructure passthrough.
    #[error(transparent)]
    Infrastructure(#[from] DomainError),
}

// ---------------------------------------------------------------------------
// SubscriptionUseCase
// ---------------------------------------------------------------------------

/// Application orchestrator for subscription CRUD + lifecycle events.
pub struct SubscriptionUseCase {
    subscriptions: Arc<dyn SubscriptionRepository>,
    /// Reserved for future expiry-warning / owner-deactivation
    /// flows. The v1 use case does not call
    /// `users.find_by_id` from any method, but the port is in scope so
    /// follow-on items can land without a constructor signature change.
    #[allow(dead_code)]
    users: Arc<dyn UserRepository>,
    events: Arc<EventStorePublisher>,
    /// Live RBAC snapshot — same `arc-swap` pattern
    /// `ApiTokenUseCase` uses. `.load()` once per public-method
    /// invocation so the cap-vs-grants checks walk a single consistent
    /// evaluator even if a swap lands mid-method.
    rbac: Arc<ArcSwap<RbacEvaluator>>,
    repositories: Arc<dyn RepositoryRepository>,
    webhook_guard: Arc<dyn WebhookTargetGuard>,
    config: SubscriptionUseCaseConfig,
}

impl SubscriptionUseCase {
    /// Construct a use case from its six port dependencies + config.
    pub fn new(
        subscriptions: Arc<dyn SubscriptionRepository>,
        users: Arc<dyn UserRepository>,
        events: Arc<EventStorePublisher>,
        rbac: Arc<ArcSwap<RbacEvaluator>>,
        repositories: Arc<dyn RepositoryRepository>,
        webhook_guard: Arc<dyn WebhookTargetGuard>,
        config: SubscriptionUseCaseConfig,
    ) -> Self {
        Self {
            subscriptions,
            users,
            events,
            rbac,
            repositories,
            webhook_guard,
            config,
        }
    }

    // -- create -------------------------------------------------------------

    /// Validate + persist a new subscription, emitting `SubscriptionCreated`
    /// on success or `SubscriptionCreationDenied` on every reject path.
    ///
    /// Order of operations: name/description structural → high-volume event filter
    /// → target-specific validation (incl. SSRF when applicable) →
    /// repository-scope authz under the token-cap matrix → uniqueness
    /// → persist → audit event.
    #[tracing::instrument(skip(self, principal, request))]
    pub async fn create(
        &self,
        principal: &CallerPrincipal,
        request: CreateSubscriptionRequest,
    ) -> Result<Subscription, SubscriptionError> {
        // 1. Structural validation — length checks are not security
        //    rules, so no denial event on these.
        validate_name(&request.name).map_err(domain_to_validation)?;
        validate_description(request.description.as_deref()).map_err(domain_to_validation)?;

        let target_kind = target_kind_wire(&request.target);
        let attempted = compute_filter_summary(&request.filter);

        // 1a. Privileged-category authority gate.
        //     Fail-fast — evaluated BEFORE the high-volume filter, the
        //     SSRF check, and the snapshot capture so a denied
        //     privileged-category request never writes a row and never
        //     reaches the (more expensive) target/SSRF validation. The
        //     acting principal's authority is evaluated LIVE here, never
        //     read from `snapshot_claims`.
        if self.privileged_category_denied(principal, &request.filter) {
            self.emit_denial(
                principal,
                target_kind,
                attempted.clone(),
                SubscriptionDenialReason::PrivilegedCategoryRequiresAdmin,
            )
            .await?;
            tracing::info!(
                actor_user_id = %principal.user_id,
                denial_reason = "privileged_category_requires_admin",
                "subscription create denied"
            );
            return Err(SubscriptionError::NotAuthorized);
        }

        // 2. High-volume event-type rejection.
        if let EventTypeFilter::Some(kinds) = &request.filter.event_types {
            if let Some(hv) = kinds.iter().find(|k| k.is_high_volume()) {
                self.emit_denial(
                    principal,
                    target_kind,
                    attempted.clone(),
                    SubscriptionDenialReason::UnsupportedEventType,
                )
                .await?;
                tracing::info!(
                    actor_user_id = %principal.user_id,
                    denial_reason = "unsupported_event_type",
                    "subscription create denied"
                );
                return Err(SubscriptionError::UnsupportedEventType(*hv));
            }
        }

        // 3. Target-specific validation.
        match &request.target {
            SubscriptionTarget::Webhook { url, .. } => {
                if let Err(e) = validate_webhook_url(url, self.config.allow_plaintext_webhooks) {
                    // `validate_webhook_url` rejects `http://` when
                    // plaintext is disallowed AND any non-http/https
                    // scheme unconditionally. Distinguish by checking
                    // the scheme so the plaintext denial event fires
                    // exactly when the cause was an `http://` URL.
                    if url.scheme() == "http" && !self.config.allow_plaintext_webhooks {
                        self.emit_denial(
                            principal,
                            target_kind,
                            attempted.clone(),
                            SubscriptionDenialReason::PlaintextWebhookDisallowed,
                        )
                        .await?;
                        tracing::info!(
                            actor_user_id = %principal.user_id,
                            webhook_host = url.host_str().unwrap_or("<missing>"),
                            denial_reason = "plaintext_webhook_disallowed",
                            "subscription create denied"
                        );
                        return Err(SubscriptionError::PlaintextWebhookDisallowed);
                    }
                    // Scheme is neither `http` nor `https` — structural
                    // validation failure; no denial event.
                    let _ = e;
                    return Err(SubscriptionError::Validation(format!(
                        "unsupported webhook URL scheme: {}",
                        url.scheme()
                    )));
                }

                // SSRF check — skipped entirely (host check AND metric
                // emission) when the operator-opt-out flag is on.
                if !self.config.allow_nonroutable_webhook_targets {
                    if let Err(reason) = self.webhook_guard.check(url).await {
                        emit_ssrf_block(ssrf_reason_label(reason));
                        self.emit_denial(
                            principal,
                            target_kind,
                            attempted.clone(),
                            SubscriptionDenialReason::WebhookTargetNotRoutable {
                                ssrf_block_reason: reason,
                            },
                        )
                        .await?;
                        tracing::info!(
                            actor_user_id = %principal.user_id,
                            webhook_host = url.host_str().unwrap_or("<missing>"),
                            ssrf_block_reason = ?reason,
                            denial_reason = "webhook_target_not_routable",
                            "subscription create denied"
                        );
                        return Err(SubscriptionError::WebhookTargetNotRoutable {
                            ssrf_block_reason: reason,
                        });
                    }
                }
            }
            SubscriptionTarget::NatsJetStream { subject } => {
                if validate_nats_subject(subject).is_err() {
                    self.emit_denial(
                        principal,
                        target_kind,
                        attempted.clone(),
                        SubscriptionDenialReason::InvalidNatsSubject,
                    )
                    .await?;
                    tracing::info!(
                        actor_user_id = %principal.user_id,
                        denial_reason = "invalid_nats_subject",
                        "subscription create denied"
                    );
                    return Err(SubscriptionError::InvalidNatsSubject);
                }
            }
        }

        // 4. Repository-scope authz under the token-cap matrix.
        //    Take one rbac snapshot so the loop walks a consistent
        //    evaluator (same precedent as `ApiTokenUseCase::issue_inner`).
        let rbac_guard = self.rbac.load();
        let rbac = &**rbac_guard;
        let cap_ids: Option<Vec<Uuid>> = principal
            .token_cap
            .as_ref()
            .and_then(|c| c.repository_ids.clone());
        match (&request.filter.repositories, cap_ids.clone()) {
            // Uncapped session, OwnedByActor — allowed; resolves
            // dynamically against live grants at delivery time.
            (RepositoryScope::OwnedByActor, None) => {}

            // Repo-capped token, OwnedByActor — must capture cap
            // explicitly as `Some(cap_ids)`.
            (RepositoryScope::OwnedByActor, Some(cap_ids)) => {
                self.emit_denial(
                    principal,
                    target_kind,
                    attempted.clone(),
                    SubscriptionDenialReason::RepoScopeMustBeExplicit,
                )
                .await?;
                tracing::info!(
                    actor_user_id = %principal.user_id,
                    denial_reason = "repo_scope_must_be_explicit",
                    "subscription create denied"
                );
                return Err(SubscriptionError::RepoScopeMustBeExplicit { cap_ids });
            }

            // Some(filter_ids), uncapped — check each id grants Read +
            // exists. Non-existent ids collapse into `unauthorized` so
            // the response never leaks existence-vs-permission.
            (RepositoryScope::Some(filter_ids), None) => {
                let unauthorized = self
                    .scan_unauthorized_or_missing(principal, filter_ids, rbac)
                    .await;
                if !unauthorized.is_empty() {
                    self.emit_denial(
                        principal,
                        target_kind,
                        attempted.clone(),
                        SubscriptionDenialReason::RepoNotAuthorised,
                    )
                    .await?;
                    tracing::info!(
                        actor_user_id = %principal.user_id,
                        unauthorized_count = unauthorized.len(),
                        denial_reason = "repo_not_authorised",
                        "subscription create denied"
                    );
                    return Err(SubscriptionError::RepoNotAuthorised { unauthorized });
                }
            }

            // Some(filter_ids), capped — cap check first (cap is the
            // strict outer bound), then grants check.
            (RepositoryScope::Some(filter_ids), Some(cap_ids)) => {
                let offending: Vec<Uuid> = filter_ids
                    .iter()
                    .filter(|id| !cap_ids.contains(id))
                    .copied()
                    .collect();
                if !offending.is_empty() {
                    self.emit_denial(
                        principal,
                        target_kind,
                        attempted.clone(),
                        SubscriptionDenialReason::RepoScopeExceedsTokenCap,
                    )
                    .await?;
                    tracing::info!(
                        actor_user_id = %principal.user_id,
                        offending_count = offending.len(),
                        denial_reason = "repo_scope_exceeds_token_cap",
                        "subscription create denied"
                    );
                    return Err(SubscriptionError::RepoScopeExceedsTokenCap { offending });
                }
                let unauthorized = self
                    .scan_unauthorized_or_missing(principal, filter_ids, rbac)
                    .await;
                if !unauthorized.is_empty() {
                    self.emit_denial(
                        principal,
                        target_kind,
                        attempted.clone(),
                        SubscriptionDenialReason::RepoNotAuthorised,
                    )
                    .await?;
                    tracing::info!(
                        actor_user_id = %principal.user_id,
                        unauthorized_count = unauthorized.len(),
                        denial_reason = "repo_not_authorised",
                        "subscription create denied"
                    );
                    return Err(SubscriptionError::RepoNotAuthorised { unauthorized });
                }
            }

            // All scope, uncapped — global Admin required.
            (RepositoryScope::All, None) => {
                if !rbac.authorize(principal, Permission::Admin, None) {
                    self.emit_denial(
                        principal,
                        target_kind,
                        attempted.clone(),
                        SubscriptionDenialReason::AdminScopeRequiresAdmin,
                    )
                    .await?;
                    tracing::info!(
                        actor_user_id = %principal.user_id,
                        denial_reason = "admin_scope_requires_admin",
                        "subscription create denied"
                    );
                    return Err(SubscriptionError::AdminScopeRequiresAdmin);
                }
            }

            // All scope, capped — unconditionally rejected.
            (RepositoryScope::All, Some(_)) => {
                self.emit_denial(
                    principal,
                    target_kind,
                    attempted.clone(),
                    SubscriptionDenialReason::AdminScopeRequiresUncappedToken,
                )
                .await?;
                tracing::info!(
                    actor_user_id = %principal.user_id,
                    denial_reason = "admin_scope_requires_uncapped_token",
                    "subscription create denied"
                );
                return Err(SubscriptionError::AdminScopeRequiresUncappedToken);
            }
        }
        // Drop the rbac snapshot before any await on subscriptions —
        // arc-swap guards are `!Send` (they borrow the swap pointer).
        drop(rbac_guard);

        // 5. Uniqueness pre-check.
        if self
            .subscriptions
            .find_by_name(principal.user_id, &request.name)
            .await?
            .is_some()
        {
            self.emit_denial(
                principal,
                target_kind,
                attempted.clone(),
                SubscriptionDenialReason::DuplicateName,
            )
            .await?;
            tracing::info!(
                actor_user_id = %principal.user_id,
                denial_reason = "duplicate_name",
                "subscription create denied"
            );
            return Err(SubscriptionError::DuplicateName);
        }

        // 6. Compose entity.
        let now = Utc::now();
        let sub = Subscription {
            id: SubscriptionId(Uuid::new_v4()),
            owner_user_id: principal.user_id,
            // TODO: plumb token_id through
            // CallerPrincipal so audit attribution carries the issuer.
            created_by_token_id: None,
            name: request.name.clone(),
            description: request.description.clone(),
            target: request.target.clone(),
            filter: request.filter.clone(),
            // Capture the acting principal's resolved
            // claims as the subscription's authority floor. The
            // privileged-category gate above already ran (fail-fast,
            // before this point). The dispatcher re-derives authority
            // against live owner state at delivery, so this
            // snapshot is the floor, never the sole control.
            snapshot_claims: principal.claims.clone(),
            state: SubscriptionState::Active,
            last_delivered_position: None,
            last_failure: None,
            created_at: now,
        };

        // 7. Persist — adapter unique-constraint race surfaces as
        //    Conflict; map back to DuplicateName so the wire response is
        //    the same shape regardless of which check caught the dup.
        if let Err(e) = self.subscriptions.create(&sub).await {
            if matches!(&e, DomainError::Conflict(msg) if msg.contains("subscription")) {
                self.emit_denial(
                    principal,
                    target_kind,
                    attempted.clone(),
                    SubscriptionDenialReason::DuplicateName,
                )
                .await?;
                tracing::info!(
                    actor_user_id = %principal.user_id,
                    denial_reason = "duplicate_name",
                    "subscription create denied (adapter race)"
                );
                return Err(SubscriptionError::DuplicateName);
            }
            return Err(SubscriptionError::Infrastructure(e));
        }

        // 8. Emit SubscriptionCreated on owner's user stream.
        let stream_id = StreamId::user(sub.owner_user_id);
        let expected = read_expected_version(self.events.as_ref(), &stream_id, false)
            .await
            .map_err(app_to_use_case_err)?;
        let snapshot_claims_count = sub.snapshot_claims.len() as u32;
        let event = DomainEvent::SubscriptionCreated(SubscriptionCreated {
            subscription_id: sub.id.0,
            owner_user_id: sub.owner_user_id,
            target_kind,
            filter_summary: compute_filter_summary(&sub.filter),
            snapshot_claims_count,
            at: now,
        });
        self.events
            .append(AppendEvents {
                stream_id,
                expected_version: expected,
                events: vec![EventToAppend::new(event)],
                correlation_id: Uuid::new_v4(),
                causation_id: None,
                actor: hort_domain::events::Actor::Api(ApiActor {
                    user_id: principal.user_id,
                }),
            })
            .await?;

        tracing::info!(
            subscription_id = %sub.id.0,
            owner_user_id = %sub.owner_user_id,
            actor_user_id = %principal.user_id,
            target_kind = ?target_kind,
            snapshot_claims_count,
            "subscription created"
        );
        Ok(sub)
    }

    /// Compute the union of "doesn't authorize Read" and "doesn't exist"
    /// repository ids — non-existent ids collapse into the unauthorized
    /// list (never leak existence-vs-permission).
    async fn scan_unauthorized_or_missing(
        &self,
        principal: &CallerPrincipal,
        filter_ids: &[Uuid],
        rbac: &RbacEvaluator,
    ) -> Vec<Uuid> {
        let mut unauthorized = Vec::new();
        for id in filter_ids {
            if !rbac.authorize(principal, Permission::Read, Some(*id)) {
                unauthorized.push(*id);
                continue;
            }
            match self.repositories.find_by_id(*id).await {
                Ok(_) => {}
                Err(DomainError::NotFound { .. }) => unauthorized.push(*id),
                Err(_) => {
                    // Infrastructure error during existence check —
                    // treat as unauthorized to avoid leaking. The audit
                    // event still records "RepoNotAuthorised" so SOCs
                    // can correlate with the warn-level adapter log.
                    unauthorized.push(*id);
                }
            }
        }
        unauthorized
    }

    /// Privileged-category authority gate predicate.
    ///
    /// Returns `true` when `filter.categories` intersects the
    /// `ADMIN_CATEGORIES` set (the categories the **hoisted `hort-domain`**
    /// [`StreamCategory::requires_admin`] predicate returns `true` for —
    /// `Policy`, `Admin`, `Authorization`, `User`, `AuthAttempts`) AND
    /// the *acting principal* does not currently satisfy
    /// `Permission::Admin`. The set is obtained from the single
    /// `hort-domain` source of truth — it is **not** re-encoded here, and
    /// `hort-app` does not (cannot) import `hort-http-events` (circular crate
    /// dependency; the events-read gate delegates to the same domain
    /// predicate). Drift between the read gate and this gate is the
    /// primary privileged-category bug class.
    ///
    /// Authority is evaluated **live** against the current RBAC snapshot,
    /// never read from `snapshot_claims` (the snapshot is the dispatch
    /// authority floor, re-checked at delivery — defence in depth; this is
    /// the create/update leg).
    fn privileged_category_denied(
        &self,
        principal: &CallerPrincipal,
        filter: &SubscriptionFilter,
    ) -> bool {
        if !filter.categories.iter().any(StreamCategory::requires_admin) {
            return false;
        }
        let rbac_guard = self.rbac.load();
        let is_admin = rbac_guard.authorize(principal, Permission::Admin, None);
        // Drop the arc-swap guard before returning — keep the !Send
        // guard's lifetime tightly scoped (no await in this fn, but the
        // callers await right after, so never hold it across the call).
        drop(rbac_guard);
        !is_admin
    }

    /// Append a [`SubscriptionCreationDenied`] event on the requesting
    /// actor's user stream (same pattern as
    /// `ApiTokenIssuanceDenied`).
    async fn emit_denial(
        &self,
        principal: &CallerPrincipal,
        target_kind: TargetKindWire,
        attempted_filter_summary: FilterSummary,
        denial_reason: SubscriptionDenialReason,
    ) -> Result<(), SubscriptionError> {
        let stream_id = StreamId::user(principal.user_id);
        let expected = read_expected_version(self.events.as_ref(), &stream_id, false)
            .await
            .map_err(app_to_use_case_err)?;
        let event = DomainEvent::SubscriptionCreationDenied(SubscriptionCreationDenied {
            requesting_user_id: principal.user_id,
            requested_target_kind: target_kind,
            attempted_filter_summary,
            denial_reason,
            at: Utc::now(),
        });
        self.events
            .append(AppendEvents {
                stream_id,
                expected_version: expected,
                events: vec![EventToAppend::new(event)],
                correlation_id: Uuid::new_v4(),
                causation_id: None,
                actor: hort_domain::events::Actor::Api(ApiActor {
                    user_id: principal.user_id,
                }),
            })
            .await?;
        Ok(())
    }

    // -- get_for_owner ------------------------------------------------------

    /// Load a subscription, authorising the caller as owner-or-admin.
    #[tracing::instrument(skip(self, principal))]
    pub async fn get_for_owner(
        &self,
        principal: &CallerPrincipal,
        id: SubscriptionId,
    ) -> Result<Subscription, SubscriptionError> {
        let sub = self.load_or_not_found(id).await?;
        self.require_owner_or_admin(principal, sub.owner_user_id)?;
        Ok(sub)
    }

    // -- list_for_owner -----------------------------------------------------

    /// List subscriptions owned by `owner`. Self-list or admin-list.
    #[tracing::instrument(skip(self, principal))]
    pub async fn list_for_owner(
        &self,
        principal: &CallerPrincipal,
        owner: Uuid,
        page: PageRequest,
    ) -> Result<Page<Subscription>, SubscriptionError> {
        self.require_owner_or_admin(principal, owner)?;
        Ok(self.subscriptions.list_for_owner(owner, page).await?)
    }

    // -- admin_list_all -----------------------------------------------------

    /// Admin-only — list every **active** subscription across all owners.
    ///
    /// Backs the `GET /api/v1/admin/subscriptions`
    /// surface. Requires `Permission::Admin` (defence in depth — the
    /// `AdminPrincipal` extractor in the inbound HTTP crate enforces
    /// the same gate at the request edge).
    ///
    /// v1 scope: returns the dispatcher's `list_active` set (active
    /// subscriptions only). Paused / disabled rows are excluded; a
    /// future PR may extend the repo port with a `list_all` variant
    /// when operator workflow surfaces demand.
    #[tracing::instrument(skip(self, principal))]
    pub async fn admin_list_all(
        &self,
        principal: &CallerPrincipal,
    ) -> Result<Vec<Subscription>, SubscriptionError> {
        let rbac_guard = self.rbac.load();
        let rbac = &**rbac_guard;
        if !rbac.authorize(principal, Permission::Admin, None) {
            return Err(SubscriptionError::NotAuthorized);
        }
        drop(rbac_guard);
        Ok(self.subscriptions.list_active().await?)
    }

    // -- update -------------------------------------------------------------

    /// Apply per-field updates with the cap-never-widens rule on
    /// `filter.repositories`.
    #[tracing::instrument(skip(self, principal, request))]
    pub async fn update(
        &self,
        principal: &CallerPrincipal,
        id: SubscriptionId,
        request: UpdateSubscriptionRequest,
    ) -> Result<Subscription, SubscriptionError> {
        let mut sub = self.load_or_not_found(id).await?;
        self.require_owner_or_admin(principal, sub.owner_user_id)?;

        let mut changed_fields: Vec<String> = Vec::new();

        if let Some(name) = &request.name {
            validate_name(name).map_err(domain_to_validation)?;
            sub.name = name.clone();
            changed_fields.push("name".into());
        }
        if let Some(desc_outer) = &request.description {
            validate_description(desc_outer.as_deref()).map_err(domain_to_validation)?;
            sub.description = desc_outer.clone();
            changed_fields.push("description".into());
        }
        if let Some(target) = &request.target {
            // Re-run target-specific validation. SSRF check applies on
            // any new webhook URL too.
            match target {
                SubscriptionTarget::Webhook { url, .. } => {
                    if url.scheme() == "http" && !self.config.allow_plaintext_webhooks {
                        return Err(SubscriptionError::PlaintextWebhookDisallowed);
                    }
                    validate_webhook_url(url, self.config.allow_plaintext_webhooks)
                        .map_err(domain_to_validation)?;
                    if !self.config.allow_nonroutable_webhook_targets {
                        if let Err(reason) = self.webhook_guard.check(url).await {
                            emit_ssrf_block(ssrf_reason_label(reason));
                            return Err(SubscriptionError::WebhookTargetNotRoutable {
                                ssrf_block_reason: reason,
                            });
                        }
                    }
                }
                SubscriptionTarget::NatsJetStream { subject } => {
                    validate_nats_subject(subject)
                        .map_err(|_| SubscriptionError::InvalidNatsSubject)?;
                }
            }
            sub.target = target.clone();
            changed_fields.push("target".into());
        }
        if let Some(new_filter) = &request.filter {
            // Privileged-category authority gate — applied to the
            // *incoming* filter so a non-admin owner cannot PATCH a
            // privileged category onto an existing subscription. Live
            // authz at the call site, never the snapshot. Fail-fast
            // BEFORE any `sub` mutation / persist (the pre-existing row
            // is left unchanged) and emits the distinct
            // `SubscriptionCreationDenied` reason for SIEM parity.
            if self.privileged_category_denied(principal, new_filter) {
                let target_kind = target_kind_wire(&sub.target);
                let attempted = compute_filter_summary(new_filter);
                self.emit_denial(
                    principal,
                    target_kind,
                    attempted,
                    SubscriptionDenialReason::PrivilegedCategoryRequiresAdmin,
                )
                .await?;
                tracing::info!(
                    actor_user_id = %principal.user_id,
                    subscription_id = %sub.id.0,
                    denial_reason = "privileged_category_requires_admin",
                    "subscription update denied"
                );
                return Err(SubscriptionError::NotAuthorized);
            }
            // Cap-never-widens transitions on `filter.repositories`.
            // Each match arm is documented for the audit-review trail.
            match (&sub.filter.repositories, &new_filter.repositories) {
                // Same shape on both sides: identical scopes are no-ops.
                // `OwnedByActor → OwnedByActor` and `All → All` carry no
                // payload; `Some → Some` is handled with id-set diff
                // below so the "same vec" case lands in there too.
                (RepositoryScope::OwnedByActor, RepositoryScope::OwnedByActor) => {}
                (RepositoryScope::All, RepositoryScope::All) => {}

                // Shrinking from All to a smaller scope — allowed.
                (RepositoryScope::All, RepositoryScope::Some(_))
                | (RepositoryScope::All, RepositoryScope::OwnedByActor) => {}

                // Adding a constraint where there was none — allowed.
                (RepositoryScope::OwnedByActor, RepositoryScope::Some(_)) => {}

                // Widening to All — rejected.
                (RepositoryScope::OwnedByActor, RepositoryScope::All)
                | (RepositoryScope::Some(_), RepositoryScope::All) => {
                    return Err(SubscriptionError::RepoScopeExceedsTokenCap {
                        offending: Vec::new(),
                    });
                }

                // Widening Some → OwnedByActor (broader-dynamic) is
                // rejected because the stored scope is the upper bound.
                (RepositoryScope::Some(_), RepositoryScope::OwnedByActor) => {
                    return Err(SubscriptionError::RepoScopeExceedsTokenCap {
                        offending: Vec::new(),
                    });
                }

                // Some(old) → Some(new): only shrinking allowed; ids
                // in `new` but not in `old` are widening attempts.
                (RepositoryScope::Some(old_ids), RepositoryScope::Some(new_ids)) => {
                    let offending: Vec<Uuid> = new_ids
                        .iter()
                        .filter(|id| !old_ids.contains(id))
                        .copied()
                        .collect();
                    if !offending.is_empty() {
                        return Err(SubscriptionError::RepoScopeExceedsTokenCap { offending });
                    }
                }
            }
            // Re-run high-volume event-type rejection on the new
            // filter — operators cannot smuggle in `ArtifactDownloaded`
            // via update.
            if let EventTypeFilter::Some(kinds) = &new_filter.event_types {
                if let Some(hv) = kinds.iter().find(|k| k.is_high_volume()) {
                    return Err(SubscriptionError::UnsupportedEventType(*hv));
                }
            }
            sub.filter = new_filter.clone();
            changed_fields.push("filter".into());
        }
        if let Some(state) = &request.state {
            sub.state = state.clone();
            changed_fields.push("state".into());
        }

        if changed_fields.is_empty() {
            // Nothing to do — no state change, no event. Idempotent.
            // (A no-op PATCH does not persist, so it does not re-snapshot
            // either — the rule is "re-set on every update", and a
            // no-op is not an update.)
            return Ok(sub);
        }

        // Re-capture the acting principal's resolved
        // claims on every persisted PATCH. Full-replace authority-floor
        // semantics (asymmetric with `filter.repositories`, which is a
        // shrink-only cap): the new value fully replaces the prior one,
        // including the PATCH-via-PAT-clears wrinkle (a PAT principal's
        // `[]` / `["admin"]` overwrites a previously-rich snapshot). The
        // The dispatch-time gate re-checks privileged-category delivery
        // against live owner authority, so a snapshot elevated to
        // `["admin"]` cannot retroactively unlock a category — that gate,
        // not this floor, closes the race.
        sub.snapshot_claims = principal.claims.clone();
        let snapshot_claims_count = sub.snapshot_claims.len() as u32;

        self.subscriptions.update(&sub).await?;

        let now = Utc::now();
        let stream_id = StreamId::user(sub.owner_user_id);
        let expected = read_expected_version(self.events.as_ref(), &stream_id, false)
            .await
            .map_err(app_to_use_case_err)?;
        let event = DomainEvent::SubscriptionUpdated(SubscriptionUpdated {
            subscription_id: sub.id.0,
            owner_user_id: sub.owner_user_id,
            changed_fields,
            snapshot_claims_count,
            at: now,
        });
        self.events
            .append(AppendEvents {
                stream_id,
                expected_version: expected,
                events: vec![EventToAppend::new(event)],
                correlation_id: Uuid::new_v4(),
                causation_id: None,
                actor: hort_domain::events::Actor::Api(ApiActor {
                    user_id: principal.user_id,
                }),
            })
            .await?;

        tracing::info!(
            subscription_id = %sub.id.0,
            owner_user_id = %sub.owner_user_id,
            actor_user_id = %principal.user_id,
            snapshot_claims_count,
            snapshot_replaced = true,
            "subscription updated"
        );
        Ok(sub)
    }

    // -- pause / resume -----------------------------------------------------

    /// Operator-pause an active subscription. Idempotent on already-paused.
    #[tracing::instrument(skip(self, principal))]
    pub async fn pause(
        &self,
        principal: &CallerPrincipal,
        id: SubscriptionId,
    ) -> Result<(), SubscriptionError> {
        let mut sub = self.load_or_not_found(id).await?;
        self.require_owner_or_admin(principal, sub.owner_user_id)?;
        sub.state = SubscriptionState::Paused;
        self.subscriptions.update(&sub).await?;
        self.emit_lifecycle(
            &sub,
            principal,
            DomainEvent::SubscriptionPaused(SubscriptionPaused {
                subscription_id: sub.id.0,
                owner_user_id: sub.owner_user_id,
                at: Utc::now(),
            }),
        )
        .await?;
        tracing::info!(
            subscription_id = %sub.id.0,
            owner_user_id = %sub.owner_user_id,
            actor_user_id = %principal.user_id,
            "subscription paused"
        );
        Ok(())
    }

    /// Resume a paused subscription.
    #[tracing::instrument(skip(self, principal))]
    pub async fn resume(
        &self,
        principal: &CallerPrincipal,
        id: SubscriptionId,
    ) -> Result<(), SubscriptionError> {
        let mut sub = self.load_or_not_found(id).await?;
        self.require_owner_or_admin(principal, sub.owner_user_id)?;
        sub.state = SubscriptionState::Active;
        self.subscriptions.update(&sub).await?;
        self.emit_lifecycle(
            &sub,
            principal,
            DomainEvent::SubscriptionResumed(SubscriptionResumed {
                subscription_id: sub.id.0,
                owner_user_id: sub.owner_user_id,
                at: Utc::now(),
            }),
        )
        .await?;
        tracing::info!(
            subscription_id = %sub.id.0,
            owner_user_id = %sub.owner_user_id,
            actor_user_id = %principal.user_id,
            "subscription resumed"
        );
        Ok(())
    }

    // -- delete -------------------------------------------------------------

    /// Hard-delete the subscription. The row is gone but the
    /// `SubscriptionDeleted` event is the durable audit record.
    #[tracing::instrument(skip(self, principal))]
    pub async fn delete(
        &self,
        principal: &CallerPrincipal,
        id: SubscriptionId,
    ) -> Result<(), SubscriptionError> {
        let sub = self.load_or_not_found(id).await?;
        self.require_owner_or_admin(principal, sub.owner_user_id)?;
        self.subscriptions.delete(id).await?;
        self.emit_lifecycle(
            &sub,
            principal,
            DomainEvent::SubscriptionDeleted(SubscriptionDeleted {
                subscription_id: sub.id.0,
                owner_user_id: sub.owner_user_id,
                at: Utc::now(),
            }),
        )
        .await?;
        tracing::info!(
            subscription_id = %sub.id.0,
            owner_user_id = %sub.owner_user_id,
            actor_user_id = %principal.user_id,
            "subscription deleted"
        );
        Ok(())
    }

    // -- disable (dispatcher-only) -----------------------------------------

    /// System-disable a subscription. Called by the
    /// dispatcher when the failure budget exhausts; the actor is
    /// `system_actor()`. Idempotent when already disabled.
    #[tracing::instrument(skip(self))]
    pub async fn disable(
        &self,
        id: SubscriptionId,
        reason: DisableReason,
    ) -> Result<(), SubscriptionError> {
        let mut sub = self.load_or_not_found(id).await?;
        if matches!(sub.state, SubscriptionState::Disabled { .. }) {
            return Ok(());
        }
        let now = Utc::now();
        sub.state = SubscriptionState::Disabled { reason, since: now };
        self.subscriptions.update(&sub).await?;

        let stream_id = StreamId::user(sub.owner_user_id);
        let expected = read_expected_version(self.events.as_ref(), &stream_id, false)
            .await
            .map_err(app_to_use_case_err)?;
        let event = DomainEvent::SubscriptionDisabled(SubscriptionDisabled {
            subscription_id: sub.id.0,
            owner_user_id: sub.owner_user_id,
            reason,
            at: now,
        });
        self.events
            .append(AppendEvents {
                stream_id,
                expected_version: expected,
                events: vec![EventToAppend::new(event)],
                correlation_id: Uuid::new_v4(),
                causation_id: None,
                actor: system_actor(),
            })
            .await?;
        tracing::info!(
            subscription_id = %sub.id.0,
            owner_user_id = %sub.owner_user_id,
            reason = ?reason,
            "subscription disabled by system"
        );
        Ok(())
    }

    // -- record_delivery_progress (dispatcher-only) ------------------------

    /// Debounced position + failure update from the dispatcher. No event
    /// emission (high-frequency, not audit-relevant).
    #[tracing::instrument(skip(self, failure))]
    pub async fn record_delivery_progress(
        &self,
        id: SubscriptionId,
        position: u64,
        failure: Option<&SubscriptionFailure>,
    ) -> Result<(), SubscriptionError> {
        self.subscriptions
            .update_last_delivered(id, position, failure)
            .await?;
        Ok(())
    }

    // -- helpers ------------------------------------------------------------

    async fn load_or_not_found(
        &self,
        id: SubscriptionId,
    ) -> Result<Subscription, SubscriptionError> {
        match self.subscriptions.find_by_id(id).await {
            Ok(s) => Ok(s),
            Err(DomainError::NotFound { .. }) => Err(SubscriptionError::SubscriptionNotFound),
            Err(other) => Err(SubscriptionError::Infrastructure(other)),
        }
    }

    fn require_owner_or_admin(
        &self,
        principal: &CallerPrincipal,
        owner_user_id: Uuid,
    ) -> Result<(), SubscriptionError> {
        if principal.user_id == owner_user_id {
            return Ok(());
        }
        let rbac_guard = self.rbac.load();
        let rbac = &**rbac_guard;
        if rbac.authorize(principal, Permission::Admin, None) {
            return Ok(());
        }
        Err(SubscriptionError::NotAuthorized)
    }

    async fn emit_lifecycle(
        &self,
        sub: &Subscription,
        principal: &CallerPrincipal,
        event: DomainEvent,
    ) -> Result<(), SubscriptionError> {
        let stream_id = StreamId::user(sub.owner_user_id);
        let expected = read_expected_version(self.events.as_ref(), &stream_id, false)
            .await
            .map_err(app_to_use_case_err)?;
        self.events
            .append(AppendEvents {
                stream_id,
                expected_version: expected,
                events: vec![EventToAppend::new(event)],
                correlation_id: Uuid::new_v4(),
                causation_id: None,
                actor: hort_domain::events::Actor::Api(ApiActor {
                    user_id: principal.user_id,
                }),
            })
            .await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Module helpers
// ---------------------------------------------------------------------------

/// Compute the audit-event filter summary from a domain filter
/// (no PII, no URLs, no repo-id list).
fn compute_filter_summary(filter: &SubscriptionFilter) -> FilterSummary {
    FilterSummary {
        categories: filter.categories.iter().map(category_to_string).collect(),
        event_type_count: match &filter.event_types {
            // 0 is the sentinel for `EventTypeFilter::All` since v1
            // never emits an `event_type_count = 0` with an explicit
            // empty Some-list (validation would reject that earlier).
            EventTypeFilter::All => 0,
            EventTypeFilter::Some(kinds) => kinds.len() as u32,
        },
        repository_scope_kind: match &filter.repositories {
            RepositoryScope::OwnedByActor => RepositoryScopeKind::OwnedByActor,
            RepositoryScope::Some(_) => RepositoryScopeKind::Some,
            RepositoryScope::All => RepositoryScopeKind::All,
        },
        // v1 ships zero `NamedPredicate` variants — the canonical hash
        // for "no predicates" is the zero array.
        predicate_hash: [0u8; 32],
    }
}

/// Mirror of the `Display` impl baked into [`StreamId::fmt`]. Kept here
/// rather than as a public domain helper because the wire shape for
/// audit-summary `categories` is intentionally a lower-case string and
/// nothing else needs this projection.
fn category_to_string(c: &StreamCategory) -> String {
    match c {
        StreamCategory::Artifact => "artifact".into(),
        StreamCategory::Policy => "policy".into(),
        StreamCategory::Admin => "admin".into(),
        StreamCategory::Ref => "ref".into(),
        StreamCategory::ArtifactGroup => "artifact_group".into(),
        StreamCategory::Curation => "curation".into(),
        StreamCategory::Repository => "repository".into(),
        StreamCategory::AuthAttempts => "auth".into(),
        StreamCategory::Authorization => "authorization".into(),
        StreamCategory::User => "user".into(),
        StreamCategory::DownloadAudit => "download_audit".into(),
        StreamCategory::TokenUse => "token_use".into(),
        StreamCategory::RetentionPolicy => "retention_policy".into(),
    }
}

/// Project the target enum to its wire-form discriminator.
fn target_kind_wire(target: &SubscriptionTarget) -> TargetKindWire {
    match target {
        SubscriptionTarget::Webhook { .. } => TargetKindWire::Webhook,
        SubscriptionTarget::NatsJetStream { .. } => TargetKindWire::NatsJetStream,
    }
}

/// `DomainError::Validation(_)` paths bubble up as
/// [`SubscriptionError::Validation`] carrying the human-readable inner
/// message; non-validation `DomainError`s flow through as
/// [`SubscriptionError::Infrastructure`].
fn domain_to_validation(e: DomainError) -> SubscriptionError {
    match e {
        DomainError::Validation(m) => SubscriptionError::Validation(m),
        other => SubscriptionError::Infrastructure(other),
    }
}

/// `read_expected_version` returns `AppError`; collapse it into the
/// use-case error envelope.
fn app_to_use_case_err(e: AppError) -> SubscriptionError {
    match e {
        AppError::Domain(d) => SubscriptionError::Infrastructure(d),
        other => SubscriptionError::Infrastructure(DomainError::Invariant(other.to_string())),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    use hort_domain::entities::api_token::TokenCap;
    use hort_domain::entities::rbac::{GrantSubject, PermissionGrant};
    use hort_domain::entities::subscription::EventTypeKind;
    use hort_domain::events::Actor;
    use hort_domain::ports::BoxFuture;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use metrics_util::MetricKind;
    use url::Url;

    use crate::use_cases::test_support::MockEventStore;

    // -------- MockSubscriptionRepository ----------------------------------

    #[derive(Default)]
    struct MockSubscriptionRepository {
        items: Mutex<HashMap<SubscriptionId, Subscription>>,
        fail_create_with_conflict: Mutex<bool>,
    }

    impl MockSubscriptionRepository {
        fn new() -> Self {
            Self::default()
        }

        fn count(&self) -> usize {
            self.items.lock().unwrap().len()
        }

        fn arm_create_conflict(&self) {
            *self.fail_create_with_conflict.lock().unwrap() = true;
        }
    }

    impl SubscriptionRepository for MockSubscriptionRepository {
        fn create(&self, s: &Subscription) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            let armed =
                std::mem::replace(&mut *self.fail_create_with_conflict.lock().unwrap(), false);
            if armed {
                return Box::pin(async {
                    Err(DomainError::Conflict(
                        "duplicate (owner, name) on subscriptions row".into(),
                    ))
                });
            }
            self.items.lock().unwrap().insert(s.id, s.clone());
            Box::pin(async { Ok(()) })
        }
        fn find_by_id(
            &self,
            id: SubscriptionId,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<Subscription>> {
            let result = self.items.lock().unwrap().get(&id).cloned();
            Box::pin(async move {
                result.ok_or(DomainError::NotFound {
                    entity: "Subscription",
                    id: id.0.to_string(),
                })
            })
        }
        fn find_by_name(
            &self,
            owner: Uuid,
            name: &str,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<Option<Subscription>>> {
            let needle = name.to_string();
            let result = self
                .items
                .lock()
                .unwrap()
                .values()
                .find(|s| s.owner_user_id == owner && s.name == needle)
                .cloned();
            Box::pin(async move { Ok(result) })
        }
        fn list_for_owner(
            &self,
            owner: Uuid,
            page: PageRequest,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<Page<Subscription>>> {
            let all: Vec<Subscription> = self
                .items
                .lock()
                .unwrap()
                .values()
                .filter(|s| s.owner_user_id == owner)
                .cloned()
                .collect();
            let total = all.len() as u64;
            let start = (page.offset as usize).min(all.len());
            let end = (start + page.limit as usize).min(all.len());
            let items = all[start..end].to_vec();
            Box::pin(async move { Ok(Page { items, total }) })
        }
        fn list_active(
            &self,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<Vec<Subscription>>> {
            let items: Vec<Subscription> = self
                .items
                .lock()
                .unwrap()
                .values()
                .filter(|s| matches!(s.state, SubscriptionState::Active))
                .cloned()
                .collect();
            Box::pin(async move { Ok(items) })
        }
        fn update(&self, s: &Subscription) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            self.items.lock().unwrap().insert(s.id, s.clone());
            Box::pin(async { Ok(()) })
        }
        fn delete(
            &self,
            id: SubscriptionId,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            self.items.lock().unwrap().remove(&id);
            Box::pin(async { Ok(()) })
        }
        fn update_last_delivered(
            &self,
            id: SubscriptionId,
            position: u64,
            last_failure: Option<&SubscriptionFailure>,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            let lf = last_failure.cloned();
            let mut items = self.items.lock().unwrap();
            if let Some(s) = items.get_mut(&id) {
                s.last_delivered_position = Some(position);
                s.last_failure = lf;
            }
            Box::pin(async { Ok(()) })
        }
    }

    // -------- MockWebhookTargetGuard --------------------------------------

    struct MockWebhookTargetGuard {
        result: Mutex<Result<(), SsrfBlockReason>>,
    }

    impl MockWebhookTargetGuard {
        fn allow() -> Self {
            Self {
                result: Mutex::new(Ok(())),
            }
        }
        fn deny(r: SsrfBlockReason) -> Self {
            Self {
                result: Mutex::new(Err(r)),
            }
        }
    }

    impl WebhookTargetGuard for MockWebhookTargetGuard {
        fn check<'a>(&'a self, _url: &'a Url) -> BoxFuture<'a, Result<(), SsrfBlockReason>> {
            let r = *self.result.lock().unwrap();
            Box::pin(async move { r })
        }
    }

    /// Guard that panics if invoked — verifies the
    /// `allow_nonroutable_webhook_targets = true` path skips the check.
    struct PanickingGuard;
    impl WebhookTargetGuard for PanickingGuard {
        fn check<'a>(&'a self, _url: &'a Url) -> BoxFuture<'a, Result<(), SsrfBlockReason>> {
            Box::pin(async {
                panic!("webhook guard must not be called when allow_nonroutable_webhook_targets = true");
            })
        }
    }

    // -------- RbacEvaluator + CallerPrincipal helpers ---------------------

    fn caller_with_roles(roles: &[&str]) -> CallerPrincipal {
        CallerPrincipal {
            user_id: Uuid::new_v4(),
            external_id: "test:sub".into(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            claims: roles.iter().map(|s| (*s).to_string()).collect(),
            token_kind: None,
            issued_at: Utc::now(),
            token_cap: None,
        }
    }

    /// Build a `Claims([role_name])`-subject grant for each
    /// `(repository, permission)` pair (claim-based subject model —
    /// shared helper for the multi-repo grant fixtures so the inline
    /// per-test grant construction is not duplicated 3+ times).
    fn claims_grants_on(role_name: &str, scopes: &[(Uuid, Permission)]) -> Vec<PermissionGrant> {
        scopes
            .iter()
            .map(|(repo, perm)| PermissionGrant {
                id: Uuid::new_v4(),
                subject: GrantSubject::Claims(vec![role_name.to_string()]),
                repository_id: Some(*repo),
                permission: *perm,
                created_at: Utc::now(),
                managed_by: hort_domain::entities::managed_by::ManagedBy::Local,
                managed_by_digest: None,
            })
            .collect()
    }

    /// Capped caller — `repository_ids = Some(cap_ids)`.
    fn caller_capped(cap_ids: Vec<Uuid>) -> CallerPrincipal {
        let mut p = caller_with_roles(&["dev"]);
        p.token_cap = Some(TokenCap {
            permissions: vec![Permission::Read],
            repository_ids: Some(cap_ids),
        });
        p
    }

    fn empty_eval() -> RbacEvaluator {
        RbacEvaluator::new(Vec::new())
    }

    fn eval_with_grant(role_name: &str, repo_id: Uuid, permission: Permission) -> RbacEvaluator {
        RbacEvaluator::new(claims_grants_on(role_name, &[(repo_id, permission)]))
    }

    // -------- Mock RepositoryRepository (test_support reuse) --------------

    use crate::use_cases::test_support::{
        sample_repository, MockRepositoryRepository, MockUserRepository,
    };

    fn seed_repo(repos: &MockRepositoryRepository, id: Uuid) {
        let mut r = sample_repository();
        r.id = id;
        r.key = format!("repo-{id}");
        repos.insert(r);
    }

    // -------- Wire helper --------------------------------------------------

    struct Fixtures {
        uc: SubscriptionUseCase,
        subs: Arc<MockSubscriptionRepository>,
        events: Arc<MockEventStore>,
        repos: Arc<MockRepositoryRepository>,
    }

    fn wire(
        rbac: RbacEvaluator,
        guard: Arc<dyn WebhookTargetGuard>,
        cfg: SubscriptionUseCaseConfig,
    ) -> Fixtures {
        let subs = Arc::new(MockSubscriptionRepository::new());
        let users = Arc::new(MockUserRepository::new());
        let events = Arc::new(MockEventStore::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let rbac = Arc::new(ArcSwap::from_pointee(rbac));
        let uc = SubscriptionUseCase::new(
            subs.clone(),
            users,
            crate::event_store_publisher::wrap_for_test(events.clone()),
            rbac,
            repos.clone(),
            guard,
            cfg,
        );
        Fixtures {
            uc,
            subs,
            events,
            repos,
        }
    }

    // -------- Fixtures for requests ---------------------------------------

    /// The webhook target carries a
    /// `SecretRef` locator, not the secret material. The use case only
    /// pattern-matches `Webhook { url, .. }`, so this value is opaque
    /// to it — but the fixtures must construct the new shape.
    fn webhook_secret_ref() -> hort_domain::ports::secret_port::SecretRef {
        hort_domain::ports::secret_port::SecretRef {
            source: hort_domain::ports::secret_port::SecretSource::EnvVar,
            location: "HORT_WEBHOOK_SECRET".into(),
        }
    }

    fn https_target() -> SubscriptionTarget {
        SubscriptionTarget::Webhook {
            url: "https://example.com/hook".parse().unwrap(),
            secret_ref: webhook_secret_ref(),
        }
    }

    fn http_target() -> SubscriptionTarget {
        SubscriptionTarget::Webhook {
            url: "http://example.com/hook".parse().unwrap(),
            secret_ref: webhook_secret_ref(),
        }
    }

    fn ip_target() -> SubscriptionTarget {
        SubscriptionTarget::Webhook {
            url: "https://10.0.0.1/hook".parse().unwrap(),
            secret_ref: webhook_secret_ref(),
        }
    }

    fn nats_target() -> SubscriptionTarget {
        SubscriptionTarget::NatsJetStream {
            subject: "hort.events.test".into(),
        }
    }

    fn filter_owned() -> SubscriptionFilter {
        SubscriptionFilter {
            categories: vec![StreamCategory::Artifact],
            event_types: EventTypeFilter::All,
            repositories: RepositoryScope::OwnedByActor,
            named_predicates: vec![],
        }
    }

    fn filter_some(ids: Vec<Uuid>) -> SubscriptionFilter {
        SubscriptionFilter {
            categories: vec![StreamCategory::Artifact],
            event_types: EventTypeFilter::All,
            repositories: RepositoryScope::Some(ids),
            named_predicates: vec![],
        }
    }

    fn filter_all() -> SubscriptionFilter {
        SubscriptionFilter {
            categories: vec![StreamCategory::Artifact],
            event_types: EventTypeFilter::All,
            repositories: RepositoryScope::All,
            named_predicates: vec![],
        }
    }

    fn req(
        name: &str,
        target: SubscriptionTarget,
        filter: SubscriptionFilter,
    ) -> CreateSubscriptionRequest {
        CreateSubscriptionRequest {
            name: name.into(),
            description: None,
            target,
            filter,
        }
    }

    fn default_cfg() -> SubscriptionUseCaseConfig {
        SubscriptionUseCaseConfig::default()
    }

    fn last_appended_event(events: &MockEventStore) -> (StreamId, DomainEvent, Actor) {
        let mut batches = events.appended_batches();
        let last = batches.pop().expect("expected at least one appended batch");
        let stream_id = last.stream_id;
        let actor = last.actor;
        let event = last.events.into_iter().next().unwrap().event;
        (stream_id, event, actor)
    }

    // ---------------- Happy-path tests ------------------------------------

    #[tokio::test]
    async fn create_with_owned_by_actor_uncapped_token_succeeds_and_emits_event() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let sub = fx
            .uc
            .create(&actor, req("ci-relay", https_target(), filter_owned()))
            .await
            .expect("happy path");

        assert_eq!(sub.owner_user_id, actor.user_id);
        assert_eq!(sub.name, "ci-relay");
        assert!(matches!(sub.state, SubscriptionState::Active));
        assert!(sub.created_by_token_id.is_none());
        assert_eq!(fx.subs.count(), 1);
        let (stream_id, event, _) = last_appended_event(&fx.events);
        assert_eq!(stream_id, StreamId::user(actor.user_id));
        assert!(matches!(event, DomainEvent::SubscriptionCreated(_)));
    }

    #[tokio::test]
    async fn successful_create_event_lands_on_owner_stream() {
        // Owner equals caller in self-mint; stream is owner's
        // (== caller's) stream.
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        fx.uc
            .create(&actor, req("ci-relay", https_target(), filter_owned()))
            .await
            .unwrap();
        let (stream_id, _, _) = last_appended_event(&fx.events);
        assert_eq!(stream_id, StreamId::user(actor.user_id));
    }

    #[tokio::test]
    async fn create_with_some_filter_ids_caller_has_read_succeeds() {
        let repo_a = Uuid::new_v4();
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            eval_with_grant("dev", repo_a, Permission::Read),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        seed_repo(&fx.repos, repo_a);
        fx.uc
            .create(
                &actor,
                req("relay-a", https_target(), filter_some(vec![repo_a])),
            )
            .await
            .expect("Read-grant ok");
        assert_eq!(fx.subs.count(), 1);
    }

    #[tokio::test]
    async fn create_with_some_filter_ids_capped_token_subset_succeeds() {
        let repo_a = Uuid::new_v4();
        let actor = caller_capped(vec![repo_a]);
        let fx = wire(
            eval_with_grant("dev", repo_a, Permission::Read),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        seed_repo(&fx.repos, repo_a);
        fx.uc
            .create(
                &actor,
                req("relay-cap", https_target(), filter_some(vec![repo_a])),
            )
            .await
            .expect("cap-subset ok");
    }

    #[tokio::test]
    async fn create_with_all_scope_admin_uncapped_token_succeeds() {
        let actor = caller_with_roles(&["admin"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        fx.uc
            .create(&actor, req("admin-relay", https_target(), filter_all()))
            .await
            .expect("admin + uncapped ok");
    }

    #[tokio::test]
    async fn create_with_nats_target_succeeds() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        fx.uc
            .create(&actor, req("nats-relay", nats_target(), filter_owned()))
            .await
            .expect("nats target ok");
    }

    #[tokio::test]
    async fn create_accepts_plaintext_webhook_when_flag_on() {
        let actor = caller_with_roles(&["dev"]);
        let cfg = SubscriptionUseCaseConfig {
            allow_plaintext_webhooks: true,
            allow_nonroutable_webhook_targets: true, // skip SSRF for simplicity
        };
        let fx = wire(empty_eval(), Arc::new(MockWebhookTargetGuard::allow()), cfg);
        fx.uc
            .create(&actor, req("plain", http_target(), filter_owned()))
            .await
            .expect("plaintext allowed when flag on");
    }

    #[test]
    fn create_skips_ssrf_when_allow_nonroutable_flag_on() {
        let actor = caller_with_roles(&["dev"]);
        let cfg = SubscriptionUseCaseConfig {
            allow_plaintext_webhooks: false,
            allow_nonroutable_webhook_targets: true,
        };
        // Use a recorder to assert no metric increment.
        let recorder = DebuggingRecorder::new();
        let snap = recorder.snapshotter();
        let fx = wire(empty_eval(), Arc::new(PanickingGuard), cfg);

        let actor_ref = &actor;
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(
                    fx.uc
                        .create(actor_ref, req("ip-target", ip_target(), filter_owned())),
                )
                .expect("ssrf check skipped");
        });

        let entries = snap.snapshot().into_vec();
        assert!(
            !entries
                .iter()
                .any(|(k, _, _, _)| k.key().name() == "hort_webhook_ssrf_block_total"),
            "no SSRF metric must fire when allow_nonroutable_webhook_targets = true"
        );
    }

    // ---------------- Denial-path tests -----------------------------------

    fn assert_last_event_is_denial(
        events: &MockEventStore,
        principal: &CallerPrincipal,
        expected_reason: &SubscriptionDenialReason,
    ) {
        let (stream_id, event, actor) = last_appended_event(events);
        assert_eq!(
            stream_id,
            StreamId::user(principal.user_id),
            "denial must land on requesting actor's stream"
        );
        match event {
            DomainEvent::SubscriptionCreationDenied(d) => {
                assert_eq!(d.denial_reason, *expected_reason);
                assert_eq!(d.requesting_user_id, principal.user_id);
            }
            other => panic!("expected SubscriptionCreationDenied, got {other:?}"),
        }
        match actor {
            Actor::Api(a) => assert_eq!(a.user_id, principal.user_id),
            other => panic!("expected Actor::Api, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn create_rejects_unsupported_event_type_in_filter() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let mut f = filter_owned();
        f.event_types = EventTypeFilter::Some(vec![EventTypeKind::AuthenticationAttempted]);
        let err = fx
            .uc
            .create(&actor, req("bad", https_target(), f))
            .await
            .unwrap_err();
        assert!(matches!(err, SubscriptionError::UnsupportedEventType(_)));
        assert_eq!(fx.subs.count(), 0);
        assert_last_event_is_denial(
            &fx.events,
            &actor,
            &SubscriptionDenialReason::UnsupportedEventType,
        );
    }

    // The companion rejection tests below mirror
    // `create_rejects_unsupported_event_type_in_filter` for the other
    // two members of `HIGH_VOLUME_EVENT_TYPES`. `ArtifactDownloaded` and
    // `ApiTokenUsed` are forward-compatible placeholder kinds (no domain
    // event emits them yet — future work may add them), but they're
    // already in the exclusion list so the issuance gate MUST reject
    // them today. Without these tests, a refactor that thinned the
    // const to a single variant would still pass the `AuthenticationAttempted`
    // test above.

    #[tokio::test]
    async fn create_rejects_artifact_downloaded_in_filter() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let mut f = filter_owned();
        f.event_types = EventTypeFilter::Some(vec![EventTypeKind::ArtifactDownloaded]);
        let err = fx
            .uc
            .create(&actor, req("bad-dl", https_target(), f))
            .await
            .unwrap_err();
        match err {
            SubscriptionError::UnsupportedEventType(k) => {
                assert_eq!(k, EventTypeKind::ArtifactDownloaded);
            }
            other => panic!("expected UnsupportedEventType(ArtifactDownloaded), got {other:?}"),
        }
        assert_eq!(fx.subs.count(), 0);
        assert_last_event_is_denial(
            &fx.events,
            &actor,
            &SubscriptionDenialReason::UnsupportedEventType,
        );
    }

    #[tokio::test]
    async fn create_rejects_api_token_used_in_filter() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let mut f = filter_owned();
        f.event_types = EventTypeFilter::Some(vec![EventTypeKind::ApiTokenUsed]);
        let err = fx
            .uc
            .create(&actor, req("bad-tok", https_target(), f))
            .await
            .unwrap_err();
        match err {
            SubscriptionError::UnsupportedEventType(k) => {
                assert_eq!(k, EventTypeKind::ApiTokenUsed);
            }
            other => panic!("expected UnsupportedEventType(ApiTokenUsed), got {other:?}"),
        }
        assert_eq!(fx.subs.count(), 0);
        assert_last_event_is_denial(
            &fx.events,
            &actor,
            &SubscriptionDenialReason::UnsupportedEventType,
        );
    }

    #[tokio::test]
    async fn create_rejects_repo_not_authorised() {
        let repo_a = Uuid::new_v4();
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        seed_repo(&fx.repos, repo_a);
        let err = fx
            .uc
            .create(
                &actor,
                req("no-read", https_target(), filter_some(vec![repo_a])),
            )
            .await
            .unwrap_err();
        match err {
            SubscriptionError::RepoNotAuthorised { unauthorized } => {
                assert_eq!(unauthorized, vec![repo_a]);
            }
            other => panic!("expected RepoNotAuthorised, got {other:?}"),
        }
        assert_last_event_is_denial(
            &fx.events,
            &actor,
            &SubscriptionDenialReason::RepoNotAuthorised,
        );
    }

    #[tokio::test]
    async fn create_collapses_missing_repo_into_unauthorized_list() {
        // Caller has Read on `repo_a` but `repo_b` does not exist in the
        // repository repository. Both should be reported as unauthorized
        // — no existence-vs-permission leak.
        let repo_a = Uuid::new_v4();
        let repo_b = Uuid::new_v4();
        let actor = caller_with_roles(&["dev"]);
        // Grant Read on BOTH ids so the rbac gate is open; only the
        // existence check fails for repo_b.
        let eval = RbacEvaluator::new(claims_grants_on(
            "dev",
            &[(repo_a, Permission::Read), (repo_b, Permission::Read)],
        ));
        let fx = wire(
            eval,
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        seed_repo(&fx.repos, repo_a);
        // repo_b deliberately not seeded.
        let err = fx
            .uc
            .create(
                &actor,
                req("partial", https_target(), filter_some(vec![repo_a, repo_b])),
            )
            .await
            .unwrap_err();
        match err {
            SubscriptionError::RepoNotAuthorised { unauthorized } => {
                assert_eq!(unauthorized, vec![repo_b]);
            }
            other => panic!("expected RepoNotAuthorised, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn create_rejects_admin_scope_requires_admin() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let err = fx
            .uc
            .create(&actor, req("all-bad", https_target(), filter_all()))
            .await
            .unwrap_err();
        assert!(matches!(err, SubscriptionError::AdminScopeRequiresAdmin));
        assert_last_event_is_denial(
            &fx.events,
            &actor,
            &SubscriptionDenialReason::AdminScopeRequiresAdmin,
        );
    }

    #[tokio::test]
    async fn create_rejects_admin_scope_requires_uncapped_token() {
        // Admin role but capped — a capped token cannot create
        // an `All` scope subscription even if the caller has admin role.
        let actor = {
            let mut p = caller_with_roles(&["admin"]);
            p.token_cap = Some(TokenCap {
                permissions: vec![Permission::Read],
                repository_ids: Some(vec![Uuid::new_v4()]),
            });
            p
        };
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let err = fx
            .uc
            .create(&actor, req("all-capped", https_target(), filter_all()))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            SubscriptionError::AdminScopeRequiresUncappedToken
        ));
        assert_last_event_is_denial(
            &fx.events,
            &actor,
            &SubscriptionDenialReason::AdminScopeRequiresUncappedToken,
        );
    }

    #[tokio::test]
    async fn create_rejects_repo_scope_must_be_explicit() {
        let repo_a = Uuid::new_v4();
        let actor = caller_capped(vec![repo_a]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let err = fx
            .uc
            .create(&actor, req("owned-capped", https_target(), filter_owned()))
            .await
            .unwrap_err();
        match err {
            SubscriptionError::RepoScopeMustBeExplicit { cap_ids } => {
                assert_eq!(cap_ids, vec![repo_a]);
            }
            other => panic!("expected RepoScopeMustBeExplicit, got {other:?}"),
        }
        assert_last_event_is_denial(
            &fx.events,
            &actor,
            &SubscriptionDenialReason::RepoScopeMustBeExplicit,
        );
    }

    #[tokio::test]
    async fn create_rejects_repo_scope_exceeds_token_cap() {
        let repo_a = Uuid::new_v4();
        let repo_b = Uuid::new_v4();
        let actor = caller_capped(vec![repo_a]);
        let fx = wire(
            eval_with_grant("dev", repo_a, Permission::Read),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        seed_repo(&fx.repos, repo_a);
        seed_repo(&fx.repos, repo_b);
        let err = fx
            .uc
            .create(
                &actor,
                req("exceeds", https_target(), filter_some(vec![repo_a, repo_b])),
            )
            .await
            .unwrap_err();
        match err {
            SubscriptionError::RepoScopeExceedsTokenCap { offending } => {
                assert_eq!(offending, vec![repo_b]);
            }
            other => panic!("expected RepoScopeExceedsTokenCap, got {other:?}"),
        }
        assert_last_event_is_denial(
            &fx.events,
            &actor,
            &SubscriptionDenialReason::RepoScopeExceedsTokenCap,
        );
    }

    #[tokio::test]
    async fn create_rejects_plaintext_webhook_disallowed() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let err = fx
            .uc
            .create(&actor, req("plain-bad", http_target(), filter_owned()))
            .await
            .unwrap_err();
        assert!(matches!(err, SubscriptionError::PlaintextWebhookDisallowed));
        assert_last_event_is_denial(
            &fx.events,
            &actor,
            &SubscriptionDenialReason::PlaintextWebhookDisallowed,
        );
    }

    #[tokio::test]
    async fn create_rejects_invalid_nats_subject() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let bad = SubscriptionTarget::NatsJetStream {
            subject: "hort.*.events".into(),
        };
        let err = fx
            .uc
            .create(&actor, req("bad-subj", bad, filter_owned()))
            .await
            .unwrap_err();
        assert!(matches!(err, SubscriptionError::InvalidNatsSubject));
        assert_last_event_is_denial(
            &fx.events,
            &actor,
            &SubscriptionDenialReason::InvalidNatsSubject,
        );
    }

    #[tokio::test]
    async fn create_rejects_duplicate_name() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        fx.uc
            .create(&actor, req("dup", https_target(), filter_owned()))
            .await
            .unwrap();
        let err = fx
            .uc
            .create(&actor, req("dup", https_target(), filter_owned()))
            .await
            .unwrap_err();
        assert!(matches!(err, SubscriptionError::DuplicateName));
        assert_last_event_is_denial(&fx.events, &actor, &SubscriptionDenialReason::DuplicateName);
    }

    #[tokio::test]
    async fn create_handles_adapter_conflict_race_as_duplicate_name() {
        // Pre-check passes (name not in mock), but the adapter create
        // returns Conflict — the use case must still surface
        // DuplicateName + emit the denial event.
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        fx.subs.arm_create_conflict();
        let err = fx
            .uc
            .create(&actor, req("race", https_target(), filter_owned()))
            .await
            .unwrap_err();
        assert!(matches!(err, SubscriptionError::DuplicateName));
        assert_last_event_is_denial(&fx.events, &actor, &SubscriptionDenialReason::DuplicateName);
    }

    #[tokio::test]
    async fn creation_denied_event_lands_on_requesting_actor_stream_not_owner() {
        // Denial stream is the caller's stream — verified by
        // `assert_last_event_is_denial`. This explicit test asserts the
        // stream is NOT a different stream id (caller != arbitrary).
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        fx.uc
            .create(&actor, req("dup", https_target(), filter_owned()))
            .await
            .unwrap();
        // Second create with same name → denial.
        fx.uc
            .create(&actor, req("dup", https_target(), filter_owned()))
            .await
            .unwrap_err();
        let (stream_id, event, _) = last_appended_event(&fx.events);
        assert!(matches!(event, DomainEvent::SubscriptionCreationDenied(_)));
        assert_eq!(stream_id, StreamId::user(actor.user_id));
        assert_ne!(stream_id, StreamId::user(Uuid::new_v4()));
    }

    // ---- SSRF block + metric ---------------------------------------------

    fn assert_ssrf_metric(
        recorder_entries: &[(
            metrics_util::CompositeKey,
            Option<metrics::Unit>,
            Option<metrics::SharedString>,
            DebugValue,
        )],
        reason_value: &str,
    ) {
        let (key, _, _, value) = recorder_entries
            .iter()
            .find(|(k, _, _, _)| {
                k.kind() == MetricKind::Counter && k.key().name() == "hort_webhook_ssrf_block_total"
            })
            .expect("hort_webhook_ssrf_block_total must fire");
        let lbls: HashMap<&str, &str> = key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(lbls.get("reason"), Some(&reason_value));
        match value {
            DebugValue::Counter(v) => assert_eq!(*v, 1),
            other => panic!("expected Counter, got {other:?}"),
        }
    }

    fn assert_ssrf_denial(events: &MockEventStore, expected: SsrfBlockReason) {
        let (_, event, _) = last_appended_event(events);
        match event {
            DomainEvent::SubscriptionCreationDenied(d) => match d.denial_reason {
                SubscriptionDenialReason::WebhookTargetNotRoutable { ssrf_block_reason } => {
                    assert_eq!(ssrf_block_reason, expected);
                }
                other => panic!("expected WebhookTargetNotRoutable, got {other:?}"),
            },
            other => panic!("expected SubscriptionCreationDenied, got {other:?}"),
        }
    }

    fn run_ssrf_denial_test(reason: SsrfBlockReason, label_value: &str) {
        let actor = caller_with_roles(&["dev"]);
        let cfg = SubscriptionUseCaseConfig {
            allow_plaintext_webhooks: true,
            allow_nonroutable_webhook_targets: false,
        };
        let recorder = DebuggingRecorder::new();
        let snap = recorder.snapshotter();
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::deny(reason)),
            cfg,
        );
        let actor_ref = &actor;
        let target = http_target(); // hits guard regardless of host
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(fx.uc.create(actor_ref, req("ssrf", target, filter_owned())))
                .unwrap_err();
        });
        let entries = snap.snapshot().into_vec();
        assert_ssrf_metric(&entries, label_value);
        assert_ssrf_denial(&fx.events, reason);
    }

    #[test]
    fn create_rejects_webhook_target_not_routable_ip_literal() {
        run_ssrf_denial_test(
            SsrfBlockReason::IpLiteralNotRoutable,
            "ip_literal_not_routable",
        );
    }

    #[test]
    fn create_rejects_webhook_target_not_routable_dns_resolved() {
        run_ssrf_denial_test(
            SsrfBlockReason::DnsResolvedNotRoutable,
            "dns_resolved_not_routable",
        );
    }

    #[test]
    fn create_rejects_webhook_target_not_routable_dns_resolution_failed() {
        run_ssrf_denial_test(
            SsrfBlockReason::DnsResolutionFailed,
            "dns_resolution_failed",
        );
    }

    // ---- name / description validation -----------------------------------

    #[tokio::test]
    async fn create_rejects_empty_name_without_emitting_denial() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let err = fx
            .uc
            .create(&actor, req("", https_target(), filter_owned()))
            .await
            .unwrap_err();
        assert!(matches!(err, SubscriptionError::Validation(_)));
        // No event emitted on structural validation failure.
        assert!(fx.events.appended_batches().is_empty());
    }

    #[tokio::test]
    async fn create_rejects_unsupported_scheme_as_validation_no_event() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let bad = SubscriptionTarget::Webhook {
            url: "ftp://example.com/hook".parse().unwrap(),
            secret_ref: webhook_secret_ref(),
        };
        let err = fx
            .uc
            .create(&actor, req("scheme", bad, filter_owned()))
            .await
            .unwrap_err();
        assert!(matches!(err, SubscriptionError::Validation(_)));
        // Unsupported scheme is structural — no denial event.
        assert!(fx.events.appended_batches().is_empty());
    }

    // ---------------- get / list ------------------------------------------

    #[tokio::test]
    async fn get_for_owner_returns_subscription_when_owner_matches() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let sub = fx
            .uc
            .create(&actor, req("a", https_target(), filter_owned()))
            .await
            .unwrap();
        let got = fx.uc.get_for_owner(&actor, sub.id).await.unwrap();
        assert_eq!(got.id, sub.id);
    }

    #[tokio::test]
    async fn get_for_owner_returns_subscription_when_admin_caller() {
        let owner = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let sub = fx
            .uc
            .create(&owner, req("a", https_target(), filter_owned()))
            .await
            .unwrap();
        let admin = caller_with_roles(&["admin"]);
        let got = fx.uc.get_for_owner(&admin, sub.id).await.unwrap();
        assert_eq!(got.id, sub.id);
    }

    #[tokio::test]
    async fn get_for_owner_returns_not_authorized_when_neither_owner_nor_admin() {
        let owner = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let sub = fx
            .uc
            .create(&owner, req("a", https_target(), filter_owned()))
            .await
            .unwrap();
        let other = caller_with_roles(&["dev"]);
        let err = fx.uc.get_for_owner(&other, sub.id).await.unwrap_err();
        assert!(matches!(err, SubscriptionError::NotAuthorized));
    }

    #[tokio::test]
    async fn get_for_owner_returns_not_found_for_unknown_id() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let err = fx
            .uc
            .get_for_owner(&actor, SubscriptionId(Uuid::new_v4()))
            .await
            .unwrap_err();
        assert!(matches!(err, SubscriptionError::SubscriptionNotFound));
    }

    #[tokio::test]
    async fn list_for_owner_returns_paginated() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        for n in 0..3 {
            fx.uc
                .create(
                    &actor,
                    req(&format!("a-{n}"), https_target(), filter_owned()),
                )
                .await
                .unwrap();
        }
        let page = fx
            .uc
            .list_for_owner(
                &actor,
                actor.user_id,
                PageRequest {
                    offset: 0,
                    limit: 10,
                },
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 3);
        assert_eq!(page.total, 3);
    }

    #[tokio::test]
    async fn list_for_owner_returns_not_authorized_for_other_user_non_admin() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let err = fx
            .uc
            .list_for_owner(&actor, Uuid::new_v4(), PageRequest::default())
            .await
            .unwrap_err();
        assert!(matches!(err, SubscriptionError::NotAuthorized));
    }

    // ---------------- admin_list_all -------------------------------------

    /// Admin-listing returns every active subscription across owners.
    /// The `admin` role short-circuits in `RbacEvaluator::authorize` so
    /// the empty grants set is sufficient.
    #[tokio::test]
    async fn admin_list_all_returns_active_subs_across_owners_for_admin() {
        let admin = caller_with_roles(&["admin"]);
        let owner_a = caller_with_roles(&["dev"]);
        let owner_b = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        fx.uc
            .create(&owner_a, req("a", nats_target(), filter_owned()))
            .await
            .unwrap();
        fx.uc
            .create(&owner_b, req("b", nats_target(), filter_owned()))
            .await
            .unwrap();

        let items = fx.uc.admin_list_all(&admin).await.unwrap();
        assert_eq!(items.len(), 2);
    }

    /// Non-admin caller is rejected at the use-case authz boundary even
    /// when the route extractor lets the request through.
    #[tokio::test]
    async fn admin_list_all_returns_not_authorized_for_non_admin() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let err = fx.uc.admin_list_all(&actor).await.unwrap_err();
        assert!(matches!(err, SubscriptionError::NotAuthorized));
    }

    // ---------------- update ----------------------------------------------

    #[tokio::test]
    async fn update_changing_only_description_emits_subscription_updated() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let sub = fx
            .uc
            .create(&actor, req("u", https_target(), filter_owned()))
            .await
            .unwrap();
        let req_upd = UpdateSubscriptionRequest {
            description: Some(Some("new desc".into())),
            ..Default::default()
        };
        let updated = fx.uc.update(&actor, sub.id, req_upd).await.unwrap();
        assert_eq!(updated.description.as_deref(), Some("new desc"));
        let (_, event, _) = last_appended_event(&fx.events);
        match event {
            DomainEvent::SubscriptionUpdated(e) => {
                assert_eq!(e.changed_fields, vec!["description".to_string()]);
            }
            other => panic!("expected SubscriptionUpdated, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn update_with_no_changes_returns_subscription_and_emits_nothing() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let sub = fx
            .uc
            .create(&actor, req("u", https_target(), filter_owned()))
            .await
            .unwrap();
        let before_count = fx.events.appended_batches().len();
        let _ = fx
            .uc
            .update(&actor, sub.id, UpdateSubscriptionRequest::default())
            .await
            .unwrap();
        assert_eq!(fx.events.appended_batches().len(), before_count);
    }

    #[tokio::test]
    async fn update_shrinking_filter_repositories_allowed() {
        let repo_a = Uuid::new_v4();
        let repo_b = Uuid::new_v4();
        let actor = caller_with_roles(&["dev"]);
        // Grant Read on both.
        let eval = RbacEvaluator::new(claims_grants_on(
            "dev",
            &[(repo_a, Permission::Read), (repo_b, Permission::Read)],
        ));
        let fx = wire(
            eval,
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        seed_repo(&fx.repos, repo_a);
        seed_repo(&fx.repos, repo_b);
        let sub = fx
            .uc
            .create(
                &actor,
                req("shr", https_target(), filter_some(vec![repo_a, repo_b])),
            )
            .await
            .unwrap();
        let upd = UpdateSubscriptionRequest {
            filter: Some(filter_some(vec![repo_a])),
            ..Default::default()
        };
        fx.uc
            .update(&actor, sub.id, upd)
            .await
            .expect("shrinking ok");
    }

    #[tokio::test]
    async fn update_widening_filter_repositories_rejected_as_cap_exceeds() {
        let repo_a = Uuid::new_v4();
        let repo_b = Uuid::new_v4();
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            eval_with_grant("dev", repo_a, Permission::Read),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        seed_repo(&fx.repos, repo_a);
        let sub = fx
            .uc
            .create(&actor, req("w", https_target(), filter_some(vec![repo_a])))
            .await
            .unwrap();
        let upd = UpdateSubscriptionRequest {
            filter: Some(filter_some(vec![repo_a, repo_b])),
            ..Default::default()
        };
        let err = fx.uc.update(&actor, sub.id, upd).await.unwrap_err();
        match err {
            SubscriptionError::RepoScopeExceedsTokenCap { offending } => {
                assert_eq!(offending, vec![repo_b]);
            }
            other => panic!("expected RepoScopeExceedsTokenCap, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn update_widening_scope_from_some_to_all_rejected_as_cap_exceeds() {
        let repo_a = Uuid::new_v4();
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            eval_with_grant("dev", repo_a, Permission::Read),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        seed_repo(&fx.repos, repo_a);
        let sub = fx
            .uc
            .create(&actor, req("w", https_target(), filter_some(vec![repo_a])))
            .await
            .unwrap();
        let upd = UpdateSubscriptionRequest {
            filter: Some(filter_all()),
            ..Default::default()
        };
        let err = fx.uc.update(&actor, sub.id, upd).await.unwrap_err();
        assert!(matches!(
            err,
            SubscriptionError::RepoScopeExceedsTokenCap { .. }
        ));
    }

    #[tokio::test]
    async fn update_widening_some_to_owned_by_actor_rejected() {
        let repo_a = Uuid::new_v4();
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            eval_with_grant("dev", repo_a, Permission::Read),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        seed_repo(&fx.repos, repo_a);
        let sub = fx
            .uc
            .create(&actor, req("w", https_target(), filter_some(vec![repo_a])))
            .await
            .unwrap();
        let upd = UpdateSubscriptionRequest {
            filter: Some(filter_owned()),
            ..Default::default()
        };
        let err = fx.uc.update(&actor, sub.id, upd).await.unwrap_err();
        assert!(matches!(
            err,
            SubscriptionError::RepoScopeExceedsTokenCap { .. }
        ));
    }

    #[tokio::test]
    async fn update_shrinking_all_to_owned_allowed() {
        let actor = caller_with_roles(&["admin"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let sub = fx
            .uc
            .create(&actor, req("u", https_target(), filter_all()))
            .await
            .unwrap();
        let upd = UpdateSubscriptionRequest {
            filter: Some(filter_owned()),
            ..Default::default()
        };
        fx.uc.update(&actor, sub.id, upd).await.expect("shrink ok");
    }

    #[tokio::test]
    async fn update_owned_to_some_adding_constraint_allowed() {
        let repo_a = Uuid::new_v4();
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            eval_with_grant("dev", repo_a, Permission::Read),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        seed_repo(&fx.repos, repo_a);
        let sub = fx
            .uc
            .create(&actor, req("u", https_target(), filter_owned()))
            .await
            .unwrap();
        let upd = UpdateSubscriptionRequest {
            filter: Some(filter_some(vec![repo_a])),
            ..Default::default()
        };
        fx.uc
            .update(&actor, sub.id, upd)
            .await
            .expect("constraint add ok");
    }

    #[tokio::test]
    async fn update_rejects_high_volume_event_type_via_filter_change() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let sub = fx
            .uc
            .create(&actor, req("u", https_target(), filter_owned()))
            .await
            .unwrap();
        let mut bad = filter_owned();
        bad.event_types = EventTypeFilter::Some(vec![EventTypeKind::AuthenticationAttempted]);
        let upd = UpdateSubscriptionRequest {
            filter: Some(bad),
            ..Default::default()
        };
        let err = fx.uc.update(&actor, sub.id, upd).await.unwrap_err();
        assert!(matches!(err, SubscriptionError::UnsupportedEventType(_)));
    }

    #[tokio::test]
    async fn update_rejects_plaintext_webhook_target() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let sub = fx
            .uc
            .create(&actor, req("u", https_target(), filter_owned()))
            .await
            .unwrap();
        let upd = UpdateSubscriptionRequest {
            target: Some(http_target()),
            ..Default::default()
        };
        let err = fx.uc.update(&actor, sub.id, upd).await.unwrap_err();
        assert!(matches!(err, SubscriptionError::PlaintextWebhookDisallowed));
    }

    #[tokio::test]
    async fn update_rejects_invalid_nats_subject() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let sub = fx
            .uc
            .create(&actor, req("u", https_target(), filter_owned()))
            .await
            .unwrap();
        let upd = UpdateSubscriptionRequest {
            target: Some(SubscriptionTarget::NatsJetStream {
                subject: "hort.*.broken".into(),
            }),
            ..Default::default()
        };
        let err = fx.uc.update(&actor, sub.id, upd).await.unwrap_err();
        assert!(matches!(err, SubscriptionError::InvalidNatsSubject));
    }

    #[tokio::test]
    async fn update_target_change_routes_through_ssrf_guard() {
        let actor = caller_with_roles(&["dev"]);
        let cfg = SubscriptionUseCaseConfig {
            allow_plaintext_webhooks: false,
            allow_nonroutable_webhook_targets: false,
        };
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::deny(
                SsrfBlockReason::IpLiteralNotRoutable,
            )),
            cfg,
        );
        // First create using `allow_nonroutable=false` would fail; flip
        // the mock to allow then to deny — we re-create with allow
        // before flipping to deny for the update.
        // Simpler approach: wire with allow=true config, then update
        // tightens to deny via new instance — but we can't change cfg
        // mid-test. Instead: use NATS for the initial create.
        let sub = fx
            .uc
            .create(&actor, req("u", nats_target(), filter_owned()))
            .await
            .unwrap();
        let new_target = SubscriptionTarget::Webhook {
            url: "https://blocked.example/h".parse().unwrap(),
            secret_ref: webhook_secret_ref(),
        };
        let upd = UpdateSubscriptionRequest {
            target: Some(new_target),
            ..Default::default()
        };
        let err = fx.uc.update(&actor, sub.id, upd).await.unwrap_err();
        assert!(matches!(
            err,
            SubscriptionError::WebhookTargetNotRoutable { .. }
        ));
    }

    #[tokio::test]
    async fn update_changing_name_emits_updated_event_with_name_field() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let sub = fx
            .uc
            .create(&actor, req("u", https_target(), filter_owned()))
            .await
            .unwrap();
        let upd = UpdateSubscriptionRequest {
            name: Some("renamed".into()),
            ..Default::default()
        };
        fx.uc.update(&actor, sub.id, upd).await.unwrap();
        let (_, event, _) = last_appended_event(&fx.events);
        match event {
            DomainEvent::SubscriptionUpdated(e) => {
                assert!(e.changed_fields.contains(&"name".to_string()));
            }
            other => panic!("expected SubscriptionUpdated, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn update_changing_state_emits_updated_event_with_state_field() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let sub = fx
            .uc
            .create(&actor, req("u", https_target(), filter_owned()))
            .await
            .unwrap();
        let upd = UpdateSubscriptionRequest {
            state: Some(SubscriptionState::Paused),
            ..Default::default()
        };
        fx.uc.update(&actor, sub.id, upd).await.unwrap();
        let (_, event, _) = last_appended_event(&fx.events);
        match event {
            DomainEvent::SubscriptionUpdated(e) => {
                assert!(e.changed_fields.contains(&"state".to_string()));
            }
            other => panic!("expected SubscriptionUpdated, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn update_returns_not_found_for_unknown_id() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let err = fx
            .uc
            .update(
                &actor,
                SubscriptionId(Uuid::new_v4()),
                UpdateSubscriptionRequest::default(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, SubscriptionError::SubscriptionNotFound));
    }

    #[tokio::test]
    async fn update_rejects_when_neither_owner_nor_admin() {
        let owner = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let sub = fx
            .uc
            .create(&owner, req("u", https_target(), filter_owned()))
            .await
            .unwrap();
        let other = caller_with_roles(&["dev"]);
        let err = fx
            .uc
            .update(&other, sub.id, UpdateSubscriptionRequest::default())
            .await
            .unwrap_err();
        assert!(matches!(err, SubscriptionError::NotAuthorized));
    }

    // ---------------- pause / resume --------------------------------------

    #[tokio::test]
    async fn pause_then_resume_round_trip() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let sub = fx
            .uc
            .create(&actor, req("p", https_target(), filter_owned()))
            .await
            .unwrap();
        fx.uc.pause(&actor, sub.id).await.unwrap();
        let after_pause = fx.uc.get_for_owner(&actor, sub.id).await.unwrap();
        assert!(matches!(after_pause.state, SubscriptionState::Paused));
        fx.uc.resume(&actor, sub.id).await.unwrap();
        let after_resume = fx.uc.get_for_owner(&actor, sub.id).await.unwrap();
        assert!(matches!(after_resume.state, SubscriptionState::Active));
    }

    #[tokio::test]
    async fn pause_emits_subscription_paused_event() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let sub = fx
            .uc
            .create(&actor, req("p", https_target(), filter_owned()))
            .await
            .unwrap();
        fx.uc.pause(&actor, sub.id).await.unwrap();
        let (_, event, _) = last_appended_event(&fx.events);
        assert!(matches!(event, DomainEvent::SubscriptionPaused(_)));
    }

    #[tokio::test]
    async fn resume_emits_subscription_resumed_event() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let sub = fx
            .uc
            .create(&actor, req("p", https_target(), filter_owned()))
            .await
            .unwrap();
        fx.uc.pause(&actor, sub.id).await.unwrap();
        fx.uc.resume(&actor, sub.id).await.unwrap();
        let (_, event, _) = last_appended_event(&fx.events);
        assert!(matches!(event, DomainEvent::SubscriptionResumed(_)));
    }

    #[tokio::test]
    async fn pause_rejects_when_neither_owner_nor_admin() {
        let owner = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let sub = fx
            .uc
            .create(&owner, req("p", https_target(), filter_owned()))
            .await
            .unwrap();
        let other = caller_with_roles(&["dev"]);
        let err = fx.uc.pause(&other, sub.id).await.unwrap_err();
        assert!(matches!(err, SubscriptionError::NotAuthorized));
    }

    #[tokio::test]
    async fn resume_rejects_when_neither_owner_nor_admin() {
        let owner = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let sub = fx
            .uc
            .create(&owner, req("p", https_target(), filter_owned()))
            .await
            .unwrap();
        let other = caller_with_roles(&["dev"]);
        let err = fx.uc.resume(&other, sub.id).await.unwrap_err();
        assert!(matches!(err, SubscriptionError::NotAuthorized));
    }

    #[tokio::test]
    async fn pause_returns_not_found_for_unknown_id() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let err = fx
            .uc
            .pause(&actor, SubscriptionId(Uuid::new_v4()))
            .await
            .unwrap_err();
        assert!(matches!(err, SubscriptionError::SubscriptionNotFound));
    }

    #[tokio::test]
    async fn resume_returns_not_found_for_unknown_id() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let err = fx
            .uc
            .resume(&actor, SubscriptionId(Uuid::new_v4()))
            .await
            .unwrap_err();
        assert!(matches!(err, SubscriptionError::SubscriptionNotFound));
    }

    // ---------------- delete ----------------------------------------------

    #[tokio::test]
    async fn delete_emits_subscription_deleted_event() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let sub = fx
            .uc
            .create(&actor, req("d", https_target(), filter_owned()))
            .await
            .unwrap();
        fx.uc.delete(&actor, sub.id).await.unwrap();
        assert_eq!(fx.subs.count(), 0);
        let (_, event, _) = last_appended_event(&fx.events);
        assert!(matches!(event, DomainEvent::SubscriptionDeleted(_)));
    }

    #[tokio::test]
    async fn delete_returns_not_authorized_when_neither_owner_nor_admin() {
        let owner = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let sub = fx
            .uc
            .create(&owner, req("d", https_target(), filter_owned()))
            .await
            .unwrap();
        let other = caller_with_roles(&["dev"]);
        let err = fx.uc.delete(&other, sub.id).await.unwrap_err();
        assert!(matches!(err, SubscriptionError::NotAuthorized));
        // Row not deleted on auth fail.
        assert_eq!(fx.subs.count(), 1);
    }

    #[tokio::test]
    async fn delete_returns_not_found_for_unknown_id() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let err = fx
            .uc
            .delete(&actor, SubscriptionId(Uuid::new_v4()))
            .await
            .unwrap_err();
        assert!(matches!(err, SubscriptionError::SubscriptionNotFound));
    }

    // ---------------- disable (system) ------------------------------------

    #[tokio::test]
    async fn disable_emits_event_and_sets_state() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let sub = fx
            .uc
            .create(&actor, req("x", https_target(), filter_owned()))
            .await
            .unwrap();
        fx.uc
            .disable(sub.id, DisableReason::DeliveryFailureBudgetExhausted)
            .await
            .unwrap();
        let after = fx.uc.get_for_owner(&actor, sub.id).await.unwrap();
        match after.state {
            SubscriptionState::Disabled { reason, .. } => {
                assert_eq!(reason, DisableReason::DeliveryFailureBudgetExhausted);
            }
            other => panic!("expected Disabled, got {other:?}"),
        }
        let (_, event, actor_field) = last_appended_event(&fx.events);
        assert!(matches!(event, DomainEvent::SubscriptionDisabled(_)));
        // System actor (not Api).
        assert!(matches!(actor_field, Actor::Internal(_)));
    }

    #[tokio::test]
    async fn disable_idempotent_when_already_disabled() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let sub = fx
            .uc
            .create(&actor, req("x", https_target(), filter_owned()))
            .await
            .unwrap();
        fx.uc
            .disable(sub.id, DisableReason::OperatorDisabled)
            .await
            .unwrap();
        let batches_after_first = fx.events.appended_batches().len();
        fx.uc
            .disable(sub.id, DisableReason::DeliveryFailureBudgetExhausted)
            .await
            .unwrap();
        // No new event emitted on the second call.
        assert_eq!(fx.events.appended_batches().len(), batches_after_first);
    }

    #[tokio::test]
    async fn disable_returns_not_found_for_unknown_id() {
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let err = fx
            .uc
            .disable(
                SubscriptionId(Uuid::new_v4()),
                DisableReason::OperatorDisabled,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, SubscriptionError::SubscriptionNotFound));
    }

    // ---------------- record_delivery_progress ----------------------------

    #[tokio::test]
    async fn record_delivery_progress_updates_position_no_event_emitted() {
        let actor = caller_with_roles(&["dev"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let sub = fx
            .uc
            .create(&actor, req("p", https_target(), filter_owned()))
            .await
            .unwrap();
        let batches_before = fx.events.appended_batches().len();
        fx.uc
            .record_delivery_progress(sub.id, 42, None)
            .await
            .unwrap();
        assert_eq!(fx.events.appended_batches().len(), batches_before);
        let after = fx.uc.get_for_owner(&actor, sub.id).await.unwrap();
        assert_eq!(after.last_delivered_position, Some(42));
    }

    // ---------------- compute_filter_summary / category helpers -----------

    #[test]
    fn compute_filter_summary_owned_by_actor_with_event_type_all() {
        let f = filter_owned();
        let s = compute_filter_summary(&f);
        assert_eq!(s.event_type_count, 0); // sentinel for `All`
        assert_eq!(s.repository_scope_kind, RepositoryScopeKind::OwnedByActor);
        assert_eq!(s.predicate_hash, [0u8; 32]);
        assert_eq!(s.categories, vec!["artifact".to_string()]);
    }

    #[test]
    fn compute_filter_summary_some_records_count() {
        let mut f = filter_some(vec![Uuid::new_v4()]);
        f.event_types = EventTypeFilter::Some(vec![
            EventTypeKind::ArtifactIngested,
            EventTypeKind::ArtifactPromoted,
        ]);
        let s = compute_filter_summary(&f);
        assert_eq!(s.event_type_count, 2);
        assert_eq!(s.repository_scope_kind, RepositoryScopeKind::Some);
    }

    #[test]
    fn compute_filter_summary_all_scope_records_kind() {
        let f = filter_all();
        let s = compute_filter_summary(&f);
        assert_eq!(s.repository_scope_kind, RepositoryScopeKind::All);
    }

    #[test]
    fn category_to_string_covers_every_variant() {
        // Closed-enum coverage — `StreamCategory` has 10 variants.
        let cats = [
            StreamCategory::Artifact,
            StreamCategory::Policy,
            StreamCategory::Admin,
            StreamCategory::Ref,
            StreamCategory::ArtifactGroup,
            StreamCategory::Curation,
            StreamCategory::Repository,
            StreamCategory::AuthAttempts,
            StreamCategory::Authorization,
            StreamCategory::User,
        ];
        let names: Vec<String> = cats.iter().map(category_to_string).collect();
        assert_eq!(names.len(), 10);
        // Each name is lower-case ASCII and non-empty.
        for n in &names {
            assert!(!n.is_empty());
            assert!(n.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
        }
    }

    #[test]
    fn target_kind_wire_projects_correctly() {
        assert_eq!(target_kind_wire(&https_target()), TargetKindWire::Webhook);
        assert_eq!(
            target_kind_wire(&nats_target()),
            TargetKindWire::NatsJetStream
        );
    }

    // ---- Config defensive: SubscriptionUseCaseConfig is not Deserialize.
    //
    // We can't conveniently assert "type T does NOT implement trait U" on
    // stable Rust without a dedicated crate. Per the type's doc comment +
    // CLAUDE.md anti-pattern checklist, the absence of `#[derive(Deserialize)]`
    // is the enforcement; review gates catch regressions. This comment is
    // the recorded review hook.

    // ====================================================================
    // snapshot_claims capture
    // ====================================================================

    /// `filter` over a single non-privileged category — used by the
    /// snapshot-capture tests so the privileged-category gate never
    /// short-circuits the path before the capture is reached.
    fn filter_owned_repo_category() -> SubscriptionFilter {
        SubscriptionFilter {
            categories: vec![StreamCategory::Repository],
            event_types: EventTypeFilter::All,
            repositories: RepositoryScope::OwnedByActor,
            named_predicates: vec![],
        }
    }

    /// `filter` whose `categories` includes a privileged
    /// (`ADMIN_CATEGORIES`) member — the privileged-category gate input.
    fn filter_privileged_category(cat: StreamCategory) -> SubscriptionFilter {
        SubscriptionFilter {
            categories: vec![cat],
            event_types: EventTypeFilter::All,
            repositories: RepositoryScope::OwnedByActor,
            named_predicates: vec![],
        }
    }

    #[tokio::test]
    async fn create_via_oidc_principal_captures_both_claims_verbatim() {
        let actor = caller_with_roles(&["developer", "team-alpha"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let sub = fx
            .uc
            .create(
                &actor,
                req("oidc-relay", https_target(), filter_owned_repo_category()),
            )
            .await
            .expect("non-privileged category, non-admin ok");
        assert_eq!(
            sub.snapshot_claims,
            vec!["developer".to_string(), "team-alpha".to_string()],
            "snapshot_claims must carry the principal's claims verbatim"
        );
        // Persisted row carries the same snapshot.
        assert_eq!(
            fx.subs.find_by_id(sub.id).await.unwrap().snapshot_claims,
            vec!["developer".to_string(), "team-alpha".to_string()]
        );
    }

    #[tokio::test]
    async fn create_via_pat_principal_empty_claims_captures_empty() {
        let actor = caller_with_roles(&[]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let sub = fx
            .uc
            .create(
                &actor,
                req("pat-relay", https_target(), filter_owned_repo_category()),
            )
            .await
            .expect("empty-claims PAT principal, non-privileged category ok");
        assert!(
            sub.snapshot_claims.is_empty(),
            "PAT principal with claims=[] snapshots []"
        );
    }

    #[tokio::test]
    async fn create_via_pat_admin_principal_captures_admin_claim() {
        let actor = caller_with_roles(&["admin"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let sub = fx
            .uc
            .create(
                &actor,
                req("admin-relay", https_target(), filter_owned_repo_category()),
            )
            .await
            .expect("admin principal ok");
        assert_eq!(sub.snapshot_claims, vec!["admin".to_string()]);
    }

    #[tokio::test]
    async fn update_via_oidc_after_pat_create_replaces_snapshot() {
        // Created via PAT principal (claims=[]), then PATCHed via an
        // OIDC principal — snapshot is fully replaced with the OIDC
        // principal's claims (full-replace authority floor).
        let pat_actor = caller_with_roles(&[]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let sub = fx
            .uc
            .create(
                &pat_actor,
                req("relay", https_target(), filter_owned_repo_category()),
            )
            .await
            .unwrap();
        assert!(sub.snapshot_claims.is_empty());

        let mut oidc_actor = caller_with_roles(&["developer", "team-alpha"]);
        // Same owner so require_owner_or_admin passes.
        oidc_actor.user_id = pat_actor.user_id;
        let upd = UpdateSubscriptionRequest {
            description: Some(Some("touch".into())),
            ..Default::default()
        };
        let updated = fx.uc.update(&oidc_actor, sub.id, upd).await.unwrap();
        assert_eq!(
            updated.snapshot_claims,
            vec!["developer".to_string(), "team-alpha".to_string()],
            "update re-captures the acting principal's claims (full replace)"
        );
    }

    #[tokio::test]
    async fn update_via_pat_nonadmin_clears_previously_rich_snapshot() {
        // Created via OIDC (rich claims), PATCHed via a PAT non-admin
        // principal (claims=[]) — snapshot replaced with [] (the
        // PATCH-via-PAT-clears wrinkle).
        let oidc_actor = caller_with_roles(&["developer", "team-alpha"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let sub = fx
            .uc
            .create(
                &oidc_actor,
                req("relay", https_target(), filter_owned_repo_category()),
            )
            .await
            .unwrap();
        assert_eq!(sub.snapshot_claims.len(), 2);

        let mut pat_actor = caller_with_roles(&[]);
        pat_actor.user_id = oidc_actor.user_id;
        let upd = UpdateSubscriptionRequest {
            description: Some(Some("touch".into())),
            ..Default::default()
        };
        let updated = fx.uc.update(&pat_actor, sub.id, upd).await.unwrap();
        assert!(
            updated.snapshot_claims.is_empty(),
            "PATCH via PAT non-admin replaces a previously-rich snapshot with []"
        );
    }

    #[tokio::test]
    async fn subscription_created_event_carries_snapshot_claims_count() {
        let actor = caller_with_roles(&["developer", "team-alpha"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        fx.uc
            .create(
                &actor,
                req("relay", https_target(), filter_owned_repo_category()),
            )
            .await
            .unwrap();
        let (_, event, _) = last_appended_event(&fx.events);
        match event {
            DomainEvent::SubscriptionCreated(e) => {
                assert_eq!(e.snapshot_claims_count, 2);
            }
            other => panic!("expected SubscriptionCreated, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn subscription_updated_event_carries_snapshot_claims_count() {
        let actor = caller_with_roles(&["developer", "team-alpha"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let sub = fx
            .uc
            .create(
                &actor,
                req("relay", https_target(), filter_owned_repo_category()),
            )
            .await
            .unwrap();
        let upd = UpdateSubscriptionRequest {
            description: Some(Some("touch".into())),
            ..Default::default()
        };
        fx.uc.update(&actor, sub.id, upd).await.unwrap();
        let (_, event, _) = last_appended_event(&fx.events);
        match event {
            DomainEvent::SubscriptionUpdated(e) => {
                assert_eq!(e.snapshot_claims_count, 2);
            }
            other => panic!("expected SubscriptionUpdated, got {other:?}"),
        }
    }

    // ====================================================================
    // Privileged-category authority gate (create/update legs)
    // ====================================================================

    #[tokio::test]
    async fn create_nonadmin_privileged_category_denied() {
        // Non-admin principal, filter.categories = [Authorization] →
        // create denied with the new distinct reason, no Subscription
        // constructed, SubscriptionCreationDenied emitted.
        let actor = caller_with_roles(&["developer"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let err = fx
            .uc
            .create(
                &actor,
                req(
                    "exfil",
                    https_target(),
                    filter_privileged_category(StreamCategory::Authorization),
                ),
            )
            .await
            .expect_err("non-admin privileged-category create must be denied");
        assert!(matches!(err, SubscriptionError::NotAuthorized));
        assert_eq!(fx.subs.count(), 0, "no subscription row written");
        assert_last_event_is_denial(
            &fx.events,
            &actor,
            &SubscriptionDenialReason::PrivilegedCategoryRequiresAdmin,
        );
    }

    #[tokio::test]
    async fn create_nonadmin_repository_category_succeeds_no_regression() {
        let actor = caller_with_roles(&["developer"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        fx.uc
            .create(
                &actor,
                req(
                    "ok",
                    https_target(),
                    filter_privileged_category(StreamCategory::Repository),
                ),
            )
            .await
            .expect("non-privileged Repository category, non-admin must succeed");
        assert_eq!(fx.subs.count(), 1);
    }

    #[tokio::test]
    async fn create_admin_multi_privileged_categories_succeeds() {
        let actor = caller_with_roles(&["admin"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let filter = SubscriptionFilter {
            categories: vec![StreamCategory::Policy, StreamCategory::Admin],
            event_types: EventTypeFilter::All,
            repositories: RepositoryScope::OwnedByActor,
            named_predicates: vec![],
        };
        fx.uc
            .create(&actor, req("admin-audit", https_target(), filter))
            .await
            .expect("admin principal may subscribe privileged categories");
        assert_eq!(fx.subs.count(), 1);
    }

    #[tokio::test]
    async fn update_adding_privileged_category_for_nonadmin_denied_row_unchanged() {
        // A non-admin owner updates an existing (non-privileged)
        // subscription to add a privileged category → denied; the
        // pre-existing persisted row is unchanged.
        let actor = caller_with_roles(&["developer"]);
        let fx = wire(
            empty_eval(),
            Arc::new(MockWebhookTargetGuard::allow()),
            default_cfg(),
        );
        let sub = fx
            .uc
            .create(
                &actor,
                req("relay", https_target(), filter_owned_repo_category()),
            )
            .await
            .unwrap();
        let before = fx.subs.find_by_id(sub.id).await.unwrap();

        let upd = UpdateSubscriptionRequest {
            filter: Some(filter_privileged_category(StreamCategory::Authorization)),
            ..Default::default()
        };
        let err = fx
            .uc
            .update(&actor, sub.id, upd)
            .await
            .expect_err("non-admin adding a privileged category must be denied");
        assert!(matches!(err, SubscriptionError::NotAuthorized));
        let after = fx.subs.find_by_id(sub.id).await.unwrap();
        assert_eq!(
            after.filter, before.filter,
            "denied update must not mutate the persisted row"
        );
        assert_eq!(after.snapshot_claims, before.snapshot_claims);
        assert_last_event_is_denial(
            &fx.events,
            &actor,
            &SubscriptionDenialReason::PrivilegedCategoryRequiresAdmin,
        );
    }
}
