//! TaskHandler for the fallback PAT rotation reconciler
//! (ADR 0018; see `docs/auth-catalog.md`).
//!
//! Triggered by the k8s CronJob (or operator host cron) hitting
//! `POST /api/v1/admin/tasks/service-account-rotation` (the
//! admin-task framework). Default schedule `*/15 * * * *`. The
//! handler is a stateless tick — the source-of-truth for "last
//! rotated" is the k8s Secret's `project-hort.de/last-rotated` annotation
//! (annotation rather than label because RFC 3339 timestamps contain
//! `:`, which k8s forbids in label values), NOT a database column.
//! Re-running the handler is idempotent because the freshness check
//! is the gate.
//!
//! Per-tick flow:
//!
//! 1. List all `ServiceAccount` rows with `fallback_rotation` set.
//! 2. For each SA, apply the decide-branch logic:
//!    - If `target_secret_namespace` is NOT in the worker's authorized
//!      `rotation_namespaces` set → warn + metric, skip.
//!    - Read the existing Secret via `KubernetesSecretWriter::read_managed`.
//!    - If the existing Secret's `managed_by != Some("hort-worker")` →
//!      warn + metric, skip (collision; operator must delete the
//!      Secret to hand off management).
//!    - If the existing Secret is fresh (`last_rotated` within
//!      `rotation_interval` of now) → debug + metric, skip.
//!    - Otherwise (missing or stale): mint a fresh PAT, upsert the
//!      Secret, emit `ServiceAccountTokenRotated`, metric.
//! 3. Return a `TaskOutcome::Completed` with per-result counts.
//!
//! # Grace window
//!
//! The reconciler does NOT revoke the previous token. Old tokens
//! expire naturally at `previous.expires_at`. The
//! `validity ≥ 2 × rotation_interval` constraint (enforced at
//! apply time AND by the DB CHECK) guarantees an overlap of at least
//! one `rotation_interval` so consumers have a full rotation cycle to
//! reload the new Secret before the old token becomes unusable.
//!
//! Helm chart wiring (CronJob, per-namespace RBAC), operator how-tos,
//! and the federation branch on `/auth/token-exchange` live elsewhere
//! (`deploy/helm/`, `docs/architecture/how-to/`, the token-exchange
//! handler).

use std::collections::HashSet;
use std::sync::Arc;

use chrono::Utc;
use serde_json::json;
use uuid::Uuid;
use zeroize::Zeroizing;

use hort_domain::error::DomainResult;
use hort_domain::events::{
    system_actor, DomainEvent, SerdeSecretFormat, ServiceAccountTokenRotated, StreamId,
};
use hort_domain::ports::event_store::{AppendEvents, EventStore, EventToAppend, ExpectedVersion};
use hort_domain::ports::kubernetes_secret_writer::{
    KubernetesSecretWriter, ManagedSecret, ManagedSecretSpec,
};
use hort_domain::ports::service_account_repository::ServiceAccountRepository;
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::BoxFuture;

use crate::metrics::{emit_rotation_result, set_rotation_lag_seconds, RotationResult};
use crate::use_cases::api_token_use_case::{ApiTokenUseCase, IssueTokenRequest};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Stable kind identifier used by the dispatch table + admin-task
/// endpoint. Hyphen-separated to match the task-kind convention.
const KIND: &str = "service-account-rotation";

/// `managed-by` label sentinel — the reconciler only manages Secrets
/// whose `project-hort.de/managed-by` projection matches this string. Any other
/// value is a collision (out-of-band creator) and the reconciler
/// refuses to overwrite.
const MANAGED_BY: &str = "hort-worker";

/// Token `name` written into `api_tokens.name` and the request
/// description. Each rotation produces a fresh PAT; the name is the
/// SA name so an operator running `hort-cli admin token list` sees the
/// SA-driven origin without parsing the description.
const TOKEN_DESCRIPTION_PREFIX: &str = "fallback rotation for service account ";

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// [`TaskHandler`] for the fallback PAT-rotation reconciler. Constructed
/// at composition time with the five ports + three config values it
/// touches.
///
/// Stateless: no per-tick local state survives a `run` call. The
/// freshness check is driven entirely by the k8s Secret's
/// `project-hort.de/last-rotated` annotation.
pub struct ServiceAccountRotationHandler {
    service_accounts: Arc<dyn ServiceAccountRepository>,
    secret_writer: Arc<dyn KubernetesSecretWriter>,
    api_tokens: Arc<ApiTokenUseCase>,
    events: Arc<dyn EventStore>,
    /// Set of k8s namespaces the worker is permitted to write Secrets
    /// in. Defence-in-depth against an SA pointing at an out-of-policy
    /// namespace (the chart wires this from
    /// `worker.rotation.targetNamespaces`).
    rotation_namespaces: HashSet<String>,
    /// Used to construct the `dockerconfigjson` `auths` map key. The
    /// registry host the SA's clients will authenticate against;
    /// derived from `HORT_PUBLIC_BASE_URL` at composition time.
    public_registry_host: String,
    /// `METRICS_INCLUDE_SERVICE_ACCOUNT_LABEL` toggle.
    /// Defaults to `true`; the composition root flips it
    /// from `Config::include_service_account_label`. When `false`,
    /// `hort_rotation_lag_seconds` and (downstream)
    /// `hort_service_account_authenticated_total` collapse the per-SA
    /// label to `_all`.
    include_service_account_label: bool,
}

impl ServiceAccountRotationHandler {
    /// Construct the handler from its port dependencies + config.
    pub fn new(
        service_accounts: Arc<dyn ServiceAccountRepository>,
        secret_writer: Arc<dyn KubernetesSecretWriter>,
        api_tokens: Arc<ApiTokenUseCase>,
        events: Arc<dyn EventStore>,
        rotation_namespaces: HashSet<String>,
        public_registry_host: String,
    ) -> Self {
        Self {
            service_accounts,
            secret_writer,
            api_tokens,
            events,
            rotation_namespaces,
            public_registry_host,
            // Default-`true` keeps existing call sites
            // source-compatible; composition flips via
            // [`Self::with_include_service_account_label`].
            include_service_account_label: true,
        }
    }

    /// Builder-style setter for the `METRICS_INCLUDE_SERVICE_ACCOUNT_LABEL`
    /// toggle. The composition root threads
    /// `Config::include_service_account_label` through here so a single
    /// env-var flip governs both per-SA emission sites
    /// (`hort_rotation_lag_seconds` here and
    /// `hort_service_account_authenticated_total` on the auth paths).
    pub fn with_include_service_account_label(mut self, include: bool) -> Self {
        self.include_service_account_label = include;
        self
    }
}

impl TaskHandler for ServiceAccountRotationHandler {
    fn kind(&self) -> &'static str {
        KIND
    }

    #[tracing::instrument(skip(self))]
    fn run<'a>(
        &'a self,
        _params: &'a serde_json::Value,
        _ctx: TaskContext,
    ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
        Box::pin(async move {
            let now = Utc::now();

            // 1. List all SAs. The aggregate read composes the
            //    sub-aggregates (`federated_identities`,
            //    `fallback_rotation`) inside the adapter.
            let all = match self.service_accounts.list().await {
                Ok(rows) => rows,
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        "service account rotation: list failed; will retry on next tick",
                    );
                    return Ok(TaskOutcome::fail(format!("list failed: {err}"), true));
                }
            };

            // 2. Filter to SAs with `fallback_rotation` set; the
            //    reconciler only manages this branch. Federation-only
            //    SAs are out of scope here.
            let total = all
                .iter()
                .filter(|sa| sa.fallback_rotation.is_some())
                .count();

            let mut counts = TickCounts::default();

            for sa in &all {
                let Some(rotation) = sa.fallback_rotation.as_ref() else {
                    continue;
                };

                let ns = rotation.target_secret_namespace.as_str();
                let name = rotation.target_secret_name.as_str();

                // -- Gate 1: namespace authorization ------------------
                if !self.rotation_namespaces.contains(ns) {
                    tracing::warn!(
                        service_account = %sa.name,
                        namespace = %ns,
                        reason = "namespace_not_authorized",
                        "service account rotation: namespace not in worker's authorized set; skipping",
                    );
                    emit_rotation_result(RotationResult::NamespaceNotAuthorized);
                    counts.namespace_not_authorized += 1;
                    continue;
                }

                // -- Gate 2: read existing Secret + decide ------------
                let existing = match self.secret_writer.read_managed(ns, name).await {
                    Ok(s) => s,
                    Err(err) => {
                        // A read failure is treated like a write
                        // failure: log + count + continue. The next
                        // tick re-attempts. This is NOT mint_failed —
                        // we haven't reached the mint step yet.
                        tracing::error!(
                            service_account = %sa.name,
                            namespace = %ns,
                            name = %name,
                            error = %err,
                            "service account rotation: read_managed failed; will retry on next tick",
                        );
                        emit_rotation_result(RotationResult::WriteFailed);
                        counts.write_failed += 1;
                        continue;
                    }
                };

                let decision = decide(existing.as_ref(), rotation.rotation_interval, now);

                match decision {
                    Decision::Collision {
                        existing_managed_by,
                    } => {
                        tracing::warn!(
                            service_account = %sa.name,
                            namespace = %ns,
                            name = %name,
                            existing_managed_by = ?existing_managed_by,
                            reason = "collision",
                            "service account rotation: existing Secret not managed by hort-worker; skipping",
                        );
                        emit_rotation_result(RotationResult::Collision);
                        counts.collision += 1;
                        continue;
                    }
                    Decision::SkipFresh { age_secs } => {
                        tracing::debug!(
                            service_account = %sa.name,
                            namespace = %ns,
                            name = %name,
                            age_secs,
                            "service account rotation: existing Secret fresh; skipping",
                        );
                        set_rotation_lag_seconds(
                            &sa.name,
                            age_secs,
                            self.include_service_account_label,
                        );
                        emit_rotation_result(RotationResult::SkippedFresh);
                        counts.skipped_fresh += 1;
                        continue;
                    }
                    Decision::Rotate => {
                        // Fall through to mint + upsert below.
                    }
                }

                // -- Mint --------------------------------------------
                // `validity` is in seconds; clamp into u64 for the
                // request. The §3 apply-time invariant pins
                // `validity ≥ 2 × rotation_interval ≥ 2 h` so the
                // value is well-bounded.
                let validity_secs = rotation.validity.as_secs();
                let issue_request = IssueTokenRequest {
                    name: sa.name.clone(),
                    description: Some(format!("{TOKEN_DESCRIPTION_PREFIX}{}", sa.name)),
                    declared_permissions: Vec::new(),
                    repository_ids: None,
                    expires_in_days: None,
                    expires_in_seconds: Some(validity_secs),
                    // The rotation tick is not federation;
                    // the federation handler is the only
                    // call site that populates these audit fields.
                    federation_source: None,
                };
                let issued = match self
                    .api_tokens
                    .issue_for_service_account_system(sa.backing_user_id, issue_request)
                    .await
                {
                    Ok(t) => t,
                    Err(err) => {
                        tracing::error!(
                            service_account = %sa.name,
                            backing_user_id = %sa.backing_user_id,
                            error = %err,
                            "service account rotation: mint failed; will retry on next tick",
                        );
                        emit_rotation_result(RotationResult::MintFailed);
                        counts.mint_failed += 1;
                        continue;
                    }
                };

                // -- Upsert -------------------------------------------
                // Wrap the freshly-issued plaintext in `Zeroizing` IMMEDIATELY
                // so the buffer is zeroed when `spec` is dropped at the end of
                // the upsert call (or at the end of this loop iteration on
                // failure). Each rotation produces exactly one `Drop` of the
                // `Zeroizing<String>` — the spec is consumed by-value into
                // `upsert_managed`.
                let token_value = Zeroizing::new(issued.plaintext);
                let spec = ManagedSecretSpec {
                    format: rotation.format,
                    token_value,
                    token_id: issued.id,
                    service_account_name: sa.name.clone(),
                    last_rotated: now,
                    registry_host: self.public_registry_host.clone(),
                };

                if let Err(err) = self.secret_writer.upsert_managed(ns, name, spec).await {
                    tracing::error!(
                        service_account = %sa.name,
                        namespace = %ns,
                        name = %name,
                        token_id = %issued.id,
                        error = %err,
                        "service account rotation: upsert_managed failed; will retry on next tick",
                    );
                    emit_rotation_result(RotationResult::WriteFailed);
                    counts.write_failed += 1;
                    continue;
                }

                // -- Audit event --------------------------------------
                if let Err(err) = self
                    .emit_rotated_event(
                        sa.id,
                        &sa.name,
                        sa.backing_user_id,
                        issued.id,
                        ns,
                        name,
                        rotation.format.into(),
                    )
                    .await
                {
                    // Event append failed AFTER the Secret was
                    // successfully written. This is the trickiest
                    // failure: the next tick will see a fresh
                    // `last_rotated` annotation and skip rotating
                    // again, but the audit log is missing the entry. Surface
                    // as a write_failed metric (the workload-visible
                    // effect is "the audit row is missing") and
                    // continue to the next SA. Tick does NOT abort.
                    tracing::error!(
                        service_account = %sa.name,
                        token_id = %issued.id,
                        error = %err,
                        "service account rotation: event append failed AFTER Secret written; audit row missing",
                    );
                    emit_rotation_result(RotationResult::WriteFailed);
                    counts.write_failed += 1;
                    continue;
                }

                // Per-SA success at `debug!` only;
                // the per-tick SUMMARY at the bottom of `run()`
                // remains the operator-facing `info!` line.
                tracing::debug!(
                    service_account = %sa.name,
                    namespace = %ns,
                    name = %name,
                    format = %rotation.format.as_str(),
                    token_id = %issued.id,
                    "service account rotation: minted + wrote",
                );
                set_rotation_lag_seconds(&sa.name, 0.0, self.include_service_account_label);
                emit_rotation_result(RotationResult::Rotated);
                counts.rotated += 1;
            }

            tracing::info!(
                total,
                rotated = counts.rotated,
                skipped_fresh = counts.skipped_fresh,
                collision = counts.collision,
                namespace_not_authorized = counts.namespace_not_authorized,
                mint_failed = counts.mint_failed,
                write_failed = counts.write_failed,
                "service account rotation tick complete",
            );

            Ok(TaskOutcome::Completed {
                result_summary: json!({
                    "total": total,
                    "rotated": counts.rotated,
                    "skipped_fresh": counts.skipped_fresh,
                    "collision": counts.collision,
                    "namespace_not_authorized": counts.namespace_not_authorized,
                    "mint_failed": counts.mint_failed,
                    "write_failed": counts.write_failed,
                }),
            })
        })
    }
}

impl ServiceAccountRotationHandler {
    /// Append a [`ServiceAccountTokenRotated`] event to the backing
    /// user's stream (mirrors the `ApiTokenIssued` correlation pattern
    /// — both events land on the same stream so a future audit query
    /// joins them by proximity). Stream-id choice is documented in
    /// `crates/hort-domain/src/events/service_account_events.rs` module
    /// docstring.
    #[allow(clippy::too_many_arguments)]
    async fn emit_rotated_event(
        &self,
        sa_id: Uuid,
        sa_name: &str,
        backing_user_id: Uuid,
        token_id: Uuid,
        ns: &str,
        name: &str,
        format: SerdeSecretFormat,
    ) -> DomainResult<()> {
        // Append using `ExpectedVersion::Any` — the rotation handler
        // is the only writer on its own audit path, but the
        // backing-user stream is shared with `ApiTokenIssued` (also
        // emitted on the same call site by the system-mint above).
        // The two events are produced sequentially in this code path,
        // so a `Conflict` here would be a code bug in the issue path,
        // not a normal race. `Any` keeps the reconciler's tail
        // resilient to other writers landing on the same stream.
        let event = DomainEvent::ServiceAccountTokenRotated(ServiceAccountTokenRotated {
            service_account_id: sa_id,
            service_account_name: sa_name.to_string(),
            token_id,
            target_secret_namespace: ns.to_string(),
            target_secret_name: name.to_string(),
            format,
            at: Utc::now(),
        });
        self.events
            .append(AppendEvents {
                stream_id: StreamId::user(backing_user_id),
                expected_version: ExpectedVersion::Any,
                events: vec![EventToAppend::new(event)],
                correlation_id: Uuid::new_v4(),
                causation_id: None,
                actor: system_actor(),
            })
            .await
            .map(|_| ())
    }
}

// ---------------------------------------------------------------------------
// Decide-branch logic (pure, unit-testable)
// ---------------------------------------------------------------------------

/// Outcome of the per-SA decide pass. Kept out of the handler body so
/// the freshness arithmetic + collision rules are independently
/// testable from the rest of the orchestration.
#[derive(Debug, Clone, PartialEq)]
enum Decision {
    /// Existing Secret is managed by someone else — refuse to
    /// overwrite. `existing_managed_by` carries whatever string the
    /// `project-hort.de/managed-by` label actually has (or `None` if absent).
    Collision { existing_managed_by: Option<String> },
    /// Existing Secret is managed by `hort-worker` AND `last_rotated`
    /// is within `rotation_interval` of `now`. `age_secs` is `now -
    /// last_rotated` in seconds (for the lag gauge).
    SkipFresh { age_secs: f64 },
    /// Missing or stale — proceed to mint + upsert.
    Rotate,
}

/// Pure freshness + collision decision. Driven by the
/// `project-hort.de/managed-by` and `project-hort.de/last-rotated` projections off the
/// existing Secret (or the absence of the Secret entirely).
///
/// Decision matrix:
///
/// | `existing` | `managed_by` | `last_rotated` age | Decision |
/// |---|---|---|---|
/// | `None` | — | — | `Rotate` |
/// | `Some` | `!= Some("hort-worker")` | — | `Collision` |
/// | `Some` | `Some("hort-worker")` | `None` (absent / parse failure) | `Rotate` |
/// | `Some` | `Some("hort-worker")` | `< rotation_interval` | `SkipFresh` |
/// | `Some` | `Some("hort-worker")` | `>= rotation_interval` | `Rotate` |
fn decide(
    existing: Option<&ManagedSecret>,
    rotation_interval: std::time::Duration,
    now: chrono::DateTime<Utc>,
) -> Decision {
    let Some(secret) = existing else {
        return Decision::Rotate;
    };
    if secret.managed_by.as_deref() != Some(MANAGED_BY) {
        return Decision::Collision {
            existing_managed_by: secret.managed_by.clone(),
        };
    }
    let Some(last_rotated) = secret.last_rotated else {
        return Decision::Rotate;
    };
    let age = now - last_rotated;
    // `age` may be negative if `last_rotated` is in the future
    // (clock skew or a manual operator write). Treat negative age as
    // "fresh, 0 seconds old" — better than rotating prematurely.
    let age_secs = age.num_seconds().max(0) as f64;
    let interval_secs = rotation_interval.as_secs() as f64;
    if age_secs < interval_secs {
        Decision::SkipFresh { age_secs }
    } else {
        Decision::Rotate
    }
}

// ---------------------------------------------------------------------------
// Per-tick counts accumulator
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone, Copy)]
struct TickCounts {
    rotated: u32,
    skipped_fresh: u32,
    collision: u32,
    namespace_not_authorized: u32,
    mint_failed: u32,
    write_failed: u32,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;
    use std::time::Duration as StdDuration;

    use arc_swap::ArcSwap;
    use chrono::Duration as ChronoDuration;

    use hort_domain::entities::api_token::TokenKind;
    use hort_domain::entities::service_account::{FallbackRotation, SecretFormat, ServiceAccount};
    use hort_domain::entities::user::User;
    use hort_domain::error::DomainError;
    use hort_domain::events::{Actor, InternalActor};
    use hort_domain::ports::api_token_repository::ApiTokenRepository;
    use hort_domain::ports::user_repository::UserRepository;

    use crate::rbac::RbacEvaluator;
    use crate::use_cases::api_token_use_case::{ApiTokenIssuanceConfig, ApiTokenUseCase};
    use crate::use_cases::test_support::{
        MockApiTokenRepository, MockEventStore, MockKubernetesSecretWriter,
        MockServiceAccountRepository, MockUserRepository,
    };

    // ---------- helpers ---------------------------------------------------

    fn fixed_user_id() -> Uuid {
        Uuid::from_u128(0xA1)
    }

    fn registry_host() -> String {
        "registry.example.test".into()
    }

    fn rotation_interval() -> StdDuration {
        StdDuration::from_secs(6 * 3600)
    }

    fn validity() -> StdDuration {
        // 2 × rotation_interval per §3 invariant.
        StdDuration::from_secs(12 * 3600)
    }

    fn sample_rotation() -> FallbackRotation {
        FallbackRotation {
            target_secret_name: "ci-hort-token".into(),
            target_secret_namespace: "ci-system".into(),
            format: SecretFormat::Dockerconfigjson,
            rotation_interval: rotation_interval(),
            validity: validity(),
        }
    }

    fn sample_sa(name: &str) -> ServiceAccount {
        ServiceAccount {
            id: Uuid::new_v4(),
            name: name.into(),
            backing_user_id: fixed_user_id(),
            role: "developer".into(),
            repositories: vec!["pypi-internal".into()],
            federated_identities: vec![],
            fallback_rotation: Some(sample_rotation()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn sample_user() -> User {
        User {
            id: fixed_user_id(),
            username: "sa:ci-pusher".into(),
            email: "sa+ci-pusher@example.test".into(),
            auth_provider: hort_domain::entities::user::AuthProvider::Local,
            external_id: Some("local:sa:ci-pusher".into()),
            display_name: Some("ci-pusher".into()),
            is_active: true,
            is_admin: false,
            is_service_account: true,
            last_login_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn ns_set(items: &[&str]) -> HashSet<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    fn make_use_case() -> (
        Arc<ApiTokenUseCase>,
        Arc<MockApiTokenRepository>,
        Arc<MockUserRepository>,
        Arc<MockEventStore>,
    ) {
        let tokens = Arc::new(MockApiTokenRepository::new());
        let users = Arc::new(MockUserRepository::new());
        users.insert(sample_user());
        let events = Arc::new(MockEventStore::new());
        let rbac = Arc::new(ArcSwap::from_pointee(RbacEvaluator::new(Vec::new())));
        let uc = Arc::new(ApiTokenUseCase::new(
            tokens.clone() as Arc<dyn ApiTokenRepository>,
            users.clone() as Arc<dyn UserRepository>,
            crate::event_store_publisher::wrap_for_test(events.clone()),
            rbac,
            ApiTokenIssuanceConfig::default(),
        ));
        (uc, tokens, users, events)
    }

    fn make_handler(
        sa_repo: Arc<MockServiceAccountRepository>,
        writer: Arc<MockKubernetesSecretWriter>,
        ns: HashSet<String>,
    ) -> (
        ServiceAccountRotationHandler,
        Arc<ApiTokenUseCase>,
        Arc<MockApiTokenRepository>,
        Arc<MockEventStore>,
    ) {
        let (uc, tokens, _users, events) = make_use_case();
        let handler = ServiceAccountRotationHandler::new(
            sa_repo as Arc<dyn ServiceAccountRepository>,
            writer as Arc<dyn KubernetesSecretWriter>,
            uc.clone(),
            events.clone() as Arc<dyn EventStore>,
            ns,
            registry_host(),
        );
        (handler, uc, tokens, events)
    }

    fn make_context() -> TaskContext {
        TaskContext {
            task_job_id: Uuid::nil(),
            actor: system_actor(),
            correlation_id: Uuid::nil(),
            job_row: hort_domain::ports::jobs_repository::JobRow {
                id: Uuid::nil(),
                kind: KIND.to_string(),
                status: hort_domain::ports::jobs_repository::JobStatus::Running,
                params: Some(serde_json::Value::Null),
                actor_id: None,
                priority: 0,
                trigger_source: "manual".to_string(),
                attempts: 1,
                created_at: chrono::DateTime::<Utc>::from_timestamp(0, 0).unwrap(),
                updated_at: chrono::DateTime::<Utc>::from_timestamp(0, 0).unwrap(),
                completed_at: None,
                last_error: None,
                result_summary: None,
                kind_fields: hort_domain::ports::jobs_repository::KindFields::Other,
            },
        }
    }

    // =====================================================================
    // kind() returns the design-pinned literal
    // =====================================================================

    #[test]
    fn kind_returns_service_account_rotation() {
        let writer = Arc::new(MockKubernetesSecretWriter::new());
        let sa_repo = Arc::new(MockServiceAccountRepository::new());
        let (handler, _, _, _) = make_handler(sa_repo, writer, ns_set(&[]));
        assert_eq!(handler.kind(), "service-account-rotation");
        assert_eq!(handler.kind(), KIND);
    }

    // =====================================================================
    // decide() — pure freshness logic
    // =====================================================================

    fn pinned_now() -> chrono::DateTime<Utc> {
        chrono::DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap()
    }

    #[test]
    fn decide_no_existing_secret_returns_rotate() {
        let now = pinned_now();
        assert_eq!(
            decide(None, StdDuration::from_secs(60), now),
            Decision::Rotate
        );
    }

    #[test]
    fn decide_foreign_managed_by_returns_collision() {
        let now = pinned_now();
        let existing = ManagedSecret {
            managed_by: Some("argocd".into()),
            service_account: Some("ci".into()),
            last_rotated: Some(now - ChronoDuration::seconds(10)),
            token_id: Some(Uuid::nil()),
        };
        match decide(Some(&existing), StdDuration::from_secs(60), now) {
            Decision::Collision {
                existing_managed_by,
            } => {
                assert_eq!(existing_managed_by, Some("argocd".to_string()));
            }
            other => panic!("expected Collision, got {other:?}"),
        }
    }

    #[test]
    fn decide_missing_managed_by_returns_collision() {
        let now = pinned_now();
        let existing = ManagedSecret {
            managed_by: None,
            service_account: None,
            last_rotated: None,
            token_id: None,
        };
        assert!(matches!(
            decide(Some(&existing), StdDuration::from_secs(60), now),
            Decision::Collision {
                existing_managed_by: None
            }
        ));
    }

    #[test]
    fn decide_fresh_within_interval_returns_skip_fresh() {
        let now = pinned_now();
        let last = now - ChronoDuration::seconds(30);
        let existing = ManagedSecret {
            managed_by: Some(MANAGED_BY.into()),
            service_account: Some("ci".into()),
            last_rotated: Some(last),
            token_id: Some(Uuid::nil()),
        };
        match decide(Some(&existing), StdDuration::from_secs(60), now) {
            Decision::SkipFresh { age_secs } => {
                assert!((age_secs - 30.0).abs() < 1e-6);
            }
            other => panic!("expected SkipFresh, got {other:?}"),
        }
    }

    #[test]
    fn decide_stale_returns_rotate() {
        let now = pinned_now();
        let last = now - ChronoDuration::seconds(120);
        let existing = ManagedSecret {
            managed_by: Some(MANAGED_BY.into()),
            service_account: Some("ci".into()),
            last_rotated: Some(last),
            token_id: Some(Uuid::nil()),
        };
        assert_eq!(
            decide(Some(&existing), StdDuration::from_secs(60), now),
            Decision::Rotate
        );
    }

    #[test]
    fn decide_managed_but_no_last_rotated_returns_rotate() {
        let now = pinned_now();
        let existing = ManagedSecret {
            managed_by: Some(MANAGED_BY.into()),
            service_account: Some("ci".into()),
            // Parse-failure or absent label.
            last_rotated: None,
            token_id: None,
        };
        assert_eq!(
            decide(Some(&existing), StdDuration::from_secs(60), now),
            Decision::Rotate
        );
    }

    #[test]
    fn decide_last_rotated_in_future_treated_as_fresh() {
        // Clock skew / manual operator write — never rotate
        // prematurely. The fresh path with `age_secs = 0`.
        let now = pinned_now();
        let last = now + ChronoDuration::seconds(60);
        let existing = ManagedSecret {
            managed_by: Some(MANAGED_BY.into()),
            service_account: Some("ci".into()),
            last_rotated: Some(last),
            token_id: Some(Uuid::nil()),
        };
        match decide(Some(&existing), StdDuration::from_secs(60), now) {
            Decision::SkipFresh { age_secs } => assert_eq!(age_secs, 0.0),
            other => panic!("expected SkipFresh with clamped age=0, got {other:?}"),
        }
    }

    #[test]
    fn decide_exactly_at_interval_boundary_returns_rotate() {
        // age == interval is NOT strictly less than interval → rotate
        // (the comparison is `<`, not `<=`, so the boundary is the
        // first re-rotation tick).
        let now = pinned_now();
        let last = now - ChronoDuration::seconds(60);
        let existing = ManagedSecret {
            managed_by: Some(MANAGED_BY.into()),
            service_account: Some("ci".into()),
            last_rotated: Some(last),
            token_id: Some(Uuid::nil()),
        };
        assert_eq!(
            decide(Some(&existing), StdDuration::from_secs(60), now),
            Decision::Rotate
        );
    }

    // =====================================================================
    // Happy path — empty world
    // =====================================================================

    #[tokio::test]
    async fn run_with_zero_service_accounts_returns_zero_counts() {
        let writer = Arc::new(MockKubernetesSecretWriter::new());
        let sa_repo = Arc::new(MockServiceAccountRepository::new());
        let (handler, _, _, _) = make_handler(sa_repo, writer.clone(), ns_set(&["ci-system"]));

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["total"], 0);
                assert_eq!(result_summary["rotated"], 0);
                assert_eq!(result_summary["skipped_fresh"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert_eq!(writer.upsert_call_count(), 0);
        assert_eq!(writer.read_call_count(), 0);
    }

    // =====================================================================
    // Namespace gate — SA pointing at out-of-policy namespace
    // =====================================================================

    #[tokio::test]
    async fn run_skips_sa_when_namespace_not_authorized() {
        let writer = Arc::new(MockKubernetesSecretWriter::new());
        let sa_repo = Arc::new(MockServiceAccountRepository::new());
        sa_repo.insert(sample_sa("ci-pusher"));

        // Authorized set deliberately empty — SA's namespace
        // "ci-system" is NOT in it.
        let (handler, _, _, events) = make_handler(sa_repo, writer.clone(), ns_set(&[]));

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["total"], 1);
                assert_eq!(result_summary["namespace_not_authorized"], 1);
                assert_eq!(result_summary["rotated"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        // No read, no upsert.
        assert_eq!(writer.read_call_count(), 0);
        assert_eq!(writer.upsert_call_count(), 0);
        // No events emitted — the SA wasn't touched.
        assert!(
            events.appended_batches().is_empty(),
            "namespace gate must short-circuit before any event append"
        );
    }

    // =====================================================================
    // Collision gate — existing Secret managed by someone else
    // =====================================================================

    #[tokio::test]
    async fn run_skips_sa_when_existing_secret_is_a_collision() {
        // The shared mock's `read_managed` always projects
        // `managed_by = Some("hort-worker")` — so we can't seed a
        // foreign value through `seed_existing`. Build a bespoke
        // writer that returns a foreign label.
        let foreign_writer = Arc::new(ForeignManagedByWriter::new());
        let sa_repo = Arc::new(MockServiceAccountRepository::new());
        sa_repo.insert(sample_sa("ci-pusher"));

        let (uc, tokens, _users, events) = make_use_case();
        let handler = ServiceAccountRotationHandler::new(
            sa_repo as Arc<dyn ServiceAccountRepository>,
            foreign_writer.clone() as Arc<dyn KubernetesSecretWriter>,
            uc,
            events.clone() as Arc<dyn EventStore>,
            ns_set(&["ci-system"]),
            registry_host(),
        );

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["collision"], 1);
                assert_eq!(result_summary["rotated"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        // Foreign writer: read happened, no upsert.
        assert_eq!(foreign_writer.upsert_call_count(), 0);
        // No mint either.
        assert_eq!(tokens.inserted().len(), 0);
        // No events.
        assert!(events.appended_batches().is_empty());
    }

    // =====================================================================
    // Fresh skip — existing Secret within rotation interval
    // =====================================================================

    #[tokio::test]
    async fn run_skips_fresh_sa() {
        let writer = Arc::new(MockKubernetesSecretWriter::new());
        let sa = sample_sa("ci-pusher");
        let sa_repo = Arc::new(MockServiceAccountRepository::new());
        sa_repo.insert(sa.clone());

        // Pre-seed: a fresh Secret already exists, last_rotated == now.
        writer.seed_existing(
            "ci-system",
            "ci-hort-token",
            crate::use_cases::test_support::MockSecretState {
                namespace: "ci-system".into(),
                name: "ci-hort-token".into(),
                format: SecretFormat::Dockerconfigjson,
                token_id: Uuid::new_v4(),
                service_account_name: "ci-pusher".into(),
                last_rotated: Utc::now(),
                registry_host: registry_host(),
            },
        );

        let (handler, _, tokens, events) =
            make_handler(sa_repo, writer.clone(), ns_set(&["ci-system"]));

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["skipped_fresh"], 1);
                assert_eq!(result_summary["rotated"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        // Read happened; no new upsert.
        assert_eq!(writer.read_call_count(), 1);
        assert_eq!(writer.upsert_call_count(), 0);
        // No mint.
        assert_eq!(tokens.inserted().len(), 0);
        // No events.
        assert!(events.appended_batches().is_empty());
    }

    // =====================================================================
    // Stale → mint + upsert + event
    // =====================================================================

    #[tokio::test]
    async fn run_rotates_stale_sa() {
        let writer = Arc::new(MockKubernetesSecretWriter::new());
        let sa = sample_sa("ci-pusher");
        let sa_id = sa.id;
        let sa_repo = Arc::new(MockServiceAccountRepository::new());
        sa_repo.insert(sa.clone());

        // Pre-seed: stale Secret, last_rotated way in the past.
        let stale_id = Uuid::new_v4();
        writer.seed_existing(
            "ci-system",
            "ci-hort-token",
            crate::use_cases::test_support::MockSecretState {
                namespace: "ci-system".into(),
                name: "ci-hort-token".into(),
                format: SecretFormat::Dockerconfigjson,
                token_id: stale_id,
                service_account_name: "ci-pusher".into(),
                last_rotated: Utc::now() - ChronoDuration::days(1),
                registry_host: registry_host(),
            },
        );

        let (handler, _, tokens, events) =
            make_handler(sa_repo, writer.clone(), ns_set(&["ci-system"]));

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["rotated"], 1);
                assert_eq!(result_summary["skipped_fresh"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert_eq!(writer.upsert_call_count(), 1);
        // One token landed.
        let snapshot = tokens.inserted();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].kind, TokenKind::ServiceAccount);
        assert_eq!(snapshot[0].user_id, fixed_user_id());

        // Two events: ApiTokenIssued + ServiceAccountTokenRotated.
        // Both on the backing-user stream.
        let batches = events.appended_batches();
        assert!(
            batches.iter().any(|b| matches!(
                b.events.first().map(|e| &e.event),
                Some(DomainEvent::ApiTokenIssued(_))
            )),
            "must emit ApiTokenIssued for the new token"
        );
        let rotated = batches
            .iter()
            .find_map(|b| match b.events.first().map(|e| &e.event) {
                Some(DomainEvent::ServiceAccountTokenRotated(r)) => Some(r.clone()),
                _ => None,
            })
            .expect("must emit ServiceAccountTokenRotated");
        assert_eq!(rotated.service_account_id, sa_id);
        assert_eq!(rotated.service_account_name, "ci-pusher");
        assert_eq!(rotated.target_secret_namespace, "ci-system");
        assert_eq!(rotated.target_secret_name, "ci-hort-token");
        assert_eq!(rotated.format, SerdeSecretFormat::Dockerconfigjson);

        // Both events must be attributed to System.
        for batch in &batches {
            assert!(
                matches!(batch.actor, Actor::Internal(InternalActor::System)),
                "system mint + rotation event must carry Actor::Internal(System), got {:?}",
                batch.actor,
            );
        }
    }

    // =====================================================================
    // No existing Secret → mint + upsert
    // =====================================================================

    #[tokio::test]
    async fn run_rotates_when_no_existing_secret() {
        let writer = Arc::new(MockKubernetesSecretWriter::new());
        let sa = sample_sa("ci-pusher");
        let sa_repo = Arc::new(MockServiceAccountRepository::new());
        sa_repo.insert(sa);

        let (handler, _, tokens, _events) =
            make_handler(sa_repo, writer.clone(), ns_set(&["ci-system"]));

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["rotated"], 1);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert_eq!(writer.upsert_call_count(), 1);
        assert_eq!(tokens.inserted().len(), 1);
    }

    // =====================================================================
    // Mint failure path — continue to next SA
    // =====================================================================

    #[tokio::test]
    async fn run_continues_on_mint_failure() {
        let writer = Arc::new(MockKubernetesSecretWriter::new());
        let sa_a = sample_sa("ci-pusher-a");
        let mut sa_b = sample_sa("ci-pusher-b");
        // Distinct target so the writer doesn't collide on key.
        if let Some(r) = sa_b.fallback_rotation.as_mut() {
            r.target_secret_name = "ci-hort-token-b".into();
        }
        let sa_repo = Arc::new(MockServiceAccountRepository::new());
        sa_repo.insert(sa_a);
        sa_repo.insert(sa_b);

        // Use a use case whose `users.find_by_id` will fail for the
        // SA's backing user: drop the user out of the users repo so
        // `find_by_id` returns `NotFound`. The mint-failed branch
        // surfaces it.
        let tokens = Arc::new(MockApiTokenRepository::new());
        let users = Arc::new(MockUserRepository::new());
        // NB: deliberately NOT inserting the user — `find_by_id` →
        // NotFound → mint_failed for every SA.
        let events = Arc::new(MockEventStore::new());
        let rbac = Arc::new(ArcSwap::from_pointee(RbacEvaluator::new(Vec::new())));
        let uc = Arc::new(ApiTokenUseCase::new(
            tokens.clone() as Arc<dyn ApiTokenRepository>,
            users.clone() as Arc<dyn UserRepository>,
            crate::event_store_publisher::wrap_for_test(events.clone()),
            rbac,
            ApiTokenIssuanceConfig::default(),
        ));

        let handler = ServiceAccountRotationHandler::new(
            sa_repo as Arc<dyn ServiceAccountRepository>,
            writer.clone() as Arc<dyn KubernetesSecretWriter>,
            uc,
            events.clone() as Arc<dyn EventStore>,
            ns_set(&["ci-system"]),
            registry_host(),
        );

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok — mint failure must not abort the tick");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                // Both SAs counted as mint_failed; tick did not abort.
                assert_eq!(result_summary["total"], 2);
                assert_eq!(result_summary["mint_failed"], 2);
                assert_eq!(result_summary["rotated"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        // No upsert — mint failed before reaching the writer.
        assert_eq!(writer.upsert_call_count(), 0);
        assert_eq!(tokens.inserted().len(), 0);
    }

    // =====================================================================
    // Upsert failure path — continue to next SA
    // =====================================================================

    #[tokio::test]
    async fn run_continues_on_upsert_failure() {
        let writer = Arc::new(FailingUpsertWriter::new());
        let sa = sample_sa("ci-pusher");
        let sa_repo = Arc::new(MockServiceAccountRepository::new());
        sa_repo.insert(sa);

        // Construct the handler with the failing writer directly —
        // `make_handler` expects the shared mock type.
        let (uc, tokens, _users, events) = make_use_case();
        let handler = ServiceAccountRotationHandler::new(
            sa_repo as Arc<dyn ServiceAccountRepository>,
            writer.clone() as Arc<dyn KubernetesSecretWriter>,
            uc,
            events.clone() as Arc<dyn EventStore>,
            ns_set(&["ci-system"]),
            registry_host(),
        );

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok — upsert failure must not abort the tick");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["write_failed"], 1);
                assert_eq!(result_summary["rotated"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        // Token DID mint — just couldn't be written. Next tick will
        // see the same stale state and try again.
        assert_eq!(tokens.inserted().len(), 1);
        // Only the ApiTokenIssued event landed; no rotation event.
        let batches = events.appended_batches();
        assert!(
            batches.iter().any(|b| matches!(
                b.events.first().map(|e| &e.event),
                Some(DomainEvent::ApiTokenIssued(_))
            )),
            "mint already succeeded — ApiTokenIssued must be on the stream",
        );
        assert!(
            !batches.iter().any(|b| matches!(
                b.events.first().map(|e| &e.event),
                Some(DomainEvent::ServiceAccountTokenRotated(_))
            )),
            "rotation event must NOT be appended when upsert failed",
        );
    }

    // =====================================================================
    // Idempotency — second tick is a no-op when first succeeded
    // =====================================================================

    #[tokio::test]
    async fn second_tick_is_idempotent_no_op() {
        let writer = Arc::new(MockKubernetesSecretWriter::new());
        let sa_a = sample_sa("ci-pusher-a");
        let mut sa_b = sample_sa("ci-pusher-b");
        if let Some(r) = sa_b.fallback_rotation.as_mut() {
            r.target_secret_name = "ci-hort-token-b".into();
        }
        let sa_repo = Arc::new(MockServiceAccountRepository::new());
        sa_repo.insert(sa_a);
        sa_repo.insert(sa_b);

        let (handler, _, tokens, _events) =
            make_handler(sa_repo, writer.clone(), ns_set(&["ci-system"]));

        // First tick — both SAs rotate.
        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("first tick Ok");
        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["rotated"], 2);
                assert_eq!(result_summary["skipped_fresh"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert_eq!(writer.upsert_call_count(), 2);
        assert_eq!(tokens.inserted().len(), 2);
        let first_tick_upserts = writer.upsert_call_count();
        let first_tick_mints = tokens.inserted().len();

        // Second tick — state from first tick is fresh; both must skip.
        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("second tick Ok");
        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["rotated"], 0, "second tick must not rotate");
                assert_eq!(
                    result_summary["skipped_fresh"], 2,
                    "second tick must skip both SAs as fresh",
                );
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        // No new upserts.
        assert_eq!(
            writer.upsert_call_count(),
            first_tick_upserts,
            "second tick must produce zero new upserts (idempotency)"
        );
        // No new mints.
        assert_eq!(
            tokens.inserted().len(),
            first_tick_mints,
            "second tick must produce zero new mints (idempotency)"
        );
    }

    // =====================================================================
    // Metric emission — counter labels match the catalog
    // =====================================================================

    #[test]
    fn run_emits_hort_rotation_total_for_each_decide_branch() {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use metrics_util::MetricKind;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let writer = Arc::new(MockKubernetesSecretWriter::new());
        // Three SAs in three states:
        //   A: namespace_not_authorized (no ns match)
        //   B: rotated (no existing Secret, ns matches)
        //   C: skipped_fresh (seeded fresh)
        let mut sa_a = sample_sa("a");
        if let Some(r) = sa_a.fallback_rotation.as_mut() {
            r.target_secret_namespace = "out-of-policy".into();
        }
        let mut sa_b = sample_sa("b");
        if let Some(r) = sa_b.fallback_rotation.as_mut() {
            r.target_secret_name = "secret-b".into();
        }
        let mut sa_c = sample_sa("c");
        if let Some(r) = sa_c.fallback_rotation.as_mut() {
            r.target_secret_name = "secret-c".into();
        }
        // Seed fresh for SA C.
        writer.seed_existing(
            "ci-system",
            "secret-c",
            crate::use_cases::test_support::MockSecretState {
                namespace: "ci-system".into(),
                name: "secret-c".into(),
                format: SecretFormat::Dockerconfigjson,
                token_id: Uuid::new_v4(),
                service_account_name: "c".into(),
                last_rotated: Utc::now(),
                registry_host: registry_host(),
            },
        );

        let sa_repo = Arc::new(MockServiceAccountRepository::new());
        sa_repo.insert(sa_a);
        sa_repo.insert(sa_b);
        sa_repo.insert(sa_c);

        let (handler, _, _, _) = make_handler(sa_repo, writer.clone(), ns_set(&["ci-system"]));

        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(handler.run(&serde_json::Value::Null, make_context()))
                .expect("Ok");
        });

        let snap = snapshotter.snapshot().into_vec();

        for expected in &["rotated", "skipped_fresh", "namespace_not_authorized"] {
            let counter = snap.iter().find(|(ck, _, _, _)| {
                ck.kind() == MetricKind::Counter
                    && ck.key().name() == "hort_rotation_total"
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "result" && l.value() == *expected)
            });
            let (_, _, _, value) = counter
                .unwrap_or_else(|| panic!("hort_rotation_total{{result=\"{expected}\"}} missing"));
            match value {
                DebugValue::Counter(n) => assert_eq!(*n, 1, "expected 1 increment for {expected}"),
                other => panic!("expected Counter for {expected}, got {other:?}"),
            }
        }

        // Lag gauge — must be set for each SA visited via the
        // skipped_fresh or rotated branch (SA A doesn't reach it
        // because the namespace gate short-circuits first).
        let lag_gauges: Vec<_> = snap
            .iter()
            .filter(|(ck, _, _, _)| {
                ck.kind() == MetricKind::Gauge && ck.key().name() == "hort_rotation_lag_seconds"
            })
            .collect();
        // Two SAs (b: rotated → lag=0; c: skipped_fresh → lag≈0).
        assert!(
            lag_gauges.len() >= 2,
            "expected ≥2 service_account gauge series, got {}",
            lag_gauges.len()
        );
        // Cardinality discipline — each gauge has exactly one
        // `service_account` label.
        for (key, _, _, _) in lag_gauges {
            let svc_acct_count = key
                .key()
                .labels()
                .filter(|l| l.key() == "service_account")
                .count();
            assert_eq!(
                svc_acct_count, 1,
                "gauge must carry exactly one service_account label"
            );
            // No forbidden high-cardinality labels.
            for forbidden in &["artifact_id", "user_id", "token_id"] {
                assert!(
                    !key.key().labels().any(|l| l.key() == *forbidden),
                    "hort_rotation_lag_seconds must not carry `{forbidden}`",
                );
            }
        }
    }

    // ---------- bespoke test writers ----------

    /// Writer whose `read_managed` returns a `ManagedSecret` with a
    /// foreign `managed_by` label — used to exercise the collision
    /// branch. The shared mock always projects `managed_by =
    /// Some("hort-worker")`, so a foreign-label test needs a separate
    /// fixture.
    struct ForeignManagedByWriter {
        upsert_count: Mutex<usize>,
    }

    impl ForeignManagedByWriter {
        fn new() -> Self {
            Self {
                upsert_count: Mutex::new(0),
            }
        }
        fn upsert_call_count(&self) -> usize {
            *self.upsert_count.lock().unwrap()
        }
    }

    impl KubernetesSecretWriter for ForeignManagedByWriter {
        fn read_managed<'a>(
            &'a self,
            _namespace: &'a str,
            _name: &'a str,
        ) -> BoxFuture<'a, DomainResult<Option<ManagedSecret>>> {
            Box::pin(async move {
                Ok(Some(ManagedSecret {
                    managed_by: Some("argocd".into()),
                    service_account: Some("ci".into()),
                    last_rotated: Some(Utc::now()),
                    token_id: Some(Uuid::nil()),
                }))
            })
        }
        fn upsert_managed<'a>(
            &'a self,
            _namespace: &'a str,
            _name: &'a str,
            _spec: ManagedSecretSpec,
        ) -> BoxFuture<'a, DomainResult<()>> {
            *self.upsert_count.lock().unwrap() += 1;
            Box::pin(async { Ok(()) })
        }
    }

    /// Writer whose `read_managed` always errors — used to exercise
    /// the read-side write_failed branch. The
    /// failure happens BEFORE we reach the mint step, so the handler
    /// must classify it as `write_failed` (not `mint_failed`) AND
    /// continue to the next SA without aborting the tick.
    struct FailingReadWriter {
        upsert_count: Mutex<usize>,
    }

    impl FailingReadWriter {
        fn new() -> Self {
            Self {
                upsert_count: Mutex::new(0),
            }
        }
        fn upsert_call_count(&self) -> usize {
            *self.upsert_count.lock().unwrap()
        }
    }

    impl KubernetesSecretWriter for FailingReadWriter {
        fn read_managed<'a>(
            &'a self,
            _namespace: &'a str,
            _name: &'a str,
        ) -> BoxFuture<'a, DomainResult<Option<ManagedSecret>>> {
            Box::pin(async { Err(DomainError::Invariant("simulated k8s GET failure".into())) })
        }
        fn upsert_managed<'a>(
            &'a self,
            _namespace: &'a str,
            _name: &'a str,
            _spec: ManagedSecretSpec,
        ) -> BoxFuture<'a, DomainResult<()>> {
            *self.upsert_count.lock().unwrap() += 1;
            Box::pin(async { Ok(()) })
        }
    }

    // =====================================================================
    // Read-side failure path — read_managed error → write_failed, no mint,
    // tick continues
    // =====================================================================

    #[tokio::test]
    async fn run_continues_on_read_failure() {
        let writer = Arc::new(FailingReadWriter::new());
        // Two SAs so the test also asserts the tick proceeds to the
        // second SA after the first SA's read fails.
        let sa_a = sample_sa("ci-pusher-a");
        let mut sa_b = sample_sa("ci-pusher-b");
        if let Some(r) = sa_b.fallback_rotation.as_mut() {
            r.target_secret_name = "ci-hort-token-b".into();
        }
        let sa_repo = Arc::new(MockServiceAccountRepository::new());
        sa_repo.insert(sa_a);
        sa_repo.insert(sa_b);

        let (uc, tokens, _users, events) = make_use_case();
        let handler = ServiceAccountRotationHandler::new(
            sa_repo as Arc<dyn ServiceAccountRepository>,
            writer.clone() as Arc<dyn KubernetesSecretWriter>,
            uc,
            events.clone() as Arc<dyn EventStore>,
            ns_set(&["ci-system"]),
            registry_host(),
        );

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok — read failure must NOT abort the tick");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["total"], 2);
                // Both SAs surfaced as write_failed (read-side bucket
                // is the same as the upsert-side bucket:
                // a read failure is "we couldn't observe the
                // existing Secret to decide", which is the same
                // operator-visible effect as an upsert failure —
                // dashboard alarm on `write_failed > 0`).
                assert_eq!(result_summary["write_failed"], 2);
                assert_eq!(result_summary["mint_failed"], 0);
                assert_eq!(result_summary["rotated"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        // Read failed BEFORE we reached the mint step — no mints
        // and no upserts.
        assert_eq!(writer.upsert_call_count(), 0);
        assert_eq!(tokens.inserted().len(), 0);
        // No events appended (rotation event lives behind a
        // successful upsert).
        assert!(
            events.appended_batches().is_empty(),
            "read-side failure short-circuits before any event append",
        );
    }

    // =====================================================================
    // Metric labels honour METRICS_INCLUDE_SERVICE_ACCOUNT_LABEL=false
    // =====================================================================

    #[test]
    fn lag_gauge_collapses_to_all_when_include_label_disabled() {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use metrics_util::MetricKind;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let writer = Arc::new(MockKubernetesSecretWriter::new());
        let sa = sample_sa("ci-pusher");
        let sa_repo = Arc::new(MockServiceAccountRepository::new());
        sa_repo.insert(sa);

        let (uc, _tokens, _users, events) = make_use_case();
        let handler = ServiceAccountRotationHandler::new(
            sa_repo as Arc<dyn ServiceAccountRepository>,
            writer.clone() as Arc<dyn KubernetesSecretWriter>,
            uc,
            events.clone() as Arc<dyn EventStore>,
            ns_set(&["ci-system"]),
            registry_host(),
        )
        .with_include_service_account_label(false);

        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(handler.run(&serde_json::Value::Null, make_context()))
                .expect("Ok");
        });

        let snap = snapshotter.snapshot().into_vec();

        // The lag gauge MUST carry exactly one
        // `service_account="_all"` series — never the per-SA name —
        // when the toggle is off.
        let lag_gauges: Vec<_> = snap
            .iter()
            .filter(|(ck, _, _, _)| {
                ck.kind() == MetricKind::Gauge && ck.key().name() == "hort_rotation_lag_seconds"
            })
            .collect();
        assert!(
            !lag_gauges.is_empty(),
            "expected hort_rotation_lag_seconds series"
        );
        for (key, _, _, value) in &lag_gauges {
            let sa_labels: Vec<_> = key
                .key()
                .labels()
                .filter(|l| l.key() == "service_account")
                .collect();
            assert_eq!(sa_labels.len(), 1);
            assert_eq!(
                sa_labels[0].value(),
                "_all",
                "with INCLUDE_SERVICE_ACCOUNT_LABEL=false the per-SA name MUST collapse",
            );
            // The collapsed gauge still carries a numeric reading
            // (0.0 for the fresh rotation path).
            match value {
                DebugValue::Gauge(g) => assert!(g.into_inner() >= 0.0),
                other => panic!("expected Gauge, got {other:?}"),
            }
        }
    }

    /// Writer whose `upsert_managed` always errors — used to exercise
    /// the write_failed branch.
    struct FailingUpsertWriter;

    impl FailingUpsertWriter {
        fn new() -> Self {
            Self
        }
    }

    impl KubernetesSecretWriter for FailingUpsertWriter {
        fn read_managed<'a>(
            &'a self,
            _namespace: &'a str,
            _name: &'a str,
        ) -> BoxFuture<'a, DomainResult<Option<ManagedSecret>>> {
            Box::pin(async { Ok(None) })
        }
        fn upsert_managed<'a>(
            &'a self,
            _namespace: &'a str,
            _name: &'a str,
            _spec: ManagedSecretSpec,
        ) -> BoxFuture<'a, DomainResult<()>> {
            Box::pin(async { Err(DomainError::Invariant("simulated k8s apply failure".into())) })
        }
    }
}
