//! `api-token-retention-sweep` `TaskHandler` — the horizon on the
//! credential store.
//!
//! Every other row-retention sweep in this family reclaims rows from
//! `public.jobs`, the task queue. This one reclaims rows from
//! `public.api_tokens`, the table that decides who may do what — so the
//! bar it has to clear is not "the rows go away" but **that its predicate
//! can be read, by someone who did not write it, as obviously unable to
//! reach a live credential**:
//!
//! ```sql
//! DELETE FROM public.api_tokens
//!  WHERE (expires_at IS NOT NULL AND expires_at < now() - $horizon)
//!     OR (revoked_at IS NOT NULL AND revoked_at < now() - $horizon)
//! ```
//!
//! **Both marks are nullable, and that is the deletion hazard.**
//! `expires_at` and `revoked_at` are `timestamp with time zone` with no
//! `NOT NULL` (`migrations/008_api_tokens.sql`), so a row with **both**
//! NULL is a durable identity that never expires. Each disjunct above
//! requires that row's *own* mark to be present, so a both-NULL row
//! matches neither and survives. A `COALESCE`-flattened or negated form
//! inverts exactly this; the statement, the forms it rules out, and the
//! reasoning live with the SQL in
//! `hort_adapters_postgres::api_token_repo`, and the port method's docs
//! state the contract every implementation owes.
//!
//! The sweep deletes by **state**, for every `kind`. It does not consult
//! `issued_via` — that column records which issuance path minted a row,
//! and a horizon keyed on provenance would retain or discard credentials
//! by origin rather than by whether they can still authenticate anybody.
//!
//! # What the window is actually deciding
//!
//! The deleted row carries `last_used_at`, `last_used_ip` and
//! `last_used_user_agent`, which exist **nowhere else in the system** —
//! the event store keeps `ApiTokenIssued`, `ApiTokenRevoked` and
//! `ApiTokenUsed`, not those three fields. So [`DEFAULT_HORIZON`] is the
//! decision that they are not worth keeping past it, which is why this is
//! a horizon and not an immediate delete: a credential that expired this
//! morning is already dead, and the 90 days buy an investigator its
//! last-use trail rather than buying the credential anything.
//!
//! # No cache invalidation per deleted row, deliberately
//!
//! `PatCache` is a per-replica in-process LRU with a 5-minute wall-clock
//! TTL, and its cached entry carries `expires_at` and `revoked_at`
//! (`crate::use_cases::pat_cache::ApiTokenValidation`). The **validator**
//! re-checks both on every cache hit, before returning the cached
//! value — `PatValidationUseCase`'s cache-hit arm answers `Expired` on
//! `expires_at <= now` and `Revoked` on a present `revoked_at`
//! (`crate::use_cases::pat_validation_use_case`), so the re-check is in
//! the consumer rather than in `PatCache::get`. A row 90 days past
//! either mark therefore cannot authenticate anybody through the cache,
//! with or without a database round trip. An
//! `ApiTokenCacheInvalidator::invalidate_token` call per deleted row
//! would be plumbing that proves nothing and implies the cache cannot be
//! trusted — so there is none, and its absence is the assertion that it
//! can.
//!
//! # The one outbound effect
//!
//! `subscriptions.created_by_token_id` references `api_tokens(id) ON
//! DELETE SET NULL` (`migrations/012_subscriptions.sql`), so this
//! `DELETE` writes to another table. 012's own comment blesses that for
//! an **operator** deleting a token; it was not written with an automated
//! sweep in mind. It is nonetheless harmless today for a reason that has
//! to be stated rather than assumed: the only production site that builds
//! a `Subscription` writes `created_by_token_id: None`
//! (`crate::use_cases::subscription_use_case`), so the column is inert in
//! production and there is no audit attribution to lose. A change that
//! starts populating it makes this sweep begin erasing that attribution,
//! and the port method's docs carry the same warning beside the
//! statement.
//!
//! # Params shape
//!
//! ```json
//! { "horizon_seconds": 7776000 }
//! ```
//!
//! `horizon_seconds` is optional, and **no supported path supplies it.**
//! The Helm CronJob and the systemd timer both run `hort-server
//! enqueue-api-token-retention-sweep`, which takes no arguments and
//! writes `params` unconditionally empty; this kind has no
//! `hort-http-admin-tasks` invoke route (that router enumerates its
//! routes one by one and this kind is not among them, so `POST
//! /api/v1/admin/tasks/api-token-retention-sweep` answers 405 — it falls
//! through to the `GET /{id}` pattern rather than 404ing). So
//! [`DEFAULT_HORIZON`] is the horizon in force on every deployment;
//! nothing short of a hand-written `INSERT` into `public.jobs` produces
//! another one.
//!
//! The parse and the cap are reused from
//! [`super::sweep_horizon::resolve_sweep_horizon`] rather than
//! re-implemented, which is what keeps that statement safe: a
//! hand-written row carrying a nonsense value fails the task instead of
//! running a year-wide `DELETE` against the credential store.
//!
//! # Why no HTTP route
//!
//! All three sibling sweeps are in `ADMIN_INVOKABLE_TASK_KINDS` and none
//! is among `hort-http-admin-tasks`' enumerated invoke routes, and the
//! reason is a security posture rather than an omission: routing a
//! default-on schedulable tick through the `hort-cli` HTTP admin-task
//! path would drag the whole `svc-token-bootstrap` Job chain (and a
//! standing `admin_task_invoke` token mount) to default-on, while the
//! runtime DSN can only `INSERT INTO public.jobs`. Adding a route here
//! would reverse that decision for the credential store of all tables.
//! An ad-hoc run is `hort-server enqueue-api-token-retention-sweep` on
//! the runtime DSN.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use hort_domain::error::DomainResult;
use hort_domain::ports::api_token_repository::ApiTokenRepository;
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::BoxFuture;

use super::sweep_horizon::resolve_sweep_horizon;

/// 90 days — the retention horizon, and the only one any supported path
/// produces (see the module docs).
///
/// Longer than the three `jobs`-row sweeps' 7 days, because what ages out
/// here is not operational accounting: it is the last-use trail
/// (`last_used_at`, `last_used_ip`, `last_used_user_agent`) of a
/// credential that existed, and 90 days is a quarter — long enough that
/// an investigation opened on a credential retired last month still finds
/// where it was used from, short enough that a table growing by one row
/// per issued credential, plus one per federated workload exchange,
/// reaches a steady state instead of accumulating forever.
pub const DEFAULT_HORIZON: Duration = Duration::from_secs(90 * 24 * 60 * 60);

/// Hard upper bound on any horizon that reaches this handler — 365 days.
///
/// Since no supported path supplies a horizon at all, the cap's live job
/// is to keep a hand-written `INSERT` from becoming a year-wide `DELETE`
/// against the credential store. Note which direction a *wider* horizon
/// errs in here: it deletes **fewer** rows, so the cap is not a safety
/// bound on the deletion itself — it is a bound on an operator silently
/// getting a retention window nobody decided on, in a table whose
/// contents an auditor reads.
pub const MAX_HORIZON: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// `TaskHandler` for the `api_tokens` retention sweep. Constructed at
/// worker composition time with the `ApiTokenRepository` port.
pub struct ApiTokenRetentionSweepHandler {
    api_tokens: Arc<dyn ApiTokenRepository>,
}

impl ApiTokenRetentionSweepHandler {
    pub fn new(api_tokens: Arc<dyn ApiTokenRepository>) -> Self {
        Self { api_tokens }
    }
}

impl TaskHandler for ApiTokenRetentionSweepHandler {
    fn kind(&self) -> &'static str {
        "api-token-retention-sweep"
    }

    #[tracing::instrument(skip(self, params))]
    fn run<'a>(
        &'a self,
        params: &'a serde_json::Value,
        _ctx: TaskContext,
    ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
        Box::pin(async move {
            let horizon =
                match resolve_sweep_horizon(self.kind(), params, DEFAULT_HORIZON, MAX_HORIZON) {
                    Ok(h) => h,
                    Err(outcome) => return Ok(outcome),
                };

            let deleted = match self
                .api_tokens
                .delete_expired_or_revoked_older_than(horizon)
                .await
            {
                Ok(n) => n,
                Err(err) => {
                    return Ok(TaskOutcome::fail(
                        format!("delete_expired_or_revoked_older_than failed: {err}"),
                        true,
                    ));
                }
            };

            tracing::info!(
                horizon_seconds = horizon.as_secs(),
                deleted,
                "api-token-retention-sweep complete",
            );

            Ok(TaskOutcome::Completed {
                result_summary: json!({
                    "horizon_seconds": horizon.as_secs(),
                    "deleted": deleted,
                }),
            })
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::Utc;
    use uuid::Uuid;

    use hort_domain::events::system_actor;
    use hort_domain::ports::jobs_repository::{JobRow, JobStatus, KindFields};

    use crate::use_cases::test_support::MockApiTokenRepository;

    fn make_context() -> TaskContext {
        let now = Utc::now();
        TaskContext {
            task_job_id: Uuid::nil(),
            actor: system_actor(),
            correlation_id: Uuid::nil(),
            job_row: JobRow {
                id: Uuid::nil(),
                kind: "api-token-retention-sweep".to_string(),
                status: JobStatus::Running,
                params: Some(serde_json::Value::Null),
                actor_id: None,
                priority: 0,
                trigger_source: "test".to_string(),
                attempts: 1,
                created_at: now,
                updated_at: now,
                completed_at: None,
                last_error: None,
                result_summary: None,
                kind_fields: KindFields::Other,
            },
        }
    }

    #[test]
    fn kind_returns_api_token_retention_sweep() {
        let api_tokens = Arc::new(MockApiTokenRepository::new());
        let h = ApiTokenRetentionSweepHandler::new(api_tokens);
        assert_eq!(h.kind(), "api-token-retention-sweep");
    }

    /// The kind literal must be in the admin-invoke allow-list so the
    /// `jobs.kind` CHECK constraint accepts the row the CronJob's
    /// `enqueue_task` inserts (the two lists are kept in lock-step by
    /// `task_kind_check_lockstep_guard`, which reads `EVENT_TASK_KINDS` —
    /// the superset).
    ///
    /// Carried forward from `jobs_row_retention_sweep`'s own copy: it is
    /// what makes the two-constant membership a compile-adjacent fact
    /// rather than a convention.
    #[test]
    fn kind_is_registered_in_the_task_kind_vocabularies() {
        use hort_domain::events::{ADMIN_INVOKABLE_TASK_KINDS, EVENT_TASK_KINDS};
        let kind = "api-token-retention-sweep";
        assert!(
            EVENT_TASK_KINDS.contains(&kind),
            "{kind} MUST be in EVENT_TASK_KINDS or the migration's kind CHECK rejects the row"
        );
        assert!(
            ADMIN_INVOKABLE_TASK_KINDS.contains(&kind),
            "{kind} MUST be in ADMIN_INVOKABLE_TASK_KINDS so an operator-driven enqueue \
             through TaskUseCase is not rejected before any I/O"
        );
    }

    /// Not a destructive kind in ADR 0028's sense, which is a narrower
    /// claim than "it deletes nothing".
    ///
    /// The row it removes could not authenticate anybody for 90 days
    /// before it went, so no authority is released and no decision is
    /// foreclosed; what the window discards is the last-use trail, and
    /// discarding that is the decision the horizon *is*. A destructive
    /// kind carries a per-UTC-day idempotency key because a second run
    /// would destroy more than the first; a second run of this sweep
    /// deletes the rows the first one already took, which is to say
    /// nothing.
    #[test]
    fn kind_is_not_destructive() {
        assert!(
            !hort_domain::events::task_kind_is_destructive("api-token-retention-sweep"),
            "the sweep releases no authority and forecloses no decision; it is not an \
             ADR 0028 destructive kind"
        );
    }

    #[tokio::test]
    async fn bare_params_uses_the_ninety_day_default_and_reports_deleted_count() {
        let api_tokens = Arc::new(MockApiTokenRepository::new());
        api_tokens.set_retention_deleted_count(9_498);
        let h = ApiTokenRetentionSweepHandler::new(api_tokens.clone());
        let outcome = h.run(&json!({}), make_context()).await.expect("Ok");
        let TaskOutcome::Completed { result_summary } = outcome else {
            panic!("expected Completed");
        };
        assert_eq!(result_summary["horizon_seconds"], 90 * 24 * 60 * 60);
        assert_eq!(result_summary["deleted"], 9_498);
        let calls = api_tokens.retention_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], DEFAULT_HORIZON);
    }

    /// The window resolves from task params when one is supplied, even
    /// though no supported path supplies one — asserted for the reason
    /// `sweep_horizon`'s own docs give: the field is readable by the
    /// handler, so a hand-written `INSERT` can reach it, and what that
    /// row does is a behaviour of this handler rather than a hypothesis.
    #[tokio::test]
    async fn a_supplied_horizon_overrides_the_default() {
        let api_tokens = Arc::new(MockApiTokenRepository::new());
        let h = ApiTokenRetentionSweepHandler::new(api_tokens.clone());
        let outcome = h
            .run(&json!({"horizon_seconds": 3600}), make_context())
            .await
            .expect("Ok");
        let TaskOutcome::Completed { result_summary } = outcome else {
            panic!("expected Completed");
        };
        assert_eq!(result_summary["horizon_seconds"], 3600);
        assert_eq!(api_tokens.retention_calls()[0], Duration::from_secs(3600));
    }

    /// Above the 365-day cap the task fails without reaching the port —
    /// the `DELETE` never runs, which is the half that matters for a
    /// statement against the credential store.
    #[tokio::test]
    async fn a_horizon_above_the_cap_is_refused_without_reaching_the_port() {
        let api_tokens = Arc::new(MockApiTokenRepository::new());
        let h = ApiTokenRetentionSweepHandler::new(api_tokens.clone());
        let outcome = h
            .run(
                &json!({"horizon_seconds": MAX_HORIZON.as_secs() + 1}),
                make_context(),
            )
            .await
            .expect("Ok");
        let TaskOutcome::Failed { retry, reason } = outcome else {
            panic!("expected Failed");
        };
        assert!(
            !retry,
            "cap-exceeded is a configuration error, not transient"
        );
        assert!(reason.contains("365 days"), "{reason}");
        assert!(
            api_tokens.retention_calls().is_empty(),
            "a refused horizon must not reach the DELETE"
        );
    }

    /// The cap value itself resolves — the check is `>`, not `>=`. Pinned
    /// here as well as in `sweep_horizon`'s own tests because it is this
    /// handler's `MAX_HORIZON` that is being enforced.
    #[tokio::test]
    async fn the_cap_value_itself_resolves() {
        let api_tokens = Arc::new(MockApiTokenRepository::new());
        let h = ApiTokenRetentionSweepHandler::new(api_tokens.clone());
        let outcome = h
            .run(
                &json!({"horizon_seconds": MAX_HORIZON.as_secs()}),
                make_context(),
            )
            .await
            .expect("Ok");
        let TaskOutcome::Completed { result_summary } = outcome else {
            panic!("expected Completed");
        };
        assert_eq!(result_summary["horizon_seconds"], MAX_HORIZON.as_secs());
        assert_eq!(api_tokens.retention_calls()[0], MAX_HORIZON);
    }

    #[tokio::test]
    async fn malformed_params_fail_without_reaching_the_port() {
        let api_tokens = Arc::new(MockApiTokenRepository::new());
        let h = ApiTokenRetentionSweepHandler::new(api_tokens.clone());
        let outcome = h
            .run(&json!({"horizon_seconds": "not-a-number"}), make_context())
            .await
            .expect("Ok");
        let TaskOutcome::Failed { retry, .. } = outcome else {
            panic!("expected Failed");
        };
        assert!(!retry);
        assert!(api_tokens.retention_calls().is_empty());
    }

    /// Nothing eligible is a completed sweep of zero rows, not a
    /// failure — the horizon having nothing to collect is the steady
    /// state an operator wants to see in `result_summary`.
    #[tokio::test]
    async fn no_eligible_rows_completes_with_zero_deleted() {
        let api_tokens = Arc::new(MockApiTokenRepository::new());
        api_tokens.set_retention_deleted_count(0);
        let h = ApiTokenRetentionSweepHandler::new(api_tokens.clone());
        let outcome = h.run(&json!({}), make_context()).await.expect("Ok");
        let TaskOutcome::Completed { result_summary } = outcome else {
            panic!("expected Completed");
        };
        assert_eq!(result_summary["deleted"], 0);
    }

    /// An infrastructure failure retries, and the message names the port
    /// method so an operator reading `last_error` knows which statement
    /// failed.
    ///
    /// Driven through the port's **default** implementation, which
    /// returns `Invariant` rather than `Ok(0)` — so this test is also the
    /// proof that a repository which never implemented the delete cannot
    /// report a successful sweep.
    #[tokio::test]
    async fn a_port_error_returns_a_retryable_failure_naming_the_method() {
        struct Bare;
        impl ApiTokenRepository for Bare {
            fn insert(
                &self,
                _token: &hort_domain::entities::api_token::ApiToken,
            ) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { Ok(()) })
            }
            fn find_by_prefix(
                &self,
                _prefix: &str,
            ) -> BoxFuture<'_, DomainResult<Option<hort_domain::entities::api_token::ApiToken>>>
            {
                Box::pin(async { Ok(None) })
            }
            fn find_by_id(
                &self,
                id: Uuid,
            ) -> BoxFuture<'_, DomainResult<hort_domain::entities::api_token::ApiToken>>
            {
                Box::pin(async move {
                    Err(hort_domain::error::DomainError::NotFound {
                        entity: "ApiToken",
                        id: id.to_string(),
                    })
                })
            }
            fn list_for_user(
                &self,
                _user_id: Uuid,
                _page: hort_domain::types::PageRequest,
            ) -> BoxFuture<
                '_,
                DomainResult<hort_domain::types::Page<hort_domain::entities::api_token::ApiToken>>,
            > {
                Box::pin(async {
                    Ok(hort_domain::types::Page {
                        items: Vec::new(),
                        total: 0,
                    })
                })
            }
            fn update_last_used(
                &self,
                _token_id: Uuid,
                _at: chrono::DateTime<Utc>,
                _client_ip: Option<&str>,
                _user_agent: Option<&str>,
            ) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { Ok(()) })
            }
            fn revoke(&self, _token_id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { Ok(()) })
            }
        }
        let api_tokens: Arc<dyn ApiTokenRepository> = Arc::new(Bare);
        let h = ApiTokenRetentionSweepHandler::new(api_tokens);
        let outcome = h.run(&json!({}), make_context()).await.expect("Ok");
        let TaskOutcome::Failed { retry, reason } = outcome else {
            panic!("expected Failed");
        };
        assert!(retry, "infrastructure failures retry");
        assert!(
            reason.contains("delete_expired_or_revoked_older_than"),
            "{reason}"
        );
    }

    /// The two horizon constants, as relations rather than as a repeat of
    /// the numbers above them.
    ///
    /// The default must sit strictly inside the cap (or the cap would
    /// reject the only horizon any supported path produces), and must be
    /// longer than the `jobs`-row sweeps' 7 days — what ages out here is
    /// a credential's last-use trail, not operational accounting, and the
    /// two windows are answering different questions.
    #[test]
    fn the_default_horizon_sits_inside_the_cap_and_above_the_jobs_row_window() {
        assert!(
            DEFAULT_HORIZON < MAX_HORIZON,
            "the cap must admit the horizon every supported path produces"
        );
        assert!(
            DEFAULT_HORIZON > crate::task_handlers::scan_row_retention_sweep::DEFAULT_HORIZON,
            "a credential's last-use trail outlives a terminal job row by design"
        );
    }
}
