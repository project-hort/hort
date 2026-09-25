//! Generic `invoke<P: TaskParams>` handler.
//!
//! Mounts once per task `kind` at route registration time. The concrete
//! `P` type carries the `KIND` constant (used for the metric label) and
//! the `validate` method (semantic checks before the use-case call).
//!
//! # Flow
//!
//! 1. Extract the authenticated caller via `AuthenticatedCaller`.
//!    Under `AuthContext::Disabled` (or anonymous Enabled) → respond 401.
//! 2. Deserialise the request body into `P`.
//! 3. Call `params.validate()` → 422 on failure.
//! 4. Check the `Idempotency-Key` header. If present and already cached
//!    for the same kind and params in `ctx.ephemeral_durable` → respond 200
//!    with the cached `task_job_id`.
//! 5. Call `ctx.task_use_case.enqueue(principal, P::KIND, params_value)`.
//! 6. Store `idem-task:<key>` → `{task_job_id, kind, params}` in
//!    `ephemeral_durable` with a 300 s TTL.
//! 7. Return 202 on the fresh path, 200 on the cache-hit path.
//!
//! # Metrics
//!
//! `hort_admin_tasks_enqueued_total{kind, result}` is incremented at every
//! terminal path:
//!
//! - `result="ok"` — 202 fresh enqueue **or** 200 idempotency cache-hit.
//!   Both map to `"ok"` because the operator's intent (enqueue the task)
//!   was semantically satisfied; the cache-hit just de-duplicates a
//!   previously-accepted request. Operators who need to distinguish the
//!   two paths should consult the `Idempotency-Key`-keyed log line
//!   emitted by the handler at `DEBUG` level.
//! - `result="rbac_denied"` — `TaskUseCase::enqueue` returned
//!   `AppError::Domain(DomainError::Forbidden)`.
//! - `result="validation_error"` — `params.validate()` failed **or**
//!   the use case returned `AppError::Domain(DomainError::Validation)`.
//!
//! No counter is emitted for the 403 "no principal" path — that path
//! indicates a misconfigured caller or a missing auth middleware, not an
//! operator invocation attempt. Counting it under `rbac_denied` would
//! conflate two different root causes.
//!
//! # Dep-graph invariant
//!
//! This file imports nothing from `hort-adapters-*`, `sqlx`, or `reqwest`.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use bytes::Bytes;
use metrics::counter;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use hort_app::error::AppError;
use hort_domain::error::DomainError;
use hort_domain::types::IdempotencyKey;

use hort_http_core::authz::extractors::AuthenticatedCaller;
use hort_http_core::context::AppContext;
use hort_http_core::error::ApiError;

use crate::params::{TaskParams, ValidationError};

/// Header name for request-level idempotency (RFC 9110 §14.1 spirit).
const IDEMPOTENCY_KEY_HEADER: &str = "Idempotency-Key";

/// Key prefix for idempotency entries stored in `ephemeral_durable`.
/// Registered in `KEYSPACE_REGISTRY` as `Durable`.
pub(crate) const IDEM_TASK_PREFIX: &str = "idem-task:";

/// TTL applied to every idempotency-key cache entry.
const IDEM_TTL: Duration = Duration::from_secs(300);

/// Maximum byte length of an `Idempotency-Key` header value.
/// Prevents pathological cache-key attacks.
const MAX_IDEM_KEY_BYTES: usize = 128;

/// Metric name emitted on every terminal path.
const METRIC_ENQUEUED: &str = "hort_admin_tasks_enqueued_total";

/// `result` label values for `hort_admin_tasks_enqueued_total`.
const RESULT_OK: &str = "ok";
const RESULT_RBAC_DENIED: &str = "rbac_denied";
const RESULT_VALIDATION_ERROR: &str = "validation_error";

/// Wire response for a successful `POST /api/v1/admin/tasks/{kind}`.
///
/// `task_job_id` is the newly-inserted (or previously-cached) `jobs.id`.
/// Consumers poll `GET /api/v1/admin/tasks/:id` to observe the row's
/// lifecycle state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvokeResponse {
    /// The `jobs.id` of the enqueued or previously-cached task.
    pub task_job_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedInvocation {
    task_job_id: Uuid,
    kind: String,
    params: serde_json::Value,
}

/// Generic handler invoked for each task kind.
///
/// Mounted once per `kind` at route registration; the `P` type parameter
/// carries the `KIND` constant and `validate` method appropriate for that
/// kind.
///
/// # Authentication
///
/// `AuthenticatedCaller` extracts the principal from request extensions,
/// reading both the `require_principal` slot AND the
/// `extract_optional_principal` slot — so the handler cannot regress
/// to the 2026-05-11 GET-only 403 bug. Anonymous callers get 401 from
/// the extractor before reaching the use-case RBAC check
/// (`Permission::AdminTaskInvoke`); the use case enforces the admin
/// gate on the principal that does come through.
pub async fn invoke<P: TaskParams>(
    State(ctx): State<Arc<AppContext>>,
    headers: HeaderMap,
    AuthenticatedCaller(principal): AuthenticatedCaller,
    Json(params): Json<P>,
) -> Result<(StatusCode, Json<InvokeResponse>), ApiError> {
    let params_value = serde_json::to_value(&params).map_err(|e| {
        ApiError(AppError::Domain(DomainError::Invariant(format!(
            "params serialization failed: {e}"
        ))))
    })?;

    // Step 1 — per-kind authz FIRST.
    //
    // The RBAC check (coarse `Permission::AdminTaskInvoke` AND, for a
    // destructive invocation, the `task:destructive` claim) runs **before**
    // param-validation and before the attacker-controlled
    // `Idempotency-Key` ephemeral-store probe. This prevents an
    // unauthenticated/under-privileged caller from probing param-validation
    // and the ephemeral store pre-authz. `TaskUseCase::enqueue` STILL
    // calls the same `authorize_kind` internally (defense-in-depth — a
    // direct use-case caller stays gated); sharing the method enforces it
    // first at the HTTP boundary too. An unknown `kind` never reaches here
    // — the route is not mounted (404 at the router).
    if let Err(err) = ctx
        .task_use_case
        .authorize_kind(&principal, P::KIND, &params_value)
    {
        if matches!(err, AppError::Domain(DomainError::Forbidden(_))) {
            counter!(METRIC_ENQUEUED, "kind" => P::KIND, "result" => RESULT_RBAC_DENIED)
                .increment(1);
        } else if matches!(err, AppError::Domain(DomainError::Validation(_))) {
            counter!(METRIC_ENQUEUED, "kind" => P::KIND, "result" => RESULT_VALIDATION_ERROR)
                .increment(1);
        }
        return Err(ApiError(err));
    }

    // Step 2 — validate task params (semantic checks; JSON schema is
    // enforced by the `Json` extractor already).
    if let Err(ValidationError(msg)) = params.validate() {
        counter!(METRIC_ENQUEUED, "kind" => P::KIND, "result" => RESULT_VALIDATION_ERROR)
            .increment(1);
        return Err(ApiError(AppError::Domain(DomainError::Validation(msg))));
    }

    // Step 3 — check the Idempotency-Key header.
    let idem_key: Option<String> = headers
        .get(IDEMPOTENCY_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .map(ToString::to_string);

    if let Some(ref key) = idem_key {
        if key.len() > MAX_IDEM_KEY_BYTES {
            return Err(ApiError(AppError::Domain(DomainError::Validation(
                format!("Idempotency-Key exceeds {MAX_IDEM_KEY_BYTES}-byte limit"),
            ))));
        }

        let store_key = format!("{IDEM_TASK_PREFIX}{key}");
        let cached = ctx.ephemeral_durable.get(&store_key).await.map_err(|e| {
            tracing::error!(error = %e, "ephemeral_durable.get failed for idempotency key");
            ApiError(AppError::Domain(DomainError::Invariant(
                "ephemeral store unavailable".into(),
            )))
        })?;

        if let Some(bytes) = cached {
            // A legacy raw UUID or a record for another kind/param set is
            // an unverified miss. Only an exact invocation record is a hit.
            // Emit result="ok": the operator's intent (enqueue this task) was
            // already satisfied by the prior request; the cache-hit is a
            // de-duplication courtesy, not a distinct failure mode.
            if let Ok(record) = serde_json::from_slice::<CachedInvocation>(&bytes) {
                if record.kind == P::KIND && record.params == params_value {
                    let task_job_id = record.task_job_id;
                    counter!(METRIC_ENQUEUED, "kind" => P::KIND, "result" => RESULT_OK)
                        .increment(1);
                    return Ok((StatusCode::OK, Json(InvokeResponse { task_job_id })));
                }
            }
        }
    }

    // Step 4b — derive the DB-layer idempotency key for destructive
    // **invocations** (see ADR 0028 / `how-to/using-hort-cli-with-admin-ops.md`
    // for the destructive-invocation idempotency contract).
    //
    // Server-derived per-UTC-day key, distinct in shape from the
    // client-supplied `Idempotency-Key` header (`<window>:<kind>`,
    // `hort_cli::admin::task_invoke::format_window_key`) so the Redis
    // fast-path and the DB partial-unique layer cannot collide on a
    // key. The Redis fast-path stays an additional cheap layer for
    // destructive kinds; the DB layer is the durable one.
    //
    // The gate is `task_invocation_is_destructive` — the same domain
    // answer Step 1's `task:destructive` claim check reads, deliberately
    // NOT the per-kind `task_kind_is_destructive`. The key exists so a
    // destructive sweep cannot re-fire; an observation has no such hazard
    // and must stay repeatable, because "look again" is the one thing a
    // preview has to support. Asking the per-kind question here would
    // deduplicate the second dry run of a UTC day back to the first and
    // report a stale observation as a fresh one. Anything that is not a
    // destructive invocation passes `None`: the DB partial-unique check
    // is inert and the insert always proceeds.
    //
    // Both `?`s below are structurally unreachable here. The mode was
    // already parsed once by Step 1's authorization check and once more
    // by Step 2's `params.validate()`, either of which rejects an
    // unparseable one before this point; re-reading it is free and keeps
    // the derivation honest about the invocation it is keying. And every
    // `DESTRUCTIVE_TASK_KINDS` literal is charset-clean while the UTC date
    // pattern is `\d{4}-\d{2}-\d{2}`, well within `IdempotencyKey`'s
    // charset and length bounds — the fallible ctor stays so that adding a
    // destructive kind that violates the charset would surface as a clean
    // error rather than a panic.
    //
    // The mode segment stays in the key even though a dry run no longer
    // reaches this branch: it costs nothing, it names the dimension the
    // key separates on, and it means a second kind gaining a mode cannot
    // silently collapse two invocations onto one key.
    let db_idempotency_key: Option<IdempotencyKey> =
        if hort_domain::events::task_invocation_is_destructive(P::KIND, &params_value)? {
            let utc_today = chrono::Utc::now().format("%Y-%m-%d");
            let derived = if P::KIND == hort_domain::events::RETENTION_EVALUATE_TASK_KIND {
                let mode = hort_domain::events::retention_evaluate_mode(&params_value)?;
                format!("cron:{}:{}:{utc_today}", P::KIND, mode.as_str())
            } else {
                format!("cron:{}:{utc_today}", P::KIND)
            };
            Some(IdempotencyKey::try_from(derived)?)
        } else {
            None
        };

    // Step 5 — call the use case (RBAC check + jobs INSERT + event append).
    //
    // The destructive-kind path threads `Some(server-derived-key)` into
    // the use case so the DB partial-unique check is engaged. A second
    // same-day enqueue of the same destructive kind returns
    // `EnqueueOutcome::Duplicate`; we surface that as 200 + the existing
    // `task_job_id` (same shape as the Redis fast-path cache-hit at
    // lines 172-182). The metric emits `result="ok"` — operator intent
    // (enqueue this task) was already satisfied.
    let task_job_id = match ctx
        .task_use_case
        .enqueue(
            &principal,
            P::KIND,
            &params_value,
            db_idempotency_key.as_ref(),
        )
        .await
    {
        Ok(hort_domain::ports::jobs_repository::EnqueueOutcome::Enqueued { job_id }) => job_id,
        Ok(hort_domain::ports::jobs_repository::EnqueueOutcome::Duplicate { existing_job_id }) => {
            // DB-layer dedup hit — same shape as the Redis fast-path
            // hit (lines 172-182): 200 + the existing task_job_id +
            // `result="ok"`. The operator's intent (enqueue this task)
            // was already satisfied by the prior same-day enqueue; this
            // is the de-duplication courtesy, not a distinct failure
            // mode.
            //
            // The `info!` is an audit-trail signal (NOT `err`),
            // mirroring the existing Forbidden/Validation denial
            // logging in the handler.
            tracing::info!(
                existing_job_id = %existing_job_id,
                kind = P::KIND,
                idempotency_key = db_idempotency_key.as_ref().map(IdempotencyKey::as_str),
                "destructive task enqueue deduped at DB partial-unique layer",
            );
            counter!(METRIC_ENQUEUED, "kind" => P::KIND, "result" => RESULT_OK).increment(1);
            return Ok((
                StatusCode::OK,
                Json(InvokeResponse {
                    task_job_id: existing_job_id,
                }),
            ));
        }
        Err(AppError::Domain(DomainError::Forbidden(msg))) => {
            counter!(METRIC_ENQUEUED, "kind" => P::KIND, "result" => RESULT_RBAC_DENIED)
                .increment(1);
            return Err(ApiError(AppError::Domain(DomainError::Forbidden(msg))));
        }
        Err(AppError::Domain(DomainError::Validation(msg))) => {
            counter!(METRIC_ENQUEUED, "kind" => P::KIND, "result" => RESULT_VALIDATION_ERROR)
                .increment(1);
            return Err(ApiError(AppError::Domain(DomainError::Validation(msg))));
        }
        Err(other) => return Err(ApiError(other)),
    };

    // Step 6 — store the idempotency mapping in ephemeral_durable.
    if let Some(key) = idem_key {
        let store_key = format!("{IDEM_TASK_PREFIX}{key}");
        let record = CachedInvocation {
            task_job_id,
            kind: P::KIND.to_owned(),
            params: params_value,
        };
        let record_bytes = serde_json::to_vec(&record).map_err(|e| {
            ApiError(AppError::Domain(DomainError::Invariant(format!(
                "idempotency record serialization failed: {e}"
            ))))
        })?;
        let id_bytes = Bytes::from(record_bytes);
        // Best-effort — a cache write failure does NOT abort the response.
        // The task was already enqueued successfully; the idempotency
        // window is a convenience, not a correctness invariant.
        if let Err(e) = ctx
            .ephemeral_durable
            .put(&store_key, id_bytes, IDEM_TTL)
            .await
        {
            tracing::warn!(error = %e, "ephemeral_durable.put failed for idempotency key — idem window will not be cached");
        }
    }

    // Step 7 — return 202 Accepted.
    counter!(METRIC_ENQUEUED, "kind" => P::KIND, "result" => RESULT_OK).increment(1);
    Ok((StatusCode::ACCEPTED, Json(InvokeResponse { task_job_id })))
}
