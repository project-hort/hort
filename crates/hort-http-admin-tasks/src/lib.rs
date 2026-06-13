//! `hort-http-admin-tasks` — inbound HTTP adapter for the admin-task REST
//! surface (see `how-to/using-hort-cli-with-admin-ops.md` and ADR 0028).
//!
//! # Routes
//!
//! All routes mount under the `/api/v1/admin/tasks` prefix (supplied by
//! `hort-server::http`). The local router carries only the suffix:
//!
//! ```text
//! POST   /                           → invoke::<NoopParams>         (noop)
//! POST   /scan                       → invoke::<ScanRawParams>
//! POST   /cron-rescan-tick           → invoke::<CronRescanTickRawParams>
//! POST   /advisory-watch-tick        → invoke::<AdvisoryWatchTickRawParams>
//! POST   /retention-evaluate         → invoke::<RetentionEvaluateRawParams>
//! POST   /retention-purge            → invoke::<RetentionPurgeRawParams>
//! POST   /eventstore-archive         → invoke::<EventstoreArchiveRawParams>
//! POST   /staging-sweep              → invoke::<StagingSweepParams>
//! POST   /service-account-rotation   → invoke::<ServiceAccountRotationRawParams>
//! POST   /eventstore-checkpoint      → invoke::<EventstoreCheckpointRawParams>
//! POST   /replay-seen-prune          → invoke::<ReplaySeenPruneRawParams>
//! GET    /                           → list_tasks
//! GET    /:id                        → get_task
//! ```
//!
//! # Dep-graph invariant
//!
//! This crate MUST NOT depend on any `hort-adapters-*` crate, `sqlx`, or
//! `reqwest`. See `Cargo.toml` note and the CLAUDE.md anti-pattern rule.
//! Run:
//!
//! ```text
//! cargo tree -p hort-http-admin-tasks --edges normal --prefix none
//! ```
//!
//! and verify `hort-adapters-*`, `sqlx`, and `reqwest` are absent.

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;

use hort_http_core::context::AppContext;

use handlers::get::get_task;
use handlers::invoke::invoke;
use handlers::list::list_tasks;
use params::{
    AdvisoryWatchTickRawParams, CronRescanTickRawParams, EventstoreArchiveRawParams,
    EventstoreCheckpointRawParams, NoopParams, ReplaySeenPruneRawParams,
    RetentionEvaluateRawParams, RetentionPurgeRawParams, ScanRawParams,
    ServiceAccountRotationRawParams, StagingSweepParams,
};

pub mod dto;
pub mod handlers;
pub mod params;

/// Build the admin-task route subtree.
///
/// Mount under `/api/v1/admin/tasks` in `hort-server::http`:
///
/// ```rust,ignore
/// router.nest("/api/v1/admin/tasks", hort_http_admin_tasks::router())
/// ```
pub fn router() -> Router<Arc<AppContext>> {
    Router::new()
        // --- task-kind invoke endpoints ---
        .route("/noop", post(invoke::<NoopParams>))
        .route("/scan", post(invoke::<ScanRawParams>))
        .route("/cron-rescan-tick", post(invoke::<CronRescanTickRawParams>))
        .route(
            "/advisory-watch-tick",
            post(invoke::<AdvisoryWatchTickRawParams>),
        )
        .route(
            "/retention-evaluate",
            post(invoke::<RetentionEvaluateRawParams>),
        )
        .route("/retention-purge", post(invoke::<RetentionPurgeRawParams>))
        .route(
            "/eventstore-archive",
            post(invoke::<EventstoreArchiveRawParams>),
        )
        .route("/staging-sweep", post(invoke::<StagingSweepParams>))
        .route(
            "/service-account-rotation",
            post(invoke::<ServiceAccountRotationRawParams>),
        )
        .route(
            "/eventstore-checkpoint",
            post(invoke::<EventstoreCheckpointRawParams>),
        )
        .route(
            "/replay-seen-prune",
            post(invoke::<ReplaySeenPruneRawParams>),
        )
        // --- list + get ---
        .route("/", get(list_tasks))
        .route("/:id", get(get_task))
}
