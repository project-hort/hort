//! `hort-http-admin-tasks` — inbound HTTP adapter for the admin-task REST
//! surface (see `how-to/using-hort-cli-with-admin-ops.md` and ADR 0028).
//!
//! # Routes
//!
//! All routes mount under the `/api/v1/admin/tasks` prefix (supplied by
//! `hort-server::http`). The local router carries only the suffix:
//!
//! ```text
//! POST   /noop                       → invoke::<NoopParams>
//! POST   /cron-rescan-tick           → invoke::<CronRescanTickRawParams>
//! POST   /advisory-watch-tick        → invoke::<AdvisoryWatchTickRawParams>
//! POST   /retention-evaluate         → invoke::<RetentionEvaluateParams>
//! POST   /retention-purge            → invoke::<RetentionPurgeRawParams>
//! POST   /eventstore-archive         → invoke::<EventstoreArchiveRawParams>
//! POST   /staging-sweep              → invoke::<StagingSweepParams>
//! POST   /service-account-rotation   → invoke::<ServiceAccountRotationRawParams>
//! POST   /eventstore-checkpoint      → invoke::<EventstoreCheckpointRawParams>
//! POST   /replay-seen-prune          → invoke::<ReplaySeenPruneRawParams>
//! POST   /scanner-registry-prune     → invoke::<ScannerRegistryPruneRawParams>
//! GET    /                           → list_tasks
//! GET    /{id}                       → get_task
//! ```
//!
//! # The invoke routes are a strict subset of `ADMIN_INVOKABLE_TASK_KINDS`
//!
//! Those eleven `POST` routes are the whole invoke surface. Every other
//! member of `hort_domain::events::ADMIN_INVOKABLE_TASK_KINDS` — the
//! three row-retention sweeps, `quarantine-release-sweep`,
//! `prefetch-tick`, `wheel-metadata-backfill`, and the rest — answers
//! **404** here. That is not a gap to be closed by widening this list:
//! `ADMIN_INVOKABLE_TASK_KINDS` is the set of kinds an admin may enqueue
//! *at all* (it also gates the DSN-direct `hort-server enqueue-*`
//! subcommands, event validation, and two handler-level assertions), so
//! the router being a subset of it is the design. The routeless kinds are
//! reached off-schedule by running their `hort-server enqueue-*`
//! subcommand on the runtime DSN, which is the same command their
//! CronJob / systemd timer runs.
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
    EventstoreCheckpointRawParams, NoopParams, ReplaySeenPruneRawParams, RetentionEvaluateParams,
    RetentionPurgeRawParams, ScannerRegistryPruneRawParams, ServiceAccountRotationRawParams,
    StagingSweepParams,
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
        .route("/cron-rescan-tick", post(invoke::<CronRescanTickRawParams>))
        .route(
            "/advisory-watch-tick",
            post(invoke::<AdvisoryWatchTickRawParams>),
        )
        .route(
            "/retention-evaluate",
            post(invoke::<RetentionEvaluateParams>),
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
        .route(
            "/scanner-registry-prune",
            post(invoke::<ScannerRegistryPruneRawParams>),
        )
        // --- list + get ---
        .route("/", get(list_tasks))
        .route("/{id}", get(get_task))
}
