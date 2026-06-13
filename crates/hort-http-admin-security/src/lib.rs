//! Inbound HTTP adapter for the admin security-score surface and the
//! per-artifact manual rescan trigger.
//!
//! Endpoints:
//!
//! - `GET /api/v1/repositories/:name/security-score` — single repo
//!   score. Pure read against
//!   [`hort_app::use_cases::security_score_use_case::SecurityScoreUseCase`].
//! - `GET /api/v1/security-score?cursor=...&limit=...` — paginated
//!   list. Same use case.
//! - `POST /api/v1/artifacts/:id/rescan` — manual rescan. Drives
//!   [`hort_app::use_cases::manual_rescan_use_case::ManualRescanUseCase`];
//!   inserts a `kind='scan'` row with `trigger_source='manual'`,
//!   `priority=20`. RBAC: `Permission::Write` on the artifact's
//!   parent repository. Returns `202 Accepted` with
//!   `{ "task_job_id": <uuid> }`.
//!
//! Per ADR 0008 (per-format-crate adapter-free invariant), this crate
//! depends only on:
//!
//! - [`hort_domain`] — port traits + domain types.
//! - [`hort_app`] — use-case orchestration.
//! - [`hort_http_core`] — `AppContext`, `ApiError`, principal extractor.
//! - `axum`, `serde`, `tracing`, `chrono`, `uuid`, `metrics`.
//!
//! It MUST NOT pull in any `hort-adapters-*` crate, `sqlx`, or `reqwest`.
//! An adapter import here is a compile-time architectural failure, NOT
//! a review finding.

pub mod dto;
pub mod handlers;
pub mod router;
