//! `hort-http-discovery` — inbound HTTP adapter for the repo-keyed
//! discovery + self-service prefetch REST surface.
//! See `docs/architecture/explanation/prefetch-pipeline.md` and ADR 0013.
//!
//! # Routes
//!
//! All routes mount under `/api/v1` in `hort-server::http` (mounting
//! is NOT this crate's responsibility). The local router fragment
//! carries the repo-keyed suffix:
//!
//! ```text
//! GET  /repositories/:repo_key/discovery/versions/:package_name
//!      → handlers::list_versions::list_versions
//! POST /repositories/:repo_key/prefetch
//!      → handlers::prefetch::prefetch
//! ```
//!
//! # Security posture
//!
//! - `GET .../discovery/versions/:package_name` requires an authenticated
//!   principal carrying `TokenKind::CliSession`. PATs and service-account
//!   tokens are rejected with `403 Forbidden`.
//! - `POST .../prefetch` accepts `TokenKind::CliSession` **or**
//!   `TokenKind::ServiceAccount` — a service-account caller is admitted
//!   only if its resolved grants include `Permission::Read ∧
//!   Permission::Prefetch` on the target repository (the same
//!   `RbacEvaluator` path every other permission check uses). PATs are
//!   still rejected. This is a deliberate divergence from the discovery
//!   endpoint above: the CI prefetch caller is specified as a
//!   read+prefetch-only, non-admin ServiceAccount bearer
//!   (`docs/ci/hort-quarantine-integration.md`) — the prior blanket
//!   CliSession-only gate on this endpoint was implementation drift from
//!   that spec (issue #80).
//!
//! Both gates live inside the use case (per the architect-doc *"Emission
//! by layer"* rule — business metrics emit at `hort-app`, not the inbound
//! layer); the handlers are thin wrappers.
//!
//! # Dep-graph invariant
//!
//! This crate MUST NOT depend on any `hort-adapters-*` crate, `sqlx`, or
//! `reqwest`. See `Cargo.toml` note and the CLAUDE.md anti-pattern rule.
//! Verify with:
//!
//! ```text
//! cargo tree -p hort-http-discovery --edges normal --prefix none
//! ```
//!
//! and confirm `hort-adapters-*`, `sqlx`, and `reqwest` are absent. An
//! adapter import here is a **compile-time architectural failure**, not
//! a review finding (ADR 0008).

pub mod dto;
pub mod handlers;
pub mod routes;

pub use routes::routes;
