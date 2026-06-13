//! Composition root for the v2 service binary.
//!
//! The binary crate is the only place in the workspace that:
//! - Installs the `tracing` subscriber and Prometheus recorder globally.
//! - Reads environment variables (via [`config::Config::from_env`]).
//! - Registers OS signal handlers.
//! - Opens real Postgres and storage connections.
//! - Assembles the top-level axum router from the per-format
//!   `hort-http-<format>` crates (see [`http`]).
//!
//! Library crates (`hort-app`, `hort-domain`, `hort-http-core`,
//! `hort-http-<format>`, etc.) remain pure and driven by mocks + local
//! recorders in their own tests. The binary wires them together.

pub mod cli;
pub mod composition;
pub mod config;
pub mod gitops_boot;
pub mod http;
pub mod migrate;
pub mod serve_loop;
pub mod shutdown;
pub mod shutdown_deadline;
pub mod storage;
pub mod telemetry;
