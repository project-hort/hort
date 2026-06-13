//! Format-agnostic HTTP handlers shared across all inbound HTTP crates.
//!
//! Per-format handlers (cargo, npm, pypi, oci) live in their own
//! `hort-http-<format>` crate. Only the format-neutral surface lives here:
//! repository administration and the Prometheus scrape endpoint.

pub mod admin;
pub mod api_tokens;
/// `GET /api/v1/auth/whoami`.
pub mod auth;
pub mod exchange;
pub mod health;
pub mod metrics;
pub(crate) mod token_exchange_common;
pub mod well_known;
