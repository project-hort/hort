//! # hort-http-core::middleware — Cross-cutting HTTP middleware
//!
//! Holds the Prometheus metrics middleware plus the auth layers
//! (`require_principal`, `extract_optional_principal` — see
//! `docs/auth-catalog.md` and ADR 0021), the [`trust`] layer that
//! establishes per-request [`trust::RequestTrust`] before any downstream
//! consumer (`docs/architecture/explanation/security.md`), and the
//! [`rate_limit`] layers built on top of it.

pub mod auth;
pub mod load_shed;
pub mod metrics;
pub mod rate_limit;
pub mod request_timeout;
pub mod security_headers;
pub mod trust;
