//! OCI-specific HTTP middleware.
//!
//! The OCI subtree (`/v2/*`) owns its own auth story: the global
//! method-based auth dispatch in `hort_http_core::router` short-circuits
//! on OCI paths and lets [`oci_auth::oci_bearer_auth`] handle
//! authentication via hort-server-minted JWTs.

pub mod oci_auth;
