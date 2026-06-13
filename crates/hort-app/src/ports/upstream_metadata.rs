//! `UpstreamMetadataPort` trait.
//!
//! Fetch + parse the upstream-advertised version list for a `(format,
//! package)` pair, scoped by a repository's [`RepositoryUpstreamMapping`].
//! Consumed by the discovery use case and the self-service prefetch
//! use case (see `docs/architecture/explanation/prefetch-pipeline.md`).
//!
//! # Why this port lives in `hort-app` (not `hort-domain`)
//!
//! The port composes two halves:
//!
//! * **Parsing side** — already in
//!   [`hort_domain::ports::format_handler::FormatHandler`]:
//!   `extract_upstream_versions` parses an npm packument /
//!   PyPI simple-index / Cargo sparse-index NDJSON body into a
//!   `Vec<String>`, and `upstream_metadata_path` returns the
//!   format-specific URL path for the package metadata fetch.
//! * **Fetch side** — the existing async helpers in the
//!   `hort-http-<format>` crates: `hort_http_npm::packument::
//!   fetch_raw_with_cache`, `hort_http_pypi::simple_index::
//!   fetch_raw_with_cache`, `hort_http_cargo::index_cache::
//!   fetch_raw_with_cache`.
//!
//! Async + `reqwest` are anti-pattern hard blocks in `hort-domain` per
//! `CLAUDE.md` → architectural direction. So the composing port lives
//! in `hort-app`, while `FormatHandler` itself stays unchanged — bolting
//! `async fn list_versions` onto `FormatHandler` would drag `reqwest`
//! into the pure-parsing layer.
//!
//! # Implementation placement
//!
//! The concrete implementation lives in the dedicated
//! `hort-formats-upstream` crate, composing the per-format inbound-HTTP
//! crates' fetch helpers in one place. This module is **only** the trait
//! + the typed error import — no impl, no `AppContext` wiring.
//!
//! # Mock
//!
//! A test-support mock lives in [`crate::use_cases::test_support`] under
//! `MockUpstreamMetadataPort`, gated by the `test-support` Cargo feature
//! (the same pattern every other `hort-app` mock uses).

use hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMapping;
use hort_domain::ports::BoxFuture;

use crate::metrics::UpstreamFetchError;

/// Outbound port: fetch + parse the upstream-advertised version list
/// for a `(format, package)` pair, scoped by a repository's
/// [`RepositoryUpstreamMapping`].
///
/// Returns `Result<Vec<String>, UpstreamFetchError>` (NOT
/// `DomainResult<Vec<String>>`). The typed error is mandatory — the
/// consuming discovery + self-service-prefetch use cases emit
/// `hort_discovery_list_versions_total` /
/// `hort_prefetch_self_service_total` with `result` labels drawn from
/// [`crate::metrics::UpstreamErrorKind`]. A flat
/// `DomainError::Validation(String)` from the port would force the use
/// case to re-parse a free-form message to recover the metric label —
/// exactly the classification-after-the-fact the architect-doc
/// "result enums live with the emitting layer" rule is designed to
/// prevent. The adapter (`hort-formats-upstream`)
/// classifies once at fetch time; the use case pattern-matches once
/// at emission time; the metric label is stable across the layer
/// boundary.
///
/// # Dispatch by `format`
///
/// `format` is the protocol key (`"npm"`, `"pypi"`, `"cargo"`).
/// Dispatch is inside the implementation (a `format → fetch-helper`
/// table). For `"oci"` and any unrecognised format string, the impl
/// returns [`UpstreamFetchError::UnsupportedFormat`] — OCI discovery
/// is deliberately out of scope here: OCI uses its
/// registry-protocol-native `/v2/_catalog` and `/v2/{name}/tags/list`
/// for discovery, and `crane pull` / `docker pull` for warm-up. The
/// use case maps this variant to metric `result = "oci_unsupported"`
/// and the inbound layer maps to `400 Bad Request`.
///
/// # Caches
///
/// The impl reuses the existing per-format packument / simple-index /
/// sparse-index caches; this port is the composition surface, not a
/// duplicate cache layer.
pub trait UpstreamMetadataPort: Send + Sync {
    /// Fetch + parse the upstream-advertised version list.
    ///
    /// See the trait-level docs for parameter semantics and the
    /// `UnsupportedFormat` short-circuit on OCI / unknown formats.
    fn list_versions<'a>(
        &'a self,
        format: &'a str,
        mapping: &'a RepositoryUpstreamMapping,
        package: &'a str,
    ) -> BoxFuture<'a, Result<Vec<String>, UpstreamFetchError>>;
}

#[cfg(test)]
mod tests {
    //! Tests for the `UpstreamMetadataPort` trait surface.
    //!
    //! The trait itself is `dyn`-compatible (object-safe) and uses
    //! `BoxFuture` rather than `async fn` per the workspace
    //! convention — these tests pin that contract by constructing
    //! `Arc<dyn UpstreamMetadataPort>` from the test-support mock and
    //! exercising every branch the mock can produce.
    //!
    //! Behavioural coverage of every `UpstreamFetchError` variant
    //! lives on the mock itself (`crate::use_cases::test_support`); here
    //! we exercise the happy path + the `UnsupportedFormat` short-
    //! circuit so the trait-level dispatch contract is locked in.

    use std::sync::Arc;

    use chrono::Utc;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::ports::repository_upstream_mapping_repository::{
        RepositoryUpstreamMapping, UpstreamAuth,
    };
    use uuid::Uuid;

    use crate::metrics::UpstreamFetchError;
    use crate::use_cases::test_support::MockUpstreamMetadataPort;

    use super::UpstreamMetadataPort;

    fn sample_mapping() -> RepositoryUpstreamMapping {
        // A minimal mapping. The mock is keyed on `(format, package)`
        // and ignores the mapping body, so concrete field values are
        // irrelevant — what we want here is *a* valid-shaped mapping
        // so the trait method signature compiles.
        let now = Utc::now();
        RepositoryUpstreamMapping {
            id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            path_prefix: String::new(),
            upstream_url: "https://upstream.example/".into(),
            upstream_name_prefix: None,
            upstream_auth: UpstreamAuth::Anonymous,
            secret_ref: None,
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
            insecure_upstream_url: false,
            trust_upstream_publish_time: false,
            mtls_cert_ref: None,
            mtls_key_ref: None,
            ca_bundle_ref: None,
            pinned_cert_sha256: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[tokio::test]
    async fn dyn_dispatch_returns_seeded_versions_on_happy_path() {
        // The trait MUST be object-safe — composing through `Arc<dyn _>`
        // is how `AppContext` will hold the impl in Item 8.
        let mock = MockUpstreamMetadataPort::new();
        mock.insert_versions("npm", "left-pad", Ok(vec!["1.0.0".into(), "1.1.0".into()]));
        let port: Arc<dyn UpstreamMetadataPort> = Arc::new(mock);

        let got = port
            .list_versions("npm", &sample_mapping(), "left-pad")
            .await
            .expect("happy path returns Ok");
        assert_eq!(got, vec!["1.0.0".to_string(), "1.1.0".to_string()]);
    }

    #[tokio::test]
    async fn dyn_dispatch_propagates_unsupported_format_for_oci() {
        // §8 non-goal — OCI dispatch returns `UnsupportedFormat`
        // straight from the port; the use case maps to
        // `result = "oci_unsupported"`.
        let mock = MockUpstreamMetadataPort::new();
        // No insert for "oci" — the default policy in the mock returns
        // `UnsupportedFormat` for any unseeded format string.
        let port: Arc<dyn UpstreamMetadataPort> = Arc::new(mock);

        let got = port
            .list_versions("oci", &sample_mapping(), "library/alpine")
            .await;
        assert_eq!(got, Err(UpstreamFetchError::UnsupportedFormat));
    }

    #[tokio::test]
    async fn dyn_dispatch_propagates_unsupported_format_for_unknown_format() {
        let mock = MockUpstreamMetadataPort::new();
        let port: Arc<dyn UpstreamMetadataPort> = Arc::new(mock);

        let got = port
            .list_versions("not-a-real-format", &sample_mapping(), "x")
            .await;
        assert_eq!(got, Err(UpstreamFetchError::UnsupportedFormat));
    }
}
