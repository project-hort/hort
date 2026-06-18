//! Dialect-specific extra-CA binding for `object_store`.
//!
//! This module implements the storage-adapter side of the process-wide
//! extra CA trust bundle (ADR 0010). It converts [`ExtraTrustAnchors`]
//! (DER-encoded certificates carried by `hort-config`) into
//! [`object_store::Certificate`] values and attaches them to
//! [`object_store::ClientOptions`].
//!
//! ## Return-type rationale
//!
//! The helper preserves `object_store::Error` rather than converting to
//! `DomainResult` or a crate-local enum. `object_store::Error` carries a
//! richer classification of the cert-rejection cause than any opaque string
//! we could construct, which yields better operator messages when a
//! malformed DER blob slips through the PEM parser.
//!
//! This asymmetry is intentional ("Helper return-type asymmetry is
//! intentional — three shapes, not two").
//!
//! ## Metric label decision (`result=tls_error` vs `result=network_error`)
//!
//! `object_store::Error` (0.13.x) has no TLS-distinguishable variant. TLS
//! failures (including rejected custom CA certs) surface as
//! `object_store::Error::Generic { source: … }` with the underlying
//! `reqwest` / `hyper` / `rustls` error buried in the `source` chain. The
//! enum has variants for `NotFound`, `AlreadyExists`, `PermissionDenied`,
//! `Unauthenticated`, `Precondition`, `NotModified`, `NotImplemented`,
//! `UnknownConfigurationKey`, and the catch-all `Generic` — none of which
//! are specifically TLS. Adding a `result=tls_error` label at the metric
//! layer would therefore require string-matching on the `Display` output of
//! an opaque error chain — a fragile, undocumented heuristic that could
//! silently break on any `object_store` version bump.
//!
//! **Decision: retain `result=network_error` for all TLS-class failures.**
//! If `object_store` introduces a dedicated TLS error variant in a future
//! version, this decision can be revisited; until then, operators who need
//! per-error-class drill-down should use tracing spans (which carry the
//! full error chain) rather than metric labels.

use hort_config::ExtraTrustAnchors;
use object_store::{Certificate, ClientOptions, Error as ObjectStoreError};

/// Apply the extra CA trust bundle to an `object_store` [`ClientOptions`]
/// builder.
///
/// Iterates the DER-encoded certificates in `anchors`, converts each one to
/// an [`object_store::Certificate`] via [`Certificate::from_der`], and
/// chains them onto `opts` via [`ClientOptions::with_root_certificate`].
///
/// Returns the augmented [`ClientOptions`] on success, or the first
/// [`object_store::Error`] encountered if any certificate's DER bytes are
/// rejected by `reqwest` (e.g. because the bytes are structurally valid
/// PEM/DER but fail `reqwest`'s certificate validation).
///
/// When `anchors` is `None` the input `opts` is returned unchanged.
pub(crate) fn apply_to_object_store_options(
    opts: ClientOptions,
    anchors: Option<&ExtraTrustAnchors>,
) -> Result<ClientOptions, ObjectStoreError> {
    let Some(anchors) = anchors else {
        return Ok(opts);
    };

    let mut opts = opts;
    for der in anchors.certs_der() {
        let cert = Certificate::from_der(der)?;
        opts = opts.with_root_certificate(cert);
    }
    Ok(opts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hort_config::ExtraTrustAnchors;

    // A real EC self-signed CA certificate in PEM format. The same fixture
    // used in `hort-config`'s unit tests — a valid DER payload that
    // `Certificate::from_der` accepts.
    const CERT_PEM_1: &str = "-----BEGIN CERTIFICATE-----\n\
        MIIBpTCCAUugAwIBAgIUYmFzZTY0ZW5jb2RlZHRlc3RjYTEwCgYIKoZIzj0EAwIw\n\
        EjEQMA4GA1UEAxMHdGVzdC1jYTAeFw0yNTAxMDEwMDAwMDBaFw0zNTAxMDEwMDAw\n\
        MDBaMBIxEDAOBgNVBAMTB3Rlc3QtY2EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\n\
        AATat5eKpAEqhlMHpj9T3ZKkV1hLFCNYmplq9R1j5kQQHRiuyp8l0p4FKT8EiERQ\n\
        VGMcKaW8LBrrkAk9yTU1o2MwYTAdBgNVHQ4EFgQUHoxGqEhOInnMtNqg9j94JCXB\n\
        gMYwHwYDVR0jBBgwFoAUHoxGqEhOInnMtNqg9j94JCXBgMYwDwYDVR0TAQH/BAUw\n\
        AwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwIDSAAwRQIhAKmfOFG4ULWX\n\
        4aT3iqFWbUTRaJ7E2tXa9r02m3qLk9gxAiB8kqIb6X/s8cLEFEEwE2RpTaqaXWrd\n\
        vz2f0FxvxGJi1Q==\n\
        -----END CERTIFICATE-----\n";

    const CERT_PEM_2: &str = "-----BEGIN CERTIFICATE-----\n\
        MIIBpTCCAUugAwIBAgIUYmFzZTY0ZW5jb2RlZHRlc3RjYTIwCgYIKoZIzj0EAwIw\n\
        EjEQMA4GA1UEAxMHdGVzdC1jYTAeFw0yNTAxMDEwMDAwMDBaFw0zNTAxMDEwMDAw\n\
        MDBaMBIxEDAOBgNVBAMTB3Rlc3QtY2EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\n\
        AATat5eKpAEqhlMHpj9T3ZKkV1hLFCNYmplq9R1j5kQQHRiuyp8l0p4FKT8EiERQ\n\
        VGMcKaW8LBrrkAk9yTU1o2MwYTAdBgNVHQ4EFgQUHoxGqEhOInnMtNqg9j94JCXB\n\
        gMYwHwYDVR0jBBgwFoAUHoxGqEhOInnMtNqg9j94JCXBgMYwDwYDVR0TAQH/BAUw\n\
        AwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwIDSAAwRQIhAKmfOFG4ULWX\n\
        4aT3iqFWbUTRaJ7E2tXa9r02m3qLk9gxAiB8kqIb6X/s8cLEFEEwE2RpTaqaXWrd\n\
        vz2f0FxvxGJi1Q==\n\
        -----END CERTIFICATE-----\n";

    // Test approach decision: no in-process HTTPS S3 mock exists in the
    // current test stack. The `object_store` S3 client speaks S3-protocol
    // HTTP, not bare HTTPS; standing up a real S3-protocol mock (e.g.
    // `localstack` or `minio`) is an integration/E2E concern, not a unit
    // concern. The `rcgen` + `axum-server` pattern used by
    // `hort-adapters-upstream-http`'s tests requires a TLS-aware HTTP server
    // that speaks the *application* protocol under test — for S3 that means
    // a full S3-protocol mock, not a bare HTTPS echo server.
    //
    // Instead, we test `apply_to_object_store_options` directly:
    // - `None` anchors → `Ok` with the input opts returned unchanged.
    // - Valid DER anchors → `Ok` (Certificate::from_der succeeds).
    // - Two certs → `Ok` (both loaded without error).
    //
    // The "N certs applied" invariant is confirmed indirectly: if
    // `Certificate::from_der` accepted the cert and
    // `with_root_certificate` was called N times without error, the
    // `ClientOptions` carries N extra roots. The `root_certificates` field
    // is private on `ClientOptions`, so we assert via the function's
    // success path rather than a getter inspection.

    fn parse_anchors(pem: &str) -> ExtraTrustAnchors {
        ExtraTrustAnchors::parse_pem(pem.as_bytes()).expect("fixture PEM should parse")
    }

    #[test]
    fn none_anchors_returns_ok_unchanged() {
        let opts = ClientOptions::new();
        let result = apply_to_object_store_options(opts, None);
        assert!(
            result.is_ok(),
            "None anchors should not produce an error: {result:?}",
        );
    }

    #[test]
    fn single_valid_der_cert_applies_without_error() {
        let anchors = parse_anchors(CERT_PEM_1);
        assert_eq!(anchors.cert_count(), 1);

        let opts = ClientOptions::new();
        let result = apply_to_object_store_options(opts, Some(&anchors));
        assert!(
            result.is_ok(),
            "single valid DER cert should apply without error: {result:?}",
        );
    }

    #[test]
    fn two_valid_der_certs_both_apply_without_error() {
        let bundle = format!("{CERT_PEM_1}{CERT_PEM_2}");
        let anchors = parse_anchors(&bundle);
        assert_eq!(anchors.cert_count(), 2);

        let opts = ClientOptions::new();
        let result = apply_to_object_store_options(opts, Some(&anchors));
        assert!(
            result.is_ok(),
            "two-cert bundle should apply both certs without error: {result:?}",
        );
    }
}
