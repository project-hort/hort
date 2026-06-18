//! Dialect-specific extra-CA helper for `hort-adapters-upstream-http`.
//!
//! Applies a process-wide [`ExtraTrustAnchors`] bundle to a
//! `reqwest::ClientBuilder`. Failures fold into the existing
//! `tls_classified_error(UpstreamErrorKind::CaUnknown, …)` discipline —
//! no parallel error enum is introduced.

use reqwest::ClientBuilder;

use hort_app::metrics::UpstreamErrorKind;
use hort_config::ExtraTrustAnchors;
use hort_domain::error::{DomainError, DomainResult};

/// Apply a process-wide extra CA bundle to a `reqwest::ClientBuilder`.
///
/// Iterates `anchors.certs_der()` and calls
/// `reqwest::Certificate::from_der` + `ClientBuilder::add_root_certificate`
/// for each DER-encoded certificate. Returns the updated builder on success.
///
/// When `anchors` is `None` the builder is returned unchanged — callers
/// may unconditionally pipe through this helper without an `if let` guard.
///
/// # Errors
///
/// `reqwest::Certificate::from_der` can reject a cert that is syntactically
/// parseable as PEM / DER but is not a valid X.509 trust anchor. The failure
/// maps to `DomainError::Invariant("upstream:ca_unknown:…")` via the same
/// sentinel pattern `tls_classified_error` uses, so metric/tracing
/// classification stays uniform with the per-mapping rustls path.
pub(crate) fn apply_to_reqwest_builder(
    builder: ClientBuilder,
    anchors: Option<&ExtraTrustAnchors>,
) -> DomainResult<ClientBuilder> {
    let Some(anchors) = anchors else {
        return Ok(builder);
    };

    let mut b = builder;
    for der_bytes in anchors.certs_der() {
        let cert = reqwest::Certificate::from_der(der_bytes).map_err(|e| {
            tls_classified_error(UpstreamErrorKind::CaUnknown, &format!("reqwest_apply:{e}"))
        })?;
        b = b.add_root_certificate(cert);
    }
    Ok(b)
}

/// Build a [`DomainError::Invariant`] with the `upstream:<kind>:<detail>`
/// sentinel format. Mirrors the helper in `tls_config.rs`; duplicated here
/// so this module stays self-contained.
fn tls_classified_error(kind: UpstreamErrorKind, detail: &str) -> DomainError {
    DomainError::Invariant(format!("upstream:{}:{}", kind.as_str(), detail))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a self-signed CA PEM using `rcgen` — the same generator
    /// used by the integration-test TLS fixtures in `lib.rs`. Using rcgen
    /// ensures the cert is a fully-valid X.509 CA that rustls / reqwest can
    /// load as a trust anchor (static PEM fixtures from `hort-config` use a
    /// minimal DER body that passes `CertificateDer::pem_slice_iter` but may
    /// fail reqwest's trust-anchor validation).
    fn make_ca_pem() -> String {
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            "extra-ca-test root CA".to_string(),
        );
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().expect("generate CA keypair");
        params.self_signed(&key).expect("self-sign CA").pem()
    }

    #[test]
    fn none_anchors_returns_builder_unchanged() {
        // Building a reqwest::ClientBuilder and passing None through the helper
        // must succeed and not alter the builder in any observable way.
        let builder = reqwest::Client::builder();
        let result = apply_to_reqwest_builder(builder, None);
        assert!(result.is_ok(), "None anchors must pass through: {result:?}");
        // Verify the resulting builder builds successfully.
        result
            .unwrap()
            .build()
            .expect("builder from None anchors must build a valid Client");
    }

    #[test]
    fn single_cert_anchors_applies_successfully() {
        let ca_pem = make_ca_pem();
        let anchors = ExtraTrustAnchors::parse_pem(ca_pem.as_bytes()).expect("parse rcgen CA PEM");
        let builder = reqwest::Client::builder();
        let result = apply_to_reqwest_builder(builder, Some(&anchors));
        assert!(
            result.is_ok(),
            "single valid cert must apply without error: {result:?}"
        );
        result
            .unwrap()
            .build()
            .expect("builder with one extra CA must build a valid Client");
    }

    /// Regression test for the format contract: `tls_classified_error` already
    /// prepends `upstream:<kind>:`, so the `detail` argument MUST NOT carry
    /// that prefix again. A prior version of `apply_to_reqwest_builder`
    /// passed `"upstream:ca_unknown:reqwest_apply:{e}"` as `detail`, which
    /// produced `upstream:ca_unknown:upstream:ca_unknown:reqwest_apply:…` —
    /// breaking any downstream regex on `^upstream:[a-z_]+:[^:]+$`.
    ///
    /// We can't drive the actual `from_der` error path here because reqwest's
    /// rustls backend implements `Certificate::from_der` as a non-fallible
    /// byte-wrap (validation happens at handshake time). This test instead
    /// pins the format-contract directly: the detail string passed to
    /// `tls_classified_error` from `apply_to_reqwest_builder` must NOT begin
    /// with `upstream:`.
    #[test]
    fn tls_classified_error_does_not_double_prefix_sentinel() {
        // The exact `detail` shape `apply_to_reqwest_builder` uses today.
        let err = tls_classified_error(UpstreamErrorKind::CaUnknown, "reqwest_apply:boom");
        let DomainError::Invariant(msg) = err else {
            panic!("expected DomainError::Invariant, got {err:?}");
        };
        assert_eq!(msg, "upstream:ca_unknown:reqwest_apply:boom");
        let rest = msg
            .strip_prefix("upstream:ca_unknown:")
            .expect("prefix present");
        assert!(
            !rest.starts_with("upstream:"),
            "sentinel prefix duplicated: {msg}"
        );
    }
}
