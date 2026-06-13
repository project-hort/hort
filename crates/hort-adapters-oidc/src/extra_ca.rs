//! Dialect-specific extra-CA helper for `hort-adapters-oidc`.
//!
//! Applies a process-wide [`ExtraTrustAnchors`] bundle to a
//! `reqwest::ClientBuilder`. The return type is a crate-local
//! `ExtraCaApplyError` — not `DomainResult` (that's the upstream-http
//! shape) and not `object_store::Error` (that's the storage shape). See
//! design §3 for the three-shape decision.

use reqwest::ClientBuilder;

use hort_config::ExtraTrustAnchors;

/// Error returned by [`apply_to_reqwest_builder`] and propagated from
/// [`OidcProvider::with_resilience`] / [`OidcProvider::new`].
///
/// Two variants cover the two fallible steps:
/// - `CertInvalid` — `reqwest::Certificate::from_der` rejected a DER blob
///   that parsed as valid PEM but is not an acceptable X.509 trust anchor.
/// - `BuildClient` — `reqwest::ClientBuilder::build()` failed (e.g. invalid
///   TLS configuration on the platform).
///
/// Both are boot-time failures; the process cannot start in a partially-
/// trusted state.
#[derive(Debug, thiserror::Error)]
pub enum ExtraCaApplyError {
    /// A DER-encoded certificate in the bundle was rejected by reqwest.
    #[error("extra CA cert rejected by reqwest: {0}")]
    CertInvalid(String),
    /// `reqwest::ClientBuilder::build()` failed after certificates were applied.
    #[error("failed to build reqwest client with extra CA bundle: {0}")]
    BuildClient(String),
}

impl From<reqwest::Error> for ExtraCaApplyError {
    fn from(e: reqwest::Error) -> Self {
        ExtraCaApplyError::BuildClient(e.to_string())
    }
}

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
/// surfaces as [`ExtraCaApplyError::CertInvalid`]. Unlike the upstream-http
/// helper (which folds into `DomainResult`), the OIDC helper has no equivalent
/// classification infrastructure — a crate-local error is the cleanest fit
/// per design §3.
pub(crate) fn apply_to_reqwest_builder(
    builder: ClientBuilder,
    anchors: Option<&ExtraTrustAnchors>,
) -> Result<ClientBuilder, ExtraCaApplyError> {
    let Some(anchors) = anchors else {
        return Ok(builder);
    };

    let mut b = builder;
    for der_bytes in anchors.certs_der() {
        let cert = reqwest::Certificate::from_der(der_bytes)
            .map_err(|e| ExtraCaApplyError::CertInvalid(e.to_string()))?;
        b = b.add_root_certificate(cert);
    }
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a self-signed CA PEM using `rcgen` — the same generator
    /// used by the upstream-http extra-CA tests. Using rcgen ensures the
    /// cert is a fully-valid X.509 CA that reqwest can load as a trust
    /// anchor (static PEM fixtures from `hort-config` use a minimal DER body
    /// that passes `CertificateDer::pem_slice_iter` but may fail reqwest's
    /// trust-anchor validation).
    fn make_ca_pem() -> String {
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            "oidc-extra-ca-test root CA".to_string(),
        );
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().expect("generate CA keypair");
        params.self_signed(&key).expect("self-sign CA").pem()
    }

    #[test]
    fn none_anchors_returns_builder_unchanged() {
        let builder = reqwest::Client::builder();
        let result = apply_to_reqwest_builder(builder, None);
        assert!(result.is_ok(), "None anchors must pass through: {result:?}");
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
}
