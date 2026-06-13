//! Dialect-specific extra-CA helper for `hort-notifier-webhook`.
//!
//! Applies a process-wide [`ExtraTrustAnchors`] bundle to a
//! `reqwest::ClientBuilder`. Failures fold into the existing
//! `tls_classified_error(UpstreamErrorKind::CaUnknown, …)` discipline —
//! no parallel error enum is introduced.
//!
//! This file is a verbatim copy of the pattern in
//! `hort-adapters-upstream-http/src/extra_ca.rs` and
//! `hort-adapters-advisory-osv/src/extra_ca.rs`. The function is per-
//! adapter (not a shared helper) on purpose: every adapter that opens TLS
//! must build via `reqwest::Client::builder()` (ADR 0010), and keeping
//! the helper local keeps the
//! dep graph local — `hort-notifier-webhook` does NOT depend on
//! `hort-adapters-upstream-http` (which would be an inbound-from-format
//! shape regression) and does NOT depend on `hort-adapters-advisory-osv`
//! either. If at 5+ copies the maintenance pain becomes real, a
//! unification initiative is the right place to address it — out of
//! scope here.

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
/// sentinel format. Same shape as the upstream-http / advisory-osv
/// helpers; duplicated here so this module stays self-contained.
fn tls_classified_error(kind: UpstreamErrorKind, detail: &str) -> DomainError {
    DomainError::Invariant(format!("upstream:{}:{}", kind.as_str(), detail))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a self-signed CA PEM using `rcgen` — the same generator
    /// used by `hort-adapters-upstream-http` / `hort-adapters-advisory-osv`.
    /// Using rcgen ensures the cert is a fully-valid X.509 CA that
    /// rustls / reqwest can load as a trust anchor.
    fn make_ca_pem() -> String {
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            "notifier-webhook extra-ca-test root CA".to_string(),
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

    /// Regression test for the format contract: `tls_classified_error` already
    /// prepends `upstream:<kind>:`, so the `detail` argument MUST NOT carry
    /// that prefix again. Mirrors the upstream-http / advisory-osv test of
    /// the same name.
    #[test]
    fn tls_classified_error_does_not_double_prefix_sentinel() {
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
