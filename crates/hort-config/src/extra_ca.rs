//! Process-wide extra CA trust bundle parsed from an env-var-pointed PEM
//! file. Zero-I/O: callers (`hort-server::composition`) read the file and
//! pass the bytes here.
//!
//! Dialect-specific binding lives with each adapter — this module deals
//! only in DER-encoded certificates. See:
//!  - `hort_adapters_upstream_http::extra_ca::apply_to_reqwest_builder`
//!  - `hort_adapters_storage::extra_ca::apply_to_object_store_options`
//!  - `hort_adapters_oidc::extra_ca::apply_to_reqwest_builder`
//!  - `hort_adapters_upstream_http::tls_config::extend_root_store_with_extras`

use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::CertificateDer;

/// Parsed process-wide extra CA trust bundle.
///
/// Holds the DER-encoded X.509 certificates from the PEM bundle
/// pointed to by `HORT_EXTRA_CA_BUNDLE`. Each adapter crate converts
/// these bytes into its own trust-anchor type via the
/// `apply_to_*` helpers shipped with that adapter.
///
/// The field is `pub(crate)` so no external crate can construct or
/// mutate it directly. The only public constructor is
/// [`ExtraTrustAnchors::parse_pem`].
///
/// `Debug` emits the certificate count only — never the raw DER bytes
/// (which are multi-kilobyte and unreadable in logs).
#[derive(Clone)]
pub struct ExtraTrustAnchors {
    /// DER-encoded X.509 certificates parsed from the PEM bundle.
    /// `Vec<u8>` (not `CertificateDer<'static>`) so the value object
    /// crosses crate boundaries without leaking the rustls type.
    pub(crate) certs_der: Vec<Vec<u8>>,
}

impl std::fmt::Debug for ExtraTrustAnchors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtraTrustAnchors")
            .field("cert_count", &self.certs_der.len())
            .finish()
    }
}

impl ExtraTrustAnchors {
    /// Parse a PEM bundle into one-or-more DER-encoded certificates.
    ///
    /// Uses `CertificateDer::pem_slice_iter` — the same entrypoint used
    /// by `hort-adapters-upstream-http`'s `parse_ca_pem` — so parsing
    /// semantics match across the codebase.
    ///
    /// Returns:
    /// - `Ok(_)` when one or more certificate blocks are found and all
    ///   parse successfully.
    /// - `Err(ExtraCaParseError::Pem(_))` when any PEM block is
    ///   malformed.
    /// - `Err(ExtraCaParseError::Empty)` when the input contains no
    ///   certificate blocks at all.
    pub fn parse_pem(pem_bytes: &[u8]) -> Result<Self, ExtraCaParseError> {
        let mut certs_der: Vec<Vec<u8>> = Vec::new();

        for entry in CertificateDer::pem_slice_iter(pem_bytes) {
            let der = entry.map_err(|e| ExtraCaParseError::Pem(e.to_string()))?;
            certs_der.push(der.as_ref().to_vec());
        }

        if certs_der.is_empty() {
            return Err(ExtraCaParseError::Empty);
        }

        Ok(Self { certs_der })
    }

    /// Returns `true` if the bundle contains no certificates.
    ///
    /// In practice this should never be true for a value produced by
    /// [`parse_pem`] (which rejects empty bundles), but the method is
    /// provided for completeness and future-proofing.
    pub fn is_empty(&self) -> bool {
        self.certs_der.is_empty()
    }

    /// Returns the number of DER-encoded certificates in the bundle.
    pub fn cert_count(&self) -> usize {
        self.certs_der.len()
    }

    /// Returns a slice of the DER-encoded certificates.
    ///
    /// Each element is the raw DER bytes of one X.509 certificate.
    /// Adapter crates iterate this slice and convert each element
    /// into the appropriate trust-anchor type for their TLS library.
    pub fn certs_der(&self) -> &[Vec<u8>] {
        &self.certs_der
    }
}

/// Error returned by [`ExtraTrustAnchors::parse_pem`].
#[derive(Debug, thiserror::Error)]
pub enum ExtraCaParseError {
    /// One or more PEM blocks in the bundle failed to parse.
    #[error("CA bundle PEM parse failed: {0}")]
    Pem(String),
    /// The PEM input contained no certificate blocks at all.
    #[error("CA bundle resolved to zero certificates")]
    Empty,
}

#[cfg(test)]
mod tests {
    use super::*;

    // A minimal self-signed CA certificate in PEM format, generated with:
    //   openssl req -x509 -newkey rsa:2048 -days 3650 -nodes \
    //     -subj "/CN=test-ca" -keyout /dev/null -out ca.pem
    // (truncated to a real but compact DER payload for test purposes)
    //
    // We use a real PEM block so `CertificateDer::pem_slice_iter` has
    // something to parse. The certificate content is irrelevant for
    // these unit tests; only the count and error paths matter.
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

    #[test]
    fn empty_input_returns_empty_error() {
        let result = ExtraTrustAnchors::parse_pem(b"");
        assert!(
            matches!(result, Err(ExtraCaParseError::Empty)),
            "expected Empty, got {result:?}",
        );
    }

    #[test]
    fn whitespace_only_input_returns_empty_error() {
        let result = ExtraTrustAnchors::parse_pem(b"   \n\n   ");
        assert!(
            matches!(result, Err(ExtraCaParseError::Empty)),
            "expected Empty on whitespace-only input, got {result:?}",
        );
    }

    #[test]
    fn single_cert_pem_returns_one_cert() {
        let result = ExtraTrustAnchors::parse_pem(CERT_PEM_1.as_bytes());
        let anchors = result.expect("single cert PEM should parse ok");
        assert_eq!(anchors.cert_count(), 1, "expected exactly one certificate");
        assert!(!anchors.is_empty());
        assert_eq!(anchors.certs_der().len(), 1);
    }

    #[test]
    fn multi_cert_bundle_returns_correct_count() {
        // Concatenate two PEM certificates — a standard bundle format.
        let bundle = format!("{CERT_PEM_1}{CERT_PEM_2}");
        let result = ExtraTrustAnchors::parse_pem(bundle.as_bytes());
        let anchors = result.expect("two-cert bundle should parse ok");
        assert_eq!(
            anchors.cert_count(),
            2,
            "expected exactly two certificates in the bundle",
        );
    }

    #[test]
    fn mid_bundle_malformed_cert_returns_pem_error() {
        // A valid cert followed by garbage that looks like a PEM header
        // but has corrupted base64.
        let bad_bundle = format!(
            "{}{}",
            CERT_PEM_1,
            "-----BEGIN CERTIFICATE-----\n\
             not_valid_base64!!!\n\
             -----END CERTIFICATE-----\n",
        );
        let result = ExtraTrustAnchors::parse_pem(bad_bundle.as_bytes());
        assert!(
            matches!(result, Err(ExtraCaParseError::Pem(_))),
            "expected Pem error on malformed mid-bundle cert, got {result:?}",
        );
    }

    #[test]
    fn non_cert_pem_type_returns_empty_error() {
        // A PEM block with a type other than CERTIFICATE — the iter
        // yields nothing (wrong PEM tag is filtered, not an error).
        let private_key_pem = "-----BEGIN PRIVATE KEY-----\n\
            MC4CAQAwBQYDK2VwBCIEIHcHbQpzGKFAkuoLF2cWmvbD+NLvTxlpFWFCqRXDYNcI\n\
            -----END PRIVATE KEY-----\n";
        let result = ExtraTrustAnchors::parse_pem(private_key_pem.as_bytes());
        assert!(
            matches!(result, Err(ExtraCaParseError::Empty)),
            "expected Empty for non-CERTIFICATE PEM type, got {result:?}",
        );
    }

    #[test]
    fn certs_der_returns_non_empty_bytes() {
        let anchors =
            ExtraTrustAnchors::parse_pem(CERT_PEM_1.as_bytes()).expect("single cert should parse");
        let ders = anchors.certs_der();
        assert_eq!(ders.len(), 1);
        // DER starts with 0x30 (SEQUENCE tag for X.509).
        assert_eq!(ders[0][0], 0x30, "DER bytes should start with SEQUENCE tag");
    }
}
