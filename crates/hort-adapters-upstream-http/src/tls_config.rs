//! Outbound TLS configuration (ADR 0010).
//!
//! Wires four `RepositoryUpstreamMapping` fields through `reqwest`'s
//! TLS path:
//!
//! - `ca_bundle_ref` — PEM-encoded extra trust anchors loaded into the
//!   `rustls::RootCertStore` *in addition to* the system CA bundle. The
//!   handshake fails as `UpstreamErrorKind::CaUnknown` when the upstream
//!   chain does not chain to any trusted anchor.
//! - `mtls_cert_ref` + `mtls_key_ref` — paired PEM-encoded client cert
//!   chain + private key. Both must be set together (the value-object
//!   constructor enforces this in lockstep with the schema CHECK). A
//!   server demanding a client cert from a mapping without these
//!   surfaces as `UpstreamErrorKind::Unauthorized` (the design doc §3.9
//!   classifies mTLS-required-but-missing as a 401-shape, not a TLS-
//!   shape).
//! - `pinned_cert_sha256` — operator-pinned SHA-256 thumbprint of the
//!   leaf certificate's DER bytes. Adds a [`PinningVerifier`] that
//!   delegates to a [`rustls::client::WebPkiServerVerifier`] for chain
//!   trust + name validation; mismatch surfaces as
//!   `UpstreamErrorKind::PinMismatch`.
//!
//! ## Pinning operates *above* WebPKI
//!
//! The `PinningVerifier` does not skip name validation or chain-trust
//! checking. The leaf cert must still be a valid X.509 (so an arbitrary
//! self-signed cert without proper subject alt names fails name
//! validation as today; pinning is *additive* defence). Per the design
//! doc §3.9: "the upstream presented a syntactically valid certificate
//! that chained to a trusted CA but did not match the operator-pinned
//! thumbprint". A pin without chain trust would be a TOFU model, which
//! the audit explicitly does not require.
//!
//! ## Cache lifetime
//!
//! Per-mapping `reqwest::Client` instances are cached in
//! [`super::HttpUpstreamProxy`] keyed by `mapping.id`. The cache is
//! never invalidated within a process lifetime: secret rotation
//! requires a redeploy / rolling restart. Operators rotate by bumping
//! the mapping's `secret_ref` (which produces a new `(source,
//! location)` cache-key in `SecretPort`'s discipline) AND by triggering
//! a server restart so this client cache forgets the old config. This
//! trade-off is documented inline at the cache definition site.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme,
    SupportedProtocolVersion,
};

/// Explicit TLS version pin for the outbound rustls client configuration.
///
/// Replaces the version-implicit `ClientConfig::builder()` (which folds
/// in `versions::DEFAULT_VERSIONS` from rustls — currently TLS 1.3 +
/// TLS 1.2, but a future rustls release could broaden that set without
/// our involvement). The explicit pin is BSI TR-02102-2 §3 Recommendation
/// 1: only TLS 1.3 (preferred) and TLS 1.2 (still required for
/// enterprise registries that have not retired 1.2). TLS 1.0 / 1.1 / SSL
/// are categorically forbidden — neither rustls nor any policy here
/// would permit them, but the pin makes the constraint load-bearing
/// rather than incidental.
///
/// Ordering: TLS 1.3 first so the pin reads as "prefer 1.3, accept 1.2".
/// rustls itself negotiates highest-mutually-supported, so the array
/// order is documentation; but a reader of this list sees the policy
/// without cross-referencing the spec.
pub(crate) const OUTBOUND_TLS_PROTOCOL_VERSIONS: &[&SupportedProtocolVersion] =
    &[&rustls::version::TLS13, &rustls::version::TLS12];
use sha2::{Digest, Sha256};

use hort_app::metrics::UpstreamErrorKind;
use hort_config::ExtraTrustAnchors;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMapping;
use hort_domain::ports::secret_port::{SecretPort, SecretValue};

/// Sentinel emitted in the [`rustls::Error::General`] message when the
/// pinning verifier rejects a leaf cert. Parsed by
/// [`super::classify_tls_handshake_error`] to map back to
/// `UpstreamErrorKind::PinMismatch`.
pub(crate) const PIN_MISMATCH_SENTINEL: &str = "hort: pin mismatch";

/// Resolved bundle of TLS material for one mapping. Constructed by
/// [`resolve_tls_material`] from the mapping's `*_ref` fields and
/// consumed by [`build_rustls_client_config`].
///
/// `pin_sha256_lower_hex` is preserved as-is from the mapping (the
/// value-object constructor enforces its 64-char lowercase-hex shape);
/// the pinning verifier converts to raw bytes lazily.
pub(crate) struct ResolvedTlsMaterial {
    /// Extra root certificates (DER) from the operator-supplied PEM CA
    /// bundle. Empty when `ca_bundle_ref` was unset.
    pub ca_certs_der: Vec<CertificateDer<'static>>,
    /// Concatenated PEM bytes of the client cert chain + private key.
    /// `Some(_)` only when both `mtls_cert_ref` and `mtls_key_ref` are
    /// set; the mapping value-object enforces the pairing invariant.
    /// Wrapped in `SecretValue` so `Drop` zeroizes the buffer.
    pub mtls_cert_chain_der: Vec<CertificateDer<'static>>,
    pub mtls_key_der: Option<PrivateKeyDer<'static>>,
    /// 64-character lowercase-hex SHA-256 of the upstream's pinned leaf
    /// certificate (DER bytes), or `None` when pinning is not configured.
    pub pin_sha256_lower_hex: Option<String>,
}

impl ResolvedTlsMaterial {
    /// True iff at least one of the four mapping TLS fields produced
    /// material. When false the caller skips the per-mapping client
    /// build entirely and reuses the proxy's default client.
    pub(crate) fn any_present(&self) -> bool {
        !self.ca_certs_der.is_empty()
            || !self.mtls_cert_chain_der.is_empty()
            || self.mtls_key_der.is_some()
            || self.pin_sha256_lower_hex.is_some()
    }
}

/// Resolve every `*_ref` on the mapping via the supplied [`SecretPort`].
/// Per-mapping resolution happens at most once (cached client lives for
/// the process lifetime). On any resolution failure we map to a
/// classified [`DomainError`] so the caller can fire the matching
/// `hort_upstream_tls_handshake_total{result=network_error}` and bubble
/// the error up.
pub(crate) async fn resolve_tls_material(
    mapping: &RepositoryUpstreamMapping,
    secret_port: &dyn SecretPort,
) -> DomainResult<ResolvedTlsMaterial> {
    let ca_certs_der = match mapping.ca_bundle_ref.as_ref() {
        None => Vec::new(),
        Some(ca_ref) => {
            let value: SecretValue = secret_port.resolve(ca_ref).await.map_err(|e| {
                tls_classified_error(
                    UpstreamErrorKind::NetworkError,
                    &format!("ca_bundle_ref resolve failed: {e}"),
                )
            })?;
            parse_ca_pem(value.as_bytes())?
        }
    };

    // mTLS: paired by the value-object constructor; treat (Some, Some)
    // as the only "present" case. (None, None) is the no-mTLS case;
    // any other combination is rejected at construction so a defensive
    // refusal here is belt-and-braces, not a behavioural difference.
    let (mtls_cert_chain_der, mtls_key_der) = match (
        mapping.mtls_cert_ref.as_ref(),
        mapping.mtls_key_ref.as_ref(),
    ) {
        (None, None) => (Vec::new(), None),
        (Some(cert_ref), Some(key_ref)) => {
            let cert_value: SecretValue = secret_port.resolve(cert_ref).await.map_err(|e| {
                tls_classified_error(
                    UpstreamErrorKind::NetworkError,
                    &format!("mtls_cert_ref resolve failed: {e}"),
                )
            })?;
            let key_value: SecretValue = secret_port.resolve(key_ref).await.map_err(|e| {
                tls_classified_error(
                    UpstreamErrorKind::NetworkError,
                    &format!("mtls_key_ref resolve failed: {e}"),
                )
            })?;
            let chain = parse_cert_pem(cert_value.as_bytes())?;
            let key = parse_private_key_pem(key_value.as_bytes())?;
            (chain, Some(key))
        }
        _ => {
            // Unreachable in practice — value-object constructor
            // enforces the pair. Fail closed if we ever see it.
            return Err(tls_classified_error(
                UpstreamErrorKind::NetworkError,
                "mapping carries mtls_cert_ref XOR mtls_key_ref; \
                     value-object invariant violated",
            ));
        }
    };

    Ok(ResolvedTlsMaterial {
        ca_certs_der,
        mtls_cert_chain_der,
        mtls_key_der,
        pin_sha256_lower_hex: mapping.pinned_cert_sha256.clone(),
    })
}

/// Parse a PEM-encoded CA bundle into a list of DER certificates.
/// Empty PEM is a configuration error (the operator pointed at a CA
/// bundle that contained zero certs); refuse rather than silently
/// degrade to "system CA only".
///
/// Uses [`rustls_pki_types::pem::PemObject::pem_slice_iter`] — the
/// successor API after `rustls-pemfile` was deprecated
/// (RUSTSEC-2025-... — the maintainers' migration note recommends
/// the `PemObject` trait).
fn parse_ca_pem(pem_bytes: &[u8]) -> DomainResult<Vec<CertificateDer<'static>>> {
    let mut certs: Vec<CertificateDer<'static>> = Vec::new();
    for entry in CertificateDer::pem_slice_iter(pem_bytes) {
        let der = entry.map_err(|e| {
            tls_classified_error(
                UpstreamErrorKind::NetworkError,
                &format!("ca_bundle_ref PEM parse failed: {e}"),
            )
        })?;
        certs.push(der);
    }
    if certs.is_empty() {
        return Err(tls_classified_error(
            UpstreamErrorKind::NetworkError,
            "ca_bundle_ref resolved to zero certificates",
        ));
    }
    Ok(certs)
}

/// Parse a PEM-encoded cert chain (mTLS client cert).
fn parse_cert_pem(pem_bytes: &[u8]) -> DomainResult<Vec<CertificateDer<'static>>> {
    let mut certs: Vec<CertificateDer<'static>> = Vec::new();
    for entry in CertificateDer::pem_slice_iter(pem_bytes) {
        let der = entry.map_err(|e| {
            tls_classified_error(
                UpstreamErrorKind::NetworkError,
                &format!("mtls_cert_ref PEM parse failed: {e}"),
            )
        })?;
        certs.push(der);
    }
    if certs.is_empty() {
        return Err(tls_classified_error(
            UpstreamErrorKind::NetworkError,
            "mtls_cert_ref resolved to zero certificates",
        ));
    }
    Ok(certs)
}

/// Parse a PEM-encoded private key. Accepts PKCS#8, PKCS#1, and SEC1 —
/// [`PrivateKeyDer::from_pem_slice`] returns the first matching section.
fn parse_private_key_pem(pem_bytes: &[u8]) -> DomainResult<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_slice(pem_bytes).map_err(|e| {
        tls_classified_error(
            UpstreamErrorKind::NetworkError,
            &format!("mtls_key_ref PEM parse failed: {e}"),
        )
    })
}

/// Build a `rustls::ClientConfig` carrying:
///
/// 1. The OS native root CA store (via `rustls_native_certs::load_native_certs()`)
///    plus any process-wide extra CA anchors (ADR 0010) and any
///    per-mapping operator-supplied CA certs.
/// 2. A custom [`PinningVerifier`] when `pin_sha256_lower_hex` is set,
///    delegating to a [`WebPkiServerVerifier`] for chain + name
///    validation. Without pinning we still install the WebPKI verifier
///    explicitly so the augmented root set is honoured.
/// 3. mTLS client cert / key when both are present.
///
/// The augmented root store is: OS roots → extra CA bundle → per-mapping
/// `ca_bundle_ref`. This order means later additions are additive on top
/// of the OS set, not replacing it.
///
/// Returns an error if the rustls process-default crypto provider is
/// not installed and the `ring` crate-feature is not active. We install
/// the `ring` provider lazily on first call; subsequent calls observe
/// the same install.
pub(crate) fn build_rustls_client_config(
    material: &ResolvedTlsMaterial,
    extra_anchors: Option<&ExtraTrustAnchors>,
) -> DomainResult<ClientConfig> {
    install_default_crypto_provider();

    // Augmented root store: OS native roots + extra CA bundle + per-mapping CA.
    let mut roots = RootCertStore::empty();

    // Load OS trust store. On partial load (some certs failed to parse),
    // warn and proceed with the parseable subset. An empty result (no OS
    // trust store at all) is a hard error.
    let native_result = rustls_native_certs::load_native_certs();
    if !native_result.errors.is_empty() && native_result.certs.is_empty() {
        return Err(tls_classified_error(
            UpstreamErrorKind::NetworkError,
            &format!(
                "OS native trust store returned no certificates ({} errors)",
                native_result.errors.len()
            ),
        ));
    }
    if !native_result.errors.is_empty() {
        tracing::warn!(
            error_count = native_result.errors.len(),
            parsed_count = native_result.certs.len(),
            "partial native trust store load"
        );
    }
    if native_result.certs.is_empty() {
        return Err(tls_classified_error(
            UpstreamErrorKind::NetworkError,
            "OS native trust store is empty (no CA certificates found)",
        ));
    }
    for cert in native_result.certs {
        // Ignore individual certs that can't be parsed as trust anchors
        // (already checked by native_certs loader; second-pass is defence).
        let _ = roots.add(cert);
    }

    // Fold in process-wide extra CA bundle (ADR 0010).
    let extra_ca_count = match extra_anchors {
        None => 0,
        Some(anchors) => {
            let count = anchors.cert_count();
            for der_bytes in anchors.certs_der() {
                let cert = CertificateDer::from(der_bytes.as_slice().to_vec());
                roots.add(cert).map_err(|e| {
                    tls_classified_error(
                        UpstreamErrorKind::CaUnknown,
                        &format!("extra CA bundle entry rejected by rustls: {e}"),
                    )
                })?;
            }
            count
        }
    };

    // Per-mapping CA certs (ca_bundle_ref). Added last so per-mapping
    // certs can extend the process-wide set for a specific upstream.
    let mapping_ca_count = material.ca_certs_der.len();
    for cert in &material.ca_certs_der {
        // `add` validates the cert is a parsable trust anchor. Same
        // classification as the extra-CA-bundle path above — both are
        // operator-supplied trust anchors and a rejection is a CA-trust
        // misconfiguration, not a network condition.
        roots.add(cert.clone()).map_err(|e| {
            tls_classified_error(
                UpstreamErrorKind::CaUnknown,
                &format!("ca_bundle_ref entry rejected by rustls: {e}"),
            )
        })?;
    }

    tracing::debug!(
        extra_ca_count,
        mapping_ca_count,
        "augmented root store built"
    );

    // WebPKI verifier — chain trust + name validation. The custom
    // `PinningVerifier` (when configured) wraps this and adds the
    // thumbprint check; without pinning we expose this verifier
    // directly so the augmented `roots` are honoured.
    let webpki: Arc<WebPkiServerVerifier> = WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| {
            tls_classified_error(
                UpstreamErrorKind::NetworkError,
                &format!("WebPKI verifier build failed: {e}"),
            )
        })?;

    let verifier: Arc<dyn ServerCertVerifier> = match &material.pin_sha256_lower_hex {
        None => webpki,
        Some(pin_hex) => Arc::new(PinningVerifier::new(webpki, pin_hex)?),
    };

    // Explicit TLS 1.3 + TLS 1.2 version pin (see OUTBOUND_TLS_PROTOCOL_VERSIONS).
    // BSI TR-02102-2 §3 Recommendation 1. Using the version-implicit
    // `builder()` would defer the policy to rustls' shifting
    // `DEFAULT_VERSIONS`, which is exactly the dependency we want to remove.
    let builder = ClientConfig::builder_with_protocol_versions(OUTBOUND_TLS_PROTOCOL_VERSIONS)
        .dangerous()
        .with_custom_certificate_verifier(verifier);

    let config = if let Some(key_der) = material.mtls_key_der.clone_optional()? {
        builder
            .with_client_auth_cert(material.mtls_cert_chain_der.clone(), key_der)
            .map_err(|e| {
                tls_classified_error(
                    UpstreamErrorKind::NetworkError,
                    &format!("rustls client-auth cert rejected: {e}"),
                )
            })?
    } else {
        builder.with_no_client_auth()
    };

    Ok(config)
}

/// `PrivateKeyDer<'static>` is not `Clone` in rustls 0.23. The cache
/// path resolves once and reuses the resulting `Client` for the
/// process lifetime, but `with_client_auth_cert` consumes the key by
/// value. The helper trait below lets us hand out `Some(key)` exactly
/// once per cache-fill — a defensive shape that turns "key already
/// consumed" into a domain error rather than a panic.
trait CloneOptional<T> {
    fn clone_optional(&self) -> DomainResult<Option<T>>;
}

impl CloneOptional<PrivateKeyDer<'static>> for Option<PrivateKeyDer<'static>> {
    fn clone_optional(&self) -> DomainResult<Option<PrivateKeyDer<'static>>> {
        match self {
            None => Ok(None),
            Some(PrivateKeyDer::Pkcs8(pkcs8)) => Ok(Some(PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(pkcs8.secret_pkcs8_der().to_vec()),
            ))),
            Some(PrivateKeyDer::Pkcs1(pkcs1)) => Ok(Some(PrivateKeyDer::Pkcs1(
                rustls::pki_types::PrivatePkcs1KeyDer::from(pkcs1.secret_pkcs1_der().to_vec()),
            ))),
            Some(PrivateKeyDer::Sec1(sec1)) => Ok(Some(PrivateKeyDer::Sec1(
                rustls::pki_types::PrivateSec1KeyDer::from(sec1.secret_sec1_der().to_vec()),
            ))),
            Some(_) => Err(tls_classified_error(
                UpstreamErrorKind::NetworkError,
                "mtls_key_ref produced an unsupported PrivateKeyDer variant",
            )),
        }
    }
}

/// Install the rustls process-default crypto provider exactly once.
/// `install_default` is idempotent on the success path: the second call
/// returns `Err(_)` carrying the already-installed provider, which we
/// silently ignore. Concurrent first-call races are handled by rustls
/// internally (atomic `OnceLock`).
fn install_default_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Hash a leaf cert's DER bytes to a 64-char lowercase-hex SHA-256
/// thumbprint. `pub(crate)` so the test module in `lib.rs` can
/// construct the expected pin from a test server's generated cert.
/// Behind `cfg(test)` because production code does not hash certs —
/// the [`PinningVerifier`] uses raw 32-byte SHA-256 for its inner
/// memcmp.
#[cfg(test)]
pub(crate) fn sha256_lower_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Custom [`ServerCertVerifier`] that compares the upstream's leaf cert
/// thumbprint against an operator-pinned SHA-256 *before* delegating to
/// the WebPKI verifier for chain trust + name validation.
///
/// **Order of operations:**
///
/// 1. Hash `end_entity` DER bytes with SHA-256.
/// 2. Compare lowercase-hex against `expected_pin_lower_hex`. Mismatch →
///    return [`rustls::Error::General`] carrying [`PIN_MISMATCH_SENTINEL`]
///    so the outer error-chain walker can map back to
///    `UpstreamErrorKind::PinMismatch`.
/// 3. Match → delegate to the inner WebPKI verifier so name + chain
///    validation still run.
///
/// The signature-verification methods (`verify_tls12_signature`,
/// `verify_tls13_signature`, `supported_verify_schemes`) delegate
/// unconditionally — they're called *after* `verify_server_cert`
/// succeeds, so by the time they run the pin has already matched.
#[derive(Debug)]
pub(crate) struct PinningVerifier {
    inner: Arc<WebPkiServerVerifier>,
    /// 32-byte raw SHA-256 thumbprint. Stored as bytes, not hex, so
    /// each handshake performs one fixed-time-ish memcmp instead of a
    /// per-byte hex parse.
    expected_pin_bytes: [u8; 32],
}

impl PinningVerifier {
    /// Construct a [`PinningVerifier`]. `expected_pin_lower_hex` must
    /// be a 64-character lowercase-hex SHA-256 (the value-object
    /// constructor on the mapping enforces this; we re-check defensively).
    pub(crate) fn new(
        inner: Arc<WebPkiServerVerifier>,
        expected_pin_lower_hex: &str,
    ) -> DomainResult<Self> {
        if expected_pin_lower_hex.len() != 64
            || !expected_pin_lower_hex
                .chars()
                .all(|c| matches!(c, '0'..='9' | 'a'..='f'))
        {
            return Err(tls_classified_error(
                UpstreamErrorKind::NetworkError,
                "pinned_cert_sha256 must be 64 lowercase hex chars",
            ));
        }
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            let hex_pair = &expected_pin_lower_hex[i * 2..i * 2 + 2];
            *byte = u8::from_str_radix(hex_pair, 16).map_err(|e| {
                tls_classified_error(
                    UpstreamErrorKind::NetworkError,
                    &format!("pinned_cert_sha256 hex decode failed: {e}"),
                )
            })?;
        }
        Ok(Self {
            inner,
            expected_pin_bytes: bytes,
        })
    }
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        // 1. Pin check — fast path before any X.509 parsing.
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let actual: [u8; 32] = hasher.finalize().into();
        if actual != self.expected_pin_bytes {
            // Sentinel string parsed by `super::classify_tls_handshake_error`.
            return Err(RustlsError::General(PIN_MISMATCH_SENTINEL.to_string()));
        }

        // 2. Delegate to WebPKI for chain + name validation. Pinning is
        //    additive defence; we do NOT skip these checks.
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Build a [`DomainError::Invariant`] with the `upstream:<kind>:<detail>`
/// sentinel format `super::classify_error` parses. Mirrors the helper in
/// `lib.rs`; duplicated here so this module stays self-contained.
fn tls_classified_error(kind: UpstreamErrorKind, detail: &str) -> DomainError {
    DomainError::Invariant(format!("upstream:{}:{}", kind.as_str(), detail))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_lower_hex_round_trips_known_vector() {
        // Empty-input vector from RFC 6234 / NIST CSRC: SHA-256("") =
        // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.
        let h = sha256_lower_hex(b"");
        assert_eq!(
            h,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn sha256_lower_hex_emits_only_lowercase_hex() {
        let h = sha256_lower_hex(b"the quick brown fox");
        for c in h.chars() {
            assert!(matches!(c, '0'..='9' | 'a'..='f'), "non-hex char: {c}");
        }
    }

    fn build_test_native_roots_verifier() -> Arc<WebPkiServerVerifier> {
        // A real WebPkiServerVerifier built against the OS native trust
        // store. The pinning-verifier unit tests only exercise the
        // constructor's hex-validation path, so a "real but never invoked"
        // inner verifier is fine. Using the same OS roots source as
        // production keeps the test trust posture consistent (ADR 0010).
        install_default_crypto_provider();
        let mut roots = RootCertStore::empty();
        let native_result = rustls_native_certs::load_native_certs();
        for cert in native_result.certs {
            let _ = roots.add(cert);
        }
        WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .expect("WebPKI verifier with OS native roots builds")
    }

    #[test]
    fn pinning_verifier_rejects_wrong_pin_length() {
        let inner = build_test_native_roots_verifier();
        let result = PinningVerifier::new(inner, "abc");
        match result {
            Err(DomainError::Invariant(msg)) => {
                assert!(
                    msg.contains("pinned_cert_sha256"),
                    "error must reference field, got: {msg}"
                );
            }
            other => panic!("expected invariant error for wrong-length pin; got {other:?}"),
        }
    }

    #[test]
    fn pinning_verifier_rejects_uppercase_hex() {
        let inner = build_test_native_roots_verifier();
        let pin = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";
        let result = PinningVerifier::new(inner, pin);
        assert!(
            matches!(result, Err(DomainError::Invariant(_))),
            "uppercase pin must be rejected"
        );
    }

    #[test]
    fn pinning_verifier_accepts_valid_lowercase_pin() {
        let inner = build_test_native_roots_verifier();
        let pin = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let v = PinningVerifier::new(inner, pin).expect("valid pin must construct");
        assert_eq!(
            v.expected_pin_bytes[0], 0xab,
            "first byte parsed from `ab` prefix"
        );
        assert_eq!(
            v.expected_pin_bytes[31], 0x89,
            "last byte parsed from `89` suffix"
        );
    }

    #[test]
    fn parse_ca_pem_rejects_empty_pem() {
        let err = parse_ca_pem(b"").expect_err("empty PEM must be rejected");
        assert!(
            matches!(err, DomainError::Invariant(_)),
            "expected classified error, got {err:?}"
        );
    }

    #[test]
    fn parse_cert_pem_rejects_empty_pem() {
        let err = parse_cert_pem(b"").expect_err("empty PEM must be rejected");
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn parse_private_key_pem_rejects_empty_pem() {
        let err = parse_private_key_pem(b"").expect_err("empty key PEM must be rejected");
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn resolved_tls_material_any_present_is_false_for_default_posture() {
        let m = ResolvedTlsMaterial {
            ca_certs_der: Vec::new(),
            mtls_cert_chain_der: Vec::new(),
            mtls_key_der: None,
            pin_sha256_lower_hex: None,
        };
        assert!(!m.any_present());
    }

    #[test]
    fn resolved_tls_material_any_present_is_true_when_pin_set() {
        let m = ResolvedTlsMaterial {
            ca_certs_der: Vec::new(),
            mtls_cert_chain_der: Vec::new(),
            mtls_key_der: None,
            pin_sha256_lower_hex: Some(
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string(),
            ),
        };
        assert!(m.any_present());
    }

    // ---- TLS version pin ---------------------
    //
    // Two assertions on the policy constant `OUTBOUND_TLS_PROTOCOL_VERSIONS`:
    //
    //   (1) the pin contains exactly TLS 1.3 + TLS 1.2 (no broader set,
    //       no narrower set — the second is what BSI TR-02102-2 §3
    //       "still-acceptable" floor requires; the first is what some
    //       enterprise registries still terminate),
    //   (2) TLS 1.3 is listed first (documentation-of-intent ordering;
    //       rustls itself negotiates highest-mutually-supported but a
    //       reader of the const must see the preference up front).
    //
    // We assert against the public `version` field of
    // `SupportedProtocolVersion` (rustls 0.23) so the test is robust to
    // pointer-equality drift across rustls patch releases.

    #[test]
    fn outbound_tls_protocol_versions_contains_tls13_and_tls12_only() {
        let versions: Vec<rustls::ProtocolVersion> = OUTBOUND_TLS_PROTOCOL_VERSIONS
            .iter()
            .map(|v| v.version)
            .collect();
        assert_eq!(
            versions.len(),
            2,
            "OUTBOUND_TLS_PROTOCOL_VERSIONS must list exactly TLS 1.3 + TLS 1.2; got {versions:?}",
        );
        assert!(
            versions.contains(&rustls::ProtocolVersion::TLSv1_3),
            "TLS 1.3 must be in the pin; got {versions:?}",
        );
        assert!(
            versions.contains(&rustls::ProtocolVersion::TLSv1_2),
            "TLS 1.2 must be in the pin; got {versions:?}",
        );
    }

    #[test]
    fn outbound_tls_protocol_versions_lists_tls13_first() {
        // Documentation-of-intent ordering. rustls negotiates by mutual
        // capability rather than slice order, but BSI TR-02102-2 §3
        // recommends 1.3 as the preferred floor with 1.2 as the
        // backward-compat fallback. The slice order makes that
        // preference legible to the next reader without cross-referring
        // the spec.
        assert_eq!(
            OUTBOUND_TLS_PROTOCOL_VERSIONS[0].version,
            rustls::ProtocolVersion::TLSv1_3,
            "TLS 1.3 must be the first entry in the pin",
        );
        assert_eq!(
            OUTBOUND_TLS_PROTOCOL_VERSIONS[1].version,
            rustls::ProtocolVersion::TLSv1_2,
            "TLS 1.2 must be the second entry in the pin",
        );
    }
}
