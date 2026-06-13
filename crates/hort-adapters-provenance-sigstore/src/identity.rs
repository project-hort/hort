//! Observed-signer-identity extraction from a verified Fulcio leaf
//! certificate (ADR 0027).
//!
//! After the bundle's cert chain + SET + signature verify offline against
//! the cached trust root, the adapter reads the **observed** `{issuer,
//! san}` out of the leaf certificate and matches it against the policy's
//! [`SignerIdentityPattern`]s (the exact-or-bounded-glob matcher lives in
//! the domain — `hort-domain`). This module is the cert-parsing half.
//!
//! `issuer` = the Fulcio OIDC-issuer X.509 extension
//! (`1.3.6.1.4.1.57264.1.1`); `san` = the certificate Subject Alternative
//! Name (URI / RFC822 / Sigstore "other name"). Mirrors how
//! `sigstore::bundle::verify::policy::Identity` reads the same fields, but
//! *extracts* the observed value (so the domain glob matcher can run)
//! rather than asserting an exact literal.

use const_oid::ObjectIdentifier;
use hort_domain::ports::provenance::SignerIdentity;
use x509_cert::ext::pkix::{name::GeneralName, SubjectAltName};
use x509_cert::Certificate;

/// The Fulcio OIDC-issuer X.509 extension OID
/// (`1.3.6.1.4.1.57264.1.1`). The newer `…1.1.8` (issuer V2, DER-encoded
/// UTF8String) is intentionally not consulted here: the V1 extension is
/// the raw-string form every current Fulcio cert still carries and is
/// what `sigstore`'s own `OIDCIssuer` policy reads. A future Tier-2
/// initiative can add V2 if a deployed IdP drops the V1 extension.
const OIDC_ISSUER_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.1");

/// The Sigstore "other name" SAN OID (`1.3.6.1.4.1.57264.1.7`) — used for
/// non-URI / non-email workload identities (mirrors `sigstore`'s policy).
const OTHERNAME_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.7");

/// Why observed-identity extraction failed — both arms fold to the
/// adapter's `BundleMalformed` reject reason (a cert that verified
/// cryptographically but carries no readable identity is a malformed
/// attestation for our purposes, not an untrusted one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IdentityExtractError {
    /// No OIDC-issuer extension (`1.3.6.1.4.1.57264.1.1`) on the cert.
    MissingIssuer,
    /// No usable Subject Alternative Name (URI / email / Sigstore other).
    MissingSan,
}

/// Extract the observed `{issuer, san}` from a leaf certificate.
///
/// Returns the first usable SAN (URI, then RFC822 email, then a Sigstore
/// "other name"), and the OIDC-issuer extension value. Both must be
/// present; a cert missing either is an [`IdentityExtractError`] which the
/// caller maps to `BundleMalformed`.
pub(crate) fn observed_identity(
    cert: &Certificate,
) -> Result<SignerIdentity, IdentityExtractError> {
    let issuer = extract_issuer(cert).ok_or(IdentityExtractError::MissingIssuer)?;
    let san = extract_san(cert).ok_or(IdentityExtractError::MissingSan)?;
    Ok(SignerIdentity { issuer, san })
}

/// Read the OIDC-issuer extension's value. The V1 extension stores the
/// issuer URL as a **raw string** in `extn_value` (no DER wrapping) — the
/// same decode `sigstore`'s `OIDCIssuer` policy uses.
fn extract_issuer(cert: &Certificate) -> Option<String> {
    let extensions = cert.tbs_certificate.extensions.as_deref().unwrap_or(&[]);
    let mut matching = extensions
        .iter()
        .filter(|ext| ext.extn_id == OIDC_ISSUER_OID);
    // Exactly one issuer extension is expected; a duplicate is anomalous
    // → treat as absent (fail closed, like the sigstore policy's
    // exactly-one guard).
    let (Some(ext), None) = (matching.next(), matching.next()) else {
        return None;
    };
    let raw = ext.extn_value.as_bytes();
    let s = std::str::from_utf8(raw).ok()?;
    if s.is_empty() {
        None
    } else {
        Some(s.to_owned())
    }
}

/// Read the first usable SAN value (URI, then email, then Sigstore
/// other-name). Mirrors the `sigstore` `Identity` policy's SAN parsing.
fn extract_san(cert: &Certificate) -> Option<String> {
    let (_crit, san): (bool, SubjectAltName) = match cert.tbs_certificate.get() {
        Ok(Some(result)) => result,
        _ => return None,
    };
    san.0.iter().find_map(|name| match name {
        GeneralName::UniformResourceIdentifier(uri) => non_empty(uri.as_str()),
        GeneralName::Rfc822Name(email) => non_empty(email.as_str()),
        GeneralName::OtherName(other) if other.type_id == OTHERNAME_OID => {
            std::str::from_utf8(other.value.value())
                .ok()
                .and_then(non_empty)
        }
        _ => None,
    })
}

fn non_empty(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_cert::der::Decode;

    /// Decode the leaf certificate out of the committed real cosign bundle
    /// fixture (a genuine GitHub-Actions keyless signature for
    /// `kubewarden/kubewarden-controller`). Used to assert observed-identity
    /// extraction against a real-world cert.
    fn real_leaf_cert() -> Certificate {
        let bundle_json = include_str!("../tests/fixtures/cosign_bundle_v03_kubewarden.json");
        let v: serde_json::Value =
            serde_json::from_str(bundle_json).expect("fixture parses as JSON");
        let raw_b64 = v["verificationMaterial"]["certificate"]["rawBytes"]
            .as_str()
            .expect("fixture has a single certificate rawBytes");
        let der = base64_decode(raw_b64);
        Certificate::from_der(&der).expect("leaf cert DER decodes")
    }

    /// Minimal base64 decode (std-only) for the fixture cert — avoids a
    /// dev-dep on a base64 crate for one call site.
    fn base64_decode(s: &str) -> Vec<u8> {
        const TBL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut lut = [255u8; 256];
        for (i, &c) in TBL.iter().enumerate() {
            lut[c as usize] = i as u8;
        }
        let mut out = Vec::new();
        let mut acc = 0u32;
        let mut bits = 0u32;
        for &b in s.as_bytes() {
            if b == b'=' || b == b'\n' || b == b'\r' {
                continue;
            }
            let v = lut[b as usize];
            assert_ne!(v, 255, "invalid base64 char {b}");
            acc = (acc << 6) | v as u32;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
            }
        }
        out
    }

    #[test]
    fn extracts_real_github_actions_identity() {
        let cert = real_leaf_cert();
        let id = observed_identity(&cert).expect("real leaf has issuer + san");
        assert_eq!(id.issuer, "https://token.actions.githubusercontent.com");
        assert_eq!(
            id.san,
            "https://github.com/kubewarden/kubewarden-controller/\
             .github/workflows/release.yml@refs/tags/v1.34.0"
        );
    }

    #[test]
    fn extract_issuer_reads_the_oidc_extension() {
        let cert = real_leaf_cert();
        assert_eq!(
            extract_issuer(&cert).as_deref(),
            Some("https://token.actions.githubusercontent.com")
        );
    }

    #[test]
    fn extract_san_reads_the_uri_san() {
        let cert = real_leaf_cert();
        let san = extract_san(&cert).expect("uri san present");
        assert!(san.starts_with("https://github.com/kubewarden/"));
    }

    #[test]
    fn non_empty_filters_blank() {
        assert_eq!(non_empty("x"), Some("x".to_owned()));
        assert_eq!(non_empty(""), None);
    }

    /// A self-signed non-Fulcio cert (rcgen) carries no OIDC-issuer
    /// extension → `extract_issuer` is `None` and `observed_identity`
    /// fails with `MissingIssuer`. Covers the no-issuer reject path.
    fn rcgen_cert_without_fulcio_oids() -> Certificate {
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            "no-fulcio-oid test cert".to_string(),
        );
        // A SAN so this isolates the *issuer*-missing path from the
        // SAN-missing path.
        params.subject_alt_names.push(rcgen::SanType::URI(
            "https://example.com/x".try_into().unwrap(),
        ));
        let key = rcgen::KeyPair::generate().expect("keypair");
        let der = params.self_signed(&key).expect("self-sign").der().to_vec();
        Certificate::from_der(&der).expect("rcgen cert decodes")
    }

    #[test]
    fn observed_identity_missing_issuer_when_no_fulcio_oid() {
        let cert = rcgen_cert_without_fulcio_oids();
        // The SAN is present, but no issuer OID → MissingIssuer.
        assert_eq!(extract_san(&cert).as_deref(), Some("https://example.com/x"));
        assert_eq!(extract_issuer(&cert), None);
        assert_eq!(
            observed_identity(&cert),
            Err(IdentityExtractError::MissingIssuer)
        );
    }

    #[test]
    fn extract_san_none_when_no_san_extension() {
        // A cert with neither SAN nor Fulcio OIDs.
        let mut params = rcgen::CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "no-san".to_string());
        let key = rcgen::KeyPair::generate().expect("keypair");
        let der = params.self_signed(&key).expect("self-sign").der().to_vec();
        let cert = Certificate::from_der(&der).expect("decodes");
        assert_eq!(extract_san(&cert), None);
    }

    #[test]
    fn identity_extract_error_variants_are_distinct() {
        assert_ne!(
            IdentityExtractError::MissingIssuer,
            IdentityExtractError::MissingSan
        );
        // Debug is exercised for coverage of the derive.
        assert!(!format!("{:?}", IdentityExtractError::MissingIssuer).is_empty());
    }
}
