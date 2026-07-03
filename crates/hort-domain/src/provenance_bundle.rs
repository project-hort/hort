//! Keyed cosign **Sigstore v0.3 bundle** signature-material extraction — pure
//! Rust, zero I/O (ADR 0039 §8).
//!
//! `cosign sign --key --registry-referrers-mode=oci-1-1` (cosign v3) does **not**
//! emit the legacy `simplesigning` layer. It emits a Sigstore v0.3 bundle
//! referrer (`artifactType = application/vnd.dev.sigstore.bundle.v0.3+json`)
//! carrying a **DSSE envelope** over an in-toto Statement — the *same wire shape*
//! as a keyless bundle, differing only in `verificationMaterial`:
//!
//! - **keyed** — `verificationMaterial.publicKey` (a bare key hint), **no**
//!   Fulcio certificate chain. The `cosign-key` verifier's shape.
//! - **keyless** — `verificationMaterial.certificate` /
//!   `x509CertificateChain` (a Fulcio-issued cert). The Sigstore verifier's
//!   shape — left untouched here.
//!
//! [`extract_keyed_dsse_signature`] parses a bundle's bytes and, **only** when
//! it is keyed (no cert chain), returns the material a pinned-key verifier
//! needs:
//!
//! - `signing_input` — the **DSSE PAE** (`DSSEv1 SP len(type) SP type SP
//!   len(payload) SP payload`) the ECDSA signature is actually computed over.
//!   The signature is **not** over the raw payload; feeding the raw payload to
//!   the verifier can never reach `Verified`.
//! - `signature` — the raw (DER) signature bytes from
//!   `dsseEnvelope.signatures[0].sig` (base64-decoded).
//! - `subject_digest` — the `sha256:<hex>` the DSSE in-toto Statement's
//!   `subject[].digest.sha256` binds. The verifier binds this to the served
//!   artifact's manifest digest (the re-tag guard — a signature over a
//!   *different* digest must be rejected, ADR 0039 §2).
//!
//! A **keyless** bundle (cert chain present) yields `Ok(None)` — it is the
//! Sigstore verifier's, never claimed here. Structurally-broken bundle JSON,
//! or a bundle that is not a keyed DSSE envelope, likewise yields `Ok(None)` or
//! [`DomainError::Validation`] per the doc on each arm; the keyed verifier maps
//! a `None`/absent to `NoAttestation`/`Malformed` at its boundary.

use base64::Engine as _;
use serde::Deserialize;

use crate::error::{DomainError, DomainResult};

/// The keyed-signature material extracted from a cosign v3 keyed Sigstore v0.3
/// bundle — everything a pinned-public-key verifier needs and nothing it must
/// read from storage. Pure value type; the adapter runs the ECDSA check over
/// [`signing_input`](Self::signing_input) and binds
/// [`subject_digest`](Self::subject_digest).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyedDsseSignature {
    /// The DSSE Pre-Authentication Encoding (`PAE(payloadType, payload)`) the
    /// signature is computed over — the bytes fed to the ECDSA verifier, **not**
    /// the raw payload.
    pub signing_input: Vec<u8>,
    /// The raw DER ECDSA signature bytes (base64-decoded from
    /// `dsseEnvelope.signatures[0].sig`).
    pub signature: Vec<u8>,
    /// The `sha256:<hex>` digest the signed in-toto Statement binds
    /// (`subject[].digest.sha256`). The verifier binds this to the served
    /// artifact's manifest digest (re-tag guard).
    pub subject_digest: String,
}

// --- Minimal serde projections of the Sigstore v0.3 bundle -----------------
// Only the fields keyed extraction needs; `serde` ignores every other bundle
// field (`mediaType`, `verificationMaterial.tlogEntries`,
// `timestampVerificationData`, …) — the keyed path uses no transparency-log
// or timestamp material.

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Bundle {
    #[serde(default)]
    verification_material: Option<VerificationMaterial>,
    #[serde(default)]
    dsse_envelope: Option<DsseEnvelope>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerificationMaterial {
    /// A bare pinned public-key hint — the **keyed** discriminator.
    #[serde(default)]
    public_key: Option<serde_json::Value>,
    /// A Fulcio leaf certificate — the **keyless** discriminator (single leaf,
    /// the modern v0.3 shape).
    #[serde(default)]
    certificate: Option<serde_json::Value>,
    /// A Fulcio certificate chain — the older keyless discriminator.
    #[serde(default)]
    x509_certificate_chain: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DsseEnvelope {
    /// Base64 (standard alphabet) of the signed payload bytes.
    payload: String,
    /// The DSSE payload type string (e.g. `application/vnd.in-toto+json`) —
    /// authenticated by the PAE, so it is part of the signing input.
    payload_type: String,
    #[serde(default)]
    signatures: Vec<DsseSignature>,
}

#[derive(Deserialize)]
struct DsseSignature {
    /// Base64 (standard alphabet) of the raw DER ECDSA signature.
    sig: String,
}

/// The in-toto Statement the DSSE payload carries — only its `subject[]`
/// digests. cosign's keyed sign emits an in-toto Statement whose single
/// subject digest is the signed image's manifest digest.
#[derive(Deserialize)]
struct InTotoStatement {
    #[serde(default)]
    subject: Vec<InTotoSubject>,
}

#[derive(Deserialize)]
struct InTotoSubject {
    #[serde(default)]
    digest: std::collections::HashMap<String, String>,
}

/// Extract the keyed-signature material from a cosign v3 Sigstore v0.3 bundle's
/// bytes, **iff** it is a keyed DSSE bundle (no Fulcio certificate).
///
/// Returns:
/// - `Ok(Some(_))` — a keyed DSSE bundle (`verificationMaterial.publicKey`, no
///   cert / cert chain) carrying a DSSE envelope with ≥1 signature and an
///   in-toto subject digest. The [`KeyedDsseSignature`] carries the PAE signing
///   input, the raw signature, and the `sha256:<hex>` subject digest.
/// - `Ok(None)` — **not this verifier's**: the bundle is keyless (a Fulcio
///   `certificate` / `x509CertificateChain` is present — the Sigstore
///   verifier's), or it is a well-formed JSON object that is simply not a keyed
///   DSSE bundle (no `dsseEnvelope`, or a keyed bundle whose envelope carries no
///   signature / no `sha256` subject). A `None` never asserts "unsigned"; it
///   asserts "not a keyed DSSE bundle" — the caller decides the verdict.
/// - `Err(DomainError::Validation)` — the bytes are not valid JSON, or the
///   embedded base64 (payload / signature) or the DSSE in-toto payload is
///   structurally undecodable. This is `Malformed` at the verifier boundary:
///   the bundle *claims* to be keyed DSSE but its material cannot be parsed, so
///   it must not silently pass as `None`/unsigned.
pub fn extract_keyed_dsse_signature(
    bundle_json: &[u8],
) -> DomainResult<Option<KeyedDsseSignature>> {
    let bundle: Bundle = serde_json::from_slice(bundle_json)
        .map_err(|e| DomainError::Validation(format!("not a valid Sigstore bundle: {e}")))?;

    // Keyed discriminator: a Fulcio certificate / chain means keyless — the
    // Sigstore verifier's bundle, never claimed here (fail-safe: presence of
    // ANY cert material routes it away from the keyed path).
    let Some(material) = &bundle.verification_material else {
        return Ok(None);
    };
    if material.certificate.is_some() || material.x509_certificate_chain.is_some() {
        return Ok(None);
    }
    // A keyed bundle asserts its trust anchor via a bare public key. Absent
    // both a cert AND a public key, the bundle carries no recognised trust
    // material — not this verifier's shape.
    if material.public_key.is_none() {
        return Ok(None);
    }

    // Keyed shape requires a DSSE envelope (cosign v3 `sign --key` emits one).
    let Some(envelope) = bundle.dsse_envelope else {
        return Ok(None);
    };

    let engine = base64::engine::general_purpose::STANDARD;
    let payload = engine.decode(envelope.payload.trim()).map_err(|e| {
        DomainError::Validation(format!(
            "keyed bundle DSSE payload is not valid base64: {e}"
        ))
    })?;

    // The DSSE envelope must carry a signature; a keyed DSSE envelope with an
    // empty `signatures` array is a keyed bundle with nothing to verify — not
    // this verifier's actionable shape (Ok(None), the caller maps to
    // NoAttestation, never a spurious Verified).
    let Some(first_sig) = envelope.signatures.first() else {
        return Ok(None);
    };
    let signature = engine.decode(first_sig.sig.trim()).map_err(|e| {
        DomainError::Validation(format!(
            "keyed bundle DSSE signature is not valid base64: {e}"
        ))
    })?;

    // The subject-digest binding: parse the in-toto Statement, take the first
    // subject's `sha256` digest. A keyed cosign sign emits exactly one subject
    // (the signed image). No `sha256` subject → nothing to bind → not
    // actionable (Ok(None)).
    let statement: InTotoStatement = serde_json::from_slice(&payload).map_err(|e| {
        DomainError::Validation(format!(
            "keyed bundle DSSE payload is not a valid in-toto Statement: {e}"
        ))
    })?;
    let Some(sha256) = statement
        .subject
        .iter()
        .find_map(|s| s.digest.get("sha256"))
    else {
        return Ok(None);
    };

    Ok(Some(KeyedDsseSignature {
        signing_input: dsse_pae(&envelope.payload_type, &payload),
        signature,
        subject_digest: format!("sha256:{sha256}"),
    }))
}

/// The DSSE Pre-Authentication Encoding (PAE) v1 the signature is computed over:
///
/// ```text
/// "DSSEv1" SP len(payloadType) SP payloadType SP len(payload) SP payload
/// ```
///
/// where `SP` is a single ASCII space and the lengths are ASCII-decimal byte
/// counts (in-toto DSSE spec). Authenticating the `payloadType` in the signed
/// bytes is what prevents a payload from being re-interpreted under a different
/// type.
fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + payload_type.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A standard-alphabet base64 of `bytes`.
    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    /// A minimal keyed v0.3 bundle carrying a DSSE envelope whose in-toto
    /// payload binds `digest_hex`, signed (opaquely) with `sig_bytes`.
    fn keyed_bundle(digest_hex: &str, payload_type: &str, sig_bytes: &[u8]) -> Vec<u8> {
        let statement = serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [ { "digest": { "sha256": digest_hex }, "annotations": {} } ],
            "predicateType": "https://sigstore.dev/cosign/sign/v1"
        })
        .to_string();
        serde_json::json!({
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": { "publicKey": { "hint": "abc" } },
            "dsseEnvelope": {
                "payload": b64(statement.as_bytes()),
                "payloadType": payload_type,
                "signatures": [ { "sig": b64(sig_bytes) } ]
            }
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn keyed_bundle_extracts_signature_pae_and_subject() {
        let digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let sig = vec![0x30, 0x44, 0x02, 0x20, 0xde, 0xad];
        let bundle = keyed_bundle(digest, "application/vnd.in-toto+json", &sig);
        let got = extract_keyed_dsse_signature(&bundle)
            .expect("valid keyed bundle")
            .expect("keyed material present");
        assert_eq!(got.signature, sig);
        assert_eq!(got.subject_digest, format!("sha256:{digest}"));
        // The signing input is the DSSE PAE, not the raw payload: it must start
        // with the DSSEv1 prefix and the payloadType length.
        assert!(got
            .signing_input
            .starts_with(b"DSSEv1 28 application/vnd.in-toto+json "));
    }

    #[test]
    fn pae_encoding_is_the_dsse_v1_shape() {
        let pae = dsse_pae("application/vnd.in-toto+json", b"HELLO");
        assert_eq!(
            pae,
            b"DSSEv1 28 application/vnd.in-toto+json 5 HELLO".to_vec()
        );
    }

    #[test]
    fn keyless_certificate_bundle_is_not_claimed() {
        // A Fulcio single-leaf `certificate` → keyless → Ok(None).
        let bundle = serde_json::json!({
            "verificationMaterial": { "certificate": { "rawBytes": "..." } },
            "dsseEnvelope": {
                "payload": b64(br#"{"subject":[{"digest":{"sha256":"aa"}}]}"#),
                "payloadType": "application/vnd.in-toto+json",
                "signatures": [ { "sig": b64(&[1, 2, 3]) } ]
            }
        })
        .to_string()
        .into_bytes();
        assert_eq!(extract_keyed_dsse_signature(&bundle).expect("valid"), None);
    }

    #[test]
    fn keyless_x509_chain_bundle_is_not_claimed() {
        let bundle = serde_json::json!({
            "verificationMaterial": { "x509CertificateChain": { "certificates": [] } },
            "dsseEnvelope": {
                "payload": b64(br#"{"subject":[{"digest":{"sha256":"aa"}}]}"#),
                "payloadType": "application/vnd.in-toto+json",
                "signatures": [ { "sig": b64(&[1]) } ]
            }
        })
        .to_string()
        .into_bytes();
        assert_eq!(extract_keyed_dsse_signature(&bundle).expect("valid"), None);
    }

    #[test]
    fn keyed_bundle_with_cert_present_prefers_keyless() {
        // Defense-in-depth: even if BOTH a publicKey and a certificate appear,
        // any cert material routes it to the keyless verifier (never claimed
        // keyed — the stricter, cert-anchored path wins).
        let bundle = serde_json::json!({
            "verificationMaterial": {
                "publicKey": { "hint": "abc" },
                "certificate": { "rawBytes": "..." }
            },
            "dsseEnvelope": {
                "payload": b64(br#"{"subject":[{"digest":{"sha256":"aa"}}]}"#),
                "payloadType": "application/vnd.in-toto+json",
                "signatures": [ { "sig": b64(&[1]) } ]
            }
        })
        .to_string()
        .into_bytes();
        assert_eq!(extract_keyed_dsse_signature(&bundle).expect("valid"), None);
    }

    #[test]
    fn no_verification_material_is_not_claimed() {
        let bundle = br#"{"dsseEnvelope":{"payload":"","payloadType":"x","signatures":[]}}"#;
        assert_eq!(extract_keyed_dsse_signature(bundle).expect("valid"), None);
    }

    #[test]
    fn public_key_but_no_dsse_envelope_is_not_claimed() {
        // A keyed bundle with a messageSignature (not a DSSE envelope) is not
        // the shape cosign v3 keyed sign emits; unclaimed here.
        let bundle = br#"{"verificationMaterial":{"publicKey":{"hint":"x"}},"messageSignature":{"signature":"AA=="}}"#;
        assert_eq!(extract_keyed_dsse_signature(bundle).expect("valid"), None);
    }

    #[test]
    fn keyed_dsse_with_empty_signatures_is_not_actionable() {
        let bundle = serde_json::json!({
            "verificationMaterial": { "publicKey": { "hint": "x" } },
            "dsseEnvelope": {
                "payload": b64(br#"{"subject":[{"digest":{"sha256":"aa"}}]}"#),
                "payloadType": "application/vnd.in-toto+json",
                "signatures": []
            }
        })
        .to_string()
        .into_bytes();
        assert_eq!(extract_keyed_dsse_signature(&bundle).expect("valid"), None);
    }

    #[test]
    fn keyed_dsse_without_sha256_subject_is_not_actionable() {
        // A subject whose only digest is sha512 → nothing to bind → Ok(None).
        let bundle = serde_json::json!({
            "verificationMaterial": { "publicKey": { "hint": "x" } },
            "dsseEnvelope": {
                "payload": b64(br#"{"subject":[{"digest":{"sha512":"deadbeef"}}]}"#),
                "payloadType": "application/vnd.in-toto+json",
                "signatures": [ { "sig": b64(&[1]) } ]
            }
        })
        .to_string()
        .into_bytes();
        assert_eq!(extract_keyed_dsse_signature(&bundle).expect("valid"), None);
    }

    #[test]
    fn keyed_dsse_with_no_subject_is_not_actionable() {
        let bundle = serde_json::json!({
            "verificationMaterial": { "publicKey": { "hint": "x" } },
            "dsseEnvelope": {
                "payload": b64(br#"{"subject":[]}"#),
                "payloadType": "application/vnd.in-toto+json",
                "signatures": [ { "sig": b64(&[1]) } ]
            }
        })
        .to_string()
        .into_bytes();
        assert_eq!(extract_keyed_dsse_signature(&bundle).expect("valid"), None);
    }

    #[test]
    fn malformed_json_is_validation_error() {
        let err = extract_keyed_dsse_signature(b"not json at all").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn non_object_json_is_validation_error() {
        // A JSON array does not deserialize into the Bundle struct.
        let err = extract_keyed_dsse_signature(b"[1,2,3]").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn keyed_dsse_payload_not_base64_is_validation_error() {
        let bundle = br#"{"verificationMaterial":{"publicKey":{"hint":"x"}},"dsseEnvelope":{"payload":"!!not base64!!","payloadType":"application/vnd.in-toto+json","signatures":[{"sig":"AA=="}]}}"#;
        let err = extract_keyed_dsse_signature(bundle).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn keyed_dsse_signature_not_base64_is_validation_error() {
        let payload = b64(br#"{"subject":[{"digest":{"sha256":"aa"}}]}"#);
        let bundle = format!(
            r#"{{"verificationMaterial":{{"publicKey":{{"hint":"x"}}}},"dsseEnvelope":{{"payload":"{payload}","payloadType":"application/vnd.in-toto+json","signatures":[{{"sig":"@@notb64@@"}}]}}}}"#
        );
        let err = extract_keyed_dsse_signature(bundle.as_bytes()).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn keyed_dsse_payload_not_intoto_is_validation_error() {
        // Valid base64, but the decoded bytes are not a JSON in-toto Statement.
        let bundle = format!(
            r#"{{"verificationMaterial":{{"publicKey":{{"hint":"x"}}}},"dsseEnvelope":{{"payload":"{}","payloadType":"application/vnd.in-toto+json","signatures":[{{"sig":"AA=="}}]}}}}"#,
            b64(b"this is not json")
        );
        let err = extract_keyed_dsse_signature(bundle.as_bytes()).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn keyed_signature_struct_constructs_and_debugs() {
        let s = KeyedDsseSignature {
            signing_input: b"DSSEv1 ...".to_vec(),
            signature: vec![1, 2, 3],
            subject_digest: "sha256:aa".to_string(),
        };
        assert_eq!(s.clone(), s);
        assert!(!format!("{s:?}").is_empty());
    }
}
