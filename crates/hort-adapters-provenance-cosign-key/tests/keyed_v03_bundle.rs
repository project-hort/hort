//! End-to-end keyed-verification test over the **real** cosign v3 keyed
//! Sigstore v0.3 bundle (ADR 0039 §8, issue #14).
//!
//! The fixtures are ground truth: `keyed_v03_bundle.json` was produced by
//! `cosign v3.0.4 sign --key <fixture> --registry-referrers-mode=oci-1-1`
//! (the exact E2E invocation) over a throwaway image, and `cosign.pub` is the
//! committed test keypair's public half (the same key the compose worker
//! pins). The bundle is a DSSE envelope over an in-toto Statement binding the
//! image's manifest digest; the signature is ECDSA-P256 over the DSSE PAE.
//!
//! These exercise the WHOLE keyed v0.3 path through the public `verify` API:
//! the orchestration's routing (`build_bundle` → `new_signed(bundle, raw sig)`)
//! is reproduced here so the crypto path is fed exactly what the worker feeds
//! it. A verify is asserted ONLY when the real signature checks out — never on
//! parse-success alone.

use hort_adapters_provenance_cosign_key::CosignKeyVerifier;
use hort_domain::ports::provenance::{
    AttestationBundle, ProvenancePort, ProvenanceRejectReason, ProvenanceRequirements,
    ProvenanceSubject, ProvenanceVerdict, SignerIdentity,
};
use hort_domain::types::ContentHash;

const BUNDLE_JSON: &str = include_str!("fixtures/keyed_v03_bundle.json");
const PUBLIC_KEY_PEM: &str = include_str!("fixtures/cosign.pub");

/// The manifest digest the fixture bundle's in-toto subject binds (the
/// throwaway image cosign signed).
const BOUND_DIGEST_HEX: &str = "c766679d161d4ffe3dc4503b4c9f90b978f0d363fcedb02d1ae0cd271e645c0a";
/// A different digest — the re-tag attack target.
const OTHER_DIGEST_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn run<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

fn verifier() -> CosignKeyVerifier {
    CosignKeyVerifier::from_pem_keys(&[PUBLIC_KEY_PEM.to_string()]).expect("fixture pub key parses")
}

fn hash(hex: &str) -> ContentHash {
    hex.parse().unwrap()
}

fn subject(h: &ContentHash) -> ProvenanceSubject<'_> {
    ProvenanceSubject {
        content_hash: h,
        payload: b"",
        name: "gt/app",
        version: Some("v1"),
    }
}

fn empty_reqs() -> ProvenanceRequirements<'static> {
    ProvenanceRequirements {
        allowed_identities: &[],
    }
}

/// Build the `AttestationBundle` exactly as the orchestration's `build_bundle`
/// does for a keyed v0.3 bundle: `new_signed(bundle bytes, raw DSSE sig)`,
/// where the raw sig is pulled from the bundle via the domain extractor (the
/// same helper the orchestrator calls).
fn keyed_bundle(bundle_bytes: &[u8]) -> AttestationBundle {
    let material = hort_domain::provenance_bundle::extract_keyed_dsse_signature(bundle_bytes)
        .expect("fixture is a valid keyed bundle")
        .expect("fixture is keyed (bare publicKey, no cert)");
    AttestationBundle::new_signed(bundle_bytes.to_vec(), material.signature)
}

fn keyed_signer() -> SignerIdentity {
    SignerIdentity {
        issuer: "cosign-key".to_string(),
        san: "pinned-public-key".to_string(),
    }
}

#[test]
fn real_keyed_v03_bundle_with_matching_digest_verifies() {
    let v = verifier();
    let h = hash(BOUND_DIGEST_HEX);
    let subj = subject(&h);
    let bundles = [keyed_bundle(BUNDLE_JSON.as_bytes())];
    let verdict = run(v.verify(&subj, &bundles, &empty_reqs())).unwrap();
    assert_eq!(
        verdict,
        ProvenanceVerdict::verified(keyed_signer(), None),
        "the real cosign v3 keyed bundle must VERIFY against the pinned fixture key with a matching subject digest"
    );
}

#[test]
fn real_keyed_v03_bundle_retagged_onto_other_image_is_digest_mismatch() {
    // The re-tag attack: a valid signature for image A presented for image B.
    // MUST be rejected (BundleMalformed per ADR 0039 §2 mapping), never Verified.
    let v = verifier();
    let h = hash(OTHER_DIGEST_HEX);
    let subj = subject(&h);
    let bundles = [keyed_bundle(BUNDLE_JSON.as_bytes())];
    let verdict = run(v.verify(&subj, &bundles, &empty_reqs())).unwrap();
    assert_eq!(
        verdict,
        ProvenanceVerdict::rejected(ProvenanceRejectReason::BundleMalformed),
        "a valid keyed signature re-tagged onto a different image digest must be Rejected"
    );
}

#[test]
fn real_keyed_v03_bundle_against_wrong_pinned_key_is_untrusted_identity() {
    // Pin a DIFFERENT P-256 key than the one that signed → the digest binds but
    // no pinned key verifies → UntrustedIdentity (WrongKey).
    let other_pub = generate_other_p256_pub_pem();
    let v = CosignKeyVerifier::from_pem_keys(&[other_pub]).unwrap();
    let h = hash(BOUND_DIGEST_HEX);
    let subj = subject(&h);
    let bundles = [keyed_bundle(BUNDLE_JSON.as_bytes())];
    let verdict = run(v.verify(&subj, &bundles, &empty_reqs())).unwrap();
    assert_eq!(
        verdict,
        ProvenanceVerdict::rejected(ProvenanceRejectReason::UntrustedIdentity),
        "the real signature must NOT verify against a different pinned key"
    );
}

#[test]
fn real_keyed_v03_bundle_with_tampered_signature_does_not_verify() {
    // Flip a byte in the raw DSSE signature: the digest still binds, but the
    // ECDSA check fails against the correct key → not Verified (WrongKey /
    // UntrustedIdentity — no pinned key verifies the tampered sig).
    let v = verifier();
    let h = hash(BOUND_DIGEST_HEX);
    let subj = subject(&h);
    let material =
        hort_domain::provenance_bundle::extract_keyed_dsse_signature(BUNDLE_JSON.as_bytes())
            .unwrap()
            .unwrap();
    let mut tampered = material.signature.clone();
    // Corrupt a byte in the middle of the DER signature (not the tag/length so
    // it stays DER-parseable but cryptographically wrong).
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0xFF;
    let bundles = [AttestationBundle::new_signed(
        BUNDLE_JSON.as_bytes().to_vec(),
        tampered,
    )];
    let verdict = run(v.verify(&subj, &bundles, &empty_reqs())).unwrap();
    assert_ne!(
        verdict,
        ProvenanceVerdict::verified(keyed_signer(), None),
        "a tampered signature must NEVER verify"
    );
    assert_eq!(
        verdict,
        ProvenanceVerdict::rejected(ProvenanceRejectReason::UntrustedIdentity),
        "a tampered but DER-parseable signature binds the digest yet no key verifies it → UntrustedIdentity"
    );
}

#[test]
fn keyless_fulcio_bundle_is_not_claimed_by_the_keyed_verifier() {
    // A keyless bundle carries a Fulcio `certificate`. `build_bundle` would
    // route it to the Sigstore verifier (signature = None); handed directly to
    // the keyed verifier it must yield NoAttestation (not claimed), never a
    // spurious verdict — the partition-by-shape guarantee (ADR 0039 §6).
    let keyless = br#"{
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": { "certificate": { "rawBytes": "AAAA" } },
        "dsseEnvelope": {
            "payload": "eyJzdWJqZWN0IjpbeyJkaWdlc3QiOnsic2hhMjU2IjoiYWEifX1dfQ==",
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [ { "sig": "AAAA" } ]
        }
    }"#;
    // The orchestration routes a keyless bundle as unsigned (signature = None).
    let bundle = AttestationBundle::new(keyless.to_vec());
    let v = verifier();
    let h = hash(BOUND_DIGEST_HEX);
    let subj = subject(&h);
    let verdict = run(v.verify(&subj, &[bundle], &empty_reqs())).unwrap();
    assert_eq!(
        verdict,
        ProvenanceVerdict::no_attestation(),
        "a keyless (Fulcio-cert) bundle must not be claimed by the keyed verifier"
    );
}

#[test]
fn malformed_keyed_bundle_is_rejected_bundle_malformed() {
    // A bundle that IS keyed-shaped (bare publicKey, no cert) but whose DSSE
    // payload is not valid base64 → the extractor errs → the keyed verifier
    // maps it to Malformed → BundleMalformed. Fed as new_signed (a keyed
    // routing) so it reaches the keyed verify path.
    let malformed = br#"{
        "verificationMaterial": { "publicKey": { "hint": "x" } },
        "dsseEnvelope": {
            "payload": "!!not base64!!",
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [ { "sig": "AAAA" } ]
        }
    }"#;
    let bundle = AttestationBundle::new_signed(malformed.to_vec(), vec![0x30, 0x06]);
    let v = verifier();
    let h = hash(BOUND_DIGEST_HEX);
    let subj = subject(&h);
    let verdict = run(v.verify(&subj, &[bundle], &empty_reqs())).unwrap();
    assert_eq!(
        verdict,
        ProvenanceVerdict::rejected(ProvenanceRejectReason::BundleMalformed),
        "a keyed-shaped bundle with undecodable DSSE material must be Rejected{{BundleMalformed}}"
    );
}

/// Generate a fresh, unrelated P-256 SPKI public-key PEM (for the wrong-key
/// negative). Uses the same `p256` the adapter verifies with.
fn generate_other_p256_pub_pem() -> String {
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::{EncodePublicKey, LineEnding};
    use rand_core::OsRng;
    let k = SigningKey::random(&mut OsRng);
    k.verifying_key().to_public_key_pem(LineEnding::LF).unwrap()
}
