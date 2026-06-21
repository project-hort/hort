//! Upstream checksum types — the verification target a format handler
//! recovers from upstream metadata (npm `dist.integrity`,
//! PyPI `digests.sha256`, Cargo `cksum`, Maven `.sha256` sidecar) so the
//! ingest use case can compare it against bytes-on-the-wire.
//!
//! See ADR 0006 (mandatory upstream verification).

use serde::{Deserialize, Serialize};

use crate::error::{DomainError, DomainResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    /// SHA-1 (40 hex chars). **Transfer-verification target ONLY.**
    ///
    /// `Sha1` is valid solely as a
    /// [`crate::ports::format_handler`]-driven
    /// `VerifiedIngestRequest::UpstreamPublished` checksum — the weaker
    /// floor Maven Central guarantees on every artifact (`.sha1` sidecar).
    /// It is **never** a `ContentHash` (the CAS key is always SHA-256,
    /// independent of the transfer floor) and is never produced by a
    /// `ProtocolNative` request. SHA-1 is collision-broken; the floor
    /// catches transport corruption and casual tampering only, with TLS
    /// (system trust store + `HORT_EXTRA_CA_BUNDLE`) as the real
    /// transport-integrity control. See ADR 0033 (SHA-1 transfer-
    /// verification floor). This invariant is a doc/review contract — there
    /// is no consumer in this module to enforce it.
    Sha1,
    Sha256,
    Sha512,
}

impl HashAlgorithm {
    /// Hex-encoded length of a checksum produced by this algorithm.
    fn hex_len(self) -> usize {
        match self {
            HashAlgorithm::Sha1 => 40,
            HashAlgorithm::Sha256 => 64,
            HashAlgorithm::Sha512 => 128,
        }
    }
}

/// An authoritative checksum published by an upstream registry,
/// recovered by the format handler from upstream metadata
/// (npm `dist.integrity`, PyPI `digests.sha256`, Cargo `cksum`,
/// Maven `.sha256` sidecar).
///
/// The constructor enforces shape (correct hex length per algorithm,
/// lowercase, hex-only). `Deserialize` does NOT re-validate — events
/// round-tripped from JSONB by the event store adapter must accept any
/// shape that was previously written (the event-store contract).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamPublishedChecksum {
    algorithm: HashAlgorithm,
    hex: String,
}

impl UpstreamPublishedChecksum {
    /// Construct a new checksum, validating that `hex` is the right length
    /// for the algorithm and contains only lowercase hex characters.
    /// Returns `DomainError::Validation` on shape failure.
    pub fn new(algorithm: HashAlgorithm, hex: impl Into<String>) -> DomainResult<Self> {
        let hex = hex.into();
        let expected = algorithm.hex_len();
        if hex.len() != expected {
            return Err(DomainError::Validation(format!(
                "upstream checksum has {} chars, {:?} requires {}",
                hex.len(),
                algorithm,
                expected
            )));
        }
        if !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(DomainError::Validation(format!(
                "upstream checksum must be lowercase hex: {hex:?}"
            )));
        }
        Ok(Self { algorithm, hex })
    }

    pub fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    pub fn hex(&self) -> &str {
        &self.hex
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- HashAlgorithm ----------------------------------------------------

    #[test]
    fn hash_algorithm_serializes_as_lowercase_string() {
        let s = serde_json::to_string(&HashAlgorithm::Sha1).unwrap();
        assert_eq!(s, "\"sha1\"");
        let s = serde_json::to_string(&HashAlgorithm::Sha256).unwrap();
        assert_eq!(s, "\"sha256\"");
        let s = serde_json::to_string(&HashAlgorithm::Sha512).unwrap();
        assert_eq!(s, "\"sha512\"");
    }

    #[test]
    fn hash_algorithm_deserializes_from_lowercase_string() {
        let a: HashAlgorithm = serde_json::from_str("\"sha1\"").unwrap();
        assert_eq!(a, HashAlgorithm::Sha1);
        let a: HashAlgorithm = serde_json::from_str("\"sha256\"").unwrap();
        assert_eq!(a, HashAlgorithm::Sha256);
        let a: HashAlgorithm = serde_json::from_str("\"sha512\"").unwrap();
        assert_eq!(a, HashAlgorithm::Sha512);
    }

    #[test]
    fn hash_algorithm_round_trips_through_serde() {
        for alg in [
            HashAlgorithm::Sha1,
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha512,
        ] {
            let json = serde_json::to_string(&alg).unwrap();
            let back: HashAlgorithm = serde_json::from_str(&json).unwrap();
            assert_eq!(back, alg);
        }
    }

    #[test]
    fn hash_algorithm_partial_eq_holds() {
        assert_eq!(HashAlgorithm::Sha1, HashAlgorithm::Sha1);
        assert_eq!(HashAlgorithm::Sha256, HashAlgorithm::Sha256);
        assert_eq!(HashAlgorithm::Sha512, HashAlgorithm::Sha512);
        assert_ne!(HashAlgorithm::Sha256, HashAlgorithm::Sha512);
        assert_ne!(HashAlgorithm::Sha1, HashAlgorithm::Sha256);
    }

    #[test]
    fn hash_algorithm_is_copy() {
        let a = HashAlgorithm::Sha256;
        let b = a;
        // Both usable after move-by-copy.
        assert_eq!(a, HashAlgorithm::Sha256);
        assert_eq!(b, HashAlgorithm::Sha256);
    }

    #[test]
    fn hash_algorithm_is_debug() {
        assert_eq!(format!("{:?}", HashAlgorithm::Sha1), "Sha1");
        assert_eq!(format!("{:?}", HashAlgorithm::Sha256), "Sha256");
        assert_eq!(format!("{:?}", HashAlgorithm::Sha512), "Sha512");
    }

    // ----- UpstreamPublishedChecksum ---------------------------------------

    /// SHA-1 of "" (empty input) — 40 hex chars.
    const SHA1_EMPTY: &str = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
    /// SHA-256 of "" (empty input) — 64 hex chars.
    const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    /// SHA-512 of "" (empty input) — 128 hex chars.
    const SHA512_EMPTY: &str = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
         47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

    #[test]
    fn published_checksum_constructs_sha1() {
        // SHA-1 is a valid transfer-verification target (Maven `.sha1`
        // floor, ADR 0033): a 40-char lowercase-hex string constructs.
        let cs = UpstreamPublishedChecksum::new(HashAlgorithm::Sha1, SHA1_EMPTY).unwrap();
        assert_eq!(cs.algorithm(), HashAlgorithm::Sha1);
        assert_eq!(cs.hex(), SHA1_EMPTY);
        // The SHA-1 hex length is exactly 40.
        assert_eq!(cs.hex().len(), 40);
    }

    #[test]
    fn hash_algorithm_sha1_hex_len_is_40() {
        assert_eq!(HashAlgorithm::Sha1.hex_len(), 40);
    }

    #[test]
    fn published_checksum_rejects_wrong_length_sha1() {
        // A 64-char hex (sha256 length) for the sha1 algorithm — must reject.
        let err = UpstreamPublishedChecksum::new(HashAlgorithm::Sha1, SHA256_EMPTY).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        // A too-short string is also rejected.
        let err = UpstreamPublishedChecksum::new(HashAlgorithm::Sha1, "deadbeef").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn published_checksum_rejects_uppercase_hex_sha1() {
        let upper = SHA1_EMPTY.to_ascii_uppercase();
        let err = UpstreamPublishedChecksum::new(HashAlgorithm::Sha1, &upper).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn published_checksum_rejects_non_hex_chars_sha1() {
        // 40 chars but contains 'g' which is not hex.
        let bad = "g".repeat(40);
        let err = UpstreamPublishedChecksum::new(HashAlgorithm::Sha1, &bad).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn published_checksum_constructs_sha256() {
        let cs = UpstreamPublishedChecksum::new(HashAlgorithm::Sha256, SHA256_EMPTY).unwrap();
        assert_eq!(cs.algorithm(), HashAlgorithm::Sha256);
        assert_eq!(cs.hex(), SHA256_EMPTY);
    }

    #[test]
    fn published_checksum_constructs_sha512() {
        let hex: String = SHA512_EMPTY
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let cs = UpstreamPublishedChecksum::new(HashAlgorithm::Sha512, &hex).unwrap();
        assert_eq!(cs.algorithm(), HashAlgorithm::Sha512);
        assert_eq!(cs.hex(), hex);
    }

    #[test]
    fn published_checksum_rejects_wrong_length_sha256() {
        let too_short = "deadbeef";
        let err = UpstreamPublishedChecksum::new(HashAlgorithm::Sha256, too_short).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn published_checksum_rejects_wrong_length_sha512() {
        // 64-char hex (sha256 length) for sha512 algorithm — must reject.
        let err = UpstreamPublishedChecksum::new(HashAlgorithm::Sha512, SHA256_EMPTY).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn published_checksum_rejects_uppercase_hex() {
        // Uppercase variant of SHA256_EMPTY.
        let upper = SHA256_EMPTY.to_ascii_uppercase();
        let err = UpstreamPublishedChecksum::new(HashAlgorithm::Sha256, &upper).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn published_checksum_rejects_non_hex_chars() {
        // 64 chars but contains 'g' which is not hex.
        let bad = "g".repeat(64);
        let err = UpstreamPublishedChecksum::new(HashAlgorithm::Sha256, &bad).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn published_checksum_round_trips_through_serde() {
        let cs = UpstreamPublishedChecksum::new(HashAlgorithm::Sha256, SHA256_EMPTY).unwrap();
        let json = serde_json::to_string(&cs).unwrap();
        let back: UpstreamPublishedChecksum = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cs);
    }

    #[test]
    fn published_checksum_deserializes_without_re_validating() {
        // The constructor enforces shape, but `Deserialize` does not — events
        // round-tripped from JSONB by the event store adapter must accept any
        // shape that was once written. Proves a structurally-invalid hex
        // string deserialises (the contract: validation lives in `new`, not
        // in serde).
        let raw = r#"{"algorithm":"sha256","hex":"too-short"}"#;
        let parsed: UpstreamPublishedChecksum = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.algorithm(), HashAlgorithm::Sha256);
        assert_eq!(parsed.hex(), "too-short");
    }
}
