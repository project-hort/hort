//! Client-supplied digest parsing — shared between blob and manifest
//! pull.
//!
//! The OCI Distribution Spec only admits `sha256:<64-hex>`. Other
//! well-formed algorithms (`sha512:…`) return `UNSUPPORTED`;
//! everything else (missing `:`, wrong length, non-hex) returns
//! `DIGEST_INVALID`. Keeping the classifier in one module means a
//! future relaxation (e.g. sha512 support) only touches this file.

use hort_domain::types::ContentHash;

/// Parsed output of [`parse_digest`].
pub(super) enum DigestParse {
    /// Valid `sha256:<64-hex>`, wrapped in `ContentHash`.
    Ok(ContentHash),
    /// Well-formed algorithm prefix but not SHA-256 (e.g.
    /// `sha512:<hex>`). Spec: `UNSUPPORTED`. Carries no data — the
    /// requested algorithm is attacker-controlled and must not flow
    /// into a response body; `parse_digest` logs it server-side.
    Unsupported,
    /// Anything else: missing `:`, wrong length, non-hex. Spec:
    /// `DIGEST_INVALID`.
    Invalid { message: String },
}

/// Message shared by every call site that maps [`DigestParse::Unsupported`]
/// onto the wire — deliberately constant (never carries the requested
/// `algorithm`, which is attacker-controlled and unbounded up to the first
/// `:`) so a future call site can't accidentally reintroduce the echo.
pub(super) const UNSUPPORTED_DIGEST_ALGORITHM_MESSAGE: &str = "unsupported digest algorithm";

/// Parse a client-supplied digest string into a [`ContentHash`] or a
/// classified failure.
///
/// Neither failure variant echoes the raw `raw` / `algo` text into its
/// message — both are attacker-controlled (query param / manifest JSON
/// field / mount source) and reflecting them in a response body is a
/// log-injection / response-reflection vector. The offending value stays
/// available server-side via `tracing::debug!`.
pub(super) fn parse_digest(raw: &str) -> DigestParse {
    let Some((algo, hex)) = raw.split_once(':') else {
        tracing::debug!(digest = %raw, "OCI digest missing `<algorithm>:` prefix");
        return DigestParse::Invalid {
            message: "digest must be of the form <algorithm>:<hex>".to_string(),
        };
    };
    if algo != "sha256" {
        tracing::debug!(algorithm = %algo, "OCI digest algorithm unsupported");
        return DigestParse::Unsupported;
    }
    match hex.parse::<ContentHash>() {
        Ok(h) => DigestParse::Ok(h),
        Err(_) => {
            tracing::debug!(digest = %raw, "OCI sha256 digest malformed");
            DigestParse::Invalid {
                message: "sha256 digest must be exactly 64 lowercase hex characters".to_string(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn parses_valid_sha256() {
        match parse_digest(&format!("sha256:{SAMPLE_HEX}")) {
            DigestParse::Ok(h) => assert_eq!(h.as_ref(), SAMPLE_HEX),
            _ => panic!("expected Ok"),
        }
    }

    #[test]
    fn rejects_sha512_as_unsupported() {
        assert!(matches!(
            parse_digest(&format!("sha512:{SAMPLE_HEX}")),
            DigestParse::Unsupported
        ));
    }

    #[test]
    fn rejects_missing_algorithm_prefix_as_invalid() {
        assert!(matches!(
            parse_digest(SAMPLE_HEX),
            DigestParse::Invalid { .. }
        ));
    }

    #[test]
    fn rejects_too_short_sha256_as_invalid() {
        assert!(matches!(
            parse_digest("sha256:deadbeef"),
            DigestParse::Invalid { .. }
        ));
    }

    #[test]
    fn rejects_uppercase_hex_as_invalid() {
        // ContentHash::FromStr enforces lowercase hex — uppercase
        // trips the `Invalid` arm, not `Unsupported`.
        let upper = SAMPLE_HEX.to_uppercase();
        assert!(matches!(
            parse_digest(&format!("sha256:{upper}")),
            DigestParse::Invalid { .. }
        ));
    }
}
