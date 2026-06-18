//! OCI Distribution Spec tag (reference) grammar validator.
//!
//! The OCI Distribution Spec pins the `<tag>` grammar as the regex:
//!
//! ```text
//! [a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}
//! ```
//!
//! That is: the first byte MUST be `[a-zA-Z0-9_]` (ASCII alphanumeric or
//! underscore — NOT `.` or `-`), every subsequent byte MUST be
//! `[a-zA-Z0-9._-]`, and the total length is at most **128** bytes
//! (one mandatory leading byte + up to 127 trailing bytes). Unlike the
//! `<name>` grammar this length IS normative — the spec fixes the cap.
//!
//! Control bytes, embedded NUL, CR / LF, `/`, space, and every UTF-8
//! multi-byte sequence are rejected by the per-byte alphabet walk.
//!
//! This validator is **adapter-local** (`pub(crate)`). The OCI grammar
//! is HTTP-adapter-specific; per the inbound-HTTP crate topology
//! (ADR 0008), protocol-shaped validation lives next to the HTTP
//! handlers, not in `hort-domain` or `hort-formats`. It is the sibling
//! of [`crate::name::validate_oci_name`] and
//! [`crate::digest::parse_digest`].
//!
//! ## Where it runs
//!
//! The manifest serve handler ([`crate::manifests::serve`]) splits a
//! `<reference>` into a digest (contains `:`) or a tag. The digest
//! branch is already validated by [`crate::digest::parse_digest`]; this
//! validator is the tag-branch equivalent. It runs BEFORE the
//! `RefUseCase::get` lookup and BEFORE any upstream pull-through URL is
//! constructed — an out-of-grammar tag must never flow into a ref query,
//! a metric label, a log line, or an upstream fetch URL.
//!
//! ## Error shape
//!
//! Returns `DomainError::Validation("oci.tag: <reason>")` on rejection.
//! The handler maps that to the same 400 `MANIFEST_INVALID` envelope it
//! already uses for a malformed manifest reference. The `<reason>` is a
//! deterministic description that NEVER echoes the offending bytes — the
//! caller's input may be attacker-controlled (CRLF, control bytes, raw
//! NULs) and surfacing it into log lines / response bodies is a
//! log-injection vector (mirrors the `name.rs` no-echo discipline).

use hort_domain::error::{DomainError, DomainResult};

/// Maximum total byte length of an OCI tag. The OCI Distribution Spec
/// pins this normatively: `[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}` is one
/// mandatory leading byte plus up to 127 trailing bytes.
pub(crate) const OCI_TAG_MAX_BYTES: usize = 128;

/// Validate `tag` against the OCI Distribution Spec tag grammar
/// `[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}`.
///
/// Returns `Ok(())` when every constraint holds; `Err(DomainError::Validation)`
/// with a structured `oci.tag: <reason>` message otherwise.
///
/// The implementation is a handwritten per-byte walk — no `regex`
/// dependency is added, mirroring [`crate::name::validate_oci_name`].
///
/// # Reject reasons
///
/// - `empty tag` — zero-length input.
/// - `exceeds 128-byte cap` — total byte length > 128.
/// - `first character must be [a-zA-Z0-9_]` — leading `.`, `-`, or any
///   byte outside the first-position alphabet (catches `..`, leading
///   `.`/`-`).
/// - `invalid character` — anything outside `[a-zA-Z0-9._-]` in a
///   non-leading position (catches `/`, space, control bytes, NUL, CR,
///   LF, UTF-8 multi-byte sequences).
pub(crate) fn validate_oci_tag(tag: &str) -> DomainResult<()> {
    if tag.is_empty() {
        return Err(DomainError::Validation(
            "oci.tag: empty tag is not permitted".to_string(),
        ));
    }
    if tag.len() > OCI_TAG_MAX_BYTES {
        return Err(DomainError::Validation(format!(
            "oci.tag: exceeds {OCI_TAG_MAX_BYTES}-byte cap"
        )));
    }

    let bytes = tag.as_bytes();

    // First byte: `[a-zA-Z0-9_]` only. `.` and `-` are NOT allowed in
    // the leading position per the spec grammar — this is what rejects
    // `..`, a leading `.`, and a leading `-`.
    let first = bytes[0];
    if !(first.is_ascii_alphanumeric() || first == b'_') {
        // Do NOT echo `first` — it's attacker-controlled.
        return Err(DomainError::Validation(
            "oci.tag: first character must be ASCII alphanumeric or `_`".to_string(),
        ));
    }

    // Remaining bytes: `[a-zA-Z0-9._-]`. Anything else (uppercase is
    // allowed for tags, unlike names; but `/`, space, control bytes,
    // NUL, CR, LF, and UTF-8 multi-byte sequences are not).
    for &b in &bytes[1..] {
        if b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-' {
            continue;
        }
        // Do NOT echo `b` — it's attacker-controlled.
        return Err(DomainError::Validation(
            "oci.tag: invalid character (allowed: `[a-zA-Z0-9._-]`)".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reason(tag: &str) -> String {
        match validate_oci_tag(tag) {
            Err(DomainError::Validation(msg)) => msg,
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    // ---------------- Accept cases ----------------

    #[test]
    fn accepts_canonical_tags() {
        validate_oci_tag("latest").expect("latest is canonical");
        validate_oci_tag("v1.2.3").expect("semver-with-v is valid");
        validate_oci_tag("1.0.0_rc1").expect("underscore + dots valid");
        validate_oci_tag("_underscore_lead").expect("leading underscore is allowed");
        validate_oci_tag("Release-2024").expect("uppercase + hyphen valid (tags allow uppercase)");
        validate_oci_tag("3").expect("single digit is valid");
    }

    #[test]
    fn accepts_tag_at_128_byte_cap() {
        // 1 leading alnum + 127 trailing = 128 bytes, exactly the cap.
        let at_cap = format!("a{}", "b".repeat(127));
        assert_eq!(at_cap.len(), OCI_TAG_MAX_BYTES);
        validate_oci_tag(&at_cap).expect("128 bytes is the cap, must accept");
    }

    // ---------------- Reject cases ----------------

    #[test]
    fn rejects_empty_tag() {
        assert!(reason("").contains("empty tag"));
    }

    #[test]
    fn rejects_tag_one_byte_over_cap() {
        // 129 bytes — one over the 128-byte cap.
        let over = "a".repeat(OCI_TAG_MAX_BYTES + 1);
        assert!(reason(&over).contains(&format!("{OCI_TAG_MAX_BYTES}-byte cap")));
    }

    #[test]
    fn rejects_leading_dot() {
        // `.` is not in the first-position alphabet.
        assert!(reason(".hidden").contains("first character"));
    }

    #[test]
    fn rejects_leading_hyphen() {
        // `-` is not in the first-position alphabet.
        assert!(reason("-flag").contains("first character"));
    }

    #[test]
    fn rejects_double_dot_path_traversal() {
        // `..` — leading `.` rejects on the first-character rule. Pinned
        // explicitly because path-traversal byte sequences are a
        // motivating threat for this validator.
        assert!(reason("..").contains("first character"));
    }

    #[test]
    fn rejects_embedded_slash() {
        // `/` would otherwise leak into the upstream pull-through URL.
        assert!(reason("foo/bar").contains("invalid character"));
    }

    #[test]
    fn rejects_embedded_space() {
        assert!(reason("foo bar").contains("invalid character"));
    }

    #[test]
    fn rejects_embedded_nul() {
        assert!(reason("foo\0bar").contains("invalid character"));
    }

    #[test]
    fn rejects_crlf() {
        // CRLF rejection covers CWE-117 (log injection) + CWE-93 (CRLF
        // injection). The whole sequence and each byte individually must
        // reject.
        assert!(reason("v1\r\nInjected").contains("invalid character"));
        assert!(validate_oci_tag("v1\rInjected").is_err());
        assert!(validate_oci_tag("v1\nInjected").is_err());
    }

    #[test]
    fn rejects_utf8_multibyte_sequence() {
        // Smiley (U+1F600) — 4-byte UTF-8 sequence; first non-ASCII byte
        // trips the per-byte walk.
        assert!(reason("v\u{1f600}").contains("invalid character"));
    }

    #[test]
    fn message_does_not_echo_input() {
        // The validator's error message must never include the offending
        // bytes — an attacker-controlled input full of CRLF would
        // otherwise pollute logs and response bodies.
        let attacker = "v1".to_string() + &"\r\n".repeat(50) + "EVIL";
        let msg = reason(&attacker);
        assert!(!msg.contains("EVIL"), "message must not echo input ({msg})");
        assert!(
            !msg.contains('\r') && !msg.contains('\n'),
            "message must not carry CRLF from input ({msg})"
        );
    }
}
