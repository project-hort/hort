//! OCI Distribution Spec name grammar validator.
//!
//! The OCI Distribution Spec defines the `<name>` ABNF as:
//!
//! ```text
//! name              := [a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*
//! ```
//!
//! The spec does NOT pin a normative length cap; this validator imposes
//! two additional caps as defence-in-depth so the rest of the OCI inbound
//! pipeline (parse → coords → metric labels → log lines) never sees a
//! pathological name:
//!
//! - **Total byte length ≤ 256** — comfortably above any real-world
//!   image name (`org/team/sub-team/project/component-variant` clocks
//!   in well under 100 bytes) and below any value that would inflate
//!   downstream log / metric / index emission.
//! - **Component count ≤ 8** — `a/b/c/d/e/f/g/h` is the limit; nine or
//!   more `/`-separated components reject. Forecloses pathological deep
//!   paths that would otherwise pass the per-component grammar but
//!   produce e.g. 256-byte names with 64 single-character components.
//!
//! Control bytes, embedded NUL, CR / LF — all rejected by the per-byte
//! grammar walk (the allowed alphabet is `[a-z0-9._-/]` plus the
//! component-internal-only `[._-]` separators).
//!
//! This validator is **adapter-local** (`pub(crate)`). The OCI grammar
//! is HTTP-adapter-specific; the `hort-formats::oci::normalize_name`
//! identity function in `hort-formats` stays as-is. Per the inbound-HTTP
//! crate topology (ADR 0008 §8), validation that's protocol-shaped lives
//! next to the HTTP handlers, not in `hort-domain` or `hort-formats`.
//!
//! ## Where it runs
//!
//! Every OCI handler that accepts a path-captured `<name>` runs the
//! validator AFTER tail parsing and BEFORE any storage / manifest /
//! upload action. This is the spec-compliance gate: a name that fails
//! the grammar must not flow into `Artifact.name`, manifest digest
//! lookups, metric labels, or log lines.
//!
//! ## Error shape
//!
//! Returns `DomainError::Validation("oci.name: <reason>")` on
//! rejection. The handler maps that to `OciError::NameInvalid` (400,
//! spec code `NAME_INVALID`). The `<reason>` carries a deterministic
//! description that NEVER echoes the offending bytes — the caller's
//! input may be megabytes of attacker-controlled bytes (CRLF, control
//! bytes, raw NULs) and surfacing it into log lines / response bodies
//! is a log-injection vector.
//!
//! Design authority: OCI Distribution Spec (name ABNF); publish-handler
//! validator invariants (reject malformed names before any storage
//! action; never echo offending bytes in error output).

use hort_domain::error::{DomainError, DomainResult};

/// Maximum total byte length of an OCI image name accepted by the
/// validator. The OCI Distribution Spec does not pin a normative limit;
/// 256 is the hort-imposed cap (defence-in-depth — see
/// module head).
pub(crate) const OCI_NAME_MAX_BYTES: usize = 256;

/// Maximum number of `/`-separated components in an OCI image name.
/// The OCI Distribution Spec does not pin a normative limit; 8 is the
/// hort-imposed cap (forecloses pathological deep paths
/// that pass per-component grammar — see module head).
pub(crate) const OCI_NAME_MAX_COMPONENTS: usize = 8;

/// Validate `name` against the OCI Distribution Spec name grammar +
/// the hort byte and component-count caps.
///
/// Grammar (canonical):
/// `[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*`
///
/// Returns `Ok(())` when every constraint holds; `Err(DomainError::Validation)`
/// with a structured `oci.name: <reason>` message otherwise.
///
/// The implementation is a handwritten state machine — no `regex`
/// dependency is added. The grammar is small enough that a per-byte
/// walk is clearer than a regex (and avoids the regex crate's compile-
/// once-per-call overhead at the request hot path).
///
/// # Reject reasons
///
/// - `empty name` — zero-length input.
/// - `exceeds 256-byte cap` — total byte length > 256.
/// - `exceeds 8-component cap` — more than 8 `/`-separated parts.
/// - `empty component` — `foo//bar`, leading or trailing `/`.
/// - `component starts with separator` — leading `.`, `_`, `-` in a
///   component (e.g. `foo/.bar`, `_baz`).
/// - `component ends with separator` — trailing `.`, `_`, `-`.
/// - `consecutive separators in component` — `foo..bar`, `foo--bar`.
/// - `invalid character` — anything outside `[a-z0-9._-/]` (catches
///   uppercase, control bytes, NUL, CR, LF, UTF-8 multi-byte sequences).
pub(crate) fn validate_oci_name(name: &str) -> DomainResult<()> {
    if name.is_empty() {
        return Err(DomainError::Validation(
            "oci.name: empty name is not permitted".to_string(),
        ));
    }
    if name.len() > OCI_NAME_MAX_BYTES {
        return Err(DomainError::Validation(format!(
            "oci.name: exceeds {OCI_NAME_MAX_BYTES}-byte cap"
        )));
    }

    // Walk the bytes once. Track:
    //   - `component_count`: number of `/`-separated parts seen so far
    //     (incremented on each `/` and at start; reset of "in_component"
    //     happens on each `/`).
    //   - `component_byte_len`: bytes in the current component (0 means
    //     we're either at the start or just after a `/`).
    //   - `prev_was_separator`: the previous byte in this component was
    //     `.`, `_`, or `-`. Used to reject consecutive separators.
    //
    // Per-byte rules:
    //   - `[a-z0-9]` — always valid in any position; clears
    //     `prev_was_separator`.
    //   - `[._-]` — valid only if (a) we're not at the start of a
    //     component (`component_byte_len > 0`) AND (b) the previous
    //     byte was alphanumeric (`!prev_was_separator`). Sets
    //     `prev_was_separator = true`.
    //   - `/` — closes the current component. The component MUST be
    //     non-empty AND its last byte MUST be alphanumeric (i.e.
    //     `prev_was_separator == false`). Increments `component_count`,
    //     resets `component_byte_len` and `prev_was_separator`.
    //   - Anything else (uppercase, control byte, NUL, CR, LF, UTF-8
    //     non-ASCII) — invalid.
    let bytes = name.as_bytes();
    let mut component_count: usize = 1; // First component is implicit at start.
    let mut component_byte_len: usize = 0;
    let mut prev_was_separator: bool = false;

    for &b in bytes {
        if b == b'/' {
            // Empty component (leading `/`, trailing `/`, or `//`).
            if component_byte_len == 0 {
                return Err(DomainError::Validation(
                    "oci.name: empty component (leading, trailing, or consecutive `/`)".to_string(),
                ));
            }
            // Trailing separator inside the just-closed component.
            if prev_was_separator {
                return Err(DomainError::Validation(
                    "oci.name: component ends with separator `.`, `_`, or `-`".to_string(),
                ));
            }
            component_count += 1;
            if component_count > OCI_NAME_MAX_COMPONENTS {
                return Err(DomainError::Validation(format!(
                    "oci.name: exceeds {OCI_NAME_MAX_COMPONENTS}-component cap"
                )));
            }
            component_byte_len = 0;
            prev_was_separator = false;
            continue;
        }

        if b.is_ascii_lowercase() || b.is_ascii_digit() {
            component_byte_len += 1;
            prev_was_separator = false;
            continue;
        }

        if b == b'.' || b == b'_' || b == b'-' {
            // Separator at the start of a component (component is empty
            // so far). The OCI grammar requires `[a-z0-9]+` BEFORE any
            // `[._-]`.
            if component_byte_len == 0 {
                return Err(DomainError::Validation(
                    "oci.name: component starts with separator `.`, `_`, or `-`".to_string(),
                ));
            }
            // Two consecutive separators (e.g. `foo..bar`, `foo--bar`).
            if prev_was_separator {
                return Err(DomainError::Validation(
                    "oci.name: consecutive separators in component".to_string(),
                ));
            }
            component_byte_len += 1;
            prev_was_separator = true;
            continue;
        }

        // Anything else is invalid: uppercase ASCII, control bytes
        // (0x00..=0x1F including NUL, CR, LF), 0x7F, UTF-8 multi-byte
        // sequences (0x80..=0xFF), space, punctuation outside `[._-/]`.
        // Do NOT echo `b` — it's attacker-controlled.
        return Err(DomainError::Validation(
            "oci.name: invalid character (allowed: `[a-z0-9._-/]`)".to_string(),
        ));
    }

    // End-of-input checks: same shape as the `/` branch.
    if component_byte_len == 0 {
        // Trailing `/` → already returned above when we saw the `/`,
        // unless the entire input was `/` — then component_count
        // bumped but we never wrote any bytes. Either way, surface as
        // "empty component".
        return Err(DomainError::Validation(
            "oci.name: empty component (leading, trailing, or consecutive `/`)".to_string(),
        ));
    }
    if prev_was_separator {
        return Err(DomainError::Validation(
            "oci.name: component ends with separator `.`, `_`, or `-`".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------- Acceptance criteria coverage ------------------------
    //
    // Backlog Item 10 lists seven mandatory test shapes. Each one has a
    // dedicated test below; additional smaller tests pin specific
    // grammar branches (e.g. trailing separator, single-component cap).

    /// Acceptance #1 — Grammar happy path.
    #[test]
    fn happy_path_accepts_legal_names() {
        validate_oci_name("library/nginx").expect("library/nginx is canonical");
        validate_oci_name("nginx").expect("single-component name is allowed");
        validate_oci_name("my.org/team-name/image-name")
            .expect("dotted org + hyphenated team / image");
        // Underscore-bearing component (allowed per grammar).
        validate_oci_name("my_org/repo").expect("underscores are valid separators");
        // 8-component name — exactly at the cap, must accept.
        validate_oci_name("a/b/c/d/e/f/g/h").expect("8-component name is at the cap");
        // 256-byte name — exactly at the byte cap, must accept.
        let at_cap: String = "a".repeat(OCI_NAME_MAX_BYTES);
        assert_eq!(at_cap.len(), OCI_NAME_MAX_BYTES);
        validate_oci_name(&at_cap).expect("256 bytes is the cap, must accept");
    }

    /// Acceptance #2 — Grammar rejection (uppercase, consecutive `/`,
    /// leading dot in component).
    #[test]
    fn grammar_violations_reject_with_validation_error() {
        // Uppercase — entire alphabet outside `[a-z0-9._-/]`.
        let err = validate_oci_name("Foo/Bar").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        let DomainError::Validation(msg) = err else {
            unreachable!()
        };
        assert!(
            msg.starts_with("oci.name: "),
            "validator messages must be tagged `oci.name:` ({msg})"
        );
        assert!(msg.contains("invalid character"), "{msg}");

        // Consecutive `/`.
        let err = validate_oci_name("foo//bar").unwrap_err();
        let DomainError::Validation(msg) = err else {
            unreachable!()
        };
        assert!(msg.contains("empty component"), "{msg}");

        // Leading dot in a component.
        let err = validate_oci_name("foo/.bar").unwrap_err();
        let DomainError::Validation(msg) = err else {
            unreachable!()
        };
        assert!(msg.contains("starts with separator"), "{msg}");
    }

    /// Acceptance #3 — Length cap at the validator (NOT at the
    /// `BoundedPath` extractor — that's a different test in `lib.rs`).
    /// 257 bytes → 400.
    #[test]
    fn rejects_name_one_byte_over_cap() {
        let over: String = "a".repeat(OCI_NAME_MAX_BYTES + 1);
        let err = validate_oci_name(&over).unwrap_err();
        let DomainError::Validation(msg) = err else {
            unreachable!()
        };
        assert!(
            msg.contains(&format!("{OCI_NAME_MAX_BYTES}-byte cap")),
            "{msg}"
        );
    }

    /// Acceptance #4 — Component count cap. 9 components must reject.
    #[test]
    fn rejects_nine_component_name() {
        // `a/b/c/d/e/f/g/h/i` — 9 components, exactly one over the cap.
        let err = validate_oci_name("a/b/c/d/e/f/g/h/i").unwrap_err();
        let DomainError::Validation(msg) = err else {
            unreachable!()
        };
        assert!(
            msg.contains(&format!("{OCI_NAME_MAX_COMPONENTS}-component cap")),
            "{msg}"
        );
    }

    /// Acceptance #6 — Embedded NUL byte. `foo\0bar` must reject.
    #[test]
    fn rejects_embedded_nul() {
        let err = validate_oci_name("foo\0bar").unwrap_err();
        let DomainError::Validation(msg) = err else {
            unreachable!()
        };
        assert!(
            msg.contains("invalid character"),
            "embedded NUL must surface as invalid character ({msg})"
        );
    }

    /// Acceptance #7 — CRLF in name. `nginx\r\nInjected` must reject
    /// at the validator BEFORE `header_value_or_bad_request` ever runs
    /// (i.e. before the response builder constructs any header).
    /// The CRLF rejection covers the audit's CWE-117 (log injection)
    /// + CWE-93 (CRLF injection) signals.
    #[test]
    fn rejects_crlf_in_name() {
        let err = validate_oci_name("nginx\r\nInjected").unwrap_err();
        let DomainError::Validation(msg) = err else {
            unreachable!()
        };
        assert!(
            msg.contains("invalid character"),
            "CRLF must surface as invalid character ({msg})"
        );
        // Cross-check: CR and LF individually also reject (defence-in-
        // depth — a future change that splits the CRLF check should
        // not silently let the individual bytes through).
        assert!(matches!(
            validate_oci_name("nginx\rInjected"),
            Err(DomainError::Validation(_))
        ));
        assert!(matches!(
            validate_oci_name("nginx\nInjected"),
            Err(DomainError::Validation(_))
        ));
    }

    // ---------------- Additional grammar branch coverage ------------------

    #[test]
    fn rejects_empty_name() {
        let err = validate_oci_name("").unwrap_err();
        let DomainError::Validation(msg) = err else {
            unreachable!()
        };
        assert!(msg.contains("empty name"), "{msg}");
    }

    #[test]
    fn rejects_leading_slash() {
        let err = validate_oci_name("/nginx").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn rejects_trailing_slash() {
        let err = validate_oci_name("nginx/").unwrap_err();
        let DomainError::Validation(msg) = err else {
            unreachable!()
        };
        assert!(msg.contains("empty component"), "{msg}");
    }

    #[test]
    fn rejects_trailing_separator_in_component() {
        // `foo-` — alphanumeric followed by separator, no closing
        // alphanumeric. Must reject at end-of-input.
        let err = validate_oci_name("foo-").unwrap_err();
        let DomainError::Validation(msg) = err else {
            unreachable!()
        };
        assert!(msg.contains("ends with separator"), "{msg}");

        // Same for `foo-/bar` — separator at the close of a component
        // must reject when we hit the `/`.
        let err = validate_oci_name("foo-/bar").unwrap_err();
        let DomainError::Validation(msg) = err else {
            unreachable!()
        };
        assert!(msg.contains("ends with separator"), "{msg}");
    }

    #[test]
    fn rejects_consecutive_separators_in_component() {
        let err = validate_oci_name("foo..bar").unwrap_err();
        let DomainError::Validation(msg) = err else {
            unreachable!()
        };
        assert!(msg.contains("consecutive separators"), "{msg}");

        let err = validate_oci_name("foo--bar").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn rejects_leading_separator_in_subcomponent() {
        // `foo/_bar` — second component starts with `_`.
        let err = validate_oci_name("foo/_bar").unwrap_err();
        let DomainError::Validation(msg) = err else {
            unreachable!()
        };
        assert!(msg.contains("starts with separator"), "{msg}");
    }

    #[test]
    fn rejects_utf8_multibyte_sequence() {
        // Smiley (U+1F600) — 4-byte UTF-8 sequence. None of the bytes
        // are in `[a-z0-9._-/]`, so the per-byte walk rejects on the
        // first non-ASCII byte.
        let err = validate_oci_name("library/n\u{1f600}ginx").unwrap_err();
        let DomainError::Validation(msg) = err else {
            unreachable!()
        };
        assert!(msg.contains("invalid character"), "{msg}");
    }

    #[test]
    fn rejects_path_traversal_marker() {
        // `..` is rejected by the leading-separator rule (`.` in
        // position 0 of a component is illegal). Pinning explicitly
        // because the audit notes path-traversal byte sequences as a
        // motivating threat.
        let err = validate_oci_name("..").unwrap_err();
        let DomainError::Validation(msg) = err else {
            unreachable!()
        };
        assert!(msg.contains("starts with separator"), "{msg}");

        let err = validate_oci_name("foo/../bar").unwrap_err();
        let DomainError::Validation(msg) = err else {
            unreachable!()
        };
        assert!(msg.contains("starts with separator"), "{msg}");
    }

    #[test]
    fn rejects_name_with_uppercase_anywhere() {
        // The grammar allows lowercase only; uppercase anywhere fails.
        for bad in &["Library/nginx", "library/Nginx", "library/ngiNx"] {
            let err = validate_oci_name(bad).unwrap_err();
            let DomainError::Validation(msg) = err else {
                unreachable!()
            };
            assert!(msg.contains("invalid character"), "{bad}: {msg}");
        }
    }

    #[test]
    fn message_does_not_echo_input() {
        // Defence-in-depth: the validator's error message must never
        // include the offending bytes. A 1024-byte attacker-controlled
        // input full of CRLF / NUL would otherwise pollute logs and
        // response bodies.
        let attacker = "a".to_string() + &"\r\n".repeat(100) + "EVIL";
        let err = validate_oci_name(&attacker).unwrap_err();
        let DomainError::Validation(msg) = err else {
            unreachable!()
        };
        assert!(
            !msg.contains("EVIL"),
            "validator message must NOT echo attacker input ({msg})"
        );
        assert!(
            !msg.contains('\r') && !msg.contains('\n'),
            "validator message must not carry CRLF from input ({msg})"
        );
    }
}
