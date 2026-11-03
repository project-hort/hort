//! Client-supplied digest parsing — shared between blob and manifest
//! pull.
//!
//! This registry only addresses `sha256:<64-hex>`. Digests must first
//! satisfy the OCI descriptor grammar; malformed values return
//! `DIGEST_INVALID`. Other grammatical algorithms return `UNSUPPORTED`.
//! The document classifier in `hort-domain::oci` must apply the same rule.

use hort_domain::types::ContentHash;

/// Parsed output of [`parse_digest`].
pub(super) enum DigestParse {
    /// Valid `sha256:<64-hex>`, wrapped in `ContentHash`.
    Ok(ContentHash),
    /// Grammatical digest with an algorithm other than SHA-256 (e.g.
    /// `sha512:<128 hex>`). Spec: `UNSUPPORTED`. Carries no data — the
    /// requested algorithm is attacker-controlled and must not flow
    /// into a response body; `parse_digest` logs it server-side.
    Unsupported,
    /// Anything else: missing `:`, invalid grammar, wrong length, non-hex. Spec:
    /// `DIGEST_INVALID`.
    Invalid { message: String },
}

/// Message shared by every call site that maps [`DigestParse::Unsupported`]
/// onto the wire — a constant, so a future call site can't accidentally
/// reintroduce the echo of the requested `algorithm`, which is
/// attacker-controlled and unbounded up to the first `:`.
///
/// The invariant is **no part of the declaration**, not "no interpolation at
/// all": the `UNSUPPORTED` envelope carries no `detail`, so a call site that
/// has to say *where* in a document the offending digest sat has only this
/// message to say it in. Appending a position hort derived itself — an index
/// child's `manifests[N]` slot, bounded by the domain's per-index child cap —
/// is therefore permitted and reflects nothing the declarant supplied.
/// Appending the algorithm, the digest, or any inner parser message is not.
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
            message: "digest must be of the form <algorithm>:<encoded>".to_string(),
        };
    };
    let algorithm_is_grammatical = algo.split(['+', '.', '_', '-']).all(|component| {
        !component.is_empty()
            && component
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    });
    let encoded_is_grammatical = !hex.is_empty()
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'=' | b'_' | b'-'));
    if !algorithm_is_grammatical || !encoded_is_grammatical {
        tracing::debug!(digest = %raw, "OCI digest violates descriptor grammar");
        return DigestParse::Invalid {
            message: "digest must match OCI descriptor grammar".to_string(),
        };
    }
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
    use hort_domain::oci::DescriptorProblem;

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
            parse_digest(&format!("sha512:{}", "a".repeat(128))),
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

    // ===================================================================
    // Guard: the strict digest classifier exists twice and nothing else
    //        holds the copies together
    // ===================================================================
    //
    // The two copies, and why there are two:
    //
    //   1. `parse_digest` above — a digest on a **request line**.
    //      `pub(super)`, inside this inbound adapter.
    //   2. `hort_domain::oci`'s private `strict_sha256_digest` — a digest
    //      read out of a **document** (an index child's
    //      `manifests[].digest`), classified into `DescriptorProblem`.
    //
    // The domain copy's own doc comment already names this one: "the same
    // split the OCI HTTP adapter draws on a request-line digest … Two
    // boundaries, two inputs; one rule." They agree today and nothing made
    // them keep agreeing.
    //
    // **Delegating one to the other is not the fix, and was rejected on
    // layering grounds.** `parse_digest` is `pub(super)` inside an inbound
    // adapter and `strict_sha256_digest` is private to `hort-domain`;
    // widening either visibility so one could call the other would trade a
    // silent divergence for an inverted dependency (ADR 0008). Two copies
    // are allowed. A silent divergence is not — so this guard holds the
    // three-way split of both copies against each other, and **needs no
    // visibility change anywhere**: `hort-http-oci` is the only crate that
    // can see both, this one `pub(super)` directly and the domain one
    // through its public surface (`index_child_descriptors` →
    // `IndexChildren` → `IndexChildFault::problem`, all `pub`).
    //
    // **The domain copy has a fourth outcome with no counterpart:
    // `DescriptorProblem::MissingDigest`.** A document field can be absent;
    // a request-line string always exists, so `parse_digest` takes `&str`
    // and has no shape for it. The asymmetry is intended and the table
    // below deliberately does NOT hold that arm — do not add a bogus
    // adapter case to "complete" it.

    /// One row of the shared classification, as the coarse verdict **both**
    /// copies are obliged to reach. It is coarser than `DescriptorProblem`
    /// on purpose: the adapter answers `DIGEST_INVALID` for a missing
    /// prefix and for malformed hex alike, while the domain splits those
    /// two — so "invalid" is the finest bucket the two actually share, and
    /// a guard asserting more would be asserting something only one side
    /// says.
    #[derive(Debug, PartialEq, Eq)]
    enum SharedVerdict {
        /// `sha256:<64 lowercase hex>` — resolves, to this hash.
        Addressable(String),
        /// Complies with the descriptor digest grammar but names an
        /// algorithm hort cannot address. The OCI image spec:
        /// "Implementations SHOULD allow digests with unrecognized
        /// algorithms to pass validation if they comply with the above
        /// grammar" — so the document is valid and only unservable, which
        /// is a different wire code from an invalid one.
        WellFormedButUnsupported,
        /// Invalid digest grammar or a malformed SHA-256 value.
        Invalid,
    }

    /// The adapter copy's verdict for `raw`.
    fn adapter_verdict(raw: &str) -> SharedVerdict {
        match parse_digest(raw) {
            DigestParse::Ok(h) => SharedVerdict::Addressable(h.as_ref().to_owned()),
            DigestParse::Unsupported => SharedVerdict::WellFormedButUnsupported,
            DigestParse::Invalid { .. } => SharedVerdict::Invalid,
        }
    }

    /// The domain copy's verdict for the same `raw`, reached the only way
    /// it is reachable from outside `hort-domain`: as the `digest` of a
    /// minimal index's single child.
    fn domain_verdict(raw: &str) -> SharedVerdict {
        let (verdict, _) = domain_classification(raw);
        verdict
    }

    /// The domain copy's coarse verdict **and** the exact
    /// [`DescriptorProblem`] behind it, so the table can assert both the
    /// shared rule and the finer split the domain owns alone.
    fn domain_classification(raw: &str) -> (SharedVerdict, Option<DescriptorProblem>) {
        let body = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [ { "digest": raw, "size": 7 } ],
        })
        .to_string()
        .into_bytes();
        let children =
            hort_domain::oci::index_child_descriptors(&body).expect("a well-formed index document");
        assert_eq!(
            children.declared(),
            1,
            "the fixture must present exactly one child for `{raw}` to be the subject"
        );
        match children.into_all_declared() {
            Ok(resolved) => (
                SharedVerdict::Addressable(resolved[0].hash.as_ref().to_owned()),
                None,
            ),
            Err(fault) => {
                assert_eq!(fault.position, 0);
                let verdict = if fault.problem.is_well_formed_but_unsupported() {
                    SharedVerdict::WellFormedButUnsupported
                } else {
                    SharedVerdict::Invalid
                };
                (verdict, Some(fault.problem))
            }
        }
    }

    /// The table. Each row pins the exact outcome on **both** sides and
    /// then asserts the two agree — the agreement is the point, the exact
    /// variants are what make a failure say which copy moved.
    #[test]
    fn the_request_line_and_document_digest_classifiers_agree_arm_for_arm() {
        let other_algorithm = format!("sha512:{}", "a".repeat(128));
        let rows: [(&str, &str, bool, Option<DescriptorProblem>); 11] = [
            // input, label, adapter-is-`Unsupported`, domain problem
            (
                SAMPLE_HEX,
                "no `<algorithm>:` prefix",
                false,
                Some(DescriptorProblem::NoAlgorithmPrefix),
            ),
            (
                &other_algorithm,
                "a prefix naming an algorithm other than sha256",
                true,
                Some(DescriptorProblem::UnsupportedAlgorithm),
            ),
            (
                "sha512:",
                "an empty encoded portion",
                false,
                Some(DescriptorProblem::MalformedDigest),
            ),
            (
                "sha512:!",
                "a forbidden encoded character",
                false,
                Some(DescriptorProblem::MalformedDigest),
            ),
            (
                "sha+512:Ab-_=",
                "allowed algorithm separator and encoded characters",
                true,
                Some(DescriptorProblem::UnsupportedAlgorithm),
            ),
            (
                "sha++512:abc",
                "an empty algorithm component",
                false,
                Some(DescriptorProblem::MalformedDigest),
            ),
            (
                ":abc",
                "an empty algorithm",
                false,
                Some(DescriptorProblem::MalformedDigest),
            ),
            (
                "SHA256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "an uppercase algorithm",
                false,
                Some(DescriptorProblem::MalformedDigest),
            ),
            (
                "sha256:",
                "an empty sha256 encoded portion",
                false,
                Some(DescriptorProblem::MalformedSha256),
            ),
            (
                "sha256:deadbeef",
                "a `sha256:` body that is not 64 lowercase hex",
                false,
                Some(DescriptorProblem::MalformedSha256),
            ),
            (
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "a valid `sha256:<64 lowercase hex>`",
                false,
                None,
            ),
        ];

        for (input, label, adapter_unsupported, expected_problem) in rows {
            let adapter = adapter_verdict(input);
            let (domain, problem) = domain_classification(input);

            // The exact adapter variant, so a lost `Unsupported` arm names
            // itself rather than showing up as a bare disagreement.
            assert_eq!(
                matches!(parse_digest(input), DigestParse::Unsupported),
                adapter_unsupported,
                "{label}: the adapter's UNSUPPORTED/DIGEST_INVALID split moved"
            );
            // The exact domain variant, including the two it splits out of
            // the shared `Invalid` bucket.
            assert_eq!(
                problem, expected_problem,
                "{label}: the domain's DescriptorProblem moved"
            );
            // And the shared rule: one rule, two boundaries.
            assert_eq!(
                adapter, domain,
                "{label}: the two copies of the strict digest classifier have diverged"
            );
        }
    }

    /// **The valid row must agree on the hash, not merely both succeed.**
    /// Two copies that both accept a digest and disagree about which CAS
    /// object it names is the worst divergence of the set and the one a
    /// `matches!(.., Ok(_))` table would not see: the request line would
    /// serve one object and the document would keep another alive.
    #[test]
    fn the_two_classifiers_agree_on_which_content_a_valid_digest_names() {
        let raw = format!("sha256:{SAMPLE_HEX}");
        assert_eq!(
            adapter_verdict(&raw),
            SharedVerdict::Addressable(SAMPLE_HEX.to_owned()),
            "the adapter must resolve to exactly the declared hex"
        );
        assert_eq!(
            domain_verdict(&raw),
            SharedVerdict::Addressable(SAMPLE_HEX.to_owned()),
            "and so must the document copy"
        );
    }

    /// **Counter-assertion: the comparison above can still fail.**
    ///
    /// Every assertion in the table is an equality between two values the
    /// test computes, so the way it goes quietly vacuous is for the
    /// comparison itself to stop discriminating — a copy collapsed to one
    /// blanket outcome, which is exactly the shape a "simplify this
    /// classifier" refactor produces. So this feeds the domain copy the
    /// neighbouring rows' inputs against a stand-in adapter that **has**
    /// collapsed (its `Unsupported` arm deleted, the single most likely
    /// loss: a relaxation that adds `sha512` support by deleting the
    /// algorithm test) and asserts the comparison notices.
    ///
    /// If this test ever passes, the table above proves nothing.
    #[test]
    fn a_collapsed_copy_is_caught_by_the_comparison() {
        /// `parse_digest` with the `if algo != "sha256"` test removed —
        /// a non-sha256 algorithm then falls through to the hex parse and
        /// comes back as the blanket `Invalid`.
        fn adapter_without_the_unsupported_arm(raw: &str) -> SharedVerdict {
            match raw.split_once(':') {
                Some((_, hex)) => match hex.parse::<ContentHash>() {
                    Ok(h) => SharedVerdict::Addressable(h.as_ref().to_owned()),
                    Err(_) => SharedVerdict::Invalid,
                },
                None => SharedVerdict::Invalid,
            }
        }

        let other_algorithm = format!("sha512:{}", "a".repeat(128));
        // The collapsed copy agrees with the domain on every row it did not
        // lose...
        for row in [
            SAMPLE_HEX,
            "sha256:deadbeef",
            &format!("sha256:{SAMPLE_HEX}"),
        ] {
            assert_eq!(
                adapter_without_the_unsupported_arm(row),
                domain_verdict(row),
                "the stand-in must differ from the real copy on exactly ONE row,                  or this counter-assertion is testing the wrong thing"
            );
        }
        // ...and the one it lost is the one the comparison catches.
        assert_ne!(
            adapter_without_the_unsupported_arm(&other_algorithm),
            domain_verdict(&other_algorithm),
            "a copy that lost its UNSUPPORTED arm must not read as agreeing"
        );
        // Which also pins that the real copy has NOT collapsed that way.
        assert_eq!(
            adapter_verdict(&other_algorithm),
            domain_verdict(&other_algorithm)
        );
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
