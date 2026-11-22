//! **The** `Authorization` auth-scheme rule for every inbound surface.
//!
//! RFC 7235 §2.1 defines `credentials = auth-scheme [ 1*SP ( token68 /
//! #auth-param ) ]`, and `auth-scheme` is a **token**, which §2.1 matches
//! **case-insensitively**. Two consequences a hand-written
//! `strip_prefix("Bearer ")` gets wrong, and a conformant client is
//! entitled to exercise either:
//!
//! - `authorization: bearer <token>` carries a Bearer credential. So do
//!   `BEARER`, `Bearer` and any other spelling.
//! - `Authorization: Bearer  <token>` — `1*SP`, one **or more** spaces —
//!   separates the scheme from the credential just as a single space does.
//!
//! Getting either wrong is not a diagnosable error on the inbound path:
//! every absence mode collapses to "no token", so an unrecognised scheme
//! spelling makes a credentialed request take the anonymous path and
//! receive the challenge / anti-enumeration answer for an
//! unauthenticated one.
//!
//! # Why this is one function rather than a convention
//!
//! The rule has six inbound consumers — the three shared-middleware
//! extractors in [`crate::middleware::auth`] plus the OCI middleware and
//! `/v2/auth` handler in `hort-http-oci` — and re-typing it per consumer
//! is how it came to be spelled case-sensitively at all six while the
//! outbound `WWW-Authenticate` parser
//! (`hort_adapters_upstream_http::challenge`) spelled it correctly. The
//! case-insensitivity and the `1*SP` run are answered **together**, in
//! one call: splitting them across two helpers lets a call site adopt one
//! half and reintroduces the drift.
//!
//! It lives in `hort-http-core` because every consumer is an inbound-HTTP
//! crate and this is their common ancestor (ADR 0008). The outbound
//! challenge parser deliberately does **not** call it: it asks a
//! different question — "is the scheme of an already-split challenge
//! Bearer" — and an `hort-adapters-*` crate depending on an
//! `hort-http-*` crate would invert the layering.
//!
//! Wire-shape inventory and per-mechanism restrictions:
//! `docs/auth-catalog.md` entries 2 / 4 (Bearer) and 8 (Basic).

/// An `auth-scheme` hort accepts on an inbound `Authorization` header.
///
/// A closed set rather than a `&str` parameter: a caller free to pass any
/// string could spell the scheme differently at each site, and that
/// divergence is the entire failure [`strip_auth_scheme`] exists to end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthScheme {
    /// RFC 7617 HTTP Basic. On every hort surface the password half is a
    /// token carrier and the username half is ignored — auth-catalog
    /// entry 8.
    Basic,
    /// RFC 6750 Bearer — auth-catalog entries 2 and 4.
    Bearer,
}

impl AuthScheme {
    /// The scheme token in its registered spelling. Only ever compared
    /// case-insensitively, so this is the canonical form for rendering a
    /// challenge, never a form an inbound header must match byte-wise.
    fn token(self) -> &'static str {
        match self {
            Self::Basic => "Basic",
            Self::Bearer => "Bearer",
        }
    }
}

/// Does `header_value` carry `scheme`, and if so what is the credential
/// after it?
///
/// `Some(credential)` when the leading `auth-scheme` token matches
/// `scheme` under ASCII case folding **and** at least one space follows
/// it. The whole `1*SP` run is the separator and is never part of the
/// returned credential.
///
/// `None` when the header carries a different scheme, or the scheme token
/// with no space after it (`"Bearer"` alone is RFC 7235 `credentials`
/// with no parameters — it carries nothing to validate).
///
/// The credential is returned verbatim otherwise: trailing whitespace,
/// emptiness and payload syntax stay the caller's to classify, so each
/// consumer's existing refusal shape is untouched. In particular
/// `Some("")` is the answer for a scheme followed by nothing but spaces,
/// which every caller already folds into its own "no credential" bucket.
pub fn strip_auth_scheme(header_value: &str, scheme: AuthScheme) -> Option<&str> {
    let token = scheme.token();
    let (candidate, rest) = header_value.split_at_checked(token.len())?;
    if !candidate.eq_ignore_ascii_case(token) {
        return None;
    }
    // `1*SP`: one space is mandatory, further spaces belong to the
    // separator rather than to the credential.
    Some(rest.strip_prefix(' ')?.trim_start_matches(' '))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_case_single_space_strips_to_the_credential() {
        assert_eq!(
            strip_auth_scheme("Bearer tok", AuthScheme::Bearer),
            Some("tok")
        );
        assert_eq!(
            strip_auth_scheme("Basic Yjo=", AuthScheme::Basic),
            Some("Yjo=")
        );
    }

    #[test]
    fn every_case_spelling_yields_the_same_credential() {
        // The property is that case does not matter, so the assertion is
        // the equality of the outcomes rather than a literal per spelling.
        let canonical = strip_auth_scheme("Bearer tok", AuthScheme::Bearer);
        for spelling in ["bearer tok", "BEARER tok", "bEaReR tok"] {
            assert_eq!(
                strip_auth_scheme(spelling, AuthScheme::Bearer),
                canonical,
                "{spelling} disagrees with the canonical-case spelling"
            );
        }
        let canonical = strip_auth_scheme("Basic Yjo=", AuthScheme::Basic);
        for spelling in ["basic Yjo=", "BASIC Yjo=", "bAsIc Yjo="] {
            assert_eq!(
                strip_auth_scheme(spelling, AuthScheme::Basic),
                canonical,
                "{spelling} disagrees with the canonical-case spelling"
            );
        }
    }

    #[test]
    fn the_whole_sp_run_is_separator_not_credential() {
        // RFC 7235 §2.1 `1*SP`: more than one space separates just as one
        // does, and none of them reaches the credential.
        let canonical = strip_auth_scheme("Bearer tok", AuthScheme::Bearer);
        for spacing in ["Bearer  tok", "Bearer   tok", "bearer     tok"] {
            assert_eq!(
                strip_auth_scheme(spacing, AuthScheme::Bearer),
                canonical,
                "{spacing:?} disagrees with the single-space spelling"
            );
        }
    }

    #[test]
    fn a_different_scheme_does_not_satisfy_this_one() {
        // Not a prefix-free "anything goes": a scheme token that is not
        // the requested one carries no credential for it.
        assert_eq!(strip_auth_scheme("Digest tok", AuthScheme::Bearer), None);
        assert_eq!(strip_auth_scheme("digest tok", AuthScheme::Bearer), None);
        assert_eq!(strip_auth_scheme("Negotiate tok", AuthScheme::Bearer), None);
        assert_eq!(strip_auth_scheme("Basic Yjo=", AuthScheme::Bearer), None);
        assert_eq!(strip_auth_scheme("Bearer tok", AuthScheme::Basic), None);
    }

    #[test]
    fn a_scheme_token_that_merely_starts_with_the_scheme_is_not_it() {
        // `Bearerish` is a different token, not `Bearer` plus a
        // credential — the mandatory SP is what separates the two.
        assert_eq!(strip_auth_scheme("Bearerish tok", AuthScheme::Bearer), None);
        assert_eq!(strip_auth_scheme("Bearer", AuthScheme::Bearer), None);
        assert_eq!(strip_auth_scheme("", AuthScheme::Bearer), None);
        assert_eq!(strip_auth_scheme("Bear", AuthScheme::Bearer), None);
    }

    #[test]
    fn a_scheme_with_no_credential_after_it_strips_to_empty() {
        // `Some("")` rather than `None`: the scheme IS present, and
        // whether an empty credential is absent or malformed is each
        // caller's existing classification, not this function's.
        assert_eq!(strip_auth_scheme("Bearer ", AuthScheme::Bearer), Some(""));
        assert_eq!(strip_auth_scheme("Bearer   ", AuthScheme::Bearer), Some(""));
        assert_eq!(strip_auth_scheme("Basic ", AuthScheme::Basic), Some(""));
    }

    #[test]
    fn only_sp_is_a_separator() {
        // `1*SP` is literally spaces. A tab is not part of the separator,
        // so it stays in the credential for the caller to reject — and a
        // tab in the scheme position is not a separator at all.
        assert_eq!(
            strip_auth_scheme("Bearer \ttok", AuthScheme::Bearer),
            Some("\ttok")
        );
        assert_eq!(strip_auth_scheme("Bearer\ttok", AuthScheme::Bearer), None);
    }

    #[test]
    fn trailing_whitespace_in_the_credential_is_left_to_the_caller() {
        assert_eq!(
            strip_auth_scheme("Bearer tok ", AuthScheme::Bearer),
            Some("tok ")
        );
    }

    #[test]
    fn a_multibyte_leading_char_is_not_a_scheme() {
        // `split_at_checked` refuses a non-char-boundary split, so a
        // header whose first bytes are a multi-byte code point cannot
        // panic its way through the comparison.
        assert_eq!(strip_auth_scheme("Béarer tok", AuthScheme::Bearer), None);
        assert_eq!(
            strip_auth_scheme("日本語テキスト x", AuthScheme::Bearer),
            None
        );
    }

    #[test]
    fn scheme_tokens_render_in_their_registered_spelling() {
        // The canonical form the challenge builders emit; the inbound
        // comparison never requires it.
        assert_eq!(AuthScheme::Basic.token(), "Basic");
        assert_eq!(AuthScheme::Bearer.token(), "Bearer");
    }
}
