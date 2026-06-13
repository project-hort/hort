//! Shared RFC 8693 token-exchange constants + gate function.
//! Consumed by the `/api/v1/auth/exchange` handler and the
//! `/.well-known/hort-client-config` discovery doc — a single home
//! for the string literals both surfaces publish.

/// RFC 8693 §2.1 — the only `grant_type` value `/exchange` accepts.
pub(crate) const EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// RFC 8693 §3 — `urn:ietf:params:oauth:token-type:access_token`.
/// The default `subject_token_type` value when callers omit
/// `subject_token_type` from the form body is also this URI.
pub(crate) const TOKEN_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";

/// RFC 8693 §3 — `urn:ietf:params:oauth:token-type:jwt`. The second
/// supported `subject_token_type`: a federated foreign JWT (k8s
/// projected SA token, GitHub Actions OIDC, GitLab CI OIDC, Keycloak
/// service-account token) exchanged for a short-lived
/// `TokenKind::ServiceAccount` bearer. The federation branch in
/// `exchange.rs` validates the JWT via the `FederatedJwtValidator`
/// port and resolves the matching `ServiceAccount` from
/// `federated_identities[].claims` (ADR 0018 + `docs/auth-catalog.md`).
pub(crate) const TOKEN_TYPE_JWT: &str = "urn:ietf:params:oauth:token-type:jwt";

/// RFC 8693 §3 — the closed set of `subject_token_type` values
/// `/exchange` accepts. `id_token` is deliberately NOT accepted:
/// accepting it was only ever a workaround for a
/// missing-`sub`-on-access_token IdP configuration, and the
/// standards-shaped fix is an IdP-side claim mapper (see
/// `docs/operator/idp-setup.md`). Mixing `id_token`'s
/// `aud = client_id` semantics with the validator's single-audience
/// matching against `HORT_OIDC_AUDIENCE` is ambiguous; narrowing the
/// surface to `access_token` makes the audience semantics
/// unambiguous.
///
/// [`TOKEN_TYPE_JWT`] is the federation branch — a foreign-IdP-signed
/// JWT exchanged for a short-lived service-account bearer.
pub(crate) const SUPPORTED_SUBJECT_TOKEN_TYPES: &[&str] =
    &[TOKEN_TYPE_ACCESS_TOKEN, TOKEN_TYPE_JWT];

/// Is `value` one of the [`SUPPORTED_SUBJECT_TOKEN_TYPES`]?
/// Single source of truth — extracted from the inline match in
/// `exchange.rs` and the doc-comment reference in `well_known.rs`
/// (which previously cited a non-existent
/// `crate::handlers::exchange::is_supported_subject_token_type`).
pub(crate) fn is_supported_subject_token_type(value: &str) -> bool {
    SUPPORTED_SUBJECT_TOKEN_TYPES.contains(&value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_subject_token_types_contains_access_token() {
        assert!(is_supported_subject_token_type(TOKEN_TYPE_ACCESS_TOKEN));
    }

    #[test]
    fn supported_subject_token_types_contains_jwt() {
        // Federation-branch supported subject token type. Companion
        // to the access_token row above.
        assert!(is_supported_subject_token_type(TOKEN_TYPE_JWT));
        assert_eq!(TOKEN_TYPE_JWT, "urn:ietf:params:oauth:token-type:jwt");
    }

    #[test]
    fn supported_subject_token_types_rejects_id_token() {
        // id_token is not accepted. The standards-shaped fix for
        // missing-`sub`-on-access_token is an IdP-side claim mapper;
        // see docs/operator/idp-setup.md.
        assert!(!is_supported_subject_token_type(
            "urn:ietf:params:oauth:token-type:id_token"
        ));
    }

    #[test]
    fn supported_subject_token_types_rejects_unknown() {
        assert!(!is_supported_subject_token_type(
            "urn:ietf:params:oauth:token-type:saml2"
        ));
        assert!(!is_supported_subject_token_type(""));
    }

    #[test]
    fn exchange_grant_type_is_rfc_8693_uri() {
        assert_eq!(
            EXCHANGE_GRANT_TYPE,
            "urn:ietf:params:oauth:grant-type:token-exchange"
        );
    }

    #[test]
    fn supported_subject_token_types_is_closed_set_of_two() {
        // Regression anchor — the closed enum is part of the wire
        // contract published in the discovery doc: `access_token`
        // plus `jwt` (federation branch). A future expansion (e.g.
        // SAML2) must touch this test alongside the catalog.
        assert_eq!(SUPPORTED_SUBJECT_TOKEN_TYPES.len(), 2);
        assert!(SUPPORTED_SUBJECT_TOKEN_TYPES.contains(&TOKEN_TYPE_ACCESS_TOKEN));
        assert!(SUPPORTED_SUBJECT_TOKEN_TYPES.contains(&TOKEN_TYPE_JWT));
    }
}
