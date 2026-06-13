use std::fmt;

use chrono::{DateTime, Utc};

use super::BoxFuture;

/// Outbound port: validates IdP-issued JWTs and returns the raw claims.
///
/// The port answers a single question — "is this token cryptographically
/// valid and what claims did it carry?". It does **not** perform JIT user
/// provisioning, role resolution, or principal construction — those live
/// in `hort-app::use_cases::AuthenticateUseCase`,
/// which orchestrates this port alongside `UserRepository` + `RbacEvaluator`.
///
/// Implementations are expected to be stateless across requests beyond any
/// internal caching they choose (e.g. JWKS caching in the OIDC adapter).
///
/// # Algorithm-rejection contract
///
/// Implementations MUST reject HMAC-family (`HS*`) and `none` algorithms
/// during construction. A second adapter that fails to enforce this is a
/// security regression. The contract is not enforced at the trait level
/// (the trait does not expose the algorithm list); each adapter MUST
/// carry an equivalent constructor-level test that drives the public
/// constructor and asserts an `HS*` / `none`-signed token is rejected
/// before signature verification.
///
/// Reference implementation: see `crates/hort-adapters-oidc/src/lib.rs`
/// (the `PRODUCTION_ALGORITHMS` allow-list and the constructor's
/// algorithm-validation gate at the head of `validate_token_impl`). The
/// matching regression tests are
/// `oidc_adapter_must_reject_hs256` and `oidc_adapter_must_reject_none`
/// in the same file's inline test module.
pub trait IdentityProvider: Send + Sync {
    /// Validate a bearer token and extract its claims.
    ///
    /// Returns a typed [`OidcValidationError`] on failure — callers
    /// (notably the auth middleware's `hort_auth_attempts_total{result}`
    /// classifier) pattern-match on the variant instead of substring-
    /// matching a message. Integrity failures (signature, issuer,
    /// audience, expiry) and claim-shape failures (missing `sub`, etc.)
    /// are all carried as variants of the same enum so consumers never
    /// need to inspect an error string to decide what happened.
    fn validate_token(&self, token: &str) -> BoxFuture<'_, Result<IdpClaims, OidcValidationError>>;
}

/// Structured validation error returned by the [`IdentityProvider`] port.
///
/// Every failure path of `validate_token` maps to exactly one of these
/// variants. The set is closed — callers exhaustively match, and the
/// enum is deliberately NOT `non_exhaustive` (every consumer lives in
/// this workspace, per the port-contract policy).
///
/// Mapping guidance for adapters:
/// - [`Self::Expired`] — token's `exp` is in the past (beyond leeway).
/// - [`Self::UnknownIssuer`] — `iss` claim does not match the configured
///   issuer.
/// - [`Self::Malformed`] — header / payload failed to parse, disallowed
///   algorithm, missing `kid`, or any other token-shape rejection that
///   happens before signature verification.
/// - [`Self::SignatureInvalid`] — signature verification failed against
///   a JWK we successfully retrieved, the JWK was unusable, or the
///   signing key could not be located in a freshly-fetched JWKS. The
///   token is **forged or stale** — caller-side problem.
/// - [`Self::AudienceMismatch`] — the token's `aud` claim does not
///   include the configured audience. The signature is valid but the
///   token was minted for a different relying party. Held distinct
///   from [`Self::SignatureInvalid`] so the structured log line names
///   the actual cause (the historic "signature invalid" log message
///   for an audience-mismatch error misled operators into checking
///   key rotation when the real fix was a Keycloak audience mapper).
/// - [`Self::IdpUnavailable`] — the adapter could not reach / parse the
///   IdP's JWKS or discovery document (transport failure, non-2xx
///   response, oversize body, malformed JSON). The token may well be
///   genuine; we simply cannot verify it on this server right now —
///   **operator-actionable** failure (IdP outage, misconfiguration,
///   network partition). Distinguished from `SignatureInvalid` so
///   metrics / logs let SOC operators tell a credential-stuffing
///   campaign apart from an IdP outage.
/// - [`Self::ClaimMissing(name)`] — a claim required by the IdP contract
///   (`sub`, `email`, `iat`, `aud` when declared required, ...) was
///   absent or unparseable. `name` carries the offending claim name so
///   operators can diagnose misconfigured IdP clients without needing
///   the adapter's internal log lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OidcValidationError {
    /// Token's `exp` is in the past (beyond the configured leeway).
    Expired,
    /// Token's `iss` claim does not match the configured issuer.
    UnknownIssuer,
    /// Token header/payload failed to parse, algorithm disallowed, or
    /// any pre-signature shape rejection.
    Malformed,
    /// Signature verification failed against a JWK we successfully
    /// retrieved (or no key matched in a freshly-fetched JWKS). The
    /// token is not cryptographically trustworthy on this server —
    /// caller-side problem.
    SignatureInvalid,
    /// The token's `aud` claim does not include the configured
    /// audience. Signature is valid; the token was minted for a
    /// different relying party. Distinct from [`Self::SignatureInvalid`]
    /// so structured logs name the real cause (audience-mapper
    /// misconfiguration on the IdP side, typically) rather than
    /// hinting at key rotation.
    AudienceMismatch,
    /// The JWKS / discovery fetch itself
    /// failed: transport error, non-2xx upstream status, oversize
    /// response body, or malformed JSON. We cannot verify the token's
    /// signature for an operator-controlled reason. Held distinct from
    /// [`Self::SignatureInvalid`] so the auth metric label
    /// (`result="idp_unavailable"`) and tracing span give SOC tooling a
    /// way to distinguish an IdP outage from a credential-stuffing
    /// campaign.
    IdpUnavailable,
    /// A required claim (e.g. `sub`, `email`, `iat`) was absent or
    /// unparseable. Payload is the claim name.
    ClaimMissing(String),
}

impl fmt::Display for OidcValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expired => f.write_str("token expired"),
            Self::UnknownIssuer => f.write_str("unknown issuer"),
            Self::Malformed => f.write_str("token malformed"),
            Self::SignatureInvalid => f.write_str("signature invalid"),
            Self::AudienceMismatch => f.write_str("audience mismatch"),
            Self::IdpUnavailable => f.write_str("idp unavailable"),
            Self::ClaimMissing(name) => write!(f, "missing claim: {name}"),
        }
    }
}

impl std::error::Error for OidcValidationError {}

/// Claims extracted from a validated IdP token.
///
/// Neutral of any specific IdP vendor — the adapter is responsible for
/// mapping vendor-specific claim names (`groups` vs `realm_access.roles`
/// vs `cognito:groups`) into this common shape. The vendor-specific
/// deserialisation happens inside the adapter on a private struct; this
/// type is what crosses the port boundary.
///
/// # Intentionally NOT `Deserialize`
///
/// `IdpClaims` represents a **validated** claim bundle, constructed only
/// after signature, issuer, and audience checks pass. Deriving
/// `Deserialize` would make it constructible from arbitrary request input,
/// defeating the point of having a dedicated "post-validation" type
/// distinct from the adapter's wire struct. The adapter internally
/// deserialises the JWT payload into its own private struct, then maps to
/// `IdpClaims` after validation — different layer, different contract.
#[derive(Debug, Clone, PartialEq)]
pub struct IdpClaims {
    /// `sub` claim — stable IdP user identifier. Opaque to everyone
    /// except the adapter that issued it.
    pub subject: String,
    /// `preferred_username` claim (or an equivalent chosen by the adapter).
    pub username: String,
    /// `email` claim.
    pub email: String,
    /// Groups as they arrived in the claim — NOT resolved role names.
    /// Role resolution happens in `hort-app` via `GroupMapping` evaluation.
    /// The claim name is adapter-configurable (default `groups`).
    pub groups: Vec<String>,
    /// `iat` claim, converted from the JWT's NumericDate representation.
    pub issued_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that `IdentityProvider` is dyn-compatible.
    #[test]
    fn port_is_dyn_compatible() {
        // Compile-time: resolves only if the trait is dyn-compatible.
        // Runtime: size_of call executes in the test body for coverage.
        let _ = size_of::<&dyn IdentityProvider>();
    }

    #[test]
    fn idp_claims_construction_and_clone() {
        let now = Utc::now();
        let claims = IdpClaims {
            subject: "keycloak:realm-users:abc-123".into(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            groups: vec!["team-alpha".into(), "hort-admins".into()],
            issued_at: now,
        };
        let cloned = claims.clone();
        assert_eq!(claims, cloned);
        assert_eq!(claims.groups.len(), 2);
    }

    #[test]
    fn oidc_validation_error_display_expired() {
        assert_eq!(OidcValidationError::Expired.to_string(), "token expired");
    }

    #[test]
    fn oidc_validation_error_display_unknown_issuer() {
        assert_eq!(
            OidcValidationError::UnknownIssuer.to_string(),
            "unknown issuer"
        );
    }

    #[test]
    fn oidc_validation_error_display_malformed() {
        assert_eq!(
            OidcValidationError::Malformed.to_string(),
            "token malformed"
        );
    }

    #[test]
    fn oidc_validation_error_display_signature_invalid() {
        assert_eq!(
            OidcValidationError::SignatureInvalid.to_string(),
            "signature invalid"
        );
    }

    #[test]
    fn oidc_validation_error_display_claim_missing_carries_name() {
        let err = OidcValidationError::ClaimMissing("sub".into());
        assert_eq!(err.to_string(), "missing claim: sub");
    }

    #[test]
    fn oidc_validation_error_display_audience_mismatch() {
        // The Display string is what the structured log line carries
        // for `oidc_error = ?variant` in the exchange + auth-middleware
        // paths; operators grep for it to spot Keycloak audience-mapper
        // misconfigurations. Pin it.
        assert_eq!(
            OidcValidationError::AudienceMismatch.to_string(),
            "audience mismatch"
        );
    }

    #[test]
    fn oidc_validation_error_audience_mismatch_distinct_from_signature_invalid() {
        // The whole point of carving this variant out of SignatureInvalid
        // is observability: callers must be able to
        // tell them apart. Lock the inequality so a future "simplifying"
        // refactor that re-collapses them fails this test.
        let err = OidcValidationError::AudienceMismatch;
        assert_eq!(err, err.clone());
        assert_ne!(err, OidcValidationError::SignatureInvalid);
        assert_ne!(err, OidcValidationError::UnknownIssuer);
    }

    #[test]
    fn oidc_validation_error_display_idp_unavailable() {
        // `IdpUnavailable` distinguishes
        // transport / oversize-body / parse failures (operator-actionable
        // IdP outage) from a genuine forged-signature reject. The Display
        // impl must be deterministic and stable so log-grep operators
        // can pivot on it.
        assert_eq!(
            OidcValidationError::IdpUnavailable.to_string(),
            "idp unavailable"
        );
    }

    #[test]
    fn oidc_validation_error_idp_unavailable_clone_eq() {
        // The new variant must round-trip through Clone + Eq alongside
        // the existing variants — every consumer pattern-matches the
        // closed enum, so identity / equality semantics need to match.
        let err = OidcValidationError::IdpUnavailable;
        assert_eq!(err, err.clone());
        assert_ne!(err, OidcValidationError::SignatureInvalid);
    }

    #[test]
    fn oidc_validation_error_clone_and_eq() {
        let err = OidcValidationError::ClaimMissing("email".into());
        assert_eq!(err, err.clone());
        assert_ne!(err, OidcValidationError::ClaimMissing("sub".into()));
        assert_ne!(OidcValidationError::Expired, OidcValidationError::Malformed);
    }

    #[test]
    fn oidc_validation_error_is_std_error() {
        // Guarantees downstream crates can box it / pass it through
        // `?` across layers that expect `Box<dyn Error>`.
        fn assert_is_error<E: std::error::Error>(_: &E) {}
        assert_is_error(&OidcValidationError::Expired);
    }
}
