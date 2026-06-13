//! Outbound port for foreign-JWT validation against trusted
//! [`OidcIssuer`](crate::entities::oidc_issuer::OidcIssuer) rows
//! (ADR 0018).
//!
//! The federation branch of `/auth/token-exchange`
//! receives a JWT in `subject_token` with `subject_token_type =
//! "urn:ietf:params:oauth:token-type:jwt"`. It calls
//! [`FederatedJwtValidator::validate`] which:
//!
//! 1. Decodes the JWT header + payload (no signature trust).
//! 2. Resolves the `iss` claim to a trusted `OidcIssuer` row.
//! 3. Gates the JWT header `alg` against
//!    `OidcIssuer.allowed_algorithms`.
//! 4. Refreshes the per-issuer JWKS cache when stale.
//! 5. Verifies the signature and the standard claims (`aud`, `exp`,
//!    `nbf`, `iat`).
//!
//! Steps 1–5 are the validator's job and produce
//! [`ValidatedClaims`] on success or a [`FederationDenyReason`]
//! variant on failure. **Service-account matching
//! is NOT this port's responsibility** — the
//! federation handler walks
//! `ServiceAccount.federated_identities[].claims` against
//! [`ValidatedClaims::all_claims`] after this port returns. The two
//! deny reasons `no_sa_match` and `multiple_sa_match` therefore live
//! on the handler, not in [`FederationDenyReason`].
//!
//! # Layering
//!
//! - Port trait lives in `hort-domain` (zero I/O). The trait method
//!   returns [`Result<ValidatedClaims, FederationDenyReason>`] —
//!   typed both ways; no string error inspection at the call site.
//! - Adapter implementation lives in `hort-adapters-oidc`,
//!   sharing the shared JWKS-fetch internals (body cap,
//!   redirect cap, TLS-pin, per-kid eviction backoff) so the
//!   security-critical fetch path is not duplicated.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

use super::BoxFuture;

// ---------------------------------------------------------------------------
// ValidatedClaims
// ---------------------------------------------------------------------------

/// Validated foreign-JWT claims, returned by
/// [`FederatedJwtValidator::validate`] on the green path.
///
/// The struct intentionally **does NOT** implement `Deserialize` /
/// `Serialize`: it is internal-only. The federation handler
/// consumes the fields directly; nothing crosses the HTTP
/// boundary as a deserialised `ValidatedClaims`.
///
/// Field notes:
///
/// - `issuer` — canonical `iss` claim value (matches the
///   `OidcIssuer.issuer_url` that was looked up).
/// - `issuer_name` — the resolved `OidcIssuer.name`. Item 5 uses this
///   to match `ServiceAccount.federated_identities[].issuer_name`
///   AND to surface in the audit log without exposing the URL form.
/// - `subject` — the validated `sub` claim.
/// - `audience` — the matched audience (one of
///   `OidcIssuer.audiences`); a JWT carrying a multi-aud array is
///   accepted iff at least one entry matches an `OidcIssuer.audiences`
///   entry; the matched value is captured here for audit.
/// - `jti` — optional JWT ID for audit logging
///   (`TokenIssued.source_jti`). Foreign IdPs are inconsistent about
///   whether they emit `jti`; absence is not a deny condition.
/// - `expires_at` — `exp` claim as a `DateTime<Utc>`. Item 5 uses this
///   to cap the minted bearer's validity at `min(1h, jwt.exp - now)`.
/// - `iat` — raw `iat` claim (RFC 7519 §4.1.6) as NumericDate seconds,
///   when present. The
///   `ReplayKey::Composite` fallback needs the *raw* `iat`/`exp` wire
///   values (byte-stable across replays of the same token), so the
///   validator surfaces them additively rather than the use case
///   re-parsing the JWT. `None` when the JWT carried no `iat` (the
///   composite key is then not constructible — see §5 behaviour
///   matrix).
/// - `exp_raw` — raw `exp` claim as NumericDate seconds. Always present
///   (the validator already enforced `exp`); kept alongside the typed
///   `expires_at` so the composite key is byte-stable without
///   round-tripping through `DateTime`.
/// - `all_claims` — the raw decoded payload as a `BTreeMap` (ordered
///   key iteration is needed for deterministic audit hashing). Item 5
///   walks `ServiceAccount.federated_identities[].claims` against
///   this map for exact-match SA resolution. The map carries
///   `serde_json::Value` so nested objects and arrays survive the
///   round trip from the JWT payload.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedClaims {
    pub issuer: String,
    pub issuer_name: String,
    pub subject: String,
    pub audience: String,
    pub jti: Option<String>,
    pub expires_at: DateTime<Utc>,
    /// Raw `iat` NumericDate seconds (RFC 7519 §4.1.6), `None` if the
    /// JWT omitted it. Feeds
    /// `ReplayKey::Composite`.
    pub iat: Option<i64>,
    /// Raw `exp` NumericDate seconds (RFC 7519 §4.1.4). Always present
    /// — the validator enforced `exp` before constructing this struct.
    /// Feeds
    /// `ReplayKey::Composite`.
    pub exp_raw: i64,
    pub all_claims: BTreeMap<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// FederationDenyReason
// ---------------------------------------------------------------------------

/// Deny taxonomy for federation-branch JWT validation, mapping 1:1 to
/// the design-doc §4 deny-log catalogue.
///
/// The federation handler maps each variant to:
/// - one `hort_token_exchange_total{kind=federated_jwt, result=...}`
///   label value,
/// - one static deny-hint string in the `WWW-Authenticate` /
///   error body (the standard deny-hint pattern), and
/// - the `reason = ...` field in the structured `info!` deny log.
///
/// The two service-account-matching variants —
/// `no_sa_match` and `multiple_sa_match` — are **deliberately
/// absent**: SA resolution happens in the federation handler AFTER
/// claims have been validated, and the two responsibilities should
/// not be conflated. This enum is the validator's contract; SA-match
/// failures belong on the handler's wider deny enum.
///
/// Variants are ordered to match the §4 flow chart (top to bottom).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederationDenyReason {
    /// Step 1: the JWT cannot be parsed (bad base64, missing header
    /// fields, malformed payload JSON, missing `kid`, etc.). The
    /// validator never reached issuer lookup.
    InvalidFormat,
    /// Step 2: `iss` claim did not resolve to any trusted
    /// [`OidcIssuer`](crate::entities::oidc_issuer::OidcIssuer) row.
    UnknownIssuer,
    /// Step 3: JWT header `alg` is not in
    /// `OidcIssuer.allowed_algorithms`. The signature is never
    /// verified — the gate is enforced before any cryptographic work.
    AlgorithmNotAllowed,
    /// Step 4: the JWT `kid` is not present in the issuer's JWKS
    /// after a refresh attempt. Distinct from `SignatureInvalid` —
    /// "no key by this name" is operator-actionable (rotate / fix
    /// IdP config); "wrong signature" is forgery / credential
    /// stuffing.
    UnknownKid,
    /// Step 5: signature verification failed against the resolved
    /// JWK. Could be forgery, a stale key on the relying side, or a
    /// key-rotation race; the wire response is the same.
    SignatureInvalid,
    /// Step 6: `aud` claim does not intersect
    /// `OidcIssuer.audiences`.
    AudMismatch,
    /// Step 6: `exp` is in the past (with the configured leeway).
    Expired,
    /// Step 6: `nbf` is in the future (with the configured leeway).
    NotYetValid,
}

impl FederationDenyReason {
    /// Wire-form string for the `result` label of
    /// `hort_token_exchange_total{kind=federated_jwt}` and the
    /// `reason = ...` deny-log field. Normative — see design doc §7.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidFormat => "invalid_format",
            Self::UnknownIssuer => "unknown_issuer",
            Self::AlgorithmNotAllowed => "algorithm_not_allowed",
            Self::UnknownKid => "unknown_kid",
            Self::SignatureInvalid => "signature_invalid",
            Self::AudMismatch => "aud_mismatch",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
        }
    }
}

// ---------------------------------------------------------------------------
// Port trait
// ---------------------------------------------------------------------------

/// Multi-issuer JWT validator port.
///
/// Resolves the JWT's `iss` to a trusted issuer internally — the
/// caller does NOT pre-select. Returns [`ValidatedClaims`] on success
/// or a [`FederationDenyReason`] classifying the failure.
///
/// Implementations live in `hort-adapters-oidc::multi_issuer` and read
/// trusted-issuer rows via
/// [`OidcIssuerRepository`](crate::ports::oidc_issuer_repository::OidcIssuerRepository).
pub trait FederatedJwtValidator: Send + Sync {
    /// Validate a foreign JWT.
    ///
    /// `jwt` is the raw compact-serialisation token from the
    /// `subject_token` form field. The implementation owns issuer
    /// resolution, JWKS caching, signature verification, and
    /// standard-claim checks.
    fn validate<'a>(
        &'a self,
        jwt: &'a str,
    ) -> BoxFuture<'a, Result<ValidatedClaims, FederationDenyReason>>;

    /// Apply-time JWKS warm-up.
    ///
    /// Best-effort: fetch the JWKS for `issuer` and populate the
    /// implementation's per-issuer cache, so the first federation
    /// `validate()` call against this issuer does NOT pay the
    /// discovery + JWKS round-trip cost. The apply pipeline calls this
    /// after persisting a new or updated `OidcIssuer` row and
    /// surfaces failures via `tracing::warn!` +
    /// `hort_jwks_refresh_total{result="apply_warmup_failed"}` —
    /// **a failure here MUST NOT fail the apply** (federation will
    /// fetch lazily on first request).
    ///
    /// Failures are reported as [`FederationDenyReason`] variants for
    /// taxonomy unity with the validate path: `UnknownKid` for
    /// fetch / body-cap / parse failures (the same mapping
    /// [`MultiIssuerJwksValidator::fetch_jwks`] already uses for these
    /// classes of failure). Calling sites should treat every
    /// non-`Ok` return as warm-up-failed for metric purposes; the
    /// specific variant exists only to keep the type signature unified.
    ///
    /// [`MultiIssuerJwksValidator::fetch_jwks`]: ../../../hort_adapters_oidc/struct.MultiIssuerJwksValidator.html
    fn refresh_issuer<'a>(
        &'a self,
        issuer: &'a crate::entities::oidc_issuer::OidcIssuer,
    ) -> BoxFuture<'a, Result<(), FederationDenyReason>>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_reason_as_str_covers_every_variant() {
        // The wire-form string is part of the public metrics +
        // deny-log contract (design doc §7). Each variant must map
        // to a fixed string.
        assert_eq!(
            FederationDenyReason::InvalidFormat.as_str(),
            "invalid_format"
        );
        assert_eq!(
            FederationDenyReason::UnknownIssuer.as_str(),
            "unknown_issuer"
        );
        assert_eq!(
            FederationDenyReason::AlgorithmNotAllowed.as_str(),
            "algorithm_not_allowed"
        );
        assert_eq!(FederationDenyReason::UnknownKid.as_str(), "unknown_kid");
        assert_eq!(
            FederationDenyReason::SignatureInvalid.as_str(),
            "signature_invalid"
        );
        assert_eq!(FederationDenyReason::AudMismatch.as_str(), "aud_mismatch");
        assert_eq!(FederationDenyReason::Expired.as_str(), "expired");
        assert_eq!(FederationDenyReason::NotYetValid.as_str(), "not_yet_valid");
    }

    #[test]
    fn deny_reason_wire_strings_are_unique() {
        use std::collections::HashSet;
        let variants = [
            FederationDenyReason::InvalidFormat,
            FederationDenyReason::UnknownIssuer,
            FederationDenyReason::AlgorithmNotAllowed,
            FederationDenyReason::UnknownKid,
            FederationDenyReason::SignatureInvalid,
            FederationDenyReason::AudMismatch,
            FederationDenyReason::Expired,
            FederationDenyReason::NotYetValid,
        ];
        let set: HashSet<_> = variants.iter().map(FederationDenyReason::as_str).collect();
        assert_eq!(set.len(), variants.len());
    }

    /// Compile-time invariant: the port trait must remain dyn-compatible.
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn FederatedJwtValidator>();
    }

    // Compile-time guard mirroring the
    // rule: validated-trust types must not be deserialisable from
    // untrusted input. `ValidatedClaims` carries the SA-resolution-
    // time decision data; an attacker reconstructing it from JSON
    // bypasses the validator. `static_assertions` lives in
    // `hort-domain`'s dev-deps already (used by `entities/api_token.rs`
    // and the SA entities), so the assertion is callable here.
    static_assertions::assert_not_impl_any!(ValidatedClaims: serde::de::DeserializeOwned);

    // `FederationDenyReason` carries the deny-classification produced
    // by the validator. It is metric-label data only, never round-
    // tripped via untrusted input — same no-`Deserialize` lock as
    // `ValidatedClaims`.
    static_assertions::assert_not_impl_any!(FederationDenyReason: serde::de::DeserializeOwned);

    /// Construction smoke: the struct has no `Deserialize` derive (the
    /// only construction path is the validator's
    /// [`FederatedJwtValidator::validate`] return), and `Clone` /
    /// `Debug` work for the audit-log shape consumers expect.
    #[test]
    fn validated_claims_clone_and_debug_round_trip() {
        let claims = ValidatedClaims {
            issuer: "https://idp.example/realms/test".into(),
            issuer_name: "test-idp".into(),
            subject: "sub-1".into(),
            audience: "hort-server".into(),
            jti: Some("jti-1".into()),
            expires_at: DateTime::<Utc>::from_timestamp(2_000_000_000, 0).unwrap(),
            iat: Some(1_999_999_000),
            exp_raw: 2_000_000_000,
            all_claims: BTreeMap::new(),
        };
        let cloned = claims.clone();
        assert_eq!(claims, cloned);
        assert!(!format!("{claims:?}").is_empty());
    }

    /// The additive raw `iat`/`exp_raw`
    /// fields are independent of the typed `expires_at` and survive
    /// the clone the federation handler relies on. `iat = None` is a
    /// representable shape (JWT omitted `iat`) distinct from
    /// `Some(0)`.
    #[test]
    fn validated_claims_raw_iat_exp_are_additive_and_independent() {
        let with_iat = ValidatedClaims {
            issuer: "https://idp.example".into(),
            issuer_name: "idp".into(),
            subject: "s".into(),
            audience: "a".into(),
            jti: None,
            expires_at: DateTime::<Utc>::from_timestamp(1_700_003_600, 0).unwrap(),
            iat: Some(1_700_000_000),
            exp_raw: 1_700_003_600,
            all_claims: BTreeMap::new(),
        };
        assert_eq!(with_iat.iat, Some(1_700_000_000));
        assert_eq!(with_iat.exp_raw, 1_700_003_600);

        let without_iat = ValidatedClaims {
            iat: None,
            ..with_iat.clone()
        };
        assert_ne!(with_iat, without_iat);
        assert_eq!(without_iat.iat, None);
        // exp_raw is decoupled from the typed expires_at conversion.
        assert_eq!(
            without_iat.exp_raw,
            without_iat.expires_at.timestamp(),
            "exp_raw and expires_at describe the same instant here, but \
             exp_raw is the wire value the composite key must pin"
        );
    }
}
