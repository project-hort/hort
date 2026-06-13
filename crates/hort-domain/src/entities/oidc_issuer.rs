//! OIDC-issuer trust entity (ADR 0018 + `docs/auth-catalog.md`).
//!
//! Declares an external OIDC issuer that hort-server federates with for
//! **workload** identity (k8s ServiceAccount JWTs, GitHub Actions OIDC,
//! GitLab CI OIDC, Keycloak service-account clients). One row per
//! trusted issuer; the row drives JWKS fetch, signature verification,
//! and audience/algorithm gating on the federation branch of
//! `/auth/token-exchange`.
//!
//! # Invariants
//!
//! - **No `Deserialize` impl.** Same anti-pattern rule that gates
//!   [`ApiToken`](super::api_token::ApiToken) — an attacker that can
//!   deserialise an `OidcIssuer` from request input can hand-roll a
//!   trust relationship with an arbitrary `issuer_url` / `audiences`
//!   set. The persisted-domain row is constructed by the
//!   `hort-adapters-postgres` row mapper and the `ApplyConfigUseCase`
//!   path; it never crosses the API boundary as a deserialised value.
//! - **No `Serialize` impl either.** Mirrors the
//!   [`ApiToken`](super::api_token::ApiToken) precedent. HTTP layers
//!   project to a handler-specific response DTO when surfacing issuer
//!   metadata; the wholesale row is internal-only. Tracing spans attach
//!   the `issuer_name` field directly.
//! - **No I/O imports.** `hort-domain` is pure Rust, zero I/O — the file
//!   imports only `chrono`, `uuid`, `std::time::Duration` and the
//!   sibling `serde`-derived event payload module.
//!
//! # Why CRUD, not event-sourced
//!
//! Issuer trust is repository-config-shaped, not artifact-lifecycle-shaped,
//! so the aggregate is CRUD (ADR 0002 scopes event sourcing to the
//! artifact lifecycle). Lifecycle events
//! ([`OidcIssuerCreated`](crate::events::OidcIssuerCreated) /
//! [`OidcIssuerUpdated`](crate::events::OidcIssuerUpdated) /
//! [`OidcIssuerDeleted`](crate::events::OidcIssuerDeleted)) are emitted
//! by the apply use case for audit attribution, but the canonical state
//! lives in the `oidc_issuers` table — projections do not reconstruct
//! it from the event stream.

use std::str::FromStr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::DomainError;

// ---------------------------------------------------------------------------
// JwtAlg
// ---------------------------------------------------------------------------

/// The set of JWT signature algorithms hort-server accepts on the
/// federation branch.
///
/// Restricted to RSA-based (`RS*`) and ECDSA-based (`ES*`) algorithms
/// per RFC 7518 §3.1. Symmetric (`HS*`) algorithms are intentionally
/// excluded — federation uses the issuer's published JWKS, which only
/// makes sense for asymmetric keys.
///
/// `Copy + Eq + Hash` are derived so the validator can build a
/// `HashSet<JwtAlg>` from
/// [`OidcIssuer::allowed_algorithms`] for O(1) membership checks at
/// verify time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JwtAlg {
    Rs256,
    Rs384,
    Rs512,
    Es256,
    Es384,
    Es512,
}

impl JwtAlg {
    /// RFC 7518 wire form — used by the federation-branch handler and
    /// by the row mapper.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Rs384 => "RS384",
            Self::Rs512 => "RS512",
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::Es512 => "ES512",
        }
    }
}

/// Parse RFC 7518 wire form into [`JwtAlg`].
///
/// Used by the Postgres row mapper to convert
/// `oidc_issuers.allowed_algorithms TEXT[]` into the typed enum.
/// Unknown literals surface as [`DomainError::Validation`]; the row
/// mapper translates that to [`DomainError::Invariant`] because the
/// apply-time validator gates writes to the supported set — only
/// out-of-band SQL can land an unknown algorithm in the column.
impl FromStr for JwtAlg {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "RS256" => Ok(Self::Rs256),
            "RS384" => Ok(Self::Rs384),
            "RS512" => Ok(Self::Rs512),
            "ES256" => Ok(Self::Es256),
            "ES384" => Ok(Self::Es384),
            "ES512" => Ok(Self::Es512),
            other => Err(DomainError::Validation(format!(
                "unknown JWT algorithm: {other}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// OidcIssuer
// ---------------------------------------------------------------------------

/// A trusted external OIDC issuer (ADR 0018 + `docs/auth-catalog.md`).
///
/// Constructed by:
/// - The Postgres adapter row mapper (`oidc_issuers` table → `OidcIssuer`).
/// - `ApplyConfigUseCase::apply_oidc_issuers` when processing a
///   `kind: OidcIssuer` envelope.
///
/// Field notes:
/// - `name` matches the CRD `metadata.name`. Unique per hort-server tenant.
///   `ServiceAccount.federated_identities[].issuer_name` references this.
/// - `issuer_url` is the canonical `iss` claim value the federation
///   branch matches on. Apply-time validation rejects HTTP — only
///   HTTPS is permitted.
/// - `audiences` is the set of acceptable `aud` claim values; must be
///   non-empty at apply time.
/// - `jwks_refresh_interval` caps how stale the JWKS cache may be
///   before forcing a refresh. Default 1h; the adapter layer honours
///   this on JWKS fetch.
/// - `allowed_algorithms` gates the JWT header `alg` field. Default
///   `[Rs256]`.
/// - `require_jti` — anti-replay gate. When `true` a federated JWT from
///   this issuer that carries no `jti` is rejected (`jti_required`)
///   *before* any replay claim or mint. When `false` the issuer is
///   opted into the weaker `(iss,sub,iat,exp)` composite anti-replay
///   fallback. **Default `true`** (secure-by-default; the composite is
///   an opt-in, documented, weaker fallback for IdPs that cannot emit
///   `jti`). The apply-time default is supplied by `OidcIssuerSpec`'s
///   `#[serde(default)]`; existing field-less issuer envelopes
///   therefore silently upgrade to `require_jti=true` on next apply —
///   an intentional security tightening.
#[derive(Debug, Clone, PartialEq)]
pub struct OidcIssuer {
    pub id: Uuid,
    pub name: String,
    pub issuer_url: String,
    pub audiences: Vec<String>,
    pub jwks_refresh_interval: Duration,
    pub allowed_algorithms: Vec<JwtAlg>,
    /// Anti-replay `jti` requirement. See the type docstring.
    /// Default `true`.
    pub require_jti: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- JwtAlg --------------------------------------------------------------

    #[test]
    fn jwt_alg_as_str_covers_every_variant() {
        assert_eq!(JwtAlg::Rs256.as_str(), "RS256");
        assert_eq!(JwtAlg::Rs384.as_str(), "RS384");
        assert_eq!(JwtAlg::Rs512.as_str(), "RS512");
        assert_eq!(JwtAlg::Es256.as_str(), "ES256");
        assert_eq!(JwtAlg::Es384.as_str(), "ES384");
        assert_eq!(JwtAlg::Es512.as_str(), "ES512");
    }

    #[test]
    fn jwt_alg_clone_copy_eq() {
        let a = JwtAlg::Rs256;
        let b = a;
        #[allow(clippy::clone_on_copy)]
        let c = a.clone();
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, JwtAlg::Es256);
    }

    #[test]
    fn jwt_alg_from_str_covers_every_variant() {
        for variant in [
            JwtAlg::Rs256,
            JwtAlg::Rs384,
            JwtAlg::Rs512,
            JwtAlg::Es256,
            JwtAlg::Es384,
            JwtAlg::Es512,
        ] {
            assert_eq!(JwtAlg::from_str(variant.as_str()).unwrap(), variant);
        }
    }

    #[test]
    fn jwt_alg_from_str_rejects_lowercase() {
        // RFC 7518 §3.1 wire form is uppercase. Apply-time validation
        // writes the uppercase canonical form, so the mapper need not
        // be case-insensitive.
        let err = JwtAlg::from_str("rs256").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("rs256"));
    }

    #[test]
    fn jwt_alg_from_str_rejects_hmac() {
        // HS256/HS384/HS512 are symmetric; federation uses JWKS over
        // HTTPS, which only carries asymmetric keys. The enum
        // deliberately excludes the HS* family — see the JwtAlg
        // docstring.
        for sym in ["HS256", "HS384", "HS512"] {
            let err = JwtAlg::from_str(sym).unwrap_err();
            assert!(matches!(err, DomainError::Validation(_)));
            assert!(err.to_string().contains(sym));
        }
    }

    #[test]
    fn jwt_alg_from_str_rejects_unknown() {
        let err = JwtAlg::from_str("RS999").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("RS999"));
    }

    #[test]
    fn jwt_alg_from_str_rejects_empty() {
        let err = JwtAlg::from_str("").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn jwt_alg_hash_round_trip() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(JwtAlg::Rs256);
        set.insert(JwtAlg::Es256);
        set.insert(JwtAlg::Rs256); // duplicate — set stays size 2
        assert_eq!(set.len(), 2);
        assert!(set.contains(&JwtAlg::Rs256));
        assert!(!set.contains(&JwtAlg::Rs384));
    }

    // -- OidcIssuer ----------------------------------------------------------

    fn sample_issuer() -> OidcIssuer {
        OidcIssuer {
            id: Uuid::nil(),
            name: "github-actions".into(),
            issuer_url: "https://token.actions.githubusercontent.com".into(),
            audiences: vec!["hort-server".into()],
            jwks_refresh_interval: Duration::from_secs(3600),
            allowed_algorithms: vec![JwtAlg::Rs256],
            require_jti: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn issuer_require_jti_participates_in_eq() {
        // `require_jti` is part of the trust shape;
        // flipping it must make two otherwise-identical issuers unequal
        // (the diff layer relies on the spec digest, but the entity's
        // structural equality must also reflect the knob).
        let secure = sample_issuer();
        assert!(secure.require_jti, "sample issuer defaults to secure");
        let opted_down = OidcIssuer {
            require_jti: false,
            ..sample_issuer()
        };
        assert_ne!(secure, opted_down);
    }

    #[test]
    fn issuer_clone_eq() {
        let a = sample_issuer();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn issuer_multi_audience_multi_alg_distinct_from_default() {
        let multi = OidcIssuer {
            audiences: vec!["hort-server".into(), "hort-cli".into()],
            allowed_algorithms: vec![JwtAlg::Rs256, JwtAlg::Es256],
            ..sample_issuer()
        };
        assert_ne!(sample_issuer(), multi);
        assert_eq!(multi.audiences.len(), 2);
        assert_eq!(multi.allowed_algorithms.len(), 2);
    }

    #[test]
    fn issuer_refresh_interval_preserved() {
        let four_hours = Duration::from_secs(4 * 3600);
        let issuer = OidcIssuer {
            jwks_refresh_interval: four_hours,
            ..sample_issuer()
        };
        assert_eq!(issuer.jwks_refresh_interval, four_hours);
    }

    // Compile-time invariant: `OidcIssuer` must not implement `Deserialize`.
    // See module docstring — the persisted-trust-row must never be
    // reconstructible from untrusted JSON. Mirrors the `ApiToken` guard.
    static_assertions::assert_not_impl_any!(OidcIssuer: serde::de::DeserializeOwned);
    // Same belt-and-braces on `JwtAlg` — the enum carries trust semantics
    // (which signature algorithms are accepted) and must not be
    // deserialisable from untrusted input either.
    static_assertions::assert_not_impl_any!(JwtAlg: serde::de::DeserializeOwned);
}
