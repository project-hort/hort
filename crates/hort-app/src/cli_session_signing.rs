//! Ed25519-signed CliSession access-token JWTs (ADR 0013).
//!
//! # Why a JWT
//!
//! A [`TokenKind::CliSession`](hort_domain::entities::api_token::TokenKind::CliSession)
//! must carry the human's IdP-resolved claim set. The CliSession access
//! token is therefore a short-lived Hort-signed JWT carrying the
//! resolved claims *in the token*, never in a DB column (the "no
//! `api_tokens.claims` column" hard-block stays untouched — claims are
//! IdP-authoritative, ADR 0013).
//!
//! # Shared signer, separate token family
//!
//! This module deliberately does NOT own its own keypair. It reuses the
//! existing [`crate::oci_token_signing::OciTokenSigningKey`] issuer
//! primitive. The OCI `/v2/auth` token and the
//! CliSession token therefore share the issuer + signing key — **so
//! issuer/signature alone do NOT separate them.** Separation is by:
//!
//! 1. a CliSession-specific **`aud`** ([`CLI_SESSION_AUDIENCE`]), and
//! 2. the **`token_kind = "cli_session"`** payload claim.
//!
//! [`CliSessionTokenSigner::verify`] checks BOTH. A non-CliSession
//! AK-JWT (e.g. an OCI pull token, `OciAccessClaims` with the OCI `aud`)
//! presented on the bearer path is rejected — it cannot replay against
//! the CliSession-gated discovery/prefetch endpoints.
//!
//! # Revocation tradeoff (recorded, not free)
//!
//! A signed JWT is non-revocable until expiry by construction. The
//! emergency-revocation path is **two** bounded entries on the durable
//! [`EphemeralStore`](hort_domain::ports::ephemeral_store::EphemeralStore),
//! both consulted on the validate path (`AuthenticateUseCase`) and both
//! fail-closed when the store cannot be read:
//!
//! - **`cli-session-revoked:{jti}`** — one session, self-expiring at
//!   that token's `exp`. Written by
//!   [`ApiTokenUseCase::revoke_cli_session`](crate::use_cases::api_token_use_case::ApiTokenUseCase::revoke_cli_session).
//!   Usable when the token itself is in hand, because `jti` and `exp`
//!   are readable out of it.
//! - **`cli-session-cutoff:{sub}`** — every session of one subject
//!   issued at or before the cutoff instant, self-expiring one
//!   CliSession lifetime cap later (by then no token issued before the
//!   cutoff can still be live). Written by
//!   [`ApiTokenUseCase::revoke_cli_sessions_for_user`](crate::use_cases::api_token_use_case::ApiTokenUseCase::revoke_cli_sessions_for_user).
//!   This is the one an operator can reach in the emergency the
//!   denylist exists for — "the device is gone, cut this person off" —
//!   because nothing persists a live CliSession, so there is no `jti`
//!   to look up.
//!
//! Shipping the claims-carrying JWT without the denylist would forfeit
//! registry-side immediate revocation — a security regression.
//!
//! # Public surface
//!
//! - [`CliSessionClaims`] — the JWT payload shape. `Serialize` AND
//!   `Deserialize` are derived because the JWT library round-trips the
//!   payload through JSON during sign/verify — this is a JWT payload,
//!   not a request DTO, so the "no `Deserialize` on principal types"
//!   anti-pattern does not apply (same rationale as `OciAccessClaims`).
//! - [`CliSessionTokenSigner`] — wraps the shared signer + the
//!   CliSession `aud` + the issuer string. `mint` / `verify`.
//! - [`CliSessionVerifyOutcome`] — three-way verify result so the
//!   middleware can distinguish "not ours, fall through to OIDC" from
//!   "structurally ours but rejected".

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::oci_token_signing::{OciTokenSigningKey, SigningError, VerificationError};

/// The `aud` claim every CliSession access-token JWT carries. Distinct
/// from the OCI `/v2/auth` token's `aud` (the registry hostname) so the
/// two token families sharing the signer are separated at verify time
/// (the token-family discriminator).
///
/// A URN rather than a hostname: it is an internal audience marker, not
/// a routable resource, and a URN makes the "this is the CliSession
/// family, not OCI" intent unmistakable at a glance in a decoded token.
pub const CLI_SESSION_AUDIENCE: &str = "urn:hort:cli-session";

/// The `token_kind` payload-claim value. The SECOND half of the
/// token-family discriminator (the first is [`CLI_SESSION_AUDIENCE`]). A
/// token-kind *string* lives here in the JWT payload — NOT in the
/// principal's `claims` (token-kind strings are forbidden as authz
/// claims). The validator copies it nowhere near `CallerPrincipal.claims`.
pub const CLI_SESSION_TOKEN_KIND: &str = "cli_session";

/// CliSession access-token JWT payload (ADR 0013).
///
/// Wire form: `iss`, `sub` (the resolved `user_id`), `aud`
/// ([`CLI_SESSION_AUDIENCE`]), `exp` (Unix seconds), `iat` (Unix
/// seconds — the subject-cutoff comparand), `jti` (denylist key),
/// `token_kind` ([`CLI_SESSION_TOKEN_KIND`]), and `claims` (the
/// IdP-resolved claim set — the whole point of the JWT form).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CliSessionClaims {
    /// `iss` — the issuing HORT instance.
    pub iss: String,
    /// `sub` — the resolved `user_id`.
    pub sub: Uuid,
    /// `aud` — always [`CLI_SESSION_AUDIENCE`] for a CliSession token.
    pub aud: String,
    /// `exp` — expiry (Unix seconds on the wire; `DateTime<Utc>` in
    /// memory via `exp_serde`).
    #[serde(with = "exp_serde")]
    pub exp: DateTime<Utc>,
    /// `iat` — issued-at (Unix seconds on the wire; `DateTime<Utc>` in
    /// memory via `iat_serde`). Set by
    /// [`CliSessionTokenSigner::mint`]; the comparand the
    /// subject-scoped revocation cutoff
    /// (`cli-session-cutoff:{sub}`) is evaluated against on the
    /// validate path.
    ///
    /// **`Option` on purpose, and it is the rollout story.** A token
    /// minted before this field existed carries no `iat` at all, and
    /// the field is absent rather than malformed — a non-`Option`
    /// field would 401 every in-flight session the moment the new
    /// binary starts serving. `None` therefore parses, and the
    /// validate path denies it *only* while a cutoff for its subject
    /// is active: such a token cannot prove it postdates the cutoff,
    /// so admitting it would make the cutoff a no-op against exactly
    /// the sessions it was raised to kill. Because every CliSession
    /// token expires within the ≤15 min cap, no `iat`-less token
    /// survives one cap-length past the upgrade.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "iat_serde")]
    pub iat: Option<DateTime<Utc>>,
    /// `jti` — unique token id; the key the emergency-revocation
    /// denylist is built on.
    pub jti: Uuid,
    /// `token_kind` — always [`CLI_SESSION_TOKEN_KIND`]; the payload
    /// half of the token-family discriminator.
    pub token_kind: String,
    /// The IdP-resolved claim set (`claim_mappings` + synthetic `admin`)
    /// the human carried at login. This is what `RbacEvaluator` reads to
    /// authorize a `GrantSubject::Claims` grant.
    pub claims: Vec<String>,
}

/// `exp` claim serde — Unix-epoch seconds on the wire, `DateTime<Utc>`
/// in memory. Identical contract to the OCI module's `exp_serde`; kept
/// local to avoid a cross-module re-export of a private serde helper.
mod exp_serde {
    use chrono::{DateTime, TimeZone, Utc};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(dt: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
        dt.timestamp().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
        let secs = i64::deserialize(d)?;
        Utc.timestamp_opt(secs, 0)
            .single()
            .ok_or_else(|| serde::de::Error::custom("exp out of range"))
    }
}

/// `iat` claim serde — Unix-epoch seconds on the wire,
/// `Option<DateTime<Utc>>` in memory. Separate from
/// [`exp_serde`](mod@exp_serde) because the field is optional: a token
/// minted before `iat` existed omits it, and `#[serde(default)]`
/// resolves that absence to `None` without reaching this module's
/// `deserialize`. A present-but-unrepresentable value is an error, not
/// a silent `None` — an `iat` the registry cannot place on the
/// timeline must not read as "this token carries no issued-at", which
/// is the state the cutoff treats as unprovable.
mod iat_serde {
    use chrono::{DateTime, TimeZone, Utc};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(dt: &Option<DateTime<Utc>>, s: S) -> Result<S::Ok, S::Error> {
        dt.map(|d| d.timestamp()).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<DateTime<Utc>>, D::Error> {
        let Some(secs) = Option::<i64>::deserialize(d)? else {
            return Ok(None);
        };
        Utc.timestamp_opt(secs, 0)
            .single()
            .map(Some)
            .ok_or_else(|| serde::de::Error::custom("iat out of range"))
    }
}

/// Signer/verifier for CliSession access-token JWTs. Wraps the shared
/// [`OciTokenSigningKey`] (one issuer primitive, two token
/// families separated by `aud` + `token_kind`).
pub struct CliSessionTokenSigner {
    signing_key: Arc<OciTokenSigningKey>,
    /// The `iss` value embedded on mint. Convention: the registry's
    /// public base URL or a stable issuer identifier.
    issuer: String,
}

impl std::fmt::Debug for CliSessionTokenSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CliSessionTokenSigner")
            .field("signing_key", &self.signing_key)
            .field("issuer", &self.issuer)
            .finish()
    }
}

impl CliSessionTokenSigner {
    /// Build from the shared signer + the `iss` string.
    pub fn new(signing_key: Arc<OciTokenSigningKey>, issuer: String) -> Self {
        Self {
            signing_key,
            issuer,
        }
    }

    /// Mint a CliSession access-token JWT for `sub` carrying `claims`,
    /// expiring at `exp`, identified by `jti`. The `aud`,
    /// `token_kind` and `iat` fields are set here so callers cannot
    /// forget them.
    ///
    /// `iat` is the mint instant, truncated to whole seconds by the
    /// wire form. It is not a caller parameter precisely because the
    /// subject-scoped revocation cutoff compares against it: a mint
    /// path that could choose its own issued-at could mint a token
    /// that outlives a cutoff already raised against its subject.
    pub fn mint(
        &self,
        sub: Uuid,
        claims: Vec<String>,
        jti: Uuid,
        exp: DateTime<Utc>,
    ) -> Result<String, SigningError> {
        let payload = CliSessionClaims {
            iss: self.issuer.clone(),
            sub,
            aud: CLI_SESSION_AUDIENCE.to_string(),
            exp,
            iat: Some(Utc::now()),
            jti,
            token_kind: CLI_SESSION_TOKEN_KIND.to_string(),
            claims,
        };
        self.signing_key.mint_claims(&payload)
    }

    /// Verify a bearer token as a CliSession access-token JWT.
    ///
    /// Returns:
    /// - [`CliSessionVerifyOutcome::Verified`] — signature OK, `aud` =
    ///   [`CLI_SESSION_AUDIENCE`], `exp` not past, AND `token_kind` =
    ///   [`CLI_SESSION_TOKEN_KIND`]. The caller proceeds to the jti
    ///   denylist check + principal build.
    /// - [`CliSessionVerifyOutcome::NotOurToken`] — not a
    ///   CliSession-family AK-JWT: bad/missing signature, structurally
    ///   not a JWT, OR a structurally-ours AK-JWT whose `aud` is NOT the
    ///   CliSession audience (e.g. an OCI `/v2/auth` token). The caller
    ///   falls through to the OIDC validator. **This is the token-family
    ///   discriminator: an OCI token lands here, NOT in `Verified`.**
    /// - [`CliSessionVerifyOutcome::Rejected`] — a token that DID match
    ///   the CliSession `aud` (so it is structurally ours) but is
    ///   otherwise invalid: expired, or a malformed/forged CliSession
    ///   payload. The caller must reject (401), NOT fall through.
    pub fn verify(&self, jwt: &str) -> CliSessionVerifyOutcome {
        match self
            .signing_key
            .verify_claims::<CliSessionClaims>(jwt, CLI_SESSION_AUDIENCE)
        {
            Ok(claims) => {
                // Signature + aud + exp all passed. The `aud` gate
                // already excluded OCI tokens (their `aud` is the
                // registry host, not CLI_SESSION_AUDIENCE). The
                // `token_kind` check is belt-and-suspenders against a
                // future AK-JWT family that reuses the CliSession `aud`.
                if claims.token_kind != CLI_SESSION_TOKEN_KIND {
                    return CliSessionVerifyOutcome::Rejected(CliSessionRejection::WrongTokenKind);
                }
                CliSessionVerifyOutcome::Verified(Box::new(claims))
            }
            // Wrong audience ⇒ NOT a CliSession token. An OCI `/v2/auth`
            // token (aud = registry host) lands here — the token-family
            // discriminator. The caller falls through to OIDC; the OIDC
            // validator then rejects it (malformed) → 401, so an OCI
            // token never reaches the CliSession-gated surfaces.
            Err(VerificationError::InvalidAudience) => CliSessionVerifyOutcome::NotOurToken,
            // Bad signature / structurally-not-a-JWT ⇒ not ours; fall
            // through to OIDC (which produces the same 401 for an
            // OIDC-malformed token).
            Err(VerificationError::InvalidSignature) | Err(VerificationError::Malformed { .. }) => {
                CliSessionVerifyOutcome::NotOurToken
            }
            // Expired but otherwise a CliSession-shaped token: it WAS
            // ours. Reject (do NOT fall through — an expired CliSession
            // token must 401, not be re-tried as an OIDC token).
            Err(VerificationError::Expired) => {
                CliSessionVerifyOutcome::Rejected(CliSessionRejection::Expired)
            }
        }
    }
}

/// Three-way outcome of [`CliSessionTokenSigner::verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliSessionVerifyOutcome {
    /// A valid CliSession access-token JWT. Boxed to keep the enum small
    /// (`CliSessionClaims` carries a `Vec<String>`).
    Verified(Box<CliSessionClaims>),
    /// Not a CliSession-family AK-JWT (bad signature, not a JWT, or the
    /// wrong `aud` — e.g. an OCI token). Caller falls through to OIDC.
    NotOurToken,
    /// A structurally-ours CliSession token that is invalid. Caller
    /// rejects (401); MUST NOT fall through.
    Rejected(CliSessionRejection),
}

/// Why a CliSession-family AK-JWT was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliSessionRejection {
    /// Token's `exp` is in the past.
    Expired,
    /// Signature + `aud` matched but the `token_kind` claim was not
    /// [`CLI_SESSION_TOKEN_KIND`]. Defence-in-depth against a future
    /// AK-JWT family reusing the CliSession audience.
    WrongTokenKind,
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::oci_token_signing::{AccessEntry, OciAccessClaims, OciTokenSigningKey};
    use ed25519_dalek::SigningKey;
    use rand::rand_core::UnwrapErr;
    use rand::rngs::SysRng;

    fn fresh_signer() -> CliSessionTokenSigner {
        let sk = SigningKey::generate(&mut UnwrapErr(SysRng));
        let key = Arc::new(OciTokenSigningKey::new(sk, None));
        CliSessionTokenSigner::new(key, "https://hort.example.com".into())
    }

    fn exp_in(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(Utc::now().timestamp() + secs, 0).unwrap()
    }

    #[test]
    fn mint_then_verify_carries_claims_and_token_kind() {
        // The minted token carries the resolved claim
        // set so the validator can build a claims-carrying principal.
        let signer = fresh_signer();
        let sub = Uuid::from_u128(0x42);
        let jti = Uuid::from_u128(0x99);
        let claims = vec!["developer".to_string(), "ci-pusher".to_string()];
        let jwt = signer
            .mint(sub, claims.clone(), jti, exp_in(900))
            .expect("mint");

        match signer.verify(&jwt) {
            CliSessionVerifyOutcome::Verified(c) => {
                assert_eq!(c.sub, sub);
                assert_eq!(c.jti, jti);
                assert_eq!(c.claims, claims);
                assert_eq!(c.token_kind, CLI_SESSION_TOKEN_KIND);
                assert_eq!(c.aud, CLI_SESSION_AUDIENCE);
                assert_eq!(c.iss, "https://hort.example.com");
            }
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    #[test]
    fn mint_sets_iat_to_the_mint_instant() {
        // `iat` is the cutoff comparand, so it must be present on every
        // token the registry mints — a caller cannot omit it.
        let signer = fresh_signer();
        let before = Utc::now().timestamp();
        let jwt = signer
            .mint(
                Uuid::from_u128(1),
                vec!["developer".into()],
                Uuid::new_v4(),
                exp_in(900),
            )
            .expect("mint");
        let after = Utc::now().timestamp();
        match signer.verify(&jwt) {
            CliSessionVerifyOutcome::Verified(c) => {
                let iat = c.iat.expect("mint sets iat").timestamp();
                assert!(
                    iat >= before && iat <= after,
                    "iat {iat} outside the mint window [{before}, {after}]"
                );
            }
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    #[test]
    fn a_token_minted_without_iat_omits_the_field_and_parses_back_as_none() {
        // The pre-`iat` token shape. The field is ABSENT from the
        // payload (not `null`), and such a token still verifies —
        // that is what keeps every in-flight session alive across the
        // upgrade. Denying it is the cutoff's job, not the parser's.
        let sk = SigningKey::generate(&mut UnwrapErr(SysRng));
        let key = Arc::new(OciTokenSigningKey::new(sk, None));
        let signer = CliSessionTokenSigner::new(key.clone(), "https://hort.example.com".into());
        let legacy = CliSessionClaims {
            iss: "https://hort.example.com".into(),
            sub: Uuid::from_u128(1),
            aud: CLI_SESSION_AUDIENCE.into(),
            exp: exp_in(900),
            iat: None,
            jti: Uuid::new_v4(),
            token_kind: CLI_SESSION_TOKEN_KIND.into(),
            claims: vec!["developer".into()],
        };
        let jwt = key.mint_claims(&legacy).expect("mint");

        // The serialised payload carries no `iat` key at all.
        let payload_b64 = jwt.split('.').nth(1).expect("jwt has a payload segment");
        let payload = base64_url_decode(payload_b64);
        let json: serde_json::Value = serde_json::from_slice(&payload).expect("payload is json");
        assert!(
            json.get("iat").is_none(),
            "an iat-less token must omit the field, got {json}"
        );

        match signer.verify(&jwt) {
            CliSessionVerifyOutcome::Verified(c) => assert_eq!(c.iat, None),
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    #[test]
    fn claims_with_an_absent_iat_deserialize_to_none() {
        // `#[serde(default)]` resolves the absence without reaching
        // `iat_serde::deserialize`. Asserted directly on the payload
        // shape so the contract is pinned independently of the signer.
        let json = r#"{
            "iss":"https://hort.example.com","sub":"00000000-0000-0000-0000-000000000001",
            "aud":"urn:hort:cli-session","exp":4102444800,
            "jti":"00000000-0000-0000-0000-000000000002",
            "token_kind":"cli_session","claims":["developer"]
        }"#;
        let parsed: CliSessionClaims = serde_json::from_str(json).expect("parses");
        assert_eq!(parsed.iat, None);
    }

    #[test]
    fn claims_with_a_null_iat_deserialize_to_none() {
        // An explicit `null` is the same unprovable state as an absent
        // field: it reaches `iat_serde::deserialize`, which returns
        // `None` rather than erroring.
        let json = r#"{
            "iss":"https://hort.example.com","sub":"00000000-0000-0000-0000-000000000001",
            "aud":"urn:hort:cli-session","exp":4102444800,"iat":null,
            "jti":"00000000-0000-0000-0000-000000000002",
            "token_kind":"cli_session","claims":["developer"]
        }"#;
        let parsed: CliSessionClaims = serde_json::from_str(json).expect("parses");
        assert_eq!(parsed.iat, None);
    }

    #[test]
    fn claims_with_an_unrepresentable_iat_are_rejected() {
        // A present `iat` the registry cannot place on the timeline is
        // an error, NOT a silent `None` — `None` is the state the
        // cutoff treats as unprovable, and conflating the two would let
        // a forged out-of-range `iat` pick its own verdict.
        let json = r#"{
            "iss":"https://hort.example.com","sub":"00000000-0000-0000-0000-000000000001",
            "aud":"urn:hort:cli-session","exp":4102444800,"iat":99999999999999999,
            "jti":"00000000-0000-0000-0000-000000000002",
            "token_kind":"cli_session","claims":["developer"]
        }"#;
        let err = serde_json::from_str::<CliSessionClaims>(json)
            .expect_err("an out-of-range iat must not parse");
        assert!(
            err.to_string().contains("iat out of range"),
            "unexpected error: {err}"
        );
    }

    /// Minimal unpadded base64url decoder for reading a JWT payload
    /// segment back out in a test. `hort-app` carries no base64
    /// dependency and this is the only place a test needs one.
    fn base64_url_decode(input: &str) -> Vec<u8> {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut acc: u32 = 0;
        let mut bits = 0_u32;
        let mut out = Vec::with_capacity(input.len() * 3 / 4);
        for ch in input.bytes() {
            let v = ALPHABET
                .iter()
                .position(|a| *a == ch)
                .expect("jwt payload is base64url") as u32;
            acc = (acc << 6) | v;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push(((acc >> bits) & 0xff) as u8);
            }
        }
        out
    }

    #[test]
    fn verify_rejects_tampered_signature_as_not_our_token() {
        let signer = fresh_signer();
        let mut jwt = signer
            .mint(
                Uuid::from_u128(1),
                vec!["developer".into()],
                Uuid::new_v4(),
                exp_in(900),
            )
            .expect("mint");
        // Flip the last signature char.
        let last = jwt.pop().expect("non-empty");
        jwt.push(if last == 'A' { 'B' } else { 'A' });
        assert_eq!(signer.verify(&jwt), CliSessionVerifyOutcome::NotOurToken);
    }

    #[test]
    fn verify_rejects_wrong_issuer_key_as_not_our_token() {
        // A JWT signed by a DIFFERENT key (a forged/wrong-issuer token)
        // fails signature verification → NotOurToken (the caller falls
        // through to OIDC, which 401s).
        let signer = fresh_signer();
        let attacker = fresh_signer();
        let jwt = attacker
            .mint(
                Uuid::from_u128(1),
                vec!["developer".into()],
                Uuid::new_v4(),
                exp_in(900),
            )
            .expect("mint");
        assert_eq!(signer.verify(&jwt), CliSessionVerifyOutcome::NotOurToken);
    }

    #[test]
    fn verify_rejects_expired_token() {
        let signer = fresh_signer();
        let jwt = signer
            .mint(
                Uuid::from_u128(1),
                vec!["developer".into()],
                Uuid::new_v4(),
                exp_in(-60),
            )
            .expect("mint");
        assert_eq!(
            signer.verify(&jwt),
            CliSessionVerifyOutcome::Rejected(CliSessionRejection::Expired)
        );
    }

    #[test]
    fn verify_rejects_oci_token_as_not_our_token() {
        // Token-family discriminator (the headline negative case): an OCI
        // `/v2/auth` token is signed by the SAME key but carries the OCI
        // `aud` (registry host), NOT the CliSession audience. It must
        // NOT verify as a CliSession token — it lands in `NotOurToken`
        // (the caller falls through to OIDC, which 401s), so it can
        // never replay against the CliSession-gated prefetch/discovery
        // surfaces.
        let sk = SigningKey::generate(&mut UnwrapErr(SysRng));
        let key = Arc::new(OciTokenSigningKey::new(sk, None));
        let signer = CliSessionTokenSigner::new(key.clone(), "https://hort.example.com".into());

        let oci_claims = OciAccessClaims {
            iss: "https://hort.example.com/v2/auth".into(),
            sub: Uuid::from_u128(7),
            aud: "registry.example.com".into(),
            exp: exp_in(300),
            access: vec![AccessEntry {
                resource_type: "repository".into(),
                name: "library/nginx".into(),
                actions: vec!["pull".into()],
            }],
        };
        let oci_jwt = key.mint(&oci_claims).expect("mint oci");

        assert_eq!(
            signer.verify(&oci_jwt),
            CliSessionVerifyOutcome::NotOurToken
        );
    }

    #[test]
    fn verify_rejects_wrong_token_kind_when_aud_matches() {
        // Defence-in-depth: a token minted with the CliSession `aud` but
        // a non-`cli_session` `token_kind` is Rejected, not Verified.
        // (Constructed via the raw signer to bypass the `mint` helper
        // which always sets the correct token_kind.)
        let sk = SigningKey::generate(&mut UnwrapErr(SysRng));
        let key = Arc::new(OciTokenSigningKey::new(sk, None));
        let signer = CliSessionTokenSigner::new(key.clone(), "https://hort.example.com".into());
        let bad = CliSessionClaims {
            iss: "https://hort.example.com".into(),
            sub: Uuid::from_u128(1),
            aud: CLI_SESSION_AUDIENCE.into(),
            exp: exp_in(900),
            iat: Some(Utc::now()),
            jti: Uuid::new_v4(),
            token_kind: "service_account".into(),
            claims: vec!["developer".into()],
        };
        let jwt = key.mint_claims(&bad).expect("mint");
        assert_eq!(
            signer.verify(&jwt),
            CliSessionVerifyOutcome::Rejected(CliSessionRejection::WrongTokenKind)
        );
    }
}
