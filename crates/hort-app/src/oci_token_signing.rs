//! Ed25519-signed OCI Distribution-Spec `/v2/auth` token JWTs.
//!
//! Implements the JWT sign + verify primitives
//! the `OciTokenExchangeUseCase` emits (see `docs/auth-catalog.md`,
//! OCI `/v2/auth` token exchange).
//!
//! # Why a dedicated key
//!
//! hort-server *validates* OIDC bearer JWTs against keys it fetches from
//! the IdP's JWKS endpoint (`HORT_JWKS_URL`). It does
//! NOT own those keys; it has no signing capability with them. The
//! OCI `/v2/auth` flow makes hort-server an *issuer* — it must sign the
//! minted JWT itself. Reusing the OIDC JWKS keys is therefore not an
//! option; this module owns a dedicated Ed25519 keypair loaded from
//! `HORT_OCI_TOKEN_SIGNING_KEY{,_FILE}` (active) and (optionally)
//! `HORT_OCI_TOKEN_SIGNING_KEY_PREV{,_FILE}` (verify-only previous half
//! for zero-downtime rotation).
//!
//! # Algorithm choice
//!
//! Ed25519 (EdDSA) — small token size, fast sign + verify, and no
//! parameter selection footgun. The Distribution Spec is silent on
//! algorithm; the JWT consumer is the same hort-server process so there
//! is no third-party validator to coordinate with.
//!
//! # Replay window
//!
//! Tokens carry a 5-minute `exp` claim. They are bearer credentials,
//! replayable within that window. Defence in depth: every storage
//! operation re-resolves the user's grants via `RbacEvaluator::authorize`,
//! so a leaked JWT can never escalate beyond what the *target user*
//! could currently do.
//!
//! # Public surface
//!
//! - [`OciAccessClaims`] — the JWT payload shape. Distribution-Spec
//!   wire form: `iss`, `sub`, `aud`, `exp`, `access[]`. Both
//!   `Serialize` AND `Deserialize` are derived because the JWT
//!   library round-trips the payload through JSON during sign / verify
//!   — this is OK because `OciAccessClaims` is a JWT payload, not a
//!   request DTO; the architect's "no `Deserialize` on principal /
//!   identity types" anti-pattern does not apply.
//! - [`OciTokenSigningKey`] — sign with the active key, verify against
//!   the active OR previous public key.
//! - [`SigningError`] / [`VerificationError`] — typed failure shapes;
//!   the use case maps each to the appropriate HTTP envelope.
//!
//! # What is NOT here
//!
//! - The HTTP handler — lives in `hort-http-oci`. This module is
//!   transport-agnostic.
//! - Composition-root key loading (`_FILE` precedence + ambiguous-
//!   source rejection) — lives in `hort-server::config` /
//!   `hort-server::composition`. Tests in *this* module exercise the
//!   parsing primitive (`from_pkcs8_pem` + `verifying_from_pem`) and
//!   the round-trip; ambiguous-source errors are tested at the
//!   composition layer.

use std::time::Duration as StdDuration;

use chrono::{DateTime, Utc};
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// OciAccessClaims — Distribution-Spec wire shape
// ---------------------------------------------------------------------------

/// Distribution-Spec JWT payload.
///
/// See [Distribution Spec §authentication](https://distribution.github.io/distribution/spec/auth/)
/// for the wire form. All fields are required; `access` is the array
/// of granted scopes (may be empty when nothing was granted — clients
/// that requested a scope but received a token with no `access` entry
/// know to treat it as "anonymous-equivalent").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciAccessClaims {
    /// `iss` — issuing authority. Convention: `https://<hort-host>/v2/auth`.
    pub iss: String,
    /// `sub` — subject (the validated user's `user_id`).
    pub sub: Uuid,
    /// `aud` — audience (the registry hostname).
    pub aud: String,
    /// `exp` — expiry (UTC seconds since epoch on the wire; we carry
    /// the parsed `DateTime<Utc>` here and convert at sign / verify
    /// time via `serde(with = "exp_serde")`).
    #[serde(with = "exp_serde")]
    pub exp: DateTime<Utc>,
    /// `access` — granted scopes. Each entry is one
    /// `(resource_type, resource_name, actions)` tuple per the
    /// Distribution Spec.
    pub access: Vec<AccessEntry>,
}

/// One entry in the `access[]` array.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessEntry {
    /// `type` on the wire. `"repository"` for blob / manifest paths,
    /// `"registry"` for catalog operations.
    #[serde(rename = "type")]
    pub resource_type: String,
    /// `name` on the wire. For `repository` this is the canonical
    /// `<group>/<image>` string; for `registry` it is `catalog`.
    pub name: String,
    /// `actions` on the wire. Distribution-Spec lowercase strings:
    /// `pull` / `push` / `delete`.
    pub actions: Vec<String>,
}

/// `exp` claim serde — the JWT spec requires Unix-epoch seconds; the
/// in-memory shape is `DateTime<Utc>` for ergonomics. Custom (de)ser
/// keeps the integer wire form without forcing every other timestamp
/// in the codebase to use the same shape.
mod exp_serde {
    use chrono::{DateTime, TimeZone, Utc};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(dt: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
        let secs = dt.timestamp();
        secs.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
        let secs = i64::deserialize(d)?;
        Utc.timestamp_opt(secs, 0)
            .single()
            .ok_or_else(|| serde::de::Error::custom("exp out of range"))
    }
}

// ---------------------------------------------------------------------------
// OciTokenSigningKey
// ---------------------------------------------------------------------------

/// Active-plus-previous Ed25519 key material for OCI-token JWTs.
///
/// `active_signing` mints; verify accepts either the active or the
/// previous public key. This is the rotation primitive: deploy new
/// active + roll old active to prev → wait `exp` window → deploy
/// without prev.
pub struct OciTokenSigningKey {
    active_signing: SigningKey,
    active_verifying: VerifyingKey,
    prev_verifying: Option<VerifyingKey>,
}

impl std::fmt::Debug for OciTokenSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose key material — `Debug` on a signing handle is a
        // log-leak vector. Surface only the structural shape (whether
        // the previous-key slot is wired) so log lines can reason
        // about rotation status without printing bytes.
        f.debug_struct("OciTokenSigningKey")
            .field("active", &"<redacted>")
            .field("prev_configured", &self.prev_verifying.is_some())
            .finish()
    }
}

impl OciTokenSigningKey {
    /// Build from an already-parsed `SigningKey` and an optional
    /// previous public-half. Used by composition (after PEM parse) and
    /// by tests (constructed in-memory).
    pub fn new(active_signing: SigningKey, prev_verifying: Option<VerifyingKey>) -> Self {
        let active_verifying = active_signing.verifying_key();
        Self {
            active_signing,
            active_verifying,
            prev_verifying,
        }
    }

    /// Parse PEM-encoded PKCS#8 for the active key and (optionally)
    /// PEM-encoded SubjectPublicKeyInfo for the previous public-half.
    ///
    /// The JSON-shaped `_PREV` slot accepts a public-only PEM (verify-
    /// only — operators rotate by holding two private keys briefly
    /// only on the deploying side; the previous key's public half is
    /// enough for verification.
    pub fn from_pem(
        active_pem: &str,
        prev_public_pem: Option<&str>,
    ) -> Result<Self, KeyParseError> {
        let active_signing = SigningKey::from_pkcs8_pem(active_pem)
            .map_err(|source| KeyParseError::ActiveParse { source })?;
        let prev_verifying = match prev_public_pem {
            None => None,
            Some(pem) => Some(
                VerifyingKey::from_public_key_pem(pem)
                    .map_err(|source| KeyParseError::PrevParse { source })?,
            ),
        };
        Ok(Self::new(active_signing, prev_verifying))
    }

    /// Mint a JWT carrying `claims`. Signs with the active key.
    ///
    /// `jsonwebtoken::EncodingKey::from_ed_der` expects a PKCS#8 DER
    /// envelope (NOT the raw 32-byte seed); we serialise the parsed
    /// `SigningKey` back to PKCS#8 once per call. The cost is
    /// negligible — Ed25519 keys are 32 bytes plus framing — and
    /// caching the encoded form would require holding it in memory
    /// for the lifetime of the process, which the security review
    /// prefers to avoid (the parsed `SigningKey` already lives in
    /// memory; the PKCS#8 DER would be a redundant copy).
    pub fn mint(&self, claims: &OciAccessClaims) -> Result<String, SigningError> {
        self.mint_claims(claims)
    }

    /// Mint a JWT carrying an arbitrary `Serialize` claims payload,
    /// signed with the active Ed25519 key.
    ///
    /// The OCI `/v2/auth` token ([`Self::mint`]) and the
    /// CliSession access token (ADR 0013) share this single signer + key —
    /// only the claims *shape* and the embedded `aud` differ. Keeping one
    /// signing primitive avoids a second Ed25519 keypair (and a second
    /// operator key-management surface) for what is the same trust
    /// anchor; the token families are kept apart at *verify* time by
    /// the `aud` + payload discriminator the caller checks, never by
    /// the signing key (see [`Self::verify_claims`] doc).
    ///
    /// `EncodingKey::from_ed_der` expects a PKCS#8 DER envelope; we
    /// re-serialise the parsed `SigningKey` once per call (negligible
    /// for a 32-byte key, and avoids holding a redundant secret copy
    /// for the process lifetime — same rationale as [`Self::mint`]).
    pub fn mint_claims<T: Serialize>(&self, claims: &T) -> Result<String, SigningError> {
        let header = Header::new(Algorithm::EdDSA);
        let pkcs8 = self
            .active_signing
            .to_pkcs8_der()
            .map_err(|source| SigningError::EncodeKey { source })?;
        let key = EncodingKey::from_ed_der(pkcs8.as_bytes());
        jsonwebtoken::encode(&header, claims, &key)
            .map_err(|source| SigningError::Encode { source })
    }

    /// Verify a JWT. Tries the active key first; on signature failure,
    /// tries the previous key (if configured). Returns the parsed
    /// claims on success.
    ///
    /// Validation enforces:
    /// - Algorithm = `EdDSA`.
    /// - `exp` not past `now`.
    /// - `aud` matches `expected_aud`.
    pub fn verify(
        &self,
        jwt: &str,
        expected_aud: &str,
    ) -> Result<OciAccessClaims, VerificationError> {
        self.verify_claims(jwt, expected_aud)
    }

    /// Verify a JWT against an arbitrary `Deserialize` claims payload.
    /// Tries the active key first; on a *signature*
    /// failure, retries with the previous key (if configured — the
    /// rotation primitive). Enforces `alg = EdDSA`, `exp` not past, and
    /// `aud == expected_aud`.
    ///
    /// **Discriminator (do NOT conflate OCI and CliSession AK-JWTs).**
    /// The OCI `/v2/auth` token and the CliSession token share this
    /// signer + issuer + key, so issuer/signature alone do NOT separate
    /// them. Separation is by the **`aud`** passed here PLUS a payload
    /// field the caller checks (CliSession: `token_kind = "cli_session"`).
    /// A caller verifying CliSession tokens MUST pass the CliSession
    /// `aud` and check the payload discriminator; an OCI pull token then
    /// fails the `aud` gate here (`InvalidAudience`) and is rejected —
    /// it cannot replay against the CliSession-gated surfaces.
    pub fn verify_claims<T: serde::de::DeserializeOwned>(
        &self,
        jwt: &str,
        expected_aud: &str,
    ) -> Result<T, VerificationError> {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&[expected_aud]);
        // `validate_exp` is `true` by default; explicit for clarity.
        validation.validate_exp = true;
        // No leeway — both the `/v2/auth` flow and the CliSession
        // verify are same-host round-trips; no clock-skew tolerance.
        validation.leeway = 0;

        // `jsonwebtoken::DecodingKey::from_ed_der` expects the SPKI
        // (SubjectPublicKeyInfo) DER form — same shape PKCS#8 wraps
        // for the public half. We serialise the parsed `VerifyingKey`
        // back via `to_public_key_der`. Cost is identical to the
        // signing path.
        let active_spki = self.active_verifying.to_public_key_der().map_err(|e| {
            VerificationError::Malformed {
                message: format!("active verify-key reserialise: {e}"),
            }
        })?;
        let active_decode = DecodingKey::from_ed_der(active_spki.as_bytes());
        match jsonwebtoken::decode::<T>(jwt, &active_decode, &validation) {
            Ok(data) => return Ok(data.claims),
            Err(active_err) => {
                // Fall through to previous-key if it is the kind of
                // error a rotation would explain (signature). Other
                // errors (expired, audience) are structural and
                // applying the previous key cannot change the outcome.
                use jsonwebtoken::errors::ErrorKind as EK;
                let try_prev = matches!(active_err.kind(), EK::InvalidSignature);
                if !try_prev || self.prev_verifying.is_none() {
                    return Err(map_jwt_error(&active_err));
                }
            }
        }

        // Active failed with InvalidSignature; try previous public-key.
        let prev = self.prev_verifying.as_ref().expect("guarded above");
        let prev_spki = prev
            .to_public_key_der()
            .map_err(|e| VerificationError::Malformed {
                message: format!("prev verify-key reserialise: {e}"),
            })?;
        let prev_decode = DecodingKey::from_ed_der(prev_spki.as_bytes());
        match jsonwebtoken::decode::<T>(jwt, &prev_decode, &validation) {
            Ok(data) => Ok(data.claims),
            Err(prev_err) => Err(map_jwt_error(&prev_err)),
        }
    }
}

fn map_jwt_error(err: &jsonwebtoken::errors::Error) -> VerificationError {
    use jsonwebtoken::errors::ErrorKind as EK;
    match err.kind() {
        EK::ExpiredSignature => VerificationError::Expired,
        EK::InvalidAudience => VerificationError::InvalidAudience,
        EK::InvalidSignature => VerificationError::InvalidSignature,
        _ => VerificationError::Malformed {
            message: err.to_string(),
        },
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Failure parsing PEM into Ed25519 key material.
#[derive(Debug, Error)]
pub enum KeyParseError {
    #[error("active signing key: {source}")]
    ActiveParse {
        #[source]
        source: ed25519_dalek::pkcs8::Error,
    },
    #[error("previous public key: {source}")]
    PrevParse {
        #[source]
        source: ed25519_dalek::pkcs8::spki::Error,
    },
}

/// Failure minting a JWT.
#[derive(Debug, Error)]
pub enum SigningError {
    #[error("jwt encode failed: {source}")]
    Encode {
        #[source]
        source: jsonwebtoken::errors::Error,
    },
    /// PKCS#8 reserialise of the active signing key failed. Should
    /// never trigger in production (the key was already parsed from
    /// PKCS#8 at boot); existing as a typed variant rather than an
    /// `expect` keeps the call site lossless if a future ed25519-dalek
    /// version surfaces a serialisation edge case.
    #[error("pkcs8 encode failed: {source}")]
    EncodeKey {
        #[source]
        source: ed25519_dalek::pkcs8::Error,
    },
}

/// Failure verifying a JWT.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerificationError {
    /// Signature did not match the active OR previous key.
    #[error("invalid signature")]
    InvalidSignature,
    /// Token's `exp` is in the past.
    #[error("token expired")]
    Expired,
    /// `aud` claim did not match the expected hostname.
    #[error("invalid audience")]
    InvalidAudience,
    /// Token is structurally malformed (parse error, missing claim,
    /// wrong algorithm, etc.).
    #[error("malformed token: {message}")]
    Malformed { message: String },
}

/// Default mint TTL (5 minutes).
pub const DEFAULT_MINT_TTL: StdDuration = StdDuration::from_secs(300);

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use ed25519_dalek::pkcs8::EncodePublicKey;
    use rand::rngs::OsRng;

    /// Build a fresh keypair via `OsRng`. Used as a building block by
    /// every test below.
    fn fresh_signing_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn sample_claims() -> OciAccessClaims {
        OciAccessClaims {
            iss: "https://hort.example.com/v2/auth".into(),
            sub: Uuid::from_u128(0x1234),
            aud: "hort.example.com".into(),
            exp: Utc::now() + chrono::Duration::seconds(300),
            access: vec![AccessEntry {
                resource_type: "repository".into(),
                name: "library/nginx".into(),
                actions: vec!["pull".into(), "push".into()],
            }],
        }
    }

    #[test]
    fn mint_then_verify_round_trips() {
        let sk = fresh_signing_key();
        let key = OciTokenSigningKey::new(sk, None);
        let claims = sample_claims();
        let jwt = key.mint(&claims).expect("mint");
        let verified = key.verify(&jwt, "hort.example.com").expect("verify");
        assert_eq!(verified.iss, claims.iss);
        assert_eq!(verified.sub, claims.sub);
        assert_eq!(verified.aud, claims.aud);
        assert_eq!(verified.access, claims.access);
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let sk = fresh_signing_key();
        let key = OciTokenSigningKey::new(sk, None);
        let mut jwt = key.mint(&sample_claims()).expect("mint");
        // Flip the LAST signature byte by mutating the encoded form;
        // truncation alone (popping the last char) yields different
        // base64url so jsonwebtoken still attempts to parse it.
        let last = jwt.pop().expect("non-empty");
        let alt = if last == 'A' { 'B' } else { 'A' };
        jwt.push(alt);
        let err = key.verify(&jwt, "hort.example.com").unwrap_err();
        assert!(
            matches!(err, VerificationError::InvalidSignature)
                || matches!(err, VerificationError::Malformed { .. }),
            "expected signature failure, got {err:?}"
        );
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let sk = fresh_signing_key();
        let key = OciTokenSigningKey::new(sk, None);
        let jwt = key.mint(&sample_claims()).expect("mint");
        // JWT shape: header.payload.signature . Replace one byte in
        // the payload to invalidate the signature.
        let mut parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let mut payload = parts[1].to_string();
        let last = payload.pop().expect("non-empty");
        let alt = if last == 'a' { 'b' } else { 'a' };
        payload.push(alt);
        parts[1] = &payload;
        let tampered = parts.join(".");
        let err = key.verify(&tampered, "hort.example.com").unwrap_err();
        // Either Malformed (base64 decode error) or InvalidSignature.
        assert!(matches!(
            err,
            VerificationError::InvalidSignature | VerificationError::Malformed { .. }
        ));
    }

    #[test]
    fn from_pem_round_trip() {
        let sk = fresh_signing_key();
        // Encode → PEM, then parse back.
        let pem = sk
            .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .expect("pkcs8 pem encode");
        let parsed = OciTokenSigningKey::from_pem(&pem, None).expect("parse");
        let claims = sample_claims();
        let jwt = parsed.mint(&claims).expect("mint");
        parsed.verify(&jwt, "hort.example.com").expect("verify");
    }

    #[test]
    fn from_pem_with_prev_public_round_trip() {
        let prev = fresh_signing_key();
        let prev_public = prev.verifying_key();
        let active = fresh_signing_key();

        let active_pem = active
            .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .expect("pkcs8 pem encode");
        let prev_public_pem = prev_public
            .to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .expect("spki pem encode");

        let key = OciTokenSigningKey::from_pem(&active_pem, Some(&prev_public_pem)).expect("parse");
        // Mint with active.
        let claims = sample_claims();
        let jwt = key.mint(&claims).expect("mint");
        key.verify(&jwt, "hort.example.com").expect("verify-active");
    }

    #[test]
    fn verify_accepts_previous_key_signature_after_rotation() {
        // Build the post-rotation state: `active = new_key`, `prev =
        // old_key.verifying_key()`. A JWT minted with the old key
        // (constructed with old_key as active) must verify against the
        // post-rotation handle.
        let old = fresh_signing_key();
        let new = fresh_signing_key();

        // Pre-rotation handle — old_key as active.
        let pre = OciTokenSigningKey::new(old.clone(), None);
        let claims = sample_claims();
        let jwt = pre.mint(&claims).expect("mint with old");

        // Post-rotation handle — new is active, old's public is prev.
        let post = OciTokenSigningKey::new(new, Some(old.verifying_key()));
        let verified = post.verify(&jwt, "hort.example.com").expect("verify");
        assert_eq!(verified.sub, claims.sub);
    }

    #[test]
    fn verify_rejects_signature_from_unknown_key() {
        let active = fresh_signing_key();
        let attacker = fresh_signing_key();
        let key = OciTokenSigningKey::new(active, None);
        // JWT minted with the attacker's key — should NOT verify.
        let attacker_handle = OciTokenSigningKey::new(attacker, None);
        let claims = sample_claims();
        let jwt = attacker_handle.mint(&claims).expect("mint");
        let err = key.verify(&jwt, "hort.example.com").unwrap_err();
        assert_eq!(err, VerificationError::InvalidSignature);
    }

    #[test]
    fn verify_rejects_expired_token() {
        let sk = fresh_signing_key();
        let key = OciTokenSigningKey::new(sk, None);
        let mut claims = sample_claims();
        claims.exp = Utc::now() - chrono::Duration::seconds(60);
        let jwt = key.mint(&claims).expect("mint");
        let err = key.verify(&jwt, "hort.example.com").unwrap_err();
        assert_eq!(err, VerificationError::Expired);
    }

    #[test]
    fn verify_rejects_wrong_audience() {
        let sk = fresh_signing_key();
        let key = OciTokenSigningKey::new(sk, None);
        let claims = sample_claims();
        let jwt = key.mint(&claims).expect("mint");
        let err = key.verify(&jwt, "other.example.com").unwrap_err();
        assert_eq!(err, VerificationError::InvalidAudience);
    }

    #[test]
    fn access_entry_serializes_with_type_field() {
        let entry = AccessEntry {
            resource_type: "repository".into(),
            name: "foo/bar".into(),
            actions: vec!["pull".into()],
        };
        let json = serde_json::to_value(&entry).expect("serialize");
        // Distribution-Spec wire form uses `type`, not `resource_type`.
        assert_eq!(json["type"], "repository");
        assert_eq!(json["name"], "foo/bar");
        assert_eq!(json["actions"][0], "pull");
    }

    #[test]
    fn claims_exp_serializes_as_unix_seconds() {
        let claims = sample_claims();
        let json = serde_json::to_value(&claims).expect("serialize");
        assert!(json["exp"].is_i64(), "exp must be an integer");
    }

    #[test]
    fn from_pem_rejects_garbage_active() {
        let err = OciTokenSigningKey::from_pem("not a pem", None).unwrap_err();
        assert!(matches!(err, KeyParseError::ActiveParse { .. }));
    }

    #[test]
    fn from_pem_rejects_garbage_prev() {
        let active = fresh_signing_key();
        let active_pem = active
            .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .expect("encode");
        let err = OciTokenSigningKey::from_pem(&active_pem, Some("not-a-pem")).unwrap_err();
        assert!(matches!(err, KeyParseError::PrevParse { .. }));
    }

    // -- Generic mint/verify reuse (CliSession) ----------------------------

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct SampleGenericClaims {
        iss: String,
        aud: String,
        #[serde(with = "exp_serde")]
        exp: DateTime<Utc>,
        marker: String,
    }

    fn sample_generic_claims() -> SampleGenericClaims {
        // Truncate to whole seconds: the JWT `exp` wire form is
        // Unix-epoch seconds (see `exp_serde`), so a sub-second `now()`
        // would not round-trip byte-equal.
        let exp = DateTime::<Utc>::from_timestamp(Utc::now().timestamp() + 900, 0).unwrap();
        SampleGenericClaims {
            iss: "https://hort.example.com/cli".into(),
            aud: "hort.example.com/cli-session".into(),
            exp,
            marker: "cli_session".into(),
        }
    }

    #[test]
    fn mint_claims_then_verify_claims_round_trips_arbitrary_payload() {
        // The CliSession JWT reuses this Ed25519 primitive with a
        // DIFFERENT claims shape. The generic methods must round-trip any
        // `Serialize`/`Deserialize` payload, not just `OciAccessClaims`.
        let sk = fresh_signing_key();
        let key = OciTokenSigningKey::new(sk, None);
        let claims = sample_generic_claims();
        let jwt = key.mint_claims(&claims).expect("mint generic");
        let verified: SampleGenericClaims = key
            .verify_claims(&jwt, "hort.example.com/cli-session")
            .expect("verify generic");
        assert_eq!(verified, claims);
    }

    #[test]
    fn verify_claims_rejects_wrong_audience() {
        // Audience discriminator: a payload minted for one `aud` must
        // NOT verify against a different `aud` — this is the
        // OCI-vs-CliSession separator (issuer/signature alone are shared).
        let sk = fresh_signing_key();
        let key = OciTokenSigningKey::new(sk, None);
        let jwt = key.mint_claims(&sample_generic_claims()).expect("mint");
        let err = key
            .verify_claims::<SampleGenericClaims>(&jwt, "some-other-aud")
            .unwrap_err();
        assert_eq!(err, VerificationError::InvalidAudience);
    }

    #[test]
    fn verify_claims_rejects_expired() {
        let sk = fresh_signing_key();
        let key = OciTokenSigningKey::new(sk, None);
        let mut claims = sample_generic_claims();
        claims.exp = Utc::now() - chrono::Duration::seconds(60);
        let jwt = key.mint_claims(&claims).expect("mint");
        let err = key
            .verify_claims::<SampleGenericClaims>(&jwt, "hort.example.com/cli-session")
            .unwrap_err();
        assert_eq!(err, VerificationError::Expired);
    }

    #[test]
    fn verify_claims_accepts_previous_key_after_rotation() {
        // The active+prev rotation primitive must apply to the generic
        // path too — a JWT minted with the old key verifies after the
        // post-rotation handle is built.
        let old = fresh_signing_key();
        let new = fresh_signing_key();
        let pre = OciTokenSigningKey::new(old.clone(), None);
        let claims = sample_generic_claims();
        let jwt = pre.mint_claims(&claims).expect("mint old");
        let post = OciTokenSigningKey::new(new, Some(old.verifying_key()));
        let verified: SampleGenericClaims = post
            .verify_claims(&jwt, "hort.example.com/cli-session")
            .expect("verify after rotation");
        assert_eq!(verified, claims);
    }

    #[test]
    fn verify_claims_rejects_unknown_key_signature() {
        let active = fresh_signing_key();
        let attacker = fresh_signing_key();
        let key = OciTokenSigningKey::new(active, None);
        let attacker_handle = OciTokenSigningKey::new(attacker, None);
        let jwt = attacker_handle
            .mint_claims(&sample_generic_claims())
            .expect("mint");
        let err = key
            .verify_claims::<SampleGenericClaims>(&jwt, "hort.example.com/cli-session")
            .unwrap_err();
        assert_eq!(err, VerificationError::InvalidSignature);
    }
}
