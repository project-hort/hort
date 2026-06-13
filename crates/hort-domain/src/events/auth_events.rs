//! Authentication attempt events.
//!
//! Emitted by `hort-app::use_cases::authenticate_use_case` and the
//! `hort-http-core::middleware::auth` token-validation paths whenever an
//! authentication attempt fails. Successes deliberately do NOT produce
//! events — the audit-value-per-byte trade-off (every authenticated
//! request would otherwise dominate stream volume) keeps successes in
//! tracing only. See design doc §3.4 + §6.
//!
//! Streams live in [`StreamCategory::AuthAttempts`](super::StreamCategory::AuthAttempts).
//! Daily rotation: one stream per UTC date (`StreamId::auth_attempts(date)`).
//! After Item 7 hardens the events table against role compromise, this
//! stream is the tamper-resistant access-decision record NIS2 Art. 21(2)(h)
//! asks for.
//!
//! **Throttle.** The use case throttles appends to ≤ 1 per 60s per
//! `(client_ip_bucket, result)` tuple via the `EphemeralStore`. The
//! coarsening lives in `hort-app::metrics::client_ip_bucket` (`/24` for
//! IPv4, `/48` for IPv6) so an attacker cannot mint arbitrary keys per
//! request to exhaust ephemeral memory. The RAW client IP — not the
//! bucket — is what lands in this event payload (the audit value
//! belongs in the durable record, not the throttle key).
//!
//! **PII note.** `client_ip` is a network identifier (moderate PII at
//! most). `external_id_if_decoded` is the JWT `sub` claim or the
//! supplied username if the local-auth path saw one — this is the
//! identity the attacker tried to use, not the identity of any
//! legitimate principal. Future GDPR erasures join against the CRUD
//! `users` table; this event log is the immutable audit trail by
//! design.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::DomainResult;

use super::validation::{validate_optional_string, validate_string};

// ---------------------------------------------------------------------------
// Validation constants
// ---------------------------------------------------------------------------

/// Maximum allowed length of `AuthenticationAttempted.result`. The
/// result strings come from a closed taxonomy
/// (`local_invalid_credentials`, `oidc_invalid_token`, ...); 64 bytes
/// is comfortably wider than the longest entry today and keeps the
/// envelope small.
const MAX_RESULT_LEN: usize = 64;

/// Maximum allowed length of
/// `AuthenticationAttempted.external_id_if_decoded`. Wide enough to
/// accommodate a 255-char username or a long JWT `sub` claim
/// (Keycloak `realm-users:<uuid>` is well under this) without inviting
/// payload bloat.
const MAX_EXTERNAL_ID_LEN: usize = 512;

/// Maximum allowed length of `OidcKeyRotated.kid_added` and
/// `OidcKeyRotated.kid_evicted`. RFC 7517 does not bound `kid`; in
/// practice IdPs use short opaque identifiers (Keycloak emits 32-char
/// UUID-like strings, Auth0 emits ~40-char base64url tokens, GCP uses
/// short hex hashes). 256 bytes is comfortably above any production
/// IdP's emission and bounds the audit-event payload.
const MAX_KID_LEN: usize = 256;

/// Maximum allowed length of `AdminStatusChanged.external_id`. The
/// value is the OIDC `sub` claim that flipped (Keycloak
/// `realm-users:<uuid>` is well under this); 512 bytes mirrors
/// [`MAX_EXTERNAL_ID_LEN`] so the two auth-stream identity fields keep
/// the same bound.
const MAX_ADMIN_EXTERNAL_ID_LEN: usize = 512;

// ---------------------------------------------------------------------------
// AuthenticationAttempted
// ---------------------------------------------------------------------------

/// Recorded when an authentication attempt fails.
///
/// Successes do NOT produce this event — see the module docstring for the
/// audit-value-per-byte rationale.
///
/// # Wire shape
///
/// `client_ip` is the raw [`IpAddr`] (audit value). The throttle key in the
/// use case uses the bucketed form (`/24` IPv4, `/48` IPv6) instead — one
/// can be replayed for forensics, the other only protects ephemeral
/// storage.
///
/// `external_id_if_decoded` carries:
/// - the JWT `sub` claim for OIDC failures where the token parsed before
///   signature failure;
/// - the supplied username for local-auth failures (sanitised — control
///   chars dropped) so operators can see which identity was being tried;
/// - `None` for the unknown-token / missing-header paths.
///
/// `at` is server-wall-clock at the moment the failure was classified.
/// The event store assigns its own `stored_at` on append; both are
/// preserved (one is "the failure happened"; the other is "the audit log
/// recorded it").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticationAttempted {
    /// The raw client IP that initiated the attempt. Populated from
    /// the `RequestTrust` extension; falls back to `None` only on
    /// transports that genuinely have no peer (currently unused —
    /// every supported transport has a peer).
    pub client_ip: IpAddr,
    /// Closed-taxonomy outcome string. Same value-set as the `result`
    /// label on `hort_auth_attempts_total` so SIEM consumers can join
    /// metric series with audit records. Examples:
    /// `local_invalid_credentials`, `local_locked_out`,
    /// `oidc_invalid_token`, `oidc_idp_unavailable`,
    /// `oidc_expired`, `oidc_unknown_issuer`, `missing_header`.
    pub result: String,
    /// Identity the caller tried to use, when the failure path could
    /// see one. JWT `sub` for OIDC failures past the parse step;
    /// supplied username for local-auth; `None` for missing-header /
    /// pre-parse paths.
    pub external_id_if_decoded: Option<String>,
    /// Server-wall-clock at the moment the failure was classified.
    pub at: DateTime<Utc>,
}

impl AuthenticationAttempted {
    pub fn validate(&self) -> DomainResult<()> {
        validate_string("result", &self.result, MAX_RESULT_LEN)?;
        validate_optional_string(
            "external_id_if_decoded",
            &self.external_id_if_decoded,
            MAX_EXTERNAL_ID_LEN,
        )?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// OidcKeyRotated
// ---------------------------------------------------------------------------

/// Recorded when the JWKS cache replaces a stale key set with a fresh
/// one and at least one signing key has actually changed.
///
/// Emitted by `hort-adapters-oidc::OidcProvider` from the slow-path
/// refresh in `resolve_jwk` after `JwksCache::replace` succeeds. Only
/// the **rotation** transition is audit-worthy; a no-op replace
/// (identical key set, e.g. periodic TTL refresh against a stable IdP)
/// produces no event so audit consumers do not have to sift through
/// idle-refresh noise.
///
/// # Stream choice
///
/// Lands on the per-UTC-date authentication-attempts stream
/// (`StreamId::auth_attempts(today_utc_date)`). Rationale: piggybacking
/// on the existing daily auth-audit stream keeps the blast radius
/// minimal — no new `StreamCategory` variant, no new
/// `Display`/`FromStr` arm, no new parser-collision regression test.
/// Audit consumers already reading the day's `auth-<uuid>` stream for
/// failed-authentication forensics see the key-rotation transitions in
/// the same chronological feed (event-type filtering separates them
/// cleanly: `OidcKeyRotated` vs. `AuthenticationAttempted`). A
/// dedicated `StreamCategory::OidcKeyRotation` was the alternative;
/// rejected as a deliberate, accepted decision
/// because key-rotation events are sparse (a well-configured
/// IdP rotates on the order of weeks-to-months) and do not justify a
/// separate aggregate. Revisit only if rotation volume grows materially.
///
/// # PII / payload contents
///
/// `kid_added` and `kid_evicted` are JWK key identifiers — opaque
/// strings the IdP picks. They are **not** secrets: the public part of
/// the JWK lives in the IdP's discoverable JWKS endpoint and the kid is
/// the index into it. The event deliberately does NOT include the JWK
/// content (modulus / x / y), only the kid strings — auditors trace key
/// rotation, but do not need the cryptographic material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcKeyRotated {
    /// The kid of a newly-fetched key that was not in the previous
    /// cache snapshot. When multiple keys are added in a single
    /// rotation (rare — typical IdP rotations overlap one outgoing and
    /// one incoming kid), the lexicographically-smallest added kid is
    /// recorded here for determinism. The event captures the
    /// transition fact; downstream tooling that needs the full kid set
    /// can join against the JWKS endpoint.
    pub kid_added: String,
    /// The kid of a key that was in the previous cache snapshot but is
    /// absent from the freshly-fetched set, when one such kid exists.
    /// `None` when the rotation only adds a new kid without dropping
    /// an old one (e.g. first-ever fetch into an empty cache, or an
    /// IdP enlarging its key set without an overlap-window
    /// retirement). When multiple keys are evicted, the
    /// lexicographically-smallest evicted kid is recorded here.
    pub kid_evicted: Option<String>,
    /// Server-wall-clock at the moment the JWKS fetch completed.
    /// Mirrors `AuthenticationAttempted.at` semantics — the time the
    /// rotation was observed locally, not the IdP's notion of when the
    /// key was minted (which is not exposed via JWKS).
    pub fetched_at: DateTime<Utc>,
}

impl OidcKeyRotated {
    pub fn validate(&self) -> DomainResult<()> {
        validate_string("kid_added", &self.kid_added, MAX_KID_LEN)?;
        validate_optional_string("kid_evicted", &self.kid_evicted, MAX_KID_LEN)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// AdminStatusChanged
// ---------------------------------------------------------------------------

/// Recorded when a persisted `User.is_admin` bit actually flips.
///
/// The login path recomputes `is_admin` from the IdP `groups` claim and
/// **persists** it onto the upserted user row on *every* OIDC login.
/// That is the intended mechanism (the IdP group is the admin source
/// of truth, not the stale DB row; ADR 0012) and this event does **not**
/// change it.
/// What it adds is observability: a transient IdP outage / empty-groups
/// response silently mutates a durable bit (a legitimate admin flips to
/// non-admin; a spurious resolve persists a wrong bit
/// composes with F-11). Auditors need to see the transition fact.
///
/// **Emission discipline.** Emitted by
/// `hort-app::use_cases::authenticate_use_case` **only** when an
/// *existing* user row's `is_admin` differs from the freshly-recomputed
/// value. A JIT-provisioned user (no prior row) is *not* a transition —
/// there is no durable bit being mutated, only an initial value being
/// set; the new-user case stays silent so the stream records flips, not
/// every first login. An idempotent recompute that leaves the bit
/// unchanged is likewise silent (the common case — admins stay admins).
///
/// # Stream choice
///
/// Lands on the **per-user** stream (`StreamId::user(user_id)`)
/// alongside `ApiTokenIssued` / `ApiTokenRevoked` — an `is_admin` flip
/// is a per-principal authority change, and an auditor reviewing a
/// specific user's authority history reads one stream. (Contrast
/// `AuthenticationAttempted`, which is per-UTC-date because failed
/// attempts are attacker-driven and not tied to a provisioned user.)
///
/// # PII / payload contents
///
/// `user_id` is the internal `users.id`. `external_id` is the OIDC
/// `sub` claim (the IdP-side identity that authenticated) — a moderate
/// identifier at most, already present in the `users` row and in
/// `AuthenticationAttempted.external_id_if_decoded`. No token, no
/// group-claim contents, no credential material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminStatusChanged {
    /// Internal `users.id` of the row whose `is_admin` bit flipped.
    pub user_id: uuid::Uuid,
    /// OIDC `sub` claim of the IdP identity that authenticated when the
    /// flip was observed. The audit identity, mirroring
    /// [`AuthenticationAttempted::external_id_if_decoded`] semantics.
    pub external_id: String,
    /// `true` when the bit flipped `false → true` (admin **granted**);
    /// `false` when it flipped `true → false` (admin **revoked**). The
    /// emission site only constructs this event on an actual flip, so
    /// this field is never "no change".
    pub granted: bool,
    /// Server-wall-clock at the moment the flip was observed (the OIDC
    /// login that recomputed the bit). Mirrors
    /// [`AuthenticationAttempted::at`] semantics.
    pub at: DateTime<Utc>,
}

impl AdminStatusChanged {
    pub fn validate(&self) -> DomainResult<()> {
        validate_string("external_id", &self.external_id, MAX_ADMIN_EXTERNAL_ID_LEN)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{Ipv4Addr, Ipv6Addr};

    fn valid() -> AuthenticationAttempted {
        AuthenticationAttempted {
            client_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42)),
            result: "local_invalid_credentials".into(),
            external_id_if_decoded: Some("alice".into()),
            at: Utc::now(),
        }
    }

    #[test]
    fn validate_accepts_minimal_valid_event() {
        valid().validate().unwrap();
    }

    #[test]
    fn validate_rejects_empty_result() {
        let mut e = valid();
        e.result = String::new();
        let err = e.validate().unwrap_err();
        assert!(err.to_string().contains("result"));
    }

    #[test]
    fn validate_rejects_oversized_result() {
        let mut e = valid();
        e.result = "r".repeat(MAX_RESULT_LEN + 1);
        let err = e.validate().unwrap_err();
        assert!(err.to_string().contains("result"));
    }

    #[test]
    fn validate_accepts_none_external_id() {
        let mut e = valid();
        e.external_id_if_decoded = None;
        e.validate().unwrap();
    }

    #[test]
    fn validate_rejects_oversized_external_id() {
        let mut e = valid();
        e.external_id_if_decoded = Some("x".repeat(MAX_EXTERNAL_ID_LEN + 1));
        let err = e.validate().unwrap_err();
        assert!(err.to_string().contains("external_id_if_decoded"));
    }

    #[test]
    fn serde_roundtrip_preserves_fields_ipv4() {
        let original = valid();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: AuthenticationAttempted = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn serde_roundtrip_preserves_fields_ipv6() {
        let original = AuthenticationAttempted {
            client_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x1234, 0xabcd, 0, 0, 0, 1)),
            result: "oidc_invalid_token".into(),
            external_id_if_decoded: None,
            at: Utc::now(),
        };
        let json = serde_json::to_string(&original).unwrap();
        let decoded: AuthenticationAttempted = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    // -- OidcKeyRotated ----------------------------------------------------

    fn valid_oidc_rotated() -> OidcKeyRotated {
        OidcKeyRotated {
            kid_added: "kid-c".into(),
            kid_evicted: Some("kid-a".into()),
            fetched_at: Utc::now(),
        }
    }

    #[test]
    fn oidc_rotated_validate_accepts_minimal_valid_event() {
        valid_oidc_rotated().validate().unwrap();
    }

    #[test]
    fn oidc_rotated_validate_accepts_none_evicted() {
        let mut e = valid_oidc_rotated();
        e.kid_evicted = None;
        e.validate().unwrap();
    }

    #[test]
    fn oidc_rotated_validate_rejects_empty_kid_added() {
        let mut e = valid_oidc_rotated();
        e.kid_added = String::new();
        let err = e.validate().unwrap_err();
        assert!(err.to_string().contains("kid_added"));
    }

    #[test]
    fn oidc_rotated_validate_rejects_oversized_kid_added() {
        let mut e = valid_oidc_rotated();
        e.kid_added = "k".repeat(MAX_KID_LEN + 1);
        let err = e.validate().unwrap_err();
        assert!(err.to_string().contains("kid_added"));
    }

    #[test]
    fn oidc_rotated_validate_rejects_oversized_kid_evicted() {
        let mut e = valid_oidc_rotated();
        e.kid_evicted = Some("k".repeat(MAX_KID_LEN + 1));
        let err = e.validate().unwrap_err();
        assert!(err.to_string().contains("kid_evicted"));
    }

    #[test]
    fn oidc_rotated_serde_roundtrip_preserves_fields() {
        let original = valid_oidc_rotated();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: OidcKeyRotated = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn oidc_rotated_serde_roundtrip_preserves_none_evicted() {
        let original = OidcKeyRotated {
            kid_added: "kid-new".into(),
            kid_evicted: None,
            fetched_at: Utc::now(),
        };
        let json = serde_json::to_string(&original).unwrap();
        let decoded: OidcKeyRotated = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    // -- AdminStatusChanged ------------------------------------------------

    fn valid_admin_changed() -> AdminStatusChanged {
        AdminStatusChanged {
            user_id: uuid::Uuid::new_v4(),
            external_id: "realm-users:abc-123".into(),
            granted: true,
            at: Utc::now(),
        }
    }

    #[test]
    fn admin_changed_validate_accepts_minimal_valid_event() {
        valid_admin_changed().validate().unwrap();
    }

    #[test]
    fn admin_changed_validate_accepts_revoked() {
        let mut e = valid_admin_changed();
        e.granted = false;
        e.validate().unwrap();
    }

    #[test]
    fn admin_changed_validate_rejects_empty_external_id() {
        let mut e = valid_admin_changed();
        e.external_id = String::new();
        let err = e.validate().unwrap_err();
        assert!(err.to_string().contains("external_id"));
    }

    #[test]
    fn admin_changed_validate_rejects_oversized_external_id() {
        let mut e = valid_admin_changed();
        e.external_id = "x".repeat(MAX_ADMIN_EXTERNAL_ID_LEN + 1);
        let err = e.validate().unwrap_err();
        assert!(err.to_string().contains("external_id"));
    }

    #[test]
    fn admin_changed_serde_roundtrip_preserves_fields_granted() {
        let original = valid_admin_changed();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: AdminStatusChanged = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn admin_changed_serde_roundtrip_preserves_fields_revoked() {
        let original = AdminStatusChanged {
            user_id: uuid::Uuid::new_v4(),
            external_id: "okta|00u1abc".into(),
            granted: false,
            at: Utc::now(),
        };
        let json = serde_json::to_string(&original).unwrap();
        let decoded: AdminStatusChanged = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }
}
