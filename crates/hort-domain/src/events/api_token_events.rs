//! Native-API-token audit events (ADR 0012).
//!
//! Emitted by `ApiTokenUseCase` through `EventStore`. Streams live in
//! category [`StreamCategory::User`](super::StreamCategory::User); each
//! user has one stream keyed by `user_id` (token-owner stream for
//! issuance/revocation; requesting-actor stream for denials).
//!
//! See ADR 0012 and `docs/auth-catalog.md` for the token model these
//! events audit.
//!
//! # No PII
//!
//! Per the project's GDPR Art. 17 strip applied to admin events
//! (see `docs/compliance/GDPR.md`), token-attribution events carry only
//! ids — `token_id`, `user_id`, `target_user_id`, `actor`. The
//! token-owner's username / email is recoverable via a `users` join at
//! audit-read time. The token plaintext, hash, and prefix are NEVER
//! part of the payload (the plaintext is shown once at issuance and
//! never recoverable; hashes stay in the `api_tokens` row).

//! # Actor lives on the envelope, not the payload
//!
//! An earlier design showed an `actor: Actor` field on each event,
//! but the project's existing event vocabulary keeps `Actor` on the
//! [`PersistedEvent`](super::PersistedEvent) envelope (`actor_type` /
//! `actor_id` columns written by `actor_to_columns`). Putting it
//! again in the payload would be a redundant write of the same
//! information. The use case threads the actor through
//! [`AppendEvents.actor`](crate::ports::event_store::AppendEvents)
//! at append time; audit consumers see it on the envelope.
//!
//! `Actor` does NOT derive `Deserialize` (anti-pattern checklist —
//! API handlers cannot forge actor identities), so embedding it in
//! the payload would also force the events to be serialise-only,
//! whereas the rest of the vocabulary round-trips through the JSONB
//! column. Following the codebase pattern (`AdminBootstrapped`,
//! `AdminPasswordRotated` — `rotated_by_admin_id: Option<Uuid>` for
//! the optional admin attribution) keeps the events
//! `Deserialize`-clean and the actor authoritative on the envelope.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::api_token::TokenKind;
use crate::entities::rbac::Permission;
use crate::error::DomainResult;

// ---------------------------------------------------------------------------
// RevokeReason
// ---------------------------------------------------------------------------

/// Reason category for [`ApiTokenRevoked`].
///
/// Closed enum — every emission site picks exactly one variant.
/// Audit consumers route on the enum value rather than free-form
/// text. New revocation paths add a variant here (and a metric label
/// row in `docs/metrics-catalog.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevokeReason {
    /// User-initiated revoke via `DELETE /users/me/tokens/:id`, OR an
    /// admin revoking a single token via `DELETE /admin/tokens/:id`.
    /// The actor field on the event distinguishes the two.
    OperatorRequest,
    /// Bulk-revoke path (e.g. `revoke all tokens for user X` on
    /// deactivation). Reserved for a future bulk-revocation surface;
    /// not emitted today.
    AdminBulk,
}

// ---------------------------------------------------------------------------
// DenialReason
// ---------------------------------------------------------------------------

/// Reason category for [`ApiTokenIssuanceDenied`]. Closed enum;
/// matches the use case's typed [`ApiTokenError`] variants 1:1 on the
/// denial side.
///
/// [`ApiTokenError`]: ../../../hort_app/use_cases/api_token_use_case/enum.ApiTokenError.html
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DenialReason {
    /// Caller's `declared_permissions` exceeded their current
    /// authority on at least one repo.
    CapExceedsAuthority,
    /// Service-account user (`is_service_account = true`) attempted
    /// to self-mint via `POST /users/me/tokens`.
    ServiceAccountSelfMint,
    /// `Permission::Admin` requested but `HORT_TOKEN_ALLOW_ADMIN=false`.
    AdminTokenDisallowed,
    /// Service-account `expires_in_days = null` requested but
    /// `HORT_TOKEN_ALLOW_UNBOUNDED_SVC=false`.
    UnboundedSvcTokenDisallowed,
    /// `repository_ids = Some(vec![])` — locking to no repos is
    /// useless; callers must omit the field for "inherit user grants".
    InvalidRepositorySet,
    /// Admin-token `expires_in_days` outside `[1, 30]` — admin tokens
    /// are clamped tighter than the global 365-day max (NIS2 Art 21(i)).
    AdminTokenExceedsThirtyDays,
    /// Admin-mint target user is not `is_service_account = true`.
    NotServiceAccount,
}

// ---------------------------------------------------------------------------
// ApiTokenIssued
// ---------------------------------------------------------------------------

/// Recorded on every successful issuance — both self-mint
/// (`POST /users/me/tokens`) and admin-mint
/// (`POST /admin/users/:user_id/tokens`).
///
/// Lands on the **token-owner's** user stream
/// ([`StreamId::user(token.user_id)`](super::StreamId::user)). For
/// self-mint the token owner equals the actor; for admin-mint the
/// owner is the service-account user and the actor is the admin.
///
/// **No PII.** Username/email come from a `users` join at audit-read
/// time. The token plaintext, hash, and prefix are NOT part of the
/// payload — the plaintext is shown once on the issuance response and
/// never recoverable; hashes stay in the `api_tokens` row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiTokenIssued {
    /// Primary key of the row inserted into `api_tokens`.
    pub token_id: Uuid,
    /// Token owner — `users.id`. For self-mint equals
    /// `actor.user_id`; for admin-mint, the service-account user.
    pub user_id: Uuid,
    /// Wire-form discriminator (`Pat` / `ServiceAccount` /
    /// `CliSession`).
    pub kind: TokenKind,
    /// Permission set declared at issuance, validated by the use case
    /// against the requesting user's authority. Runtime
    /// intersection (`RbacEvaluator::authorize`) re-applies the cap
    /// on every request.
    pub declared_permissions: Vec<Permission>,
    /// `Some(ids)` ⇒ token locked to those repos. `None` ⇒ inherit
    /// user grants. `Some(vec![])` is rejected at issuance and
    /// therefore never appears here.
    pub repository_ids: Option<Vec<Uuid>>,
    /// `None` ⇒ unbounded (only allowed for service-account tokens
    /// when `HORT_TOKEN_ALLOW_UNBOUNDED_SVC=true`); `Some(t)` ⇒
    /// expiry timestamp.
    pub expires_at: Option<DateTime<Utc>>,
    /// `Some(id)` when the token was admin-minted on behalf of a
    /// service-account user (`created_by_user_id != user_id`);
    /// `None` for self-mint where the owner equals the actor.
    /// Mirrors `AdminPasswordRotated.rotated_by_admin_id`'s shape —
    /// audit consumers read the canonical actor off the envelope
    /// and use this field to distinguish self-mint from admin-mint
    /// without joining `users`.
    pub minted_by_admin_id: Option<Uuid>,
    /// Server-wall-clock at the moment the row was inserted. Same
    /// convention as the admin-event family — both `at` and the
    /// adapter-assigned `stored_at` survive on the persisted event.
    pub at: DateTime<Utc>,
    /// `Some(name)` when the token was minted via the federation
    /// branch of `/auth/token-exchange` (ADR 0018) — the
    /// [`OidcIssuer.name`](crate::entities::oidc_issuer::OidcIssuer)
    /// of the foreign issuer whose JWT was exchanged. `None` for every
    /// non-federated issuance path (self-mint PAT, admin-mint
    /// service-account PAT, CLI-session refresh).
    ///
    /// **Backward compatibility.** This field is wire-additive.
    /// Existing JSONB rows in the `events` table that predate it
    /// deserialise with `None` via the `#[serde(default)]`
    /// attribute below — the event store is append-only and replays
    /// every historical row through this same `Deserialize` impl, so
    /// the default-on-absent contract is load-bearing for replay
    /// correctness. The on-disk shape stays compact via
    /// `skip_serializing_if = "Option::is_none"`: rows minted from
    /// non-federated paths never emit the key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_issuer: Option<String>,
    /// `Some(jti)` when the federation branch saw a `jti` claim on the
    /// exchanged JWT — the JWT's unique identifier, copied verbatim
    /// from the `jti` claim. `None` when the JWT carried no `jti`
    /// claim, OR for every non-federated issuance path. Audit
    /// consumers can correlate this back to the issuing platform's
    /// JWT log; hort-server does NOT use it for replay detection.
    ///
    /// Backward-compatibility contract: identical to
    /// [`source_issuer`](Self::source_issuer) — `#[serde(default)]`
    /// keeps rows predating the field deserialising cleanly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_jti: Option<String>,
    /// `Some(sub)` when the federation branch matched a JWT — the
    /// JWT's `sub` claim. Carries the foreign issuer's view of the
    /// workload identity (e.g. `repo:my-org/my-repo:ref:refs/heads/main`
    /// for GitHub Actions, `system:serviceaccount:ns:sa` for k8s).
    /// `None` for every non-federated issuance path.
    ///
    /// **Why not the full claim set.** The federation matcher walks
    /// `ServiceAccount.federated_identities[].claims`; storing each
    /// matched claim's `(key, value)` would put operator-defined
    /// claim values (potentially PII) into the immutable event log.
    /// `sub` is the standard OIDC subject identifier and is the
    /// minimum information needed to attribute the issued token.
    ///
    /// Backward-compatibility contract: identical to
    /// [`source_issuer`](Self::source_issuer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_sub: Option<String>,
}

impl ApiTokenIssued {
    /// Validate the event payload. No string fields to length-check
    /// (per the no-PII contract); the method is kept for symmetry
    /// with the rest of the event vocabulary so the
    /// [`DomainEvent::validate`](super::DomainEvent::validate)
    /// dispatch stays uniform.
    pub fn validate(&self) -> DomainResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ApiTokenRevoked
// ---------------------------------------------------------------------------

/// Recorded on every successful revoke — self
/// (`DELETE /users/me/tokens/:id`) or admin
/// (`DELETE /admin/tokens/:id`).
///
/// Lands on the **token-owner's** user stream (same stream as the
/// matching `ApiTokenIssued`). The actor field distinguishes the
/// self-revoke (`actor.user_id == user_id`) from the admin-revoke
/// (`actor.user_id` is the admin).
///
/// Revocation is a **soft delete** at the row level (`revoked_at =
/// NOW()`); the row stays for audit. The companion event here is
/// the durable record SIEMs ingest when the row eventually rolls off
/// retention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiTokenRevoked {
    pub token_id: Uuid,
    /// Token owner — `users.id`. The stream lives on
    /// [`StreamId::user(user_id)`](super::StreamId::user).
    pub user_id: Uuid,
    /// `Some(id)` when an admin revoked another user's token;
    /// `None` for self-revoke (owner == actor). Same pattern as
    /// `ApiTokenIssued::minted_by_admin_id` — actor lives on the
    /// envelope; this discriminator separates self vs admin.
    pub revoked_by_admin_id: Option<Uuid>,
    /// Closed reason category (see [`RevokeReason`]).
    pub reason: RevokeReason,
    /// Server-wall-clock at the moment the UPDATE landed.
    pub at: DateTime<Utc>,
}

impl ApiTokenRevoked {
    /// Validate the event payload. No string fields to length-check;
    /// see [`ApiTokenIssued::validate`] for the rationale.
    pub fn validate(&self) -> DomainResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ApiTokenIssuanceDenied
// ---------------------------------------------------------------------------

/// Recorded on every refused issuance.
///
/// Lands on the **requesting actor's** user stream (the timeline
/// being audited is "this user tried X and was refused"). For
/// self-mint that is `StreamId::user(actor.user_id)`; for admin-mint
/// it is `StreamId::user(actor.user_id)` (the admin's stream),
/// distinct from `target_user_id`'s stream — the latter records what
/// happened to a service-account user, the former records what an
/// admin tried.
///
/// One denial event per refused request — the seven [`DenialReason`]
/// variants partition the `ApiTokenError` denial surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiTokenIssuanceDenied {
    /// For whom the token would have been minted. On self-mint paths
    /// `target_user_id == envelope_actor.user_id`; on admin-mint
    /// paths it is the service-account user. The requesting actor
    /// (admin or self) lives on the [`PersistedEvent`](super::PersistedEvent)
    /// envelope.
    pub target_user_id: Uuid,
    /// Wire-form kind that was requested.
    pub requested_kind: TokenKind,
    pub requested_permissions: Vec<Permission>,
    pub requested_repository_ids: Option<Vec<Uuid>>,
    /// Closed denial-reason category (see [`DenialReason`]).
    pub denial_reason: DenialReason,
    /// Server-wall-clock at the moment the request was refused.
    pub at: DateTime<Utc>,
}

impl ApiTokenIssuanceDenied {
    /// Validate the event payload. No string fields to length-check;
    /// see [`ApiTokenIssued::validate`] for the rationale.
    pub fn validate(&self) -> DomainResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ApiTokenUsed
// ---------------------------------------------------------------------------

/// Recorded when a native API token (`Pat` / `ServiceAccount` /
/// `CliSession`) is successfully exercised — i.e. a PAT validation
/// returned `Ok`. Emitted by `PatValidationUseCase::validate_pat`'s
/// wrapper on the success path **only** (a failed validation is not a
/// *use*; `AuthenticationAttempted` does not cover PATs, so there is
/// no double-count and no gap). The common cache-hit path is covered
/// too — it is not an audit blind spot.
///
/// Lands on a dedicated per-`(token_id, UTC-date)`
/// [`StreamCategory::TokenUse`](super::StreamCategory::TokenUse)
/// stream ([`StreamId::token_use`](super::StreamId::token_use)),
/// **never** the token-owner's `StreamCategory::User` lifecycle stream
/// — the issuance/revocation audit and the per-use telemetry
/// are different audit classes with different volumes. The append uses
/// `ExpectedVersion::Any` (each use is an independent observation) and
/// the batch recorder is `system_actor()`.
///
/// **Throttled (decision #1 — 1 hour).** The first use within a
/// 1-hour window per `token_id` wins; the rest are suppressed
/// (`hort_api_token_used_audit_dropped{result="throttled"}`). The
/// throttle is the volume control (contrast B12's opt-in flag) — a
/// hot CI token used thousands of times per hour produces one event
/// per hour, not one per request.
///
/// **No PII / no credential material.** Carries only ids + the
/// wire-form `kind`. The token plaintext, hash, and prefix are NEVER
/// part of the payload (same strip as the rest of this module). The
/// token-owner's username / email is recoverable via a `users` join
/// at audit-read time. No IP / UA — deliberately out of scope (the
/// no-PII event contract).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiTokenUsed {
    /// `api_tokens.id` — the token that was exercised. Also the
    /// per-`(token_id, UTC-date)` stream-sharding key.
    pub token_id: Uuid,
    /// `users.id` — the token owner. Username/email come from a
    /// `users` join at audit-read time (no PII in the payload).
    pub user_id: Uuid,
    /// Wire-form discriminator (`Pat` / `ServiceAccount` /
    /// `CliSession`). Already present on `ApiTokenValidation`; carried
    /// here for audit-routing (decision #3) — no-PII, lets a SIEM
    /// route service-account use distinctly from interactive PAT use.
    pub kind: TokenKind,
    /// Server-wall-clock at the moment the validation returned `Ok`.
    /// The event store assigns its own `stored_at` on append; both
    /// survive — same convention as the rest of this module's `at`
    /// fields and [`super::AuthenticationAttempted::at`].
    pub occurred_at: DateTime<Utc>,
}

impl ApiTokenUsed {
    /// Validate the event payload. No string fields to length-check
    /// (per the no-PII contract — only ids + a closed `kind` enum);
    /// the method is kept for symmetry with the rest of the event
    /// vocabulary so the
    /// [`DomainEvent::validate`](super::DomainEvent::validate)
    /// dispatch stays uniform.
    pub fn validate(&self) -> DomainResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn issued() -> ApiTokenIssued {
        ApiTokenIssued {
            token_id: Uuid::from_u128(0x000A_CEF0),
            user_id: Uuid::from_u128(0xACE),
            kind: TokenKind::Pat,
            declared_permissions: vec![Permission::Read, Permission::Write],
            repository_ids: Some(vec![Uuid::from_u128(0xA)]),
            expires_at: Some(Utc::now()),
            minted_by_admin_id: None,
            at: Utc::now(),
            source_issuer: None,
            source_jti: None,
            source_sub: None,
        }
    }

    fn revoked() -> ApiTokenRevoked {
        ApiTokenRevoked {
            token_id: Uuid::from_u128(0x000A_CEF0),
            user_id: Uuid::from_u128(0xACE),
            revoked_by_admin_id: None,
            reason: RevokeReason::OperatorRequest,
            at: Utc::now(),
        }
    }

    fn denied() -> ApiTokenIssuanceDenied {
        ApiTokenIssuanceDenied {
            target_user_id: Uuid::from_u128(0xACE),
            requested_kind: TokenKind::Pat,
            requested_permissions: vec![Permission::Admin],
            requested_repository_ids: None,
            denial_reason: DenialReason::AdminTokenDisallowed,
            at: Utc::now(),
        }
    }

    // -- ApiTokenIssued -----------------------------------------------------

    #[test]
    fn issued_validate_returns_ok() {
        issued().validate().unwrap();
    }

    #[test]
    fn issued_serde_round_trip() {
        let original = issued();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: ApiTokenIssued = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn issued_payload_does_not_carry_pii_keys() {
        // Same belt-and-braces strip as AdminBootstrapped — the
        // serialised JSON object MUST NOT carry username / email /
        // password / hash keys, AND MUST NOT carry token /
        // token_hash / token_prefix keys (the wire-shape of the
        // token must never reach the audit log).
        let json = serde_json::to_string(&issued()).unwrap();
        for forbidden in [
            "\"username\"",
            "\"email\"",
            "\"password\"",
            "\"hash\"",
            "\"token\"",
            "\"token_hash\"",
            "\"token_prefix\"",
            "\"plaintext\"",
        ] {
            assert!(
                !json.contains(forbidden),
                "ApiTokenIssued JSON must not carry {forbidden}, got: {json}"
            );
        }
    }

    #[test]
    fn issued_repository_ids_none_serialises_as_null() {
        let original = ApiTokenIssued {
            repository_ids: None,
            ..issued()
        };
        let value: serde_json::Value = serde_json::to_value(&original).unwrap();
        assert!(value["repository_ids"].is_null());
    }

    #[test]
    fn issued_clone_eq() {
        let a = issued();
        let b = a.clone();
        assert_eq!(a, b);
    }

    // -- Federation-source fields --------------------------------------------
    //
    // The three optional fields (`source_issuer`, `source_jti`,
    // `source_sub`) are wire-additive. They MUST
    // round-trip cleanly when present, AND the encoded shape MUST
    // remain backward-compatible with older JSONB rows that
    // never wrote the keys.

    #[test]
    fn issued_federated_round_trips_with_all_three_source_fields() {
        let original = ApiTokenIssued {
            source_issuer: Some("github-actions".into()),
            source_jti: Some("e1b2c3d4-9999-4111-aaaa-bbbbccccdddd".into()),
            source_sub: Some("repo:my-org/my-repo:ref:refs/heads/main".into()),
            ..issued()
        };
        let json = serde_json::to_string(&original).unwrap();
        let decoded: ApiTokenIssued = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
        // Belt-and-braces — the three keys ARE in the wire shape when
        // populated; the skip-if-none attribute is for absence only.
        assert!(json.contains("\"source_issuer\""));
        assert!(json.contains("\"source_jti\""));
        assert!(json.contains("\"source_sub\""));
    }

    #[test]
    fn issued_non_federated_omits_source_fields_from_wire() {
        // The on-disk shape must stay compact for non-federated rows:
        // every existing PAT / service-account / refresh issuance path
        // populates the three new fields with `None`, and the
        // serialiser must drop the keys via
        // `skip_serializing_if = "Option::is_none"`. Otherwise every
        // historical row would be re-emitted with explicit
        // `"source_issuer": null` keys on the next migration, which
        // would diverge from the existing on-disk shape.
        let json = serde_json::to_string(&issued()).unwrap();
        assert!(
            !json.contains("\"source_issuer\""),
            "non-federated ApiTokenIssued JSON must omit source_issuer, got: {json}"
        );
        assert!(
            !json.contains("\"source_jti\""),
            "non-federated ApiTokenIssued JSON must omit source_jti, got: {json}"
        );
        assert!(
            !json.contains("\"source_sub\""),
            "non-federated ApiTokenIssued JSON must omit source_sub, got: {json}"
        );
    }

    #[test]
    fn issued_legacy_json_without_source_fields_deserialises_as_none() {
        // The load-bearing backward-compatibility contract:
        // existing JSONB rows in the `events` table predate the
        // three federation fields. The event store replays every
        // historical row through this `Deserialize` impl on subscribe,
        // so a row that NEVER wrote the keys must decode with `None`
        // values (not error).
        //
        // The fixture below is a hand-rolled JSON object containing
        // exactly the legacy key set — no `source_issuer`,
        // `source_jti`, or `source_sub`.
        let legacy_json = r#"{
            "token_id": "0000000a-cef0-0000-0000-000000000000",
            "user_id": "00000000-0000-0000-0000-000000000ace",
            "kind": "Pat",
            "declared_permissions": ["Read", "Write"],
            "repository_ids": ["0000000a-0000-0000-0000-000000000000"],
            "expires_at": "2026-05-13T12:00:00Z",
            "minted_by_admin_id": null,
            "at": "2026-05-13T12:00:00Z"
        }"#;
        let decoded: ApiTokenIssued = serde_json::from_str(legacy_json).unwrap();
        assert!(decoded.source_issuer.is_none());
        assert!(decoded.source_jti.is_none());
        assert!(decoded.source_sub.is_none());
        // Sanity — the rest of the payload is preserved.
        assert_eq!(decoded.kind, TokenKind::Pat);
        assert_eq!(decoded.declared_permissions.len(), 2);
    }

    #[test]
    fn issued_source_fields_round_trip_independently() {
        // Each of the three optional fields must round-trip on its own
        // — the federation handler may populate any subset (a JWT with
        // no `jti` claim still produces a federated bearer with
        // `source_issuer` + `source_sub` set and `source_jti = None`).
        let cases = [
            (Some("github-actions".into()), None, None),
            (None, Some("jti-only".into()), None),
            (None, None, Some("sub-only".into())),
            (
                Some("gitlab-ci".into()),
                None,
                Some("project:my-group/my-proj".into()),
            ),
        ];
        for (issuer, jti, sub) in cases {
            let original = ApiTokenIssued {
                source_issuer: issuer.clone(),
                source_jti: jti.clone(),
                source_sub: sub.clone(),
                ..issued()
            };
            let json = serde_json::to_string(&original).unwrap();
            let decoded: ApiTokenIssued = serde_json::from_str(&json).unwrap();
            assert_eq!(
                original, decoded,
                "subset (issuer={issuer:?}, jti={jti:?}, sub={sub:?})"
            );
        }
    }

    // -- ApiTokenRevoked ----------------------------------------------------

    #[test]
    fn revoked_validate_returns_ok() {
        revoked().validate().unwrap();
    }

    #[test]
    fn revoked_serde_round_trip() {
        let original = revoked();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: ApiTokenRevoked = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn revoked_admin_bulk_reason_round_trips() {
        let original = ApiTokenRevoked {
            reason: RevokeReason::AdminBulk,
            ..revoked()
        };
        let json = serde_json::to_string(&original).unwrap();
        let decoded: ApiTokenRevoked = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
        assert!(matches!(decoded.reason, RevokeReason::AdminBulk));
    }

    #[test]
    fn revoke_reason_clone_copy_eq() {
        let a = RevokeReason::OperatorRequest;
        let b = a;
        #[allow(clippy::clone_on_copy)]
        let c = a.clone();
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, RevokeReason::AdminBulk);
    }

    // -- ApiTokenIssuanceDenied --------------------------------------------

    #[test]
    fn denied_validate_returns_ok() {
        denied().validate().unwrap();
    }

    #[test]
    fn denied_serde_round_trip() {
        let original = denied();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: ApiTokenIssuanceDenied = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn denied_payload_does_not_carry_pii_or_token_keys() {
        let json = serde_json::to_string(&denied()).unwrap();
        for forbidden in [
            "\"username\"",
            "\"email\"",
            "\"password\"",
            "\"hash\"",
            "\"token\"",
            "\"token_hash\"",
            "\"plaintext\"",
        ] {
            assert!(
                !json.contains(forbidden),
                "ApiTokenIssuanceDenied JSON must not carry {forbidden}, got: {json}"
            );
        }
    }

    #[test]
    fn denial_reason_round_trips_every_variant() {
        // Every variant has to flow through serde without losing
        // discriminant identity — the audit consumer routes on
        // exact-match.
        let variants = [
            DenialReason::CapExceedsAuthority,
            DenialReason::ServiceAccountSelfMint,
            DenialReason::AdminTokenDisallowed,
            DenialReason::UnboundedSvcTokenDisallowed,
            DenialReason::InvalidRepositorySet,
            DenialReason::AdminTokenExceedsThirtyDays,
            DenialReason::NotServiceAccount,
        ];
        for r in variants {
            let original = ApiTokenIssuanceDenied {
                denial_reason: r,
                ..denied()
            };
            let json = serde_json::to_string(&original).unwrap();
            let decoded: ApiTokenIssuanceDenied = serde_json::from_str(&json).unwrap();
            assert_eq!(original, decoded);
        }
    }

    #[test]
    fn denial_reason_clone_copy_eq() {
        let a = DenialReason::CapExceedsAuthority;
        let b = a;
        #[allow(clippy::clone_on_copy)]
        let c = a.clone();
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, DenialReason::ServiceAccountSelfMint);
    }

    // -- ApiTokenUsed ---------------------------------------------------------

    fn used() -> ApiTokenUsed {
        ApiTokenUsed {
            token_id: Uuid::from_u128(0x000A_CEF0),
            user_id: Uuid::from_u128(0xACE),
            kind: TokenKind::Pat,
            occurred_at: Utc::now(),
        }
    }

    #[test]
    fn used_validate_returns_ok() {
        used().validate().unwrap();
    }

    #[test]
    fn used_serde_round_trip() {
        let original = used();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: ApiTokenUsed = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn used_clone_eq() {
        let a = used();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn used_kind_round_trips_every_variant() {
        // `kind` is part of the audit-routing contract (decision #3) —
        // every wire-form discriminator must survive serde without
        // losing identity so a SIEM can route on it.
        for k in [
            TokenKind::Pat,
            TokenKind::ServiceAccount,
            TokenKind::CliSession,
        ] {
            let original = ApiTokenUsed { kind: k, ..used() };
            let json = serde_json::to_string(&original).unwrap();
            let decoded: ApiTokenUsed = serde_json::from_str(&json).unwrap();
            assert_eq!(original, decoded);
            assert_eq!(decoded.kind, k);
        }
    }

    #[test]
    fn used_payload_does_not_carry_pii_or_token_keys() {
        // Same belt-and-braces strip as ApiTokenIssued — the
        // serialised JSON MUST NOT carry username / email / password /
        // hash / token / token_hash / token_prefix / plaintext keys.
        // A per-use audit fact is the highest-volume token event;
        // letting a credential shape leak here would be the worst
        // place for it.
        let json = serde_json::to_string(&used()).unwrap();
        for forbidden in [
            "\"username\"",
            "\"email\"",
            "\"password\"",
            "\"hash\"",
            "\"token\"",
            "\"token_hash\"",
            "\"token_prefix\"",
            "\"plaintext\"",
        ] {
            assert!(
                !json.contains(forbidden),
                "ApiTokenUsed JSON must not carry {forbidden}, got: {json}"
            );
        }
    }
}
