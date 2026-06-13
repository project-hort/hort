//! ServiceAccount lifecycle + rotation audit events (ADR 0018).
//!
//! Two event families:
//!
//! 1. **Lifecycle** — [`ServiceAccountCreated`], [`ServiceAccountUpdated`],
//!    [`ServiceAccountDeleted`]. Emitted by
//!    `ApplyConfigUseCase::apply_service_accounts` when
//!    the gitops apply path creates, updates, or deletes a
//!    [`ServiceAccount`](crate::entities::service_account::ServiceAccount).
//!    The aggregate is CRUD; these events are audit-only attribution.
//! 2. **Rotation** — [`ServiceAccountTokenRotated`]. Emitted by the
//!    `ServiceAccountRotationHandler` `TaskHandler`
//!    every time the reconciler mints a new fallback PAT and writes it
//!    to the target Secret. Load-bearing for audit: every issued PAT
//!    correlates back to a CRD-declared identity and rotation tick.
//!
//! Streams: lifecycle events naturally land on the same global
//! [`StreamCategory::Authorization`](super::StreamCategory::Authorization)
//! stream the rest of the apply-time authz mutations use; the rotation
//! event lands on the SA's backing-user stream
//! ([`StreamId::user`](super::StreamId::user)) alongside the
//! `ApiTokenIssued` it correlates with. Item 1's scope ends at the
//! payload struct; the apply use case and the rotation handler pick the
//! stream id.
//!
//! # No PII
//!
//! Same GDPR Art. 17 strip as the rest of the event vocabulary. The
//! payloads carry only ids and operator-chosen identifiers:
//! - `service_account_id` / `service_account_name` — foreign key into
//!   `service_accounts` + the operator-chosen identifier mirroring the
//!   CRD `metadata.name`.
//! - `token_id` (on `ServiceAccountTokenRotated`) — foreign key into
//!   `api_tokens`, NOT the token plaintext.
//! - Target Secret coordinates (`target_secret_namespace`,
//!   `target_secret_name`) — these are k8s resource names, not
//!   credentials. Carried verbatim so an audit consumer reading a stuck
//!   reconciler can tell which target diverged without joining the
//!   `service_accounts` row.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::service_account::SecretFormat;
use crate::error::DomainResult;

use super::validation::validate_string;

// ---------------------------------------------------------------------------
// Validation constants
// ---------------------------------------------------------------------------

/// Maximum allowed length of an OIDC-issuer or service-account `name`
/// across this event family. Same cap as the `oidc_issuer_events`
/// module (k8s `metadata.name` RFC 1123 DNS label semantics, ≤ 253
/// bytes; 256 byte cap gives a small safety margin).
const MAX_NAME_LEN: usize = 256;

/// Maximum allowed length of `ServiceAccountTokenRotated`'s
/// `target_secret_namespace`. k8s DNS label semantics, ≤ 253 bytes.
const MAX_NAMESPACE_LEN: usize = 253;

/// Maximum allowed length of `ServiceAccountTokenRotated`'s
/// `target_secret_name`. k8s DNS subdomain semantics, ≤ 253 bytes.
const MAX_SECRET_NAME_LEN: usize = 253;

// ---------------------------------------------------------------------------
// SerdeSecretFormat (wire-form shim)
// ---------------------------------------------------------------------------

/// Wire-form discriminator for [`SecretFormat`] inside event payloads.
///
/// [`SecretFormat`] intentionally does not derive `Deserialize` (the
/// trust-relationship-row guarantee on
/// [`crate::entities::service_account`]). The audit event log, on the
/// other hand, must round-trip through `serde::Deserialize` from JSONB
/// — the event store needs to replay it. This local shim is the
/// audit-only serialise/deserialise form; the conversion is total and
/// lossless because `SecretFormat` is a closed 2-variant enum.
///
/// Same shape as the existing `TokenKind` discriminator on
/// `ApiTokenIssued`: the entity carries semantic methods (`as_str`),
/// the event payload carries the wire-form discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SerdeSecretFormat {
    Dockerconfigjson,
    Opaque,
}

impl From<SecretFormat> for SerdeSecretFormat {
    fn from(value: SecretFormat) -> Self {
        match value {
            SecretFormat::Dockerconfigjson => Self::Dockerconfigjson,
            SecretFormat::Opaque => Self::Opaque,
        }
    }
}

impl From<SerdeSecretFormat> for SecretFormat {
    fn from(value: SerdeSecretFormat) -> Self {
        match value {
            SerdeSecretFormat::Dockerconfigjson => Self::Dockerconfigjson,
            SerdeSecretFormat::Opaque => Self::Opaque,
        }
    }
}

// ---------------------------------------------------------------------------
// ServiceAccountCreated
// ---------------------------------------------------------------------------

/// Recorded when `ApplyConfigUseCase::apply_service_accounts` minted a
/// new `service_accounts` row from a `kind: ServiceAccount` envelope.
///
/// The backing `users` row creation (with `is_service_account = true`
/// and `username = "sa:" || name`) is the same apply pass — its audit
/// flows through the existing user-creation path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceAccountCreated {
    pub service_account_id: Uuid,
    /// Operator-chosen identifier — mirrors the CRD `metadata.name`.
    pub service_account_name: String,
    /// Foreign key into `users`. The companion `users` row carries
    /// `is_service_account = true`.
    pub backing_user_id: Uuid,
    pub at: DateTime<Utc>,
}

impl ServiceAccountCreated {
    pub fn validate(&self) -> DomainResult<()> {
        validate_string(
            "ServiceAccountCreated.service_account_name",
            &self.service_account_name,
            MAX_NAME_LEN,
        )
    }
}

// ---------------------------------------------------------------------------
// ServiceAccountUpdated
// ---------------------------------------------------------------------------

/// Recorded when the apply pass updated an existing `service_accounts`
/// row — role, repositories, federated identities, or fallback rotation
/// changed for the matching `metadata.name`.
///
/// Identity is `service_account_name` (§3). Before/after values stay
/// out of the payload (see module docstring).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceAccountUpdated {
    pub service_account_id: Uuid,
    pub service_account_name: String,
    pub at: DateTime<Utc>,
}

impl ServiceAccountUpdated {
    pub fn validate(&self) -> DomainResult<()> {
        validate_string(
            "ServiceAccountUpdated.service_account_name",
            &self.service_account_name,
            MAX_NAME_LEN,
        )
    }
}

// ---------------------------------------------------------------------------
// ServiceAccountDeleted
// ---------------------------------------------------------------------------

/// Recorded when the apply pass removed a `service_accounts` row
/// because the matching envelope no longer appears in the declared
/// set.
///
/// The backing `users` row is NOT deleted — it is marked inactive and
/// existing `api_tokens` rows referencing it are revoked. The revoke
/// path emits its own `ApiTokenRevoked` events; this event records the
/// SA-side fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceAccountDeleted {
    pub service_account_id: Uuid,
    pub service_account_name: String,
    pub backing_user_id: Uuid,
    pub at: DateTime<Utc>,
}

impl ServiceAccountDeleted {
    pub fn validate(&self) -> DomainResult<()> {
        validate_string(
            "ServiceAccountDeleted.service_account_name",
            &self.service_account_name,
            MAX_NAME_LEN,
        )
    }
}

// ---------------------------------------------------------------------------
// ServiceAccountTokenRotated
// ---------------------------------------------------------------------------

/// Recorded every time the [`ServiceAccountRotationHandler`] mints a
/// new fallback PAT and writes it to the target k8s Secret.
///
/// Each rotation also produces an [`ApiTokenIssued`](super::ApiTokenIssued)
/// event on the backing-user's stream — the rotation event is the
/// reconciler-side correlated fact (target Secret coordinates, format).
/// The two events share an envelope `correlation_id`.
///
/// Lands on the backing-user's stream
/// ([`StreamId::user`](super::StreamId::user)) — same place as the
/// correlated `ApiTokenIssued`.
///
/// [`ServiceAccountRotationHandler`]:
/// ../../../hort_app/tasks/service_account_rotation/struct.ServiceAccountRotationHandler.html
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceAccountTokenRotated {
    pub service_account_id: Uuid,
    pub service_account_name: String,
    /// Foreign key into `api_tokens` — the row carrying the new
    /// rotated token. The token plaintext / hash / prefix are NEVER in
    /// the payload (same contract as `ApiTokenIssued`).
    pub token_id: Uuid,
    pub target_secret_namespace: String,
    pub target_secret_name: String,
    /// Wire-form `SecretFormat` discriminator. Domain-side construction
    /// uses the entity type via `From<SecretFormat>`; this is the
    /// audit-only round-trip shape.
    pub format: SerdeSecretFormat,
    pub at: DateTime<Utc>,
}

impl ServiceAccountTokenRotated {
    pub fn validate(&self) -> DomainResult<()> {
        validate_string(
            "ServiceAccountTokenRotated.service_account_name",
            &self.service_account_name,
            MAX_NAME_LEN,
        )?;
        validate_string(
            "ServiceAccountTokenRotated.target_secret_namespace",
            &self.target_secret_namespace,
            MAX_NAMESPACE_LEN,
        )?;
        validate_string(
            "ServiceAccountTokenRotated.target_secret_name",
            &self.target_secret_name,
            MAX_SECRET_NAME_LEN,
        )?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn created() -> ServiceAccountCreated {
        ServiceAccountCreated {
            service_account_id: Uuid::from_u128(0x5A1_u128),
            service_account_name: "ci-pypi-pusher".into(),
            backing_user_id: Uuid::from_u128(0xACE),
            at: Utc::now(),
        }
    }

    fn updated() -> ServiceAccountUpdated {
        ServiceAccountUpdated {
            service_account_id: Uuid::from_u128(0x5A1_u128),
            service_account_name: "ci-pypi-pusher".into(),
            at: Utc::now(),
        }
    }

    fn deleted() -> ServiceAccountDeleted {
        ServiceAccountDeleted {
            service_account_id: Uuid::from_u128(0x5A1_u128),
            service_account_name: "ci-pypi-pusher".into(),
            backing_user_id: Uuid::from_u128(0xACE),
            at: Utc::now(),
        }
    }

    fn rotated() -> ServiceAccountTokenRotated {
        ServiceAccountTokenRotated {
            service_account_id: Uuid::from_u128(0x5A1_u128),
            service_account_name: "ci-pypi-pusher".into(),
            token_id: Uuid::from_u128(0xACEF0),
            target_secret_namespace: "ci-system".into(),
            target_secret_name: "ci-hort-token".into(),
            format: SerdeSecretFormat::Dockerconfigjson,
            at: Utc::now(),
        }
    }

    // -- SerdeSecretFormat conversions --------------------------------------

    #[test]
    fn serde_secret_format_round_trip_dockerconfigjson() {
        let domain = SecretFormat::Dockerconfigjson;
        let wire: SerdeSecretFormat = domain.into();
        let back: SecretFormat = wire.into();
        assert_eq!(domain, back);
    }

    #[test]
    fn serde_secret_format_round_trip_opaque() {
        let domain = SecretFormat::Opaque;
        let wire: SerdeSecretFormat = domain.into();
        let back: SecretFormat = wire.into();
        assert_eq!(domain, back);
    }

    #[test]
    fn serde_secret_format_serialises_as_snake_case() {
        // The reconciler audit log is read by operators — the wire
        // shape must be lower-snake-case to match the CRD `format:`
        // field and the rest of the gitops vocabulary.
        let json = serde_json::to_string(&SerdeSecretFormat::Dockerconfigjson).unwrap();
        assert_eq!(json, "\"dockerconfigjson\"");
        let json = serde_json::to_string(&SerdeSecretFormat::Opaque).unwrap();
        assert_eq!(json, "\"opaque\"");
    }

    #[test]
    fn serde_secret_format_serde_round_trip_each_variant() {
        for variant in [
            SerdeSecretFormat::Dockerconfigjson,
            SerdeSecretFormat::Opaque,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let decoded: SerdeSecretFormat = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, decoded);
        }
    }

    // -- ServiceAccountCreated ----------------------------------------------

    #[test]
    fn created_validate_returns_ok() {
        created().validate().unwrap();
    }

    #[test]
    fn created_validate_rejects_empty_name() {
        let e = ServiceAccountCreated {
            service_account_name: String::new(),
            ..created()
        };
        assert!(e.validate().is_err());
    }

    #[test]
    fn created_validate_rejects_overlong_name() {
        let e = ServiceAccountCreated {
            service_account_name: "x".repeat(MAX_NAME_LEN + 1),
            ..created()
        };
        assert!(e.validate().is_err());
    }

    #[test]
    fn created_serde_round_trip() {
        let original = created();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: ServiceAccountCreated = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn created_clone_eq() {
        let a = created();
        let b = a.clone();
        assert_eq!(a, b);
    }

    // -- ServiceAccountUpdated ----------------------------------------------

    #[test]
    fn updated_validate_returns_ok() {
        updated().validate().unwrap();
    }

    #[test]
    fn updated_validate_rejects_empty_name() {
        let e = ServiceAccountUpdated {
            service_account_name: String::new(),
            ..updated()
        };
        assert!(e.validate().is_err());
    }

    #[test]
    fn updated_validate_rejects_overlong_name() {
        let e = ServiceAccountUpdated {
            service_account_name: "x".repeat(MAX_NAME_LEN + 1),
            ..updated()
        };
        assert!(e.validate().is_err());
    }

    #[test]
    fn updated_serde_round_trip() {
        let original = updated();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: ServiceAccountUpdated = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn updated_clone_eq() {
        let a = updated();
        let b = a.clone();
        assert_eq!(a, b);
    }

    // -- ServiceAccountDeleted ----------------------------------------------

    #[test]
    fn deleted_validate_returns_ok() {
        deleted().validate().unwrap();
    }

    #[test]
    fn deleted_validate_rejects_empty_name() {
        let e = ServiceAccountDeleted {
            service_account_name: String::new(),
            ..deleted()
        };
        assert!(e.validate().is_err());
    }

    #[test]
    fn deleted_validate_rejects_overlong_name() {
        let e = ServiceAccountDeleted {
            service_account_name: "x".repeat(MAX_NAME_LEN + 1),
            ..deleted()
        };
        assert!(e.validate().is_err());
    }

    #[test]
    fn deleted_serde_round_trip() {
        let original = deleted();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: ServiceAccountDeleted = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn deleted_clone_eq() {
        let a = deleted();
        let b = a.clone();
        assert_eq!(a, b);
    }

    // -- ServiceAccountTokenRotated -----------------------------------------

    #[test]
    fn rotated_validate_returns_ok() {
        rotated().validate().unwrap();
    }

    #[test]
    fn rotated_validate_rejects_empty_name() {
        let e = ServiceAccountTokenRotated {
            service_account_name: String::new(),
            ..rotated()
        };
        assert!(e.validate().is_err());
    }

    #[test]
    fn rotated_validate_rejects_overlong_name() {
        let e = ServiceAccountTokenRotated {
            service_account_name: "x".repeat(MAX_NAME_LEN + 1),
            ..rotated()
        };
        assert!(e.validate().is_err());
    }

    #[test]
    fn rotated_validate_rejects_empty_namespace() {
        let e = ServiceAccountTokenRotated {
            target_secret_namespace: String::new(),
            ..rotated()
        };
        assert!(e.validate().is_err());
    }

    #[test]
    fn rotated_validate_rejects_overlong_namespace() {
        let e = ServiceAccountTokenRotated {
            target_secret_namespace: "x".repeat(MAX_NAMESPACE_LEN + 1),
            ..rotated()
        };
        assert!(e.validate().is_err());
    }

    #[test]
    fn rotated_validate_rejects_empty_secret_name() {
        let e = ServiceAccountTokenRotated {
            target_secret_name: String::new(),
            ..rotated()
        };
        assert!(e.validate().is_err());
    }

    #[test]
    fn rotated_validate_rejects_overlong_secret_name() {
        let e = ServiceAccountTokenRotated {
            target_secret_name: "x".repeat(MAX_SECRET_NAME_LEN + 1),
            ..rotated()
        };
        assert!(e.validate().is_err());
    }

    #[test]
    fn rotated_serde_round_trip() {
        let original = rotated();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: ServiceAccountTokenRotated = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn rotated_serde_round_trip_opaque_format() {
        let original = ServiceAccountTokenRotated {
            format: SerdeSecretFormat::Opaque,
            ..rotated()
        };
        let json = serde_json::to_string(&original).unwrap();
        let decoded: ServiceAccountTokenRotated = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn rotated_clone_eq() {
        let a = rotated();
        let b = a.clone();
        assert_eq!(a, b);
    }

    // -- No-PII / no-secret contract ----------------------------------------

    #[test]
    fn sa_events_never_carry_secrets_or_token_material() {
        for json in [
            serde_json::to_string(&created()).unwrap(),
            serde_json::to_string(&updated()).unwrap(),
            serde_json::to_string(&deleted()).unwrap(),
            serde_json::to_string(&rotated()).unwrap(),
        ] {
            for forbidden in [
                "\"token\"",
                "\"token_hash\"",
                "\"token_prefix\"",
                "\"plaintext\"",
                "\"password\"",
                "\"client_secret\"",
                "\"private_key\"",
            ] {
                assert!(
                    !json.contains(forbidden),
                    "SA event JSON must not carry {forbidden}, got: {json}"
                );
            }
        }
    }
}
