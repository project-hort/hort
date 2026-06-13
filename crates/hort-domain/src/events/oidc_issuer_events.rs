//! OIDC-issuer lifecycle audit events (ADR 0018).
//!
//! Emitted by `ApplyConfigUseCase::apply_oidc_issuers`
//! when the gitops apply path creates, updates, or deletes an
//! [`OidcIssuer`](crate::entities::oidc_issuer::OidcIssuer). The
//! aggregate is CRUD — these events are audit-only attribution, not a
//! state-reconstruction stream (§2).
//!
//! Streams: the design doc leaves stream placement to Item 3's apply
//! path; the natural fit is the global
//! [`StreamCategory::Authorization`](super::StreamCategory::Authorization)
//! stream where the other apply-time authz mutations already land.
//! This module's scope ends at the payload struct; the
//! `StreamId` selection is the apply use case's responsibility.
//!
//! # No PII
//!
//! Per the project's GDPR Art. 17 strip applied to admin / token-attribution
//! events, OIDC-issuer events carry only:
//! - `issuer_id` (Uuid) — foreign key into the `oidc_issuers` table.
//! - `name` (String) — operator-chosen identifier, mirrors the CRD
//!   `metadata.name`. Not PII; it appears in operator audit logs as the
//!   trust-relationship identifier.
//!
//! The issuer URL, audiences, allowed algorithms, and JWKS refresh
//! interval are intentionally NOT in the payload — they are recoverable
//! by joining the `oidc_issuers` row at audit-read time, and putting
//! them in the immutable event would force a re-emission cascade on
//! every spec edit. The actor lives on the
//! [`PersistedEvent`](super::PersistedEvent) envelope (gitops apply
//! attribution).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::DomainResult;

use super::validation::validate_string;

// ---------------------------------------------------------------------------
// Validation constants
// ---------------------------------------------------------------------------

/// Maximum allowed length of an OIDC-issuer or service-account `name`
/// across every event in this family.
///
/// `oidc_issuers.name` and `service_accounts.name` mirror k8s
/// `metadata.name` — RFC 1123 DNS label semantics, ≤ 253 bytes. 256
/// gives a small safety margin without inviting payload bloat. The
/// schema enforces the same cap at the
/// column level.
const MAX_NAME_LEN: usize = 256;

// ---------------------------------------------------------------------------
// OidcIssuerCreated
// ---------------------------------------------------------------------------

/// Recorded when `ApplyConfigUseCase::apply_oidc_issuers` minted a new
/// `oidc_issuers` row from a `kind: OidcIssuer` envelope.
///
/// Companion to [`OidcIssuerUpdated`] (existing row, non-identity field
/// changed) and [`OidcIssuerDeleted`] (envelope removed from the
/// declared set).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcIssuerCreated {
    /// Primary key of the row inserted into `oidc_issuers`.
    pub issuer_id: Uuid,
    /// Operator-chosen identifier — mirrors the CRD `metadata.name`.
    /// Length-validated against the schema's column cap.
    pub name: String,
    /// Server-wall-clock at the moment the apply pass completed. Same
    /// convention as `AdminBootstrapped.at`.
    pub at: DateTime<Utc>,
}

impl OidcIssuerCreated {
    pub fn validate(&self) -> DomainResult<()> {
        validate_string("OidcIssuerCreated.name", &self.name, MAX_NAME_LEN)
    }
}

// ---------------------------------------------------------------------------
// OidcIssuerUpdated
// ---------------------------------------------------------------------------

/// Recorded when the apply pass updated an existing `oidc_issuers` row
/// — issuer URL, audiences, refresh interval, or allowed algorithms
/// changed for the matching `metadata.name`.
///
/// Identity is `name` (§3 — issuer-URL changes are treated as Updated,
/// not Created+Deleted, to preserve audit continuity). The before/after
/// values stay out of the payload by design — see the module docstring
/// (recoverable via the row + future `events` row's `at` join).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcIssuerUpdated {
    pub issuer_id: Uuid,
    pub name: String,
    pub at: DateTime<Utc>,
}

impl OidcIssuerUpdated {
    pub fn validate(&self) -> DomainResult<()> {
        validate_string("OidcIssuerUpdated.name", &self.name, MAX_NAME_LEN)
    }
}

// ---------------------------------------------------------------------------
// OidcIssuerDeleted
// ---------------------------------------------------------------------------

/// Recorded when the apply pass removed an `oidc_issuers` row because
/// the matching `kind: OidcIssuer` envelope no longer appears in the
/// declared set.
///
/// The row's foreign keys (referencing service-account
/// `federated_identities[].issuer_name`) are validated by the apply
/// use case before deletion — an issuer with live FK references is not
/// deleted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcIssuerDeleted {
    pub issuer_id: Uuid,
    pub name: String,
    pub at: DateTime<Utc>,
}

impl OidcIssuerDeleted {
    pub fn validate(&self) -> DomainResult<()> {
        validate_string("OidcIssuerDeleted.name", &self.name, MAX_NAME_LEN)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn created() -> OidcIssuerCreated {
        OidcIssuerCreated {
            issuer_id: Uuid::from_u128(0x1A55_0E10),
            name: "github-actions".into(),
            at: Utc::now(),
        }
    }

    fn updated() -> OidcIssuerUpdated {
        OidcIssuerUpdated {
            issuer_id: Uuid::from_u128(0x1A55_0E10),
            name: "github-actions".into(),
            at: Utc::now(),
        }
    }

    fn deleted() -> OidcIssuerDeleted {
        OidcIssuerDeleted {
            issuer_id: Uuid::from_u128(0x1A55_0E10),
            name: "github-actions".into(),
            at: Utc::now(),
        }
    }

    // -- OidcIssuerCreated --------------------------------------------------

    #[test]
    fn created_validate_returns_ok() {
        created().validate().unwrap();
    }

    #[test]
    fn created_validate_rejects_empty_name() {
        let e = OidcIssuerCreated {
            name: String::new(),
            ..created()
        };
        assert!(e.validate().is_err());
    }

    #[test]
    fn created_validate_rejects_overlong_name() {
        let e = OidcIssuerCreated {
            name: "x".repeat(MAX_NAME_LEN + 1),
            ..created()
        };
        assert!(e.validate().is_err());
    }

    #[test]
    fn created_serde_round_trip() {
        let original = created();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: OidcIssuerCreated = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn created_clone_eq() {
        let a = created();
        let b = a.clone();
        assert_eq!(a, b);
    }

    // -- OidcIssuerUpdated --------------------------------------------------

    #[test]
    fn updated_validate_returns_ok() {
        updated().validate().unwrap();
    }

    #[test]
    fn updated_validate_rejects_empty_name() {
        let e = OidcIssuerUpdated {
            name: String::new(),
            ..updated()
        };
        assert!(e.validate().is_err());
    }

    #[test]
    fn updated_validate_rejects_overlong_name() {
        let e = OidcIssuerUpdated {
            name: "x".repeat(MAX_NAME_LEN + 1),
            ..updated()
        };
        assert!(e.validate().is_err());
    }

    #[test]
    fn updated_serde_round_trip() {
        let original = updated();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: OidcIssuerUpdated = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn updated_clone_eq() {
        let a = updated();
        let b = a.clone();
        assert_eq!(a, b);
    }

    // -- OidcIssuerDeleted --------------------------------------------------

    #[test]
    fn deleted_validate_returns_ok() {
        deleted().validate().unwrap();
    }

    #[test]
    fn deleted_validate_rejects_empty_name() {
        let e = OidcIssuerDeleted {
            name: String::new(),
            ..deleted()
        };
        assert!(e.validate().is_err());
    }

    #[test]
    fn deleted_validate_rejects_overlong_name() {
        let e = OidcIssuerDeleted {
            name: "x".repeat(MAX_NAME_LEN + 1),
            ..deleted()
        };
        assert!(e.validate().is_err());
    }

    #[test]
    fn deleted_serde_round_trip() {
        let original = deleted();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: OidcIssuerDeleted = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn deleted_clone_eq() {
        let a = deleted();
        let b = a.clone();
        assert_eq!(a, b);
    }

    // -- No-PII contract ----------------------------------------------------

    #[test]
    fn issuer_events_never_carry_secrets_or_jwks_material() {
        // Belt-and-braces strip: the immutable event log must not
        // accumulate operator secrets or JWKS material. The audit
        // value lives in the row + the actor on the envelope.
        for json in [
            serde_json::to_string(&created()).unwrap(),
            serde_json::to_string(&updated()).unwrap(),
            serde_json::to_string(&deleted()).unwrap(),
        ] {
            for forbidden in [
                "\"jwks\"",
                "\"private_key\"",
                "\"client_secret\"",
                "\"password\"",
                "\"token\"",
                "\"issuer_url\"",
                "\"audiences\"",
            ] {
                assert!(
                    !json.contains(forbidden),
                    "issuer event JSON must not carry {forbidden}, got: {json}"
                );
            }
        }
    }
}
