//! ServiceAccount entity and friends (ADR 0018 + `docs/auth-catalog.md`).
//!
//! Declares a non-human identity that hort-server may federate to (via
//! [`FederatedIdentity`]) and/or rotate a Kubernetes Secret for (via
//! [`FallbackRotation`]). Either, both, or neither sub-block may be set
//! — the "neither" case is a PAT-only identity an operator mints via
//! `hort-cli admin token issue`.
//!
//! Backed by a `users` row with `is_service_account = true` and
//! `username = "sa:" || sa.name`. The prefix prevents collisions with
//! human usernames (the `users.username UNIQUE` constraint).
//!
//! # Invariants
//!
//! - **No `Deserialize` impl** on [`ServiceAccount`],
//!   [`FederatedIdentity`], [`FallbackRotation`], or [`SecretFormat`].
//!   Same anti-pattern rule as [`OidcIssuer`](super::oidc_issuer::OidcIssuer)
//!   and [`ApiToken`](super::api_token::ApiToken) — the persisted-trust
//!   row must never be reconstructible from untrusted JSON. The
//!   adapter row mapper and `ApplyConfigUseCase::apply_service_accounts`
//!   are the canonical constructors.
//! - **No `Serialize` impl either.** Matches the `ApiToken` / `OidcIssuer`
//!   precedent — HTTP layers project to handler-specific response DTOs.
//! - **No I/O imports.** `hort-domain` is pure Rust; the file imports
//!   only `chrono`, `uuid`, `std::collections::BTreeMap`, and
//!   `std::time::Duration`.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::DomainError;

// ---------------------------------------------------------------------------
// SecretFormat
// ---------------------------------------------------------------------------

/// Wire-format the [`FallbackRotation`] reconciler writes the rotated
/// PAT into.
///
/// Two formats:
/// - [`SecretFormat::Dockerconfigjson`] — `type:
///   kubernetes.io/dockerconfigjson` Secret consumable by k8s
///   `imagePullSecrets` for OCI pull workflows.
/// - [`SecretFormat::Opaque`] — a plain `type: Opaque` Secret with a
///   `token` key. Suited to non-OCI consumers (CI runners, generic
///   clients).
///
/// `Copy + Eq + Hash` so the reconciler can use it as a routing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretFormat {
    Dockerconfigjson,
    Opaque,
}

impl SecretFormat {
    /// Wire form used by the CRD (`format:` field) and the reconciler
    /// audit event payload. Lower-snake-case matches the existing
    /// gitops kind conventions.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Dockerconfigjson => "dockerconfigjson",
            Self::Opaque => "opaque",
        }
    }
}

/// Parse the wire-form `format` string from
/// `service_account_fallback_rotations.format` into [`SecretFormat`].
///
/// The DB CHECK constraint pins the column to
/// `('dockerconfigjson','opaque')`; unknown literals therefore mean
/// out-of-band SQL has touched the row and the mapper should surface
/// the corruption as [`DomainError::Invariant`].
impl FromStr for SecretFormat {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "dockerconfigjson" => Ok(Self::Dockerconfigjson),
            "opaque" => Ok(Self::Opaque),
            other => Err(DomainError::Validation(format!(
                "unknown secret format: {other}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// FederatedIdentity
// ---------------------------------------------------------------------------

/// One trust relationship between a [`ServiceAccount`] and an
/// [`OidcIssuer`](super::oidc_issuer::OidcIssuer).
///
/// A federated JWT may assume the SA only when:
/// 1. `issuer_name` matches the validated issuer's
///    [`OidcIssuer.name`](super::oidc_issuer::OidcIssuer), AND
/// 2. **Every** `(key, value)` pair in `claims` matches the JWT's
///    payload exactly (string equality only — regex / jq matching is
///    deliberately out of scope).
///
/// `claims` is a [`BTreeMap`] so the matching pass and the event-
/// audit serialisation are both order-stable. Apply-time validation
/// rejects an empty `claims` map — an empty exact-match set means
/// "any JWT from this issuer can assume me," which is a privilege-
/// escalation footgun (see the anti-patterns checklist in `CLAUDE.md`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederatedIdentity {
    pub issuer_name: String,
    /// Exact-match claim fragment. Empty maps are rejected by apply-
    /// time validation in
    /// [`hort_config::service_account`](../../../../../hort-config/src/service_account.rs) —
    /// see the `validate_federated_identity_claims_non_empty` rule
    /// there. An empty claims map would match every JWT from the
    /// issuer — a privilege-escalation footgun. This field's invariant
    /// lives at the apply layer, not in the domain constructor (the
    /// domain struct represents the post-validation shape).
    pub claims: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// FallbackRotation
// ---------------------------------------------------------------------------

/// Reconciler target for the fallback PAT-rotation path.
///
/// The reconciler (`ServiceAccountRotationHandler`) reads
/// `(target_secret_namespace, target_secret_name)` from k8s, mints
/// a new PAT when the stored secret is stale, and writes the new token
/// in the declared `format`. Tokens overlap to bound consumer reload
/// latency — `validity ≥ 2 × rotation_interval`.
///
/// `rotation_interval` minimum: 1h. `validity` minimum: 2 ×
/// `rotation_interval`. Both rules are apply-time invariants; the
/// domain struct represents the post-validation shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FallbackRotation {
    pub target_secret_name: String,
    pub target_secret_namespace: String,
    pub format: SecretFormat,
    pub rotation_interval: Duration,
    pub validity: Duration,
}

// ---------------------------------------------------------------------------
// ServiceAccount
// ---------------------------------------------------------------------------

/// A non-human identity (ADR 0018 + `docs/auth-catalog.md`).
///
/// Construction is restricted to the adapter row mapper and the apply
/// use case — see the module-level invariants on `Deserialize`.
///
/// Field notes:
/// - `name` matches the CRD `metadata.name`. The backing `users` row's
///   `username` is `"sa:" || sa.name`.
/// - `backing_user_id` points at the `users` row carrying
///   `is_service_account = true`. Authz evaluation flows through the
///   same `RbacEvaluator::authorize` path as human users — the SA's
///   grants are regular `permission_grants` rows.
/// - `role` constrained to {`developer`, `reader`} at apply time.
///   Admin SAs are forbidden by design — admin authority is reserved
///   for short-lived interactive sessions (ADR 0013).
/// - `repositories` is the per-repo grant scope. Non-empty at apply
///   time — no global service-account grants.
/// - `federated_identities` and `fallback_rotation` are optional and
///   independent. The "neither" case is a PAT-only SA an operator
///   manages with `hort-cli admin token issue`.
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceAccount {
    pub id: Uuid,
    pub name: String,
    /// FK into `users.id` with the `is_service_account = true`
    /// invariant: every SA aggregate points at a backing `users` row
    /// whose `is_service_account` column is `true` (the schema enforces
    /// this with a CHECK + the `service_accounts.backing_user_id`
    /// REFERENCES with `ON DELETE RESTRICT`, so the backing row cannot
    /// be deleted out from under the SA). Apply-only writer: the only
    /// path that creates / mutates SA rows is `apply_service_accounts`
    /// in the apply use case; inbound HTTP never writes here. The trio
    /// (is_service_account flag + ON DELETE RESTRICT + apply-only
    /// writer) is documented here so a future caller doesn't reach for
    /// a side door.
    pub backing_user_id: Uuid,
    pub role: String,
    pub repositories: Vec<String>,
    pub federated_identities: Vec<FederatedIdentity>,
    pub fallback_rotation: Option<FallbackRotation>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- SecretFormat --------------------------------------------------------

    #[test]
    fn secret_format_as_str_covers_every_variant() {
        assert_eq!(SecretFormat::Dockerconfigjson.as_str(), "dockerconfigjson");
        assert_eq!(SecretFormat::Opaque.as_str(), "opaque");
    }

    #[test]
    fn secret_format_clone_copy_eq() {
        let a = SecretFormat::Dockerconfigjson;
        let b = a;
        #[allow(clippy::clone_on_copy)]
        let c = a.clone();
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, SecretFormat::Opaque);
    }

    #[test]
    fn secret_format_from_str_round_trip() {
        for variant in [SecretFormat::Dockerconfigjson, SecretFormat::Opaque] {
            assert_eq!(SecretFormat::from_str(variant.as_str()).unwrap(), variant);
        }
    }

    #[test]
    fn secret_format_from_str_rejects_unknown() {
        let err = SecretFormat::from_str("yaml").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("yaml"));
    }

    #[test]
    fn secret_format_from_str_is_case_sensitive() {
        // The DB CHECK is lowercase-only; mirror it here so an
        // out-of-band uppercase write surfaces as Validation rather
        // than silently coercing.
        let err = SecretFormat::from_str("Dockerconfigjson").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn secret_format_from_str_rejects_empty() {
        let err = SecretFormat::from_str("").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    // -- FederatedIdentity ---------------------------------------------------

    fn sample_federated() -> FederatedIdentity {
        let mut claims = BTreeMap::new();
        claims.insert("repository".into(), "my-org/my-repo".into());
        claims.insert("environment".into(), "production".into());
        FederatedIdentity {
            issuer_name: "github-actions".into(),
            claims,
        }
    }

    #[test]
    fn federated_identity_clone_eq() {
        let a = sample_federated();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn federated_identity_btreemap_is_order_stable() {
        // BTreeMap key iteration is sorted — exercised because the
        // federation-branch matcher walks claims in deterministic
        // order and the audit event serialises this map.
        let fi = sample_federated();
        let keys: Vec<&String> = fi.claims.keys().collect();
        assert_eq!(keys, vec!["environment", "repository"]);
    }

    // -- FallbackRotation ----------------------------------------------------

    fn sample_rotation() -> FallbackRotation {
        FallbackRotation {
            target_secret_name: "ci-hort-token".into(),
            target_secret_namespace: "ci-system".into(),
            format: SecretFormat::Dockerconfigjson,
            rotation_interval: Duration::from_secs(6 * 3600),
            validity: Duration::from_secs(24 * 3600),
        }
    }

    #[test]
    fn fallback_rotation_clone_eq() {
        let a = sample_rotation();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn fallback_rotation_opaque_format_distinct() {
        let opaque = FallbackRotation {
            format: SecretFormat::Opaque,
            ..sample_rotation()
        };
        assert_ne!(sample_rotation(), opaque);
    }

    // -- ServiceAccount ------------------------------------------------------

    fn sample_sa() -> ServiceAccount {
        ServiceAccount {
            id: Uuid::nil(),
            name: "ci-pypi-pusher".into(),
            backing_user_id: Uuid::from_u128(1),
            role: "developer".into(),
            repositories: vec!["pypi-internal".into()],
            federated_identities: vec![sample_federated()],
            fallback_rotation: Some(sample_rotation()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn service_account_clone_eq() {
        let a = sample_sa();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn service_account_federation_only_shape() {
        // Federation-only is a valid shape (no fallback Secret).
        let sa = ServiceAccount {
            fallback_rotation: None,
            ..sample_sa()
        };
        assert!(sa.fallback_rotation.is_none());
        assert!(!sa.federated_identities.is_empty());
    }

    #[test]
    fn service_account_rotation_only_shape() {
        // Rotation-only is a valid shape (PAT for legacy CI that
        // can't do OIDC).
        let sa = ServiceAccount {
            federated_identities: vec![],
            ..sample_sa()
        };
        assert!(sa.federated_identities.is_empty());
        assert!(sa.fallback_rotation.is_some());
    }

    #[test]
    fn service_account_neither_block_shape() {
        // "Neither" is a valid shape — a PAT-only SA the operator
        // mints via `hort-cli admin token issue`.
        let sa = ServiceAccount {
            federated_identities: vec![],
            fallback_rotation: None,
            ..sample_sa()
        };
        assert!(sa.federated_identities.is_empty());
        assert!(sa.fallback_rotation.is_none());
    }

    // Compile-time invariants — none of these structs may implement
    // `Deserialize`. The persisted-trust-row must never be
    // reconstructible from untrusted JSON. Mirrors `ApiToken` and
    // `OidcIssuer`.
    static_assertions::assert_not_impl_any!(ServiceAccount: serde::de::DeserializeOwned);
    static_assertions::assert_not_impl_any!(FederatedIdentity: serde::de::DeserializeOwned);
    static_assertions::assert_not_impl_any!(FallbackRotation: serde::de::DeserializeOwned);
    static_assertions::assert_not_impl_any!(SecretFormat: serde::de::DeserializeOwned);
}
