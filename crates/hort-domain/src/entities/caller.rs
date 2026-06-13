use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::entities::api_token::{TokenCap, TokenKind};

// ---------------------------------------------------------------------------
// CallerPrincipal
// ---------------------------------------------------------------------------

/// The authenticated caller carried through the request pipeline.
///
/// Middleware constructs this after validating the bearer token (IdP-issued
/// or registry-minted). See ADR 0012 and `docs/auth-catalog.md`.
///
/// # Fields
///
/// - `user_id` — stable DB-row ID, JIT-provisioned on first IdP login.
/// - `external_id` — the `sub` claim from the IdP, opaque to everyone
///   except the adapter that issued it.
/// - `claims` — the caller's **resolved claim set** (ADR 0012). For
///   OIDC / CLI-session principals it is the IdP `groups` claim
///   flattened through the `claim_mappings` table by
///   `hort-app::rbac::resolve_claims`; for PAT-authenticated principals
///   it is at most `["admin"]` (the synthetic claim derived from
///   `user.is_admin=true` — long-lived static tokens stay
///   under-privileged by design). The admin short-circuit fires on
///   `claims.contains("admin")` — see `RbacEvaluator::authorize`. A
///   `Claims(_)` grant is satisfied when its required set is a subset
///   of this field; claim *names* are never logged (operator-authored,
///   may carry organisational topology).
/// - `token_kind` — `Some(kind)` when the principal arrived via a native
///   API token (PAT / cli-session / service-account / refresh), `None`
///   for OIDC-bearer, local-session, and dispatcher-synthesised
///   principals. Keeping it a typed field (not a string in `claims`) is
///   load-bearing — runtime-invented claim names are forbidden
///   (ADR 0012), and a token-kind string sitting next to real claims
///   could accidentally satisfy a `Claims([..])` grant. The evaluator
///   never sees it.
/// - `issued_at` — when this principal was authenticated (not when the
///   underlying token was issued; for registry-minted tokens these
///   coincide, for IdP tokens they differ).
/// - `token_cap` — `Some(cap)` when the principal arrived via a native
///   API token (PAT / service-account / cli-session); `None` for
///   OIDC-bearer or local-session principals. The cap is intersected
///   AND-style with the user's grants by `RbacEvaluator::authorize`.
///   The cap field is fixed at issuance and never widens at runtime;
///   the user's grant set is re-resolved live so revoking a grant drops
///   the token's effective authority on the next call.
///
/// # Intentionally NOT `Deserialize`
///
/// `CallerPrincipal` represents a *validated* identity. Deriving
/// `Deserialize` would make it constructible from arbitrary request input
/// (body, query string, headers), opening an identity-spoofing vector:
/// any handler accepting a deserializable payload would accept a forged
/// principal. Per the hort-domain anti-patterns checklist, principal types
/// are server-constructed from validated tokens only. The type is
/// populated in request extensions by the auth middleware and extracted
/// by handlers — never deserialised from the wire.
#[derive(Debug, Clone, PartialEq)]
pub struct CallerPrincipal {
    pub user_id: Uuid,
    pub external_id: String,
    pub username: String,
    pub email: String,
    /// Resolved claim set. Subset-checked against `GrantSubject::Claims`
    /// by the evaluator; carries the synthetic `admin` claim when
    /// applicable.
    pub claims: Vec<String>,
    /// Typed token-kind marker. `None` for OIDC / local-session /
    /// dispatcher-synthesised principals. Never a claim.
    pub token_kind: Option<TokenKind>,
    pub issued_at: DateTime<Utc>,
    pub token_cap: Option<TokenCap>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::rbac::Permission;

    fn sample_principal() -> CallerPrincipal {
        CallerPrincipal {
            user_id: Uuid::from_u128(0x1000),
            external_id: "keycloak:realm-users:abc-123".into(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            claims: vec!["developer".into(), "admin".into()],
            token_kind: None,
            issued_at: Utc::now(),
            token_cap: None,
        }
    }

    #[test]
    fn caller_principal_construction() {
        let p = sample_principal();
        assert_eq!(p.user_id, Uuid::from_u128(0x1000));
        assert_eq!(p.external_id, "keycloak:realm-users:abc-123");
        assert_eq!(p.username, "alice");
        assert_eq!(p.email, "alice@example.com");
        assert_eq!(p.claims.len(), 2);
        assert!(p.claims.contains(&"admin".to_string()));
        // OIDC-bearer / local-session principals carry no token kind.
        assert!(p.token_kind.is_none());
        // Non-token-validated principals (OIDC bearer, local session)
        // default to `token_cap = None`.
        assert!(p.token_cap.is_none());
    }

    #[test]
    fn caller_principal_clone_eq() {
        let a = sample_principal();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn caller_principal_empty_claims_are_allowed() {
        // A non-admin PAT-authenticated principal arrives with
        // `claims: []`. The local-auth bootstrap admin gets the
        // synthetic `["admin"]` claim instead (ADR 0012).
        let p = CallerPrincipal {
            user_id: Uuid::from_u128(1),
            external_id: "local:admin".into(),
            username: "admin".into(),
            email: "admin@example.com".into(),
            claims: vec!["admin".into()],
            token_kind: Some(TokenKind::Pat),
            issued_at: Utc::now(),
            token_cap: None,
        };
        assert_eq!(p.claims, vec!["admin".to_string()]);
        assert_eq!(p.token_kind, Some(TokenKind::Pat));
        assert!(p.token_cap.is_none());

        // An under-privileged PAT principal: empty claim set.
        let bare = CallerPrincipal {
            claims: vec![],
            ..p.clone()
        };
        assert!(bare.claims.is_empty());
    }

    #[test]
    fn caller_principal_token_kind_is_observable_via_eq() {
        // The typed token-kind carrier is part of structural
        // identity — two principals differing only in `token_kind`
        // compare unequal.
        let a = sample_principal();
        let b = CallerPrincipal {
            token_kind: Some(TokenKind::CliSession),
            ..a.clone()
        };
        assert_ne!(a, b);
    }

    #[test]
    fn caller_principal_with_token_cap_is_observable_via_eq() {
        // A principal carrying a token cap is structurally
        // distinct from one without; `Eq` reflects that.
        // Pin `issued_at` so the only varying field across the eq compare
        // is `token_cap`.
        let pinned_issued_at = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let template = CallerPrincipal {
            user_id: Uuid::from_u128(0x1000),
            external_id: "keycloak:realm-users:abc-123".into(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            claims: vec!["developer".into()],
            token_kind: None,
            issued_at: pinned_issued_at,
            token_cap: None,
        };

        let a = template.clone();
        let mut b = template.clone();
        b.token_cap = Some(TokenCap {
            permissions: vec![Permission::Read],
            repository_ids: None,
        });
        assert_ne!(a, b);

        // Two principals with the same cap compare equal.
        let cap = TokenCap {
            permissions: vec![Permission::Read, Permission::Write],
            repository_ids: Some(vec![Uuid::from_u128(0xA)]),
        };
        let mut c = template.clone();
        c.token_cap = Some(cap.clone());
        let mut d = template;
        d.token_cap = Some(cap);
        assert_eq!(c, d);
    }

    // NOTE: `CallerPrincipal` intentionally does NOT implement `Serialize`
    // or `Deserialize` (see the type-level doc comment). Enforcement is by
    // absence-of-derive, cross-checked by review. A negative trait-bound
    // compile-time assertion was evaluated; every pattern available on
    // stable Rust (autoref-specialization, overlapping blanket impls) is
    // fragile against derive-ordering and yields unhelpful error messages
    // when tripped. The doc comment + review gate is the enforcement
    // mechanism, matching other "do not derive this" contracts in the
    // codebase (e.g. `hort-domain::types::ContentHash` secret handling).
}
