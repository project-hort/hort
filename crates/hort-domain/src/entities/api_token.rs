//! Native API token entity + cap-intersection algorithm.
//!
//! See ADR 0012 and `docs/auth-catalog.md` for the token model and its
//! invariants.
//!
//! # Invariants encoded here
//!
//! - **No `Deserialize` impl on [`ApiToken`].** This struct is **not** an
//!   API request DTO. It is the persisted-domain shape. Per the
//!   anti-pattern checklist (CLAUDE.md "Anti-Patterns Checklist") only
//!   handler-specific request DTOs are deserialised from external input;
//!   wiring `Deserialize` here would let an attacker hand-roll an
//!   `ApiToken` with arbitrary `token_hash` / `token_prefix` /
//!   `declared_permissions` claims and feed it through any code path that
//!   round-trips JSON. Adding `#[derive(Deserialize)]` to this struct is a
//!   review-blocking change.
//! - **No `Serialize` impl on [`ApiToken`] either.** The token row is
//!   never serialised wholesale on the wire — list endpoints emit a
//!   handler-specific response DTO that excludes `token_hash` (issuance
//!   surfaces the plaintext **once**, never again). Tracing spans attach
//!   the `token_id` field directly via `tracing::field`; they do not
//!   need a `Serialize` impl on the whole struct.
//! - **No I/O imports.** `hort-domain` is pure Rust, zero I/O — the file
//!   imports `chrono`, `uuid`, and the local `rbac::Permission` only. No
//!   `sqlx`, `reqwest`, `axum`, or `tracing`.
//!
//! # Cap intersection ([`effective_permission`])
//!
//! The runtime authority for a token-bearing request is the AND of:
//!
//! 1. The user's *current* RBAC grants (the caller assembles
//!    `Vec<PermissionGrant>` from the live evaluator — group changes
//!    propagate immediately).
//! 2. The token's declared cap, if any. The cap is fixed at issuance and
//!    never widens. A token issued with `[Read]` cannot acquire `Write`
//!    even if the user later gains `Write` on the target repo.
//!
//! The function takes both inputs and returns a single `bool`. The "live"
//! part — re-resolving user grants on every call — is the caller's
//! responsibility; here we are pure.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::rbac::{Permission, PermissionGrant};

// ---------------------------------------------------------------------------
// TokenKind
// ---------------------------------------------------------------------------

/// Token kind discriminator.
///
/// Wire-format short codes (`pat` / `svc` / `cli`) live at the
/// `hort_<kind>_<body>` token-format boundary in `hort-app`; the domain enum
/// is the canonical form.
///
/// `Serialize` + `Deserialize` are derived because the discriminator
/// is part of the `ApiTokenIssued` / `ApiTokenIssuanceDenied` event
/// payloads, and the event store round-trips event
/// JSONB through `serde::Deserialize`. This is consistent with the
/// per-event no-PII contract — `TokenKind` is a 3-variant
/// discriminator with no PII or secret material. The neighbouring
/// [`ApiToken`] / [`TokenCap`] structs intentionally do NOT derive
/// `Deserialize`; only the discriminator needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TokenKind {
    /// Self-issued personal access token. Default 90d expiry, max 365d.
    Pat,
    /// Admin-issued for `is_service_account = true` users. Default 365d,
    /// max 365d (or unbounded with `HORT_TOKEN_ALLOW_UNBOUNDED_SVC=true`).
    ServiceAccount,
    /// CLI-session token (ADR 0013). Sliding 30-day, refreshed on use.
    CliSession,
}

// ---------------------------------------------------------------------------
// TokenCap
// ---------------------------------------------------------------------------

/// The cap a token carries — an upper bound on its effective permissions.
///
/// - `permissions` is the typed subset of [`Permission`] the token is
///   allowed to exercise.
/// - `repository_ids = None` means "inherit user grants" — the cap places
///   no per-repository restriction. `Some(vec![…])` locks the token to
///   exactly those repos. `Some(vec![])` is rejected at issuance but is
///   structurally allowed for forward-compat with `kind = CliSession`'s
///   transient empty-set state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenCap {
    pub permissions: Vec<Permission>,
    pub repository_ids: Option<Vec<Uuid>>,
}

// ---------------------------------------------------------------------------
// ApiToken
// ---------------------------------------------------------------------------

/// A persisted native API token row.
///
/// **Not a DTO.** This is the domain shape used internally; HTTP layers
/// project to/from request- and response-specific structs that pass
/// through serde. See top-of-file invariant.
///
/// Field notes:
/// - `token_hash` is the Argon2id encoded form of the full
///   `hort_<kind>_<body>` token. The plaintext is shown to the issuer
///   once and never recoverable.
/// - `token_prefix` is the **first 8 chars of the body** (not including
///   `hort_<kind>_`). Indexed for O(1) prefix lookup; constant-time Argon2
///   verify always runs even on prefix-not-found.
/// - `repository_ids = None` ⇒ inherit user grants. `Some(vec![])`
///   structurally allowed (see [`TokenCap`]); rejected at issuance for
///   `Pat` / `ServiceAccount`.
/// - `last_used_ip` is **already bucketed** at adapter write — `/24` for
///   IPv4, `/48` for IPv6 — to satisfy GDPR Art 5(1)(c) data
///   minimisation. The domain entity carries the bucketed string; raw
///   IPs never reach this struct.
/// - `last_used_user_agent` is **truncated to 256 chars** at adapter
///   write. UA strings longer than that are common fingerprinting
///   signals and are not security-useful.
/// - `created_by_user_id` is the actor who minted the token; for
///   self-mint PATs this equals `user_id`, for admin-mint
///   service-account tokens it is the issuing admin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub kind: TokenKind,
    pub token_hash: String,
    pub token_prefix: String,
    pub declared_permissions: Vec<Permission>,
    pub repository_ids: Option<Vec<Uuid>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub last_used_ip: Option<String>,
    pub last_used_user_agent: Option<String>,
    pub created_by_user_id: Uuid,
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Cap intersection
// ---------------------------------------------------------------------------

/// AND-of-cap-and-grants intersection check.
///
/// Returns `true` iff all of the following hold:
///
/// 1. The user's `user_grants` set authorises `requested` on `repo`.
///    A grant matches when its `permission == requested` AND
///    (`repository_id == None` OR `repository_id == Some(repo)`). A
///    global grant (`repository_id == None`) covers every repo.
///    [`Permission::Admin`] in any user grant short-circuits to allow
///    regardless of `requested` — admin is the established RBAC
///    pass-through (ADR 0012) and the cap intersection preserves it.
/// 2. The token cap, if present, permits the action:
///    - `cap.permissions.contains(requested)` AND
///    - `cap.repository_ids` is `None` (no per-repo restriction) OR
///      contains `repo`.
///
/// `token_cap = None` means an OIDC bearer / non-tokenised principal —
/// no cap, only the user's grants gate access.
///
/// # Live-grants discipline
///
/// `user_grants` must be the user's **currently resolved** grant set.
/// Group claims propagate immediately; tokens cannot retain authority
/// the user has lost. The "live" part is the caller's responsibility —
/// the function is pure.
///
/// # Cap-vs-user-authority discipline
///
/// At issuance the use case rejects caps wider than the user's authority,
/// but runtime intersection is authoritative — even if `cap.permissions`
/// were somehow wider than the user's grants, the user grants leg of the
/// AND would deny. Conversely, if the user later gains `Write` on a repo
/// but the cap only declares `Read`, the cap leg of the AND denies.
pub fn effective_permission(
    token_cap: Option<&TokenCap>,
    user_grants: &[PermissionGrant],
    requested: Permission,
    repo: Uuid,
) -> bool {
    user_grants_allow(user_grants, requested, repo) && cap_allows(token_cap, requested, repo)
}

/// Walks `user_grants` to see whether any grant authorises `requested`
/// on `repo`. Admin pass-through: an `Admin` grant on the matching scope
/// satisfies any `requested`.
fn user_grants_allow(grants: &[PermissionGrant], requested: Permission, repo: Uuid) -> bool {
    grants.iter().any(|g| {
        let scope_matches = match g.repository_id {
            None => true,
            Some(id) => id == repo,
        };
        scope_matches && (g.permission == Permission::Admin || g.permission == requested)
    })
}

/// Applies the token cap leg of the AND. `None` ⇒ no cap, allow.
fn cap_allows(cap: Option<&TokenCap>, requested: Permission, repo: Uuid) -> bool {
    cap_allows_optional_repo(cap, requested, Some(repo))
}

/// Cap leg of the cap-intersection, generalised to `Option<Uuid>` for the
/// `RbacEvaluator::authorize` call site.
///
/// The full intersection in [`effective_permission`] requires a concrete
/// `repo: Uuid` because grants are always evaluated against a target repo.
/// The integration in `RbacEvaluator::authorize` is broader: handlers
/// authorize system-level operations with `repository_id = None` (e.g.
/// catalog-style ops, admin actions). For those calls the cap leg still
/// has to apply, and it has to apply *correctly* for both the per-repo
/// and the no-repo case.
///
/// Semantics:
///
/// - `cap = None` → no cap, allow (the integration's user-grants leg is
///   the authoritative gate).
/// - `cap = Some(c)` and `c.permissions` does NOT contain `requested` →
///   deny.
/// - `cap = Some(c)`, permission allowed, `c.repository_ids = None` (no
///   per-repo restriction) → allow regardless of `repository_id`.
/// - `cap = Some(c)`, permission allowed, `c.repository_ids = Some(ids)`,
///   `repository_id = Some(repo)` → allow iff `ids.contains(&repo)`.
/// - `cap = Some(c)`, permission allowed, `c.repository_ids = Some(_)`,
///   `repository_id = None` → **deny**. A per-repo-restricted token
///   cannot authorize a system-level op; the cap explicitly bounds the
///   token to a finite set of repos and "no repo" is outside that set.
///
/// This is the same logic the [`effective_permission`] cap leg uses,
/// extracted here so the AppContext-level [`RbacEvaluator::authorize`]
/// can call it without materialising a synthetic `Vec<PermissionGrant>`
/// per request (this is on the artifact-read hot path). The `Some(repo)`
/// branch behaves identically to the private `cap_allows` helper used
/// by `effective_permission` — there is one source of truth for the cap
/// algorithm; this function shapes the input for both call sites.
///
/// [`RbacEvaluator::authorize`]: ../../../hort_app/rbac/struct.RbacEvaluator.html
pub fn cap_allows_optional_repo(
    cap: Option<&TokenCap>,
    requested: Permission,
    repository_id: Option<Uuid>,
) -> bool {
    match cap {
        None => true,
        Some(cap) => {
            if !cap.permissions.contains(&requested) {
                return false;
            }
            match (&cap.repository_ids, repository_id) {
                // No per-repo restriction on the cap → allow on either
                // a repo-scoped or a system-level op.
                (None, _) => true,
                // Per-repo cap + concrete repo → membership check.
                (Some(ids), Some(repo)) => ids.contains(&repo),
                // Per-repo cap + system-level op → deny. The cap bounds
                // the token to specific repos; "no repo" is outside it.
                (Some(_), None) => false,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::managed_by::ManagedBy;
    use crate::entities::rbac::GrantSubject;

    // -- Fixtures -----------------------------------------------------------

    fn repo_a() -> Uuid {
        Uuid::from_u128(0xA)
    }

    fn repo_b() -> Uuid {
        Uuid::from_u128(0xB)
    }

    fn grant(scope: Option<Uuid>, perm: Permission) -> PermissionGrant {
        PermissionGrant {
            id: Uuid::nil(),
            subject: GrantSubject::User(Uuid::nil()),
            repository_id: scope,
            permission: perm,
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
            created_at: Utc::now(),
        }
    }

    fn cap(perms: Vec<Permission>, repos: Option<Vec<Uuid>>) -> TokenCap {
        TokenCap {
            permissions: perms,
            repository_ids: repos,
        }
    }

    // -- effective_permission: token_cap = None (no cap) ---------------------

    #[test]
    fn no_cap_allows_when_user_has_matching_grant() {
        let grants = vec![grant(Some(repo_a()), Permission::Read)];
        assert!(effective_permission(
            None,
            &grants,
            Permission::Read,
            repo_a()
        ));
    }

    #[test]
    fn no_cap_denies_when_user_lacks_grant() {
        let grants: Vec<PermissionGrant> = vec![];
        assert!(!effective_permission(
            None,
            &grants,
            Permission::Read,
            repo_a()
        ));
    }

    #[test]
    fn no_cap_denies_when_user_grant_is_for_different_repo() {
        let grants = vec![grant(Some(repo_b()), Permission::Read)];
        assert!(!effective_permission(
            None,
            &grants,
            Permission::Read,
            repo_a()
        ));
    }

    #[test]
    fn no_cap_global_grant_covers_every_repo() {
        let grants = vec![grant(None, Permission::Write)];
        assert!(effective_permission(
            None,
            &grants,
            Permission::Write,
            repo_a()
        ));
        assert!(effective_permission(
            None,
            &grants,
            Permission::Write,
            repo_b()
        ));
    }

    // -- Admin pass-through --------------------------------------------------

    #[test]
    fn admin_grant_on_repo_satisfies_any_requested_when_no_cap() {
        let grants = vec![grant(Some(repo_a()), Permission::Admin)];
        for perm in [
            Permission::Read,
            Permission::Write,
            Permission::Delete,
            Permission::Admin,
        ] {
            assert!(
                effective_permission(None, &grants, perm, repo_a()),
                "admin grant should pass through for {perm:?}"
            );
        }
    }

    #[test]
    fn global_admin_grant_satisfies_any_requested_on_any_repo() {
        let grants = vec![grant(None, Permission::Admin)];
        for perm in [
            Permission::Read,
            Permission::Write,
            Permission::Delete,
            Permission::Admin,
        ] {
            assert!(effective_permission(None, &grants, perm, repo_a()));
            assert!(effective_permission(None, &grants, perm, repo_b()));
        }
    }

    #[test]
    fn admin_grant_for_other_repo_does_not_pass_through() {
        let grants = vec![grant(Some(repo_b()), Permission::Admin)];
        assert!(!effective_permission(
            None,
            &grants,
            Permission::Read,
            repo_a()
        ));
    }

    // -- effective_permission: cap.permissions gating ------------------------

    #[test]
    fn cap_permissions_must_contain_requested() {
        let grants = vec![grant(Some(repo_a()), Permission::Write)];
        let read_only = cap(vec![Permission::Read], None);
        // User has Write, but cap is Read-only → deny Write.
        assert!(!effective_permission(
            Some(&read_only),
            &grants,
            Permission::Write,
            repo_a()
        ));
    }

    #[test]
    fn cap_permissions_allow_requested_when_present() {
        let grants = vec![grant(Some(repo_a()), Permission::Read)];
        let read_only = cap(vec![Permission::Read], None);
        assert!(effective_permission(
            Some(&read_only),
            &grants,
            Permission::Read,
            repo_a()
        ));
    }

    #[test]
    fn cap_with_multiple_permissions_allows_each_in_set() {
        let grants = vec![grant(None, Permission::Admin)];
        let rw = cap(vec![Permission::Read, Permission::Write], None);
        assert!(effective_permission(
            Some(&rw),
            &grants,
            Permission::Read,
            repo_a()
        ));
        assert!(effective_permission(
            Some(&rw),
            &grants,
            Permission::Write,
            repo_a()
        ));
        // Delete not in cap, even though user has admin pass-through.
        assert!(!effective_permission(
            Some(&rw),
            &grants,
            Permission::Delete,
            repo_a()
        ));
    }

    // -- effective_permission: cap.repository_ids = None / Some([…]) / Some([])

    #[test]
    fn cap_repository_ids_none_inherits_user_grants() {
        let grants = vec![grant(Some(repo_a()), Permission::Read)];
        let cap_no_repo_restriction = cap(vec![Permission::Read], None);
        assert!(effective_permission(
            Some(&cap_no_repo_restriction),
            &grants,
            Permission::Read,
            repo_a()
        ));
    }

    #[test]
    fn cap_repository_ids_some_restricts_to_listed_repos() {
        let grants = vec![grant(None, Permission::Read)];
        let cap_only_a = cap(vec![Permission::Read], Some(vec![repo_a()]));
        assert!(effective_permission(
            Some(&cap_only_a),
            &grants,
            Permission::Read,
            repo_a()
        ));
        assert!(!effective_permission(
            Some(&cap_only_a),
            &grants,
            Permission::Read,
            repo_b()
        ));
    }

    #[test]
    fn cap_repository_ids_empty_vec_denies_all_repos() {
        // Some(vec![]) is rejected at issuance for Pat/ServiceAccount but
        // structurally allowed (e.g. transient CliSession state). Runtime
        // intersection must still treat it correctly: the cap permits no
        // repo → deny everything.
        let grants = vec![grant(None, Permission::Admin)];
        let cap_no_repos = cap(vec![Permission::Read], Some(vec![]));
        assert!(!effective_permission(
            Some(&cap_no_repos),
            &grants,
            Permission::Read,
            repo_a()
        ));
        assert!(!effective_permission(
            Some(&cap_no_repos),
            &grants,
            Permission::Read,
            repo_b()
        ));
    }

    #[test]
    fn cap_repository_ids_some_multi_allows_each_listed() {
        let grants = vec![grant(None, Permission::Write)];
        let cap_a_b = cap(vec![Permission::Write], Some(vec![repo_a(), repo_b()]));
        assert!(effective_permission(
            Some(&cap_a_b),
            &grants,
            Permission::Write,
            repo_a()
        ));
        assert!(effective_permission(
            Some(&cap_a_b),
            &grants,
            Permission::Write,
            repo_b()
        ));
        // Anything else denied.
        assert!(!effective_permission(
            Some(&cap_a_b),
            &grants,
            Permission::Write,
            Uuid::from_u128(0xC)
        ));
    }

    // -- token-cap-narrower-than-user invariant ---------------------------------

    #[test]
    fn invariant_4_user_gains_write_later_token_still_capped_to_read() {
        // Token issued with declared_permissions = [Read], repository_ids = None.
        // User later gains Write on the target repo. Token MUST NOT acquire
        // Write authority.
        let read_only_cap = cap(vec![Permission::Read], None);
        let grants_after_promotion = vec![
            grant(Some(repo_a()), Permission::Read),
            grant(Some(repo_a()), Permission::Write),
        ];
        // Read still works.
        assert!(effective_permission(
            Some(&read_only_cap),
            &grants_after_promotion,
            Permission::Read,
            repo_a()
        ));
        // Write is denied even though user has Write — the cap bounds it down.
        assert!(!effective_permission(
            Some(&read_only_cap),
            &grants_after_promotion,
            Permission::Write,
            repo_a()
        ));
    }

    // -- user loses role, token authority drops --------------------------------

    #[test]
    fn invariant_2_user_loses_role_token_authority_drops() {
        // A token issued with cap [Read, Write] on repo_a. User originally had
        // both grants. After role removal the caller passes a smaller
        // user_grants set; the function (pure) reflects the live shape.
        let cap_rw = cap(
            vec![Permission::Read, Permission::Write],
            Some(vec![repo_a()]),
        );

        // Before role removal: both pass.
        let grants_before = vec![
            grant(Some(repo_a()), Permission::Read),
            grant(Some(repo_a()), Permission::Write),
        ];
        assert!(effective_permission(
            Some(&cap_rw),
            &grants_before,
            Permission::Read,
            repo_a()
        ));
        assert!(effective_permission(
            Some(&cap_rw),
            &grants_before,
            Permission::Write,
            repo_a()
        ));

        // After role removal — user only has Read now. Token can no longer
        // exercise Write even though the cap still permits it.
        let grants_after = vec![grant(Some(repo_a()), Permission::Read)];
        assert!(effective_permission(
            Some(&cap_rw),
            &grants_after,
            Permission::Read,
            repo_a()
        ));
        assert!(!effective_permission(
            Some(&cap_rw),
            &grants_after,
            Permission::Write,
            repo_a()
        ));

        // After full role removal — user has nothing. Token denies everything.
        let grants_empty: Vec<PermissionGrant> = vec![];
        assert!(!effective_permission(
            Some(&cap_rw),
            &grants_empty,
            Permission::Read,
            repo_a()
        ));
        assert!(!effective_permission(
            Some(&cap_rw),
            &grants_empty,
            Permission::Write,
            repo_a()
        ));
    }

    // -- Combined cap + grant matrix ------------------------------------------

    #[test]
    fn cap_and_grant_both_required_when_cap_present() {
        let grants_read = vec![grant(Some(repo_a()), Permission::Read)];
        let cap_read = cap(vec![Permission::Read], Some(vec![repo_a()]));

        // Both legs satisfied → allow.
        assert!(effective_permission(
            Some(&cap_read),
            &grants_read,
            Permission::Read,
            repo_a()
        ));

        // Cap satisfies but user grant missing → deny.
        let grants_empty: Vec<PermissionGrant> = vec![];
        assert!(!effective_permission(
            Some(&cap_read),
            &grants_empty,
            Permission::Read,
            repo_a()
        ));

        // User grant satisfies but cap doesn't list repo → deny.
        let cap_only_b = cap(vec![Permission::Read], Some(vec![repo_b()]));
        assert!(!effective_permission(
            Some(&cap_only_b),
            &grants_read,
            Permission::Read,
            repo_a()
        ));
    }

    #[test]
    fn cap_admin_token_with_admin_user_passes() {
        // Admin tokens (off by default) — when allowed,
        // the cap must explicitly list Admin and the user must hold Admin
        // authority. Both legs of the AND apply.
        let cap_admin = cap(vec![Permission::Admin], None);
        let grants_admin = vec![grant(None, Permission::Admin)];
        assert!(effective_permission(
            Some(&cap_admin),
            &grants_admin,
            Permission::Admin,
            repo_a()
        ));
    }

    #[test]
    fn cap_without_admin_denies_admin_request_even_for_admin_user() {
        let cap_rw = cap(vec![Permission::Read, Permission::Write], None);
        let grants_admin = vec![grant(None, Permission::Admin)];
        assert!(!effective_permission(
            Some(&cap_rw),
            &grants_admin,
            Permission::Admin,
            repo_a()
        ));
    }

    // -- Entity construction smoke tests ------------------------------------

    fn sample_token() -> ApiToken {
        ApiToken {
            id: Uuid::nil(),
            user_id: Uuid::from_u128(1),
            name: "ci-myproject".into(),
            description: Some("CI publish".into()),
            kind: TokenKind::Pat,
            token_hash: "$argon2id$v=19$m=19456,t=2,p=1$...".into(),
            token_prefix: "a1b2c3d4".into(),
            declared_permissions: vec![Permission::Read, Permission::Write],
            repository_ids: Some(vec![repo_a()]),
            expires_at: Some(Utc::now()),
            revoked_at: None,
            last_used_at: None,
            last_used_ip: None,
            last_used_user_agent: None,
            created_by_user_id: Uuid::from_u128(1),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn api_token_clone_eq() {
        let a = sample_token();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn api_token_kinds_distinct() {
        let pat = TokenKind::Pat;
        let svc = TokenKind::ServiceAccount;
        let cli = TokenKind::CliSession;
        assert_ne!(pat, svc);
        assert_ne!(svc, cli);
        assert_ne!(pat, cli);
    }

    #[test]
    fn api_token_kind_copy() {
        let a = TokenKind::ServiceAccount;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn token_cap_clone_eq() {
        let a = cap(
            vec![Permission::Read, Permission::Write],
            Some(vec![repo_a(), repo_b()]),
        );
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn token_cap_inherit_grants_shape() {
        let c = cap(vec![Permission::Read], None);
        assert!(c.repository_ids.is_none());
    }

    #[test]
    fn api_token_revoked_state_distinguishes() {
        let active = sample_token();
        let revoked = ApiToken {
            revoked_at: Some(Utc::now()),
            ..sample_token()
        };
        assert!(active.revoked_at.is_none());
        assert!(revoked.revoked_at.is_some());
        assert_ne!(active, revoked);
    }

    // Compile-time invariant: `ApiToken` must not implement
    // `Deserialize`. See module docstring for the rationale — the
    // persisted-domain row must never be reconstructible from
    // untrusted JSON. A plain construction test (`let _ =
    // sample_token();`) would NOT catch a future
    // `#[derive(Deserialize)]` on `ApiToken`. The macro below expands
    // to a `const _` block that fails to compile if any
    // `Deserialize<'de>` impl exists for `ApiToken`. `DeserializeOwned`
    // is the higher-rank form `for<'de> Deserialize<'de>` — exactly
    // what `#[derive(Deserialize)]` synthesises.
    static_assertions::assert_not_impl_any!(ApiToken: serde::de::DeserializeOwned);

    // -- cap_allows_optional_repo (RbacEvaluator integration helper) ----------

    #[test]
    fn cap_optional_repo_none_cap_allows_with_or_without_repo() {
        assert!(cap_allows_optional_repo(
            None,
            Permission::Read,
            Some(repo_a())
        ));
        assert!(cap_allows_optional_repo(None, Permission::Admin, None));
    }

    #[test]
    fn cap_optional_repo_permission_not_in_cap_denies() {
        let c = cap(vec![Permission::Read], None);
        assert!(!cap_allows_optional_repo(
            Some(&c),
            Permission::Write,
            Some(repo_a())
        ));
        // Same on a system-level op.
        assert!(!cap_allows_optional_repo(Some(&c), Permission::Write, None));
    }

    #[test]
    fn cap_optional_repo_no_repo_restriction_allows_either_arg_shape() {
        let c = cap(vec![Permission::Read], None);
        assert!(cap_allows_optional_repo(
            Some(&c),
            Permission::Read,
            Some(repo_a())
        ));
        assert!(cap_allows_optional_repo(Some(&c), Permission::Read, None));
    }

    #[test]
    fn cap_optional_repo_per_repo_cap_with_concrete_repo_membership_check() {
        let c = cap(vec![Permission::Read], Some(vec![repo_a()]));
        assert!(cap_allows_optional_repo(
            Some(&c),
            Permission::Read,
            Some(repo_a())
        ));
        assert!(!cap_allows_optional_repo(
            Some(&c),
            Permission::Read,
            Some(repo_b())
        ));
    }

    #[test]
    fn cap_optional_repo_per_repo_cap_denies_system_level_op() {
        // A per-repo-restricted token cannot authorize a
        // `repository_id = None` operation.
        let c = cap(vec![Permission::Read], Some(vec![repo_a()]));
        assert!(!cap_allows_optional_repo(Some(&c), Permission::Read, None));
    }

    #[test]
    fn cap_optional_repo_empty_repo_set_denies_everything() {
        // `Some(vec![])` — structurally allowed for forward-compat, denies
        // every concrete repo and every system-level op.
        let c = cap(vec![Permission::Read], Some(vec![]));
        assert!(!cap_allows_optional_repo(
            Some(&c),
            Permission::Read,
            Some(repo_a())
        ));
        assert!(!cap_allows_optional_repo(Some(&c), Permission::Read, None));
    }

    #[test]
    fn cap_optional_repo_matches_cap_allows_on_some_repo() {
        // The new helper must agree with the existing `cap_allows` private
        // function on the `Some(repo)` shape — single source of truth.
        let scenarios = [
            (
                cap(vec![Permission::Read], None),
                Permission::Read,
                repo_a(),
            ),
            (
                cap(vec![Permission::Read], None),
                Permission::Write,
                repo_a(),
            ),
            (
                cap(vec![Permission::Write], Some(vec![repo_a()])),
                Permission::Write,
                repo_a(),
            ),
            (
                cap(vec![Permission::Write], Some(vec![repo_a()])),
                Permission::Write,
                repo_b(),
            ),
            (
                cap(vec![Permission::Read], Some(vec![])),
                Permission::Read,
                repo_a(),
            ),
        ];
        for (c, perm, repo) in scenarios {
            assert_eq!(
                cap_allows(Some(&c), perm, repo),
                cap_allows_optional_repo(Some(&c), perm, Some(repo)),
                "cap_allows vs cap_allows_optional_repo divergence on {c:?} {perm:?} {repo:?}"
            );
        }
        // None-cap parity.
        assert_eq!(
            cap_allows(None, Permission::Read, repo_a()),
            cap_allows_optional_repo(None, Permission::Read, Some(repo_a()))
        );
    }
}
