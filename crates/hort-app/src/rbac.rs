//! # RBAC evaluator
//!
//! Pure in-memory authorization predicate. No I/O, no async, no tracing.
//! Deny-logging and metrics emission happen at the handler layer —
//! this module is a decision function, not an observer.
//!
//! The evaluator implements the additive-claims subject model that
//! replaced the role/group-mapping model (ADR 0012;
//! `docs/operator/claim-based-rbac.md`).

use std::sync::Arc;

use uuid::Uuid;

use hort_domain::entities::api_token::{cap_allows_optional_repo, TokenCap, TokenKind};
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::rbac::{ClaimMapping, GrantSubject, Permission, PermissionGrant};

// ---------------------------------------------------------------------------
// EffectiveGrantSet
// ---------------------------------------------------------------------------

/// Flat enumeration of the `(repository, permission)` cells an authority
/// set holds — the load-bearing shared enumeration.
///
/// Produced by [`RbacEvaluator::effective_grants`] and consumed by three
/// read surfaces (whoami self-view, the per-user endpoint, the what-if
/// resolver) plus [`RbacEvaluator::derive_cli_session_cap`], so all four
/// agree with the request-time gate ([`RbacEvaluator::authorize`]) — one
/// authority source of truth.
///
/// `is_global_admin = true` short-circuits the cell list (means
/// "everything") when the inputs resolve to admin — `claims` contains the
/// synthetic `admin` claim OR `is_admin` is set. The list is **never** an
/// enumeration of every repository (unbounded, useless); the marker stands
/// in for the full authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveGrantSet {
    /// `true` ⇒ the authority set is a full admin: `cells` is empty and the
    /// marker means "holds everything". `false` ⇒ `cells` is the exact
    /// held footprint (possibly empty = holds nothing).
    pub is_global_admin: bool,
    /// `(None, perm)` = global grant; `(Some(repo), perm)` = per-repo.
    /// De-duplicated, insertion-order preserved. Empty + `!is_global_admin`
    /// = the authority set holds nothing.
    pub cells: Vec<(Option<Uuid>, Permission)>,
}

// ---------------------------------------------------------------------------
// RbacEvaluator
// ---------------------------------------------------------------------------

/// In-memory authorization evaluator.
///
/// Constructed once at startup from a full DB snapshot of permission
/// grants — the composition root in `hort-server` queries
/// `PermissionGrantRepository::list_all_grants` and passes the result into
/// [`RbacEvaluator::new`]. The evaluator is read-only and `Arc`-wraps its
/// snapshot so `Clone` is cheap; the type is trivially `Send + Sync`, safe
/// to share across axum handlers.
///
/// # Additive-claims subject model
///
/// An earlier structural-RBAC evaluator kept two indexes (`roles_by_name:
/// HashMap<String, Role>` + `grants_by_role: HashMap<Uuid,
/// Vec<PermissionGrant>>`) and resolved a principal's role-name list to
/// role ids before scanning that role's grants. The additive-claims model
/// deleted the `Role` entity and `PermissionGrant.role_id`: a grant binds to a
/// [`GrantSubject`] — either a *required claim set* the caller must wholly
/// possess, or a *direct user id*. There is no role id left to key on, so
/// the index itself collapses to a flat `Vec<PermissionGrant>` scanned
/// with a subject match. The grant count is small in practice
/// (single- to low-double-digit per deployment); a linear scan is faster
/// than maintaining a `repository_id`-keyed map and keeps the type
/// trivially correct. A repo-keyed index is a pure optimisation that can
/// land later if a deployment's grant count ever justifies it — it is not
/// required for correctness.
///
/// Hot-reload is handled by `hort-server` swapping the whole evaluator
/// behind an `ArcSwap`; the evaluator value itself is immutable.
#[derive(Clone)]
pub struct RbacEvaluator {
    /// The full grant set. Scanned linearly by [`Self::user_grants_authorize`]
    /// applying the [`GrantSubject`] match. Held behind an `Arc` so `Clone`
    /// is a refcount bump.
    grants: Arc<Vec<PermissionGrant>>,
}

impl RbacEvaluator {
    /// Build a new evaluator from the adapter-supplied grant snapshot.
    ///
    /// The caller owns a single query: a full list of [`PermissionGrant`]
    /// rows (claims-subject and user-subject grants intermixed). The
    /// evaluator does not interpret `managed_by` / `managed_by_digest` —
    /// those are gitops-apply concerns; evaluation only reads
    /// `subject` / `permission` / `repository_id`.
    pub fn new(grants: Vec<PermissionGrant>) -> Self {
        Self {
            grants: Arc::new(grants),
        }
    }

    /// Pure authorization predicate.
    ///
    /// Returns `true` when the principal is allowed to perform `permission`
    /// against the (optionally repository-scoped) resource. Returns `false`
    /// otherwise.
    ///
    /// **This does not return `Result`.** Authorization failure is a
    /// decision, not an error — the handler that invoked the check shapes
    /// the 403 response. Errors are reserved for infrastructure failures
    /// (unreachable DB, malformed token); a clean deny is normal traffic.
    ///
    /// # Two-leg AND for token-bearing principals
    ///
    /// When `principal.token_cap = Some(cap)` (a native API token) the
    /// final decision is the AND of:
    ///
    /// 1. **User-grants leg** ([`Self::user_grants_authorize`]) — the
    ///    admin short-circuit + the subject-model grant scan, unchanged for
    ///    non-token callers.
    /// 2. **Cap leg** ([`cap_allows_optional_repo`]) — the cap-side of the
    ///    intersection algorithm, sharing the SAME function the pure
    ///    [`hort_domain::entities::api_token::effective_permission`] uses
    ///    (extracted to one place; not duplicated). The helper handles
    ///    both `Some(repo)` and `None` (system-level) call shapes.
    ///
    /// `principal.token_cap = None` keeps the legacy single-leg behaviour:
    /// OIDC bearer / local-session callers see `cap_allows_optional_repo`
    /// return `true` and the user-grants leg is the sole gate.
    ///
    /// **The admin short-circuit lives inside the user-grants leg, not at
    /// the top of `authorize`.** This placement is load-bearing
    /// for the cap-intersection invariant: an admin user with a limited
    /// token cap (e.g. cap = `[Read]`) MUST be denied a `Write` action,
    /// even though a top-level short-circuit would have returned `true`
    /// from the grant check alone. The cap leg is unconditional — every
    /// code path runs it — so the AND composes correctly. (Do not
    /// refactor the cap leg out of the AND.)
    ///
    /// # Admin short-circuit
    ///
    /// When `principal.claims.contains("admin")` the user-grants leg
    /// returns `true` immediately without consulting any grants. The
    /// match is **case-sensitive on the exact lowercase string `"admin"`**
    /// — the canonical spelling synthesised by
    /// [`add_admin_claim_if_admin`] and produced by
    /// [`resolve_claims`] from the operator-declared `claim_mappings`.
    /// `"ADMIN"`, `"Admin"`, and any other casing do NOT short-circuit;
    /// this mirrors the claim-name convention and avoids an accidental
    /// privilege-escalation vector if a claim-mapping file is hand-edited
    /// with a misspelled admin-adjacent name. (The structural-RBAC
    /// predecessor matched `principal.roles`; the subject model moved it
    /// to `principal.claims`.)
    ///
    /// # Subject match
    ///
    /// A non-admin grant matches when its `permission` equals the
    /// requested `permission`, the repository scope matches, AND its
    /// [`GrantSubject`] is satisfied:
    ///
    /// - [`GrantSubject::Claims`]`(required)` — satisfied when every claim
    ///   in `required` is present in `principal.claims` (subset test).
    /// - [`GrantSubject::User`]`(uid)` — satisfied when `uid` equals
    ///   `principal.user_id` (identity test; how service accounts
    ///   express authority).
    ///
    /// # Repository scoping
    ///
    /// - A global grant (`grant.repository_id == None`) matches every
    ///   `repository_id` argument, including `None`.
    /// - A repository-scoped grant (`grant.repository_id == Some(r)`)
    ///   matches only when the caller-supplied `repository_id == Some(r)`.
    ///   In particular, a repo-scoped grant does NOT match a `None`
    ///   repository-id argument.
    pub fn authorize(
        &self,
        principal: &CallerPrincipal,
        permission: Permission,
        repository_id: Option<Uuid>,
    ) -> bool {
        // User-grants leg — admin short-circuit + subject-model grant
        // scan, unchanged for non-token callers.
        let user_leg = self.user_grants_authorize(principal, permission, repository_id);
        // Cap leg — the cap-intersection invariant (do not refactor
        // it out of the AND). Calls
        // the SAME helper the pure `effective_permission` uses for
        // its cap leg; `token_cap = None` ⇒ helper returns `true` ⇒ leg
        // disappears from the AND.
        let cap_leg =
            cap_allows_optional_repo(principal.token_cap.as_ref(), permission, repository_id);
        user_leg && cap_leg
    }

    /// User-grants leg of [`Self::authorize`]. Pure scan over the
    /// evaluator's flat grant set applying the subject
    /// match, with the lowercase-`"admin"` claim short-circuit. Extracted
    /// into its own method so the `authorize` body composes the user leg
    /// + cap leg uniformly via AND.
    fn user_grants_authorize(
        &self,
        principal: &CallerPrincipal,
        permission: Permission,
        repository_id: Option<Uuid>,
    ) -> bool {
        // Admin short-circuit — string-level match on the resolved claim
        // set. One source of truth at evaluation time; `User.is_admin` is
        // DB metadata kept in sync with the synthetic `admin` claim by
        // construction.
        if principal.claims.iter().any(|c| c == "admin") {
            // B1 (ADR 0036): a cap-bound native token (Pat/ServiceAccount) carrying
            // the admin claim MUST also carry a cap — `authenticate_pat` always
            // constructs `Some(cap)`. A `None` cap here is an anomalous construction;
            // fail closed rather than grant unfenced admin. OIDC (token_kind:None) and
            // CliSession (token_kind:Some(CliSession)) legitimately carry a `None` cap
            // and are full-authority by design — they are deliberately NOT guarded.
            if matches!(
                principal.token_kind,
                Some(TokenKind::Pat) | Some(TokenKind::ServiceAccount)
            ) && principal.token_cap.is_none()
            {
                return false;
            }
            return true;
        }

        self.grants.iter().any(|grant| {
            if grant.permission != permission {
                return false;
            }
            let matches_repo = match grant.repository_id {
                None => true,
                Some(scoped) => repository_id == Some(scoped),
            };
            if !matches_repo {
                return false;
            }
            subject_matches(&grant.subject, &principal.claims, Some(principal.user_id))
        })
    }

    /// Enumerate every `(repository, permission)` the given authority
    /// inputs hold — the shared enumeration.
    ///
    /// Uses the SAME subject-match ([`subject_matches`]) + admin
    /// short-circuit + repository-scope semantics as
    /// [`Self::user_grants_authorize`] / [`Self::authorize`] — one
    /// authority source of truth, so the enumeration cannot drift from the
    /// request-time gate.
    ///
    /// - `claims` — the resolved claim set (from a token, or from
    ///   [`resolve_claims`] for the what-if resolver).
    /// - `user_id` — `Some` to also include [`GrantSubject::User`] grants
    ///   (self / per-user view); `None` for the claims-only what-if
    ///   resolver (no user identity in scope), which excludes every `User`
    ///   grant.
    /// - `is_admin` — folds the synthetic `admin` claim in
    ///   so an `is_admin` Local user — or a group mapped to
    ///   the `admin` claim — short-circuits.
    ///
    /// # Admin short-circuit (a marker, never an enumeration)
    ///
    /// When `claims` contains the case-sensitive lowercase `"admin"` claim
    /// OR `is_admin` is set, the result is
    /// `EffectiveGrantSet { is_global_admin: true, cells: vec![] }`. A full
    /// admin holds every authority; enumerating every repository would be
    /// unbounded and useless, so the marker stands in for it.
    ///
    /// # Cap-agnostic by design
    ///
    /// This reports the `grant_leg` authority of a claim / user set, not
    /// what any one *token* can exercise — there is no token cap in scope.
    /// That is correct for the per-user view and the what-if resolver.
    /// The token-cap intersection is the **caller's** business and
    /// is applied only at the whoami consumer.
    #[must_use]
    pub fn effective_grants(
        &self,
        claims: &[String],
        user_id: Option<Uuid>,
        is_admin: bool,
    ) -> EffectiveGrantSet {
        // Admin short-circuit — `claims` carries the synthetic `admin`
        // claim, OR `is_admin` folds it in. Marker
        // only: never enumerate every repository.
        if is_admin || claims.iter().any(|c| c == "admin") {
            return EffectiveGrantSet {
                is_global_admin: true,
                cells: Vec::new(),
            };
        }

        let mut cells: Vec<(Option<Uuid>, Permission)> = Vec::new();
        for grant in self.grants.iter() {
            if !subject_matches(&grant.subject, claims, user_id) {
                continue;
            }
            let cell = (grant.repository_id, grant.permission);
            if !cells.contains(&cell) {
                cells.push(cell);
            }
        }
        EffectiveGrantSet {
            is_global_admin: false,
            cells,
        }
    }

    /// Does `principal` satisfy a required claim set, using the **same**
    /// subset-match primitive and synthetic-`"admin"` short-circuit as
    /// the `GrantSubject::Claims` arm of [`Self::user_grants_authorize`]?
    ///
    /// This is the claim model's set-membership test exposed as a
    /// standalone predicate so callers that need a *claim requirement*
    /// that is not itself a `Permission` grant (the
    /// destructive-task tier: `Permission::AdminTaskInvoke` **AND** the
    /// `task:destructive` claim) reuse the evaluator instead of
    /// hand-rolling a parallel subset test. It deliberately mirrors
    /// `user_grants_authorize`'s `GrantSubject::Claims(required)` arm
    /// (`required.iter().all(|c| principal.claims.contains(c))`) and its
    /// case-sensitive lowercase-`"admin"` short-circuit so there is one
    /// claim-match semantics in the codebase, nothing to drift.
    ///
    /// Adds **no** `Permission` or `GrantSubject` variant — the closed
    /// taxonomies are untouched; this is a read-only predicate
    /// over the existing claim set.
    #[must_use]
    pub fn claims_satisfy(&self, principal: &CallerPrincipal, required: &[&str]) -> bool {
        // Synthetic-`admin` short-circuit — identical semantics to
        // `user_grants_authorize` (a full admin holds every authority,
        // including any claim requirement). Case-sensitive on the exact
        // lowercase `"admin"` literal.
        if principal.claims.iter().any(|c| c == "admin") {
            return true;
        }
        required
            .iter()
            .all(|c| principal.claims.iter().any(|pc| pc == c))
    }

    /// Derive the [`TokenCap`] for an OIDC `/exchange` CliSession mint
    /// from the caller's **effective authority** (ADR 0013).
    ///
    /// The exchange used to hardcode `repository_ids: None` (a global-cap
    /// request), which routed through the issuance clamp's global branch
    /// and required the caller to hold each requested permission
    /// *globally*. A per-repo-only grantee (the canonical
    /// dev-user shape) therefore could never mint a CliSession — `403
    /// cap_exceeds_authority`. This method closes that gap at issuance
    /// time by clamping BOTH axes to what this evaluator says the caller
    /// holds:
    ///
    /// - **Permission axis** — only requested permissions the caller holds
    ///   *somewhere* (globally or on ≥1 repo) appear in the result.
    /// - **Repository axis** — `None` (global cap) when the caller is admin
    ///   or holds every derived permission globally; otherwise
    ///   `Some(repos)` where `repos` is the set of repositories on which
    ///   the caller holds **all** of the derived permissions.
    ///
    /// # Valid by construction
    ///
    /// Every cell of the returned cap re-passes [`Self::authorize`] for the
    /// same `principal`: a global cap's permissions each authorize at
    /// `repository_id = None`, and a per-repo cap's `(perm, repo)` cross
    /// product each authorize at `repository_id = Some(repo)`. The
    /// issuance clamp (`run_issuance_gates` step 5) re-validates the same
    /// cells, so it is a defense-in-depth backstop rather than the primary
    /// gate — a non-rectangular grant set that this derivation cannot
    /// express as a single clean rectangle simply yields a *smaller*
    /// (fail-closed, least-privilege) cap, never an over-broad one.
    ///
    /// # Empty footprint
    ///
    /// Returns `None` when the caller holds **none** of the requested
    /// permissions (or `requested_permissions` is empty). The caller MUST
    /// translate `None` into the existing `cap_exceeds_authority` 403 —
    /// minting an empty-cap token would silently authorize nothing while
    /// looking like a success.
    ///
    /// This reuses the SAME subject-match + admin short-circuit +
    /// repository-scope semantics as [`Self::authorize`] — the live
    /// request-time RBAC primitive, which sees the principal's resolved
    /// `claims` — so the cap decision cannot drift from the request-time
    /// gate. It deliberately does NOT use `EffectivePermissionsUseCase`:
    /// that enumerates DB grants by `user_id` with
    /// `claims: []` (no claims cache; OIDC resolves live at login), so
    /// reusing it would yield an empty cap for a claims-only principal —
    /// re-breaking the per-repo-grantee footgun this derivation closes.
    #[must_use]
    pub fn derive_cli_session_cap(
        &self,
        principal: &CallerPrincipal,
        requested_permissions: &[Permission],
    ) -> Option<TokenCap> {
        // Admin short-circuit — a full admin holds every requested
        // permission globally. Mirror the existing global-cap request shape
        // (`repository_ids: None`) so the clamp's global branch + the ≤1h
        // admin gate run UNCHANGED. Dedup keeps the cap shape stable if a
        // caller repeats a permission.
        if principal.claims.iter().any(|c| c == "admin") {
            let permissions = dedup_preserving_order(requested_permissions);
            if permissions.is_empty() {
                return None;
            }
            return Some(TokenCap {
                permissions,
                repository_ids: None,
            });
        }

        // Admin-scope-by-a-non-admin is NOT a derivation concern — it is
        // the existing issuance admin gate's job (`run_issuance_gates`
        // step 3 → `AdminAuthorityRequired` / `AdminTokenDisallowed`),
        // which the issuance admin gate requires run UNCHANGED. So when a non-admin caller
        // requests `Permission::Admin`, keep it verbatim in the derived
        // cap (forcing a global shape — `Admin` only makes sense globally)
        // and let the downstream admin gate deny it. Clamping it away here
        // would silently downgrade the request to a non-admin session
        // instead of surfacing the explicit `AdminAuthorityRequired`
        // signal the caller expects.
        if requested_permissions.contains(&Permission::Admin) {
            return Some(TokenCap {
                permissions: dedup_preserving_order(requested_permissions),
                repository_ids: None,
            });
        }

        // The held footprint comes from the ONE shared enumeration —
        // the SAME subject-match + repo-scope semantics
        // as `authorize`, so the cap decision cannot drift from the
        // request-time gate. We reached here past the admin-claim
        // short-circuit, so `effective_grants` returns `is_global_admin =
        // false` and the full cell footprint. The principal's `token_cap`
        // is `None` on the exchange path; `effective_grants`
        // is cap-agnostic, matching the `authorize(.., None-cap)`
        // behaviour for every input this derivation sees.
        let footprint = self.effective_grants(&principal.claims, Some(principal.user_id), false);

        // `held_globally` ⇒ a `(None, perm)` cell authorizes the permission
        // at the system level; any `(Some(_), perm)` cell means the
        // permission is held on at least one repository.
        let held_globally = |perm: Permission| footprint.cells.contains(&(None, perm));
        let held_per_repo = |perm: Permission| {
            footprint
                .cells
                .iter()
                .any(|&(r, p)| r.is_some() && p == perm)
        };

        // Permission axis — keep only requested permissions the caller
        // holds somewhere (globally or per-repo), deduped in request order.
        let mut held_permissions: Vec<Permission> = Vec::new();
        let mut all_held_globally = true;
        for &perm in requested_permissions {
            if held_permissions.contains(&perm) {
                continue;
            }
            if held_globally(perm) {
                held_permissions.push(perm);
            } else if held_per_repo(perm) {
                held_permissions.push(perm);
                all_held_globally = false;
            }
        }

        if held_permissions.is_empty() {
            return None;
        }

        // Repository axis — a global cap when every held permission is
        // held globally; otherwise clamp to the repos on which the caller
        // holds ALL the derived permissions (a valid rectangle).
        if all_held_globally {
            return Some(TokenCap {
                permissions: held_permissions,
                repository_ids: None,
            });
        }

        // Candidate repos = the distinct repositories appearing on the
        // footprint's per-repo cells, insertion-order preserved. A repo
        // with no matching grant could never hold the (necessarily
        // per-repo-only here) derived permission set, so it would be
        // filtered out anyway — enumerating beyond the footprint is wasted
        // work (this is the cells-based equivalent of the earlier
        // `candidate_repository_ids` scan).
        let repos: Vec<Uuid> = footprint_candidate_repos(&footprint)
            .into_iter()
            .filter(|&repo| {
                held_permissions.iter().all(|&perm| {
                    held_globally(perm) || footprint.cells.contains(&(Some(repo), perm))
                })
            })
            .collect();

        if repos.is_empty() {
            // No single repository authorizes the full derived permission
            // set — fail closed rather than mint a cap whose clamp would
            // reject every cell anyway.
            return None;
        }

        Some(TokenCap {
            permissions: held_permissions,
            repository_ids: Some(repos),
        })
    }
}

/// The distinct repository ids appearing on the per-repo cells of an
/// [`EffectiveGrantSet`], de-duplicated, insertion order preserved. These
/// are the only repositories
/// [`RbacEvaluator::derive_cli_session_cap`]'s per-repo branch needs to
/// consider — a repo absent from the footprint can never hold a
/// per-repo-only derived permission, so enumerating beyond it is wasted
/// work.
fn footprint_candidate_repos(footprint: &EffectiveGrantSet) -> Vec<Uuid> {
    let mut out: Vec<Uuid> = Vec::new();
    for &(repo, _) in &footprint.cells {
        if let Some(repo) = repo {
            if !out.contains(&repo) {
                out.push(repo);
            }
        }
    }
    out
}

/// The per-grant subject match, factored to one place so
/// [`RbacEvaluator::user_grants_authorize`], [`RbacEvaluator::effective_grants`],
/// and `EffectivePermissionsUseCase::for_user` share **one** authority
/// source (no parallel `GrantSubject` match implementation).
///
/// - [`GrantSubject::Claims`]`(required)` — satisfied when every claim in
///   `required` is a subset of `claims`.
/// - [`GrantSubject::User`]`(uid)` — satisfied when `user_id == Some(uid)`.
///   `user_id = None` (the claims-only what-if resolver) therefore
///   never matches a `User` grant.
///
/// Deliberately does NOT fold in the synthetic-`admin` short-circuit — that
/// is the *caller's* concern (`authorize` / `effective_grants` apply it
/// before scanning grants), so this primitive stays a pure per-grant test.
///
/// `pub(crate)` (not module-private) because the per-user
/// effective-permissions surface needs the per-grant test
/// while keeping each matching grant's *row* shape (subject + permission +
/// repo) — it cannot route through `effective_grants`, which flattens to
/// `(repo, permission)` cells and drops the subject. Sharing this
/// primitive keeps one subject-match impl, no parallel `match` on
/// `GrantSubject` outside `rbac.rs`.
pub(crate) fn subject_matches(
    subject: &GrantSubject,
    claims: &[String],
    user_id: Option<Uuid>,
) -> bool {
    match subject {
        GrantSubject::Claims(required) => required.iter().all(|c| claims.contains(c)),
        GrantSubject::User(uid) => user_id == Some(*uid),
    }
}

/// De-duplicate a permission slice, preserving first-seen order. Used by
/// the admin branch of [`RbacEvaluator::derive_cli_session_cap`] so a
/// caller repeating a permission in the requested scope does not produce
/// a cap with duplicate entries.
fn dedup_preserving_order(perms: &[Permission]) -> Vec<Permission> {
    let mut out: Vec<Permission> = Vec::new();
    for &p in perms {
        if !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// resolve_claims
// ---------------------------------------------------------------------------

/// Flatten `ClaimMapping`s against a principal's IdP `groups` claim.
///
/// Returns the claim names whose [`ClaimMapping::idp_group`] appears in
/// `idp_groups`. Duplicates are removed (two mappings pointing at the same
/// claim, both groups present, yields the claim once). Iteration order
/// follows the `mappings` slice so output is predictable for logging and
/// tests.
///
/// This is the claim-model rename of the structural-RBAC
/// `resolve_roles_for_groups`
/// (which walked the dropped `GroupMapping` and returned *role* names).
/// [`ClaimMapping`] is the **only** source of resolved claim names — code
/// paths must not invent claim names at runtime.
/// The single synthetic exception is the `admin` claim derived from
/// `user.is_admin=true`, added by [`add_admin_claim_if_admin`] downstream
/// of this function.
///
/// Per-repository scoping of claim resolution is not modelled here:
/// repository scoping lives on `PermissionGrant.repository_id` and is
/// enforced at authorize-time.
pub fn resolve_claims(mappings: &[ClaimMapping], idp_groups: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for mapping in mappings {
        if idp_groups.iter().any(|g| g == &mapping.idp_group) && !out.contains(&mapping.claim) {
            out.push(mapping.claim.clone());
        }
    }
    out
}

// ---------------------------------------------------------------------------
// add_admin_claim_if_admin
// ---------------------------------------------------------------------------

/// Append the synthetic `admin` claim to `claims` iff `is_admin` and it is
/// not already present.
///
/// **Idempotent**: calling it twice, or on a claim set that already
/// resolved an `admin` claim from `claim_mappings`, never produces a
/// duplicate. This keeps the `User.is_admin` bit and the `admin` claim in
/// sync by construction — auditors querying "who has admin?" can grep the
/// bit or the claim and get the same answer.
///
/// `pub(crate)` because every principal-build path (OIDC happy path,
/// PAT path, dispatcher synthesis) calls it. It is intentionally NOT
/// public API: external crates build principals through the use-case
/// layer, not by hand.
pub(crate) fn add_admin_claim_if_admin(claims: &mut Vec<String>, is_admin: bool) {
    if is_admin && !claims.iter().any(|c| c == "admin") {
        claims.push("admin".to_string());
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::Utc;

    use hort_domain::entities::api_token::TokenCap;
    use hort_domain::entities::managed_by::ManagedBy;

    // -- fixtures ----------------------------------------------------------

    /// A claims-subject grant.
    fn claims_grant(required: &[&str], repo: Option<Uuid>, perm: Permission) -> PermissionGrant {
        PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::Claims(required.iter().map(|s| (*s).to_string()).collect()),
            repository_id: repo,
            permission: perm,
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
            created_at: Utc::now(),
        }
    }

    /// A user-subject grant.
    fn user_grant(uid: Uuid, repo: Option<Uuid>, perm: Permission) -> PermissionGrant {
        PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::User(uid),
            repository_id: repo,
            permission: perm,
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
            created_at: Utc::now(),
        }
    }

    /// A principal carrying the given claim strings, no token cap.
    fn principal(claims: &[&str]) -> CallerPrincipal {
        CallerPrincipal {
            user_id: Uuid::new_v4(),
            external_id: "test:sub".into(),
            username: "tester".into(),
            email: "tester@example.com".into(),
            claims: claims.iter().map(|s| (*s).to_string()).collect(),
            token_kind: None,
            issued_at: Utc::now(),
            token_cap: None,
        }
    }

    /// A principal with an explicit user id (for `GrantSubject::User`
    /// tests) and the given claims.
    fn principal_with_id(uid: Uuid, claims: &[&str]) -> CallerPrincipal {
        let mut p = principal(claims);
        p.user_id = uid;
        p
    }

    /// Same as [`principal`] but pre-populated with a token cap.
    fn principal_with_cap(claims: &[&str], cap: TokenCap) -> CallerPrincipal {
        let mut p = principal(claims);
        p.token_cap = Some(cap);
        p
    }

    /// Same as [`principal`] but with explicit `token_kind` / `token_cap`,
    /// for the B1 cap-backstop tests (ADR 0036).
    fn principal_kind_cap(
        claims: &[&str],
        kind: Option<TokenKind>,
        token_cap: Option<TokenCap>,
    ) -> CallerPrincipal {
        let mut p = principal(claims);
        p.token_kind = kind;
        p.token_cap = token_cap;
        p
    }

    fn cap(perms: Vec<Permission>, repos: Option<Vec<Uuid>>) -> TokenCap {
        TokenCap {
            permissions: perms,
            repository_ids: repos,
        }
    }

    fn mapping(idp_group: &str, claim: &str) -> ClaimMapping {
        ClaimMapping {
            id: Uuid::new_v4(),
            idp_group: idp_group.into(),
            claim: claim.into(),
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
        }
    }

    // -- authorize: admin short-circuit ------------------------------------

    #[test]
    fn authorize_admin_claim_short_circuits_allows_write_without_grants() {
        let eval = RbacEvaluator::new(Vec::new());
        let p = principal(&["admin"]);
        assert!(eval.authorize(&p, Permission::Write, Some(Uuid::new_v4())));
    }

    #[test]
    fn authorize_admin_claim_short_circuits_for_all_permissions() {
        let eval = RbacEvaluator::new(Vec::new());
        let p = principal(&["admin"]);
        for perm in [
            Permission::Read,
            Permission::Write,
            Permission::Delete,
            Permission::Admin,
        ] {
            assert!(
                eval.authorize(&p, perm, None),
                "admin short-circuit failed for {perm:?}"
            );
            assert!(
                eval.authorize(&p, perm, Some(Uuid::new_v4())),
                "admin short-circuit failed for {perm:?} with repo"
            );
        }
    }

    #[test]
    fn authorize_admin_short_circuit_case_sensitive() {
        // The convention is lowercase "admin". Uppercase / mixed case must
        // NOT trigger the short-circuit — see the doc comment on
        // `authorize`. (Carried over from the structural-RBAC test of the
        // same name; the field moved from `roles` to `claims`.)
        let eval = RbacEvaluator::new(Vec::new());
        let p = principal(&["ADMIN"]);
        assert!(!eval.authorize(&p, Permission::Write, None));

        let p_mixed = principal(&["Admin"]);
        assert!(!eval.authorize(&p_mixed, Permission::Write, None));

        // Sanity: the canonical spelling still works.
        let p_ok = principal(&["admin"]);
        assert!(eval.authorize(&p_ok, Permission::Write, None));
    }

    #[test]
    fn authorize_denies_when_principal_has_no_claims_and_no_grants() {
        let eval = RbacEvaluator::new(Vec::new());
        let p = principal(&[]);
        for perm in [
            Permission::Read,
            Permission::Write,
            Permission::Delete,
            Permission::Admin,
        ] {
            assert!(!eval.authorize(&p, perm, None));
            assert!(!eval.authorize(&p, perm, Some(Uuid::new_v4())));
        }
    }

    // -- authorize: B1 fail-closed cap backstop (ADR 0036) -----------------

    #[test]
    fn b1_admin_claim_pat_with_none_cap_is_denied() {
        // A cap-bound native token (Pat) carrying the admin claim but no cap
        // is an anomalous construction — `authenticate_pat` always builds
        // `Some(cap)`. The backstop fails closed.
        let eval = RbacEvaluator::new(Vec::new());
        let p = principal_kind_cap(&["admin"], Some(TokenKind::Pat), None);
        assert!(!eval.authorize(&p, Permission::Write, None));
        assert!(!eval.authorize(&p, Permission::Read, Some(Uuid::new_v4())));
    }

    #[test]
    fn b1_admin_claim_service_account_with_none_cap_is_denied() {
        let eval = RbacEvaluator::new(Vec::new());
        let p = principal_kind_cap(&["admin"], Some(TokenKind::ServiceAccount), None);
        assert!(!eval.authorize(&p, Permission::Write, None));
        assert!(!eval.authorize(&p, Permission::Read, Some(Uuid::new_v4())));
    }

    #[test]
    fn b1_admin_claim_oidc_none_kind_with_none_cap_is_authorized() {
        // LOAD-BEARING SAFETY: an OIDC bearer admin (token_kind = None)
        // legitimately carries a `None` cap and is full-authority by design.
        // The backstop must NOT deny it.
        let eval = RbacEvaluator::new(Vec::new());
        let p = principal_kind_cap(&["admin"], None, None);
        for perm in [
            Permission::Read,
            Permission::Write,
            Permission::Delete,
            Permission::Admin,
        ] {
            assert!(
                eval.authorize(&p, perm, None),
                "OIDC admin denied for {perm:?}"
            );
            assert!(
                eval.authorize(&p, perm, Some(Uuid::new_v4())),
                "OIDC admin denied for {perm:?} with repo"
            );
        }
    }

    #[test]
    fn b1_admin_claim_cli_session_with_none_cap_is_authorized() {
        // LOAD-BEARING SAFETY: a CliSession admin (token_kind = Some(CliSession))
        // legitimately carries a `None` cap (authority = claims + live grants,
        // no cap leg). The backstop must NOT deny it.
        let eval = RbacEvaluator::new(Vec::new());
        let p = principal_kind_cap(&["admin"], Some(TokenKind::CliSession), None);
        for perm in [
            Permission::Read,
            Permission::Write,
            Permission::Delete,
            Permission::Admin,
        ] {
            assert!(
                eval.authorize(&p, perm, None),
                "CliSession admin denied for {perm:?}"
            );
            assert!(
                eval.authorize(&p, perm, Some(Uuid::new_v4())),
                "CliSession admin denied for {perm:?} with repo"
            );
        }
    }

    #[test]
    fn b1_admin_claim_pat_with_some_cap_still_authorized() {
        // The short-circuit still grants when the Pat carries a cap; the cap
        // then clips at the `authorize` AND. With a permissive cap (the
        // requested permission present, no repo restriction) the AND passes.
        let eval = RbacEvaluator::new(Vec::new());
        let token_cap = cap(vec![Permission::Write, Permission::Read], None);
        let p = principal_kind_cap(&["admin"], Some(TokenKind::Pat), Some(token_cap));
        assert!(eval.authorize(&p, Permission::Write, None));
        assert!(eval.authorize(&p, Permission::Read, Some(Uuid::new_v4())));
    }

    // -- authorize: GrantSubject::Claims arm -------------------------------

    #[test]
    fn authorize_claims_subset_hit_single_claim() {
        let g = claims_grant(&["developer"], None, Permission::Write);
        let eval = RbacEvaluator::new(vec![g]);
        let p = principal(&["developer"]);
        assert!(eval.authorize(&p, Permission::Write, None));
    }

    #[test]
    fn authorize_claims_subset_hit_multi_claim_requirement() {
        // Grant requires BOTH claims; principal carries both (+ an extra).
        let g = claims_grant(&["developer", "team-alpha"], None, Permission::Write);
        let eval = RbacEvaluator::new(vec![g]);
        let p = principal(&["developer", "team-alpha", "noise"]);
        assert!(eval.authorize(&p, Permission::Write, None));
    }

    #[test]
    fn authorize_claims_subset_miss_partial_overlap() {
        // Grant requires BOTH; principal carries only one → not a subset.
        let g = claims_grant(&["developer", "team-alpha"], None, Permission::Write);
        let eval = RbacEvaluator::new(vec![g]);
        let p = principal(&["developer"]);
        assert!(!eval.authorize(&p, Permission::Write, None));
    }

    #[test]
    fn authorize_claims_subset_miss_no_overlap() {
        let g = claims_grant(&["developer"], None, Permission::Write);
        let eval = RbacEvaluator::new(vec![g]);
        let p = principal(&["reader"]);
        assert!(!eval.authorize(&p, Permission::Write, None));
    }

    #[test]
    fn authorize_claims_grant_denies_when_permission_not_granted() {
        let g = claims_grant(&["reader"], None, Permission::Read);
        let eval = RbacEvaluator::new(vec![g]);
        let p = principal(&["reader"]);
        assert!(eval.authorize(&p, Permission::Read, None));
        assert!(!eval.authorize(&p, Permission::Write, None));
        assert!(!eval.authorize(&p, Permission::Delete, None));
    }

    #[test]
    fn authorize_multiple_grants_any_satisfying_permits() {
        // One grant gives reader Read; another gives developer Write.
        // Principal carries both claims; Write must be permitted via the
        // second grant.
        let eval = RbacEvaluator::new(vec![
            claims_grant(&["reader"], None, Permission::Read),
            claims_grant(&["developer"], None, Permission::Write),
        ]);
        let p = principal(&["reader", "developer"]);
        assert!(eval.authorize(&p, Permission::Write, None));
        assert!(eval.authorize(&p, Permission::Read, None));
    }

    // -- authorize: GrantSubject::User arm ---------------------------------

    #[test]
    fn authorize_user_subject_hit_identity_match() {
        let uid = Uuid::new_v4();
        let g = user_grant(uid, None, Permission::Write);
        let eval = RbacEvaluator::new(vec![g]);
        // Principal carries NO claims — authority is purely the user-id
        // grant (the service-account shape).
        let p = principal_with_id(uid, &[]);
        assert!(eval.authorize(&p, Permission::Write, None));
    }

    #[test]
    fn authorize_user_subject_miss_different_user() {
        let granted_uid = Uuid::new_v4();
        let g = user_grant(granted_uid, None, Permission::Write);
        let eval = RbacEvaluator::new(vec![g]);
        let p = principal_with_id(Uuid::new_v4(), &[]);
        assert!(!eval.authorize(&p, Permission::Write, None));
    }

    #[test]
    fn authorize_user_subject_denies_when_permission_not_granted() {
        let uid = Uuid::new_v4();
        let g = user_grant(uid, None, Permission::Read);
        let eval = RbacEvaluator::new(vec![g]);
        let p = principal_with_id(uid, &[]);
        assert!(eval.authorize(&p, Permission::Read, None));
        assert!(!eval.authorize(&p, Permission::Write, None));
    }

    // -- authorize: repository scoping -------------------------------------

    #[test]
    fn authorize_global_grant_matches_any_repository_including_none() {
        let g = claims_grant(&["developer"], None, Permission::Write);
        let eval = RbacEvaluator::new(vec![g]);
        let p = principal(&["developer"]);
        assert!(eval.authorize(&p, Permission::Write, Some(Uuid::new_v4())));
        assert!(eval.authorize(&p, Permission::Write, None));
    }

    #[test]
    fn authorize_repo_scoped_claims_grant_matches_only_target_repo() {
        let repo_a = Uuid::new_v4();
        let repo_b = Uuid::new_v4();
        let g = claims_grant(&["developer"], Some(repo_a), Permission::Write);
        let eval = RbacEvaluator::new(vec![g]);
        let p = principal(&["developer"]);
        assert!(eval.authorize(&p, Permission::Write, Some(repo_a)));
        assert!(!eval.authorize(&p, Permission::Write, Some(repo_b)));
        assert!(!eval.authorize(&p, Permission::Write, None));
    }

    #[test]
    fn authorize_repo_scoped_user_grant_matches_only_target_repo() {
        let uid = Uuid::new_v4();
        let repo_a = Uuid::new_v4();
        let repo_b = Uuid::new_v4();
        let g = user_grant(uid, Some(repo_a), Permission::Write);
        let eval = RbacEvaluator::new(vec![g]);
        let p = principal_with_id(uid, &[]);
        assert!(eval.authorize(&p, Permission::Write, Some(repo_a)));
        assert!(!eval.authorize(&p, Permission::Write, Some(repo_b)));
        assert!(!eval.authorize(&p, Permission::Write, None));
    }

    #[test]
    fn authorize_empty_grant_set_denies_non_admin() {
        let eval = RbacEvaluator::new(Vec::new());
        let p = principal(&["developer"]);
        assert!(!eval.authorize(&p, Permission::Read, None));
        assert!(!eval.authorize(&p, Permission::Write, Some(Uuid::new_v4())));
    }

    // -- evaluator construction / marker traits ----------------------------

    #[test]
    fn evaluator_is_clone() {
        let original =
            RbacEvaluator::new(vec![claims_grant(&["developer"], None, Permission::Write)]);
        let cloned = original.clone();
        let p = principal(&["developer"]);
        assert_eq!(
            original.authorize(&p, Permission::Write, None),
            cloned.authorize(&p, Permission::Write, None)
        );
        assert!(cloned.authorize(&p, Permission::Write, None));
    }

    #[test]
    fn evaluator_is_send_sync() {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RbacEvaluator>();
    }

    // -- resolve_claims ----------------------------------------------------

    #[test]
    fn resolve_empty_groups_returns_empty() {
        let mappings = vec![mapping("admins", "admin")];
        let groups: Vec<String> = vec![];
        assert!(resolve_claims(&mappings, &groups).is_empty());
    }

    #[test]
    fn resolve_single_group_single_mapping_returns_claim() {
        let mappings = vec![mapping("admins", "admin")];
        let groups = vec!["admins".to_string()];
        assert_eq!(
            resolve_claims(&mappings, &groups),
            vec!["admin".to_string()]
        );
    }

    #[test]
    fn resolve_unmatched_group_returns_empty() {
        let mappings = vec![mapping("admins", "admin")];
        let groups = vec!["not-mapped".to_string()];
        assert!(resolve_claims(&mappings, &groups).is_empty());
    }

    #[test]
    fn resolve_multiple_groups_multiple_claims_order_preserved() {
        let mappings = vec![mapping("admins", "admin"), mapping("devs", "developer")];
        let groups = vec!["admins".to_string(), "devs".to_string()];
        // Order follows the `mappings` slice, not the `groups` slice.
        assert_eq!(
            resolve_claims(&mappings, &groups),
            vec!["admin".to_string(), "developer".to_string()]
        );
    }

    #[test]
    fn resolve_deduplicates_claims_when_groups_overlap() {
        let mappings = vec![mapping("admins-a", "admin"), mapping("admins-b", "admin")];
        let groups = vec!["admins-a".to_string(), "admins-b".to_string()];
        assert_eq!(
            resolve_claims(&mappings, &groups),
            vec!["admin".to_string()]
        );
    }

    #[test]
    fn resolve_order_follows_mappings_not_groups() {
        // groups arrive devs-first, but mappings list admins-first →
        // output is admins-first (iteration order = mappings order).
        let mappings = vec![mapping("admins", "admin"), mapping("devs", "developer")];
        let groups = vec!["devs".to_string(), "admins".to_string()];
        assert_eq!(
            resolve_claims(&mappings, &groups),
            vec!["admin".to_string(), "developer".to_string()]
        );
    }

    // -- add_admin_claim_if_admin ------------------------------------------

    #[test]
    fn add_admin_claim_appends_when_admin_and_absent() {
        let mut claims = vec!["developer".to_string()];
        add_admin_claim_if_admin(&mut claims, true);
        assert_eq!(claims, vec!["developer".to_string(), "admin".to_string()]);
    }

    #[test]
    fn add_admin_claim_noop_when_not_admin() {
        let mut claims = vec!["developer".to_string()];
        add_admin_claim_if_admin(&mut claims, false);
        assert_eq!(claims, vec!["developer".to_string()]);
    }

    #[test]
    fn add_admin_claim_noop_when_not_admin_and_empty() {
        let mut claims: Vec<String> = Vec::new();
        add_admin_claim_if_admin(&mut claims, false);
        assert!(claims.is_empty());
    }

    #[test]
    fn add_admin_claim_idempotent_when_already_present() {
        // Already resolved an `admin` claim from claim_mappings → no dup.
        let mut claims = vec!["admin".to_string()];
        add_admin_claim_if_admin(&mut claims, true);
        assert_eq!(claims, vec!["admin".to_string()]);
    }

    #[test]
    fn add_admin_claim_idempotent_across_double_call() {
        let mut claims: Vec<String> = Vec::new();
        add_admin_claim_if_admin(&mut claims, true);
        add_admin_claim_if_admin(&mut claims, true);
        assert_eq!(claims, vec!["admin".to_string()]);
    }

    // ====================================================================
    // Cap-intersection integration tests.
    //
    // Each test exercises the FULL `authorize` call path (real evaluator,
    // real flat grant set) with a `principal.token_cap = Some(cap)` —
    // proving the cap leg composes via AND with the user-grants leg.
    // Expressed against the additive-claims subject model: the user-grants
    // leg is driven by `GrantSubject::Claims` / `GrantSubject::User`
    // instead of role-name resolution, but the AND composition with the
    // shared `cap_allows_optional_repo` leg is unchanged.
    // ====================================================================

    /// Helper: an evaluator where the `developer` claim grants `Write` on
    /// `repo_a`.
    fn dev_writes_repo_a(repo_a: Uuid) -> RbacEvaluator {
        RbacEvaluator::new(vec![claims_grant(
            &["developer"],
            Some(repo_a),
            Permission::Write,
        )])
    }

    #[test]
    fn cap_read_only_denies_write_even_when_user_has_write() {
        let repo_a = Uuid::new_v4();
        let eval = dev_writes_repo_a(repo_a);
        let p = principal_with_cap(&["developer"], cap(vec![Permission::Read], None));
        assert!(!eval.authorize(&p, Permission::Write, Some(repo_a)));
    }

    #[test]
    fn cap_read_and_write_allows_both_when_user_has_both() {
        let repo_a = Uuid::new_v4();
        let eval = RbacEvaluator::new(vec![
            claims_grant(&["developer"], Some(repo_a), Permission::Read),
            claims_grant(&["developer"], Some(repo_a), Permission::Write),
        ]);
        let p = principal_with_cap(
            &["developer"],
            cap(vec![Permission::Read, Permission::Write], None),
        );
        assert!(eval.authorize(&p, Permission::Read, Some(repo_a)));
        assert!(eval.authorize(&p, Permission::Write, Some(repo_a)));
        // Delete is outside the cap — denied even if user grants permitted it.
        assert!(!eval.authorize(&p, Permission::Delete, Some(repo_a)));
    }

    #[test]
    fn cap_repo_scoped_denies_other_repo_even_when_user_has_global_grant() {
        // GLOBAL Write grant for the developer claim — the user can write
        // to any repo via the user-grants leg. The cap restricts to
        // repo_a; repo_b must therefore be denied.
        let eval = RbacEvaluator::new(vec![claims_grant(&["developer"], None, Permission::Write)]);
        let repo_a = Uuid::new_v4();
        let repo_b = Uuid::new_v4();
        let p = principal_with_cap(
            &["developer"],
            cap(vec![Permission::Write], Some(vec![repo_a])),
        );
        assert!(eval.authorize(&p, Permission::Write, Some(repo_a)));
        assert!(!eval.authorize(&p, Permission::Write, Some(repo_b)));
    }

    #[test]
    fn cap_with_empty_repo_set_denies_all() {
        // Some(vec![]) — structurally allowed for forward-compat with
        // CliSession transient state. Runtime intersection treats it as
        // "no repos permitted by cap" — every authorize call denies.
        let eval = RbacEvaluator::new(vec![claims_grant(&["developer"], None, Permission::Read)]);
        let p = principal_with_cap(&["developer"], cap(vec![Permission::Read], Some(vec![])));
        assert!(!eval.authorize(&p, Permission::Read, Some(Uuid::new_v4())));
        assert!(!eval.authorize(&p, Permission::Read, None));
    }

    #[test]
    fn cap_no_repo_restriction_with_none_repo_arg_only_permission_leg_applies() {
        let eval = RbacEvaluator::new(vec![claims_grant(&["developer"], None, Permission::Read)]);
        let p = principal_with_cap(&["developer"], cap(vec![Permission::Read], None));
        // User has a global Read grant; cap permits Read; system-level op → allow.
        assert!(eval.authorize(&p, Permission::Read, None));
        // Same shape, but Write requested → cap permission leg denies.
        assert!(!eval.authorize(&p, Permission::Write, None));
    }

    #[test]
    fn cap_per_repo_restricted_denies_system_level_op() {
        // cap.repository_ids = Some([…]) on a `None` repo arg → DENY.
        let repo_a = Uuid::new_v4();
        let eval = dev_writes_repo_a(repo_a);
        let p = principal_with_cap(
            &["developer"],
            cap(vec![Permission::Write], Some(vec![repo_a])),
        );
        assert!(!eval.authorize(&p, Permission::Write, None));
    }

    #[test]
    fn admin_user_with_admin_cap_permits_admin_action() {
        // Admin claim + cap = [Admin] → allow Admin operation. Both legs
        // satisfied: admin short-circuit on the user leg, cap explicitly
        // permits Admin.
        let eval = RbacEvaluator::new(Vec::new());
        let p = principal_with_cap(&["admin"], cap(vec![Permission::Admin], None));
        assert!(eval.authorize(&p, Permission::Admin, None));
        assert!(eval.authorize(&p, Permission::Admin, Some(Uuid::new_v4())));
    }

    #[test]
    fn admin_user_with_non_admin_cap_denies_admin_action() {
        // Admin short-circuit no longer bypasses the cap leg.
        // Admin claim + cap = [Read,Write] requesting Admin → DENY (cap doesn't list Admin).
        let eval = RbacEvaluator::new(Vec::new());
        let p = principal_with_cap(
            &["admin"],
            cap(vec![Permission::Read, Permission::Write], None),
        );
        assert!(!eval.authorize(&p, Permission::Admin, None));
        // Read/Write are inside the cap → admin leg + cap leg both pass.
        assert!(eval.authorize(&p, Permission::Read, None));
        assert!(eval.authorize(&p, Permission::Write, None));
    }

    #[test]
    fn admin_user_with_repo_restricted_cap_denies_outside_repo() {
        let eval = RbacEvaluator::new(Vec::new());
        let repo_a = Uuid::new_v4();
        let repo_b = Uuid::new_v4();
        let p = principal_with_cap(&["admin"], cap(vec![Permission::Write], Some(vec![repo_a])));
        assert!(eval.authorize(&p, Permission::Write, Some(repo_a)));
        assert!(!eval.authorize(&p, Permission::Write, Some(repo_b)));
    }

    #[test]
    fn token_cap_none_preserves_legacy_behaviour() {
        // The contract for non-token callers: results are unchanged.
        let repo_a = Uuid::new_v4();
        let eval = dev_writes_repo_a(repo_a);

        // User with developer claim — user-grants leg authoritative.
        let dev_no_cap = principal(&["developer"]);
        assert!(eval.authorize(&dev_no_cap, Permission::Write, Some(repo_a)));
        assert!(!eval.authorize(&dev_no_cap, Permission::Read, Some(repo_a)));

        // Admin short-circuit unaffected when no cap is present.
        let admin_no_cap = principal(&["admin"]);
        for perm in [
            Permission::Read,
            Permission::Write,
            Permission::Delete,
            Permission::Admin,
        ] {
            assert!(eval.authorize(&admin_no_cap, perm, None));
            assert!(eval.authorize(&admin_no_cap, perm, Some(repo_a)));
        }
    }

    #[test]
    fn cap_with_grant_missing_denies_even_when_cap_permits() {
        // The cap permits Write but the user has no Write grant on
        // repo_a → user-grants leg denies → AND denies.
        let eval = RbacEvaluator::new(Vec::new());
        let repo_a = Uuid::new_v4();
        let p = principal_with_cap(
            &["developer"],
            cap(vec![Permission::Write], Some(vec![repo_a])),
        );
        assert!(!eval.authorize(&p, Permission::Write, Some(repo_a)));
    }

    #[test]
    fn user_subject_grant_composes_with_cap_leg() {
        // The service-account shape under a token cap: authority
        // is a `GrantSubject::User` grant, gated by the cap leg via AND.
        let uid = Uuid::new_v4();
        let repo_a = Uuid::new_v4();
        let eval = RbacEvaluator::new(vec![user_grant(uid, Some(repo_a), Permission::Write)]);

        // Cap permits Write on repo_a, principal id matches the grant.
        let mut p = principal_with_cap(&[], cap(vec![Permission::Write], Some(vec![repo_a])));
        p.user_id = uid;
        assert!(eval.authorize(&p, Permission::Write, Some(repo_a)));

        // Same principal, cap downgraded to Read → user leg passes but cap
        // leg denies the Write.
        let mut p_ro = principal_with_cap(&[], cap(vec![Permission::Read], Some(vec![repo_a])));
        p_ro.user_id = uid;
        assert!(!eval.authorize(&p_ro, Permission::Write, Some(repo_a)));
    }

    /// **Live-intersection regression test.**
    ///
    /// Build evaluator A where the developer claim grants Write on
    /// `repo_a`; principal carries cap `[Read, Write]`. Authorize succeeds.
    ///
    /// Rebuild evaluator B with the SAME principal (same `token_cap`,
    /// same `claims`) but the grant removed — i.e. the grant has been
    /// revoked. Authorize must DENY even though the cap is unchanged.
    ///
    /// This proves the "live" part of the live-intersection invariant:
    /// the cap doesn't carry frozen grants, so revoking the grant
    /// invalidates token authority on the next authorize call.
    #[test]
    fn live_intersection_grant_revoked_denies_next_call() {
        let repo_a = Uuid::new_v4();
        let cap_rw = cap(
            vec![Permission::Read, Permission::Write],
            Some(vec![repo_a]),
        );
        let p = principal_with_cap(&["developer"], cap_rw.clone());

        // Evaluator A: developer claim grants Write on repo_a.
        let eval_a = dev_writes_repo_a(repo_a);
        assert!(
            eval_a.authorize(&p, Permission::Write, Some(repo_a)),
            "pre-revocation: cap permits Write, user has Write → allow"
        );

        // Evaluator B: same principal, same cap, but the grant is gone.
        // Cap is unchanged — but the user-grants leg now denies, so the
        // AND denies. Token authority drops automatically.
        let eval_b = RbacEvaluator::new(Vec::new());
        assert!(
            !eval_b.authorize(&p, Permission::Write, Some(repo_a)),
            "post-revocation: cap unchanged, but user lost Write grant → deny"
        );

        // Sanity: the token cap itself is unchanged across the rebuild.
        assert_eq!(
            p.token_cap.as_ref().unwrap(),
            &cap_rw,
            "cap field is fixed at issuance and must not have mutated"
        );
    }

    // -- claims_satisfy ----------------------------------------------------

    #[test]
    fn claims_satisfy_all_required_present_is_true() {
        let eval = RbacEvaluator::new(Vec::new());
        let p = principal(&["task-admin", "task:destructive"]);
        assert!(eval.claims_satisfy(&p, &["task:destructive"]));
        assert!(eval.claims_satisfy(&p, &["task-admin", "task:destructive"]));
    }

    #[test]
    fn claims_satisfy_missing_required_is_false() {
        let eval = RbacEvaluator::new(Vec::new());
        let p = principal(&["task-admin"]); // no task:destructive
        assert!(!eval.claims_satisfy(&p, &["task:destructive"]));
    }

    #[test]
    fn claims_satisfy_partial_overlap_is_false() {
        let eval = RbacEvaluator::new(Vec::new());
        let p = principal(&["task:destructive"]);
        // Requires both; only one present → not a subset.
        assert!(!eval.claims_satisfy(&p, &["task:destructive", "other"]));
    }

    #[test]
    fn claims_satisfy_admin_short_circuit_is_true_even_without_claim() {
        let eval = RbacEvaluator::new(Vec::new());
        let p = principal(&["admin"]); // synthetic admin, no task:destructive
        assert!(eval.claims_satisfy(&p, &["task:destructive"]));
    }

    #[test]
    fn claims_satisfy_admin_short_circuit_is_case_sensitive() {
        let eval = RbacEvaluator::new(Vec::new());
        // Uppercase must NOT short-circuit (mirrors user_grants_authorize).
        let p = principal(&["ADMIN"]);
        assert!(!eval.claims_satisfy(&p, &["task:destructive"]));
    }

    #[test]
    fn claims_satisfy_empty_required_is_vacuously_true() {
        let eval = RbacEvaluator::new(Vec::new());
        let p = principal(&[]);
        // No requirements ⇒ trivially satisfied (this pins the `.all()` boundary).
        assert!(eval.claims_satisfy(&p, &[]));
    }

    // -- derive_cli_session_cap --------------------------------------------
    //
    // The exchange-time cap derivation. Given a caller principal and the
    // requested permission set, returns the `TokenCap` the issuance gate
    // should clamp against — both the permission set AND `repository_ids`
    // clamped to what the live evaluator says the caller holds. Every cap
    // it returns is **valid by construction**: each `(perm, repo)` cell
    // (or each global `perm`) re-passes `authorize` for the same
    // principal — the issuance clamp is the defense-in-depth backstop, not
    // the primary gate.

    #[test]
    fn derive_cap_admin_yields_global_cap_with_requested_permissions() {
        // An admin (or any globally-authorized caller) derives a GLOBAL cap
        // (`repository_ids: None`) via the admin short-circuit, so the
        // existing global-branch + ≤1h admin gate run unchanged.
        let eval = RbacEvaluator::new(Vec::new());
        let p = principal(&["admin"]);
        let cap = eval
            .derive_cli_session_cap(
                &p,
                &[Permission::Read, Permission::Write, Permission::Delete],
            )
            .expect("admin must derive a non-empty cap");
        assert_eq!(cap.repository_ids, None, "admin derives a global cap");
        assert_eq!(
            cap.permissions,
            vec![Permission::Read, Permission::Write, Permission::Delete],
        );
    }

    #[test]
    fn derive_cap_global_grants_yield_global_cap() {
        // A non-admin holding every requested permission GLOBALLY (a
        // `repository_id = None` grant) derives a global cap → routes
        // through the clamp's global branch, mints unrestricted-by-repo.
        let eval = RbacEvaluator::new(vec![
            claims_grant(&["developer"], None, Permission::Read),
            claims_grant(&["developer"], None, Permission::Write),
        ]);
        let p = principal(&["developer"]);
        let cap = eval
            .derive_cli_session_cap(&p, &[Permission::Read, Permission::Write])
            .expect("global grantee derives a cap");
        assert_eq!(cap.repository_ids, None);
        assert_eq!(cap.permissions, vec![Permission::Read, Permission::Write]);
    }

    #[test]
    fn derive_cap_per_repo_uniform_grants_yield_per_repo_cap() {
        // The canonical dev-user shape: per-repo grants for `{Read, Prefetch}`
        // on three repos, NO global grant. Derivation yields
        // `{npm,pypi,cargo} × {read,prefetch}` → `Some(repos)` → the
        // clamp's per-repo branch passes.
        let npm = Uuid::new_v4();
        let pypi = Uuid::new_v4();
        let cargo = Uuid::new_v4();
        let mut rows = Vec::new();
        for repo in [npm, pypi, cargo] {
            rows.push(claims_grant(&["developer"], Some(repo), Permission::Read));
            rows.push(claims_grant(
                &["developer"],
                Some(repo),
                Permission::Prefetch,
            ));
        }
        let eval = RbacEvaluator::new(rows);
        let p = principal(&["developer", "ci-pusher"]);

        let cap = eval
            .derive_cli_session_cap(&p, &[Permission::Read, Permission::Prefetch])
            .expect("per-repo grantee derives a cap");

        assert!(
            cap.repository_ids.is_some(),
            "per-repo-only grantee must derive Some(repos), not a global cap"
        );
        let mut repos = cap.repository_ids.clone().unwrap();
        repos.sort();
        let mut expected = vec![npm, pypi, cargo];
        expected.sort();
        assert_eq!(repos, expected, "repos clamp to the three held repos");
        assert_eq!(
            cap.permissions,
            vec![Permission::Read, Permission::Prefetch],
            "permissions clamp to the held subset"
        );

        // Valid-by-construction: every cell re-authorizes under the SAME
        // principal (this is exactly what the issuance clamp re-checks).
        for &perm in &cap.permissions {
            for &repo in cap.repository_ids.as_ref().unwrap() {
                assert!(
                    eval.authorize(&p, perm, Some(repo)),
                    "derived cell ({perm:?}, {repo:?}) must re-authorize"
                );
            }
        }
    }

    #[test]
    fn derive_cap_clamps_requested_permissions_to_held_subset() {
        // A caller requests [Read, Write, Delete] but only holds Read on
        // the repo → the derived cap drops Write/Delete (clamp the
        // permission axis), keeping only what the caller actually holds.
        let repo = Uuid::new_v4();
        let eval = RbacEvaluator::new(vec![claims_grant(
            &["developer"],
            Some(repo),
            Permission::Read,
        )]);
        let p = principal(&["developer"]);
        let cap = eval
            .derive_cli_session_cap(
                &p,
                &[Permission::Read, Permission::Write, Permission::Delete],
            )
            .expect("partial-authority caller still derives a cap for what it holds");
        assert_eq!(cap.permissions, vec![Permission::Read]);
        assert_eq!(cap.repository_ids, Some(vec![repo]));
    }

    #[test]
    fn derive_cap_zero_authority_yields_none() {
        // A caller holding NONE of the requested permissions derives an
        // EMPTY footprint → None. The use case must NOT mint an empty-cap
        // token that silently authorizes nothing.
        let eval = RbacEvaluator::new(vec![claims_grant(
            &["reader"],
            Some(Uuid::new_v4()),
            Permission::Read,
        )]);
        // Principal carries NO matching claim and no grants.
        let p = principal(&["stranger"]);
        assert!(
            eval.derive_cli_session_cap(&p, &[Permission::Read, Permission::Write])
                .is_none(),
            "zero-authority caller must derive None (→ 403), never an empty cap"
        );
    }

    #[test]
    fn derive_cap_empty_requested_yields_none() {
        // Defensive boundary: an empty requested set has no footprint to
        // clamp → None (the caller asked for nothing). The issuance path
        // always resolves a non-empty default before calling, so this is
        // a guard against misuse, not a live path.
        let eval = RbacEvaluator::new(vec![claims_grant(&["developer"], None, Permission::Read)]);
        let p = principal(&["developer"]);
        assert!(eval.derive_cli_session_cap(&p, &[]).is_none());
    }

    #[test]
    fn derive_cap_global_takes_precedence_over_per_repo_for_same_permission() {
        // A permission held BOTH globally and per-repo collapses to the
        // global cap (the broader authority), not a per-repo restriction.
        let repo = Uuid::new_v4();
        let eval = RbacEvaluator::new(vec![
            claims_grant(&["developer"], None, Permission::Read),
            claims_grant(&["developer"], Some(repo), Permission::Read),
        ]);
        let p = principal(&["developer"]);
        let cap = eval
            .derive_cli_session_cap(&p, &[Permission::Read])
            .expect("derive");
        assert_eq!(
            cap.repository_ids, None,
            "a globally-held permission yields a global cap"
        );
        assert_eq!(cap.permissions, vec![Permission::Read]);
    }

    #[test]
    fn derive_cap_non_admin_dedups_repeated_requested_permission_and_skips_global_grant_in_repo_scan(
    ) {
        // Two coverage corners in one realistic shape:
        //  - a REPEATED requested permission exercises the dedup `continue`
        //    on the non-admin permission scan;
        //  - a mix of a GLOBAL grant (`repository_id = None`) and a
        //    per-repo grant exercises the `candidate_repository_ids` scan's
        //    skip-the-global-grant arm. `Prefetch` is held only per-repo,
        //    so the cap is per-repo-shaped and the global `Read` grant rides
        //    along (held on every repo via the None grant).
        let repo = Uuid::new_v4();
        let eval = RbacEvaluator::new(vec![
            claims_grant(&["developer"], None, Permission::Read),
            claims_grant(&["developer"], Some(repo), Permission::Prefetch),
        ]);
        let p = principal(&["developer"]);
        let cap = eval
            .derive_cli_session_cap(
                &p,
                // `Read` requested twice → the second hits the dedup skip.
                &[Permission::Read, Permission::Read, Permission::Prefetch],
            )
            .expect("derive");
        // `Prefetch` is per-repo-only ⇒ per-repo cap shape.
        assert_eq!(cap.repository_ids, Some(vec![repo]));
        // Deduped: `Read` appears once, `Prefetch` once.
        assert_eq!(
            cap.permissions,
            vec![Permission::Read, Permission::Prefetch]
        );
    }

    #[test]
    fn derive_cap_admin_with_empty_requested_yields_none() {
        // The admin branch's empty-requested guard: even an admin asking
        // for nothing derives no footprint → None.
        let eval = RbacEvaluator::new(Vec::new());
        let p = principal(&["admin"]);
        assert!(eval.derive_cli_session_cap(&p, &[]).is_none());
    }

    #[test]
    fn derive_cap_non_rectangular_per_repo_grants_fail_closed_to_none() {
        // A non-rectangular grant set — `Read` on repo A, `Prefetch` on
        // repo B, with neither permission held on the OTHER repo — has no
        // single repository on which the caller holds BOTH derived
        // permissions. The derivation fails CLOSED (None) rather than mint
        // a cap whose every cell the clamp would reject anyway.
        let repo_a = Uuid::new_v4();
        let repo_b = Uuid::new_v4();
        let eval = RbacEvaluator::new(vec![
            claims_grant(&["developer"], Some(repo_a), Permission::Read),
            claims_grant(&["developer"], Some(repo_b), Permission::Prefetch),
        ]);
        let p = principal(&["developer"]);
        assert!(
            eval.derive_cli_session_cap(&p, &[Permission::Read, Permission::Prefetch])
                .is_none(),
            "no single repo holds BOTH derived permissions → fail closed (None)"
        );
    }

    #[test]
    fn derive_cap_non_admin_requesting_admin_keeps_admin_for_the_gate() {
        // The admin gate (`run_issuance_gates` step 3) runs UNCHANGED.
        // A non-admin requesting `Admin` must NOT have it silently clamped
        // away (which would downgrade to a non-admin session); the
        // derivation keeps `Admin` so the downstream gate surfaces
        // `AdminAuthorityRequired`. The cap is global-shaped.
        let repo = Uuid::new_v4();
        let eval = RbacEvaluator::new(vec![claims_grant(
            &["developer"],
            Some(repo),
            Permission::Read,
        )]);
        let p = principal(&["developer"]); // NOT admin
        let cap = eval
            .derive_cli_session_cap(&p, &[Permission::Admin, Permission::Read])
            .expect("admin-requested cap is kept for the gate, not None");
        assert!(
            cap.permissions.contains(&Permission::Admin),
            "Admin must survive derivation so the admin gate can deny it"
        );
        assert_eq!(
            cap.repository_ids, None,
            "Admin-bearing cap is global-shaped"
        );
    }

    #[test]
    fn derive_cap_user_subject_grant_per_repo() {
        // The service-account shape: authority via a
        // `GrantSubject::User` grant (no claims). Derivation honors it the
        // same way `authorize` does — per-repo cap from the user grant.
        let uid = Uuid::new_v4();
        let repo = Uuid::new_v4();
        let eval = RbacEvaluator::new(vec![user_grant(uid, Some(repo), Permission::Write)]);
        let p = principal_with_id(uid, &[]);
        let cap = eval
            .derive_cli_session_cap(&p, &[Permission::Write])
            .expect("user-subject grantee derives a cap");
        assert_eq!(cap.permissions, vec![Permission::Write]);
        assert_eq!(cap.repository_ids, Some(vec![repo]));
    }

    // -- effective_grants ----------------------------------------------------
    //
    // The shared flat enumeration. Given a resolved authority set (claims +
    // optional user id + the `is_admin` flag), returns every
    // `(repository, permission)` cell the set holds — the SAME subject
    // match + admin short-circuit + repo-scope semantics as `authorize`.
    // Cap-agnostic by design: it reports the grant-leg authority,
    // not what a token can exercise.

    /// Convenience: turn `&[&str]` into the owned `Vec<String>`
    /// `effective_grants` takes (it operates on a resolved claim *slice*,
    /// not a `CallerPrincipal`).
    fn claims_vec(claims: &[&str]) -> Vec<String> {
        claims.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn effective_grants_admin_via_admin_claim_short_circuits_to_marker() {
        // `claims` carries the synthetic `admin` claim → marker, empty
        // cells, NEVER an enumeration of every repo.
        let eval = RbacEvaluator::new(vec![
            claims_grant(&["developer"], Some(Uuid::new_v4()), Permission::Read),
            claims_grant(&["admin"], None, Permission::Write),
        ]);
        let result = eval.effective_grants(&claims_vec(&["admin"]), Some(Uuid::new_v4()), false);
        assert!(result.is_global_admin);
        assert!(
            result.cells.is_empty(),
            "admin marker must NOT enumerate cells"
        );
    }

    #[test]
    fn effective_grants_admin_via_is_admin_flag_short_circuits_to_marker() {
        // The synthetic `admin` claim is folded in via the `is_admin` flag
        // even when `claims` is empty — an
        // `is_admin` Local user with no resolved claims still short-circuits.
        let eval = RbacEvaluator::new(vec![claims_grant(&["developer"], None, Permission::Read)]);
        let result = eval.effective_grants(&claims_vec(&[]), Some(Uuid::new_v4()), true);
        assert!(result.is_global_admin);
        assert!(result.cells.is_empty());
    }

    #[test]
    fn effective_grants_admin_short_circuit_case_sensitive() {
        // Mirrors `authorize`: only the lowercase `"admin"` claim
        // short-circuits. `"ADMIN"` with `is_admin = false` is NOT admin —
        // and matches no grant here, so the footprint is empty + non-admin.
        let eval = RbacEvaluator::new(vec![claims_grant(&["developer"], None, Permission::Read)]);
        let result = eval.effective_grants(&claims_vec(&["ADMIN"]), Some(Uuid::new_v4()), false);
        assert!(!result.is_global_admin);
        assert!(result.cells.is_empty());
    }

    #[test]
    fn effective_grants_global_claims_grant_yields_global_cell() {
        let eval = RbacEvaluator::new(vec![claims_grant(&["developer"], None, Permission::Write)]);
        let result = eval.effective_grants(&claims_vec(&["developer"]), None, false);
        assert!(!result.is_global_admin);
        assert_eq!(result.cells, vec![(None, Permission::Write)]);
    }

    #[test]
    fn effective_grants_per_repo_claims_grant_yields_scoped_cell() {
        let repo = Uuid::new_v4();
        let eval = RbacEvaluator::new(vec![claims_grant(
            &["developer"],
            Some(repo),
            Permission::Read,
        )]);
        let result = eval.effective_grants(&claims_vec(&["developer"]), None, false);
        assert_eq!(result.cells, vec![(Some(repo), Permission::Read)]);
    }

    #[test]
    fn effective_grants_mixed_global_and_per_repo_preserves_insertion_order() {
        let repo_a = Uuid::new_v4();
        let repo_b = Uuid::new_v4();
        let eval = RbacEvaluator::new(vec![
            claims_grant(&["developer"], None, Permission::Read),
            claims_grant(&["developer"], Some(repo_a), Permission::Write),
            claims_grant(&["developer"], Some(repo_b), Permission::Prefetch),
        ]);
        let result = eval.effective_grants(&claims_vec(&["developer"]), None, false);
        assert!(!result.is_global_admin);
        assert_eq!(
            result.cells,
            vec![
                (None, Permission::Read),
                (Some(repo_a), Permission::Write),
                (Some(repo_b), Permission::Prefetch),
            ],
            "insertion order of the matching grants is preserved"
        );
    }

    #[test]
    fn effective_grants_subset_match_requires_all_claims() {
        // A multi-claim grant matches only when EVERY required claim is
        // present (subset test — same as `authorize`'s Claims arm).
        let eval = RbacEvaluator::new(vec![claims_grant(
            &["developer", "team-alpha"],
            None,
            Permission::Write,
        )]);
        // Missing `team-alpha` → no match → empty footprint.
        let partial = eval.effective_grants(&claims_vec(&["developer"]), None, false);
        assert!(partial.cells.is_empty());
        // Both present (+ noise) → match.
        let full = eval.effective_grants(
            &claims_vec(&["developer", "team-alpha", "noise"]),
            None,
            false,
        );
        assert_eq!(full.cells, vec![(None, Permission::Write)]);
    }

    #[test]
    fn effective_grants_user_id_none_excludes_user_grants() {
        // `user_id = None` (claims-only what-if resolver) NEVER matches a
        // `GrantSubject::User` grant, even one whose uid would match a real
        // caller. Only the claims grant survives.
        let uid = Uuid::new_v4();
        let eval = RbacEvaluator::new(vec![
            user_grant(uid, None, Permission::Write),
            claims_grant(&["developer"], None, Permission::Read),
        ]);
        let result = eval.effective_grants(&claims_vec(&["developer"]), None, false);
        assert_eq!(
            result.cells,
            vec![(None, Permission::Read)],
            "User grant excluded when user_id is None"
        );
    }

    #[test]
    fn effective_grants_user_id_some_includes_matching_user_grants() {
        // `user_id = Some(uid)` includes the `User(uid)` grant alongside
        // claims grants — the self / per-user view.
        let uid = Uuid::new_v4();
        let repo = Uuid::new_v4();
        let eval = RbacEvaluator::new(vec![
            user_grant(uid, Some(repo), Permission::Write),
            claims_grant(&["developer"], None, Permission::Read),
        ]);
        let result = eval.effective_grants(&claims_vec(&["developer"]), Some(uid), false);
        assert_eq!(
            result.cells,
            vec![(Some(repo), Permission::Write), (None, Permission::Read),]
        );
    }

    #[test]
    fn effective_grants_user_id_some_excludes_other_users_grants() {
        // A `User(other)` grant does not match `Some(uid)` when the uids
        // differ — identity match, same as `authorize`.
        let uid = Uuid::new_v4();
        let other = Uuid::new_v4();
        let eval = RbacEvaluator::new(vec![user_grant(other, None, Permission::Write)]);
        let result = eval.effective_grants(&claims_vec(&[]), Some(uid), false);
        assert!(result.cells.is_empty());
    }

    #[test]
    fn effective_grants_empty_claims_no_user_yields_empty_cells() {
        // No claims, no user id, not admin → holds nothing. Non-admin
        // marker + empty cells (distinct from the admin marker).
        let eval = RbacEvaluator::new(vec![claims_grant(&["developer"], None, Permission::Read)]);
        let result = eval.effective_grants(&claims_vec(&[]), None, false);
        assert!(!result.is_global_admin);
        assert!(result.cells.is_empty());
    }

    #[test]
    fn effective_grants_deduplicates_identical_cells() {
        // Two distinct grant rows producing the SAME (repo, perm) cell
        // (e.g. one `Claims(["developer"])` grant and one
        // `Claims(["team-alpha"])` grant, both global Read, caller holds
        // both claims) collapse to a single cell, insertion order kept.
        let eval = RbacEvaluator::new(vec![
            claims_grant(&["developer"], None, Permission::Read),
            claims_grant(&["team-alpha"], None, Permission::Read),
        ]);
        let result = eval.effective_grants(&claims_vec(&["developer", "team-alpha"]), None, false);
        assert_eq!(
            result.cells,
            vec![(None, Permission::Read)],
            "duplicate (repo, perm) cells are collapsed to one"
        );
    }

    #[test]
    fn effective_grants_agrees_with_authorize_per_cell() {
        // The load-bearing invariant: every cell `effective_grants`
        // produces re-authorizes under a cap-free principal carrying the
        // same claims/user — proving "one authority source" (G3) at the
        // value level, not just structurally.
        let uid = Uuid::new_v4();
        let repo = Uuid::new_v4();
        let eval = RbacEvaluator::new(vec![
            claims_grant(&["developer"], None, Permission::Read),
            claims_grant(&["developer"], Some(repo), Permission::Write),
            user_grant(uid, Some(repo), Permission::Delete),
        ]);
        let p = principal_with_id(uid, &["developer"]);
        let result = eval.effective_grants(&p.claims, Some(p.user_id), false);
        for (cell_repo, perm) in &result.cells {
            assert!(
                eval.authorize(&p, *perm, *cell_repo),
                "cell ({cell_repo:?}, {perm:?}) must re-authorize"
            );
        }
        // And the cell set is exactly the three grants' (repo, perm).
        assert_eq!(
            result.cells,
            vec![
                (None, Permission::Read),
                (Some(repo), Permission::Write),
                (Some(repo), Permission::Delete),
            ]
        );
    }
}
