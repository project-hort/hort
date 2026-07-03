# 0044 — Service accounts are identity-only; authority is explicit grants

- **Status:** Accepted
- **Enforced by:** `ServiceAccountSpec` carries no authority fields and
  `#[serde(deny_unknown_fields)]` fails apply at parse for an envelope still
  declaring `role:` / `repositories:`
  (`crates/hort-config/src/service_account.rs`); migration
  `014_service_accounts_identity_only.sql` drops the two columns; the two
  unattended issuance sites derive the token cap from
  `RbacEvaluator::service_account_cap_permissions`
  (`crates/hort-app/src/rbac.rs`) — the federation branch of
  `crates/hort-http-core/src/handlers/exchange.rs` and the fallback-rotation
  mint in `crates/hort-app/src/task_handlers/service_account_rotation.rs`;
  the three-point non-admin enforcement (below); E2E:
  `crates/hort-server/tests/exchange_cap_derivation_e2e.rs` and the
  federation host-test (`scripts/host-tests/test-gitops-machine-identity.sh`).
- **Supersedes:** the envelope-authority statements in earlier ADRs, **on that
  point only** (the ADRs themselves stand as historical records; see
  *Supersession notes* below): [0034](0034-public-dogfood-deployment.md)
  §"Surface 1" ("`role` and `repositories` confer authority; there are no
  `PermissionGrant`s" and the three `role: reader`/`developer` SA
  descriptions), [0037](0037-gitops-service-account-grant.md) §Context (the
  role/repositories envelope baseline the grant shape supplemented),
  [0038](0038-admin-identity-model.md) §Decision 2 ("apply-time validation
  rejects an `admin`-role SA envelope" — there is no `role` field to reject;
  the non-admin invariant rides the three-point enforcement below).
- **Relates:** [0012](0012-claim-based-rbac-claimless-static-tokens.md) (no
  server-side role bundling; SA authority via `User`-subject grants),
  [0018](0018-auth-catalog-canonical.md) (`docs/auth-catalog.md` Entries 4
  and 6 record the identity-only envelope and the issuance-cap semantics —
  updated in the same change as the behavior, per the catalog's same-PR
  rule), [0036](0036-oci-auth-capability-token.md) (the cap model this
  snapshot feeds; the B1 fail-closed Pat/SA cap backstop),
  [0037](0037-gitops-service-account-grant.md) (the `serviceAccount`-subject
  grant shape — now the *only* SA authority mechanism, no longer a
  supplement), [0038](0038-admin-identity-model.md) (service accounts
  strictly non-admin).
- **Closes:** the last gate of issue #13 — an explicitly granted `read` on a
  `developer`-role SA passed the live grants-leg but could never enter the
  issued token's cap, because the cap was derived from the envelope role, not
  from the grants.

## Context

A `ServiceAccount` gitops envelope used to carry two authority fields —
`role: reader | developer` and `repositories: [...]` — which the apply pass
materialized into `User`-subject grants and the federation exchange mapped
into the issued token's cap (`service_account_permission_for_role`:
`developer → Write`, `reader → Read`). Because authorization is
**grants-leg ∧ cap-leg** (ADR 0036) and permissions are flat, an explicit
`PermissionGrant` added beside the envelope entered the grants-leg but never
the cap: a `developer` SA with an explicit `read` grant could push an image
and then not read it back to sign it. The role was a second, partially
hidden authority source — an operator with admin tooling could not
distinguish envelope authority from grant authority, and the role→permission
mapping's own doc comment recorded that the flat `Permission` enum had
already lost the intended "bundled grant" semantics.

The fallback-rotation mint had the sibling defect in the opposite
direction: it issued with `declared_permissions: Vec::new()` — under
`cap_allows_optional_repo` an empty cap denies every authorization check,
so rotated fallback tokens were inert against any non-anonymous surface.

ADR 0012 decided that permission bundling lives in operator-side templating,
not a server-side `roles` table; the SA role enum was the one surviving
code-level exception.

## Decision

**The `ServiceAccount` envelope declares identity and federation binding
only; authority comes exclusively from explicit `PermissionGrant`s; the two
unattended issuance sites snapshot the SA's effective grants into the token
cap at issuance.**

1. **Identity-only envelope.** `ServiceAccountSpec` carries `metadata.name`,
   `federatedIdentities[]` (the non-empty-`claims` rule is unchanged —
   ADR 0018), and `fallbackRotation`. There is no `role` and no
   `repositories`; migration 014 drops the columns. An envelope still
   carrying the retired fields **fails apply at parse**
   (`deny_unknown_fields`) — a deliberate deployer signal, never a silent
   ignore (ADR 0015 discipline).

2. **Grants-only authority.** Nothing is materialized from the envelope.
   The SA's authority is exactly its explicit `PermissionGrant`s — normally
   the `serviceAccount`-subject gitops shape (ADR 0037), resolving to
   `GrantSubject::User(backing_user_id)` — evaluated by the same live
   grants-leg every request rides.

3. **Grants-snapshot issuance caps — both unattended sites.** The federation
   `/exchange` and the fallback-rotation mint derive the issued token's
   `declared_permissions` from
   `RbacEvaluator::service_account_cap_permissions(backing_user_id, scope)`:
   the distinct permission set of the backing user's effective grants,
   enumerated with `claims: []` and `is_admin: false` — only
   `User(backing_user_id)`-subject grants enter the cap, no claims-grants,
   nothing ambient. `repository_ids` stays unset: repo scoping is enforced
   by the live grants-leg, so the cap never goes stale on the repository
   axis.
   - **Exchange ∩ requested scope.** When the RFC 8693 `scope` parameter is
     present, the cap narrows to the held subset of the requested
     permissions. A requested scope of which the SA holds nothing is denied
     `403 access_denied` / `cap_exceeds_authority` (minting an empty-cap
     token for an explicitly requested scope would look like success while
     authorizing nothing). An absent scope applies no narrowing.
   - **Zero-grant SA, no scope:** mints normally with an empty-permissions
     `Some(cap)` — the token authorizes nothing, fail-closed by intersection
     at use time, with no new error path. The ADR 0036 B1 backstop holds: an
     SA principal always carries `Some(cap)`.
   - **Rotation mint:** the identical snapshot, no scope parameter — the
     snapshot *is* the cap. Rotated fallback tokens carry the SA's real
     granted authority.

4. **Freshness semantics (deliberate).** The cap is a per-token attenuation
   snapshot. A grant added after mint does not widen an outstanding token —
   it enters the next exchange's cap (CI exchanges per job) or the next
   rotation's (staleness bounded by `rotationInterval`). A revocation bites
   outstanding tokens **immediately** through the live grants-leg, because
   authority is always grants ∩ cap.

5. **Non-admin enforcement is three-point, independent of any role.** The
   role gate's removal lost nothing, because the SA non-admin invariant
   (ADR 0038) never rested on it:
   - `hort-config::validate_permission_grant` hard-rejects a
     `serviceAccount` subject with `permission: admin` at apply-parse
     (`crates/hort-config/src/permission_grant.rs`);
   - the apply linter's `direct-user-grant-without-justification` rule
     denies the SA-provenance exemption for `Admin`
     (`crates/hort-app/src/lint/permission_grants.rs`, pinned by
     `direct_user_sa_owned_admin_is_rejected`);
   - `issue-svc-token` rejects `--permission=admin`
     (`crates/hort-server/src/cli/admin.rs`).

   A future change to any one of these points must account for the other
   two.

6. **`issue-svc-token` keeps its operator-declared cap — a deliberate
   posture asymmetry.** The interactive admin mint takes explicit
   `--permission` flags (admin rejected): an operator declaring intent for a
   static token, versus the unattended sites where no human is present and
   the granted authority is the only honest cap source. The two postures are
   intentionally different and both fail closed.

## Consequences

- **One authority source.** "What can this SA do?" has exactly one answer:
  its `PermissionGrant`s. The audit story, the effective-permissions
  endpoint, and the issued-token cap all read from the same place.
- **Parity with the user model.** Users: `ClaimMapping` binds the identity,
  claims-subject grants confer authority. Service accounts:
  `federatedIdentities` binds the identity, SA-subject grants confer
  authority. Neither carries authority in its identity envelope.
- **ADR 0012 completed.** The SA role enum was the last code-level
  permission bundle; bundling now lives entirely in operator-side templating
  for users and explicit grant documents for SAs. ADR 0037's grant shape is
  strengthened from supplemental to sole mechanism.
- The apply linter's SA-provenance exemption derives from the desired
  service-account set itself (every `desired.service_accounts` entry's
  backing user), so explicit SA-subject grants pass the
  `direct-user-grant` rule without any role replay.
- Deployments converge on first apply: the managed-partition full-reconcile
  drops previously role-materialized grant rows from the desired set;
  explicit grant documents carry the authority from the same apply onward.

## Alternatives considered

- **Widen the role table / enum (add roles, or let roles imply grants).**
  Rejected — it deepens the second authority source instead of removing it,
  re-opens the RBAC-vs-ABAC bifurcation ADR 0012 closed, and still cannot
  express what explicit grants express (global capabilities, `curate`,
  per-repo asymmetric read/write).
- **Cap = requested scope with a `[Read, Write, Delete]` default (no grant
  consultation).** Rejected — simpler at the issuance site, but the cap then
  carries no attenuation content for SAs: every leaked SA token holds a
  maximal ceiling and ADR 0036's cap-intersection becomes meaningless on
  this path. The grants snapshot keeps the cap honest at zero operational
  cost given per-job exchange.

## Supersession notes

The following statements in earlier ADRs describe the retired
envelope-authority model. The ADRs are historical records and their bodies
stand unmodified; **this section is the durable pointer** that they are
superseded on this point:

- **ADR 0034** — §"Surface 1": "`role` and `repositories` confer authority;
  there are no `PermissionGrant`s", and the `gha-ci` / `gitlab-ci` /
  `gha-release` descriptions by role and repository list. The deployed
  gitops tree now declares identity-only envelopes with per-repo
  `serviceAccount`-subject read grants for the CI pull accounts and
  write-plus-signing-read grants for the release account
  (`deploy/ansible/files/gitops/auth/`).
- **ADR 0037** — §Context: the "envelope confers authority through its
  `role` and `repositories` list" baseline. The grant shape 0037 introduced
  is now the sole SA authority mechanism; 0037's decision (apply-boundary
  sugar, two-variant domain taxonomy) is unchanged.
- **ADR 0038** — §Decision 2 / "Enforced by": "apply-time validation rejects
  an `admin`-role SA envelope" (`validate_rejects_admin_role`). There is no
  role field; the strictly-non-admin invariant is carried by the three-point
  enforcement in this ADR's Decision 5.
- **ADR 0018** — no body statement is superseded; it is named here because
  the catalog it makes canonical is where the current SA surface is
  specified: `docs/auth-catalog.md` Entry 4 (identity-only envelope, the
  three-point non-admin enforcement, the rotation and `issue-svc-token` cap
  semantics) and Entry 6 (the exchange's grants-snapshot ∩ scope cap).

## References

- `crates/hort-config/src/service_account.rs` — the identity-only spec;
  parse-time rejection of the retired fields.
- `migrations/014_service_accounts_identity_only.sql` — the column drops.
- `crates/hort-app/src/rbac.rs` —
  `RbacEvaluator::service_account_cap_permissions`.
- `crates/hort-http-core/src/handlers/exchange.rs` — the federation-branch
  snapshot ∩ scope and the `cap_exceeds_authority` denial.
- `crates/hort-app/src/task_handlers/service_account_rotation.rs` — the
  rotation-mint snapshot.
- `crates/hort-server/tests/exchange_cap_derivation_e2e.rs` — cap-derivation
  pins (snapshot freshness, scope narrowing, zero-grant, B1 `Some(cap)`).
- `docs/auth-catalog.md` Entries 4 and 6 — the canonical inbound-auth
  entries for the SA surface.
- `docs/architecture/how-to/declare-gitops-config.md`
  `kind: ServiceAccount` — the operator-facing schema reference.
