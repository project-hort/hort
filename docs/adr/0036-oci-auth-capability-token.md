# 0036 — OCI `/v2/auth` is a per-identity capability token

- **Status:** Accepted
- **Enforced by:** the mint principal in
  `OciTokenExchangeUseCase::exchange`
  (`crates/hort-app/src/use_cases/oci_token_exchange_use_case.rs`) carries
  `claims: []` (the `add_admin_claim_if_admin` step is gone), so the admin
  short-circuit cannot fire on the OCI surface; the B1 fail-closed cap backstop
  in `RbacEvaluator::user_grants_authorize`
  (`crates/hort-app/src/rbac.rs` — the `Some(TokenKind::Pat) |
  Some(TokenKind::ServiceAccount)` arm) denies a cap-bound native token that
  carries the admin claim but a `None` cap. Regression tests:
  `authorize: B1 fail-closed cap backstop` group in `crates/hort-app/src/rbac.rs`
  (asserts Pat/ServiceAccount admin-claim + `None`-cap deny, and that OIDC +
  CliSession admins with a `None` cap are NOT denied).
- **Supersedes:** —
- **Relates:** [0011](0011-authority-hierarchy-and-api-versioning.md) (OCI
  Distribution Spec is authoritative over the implementation),
  [0012](0012-claim-based-rbac-claimless-static-tokens.md) (claim-based RBAC;
  long-lived static tokens stay claimless),
  [0013](0013-idp-authoritative-cli-sessions.md) (OIDC/CliSession admins
  legitimately carry a `None` cap), [0018](0018-auth-catalog-canonical.md)
  (auth-catalog Entry 7 is the canonical view of this mechanism). Open-items
  register row **CRYP-1** (the OCI and CliSession families share one Ed25519
  signing key; separation is verify-time `aud`+`token_kind`, not cryptographic).

## Context

The OCI `/v2/auth` mint exchanges a validated native PAT (carried as
`Authorization: Basic <PAT>`) for a short-lived OCI registry bearer the Docker /
OCI client then presents on `/v2/*` (Entry 7). The bug this ADR closes (F1): the
mint principal was built by `add_admin_claim_if_admin`, so a PAT whose owning
user was `is_admin` minted an OCI token carrying the synthetic `admin` claim. The
RBAC evaluator short-circuits on the `admin` claim — granting **every** authority
on **every** repository regardless of the token's cap. The OCI surface therefore
carried *ambient admin*: a registry token that should authorise push/pull of
specific repositories instead authorised everything an admin could do, including
authority the PAT's own cap never granted.

Two facts make this the wrong shape:

1. **The OCI token is a registry capability, not a principal session.** The
   Distribution Spec's bearer-token flow scopes a token to the repository
   actions the client asked for. Admin is not an OCI scope; there is no
   `repository:*:admin` in the protocol. Carrying the `admin` claim through the
   mint imports an authority the protocol surface has no vocabulary for.
2. **The consume side never re-derives admin from the token.** `/v2/*` consume
   re-evaluates authority from the caller's *current* `User`-subject grants
   intersected with the token's cap (`verify_inbound`). The mint-side admin claim
   was the only place ambient admin leaked in — and it diverged from what the
   consume side would compute.

## Decision

**The OCI `/v2/auth` token is a per-identity capability token. Its authority is
`User`-subject grants ∩ token cap, never an ambient admin short-circuit.**

- **Mint carries no admin claim.** The mint principal is constructed with
  `claims: []` (`add_admin_claim_if_admin` is dropped). The admin short-circuit
  is structurally unreachable on the OCI surface because the OCI principal has no
  `admin` claim to short-circuit on. Authority is computed the same way the
  consume side computes it: the user's persisted `GrantSubject::User` grants,
  intersected with the cap the PAT carries. Registry/catalog scope evaluation on
  the mint side is now empty (vestigial — `_catalog` consume is itself
  capability-scoped).
- **B1 — fail-closed cap backstop.** `user_grants_authorize` denies when a
  cap-bound native token (`TokenKind::Pat` or `TokenKind::ServiceAccount`)
  carries the `admin` claim **and** a `None` cap. `authenticate_pat` always
  constructs `Some(cap)` for these kinds, so a `None` cap on a Pat/SA admin
  principal is an anomalous construction; the evaluator fails closed rather than
  grant unfenced admin. This is defence in depth behind the mint change — even if
  some future path reintroduced an admin-claimed Pat/SA, an absent cap denies
  rather than amplifies.
- **Admin is off the OCI surface entirely.** No OCI token grants admin. An
  operator who needs admin authority uses the human-admin path (OIDC →
  CliSession, ADR 0013) or the DSN-gated `bootstrap-session` (ADR 0038), not a
  registry bearer.

## Spec-correction — B1 is scoped to Pat/ServiceAccount, NOT all token kinds

The original plan's B1 was written as "admin claim + `None` cap → deny" for *any*
token. The hard-gate verification during implementation found this **unsafe**:
**OIDC** principals (`token_kind: None`) and **CliSession** principals
(`token_kind: Some(CliSession)`) legitimately carry a `None` cap — their
authority is `claims + live grants` with no cap leg by design (ADR 0012's
claimless-static-token invariant scopes to long-lived static tokens; OIDC and
CliSession are IdP-backed and session-fresh — ADR 0013). A blanket
admin-claim-+-`None`-cap deny would have denied every legitimate IdP/CliSession
admin. The backstop is therefore scoped to `Pat`/`ServiceAccount` only; the
load-bearing tests assert OIDC + CliSession admins with a `None` cap are **not**
denied. This deviation is declared under the implementation-discipline rule (ADR
0023) — it is a correctness fix where the design was wrong, not a convenience.

## Consequences

- The OCI surface can no longer over-grant. A registry token authorises exactly
  the repositories its owner's `User`-subject grants ∩ cap permit — the same
  basis the consume side already re-evaluated, so mint and consume no longer
  diverge.
- The B1 backstop closes the residual: an admin-claimed cap-bound native token
  with no cap fails closed instead of short-circuiting to full authority.
- IdP and CliSession admins are unaffected — the backstop is kind-scoped so it
  cannot regress the legitimate `None`-cap full-authority sessions.
- Admin authority is concentrated on the IdP/CliSession + bootstrap-session paths
  (ADR 0038); the registry surface holds none of it.
- CRYP-1 (shared OCI/CliSession Ed25519 key, verify-time `aud`+`token_kind`
  separation) is unchanged by this decision and remains an accepted posture in
  the open-items register.

## Alternatives considered

- **Resolve the PAT-holder's persisted claims at OCI mint.** Rejected — it
  conflicts with ADR 0012's claimless-PAT invariant (a Pat never consults
  `claim_mappings`), and it would re-import claim-derived authority onto a surface
  whose protocol has no admin vocabulary. The capability model (grants ∩ cap) is
  the correct shape.
- **Blanket admin-claim-+-`None`-cap deny across all token kinds.** Rejected as
  unsafe (see the spec-correction above) — it denies legitimate OIDC/CliSession
  admins.
- **Leave the mint admin claim, rely on consume-side re-evaluation.** Rejected —
  the mint token itself is presented to OCI clients and is the artefact whose
  authority must be correct; a token that *claims* admin is a confused-deputy
  hazard even if one consume path happens to re-narrow it.

## References

- `crates/hort-app/src/use_cases/oci_token_exchange_use_case.rs` — the mint
  (`claims: []`) and the unified consume `verify_inbound`.
- `crates/hort-app/src/rbac.rs` — `user_grants_authorize` and the B1
  Pat/ServiceAccount fail-closed cap backstop + its test group.
- `docs/auth-catalog.md` Entry 7 — the canonical catalog view of this mechanism.
- [0012](0012-claim-based-rbac-claimless-static-tokens.md),
  [0013](0013-idp-authoritative-cli-sessions.md) — the claimless-static-token and
  IdP-session invariants the spec-correction turns on.
- [0038](0038-admin-identity-model.md) — where admin authority lives now that it
  is off the OCI surface.
