# 0038 — Admin-identity model: IdP-assumed, service accounts strictly non-admin, DSN-gated bootstrap-session

- **Status:** Accepted
- **Enforced by:** `hort-server admin issue-svc-token` rejects
  `--permission=admin` and requires a **pre-existing** gitops `ServiceAccount`
  (no `is_admin` fabrication) — `crates/hort-server/src/cli/admin.rs`
  (`resolve_svc_user` refuses an `is_admin` row; the admin permission
  is rejected before mint); `hort-server admin bootstrap-session` is gated on
  `HORT_TOKEN_ALLOW_ADMIN` (`require_allow_admin_tokens`) and mints a
  short-lived full-cap admin `Pat` for the reserved non-SA `bootstrap-admin`
  user (`crates/hort-server/src/cli/admin.rs`,
  `crates/hort-app/src/use_cases/api_token_use_case.rs`); apply-time SA admin
  rejection (`crates/hort-config/src/service_account.rs` —
  `validate_rejects_admin_role`); the human-admin path is OIDC → CliSession via
  the `admin` ClaimMapping (`crates/hort-app/src/use_cases/authenticate_use_case.rs`).
- **Supersedes:** the no-IdP / local-admin posture sketched in
  [0034](0034-public-dogfood-deployment.md) §"Asymmetric identity model" for any
  deployment that wants a human admin (0034's *CI federation* and *scan posture*
  decisions stand; only its "no interactive IdP, admin via ad-hoc tokens"
  framing is refined here to "assume an IdP; the no-IdP admin path is a narrow
  bootstrap").
- **Relates:** [0012](0012-claim-based-rbac-claimless-static-tokens.md) (SAs
  strictly non-admin; claimless static tokens),
  [0013](0013-idp-authoritative-cli-sessions.md) (IdP-authoritative short-lived
  CLI sessions; ≤1 h admin cap), [0018](0018-auth-catalog-canonical.md)
  (auth-catalog: Entry 1 OIDC, Entry 3 CliSession, Entry 4 ServiceAccount, the
  bootstrap-session note), [0020](0020-single-flight-seal-pool-backstop.md) (the
  single-flight surface the destructive-approval follow-on touches —
  **security co-review**), [0028](0028-destructive-task-idempotency.md)
  (`task:destructive` idempotency), [0036](0036-oci-auth-capability-token.md)
  (admin off the OCI surface; the B1 backstop), [0037](0037-gitops-service-account-grant.md)
  (serviceAccount-subject grants — how non-admin SAs hold scoped authority).

## Context

The OCI over-grant fix (ADR 0036) raised a deeper question: *where does admin
authority live, and how does a machine run admin-flavoured housekeeping?* Chasing
"admin off the OCI token → make service-account tokens non-admin" tempted a slide
into building **no-IdP local-admin machinery** — a bootstrap-admin CliSession, a
local-login flow, PAT-vs-CliSession local-admin distinctions. The root error in
that direction: engineering around a standard dependency — an identity provider —
that every real deployment already has, and reviving password/host-coupled
identity surfaces (the removed Entry 9 family) in the process.

The reset re-derives the admin-identity model around one lesson: **assume an IdP,
eliminate standing privilege, and keep the no-IdP case a narrow bootstrap, not a
first-class model.**

### A critical accuracy correction about Dex `staticPasswords`

Hort derives `is_admin` (and all claim-mapped grants) from the IdP **`groups`
claim** via a `ClaimMapping` (group → `admin`). An empirical finding during this
work, reproduced across **Dex v2.41–2.44**: **Dex's `staticPasswords` connector
does NOT emit a `groups` claim.** Only a group-capable connector (LDAP, or a real
upstream OIDC/SSO that carries groups) emits `groups`. Therefore a Dex
`staticPasswords`-only deployment yields **non-admin** humans — the static admin
can complete the OIDC → CliSession exchange but resolves to no `admin` claim. The
docs must not claim "a static Dex admin is a Hort admin." The accurate model is
below.

## Decision

### 1. Human admin = IdP-assumed (OIDC → CliSession)

Steady-state human admin is **OIDC → CliSession** (Entries 1/3):

- The IdP must be **group-capable** — the org's real SSO, or **Dex fronting a
  group-capable connector** (LDAP / GitHub / an upstream OIDC). A group → `admin`
  `ClaimMapping` resolves a member of the admin group to `is_admin` at
  authentication time; the CliSession carries that authority for ≤15 min
  (ADR 0013).
- **Dex is the recommended *minimal* IdP for deployments that have a
  group-capable connector to point it at.** Hort stays IdP-agnostic — Dex is
  replaceable by, and can front, the org's real SSO. **A Dex
  `staticPasswords`-only setup does not grant admin** (no `groups` claim); it is
  fine for non-admin OIDC humans, with admin obtained via a real connector or the
  bootstrap-session below.

### 2. Service accounts are strictly non-admin

No service account holds admin — no exception (Entry 4, ADR 0012):

- `issue-svc-token` **rejects `--permission=admin`** and requires a
  **pre-existing** gitops `ServiceAccount` (it no longer fabricates an `is_admin`
  user when the SA is absent — it errors).
- Non-admin SA authority flows through gitops `serviceAccount`-subject grants
  (ADR 0037): `read` / `curate` / global `admin_task_invoke`, all via the audited
  apply path.
- Apply-time validation rejects an `admin`-role SA envelope.

### 3. The DSN-gated `bootstrap-session` is the only no-IdP / first-admin admin path

`hort-server admin bootstrap-session` is the narrow first-admin / break-glass
path:

- **Doubly gated:** operator-level Postgres (DSN) access **and**
  `HORT_TOKEN_ALLOW_ADMIN=true` (refuses otherwise).
- Mints a **short-lived (≤1 h)**, **full-cap** admin `Pat` for the reserved
  **non-service-account** user `bootstrap-admin` (`is_admin=true`,
  `is_service_account=false`), revoking any prior bootstrap token first (single
  active token). The explicit full cap is required because the ADR 0036 B1
  backstop denies an admin-claim `Pat` carrying a `None`/admin-less cap.
- **Bootstrap / break-glass only** — used once to wire the IdP (Dex / SSO) + the
  group → `admin` `ClaimMapping`, or when the IdP is down. Steady-state admin is
  IdP-backed.
- This **replaces** the elaborate local-CliSession / local-login design that was
  considered and dropped — once the IdP is wired you use the IdP; the
  bootstrap-session is just the one-time wire-up (or break-glass).

### 4. Zero standing destructive privilege — the `task:destructive`-as-claim property is KEPT

Irreversible operations (retention-purge / eventstore-archive / retention-evaluate)
require the `task:destructive` *claim*, which is satisfiable only by a **fresh,
claim-bearing admin session** — never a static token. With an IdP, the fresh admin
CliSession is that session. This property is **good and deliberately kept**: there
is zero *standing* destructive privilege, so unattended machine execution of a
destructive op is intentionally impossible. A non-admin cron SA holding only
`admin_task_invoke` can enqueue non-destructive admin tasks but **cannot** run the
destructive ones. In the interim, the deploy may keep destructive CronJobs
disabled by default (the reset's choice) or run them by hand with a Dex
CliSession; the production answer is the approval-workflow follow-on below.

## Consequences

- Admin authority is concentrated on two paths: IdP → CliSession (steady state)
  and the DSN-gated bootstrap-session (first-admin / break-glass). No standing
  admin token, no admin on the OCI surface (ADR 0036), no admin service account.
- The minimal-IdP recommendation (Dex) is accurate: it grants admin only with a
  group-capable connector; a `staticPasswords`-only Dex is for non-admin OIDC
  humans plus the bootstrap-session.
- The compose E2E uses **Keycloak** (which emits `groups`); the k8s no-IdP tier
  moves to the chart's **Dex** sidecar for the OIDC → CliSession path. The tested
  path is the recommended path.
- Destructive housekeeping has no unattended machine path by construction; this is
  the intended posture, with the approval workflow as the production-scale answer.

## Follow-ons (recorded in the open-items register, `0000`)

1. **Destructive-op approval workflow** (propose → confirm → execute): cron
   proposes a destructive op non-destructively; a fresh admin CliSession confirms;
   the worker executes attributed. This is the fully-de-admined answer for
   destructive housekeeping. It touches the ADR 0020 single-flight surface and
   requires its own design pass with a **security co-review**.
2. **Workload-identity federation for CronJobs**: replace the static `HORT_TOKEN`
   secret with `/exchange` from a projected k8s SA token (keyless), as the CI
   federation already does (ADR 0034 / Entry 6).
3. **Dogfood Dex needs a group-capable connector for live group-based admin.** The
   dogfood Dex sidecar ships `staticPasswords` only, so its static admin is
   **non-admin**; admin on that instance is via the bootstrap-session or by
   pointing Dex at a real connector (caveat documented at the Dex config + the
   `admins` ClaimMapping).

## Alternatives considered

- **First-class no-IdP local-admin (bootstrap-admin CliSession, local-login).**
  Rejected — engineers around the IdP dependency every real deployment has, and
  revives password / host-coupled identity surfaces (the removed Entry 9 family).
  Collapsed to the minimal bootstrap-session.
- **Self-developed OIDC IdP, or a host-PAM admin.** Rejected — do not build
  security primitives; PAM revives the Entry-9 password surface and couples auth to
  the host (broken in containers / k8s). "I control the infra" is expressed as the
  DSN-gated bootstrap, not PAM.
- **Allow an admin service account for destructive housekeeping.** Rejected — it
  reintroduces standing destructive privilege, the exact property the
  `task:destructive`-as-claim model exists to prevent. The approval-workflow
  follow-on is the de-admined replacement.
- **Document "a static Dex admin is a Hort admin."** Rejected as **factually
  wrong** — Dex `staticPasswords` emit no `groups` claim, so no `admin` mapping
  resolves (the accuracy correction above).

## References

- `crates/hort-server/src/cli/admin.rs` — `issue-svc-token` non-admin
  conformance + the `bootstrap-session` mechanism.
- `crates/hort-app/src/use_cases/api_token_use_case.rs` — the bootstrap-session
  mint + the svc-token guards.
- `crates/hort-app/src/use_cases/authenticate_use_case.rs` — the OIDC group →
  `admin` ClaimMapping resolution (the human-admin path).
- `deploy/ansible/files/gitops/auth/admins.yaml` — the `hort-admins → admin`
  ClaimMapping; `deploy/ansible/roles/hort/templates/dex-config.yaml.j2` — the Dex
  sidecar config with the group-claim caveat.
- `deploy/ansible/files/gitops/auth/service-accounts/` +
  `deploy/ansible/files/gitops/auth/grants/` — the non-admin cron/maintainer SAs
  and their serviceAccount-subject grants (ADR 0037).
- `docs/architecture/how-to/deploy/admin-identity-and-dex.md` — the operator
  how-to for the admin-identity + Dex bootstrap.
- `docs/auth-catalog.md` — Entries 1/3/4 + the bootstrap-session note + the
  deployment/IdP note.
