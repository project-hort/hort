# Authentication Means Catalog

| | |
|---|---|
| **Status** | Canonical reference — architect-enforced (see §4) |
| **Scope** | Inbound authentication mechanisms + inbound-gating trust anchors. Outbound credential handling (webhook HMAC, NATS, upstream creds) is out of scope. |
| **Authority** | official protocol/registry spec > **this catalog** > any other design document > implementation. On any inbound-auth conflict, this catalog wins (reconciled cross-cutting view) — `docs/adr/0018-auth-catalog-canonical.md`. |
| **Companion** | `docs/adr/0018-auth-catalog-canonical.md` (the canonical-catalog rule), `docs/architecture/explanation/security.md` (the surrounding security model) |

## §1 — Threat model (the spine)

This catalog defends, for every inbound credential and inbound-gating
trust decision: credential capture/replay; confused-deputy /
token-redirection; privilege persistence beyond a session; IdP
impersonation via trust anchors; public-by-requirement surfaces with no
network backstop; and secure-by-default (no security control that
requires an operator opt-in). Every entry's guardrails in §3 trace to
one of these.

### §1.1 — What this catalog does NOT establish (hard boundary)

- **Out of catalog scope (non-auth control families):** supply-chain &
  vulnerability handling (the scanning pipeline and provenance
  verification — ADR 0007 / ADR 0027), audit-log integrity,
  availability/DoS, injection, SSRF, network segmentation. These are
  covered by `docs/architecture/explanation/security.md` and the
  open-items register (`docs/adr/0000-historical-decisions-index.md`).
- **Not satisfiable by any code/doc artifact:** risk-management
  governance, coordinated-vulnerability-disclosure policy, NIS2 Art. 23
  incident-reporting procedures & timelines, training, the EU CRA
  conformity-assessment + technical-documentation regime.
- **Hard rule:** no compliance attestation may cite this catalog as
  evidence of conformity. It is an engineering control spec +
  traceability mapping. This rule exists because a control inventory is
  not an attestation: an earlier conformity claim leaned on the
  then-unchained event log exactly this way, and the catalog must never
  be misusable as that kind of evidence.

## §2 — Per-entry schema

Every entry in §3 carries exactly these fields:

| Field | Meaning |
|---|---|
| **Mechanism** | e.g. `Native token — CliSession` |
| **Credential form** | wire shape (`hort_cli_*` bearer, OIDC JWT, Basic carrier, …) |
| **Purpose / allowed use** | what it is for; which principals legitimately use it |
| **Restrictions & caps** | lifetime/admin caps, under-privilege rules, scoping |
| **Protection** | at rest · in transit · blast-radius bound |
| **Allowed call paths / surfaces** | which routers/tiers may accept it; public-by-requirement marked |
| **Enforcement owner** | `Hort-enforced` · `Operator-obligation` · `Shared` |
| **Status** | `Active` · `Partial` · `Planned` · `Deprecated` (the entry names its replacement) · `Forbidden-in-release` |
| **Mandatory guardrails** | enforced rules, each clause-tagged per §6; "ship gate (not yet met)" called out |

**Enforcement owner values.** `Hort-enforced` = code / dep-graph /
architect-review. `Operator-obligation` = outside Hort code; named and
mandated here but not satisfiable by Hort (IdP MFA, IdP session policy,
`HORT_EXTRA_CA_BUNDLE`/ClusterTrustBundle RBAC, public token-gen
rate-limit infra). `Shared` = Hort provides the hook, the operator must
configure it correctly.

**Status definition-of-done.** A guardrail is `Active` only with
implementation **+ test + telemetry** all present. "Coded but
unverified" is `Partial`. This wires NIS2 Art. 21(2)(f) / CRA Annex I
Part II(3) effectiveness into the catalog's done-criteria.

## §3 — Catalog entries

### Entry 1 — OIDC bearer (interactive human)

- **Credential form:** IdP-issued OIDC access-token JWT.
- **Purpose / allowed use:** interactive human authentication; the only mechanism that resolves `claim_mappings` → RBAC claims (ADR 0012).
- **Restrictions & caps:** session-fresh authority; `is_admin` recomputed from IdP groups and persisted per login (`crates/hort-app/src/use_cases/authenticate_use_case.rs`).
- **Protection:** at rest — none persisted (bearer); in transit — TLS + JWKS verified (Entry 12); blast-radius — bounded by token lifetime + live RBAC re-intersection.
- **Allowed call paths / surfaces:** all API surfaces; not a token-mint path.
- **Enforcement owner:** `Hort-enforced` + `Operator-obligation` (MFA at IdP — NIS2 21(2)(j)).
- **Status:** `Active`.
- **Mandatory guardrails:** [OWASP A07 · NIS2 21(2)(i) · CRA I(2)(a) · BSI ORP.4] `is_admin`-transition audit event + `hort_is_admin_transition_total{result}` metric **delivered** (`AdminStatusChanged` on the per-user stream — `crates/hort-domain/src/events/auth_events.rs`, emitted from `authenticate_use_case.rs`); for `HORT_TOKEN_ALLOW_ADMIN` deployments prefer a durable `User`-subject Admin grant over the purely-IdP-derived bit — operator guidance in `docs/architecture/how-to/operate/claim-based-rbac.md` §3.1.

### Entry 2 — Native token — Pat

- **Credential form:** `hort_pat_*` bearer; Argon2id-hashed at rest.
- **Purpose / allowed use:** long-lived static automation credential for human-owned tooling.
- **Restrictions & caps:** under-privileged — never consults `claim_mappings` (ADR 0012); admin only under `HORT_TOKEN_ALLOW_ADMIN=true` + global Admin grant + ≤30 d clamp (`crates/hort-app/src/use_cases/api_token_use_case.rs`); effective authority = `user_grants AND cap`. Excluded from amplification surfaces — see the CliSession `Restrictions` row below.
- **Protection:** at rest — Argon2id; in transit — TLS, plaintext shown once; blast-radius — cap-leg AND; no `users.claims`/`api_tokens.claims`.
- **Allowed call paths / surfaces:** all API surfaces via `Authorization: Bearer` or as a Basic carrier (Entry 8).
- **Enforcement owner:** `Hort-enforced`.
- **Status:** `Active`.
- **Mandatory guardrails:** [OWASP A07/A01 · NIS2 21(2)(i) · CRA I(2)(a) · BSI ORP.4] cap-leg AND preserved; no persisted claim set on the token row (ADR 0012).

### Entry 3 — Native token — CliSession

- **Credential form:** **Hort-signed Ed25519 JWT** (minted and verified in `crates/hort-app/src/cli_session_signing.rs`; session model: ADR 0013). Carries the human's IdP-resolved claim set + `sub` + a CliSession-specific `aud` (`urn:hort:cli-session`) + `token_kind="cli_session"` + `exp` + `jti`. Signed with the SAME Ed25519 key as the OCI `/v2/auth` token (Entry 7) — the two families are separated by `aud` + `token_kind`, never by issuer/signature. **Claims ride in the token, never in a DB column** (the "no `api_tokens.claims`/`users.claims`" hard-block of ADR 0012 is untouched — there is no CliSession `api_tokens` row at all).
- **Purpose / allowed use:** short-lived interactive CLI session, optionally admin-capable. **The only native-token kind that carries non-admin claims** (ADR 0012's claimless invariant scopes to long-lived static tokens; CliSession is ≤15 min and IdP-backed — ADR 0013); PAT/SA/Refresh stay claimless. This is what lets a `GrantSubject::Claims` grant authorize the CliSession-gated discovery/prefetch endpoints.
- **Restrictions & caps:** default **15 min (900 s)**; admin-capable bounded by the SAME **≤15 min (900 s)** hard cap (`crates/hort-app/src/use_cases/api_token_use_case.rs` clamp + `cli_session_signing.rs`) — a signed JWT is non-revocable-until-`exp` by construction, so the TTL is the revocation floor. Minted via PKCE-S256 mediated login (RFC 8252 loopback redirect + RFC 7636 S256 — `crates/hort-cli/src/auth/loopback.rs`). Endpoints `GET /api/v1/repositories/{repo_key}/discovery/versions/{package}` and `POST /api/v1/repositories/{repo_key}/prefetch` require `TokenKind::CliSession` (token-kind gate in `crates/hort-app/src/use_cases/discovery_use_case.rs` — cost-shape rationale: an amplification surface requires a time-capped credential).
- **Protection:** at rest — **none persisted** (the JWT is stateless; no row, no hash — claims live in the signed token); in transit — TLS — the auth middleware refuses a CliSession-family JWT over plaintext HTTP with `426 Upgrade Required` under the secure-default `HORT_BEARER_ALLOW_OVER_HTTP=false` (the transport gate covers *any* bearer — PAT-shaped tokens AND CliSession JWTs — hence the bearer-scoped knob name; `crates/hort-http-core/src/middleware/auth.rs`). Setting `HORT_BEARER_ALLOW_OVER_HTTP=true` together with an `https://` `HORT_PUBLIC_BASE_URL` is a **boot hard-fail** (`ConfigError::BearerOverHttpContradictsTls`, INFRA-13): a TLS-terminated deploy that also relaxes the bearer transport guard is self-contradictory and almost certainly a misconfiguration; only a plaintext (`http://...` or unset) public base URL keeps the relaxation as a boot WARN. Blast-radius — ≤15 min cap **+ Hort-side `jti` emergency-revocation denylist** (see Revocability below).
- **Revocability:** **`jti` denylist, bounded by TTL.** A signed JWT is non-revocable-until-`exp` by construction; emergency revocation writes `cli-session-revoked:{jti}` to the **durable** `EphemeralStore` (self-expiring at the token's `exp`, so the set stays bounded — keyspace registered in `crates/hort-app/src/ephemeral_keyspace.rs`). The validate path consults the denylist on every CliSession-JWT request and **fails closed** if the denylist is unreachable (deny rather than admit a possibly-revoked token).
- **Allowed call paths / surfaces:** all API surfaces; minted via the mediated-login flow only. Validated on the shared `AuthenticateUseCase::authenticate_bearer` bearer path (NOT the OCI-path middleware); a non-CliSession Hort-JWT (an OCI `/v2/auth` token) presented here is rejected by the `aud`+`token_kind` discriminator → 401.
- **Enforcement owner:** `Hort-enforced`.
- **Status:** `Active`.
- **Mandatory guardrails:** [OWASP A07 · NIS2 21(2)(i),(j) · CRA I(2)(a) · BSI ORP.4] the ≤15 min admin cap and the `jti`-denylist revocation control are an inseparable pair — neither may be relaxed independently (a signed JWT without the denylist regresses immediate revocation; a long TTL without revocation widens the unrevocable window). The `aud`+`token_kind` discriminator MUST gate verification (issuer/signature alone do not separate the CliSession and OCI token families — `cli_session_signing.rs::verify` + `OciTokenExchangeUseCase::verify_inbound`).

### Entry 4 — Native token — ServiceAccount

- **Credential form:** `hort_svc_*` bearer; Argon2id-hashed at rest.
- **Purpose / allowed use:** admin-minted machine identity for non-human consumers.
- **Restrictions & caps:** admin forbidden at apply time (`crates/hort-config/src/service_account.rs` — `validate_rejects_admin_role` pins it); authority exclusively via `GrantSubject::User(backing_user_id)` grants (ADR 0012); self-mint forbidden.
- **Protection:** at rest — Argon2id; in transit — TLS; blast-radius — User-subject grants only, never claim-mapped.
- **Allowed call paths / surfaces:** all API surfaces; admin-mint path only.
- **Enforcement owner:** `Hort-enforced`.
- **Status:** `Active`.
- **Mandatory guardrails:** [OWASP A07/A01 · NIS2 21(2)(i) · CRA I(2)(a) · BSI ORP.4] no `claims:[…]` ever; SA self-mint is a hard reject.

### Entry 5 — Native token — Refresh

- **Credential form:** refresh token (unbuilt — the refresh half of the ADR 0013 session model).
- **Purpose / allowed use:** renew a `CliSession` access token without re-running mediated login.
- **Restrictions & caps:** never sent to API endpoints; never persisted to disk; replay detection required.
- **Protection:** at rest — must never be on disk; in transit — TLS to the refresh endpoint only; blast-radius — replay-detected, single-use.
- **Allowed call paths / surfaces:** the refresh endpoint only.
- **Enforcement owner:** `Hort-enforced`.
- **Status:** `Planned` (unbuilt). Catalogued now so it cannot ship without the three guardrails above.
- **Mandatory guardrails (ship gate — must hold before Status may become `Active`):** [OWASP A07 · NIS2 21(2)(i),(j) · CRA I(2)(a)] replay detection; never on disk; never sent to API endpoints.

### Entry 6 — OIDC federation exchange

- **Credential form:** foreign workload JWT (k8s SA / GitHub Actions / GitLab CI OIDC) exchanged at `/api/v1/auth/exchange` for a short-lived `ServiceAccount` bearer.
- **Purpose / allowed use:** keyless machine identity for OIDC-capable workloads (`crates/hort-http-core/src/handlers/exchange.rs`).
- **Restrictions & caps:** short-lived minted bearer; SA selected by `issuer_name` + non-empty `FederatedIdentity.claims` subset match. **Anti-replay:** every accepted JWT is atomically claimed in the durable `jwt_replay_seen` seen-set **before** any token is minted (`ReplayGuardPort` — `crates/hort-domain/src/ports/replay_guard.rs`, Postgres impl `crates/hort-adapters-postgres/src/replay_guard_repo.rs`); a second presentation of the same `jti` (or `(iss,sub,iat,exp)` composite) within its TTL window is denied — no bearer is minted on a replay. Per-`OidcIssuer` `require_jti` trust knob (**default `true`** — secure-by-default; a field-less issuer config means `require_jti=true`, so jti-less JWTs from it are rejected). Setting `require_jti=false` opts an issuer into the weaker `(iss,sub,iat,exp)` composite fallback, which mis-classifies as a replay any two genuinely-distinct JWTs the IdP mints for the same `sub` within the same `iat` second *and* `exp` (documented false-positive cost of the opt-down).
- **Protection:** at rest — none (exchange); in transit — TLS; **anti-replay — durable `jwt_replay_seen` Postgres seen-set (DURABLE class, explicitly NOT evictable/ephemeral — an evicted row would silently re-permit the replay it recorded)**; blast-radius — minted bearer is a `ServiceAccount` (Entry 4), User-subject grants only.
- **Allowed call paths / surfaces:** `/api/v1/auth/exchange` — **public-by-requirement**; no network backstop — anti-replay is the *sole* control on this surface, hence a hard ship gate, not defense-in-depth.
- **Enforcement owner:** `Hort-enforced` + `Operator-obligation` (issuer/claims hygiene).
- **Fail-mode:** **fail-CLOSED** — if the replay guard cannot be evaluated (seen-set backing store unreachable) the exchange is denied `503 temporarily_unavailable`; there is no path where a guard outage falls through to minting. A *cleanup*-task outage (the default-enabled `replay-seen-prune` worker task stops) degrades **safe**: the seen-set never forgets within TTL, only storage grows.
- **Status:** `Active` per §2 definition-of-done — all three ship-gate guardrails below (anti-replay, `aud`→SA binding, empty-claims fail-closed) are met.
- **Enablement invariant (amended):** Federation exchange is **independent of interactive-OIDC config**. `HORT_TOKEN_EXCHANGE_ENABLED=true` + `HORT_AUTH_PROVIDER=disabled` + `HORT_NATIVE_TOKENS_ENABLED=true` enables the federated-JWT branch of `/exchange` without configuring an interactive IdP (`HORT_OIDC_ISSUER_URL`, `HORT_OIDC_CLI_CLIENT_ID`, `HORT_PUBLIC_BASE_URL` are not required under `Disabled`). In this mode the `/.well-known/hort-client-config` discovery doc is not served and the interactive `access_token` branch of `/exchange` returns `400 invalid_request` with a clear message. The three ship-gate guardrails (anti-replay, `aud`→SA binding, empty-claims fail-closed) are **UNCHANGED** by this enablement-invariant relaxation — they live in the handler and are not conditioned on `AuthConfig`.
  > **Invariant:** Federation-exchange is enablement-independent of interactive OIDC; the three ship-gates live in the handler and are not affected by the auth-mode split.
- **Mandatory guardrails (ship gates — all met):** [OWASP A07/A01 · NIS2 21(2)(i),(j),(d) · CRA I(1),(2)(a) · BSI ORP.4] **JWT replay seen-set — MET** (`ReplayGuardPort` + durable `jwt_replay_seen` + per-issuer `require_jti` on `crates/hort-domain/src/entities/oidc_issuer.rs`, checked before mint, fail-closed); **`aud`→SA binding — MET** (per-`FederatedIdentity` explicit `audience` bound to `claims.audience`/required `aud`, consulted in SA selection — `collect_sa_matches` in `crates/hort-http-core/src/handlers/exchange.rs` — with an apply-time under-constrained-issuer warning that also flags identities declaring no scope-narrowing claim (the sub-only shape), and `hort_fed_sa_match_total{result="denied_audience"}`); **empty-claims fail-closed — MET** (three layers on top of the apply-time reject `validate_federated_identity_claims_non_empty` in `crates/hort-config/src/service_account.rs`: runtime `collect_sa_matches` skip-empty, DB `CHECK (jsonb_typeof(claims)='object' AND claims <> '{}')` in `migrations/011_gitops_machine_identity.sql`, `TryFrom<FederatedIdentityRow>` reject in `crates/hort-adapters-postgres/src/mappers.rs`, `hort_fed_sa_match_total{result="denied_empty_claims"}`). No ship gate remains open on this path.

### Entry 7 — OCI `/v2/auth` token

- **Credential form:** OCI registry bearer; server-config `aud`; `sub` = validated PAT's user.
- **Purpose / allowed use:** Docker/OCI client auth against the registry endpoints.
- **Restrictions & caps:** roles re-resolved from current DB grants on consume; `aud` is server-config (not attacker-controlled).
- **Protection:** at rest — none (bearer); in transit — TLS; blast-radius — forged token requires signing-key compromise.
- **Allowed call paths / surfaces:** OCI `/v2/*` + `/v2/auth` — **public-by-requirement** (push clients / CI).
- **Enforcement owner:** `Hort-enforced`.
- **Status:** `Active`. Consume-side validation is **unified** behind the single `hort-app` entrypoint `OciTokenExchangeUseCase::verify_inbound → OciVerifyOutcome` (`crates/hort-app/src/use_cases/oci_token_exchange_use_case.rs`) — no bespoke verification logic lives in the inbound crate; the mint half delegates PAT validation to the shared `PatValidationUseCase`. The Ed25519 sign/verify primitive *is* the OCI Distribution-Spec issuer mechanism, not bespoke-by-choice. The **`service=`-vs-configured-`aud` 400-on-mismatch gate** is enforced as an unbypassable Step-0 inside `OciTokenExchangeUseCase::exchange` (before scope parse + PAT validate; HTTP 400 `UNSUPPORTED` envelope, message constant `"service mismatch"`, requested value goes to the structured audit log only). Consume-side `aud` is centralised on `config.jwt_audience` (no mint/consume aud-derivation drift).
- **Mandatory guardrails:** [OWASP A07 · NIS2 21(2)(i) · CRA I(2)(a)] `service=` validated-or-rejected — **met** by the unbypassable Step-0 gate in `exchange`; the verifier stays unified onto the single `hort-app` `verify_inbound` entrypoint.

### Entry 8 — HTTP Basic

- **Credential form:** `Authorization: Basic` carrying `__token__:<hort_pat_*>` (token-as-password).
- **Purpose / allowed use:** carrier transport for a native token on package-manager tooling (npm/pip/cargo/maven/gradle).
- **Restrictions & caps:** Basic is **not** an identity source — it only carries a native token, which is then validated as Entry 2/4. The username field is **ignored** on the artifact plane (it is decorative carrier metadata, not an identity claim).
- **Protection:** inherits the carried token's protections (Entry 2/4); in transit — TLS.
- **Allowed call paths / surfaces:** package-manager artifact surfaces — npm/pip/cargo and **maven/gradle** (`mvn deploy` / `gradle publish` deploy `PUT`s authenticate here via `Authorization: Basic base64(<anything>:<hort_pat_*>)`, username ignored, password = PAT validated as Entry 2; the Maven handler serves both `RepositoryFormat::Maven` and `RepositoryFormat::Gradle` repos on one wire protocol). Maven/Gradle introduce **no new auth mechanism** — they reuse this carrier unchanged.
- **Enforcement owner:** `Hort-enforced`.
- **Status:** Basic-as-token-carrier is `Active`. Basic carrying a raw username+password as an identity source is **`Forbidden-in-release`**: there is no DB password-check-per-request identity path in the unified auth middleware (`crates/hort-http-core/src/middleware/auth.rs::require_principal`) — it was removed with no compat shim. Native tokens fully cover the tooling; this keeps a password-brute-force surface off the public artifact plane. A raw username+password reaches the bearer validator (token not valid) → `401`, with no DB password check. The password-hash producer chain is gone end-to-end (no `admin bootstrap` subcommand, no `UserUseCase::create_or_rotate_admin`, no `users.password_hash` column, no `AdminBootstrapped`/`AdminPasswordRotated` events) — see the Entry 9 tombstone.
- **Mandatory guardrails:** [OWASP A07/A01 · NIS2 21(2)(i) · CRA I(1),(2)(a) · BSI ORP.4] no new call site may treat Basic username+password as an identity source (architect anti-pattern, §4) — a `Deprecated` / `Forbidden-in-release` mechanism gaining a new call site is a hard block.

### Entry 9 — Admin bootstrap — **REMOVED**

The bootstrap mechanism was an `is_admin=true` Local user provisioned
from `HORT_ADMIN_*` env + minted via an `admin bootstrap` CLI. It
stopped being an inbound auth surface when the Basic password-identity
consumer was removed (Entry 8), and the producer chain
(CLI + `UserUseCase::create_or_rotate_admin` + the
`AdminBootstrapped` / `AdminPasswordRotated` events +
`users.password_hash`) was subsequently removed end-to-end. The
minimal-setup bring-up path is now the `admin issue-svc-token` recipe
(`crates/hort-server/src/cli/admin.rs`; documented on Entry 8 and in
the Helm chart's `values.yaml` `auth.provider` doc-comment). Entry
number retained as a tombstone so future audit sweeps grepping
`Entry 9` land on this explanation rather than silence; subsequent
entry numbers are **not** renumbered (external references in
`docs/metrics-catalog.md` and
`docs/architecture/how-to/deploy/security-hardening-checklist.md`
stay stable).

### Entry 10 — Test-clock bypass

- **Credential form:** `POST /test/clock/advance` — deliberate expiry-control auth-bypass primitive.
- **Purpose / allowed use:** test harness only; never production.
- **Restrictions & caps:** double-gated `#[cfg(feature="test-clock")]` + `HORT_TEST_CLOCK_ENABLED=true`.
- **Protection:** blast-radius — must be unreachable in any release build.
- **Allowed call paths / surfaces:** test-feature builds only.
- **Enforcement owner:** `Hort-enforced`.
- **Status:** `Forbidden-in-release`.
- **Mandatory guardrails:** [OWASP A05 · CRA I(1),(2)(g)] startup hard-fail if enabled in a release/non-feature build (`crates/hort-server/src/composition.rs` boot gate); `hort_unsafe_config_active{kind=test_clock}=1` gauge.

### Entry 11 — Trust anchor — `HORT_EXTRA_CA_BUNDLE`

- **Credential form:** operator-supplied CA bundle, additive across all TLS surfaces incl. OIDC discovery + JWKS (ADR 0010).
- **Purpose / allowed use:** trust internal/private CAs for upstream/OIDC/webhook/S3 TLS.
- **Restrictions & caps:** process-wide; no scoping knob; no `*_INSECURE_TLS` alternative.
- **Protection:** blast-radius — **auth-critical**: an unconstrained CA here can impersonate the IdP (the single-additive-bundle posture is a recorded accepted risk — see the open-items register, `docs/adr/0000-historical-decisions-index.md`), amplified where admin is purely IdP-derived (see Entry 1's durable-Admin-grant guidance).
- **Allowed call paths / surfaces:** all outbound TLS the server opens.
- **Enforcement owner:** `Shared` (Hort consumes it fail-closed; operator owns the bundle's integrity & RBAC).
- **Status:** `Active`, auth-critical asset.
- **Mandatory guardrails:** [OWASP A02/A05 · NIS2 21(2)(h) · CRA I(2)(a),(b) · BSI CON.1] operator-obligation: ClusterTrustBundle over namespace ConfigMap, RBAC ≥ OIDC-client-secret, name-constrained intermediates (`docs/architecture/how-to/deploy/security-hardening-checklist.md`); no `*_INSECURE_TLS` knob anywhere (ADR 0010).

### Entry 12 — Trust anchor — JWKS verification

- **Credential form:** IdP JWKS fetched via the shared TLS-hardened client (`internal::build_http_client` in `crates/hort-adapters-oidc/src/internal.rs`).
- **Purpose / allowed use:** verify OIDC bearer + federation JWT signatures.
- **Restrictions & caps:** `exp/nbf/iss/alg` validated, 30 s leeway; no `insecure_jwks_url` knob.
- **Protection:** in transit — TLS verified against system trust + `HORT_EXTRA_CA_BUNDLE`; blast-radius — bounded by Entry 11's trust posture.
- **Allowed call paths / surfaces:** OIDC + federation validation paths.
- **Enforcement owner:** `Hort-enforced`.
- **Status:** `Active`.
- **Mandatory guardrails:** [OWASP A02/A07 · NIS2 21(2)(h),(i) · CRA I(2)(a)] no `insecure_jwks_url`; mirrors the no-insecure-TLS reqwest-builder rule (ADR 0010).

### Cross-cutting guardrail — read-authz is not method-dispatched

Not a mechanism. Every read use case MUST enforce caller visibility;
method-based anonymous-by-default dispatch is **not** a defense layer
(ADR 0021). **Enforcement owner:** `Hort-enforced` (architect
read-authz review checklist). [OWASP A01/A04 · NIS2 21(2)(i) ·
CRA I(2)(a)]

## §4 — How this catalog is enforced

`.claude/commands/hort-architect.md` adds this doc to its
authority hierarchy and an "Authentication Guardrails" anti-pattern
subsection: a not-in-catalog inbound mechanism is a hard block; any PR
altering an auth path/token kind/credential form/cap/trust anchor must
update this catalog in the same change; a `Forbidden-in-release`
mechanism reachable in a release build is a hard block; a `Deprecated`
mechanism gaining new call sites is a hard block; a federation path not
meeting its catalogued ship-gate guardrails is a hard block.

Enforcement is **architect-skill-only**, exactly as the analogous
`docs/metrics-catalog.md` rule is enforced. It is deliberately **not**
mirrored into the project `CLAUDE.md`: that file's Anti-Patterns
Checklist mirrors only rules whose enforcement is *structural*
(compile-error / dep-graph), whereas the not-in-catalog rule is
convention/review-enforced. The metrics-catalog rule is absent from
`CLAUDE.md` for exactly this reason; this catalog follows the same
convention.

## §5 — Consolidation state

The auth-means consolidation this catalog once scoped is **complete**:
no entry carries a `Deprecated` status, and no catalogued ship gate is
open except Entry 5's (which gates a `Planned`, unbuilt mechanism). The
formerly-open remediation scope — removing Basic username+password as
an identity source (Entry 8), unifying the OCI `/v2/auth` verifier and
its `service=`-vs-`aud` gate (Entry 7), the three federation ship gates
(anti-replay seen-set, `aud`→SA binding, empty-claims fail-closed —
Entry 6), and the `is_admin`-transition audit event (Entry 1) — is
delivered, and each entry above describes the live state with its
enforcing code, tests, and telemetry. The §4 "federation ship-gate" and
`Deprecated` enforcement bullets are state-descriptive rules and apply
to any future entry that enters those states.

## §6 — Regulatory traceability (mapping, NOT conformity)

This section maps **auth-relevant clauses only**. The remaining
clauses belong to the non-auth control families §1.1 marks out of
scope. **The §1.1 hard rule applies: this is a mapping, not a
conformity assessment — no attestation may cite it.**

**Forward traceability:** every Entry's "Mandatory guardrails" line in
§3 carries `[OWASP · NIS2 · CRA · BSI]` clause tags. That is the
forward map; this section is the reverse rollup.

**Reverse rollup** (Covered = verified control present; Partial = open
ship-gate / unverified; Operator-obligation = IdP/operator-side;
OOS = out of scope of this catalog):

| Clause | Status | Evidence |
|---|---|---|
| OWASP A01 Broken Access Control | Partial | Entries 2/4/8 cap+grant model ✔; Entry 6 federation ship-gates met (anti-replay, audience binding, empty-claims) ✔; cross-cutting read-authz remains review-enforced, not structural (ADR 0021) |
| OWASP A02 Cryptographic Failures | Partial | Entry 12 JWKS ✔; Entry 11 `HORT_EXTRA_CA_BUNDLE` IdP-impersonation residual (accepted posture) |
| OWASP A07 Identification & Auth Failures | Partial | Entries 1–4 ✔; Entry 6 ship-gates met (anti-replay, audience binding, empty-claims) ✔; Entry 5 Planned (not yet implemented) |
| NIS2 21(2)(h) Cryptography | Partial | Entries 11/12; CA-bundle impersonation residual (Entry 11) |
| NIS2 21(2)(i) Access control | Partial | Entries 1–4/9 ✔; Entry 6 federation ship-gates met ✔; cross-cutting read-authz remains review-enforced (ADR 0021) |
| NIS2 21(2)(j) MFA / secured comms | Operator-obligation | MFA delegated to IdP (Entry 1); Hort must not provide an MFA end-run beyond catalogued PAT rules |
| NIS2 Art. 23 (auth-evidence slice) | Partial | `is_admin`-transition audit event (Entry 1); broader log integrity is a non-auth control family (OOS — §1.1) |
| CRA Annex I (1) secure-by-default | Covered | Entry 10 forbidden-in-release ✔; Entry 6 federation ship-gates met (anti-replay, audience binding, empty-claims) ✔ |
| CRA Annex I (2)(a) unauthorised access | Covered | Entries 1–4/6/7/8/9 ✔ (Entry 6 federation ship-gates met) |
| CRA Annex I (2)(b) confidentiality (token-at-rest slice) | Covered | Entries 2/3/4 Argon2id-at-rest |
| BSI ORP.4 Identitäts-/Berechtigungsmgmt | Covered | Entries 1–4/6/8/9 ✔ (Entry 6 federation ship-gates met) |
| BSI CON.1 Kryptokonzept (auth-crypto slice) | Partial | Entries 11/12 |

This table deliberately does **not** present a full NIS2/CRA matrix —
doing so would re-invite the "complete = compliant" misread §1.1
forbids.
