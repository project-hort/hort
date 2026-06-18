//! OCI Distribution-Spec `/v2/auth` token-exchange use case.
//!
//! Orchestrates the full flow (see `docs/auth-catalog.md`):
//!
//! 1. Validate the Basic-as-PAT credential via [`PatValidationUseCase`].
//! 2. Parse each `scope` query parameter against the spec grammar:
//!    `<resource_type>:<resource_name>:<action>[,<action>...]`.
//! 3. For every scope: resolve the repo (or admit `registry:catalog`),
//!    map actions to `Permission` variants, evaluate via the live
//!    [`RbacEvaluator::authorize`].
//! 4. Mint a Distribution-Spec-shaped JWT carrying the granted subset,
//!    signed with the dedicated Ed25519 JWT signing key.
//!
//! # Failure model
//!
//! - [`OciTokenExchangeError::InvalidCredential`] — every
//!   [`PatValidationError`] variant collapses here. The handler maps
//!   to 401 with the Bearer challenge re-emitted.
//! - [`OciTokenExchangeError::InvalidScope`] — malformed scope, unknown
//!   resource_type, unknown action, or wildcard resource_name. Maps
//!   to 400 with the Distribution-Spec `UNSUPPORTED` envelope.
//! - **Empty granted subset is NOT an error** — the
//!   flow returns 200 with an empty `access[]` array (clients
//!   interpret it as "anonymous-equivalent"). Increments
//!   `hort_oci_v2_auth_total{result="no_grant"}`.
//!
//! # Replayability
//!
//! See [`crate::oci_token_signing`] module-level doc — the minted JWT
//! is replayable within the 5-min `exp` window. The use case ships the
//! exact wire shape the spec mandates; the handler attaches the
//! response.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use chrono::{DateTime, Utc};
use thiserror::Error;

use hort_domain::entities::api_token::TokenCap;
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::rbac::Permission;
use hort_domain::error::DomainError;
use hort_domain::ports::user_repository::UserRepository;

use crate::metrics::labels;
use crate::oci_token_signing::{
    AccessEntry, OciAccessClaims, OciTokenSigningKey, SigningError, VerificationError,
    DEFAULT_MINT_TTL,
};
use crate::rbac::{add_admin_claim_if_admin, RbacEvaluator};
use crate::use_cases::pat_validation_use_case::{PatValidationError, PatValidationUseCase};
use crate::use_cases::repository_access::RepositoryAccessUseCase;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Raw input the handler hands to the use case.
///
/// `service` and `scopes` echo the query-string. `client_ip` is
/// threaded through so PAT validation's brute-force-lockout gate
/// continues to apply on the `/v2/auth` path.
pub struct OciTokenExchangeRequest {
    /// PAT plaintext (the password slot of the inbound `Basic` header).
    /// The username field is ignored per Distribution-Spec convention.
    pub plaintext_pat: String,
    /// Echoed `service` query parameter; logged but not currently used
    /// for routing (every hort-server instance answers for itself).
    pub service: String,
    /// Multi-`scope` query parameter values (the spec allows repeated
    /// `scope=…` entries; axum surfaces them as a `Vec<String>`).
    pub scopes: Vec<String>,
    /// Client IP for the brute-force-lockout gate. `None` for
    /// in-process callers (tests / CLI).
    pub client_ip: Option<IpAddr>,
}

/// Successful response payload — the handler wraps this in the
/// Distribution-Spec response shape (`token` / `access_token` /
/// `expires_in` / `issued_at`).
pub struct OciTokenExchangeResponse {
    /// The minted JWT — placed in BOTH the `token` AND `access_token`
    /// response fields (the former for older Docker clients, the
    /// latter for OAuth2-compliant ones).
    pub jwt: String,
    /// `expires_in` per the spec — seconds until the JWT expires.
    pub expires_in_secs: u64,
    /// `issued_at` per the spec — ISO-8601 timestamp of mint.
    pub issued_at: DateTime<Utc>,
    /// Granted subset (echo of the JWT `access[]` for callers that
    /// want to log / metric without re-decoding the JWT).
    pub granted_subset: Vec<AccessEntry>,
}

/// Failure model — the handler maps each variant to its HTTP shape.
#[derive(Debug, Error)]
pub enum OciTokenExchangeError {
    /// The inbound `?service=<value>` query
    /// parameter does not match the configured registry audience
    /// (`OciTokenExchangeConfig.jwt_audience`). Enforced as an
    /// unbypassable Step-0 inside [`OciTokenExchangeUseCase::exchange`]
    /// (before scope parse and before PAT validation): a `service`
    /// mismatch means the client is talking to the wrong registry, so
    /// the (expensive) Argon2 PAT verify is never reached. Maps to
    /// **HTTP 400** with the Distribution-Spec `UNSUPPORTED` envelope
    /// and the constant message `"service mismatch"` — the `requested`
    /// / `expected` hosts go to the structured audit log only, never
    /// the wire body — no reflected value in the response.
    #[error("service mismatch")]
    ServiceMismatch { requested: String, expected: String },
    /// PAT validation rejected the supplied Basic credential. Maps to
    /// 401 with the Distribution-Spec error envelope + the Bearer
    /// challenge re-emitted (Distribution-Spec convention).
    #[error("invalid credential")]
    InvalidCredential,
    /// One of the `scope=…` query parameters did not parse against the
    /// `<resource_type>:<resource_name>:<action>[,…]` grammar, used
    /// an unknown `resource_type`, an unknown action, or a wildcard
    /// `resource_name`. Maps to 400 with the
    /// `{"errors":[{"code":"UNSUPPORTED",…}]}` envelope.
    #[error("invalid scope: {raw}")]
    InvalidScope { raw: String },
    /// Adapter / repository lookup blew up. Maps to 500.
    #[error("infrastructure error: {0}")]
    Infrastructure(#[from] DomainError),
    /// JWT minting failed (signing key broken). Maps to 500. Should
    /// never trigger in production.
    #[error("token mint failed: {0}")]
    Mint(#[from] SigningError),
}

/// Per-instance configuration. Threaded in by the composition root so
/// the use case has no `env::var` access.
#[derive(Debug, Clone)]
pub struct OciTokenExchangeConfig {
    /// `iss` claim value — convention: `https://<hort-host>/v2/auth`.
    pub jwt_issuer: String,
    /// `aud` claim value — registry hostname.
    pub jwt_audience: String,
    /// JWT lifetime; default [`DEFAULT_MINT_TTL`] = 5 min per spec.
    pub mint_ttl: StdDuration,
}

impl OciTokenExchangeConfig {
    /// Build with the design-doc default 5-minute TTL.
    pub fn new(jwt_issuer: String, jwt_audience: String) -> Self {
        Self {
            jwt_issuer,
            jwt_audience,
            mint_ttl: DEFAULT_MINT_TTL,
        }
    }
}

/// The use case itself.
///
/// Holds `Arc<dyn …>` for every collaborator. Composition wires this
/// once at boot; tests inject mocks via the `Arc<dyn …>` shape.
pub struct OciTokenExchangeUseCase {
    pat_validation: Arc<PatValidationUseCase>,
    users: Arc<dyn UserRepository>,
    rbac: Arc<arc_swap::ArcSwap<RbacEvaluator>>,
    repo_access: Arc<RepositoryAccessUseCase>,
    signing_key: Arc<OciTokenSigningKey>,
    config: OciTokenExchangeConfig,
}

impl OciTokenExchangeUseCase {
    pub fn new(
        pat_validation: Arc<PatValidationUseCase>,
        users: Arc<dyn UserRepository>,
        rbac: Arc<arc_swap::ArcSwap<RbacEvaluator>>,
        repo_access: Arc<RepositoryAccessUseCase>,
        signing_key: Arc<OciTokenSigningKey>,
        config: OciTokenExchangeConfig,
    ) -> Self {
        Self {
            pat_validation,
            users,
            rbac,
            repo_access,
            signing_key,
            config,
        }
    }

    /// Drive the full /v2/auth flow.
    pub async fn exchange(
        &self,
        request: OciTokenExchangeRequest,
    ) -> Result<OciTokenExchangeResponse, OciTokenExchangeError> {
        // Step 0: the inbound `?service=` MUST
        // match the configured registry audience. This is an
        // unbypassable gate inside the shared use case — no inbound
        // caller can skip it. It runs BEFORE scope parse and
        // BEFORE the expensive Argon2 PAT verify: a `service` mismatch
        // means the client is talking to the wrong registry entirely,
        // so the scopes + credential are moot. Comparison is
        // case-insensitive (RFC 3986 §3.2.2 — DNS hostnames are
        // case-insensitive) and whitespace-trimmed; an empty requested
        // service after trim cannot equal a non-empty configured host
        // and therefore mismatches → 400. Bare-host vs bare-host: a
        // client that sends a scheme or port (`https://host`,
        // `host:5000`) mismatches and 400s — that is itself a
        // misconfiguration worth surfacing.
        let requested = normalize_service(&request.service);
        let expected = normalize_service(&self.config.jwt_audience);
        if requested != expected {
            emit_verify_metric(VerifyResultLabel::ServiceMismatch);
            // Audit fact (client/config error, NOT an `error!`): both
            // values are hostnames (server config + client-echoed) — no
            // credential, no PII. The wire body stays
            // constant; the operator-debuggable detail lives here.
            tracing::info!(
                event = "oci_v2_auth_denied",
                reason = "service_mismatch",
                requested = %requested,
                expected = %expected,
                "/v2/auth rejected: service= does not match configured audience"
            );
            return Err(OciTokenExchangeError::ServiceMismatch {
                requested,
                expected,
            });
        }

        // Step 1: parse every scope BEFORE PAT validation. A malformed
        // scope is a deterministic 400 regardless of credential
        // validity; emitting it before the (expensive) Argon2 verify
        // saves work and produces a clearer client-side error.
        let parsed: Vec<ParsedScope> = request
            .scopes
            .iter()
            .map(|raw| parse_scope(raw))
            .collect::<Result<_, _>>()
            .map_err(|raw| {
                emit_result_metric(ResultLabel::InvalidScope);
                emit_verify_metric(VerifyResultLabel::Denied);
                OciTokenExchangeError::InvalidScope { raw }
            })?;

        // Step 2: validate the PAT.
        let validation = self
            .pat_validation
            .validate_pat(&request.plaintext_pat, request.client_ip)
            .await
            .map_err(|err| {
                emit_result_metric(ResultLabel::InvalidCredential);
                emit_verify_metric(VerifyResultLabel::Denied);
                map_pat_error(err)
            })?;

        // Step 3: build a synthetic principal carrying the validated
        // user_id + token_cap. Roles are seeded from the live `User`
        // row's `is_admin` bit, mirroring `authenticate_pat` (live
        // re-resolution per request). PAT-bearing callers carry no
        // fresh IdP claim, so `groups` stays empty and the only
        // authority leg through the user-grants path is the admin
        // short-circuit (when `is_admin = true`) or per-repo
        // `PermissionGrant` rows attached to roles the user holds.
        // Without this re-resolution `roles: Vec::new()` would
        // short-circuit `RbacEvaluator::user_grants_authorize` to
        // `false` and every minted JWT would carry an empty `access[]`.
        //
        // The validator already short-circuited on `is_active = false`
        // upstream, so a successful `validation` implies the user row
        // exists and is active. A `NotFound` here means the user was
        // deleted between PAT issuance and exchange; we surface that
        // as `Infrastructure(DomainError::NotFound)` (5xx) — same
        // shape as any other repository miss on a hot path.
        let user = self.users.find_by_id(validation.user_id).await?;
        // Behaviour-preserving: the
        // `is_admin → ["admin"]` derivation is reproduced exactly via
        // the shared synthetic-admin helper — no claim is invented beyond
        // the synthetic `admin` claim. PAT-bearing callers carry
        // no fresh IdP claim, so the claim set is at most `["admin"]`.
        let mut claims = Vec::new();
        add_admin_claim_if_admin(&mut claims, user.is_admin);
        let principal = CallerPrincipal {
            user_id: user.id,
            external_id: user
                .external_id
                .clone()
                .unwrap_or_else(|| user.id.to_string()),
            username: user.username.clone(),
            email: user.email.clone(),
            claims,
            // Unambiguous from local context: this is the native-token
            // (PAT / service-account / cli-session) exchange path; the
            // validated token's kind is threaded straight through.
            token_kind: Some(validation.kind),
            issued_at: Utc::now(),
            token_cap: Some(validation.token_cap.clone()),
        };

        // Step 4: per-scope authorization. Build the granted subset.
        let mut granted: Vec<AccessEntry> = Vec::with_capacity(parsed.len());
        let mut requested_action_count: usize = 0;
        let mut granted_action_count: usize = 0;
        for scope in &parsed {
            let grants = self.evaluate_scope(scope, &principal).await?;
            requested_action_count += scope.actions.len();
            granted_action_count += grants.actions.len();
            for action in &grants.actions {
                emit_action_metric(action);
            }
            // Empty per-scope grant = no `access[]` entry for that
            // scope. Per Distribution-Spec convention a client that
            // requested `repository:foo:pull,push` and got back an
            // entry with `actions: ["pull"]` knows pull was granted
            // and push was not. An entirely-omitted entry signals
            // "nothing was granted on that resource".
            if !grants.actions.is_empty() {
                granted.push(AccessEntry {
                    resource_type: scope.resource_type.wire_str().to_string(),
                    name: scope.resource_name.clone(),
                    actions: grants.actions,
                });
            }
        }

        // Step 5: classify grant outcome for metrics. Empty `granted`
        // == no_grant. `granted_action_count == requested_action_count`
        // == full_grant. Anything in-between == partial_grant.
        let result_label = if requested_action_count == 0 {
            // No scopes requested at all — degenerate case (a client
            // could legitimately call /v2/auth with `service=` only,
            // for a "ping me" anonymous token). Treat as no_grant.
            ResultLabel::NoGrant
        } else if granted_action_count == 0 {
            ResultLabel::NoGrant
        } else if granted_action_count == requested_action_count {
            ResultLabel::FullGrant
        } else {
            ResultLabel::PartialGrant
        };
        emit_result_metric(result_label);

        // Step 6: mint the JWT.
        let now = Utc::now();
        let exp = now
            + chrono::Duration::from_std(self.config.mint_ttl)
                .unwrap_or_else(|_| chrono::Duration::seconds(300));
        let claims = OciAccessClaims {
            iss: self.config.jwt_issuer.clone(),
            sub: validation.user_id,
            aud: self.config.jwt_audience.clone(),
            exp,
            access: granted.clone(),
        };
        let jwt = match self.signing_key.mint(&claims) {
            Ok(jwt) => jwt,
            Err(err) => {
                // Mint failure — signing key broken: the mint-path
                // failure maps to `denied`. The existing
                // `error!` at the inbound site (v2_auth.rs) stays; this
                // is the verify-axis counter only.
                emit_verify_metric(VerifyResultLabel::Denied);
                return Err(err.into());
            }
        };

        // Mint path succeeded: PAT validated + JWT minted (`ok`).
        // Orthogonal to `hort_oci_v2_auth_total` (grant breadth) —
        // this is the verify-outcome axis.
        emit_verify_metric(VerifyResultLabel::Ok);

        Ok(OciTokenExchangeResponse {
            jwt,
            expires_in_secs: self.config.mint_ttl.as_secs(),
            issued_at: now,
            granted_subset: granted,
        })
    }

    /// Resolve one parsed scope into the granted-actions subset.
    async fn evaluate_scope(
        &self,
        scope: &ParsedScope,
        principal: &CallerPrincipal,
    ) -> Result<GrantedActions, OciTokenExchangeError> {
        let rbac = self.rbac.load();
        match scope.resource_type {
            ResourceType::Repository => {
                // Resolve the repo by key. A miss means the user
                // requested a scope on a repo they cannot see; per
                // anti-enumeration discipline we surface "no grant"
                // for that scope (NOT a 404), so the OCI client falls
                // through to the storage layer's existing
                // NAME_UNKNOWN handling.
                let repo_id = match self
                    .repo_access
                    .find_repo_id_by_key_unchecked(&scope.resource_name)
                    .await
                {
                    Ok(Some(id)) => id,
                    Ok(None) => return Ok(GrantedActions::empty()),
                    Err(crate::error::AppError::Domain(d)) => return Err(d.into()),
                    Err(other) => {
                        return Err(OciTokenExchangeError::Infrastructure(
                            DomainError::Invariant(format!("repo lookup error: {other}")),
                        ));
                    }
                };
                let mut granted_actions = Vec::with_capacity(scope.actions.len());
                for action in &scope.actions {
                    if rbac.authorize(principal, action.required_permission(), Some(repo_id)) {
                        granted_actions.push(action.wire_str().to_string());
                    }
                }
                Ok(GrantedActions {
                    actions: granted_actions,
                })
            }
            ResourceType::Registry => {
                // Catalog ops: require admin authority. The cap leg
                // applies via `RbacEvaluator::authorize`'s built-in
                // intersection; a token without `Permission::Admin`
                // in its cap fails the cap leg and is denied.
                let mut granted_actions = Vec::with_capacity(scope.actions.len());
                for action in &scope.actions {
                    let perm = action.required_permission();
                    // The catalog-grant check uses
                    // `repository_id = None` (system-level op). The
                    // cap-intersection helper denies a per-repo-
                    // restricted token on this path automatically.
                    if rbac.authorize(principal, perm, None) {
                        granted_actions.push(action.wire_str().to_string());
                    }
                }
                Ok(GrantedActions {
                    actions: granted_actions,
                })
            }
        }
    }

    /// The single consume-side verify entrypoint for an
    /// inbound `/v2/*` `Authorization: Bearer <jwt>`.
    ///
    /// This is the Entry-7 "bespoke validation" closure: the
    /// `match key.verify(...)` arm logic and the principal synthesis
    /// that used to live inlined in `hort-http-oci`'s `oci_bearer_auth`
    /// middleware move here, behind a typed [`OciVerifyOutcome`] the
    /// middleware maps without ever inspecting [`VerificationError`].
    ///
    /// The Ed25519 sign/verify primitive ([`OciTokenSigningKey`]) is
    /// **unchanged** — it is the OCI Distribution-Spec issuer
    /// mechanism, not bespoke-by-choice. The expected
    /// audience is `self.config.jwt_audience` — the **same** value the
    /// mint side embeds in the JWT `aud` claim. Centralising both
    /// derivations on this one config field eliminates the latent
    /// mint/consume aud-derivation drift (the consume side previously
    /// re-derived `host_of(oci_public_base_url)` independently).
    #[tracing::instrument(skip_all)]
    pub fn verify_inbound(&self, jwt: &str) -> OciVerifyOutcome {
        match self.signing_key.verify(jwt, &self.config.jwt_audience) {
            Ok(claims) => {
                emit_verify_metric(VerifyResultLabel::Ok);
                OciVerifyOutcome::Verified(Box::new(synthesize_principal_from_jwt(&claims)))
            }
            // Not an hort-server-OCI-minted JWT (bad signature /
            // structurally not ours). Fall through to the IdP-JWT
            // validator. NOT counted `denied` — a fall-through is not
            // a denial (counting it would double-count against the IdP
            // path's own telemetry).
            Err(VerificationError::InvalidSignature) | Err(VerificationError::Malformed { .. }) => {
                OciVerifyOutcome::NotOurToken
            }
            // Structurally-ours token that is invalid (expired / wrong
            // audience). HARD reject — the middleware must NOT fall
            // through.
            Err(VerificationError::Expired) => {
                emit_verify_metric(VerifyResultLabel::Denied);
                tracing::info!(
                    event = "oci_bearer_rejected",
                    reason = "expired",
                    "oci_bearer_auth: native OCI JWT rejected"
                );
                OciVerifyOutcome::Rejected(OciVerifyRejection::Expired)
            }
            Err(VerificationError::InvalidAudience) => {
                emit_verify_metric(VerifyResultLabel::Denied);
                tracing::info!(
                    event = "oci_bearer_rejected",
                    reason = "invalid_audience",
                    "oci_bearer_auth: native OCI JWT rejected"
                );
                OciVerifyOutcome::Rejected(OciVerifyRejection::InvalidAudience)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Consume-side verify outcome
// ---------------------------------------------------------------------------

/// Outcome of verifying an inbound `/v2/*` bearer against the OCI
/// signing key. Typed so the inbound middleware maps arms without
/// inspecting [`VerificationError`] (the Entry-7 "bespoke validation"
/// the auth-catalog flags moves behind this).
#[derive(Debug)]
pub enum OciVerifyOutcome {
    /// JWT verified against the active OR previous OCI signing key.
    /// Carries the synthesized principal (built in `hort-app`, not the
    /// inbound crate).
    Verified(Box<CallerPrincipal>),
    /// Not an hort-server-OCI-minted JWT (bad signature / structurally
    /// not ours). The middleware falls through to the IdP-JWT
    /// validator.
    NotOurToken,
    /// A structurally-ours token that is invalid (expired / wrong
    /// audience). The middleware rejects with the OCI 401 challenge —
    /// it must NOT fall through.
    Rejected(OciVerifyRejection),
}

/// Why a structurally-ours OCI JWT was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OciVerifyRejection {
    /// Token's `exp` is in the past.
    Expired,
    /// `aud` claim did not match the configured audience.
    InvalidAudience,
}

/// Build a synthetic [`CallerPrincipal`] from the OCI JWT claims.
///
/// Moved **verbatim** out of `hort-http-oci`'s
/// `oci_bearer_auth` middleware — the format crate keeps no bespoke
/// validation logic. It is pure (claims
/// → principal, no I/O) and is validation logic — it belongs with the
/// verifier in `hort-app`.
///
/// The JWT carries the granted `access[]` array — we materialise it
/// as a [`TokenCap`] so downstream `RbacEvaluator::authorize` applies
/// the cap leg correctly. The cap's `permissions` is the union of
/// every action across every entry, mapped via the `pull→Read`,
/// `push→Write`, `delete→Delete` rule. The cap's `repository_ids`
/// stays `None` because the claims carry repo NAMES, not ids — the
/// per-request authz at the storage layer re-resolves the name to an
/// id and the cap leg falls through to the user's grants.
///
/// This is admittedly a coarser cap than the original PAT carried
/// (we lose the per-repo-id scoping when the repo set is wide), but
/// it preserves the invariant "a token's permissions never
/// widen": the JWT claims carry an upper bound on the actions the
/// user could exercise at mint time, and `RbacEvaluator::authorize`
/// re-resolves the user's *current* grants on every call.
fn synthesize_principal_from_jwt(claims: &OciAccessClaims) -> CallerPrincipal {
    let mut permissions: Vec<Permission> = Vec::new();
    for entry in &claims.access {
        for action in &entry.actions {
            let perm = match action.as_str() {
                "pull" => Permission::Read,
                "push" => Permission::Write,
                "delete" => Permission::Delete,
                _ => continue,
            };
            if !permissions.contains(&perm) {
                permissions.push(perm);
            }
        }
    }
    CallerPrincipal {
        user_id: claims.sub,
        external_id: format!("oci-jwt:{}", claims.sub),
        username: format!("oci-jwt:{}", claims.sub),
        email: String::new(),
        // The bespoke OCI `/v2/auth` JWT path is not a
        // native-token (`authenticate_pat`) path and does not resolve
        // `claim_mappings`; it carries no claims. Authority
        // is the JWT-derived `token_cap` only. `token_kind = None` per
        // the non-native principal-build convention (OIDC / local set
        // `None`; only `authenticate_pat` sets `Some(validation.kind)`).
        claims: Vec::new(),
        token_kind: None,
        issued_at: claims.exp,
        token_cap: Some(TokenCap {
            permissions,
            repository_ids: None,
        }),
    }
}

/// Normalize a `service=` / `aud` host for
/// the Step-0 mismatch predicate: ASCII-lowercase + trim. Host
/// comparison is case-insensitive per RFC 3986 §3.2.2 (DNS hostnames
/// are case-insensitive). Bare host only — no scheme/port
/// stripping: a `service=` carrying a scheme or
/// port is itself a misconfiguration and mismatches → 400.
fn normalize_service(s: &str) -> String {
    s.trim().to_ascii_lowercase()
}

// ---------------------------------------------------------------------------
// Scope grammar
// ---------------------------------------------------------------------------

/// Parsed shape of one `scope=…` query-string entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedScope {
    pub resource_type: ResourceType,
    pub resource_name: String,
    pub actions: Vec<ScopeAction>,
}

/// Distribution-Spec resource-type discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceType {
    Repository,
    Registry,
}

impl ResourceType {
    fn wire_str(self) -> &'static str {
        match self {
            Self::Repository => "repository",
            Self::Registry => "registry",
        }
    }
}

/// Distribution-Spec action discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeAction {
    Pull,
    Push,
    Delete,
}

impl ScopeAction {
    fn wire_str(self) -> &'static str {
        match self {
            Self::Pull => "pull",
            Self::Push => "push",
            Self::Delete => "delete",
        }
    }

    /// Map to the internal `Permission` enum: `pull → Read`,
    /// `push → Write` (push implies pull — the
    /// caller checks both Read AND Write when push is requested),
    /// `delete → Delete`.
    fn required_permission(self) -> Permission {
        match self {
            Self::Pull => Permission::Read,
            Self::Push => Permission::Write,
            Self::Delete => Permission::Delete,
        }
    }
}

/// Per-scope granted-actions accumulator. Kept distinct from
/// [`AccessEntry`] so we can decide whether to push an entry into the
/// response (empty = skip).
struct GrantedActions {
    actions: Vec<String>,
}

impl GrantedActions {
    fn empty() -> Self {
        Self { actions: vec![] }
    }
}

/// Parse one raw `scope=…` value. Returns the raw string on failure
/// so the caller can emit it in the `UNSUPPORTED` envelope.
///
/// Grammar: `<resource_type>:<resource_name>:<action>[,<action>...]`.
/// - `resource_type` ∈ {`repository`, `registry`}.
/// - `resource_name` cannot contain `*` (wildcard rejection).
/// - `action` ∈ {`pull`, `push`, `delete`}.
/// - **`push` implies `pull`** per spec — the parser auto-promotes
///   `push` to `pull,push` (with deduplication) so downstream evaluation
///   checks both legs.
pub fn parse_scope(raw: &str) -> Result<ParsedScope, String> {
    // Distribution-Spec uses ':' as the separator. resource_name MAY
    // contain '/' (canonical for `<group>/<image>`); split on the
    // FIRST and LAST ':' so the middle (the name) is preserved.
    let first = raw.find(':').ok_or_else(|| raw.to_string())?;
    let after_first = &raw[first + 1..];
    let last_in_after = after_first.rfind(':').ok_or_else(|| raw.to_string())?;
    let last_abs = first + 1 + last_in_after;

    let resource_type = &raw[..first];
    let resource_name = &raw[first + 1..last_abs];
    let actions_str = &raw[last_abs + 1..];

    if resource_name.is_empty() || actions_str.is_empty() {
        return Err(raw.to_string());
    }
    if resource_name.contains('*') {
        return Err(raw.to_string());
    }

    let resource_type = match resource_type {
        "repository" => ResourceType::Repository,
        "registry" => ResourceType::Registry,
        _ => return Err(raw.to_string()),
    };

    if matches!(resource_type, ResourceType::Registry) && resource_name != "catalog" {
        // The spec only defines `registry:catalog:*`; reject any other
        // shape so future spec extensions surface as deliberate
        // additions rather than silent acceptances.
        return Err(raw.to_string());
    }

    let mut actions: Vec<ScopeAction> = Vec::new();
    for raw_action in actions_str.split(',') {
        let action = match raw_action.trim() {
            "pull" => ScopeAction::Pull,
            "push" => {
                // push implies pull — pre-seed pull if not already present.
                if !actions.contains(&ScopeAction::Pull) {
                    actions.push(ScopeAction::Pull);
                }
                ScopeAction::Push
            }
            "delete" => ScopeAction::Delete,
            "*" => {
                // The spec uses `*` as a wildcard *for the catalog
                // grant only*. We accept `registry:catalog:*` as
                // shorthand for `pull` (the only meaningful catalog
                // action today); everything else stays a hard reject.
                if matches!(resource_type, ResourceType::Registry) {
                    ScopeAction::Pull
                } else {
                    return Err(raw.to_string());
                }
            }
            _ => return Err(raw.to_string()),
        };
        if !actions.contains(&action) {
            actions.push(action);
        }
    }

    Ok(ParsedScope {
        resource_type,
        resource_name: resource_name.to_string(),
        actions,
    })
}

// ---------------------------------------------------------------------------
// Metrics — `hort_oci_v2_auth_total{result}` + `…_scope_actions_granted_total`
//           + `hort_oci_auth_verify_total{result}`
// ---------------------------------------------------------------------------

const RESULT_METRIC: &str = "hort_oci_v2_auth_total";
const SCOPE_ACTIONS_METRIC: &str = "hort_oci_v2_auth_scope_actions_granted_total";
/// Verify-outcome axis across BOTH the mint
/// (`/v2/auth`) and consume (`/v2/*` bearer) paths. Orthogonal to
/// `hort_oci_v2_auth_total` (grant breadth) — emitted at the `hort-app`
/// layer that owns the verify decision (one metric, one layer, no
/// double-count). Catalog row: `docs/metrics-catalog.md`.
const VERIFY_METRIC: &str = "hort_oci_auth_verify_total";

#[derive(Debug, Clone, Copy)]
enum ResultLabel {
    FullGrant,
    PartialGrant,
    NoGrant,
    InvalidScope,
    InvalidCredential,
}

impl ResultLabel {
    fn wire(self) -> &'static str {
        match self {
            Self::FullGrant => "full_grant",
            Self::PartialGrant => "partial_grant",
            Self::NoGrant => "no_grant",
            Self::InvalidScope => "invalid_scope",
            Self::InvalidCredential => "invalid_credential",
        }
    }
}

/// `hort_oci_auth_verify_total{result}` axis.
/// `result ∈ { ok, service_mismatch, denied }`. 3 series
/// per deployment; no per-user/repo/service labels (architect
/// high-cardinality anti-pattern — those are tracing/audit concerns).
#[derive(Debug, Clone, Copy)]
enum VerifyResultLabel {
    /// Mint path PAT validated + JWT minted, OR consume path
    /// `OciVerifyOutcome::Verified`.
    Ok,
    /// Step-0 gate fired (mint path only): `service=` ≠ configured
    /// audience. 400 returned; no PAT validated, no JWT minted.
    ServiceMismatch,
    /// Mint path: PAT invalid / scope invalid / mint failure. Consume
    /// path: `OciVerifyOutcome::Rejected` (expired / wrong aud).
    /// `NotOurToken` is **not** counted here (fall-through, not a
    /// denial).
    Denied,
}

impl VerifyResultLabel {
    fn wire(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::ServiceMismatch => "service_mismatch",
            Self::Denied => "denied",
        }
    }
}

fn emit_result_metric(label: ResultLabel) {
    metrics::counter!(RESULT_METRIC, labels::RESULT => label.wire()).increment(1);
}

fn emit_verify_metric(label: VerifyResultLabel) {
    metrics::counter!(VERIFY_METRIC, labels::RESULT => label.wire()).increment(1);
}

fn emit_action_metric(action: &str) {
    // Action label is bounded by the parser to {pull, push, delete}.
    metrics::counter!(SCOPE_ACTIONS_METRIC, labels::ACTION => action.to_string()).increment(1);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn map_pat_error(err: PatValidationError) -> OciTokenExchangeError {
    match err {
        PatValidationError::Infrastructure(d) => OciTokenExchangeError::Infrastructure(d),
        // Every other variant collapses to InvalidCredential —
        // the OCI client only sees a 401 + Bearer challenge
        // regardless of the underlying reason.
        _ => OciTokenExchangeError::InvalidCredential,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- parse_scope ----------

    #[test]
    fn parse_scope_repository_with_pull_actions() {
        let p = parse_scope("repository:library/nginx:pull").expect("parse");
        assert_eq!(p.resource_type, ResourceType::Repository);
        assert_eq!(p.resource_name, "library/nginx");
        assert_eq!(p.actions, vec![ScopeAction::Pull]);
    }

    #[test]
    fn parse_scope_repository_with_push_implies_pull() {
        let p = parse_scope("repository:foo/bar:push").expect("parse");
        // push implies pull — both must appear, pull first.
        assert_eq!(p.actions, vec![ScopeAction::Pull, ScopeAction::Push]);
    }

    #[test]
    fn parse_scope_repository_with_pull_push_explicit_dedupes() {
        let p = parse_scope("repository:foo/bar:pull,push").expect("parse");
        assert_eq!(p.actions, vec![ScopeAction::Pull, ScopeAction::Push]);
    }

    #[test]
    fn parse_scope_registry_catalog_with_wildcard_action() {
        let p = parse_scope("registry:catalog:*").expect("parse");
        assert_eq!(p.resource_type, ResourceType::Registry);
        assert_eq!(p.resource_name, "catalog");
        assert_eq!(p.actions, vec![ScopeAction::Pull]);
    }

    #[test]
    fn parse_scope_unknown_resource_type_returns_invalid_scope() {
        let raw = "blob:foo:pull";
        let err = parse_scope(raw).unwrap_err();
        assert_eq!(err, raw);
    }

    #[test]
    fn parse_scope_wildcard_resource_name_rejected() {
        let raw = "repository:*:pull";
        let err = parse_scope(raw).unwrap_err();
        assert_eq!(err, raw);
        let raw = "repository:team-*:pull";
        let err = parse_scope(raw).unwrap_err();
        assert_eq!(err, raw);
    }

    #[test]
    fn parse_scope_unknown_action_rejected() {
        let raw = "repository:foo:fly";
        let err = parse_scope(raw).unwrap_err();
        assert_eq!(err, raw);
    }

    #[test]
    fn parse_scope_malformed_missing_colons_rejected() {
        // Total miss.
        assert!(parse_scope("nope").is_err());
        // One colon only.
        assert!(parse_scope("repository:foo").is_err());
        // Empty resource_name.
        assert!(parse_scope("repository::pull").is_err());
        // Empty actions.
        assert!(parse_scope("repository:foo:").is_err());
    }

    #[test]
    fn parse_scope_registry_with_non_catalog_name_rejected() {
        // Distribution Spec only defines `registry:catalog:*` —
        // everything else stays a deliberate addition.
        let raw = "registry:something_else:pull";
        let err = parse_scope(raw).unwrap_err();
        assert_eq!(err, raw);
    }

    #[test]
    fn parse_scope_repository_with_delete_action() {
        let p = parse_scope("repository:foo:delete").expect("parse");
        assert_eq!(p.actions, vec![ScopeAction::Delete]);
    }

    #[test]
    fn parse_scope_repository_with_pull_push_delete() {
        let p = parse_scope("repository:foo:pull,push,delete").expect("parse");
        assert_eq!(
            p.actions,
            vec![ScopeAction::Pull, ScopeAction::Push, ScopeAction::Delete]
        );
    }

    #[test]
    fn scope_action_required_permission_mapping() {
        assert_eq!(ScopeAction::Pull.required_permission(), Permission::Read);
        assert_eq!(ScopeAction::Push.required_permission(), Permission::Write);
        assert_eq!(
            ScopeAction::Delete.required_permission(),
            Permission::Delete
        );
    }

    // =================================================================
    // DebuggingRecorder happy- and failure-path tests for the OCI
    // token-exchange metrics:
    //   - `hort_oci_v2_auth_total{result}`
    //   - `hort_oci_v2_auth_scope_actions_granted_total{action}`
    //
    // Mirrors the test structure used for `hort_api_token_*` in the
    // sister modules (`api_token_use_case.rs`, `pat_validation_use_case.rs`).
    // Each test sets up a `DebuggingRecorder`, drives `exchange()` end-
    // to-end, and asserts the metric fires with the expected
    // `result` / `action` label. Cardinality-discipline tests pin the
    // exact label set for both metrics.
    // =================================================================

    use std::collections::{BTreeSet, HashMap};
    use std::net::IpAddr;
    use std::sync::Mutex;
    use std::time::Duration;

    use bytes::Bytes;
    use chrono::{DateTime, Duration as ChronoDuration};
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use metrics_util::{CompositeKey, MetricKind};
    use uuid::Uuid;

    use hort_domain::entities::api_token::{ApiToken, TokenKind};
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::rbac::{GrantSubject, PermissionGrant};
    use hort_domain::entities::repository::{
        IndexMode, PrefetchPolicy, Repository, RepositoryFormat, RepositoryType,
    };
    use hort_domain::entities::user::{AuthProvider, User};
    use hort_domain::error::{DomainError, DomainResult};
    use hort_domain::ports::api_token_repository::ApiTokenRepository;
    use hort_domain::ports::ephemeral_store::EphemeralStore;
    use hort_domain::ports::repository_repository::RepositoryRepository;
    use hort_domain::ports::user_repository::UserRepository;
    use hort_domain::ports::BoxFuture;
    use hort_domain::types::{Page, PageRequest};

    use crate::argon2_hash::{hash_token, Argon2Verifier};
    use crate::use_cases::pat_cache::{Clock, PatCache};
    use crate::use_cases::pat_validation_use_case::PatLockoutConfig;
    use crate::use_cases::repository_access::RbacAccess;

    use ed25519_dalek::SigningKey;

    // -- Fixed clock so the histogram side-effect is deterministic.
    struct FixedClock(DateTime<Utc>);
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    // -- Spy verifier returning a planted result. We use it to drive
    //    the deterministic happy-path; the real Argon2 verify costs
    //    >50 ms which would slow the test suite.
    struct SpyVerifier(bool);
    impl Argon2Verifier for SpyVerifier {
        fn verify(&self, _plaintext: &[u8], _hash: &str) -> bool {
            self.0
        }
    }

    // -- Tiny in-memory ApiTokenRepository scoped to OCI tests. The
    //    public `MockApiTokenRepository` in `test_support` always
    //    returns `None` from `find_by_prefix`, which would short-
    //    circuit the validator before reaching the verify call.
    struct OciInMemoryTokenRepo {
        by_prefix: Mutex<HashMap<String, ApiToken>>,
    }
    impl OciInMemoryTokenRepo {
        fn new() -> Self {
            Self {
                by_prefix: Mutex::new(HashMap::new()),
            }
        }
        fn insert(&self, prefix: &str, token: ApiToken) {
            self.by_prefix
                .lock()
                .unwrap()
                .insert(prefix.to_string(), token);
        }
    }
    impl ApiTokenRepository for OciInMemoryTokenRepo {
        fn insert(&self, _token: &ApiToken) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn find_by_prefix(&self, prefix: &str) -> BoxFuture<'_, DomainResult<Option<ApiToken>>> {
            let result = self.by_prefix.lock().unwrap().get(prefix).cloned();
            Box::pin(async move { Ok(result) })
        }
        fn find_by_id(&self, id: Uuid) -> BoxFuture<'_, DomainResult<ApiToken>> {
            let result = self
                .by_prefix
                .lock()
                .unwrap()
                .values()
                .find(|t| t.id == id)
                .cloned()
                .ok_or_else(|| DomainError::NotFound {
                    entity: "ApiToken",
                    id: id.to_string(),
                });
            Box::pin(async move { result })
        }
        fn list_for_user(
            &self,
            _user_id: Uuid,
            _page: PageRequest,
        ) -> BoxFuture<'_, DomainResult<Page<ApiToken>>> {
            Box::pin(async {
                Ok(Page {
                    items: Vec::new(),
                    total: 0,
                })
            })
        }
        fn update_last_used(
            &self,
            _token_id: Uuid,
            _at: DateTime<Utc>,
            _client_ip: Option<&str>,
            _user_agent: Option<&str>,
        ) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn revoke(&self, _token_id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    // -- Tiny in-memory UserRepository — only `find_by_id` is
    //    reached by the validator, but the trait demands every method
    //    so the unreachable!s document scope.
    struct OciInMemoryUserRepo {
        users: Mutex<HashMap<Uuid, User>>,
    }
    impl OciInMemoryUserRepo {
        fn new() -> Self {
            Self {
                users: Mutex::new(HashMap::new()),
            }
        }
        fn insert(&self, user: User) {
            self.users.lock().unwrap().insert(user.id, user);
        }
    }
    impl UserRepository for OciInMemoryUserRepo {
        fn find_by_id(&self, id: Uuid) -> BoxFuture<'_, DomainResult<User>> {
            let result =
                self.users
                    .lock()
                    .unwrap()
                    .get(&id)
                    .cloned()
                    .ok_or_else(|| DomainError::NotFound {
                        entity: "User",
                        id: id.to_string(),
                    });
            Box::pin(async move { result })
        }
        fn find_by_username(&self, _u: &str) -> BoxFuture<'_, DomainResult<Option<User>>> {
            unreachable!("OCI test does not call find_by_username")
        }
        fn find_by_email(&self, _e: &str) -> BoxFuture<'_, DomainResult<Option<User>>> {
            unreachable!("OCI test does not call find_by_email")
        }
        fn list(&self, _p: PageRequest) -> BoxFuture<'_, DomainResult<Page<User>>> {
            unreachable!("OCI test does not call list")
        }
        fn save(&self, _u: &User) -> BoxFuture<'_, DomainResult<()>> {
            unreachable!("OCI test does not call save")
        }
        fn delete(&self, _id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
            unreachable!("OCI test does not call delete")
        }
        fn find_by_external_id(
            &self,
            _ap: AuthProvider,
            _ext: &str,
        ) -> BoxFuture<'_, DomainResult<Option<User>>> {
            unreachable!("OCI test does not call find_by_external_id")
        }
        fn upsert_on_login(&self, _u: &User) -> BoxFuture<'_, DomainResult<User>> {
            unreachable!("OCI test does not call upsert_on_login")
        }
    }

    // -- Tiny in-memory RepositoryRepository with `find_by_key`.
    //    OCI scope evaluation calls `find_repo_id_by_key_unchecked`
    //    which goes through `find_by_key`.
    struct OciInMemoryRepoRepo {
        by_key: Mutex<HashMap<String, Repository>>,
    }
    impl OciInMemoryRepoRepo {
        fn new() -> Self {
            Self {
                by_key: Mutex::new(HashMap::new()),
            }
        }
        fn insert(&self, repo: Repository) {
            self.by_key.lock().unwrap().insert(repo.key.clone(), repo);
        }
    }
    impl RepositoryRepository for OciInMemoryRepoRepo {
        fn find_by_id(&self, id: Uuid) -> BoxFuture<'_, DomainResult<Repository>> {
            let result = self
                .by_key
                .lock()
                .unwrap()
                .values()
                .find(|r| r.id == id)
                .cloned()
                .ok_or_else(|| DomainError::NotFound {
                    entity: "Repository",
                    id: id.to_string(),
                });
            Box::pin(async move { result })
        }
        fn find_by_key(&self, key: &str) -> BoxFuture<'_, DomainResult<Repository>> {
            let result = self
                .by_key
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| DomainError::NotFound {
                    entity: "Repository",
                    id: key.to_string(),
                });
            Box::pin(async move { result })
        }
        fn list(
            &self,
            _p: PageRequest,
            _s: Option<&str>,
        ) -> BoxFuture<'_, DomainResult<Page<Repository>>> {
            unreachable!("OCI test does not call list")
        }
        fn save(&self, _r: &Repository) -> BoxFuture<'_, DomainResult<()>> {
            unreachable!("OCI test does not call save")
        }
        fn delete(&self, _id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
            unreachable!("OCI test does not call delete")
        }
        fn get_virtual_members(&self, _id: Uuid) -> BoxFuture<'_, DomainResult<Vec<Repository>>> {
            unreachable!("OCI test does not call get_virtual_members")
        }
        fn add_virtual_member(&self, _v: Uuid, _m: Uuid) -> BoxFuture<'_, DomainResult<()>> {
            unreachable!("OCI test does not call add_virtual_member")
        }
        fn remove_virtual_member(&self, _v: Uuid, _m: Uuid) -> BoxFuture<'_, DomainResult<()>> {
            unreachable!("OCI test does not call remove_virtual_member")
        }
        fn get_storage_usage(&self, _id: Uuid) -> BoxFuture<'_, DomainResult<u64>> {
            unreachable!("OCI test does not call get_storage_usage")
        }
        fn save_managed(&self, _r: &Repository, _d: &[u8; 32]) -> BoxFuture<'_, DomainResult<()>> {
            unreachable!("OCI test does not call save_managed")
        }
        fn delete_managed(&self, _id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
            unreachable!("OCI test does not call delete_managed")
        }
    }

    // -- Tiny in-memory EphemeralStore. The validator's lockout-gate
    //    queries the `client_ip_bucket` key; the test harness keeps
    //    every entry live indefinitely so the gate stays open.
    struct OciInMemoryEphemeralStore {
        entries: Mutex<HashMap<String, Bytes>>,
    }
    impl OciInMemoryEphemeralStore {
        fn new() -> Self {
            Self {
                entries: Mutex::new(HashMap::new()),
            }
        }
    }
    impl EphemeralStore for OciInMemoryEphemeralStore {
        fn get(&self, key: &str) -> BoxFuture<'_, DomainResult<Option<Bytes>>> {
            let result = self.entries.lock().unwrap().get(key).cloned();
            Box::pin(async move { Ok(result) })
        }
        fn put(&self, key: &str, value: Bytes, _ttl: Duration) -> BoxFuture<'_, DomainResult<()>> {
            self.entries.lock().unwrap().insert(key.to_string(), value);
            Box::pin(async { Ok(()) })
        }
        fn put_if_absent(
            &self,
            key: &str,
            value: Bytes,
            _ttl: Duration,
        ) -> BoxFuture<'_, DomainResult<bool>> {
            let mut e = self.entries.lock().unwrap();
            let created = !e.contains_key(key);
            if created {
                e.insert(key.to_string(), value);
            }
            Box::pin(async move { Ok(created) })
        }
        fn compare_and_swap(
            &self,
            _k: &str,
            _v: u64,
            _nv: Bytes,
            _ttl: Duration,
        ) -> BoxFuture<'_, DomainResult<Option<u64>>> {
            unreachable!("OCI test does not CAS")
        }
        fn delete(&self, key: &str) -> BoxFuture<'_, DomainResult<()>> {
            self.entries.lock().unwrap().remove(key);
            Box::pin(async { Ok(()) })
        }
        fn extend_ttl(&self, _key: &str, _ttl: Duration) -> BoxFuture<'_, DomainResult<()>> {
            unreachable!("OCI test does not extend_ttl")
        }
    }

    // -----------------------------------------------------------------
    // Bag of handles returned by `make_use_case`. Tests reach into
    // them to seed users / tokens / repos as needed.
    // -----------------------------------------------------------------
    type Fixtures = (
        OciTokenExchangeUseCase,
        Arc<OciInMemoryTokenRepo>,
        Arc<OciInMemoryUserRepo>,
        Arc<OciInMemoryRepoRepo>,
    );

    /// Build a use case wired to in-memory mocks and an evaluator
    /// pre-loaded with the supplied grants on the role `developer`.
    /// The caller principal carries `developer` in its roles, so
    /// the evaluator's `authorize` checks resolve via that role.
    ///
    /// `verifier_result` controls the `Argon2Verifier` planted in the
    /// validator: `true` simulates a matching hash (happy path), `false`
    /// simulates a mismatch (the validator returns `HashMismatch` →
    /// `InvalidCredential`).
    fn make_use_case(grants: Vec<(Permission, Option<Uuid>)>, verifier_result: bool) -> Fixtures {
        // -- Token + user repositories.
        let tokens = Arc::new(OciInMemoryTokenRepo::new());
        let users = Arc::new(OciInMemoryUserRepo::new());
        let repos = Arc::new(OciInMemoryRepoRepo::new());
        let ephemeral = Arc::new(OciInMemoryEphemeralStore::new());

        // -- PAT cache + clock + validator.
        let now = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).expect("epoch");
        let clock: Arc<dyn Clock> = Arc::new(FixedClock(now));
        let cache = Arc::new(PatCache::new(16, Duration::from_secs(300)));
        let pat_validation = Arc::new(PatValidationUseCase::new_with_verifier(
            tokens.clone() as Arc<dyn ApiTokenRepository>,
            users.clone() as Arc<dyn UserRepository>,
            ephemeral.clone() as Arc<dyn EphemeralStore>,
            cache,
            Arc::new(SpyVerifier(verifier_result)) as Arc<dyn Argon2Verifier>,
            clock,
            PatLockoutConfig::DEFAULT,
        ));

        // -- RbacEvaluator where the `developer` claim grants the
        //    requested permissions (claim-based subject model — a
        //    `Claims(["developer"])` subject, no `(Role, role_id)`
        //    indirection).
        let rows: Vec<PermissionGrant> = grants
            .into_iter()
            .map(|(perm, repo)| PermissionGrant {
                id: Uuid::new_v4(),
                subject: GrantSubject::Claims(vec!["developer".to_string()]),
                repository_id: repo,
                permission: perm,
                created_at: now,
                managed_by: ManagedBy::Local,
                managed_by_digest: None,
            })
            .collect();
        let rbac = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(rows)));

        // -- RepositoryAccessUseCase with the in-memory repo + RBAC.
        let repo_access = Arc::new(RepositoryAccessUseCase::new(
            repos.clone() as Arc<dyn RepositoryRepository>,
            RbacAccess::Enabled(rbac.clone()),
            true,
        ));

        // -- Signing key — fresh per-test so tests stay independent.
        let signing_key = Arc::new(OciTokenSigningKey::new(
            SigningKey::generate(&mut rand::rngs::OsRng),
            None,
        ));
        let cfg =
            OciTokenExchangeConfig::new("https://hort.test/v2/auth".into(), "hort.test".into());
        let uc = OciTokenExchangeUseCase::new(
            pat_validation,
            users.clone() as Arc<dyn UserRepository>,
            rbac,
            repo_access,
            signing_key,
            cfg,
        );
        (uc, tokens, users, repos)
    }

    /// Plant a valid PAT row in the supplied repos. Returns the
    /// plaintext the test should hand to `exchange()`. The fixture
    /// prefix is the constant `aaaaaaaa` so the validator hits the
    /// planted row deterministically.
    ///
    /// `is_admin` controls the `User.is_admin` bit of the seeded user
    /// row. `OciTokenExchangeUseCase::exchange` re-resolves the user
    /// via `UserRepository::find_by_id` and seeds `roles: vec!["admin"]`
    /// when the row is admin (mirroring `authenticate_pat`). The
    /// full-grant / pull-push-delete tests
    /// pass `true`; the partial-grant test combines `is_admin = true`
    /// with a narrowed `declared_permissions` to exercise the cap
    /// leg's deny path.
    ///
    /// `declared_permissions` controls the `ApiToken.declared_permissions`
    /// (the token cap). Default is `[Read, Write, Delete]` (full cap);
    /// the partial-grant test passes `[Read]` so the cap leg denies
    /// `Write` (push) while admin's user-leg allows it.
    fn seed_pat_row(
        tokens: &OciInMemoryTokenRepo,
        users: &OciInMemoryUserRepo,
        is_admin: bool,
        declared_permissions: Vec<Permission>,
    ) -> (String, Uuid) {
        // Format per `parse_pat_token_format`: `hort_pat_<32-char-base32>`.
        let plaintext = "hort_pat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let user_id = Uuid::new_v4();
        let now = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).expect("epoch");
        users.insert(User {
            id: user_id,
            username: "alice".into(),
            email: "alice@test".into(),
            auth_provider: AuthProvider::Local,
            external_id: None,
            display_name: None,
            is_active: true,
            is_admin,
            is_service_account: false,
            last_login_at: None,
            created_at: now,
            updated_at: now,
        });
        // The hash is opaque to the spy verifier; we still produce a
        // real Argon2id PHC string for fidelity.
        let token_hash = hash_token(&plaintext).expect("hash");
        let token = ApiToken {
            id: Uuid::new_v4(),
            user_id,
            name: "alice-pat".into(),
            description: None,
            kind: TokenKind::Pat,
            token_hash,
            token_prefix: "aaaaaaaa".into(),
            declared_permissions,
            repository_ids: None,
            expires_at: Some(now + ChronoDuration::days(30)),
            revoked_at: None,
            last_used_at: None,
            last_used_ip: None,
            last_used_user_agent: None,
            created_by_user_id: user_id,
            created_at: now,
        };
        tokens.insert("aaaaaaaa", token);
        (plaintext, user_id)
    }

    /// Build a plain in-memory repository with the supplied key.
    fn build_repo(key: &str) -> Repository {
        let now = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).expect("epoch");
        Repository {
            id: Uuid::new_v4(),
            key: key.into(),
            name: "OCI Repo".into(),
            description: None,
            format: RepositoryFormat::Oci,
            repo_type: RepositoryType::Hosted,
            storage_backend: "filesystem".into(),
            storage_path: format!("/data/repos/{key}"),
            upstream_url: None,
            index_upstream_url: None,
            is_public: false,
            download_audit_enabled: false,
            quota_bytes: None,
            replication_priority: hort_domain::entities::repository::ReplicationPriority::OnDemand,
            promotion: None,
            curation_rule_names: Vec::new(),
            index_mode: IndexMode::ReleasedOnly,
            prefetch_policy: PrefetchPolicy::default(),
            created_at: now,
            updated_at: now,
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
        }
    }

    /// Capture metric emissions while running an async closure in a
    /// dedicated tokio runtime under a `DebuggingRecorder`. Returns
    /// the snapshot vec directly — assertions filter by name + label.
    fn capture_async<F, Fut>(
        f: F,
    ) -> Vec<(
        CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    )>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Runtime::new().unwrap().block_on(f());
        });
        snapshotter.snapshot().into_vec()
    }

    /// Walk a snapshot and return the counter value for the given
    /// `(metric_name, exact label set)`. Returns 0 when the metric +
    /// label combo is absent. Mirrors `b9_counter_value` in the sister
    /// modules but inlined here so the OCI tests are self-contained.
    fn counter_value(
        snap: &[(
            CompositeKey,
            Option<metrics::Unit>,
            Option<metrics::SharedString>,
            DebugValue,
        )],
        metric_name: &str,
        label_kvs: &[(&str, &str)],
    ) -> u64 {
        for (key, _u, _d, value) in snap {
            if key.kind() != MetricKind::Counter {
                continue;
            }
            if key.key().name() != metric_name {
                continue;
            }
            let got: HashMap<String, String> = key
                .key()
                .labels()
                .map(|l| (l.key().to_string(), l.value().to_string()))
                .collect();
            let labels_match = label_kvs
                .iter()
                .all(|(k, v)| got.get(*k).is_some_and(|g| g == v))
                && got.len() == label_kvs.len();
            if labels_match {
                if let DebugValue::Counter(v) = value {
                    return *v;
                }
            }
        }
        0
    }

    /// Collect every label-key seen on `metric_name` across the
    /// snapshot. Used by the cardinality-discipline tests to prove no
    /// forbidden keys (`token_id`, `user_id`, `repo_id`,
    /// `repository_name`, `scope_string`) appear on the OCI metrics.
    fn collect_label_keys(
        snap: &[(
            CompositeKey,
            Option<metrics::Unit>,
            Option<metrics::SharedString>,
            DebugValue,
        )],
        metric_name: &str,
    ) -> BTreeSet<String> {
        let mut keys = BTreeSet::new();
        for (key, _, _, _) in snap {
            if key.key().name() == metric_name {
                for label in key.key().labels() {
                    keys.insert(label.key().to_string());
                }
            }
        }
        keys
    }

    fn ip() -> IpAddr {
        "203.0.113.42".parse().unwrap()
    }

    // -- hort_oci_v2_auth_total — failure paths ------------------------

    /// Failure-path: PAT validation fails (verifier returns false →
    /// `HashMismatch` → `map_pat_error` collapses to
    /// `InvalidCredential`). `result="invalid_credential"` MUST fire.
    #[test]
    fn oci_v2_auth_total_emits_invalid_credential_on_pat_validation_failure() {
        let snap = capture_async(|| async {
            let (uc, tokens, users, repos) = make_use_case(
                vec![(Permission::Read, None)],
                false, // verifier returns false → HashMismatch
            );
            let (plaintext, _user_id) = seed_pat_row(
                &tokens,
                &users,
                false,
                vec![Permission::Read, Permission::Write, Permission::Delete],
            );
            repos.insert(build_repo("library/nginx"));

            let res = uc
                .exchange(OciTokenExchangeRequest {
                    plaintext_pat: plaintext,
                    service: "hort.test".into(),
                    scopes: vec!["repository:library/nginx:pull".into()],
                    client_ip: Some(ip()),
                })
                .await;
            assert!(
                matches!(res, Err(OciTokenExchangeError::InvalidCredential)),
                "expected InvalidCredential error"
            );
        });
        assert_eq!(
            counter_value(
                &snap,
                "hort_oci_v2_auth_total",
                &[("result", "invalid_credential")],
            ),
            1,
            "PAT validation failure must emit result=invalid_credential"
        );
    }

    /// Failure-path: scope grammar violation produces `InvalidScope`
    /// BEFORE PAT validation runs. `result="invalid_scope"` MUST fire.
    #[test]
    fn oci_v2_auth_total_emits_invalid_scope_on_unparseable_scope() {
        let snap = capture_async(|| async {
            let (uc, _tokens, _users, _repos) = make_use_case(
                vec![(Permission::Read, None)],
                true, // irrelevant — invalid_scope short-circuits BEFORE PAT validation
            );
            let res = uc
                .exchange(OciTokenExchangeRequest {
                    plaintext_pat: "hort_pat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                    service: "hort.test".into(),
                    scopes: vec!["blob:foo:pull".into()], // unknown resource_type
                    client_ip: Some(ip()),
                })
                .await;
            assert!(
                matches!(res, Err(OciTokenExchangeError::InvalidScope { .. })),
                "expected InvalidScope error"
            );
        });
        assert_eq!(
            counter_value(
                &snap,
                "hort_oci_v2_auth_total",
                &[("result", "invalid_scope")],
            ),
            1,
            "Malformed scope must emit result=invalid_scope"
        );
    }

    // -- hort_oci_v2_auth_total — happy + grant-classification paths ---

    /// Happy path: every requested action is authorised → full_grant.
    /// Drives `exchange()` end-to-end with an admin user (so the
    /// admin short-circuit allows the user-grants leg) and a full cap
    /// (so the cap leg admits Read/Write/Delete). Single `pull` scope
    /// → 1 requested, 1 granted → `ResultLabel::FullGrant`.
    ///
    /// Previously this test went around `exchange()` because the
    /// synthetic principal carried `roles: Vec::new()` and could never
    /// reach the FullGrant arm; the fix wires
    /// `UserRepository::find_by_id` into the principal-construction
    /// step and seeds `roles: ["admin"]` from the live `is_admin` bit,
    /// making the arm reachable.
    #[test]
    fn oci_v2_auth_total_emits_full_grant_on_authorised_request() {
        let snap = capture_async(|| async {
            let (uc, tokens, users, repos) = make_use_case(vec![], true);
            // Admin user → user-leg short-circuits to allow.
            // Full cap → cap leg allows every action.
            let (plaintext, _user_id) = seed_pat_row(
                &tokens,
                &users,
                true,
                vec![Permission::Read, Permission::Write, Permission::Delete],
            );
            repos.insert(build_repo("myrepo"));

            let resp = uc
                .exchange(OciTokenExchangeRequest {
                    plaintext_pat: plaintext,
                    service: "hort.test".into(),
                    scopes: vec!["repository:myrepo:pull".into()],
                    client_ip: Some(ip()),
                })
                .await
                .expect("admin user with full cap must mint a JWT");
            // The single requested action `pull` lands in the granted
            // subset → exchange() classifies as full_grant.
            assert_eq!(resp.granted_subset.len(), 1);
            assert_eq!(resp.granted_subset[0].actions, vec!["pull".to_string()]);
        });
        assert_eq!(
            counter_value(&snap, "hort_oci_v2_auth_total", &[("result", "full_grant")],),
            1,
            "Full authorisation must emit result=full_grant"
        );
    }

    /// Partial path: some actions authorised, some not → partial_grant.
    /// Drives `exchange()` end-to-end. The shape that produces this
    /// classification through the live evaluator: admin user (so the
    /// user-leg short-circuits to allow every action) combined with a
    /// narrowed token cap (`Permission::Read` only) so the cap leg
    /// denies `Write`. Requesting `pull,push` then yields `pull`
    /// granted but `push` denied → 2 requested, 1 granted →
    /// `ResultLabel::PartialGrant`.
    ///
    /// Previously this test went around `exchange()` because the
    /// synthetic principal carried `roles: Vec::new()` and could never
    /// reach the PartialGrant arm; the fix makes it reachable by
    /// re-resolving roles from the live user row.
    #[test]
    fn oci_v2_auth_total_emits_partial_grant_when_some_actions_unauthorised() {
        let snap = capture_async(|| async {
            let (uc, tokens, users, repos) = make_use_case(vec![], true);
            // Admin user → admin short-circuits the user-leg for every
            // action. Cap is narrowed to `Read` only so the cap leg
            // denies `Write` (push).
            let (plaintext, _user_id) = seed_pat_row(&tokens, &users, true, vec![Permission::Read]);
            repos.insert(build_repo("myrepo"));

            let resp = uc
                .exchange(OciTokenExchangeRequest {
                    plaintext_pat: plaintext,
                    service: "hort.test".into(),
                    // `push` parses to `[Pull, Push]` (push implies
                    // pull), so the request totals 2 actions. With cap
                    // = [Read], pull is granted, push is denied.
                    scopes: vec!["repository:myrepo:push".into()],
                    client_ip: Some(ip()),
                })
                .await
                .expect("admin user must always mint a JWT");
            // Pull granted, push denied → partial.
            assert_eq!(resp.granted_subset.len(), 1);
            assert_eq!(resp.granted_subset[0].actions, vec!["pull".to_string()]);
        });
        assert_eq!(
            counter_value(
                &snap,
                "hort_oci_v2_auth_total",
                &[("result", "partial_grant")],
            ),
            1,
            "Subset authorisation must emit result=partial_grant"
        );
    }

    /// No-grant path: zero actions authorised → no_grant.
    #[test]
    fn oci_v2_auth_total_emits_no_grant_when_zero_actions_authorised() {
        let snap = capture_async(|| async {
            // No grants at all — every action denied. `is_admin = false`
            // so the user-leg has no admin short-circuit; with no role
            // grants either, every requested action falls to no_grant.
            let (uc, tokens, users, repos) = make_use_case(vec![], true);
            let (plaintext, _user_id) = seed_pat_row(
                &tokens,
                &users,
                false,
                vec![Permission::Read, Permission::Write, Permission::Delete],
            );
            repos.insert(build_repo("myrepo"));

            let resp = uc
                .exchange(OciTokenExchangeRequest {
                    plaintext_pat: plaintext,
                    service: "hort.test".into(),
                    scopes: vec!["repository:myrepo:pull".into()],
                    client_ip: Some(ip()),
                })
                .await
                .expect("no-grant exchange still returns 200");
            assert!(resp.granted_subset.is_empty());
        });
        assert_eq!(
            counter_value(&snap, "hort_oci_v2_auth_total", &[("result", "no_grant")],),
            1,
            "Zero authorised actions must emit result=no_grant"
        );
    }

    // -- hort_oci_v2_auth_scope_actions_granted_total ------------------

    /// Watchpoint #2: the `action` label MUST cover all three values
    /// (`pull`, `push`, `delete`). Drives `exchange()` end-to-end with
    /// an admin user + full cap requesting `pull,push,delete`; with
    /// admin short-circuiting the user-leg and the cap admitting
    /// every permission, each of the three actions lands in the
    /// granted subset and emits one increment on
    /// `hort_oci_v2_auth_scope_actions_granted_total`.
    ///
    /// Previously this test went around `exchange()` because the
    /// synthetic principal carried `roles: Vec::new()` and could
    /// never accumulate any granted actions; the fix re-resolves
    /// the user row and seeds `roles: ["admin"]` from `is_admin`,
    /// making every action reachable through `evaluate_scope`.
    #[test]
    fn oci_v2_auth_scope_actions_granted_total_emits_pull_push_delete() {
        let snap = capture_async(|| async {
            let (uc, tokens, users, repos) = make_use_case(vec![], true);
            let (plaintext, _user_id) = seed_pat_row(
                &tokens,
                &users,
                true,
                vec![Permission::Read, Permission::Write, Permission::Delete],
            );
            repos.insert(build_repo("myrepo"));

            let resp = uc
                .exchange(OciTokenExchangeRequest {
                    plaintext_pat: plaintext,
                    service: "hort.test".into(),
                    scopes: vec!["repository:myrepo:pull,push,delete".into()],
                    client_ip: Some(ip()),
                })
                .await
                .expect("admin user must mint a JWT");
            // All three actions granted (admin user-leg + full cap).
            assert_eq!(resp.granted_subset.len(), 1);
            assert_eq!(
                resp.granted_subset[0].actions,
                vec!["pull".to_string(), "push".to_string(), "delete".to_string()]
            );
        });
        for action in ["pull", "push", "delete"] {
            assert_eq!(
                counter_value(
                    &snap,
                    "hort_oci_v2_auth_scope_actions_granted_total",
                    &[("action", action)],
                ),
                1,
                "hort_oci_v2_auth_scope_actions_granted_total{{action=\"{action}\"}} \
                 must fire exactly once for the multi-action scope"
            );
        }
    }

    // -- Cardinality-discipline tests --------------------------------

    /// `hort_oci_v2_auth_total` MUST carry EXACTLY the `result` label.
    /// No `token_id`, `user_id`, `repo_id`, `repository_name`,
    /// `scope_string` slip-ins.
    #[test]
    fn oci_v2_auth_total_label_set_is_exactly_result() {
        let snap = capture_async(|| async {
            let repo = build_repo("myrepo");
            let repo_id = repo.id;
            let (uc, tokens, users, repos) =
                make_use_case(vec![(Permission::Read, Some(repo_id))], true);
            // Admin user → admin short-circuits user-leg, exercising
            // the same exchange() path the cardinality test pins.
            let (plaintext, _user_id) = seed_pat_row(
                &tokens,
                &users,
                true,
                vec![Permission::Read, Permission::Write, Permission::Delete],
            );
            repos.insert(repo);

            let _ = uc
                .exchange(OciTokenExchangeRequest {
                    plaintext_pat: plaintext,
                    service: "hort.test".into(),
                    scopes: vec!["repository:myrepo:pull".into()],
                    client_ip: Some(ip()),
                })
                .await;
        });
        let keys = collect_label_keys(&snap, "hort_oci_v2_auth_total");
        let expected: BTreeSet<String> = ["result".to_string()].into_iter().collect();
        assert_eq!(
            keys, expected,
            "hort_oci_v2_auth_total label set MUST be exactly {{result}}; got {keys:?}"
        );
        for forbidden in [
            "token_id",
            "user_id",
            "repo_id",
            "repository_name",
            "scope_string",
        ] {
            assert!(
                !keys.contains(forbidden),
                "forbidden label `{forbidden}` MUST NOT appear on hort_oci_v2_auth_total"
            );
        }
    }

    /// `hort_oci_v2_auth_scope_actions_granted_total` MUST carry
    /// EXACTLY the `action` label. Drives `exchange()` end-to-end
    /// with an admin user so the action metric actually fires through
    /// the live evaluator path.
    #[test]
    fn oci_v2_auth_scope_actions_granted_label_set_is_exactly_action() {
        let snap = capture_async(|| async {
            let (uc, tokens, users, repos) = make_use_case(vec![], true);
            let (plaintext, _user_id) = seed_pat_row(
                &tokens,
                &users,
                true,
                vec![Permission::Read, Permission::Write, Permission::Delete],
            );
            repos.insert(build_repo("myrepo"));
            let _ = uc
                .exchange(OciTokenExchangeRequest {
                    plaintext_pat: plaintext,
                    service: "hort.test".into(),
                    scopes: vec!["repository:myrepo:pull".into()],
                    client_ip: Some(ip()),
                })
                .await;
        });
        let keys = collect_label_keys(&snap, "hort_oci_v2_auth_scope_actions_granted_total");
        let expected: BTreeSet<String> = ["action".to_string()].into_iter().collect();
        assert_eq!(
            keys, expected,
            "hort_oci_v2_auth_scope_actions_granted_total label set MUST be exactly \
             {{action}}; got {keys:?}"
        );
        for forbidden in [
            "token_id",
            "user_id",
            "repo_id",
            "repository_name",
            "scope_string",
            "result",
        ] {
            assert!(
                !keys.contains(forbidden),
                "forbidden label `{forbidden}` MUST NOT appear on \
                 hort_oci_v2_auth_scope_actions_granted_total"
            );
        }
    }

    // =================================================================
    // Step-0 `service=` mismatch gate +
    // `verify_inbound` (`OciVerifyOutcome`) + `hort_oci_auth_verify_total`.
    //
    // `make_use_case` builds the config with `jwt_audience = "Hort.test"`
    // (see `OciTokenExchangeConfig::new(...)`), so the gate's expected
    // host is `Hort.test`. The required arms:
    // equal / case-difference-equal / whitespace-equal / empty-requested
    // / scheme-or-port mismatch, the `ServiceMismatch` variant, every
    // `OciVerifyOutcome` arm, and the per-arm metric.
    // =================================================================

    /// Helper: build a use case whose OCI signing key is one the test
    /// holds, so it can mint tokens to drive `verify_inbound`. Reuses
    /// `make_use_case` then swaps the key in via a fresh construction —
    /// `make_use_case`'s collaborators are all the verify path needs
    /// to ignore (verify only touches `signing_key` + `config`).
    fn make_verify_uc(signing: Arc<OciTokenSigningKey>, audience: &str) -> OciTokenExchangeUseCase {
        let (base, _t, _u, _r) = make_use_case(vec![], true);
        OciTokenExchangeUseCase {
            pat_validation: base.pat_validation,
            users: base.users,
            rbac: base.rbac,
            repo_access: base.repo_access,
            signing_key: signing,
            config: OciTokenExchangeConfig::new(
                "https://hort.test/v2/auth".into(),
                audience.to_string(),
            ),
        }
    }

    fn mint_token(signing: &OciTokenSigningKey, aud: &str, exp_offset_secs: i64) -> String {
        let claims = OciAccessClaims {
            iss: "https://hort.test/v2/auth".into(),
            sub: Uuid::from_u128(0xABCDEF),
            aud: aud.to_string(),
            exp: Utc::now() + ChronoDuration::seconds(exp_offset_secs),
            access: vec![AccessEntry {
                resource_type: "repository".into(),
                name: "foo/bar".into(),
                actions: vec!["pull".into(), "push".into()],
            }],
        };
        signing.mint(&claims).expect("mint")
    }

    // -- Step-0 service predicate ------------------------------------

    /// Exact host match → gate passes (mint proceeds). Control proving
    /// the gate is a precise equality, not a blanket reject.
    #[test]
    fn f28_exact_service_match_passes_gate() {
        let snap = capture_async(|| async {
            let (uc, tokens, users, repos) = make_use_case(vec![], true);
            let (plaintext, _u) = seed_pat_row(
                &tokens,
                &users,
                true,
                vec![Permission::Read, Permission::Write, Permission::Delete],
            );
            repos.insert(build_repo("myrepo"));
            let res = uc
                .exchange(OciTokenExchangeRequest {
                    plaintext_pat: plaintext,
                    service: "hort.test".into(),
                    scopes: vec!["repository:myrepo:pull".into()],
                    client_ip: Some(ip()),
                })
                .await;
            assert!(res.is_ok(), "exact host match must pass the service gate");
        });
        // ok on the verify axis, never service_mismatch.
        assert_eq!(
            counter_value(&snap, "hort_oci_auth_verify_total", &[("result", "ok")]),
            1
        );
        assert_eq!(
            counter_value(
                &snap,
                "hort_oci_auth_verify_total",
                &[("result", "service_mismatch")]
            ),
            0
        );
    }

    /// Case-insensitive host (RFC 3986 §3.2.2): a client echoing the
    /// challenge host with different casing must NOT 400.
    #[test]
    fn f28_case_insensitive_service_match_passes_gate() {
        let res = run_exchange_with_service("HORT.Test");
        assert!(
            res.is_ok(),
            "mixed-case echo of the configured host must NOT 400"
        );
    }

    /// Surrounding ASCII whitespace is trimmed before compare.
    #[test]
    fn f28_whitespace_trimmed_service_match_passes_gate() {
        let res = run_exchange_with_service("  hort.test  ");
        assert!(res.is_ok(), "whitespace-only difference must NOT 400");
    }

    /// Different host → `ServiceMismatch { requested, expected }`,
    /// normalized values, BEFORE PAT validation.
    #[test]
    fn f28_different_host_returns_service_mismatch() {
        let res = run_exchange_with_service("evil.example.com");
        match res {
            Err(OciTokenExchangeError::ServiceMismatch {
                requested,
                expected,
            }) => {
                assert_eq!(requested, "evil.example.com");
                assert_eq!(expected, "hort.test");
            }
            Err(other) => panic!("expected ServiceMismatch, got {other:?}"),
            Ok(_) => panic!("expected ServiceMismatch, got Ok(<minted>)"),
        }
    }

    /// Empty requested service after trim cannot equal a non-empty
    /// configured host → mismatch → 400.
    #[test]
    fn f28_empty_requested_service_is_mismatch() {
        let res = run_exchange_with_service("   ");
        assert!(matches!(
            res,
            Err(OciTokenExchangeError::ServiceMismatch { .. })
        ));
    }

    /// A `service=` carrying a scheme or port is bare-host-unequal →
    /// mismatch → 400 (NOT stripped).
    #[test]
    fn f28_scheme_or_port_in_service_is_mismatch() {
        for s in ["https://hort.test", "hort.test:5000", "http://hort.test/v2"] {
            let res = run_exchange_with_service(s);
            assert!(
                matches!(res, Err(OciTokenExchangeError::ServiceMismatch { .. })),
                "`{s}` must mismatch the bare configured host"
            );
        }
    }

    /// A service mismatch emits `hort_oci_auth_verify_total{result=service_mismatch}`
    /// exactly once and NOT `ok`/`denied`.
    #[test]
    fn f28_mismatch_emits_service_mismatch_metric_only() {
        let snap = capture_async(|| async {
            let (uc, _t, _u, _r) = make_use_case(vec![], true);
            let _ = uc
                .exchange(OciTokenExchangeRequest {
                    plaintext_pat: "hort_pat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                    service: "wrong.example.com".into(),
                    scopes: vec!["repository:myrepo:pull".into()],
                    client_ip: Some(ip()),
                })
                .await;
        });
        assert_eq!(
            counter_value(
                &snap,
                "hort_oci_auth_verify_total",
                &[("result", "service_mismatch")]
            ),
            1
        );
        assert_eq!(
            counter_value(&snap, "hort_oci_auth_verify_total", &[("result", "ok")]),
            0
        );
        assert_eq!(
            counter_value(&snap, "hort_oci_auth_verify_total", &[("result", "denied")]),
            0
        );
    }

    /// The `hort_oci_auth_verify_total` label set MUST be exactly
    /// `{result}` — no high-cardinality leakage (architect rule).
    #[test]
    fn oci_auth_verify_total_label_set_is_exactly_result() {
        let snap = capture_async(|| async {
            let (uc, _t, _u, _r) = make_use_case(vec![], true);
            let _ = uc
                .exchange(OciTokenExchangeRequest {
                    plaintext_pat: "hort_pat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                    service: "wrong.example.com".into(),
                    scopes: vec![],
                    client_ip: Some(ip()),
                })
                .await;
        });
        let keys = collect_label_keys(&snap, "hort_oci_auth_verify_total");
        let expected: BTreeSet<String> = ["result".to_string()].into_iter().collect();
        assert_eq!(
            keys, expected,
            "hort_oci_auth_verify_total label set MUST be exactly {{result}}; got {keys:?}"
        );
        for forbidden in ["service", "user_id", "repository", "requested", "expected"] {
            assert!(
                !keys.contains(forbidden),
                "forbidden label `{forbidden}` MUST NOT appear on hort_oci_auth_verify_total"
            );
        }
    }

    /// Mint-path failure (scope grammar violation, pre-PAT) emits
    /// `hort_oci_auth_verify_total{result=denied}`.
    #[test]
    fn invalid_scope_emits_denied_on_verify_axis() {
        let snap = capture_async(|| async {
            let (uc, _t, _u, _r) = make_use_case(vec![], true);
            let _ = uc
                .exchange(OciTokenExchangeRequest {
                    plaintext_pat: "hort_pat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                    service: "hort.test".into(),
                    scopes: vec!["blob:foo:pull".into()], // unknown resource_type
                    client_ip: Some(ip()),
                })
                .await;
        });
        assert_eq!(
            counter_value(&snap, "hort_oci_auth_verify_total", &[("result", "denied")]),
            1
        );
    }

    /// Mint-path PAT failure emits `denied` on the verify axis.
    #[test]
    fn invalid_credential_emits_denied_on_verify_axis() {
        let snap = capture_async(|| async {
            // verifier=false → HashMismatch → InvalidCredential.
            let (uc, tokens, users, repos) = make_use_case(vec![], false);
            let (plaintext, _u) = seed_pat_row(
                &tokens,
                &users,
                false,
                vec![Permission::Read, Permission::Write, Permission::Delete],
            );
            repos.insert(build_repo("myrepo"));
            let _ = uc
                .exchange(OciTokenExchangeRequest {
                    plaintext_pat: plaintext,
                    service: "hort.test".into(),
                    scopes: vec!["repository:myrepo:pull".into()],
                    client_ip: Some(ip()),
                })
                .await;
        });
        assert_eq!(
            counter_value(&snap, "hort_oci_auth_verify_total", &[("result", "denied")]),
            1
        );
    }

    // -- verify_inbound — every OciVerifyOutcome arm -----------------

    /// Valid ours-token → `Verified` with the byte-identical
    /// synthetic `oci-jwt:<sub>` principal + `ok` metric.
    #[test]
    fn verify_inbound_valid_token_is_verified() {
        let snap = capture_async(|| async {
            let signing = Arc::new(OciTokenSigningKey::new(
                SigningKey::generate(&mut rand::rngs::OsRng),
                None,
            ));
            let jwt = mint_token(&signing, "hort.test", 300);
            let uc = make_verify_uc(signing, "hort.test");
            match uc.verify_inbound(&jwt) {
                OciVerifyOutcome::Verified(p) => {
                    assert_eq!(p.user_id, Uuid::from_u128(0xABCDEF));
                    assert_eq!(p.username, format!("oci-jwt:{}", Uuid::from_u128(0xABCDEF)));
                    let cap = p.token_cap.expect("cap present");
                    assert!(cap.permissions.contains(&Permission::Read));
                    assert!(cap.permissions.contains(&Permission::Write));
                    assert!(cap.repository_ids.is_none());
                    assert!(p.claims.is_empty());
                    assert!(p.token_kind.is_none());
                }
                other => panic!("expected Verified, got {other:?}"),
            }
        });
        assert_eq!(
            counter_value(&snap, "hort_oci_auth_verify_total", &[("result", "ok")]),
            1
        );
    }

    /// Garbage / not-our-signature → `NotOurToken`, NO metric (it is a
    /// fall-through, not a denial).
    #[test]
    fn verify_inbound_foreign_token_is_not_our_token() {
        let snap = capture_async(|| async {
            let active = Arc::new(OciTokenSigningKey::new(
                SigningKey::generate(&mut rand::rngs::OsRng),
                None,
            ));
            let attacker =
                OciTokenSigningKey::new(SigningKey::generate(&mut rand::rngs::OsRng), None);
            let foreign = mint_token(&attacker, "hort.test", 300);
            let uc = make_verify_uc(active, "hort.test");
            assert!(matches!(
                uc.verify_inbound(&foreign),
                OciVerifyOutcome::NotOurToken
            ));
            // Structurally-bad string also → NotOurToken.
            assert!(matches!(
                uc.verify_inbound("not.a.jwt"),
                OciVerifyOutcome::NotOurToken
            ));
        });
        // Fall-through is NOT counted on the verify axis.
        assert_eq!(
            counter_value(&snap, "hort_oci_auth_verify_total", &[("result", "denied")]),
            0
        );
        assert_eq!(
            counter_value(&snap, "hort_oci_auth_verify_total", &[("result", "ok")]),
            0
        );
    }

    /// Expired ours-token → `Rejected(Expired)` + `denied` metric.
    #[test]
    fn verify_inbound_expired_token_is_rejected_expired() {
        let snap = capture_async(|| async {
            let signing = Arc::new(OciTokenSigningKey::new(
                SigningKey::generate(&mut rand::rngs::OsRng),
                None,
            ));
            let jwt = mint_token(&signing, "hort.test", -10); // already expired
            let uc = make_verify_uc(signing, "hort.test");
            assert!(matches!(
                uc.verify_inbound(&jwt),
                OciVerifyOutcome::Rejected(OciVerifyRejection::Expired)
            ));
        });
        assert_eq!(
            counter_value(&snap, "hort_oci_auth_verify_total", &[("result", "denied")]),
            1
        );
    }

    /// Ours-token minted for a different `aud` is rejected as
    /// `InvalidAudience` and emits the `denied` metric. Also proves
    /// divergence D3 — the consume side verifies against
    /// `config.jwt_audience`, never an independently re-derived host.
    #[test]
    fn verify_inbound_wrong_audience_is_rejected_invalid_audience() {
        let snap = capture_async(|| async {
            let signing = Arc::new(OciTokenSigningKey::new(
                SigningKey::generate(&mut rand::rngs::OsRng),
                None,
            ));
            // Token minted for a DIFFERENT aud than the use case config.
            let jwt = mint_token(&signing, "other.example.com", 300);
            let uc = make_verify_uc(signing, "hort.test");
            assert!(matches!(
                uc.verify_inbound(&jwt),
                OciVerifyOutcome::Rejected(OciVerifyRejection::InvalidAudience)
            ));
        });
        assert_eq!(
            counter_value(&snap, "hort_oci_auth_verify_total", &[("result", "denied")]),
            1
        );
    }

    /// `normalize_service` unit-level: trim + ascii-lowercase, bare.
    #[test]
    fn normalize_service_trims_and_lowercases() {
        assert_eq!(normalize_service("  HORT.Test "), "hort.test");
        assert_eq!(normalize_service("hort.test"), "hort.test");
        assert_eq!(normalize_service("   "), "");
        assert_eq!(normalize_service("HTTPS://HORT.TEST"), "https://hort.test");
    }

    /// Drive `exchange` with the given `service=` against the standard
    /// admin+full-cap fixture (so a passing gate yields `Ok`). Used by
    /// the service match/mismatch predicate tests above.
    fn run_exchange_with_service(
        service: &str,
    ) -> Result<OciTokenExchangeResponse, OciTokenExchangeError> {
        let service = service.to_string();
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async move {
                let (uc, tokens, users, repos) = make_use_case(vec![], true);
                let (plaintext, _u) = seed_pat_row(
                    &tokens,
                    &users,
                    true,
                    vec![Permission::Read, Permission::Write, Permission::Delete],
                );
                repos.insert(build_repo("myrepo"));
                uc.exchange(OciTokenExchangeRequest {
                    plaintext_pat: plaintext,
                    service,
                    scopes: vec!["repository:myrepo:pull".into()],
                    client_ip: Some(ip()),
                })
                .await
            })
    }
}
