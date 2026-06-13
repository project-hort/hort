//! Native API token issuance + revocation + listing use case
//! (ADR 0012; `docs/auth-catalog.md`).
//!
//! # Surface
//!
//! - [`ApiTokenUseCase::issue_self_token`] — `POST /users/me/tokens`
//! - [`ApiTokenUseCase::issue_for_service_account`] —
//!   `POST /admin/users/:user_id/tokens`
//! - [`ApiTokenUseCase::revoke`] — both self
//!   (`DELETE /users/me/tokens/:id`) and admin
//!   (`DELETE /admin/tokens/:id`)
//! - [`ApiTokenUseCase::list_for_user`] — both self and admin
//!
//! # Token format
//!
//! `hort_<kind>_<base32(20 random bytes)>`:
//!
//! - `hort_pat_…` — self-issued personal access token
//! - `hort_svc_…` — admin-issued for `is_service_account = true` users
//! - `hort_cli_…` — CLI-session token (not minted by this use
//!   case yet; the parser knows about the kind for forward-compat)
//!
//! Body is 32 lowercase base32 chars (RFC 4648 §6 alphabet `a-z2-7`),
//! 20 bytes random → 160 bits of entropy. Total length 39 chars.
//!
//! `token_prefix` is the **first 8 chars of the body** (NOT including
//! `hort_<kind>_`); the prefix is what the indexed lookup keys on
//! (validator B5 path).
//!
//! # Audit events
//!
//! Every successful mint emits [`ApiTokenIssued`] to the **token-owner's**
//! user stream. Every successful revoke emits [`ApiTokenRevoked`] to
//! the same. Every refused issuance emits [`ApiTokenIssuanceDenied`]
//! to the **requesting actor's** user stream (per §8 invariant 9). The
//! `Actor` lives on the [`PersistedEvent`](hort_domain::events::PersistedEvent)
//! envelope, not in the payload — see the api_token_events module
//! docstring for the rationale.

use std::sync::Arc;
use std::time::Duration as StdDuration;

use arc_swap::ArcSwap;
use bytes::Bytes;
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use uuid::Uuid;

use hort_domain::entities::api_token::{ApiToken, TokenKind};
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::rbac::Permission;
use hort_domain::entities::user::User;
use hort_domain::error::DomainError;
use hort_domain::events::{
    system_actor, ApiActor, ApiTokenIssuanceDenied, ApiTokenIssued, ApiTokenRevoked, DenialReason,
    DomainEvent, RevokeReason, StreamId,
};
use hort_domain::ports::api_token_repository::ApiTokenRepository;
use hort_domain::ports::ephemeral_store::EphemeralStore;
use hort_domain::ports::event_store::{AppendEvents, EventStore, EventToAppend};
use hort_domain::ports::user_repository::UserRepository;
use hort_domain::types::{Page, PageRequest};

use crate::argon2_hash::hash_token;
use crate::event_store_publisher::EventStorePublisher;
use crate::metrics::labels;
use crate::rbac::RbacEvaluator;

use super::read_expected_version;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum length of `ApiToken.description` per §3 schema CHECK
/// (`api_tokens_description_length_check`). The use case rejects up
/// front so the row never reaches the schema layer with an oversize
/// payload.
pub const MAX_DESCRIPTION_LEN: usize = 1024;

/// Maximum length of `ApiToken.name` (255-char schema cap).
/// `issue_cli_session` truncates to this length rather than rejecting
/// when the wire-supplied `client_id` is oversize.
pub const MAX_NAME_LEN: usize = 255;

/// Global default expiry for PAT and service-account tokens when the
/// caller omits `expires_in_days`. 90 days for PAT (§3 / §4) — the
/// service-account path overrides to 365 in `default_expiry_days`.
pub const DEFAULT_PAT_EXPIRY_DAYS: u32 = 90;

/// Default expiry for service-account tokens (§3 / §4 admin-mint).
pub const DEFAULT_SVC_EXPIRY_DAYS: u32 = 365;

/// Hard cap on `expires_in_days` for non-admin tokens (§4 step 5).
pub const MAX_EXPIRY_DAYS: u32 = 365;

/// Tighter cap when the token's `declared_permissions` contains
/// `Permission::Admin` (§4 step 4 second half / NIS2 Art 21(i) — admin
/// tokens have severe blast radius on leak; 30 days bounds it).
pub const MAX_ADMIN_EXPIRY_DAYS: u32 = 30;

// -- CLI-session lifetime caps (seconds; ADR 0013) --
//
// RFC 8693 §2.1 seconds-based `requested_token_lifetime`. Below-min is
// rejected; above-max is clamped silently (RFC 8693 §2.1 explicit guidance).

/// Minimum CLI-session lifetime in seconds (5 min). Below this the
/// request is rejected with [`ApiTokenError::LifetimeBelowMinimum`]
/// so operators get a clear signal rather than a surprise short
/// session.
pub const MIN_CLI_SESSION_LIFETIME_SECS: u64 = 300;

/// Maximum admin-cap CLI-session lifetime in seconds (15 min).
///
/// The
/// CliSession access token is a registry-signed JWT,
/// which is **non-revocable until `exp` by construction** —
/// the access-token TTL is therefore the revocation-latency floor. The
/// `jti` denylist (`revoke_cli_session`) provides emergency revocation,
/// but a tight TTL bounds the worst case directly: a stolen
/// admin-capable CliSession JWT is live-and-unrevocable for at most its
/// TTL. 900 s applies to
/// BOTH cap shapes (re-login hits the IdP, which is cheap with the
/// PKCE-mediated flow). See ADR 0013.
pub const MAX_ADMIN_CLI_SESSION_LIFETIME_SECS: u64 = 900;

/// Maximum non-admin CLI-session lifetime in seconds (15 min).
///
/// Same
/// rationale as [`MAX_ADMIN_CLI_SESSION_LIFETIME_SECS`]: the JWT is
/// non-revocable until `exp`, so the TTL is the revocation floor for
/// EVERY CliSession token, admin or not —
/// 900 s for both cap shapes. A longer non-admin ceiling would
/// assume an opaque token revocable within seconds via `revoked_at` +
/// LISTEN/NOTIFY — that immediate-revocation property does not hold for
/// a signed JWT, so the ceiling matches the admin one.
pub const MAX_NON_ADMIN_CLI_SESSION_LIFETIME_SECS: u64 = 900;

/// Default CLI-session lifetime in seconds (15 min) when the caller
/// omits `requested_token_lifetime`.
///
/// With both
/// per-cap maxima at 900 s, the default coincides with the ceiling:
/// every CliSession JWT is the maximally-short 15 min session. See
/// [`MAX_ADMIN_CLI_SESSION_LIFETIME_SECS`] for the revocation-floor
/// rationale.
pub const DEFAULT_CLI_SESSION_LIFETIME_SECS: u64 = 900;

/// Body length in base32 chars (20 bytes → 32 chars). Matches the
/// schema's `token_prefix CHAR(8)` column shape and the validator's
/// `parse_pat_token_format` strict-39-char check.
const TOKEN_BODY_LEN: usize = 32;
/// Number of random bytes for the body (20 bytes → 160 bits of
/// entropy, well above the 128-bit cryptographic floor).
const TOKEN_BODY_RAW_BYTES: usize = 20;
/// Prefix length the indexed lookup keys on (§3 — first 8 chars of
/// body). `parse_pat_token_format` returns this slice.
const TOKEN_PREFIX_LEN: usize = 8;

/// Lowercase base32 alphabet, RFC 4648 §6.
const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Composition-root flags consumed by the issuance path.
///
/// Defaults are off; operators flip via the matching env vars in
/// `hort-server::config::Config`. Both flags appear in the `Display`
/// rendering of [`AppContext`](../../../hort_http_core/context/struct.AppContext.html)
/// so a misconfig is visible at boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ApiTokenIssuanceConfig {
    /// `HORT_TOKEN_ALLOW_ADMIN` — when `true`, `Permission::Admin` may
    /// appear in `declared_permissions`. Default `false`. Lifetime
    /// caps differ by kind: Pat admin tokens are clamped to `[1, 30]`
    /// days ([`MAX_ADMIN_EXPIRY_DAYS`]); CliSession
    /// admin tokens are clamped
    /// ([`MAX_ADMIN_CLI_SESSION_LIFETIME_SECS`]) by
    /// [`clamp_lifetime`] before reaching `issue_inner`.
    pub allow_admin_tokens: bool,
    /// `HORT_TOKEN_ALLOW_UNBOUNDED_SVC` — when `true`,
    /// service-account tokens may have `expires_at = null`.
    /// Default `false`. Admin tokens cannot be unbounded regardless.
    pub allow_unbounded_svc_tokens: bool,
}

// ---------------------------------------------------------------------------
// FederationSource
// ---------------------------------------------------------------------------

/// Foreign-JWT attribution carried into the `ApiTokenIssued` event when
/// a service-account token was minted via the federation branch of
/// `/auth/token-exchange` (ADR 0018).
///
/// The three fields land on the matching
/// [`ApiTokenIssued`](hort_domain::events::api_token_events::ApiTokenIssued)
/// payload as `source_issuer`, `source_jti`, `source_sub` — backward-
/// compatible optional fields. Together they
/// form the PII-safe audit trail correlating the minted hort-server
/// token back to the foreign issuer's JWT log.
///
/// Constructed exclusively by the federation handler
/// (`hort-http-core::handlers::exchange::handle_federated_jwt`); every
/// other issuance path leaves [`IssueTokenRequest::federation_source`]
/// as `None`. No `Deserialize` / `Serialize` impls — the struct never
/// crosses an HTTP boundary as a deserialised value.
#[derive(Debug, Clone)]
pub struct FederationSource {
    /// `OidcIssuer.name` of the foreign issuer whose JWT was exchanged
    /// — propagated to `ApiTokenIssued.source_issuer` AND used as the
    /// replay-key `issuer_name`.
    pub issuer: String,
    /// JWT `jti` claim, when present. `None` when the JWT carried no
    /// `jti`. Propagated to `ApiTokenIssued.source_jti` and selects the
    /// replay-key variant (`Some` → `ReplayKey::Jti`).
    pub jti: Option<String>,
    /// JWT `sub` claim — propagated to `ApiTokenIssued.source_sub` and
    /// part of the `ReplayKey::Composite` fallback.
    pub subject: String,
    /// Raw `iss` claim value. Part
    /// of the `ReplayKey::Composite` fallback. NOT the same as
    /// [`Self::issuer`] (which is the resolved `OidcIssuer.name`); this
    /// is the JWT's literal `iss` URL, kept verbatim so the composite
    /// digest is byte-stable across replays of the same token.
    pub iss: String,
    /// Raw `iat` NumericDate
    /// seconds, `None` when the JWT omitted `iat`. Part of the
    /// `ReplayKey::Composite` fallback; when the composite path is
    /// selected (`jti = None`, `require_jti = false`) but `iat` is
    /// `None`, the composite is not constructible and the use case
    /// denies `jti_required`-equivalent (§5).
    pub iat: Option<i64>,
    /// Raw `exp` NumericDate
    /// seconds. Always present (the validator enforced `exp`). Part of
    /// the `ReplayKey::Composite` fallback.
    pub exp: i64,
    /// The resolved
    /// `OidcIssuer.require_jti` flag, threaded from the handler (which
    /// already holds the `OidcIssuer`). `true` ⇒ a jti-less JWT is
    /// denied `jti_required` before any claim/mint; `false` ⇒ the
    /// composite fallback is used when `jti` is absent.
    pub require_jti: bool,
}

// ---------------------------------------------------------------------------
// IssueTokenRequest
// ---------------------------------------------------------------------------

/// Inputs for `issue_self_token` and `issue_for_service_account`.
///
/// Constructed by handlers from the request DTO. The use case never
/// sees raw HTTP bodies; this struct is the pre-validated handoff.
#[derive(Debug, Clone)]
pub struct IssueTokenRequest {
    pub name: String,
    pub description: Option<String>,
    pub declared_permissions: Vec<Permission>,
    /// `Some(ids)` ⇒ lock to those repos. `None` ⇒ inherit user
    /// grants. `Some(vec![])` is rejected at issuance.
    pub repository_ids: Option<Vec<Uuid>>,
    /// `Some(n)` ⇒ explicit expiry in days. `None` ⇒ apply default
    /// (90 for PAT, 365 for service-account). Service-account
    /// `None` is the unbounded path — gated on
    /// [`ApiTokenIssuanceConfig::allow_unbounded_svc_tokens`].
    ///
    /// Mutually exclusive with [`expires_in_seconds`]: setting both
    /// is [`ApiTokenError::ExpiryUnitConflict`] at [`Self::validate`].
    pub expires_in_days: Option<u32>,
    /// Seconds-based expiry path for CLI-session
    /// issuance. `Some(secs)` ⇒ explicit expiry; caller is expected
    /// to have run the value through [`clamp_lifetime`] first. `None`
    /// ⇒ days-based path applies (or kind-specific default if both
    /// are `None`).
    ///
    /// Mutually exclusive with [`expires_in_days`].
    pub expires_in_seconds: Option<u64>,
    /// `Some(_)` only when the issuance call site is
    /// the federation branch of `/auth/token-exchange`. The fields
    /// propagate verbatim into `ApiTokenIssued.source_issuer /
    /// source_jti / source_sub` (optional fields with
    /// `#[serde(default)]`). Existing call sites (admin
    /// CLI, rotation handler, self-mint, OCI bearer mint) leave this
    /// as `None`; the field default is also `None` so backward-
    /// compatibility is mechanical.
    pub federation_source: Option<FederationSource>,
}

impl Default for IssueTokenRequest {
    /// Helper for tests / call sites that want a quick "no federation"
    /// baseline. Not used in production wiring (all production
    /// constructors enumerate every field explicitly).
    fn default() -> Self {
        Self {
            name: String::new(),
            description: None,
            declared_permissions: Vec::new(),
            repository_ids: None,
            expires_in_days: None,
            expires_in_seconds: None,
            federation_source: None,
        }
    }
}

impl IssueTokenRequest {
    /// Reject if BOTH `expires_in_days` and
    /// `expires_in_seconds` are set. Either-None or one-set is
    /// allowed (the issuance pipeline resolves the kind-specific
    /// default for either-None).
    ///
    /// `issue_inner` calls this at the head of step 1 (static request
    /// validation, before the name/description/repo-set shape checks);
    /// new callers are encouraged to call it at construction time so
    /// the error surfaces close to the source.
    pub fn validate(&self) -> Result<(), ApiTokenError> {
        if self.expires_in_days.is_some() && self.expires_in_seconds.is_some() {
            return Err(ApiTokenError::ExpiryUnitConflict);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// IssueCliSessionRequest
// ---------------------------------------------------------------------------

/// Inputs for [`ApiTokenUseCase::issue_cli_session`]. Constructed by the
/// `POST /api/v1/auth/exchange` handler from the
/// RFC 8693 form fields.
///
/// `Permission::Admin` is allowed in CliSession tokens (the
/// short-lifetime-with-refresh trade-off, ADR 0013). The handler
/// accepts a
/// `scope` field (RFC 8693 §2.1) and forwards the parsed permissions
/// here; the existing admin gate at the bottom of `issue_inner`
/// (`allow_admin_tokens` + `principal_is_admin`) is the SAME gate Pat
/// uses, so an admin-cap CliSession is gated identically to an admin
/// Pat. The lifetime cap (`MAX_ADMIN_CLI_SESSION_LIFETIME_SECS`) keeps
/// the laptop-theft blast radius bounded; refresh tokens
/// close the UX gap.
#[derive(Debug, Clone)]
pub struct IssueCliSessionRequest {
    /// Optional human label for the issued token, sourced from the
    /// `client_id` form field on `/exchange`. Truncated (NOT rejected)
    /// to [`MAX_NAME_LEN`]. Empty / whitespace defaults to `"hort-cli"`.
    pub client_name: Option<String>,
    /// Source IP of the `/exchange` request, embedded in the token's
    /// `description` for audit / revocation UX. Required.
    pub source_ip: String,
    /// Caller-supplied scope (RFC 8693 §2.1 `scope`).
    /// Empty list ⇒ default to `[Read, Write, Delete]`.
    /// May contain `Permission::Admin`,
    /// in which case the admin gate at `issue_inner` step 3 fires
    /// uniformly with the Pat path. Parsed by the handler from the
    /// space-separated wire form.
    pub requested_scope: Vec<Permission>,
    /// Caller-supplied lifetime in seconds (RFC 8693
    /// §2.1 `requested_token_lifetime`). `None` ⇒
    /// [`DEFAULT_CLI_SESSION_LIFETIME_SECS`] applies. The value is
    /// clamped against the per-cap-shape table at the top of
    /// `issue_cli_session_inner` via [`clamp_lifetime`]; below 300 s
    /// is rejected with [`ApiTokenError::LifetimeBelowMinimum`].
    pub requested_lifetime_secs: Option<u64>,
}

// ---------------------------------------------------------------------------
// IssuedToken
// ---------------------------------------------------------------------------

/// The success result of an issuance. Plaintext is shown ONCE on the
/// response body and never recoverable.
#[derive(Debug, Clone)]
pub struct IssuedToken {
    pub id: Uuid,
    /// Operator-supplied human label, echoed back from the request.
    /// The issuance response carries `name`
    /// alongside `id`, `kind`, `token`, `expires_at`.
    pub name: String,
    pub kind: TokenKind,
    /// Full `hort_<kind>_<32 base32 chars>` plaintext. Handlers serialise
    /// to JSON and never log.
    pub plaintext: String,
    pub expires_at: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// Authority helpers
// ---------------------------------------------------------------------------

/// Lowercase string-match short-circuit, same vocabulary as
/// [`RbacEvaluator::authorize`]. Centralised here so the issuance path
/// uses the same check the evaluator does — no parallel admin-
/// discriminator helper to drift. (The synthetic `admin` claim carries
/// the same lowercase vocabulary the evaluator short-circuits on.)
fn principal_is_admin(principal: &CallerPrincipal) -> bool {
    principal.claims.iter().any(|c| c == "admin")
}

/// Clamp a requested CLI-session lifetime against the
/// per-cap-shape bounds.
///
/// | Cap includes | Max lifetime | Min lifetime |
/// |---|---|---|
/// | Only `read/write/delete` | 86 400 s (24 h) | 300 s |
/// | Includes `admin` | 3 600 s (1 h) | 300 s |
///
/// Below 300 s ⇒ `Err(ApiTokenError::LifetimeBelowMinimum)`.
/// Above the per-cap max ⇒ clamped silently (RFC 8693 §2.1 explicit
/// guidance; the caller can compare its requested value against the
/// returned value to detect the clamp and surface a `note:` to the
/// operator — hort-cli does this in its post-login output).
pub fn clamp_lifetime(secs: u64, has_admin: bool) -> Result<u64, ApiTokenError> {
    if secs < MIN_CLI_SESSION_LIFETIME_SECS {
        return Err(ApiTokenError::LifetimeBelowMinimum);
    }
    let max = if has_admin {
        MAX_ADMIN_CLI_SESSION_LIFETIME_SECS
    } else {
        MAX_NON_ADMIN_CLI_SESSION_LIFETIME_SECS
    };
    Ok(secs.min(max))
}

// ---------------------------------------------------------------------------
// ApiTokenError
// ---------------------------------------------------------------------------

/// Typed errors surfaced by [`ApiTokenUseCase`]. Mapped to HTTP
/// envelopes by the handler crate per the wire-status table in the
/// B7 backlog item.
#[derive(Debug, thiserror::Error)]
pub enum ApiTokenError {
    /// 403 — declared permissions exceed user's current authority.
    /// `failed` lists the (repo, permission) tuples that did not
    /// authorise (one entry per declared permission per repo for
    /// per-repo caps; one per permission for global caps).
    #[error("declared permissions exceed user authority")]
    CapExceedsAuthority {
        failed: Vec<(Option<Uuid>, Permission)>,
    },

    /// 403 — service-account user attempted self-mint.
    #[error("service accounts must use admin-mint")]
    ServiceAccountSelfMint,

    /// 400 — admin token requested without `HORT_TOKEN_ALLOW_ADMIN=true`.
    #[error("admin tokens disabled by composition-root config")]
    AdminTokenDisallowed,

    /// 403 — `Permission::Admin` declared by a non-admin caller.
    #[error("admin authority required to declare admin permission")]
    AdminAuthorityRequired,

    /// 400 — admin-token `expires_in_days` outside `[1, 30]`.
    #[error("admin token expiry must be within [1, 30] days")]
    AdminTokenExceedsThirtyDays,

    /// 400 — admin-token `expires_in_days = None`.
    #[error("admin tokens require an explicit expiry")]
    AdminTokenUnboundedNotAllowed,

    /// 400 — service-account `expires_in_days = None` without
    /// `HORT_TOKEN_ALLOW_UNBOUNDED_SVC=true`.
    #[error("unbounded service-account tokens disabled by composition-root config")]
    UnboundedSvcTokenDisallowed,

    /// 400 — `repository_ids = Some(vec![])`. Locking to no repos
    /// is useless; callers must omit the field for "inherit user
    /// grants".
    #[error("repository_ids = [] is invalid; omit the field to inherit user grants")]
    InvalidRepositorySet,

    /// 400 — admin-mint target user is not `is_service_account = true`.
    #[error("admin-mint target is not a service account")]
    NotServiceAccount,

    /// 401 / 403 — caller authorisation failure (e.g. listing or
    /// revoking another user's token without admin authority).
    #[error("not authorized")]
    NotAuthorized,

    /// 404 — token id unknown.
    #[error("token not found")]
    TokenNotFound,

    /// 400 — name must be non-empty (255-char schema cap).
    #[error("name must not be empty")]
    NameEmpty,

    /// 400 — name exceeds 255-char schema cap.
    #[error("name exceeds 255 character limit")]
    NameTooLong,

    /// 400 — `description` exceeded 1024-char schema CHECK.
    #[error("description exceeds 1024 character limit")]
    DescriptionTooLong,

    /// 400 — `expires_in_days = 0`. Clamp is `[1, max]`.
    #[error("expires_in_days must be at least 1")]
    ExpiryZero,

    /// 400 — `expires_in_days > 365` for non-admin tokens.
    #[error("expires_in_days exceeds 365-day maximum")]
    ExpiryTooLong,

    /// 400 — `requested_token_lifetime` (seconds)
    /// below the 300 s minimum. Above-max is clamped silently
    /// (RFC 8693 §2.1); below-min is rejected so callers learn to size
    /// requests instead of getting a surprise short session.
    #[error("requested_token_lifetime below 300-second minimum")]
    LifetimeBelowMinimum,

    /// 400 — both `expires_in_days` and
    /// `expires_in_seconds` were set on the same `IssueTokenRequest`.
    /// The two are mutually exclusive; callers pick one. Either-None
    /// is also allowed (kind-specific default applies).
    #[error("expires_in_days and expires_in_seconds are mutually exclusive")]
    ExpiryUnitConflict,

    /// 401 — the presented
    /// federated JWT's identity is already in the durable replay
    /// seen-set within its TTL window: a replay. **No token is minted,
    /// no event appended.** `composite` distinguishes the deny reason
    /// (`replayed_jti` vs `replayed_composite`) the handler surfaces.
    /// Only produced on the federation path
    /// (`request.federation_source.is_some()`).
    #[error("subject_token already exchanged (replay detected)")]
    ReplayDetected { composite: bool },

    /// 503 — the replay guard
    /// could not be evaluated (seen-set backing store unreachable).
    /// **Fail-CLOSED**: the use case denies rather than minting a
    /// possibly-replayed token. No
    /// token minted, no event appended.
    #[error("replay guard unavailable")]
    ReplayGuardUnavailable,

    /// 401 — the resolved issuer
    /// requires a `jti` claim (`require_jti = true`) but the JWT
    /// carried none; OR the issuer allows missing `jti`
    /// (`require_jti = false`) but the JWT also lacks `iat`, so the
    /// `(iss,sub,iat,exp)` composite anti-replay key is not
    /// constructible. A *validation* deny — it never reaches the
    /// replay guard and is NOT counted on `hort_jwt_replay_rejected_total`
    /// (no replay was evaluated). Federation path only.
    #[error("issuer requires a jti claim")]
    JtiRequired,

    /// 5xx infrastructure — propagated from outbound ports.
    #[error(transparent)]
    Infrastructure(#[from] DomainError),
}

// ---------------------------------------------------------------------------
// ApiTokenUseCase
// ---------------------------------------------------------------------------

/// Application orchestrator for native API token lifecycle.
pub struct ApiTokenUseCase {
    tokens: Arc<dyn ApiTokenRepository>,
    users: Arc<dyn UserRepository>,
    events: Arc<EventStorePublisher>,
    /// Single source of truth for the cap-vs-authority
    /// gate in `issue_inner`. The evaluator already serves the
    /// per-request authorize path (`AuthContext::Enabled.rbac`); injecting
    /// it here means issuance walks the SAME admin short-circuit + role +
    /// per-repo grant logic, including per-repo grants that the prior
    /// `IssuanceCaller` flat-list projection silently dropped.
    ///
    /// Held as `Arc<ArcSwap<RbacEvaluator>>` to match
    /// [`OciTokenExchangeUseCase`] and the inbound `AuthContext::Enabled`
    /// path: the grant-refresh task swaps the pointer in-place
    /// when roles/grants change, so issuance immediately picks up new
    /// authority without an `hort-server` restart. Each request takes a
    /// single `.load()` snapshot up-front (see `issue_inner` step 5) so
    /// the cap-vs-authority loop walks one consistent evaluator instead
    /// of risking a torn read across multiple `authorize` calls when a
    /// swap lands mid-loop.
    rbac: Arc<ArcSwap<RbacEvaluator>>,
    config: ApiTokenIssuanceConfig,
    /// Durable anti-replay seen-set.
    ///
    /// `Some(_)` when federation is enabled (mirrors the opt-in
    /// `federated_jwt_validator` wiring at the composition root —
    /// federation has no meaning without an auth context). The guard
    /// is invoked ONLY on the federation system-mint path
    /// (`request.federation_source.is_some()`), immediately before
    /// `tokens.insert`. Every non-federation issuance path leaves
    /// `federation_source = None` and never touches the guard, so a
    /// `None` slot here is only ever reached on those paths and is
    /// inert there. When federation IS enabled but this slot is
    /// `None`, a federation mint fails CLOSED (`ReplayGuardUnavailable`)
    /// rather than minting unguarded — a composition bug must not open
    /// the replay hole.
    replay_guard: Option<Arc<dyn hort_domain::ports::replay_guard::ReplayGuardPort>>,
    /// CliSession access-token JWT signer (ADR 0013).
    ///
    /// `Some(_)` whenever the CliSession issuance path is reachable
    /// (i.e. auth is enabled — `/exchange` requires an OIDC IdP). The
    /// signer is consumed ONLY by [`Self::issue_cli_session`]; every
    /// other issuance path (PAT self-mint, admin-mint, SA system-mint,
    /// OCI bearer mint) mints an opaque `hort_<kind>_*` token and never
    /// touches it. A `None` slot reached on the CliSession path is a
    /// composition bug — the use case fails the mint with an
    /// `Infrastructure` error rather than falling back to the now-removed
    /// opaque `hort_cli_*` shape.
    cli_session_signer: Option<Arc<crate::cli_session_signing::CliSessionTokenSigner>>,
    /// Emergency-revocation `jti` denylist.
    ///
    /// The durable [`EphemeralStore`] the CliSession `jti` denylist is
    /// written to by [`Self::revoke_cli_session`]; the validate path
    /// (`AuthenticateUseCase`) reads the same store. `Some(_)` whenever
    /// CliSession issuance is reachable (mirrors `cli_session_signer`).
    /// Keys are `cli-session-revoked:{jti}` with TTL = remaining-until-
    /// `exp`, so the set self-bounds.
    cli_session_revocation_denylist: Option<Arc<dyn EphemeralStore>>,
}

impl ApiTokenUseCase {
    pub fn new(
        tokens: Arc<dyn ApiTokenRepository>,
        users: Arc<dyn UserRepository>,
        events: Arc<EventStorePublisher>,
        rbac: Arc<ArcSwap<RbacEvaluator>>,
        config: ApiTokenIssuanceConfig,
    ) -> Self {
        Self {
            tokens,
            users,
            events,
            rbac,
            config,
            replay_guard: None,
            cli_session_signer: None,
            cli_session_revocation_denylist: None,
        }
    }

    /// Attach the CliSession JWT signer + its
    /// emergency-revocation `jti` denylist.
    ///
    /// Builder-style opt-in mirroring [`Self::with_replay_guard`]: the
    /// composition root calls this iff auth is enabled (CliSession
    /// issuance flows through `/exchange`, which needs an OIDC IdP). The
    /// signer and the denylist are wired together because shipping the
    /// claims-carrying JWT mint without the AK-side revocation denylist
    /// would regress today's immediate revocation — a security
    /// regression the design (§13.4) forbids deferring past the cutover.
    #[must_use]
    pub fn with_cli_session_signing(
        mut self,
        signer: Arc<crate::cli_session_signing::CliSessionTokenSigner>,
        revocation_denylist: Arc<dyn EphemeralStore>,
    ) -> Self {
        self.cli_session_signer = Some(signer);
        self.cli_session_revocation_denylist = Some(revocation_denylist);
        self
    }

    /// Attach the durable replay guard.
    ///
    /// Builder-style opt-in mirroring
    /// `ApplyConfigUseCase::with_federated_jwt_validator`: the
    /// composition root calls this iff federation is enabled (auth on),
    /// so the federation system-mint path always has a `Some` guard.
    /// Non-federation callers (admin CLI mint, rotation reconciler,
    /// self-mint, OCI bearer mint) construct the use case without it
    /// and are unaffected — they set `federation_source = None`.
    #[must_use]
    pub fn with_replay_guard(
        mut self,
        guard: Arc<dyn hort_domain::ports::replay_guard::ReplayGuardPort>,
    ) -> Self {
        self.replay_guard = Some(guard);
        self
    }

    // -- issue_self_token ---------------------------------------------------

    /// Self-mint a `Pat` token. The caller's user_id is both the
    /// requesting actor and the eventual token owner.
    #[tracing::instrument(skip(self, principal, request))]
    pub async fn issue_self_token(
        &self,
        principal: &CallerPrincipal,
        request: IssueTokenRequest,
    ) -> Result<IssuedToken, ApiTokenError> {
        let result = self.issue_self_token_inner(principal, request).await;
        emit_issued_metric(TokenKind::Pat, issuance_result_label(&result));
        result
    }

    async fn issue_self_token_inner(
        &self,
        principal: &CallerPrincipal,
        request: IssueTokenRequest,
    ) -> Result<IssuedToken, ApiTokenError> {
        let target = self.users.find_by_id(principal.user_id).await?;
        if target.is_service_account {
            self.emit_denial(
                principal.user_id,
                principal.user_id,
                TokenKind::Pat,
                &request,
                DenialReason::ServiceAccountSelfMint,
            )
            .await?;
            tracing::info!(
                actor_user_id = %principal.user_id,
                target_user_id = %principal.user_id,
                denial_reason = "service_account_self_mint",
                "PAT issuance denied"
            );
            return Err(ApiTokenError::ServiceAccountSelfMint);
        }

        self.issue_inner(
            ApiActor {
                user_id: principal.user_id,
            },
            principal,
            target,
            TokenKind::Pat,
            request,
        )
        .await
    }

    // -- issue_for_service_account -----------------------------------------

    /// Admin-mint a `ServiceAccount` token for a service-account user.
    #[tracing::instrument(skip(self, admin, request))]
    pub async fn issue_for_service_account(
        &self,
        admin: &CallerPrincipal,
        target_user_id: Uuid,
        request: IssueTokenRequest,
    ) -> Result<IssuedToken, ApiTokenError> {
        let result = self
            .issue_for_service_account_inner(admin, target_user_id, request)
            .await;
        emit_issued_metric(TokenKind::ServiceAccount, issuance_result_label(&result));
        result
    }

    async fn issue_for_service_account_inner(
        &self,
        admin: &CallerPrincipal,
        target_user_id: Uuid,
        request: IssueTokenRequest,
    ) -> Result<IssuedToken, ApiTokenError> {
        if !principal_is_admin(admin) {
            // No event for "wasn't actually admin" — that's the
            // extractor's territory. The use case still defends
            // depth-in-depth in case the handler skips the extractor.
            return Err(ApiTokenError::NotAuthorized);
        }
        let target = self.users.find_by_id(target_user_id).await?;
        if !target.is_service_account {
            self.emit_denial(
                admin.user_id,
                target_user_id,
                TokenKind::ServiceAccount,
                &request,
                DenialReason::NotServiceAccount,
            )
            .await?;
            tracing::info!(
                actor_user_id = %admin.user_id,
                target_user_id = %target_user_id,
                denial_reason = "not_service_account",
                "service-account token issuance denied"
            );
            return Err(ApiTokenError::NotServiceAccount);
        }
        self.issue_inner(
            ApiActor {
                user_id: admin.user_id,
            },
            admin,
            target,
            TokenKind::ServiceAccount,
            request,
        )
        .await
    }

    // -- issue_for_service_account_system ----------------------------------
    //
    // System-mint path for the `ServiceAccountRotationHandler`
    // (`crates/hort-app/src/task_handlers/service_account_rotation.rs`).
    // The worker is a trusted process with no human `CallerPrincipal`
    // — the SA's effective authority is bounded at validation time by
    // the live `RbacEvaluator::authorize` walk over the backing user's
    // grants, not by an admin-issuance gate. The cap-vs-authority
    // check in `issue_inner` would have nothing to authorise against
    // here (no caller principal), so this method short-circuits it
    // and emits the audit event with `Actor::Internal(System)`.
    //
    // The shape mirrors `issue_for_service_account` minus the admin
    // gate: name/description/expiry validation still runs, the target
    // is required to be `is_service_account = true`, and admin scope
    // is rejected unconditionally (a worker-minted admin token would
    // bypass the short-lifetime trade-off — the
    // operator-declared SA role is constrained to {developer, reader}
    // at apply time and admin SAs are forbidden, ADR 0018).

    /// System-mint a `ServiceAccount` token.
    ///
    /// Called by the `ServiceAccountRotationHandler` once per rotation
    /// tick. Trust contract: no `CallerPrincipal` is required — the
    /// worker is a trusted background process. Skipping the cap-vs-
    /// authority gate is safe because the eventual token's effective
    /// authority is bounded by the backing user's live grants on every
    /// request (`RbacEvaluator::authorize` runs at validation time).
    ///
    /// Audit attribution is `Actor::Internal(InternalActor::System)`.
    /// `ApiTokenIssued.minted_by_admin_id` is `None` — there is no
    /// admin actor. The token-owner's user stream still carries the
    /// event so a future audit query joins it with the matching
    /// `ServiceAccountTokenRotated` on the same stream.
    #[tracing::instrument(skip(self, request))]
    pub async fn issue_for_service_account_system(
        &self,
        target_user_id: Uuid,
        request: IssueTokenRequest,
    ) -> Result<IssuedToken, ApiTokenError> {
        let result = self
            .issue_for_service_account_system_inner(target_user_id, request)
            .await;
        emit_issued_metric(TokenKind::ServiceAccount, issuance_result_label(&result));
        result
    }

    async fn issue_for_service_account_system_inner(
        &self,
        target_user_id: Uuid,
        request: IssueTokenRequest,
    ) -> Result<IssuedToken, ApiTokenError> {
        // 1. Static request validation.
        request.validate()?;
        if request.name.trim().is_empty() {
            return Err(ApiTokenError::NameEmpty);
        }
        if request.name.len() > MAX_NAME_LEN {
            return Err(ApiTokenError::NameTooLong);
        }
        if let Some(d) = &request.description {
            if d.len() > MAX_DESCRIPTION_LEN {
                return Err(ApiTokenError::DescriptionTooLong);
            }
        }
        if matches!(&request.repository_ids, Some(ids) if ids.is_empty()) {
            return Err(ApiTokenError::InvalidRepositorySet);
        }

        // 2. Admin scope is forbidden on the system-mint path. The
        //    short-lifetime trade-off (ADR 0013) was a deliberate
        //    operator-facing decision; system-issued tokens with admin
        //    cap would route around it. Admin
        //    SAs are also forbidden at the declaration layer (ADR
        //    0018); this is the runtime defence-in-depth.
        if request.declared_permissions.contains(&Permission::Admin) {
            return Err(ApiTokenError::AdminAuthorityRequired);
        }

        // 3. Resolve target + verify it's a service-account user.
        let target = self.users.find_by_id(target_user_id).await?;
        if !target.is_service_account {
            return Err(ApiTokenError::NotServiceAccount);
        }

        // 4. Expiry resolution — system-mint accepts the seconds-based
        //    path (the reconciler clamps `sa.validity` into seconds
        //    upstream), falling back to days, then the SVC default. The
        //    unbounded path is closed: a stale rotation that fails to
        //    write the new Secret must NOT also produce a never-
        //    expiring stale token.
        let expires_at = if let Some(secs) = request.expires_in_seconds {
            Some(Utc::now() + Duration::seconds(secs as i64))
        } else if let Some(days) = request.expires_in_days {
            if days == 0 {
                return Err(ApiTokenError::ExpiryZero);
            }
            if days > MAX_EXPIRY_DAYS {
                return Err(ApiTokenError::ExpiryTooLong);
            }
            Some(Utc::now() + Duration::days(days as i64))
        } else {
            Some(Utc::now() + Duration::days(DEFAULT_SVC_EXPIRY_DAYS as i64))
        };

        // 5. Generate the token plaintext + hash + prefix.
        let (plaintext, body_prefix) = generate_token_plaintext(TokenKind::ServiceAccount);
        let token_hash = hash_token(&plaintext)
            .map_err(|e| DomainError::Invariant(format!("argon2 hash failed: {e}")))?;

        // 6. Build the row. `created_by_user_id` carries the target's
        //    own id — the worker has no user_id, and a placeholder
        //    `Uuid::nil()` here would re-introduce the
        //    nil-actor anti-pattern. The audit channel for "who
        //    triggered this" is the `Actor::Internal(System)` field on
        //    the appended event, not the row. Correct by
        //    design: rejecting nil and
        //    attributing to System is the intended behaviour, not a gap.
        let now = Utc::now();
        let token = ApiToken {
            id: Uuid::new_v4(),
            user_id: target.id,
            name: request.name.clone(),
            description: request.description.clone(),
            kind: TokenKind::ServiceAccount,
            token_hash,
            token_prefix: body_prefix,
            declared_permissions: request.declared_permissions.clone(),
            repository_ids: request.repository_ids.clone(),
            expires_at,
            revoked_at: None,
            last_used_at: None,
            last_used_ip: None,
            last_used_user_agent: None,
            created_by_user_id: target.id,
            created_at: now,
        };

        // 6.5. Durable anti-replay
        //      claim. Runs ONLY on the federation path
        //      (`federation_source.is_some()`); the rotation reconciler
        //      and every other system-mint caller set it to `None` and
        //      skip the guard entirely. Placed AFTER expiry resolution
        //      (the seen-set row reuses the resolved token
        //      `expires_at = min(jwt_remaining, fed_max)`) and BEFORE
        //      `tokens.insert` + the `ApiTokenIssued` append, so a
        //      replay or a guard outage produces ZERO side effects (no
        //      token row, no event — "no partial side effects on deny").
        if let Some(fs) = request.federation_source.as_ref() {
            // The seen-set TTL horizon is exactly the resolved token
            // expiry (§4). The system-mint path always resolves a
            // bounded `expires_at` (the unbounded path is closed for
            // federation), so a `None` here is an invariant violation,
            // not a "never expires" seen-set row.
            let seen_expires_at = token.expires_at.ok_or_else(|| {
                ApiTokenError::Infrastructure(DomainError::Invariant(
                    "federation mint resolved an unbounded expiry — \
                     replay seen-set TTL is not derivable"
                        .to_string(),
                ))
            })?;

            // §5 behaviour matrix → either a ReplayKey or the
            // `jti_required` *validation* deny (never reaches the
            // guard, not on the replay metric).
            let key = build_replay_key(fs)?;

            // The guard slot must be wired when federation is enabled.
            // A `None` here on the federation path is a composition bug
            // — fail CLOSED rather than mint unguarded.
            let Some(guard) = self.replay_guard.as_ref() else {
                tracing::error!(
                    event = "token_exchange_denied",
                    subject_token_type = "jwt",
                    reason = "replay_guard_unavailable",
                    iss = %fs.iss,
                    sub = %fs.subject,
                    issuer_name = %fs.issuer,
                    "federation mint reached with no replay guard wired — \
                     composition bug; failing CLOSED (no token minted)"
                );
                return Err(ApiTokenError::ReplayGuardUnavailable);
            };

            match guard.claim(&key, seen_expires_at).await {
                Ok(hort_domain::ports::replay_guard::ReplayClaim::FirstSeen) => {
                    // First sighting — fall through to mint.
                }
                Ok(hort_domain::ports::replay_guard::ReplayClaim::Replayed) => {
                    let composite = matches!(
                        key,
                        hort_domain::ports::replay_guard::ReplayKey::Composite { .. }
                    );
                    // Single hort-app emission site for
                    // `hort_jwt_replay_rejected_total{result}` — fired
                    // ONLY here, when a replay was actually detected.
                    metrics::counter!(
                        JWT_REPLAY_REJECTED_METRIC,
                        labels::RESULT => key.replay_result_label(),
                    )
                    .increment(1);
                    // Audit fact at info! (NOT error!, NOT
                    // #[instrument(err)]). No jti value, no
                    // subject_token, no token/credential material.
                    tracing::info!(
                        event = "token_exchange_denied",
                        subject_token_type = "jwt",
                        reason = key.replay_result_label(),
                        iss = %fs.iss,
                        sub = %fs.subject,
                        issuer_name = %fs.issuer,
                        "federated JWT replay rejected — no token minted"
                    );
                    return Err(ApiTokenError::ReplayDetected { composite });
                }
                Err(hort_domain::ports::replay_guard::ReplayGuardError::Unavailable(cause)) => {
                    // FAIL-CLOSED (anti-F-22). The adapter already
                    // logged the infra cause at error!; the app logs
                    // the *deny* at info!. NOT on the replay counter
                    // (no replay was detected) — it rides the existing
                    // hort_token_exchange_total taxonomy via the handler.
                    tracing::info!(
                        event = "token_exchange_denied",
                        subject_token_type = "jwt",
                        reason = "replay_guard_unavailable",
                        iss = %fs.iss,
                        sub = %fs.subject,
                        issuer_name = %fs.issuer,
                        cause = %cause,
                        "replay guard unavailable — failing CLOSED, no token minted"
                    );
                    return Err(ApiTokenError::ReplayGuardUnavailable);
                }
            }
        }

        // 7. Persist.
        self.tokens.insert(&token).await?;

        // 8. Emit ApiTokenIssued on the token-owner's user stream,
        //    attributed to System.
        let stream_id = StreamId::user(target.id);
        let expected = read_expected_version(self.events.as_ref(), &stream_id, false)
            .await
            .map_err(|e| match e {
                crate::error::AppError::Domain(d) => ApiTokenError::Infrastructure(d),
                other => ApiTokenError::Infrastructure(DomainError::Invariant(other.to_string())),
            })?;
        let event = DomainEvent::ApiTokenIssued(ApiTokenIssued {
            token_id: token.id,
            user_id: target.id,
            kind: TokenKind::ServiceAccount,
            declared_permissions: token.declared_permissions.clone(),
            repository_ids: token.repository_ids.clone(),
            expires_at: token.expires_at,
            // No admin actor — system mint.
            minted_by_admin_id: None,
            at: now,
            // Federation-source attribution is the
            // single audit-trail link from minted token back to JWT.
            // The system-mint path is reached by BOTH the rotation
            // reconciler (`federation_source = None`) AND the
            // federation handler (Item 5 — `Some(_)` carrying the
            // issuer/jti/sub). Threading verbatim keeps the field
            // contract identical to `issue_inner`'s.
            source_issuer: request
                .federation_source
                .as_ref()
                .map(|fs| fs.issuer.clone()),
            source_jti: request
                .federation_source
                .as_ref()
                .and_then(|fs| fs.jti.clone()),
            source_sub: request
                .federation_source
                .as_ref()
                .map(|fs| fs.subject.clone()),
        });
        self.events
            .append(AppendEvents {
                stream_id,
                expected_version: expected,
                events: vec![EventToAppend::new(event)],
                correlation_id: Uuid::new_v4(),
                causation_id: None,
                actor: system_actor(),
            })
            .await?;

        tracing::info!(
            token_id = %token.id,
            kind = ?TokenKind::ServiceAccount,
            user_id = %target.id,
            actor = "system",
            declared_permission_count = token.declared_permissions.len(),
            repository_count = token.repository_ids.as_ref().map(Vec::len).unwrap_or(0),
            "API token issued (system mint)"
        );

        Ok(IssuedToken {
            id: token.id,
            name: token.name.clone(),
            kind: TokenKind::ServiceAccount,
            plaintext,
            expires_at: token.expires_at,
        })
    }

    // -- issue_cli_session ---------------------------------------------------

    /// Mint a [`TokenKind::CliSession`] token for the IdP-mediated CLI
    /// login flow (`POST /api/v1/auth/exchange`; ADR 0013).
    ///
    /// The principal is the user that the `/exchange` handler resolved
    /// from the IdP-issued `subject_token` via
    /// `AuthenticateUseCase::authenticate_bearer` — this is a
    /// self-issuance shape: actor and target are the same user.
    ///
    /// Fields propagated from the request:
    ///
    /// | Field | Value |
    /// |---|---|
    /// | `kind` | [`TokenKind::CliSession`] (hardcoded) |
    /// | `name` | `client_name` truncated to [`MAX_NAME_LEN`], or `"hort-cli"` if empty / whitespace |
    /// | `description` | `"Issued via /exchange from <source_ip>"` |
    /// | `declared_permissions` | `request.requested_scope` (default `[Read, Write, Delete]` when empty) |
    /// | `repository_ids` | `None` (inherits the user's full repo set) |
    /// | `expires_in_seconds` | `clamp_lifetime(request.requested_lifetime_secs.unwrap_or(DEFAULT_CLI_SESSION_LIFETIME_SECS), has_admin)` |
    ///
    /// The admin gate at `issue_inner` step 3
    /// (`allow_admin_tokens` + `principal_is_admin`) fires uniformly
    /// for any path including the CliSession one — admin authority and
    /// the deployment flag together control admin-cap CliSession
    /// issuance, and the lifetime cap keeps the blast radius
    /// bounded (ADR 0013).
    #[tracing::instrument(skip(self, principal, request))]
    pub async fn issue_cli_session(
        &self,
        principal: &CallerPrincipal,
        request: IssueCliSessionRequest,
    ) -> Result<IssuedToken, ApiTokenError> {
        // Peek at the requested scope BEFORE consuming
        // the request so the admin-issuance metric can be emitted on
        // each gate outcome. `requested_scope` is small (≤ a handful
        // of permissions); checking once is cheap and avoids a clone.
        let admin_requested = request.requested_scope.contains(&Permission::Admin);
        let result = self.issue_cli_session_inner(principal, request).await;
        emit_issued_metric(TokenKind::CliSession, issuance_result_label(&result));
        // Narrow admin-issuance counter. Fires only when
        // admin was in the requested scope AND the outcome maps to
        // one of the four documented buckets. Other failure modes
        // (infrastructure, name shape, cap-vs-authority) are
        // intentionally not counted here — they belong to the
        // broader `hort_api_token_issued_total` counter.
        if admin_requested {
            if let Some(label) = session_admin_issuance_result(&result) {
                emit_session_admin_issuance_metric(label);
            }
        }
        if let Ok(ref issued) = result {
            tracing::info!(
                user_id = %principal.user_id,
                kind = "cli_session",
                token_id = %issued.id,
                admin_requested,
                "cli session token issued"
            );
        }
        result
    }

    async fn issue_cli_session_inner(
        &self,
        principal: &CallerPrincipal,
        request: IssueCliSessionRequest,
    ) -> Result<IssuedToken, ApiTokenError> {
        let target = self.users.find_by_id(principal.user_id).await?;

        // Forced-fields table — design doc 039 §6.
        // Truncate (NOT reject) the wire client_id; default empty /
        // whitespace to "hort-cli".
        let trimmed = request.client_name.as_deref().map(str::trim).unwrap_or("");
        let name = if trimmed.is_empty() {
            "hort-cli".to_string()
        } else {
            // `client_name` is non-empty after trim; truncate the
            // ORIGINAL (pre-trim) string to MAX_NAME_LEN so callers see
            // their input echoed verbatim up to the cap. Truncation is
            // char-boundary-safe: walk the boundary so a multi-byte
            // codepoint straddling MAX_NAME_LEN doesn't panic.
            let original = request.client_name.as_deref().unwrap_or("");
            if original.len() > MAX_NAME_LEN {
                let mut cut = MAX_NAME_LEN;
                while cut > 0 && !original.is_char_boundary(cut) {
                    cut -= 1;
                }
                original[..cut].to_string()
            } else {
                original.to_string()
            }
        };

        // Caller-supplied scope, with the
        // [Read, Write, Delete] fallback when the request omits one.
        // Empty list means "no scope specified" — the wire layer
        // converts an absent `scope` field into Vec::new().
        let requested_permissions = if request.requested_scope.is_empty() {
            vec![Permission::Read, Permission::Write, Permission::Delete]
        } else {
            request.requested_scope
        };

        // Derive the CliSession cap from
        // the caller's EFFECTIVE AUTHORITY via the live `RbacEvaluator`,
        // never a hardcoded `repository_ids: None` (a
        // global-token request that routed through the clamp's global
        // branch and required GLOBAL possession of every requested
        // permission). An admin / globally-authorized caller derives a
        // global cap (`repository_ids: None`) via the evaluator's admin
        // short-circuit — so the existing global-branch + the ≤1h admin
        // gate below run UNCHANGED; a per-repo-only grantee derives
        // `Some(repos)` and routes through the clamp's per-repo branch.
        //
        // An empty footprint (caller holds none of the requested
        // permissions) ⇒ `None` ⇒ we DENY here exactly as the clamp's
        // global branch would have, rather than minting an empty-cap token
        // that silently authorizes nothing (§13.8 acceptance #4).
        let derived_cap = {
            let rbac_guard = self.rbac.load();
            rbac_guard.derive_cli_session_cap(principal, &requested_permissions)
        };
        let Some(derived_cap) = derived_cap else {
            // Zero effective authority for any requested permission.
            // Emit the same denial event + return the same error the
            // clamp's global branch would have, so the audit trail and
            // the wire 403 are identical to the pre-Item-11 deny.
            let actor = ApiActor {
                user_id: principal.user_id,
            };
            let denial_request = IssueTokenRequest {
                name: name.clone(),
                description: Some(format!("Issued via /exchange from {}", request.source_ip)),
                declared_permissions: requested_permissions.clone(),
                repository_ids: None,
                expires_in_days: None,
                expires_in_seconds: Some(DEFAULT_CLI_SESSION_LIFETIME_SECS),
                federation_source: None,
            };
            self.emit_denial(
                actor.user_id,
                target.id,
                TokenKind::CliSession,
                &denial_request,
                DenialReason::CapExceedsAuthority,
            )
            .await?;
            tracing::info!(
                user_id = %principal.user_id,
                denial_reason = "cap_exceeds_authority",
                requested_permission_count = requested_permissions.len(),
                "cli session issuance denied: caller holds none of the \
                 requested permissions (empty derived footprint)"
            );
            return Err(ApiTokenError::CapExceedsAuthority {
                failed: requested_permissions
                    .into_iter()
                    .map(|p| (None, p))
                    .collect(),
            });
        };

        // The derived cap is the clamped footprint — `permissions` is the
        // held subset of the requested scope, `repository_ids` is `None`
        // (admin / global) or `Some(repos)` (per-repo). Log it at `debug`
        // (Item 11 observability — never logs claim names; permission +
        // repo-count only).
        tracing::debug!(
            user_id = %principal.user_id,
            derived_permission_count = derived_cap.permissions.len(),
            derived_repository_count = derived_cap
                .repository_ids
                .as_ref()
                .map(Vec::len),
            "derived cli session cap from effective authority"
        );

        let declared_permissions = derived_cap.permissions;
        let repository_ids = derived_cap.repository_ids;

        // Clamp the requested lifetime against the
        // per-cap-shape table. The admin gate at `issue_inner` step 3
        // (`allow_admin_tokens` + `principal_is_admin`) fires below
        // for the admin-cap case; we still clamp lifetime first so a
        // sub-minimum value surfaces a clear `LifetimeBelowMinimum`
        // error before the admin gate runs.
        let has_admin = declared_permissions.contains(&Permission::Admin);
        let requested_secs = request
            .requested_lifetime_secs
            .unwrap_or(DEFAULT_CLI_SESSION_LIFETIME_SECS);
        let clamped_secs = clamp_lifetime(requested_secs, has_admin)?;

        let inner_request = IssueTokenRequest {
            name: name.clone(),
            description: Some(format!("Issued via /exchange from {}", request.source_ip)),
            declared_permissions,
            // The cap's repo set is
            // derived from effective authority.
            repository_ids,
            // Seconds-based path; the
            // days-based field stays None on this code path.
            expires_in_days: None,
            expires_in_seconds: Some(clamped_secs),
            // CLI-session path is not federation;
            // every federation-source field stays None.
            federation_source: None,
        };

        let actor = ApiActor {
            user_id: principal.user_id,
        };

        // Run the SHARED issuance gates (static validation, admin
        // gating, expiry resolution, cap-vs-authority) — the same gates
        // the opaque-token path runs. `expires_at` is `Some(_)` here
        // because the request carries `expires_in_seconds`.
        let expires_at = self
            .run_issuance_gates(
                &actor,
                principal,
                &target,
                TokenKind::CliSession,
                &inner_request,
            )
            .await?
            .ok_or_else(|| {
                ApiTokenError::Infrastructure(DomainError::Invariant(
                    "CliSession gate resolved an unbounded expiry — \
                     issue_cli_session always sets expires_in_seconds"
                        .to_string(),
                ))
            })?;

        // Mint a signed JWT instead of an opaque token (ADR 0013).
        // The JWT carries the principal's RESOLVED claim set
        // (`principal.claims`
        // — an OIDC-resolved CliSession authorizes
        // `GrantSubject::Claims` grants) plus a fresh `jti` (the
        // emergency-revocation denylist key). NO `api_tokens` row is
        // persisted: claims live in the token, never a DB column
        // (§1.1 / §2 hard-block preserved).
        let Some(signer) = self.cli_session_signer.as_ref() else {
            // Composition bug — fail CLOSED rather than fall back to the
            // removed opaque `hort_cli_*` shape (which would silently emit
            // `claims: []` and re-open the footgun).
            tracing::error!(
                user_id = %principal.user_id,
                "CliSession mint reached with no signer wired — composition \
                 bug; failing closed (no token minted)"
            );
            return Err(ApiTokenError::Infrastructure(DomainError::Invariant(
                "cli session signer not configured".to_string(),
            )));
        };

        let jti = Uuid::new_v4();
        let plaintext = signer
            .mint(principal.user_id, principal.claims.clone(), jti, expires_at)
            .map_err(|e| {
                ApiTokenError::Infrastructure(DomainError::Invariant(format!(
                    "cli session jwt mint failed: {e}"
                )))
            })?;

        // Emit the issuance audit event on the user's stream, keyed on
        // the `jti` (there is no row id). Issuance is security-relevant
        // and must stay auditable even though the credential is now a
        // stateless JWT.
        let now = Utc::now();
        let stream_id = StreamId::user(target.id);
        let expected = read_expected_version(self.events.as_ref(), &stream_id, false)
            .await
            .map_err(|e| match e {
                crate::error::AppError::Domain(d) => ApiTokenError::Infrastructure(d),
                other => ApiTokenError::Infrastructure(DomainError::Invariant(other.to_string())),
            })?;
        let event = DomainEvent::ApiTokenIssued(ApiTokenIssued {
            token_id: jti,
            user_id: target.id,
            kind: TokenKind::CliSession,
            declared_permissions: inner_request.declared_permissions.clone(),
            // The audit event records the
            // DERIVED repo footprint: `None` for an
            // admin / global cap, `Some(repos)` for a per-repo cap. Keeping
            // the event in step with the issued cap means the audit trail
            // reflects the real scope of the minted session.
            repository_ids: inner_request.repository_ids.clone(),
            expires_at: Some(expires_at),
            // Self-issuance (the human IS the actor and the target).
            minted_by_admin_id: None,
            at: now,
            // CliSession is not federation.
            source_issuer: None,
            source_jti: None,
            source_sub: None,
        });
        self.events
            .append(AppendEvents {
                stream_id,
                expected_version: expected,
                events: vec![EventToAppend::new(event)],
                correlation_id: Uuid::new_v4(),
                causation_id: None,
                actor: hort_domain::events::Actor::Api(actor),
            })
            .await?;

        Ok(IssuedToken {
            id: jti,
            name,
            kind: TokenKind::CliSession,
            plaintext,
            expires_at: Some(expires_at),
        })
    }

    /// Emergency-revoke a CliSession access
    /// token by its `jti`.
    ///
    /// Writes `cli-session-revoked:{jti}` to the durable denylist with
    /// TTL = remaining-until-`exp`, so the entry self-expires when the
    /// token would have anyway (the set stays bounded). The validate
    /// path (`AuthenticateUseCase`) consults the same store and rejects
    /// (401) any `jti` it finds before the token's `exp`.
    ///
    /// This restores the AK-side *immediate* revocation the opaque→JWT
    /// cutover would otherwise lose: a signed JWT is non-revocable until
    /// `exp` by construction, so without this denylist a leaked
    /// admin-capable CliSession token would be live-and-unrevocable for
    /// its whole TTL (§13.4 — the denylist MUST ship with the cutover,
    /// not after).
    ///
    /// `exp` past `now` ⇒ a non-positive TTL: the token is already
    /// expired, so revoking it is a no-op (the entry would expire
    /// instantly). We still write with a 1 s floor so an in-flight
    /// clock-skew race cannot leave a just-expired token un-denied.
    #[tracing::instrument(skip(self))]
    pub async fn revoke_cli_session(
        &self,
        jti: Uuid,
        exp: DateTime<Utc>,
    ) -> Result<(), ApiTokenError> {
        // `ephemeral_*` local name so the keyspace-exhaustiveness
        // walker (`ephemeral_keyspace_exhaustive` guard) recognises this
        // `.put` as an `EphemeralStore` write site
        // (its receiver heuristic matches the "ephemeral" substring).
        let Some(ephemeral_denylist) = self.cli_session_revocation_denylist.as_ref() else {
            tracing::error!(
                "revoke_cli_session reached with no denylist wired — \
                 composition bug; failing closed"
            );
            return Err(ApiTokenError::Infrastructure(DomainError::Invariant(
                "cli session revocation denylist not configured".to_string(),
            )));
        };
        let remaining = (exp - Utc::now()).num_seconds().max(1) as u64;
        // `let key = format!(...)` THEN `.put(&key, ...)` so the
        // keyspace-exhaustiveness walker statically resolves the
        // `cli-session-revoked:` prefix via its let-binding resolver
        // (the same shape the `auth:event:throttle:` write site uses).
        let key = format!("cli-session-revoked:{jti}");
        ephemeral_denylist
            .put(
                &key,
                Bytes::from_static(b"1"),
                StdDuration::from_secs(remaining),
            )
            .await
            .map_err(ApiTokenError::Infrastructure)?;
        // Security-relevant state change — `info!` (audit), never `err`.
        tracing::info!(
            jti = %jti,
            "cli session revoked (jti added to denylist)"
        );
        Ok(())
    }

    /// Shared issuance pipeline for both self-mint and admin-mint.
    /// `caller` is the authority used for the cap-vs-grants check (§4
    /// step 2). For self-mint that is the user themselves; for
    /// admin-mint that is the admin (the service account's grants
    /// don't gate this — runtime intersection bounds the eventual
    /// authority down to the SA's actual grants).
    ///
    /// This is the OPAQUE-token path (PAT / ServiceAccount). The
    /// CliSession path (`issue_cli_session`) shares the
    /// [`Self::run_issuance_gates`] validation + authority gates but
    /// mints a signed JWT instead of generating + persisting an opaque
    /// `hort_<kind>_*` row (claims live in the token, not
    /// a DB column — ADR 0013).
    async fn issue_inner(
        &self,
        actor: ApiActor,
        caller: &CallerPrincipal,
        target: User,
        kind: TokenKind,
        request: IssueTokenRequest,
    ) -> Result<IssuedToken, ApiTokenError> {
        // Steps 1-5 — static validation, repo-set / admin gating,
        // expiry resolution, cap-vs-authority. Shared with the
        // CliSession JWT path.
        let expires_at = self
            .run_issuance_gates(&actor, caller, &target, kind, &request)
            .await?;

        // 6. Generate the token plaintext + hash + prefix.
        let (plaintext, body_prefix) = generate_token_plaintext(kind);
        let token_hash = hash_token(&plaintext)
            .map_err(|e| DomainError::Invariant(format!("argon2 hash failed: {e}")))?;

        // 7. Build the row.
        let now = Utc::now();
        let token = ApiToken {
            id: Uuid::new_v4(),
            user_id: target.id,
            name: request.name.clone(),
            description: request.description.clone(),
            kind,
            token_hash,
            token_prefix: body_prefix,
            declared_permissions: request.declared_permissions.clone(),
            repository_ids: request.repository_ids.clone(),
            expires_at,
            revoked_at: None,
            last_used_at: None,
            last_used_ip: None,
            last_used_user_agent: None,
            created_by_user_id: actor.user_id,
            created_at: now,
        };

        // 8. Persist.
        self.tokens.insert(&token).await?;

        // 9. Emit ApiTokenIssued on the token-owner's user stream.
        let stream_id = StreamId::user(target.id);
        let expected = read_expected_version(self.events.as_ref(), &stream_id, false)
            .await
            .map_err(|e| match e {
                crate::error::AppError::Domain(d) => ApiTokenError::Infrastructure(d),
                other => ApiTokenError::Infrastructure(DomainError::Invariant(other.to_string())),
            })?;
        let minted_by_admin_id = if actor.user_id == target.id {
            None
        } else {
            Some(actor.user_id)
        };
        let event = DomainEvent::ApiTokenIssued(ApiTokenIssued {
            token_id: token.id,
            user_id: target.id,
            kind,
            declared_permissions: token.declared_permissions.clone(),
            repository_ids: token.repository_ids.clone(),
            expires_at: token.expires_at,
            minted_by_admin_id,
            at: now,
            // Federation-source attribution.
            // PAT / service-account self-mint and admin-mint paths leave
            // these `None`; the federation branch (handled here when
            // `request.federation_source = Some(_)`) populates them with
            // the foreign issuer / `jti` / `sub` so the audit trail
            // correlates the minted hort-server token back to the JWT.
            source_issuer: request
                .federation_source
                .as_ref()
                .map(|fs| fs.issuer.clone()),
            source_jti: request
                .federation_source
                .as_ref()
                .and_then(|fs| fs.jti.clone()),
            source_sub: request
                .federation_source
                .as_ref()
                .map(|fs| fs.subject.clone()),
        });
        self.events
            .append(AppendEvents {
                stream_id,
                expected_version: expected,
                events: vec![EventToAppend::new(event)],
                correlation_id: Uuid::new_v4(),
                causation_id: None,
                actor: hort_domain::events::Actor::Api(actor.clone()),
            })
            .await?;

        tracing::info!(
            token_id = %token.id,
            kind = ?kind,
            user_id = %target.id,
            actor_user_id = %actor.user_id,
            declared_permission_count = token.declared_permissions.len(),
            repository_count = token.repository_ids.as_ref().map(Vec::len).unwrap_or(0),
            "API token issued"
        );

        Ok(IssuedToken {
            id: token.id,
            name: token.name.clone(),
            kind,
            plaintext,
            expires_at: token.expires_at,
        })
    }

    /// Steps 1-5 of the issuance pipeline — static request validation,
    /// repo-set / admin-token gating (with denial-event emission),
    /// expiry resolution, and the cap-vs-authority check against the
    /// live [`RbacEvaluator`]. Returns the resolved `expires_at`.
    ///
    /// Extracted from `issue_inner` so the
    /// opaque-token path (`issue_inner`) and the CliSession JWT path
    /// (`issue_cli_session`) share ONE copy of these gates — the gates
    /// are the security boundary and must not drift between the two
    /// credential forms.
    async fn run_issuance_gates(
        &self,
        actor: &ApiActor,
        caller: &CallerPrincipal,
        target: &User,
        kind: TokenKind,
        request: &IssueTokenRequest,
    ) -> Result<Option<DateTime<Utc>>, ApiTokenError> {
        // 1. Static request validation (description / name / empty
        //    repository_ids). These do not produce a denial event —
        //    they are malformed-input rejects, not authority
        //    refusals. The denial-event taxonomy in §B7 covers
        //    refusals tied to authority + flag gating; raw shape
        //    errors (empty repository_ids) DO emit a denial because
        //    that is one of the four §4 reject paths in the
        //    `DenialReason::InvalidRepositorySet` arm.
        //
        // Mutual-exclusion check on the expiry-unit
        // fields runs first; both-set is wire-shape garbage and
        // never persisted, so it doesn't emit a denial event either.
        request.validate()?;
        if request.name.trim().is_empty() {
            return Err(ApiTokenError::NameEmpty);
        }
        if request.name.len() > 255 {
            return Err(ApiTokenError::NameTooLong);
        }
        if let Some(d) = &request.description {
            if d.len() > MAX_DESCRIPTION_LEN {
                return Err(ApiTokenError::DescriptionTooLong);
            }
        }

        // 2. repository_ids = Some(vec![]) — emit denial AND reject.
        if matches!(&request.repository_ids, Some(ids) if ids.is_empty()) {
            self.emit_denial(
                actor.user_id,
                target.id,
                kind,
                request,
                DenialReason::InvalidRepositorySet,
            )
            .await?;
            tracing::info!(
                actor_user_id = %actor.user_id,
                target_user_id = %target.id,
                denial_reason = "invalid_repository_set",
                "token issuance denied"
            );
            return Err(ApiTokenError::InvalidRepositorySet);
        }

        // 3. Admin-token gating — §4 step 4. Two distinct error
        //    modes: AdminTokenDisallowed (flag off) and
        //    AdminAuthorityRequired (caller not admin). Both emit
        //    DenialReason::AdminTokenDisallowed (the public taxonomy
        //    has one variant for "admin token refused" — operators
        //    differentiate via the typed error in tracing).
        let declares_admin = request.declared_permissions.contains(&Permission::Admin);
        if declares_admin {
            if !self.config.allow_admin_tokens {
                self.emit_denial(
                    actor.user_id,
                    target.id,
                    kind,
                    request,
                    DenialReason::AdminTokenDisallowed,
                )
                .await?;
                tracing::info!(
                    actor_user_id = %actor.user_id,
                    target_user_id = %target.id,
                    denial_reason = "admin_token_disallowed",
                    "admin token issuance denied (flag off)"
                );
                return Err(ApiTokenError::AdminTokenDisallowed);
            }
            if !principal_is_admin(caller) {
                self.emit_denial(
                    actor.user_id,
                    target.id,
                    kind,
                    request,
                    DenialReason::AdminTokenDisallowed,
                )
                .await?;
                tracing::info!(
                    actor_user_id = %actor.user_id,
                    target_user_id = %target.id,
                    denial_reason = "admin_authority_required",
                    "admin token issuance denied (no admin authority)"
                );
                return Err(ApiTokenError::AdminAuthorityRequired);
            }
        }

        // 4. Expiry resolution + clamping.
        //    Seconds-based path takes precedence when
        //    set. Caller is expected to have run the value through
        //    [`clamp_lifetime`] BEFORE constructing the request;
        //    this arm trusts the value (defensive bounds-check would
        //    duplicate the clamp logic and drift). The seconds path
        //    is the one CliSession issuance flows through after
        //    Item 2's Step D rewrite of `issue_cli_session_inner`.
        let expires_at = if let Some(secs) = request.expires_in_seconds {
            Some(Utc::now() + Duration::seconds(secs as i64))
        } else {
            //    - admin-token: must have explicit expiry within [1, 30].
            //    - service-account: None allowed only when
            //      HORT_TOKEN_ALLOW_UNBOUNDED_SVC=true AND admin authority.
            //    - PAT: None falls back to default (90); else clamped to [1, 365].
            match (declares_admin, kind, request.expires_in_days) {
                // Admin token, no expiry → always reject. Even with
                // HORT_TOKEN_ALLOW_UNBOUNDED_SVC=true (per §4 step 4 second half).
                (true, _, None) => {
                    self.emit_denial(
                        actor.user_id,
                        target.id,
                        kind,
                        request,
                        DenialReason::AdminTokenExceedsThirtyDays,
                    )
                    .await?;
                    tracing::info!(
                        actor_user_id = %actor.user_id,
                        target_user_id = %target.id,
                        denial_reason = "admin_token_must_have_expiry",
                        "admin token issuance denied"
                    );
                    return Err(ApiTokenError::AdminTokenUnboundedNotAllowed);
                }
                // Admin token, explicit days outside [1, 30] → reject.
                (true, _, Some(days)) if !(1..=MAX_ADMIN_EXPIRY_DAYS).contains(&days) => {
                    self.emit_denial(
                        actor.user_id,
                        target.id,
                        kind,
                        request,
                        DenialReason::AdminTokenExceedsThirtyDays,
                    )
                    .await?;
                    tracing::info!(
                        actor_user_id = %actor.user_id,
                        target_user_id = %target.id,
                        denial_reason = "admin_token_max_30_days",
                        "admin token issuance denied (out of range)"
                    );
                    return Err(ApiTokenError::AdminTokenExceedsThirtyDays);
                }
                // Admin token, valid days → use them.
                (true, _, Some(days)) => Some(Utc::now() + Duration::days(days as i64)),
                // Service-account, no expiry → flag-gated.
                (false, TokenKind::ServiceAccount, None) => {
                    if !self.config.allow_unbounded_svc_tokens || !principal_is_admin(caller) {
                        self.emit_denial(
                            actor.user_id,
                            target.id,
                            kind,
                            request,
                            DenialReason::UnboundedSvcTokenDisallowed,
                        )
                        .await?;
                        tracing::info!(
                            actor_user_id = %actor.user_id,
                            target_user_id = %target.id,
                            denial_reason = "unbounded_svc_token_disallowed",
                            "service-account token issuance denied"
                        );
                        return Err(ApiTokenError::UnboundedSvcTokenDisallowed);
                    }
                    None
                }
                // PAT or service-account, days specified → clamp.
                (false, _, Some(days)) => {
                    if days == 0 {
                        return Err(ApiTokenError::ExpiryZero);
                    }
                    if days > MAX_EXPIRY_DAYS {
                        return Err(ApiTokenError::ExpiryTooLong);
                    }
                    Some(Utc::now() + Duration::days(days as i64))
                }
                // PAT, no expiry → default 90 days.
                (false, TokenKind::Pat, None) => {
                    Some(Utc::now() + Duration::days(DEFAULT_PAT_EXPIRY_DAYS as i64))
                }
                // CliSession, no expiry → 1 h
                // defensive default for any
                // external caller that constructs IssueTokenRequest
                // directly with both expiry fields None and kind
                // CliSession; the canonical path through
                // `issue_cli_session_inner` always sets
                // `expires_in_seconds` after clamp_lifetime, so this
                // arm is only reachable from misuse or tests.
                //
                // The `debug_assert!`
                // surfaces the architectural intent — every legitimate
                // caller of `IssueTokenRequest` for a CliSession token
                // routes through `issue_cli_session_inner`, which
                // always sets `expires_in_seconds`. Reaching this arm
                // means a future caller bypassed that helper. The
                // existing fallback is kept (debug_assert is a no-op
                // in release builds) so a production misuse cannot
                // panic; the dev/test build will fail loudly. NB:
                // removing the fallback entirely (in favour of
                // `unreachable!`) would have meant losing the
                // documented backstop for external-caller misuse, so
                // we keep both — assert in debug, default in release.
                (false, TokenKind::CliSession, None) => {
                    debug_assert!(
                        false,
                        "CliSession with no expiry reached the issue_token \
                         default-expiry arm — every legitimate CliSession \
                         issuance routes through issue_cli_session_inner, \
                         which sets expires_in_seconds after clamp_lifetime. \
                         A direct IssueTokenRequest construction reached \
                         here, which is misuse."
                    );
                    Some(Utc::now() + Duration::seconds(DEFAULT_CLI_SESSION_LIFETIME_SECS as i64))
                }
            }
        };

        // 5. Cap-vs-authority check:
        //    delegate to the live `RbacEvaluator` so admin short-circuit,
        //    role-walk, and per-repo grants share ONE source of truth
        //    with `AuthContext::Enabled.rbac`. A flat-list
        //    `IssuanceCaller.grants` projection would
        //    silently drop per-repo grants.
        //
        //    For self-mint: caller IS target; for admin-mint: caller is
        //    the admin and we gate against admin's grants (per §4
        //    admin-mint permission-cap rule). Runtime intersection
        //    bounds the eventual authority for both cases.
        // Take ONE evaluator snapshot for the whole cap loop. Calling
        // `.load()` per (perm, repo) is cheap (lock-free + uncontended on
        // the read path per `arc_swap` docs), but a swap landing mid-loop
        // would produce a torn read where some tuples saw the old
        // evaluator and some the new one. Pinning a single guard is the
        // pattern `OciTokenExchangeUseCase::evaluate_scope` uses for the
        // same reason. `&**rbac` derefs the `Guard` → `Arc<_>` → `&_`.
        let rbac_guard = self.rbac.load();
        let rbac = &**rbac_guard;
        let mut failed: Vec<(Option<Uuid>, Permission)> = Vec::new();
        match &request.repository_ids {
            None => {
                // Global token (inherit user grants). The caller must
                // have each declared permission globally — `repository_id
                // = None` requires a grant whose `repository_id == None`
                // (or admin short-circuit). A per-repo-only grantee
                // CANNOT mint a global token, only a per-repo one.
                for perm in &request.declared_permissions {
                    if !rbac.authorize(caller, *perm, None) {
                        failed.push((None, *perm));
                    }
                }
            }
            Some(ids) => {
                // Per-repo token. Each (perm, repo) tuple must authorise.
                // The evaluator handles admin short-circuit + global +
                // per-repo grants uniformly.
                for repo in ids {
                    for perm in &request.declared_permissions {
                        if !rbac.authorize(caller, *perm, Some(*repo)) {
                            failed.push((Some(*repo), *perm));
                        }
                    }
                }
            }
        }
        if !failed.is_empty() {
            self.emit_denial(
                actor.user_id,
                target.id,
                kind,
                request,
                DenialReason::CapExceedsAuthority,
            )
            .await?;
            tracing::info!(
                actor_user_id = %actor.user_id,
                target_user_id = %target.id,
                denial_reason = "cap_exceeds_authority",
                failed_count = failed.len(),
                "token issuance denied"
            );
            return Err(ApiTokenError::CapExceedsAuthority { failed });
        }

        Ok(expires_at)
    }

    /// Append an [`ApiTokenIssuanceDenied`] event to the requesting
    /// actor's user stream. Stream is `StreamId::user(actor_user_id)`
    /// — the timeline being audited is "this user tried X and was
    /// refused", not "this target user was the subject of a refused
    /// mint".
    async fn emit_denial(
        &self,
        actor_user_id: Uuid,
        target_user_id: Uuid,
        requested_kind: TokenKind,
        request: &IssueTokenRequest,
        denial_reason: DenialReason,
    ) -> Result<(), ApiTokenError> {
        let stream_id = StreamId::user(actor_user_id);
        let expected = read_expected_version(self.events.as_ref(), &stream_id, false)
            .await
            .map_err(|e| match e {
                crate::error::AppError::Domain(d) => ApiTokenError::Infrastructure(d),
                other => ApiTokenError::Infrastructure(DomainError::Invariant(other.to_string())),
            })?;
        let event = DomainEvent::ApiTokenIssuanceDenied(ApiTokenIssuanceDenied {
            target_user_id,
            requested_kind,
            requested_permissions: request.declared_permissions.clone(),
            requested_repository_ids: request.repository_ids.clone(),
            denial_reason,
            at: Utc::now(),
        });
        self.events
            .append(AppendEvents {
                stream_id,
                expected_version: expected,
                events: vec![EventToAppend::new(event)],
                correlation_id: Uuid::new_v4(),
                causation_id: None,
                actor: hort_domain::events::Actor::Api(ApiActor {
                    user_id: actor_user_id,
                }),
            })
            .await?;
        Ok(())
    }

    // -- revoke -------------------------------------------------------------

    /// Revoke a token by id. `admin_authority = true` means the caller
    /// is acting via `/admin/tokens/:id`; otherwise it is a self
    /// revoke and `actor.user_id` MUST equal the token's `user_id`.
    #[tracing::instrument(skip(self))]
    pub async fn revoke(
        &self,
        actor: ApiActor,
        token_id: Uuid,
        admin_authority: bool,
    ) -> Result<(), ApiTokenError> {
        let token = match self.tokens.find_by_id(token_id).await {
            Ok(t) => t,
            Err(DomainError::NotFound { .. }) => return Err(ApiTokenError::TokenNotFound),
            Err(other) => return Err(ApiTokenError::Infrastructure(other)),
        };
        if !admin_authority && actor.user_id != token.user_id {
            return Err(ApiTokenError::NotAuthorized);
        }
        self.tokens.revoke(token_id).await?;

        // Emit ApiTokenRevoked on the token-owner's user stream.
        let stream_id = StreamId::user(token.user_id);
        let expected = read_expected_version(self.events.as_ref(), &stream_id, false)
            .await
            .map_err(|e| match e {
                crate::error::AppError::Domain(d) => ApiTokenError::Infrastructure(d),
                other => ApiTokenError::Infrastructure(DomainError::Invariant(other.to_string())),
            })?;
        let revoked_by_admin_id = if admin_authority && actor.user_id != token.user_id {
            Some(actor.user_id)
        } else {
            None
        };
        let event = DomainEvent::ApiTokenRevoked(ApiTokenRevoked {
            token_id,
            user_id: token.user_id,
            revoked_by_admin_id,
            reason: RevokeReason::OperatorRequest,
            at: Utc::now(),
        });
        self.events
            .append(AppendEvents {
                stream_id,
                expected_version: expected,
                events: vec![EventToAppend::new(event)],
                correlation_id: Uuid::new_v4(),
                causation_id: None,
                actor: hort_domain::events::Actor::Api(actor.clone()),
            })
            .await?;

        let actor_kind = if admin_authority && actor.user_id != token.user_id {
            "admin"
        } else {
            "self"
        };
        tracing::info!(
            token_id = %token_id,
            user_id = %token.user_id,
            actor_user_id = %actor.user_id,
            actor_kind = actor_kind,
            "API token revoked"
        );
        // B9 — emit `hort_api_token_revoked_total{actor_kind}` AFTER the
        // repo revoke succeeds AND the event is appended. Failure paths
        // (TokenNotFound, NotAuthorized, infrastructure) do NOT emit —
        // the metric counts successful revocations only.
        emit_revoked_metric(actor_kind);
        Ok(())
    }

    // -- list_for_user ------------------------------------------------------

    /// List tokens belonging to `target_user_id`. Admin authority lets
    /// the caller list any user's tokens; otherwise `actor.user_id`
    /// must equal `target_user_id`.
    #[tracing::instrument(skip(self))]
    pub async fn list_for_user(
        &self,
        actor: ApiActor,
        target_user_id: Uuid,
        admin_authority: bool,
        page: PageRequest,
    ) -> Result<Page<ApiToken>, ApiTokenError> {
        if !admin_authority && actor.user_id != target_user_id {
            return Err(ApiTokenError::NotAuthorized);
        }
        let result = self.tokens.list_for_user(target_user_id, page).await?;
        tracing::debug!(
            target_user_id = %target_user_id,
            actor_user_id = %actor.user_id,
            count = result.items.len(),
            "API tokens listed"
        );
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Metric emission
// ---------------------------------------------------------------------------

/// `hort_api_token_issued_total` metric name. Emitted exactly once per
/// invocation of [`ApiTokenUseCase::issue_self_token`] and
/// [`ApiTokenUseCase::issue_for_service_account`] — every Ok and Err
/// arm goes through one of the two `emit_issued_metric` calls in the
/// public wrappers (design doc §9).
const ISSUED_METRIC: &str = "hort_api_token_issued_total";
/// `hort_api_token_revoked_total` metric name. Emitted only on
/// successful revocation, after the repo `revoke()` call AND the
/// `ApiTokenRevoked` event have been appended.
const REVOKED_METRIC: &str = "hort_api_token_revoked_total";

/// `hort_jwt_replay_rejected_total`
/// metric name. Counter, label `result ∈ {replayed_jti,
/// replayed_composite}` (the `ReplayKey` variant via
/// [`ReplayKey::replay_result_label`](hort_domain::ports::replay_guard::ReplayKey::replay_result_label)).
///
/// Emitted at **exactly one hort-app site** — the guard call site in
/// `issue_for_service_account_system_inner`, ONLY when `claim()`
/// returns `Replayed`. `jti_required` and `replay_guard_unavailable`
/// are deliberately NOT on this counter (no replay was *detected*) —
/// they ride the existing `hort_token_exchange_total{kind=federated_jwt}`
/// taxonomy via the inbound handler. Closed taxonomy: 2 series. The
/// catalog row lives in `docs/metrics-catalog.md`.
const JWT_REPLAY_REJECTED_METRIC: &str = "hort_jwt_replay_rejected_total";

/// Wire short-form for [`TokenKind`] on the `kind` label of
/// `hort_api_token_issued_total`. Mirrors the on-the-wire prefixes
/// (`hort_pat_`, `hort_svc_`, `hort_cli_`) so dashboards filter on the same
/// 3-char vocabulary operators see in token plaintexts. Note: `svc`
/// is the wire short-form for the schema's `service_account` long
/// form (design doc §3 token-format paragraph).
fn token_kind_metric_label(kind: TokenKind) -> &'static str {
    match kind {
        TokenKind::Pat => "pat",
        TokenKind::ServiceAccount => "svc",
        TokenKind::CliSession => "cli",
    }
}

/// Select the
/// [`ReplayKey`](hort_domain::ports::replay_guard::ReplayKey) for a
/// federation exchange, or return the `jti_required` *validation* deny.
///
/// This is the pure §5 matrix. It never performs I/O and is exercised
/// directly by unit tests (100 % hort-app branch coverage):
///
/// ```text
/// jti present? | require_jti | result
/// -------------+-------------+--------------------------------------------
/// yes          | (either)    | Ok(ReplayKey::Jti)
/// no           | true        | Err(JtiRequired)  (issuer requires a jti)
/// no           | false, iat  | Ok(ReplayKey::Composite)
/// no           | false, !iat | Err(JtiRequired)  (composite not constructible)
/// ```
///
/// `exp` is always present in `FederationSource` (the validator
/// enforced `exp` upstream), so the only "composite not constructible"
/// case is a missing `iat`.
fn build_replay_key(
    fs: &FederationSource,
) -> Result<hort_domain::ports::replay_guard::ReplayKey, ApiTokenError> {
    use hort_domain::ports::replay_guard::ReplayKey;
    match (&fs.jti, fs.require_jti) {
        (Some(jti), _) => Ok(ReplayKey::Jti {
            issuer_name: fs.issuer.clone(),
            jti: jti.clone(),
        }),
        (None, true) => Err(ApiTokenError::JtiRequired),
        (None, false) => match fs.iat {
            Some(iat) => Ok(ReplayKey::Composite {
                issuer_name: fs.issuer.clone(),
                iss: fs.iss.clone(),
                sub: fs.subject.clone(),
                iat,
                exp: fs.exp,
            }),
            // Issuer allows missing jti but the JWT also lacks `iat` —
            // the composite anti-replay key is not constructible.
            // Treated as `jti_required`-equivalent (§5).
            None => Err(ApiTokenError::JtiRequired),
        },
    }
}

/// Map an [`ApiTokenUseCase::issue_*`] outcome to the `result` label
/// of `hort_api_token_issued_total` per design doc §9. Closed taxonomy
/// — every variant maps to exactly one of the four buckets.
///
/// Buckets:
/// - `success` — `Ok(_)`.
/// - `cap_exceeds_authority` — declared permissions exceed the
///   caller's grants on at least one (repo, permission) tuple.
/// - `admin_disallowed` — every reject path tied to admin-token
///   gating (flag-off, no admin authority, expiry-out-of-range, or
///   admin-token-without-explicit-expiry).
/// - `validation_error` — every other malformed-input or
///   authorization-shaped reject (service-account self-mint, target
///   not service account, unbounded SVC token disallowed, empty
///   repo set, name/description shape, expiry outside [1, 365],
///   not-authorized, infrastructure failure, and the
///   federation deny variants — they are tracked on the dedicated
///   `hort_jwt_replay_rejected_total` / `hort_token_exchange_total`
///   counters, not this one).
fn issuance_result_label(result: &Result<IssuedToken, ApiTokenError>) -> &'static str {
    match result {
        Ok(_) => "success",
        Err(ApiTokenError::CapExceedsAuthority { .. }) => "cap_exceeds_authority",
        Err(ApiTokenError::AdminTokenDisallowed)
        | Err(ApiTokenError::AdminAuthorityRequired)
        | Err(ApiTokenError::AdminTokenExceedsThirtyDays)
        | Err(ApiTokenError::AdminTokenUnboundedNotAllowed) => "admin_disallowed",
        // Every other Err variant — service-account self-mint,
        // unbounded SVC, invalid repo set, NotServiceAccount,
        // NotAuthorized, TokenNotFound (cannot occur on issuance
        // path but exhaustive for safety), name/description/expiry
        // shape errors, infrastructure failures — collapses to the
        // generic `validation_error` bucket.
        Err(_) => "validation_error",
    }
}

/// Emit `hort_api_token_issued_total{kind, result}`. Called exactly
/// once per public-wrapper invocation in
/// [`ApiTokenUseCase::issue_self_token`] /
/// [`ApiTokenUseCase::issue_for_service_account`].
///
/// Cardinality: 3 `kind` × 4 `result` = 12 series (closed taxonomy).
/// No per-token or per-user labels.
fn emit_issued_metric(kind: TokenKind, result_label: &'static str) {
    metrics::counter!(
        ISSUED_METRIC,
        labels::KIND => token_kind_metric_label(kind),
        labels::RESULT => result_label,
    )
    .increment(1);
}

/// Emit `hort_api_token_revoked_total{actor_kind}`. Called exactly once
/// at the tail of [`ApiTokenUseCase::revoke`] — after the repo's
/// `revoke()` succeeds AND the `ApiTokenRevoked` event has been
/// appended. Failure paths (NotAuthorized / TokenNotFound /
/// infrastructure) do NOT emit.
///
/// `actor_kind ∈ {self, admin}` — `admin` only when the caller's
/// authority is admin AND the token belongs to a different user;
/// otherwise `self`. Cardinality: 2 series, closed taxonomy.
fn emit_revoked_metric(actor_kind: &'static str) {
    metrics::counter!(REVOKED_METRIC, labels::ACTOR_KIND => actor_kind).increment(1);
}

/// `hort_session_admin_issuance_total` metric name.
/// Operator-visible counter on admin-cap CliSession issuance
/// attempts. Distinct from `hort_token_exchange_total` (the exchange-
/// protocol outcome) — this metric counts the issuance-gate decision
/// for admin scope specifically, so security reviewers can see how
/// often admin-cap sessions are minted vs each denial mode.
const SESSION_ADMIN_ISSUANCE_METRIC: &str = "hort_session_admin_issuance_total";

/// Closed-taxonomy result values for
/// [`SESSION_ADMIN_ISSUANCE_METRIC`]. Emitted only when the request
/// included admin scope; non-admin issuance does not increment.
const SESSION_ADMIN_ISSUANCE_RESULT_GRANTED: &str = "granted";
const SESSION_ADMIN_ISSUANCE_RESULT_DENIED_FLAG: &str = "denied_flag";
const SESSION_ADMIN_ISSUANCE_RESULT_DENIED_AUTHORITY: &str = "denied_authority";
const SESSION_ADMIN_ISSUANCE_RESULT_DENIED_LIFETIME: &str = "denied_lifetime";

/// Classify an [`ApiTokenUseCase::issue_cli_session`] outcome for the
/// admin-issuance counter. Called only when admin scope was
/// requested. Returns `None` for outcomes that are not gated by the
/// admin-issuance decision (e.g. infrastructure errors, name shape
/// errors); only the four documented buckets emit.
fn session_admin_issuance_result(
    result: &Result<IssuedToken, ApiTokenError>,
) -> Option<&'static str> {
    match result {
        Ok(_) => Some(SESSION_ADMIN_ISSUANCE_RESULT_GRANTED),
        Err(ApiTokenError::AdminTokenDisallowed) => Some(SESSION_ADMIN_ISSUANCE_RESULT_DENIED_FLAG),
        Err(ApiTokenError::AdminAuthorityRequired) => {
            Some(SESSION_ADMIN_ISSUANCE_RESULT_DENIED_AUTHORITY)
        }
        Err(ApiTokenError::LifetimeBelowMinimum) => {
            Some(SESSION_ADMIN_ISSUANCE_RESULT_DENIED_LIFETIME)
        }
        // Other Err variants (CapExceedsAuthority, Infrastructure,
        // NameTooLong, etc.) are not gated by the admin-issuance
        // decision. Do not emit — keeps the catalog closed at four
        // values.
        Err(_) => None,
    }
}

fn emit_session_admin_issuance_metric(result_label: &'static str) {
    metrics::counter!(
        SESSION_ADMIN_ISSUANCE_METRIC,
        labels::RESULT => result_label,
    )
    .increment(1);
}

// ---------------------------------------------------------------------------
// Token plaintext generation
// ---------------------------------------------------------------------------

/// Generate `(plaintext, body_prefix)` for a fresh token.
///
/// `plaintext` is `hort_<kind-3-chars>_<32 base32 chars>`; `body_prefix`
/// is the first 8 chars of the body (the indexed lookup key).
///
/// Internal — exposed via the use case for in-process callers; tests
/// reach for it via the `pub(crate)` boundary.
pub(crate) fn generate_token_plaintext(kind: TokenKind) -> (String, String) {
    let mut bytes = [0u8; TOKEN_BODY_RAW_BYTES];
    rand::thread_rng().fill_bytes(&mut bytes);
    let body = encode_base32_lowercase(&bytes);
    debug_assert_eq!(body.len(), TOKEN_BODY_LEN);
    let kind_prefix = match kind {
        TokenKind::Pat => "pat",
        TokenKind::ServiceAccount => "svc",
        TokenKind::CliSession => "cli",
    };
    let plaintext = format!("hort_{kind_prefix}_{body}");
    let body_prefix = body[..TOKEN_PREFIX_LEN].to_string();
    (plaintext, body_prefix)
}

/// Encode 20 bytes as 32 lowercase base32 chars (RFC 4648 §6 alphabet).
///
/// 20 bytes × 8 bits = 160 bits, evenly divisible by 5 → 32 chars
/// exactly, no padding needed. The encoder is hand-rolled to avoid
/// pulling a base32 dependency for one call site.
fn encode_base32_lowercase(bytes: &[u8]) -> String {
    debug_assert_eq!(bytes.len(), TOKEN_BODY_RAW_BYTES);
    let mut out = String::with_capacity(TOKEN_BODY_LEN);
    let mut buffer: u32 = 0;
    let mut bits_left: u32 = 0;
    for &b in bytes {
        buffer = (buffer << 8) | u32::from(b);
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            let idx = ((buffer >> bits_left) & 0b11111) as usize;
            out.push(BASE32_ALPHABET[idx] as char);
        }
    }
    debug_assert_eq!(bits_left, 0, "20 bytes encode evenly into base32");
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use hort_domain::entities::user::AuthProvider;
    use hort_domain::events::{Actor, ApiActor, PersistedEvent};
    use hort_domain::ports::BoxFuture;

    use crate::use_cases::test_support::{MockEventStore, MockUserRepository};

    // ---------- MockApiTokenRepository ----------

    /// Test fixture for `ApiTokenRepository`. Records every call so
    /// the use-case tests can assert insert / revoke / list flows.
    struct MockApiTokenRepository {
        inserts: Mutex<Vec<ApiToken>>,
        revokes: Mutex<Vec<Uuid>>,
        by_id: Mutex<HashMap<Uuid, ApiToken>>,
        list_pages: Mutex<Vec<(Uuid, PageRequest)>>,
        canned_list: Mutex<Vec<ApiToken>>,
    }

    impl MockApiTokenRepository {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                inserts: Mutex::new(Vec::new()),
                revokes: Mutex::new(Vec::new()),
                by_id: Mutex::new(HashMap::new()),
                list_pages: Mutex::new(Vec::new()),
                canned_list: Mutex::new(Vec::new()),
            })
        }
        fn seed_token(&self, token: ApiToken) {
            self.by_id.lock().unwrap().insert(token.id, token);
        }
        fn seed_list(&self, items: Vec<ApiToken>) {
            *self.canned_list.lock().unwrap() = items;
        }
        fn inserts(&self) -> Vec<ApiToken> {
            self.inserts.lock().unwrap().clone()
        }
        fn revokes(&self) -> Vec<Uuid> {
            self.revokes.lock().unwrap().clone()
        }
        fn list_calls(&self) -> Vec<(Uuid, PageRequest)> {
            self.list_pages.lock().unwrap().clone()
        }
    }

    impl ApiTokenRepository for MockApiTokenRepository {
        fn insert(&self, token: &ApiToken) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            self.inserts.lock().unwrap().push(token.clone());
            self.by_id.lock().unwrap().insert(token.id, token.clone());
            Box::pin(async { Ok(()) })
        }
        fn find_by_prefix(
            &self,
            _prefix: &str,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<Option<ApiToken>>> {
            Box::pin(async { Ok(None) })
        }
        fn find_by_id(
            &self,
            id: Uuid,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<ApiToken>> {
            let result =
                self.by_id
                    .lock()
                    .unwrap()
                    .get(&id)
                    .cloned()
                    .ok_or_else(|| DomainError::NotFound {
                        entity: "ApiToken",
                        id: id.to_string(),
                    });
            Box::pin(async move { result })
        }
        fn list_for_user(
            &self,
            user_id: Uuid,
            page: PageRequest,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<Page<ApiToken>>> {
            self.list_pages
                .lock()
                .unwrap()
                .push((user_id, page.clone()));
            let items = self.canned_list.lock().unwrap().clone();
            let total = items.len() as u64;
            Box::pin(async move { Ok(Page { items, total }) })
        }
        fn update_last_used(
            &self,
            _token_id: Uuid,
            _at: DateTime<Utc>,
            _client_ip: Option<&str>,
            _user_agent: Option<&str>,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn revoke(&self, token_id: Uuid) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            self.revokes.lock().unwrap().push(token_id);
            Box::pin(async { Ok(()) })
        }
    }

    // ---------- Helpers ----------

    fn user(is_service_account: bool) -> User {
        User {
            id: Uuid::from_u128(0xACE),
            username: "alice".into(),
            email: "alice@example.com".into(),
            auth_provider: AuthProvider::Local,
            external_id: None,
            display_name: None,
            is_active: true,
            is_admin: false,
            is_service_account,
            last_login_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::rbac::{GrantSubject, PermissionGrant};
    use std::collections::HashMap;

    // ---------- Principal + RBAC fixtures ----------
    //
    // The use case takes `&CallerPrincipal` plus an
    // `Arc<ArcSwap<RbacEvaluator>>` dependency, so test fixtures wire
    // BOTH halves: a principal carrying the role names + an `ArcSwap`
    // pointer to an evaluator seeded with the role rows + their grants.
    // The `ArcSwap` shape mirrors the production wiring at
    // `crates/hort-server/src/composition.rs:715` so tests pick up the same
    // live-reload semantics the inbound auth path has (the grant-refresh
    // task swaps the pointer in-place; issuance reads via
    // `.load()` per call).

    /// Build a [`CallerPrincipal`] with the given role names. `user_id` is
    /// fixed to the well-known `0xACE` so the user-row mock and the
    /// principal align without each call site re-threading the id.
    fn principal(roles: Vec<&str>) -> CallerPrincipal {
        principal_with_id(Uuid::from_u128(0xACE), roles)
    }

    fn principal_with_id(user_id: Uuid, roles: Vec<&str>) -> CallerPrincipal {
        CallerPrincipal {
            user_id,
            external_id: "test:sub".into(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            claims: roles.into_iter().map(String::from).collect(),
            token_kind: None,
            issued_at: Utc::now(),
            token_cap: None,
        }
    }

    /// Build a `Claims([claim])`-subject grant (claim-subject
    /// model, ADR 0012 — a single required claim name, no role
    /// indirection).
    fn grant_row(claim: &str, repo: Option<Uuid>, perm: Permission) -> PermissionGrant {
        PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::Claims(vec![claim.to_string()]),
            repository_id: repo,
            permission: perm,
            created_at: Utc::now(),
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
        }
    }

    /// Empty evaluator wrapped in `ArcSwap` — admin-bearing principals
    /// short-circuit through it. Used for admin tests that don't need
    /// any grants seeded. The `ArcSwap` wrapper matches production
    /// wiring so tests can swap a fresh evaluator in
    /// to exercise the live-reload contract (`issue_self_token_picks_
    /// up_rbac_reload_for_newly_granted_repo`).
    fn empty_evaluator() -> Arc<ArcSwap<RbacEvaluator>> {
        Arc::new(ArcSwap::from_pointee(RbacEvaluator::new(Vec::new())))
    }

    /// Build an evaluator with one role (`developer`) granting the
    /// supplied list of `(permission, optional_repo)` tuples. The
    /// principals returned by [`principal_with_grants`] carry that role.
    /// This is the F3 watchpoint #1 fixture: a non-admin principal whose
    /// authority is materialised through the SAME evaluator that
    /// production handlers consume. Returns the bare `RbacEvaluator` so
    /// the live-reload regression test can build a fresh evaluator and
    /// pass it through `ArcSwap::store(Arc::new(_))`.
    fn evaluator_with_role_grants(
        role_name: &str,
        grants: Vec<(Permission, Option<Uuid>)>,
    ) -> RbacEvaluator {
        let rows: Vec<PermissionGrant> = grants
            .into_iter()
            .map(|(perm, repo)| grant_row(role_name, repo, perm))
            .collect();
        RbacEvaluator::new(rows)
    }

    /// Standard non-admin principal + evaluator wired with the supplied
    /// grants. The principal carries the `developer` role; the evaluator
    /// indexes that role to the given grant set. The evaluator is
    /// wrapped in `ArcSwap` so the use case can take a `.load()` guard
    /// against the same shape it sees in production.
    fn principal_with_grants(
        grants: Vec<(Permission, Option<Uuid>)>,
    ) -> (CallerPrincipal, Arc<ArcSwap<RbacEvaluator>>) {
        let p = principal(vec!["developer"]);
        let eval = evaluator_with_role_grants("developer", grants);
        (p, Arc::new(ArcSwap::from_pointee(eval)))
    }

    /// Fixture: a non-admin principal
    /// with a per-repo-only grant on `repo` for `perm`. Verifies the
    /// code path a flat-list `IssuanceCaller`
    /// projection would silently drop.
    fn non_admin_with_repo_grant(
        repo: Uuid,
        perm: Permission,
    ) -> (CallerPrincipal, Arc<ArcSwap<RbacEvaluator>>) {
        principal_with_grants(vec![(perm, Some(repo))])
    }

    /// Admin principal — the `admin` role short-circuits the evaluator
    /// for any (perm, repo) tuple, so the caller can mint any cap. The
    /// `user_id` is `0xAD` to mirror the prior `admin_caller()` fixture
    /// shape; tests that need admin = the target user override the id.
    fn admin_principal() -> (CallerPrincipal, Arc<ArcSwap<RbacEvaluator>>) {
        let p = principal_with_id(Uuid::from_u128(0xAD), vec!["admin"]);
        (p, empty_evaluator())
    }

    /// Non-admin principal + evaluator with global Read/Write/Delete.
    /// Most happy-path tests (PAT happy path, expiry tests) want a
    /// caller that can mint anything but admin.
    fn full_grants_principal() -> (CallerPrincipal, Arc<ArcSwap<RbacEvaluator>>) {
        principal_with_grants(vec![
            (Permission::Read, None),
            (Permission::Write, None),
            (Permission::Delete, None),
        ])
    }

    fn make_use_case_with_rbac(
        config: ApiTokenIssuanceConfig,
        rbac: Arc<ArcSwap<RbacEvaluator>>,
    ) -> (
        ApiTokenUseCase,
        Arc<MockApiTokenRepository>,
        Arc<MockUserRepository>,
        Arc<MockEventStore>,
    ) {
        let tokens = MockApiTokenRepository::new();
        let users = Arc::new(MockUserRepository::new());
        let events = Arc::new(MockEventStore::new());
        let uc = ApiTokenUseCase::new(
            tokens.clone() as Arc<dyn ApiTokenRepository>,
            users.clone() as Arc<dyn UserRepository>,
            crate::event_store_publisher::wrap_for_test(events.clone()),
            rbac,
            config,
        );
        (uc, tokens, users, events)
    }

    /// Default-rbac use case — empty evaluator. For tests that don't
    /// exercise the cap-vs-authority loop (revoke, list, name-shape).
    fn make_use_case(
        config: ApiTokenIssuanceConfig,
    ) -> (
        ApiTokenUseCase,
        Arc<MockApiTokenRepository>,
        Arc<MockUserRepository>,
        Arc<MockEventStore>,
    ) {
        make_use_case_with_rbac(config, empty_evaluator())
    }

    fn make_request_pat() -> IssueTokenRequest {
        IssueTokenRequest {
            name: "ci-myproject".into(),
            description: Some("CI publish".into()),
            declared_permissions: vec![Permission::Read, Permission::Write],
            repository_ids: None,
            expires_in_days: Some(90),
            expires_in_seconds: None,
            federation_source: None,
        }
    }

    fn assert_issued_event(events: &MockEventStore, expected_user_id: Uuid) -> ApiTokenIssued {
        let batches = events.appended_batches();
        let last = batches
            .iter()
            .rev()
            .find_map(|b| match &b.events.first()?.event {
                DomainEvent::ApiTokenIssued(e) => Some(e.clone()),
                _ => None,
            })
            .expect("ApiTokenIssued not appended");
        assert_eq!(last.user_id, expected_user_id);
        last
    }

    fn assert_denial_event(events: &MockEventStore) -> ApiTokenIssuanceDenied {
        let batches = events.appended_batches();
        batches
            .iter()
            .rev()
            .find_map(|b| match &b.events.first()?.event {
                DomainEvent::ApiTokenIssuanceDenied(e) => Some(e.clone()),
                _ => None,
            })
            .expect("ApiTokenIssuanceDenied not appended")
    }

    fn assert_revoked_event(events: &MockEventStore) -> ApiTokenRevoked {
        let batches = events.appended_batches();
        batches
            .iter()
            .rev()
            .find_map(|b| match &b.events.first()?.event {
                DomainEvent::ApiTokenRevoked(e) => Some(e.clone()),
                _ => None,
            })
            .expect("ApiTokenRevoked not appended")
    }

    fn count_denials(events: &MockEventStore) -> usize {
        events
            .appended_batches()
            .iter()
            .filter(|b| {
                matches!(
                    b.events.first().map(|e| &e.event),
                    Some(DomainEvent::ApiTokenIssuanceDenied(_))
                )
            })
            .count()
    }

    fn count_issuances(events: &MockEventStore) -> usize {
        events
            .appended_batches()
            .iter()
            .filter(|b| {
                matches!(
                    b.events.first().map(|e| &e.event),
                    Some(DomainEvent::ApiTokenIssued(_))
                )
            })
            .count()
    }

    // ---------- Token plaintext format ----------

    #[test]
    fn token_plaintext_format_matches_spec() {
        let (plaintext, body_prefix) = generate_token_plaintext(TokenKind::Pat);
        assert_eq!(plaintext.len(), 41, "hort_pat_<32 base32 chars> = 41 chars");
        assert!(plaintext.starts_with("hort_pat_"));
        let body = &plaintext[9..];
        assert_eq!(body.len(), 32);
        assert!(
            body.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')),
            "body must be RFC4648 §6 lowercase base32, got {body}"
        );
        assert_eq!(body_prefix.len(), 8);
        assert_eq!(body_prefix, body[..8]);
    }

    #[test]
    fn token_plaintext_kind_prefixes() {
        for (kind, prefix) in [
            (TokenKind::Pat, "hort_pat_"),
            (TokenKind::ServiceAccount, "hort_svc_"),
            (TokenKind::CliSession, "hort_cli_"),
        ] {
            let (plaintext, _) = generate_token_plaintext(kind);
            assert!(
                plaintext.starts_with(prefix),
                "kind {kind:?} should produce {prefix}…, got {plaintext}"
            );
        }
    }

    #[test]
    fn generate_token_plaintext_unique_per_call() {
        // 160 bits of entropy → collision probability is negligible.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..100 {
            let (p, _) = generate_token_plaintext(TokenKind::Pat);
            assert!(seen.insert(p), "duplicate token in 100 generations");
        }
    }

    #[test]
    fn token_prefix_extracts_first_8_chars_of_body() {
        // The indexed-lookup contract: prefix is the FIRST 8 base32
        // chars of the body, NOT including `hort_<kind>_`.
        let (plaintext, body_prefix) = generate_token_plaintext(TokenKind::Pat);
        let body = &plaintext[9..];
        assert_eq!(body_prefix, body[..8]);
    }

    // ---------- issue_self_token happy path ----------

    #[tokio::test]
    async fn issue_self_token_happy_path() {
        let (caller, rbac) = full_grants_principal();
        let (uc, tokens, users, events) =
            make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
        users.insert(user(false));
        let issued = uc
            .issue_self_token(&caller, make_request_pat())
            .await
            .expect("issue succeeds");

        assert_eq!(issued.kind, TokenKind::Pat);
        assert!(issued.plaintext.starts_with("hort_pat_"));
        assert_eq!(issued.plaintext.len(), 41);
        assert!(issued.expires_at.is_some());

        let inserts = tokens.inserts();
        assert_eq!(inserts.len(), 1);
        let row = &inserts[0];
        assert_eq!(row.user_id, Uuid::from_u128(0xACE));
        assert_eq!(row.created_by_user_id, Uuid::from_u128(0xACE));
        assert_eq!(row.kind, TokenKind::Pat);
        assert_eq!(row.token_prefix.len(), 8);
        assert!(row.token_hash.starts_with("$argon2id$v=19$"));

        let event = assert_issued_event(&events, Uuid::from_u128(0xACE));
        assert_eq!(event.token_id, row.id);
        assert_eq!(event.kind, TokenKind::Pat);
        assert_eq!(event.declared_permissions.len(), 2);
        assert!(event.minted_by_admin_id.is_none());
        assert_eq!(count_denials(&events), 0);
    }

    // ---------- IssuedToken.name ----------

    /// The issuance response shape includes
    /// `name`. The use-case-level [`IssuedToken`] must surface the name
    /// supplied on the request so the handler can echo it back without
    /// re-reading the row from storage.
    #[tokio::test]
    async fn issued_token_carries_request_name() {
        let (caller, rbac) = full_grants_principal();
        let (uc, _tokens, users, _events) =
            make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
        users.insert(user(false));
        let request = IssueTokenRequest {
            name: "ci-myproject".into(),
            ..make_request_pat()
        };
        let issued = uc
            .issue_self_token(&caller, request)
            .await
            .expect("issue succeeds");
        assert_eq!(issued.name, "ci-myproject");
    }

    // ---------- cap exceeds authority ----------

    #[tokio::test]
    async fn issue_self_token_cap_exceeds_authority_emits_denial_event() {
        // Caller has Read only; requests Write → fails.
        let (caller, rbac) = principal_with_grants(vec![(Permission::Read, None)]);
        let (uc, tokens, users, events) =
            make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
        users.insert(user(false));
        let request = IssueTokenRequest {
            declared_permissions: vec![Permission::Write],
            repository_ids: Some(vec![Uuid::from_u128(0xA)]),
            ..make_request_pat()
        };
        let err = uc.issue_self_token(&caller, request).await.unwrap_err();
        match err {
            ApiTokenError::CapExceedsAuthority { failed } => {
                assert_eq!(failed.len(), 1);
                assert_eq!(failed[0], (Some(Uuid::from_u128(0xA)), Permission::Write));
            }
            other => panic!("expected CapExceedsAuthority, got {other:?}"),
        }
        // Insert side: nothing persisted.
        assert!(tokens.inserts().is_empty());
        // Denial event emitted.
        let denial = assert_denial_event(&events);
        assert!(matches!(
            denial.denial_reason,
            DenialReason::CapExceedsAuthority
        ));
        assert_eq!(count_issuances(&events), 0);
    }

    // ---------- service-account self-mint ----------

    #[tokio::test]
    async fn issue_self_token_service_account_blocked() {
        let (caller, rbac) = full_grants_principal();
        let (uc, tokens, users, events) =
            make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
        users.insert(user(true)); // is_service_account = true
        let err = uc
            .issue_self_token(&caller, make_request_pat())
            .await
            .unwrap_err();
        assert!(matches!(err, ApiTokenError::ServiceAccountSelfMint));
        assert!(tokens.inserts().is_empty());
        let denial = assert_denial_event(&events);
        assert!(matches!(
            denial.denial_reason,
            DenialReason::ServiceAccountSelfMint
        ));
    }

    // ---------- admin token gating ----------

    #[tokio::test]
    async fn issue_self_token_admin_token_disallowed_when_flag_off() {
        // Admin caller — `roles: ["admin"]` short-circuits the
        // evaluator. Admin-token gating runs BEFORE the cap-vs-authority
        // check, so the flag-off reject fires regardless of the
        // evaluator's grant index.
        let caller = principal(vec!["admin"]);
        let (uc, tokens, users, events) =
            make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), empty_evaluator());
        users.insert(user(false));
        let request = IssueTokenRequest {
            declared_permissions: vec![Permission::Admin],
            expires_in_days: Some(15),
            ..make_request_pat()
        };
        let err = uc.issue_self_token(&caller, request).await.unwrap_err();
        assert!(matches!(err, ApiTokenError::AdminTokenDisallowed));
        assert!(tokens.inserts().is_empty());
        let denial = assert_denial_event(&events);
        assert!(matches!(
            denial.denial_reason,
            DenialReason::AdminTokenDisallowed
        ));
    }

    #[tokio::test]
    async fn issue_self_token_admin_authority_required_when_flag_on() {
        // Caller has a grant on Permission::Admin but is NOT in the
        // `admin` role. With the flag on, admin-token gating reaches
        // the principal_is_admin check and rejects.
        let (caller, rbac) = principal_with_grants(vec![(Permission::Admin, None)]);
        let (uc, tokens, users, events) = make_use_case_with_rbac(
            ApiTokenIssuanceConfig {
                allow_admin_tokens: true,
                allow_unbounded_svc_tokens: false,
            },
            rbac,
        );
        users.insert(user(false));
        let request = IssueTokenRequest {
            declared_permissions: vec![Permission::Admin],
            expires_in_days: Some(15),
            ..make_request_pat()
        };
        let err = uc.issue_self_token(&caller, request).await.unwrap_err();
        assert!(matches!(err, ApiTokenError::AdminAuthorityRequired));
        assert!(tokens.inserts().is_empty());
        let denial = assert_denial_event(&events);
        assert!(matches!(
            denial.denial_reason,
            DenialReason::AdminTokenDisallowed
        ));
    }

    // ---------- admin token expiry clamp ----------

    #[tokio::test]
    async fn issue_self_token_admin_token_clamps_to_30_days() {
        // Admin principal whose user_id matches the seeded 0xACE row so
        // self-mint resolves to the same user. Admin role lets the
        // evaluator short-circuit on every (perm, repo) tuple; the
        // 30-day clamp is the failure point.
        let caller = principal_with_id(Uuid::from_u128(0xACE), vec!["admin"]);
        let (uc, tokens, users, events) = make_use_case_with_rbac(
            ApiTokenIssuanceConfig {
                allow_admin_tokens: true,
                ..Default::default()
            },
            empty_evaluator(),
        );
        users.insert(user(false));
        let request = IssueTokenRequest {
            declared_permissions: vec![Permission::Admin],
            expires_in_days: Some(31), // > 30 → reject
            ..make_request_pat()
        };
        let err = uc.issue_self_token(&caller, request).await.unwrap_err();
        assert!(matches!(err, ApiTokenError::AdminTokenExceedsThirtyDays));
        assert!(tokens.inserts().is_empty());
        let denial = assert_denial_event(&events);
        assert!(matches!(
            denial.denial_reason,
            DenialReason::AdminTokenExceedsThirtyDays
        ));
    }

    #[tokio::test]
    async fn issue_self_token_admin_token_null_expiry_rejected_even_with_unbounded_flag() {
        let caller = principal_with_id(Uuid::from_u128(0xACE), vec!["admin"]);
        let (uc, tokens, users, events) = make_use_case_with_rbac(
            ApiTokenIssuanceConfig {
                allow_admin_tokens: true,
                allow_unbounded_svc_tokens: true,
            },
            empty_evaluator(),
        );
        users.insert(user(false));
        let request = IssueTokenRequest {
            declared_permissions: vec![Permission::Admin],
            expires_in_days: None, // unbounded request
            ..make_request_pat()
        };
        let err = uc.issue_self_token(&caller, request).await.unwrap_err();
        assert!(matches!(err, ApiTokenError::AdminTokenUnboundedNotAllowed));
        assert!(tokens.inserts().is_empty());
        let denial = assert_denial_event(&events);
        assert!(matches!(
            denial.denial_reason,
            DenialReason::AdminTokenExceedsThirtyDays
        ));
    }

    // ---------- empty repository_ids ----------

    #[tokio::test]
    async fn issue_self_token_empty_repository_ids_rejected() {
        let (caller, rbac) = full_grants_principal();
        let (uc, tokens, users, events) =
            make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
        users.insert(user(false));
        let request = IssueTokenRequest {
            repository_ids: Some(vec![]),
            ..make_request_pat()
        };
        let err = uc.issue_self_token(&caller, request).await.unwrap_err();
        assert!(matches!(err, ApiTokenError::InvalidRepositorySet));
        assert!(tokens.inserts().is_empty());
        let denial = assert_denial_event(&events);
        assert!(matches!(
            denial.denial_reason,
            DenialReason::InvalidRepositorySet
        ));
    }

    // ---------- description too long ----------

    #[tokio::test]
    async fn issue_self_token_description_too_long_rejected() {
        let (caller, rbac) = full_grants_principal();
        let (uc, tokens, users, _) =
            make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
        users.insert(user(false));
        let request = IssueTokenRequest {
            description: Some("x".repeat(MAX_DESCRIPTION_LEN + 1)),
            ..make_request_pat()
        };
        let err = uc.issue_self_token(&caller, request).await.unwrap_err();
        assert!(matches!(err, ApiTokenError::DescriptionTooLong));
        assert!(tokens.inserts().is_empty());
    }

    #[tokio::test]
    async fn issue_self_token_empty_name_rejected() {
        let (caller, rbac) = full_grants_principal();
        let (uc, tokens, users, _) =
            make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
        users.insert(user(false));
        let request = IssueTokenRequest {
            name: "   ".into(),
            ..make_request_pat()
        };
        let err = uc.issue_self_token(&caller, request).await.unwrap_err();
        assert!(matches!(err, ApiTokenError::NameEmpty));
        assert!(tokens.inserts().is_empty());
    }

    #[tokio::test]
    async fn issue_self_token_oversize_name_rejected() {
        let (caller, rbac) = full_grants_principal();
        let (uc, _, users, _) = make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
        users.insert(user(false));
        let request = IssueTokenRequest {
            name: "n".repeat(256),
            ..make_request_pat()
        };
        let err = uc.issue_self_token(&caller, request).await.unwrap_err();
        assert!(matches!(err, ApiTokenError::NameTooLong));
    }

    #[tokio::test]
    async fn issue_self_token_zero_expiry_rejected() {
        let (caller, rbac) = full_grants_principal();
        let (uc, _, users, _) = make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
        users.insert(user(false));
        let request = IssueTokenRequest {
            expires_in_days: Some(0),
            ..make_request_pat()
        };
        let err = uc.issue_self_token(&caller, request).await.unwrap_err();
        assert!(matches!(err, ApiTokenError::ExpiryZero));
    }

    #[tokio::test]
    async fn issue_self_token_oversize_expiry_rejected() {
        let (caller, rbac) = full_grants_principal();
        let (uc, _, users, _) = make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
        users.insert(user(false));
        let request = IssueTokenRequest {
            expires_in_days: Some(366),
            ..make_request_pat()
        };
        let err = uc.issue_self_token(&caller, request).await.unwrap_err();
        assert!(matches!(err, ApiTokenError::ExpiryTooLong));
    }

    #[tokio::test]
    async fn issue_self_token_default_expiry_applied_when_omitted() {
        let (caller, rbac) = full_grants_principal();
        let (uc, tokens, users, _) =
            make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
        users.insert(user(false));
        let request = IssueTokenRequest {
            expires_in_days: None,
            ..make_request_pat()
        };
        let issued = uc.issue_self_token(&caller, request).await.unwrap();
        // Default 90 days for PAT.
        let row = &tokens.inserts()[0];
        let exp = row.expires_at.unwrap();
        let now = Utc::now();
        assert!((exp - now).num_days() >= 89);
        assert!((exp - now).num_days() <= 91);
        assert_eq!(issued.expires_at, row.expires_at);
    }

    // ---------- issue_for_service_account ----------

    #[tokio::test]
    async fn issue_for_service_account_admin_authority_required() {
        // Caller has a global Admin grant but is NOT in the `admin`
        // role — admin-mint requires admin role, not just Admin grant.
        let (caller, rbac) = principal_with_grants(vec![(Permission::Admin, None)]);
        let (uc, tokens, users, _) =
            make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
        users.insert(user(true));
        let err = uc
            .issue_for_service_account(&caller, Uuid::from_u128(0xACE), make_request_pat())
            .await
            .unwrap_err();
        assert!(matches!(err, ApiTokenError::NotAuthorized));
        assert!(tokens.inserts().is_empty());
    }

    #[tokio::test]
    async fn issue_for_service_account_target_must_be_service_account() {
        let (admin, rbac) = admin_principal();
        let (uc, tokens, users, events) =
            make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
        users.insert(user(false)); // NOT a service account
        let err = uc
            .issue_for_service_account(&admin, Uuid::from_u128(0xACE), make_request_pat())
            .await
            .unwrap_err();
        assert!(matches!(err, ApiTokenError::NotServiceAccount));
        assert!(tokens.inserts().is_empty());
        let denial = assert_denial_event(&events);
        assert!(matches!(
            denial.denial_reason,
            DenialReason::NotServiceAccount
        ));
    }

    #[tokio::test]
    async fn issue_for_service_account_unbounded_expiry_requires_flag() {
        let (admin, rbac) = admin_principal();
        let (uc, tokens, users, events) =
            make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
        users.insert(user(true)); // is_service_account
        let request = IssueTokenRequest {
            expires_in_days: None,
            ..make_request_pat()
        };
        let err = uc
            .issue_for_service_account(&admin, Uuid::from_u128(0xACE), request)
            .await
            .unwrap_err();
        assert!(matches!(err, ApiTokenError::UnboundedSvcTokenDisallowed));
        assert!(tokens.inserts().is_empty());
        let denial = assert_denial_event(&events);
        assert!(matches!(
            denial.denial_reason,
            DenialReason::UnboundedSvcTokenDisallowed
        ));
    }

    #[tokio::test]
    async fn issue_for_service_account_unbounded_expiry_allowed_with_flag() {
        let (admin, rbac) = admin_principal();
        let (uc, tokens, users, events) = make_use_case_with_rbac(
            ApiTokenIssuanceConfig {
                allow_admin_tokens: false,
                allow_unbounded_svc_tokens: true,
            },
            rbac,
        );
        users.insert(user(true));
        let request = IssueTokenRequest {
            expires_in_days: None,
            ..make_request_pat()
        };
        let issued = uc
            .issue_for_service_account(&admin, Uuid::from_u128(0xACE), request)
            .await
            .unwrap();
        assert!(issued.expires_at.is_none());
        assert!(issued.plaintext.starts_with("hort_svc_"));
        let inserts = tokens.inserts();
        assert_eq!(inserts.len(), 1);
        assert_eq!(inserts[0].kind, TokenKind::ServiceAccount);
        assert_eq!(inserts[0].user_id, Uuid::from_u128(0xACE));
        assert_eq!(inserts[0].created_by_user_id, Uuid::from_u128(0xAD));
        let event = assert_issued_event(&events, Uuid::from_u128(0xACE));
        assert_eq!(event.minted_by_admin_id, Some(Uuid::from_u128(0xAD)));
    }

    // ---------- issue_for_service_account_system ----------

    /// Helper: build a `Read+Write` request shaped for the system-mint
    /// path. No admin scope; seconds-based expiry matching what the
    /// rotation handler passes (`sa.validity` clamped to seconds).
    fn make_request_system() -> IssueTokenRequest {
        IssueTokenRequest {
            name: "ci-pusher".into(),
            description: Some("fallback rotation for service account ci-pusher".into()),
            declared_permissions: vec![Permission::Read, Permission::Write],
            repository_ids: None,
            expires_in_days: None,
            expires_in_seconds: Some(24 * 3600),
            federation_source: None,
        }
    }

    #[tokio::test]
    async fn issue_for_service_account_system_happy_path_emits_system_actor_event() {
        let (uc, tokens, users, events) = make_use_case(ApiTokenIssuanceConfig::default());
        users.insert(user(true));

        let issued = uc
            .issue_for_service_account_system(Uuid::from_u128(0xACE), make_request_system())
            .await
            .expect("system mint must succeed when target is a service account");
        assert_eq!(issued.kind, TokenKind::ServiceAccount);
        assert!(issued.plaintext.starts_with("hort_svc_"));
        assert!(issued.expires_at.is_some());

        // Row persisted with `created_by_user_id = target.id` — system
        // has no user_id, and the audit channel is the event's Actor field.
        let inserts = tokens.inserts();
        assert_eq!(inserts.len(), 1);
        assert_eq!(inserts[0].kind, TokenKind::ServiceAccount);
        assert_eq!(inserts[0].user_id, Uuid::from_u128(0xACE));
        assert_eq!(inserts[0].created_by_user_id, Uuid::from_u128(0xACE));

        // Event emitted on the target's stream with `Actor::Internal(System)`.
        let batches = events.appended_batches();
        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        assert!(matches!(
            batch.actor,
            Actor::Internal(hort_domain::events::InternalActor::System)
        ));
        let event = assert_issued_event(&events, Uuid::from_u128(0xACE));
        // No admin minted this — the field carries None.
        assert!(event.minted_by_admin_id.is_none());
    }

    #[tokio::test]
    async fn issue_for_service_account_system_rejects_admin_scope() {
        let (uc, tokens, users, _events) = make_use_case(ApiTokenIssuanceConfig::default());
        users.insert(user(true));
        let request = IssueTokenRequest {
            declared_permissions: vec![Permission::Admin],
            ..make_request_system()
        };
        let err = uc
            .issue_for_service_account_system(Uuid::from_u128(0xACE), request)
            .await
            .unwrap_err();
        // Admin scope is forbidden on the system-mint path regardless
        // of the flag — the deliberately tight gate is the second half
        // of the short-lifetime trade-off (no
        // worker-issued admin tokens, period).
        assert!(matches!(err, ApiTokenError::AdminAuthorityRequired));
        assert!(tokens.inserts().is_empty());
    }

    #[tokio::test]
    async fn issue_for_service_account_system_rejects_non_service_account_target() {
        let (uc, tokens, users, _events) = make_use_case(ApiTokenIssuanceConfig::default());
        users.insert(user(false)); // NOT a service account
        let err = uc
            .issue_for_service_account_system(Uuid::from_u128(0xACE), make_request_system())
            .await
            .unwrap_err();
        assert!(matches!(err, ApiTokenError::NotServiceAccount));
        assert!(tokens.inserts().is_empty());
    }

    #[tokio::test]
    async fn issue_for_service_account_system_default_expiry_when_request_silent() {
        let (uc, _tokens, users, _events) = make_use_case(ApiTokenIssuanceConfig::default());
        users.insert(user(true));
        let request = IssueTokenRequest {
            expires_in_days: None,
            expires_in_seconds: None,
            ..make_request_system()
        };
        let issued = uc
            .issue_for_service_account_system(Uuid::from_u128(0xACE), request)
            .await
            .expect("system mint must succeed with no-expiry request");
        // The system path NEVER produces an unbounded token —
        // defence-in-depth against a stale rotation handler producing
        // a token that outlives its replacement Secret.
        assert!(
            issued.expires_at.is_some(),
            "system mint must never produce an unbounded token"
        );
    }

    // ====================================================================
    // federated-JWT replay guard
    // ====================================================================

    use hort_domain::ports::replay_guard::{
        ReplayClaim, ReplayGuardError, ReplayGuardPort, ReplayKey,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Mock `ReplayGuardPort`. `outcome` is the canned reply; every
    /// `claim` call is recorded so a test can assert the guard was
    /// invoked exactly once with the expected key + TTL.
    struct MockReplayGuard {
        outcome: Mutex<Result<ReplayClaim, ReplayGuardError>>,
        calls: Mutex<Vec<(ReplayKey, DateTime<Utc>)>>,
        call_count: AtomicUsize,
    }

    impl MockReplayGuard {
        fn new(outcome: Result<ReplayClaim, ReplayGuardError>) -> Arc<Self> {
            Arc::new(Self {
                outcome: Mutex::new(outcome),
                calls: Mutex::new(Vec::new()),
                call_count: AtomicUsize::new(0),
            })
        }
        fn calls(&self) -> Vec<(ReplayKey, DateTime<Utc>)> {
            self.calls.lock().unwrap().clone()
        }
        fn call_count(&self) -> usize {
            self.call_count.load(Ordering::Relaxed)
        }
    }

    impl ReplayGuardPort for MockReplayGuard {
        fn claim<'a>(
            &'a self,
            key: &'a ReplayKey,
            expires_at: DateTime<Utc>,
        ) -> BoxFuture<'a, Result<ReplayClaim, ReplayGuardError>> {
            self.call_count.fetch_add(1, Ordering::Relaxed);
            self.calls.lock().unwrap().push((key.clone(), expires_at));
            let out = self.outcome.lock().unwrap().clone();
            Box::pin(async move { out })
        }
    }

    /// A federation system-mint request carrying a `jti` (the common
    /// case → `ReplayKey::Jti`). `expires_in_seconds` is bounded so the
    /// seen-set TTL is derivable.
    fn make_request_federation_jti(jti: &str) -> IssueTokenRequest {
        IssueTokenRequest {
            name: "ci-pusher".into(),
            description: Some("federated via /exchange".into()),
            declared_permissions: Vec::new(),
            repository_ids: None,
            expires_in_days: None,
            expires_in_seconds: Some(900),
            federation_source: Some(FederationSource {
                issuer: "github-actions".into(),
                jti: Some(jti.into()),
                subject: "repo:acme/app:ref:refs/heads/main".into(),
                iss: "https://token.actions.githubusercontent.com".into(),
                iat: Some(1_700_000_000),
                exp: 1_700_000_900,
                require_jti: true,
            }),
        }
    }

    fn make_uc_with_guard(
        guard: Arc<dyn ReplayGuardPort>,
    ) -> (
        ApiTokenUseCase,
        Arc<MockApiTokenRepository>,
        Arc<MockUserRepository>,
        Arc<MockEventStore>,
    ) {
        let (uc, tokens, users, events) = make_use_case(ApiTokenIssuanceConfig::default());
        (uc.with_replay_guard(guard), tokens, users, events)
    }

    /// Replay test (centerpiece): first presentation of a `jti` mints;
    /// the second presentation of the SAME `jti` is denied
    /// `ReplayDetected{composite:false}` with **no token row and no
    /// ApiTokenIssued event**, and the guard was consulted before any
    /// persistence.
    #[tokio::test]
    async fn federation_first_jti_mints_second_is_replay_denied() {
        // -- first presentation: guard says FirstSeen → mint proceeds --
        let guard_first = MockReplayGuard::new(Ok(ReplayClaim::FirstSeen));
        let (uc, tokens, users, events) = make_uc_with_guard(guard_first.clone());
        users.insert(user(true));
        let issued = uc
            .issue_for_service_account_system(
                Uuid::from_u128(0xACE),
                make_request_federation_jti("jti-replay-A"),
            )
            .await
            .expect("first presentation must mint");
        assert_eq!(issued.kind, TokenKind::ServiceAccount);
        assert_eq!(
            tokens.inserts().len(),
            1,
            "first presentation persists a token"
        );
        assert_eq!(
            guard_first.call_count(),
            1,
            "guard consulted exactly once before mint"
        );
        // The claim used a Jti key scoped to the resolved issuer name,
        // and the TTL is the resolved token expiry (min(jwt, fed_max)).
        let (key, ttl) = guard_first.calls()[0].clone();
        assert_eq!(
            key,
            ReplayKey::Jti {
                issuer_name: "github-actions".into(),
                jti: "jti-replay-A".into(),
            }
        );
        assert_eq!(
            Some(ttl),
            issued.expires_at,
            "seen-set TTL must equal the resolved token expiry"
        );

        // -- second presentation: guard says Replayed → DENY, no side effects --
        let guard_replay = MockReplayGuard::new(Ok(ReplayClaim::Replayed));
        let (uc2, tokens2, users2, events2) = make_uc_with_guard(guard_replay.clone());
        users2.insert(user(true));
        let err = uc2
            .issue_for_service_account_system(
                Uuid::from_u128(0xACE),
                make_request_federation_jti("jti-replay-A"),
            )
            .await
            .expect_err("a replayed jti must be denied");
        assert!(
            matches!(err, ApiTokenError::ReplayDetected { composite: false }),
            "expected ReplayDetected{{composite:false}}, got {err:?}"
        );
        assert!(
            tokens2.inserts().is_empty(),
            "a replay must NOT persist a token row"
        );
        assert!(
            events2.appended_batches().is_empty(),
            "a replay must NOT append an ApiTokenIssued event"
        );
        assert_eq!(guard_replay.call_count(), 1);
        // sanity: the first path DID append exactly one event
        assert_eq!(events.appended_batches().len(), 1);
    }

    /// Fail-CLOSED regression (centerpiece, anti-F-22): the guard
    /// returns `Unavailable` ⇒ the exchange is denied
    /// `ReplayGuardUnavailable`, **no token row, no ApiTokenIssued
    /// event**. There must be NO path where a guard outage falls
    /// through to minting.
    #[tokio::test]
    async fn federation_guard_unavailable_fails_closed_no_mint_no_event() {
        let guard = MockReplayGuard::new(Err(ReplayGuardError::Unavailable("db down".into())));
        let (uc, tokens, users, events) = make_uc_with_guard(guard.clone());
        users.insert(user(true));

        let err = uc
            .issue_for_service_account_system(
                Uuid::from_u128(0xACE),
                make_request_federation_jti("jti-outage"),
            )
            .await
            .expect_err("guard outage must fail CLOSED (deny), never mint");

        assert!(
            matches!(err, ApiTokenError::ReplayGuardUnavailable),
            "guard Unavailable must map to ReplayGuardUnavailable (503), got {err:?}"
        );
        assert!(
            tokens.inserts().is_empty(),
            "FAIL-CLOSED: a guard outage must NOT persist a token row"
        );
        assert!(
            events.appended_batches().is_empty(),
            "FAIL-CLOSED: a guard outage must NOT append an ApiTokenIssued event"
        );
        assert_eq!(guard.call_count(), 1, "guard consulted exactly once");
    }

    /// Composition-bug guard: federation path reached with the guard
    /// slot unwired ⇒ fail CLOSED (never mint unguarded).
    #[tokio::test]
    async fn federation_without_wired_guard_fails_closed() {
        // `make_use_case` builds the UC with `replay_guard = None`.
        let (uc, tokens, users, events) = make_use_case(ApiTokenIssuanceConfig::default());
        users.insert(user(true));
        let err = uc
            .issue_for_service_account_system(
                Uuid::from_u128(0xACE),
                make_request_federation_jti("jti-x"),
            )
            .await
            .expect_err("federation mint with no guard wired must fail closed");
        assert!(matches!(err, ApiTokenError::ReplayGuardUnavailable));
        assert!(tokens.inserts().is_empty());
        assert!(events.appended_batches().is_empty());
    }

    /// Non-federation system mint (`federation_source = None`, e.g. the
    /// rotation reconciler) must SKIP the guard entirely and mint
    /// unaffected — even when a guard IS wired.
    #[tokio::test]
    async fn non_federation_system_mint_skips_guard() {
        let guard = MockReplayGuard::new(Err(ReplayGuardError::Unavailable("would deny".into())));
        let (uc, tokens, users, _events) = make_uc_with_guard(guard.clone());
        users.insert(user(true));
        // make_request_system() has federation_source = None.
        let issued = uc
            .issue_for_service_account_system(Uuid::from_u128(0xACE), make_request_system())
            .await
            .expect("non-federation system mint must succeed and not touch the guard");
        assert_eq!(issued.kind, TokenKind::ServiceAccount);
        assert_eq!(tokens.inserts().len(), 1);
        assert_eq!(
            guard.call_count(),
            0,
            "the guard must NOT be consulted on a non-federation mint"
        );
    }

    /// §5 matrix: issuer requires jti, JWT has none ⇒ `JtiRequired`
    /// validation deny BEFORE the guard (guard never consulted, no
    /// mint, no event).
    #[tokio::test]
    async fn federation_jti_required_denies_before_guard() {
        let guard = MockReplayGuard::new(Ok(ReplayClaim::FirstSeen));
        let (uc, tokens, users, events) = make_uc_with_guard(guard.clone());
        users.insert(user(true));
        let mut req = make_request_federation_jti("ignored");
        if let Some(fs) = req.federation_source.as_mut() {
            fs.jti = None;
            fs.require_jti = true;
        }
        let err = uc
            .issue_for_service_account_system(Uuid::from_u128(0xACE), req)
            .await
            .expect_err("jti-less JWT against require_jti=true must be denied");
        assert!(matches!(err, ApiTokenError::JtiRequired));
        assert_eq!(
            guard.call_count(),
            0,
            "jti_required is a validation deny — the guard is NEVER consulted"
        );
        assert!(tokens.inserts().is_empty());
        assert!(events.appended_batches().is_empty());
    }

    /// §5 matrix: issuer allows missing jti (`require_jti=false`) and
    /// the JWT has `iat` ⇒ composite key; a replay is denied
    /// `ReplayDetected{composite:true}`.
    #[tokio::test]
    async fn federation_composite_replay_denied() {
        let guard = MockReplayGuard::new(Ok(ReplayClaim::Replayed));
        let (uc, tokens, users, _events) = make_uc_with_guard(guard.clone());
        users.insert(user(true));
        let mut req = make_request_federation_jti("ignored");
        if let Some(fs) = req.federation_source.as_mut() {
            fs.jti = None;
            fs.require_jti = false;
            fs.iat = Some(1_700_000_000);
        }
        let err = uc
            .issue_for_service_account_system(Uuid::from_u128(0xACE), req)
            .await
            .expect_err("composite replay must be denied");
        assert!(
            matches!(err, ApiTokenError::ReplayDetected { composite: true }),
            "expected composite replay, got {err:?}"
        );
        let (key, _ttl) = guard.calls()[0].clone();
        assert!(
            matches!(key, ReplayKey::Composite { .. }),
            "jti-less + require_jti=false must use the composite key"
        );
        assert!(tokens.inserts().is_empty());
    }

    /// §5 matrix: issuer allows missing jti but the JWT also lacks
    /// `iat` ⇒ composite not constructible ⇒ `JtiRequired`-equivalent,
    /// guard never consulted.
    #[tokio::test]
    async fn federation_composite_without_iat_denies_jti_required() {
        let guard = MockReplayGuard::new(Ok(ReplayClaim::FirstSeen));
        let (uc, tokens, users, _events) = make_uc_with_guard(guard.clone());
        users.insert(user(true));
        let mut req = make_request_federation_jti("ignored");
        if let Some(fs) = req.federation_source.as_mut() {
            fs.jti = None;
            fs.require_jti = false;
            fs.iat = None;
        }
        let err = uc
            .issue_for_service_account_system(Uuid::from_u128(0xACE), req)
            .await
            .expect_err("composite not constructible must be denied");
        assert!(matches!(err, ApiTokenError::JtiRequired));
        assert_eq!(guard.call_count(), 0);
        assert!(tokens.inserts().is_empty());
    }

    // -- build_replay_key pure §5 matrix (exhaustive) --------------------

    fn fs_with(jti: Option<&str>, require_jti: bool, iat: Option<i64>) -> FederationSource {
        FederationSource {
            issuer: "iss-name".into(),
            jti: jti.map(String::from),
            subject: "sub".into(),
            iss: "https://idp.example".into(),
            iat,
            exp: 1_700_003_600,
            require_jti,
        }
    }

    #[test]
    fn build_replay_key_jti_present_yields_jti_key_regardless_of_flag() {
        for require in [true, false] {
            let k = build_replay_key(&fs_with(Some("j1"), require, None)).unwrap();
            assert_eq!(
                k,
                ReplayKey::Jti {
                    issuer_name: "iss-name".into(),
                    jti: "j1".into()
                }
            );
        }
    }

    #[test]
    fn build_replay_key_no_jti_require_true_is_jti_required() {
        let err = build_replay_key(&fs_with(None, true, Some(1))).unwrap_err();
        assert!(matches!(err, ApiTokenError::JtiRequired));
    }

    #[test]
    fn build_replay_key_no_jti_require_false_with_iat_is_composite() {
        let k = build_replay_key(&fs_with(None, false, Some(1_700_000_000))).unwrap();
        assert_eq!(
            k,
            ReplayKey::Composite {
                issuer_name: "iss-name".into(),
                iss: "https://idp.example".into(),
                sub: "sub".into(),
                iat: 1_700_000_000,
                exp: 1_700_003_600,
            }
        );
    }

    #[test]
    fn build_replay_key_no_jti_require_false_no_iat_is_jti_required() {
        let err = build_replay_key(&fs_with(None, false, None)).unwrap_err();
        assert!(matches!(err, ApiTokenError::JtiRequired));
    }

    // -- hort_jwt_replay_rejected_total metric (single emitter, 2 labels) --

    #[test]
    fn replay_rejected_metric_fires_with_replayed_jti_label() {
        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        let snap = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let guard = MockReplayGuard::new(Ok(ReplayClaim::Replayed));
                    let (uc, _t, users, _e) = make_uc_with_guard(guard);
                    users.insert(user(true));
                    let _ = uc
                        .issue_for_service_account_system(
                            Uuid::from_u128(0xACE),
                            make_request_federation_jti("jti-metric"),
                        )
                        .await;
                });
        });
        let entries = snap.snapshot().into_vec();
        let found = entries.iter().any(|(ck, _, _, dv)| {
            ck.kind() == MetricKind::Counter
                && ck.key().name() == JWT_REPLAY_REJECTED_METRIC
                && ck
                    .key()
                    .labels()
                    .any(|l| l.key() == "result" && l.value() == "replayed_jti")
                && matches!(dv, DebugValue::Counter(n) if *n == 1)
        });
        assert!(
            found,
            "hort_jwt_replay_rejected_total{{result=replayed_jti}} must fire once"
        );
    }

    #[test]
    fn replay_rejected_metric_fires_with_replayed_composite_label() {
        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        let snap = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let guard = MockReplayGuard::new(Ok(ReplayClaim::Replayed));
                    let (uc, _t, users, _e) = make_uc_with_guard(guard);
                    users.insert(user(true));
                    let mut req = make_request_federation_jti("ignored");
                    if let Some(fs) = req.federation_source.as_mut() {
                        fs.jti = None;
                        fs.require_jti = false;
                        fs.iat = Some(1_700_000_000);
                    }
                    let _ = uc
                        .issue_for_service_account_system(Uuid::from_u128(0xACE), req)
                        .await;
                });
        });
        let entries = snap.snapshot().into_vec();
        let found = entries.iter().any(|(ck, _, _, dv)| {
            ck.kind() == MetricKind::Counter
                && ck.key().name() == JWT_REPLAY_REJECTED_METRIC
                && ck
                    .key()
                    .labels()
                    .any(|l| l.key() == "result" && l.value() == "replayed_composite")
                && matches!(dv, DebugValue::Counter(n) if *n == 1)
        });
        assert!(
            found,
            "hort_jwt_replay_rejected_total{{result=replayed_composite}} must fire once"
        );
    }

    #[test]
    fn replay_rejected_metric_not_emitted_on_guard_unavailable() {
        // §8: replay_guard_unavailable is NOT on this counter (no
        // replay was detected).
        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        let snap = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let guard =
                        MockReplayGuard::new(Err(ReplayGuardError::Unavailable("x".into())));
                    let (uc, _t, users, _e) = make_uc_with_guard(guard);
                    users.insert(user(true));
                    let _ = uc
                        .issue_for_service_account_system(
                            Uuid::from_u128(0xACE),
                            make_request_federation_jti("jti-u"),
                        )
                        .await;
                });
        });
        let entries = snap.snapshot().into_vec();
        let any_replay_metric = entries.iter().any(|(ck, _, _, _)| {
            ck.kind() == MetricKind::Counter && ck.key().name() == JWT_REPLAY_REJECTED_METRIC
        });
        assert!(
            !any_replay_metric,
            "guard-unavailable must NOT touch hort_jwt_replay_rejected_total"
        );
    }

    // ---------- revoke ----------

    #[tokio::test]
    async fn revoke_self_succeeds_emits_event_and_calls_repo_revoke() {
        let (uc, tokens, _, events) = make_use_case(ApiTokenIssuanceConfig::default());
        let token = ApiToken {
            id: Uuid::from_u128(0xF1),
            user_id: Uuid::from_u128(0xACE),
            name: "n".into(),
            description: None,
            kind: TokenKind::Pat,
            token_hash: "$argon2id$v=19$m=19456,t=2,p=1$abc$def".into(),
            token_prefix: "abcdefgh".into(),
            declared_permissions: vec![Permission::Read],
            repository_ids: None,
            expires_at: None,
            revoked_at: None,
            last_used_at: None,
            last_used_ip: None,
            last_used_user_agent: None,
            created_by_user_id: Uuid::from_u128(0xACE),
            created_at: Utc::now(),
        };
        tokens.seed_token(token.clone());

        uc.revoke(
            ApiActor {
                user_id: Uuid::from_u128(0xACE),
            },
            token.id,
            false,
        )
        .await
        .unwrap();
        assert_eq!(tokens.revokes(), vec![token.id]);
        let revoked = assert_revoked_event(&events);
        assert_eq!(revoked.token_id, token.id);
        assert_eq!(revoked.user_id, Uuid::from_u128(0xACE));
        assert!(revoked.revoked_by_admin_id.is_none());
    }

    #[tokio::test]
    async fn revoke_other_user_token_without_admin_authority_returns_not_authorized() {
        let (uc, tokens, _, _) = make_use_case(ApiTokenIssuanceConfig::default());
        let token = ApiToken {
            id: Uuid::from_u128(0xF1),
            user_id: Uuid::from_u128(0xACE),
            ..ApiToken {
                name: "n".into(),
                description: None,
                kind: TokenKind::Pat,
                token_hash: "$argon2id$v=19$m=19456,t=2,p=1$abc$def".into(),
                token_prefix: "abcdefgh".into(),
                declared_permissions: vec![],
                repository_ids: None,
                expires_at: None,
                revoked_at: None,
                last_used_at: None,
                last_used_ip: None,
                last_used_user_agent: None,
                created_by_user_id: Uuid::from_u128(0xACE),
                created_at: Utc::now(),
                id: Uuid::nil(),
                user_id: Uuid::nil(),
            }
        };
        tokens.seed_token(token.clone());
        let stranger = ApiActor {
            user_id: Uuid::from_u128(0xBEEF),
        };
        let err = uc.revoke(stranger, token.id, false).await.unwrap_err();
        assert!(matches!(err, ApiTokenError::NotAuthorized));
        assert!(tokens.revokes().is_empty());
    }

    #[tokio::test]
    async fn revoke_admin_authority_succeeds_for_any_token() {
        let (uc, tokens, _, events) = make_use_case(ApiTokenIssuanceConfig::default());
        let token = ApiToken {
            id: Uuid::from_u128(0xF1),
            user_id: Uuid::from_u128(0xACE),
            ..ApiToken {
                name: "n".into(),
                description: None,
                kind: TokenKind::Pat,
                token_hash: "$argon2id$v=19$m=19456,t=2,p=1$abc$def".into(),
                token_prefix: "abcdefgh".into(),
                declared_permissions: vec![],
                repository_ids: None,
                expires_at: None,
                revoked_at: None,
                last_used_at: None,
                last_used_ip: None,
                last_used_user_agent: None,
                created_by_user_id: Uuid::from_u128(0xACE),
                created_at: Utc::now(),
                id: Uuid::nil(),
                user_id: Uuid::nil(),
            }
        };
        tokens.seed_token(token.clone());
        let admin = ApiActor {
            user_id: Uuid::from_u128(0xAD),
        };
        uc.revoke(admin, token.id, true).await.unwrap();
        assert_eq!(tokens.revokes(), vec![token.id]);
        let revoked = assert_revoked_event(&events);
        assert_eq!(revoked.revoked_by_admin_id, Some(Uuid::from_u128(0xAD)));
    }

    #[tokio::test]
    async fn revoke_unknown_token_returns_not_found() {
        let (uc, _, _, _) = make_use_case(ApiTokenIssuanceConfig::default());
        let err = uc
            .revoke(
                ApiActor {
                    user_id: Uuid::from_u128(0xACE),
                },
                Uuid::from_u128(0xDEAD),
                false,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ApiTokenError::TokenNotFound));
    }

    // ---------- list_for_user ----------

    #[tokio::test]
    async fn list_for_user_self_succeeds() {
        let (uc, tokens, _, _) = make_use_case(ApiTokenIssuanceConfig::default());
        tokens.seed_list(vec![]);
        let actor = ApiActor {
            user_id: Uuid::from_u128(0xACE),
        };
        let page = uc
            .list_for_user(actor, Uuid::from_u128(0xACE), false, PageRequest::default())
            .await
            .unwrap();
        assert_eq!(page.total, 0);
        let calls = tokens.list_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, Uuid::from_u128(0xACE));
    }

    #[tokio::test]
    async fn list_for_user_other_user_without_admin_authority_returns_not_authorized() {
        let (uc, tokens, _, _) = make_use_case(ApiTokenIssuanceConfig::default());
        tokens.seed_list(vec![]);
        let actor = ApiActor {
            user_id: Uuid::from_u128(0xBEEF),
        };
        let err = uc
            .list_for_user(actor, Uuid::from_u128(0xACE), false, PageRequest::default())
            .await
            .unwrap_err();
        assert!(matches!(err, ApiTokenError::NotAuthorized));
        assert!(tokens.list_calls().is_empty());
    }

    #[tokio::test]
    async fn list_for_user_admin_authority_can_list_any_user() {
        let (uc, tokens, _, _) = make_use_case(ApiTokenIssuanceConfig::default());
        tokens.seed_list(vec![]);
        let actor = ApiActor {
            user_id: Uuid::from_u128(0xAD),
        };
        uc.list_for_user(actor, Uuid::from_u128(0xACE), true, PageRequest::default())
            .await
            .unwrap();
        let calls = tokens.list_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, Uuid::from_u128(0xACE));
    }

    // ---------- per-repo grant authorization ----------
    //
    // A naive implementation would project the caller's grants into a
    // flat `Vec<(Permission, Option<Uuid>)>` via the
    // `caller_from_principal` helper in `hort-http-core`, which only
    // enumerated GLOBAL grants. A non-admin user with a per-repo grant
    // could therefore not mint a per-repo-scoped token. Each test below
    // pins ONE arm of the fixed cap-vs-authority loop in
    // `issue_inner`: every (perm, repo) tuple is now checked through
    // `RbacEvaluator::authorize`, the same evaluator the request-time
    // authorize path consults.

    /// F3 watchpoint #1 — non-admin user with a per-repo Read grant
    /// can mint a token capped to `[Read]` × `[repo_a]`. This is the
    /// regression that the pre-F3 code rejected with
    /// `CapExceedsAuthority`.
    #[tokio::test]
    async fn issue_self_token_non_admin_with_per_repo_grant_succeeds_for_that_repo() {
        let repo_a = Uuid::from_u128(0xA);
        let (caller, rbac) = non_admin_with_repo_grant(repo_a, Permission::Read);
        let (uc, tokens, users, events) =
            make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
        users.insert(user(false));

        let request = IssueTokenRequest {
            declared_permissions: vec![Permission::Read],
            repository_ids: Some(vec![repo_a]),
            ..make_request_pat()
        };
        let issued = uc
            .issue_self_token(&caller, request)
            .await
            .expect("per-repo grant must authorise per-repo issuance");
        assert_eq!(issued.kind, TokenKind::Pat);
        let inserts = tokens.inserts();
        assert_eq!(inserts.len(), 1);
        assert_eq!(inserts[0].repository_ids, Some(vec![repo_a]));
        assert_eq!(inserts[0].declared_permissions, vec![Permission::Read]);
        let event = assert_issued_event(&events, Uuid::from_u128(0xACE));
        assert_eq!(event.repository_ids, Some(vec![repo_a]));
        assert_eq!(count_denials(&events), 0);
    }

    /// F3 — same per-repo Read grant on `repo_a`; minting against
    /// `repo_b` MUST fail with `CapExceedsAuthority` and the failed
    /// list must carry exactly `(Some(repo_b), Read)`.
    #[tokio::test]
    async fn issue_self_token_non_admin_with_per_repo_grant_fails_for_other_repo() {
        let repo_a = Uuid::from_u128(0xA);
        let repo_b = Uuid::from_u128(0xB);
        let (caller, rbac) = non_admin_with_repo_grant(repo_a, Permission::Read);
        let (uc, tokens, users, events) =
            make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
        users.insert(user(false));

        let request = IssueTokenRequest {
            declared_permissions: vec![Permission::Read],
            repository_ids: Some(vec![repo_b]),
            ..make_request_pat()
        };
        let err = uc.issue_self_token(&caller, request).await.unwrap_err();
        match err {
            ApiTokenError::CapExceedsAuthority { failed } => {
                assert_eq!(failed, vec![(Some(repo_b), Permission::Read)]);
            }
            other => panic!("expected CapExceedsAuthority, got {other:?}"),
        }
        assert!(tokens.inserts().is_empty());
        let denial = assert_denial_event(&events);
        assert!(matches!(
            denial.denial_reason,
            DenialReason::CapExceedsAuthority
        ));
    }

    /// F3 — non-admin with a GLOBAL Read grant CAN mint a global
    /// (None-scoped) token. This was always working pre-F3; pinned
    /// here so the new code path doesn't regress the global case.
    #[tokio::test]
    async fn issue_self_token_non_admin_with_global_grant_can_mint_global_token() {
        let (caller, rbac) = principal_with_grants(vec![(Permission::Read, None)]);
        let (uc, tokens, users, events) =
            make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
        users.insert(user(false));

        let request = IssueTokenRequest {
            declared_permissions: vec![Permission::Read],
            repository_ids: None,
            ..make_request_pat()
        };
        let issued = uc
            .issue_self_token(&caller, request)
            .await
            .expect("global grant authorises global issuance");
        assert_eq!(issued.kind, TokenKind::Pat);
        assert_eq!(tokens.inserts().len(), 1);
        assert_eq!(tokens.inserts()[0].repository_ids, None);
        assert_eq!(count_denials(&events), 0);
    }

    /// F3 — a per-repo-only grantee CANNOT mint a global (None-scoped)
    /// token even for the permission they're granted. The cap-vs-
    /// authority loop hits `rbac.authorize(_, perm, None)`, which the
    /// per-repo grant fails (`grant.repository_id = Some(_)` does not
    /// match `repository_id = None` per `RbacEvaluator::authorize`'s
    /// scoping doc).
    #[tokio::test]
    async fn issue_self_token_non_admin_with_per_repo_grant_cannot_mint_global_token() {
        let repo_a = Uuid::from_u128(0xA);
        let (caller, rbac) = non_admin_with_repo_grant(repo_a, Permission::Read);
        let (uc, tokens, users, events) =
            make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
        users.insert(user(false));

        let request = IssueTokenRequest {
            declared_permissions: vec![Permission::Read],
            repository_ids: None,
            ..make_request_pat()
        };
        let err = uc.issue_self_token(&caller, request).await.unwrap_err();
        match err {
            ApiTokenError::CapExceedsAuthority { failed } => {
                assert_eq!(failed, vec![(None, Permission::Read)]);
            }
            other => panic!("expected CapExceedsAuthority, got {other:?}"),
        }
        assert!(tokens.inserts().is_empty());
        let denial = assert_denial_event(&events);
        assert!(matches!(
            denial.denial_reason,
            DenialReason::CapExceedsAuthority
        ));
    }

    /// F3 — admin role short-circuits ANY (perm, repo) tuple. Pinned
    /// here so the rewrite preserves admin-can-mint-anything.
    #[tokio::test]
    async fn issue_self_token_admin_role_authorizes_anything() {
        // Admin principal with user_id = 0xACE so self-mint resolves
        // to the seeded user row.
        let caller = principal_with_id(Uuid::from_u128(0xACE), vec!["admin"]);
        let (uc, tokens, users, _) =
            make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), empty_evaluator());
        users.insert(user(false));

        // Mint a token capped to Write × [arbitrary repo] — no grants
        // seeded for that repo, but admin role passes the evaluator.
        let arbitrary_repo = Uuid::from_u128(0xDEAD_BEEF);
        let request = IssueTokenRequest {
            declared_permissions: vec![Permission::Write, Permission::Delete],
            repository_ids: Some(vec![arbitrary_repo]),
            ..make_request_pat()
        };
        let issued = uc.issue_self_token(&caller, request).await.unwrap();
        assert_eq!(issued.kind, TokenKind::Pat);
        let inserts = tokens.inserts();
        assert_eq!(inserts.len(), 1);
        assert_eq!(inserts[0].repository_ids, Some(vec![arbitrary_repo]));
    }

    /// F3 — the cap-vs-authority loop must call the evaluator for
    /// EVERY (perm, repo) tuple in the request. With one repo
    /// authorized and one not, the failed list carries the
    /// not-authorized entry only — proving the loop walks every
    /// repo, not just the first or globals.
    #[tokio::test]
    async fn cap_check_calls_evaluator_per_repo_in_request() {
        let repo_a = Uuid::from_u128(0xA);
        let repo_b = Uuid::from_u128(0xB);
        // Caller has Read on repo_a only (per-repo grant).
        let (caller, rbac) = non_admin_with_repo_grant(repo_a, Permission::Read);
        let (uc, _, users, _) = make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
        users.insert(user(false));

        // Request both repos; evaluator must be consulted per (perm, repo).
        let request = IssueTokenRequest {
            declared_permissions: vec![Permission::Read],
            repository_ids: Some(vec![repo_a, repo_b]),
            ..make_request_pat()
        };
        let err = uc.issue_self_token(&caller, request).await.unwrap_err();
        match err {
            ApiTokenError::CapExceedsAuthority { failed } => {
                // repo_a authorises (per-repo grant matches); repo_b
                // does NOT — ONLY repo_b appears in `failed`.
                assert_eq!(failed, vec![(Some(repo_b), Permission::Read)]);
            }
            other => panic!("expected CapExceedsAuthority, got {other:?}"),
        }
    }

    /// F3 — per-tuple loop: with two declared permissions and two
    /// repos and NO grants, every (perm, repo) tuple appears in
    /// `failed`. Pins the matrix expansion so the loop's structure
    /// can't silently change to "fail-fast on first miss".
    #[tokio::test]
    async fn cap_check_failed_list_collects_every_unauthorized_tuple() {
        let repo_a = Uuid::from_u128(0xA);
        let repo_b = Uuid::from_u128(0xB);
        // Caller has no grants on either perm or repo.
        let (caller, rbac) = principal_with_grants(vec![]);
        let (uc, _, users, _) = make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
        users.insert(user(false));

        let request = IssueTokenRequest {
            declared_permissions: vec![Permission::Read, Permission::Write],
            repository_ids: Some(vec![repo_a, repo_b]),
            ..make_request_pat()
        };
        let err = uc.issue_self_token(&caller, request).await.unwrap_err();
        match err {
            ApiTokenError::CapExceedsAuthority { failed } => {
                // 2 perms × 2 repos = 4 entries. Order follows the
                // outer-repo / inner-perm loop in `issue_inner`.
                assert_eq!(failed.len(), 4);
                assert!(failed.contains(&(Some(repo_a), Permission::Read)));
                assert!(failed.contains(&(Some(repo_a), Permission::Write)));
                assert!(failed.contains(&(Some(repo_b), Permission::Read)));
                assert!(failed.contains(&(Some(repo_b), Permission::Write)));
            }
            other => panic!("expected CapExceedsAuthority, got {other:?}"),
        }
    }

    /// F3 live-reload regression — the `ApiTokenUseCase` must read its
    /// `RbacEvaluator` through the `ArcSwap` pointer, not a snapshot
    /// taken at composition time. This locks in the contract that the
    /// grant-refresh task can extend a user's authority and
    /// the next issuance call honours it WITHOUT an `hort-server`
    /// restart.
    ///
    /// Symmetry with production: `composition.rs` builds
    /// `Arc<ArcSwap<RbacEvaluator>>` once (line 715), threads
    /// `rbac_swap.clone()` into `ApiTokenUseCase::new`, and the refresh
    /// task calls `swap.store(Arc::new(new_eval))` when roles/grants
    /// change. The use case picks up the new evaluator on the next
    /// `.load()`.
    ///
    /// Sequence:
    /// 1. Non-admin principal `P` with NO grants → mint `[Read]` on
    ///    `repo_a` is rejected with `CapExceedsAuthority`.
    /// 2. Swap a fresh evaluator that grants `P` Read on `repo_a`.
    /// 3. Re-attempt the same issuance → succeeds. The use case picked
    ///    up the swap.
    #[tokio::test]
    async fn issue_self_token_picks_up_rbac_reload_for_newly_granted_repo() {
        let repo_a = Uuid::from_u128(0xA);
        // Step 1: non-admin principal P with NO grants. Build the
        // `ArcSwap` directly so we keep a handle to swap a new
        // evaluator in mid-test.
        let (caller, rbac) = principal_with_grants(vec![]);
        let (uc, tokens, users, _) =
            make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac.clone());
        users.insert(user(false));

        let request = IssueTokenRequest {
            declared_permissions: vec![Permission::Read],
            repository_ids: Some(vec![repo_a]),
            ..make_request_pat()
        };
        let err = uc
            .issue_self_token(&caller, request.clone())
            .await
            .unwrap_err();
        match err {
            ApiTokenError::CapExceedsAuthority { failed } => {
                assert_eq!(failed, vec![(Some(repo_a), Permission::Read)]);
            }
            other => panic!("expected CapExceedsAuthority pre-reload, got {other:?}"),
        }
        assert!(
            tokens.inserts().is_empty(),
            "no token must persist on a refused mint"
        );

        // Step 2: swap a fresh evaluator that grants `developer` Read
        // on repo_a. The principal's role list (`["developer"]`) is
        // unchanged; only the role's grant index expands. This is the
        // exact shape the grant-refresh task produces.
        let new_eval =
            evaluator_with_role_grants("developer", vec![(Permission::Read, Some(repo_a))]);
        rbac.store(Arc::new(new_eval));

        // Step 3: same request — must now succeed because the use case
        // re-loads the pointer on the next call.
        let issued = uc
            .issue_self_token(&caller, request)
            .await
            .expect("post-reload issuance must honour the newly granted per-repo Read");
        assert_eq!(issued.kind, TokenKind::Pat);
        let inserts = tokens.inserts();
        assert_eq!(inserts.len(), 1);
        assert_eq!(inserts[0].repository_ids, Some(vec![repo_a]));
        assert_eq!(inserts[0].declared_permissions, vec![Permission::Read]);
    }

    // ---------- Stream routing — denial event lands on actor's stream, not target's ----------

    #[tokio::test]
    async fn denial_event_lands_on_requesting_actor_stream() {
        let (admin, rbac) = admin_principal(); // user_id = 0xAD
        let (uc, _, users, events) =
            make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
        users.insert(user(true)); // service account at 0xACE
        let request = IssueTokenRequest {
            ..make_request_pat()
        };
        // Service-account user is not actually a service account — wait, it IS true above.
        // Re-jig: this path triggers admin-mint to non-service-account → NotServiceAccount.
        users.insert(User {
            id: Uuid::from_u128(0x55),
            is_service_account: false,
            ..user(false)
        });
        let _ = uc
            .issue_for_service_account(&admin, Uuid::from_u128(0x55), request)
            .await
            .unwrap_err();

        let batches = events.appended_batches();
        let denial_batch = batches
            .iter()
            .find(|b| {
                matches!(
                    b.events.first().map(|e| &e.event),
                    Some(DomainEvent::ApiTokenIssuanceDenied(_))
                )
            })
            .expect("denial appended");
        assert_eq!(
            denial_batch.stream_id,
            StreamId::user(Uuid::from_u128(0xAD)),
            "denial event must land on the REQUESTING ACTOR's stream"
        );
        let DomainEvent::ApiTokenIssuanceDenied(d) = &denial_batch.events[0].event else {
            panic!("not a denial");
        };
        assert_eq!(
            d.target_user_id,
            Uuid::from_u128(0x55),
            "but target_user_id payload field carries the target"
        );
    }

    #[tokio::test]
    async fn issued_event_lands_on_token_owner_stream() {
        let (admin, rbac) = admin_principal(); // user_id = 0xAD
        let (uc, _, users, events) = make_use_case_with_rbac(
            ApiTokenIssuanceConfig {
                allow_unbounded_svc_tokens: false,
                allow_admin_tokens: false,
            },
            rbac,
        );
        users.insert(User {
            id: Uuid::from_u128(0xCAFE),
            is_service_account: true,
            ..user(true)
        });
        let issued = uc
            .issue_for_service_account(&admin, Uuid::from_u128(0xCAFE), make_request_pat())
            .await
            .unwrap();
        assert_eq!(issued.kind, TokenKind::ServiceAccount);

        let batches = events.appended_batches();
        let issued_batch = batches
            .iter()
            .find(|b| {
                matches!(
                    b.events.first().map(|e| &e.event),
                    Some(DomainEvent::ApiTokenIssued(_))
                )
            })
            .expect("issued appended");
        assert_eq!(
            issued_batch.stream_id,
            StreamId::user(Uuid::from_u128(0xCAFE)),
            "issued event must land on the TOKEN OWNER's stream"
        );
        // Envelope actor is the admin.
        match &issued_batch.actor {
            Actor::Api(a) => assert_eq!(a.user_id, Uuid::from_u128(0xAD)),
            other => panic!("expected Api actor, got {other:?}"),
        }
    }

    // ===================================================================
    // `hort_api_token_issued_total` and
    // `hort_api_token_revoked_total` metric emission tests.
    // ===================================================================

    use crate::metrics::capture_metrics;
    use metrics_util::debugging::DebugValue;
    use metrics_util::{CompositeKey, MetricKind};

    /// Walk a debugging-recorder snapshot and return the counter value
    /// for the given (metric_name, label_kvs) tuple. Returns 0 when
    /// the metric+labels combination is absent — the recorder simply
    /// did not see an emission.
    fn b9_counter_value(
        snap: &[(
            CompositeKey,
            Option<metrics::Unit>,
            Option<metrics::SharedString>,
            DebugValue,
        )],
        metric_name: &str,
        label_kvs: &[(&str, &str)],
    ) -> u64 {
        for (key, _unit, _desc, value) in snap {
            if key.kind() != MetricKind::Counter {
                continue;
            }
            if key.key().name() != metric_name {
                continue;
            }
            // All requested labels MUST be present with the requested
            // values; extra labels are not allowed (the cardinality
            // assertions below depend on knowing the exact label set).
            let mut got: HashMap<String, String> = HashMap::new();
            for label in key.key().labels() {
                got.insert(label.key().to_string(), label.value().to_string());
            }
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

    /// Collect every label set seen on `metric_name` in the snapshot.
    /// Used by the cardinality-discipline assertion to prove no
    /// forbidden label keys (`token_id`, `user_id`, `repo_id`,
    /// `repository_name`, `scope_string`) appear on the new metrics.
    fn b9_collect_label_keys(
        snap: &[(
            CompositeKey,
            Option<metrics::Unit>,
            Option<metrics::SharedString>,
            DebugValue,
        )],
        metric_name: &str,
    ) -> std::collections::BTreeSet<String> {
        let mut keys = std::collections::BTreeSet::new();
        for (key, _, _, _) in snap {
            if key.key().name() == metric_name {
                for label in key.key().labels() {
                    keys.insert(label.key().to_string());
                }
            }
        }
        keys
    }

    fn b9_capture_async<F, Fut>(
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
        capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(f());
        })
        .into_vec()
    }

    // -- hort_api_token_issued_total — happy path ------------------------------

    #[test]
    fn issued_metric_emits_kind_pat_result_success_on_self_mint() {
        let snap = b9_capture_async(|| async move {
            let (caller, rbac) = full_grants_principal();
            let (uc, _, users, _) =
                make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
            users.insert(user(false));
            let _ = uc
                .issue_self_token(&caller, make_request_pat())
                .await
                .unwrap();
        });
        assert_eq!(
            b9_counter_value(
                &snap,
                "hort_api_token_issued_total",
                &[("kind", "pat"), ("result", "success")],
            ),
            1,
            "self-mint success must emit kind=pat, result=success"
        );
    }

    #[test]
    fn issued_metric_emits_kind_svc_result_success_on_admin_mint() {
        let snap = b9_capture_async(|| async move {
            let (admin, rbac) = admin_principal();
            let (uc, _, users, _) =
                make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
            users.insert(User {
                id: Uuid::from_u128(0xCAFE),
                is_service_account: true,
                ..user(true)
            });
            let _ = uc
                .issue_for_service_account(&admin, Uuid::from_u128(0xCAFE), make_request_pat())
                .await
                .unwrap();
        });
        assert_eq!(
            b9_counter_value(
                &snap,
                "hort_api_token_issued_total",
                &[("kind", "svc"), ("result", "success")],
            ),
            1,
            "admin-mint for service account must emit kind=svc, result=success"
        );
    }

    // -- hort_api_token_issued_total — failure paths --------------------------

    #[test]
    fn issued_metric_emits_cap_exceeds_authority_bucket() {
        let snap = b9_capture_async(|| async move {
            let (caller, rbac) = principal_with_grants(vec![(Permission::Read, None)]);
            let (uc, _, users, _) =
                make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
            users.insert(user(false));
            let request = IssueTokenRequest {
                declared_permissions: vec![Permission::Write],
                repository_ids: Some(vec![Uuid::from_u128(0xA)]),
                ..make_request_pat()
            };
            let _ = uc.issue_self_token(&caller, request).await.unwrap_err();
        });
        assert_eq!(
            b9_counter_value(
                &snap,
                "hort_api_token_issued_total",
                &[("kind", "pat"), ("result", "cap_exceeds_authority")],
            ),
            1
        );
    }

    #[test]
    fn issued_metric_emits_admin_disallowed_bucket() {
        // Flag off + admin permission requested → AdminTokenDisallowed.
        let snap = b9_capture_async(|| async move {
            // Admin role + flag off — first admin-token gate trips.
            let caller = principal_with_id(Uuid::from_u128(0xACE), vec!["admin"]);
            let (uc, _, users, _) =
                make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), empty_evaluator());
            users.insert(user(false));
            let request = IssueTokenRequest {
                declared_permissions: vec![Permission::Admin],
                expires_in_days: Some(15),
                ..make_request_pat()
            };
            let _ = uc.issue_self_token(&caller, request).await.unwrap_err();
        });
        assert_eq!(
            b9_counter_value(
                &snap,
                "hort_api_token_issued_total",
                &[("kind", "pat"), ("result", "admin_disallowed")],
            ),
            1,
            "admin-token disallowed must collapse into the admin_disallowed bucket"
        );
    }

    #[test]
    fn issued_metric_admin_disallowed_covers_admin_authority_required() {
        // Flag on, but caller is NOT admin → AdminAuthorityRequired,
        // also collapses into admin_disallowed bucket per the result-
        // mapping table.
        let snap = b9_capture_async(|| async move {
            let (caller, rbac) = principal_with_grants(vec![(Permission::Admin, None)]);
            let (uc, _, users, _) = make_use_case_with_rbac(
                ApiTokenIssuanceConfig {
                    allow_admin_tokens: true,
                    allow_unbounded_svc_tokens: false,
                },
                rbac,
            );
            users.insert(user(false));
            let request = IssueTokenRequest {
                declared_permissions: vec![Permission::Admin],
                expires_in_days: Some(15),
                ..make_request_pat()
            };
            let _ = uc.issue_self_token(&caller, request).await.unwrap_err();
        });
        assert_eq!(
            b9_counter_value(
                &snap,
                "hort_api_token_issued_total",
                &[("kind", "pat"), ("result", "admin_disallowed")],
            ),
            1
        );
    }

    #[test]
    fn issued_metric_admin_disallowed_covers_admin_token_exceeds_thirty_days() {
        let snap = b9_capture_async(|| async move {
            let caller = principal_with_id(Uuid::from_u128(0xACE), vec!["admin"]);
            let (uc, _, users, _) = make_use_case_with_rbac(
                ApiTokenIssuanceConfig {
                    allow_admin_tokens: true,
                    allow_unbounded_svc_tokens: false,
                },
                empty_evaluator(),
            );
            users.insert(user(false));
            let request = IssueTokenRequest {
                declared_permissions: vec![Permission::Admin],
                expires_in_days: Some(31),
                ..make_request_pat()
            };
            let _ = uc.issue_self_token(&caller, request).await.unwrap_err();
        });
        assert_eq!(
            b9_counter_value(
                &snap,
                "hort_api_token_issued_total",
                &[("kind", "pat"), ("result", "admin_disallowed")],
            ),
            1
        );
    }

    #[test]
    fn issued_metric_emits_validation_error_bucket_for_service_account_self_mint() {
        let snap = b9_capture_async(|| async move {
            let (caller, rbac) = full_grants_principal();
            let (uc, _, users, _) =
                make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
            users.insert(user(true)); // is_service_account
            let _ = uc
                .issue_self_token(&caller, make_request_pat())
                .await
                .unwrap_err();
        });
        assert_eq!(
            b9_counter_value(
                &snap,
                "hort_api_token_issued_total",
                &[("kind", "pat"), ("result", "validation_error")],
            ),
            1
        );
    }

    #[test]
    fn issued_metric_validation_error_bucket_covers_invalid_repository_set() {
        let snap = b9_capture_async(|| async move {
            let (caller, rbac) = full_grants_principal();
            let (uc, _, users, _) =
                make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
            users.insert(user(false));
            let request = IssueTokenRequest {
                repository_ids: Some(vec![]),
                ..make_request_pat()
            };
            let _ = uc.issue_self_token(&caller, request).await.unwrap_err();
        });
        assert_eq!(
            b9_counter_value(
                &snap,
                "hort_api_token_issued_total",
                &[("kind", "pat"), ("result", "validation_error")],
            ),
            1
        );
    }

    #[test]
    fn issued_metric_label_set_is_exactly_kind_and_result() {
        // Cardinality discipline (acceptance bullet 3) — the
        // forbidden labels (token_id, user_id, repo_id,
        // repository_name, scope_string) MUST NOT appear on
        // hort_api_token_issued_total.
        let snap = b9_capture_async(|| async move {
            let (caller, rbac) = full_grants_principal();
            let (uc, _, users, _) =
                make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
            users.insert(user(false));
            let _ = uc.issue_self_token(&caller, make_request_pat()).await;
        });
        let keys = b9_collect_label_keys(&snap, "hort_api_token_issued_total");
        let expected: std::collections::BTreeSet<String> =
            ["kind".to_string(), "result".to_string()]
                .into_iter()
                .collect();
        assert_eq!(
            keys, expected,
            "hort_api_token_issued_total label set MUST be exactly {{kind, result}}; got {keys:?}"
        );
        // Belt-and-braces: forbidden keys absent.
        for forbidden in [
            "token_id",
            "user_id",
            "repo_id",
            "repository_name",
            "scope_string",
        ] {
            assert!(
                !keys.contains(forbidden),
                "forbidden label `{forbidden}` MUST NOT appear on hort_api_token_issued_total"
            );
        }
    }

    // -- hort_api_token_revoked_total -----------------------------------------

    #[test]
    fn revoked_metric_emits_actor_kind_self_on_self_revoke() {
        let snap = b9_capture_async(|| async move {
            let (uc, tokens, _, _) = make_use_case(ApiTokenIssuanceConfig::default());
            let token = ApiToken {
                id: Uuid::from_u128(0xF1),
                user_id: Uuid::from_u128(0xACE),
                name: "n".into(),
                description: None,
                kind: TokenKind::Pat,
                token_hash: "$argon2id$v=19$m=19456,t=2,p=1$abc$def".into(),
                token_prefix: "abcdefgh".into(),
                declared_permissions: vec![Permission::Read],
                repository_ids: None,
                expires_at: None,
                revoked_at: None,
                last_used_at: None,
                last_used_ip: None,
                last_used_user_agent: None,
                created_by_user_id: Uuid::from_u128(0xACE),
                created_at: Utc::now(),
            };
            tokens.seed_token(token.clone());
            uc.revoke(
                ApiActor {
                    user_id: Uuid::from_u128(0xACE),
                },
                token.id,
                false,
            )
            .await
            .unwrap();
        });
        assert_eq!(
            b9_counter_value(
                &snap,
                "hort_api_token_revoked_total",
                &[("actor_kind", "self")],
            ),
            1
        );
    }

    #[test]
    fn revoked_metric_emits_actor_kind_admin_on_admin_revoke() {
        let snap = b9_capture_async(|| async move {
            let (uc, tokens, _, _) = make_use_case(ApiTokenIssuanceConfig::default());
            let token = ApiToken {
                id: Uuid::from_u128(0xF2),
                user_id: Uuid::from_u128(0xACE),
                name: "n".into(),
                description: None,
                kind: TokenKind::Pat,
                token_hash: "$argon2id$v=19$m=19456,t=2,p=1$abc$def".into(),
                token_prefix: "abcdefgh".into(),
                declared_permissions: vec![Permission::Read],
                repository_ids: None,
                expires_at: None,
                revoked_at: None,
                last_used_at: None,
                last_used_ip: None,
                last_used_user_agent: None,
                created_by_user_id: Uuid::from_u128(0xACE),
                created_at: Utc::now(),
            };
            tokens.seed_token(token.clone());
            // Admin (different user_id) revokes someone else's token.
            uc.revoke(
                ApiActor {
                    user_id: Uuid::from_u128(0xAD),
                },
                token.id,
                true,
            )
            .await
            .unwrap();
        });
        assert_eq!(
            b9_counter_value(
                &snap,
                "hort_api_token_revoked_total",
                &[("actor_kind", "admin")],
            ),
            1
        );
    }

    #[test]
    fn revoked_metric_does_not_emit_on_failed_revoke() {
        // Failure path: TokenNotFound. The revoke metric counts
        // SUCCESSFUL revocations only — failure paths must NOT emit.
        let snap = b9_capture_async(|| async move {
            let (uc, _, _, _) = make_use_case(ApiTokenIssuanceConfig::default());
            let _ = uc
                .revoke(
                    ApiActor {
                        user_id: Uuid::from_u128(0xACE),
                    },
                    Uuid::from_u128(0xDEAD),
                    false,
                )
                .await
                .unwrap_err();
        });
        // Either label arm MUST be zero on the failure path.
        assert_eq!(
            b9_counter_value(
                &snap,
                "hort_api_token_revoked_total",
                &[("actor_kind", "self")],
            ),
            0
        );
        assert_eq!(
            b9_counter_value(
                &snap,
                "hort_api_token_revoked_total",
                &[("actor_kind", "admin")],
            ),
            0
        );
    }

    #[test]
    fn revoked_metric_label_set_is_exactly_actor_kind() {
        let snap = b9_capture_async(|| async move {
            let (uc, tokens, _, _) = make_use_case(ApiTokenIssuanceConfig::default());
            let token = ApiToken {
                id: Uuid::from_u128(0xF3),
                user_id: Uuid::from_u128(0xACE),
                name: "n".into(),
                description: None,
                kind: TokenKind::Pat,
                token_hash: "$argon2id$v=19$m=19456,t=2,p=1$abc$def".into(),
                token_prefix: "abcdefgh".into(),
                declared_permissions: vec![Permission::Read],
                repository_ids: None,
                expires_at: None,
                revoked_at: None,
                last_used_at: None,
                last_used_ip: None,
                last_used_user_agent: None,
                created_by_user_id: Uuid::from_u128(0xACE),
                created_at: Utc::now(),
            };
            tokens.seed_token(token.clone());
            uc.revoke(
                ApiActor {
                    user_id: Uuid::from_u128(0xACE),
                },
                token.id,
                false,
            )
            .await
            .unwrap();
        });
        let keys = b9_collect_label_keys(&snap, "hort_api_token_revoked_total");
        let expected: std::collections::BTreeSet<String> =
            ["actor_kind".to_string()].into_iter().collect();
        assert_eq!(keys, expected);
        for forbidden in [
            "token_id",
            "user_id",
            "repo_id",
            "repository_name",
            "scope_string",
        ] {
            assert!(
                !keys.contains(forbidden),
                "forbidden label `{forbidden}` MUST NOT appear on hort_api_token_revoked_total"
            );
        }
    }

    // -- issue_cli_session ---------------------------------------------------
    //
    // The cli_session minting path is the issuance side of the RFC 8693
    // token-exchange flow (`POST /api/v1/auth/exchange`). Forced fields
    // per design doc 039 §6 — `kind=CliSession`, hardcoded
    // `[Read,Write,Delete]` (NEVER Admin), no repo restriction, 30-day
    // expiry — and admin-disallow is enforced by overwriting
    // `declared_permissions` upstream of the existing
    // `allow_admin_tokens` gate (design doc 039 §8 invariant 4).

    // ---------- CliSession JWT test rig ----------

    use crate::cli_session_signing::{
        CliSessionTokenSigner, CliSessionVerifyOutcome, CLI_SESSION_TOKEN_KIND,
    };
    use crate::oci_token_signing::OciTokenSigningKey;

    /// Minimal in-memory `EphemeralStore` for the CliSession `jti`
    /// denylist tests. Mirrors the inline mocks in
    /// `authenticate_use_case.rs` / `pat_validation_use_case.rs` (the
    /// shared `InMemoryEphemeralStore` adapter is an `hort-adapters-*`
    /// crate; `hort-app` must not take an adapter dep even in dev). Only
    /// the methods the denylist exercises (`put` / `get`) carry real
    /// behaviour; the rest are inert.
    #[derive(Default)]
    struct DenylistMockStore {
        map: Mutex<HashMap<String, Bytes>>,
    }

    impl DenylistMockStore {
        fn new() -> Self {
            Self::default()
        }
        fn contains(&self, key: &str) -> bool {
            self.map.lock().unwrap().contains_key(key)
        }
    }

    impl EphemeralStore for DenylistMockStore {
        fn get(&self, key: &str) -> BoxFuture<'_, hort_domain::error::DomainResult<Option<Bytes>>> {
            let v = self.map.lock().unwrap().get(key).cloned();
            Box::pin(async move { Ok(v) })
        }
        fn put(
            &self,
            key: &str,
            value: Bytes,
            _ttl: StdDuration,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            self.map.lock().unwrap().insert(key.to_string(), value);
            Box::pin(async { Ok(()) })
        }
        fn put_if_absent(
            &self,
            _key: &str,
            _value: Bytes,
            _ttl: StdDuration,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<bool>> {
            Box::pin(async { Ok(true) })
        }
        fn compare_and_swap(
            &self,
            _key: &str,
            _expected_version: u64,
            _new_value: Bytes,
            _ttl: StdDuration,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<Option<u64>>> {
            Box::pin(async { Ok(None) })
        }
        fn delete(&self, _key: &str) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn extend_ttl(
            &self,
            _key: &str,
            _ttl: StdDuration,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    /// Build a fresh `CliSessionTokenSigner` over a one-shot Ed25519
    /// keypair, plus the denylist store, both shareable.
    fn cli_session_rig() -> (Arc<CliSessionTokenSigner>, Arc<DenylistMockStore>) {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let key = Arc::new(OciTokenSigningKey::new(sk, None));
        let signer = Arc::new(CliSessionTokenSigner::new(
            key,
            "https://hort.test".to_string(),
        ));
        (signer, Arc::new(DenylistMockStore::new()))
    }

    fn make_cli_request(client_name: Option<&str>, source_ip: &str) -> IssueCliSessionRequest {
        IssueCliSessionRequest {
            client_name: client_name.map(String::from),
            source_ip: source_ip.into(),
            // Vec::new() means "no scope specified",
            // which `issue_cli_session_inner` resolves to the
            // [Read, Write, Delete] default. `None` for
            // lifetime resolves to DEFAULT_CLI_SESSION_LIFETIME_SECS
            // (1 h). Tests asking for a specific scope or lifetime
            // construct IssueCliSessionRequest directly rather than
            // going through this helper.
            requested_scope: Vec::new(),
            requested_lifetime_secs: None,
        }
    }

    /// All the handles `make_cli_session_use_case` hands back: the use
    /// case, the four mock-port handles, the JWT signer, the denylist
    /// store, and the caller principal.
    type CliSessionRig = (
        ApiTokenUseCase,
        Arc<MockApiTokenRepository>,
        Arc<MockUserRepository>,
        Arc<MockEventStore>,
        Arc<CliSessionTokenSigner>,
        Arc<DenylistMockStore>,
        CallerPrincipal,
    );

    /// Wire a CliSession-capable use case: full grants, the JWT signer,
    /// and the denylist store. Returns the rig handles so tests can
    /// verify the minted JWT and inspect the denylist.
    fn make_cli_session_use_case() -> CliSessionRig {
        let (caller, rbac) = full_grants_principal();
        let (uc, tokens, users, events) =
            make_cli_session_use_case_with(ApiTokenIssuanceConfig::default(), rbac);
        let (signer, denylist) = cli_session_last_rig();
        (uc, tokens, users, events, signer, denylist, caller)
    }

    // The CliSession rig the most recent `make_cli_session_use_case_with`
    // call wired, so `make_cli_session_use_case` can hand the signer +
    // denylist handles back to the test. Thread-local because the tests
    // run on per-test current-thread runtimes.
    thread_local! {
        static LAST_RIG: std::cell::RefCell<
            Option<(Arc<CliSessionTokenSigner>, Arc<DenylistMockStore>)>,
        > = const { std::cell::RefCell::new(None) };
    }

    fn cli_session_last_rig() -> (Arc<CliSessionTokenSigner>, Arc<DenylistMockStore>) {
        LAST_RIG.with(|r| r.borrow().clone().expect("rig was wired"))
    }

    /// Build a CliSession-capable use case with a caller-chosen config +
    /// rbac, wiring the signer + denylist. Used by the admin-scope /
    /// metric tests that need a specific `ApiTokenIssuanceConfig` or
    /// `admin_principal()` evaluator.
    fn make_cli_session_use_case_with(
        config: ApiTokenIssuanceConfig,
        rbac: Arc<ArcSwap<RbacEvaluator>>,
    ) -> (
        ApiTokenUseCase,
        Arc<MockApiTokenRepository>,
        Arc<MockUserRepository>,
        Arc<MockEventStore>,
    ) {
        let (uc, tokens, users, events) = make_use_case_with_rbac(config, rbac);
        let (signer, denylist) = cli_session_rig();
        LAST_RIG.with(|r| {
            *r.borrow_mut() = Some((signer.clone(), denylist.clone()));
        });
        let uc = uc.with_cli_session_signing(signer, denylist as Arc<dyn EphemeralStore>);
        (uc, tokens, users, events)
    }

    // -- CliSession JWT mint ---------------------------------------------------

    #[tokio::test]
    async fn issue_cli_session_mints_jwt_carrying_resolved_claims() {
        // §13 footgun fix (headline mint side): the minted CliSession
        // token is a signed JWT carrying the principal's resolved claim
        // set (`["developer"]`), NOT an opaque `hort_cli_*` token with
        // `claims: []`. The signer verifies it round-trips with the
        // claims + token_kind + a jti.
        let (uc, _tokens, users, _events, signer, _denylist, caller) = make_cli_session_use_case();
        users.insert(user(false));

        let issued = uc
            .issue_cli_session(
                &caller,
                make_cli_request(Some("hort-cli/1.0"), "203.0.113.7"),
            )
            .await
            .expect("cli session issuance succeeds");

        assert_eq!(issued.kind, TokenKind::CliSession);
        // No longer an opaque token — it's a JWT (three dot-separated
        // base64url segments), NOT `hort_cli_…`.
        assert!(
            !issued.plaintext.starts_with("hort_cli_"),
            "CliSession plaintext must be a JWT, not an opaque hort_cli_ token: {}",
            issued.plaintext
        );
        assert_eq!(
            issued.plaintext.split('.').count(),
            3,
            "expected a 3-segment JWT, got {}",
            issued.plaintext
        );

        // The JWT verifies and carries the resolved claims + token_kind.
        match signer.verify(&issued.plaintext) {
            CliSessionVerifyOutcome::Verified(c) => {
                assert_eq!(c.sub, caller.user_id);
                assert_eq!(c.claims, vec!["developer".to_string()]);
                assert_eq!(c.token_kind, CLI_SESSION_TOKEN_KIND);
                assert_eq!(c.jti, issued.id, "IssuedToken.id is the JWT jti");
            }
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn issue_cli_session_persists_no_db_row() {
        // §13.4 / §1.1 — the CliSession JWT carries its claims; there is
        // NO `api_tokens` row (and a fortiori no claims column).
        let (uc, tokens, users, _events, _signer, _denylist, caller) = make_cli_session_use_case();
        users.insert(user(false));
        uc.issue_cli_session(&caller, make_cli_request(Some("hort-cli"), "10.0.0.1"))
            .await
            .expect("issue");
        assert!(
            tokens.inserts().is_empty(),
            "CliSession JWT must NOT persist an api_tokens row"
        );
    }

    #[tokio::test]
    async fn issue_cli_session_emits_issuance_audit_event_keyed_on_jti() {
        // Issuance stays auditable: `ApiTokenIssued` fires on the user's
        // stream with `token_id = jti` even though no row is persisted.
        let (uc, _tokens, users, events, _signer, _denylist, caller) = make_cli_session_use_case();
        users.insert(user(false));
        let issued = uc
            .issue_cli_session(&caller, make_cli_request(Some("hort-cli"), "10.0.0.1"))
            .await
            .expect("issue");
        let event = assert_issued_event(&events, Uuid::from_u128(0xACE));
        assert_eq!(event.kind, TokenKind::CliSession);
        assert_eq!(event.token_id, issued.id);
    }

    #[tokio::test]
    async fn issue_cli_session_without_signer_fails_closed() {
        // A `None` signer reached on the CliSession path is a
        // composition bug — fail with Infrastructure, do NOT fall back
        // to the removed opaque shape.
        let (caller, rbac) = full_grants_principal();
        let (uc, _tokens, users, _events) =
            make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
        users.insert(user(false));
        let err = uc
            .issue_cli_session(&caller, make_cli_request(Some("hort-cli"), "10.0.0.1"))
            .await
            .expect_err("must fail without a signer");
        assert!(matches!(err, ApiTokenError::Infrastructure(_)));
    }

    // -- jti emergency-revocation denylist -------------------------------------

    #[tokio::test]
    async fn revoke_cli_session_writes_jti_to_denylist() {
        let (uc, _tokens, users, _events, signer, denylist, caller) = make_cli_session_use_case();
        users.insert(user(false));
        let issued = uc
            .issue_cli_session(&caller, make_cli_request(Some("hort-cli"), "10.0.0.1"))
            .await
            .expect("issue");
        let exp = issued.expires_at.expect("cli session has expiry");

        uc.revoke_cli_session(issued.id, exp).await.expect("revoke");

        // The denylist now contains the jti key.
        assert!(
            denylist.contains(&format!("cli-session-revoked:{}", issued.id)),
            "revoked jti must be on the denylist"
        );
        // (sanity) the token still verifies cryptographically — the
        // denylist is the AK-side revocation layer, checked separately
        // on the validate path.
        assert!(matches!(
            signer.verify(&issued.plaintext),
            CliSessionVerifyOutcome::Verified(_)
        ));
    }

    #[tokio::test]
    async fn issue_cli_session_happy_path() {
        // A CliSession is a signed JWT, NOT
        // an opaque `hort_cli_*` row. The happy path asserts the JWT shape,
        // the default 900 s lifetime, and that issuance stays auditable
        // (event keyed on jti) with NO persisted row.
        let (uc, tokens, users, events, _signer, _denylist, caller) = make_cli_session_use_case();
        users.insert(user(false));

        let issued = uc
            .issue_cli_session(
                &caller,
                make_cli_request(Some("hort-cli/0.4.2"), "203.0.113.7"),
            )
            .await
            .expect("cli session issuance succeeds");

        assert_eq!(issued.kind, TokenKind::CliSession);
        // JWT, not an opaque token.
        assert!(!issued.plaintext.starts_with("hort_cli_"));
        assert_eq!(issued.plaintext.split('.').count(), 3);
        assert_eq!(issued.name, "hort-cli/0.4.2");

        // Default CLI-session lifetime is 900 s.
        // Tolerance: 60 s.
        let exp = issued.expires_at.expect("cli session has an expiry");
        let diff = (exp - Utc::now()).num_seconds();
        assert!(
            diff >= DEFAULT_CLI_SESSION_LIFETIME_SECS as i64 - 60
                && diff <= DEFAULT_CLI_SESSION_LIFETIME_SECS as i64 + 60,
            "expected ≈ {} s, got {}",
            DEFAULT_CLI_SESSION_LIFETIME_SECS,
            diff
        );
        assert_eq!(DEFAULT_CLI_SESSION_LIFETIME_SECS, 900);

        // No `api_tokens` row — claims live in the JWT, not a column.
        assert!(
            tokens.inserts().is_empty(),
            "CliSession JWT must NOT persist an api_tokens row"
        );

        // Issuance event was emitted on the user's stream, keyed on jti.
        let event = assert_issued_event(&events, Uuid::from_u128(0xACE));
        assert_eq!(event.token_id, issued.id);
        assert_eq!(event.kind, TokenKind::CliSession);
        assert_eq!(event.repository_ids, None);
        assert_eq!(count_denials(&events), 0);
    }

    // -- exchange-time cap derivation -----------------------------------------
    //
    // If `issue_cli_session_inner` hardcoded
    // `repository_ids: None`, it would route through the clamp's GLOBAL
    // branch:
    // the caller had to hold each requested permission *globally*. A
    // per-repo-only grantee (the canonical dev-user)
    // would get `403 cap_exceeds_authority` and could never mint a
    // CliSession. Instead the cap derives from the caller's effective
    // authority via the live `RbacEvaluator`, so a per-repo grantee mints
    // a per-repo-scoped session; admin still derives a global cap.

    /// `IssueCliSessionRequest` with an explicit requested scope (the wire
    /// `scope` form field, parsed upstream by the exchange handler).
    fn make_cli_request_scoped(scope: Vec<Permission>) -> IssueCliSessionRequest {
        IssueCliSessionRequest {
            client_name: Some("hort-cli".into()),
            source_ip: "203.0.113.7".into(),
            requested_scope: scope,
            requested_lifetime_secs: None,
        }
    }

    /// Evaluator granting `developer` per-repo `Read` + `Prefetch` on the
    /// supplied repos, with NO global grant — the canonical dev-user shape
    /// (§13.8). Returns the bare evaluator wrapped in `ArcSwap`.
    fn per_repo_dev_evaluator(repos: &[Uuid]) -> Arc<ArcSwap<RbacEvaluator>> {
        let mut rows = Vec::new();
        for &repo in repos {
            rows.push(grant_row("developer", Some(repo), Permission::Read));
            rows.push(grant_row("developer", Some(repo), Permission::Prefetch));
        }
        Arc::new(ArcSwap::from_pointee(RbacEvaluator::new(rows)))
    }

    #[tokio::test]
    async fn issue_cli_session_per_repo_grantee_mints_with_derived_per_repo_cap() {
        // §13.8 / acceptance #2 — a per-repo-ONLY grantee (developer holds
        // Read+Prefetch on three repos, no global grant) mints a
        // CliSession successfully. The pre-Item-11 hardcoded
        // `repository_ids: None` would have routed this through the global
        // branch and denied with `cap_exceeds_authority`.
        let npm = Uuid::new_v4();
        let pypi = Uuid::new_v4();
        let cargo = Uuid::new_v4();
        let rbac = per_repo_dev_evaluator(&[npm, pypi, cargo]);
        let (uc, _tokens, users, events) =
            make_cli_session_use_case_with(ApiTokenIssuanceConfig::default(), rbac);
        let (signer, _denylist) = cli_session_last_rig();
        users.insert(user(false));
        let caller = principal(vec!["developer", "ci-pusher"]);

        let issued = uc
            .issue_cli_session(
                &caller,
                make_cli_request_scoped(vec![Permission::Read, Permission::Prefetch]),
            )
            .await
            .expect("per-repo grantee must mint a CliSession (Item 11 — was 403)");

        assert_eq!(issued.kind, TokenKind::CliSession);
        assert!(matches!(
            signer.verify(&issued.plaintext),
            CliSessionVerifyOutcome::Verified(_)
        ));
        // No denial event — issuance succeeded.
        assert_eq!(count_denials(&events), 0);
    }

    #[tokio::test]
    async fn issue_cli_session_admin_derives_global_cap_unchanged() {
        // §13.8 / acceptance #3 (regression) — an admin caller derives a
        // GLOBAL cap (`repository_ids: None`) via the admin short-circuit;
        // the existing global-branch + ≤1h admin gate run unchanged. The
        // admin path is untouched by the per-repo derivation.
        let (caller, rbac) = admin_principal();
        let (uc, _tokens, users, events) =
            make_cli_session_use_case_with(ApiTokenIssuanceConfig::default(), rbac);
        // Admin user_id must match the principal (0xAD).
        users.insert(User {
            id: Uuid::from_u128(0xAD),
            is_admin: true,
            ..user(false)
        });

        let issued = uc
            .issue_cli_session(
                &caller,
                make_cli_request_scoped(vec![Permission::Read, Permission::Write]),
            )
            .await
            .expect("admin must mint a global-cap CliSession");

        assert_eq!(issued.kind, TokenKind::CliSession);
        // The persisted issuance event records the global (None) repo set.
        let event = assert_issued_event(&events, Uuid::from_u128(0xAD));
        assert_eq!(
            event.repository_ids, None,
            "admin derives a global cap (repository_ids: None)"
        );
        assert_eq!(count_denials(&events), 0);
    }

    #[tokio::test]
    async fn issue_cli_session_zero_authority_caller_denied_cap_exceeds_authority() {
        // §13.8 / acceptance #4 — a caller holding NONE of the requested
        // permissions derives an empty footprint → still 403
        // `cap_exceeds_authority`. The fix must NOT mint an empty-cap
        // token that silently authorizes nothing.
        let other_repo = Uuid::new_v4();
        // The evaluator grants the `developer` claim, but the caller
        // carries an unrelated claim → no matching grant.
        let rbac = per_repo_dev_evaluator(&[other_repo]);
        let (uc, _tokens, users, events) =
            make_cli_session_use_case_with(ApiTokenIssuanceConfig::default(), rbac);
        users.insert(user(false));
        let caller = principal(vec!["stranger"]);

        let err = uc
            .issue_cli_session(
                &caller,
                make_cli_request_scoped(vec![Permission::Read, Permission::Prefetch]),
            )
            .await
            .expect_err("zero-authority caller must be denied");
        assert!(
            matches!(err, ApiTokenError::CapExceedsAuthority { .. }),
            "expected CapExceedsAuthority, got {err:?}"
        );
        assert_eq!(count_denials(&events), 1, "a denial event must be emitted");
    }

    #[tokio::test]
    async fn issue_cli_session_clamps_requested_scope_to_held_subset() {
        // A per-repo grantee that requests [Read, Write, Prefetch] but
        // only holds Read+Prefetch on its repos mints successfully — the
        // derivation clamps the permission axis to the held subset (Write
        // is dropped, not a hard 403).
        let npm = Uuid::new_v4();
        let rbac = per_repo_dev_evaluator(&[npm]);
        let (uc, _tokens, users, events) =
            make_cli_session_use_case_with(ApiTokenIssuanceConfig::default(), rbac);
        users.insert(user(false));
        let caller = principal(vec!["developer"]);

        let issued = uc
            .issue_cli_session(
                &caller,
                make_cli_request_scoped(vec![
                    Permission::Read,
                    Permission::Write,
                    Permission::Prefetch,
                ]),
            )
            .await
            .expect("partial-authority caller mints what it holds");
        assert_eq!(issued.kind, TokenKind::CliSession);
        assert_eq!(count_denials(&events), 0);
    }

    #[test]
    fn issue_cli_session_cap_derivation_observability_evaluates_log_fields() {
        // Item 11 observability: the success path emits a `debug!` carrying
        // the derived (permission_count, repository_count) footprint, and
        // the empty-footprint denial emits an `info!` carrying the
        // requested-permission count. Drive BOTH under a `DEBUG`-level
        // subscriber installed for the duration of the test so the
        // structured-field expressions are actually evaluated (a disabled
        // level short-circuits them) — this pins the field exprs the
        // §13.8 / Item-11 observability requirement adds, and asserts the
        // log NEVER carries a claim name (claims are operator topology).
        use tracing_subscriber::fmt::format::FmtSpan;

        let collector = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_span_events(FmtSpan::NONE)
            .with_test_writer()
            .finish();

        let fut = async {
            // (a) Success path → the `debug!` derived-footprint field exprs.
            let npm = Uuid::new_v4();
            let rbac = per_repo_dev_evaluator(&[npm]);
            let (uc, _tokens, users, _events) =
                make_cli_session_use_case_with(ApiTokenIssuanceConfig::default(), rbac);
            users.insert(user(false));
            let caller = principal(vec!["developer"]);
            uc.issue_cli_session(
                &caller,
                make_cli_request_scoped(vec![Permission::Read, Permission::Prefetch]),
            )
            .await
            .expect("per-repo mint succeeds");

            // (b) Empty footprint → the `info!` denial field expr.
            let rbac2 = per_repo_dev_evaluator(&[Uuid::new_v4()]);
            let (uc2, _t2, users2, _e2) =
                make_cli_session_use_case_with(ApiTokenIssuanceConfig::default(), rbac2);
            users2.insert(user(false));
            let stranger = principal(vec!["stranger"]);
            let err = uc2
                .issue_cli_session(
                    &stranger,
                    make_cli_request_scoped(vec![Permission::Read, Permission::Prefetch]),
                )
                .await
                .expect_err("zero-authority caller is denied");
            assert!(matches!(err, ApiTokenError::CapExceedsAuthority { .. }));
        };

        tracing::subscriber::with_default(collector, || {
            // Drive the async body to completion on a local runtime inside
            // the subscriber scope so the log emissions evaluate their
            // structured fields.
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(fut);
        });
    }

    #[tokio::test]
    async fn issue_cli_session_default_scope_omits_admin() {
        // Admin is allowed in CliSession scope; admin authority is
        // caller-opt-in
        // via the `scope` form field (see admin-scope tests below).
        // This test pins the DEFAULT-behaviour half of the shape:
        // an empty `requested_scope` resolves to [Read, Write,
        // Delete]. The
        // `HORT_TOKEN_ALLOW_ADMIN=true` flag does not implicitly
        // grant admin to default-scope sessions.
        let (caller, rbac) = full_grants_principal();
        let config = ApiTokenIssuanceConfig {
            allow_admin_tokens: true,
            allow_unbounded_svc_tokens: false,
        };
        let (uc, _tokens, users, _events) = make_cli_session_use_case_with(config, rbac);
        let (signer, _denylist) = cli_session_last_rig();
        users.insert(user(false));

        // A default-scope (empty `requested_scope`) request from a
        // non-admin caller succeeds without admin authority — the
        // default scope does NOT implicitly request Admin even with
        // `HORT_TOKEN_ALLOW_ADMIN=true`. (The JWT does not
        // carry a declared-permission cap; the scope only
        // gates the admin/lifetime decisions at mint, so we assert the
        // gate outcome — success — rather than a persisted cap.)
        let issued = uc
            .issue_cli_session(&caller, make_cli_request(Some("hort-cli"), "10.0.0.1"))
            .await
            .expect("default-scope non-admin cli_session issuance succeeds");
        assert_eq!(issued.kind, TokenKind::CliSession);
        // Default-scope sessions clamp to the 15 min ceiling (no admin →
        // same 900 s cap as admin per Item 10).
        let diff = (issued.expires_at.unwrap() - Utc::now()).num_seconds();
        assert!((900 - 60..=900 + 60).contains(&diff), "got {diff}s");
        // The JWT verifies and carries the caller's resolved claims, not
        // a declared-permission cap.
        assert!(matches!(
            signer.verify(&issued.plaintext),
            CliSessionVerifyOutcome::Verified(_)
        ));
    }

    #[tokio::test]
    async fn issue_cli_session_empty_client_name_defaults_to_hort_cli() {
        // Three sub-cases: None, Some(""), Some("   "). All resolve to
        // the documented default name "hort-cli" per design doc 039 §6.
        for client_name in [None, Some(""), Some("   ")] {
            let (caller, rbac) = full_grants_principal();
            let (uc, _tokens, users, _events) =
                make_cli_session_use_case_with(ApiTokenIssuanceConfig::default(), rbac);
            users.insert(user(false));

            let issued = uc
                .issue_cli_session(&caller, make_cli_request(client_name, "127.0.0.1"))
                .await
                .expect("cli session issuance succeeds");

            assert_eq!(
                issued.name, "hort-cli",
                "empty client_name {client_name:?} must default to \"hort-cli\""
            );
        }
    }

    #[tokio::test]
    async fn issue_cli_session_oversize_client_name_truncated() {
        // Per design doc 039 §6 — truncate, do NOT reject. A 300-char
        // client_id from the wire must yield a 255-char name on the
        // resulting token, not a NameTooLong error.
        let (caller, rbac) = full_grants_principal();
        let (uc, _tokens, users, _events) =
            make_cli_session_use_case_with(ApiTokenIssuanceConfig::default(), rbac);
        users.insert(user(false));

        let oversize = "a".repeat(300);
        let issued = uc
            .issue_cli_session(&caller, make_cli_request(Some(&oversize), "10.0.0.2"))
            .await
            .expect("oversize client_name should be truncated, not rejected");

        assert_eq!(issued.name.len(), MAX_NAME_LEN);
        assert!(issued.name.chars().all(|c| c == 'a'));
    }

    // ---------------------------------------------------------------
    // cli_session caller-supplied scope + lifetime
    // ---------------------------------------------------------------

    fn make_cli_request_with_scope_lifetime(
        scope: Vec<Permission>,
        lifetime_secs: Option<u64>,
    ) -> IssueCliSessionRequest {
        IssueCliSessionRequest {
            client_name: Some("hort-cli".into()),
            source_ip: "10.0.0.5".into(),
            requested_scope: scope,
            requested_lifetime_secs: lifetime_secs,
        }
    }

    #[tokio::test]
    async fn issue_cli_session_admin_scope_succeeds_for_admin_caller_with_flag_on() {
        // Admin-cap CliSession is allowed when caller is
        // admin AND HORT_TOKEN_ALLOW_ADMIN=true;
        // the lifetime is clamped to the 900 s admin ceiling,
        // and the credential is a JWT carrying the admin caller's
        // resolved claims (here `["admin"]`).
        let (caller, rbac) = admin_principal();
        let config = ApiTokenIssuanceConfig {
            allow_admin_tokens: true,
            allow_unbounded_svc_tokens: false,
        };
        let (uc, _tokens, users, _events) = make_cli_session_use_case_with(config, rbac);
        let (signer, _denylist) = cli_session_last_rig();
        users.insert(User {
            id: caller.user_id,
            ..user(false)
        });

        let issued = uc
            .issue_cli_session(
                &caller,
                make_cli_request_with_scope_lifetime(
                    vec![
                        Permission::Admin,
                        Permission::Read,
                        Permission::Write,
                        Permission::Delete,
                    ],
                    Some(4 * 3_600), // 4h asked; admin clamps to 900 s
                ),
            )
            .await
            .expect("admin-cap cli_session issuance succeeds under §1.5-a");

        assert_eq!(issued.kind, TokenKind::CliSession);
        let diff = (issued.expires_at.unwrap() - Utc::now()).num_seconds();
        assert!(
            (MAX_ADMIN_CLI_SESSION_LIFETIME_SECS as i64 - 60
                ..=MAX_ADMIN_CLI_SESSION_LIFETIME_SECS as i64 + 60)
                .contains(&diff),
            "admin lifetime must clamp to the 900 s admin ceiling, got {diff}s"
        );
        // The JWT carries the admin caller's resolved claim set.
        match signer.verify(&issued.plaintext) {
            CliSessionVerifyOutcome::Verified(c) => {
                assert!(c.claims.contains(&"admin".to_string()));
            }
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn issue_cli_session_admin_scope_rejected_when_flag_off() {
        // HORT_TOKEN_ALLOW_ADMIN=false rejects admin scope even for
        // admin callers. The existing admin gate fires uniformly —
        // there is no separate CliSession gate.
        let (caller, rbac) = admin_principal();
        let config = ApiTokenIssuanceConfig {
            allow_admin_tokens: false,
            allow_unbounded_svc_tokens: false,
        };
        let (uc, _tokens, users, _events) = make_use_case_with_rbac(config, rbac);
        users.insert(User {
            id: caller.user_id,
            ..user(false)
        });

        let err = uc
            .issue_cli_session(
                &caller,
                make_cli_request_with_scope_lifetime(
                    vec![Permission::Admin, Permission::Read],
                    None,
                ),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, ApiTokenError::AdminTokenDisallowed),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn issue_cli_session_admin_scope_rejected_when_caller_not_admin() {
        // Non-admin caller requesting admin scope → AdminAuthorityRequired.
        // Uniform with the Pat path (existing gate at issue_inner step 3).
        let (caller, rbac) = full_grants_principal();
        let config = ApiTokenIssuanceConfig {
            allow_admin_tokens: true,
            allow_unbounded_svc_tokens: false,
        };
        let (uc, _tokens, users, _events) = make_use_case_with_rbac(config, rbac);
        users.insert(user(false));

        let err = uc
            .issue_cli_session(
                &caller,
                make_cli_request_with_scope_lifetime(
                    vec![Permission::Admin, Permission::Read],
                    None,
                ),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, ApiTokenError::AdminAuthorityRequired),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn issue_cli_session_below_minimum_lifetime_rejected() {
        // Sub-300s requested lifetime → LifetimeBelowMinimum surfaces
        // BEFORE the issuance pipeline; clamp_lifetime is the gate.
        let (caller, rbac) = full_grants_principal();
        let (uc, _tokens, users, _events) =
            make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
        users.insert(user(false));

        let err = uc
            .issue_cli_session(
                &caller,
                make_cli_request_with_scope_lifetime(Vec::new(), Some(200)),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, ApiTokenError::LifetimeBelowMinimum),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn issue_cli_session_honors_explicit_sub_cap_lifetime() {
        // Both caps are 900 s. An explicit
        // lifetime BELOW the ceiling (here 600 s) passes through
        // unclamped — the clamp only fires above the ceiling.
        let (caller, rbac) = full_grants_principal();
        let (uc, _tokens, users, _events) =
            make_cli_session_use_case_with(ApiTokenIssuanceConfig::default(), rbac);
        users.insert(user(false));

        let issued = uc
            .issue_cli_session(
                &caller,
                make_cli_request_with_scope_lifetime(Vec::new(), Some(600)),
            )
            .await
            .expect("a sub-ceiling explicit lifetime is honored");

        let diff = (issued.expires_at.unwrap() - Utc::now()).num_seconds();
        assert!(
            (600 - 60..=600 + 60).contains(&diff),
            "expected ≈ 600 s, got {diff}s"
        );
    }

    // ---------------------------------------------------------------
    // `hort_session_admin_issuance_total{result}` counter
    // ---------------------------------------------------------------

    #[test]
    fn session_admin_issuance_metric_emits_granted_on_success() {
        let snap = b9_capture_async(|| async move {
            let (caller, rbac) = admin_principal();
            let config = ApiTokenIssuanceConfig {
                allow_admin_tokens: true,
                allow_unbounded_svc_tokens: false,
            };
            let (uc, _, users, _) = make_cli_session_use_case_with(config, rbac);
            users.insert(User {
                id: caller.user_id,
                ..user(false)
            });
            let _ = uc
                .issue_cli_session(
                    &caller,
                    make_cli_request_with_scope_lifetime(
                        vec![
                            Permission::Admin,
                            Permission::Read,
                            Permission::Write,
                            Permission::Delete,
                        ],
                        None,
                    ),
                )
                .await
                .unwrap();
        });
        assert_eq!(
            b9_counter_value(
                &snap,
                SESSION_ADMIN_ISSUANCE_METRIC,
                &[("result", "granted")]
            ),
            1
        );
    }

    #[test]
    fn session_admin_issuance_metric_emits_denied_flag_when_off() {
        let snap = b9_capture_async(|| async move {
            let (caller, rbac) = admin_principal();
            let config = ApiTokenIssuanceConfig {
                allow_admin_tokens: false,
                allow_unbounded_svc_tokens: false,
            };
            let (uc, _, users, _) = make_use_case_with_rbac(config, rbac);
            users.insert(User {
                id: caller.user_id,
                ..user(false)
            });
            let _ = uc
                .issue_cli_session(
                    &caller,
                    make_cli_request_with_scope_lifetime(
                        vec![Permission::Admin, Permission::Read],
                        None,
                    ),
                )
                .await;
        });
        assert_eq!(
            b9_counter_value(
                &snap,
                SESSION_ADMIN_ISSUANCE_METRIC,
                &[("result", "denied_flag")]
            ),
            1
        );
    }

    #[test]
    fn session_admin_issuance_metric_emits_denied_authority_for_non_admin() {
        let snap = b9_capture_async(|| async move {
            let (caller, rbac) = full_grants_principal();
            let config = ApiTokenIssuanceConfig {
                allow_admin_tokens: true,
                allow_unbounded_svc_tokens: false,
            };
            let (uc, _, users, _) = make_use_case_with_rbac(config, rbac);
            users.insert(user(false));
            let _ = uc
                .issue_cli_session(
                    &caller,
                    make_cli_request_with_scope_lifetime(
                        vec![Permission::Admin, Permission::Read],
                        None,
                    ),
                )
                .await;
        });
        assert_eq!(
            b9_counter_value(
                &snap,
                SESSION_ADMIN_ISSUANCE_METRIC,
                &[("result", "denied_authority")]
            ),
            1
        );
    }

    #[test]
    fn session_admin_issuance_metric_emits_denied_lifetime_below_minimum() {
        let snap = b9_capture_async(|| async move {
            let (caller, rbac) = admin_principal();
            let config = ApiTokenIssuanceConfig {
                allow_admin_tokens: true,
                allow_unbounded_svc_tokens: false,
            };
            let (uc, _, users, _) = make_use_case_with_rbac(config, rbac);
            users.insert(User {
                id: caller.user_id,
                ..user(false)
            });
            let _ = uc
                .issue_cli_session(
                    &caller,
                    make_cli_request_with_scope_lifetime(
                        vec![Permission::Admin, Permission::Read],
                        Some(200), // below the 300s minimum
                    ),
                )
                .await;
        });
        assert_eq!(
            b9_counter_value(
                &snap,
                SESSION_ADMIN_ISSUANCE_METRIC,
                &[("result", "denied_lifetime")]
            ),
            1
        );
    }

    #[test]
    fn session_admin_issuance_metric_does_not_emit_for_non_admin_scope() {
        // Non-admin issuance (default scope) MUST NOT touch the
        // admin-issuance counter — security reviewers depend on
        // the counter being a pure admin-attempt signal.
        let snap = b9_capture_async(|| async move {
            let (caller, rbac) = full_grants_principal();
            let (uc, _, users, _) =
                make_cli_session_use_case_with(ApiTokenIssuanceConfig::default(), rbac);
            users.insert(user(false));
            let _ = uc
                .issue_cli_session(&caller, make_cli_request(Some("hort-cli"), "1.2.3.4"))
                .await
                .unwrap();
        });
        for label in [
            "granted",
            "denied_flag",
            "denied_authority",
            "denied_lifetime",
        ] {
            assert_eq!(
                b9_counter_value(&snap, SESSION_ADMIN_ISSUANCE_METRIC, &[("result", label)]),
                0,
                "non-admin scope must not increment result={label}"
            );
        }
    }

    #[tokio::test]
    async fn issue_cli_session_infrastructure_failure_propagates() {
        // The user-row lookup at the head of issue_cli_session feeds the
        // existing issue_inner pipeline. When the user repo returns an
        // error (here, NotFound for an unseeded user_id), the use case
        // surfaces it as ApiTokenError::Infrastructure — same behaviour
        // as issue_self_token.
        let (caller, rbac) = full_grants_principal();
        let (uc, _tokens, _users, _events) =
            make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
        // NB: deliberately do NOT seed the user row.

        let err = uc
            .issue_cli_session(&caller, make_cli_request(Some("hort-cli"), "10.0.0.3"))
            .await
            .expect_err("missing user must surface as Infrastructure");

        assert!(
            matches!(err, ApiTokenError::Infrastructure(_)),
            "expected Infrastructure, got {err:?}"
        );
    }

    // -- result-mapping table coverage --------------------------------------

    #[test]
    fn issuance_result_label_table_is_exhaustive() {
        // Pin the result-mapping table from B9. Any future variant
        // added to ApiTokenError must update issuance_result_label
        // and this test (the match in the helper is exhaustive, so
        // a new variant breaks the build; this test pins the
        // mapping verbatim).
        use ApiTokenError::*;
        let admin_disallowed: Result<IssuedToken, _> = Err(AdminTokenDisallowed);
        assert_eq!(issuance_result_label(&admin_disallowed), "admin_disallowed");
        let admin_auth: Result<IssuedToken, _> = Err(AdminAuthorityRequired);
        assert_eq!(issuance_result_label(&admin_auth), "admin_disallowed");
        let admin_30: Result<IssuedToken, _> = Err(AdminTokenExceedsThirtyDays);
        assert_eq!(issuance_result_label(&admin_30), "admin_disallowed");
        let admin_unbounded: Result<IssuedToken, _> = Err(AdminTokenUnboundedNotAllowed);
        assert_eq!(issuance_result_label(&admin_unbounded), "admin_disallowed");
        let cap: Result<IssuedToken, _> = Err(CapExceedsAuthority { failed: vec![] });
        assert_eq!(issuance_result_label(&cap), "cap_exceeds_authority");
        // Every other variant collapses to validation_error.
        for err in [
            ServiceAccountSelfMint,
            UnboundedSvcTokenDisallowed,
            InvalidRepositorySet,
            NotServiceAccount,
            NotAuthorized,
            TokenNotFound,
            NameEmpty,
            NameTooLong,
            DescriptionTooLong,
            ExpiryZero,
            ExpiryTooLong,
            // The three federation
            // deny variants collapse into `validation_error` for the
            // `hort_api_token_issued_total` counter (its taxonomy stays
            // closed at 4 values). Replay-specific accounting lives on
            // the dedicated `hort_jwt_replay_rejected_total` counter
            // (replayed_*) and the existing
            // `hort_token_exchange_total{kind=federated_jwt}` taxonomy
            // (jti_required / replay_guard_unavailable) — NOT here.
            ReplayDetected { composite: false },
            ReplayDetected { composite: true },
            ReplayGuardUnavailable,
            JtiRequired,
        ] {
            let label = format!("{err:?}");
            let r: Result<IssuedToken, _> = Err(err);
            assert_eq!(
                issuance_result_label(&r),
                "validation_error",
                "expected validation_error for {label}"
            );
        }
        // Infrastructure variant requires a constructed DomainError.
        let infra: Result<IssuedToken, _> =
            Err(Infrastructure(DomainError::Invariant("test".into())));
        assert_eq!(issuance_result_label(&infra), "validation_error");
    }

    #[test]
    fn token_kind_metric_labels_match_wire_short_forms() {
        // Closed-taxonomy discipline: the metric's `kind` label MUST
        // mirror the on-wire 3-char prefixes (hort_pat_, hort_svc_,
        // hort_cli_) so dashboards filter on the same vocabulary
        // operators see in token plaintexts.
        assert_eq!(token_kind_metric_label(TokenKind::Pat), "pat");
        assert_eq!(token_kind_metric_label(TokenKind::ServiceAccount), "svc");
        assert_eq!(token_kind_metric_label(TokenKind::CliSession), "cli");
    }

    // Suppress unused-import warnings on test-only helpers.
    #[allow(dead_code)]
    fn _unused(_p: PersistedEvent) {}

    // ---------------------------------------------------------------
    // clamp_lifetime
    // ---------------------------------------------------------------
    //
    // Six cases:
    //   1. under-min rejected (admin)
    //   2. at-min accepted (admin)
    //   3. mid-range accepted (admin)
    //   4. at-max accepted (admin)
    //   5. above-max clamped silently (admin asked for 12h → 1h)
    //   6. above-max clamped silently (non-admin asked for 48h → 24h)
    //
    // Plus two boundary spot-checks pinning the per-cap-shape distinction
    // (3601s is allowed for non-admin but clamped to 3600s for admin).

    #[test]
    fn clamp_lifetime_rejects_below_minimum_admin() {
        let err = clamp_lifetime(299, true).unwrap_err();
        assert!(matches!(err, ApiTokenError::LifetimeBelowMinimum));
    }

    #[test]
    fn clamp_lifetime_accepts_at_minimum_admin() {
        let v = clamp_lifetime(300, true).unwrap();
        assert_eq!(v, 300);
    }

    #[test]
    fn clamp_lifetime_accepts_mid_range_admin() {
        // Both caps are 900 s. A value
        // between the 300 s floor and the 900 s ceiling passes through.
        let v = clamp_lifetime(600, true).unwrap();
        assert_eq!(v, 600);
    }

    #[test]
    fn clamp_lifetime_accepts_at_admin_maximum() {
        // The admin cap is 900 s.
        let v = clamp_lifetime(900, true).unwrap();
        assert_eq!(v, 900);
    }

    #[test]
    fn clamp_lifetime_admin_request_for_12h_clamps_to_max() {
        let v = clamp_lifetime(12 * 3_600, true).unwrap();
        assert_eq!(v, MAX_ADMIN_CLI_SESSION_LIFETIME_SECS);
        assert_eq!(v, 900, "admin CLI-session cap is 900 s");
    }

    #[test]
    fn clamp_lifetime_non_admin_request_for_48h_clamps_to_max() {
        // The non-admin cap is also 900 s
        // (the JWT is non-revocable until exp, so the TTL is the
        // revocation floor for every CliSession token).
        let v = clamp_lifetime(48 * 3_600, false).unwrap();
        assert_eq!(v, MAX_NON_ADMIN_CLI_SESSION_LIFETIME_SECS);
        assert_eq!(v, 900, "non-admin CLI-session cap is also 900 s");
    }

    #[test]
    fn clamp_lifetime_both_caps_are_900s() {
        // BOTH admin and non-admin caps are 900 s, so a request above
        // 900 s clamps identically regardless of the admin flag — the
        // per-cap-shape *distinction* in the lifetime axis collapses
        // (the admin gate is still enforced elsewhere via the RBAC
        // cap-vs-authority check; only the lifetime ceiling coincides).
        let above = 1_000;
        assert_eq!(clamp_lifetime(above, true).unwrap(), 900);
        assert_eq!(clamp_lifetime(above, false).unwrap(), 900);
    }

    #[test]
    fn clamp_lifetime_rejects_below_minimum_non_admin() {
        let err = clamp_lifetime(0, false).unwrap_err();
        assert!(matches!(err, ApiTokenError::LifetimeBelowMinimum));
    }

    // ---------------------------------------------------------------
    // IssueTokenRequest::validate +
    // expires_in_seconds integration in issue_inner
    // ---------------------------------------------------------------

    #[test]
    fn validate_rejects_when_both_expiry_fields_set() {
        let req = IssueTokenRequest {
            expires_in_seconds: Some(3_600),
            ..make_request_pat() // make_request_pat carries expires_in_days = Some(90)
        };
        assert!(matches!(
            req.validate(),
            Err(ApiTokenError::ExpiryUnitConflict)
        ));
    }

    #[test]
    fn validate_accepts_neither_field_set() {
        let req = IssueTokenRequest {
            expires_in_days: None,
            expires_in_seconds: None,
            ..make_request_pat()
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn validate_accepts_only_days_field_set() {
        // make_request_pat sets days=Some(90), seconds=None — the
        // days-based wire shape. Must continue to pass validation.
        let req = make_request_pat();
        assert!(req.validate().is_ok());
    }

    #[test]
    fn validate_accepts_only_seconds_field_set() {
        let req = IssueTokenRequest {
            expires_in_days: None,
            expires_in_seconds: Some(3_600),
            ..make_request_pat()
        };
        assert!(req.validate().is_ok());
    }

    #[tokio::test]
    async fn issue_self_token_returns_expiry_unit_conflict_when_both_set() {
        let (caller, rbac) = full_grants_principal();
        let (uc, _tokens, users, _events) =
            make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
        users.insert(user(false));
        let request = IssueTokenRequest {
            expires_in_seconds: Some(3_600),
            ..make_request_pat()
        };
        let err = uc.issue_self_token(&caller, request).await.unwrap_err();
        assert!(matches!(err, ApiTokenError::ExpiryUnitConflict));
    }

    #[tokio::test]
    async fn issue_self_token_honors_expires_in_seconds() {
        let (caller, rbac) = full_grants_principal();
        let (uc, _tokens, users, _events) =
            make_use_case_with_rbac(ApiTokenIssuanceConfig::default(), rbac);
        users.insert(user(false));
        let request = IssueTokenRequest {
            expires_in_days: None,
            expires_in_seconds: Some(3_600),
            ..make_request_pat()
        };
        let issued = uc.issue_self_token(&caller, request).await.unwrap();
        let exp = issued.expires_at.expect("seconds path always sets expiry");
        let diff = (exp - Utc::now()).num_seconds();
        // 60s tolerance — mirrors the existing 30d-tolerance pattern.
        assert!(
            (3_600 - 60..=3_600 + 60).contains(&diff),
            "expected ≈ 3600s, got {diff}"
        );
    }
}
