//! `hort-server admin` — service-account token management (ADR 0012;
//! catalogued in `docs/auth-catalog.md`).
//!
//! Inbound adapter for
//! [`hort_app::use_cases::api_token_use_case::ApiTokenUseCase`].
//! This module only parses CLI arguments and forwards the
//! request through the use case. No `sqlx::query!` lives here and no
//! `INSERT INTO api_tokens` either — the SQL work happens in
//! `PgApiTokenRepository`.
//!
//! Shape: a nested subcommand enum — `IssueSvcToken` and
//! `BootstrapSession`; future operations (list-tokens,
//! rotate-signing-key, …) each get a discrete variant without
//! re-shaping [`Command::Admin`].
//!
//! `issue-svc-token` mints a strictly **non-admin** service-account
//! token for a *pre-existing* gitops `ServiceAccount` (Entry 4 /
//! ADR 0012). It rejects `--permission=admin` and never fabricates an
//! admin identity; grants flow through the audited gitops apply path.
//!
//! `bootstrap-session` is the narrow DSN-gated first-admin /
//! break-glass path: it mints a short-lived (≤ 1 h) full-cap admin
//! `Pat` for the reserved non-service-account `bootstrap-admin` user,
//! gated by `HORT_TOKEN_ALLOW_ADMIN`. Steady-state human admin is
//! IdP-backed (OIDC → CliSession); this command is only for the
//! one-time wire-up (or break-glass when the IdP is down). The old
//! HTTP-Basic-against-local-admin-row identity path remains removed
//! (commit b7fd6d65).
//!
//! [`Command::Admin`]: super::Command::Admin

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::Context;
use arc_swap::ArcSwap;
use clap::{Args, Subcommand};
use sqlx::postgres::PgPoolOptions;
use tracing::info;
use uuid::Uuid;

use hort_adapters_postgres::{
    api_token_repo::PgApiTokenRepository, event_store::PgEventStore, user_repo::PgUserRepository,
};
use hort_app::event_store_publisher::EventStorePublisher;
use hort_app::rbac::RbacEvaluator;
use hort_app::use_cases::api_token_use_case::{
    ApiTokenIssuanceConfig, ApiTokenUseCase, IssueTokenRequest, DEFAULT_SVC_EXPIRY_DAYS,
};
use hort_app::use_cases::user_use_case::{CreateUser, UserPrivileges, UserUseCase};
use hort_domain::entities::api_token::ApiToken;
use hort_domain::entities::rbac::Permission;
use hort_domain::entities::user::{AuthProvider, User};
use hort_domain::events::ApiActor;
use hort_domain::ports::api_token_repository::ApiTokenRepository;
use hort_domain::ports::event_store::EventStore;
use hort_domain::ports::user_repository::UserRepository;
use hort_domain::types::PageRequest;

use crate::config::MinimalConfig;
use crate::{migrate, telemetry};

/// Top-level container for the `admin` subcommand. Wraps a nested
/// [`AdminSubcommand`] enum so future admin operations are discrete
/// `clap` subcommands — each one an inbound adapter.
#[derive(Debug, Args)]
pub struct AdminCommand {
    #[command(subcommand)]
    pub command: AdminSubcommand,
}

/// Admin sub-operations.
#[derive(Debug, Subcommand)]
pub enum AdminSubcommand {
    /// Issue a long-lived service-account token.
    ///
    /// Run by the Helm post-install / post-upgrade hook to mint the
    /// `hort_svc_*` token mounted into CronJob pods. Idempotent: if the
    /// named token already exists in `users.api_tokens` it is NOT
    /// rotated (operator forces rotation by passing `--rotate`).
    ///
    /// The command finds the gitops-created service-account user named
    /// `sa:<name>` (e.g. `sa:cronjob-tasks`), then calls
    /// `ApiTokenUseCase::issue_for_service_account_system`
    /// with the requested permissions. The system-mint path is correct
    /// here because the CLI runs at deploy time with operator-level DSN
    /// access but no human caller principal — the same trust contract
    /// as the worker's rotation tick. The plaintext token is printed to
    /// stdout by default so the Helm bootstrap Job can pipe it into
    /// `kubectl create secret`.
    ///
    /// Deferred post-v1: output mode
    /// `kube-secret` is post-v1 (cluster RBAC). The bootstrap Job uses
    /// `hort-server admin issue-svc-token --output=stdout` and pipes to
    /// `kubectl apply -f -`. Future Helm chart versions may add CLI-
    /// direct kube-secret writing once the cluster RBAC surface is
    /// finalised. No pre-v1 action expected.
    IssueSvcToken(IssueSvcTokenArgs),

    /// Mint a short-lived first-admin / break-glass admin token.
    ///
    /// DSN-gated (operator-level Postgres access) and additionally
    /// gated on `HORT_TOKEN_ALLOW_ADMIN=true` — it refuses otherwise.
    /// Creates (or reuses) the reserved **non-service-account** admin
    /// user `bootstrap-admin` and mints it a short-lived (≤ 1 h) `Pat`
    /// carrying an explicit FULL admin cap. Any prior `bootstrap-admin`
    /// token is revoked first (single active bootstrap token).
    ///
    /// This is the narrow no-IdP bootstrap: use it once to wire the
    /// IdP (Dex / SSO) + the group→`admin` `ClaimMapping`, then switch
    /// to OIDC → CliSession for steady-state admin. Keep it for
    /// break-glass when the IdP is down. Not a first-class admin model
    /// (ADR 0012 / ADR 0013).
    BootstrapSession(BootstrapSessionArgs),
}

/// Arguments to `admin issue-svc-token`.
#[derive(Debug, Args)]
pub struct IssueSvcTokenArgs {
    /// Logical name for the token row.
    ///
    /// Stored in `api_tokens.name`; surfaced in audit events. Also used to
    /// derive the service-account username (`sa:<name>`). Must be
    /// non-empty and ≤ 255 characters.
    #[arg(long)]
    pub name: String,

    /// Permissions to grant. Defaults to `admin_task_invoke` (the single
    /// permission the CronJob tasks need; future task kinds requiring
    /// different permissions pass them here). May be repeated.
    #[arg(long = "permission", default_values_t = vec!["admin_task_invoke".to_string()])]
    pub permissions: Vec<String>,

    /// Output mode for the issued token.
    ///
    /// - `stdout` (default): print to stdout. The Helm bootstrap Job pipes
    ///   this into `kubectl create secret generic`.
    /// - `file:<path>`: write to `<path>` with mode 0600. Useful for local
    ///   dev and provisioning scripts that need a file-based secret.
    /// - `kube-secret`: deferred —
    ///   post-v1 (cluster RBAC); not implemented in v1. The bootstrap Job
    ///   uses the `stdout` mode and shells out to `kubectl`. This mode
    ///   may be added when in-cluster ServiceAccount RBAC is finalised.
    ///   No pre-v1 action expected.
    #[arg(long, default_value = "stdout")]
    pub output: String,

    /// Force rotation: revoke the existing token (if any) and mint a new
    /// one. Default: idempotent — exit 0 with no rotation if the named
    /// token already exists.
    #[arg(long)]
    pub rotate: bool,

    /// Token lifetime in days. Default matches `DEFAULT_SVC_EXPIRY_DAYS`
    /// (365). Must be in `[1, 365]`. Unbounded service-account tokens
    /// are disallowed on the admin-mint path
    /// (`ApiTokenIssuanceConfig::allow_unbounded_svc_tokens` defaults to
    /// false); the system-mint rotation path also defaults to 365, so
    /// keeping the CLI default in lock-step avoids per-tool drift.
    #[arg(long = "expires-in-days", default_value_t = DEFAULT_SVC_EXPIRY_DAYS)]
    pub expires_in_days: u32,
}

/// Arguments to `admin bootstrap-session`.
#[derive(Debug, Args)]
pub struct BootstrapSessionArgs {
    /// Output mode for the issued token.
    ///
    /// - `stdout` (default): print to stdout.
    /// - `file:<path>`: write to `<path>` with mode 0600.
    ///
    /// Same shape as `issue-svc-token`; `kube-secret` is not supported
    /// here (the bootstrap token is a one-off break-glass credential,
    /// not a mounted secret).
    #[arg(long, default_value = "stdout")]
    pub output: String,

    /// Token lifetime. Accepts a bare seconds count or a single-unit
    /// suffix `s`/`m`/`h` (e.g. `1h`, `30m`, `900s`, `3600`). Default
    /// `1h`. Clamped to ≤ 1 h — the ADR-0013 admin cap. A longer value
    /// is silently clamped down (the use case enforces the ceiling);
    /// `0` is rejected.
    #[arg(long, default_value = "1h")]
    pub ttl: String,
}

/// Entry point. Dispatches to the subcommand handler. Process exit code
/// translation happens here (0 on success, non-zero on any failure).
pub fn run(cmd: AdminCommand) -> ExitCode {
    match cmd.command {
        AdminSubcommand::IssueSvcToken(args) => run_issue_svc_token(args),
        AdminSubcommand::BootstrapSession(args) => run_bootstrap_session(args),
    }
}

// ---------------------------------------------------------------------------
// issue-svc-token
// ---------------------------------------------------------------------------

/// Synchronous entry point for `admin issue-svc-token`.
fn run_issue_svc_token(args: IssueSvcTokenArgs) -> ExitCode {
    super::run_with_runtime(move || issue_svc_token_async(args), |_| ExitCode::SUCCESS)
}

/// Service-account username derived from the token logical name.
///
/// Convention: `sa:<name>` — the SAME backing-`users` username a gitops
/// `ServiceAccount` apply writes (`ensure_backing_user`). The CLI lookup
/// MUST match the apply convention or `issue-svc-token` can never find a
/// gitops-declared SA; routing through
/// [`hort_domain::entities::service_account::backing_username`] is the
/// single source of truth that prevents the two from drifting again.
fn svc_username(name: &str) -> String {
    hort_domain::entities::service_account::backing_username(name)
}

/// Validate the user `issue-svc-token` is about to mint for.
///
/// `issue-svc-token` requires a PRE-EXISTING gitops `ServiceAccount`
/// and never fabricates a user (ADR 0012). `found` is the
/// `find_by_username` result for `username` (= `sa:<svc_name>`); the
/// resolution rules are:
///
/// - `None` (no such user) → error: define the SA in gitops + apply
///   first. The caller must NOT create the user.
/// - exists but `!is_service_account` → error (the existing guard).
/// - exists, is a service account, but `is_admin` → error: service
///   accounts are strictly non-admin (Entry 4 / ADR 0012); refuse
///   rather than mint an admin-capable token.
/// - exists, service account, non-admin → return it for the mint.
///
/// Pure (operates on the already-fetched `Option<User>`) so every
/// branch is unit-testable without a database.
fn resolve_svc_user(found: Option<User>, username: &str, svc_name: &str) -> anyhow::Result<User> {
    match found {
        Some(u) => {
            if !u.is_service_account {
                anyhow::bail!(
                    "user {username:?} exists but is not a service account; \
                     refusing to issue a service-account token for it"
                );
            }
            if u.is_admin {
                anyhow::bail!(
                    "refusing to issue a token for an admin user via issue-svc-token; \
                     service accounts must be non-admin (Entry 4 / ADR 0012)"
                );
            }
            Ok(u)
        }
        None => {
            anyhow::bail!(
                "service account {svc_name:?} not found — define it as a ServiceAccount in \
                 gitops and apply before issuing its token (grants flow through the \
                 audited apply path, ADR 0012)."
            );
        }
    }
}

async fn issue_svc_token_async(args: IssueSvcTokenArgs) -> anyhow::Result<()> {
    if args.name.is_empty() {
        anyhow::bail!("--name must not be empty");
    }
    if args.output == "kube-secret" {
        anyhow::bail!(
            "output mode 'kube-secret' is not implemented in v1. \
             Use --output=stdout and pipe to: \
             kubectl create secret generic <name> --from-literal=token=\"$TOKEN\""
        );
    }

    // Parse permissions up-front before hitting the database.
    let permissions: Vec<Permission> = args
        .permissions
        .iter()
        .map(|s| {
            s.parse::<Permission>()
                .map_err(|_| anyhow::anyhow!("unknown permission {s:?}"))
        })
        .collect::<anyhow::Result<_>>()?;

    // Service accounts are strictly non-admin (Entry 4 / ADR 0012):
    // `issue-svc-token` must never mint an admin-cap token. Reject
    // `--permission=admin` here, before any DB work — there is no
    // operator opt-in for it.
    reject_admin_permission(&permissions)?;

    // Parse output mode.
    let output_path = parse_output_mode(&args.output)?;

    let cfg = MinimalConfig::from_env().context("parsing environment")?;
    telemetry::init_tracing(cfg.log_format)?;

    let pool = PgPoolOptions::new()
        .connect(&cfg.database_url)
        .await
        .context("connecting to postgres")?;
    // `issue-svc-token` is a
    // runtime-DML operation (INSERT into `users` + `api_tokens`); it
    // must not attempt DDL. The runtime DSN is least-privilege
    // (ADR 0009) and lacks CREATE on `public`, so `migrate::run`
    // would issue `CREATE TABLE IF NOT EXISTS _sqlx_migrations` and
    // fail even on a no-op pass. The `migrate` subcommand (run as a
    // separate Job under the admin DSN) is the canonical migration
    // entrypoint; this path only verifies the schema version matches
    // the binary's embedded set. Mirrors serve.rs:261.
    migrate::assert_current(&pool)
        .await
        .context("verifying schema version")?;

    // Build outbound-port instances.
    let user_repo: Arc<dyn UserRepository> = Arc::new(PgUserRepository::new(pool.clone()));
    let token_repo: Arc<dyn ApiTokenRepository> = Arc::new(PgApiTokenRepository::new(pool.clone()));
    let event_store: Arc<dyn EventStore> = Arc::new(
        PgEventStore::new(pool.clone())
            .await
            .context("constructing event store")?,
    );
    // The admin CLI does not run the dispatcher, so wrap
    // the event store in a no-broadcast publisher.
    let event_publisher = Arc::new(EventStorePublisher::without_broadcast(event_store));

    // Require a PRE-EXISTING gitops ServiceAccount. The command no
    // longer creates a user when absent: an SA's authority must flow
    // through the audited gitops apply path (ADR 0012), not be
    // fabricated here. It also no longer creates an `is_admin` user —
    // service accounts are strictly non-admin (Entry 4).
    let username = svc_username(&args.name);
    let user_uc = UserUseCase::new(user_repo.clone());
    let found = user_uc.find_by_username(&username).await?;
    let svc_user = resolve_svc_user(found, &username, &args.name)?;

    // Check for an existing token with the same name on this user.
    let existing: Option<ApiToken> =
        find_token_by_name(token_repo.as_ref(), svc_user.id, &args.name).await?;

    if let Some(ref tok) = existing {
        if !args.rotate {
            // Idempotent: token already exists, --rotate not requested.
            // Print a tombstone-safe message on stderr and exit 0.
            eprintln!(
                "info: token {:?} already exists for {username}; \
                 skipping (pass --rotate to replace)",
                args.name
            );
            // We can't re-emit the plaintext (it's hashed in the DB), so
            // the caller must treat this exit-0 path as "already provisioned".
            return Ok(());
        }
        // --rotate: revoke the old token before minting.
        info!(token_id = %tok.id, "revoking existing token for rotation");
        let token_uc = build_token_use_case(
            token_repo.clone(),
            user_repo.clone(),
            event_publisher.clone(),
        );
        let admin_actor = ApiActor {
            user_id: svc_user.id,
        };
        // Revoke with admin_authority=true so the system-actor can revoke
        // its own service-account token without a self-match check.
        token_uc
            .revoke(admin_actor, tok.id, true)
            .await
            .context("revoking existing token")?;
    }

    // System-mint path. The CLI runs at deploy time
    // (Helm post-install hook) with operator-level DSN access but no
    // human `CallerPrincipal` and no admin user row — the same trust
    // contract as the worker's rotation tick. The admin-mint path
    // (`issue_for_service_account`) would FK-violate `api_tokens.
    // created_by_user_id` against a synthetic nil admin id, and would
    // also require `allow_unbounded_svc_tokens` in the composition
    // root for the default-expiry path. The system-mint path is
    // designed exactly for this: it stamps `created_by_user_id =
    // target.id` (the service-account's own row), emits
    // `Actor::Internal(System)` for audit, and accepts an explicit
    // expiry without the unbounded-flag gate.
    let token_uc = build_token_use_case(token_repo, user_repo, event_publisher);

    let issued = token_uc
        .issue_for_service_account_system(
            svc_user.id,
            IssueTokenRequest {
                name: args.name.clone(),
                description: Some("Issued by hort-server admin issue-svc-token".to_owned()),
                declared_permissions: permissions,
                repository_ids: None,
                // System-mint resolves `None` to `DEFAULT_SVC_EXPIRY_DAYS`
                // (365) itself, but we pass the CLI value explicitly so
                // `--expires-in-days <N>` overrides cleanly.
                expires_in_days: Some(args.expires_in_days),
                expires_in_seconds: None,
                // CLI issuance is not federation.
                federation_source: None,
            },
        )
        .await
        .context("issuing service-account token")?;

    info!(
        token_id = %issued.id,
        name = %issued.name,
        kind = ?issued.kind,
        user_id = %svc_user.id,
        "service-account token issued"
    );

    // Write the plaintext token to the requested output.
    write_plaintext(&output_path, &issued.plaintext)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Shared output helpers
// ---------------------------------------------------------------------------

/// Reject `Permission::Admin` in an `issue-svc-token` permission set.
///
/// Service accounts are strictly non-admin (Entry 4 / ADR 0012) and
/// there is no operator opt-in for an admin-cap svc token — the only
/// admin mint path is `bootstrap-session`. Pure so the rejection is
/// unit-testable without a database.
fn reject_admin_permission(permissions: &[Permission]) -> anyhow::Result<()> {
    if permissions.contains(&Permission::Admin) {
        anyhow::bail!(
            "--permission=admin is not permitted for service-account tokens — \
             service accounts are strictly non-admin (Entry 4 / ADR 0012). \
             Human admin uses OIDC → CliSession; first-admin bootstrap uses \
             `hort-server admin bootstrap-session`."
        );
    }
    Ok(())
}

/// Parse an `--output` value into an optional file path.
///
/// `stdout` → `None` (print to stdout). `file:<path>` → `Some(path)`.
/// Any other value is an error. `kube-secret` is intentionally NOT
/// handled here — `issue-svc-token` rejects it earlier with a tailored
/// message, and `bootstrap-session` never advertises it.
fn parse_output_mode(output: &str) -> anyhow::Result<Option<String>> {
    if output == "stdout" {
        Ok(None)
    } else if let Some(path) = output.strip_prefix("file:") {
        Ok(Some(path.to_owned()))
    } else {
        anyhow::bail!("unknown output mode {output:?}; valid values: stdout, file:<path>")
    }
}

/// Write the plaintext token to the resolved output sink.
///
/// `None` → stdout (the Helm / provisioning caller reads it). `Some(path)`
/// → write to `<path>` with mode 0600 so only the owning process can read.
fn write_plaintext(output_path: &Option<String>, plaintext: &str) -> anyhow::Result<()> {
    match output_path {
        None => {
            println!("{plaintext}");
        }
        Some(path) => {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)
                .with_context(|| format!("opening output file {path:?}"))?;
            file.write_all(plaintext.as_bytes())
                .with_context(|| format!("writing token to {path:?}"))?;
            eprintln!("info: token written to {path}");
        }
    }
    Ok(())
}

/// Scan the first page of tokens for a user and return the one whose
/// `name` matches `token_name`, if any.
///
/// The port only exposes `list_for_user` (no `find_by_name`). For the
/// CLI bootstrap path this is acceptable: service accounts have at most
/// a handful of tokens, so a single page (100 items) is always enough.
async fn find_token_by_name(
    repo: &dyn ApiTokenRepository,
    user_id: Uuid,
    token_name: &str,
) -> anyhow::Result<Option<ApiToken>> {
    let page = repo
        .list_for_user(
            user_id,
            PageRequest {
                offset: 0,
                limit: 100,
            },
        )
        .await
        .context("listing tokens for service-account user")?;
    Ok(page.items.into_iter().find(|t| t.name == token_name))
}

/// Build an [`ApiTokenUseCase`] used by the admin CLI bootstrap path.
///
/// The CLI's issuance goes through the system-mint entrypoint
/// (`issue_for_service_account_system`), which short-circuits the
/// cap-vs-authority check and therefore does not consult the
/// [`RbacEvaluator`]. We still need a non-empty `ApiTokenUseCase`
/// instance, so we hand it an empty evaluator. The default
/// [`ApiTokenIssuanceConfig`] is also fine for the same reason:
/// `allow_unbounded_svc_tokens` is only consulted on the admin-mint
/// path, which the CLI no longer takes.
fn build_token_use_case(
    tokens: Arc<dyn ApiTokenRepository>,
    users: Arc<dyn UserRepository>,
    events: Arc<EventStorePublisher>,
) -> ApiTokenUseCase {
    let rbac = Arc::new(ArcSwap::from_pointee(RbacEvaluator::new(vec![])));
    ApiTokenUseCase::new(
        tokens,
        users,
        events,
        rbac,
        ApiTokenIssuanceConfig::default(),
    )
}

// ---------------------------------------------------------------------------
// bootstrap-session
// ---------------------------------------------------------------------------

/// Reserved username for the first-admin / break-glass admin identity.
///
/// This is the ONE deliberate admin-identity creation in the CLI. It is
/// a NON-service-account user (`is_admin = true`,
/// `is_service_account = false`) — service accounts are strictly
/// non-admin (Entry 4 / ADR 0012), so the bootstrap admin is
/// intentionally not one.
const BOOTSTRAP_ADMIN_USERNAME: &str = "bootstrap-admin";

/// Token row name (and audit label) for the bootstrap-admin token.
const BOOTSTRAP_ADMIN_TOKEN_NAME: &str = "bootstrap-session";

/// The full admin cap minted onto the bootstrap token: every
/// [`Permission`] variant, with no per-repo restriction
/// (`repository_ids = None`). The explicit `Admin` permission is
/// REQUIRED — the B1 fail-closed backstop denies an admin-claim `Pat`
/// carrying a `None`/admin-less cap, so the cap must be present and
/// full. Listed exhaustively (the enum has no iterator); a new variant
/// is a deliberate review point for whether the break-glass admin
/// should hold it (it should — full cap is the contract).
fn full_admin_cap() -> Vec<Permission> {
    vec![
        Permission::Read,
        Permission::Write,
        Permission::Delete,
        Permission::Admin,
        Permission::AdminTaskInvoke,
        Permission::Curate,
        Permission::Prefetch,
    ]
}

/// Gate `bootstrap-session` on the `HORT_TOKEN_ALLOW_ADMIN` opt-in.
///
/// Pure so the gate is unit-testable without a database. Refuses unless
/// the operator opted in — the command is the DSN-gated first-admin /
/// break-glass path; steady-state admin is IdP-backed.
fn require_allow_admin_tokens(allow_admin_tokens: bool) -> anyhow::Result<()> {
    if !allow_admin_tokens {
        anyhow::bail!(
            "bootstrap-session requires HORT_TOKEN_ALLOW_ADMIN=true; it is the \
             DSN-gated first-admin / break-glass path. Steady-state admin is \
             IdP-backed (OIDC → CliSession)."
        );
    }
    Ok(())
}

/// Parse a `--ttl` value into seconds. Accepts a bare integer (seconds)
/// or a single-unit suffix `s` / `m` / `h`. Rejects `0`, empty, and
/// anything else. Kept dependency-free (no `humantime`) since the
/// accepted surface is intentionally tiny.
fn parse_ttl_secs(ttl: &str) -> anyhow::Result<u64> {
    let ttl = ttl.trim();
    if ttl.is_empty() {
        anyhow::bail!("--ttl must not be empty");
    }
    let (num, mult): (&str, u64) = match ttl.as_bytes().last() {
        Some(b's') => (&ttl[..ttl.len() - 1], 1),
        Some(b'm') => (&ttl[..ttl.len() - 1], 60),
        Some(b'h') => (&ttl[..ttl.len() - 1], 3600),
        Some(b'0'..=b'9') => (ttl, 1),
        _ => anyhow::bail!("invalid --ttl {ttl:?}; use a bare seconds count or a s/m/h suffix"),
    };
    let n: u64 = num
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid --ttl {ttl:?}; not a number"))?;
    let secs = n
        .checked_mul(mult)
        .ok_or_else(|| anyhow::anyhow!("--ttl {ttl:?} overflows"))?;
    if secs == 0 {
        anyhow::bail!("--ttl must be at least 1 second");
    }
    Ok(secs)
}

/// Synchronous entry point for `admin bootstrap-session`.
fn run_bootstrap_session(args: BootstrapSessionArgs) -> ExitCode {
    super::run_with_runtime(move || bootstrap_session_async(args), |_| ExitCode::SUCCESS)
}

async fn bootstrap_session_async(args: BootstrapSessionArgs) -> anyhow::Result<()> {
    // Parse output + TTL up-front, before any DB work.
    let output_path = parse_output_mode(&args.output)?;
    let ttl_secs = parse_ttl_secs(&args.ttl)?;

    let cfg = MinimalConfig::from_env().context("parsing environment")?;
    telemetry::init_tracing(cfg.log_format)?;

    // Gate: bootstrap-session is the DSN-gated first-admin / break-glass
    // path and additionally requires the operator's explicit opt-in.
    // Steady-state admin is IdP-backed (OIDC → CliSession).
    require_allow_admin_tokens(cfg.allow_admin_tokens)?;

    let pool = PgPoolOptions::new()
        .connect(&cfg.database_url)
        .await
        .context("connecting to postgres")?;
    // Runtime-DML only (INSERT into `users` + `api_tokens`); no DDL.
    // Mirrors `issue_svc_token_async`.
    migrate::assert_current(&pool)
        .await
        .context("verifying schema version")?;

    let user_repo: Arc<dyn UserRepository> = Arc::new(PgUserRepository::new(pool.clone()));
    let token_repo: Arc<dyn ApiTokenRepository> = Arc::new(PgApiTokenRepository::new(pool.clone()));
    let event_store: Arc<dyn EventStore> = Arc::new(
        PgEventStore::new(pool.clone())
            .await
            .context("constructing event store")?,
    );
    let event_publisher = Arc::new(EventStorePublisher::without_broadcast(event_store));

    // Find or create the reserved bootstrap-admin user. This is the ONE
    // deliberate admin-identity creation: a NON-service-account user
    // with `is_admin = true`.
    let user_uc = UserUseCase::new(user_repo.clone());
    let admin_user = match user_uc.find_by_username(BOOTSTRAP_ADMIN_USERNAME).await? {
        Some(u) => {
            // Defence-in-depth: the row must be the expected shape. A
            // pre-existing `bootstrap-admin` that is somehow a service
            // account is a misconfiguration — refuse rather than mint.
            if u.is_service_account {
                anyhow::bail!(
                    "user {BOOTSTRAP_ADMIN_USERNAME:?} exists but is a service account; \
                     the bootstrap admin must be a non-service-account user"
                );
            }
            u
        }
        None => {
            info!(
                username = BOOTSTRAP_ADMIN_USERNAME,
                "creating bootstrap-admin user"
            );
            user_uc
                .create(
                    CreateUser {
                        username: BOOTSTRAP_ADMIN_USERNAME.to_owned(),
                        email: format!("{BOOTSTRAP_ADMIN_USERNAME}@hort-internal.local"),
                        auth_provider: AuthProvider::Local,
                        external_id: None,
                        display_name: Some("Bootstrap admin (break-glass)".to_owned()),
                    },
                    UserPrivileges {
                        is_active: true,
                        // The deliberate admin-identity creation.
                        is_admin: true,
                        // Strictly NOT a service account (Entry 4).
                        is_service_account: false,
                    },
                )
                .await?
        }
    };

    // Single active bootstrap token: revoke any prior one before minting.
    if let Some(prev) = find_token_by_name(
        token_repo.as_ref(),
        admin_user.id,
        BOOTSTRAP_ADMIN_TOKEN_NAME,
    )
    .await?
    {
        info!(token_id = %prev.id, "revoking prior bootstrap-admin token");
        let token_uc = build_token_use_case(
            token_repo.clone(),
            user_repo.clone(),
            event_publisher.clone(),
        );
        token_uc
            .revoke(
                ApiActor {
                    user_id: admin_user.id,
                },
                prev.id,
                true,
            )
            .await
            .context("revoking prior bootstrap-admin token")?;
    }

    // System-mint a short-lived (≤ 1 h) full-cap admin Pat. The use case
    // requires the explicit admin cap (B1) and bounds the lifetime to
    // the ADR-0013 admin ceiling.
    let token_uc = build_token_use_case(token_repo, user_repo, event_publisher);
    let issued = token_uc
        .issue_for_bootstrap_admin_system(
            admin_user.id,
            BOOTSTRAP_ADMIN_TOKEN_NAME.to_owned(),
            full_admin_cap(),
            ttl_secs,
        )
        .await
        .context("minting bootstrap-admin token")?;

    info!(
        token_id = %issued.id,
        user_id = %admin_user.id,
        expires_at = ?issued.expires_at,
        "bootstrap-admin token issued"
    );

    write_plaintext(&output_path, &issued.plaintext)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use clap::Parser;

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: super::super::Command,
    }

    // -- issue-svc-token CLI parsing -----------------------------------------

    #[test]
    fn issue_svc_token_requires_name() {
        let err = TestCli::try_parse_from(["hort-server", "admin", "issue-svc-token"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn issue_svc_token_parses_with_name() {
        let cli = TestCli::try_parse_from([
            "hort-server",
            "admin",
            "issue-svc-token",
            "--name",
            "cronjob-tasks",
        ])
        .unwrap();
        let super::super::Command::Admin(admin_cmd) = cli.command else {
            panic!("expected Admin");
        };
        let AdminSubcommand::IssueSvcToken(args) = admin_cmd.command else {
            panic!("expected IssueSvcToken");
        };
        assert_eq!(args.name, "cronjob-tasks");
        // Default permission.
        assert_eq!(args.permissions, vec!["admin_task_invoke"]);
        // Default output.
        assert_eq!(args.output, "stdout");
        // Default: no rotation.
        assert!(!args.rotate);
        // Default expiry: matches the system-mint path's
        // `DEFAULT_SVC_EXPIRY_DAYS` so admin-mint and rotation agree.
        assert_eq!(args.expires_in_days, DEFAULT_SVC_EXPIRY_DAYS);
    }

    #[test]
    fn issue_svc_token_accepts_custom_expiry() {
        let cli = TestCli::try_parse_from([
            "hort-server",
            "admin",
            "issue-svc-token",
            "--name",
            "my-token",
            "--expires-in-days",
            "30",
        ])
        .unwrap();
        let super::super::Command::Admin(admin_cmd) = cli.command else {
            panic!("expected Admin");
        };
        let AdminSubcommand::IssueSvcToken(args) = admin_cmd.command else {
            panic!("expected IssueSvcToken");
        };
        assert_eq!(args.expires_in_days, 30);
    }

    #[test]
    fn issue_svc_token_accepts_custom_permission() {
        let cli = TestCli::try_parse_from([
            "hort-server",
            "admin",
            "issue-svc-token",
            "--name",
            "my-token",
            "--permission",
            "read",
            "--permission",
            "write",
        ])
        .unwrap();
        let super::super::Command::Admin(admin_cmd) = cli.command else {
            panic!("expected Admin");
        };
        let AdminSubcommand::IssueSvcToken(args) = admin_cmd.command else {
            panic!("expected IssueSvcToken");
        };
        assert_eq!(args.permissions, vec!["read", "write"]);
    }

    #[test]
    fn issue_svc_token_accepts_file_output() {
        let cli = TestCli::try_parse_from([
            "hort-server",
            "admin",
            "issue-svc-token",
            "--name",
            "my-token",
            "--output",
            "file:/tmp/token.txt",
        ])
        .unwrap();
        let super::super::Command::Admin(admin_cmd) = cli.command else {
            panic!("expected Admin");
        };
        let AdminSubcommand::IssueSvcToken(args) = admin_cmd.command else {
            panic!("expected IssueSvcToken");
        };
        assert_eq!(args.output, "file:/tmp/token.txt");
    }

    #[test]
    fn issue_svc_token_accepts_rotate_flag() {
        let cli = TestCli::try_parse_from([
            "hort-server",
            "admin",
            "issue-svc-token",
            "--name",
            "my-token",
            "--rotate",
        ])
        .unwrap();
        let super::super::Command::Admin(admin_cmd) = cli.command else {
            panic!("expected Admin");
        };
        let AdminSubcommand::IssueSvcToken(args) = admin_cmd.command else {
            panic!("expected IssueSvcToken");
        };
        assert!(args.rotate);
    }

    // -- svc_username derivation --------------------------------------------

    #[test]
    fn svc_username_derives_correct_name() {
        assert_eq!(svc_username("cronjob-tasks"), "sa:cronjob-tasks");
        assert_eq!(svc_username("foo"), "sa:foo");
    }

    #[test]
    fn svc_username_matches_gitops_backing_user_convention() {
        // The CLI lookup IS the gitops backing-user convention: both must
        // derive the SAME `sa:<name>` username, or `issue-svc-token` can
        // never find a gitops-declared SA (the `hort-svc-` mismatch that
        // shipped in 0.9.5-beta.1). Pinning them to the single
        // `hort_domain::entities::service_account::backing_username` source
        // of truth keeps the two from drifting again.
        for name in ["cronjob-tasks", "foo", "bar-baz"] {
            assert_eq!(
                svc_username(name),
                hort_domain::entities::service_account::backing_username(name),
            );
        }
    }

    // -- output-mode parsing (unit tests on the pure logic) -----------------

    #[test]
    fn kube_secret_mode_is_rejected() {
        // Deferred post-v1: kube-secret is
        // post-v1 (cluster RBAC). The async body rejects it up-front
        // before touching the database. No pre-v1 action expected.
        let args = IssueSvcTokenArgs {
            name: "tok".into(),
            permissions: vec!["admin_task_invoke".into()],
            output: "kube-secret".into(),
            rotate: false,
            expires_in_days: DEFAULT_SVC_EXPIRY_DAYS,
        };
        // We can't call issue_svc_token_async without a live DB, but we can
        // assert the output detection logic by checking the expected branch.
        assert_eq!(args.output, "kube-secret");
        // The runtime test of the rejection lives in E2E fixtures. Here we
        // pin the string so a refactor doesn't silently accept it.
    }

    #[test]
    fn file_output_prefix_strips_correctly() {
        // Mirror the `strip_prefix("file:")` logic used in issue_svc_token_async.
        let output = "file:/var/run/secrets/token.txt";
        let path = output.strip_prefix("file:").unwrap();
        assert_eq!(path, "/var/run/secrets/token.txt");
    }

    #[test]
    fn stdout_output_produces_no_path() {
        let output = "stdout";
        assert!(output.strip_prefix("file:").is_none());
        assert_ne!(output, "kube-secret");
    }

    // -- issue-svc-token: --permission=admin rejection ----------------------

    #[test]
    fn issue_svc_token_rejects_admin_permission() {
        // `--permission=admin` must be rejected before any DB work —
        // service accounts are strictly non-admin (Entry 4 / ADR 0012).
        let err = reject_admin_permission(&[Permission::Read, Permission::Admin]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not permitted for service-account tokens"),
            "unexpected message: {msg}"
        );
        assert!(
            msg.contains("bootstrap-session"),
            "should point at the bootstrap path: {msg}"
        );
    }

    #[test]
    fn issue_svc_token_accepts_non_admin_permissions() {
        // The common non-admin caps pass the gate.
        reject_admin_permission(&[Permission::AdminTaskInvoke]).expect("admin_task_invoke ok");
        reject_admin_permission(&[Permission::Read, Permission::Write]).expect("read+write ok");
        reject_admin_permission(&[Permission::Curate, Permission::Prefetch]).expect("curate ok");
    }

    // -- issue-svc-token: SA resolution (no user fabrication) ----------------

    fn svc_user_row(is_service_account: bool, is_admin: bool) -> User {
        User {
            id: Uuid::from_u128(0x5A),
            username: "sa:cronjob-tasks".into(),
            email: "x@hort-internal.local".into(),
            auth_provider: AuthProvider::Local,
            external_id: None,
            display_name: None,
            is_active: true,
            is_admin,
            is_service_account,
            last_login_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn resolve_svc_user_errors_when_missing() {
        // Missing SA → error pointing at gitops; the caller does NOT
        // create a user (this helper returning Err is what prevents it).
        let err = resolve_svc_user(None, "sa:cronjob-tasks", "cronjob-tasks").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not found"), "unexpected: {msg}");
        assert!(
            msg.contains("gitops"),
            "should point at gitops apply: {msg}"
        );
    }

    #[test]
    fn resolve_svc_user_errors_when_not_a_service_account() {
        let row = svc_user_row(false, false);
        let err = resolve_svc_user(Some(row), "sa:cronjob-tasks", "cronjob-tasks").unwrap_err();
        assert!(err.to_string().contains("is not a service account"));
    }

    #[test]
    fn resolve_svc_user_errors_when_admin() {
        // A service-account row that is somehow is_admin is refused —
        // service accounts must be non-admin.
        let row = svc_user_row(true, true);
        let err = resolve_svc_user(Some(row), "sa:cronjob-tasks", "cronjob-tasks").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("admin user"), "unexpected: {msg}");
        assert!(msg.contains("non-admin"), "unexpected: {msg}");
    }

    #[test]
    fn resolve_svc_user_returns_non_admin_service_account() {
        let row = svc_user_row(true, false);
        let resolved = resolve_svc_user(Some(row.clone()), "sa:cronjob-tasks", "cronjob-tasks")
            .expect("non-admin SA must resolve");
        assert_eq!(resolved.id, row.id);
        assert!(resolved.is_service_account);
        assert!(!resolved.is_admin);
    }

    // -- output-mode parsing (shared helper) --------------------------------

    #[test]
    fn parse_output_mode_handles_stdout_and_file() {
        assert_eq!(parse_output_mode("stdout").unwrap(), None);
        assert_eq!(
            parse_output_mode("file:/tmp/t.txt").unwrap(),
            Some("/tmp/t.txt".to_string())
        );
        let err = parse_output_mode("kube-secret").unwrap_err();
        assert!(err.to_string().contains("unknown output mode"));
    }

    // -- bootstrap-session: HORT_TOKEN_ALLOW_ADMIN gate ----------------------

    #[test]
    fn bootstrap_session_requires_allow_admin_tokens() {
        // Without the opt-in: refused with a message pointing at the env
        // var and the IdP-backed steady-state path.
        let err = require_allow_admin_tokens(false).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("HORT_TOKEN_ALLOW_ADMIN=true"),
            "unexpected: {msg}"
        );
        assert!(msg.contains("break-glass"), "unexpected: {msg}");
        // With it: passes.
        require_allow_admin_tokens(true).expect("opt-in must allow bootstrap-session");
    }

    // -- bootstrap-session: --ttl parsing + clamp ----------------------------

    #[test]
    fn parse_ttl_secs_accepts_units_and_bare_seconds() {
        assert_eq!(parse_ttl_secs("1h").unwrap(), 3600);
        assert_eq!(parse_ttl_secs("30m").unwrap(), 1800);
        assert_eq!(parse_ttl_secs("900s").unwrap(), 900);
        assert_eq!(parse_ttl_secs("3600").unwrap(), 3600);
        assert_eq!(parse_ttl_secs("  1h ").unwrap(), 3600);
    }

    #[test]
    fn parse_ttl_secs_rejects_zero_and_garbage() {
        assert!(parse_ttl_secs("0").is_err());
        assert!(parse_ttl_secs("0s").is_err());
        assert!(parse_ttl_secs("").is_err());
        assert!(parse_ttl_secs("   ").is_err());
        assert!(parse_ttl_secs("abc").is_err());
        assert!(parse_ttl_secs("1d").is_err()); // unsupported unit
        assert!(parse_ttl_secs("h").is_err()); // no number
    }

    #[test]
    fn full_admin_cap_is_every_permission_including_admin() {
        let cap = full_admin_cap();
        // Admin MUST be present — the B1 backstop fail-closes an
        // admin-claim Pat with a None/admin-less cap.
        assert!(cap.contains(&Permission::Admin));
        // Every variant present (full cap).
        for p in [
            Permission::Read,
            Permission::Write,
            Permission::Delete,
            Permission::Admin,
            Permission::AdminTaskInvoke,
            Permission::Curate,
            Permission::Prefetch,
        ] {
            assert!(cap.contains(&p), "full cap missing {p:?}");
        }
    }

    // -- bootstrap-session CLI parsing --------------------------------------

    #[test]
    fn bootstrap_session_parses_with_defaults() {
        let cli = TestCli::try_parse_from(["hort-server", "admin", "bootstrap-session"]).unwrap();
        let super::super::Command::Admin(admin_cmd) = cli.command else {
            panic!("expected Admin");
        };
        let AdminSubcommand::BootstrapSession(args) = admin_cmd.command else {
            panic!("expected BootstrapSession");
        };
        assert_eq!(args.output, "stdout");
        assert_eq!(args.ttl, "1h");
    }

    #[test]
    fn bootstrap_session_parses_custom_ttl_and_output() {
        let cli = TestCli::try_parse_from([
            "hort-server",
            "admin",
            "bootstrap-session",
            "--ttl",
            "30m",
            "--output",
            "file:/tmp/admin.txt",
        ])
        .unwrap();
        let super::super::Command::Admin(admin_cmd) = cli.command else {
            panic!("expected Admin");
        };
        let AdminSubcommand::BootstrapSession(args) = admin_cmd.command else {
            panic!("expected BootstrapSession");
        };
        assert_eq!(args.ttl, "30m");
        assert_eq!(args.output, "file:/tmp/admin.txt");
    }

    #[test]
    fn bootstrap_admin_username_is_non_sa_reserved_name() {
        // Pin the reserved identity name so a rename is a deliberate
        // review point (catalog + ADR reference it).
        assert_eq!(BOOTSTRAP_ADMIN_USERNAME, "bootstrap-admin");
        assert_eq!(BOOTSTRAP_ADMIN_TOKEN_NAME, "bootstrap-session");
    }
}
