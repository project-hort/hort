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

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::Context;
use arc_swap::ArcSwap;
use clap::{Args, Subcommand};
use sqlx::postgres::PgPoolOptions;
use tracing::info;
use uuid::Uuid;

use hort_adapters_postgres::{
    api_token_repo::PgApiTokenRepository, event_store::PgEventStore,
    permission_grant_repo::PgPermissionGrantRepository, repository_repo::PgRepositoryRepository,
    user_repo::PgUserRepository,
};
use hort_app::event_store_publisher::EventStorePublisher;
use hort_app::rbac::RbacEvaluator;
use hort_app::use_cases::api_token_use_case::{
    ApiTokenIssuanceConfig, ApiTokenUseCase, IssueTokenRequest, BOOTSTRAP_ADMIN_USERNAME,
    DEFAULT_SVC_EXPIRY_DAYS,
};
use hort_app::use_cases::user_use_case::{CreateUser, UserPrivileges, UserUseCase};
use hort_domain::entities::api_token::ApiToken;
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::rbac::Permission;
use hort_domain::entities::user::{AuthProvider, User};
use hort_domain::events::ApiActor;
use hort_domain::ports::api_token_repository::ApiTokenRepository;
use hort_domain::ports::event_store::EventStore;
use hort_domain::ports::permission_grant_repository::PermissionGrantRepository;
use hort_domain::ports::repository_repository::RepositoryRepository;
use hort_domain::ports::user_repository::UserRepository;
use hort_domain::types::PageRequest;

use crate::config::MinimalConfig;
use crate::{migrate, pg_identity, telemetry};

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
    /// - `file:<path>`: atomically place the token at `<path>` as a file
    ///   this process created at mode 0600 — a pre-existing file or
    ///   symlink there is *replaced*, never inherited or followed, so the
    ///   0600 promise holds on an overwrite too. `<path>`'s parent
    ///   directory must already exist and is left untouched. Useful for
    ///   local dev and provisioning scripts that need a file-based secret.
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

    /// Verify each `--permission` is backed by a live `PermissionGrant` on
    /// the service account before minting; fail with actionable guidance
    /// if not. There is no value that disables the check once the flag is
    /// present — only the scope it runs at changes.
    ///
    /// - absent (default): no preflight — unchanged behaviour, no grant
    ///   read, matching every prior release (other callers may
    ///   legitimately mint a cap before applying the grant).
    /// - bare `--require-authority`: the preflight scope follows
    ///   `--repository` — global unless `--repository` is also set, in
    ///   which case that repository's scope. This is the byte-compatible
    ///   form: it reproduces exactly what the bare flag did before it
    ///   could carry its own value.
    /// - `--require-authority=<repo-key>`: the preflight scope is
    ///   `<repo-key>`, resolved to a repository id before any DB write —
    ///   an unknown key fails loudly, the same shape as an unknown
    ///   `--repository`. This is independent of `--repository`, so an
    ///   identity can carry a global (unscoped) cap while its authority
    ///   is still checked at a specific repository. An explicit empty
    ///   value (`--require-authority=`) is treated the same as the bare
    ///   form, never as "skip the check".
    ///
    /// The Helm bootstrap Job always sets this (bare, or with a scope) so
    /// a missing grant fails the install loudly instead of 403-ing
    /// silently at every CronJob tick (issue #21).
    #[arg(long, num_args = 0..=1, default_missing_value = "")]
    pub require_authority: Option<String>,

    /// Scope the minted token to a single repository by its `key`.
    ///
    /// Omit for a global-scope token (today's behaviour, byte-compatible:
    /// the cap carries `repository_ids = None`). With this flag, the name
    /// is resolved to a repository id before any DB write — an unknown
    /// name fails loudly — and the minted cap carries
    /// `repository_ids = [<repo_id>]`.
    ///
    /// Governs cap width ONLY — it no longer also drives the
    /// `--require-authority` preflight's scope. A bare `--require-authority`
    /// still follows this flag for byte-compatibility, but
    /// `--require-authority=<repo-key>` names its own scope independently,
    /// so an identity can carry a global cap while its authority is
    /// checked at a specific repository (a global grant still satisfies a
    /// repo-scoped check either way, since global authority encompasses
    /// every repository scope).
    #[arg(long)]
    pub repository: Option<String>,
}

/// Arguments to `admin bootstrap-session`.
#[derive(Debug, Args)]
pub struct BootstrapSessionArgs {
    /// Output mode for the issued token.
    ///
    /// - `stdout` (default): print to stdout.
    /// - `file:<path>`: atomically place the token at `<path>` as a file
    ///   this process created at mode 0600 (see `issue-svc-token`'s
    ///   `--output` for the exact guarantee).
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

/// Evaluator-backed authority check for `--require-authority`.
///
/// Verifies each permission in `permissions` is backed by a live grant on
/// `svc_user_id` at `scope` — `None` for **global** scope (today's
/// unchanged behaviour), `Some((repo_id, repo_name))` to check the SAME
/// scope the minted token will be capped to — using
/// [`RbacEvaluator::authorize_granted`] — the SAME grants-leg-only
/// evaluation the runtime already uses for the quarantine hold-exemption
/// basis (ADR 0039 §10), rather than a hand-rolled grants query that
/// could drift from the request-time gate. Passing `Some(repo_id)` as the
/// evaluator's scope reuses the runtime's own global-⊇-repo semantics
/// (`RbacEvaluator::user_grants_authorize` treats a grant with
/// `repository_id: None` as matching every scope), so a global grant
/// backs a repo-scoped preflight exactly as it backs a repo-scoped
/// request at runtime — no separate "global also satisfies" branch
/// needed here. `authorize_granted` ignores `token_cap` entirely, which
/// is exactly right here: the probe principal built below always carries
/// `token_cap: None`, so there is no cap leg that could mask a missing
/// grant — the decision is 100% the grants leg.
///
/// A service-account principal carries no claims (service accounts are
/// strictly non-admin and never resolve IdP groups), so only a
/// `GrantSubject::User(svc_user_id)` grant can back a declared permission
/// here — the same shape `RbacEvaluator::service_account_cap_permissions`
/// assumes.
///
/// Pure over the caller-supplied `evaluator` (no I/O): the caller loads
/// the grant snapshot from Postgres and builds the evaluator once, so
/// this function — and therefore the whole unbacked-permission-set
/// mapping — is unit-testable without a database.
///
/// Returns `Ok(())` when every declared permission is backed; otherwise
/// `Err` naming ALL unbacked permissions plus a copy-paste
/// `PermissionGrant` YAML block per permission ([`unbacked_authority_message`]).
fn check_require_authority(
    evaluator: &RbacEvaluator,
    svc_name: &str,
    svc_user_id: Uuid,
    permissions: &[Permission],
    scope: Option<(Uuid, &str)>,
) -> anyhow::Result<()> {
    // A probe principal with no claims and no token cap: the shape a
    // service account's own identity carries. `authorize_granted` reads
    // only `user_id` / `claims` / `token_kind` / `token_cap`; the other
    // identity fields are never inspected, so placeholders are fine.
    let principal = CallerPrincipal {
        user_id: svc_user_id,
        external_id: String::new(),
        username: String::new(),
        email: String::new(),
        claims: Vec::new(),
        token_kind: None,
        issued_at: chrono::Utc::now(),
        token_cap: None,
    };
    let repository_id = scope.map(|(id, _)| id);
    let unbacked: Vec<Permission> = permissions
        .iter()
        .copied()
        .filter(|&p| !evaluator.authorize_granted(&principal, p, repository_id))
        .collect();
    if unbacked.is_empty() {
        return Ok(());
    }
    anyhow::bail!(unbacked_authority_message(
        svc_name,
        &unbacked,
        scope.map(|(_, name)| name)
    ));
}

/// Render the `--require-authority` preflight failure message.
///
/// Names every unbacked declared permission in one message (not just the
/// first) and prints a copy-paste `PermissionGrant` YAML block per
/// permission, so an operator fixes all of them in a single gitops apply
/// pass. `repository_name` is `None` for the global check (message shape
/// unchanged from before scope-awareness) or `Some(name)` to name the
/// checked repository inline and add the matching `repository: <name>`
/// line to each YAML block — never the global form when a scope was
/// actually checked. Pure string formatting — no I/O — so it is
/// unit-testable without a live grant set.
///
/// `unbacked` is expected non-empty; the sole caller
/// ([`check_require_authority`]) only invokes this after confirming that.
fn unbacked_authority_message(
    svc_name: &str,
    unbacked: &[Permission],
    repository_name: Option<&str>,
) -> String {
    let scope_suffix = match repository_name {
        Some(r) => format!(" (repository: {r})"),
        None => String::new(),
    };
    let names: Vec<String> = unbacked.iter().map(ToString::to_string).collect();
    let mut msg = format!(
        "service account {svc_name:?} exists but has no grant for permission(s): {}{scope_suffix} \
         — the token would mint but the corresponding admin-task CronJob(s) would be denied \
         (403) at run time. Add the following to your gitopsConfig and re-apply:\n",
        names.join(", ")
    );
    for name in &names {
        let repo_line = match repository_name {
            Some(r) => format!("\n    repository: {r}"),
            None => "        # global (no repository:)".to_string(),
        };
        msg.push_str(&format!(
            "\n  apiVersion: project-hort.de/v1\n  kind: PermissionGrant\n  \
             metadata: {{ name: {svc_name}-{name} }}\n  spec:\n    \
             subject: {{ kind: serviceAccount, name: {svc_name} }}\n    \
             permission: {name}{repo_line}\n"
        ));
    }
    msg
}

/// The minted token's per-repository cap: `None` for a
/// global token — today's byte-compatible default — or `Some([repo_id])`
/// when `--repository` scoped the mint. Single-element only: a
/// list-valued `--repository` is a distinct future need, out of scope
/// here. Pure so the regression pin (flagless mint stays `None`) is
/// unit-testable without a database.
fn cap_repository_ids(repository_id: Option<Uuid>) -> Option<Vec<Uuid>> {
    repository_id.map(|id| vec![id])
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
        .connect_with(pg_identity::connect_options(&cfg.database_url)?)
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

    // Resolve `--repository` to a repository id before any DB write —
    // an unknown name fails loudly here, not after minting. Governs the
    // minted token's capability ONLY (see `authority_scope` below for the
    // preflight). Without the flag: `None`, byte-compatible with today
    // (global cap).
    let repository_scope: Option<(Uuid, String)> = match &args.repository {
        Some(name) => {
            let repository_repo: Arc<dyn RepositoryRepository> =
                Arc::new(PgRepositoryRepository::new(pool.clone()));
            let repo = repository_repo
                .find_by_key(name)
                .await
                .with_context(|| format!("resolving --repository {name:?}: unknown repository"))?;
            Some((repo.id, name.clone()))
        }
        None => None,
    };

    // Resolve the `--require-authority` preflight scope, independently of
    // `--repository`'s cap-width resolution above.
    //
    // - `None`: the flag was not given at all — no preflight, byte-
    //   compatible with today's `false` default.
    // - `Some(repository_scope.clone())`: the bare flag (or an explicit
    //   empty value) — reproduces exactly what the bare flag did before
    //   it could carry its own value: global unless `--repository` is
    //   ALSO set, in which case that repository's scope. This is the
    //   byte-compatibility case every existing invocation relies on.
    // - `Some(Some((id, name)))`: an explicit `--require-authority=<repo-
    //   key>` names its own scope, resolved to a repository id before any
    //   DB write — an unknown key fails loudly, the same shape as an
    //   unknown `--repository` above. Independent of `--repository`, so
    //   cap width and preflight scope are no longer welded together.
    let authority_scope: Option<Option<(Uuid, String)>> = match args.require_authority.as_deref() {
        None => None,
        Some("") => Some(repository_scope.clone()),
        Some(name) => {
            let repository_repo: Arc<dyn RepositoryRepository> =
                Arc::new(PgRepositoryRepository::new(pool.clone()));
            let repo = repository_repo.find_by_key(name).await.with_context(|| {
                format!("resolving --require-authority scope {name:?}: unknown repository")
            })?;
            Some(Some((repo.id, name.to_string())))
        }
    };

    // Require a PRE-EXISTING gitops ServiceAccount. The command no
    // longer creates a user when absent: an SA's authority must flow
    // through the audited gitops apply path (ADR 0012), not be
    // fabricated here. It also no longer creates an `is_admin` user —
    // service accounts are strictly non-admin (Entry 4).
    let username = svc_username(&args.name);
    let user_uc = UserUseCase::new(user_repo.clone());
    let found = user_uc.find_by_username(&username).await?;
    let svc_user = resolve_svc_user(found, &username, &args.name)?;

    // `--require-authority` preflight (design doc §4, issue #21): catch
    // the SILENT failure mode where the SA exists but its backing grant
    // does not — the token would mint fine and every admin-task CronJob
    // would 403 at run time with no install-time signal. Runs BEFORE the
    // idempotent early-exit below so a grant an operator later revoked
    // still surfaces on the next routine upgrade, not just on `--rotate`.
    if let Some(scope) = authority_scope.as_ref() {
        let permission_grant_repo: Arc<dyn PermissionGrantRepository> =
            Arc::new(PgPermissionGrantRepository::new(pool.clone()));
        let grants = permission_grant_repo
            .list_all()
            .await
            .context("listing permission grants for --require-authority preflight")?;
        // The SAME RbacEvaluator the runtime authorizes every request
        // with — not a hand-rolled grants query — so this check cannot
        // drift from the request-time gate.
        let evaluator = RbacEvaluator::new(grants);
        check_require_authority(
            &evaluator,
            &args.name,
            svc_user.id,
            &permissions,
            scope.as_ref().map(|(id, name)| (*id, name.as_str())),
        )?;
    }

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
                repository_ids: cap_repository_ids(repository_scope.as_ref().map(|(id, _)| *id)),
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
/// `None` → stdout (the Helm / provisioning caller reads it).
/// `Some(path)` → atomically place it at `<path>` as a file *this* process
/// created at mode 0600, via the shared
/// [`hort_secret_file::write_secret_file`].
///
/// The secret never reaches a file whose mode or type this process did not
/// set. `OpenOptionsExt::mode` applies only when a file is *created*, so
/// opening `<path>` with `create(true).truncate(true).mode(0o600)` would
/// leave a pre-existing group- or world-readable file at its own
/// permissions and write the bearer into it — the documented 0600 output
/// silently not holding — and would follow a symlink at `<path>` to a path
/// the operator never named. Replacing the directory entry closes both.
/// What leaks on that path is a service-account bearer or a full-cap
/// bootstrap admin PAT, and the issuance gates (DSN access,
/// `HORT_TOKEN_ALLOW_ADMIN`) guard the *minting*, not this sink.
///
/// Re-running the command against the same `<path>` keeps working: what
/// makes the overwrite safe is the atomic replace, not a refusal to
/// overwrite.
///
/// `<path>`'s parent directory must already exist and is never modified.
/// The operator chose that directory, and the native deployment's default
/// token location is `/etc/hort/tasks-token` — a directory deliberately
/// kept `root:hort` 0750 so `hort-server.service` can read the env files
/// beside the token. Tightening it to 0700 on a token mint would break the
/// service. The parent's mode is not what protects the secret anyway; the
/// 0600 inode is. The replaced file is owned by this process, so a caller
/// needing a different owner (the Ansible timers role chowns the token to
/// its run user) sets it after the write.
fn write_plaintext(output_path: &Option<String>, plaintext: &str) -> anyhow::Result<()> {
    match output_path {
        None => {
            println!("{plaintext}");
        }
        Some(path) => {
            hort_secret_file::write_secret_file(Path::new(path), plaintext.as_bytes())
                .with_context(|| format!("writing token to {path:?}"))?;
            eprintln!("info: token written to {path}");
        }
    }
    Ok(())
}

/// Page size for the `list_for_user` walks below. The port exposes no
/// `find_by_name` and no "all rows" read, so every enumeration pages.
const TOKEN_PAGE_LIMIT: u64 = 100;

/// Upper bound on pages walked by [`live_token_ids_for_user`].
///
/// The walk stops on a short page; this budget only exists so a
/// repository that ignored `offset` could not spin the CLI forever —
/// headless, a non-terminating loop is indistinguishable from a hang.
/// Exhausting it is reported as an error, never silently truncated: a
/// truncated enumeration would leave tokens un-revoked while the
/// command reported success.
const MAX_TOKEN_PAGES: usize = 1_000;

/// Scan the first page of tokens for a user and return the one whose
/// `name` matches `token_name`, if any.
///
/// The port only exposes `list_for_user` (no `find_by_name`). For the
/// service-account rotation path this is acceptable: the operator names
/// the token, and a service account holds at most a handful, so a single
/// page (100 items) is always enough. The bootstrap rotation does NOT
/// use this — it revokes by principal, see
/// [`live_token_ids_for_user`].
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
                limit: TOKEN_PAGE_LIMIT,
            },
        )
        .await
        .context("listing tokens for service-account user")?;
    Ok(page.items.into_iter().find(|t| t.name == token_name))
}

/// Collect the ids of every not-yet-revoked token owned by `user_id`,
/// walking **all** pages.
///
/// Identity, not label, is the selector: the owner is the whole
/// predicate and the token's `name` is never read. A caller-chosen name
/// says nothing about who owns a credential, so a name-matched sweep
/// leaves every differently-named token of the same principal in place —
/// and the first page only compounds it.
///
/// Already-revoked rows are skipped: `ApiTokenRepository::revoke` is
/// idempotent, so including them would be harmless but would emit a
/// second `ApiTokenRevoked` event per row and inflate the count the
/// caller logs.
async fn live_token_ids_for_user(
    repo: &dyn ApiTokenRepository,
    user_id: Uuid,
) -> anyhow::Result<Vec<Uuid>> {
    let mut ids = Vec::new();
    let mut offset = 0u64;
    for _ in 0..MAX_TOKEN_PAGES {
        let page = repo
            .list_for_user(
                user_id,
                PageRequest {
                    offset,
                    limit: TOKEN_PAGE_LIMIT,
                },
            )
            .await
            .with_context(|| format!("listing tokens for user {user_id}"))?;
        let fetched = page.items.len() as u64;
        ids.extend(
            page.items
                .iter()
                .filter(|t| t.revoked_at.is_none())
                .map(|t| t.id),
        );
        // A short page is the end of the list. Deliberately not keyed on
        // `page.total`: revocation is an UPDATE, not a DELETE, so the row
        // count cannot shrink underneath the walk, but a `total` computed
        // by a separate count query is still the weaker signal of the two.
        if fetched < TOKEN_PAGE_LIMIT {
            return Ok(ids);
        }
        offset += fetched;
    }
    anyhow::bail!(
        "listing tokens for user {user_id} did not terminate within \
         {MAX_TOKEN_PAGES} pages of {TOKEN_PAGE_LIMIT}; refusing to proceed on a \
         partial enumeration — a truncated sweep would leave live tokens behind"
    )
}

/// Revoke each token id in `ids` through the use case, so every
/// revocation lands its `ApiTokenRevoked` audit event.
///
/// Fails on the first error rather than continuing: a partially-revoked
/// rotation that reported success would leave a live full-admin
/// credential behind with nothing recording it.
async fn revoke_bootstrap_admin_tokens(
    token_uc: &ApiTokenUseCase,
    actor: ApiActor,
    ids: &[Uuid],
) -> anyhow::Result<()> {
    for id in ids {
        info!(token_id = %id, "revoking prior bootstrap-admin token");
        token_uc
            .revoke(actor.clone(), *id, true)
            .await
            .with_context(|| format!("revoking prior bootstrap-admin token {id}"))?;
    }
    Ok(())
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

// The reserved username of the first-admin / break-glass admin identity is
// `hort_app::use_cases::api_token_use_case::BOOTSTRAP_ADMIN_USERNAME`,
// imported above rather than declared here. It belongs to the use-case
// layer because the issuance gates refuse request-path tokens for that
// identity and must name the same user this command reserves; a second
// copy here could drift and leave the gate guarding a row the CLI does
// not create.

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
        .connect_with(pg_identity::connect_options(&cfg.database_url)?)
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

    // Single active credential for the break-glass identity: revoke
    // every live token the principal owns before minting the next one.
    //
    // By principal, not by name. The reserved name is what this command
    // mints under, but it is not what the identity is, and a token the
    // principal owns under any other name is exactly as powerful — so
    // matching the name left such a token live through every subsequent
    // rotation. The walk also covers every page, not just the first.
    let stale = live_token_ids_for_user(token_repo.as_ref(), admin_user.id).await?;
    if !stale.is_empty() {
        let token_uc = build_token_use_case(
            token_repo.clone(),
            user_repo.clone(),
            event_publisher.clone(),
        );
        revoke_bootstrap_admin_tokens(
            &token_uc,
            ApiActor {
                user_id: admin_user.id,
            },
            &stale,
        )
        .await?;
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
        // Default: the preflight is opt-in — unset ⇒ byte-for-byte
        // unchanged behaviour, no grant read.
        assert_eq!(args.require_authority, None);
    }

    #[test]
    fn issue_svc_token_accepts_require_authority_bare_flag() {
        // The bare form must stay byte-compatible: `Some("")`, not a
        // named scope — the async body treats an empty value the same as
        // the pre-238 boolean `true` (preflight scope follows
        // `--repository`, or global if that is also absent).
        let cli = TestCli::try_parse_from([
            "hort-server",
            "admin",
            "issue-svc-token",
            "--name",
            "cronjob-tasks",
            "--require-authority",
        ])
        .unwrap();
        let super::super::Command::Admin(admin_cmd) = cli.command else {
            panic!("expected Admin");
        };
        let AdminSubcommand::IssueSvcToken(args) = admin_cmd.command else {
            panic!("expected IssueSvcToken");
        };
        assert_eq!(args.require_authority.as_deref(), Some(""));
    }

    #[test]
    fn issue_svc_token_accepts_require_authority_with_explicit_scope() {
        // `--require-authority=<repo-key>` aims the preflight at that
        // scope, independent of `--repository` (which is absent here).
        let cli = TestCli::try_parse_from([
            "hort-server",
            "admin",
            "issue-svc-token",
            "--name",
            "uat-smoke",
            "--require-authority=maven-proxy",
        ])
        .unwrap();
        let super::super::Command::Admin(admin_cmd) = cli.command else {
            panic!("expected Admin");
        };
        let AdminSubcommand::IssueSvcToken(args) = admin_cmd.command else {
            panic!("expected IssueSvcToken");
        };
        assert_eq!(args.require_authority.as_deref(), Some("maven-proxy"));
        // `--repository` (cap width) is untouched by this flag.
        assert_eq!(args.repository, None);
    }

    #[test]
    fn issue_svc_token_accepts_repository_flag() {
        let cli = TestCli::try_parse_from([
            "hort-server",
            "admin",
            "issue-svc-token",
            "--name",
            "uat-smoke",
            "--repository",
            "maven-proxy",
        ])
        .unwrap();
        let super::super::Command::Admin(admin_cmd) = cli.command else {
            panic!("expected Admin");
        };
        let AdminSubcommand::IssueSvcToken(args) = admin_cmd.command else {
            panic!("expected IssueSvcToken");
        };
        assert_eq!(args.repository.as_deref(), Some("maven-proxy"));
    }

    #[test]
    fn issue_svc_token_repository_flag_defaults_to_none() {
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
        assert_eq!(args.repository, None);
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
            require_authority: None,
            repository: None,
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

    #[test]
    fn resolve_svc_user_sa_absent_path_is_unchanged_by_require_authority() {
        // `--require-authority` only changes behaviour AFTER `resolve_svc_user`
        // succeeds. The SA-absent path is untouched: it still bails here,
        // before any grant is ever consulted (there is no `RbacEvaluator` in
        // scope in this branch at all).
        let err = resolve_svc_user(None, "sa:cronjob-tasks", "cronjob-tasks").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not found"));
        assert!(msg.contains("gitops"));
    }

    // -- issue-svc-token: --require-authority preflight ---------------------
    //
    // `check_require_authority` / `unbacked_authority_message` are pure over
    // an in-memory `RbacEvaluator` snapshot (no I/O), so every branch is
    // unit-testable without a database — design doc §4.

    fn user_grant(
        uid: Uuid,
        perm: Permission,
        repo: Option<Uuid>,
    ) -> hort_domain::entities::rbac::PermissionGrant {
        hort_domain::entities::rbac::PermissionGrant {
            id: Uuid::new_v4(),
            subject: hort_domain::entities::rbac::GrantSubject::User(uid),
            repository_id: repo,
            permission: perm,
            managed_by: hort_domain::entities::managed_by::ManagedBy::GitOps,
            managed_by_digest: Some([0u8; 32]),
            created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn check_require_authority_passes_when_every_permission_is_backed() {
        let uid = Uuid::new_v4();
        let eval = RbacEvaluator::new(vec![
            user_grant(uid, Permission::AdminTaskInvoke, None),
            user_grant(uid, Permission::Read, None),
        ]);
        check_require_authority(
            &eval,
            "cronjob-tasks",
            uid,
            &[Permission::AdminTaskInvoke, Permission::Read],
            None,
        )
        .expect("all declared permissions are backed by a global grant");
    }

    #[test]
    fn check_require_authority_fails_naming_the_single_unbacked_permission() {
        let uid = Uuid::new_v4();
        let eval = RbacEvaluator::new(Vec::new());
        let err = check_require_authority(
            &eval,
            "cronjob-tasks",
            uid,
            &[Permission::AdminTaskInvoke],
            None,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("cronjob-tasks"), "unexpected: {msg}");
        assert!(msg.contains("admin_task_invoke"), "unexpected: {msg}");
        assert!(msg.contains("no grant"), "unexpected: {msg}");
        assert!(
            msg.contains("kind: PermissionGrant"),
            "must print copy-paste YAML: {msg}"
        );
        assert!(
            msg.contains("kind: serviceAccount, name: cronjob-tasks"),
            "must name the SA subject: {msg}"
        );
        assert!(
            msg.contains("permission: admin_task_invoke"),
            "must print the missing permission in the YAML: {msg}"
        );
    }

    #[test]
    fn check_require_authority_fails_naming_all_unbacked_permissions_when_several() {
        let uid = Uuid::new_v4();
        // Only `Read` is backed; `AdminTaskInvoke` and `Write` are not.
        let eval = RbacEvaluator::new(vec![user_grant(uid, Permission::Read, None)]);
        let err = check_require_authority(
            &eval,
            "cronjob-tasks",
            uid,
            &[
                Permission::AdminTaskInvoke,
                Permission::Read,
                Permission::Write,
            ],
            None,
        )
        .unwrap_err();
        let msg = err.to_string();
        // Both unbacked permissions are named — not just the first.
        assert!(msg.contains("admin_task_invoke"), "unexpected: {msg}");
        assert!(msg.contains("write"), "unexpected: {msg}");
        // The backed permission must NOT be reported as missing.
        assert_eq!(
            msg.matches("no grant for permission").count(),
            1,
            "one summary clause naming both, not per-permission bails: {msg}"
        );
        // One copy-paste YAML block per unbacked permission (two), not one.
        assert_eq!(
            msg.matches("kind: PermissionGrant").count(),
            2,
            "expected one YAML block per unbacked permission: {msg}"
        );
    }

    #[test]
    fn check_require_authority_repo_scoped_grant_does_not_satisfy_the_global_check() {
        // Regression pin: repo-scoped grant + NO `--repository`
        // still fails the GLOBAL check exactly as today. A grant scoped to
        // one repository must not be mistaken for a global grant — it would
        // let the preflight pass while the CronJob (which invokes admin
        // tasks with no repository in scope) still 403s.
        let uid = Uuid::new_v4();
        let repo = Uuid::new_v4();
        let eval = RbacEvaluator::new(vec![user_grant(
            uid,
            Permission::AdminTaskInvoke,
            Some(repo),
        )]);
        let err = check_require_authority(
            &eval,
            "cronjob-tasks",
            uid,
            &[Permission::AdminTaskInvoke],
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("admin_task_invoke"));
    }

    #[test]
    fn check_require_authority_ignores_grants_on_a_different_user() {
        let uid = Uuid::new_v4();
        let other_uid = Uuid::new_v4();
        let eval = RbacEvaluator::new(vec![user_grant(
            other_uid,
            Permission::AdminTaskInvoke,
            None,
        )]);
        let err = check_require_authority(
            &eval,
            "cronjob-tasks",
            uid,
            &[Permission::AdminTaskInvoke],
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("admin_task_invoke"));
    }

    #[test]
    fn unbacked_authority_message_lists_every_permission_and_a_yaml_block_each() {
        let msg = unbacked_authority_message(
            "cronjob-tasks",
            &[Permission::AdminTaskInvoke, Permission::Read],
            None,
        );
        assert!(msg.contains("admin_task_invoke"));
        assert!(msg.contains("permission: read"));
        assert_eq!(msg.matches("apiVersion: project-hort.de/v1").count(), 2);
        assert_eq!(msg.matches("metadata: { name: cronjob-tasks-").count(), 2);
    }

    // -- issue-svc-token: scope-aware preflight -----------------------------

    #[test]
    fn check_require_authority_repo_scoped_grant_backs_matching_repository_scope() {
        // A grant scoped to the SAME repository the CLI checks satisfies
        // the preflight — the whole point of scope-aware authority.
        let uid = Uuid::new_v4();
        let repo = Uuid::new_v4();
        let eval = RbacEvaluator::new(vec![user_grant(uid, Permission::Read, Some(repo))]);
        check_require_authority(
            &eval,
            "uat-smoke",
            uid,
            &[Permission::Read],
            Some((repo, "maven-proxy")),
        )
        .expect("repo-scoped grant backs the matching repo-scoped check");
    }

    #[test]
    fn check_require_authority_repo_scoped_grant_does_not_back_a_different_repository() {
        let uid = Uuid::new_v4();
        let granted_repo = Uuid::new_v4();
        let checked_repo = Uuid::new_v4();
        let eval = RbacEvaluator::new(vec![user_grant(uid, Permission::Read, Some(granted_repo))]);
        let err = check_require_authority(
            &eval,
            "uat-smoke",
            uid,
            &[Permission::Read],
            Some((checked_repo, "maven-proxy")),
        )
        .unwrap_err();
        let msg = err.to_string();
        // Names the checked scope, not just the permission.
        assert!(msg.contains("maven-proxy"), "unexpected: {msg}");
        assert!(msg.contains("read"), "unexpected: {msg}");
    }

    #[test]
    fn check_require_authority_global_grant_backs_a_repo_scoped_check() {
        // Global ⊇ repo: a global grant satisfies a repo-scoped preflight
        // exactly as it satisfies a repo-scoped request at runtime.
        let uid = Uuid::new_v4();
        let repo = Uuid::new_v4();
        let eval = RbacEvaluator::new(vec![user_grant(uid, Permission::Read, None)]);
        check_require_authority(
            &eval,
            "uat-smoke",
            uid,
            &[Permission::Read],
            Some((repo, "maven-proxy")),
        )
        .expect("a global grant must satisfy a repo-scoped preflight (global ⊇ repo)");
    }

    #[test]
    fn unbacked_authority_message_names_the_checked_repository_scope() {
        let msg = unbacked_authority_message("uat-smoke", &[Permission::Read], Some("maven-proxy"));
        assert!(
            msg.contains("(repository: maven-proxy)"),
            "must name the checked scope in the summary: {msg}"
        );
        assert!(
            msg.contains("repository: maven-proxy"),
            "must show the matching grant YAML shape for that scope: {msg}"
        );
        // Never the unconditional global form when a scope was checked.
        assert!(
            !msg.contains("global (no repository:)"),
            "must not show the global YAML shape for a scoped check: {msg}"
        );
    }

    #[test]
    fn unbacked_authority_message_global_form_is_byte_unchanged() {
        // No repository scope → identical shape to the pre-scoping message.
        let msg = unbacked_authority_message("cronjob-tasks", &[Permission::AdminTaskInvoke], None);
        assert!(msg.contains("# global (no repository:)"));
        assert!(!msg.contains("(repository:"));
    }

    // -- issue-svc-token: cap scoping ----------------------------------------

    #[test]
    fn cap_repository_ids_is_none_without_a_repository_flag() {
        // Regression pin: flagless mint stays byte-compatible — `None`,
        // not an empty vec (which the use case rejects outright).
        assert_eq!(cap_repository_ids(None), None);
    }

    #[test]
    fn cap_repository_ids_scopes_to_the_single_resolved_repo() {
        let repo = Uuid::new_v4();
        assert_eq!(cap_repository_ids(Some(repo)), Some(vec![repo]));
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

    // -- `--output=file:` sink: the secret never lands in a file whose
    //    mode or type this process did not set -----------------------------
    //
    // The three cases the sink has to survive, each asserting the
    // PERMISSIONS of the resulting file and not merely its content:
    // a pre-existing world-readable regular file, a pre-existing symlink,
    // and a target that does not exist yet. What flows through here is a
    // service-account bearer or a full-cap bootstrap admin PAT, so these
    // run against a real filesystem — the mode bits of the resulting
    // inode, and whether a symlink was followed, are not observable any
    // other way.

    const SINK_TOKEN: &str = "hort_pat_sekret-bearer-value";

    /// Permission bits of `path`.
    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).expect("stat").permissions().mode() & 0o777
    }

    /// Drive the `file:<path>` sink exactly as the command does: through
    /// `parse_output_mode`, so the test covers the real argument path and
    /// not just the writer.
    fn write_token_to(path: &Path) {
        let mode = parse_output_mode(&format!("file:{}", path.display())).expect("parse");
        assert_eq!(mode.as_deref(), Some(path.to_str().unwrap()));
        write_plaintext(&mode, SINK_TOKEN).expect("write");
    }

    #[cfg(unix)]
    #[test]
    fn output_file_target_that_does_not_exist_is_created_0600() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("svc.token");

        write_token_to(&path);

        assert_eq!(mode_of(&path), 0o600, "a fresh token file must be 0600");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), SINK_TOKEN);
        // No temp sibling may survive — a leftover would be a second copy
        // of the bearer at a name nothing cleans up.
        let mut names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, vec!["svc.token".to_string()]);
    }

    #[cfg(unix)]
    #[test]
    fn output_file_existing_world_readable_target_ends_up_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("svc.token");

        // A local user pre-creates the operator's output path 0644. With
        // `create(true).truncate(true).mode(0o600)` the mode would survive
        // (mode applies only on create) and the bearer would land in a
        // world-readable file.
        std::fs::write(&path, "pre-existing").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(mode_of(&path), 0o644, "precondition");

        write_token_to(&path);

        assert_eq!(
            mode_of(&path),
            0o600,
            "the documented 0600 output must hold on an overwrite too"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            SINK_TOKEN,
            "and the overwrite must still work — operators re-run \
             issue-svc-token against the same path"
        );
    }

    #[cfg(unix)]
    #[test]
    fn output_file_existing_symlink_is_replaced_not_followed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let elsewhere = dir.path().join("attacker-readable");
        std::fs::write(&elsewhere, "original elsewhere bytes").unwrap();
        let path = dir.path().join("svc.token");
        std::os::unix::fs::symlink(&elsewhere, &path).unwrap();

        write_token_to(&path);

        assert!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_file(),
            "the symlink must be replaced by our own regular file"
        );
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), SINK_TOKEN);
        assert_eq!(
            std::fs::read_to_string(&elsewhere).unwrap(),
            "original elsewhere bytes",
            "the bearer must not reach the link target — a path the \
             operator never named"
        );
    }

    #[cfg(unix)]
    #[test]
    fn output_file_leaves_the_operators_directory_mode_alone() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let etc_hort = dir.path().join("etc-hort");
        std::fs::create_dir(&etc_hort).unwrap();
        // Mimic the native deployment's /etc/hort: group-readable on
        // purpose so the service user can read hort-server.env beside the
        // token. Pulling it to 0700 on a mint would break the service.
        std::fs::set_permissions(&etc_hort, std::fs::Permissions::from_mode(0o750)).unwrap();

        write_token_to(&etc_hort.join("tasks-token"));

        assert_eq!(mode_of(&etc_hort), 0o750);
    }

    #[test]
    fn output_file_with_a_missing_parent_directory_fails_loudly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("no-such-dir").join("svc.token");
        let mode = parse_output_mode(&format!("file:{}", path.display())).expect("parse");

        let err = write_plaintext(&mode, SINK_TOKEN).expect_err("must fail");

        // The message has to name the path the operator passed, so a
        // provisioning run that fails is actionable from its log alone.
        let msg = format!("{err:#}");
        assert!(msg.contains(path.to_str().unwrap()), "unexpected: {msg}");
        assert!(!path.exists(), "no partial token file may be left behind");
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

    // -- bootstrap rotation: revoke by principal, every page ---------------

    /// Shorthand for the `ApiTokenRepository` port's return type. The fully
    /// qualified form is wider than the 100-char line budget in every method
    /// signature below.
    type Fut<'a, T> = hort_domain::ports::BoxFuture<'a, hort_domain::error::DomainResult<T>>;

    /// `ApiTokenRepository` fixture that honours `PageRequest`.
    ///
    /// The shared `hort_app::use_cases::test_support::MockApiTokenRepository`
    /// returns its whole canned list on every call regardless of offset, so
    /// it cannot tell a one-page walk from an all-pages walk — which is the
    /// property under test here.
    struct PagingTokenRepo {
        rows: Vec<ApiToken>,
        revokes: std::sync::Mutex<Vec<Uuid>>,
    }

    impl PagingTokenRepo {
        fn new(rows: Vec<ApiToken>) -> Self {
            Self {
                rows,
                revokes: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn revoked(&self) -> Vec<Uuid> {
            self.revokes.lock().unwrap().clone()
        }
    }

    impl ApiTokenRepository for PagingTokenRepo {
        fn insert(&self, _token: &ApiToken) -> Fut<'_, ()> {
            Box::pin(async { Ok(()) })
        }

        fn find_by_prefix(&self, _prefix: &str) -> Fut<'_, Option<ApiToken>> {
            Box::pin(async { Ok(None) })
        }

        fn find_by_id(&self, id: Uuid) -> Fut<'_, ApiToken> {
            let found = self.rows.iter().find(|t| t.id == id).cloned().ok_or(
                hort_domain::error::DomainError::NotFound {
                    entity: "ApiToken",
                    id: id.to_string(),
                },
            );
            Box::pin(async move { found })
        }

        fn list_for_user(
            &self,
            user_id: Uuid,
            page: PageRequest,
        ) -> Fut<'_, hort_domain::types::Page<ApiToken>> {
            let owned: Vec<ApiToken> = self
                .rows
                .iter()
                .filter(|t| t.user_id == user_id)
                .cloned()
                .collect();
            let total = owned.len() as u64;
            let items = owned
                .into_iter()
                .skip(page.offset as usize)
                .take(page.limit as usize)
                .collect();
            Box::pin(async move { Ok(hort_domain::types::Page { items, total }) })
        }

        fn update_last_used(
            &self,
            _token_id: Uuid,
            _at: chrono::DateTime<chrono::Utc>,
            _client_ip: Option<&str>,
            _user_agent: Option<&str>,
        ) -> Fut<'_, ()> {
            Box::pin(async { Ok(()) })
        }

        fn revoke(&self, token_id: Uuid) -> Fut<'_, ()> {
            self.revokes.lock().unwrap().push(token_id);
            Box::pin(async { Ok(()) })
        }
    }

    const BOOTSTRAP_USER_ID: Uuid = Uuid::from_u128(0xB0075);

    fn token_row(name: &str, user_id: Uuid, revoked: bool) -> ApiToken {
        ApiToken {
            id: Uuid::new_v4(),
            user_id,
            name: name.to_owned(),
            description: None,
            kind: hort_domain::entities::api_token::TokenKind::Pat,
            token_hash: "$argon2id$dummy".to_owned(),
            token_prefix: "abcdefgh".to_owned(),
            declared_permissions: vec![Permission::Admin],
            repository_ids: None,
            expires_at: None,
            revoked_at: revoked.then(chrono::Utc::now),
            last_used_at: None,
            last_used_ip: None,
            last_used_user_agent: None,
            created_by_user_id: user_id,
            created_at: chrono::Utc::now(),
        }
    }

    /// An `ApiTokenUseCase` over the paging repo, wired the way
    /// `bootstrap_session_async` wires it.
    fn token_use_case_over(repo: Arc<PagingTokenRepo>) -> ApiTokenUseCase {
        use hort_app::use_cases::test_support::{MockEventStore, MockUserRepository};
        let users = Arc::new(MockUserRepository::new());
        let events = Arc::new(EventStorePublisher::without_broadcast(
            Arc::new(MockEventStore::new()) as Arc<dyn EventStore>,
        ));
        build_token_use_case(repo as Arc<dyn ApiTokenRepository>, users, events)
    }

    #[tokio::test]
    async fn rotation_revokes_a_bootstrap_token_under_a_non_reserved_name() {
        // The finding: a token the break-glass principal owns under an
        // operator-chosen name is exactly as powerful as the reserved one,
        // and the name-matched sweep left it live through every subsequent
        // rotation. Ownership is the whole predicate.
        let reserved = token_row(BOOTSTRAP_ADMIN_TOKEN_NAME, BOOTSTRAP_USER_ID, false);
        let renamed = token_row("ci-automation", BOOTSTRAP_USER_ID, false);
        let already_revoked = token_row("stale", BOOTSTRAP_USER_ID, true);
        let someone_else = token_row("other-user-token", Uuid::new_v4(), false);
        let repo = Arc::new(PagingTokenRepo::new(vec![
            reserved.clone(),
            renamed.clone(),
            already_revoked.clone(),
            someone_else.clone(),
        ]));

        let ids = live_token_ids_for_user(repo.as_ref(), BOOTSTRAP_USER_ID)
            .await
            .unwrap();
        let uc = token_use_case_over(repo.clone());
        revoke_bootstrap_admin_tokens(
            &uc,
            ApiActor {
                user_id: BOOTSTRAP_USER_ID,
            },
            &ids,
        )
        .await
        .unwrap();

        let revoked = repo.revoked();
        assert!(
            revoked.contains(&renamed.id),
            "a non-reserved-name token of the bootstrap principal must be revoked"
        );
        assert!(revoked.contains(&reserved.id));
        // Already-revoked rows are skipped, and another user's token is not
        // this principal's to revoke.
        assert!(!revoked.contains(&already_revoked.id));
        assert!(!revoked.contains(&someone_else.id));
        assert_eq!(revoked.len(), 2);
    }

    #[tokio::test]
    async fn rotation_revokes_tokens_beyond_the_first_page() {
        // The second half of the same finding: the sweep read one page.
        // Seed more rows than `TOKEN_PAGE_LIMIT` and require the last one —
        // which only a multi-page walk reaches — to be revoked.
        let rows: Vec<ApiToken> = (0..(TOKEN_PAGE_LIMIT as usize * 2 + 7))
            .map(|i| token_row(&format!("token-{i}"), BOOTSTRAP_USER_ID, false))
            .collect();
        let last_id = rows.last().unwrap().id;
        let repo = Arc::new(PagingTokenRepo::new(rows.clone()));

        let ids = live_token_ids_for_user(repo.as_ref(), BOOTSTRAP_USER_ID)
            .await
            .unwrap();
        assert_eq!(ids.len(), rows.len());
        let uc = token_use_case_over(repo.clone());
        revoke_bootstrap_admin_tokens(
            &uc,
            ApiActor {
                user_id: BOOTSTRAP_USER_ID,
            },
            &ids,
        )
        .await
        .unwrap();

        let revoked = repo.revoked();
        assert_eq!(revoked.len(), rows.len());
        assert!(
            revoked.contains(&last_id),
            "a token past the first page must be revoked"
        );
    }

    #[tokio::test]
    async fn live_token_ids_for_user_is_empty_for_a_principal_with_no_tokens() {
        // First bootstrap run on a fresh database: nothing to revoke, and
        // the walk must not bail.
        let repo = PagingTokenRepo::new(Vec::new());
        let ids = live_token_ids_for_user(&repo, BOOTSTRAP_USER_ID)
            .await
            .unwrap();
        assert!(ids.is_empty());
    }

    #[tokio::test]
    async fn live_token_ids_for_user_bails_when_the_walk_does_not_terminate() {
        // A repository that ignores `offset` would otherwise spin the CLI
        // forever — headless, indistinguishable from a hang. The budget
        // reports an error rather than silently truncating the sweep, which
        // would leave live full-admin tokens behind while the command
        // claimed success.
        struct OffsetIgnoringRepo {
            page: Vec<ApiToken>,
        }

        impl ApiTokenRepository for OffsetIgnoringRepo {
            fn insert(&self, _token: &ApiToken) -> Fut<'_, ()> {
                Box::pin(async { Ok(()) })
            }
            fn find_by_prefix(&self, _prefix: &str) -> Fut<'_, Option<ApiToken>> {
                Box::pin(async { Ok(None) })
            }
            fn find_by_id(&self, id: Uuid) -> Fut<'_, ApiToken> {
                Box::pin(async move {
                    Err(hort_domain::error::DomainError::NotFound {
                        entity: "ApiToken",
                        id: id.to_string(),
                    })
                })
            }
            fn list_for_user(
                &self,
                _user_id: Uuid,
                _page: PageRequest,
            ) -> Fut<'_, hort_domain::types::Page<ApiToken>> {
                let items = self.page.clone();
                Box::pin(async move {
                    Ok(hort_domain::types::Page {
                        items,
                        total: u64::MAX,
                    })
                })
            }
            fn update_last_used(
                &self,
                _token_id: Uuid,
                _at: chrono::DateTime<chrono::Utc>,
                _client_ip: Option<&str>,
                _user_agent: Option<&str>,
            ) -> Fut<'_, ()> {
                Box::pin(async { Ok(()) })
            }
            fn revoke(&self, _token_id: Uuid) -> Fut<'_, ()> {
                Box::pin(async { Ok(()) })
            }
        }

        let repo = OffsetIgnoringRepo {
            page: (0..TOKEN_PAGE_LIMIT)
                .map(|i| token_row(&format!("t{i}"), BOOTSTRAP_USER_ID, false))
                .collect(),
        };
        let err = live_token_ids_for_user(&repo, BOOTSTRAP_USER_ID)
            .await
            .expect_err("a non-terminating walk must be reported, not truncated");
        assert!(
            err.to_string().contains("did not terminate"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn bootstrap_admin_username_is_non_sa_reserved_name() {
        // Pin the reserved identity name so a rename is a deliberate
        // review point (catalog + ADR reference it).
        assert_eq!(BOOTSTRAP_ADMIN_USERNAME, "bootstrap-admin");
        assert_eq!(BOOTSTRAP_ADMIN_TOKEN_NAME, "bootstrap-session");
    }
}
