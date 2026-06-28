//! `hort-cli admin` subcommand tree.
//!
//! # Dep-graph invariant
//!
//! This module — and all its children — must not import anything from
//! `hort-domain`, `hort-app`, or `hort-adapters-*`. The DTOs (`TaskRow`,
//! `TaskListResponse`, `InvokeResponse`) are defined here verbatim from
//! the wire contract exposed by `hort-http-admin-tasks::dto`. Keeping them
//! local preserves the adapter-free property of `hort-cli`.
//!
//! **Sync note**: `TaskRow` and `TaskListResponse` here must stay in sync
//! with `hort-http-admin-tasks::dto::{JobRowDto, TaskListDto}`. The wire
//! format (field names, JSON serialisation) is the contract.

pub mod quarantine;
pub mod rbac;
pub mod rescan;
pub mod task_get;
pub mod task_invoke;
pub mod task_list;
pub mod users;
pub mod workers;

use clap::Subcommand;

use crate::config::OutputFormat;

// ---------------------------------------------------------------------------
// Clap subcommand tree
// ---------------------------------------------------------------------------

/// `hort-cli admin` arguments.
#[derive(clap::Args, Debug)]
pub struct AdminArgs {
    #[command(subcommand)]
    pub cmd: AdminCommand,
}

/// `admin` sub-subcommands.
#[derive(Subcommand, Debug)]
pub enum AdminCommand {
    /// Manage admin tasks (invoke, list, get).
    Task(TaskArgs),

    /// Trigger a manual rescan of a single artifact.
    ///
    /// POSTs to `/api/v1/artifacts/<id>/rescan` and returns the new
    /// `task_job_id`. Distinct from `admin task invoke` because the server
    /// endpoint is per-artifact, not per-kind.
    Rescan(rescan::RescanArgs),

    /// Quarantine operations: list patch-candidates, admin-release a
    /// quarantined artifact.
    ///
    /// Surfaces the patch-candidate read endpoint and the admin override
    /// release under one `admin quarantine` group. Mirrors the HTTP
    /// surface, where both routes nest under `/admin/quarantine/...`.
    /// See `docs/architecture/how-to/quarantine-patch-release.md`.
    Quarantine(quarantine::QuarantineArgs),

    /// Per-user admin reads.
    ///
    /// `users effective-permissions <user_id>` surfaces what HORT knows
    /// about a user *without their token*: the `is_admin` bit and every
    /// currently-matching grant
    /// (`GET /admin/users/:user_id/effective-permissions`).
    /// See `docs/architecture/how-to/operate/claim-based-rbac.md`.
    Users(users::UsersArgs),

    /// RBAC introspection reads.
    ///
    /// `rbac resolve --group <g>...` is the admin what-if resolver
    /// (`POST /admin/rbac/resolve`): supply a user's IdP groups and HORT
    /// resolves the `groups → claims → effective (repo, permission) grants`
    /// half it owns (no IdP query, no cache). The claim-based companion to
    /// `users effective-permissions`.
    /// See `docs/architecture/how-to/operate/claim-based-rbac.md`.
    Rbac(rbac::RbacArgs),

    /// Scanner-worker registry reads.
    ///
    /// `workers list` shows every worker that has registered in the
    /// `scanner_registry` — its advertised backends and liveness
    /// (`GET /admin/workers`). Stale/dead workers stay in the listing
    /// (`LIVE=NO`) rather than vanishing.
    Workers(workers::WorkersArgs),
}

/// `admin task` arguments.
#[derive(clap::Args, Debug)]
pub struct TaskArgs {
    #[command(subcommand)]
    pub cmd: TaskCommand,
}

/// `admin task` sub-subcommands.
#[derive(Subcommand, Debug)]
pub enum TaskCommand {
    /// Invoke a task by kind.
    ///
    /// v1 allowlist: noop, staging-sweep, scan, cron-rescan-tick,
    /// advisory-watch-tick, retention-evaluate, retention-purge,
    /// eventstore-archive.
    ///
    /// Body defaults to `{}`. Use `--params-file <path>` to supply JSON
    /// params. `--param k=v` style is deferred post-v1.
    Invoke(task_invoke::TaskInvokeArgs),

    /// List enqueued / running / completed task jobs.
    List(task_list::TaskListArgs),

    /// Show a single task job by ID.
    Get(task_get::TaskGetArgs),
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Dispatch `admin` sub-subcommands.
pub async fn run(
    args: AdminArgs,
    output: OutputFormat,
    cli_server: Option<String>,
    cli_token: Option<String>,
) -> anyhow::Result<std::process::ExitCode> {
    match args.cmd {
        AdminCommand::Task(task_args) => run_task(task_args, output, cli_server, cli_token).await,
        AdminCommand::Rescan(rescan_args) => {
            run_rescan(rescan_args, output, cli_server, cli_token).await
        }
        AdminCommand::Quarantine(quarantine_args) => {
            run_quarantine(quarantine_args, output, cli_server, cli_token).await
        }
        AdminCommand::Users(users_args) => {
            run_users(users_args, output, cli_server, cli_token).await
        }
        AdminCommand::Rbac(rbac_args) => run_rbac(rbac_args, output, cli_server, cli_token).await,
        AdminCommand::Workers(workers_args) => {
            run_workers(workers_args, output, cli_server, cli_token).await
        }
    }
}

async fn run_task(
    args: TaskArgs,
    output: OutputFormat,
    cli_server: Option<String>,
    cli_token: Option<String>,
) -> anyhow::Result<std::process::ExitCode> {
    use crate::client::AkClient;
    use crate::config::load_effective_config;

    let cfg = match load_effective_config(cli_server, cli_token) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("hort-cli: config error: {e}");
            eprintln!("Hint: run `hort-cli auth login` to set up credentials.");
            return Ok(std::process::ExitCode::from(2));
        }
    };

    let client = AkClient::new(&cfg)?;

    match args.cmd {
        TaskCommand::Invoke(invoke_args) => {
            task_invoke::run(client, invoke_args, output).await?;
            Ok(std::process::ExitCode::SUCCESS)
        }
        TaskCommand::List(list_args) => {
            task_list::run(client, list_args, output).await?;
            Ok(std::process::ExitCode::SUCCESS)
        }
        TaskCommand::Get(get_args) => {
            task_get::run(client, get_args, output).await?;
            Ok(std::process::ExitCode::SUCCESS)
        }
    }
}

/// Dispatch for `admin rescan`.
async fn run_rescan(
    args: rescan::RescanArgs,
    output: OutputFormat,
    cli_server: Option<String>,
    cli_token: Option<String>,
) -> anyhow::Result<std::process::ExitCode> {
    use crate::client::AkClient;
    use crate::config::load_effective_config;

    let cfg = match load_effective_config(cli_server, cli_token) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("hort-cli: config error: {e}");
            eprintln!("Hint: run `hort-cli auth login` to set up credentials.");
            return Ok(std::process::ExitCode::from(2));
        }
    };

    let client = AkClient::new(&cfg)?;
    rescan::run(client, args, output).await?;
    Ok(std::process::ExitCode::SUCCESS)
}

/// Dispatch for `admin quarantine`.
///
/// Mirrors `run_rescan` — loads config, builds the HTTP client, hands
/// off to the `quarantine` module's per-subcommand dispatcher.
async fn run_quarantine(
    args: quarantine::QuarantineArgs,
    output: OutputFormat,
    cli_server: Option<String>,
    cli_token: Option<String>,
) -> anyhow::Result<std::process::ExitCode> {
    use crate::client::AkClient;
    use crate::config::load_effective_config;

    let cfg = match load_effective_config(cli_server, cli_token) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("hort-cli: config error: {e}");
            eprintln!("Hint: run `hort-cli auth login` to set up credentials.");
            return Ok(std::process::ExitCode::from(2));
        }
    };

    let client = AkClient::new(&cfg)?;
    quarantine::run(client, args, output).await?;
    Ok(std::process::ExitCode::SUCCESS)
}

/// Dispatch for `admin workers`.
///
/// Mirrors `run_quarantine` — loads config, builds the HTTP client, hands
/// off to the `workers` module's per-subcommand dispatcher.
async fn run_workers(
    args: workers::WorkersArgs,
    output: OutputFormat,
    cli_server: Option<String>,
    cli_token: Option<String>,
) -> anyhow::Result<std::process::ExitCode> {
    use crate::client::AkClient;
    use crate::config::load_effective_config;

    let cfg = match load_effective_config(cli_server, cli_token) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("hort-cli: config error: {e}");
            eprintln!("Hint: run `hort-cli auth login` to set up credentials.");
            return Ok(std::process::ExitCode::from(2));
        }
    };

    let client = AkClient::new(&cfg)?;
    workers::run(client, args, output).await?;
    Ok(std::process::ExitCode::SUCCESS)
}

/// Dispatch for `admin users`.
///
/// Mirrors `run_quarantine` — loads config, builds the HTTP client,
/// hands off to the `users` module's per-subcommand dispatcher.
async fn run_users(
    args: users::UsersArgs,
    output: OutputFormat,
    cli_server: Option<String>,
    cli_token: Option<String>,
) -> anyhow::Result<std::process::ExitCode> {
    use crate::client::AkClient;
    use crate::config::load_effective_config;

    let cfg = match load_effective_config(cli_server, cli_token) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("hort-cli: config error: {e}");
            eprintln!("Hint: run `hort-cli auth login` to set up credentials.");
            return Ok(std::process::ExitCode::from(2));
        }
    };

    let client = AkClient::new(&cfg)?;
    users::run(client, args, output).await?;
    Ok(std::process::ExitCode::SUCCESS)
}

/// Dispatch for `admin rbac`.
///
/// Mirrors `run_users` — loads config, builds the HTTP client, hands off
/// to the `rbac` module's per-subcommand dispatcher.
async fn run_rbac(
    args: rbac::RbacArgs,
    output: OutputFormat,
    cli_server: Option<String>,
    cli_token: Option<String>,
) -> anyhow::Result<std::process::ExitCode> {
    use crate::client::AkClient;
    use crate::config::load_effective_config;

    let cfg = match load_effective_config(cli_server, cli_token) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("hort-cli: config error: {e}");
            eprintln!("Hint: run `hort-cli auth login` to set up credentials.");
            return Ok(std::process::ExitCode::from(2));
        }
    };

    let client = AkClient::new(&cfg)?;
    rbac::run(client, args, output).await?;
    Ok(std::process::ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// Shared wire DTOs (copied from hort-http-admin-tasks::dto — must stay in sync)
// ---------------------------------------------------------------------------

/// Wire projection of a `jobs` table row.
///
/// **Sync-required**: this struct mirrors `JobRowDto` in
/// `hort-http-admin-tasks::dto`. The field names and JSON serialisation
/// form the wire contract. Any change to `JobRowDto` must be reflected
/// here.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct TaskRow {
    pub id: String,
    pub kind: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,
    pub priority: i16,
    pub trigger_source: String,
    pub attempts: u32,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    // `result_summary` is a structured JSONB value on the wire (the
    // server's `JobRowDto` emits the `jobs.result_summary` jsonb column as
    // a JSON object), so it deserialises as `serde_json::Value`, not
    // `String`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_summary: Option<serde_json::Value>,
}

/// Paginated list of task rows.
///
/// **Sync-required**: mirrors `TaskListDto` in `hort-http-admin-tasks::dto`.
#[derive(Debug, serde::Deserialize)]
pub struct TaskListResponse {
    pub tasks: Vec<TaskRow>,
    pub next_cursor: Option<String>,
}

/// Response from `POST /api/v1/admin/tasks/{kind}`.
///
/// **Sync-required**: mirrors `InvokeResponse` in
/// `hort-http-admin-tasks::handlers::invoke`.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct InvokeResponse {
    pub task_job_id: String,
}
