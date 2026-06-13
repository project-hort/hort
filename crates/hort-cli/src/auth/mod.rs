//! `hort-cli auth` subcommands: login, status, logout.

pub mod discovery;
pub mod login;
pub mod logout;
/// RFC 8252 loopback-redirect flow (desktop default).
pub mod loopback;
pub mod oidc;
pub mod status;

use clap::Subcommand;

use crate::config::OutputFormat;

/// Wire DTO mirroring `GET /api/v1/auth/whoami` response.
///
/// Defined here (not in `hort-http-core`) so `hort-cli` has zero dep on any
/// server crate. The shape is stable: any future field additions are
/// backwards-compatible via `#[serde(default)]`.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct WhoamiResponse {
    pub user_id: Option<String>,
    pub username: Option<String>,
    pub token_kind: Option<String>,
    pub permissions: Vec<String>,
}

// ---------------------------------------------------------------------------
// Clap subcommand tree
// ---------------------------------------------------------------------------

/// `hort-cli auth` subcommand arguments.
#[derive(clap::Args, Debug)]
pub struct AuthArgs {
    #[command(subcommand)]
    pub cmd: AuthCommand,
}

/// `auth` sub-subcommands.
#[derive(Subcommand, Debug)]
pub enum AuthCommand {
    /// Authenticate and persist a token to ~/.hort/config.toml.
    Login(login::LoginArgs),
    /// Show the current authenticated principal.
    Status,
    /// Clear the locally stored token (server-side token remains valid).
    Logout,
}

/// Dispatch `auth` sub-subcommands.
pub async fn run(args: AuthArgs, output: OutputFormat) -> anyhow::Result<std::process::ExitCode> {
    match args.cmd {
        AuthCommand::Login(login_args) => login::run(login_args).await,
        AuthCommand::Status => status::run(output).await,
        AuthCommand::Logout => logout::run().await,
    }
}
