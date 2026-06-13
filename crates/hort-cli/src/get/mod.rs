//! `hort-cli get` subcommand tree.
//!
//! # Dep-graph invariant
//!
//! This module — and all its children — must not import anything from
//! `hort-domain`, `hort-app`, or `hort-adapters-*`. The DTOs (`SecurityScoreDto`,
//! `SecurityScoreListDto`) are defined here verbatim from the wire contract
//! exposed by `hort-http-admin-security::dto`. Keeping them local preserves
//! the adapter-free property of `hort-cli`.
//!
//! **Sync note**: `SecurityScoreDto` and `SecurityScoreListDto` here must
//! stay in sync with `hort-http-admin-security::dto`. The wire format (field
//! names, JSON serialisation) is the contract.

pub mod repo_score;

use clap::Subcommand;

use crate::config::OutputFormat;

// ---------------------------------------------------------------------------
// Clap subcommand tree
// ---------------------------------------------------------------------------

/// `hort-cli get` arguments.
#[derive(clap::Args, Debug)]
pub struct GetArgs {
    #[command(subcommand)]
    pub cmd: GetCommand,
}

/// `get` sub-subcommands.
#[derive(Subcommand, Debug)]
pub enum GetCommand {
    /// Print repository security scores
    RepoScore(repo_score::RepoScoreArgs),
}

/// Run the `get` subcommand dispatcher.
pub async fn run(
    args: GetArgs,
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
        GetCommand::RepoScore(args) => {
            repo_score::run(client, args, output).await?;
            Ok(std::process::ExitCode::SUCCESS)
        }
    }
}
