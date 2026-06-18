//! `hort-cli` library root.
//!
//! Re-exports the three public modules so integration tests (in
//! `crates/hort-cli/tests/`) can import via `hort_cli::client::AkClient`,
//! `hort_cli::config::EffectiveConfig`, and `hort_cli::output::format_json`
//! without duplicating paths.
//!
//! This is a pure HTTP client: zero deps on `hort-domain`, `hort-app`, or
//! `hort-adapters-*`. This is enforced by the dep graph (no path-dep on
//! any of those crates in `Cargo.toml`) and verified post-build via
//! `cargo tree -p hort-cli`.

use clap::{Parser, Subcommand};

use crate::admin::AdminArgs;
use crate::auth::AuthArgs;
use crate::completions::CompletionsArgs;
use crate::config::OutputFormat;
use crate::curation::CurationArgs;
use crate::get::GetArgs;
use crate::list_versions::ListVersionsArgs;
use crate::prefetch::PrefetchArgs;

/// Admin task subcommands (invoke, list, get).
pub mod admin;
/// Auth subcommands (login, status, logout).
pub mod auth;
pub mod client;
pub mod completions;
pub mod config;
/// Curation decision subcommands (waive, block, exclude-finding,
/// unexclude-finding). Mounted at the top level of the `Commands` enum,
/// NOT under `admin`.
pub mod curation;
/// Get subcommands (repo-score).
pub mod get;
/// `list-versions` subcommand. Top-level mount (mirrors `get`'s
/// placement); calls
/// `GET /api/v1/repositories/{repo}/discovery/versions/{package}` and
/// renders a status-annotated table.
pub mod list_versions;
pub mod output;
/// `prefetch` subcommand. Top-level mount; POSTs a single-item `items`
/// array to `/api/v1/repositories/{repo}/prefetch` and renders the
/// `PrefetchOutcome` continue-on-error envelope.
pub mod prefetch;

// -----------------------------------------------------------------
// CLI shape (pub so `main.rs` and `completions.rs` can both see them)
// -----------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name = "hort-cli",
    version,
    about = "Hort CLI",
    long_about = None,
    // Print help when no subcommand is given.
    subcommand_required = false,
    arg_required_else_help = false,
)]
pub struct Cli {
    /// Server base URL (overrides HORT_SERVER and config file).
    #[arg(long, env = "HORT_SERVER", global = true)]
    pub server: Option<String>,

    /// Bearer token (overrides HORT_TOKEN and config file).
    #[arg(long, env = "HORT_TOKEN", global = true)]
    pub token: Option<String>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Table, global = true)]
    pub output: OutputFormat,

    #[command(subcommand)]
    pub cmd: Option<Commands>,
}

/// Subcommand variants.
///
/// `Curation` is mounted at the top level, NOT under `Admin` — the
/// hort-server convention places operational verbs alongside `Admin`.
#[derive(Subcommand, Debug)]
pub enum Commands {
    // Auth subcommands.
    /// Authenticate with the server (login, status, logout).
    Auth(AuthArgs),
    // Admin task subcommands.
    /// Manage server admin tasks (invoke, list, get).
    Admin(AdminArgs),
    // Get subcommands.
    /// Get repository security scores.
    Get(GetArgs),
    // Curator decision subcommands (top-level, not under admin).
    /// Curator decisions: waive, block, exclude-finding, unexclude-finding.
    Curation(CurationArgs),
    // Discovery + self-service prefetch subcommands (top-level,
    // mirroring the `get` subcommand placement). Both require a CLI
    // session JWT (TokenKind::CliSession) — enforced server-side, no
    // client-side pre-flight (the server is the source of truth and a
    // redundant check would drift).
    /// List versions of a package in a repository with per-version
    /// status (released / quarantined / rejected / unknown / ...).
    ListVersions(ListVersionsArgs),
    /// Enqueue a self-service prefetch for `(repo, package, version?)`.
    Prefetch(PrefetchArgs),
    /// Generate a shell completion script (bash/zsh/fish/powershell/elvish).
    Completions(CompletionsArgs),
}

/// Render a top-level CLI error for stderr.
///
/// `hort-cli` is a pure HTTP client; the operationally-important failure
/// class is a transport error wrapped in `.context("HTTP <verb>")` by
/// [`client::AkClient`]. The underlying cause (connection refused, DNS
/// failure, TLS error, timeout) lives in the `anyhow` *source chain*.
///
/// The bare `{err}` Display renders only the outermost context — so a
/// `kubectl logs` of a failed CronJob showed only `hort-cli: HTTP POST`
/// with the actual reason swallowed (the rotation-smoke masking bug).
/// The alternate `{err:#}` Display walks the full chain
/// (`HTTP POST: error trying to connect: tcp connect error: …`), which
/// is what an operator needs. Kept as a small pure function so the
/// chain-preservation guarantee is unit-testable without driving
/// `main()`.
pub fn render_cli_error(err: &anyhow::Error) -> String {
    format!("hort-cli: {err:#}")
}

#[cfg(test)]
mod tests {
    use anyhow::{anyhow, Context};

    #[test]
    fn render_cli_error_includes_full_anyhow_chain() {
        // Reproduces the masking bug: a transport error wrapped in
        // `.context("HTTP POST")` (client.rs:146) must surface BOTH the
        // context AND the underlying cause — not just the top context.
        let err = Err::<(), _>(anyhow!(
            "error trying to connect: tcp connect error: Connection refused (os error 111)"
        ))
        .context("HTTP POST")
        .unwrap_err();

        let rendered = super::render_cli_error(&err);

        assert!(
            rendered.contains("HTTP POST"),
            "top-level context missing: {rendered}"
        );
        assert!(
            rendered.contains("Connection refused"),
            "underlying cause swallowed (the smoke masking bug): {rendered}"
        );
    }
}
