//! `hort-cli` binary entrypoint.
//!
//! clap dispatch shell for the hort command-line client. Wires the
//! subcommands (auth / admin task / get repo-score / curation /
//! discovery / prefetch) and prints help when invoked with no
//! subcommand so `hort-cli --help` works.
//!
//! # Design notes
//!
//! - `current_thread` tokio runtime is sufficient for a CLI tool that
//!   makes sequential HTTP requests. No background tasks run here;
//!   concurrency is at the process level (operator scripts).
//! - Config resolution (`load_effective_config`) is called before
//!   any subcommand dispatch so all subcommands receive a validated
//!   `EffectiveConfig`. Unknown-field tolerance is handled inside
//!   `load_effective_config`.
//! - Tracing is initialised at `WARN` level for third-party crates
//!   (`reqwest`, `hyper`) to prevent bearer tokens from appearing in
//!   debug logs via reqwest's own log adapter.

use std::process::ExitCode;

use clap::{Parser, Subcommand};

use hort_cli::admin::AdminArgs;
use hort_cli::auth::AuthArgs;
use hort_cli::config::OutputFormat;
use hort_cli::curation::CurationArgs;
use hort_cli::get::GetArgs;
use hort_cli::list_versions::ListVersionsArgs;
use hort_cli::prefetch::PrefetchArgs;

// -----------------------------------------------------------------
// CLI shape
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
struct Cli {
    /// Server base URL (overrides HORT_SERVER and config file).
    #[arg(long, env = "HORT_SERVER", global = true)]
    server: Option<String>,

    /// Bearer token (overrides HORT_TOKEN and config file).
    #[arg(long, env = "HORT_TOKEN", global = true)]
    token: Option<String>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Table, global = true)]
    output: OutputFormat,

    #[command(subcommand)]
    cmd: Option<Commands>,
}

/// Subcommand variants.
///
/// `Curation` is mounted at the top level, NOT under `Admin` — the
/// hort-server convention places operational verbs alongside `Admin`.
#[derive(Subcommand, Debug)]
enum Commands {
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
}

// -----------------------------------------------------------------
// Entrypoint
// -----------------------------------------------------------------

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    // Initialise tracing. RUST_LOG overrides the default.
    // Third-party crates (reqwest, hyper) are clamped to WARN so their
    // debug logs — which may include request headers — stay silent by
    // default. Our own `hort_cli` target defaults to the outer RUST_LOG
    // value, falling back to INFO.
    init_tracing();

    // Dispatch subcommands. Each subcommand handles config resolution
    // independently so `auth login` can run without an existing config file.
    match cli.cmd {
        None => {
            // No subcommand — print a short nudge. clap's --help gives the
            // full usage; we keep this brief so it doesn't drown in noise.
            eprintln!("hort-cli: no subcommand. Run `hort-cli --help` for usage.");
            ExitCode::from(2)
        }
        // Auth subcommands.
        Some(Commands::Auth(auth_args)) => match hort_cli::auth::run(auth_args, cli.output).await {
            Ok(code) => code,
            Err(e) => {
                eprintln!("{}", hort_cli::render_cli_error(&e));
                ExitCode::from(1)
            }
        },
        // Admin task subcommands.
        Some(Commands::Admin(admin_args)) => {
            match hort_cli::admin::run(admin_args, cli.output, cli.server, cli.token).await {
                Ok(code) => code,
                Err(e) => {
                    eprintln!("{}", hort_cli::render_cli_error(&e));
                    ExitCode::from(1)
                }
            }
        }
        // Get subcommands.
        Some(Commands::Get(get_args)) => {
            match hort_cli::get::run(get_args, cli.output, cli.server, cli.token).await {
                Ok(code) => code,
                Err(e) => {
                    eprintln!("{}", hort_cli::render_cli_error(&e));
                    ExitCode::from(1)
                }
            }
        }
        // Curator decision subcommands.
        Some(Commands::Curation(curation_args)) => {
            match hort_cli::curation::run(curation_args, cli.output, cli.server, cli.token).await {
                Ok(code) => code,
                Err(e) => {
                    eprintln!("{}", hort_cli::render_cli_error(&e));
                    ExitCode::from(1)
                }
            }
        }
        // list-versions subcommand.
        Some(Commands::ListVersions(args)) => {
            match hort_cli::list_versions::run(args, cli.output, cli.server, cli.token).await {
                Ok(code) => code,
                Err(e) => {
                    eprintln!("{}", hort_cli::render_cli_error(&e));
                    ExitCode::from(1)
                }
            }
        }
        // prefetch subcommand.
        Some(Commands::Prefetch(args)) => {
            match hort_cli::prefetch::run(args, cli.output, cli.server, cli.token).await {
                Ok(code) => code,
                Err(e) => {
                    eprintln!("{}", hort_cli::render_cli_error(&e));
                    ExitCode::from(1)
                }
            }
        }
    }
}

// -----------------------------------------------------------------
// Tracing initialisation
// -----------------------------------------------------------------

/// Install a `tracing-subscriber` that:
/// - reads `RUST_LOG` for the filter (defaulting to `warn`), and
/// - clamps `reqwest` / `hyper` to `warn` so their debug output
///   (which may include headers) stays silent.
///
/// The default is `warn` rather than `info` because `hort-cli` is an
/// interactive CLI: every user-facing event already has a dedicated
/// `eprintln!` / `println!` line, and `info!` events about the same
/// transitions (login success, token rejection, headless detection,
/// device-flow terminal states) would print twice on stderr — once via
/// the user-facing line, once via the tracing format. Operators wanting
/// the structured `info!` trail (CI / log scrapers) opt in with
/// `RUST_LOG=info`.
///
/// Uses the compact formatter (no timestamps by default) so CLI output
/// is readable without a log aggregator. Operators who need JSON output
/// can pipe through `jq` or set `RUST_LOG_FORMAT=json` in a future
/// revision.
fn init_tracing() {
    use tracing_subscriber::EnvFilter;

    let base = std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".to_string());
    // Append a hard floor for reqwest / hyper so tokens never leak via
    // their DEBUG log output even if the operator sets RUST_LOG=debug.
    let filter_str = format!("{base},reqwest=warn,hyper=warn,hyper_util=warn");
    let filter = EnvFilter::try_new(&filter_str)
        .unwrap_or_else(|_| EnvFilter::new("warn,reqwest=warn,hyper=warn"));

    // `try_init` returns Err only if a global subscriber is already set
    // (happens in test harness when multiple tests call init). Silently
    // ignore that error.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
