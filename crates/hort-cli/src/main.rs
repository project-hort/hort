//! `hort-cli` binary entrypoint.
//!
//! clap dispatch shell for the hort command-line client. Wires the
//! subcommands (auth / admin task / get repo-score / curation /
//! discovery / prefetch / completions) and prints help when invoked with
//! no subcommand so `hort-cli --help` works.
//!
//! # Design notes
//!
//! - `current_thread` tokio runtime is sufficient for a CLI tool that
//!   makes sequential HTTP requests. No background tasks run here;
//!   concurrency is at the process level (operator scripts). The runtime
//!   is built explicitly (rather than via `#[tokio::main]`) so the dynamic
//!   shell-completion entrypoint can run *before* any runtime exists — the
//!   completer's value provider does its own `block_on`, which would panic
//!   if nested inside a running runtime. See `main`.
//! - Config resolution (`load_effective_config`) is called before
//!   any subcommand dispatch so all subcommands receive a validated
//!   `EffectiveConfig`. Unknown-field tolerance is handled inside
//!   `load_effective_config`.
//! - Tracing is initialised at `WARN` level for third-party crates
//!   (`reqwest`, `hyper`) to prevent bearer tokens from appearing in
//!   debug logs via reqwest's own log adapter.

use std::process::ExitCode;

use clap::{CommandFactory, Parser};

use hort_cli::{Cli, Commands};

// -----------------------------------------------------------------
// Entrypoint
// -----------------------------------------------------------------

fn main() -> ExitCode {
    // Dynamic shell-completion entrypoint (clap_complete unstable-dynamic
    // engine). This MUST run before any stdout is written, before
    // `Cli::parse()`, and — critically — BEFORE the tokio runtime is built.
    //
    // It is a no-op unless the `COMPLETE` env var is set (i.e. the shell
    // re-invoked us mid-TAB via the registration stub from
    // `source <(COMPLETE=bash hort-cli)`); in that case it prints the
    // candidates and `process::exit(0)`s before returning. In the normal
    // (no-`COMPLETE`) case it returns immediately and we fall through to the
    // tokio runtime below.
    //
    // # Why outside the runtime
    //
    // The repo-key value provider ([`completions::repo_arg_candidates`])
    // synchronously `block_on`s a throwaway current-thread tokio runtime to
    // run the HTTP fetch. If `CompleteEnv::complete()` ran *inside* an
    // already-running `#[tokio::main]` runtime, that nested `block_on` would
    // panic ("Cannot start a runtime from within a runtime") — and a panic
    // in the completer breaks the user's shell line. Running the completion
    // entrypoint here, before any runtime exists, keeps the provider's
    // `block_on` legal. The static `hort-cli completions <shell>` subcommand
    // remains the always-available floor; see `completions::run`.
    clap_complete::CompleteEnv::with_factory(Cli::command).complete();

    // Normal (non-completion) path: build the current-thread runtime and
    // drive the async entrypoint. `current_thread` is sufficient for a CLI
    // that makes sequential HTTP requests.
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("hort-cli: failed to start async runtime: {e}");
            return ExitCode::from(1);
        }
    };
    runtime.block_on(run())
}

async fn run() -> ExitCode {
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
        // completions subcommand — synchronous, no config needed.
        Some(Commands::Completions(args)) => hort_cli::completions::run(&args),
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
