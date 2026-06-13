//! `hort-worker` clap surface.
//!
//! The worker has a `healthcheck` subcommand so the k8s `livenessProbe`
//! can do an `exec` probe against the binary itself instead of `pgrep -f`
//! (which requires `procps`, which the distroless runtime doesn't ship).
//!
//! No other subcommands. The default (zero-arg invocation) preserves the
//! normal behaviour: parse env, build composition, run the `TaskDispatcher`
//! until SIGTERM. That's what every existing deployment manifest invokes.
//!
//! Why a subcommand instead of a separate binary: a separate binary would
//! need its own Cargo `[[bin]]` target, a separate Docker `COPY
//! --from=builder` line, and a separate clap entry point — for a single
//! function call. The subcommand approach reuses the same binary the
//! runtime image already ships, so the k8s exec probe just invokes
//! `hort-worker healthcheck` against the existing image layer.
//!
//! The healthcheck deliberately does NOT attempt to start scanners,
//! register handlers, or open any filesystem-CAS handles. It checks
//! the cheap, frequently-failing things (env parse, DB reachability)
//! and exits. Anything heavier turns the probe into a load source.

use clap::{Parser, Subcommand};

/// Top-level CLI. `cmd` is optional so the no-subcommand invocation
/// (every existing manifest uses this) keeps working.
#[derive(Debug, Parser)]
#[command(
    name = "hort-worker",
    version,
    about = "hort v2 worker — multi-kind job dispatcher"
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Option<Command>,
}

/// Subcommands — exactly one is available.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Liveness check for the k8s `livenessProbe` exec gate.
    ///
    /// Verifies that:
    ///   1. the worker's environment parses (`WorkerConfig::from_env`),
    ///   2. the configured Postgres DSN is reachable (a single
    ///      `SELECT 1` against `hort_app_role`).
    ///
    /// Exits 0 on success, 1 on any failure. No metrics, no tracing
    /// initialisation — the probe runs every few seconds, so it must
    /// stay cheap.
    Healthcheck,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_clap_definition_validates() {
        // `Command::debug_assert` runs clap's internal sanity checks on
        // the derive-generated parser. Catches malformed `#[arg(...)]`
        // attributes at test time rather than at first user invocation.
        Cli::command().debug_assert();
    }

    #[test]
    fn no_subcommand_parses_to_none() {
        let cli = Cli::try_parse_from(["hort-worker"]).expect("zero-arg parse");
        assert!(
            cli.cmd.is_none(),
            "default (no subcommand) preserves serve behaviour"
        );
    }

    #[test]
    fn healthcheck_subcommand_parses() {
        let cli = Cli::try_parse_from(["hort-worker", "healthcheck"]).expect("healthcheck parse");
        assert!(matches!(cli.cmd, Some(Command::Healthcheck)));
    }

    #[test]
    fn unknown_subcommand_rejected() {
        let err = Cli::try_parse_from(["hort-worker", "serve"])
            .expect_err("clap must reject unknown subcommands");
        // clap returns an `InvalidSubcommand` error kind.
        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidSubcommand);
    }
}
