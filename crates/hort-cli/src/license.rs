//! `hort-cli license` — print hort's SPDX license identifier and, with
//! `--full`, the complete text of both license files.
//!
//! Synchronous, no config, no server call — mirrors `completions` (the
//! other print-and-exit subcommand): no `EffectiveConfig`, no HTTP
//! client, no Tokio work of its own. All logic lives in the shared,
//! zero-`hort-*`-dep `hort-attribution` crate; this module is a thin
//! clap + stdout shim.

use std::process::ExitCode;

/// `license` arguments.
#[derive(clap::Args, Debug)]
pub struct LicenseArgs {
    /// Also print the full text of both LICENSE-MIT and LICENSE-APACHE.
    #[arg(long)]
    pub full: bool,
}

/// Print hort's license information to stdout and exit 0.
pub fn run(args: &LicenseArgs) -> ExitCode {
    print!("{}", hort_attribution::render_license(args.full));
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_prints_spdx_and_succeeds() {
        // `run` is a thin wrapper over `render_license`; assert the
        // rendered content it prints contains the SPDX expression and
        // that the command itself reports success.
        assert!(hort_attribution::render_license(false).contains("MIT OR Apache-2.0"));
        let code = run(&LicenseArgs { full: false });
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[test]
    fn full_flag_inlines_both_license_texts_and_succeeds() {
        let out = hort_attribution::render_license(true);
        assert!(out.contains("Permission is hereby granted"));
        assert!(out.contains("Apache License"));
        let code = run(&LicenseArgs { full: true });
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[test]
    fn license_args_parses_via_cli() {
        use clap::Parser;

        let cli = crate::Cli::try_parse_from(["hort-cli", "license"]).unwrap();
        let Some(crate::Commands::License(args)) = cli.cmd else {
            panic!("expected Commands::License");
        };
        assert!(!args.full);

        let cli = crate::Cli::try_parse_from(["hort-cli", "license", "--full"]).unwrap();
        let Some(crate::Commands::License(args)) = cli.cmd else {
            panic!("expected Commands::License");
        };
        assert!(args.full);
    }
}
