//! `hort-server license` — print hort's SPDX license identifier and,
//! with `--full`, the complete text of both license files.
//!
//! Synchronous and DSN-free: no `Config::from_env`, no Tokio runtime —
//! mirrors `validate-config`'s DB-free shape, except this command reads
//! no env at all. The rendered text is compiled in via `hort-attribution`
//! (`include_str!` of the repository-root license files at build time).

use std::process::ExitCode;

use clap::Args;

/// Arguments to `hort-server license`.
#[derive(Debug, Args)]
pub struct LicenseArgs {
    /// Also print the full text of both LICENSE-MIT and LICENSE-APACHE.
    #[arg(long)]
    pub full: bool,
}

/// Print hort's license information to stdout and exit 0. A closed stdout
/// pipe (`| head`) exits cleanly rather than panicking — see
/// `hort_attribution::write_stdout_or_exit`.
pub fn run(args: &LicenseArgs) -> ExitCode {
    run_to(&mut std::io::stdout(), args)
}

/// Generic-sink form of [`run`]: same rendering and exit behaviour against
/// any [`std::io::Write`], so tests can assert on the written bytes without
/// printing the embedded document to the real stdout.
fn run_to<W: std::io::Write>(w: &mut W, args: &LicenseArgs) -> ExitCode {
    hort_attribution::write_to_or_exit(w, &hort_attribution::render_license(args.full))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_prints_spdx_and_succeeds() {
        let mut buf: Vec<u8> = Vec::new();
        let code = run_to(&mut buf, &LicenseArgs { full: false });
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("MIT OR Apache-2.0"));
    }

    #[test]
    fn full_flag_inlines_both_license_texts_and_succeeds() {
        let mut buf: Vec<u8> = Vec::new();
        let code = run_to(&mut buf, &LicenseArgs { full: true });
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("Permission is hereby granted"));
        assert!(out.contains("Apache License"));
    }

    #[test]
    fn license_args_parses_with_and_without_full() {
        use clap::Parser;

        #[derive(Debug, Parser)]
        struct TestCli {
            #[command(subcommand)]
            command: super::super::Command,
        }

        let cli = TestCli::try_parse_from(["hort-server", "license"]).unwrap();
        let super::super::Command::License(args) = cli.command else {
            panic!("expected License");
        };
        assert!(!args.full);

        let cli = TestCli::try_parse_from(["hort-server", "license", "--full"]).unwrap();
        let super::super::Command::License(args) = cli.command else {
            panic!("expected License");
        };
        assert!(args.full);
    }
}
