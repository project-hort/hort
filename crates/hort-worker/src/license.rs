//! `hort-worker license` — print hort's SPDX license identifier and,
//! with `--full`, the complete text of both license files.
//!
//! Synchronous, no config, no DB, no Tokio runtime — dispatched
//! directly from `main`'s already-synchronous match (see
//! `main::main`). All logic lives in the shared, zero-`hort-*`-dep
//! `hort-attribution` crate; this module is a thin clap + stdout shim.

use clap::Args;

/// Arguments to `hort-worker license`.
#[derive(Debug, Args)]
pub struct LicenseArgs {
    /// Also print the full text of both LICENSE-MIT and LICENSE-APACHE.
    #[arg(long)]
    pub full: bool,
}

/// Print hort's license information to stdout.
pub fn run(args: &LicenseArgs) -> anyhow::Result<()> {
    print!("{}", hort_attribution::render_license(args.full));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_prints_spdx_and_succeeds() {
        assert!(hort_attribution::render_license(false).contains("MIT OR Apache-2.0"));
        assert!(run(&LicenseArgs { full: false }).is_ok());
    }

    #[test]
    fn full_flag_inlines_both_license_texts_and_succeeds() {
        let out = hort_attribution::render_license(true);
        assert!(out.contains("Permission is hereby granted"));
        assert!(out.contains("Apache License"));
        assert!(run(&LicenseArgs { full: true }).is_ok());
    }
}
