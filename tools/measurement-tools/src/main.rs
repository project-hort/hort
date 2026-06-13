//! Measurement tool — calibrates per-format metadata-size caps.
//!
//! Not a production binary. Depends on the format + domain crates so the
//! handler code path (name normalisation, `metadata_expected_max_bytes`) is
//! the real one.
//!
//! The ingest-side extraction logic is reimplemented minimally here because
//! the ingest handlers read from raw upload bodies (multipart / JSON /
//! tarball), not from upstream registry JSON.
//!
//! Output: a CSV with per-package sizes plus a summary printed to stdout.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

mod cargo;
mod npm;
mod percentile;
mod pypi;
mod sample_lists;

/// Measurement tool — fetches representative packages from public registries,
/// computes the metadata blob our ingest handlers would store, and reports
/// per-format size distributions (min / p50 / p95 / p99 / max).
#[derive(Parser)]
#[command(name = "measure-metadata-sizes", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,

    /// User-Agent to send with every HTTP request. Public registries ask
    /// for identifiable crawlers.
    #[arg(
        long,
        default_value = "hort-measurement/0.1 (+https://github.com/project-hort/hort)"
    )]
    user_agent: String,

    /// Directory to write the per-package CSV to.
    #[arg(long, default_value = ".")]
    out_dir: PathBuf,

    /// Per-request polite delay, milliseconds. Applied after every upstream
    /// call.
    #[arg(long, default_value_t = 50)]
    delay_ms: u64,

    /// Request timeout, seconds.
    #[arg(long, default_value_t = 20)]
    timeout_s: u64,

    /// Maximum number of packages to fetch per format. The backlog asks
    /// for ~500; drop for faster iteration.
    #[arg(long, default_value_t = 500)]
    sample_size: usize,
}

#[derive(Subcommand)]
enum Cmd {
    /// Measure PyPI `pkg_info` metadata sizes (info block from the JSON API).
    Pypi,
    /// Measure Cargo sparse-index entry sizes (one JSON object per version).
    Cargo,
    /// Measure npm per-version packument entry sizes (versions[v] sub-objects).
    Npm,
    /// Run all three formats and emit one CSV each.
    All,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // Shared reqwest client — one connection pool across all fetches.
    let client = reqwest::Client::builder()
        .user_agent(&cli.user_agent)
        .timeout(Duration::from_secs(cli.timeout_s))
        .build()
        .context("building reqwest client")?;

    std::fs::create_dir_all(&cli.out_dir)
        .with_context(|| format!("creating out_dir {}", cli.out_dir.display()))?;

    let delay = Duration::from_millis(cli.delay_ms);

    match cli.cmd {
        Cmd::Pypi => {
            pypi::run(&client, delay, cli.sample_size, &cli.out_dir).await?;
        }
        Cmd::Cargo => {
            cargo::run(&client, delay, cli.sample_size, &cli.out_dir).await?;
        }
        Cmd::Npm => {
            npm::run(&client, delay, cli.sample_size, &cli.out_dir).await?;
        }
        Cmd::All => {
            pypi::run(&client, delay, cli.sample_size, &cli.out_dir).await?;
            cargo::run(&client, delay, cli.sample_size, &cli.out_dir).await?;
            npm::run(&client, delay, cli.sample_size, &cli.out_dir).await?;
        }
    }

    Ok(())
}
