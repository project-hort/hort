//! `hort-cli admin workers` — list scanner workers and their liveness.
//!
//! Wire contract: GET `/api/v1/admin/workers`
//! (`hort-http-core::handlers::admin`). The CLI mirrors the response DTO
//! verbatim and renders a table or pretty-printed JSON.
//!
//! # Dep-graph invariant
//!
//! Like the rest of `hort-cli`, this module must not import from
//! `hort-domain`, `hort-app`, or `hort-adapters-*`. The DTOs below are
//! defined verbatim from the wire contract; the wire format (field names,
//! JSON serialisation) is the contract.

use std::io::Write;

use anyhow::Result;
use chrono::{DateTime, Utc};
use clap::Subcommand;

use crate::client::AkClient;
use crate::config::OutputFormat;
use crate::output::{format_json, format_table_rows};

// ---------------------------------------------------------------------------
// Wire DTOs (mirror hort-http-core::handlers::admin::ScannerWorker{Dto,ResponseDto})
// ---------------------------------------------------------------------------

/// One worker row.
///
/// **Sync-required**: mirrors `ScannerWorkerDto` in
/// `hort-http-core::handlers::admin`. Field names form the wire contract;
/// any rename on the server side must land here in the same change.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct ScannerWorkerRowDto {
    pub worker_id: String,
    pub backends: Vec<String>,
    pub registered_at: DateTime<Utc>,
    pub last_heartbeat: DateTime<Utc>,
    pub live: bool,
    pub last_seen_secs_ago: i64,
}

/// Response envelope from `GET /admin/workers`.
///
/// **Sync-required**: mirrors `ScannerWorkersResponseDto`.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct ScannerWorkerListResponseDto {
    pub workers: Vec<ScannerWorkerRowDto>,
}

// ---------------------------------------------------------------------------
// Clap args
// ---------------------------------------------------------------------------

/// `hort-cli admin workers` arguments.
#[derive(clap::Args, Debug)]
pub struct WorkersArgs {
    #[command(subcommand)]
    pub cmd: WorkersCommand,
}

/// `admin workers` sub-subcommands.
#[derive(Subcommand, Debug)]
pub enum WorkersCommand {
    /// List registered scanner workers and their liveness.
    ///
    /// Reads `GET /api/v1/admin/workers`. Shows every worker that has
    /// registered in the `scanner_registry` — including stale/dead ones
    /// (`LIVE=NO`) so a worker that stopped heartbeating stays visible
    /// rather than silently vanishing.
    List(WorkersListArgs),
}

/// `admin workers list` arguments. No flags — output format is the global
/// `--output` selector.
#[derive(clap::Args, Debug)]
pub struct WorkersListArgs {}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Per-subcommand dispatcher (mirrors `quarantine::run`).
pub async fn run(client: AkClient, args: WorkersArgs, output: OutputFormat) -> Result<()> {
    match args.cmd {
        WorkersCommand::List(list_args) => run_list(client, list_args, output).await,
    }
}

/// Dispatch path. Writes to stdout.
pub async fn run_list(client: AkClient, args: WorkersListArgs, output: OutputFormat) -> Result<()> {
    run_list_with_output(client, args, output, &mut std::io::stdout()).await
}

/// Testable variant — writes to an arbitrary `Write` impl so integration
/// tests can capture output into a `Vec<u8>` buffer.
pub async fn run_list_with_output(
    client: AkClient,
    _args: WorkersListArgs,
    output: OutputFormat,
    out: &mut impl Write,
) -> Result<()> {
    let resp: ScannerWorkerListResponseDto = client.get("/api/v1/admin/workers").await?;

    match output {
        OutputFormat::Json => {
            writeln!(out, "{}", format_json(&resp))?;
        }
        OutputFormat::Table => {
            if resp.workers.is_empty() {
                writeln!(out, "No workers registered")?;
            } else {
                let table = render_table(&resp.workers, Utc::now());
                write!(out, "{table}")?;
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Table rendering
// ---------------------------------------------------------------------------

/// Render the worker listing as an aligned table.
///
/// Columns: `WORKER_ID  BACKENDS  LIVE  LAST_SEEN  REGISTERED`.
/// `LAST_SEEN` is the humanised `last_seen_secs_ago`; `REGISTERED` is the
/// humanised age of `registered_at` against `now`.
fn render_table(rows: &[ScannerWorkerRowDto], now: DateTime<Utc>) -> String {
    let headers = &["WORKER_ID", "BACKENDS", "LIVE", "LAST_SEEN", "REGISTERED"];

    let data: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            vec![
                r.worker_id.clone(),
                r.backends.join(","),
                if r.live { "yes" } else { "NO" }.to_string(),
                humanise_ago(r.last_seen_secs_ago),
                humanise_ago(now.signed_duration_since(r.registered_at).num_seconds()),
            ]
        })
        .collect();

    format_table_rows(headers, &data)
}

/// Humanise a non-negative seconds count as `<n>s ago` / `<m>m ago` /
/// `<h>h ago` / `<d>d ago`. Negative inputs (clock skew) clamp to `0s ago`.
/// Implemented inline so the CLI keeps its dep set tight (no `humantime`).
fn humanise_ago(secs: i64) -> String {
    let s = secs.max(0);
    if s < 60 {
        format!("{s}s ago")
    } else if s < 3600 {
        format!("{}m ago", s / 60)
    } else if s < 86_400 {
        format!("{}h ago", s / 3600)
    } else {
        format!("{}d ago", s / 86_400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(worker_id: &str, live: bool, last_seen_secs_ago: i64) -> ScannerWorkerRowDto {
        let now = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        ScannerWorkerRowDto {
            worker_id: worker_id.into(),
            backends: vec!["trivy".into(), "osv".into()],
            registered_at: now,
            last_heartbeat: now,
            live,
            last_seen_secs_ago,
        }
    }

    #[test]
    fn humanise_ago_buckets() {
        assert_eq!(humanise_ago(-5), "0s ago", "negative clamps to 0");
        assert_eq!(humanise_ago(0), "0s ago");
        assert_eq!(humanise_ago(45), "45s ago");
        assert_eq!(humanise_ago(120), "2m ago");
        assert_eq!(humanise_ago(7200), "2h ago");
        assert_eq!(humanise_ago(172_800), "2d ago");
    }

    #[test]
    fn render_table_shows_live_and_stale_rows() {
        let now = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let rows = vec![row("w-fresh", true, 10), row("w-stale", false, 3600)];
        let table = render_table(&rows, now);

        assert!(table.contains("WORKER_ID"), "header present");
        assert!(table.contains("w-fresh") && table.contains("w-stale"));
        assert!(table.contains("trivy,osv"), "backends joined with comma");
        // The stale worker is rendered with LIVE=NO, not filtered out.
        assert!(table.contains("yes"), "live worker shows yes");
        assert!(table.contains("NO"), "stale worker shows NO, stays visible");
    }

    #[test]
    fn render_table_empty_is_noop_via_caller() {
        // `render_table` itself is only called on non-empty input (the
        // empty case prints "No workers registered" in the caller), but
        // pin that it produces just the header row for a single entry.
        let now = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let table = render_table(&[row("solo", true, 1)], now);
        assert!(table.contains("solo"));
    }
}
