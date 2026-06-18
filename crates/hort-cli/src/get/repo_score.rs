//! `hort-cli get repo-score` subcommand implementation.
//!
//! Two endpoint shapes:
//!
//! - With `--name <repo>`: `GET /api/v1/repositories/<repo>/security-score`
//!   (single score)
//! - Without `--name`: `GET /api/v1/security-score?limit=...&cursor=...`
//!   (paginated list)
//!
//! Both output formats (table / JSON) are supported. A pagination hint is
//! printed to stderr when `next_cursor` is present in the list response.

use chrono::{DateTime, Utc};
use clap::Args;
use serde::{Deserialize, Serialize};

use crate::client::AkClient;
use crate::config::OutputFormat;
use crate::output::{format_json, format_table_rows};

// ---------------------------------------------------------------------------
// Wire-shape DTOs (sync-required with hort-http-admin-security::dto)
// ---------------------------------------------------------------------------

/// JSON envelope for `GET /api/v1/repositories/:name/security-score`.
///
/// **Sync-required with hort-http-admin-security::dto**. Field names and
/// serialisation format are part of the public API contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityScoreDto {
    /// Repository name (key), NOT the UUID. Resolved by the handler
    /// from `repository_id` so the wire response is operator-friendly.
    pub repository: String,
    pub quarantined: u32,
    pub rejected: u32,
    pub released: u32,
    pub severity_histogram: SeverityHistogramDto,
    /// Most-recent scan time across the repository. `None` when no
    /// scan has completed for any artifact in this repository yet.
    /// Serialises as JSON `null`.
    pub last_scan_at: Option<DateTime<Utc>>,
}

/// Severity histogram envelope for [`SecurityScoreDto::severity_histogram`].
///
/// **Sync-required with hort-http-admin-security::dto**.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SeverityHistogramDto {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
}

/// JSON envelope for `GET /api/v1/security-score` (paginated list).
///
/// **Sync-required with hort-http-admin-security::dto**.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityScoreListDto {
    pub scores: Vec<SecurityScoreDto>,
    pub next_cursor: Option<String>,
}

// ---------------------------------------------------------------------------
// Clap arguments
// ---------------------------------------------------------------------------

/// `hort-cli get repo-score` arguments.
#[derive(Args, Debug)]
pub struct RepoScoreArgs {
    /// Show a single repository (omit for paginated list)
    #[arg(long)]
    pub name: Option<String>,
    /// Page size (list mode only)
    #[arg(long)]
    pub limit: Option<u32>,
    /// Continuation cursor (list mode only)
    #[arg(long)]
    pub cursor: Option<String>,
}

// ---------------------------------------------------------------------------
// Command implementation
// ---------------------------------------------------------------------------

/// Entry point from the clap dispatcher.
pub async fn run(
    client: AkClient,
    args: RepoScoreArgs,
    output: OutputFormat,
) -> anyhow::Result<()> {
    run_impl(&client, args.name, args.limit, args.cursor, output).await
}

/// Core logic: fetch and render a security score (single or list).
///
/// Returns `Ok(())` on success, `Err` on HTTP errors or format issues.
async fn run_impl(
    client: &AkClient,
    name: Option<String>,
    limit: Option<u32>,
    cursor: Option<String>,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match name {
        Some(repo_name) => {
            // Single repo: GET /api/v1/repositories/:name/security-score
            let score = fetch_single(client, &repo_name).await?;
            render_single(&score, output);
            Ok(())
        }
        None => {
            // List: GET /api/v1/security-score?limit=...&cursor=...
            let list = fetch_list(client, limit, cursor).await?;
            render_list(&list, output);
            Ok(())
        }
    }
}

/// Test helper: fetch and return output as String.
pub async fn run_to_string(
    client: &AkClient,
    name: Option<String>,
    limit: Option<u32>,
    cursor: Option<String>,
    output: OutputFormat,
) -> anyhow::Result<String> {
    match name {
        Some(repo_name) => {
            let score = fetch_single(client, &repo_name).await?;
            Ok(render_single_to_string(&score, output))
        }
        None => {
            let list = fetch_list(client, limit, cursor).await?;
            Ok(render_list_to_string(&list, output))
        }
    }
}

/// Test helper: fetch and return output as (stdout, stderr) tuple.
pub async fn run_to_string_with_stderr(
    client: &AkClient,
    name: Option<String>,
    limit: Option<u32>,
    cursor: Option<String>,
    output: OutputFormat,
) -> anyhow::Result<(String, String)> {
    match name {
        Some(repo_name) => {
            let score = fetch_single(client, &repo_name).await?;
            Ok((render_single_to_string(&score, output), String::new()))
        }
        None => {
            let list = fetch_list(client, limit, cursor).await?;
            Ok(render_list_to_string_with_stderr(&list, output))
        }
    }
}

// ---------------------------------------------------------------------------
// Fetch functions
// ---------------------------------------------------------------------------

async fn fetch_single(client: &AkClient, repo_name: &str) -> anyhow::Result<SecurityScoreDto> {
    let path = format!("/api/v1/repositories/{repo_name}/security-score");
    client.get(&path).await
}

async fn fetch_list(
    client: &AkClient,
    limit: Option<u32>,
    cursor: Option<String>,
) -> anyhow::Result<SecurityScoreListDto> {
    let mut path = "/api/v1/security-score".to_string();

    // Build query string.
    let mut query_parts = Vec::new();
    if let Some(l) = limit {
        query_parts.push(format!("limit={l}"));
    }
    if let Some(c) = cursor {
        query_parts.push(format!("cursor={c}"));
    }

    if !query_parts.is_empty() {
        path.push('?');
        path.push_str(&query_parts.join("&"));
    }

    client.get(&path).await
}

// ---------------------------------------------------------------------------
// Render functions
// ---------------------------------------------------------------------------

fn render_single(score: &SecurityScoreDto, output: OutputFormat) {
    let out = render_single_to_string(score, output);
    println!("{out}");
}

fn render_single_to_string(score: &SecurityScoreDto, output: OutputFormat) -> String {
    match output {
        OutputFormat::Json => format_json(score),
        OutputFormat::Table => {
            let headers = &[
                "REPOSITORY",
                "QUARANTINED",
                "REJECTED",
                "RELEASED",
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW",
                "LAST_SCAN_AT",
            ];

            let last_scan = score
                .last_scan_at
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_else(|| "Never".to_string());

            let rows = vec![vec![
                score.repository.clone(),
                score.quarantined.to_string(),
                score.rejected.to_string(),
                score.released.to_string(),
                score.severity_histogram.critical.to_string(),
                score.severity_histogram.high.to_string(),
                score.severity_histogram.medium.to_string(),
                score.severity_histogram.low.to_string(),
                last_scan,
            ]];

            format_table_rows(headers, &rows)
        }
    }
}

fn render_list(list: &SecurityScoreListDto, output: OutputFormat) {
    let (out, err) = render_list_to_string_with_stderr(list, output);
    println!("{out}");
    if !err.is_empty() {
        eprintln!("{err}");
    }
}

#[allow(dead_code)]
fn render_list_to_string(list: &SecurityScoreListDto, output: OutputFormat) -> String {
    let (out, _err) = render_list_to_string_with_stderr(list, output);
    out
}

fn render_list_to_string_with_stderr(
    list: &SecurityScoreListDto,
    output: OutputFormat,
) -> (String, String) {
    match output {
        OutputFormat::Json => (format_json(list), String::new()),
        OutputFormat::Table => {
            let headers = &[
                "REPOSITORY",
                "QUARANTINED",
                "REJECTED",
                "RELEASED",
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW",
            ];

            let rows: Vec<Vec<String>> = list
                .scores
                .iter()
                .map(|score| {
                    vec![
                        score.repository.clone(),
                        score.quarantined.to_string(),
                        score.rejected.to_string(),
                        score.released.to_string(),
                        score.severity_histogram.critical.to_string(),
                        score.severity_histogram.high.to_string(),
                        score.severity_histogram.medium.to_string(),
                        score.severity_histogram.low.to_string(),
                    ]
                })
                .collect();

            let table = format_table_rows(headers, &rows);

            let pagination_hint = if let Some(next_cursor) = &list.next_cursor {
                format!("(more results — pass --cursor {next_cursor} for the next page)\n")
            } else {
                String::new()
            };

            (table, pagination_hint)
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_single_table_includes_all_columns() {
        let score = SecurityScoreDto {
            repository: "test-repo".to_string(),
            quarantined: 1,
            rejected: 2,
            released: 100,
            severity_histogram: SeverityHistogramDto {
                critical: 0,
                high: 1,
                medium: 2,
                low: 5,
            },
            last_scan_at: None,
        };

        let out = render_single_to_string(&score, OutputFormat::Table);
        assert!(out.contains("REPOSITORY"));
        assert!(out.contains("test-repo"));
        assert!(out.contains("QUARANTINED"));
        assert!(out.contains("RELEASED"));
        assert!(out.contains("CRITICAL"));
    }

    #[test]
    fn render_list_with_cursor_adds_pagination_hint() {
        let list = SecurityScoreListDto {
            scores: vec![SecurityScoreDto {
                repository: "repo1".to_string(),
                quarantined: 0,
                rejected: 0,
                released: 50,
                severity_histogram: SeverityHistogramDto {
                    critical: 0,
                    high: 0,
                    medium: 0,
                    low: 0,
                },
                last_scan_at: None,
            }],
            next_cursor: Some("abc123".to_string()),
        };

        let (_stdout, stderr) = render_list_to_string_with_stderr(&list, OutputFormat::Table);
        assert!(stderr.contains("--cursor"));
        assert!(stderr.contains("abc123"));
    }

    #[test]
    fn render_list_without_cursor_has_no_hint() {
        let list = SecurityScoreListDto {
            scores: vec![],
            next_cursor: None,
        };

        let (_stdout, stderr) = render_list_to_string_with_stderr(&list, OutputFormat::Table);
        assert!(stderr.is_empty());
    }
}
