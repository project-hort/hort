//! `hort-cli admin task list` — GET `/api/v1/admin/tasks`.
//!
//! # Behaviour
//!
//! 1. Collect optional query filters: `--kind`, `--status`, `--limit`,
//!    `--cursor`.
//! 2. Build the query string and GET `/api/v1/admin/tasks?...`.
//! 3. `--output table` (default): render an aligned column table with
//!    columns `ID  KIND  STATUS  TRIGGER_SOURCE  CREATED_AT`.
//! 4. `--output json`: pretty-print the full response JSON.
//! 5. When `next_cursor` is present in the response, print a paging hint
//!    to stderr.

use std::io::Write;

use anyhow::Result;

use crate::admin::{TaskListResponse, TaskRow};
use crate::client::AkClient;
use crate::config::OutputFormat;
use crate::output::{format_json, format_table_rows};

// ---------------------------------------------------------------------------
// Clap args
// ---------------------------------------------------------------------------

/// Arguments for `hort-cli admin task list`.
#[derive(clap::Args, Debug)]
pub struct TaskListArgs {
    /// Filter by task kind (e.g. `noop`, `scan`).
    #[arg(long)]
    pub kind: Option<String>,

    /// Filter by lifecycle status: `pending`, `running`, `completed`, `failed`.
    #[arg(long)]
    pub status: Option<String>,

    /// Maximum rows per page (server clamps to its own maximum).
    #[arg(long)]
    pub limit: Option<u32>,

    /// Opaque pagination cursor from the previous page's `next_cursor` field.
    #[arg(long)]
    pub cursor: Option<String>,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Entry point for the CLI dispatch path. Writes stdout to `stdout` and
/// paging hints to `stderr`.
pub async fn run(client: AkClient, args: TaskListArgs, output: OutputFormat) -> Result<()> {
    run_with_output(
        client,
        args,
        output,
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    )
    .await
}

/// Testable variant that accepts arbitrary `Write` impls for stdout and stderr.
pub async fn run_with_output(
    client: AkClient,
    args: TaskListArgs,
    output: OutputFormat,
    out: &mut impl Write,
    err_out: &mut impl Write,
) -> Result<()> {
    // Build query string from provided filters.
    let mut parts: Vec<String> = Vec::new();
    if let Some(ref k) = args.kind {
        parts.push(format!("kind={}", urlencoded(k)));
    }
    if let Some(ref s) = args.status {
        parts.push(format!("status={}", urlencoded(s)));
    }
    if let Some(l) = args.limit {
        parts.push(format!("limit={l}"));
    }
    if let Some(ref c) = args.cursor {
        parts.push(format!("cursor={}", urlencoded(c)));
    }

    let path = if parts.is_empty() {
        "/api/v1/admin/tasks".to_string()
    } else {
        format!("/api/v1/admin/tasks?{}", parts.join("&"))
    };

    let page: TaskListResponse = client.get(&path).await?;

    match output {
        OutputFormat::Json => {
            writeln!(out, "{}", format_json(&page.tasks))?;
        }
        OutputFormat::Table => {
            let table = render_table(&page.tasks);
            write!(out, "{table}")?;
        }
    }

    // Paging hint to stderr when more results are available.
    if let Some(ref cursor) = page.next_cursor {
        writeln!(
            err_out,
            "(more results — pass --cursor {cursor} for the next page)"
        )?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Render a list of `TaskRow`s as an aligned column table.
fn render_table(tasks: &[TaskRow]) -> String {
    let headers = &["ID", "KIND", "STATUS", "TRIGGER_SOURCE", "CREATED_AT"];
    let rows: Vec<Vec<String>> = tasks
        .iter()
        .map(|t| {
            vec![
                t.id.clone(),
                t.kind.clone(),
                t.status.clone(),
                t.trigger_source.clone(),
                t.created_at.clone(),
            ]
        })
        .collect();
    format_table_rows(headers, &rows)
}

/// Percent-encode a query-string value (space → `%20`, not `+`).
///
/// Only encodes characters that are special in query strings. Valid
/// filter values (UUIDs, status literals, kind names) pass through
/// unchanged.
fn urlencoded(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            // Unreserved: pass through (RFC 3986 §2.3 + `-`, `.`).
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b => {
                out.push('%');
                out.push(
                    char::from_digit((b >> 4) as u32, 16)
                        .unwrap_or('0')
                        .to_ascii_uppercase(),
                );
                out.push(
                    char::from_digit((b & 0x0f) as u32, 16)
                        .unwrap_or('0')
                        .to_ascii_uppercase(),
                );
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_row(id: &str, kind: &str, status: &str) -> TaskRow {
        TaskRow {
            id: id.to_string(),
            kind: kind.to_string(),
            status: status.to_string(),
            params: None,
            actor_id: None,
            priority: 0,
            trigger_source: "manual".to_string(),
            attempts: 0,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:01:00Z".to_string(),
            completed_at: None,
            last_error: None,
            result_summary: None,
        }
    }

    #[test]
    fn render_table_includes_headers_and_rows() {
        let rows = vec![
            make_row("aaa", "noop", "completed"),
            make_row("bbb", "scan", "running"),
        ];
        let table = render_table(&rows);
        assert!(table.contains("ID"), "must have ID column header");
        assert!(table.contains("KIND"), "must have KIND column header");
        assert!(table.contains("STATUS"), "must have STATUS column header");
        assert!(table.contains("noop"), "must contain noop kind");
        assert!(table.contains("scan"), "must contain scan kind");
        assert!(table.contains("completed"), "must contain completed status");
    }

    #[test]
    fn render_table_empty_rows_renders_header_only() {
        let table = render_table(&[]);
        let lines: Vec<&str> = table.lines().collect();
        assert_eq!(lines.len(), 1, "only header line when no rows");
        assert!(lines[0].starts_with("ID"), "header must start with ID");
    }

    #[test]
    fn urlencoded_passes_through_valid_chars() {
        assert_eq!(urlencoded("noop"), "noop");
        assert_eq!(urlencoded("staging-sweep"), "staging-sweep");
        assert_eq!(
            urlencoded("11111111-1111-1111-1111-111111111111"),
            "11111111-1111-1111-1111-111111111111"
        );
    }

    #[test]
    fn urlencoded_encodes_spaces_and_specials() {
        assert_eq!(urlencoded("foo bar"), "foo%20bar");
        assert_eq!(urlencoded("a=b"), "a%3Db");
    }
}
