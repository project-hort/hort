//! `hort-cli admin task get` — GET `/api/v1/admin/tasks/<id>`.
//!
//! # Behaviour
//!
//! 1. Validate the given `<task_job_id>` is a plausible UUID string
//!    (no strict parsing — the server enforces UUID format; we just
//!    forward the string and surface any 4xx/5xx as an error).
//! 2. GET `/api/v1/admin/tasks/<task_job_id>`.
//! 3. `--output table` (default): render a two-column field/value table
//!    showing the full row.
//! 4. `--output json`: pretty-print the full response JSON.

use std::io::Write;

use anyhow::Result;

use crate::admin::TaskRow;
use crate::client::AkClient;
use crate::config::OutputFormat;
use crate::output::{format_json, format_table_rows};

// ---------------------------------------------------------------------------
// Clap args
// ---------------------------------------------------------------------------

/// Arguments for `hort-cli admin task get`.
#[derive(clap::Args, Debug)]
pub struct TaskGetArgs {
    /// The UUID of the task job to retrieve.
    pub task_job_id: String,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Entry point for the CLI dispatch path. Writes output to `stdout`.
pub async fn run(client: AkClient, args: TaskGetArgs, output: OutputFormat) -> Result<()> {
    run_with_output(client, args, output, &mut std::io::stdout()).await
}

/// Testable variant that accepts an arbitrary `Write` impl for output.
pub async fn run_with_output(
    client: AkClient,
    args: TaskGetArgs,
    output: OutputFormat,
    out: &mut impl Write,
) -> Result<()> {
    let path = format!("/api/v1/admin/tasks/{}", args.task_job_id);
    let row: TaskRow = client.get(&path).await?;

    match output {
        OutputFormat::Json => {
            writeln!(out, "{}", format_json(&row))?;
        }
        OutputFormat::Table => {
            let table = render_row_table(&row);
            write!(out, "{table}")?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Render a `TaskRow` as a two-column field/value table.
fn render_row_table(row: &TaskRow) -> String {
    let mut data: Vec<Vec<String>> = vec![
        vec!["id".to_string(), row.id.clone()],
        vec!["kind".to_string(), row.kind.clone()],
        vec!["status".to_string(), row.status.clone()],
        vec!["priority".to_string(), row.priority.to_string()],
        vec!["trigger_source".to_string(), row.trigger_source.clone()],
        vec!["attempts".to_string(), row.attempts.to_string()],
        vec!["created_at".to_string(), row.created_at.clone()],
        vec!["updated_at".to_string(), row.updated_at.clone()],
    ];

    if let Some(ref actor) = row.actor_id {
        data.push(vec!["actor_id".to_string(), actor.clone()]);
    }
    if let Some(ref completed) = row.completed_at {
        data.push(vec!["completed_at".to_string(), completed.clone()]);
    }
    if let Some(ref error) = row.last_error {
        data.push(vec!["last_error".to_string(), error.clone()]);
    }
    if let Some(ref summary) = row.result_summary {
        data.push(vec!["result_summary".to_string(), summary.clone()]);
    }

    format_table_rows(&["FIELD", "VALUE"], &data)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_row() -> TaskRow {
        TaskRow {
            id: "aaa-bbb-ccc".to_string(),
            kind: "noop".to_string(),
            status: "completed".to_string(),
            params: None,
            actor_id: None,
            priority: 0,
            trigger_source: "api".to_string(),
            attempts: 1,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:01:00Z".to_string(),
            completed_at: Some("2026-01-01T00:01:00Z".to_string()),
            last_error: None,
            result_summary: Some("ok".to_string()),
        }
    }

    #[test]
    fn render_row_table_includes_all_core_fields() {
        let row = sample_row();
        let table = render_row_table(&row);
        assert!(table.contains("id"), "must contain 'id' field");
        assert!(table.contains("aaa-bbb-ccc"), "must contain id value");
        assert!(table.contains("kind"), "must contain 'kind' field");
        assert!(table.contains("noop"), "must contain kind value");
        assert!(table.contains("status"), "must contain 'status' field");
        assert!(table.contains("completed"), "must contain status value");
    }

    #[test]
    fn render_row_table_includes_optional_fields_when_set() {
        let row = sample_row();
        let table = render_row_table(&row);
        assert!(
            table.contains("completed_at"),
            "must contain completed_at when set"
        );
        assert!(
            table.contains("result_summary"),
            "must contain result_summary when set"
        );
        assert!(table.contains("ok"), "must contain result_summary value");
    }

    #[test]
    fn render_row_table_omits_none_fields() {
        let row = sample_row();
        let table = render_row_table(&row);
        // actor_id and last_error are None in sample_row — must not appear.
        assert!(
            !table.contains("last_error"),
            "must omit last_error when None"
        );
        assert!(!table.contains("actor_id"), "must omit actor_id when None");
    }
}
