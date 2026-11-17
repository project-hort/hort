//! `hort-cli admin task get` — GET `/api/v1/admin/tasks/<id>`.
//!
//! # Behaviour
//!
//! 1. Validate the given `<task_job_id>` is a plausible UUID string
//!    (no strict parsing — the server enforces UUID format; we just
//!    forward the string and surface any 4xx/5xx as an error).
//! 2. GET `/api/v1/admin/tasks/<task_job_id>`.
//! 3. `--output table` (default): render a two-column field/value table
//!    showing the row. Every field is shown whole except the two that
//!    have no bound on their size — `result_summary` and `last_error` —
//!    which are cut to a readable prefix that names how to read the rest
//!    (see `bounded_field_cell`).
//! 4. `--output json`: pretty-print the full response JSON. This is the
//!    lossless form, and the one the table points at: it is never cut,
//!    at any size.

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

/// How much of a field with no bound on its size the table shows before
/// it points at the lossless form instead.
///
/// Two fields of a job row are unbounded: `result_summary` is whatever
/// document the task handler wrote (a `retention-evaluate` dry run's
/// carries its full `groups` and `sample` arrays, which run to six
/// figures of bytes), and `last_error` is whatever string the failure
/// produced. Rendered whole, either is a single-line table cell nothing
/// can read, however well the renderer pads around it.
///
/// 400 bytes is the identifying part of such a document — a summary's
/// opening keys, which say which run this was, its counters, and whether
/// a body follows — while staying a few wrapped lines on an 80-column
/// terminal rather than a screenful. Nothing is lost by the cut: the
/// whole value is one flag away and the cell names the flag.
const UNBOUNDED_FIELD_PREVIEW_BYTES: usize = 400;

/// Render a value with no bound on its size as a bounded cell, carrying
/// the way to read the rest when it had to cut.
///
/// A value within the bound comes back untouched, so a cell that looks
/// like a whole value is one — the marker never appears in ordinary
/// output. When it does appear it states both sizes, so an operator can
/// see how much is missing rather than guess.
fn bounded_field_cell(value: &str, job_id: &str) -> String {
    if value.len() <= UNBOUNDED_FIELD_PREVIEW_BYTES {
        return value.to_string();
    }
    // Cut on a char boundary — a cell is text, and half a code point is
    // not. `floor_char_boundary` never exceeds the bound.
    let shown = &value[..value.floor_char_boundary(UNBOUNDED_FIELD_PREVIEW_BYTES)];
    format!(
        "{shown}… [TRUNCATED: {} of {} bytes shown — read the whole value with: \
         hort-cli admin task get {job_id} --output json]",
        shown.len(),
        value.len(),
    )
}

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
        data.push(vec![
            "last_error".to_string(),
            bounded_field_cell(error, &row.id),
        ]);
    }
    if let Some(ref summary) = row.result_summary {
        // `result_summary` is a structured JSON value; the cell carries its
        // compact JSON form, bounded — see `bounded_field_cell`.
        data.push(vec![
            "result_summary".to_string(),
            bounded_field_cell(&summary.to_string(), &row.id),
        ]);
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
            result_summary: Some(serde_json::json!({ "ok": true })),
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

    /// Build a dry-run-shaped summary with `sample_rows` sample entries —
    /// the unbounded part of a `retention-evaluate` preview.
    fn oversize_summary(sample_rows: usize) -> serde_json::Value {
        let sample: Vec<serde_json::Value> = (0..sample_rows)
            .map(|i| serde_json::json!({ "artifact_id": format!("artifact-{i}"), "rows": i }))
            .collect();
        serde_json::json!({ "mode": "dry_run", "preview": { "sample": sample } })
    }

    /// A `retention-evaluate` dry run's summary is a document, not a
    /// field: the cell carries a readable prefix and the command that
    /// prints the rest, plus both sizes so the operator knows how much is
    /// missing.
    #[test]
    fn an_oversize_result_summary_becomes_a_bounded_cell_naming_the_lossless_form() {
        let mut row = sample_row();
        let summary = oversize_summary(4_000);
        let whole = summary.to_string();
        assert!(
            whole.len() > 100_000,
            "the fixture must be the size the defect was reported at, got {}",
            whole.len()
        );
        row.result_summary = Some(summary);

        let table = render_row_table(&row);

        assert!(
            table.contains(&whole[..UNBOUNDED_FIELD_PREVIEW_BYTES / 2]),
            "the prefix shown is the real head of the document:\n{table}"
        );
        assert!(
            !table.contains(&whole[whole.len() - 64..]),
            "the tail is not in the table — it was genuinely cut:\n{table}"
        );
        assert!(
            table.contains("TRUNCATED"),
            "the cut is unmissable:\n{table}"
        );
        assert!(
            table.contains(&format!("{} bytes", whole.len())),
            "the cell states the whole size, so the operator can see what is \
             missing:\n{table}"
        );
        assert!(
            table.contains("hort-cli admin task get aaa-bbb-ccc --output json"),
            "the cell names the command that prints the whole value, for this \
             job:\n{table}"
        );
        // The property the bound exists for: the table is output someone
        // can read, not a transcription of the document.
        assert!(
            table.len() < whole.len() / 10,
            "the table stays an order of magnitude below the document, got {} for {}",
            table.len(),
            whole.len()
        );
    }

    /// The property stated without reference to the chosen bound: past
    /// it, the table stops growing with the document. Doubling the
    /// summary moves the rendered table by no more than the digits the
    /// size figure gained.
    #[test]
    fn the_table_size_stops_tracking_the_summary_size() {
        let render = |sample_rows: usize| -> usize {
            let mut row = sample_row();
            row.result_summary = Some(oversize_summary(sample_rows));
            render_row_table(&row).len()
        };
        let small = render(4_000);
        let doubled = render(8_000);
        assert!(
            doubled.abs_diff(small) <= 8,
            "a document twice the size renders a table of the same size \
             (only the byte figure grows): {small} vs {doubled}"
        );
    }

    /// The counter-assertion: truncation must not reach ordinary output.
    /// A summary a cell can hold is rendered exactly as before, marker
    /// and pointer absent.
    #[test]
    fn a_small_result_summary_is_rendered_unchanged() {
        let table = render_row_table(&sample_row());
        assert!(
            table.contains(r#"{"ok":true}"#),
            "the whole compact value is in the cell:\n{table}"
        );
        assert!(
            !table.contains("TRUNCATED"),
            "no marker on a value that fit:\n{table}"
        );
        assert!(
            !table.contains("--output json"),
            "no pointer on a value that fit:\n{table}"
        );
    }

    /// `last_error` is the other field with no bound: a failure can carry
    /// an arbitrarily long message, and it is cut the same way.
    #[test]
    fn an_oversize_last_error_becomes_a_bounded_cell_too() {
        let mut row = sample_row();
        let error = "destructive task refused at execution: ".to_string() + &"why ".repeat(20_000);
        row.last_error = Some(error.clone());

        let table = render_row_table(&row);

        assert!(
            table.contains("destructive task refused at execution"),
            "the head of the message — the part that says what happened — \
             survives:\n{table}"
        );
        assert!(table.contains("TRUNCATED"), "the cut is marked:\n{table}");
        assert!(
            table.contains("--output json"),
            "the cell names the lossless form:\n{table}"
        );
        assert!(
            table.len() < error.len() / 10,
            "the table stays an order of magnitude below the message, got {}",
            table.len()
        );
    }

    /// A cell is text: the cut lands on a char boundary, never inside a
    /// code point. Slicing one in half would panic, so this pins it
    /// rather than inspecting it.
    #[test]
    fn the_cut_never_splits_a_multibyte_character() {
        // 3 bytes per char, so the bound itself is mid-character.
        let value = "€".repeat(1_000);
        assert_ne!(
            UNBOUNDED_FIELD_PREVIEW_BYTES % 3,
            0,
            "the fixture only tests anything while the bound lands mid-char"
        );
        let cell = bounded_field_cell(&value, "job-1");
        let shown: String = cell.chars().take_while(|c| *c == '€').collect();
        assert!(
            shown.len() <= UNBOUNDED_FIELD_PREVIEW_BYTES,
            "the prefix never exceeds the bound, got {}",
            shown.len()
        );
        assert!(
            value.starts_with(&shown) && !shown.is_empty(),
            "the prefix is a prefix of the value: {shown:?}"
        );
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
