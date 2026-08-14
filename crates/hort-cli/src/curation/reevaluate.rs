//! `hort-cli curation reevaluate` — POST `/api/v1/admin/curation/quarantine/:artifact_id/reevaluate`.
//!
//! Wire contract: `POST /api/v1/admin/curation/quarantine/:artifact_id/reevaluate`
//! (`hort-http-core::handlers::admin::curation::reevaluate`).
//! Source-state guard is `Rejected` only (waive's single-source-state
//! discipline mirrored on the opposite terminal state).
//!
//! No request body — the server recomputes the verdict from stored
//! findings under the currently active policy; there is no operator
//! override or justification to supply (that's `waive` / `block`'s
//! surface).
//!
//! The endpoint returns `200 OK` with the outcome envelope on success
//! (including an unchanged `still_rejected` verdict — idempotent, not an
//! error); non-2xx surfaces via the standard error envelope.

use std::io::Write;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::client::AkClient;
use crate::config::OutputFormat;
use crate::output::{format_json, format_table_rows};

use super::encode_path_segment;

// ---------------------------------------------------------------------------
// Wire DTO (response body)
// ---------------------------------------------------------------------------

/// Response envelope for
/// `POST /admin/curation/quarantine/:artifact_id/reevaluate`.
///
/// **Sync-required**: mirrors `ReevaluateOutcomeDto` in
/// `hort-http-core::handlers::admin::curation::reevaluate`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReevaluateOutcomeDto {
    pub outcome: String,
    pub previous_status: String,
    pub new_status: String,
}

// ---------------------------------------------------------------------------
// Clap args
// ---------------------------------------------------------------------------

/// Arguments for `hort-cli curation reevaluate`.
#[derive(clap::Args, Debug)]
pub struct ReevaluateArgs {
    /// Artifact UUID to re-evaluate (a `Rejected` artifact's verdict is
    /// recomputed from its stored findings under the active policy).
    pub artifact_id: String,
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Dispatch path. Writes to stdout.
pub async fn run(client: AkClient, args: ReevaluateArgs, output: OutputFormat) -> Result<()> {
    run_with_output(client, args, output, &mut std::io::stdout()).await
}

/// Testable variant — writes to an arbitrary `Write` impl.
pub async fn run_with_output(
    client: AkClient,
    args: ReevaluateArgs,
    output: OutputFormat,
    out: &mut impl Write,
) -> Result<()> {
    let encoded_id = encode_path_segment(&args.artifact_id);
    let path = format!("/api/v1/admin/curation/quarantine/{encoded_id}/reevaluate");

    // No request body — the server recomputes from stored evidence.
    let outcome: ReevaluateOutcomeDto = client.post(&path, &serde_json::json!({})).await?;

    render_outcome(&args.artifact_id, &outcome, output, out)
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn render_outcome(
    artifact_id: &str,
    outcome: &ReevaluateOutcomeDto,
    output: OutputFormat,
    out: &mut impl Write,
) -> Result<()> {
    match output {
        OutputFormat::Json => {
            writeln!(out, "{}", format_json(outcome))?;
        }
        OutputFormat::Table => {
            let headers = &["ARTIFACT_ID", "OUTCOME", "PREVIOUS_STATUS", "NEW_STATUS"];
            let rows = vec![vec![
                artifact_id.to_string(),
                outcome.outcome.clone(),
                outcome.previous_status.clone(),
                outcome.new_status.clone(),
            ]];
            write!(out, "{}", format_table_rows(headers, &rows))?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn still_rejected_outcome() -> ReevaluateOutcomeDto {
        ReevaluateOutcomeDto {
            outcome: "still_rejected".into(),
            previous_status: "rejected".into(),
            new_status: "rejected".into(),
        }
    }

    #[test]
    fn render_outcome_table_includes_artifact_id_and_outcome() {
        let outcome = still_rejected_outcome();
        let mut buf = Vec::new();
        render_outcome(
            "11111111-1111-1111-1111-111111111111",
            &outcome,
            OutputFormat::Table,
            &mut buf,
        )
        .expect("renders");
        let text = String::from_utf8(buf).expect("utf8");
        assert!(text.contains("ARTIFACT_ID"));
        assert!(text.contains("11111111-1111-1111-1111-111111111111"));
        assert!(text.contains("still_rejected"));
    }

    #[test]
    fn render_outcome_json_emits_envelope() {
        let outcome = ReevaluateOutcomeDto {
            outcome: "reset_to_released".into(),
            previous_status: "rejected".into(),
            new_status: "released".into(),
        };
        let mut buf = Vec::new();
        render_outcome("id", &outcome, OutputFormat::Json, &mut buf).expect("renders");
        let text = String::from_utf8(buf).expect("utf8");
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("valid json");
        assert_eq!(parsed["outcome"], "reset_to_released");
        assert_eq!(parsed["previous_status"], "rejected");
        assert_eq!(parsed["new_status"], "released");
    }
}
