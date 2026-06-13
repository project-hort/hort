//! `hort-cli curation waive` — POST `/api/v1/admin/curation/quarantine/:artifact_id/waive`.
//!
//! Wire contract: `POST /api/v1/admin/curation/quarantine/:artifact_id/waive`
//! (`hort-http-core::handlers::admin::curation::waive`).
//! Source-state guard is `Quarantined` only (curator does NOT clear
//! `ScanIndeterminate` artifacts; admin authority only).
//!
//! The endpoint returns `200 OK` with no body on success; on
//! continue-on-error / domain-state errors it returns 4xx with the
//! standard error envelope.
//!
//! # Client-side validation
//!
//! `--justification` is validated BEFORE any HTTP call via the shared
//! [`super::validate_justification`] helper — operator gets fast
//! feedback; the audit log is spared a denied-write.

use std::io::Write;

use anyhow::Result;

use crate::client::AkClient;
use crate::config::OutputFormat;
use crate::output::format_json;

use super::{encode_path_segment, validate_justification};

// ---------------------------------------------------------------------------
// Wire DTO (request body)
// ---------------------------------------------------------------------------

/// Request body for `POST /admin/curation/quarantine/:artifact_id/waive`.
///
/// **Sync-required**: mirrors `WaiveRequestDto` in
/// `hort-http-core::handlers::admin::curation::waive`.
#[derive(Debug, serde::Serialize)]
struct WaiveRequestBody<'a> {
    justification: &'a str,
}

// ---------------------------------------------------------------------------
// Clap args
// ---------------------------------------------------------------------------

/// Arguments for `hort-cli curation waive`.
///
/// `--justification` is REQUIRED. The text rides the emitted
/// `ArtifactReleased { authority: CuratorWaiver }` event as the
/// audit-anchor `reason` field.
#[derive(clap::Args, Debug)]
pub struct WaiveArgs {
    /// Artifact UUID to waive (release with curator attribution).
    pub artifact_id: String,

    /// Operator justification recorded on the audit event. Must be
    /// non-empty and ≤ 512 bytes (validated client-side).
    #[arg(long, required = true)]
    pub justification: String,
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Dispatch path. Writes to stdout.
pub async fn run(client: AkClient, args: WaiveArgs, output: OutputFormat) -> Result<()> {
    run_with_output(client, args, output, &mut std::io::stdout()).await
}

/// Testable variant — writes to an arbitrary `Write` impl.
pub async fn run_with_output(
    client: AkClient,
    args: WaiveArgs,
    output: OutputFormat,
    out: &mut impl Write,
) -> Result<()> {
    // Step 1 — CLI-side validation. Fail fast BEFORE the HTTP call.
    validate_justification(&args.justification)?;

    // Step 2 — percent-encode the artifact id path segment.
    let encoded_id = encode_path_segment(&args.artifact_id);
    let path = format!("/api/v1/admin/curation/quarantine/{encoded_id}/waive");

    // Step 3 — POST. The server returns 200 OK with no body on success.
    // Use `post_no_response` so an empty body is not treated as a JSON
    // parse failure.
    let body = WaiveRequestBody {
        justification: &args.justification,
    };
    client.post_no_response(&path, &body).await?;

    // Step 4 — output. The server returned 200 with no body; synthesise
    // a minimal envelope under `--output json` so scripted callers get
    // a parseable result.
    match output {
        OutputFormat::Json => {
            let body = serde_json::json!({ "waived_artifact_id": &args.artifact_id });
            writeln!(out, "{}", format_json(&body))?;
        }
        OutputFormat::Table => {
            writeln!(out, "waived artifact {}", args.artifact_id)?;
        }
    }

    Ok(())
}
