//! `hort-cli admin rescan` — POST `/api/v1/artifacts/<id>/rescan`.
//!
//! # Why a top-level `admin rescan` and not `admin task invoke rescan`?
//!
//! The server endpoint is per-artifact (`/api/v1/artifacts/:id/rescan`),
//! not under the per-kind admin-task framework at
//! `/api/v1/admin/tasks/`. The wire shape, authz check, and
//! 404-anti-enumeration semantics are artifact-specific. A separate
//! subcommand keeps the CLI surface aligned with the HTTP surface.
//!
//! # Behaviour
//!
//! 1. Percent-encode the artifact id path segment (defensive — UUIDs
//!    are URL-safe, but the encoder also blocks `..` traversal).
//! 2. POST an empty JSON body `{}` to `/api/v1/artifacts/<id>/rescan`.
//! 3. Print the returned `task_job_id` (table mode) or the full JSON
//!    response (`--output json`).
//!
//! # Wire DTO sync
//!
//! `RescanResponse` mirrors `hort_http_admin_security::dto::RescanResponse`
//! verbatim. Defined locally to keep `hort-cli` adapter-free (no dep on
//! workspace-internal HTTP/domain crates).

use std::io::Write;

use anyhow::Result;

use crate::client::AkClient;
use crate::config::OutputFormat;
use crate::output::format_json;

// ---------------------------------------------------------------------------
// Wire DTO (kept in sync with hort-http-admin-security::dto::RescanResponse)
// ---------------------------------------------------------------------------

/// Response from `POST /api/v1/artifacts/:id/rescan`.
///
/// **Sync-required**: mirrors `RescanResponse` in
/// `hort-http-admin-security::dto`. The wire JSON form is the contract.
/// `task_job_id` is the **new `jobs.id`** (not the artifact id) — the
/// caller can poll `/api/v1/admin/tasks/<task_job_id>` for status.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct RescanResponse {
    /// Newly-inserted `jobs.id` for the manual rescan request. Stored as
    /// `String` for display — server emits a UUID, but the CLI never
    /// parses it.
    pub task_job_id: String,
}

// ---------------------------------------------------------------------------
// Clap args
// ---------------------------------------------------------------------------

/// Arguments for `hort-cli admin rescan`.
#[derive(clap::Args, Debug)]
pub struct RescanArgs {
    /// Artifact UUID to rescan.
    pub artifact_id: String,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Entry point for the CLI dispatch path. Writes output to `stdout`.
pub async fn run(client: AkClient, args: RescanArgs, output: OutputFormat) -> Result<()> {
    run_with_output(client, args, output, &mut std::io::stdout()).await
}

/// Testable variant that writes output to an arbitrary `Write` impl.
pub async fn run_with_output(
    client: AkClient,
    args: RescanArgs,
    output: OutputFormat,
    out: &mut impl Write,
) -> Result<()> {
    // Step 1 — percent-encode the artifact id segment.
    let encoded_id = encode_path_segment(&args.artifact_id);
    let path = format!("/api/v1/artifacts/{encoded_id}/rescan");

    // Step 2 — POST with an empty JSON body. The server endpoint takes
    // no body; `artifact_id` is the path parameter. Sending `{}` matches
    // the convention used by `admin task invoke` when no params are
    // supplied.
    let body = serde_json::json!({});
    let resp: RescanResponse = client.post(&path, &body).await?;

    // Step 3 — output.
    match output {
        OutputFormat::Json => {
            writeln!(out, "{}", format_json(&resp))?;
        }
        OutputFormat::Table => {
            writeln!(out, "task_job_id: {}", resp.task_job_id)?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Percent-encode a single URL path segment.
///
/// Defensive — UUIDs are URL-safe in the unreserved set, but encoding
/// guards against malformed input (e.g. `..` traversal sequences) if the
/// `artifact_id` arg is anything other than a canonical UUID. Mirrors
/// the helper in `task_invoke.rs`; not a shared util because the two
/// helpers may diverge (task kinds and artifact ids have different
/// validation rules).
fn encode_path_segment(segment: &str) -> String {
    let mut encoded = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        match byte {
            // Unreserved safe set: letters, digits, hyphen, underscore, tilde.
            // `.` is intentionally excluded so `..` cannot survive encoding.
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'~' => {
                encoded.push(byte as char);
            }
            b => {
                encoded.push('%');
                encoded.push(
                    char::from_digit((b >> 4) as u32, 16)
                        .unwrap_or('0')
                        .to_ascii_uppercase(),
                );
                encoded.push(
                    char::from_digit((b & 0x0f) as u32, 16)
                        .unwrap_or('0')
                        .to_ascii_uppercase(),
                );
            }
        }
    }
    encoded
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_path_segment_passes_through_uuid() {
        // Canonical UUID — every char is in the unreserved set, no encoding.
        let uuid = "11111111-2222-3333-4444-555555555555";
        assert_eq!(encode_path_segment(uuid), uuid);
    }

    #[test]
    fn encode_path_segment_blocks_traversal() {
        assert_eq!(encode_path_segment(".."), "%2E%2E");
        assert_eq!(encode_path_segment("foo/../bar"), "foo%2F%2E%2E%2Fbar");
    }
}
