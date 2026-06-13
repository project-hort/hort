//! `hort-cli admin quarantine release` — POST `/api/v1/admin/quarantine/<artifact_id>/release`.
//!
//! Wire contract: `POST /api/v1/admin/quarantine/<artifact_id>/release`
//! (`hort-http-core::handlers::admin`). The endpoint
//! returns 204 No Content on success; this subcommand uses
//! [`AkClient::post_no_response`] so an empty-body 2xx is not mistaken
//! for a JSON parse failure.
//!
//! # Client-side validation
//!
//! `--justification` is validated BEFORE any HTTP call:
//! - empty (after trim) → `Err` ("justification must not be empty");
//! - > 512 bytes → `Err` ("justification exceeds 512 bytes (got N)").
//!
//! Both mirrors of the server-side validation at the boundary in
//! `hort-http-core::handlers::admin` (the 512-byte cap is the domain-layer
//! invariant from `ArtifactReleased::validate`). Catching it client-side
//! gives operators a fast feedback loop and avoids burning an audit-log
//! 400 on operator error.

use std::io::Write;

use anyhow::{anyhow, Result};

use crate::client::AkClient;
use crate::config::OutputFormat;
use crate::output::format_json;

/// Maximum byte length of the operator-supplied justification. Mirrors
/// `MAX_RELEASE_JUSTIFICATION_BYTES` in `hort-http-core::handlers::admin`,
/// which itself mirrors the domain-layer cap on
/// `ArtifactReleased::validate`. Single source of truth lives in the
/// domain; this constant must match.
const MAX_JUSTIFICATION_BYTES: usize = 512;

// ---------------------------------------------------------------------------
// Wire DTO (request body)
// ---------------------------------------------------------------------------

/// Request body for `POST /admin/quarantine/:artifact_id/release`.
///
/// **Sync-required**: mirrors `AdminReleaseRequest` in
/// `hort-http-core::handlers::admin`. The JSON field name is the contract.
#[derive(Debug, serde::Serialize)]
struct ReleaseRequestBody<'a> {
    justification: &'a str,
}

// ---------------------------------------------------------------------------
// Clap args
// ---------------------------------------------------------------------------

/// Arguments for `hort-cli admin quarantine release`.
///
/// `--justification` is REQUIRED. No interactive prompt — the surface
/// is designed for scripted operator workflows.
#[derive(clap::Args, Debug)]
pub struct ReleaseArgs {
    /// Artifact UUID to release.
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
pub async fn run(client: AkClient, args: ReleaseArgs, output: OutputFormat) -> Result<()> {
    run_with_output(client, args, output, &mut std::io::stdout()).await
}

/// Testable variant — writes to an arbitrary `Write` impl so integration
/// tests can capture output into a `Vec<u8>` buffer.
pub async fn run_with_output(
    client: AkClient,
    args: ReleaseArgs,
    output: OutputFormat,
    out: &mut impl Write,
) -> Result<()> {
    // Step 1 — client-side validation. Fail fast BEFORE the HTTP call so
    // operator errors don't burn an audit-log 400 (and don't surprise a
    // tail of `hort_authz_decisions_total` with a denied admin write).
    let trimmed = args.justification.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("justification must not be empty"));
    }
    if args.justification.len() > MAX_JUSTIFICATION_BYTES {
        return Err(anyhow!(
            "justification exceeds {MAX_JUSTIFICATION_BYTES} bytes (got {})",
            args.justification.len()
        ));
    }

    // Step 2 — percent-encode the artifact id path segment. UUIDs are
    // URL-safe, but encoding guards against malformed input (e.g. a
    // `..` traversal sequence) if the operator pastes something other
    // than a UUID. The helper is intentionally a sibling copy of the
    // one in `rescan.rs` per the comment there — the two helpers may
    // diverge as artifact-id-vs-task-kind validation evolves.
    let encoded_id = encode_path_segment(&args.artifact_id);
    let path = format!("/api/v1/admin/quarantine/{encoded_id}/release");

    // Step 3 — POST. The server returns 204 No Content; `post_no_response`
    // succeeds without attempting to deserialise the empty body.
    let body = ReleaseRequestBody {
        justification: &args.justification,
    };
    client.post_no_response(&path, &body).await?;

    // Step 4 — output. The server returned 204 with no body, so for
    // `--output json` we synthesise a minimal envelope. Operators
    // scripting against `jq '.released_artifact_id'` get a parseable
    // result; the table mode prints a human-readable line.
    match output {
        OutputFormat::Json => {
            // Build via serde_json so an artifact_id containing `"` or `\`
            // cannot produce malformed JSON for downstream `jq` consumers.
            let body = serde_json::json!({ "released_artifact_id": &args.artifact_id });
            writeln!(out, "{}", format_json(&body))?;
        }
        OutputFormat::Table => {
            writeln!(out, "released artifact {}", args.artifact_id)?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Percent-encode a single URL path segment.
///
/// Defensive — UUIDs are URL-safe in the RFC 3986 unreserved set, but
/// encoding guards against malformed input (e.g. `..` traversal
/// sequences) if `artifact_id` is anything other than a canonical
/// UUID. Sibling copy of the helper in `rescan.rs`; not a shared util
/// because the two may diverge.
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
        let uuid = "11111111-2222-3333-4444-555555555555";
        assert_eq!(encode_path_segment(uuid), uuid);
    }

    #[test]
    fn encode_path_segment_blocks_traversal() {
        assert_eq!(encode_path_segment(".."), "%2E%2E");
        assert_eq!(encode_path_segment("foo/../bar"), "foo%2F%2E%2E%2Fbar");
    }

    #[test]
    fn max_justification_bytes_matches_server_cap() {
        // The server cap lives at
        // `hort-http-core::handlers::admin::MAX_RELEASE_JUSTIFICATION_BYTES`
        // and ultimately enforces the domain invariant on
        // `ArtifactReleased::validate`. If this constant ever diverges
        // from 512 we want the test to break loudly.
        assert_eq!(MAX_JUSTIFICATION_BYTES, 512);
    }
}
