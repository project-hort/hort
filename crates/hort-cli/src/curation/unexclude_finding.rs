//! `hort-cli curation unexclude-finding` — DELETE `/api/v1/admin/policies/:policy_id/exclusions/:cve_id`.
//!
//! Wire contract: `DELETE /api/v1/admin/policies/:policy_id/exclusions/:cve_id`
//! (`hort-http-core::handlers::admin::policies::exclusions`).
//! Removes a CVE-scoped exclusion from a scan policy; the server-side
//! handler resolves the CVE → exclusion_id via the projection and
//! emits `ExclusionRemoved` with curator attribution.
//!
//! # Cascade behaviour
//!
//! Removing an exclusion re-arms the now-restored CVE for the policy's
//! scope. The post-exclusion re-evaluation cascade may transition
//! artifacts that were previously released-by-exclusion back to
//! `Quarantined`/`Rejected` if the now-restored CVE is blocking.
//! Mirrors the `exclude-finding` blast-radius warning — the
//! audit-event chain (one `ExclusionRemoved` + N follow-up
//! state-change events) makes the cascade reconstructable.
//!
//! # Wire shape
//!
//! Per the server-side DELETE handler, the body is **optional** at the
//! HTTP layer (the handler accepts `Option<Json<RemoveExclusionRequestDto>>`)
//! but `reason` is REQUIRED — an empty `reason` is rejected with 400.
//! The CLI always sends the body so the curator-supplied justification
//! is recorded.

use std::io::Write;

use anyhow::Result;

use crate::client::AkClient;
use crate::config::OutputFormat;
use crate::output::format_json;

use super::{encode_path_segment, validate_justification};

// ---------------------------------------------------------------------------
// Wire DTO (request body)
// ---------------------------------------------------------------------------

/// Request body for `DELETE /admin/policies/:policy_id/exclusions/:cve_id`.
///
/// **Sync-required**: mirrors `RemoveExclusionRequestDto` in
/// `hort-http-core::handlers::admin::policies::exclusions`. The `reason`
/// field maps onto the operator-supplied `--justification`.
#[derive(Debug, serde::Serialize)]
struct RemoveExclusionRequestBody<'a> {
    reason: &'a str,
}

// ---------------------------------------------------------------------------
// Clap args
// ---------------------------------------------------------------------------

/// Arguments for `hort-cli curation unexclude-finding`.
#[derive(clap::Args, Debug)]
pub struct UnexcludeFindingArgs {
    /// Scan policy UUID carrying the exclusion to remove.
    #[arg(long, required = true)]
    pub policy: String,

    /// CVE identifier of the exclusion to remove (e.g. `CVE-2026-0001`).
    /// A miss surfaces as 404 (no exclusion with that CVE on this
    /// policy).
    #[arg(long, required = true)]
    pub cve: String,

    /// Operator justification recorded on the emitted
    /// `ExclusionRemoved` event. Must be non-empty and ≤ 512 bytes
    /// (validated client-side).
    #[arg(long, required = true)]
    pub justification: String,
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Dispatch path. Writes to stdout.
pub async fn run(client: AkClient, args: UnexcludeFindingArgs, output: OutputFormat) -> Result<()> {
    run_with_output(client, args, output, &mut std::io::stdout()).await
}

/// Testable variant — writes to an arbitrary `Write` impl.
pub async fn run_with_output(
    client: AkClient,
    args: UnexcludeFindingArgs,
    output: OutputFormat,
    out: &mut impl Write,
) -> Result<()> {
    validate_justification(&args.justification)?;
    if args.cve.trim().is_empty() {
        return Err(anyhow::anyhow!("--cve must not be empty"));
    }

    let encoded_policy = encode_path_segment(&args.policy);
    let encoded_cve = encode_path_segment(&args.cve);
    let path = format!("/api/v1/admin/policies/{encoded_policy}/exclusions/{encoded_cve}");

    let body = RemoveExclusionRequestBody {
        reason: &args.justification,
    };
    // The server returns 204 No Content on success.
    client.delete_no_response(&path, &body).await?;

    match output {
        OutputFormat::Json => {
            let body = serde_json::json!({
                "removed_exclusion_cve": &args.cve,
                "policy_id": &args.policy,
            });
            writeln!(out, "{}", format_json(&body))?;
        }
        OutputFormat::Table => {
            writeln!(
                out,
                "removed exclusion {cve} from policy {policy}",
                cve = args.cve,
                policy = args.policy,
            )?;
        }
    }

    Ok(())
}
