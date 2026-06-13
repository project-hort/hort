//! `hort-cli curation exclude-finding` — POST `/api/v1/admin/policies/:policy_id/exclusions`.
//!
//! Wire contract: `POST /api/v1/admin/policies/:policy_id/exclusions`
//! (`hort-http-core::handlers::admin::policies::exclusions`).
//! Adds a CVE-scoped exclusion to a scan policy with curator
//! attribution; the server-side use case mints the `exclusion_id` and
//! returns it in a `201 Created` envelope.
//!
//! # Blast-radius warning
//!
//! Adding a CVE exclusion triggers the post-exclusion re-evaluation
//! cascade — artifacts whose only blocking findings were the
//! now-excluded CVE may transition `Rejected` → `Quarantined`/`Released`.
//! This is by design; the audit chain (one
//! `ExclusionAdded` + N `ArtifactReleased { authority: PolicyReEvaluation }`)
//! makes the cascade reconstructable after the fact. The
//! `--justification` text rides the `ExclusionAdded.reason` field as
//! the load-bearing audit anchor.
//!
//! # Scope discriminator
//!
//! The server-side request DTO carries a tagged-union `scope` field
//! (`{ "kind": "global" }` or `{ "kind": "repository", "repository_id":
//! "<uuid>" }`). The CLI v1 surface targets the global-scope case
//! (operator policies are typically global); a future revision can add
//! `--repo` to mint a repository-scoped exclusion. The global-scope
//! path ships the curator-most-common case; repository-scoped exclusion
//! is deferred.

use std::io::Write;

use anyhow::Result;
use uuid::Uuid;

use crate::client::AkClient;
use crate::config::OutputFormat;
use crate::output::format_json;

use super::{encode_path_segment, validate_justification};

// ---------------------------------------------------------------------------
// Wire DTOs
// ---------------------------------------------------------------------------

/// Tagged-union scope discriminator on the wire.
///
/// **Sync-required**: mirrors `ScopeDto` in
/// `hort-http-core::handlers::admin::policies::exclusions`. v1 emits the
/// `Global` arm only; the `Repository { repository_id }` arm is the
/// server's other variant.
#[derive(Debug, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ScopeBody {
    Global,
}

/// Request body for `POST /admin/policies/:policy_id/exclusions`.
///
/// **Sync-required**: mirrors `AddExclusionRequestDto` in
/// `hort-http-core::handlers::admin::policies::exclusions`. The `reason`
/// field maps onto the operator-supplied `--justification`.
#[derive(Debug, serde::Serialize)]
struct AddExclusionRequestBody<'a> {
    cve_id: &'a str,
    scope: ScopeBody,
    reason: &'a str,
}

/// Response body for `POST /admin/policies/:policy_id/exclusions`.
///
/// **Sync-required**: mirrors `AddExclusionResponseDto`. The
/// server-minted `exclusion_id` is returned so the caller doesn't need
/// a follow-up GET to learn the value.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct AddExclusionResponseDto {
    pub exclusion_id: Uuid,
}

// ---------------------------------------------------------------------------
// Clap args
// ---------------------------------------------------------------------------

/// Arguments for `hort-cli curation exclude-finding`.
#[derive(clap::Args, Debug)]
pub struct ExcludeFindingArgs {
    /// Scan policy UUID to attach the exclusion to.
    #[arg(long, required = true)]
    pub policy: String,

    /// CVE identifier (e.g. `CVE-2026-0001`, or a vendor advisory id
    /// like `GHSA-1234-5678-9abc`). Server caps the length at 64 bytes.
    #[arg(long, required = true)]
    pub cve: String,

    /// Operator justification recorded on the emitted `ExclusionAdded`
    /// event. Must be non-empty and ≤ 512 bytes (validated client-side).
    #[arg(long, required = true)]
    pub justification: String,
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Dispatch path. Writes to stdout.
pub async fn run(client: AkClient, args: ExcludeFindingArgs, output: OutputFormat) -> Result<()> {
    run_with_output(client, args, output, &mut std::io::stdout()).await
}

/// Testable variant — writes to an arbitrary `Write` impl.
pub async fn run_with_output(
    client: AkClient,
    args: ExcludeFindingArgs,
    output: OutputFormat,
    out: &mut impl Write,
) -> Result<()> {
    // Step 1 — CLI-side validation. Fail fast BEFORE the HTTP call.
    validate_justification(&args.justification)?;
    if args.cve.trim().is_empty() {
        return Err(anyhow::anyhow!("--cve must not be empty"));
    }

    // Step 2 — percent-encode the policy id path segment.
    let encoded_policy = encode_path_segment(&args.policy);
    let path = format!("/api/v1/admin/policies/{encoded_policy}/exclusions");

    let body = AddExclusionRequestBody {
        cve_id: &args.cve,
        scope: ScopeBody::Global,
        reason: &args.justification,
    };
    let resp: AddExclusionResponseDto = client.post(&path, &body).await?;

    match output {
        OutputFormat::Json => {
            writeln!(out, "{}", format_json(&resp))?;
        }
        OutputFormat::Table => {
            writeln!(
                out,
                "excluded {cve} on policy {policy} (exclusion_id {id})",
                cve = args.cve,
                policy = args.policy,
                id = resp.exclusion_id,
            )?;
        }
    }

    Ok(())
}
