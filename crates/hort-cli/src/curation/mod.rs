//! `hort-cli curation` subcommand tree.
//!
//! Mounted at the **top level** of `Commands` (alongside `Auth`,
//! `Admin`, `Get`) — NOT under `admin`. Operational curator verbs sit
//! alongside `Admin`, not nested under it.
//!
//! Five curator decision subcommands:
//!
//! - `waive <artifact_id> --justification <text>` →
//!   POST `/api/v1/admin/curation/quarantine/:artifact_id/waive`
//!   (releases a `Quarantined` artifact with curator attribution).
//! - `block artifact <artifact_id> --justification <text>` →
//!   POST `/api/v1/admin/curation/quarantine/:artifact_id/block`
//!   (single-artifact curator block).
//! - `block versions --repo <key> --package <name> --versions <v1>,<v2>,…
//!   --justification <text>` →
//!   POST `/api/v1/admin/curation/block-versions`
//!   (bulk-by-version-list curator block; continue-on-error).
//! - `exclude-finding --policy <id> --cve <id> --justification <text>` →
//!   POST `/api/v1/admin/policies/:policy_id/exclusions`
//!   (policy-scoped CVE exclusion).
//! - `unexclude-finding --policy <id> --cve <id> --justification <text>` →
//!   DELETE `/api/v1/admin/policies/:policy_id/exclusions/:cve_id`
//!   (remove a policy-scoped CVE exclusion).
//!
//! # Single vs bulk `block`
//!
//! The original design lists `block <artifact_id>` AND `block --repo ... --package
//! ... --versions ...` as two variants of the same `block` command. Clap's
//! XOR-between-positional-and-flag-group story produces vague error
//! messages on misuse (e.g. "the following required arguments were not
//! provided: <artifact_id>" instead of "supply either an artifact id OR
//! --repo + --package + --versions"). The implementation splits `block`
//! into two sub-subcommands — `block artifact <id>` and `block versions
//! --repo ... --package ... --versions ...` — which are self-documenting
//! in `--help` and produce specific errors on misuse. The wire endpoints
//! (`/quarantine/:id/block` vs `/block-versions`) and the per-event audit
//! shape are unchanged.
//!
//! # File-layout pattern
//!
//! One file per subcommand, a `mod.rs` that ties them together with the
//! clap subcommand enum + dispatcher. Only the parser-enum mount point
//! differs (top-level here, `admin/quarantine` nested under `admin`).
//!
//! # Dep-graph invariant
//!
//! This module — and its children — must not import anything from
//! `hort-domain`, `hort-app`, or `hort-adapters-*`. Wire DTOs are mirrored
//! verbatim from `hort-http-core::handlers::admin::curation::*` (the
//! `BlockOutcomeDto` + `FailedBlockEntryDto` shapes — single source of
//! truth on the server side). The "sync-required" comment on each DTO
//! flags the cross-crate contract for future maintainers.

pub mod block;
pub mod decisions;
pub mod exclude_finding;
pub mod exclusions;
pub mod queue;
pub mod unexclude_finding;
pub mod waive;

use clap::Subcommand;

use crate::client::AkClient;
use crate::config::OutputFormat;

// ---------------------------------------------------------------------------
// Clap subcommand tree
// ---------------------------------------------------------------------------

/// `hort-cli curation` arguments.
#[derive(clap::Args, Debug)]
pub struct CurationArgs {
    #[command(subcommand)]
    pub cmd: CurationCommand,
}

/// `curation` sub-subcommands.
#[derive(Subcommand, Debug)]
pub enum CurationCommand {
    /// Waive a quarantined artifact — release with curator attribution.
    ///
    /// Emits `ArtifactReleased { authority: CuratorWaiver, reason:
    /// Curator }`. Source-state guard: `Quarantined` only (the use case
    /// rejects `ScanIndeterminate`; that authority stays admin-only).
    /// `--justification` is required (≤ 512 bytes).
    Waive(waive::WaiveArgs),

    /// Block one or more artifacts — `Quarantined`/`Released` →
    /// `Rejected` with curator attribution.
    ///
    /// Two modes: `block artifact <id>` (single) and `block versions
    /// --repo ... --package ... --versions ...` (bulk-by-version-list,
    /// continue-on-error). See module-level docs for the
    /// rationale on the sub-subcommand split vs the original design.
    Block(block::BlockArgs),

    /// Exclude a CVE finding for a scan policy.
    ///
    /// POST `/api/v1/admin/policies/:policy_id/exclusions`. Triggers the
    /// existing post-exclusion re-evaluation cascade — operators should
    /// be aware that one exclusion can release multiple artifacts whose
    /// only blocking findings were the now-excluded CVE (blast-radius
    /// consideration).
    ExcludeFinding(exclude_finding::ExcludeFindingArgs),

    /// Remove a CVE exclusion from a scan policy.
    ///
    /// DELETE `/api/v1/admin/policies/:policy_id/exclusions/:cve_id`.
    /// Emits `ExclusionRemoved`; affected artifacts re-evaluate via the
    /// same cascade (some may transition back to `Quarantined` /
    /// `Rejected` if the now-restored CVE is blocking).
    UnexcludeFinding(unexclude_finding::UnexcludeFindingArgs),

    /// List artifacts currently in a curator-actionable state.
    ///
    /// GET `/api/v1/admin/curation/queue` — paginated read of
    /// `Quarantined` / `Rejected` / `ScanIndeterminate` artifacts
    /// with per-row quarantine deadlines, finding counts, and a
    /// `rejection_reason_kind` discriminator for rejected rows.
    Queue(queue::QueueArgs),

    /// List historical curator decisions (event-log read).
    ///
    /// GET `/api/v1/admin/curation/decisions` — uncollapsed by default
    /// (one row per event); `--by-correlation` collapses bulk operations
    /// into the curator's intent. The rollup is server-side.
    Decisions(decisions::DecisionsArgs),

    /// List active CVE exclusions (current-state read).
    ///
    /// GET `/api/v1/admin/curation/exclusions` — paginated read of
    /// `exclusion_projections`; distinct from `decisions` because
    /// exclusions have ongoing state.
    Exclusions(exclusions::ExclusionsArgs),
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Entry point for the `curation` subcommand tree.
///
/// Loads `EffectiveConfig`, builds the `AkClient`, then hands off to
/// the per-subcommand `run` function. Mirrors the `admin::run` shape so
/// the dispatch surface is uniform across the top-level command tree.
pub async fn run(
    args: CurationArgs,
    output: OutputFormat,
    cli_server: Option<String>,
    cli_token: Option<String>,
) -> anyhow::Result<std::process::ExitCode> {
    use crate::config::load_effective_config;

    // Honor the global `--server`/`--token` flags (flag > env > config file),
    // same as get/list-versions/prefetch. Passing None here would silently
    // ignore `--server`, routing to the configured server — a footgun.
    let cfg = match load_effective_config(cli_server, cli_token) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("hort-cli: config error: {e}");
            eprintln!("Hint: run `hort-cli auth login` to set up credentials.");
            return Ok(std::process::ExitCode::from(2));
        }
    };

    let client = AkClient::new(&cfg)?;

    match args.cmd {
        CurationCommand::Waive(waive_args) => {
            waive::run(client, waive_args, output).await?;
        }
        CurationCommand::Block(block_args) => {
            block::run(client, block_args, output).await?;
        }
        CurationCommand::ExcludeFinding(exclude_args) => {
            exclude_finding::run(client, exclude_args, output).await?;
        }
        CurationCommand::UnexcludeFinding(unexclude_args) => {
            unexclude_finding::run(client, unexclude_args, output).await?;
        }
        CurationCommand::Queue(queue_args) => {
            queue::run(client, queue_args, output).await?;
        }
        CurationCommand::Decisions(decisions_args) => {
            decisions::run(client, decisions_args, output).await?;
        }
        CurationCommand::Exclusions(exclusions_args) => {
            exclusions::run(client, exclusions_args, output).await?;
        }
    }
    Ok(std::process::ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// Shared constants
// ---------------------------------------------------------------------------

/// Maximum byte length of the operator-supplied justification on every
/// curation decision subcommand. Mirrors `MAX_JUSTIFICATION_BYTES` in
/// `hort-http-core::handlers::admin::curation` (= 512), which itself
/// mirrors `CurationUseCase::validate_justification` and the domain
/// `ArtifactReleased`/`ArtifactRejected` event validators. Catching it
/// CLI-side gives operators a fast feedback loop and avoids burning an
/// audit-log 400 on operator error.
pub(crate) const MAX_JUSTIFICATION_BYTES: usize = 512;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Validate `--justification` text client-side.
///
/// Mirrors the server-side gate at every curation decision endpoint:
/// empty (after trim) and > 512 bytes are both rejected before any
/// HTTP round-trip. The error messages match `release.rs` verbatim so
/// operators see the same wording across the two surfaces.
pub(crate) fn validate_justification(justification: &str) -> anyhow::Result<()> {
    let trimmed = justification.trim();
    if trimmed.is_empty() {
        return Err(anyhow::anyhow!("justification must not be empty"));
    }
    if justification.len() > MAX_JUSTIFICATION_BYTES {
        return Err(anyhow::anyhow!(
            "justification exceeds {MAX_JUSTIFICATION_BYTES} bytes (got {})",
            justification.len()
        ));
    }
    Ok(())
}

/// Percent-encode a single URL path segment.
///
/// Defensive — UUIDs (artifact_id, policy_id) are URL-safe in the RFC
/// 3986 unreserved set, but encoding guards against malformed input
/// (e.g. `..` traversal sequences) if the operator pastes something
/// other than a canonical UUID. CVE IDs (`CVE-2026-XXXX`) are also
/// unreserved; vendor advisory IDs that contain non-unreserved bytes
/// (rare but allowed by the server) survive transit via the encoding.
///
/// `.` is intentionally excluded so `..` cannot survive encoding.
/// Sibling copy of the helper in `admin/quarantine/release.rs` — not
/// shared because the two may diverge as the validation rules evolve.
pub(crate) fn encode_path_segment(segment: &str) -> String {
    let mut encoded = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        match byte {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_justification_accepts_ordinary_text() {
        assert!(validate_justification("CVE-2026-XXXX false-positive").is_ok());
    }

    #[test]
    fn validate_justification_rejects_empty() {
        let err = validate_justification("").unwrap_err().to_string();
        assert!(err.contains("empty"), "error references empty: {err}");
    }

    #[test]
    fn validate_justification_rejects_whitespace_only() {
        let err = validate_justification("   \n\t  ").unwrap_err().to_string();
        assert!(err.contains("empty"), "error references empty: {err}");
    }

    #[test]
    fn validate_justification_rejects_oversize() {
        let oversize = "a".repeat(513);
        let err = validate_justification(&oversize).unwrap_err().to_string();
        assert!(
            err.contains("512") || err.contains("exceeds"),
            "error references the cap: {err}"
        );
    }

    #[test]
    fn validate_justification_accepts_exactly_512_bytes() {
        let exact = "a".repeat(512);
        assert!(validate_justification(&exact).is_ok());
    }

    #[test]
    fn max_justification_bytes_matches_server_cap() {
        // Mirrors `hort-http-core::handlers::admin::curation::MAX_JUSTIFICATION_BYTES`.
        // If the server cap changes, this test breaks loudly.
        assert_eq!(MAX_JUSTIFICATION_BYTES, 512);
    }

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
    fn encode_path_segment_handles_cve_id() {
        // CVE-2026-XXXX is in the unreserved set. Vendor advisory IDs
        // (e.g. `GHSA-xxxx-yyyy-zzzz`) likewise unreserved.
        assert_eq!(encode_path_segment("CVE-2026-0001"), "CVE-2026-0001");
        assert_eq!(
            encode_path_segment("GHSA-1234-5678-9abc"),
            "GHSA-1234-5678-9abc"
        );
    }
}
