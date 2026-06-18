//! `hort-cli curation block` — POST to curation block endpoints.
//!
//! Two sub-subcommands:
//!
//! - `block artifact <artifact_id> --justification <text>` →
//!   `POST /api/v1/admin/curation/quarantine/:artifact_id/block` (single
//!   artifact; uses [`BlockTarget::Artifact`] on the server side).
//! - `block versions --repo <key> --package <name> --versions <v1>,<v2>,…
//!   --justification <text>` →
//!   `POST /api/v1/admin/curation/block-versions` (bulk-by-version-list;
//!   server uses [`BlockTarget::VersionList`] and runs continue-on-error
//!   — partial success is 200 OK, NOT 5xx).
//!
//! See the parent `curation/mod.rs` docs for why this is split into two
//! sub-subcommands instead of a literal "single `block` with
//! XOR-of-positional-vs-flags" shape: clap's XOR error messages on misuse
//! are vague; the explicit `block artifact` / `block versions` split is
//! self-documenting in `--help`.
//!
//! # Output (`block versions`)
//!
//! The bulk endpoint returns a `BlockOutcomeDto` envelope with five
//! fields:
//!
//! - `correlation_id` — shared across every `ArtifactRejected` the call
//!   emits; the operator dashboards group by this id
//! - `blocked_artifact_ids` — transitioned to `Rejected` on this call
//! - `already_rejected_ids` — idempotent no-op (no event appended)
//! - `not_found_versions` — strings the resolver could not match;
//!   **future ingests of these are not auto-blocked** (operator
//!   playbook documents this; the CLI table highlights the count so
//!   the operator notices)
//! - `failed` — per-`(artifact_id, error)` pairs that hit a
//!   continue-on-error path mid-call. The CLI renders `failed` in red
//!   (ANSI escape) when non-empty so the operator retries the failed
//!   subset using the same `correlation_id`.

use std::io::{IsTerminal, Write};

use anyhow::Result;
use clap::Subcommand;
use uuid::Uuid;

use crate::client::AkClient;
use crate::config::OutputFormat;
use crate::output::{format_json, format_table_rows};

use super::{encode_path_segment, validate_justification};

// ANSI escape for red text — used in table output to highlight
// `failed` and `not_found_versions` counts when they are non-zero.
// Inline literals avoid pulling in the `colored` crate (keep the dep
// set tight).
const ANSI_RED: &str = "\x1b[31m";
const ANSI_RESET: &str = "\x1b[0m";

// ---------------------------------------------------------------------------
// Wire DTOs
// ---------------------------------------------------------------------------

/// Request body for `POST /admin/curation/quarantine/:artifact_id/block`.
///
/// **Sync-required**: mirrors `BlockRequestDto` in
/// `hort-http-core::handlers::admin::curation::block`.
#[derive(Debug, serde::Serialize)]
struct BlockArtifactRequestBody<'a> {
    justification: &'a str,
}

/// Request body for `POST /admin/curation/block-versions`.
///
/// **Sync-required**: mirrors `BlockVersionsRequestDto` in
/// `hort-http-core::handlers::admin::curation::block_versions`.
/// `repository` is the operator-facing stable key (not a UUID).
#[derive(Debug, serde::Serialize)]
struct BlockVersionsRequestBody<'a> {
    repository: &'a str,
    package: &'a str,
    versions: Vec<String>,
    justification: &'a str,
}

/// Per-entry projection of `(Uuid, AppError)` from
/// [`BlockOutcomeDto::failed`].
///
/// **Sync-required**: mirrors `FailedBlockEntryDto` in
/// `hort-http-core::handlers::admin::curation::block_versions`.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct FailedBlockEntryDto {
    pub artifact_id: Uuid,
    pub error_kind: String,
    pub message: String,
}

/// Response envelope returned by both `POST /admin/curation/quarantine/:id/block`
/// (single — trivial envelope) and `POST /admin/curation/block-versions`
/// (bulk — full envelope).
///
/// **Sync-required**: mirrors `BlockOutcomeDto` in
/// `hort-http-core::handlers::admin::curation::block_versions`.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct BlockOutcomeDto {
    pub correlation_id: Uuid,
    pub blocked_artifact_ids: Vec<Uuid>,
    pub already_rejected_ids: Vec<Uuid>,
    pub not_found_versions: Vec<String>,
    pub failed: Vec<FailedBlockEntryDto>,
}

// ---------------------------------------------------------------------------
// Clap args
// ---------------------------------------------------------------------------

/// `hort-cli curation block` arguments.
#[derive(clap::Args, Debug)]
pub struct BlockArgs {
    #[command(subcommand)]
    pub cmd: BlockCommand,
}

/// `block` sub-subcommands.
#[derive(Subcommand, Debug)]
pub enum BlockCommand {
    /// Block a single artifact by UUID.
    ///
    /// Emits a single `ArtifactRejected { rejected_by: Curator }` event;
    /// state guard `Quarantined`/`Released` → `Rejected`.
    Artifact(BlockArtifactArgs),

    /// Bulk block by `(repository, package, version-list)`.
    ///
    /// Continue-on-error — partial success is 200 OK with a
    /// non-empty `failed` list; the operator retries the failed subset
    /// using the same `correlation_id`. Future ingests of any version
    /// the resolver could not find are NOT auto-blocked.
    Versions(BlockVersionsArgs),
}

/// Arguments for `hort-cli curation block artifact <id> --justification <text>`.
#[derive(clap::Args, Debug)]
pub struct BlockArtifactArgs {
    /// Artifact UUID to block (transitions `Quarantined`/`Released` →
    /// `Rejected`).
    pub artifact_id: String,

    /// Operator justification recorded on the emitted
    /// `ArtifactRejected` event. Must be non-empty and ≤ 512 bytes
    /// (validated client-side).
    #[arg(long, required = true)]
    pub justification: String,
}

/// Arguments for
/// `hort-cli curation block versions --repo <key> --package <name>
/// --versions <v1>,<v2>,… --justification <text>`.
#[derive(clap::Args, Debug)]
pub struct BlockVersionsArgs {
    /// Repository stable key (e.g. `npm-proxy`). Resolved server-side
    /// via `RepositoryUseCase::get_by_key`; unknown keys surface as 404.
    #[arg(long = "repo", required = true, add = crate::completions::repo_arg_candidates())]
    pub repository: String,

    /// Package name to match (`artifacts.name` column).
    #[arg(long, required = true)]
    pub package: String,

    /// Comma-separated list of versions to block (e.g. `1.0.0,1.0.1,1.1.0`).
    /// Cap: 100 versions per call (server-side `MAX_VERSIONS_PER_CALL`).
    /// Unknown versions land in `outcome.not_found_versions`; the call
    /// still emits `ArtifactRejected` for every version that resolved.
    #[arg(long, required = true, value_delimiter = ',')]
    pub versions: Vec<String>,

    /// Operator justification recorded on every emitted
    /// `ArtifactRejected` event (same text rides each per-artifact
    /// event tied by `correlation_id`). Must be non-empty and ≤ 512
    /// bytes (validated client-side).
    #[arg(long, required = true)]
    pub justification: String,
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Dispatch path. Writes to stdout.
pub async fn run(client: AkClient, args: BlockArgs, output: OutputFormat) -> Result<()> {
    match args.cmd {
        BlockCommand::Artifact(a) => {
            run_artifact_with_output(client, a, output, &mut std::io::stdout()).await
        }
        BlockCommand::Versions(v) => {
            run_versions_with_output(client, v, output, &mut std::io::stdout()).await
        }
    }
}

/// Testable variant for `block artifact <id>`.
pub async fn run_artifact_with_output(
    client: AkClient,
    args: BlockArtifactArgs,
    output: OutputFormat,
    out: &mut impl Write,
) -> Result<()> {
    validate_justification(&args.justification)?;

    let encoded_id = encode_path_segment(&args.artifact_id);
    let path = format!("/api/v1/admin/curation/quarantine/{encoded_id}/block");

    let body = BlockArtifactRequestBody {
        justification: &args.justification,
    };
    // The server returns 200 OK with a trivial `BlockOutcomeDto` envelope
    // (at most one entry in `blocked_artifact_ids` / `already_rejected_ids`
    // / `failed`).
    let outcome: BlockOutcomeDto = client.post(&path, &body).await?;

    // TTY-gate ANSI colors based on the program's *stdout* rather than
    // the test-injected `out` buffer — mirrors `auth::login`'s pattern.
    // Pipes (`| grep`), file redirects, and CI log aggregators all see
    // plain text; only interactive terminals get red highlights.
    let use_ansi = std::io::stdout().is_terminal();
    render_outcome(&outcome, output, out, use_ansi)?;
    Ok(())
}

/// Testable variant for `block versions --repo ... --package ... --versions ...`.
pub async fn run_versions_with_output(
    client: AkClient,
    args: BlockVersionsArgs,
    output: OutputFormat,
    out: &mut impl Write,
) -> Result<()> {
    validate_justification(&args.justification)?;

    if args.versions.is_empty() {
        return Err(anyhow::anyhow!("--versions must not be empty"));
    }

    let body = BlockVersionsRequestBody {
        repository: &args.repository,
        package: &args.package,
        versions: args.versions.clone(),
        justification: &args.justification,
    };
    let outcome: BlockOutcomeDto = client
        .post("/api/v1/admin/curation/block-versions", &body)
        .await?;

    // TTY-gate ANSI colors (see `run_artifact_with_output` for the
    // identical rationale).
    let use_ansi = std::io::stdout().is_terminal();
    render_outcome(&outcome, output, out, use_ansi)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// Render a `BlockOutcomeDto` to `out`.
///
/// Table mode prints the five-column summary (correlation_id +
/// counts), then — when non-empty — a per-entry failed-rows section.
/// JSON mode emits the envelope verbatim. The `failed` count column
/// and the `not_found_versions` count column are wrapped in ANSI red
/// when non-zero **AND `use_ansi` is true** so the operator notices:
///
/// - `not_found_versions` → the operator should know future ingests of
///   those versions are NOT auto-blocked.
/// - `failed` → continue-on-error — the operator retries the
///   failed subset using the same `correlation_id`.
///
/// `use_ansi` is a TTY gate — production callers compute it once via
/// `std::io::stdout().is_terminal()` (mirrors `auth::login` —
/// `crates/hort-cli/src/auth/login.rs:194`). When stdout is piped to
/// `grep`/`awk`, redirected to a file, or captured by CI scripts the
/// caller passes `false`; raw ANSI escape bytes never leak into the
/// downstream consumer's text stream. JSON output is never colored
/// regardless of `use_ansi`.
fn render_outcome(
    outcome: &BlockOutcomeDto,
    output: OutputFormat,
    out: &mut impl Write,
    use_ansi: bool,
) -> Result<()> {
    match output {
        OutputFormat::Json => {
            writeln!(out, "{}", format_json(outcome))?;
        }
        OutputFormat::Table => {
            let headers = &[
                "CORRELATION_ID",
                "BLOCKED",
                "ALREADY_REJECTED",
                "NOT_FOUND",
                "FAILED",
            ];
            let blocked = outcome.blocked_artifact_ids.len().to_string();
            let already = outcome.already_rejected_ids.len().to_string();
            let not_found = highlight_if_nonzero(outcome.not_found_versions.len(), use_ansi);
            let failed = highlight_if_nonzero(outcome.failed.len(), use_ansi);
            let rows = vec![vec![
                outcome.correlation_id.to_string(),
                blocked,
                already,
                not_found,
                failed,
            ]];
            write!(out, "{}", format_table_rows(headers, &rows))?;

            // Per-entry detail sections. Only emit when non-empty so the
            // happy-path output stays compact. ANSI wrapping is gated on
            // `use_ansi` — same justification as the column highlight.
            let (red, reset) = if use_ansi {
                (ANSI_RED, ANSI_RESET)
            } else {
                ("", "")
            };
            if !outcome.not_found_versions.is_empty() {
                writeln!(
                    out,
                    "\n{red}NOT_FOUND_VERSIONS ({}) — future ingests of these are NOT auto-blocked:{reset}",
                    outcome.not_found_versions.len()
                )?;
                for v in &outcome.not_found_versions {
                    writeln!(out, "  - {v}")?;
                }
            }
            if !outcome.failed.is_empty() {
                writeln!(
                    out,
                    "\n{red}FAILED ({}) — retry the failed subset with correlation_id {}:{reset}",
                    outcome.failed.len(),
                    outcome.correlation_id
                )?;
                let fhdr = &["ARTIFACT_ID", "ERROR_KIND", "MESSAGE"];
                let frows: Vec<Vec<String>> = outcome
                    .failed
                    .iter()
                    .map(|f| {
                        vec![
                            f.artifact_id.to_string(),
                            f.error_kind.clone(),
                            f.message.clone(),
                        ]
                    })
                    .collect();
                write!(out, "{}", format_table_rows(fhdr, &frows))?;
            }
        }
    }
    Ok(())
}

/// Wrap `n` in ANSI red when `n > 0` AND `use_ansi` is true. Used for
/// the `not_found` and `failed` columns so the operator's eye is drawn
/// to non-zero counts on an interactive TTY — but the wrap is suppressed
/// when stdout is piped/redirected so raw escape bytes don't corrupt
/// downstream `grep`/`awk`/log-aggregator consumers (mirrors
/// `auth::login`'s `is_terminal()` gating).
fn highlight_if_nonzero(n: usize, use_ansi: bool) -> String {
    if n > 0 && use_ansi {
        format!("{ANSI_RED}{n}{ANSI_RESET}")
    } else {
        n.to_string()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_outcome() -> BlockOutcomeDto {
        BlockOutcomeDto {
            correlation_id: Uuid::nil(),
            blocked_artifact_ids: vec![],
            already_rejected_ids: vec![],
            not_found_versions: vec![],
            failed: vec![],
        }
    }

    #[test]
    fn highlight_if_nonzero_zero_no_ansi() {
        // When the count is zero, NO ANSI escape is emitted regardless of
        // the `use_ansi` flag — a plain "0" is unambiguous and matches the
        // operator's expectation that "zero is not worth highlighting".
        assert_eq!(highlight_if_nonzero(0, true), "0");
        assert_eq!(highlight_if_nonzero(0, false), "0");
    }

    #[test]
    fn highlight_if_nonzero_positive_with_ansi_wraps_in_red() {
        // Interactive TTY path — count > 0 and `use_ansi=true` → wrap in
        // ANSI red so the operator's eye is drawn to non-zero counts.
        let s = highlight_if_nonzero(3, true);
        assert!(s.contains("3"));
        assert!(s.contains(ANSI_RED));
        assert!(s.contains(ANSI_RESET));
    }

    #[test]
    fn highlight_if_nonzero_positive_without_ansi_is_plain() {
        // Non-TTY path (pipe / file redirect / CI log capture) — count > 0
        // but `use_ansi=false` → emit plain digits so downstream
        // `grep`/`awk`/log aggregators don't see raw ANSI escape bytes.
        // This is the core TTY-gating contract the function exposes.
        let s = highlight_if_nonzero(3, false);
        assert_eq!(s, "3");
        assert!(!s.contains(ANSI_RED));
        assert!(!s.contains(ANSI_RESET));
        assert!(!s.contains('\x1b'));
    }

    #[test]
    fn render_outcome_table_empty_lists_no_detail_sections() {
        let outcome = empty_outcome();
        let mut buf = Vec::new();
        render_outcome(&outcome, OutputFormat::Table, &mut buf, true).expect("renders");
        let out = String::from_utf8(buf).expect("utf8");
        // Header row present; no detail sections for empty lists.
        assert!(out.contains("CORRELATION_ID"));
        assert!(out.contains("FAILED"));
        assert!(!out.contains("NOT_FOUND_VERSIONS ("));
        assert!(!out.contains("FAILED ("));
    }

    #[test]
    fn render_outcome_table_failed_section_uses_red_when_ansi() {
        let mut outcome = empty_outcome();
        outcome.failed.push(FailedBlockEntryDto {
            artifact_id: Uuid::nil(),
            error_kind: "conflict".to_string(),
            message: "event-store version conflict".to_string(),
        });
        let mut buf = Vec::new();
        render_outcome(&outcome, OutputFormat::Table, &mut buf, true).expect("renders");
        let out = String::from_utf8(buf).expect("utf8");
        assert!(out.contains("FAILED (1)"));
        assert!(out.contains(ANSI_RED));
        // FAILED column value AND header section are wrapped in red.
        assert!(out.contains("event-store version conflict"));
    }

    #[test]
    fn render_outcome_table_failed_section_no_ansi_when_piped() {
        // Pipe/redirect path — `use_ansi=false`. The failed-section header
        // and the FAILED column value MUST NOT carry raw ANSI escape bytes
        // (`grep`/`awk` corruption fix — ANSI must be suppressed when piped).
        let mut outcome = empty_outcome();
        outcome.failed.push(FailedBlockEntryDto {
            artifact_id: Uuid::nil(),
            error_kind: "conflict".to_string(),
            message: "event-store version conflict".to_string(),
        });
        let mut buf = Vec::new();
        render_outcome(&outcome, OutputFormat::Table, &mut buf, false).expect("renders");
        let out = String::from_utf8(buf).expect("utf8");
        // Section header + per-row detail still present — only color is gated.
        assert!(out.contains("FAILED (1)"));
        assert!(out.contains("event-store version conflict"));
        assert!(
            !out.contains('\x1b'),
            "no ANSI escape bytes when piped: {out:?}"
        );
    }

    #[test]
    fn render_outcome_table_not_found_section_uses_red_when_ansi() {
        let mut outcome = empty_outcome();
        outcome.not_found_versions.push("9.9.9".to_string());
        let mut buf = Vec::new();
        render_outcome(&outcome, OutputFormat::Table, &mut buf, true).expect("renders");
        let out = String::from_utf8(buf).expect("utf8");
        assert!(out.contains("NOT_FOUND_VERSIONS (1)"));
        assert!(out.contains("9.9.9"));
        assert!(out.contains(ANSI_RED));
    }

    #[test]
    fn render_outcome_table_not_found_section_no_ansi_when_piped() {
        // Pipe/redirect path mirror of the failed-section test —
        // not_found section retains content but drops ANSI escapes.
        let mut outcome = empty_outcome();
        outcome.not_found_versions.push("9.9.9".to_string());
        let mut buf = Vec::new();
        render_outcome(&outcome, OutputFormat::Table, &mut buf, false).expect("renders");
        let out = String::from_utf8(buf).expect("utf8");
        assert!(out.contains("NOT_FOUND_VERSIONS (1)"));
        assert!(out.contains("9.9.9"));
        assert!(
            !out.contains('\x1b'),
            "no ANSI escape bytes when piped: {out:?}"
        );
    }

    #[test]
    fn render_outcome_json_emits_envelope() {
        // JSON path bypasses ANSI rendering entirely — `use_ansi` is a
        // no-op for serde output. Verify both arms produce identical
        // valid JSON.
        for use_ansi in [true, false] {
            let outcome = empty_outcome();
            let mut buf = Vec::new();
            render_outcome(&outcome, OutputFormat::Json, &mut buf, use_ansi).expect("renders");
            let out = String::from_utf8(buf).expect("utf8");
            assert!(
                !out.contains('\x1b'),
                "JSON never carries ANSI ({use_ansi}): {out:?}"
            );
            let parsed: serde_json::Value = serde_json::from_str(&out).expect("valid json");
            assert!(parsed.get("correlation_id").is_some());
            assert!(parsed.get("blocked_artifact_ids").is_some());
            assert!(parsed.get("already_rejected_ids").is_some());
            assert!(parsed.get("not_found_versions").is_some());
            assert!(parsed.get("failed").is_some());
        }
    }
}
