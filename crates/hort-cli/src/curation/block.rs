//! `hort-cli curation block` — the curator's block, addressed three ways.
//!
//! - `block artifact <artifact_id> --justification <text>` →
//!   `POST /api/v1/admin/curation/quarantine/:artifact_id/block` (single
//!   artifact; uses `BlockTarget::Artifact` on the server side).
//! - `block versions --repo <key> --package <name> --versions <v1>,<v2>,…
//!   --justification <text>` →
//!   `POST /api/v1/admin/curation/block-versions` (bulk-by-version-list;
//!   server uses `BlockTarget::VersionList`).
//! - `block digests --repo <key> --digests <d1>,<d2>,…
//!   --justification <text>` →
//!   `POST /api/v1/admin/curation/block-digests` (bulk-by-content-digest;
//!   server uses `BlockTarget::DigestList`) — for OCI and everything else
//!   where `artifacts.version` is `NULL` by construction, and for any
//!   decision taken over the bytes that were reviewed.
//!
//! Both bulk modes run **continue-on-error**: partial success is 200 OK,
//! NOT 5xx. That is the inverse of the bulk waive's all-or-nothing
//! contract, and the asymmetry is deliberate — see `curation/mod.rs`.
//!
//! See the parent `curation/mod.rs` docs for why this is split into
//! sub-subcommands instead of a literal "single `block` with
//! XOR-of-positional-vs-flags" shape: clap's XOR error messages on misuse
//! are vague; the explicit split is self-documenting in `--help`.
//!
//! # Output (the bulk modes)
//!
//! The bulk endpoints return a `BlockOutcomeDto` envelope with six
//! fields:
//!
//! - `correlation_id` — shared across every `ArtifactRejected` the call
//!   emits; the operator dashboards group by this id
//! - `blocked_artifact_ids` — transitioned to `Rejected` on this call
//! - `already_rejected_ids` — idempotent no-op (no event appended)
//! - `not_found_versions` / `not_found_digests` — keys the resolver could
//!   not match; **future ingests of these are not auto-blocked** (operator
//!   playbook documents this; the CLI table highlights the count so
//!   the operator notices). Both lists are always present and the one the
//!   call did not address by is empty
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

use super::{
    ansi_pair, encode_path_segment, highlight_if_nonzero, normalize_digests, validate_justification,
};

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

/// Request body for `POST /admin/curation/block-digests`.
///
/// **Sync-required**: mirrors `BlockDigestsRequestDto` in
/// `hort-http-core::handlers::admin::curation::block_digests`.
///
/// No `package` field: a digest is repository-scoped and names its bytes
/// outright, so the package the bytes happen to sit under is not part of
/// the address. And no `tags` field — a tag is a mutable pointer, and a
/// curation decision binds to the bytes that were reviewed.
#[derive(Debug, serde::Serialize)]
struct BlockDigestsRequestBody<'a> {
    repository: &'a str,
    digests: Vec<String>,
    justification: &'a str,
}

/// Per-entry projection of `(Uuid, AppError)` from
/// `BlockOutcomeDto::failed`.
///
/// **Sync-required**: mirrors `FailedBlockEntryDto` in
/// `hort-http-core::handlers::admin::curation::block_versions`. Shared
/// with the bulk-waive outcome exactly as the server shares it: a
/// per-entry apply failure is the same wire shape whichever bulk verb
/// produced it.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct FailedBlockEntryDto {
    pub artifact_id: Uuid,
    pub error_kind: String,
    pub message: String,
}

/// Response envelope returned by `POST /admin/curation/quarantine/:id/block`
/// (single — trivial envelope), `POST /admin/curation/block-versions` and
/// `POST /admin/curation/block-digests` (bulk — full envelope).
///
/// **Sync-required**: mirrors `BlockOutcomeDto` in
/// `hort-http-core::handlers::admin::curation::block_versions`. Both
/// `not_found_*` lists are modelled, because which addressing mode a
/// call used is the request's property: the server always sends both and
/// leaves the unused one empty, and a mirror missing one of them drops
/// the key on `--output json` re-serialisation.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct BlockOutcomeDto {
    pub correlation_id: Uuid,
    pub blocked_artifact_ids: Vec<Uuid>,
    pub already_rejected_ids: Vec<Uuid>,
    pub not_found_versions: Vec<String>,
    pub not_found_digests: Vec<String>,
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

/// `block` sub-subcommands — one per addressing mode.
#[derive(Subcommand, Debug)]
pub enum BlockCommand {
    /// Block a single artifact, named by its UUID.
    ///
    /// Emits a single `ArtifactRejected { rejected_by: Curator }` event;
    /// state guard `Quarantined`/`Released` → `Rejected`.
    Artifact(BlockArtifactArgs),

    /// Block a batch, named by `(repository, package, version-list)`.
    ///
    /// Continue-on-error — partial success is 200 OK with a
    /// non-empty `failed` list; the operator retries the failed subset
    /// using the same `correlation_id`. Future ingests of any version
    /// the resolver could not find are NOT auto-blocked.
    Versions(BlockVersionsArgs),

    /// Block a batch, named by content digest.
    ///
    /// For OCI and everything else where `artifacts.version` is `NULL`
    /// by construction. Same continue-on-error contract as `versions`,
    /// with one exception: a digest matching more than one live row is
    /// refused naming the candidates, before the first append.
    Digests(BlockDigestsArgs),
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

/// Arguments for
/// `hort-cli curation block digests --repo <key> --digests <d1>,<d2>,…
/// --justification <text>`.
#[derive(clap::Args, Debug)]
pub struct BlockDigestsArgs {
    /// Repository stable key (e.g. `oci-proxy`). Resolved server-side
    /// via `RepositoryUseCase::get_by_key`; unknown keys surface as 404.
    #[arg(long = "repo", required = true, add = crate::completions::repo_arg_candidates())]
    pub repository: String,

    /// Comma-separated SHA-256 digests of the artifacts to block.
    /// A bare 64-hex digest and a `sha256:`-prefixed one are the same
    /// address. Any other algorithm prefix is refused rather than
    /// stripped. Unknown digests land in `outcome.not_found_digests`;
    /// a digest matching more than one live row is refused naming the
    /// candidates, because which row the curator reviewed is not the
    /// server's to guess.
    #[arg(long, required = true, value_delimiter = ',')]
    pub digests: Vec<String>,

    /// Operator justification recorded on every emitted
    /// `ArtifactRejected` event. Must be non-empty and ≤ 512 bytes
    /// (validated client-side).
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
        BlockCommand::Digests(d) => {
            run_digests_with_output(client, d, output, &mut std::io::stdout()).await
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

    render_outcome(&outcome, output, out, stdout_is_tty())?;
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

    render_outcome(&outcome, output, out, stdout_is_tty())?;
    Ok(())
}

/// Testable variant for `block digests --repo ... --digests ...`.
pub async fn run_digests_with_output(
    client: AkClient,
    args: BlockDigestsArgs,
    output: OutputFormat,
    out: &mut impl Write,
) -> Result<()> {
    validate_justification(&args.justification)?;
    // Both spellings of one digest are one address, so the request body
    // is the same either way, and it is the same normalisation the waive
    // side applies (see `super::normalize_digests`).
    let digests = normalize_digests(&args.digests)?;

    let body = BlockDigestsRequestBody {
        repository: &args.repository,
        digests,
        justification: &args.justification,
    };
    let outcome: BlockOutcomeDto = client
        .post("/api/v1/admin/curation/block-digests", &body)
        .await?;

    render_outcome(&outcome, output, out, stdout_is_tty())?;
    Ok(())
}

/// TTY-gate ANSI colors on the program's *stdout* rather than the
/// test-injected `out` buffer — mirrors `auth::login`'s pattern. Pipes
/// (`| grep`), file redirects, and CI log aggregators all see plain
/// text; only interactive terminals get red highlights.
fn stdout_is_tty() -> bool {
    std::io::stdout().is_terminal()
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// Render a `BlockOutcomeDto` to `out`.
///
/// Table mode prints the five-column summary (correlation_id +
/// counts), then — when non-empty — the per-entry not-found and failed
/// sections. JSON mode emits the envelope verbatim. The `failed` count
/// column and the `not_found` count column are wrapped in ANSI red
/// when non-zero **AND `use_ansi` is true** so the operator notices:
///
/// - `not_found` → the operator should know future ingests of those
///   versions or digests are NOT auto-blocked.
/// - `failed` → continue-on-error — the operator retries the
///   failed subset using the same `correlation_id`.
///
/// `NOT_FOUND` is **one column over both not-found lists**: a call
/// addresses by versions or by digests, never both, so the server leaves
/// the other list empty and a second always-zero column would be noise.
/// The detail sections below the summary are per-list, and say which
/// kind of key went unmatched.
///
/// `use_ansi` is a TTY gate — production callers compute it once via
/// [`stdout_is_tty`] (mirrors `auth::login` —
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
            let not_found_total =
                outcome.not_found_versions.len() + outcome.not_found_digests.len();
            let not_found = highlight_if_nonzero(not_found_total, use_ansi);
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
            let (red, reset) = ansi_pair(use_ansi);
            render_not_found_section(
                out,
                "NOT_FOUND_VERSIONS",
                &outcome.not_found_versions,
                red,
                reset,
            )?;
            render_not_found_section(
                out,
                "NOT_FOUND_DIGESTS",
                &outcome.not_found_digests,
                red,
                reset,
            )?;
            render_failed_entries(out, &outcome.failed, outcome.correlation_id, red, reset)?;
        }
    }
    Ok(())
}

/// One not-found section, or nothing when the list is empty.
///
/// Both lists carry the same consequence — a key the resolver did not
/// match is a key whose future ingest this surface does not auto-block —
/// so they say it in one place rather than once per addressing mode.
fn render_not_found_section(
    out: &mut impl Write,
    title: &str,
    keys: &[String],
    red: &str,
    reset: &str,
) -> Result<()> {
    if keys.is_empty() {
        return Ok(());
    }
    writeln!(
        out,
        "\n{red}{title} ({}) — future ingests of these are NOT auto-blocked:{reset}",
        keys.len()
    )?;
    for key in keys {
        writeln!(out, "  - {key}")?;
    }
    Ok(())
}

/// The per-entry failed section shared by every bulk decision verb.
///
/// `pub(crate)` because the bulk waive renders the same list from the
/// same DTO: an apply failure reads the same whichever verb produced it,
/// and the retry instruction — re-issue for the failed subset, carrying
/// the same justification — is the same instruction.
pub(crate) fn render_failed_entries(
    out: &mut impl Write,
    failed: &[FailedBlockEntryDto],
    correlation_id: Uuid,
    red: &str,
    reset: &str,
) -> Result<()> {
    if failed.is_empty() {
        return Ok(());
    }
    writeln!(
        out,
        "\n{red}FAILED ({}) — retry the failed subset with correlation_id {correlation_id}:{reset}",
        failed.len()
    )?;
    let headers = &["ARTIFACT_ID", "ERROR_KIND", "MESSAGE"];
    let rows: Vec<Vec<String>> = failed
        .iter()
        .map(|f| {
            vec![
                f.artifact_id.to_string(),
                f.error_kind.clone(),
                f.message.clone(),
            ]
        })
        .collect();
    write!(out, "{}", format_table_rows(headers, &rows))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curation::{ANSI_RED, ANSI_RESET};

    const DIGEST: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    fn empty_outcome() -> BlockOutcomeDto {
        BlockOutcomeDto {
            correlation_id: Uuid::nil(),
            blocked_artifact_ids: vec![],
            already_rejected_ids: vec![],
            not_found_versions: vec![],
            not_found_digests: vec![],
            failed: vec![],
        }
    }

    fn render_table(outcome: &BlockOutcomeDto, use_ansi: bool) -> String {
        let mut buf = Vec::new();
        render_outcome(outcome, OutputFormat::Table, &mut buf, use_ansi).expect("renders");
        String::from_utf8(buf).expect("utf8")
    }

    #[test]
    fn render_outcome_table_empty_lists_no_detail_sections() {
        let out = render_table(&empty_outcome(), true);
        // Header row present; no detail sections for empty lists.
        assert!(out.contains("CORRELATION_ID"));
        assert!(out.contains("FAILED"));
        assert!(!out.contains("NOT_FOUND_VERSIONS ("));
        assert!(!out.contains("NOT_FOUND_DIGESTS ("));
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
        let out = render_table(&outcome, true);
        assert!(out.contains("FAILED (1)"));
        assert!(out.contains(ANSI_RED));
        // FAILED column value AND header section are wrapped in red.
        assert!(out.contains("event-store version conflict"));
        assert!(out.contains(ANSI_RESET));
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
        let out = render_table(&outcome, false);
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
        let out = render_table(&outcome, true);
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
        let out = render_table(&outcome, false);
        assert!(out.contains("NOT_FOUND_VERSIONS (1)"));
        assert!(out.contains("9.9.9"));
        assert!(
            !out.contains('\x1b'),
            "no ANSI escape bytes when piped: {out:?}"
        );
    }

    /// A digest-addressed call reports its unmatched keys in a section of
    /// their own — and counts them in the same `NOT_FOUND` column, which
    /// is what keeps the summary row one shape across both modes.
    #[test]
    fn an_unmatched_digest_has_its_own_section_and_the_shared_column() {
        let mut outcome = empty_outcome();
        outcome.not_found_digests.push(DIGEST.to_string());
        let out = render_table(&outcome, false);
        assert!(out.contains("NOT_FOUND_DIGESTS (1)"), "{out}");
        assert!(out.contains(DIGEST), "{out}");
        assert!(!out.contains("NOT_FOUND_VERSIONS ("), "{out}");
        assert!(
            out.contains("NOT auto-blocked"),
            "the consequence is stated for digests too: {out}"
        );
        // The column counts it: header row, then a row whose NOT_FOUND
        // cell is 1.
        let data_row = out.lines().nth(1).expect("a data row");
        assert!(
            data_row.split_whitespace().nth(3) == Some("1"),
            "NOT_FOUND column counts the digest: {data_row}"
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
            assert!(parsed.get("not_found_digests").is_some());
            assert!(parsed.get("failed").is_some());
        }
    }

    /// The acceptance criterion the mirror DTO exists for: the server
    /// sends both not-found lists, so `--output json` must hand both
    /// back. Before `not_found_digests` was mirrored here, a
    /// `block versions --output json` re-serialisation dropped the key.
    #[test]
    fn the_outcome_dto_round_trips_both_not_found_lists() {
        let id = Uuid::nil();
        let body = format!(
            r#"{{"correlation_id":"{id}","blocked_artifact_ids":[],
                 "already_rejected_ids":[],"not_found_versions":["9.9.9"],
                 "not_found_digests":["{DIGEST}"],"failed":[]}}"#
        );
        let parsed: BlockOutcomeDto = serde_json::from_str(&body).expect("parses");
        let reserialized: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&parsed).expect("serialises"))
                .expect("valid json");
        let original: serde_json::Value = serde_json::from_str(&body).expect("valid json");
        assert_eq!(reserialized, original);
    }

    /// `block` advertises the same three addressing modes `waive` does —
    /// the property this command tree exists to hold.
    #[test]
    fn block_help_advertises_the_same_three_addressing_modes_as_waive() {
        use clap::CommandFactory;
        let mut cmd = crate::Cli::command();
        let curation = cmd
            .find_subcommand_mut("curation")
            .expect("curation is mounted");
        let names = |verb: &str, cmd: &mut clap::Command| -> Vec<String> {
            cmd.find_subcommand_mut(verb)
                .expect("verb is mounted")
                .get_subcommands()
                .map(|s| s.get_name().to_string())
                .filter(|n| n != "help")
                .collect()
        };
        assert_eq!(
            names("block", curation),
            vec!["artifact", "versions", "digests"]
        );
        assert_eq!(names("block", curation), names("waive", curation));
    }
}
