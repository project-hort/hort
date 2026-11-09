//! `hort-cli curation waive` — the curator's manual release, addressed
//! three ways.
//!
//! - `waive artifact <artifact_id>` → POST
//!   `/api/v1/admin/curation/quarantine/:artifact_id/waive` (one
//!   artifact; `200 OK` with no body).
//! - `waive versions --repo <key> --package <name> --versions <v1>,<v2>,…`
//!   → POST `/api/v1/admin/curation/waive-versions`.
//! - `waive digests --repo <key> --digests <d1>,<d2>,…` → POST
//!   `/api/v1/admin/curation/waive-digests`.
//!
//! Source states are `Quarantined`, `ScanIndeterminate` and — on the
//! axes the curator owns (scan, curation, provenance) — `Rejected` for
//! the per-artifact route. One authority owns the manual release, so the
//! curator clears a stuck scanner and overrides a rejection it has the
//! instrument to judge; a corruption tombstone is never reachable
//! (ADR 0007, "One authority owns the manual release"). The **bulk**
//! routes are narrower on purpose — `{Quarantined, Released}` only — so
//! a batch cannot walk an entry into a state whose release is a decision
//! taken with a verdict in view.
//!
//! # The flat `waive <artifact_id>` form is removed
//!
//! `waive` used to be a flat command taking a UUID positionally, which
//! is a shape no other addressing mode can use and one an operator who
//! had learned `block versions` could not guess. The positional is gone
//! rather than deprecated: keeping it beside `waive artifact <id>` would
//! preserve exactly the inconsistency the three modes exist to end.
//! [`WaiveCommand::Removed`] catches the old shape so the caller is told
//! what to run instead — a bare "unrecognized subcommand" would leave a
//! broken script's author to guess where the command went.
//!
//! # All-or-nothing, not continue-on-error
//!
//! The bulk routes are the fail-open half of curation and their contract
//! is the inverse of `block versions`'. One entry that is unresolvable,
//! ambiguous, or in a state a bulk waive does not reach aborts the whole
//! batch: `409 Conflict` carrying the full per-entry report, and **zero
//! releases applied**. `ArtifactReleased` is history that cannot be
//! retracted, so releasing the resolvable subset of a list the curator
//! wrote wrongly is the defect that contract exists to prevent — while a
//! block the curator did not mean is reversible a minute later. Hence
//! also the entry cap: 25 per bulk waive against `block`'s 100.
//!
//! The report is **data, not a message**: it names every entry, the fine
//! ones included, so a curator who asked for five releases and got none
//! can see which entry stopped the batch without bisecting their list.
//! It is therefore printed to the chosen output stream — verbatim under
//! `--output json` — and the command exits [`WAIVE_ABORTED_EXIT`] rather
//! than flattening the report into an error sentence on stderr.
//!
//! # Client-side validation
//!
//! `--justification` is validated BEFORE any HTTP call via the shared
//! [`super::validate_justification`] helper, and `--digests` through
//! [`super::normalize_digests`] — operator gets fast feedback; the audit
//! log is spared a denied-write. Neither cap (25 entries, 100 for a
//! block) is re-stated here: the server owns it, and a stale local copy
//! would refuse a call the server accepts.

use std::io::{IsTerminal, Write};
use std::process::ExitCode;

use anyhow::Result;
use clap::Subcommand;
use uuid::Uuid;

use crate::client::AkClient;
use crate::config::OutputFormat;
use crate::output::{format_json, format_table_rows};

// The per-entry apply-failure shape is the block verbs' DTO, reused
// exactly as the server reuses it (`waive_bulk.rs` imports
// `FailedBlockEntryDto` from `block_versions.rs`): a per-entry failure is
// the same wire shape whichever bulk verb produced it, and a second copy
// would be a second thing to keep in sync with the server.
use super::block::{render_failed_entries, FailedBlockEntryDto};
use super::{
    ansi_pair, encode_path_segment, highlight_if_nonzero, normalize_digests, validate_justification,
};

/// Exit code for a bulk waive the server refused whole.
///
/// Distinct from `0` (the batch applied) and from `1` (the command never
/// got an answer it could read — transport, 403, 404, a malformed
/// request): an aborted batch released **nothing**, and an unattended
/// caller must be able to tell that from both without re-reading the
/// output it just wrote. Same reasoning as `admin retention`'s
/// `RetentionExit`, which separates "I never saw the result" from "the
/// operator said no" for the same reason.
pub const WAIVE_ABORTED_EXIT: u8 = 3;

// ---------------------------------------------------------------------------
// Wire DTOs (request bodies)
// ---------------------------------------------------------------------------

/// Request body for `POST /admin/curation/quarantine/:artifact_id/waive`.
///
/// **Sync-required**: mirrors `WaiveRequestDto` in
/// `hort-http-core::handlers::admin::curation::waive`.
#[derive(Debug, serde::Serialize)]
struct WaiveRequestBody<'a> {
    justification: &'a str,
}

/// Request body for `POST /admin/curation/waive-versions`.
///
/// **Sync-required**: mirrors `WaiveVersionsRequestDto` in
/// `hort-http-core::handlers::admin::curation::waive_bulk`.
/// `repository` is the operator-facing stable key (not a UUID).
#[derive(Debug, serde::Serialize)]
struct WaiveVersionsRequestBody<'a> {
    repository: &'a str,
    package: &'a str,
    versions: Vec<String>,
    justification: &'a str,
}

/// Request body for `POST /admin/curation/waive-digests`.
///
/// **Sync-required**: mirrors `WaiveDigestsRequestDto` in
/// `hort-http-core::handlers::admin::curation::waive_bulk`.
///
/// No `package` field: a digest is repository-scoped and names its bytes
/// outright. And no `tags` field — a tag is a mutable pointer, and a
/// curation decision binds to the bytes that were reviewed.
#[derive(Debug, serde::Serialize)]
struct WaiveDigestsRequestBody<'a> {
    repository: &'a str,
    digests: Vec<String>,
    justification: &'a str,
}

// ---------------------------------------------------------------------------
// Wire DTOs (responses)
// ---------------------------------------------------------------------------

/// The body of a `200` from either bulk route.
///
/// **Sync-required**: mirrors `WaiveOutcomeDto` in
/// `hort-http-core::handlers::admin::curation::waive_bulk`.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct WaiveOutcomeDto {
    /// Shared by every `ArtifactReleased` this call emitted.
    pub correlation_id: Uuid,
    /// Artifacts released **on this call** — one `ArtifactReleased` each.
    pub released_artifact_ids: Vec<Uuid>,
    /// Artifacts that were already `Released`: idempotent successes with
    /// no event appended. Rendered as its own column and its own section
    /// because a converged re-apply must not read as a release that just
    /// happened — the waiver took effect earlier, and an operator who
    /// confuses the two believes a decision landed now that did not.
    pub already_released_ids: Vec<Uuid>,
    /// Per-artifact apply failures inside an otherwise-valid batch.
    pub failed: Vec<FailedBlockEntryDto>,
}

/// The body of a `409` — the full per-entry pre-validation report.
///
/// **Sync-required**: mirrors `WaiveAbortDto` in
/// `hort-http-core::handlers::admin::curation::waive_bulk`. There is no
/// `released_artifact_ids` member and that is deliberate on the server
/// side: nothing was released, and an empty list beside the report would
/// invite a reader to treat the two bodies as one shape with some fields
/// missing.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct WaiveAbortDto {
    /// Fixed discriminator (`"aborted"`), so a client can branch on the
    /// body as well as on the status code.
    pub outcome: String,
    /// Every entry of the request, in the order it was written.
    pub entries: Vec<WaiveEntryReportDto>,
}

/// One entry of the pre-validation report.
///
/// **Sync-required**: mirrors `WaiveEntryReportDto` in
/// `hort-http-core::handlers::admin::curation::waive_bulk`. The three
/// conditional members carry `skip_serializing_if` on both sides, so
/// `--output json` re-emits the body the server sent rather than
/// materialising keys it omitted.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct WaiveEntryReportDto {
    /// The addressing key as it reached the server, so the report line
    /// matches the entry that produced it.
    pub key: String,
    /// The resolved row, when resolution produced exactly one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<Uuid>,
    /// Stable verdict discriminator: `releasable`, `already_released`,
    /// `unresolvable`, `ambiguous`, `state_not_releasable`.
    pub verdict: String,
    /// For `ambiguous`: every live artifact id carrying these bytes —
    /// the field the curator re-addresses the decision with.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidate_artifact_ids: Vec<Uuid>,
    /// For `state_not_releasable`: the state the row is actually in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// The two verdicts that do not stop a batch. Every other verdict is an
/// entry the curator has to fix before the batch can apply.
const NON_BLOCKING_VERDICTS: &[&str] = &["releasable", "already_released"];

// ---------------------------------------------------------------------------
// Clap args
// ---------------------------------------------------------------------------

/// `hort-cli curation waive` arguments.
#[derive(clap::Args, Debug)]
pub struct WaiveArgs {
    #[command(subcommand)]
    pub cmd: WaiveCommand,
}

/// `waive` sub-subcommands — one per addressing mode.
#[derive(Subcommand, Debug)]
pub enum WaiveCommand {
    /// Release one artifact, named by its UUID.
    ///
    /// The one-off, and the only mode that reaches `ScanIndeterminate`
    /// or overrides a `Rejected` verdict.
    Artifact(WaiveArtifactArgs),

    /// Release a batch, named by `(repository, package, version-list)`.
    ///
    /// For the formats where `artifacts.version` is populated. A version
    /// that names more than one stored row (a PyPI release holding an
    /// sdist and a wheel) resolves to the first match — address such a
    /// release by digest instead.
    Versions(WaiveVersionsArgs),

    /// Release a batch, named by content digest.
    ///
    /// For OCI and everything else where `artifacts.version` is `NULL`
    /// by construction, and for any release where the bytes are what was
    /// reviewed. Read the digest off a `curation queue` row.
    Digests(WaiveDigestsArgs),

    /// Catches the removed flat `waive <artifact_id>` form (and any
    /// other unknown target) so the caller is told what to run instead.
    ///
    /// Not advertised in `--help`: clap renders no entry for an external
    /// subcommand, so `waive --help` lists exactly the three addressing
    /// modes.
    #[command(external_subcommand)]
    Removed(Vec<String>),
}

/// Arguments for `hort-cli curation waive artifact <id> --justification <text>`.
#[derive(clap::Args, Debug)]
pub struct WaiveArtifactArgs {
    /// Artifact UUID to waive (release with curator attribution).
    pub artifact_id: String,

    /// Operator justification recorded on the audit event. Must be
    /// non-empty and ≤ 512 bytes (validated client-side).
    #[arg(long, required = true)]
    pub justification: String,
}

/// Arguments for
/// `hort-cli curation waive versions --repo <key> --package <name>
/// --versions <v1>,<v2>,… --justification <text>`.
#[derive(clap::Args, Debug)]
pub struct WaiveVersionsArgs {
    /// Repository stable key (e.g. `npm-proxy`). Resolved server-side;
    /// unknown keys surface as 404.
    #[arg(long = "repo", required = true, add = crate::completions::repo_arg_candidates())]
    pub repository: String,

    /// Package name to match (`artifacts.name` column).
    #[arg(long, required = true)]
    pub package: String,

    /// Comma-separated list of versions to release (e.g.
    /// `1.0.0,1.0.1`). All-or-nothing: one entry the server cannot
    /// release refuses the whole batch and releases nothing. The
    /// per-call entry cap is the server's (a quarter of the block cap,
    /// because a release cannot be retracted).
    #[arg(long, required = true, value_delimiter = ',')]
    pub versions: Vec<String>,

    /// Operator justification recorded on every emitted
    /// `ArtifactReleased` event (same text rides each per-artifact event
    /// tied by `correlation_id`). Must be non-empty and ≤ 512 bytes
    /// (validated client-side).
    #[arg(long, required = true)]
    pub justification: String,
}

/// Arguments for
/// `hort-cli curation waive digests --repo <key> --digests <d1>,<d2>,…
/// --justification <text>`.
#[derive(clap::Args, Debug)]
pub struct WaiveDigestsArgs {
    /// Repository stable key (e.g. `oci-proxy`). Resolved server-side;
    /// unknown keys surface as 404.
    #[arg(long = "repo", required = true, add = crate::completions::repo_arg_candidates())]
    pub repository: String,

    /// Comma-separated SHA-256 digests of the artifacts to release.
    /// A bare 64-hex digest and a `sha256:`-prefixed one are the same
    /// address. Any other algorithm prefix is refused rather than
    /// stripped. A digest matching more than one live row in the
    /// repository is refused naming the candidates — which row the
    /// curator reviewed is not the server's to guess.
    #[arg(long, required = true, value_delimiter = ',')]
    pub digests: Vec<String>,

    /// Operator justification recorded on every emitted
    /// `ArtifactReleased` event. Must be non-empty and ≤ 512 bytes
    /// (validated client-side).
    #[arg(long, required = true)]
    pub justification: String,
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Dispatch path. Writes to stdout and hands back the exit code the
/// outcome deserves (see [`WAIVE_ABORTED_EXIT`]).
pub async fn run(client: AkClient, args: WaiveArgs, output: OutputFormat) -> Result<ExitCode> {
    match args.cmd {
        WaiveCommand::Artifact(a) => {
            run_artifact_with_output(client, a, output, &mut std::io::stdout()).await
        }
        WaiveCommand::Versions(v) => {
            run_versions_with_output(client, v, output, &mut std::io::stdout()).await
        }
        WaiveCommand::Digests(d) => {
            run_digests_with_output(client, d, output, &mut std::io::stdout()).await
        }
        WaiveCommand::Removed(captured) => Err(removed_form_error(&captured)),
    }
}

/// Testable variant for `waive artifact <id>`.
pub async fn run_artifact_with_output(
    client: AkClient,
    args: WaiveArtifactArgs,
    output: OutputFormat,
    out: &mut impl Write,
) -> Result<ExitCode> {
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

    Ok(ExitCode::SUCCESS)
}

/// Testable variant for `waive versions --repo ... --package ... --versions ...`.
pub async fn run_versions_with_output(
    client: AkClient,
    args: WaiveVersionsArgs,
    output: OutputFormat,
    out: &mut impl Write,
) -> Result<ExitCode> {
    validate_justification(&args.justification)?;
    if args.versions.is_empty() {
        return Err(anyhow::anyhow!("--versions must not be empty"));
    }

    let body = WaiveVersionsRequestBody {
        repository: &args.repository,
        package: &args.package,
        versions: args.versions.clone(),
        justification: &args.justification,
    };
    submit_bulk(
        client,
        "/api/v1/admin/curation/waive-versions",
        &body,
        output,
        out,
    )
    .await
}

/// Testable variant for `waive digests --repo ... --digests ...`.
pub async fn run_digests_with_output(
    client: AkClient,
    args: WaiveDigestsArgs,
    output: OutputFormat,
    out: &mut impl Write,
) -> Result<ExitCode> {
    validate_justification(&args.justification)?;
    // Both spellings of one digest are one address, so the request body
    // is the same either way (see `super::normalize_digests`).
    let digests = normalize_digests(&args.digests)?;

    let body = WaiveDigestsRequestBody {
        repository: &args.repository,
        digests,
        justification: &args.justification,
    };
    submit_bulk(
        client,
        "/api/v1/admin/curation/waive-digests",
        &body,
        output,
        out,
    )
    .await
}

/// POST a bulk-waive body and render whichever of the two answers came
/// back.
///
/// One function for both addressing modes, because they differ only in
/// how an entry names its row: a second copy of the abort handling is how
/// the two modes would start reporting a refused batch differently.
async fn submit_bulk<B: serde::Serialize>(
    client: AkClient,
    path: &str,
    body: &B,
    output: OutputFormat,
    out: &mut impl Write,
) -> Result<ExitCode> {
    // The refusal is taken as a response rather than a flattened error
    // because the abort body IS the report the curator has to read.
    let answer: std::result::Result<WaiveOutcomeDto, crate::client::HttpFailure> =
        client.post_capturing_failure(path, body).await?;

    // TTY-gate ANSI colors on the program's *stdout* rather than the
    // test-injected `out` buffer — mirrors `auth::login`'s pattern.
    let use_ansi = std::io::stdout().is_terminal();

    match answer {
        Ok(outcome) => {
            render_outcome(&outcome, output, out, use_ansi)?;
            Ok(ExitCode::SUCCESS)
        }
        Err(failure) => match parse_abort(&failure) {
            Some(abort) => {
                render_abort(&abort, output, out, use_ansi)?;
                Ok(ExitCode::from(WAIVE_ABORTED_EXIT))
            }
            // Anything else — including a 409 whose body is not the
            // report — surfaces verbatim, as every other call in the CLI
            // does. A parser that did not match must not swallow what
            // the server said.
            None => Err(failure.into_error()),
        },
    }
}

/// The error a caller of the removed flat form gets.
///
/// `captured` is what clap collected where a subcommand was expected:
/// for the removed shape that is the artifact id followed by the flags
/// that trailed it. The message names the replacement rather than the
/// mistake, because the caller is a script whose author has to change a
/// line, and a bare "unrecognized subcommand" tells them only that
/// something moved.
fn removed_form_error(captured: &[String]) -> anyhow::Error {
    let target = captured.first().map(String::as_str).unwrap_or("");
    let lead = if target.parse::<Uuid>().is_ok() {
        format!(
            "`curation waive <artifact_id>` was removed. Run instead:\n  \
             hort-cli curation waive artifact {target} --justification '…'"
        )
    } else {
        format!(
            "`curation waive` has no target {target:?}. A waive names how it \
             addresses its target:\n  \
             hort-cli curation waive artifact <artifact_id> --justification '…'"
        )
    };
    anyhow::anyhow!(
        "{lead}\n  \
         hort-cli curation waive versions --repo <key> --package <name> \
         --versions v1,v2 --justification '…'\n  \
         hort-cli curation waive digests --repo <key> --digests <sha256>,… \
         --justification '…'"
    )
}

/// Recognise the abort report, or `None` when this refusal is not it.
fn parse_abort(failure: &crate::client::HttpFailure) -> Option<WaiveAbortDto> {
    if failure.status != reqwest::StatusCode::CONFLICT {
        return None;
    }
    let parsed: WaiveAbortDto = serde_json::from_str(&failure.body).ok()?;
    // A report listing nobody names nothing to fix; the server's own
    // words are worth more than an empty table.
    if parsed.entries.is_empty() {
        return None;
    }
    Some(parsed)
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// Render an applied batch.
///
/// Table mode prints the summary row, then — when non-empty — one
/// section per list. `RELEASED` and `ALREADY_RELEASED` are separate
/// columns AND separate sections, with each section header saying when
/// the release happened: a converged re-apply and a release that just
/// happened are different facts, and an operator who reads the first as
/// the second believes a waiver took effect now when it took effect
/// earlier. `FAILED` is wrapped in ANSI red when non-empty and
/// `use_ansi` is true. JSON mode emits the envelope verbatim and is
/// never colored.
fn render_outcome(
    outcome: &WaiveOutcomeDto,
    output: OutputFormat,
    out: &mut impl Write,
    use_ansi: bool,
) -> Result<()> {
    match output {
        OutputFormat::Json => {
            writeln!(out, "{}", format_json(outcome))?;
        }
        OutputFormat::Table => {
            let headers = &["CORRELATION_ID", "RELEASED", "ALREADY_RELEASED", "FAILED"];
            let rows = vec![vec![
                outcome.correlation_id.to_string(),
                outcome.released_artifact_ids.len().to_string(),
                outcome.already_released_ids.len().to_string(),
                highlight_if_nonzero(outcome.failed.len(), use_ansi),
            ]];
            write!(out, "{}", format_table_rows(headers, &rows))?;

            // Per-entry detail sections. Only emitted when non-empty so
            // the happy path stays compact.
            render_id_section(
                out,
                "RELEASED",
                "released by this call — one ArtifactReleased event each",
                &outcome.released_artifact_ids,
            )?;
            render_id_section(
                out,
                "ALREADY_RELEASED",
                "already Released before this call — idempotent, no event appended now",
                &outcome.already_released_ids,
            )?;
            let (red, reset) = ansi_pair(use_ansi);
            render_failed_entries(out, &outcome.failed, outcome.correlation_id, red, reset)?;
        }
    }
    Ok(())
}

/// One `TITLE (n) — <what it means>:` section over a list of artifact
/// ids, or nothing when the list is empty.
///
/// Never colored: both lists it renders are successes, and highlighting
/// one of them would say the batch needs acting on when it does not.
fn render_id_section(out: &mut impl Write, title: &str, meaning: &str, ids: &[Uuid]) -> Result<()> {
    if ids.is_empty() {
        return Ok(());
    }
    writeln!(out, "\n{title} ({}) — {meaning}:", ids.len())?;
    for id in ids {
        writeln!(out, "  - {id}")?;
    }
    Ok(())
}

/// Render a refused batch — the `409` report.
///
/// Table mode leads with the fact that nothing was released and how many
/// entries have to change, then one row per entry **including the fine
/// ones**, so the curator sees which entry stopped the batch without
/// bisecting their list. JSON mode emits the report verbatim.
fn render_abort(
    abort: &WaiveAbortDto,
    output: OutputFormat,
    out: &mut impl Write,
    use_ansi: bool,
) -> Result<()> {
    match output {
        OutputFormat::Json => {
            writeln!(out, "{}", format_json(abort))?;
        }
        OutputFormat::Table => {
            let blocking = abort
                .entries
                .iter()
                .filter(|e| !NON_BLOCKING_VERDICTS.contains(&e.verdict.as_str()))
                .count();
            let (red, reset) = ansi_pair(use_ansi);
            writeln!(
                out,
                "{red}BATCH ABORTED — nothing was released.{reset} {blocking} of {total} \
                 entries cannot be released; a bulk waive is all-or-nothing because a \
                 release cannot be retracted. Fix the entries below and re-run:",
                total = abort.entries.len()
            )?;
            let headers = &["KEY", "ARTIFACT_ID", "VERDICT", "DETAIL"];
            let rows: Vec<Vec<String>> = abort
                .entries
                .iter()
                .map(|e| {
                    vec![
                        e.key.clone(),
                        e.artifact_id
                            .map(|id| id.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                        e.verdict.clone(),
                        entry_detail(e),
                    ]
                })
                .collect();
            write!(out, "{}", format_table_rows(headers, &rows))?;

            // The one verdict whose remedy is a different command.
            if abort
                .entries
                .iter()
                .any(|e| !e.candidate_artifact_ids.is_empty())
            {
                writeln!(
                    out,
                    "\nAn ambiguous key names more than one live row — identical bytes can be \
                     ingested at several paths. Release the row you reviewed with \
                     `hort-cli curation waive artifact <artifact_id>`."
                )?;
            }
        }
    }
    Ok(())
}

/// The `DETAIL` cell: whatever the verdict carries that the curator acts
/// on — the candidate ids for an ambiguous key, the actual state for a
/// row a bulk waive does not reach — and `-` for the verdicts that carry
/// nothing.
fn entry_detail(entry: &WaiveEntryReportDto) -> String {
    if !entry.candidate_artifact_ids.is_empty() {
        return format!(
            "candidates: {}",
            entry
                .candidate_artifact_ids
                .iter()
                .map(Uuid::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );
    }
    match &entry.status {
        Some(status) => format!("status {status}"),
        None => "-".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::HttpFailure;

    const ARTIFACT_A: &str = "11111111-1111-1111-1111-111111111111";
    const ARTIFACT_B: &str = "22222222-2222-2222-2222-222222222222";
    const DIGEST: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    fn uuid(s: &str) -> Uuid {
        s.parse().expect("valid uuid")
    }

    fn applied() -> WaiveOutcomeDto {
        WaiveOutcomeDto {
            correlation_id: Uuid::nil(),
            released_artifact_ids: vec![uuid(ARTIFACT_A)],
            already_released_ids: vec![uuid(ARTIFACT_B)],
            failed: vec![],
        }
    }

    fn render_table(outcome: &WaiveOutcomeDto, use_ansi: bool) -> String {
        let mut buf = Vec::new();
        render_outcome(outcome, OutputFormat::Table, &mut buf, use_ansi).expect("renders");
        String::from_utf8(buf).expect("utf8")
    }

    // -- the removed form --------------------------------------------------

    /// The migration message: a caller of the old shape must leave with
    /// the command to run, not with "unrecognized subcommand".
    #[test]
    fn the_removed_positional_form_names_its_replacement() {
        let err = removed_form_error(&[
            ARTIFACT_A.to_string(),
            "--justification".to_string(),
            "risk accepted".to_string(),
        ])
        .to_string();
        assert!(err.contains("was removed"), "says it went away: {err}");
        assert!(
            err.contains(&format!("curation waive artifact {ARTIFACT_A}")),
            "names the replacement with the operator's own id: {err}"
        );
        // The other two modes are named too — a script waiving a list of
        // ids one at a time has a better answer than N invocations.
        assert!(err.contains("waive versions"), "names versions: {err}");
        assert!(err.contains("waive digests"), "names digests: {err}");
        // Not the operator's justification text, which would need
        // re-quoting to be copy-pasteable and would be wrong if it were.
        assert!(
            !err.contains("risk accepted"),
            "does not echo the trailing args: {err}"
        );
    }

    /// A mistyped subcommand lands in the same catch-all, and must not
    /// be told its typo was "the removed positional form".
    #[test]
    fn a_mistyped_target_is_told_the_three_modes_not_a_migration() {
        let err = removed_form_error(&["artifcat".to_string(), ARTIFACT_A.to_string()]).to_string();
        assert!(
            err.contains("no target \"artifcat\""),
            "names what it did not understand: {err}"
        );
        assert!(
            !err.contains("was removed"),
            "a typo is not the migration case: {err}"
        );
        assert!(
            err.contains("waive artifact <artifact_id>")
                && err.contains("waive versions")
                && err.contains("waive digests"),
            "lists the three modes: {err}"
        );
    }

    #[test]
    fn an_empty_capture_still_lists_the_three_modes() {
        let err = removed_form_error(&[]).to_string();
        assert!(err.contains("waive artifact"), "{err}");
        assert!(err.contains("waive versions"), "{err}");
        assert!(err.contains("waive digests"), "{err}");
    }

    // -- the clap tree ------------------------------------------------------

    /// `waive --help` advertises exactly the three addressing modes: the
    /// external-subcommand catch-all must not appear beside them, or the
    /// removed form would read as still supported.
    #[test]
    fn waive_help_advertises_exactly_the_three_addressing_modes() {
        use clap::CommandFactory;
        let mut cmd = crate::Cli::command();
        let waive = cmd
            .find_subcommand_mut("curation")
            .expect("curation is mounted")
            .find_subcommand_mut("waive")
            .expect("waive is mounted");
        let advertised: Vec<String> = waive
            .get_subcommands()
            .map(|s| s.get_name().to_string())
            .filter(|n| n != "help")
            .collect();
        assert_eq!(advertised, vec!["artifact", "versions", "digests"]);

        // Each mode's own help names the mode it addresses by.
        let rendered = waive.render_long_help().to_string();
        for needle in ["artifact", "version", "digest"] {
            assert!(
                rendered.contains(needle),
                "waive --help names {needle}: {rendered}"
            );
        }
    }

    /// The parse half of the removed form: clap routes the old shape to
    /// the catch-all instead of erroring out, which is what lets the CLI
    /// answer with a migration message at all.
    #[test]
    fn the_old_shape_parses_into_the_catch_all() {
        use clap::Parser;
        let cli = crate::Cli::try_parse_from([
            "hort-cli",
            "curation",
            "waive",
            ARTIFACT_A,
            "--justification",
            "t",
        ])
        .expect("the old shape parses rather than erroring");
        let crate::Commands::Curation(args) = cli.cmd.expect("a subcommand") else {
            panic!("expected the curation subcommand");
        };
        let super::super::CurationCommand::Waive(waive) = args.cmd else {
            panic!("expected the waive subcommand");
        };
        match waive.cmd {
            WaiveCommand::Removed(captured) => {
                assert_eq!(captured.first().map(String::as_str), Some(ARTIFACT_A));
            }
            other => panic!("expected the catch-all, got {other:?}"),
        }
    }

    /// The digest list is comma-delimited on both bulk verbs, as
    /// `--versions` already is.
    #[test]
    fn a_comma_separated_digest_list_parses_into_entries() {
        use clap::Parser;
        let cli = crate::Cli::try_parse_from([
            "hort-cli",
            "curation",
            "waive",
            "digests",
            "--repo",
            "oci-proxy",
            "--digests",
            &format!("{DIGEST},sha256:{DIGEST}"),
            "--justification",
            "t",
        ])
        .expect("parses");
        let crate::Commands::Curation(args) = cli.cmd.expect("a subcommand") else {
            panic!("expected the curation subcommand");
        };
        let super::super::CurationCommand::Waive(waive) = args.cmd else {
            panic!("expected the waive subcommand");
        };
        match waive.cmd {
            WaiveCommand::Digests(d) => assert_eq!(d.digests.len(), 2),
            other => panic!("expected digests, got {other:?}"),
        }
    }

    // -- the applied arm ----------------------------------------------------

    /// The acceptance criterion: a converged re-apply must not read as a
    /// release that just happened. Distinct columns AND distinct
    /// sections, each saying when the release happened.
    #[test]
    fn released_and_already_released_are_distinguishable_in_the_table() {
        let out = render_table(&applied(), false);
        assert!(out.contains("RELEASED"), "column header: {out}");
        assert!(out.contains("ALREADY_RELEASED"), "column header: {out}");
        assert!(
            out.contains("RELEASED (1) — released by this call"),
            "the fresh releases say they happened now: {out}"
        );
        assert!(
            out.contains("ALREADY_RELEASED (1) — already Released before this call"),
            "the converged entries say they happened earlier: {out}"
        );
        assert!(
            out.contains("no event appended now"),
            "and that no event was written for them: {out}"
        );
        // Each id appears under its own section, so neither set can be
        // read as the other.
        let released_at = out.find(ARTIFACT_A).expect("released id rendered");
        let already_at = out.find(ARTIFACT_B).expect("already-released id rendered");
        let header_at = out
            .find("ALREADY_RELEASED (1)")
            .expect("already section header");
        assert!(released_at < header_at && header_at < already_at, "{out}");
    }

    #[test]
    fn an_empty_list_renders_no_section_for_itself() {
        let outcome = WaiveOutcomeDto {
            correlation_id: Uuid::nil(),
            released_artifact_ids: vec![uuid(ARTIFACT_A)],
            already_released_ids: vec![],
            failed: vec![],
        };
        let out = render_table(&outcome, false);
        assert!(out.contains("RELEASED (1)"), "{out}");
        assert!(!out.contains("ALREADY_RELEASED ("), "{out}");
        assert!(!out.contains("FAILED ("), "{out}");
    }

    #[test]
    fn a_failed_entry_is_highlighted_and_detailed() {
        let mut outcome = applied();
        outcome.failed.push(FailedBlockEntryDto {
            artifact_id: uuid(ARTIFACT_A),
            error_kind: "conflict".to_string(),
            message: "event-store version conflict".to_string(),
        });
        let out = render_table(&outcome, true);
        assert!(out.contains("FAILED (1)"), "{out}");
        assert!(out.contains("event-store version conflict"), "{out}");
        assert!(out.contains(crate::curation::ANSI_RED), "{out}");

        // Piped: same content, no escape bytes.
        let plain = render_table(&outcome, false);
        assert!(plain.contains("FAILED (1)"), "{plain}");
        assert!(!plain.contains('\x1b'), "no ANSI when piped: {plain:?}");
    }

    /// JSON mode is the server's envelope, verbatim and uncolored —
    /// including the member that distinguishes the two success lists.
    #[test]
    fn json_mode_emits_the_outcome_envelope_verbatim() {
        for use_ansi in [true, false] {
            let mut buf = Vec::new();
            render_outcome(&applied(), OutputFormat::Json, &mut buf, use_ansi).expect("renders");
            let out = String::from_utf8(buf).expect("utf8");
            assert!(!out.contains('\x1b'), "JSON never carries ANSI: {out:?}");
            let parsed: serde_json::Value = serde_json::from_str(&out).expect("valid json");
            let obj = parsed.as_object().expect("object");
            assert_eq!(obj.len(), 4, "exactly the server's members: {out}");
            for key in [
                "correlation_id",
                "released_artifact_ids",
                "already_released_ids",
                "failed",
            ] {
                assert!(obj.contains_key(key), "{key} present: {out}");
            }
        }
    }

    /// The round trip the mirror DTO exists for: the server's body
    /// deserialises and re-serialises to itself.
    #[test]
    fn the_outcome_dto_round_trips_the_servers_body() {
        let body = format!(
            r#"{{"correlation_id":"{ARTIFACT_A}","released_artifact_ids":["{ARTIFACT_B}"],
                 "already_released_ids":[],"failed":[]}}"#
        );
        let parsed: WaiveOutcomeDto = serde_json::from_str(&body).expect("parses");
        let reserialized: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&parsed).expect("serialises"))
                .expect("valid json");
        let original: serde_json::Value = serde_json::from_str(&body).expect("valid json");
        assert_eq!(reserialized, original);
    }

    // -- the aborted arm ----------------------------------------------------

    fn abort_body() -> String {
        format!(
            r#"{{"outcome":"aborted","entries":[
                {{"key":"1.0.0","artifact_id":"{ARTIFACT_A}","verdict":"releasable"}},
                {{"key":"1.0.1","verdict":"unresolvable"}},
                {{"key":"{DIGEST}","verdict":"ambiguous",
                  "candidate_artifact_ids":["{ARTIFACT_A}","{ARTIFACT_B}"]}},
                {{"key":"1.0.2","artifact_id":"{ARTIFACT_B}",
                  "verdict":"state_not_releasable","status":"rejected"}}
              ]}}"#
        )
    }

    fn conflict(body: &str) -> HttpFailure {
        HttpFailure {
            status: reqwest::StatusCode::CONFLICT,
            body: body.to_string(),
        }
    }

    #[test]
    fn the_abort_table_names_every_entry_and_what_stopped_the_batch() {
        let abort = parse_abort(&conflict(&abort_body())).expect("the report is recognised");
        let mut buf = Vec::new();
        render_abort(&abort, OutputFormat::Table, &mut buf, false).expect("renders");
        let out = String::from_utf8(buf).expect("utf8");

        assert!(
            out.contains("BATCH ABORTED — nothing was released."),
            "leads with the fact that no release happened: {out}"
        );
        assert!(
            out.contains("3 of 4 entries cannot be released"),
            "counts only the blocking entries: {out}"
        );
        assert!(
            out.contains("cannot be retracted"),
            "says why the contract is all-or-nothing: {out}"
        );
        // Every entry, the fine one included — the curator must not have
        // to bisect their list.
        for key in ["1.0.0", "1.0.1", "1.0.2", DIGEST] {
            assert!(out.contains(key), "entry {key} listed: {out}");
        }
        assert!(out.contains("releasable"), "{out}");
        assert!(out.contains("unresolvable"), "{out}");
        assert!(
            out.contains(&format!("candidates: {ARTIFACT_A},{ARTIFACT_B}")),
            "the ambiguous entry carries the ids to re-address with: {out}"
        );
        assert!(
            out.contains("status rejected"),
            "the non-releasable entry carries its actual state: {out}"
        );
        assert!(
            out.contains("waive artifact <artifact_id>"),
            "names the command that resolves an ambiguous key: {out}"
        );
    }

    #[test]
    fn the_abort_header_is_red_on_a_tty_and_plain_when_piped() {
        let abort = parse_abort(&conflict(&abort_body())).expect("recognised");
        let mut colored = Vec::new();
        render_abort(&abort, OutputFormat::Table, &mut colored, true).expect("renders");
        assert!(String::from_utf8(colored).expect("utf8").contains('\x1b'));

        let mut plain = Vec::new();
        render_abort(&abort, OutputFormat::Table, &mut plain, false).expect("renders");
        assert!(!String::from_utf8(plain).expect("utf8").contains('\x1b'));
    }

    /// The second half of the "verbatim, both arms" criterion: the
    /// refused body is re-emitted as the server wrote it, absent members
    /// still absent — a client branching on `artifact_id`'s presence
    /// must see what the server said.
    #[test]
    fn json_mode_emits_the_abort_report_verbatim() {
        let abort = parse_abort(&conflict(&abort_body())).expect("recognised");
        let mut buf = Vec::new();
        render_abort(&abort, OutputFormat::Json, &mut buf, true).expect("renders");
        let out = String::from_utf8(buf).expect("utf8");
        assert!(!out.contains('\x1b'), "JSON never carries ANSI: {out:?}");
        let reserialized: serde_json::Value = serde_json::from_str(&out).expect("valid json");
        let original: serde_json::Value = serde_json::from_str(&abort_body()).expect("valid json");
        assert_eq!(reserialized, original);
    }

    #[test]
    fn a_refusal_that_is_not_the_report_is_not_parsed_as_one() {
        // Wrong status, right shape.
        assert!(parse_abort(&HttpFailure {
            status: reqwest::StatusCode::BAD_REQUEST,
            body: abort_body(),
        })
        .is_none());
        // Right status, wrong shape — and the empty-report case, which
        // names nothing to fix.
        assert!(parse_abort(&conflict(r#"{"error":"forbidden"}"#)).is_none());
        assert!(parse_abort(&conflict("not json at all")).is_none());
        assert!(parse_abort(&conflict(r#"{"outcome":"aborted","entries":[]}"#)).is_none());
    }
}
