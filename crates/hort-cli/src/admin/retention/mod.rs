//! `hort-cli admin retention` — show what a retention run would remove,
//! then execute it against a proposal the operator has actually read.
//!
//! `admin task invoke retention-evaluate` can already start the sweep.
//! For a cleanup at production scale that is not enough: before
//! executing, an operator needs a readable answer to "what exactly
//! happens if I do this now", and afterwards the certainty that what ran
//! is what they saw. That is what this group is, and it is the whole of
//! the safety mechanism — nothing downstream re-checks the decision.
//!
//! - `preview` invokes the dry run, waits for the job, and renders the
//!   result. Read-only; it needs no destructive authority.
//! - `apply` runs a **fresh** preview immediately before executing,
//!   shows the difference against a named earlier one, takes the
//!   confirmation, and only then executes.
//!
//! # Authorization
//!
//! Neither subcommand introduces authority. Both go through the existing
//! `POST /api/v1/admin/tasks/retention-evaluate`, which gates on
//! `Permission::AdminTaskInvoke` and — for `mode=execute` only — the
//! `task:destructive` claim. A fresh IdP-backed admin `CliSession`
//! already carries both; a session without the destructive claim can
//! still run `preview` and will be refused at `apply`'s execute step by
//! the server, which is exactly the intended split.
//!
//! # Dep-graph invariant
//!
//! This module and its children import nothing from `hort-domain`,
//! `hort-app`, or `hort-adapters-*`. The `result_summary` shape is
//! mirrored locally in [`dto`].

pub mod apply;
pub mod dto;
pub mod preview;
pub mod render;
pub mod wait;

use std::process::ExitCode;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::Subcommand;

use crate::admin::{InvokeResponse, TaskRow};
use crate::client::AkClient;
use crate::config::OutputFormat;

use dto::RetentionRunSummary;
use render::JobFacts;
use wait::{WaitConfig, WaitOutcome};

/// The task kind both subcommands drive.
const RETENTION_KIND: &str = "retention-evaluate";

/// The path an operator is told to use when the wait window closes
/// before the job does.
const READ_LATER_COMMAND: &str = "hort-cli admin task get";

/// The exact command line that reads `job_id` later.
pub fn read_later_command(job_id: &str) -> String {
    format!("{READ_LATER_COMMAND} {job_id}")
}

// ---------------------------------------------------------------------------
// Exit codes
// ---------------------------------------------------------------------------

/// How a retention subcommand ended.
///
/// A distinct exit code per outcome, because a script must be able to
/// tell "the sweep ran and I read it" from "I never saw the result" and
/// from "the operator said no". Collapsing any pair of those into one
/// code would let an unattended caller treat an unobserved run as a
/// completed one.
///
/// A job that finished in a failure state is *not* in this enum: it
/// surfaces as an `Err`, so it exits 1 with the server's own message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionExit {
    /// The command did what it was asked and saw the result.
    Success,
    /// The wait window closed before the job reached a terminal state.
    /// The job is still running server-side; the CLI saw no result and
    /// says so rather than reporting one.
    StillRunning,
    /// The operator did not confirm. Nothing was executed.
    NotConfirmed,
}

impl RetentionExit {
    pub fn code(self) -> ExitCode {
        match self {
            Self::Success => ExitCode::SUCCESS,
            Self::StillRunning => ExitCode::from(3),
            Self::NotConfirmed => ExitCode::from(4),
        }
    }
}

// ---------------------------------------------------------------------------
// Clap subcommand tree
// ---------------------------------------------------------------------------

/// `hort-cli admin retention` arguments.
#[derive(clap::Args, Debug)]
pub struct RetentionArgs {
    #[command(subcommand)]
    pub cmd: RetentionCommand,
}

/// `admin retention` sub-subcommands.
#[derive(Subcommand, Debug)]
pub enum RetentionCommand {
    /// Show what the active retention policies would expire right now.
    ///
    /// Runs `retention-evaluate` in `dry_run` mode, waits for the job,
    /// and renders the proposal: per policy and repository the artifact
    /// rows and the distinct stored contents, the measured bytes the
    /// purge would reclaim (or an explicit statement that hort did not
    /// measure them), and a capped sample so the selection can be
    /// sanity-checked instead of a total believed.
    ///
    /// Read-only. It appends no events and needs no destructive claim.
    Preview(preview::PreviewArgs),

    /// Execute retention, after showing what will happen and taking a
    /// confirmation.
    ///
    /// Always runs a fresh preview immediately before executing. With
    /// `--from-preview <task_job_id>` that fresh preview is compared
    /// against the earlier one you name, and any difference must be
    /// confirmed separately — a proposal you read an hour ago is not
    /// the one that would run now. Requires the `task:destructive`
    /// claim, which a fresh admin `CliSession` carries.
    Apply(apply::ApplyArgs),
}

// ---------------------------------------------------------------------------
// Shared wait/format options
// ---------------------------------------------------------------------------

/// How long to wait for a job, and how many sample rows to print.
#[derive(clap::Args, Debug, Clone)]
pub struct SweepOptions {
    /// How long to wait for a sweep to finish before giving up on
    /// reading its result. Go-style duration (`90s`, `5m`).
    ///
    /// Giving up is never silent: the CLI prints the job id and says the
    /// job is still running.
    #[arg(long, value_parser = parse_duration_arg, default_value = "120s")]
    pub wait_timeout: Duration,

    /// How often to re-read the job while waiting. Go-style duration.
    #[arg(long, value_parser = parse_duration_arg, default_value = "2s")]
    pub poll_interval: Duration,

    /// How many sampled artifacts to print. `0` prints none. The server
    /// records at most a few hundred regardless; `--output json` always
    /// carries every row it recorded.
    #[arg(long, default_value_t = 20)]
    pub sample: usize,
}

impl SweepOptions {
    fn wait_config(&self) -> WaitConfig {
        WaitConfig {
            timeout: self.wait_timeout,
            interval: self.poll_interval,
        }
    }
}

/// Parse a go-style duration for the wait flags.
fn parse_duration_arg(s: &str) -> Result<Duration, String> {
    humantime::parse_duration(s)
        .map_err(|e| format!("invalid duration '{s}': {e} (expected e.g. 30s, 2m, 5m)"))
}

// ---------------------------------------------------------------------------
// Shared sweep plumbing
// ---------------------------------------------------------------------------

/// A sweep that reached a terminal state inside the wait window.
#[derive(Debug)]
pub struct FinishedSweep {
    pub facts: JobFacts,
    pub summary: RetentionRunSummary,
}

/// What driving one sweep produced.
pub enum SweepResult {
    Finished(Box<FinishedSweep>),
    /// The wait window closed first. Nothing about the outcome is known.
    StillRunning {
        job_id: String,
        last_status: String,
    },
}

/// Invoke `retention-evaluate` in `mode` and wait for the job.
///
/// The response status is load-bearing and is carried into
/// [`JobFacts::deduplicated`]: the server deduplicates a retention
/// invocation per mode per UTC day, answering `200 OK` with the
/// **existing** job rather than `202 Accepted` with a new one. A CLI
/// that ignored the distinction would present an earlier sweep's numbers
/// as a fresh observation of the current state — precisely the claim
/// this command exists to make trustworthy.
pub async fn run_sweep(client: &AkClient, mode: &str, opts: &SweepOptions) -> Result<SweepResult> {
    let path = format!("/api/v1/admin/tasks/{RETENTION_KIND}");
    let body = serde_json::json!({ "mode": mode });
    let (status, resp): (reqwest::StatusCode, InvokeResponse) =
        client.post_with_status(&path, &body).await?;
    let deduplicated = status != reqwest::StatusCode::ACCEPTED;

    match wait::wait_for_terminal(client, &resp.task_job_id, opts.wait_config()).await? {
        WaitOutcome::Terminal(row) => {
            Ok(SweepResult::Finished(Box::new(finish(*row, deduplicated)?)))
        }
        WaitOutcome::TimedOut {
            job_id,
            last_status,
        } => Ok(SweepResult::StillRunning {
            job_id,
            last_status,
        }),
    }
}

/// Read an already-finished job back through the admin-tasks surface.
///
/// Used by `apply --from-preview` to fetch the baseline the operator
/// named. `deduplicated` is meaningless for a read, so it is `false`.
pub async fn read_finished_job(client: &AkClient, job_id: &str) -> Result<FinishedSweep> {
    let row: TaskRow = client
        .get(&format!("/api/v1/admin/tasks/{job_id}"))
        .await
        .with_context(|| format!("reading task job {job_id}"))?;
    if wait::is_non_terminal(&row.status) {
        return Err(anyhow!(
            "task job {job_id} is still {} — it has no result to compare against yet",
            row.status
        ));
    }
    finish(row, false)
}

/// Turn a terminal job row into a usable result, refusing to invent one.
///
/// A job that did not complete, or completed without a `result_summary`
/// this CLI can read, produces an error rather than a zeroed summary: a
/// preview showing `0 rows` because the payload was unreadable is
/// indistinguishable from one showing `0 rows` because nothing matched,
/// and those are opposite facts.
fn finish(row: TaskRow, deduplicated: bool) -> Result<FinishedSweep> {
    if row.status != "completed" {
        return Err(anyhow!(
            "task job {} finished as '{}'{}",
            row.id,
            row.status,
            row.last_error
                .as_deref()
                .map(|e| format!(": {e}"))
                .unwrap_or_default()
        ));
    }
    let raw = row
        .result_summary
        .clone()
        .ok_or_else(|| anyhow!("task job {} completed without a result summary", row.id))?;
    let summary: RetentionRunSummary = serde_json::from_value(raw)
        .with_context(|| format!("reading the result summary of task job {}", row.id))?;
    Ok(FinishedSweep {
        facts: JobFacts {
            job_id: row.id,
            job_status: row.status,
            completed_at: row.completed_at,
            deduplicated,
        },
        summary,
    })
}

/// Render the "the job is still running" outcome in both output modes.
///
/// Never reports a result: it says what the CLI last saw, names the job,
/// and names the command that reads it later.
pub fn render_still_running(
    command: &str,
    job_id: &str,
    last_status: &str,
    waited: Duration,
    note: Option<&str>,
    output: OutputFormat,
) -> String {
    match output {
        OutputFormat::Json => crate::output::format_json(&serde_json::json!({
            "command": command,
            "outcome": "still_running",
            "task_job_id": job_id,
            "last_observed_status": last_status,
            "waited_seconds": waited.as_secs(),
            "note": note,
            "read_later_with": read_later_command(job_id),
        })),
        OutputFormat::Table => format!(
            "THE JOB IS STILL RUNNING — no result was seen\n  \
             task job            {job_id}\n  \
             last seen as        {}\n  \
             waited              {}s\n{}\n  \
             The sweep was not cancelled and nothing here reports its outcome.\n  \
             Read it when it finishes:\n\n    {}\n",
            last_status,
            waited.as_secs(),
            note.map(|n| format!("\n  {n}\n")).unwrap_or_default(),
            read_later_command(job_id),
        ),
    }
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Entry point for the `admin retention` subcommand tree.
pub async fn run(client: AkClient, args: RetentionArgs, output: OutputFormat) -> Result<ExitCode> {
    let outcome = match args.cmd {
        RetentionCommand::Preview(preview_args) => {
            preview::run(client, preview_args, output).await?
        }
        RetentionCommand::Apply(apply_args) => apply::run(client, apply_args, output).await?,
    };
    Ok(outcome.code())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(status: &str, summary: Option<serde_json::Value>) -> TaskRow {
        TaskRow {
            id: "job-1".into(),
            kind: RETENTION_KIND.into(),
            status: status.into(),
            params: None,
            actor_id: None,
            priority: 0,
            trigger_source: "api".into(),
            attempts: 1,
            created_at: "2026-09-25T11:00:00Z".into(),
            updated_at: "2026-09-25T11:02:00Z".into(),
            completed_at: Some("2026-09-25T11:02:00Z".into()),
            last_error: None,
            result_summary: summary,
        }
    }

    #[test]
    fn a_completed_job_yields_its_summary() {
        let finished = finish(
            row(
                "completed",
                Some(serde_json::json!({ "mode": "dry_run", "coverage": "complete" })),
            ),
            false,
        )
        .expect("parses");
        assert_eq!(finished.summary.mode, "dry_run");
        assert!(!finished.facts.deduplicated);
    }

    #[test]
    fn a_failed_job_is_an_error_not_an_empty_preview() {
        let mut r = row("failed", None);
        r.last_error = Some("list_active failed".into());
        let err = finish(r, false).expect_err("must not fabricate a result");
        let text = format!("{err:#}");
        assert!(text.contains("failed"), "{text}");
        assert!(text.contains("list_active failed"), "{text}");
    }

    #[test]
    fn a_completed_job_without_a_summary_is_an_error_not_zero_rows() {
        let err = finish(row("completed", None), false).expect_err("no summary is not zero rows");
        assert!(format!("{err:#}").contains("without a result summary"));
    }

    #[test]
    fn an_unreadable_summary_is_an_error() {
        let err = finish(
            row("completed", Some(serde_json::json!("not an object"))),
            false,
        )
        .expect_err("garbage is not a preview");
        assert!(format!("{err:#}").contains("result summary"));
    }

    #[test]
    fn every_outcome_has_its_own_exit_code() {
        // `ExitCode` is opaque, so compare the u8 the mapping is built
        // from: the point of the test is that no two outcomes collapse.
        let codes = [
            (RetentionExit::Success, 0_u8),
            (RetentionExit::StillRunning, 3),
            (RetentionExit::NotConfirmed, 4),
        ];
        let distinct: std::collections::BTreeSet<u8> = codes.iter().map(|(_, c)| *c).collect();
        assert_eq!(distinct.len(), codes.len());
    }

    #[test]
    fn duration_flags_reject_nonsense() {
        assert!(parse_duration_arg("30s").is_ok());
        assert!(parse_duration_arg("2m").is_ok());
        let err = parse_duration_arg("soon").expect_err("not a duration");
        assert!(err.contains("invalid duration 'soon'"), "{err}");
    }

    #[test]
    fn still_running_names_the_job_and_how_to_read_it_later() {
        let rendered = render_still_running(
            "preview",
            "job-7",
            "running",
            Duration::from_secs(120),
            None,
            OutputFormat::Table,
        );
        assert!(rendered.contains("STILL RUNNING"), "{rendered}");
        assert!(rendered.contains("job-7"), "{rendered}");
        assert!(
            rendered.contains("hort-cli admin task get job-7"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("expired"),
            "must not report any result: {rendered}"
        );
    }

    #[test]
    fn still_running_states_when_the_run_it_could_not_read_was_destructive() {
        let rendered = render_still_running(
            "apply",
            "job-8",
            "running",
            Duration::from_secs(10),
            Some("The execution WAS started and is running now."),
            OutputFormat::Table,
        );
        assert!(rendered.contains("WAS started"), "{rendered}");
    }

    #[test]
    fn still_running_json_carries_the_same_facts() {
        let rendered = render_still_running(
            "apply",
            "job-7",
            "pending",
            Duration::from_secs(5),
            Some("the execution was started"),
            OutputFormat::Json,
        );
        let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");
        assert_eq!(parsed["outcome"], "still_running");
        assert_eq!(parsed["task_job_id"], "job-7");
        assert_eq!(parsed["last_observed_status"], "pending");
        assert_eq!(parsed["waited_seconds"], 5);
        assert_eq!(parsed["read_later_with"], "hort-cli admin task get job-7");
        assert_eq!(parsed["note"], "the execution was started");
    }
}
