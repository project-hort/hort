//! `hort-cli admin retention apply` — execute retention, but not blind.
//!
//! # The shape of the command
//!
//! `apply` always runs a **fresh** dry run immediately before executing.
//! That fresh preview is the thing being confirmed. With
//! `--from-preview <task_job_id>` it is additionally compared against an
//! earlier preview the operator names, and the difference between the
//! two is rendered before the confirmation is taken — because a proposal
//! read an hour ago is not the proposal that would run now. When the two
//! differ the operator is asked **twice**: once to acknowledge that the
//! world moved, and once to execute. The difference is the point of the
//! command, not a warning attached to it.
//!
//! Without `--from-preview` there is nothing to compare against, so no
//! delta is invented: the fresh preview is presented on its own terms.
//!
//! `--yes` skips the questions. It never skips the comparison — the
//! delta is rendered either way, so a scripted run still leaves a record
//! of what the world looked like when it executed.
//!
//! # Where the text goes
//!
//! Prompts go to **stderr**; the rendered result goes to **stdout**.
//! That keeps `--output json` parseable while an interactive operator
//! still sees the question. In JSON mode the human rendering of the
//! proposal is written to stderr too, immediately before the prompt, so
//! the person answering is reading the same proposal the JSON document
//! records.
//!
//! # Authorization
//!
//! Nothing new. The preview half needs only
//! `Permission::AdminTaskInvoke`; the execute half additionally needs the
//! `task:destructive` claim, which the server — not this CLI — enforces.
//! A session without it gets as far as reading the proposal and is
//! refused at the execute step, which is the intended split.

use std::io::{BufRead, Write};

use anyhow::{anyhow, Context, Result};
use serde_json::json;

use crate::client::AkClient;
use crate::config::OutputFormat;
use crate::output::format_json;

use super::dto::ProposalComparison;
use super::preview::{freed_bytes_json, preview_json, proposal_digest_json};
use super::render::{self, PreviewDelta};
use super::{
    read_finished_job, read_later_command, render_still_running, run_sweep, FinishedSweep,
    RetentionExit, SweepOptions, SweepResult,
};

/// The word the operator must type. Deliberately not `y`: this expires
/// artifact records across the whole instance, and the cost of typing
/// three characters is smaller than the cost of a reflex keypress.
const CONFIRM_WORD: &str = "yes";

/// Arguments for `hort-cli admin retention apply`.
#[derive(clap::Args, Debug)]
pub struct ApplyArgs {
    /// Compare against this earlier `retention preview` job before
    /// executing.
    ///
    /// Its `result_summary` is read back through the admin-tasks
    /// surface and compared with a preview run just now. If the two
    /// differ, the difference is shown and a separate confirmation is
    /// required for it.
    #[arg(long, value_name = "TASK_JOB_ID")]
    pub from_preview: Option<String>,

    /// Skip the interactive confirmation. The comparison is still run
    /// and still rendered.
    #[arg(long)]
    pub yes: bool,

    #[command(flatten)]
    pub sweep: SweepOptions,
}

/// Dispatch path: stdout for results, stderr for prompts, stdin for the
/// answer.
pub async fn run(client: AkClient, args: ApplyArgs, output: OutputFormat) -> Result<RetentionExit> {
    run_with_io(
        client,
        args,
        output,
        &mut std::io::stdout(),
        &mut std::io::stderr(),
        &mut std::io::stdin().lock(),
    )
    .await
}

/// Testable variant with all three streams injected.
pub async fn run_with_io(
    client: AkClient,
    args: ApplyArgs,
    output: OutputFormat,
    out: &mut impl Write,
    prompt: &mut impl Write,
    input: &mut impl BufRead,
) -> Result<RetentionExit> {
    // Step 1 — the baseline, if one was named. Validate the id locally
    // so a typo costs no round-trip and cannot be mistaken for "that
    // preview no longer exists".
    let baseline = match args.from_preview.as_deref() {
        None => None,
        Some(raw) => {
            let id = uuid::Uuid::parse_str(raw.trim()).map_err(|_| {
                anyhow!("--from-preview expects a task job id (a UUID); got {raw:?}")
            })?;
            let job = read_finished_job(&client, &id.to_string())
                .await
                .with_context(|| format!("reading the preview named by --from-preview ({id})"))?;
            if job.summary.preview.is_none() {
                return Err(anyhow!(
                    "task job {id} is a '{}' run, not a dry run — there is no proposal in it to \
                     compare against",
                    job.summary.mode
                ));
            }
            Some(job)
        }
    };

    // Step 2 — the fresh preview. This is what gets confirmed, whether
    // or not a baseline was named.
    let fresh = match run_sweep(&client, "dry_run", &args.sweep).await? {
        SweepResult::StillRunning {
            job_id,
            last_status,
        } => {
            write!(
                out,
                "{}",
                render_still_running(
                    "apply",
                    &job_id,
                    &last_status,
                    args.sweep.wait_timeout,
                    Some(
                        "This was the pre-execution preview. Nothing was executed and nothing \
                         has been deleted."
                    ),
                    output,
                )
            )?;
            if matches!(output, OutputFormat::Json) {
                writeln!(out)?;
            }
            return Ok(RetentionExit::StillRunning);
        }
        SweepResult::Finished(finished) => *finished,
    };

    // Step 3 — the comparison. Computed only against a named baseline;
    // with nothing to compare to, no delta is invented.
    let delta = baseline
        .as_ref()
        .map(|b| render::diff(&b.summary, &fresh.summary));

    // Step 4 — render the proposal. In table mode it is the command's
    // output; in JSON mode the final document carries it, so the human
    // copy goes to stderr where the operator will be answering.
    let proposal = render_proposal(baseline.as_ref(), &fresh, delta.as_ref(), args.sweep.sample);
    match output {
        OutputFormat::Table => write!(out, "{proposal}")?,
        OutputFormat::Json => write!(prompt, "{proposal}")?,
    }

    // Step 5 — confirmation. A moved world is confirmed separately from
    // the execution itself: acknowledging that the numbers changed is a
    // different act from authorising the run.
    let world_moved = delta.as_ref().is_some_and(PreviewDelta::changed);
    let mut questions_asked = 0_u32;
    if !args.yes {
        if world_moved {
            questions_asked += 1;
            if !ask(
                prompt,
                input,
                &change_question(
                    delta
                        .as_ref()
                        .expect("world_moved is false without a delta to have moved"),
                ),
            )? {
                return finish_unconfirmed(
                    out,
                    output,
                    baseline.as_ref(),
                    &fresh,
                    delta.as_ref(),
                    questions_asked,
                );
            }
        }
        questions_asked += 1;
        if !ask(prompt, input, &execute_question(&fresh))? {
            return finish_unconfirmed(
                out,
                output,
                baseline.as_ref(),
                &fresh,
                delta.as_ref(),
                questions_asked,
            );
        }
    }

    // Step 6 — execute.
    //
    // A timeout here is not the same event as a timeout on the
    // pre-execution preview: something irreversible was started. Table
    // mode has already printed the proposal above, so the JSON document
    // carries it too — the machine record of a destructive run must not
    // be thinner than the human one.
    let executed = match run_sweep(&client, "execute", &args.sweep).await? {
        SweepResult::StillRunning {
            job_id,
            last_status,
        } => {
            const STARTED: &str = "The execution WAS started and is still running. This is not \
                                   a dry run: read the job to find out what it expired.";
            match output {
                OutputFormat::Table => write!(
                    out,
                    "{}",
                    render_still_running(
                        "apply",
                        &job_id,
                        &last_status,
                        args.sweep.wait_timeout,
                        Some(STARTED),
                        output,
                    )
                )?,
                OutputFormat::Json => {
                    let mut doc = apply_json(
                        baseline.as_ref(),
                        &fresh,
                        delta.as_ref(),
                        questions_asked,
                        args.yes,
                        None,
                    );
                    doc["outcome"] = json!("still_running");
                    doc["confirmation"]["granted"] = json!(true);
                    doc["execution"] = json!({
                        "task_job_id": job_id,
                        "job_status": "still_running",
                        "last_observed_status": last_status,
                        "waited_seconds": args.sweep.wait_timeout.as_secs(),
                        "note": STARTED,
                        "read_later_with": read_later_command(&job_id),
                    });
                    writeln!(out, "{}", format_json(&doc))?;
                }
            }
            return Ok(RetentionExit::StillRunning);
        }
        SweepResult::Finished(finished) => *finished,
    };

    match output {
        OutputFormat::Table => write!(
            out,
            "\n{}",
            render::render_execution(&executed.facts, &executed.summary)
        )?,
        OutputFormat::Json => writeln!(
            out,
            "{}",
            format_json(&apply_json(
                baseline.as_ref(),
                &fresh,
                delta.as_ref(),
                questions_asked,
                args.yes,
                Some(&executed),
            ))
        )?,
    }
    Ok(RetentionExit::Success)
}

/// The question that acknowledges a comparison which did not leave the
/// proposal where the operator last read it.
///
/// It names *what* the comparison found, because the three findings ask
/// for different judgement: rows that moved, figures that moved around
/// rows that did not, and a comparison that could not see the rows at
/// all. Wording all three as "the proposal changed" would be false on
/// two of them — and a prompt an operator learns is sometimes false is a
/// prompt they stop reading.
fn change_question(delta: &PreviewDelta) -> String {
    let finding = match delta.identity() {
        ProposalComparison::Different => {
            "The proposal changed since the preview you named: different artifacts would be \
             expired now."
        }
        ProposalComparison::Same => {
            "The same artifacts would be expired as in the preview you named, but the figures \
             around them moved."
        }
        ProposalComparison::Unreported | ProposalComparison::SchemeMismatch => {
            "This comparison could not check WHICH artifacts would be expired — it compared \
             totals only, and equal totals are not the same artifacts."
        }
    };
    let window = if delta.window_limited() {
        " At least one of the two previews examined only a window of the candidate set, so what \
         was compared is two windows."
    } else {
        ""
    };
    format!("{finding}{window} Type \"yes\" to confirm you have read the difference above: ")
}

/// The question that authorises the run.
///
/// When the server deduplicated the pre-execution preview, the proposal
/// the operator just read is an earlier sweep from the same UTC day
/// replayed, not a measurement of the current state — and the execution
/// about to be authorised *is* fresh. That mismatch is stated in the
/// question itself, not only in the header above it: the prompt is the
/// last thing read before the decision.
fn execute_question(fresh: &FinishedSweep) -> String {
    let rows = render::count(rows_of(fresh));
    if fresh.facts.deduplicated {
        format!(
            "The proposal above is an EARLIER sweep from today, replayed — not a measurement \
             of the state right now. The execution will be fresh. Execute retention anyway, \
             expiring at least {rows} artifact rows? Type \"yes\" to proceed: "
        )
    } else {
        format!("Execute retention now, expiring {rows} artifact rows? Type \"yes\" to proceed: ")
    }
}

/// How many artifact rows the fresh preview proposes to expire.
fn rows_of(sweep: &FinishedSweep) -> u64 {
    sweep.summary.preview.as_ref().map_or(0, |p| p.rows)
}

/// Render everything the operator must read before answering.
fn render_proposal(
    baseline: Option<&FinishedSweep>,
    fresh: &FinishedSweep,
    delta: Option<&PreviewDelta>,
    sample: usize,
) -> String {
    let mut out = render::render_preview(
        "RETENTION APPLY — this is what would be expired, measured just now",
        &fresh.facts,
        &fresh.summary,
        sample,
    );
    match (baseline, delta) {
        (Some(b), Some(d)) => {
            out.push('\n');
            if b.facts.job_id == fresh.facts.job_id {
                out.push_str(
                    "  NOTE  The server handed back the very preview you named rather than \
                     running\n        a new one. The comparison below is therefore a job \
                     against itself and\n        proves nothing about what has changed \
                     since.\n\n",
                );
            }
            out.push_str(&render::render_delta(
                d,
                &b.facts.job_id,
                &fresh.facts.job_id,
            ));
        }
        _ => {
            out.push_str(
                "\nNO BASELINE TO COMPARE AGAINST\n  \
                 No --from-preview was given, so there is no earlier proposal to measure this\n  \
                 one against and none is invented. What is above is the whole of what you are\n  \
                 confirming.\n",
            );
        }
    }
    out
}

/// Ask one question. Anything but the exact confirmation word — an empty
/// line, `y`, EOF from a non-interactive stdin — is a refusal.
fn ask(prompt: &mut impl Write, input: &mut impl BufRead, question: &str) -> Result<bool> {
    write!(prompt, "\n{question}")?;
    prompt.flush()?;
    let mut line = String::new();
    let read = input.read_line(&mut line).context("reading confirmation")?;
    if read == 0 {
        writeln!(
            prompt,
            "\n(no answer — stdin reached end of input; treating that as \"no\")"
        )?;
        return Ok(false);
    }
    Ok(line.trim().eq_ignore_ascii_case(CONFIRM_WORD))
}

/// Report a refusal. Nothing was executed, and the exit code says so.
fn finish_unconfirmed(
    out: &mut impl Write,
    output: OutputFormat,
    baseline: Option<&FinishedSweep>,
    fresh: &FinishedSweep,
    delta: Option<&PreviewDelta>,
    questions_asked: u32,
) -> Result<RetentionExit> {
    match output {
        OutputFormat::Table => write!(
            out,
            "\nNOT CONFIRMED — nothing was executed and nothing has been deleted.\n"
        )?,
        OutputFormat::Json => writeln!(
            out,
            "{}",
            format_json(&apply_json(
                baseline,
                fresh,
                delta,
                questions_asked,
                false,
                None
            ))
        )?,
    }
    Ok(RetentionExit::NotConfirmed)
}

/// The machine-readable record of an `apply`.
pub fn apply_json(
    baseline: Option<&FinishedSweep>,
    fresh: &FinishedSweep,
    delta: Option<&PreviewDelta>,
    questions_asked: u32,
    skipped_with_yes: bool,
    executed: Option<&FinishedSweep>,
) -> serde_json::Value {
    json!({
        "command": "apply",
        "outcome": if executed.is_some() { "executed" } else { "not_confirmed" },
        "baseline": match baseline {
            Some(b) => preview_json("baseline", &b.facts, &b.summary),
            None => json!(null),
        },
        "fresh_preview": preview_json("fresh_preview", &fresh.facts, &fresh.summary),
        "delta": match delta {
            Some(d) => delta_json(d),
            None => json!(null),
        },
        "confirmation": {
            "questions_asked": questions_asked,
            "skipped_with_yes": skipped_with_yes,
            "granted": executed.is_some(),
        },
        "execution": match executed {
            Some(e) => json!({
                "task_job_id": e.facts.job_id,
                "job_status": e.facts.job_status,
                "finished_at": e.facts.completed_at,
                "deduplicated": e.facts.deduplicated,
                "mode": e.summary.mode,
                "coverage": e.summary.coverage,
                "coverage_is_partial": e.summary.coverage_is_partial(),
                "policies": e.summary.policies,
                "evaluated": e.summary.evaluated,
                "artifact_rows_expired": e.summary.expired,
                "already_expired": e.summary.already_expired,
                "skipped_protected": e.summary.skipped_protected,
                "skipped_stale_scan": e.summary.skipped_stale_scan,
                "errors": e.summary.errors,
            }),
            None => json!(null),
        },
    })
}

/// The wire word for a comparison outcome.
///
/// One function for the run-level field and the per-group one, so the
/// two vocabularies cannot drift apart under a consumer that switches on
/// either.
fn comparison_word(comparison: ProposalComparison) -> &'static str {
    match comparison {
        ProposalComparison::Same => "same",
        ProposalComparison::Different => "different",
        ProposalComparison::Unreported => "unreported",
        ProposalComparison::SchemeMismatch => "scheme_mismatch",
    }
}

/// Project the delta. `changed` is the field a script gates on.
///
/// `changed` is fail-closed: it is `true` whenever this comparison did
/// not *establish* that the same rows would be expired, which includes
/// the case where no identity was reported at all. A script that
/// auto-applies on `changed == false` therefore stops when the
/// comparison could not check, which is the only safe reading of a field
/// by that name. `proposal.comparison` is there for a consumer that
/// needs to tell the two apart.
pub fn delta_json(delta: &PreviewDelta) -> serde_json::Value {
    json!({
        "changed": delta.changed(),
        "proposal": {
            "comparison": comparison_word(delta.identity()),
            "window_limited": delta.window_limited(),
            "baseline": proposal_digest_json(delta.baseline_proposal.as_ref()),
            "fresh": proposal_digest_json(delta.fresh_proposal.as_ref()),
        },
        "artifact_rows": { "baseline": delta.baseline_rows, "fresh": delta.fresh_rows },
        "distinct_contents": {
            "baseline": delta.baseline_distinct,
            "fresh": delta.fresh_distinct,
        },
        "freed_bytes": {
            "baseline": freed_bytes_json(&delta.baseline_bytes),
            "fresh": freed_bytes_json(&delta.fresh_bytes),
        },
        "coverage": { "baseline": delta.baseline_coverage, "fresh": delta.fresh_coverage },
        "groups": delta.groups.iter().map(|g| json!({
            "policy_id": g.policy_id,
            "policy_name": g.policy_name,
            "repository_id": g.repository_id,
            "repository_key": g.repository_key,
            "changed": g.changed(),
            "proposal_comparison": g.identity.map(comparison_word),
            "baseline": g.baseline.map(|(rows, distinct)| json!({
                "artifact_rows": rows, "distinct_contents": distinct,
            })),
            "fresh": g.fresh.map(|(rows, distinct)| json!({
                "artifact_rows": rows, "distinct_contents": distinct,
            })),
        })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::admin::retention::dto::{
        FreedBytes, PreviewBody, PreviewGroup, ProposalDigest, RetentionRunSummary,
        OMITTED_BYTES_REASON,
    };
    use crate::admin::retention::render::JobFacts;

    /// A stand-in proposal identity, seeded so that two fixtures with
    /// the same rows name the same artifacts and two with different rows
    /// do not — which is what the server's digest would say about them.
    fn digest(seed: &str) -> Option<ProposalDigest> {
        Some(ProposalDigest {
            scheme: "policy-artifact-pairs-v1".into(),
            value: seed.to_string(),
        })
    }

    fn sweep(job: &str, rows: u64) -> FinishedSweep {
        FinishedSweep {
            facts: JobFacts {
                job_id: job.into(),
                job_status: "completed".into(),
                completed_at: Some("2026-09-25T11:02:14Z".into()),
                deduplicated: false,
            },
            summary: RetentionRunSummary {
                mode: "dry_run".into(),
                coverage: "complete".into(),
                policies: 1,
                evaluated: 100,
                expired: rows,
                preview: Some(PreviewBody {
                    rows,
                    distinct_contents: rows,
                    freed_bytes: FreedBytes::Exact { bytes: rows * 10 },
                    proposal_digest: digest(&format!("run/{rows}")),
                    groups: vec![PreviewGroup {
                        policy_id: "p1".into(),
                        policy_name: "npm-90d".into(),
                        repository_id: "r1".into(),
                        repository_key: "npm-proxy".into(),
                        rows,
                        distinct_contents: rows,
                        proposal_digest: digest(&format!("npm-proxy/{rows}")),
                    }],
                    sample: vec![],
                    sample_limit: Some(500),
                }),
                ..RetentionRunSummary::default()
            },
        }
    }

    #[test]
    fn only_the_exact_word_confirms() {
        for answer in ["yes\n", "YES\n", "  Yes  \n"] {
            let mut prompt = Vec::new();
            let mut input = Cursor::new(answer.as_bytes().to_vec());
            assert!(
                ask(&mut prompt, &mut input, "q: ").expect("asks"),
                "{answer:?}"
            );
        }
        for answer in ["y\n", "\n", "no\n", "yes please\n"] {
            let mut prompt = Vec::new();
            let mut input = Cursor::new(answer.as_bytes().to_vec());
            assert!(
                !ask(&mut prompt, &mut input, "q: ").expect("asks"),
                "{answer:?}"
            );
        }
    }

    #[test]
    fn end_of_input_is_a_refusal_and_says_so() {
        let mut prompt = Vec::new();
        let mut input = Cursor::new(Vec::new());
        assert!(!ask(&mut prompt, &mut input, "q: ").expect("asks"));
        let text = String::from_utf8(prompt).expect("utf8");
        assert!(text.contains("treating that as \"no\""), "{text}");
    }

    #[test]
    fn with_no_baseline_no_delta_is_invented() {
        let fresh = sweep("fresh-1", 10);
        let text = render_proposal(None, &fresh, None, 0);
        assert!(text.contains("NO BASELINE TO COMPARE AGAINST"), "{text}");
        assert!(!text.contains("CHANGED SINCE"), "{text}");
    }

    #[test]
    fn a_differing_baseline_renders_the_difference() {
        let baseline = sweep("base-1", 10);
        let fresh = sweep("fresh-1", 25);
        let delta = render::diff(&baseline.summary, &fresh.summary);
        assert!(delta.changed());
        let text = render_proposal(Some(&baseline), &fresh, Some(&delta), 0);
        assert!(text.contains("WHAT CHANGED SINCE"), "{text}");
        assert!(text.contains("+15"), "{text}");
    }

    #[test]
    fn a_baseline_the_server_deduplicated_to_says_the_comparison_proves_nothing() {
        let baseline = sweep("same-1", 10);
        let fresh = sweep("same-1", 10);
        let delta = render::diff(&baseline.summary, &fresh.summary);
        let text = render_proposal(Some(&baseline), &fresh, Some(&delta), 0);
        // Collapse the wrap before matching: the note's wording is the
        // property, its line breaks are not.
        let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            flat.contains("handed back the very preview you named"),
            "{text}"
        );
        assert!(
            flat.contains("proves nothing about what has changed since"),
            "{text}"
        );
    }

    #[test]
    fn delta_json_exposes_changed_and_every_moved_group() {
        let baseline = sweep("base-1", 10);
        let fresh = sweep("fresh-1", 25);
        let doc = delta_json(&render::diff(&baseline.summary, &fresh.summary));
        assert_eq!(doc["changed"], true);
        assert_eq!(doc["artifact_rows"]["baseline"], 10);
        assert_eq!(doc["artifact_rows"]["fresh"], 25);
        assert_eq!(doc["groups"][0]["changed"], true);
        assert_eq!(doc["groups"][0]["repository_key"], "npm-proxy");
        assert_eq!(doc["groups"][0]["baseline"]["artifact_rows"], 10);
        assert_eq!(doc["groups"][0]["fresh"]["artifact_rows"], 25);
    }

    #[test]
    fn delta_json_marks_an_unmeasured_side_unmeasured() {
        let baseline = sweep("base-1", 10);
        let mut fresh = sweep("fresh-1", 10);
        fresh.summary.preview.as_mut().expect("preview").freed_bytes = FreedBytes::Omitted {
            reason: OMITTED_BYTES_REASON.into(),
        };
        let doc = delta_json(&render::diff(&baseline.summary, &fresh.summary));
        assert_eq!(doc["changed"], true);
        assert_eq!(doc["freed_bytes"]["baseline"]["measured"], true);
        assert_eq!(doc["freed_bytes"]["fresh"]["measured"], false);
        assert!(doc["freed_bytes"]["fresh"]["bytes"].is_null());
    }

    #[test]
    fn apply_json_records_a_refusal_as_not_confirmed() {
        let fresh = sweep("fresh-1", 10);
        let doc = apply_json(None, &fresh, None, 1, false, None);
        assert_eq!(doc["outcome"], "not_confirmed");
        assert_eq!(doc["confirmation"]["granted"], false);
        assert_eq!(doc["confirmation"]["questions_asked"], 1);
        assert!(doc["execution"].is_null());
    }

    /// A refusal is a record of a decision, so it keeps what the decision
    /// was made against — both previews and the delta between them.
    #[test]
    fn a_refusal_record_keeps_the_baseline_it_was_compared_against() {
        let baseline = sweep("base-1", 10);
        let fresh = sweep("fresh-1", 25);
        let delta = render::diff(&baseline.summary, &fresh.summary);
        let doc = apply_json(Some(&baseline), &fresh, Some(&delta), 2, false, None);
        assert_eq!(doc["outcome"], "not_confirmed");
        assert_eq!(doc["baseline"]["task_job_id"], "base-1");
        assert_eq!(doc["delta"]["changed"], true);
        assert!(doc["execution"].is_null());
    }

    #[test]
    fn apply_json_records_an_execution_and_how_it_was_authorised() {
        let baseline = sweep("base-1", 10);
        let fresh = sweep("fresh-1", 25);
        let mut executed = sweep("exec-1", 0);
        executed.summary.mode = "execute".into();
        executed.summary.expired = 25;
        executed.summary.preview = None;
        let delta = render::diff(&baseline.summary, &fresh.summary);
        let doc = apply_json(
            Some(&baseline),
            &fresh,
            Some(&delta),
            0,
            true,
            Some(&executed),
        );
        assert_eq!(doc["outcome"], "executed");
        assert_eq!(doc["confirmation"]["skipped_with_yes"], true);
        assert_eq!(doc["confirmation"]["questions_asked"], 0);
        assert_eq!(doc["delta"]["changed"], true);
        assert_eq!(doc["execution"]["artifact_rows_expired"], 25);
        assert_eq!(doc["execution"]["mode"], "execute");
        assert_eq!(doc["baseline"]["task_job_id"], "base-1");
        assert_eq!(doc["fresh_preview"]["task_job_id"], "fresh-1");
    }

    /// A substitution the totals hide still reaches the question, and
    /// the question says what moved rather than leaving the operator to
    /// find it in the table.
    #[test]
    fn the_change_question_names_a_substituted_proposal_as_different_artifacts() {
        let baseline = sweep("base-1", 10);
        let mut fresh = sweep("fresh-1", 10);
        {
            let preview = fresh.summary.preview.as_mut().expect("preview");
            preview.proposal_digest = digest("run/after-the-substitution");
            preview.groups[0].proposal_digest = digest("npm-proxy/after-the-substitution");
        }
        let delta = render::diff(&baseline.summary, &fresh.summary);
        assert!(delta.changed(), "the confirmation is demanded");

        let q = change_question(&delta);
        assert!(q.contains("changed since the preview you named"), "{q}");
        assert!(
            q.contains("different artifacts would be expired now"),
            "{q}"
        );
        assert!(
            !q.contains("window"),
            "complete coverage carries no caveat: {q}"
        );
        assert!(q.contains(r#"Type "yes""#), "{q}");
    }

    /// Figures moving around an unchanged set is a real change, and
    /// calling it "the proposal changed" would be false — a prompt an
    /// operator learns is sometimes false is a prompt they stop reading.
    #[test]
    fn the_change_question_does_not_claim_the_artifacts_moved_when_only_figures_did() {
        let baseline = sweep("base-1", 10);
        let mut fresh = sweep("fresh-1", 10);
        fresh.summary.preview.as_mut().expect("preview").freed_bytes =
            FreedBytes::Exact { bytes: 4_096 };
        let delta = render::diff(&baseline.summary, &fresh.summary);

        let q = change_question(&delta);
        assert!(q.contains("The same artifacts would be expired"), "{q}");
        assert!(q.contains("the figures around them moved"), "{q}");
    }

    #[test]
    fn the_change_question_says_when_it_could_not_check_which_artifacts() {
        let baseline = sweep("base-1", 10);
        let mut fresh = sweep("fresh-1", 10);
        fresh
            .summary
            .preview
            .as_mut()
            .expect("preview")
            .proposal_digest = None;
        let delta = render::diff(&baseline.summary, &fresh.summary);
        assert!(
            delta.changed(),
            "a comparison that could not check still demands the confirmation",
        );

        let q = change_question(&delta);
        assert!(q.contains("could not check WHICH artifacts"), "{q}");
        assert!(q.contains("equal totals are not the same artifacts"), "{q}");
    }

    #[test]
    fn the_change_question_says_when_it_compared_two_windows() {
        let mut baseline = sweep("base-1", 10);
        baseline.summary.coverage = "partial".into();
        let mut fresh = sweep("fresh-1", 10);
        fresh.summary.coverage = "partial".into();
        fresh
            .summary
            .preview
            .as_mut()
            .expect("preview")
            .proposal_digest = digest("run/a-different-window");
        let delta = render::diff(&baseline.summary, &fresh.summary);

        let q = change_question(&delta);
        assert!(q.contains("only a window of the candidate set"), "{q}");
        assert!(q.contains("what was compared is two windows"), "{q}");
    }

    /// `changed` is what a script gates an unattended apply on, so it
    /// has to be false only when sameness was actually established.
    #[test]
    fn delta_json_exposes_the_identity_beside_the_fail_closed_changed_flag() {
        let baseline = sweep("base-1", 10);
        let mut fresh = sweep("fresh-1", 10);
        {
            let preview = fresh.summary.preview.as_mut().expect("preview");
            preview.proposal_digest = digest("run/after-the-substitution");
            preview.groups[0].proposal_digest = digest("npm-proxy/after-the-substitution");
        }
        let doc = delta_json(&render::diff(&baseline.summary, &fresh.summary));

        assert_eq!(doc["changed"], true);
        assert_eq!(doc["proposal"]["comparison"], "different");
        assert_eq!(doc["proposal"]["window_limited"], false);
        assert_eq!(doc["proposal"]["baseline"]["value"], "run/10");
        assert_eq!(
            doc["proposal"]["fresh"]["value"],
            "run/after-the-substitution"
        );
        assert_eq!(
            doc["artifact_rows"]["baseline"],
            doc["artifact_rows"]["fresh"]
        );
        assert_eq!(doc["groups"][0]["proposal_comparison"], "different");
        assert_eq!(doc["groups"][0]["changed"], true);
    }

    #[test]
    fn delta_json_reports_an_undecidable_identity_as_such_and_still_as_changed() {
        let baseline = sweep("base-1", 10);
        let mut fresh = sweep("fresh-1", 10);
        {
            let preview = fresh.summary.preview.as_mut().expect("preview");
            preview.proposal_digest = None;
            preview.groups[0].proposal_digest = None;
        }
        let doc = delta_json(&render::diff(&baseline.summary, &fresh.summary));

        assert_eq!(doc["proposal"]["comparison"], "unreported");
        assert!(doc["proposal"]["fresh"].is_null());
        assert_eq!(
            doc["changed"], true,
            "a script that auto-applies on !changed must stop when the check did not run",
        );
        assert_eq!(doc["groups"][0]["proposal_comparison"], "unreported");
        assert_eq!(
            doc["groups"][0]["changed"], false,
            "an undecidable identity is not this group moving",
        );
    }

    #[test]
    fn delta_json_marks_two_identities_from_different_schemes_as_not_comparable() {
        let baseline = sweep("base-1", 10);
        let mut fresh = sweep("fresh-1", 10);
        fresh
            .summary
            .preview
            .as_mut()
            .expect("preview")
            .proposal_digest = Some(ProposalDigest {
            scheme: "policy-artifact-pairs-v2".into(),
            value: "run/10".into(),
        });
        let doc = delta_json(&render::diff(&baseline.summary, &fresh.summary));
        assert_eq!(doc["proposal"]["comparison"], "scheme_mismatch");
        assert_eq!(doc["changed"], true);
    }

    #[test]
    fn delta_json_reports_a_group_present_on_one_side_only_with_no_verdict() {
        let baseline = sweep("base-1", 10);
        let mut fresh = sweep("fresh-1", 10);
        fresh
            .summary
            .preview
            .as_mut()
            .expect("preview")
            .groups
            .clear();
        let doc = delta_json(&render::diff(&baseline.summary, &fresh.summary));
        assert!(doc["groups"][0]["proposal_comparison"].is_null());
        assert_eq!(doc["groups"][0]["changed"], true);
    }

    #[test]
    fn the_execute_question_names_the_row_count() {
        let q = execute_question(&sweep("fresh-1", 51_907));
        assert!(q.contains("51,907 artifact rows"), "{q}");
        assert!(q.contains(r#"Type "yes""#), "{q}");
    }

    #[test]
    fn the_execute_question_warns_when_the_proposal_is_a_replayed_sweep() {
        let mut fresh = sweep("fresh-1", 10);
        fresh.facts.deduplicated = true;
        let q = execute_question(&fresh);
        assert!(q.contains("EARLIER sweep from today"), "{q}");
        assert!(q.contains("The execution will be fresh"), "{q}");
        assert!(q.contains("at least 10 artifact rows"), "{q}");
    }

    #[test]
    fn rows_of_a_summary_without_a_preview_is_zero() {
        let mut s = sweep("x", 5);
        s.summary.preview = None;
        assert_eq!(rows_of(&s), 0);
    }

    #[test]
    fn the_confirmation_word_is_the_full_word() {
        assert_eq!(CONFIRM_WORD, "yes");
    }
}
