//! `hort-cli admin retention preview` — what would retention take, right
//! now, if it ran?
//!
//! Invokes `retention-evaluate` with `{"mode": "dry_run"}`, waits for the
//! job to reach a terminal state, and renders its `result_summary`.
//!
//! The dry run appends no events and deletes nothing, so this subcommand
//! needs `Permission::AdminTaskInvoke` and nothing further — in
//! particular **not** the `task:destructive` claim, which the server
//! requires only for `mode=execute`. An operator can therefore read the
//! proposal with an ordinary admin session and needs the destructive
//! authority only at the moment of acting on it.

use std::io::Write;

use anyhow::Result;
use serde_json::json;

use crate::client::AkClient;
use crate::config::OutputFormat;
use crate::output::format_json;

use super::dto::{FreedBytes, ProposalDigest, RetentionRunSummary};
use super::render::JobFacts;
use super::{render, render_still_running, run_sweep, RetentionExit, SweepOptions, SweepResult};

/// Arguments for `hort-cli admin retention preview`.
#[derive(clap::Args, Debug)]
pub struct PreviewArgs {
    #[command(flatten)]
    pub sweep: SweepOptions,
}

/// Dispatch path. Writes to stdout.
pub async fn run(
    client: AkClient,
    args: PreviewArgs,
    output: OutputFormat,
) -> Result<RetentionExit> {
    run_with_output(client, args, output, &mut std::io::stdout()).await
}

/// Testable variant writing to an arbitrary `Write`.
pub async fn run_with_output(
    client: AkClient,
    args: PreviewArgs,
    output: OutputFormat,
    out: &mut impl Write,
) -> Result<RetentionExit> {
    match run_sweep(&client, "dry_run", &args.sweep).await? {
        SweepResult::StillRunning {
            job_id,
            last_status,
        } => {
            write!(
                out,
                "{}",
                render_still_running(
                    "preview",
                    &job_id,
                    &last_status,
                    args.sweep.wait_timeout,
                    None,
                    output,
                )
            )?;
            if matches!(output, OutputFormat::Json) {
                writeln!(out)?;
            }
            Ok(RetentionExit::StillRunning)
        }
        SweepResult::Finished(finished) => {
            match output {
                OutputFormat::Json => writeln!(
                    out,
                    "{}",
                    format_json(&preview_json("preview", &finished.facts, &finished.summary))
                )?,
                OutputFormat::Table => write!(
                    out,
                    "{}",
                    render::render_preview(
                        "RETENTION PREVIEW — a dry run; nothing has been deleted",
                        &finished.facts,
                        &finished.summary,
                        args.sweep.sample,
                    )
                )?,
            }
            Ok(RetentionExit::Success)
        }
    }
}

/// Machine-readable projection carrying exactly what the human output
/// carries.
///
/// `freed_bytes.measured` is the boolean a script must branch on: a
/// consumer that reads `bytes` without it would treat an unmeasured run
/// as zero bytes, which is the same misreading the human rendering goes
/// out of its way to prevent. The row counts are named `artifact_rows`
/// rather than `rows` for the same reason the human output labels them —
/// so a machine consumer cannot casually sum them as a size either.
pub fn preview_json(
    command: &str,
    facts: &JobFacts,
    summary: &RetentionRunSummary,
) -> serde_json::Value {
    let mut doc = json!({
        "command": command,
        "outcome": "completed",
        "task_job_id": facts.job_id,
        "job_status": facts.job_status,
        "finished_at": facts.completed_at,
        "deduplicated": facts.deduplicated,
        "mode": summary.mode,
        "coverage": summary.coverage,
        "coverage_is_partial": summary.coverage_is_partial(),
        "sweep": {
            "policies": summary.policies,
            "evaluated": summary.evaluated,
            "matched": summary.expired,
            "already_expired": summary.already_expired,
            "skipped_protected": summary.skipped_protected,
            "skipped_stale_scan": summary.skipped_stale_scan,
            "errors": summary.errors,
        },
    });

    let Some(preview) = summary.preview.as_ref() else {
        doc["preview_present"] = json!(false);
        return doc;
    };
    doc["preview_present"] = json!(true);
    doc["totals"] = json!({
        "artifact_rows": preview.rows,
        "distinct_contents": preview.distinct_contents,
        "freed_bytes": freed_bytes_json(&preview.freed_bytes),
    });
    doc["proposal_digest"] = proposal_digest_json(preview.proposal_digest.as_ref());
    doc["groups"] = json!(preview
        .groups
        .iter()
        .map(|g| json!({
            "policy_id": g.policy_id,
            "policy_name": g.policy_name,
            "repository_id": g.repository_id,
            "repository_key": g.repository_key,
            "artifact_rows": g.rows,
            "distinct_contents": g.distinct_contents,
            "proposal_digest": proposal_digest_json(g.proposal_digest.as_ref()),
        }))
        .collect::<Vec<_>>());
    doc["sample"] = json!(preview
        .sample
        .iter()
        .map(|row| json!({
            "artifact_id": row.artifact_id,
            "policy_id": row.policy_id,
            "repository_id": row.repository_id,
            "repository_key": row.repository_key,
            "name": row.name,
            "version": row.version,
            "age_seconds": row.age_seconds,
        }))
        .collect::<Vec<_>>());
    doc["sample_limit"] = json!(preview.sample_limit);
    doc
}

/// Project the identity of the proposed rows, or an explicit `null`.
///
/// `null` is the whole point of the shape: a consumer comparing two
/// previews on this field must be able to tell "these name different
/// rows" from "this server did not say which rows it names". Collapsing
/// the second into an empty string would let a script compare two blanks
/// and conclude the proposals agree. The `scheme` half travels with the
/// value because two digests are comparable only under the same scheme.
pub fn proposal_digest_json(digest: Option<&ProposalDigest>) -> serde_json::Value {
    match digest.filter(|d| d.is_usable()) {
        Some(d) => json!({ "scheme": d.scheme, "value": d.value }),
        None => json!(null),
    }
}

/// Project the byte accounting so no consumer can read an unmeasured run
/// as zero.
pub fn freed_bytes_json(freed: &FreedBytes) -> serde_json::Value {
    match freed {
        FreedBytes::Exact { bytes } => json!({
            "status": "exact",
            "measured": true,
            "bytes": bytes,
        }),
        FreedBytes::Omitted { .. } | FreedBytes::Unrecognised => json!({
            "status": if matches!(freed, FreedBytes::Omitted { .. }) {
                "omitted"
            } else {
                "unrecognised"
            },
            "measured": false,
            "reason": freed.omission_reason(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::retention::dto::{
        PreviewBody, PreviewGroup, PreviewSampleRow, OMITTED_BYTES_REASON,
    };

    fn facts() -> JobFacts {
        JobFacts {
            job_id: "job-9".into(),
            job_status: "completed".into(),
            completed_at: Some("2026-09-25T11:02:14Z".into()),
            deduplicated: false,
        }
    }

    fn summary(freed: FreedBytes) -> RetentionRunSummary {
        RetentionRunSummary {
            mode: "dry_run".into(),
            coverage: "partial".into(),
            policies: 2,
            evaluated: 1_200,
            expired: 812,
            preview: Some(PreviewBody {
                rows: 812,
                distinct_contents: 634,
                freed_bytes: freed,
                proposal_digest: Some(ProposalDigest {
                    scheme: "policy-artifact-pairs-v1".into(),
                    value: "run-abc".into(),
                }),
                groups: vec![PreviewGroup {
                    policy_id: "p1".into(),
                    policy_name: "npm-90d".into(),
                    repository_id: "r1".into(),
                    repository_key: "npm-proxy".into(),
                    rows: 812,
                    distinct_contents: 634,
                    proposal_digest: Some(ProposalDigest {
                        scheme: "policy-artifact-pairs-v1".into(),
                        value: "group-abc".into(),
                    }),
                }],
                sample: vec![PreviewSampleRow {
                    artifact_id: "a1".into(),
                    policy_id: "p1".into(),
                    repository_id: "r1".into(),
                    repository_key: "npm-proxy".into(),
                    name: "left-pad".into(),
                    version: Some("1.3.0".into()),
                    age_seconds: 98_765,
                }],
                sample_limit: Some(500),
            }),
            ..RetentionRunSummary::default()
        }
    }

    #[test]
    fn json_carries_the_coverage_flag_and_the_repository_key() {
        let doc = preview_json(
            "preview",
            &facts(),
            &summary(FreedBytes::Exact { bytes: 7 }),
        );
        assert_eq!(doc["coverage"], "partial");
        assert_eq!(doc["coverage_is_partial"], true);
        assert_eq!(doc["groups"][0]["repository_key"], "npm-proxy");
        assert_eq!(doc["groups"][0]["repository_id"], "r1");
        assert_eq!(doc["sample"][0]["repository_key"], "npm-proxy");
        assert_eq!(doc["totals"]["artifact_rows"], 812);
        assert_eq!(doc["sample_limit"], 500);
    }

    /// A machine consumer gets the same identity the human rendering
    /// decides on, so a script can compare two previews on which rows
    /// they name rather than on how many.
    #[test]
    fn json_carries_the_identity_of_the_proposed_rows_at_both_levels() {
        let doc = preview_json(
            "preview",
            &facts(),
            &summary(FreedBytes::Exact { bytes: 7 }),
        );
        assert_eq!(doc["proposal_digest"]["scheme"], "policy-artifact-pairs-v1");
        assert_eq!(doc["proposal_digest"]["value"], "run-abc");
        assert_eq!(doc["groups"][0]["proposal_digest"]["value"], "group-abc");
    }

    /// `null`, never a blank: a consumer must be able to tell "names
    /// different rows" from "did not say which rows", and two blanks
    /// comparing equal would manufacture the first answer out of the
    /// second.
    #[test]
    fn json_reports_an_absent_or_half_present_identity_as_null() {
        let mut s = summary(FreedBytes::Exact { bytes: 7 });
        {
            let preview = s.preview.as_mut().expect("preview");
            preview.proposal_digest = None;
            preview.groups[0].proposal_digest = Some(ProposalDigest {
                scheme: "policy-artifact-pairs-v1".into(),
                value: String::new(),
            });
        }
        let doc = preview_json("preview", &facts(), &s);
        assert!(doc["proposal_digest"].is_null());
        assert!(
            doc["groups"][0]["proposal_digest"].is_null(),
            "half a digest decides nothing and is reported as none",
        );
    }

    #[test]
    fn json_marks_a_measured_size_as_measured() {
        let doc = preview_json(
            "preview",
            &facts(),
            &summary(FreedBytes::Exact { bytes: 4_096 }),
        );
        assert_eq!(doc["totals"]["freed_bytes"]["measured"], true);
        assert_eq!(doc["totals"]["freed_bytes"]["bytes"], 4_096);
    }

    #[test]
    fn json_omission_carries_the_reason_and_no_byte_field_at_all() {
        let doc = preview_json(
            "preview",
            &facts(),
            &summary(FreedBytes::Omitted {
                reason: OMITTED_BYTES_REASON.into(),
            }),
        );
        let freed = &doc["totals"]["freed_bytes"];
        assert_eq!(freed["status"], "omitted");
        assert_eq!(freed["measured"], false);
        assert!(
            freed["bytes"].is_null(),
            "an unmeasured run must expose no byte figure at all: {freed}"
        );
        assert_eq!(
            freed["reason"].as_str().expect("a reason"),
            OMITTED_BYTES_REASON,
            "the reason is the server's, carried through untouched",
        );
    }

    #[test]
    fn json_marks_an_unknown_status_unmeasured_too() {
        let doc = preview_json("preview", &facts(), &summary(FreedBytes::Unrecognised));
        assert_eq!(doc["totals"]["freed_bytes"]["status"], "unrecognised");
        assert_eq!(doc["totals"]["freed_bytes"]["measured"], false);
        assert!(doc["totals"]["freed_bytes"]["bytes"].is_null());
    }

    #[test]
    fn json_for_a_summary_without_a_preview_says_so_rather_than_emitting_zeroes() {
        let doc = preview_json(
            "preview",
            &facts(),
            &RetentionRunSummary {
                mode: "execute".into(),
                coverage: "complete".into(),
                ..RetentionRunSummary::default()
            },
        );
        assert_eq!(doc["preview_present"], false);
        assert!(doc["totals"].is_null());
    }

    #[test]
    fn json_reports_a_deduplicated_job() {
        let mut f = facts();
        f.deduplicated = true;
        let doc = preview_json("preview", &f, &summary(FreedBytes::Exact { bytes: 1 }));
        assert_eq!(doc["deduplicated"], true);
    }
}
