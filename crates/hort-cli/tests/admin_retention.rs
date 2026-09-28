//! Integration tests for `hort-cli admin retention {preview, apply}`.
//!
//! These drive the real command bodies against a `mockito` server, so
//! the request shapes (`{"mode":"dry_run"}` vs `{"mode":"execute"}`),
//! the job polling, the confirmation flow and the rendered text are all
//! exercised end to end. The text is the deliverable here: this is the
//! surface an operator reads before deleting content, so several tests
//! assert on what the output says rather than only on what it does.
//!
//! No env-lock is needed: every test builds its `AkClient` from an
//! explicit `EffectiveConfig` and touches no `HORT_*` variable.

use std::io::Cursor;
use std::time::Duration;

use mockito::{Matcher, Server, ServerGuard};

use hort_cli::admin::retention::apply::{self, ApplyArgs};
use hort_cli::admin::retention::preview::{self, PreviewArgs};
use hort_cli::admin::retention::{RetentionExit, SweepOptions};
use hort_cli::client::AkClient;
use hort_cli::config::{EffectiveConfig, OutputFormat};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const DRY_RUN_JOB: &str = "11111111-1111-1111-1111-111111111111";
const EXECUTE_JOB: &str = "22222222-2222-2222-2222-222222222222";
const BASELINE_JOB: &str = "33333333-3333-3333-3333-333333333333";
const NPM_REPO_UUID: &str = "9f1d7c2e-4b3a-4f18-8c7d-0a5e6b4c3d21";
const PYPI_REPO_UUID: &str = "7c0b5a44-2e19-4d6f-9a8b-1f2e3d4c5b6a";

/// A `freed_bytes.omitted.reason` in the shape the server actually sends
/// (`bound_omission_reason` in the `retention-evaluate` task handler):
/// which simulation ceiling stopped the exact accounting, what it is set
/// to, and what this run presented to it. The CLI never matches on this
/// text — it passes the server's words through — so the value is
/// illustrative and the assertions check shape, not wording.
const OMITTED_BYTES_REASON: &str =
    "exact byte accounting is bounded at 128000 reclaimable content targets; this run reached at least 128001. Narrow the sweep's scope — fewer repositories, or a predicate that matches fewer artifacts — to bring it under the bound.";

fn test_client(server_url: &str) -> AkClient {
    let cfg = EffectiveConfig {
        server: url::Url::parse(server_url).expect("valid url"),
        token: "test-token".to_string(),
        default_format: OutputFormat::Table,
    };
    AkClient::new(&cfg).expect("client builds")
}

fn opts() -> SweepOptions {
    SweepOptions {
        wait_timeout: Duration::from_secs(5),
        poll_interval: Duration::from_millis(5),
        sample: 20,
    }
}

/// The scheme the shipped `retention-evaluate` handler tags every
/// proposal digest with. Two digests are comparable only under the same
/// one, so the fixtures carry the real tag rather than a placeholder.
const PROPOSAL_SCHEME: &str = "policy-artifact-pairs-v1";

/// A stand-in proposal identity. The value is a readable seed rather
/// than 64 hex characters: the CLI compares these for equality and never
/// parses one, so a real digest would only make the fixtures harder to
/// read.
fn digest(seed: &str) -> serde_json::Value {
    serde_json::json!({ "scheme": PROPOSAL_SCHEME, "value": seed })
}

/// A realistic dry-run `result_summary`: two policies over two
/// repositories, a measured byte figure, and a sample.
///
/// The proposal identity is seeded from the row count, so two fixtures
/// with the same totals name the same artifacts — which is what makes
/// [`dry_run_summary_proposing`] the interesting case.
fn dry_run_summary(rows: u64, coverage: &str, freed: &serde_json::Value) -> serde_json::Value {
    dry_run_summary_proposing(rows, coverage, freed, &format!("rows-{rows}"))
}

/// The same fixture with the proposed set named independently of the
/// totals, so a test can hold every figure still and move only the
/// artifacts.
fn dry_run_summary_proposing(
    rows: u64,
    coverage: &str,
    freed: &serde_json::Value,
    proposal: &str,
) -> serde_json::Value {
    // Split the rows across the two groups so the per-group figures stay
    // consistent with the total for any fixture size.
    let pypi_rows = rows / 12;
    let npm_rows = rows - pypi_rows;
    serde_json::json!({
        "mode": "dry_run",
        "coverage": coverage,
        "policies": 2,
        "evaluated": 74_912,
        "expired": rows,
        "already_expired": 118,
        "skipped_protected": 402,
        "skipped_stale_scan": 1_207,
        "errors": 0,
        "preview": {
            "rows": rows,
            "distinct_contents": 34_102,
            "freed_bytes": freed,
            "proposal_digest": digest(&format!("run/{proposal}")),
            "groups": [
                {
                    "policy_id": "a1b2c3d4-0000-0000-0000-000000000001",
                    "policy_name": "npm-keep-last-5",
                    "repository_id": NPM_REPO_UUID,
                    "repository_key": "npm-proxy",
                    "rows": npm_rows,
                    "distinct_contents": 30_884,
                    "proposal_digest": digest(&format!("npm-proxy/{proposal}"))
                },
                {
                    "policy_id": "a1b2c3d4-0000-0000-0000-000000000002",
                    "policy_name": "pypi-age-365d",
                    "repository_id": PYPI_REPO_UUID,
                    "repository_key": "pypi-proxy",
                    "rows": pypi_rows,
                    "distinct_contents": 3_218,
                    "proposal_digest": digest(&format!("pypi-proxy/{proposal}"))
                }
            ],
            "sample": [
                {
                    "artifact_id": "c0ffee00-0000-0000-0000-000000000001",
                    "policy_id": "a1b2c3d4-0000-0000-0000-000000000001",
                    "repository_id": NPM_REPO_UUID,
                    "repository_key": "npm-proxy",
                    "name": "lodash", "version": "4.17.19", "age_seconds": 41_558_400
                },
                {
                    "artifact_id": "c0ffee00-0000-0000-0000-000000000002",
                    "policy_id": "a1b2c3d4-0000-0000-0000-000000000001",
                    "repository_id": NPM_REPO_UUID,
                    "repository_key": "npm-proxy",
                    "name": "@types/node", "version": "18.11.9", "age_seconds": 30_931_200
                },
                {
                    "artifact_id": "c0ffee00-0000-0000-0000-000000000003",
                    "policy_id": "a1b2c3d4-0000-0000-0000-000000000002",
                    "repository_id": PYPI_REPO_UUID,
                    "repository_key": "pypi-proxy",
                    "name": "requests", "version": "2.25.1", "age_seconds": 52_876_800
                }
            ],
            "sample_limit": 500
        }
    })
}

fn execute_summary(expired: u64) -> serde_json::Value {
    serde_json::json!({
        "mode": "execute",
        "coverage": "complete",
        "policies": 2,
        "evaluated": 74_912,
        "expired": expired,
        "already_expired": 118,
        "skipped_protected": 402,
        "skipped_stale_scan": 1_207,
        "errors": 0,
        "preview": null
    })
}

fn job_row(id: &str, status: &str, summary: Option<serde_json::Value>) -> String {
    let mut row = serde_json::json!({
        "id": id,
        "kind": "retention-evaluate",
        "status": status,
        "priority": 0,
        "trigger_source": "api",
        "attempts": 1,
        "created_at": "2026-09-25T11:00:00Z",
        "updated_at": "2026-09-25T11:02:14Z",
        "completed_at": "2026-09-25T11:02:14Z"
    });
    if let Some(s) = summary {
        row["result_summary"] = s;
    }
    row.to_string()
}

/// Mock one invoke. `status` is the wire distinction between a fresh
/// enqueue (202) and the server's same-day dedup (200).
async fn mock_invoke(server: &mut ServerGuard, mode: &str, job_id: &str, status: usize) {
    server
        .mock("POST", "/api/v1/admin/tasks/retention-evaluate")
        .match_body(Matcher::Json(serde_json::json!({ "mode": mode })))
        .with_status(status)
        .with_header("content-type", "application/json")
        .with_body(serde_json::json!({ "task_job_id": job_id }).to_string())
        .create_async()
        .await;
}

async fn mock_job(
    server: &mut ServerGuard,
    id: &str,
    status: &str,
    summary: Option<serde_json::Value>,
) {
    server
        .mock("GET", format!("/api/v1/admin/tasks/{id}").as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(job_row(id, status, summary))
        .create_async()
        .await;
}

// ---------------------------------------------------------------------------
// preview
// ---------------------------------------------------------------------------

#[tokio::test]
async fn preview_invokes_the_dry_run_and_renders_the_proposal() {
    let mut server = Server::new_async().await;
    // `match_body` is what proves the dry run was requested: an
    // `execute` body would not match this mock and the call would fail.
    mock_invoke(&mut server, "dry_run", DRY_RUN_JOB, 202).await;
    mock_job(
        &mut server,
        DRY_RUN_JOB,
        "completed",
        Some(dry_run_summary(
            51_535,
            "complete",
            &serde_json::json!({ "status": "exact", "bytes": 12_884_901_888_u64 }),
        )),
    )
    .await;

    let mut out = Vec::new();
    let exit = preview::run_with_output(
        test_client(&server.url()),
        PreviewArgs { sweep: opts() },
        OutputFormat::Table,
        &mut out,
    )
    .await
    .expect("preview runs");
    assert_eq!(exit, RetentionExit::Success);

    let text = String::from_utf8(out).expect("utf8");
    assert!(text.contains("51,535"), "{text}");
    assert!(text.contains("34,102"), "{text}");
    assert!(text.contains("12,884,901,888 bytes, measured"), "{text}");
    assert!(text.contains("npm-keep-last-5"), "{text}");
    assert!(text.contains("lodash"), "{text}");
}

/// The acceptance criterion with teeth: no bare repository UUID may
/// stand in for a repository anywhere in the rendered human output.
#[tokio::test]
async fn preview_names_repositories_by_key_and_never_by_a_bare_uuid() {
    let mut server = Server::new_async().await;
    mock_invoke(&mut server, "dry_run", DRY_RUN_JOB, 202).await;
    mock_job(
        &mut server,
        DRY_RUN_JOB,
        "completed",
        Some(dry_run_summary(
            51_535,
            "complete",
            &serde_json::json!({ "status": "exact", "bytes": 4_096 }),
        )),
    )
    .await;

    let mut out = Vec::new();
    preview::run_with_output(
        test_client(&server.url()),
        PreviewArgs { sweep: opts() },
        OutputFormat::Table,
        &mut out,
    )
    .await
    .expect("preview runs");
    let text = String::from_utf8(out).expect("utf8");

    assert!(text.contains("npm-proxy"), "the key is shown:\n{text}");
    assert!(text.contains("pypi-proxy"), "both keys are shown:\n{text}");
    assert!(
        !text.contains(NPM_REPO_UUID),
        "a repository UUID leaked into the human output:\n{text}"
    );
    assert!(
        !text.contains(PYPI_REPO_UUID),
        "a repository UUID leaked into the human output:\n{text}"
    );
}

#[tokio::test]
async fn preview_puts_partial_coverage_above_every_figure_it_qualifies() {
    let mut server = Server::new_async().await;
    mock_invoke(&mut server, "dry_run", DRY_RUN_JOB, 202).await;
    mock_job(
        &mut server,
        DRY_RUN_JOB,
        "completed",
        Some(dry_run_summary(
            51_535,
            "partial",
            &serde_json::json!({ "status": "exact", "bytes": 4_096 }),
        )),
    )
    .await;

    let mut out = Vec::new();
    preview::run_with_output(
        test_client(&server.url()),
        PreviewArgs { sweep: opts() },
        OutputFormat::Table,
        &mut out,
    )
    .await
    .expect("preview runs");
    let text = String::from_utf8(out).expect("utf8");

    let partial_at = text.find("PARTIAL").expect("partial is stated");
    let first_number = text.find("51,535").expect("the totals appear");
    assert!(partial_at < first_number, "{text}");
}

#[tokio::test]
async fn preview_states_an_unmeasured_size_with_its_reason_and_never_a_zero() {
    let mut server = Server::new_async().await;
    mock_invoke(&mut server, "dry_run", DRY_RUN_JOB, 202).await;
    mock_job(
        &mut server,
        DRY_RUN_JOB,
        "completed",
        Some(dry_run_summary(
            51_535,
            "complete",
            &serde_json::json!({
                "status": "omitted",
                "reason": OMITTED_BYTES_REASON
            }),
        )),
    )
    .await;

    let mut out = Vec::new();
    preview::run_with_output(
        test_client(&server.url()),
        PreviewArgs { sweep: opts() },
        OutputFormat::Table,
        &mut out,
    )
    .await
    .expect("preview runs");
    let text = String::from_utf8(out).expect("utf8");

    let line = text
        .lines()
        .find(|l| l.contains("storage freed"))
        .expect("the storage line exists");
    assert!(line.contains("NOT MEASURED"), "{line}");
    // The server's reason reaches the operator word for word, and nothing
    // stands where the byte figure would be. Split at the banner rather
    // than scanning the whole line for a `0`: the reason legitimately
    // carries the bound and the observed count, and those digits are the
    // explanation of why there is no figure, not a figure.
    let (banner, reason) = line
        .split_once(" — ")
        .unwrap_or_else(|| panic!("banner, then the server's reason: {line}"));
    assert_eq!(reason.trim_end(), OMITTED_BYTES_REASON, "{line}");
    assert!(
        !banner.contains(|c: char| c.is_ascii_digit()),
        "no number may stand where the byte figure would be: {banner:?}"
    );
}

#[tokio::test]
async fn preview_json_carries_the_coverage_flag_and_the_omission_status() {
    let mut server = Server::new_async().await;
    mock_invoke(&mut server, "dry_run", DRY_RUN_JOB, 202).await;
    mock_job(
        &mut server,
        DRY_RUN_JOB,
        "completed",
        Some(dry_run_summary(
            51_535,
            "partial",
            &serde_json::json!({ "status": "omitted", "reason": "bound exceeded" }),
        )),
    )
    .await;

    let mut out = Vec::new();
    preview::run_with_output(
        test_client(&server.url()),
        PreviewArgs { sweep: opts() },
        OutputFormat::Json,
        &mut out,
    )
    .await
    .expect("preview runs");

    let doc: serde_json::Value =
        serde_json::from_slice(&out).expect("stdout is a single JSON document");
    assert_eq!(doc["coverage_is_partial"], true);
    assert_eq!(doc["totals"]["artifact_rows"], 51_535);
    assert_eq!(doc["totals"]["freed_bytes"]["measured"], false);
    assert_eq!(doc["totals"]["freed_bytes"]["reason"], "bound exceeded");
    assert!(doc["totals"]["freed_bytes"]["bytes"].is_null());
    assert_eq!(doc["groups"][0]["repository_key"], "npm-proxy");
    assert_eq!(doc["groups"][0]["repository_id"], NPM_REPO_UUID);
    assert_eq!(doc["sample"].as_array().expect("sample").len(), 3);
    assert_eq!(doc["proposal_digest"]["scheme"], PROPOSAL_SCHEME);
    assert_eq!(doc["proposal_digest"]["value"], "run/rows-51535");
    assert_eq!(
        doc["groups"][0]["proposal_digest"]["value"], "npm-proxy/rows-51535",
        "the per-group identity rides through too, so a script can say which group moved",
    );
}

#[tokio::test]
async fn preview_polls_until_the_job_leaves_a_non_terminal_state() {
    let mut server = Server::new_async().await;
    mock_invoke(&mut server, "dry_run", DRY_RUN_JOB, 202).await;
    // Two mocks on the same path: mockito serves the first until its
    // expected hit count is spent, then the second.
    server
        .mock("GET", format!("/api/v1/admin/tasks/{DRY_RUN_JOB}").as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(job_row(DRY_RUN_JOB, "running", None))
        .expect(1)
        .create_async()
        .await;
    mock_job(
        &mut server,
        DRY_RUN_JOB,
        "completed",
        Some(dry_run_summary(
            7,
            "complete",
            &serde_json::json!({ "status": "exact", "bytes": 1_024 }),
        )),
    )
    .await;

    let mut out = Vec::new();
    let exit = preview::run_with_output(
        test_client(&server.url()),
        PreviewArgs { sweep: opts() },
        OutputFormat::Table,
        &mut out,
    )
    .await
    .expect("preview runs");
    assert_eq!(exit, RetentionExit::Success);
    assert!(String::from_utf8(out).expect("utf8").contains("1.00 KiB"));
}

#[tokio::test]
async fn preview_that_outlives_its_wait_window_names_the_job_and_reports_no_result() {
    let mut server = Server::new_async().await;
    mock_invoke(&mut server, "dry_run", DRY_RUN_JOB, 202).await;
    mock_job(&mut server, DRY_RUN_JOB, "running", None).await;

    let mut out = Vec::new();
    let exit = preview::run_with_output(
        test_client(&server.url()),
        PreviewArgs {
            sweep: SweepOptions {
                wait_timeout: Duration::from_millis(0),
                ..opts()
            },
        },
        OutputFormat::Table,
        &mut out,
    )
    .await
    .expect("preview returns rather than hanging");
    assert_eq!(exit, RetentionExit::StillRunning);

    let text = String::from_utf8(out).expect("utf8");
    assert!(text.contains("STILL RUNNING"), "{text}");
    assert!(text.contains(DRY_RUN_JOB), "{text}");
    assert!(
        text.contains(&format!("hort-cli admin task get {DRY_RUN_JOB}")),
        "it names how to read the job later:\n{text}"
    );
    assert!(
        !text.contains("WHAT WOULD BE EXPIRED"),
        "no result may be reported:\n{text}"
    );
}

#[tokio::test]
async fn a_deduplicated_preview_says_it_is_not_a_fresh_observation() {
    let mut server = Server::new_async().await;
    // 200, not 202: the server's per-mode per-UTC-day idempotency layer
    // handed back an earlier job instead of enqueuing a new one.
    mock_invoke(&mut server, "dry_run", DRY_RUN_JOB, 200).await;
    mock_job(
        &mut server,
        DRY_RUN_JOB,
        "completed",
        Some(dry_run_summary(
            9,
            "complete",
            &serde_json::json!({ "status": "exact", "bytes": 1 }),
        )),
    )
    .await;

    let mut out = Vec::new();
    preview::run_with_output(
        test_client(&server.url()),
        PreviewArgs { sweep: opts() },
        OutputFormat::Table,
        &mut out,
    )
    .await
    .expect("preview runs");
    let text = String::from_utf8(out).expect("utf8");
    assert!(text.contains("EARLIER sweep from today"), "{text}");
    assert!(text.contains("not a fresh"), "{text}");
}

#[tokio::test]
async fn a_failed_preview_job_is_an_error_not_an_empty_proposal() {
    let mut server = Server::new_async().await;
    mock_invoke(&mut server, "dry_run", DRY_RUN_JOB, 202).await;
    server
        .mock("GET", format!("/api/v1/admin/tasks/{DRY_RUN_JOB}").as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            serde_json::json!({
                "id": DRY_RUN_JOB, "kind": "retention-evaluate", "status": "failed",
                "priority": 0, "trigger_source": "api", "attempts": 3,
                "created_at": "2026-09-25T11:00:00Z", "updated_at": "2026-09-25T11:01:00Z",
                "last_error": "list_active failed: connection reset"
            })
            .to_string(),
        )
        .create_async()
        .await;

    let mut out = Vec::new();
    let err = preview::run_with_output(
        test_client(&server.url()),
        PreviewArgs { sweep: opts() },
        OutputFormat::Table,
        &mut out,
    )
    .await
    .expect_err("a failed job must not render as a proposal");
    let text = format!("{err:#}");
    assert!(text.contains("failed"), "{text}");
    assert!(text.contains("connection reset"), "{text}");
    assert!(out.is_empty(), "nothing was rendered");
}

// ---------------------------------------------------------------------------
// apply
// ---------------------------------------------------------------------------

struct ApplyRun {
    exit: RetentionExit,
    stdout: String,
    prompts: String,
}

async fn run_apply(
    server_url: &str,
    args: ApplyArgs,
    output: OutputFormat,
    answers: &str,
) -> ApplyRun {
    let mut out = Vec::new();
    let mut prompt = Vec::new();
    let mut input = Cursor::new(answers.as_bytes().to_vec());
    let exit = apply::run_with_io(
        test_client(server_url),
        args,
        output,
        &mut out,
        &mut prompt,
        &mut input,
    )
    .await
    .expect("apply runs");
    ApplyRun {
        exit,
        stdout: String::from_utf8(out).expect("utf8"),
        prompts: String::from_utf8(prompt).expect("utf8"),
    }
}

fn apply_args(from_preview: Option<&str>, yes: bool) -> ApplyArgs {
    ApplyArgs {
        from_preview: from_preview.map(ToString::to_string),
        yes,
        sweep: opts(),
    }
}

/// Stage a baseline preview that DIFFERS from the fresh one, plus the
/// fresh preview and the execution.
async fn stage_differing(server: &mut ServerGuard) {
    mock_job(
        server,
        BASELINE_JOB,
        "completed",
        Some(dry_run_summary(
            51_535,
            "complete",
            &serde_json::json!({ "status": "exact", "bytes": 12_884_901_888_u64 }),
        )),
    )
    .await;
    mock_invoke(server, "dry_run", DRY_RUN_JOB, 202).await;
    mock_job(
        server,
        DRY_RUN_JOB,
        "completed",
        Some(dry_run_summary(
            51_907,
            "partial",
            &serde_json::json!({ "status": "exact", "bytes": 12_889_096_192_u64 }),
        )),
    )
    .await;
    mock_invoke(server, "execute", EXECUTE_JOB, 202).await;
    mock_job(
        server,
        EXECUTE_JOB,
        "completed",
        Some(execute_summary(51_907)),
    )
    .await;
}

/// The acceptance criterion the identical case cannot prove: when the
/// fresh preview differs from the named one, the difference is shown
/// and the operator is asked to confirm **again**.
#[tokio::test]
async fn apply_against_a_differing_preview_shows_the_delta_and_asks_twice() {
    let mut server = Server::new_async().await;
    stage_differing(&mut server).await;

    let run = run_apply(
        &server.url(),
        apply_args(Some(BASELINE_JOB), false),
        OutputFormat::Table,
        "yes\nyes\n",
    )
    .await;

    assert_eq!(run.exit, RetentionExit::Success);
    assert!(run.stdout.contains("WHAT CHANGED SINCE"), "{}", run.stdout);
    assert!(run.stdout.contains("+372"), "the row delta: {}", run.stdout);
    assert!(run.stdout.contains("RETENTION EXECUTED"), "{}", run.stdout);

    // Two questions, and the first is specifically about the change.
    let asked = run.prompts.matches("Type \"yes\"").count();
    assert_eq!(
        asked, 2,
        "confirmation must be requested again:\n{}",
        run.prompts
    );
    assert!(
        run.prompts.contains("changed since the preview you named"),
        "{}",
        run.prompts
    );
    assert!(
        run.prompts.contains("Execute retention now"),
        "{}",
        run.prompts
    );
}

#[tokio::test]
async fn declining_the_change_acknowledgement_executes_nothing() {
    let mut server = Server::new_async().await;
    mock_job(
        &mut server,
        BASELINE_JOB,
        "completed",
        Some(dry_run_summary(
            51_535,
            "complete",
            &serde_json::json!({ "status": "exact", "bytes": 1 }),
        )),
    )
    .await;
    mock_invoke(&mut server, "dry_run", DRY_RUN_JOB, 202).await;
    mock_job(
        &mut server,
        DRY_RUN_JOB,
        "completed",
        Some(dry_run_summary(
            51_907,
            "complete",
            &serde_json::json!({ "status": "exact", "bytes": 2 }),
        )),
    )
    .await;
    // The execute invoke must never be called. `expect(0)` turns a call
    // into a test failure at assert time.
    let never = server
        .mock("POST", "/api/v1/admin/tasks/retention-evaluate")
        .match_body(Matcher::Json(serde_json::json!({ "mode": "execute" })))
        .with_status(202)
        .with_body(serde_json::json!({ "task_job_id": EXECUTE_JOB }).to_string())
        .expect(0)
        .create_async()
        .await;

    let run = run_apply(
        &server.url(),
        apply_args(Some(BASELINE_JOB), false),
        OutputFormat::Table,
        "no\n",
    )
    .await;

    assert_eq!(run.exit, RetentionExit::NotConfirmed);
    assert!(run.stdout.contains("NOT CONFIRMED"), "{}", run.stdout);
    assert!(
        run.stdout.contains("nothing has been deleted"),
        "{}",
        run.stdout
    );
    never.assert_async().await;
}

#[tokio::test]
async fn declining_the_execution_itself_executes_nothing() {
    let mut server = Server::new_async().await;
    mock_invoke(&mut server, "dry_run", DRY_RUN_JOB, 202).await;
    mock_job(
        &mut server,
        DRY_RUN_JOB,
        "completed",
        Some(dry_run_summary(
            12,
            "complete",
            &serde_json::json!({ "status": "exact", "bytes": 3 }),
        )),
    )
    .await;
    let never = server
        .mock("POST", "/api/v1/admin/tasks/retention-evaluate")
        .match_body(Matcher::Json(serde_json::json!({ "mode": "execute" })))
        .with_status(202)
        .with_body(serde_json::json!({ "task_job_id": EXECUTE_JOB }).to_string())
        .expect(0)
        .create_async()
        .await;

    let run = run_apply(
        &server.url(),
        apply_args(None, false),
        OutputFormat::Table,
        "\n",
    )
    .await;

    assert_eq!(run.exit, RetentionExit::NotConfirmed);
    never.assert_async().await;
}

#[tokio::test]
async fn a_non_interactive_stdin_without_yes_refuses_rather_than_executing() {
    let mut server = Server::new_async().await;
    mock_invoke(&mut server, "dry_run", DRY_RUN_JOB, 202).await;
    mock_job(
        &mut server,
        DRY_RUN_JOB,
        "completed",
        Some(dry_run_summary(
            12,
            "complete",
            &serde_json::json!({ "status": "exact", "bytes": 3 }),
        )),
    )
    .await;
    let never = server
        .mock("POST", "/api/v1/admin/tasks/retention-evaluate")
        .match_body(Matcher::Json(serde_json::json!({ "mode": "execute" })))
        .with_status(202)
        .with_body(serde_json::json!({ "task_job_id": EXECUTE_JOB }).to_string())
        .expect(0)
        .create_async()
        .await;

    // Empty stdin: EOF on the first read.
    let run = run_apply(
        &server.url(),
        apply_args(None, false),
        OutputFormat::Table,
        "",
    )
    .await;
    assert_eq!(run.exit, RetentionExit::NotConfirmed);
    assert!(
        run.prompts.contains("treating that as \"no\""),
        "{}",
        run.prompts
    );
    never.assert_async().await;
}

#[tokio::test]
async fn yes_skips_the_prompt_but_still_emits_the_delta() {
    let mut server = Server::new_async().await;
    stage_differing(&mut server).await;

    let run = run_apply(
        &server.url(),
        apply_args(Some(BASELINE_JOB), true),
        OutputFormat::Table,
        "",
    )
    .await;

    assert_eq!(run.exit, RetentionExit::Success);
    assert!(
        run.prompts.is_empty(),
        "--yes must ask nothing: {}",
        run.prompts
    );
    assert!(
        run.stdout.contains("WHAT CHANGED SINCE"),
        "--yes skips the question, never the comparison:\n{}",
        run.stdout
    );
    assert!(run.stdout.contains("+372"), "{}", run.stdout);
    assert!(run.stdout.contains("RETENTION EXECUTED"), "{}", run.stdout);
}

#[tokio::test]
async fn an_identical_preview_is_confirmed_once_and_says_nothing_changed() {
    let mut server = Server::new_async().await;
    let same = dry_run_summary(
        51_535,
        "complete",
        &serde_json::json!({ "status": "exact", "bytes": 4_096 }),
    );
    mock_job(&mut server, BASELINE_JOB, "completed", Some(same.clone())).await;
    mock_invoke(&mut server, "dry_run", DRY_RUN_JOB, 202).await;
    mock_job(&mut server, DRY_RUN_JOB, "completed", Some(same)).await;
    mock_invoke(&mut server, "execute", EXECUTE_JOB, 202).await;
    mock_job(
        &mut server,
        EXECUTE_JOB,
        "completed",
        Some(execute_summary(51_535)),
    )
    .await;

    let run = run_apply(
        &server.url(),
        apply_args(Some(BASELINE_JOB), false),
        OutputFormat::Table,
        "yes\n",
    )
    .await;

    assert_eq!(run.exit, RetentionExit::Success);
    assert!(
        run.stdout.contains("NOTHING CHANGED SINCE"),
        "{}",
        run.stdout
    );
    assert_eq!(
        run.prompts.matches("Type \"yes\"").count(),
        1,
        "one question when nothing moved:\n{}",
        run.prompts
    );
    assert!(
        run.stdout.contains("The SAME artifacts"),
        "and it is earned by the artifacts, not by the totals:\n{}",
        run.stdout
    );
}

/// The failure this whole mechanism exists for, end to end: between the
/// baseline preview and the apply, one artifact stops matching and an
/// equally sized one starts. Every figure on the page is identical —
/// rows, distinct contents, bytes, coverage, both per-group rollups —
/// and the comparison must still demand the confirmation, because the
/// apply is about to destroy a different artifact than the operator
/// read about.
#[tokio::test]
async fn an_equal_sized_substitution_is_detected_and_asked_about() {
    let mut server = Server::new_async().await;
    let freed = serde_json::json!({ "status": "exact", "bytes": 4_096 });
    let baseline = dry_run_summary_proposing(51_535, "complete", &freed, "before");
    let fresh = dry_run_summary_proposing(51_535, "complete", &freed, "after");

    // Nothing an aggregate comparison can see has moved.
    assert_eq!(baseline["preview"]["rows"], fresh["preview"]["rows"]);
    assert_eq!(
        baseline["preview"]["distinct_contents"],
        fresh["preview"]["distinct_contents"]
    );
    assert_eq!(
        baseline["preview"]["freed_bytes"],
        fresh["preview"]["freed_bytes"]
    );
    assert_eq!(baseline["coverage"], fresh["coverage"]);
    for group in 0..2 {
        assert_eq!(
            baseline["preview"]["groups"][group]["rows"],
            fresh["preview"]["groups"][group]["rows"]
        );
        assert_eq!(
            baseline["preview"]["groups"][group]["distinct_contents"],
            fresh["preview"]["groups"][group]["distinct_contents"]
        );
    }

    mock_job(&mut server, BASELINE_JOB, "completed", Some(baseline)).await;
    mock_invoke(&mut server, "dry_run", DRY_RUN_JOB, 202).await;
    mock_job(&mut server, DRY_RUN_JOB, "completed", Some(fresh)).await;
    mock_invoke(&mut server, "execute", EXECUTE_JOB, 202).await;
    mock_job(
        &mut server,
        EXECUTE_JOB,
        "completed",
        Some(execute_summary(51_535)),
    )
    .await;

    let run = run_apply(
        &server.url(),
        apply_args(Some(BASELINE_JOB), false),
        OutputFormat::Table,
        "yes\nyes\n",
    )
    .await;

    assert_eq!(run.exit, RetentionExit::Success);
    assert!(
        !run.stdout.contains("NOTHING CHANGED"),
        "equal totals must not earn it:\n{}",
        run.stdout
    );
    assert!(run.stdout.contains("WHAT CHANGED SINCE"), "{}", run.stdout);
    assert!(run.stdout.contains("DIFFERENT artifacts"), "{}", run.stdout);
    assert_eq!(
        run.prompts.matches("Type \"yes\"").count(),
        2,
        "the change acknowledgement is demanded even though every figure held:\n{}",
        run.prompts
    );
    assert!(
        run.prompts
            .contains("different artifacts would be expired now"),
        "{}",
        run.prompts
    );
}

/// A server that reports no proposal identity cannot earn `NOTHING
/// CHANGED` on equal totals — it gets the confirmation and a statement
/// that the check did not run.
#[tokio::test]
async fn a_preview_without_a_proposal_identity_is_not_reported_as_unchanged() {
    let mut server = Server::new_async().await;
    let mut same = dry_run_summary(
        51_535,
        "complete",
        &serde_json::json!({ "status": "exact", "bytes": 4_096 }),
    );
    // A server older than the proposal-identity field: totals and
    // groups, no statement of which rows they cover.
    same["preview"]
        .as_object_mut()
        .expect("preview object")
        .remove("proposal_digest");
    for group in same["preview"]["groups"]
        .as_array_mut()
        .expect("groups array")
    {
        group
            .as_object_mut()
            .expect("group object")
            .remove("proposal_digest");
    }

    mock_job(&mut server, BASELINE_JOB, "completed", Some(same.clone())).await;
    mock_invoke(&mut server, "dry_run", DRY_RUN_JOB, 202).await;
    mock_job(&mut server, DRY_RUN_JOB, "completed", Some(same)).await;
    mock_invoke(&mut server, "execute", EXECUTE_JOB, 202).await;
    mock_job(
        &mut server,
        EXECUTE_JOB,
        "completed",
        Some(execute_summary(51_535)),
    )
    .await;

    let run = run_apply(
        &server.url(),
        apply_args(Some(BASELINE_JOB), false),
        OutputFormat::Table,
        "yes\nyes\n",
    )
    .await;

    assert_eq!(run.exit, RetentionExit::Success);
    assert!(
        !run.stdout.contains("NOTHING CHANGED"),
        "a comparison that could not check must not sound like one that did:\n{}",
        run.stdout
    );
    assert!(
        run.stdout
            .contains("THIS COMPARISON COULD NOT CHECK WHICH ARTIFACTS"),
        "{}",
        run.stdout
    );
    assert_eq!(run.prompts.matches("Type \"yes\"").count(), 2);
    assert!(
        run.prompts.contains("could not check WHICH artifacts"),
        "{}",
        run.prompts
    );
}

/// Two `partial` runs walk windows of the candidate set, and the sweep's
/// saved position moves under them. A comparison across them says what
/// it compared instead of reporting the window as the world.
#[tokio::test]
async fn a_comparison_across_partial_coverage_says_it_compared_windows() {
    let mut server = Server::new_async().await;
    let freed = serde_json::json!({ "status": "exact", "bytes": 4_096 });
    mock_job(
        &mut server,
        BASELINE_JOB,
        "completed",
        Some(dry_run_summary_proposing(
            51_535,
            "partial",
            &freed,
            "first-window",
        )),
    )
    .await;
    mock_invoke(&mut server, "dry_run", DRY_RUN_JOB, 202).await;
    mock_job(
        &mut server,
        DRY_RUN_JOB,
        "completed",
        Some(dry_run_summary_proposing(
            51_535,
            "partial",
            &freed,
            "second-window",
        )),
    )
    .await;
    mock_invoke(&mut server, "execute", EXECUTE_JOB, 202).await;
    mock_job(
        &mut server,
        EXECUTE_JOB,
        "completed",
        Some(execute_summary(51_535)),
    )
    .await;

    let run = run_apply(
        &server.url(),
        apply_args(Some(BASELINE_JOB), false),
        OutputFormat::Table,
        "yes\nyes\n",
    )
    .await;

    assert_eq!(run.exit, RetentionExit::Success);
    let flat = run.stdout.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        flat.contains("what was compared here is two windows"),
        "{}",
        run.stdout
    );
    assert!(
        flat.contains("may be the window moving rather than the world"),
        "the difference is not attributed to the world:\n{}",
        run.stdout
    );
    assert!(
        run.prompts.contains("what was compared is two windows"),
        "and the prompt says it too:\n{}",
        run.prompts
    );
}

#[tokio::test]
async fn apply_without_a_baseline_invents_no_delta() {
    let mut server = Server::new_async().await;
    mock_invoke(&mut server, "dry_run", DRY_RUN_JOB, 202).await;
    mock_job(
        &mut server,
        DRY_RUN_JOB,
        "completed",
        Some(dry_run_summary(
            51_535,
            "complete",
            &serde_json::json!({ "status": "exact", "bytes": 4_096 }),
        )),
    )
    .await;
    mock_invoke(&mut server, "execute", EXECUTE_JOB, 202).await;
    mock_job(
        &mut server,
        EXECUTE_JOB,
        "completed",
        Some(execute_summary(51_535)),
    )
    .await;

    let run = run_apply(
        &server.url(),
        apply_args(None, false),
        OutputFormat::Table,
        "yes\n",
    )
    .await;

    assert_eq!(run.exit, RetentionExit::Success);
    assert!(
        run.stdout.contains("NO BASELINE TO COMPARE AGAINST"),
        "{}",
        run.stdout
    );
    assert!(!run.stdout.contains("CHANGED SINCE"), "{}", run.stdout);
    assert_eq!(run.prompts.matches("Type \"yes\"").count(), 1);
}

#[tokio::test]
async fn apply_json_puts_one_document_on_stdout_and_the_proposal_on_stderr() {
    let mut server = Server::new_async().await;
    stage_differing(&mut server).await;

    let run = run_apply(
        &server.url(),
        apply_args(Some(BASELINE_JOB), true),
        OutputFormat::Json,
        "",
    )
    .await;

    let doc: serde_json::Value =
        serde_json::from_str(&run.stdout).expect("stdout is a single JSON document");
    assert_eq!(doc["outcome"], "executed");
    assert_eq!(doc["delta"]["changed"], true);
    assert_eq!(doc["delta"]["artifact_rows"]["baseline"], 51_535);
    assert_eq!(doc["delta"]["artifact_rows"]["fresh"], 51_907);
    assert_eq!(doc["delta"]["coverage"]["baseline"], "complete");
    assert_eq!(doc["delta"]["coverage"]["fresh"], "partial");
    assert_eq!(doc["confirmation"]["skipped_with_yes"], true);
    assert_eq!(doc["confirmation"]["questions_asked"], 0);
    assert_eq!(doc["execution"]["artifact_rows_expired"], 51_907);
    assert_eq!(doc["baseline"]["task_job_id"], BASELINE_JOB);
    assert_eq!(doc["fresh_preview"]["task_job_id"], DRY_RUN_JOB);
    assert_eq!(doc["delta"]["proposal"]["comparison"], "different");
    assert_eq!(
        doc["delta"]["proposal"]["window_limited"], true,
        "the fresh side is partial, and a script must be able to see that",
    );
    assert_eq!(
        doc["delta"]["groups"][0]["proposal_comparison"],
        "different"
    );
    // The human still gets the comparison, on the stream that does not
    // have to stay parseable.
    assert!(
        run.prompts.contains("WHAT CHANGED SINCE"),
        "{}",
        run.prompts
    );
}

#[tokio::test]
async fn apply_json_records_a_refusal_without_an_execution() {
    let mut server = Server::new_async().await;
    mock_invoke(&mut server, "dry_run", DRY_RUN_JOB, 202).await;
    mock_job(
        &mut server,
        DRY_RUN_JOB,
        "completed",
        Some(dry_run_summary(
            12,
            "complete",
            &serde_json::json!({ "status": "exact", "bytes": 3 }),
        )),
    )
    .await;

    let run = run_apply(
        &server.url(),
        apply_args(None, false),
        OutputFormat::Json,
        "no\n",
    )
    .await;

    assert_eq!(run.exit, RetentionExit::NotConfirmed);
    let doc: serde_json::Value = serde_json::from_str(&run.stdout).expect("json");
    assert_eq!(doc["outcome"], "not_confirmed");
    assert!(doc["execution"].is_null());
    assert_eq!(doc["confirmation"]["granted"], false);
    assert_eq!(doc["fresh_preview"]["totals"]["artifact_rows"], 12);
}

/// The dedup case end to end: the pre-execution preview was replayed
/// rather than re-measured, and the prompt — the last thing read before
/// the decision — says so.
#[tokio::test]
async fn a_replayed_pre_execution_preview_is_stated_in_the_prompt_itself() {
    let mut server = Server::new_async().await;
    // 200, not 202: the server handed back an earlier same-day dry run.
    mock_invoke(&mut server, "dry_run", DRY_RUN_JOB, 200).await;
    mock_job(
        &mut server,
        DRY_RUN_JOB,
        "completed",
        Some(dry_run_summary(
            51_535,
            "complete",
            &serde_json::json!({ "status": "exact", "bytes": 4_096 }),
        )),
    )
    .await;
    mock_invoke(&mut server, "execute", EXECUTE_JOB, 202).await;
    mock_job(
        &mut server,
        EXECUTE_JOB,
        "completed",
        Some(execute_summary(51_900)),
    )
    .await;

    let run = run_apply(
        &server.url(),
        apply_args(None, false),
        OutputFormat::Table,
        "yes\n",
    )
    .await;

    assert_eq!(run.exit, RetentionExit::Success);
    assert!(
        run.stdout.contains("EARLIER sweep from today"),
        "the header says it:\n{}",
        run.stdout
    );
    assert!(
        run.prompts.contains("EARLIER sweep from today"),
        "and so does the question being answered:\n{}",
        run.prompts
    );
    assert!(
        run.prompts.contains("The execution will be fresh"),
        "{}",
        run.prompts
    );
}

#[tokio::test]
async fn an_execution_that_outlives_the_wait_window_says_it_was_started() {
    let mut server = Server::new_async().await;
    mock_invoke(&mut server, "dry_run", DRY_RUN_JOB, 202).await;
    mock_job(
        &mut server,
        DRY_RUN_JOB,
        "completed",
        Some(dry_run_summary(
            9,
            "complete",
            &serde_json::json!({ "status": "exact", "bytes": 1 }),
        )),
    )
    .await;
    mock_invoke(&mut server, "execute", EXECUTE_JOB, 202).await;
    mock_job(&mut server, EXECUTE_JOB, "running", None).await;

    let mut out = Vec::new();
    let mut prompt = Vec::new();
    let mut input = Cursor::new(b"yes\n".to_vec());
    let exit = apply::run_with_io(
        test_client(&server.url()),
        ApplyArgs {
            from_preview: None,
            yes: false,
            // The dry-run job is already `completed` on its first read,
            // so a zero window still reads it; the execute job never
            // leaves `running`, so the same window expires on it.
            sweep: SweepOptions {
                wait_timeout: Duration::from_millis(0),
                ..opts()
            },
        },
        OutputFormat::Table,
        &mut out,
        &mut prompt,
        &mut input,
    )
    .await
    .expect("apply returns");

    assert_eq!(exit, RetentionExit::StillRunning);
    let text = String::from_utf8(out).expect("utf8");
    assert!(text.contains("The execution WAS started"), "{text}");
    assert!(text.contains(EXECUTE_JOB), "{text}");
    assert!(
        !text.contains("RETENTION EXECUTED"),
        "no result may be reported:\n{text}"
    );
}

/// The machine record of a destructive run must not be thinner than the
/// human one: table mode has already printed the proposal by the time the
/// execute job outruns the wait window, so the JSON document carries it
/// too — plus the fact that the execution was started.
#[tokio::test]
async fn an_execution_that_outlives_the_wait_window_still_records_the_proposal_in_json() {
    let mut server = Server::new_async().await;
    mock_job(
        &mut server,
        BASELINE_JOB,
        "completed",
        Some(dry_run_summary(
            51_535,
            "complete",
            &serde_json::json!({ "status": "exact", "bytes": 4_096 }),
        )),
    )
    .await;
    mock_invoke(&mut server, "dry_run", DRY_RUN_JOB, 202).await;
    mock_job(
        &mut server,
        DRY_RUN_JOB,
        "completed",
        Some(dry_run_summary(
            51_907,
            "complete",
            &serde_json::json!({ "status": "exact", "bytes": 8_192 }),
        )),
    )
    .await;
    mock_invoke(&mut server, "execute", EXECUTE_JOB, 202).await;
    mock_job(&mut server, EXECUTE_JOB, "running", None).await;

    let mut out = Vec::new();
    let mut prompt = Vec::new();
    let mut input = Cursor::new(Vec::new());
    let exit = apply::run_with_io(
        test_client(&server.url()),
        ApplyArgs {
            from_preview: Some(BASELINE_JOB.to_string()),
            yes: true,
            sweep: SweepOptions {
                wait_timeout: Duration::from_millis(0),
                ..opts()
            },
        },
        OutputFormat::Json,
        &mut out,
        &mut prompt,
        &mut input,
    )
    .await
    .expect("apply returns");

    assert_eq!(exit, RetentionExit::StillRunning);
    let doc: serde_json::Value =
        serde_json::from_slice(&out).expect("stdout is a single JSON document");
    assert_eq!(doc["outcome"], "still_running");
    assert_eq!(doc["execution"]["task_job_id"], EXECUTE_JOB);
    assert_eq!(doc["execution"]["job_status"], "still_running");
    assert!(
        doc["execution"]["note"]
            .as_str()
            .expect("a note")
            .contains("WAS started"),
        "{doc}"
    );
    assert_eq!(
        doc["execution"]["read_later_with"],
        format!("hort-cli admin task get {EXECUTE_JOB}")
    );
    // The proposal it was authorised against is still in the record.
    assert_eq!(doc["delta"]["changed"], true);
    assert_eq!(doc["delta"]["artifact_rows"]["baseline"], 51_535);
    assert_eq!(doc["fresh_preview"]["totals"]["artifact_rows"], 51_907);
    assert_eq!(doc["confirmation"]["granted"], true);
    assert_eq!(doc["confirmation"]["skipped_with_yes"], true);
}

#[tokio::test]
async fn from_preview_rejects_something_that_is_not_a_task_job_id() {
    let server = Server::new_async().await;
    let mut out = Vec::new();
    let mut prompt = Vec::new();
    let mut input = Cursor::new(Vec::new());
    let err = apply::run_with_io(
        test_client(&server.url()),
        apply_args(Some("yesterday's preview"), true),
        OutputFormat::Table,
        &mut out,
        &mut prompt,
        &mut input,
    )
    .await
    .expect_err("not a UUID");
    assert!(format!("{err:#}").contains("--from-preview expects a task job id"));
    assert!(out.is_empty());
}

#[tokio::test]
async fn from_preview_rejects_a_job_that_is_not_a_dry_run() {
    let mut server = Server::new_async().await;
    mock_job(
        &mut server,
        BASELINE_JOB,
        "completed",
        Some(execute_summary(4)),
    )
    .await;

    let mut out = Vec::new();
    let mut prompt = Vec::new();
    let mut input = Cursor::new(Vec::new());
    let err = apply::run_with_io(
        test_client(&server.url()),
        apply_args(Some(BASELINE_JOB), true),
        OutputFormat::Table,
        &mut out,
        &mut prompt,
        &mut input,
    )
    .await
    .expect_err("an execution is not a proposal");
    let text = format!("{err:#}");
    assert!(text.contains("not a dry run"), "{text}");
}

#[tokio::test]
async fn from_preview_rejects_a_job_that_has_not_finished() {
    let mut server = Server::new_async().await;
    mock_job(&mut server, BASELINE_JOB, "running", None).await;

    let mut out = Vec::new();
    let mut prompt = Vec::new();
    let mut input = Cursor::new(Vec::new());
    let err = apply::run_with_io(
        test_client(&server.url()),
        apply_args(Some(BASELINE_JOB), true),
        OutputFormat::Table,
        &mut out,
        &mut prompt,
        &mut input,
    )
    .await
    .expect_err("an unfinished job has no proposal in it");
    assert!(format!("{err:#}").contains("still running"));
}
