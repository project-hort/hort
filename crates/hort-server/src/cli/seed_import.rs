//! `hort-server seed-import` — bulk-register CAS-present artifacts.
//!
//! A **DB-only** enqueue subcommand the operator runs once per
//! cutover. It parses an operator-supplied TSV input file (or stdin),
//! validates each row, and inserts a single `kind = 'seed-import'`
//! row into `public.jobs` carrying the parsed items in `params.items`.
//! The always-on worker (`hort-worker`) then claims the row and
//! dispatches to `SeedImportHandler`, which delegates to
//! `SeedImportUseCase::run` to bulk-register each item with a
//! backdated `quarantine_window_start` anchor.
//!
//! ## Why a DB-only subcommand
//!
//! Mirrors `enqueue-quarantine-release-sweep`
//! exactly: the subcommand uses the **runtime DSN** and parses
//! [`MinimalConfig`] — no svc-token, no `Config::from_env`. ADR 0009
//! bans DB-only subcommands from consuming the full
//! serve-config surface; seed-import enqueues a job row and exits, so
//! it qualifies.
//!
//! The actual ingest work (CAS lookup, lifecycle commit, event-store
//! append, format-handler dispatch) runs inside the worker where the
//! full stack is already wired. The subcommand is a thin parser +
//! enqueuer.
//!
//! ## Input format
//!
//! **Design choice declared per Implementation Discipline.** The
//! input shape was left open ("lockfile closure or
//! an explicit list"); pick the smallest honest start:
//!
//! - **TSV** (tab-separated), one item per line.
//! - Five required columns, in order:
//!   1. `repository_id` — UUID of the target repo.
//!   2. `format` — `RepositoryFormat` string (e.g. `pypi`, `npm`,
//!      `cargo`, `maven`).
//!   3. `name` — normalized artifact name.
//!   4. `version` — artifact version.
//!   5. `content_hash` — lowercase-hex SHA-256 of the CAS-present bytes.
//! - Blank lines and `#`-prefixed comment lines are skipped.
//! - The bytes must already be present in CAS; this path does not
//!   fetch from upstream. The deployment scenario is "operator restored
//!   CAS from backup and now wants to register the metadata rows."
//!
//! Rationale: an explicit list is the smaller, most-honest start. A
//! lockfile parser (one per ecosystem) is significant scope and lands
//! as a follow-on initiative if operators ask for it. JSON was
//! considered but TSV is the smaller surface — `awk` / `cut` /
//! `grep` etc. round-trip cleanly.
//!
//! ## Idempotency
//!
//! The use case handles per-item dedup: a re-run with the same input
//! set counts each pre-existing row as `already_imported` (no second
//! event commit). The subcommand itself does NOT dedup at the enqueue
//! layer — two ticks of "operator runs seed-import twice" enqueue
//! two job rows; the second's use-case run produces an
//! `already_imported`-heavy summary.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{bail, Context};
use clap::Args;
use sqlx::postgres::PgPoolOptions;
use tracing::info;
use uuid::Uuid;

use hort_adapters_postgres::jobs_repository::PgJobsRepository;
use hort_domain::entities::repository::RepositoryFormat;
use hort_domain::ports::jobs_repository::JobsRepository;
use hort_domain::types::ContentHash;

use crate::config::MinimalConfig;
use crate::telemetry;

/// `trigger_source` literal for `jobs.trigger_source`.
/// Seed-import is always operator-driven (the subcommand is
/// run from a CLI) AND distinct from other `'manual'` enqueues
/// (admin-tasks API, manual-rescan, etc.), so the discriminator
/// surfaces seed-import in the audit trail without depending on
/// per-row `actor_id` attribution (which stays a separate larger ask
/// — see the module docstring).
///
/// Constraint: the literal must match the `'seed-import'` arm in
/// `009_scan_jobs_and_findings.sql`'s `trigger_source` CHECK. The
/// `constants_match_init33_trigger_source_ranking` test below pins
/// both the literal and the priority so a future rename has to
/// touch the test in lock-step with the CHECK.
const SEED_IMPORT_TRIGGER_SOURCE: &str = "seed-import";

/// `priority` for the enqueued row. The trigger-source
/// ranking is `ingest=0 → advisory=5 → cron=10 → manual=20`. Manual
/// invocation drains first; that matches the operator expectation
/// for a one-shot cutover ("run the import, don't wait behind every
/// scheduled cron tick").
const MANUAL_PRIORITY: i16 = 20;

/// Arguments to `hort-server seed-import`.
///
/// One flag — the input file path. `--file -` reads from stdin (the
/// conventional `-` filename convention).
#[derive(Debug, Args)]
pub struct SeedImportArgs {
    /// Path to the TSV input file. Use `-` to read from stdin.
    ///
    /// Five tab-separated columns per row, in order:
    /// `repository_id` `format` `name` `version` `content_hash`.
    /// Blank lines and `#`-prefixed comment lines are skipped.
    #[arg(long, short = 'f', value_name = "PATH")]
    pub file: PathBuf,
}

/// Synchronous entry point — same shape as
/// `enqueue_quarantine_release_sweep::run`.
pub fn run(args: SeedImportArgs) -> ExitCode {
    super::run_with_runtime(move || run_async(args), |_| ExitCode::SUCCESS)
}

async fn run_async(args: SeedImportArgs) -> anyhow::Result<()> {
    // DB-only subcommand → MinimalConfig, NOT Config::from_env
    // (ADR 0009). The subcommand needs the DSN (`HORT_DATABASE_URL`,
    // falling back to bare `DATABASE_URL` — ADR 0029) + log
    // format only; the worker (where the actual CAS / lifecycle work
    // happens) already has its own full config.
    let cfg = MinimalConfig::from_env().context("parsing environment")?;
    telemetry::init_tracing(cfg.log_format)?;
    info!("seed-import: parsing input + enqueueing job");

    let raw = read_input(&args.file).context("reading seed-import input")?;
    let items = parse_tsv(&raw).context("parsing seed-import TSV")?;

    if items.is_empty() {
        bail!(
            "seed-import input had zero items after parsing — nothing to enqueue (rejecting before \
             touching the DB so the operator notices the empty file)"
        );
    }

    info!(item_count = items.len(), "parsed seed-import input");

    let pool = PgPoolOptions::new()
        .connect(&cfg.database_url)
        .await
        .context("connecting to postgres")?;
    let jobs: Arc<dyn JobsRepository> = Arc::new(PgJobsRepository::new(pool));

    // The worker reads `params.items` — see `SeedImportHandler::run`.
    let params = serde_json::json!({ "items": items });

    let outcome = jobs
        .enqueue_task(
            "seed-import",
            &params,
            None, // actor_id — see module docstring; v1 attributes to system
            MANUAL_PRIORITY,
            SEED_IMPORT_TRIGGER_SOURCE,
            None, // non-destructive task kind — no DB-side idempotency key (ADR 0028)
        )
        .await
        .context("enqueueing seed-import job")?;
    // This caller passes None so the DB-side
    // partial-unique check is inert and `Duplicate` cannot fire. Treat
    // both arms identically — the operator sees the same `job_id` log
    // line either way.
    let id: Uuid = match outcome {
        hort_domain::ports::jobs_repository::EnqueueOutcome::Enqueued { job_id } => job_id,
        hort_domain::ports::jobs_repository::EnqueueOutcome::Duplicate { existing_job_id } => {
            existing_job_id
        }
    };

    info!(
        job_id = %id,
        kind = "seed-import",
        priority = MANUAL_PRIORITY,
        trigger_source = SEED_IMPORT_TRIGGER_SOURCE,
        item_count = items.len(),
        "seed-import job enqueued"
    );
    // One-line summary on stdout — operators tail this to confirm the
    // enqueue happened.
    println!("seed-import: job_id={id} items={}", items.len());
    Ok(())
}

/// Read the input. `-` denotes stdin; any other path is read whole
/// (TSV files are operator-sized — kilobytes to a few MB at most, not
/// streamed).
fn read_input(file: &std::path::Path) -> anyhow::Result<String> {
    use std::io::Read;
    if file.as_os_str() == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        Ok(buf)
    } else {
        Ok(std::fs::read_to_string(file)?)
    }
}

/// Parse TSV input into a JSON-array shape the use case understands.
/// Returns `serde_json::Value::Array` ready to embed into
/// `params.items`.
///
/// Validation rules:
/// - Each non-blank, non-comment line MUST have exactly 5 tab-separated
///   columns.
/// - `repository_id` MUST parse as a UUID.
/// - `format` MUST parse as a known `RepositoryFormat`.
/// - `content_hash` MUST parse as a `ContentHash` (lowercase-hex SHA-256).
/// - `name` and `version` are non-empty strings (whitespace-trimmed).
///
/// A malformed row causes the WHOLE parse to fail — operators want to
/// know about the bad row before the job is enqueued, not from the
/// worker's result_summary half an hour later.
fn parse_tsv(raw: &str) -> anyhow::Result<Vec<serde_json::Value>> {
    let mut items = Vec::new();
    for (idx, line) in raw.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() != 5 {
            bail!(
                "line {line_no}: expected 5 tab-separated columns \
                 (repository_id, format, name, version, content_hash); got {}",
                cols.len()
            );
        }

        let repo_id: Uuid = cols[0]
            .trim()
            .parse()
            .with_context(|| format!("line {line_no}: column 1 (repository_id) is not a UUID"))?;

        // RepositoryFormat::from_str is `Infallible` — empty / unknown
        // strings parse as `Other(lower)`. Reject empty explicitly so
        // operators don't accidentally land artifacts under a blank
        // format key (which would also fail the format-handler lookup
        // downstream, but the seed-import surface is the right place
        // to surface this).
        let format_str = cols[1].trim();
        if format_str.is_empty() {
            bail!("line {line_no}: column 2 (format) is empty");
        }
        let format: RepositoryFormat = format_str.parse().with_context(|| {
            format!("line {line_no}: column 2 (format) is not a RepositoryFormat")
        })?;

        let name = cols[2].trim();
        if name.is_empty() {
            bail!("line {line_no}: column 3 (name) is empty");
        }

        let version = cols[3].trim();
        if version.is_empty() {
            bail!("line {line_no}: column 4 (version) is empty");
        }

        let content_hash: ContentHash = cols[4].trim().parse().with_context(|| {
            format!("line {line_no}: column 5 (content_hash) is not a SHA-256 hex")
        })?;

        // Build the JSON shape matching `SeedImportItem`'s serde
        // derive. Keep field names identical so the worker's
        // `serde_json::from_value` round-trip works without a custom
        // deserializer.
        items.push(serde_json::json!({
            "repository_id": repo_id,
            "format": format,
            "name": name,
            "version": version,
            "content_hash": content_hash,
        }));
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    use clap::Parser;

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: super::super::Command,
    }

    #[test]
    fn parses_required_file_flag() {
        let cli =
            TestCli::try_parse_from(["hort-server", "seed-import", "--file", "/tmp/seed.tsv"])
                .expect("parse");
        let super::super::Command::SeedImport(args) = cli.command else {
            panic!("expected SeedImport variant");
        };
        assert_eq!(args.file, PathBuf::from("/tmp/seed.tsv"));
    }

    #[test]
    fn parses_short_flag_alias() {
        let cli = TestCli::try_parse_from(["hort-server", "seed-import", "-f", "input.tsv"])
            .expect("parse");
        let super::super::Command::SeedImport(args) = cli.command else {
            panic!("expected SeedImport variant");
        };
        assert_eq!(args.file, PathBuf::from("input.tsv"));
    }

    #[test]
    fn missing_file_flag_errors() {
        let err = TestCli::try_parse_from(["hort-server", "seed-import"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn help_renders_with_input_format_documentation() {
        let err = TestCli::try_parse_from(["hort-server", "seed-import", "--help"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
        let rendered = err.to_string();
        // The --help string must surface "TSV" and the column order so
        // operators see the input shape without reading the source.
        assert!(rendered.contains("TSV"), "{rendered}");
    }

    #[test]
    fn constants_match_init33_trigger_source_ranking() {
        // The `'seed-import'` discriminator is the
        // load-bearing audit-trail signal; this assertion pins the
        // literal in lock-step with the `'seed-import'` arm in
        // `009_scan_jobs_and_findings.sql`'s `trigger_source` CHECK. A
        // rename to either side without touching the other fails CI
        // when the worker's claim path inserts a row that fails the
        // CHECK.
        assert_eq!(SEED_IMPORT_TRIGGER_SOURCE, "seed-import");
        // priority=20 matches the manual tier — seed-import
        // is operator-driven so it inherits the manual-tier priority
        // (drains first ahead of cron / advisory ticks).
        assert_eq!(MANUAL_PRIORITY, 20);
    }

    // ---- TSV parser tests --------------------------------------------------

    fn sample_hash_hex() -> String {
        "a".repeat(64)
    }

    #[test]
    fn parse_tsv_accepts_valid_input() {
        let repo_id = Uuid::new_v4();
        let raw = format!("{repo_id}\tpypi\tmy-pkg\t1.0.0\t{}\n", sample_hash_hex());
        let items = parse_tsv(&raw).expect("parses");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["name"], "my-pkg");
        assert_eq!(items[0]["version"], "1.0.0");
    }

    #[test]
    fn parse_tsv_skips_blank_and_comment_lines() {
        let repo_id = Uuid::new_v4();
        let raw = format!(
            "# this is a comment\n\n{repo_id}\tnpm\tlodash\t4.17.21\t{}\n# trailing comment\n",
            sample_hash_hex()
        );
        let items = parse_tsv(&raw).expect("parses");
        assert_eq!(items.len(), 1);
    }

    #[test]
    fn parse_tsv_rejects_wrong_column_count() {
        let raw = "not\tenough\tcolumns\n";
        let err = parse_tsv(raw).unwrap_err();
        assert!(err.to_string().contains("expected 5 tab-separated columns"));
    }

    #[test]
    fn parse_tsv_rejects_invalid_uuid() {
        let raw = format!("not-a-uuid\tpypi\tpkg\t1.0\t{}\n", sample_hash_hex());
        let err = parse_tsv(&raw).unwrap_err();
        assert!(err.to_string().contains("repository_id"));
    }

    #[test]
    fn parse_tsv_rejects_invalid_format() {
        let repo_id = Uuid::new_v4();
        let raw = format!("{repo_id}\t\tpkg\t1.0\t{}\n", sample_hash_hex());
        let err = parse_tsv(&raw).unwrap_err();
        assert!(err.to_string().contains("format"));
    }

    #[test]
    fn parse_tsv_rejects_empty_name() {
        let repo_id = Uuid::new_v4();
        let raw = format!("{repo_id}\tpypi\t\t1.0\t{}\n", sample_hash_hex());
        let err = parse_tsv(&raw).unwrap_err();
        assert!(err.to_string().contains("name"));
    }

    #[test]
    fn parse_tsv_rejects_empty_version() {
        let repo_id = Uuid::new_v4();
        let raw = format!("{repo_id}\tpypi\tpkg\t\t{}\n", sample_hash_hex());
        let err = parse_tsv(&raw).unwrap_err();
        assert!(err.to_string().contains("version"));
    }

    #[test]
    fn parse_tsv_rejects_invalid_hash() {
        let repo_id = Uuid::new_v4();
        let raw = format!("{repo_id}\tpypi\tpkg\t1.0\tnot-a-hash\n");
        let err = parse_tsv(&raw).unwrap_err();
        assert!(err.to_string().contains("content_hash"));
    }

    #[test]
    fn parse_tsv_empty_input_returns_zero_items() {
        let items = parse_tsv("\n# only comments\n\n").expect("parses");
        assert!(items.is_empty());
    }
}
