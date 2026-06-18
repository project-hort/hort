//! `hort-server verify-event-chain` — offline tamper-evidence verifier
//! for the sealed event chain (ADR 0002).
//!
//! Inbound adapter (CLI sense) that composes the pure `hort-domain`
//! verify core
//! ([`verify_stream_chain`](hort_domain::events::verify_stream_chain),
//! [`verify_against_checkpoint`](hort_domain::events::verify_against_checkpoint),
//! and [`roll_up`](hort_domain::events::roll_up)) with the I/O the domain
//! core forbids: reading the `events` table and the externally-anchored
//! checkpoints. This module parses CLI args,
//! does the reads, feeds the pure core, and maps the
//! [`ChainReport`](hort_domain::events::ChainReport) to a process exit
//! code + the single G1 metric. **No verify logic lives here** — the
//! verdict is computed entirely by the pure core; this module only
//! orchestrates I/O and maps the result.
//!
//! ## Read posture
//!
//! The verifier connects with the **runtime DML DSN** (read via
//! `MinimalConfig::from_env`, which prefers `HORT_DATABASE_URL` and falls
//! back to bare `DATABASE_URL` — ADR 0029; the
//! `hort_app_role`-equivalent role that holds only `SELECT`/`INSERT`
//! on `events`) — never the `migrate`/DDL role. It needs no write and
//! no DDL; that is itself part of the security story (verification
//! cannot be the vector that mutates the log).
//!
//! The reads go through a **dedicated [`EventChainReaderPort`]
//! (`hort-domain`) implemented by `PgEventChainReader` (`hort-adapters-postgres`)**
//! rather than reusing `EventStore::read_stream`:
//! `EventStore` returns `PersistedEvent`, which by design does **not**
//! carry the `prev_event_hash`/`event_hash` chain columns the chain
//! model needs to localize a tamper to an exact `Broken { at_position }`,
//! and issuing raw `sqlx` `SELECT`s **inside this `hort-server` binary**
//! would violate the
//! "SQL lives only in the Postgres adapter" guardrail and
//! Postgres-lock a verifier the architecture promises is
//! backend-agnostic. So all `sqlx` sits behind the dedicated port
//! (the exact pattern the emitter half's
//! [`EventChainHeadReaderPort`](hort_domain::ports::event_chain_head_reader)
//! / `PgEventChainHeadReader` already established): an adapter issuing
//! its own bounded `SELECT` that additionally returns the chain columns,
//! **without** widening `EventStore`. The verifier depends only on
//! `Arc<dyn EventChainReaderPort>`, so an EventStoreDB/KurrentDB backend
//! implements the same port. This is a **new** port, not a widening of
//! the well-designed `EventStore` trait.
//!
//! The read is **streamed per stream, ordered by `(stream_id,
//! stream_position)`**, one stream's bounded pages at a time (the
//! adapter pages internally) — never buffering the whole table.
//!
//! ## Exit codes (distinct so automated gates can key on them
//! deterministically)
//!
//! - `0` — [`ChainReport::Ok`].
//! - `2` — [`ChainReport::Broken`] (a detected integrity violation).
//! - `3` — [`ChainReport::MissingCheckpoint`] when
//!   `--fail-on-missing-checkpoint` (default `true`); a coverage gap,
//!   not a proven violation.
//! - `1` — operational error (DB unreachable, anchor store unreadable,
//!   a deserialization failure not attributable to tampering): the
//!   verifier could not run. Surfaced via [`super::run_with_runtime`]'s
//!   `Err` → `ExitCode::FAILURE` path.

use std::collections::BTreeSet;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::{Args, ValueEnum};
use sqlx::postgres::PgPoolOptions;
use tracing::{error, info, warn};

use hort_adapters_checkpoint_anchor::ObjectStoreCheckpointAnchor;
use hort_adapters_postgres::event_chain_reader::PgEventChainReader;
use hort_adapters_postgres::jobs_repository::PgJobsRepository;
use hort_adapters_storage::builders::{build_s3_object_store, S3StorageOpts};
use hort_domain::events::{
    roll_up, verify_against_checkpoint, verify_stream_chain, ChainReport, ChainRow, Checkpoint,
    EventHash, StreamRow, StreamRows, StreamVerdict,
};
use hort_domain::ports::checkpoint_anchor::CheckpointAnchorPort;
use hort_domain::ports::event_chain_reader::EventChainReaderPort;

use crate::composition;
use crate::config::{MinimalConfig, StorageConfig};
use crate::telemetry;

/// The `result` label values for `hort_event_chain_verify_total`. The
/// enum lives **with the emitting layer** (this `hort-server` subcommand),
/// NOT in `hort-domain` (architect "result enums live with the emitting
/// layer"; the domain core has zero observability).
const METRIC_NAME: &str = "hort_event_chain_verify_total";
const RESULT_OK: &str = "ok";
const RESULT_BROKEN: &str = "broken";
const RESULT_MISSING_CHECKPOINT: &str = "missing_checkpoint";

/// Output format for the verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable one-liner (default).
    Text,
    /// Machine-readable JSON for CI consumption.
    Json,
}

/// Arguments to `hort-server verify-event-chain`.
#[derive(Debug, Args)]
pub struct VerifyEventChainArgs {
    /// Verify only the named stream(s) (repeatable). Default: every
    /// stream. The value is the wire-form stream id, e.g.
    /// `authorization-<uuid>`.
    #[arg(long = "stream")]
    pub streams: Vec<String>,

    /// Only verify rows with `global_position >= N` (incremental
    /// re-verify). The chain is still validated from each touched
    /// stream's genesis (the per-stream chain is self-contained).
    #[arg(long)]
    pub since_global: Option<u64>,

    /// Where to read anchored checkpoints from. Default: the configured
    /// anchor object-store prefix. A verifying auditor can point this at
    /// an exported copy. Currently only the configured object store is
    /// supported; an explicit value that differs is rejected (a future
    /// item adds file:// / explicit-URI sources).
    #[arg(long)]
    pub checkpoint_source: Option<String>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Whether `missing_checkpoint` is a non-zero exit. CI wants `true`
    /// (the default — a coverage gap must be investigated);
    /// an operator spot-check may pass `--fail-on-missing-checkpoint=false`.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub fail_on_missing_checkpoint: bool,
}

// ---------------------------------------------------------------------------
// Pure result → exit-code / metric / log mapping (unit-tested, no I/O)
// ---------------------------------------------------------------------------

/// Map a [`ChainReport`] (+ the `--fail-on-missing-checkpoint` flag) to
/// a process exit code. Pure.
fn report_to_exit_code(report: ChainReport, fail_on_missing: bool) -> ExitCode {
    match report {
        ChainReport::Ok => ExitCode::SUCCESS,
        ChainReport::Broken => ExitCode::from(2),
        ChainReport::MissingCheckpoint => {
            if fail_on_missing {
                ExitCode::from(3)
            } else {
                ExitCode::SUCCESS
            }
        }
    }
}

/// The `result` label value for a [`ChainReport`]. Pure.
fn result_label(report: ChainReport) -> &'static str {
    match report {
        ChainReport::Ok => RESULT_OK,
        ChainReport::Broken => RESULT_BROKEN,
        ChainReport::MissingCheckpoint => RESULT_MISSING_CHECKPOINT,
    }
}

/// Emit `hort_event_chain_verify_total{result}` exactly once per run.
/// **The single emitter** for this metric ("one metric, one layer, no
/// double-count"). Called once, here, from the subcommand layer — never
/// from `hort-domain` or `hort-adapters-postgres`.
fn emit_metric(report: ChainReport) {
    metrics::counter!(METRIC_NAME, "result" => result_label(report)).increment(1);
}

/// Structured log for the verdict:
/// `error!` on a detected break (unrecoverable integrity failure),
/// `warn!` on `missing_checkpoint` (a coverage gap, not a proven
/// violation), `info!` on ok. **No `#[instrument(err)]`** anywhere on
/// this path — a chain break is a *verdict*, not a `Result::Err`.
fn log_report(report: ChainReport, summary: &VerifySummary) {
    match report {
        ChainReport::Ok => info!(
            streams_verified = summary.streams_verified,
            rows_read = summary.rows_read,
            "event-chain verification OK — all streams intact and anchor cross-check passed"
        ),
        ChainReport::MissingCheckpoint => warn!(
            streams_verified = summary.streams_verified,
            rows_read = summary.rows_read,
            "event-chain verification: chain intact but external anchoring \
             could not be fully attested (missing/stale/gapped checkpoint) — \
             investigate the checkpoint emitter"
        ),
        ChainReport::Broken => error!(
            streams_verified = summary.streams_verified,
            rows_read = summary.rows_read,
            first_broken_stream = ?summary.first_broken_stream,
            "event-chain verification FAILED — a tamper-evident integrity \
             violation was detected (per-event hash mismatch, dangling chain, \
             or an unsealed/absent stream not justified by an anchored \
             StreamSealed). This is an unrecoverable audit-integrity failure."
        ),
    }
}

/// Minimal JSON string escaping for the one variable field in the JSON
/// output (`first_broken_stream`). Escapes `"`, `\`, and control chars
/// per RFC 8259 §7 — enough for an id string; the rest of the object is
/// fixed-shape integers/enums.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Summary counts for the one-line / JSON output and the log line.
/// Pure data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifySummary {
    pub report: ChainReport,
    pub streams_verified: usize,
    pub rows_read: usize,
    /// Wire id of the first stream a break was found in, if any (for the
    /// `error!` log + JSON; the precise position/reason is in the
    /// per-stream verdict).
    pub first_broken_stream: Option<String>,
}

impl VerifySummary {
    /// Render the human-readable one-liner.
    fn to_text(&self) -> String {
        format!(
            "verify-event-chain: result={} streams={} rows={}{}",
            result_label(self.report),
            self.streams_verified,
            self.rows_read,
            match &self.first_broken_stream {
                Some(s) => format!(" first_broken_stream={s}"),
                None => String::new(),
            }
        )
    }

    /// Render the machine-readable JSON line for CI. Hand-built (no
    /// `serde_json` runtime dep in `hort-server`): the only variable-shape
    /// field is `first_broken_stream`, a stream id from the
    /// `"{category}-{uuid}"` closed grammar (no JSON metacharacters);
    /// it is still escaped defensively via [`json_escape`] so a
    /// hypothetical `--stream` value with a quote cannot break the line.
    fn to_json(&self) -> String {
        let broken = match &self.first_broken_stream {
            Some(s) => format!("\"{}\"", json_escape(s)),
            None => "null".to_string(),
        };
        format!(
            "{{\"result\":\"{}\",\"streams_verified\":{},\"rows_read\":{},\
             \"first_broken_stream\":{}}}",
            result_label(self.report),
            self.streams_verified,
            self.rows_read,
            broken
        )
    }

    fn render(&self, format: OutputFormat) -> String {
        match format {
            OutputFormat::Text => self.to_text(),
            OutputFormat::Json => self.to_json(),
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Entry point. Builds a Tokio runtime, runs [`run_async`], maps the
/// [`VerifySummary`] to the exit code via [`report_to_exit_code`].
pub fn run(args: VerifyEventChainArgs) -> ExitCode {
    let fail_on_missing = args.fail_on_missing_checkpoint;
    super::run_with_runtime(
        move || run_async(args),
        move |summary| report_to_exit_code(summary.report, fail_on_missing),
    )
}

async fn run_async(args: VerifyEventChainArgs) -> anyhow::Result<VerifySummary> {
    // DB-only subcommand → MinimalConfig (same pattern as
    // reconcile-groups). The runtime DML DSN is read from
    // `HORT_DATABASE_URL`, falling back to bare `DATABASE_URL` —
    // identical to the serve path and the worker.
    let cfg = MinimalConfig::from_env().context("parsing environment")?;
    telemetry::init_tracing(cfg.log_format)?;

    // The full Config carries the storage backend (for the anchor
    // object store). MinimalConfig is the DB subset; we also parse the
    // storage config for the checkpoint anchor. Parse it independently
    // so the verifier fails loud if storage is misconfigured.
    let full = crate::config::Config::from_env().context("parsing environment (storage)")?;

    info!(
        streams = ?args.streams,
        since_global = ?args.since_global,
        format = ?args.format,
        fail_on_missing_checkpoint = args.fail_on_missing_checkpoint,
        "hort-server verify-event-chain starting"
    );

    if let Some(src) = &args.checkpoint_source {
        // v1 only supports the configured anchor object store. An
        // explicit alternate source is a future item — reject loudly
        // rather than silently ignoring the operator's intent.
        anyhow::bail!(
            "--checkpoint-source is not yet supported (got {src:?}); v1 reads \
             the configured anchor object store"
        );
    }

    let pool = PgPoolOptions::new()
        .connect(&cfg.database_url)
        .await
        .context("connecting to postgres (runtime DML DSN)")?;

    // All `sqlx` lives behind this adapter — the verifier itself
    // depends only on the
    // backend-agnostic `EventChainReaderPort`. The pool is cloned (cheap
    // — `PgPool` is an `Arc` handle) so the same connection pool also
    // backs the liveness-breadcrumb writer below.
    let jobs_repo = PgJobsRepository::new(pool.clone());
    let reader = PgEventChainReader::new(pool);

    // Build the checkpoint anchor read adapter from the same storage
    // backend the server uses. Reuses `build_s3_object_store` (ADR 0010
    // TLS posture); the verifier never constructs its own reqwest
    // client. Filesystem-backed deployments have no object store to
    // anchor to — the anchor read then yields no checkpoints, which the
    // pure core correctly maps to `missing_checkpoint`.
    let anchor = build_anchor(&full).await?;

    // The anchor-staleness window cadence — from config (default hourly),
    // not hardcoded. MUST match the deployment's `eventstore-checkpoint`
    // CronJob cadence.
    let cadence = Duration::from_secs(full.event_chain_checkpoint_cadence_secs);

    let summary = verify(&reader, &args, anchor.as_ref(), cadence).await?;

    // Single emitter — once per run, here.
    emit_metric(summary.report);
    log_report(summary.report, &summary);
    println!("{}", summary.render(args.format));

    // Record this run's completion so
    // the boot-time `hort_event_chain_verify_overdue` gauge can later
    // attest the verifier is live (the producer half). Recorded for
    // every terminal verdict (Ok / Broken / MissingCheckpoint) — all three
    // mean "the verifier ran to completion", which is exactly the liveness
    // fact the gauge tracks. An operational error (DB unreachable, etc.)
    // bailed earlier via `?` and records nothing — correct, the run did
    // not complete. The write is **observability, not fail-closed**: a
    // recording failure is logged and swallowed, never blocking the
    // verify verdict (mirrors the staging-sweep liveness posture and the
    // CLI's own "a chain break is a verdict, not an Err" discipline).
    use hort_domain::ports::jobs_repository::JobsRepository as _;
    if let Err(e) = jobs_repo
        .record_run_completion("verify-event-chain", chrono::Utc::now())
        .await
    {
        warn!(
            error = %e,
            "could not record the verify-event-chain run completion — the \
             hort_event_chain_verify_overdue liveness gauge may show stale/overdue \
             despite this run completing. The verify verdict itself is unaffected."
        );
    }

    Ok(summary)
}

/// Build the `CheckpointAnchorPort` read adapter. Returns an
/// `Arc<dyn CheckpointAnchorPort>`. For a filesystem storage backend
/// (no object store) the anchor is `None` — the verifier then reports
/// `missing_checkpoint` (a correct, spec-defined verdict when no anchor
/// is configured/deployed).
async fn build_anchor(
    cfg: &crate::config::Config,
) -> anyhow::Result<Arc<dyn CheckpointAnchorPort>> {
    let extra_trust_anchors =
        composition::read_extra_ca_bundle().map_err(|e| anyhow::anyhow!("extra CA bundle: {e}"))?;

    match &cfg.storage {
        StorageConfig::S3 {
            bucket,
            region,
            endpoint,
            force_path_style,
            allow_http,
            access_key_id,
            secret_access_key,
            sse_mode,
        } => {
            let opts = S3StorageOpts {
                bucket,
                region,
                endpoint: endpoint.as_deref(),
                force_path_style: *force_path_style,
                allow_http: *allow_http,
                access_key: access_key_id,
                secret_key: secret_access_key,
                extra_trust_anchors: extra_trust_anchors.as_ref(),
                sse_mode: sse_mode.as_ref().map(crate::config::S3SseMode::to_adapter),
            };
            let store = build_s3_object_store(&opts)
                .map_err(|e| anyhow::anyhow!("building anchor object store: {e}"))?;
            let public_key_pem = read_anchor_public_key()?;
            let adapter = ObjectStoreCheckpointAnchor::new(store, &public_key_pem)
                .map_err(|e| anyhow::anyhow!("anchor adapter: {e}"))?;
            Ok(Arc::new(adapter))
        }
        StorageConfig::Filesystem { .. } => {
            // No object store to anchor checkpoints in. The verifier
            // still runs the per-stream chain check; the anchor
            // cross-check resolves to `missing_checkpoint`.
            Ok(Arc::new(NoAnchor))
        }
    }
}

/// Operator-provisioned anchor public-key PEM file. Read from
/// `HORT_EVENT_CHAIN_ANCHOR_PUBKEY_FILE`.
fn read_anchor_public_key() -> anyhow::Result<String> {
    let path = std::env::var("HORT_EVENT_CHAIN_ANCHOR_PUBKEY_FILE").context(
        "HORT_EVENT_CHAIN_ANCHOR_PUBKEY_FILE must point to the operator-provisioned \
         anchor Ed25519 SPKI public-key PEM",
    )?;
    std::fs::read_to_string(&path).with_context(|| format!("reading anchor public key file {path}"))
}

/// Null anchor: no checkpoints (filesystem backend / no object store).
/// The pure core maps an empty checkpoint set to `MissingCheckpoint`.
struct NoAnchor;

impl CheckpointAnchorPort for NoAnchor {
    fn read_all(
        &self,
    ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<Vec<Checkpoint>>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

// ---------------------------------------------------------------------------
// The verify orchestration (I/O via the port + pure-core composition)
// ---------------------------------------------------------------------------

/// The explicit `--stream` allow-list, de-duplicated and sorted for a
/// reproducible run. Applied **by the caller** (no DB read) before the
/// port is consulted — the port's
/// [`list_stream_ids`](EventChainReaderPort::list_stream_ids) covers only
/// the "verify all / `--since-global`" path (per the port doc, the
/// allow-list is the caller's concern).
fn explicit_stream_ids(streams: &[String]) -> Vec<String> {
    let mut s: Vec<String> = streams
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    s.sort();
    s
}

/// Compose the pure core over the reads the [`EventChainReaderPort`]
/// performs: per-stream `verify_stream_chain`, the anchor cross-check
/// `verify_against_checkpoint` (fed the **real** `StreamSealed` records
/// from the audit-meta stream), then `roll_up`. All `sqlx` lives behind
/// the port; the pure verdict logic is entirely `hort-domain`.
///
/// `cadence` is the anchor-staleness window input — from config (default
/// hourly), not hardcoded.
async fn verify(
    reader: &dyn EventChainReaderPort,
    args: &VerifyEventChainArgs,
    anchor: &dyn CheckpointAnchorPort,
    cadence: Duration,
) -> anyhow::Result<VerifySummary> {
    // Stream selection: the explicit `--stream` allow-list short-circuits
    // the DB read; otherwise the port lists ids (optionally filtered by
    // `--since-global`, a *stream-selection* filter — each selected
    // stream is still read from genesis by the adapter).
    let stream_ids = if args.streams.is_empty() {
        reader
            .list_stream_ids(args.since_global)
            .await
            .map_err(|e| anyhow::anyhow!("listing stream ids: {e}"))?
    } else {
        explicit_stream_ids(&args.streams)
    };

    let mut stream_verdicts = Vec::with_capacity(stream_ids.len());
    let mut live_heads: Vec<(String, u64, EventHash)> = Vec::new();
    let mut rows_read = 0usize;
    let mut first_broken_stream: Option<String> = None;

    for sid in &stream_ids {
        let rows: Vec<ChainRow> = reader
            .read_stream_chain(sid)
            .await
            .map_err(|e| anyhow::anyhow!("reading stream {sid}: {e}"))?;
        rows_read += rows.len();
        let views: Vec<StreamRow<'_>> = rows.iter().map(ChainRow::as_stream_row).collect();
        let verdict = verify_stream_chain(&StreamRows::new(&views));
        match &verdict {
            StreamVerdict::Ok { head, position } => {
                // Only record a real head (a non-empty stream). An empty
                // result for a named stream contributes no live head.
                if *position != u64::MAX {
                    live_heads.push((sid.clone(), *position, *head));
                }
            }
            StreamVerdict::Broken { .. } => {
                if first_broken_stream.is_none() {
                    first_broken_stream = Some(sid.clone());
                }
            }
            StreamVerdict::SealedGap { .. } => {}
        }
        stream_verdicts.push(verdict);
    }

    // Read anchored checkpoints (read-only, signature-verified by the
    // adapter). An operational failure (store unreachable) bubbles as
    // Err → exit 1. An empty set is valid → MissingCheckpoint.
    let checkpoints = anchor
        .read_all()
        .await
        .map_err(|e| anyhow::anyhow!("reading anchored checkpoints: {e}"))?;

    // The anchor cross-check's `StreamSealed` records, read through the
    // port from `StreamId::eventstore_retention()` (the retention sweep
    // emits them, anchored by a checkpoint that post-dates the seal). Empty is
    // valid (nothing sealed yet). This is the input the pre-amendment
    // code hardcoded to `Vec::new()`, which left the sealed-stream
    // cross-check branches (`UnsealedAbsentStream` justification +
    // `SealUnanchored`) unreachable from `verify`.
    let sealed = reader
        .read_sealed_records()
        .await
        .map_err(|e| anyhow::anyhow!("reading StreamSealed records: {e}"))?;

    let anchor_verdict = verify_against_checkpoint(
        &live_heads,
        &sealed,
        &checkpoints,
        chrono::Utc::now(),
        cadence,
    );

    let report = roll_up(&stream_verdicts, &anchor_verdict);
    Ok(VerifySummary {
        report,
        streams_verified: stream_ids.len(),
        rows_read,
        first_broken_stream,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use metrics_util::{CompositeKey, MetricKind};

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: super::super::Command,
    }

    fn parsed(argv: &[&str]) -> VerifyEventChainArgs {
        let mut v = vec!["hort-server", "verify-event-chain"];
        v.extend_from_slice(argv);
        let cli = TestCli::try_parse_from(v).unwrap();
        let super::super::Command::VerifyEventChain(args) = cli.command else {
            panic!("expected VerifyEventChain");
        };
        args
    }

    // -- CLI parsing -------------------------------------------------------

    #[test]
    fn parses_with_defaults() {
        let a = parsed(&[]);
        assert!(a.streams.is_empty());
        assert!(a.since_global.is_none());
        assert!(a.checkpoint_source.is_none());
        assert_eq!(a.format, OutputFormat::Text);
        assert!(a.fail_on_missing_checkpoint);
    }

    #[test]
    fn parses_repeatable_stream_and_since_global() {
        let a = parsed(&[
            "--stream",
            "authorization-a",
            "--stream",
            "admin-b",
            "--since-global",
            "42",
        ]);
        assert_eq!(a.streams, vec!["authorization-a", "admin-b"]);
        assert_eq!(a.since_global, Some(42));
    }

    #[test]
    fn parses_json_format_and_fail_flag_false() {
        let a = parsed(&["--format", "json", "--fail-on-missing-checkpoint", "false"]);
        assert_eq!(a.format, OutputFormat::Json);
        assert!(!a.fail_on_missing_checkpoint);
    }

    #[test]
    fn rejects_unknown_format() {
        let err =
            TestCli::try_parse_from(["hort-server", "verify-event-chain", "--format", "yaml"])
                .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidValue);
    }

    #[test]
    fn rejects_non_numeric_since_global() {
        let err = TestCli::try_parse_from([
            "hort-server",
            "verify-event-chain",
            "--since-global",
            "soon",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
    }

    #[test]
    fn help_renders_all_args() {
        let err =
            TestCli::try_parse_from(["hort-server", "verify-event-chain", "--help"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
        let r = err.to_string();
        assert!(r.contains("stream"));
        assert!(r.contains("since-global"));
        assert!(r.contains("checkpoint-source"));
        assert!(r.contains("format"));
        assert!(r.contains("fail-on-missing-checkpoint"));
    }

    // -- Exit-code mapping: all 4 codes ------------------------------------

    #[test]
    fn ok_maps_to_success() {
        assert_eq!(
            format!("{:?}", report_to_exit_code(ChainReport::Ok, true)),
            format!("{:?}", ExitCode::SUCCESS)
        );
    }

    #[test]
    fn broken_maps_to_exit_2() {
        assert_eq!(
            format!("{:?}", report_to_exit_code(ChainReport::Broken, true)),
            format!("{:?}", ExitCode::from(2))
        );
        // The flag does not affect Broken.
        assert_eq!(
            format!("{:?}", report_to_exit_code(ChainReport::Broken, false)),
            format!("{:?}", ExitCode::from(2))
        );
    }

    #[test]
    fn missing_checkpoint_maps_to_exit_3_when_failing() {
        assert_eq!(
            format!(
                "{:?}",
                report_to_exit_code(ChainReport::MissingCheckpoint, true)
            ),
            format!("{:?}", ExitCode::from(3))
        );
    }

    #[test]
    fn missing_checkpoint_maps_to_success_when_not_failing() {
        // Operator spot-check: --fail-on-missing-checkpoint=false.
        assert_eq!(
            format!(
                "{:?}",
                report_to_exit_code(ChainReport::MissingCheckpoint, false)
            ),
            format!("{:?}", ExitCode::SUCCESS)
        );
    }

    // Operational error (exit 1) is the `Err` → run_with_runtime
    // FAILURE path, not a ChainReport — covered by run_with_runtime's
    // own tests + the anyhow bail in run_async; asserted here as the
    // contract that no ChainReport maps to FAILURE.
    #[test]
    fn no_chain_report_maps_to_exit_1() {
        for (r, f) in [
            (ChainReport::Ok, true),
            (ChainReport::Broken, true),
            (ChainReport::MissingCheckpoint, true),
            (ChainReport::MissingCheckpoint, false),
        ] {
            assert_ne!(
                format!("{:?}", report_to_exit_code(r, f)),
                format!("{:?}", ExitCode::FAILURE),
                "exit 1 is reserved for operational Err, never a verdict"
            );
        }
    }

    // -- result_label ------------------------------------------------------

    #[test]
    fn result_labels_are_the_three_catalog_values() {
        assert_eq!(result_label(ChainReport::Ok), "ok");
        assert_eq!(result_label(ChainReport::Broken), "broken");
        assert_eq!(
            result_label(ChainReport::MissingCheckpoint),
            "missing_checkpoint"
        );
    }

    // -- Metric: DebuggingRecorder catalog test ---------------------------

    type MetricEntry = (
        CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    );

    fn counter_for<'a>(entries: &'a [MetricEntry], result: &str) -> Option<&'a DebugValue> {
        entries.iter().find_map(|(ck, _, _, dv)| {
            if ck.kind() != MetricKind::Counter || ck.key().name() != METRIC_NAME {
                return None;
            }
            ck.key()
                .labels()
                .any(|l| l.key() == "result" && l.value() == result)
                .then_some(dv)
        })
    }

    fn capture(report: ChainReport) -> Vec<MetricEntry> {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || emit_metric(report));
        snapshotter.snapshot().into_vec()
    }

    #[test]
    fn metric_fires_with_result_ok() {
        let e = capture(ChainReport::Ok);
        let v = counter_for(&e, "ok").expect("ok counter absent");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
        // Exactly one series, exactly one increment.
        assert!(counter_for(&e, "broken").is_none());
        assert!(counter_for(&e, "missing_checkpoint").is_none());
    }

    #[test]
    fn metric_fires_with_result_broken() {
        let e = capture(ChainReport::Broken);
        let v = counter_for(&e, "broken").expect("broken counter absent");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
    }

    #[test]
    fn metric_fires_with_result_missing_checkpoint() {
        let e = capture(ChainReport::MissingCheckpoint);
        let v = counter_for(&e, "missing_checkpoint").expect("missing_checkpoint counter absent");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
    }

    // -- VerifySummary rendering ------------------------------------------

    #[test]
    fn summary_text_render_ok() {
        let s = VerifySummary {
            report: ChainReport::Ok,
            streams_verified: 3,
            rows_read: 12,
            first_broken_stream: None,
        };
        assert_eq!(
            s.render(OutputFormat::Text),
            "verify-event-chain: result=ok streams=3 rows=12"
        );
    }

    #[test]
    fn summary_text_render_broken_names_stream() {
        let s = VerifySummary {
            report: ChainReport::Broken,
            streams_verified: 2,
            rows_read: 5,
            first_broken_stream: Some("authorization-x".into()),
        };
        assert_eq!(
            s.render(OutputFormat::Text),
            "verify-event-chain: result=broken streams=2 rows=5 \
             first_broken_stream=authorization-x"
        );
    }

    #[test]
    fn summary_json_render_is_machine_readable() {
        let s = VerifySummary {
            report: ChainReport::MissingCheckpoint,
            streams_verified: 1,
            rows_read: 0,
            first_broken_stream: None,
        };
        let v: serde_json::Value = serde_json::from_str(&s.render(OutputFormat::Json)).unwrap();
        assert_eq!(v["result"], "missing_checkpoint");
        assert_eq!(v["streams_verified"], 1);
        assert_eq!(v["rows_read"], 0);
        assert_eq!(v["first_broken_stream"], serde_json::Value::Null);
    }

    #[test]
    fn summary_json_broken_carries_stream() {
        let s = VerifySummary {
            report: ChainReport::Broken,
            streams_verified: 1,
            rows_read: 9,
            first_broken_stream: Some("admin-z".into()),
        };
        let v: serde_json::Value = serde_json::from_str(&s.render(OutputFormat::Json)).unwrap();
        assert_eq!(v["result"], "broken");
        assert_eq!(v["first_broken_stream"], "admin-z");
    }

    // -- explicit_stream_ids: --stream allow-list dedup + sort ------------

    #[test]
    fn explicit_stream_ids_dedups_and_sorts() {
        let got = explicit_stream_ids(&[
            "authorization-b".into(),
            "admin-a".into(),
            "authorization-b".into(),
        ]);
        assert_eq!(
            got,
            vec!["admin-a".to_string(), "authorization-b".to_string()]
        );
    }

    #[test]
    fn explicit_stream_ids_empty_is_empty() {
        assert!(explicit_stream_ids(&[]).is_empty());
    }

    // -- log_report does not panic for any verdict ------------------------

    #[test]
    fn log_report_covers_every_arm() {
        let base = VerifySummary {
            report: ChainReport::Ok,
            streams_verified: 1,
            rows_read: 1,
            first_broken_stream: None,
        };
        log_report(ChainReport::Ok, &base);
        log_report(ChainReport::MissingCheckpoint, &base);
        log_report(
            ChainReport::Broken,
            &VerifySummary {
                report: ChainReport::Broken,
                first_broken_stream: Some("s".into()),
                ..base.clone()
            },
        );
    }

    #[test]
    fn no_anchor_yields_empty_checkpoints() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let cps = rt.block_on(async { NoAnchor.read_all().await.unwrap() });
        assert!(cps.is_empty());
    }

    // =====================================================================
    // DB-backed integration tests for the orchestration path
    // (`verify` over the `EventChainReaderPort`).
    //
    // Coverage gap these close: nothing else exercises
    // the real SQL + keyset pagination + `TryFrom<EventRow>` + pure-core
    // composition end-to-end. That gap once hid a
    // `--since-global` regression — every unit test above is pure and
    // never touches the per-row `global_position` predicate. The SQL
    // lives in
    // `PgEventChainReader`; these tests drive `verify` with a real
    // `PgEventChainReader` over a live pool — NOT mocks.
    //
    // Isolation: each test gets its OWN freshly-migrated throwaway DB via
    // `hort_adapters_postgres::test_support::isolated_db_from` (the same
    // helper the adapter suites use). This is REQUIRED, not just hygiene:
    // `verify` now reads the *real* `StreamSealed` records from the global
    // `eventstore_retention` stream via the port — on a shared CI DB that
    // stream carries sibling-suite seals, which a per-test `FixedAnchor`
    // does not anchor, so the cross-check would (correctly) report
    // `SealUnanchored` → `Broken` and break these otherwise-correct tests.
    // An isolated DB starts with an empty retention stream, so seals are
    // exactly what the test itself seeds. `None` (DATABASE_URL unset / DB
    // unreachable) ⇒ silent early return so `--lib` stays green locally.
    // Streams are seeded through the *real* `PgEventStore::append` path so
    // the stored chain hashes are exactly what production writes.
    // =====================================================================
    use hort_adapters_postgres::event_chain_reader::PgEventChainReader;
    use hort_adapters_postgres::event_store::PgEventStore;
    use hort_domain::events::{
        Actor, ApiActor, ArtifactIngested, DomainEvent, IngestSource, StreamId, StreamSealed,
    };
    use hort_domain::ports::event_chain_reader::EventChainReaderPort;
    use hort_domain::ports::event_store::{
        AppendEvents, EventStore, EventToAppend, ExpectedVersion,
    };
    use serial_test::serial;
    use sqlx::Row;

    /// Test staleness cadence (the production default; these tests pin
    /// fresh anchors so staleness never trips).
    const TEST_CADENCE: Duration = Duration::from_secs(3600);

    async fn maybe_pool() -> Option<sqlx::PgPool> {
        // bare `DATABASE_URL` is read here INTENTIONALLY:
        // this is the Tier-2 test-helper / sqlx-tooling fallback that the
        // canonical `HORT_DATABASE_URL` precedence keeps alive (NOT a
        // straggler). The operator/runtime DSN read lives in `MinimalConfig`.
        let url = std::env::var("DATABASE_URL").ok()?;
        let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .expect("migrations run cleanly against the test DB");
        Some(pool)
    }

    /// A test `CheckpointAnchorPort` returning a fixed, already-verified
    /// set of `Checkpoint`s (signature verification is the adapter's
    /// concern; the *port* yields verified domain values). Used to drive
    /// the anchor cross-check to `Ok` so the roll-up is `ChainReport::Ok`
    /// — with `NoAnchor` the verdict would (correctly) be
    /// `MissingCheckpoint`, which is its own test below.
    struct FixedAnchor(Vec<Checkpoint>);
    impl CheckpointAnchorPort for FixedAnchor {
        fn read_all(
            &self,
        ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<Vec<Checkpoint>>>
        {
            let cps = self.0.clone();
            Box::pin(async move { Ok(cps) })
        }
    }

    /// Append `n` events to a fresh artifact stream via the real
    /// `PgEventStore::append` path. Returns the wire-form stream id.
    async fn seed_stream(pool: &sqlx::PgPool, n: usize) -> String {
        let store = PgEventStore::new(pool.clone())
            .await
            .expect("PgEventStore::new");
        let artifact_id = uuid::Uuid::new_v4();
        let stream = StreamId::artifact(artifact_id);
        let hash: hort_domain::types::ContentHash =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .parse()
                .expect("static SHA-256");
        for i in 0..n {
            let expected = if i == 0 {
                ExpectedVersion::NoStream
            } else {
                ExpectedVersion::Exact((i - 1) as u64)
            };
            let batch = AppendEvents {
                stream_id: stream.clone(),
                expected_version: expected,
                events: vec![EventToAppend::new(DomainEvent::ArtifactIngested(
                    ArtifactIngested {
                        artifact_id,
                        repository_id: uuid::Uuid::new_v4(),
                        name: format!("verify-it-{artifact_id}-{i}"),
                        version: Some(format!("1.0.{i}")),
                        sha256: hash.clone(),
                        size_bytes: 8,
                        source: IngestSource::Direct,
                        metadata: serde_json::Value::Null,
                        metadata_blob: None,
                        upstream_published_at: None,
                    },
                ))],
                correlation_id: uuid::Uuid::new_v4(),
                causation_id: None,
                actor: Actor::Api(ApiActor {
                    user_id: uuid::Uuid::new_v4(),
                }),
            };
            store.append(batch).await.expect("seed append");
        }
        stream.to_string()
    }

    /// Read back the head `event_hash` + final `stream_position` +
    /// genesis `global_position` for a seeded stream straight from the
    /// table, so the test anchor can mirror the head the real append
    /// path computed.
    async fn stream_head(pool: &sqlx::PgPool, stream_id: &str) -> (EventHash, u64, u64) {
        let row = sqlx::query(
            "SELECT event_hash, stream_position, global_position \
             FROM events WHERE stream_id = $1 \
             ORDER BY stream_position DESC LIMIT 1",
        )
        .bind(stream_id)
        .fetch_one(pool)
        .await
        .expect("read head row");
        let head_bytes: Vec<u8> = row.get("event_hash");
        let head = EventHash(head_bytes.try_into().expect("event_hash is 32 bytes"));
        let pos: i64 = row.get("stream_position");
        let genesis_gp: i64 = sqlx::query(
            "SELECT global_position FROM events WHERE stream_id = $1 \
             ORDER BY stream_position ASC LIMIT 1",
        )
        .bind(stream_id)
        .fetch_one(pool)
        .await
        .expect("read genesis row")
        .get("global_position");
        (head, pos as u64, genesis_gp as u64)
    }

    fn anchor_for(stream_id: &str, head: EventHash, final_pos: u64) -> FixedAnchor {
        FixedAnchor(vec![Checkpoint {
            chain_format_version: "hort-evchain/v1".into(),
            checkpoint_seq: 1,
            created_at: chrono::Utc::now(),
            stream_heads: vec![(stream_id.to_string(), final_pos, head)],
            sealed_streams: Vec::new(),
        }])
    }

    fn args_for(stream_id: &str, since_global: Option<u64>) -> VerifyEventChainArgs {
        VerifyEventChainArgs {
            streams: vec![stream_id.to_string()],
            since_global,
            checkpoint_source: None,
            format: OutputFormat::Json,
            fail_on_missing_checkpoint: true,
        }
    }

    /// Clean chained stream + matching anchor → `ChainReport::Ok`,
    /// exit 0, `result="ok"`. Exercises the real SELECT + keyset paging
    /// + `TryFrom<EventRow>` + `verify_stream_chain`/`roll_up`.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn verify_clean_chained_stream_is_ok() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let sid = seed_stream(&pool, 2).await;
        let (head, final_pos, _genesis_gp) = stream_head(&pool, &sid).await;
        let anchor = anchor_for(&sid, head, final_pos);
        let args = args_for(&sid, None);

        let summary = verify(
            &PgEventChainReader::new(pool.clone()),
            &args,
            &anchor,
            TEST_CADENCE,
        )
        .await
        .unwrap();
        assert_eq!(summary.report, ChainReport::Ok);
        assert_eq!(result_label(summary.report), "ok");
        assert_eq!(
            format!("{:?}", report_to_exit_code(summary.report, true)),
            format!("{:?}", ExitCode::SUCCESS)
        );
        assert_eq!(summary.rows_read, 2);
        assert!(summary.first_broken_stream.is_none());
    }

    /// A tampered stored row → `ChainReport::Broken`, exit 2,
    /// `result="broken"`. The events table is append-only (BEFORE
    /// UPDATE/DELETE trigger), so to simulate real on-disk tampering the
    /// test (as the table owner) disables the immutability trigger,
    /// rewrites one `event_hash` byte-vector to a wrong value, then
    /// re-enables it. The verifier then recomputes the chain over the
    /// real SELECT and the pure core detects the mismatch.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn verify_tampered_row_is_broken() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let sid = seed_stream(&pool, 3).await;
        let (head, final_pos, _) = stream_head(&pool, &sid).await;

        sqlx::query("ALTER TABLE events DISABLE TRIGGER events_immutable")
            .execute(&pool)
            .await
            .expect("disable immutability trigger (test owns the table)");
        // Flip the genesis row's event_hash to a value that cannot be
        // the real SHA-256 — the successor's prev_event_hash now dangles.
        let tamper = sqlx::query(
            "UPDATE events SET event_hash = $1 \
             WHERE stream_id = $2 AND stream_position = 0",
        )
        .bind(vec![0xABu8; 32])
        .bind(&sid)
        .execute(&pool)
        .await;
        sqlx::query("ALTER TABLE events ENABLE TRIGGER events_immutable")
            .execute(&pool)
            .await
            .expect("re-enable immutability trigger");
        tamper.expect("tamper UPDATE applied while trigger disabled");

        // Anchor matches the (untampered) head value we read earlier;
        // the break must be detected by the per-stream chain check, not
        // the anchor cross-check, so this isolates the per-stream chain path.
        let anchor = anchor_for(&sid, head, final_pos);
        let args = args_for(&sid, None);

        let summary = verify(
            &PgEventChainReader::new(pool.clone()),
            &args,
            &anchor,
            TEST_CADENCE,
        )
        .await
        .unwrap();
        assert_eq!(summary.report, ChainReport::Broken);
        assert_eq!(result_label(summary.report), "broken");
        assert_eq!(
            format!("{:?}", report_to_exit_code(summary.report, true)),
            format!("{:?}", ExitCode::from(2))
        );
        assert_eq!(summary.first_broken_stream.as_deref(), Some(sid.as_str()));
    }

    /// Empty anchor store → `ChainReport::MissingCheckpoint`: exit 3
    /// with `--fail-on-missing-checkpoint` (default), exit 0 without.
    /// The per-stream chain is intact (clean seed) so the only reason
    /// for the verdict is the absent checkpoint.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn verify_empty_anchor_is_missing_checkpoint() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let sid = seed_stream(&pool, 2).await;
        let args = args_for(&sid, None);

        let summary = verify(
            &PgEventChainReader::new(pool.clone()),
            &args,
            &NoAnchor,
            TEST_CADENCE,
        )
        .await
        .unwrap();
        assert_eq!(summary.report, ChainReport::MissingCheckpoint);
        assert_eq!(result_label(summary.report), "missing_checkpoint");
        assert_eq!(
            format!("{:?}", report_to_exit_code(summary.report, true)),
            format!("{:?}", ExitCode::from(3))
        );
        assert_eq!(
            format!("{:?}", report_to_exit_code(summary.report, false)),
            format!("{:?}", ExitCode::SUCCESS)
        );
    }

    /// **Critical #1 regression guard.** A ≥3-event stream verified with
    /// `--since-global <mid>` where `mid` is strictly above the genesis
    /// event's `global_position` must still produce `ChainReport::Ok`.
    ///
    /// Pre-fix, the per-stream read applied `AND global_position > $mid`
    /// to the per-row read, so `verify_stream_chain` received a suffix
    /// whose first row had `stream_position != 0` →
    /// `StreamVerdict::Broken{PositionGap}` → `ChainReport::Broken` →
    /// exit 2 + `result="broken"`: a false integrity alarm on the
    /// headline incremental-verify path. The per-stream read now always
    /// starts from genesis (in `PgEventChainReader::read_stream_chain`);
    /// `--since-global` is a stream-*selection* filter only. This
    /// assertion (`report == Ok`, not `Broken`) is the regression guard.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn since_global_above_genesis_still_ok_regression() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let sid = seed_stream(&pool, 4).await;
        let (head, final_pos, genesis_gp) = stream_head(&pool, &sid).await;
        // `mid` strictly above the genesis row's global_position — the
        // exact condition that made the pre-fix per-row predicate slice
        // off the genesis row.
        let mid = genesis_gp + 1;
        let anchor = anchor_for(&sid, head, final_pos);
        let args = args_for(&sid, Some(mid));

        let summary = verify(
            &PgEventChainReader::new(pool.clone()),
            &args,
            &anchor,
            TEST_CADENCE,
        )
        .await
        .unwrap();
        assert_eq!(
            summary.report,
            ChainReport::Ok,
            "since-global must select the stream then verify it from \
             genesis; a per-row global_position filter would slice off \
             stream_position 0 and yield a false Broken (Critical #1)"
        );
        assert_eq!(result_label(summary.report), "ok");
        // The full stream is still read (from genesis), not a suffix.
        assert_eq!(summary.rows_read, 4);
    }

    /// **Inclusive boundary regression guard.** `EventChainReaderPort::list_stream_ids`
    /// with `--since-global N` must select a stream whose genesis activity
    /// is *exactly* at `global_position == N` (`>= N`, not `> N`). Pre-fix
    /// the predicate was `global_position > $1` with `$1 = N` (i.e.
    /// `>= N+1`), silently dropping such a stream. This test seeds a stream,
    /// reads its genesis `global_position`, then asks the reader for the
    /// `--since-global == that position` set (the adapter's DB query now
    /// owns this boundary) and asserts the stream is in it.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn list_stream_ids_since_global_is_inclusive_regression() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let sid = seed_stream(&pool, 1).await;
        let (_, _, genesis_gp) = stream_head(&pool, &sid).await;

        let reader = PgEventChainReader::new(pool.clone());
        // since_global == the stream's exact genesis global_position.
        let ids = reader.list_stream_ids(Some(genesis_gp)).await.unwrap();
        assert!(
            ids.iter().any(|s| s == &sid),
            "a stream whose only activity is exactly at global_position \
             == N must be selected by --since-global N (>= N, inclusive); \
             pre-fix `> N` dropped it"
        );

        // And one position above its genesis it must NOT be selected
        // (pins the boundary is exactly N, not N-1).
        let ids_above = reader.list_stream_ids(Some(genesis_gp + 1)).await.unwrap();
        assert!(
            !ids_above.iter().any(|s| s == &sid),
            "a single-event stream must NOT be selected when \
             --since-global is strictly above its only global_position"
        );
    }

    /// **Seals-present cross-check guard.**
    /// `verify` reads the *real* `StreamSealed` records
    /// through the port (a hardcoded `Vec::new()` here would leave the
    /// sealed-stream cross-check branches unreachable from `verify`).
    ///
    /// Scenario, on an isolated DB so the retention stream holds only the
    /// seal we seed: a checkpoint anchored stream `S_sealed` (head `H`),
    /// `S_sealed`'s rows are absent (sealed-then-removed), and a
    /// `StreamSealed{S_sealed, H}` record sits on the retention stream and
    /// is itself anchored by that checkpoint. The cross-check must resolve
    /// to `Ok`: the seal justifies the absent anchored stream
    /// (no `UnsealedAbsentStream`) and is itself anchored (no
    /// `SealUnanchored`).
    ///
    /// This FAILS red against the pre-amendment `sealed = Vec::new()`:
    /// with no seals read, the absent anchored `S_sealed` would be
    /// `Broken(UnsealedAbsentStream)` → `ChainReport::Broken`. So the
    /// assertion (`Ok`, not `Broken`) is exactly the previously-unreachable
    /// path the hardcoded `[]` hid.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn seals_present_justify_absent_anchored_stream_is_ok() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        // A real, present, clean stream (so `verify` also exercises a live
        // head that matches the checkpoint).
        let live_sid = seed_stream(&pool, 2).await;
        let (live_head, live_pos, _) = stream_head(&pool, &live_sid).await;

        // The sealed-then-removed stream: never seeded into `events`, so
        // it is absent. Its identity + head live only in the seal record
        // and the checkpoint.
        let sealed_sid = StreamId::artifact(uuid::Uuid::new_v4()).to_string();
        let sealed_head = [0x5eu8; 32];

        // Seed the StreamSealed tombstone on the retention stream via the
        // real append path (the retention sweep's emitter shape).
        let store = PgEventStore::new(pool.clone())
            .await
            .expect("PgEventStore::new");
        store
            .append(AppendEvents {
                stream_id: StreamId::eventstore_retention(),
                expected_version: ExpectedVersion::Any,
                events: vec![EventToAppend::new(DomainEvent::StreamSealed(
                    StreamSealed {
                        sealed_stream_id: sealed_sid.clone(),
                        sealed_stream_category: "artifact".into(),
                        final_stream_position: 0,
                        final_event_hash: sealed_head,
                        event_count: 1,
                        retention_policy_id: uuid::Uuid::nil(),
                        actor_id: None,
                    },
                ))],
                correlation_id: uuid::Uuid::new_v4(),
                causation_id: None,
                actor: hort_domain::events::system_actor(),
            })
            .await
            .expect("seal append");

        // A checkpoint that anchors BOTH the live stream's head AND the
        // sealed stream's head, and records the seal — so the seal is
        // provably anchored and the absent stream is justified.
        let anchor = FixedAnchor(vec![Checkpoint {
            chain_format_version: "hort-evchain/v1".into(),
            checkpoint_seq: 1,
            created_at: chrono::Utc::now(),
            stream_heads: vec![
                (live_sid.clone(), live_pos, live_head),
                (sealed_sid.clone(), 0, EventHash(sealed_head)),
            ],
            sealed_streams: vec![hort_domain::events::SealedStreamRecord {
                sealed_stream_id: sealed_sid.clone(),
                final_event_hash: EventHash(sealed_head),
            }],
        }]);

        // Verify all streams (no `--stream`): {live_sid, retention stream}
        // are present + verified; `sealed_sid` is absent. The seal read
        // from the retention stream feeds the cross-check.
        let args = VerifyEventChainArgs {
            streams: vec![],
            since_global: None,
            checkpoint_source: None,
            format: OutputFormat::Json,
            fail_on_missing_checkpoint: true,
        };
        let summary = verify(
            &PgEventChainReader::new(pool.clone()),
            &args,
            &anchor,
            TEST_CADENCE,
        )
        .await
        .unwrap();
        assert_eq!(
            summary.report,
            ChainReport::Ok,
            "a sealed-then-removed anchored stream must be justified by the \
             real StreamSealed record read through the port; pre-amendment \
             `sealed = Vec::new()` would mis-report UnsealedAbsentStream → Broken"
        );
    }
}
