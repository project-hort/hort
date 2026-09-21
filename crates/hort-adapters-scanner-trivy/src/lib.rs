//! Trivy [`ScannerPort`] adapter (CLI).
//!
//! `TrivyAdapter` implements [`ScannerPort`](hort_domain::ports::scanner::ScannerPort)
//! by shelling out to the `trivy` CLI. The adapter owns its workspace
//! lifecycle: it materialises the artifact's bytes into a
//! `tempfile::TempDir` (auto-removed on drop, including the panic and
//! error paths) in the shape the scanner's analyzers expect, invokes
//! `trivy`, parses the JSON output, and reports what came of it.
//!
//! # Materialisation is the evidence
//!
//! Trivy selects analyzers by file name, extension and directory layout,
//! and it does not open archives. A directory holding one opaque blob
//! therefore yields a report with no `Results` — which, read as a finding
//! list, is an empty one, indistinguishable from a clean scan. So the
//! adapter materialises **by artifact kind**: a Java archive keeps its
//! extension, a POM becomes `pom.xml`, an npm tarball is planted under
//! `node_modules/<name>/`, wheels and sdists and `.crate` files are
//! extracted, an OCI layer becomes a root filesystem.
//!
//! The **subcommand** comes from the kind too, and for the same reason.
//! Trivy's coverage matrix runs each analyzer under only some of its four
//! targets: a post-build artifact (Java archive, wheel/egg,
//! `package.json` under `node_modules`) is claimed by the Image and
//! Rootfs targets, a pre-build declaration (`pom.xml`, lockfiles) by
//! Filesystem and Repository. Pointing `trivy fs` at a JAR runs no
//! analyzer at all. [`workspace`] holds the table and the reasoning.
//!
//! # "Nothing analysable" is not "clean"
//!
//! The adapter distinguishes three outcomes, which is why
//! [`ScannerPort::scan`] returns
//! [`ScanAnalysis`](hort_domain::ports::scanner::ScanAnalysis) rather
//! than a bare finding list:
//!
//! - **A verdict** — Trivy reported at least one analysed target. The
//!   finding list, empty or not, is the verdict.
//! - **Nothing to analyse** — no materialisation applies to this kind, the
//!   payload's container could not be safely opened, or Trivy returned a
//!   report with no `Results` at all. There is no verdict. An empty
//!   report from an `fs`-mode invocation is a surface that went
//!   unassessed, so the orchestrator holds the artifact fail-closed (ADR
//!   0007) rather than recording a clean scan of bytes nothing examined.
//!   An empty report from a `rootfs`-mode invocation is different: that
//!   target runs every analyzer over the whole tree, so an empty result
//!   means the tree has no package surface at all — a completed "not
//!   applicable" fact, not a hold.
//! - **A failure** — the binary is missing, the child timed out, the
//!   report blew its cap. `Err`, and retryable.
//!
//! Module layout:
//! - [`severity`] — Trivy severity string → `SeverityThreshold` (pure)
//! - [`purl`] — Trivy `Type` + `PkgName` + `InstalledVersion` → PURL (pure)
//! - [`parse`] — Trivy JSON wire types + finding mapper (pure)
//! - [`extract`] — bounded, path-safe archive extraction
//! - [`workspace`] — materialisation by kind (adapter-internal I/O)
//! - this module — `TrivyAdapter` itself + the `ScannerPort` impl
//!
//! See `docs/architecture/explanation/scanning-pipeline.md`.

mod extract;
mod parse;
mod purl;
mod severity;
mod workspace;

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::scanner::{
    NotAnalysable, ScanAnalysis, ScanTarget, ScannerPort, SCAN_REPORT_TOO_LARGE_MARKER,
};
use hort_domain::ports::storage::StoragePort;
use hort_domain::ports::BoxFuture;
use hort_domain::types::{Finding, Sbom};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

use crate::parse::{aggregate_findings, parse_trivy_report};
use crate::workspace::{materialise, Materialised, ScanMode};

/// Drain `pipe` into a `Vec`, bounded to
/// `cap + 1` bytes via [`AsyncReadExt::take`]. Returns the drained
/// buffer and whether the cap was *tripped* (i.e. the source had more
/// than `cap` bytes). Reading through `.take(cap + 1)` makes the
/// detection unambiguous and non-flaky: a report of exactly `cap` bytes
/// reads `cap` bytes, hits EOF, and yields `len == cap` (NOT tripped);
/// only a report strictly larger than `cap` yields `len == cap + 1`.
/// The buffer therefore never grows past `cap + 1`, so a runaway pipe
/// cannot OOM the worker. Mirrored verbatim in the OSV adapter (a
/// 2-instance template, per the design — not extracted to a shared
/// crate for only two call sites).
async fn drain_capped<R: AsyncRead + Unpin>(
    pipe: &mut R,
    cap: u64,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut buf = Vec::new();
    pipe.take(cap.saturating_add(1))
        .read_to_end(&mut buf)
        .await?;
    let tripped = buf.len() as u64 > cap;
    Ok((buf, tripped))
}

/// Drain both report pipes concurrently, each
/// bounded by [`drain_capped`], and return `(stdout, stderr, tripped)`
/// where `tripped` is true if EITHER pipe exceeded `cap`.
///
/// The moment one pipe trips we **return immediately** with
/// `tripped = true` and stop reading — the buffers are about to be
/// discarded (the scan fails closed), so there is nothing to gain by
/// finishing the sibling drain, and waiting for it is unsafe: a
/// cap-tripping child is wedged writing into the now-full pipe, and a
/// grandchild process (e.g. a `head` under `sh`) can keep the sibling
/// pipe's write-end open even after the parent is killed, so the
/// sibling drain might never EOF. Returning on first-trip makes the
/// cap-hit detection prompt and deadlock-free; the caller then kills
/// the child. When neither pipe trips, both drains hit a clean EOF on a
/// ≤ cap report and we return the full buffers. Mirrored verbatim in
/// the OSV adapter (2-instance template, not extracted for two call
/// sites).
async fn drain_both_capped<O, E>(
    stdout_pipe: &mut O,
    stderr_pipe: &mut E,
    cap: u64,
) -> std::io::Result<(Vec<u8>, Vec<u8>, bool)>
where
    O: AsyncRead + Unpin,
    E: AsyncRead + Unpin,
{
    let mut out_done: Option<Vec<u8>> = None;
    let mut err_done: Option<Vec<u8>> = None;
    let mut out_fut = std::pin::pin!(drain_capped(stdout_pipe, cap));
    let mut err_fut = std::pin::pin!(drain_capped(stderr_pipe, cap));
    while out_done.is_none() || err_done.is_none() {
        tokio::select! {
            r = &mut out_fut, if out_done.is_none() => {
                let (buf, tripped) = r?;
                if tripped {
                    return Ok((buf, Vec::new(), true));
                }
                out_done = Some(buf);
            }
            r = &mut err_fut, if err_done.is_none() => {
                let (buf, tripped) = r?;
                if tripped {
                    return Ok((Vec::new(), buf, true));
                }
                err_done = Some(buf);
            }
        }
    }
    Ok((
        out_done.expect("loop exits with stdout drained"),
        err_done.expect("loop exits with stderr drained"),
        false,
    ))
}

// ---------------------------------------------------------------------------
// Public parser entry point
// ---------------------------------------------------------------------------

/// Parse a `trivy <fs|rootfs> --format json` document and return the lowered
/// [`Finding`] list, applying the same per-finding cap filter
/// [`TrivyAdapter::scan`] applies.
///
/// Exposed publicly for fixture-based testing (the adapter's own
/// integration tests in `tests/` consume this) and for any future
/// caller that needs to re-parse a Trivy report archived elsewhere.
/// `Err(DomainError::Validation)` on malformed JSON.
pub fn parse_findings_from_json(stdout: &[u8]) -> DomainResult<Vec<Finding>> {
    let report = parse_trivy_report(stdout)
        .map_err(|e| DomainError::Validation(format!("trivy adapter: malformed JSON: {e}")))?;
    Ok(aggregate_findings(&report))
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Static configuration for [`TrivyAdapter`]. The composition root
/// populates these from `HORT_SCANNER_TRIVY_*` envvars.
#[derive(Debug, Clone)]
pub struct TrivyConfig {
    /// Path to the `trivy` binary. Default: `trivy` (resolved via
    /// `PATH`).
    pub trivy_bin: PathBuf,
    /// Override path for Trivy's vulnerability DB cache. `None` →
    /// Trivy uses its compiled-in default (`~/.cache/trivy` or
    /// `/var/cache/trivy` depending on user).
    pub db_dir: Option<PathBuf>,
    /// Per-scan timeout. Passed to the `trivy --timeout` CLI flag
    /// (Trivy's own cooperative deadline) **and** used as the
    /// Rust-side `tokio::time::timeout` backstop in
    /// [`TrivyAdapter::run_scan`] — if `trivy` hangs before honouring
    /// its own `--timeout`, the adapter kills the child after this
    /// duration. Default: 5 minutes.
    pub timeout: Duration,
    /// Maximum artifact size, in bytes, that the adapter will
    /// stream into a scan workspace. `prepare_workspace` streams the
    /// CAS bytes to the temp file with a running byte count; if the
    /// copy would exceed this cap it is aborted and the artifact is
    /// rejected *pre-scan* with a `DomainError::Invariant`. This is a
    /// DoS / worker-OOM backstop — a multi-GB OCI layer (or a storage
    /// stream that never EOFs) can no longer be buffered/written
    /// unbounded. Default: 8 GiB — large enough not to false-positive
    /// on real-world OCI layers (which are typically well under 1 GiB
    /// per layer, with multi-GB layers rare and operator-tunable via
    /// `HORT_SCANNER_TRIVY_MAX_ARTIFACT_SIZE`), small enough that
    /// a single oversize artifact cannot exhaust a worker's memory or
    /// scratch disk.
    pub max_artifact_size: u64,
    /// Maximum scan-*report* size, in bytes, that the adapter will drain
    /// from the child's stdout/stderr. `run_scan` wraps each pipe in
    /// `.take(max_report_size + 1)` before `read_to_end`; if either
    /// drain reads more than the cap the child is killed and the scan is
    /// failed with a distinguishable
    /// [`SCAN_REPORT_TOO_LARGE_MARKER`](hort_domain::ports::scanner::SCAN_REPORT_TOO_LARGE_MARKER)
    /// error → `ScanIndeterminate` (fail-closed; never serve-unscanned,
    /// ADR 0007). This is the report-side complement to the input-copy
    /// cap: input is bounded during the CAS→tempfile copy; this bounds
    /// the *output* drain so a scanner emitting a huge (adversarial or
    /// buggy) report can no longer OOM the worker before the wall-clock
    /// timeout fires. Default: 256 MiB — comfortably above any
    /// legitimate findings JSON, operator-tunable via the shared
    /// `HORT_SCANNER_MAX_REPORT_SIZE` knob.
    pub max_report_size: u64,
    /// Trivy `--severity` filter. Default: every band — `CRITICAL`,
    /// `HIGH`, `MEDIUM`, `LOW`. The orchestrator further filters by
    /// `ScanPolicy.severity_threshold`; this CLI flag only trims the
    /// lower tail to keep the JSON output small.
    pub severity_filter: Vec<&'static str>,
    /// Path to a merged CA bundle (system roots + operator's
    /// `HORT_EXTRA_CA_BUNDLE` contents) that the adapter sets as
    /// `SSL_CERT_FILE` on every spawned `trivy` invocation (ADR 0010).
    /// `None` (the default) leaves the spawned process's trust store
    /// untouched — Trivy then uses Go's default
    /// `/etc/ssl/certs/ca-certificates.crt`. The worker boot path
    /// (`hort_worker::extra_ca::read_and_propagate`) is what populates
    /// this when an extra-CA bundle is configured.
    pub subprocess_ca_bundle: Option<PathBuf>,
}

impl Default for TrivyConfig {
    fn default() -> Self {
        Self {
            trivy_bin: PathBuf::from("trivy"),
            db_dir: None,
            timeout: Duration::from_secs(300),
            // 8 GiB. See field doc for the sizing rationale.
            max_artifact_size: 8 * 1024 * 1024 * 1024,
            // 256 MiB report-drain cap. See field doc.
            max_report_size: 256 * 1024 * 1024,
            severity_filter: vec!["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            subprocess_ca_bundle: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

/// Outbound adapter implementing [`ScannerPort`] via the Trivy CLI.
pub struct TrivyAdapter {
    config: TrivyConfig,
    storage: Arc<dyn StoragePort>,
}

impl TrivyAdapter {
    /// Construct the adapter from a [`TrivyConfig`] and a `StoragePort`
    /// handle. The composition root wires `storage` to the same CAS
    /// the server writes to so the worker reads identical bytes.
    pub fn new(config: TrivyConfig, storage: Arc<dyn StoragePort>) -> Self {
        Self { config, storage }
    }

    /// Build the argv vector for `trivy <fs|rootfs> --format json …`.
    /// Pulled out of [`Self::run_scan`] so it is unit-testable without
    /// touching the real binary.
    ///
    /// The subcommand comes from the materialisation: an extracted image
    /// layer is a root filesystem, and only `trivy rootfs` runs the
    /// OS-package analyzers over it
    /// (<https://trivy.dev/latest/docs/target/rootfs/>). Every other flag
    /// is identical between the two targets.
    fn scan_argv(&self, mode: ScanMode, target_dir: &str) -> Vec<String> {
        let mut argv: Vec<String> = vec![
            mode.subcommand().to_string(),
            "--format".to_string(),
            "json".to_string(),
            "--quiet".to_string(),
            "--timeout".to_string(),
            format!("{}s", self.config.timeout.as_secs()),
        ];
        if !self.config.severity_filter.is_empty() {
            argv.push("--severity".to_string());
            argv.push(self.config.severity_filter.join(","));
        }
        if let Some(db_dir) = &self.config.db_dir {
            argv.push("--cache-dir".to_string());
            argv.push(db_dir.to_string_lossy().into_owned());
        }
        argv.push(target_dir.to_string());
        argv
    }

    /// Build the argv for the `trivy --version` health probe.
    fn health_argv(&self) -> Vec<String> {
        vec!["--version".to_string()]
    }

    /// Apply the `subprocess_ca_bundle` (if configured) as
    /// `SSL_CERT_FILE` on the supplied [`Command`]. Centralised so
    /// the scan and health-check paths stay in sync.
    fn apply_subprocess_ca(&self, cmd: &mut Command) {
        if let Some(path) = self.config.subprocess_ca_bundle.as_ref() {
            cmd.env("SSL_CERT_FILE", path);
        }
    }

    /// Run the Trivy CLI against `target_dir`, return the parsed
    /// report.
    ///
    /// **Timeout enforcement.** Trivy's own `--timeout` CLI
    /// flag is cooperative defence-in-depth; it is the inner deadline.
    /// The outer guarantee is a Rust-side `tokio::time::timeout` of
    /// the same duration around the spawned child: if `trivy` hangs
    /// before honouring its own `--timeout`, we `child.kill().await`
    /// and surface `DomainError::Invariant("trivy adapter: scan
    /// exceeded timeout (Ns)")`. Wording is kept uniform with the OSV
    /// adapter so operators see one cross-backend surface. The shape
    /// mirrors `OsvScannerAdapter::run_scan`: spawn the child, take
    /// owned `stdout`/`stderr` pipes, race a single future that
    /// drains both pipes and awaits `child.wait()` against the
    /// timeout. The existing Trivy-side "cancel/deadline exceeded"
    /// stderr heuristic is preserved and now coexists with the hard
    /// Rust timeout (the cooperative path still produces the tuned
    /// message; the Rust timeout is the backstop for a true hang).
    /// On success returns the parsed report **and the child's stderr**.
    /// Trivy under `--quiet` still writes DB-download progress, analyzer
    /// warnings and "no such file" complaints there, and that text is the
    /// only evidence available when the report comes back with no
    /// analysed target — so it is carried out rather than dropped.
    async fn run_scan(
        &self,
        mode: ScanMode,
        target_dir: &str,
    ) -> DomainResult<(parse::TrivyReport, Vec<u8>)> {
        tracing::debug!(
            scanner = "trivy",
            bin = %self.config.trivy_bin.display(),
            subcommand = mode.subcommand(),
            "trivy adapter: invoking CLI"
        );
        let mut cmd = Command::new(&self.config.trivy_bin);
        cmd.args(self.scan_argv(mode, target_dir))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        self.apply_subprocess_ca(&mut cmd);
        let mut child = cmd.spawn().map_err(|e| {
            DomainError::Invariant(format!(
                "trivy adapter: trivy binary not found at {}: {}",
                self.config.trivy_bin.display(),
                e
            ))
        })?;

        // Take owned pipe handles so `child.wait()` can run alongside
        // the drain futures without `wait_with_output` consuming the
        // Child (which would block the timeout branch from killing it).
        let mut stdout_pipe = child
            .stdout
            .take()
            .expect("Stdio::piped guarantees stdout handle");
        let mut stderr_pipe = child
            .stderr
            .take()
            .expect("Stdio::piped guarantees stderr handle");

        let timeout_duration = self.config.timeout;
        let max_report_size = self.config.max_report_size;
        // Bound BOTH report pipes. Each pipe is drained through
        // `drain_capped` (`.take(cap + 1)`); we do NOT await
        // `child.wait()` inside this race, because a cap-tripping child
        // keeps writing into a now-full pipe and never exits — racing
        // `child.wait()` here would mask the cap-hit as a wall-clock
        // timeout. A cap-tripping child also never closes the *other*
        // pipe (it is wedged on the full one), so we cannot simply
        // `join!` both drains to EOF either: the instant one drain
        // trips we must kill the child so the sibling drain unblocks.
        // `drain_both_capped` does exactly that — it returns as soon as
        // a trip is observed (after killing the child) or once both
        // pipes hit a clean EOF on a ≤ cap report.
        let drain = drain_both_capped(&mut stdout_pipe, &mut stderr_pipe, max_report_size);

        let (stdout_buf, stderr_buf, report_tripped) =
            match tokio::time::timeout(timeout_duration, drain).await {
                Ok(Ok(triple)) => triple,
                Ok(Err(e)) => {
                    let _ = child.kill().await;
                    return Err(DomainError::Invariant(format!(
                        "trivy adapter: failed to read scan output: {e}"
                    )));
                }
                Err(_elapsed) => {
                    // Rust-side timeout fired before Trivy honoured its
                    // own `--timeout` — terminate the child.
                    // `kill().await` is best-effort: even if it fails
                    // (child already exited in the race window) we
                    // still surface the timeout to the caller.
                    let _ = child.kill().await;
                    tracing::warn!(
                        scanner = "trivy",
                        timeout_secs = timeout_duration.as_secs(),
                        "trivy adapter: scan exceeded Rust-side timeout; killed child"
                    );
                    return Err(DomainError::Invariant(format!(
                        "trivy adapter: scan exceeded timeout ({}s)",
                        timeout_duration.as_secs()
                    )));
                }
            };

        if report_tripped {
            // The report drain hit the cap. Kill the child (it is
            // blocked writing into a full pipe) and fail the scan CLOSED.
            // `info!` (audit, not error): the scanner kind + the byte cap,
            // never the artifact id (high-cardinality / tracing-only).
            let _ = child.kill().await;
            tracing::info!(
                scanner = "trivy",
                max_report_bytes = max_report_size,
                "trivy adapter: scan report exceeded byte cap; killed child (fail-closed)"
            );
            return Err(DomainError::Invariant(format!(
                "trivy adapter: {SCAN_REPORT_TOO_LARGE_MARKER} ({max_report_size} bytes); killed child"
            )));
        }

        let status = match tokio::time::timeout(timeout_duration, child.wait()).await {
            Ok(Ok(status)) => status,
            Ok(Err(e)) => {
                let _ = child.kill().await;
                return Err(DomainError::Invariant(format!(
                    "trivy adapter: failed to await child exit: {e}"
                )));
            }
            Err(_elapsed) => {
                let _ = child.kill().await;
                tracing::warn!(
                    scanner = "trivy",
                    timeout_secs = timeout_duration.as_secs(),
                    "trivy adapter: scan exceeded Rust-side timeout; killed child"
                );
                return Err(DomainError::Invariant(format!(
                    "trivy adapter: scan exceeded timeout ({}s)",
                    timeout_duration.as_secs()
                )));
            }
        };

        if !status.success() {
            let stderr = String::from_utf8_lossy(&stderr_buf).into_owned();
            // Heuristic timeout detection: Trivy emits "context
            // canceled" / "context deadline exceeded" on its own
            // `--timeout` (cooperative) path. Map those to a distinct
            // "exceeded timeout" message so operators can tune. This
            // coexists with the hard Rust timeout above — the Rust
            // timeout is the outer guarantee; this is the inner
            // cooperative-deadline message.
            let lower = stderr.to_lowercase();
            if lower.contains("cancel")
                || lower.contains("deadline exceeded")
                || lower.contains("context canceled")
            {
                return Err(DomainError::Invariant(format!(
                    "trivy adapter: scan exceeded timeout: {}",
                    stderr.trim()
                )));
            }
            return Err(DomainError::Invariant(format!(
                "trivy adapter: scan failed (exit {}): {}",
                status,
                stderr.trim()
            )));
        }

        let report = parse_trivy_report(&stdout_buf)
            .map_err(|e| DomainError::Validation(format!("trivy adapter: malformed JSON: {e}")))?;
        Ok((report, stderr_buf))
    }
}

/// Bytes of the child's stderr carried into the "no analysed target"
/// diagnostic.
const STDERR_TAIL_BYTES: usize = 1024;

/// The tail of a captured stderr buffer, for one log field.
///
/// The **tail** rather than the head because Trivy's last words are the
/// ones about the scan that just produced nothing; the earlier bytes are
/// DB bookkeeping. Lossy UTF-8 decoding is deliberate: the cut can land
/// mid-codepoint, and a replacement character at the front of a
/// diagnostic is better than dropping the diagnostic.
fn stderr_tail(stderr: &[u8]) -> String {
    let start = stderr.len().saturating_sub(STDERR_TAIL_BYTES);
    String::from_utf8_lossy(&stderr[start..]).trim().to_string()
}

impl ScannerPort for TrivyAdapter {
    fn name(&self) -> &str {
        "trivy"
    }

    /// Trivy's half of the scanner capability map, answered from this
    /// adapter's own materialisation truth: a format is analysable when
    /// one of its artifact kinds has a materialisation plan *and* a
    /// known-vulnerable fixture of that format has been shown to yield a
    /// finding through it. [`workspace::format_is_analysable`] holds the
    /// table and names the evidence test behind each cell.
    fn applies_to(&self, format: &str) -> bool {
        workspace::format_is_analysable(format)
    }

    fn scan<'a>(
        &'a self,
        target: &'a ScanTarget<'a>,
        _sbom: Option<&'a Sbom>,
    ) -> BoxFuture<'a, DomainResult<ScanAnalysis>> {
        Box::pin(async move {
            // 1. Materialise by kind into a TempDir. RAII drop on
            //    success / error / panic removes the directory tree. A
            //    kind with no materialisation, or a payload whose
            //    container cannot be safely opened, ends here with no
            //    verdict — never with an empty finding list.
            let (ws, mode) =
                match materialise(&self.storage, target, self.config.max_artifact_size).await? {
                    Materialised::Ready { ws, mode } => (ws, mode),
                    Materialised::Nothing(reason) => {
                        return Ok(ScanAnalysis::NothingAnalysable(reason));
                    }
                };
            let dir = ws.dir().to_string_lossy().into_owned();

            // 2. Run Trivy against the materialised tree.
            let (report, stderr) = self.run_scan(mode, &dir).await?;

            // 3. No `Results` section at all means no analyzer claimed
            //    anything in the workspace — Trivy found nothing to
            //    analyse, which is NOT the same fact as "analysed and
            //    found no vulnerabilities" (that comes back as a
            //    `Results` entry with an empty `Vulnerabilities` list).
            //    Collapsing the two is the defect this distinction
            //    exists to remove: the first has no verdict to give.
            if report.results.is_empty() {
                // The two facts that make either branch's log actionable:
                // what the scanner said on its way to saying nothing, and
                // what the tree it was pointed at actually contained.
                // Without them the two outcomes below are indistinguishable
                // from a materialisation this adapter got wrong.
                //
                // Both are computed *before* the macros: a `.await` inside
                // `warn!`/`info!` would hold the event's `Arguments` across
                // it and make the whole future non-`Send`.
                let materialised = ws.listing().await;
                match mode {
                    // `rootfs` runs every OS-package, language and binary
                    // analyzer over the whole extracted tree. An empty
                    // report there is not a pairing mismatch — it is the
                    // analyzers agreeing the tree has no package surface at
                    // all, which is a completed fact about the artifact,
                    // not an unassessed one. The listing is still worth
                    // keeping for an operator who doubts that fact, so it
                    // moves to `debug!` instead of dropping out of the log
                    // entirely.
                    ScanMode::Rootfs => {
                        tracing::debug!(
                            scanner = "trivy",
                            kind = target.kind.as_str(),
                            materialised,
                            "trivy adapter: root filesystem listing"
                        );
                        tracing::info!(
                            scanner = "trivy",
                            kind = target.kind.as_str(),
                            format = target.format,
                            subcommand = mode.subcommand(),
                            stderr_tail = stderr_tail(&stderr),
                            skipped_links = ws.skipped_links(),
                            "trivy adapter: root filesystem walked, no package surface — nothing to assess"
                        );
                        return Ok(ScanAnalysis::NothingAnalysable(
                            NotAnalysable::NotApplicable,
                        ));
                    }
                    // `fs` targets one artifact whose analyzer either
                    // engages or does not; an empty report here means the
                    // surface this kind was materialised for went
                    // unassessed, which still fails closed.
                    ScanMode::Fs => {
                        tracing::warn!(
                            scanner = "trivy",
                            kind = target.kind.as_str(),
                            format = target.format,
                            subcommand = mode.subcommand(),
                            stderr_tail = stderr_tail(&stderr),
                            materialised,
                            skipped_links = ws.skipped_links(),
                            "trivy adapter: report carries no analysed target; no verdict"
                        );
                        return Ok(ScanAnalysis::NothingAnalysable(
                            NotAnalysable::NoAnalyzerMatched,
                        ));
                    }
                }
            }

            // 4. Lower into Vec<Finding>. Findings that fail
            //    Finding::validate are dropped with tracing::warn!
            //    inside aggregate_findings.
            let findings = aggregate_findings(&report);

            tracing::info!(
                scanner = "trivy",
                content_hash = %target.content_hash,
                kind = target.kind.as_str(),
                subcommand = mode.subcommand(),
                analysed_targets = report.results.len(),
                finding_count = findings.len(),
                "trivy adapter: scan completed"
            );

            // 5. ws drops here — TempDir cleanup runs.
            Ok(ScanAnalysis::Analysed(findings))
        })
    }

    fn health_check(&self) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async move {
            let mut cmd = Command::new(&self.config.trivy_bin);
            cmd.args(self.health_argv())
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            self.apply_subprocess_ca(&mut cmd);
            let output = cmd.output().await.map_err(|e| {
                DomainError::Invariant(format!(
                    "trivy adapter: trivy binary not found at {}: {}",
                    self.config.trivy_bin.display(),
                    e
                ))
            })?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(DomainError::Invariant(format!(
                    "trivy adapter: --version exit {} ({})",
                    output.status,
                    stderr.trim()
                )));
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    use hort_domain::ports::storage::{PutResult, StoragePort as P};
    use hort_domain::ports::BoxFuture as Bf;
    use hort_domain::types::{ByteRange, ContentHash as Ch};
    use tokio::io::AsyncRead;

    /// Serializes every write-then-exec fixture in this test binary. An
    /// executable's write descriptor stays open (and inherited across a
    /// fork) until whichever process holds it execs or closes it — so a
    /// second thread that forks a child while our script is still open for
    /// writing can keep that descriptor alive in the child even after we
    /// close our own handle, and our own later exec of the same path fails
    /// with `ETXTBSY`. Held from script creation through the `scan`/
    /// `run_scan` call that execs it, so no other thread in this process
    /// can fork while a script is open for writing.
    static SCRIPT_WRITE_GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// What the one test storage stub does when the adapter calls `get`.
    /// Every other `StoragePort` method is unreachable in these tests, so
    /// one impl with a behaviour selector replaces what would otherwise be
    /// five near-identical stubs.
    enum Get {
        /// Yield these bytes.
        Bytes(Vec<u8>),
        /// Fail the read, to assert the error propagates.
        NotFound,
        /// Panic — asserts a code path must not read storage at all.
        Forbidden,
    }

    struct StubStorage(Get);

    impl StubStorage {
        fn unused() -> Arc<Self> {
            Arc::new(Self(Get::Forbidden))
        }
        fn bytes(b: &[u8]) -> Arc<Self> {
            Arc::new(Self(Get::Bytes(b.to_vec())))
        }
    }

    impl P for StubStorage {
        fn put(&self, _s: Box<dyn AsyncRead + Send + Unpin>) -> Bf<'_, DomainResult<PutResult>> {
            Box::pin(async { unreachable!("tests never write") })
        }
        fn get(&self, _h: &Ch) -> Bf<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
            let bytes = match &self.0 {
                Get::Bytes(b) => Some(b.clone()),
                Get::NotFound => None,
                Get::Forbidden => panic!("this code path must not read storage"),
            };
            Box::pin(async move {
                match bytes {
                    Some(b) => {
                        let r: Box<dyn AsyncRead + Send + Unpin> = Box::new(Cursor::new(b));
                        Ok(r)
                    }
                    None => Err(DomainError::NotFound {
                        entity: "content",
                        id: "x".into(),
                    }),
                }
            })
        }
        fn get_range(
            &self,
            _h: &Ch,
            _r: ByteRange,
        ) -> Bf<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
            Box::pin(async { unreachable!() })
        }
        fn exists(&self, _h: &Ch) -> Bf<'_, DomainResult<bool>> {
            Box::pin(async { unreachable!() })
        }
        fn size_of(&self, _h: &Ch) -> Bf<'_, DomainResult<u64>> {
            Box::pin(async { unreachable!() })
        }
    }

    /// A Maven-JAR scan target: the only `Rootfs`-mode kind whose
    /// materialisation is a single file, so the CLI paths below are
    /// exercised without also exercising archive extraction.
    fn jar_coords() -> hort_domain::types::ArtifactCoords {
        hort_domain::types::ArtifactCoords {
            name: "com.example:app".to_string(),
            name_as_published: "com.example:app".to_string(),
            version: Some("1.0.0".to_string()),
            path: "com/example/app/1.0.0/app-1.0.0.jar".to_string(),
            format: hort_domain::entities::repository::RepositoryFormat::Maven,
            metadata: serde_json::Value::Null,
        }
    }

    /// A Maven-POM scan target: the `Fs`-mode single-file counterpart to
    /// [`jar_coords`], for cases that must pin `Fs`-mode behaviour
    /// specifically rather than `Rootfs`-mode's.
    fn pom_coords() -> hort_domain::types::ArtifactCoords {
        hort_domain::types::ArtifactCoords {
            name: "com.example:app".to_string(),
            name_as_published: "com.example:app".to_string(),
            version: Some("1.0.0".to_string()),
            path: "com/example/app/1.0.0/app-1.0.0.pom".to_string(),
            format: hort_domain::entities::repository::RepositoryFormat::Maven,
            metadata: serde_json::Value::Null,
        }
    }

    fn sample_hash() -> Ch {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .expect("64 hex chars parse")
    }

    fn jar_target<'a>(
        hash: &'a Ch,
        coords: &'a hort_domain::types::ArtifactCoords,
    ) -> ScanTarget<'a> {
        ScanTarget {
            content_hash: hash,
            format: "maven",
            coords,
            kind: hort_domain::types::ArtifactKind::MavenJar,
        }
    }

    fn pom_target<'a>(
        hash: &'a Ch,
        coords: &'a hort_domain::types::ArtifactCoords,
    ) -> ScanTarget<'a> {
        ScanTarget {
            content_hash: hash,
            format: "maven",
            coords,
            kind: hort_domain::types::ArtifactKind::MavenPom,
        }
    }

    fn cfg() -> TrivyConfig {
        TrivyConfig {
            trivy_bin: PathBuf::from("/usr/local/bin/trivy"),
            db_dir: Some(PathBuf::from("/var/cache/trivy")),
            timeout: Duration::from_secs(120),
            max_artifact_size: 8 * 1024 * 1024 * 1024,
            max_report_size: 256 * 1024 * 1024,
            severity_filter: vec!["CRITICAL", "HIGH"],
            subprocess_ca_bundle: None,
        }
    }

    fn adapter() -> TrivyAdapter {
        TrivyAdapter::new(cfg(), StubStorage::unused())
    }

    #[test]
    fn name_is_lowercase_trivy() {
        assert_eq!(adapter().name(), "trivy");
    }

    #[test]
    fn scan_argv_starts_with_fs_subcommand() {
        let argv = adapter().scan_argv(ScanMode::Fs, "/tmp/scan");
        assert_eq!(argv[0], "fs");
    }

    #[test]
    fn scan_argv_emits_format_json() {
        let argv = adapter().scan_argv(ScanMode::Fs, "/tmp/scan");
        let i = argv.iter().position(|s| s == "--format").unwrap();
        assert_eq!(argv[i + 1], "json");
    }

    #[test]
    fn scan_argv_emits_quiet_flag() {
        let argv = adapter().scan_argv(ScanMode::Fs, "/tmp/scan");
        assert!(argv.iter().any(|s| s == "--quiet"), "argv: {argv:?}");
    }

    #[test]
    fn scan_argv_emits_severity_filter_csv() {
        let argv = adapter().scan_argv(ScanMode::Fs, "/tmp/scan");
        let i = argv.iter().position(|s| s == "--severity").unwrap();
        assert_eq!(argv[i + 1], "CRITICAL,HIGH");
    }

    #[test]
    fn scan_argv_emits_cache_dir_when_db_dir_set() {
        let argv = adapter().scan_argv(ScanMode::Fs, "/tmp/scan");
        let i = argv.iter().position(|s| s == "--cache-dir").unwrap();
        assert_eq!(argv[i + 1], "/var/cache/trivy");
    }

    #[test]
    fn scan_argv_omits_cache_dir_when_db_dir_unset() {
        let mut c = cfg();
        c.db_dir = None;
        let a = TrivyAdapter::new(c, StubStorage::unused());
        let argv = a.scan_argv(ScanMode::Fs, "/tmp/scan");
        assert!(
            !argv.iter().any(|s| s == "--cache-dir"),
            "argv must not include --cache-dir: {argv:?}"
        );
    }

    #[test]
    fn scan_argv_target_dir_is_last_argument() {
        let argv = adapter().scan_argv(ScanMode::Fs, "/tmp/scan-here");
        assert_eq!(argv.last().map(String::as_str), Some("/tmp/scan-here"));
    }

    #[test]
    fn scan_argv_emits_timeout_in_seconds() {
        let argv = adapter().scan_argv(ScanMode::Fs, "/tmp/scan");
        let i = argv.iter().position(|s| s == "--timeout").unwrap();
        assert_eq!(argv[i + 1], "120s");
    }

    #[test]
    fn scan_argv_omits_severity_filter_when_empty() {
        let mut c = cfg();
        c.severity_filter = Vec::new();
        let a = TrivyAdapter::new(c, StubStorage::unused());
        let argv = a.scan_argv(ScanMode::Fs, "/tmp/scan");
        assert!(!argv.iter().any(|s| s == "--severity"), "argv: {argv:?}");
    }

    #[test]
    fn scan_argv_uses_the_rootfs_subcommand_for_an_extracted_layer() {
        let argv = adapter().scan_argv(ScanMode::Rootfs, "/tmp/scan");
        assert_eq!(
            argv[0], "rootfs",
            "an extracted image layer is only read by the rootfs target"
        );
        // Every other flag is identical between the two targets, so the
        // rest of the argv must not drift from the `fs` form.
        let fs_argv = adapter().scan_argv(ScanMode::Fs, "/tmp/scan");
        assert_eq!(argv[1..], fs_argv[1..]);
    }

    // -- empty-report diagnostics ---------------------------------------

    #[test]
    fn stderr_tail_keeps_the_last_bytes_and_trims_whitespace() {
        assert_eq!(
            stderr_tail(b"\n  db download failed  \n"),
            "db download failed"
        );
        assert_eq!(stderr_tail(b""), "");
        let long: Vec<u8> = std::iter::repeat_n(b'a', STDERR_TAIL_BYTES)
            .chain(b"THE-LAST-WORDS".iter().copied())
            .collect();
        let tail = stderr_tail(&long);
        assert_eq!(tail.len(), STDERR_TAIL_BYTES);
        assert!(
            tail.ends_with("THE-LAST-WORDS"),
            "the tail is what Trivy said last, not what it said first"
        );
    }

    /// A cut landing mid-codepoint must not cost the diagnostic. Lossy
    /// decoding turns the partial byte into a replacement character and
    /// the rest of the text survives.
    #[test]
    fn stderr_tail_survives_a_cut_inside_a_multibyte_character() {
        let mut bytes = vec![b'z'; STDERR_TAIL_BYTES];
        bytes.extend_from_slice("é ok".as_bytes());
        let tail = stderr_tail(&bytes);
        assert!(tail.ends_with("ok"), "{tail}");
    }

    #[test]
    fn health_argv_is_just_version() {
        assert_eq!(adapter().health_argv(), vec!["--version".to_string()]);
    }

    #[test]
    fn default_config_uses_trivy_bin_and_full_severity_set() {
        let c = TrivyConfig::default();
        assert_eq!(c.trivy_bin, PathBuf::from("trivy"));
        assert!(c.db_dir.is_none());
        assert_eq!(c.timeout, Duration::from_secs(300));
        assert_eq!(c.severity_filter, vec!["CRITICAL", "HIGH", "MEDIUM", "LOW"]);
        // Default artifact-size cap is a few GB: large enough not to
        // false-positive on real OCI layers, small enough to keep a
        // single hung/oversize artifact from OOM-ing the worker.
        assert_eq!(c.max_artifact_size, 8 * 1024 * 1024 * 1024);
        // Default report-drain cap is 256 MiB: comfortably above any
        // legitimate findings JSON, small enough that a runaway /
        // adversarial report cannot OOM the worker before the wall-clock
        // timeout fires.
        assert_eq!(c.max_report_size, 256 * 1024 * 1024);
        // Default leaves SSL_CERT_FILE untouched on spawned subprocesses.
        // Operators get the merged bundle by configuring
        // `HORT_EXTRA_CA_BUNDLE` at the worker boundary; that path is
        // wired in by the worker composition root.
        assert!(c.subprocess_ca_bundle.is_none());
    }

    /// When `subprocess_ca_bundle` is `Some`, `apply_subprocess_ca` sets
    /// `SSL_CERT_FILE` on the supplied Command. Without setting it
    /// (default = `None`), the env stays untouched.
    ///
    /// We can't easily inspect `Command`'s env map directly through
    /// the public API, but we CAN observe the effect end-to-end via
    /// a child that prints `${SSL_CERT_FILE:-unset}`. This keeps the
    /// test self-contained (no ghost-binary fixtures).
    #[tokio::test]
    async fn apply_subprocess_ca_sets_ssl_cert_file_when_configured() {
        // Build a minimal adapter with a known bundle path.
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let bundle_path = tmp.path().to_path_buf();
        let mut c = cfg();
        c.subprocess_ca_bundle = Some(bundle_path.clone());

        let a = TrivyAdapter::new(c, StubStorage::unused());

        // Spawn `sh -c 'echo ${SSL_CERT_FILE:-unset}'` through
        // apply_subprocess_ca to confirm the env-var lands on the
        // child. `sh` is provided by the dev sandbox; the test gate
        // skips on hosts that lack it.
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "printf %s \"${SSL_CERT_FILE:-unset}\""])
            .stdout(Stdio::piped());
        a.apply_subprocess_ca(&mut cmd);
        // dev host lacks `sh` → skip the test cleanly.
        let Ok(out) = cmd.output().await else { return };
        assert!(out.status.success(), "sh subprocess should succeed");
        let stdout = String::from_utf8(out.stdout).expect("utf-8");
        assert_eq!(
            stdout,
            bundle_path.to_string_lossy(),
            "SSL_CERT_FILE must reach the spawned subprocess"
        );
    }

    /// Default (no bundle) leaves SSL_CERT_FILE alone — the spawned
    /// subprocess inherits the parent process's value (or the absence
    /// of one), preserving the default behaviour for deployments that
    /// don't set `HORT_EXTRA_CA_BUNDLE`.
    #[tokio::test]
    async fn apply_subprocess_ca_default_leaves_ssl_cert_file_untouched() {
        let a = TrivyAdapter::new(cfg(), StubStorage::unused());

        let mut cmd = Command::new("sh");
        cmd.args(["-c", "printf %s \"${SSL_CERT_FILE:-unset}\""])
            .env_remove("SSL_CERT_FILE")
            .stdout(Stdio::piped());
        a.apply_subprocess_ca(&mut cmd);
        let Ok(out) = cmd.output().await else { return };
        assert!(out.status.success());
        let stdout = String::from_utf8(out.stdout).expect("utf-8");
        assert_eq!(
            stdout, "unset",
            "default cfg() must leave SSL_CERT_FILE unset on the spawned subprocess"
        );
    }

    // -- scan() / health_check() runtime smoke (no real binary needed) --------

    #[tokio::test]
    async fn scan_propagates_storage_get_failure() {
        let a = TrivyAdapter::new(TrivyConfig::default(), Arc::new(StubStorage(Get::NotFound)));
        let h = sample_hash();
        let c = jar_coords();
        let r = a.scan(&jar_target(&h, &c), None).await;
        assert!(matches!(r, Err(DomainError::NotFound { .. })));
    }

    #[tokio::test]
    async fn health_check_with_missing_binary_returns_invariant_error() {
        let c = TrivyConfig {
            trivy_bin: PathBuf::from("/no/such/trivy/binary/exists/here"),
            ..TrivyConfig::default()
        };
        let a = TrivyAdapter::new(c, StubStorage::unused());
        let r = a.health_check().await;
        match r {
            Err(DomainError::Invariant(msg)) => {
                assert!(msg.contains("trivy adapter"), "{msg}");
                assert!(msg.contains("not found"), "{msg}");
            }
            other => panic!("expected Invariant error, got {other:?}"),
        }
    }

    // -- bounded report drain -------------------------------------------

    use hort_domain::ports::scanner::SCAN_REPORT_TOO_LARGE_MARKER;

    /// The bounded drain stops at the cap and reports the trip.
    /// A payload strictly larger than the cap is detected (`tripped ==
    /// true`) and the buffer is bounded to `cap + 1` bytes (NOT the
    /// whole input) — no unbounded allocation.
    #[tokio::test]
    async fn drain_capped_trips_and_bounds_allocation_on_over_cap_input() {
        let cap: u64 = 16;
        // 10 KiB of input — far over the 16-byte cap.
        let mut src = Cursor::new(vec![b'x'; 10 * 1024]);
        let (buf, tripped) = drain_capped(&mut src, cap).await.expect("drain");
        assert!(tripped, "an over-cap payload must trip the cap");
        assert_eq!(
            buf.len() as u64,
            cap + 1,
            "the bounded drain must read at most cap+1 bytes, not the whole 10 KiB input"
        );
    }

    /// A payload of EXACTLY the cap does NOT false-positive: it
    /// reads `cap` bytes, hits EOF, and `tripped` stays false. This is
    /// the boundary the `.take(cap + 1)` design guarantees.
    #[tokio::test]
    async fn drain_capped_exactly_cap_bytes_does_not_trip() {
        let cap: u64 = 32;
        let mut src = Cursor::new(vec![b'y'; cap as usize]);
        let (buf, tripped) = drain_capped(&mut src, cap).await.expect("drain");
        assert!(
            !tripped,
            "a report of exactly cap bytes must NOT trip (no false positive)"
        );
        assert_eq!(buf.len() as u64, cap);
    }

    /// An under-cap payload drains fully and does not trip.
    #[tokio::test]
    async fn drain_capped_under_cap_drains_fully() {
        let cap: u64 = 1024;
        let mut src = Cursor::new(b"small report".to_vec());
        let (buf, tripped) = drain_capped(&mut src, cap).await.expect("drain");
        assert!(!tripped);
        assert_eq!(buf, b"small report");
    }

    /// When the child's stdout exceeds the configured `max_report_size`,
    /// `run_scan` kills the child and returns the
    /// distinguishable "report exceeded cap" `Invariant` error (the
    /// shape the orchestrator routes to `ScanIndeterminate`). Uses a
    /// real child: a tiny executable script that ignores its argv and
    /// floods stdout, pointed at via `trivy_bin`.
    #[tokio::test]
    async fn run_scan_over_cap_stdout_kills_child_and_returns_report_too_large() {
        // Skip cleanly on hosts without `/bin/sh` (the dev sandbox has it).
        if !std::path::Path::new("/bin/sh").exists() {
            return;
        }
        let _guard = SCRIPT_WRITE_GUARD.lock().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let script = dir.path().join("fake-trivy.sh");
        // Emit ~1 MiB of NUL bytes to stdout regardless of argv, then exit 0.
        // Write via an explicit handle we sync + drop before exec so the
        // kernel has no open writable fd on the file (avoids the
        // transient ETXTBSY race on spawn).
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .mode(0o700)
                .open(&script)
                .expect("create script");
            f.write_all(b"#!/bin/sh\nhead -c 1048576 /dev/zero\nexit 0\n")
                .expect("write script");
            f.sync_all().expect("sync script");
        }
        let c = TrivyConfig {
            trivy_bin: script.clone(),
            // 1 KiB cap, far below the ~1 MiB the script emits.
            max_report_size: 1024,
            ..TrivyConfig::default()
        };
        let a = TrivyAdapter::new(c, StubStorage::unused());
        // Retry the spawn a few times to absorb any residual ETXTBSY on
        // slow filesystems — the cap-hit behaviour is what we assert.
        let mut r = a.run_scan(ScanMode::Fs, "/tmp/ignored").await;
        for _ in 0..5 {
            match &r {
                Err(DomainError::Invariant(msg)) if msg.contains("Text file busy") => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    r = a.run_scan(ScanMode::Fs, "/tmp/ignored").await;
                }
                _ => break,
            }
        }
        match r {
            Err(DomainError::Invariant(msg)) => {
                assert!(
                    msg.contains(SCAN_REPORT_TOO_LARGE_MARKER),
                    "cap-hit error must carry the report-too-large marker: {msg}"
                );
                assert!(msg.contains("trivy adapter"), "{msg}");
            }
            other => panic!("expected report-too-large Invariant, got {other:?}"),
        }
    }

    // -- "nothing analysable" vs "clean" ----------------------------------

    /// Materialise a fake `trivy` that prints `stdout_json` and exits 0,
    /// point the adapter at it, and scan the given target.
    ///
    /// A real binary standing in for Trivy is what makes the
    /// `Results`-present / `Results`-absent distinction testable at all:
    /// it is a property of the report the child emits, not of anything
    /// the adapter can be asked directly.
    #[cfg(unix)]
    async fn scan_against_fake_trivy_target(
        stdout_json: &str,
        target: &ScanTarget<'_>,
    ) -> DomainResult<ScanAnalysis> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let _guard = SCRIPT_WRITE_GUARD.lock().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let script = dir.path().join("fake-trivy.sh");
        {
            // Write through a handle we sync and drop before exec so the
            // kernel holds no writable fd on the file (ETXTBSY).
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .mode(0o700)
                .open(&script)
                .expect("create script");
            writeln!(f, "#!/bin/sh").expect("write");
            writeln!(f, "cat <<'TRIVY_REPORT'").expect("write");
            writeln!(f, "{stdout_json}").expect("write");
            writeln!(f, "TRIVY_REPORT").expect("write");
            writeln!(f, "exit 0").expect("write");
            f.sync_all().expect("sync");
        }
        let c = TrivyConfig {
            trivy_bin: script,
            ..TrivyConfig::default()
        };
        let a = TrivyAdapter::new(c, StubStorage::bytes(b"PK\x03\x04fake payload"));
        a.scan(target, None).await
    }

    /// [`scan_against_fake_trivy_target`] against a Maven-JAR (`Rootfs`
    /// mode) target — the shape most of this module's fake-Trivy tests
    /// want.
    #[cfg(unix)]
    async fn scan_against_fake_trivy(stdout_json: &str) -> DomainResult<ScanAnalysis> {
        let h = sample_hash();
        let coords = jar_coords();
        scan_against_fake_trivy_target(stdout_json, &jar_target(&h, &coords)).await
    }

    /// A report with no `Results` section means no analyzer claimed
    /// anything in the workspace. In `Rootfs` mode that is a completed
    /// "no package surface" fact, not the absence of a verdict — it must
    /// NOT hold the artifact.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_report_with_no_results_in_rootfs_mode_is_not_applicable() {
        if !std::path::Path::new("/bin/sh").exists() {
            return;
        }
        for report in [r#"{}"#, r#"{"Results":null}"#, r#"{"Results":[]}"#] {
            let analysis = scan_against_fake_trivy(report)
                .await
                .expect("the child exited 0, so the scan itself succeeded");
            assert_eq!(
                analysis,
                ScanAnalysis::NothingAnalysable(NotAnalysable::NotApplicable),
                "report {report} over a rootfs target must read as nothing to assess, not a hold"
            );
        }
    }

    /// The `Fs`-mode counterpart: one artifact's analyzer either engages
    /// or it does not, so an empty report there stays the absence of a
    /// verdict — it must NOT come back as an empty finding list (a clean
    /// verdict) nor as `NotApplicable` (no hold).
    #[cfg(unix)]
    #[tokio::test]
    async fn a_report_with_no_results_in_fs_mode_is_nothing_analysable_not_clean() {
        if !std::path::Path::new("/bin/sh").exists() {
            return;
        }
        let h = sample_hash();
        let coords = pom_coords();
        for report in [r#"{}"#, r#"{"Results":null}"#, r#"{"Results":[]}"#] {
            let analysis = scan_against_fake_trivy_target(report, &pom_target(&h, &coords))
                .await
                .expect("the child exited 0, so the scan itself succeeded");
            assert_eq!(
                analysis,
                ScanAnalysis::NothingAnalysable(NotAnalysable::NoAnalyzerMatched),
                "report {report} over an fs target must not be read as a clean verdict"
            );
        }
    }

    /// The other side of the same distinction: a report that *does* carry
    /// an analysed target with no vulnerabilities IS a clean verdict.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_report_with_an_analysed_target_and_no_vulnerabilities_is_a_clean_verdict() {
        if !std::path::Path::new("/bin/sh").exists() {
            return;
        }
        let report = r#"{"Results":[{"Target":"app-1.0.0.jar","Class":"lang-pkgs","Type":"jar"}]}"#;
        let analysis = scan_against_fake_trivy(report).await.expect("scan");
        assert_eq!(
            analysis,
            ScanAnalysis::clean(),
            "an analysed target with no vulnerabilities is a real clean verdict"
        );
    }

    /// And a report carrying a vulnerability lowers into findings.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_report_with_a_vulnerability_is_a_verdict_with_findings() {
        if !std::path::Path::new("/bin/sh").exists() {
            return;
        }
        let report = r#"{"Results":[{"Target":"app-1.0.0.jar","Class":"lang-pkgs","Type":"jar",
            "Vulnerabilities":[{"VulnerabilityID":"CVE-2021-44228",
            "PkgName":"org.apache.logging.log4j:log4j-core",
            "InstalledVersion":"2.14.1","Severity":"CRITICAL"}]}]}"#;
        let analysis = scan_against_fake_trivy(report).await.expect("scan");
        match analysis {
            ScanAnalysis::Analysed(findings) => {
                assert_eq!(findings.len(), 1);
                assert_eq!(findings[0].vulnerability_id, "CVE-2021-44228");
            }
            other => panic!("expected a verdict with findings, got {other:?}"),
        }
    }

    /// A kind with no materialisation never spawns the CLI at all — the
    /// bogus binary path proves it, since reaching the invocation would
    /// surface as a "not found" `Invariant`.
    #[tokio::test]
    async fn an_unclaimed_kind_abstains_without_invoking_the_cli() {
        let c = TrivyConfig {
            trivy_bin: PathBuf::from("/no/such/trivy/binary/exists/here"),
            ..TrivyConfig::default()
        };
        let a = TrivyAdapter::new(c, StubStorage::unused());
        let h = sample_hash();
        let coords = jar_coords();
        let target = ScanTarget {
            content_hash: &h,
            format: "oci",
            coords: &coords,
            kind: hort_domain::types::ArtifactKind::OciManifest,
        };
        let r = a.scan(&target, None).await.expect("no CLI, no error");
        assert_eq!(
            r,
            ScanAnalysis::NothingAnalysable(NotAnalysable::NotApplicable)
        );
    }

    #[tokio::test]
    async fn scan_with_missing_binary_returns_invariant_error() {
        // Stub storage with an empty payload so we get past
        // `prepare_workspace` and into the CLI invocation.
        let c = TrivyConfig {
            trivy_bin: PathBuf::from("/no/such/trivy/binary/exists/here"),
            ..TrivyConfig::default()
        };
        let a = TrivyAdapter::new(c, StubStorage::bytes(&[]));
        let h = sample_hash();
        let c = jar_coords();
        let r = a.scan(&jar_target(&h, &c), None).await;
        assert!(matches!(r, Err(DomainError::Invariant(_))));
    }
}
