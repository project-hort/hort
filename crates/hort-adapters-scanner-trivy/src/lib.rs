//! Trivy [`ScannerPort`] adapter (filesystem mode).
//!
//! `TrivyAdapter` implements [`ScannerPort`](hort_domain::ports::scanner::ScannerPort)
//! by shelling out to the `trivy` CLI in `trivy fs --format json
//! --quiet <dir>` mode. The adapter owns its workspace lifecycle: it
//! pulls the artifact bytes from `StoragePort::get`, writes them into
//! a `tempfile::TempDir` (auto-removed on drop, including the panic
//! and error paths), invokes `trivy`, parses the JSON output, and
//! returns `Vec<Finding>`.
//!
//! Module layout:
//! - [`severity`] — Trivy severity string → `SeverityThreshold` (pure)
//! - [`purl`] — Trivy `Type` + `PkgName` + `InstalledVersion` → PURL (pure)
//! - [`parse`] — Trivy JSON wire types + finding mapper (pure)
//! - [`workspace`] — temp-dir + payload write (adapter-internal I/O)
//! - this module — `TrivyAdapter` itself + the `ScannerPort` impl
//!
//! See `docs/architecture/explanation/scanning-pipeline.md`.

mod parse;
mod purl;
mod severity;
mod workspace;

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::scanner::{ScannerPort, SCAN_REPORT_TOO_LARGE_MARKER};
use hort_domain::ports::storage::StoragePort;
use hort_domain::ports::BoxFuture;
use hort_domain::types::{ContentHash, Finding, Sbom};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

use crate::parse::{aggregate_findings, parse_trivy_report};
use crate::workspace::prepare_workspace;

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

/// Parse a `trivy fs --format json` document and return the lowered
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

/// Static configuration for [`TrivyAdapter`]. Mirrors the envvar
/// surface in §6 of the design doc — the composition root populates
/// these from `HORT_SCANNER_TRIVY_*` envvars.
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
    /// duration. Default: 5 minutes. (F-15.)
    pub timeout: Duration,
    /// F-15 — maximum artifact size, in bytes, that the adapter will
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
            // F-15 — 8 GiB. See field doc for the sizing rationale.
            max_artifact_size: 8 * 1024 * 1024 * 1024,
            // F-40 — 256 MiB report-drain cap. See field doc.
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

    /// Build the argv vector for `trivy fs --format json …`. Pulled
    /// out of [`Self::run_scan`] so it is unit-testable without
    /// touching the real binary.
    fn scan_argv(&self, target_dir: &str) -> Vec<String> {
        let mut argv: Vec<String> = vec![
            "fs".to_string(),
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
    /// report. Errors mirror the design doc's error-mapping table.
    ///
    /// **Timeout enforcement (F-15).** Trivy's own `--timeout` CLI
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
    async fn run_scan(&self, target_dir: &str) -> DomainResult<parse::TrivyReport> {
        tracing::debug!(
            scanner = "trivy",
            bin = %self.config.trivy_bin.display(),
            "trivy adapter: invoking CLI"
        );
        let mut cmd = Command::new(&self.config.trivy_bin);
        cmd.args(self.scan_argv(target_dir))
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
        // F-40 — bound BOTH report pipes. Each pipe is drained through
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
            // F-40 — the report drain hit the cap. Kill the child (it is
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

        parse_trivy_report(&stdout_buf)
            .map_err(|e| DomainError::Validation(format!("trivy adapter: malformed JSON: {e}")))
    }
}

impl ScannerPort for TrivyAdapter {
    fn name(&self) -> &str {
        "trivy"
    }

    fn scan<'a>(
        &'a self,
        content_hash: &'a ContentHash,
        _sbom: Option<&'a Sbom>,
    ) -> BoxFuture<'a, DomainResult<Vec<Finding>>> {
        Box::pin(async move {
            // 1. Materialise content into a TempDir. RAII drop on
            //    success / error / panic removes the directory tree.
            let ws = prepare_workspace(&self.storage, content_hash, self.config.max_artifact_size)
                .await?;
            let dir = ws.dir().to_string_lossy().into_owned();

            // 2. Run Trivy.
            let report = self.run_scan(&dir).await?;

            // 3. Lower into Vec<Finding>. Findings that fail
            //    Finding::validate are dropped with tracing::warn!
            //    inside aggregate_findings.
            let findings = aggregate_findings(&report);

            tracing::info!(
                scanner = "trivy",
                content_hash = %content_hash,
                finding_count = findings.len(),
                "trivy adapter: scan completed"
            );

            // 4. ws drops here — TempDir cleanup runs.
            Ok(findings)
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

    /// Storage stub used purely as a `#[cfg(test)]` placeholder where the
    /// adapter won't actually call `get`. All methods panic if invoked.
    /// Test-only stub, not a production residual.
    struct UnusedStorage;
    impl P for UnusedStorage {
        fn put(&self, _s: Box<dyn AsyncRead + Send + Unpin>) -> Bf<'_, DomainResult<PutResult>> {
            Box::pin(async { unreachable!() })
        }
        fn get(&self, _h: &Ch) -> Bf<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
            Box::pin(async { unreachable!() })
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
        TrivyAdapter::new(cfg(), Arc::new(UnusedStorage))
    }

    #[test]
    fn name_is_lowercase_trivy() {
        assert_eq!(adapter().name(), "trivy");
    }

    #[test]
    fn scan_argv_starts_with_fs_subcommand() {
        let argv = adapter().scan_argv("/tmp/scan");
        assert_eq!(argv[0], "fs");
    }

    #[test]
    fn scan_argv_emits_format_json() {
        let argv = adapter().scan_argv("/tmp/scan");
        let i = argv.iter().position(|s| s == "--format").unwrap();
        assert_eq!(argv[i + 1], "json");
    }

    #[test]
    fn scan_argv_emits_quiet_flag() {
        let argv = adapter().scan_argv("/tmp/scan");
        assert!(argv.iter().any(|s| s == "--quiet"), "argv: {argv:?}");
    }

    #[test]
    fn scan_argv_emits_severity_filter_csv() {
        let argv = adapter().scan_argv("/tmp/scan");
        let i = argv.iter().position(|s| s == "--severity").unwrap();
        assert_eq!(argv[i + 1], "CRITICAL,HIGH");
    }

    #[test]
    fn scan_argv_emits_cache_dir_when_db_dir_set() {
        let argv = adapter().scan_argv("/tmp/scan");
        let i = argv.iter().position(|s| s == "--cache-dir").unwrap();
        assert_eq!(argv[i + 1], "/var/cache/trivy");
    }

    #[test]
    fn scan_argv_omits_cache_dir_when_db_dir_unset() {
        let mut c = cfg();
        c.db_dir = None;
        let a = TrivyAdapter::new(c, Arc::new(UnusedStorage));
        let argv = a.scan_argv("/tmp/scan");
        assert!(
            !argv.iter().any(|s| s == "--cache-dir"),
            "argv must not include --cache-dir: {argv:?}"
        );
    }

    #[test]
    fn scan_argv_target_dir_is_last_argument() {
        let argv = adapter().scan_argv("/tmp/scan-here");
        assert_eq!(argv.last().map(String::as_str), Some("/tmp/scan-here"));
    }

    #[test]
    fn scan_argv_emits_timeout_in_seconds() {
        let argv = adapter().scan_argv("/tmp/scan");
        let i = argv.iter().position(|s| s == "--timeout").unwrap();
        assert_eq!(argv[i + 1], "120s");
    }

    #[test]
    fn scan_argv_omits_severity_filter_when_empty() {
        let mut c = cfg();
        c.severity_filter = Vec::new();
        let a = TrivyAdapter::new(c, Arc::new(UnusedStorage));
        let argv = a.scan_argv("/tmp/scan");
        assert!(!argv.iter().any(|s| s == "--severity"), "argv: {argv:?}");
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
        // F-15 — default artifact-size cap is a few GB: large enough
        // not to false-positive on real OCI layers, small enough to
        // keep a single hung/oversize artifact from OOM-ing the worker.
        assert_eq!(c.max_artifact_size, 8 * 1024 * 1024 * 1024);
        // F-40 — default report-drain cap is 256 MiB: comfortably above
        // any legitimate findings JSON, small enough that a runaway /
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

        let a = TrivyAdapter::new(c, Arc::new(UnusedStorage));

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
        let a = TrivyAdapter::new(cfg(), Arc::new(UnusedStorage));

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
        struct ErrStorage;
        impl P for ErrStorage {
            fn put(
                &self,
                _s: Box<dyn AsyncRead + Send + Unpin>,
            ) -> Bf<'_, DomainResult<PutResult>> {
                Box::pin(async { unreachable!() })
            }
            fn get(&self, _h: &Ch) -> Bf<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
                Box::pin(async {
                    Err(DomainError::NotFound {
                        entity: "content",
                        id: "x".into(),
                    })
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
        let a = TrivyAdapter::new(TrivyConfig::default(), Arc::new(ErrStorage));
        let h: Ch = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap();
        let r = a.scan(&h, None).await;
        assert!(matches!(r, Err(DomainError::NotFound { .. })));
    }

    #[tokio::test]
    async fn health_check_with_missing_binary_returns_invariant_error() {
        let c = TrivyConfig {
            trivy_bin: PathBuf::from("/no/such/trivy/binary/exists/here"),
            ..TrivyConfig::default()
        };
        let a = TrivyAdapter::new(c, Arc::new(UnusedStorage));
        let r = a.health_check().await;
        match r {
            Err(DomainError::Invariant(msg)) => {
                assert!(msg.contains("trivy adapter"), "{msg}");
                assert!(msg.contains("not found"), "{msg}");
            }
            other => panic!("expected Invariant error, got {other:?}"),
        }
    }

    // -- F-40 bounded report drain --------------------------------------

    use hort_domain::ports::scanner::SCAN_REPORT_TOO_LARGE_MARKER;

    /// F-40 — the bounded drain stops at the cap and reports the trip.
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

    /// F-40 — a payload of EXACTLY the cap does NOT false-positive: it
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

    /// F-40 — an under-cap payload drains fully and does not trip.
    #[tokio::test]
    async fn drain_capped_under_cap_drains_fully() {
        let cap: u64 = 1024;
        let mut src = Cursor::new(b"small report".to_vec());
        let (buf, tripped) = drain_capped(&mut src, cap).await.expect("drain");
        assert!(!tripped);
        assert_eq!(buf, b"small report");
    }

    /// F-40 — when the child's stdout exceeds the configured
    /// `max_report_size`, `run_scan` kills the child and returns the
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
        let a = TrivyAdapter::new(c, Arc::new(UnusedStorage));
        // Retry the spawn a few times to absorb any residual ETXTBSY on
        // slow filesystems — the cap-hit behaviour is what we assert.
        let mut r = a.run_scan("/tmp/ignored").await;
        for _ in 0..5 {
            match &r {
                Err(DomainError::Invariant(msg)) if msg.contains("Text file busy") => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    r = a.run_scan("/tmp/ignored").await;
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

    #[tokio::test]
    async fn scan_with_missing_binary_returns_invariant_error() {
        // Stub storage with an empty payload so we get past
        // `prepare_workspace` and into the CLI invocation.
        struct OkStorage;
        impl P for OkStorage {
            fn put(
                &self,
                _s: Box<dyn AsyncRead + Send + Unpin>,
            ) -> Bf<'_, DomainResult<PutResult>> {
                Box::pin(async { unreachable!() })
            }
            fn get(&self, _h: &Ch) -> Bf<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
                Box::pin(async {
                    let r: Box<dyn AsyncRead + Send + Unpin> =
                        Box::new(Cursor::new(Vec::<u8>::new()));
                    Ok(r)
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
        let c = TrivyConfig {
            trivy_bin: PathBuf::from("/no/such/trivy/binary/exists/here"),
            ..TrivyConfig::default()
        };
        let a = TrivyAdapter::new(c, Arc::new(OkStorage));
        let h: Ch = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap();
        let r = a.scan(&h, None).await;
        assert!(matches!(r, Err(DomainError::Invariant(_))));
    }
}
