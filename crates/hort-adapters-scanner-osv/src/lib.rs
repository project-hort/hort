//! osv-scanner [`ScannerPort`] adapter (SBOM mode).
//!
//! `OsvScannerAdapter` implements [`ScannerPort`](hort_domain::ports::scanner::ScannerPort)
//! by serialising the supplied [`Sbom`] into a CycloneDX 1.5 JSON
//! document, shelling out to
//! `osv-scanner scan source --format json --sbom <path>`,
//! parsing the JSON output, and returning the lowered findings.
//!
//! Unlike the Trivy adapter, this scanner does **not** consume the
//! artifact's content bytes. osv-scanner derives every match from the
//! SBOM's PURLs, so nothing on the
//! [`ScanTarget`](hort_domain::ports::scanner::ScanTarget) — not the
//! content hash, not the artifact kind — is read: there is no payload for
//! this backend to materialise. The parameter is kept for trait
//! conformance and for future caching keys.
//!
//! Behaviour when `sbom: None`: the adapter returns
//! `NothingAnalysable(NotApplicable)` — the explicit absence of a
//! verdict, never a clean one. osv-scanner needs an SBOM input and has
//! no payload-based fallback, so with no SBOM there is nothing this
//! backend examined; an empty finding list would claim otherwise and
//! would hand an unexamined artifact the release authority of a scan
//! (ADR 0007). `NotApplicable` rather than a gating arm because a
//! missing SBOM is a property of the artifact — the handler declares
//! these bytes to carry no dependency information — so there is nothing
//! for a hold to wait on.
//!
//! Module layout:
//! - [`severity`] — score / label → `SeverityThreshold` (pure)
//! - [`ecosystem`] — `Ecosystem` ↔ OSV ecosystem string + PURL type (pure)
//! - [`cyclonedx`] — `Sbom` → CycloneDX JSON (pure)
//! - [`parse`] — osv-scanner JSON wire types + finding mapper (pure)
//! - [`workspace`] — TempDir + SBOM JSON write (adapter-internal I/O)
//! - this module — `OsvScannerAdapter` itself + the `ScannerPort` impl
//!
//! See `docs/architecture/explanation/scanning-pipeline.md` for the
//! scanning pipeline design.

mod cyclonedx;
mod ecosystem;
mod parse;
mod severity;
mod workspace;

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::scanner::{
    NotAnalysable, ScanAnalysis, ScanTarget, ScannerPort, SCAN_REPORT_TOO_LARGE_MARKER,
};
use hort_domain::ports::BoxFuture;
use hort_domain::types::{Finding, Sbom};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

use crate::parse::{aggregate_findings, parse_osv_scanner_report};
use crate::workspace::prepare_sbom_workspace;

/// Drain `pipe` into a `Vec`, bounded to `cap + 1` bytes via
/// [`AsyncReadExt::take`]. Returns the drained buffer and whether the cap
/// was *tripped* (the source had more than `cap` bytes). Reading through
/// `.take(cap + 1)` makes detection unambiguous and non-flaky: a report
/// of exactly `cap` bytes reads `cap` bytes, hits EOF, and yields
/// `len == cap` (NOT tripped); only a report strictly larger than `cap`
/// yields `len == cap + 1`. The buffer never grows past `cap + 1`, so a
/// runaway pipe cannot OOM the worker. Mirrors the Trivy adapter
/// (2-instance template, not extracted to a shared crate for only two
/// call sites).
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

/// Drain both report pipes concurrently, each bounded by [`drain_capped`],
/// and return `(stdout, stderr, tripped)` where `tripped` is true if
/// EITHER pipe exceeded `cap`.
///
/// On first-trip we **return immediately** with `tripped = true` and
/// stop reading: the buffers are about to be discarded (the scan fails
/// closed), and waiting for the sibling drain is unsafe — a cap-tripping
/// child is wedged writing into the now-full pipe, and a grandchild
/// process can keep the sibling pipe's write-end open even after the
/// parent is killed, so the sibling drain might never EOF. Returning on
/// first-trip makes detection prompt and deadlock-free; the caller then
/// kills the child. When neither pipe trips, both drains hit a clean
/// EOF on a ≤ cap report and the full buffers are returned. Mirrors the
/// Trivy adapter (2-instance template).
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

/// Parse an `osv-scanner --format json` document and return the
/// lowered [`Finding`] list, applying the same per-finding cap filter
/// [`OsvScannerAdapter::scan`] applies.
///
/// Exposed publicly for fixture-based testing (the adapter's own
/// integration tests in `tests/` consume this) and for any future
/// caller that needs to re-parse an osv-scanner report archived
/// elsewhere. `Err(DomainError::Validation)` on malformed JSON.
pub fn parse_findings_from_json(stdout: &[u8]) -> DomainResult<Vec<Finding>> {
    let report = parse_osv_scanner_report(stdout)
        .map_err(|e| DomainError::Validation(format!("osv adapter: malformed JSON: {e}")))?;
    Ok(aggregate_findings(&report))
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Static configuration for [`OsvScannerAdapter`]. The composition root
/// populates these from `HORT_SCANNER_OSV_*` envvars.
#[derive(Debug, Clone)]
pub struct OsvScannerConfig {
    /// Path to the `osv-scanner` binary. Default: `osv-scanner`
    /// (resolved via `PATH`).
    pub osv_scanner_bin: PathBuf,
    /// Per-scan timeout. Default: 5 minutes. osv-scanner does not
    /// expose a `--timeout` flag in its CLI surface as of v1.7+;
    /// `run_scan` enforces this by wrapping the child process in
    /// `tokio::time::timeout` and `child.kill()`-ing the process on
    /// expiry. The error surfaced on timeout is
    /// `DomainError::Invariant("osv adapter: scan exceeded timeout
    /// ({}s)")`, matching the Trivy adapter's wording so operators
    /// see a uniform surface across scanner backends.
    pub timeout: Duration,
    /// Maximum scan-*report* size, in bytes, that the adapter will drain
    /// from the child's stdout/stderr. `run_scan` wraps each pipe in
    /// `.take(max_report_size + 1)` before `read_to_end`; if either drain
    /// reads more than the cap the child is killed and the scan is failed
    /// with a distinguishable
    /// [`SCAN_REPORT_TOO_LARGE_MARKER`](hort_domain::ports::scanner::SCAN_REPORT_TOO_LARGE_MARKER)
    /// error → `ScanIndeterminate` (fail-closed; never serve-unscanned,
    /// see ADR 0007). The report-side complement to the Trivy adapter's
    /// input-copy cap: it bounds the *output* drain so an osv-scanner
    /// emitting a huge (adversarial or buggy) report can no longer OOM
    /// the worker before the wall-clock timeout fires. Default: 256 MiB,
    /// operator-tunable via the shared `HORT_SCANNER_MAX_REPORT_SIZE`
    /// knob (same default + wording as the Trivy adapter so operators
    /// see one cross-backend surface).
    pub max_report_size: u64,
    /// Path to a merged CA bundle (system roots + operator's
    /// `HORT_EXTRA_CA_BUNDLE` contents) that the adapter sets as
    /// `SSL_CERT_FILE` on every spawned `osv-scanner` invocation.
    /// `None` (the default) leaves the spawned process's trust store
    /// untouched. The worker boot path
    /// (`hort_worker::extra_ca::read_and_propagate`) populates this when
    /// an extra-CA bundle is configured (ADR 0010).
    pub subprocess_ca_bundle: Option<PathBuf>,
}

impl Default for OsvScannerConfig {
    fn default() -> Self {
        Self {
            osv_scanner_bin: PathBuf::from("osv-scanner"),
            timeout: Duration::from_secs(300),
            // 256 MiB report-drain cap. See field doc.
            max_report_size: 256 * 1024 * 1024,
            subprocess_ca_bundle: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Capability map
// ---------------------------------------------------------------------------

/// The repository formats this backend can produce a verdict for: those
/// whose compiled-in format handler exposes an SBOM the orchestrator can
/// hand over.
///
/// This backend reads nothing but the SBOM, so its coverage is exactly
/// the set of formats that *have* one. `oci` is absent and that absence
/// is the point: an OCI blob has no SBOM source, so pairing `osv` with
/// an OCI repository analyses nothing — while looking, in a policy, like
/// a second scan authority.
///
/// Derived from the handlers' own declarations, and — per the map's
/// rule that a cell is "yes" only with a known-vulnerable-fixture test
/// behind it — evidenced per format in `tests/sbom_evidence.rs`:
///
/// | format  | SBOM source | evidence test |
/// |---------|-------------|---------------|
/// | `npm`   | packument metadata → `FormatHandler::extract_sbom` | `a_known_vulnerable_npm_sbom_yields_a_finding` |
/// | `pypi`  | per-release JSON `requires_dist` → `FormatHandler::extract_sbom` | `a_known_vulnerable_pypi_sbom_yields_a_finding` |
/// | `cargo` | the `.crate`'s `Cargo.lock` → `PayloadSbom` | `a_known_vulnerable_cargo_sbom_yields_a_finding` |
/// | `maven` | the POM's `<dependencies>` → `PayloadSbom` | `a_known_vulnerable_maven_sbom_yields_a_finding` |
///
/// The set is static here because a scanner adapter depends on
/// `hort-domain` alone and cannot ask `hort-formats`. The worker's
/// parity guard closes that gap: it asks every registered handler
/// whether it is SBOM-capable and asserts this answer matches, so a
/// handler gaining or losing an SBOM source without this const moving
/// fails the test gate.
const SBOM_CAPABLE_FORMATS: &[&str] = &["npm", "pypi", "cargo", "maven"];

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

/// Outbound adapter implementing [`ScannerPort`] via the osv-scanner
/// CLI. Owns no state beyond its configuration; constructible without
/// `StoragePort` because osv-scanner reads the SBOM, not the artifact.
pub struct OsvScannerAdapter {
    config: OsvScannerConfig,
}

impl OsvScannerAdapter {
    /// Construct the adapter from an [`OsvScannerConfig`].
    pub fn new(config: OsvScannerConfig) -> Self {
        Self { config }
    }

    /// Build the argv vector for
    /// `osv-scanner scan source --format json --sbom <path>`.
    ///
    /// osv-scanner ≥ 2.0 (the worker image pins 2.3.8) requires a
    /// subcommand — `scan source` for SBOM/lockfile inputs. The v1
    /// flat `osv-scanner --format json --sbom <path>` syntax no
    /// longer reaches the SBOM scanner; instead the v2 binary falls
    /// into a filesystem-walk path that finds 0 packages and exits
    /// with `No package sources found`.
    ///
    /// `--sbom` is itself deprecated in favor of `-L` in 2.x but is
    /// still functional (with a runtime warning). Keep `--sbom` until
    /// osv-scanner drops it entirely, then switch to `-L sbom:<path>`
    /// (or the 2.x-native form). This comment is the tracker; no
    /// separate work item until the flag is actually removed upstream.
    ///
    /// Pulled out of [`Self::run_scan`] so it is unit-testable without
    /// touching the real binary.
    fn scan_argv(&self, sbom_path: &str) -> Vec<String> {
        vec![
            "scan".to_string(),
            "source".to_string(),
            "--format".to_string(),
            "json".to_string(),
            "--sbom".to_string(),
            sbom_path.to_string(),
        ]
    }

    /// Apply the `subprocess_ca_bundle` (if configured) as
    /// `SSL_CERT_FILE` on the supplied [`Command`]. Centralised so
    /// the scan and health-check paths stay in sync.
    fn apply_subprocess_ca(&self, cmd: &mut Command) {
        if let Some(path) = self.config.subprocess_ca_bundle.as_ref() {
            cmd.env("SSL_CERT_FILE", path);
        }
    }

    /// Build the argv for the `osv-scanner --version` health probe.
    fn health_argv(&self) -> Vec<String> {
        vec!["--version".to_string()]
    }

    /// Run the osv-scanner CLI against `sbom_path`, return the parsed
    /// report.
    ///
    /// **Exit-code policy.** osv-scanner uses non-zero exits to signal
    /// "found vulnerabilities" (exit 1) as well as actual errors (exit
    /// 2+). We explicitly tolerate exit 1 with a parseable JSON
    /// stdout — that is the find-something path. Empty stdout on a
    /// non-zero exit is treated as a real error.
    ///
    /// **Timeout enforcement.** osv-scanner exposes no `--timeout`
    /// CLI flag, so we wrap the child in `tokio::time::timeout`. The
    /// shape: spawn the child, take owned `stdout`/`stderr` pipes,
    /// race a single future that drains both pipes and awaits
    /// `child.wait()` against the configured timeout. On expiry we
    /// `child.kill().await` and surface
    /// `DomainError::Invariant("osv adapter: scan exceeded timeout")`
    /// — wording matches the Trivy adapter's timeout error so
    /// operators see a uniform surface across backends.
    async fn run_scan(&self, sbom_path: &str) -> DomainResult<parse::OsvScannerReport> {
        tracing::debug!(
            scanner = "osv",
            bin = %self.config.osv_scanner_bin.display(),
            sbom_path,
            "osv adapter: invoking CLI"
        );
        let mut cmd = Command::new(&self.config.osv_scanner_bin);
        cmd.args(self.scan_argv(sbom_path))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        self.apply_subprocess_ca(&mut cmd);
        let mut child = cmd.spawn().map_err(|e| {
            DomainError::Invariant(format!(
                "osv adapter: osv-scanner binary not found at {}: {}",
                self.config.osv_scanner_bin.display(),
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
        // Bound BOTH report pipes via `drain_both_capped`
        // (`.take(cap + 1)` each). We do NOT await `child.wait()` inside
        // the race: a cap-tripping child keeps writing into a now-full
        // pipe and never exits, and a grandchild can hold the sibling
        // pipe open, so `drain_both_capped` returns the instant either
        // pipe trips (the caller then kills the child) rather than
        // hanging until the wall-clock timeout. On a ≤ cap report both
        // pipes hit a clean EOF and `child.wait()` returns promptly
        // afterwards.
        let drain = drain_both_capped(&mut stdout_pipe, &mut stderr_pipe, max_report_size);

        let (stdout_buf, stderr_buf, report_tripped) =
            match tokio::time::timeout(timeout_duration, drain).await {
                Ok(Ok(triple)) => triple,
                Ok(Err(e)) => {
                    let _ = child.kill().await;
                    return Err(DomainError::Invariant(format!(
                        "osv adapter: failed to read scan output: {e}"
                    )));
                }
                Err(_elapsed) => {
                    // Timeout fired — terminate the child. `kill().await`
                    // is best-effort: even if the kill fails (e.g. the
                    // child already exited between the timeout firing
                    // and this point) we still want to surface the
                    // timeout to the caller.
                    let _ = child.kill().await;
                    return Err(DomainError::Invariant(format!(
                        "osv adapter: scan exceeded timeout ({}s)",
                        timeout_duration.as_secs()
                    )));
                }
            };

        if report_tripped {
            // The report drain hit the cap. Kill the child (it is blocked
            // writing into a full pipe) and fail the scan CLOSED.
            // `info!` (audit, not error): scanner kind + byte cap, never
            // the artifact id (high-cardinality / tracing-only).
            let _ = child.kill().await;
            tracing::info!(
                scanner = "osv",
                max_report_bytes = max_report_size,
                "osv adapter: scan report exceeded byte cap; killed child (fail-closed)"
            );
            return Err(DomainError::Invariant(format!(
                "osv adapter: {SCAN_REPORT_TOO_LARGE_MARKER} ({max_report_size} bytes); killed child"
            )));
        }

        let status = match tokio::time::timeout(timeout_duration, child.wait()).await {
            Ok(Ok(status)) => status,
            Ok(Err(e)) => {
                let _ = child.kill().await;
                return Err(DomainError::Invariant(format!(
                    "osv adapter: failed to await child exit: {e}"
                )));
            }
            Err(_elapsed) => {
                let _ = child.kill().await;
                return Err(DomainError::Invariant(format!(
                    "osv adapter: scan exceeded timeout ({}s)",
                    timeout_duration.as_secs()
                )));
            }
        };

        // osv-scanner exits 1 when it finds vulnerabilities — that is
        // success from our perspective. Only treat exit 2+ (or exit 1
        // with empty stdout) as a real error.
        let code = status.code();
        let stdout_empty = stdout_buf.is_empty();
        let is_findings_exit = code == Some(1) && !stdout_empty;
        if !status.success() && !is_findings_exit {
            let stderr = String::from_utf8_lossy(&stderr_buf).into_owned();
            return Err(DomainError::Invariant(format!(
                "osv adapter: scan failed (exit {}): {}",
                status,
                stderr.trim()
            )));
        }

        parse_osv_scanner_report(&stdout_buf)
            .map_err(|e| DomainError::Validation(format!("osv adapter: malformed JSON: {e}")))
    }
}

impl ScannerPort for OsvScannerAdapter {
    fn name(&self) -> &str {
        "osv"
    }

    /// OSV's half of the scanner capability map: the formats whose
    /// compiled-in handler exposes an SBOM the orchestrator can hand
    /// over. [`SBOM_CAPABLE_FORMATS`] holds the set and the reasoning.
    fn applies_to(&self, format: &str) -> bool {
        SBOM_CAPABLE_FORMATS.contains(&format)
    }

    /// OSV-scanner adjudicates the **SBOM**, not the payload, so the
    /// materialisation facts on [`ScanTarget`] (the kind, the coords, the
    /// content hash) are not consulted: there is nothing for this backend
    /// to put on disk. Its input is whatever the format handler extracted.
    ///
    /// No SBOM means no verdict, never a clean one — see the module docs.
    fn scan<'a>(
        &'a self,
        _target: &'a ScanTarget<'a>,
        sbom: Option<&'a Sbom>,
    ) -> BoxFuture<'a, DomainResult<ScanAnalysis>> {
        Box::pin(async move {
            let Some(sbom) = sbom else {
                // A missing SBOM is a fact about the *artifact*, not an
                // unassessed surface: the handler declares these bytes
                // (an OCI blob, a checksum sidecar, a `-sources.jar`) to
                // carry no dependency information, so there is nothing
                // for a hold to wait on — the same arm Trivy uses for a
                // kind it has no materialisation for. `debug!` because
                // this is the steady state for every such artifact, not
                // an operator action.
                //
                // What it must never be is `clean()`. An empty finding
                // list is a *verdict* and carries release authority, so
                // returning one here would make this backend a false
                // scan authority for every SBOM-less artifact — and on a
                // policy where the other backend abstains, that false
                // authority is the only thing standing between an
                // unexamined artifact and release.
                tracing::debug!(
                    scanner = "osv",
                    "osv adapter: no SBOM for this artifact — nothing to assess"
                );
                return Ok(ScanAnalysis::NothingAnalysable(
                    NotAnalysable::NotApplicable,
                ));
            };

            // 1. Materialise SBOM into a TempDir. RAII drop on
            //    success / error / panic removes the directory tree.
            let ws = prepare_sbom_workspace(sbom).await?;
            let path = ws.sbom_path().to_string_lossy().into_owned();

            // 2. Run osv-scanner.
            let report = self.run_scan(&path).await?;

            // 3. Lower into Vec<Finding>. Findings that fail
            //    Finding::validate are dropped with tracing::warn!
            //    inside aggregate_findings.
            let findings = aggregate_findings(&report);

            tracing::info!(
                scanner = "osv",
                finding_count = findings.len(),
                sbom_components = sbom.components.len(),
                "osv adapter: scan completed"
            );

            // 4. ws drops here — TempDir cleanup runs.
            Ok(ScanAnalysis::Analysed(findings))
        })
    }

    fn health_check(&self) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async move {
            let mut cmd = Command::new(&self.config.osv_scanner_bin);
            cmd.args(self.health_argv())
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            self.apply_subprocess_ca(&mut cmd);
            let output = cmd.output().await.map_err(|e| {
                DomainError::Invariant(format!(
                    "osv adapter: osv-scanner binary not found at {}: {}",
                    self.config.osv_scanner_bin.display(),
                    e
                ))
            })?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(DomainError::Invariant(format!(
                    "osv adapter: --version exit {} ({})",
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

    use hort_domain::ports::scanner::SCAN_REPORT_TOO_LARGE_MARKER;
    use std::io::Cursor;

    fn cfg() -> OsvScannerConfig {
        OsvScannerConfig {
            osv_scanner_bin: PathBuf::from("/usr/local/bin/osv-scanner"),
            timeout: Duration::from_secs(120),
            max_report_size: 256 * 1024 * 1024,
            subprocess_ca_bundle: None,
        }
    }

    fn adapter() -> OsvScannerAdapter {
        OsvScannerAdapter::new(cfg())
    }

    fn sample_hash() -> hort_domain::types::ContentHash {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap()
    }

    fn sample_coords() -> hort_domain::types::ArtifactCoords {
        hort_domain::types::ArtifactCoords {
            name: "lodash".to_string(),
            name_as_published: "lodash".to_string(),
            version: Some("4.17.21".to_string()),
            path: "lodash/-/lodash-4.17.21.tgz".to_string(),
            format: hort_domain::entities::repository::RepositoryFormat::Npm,
            metadata: serde_json::Value::Null,
        }
    }

    /// A scan target this backend ignores every payload fact of — it
    /// scans the SBOM. Present so the port's shape is exercised.
    fn sample_target<'a>(
        hash: &'a hort_domain::types::ContentHash,
        coords: &'a hort_domain::types::ArtifactCoords,
    ) -> ScanTarget<'a> {
        ScanTarget {
            content_hash: hash,
            format: "npm",
            coords,
            kind: hort_domain::types::ArtifactKind::NpmTarball,
        }
    }

    // ----- argv shape (no real binary needed) ------------------------------

    #[test]
    fn name_is_lowercase_osv() {
        assert_eq!(adapter().name(), "osv");
    }

    #[test]
    fn scan_argv_emits_format_json() {
        let argv = adapter().scan_argv("/tmp/sbom.cdx.json");
        let i = argv.iter().position(|s| s == "--format").unwrap();
        assert_eq!(argv[i + 1], "json");
    }

    #[test]
    fn scan_argv_emits_sbom_path() {
        let argv = adapter().scan_argv("/tmp/sbom.cdx.json");
        let i = argv.iter().position(|s| s == "--sbom").unwrap();
        assert_eq!(argv[i + 1], "/tmp/sbom.cdx.json");
    }

    #[test]
    fn scan_argv_starts_with_scan_source_subcommand() {
        // osv-scanner v2 (≥ 2.0) reorganised the CLI: scans now require
        // a `scan source` subcommand. The flat `osv-scanner --format
        // json --sbom <path>` shape from v1 silently no-ops in v2 — the
        // binary prints a deprecation warning, falls into a filesystem
        // walk starting at "/", scans 1 inode, finds 0 packages, and
        // exits non-zero with "No package sources found". The smoke
        // test caught this as a "0 findings always" symptom before this
        // test was written. The contract this test pins: every
        // osv-scanner CLI invocation MUST start with the `scan source`
        // subcommand.
        let argv = adapter().scan_argv("/tmp/sbom.cdx.json");
        assert_eq!(
            argv.first().map(String::as_str),
            Some("scan"),
            "argv must start with `scan`; got {argv:?}"
        );
        assert_eq!(
            argv.get(1).map(String::as_str),
            Some("source"),
            "argv[1] must be `source` (the `scan source` subcommand); got {argv:?}"
        );
    }

    #[test]
    fn scan_argv_sbom_path_is_last_argument() {
        // The `--sbom <path>` pair appears after the subcommand and
        // after `--format json`, with the path as the final argument.
        // Guards against accidental insertion of a trailing flag that
        // would change interpretation.
        let argv = adapter().scan_argv("/tmp/sbom.cdx.json");
        assert_eq!(argv.last().map(String::as_str), Some("/tmp/sbom.cdx.json"));
    }

    #[test]
    fn health_argv_is_just_version() {
        assert_eq!(adapter().health_argv(), vec!["--version".to_string()]);
    }

    #[test]
    fn default_config_uses_osv_scanner_bin_and_300s_timeout() {
        let c = OsvScannerConfig::default();
        assert_eq!(c.osv_scanner_bin, PathBuf::from("osv-scanner"));
        assert_eq!(c.timeout, Duration::from_secs(300));
        // Default report-drain cap is 256 MiB (shared knob with the
        // Trivy adapter; see the field doc).
        assert_eq!(c.max_report_size, 256 * 1024 * 1024);
    }

    // -- bounded report drain -------------------------------------------

    /// The bounded drain stops at the cap and reports the trip.
    /// An over-cap payload is detected and the buffer is bounded to
    /// `cap + 1` bytes (no unbounded allocation).
    #[tokio::test]
    async fn drain_capped_trips_and_bounds_allocation_on_over_cap_input() {
        let cap: u64 = 16;
        let mut src = Cursor::new(vec![b'x'; 10 * 1024]);
        let (buf, tripped) = drain_capped(&mut src, cap).await.expect("drain");
        assert!(tripped, "an over-cap payload must trip the cap");
        assert_eq!(
            buf.len() as u64,
            cap + 1,
            "the bounded drain must read at most cap+1 bytes, not the whole input"
        );
    }

    /// A payload of EXACTLY the cap does NOT false-positive.
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

    /// When the child's stdout exceeds `max_report_size`, `run_scan`
    /// kills the child and returns the distinguishable "report exceeded
    /// cap" `Invariant` error (→ `ScanIndeterminate`).
    #[tokio::test]
    async fn run_scan_over_cap_stdout_kills_child_and_returns_report_too_large() {
        if !std::path::Path::new("/bin/sh").exists() {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let script = dir.path().join("fake-osv.sh");
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
        let c = OsvScannerConfig {
            osv_scanner_bin: script.clone(),
            max_report_size: 1024,
            ..OsvScannerConfig::default()
        };
        let a = OsvScannerAdapter::new(c);
        let mut r = a.run_scan("/tmp/ignored.json").await;
        for _ in 0..5 {
            match &r {
                Err(DomainError::Invariant(msg)) if msg.contains("Text file busy") => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    r = a.run_scan("/tmp/ignored.json").await;
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
                assert!(msg.contains("osv adapter"), "{msg}");
            }
            other => panic!("expected report-too-large Invariant, got {other:?}"),
        }
    }

    // ----- scan(None) early-return path ------------------------------------

    #[tokio::test]
    async fn scan_with_none_sbom_abstains_without_invoking_cli() {
        // The configured binary path is bogus — if `scan` actually
        // tried to run osv-scanner, this would surface as
        // DomainError::Invariant("not found"). Reaching `Ok(_)` proves
        // the early-return path skipped the CLI entirely.
        let c = OsvScannerConfig {
            osv_scanner_bin: PathBuf::from("/no/such/osv-scanner/exists/here"),
            ..OsvScannerConfig::default()
        };
        let a = OsvScannerAdapter::new(c);
        let h = sample_hash();
        let coords = sample_coords();
        let r = a
            .scan(&sample_target(&h, &coords), None)
            .await
            .expect("none-sbom returns Ok");
        // With no SBOM this backend examined nothing, so it has no
        // verdict to give. A clean verdict here would carry release
        // authority for an artifact nothing looked at.
        assert_eq!(
            r,
            ScanAnalysis::NothingAnalysable(NotAnalysable::NotApplicable),
            "scan(None) must be the absence of a verdict, not a clean one"
        );
        assert_ne!(r, ScanAnalysis::clean());
    }

    // ----- capability map --------------------------------------------------

    /// The formats whose handlers expose an SBOM, and only those. `oci`
    /// is the cell this map exists to close: an OCI blob has no SBOM
    /// source, so this backend can never adjudicate one.
    #[test]
    fn applies_to_is_exactly_the_sbom_capable_formats() {
        let a = OsvScannerAdapter::new(cfg());
        for format in ["npm", "pypi", "cargo", "maven"] {
            assert!(a.applies_to(format), "{format} has an SBOM source");
        }
        for format in ["oci", "gradle", "generic", "", "NPM"] {
            assert!(!a.applies_to(format), "{format} has no SBOM source");
        }
    }

    // ----- runtime smoke (no real binary needed) ---------------------------

    #[tokio::test]
    async fn health_check_with_missing_binary_returns_invariant_error() {
        let c = OsvScannerConfig {
            osv_scanner_bin: PathBuf::from("/no/such/osv-scanner/exists/here"),
            ..OsvScannerConfig::default()
        };
        let a = OsvScannerAdapter::new(c);
        let r = a.health_check().await;
        match r {
            Err(DomainError::Invariant(msg)) => {
                assert!(msg.contains("osv adapter"), "{msg}");
                assert!(msg.contains("not found"), "{msg}");
            }
            other => panic!("expected Invariant error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn scan_with_sbom_and_missing_binary_returns_invariant_error() {
        // sbom: Some(_) drives the CLI invocation path. With a bogus
        // binary, the failure must be Invariant("not found").
        let c = OsvScannerConfig {
            osv_scanner_bin: PathBuf::from("/no/such/osv-scanner/exists/here"),
            ..OsvScannerConfig::default()
        };
        let a = OsvScannerAdapter::new(c);
        let h = sample_hash();
        let coords = sample_coords();
        let sbom = Sbom {
            subject: None,
            components: vec![],
        };
        let r = a.scan(&sample_target(&h, &coords), Some(&sbom)).await;
        assert!(matches!(r, Err(DomainError::Invariant(_))));
    }

    // ----- public re-export of parser --------------------------------------

    #[test]
    fn parse_findings_from_json_returns_validation_error_on_malformed_input() {
        let r = parse_findings_from_json(b"{not json");
        match r {
            Err(DomainError::Validation(msg)) => {
                assert!(msg.contains("osv adapter"), "{msg}");
            }
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    #[test]
    fn parse_findings_from_json_returns_empty_vec_on_clean_scan() {
        let r = parse_findings_from_json(b"{\"results\":[]}").expect("parse");
        assert!(r.is_empty());
    }
}
