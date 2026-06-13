use crate::error::DomainResult;
use crate::types::{ContentHash, Finding, Sbom};

use super::BoxFuture;

/// Stable marker substring embedded in a scanner adapter's
/// [`DomainError::Invariant`](crate::error::DomainError::Invariant)
/// message when a scan is failed because the child's report drain hit
/// the `HORT_SCANNER_MAX_REPORT_SIZE` cap.
/// The orchestrator (`ScanOrchestrationUseCase::run_scan`)
/// matches this marker on a per-backend scan error to attribute the
/// `hort_scan_record_outcome_failures_total{result="report_too_large"}`
/// metric, then routes the backend failure through the normal
/// fail-closed `ScanIndeterminate` path. Centralised here (in the only
/// crate both the scanner adapters and `hort-app` depend on) so the
/// producer and the consumer cannot drift on the literal.
pub const SCAN_REPORT_TOO_LARGE_MARKER: &str = "scan report exceeded cap";

/// Outbound port for vulnerability scanners (Trivy, OSV-scanner, etc.).
///
/// Scanner adapters live in their own per-backend crates
/// (`hort-adapters-scanner-<name>`) and depend only on `hort-domain`.
/// Implementations are responsible for any temporary workspace setup
/// and teardown — pulling content bytes from `StoragePort`, extracting
/// to a temp dir, invoking the scanner, parsing output. The orchestrator
/// (`ScanOrchestrationUseCase`) treats scanners as opaque
/// content-hash-in, findings-out functions.
///
/// `sbom` is the format-handler-extracted component list. Many scanners
/// (OSV-scanner) consume it directly; others (Trivy fs) ignore it and
/// re-discover from the payload.
pub trait ScannerPort: Send + Sync {
    /// Stable identifier used in `ScanPolicy.scan_backends` (`"trivy"`,
    /// `"osv"`). Must match the registry name registered at startup.
    fn name(&self) -> &str;

    /// Run the scanner against the artifact's content and return findings.
    fn scan<'a>(
        &'a self,
        content_hash: &'a ContentHash,
        sbom: Option<&'a Sbom>,
    ) -> BoxFuture<'a, DomainResult<Vec<Finding>>>;

    /// Health check invoked at worker startup. Failure means the backend
    /// is not deployable; the worker logs and exits non-zero.
    fn health_check(&self) -> BoxFuture<'_, DomainResult<()>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that `ScannerPort` is dyn-compatible.
    /// Runtime: `size_of` executes in the test body for coverage.
    #[test]
    fn scanner_port_is_dyn_compatible() {
        let _ = size_of::<&dyn ScannerPort>();
    }

    /// `Box<dyn ScannerPort>` resolves — proves the trait can be
    /// type-erased into an owned trait object the way adapter
    /// composition roots will store it.
    #[test]
    fn scanner_port_can_be_boxed() {
        let _: Option<Box<dyn ScannerPort>> = None;
    }
}
