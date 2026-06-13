//! Adapter-internal workspace setup. osv-scanner reads a CycloneDX
//! JSON file via `--sbom <path>`; this module serialises the SBOM into
//! a fresh `TempDir` and hands the directory back to the adapter.
//!
//! Cleanup is RAII: the returned [`TempDir`] removes its contents on
//! `Drop`, which fires whether the scan succeeded, failed, or panicked.
//!
//! Unlike the Trivy adapter, this workspace does NOT pull bytes from
//! `StoragePort`. osv-scanner consumes only the SBOM JSON; the raw
//! artifact payload is irrelevant.

use std::path::PathBuf;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::types::Sbom;
use tempfile::{Builder, TempDir};
use tokio::io::AsyncWriteExt;

use crate::cyclonedx::build_cyclonedx_json;

/// File name used inside the workspace dir. osv-scanner's `--sbom`
/// flag accepts an explicit path so the choice is arbitrary, but a
/// stable name makes diagnostics easier when debugging a failed scan.
pub(crate) const SBOM_FILENAME: &str = "sbom.cdx.json";

/// Result of [`prepare_sbom_workspace`]. Holds the `TempDir` so the
/// caller keeps the workspace alive across the osv-scanner invocation;
/// drop semantics remove the directory tree.
pub(crate) struct ScanWorkspace {
    /// RAII handle. Drop → directory tree removed.
    tmp: TempDir,
    /// Path to the CycloneDX JSON file inside `tmp`. osv-scanner is
    /// invoked with this path as the `--sbom` argument.
    sbom_path: PathBuf,
}

impl ScanWorkspace {
    /// Path to the on-disk CycloneDX SBOM. Hand this to osv-scanner
    /// via `--sbom <path>`.
    pub(crate) fn sbom_path(&self) -> &std::path::Path {
        &self.sbom_path
    }

    /// Path to the workspace directory. Useful for diagnostics; the
    /// adapter passes `sbom_path()` to osv-scanner, not this.
    #[allow(dead_code)] // exposed for future diagnostics; not used by current adapter paths
    pub(crate) fn dir(&self) -> &std::path::Path {
        self.tmp.path()
    }
}

/// Build a fresh workspace for one scan: serialise the SBOM into
/// CycloneDX JSON, write it into a fresh `TempDir`, and return the
/// [`ScanWorkspace`]. The file inside the workspace is named
/// [`SBOM_FILENAME`]; the workspace itself uses a randomised
/// `hort-scan-osv-` prefix.
///
/// Errors:
/// - `DomainError::Invariant(...)` for I/O failures inside the temp
///   workspace (`tempfile`, `tokio::fs::File::create`, write).
/// - `DomainError::Invariant(...)` for `serde_json::to_vec` failure
///   (a non-stringable component would surface here, but the SBOM
///   shape only carries plain strings so this is a defensive branch).
pub(crate) async fn prepare_sbom_workspace(sbom: &Sbom) -> DomainResult<ScanWorkspace> {
    let tmp = Builder::new()
        .prefix("hort-scan-osv-")
        .tempdir()
        .map_err(|e| {
            DomainError::Invariant(format!("osv adapter: failed to create temp workspace: {e}"))
        })?;
    let sbom_path = tmp.path().join(SBOM_FILENAME);

    let value = build_cyclonedx_json(sbom);
    // Compact form — osv-scanner does not care about pretty printing
    // and the file may carry hundreds of components for large SBOMs.
    let bytes = serde_json::to_vec(&value).map_err(|e| {
        DomainError::Invariant(format!("osv adapter: failed to encode CycloneDX JSON: {e}"))
    })?;

    let mut file = tokio::fs::File::create(&sbom_path).await.map_err(|e| {
        DomainError::Invariant(format!(
            "osv adapter: failed to create SBOM file at {}: {}",
            sbom_path.display(),
            e
        ))
    })?;
    file.write_all(&bytes).await.map_err(|e| {
        DomainError::Invariant(format!(
            "osv adapter: failed to write SBOM bytes to {}: {}",
            sbom_path.display(),
            e
        ))
    })?;
    file.flush().await.map_err(|e| {
        DomainError::Invariant(format!(
            "osv adapter: failed to flush SBOM file at {}: {}",
            sbom_path.display(),
            e
        ))
    })?;

    Ok(ScanWorkspace { tmp, sbom_path })
}

#[cfg(test)]
mod tests {
    use super::*;

    use hort_domain::types::{Ecosystem, SbomComponent};

    fn npm_sbom() -> Sbom {
        Sbom {
            subject: None,
            components: vec![SbomComponent {
                purl: "pkg:npm/lodash@4.17.20".into(),
                name: "lodash".into(),
                version: Some("4.17.20".into()),
                ecosystem: Ecosystem::Npm,
                licenses: vec![],
                direct_dependency: true,
            }],
        }
    }

    #[tokio::test]
    async fn prepare_sbom_workspace_writes_cyclonedx_json_into_temp_dir() {
        let sbom = npm_sbom();
        let ws = prepare_sbom_workspace(&sbom).await.expect("prepare");
        assert!(ws.sbom_path().exists());
        let bytes = tokio::fs::read(ws.sbom_path()).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["bomFormat"], "CycloneDX");
        assert_eq!(v["specVersion"], "1.5");
        let comps = v["components"].as_array().unwrap();
        assert_eq!(comps.len(), 1);
        assert_eq!(comps[0]["purl"], "pkg:npm/lodash@4.17.20");
    }

    #[tokio::test]
    async fn workspace_drops_remove_temp_dir() {
        let sbom = npm_sbom();
        let dir_path: PathBuf;
        let sbom_path: PathBuf;
        {
            let ws = prepare_sbom_workspace(&sbom).await.expect("prepare");
            dir_path = ws.dir().to_path_buf();
            sbom_path = ws.sbom_path().to_path_buf();
            assert!(dir_path.exists());
            assert!(sbom_path.exists());
        }
        // After ws drops, the temp dir + SBOM file are gone.
        assert!(
            !dir_path.exists(),
            "TempDir drop should remove the workspace at {}",
            dir_path.display()
        );
        assert!(
            !sbom_path.exists(),
            "TempDir drop should remove the SBOM file at {}",
            sbom_path.display()
        );
    }

    #[tokio::test]
    async fn empty_sbom_writes_well_formed_envelope() {
        let sbom = Sbom {
            subject: None,
            components: vec![],
        };
        let ws = prepare_sbom_workspace(&sbom).await.expect("prepare");
        let bytes = tokio::fs::read(ws.sbom_path()).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["bomFormat"], "CycloneDX");
        let comps = v["components"].as_array().unwrap();
        assert!(comps.is_empty());
    }

    #[test]
    fn sbom_filename_is_stable() {
        // Pin the filename — diagnostic ergonomics rely on this string
        // being predictable when an operator finds an `hort-scan-osv-…`
        // tempdir on a worker.
        assert_eq!(SBOM_FILENAME, "sbom.cdx.json");
    }
}
