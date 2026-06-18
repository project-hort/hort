//! `HORT_EXTRA_CA_BUNDLE` boot integration for `hort-worker`.
//!
//! Two responsibilities, both run once at worker startup:
//!
//! 1. **Read + parse** the env var into [`ExtraTrustAnchors`] for the
//!    Rust adapters that build reqwest clients (the OSV advisory
//!    adapter is currently the only one in the worker; future
//!    reqwest-using adapters layer on the same anchors). Mirrors
//!    `hort-server`'s `read_extra_ca_bundle()` in shape.
//!
//! 2. **Build a merged CA bundle for spawned scanner subprocesses.**
//!    Trivy and osv-scanner are Go binaries; Go's standard library
//!    honours `SSL_CERT_FILE` as the trust-store path. The scanner
//!    adapters (`hort-adapters-scanner-trivy`,
//!    `hort-adapters-scanner-osv`) set `SSL_CERT_FILE` on each
//!    `tokio::process::Command` they spawn, pointing at the merged
//!    file this module writes.
//!
//!    The merged bundle (system + operator) is written to
//!    `/tmp/hort-worker-ca-bundle.pem`. `SSL_CERT_FILE` *replaces* the
//!    Go default trust store rather than augmenting it, so the file
//!    must contain BOTH the system roots (so public endpoints like
//!    osv.dev keep working) AND the operator's bundle (so private
//!    endpoints behind the operator's CA work).
//!
//!    We pass the path explicitly to each `Command::env(...)` rather
//!    than `std::env::set_var` because the workspace forbids
//!    `unsafe_code`, and (per the 2024 edition) `set_var` is
//!    `unsafe`. The adapter-side wiring is also more honest about
//!    where the env-var crosses a process boundary.
//!
//! Why we emit a fresh file under `/tmp` rather than mutating
//! `/etc/ssl/certs/ca-certificates.crt`: the runtime image is
//! distroless (read-only `/etc`), and `/tmp` is the worker's
//! emptyDir mount in the chart's `volumeMounts`.

use std::path::{Path, PathBuf};

use hort_config::{ExtraCaParseError, ExtraTrustAnchors};

/// Path the merged trust store is written to inside the container.
/// Must live on a writable mount; the chart attaches an `emptyDir`
/// at `/tmp` for exactly this. Tests pin the path so a casual edit
/// can't drift it without flagging the chart change.
pub(crate) const SUBPROCESS_BUNDLE_PATH: &str = "/tmp/hort-worker-ca-bundle.pem";

/// System trust store on Debian-derived distroless base images
/// (`gcr.io/distroless/cc-debian13:nonroot`). The path is
/// architecture-stable on every Debian release we currently target;
/// a future move to Alpine or Wolfi would need this updated.
pub(crate) const SYSTEM_BUNDLE_PATH: &str = "/etc/ssl/certs/ca-certificates.crt";

/// Outcome of [`read_and_propagate`]. Carries:
///   - the parsed anchors for the in-process Rust adapter wiring
///     (composition threads them into the OSV advisory adapter and
///     any other reqwest-using adapter);
///   - the path to the merged subprocess CA bundle that the scanner
///     adapters' `Command::env("SSL_CERT_FILE", ...)` calls
///     consume.
///
/// Both fields are `None` when `HORT_EXTRA_CA_BUNDLE` was unset — in
/// which case neither in-process anchors nor subprocess wiring is
/// needed (Go binaries fall back to their default
/// `/etc/ssl/certs/ca-certificates.crt`).
#[derive(Debug)]
pub struct ExtraCaBoot {
    pub anchors: Option<ExtraTrustAnchors>,
    pub subprocess_bundle_path: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum ExtraCaBootError {
    // The message NAMES the missing path AND points the operator at the
    // likely cause (a CA-bundle volume that was never mounted onto the
    // worker pod). The chart only sets this env when it also auto-mounts
    // the bundle (`extraCaBundle.{configMapName,secretName}`); the common
    // way to reach this error is the manual Recipe-B path where the
    // operator wired `worker.extraVolumes`/`worker.extraVolumeMounts` on
    // only one of the two Deployments. A bare `No such file or directory`
    // crashloop would be opaque; this turns it into an actionable fatal.
    #[error(
        "HORT_EXTRA_CA_BUNDLE points at {path:?} but no file is readable there: {source}. \
         The worker pod is missing the CA-bundle mount at that path — set \
         extraCaBundle.configMapName or extraCaBundle.secretName (the chart auto-mounts \
         both server and worker), or, for the manual Recipe-B path, ensure \
         worker.extraVolumes/worker.extraVolumeMounts mount the bundle at this path on the \
         worker Deployment too"
    )]
    Unreadable {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("HORT_EXTRA_CA_BUNDLE at {path:?} did not parse as PEM: {source}")]
    ParseFailed {
        path: String,
        #[source]
        source: ExtraCaParseError,
    },
    #[error("failed to write merged subprocess CA bundle to {path:?}: {source}")]
    WriteFailed {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// Read `HORT_EXTRA_CA_BUNDLE`, parse the operator bundle, and (on
/// success) write a merged system+operator bundle to
/// [`SUBPROCESS_BUNDLE_PATH`] for the scanner adapters'
/// `Command::env("SSL_CERT_FILE", ...)` calls.
///
/// Returns the parsed anchors AND the merged-bundle path so
/// composition can hand them to the appropriate adapters. When
/// `HORT_EXTRA_CA_BUNDLE` is unset, both outputs are `None`/no-op —
/// the worker keeps using public-root TLS just like before, and
/// scanner subprocesses fall back to their default trust store.
///
/// Boot semantics: this is called from `main` BEFORE composition.
/// A failure aborts the boot — same posture as `hort-server`'s
/// `read_extra_ca_bundle` (an extra-CA bundle that's been configured
/// but is broken should fail fast at startup rather than silently
/// fall back to public-root-only TLS in a private-CA deployment).
pub fn read_and_propagate() -> Result<ExtraCaBoot, ExtraCaBootError> {
    const VAR: &str = "HORT_EXTRA_CA_BUNDLE";

    let path_str = match std::env::var(VAR) {
        Ok(v) if !v.is_empty() => v,
        _ => {
            tracing::debug!(
                "HORT_EXTRA_CA_BUNDLE: not configured; subprocess CA propagation skipped"
            );
            return Ok(ExtraCaBoot {
                anchors: None,
                subprocess_bundle_path: None,
            });
        }
    };

    let operator_bytes =
        std::fs::read(&path_str).map_err(|source| ExtraCaBootError::Unreadable {
            path: path_str.clone(),
            source,
        })?;

    let anchors = ExtraTrustAnchors::parse_pem(&operator_bytes).map_err(|source| {
        ExtraCaBootError::ParseFailed {
            path: path_str.clone(),
            source,
        }
    })?;

    // Build the merged bundle for spawned Go subprocesses. The system
    // bundle may not exist on every base image — log a warning and
    // continue with operator-only contents. The chart's distroless
    // runtime DOES ship `/etc/ssl/certs/ca-certificates.crt`, so the
    // warning path is reserved for dev / non-distroless dev images.
    let system_bytes = match std::fs::read(SYSTEM_BUNDLE_PATH) {
        Ok(b) => Some(b),
        Err(e) => {
            tracing::warn!(
                path = SYSTEM_BUNDLE_PATH,
                error = %e,
                "system CA bundle missing — spawned scanners will see only the operator's bundle, \
                 which means public endpoints (osv.dev) will fail TLS validation",
            );
            None
        }
    };

    let merged = merge_bundles(system_bytes.as_deref(), &operator_bytes);

    write_subprocess_bundle(Path::new(SUBPROCESS_BUNDLE_PATH), &merged).map_err(|source| {
        ExtraCaBootError::WriteFailed {
            path: SUBPROCESS_BUNDLE_PATH.to_string(),
            source,
        }
    })?;

    tracing::info!(
        operator_path = %path_str,
        merged_path = SUBPROCESS_BUNDLE_PATH,
        system_present = system_bytes.is_some(),
        "HORT_EXTRA_CA_BUNDLE: parsed + merged with system roots; subprocess SSL_CERT_FILE will \
         point at the merged bundle",
    );

    Ok(ExtraCaBoot {
        anchors: Some(anchors),
        subprocess_bundle_path: Some(PathBuf::from(SUBPROCESS_BUNDLE_PATH)),
    })
}

/// Concatenate `system` (if present) and `operator` PEM bytes into a
/// single buffer with a newline separator between them. Each input
/// is appended verbatim (no normalisation) — PEM is already a
/// well-defined newline-delimited format, so concatenation is the
/// canonical "merge" operation.
pub(crate) fn merge_bundles(system: Option<&[u8]>, operator: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(system.map_or(0, <[u8]>::len) + operator.len() + 1);
    if let Some(s) = system {
        out.extend_from_slice(s);
        // Belt-and-braces: ensure a separator newline even if the
        // upstream bundle didn't end with one. PEM parsers tolerate
        // arbitrary whitespace between blocks, so an extra newline
        // is safe; a missing one risks fusing the last system
        // BEGIN/END line with the first operator BEGIN line.
        if !out.ends_with(b"\n") {
            out.push(b'\n');
        }
    }
    out.extend_from_slice(operator);
    out
}

/// Write the merged bundle to `path` with mode 0644 (readable by
/// everyone in the container, which matters because Go subprocesses
/// run as the same UID but Trivy may drop further privileges in its
/// own sandbox).
fn write_subprocess_bundle(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    // Atomic write via tempfile + rename in the same directory so a
    // partial bundle never reaches a subprocess that opens it
    // mid-write.
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut tmp = tempfile_for(path)?;
    {
        use std::io::Write;
        tmp.write_all(bytes)?;
        tmp.flush()?;
    }
    tmp.persist(path)?;
    Ok(())
}

/// Construct a write-only tempfile in the same directory as `path`
/// so the subsequent `persist` is a same-filesystem rename (atomic).
fn tempfile_for(path: &Path) -> std::io::Result<tempfile::NamedTempFile> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    tempfile::Builder::new()
        .prefix(".hort-worker-ca-bundle-")
        .suffix(".pem")
        .tempfile_in(parent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_bundles_with_no_system_returns_operator_only() {
        let operator = b"-----BEGIN CERTIFICATE-----\nopop\n-----END CERTIFICATE-----\n";
        let merged = merge_bundles(None, operator);
        assert_eq!(merged, operator);
    }

    #[test]
    fn merge_bundles_concatenates_with_separator_newline() {
        let system = b"-----BEGIN CERTIFICATE-----\nsys\n-----END CERTIFICATE-----\n";
        let operator = b"-----BEGIN CERTIFICATE-----\nop\n-----END CERTIFICATE-----\n";
        let merged = merge_bundles(Some(system), operator);
        let s = std::str::from_utf8(&merged).expect("utf-8");
        // System bundle ends with \n already; operator follows directly.
        assert!(s.starts_with("-----BEGIN CERTIFICATE-----\nsys"));
        assert!(s.contains("-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nop"));
    }

    #[test]
    fn merge_bundles_inserts_separator_when_system_lacks_trailing_newline() {
        // Defensive — if the system bundle is malformed (no trailing
        // newline), merge_bundles still produces a valid concatenation
        // by inserting a separator.
        let system = b"-----BEGIN CERTIFICATE-----\nsys\n-----END CERTIFICATE-----";
        let operator = b"-----BEGIN CERTIFICATE-----\nop\n-----END CERTIFICATE-----\n";
        let merged = merge_bundles(Some(system), operator);
        let s = std::str::from_utf8(&merged).expect("utf-8");
        assert!(s.contains("-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn subprocess_bundle_path_is_under_writable_mount() {
        // The chart's worker-deployment.yaml mounts an emptyDir at
        // /tmp; the subprocess bundle lands there. If we move this
        // path, we must update the chart's volumeMounts.
        assert!(
            SUBPROCESS_BUNDLE_PATH.starts_with("/tmp/"),
            "SUBPROCESS_BUNDLE_PATH must live under the chart's /tmp emptyDir mount"
        );
    }

    #[test]
    fn write_subprocess_bundle_is_atomic_via_tempfile() {
        // Round-trip through a tmpdir to confirm the helper writes
        // something readable.
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("merged.pem");
        let bytes = b"-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n";
        write_subprocess_bundle(&path, bytes).expect("write");
        let read_back = std::fs::read(&path).expect("read");
        assert_eq!(read_back, bytes);
    }

    // -- Missing-file boot path -------------------------------------------
    //
    // The chart only sets `HORT_EXTRA_CA_BUNDLE` on the worker when the
    // bundle is actually auto-mounted on the worker pod
    // (`extraCaBundle.{configMapName,secretName}`). But an operator can
    // still misconfigure the env directly (Recipe B manual wiring with a
    // missing `worker.extraVolumeMounts` half, or a typo'd path). When the
    // env points at a path that does not exist, the worker MUST abort boot
    // with a CLEAR, NAMED error — never an opaque crashloop — so the
    // operator can immediately see which mount they forgot.

    #[test]
    fn missing_file_boot_returns_named_unreadable_error() {
        // Drive `HORT_EXTRA_CA_BUNDLE` to a path guaranteed not to exist.
        // `temp_env::with_var` restores the prior env on exit (even on
        // panic), so this is safe under the workspace's no-`unsafe`
        // rule (it never calls `std::env::set_var` from our code).
        let missing = "/nonexistent/hort/extra-ca/ca.crt";
        temp_env::with_var("HORT_EXTRA_CA_BUNDLE", Some(missing), || {
            let err = read_and_propagate().expect_err("missing file must abort boot");
            // It must be the Unreadable variant (not Parse/Write).
            assert!(
                matches!(err, ExtraCaBootError::Unreadable { .. }),
                "expected Unreadable, got {err:?}",
            );
            // The rendered message must NAME the offending path so the
            // operator sees exactly which file is missing.
            let msg = err.to_string();
            assert!(
                msg.contains(missing),
                "error must name the missing path; got: {msg}",
            );
            // …and it must point the operator at the likely cause — a
            // missing CA-bundle MOUNT on the worker pod — rather than a
            // bare OS errno. This is the difference between a clear fatal
            // and an opaque crashloop.
            assert!(
                msg.to_lowercase().contains("mount"),
                "error must hint at the missing mount; got: {msg}",
            );
        });
    }

    #[test]
    fn unset_env_is_a_noop_boot() {
        // Belt-and-braces: with the env unset, boot is a clean no-op
        // (both outputs `None`), never an error — the worker keeps
        // public-root TLS.
        temp_env::with_var("HORT_EXTRA_CA_BUNDLE", None::<&str>, || {
            let boot = read_and_propagate().expect("unset env is a clean no-op");
            assert!(boot.anchors.is_none());
            assert!(boot.subprocess_bundle_path.is_none());
        });
    }
}
