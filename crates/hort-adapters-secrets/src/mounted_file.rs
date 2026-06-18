//! `MountedFileSecretAdapter` — resolves `SecretRef { source: File, location }`
//! by reading the file at `location` from the local filesystem.
//!
//! Reads on every call (tmpfs is microseconds), strips exactly one trailing
//! `\n` or `\r\n` to normalise the editor-vs-CSI wiring discrepancy without
//! corrupting secrets whose terminating bytes matter.
//!
//! # Defence-in-depth (see `docs/how-to/wire-secrets.md`)
//!
//! - **Containment**: when `secrets_root` is configured (operator sets
//!   `HORT_SECRETS_FILE_ROOT`) the adapter canonicalises the requested path
//!   and rejects any resolution whose canonical target falls outside the
//!   root. This protects against a `SecretRef` whose `location` resolves
//!   through a symlink to (e.g.) `/etc/shadow`. When `secrets_root` is
//!   `None` the check is skipped — the legacy behaviour, used by tests
//!   and by deployments that have not yet adopted the env var.
//! - **Mode warning**: on Unix, every successful read checks
//!   `mode & 0o077`. Non-zero (i.e. group/other has *any* bit set) emits
//!   one `WARN` carrying the path and octal mode. The check is
//!   informational only — Kubernetes mounts files at `0644` by default
//!   and refusing to read would break real deployments.
//! - **Demoted success log**: routine successful resolves emit `debug!`
//!   instead of `info!` (architect observability rule —
//!   "reserve `info!` for state changes / security-impact events").
//!   `WARN` / `ERROR` paths (not-found, mode-warn, read-failure) are
//!   unchanged.

use std::io::ErrorKind;
use std::path::PathBuf;

use hort_domain::error::DomainResult;
use hort_domain::ports::secret_port::{
    SecretError, SecretPort, SecretRef, SecretSource, SecretValue,
};
use hort_domain::ports::BoxFuture;

use crate::metrics::{classify_to_domain_error, emit_resolve, values, SecretResolveResult};

/// Reads secrets from files on the local filesystem.
///
/// `secrets_root`, when `Some(_)`, restricts every resolve to paths
/// whose canonical form is a descendant of the root. Symlinks pointing
/// outside the root are rejected (containment — see
/// `docs/how-to/wire-secrets.md`). `None` keeps the legacy unconstrained
/// behaviour for tests and for deployments that have not opted in.
pub struct MountedFileSecretAdapter {
    secrets_root: Option<PathBuf>,
}

impl MountedFileSecretAdapter {
    /// Construct an adapter with no containment root. Equivalent to
    /// `new_with_root(None)`. Kept as the zero-arg constructor so
    /// existing test sites that wrote `MountedFileSecretAdapter` (a
    /// unit struct previously) port to `MountedFileSecretAdapter::new()`
    /// with no surprises.
    pub fn new() -> Self {
        Self::new_with_root(None)
    }

    /// Construct an adapter with an optional containment root. The
    /// composition root (`hort-server`) reads `HORT_SECRETS_FILE_ROOT` and
    /// passes the resulting `PathBuf` here; the rest of the binary
    /// stays generic over `SecretPort`.
    ///
    /// The supplied path is canonicalised lazily (on each resolve) so
    /// a misconfigured root surfaces as a structured error at first
    /// use, not as a startup panic.
    pub fn new_with_root(secrets_root: Option<PathBuf>) -> Self {
        Self { secrets_root }
    }
}

impl Default for MountedFileSecretAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretPort for MountedFileSecretAdapter {
    fn resolve<'a>(&'a self, reference: &'a SecretRef) -> BoxFuture<'a, DomainResult<SecretValue>> {
        Box::pin(async move {
            if reference.source != SecretSource::File {
                emit_resolve(values::SOURCE_FILE, SecretResolveResult::DecodeError);
                tracing::error!(
                    source = "file",
                    location = %reference.location,
                    "MountedFileSecretAdapter received non-file SecretRef",
                );
                let err = SecretError::Decode(
                    "MountedFileSecretAdapter received non-file SecretRef".into(),
                );
                return Err(classify_to_domain_error(&err));
            }

            // Containment check (when `secrets_root` is configured).
            // `canonicalize` resolves symlinks and `.`/`..` components;
            // the result must be a descendant of the canonicalised root.
            //
            // `canonicalize` requires the file to exist, so the
            // not-found branch is folded in here — failures map to
            // the existing `NotFound` arm. This keeps the wire shape
            // (caller-visible error) unchanged.
            let path_for_open: PathBuf = match self.secrets_root.as_ref() {
                Some(root) => match enforce_containment(&reference.location, root) {
                    Ok(canonical) => canonical,
                    Err(ContainmentError::NotFound) => {
                        emit_resolve(values::SOURCE_FILE, SecretResolveResult::NotFound);
                        tracing::warn!(
                            source = "file",
                            location = %reference.location,
                            "secret not found",
                        );
                        let err = SecretError::NotFound {
                            source: SecretSource::File,
                            location: reference.location.clone(),
                        };
                        return Err(classify_to_domain_error(&err));
                    }
                    Err(ContainmentError::Escape) => {
                        emit_resolve(values::SOURCE_FILE, SecretResolveResult::ReadFailure);
                        tracing::error!(
                            source = "file",
                            location = %reference.location,
                            secrets_root = %root.display(),
                            "secret path escapes configured HORT_SECRETS_FILE_ROOT — \
                             rejecting (symlink-escape protection)",
                        );
                        let err = SecretError::ReadFailure(format!(
                            "secret path `{}` is outside HORT_SECRETS_FILE_ROOT",
                            reference.location
                        ));
                        return Err(classify_to_domain_error(&err));
                    }
                    Err(ContainmentError::RootCanonicalize(msg)) => {
                        emit_resolve(values::SOURCE_FILE, SecretResolveResult::ReadFailure);
                        tracing::error!(
                            source = "file",
                            location = %reference.location,
                            secrets_root = %root.display(),
                            error = %msg,
                            "HORT_SECRETS_FILE_ROOT could not be canonicalised",
                        );
                        let err = SecretError::ReadFailure(format!(
                            "HORT_SECRETS_FILE_ROOT canonicalisation failed: {msg}"
                        ));
                        return Err(classify_to_domain_error(&err));
                    }
                },
                None => PathBuf::from(&reference.location),
            };

            match tokio::fs::read(&path_for_open).await {
                Ok(bytes) => {
                    let stripped = strip_one_trailing_newline(bytes);
                    // Mode check (Unix-only). Non-zero `mode & 0o077`
                    // means group or other has at least one bit set
                    // and is operator-actionable. Failure to stat is
                    // not fatal — log at debug! and continue (we have
                    // the bytes already; refusing to return them on a
                    // metadata hiccup would be worse than the missing
                    // warning).
                    #[cfg(unix)]
                    check_mode_warning(&path_for_open).await;

                    emit_resolve(values::SOURCE_FILE, SecretResolveResult::Success);
                    // Demoted from `info!` per architect observability
                    // rule (reserve `info!` for state changes /
                    // security-impact events).
                    tracing::debug!(
                        source = "file",
                        location = %reference.location,
                        "secret resolved",
                    );
                    Ok(SecretValue::from_bytes(stripped))
                }
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    emit_resolve(values::SOURCE_FILE, SecretResolveResult::NotFound);
                    tracing::warn!(
                        source = "file",
                        location = %reference.location,
                        "secret not found",
                    );
                    let err = SecretError::NotFound {
                        source: SecretSource::File,
                        location: reference.location.clone(),
                    };
                    Err(classify_to_domain_error(&err))
                }
                Err(e) => {
                    // PermissionDenied + any other I/O kind. These all
                    // map to ReadFailure; the kind() distinction is
                    // observable via the std::io::Error message inside the
                    // payload but not as a separate metric label.
                    emit_resolve(values::SOURCE_FILE, SecretResolveResult::ReadFailure);
                    tracing::error!(
                        source = "file",
                        location = %reference.location,
                        kind = ?e.kind(),
                        "secret read failure",
                    );
                    let err = SecretError::ReadFailure(e.to_string());
                    Err(classify_to_domain_error(&err))
                }
            }
        })
    }
}

/// Failure modes for the containment check. Each variant maps to a
/// different metric / log shape in the caller; kept explicit rather
/// than collapsing into a single `String` so future code review can
/// see the path → outcome wiring at a glance.
#[derive(Debug)]
enum ContainmentError {
    /// The requested path does not exist (or `canonicalize` failed
    /// with `NotFound`). Folded into the standard `NotFound` arm.
    NotFound,
    /// The canonical path is outside the configured root. Rejected.
    Escape,
    /// The configured `secrets_root` itself could not be canonicalised
    /// (e.g. operator set `HORT_SECRETS_FILE_ROOT=/nonexistent`). Surface
    /// this distinctly from the per-secret cases so the operator can
    /// distinguish "my env var is wrong" from "this particular
    /// `secret_ref` is wrong".
    RootCanonicalize(String),
}

/// Canonicalise `location` and assert its result is a descendant of
/// the canonicalised `root`. Returns the canonical path on success
/// (the caller uses it for the read so any subsequent `.symlink_to(...)`
/// race is closed — TOCTOU-tight modulo a same-name `rename` which is
/// outside the threat model).
fn enforce_containment(
    location: &str,
    root: &std::path::Path,
) -> Result<PathBuf, ContainmentError> {
    let canonical_root = std::fs::canonicalize(root).map_err(|e| {
        // Distinguish a missing-root error (operator misconfig) from a
        // missing-secret error (operator forgot to wire the secret).
        ContainmentError::RootCanonicalize(e.to_string())
    })?;
    let canonical = match std::fs::canonicalize(location) {
        Ok(p) => p,
        Err(e) if e.kind() == ErrorKind::NotFound => return Err(ContainmentError::NotFound),
        Err(e) => return Err(ContainmentError::RootCanonicalize(e.to_string())),
    };
    if canonical.starts_with(&canonical_root) {
        Ok(canonical)
    } else {
        Err(ContainmentError::Escape)
    }
}

/// Unix-only mode check. Reads file metadata, extracts the permission
/// bits, and emits one `WARN` if `mode & 0o077 != 0`. Failure to stat
/// is logged at `debug!` and otherwise ignored — the caller already
/// has the bytes.
#[cfg(unix)]
async fn check_mode_warning(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    match tokio::fs::metadata(path).await {
        Ok(meta) => {
            let mode = meta.permissions().mode();
            // Mask to the low 12 bits so we don't print the file-type
            // / sticky bits. `mode & 0o077` is the actionable test.
            if mode & 0o077 != 0 {
                tracing::warn!(
                    path = %path.display(),
                    mode = format!("{:o}", mode & 0o7777),
                    "secret file is readable by group or other — \
                     recommend chmod 0600 (or 0400)",
                );
            }
        }
        Err(e) => {
            // The bytes are already in hand; metadata failure is not
            // fatal. Emit at debug! so it shows up under
            // RUST_LOG=debug for diagnosis but doesn't pollute info.
            tracing::debug!(
                path = %path.display(),
                error = %e,
                "secret file metadata stat failed (mode-warning skipped)",
            );
        }
    }
}

/// Strip exactly one trailing `\n` or `\r\n` from the byte vector if
/// present; never more. Operates on raw bytes — no UTF-8 validation.
///
/// Pinned semantics — see the mounted_file tests for the full
/// expected-output matrix.
pub(crate) fn strip_one_trailing_newline(mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::block_on;
    use hort_domain::error::DomainError;
    use std::io::Write;

    #[test]
    fn strip_one_trailing_newline_table() {
        // Pinned semantics; touching this table is a deliberate contract
        // change.
        let cases: &[(&[u8], &[u8])] = &[
            (b"", b""),
            (b"x", b"x"),
            (b"secret", b"secret"),
            (b"secret\n", b"secret"),
            (b"secret\r\n", b"secret"),
            // Only ONE newline is stripped; the second \n is preserved as
            // part of the secret payload.
            (b"secret\n\n", b"secret\n"),
            (b"\n", b""),
            // Non-UTF-8 must round-trip untouched.
            (b"binary\x00\xff", b"binary\x00\xff"),
            // Bare CRLF normalises to empty.
            (b"\r\n", b""),
        ];
        for (input, expected) in cases {
            let got = strip_one_trailing_newline(input.to_vec());
            assert_eq!(
                got.as_slice(),
                *expected,
                "strip(input={input:?}) — expected {expected:?}, got {got:?}",
            );
        }
    }

    #[test]
    fn happy_path_strips_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"secret\n").unwrap();
        }
        let r = SecretRef {
            source: SecretSource::File,
            location: path.to_string_lossy().into_owned(),
        };
        let v = block_on(MountedFileSecretAdapter::new().resolve(&r)).expect("resolve");
        assert_eq!(v.as_bytes(), b"secret");
    }

    #[test]
    fn happy_path_no_newline_passes_through() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret-no-nl.txt");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"secret").unwrap();
        }
        let r = SecretRef {
            source: SecretSource::File,
            location: path.to_string_lossy().into_owned(),
        };
        let v = block_on(MountedFileSecretAdapter::new().resolve(&r)).expect("resolve");
        assert_eq!(v.as_bytes(), b"secret");
    }

    #[test]
    fn non_utf8_file_round_trips_with_newline_strip() {
        // The SecretValue carries raw bytes — UTF-8 is not a precondition.
        // The trailing newline is stripped but the binary payload is
        // preserved untouched.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("binary.bin");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"binary\x00\xff\n").unwrap();
        }
        let r = SecretRef {
            source: SecretSource::File,
            location: path.to_string_lossy().into_owned(),
        };
        let v = block_on(MountedFileSecretAdapter::new().resolve(&r)).expect("resolve");
        assert_eq!(v.as_bytes(), b"binary\x00\xff");
    }

    /// Helper: assert the result is `Err(DomainError::Invariant(msg))` and
    /// return the message. `SecretValue` has no `Debug` so we cannot
    /// use `unwrap_err()` directly — match by hand.
    fn expect_invariant_err(result: DomainResult<SecretValue>) -> String {
        match result {
            Err(DomainError::Invariant(msg)) => msg,
            Err(other) => panic!("expected Invariant, got {other:?}"),
            Ok(_) => panic!("expected Err, got Ok"),
        }
    }

    #[test]
    fn not_found_returns_invariant_error() {
        let r = SecretRef {
            source: SecretSource::File,
            location: "/nonexistent/path/that/does/not/exist".into(),
        };
        let msg = expect_invariant_err(block_on(MountedFileSecretAdapter::new().resolve(&r)));
        assert!(msg.contains("not found"), "got: {msg}");
    }

    #[cfg(unix)]
    #[test]
    fn permission_denied_returns_read_failure() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("locked.txt");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"secret\n").unwrap();
        }
        // chmod 000 — file exists but is unreadable.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();

        let r = SecretRef {
            source: SecretSource::File,
            location: path.to_string_lossy().into_owned(),
        };
        let result = block_on(MountedFileSecretAdapter::new().resolve(&r));

        // Restore perms so tempdir cleanup can delete the file (otherwise
        // some filesystems refuse to remove a 000 file inside a 700 dir
        // owned by us — defensive).
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));

        // CI / sandbox environments occasionally run as root, in which
        // case 000 doesn't actually deny reads. Skip with a soft assert
        // rather than fail the build.
        match result {
            Err(DomainError::Invariant(msg)) => {
                assert!(
                    msg.contains("read failure"),
                    "expected read failure, got: {msg}"
                );
            }
            Ok(_) => {
                // Running as root (CI sandbox quirk). The structural arm
                // is type-checked; behaviourally we cannot exercise it.
                eprintln!("permission_denied test: chmod 000 was no-op (probably root); skipping");
            }
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn mismatched_source_returns_decode_error() {
        let r = SecretRef {
            source: SecretSource::EnvVar,
            location: "WRONG".into(),
        };
        let msg = expect_invariant_err(block_on(MountedFileSecretAdapter::new().resolve(&r)));
        assert!(msg.contains("non-file"), "got: {msg}");
    }

    // ----------------------------------------------------------------------
    // Containment + symlink escape guard (see `docs/how-to/wire-secrets.md`)
    // ----------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn path_inside_secrets_root_resolves_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ok.txt");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"value\n").unwrap();
        }
        let adapter = MountedFileSecretAdapter::new_with_root(Some(dir.path().to_path_buf()));
        let r = SecretRef {
            source: SecretSource::File,
            location: path.to_string_lossy().into_owned(),
        };
        let v = block_on(adapter.resolve(&r)).expect("resolve inside root");
        assert_eq!(v.as_bytes(), b"value");
    }

    #[cfg(unix)]
    #[test]
    fn path_outside_secrets_root_is_rejected() {
        // Build two temp directories: `root` is the configured root,
        // `outside` is a peer that the adapter must refuse to read.
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let leaked = outside.path().join("oops.txt");
        {
            let mut f = std::fs::File::create(&leaked).unwrap();
            f.write_all(b"escaped\n").unwrap();
        }
        let adapter = MountedFileSecretAdapter::new_with_root(Some(root.path().to_path_buf()));
        let r = SecretRef {
            source: SecretSource::File,
            location: leaked.to_string_lossy().into_owned(),
        };
        let msg = expect_invariant_err(block_on(adapter.resolve(&r)));
        assert!(
            msg.contains("outside HORT_SECRETS_FILE_ROOT"),
            "expected escape rejection, got: {msg}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escaping_secrets_root_is_rejected() {
        use std::os::unix::fs::symlink;

        // The symlink TARGET lives outside the root; the symlink ITSELF
        // lives inside the root. `canonicalize` resolves the symlink
        // and the final canonical path must fall outside — adapter
        // rejects.
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let real = outside.path().join("real-secret.txt");
        {
            let mut f = std::fs::File::create(&real).unwrap();
            f.write_all(b"sneaky\n").unwrap();
        }
        let link = root.path().join("looks-legit.txt");
        symlink(&real, &link).unwrap();

        let adapter = MountedFileSecretAdapter::new_with_root(Some(root.path().to_path_buf()));
        let r = SecretRef {
            source: SecretSource::File,
            location: link.to_string_lossy().into_owned(),
        };
        let msg = expect_invariant_err(block_on(adapter.resolve(&r)));
        assert!(
            msg.contains("outside HORT_SECRETS_FILE_ROOT"),
            "expected symlink-escape rejection, got: {msg}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_inside_secrets_root_is_allowed() {
        // Symlink whose target ALSO lives inside the root resolves
        // cleanly — the canonicalisation step doesn't penalise the
        // legitimate redirection-within-root case.
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("real.txt");
        {
            let mut f = std::fs::File::create(&real).unwrap();
            f.write_all(b"legit\n").unwrap();
        }
        let link = root.path().join("link.txt");
        symlink(&real, &link).unwrap();

        let adapter = MountedFileSecretAdapter::new_with_root(Some(root.path().to_path_buf()));
        let r = SecretRef {
            source: SecretSource::File,
            location: link.to_string_lossy().into_owned(),
        };
        let v = block_on(adapter.resolve(&r)).expect("symlink inside root");
        assert_eq!(v.as_bytes(), b"legit");
    }

    #[cfg(unix)]
    #[test]
    fn missing_path_with_root_configured_returns_not_found() {
        // canonicalize fails with NotFound — adapter folds this back
        // into the standard NotFound arm so the wire-shape stays
        // consistent with the no-root case.
        let root = tempfile::tempdir().unwrap();
        let adapter = MountedFileSecretAdapter::new_with_root(Some(root.path().to_path_buf()));
        let r = SecretRef {
            source: SecretSource::File,
            location: root
                .path()
                .join("never-created.txt")
                .to_string_lossy()
                .into_owned(),
        };
        let msg = expect_invariant_err(block_on(adapter.resolve(&r)));
        assert!(msg.contains("not found"), "got: {msg}");
    }

    #[cfg(unix)]
    #[test]
    fn nonexistent_secrets_root_emits_read_failure() {
        // Operator typoed the env var. The error must be distinct
        // from "this particular secret_ref is missing" so the
        // operator can debug.
        let bogus = PathBuf::from("/this/path/never/exists/anywhere");
        let adapter = MountedFileSecretAdapter::new_with_root(Some(bogus));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("any.txt");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"x\n").unwrap();
        }
        let r = SecretRef {
            source: SecretSource::File,
            location: path.to_string_lossy().into_owned(),
        };
        let msg = expect_invariant_err(block_on(adapter.resolve(&r)));
        assert!(
            msg.contains("HORT_SECRETS_FILE_ROOT"),
            "expected misconfigured-root marker, got: {msg}"
        );
    }

    // ----------------------------------------------------------------------
    // Mode warning (world-readable secret file)
    // ----------------------------------------------------------------------

    #[cfg(unix)]
    #[tracing_test::traced_test]
    #[test]
    fn mode_0644_emits_warn() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("loose.txt");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"secret\n").unwrap();
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let r = SecretRef {
            source: SecretSource::File,
            location: path.to_string_lossy().into_owned(),
        };
        let _ = block_on(MountedFileSecretAdapter::new().resolve(&r)).expect("resolve");

        // `logs_contain` is the per-scope helper injected by
        // `#[traced_test]` — it filters captured lines to the test's
        // own scope so parallel test runs do not cross-contaminate.
        assert!(
            logs_contain("readable by group or other"),
            "expected mode-loose warning to fire on 0644"
        );
    }

    #[cfg(unix)]
    #[tracing_test::traced_test]
    #[test]
    fn mode_0600_is_silent() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tight.txt");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"secret\n").unwrap();
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let r = SecretRef {
            source: SecretSource::File,
            location: path.to_string_lossy().into_owned(),
        };
        let _ = block_on(MountedFileSecretAdapter::new().resolve(&r)).expect("resolve");

        assert!(
            !logs_contain("readable by group or other"),
            "0600 must not trigger the mode warning"
        );
    }

    // ----------------------------------------------------------------------
    // Demoted log level — success resolves emit debug!, not info!
    // ----------------------------------------------------------------------

    #[tracing_test::traced_test]
    #[test]
    fn success_resolve_does_not_emit_info_line() {
        // tracing-test's per-scope capture covers the crate by default.
        // The previous behaviour was `info!("secret resolved")`; the
        // demoted version is `debug!`, which `traced_test` collects
        // but is filterable by level. We assert the literal "INFO"
        // marker for the resolve message is absent — debug! is fine.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ok.txt");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"v\n").unwrap();
        }
        let r = SecretRef {
            source: SecretSource::File,
            location: path.to_string_lossy().into_owned(),
        };
        let _ = block_on(MountedFileSecretAdapter::new().resolve(&r)).expect("resolve");

        // `logs_assert` is the per-scope helper injected by
        // `#[traced_test]`. It panics if the closure returns `Err`.
        // We assert no INFO-level "secret resolved" line is captured —
        // the demoted version emits at `debug!`.
        logs_assert(|lines: &[&str]| {
            // ` INFO ` with whitespace boundaries to match the
            // tracing-subscriber level field, not arbitrary substrings.
            let info_resolved = lines
                .iter()
                .filter(|l| l.contains(" INFO ") && l.contains("secret resolved"))
                .count();
            if info_resolved == 0 {
                Ok(())
            } else {
                Err(format!(
                    "successful resolve must not emit INFO-level 'secret resolved' \
                     (found {info_resolved} occurrences in: {lines:?})"
                ))
            }
        });
    }

    #[tracing_test::traced_test]
    #[test]
    fn not_found_still_emits_warn() {
        // Failure paths keep their level. The warn arm fires even
        // though the success arm was demoted.
        let r = SecretRef {
            source: SecretSource::File,
            location: "/definitely/not/here/never".into(),
        };
        let _ = block_on(MountedFileSecretAdapter::new().resolve(&r));

        logs_assert(|lines: &[&str]| {
            let warn_lines = lines
                .iter()
                .filter(|l| l.contains(" WARN ") && l.contains("secret not found"))
                .count();
            if warn_lines >= 1 {
                Ok(())
            } else {
                Err(format!(
                    "expected at least one WARN 'secret not found' line; got: {lines:?}"
                ))
            }
        });
    }

    // ----------------------------------------------------------------------
    // Metric emission tests
    // ----------------------------------------------------------------------
    //
    // Mirrors the storage-adapter pattern (`hort-adapters-storage::filesystem`):
    // wrap the call in `metrics::with_local_recorder` and assert the
    // counter showed up in the snapshot. We only assert one error label
    // (not_found) and one success label per the spec — the other two
    // result variants are exercised by the structural tests above and the
    // catalog string discipline is covered in `metrics::tests`.

    use crate::metrics::{labels, values};
    use metrics::SharedString;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshot};
    use metrics_util::{CompositeKey, MetricKind};

    type MetricEntry = (
        CompositeKey,
        Option<metrics::Unit>,
        Option<SharedString>,
        DebugValue,
    );

    fn capture_async<F, Fut>(f: F) -> Snapshot
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(f());
        });
        snapshotter.snapshot()
    }

    fn counter_value(
        entries: &[MetricEntry],
        name: &str,
        expected_labels: &[(&str, &str)],
    ) -> Option<u64> {
        for (ck, _, _, dv) in entries {
            if ck.kind() != MetricKind::Counter || ck.key().name() != name {
                continue;
            }
            let matches = expected_labels
                .iter()
                .all(|(k, v)| ck.key().labels().any(|l| l.key() == *k && l.value() == *v));
            if !matches {
                continue;
            }
            if let DebugValue::Counter(n) = dv {
                return Some(*n);
            }
        }
        None
    }

    #[test]
    fn metric_fires_success_on_file_resolve() {
        let snap = capture_async(|| async {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("ok.txt");
            tokio::fs::write(&path, b"value\n").await.unwrap();
            let r = SecretRef {
                source: SecretSource::File,
                location: path.to_string_lossy().into_owned(),
            };
            let _ = MountedFileSecretAdapter::new()
                .resolve(&r)
                .await
                .expect("resolve");
        });
        let entries = snap.into_vec();
        let n = counter_value(
            &entries,
            "hort_secret_resolve_total",
            &[
                (labels::SOURCE, values::SOURCE_FILE),
                (labels::RESULT, "success"),
            ],
        );
        assert_eq!(
            n,
            Some(1),
            "expected hort_secret_resolve_total{{source=file,result=success}} == 1; \
             saw entries: {:?}",
            entries
                .iter()
                .map(|(ck, _, _, _)| ck.key().name())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn metric_fires_not_found_on_missing_file() {
        let snap = capture_async(|| async {
            let r = SecretRef {
                source: SecretSource::File,
                location: "/this/path/definitely/does/not/exist".into(),
            };
            let _ = MountedFileSecretAdapter::new().resolve(&r).await;
        });
        let entries = snap.into_vec();
        let n = counter_value(
            &entries,
            "hort_secret_resolve_total",
            &[
                (labels::SOURCE, values::SOURCE_FILE),
                (labels::RESULT, "not_found"),
            ],
        );
        assert_eq!(
            n,
            Some(1),
            "expected hort_secret_resolve_total{{source=file,result=not_found}} == 1"
        );
    }
}
