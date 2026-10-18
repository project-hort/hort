//! Atomic 0600 secret-file write — the one way a hort binary puts a
//! plaintext credential on disk.
//!
//! This crate *writes* a secret to a path the operator named. It is not
//! the counterpart of
//! `hort_adapters_secrets::MountedFileSecretAdapter`, which *reads* a
//! secret an external secret manager mounted; the two never meet.
//!
//! # The fault class this closes
//!
//! The obvious implementation — `OpenOptions::new().write(true)
//! .create(true).truncate(true).mode(0o600).open(path)` — is wrong in
//! three ways, because `OpenOptionsExt::mode` applies **only when the
//! file is created**:
//!
//! - **(a) umask window.** A `create` without `mode` lands at the
//!   process umask (commonly 0644) and needs a follow-up `chmod`, which
//!   leaves the secret world-readable in between. `create_new` + `mode`
//!   has no such window: the file exists at 0600 from the first
//!   instant.
//! - **(b) inherited mode.** An *existing* target keeps whatever
//!   permissions it already had — a group- or world-readable file is
//!   truncated in place and the secret lands inside it. The documented
//!   0600 promise silently does not hold.
//! - **(c) pre-created target.** `open` follows a symlink, so a local
//!   user who can create the target path first decides where the secret
//!   actually lands; pre-creating a *regular* file instead reproduces
//!   case (b) on demand.
//!
//! # The form
//!
//! [`write_secret_file`] writes a uniquely-named sibling temp file in
//! the **same directory** via `OpenOptions … create_new(true)
//! .mode(0o600)`, `sync_all`s it, and `rename`s it over the target:
//!
//! - `create_new` is `O_EXCL`: the write only ever reaches an inode this
//!   process created, at 0600, with no umask window — (a), and (c) for
//!   the temp name.
//! - `rename` replaces the target's directory entry whatever it held, so
//!   the final file never inherits a stale mode — (b) — and a symlink at
//!   the target is **replaced, not followed** — (c).
//! - The replace is atomic on one filesystem, so a concurrent reader
//!   sees either the old file or the complete new one, never a partial
//!   or a wider-moded one.
//! - The temp file is best-effort removed on every error path.
//!
//! # What it deliberately does not do
//!
//! **It never touches the target's parent directory** — no
//! `create_dir_all`, no `chmod`. The caller owns that decision, because
//! the right answer depends on who chose the path. For a path under
//! `$HOME` that this process also created, tightening the parent is
//! correct and the caller does it before calling in. For an
//! operator-named path it is not: `/etc/hort` is deliberately
//! `root:hort` 0750 so the service user can read the env files beside
//! the token, and silently pulling it to 0700 would break the service
//! on the next token mint. The parent's mode is not what protects the
//! secret anyway — the 0600 inode is.
//!
//! The replaced file is owned by **this** process's uid/gid, not the
//! previous file's. Replacing an inode cannot preserve an owner the
//! writer may not even be able to set. A caller that needs a different
//! owner than the writing process sets it after the write.
//!
//! The temp name is derived from the pid plus a process-local counter,
//! not from randomness, and a `create_new` collision is **not** retried.
//! In a world-writable parent (`/tmp`) that makes a pre-created temp
//! name a repeatable denial vector, and a temp file left behind by a
//! crashed run with the same pid blocks the first write of the next run.
//! Both fail closed — no secret is ever written into a file this process
//! did not create — and the availability half is the caller's to decide,
//! so it is not papered over here.
//!
//! The parent directory is not `fsync`ed, so a crash immediately after
//! the rename can lose it. Durability is not the property this crate
//! owns: the credential is also hashed in the database, and a lost write
//! is recovered by re-minting.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Disambiguates concurrent writers inside one process. Paired with the
/// pid in the temp name so two threads writing different secrets into one
/// directory cannot pick the same temp path.
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Which step of [`write_secret_file`] failed.
///
/// Exposed so a caller can tell "the directory you named does not exist"
/// ([`Step::CreateTemp`] with [`io::ErrorKind::NotFound`]) from "the
/// replace failed" ([`Step::Replace`]) without string-matching a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Deriving the sibling temp path — the target names no file.
    DeriveTempPath,
    /// `create_new` of the sibling temp file at mode 0600. A `NotFound`
    /// here means the parent directory does not exist; an `AlreadyExists`
    /// means something already occupies the temp name.
    CreateTemp,
    /// Writing the secret bytes into the temp file.
    Write,
    /// `sync_all` on the temp file.
    Sync,
    /// `rename` of the temp file over the target.
    Replace,
}

impl Step {
    /// Human-readable phrase naming the failed step, for [`fmt::Display`].
    fn describe(self) -> &'static str {
        match self {
            Step::DeriveTempPath => "deriving a temp file name for secret file",
            Step::CreateTemp => "creating temp secret file",
            Step::Write => "writing temp secret file",
            Step::Sync => "syncing temp secret file",
            Step::Replace => "atomically replacing secret file",
        }
    }
}

/// A [`write_secret_file`] failure: which step failed, on which path, and
/// the underlying [`io::Error`].
///
/// The path is the one the failing syscall was aimed at — the temp
/// sibling for the create/write/sync steps, the caller's target for the
/// replace step — because that is the path an operator needs to see.
#[derive(Debug)]
pub struct SecretFileError {
    step: Step,
    path: PathBuf,
    source: io::Error,
}

impl SecretFileError {
    /// Constructor naming the failed step and the path the syscall was
    /// aimed at.
    fn at(step: Step, path: &Path, source: io::Error) -> Self {
        Self {
            step,
            path: path.to_path_buf(),
            source,
        }
    }

    /// The step that failed.
    #[must_use]
    pub fn step(&self) -> Step {
        self.step
    }

    /// The path the failing syscall was aimed at.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The underlying I/O error kind.
    #[must_use]
    pub fn io_kind(&self) -> io::ErrorKind {
        self.source.kind()
    }
}

impl fmt::Display for SecretFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {:?}: {}",
            self.step.describe(),
            self.path,
            self.source
        )
    }
}

impl std::error::Error for SecretFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Place `bytes` at `path` as a file this process created at mode 0600,
/// replacing whatever the path held.
///
/// See the crate docs for the fault class this closes, the exact form,
/// and what it deliberately leaves to the caller — in particular that
/// the **parent directory must already exist** and is never modified.
///
/// On Unix the resulting file is exactly 0600. On other platforms the
/// atomic create-and-replace still holds but no mode is set (matching
/// `std`'s portability surface — `OpenOptionsExt` is Unix-only).
///
/// # Errors
///
/// Returns [`SecretFileError`] if the temp path cannot be derived, the
/// temp file cannot be created at 0600, the bytes cannot be written or
/// synced, or the rename over the target fails. The temp file is
/// best-effort removed on every one of those paths, so a failed call
/// leaves no secret behind at a name the caller does not know about.
pub fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<(), SecretFileError> {
    let tmp_path = temp_sibling(path)?;

    if let Err(e) = fill_temp(&tmp_path, bytes) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }

    // Atomic same-filesystem replace. Whatever the target held — a
    // world-readable regular file, a symlink pointing elsewhere, nothing
    // — the directory entry now names our fresh 0600 inode.
    if let Err(source) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(SecretFileError::at(Step::Replace, path, source));
    }

    Ok(())
}

/// Derive a uniquely-named temp path in the **same directory** as `path`.
///
/// Same directory because `rename` is only atomic within one filesystem;
/// a temp file in `/tmp` would degrade the replace to a copy across a
/// mount boundary. The leading dot keeps the temp out of a casual `ls`
/// while it exists.
fn temp_sibling(path: &Path) -> Result<PathBuf, SecretFileError> {
    let Some(file_name) = path.file_name() else {
        // `/`, or a path ending in `..`. There is no target to replace,
        // so fail here with the reason rather than inventing a temp name
        // and surfacing a confusing rename error one step later.
        return Err(SecretFileError::at(
            Step::DeriveTempPath,
            path,
            io::Error::new(io::ErrorKind::InvalidInput, "path names no file"),
        ));
    };
    // `parent()` is `Some("")` for a bare relative file name, and joining
    // onto `""` yields the plain temp name — i.e. the current directory,
    // which is where that target lives too.
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    Ok(dir.join(format!(
        ".{}.{}.{seq}.tmp",
        file_name.to_string_lossy(),
        std::process::id()
    )))
}

/// Create the temp file at 0600 and fill it with `bytes`.
///
/// `create_new` is the load-bearing flag: combined with `mode` it is an
/// atomic create at 0600 with no umask window, and it *fails* rather than
/// writing into anything — file or symlink — that already occupies the
/// temp name.
fn fill_temp(tmp_path: &Path, bytes: &[u8]) -> Result<(), SecretFileError> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(tmp_path)
        .map_err(|e| SecretFileError::at(Step::CreateTemp, tmp_path, e))?;
    f.write_all(bytes)
        .map_err(|e| SecretFileError::at(Step::Write, tmp_path, e))?;
    // Sync before the rename so the replace cannot publish a directory
    // entry whose data has not reached the disk.
    f.sync_all()
        .map_err(|e| SecretFileError::at(Step::Sync, tmp_path, e))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
//
// The property under test is a property of a real filesystem — the mode
// bits of the inode the target names afterwards, and whether a symlink at
// the target was followed — so every test drives a real scratch directory.
// A mock filesystem could not observe either.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"hort_pat_sekret-value-xyz\n";

    /// Permission bits of `path`, following no symlink of its own
    /// (`metadata` follows; every caller here asserts on a regular file).
    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).expect("stat").permissions().mode() & 0o777
    }

    /// File names directly inside `dir`, sorted — used to assert no temp
    /// sibling survives.
    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    // -- case: the target does not exist -----------------------------------

    #[cfg(unix)]
    #[test]
    fn fresh_target_is_created_at_0600_with_exact_bytes() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("token");

        write_secret_file(&path, SECRET).expect("write");

        assert_eq!(mode_of(&path), 0o600, "a fresh secret file must be 0600");
        assert_eq!(fs::read(&path).unwrap(), SECRET);
        assert_eq!(
            entries(tmp.path()),
            vec!["token".to_string()],
            "no temp sibling may survive a successful write"
        );
    }

    // -- case: an existing world-readable regular file ---------------------

    #[cfg(unix)]
    #[test]
    fn existing_world_readable_target_ends_up_0600_not_truncated_in_place() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("token");

        // A local user pre-creates the target world-readable.
        fs::write(&path, b"pre-existing bytes").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let stale_ino = inode_of(&path);
        assert_eq!(mode_of(&path), 0o644, "precondition");

        write_secret_file(&path, SECRET).expect("write");

        assert_eq!(
            mode_of(&path),
            0o600,
            "an existing 0644 target must end up 0600 — the secret must not \
             land in a file whose mode this process did not set"
        );
        assert_eq!(fs::read(&path).unwrap(), SECRET, "stale bytes replaced");
        assert_ne!(
            inode_of(&path),
            stale_ino,
            "the target must be a NEW inode (replaced), not the pre-created \
             one truncated in place"
        );
    }

    /// Inode number of `path` — the direct evidence that the target was
    /// replaced rather than reopened.
    #[cfg(unix)]
    fn inode_of(path: &Path) -> u64 {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(path).expect("stat").ino()
    }

    // -- case: an existing symlink at the target ---------------------------

    #[cfg(unix)]
    #[test]
    fn existing_symlink_target_is_replaced_not_followed() {
        let tmp = tempfile::TempDir::new().unwrap();
        let elsewhere = tmp.path().join("attacker-readable");
        fs::write(&elsewhere, b"original elsewhere bytes").unwrap();
        let path = tmp.path().join("token");
        std::os::unix::fs::symlink(&elsewhere, &path).unwrap();
        assert!(
            fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink(),
            "precondition"
        );

        write_secret_file(&path, SECRET).expect("write");

        // The link is gone: the target path is now our own regular file.
        let meta = fs::symlink_metadata(&path).unwrap();
        assert!(
            meta.file_type().is_file(),
            "the symlink must be replaced by a regular file, not followed"
        );
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(fs::read(&path).unwrap(), SECRET);

        // And the place it pointed at never saw the secret.
        assert_eq!(
            fs::read(&elsewhere).unwrap(),
            b"original elsewhere bytes",
            "the former link target must be untouched — nothing of the \
             secret may reach a path the operator did not name"
        );
    }

    // -- the parent directory is never modified ----------------------------

    #[cfg(unix)]
    #[test]
    fn parent_directory_mode_is_left_alone() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("etc-hort");
        fs::create_dir(&dir).unwrap();
        // Mimic /etc/hort: group-readable on purpose so the service user
        // can read the env files that live beside the token.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o750)).unwrap();

        write_secret_file(&dir.join("tasks-token"), SECRET).expect("write");

        assert_eq!(
            mode_of(&dir),
            0o750,
            "the parent of an operator-named path must keep its mode — \
             pulling it to 0700 would lock the service user out of the \
             config beside the token"
        );
    }

    // -- repeated writes (the overwrite the operator expects) --------------

    #[cfg(unix)]
    #[test]
    fn rewriting_the_same_path_succeeds_and_leaves_no_temp() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("token");

        write_secret_file(&path, b"first").expect("first write");
        write_secret_file(&path, b"second").expect("second write");

        assert_eq!(fs::read(&path).unwrap(), b"second");
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(entries(tmp.path()), vec!["token".to_string()]);
    }

    // -- error paths --------------------------------------------------------

    #[test]
    fn missing_parent_directory_fails_at_create_temp_with_not_found() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("no-such-dir").join("token");

        let err = write_secret_file(&path, SECRET).expect_err("must fail");

        assert_eq!(err.step(), Step::CreateTemp);
        assert_eq!(err.io_kind(), io::ErrorKind::NotFound);
        assert!(
            !path.exists(),
            "a failed write must not leave the target behind"
        );
        assert!(
            err.to_string().contains("creating temp secret file"),
            "message must name the step: {err}"
        );
    }

    #[test]
    fn a_path_naming_no_file_fails_before_touching_the_filesystem() {
        let err = write_secret_file(Path::new("/"), SECRET).expect_err("must fail");

        assert_eq!(err.step(), Step::DeriveTempPath);
        assert_eq!(err.io_kind(), io::ErrorKind::InvalidInput);
        assert_eq!(err.path(), Path::new("/"));
    }

    /// An occupied temp name fails closed instead of being written
    /// through — the `create_new` half of the contract.
    ///
    /// Driven against `fill_temp` rather than `write_secret_file` because
    /// the temp name carries a process-local counter: predicting the name
    /// the next public call will pick would race every other test in this
    /// binary. The property is `create_new`'s, and this is where it lives.
    #[cfg(unix)]
    #[test]
    fn an_occupied_temp_name_fails_closed_rather_than_writing_into_it() {
        let tmp = tempfile::TempDir::new().unwrap();
        let squatted = tmp.path().join(".token.squatted.tmp");
        fs::write(&squatted, b"squatter").unwrap();

        let err = fill_temp(&squatted, SECRET).expect_err("must fail closed");

        assert_eq!(err.step(), Step::CreateTemp);
        assert_eq!(err.io_kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            fs::read(&squatted).unwrap(),
            b"squatter",
            "create_new must refuse the occupied name, never write through it"
        );
    }

    /// The same refusal when a *symlink* occupies the temp name: `O_EXCL`
    /// does not follow it, so a pre-planted link cannot redirect the
    /// secret.
    #[cfg(unix)]
    #[test]
    fn a_symlink_at_the_temp_name_is_refused_not_followed() {
        let tmp = tempfile::TempDir::new().unwrap();
        let elsewhere = tmp.path().join("elsewhere");
        fs::write(&elsewhere, b"original").unwrap();
        let squatted = tmp.path().join(".token.squatted.tmp");
        std::os::unix::fs::symlink(&elsewhere, &squatted).unwrap();

        let err = fill_temp(&squatted, SECRET).expect_err("must fail closed");

        assert_eq!(err.step(), Step::CreateTemp);
        assert_eq!(err.io_kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&elsewhere).unwrap(), b"original");
    }

    // -- error surface shape -----------------------------------------------

    #[test]
    fn error_display_and_source_name_the_step_path_and_cause() {
        let err = SecretFileError::at(
            Step::Replace,
            Path::new("/run/secrets/hort.token"),
            io::Error::new(io::ErrorKind::PermissionDenied, "nope"),
        );

        let msg = err.to_string();
        assert!(msg.contains("atomically replacing secret file"), "{msg}");
        assert!(msg.contains("/run/secrets/hort.token"), "{msg}");
        assert!(msg.contains("nope"), "{msg}");
        assert_eq!(err.step(), Step::Replace);
        assert_eq!(err.io_kind(), io::ErrorKind::PermissionDenied);
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn every_step_describes_itself_distinctly() {
        let steps = [
            Step::DeriveTempPath,
            Step::CreateTemp,
            Step::Write,
            Step::Sync,
            Step::Replace,
        ];
        let mut seen: Vec<&str> = steps.iter().map(|s| s.describe()).collect();
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(before, seen.len(), "step descriptions must be distinct");
        assert!(seen.iter().all(|d| !d.is_empty()));
    }

    #[test]
    fn temp_sibling_lives_in_the_targets_own_directory() {
        let path = Path::new("/run/secrets/hort-dev.token");
        let tmp = temp_sibling(path).expect("derive");

        assert_eq!(
            tmp.parent(),
            path.parent(),
            "the temp file must be a sibling — rename is only atomic \
             within one filesystem"
        );
        let name = tmp.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with(".hort-dev.token."), "{name}");
        assert!(name.ends_with(".tmp"), "{name}");
    }

    #[test]
    fn temp_sibling_names_are_unique_within_a_process() {
        let path = Path::new("token");
        let a = temp_sibling(path).expect("derive");
        let b = temp_sibling(path).expect("derive");
        assert_ne!(a, b, "two concurrent writers must not share a temp name");
        // A bare relative target's sibling is a bare relative temp name.
        assert_eq!(a.parent(), Some(Path::new("")));
    }
}
