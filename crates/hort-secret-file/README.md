# hort-secret-file — Atomic 0600 Secret-File Write

## Layer

Leaf — std-only: `[dependencies]` is empty. Zero `hort-*` dependencies and
zero external crates.io runtime dependencies. The only entry in
`[dev-dependencies]` is `tempfile`, because the behaviour under test is a
property of a real filesystem.

## Responsibility

The **one** way a hort binary puts a plaintext credential on disk. Takes a
path and bytes, and leaves the path naming a regular file this process
created at mode 0600 — whatever the path held before.

This crate *writes*. It is not the counterpart of
`hort_adapters_secrets::MountedFileSecretAdapter`, which *reads* a secret
an external secret manager mounted.

## Ports

- **Implements:** none — no port traits; this crate sits below the domain
  layer entirely.
- **Consumes:** none.

## Key types

- `write_secret_file(path: &Path, bytes: &[u8]) -> Result<(), SecretFileError>`
  — temp sibling via `create_new(true).mode(0o600)`, `sync_all`, `rename`
  over the target.
- `SecretFileError` — `step()`, `path()`, `io_kind()`; `Display` names all
  three; `source()` yields the `io::Error`.
- `Step::{DeriveTempPath, CreateTemp, Write, Sync, Replace}` — which
  syscall failed, so a caller can tell "the directory you named does not
  exist" from "the replace failed" without string-matching.

## Why the form

`OpenOptionsExt::mode` applies **only when the file is created**, so the
obvious `create(true).truncate(true).mode(0o600)` leaves three holes: a
umask window before a follow-up `chmod`; an *existing* group- or
world-readable target truncated in place, keeping its mode; and a symlink
at the target silently followed to a path the operator never named.
`create_new` + `mode` + `rename` closes all three — the write only ever
reaches an inode this process created at 0600, and the replace swaps the
directory entry rather than reopening whatever it held.

## Rules

- Zero `hort-*` dependencies is deliberate and load-bearing. The two sinks
  that put a plaintext credential on disk are `hort-cli`
  (`auth::login::persist_token_to` → `~/.hort/config.toml`) and
  `hort-server` (`cli::admin::write_plaintext` → `--output=file:<path>`).
  `hort-cli` is a pure HTTP client with no
  `hort-domain`/`hort-app`/`hort-adapters-*` dep (enforced via
  `cargo tree -p hort-cli`), so a shared helper in `hort-domain` (also a
  zero-I/O layer that must not grow a filesystem surface) or `hort-app`
  would drag that isolation down — the same reasoning that produced
  `hort-attribution` (ADR 0047, D2). Do not add a `hort-domain`/`hort-app`
  dependency to this crate under any circumstance.
- **Never touch the target's parent directory** — no `create_dir_all`, no
  `chmod`. Who owns that decision depends on who chose the path, so it
  stays with the caller: `/etc/hort` is deliberately `root:hort` 0750 so
  the service user can read the env files beside the token, and pulling it
  to 0700 on a token mint would break the service. The parent's mode is
  not what protects the secret; the 0600 inode is.
- No `tokio`. The write is a few syscalls on a path the operator named, so
  a blocking `std::fs` call is the honest shape and keeps the crate usable
  from both sync CLI paths and an async one.
- A `create_new` collision is **not** retried and the temp name is not
  randomised. Both fail closed — no secret reaches a file this process did
  not create — and the availability half (a world-writable parent makes a
  pre-created temp name a repeatable denial vector; a crashed run can
  leave a temp file that blocks the next write at the same pid) is the
  caller's call, not something to paper over here.
