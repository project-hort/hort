# 159 — Rust toolchain 1.94.1 → 1.97.1 (MSRV + builder images)

**Contract:** this file. Runtime-baseline bump, one branch, all pin sites
together. Target is 1.97.1 (1.98 deliberately skipped; the next move goes to a
seasoned 1.99+ when a trigger fires).

## Pin sites — all move together

| site | today | to |
|---|---|---|
| `.clippy.toml` `msrv` | 1.94.0 | 1.97.0 |
| `Cargo.toml` `rust-version` | 1.94 | 1.97 |
| `docker/Dockerfile.hort-server` `ARG RUST_VERSION` + `rust:*-slim` digest | 1.94.1 | 1.97.1 + current upstream digest |
| `docker/Dockerfile.worker` `ARG RUST_VERSION` + digest | 1.94.1 | same |
| `deploy/compose/Dockerfile` `rust:1.94-slim-trixie` digest | 1.94 | `rust:1.97-slim-trixie` + current digest |
| `rust-toolchain.toml` `channel` | 1.94.1 | 1.97.1 (checked by `check-rust-version.sh` lockstep) |
| `scripts/native-tests/Dockerfile.client` `rust:*-slim-trixie` tag + comment | 1.94 | 1.97 (E2E client image; not gate-checked, kept in lockstep) |

Resolve the new image digests from Docker Hub for the exact tags used and pin
them in the same `tag@sha256:` form as today. `scripts/check-rust-version.sh`
must pass — it enforces the `.clippy.toml` ↔ `Cargo.toml` lockstep.

## Lint fallout — fix forward, never silence

1.94 → 1.97 spans several clippy releases. New lints under `-D warnings` are
fixed forward in this branch, in idiomatic form. A lint whose fix would force a
design change (public API shape, layering, port contract) is a STOP-and-report,
never a `#[allow]`.

## Gate (evidence in the report — one-shot log capture, `set -o pipefail`)

The sandbox toolchain provides 1.97.1 via rustup (`rustup toolchain install
1.97.1` if absent; run every gate step with `cargo +1.97.1 …` — the report
must show the toolchain actually used, e.g. `cargo +1.97.1 --version`):

- `cargo +1.97.1 fmt --all -- --check`
- `cargo +1.97.1 clippy --workspace --all-targets -- -D warnings`
- `cargo +1.97.1 test --workspace`
- `cargo-audit audit -D warnings` and `cargo-deny check`
- `scripts/check-rust-version.sh`

No dependency changes expected: `Cargo.lock` must not move (a `rust-version`
bump alone changes no third-party crate). If the lockfile moves anyway, STOP
and report why. Attribution therefore also must not change.

## Acceptance

All five pin sites on 1.97.x with current digests, lockstep script green, full
gate green on 1.97.1, zero `#[allow]` additions, `Cargo.lock` untouched.
