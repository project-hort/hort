# Develop hort locally

Use this guide to set up a Rust workspace for contributing to hort. This is **developer documentation**; to deploy hort, use the [operator documentation](https://project-hort.de/docs/index.html).

## Prerequisites

- Git and the Rust toolchain required by the repository's `Cargo.toml` (workspace `rust-version` is **1.97** in this source snapshot). Check the current workspace before installing a toolchain.
- A Linux/macOS development environment or a supported Rust toolchain on your platform.
- PostgreSQL and Docker/Compose **only** for tests that need them; basic library checks do not require a running hort service.

## Clone and inspect the workspace

```sh
git clone https://github.com/project-hort/hort.git
cd hort
grep -n 'rust-version' Cargo.toml
cargo --version
```

## Build and run library tests

```sh
cargo build --workspace
cargo test --workspace --lib
```

These commands build and test workspace crates. Building successfully is **not** proof that the database-backed or end-to-end scenarios pass.

## Format and lint

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

Before submitting changes, see [Testing changes](../contributing/testing-changes.md). For the workspace architecture, start with the [Crate map](../crates/crate-map.md).

## Find the owning crate

When changing a protocol endpoint, begin with `crates/hort-http-<format>/`. For a domain invariant, look at `crates/hort-domain/`. To change infrastructure wiring, inspect `crates/hort-server/` and the relevant adapter. These are navigation hints, not substitutes for reading the actual dependency graph.

## Get help or propose a change

Read [Contributing](../../../CONTRIBUTING.md) and open a GitHub issue or pull request with a reproducible description. The repository's current CI checks remain the authoritative acceptance criteria.
