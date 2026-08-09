# 098 — Toolchain: build on Rust 1.94.1 (MSRV contract unchanged)

**Issue:** operator direction (Tom, Matrix 2026-08-09), option **A** ·
**Branch:** `chore/rust-1.94.1` · **Scope:** toolchain pins only

## Change

Move the toolchain we build and test with from 1.94.0 to 1.94.1. The MSRV
**contract** does not move: `scripts/check-rust-version.sh` compares at
MAJOR.MINOR and documents the patch level as implementation detail.

- `rust-toolchain.toml` — `channel = "1.94.0"` → `"1.94.1"`. This is the only
  substantive edit: rustup honours this file inside the checkout, so it is
  what actually selects the compiler everywhere (CI jobs, the product image
  build, local checkouts).
- `.gitlab-ci.yml` — `RUST_IMAGE: "rust:1.94-slim"` → `"rust:1.94.1-slim"`.
- `docker/Dockerfile.hort-server`, `docker/Dockerfile.worker` — `ARG
  RUST_VERSION=1.94` → `1.94.1`.

**Unchanged on purpose:** `Cargo.toml` `rust-version = "1.94"` and
`.clippy.toml` `msrv = "1.94.0"`. The supported floor stays 1.94.0; only the
toolchain we exercise moves.

## Why the image pins are cosmetic here

`rust:1.94-slim` and `rust:1.94.1-slim` resolve to the SAME digest —
`sha256:cf09adf8c3ebaba10779e5c23ff7fe4df4cccdab8a91f199b0c142c53fef3e1a` —
and that digest is already pinned in both Dockerfiles. The base image is
therefore already 1.94.1; the tag text is documentation. **Do not change the
digest.**

The real effect of the change is the opposite of a cost: today
`rust-toolchain.toml` asks for 1.94.0 inside an image that ships 1.94.1, so
rustup downloads a second toolchain on every build. Aligning the channel
removes that download.

## Risk

A patch bump can introduce new clippy lints, and the gate runs
`-D warnings`. If any fire, fix them in this same change.

## Acceptance

Full gate green: `cargo fmt --all -- --check`, `cargo clippy --workspace
--all-targets -- -D warnings`, `cargo test --workspace`, plus
`bash scripts/check-rust-version.sh` (the MAJOR.MINOR lockstep guard must
still pass with Cargo MSRV at "1.94" and the channel at "1.94.1").
