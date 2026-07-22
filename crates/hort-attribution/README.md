# hort-attribution — License + Third-Party Attribution

## Layer

Leaf — genuinely std-only: both `[dependencies]` and `[dev-dependencies]`
are empty in `Cargo.toml`. Zero `hort-*` dependencies **and** zero external
crates.io dependencies of any kind (not even `serde`/`clap`/`tokio`).

## Responsibility

Embeds the project's license text and generated third-party attribution at
compile time (`include_str!` of the root `LICENSE-MIT`, `LICENSE-APACHE`,
`THIRD-PARTY-LICENSES.{md,json}`) and exposes plain sync rendering
functions for the `license`/`attribution` CLI subcommands shared by all
three shipped binaries.

## Ports

- **Implements:** none — no port traits; this crate sits below the domain
  layer entirely.
- **Consumes:** none.

## Key types

- `SPDX: &str` — `"MIT OR Apache-2.0"`.
- `render_license(full: bool) -> String`.
- `AttributionFormat::{Text, Json}`, `render_attribution(format) -> &'static str`.
- `write_stdout_or_exit(s: &str) -> ExitCode` — a SIGPIPE-safe stdout
  writer (Rust ignores SIGPIPE and `unsafe` is workspace-forbidden, so this
  swallows `BrokenPipe` into a clean exit rather than panicking).

## Rules

- Zero `hort-*` dependencies is deliberate and load-bearing: `hort-cli` is
  a pure HTTP client with no `hort-domain`/`hort-app`/`hort-adapters-*` dep
  (enforced via `cargo tree -p hort-cli`), and this crate is the one thing
  all three shipped binaries (`hort-server`/`hort-worker`/`hort-cli`)
  depend on for their `license`/`attribution` subcommands. Putting this
  logic in `hort-domain` or `hort-app` instead would drag `hort-cli`'s
  isolation guarantee down with it — do not add a `hort-domain`/`hort-app`
  dependency to this crate under any circumstance.
- No `tokio`, no `clap` — each binary's clap wiring lives in that binary,
  not here.
