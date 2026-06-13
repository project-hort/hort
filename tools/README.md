# `tools/`

Standalone, **outside-workspace** binaries. Each subdirectory here is a
self-contained Cargo project that builds via `(cd tools/<name> && cargo
build)`, not as part of the workspace.

## Why these live outside the workspace

The workspace `Cargo.toml` excludes `tools/*` (`exclude = ["tools/*"]`). The two reasons a tool belongs here, not in `crates/`:

1. **Throwaway / one-off binaries.** Calibration scripts, metadata-size
   measurement runs, ad-hoc migration baselines. They produce a number or
   a report, the report informs a design decision, and the binary is then
   archived. Putting them in the workspace would pull their CLI/HTTP-
   scraping dependency surface (`clap`, `reqwest`, `tracing-subscriber`,
   `chrono`, `anyhow`, …) into the production `Cargo.lock` and the
   workspace lint profile for no production value.

2. **Tooling that must not be subject to the production lint profile.**
   Tools sometimes need to do things (raw `reqwest::Client::new`, ad-hoc
   error handling, broad `unwrap`s) that the workspace lint profile and
   architectural rules forbid for good reason in production code. A tool
   that lives outside the workspace cannot violate workspace rules — they
   formally do not apply.

## Architectural rule scoping

Several architectural rules are **scoped to the workspace** and do not
apply to crates under `tools/`. The most load-bearing one is:

- **`reqwest::Client::builder()` mandate (ADR 0010).** The rule that every
  adapter opening TLS must build via `reqwest::Client::builder()` so the
  composition root can layer `apply_to_reqwest_builder` onto it is scoped
  to **production adapters in `crates/`**. Tools in `tools/` are not in
  the composition root and are not exposed to operator-controlled TLS
  configuration; they may use `reqwest::Client::new()`. Each tool's
  `Cargo.toml` documents its specific exemption rationale and the
  promotion-back checklist.

- **Workspace lints (`[lints] workspace = true`).** Tools cannot inherit
  the workspace lint profile. They use cargo's defaults. Crate-local
  `#![deny(...)]` is acceptable if a tool wants stricter linting; do not
  add it as a workaround for genuine cargo-default behaviour, since
  diverging from cargo defaults in a one-off tool is rarely worth the
  maintenance cost.

- **Production dep gates.** `cargo audit`, coverage thresholds, and
  duplication gates apply to the workspace. Tools are excluded from those
  gates by virtue of not being workspace members.

## Adding a new tool

1. Create `tools/<name>/` with its own `Cargo.toml`. Inline versions
   (do not use `workspace = true`); the crate will not see the workspace
   table.
2. Path deps into the workspace use `../../crates/<crate>`.
3. The top of the `Cargo.toml` must contain a doc-comment block stating:
   - that the crate is intentionally outside the workspace,
   - which architectural rules formally do not apply and why,
   - the promotion-back checklist if the tool is ever re-promoted into
     `crates/`.
4. Add a brief README inside `tools/<name>/` if the tool's invocation is
   non-obvious.

## Promotion back into the workspace

If a tool stops being a one-off (e.g. it gets wired into CI, or its
results gate a release), promote it:

1. Move it back under `crates/` (or add `tools/<name>` to the workspace
   `members = [...]` list and narrow the `tools/*` exclude).
2. Switch path deps from `../../crates/<crate>` to `../<crate>`.
3. Restore `version.workspace = true`, `edition.workspace = true`,
   `license.workspace = true` on `[package]`.
4. Restore `[lints] workspace = true`; convert each `[dependencies]`
   entry to `{ workspace = true }`.
5. Audit and migrate every `reqwest::Client::new()` call site to
   `reqwest::Client::builder()` (ADR 0010); route the result through
   `apply_to_reqwest_builder` from `hort-net-egress`.
6. Add the crate to the `cargo audit` / coverage / duplication gates as
   appropriate for its tier.

## Current tools

- `measurement-tools/` — metadata-cap calibrator.
