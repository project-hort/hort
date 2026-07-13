# 022 — CLI print-and-exit commands panic on broken pipe (SIGPIPE / EPIPE)

- **Source:** GitLab issue #22
- **Type:** bug (CLI robustness)
- **Model hint:** small (mechanical/pattern work — single shared helper + call-site swap)
- **Reviewable unit:** one directive.

## Problem

The print-and-exit subcommands panic with a broken-pipe error when stdout is
piped to a consumer that closes early (`hort-cli attribution | head`,
`… | less` then `q`). Rust ignores `SIGPIPE` by default, so the write to a
closed pipe returns `EPIPE`, and the `print!` / `io::stdout()` write path
unwraps it → panic on stderr. The bytes still reach the consumer; this is a
cosmetic stderr panic, not a correctness or legal defect. Pre-existing
(not introduced by #17). Exposure is highest for `attribution` (~900 KB
embedded doc → `| head` is a very plausible invocation).

## Chosen approach

Safe write-error handling — **not** `libc::signal(SIGPIPE, SIG_DFL)` (blocked by
the workspace-wide `unsafe_code = "forbid"`; ADR/CLAUDE.md policy).

Add one shared helper in the zero-`hort-*`-dep `hort-attribution` crate (std-only,
no new deps), e.g.:

```rust
/// Write `s` to stdout; treat a closed-pipe (EPIPE) as a clean exit.
pub fn write_stdout_or_exit(s: &str) -> std::process::ExitCode { … }
```

which writes via `io::stdout().write_all`, and on `Err(e) if e.kind() ==
io::ErrorKind::BrokenPipe` returns `ExitCode::SUCCESS` (swallow, exit 0),
propagating any other error as today.

Swap every print-and-exit site to route through it:

| Binary | Sites |
|---|---|
| `hort-cli` | `src/attribution.rs`, `src/license.rs`, `src/completions.rs` |
| `hort-server` | `src/cli/attribution.rs`, `src/cli/license.rs` |
| `hort-worker` | `src/attribution.rs`, `src/license.rs` |

`completions.rs` uses `clap_complete::generate(…, &mut io::stdout())` — wrap the
same broken-pipe swallow around that write (generate into a buffer, then
`write_stdout_or_exit`, or handle the writer error).

## Out of scope

- Any change to what the commands *print* (attribution content, license text).
- `SIGPIPE`-at-process-start resets (unsafe; forbidden).
- The server/worker long-running paths (this is only the print-and-exit floor).

## Acceptance criteria

- `hort-cli attribution | head -1`, `hort-cli license --full | head`,
  `hort-cli completions bash | head`, and the `hort-server` / `hort-worker`
  `attribution` / `license` equivalents **exit 0 with no panic** when the pipe
  closes early; full output still reaches an un-truncating consumer.
- A regression test exercises the `BrokenPipe` branch of the shared helper
  (unit test on `hort-attribution` — simulate a writer that returns
  `ErrorKind::BrokenPipe`; assert `ExitCode::SUCCESS`, no panic).
- `hort-attribution` stays zero-`hort-*`-dep and std-only (no new crate deps).
- Full local gate green (`fmt` / `clippy --workspace --all-targets` /
  `cargo test --workspace` / `audit` / `deny`); `hort-cli` ≥ 85% on new lines.

## Verification (for the cockpit report)

- Build the CLI and run each command piped to `head`; confirm exit 0 and no
  `thread 'main' panicked … Broken pipe` on stderr.
- Show the new unit test passing.
