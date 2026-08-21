# 128 — Attribution and licence tests must not write to the real stdout

Issue: #182.

## Why

The `v0.11.0-beta.6` tag pipeline's `test:integration` job hit GitLab's 4 MB
log cap:

```
Job's log exceeded limit of 4194304 bytes.
Job execution will continue but no more output will be collected.
```

The failing test's name and assertion never made it into the log. The tail of
the retrievable 4 MB was third-party licence boilerplate. Diagnosis had to
proceed by hypothesis-and-reproduction instead of by reading the error — on a
release-tag pipeline, minutes versus half an hour.

It degrades silently: the job still reports pass/fail correctly, so nothing
looks wrong until the log is needed, which is exactly when something already
is.

## Root cause — established, do not re-derive

`hort_attribution::write_stdout_or_exit` writes to **`std::io::stdout()`
directly** (`crates/hort-attribution/src/lib.rs:95-97` → `write_or_exit` at
`:99-105`, `w.write_all(...)`).

libtest's output capture is `std::io::set_output_capture`, a thread-local
consulted **only** by `std::io::_print` / `_eprint` — the `print!` /
`println!` family — and the panic hook. A `Stdout` handle acquired directly
writes to fd 1 and is never intercepted. So these tests pass, report `ok`, and
still dump their payload into the CI log.

It is **not** `--nocapture` (absent from `.gitlab-ci.yml`, `.github/`, and
`.cargo/config.toml` — the job is a plain `cargo test --workspace --tests`),
not a child process with inherited stdio, and not a panic message.

**The six offenders**, each emitting one full copy of a ~930 KB embedded
document (`THIRD-PARTY-LICENSES.md` = 934,381 B, `.json` = 927,599 B, both
`include_str!`-embedded at `crates/hort-attribution/src/lib.rs:36` and `:41`):

| Test fn | Emitting line |
|---|---|
| `text_format_is_default_and_succeeds` | `crates/hort-cli/src/attribution.rs:52` → `:43` |
| `json_format_differs_from_text_and_succeeds` | `crates/hort-cli/src/attribution.rs:63` → `:43` |
| `text_format_is_default_and_succeeds` | `crates/hort-server/src/cli/attribution.rs:54` → `:45` |
| `json_format_differs_from_text_and_succeeds` | `crates/hort-server/src/cli/attribution.rs:65` → `:45` |
| `text_format_is_default_and_succeeds` | `crates/hort-worker/src/attribution.rs:56` → `:44` |
| `json_format_differs_from_text_and_succeeds` | `crates/hort-worker/src/attribution.rs:67` → `:44` |

**≈ 5.6 MB**, which overruns the 4 MB cap on its own. All three modules are
`pub mod` in lib targets, so `--tests` builds and runs every one.

The tests never inspect the printed bytes — they assert only
`ExitCode::SUCCESS`. The ~1.9 MB written per crate is pure waste.

## What to do

`write_or_exit<W: Write>` already exists and is already generic over the sink
— it is simply **private**. The BrokenPipe-to-`SUCCESS` behaviour it encodes
is the whole point of the helper and must be preserved on the production path.

Give each `run()` a writer-taking form and point the tests at it:

- Expose the generic writer path from `hort-attribution` (make `write_or_exit`
  public under a clear name, or add a `run_to(&mut impl Write, …)` beside each
  `run()`), keeping `run()` itself passing `io::stdout()` so the shipped
  behaviour — including BrokenPipe — is unchanged.
- Point the six tests at an in-memory sink. Then assert something real about
  the bytes (non-empty, contains a known crate, parses as N JSON entries)
  rather than only the exit code — the assertion gets stronger *and* the log
  gets quiet.
- Print on failure only, and then a bounded excerpt.

## Sweep the same defect class while in there

Same direct-fd bypass, smaller payloads, same fix:

- `crates/hort-cli/src/license.rs:46`, `crates/hort-server/src/cli/license.rs:44`,
  `crates/hort-worker/src/license.rs:42` (`full_flag_inlines_both_license_texts_and_succeeds`)
  — `LICENSE-MIT` + `LICENSE-APACHE` ≈ 12.4 KB each; plus the three
  `run_prints_spdx_and_succeeds` variants emitting a short header.
- `crates/hort-cli/src/completions.rs:181`
  (`run_generates_and_writes_completion_script_successfully`) — dumps the full
  generated bash completion script for the entire command tree. **Unlike the
  licence tests this has no fixed ceiling**: it grows with every subcommand
  added.
- `crates/hort-attribution/src/lib.rs:228`
  (`write_stdout_or_exit_writes_to_real_stdout_and_succeeds`) — deliberately
  exercises the real-stdout path and emits one short line. **Keep it.** It is
  the one test that must hit fd 1, and it is bounded.

## Cleared as suspects — do not re-investigate

No `dbg!` anywhere in `crates/`. No `Stdio::inherit` or `.spawn()` in any
`crates/*/tests/` target. No integration test under `crates/*/tests/` touches
attribution or licence at all — the whole surface is the `src/` files above.
`scripts/check-attribution.sh` and `scripts/regenerate-attribution.sh` run
only from their own CI lint jobs, never from `test:integration`.

## Done when

- `cargo test --workspace --tests` emits no unbounded document to stdout; the
  six attribution tests write to an in-memory sink and assert on its content.
- The licence and completions tests do the same.
- `write_stdout_or_exit`'s production behaviour, BrokenPipe handling included,
  is unchanged, and its own real-stdout test still exercises fd 1.
- `cargo fmt --check` and `cargo clippy --workspace --all-targets -- -D warnings`
  clean.
