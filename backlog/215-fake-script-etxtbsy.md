# 215 — Fake-scanner fixtures: no fork may inherit an open write descriptor on the script

**Issue:** #276 · **Branch:** `agent/276-fake-script-etxtbsy`
**Governing decisions:** none (test-harness defect; no ADR governs it).

## Why

`cargo test --workspace --lib` fails intermittently on CI:

```
test tests::a_report_with_no_results_in_fs_mode_is_nothing_analysable_not_clean ... FAILED
panicked at crates/hort-adapters-scanner-trivy/src/lib.rs:1241:18:
  Invariant("trivy adapter: trivy binary not found at /tmp/.tmpaYnMWd/fake-trivy.sh:
             Text file busy (os error 26)")
```

`ETXTBSY` on `exec` means a process still holds an **open write descriptor** on that
file. Each fixture already closes its own handle before spawning (open with
`mode(0o700)` → write → `sync_all` → drop, `lib.rs:1178-1195`). That is not enough:
the test process is multi-threaded and many tests spawn children. Descriptors are
inherited at **fork**; `O_CLOEXEC` only clears them when the child **execs**. So when
thread B forks while thread A still holds its script open for writing, B's child keeps
that descriptor alive, and A's `exec` of its own script fails. Per-test temp
directories do not help — the inherited descriptor refers to that inode.

Reproduced only under CI load (4 vCPU); four local runs, one with a scrubbed
environment and `RUST_TEST_THREADS=4`, were green. The tests arrived with the
rootfs/fs abstention work, which is why this surfaced now.

## Scope

1. **A process-wide guard around write-and-spawn.** Add a crate-local
   `static` `tokio::sync::Mutex<()>` (a plain `std::sync::Mutex` is wrong here — the
   guard must be held across the `.await` on `scan`). Acquire it **before** creating
   the script and hold it until the `scan` call returns, in **both** Trivy helpers:
   - `scan_against_fake_trivy_target` (`crates/hort-adapters-scanner-trivy/src/lib.rs:1170`)
   - the over-cap test's inline script writer (`…/src/lib.rs:1104`)
   The comment states the invariant — no thread of this process may fork while a
   write descriptor on an executable fixture is open — not the incident.
2. **Same treatment for every sibling fixture that writes a script and execs it.**
   At least `crates/hort-adapters-scanner-osv/src/lib.rs:718` (`fake-osv.sh`) and the
   two `tests/timeout.rs` files (`hort-adapters-scanner-trivy`,
   `hort-adapters-scanner-osv`). Grep the workspace for the pattern rather than
   trusting this list: a writer + `mode(0o7..)`/`set_permissions` + a later spawn of
   that path. Each *test binary* is its own process, so a guard is needed per crate,
   not globally.
3. **Prove it.** Run the affected crates' tests repeatedly under raised parallelism
   (`RUST_TEST_THREADS` at or above the host's core count, at least 20 consecutive
   runs of `-p hort-adapters-scanner-trivy -p hort-adapters-scanner-osv --lib`), and
   report the run count and the result. A single green run is not evidence for a race.

## Explicitly not

- **No retry on `ETXTBSY` in the adapter.** Production code does not carry a loop for
  a race in test setup; the adapter's current behaviour (surface the exec error as an
  Invariant) is correct and stays.
- No change to what the tests assert, no new test, no production-code change at all.
  If the fix appears to need one, stop and report instead.

## Acceptance

- No test helper in the workspace holds a write descriptor on an executable file while
  any thread of the same process may fork.
- The repeated high-parallelism runs are green, with the count stated in the report.
- Gate green: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, `cargo-audit audit --deny warnings`, `cargo deny check`.
- Code comments state the invariant, never an issue or directive number.
