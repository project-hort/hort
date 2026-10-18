# 286 — The scrub classifies a real hash mismatch as a mismatch

**Issue:** #341 · **Branch:** `agent/341-audit-block-4`
**Governing decisions:** ADR 0003 (enforced CAS: `StoragePort` verifies on
read) · ADR 0030 (the scrub's `CasIntegrityMismatch` is part of the integrity
record) · the **recorded exit-code posture** in
`crates/hort-server/src/cli/scrub.rs`, which this item deliberately does not
touch — see below.

## What is true today

`CasScrubUseCase::check_one_hash` calls `storage.get(hash)` and then re-hashes
the stream with `stream_sha256`. On both production adapters that stream is
already wrapped in `VerifyingReader`
(`crates/hort-adapters-storage/src/filesystem.rs:367`,
`object_store_backend.rs:407`), which compares the hash itself and, on a
mismatch, returns `io::ErrorKind::InvalidData` **at EOF** — before
`stream_sha256` can return an observed digest.

So for a corrupted blob the scrub takes its `Err` arm and records
`CasScrubResult::ReadError`. Consequences, in order of severity:

1. **The scrub's own comparison is unreachable in production.** The
   `observed != hash` branch — the one that emits `CasIntegrityMismatch`, logs
   `CAS integrity mismatch`, and calls `try_tombstone_artifact` — can only be
   reached through a reader that does *not* verify. In the shipped composition
   that is dead code.
2. **The configured `action: tombstone` never executes.** An operator selected
   a response to corruption; the path to it is not reachable.
3. **`hort-server scrub` exits `0`.** `report_to_exit_code` escalates on
   `mismatches > 0`, and a real mismatch never increments that field — it
   increments `read_errors`, which the CLI documents and pins as
   *observability-only*. A scheduled scrub therefore reports success over a
   present corrupted object.

The test that appears to cover this uses `MockStoragePort::inject_tampered`,
whose `get` hands back raw wrong bytes with **no** verifier, so it exercises
the branch that production cannot reach. The two real-adapter tamper tests
assert the opposite reader shape (`InvalidData` at EOF). All three pass. The
gap is exactly the composition none of them covers.

## Why the fix is "consume the verdict", not "re-hash harder"

Two components hash the same bytes for the same reason, and the one whose
answer is thrown away is the one that runs. The correction is to stop
duplicating the work and read the verifier's verdict instead.

**The hook already exists and already fires at the right moment.**
`VerifyingReader` takes an `on_mismatch: Option<Box<dyn FnOnce() + Send + Sync>>`
(`crates/hort-adapters-storage/src/integrity.rs:30`) that fires exactly once,
at the mismatch, and **takes no arguments** — while the computed hash is right
there and goes into a format string:

    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("CAS integrity failure: expected {}, computed {}", self.expected, computed),
    )

That is this block's own lens pointed at the integrity path: a mechanism that
knows the answer and does not hand it over, so the only way to recover
`observed` today is to parse a message. **Do not parse the message.** Make the
observed hash travel as data — the hook's parameter, or a typed error the
adapter maps — and let the scrub classify from that.

Sniffing `ErrorKind::InvalidData` is the other conceivable route and it is
worse: it cannot produce the observed digest that `CasIntegrityMismatch` and
the tombstone path both need, and it would read any other `InvalidData` from
the backend as corruption.

## What this item does NOT change: the exit-code posture

`scrub.rs` escalates on `mismatches > 0` only, and
`report_with_missing_and_read_errors_but_no_mismatch_is_success` pins that with
the comment *"Missing, read_errors, and shards_truncated alone do NOT escalate
— they are observability-only."* **That decision is correct and stays.** It was
only ever unsafe because corruption was landing in `read_errors`; once
classification is right, the recorded posture does what it says. Do not widen
the exit code, and do not "fix" that test.

## What to do

1. **Give the mismatch its data.** Extend `VerifyingReader`'s mismatch
   signal so the computed hash reaches the caller as a value. Both production
   adapters construct the reader, so whatever shape you choose has exactly two
   construction sites to update.
2. **Make the scrub classify from the verifier**, so a corrupted blob yields
   `CasScrubResult::HashMismatch` with the observed digest, emits
   `CasIntegrityMismatch`, and reaches `try_tombstone_artifact` when the
   configured action says so. A genuine I/O failure must still be
   `ReadError` — the two must remain distinguishable, which is the whole point
   of carrying the verdict as data.
3. **Decide whether the scrub still re-hashes at all** and say why in the
   report. If the verifier's verdict is authoritative, a second hash of the
   same bytes is cost without information; if you keep it, state what it
   catches that the verifier does not.
4. **Fix the test double.** `MockStoragePort::inject_tampered` must honour the
   same read contract as the real adapters (mismatch surfaces at EOF, carrying
   the computed hash). A mock that hands back raw wrong bytes lets a future
   regression pass the suite exactly as it does today — **this is the half of
   the item that keeps it fixed.**

## Explicitly out of scope

- **F13-1, the serving path**: same-length corrupted bytes completing as a
  successful HTTP/1 download because the verifier only errors on a subsequent
  EOF poll. Different site, different mechanism, still open. Note in the report
  that this unit restores **one** of the two controls that standing acceptance
  SUP-6 rests on, so SUP-6 is not whole again — do not claim it is.
- The scrub's scheduling, budget, sharding and `shards_truncated`.
- The `Missing` classification and the refcount/orphan question.
- Any new configuration.

## Acceptance

- A test that composes the **real** adapter with the scrub — both backends —
  tampers a blob, and proves: `HashMismatch`, a `CasIntegrityMismatch` carrying
  the observed digest, and the tombstone path taken when the action says so.
  This is the composition no existing test covers and the reason the item
  exists.
- A test that a genuine read failure is still `ReadError` and not a mismatch.
- A test that `hort-server scrub` now exits non-zero over a tampered blob,
  through `report_to_exit_code` as it stands.
- `MockStoragePort::inject_tampered` behaves like the real readers, and the
  pre-existing mock-based mismatch test still passes **for the right reason**.
- The diff adds no uncovered lines.
- Gate green, one-shot capture, exit codes separate from the output.
  `cargo test --workspace` as **one** invocation with `DATABASE_URL` set;
  background it, then wait in your own turn until its exit code is in hand, and
  touch no source file between launch and completion.
