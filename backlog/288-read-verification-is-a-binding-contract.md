# 288 — Read verification is a binding contract, not a convention at two sites

**Issue:** #341 · **Branch:** `agent/341-audit-block-4`
**Governing decisions:** **ADR 0003** (enforced CAS — amended by this item,
on the answered decision recorded on #341) · ADR 0007's guard family as the
enforcement precedent.

Item 286 made a CAS read-verification failure carry a typed verdict. This item
makes that binding, which is the only thing that gives it value.

## What is true today

Two facts, both measured:

1. **The verifying wrap is hand-written at exactly two sites** —
   `crates/hort-adapters-storage/src/filesystem.rs:367` and
   `object_store_backend.rs:407`, each constructing `VerifyingReader` inside
   its own `StoragePort::get`. There are exactly two production
   `StoragePort` implementations (`filesystem.rs:203`,
   `object_store_backend.rs:175`); everything else implementing the port is a
   test double.
2. **Nothing enforces it.** A third adapter — and storage being a port with
   swappable backends is ADR 0003's own premise — can return an unverified
   stream from `get` and it compiles, passes clippy, and passes the whole
   suite. ADR 0003 says reads are verified; it does not say a failure is
   distinguishable or carries the computed digest, so such an adapter violates
   no recorded decision while silently returning the CAS scrub to the
   `ReadError` misclassification item 286 just fixed.

The scrub's own second SHA-256 pass is what currently stands between those two
facts and a clean sweep over corrupt storage. That is a mitigation of the gap,
not a close of it: it protects one consumer, by accident of that consumer
hashing twice, and it says nothing to the next one.

## What to do

### 1. Amend ADR 0003 — one paragraph

The decision gains the half it never stated: a read-verification failure is
**distinguishable from an I/O failure** and **carries the digest the delivered
bytes actually hashed to**. `CasIntegrityFailure` is the shape; name it, name
its single construction point, and say what a consumer may rely on.

Keep it to the amendment. Do not restate the decision, do not restructure the
ADR, and do not fold in the scrub's classification (that is item 286's record,
already in `docs/architecture/explanation/cas-storage.md`).

### 2. The guard — `crates/hort-app/tests/` family, no allow-list

A DB-free source scan in the family of `capped_stream_reads`,
`status_decode_fails_closed` and `db_tests_are_serialized`. It asserts: **for
every `impl StoragePort for` in `crates/hort-adapters-*/src/**`, the `get`
implementation constructs `VerifyingReader`.**

Four things that make it the right shape rather than a lint:

- **The scope is derived, not exempted.** Scanning the adapter crates is a
  structural statement — a production storage adapter lives in an
  `hort-adapters-*` crate, and the dep-graph rules already make that true —
  **not** a table of files to skip. No allow-list, by design, like its
  siblings. Test doubles are out of scope because they are not in adapter
  crates, which is a property of where they live and not an entry you can add.
- **Function-scoped, not file-scoped.** A file that happens to mention
  `VerifyingReader` in a comment must not satisfy it.
  `capped_stream_reads.rs:221` has `enclosing_fn_name(text, offset)` for
  exactly this; reuse the technique. If this becomes the third copy of that
  helper, extract it (CLAUDE.md's 3-occurrence rule) — say in the report which
  you did and why.
- **One assertion covers both halves of the contract**, and say so in the
  guard's own module doc: `VerifyingReader` is the single production
  construction point of `CasIntegrityFailure`, so "the wrap is present"
  implies "a mismatch is reported distinguishably and carries the digest".
  If that stops being true — a second producer of the verdict — the guard's
  reasoning breaks before the guard does, which is worth a sentence.
- **Counter-assertion, so a rename cannot make it vacuously green.** The scan
  must find exactly the two known adapter `get` implementations today and fail
  if it finds none. Every sibling guard carries one; `capped_stream_reads`'s
  "the scan still finds both audited reads" is the model.

### 3. Leave the scrub's second hash alone

It stays. With the guard in place it is belt-and-braces rather than the
load-bearing defence, and that is the point — but removing it is a separate
decision with a measurement behind it (what a full sweep costs), and this item
supplies no such measurement. Note in the report that it is now optional, so
whoever measures later knows it is removable without reopening anything.

## Explicitly out of scope

- Removing the scrub's independent hash (above).
- The serving path (same-length corrupted bytes completing as a successful
  download) — still open, different mechanism, named on #341.
- Any change to `VerifyingReader`'s behaviour, the error text, or the
  `on_mismatch` hook.
- A new ADR. This is an amendment to a standing decision, confirmed as such.

## Acceptance

- The guard fails on a deliberately broken tree: drop the `VerifyingReader`
  wrap from one adapter's `get` and show it red, with the adapter named in the
  failure message. **Demonstrate this, do not assert it** — a guard nobody has
  seen fail is a guard nobody has tested.
- The guard fails if the scan matches nothing (the counter-assertion), shown
  the same way.
- The guard is DB-free and sub-second, and runs under `cargo test --workspace`
  with no gate-list entry (it is a `tests/` target, like its siblings).
- The ADR amendment is one paragraph and changes no other text in the file.
- The diff adds no uncovered lines.
- Gate green, one-shot capture, exit codes separate from the output.
  `cargo test --workspace` as one invocation with `DATABASE_URL` set:
  background it, wait in your own turn until the exit code is in hand, and
  touch no source file between launch and completion.
