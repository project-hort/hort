# 395 — The broker comes from a URL

**Issue:** #417 · **Branch:** `agent/417-the-broker-comes-from-a-url` · item 2
of 2, and the last. **No production code changes** — one test file, three
manifests, the lockfile, the attribution, and two advisory configs.

**Governing decisions:** the risk acceptance recorded in `.cargo/audit.toml`
for RUSTSEC-2026-0440 names its own removal trigger — "when a `testcontainers`
release drops the dependency". This item reaches the same end by the other
route, so the entry comes out here.

## The property

**`testcontainers` leaves the workspace**, so `astral-tokio-tar` leaves
`Cargo.lock` and the RUSTSEC-2026-0440 acceptance is deleted rather than
carried.

## Why this is not the compose move I first scoped

The earlier framing was "bring NATS into the compose stack, then delete the
tests". Reading what the dependency actually supplies made that unnecessary.

`testcontainers` provides the NATS suite with **exactly one thing: a URL.**
`start_nats()` boots `nats:2.10` with `-js`, waits for "Server is ready" on
stderr and returns the mapped port; `setup_adapter_with_stream` then builds
`nats://127.0.0.1:{port}` and hands the result to `async_nats::connect`. The
adapter under test takes a client, not a container. So pointing the suite at a
broker URL supplied by the operator removes the dependency and keeps both live
assertions **unchanged** — the same shape the deleted `s3_multipart.rs` used
for its one working mode.

A compose NATS service plus a scenario is a genuine improvement on top of this,
because it is what would make these assertions run in CI for the first time.
It is **not** this item, and it must not be an overlay when it comes: item 1
established that `scripts/native-tests/scenarios/storage/s3-multipart-blob.sh`
is skipped on every CI run because no lane passes its `compose:s3` overlay.

## Two of the four tests never ran, and do not relocate

`crates/hort-notifier-nats/tests/jetstream_publish.rs` holds four tests. Two
carry a permanent `#[ignore]`:

- `connection_lost_during_publish_returns_failed` — *"container-kill timing is
  racy; needs deterministic TCP intercept"*. It is also the **only** test that
  needs control over the broker process (`container.stop()`), which a URL
  cannot give. Its own TODO says the fix is a TCP intercept, not a container.
- `ack_timeout_classified_correctly` — *"no deterministic way to stall an ack
  against a real broker"*.

**Delete both.** They assert nothing today, neither can be expressed against a
broker the suite does not own, and keeping an `#[ignore]`d body that references
a removed helper is dead weight. **Record their intent here so it is not lost:**
hort still wants `NotifyOutcome::Failed` classification covered for a
connection lost mid-publish and for a stalled ack, and the stated route is a
deterministic TCP intercept or an in-process broker stub — not a container.

## What to do

1. `crates/hort-notifier-nats/tests/jetstream_publish.rs`:
   - delete `start_nats()` and the three `use testcontainers::…` imports;
   - delete the two `#[ignore]`d tests named above;
   - change the gate to a **URL**: the suite self-skips unless the operator
     supplies a broker. Keep the existing `HORT_TEST_NATS=1` sentinel as the
     opt-in and read the endpoint from a sibling variable in the established
     namespace (`HORT_TEST_NATS_URL`), defaulting to nothing — an opt-in with
     no URL skips with a note naming the variable, the way
     `skip_without_external_endpoint()` did. Do not invent a second
     mechanism.
   - `setup_adapter_with_stream` takes the URL instead of a port;
   - correct the module header. It currently claims *"CI runs this suite with
     the sentinel enabled"*, which is false — `HORT_TEST_NATS` is set in no CI
     config. Say what is true: the suite is opt-in and needs a reachable
     broker.
2. Remove `testcontainers = { workspace = true }` **and its comment** from
   `[dev-dependencies]` in `crates/hort-notifier-nats/Cargo.toml`.
3. Remove `testcontainers = "0.28"` from `[workspace.dependencies]` in the root
   `Cargo.toml`.
4. Regenerate `Cargo.lock` (`cargo check --workspace`). `testcontainers` and
   `astral-tokio-tar` must both disappear from it.
5. Run `scripts/regenerate-attribution.sh` and commit the updated
   `THIRD-PARTY-LICENSES.{md,json}` **in the same change** — the dependency
   graph moves, so this is mandatory, and the release-scoped
   `security:attribution-sync` gate is the backstop that catches it late.
   (**Measured: a no-op.** The graph move is dev-only and the attribution
   excludes dev-dependencies — see the CHANGELOG correction below. Run it
   anyway, for the byte-identity evidence; there is nothing to commit.)
6. Delete the RUSTSEC-2026-0440 entry from **both** `.cargo/audit.toml` and
   `deny.toml`.
7. Fix the three comments that cite the file item 1 deleted, dropping only the
   `s3_multipart.rs` clause and leaving each comment's surviving second source:
   `deploy/compose/docker-compose.s3.yml:36`,
   `deploy/compose/s3/garage-bootstrap.sh:10`,
   `scripts/native-tests/scenarios/storage/s3-multipart-blob.sh:31`.

## Step 6 is not optional, and step 5 has an ordering trap

Once `astral-tokio-tar` is out of the lockfile, an ignore for an advisory
`cargo deny` can no longer see is reported as **`advisory-not-detected`**,
which is a hard failure. Leaving the entry in trades one red gate for another.

`scripts/check-attribution.sh` **restores** `THIRD-PARTY-LICENSES.{md,json}`
from `HEAD` as part of its comparison, so never run it after regenerating and
before committing — it will revert the regeneration. Order: regenerate,
commit, then verify.

## CHANGELOG

One entry, one or two lines, under `### Changed` or `### Removed`: the
`testcontainers` dev-dependency is gone and the broker-backed notifier tests
now take an endpoint. No issue-reference-free prose: the `(#417)` reference
belongs in it, per the changelog's own convention.

**Correction — the attribution does not move, so the grounds stated here for
the entry were wrong.** The grooming justified the entry as operator-visible
because "the third-party set shipped in `THIRD-PARTY-LICENSES.*` changes". It
does not: `about.toml` sets `ignore-dev-dependencies = true`, so the
attribution covers only the graph compiled into `hort-server` / `hort-worker` /
`hort-cli`, which never contained `testcontainers` or any of the 21 crates it
pulled. A fresh `scripts/regenerate-attribution.sh` is **byte-identical** to
the committed files, and none of the 21 names appear in
`THIRD-PARTY-LICENSES.json` at all. Step 5 below is therefore a no-op that
proves the graph move is dev-only, not a mandatory regeneration — worth running
for exactly that evidence, with nothing to commit from it.

**Decided: no CHANGELOG entry at all.** The question was escalated correctly
and the answer is the stricter reading, on four counts. Nothing here is
observable to someone running or upgrading hort — no binary changes, no
behaviour changes, and, measured, no attribution change. The changelog's own
rule excludes test-harness work by name. `HORT_TEST_NATS_URL` is a variable a
contributor running the suite sets, not an operator. And the symmetry decides
it: the risk acceptance this removes was **added** without a changelog entry
(commit `811ea351`, `.cargo/audit.toml` + `deny.toml` only), so recording its
removal would narrate a round trip no reader ever saw — `[Unreleased]`
accumulates across the pre-release series and is stamped once at promotion, so
the net change for a 0.17.3 reader is nothing.

## Acceptance

- `grep -rn testcontainers --include='Cargo.toml' .` finds nothing.
- `grep -c 'astral-tokio-tar' Cargo.lock` is **0**, and `testcontainers` is
  likewise absent.
- `grep -rn 'RUSTSEC-2026-0440' .cargo/audit.toml deny.toml` finds nothing.
- `cargo audit --deny warnings` and `cargo deny check` are both green **with no
  entry for RUSTSEC-2026-0440** — this is the whole point of the item, so paste
  both outputs.
- `scripts/check-advisory-sync.sh` green.
- `scripts/check-attribution.sh` green, run **after** the regeneration is
  committed.
- `cargo test --workspace` green, run **once**. The NATS suite must **self-skip
  cleanly** with no URL set, which is the only path CI will ever take; say in
  the report how many tests the file now reports and that it skipped rather
  than failed.
- The two surviving assertions still exist and still read the same way. State
  what a reader has to set to run them.

## What you cannot verify, and must not claim

There is **no container runtime** in the sandbox — no `docker`, no `podman`, no
`/var/run/docker.sock`. So you cannot stand up a broker and cannot see the two
surviving tests pass. Verify the self-skip path and the compile, and say
plainly in the report that the broker-backed path is unverified here. Do not
report it as green. This change is handed to the human on the branch for that
reason; do not expect an MR.
