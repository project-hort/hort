# 463b — the mount's source lookup honours the expand window

**Issue:** #459 · **Branch:** `agent/459-oci-namespace-identity` ·
Correction to unit 463.
**Found 2026-11-23** by the first DB-backed run of
`cargo test --workspace --tests` since 2026-11-22. Six tests in
`crates/hort-server/tests/oci_cross_mount_scan_enqueue_real_db.rs` fail, all
on the same assertion: the mount answers `202` where they expect `201`.

## What the failure actually says

Two separate things, and only one of them is a defect.

### The fixtures encode the pre-463 contract — test-only

The fixture builds
`…/blobs/uploads/?mount=sha256:<hex>&from=oci-mount-source` — a bare
repository key with no `/`. Unit 463 decided `from=` is an OCI **namespace**,
`<repository>/<name>`, so `split_oci_namespace` returns `None` and the handler
falls through to initiate (`uploads.rs:311`). The `202` is correct; the
fixture is asking the pre-463 question. The module doc says so too, in as many
words: *"`from=<repo>`"* and *"The source repository's key, and the `from=`
query parameter"*.

This is not merely a stale assertion. Those six tests are the only coverage of
the mount's **gate** behaviour — the scan row landing in the ingest
transaction, the gate catch-up on a repeat, exactly one gate under two
concurrent repeats, and no artifact left without its scan row. Taking the
fallback path, they prove none of it. **So do not re-point the assertions at
`202`** — that would read as a passing suite over four lost invariants. Send a
namespace and keep every assertion as it stands.

### The source lookup has no legacy fallback — this is the defect

`handle_cross_mount` resolves exactly one path:

```rust
let source_path = oci_blob_coords(src_name, &hash).path;   // uploads.rs:360
ctx.artifact_use_case.find_in_repo_by_path(src_repo.id, &source_path)
```

A blob row written before unit 460 carries the legacy name-free path
`blobs/sha256:<hex>`, so it **misses**, and the mount degrades to a `202`
re-upload for every pre-460 blob in the source repository until unit 464
migrates the rows.

Every other unit in this series carries the opposite posture, each with a
named test: a read tries the scoped path, then the legacy one; a legacy
name-free row's namespace is **unknown**, so it stays usable under any name;
and a fallen-back read does not rewrite the row. 460, 461, 462, 465 and 466 all
do this. **463 does not, and that was an omission in its item rather than a
decision** — the item does not contain the words "legacy", "expand" or
"name-free", and `uploads.rs` holds no such test.

The severity is low and worth stating so it is not over-read: the client gets
the spec's sanctioned `202` and re-uploads, CAS dedups the bytes, and the
re-upload path runs its own scan gate. Nothing is unsafe. What is wrong is that
one surface behaves differently from the other five during the expand window,
which is exactly what the posture exists to prevent.

## The fix

One site. Try `oci_blob_coords(src_name, &hash).path`, then
`legacy_oci_artifact_path(OciArtifactRole::Blob, &hash)` on a miss, with the
terminal-status check applied to whichever row answers — the status half must
not be skipped for a legacy row.

**The comment above the lookup has to grow the caveat.** It currently claims
the lookup *"is the ONLY thing that scopes the mount to `src_name`"*. After the
change that is true of the scoped arm and false of the legacy arm, where no
name is knowable. A reader who trusts the unqualified sentence will conclude a
legacy row is name-scoped when it is not.

## Acceptance

- A mount whose source blob sits at the **scoped** path still answers `201`
  and still lands its scan row — unchanged behaviour, and the six real-DB
  tests prove it once their `from=` is a namespace.
- A mount whose source blob sits at the **legacy name-free** path answers
  `201`, in a test named for that as the expand-window posture rather than as a
  gap.
- A mount naming a source blob that exists only under **another name** in the
  source repository still answers `202`. This is unit 463's whole point and
  the legacy fallback must not widen it: the fallback admits a row with **no**
  name, never a row with a **different** name.
- A terminally-quarantined source row answers `202` on both arms.
- `from=` without a `/`, and `from=` whose name half fails
  `validate_oci_name`, still fall through to initiate.
- The six tests in `oci_cross_mount_scan_enqueue_real_db.rs` pass **with their
  assertions unchanged**, and the module doc no longer says `from=<repo>`.
- The change adds no uncovered lines.

## Why nothing caught this

Worth recording where the hole is, because it is not the worker's. The target
is DB-gated: with `DATABASE_URL` unset it self-skips and reports `ok`, not
`ignored`. My own architect gate runs with the variable unset on purpose, and
CI's `test:integration` runs only on `main`, `release/*` and tags — so a
DB-gated `tests/` target that encodes a contract a behaviour change invalidates
is invisible to **both** gates until promotion. A behaviour change to a path
with real-DB coverage needs that target named and run.

## Governing decisions

ADR 0030 (expand/contract: reads try both shapes during the window), ADR 0043,
and `docs/architecture/reference/oci-namespace-and-identity.md` (the reach: the
whole OCI surface). The OCI Distribution Spec's mount paragraph supplies the
`202`: *"if a registry does not support cross-repository mounting or is unable
to mount the requested blob, it **SHOULD** return a `202`"* — a SHOULD, which
is why the fallback is a legitimate degradation and not a refusal.

## Integration note 2026-11-23 — one fixture requirement the directive missed

The implementing unit reported it, and it is worth keeping because the next
person to touch this target will hit it. The six real-DB tests compose a
context where the **ingest** goes to Postgres while the handler's
repository and source-artifact lookups stay on the mock (`with_ingest_use_case`
rebuilds only the ingest use case). So pointing `from=` at a namespace was not
enough: the source row had to be mirrored into the mock artifact repository
under the same id as the real row, or the handler's lookup missed and the mount
still answered `202`.

That split is deliberate and the module doc states it — the target exists to
prove the `jobs.trigger_source` CHECK constraint and the gate's transactional
behaviour against a real database, not to prove path resolution. Path
resolution is proven by the `--lib` tests in `uploads.rs`. A directive naming
this target should say which half is real.
