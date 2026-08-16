# 115 — E2E gate diagnosability + multiarch zero-window edge race

Issue: #161. One reviewable unit: harness log-capture + code-level
root-cause of the missing constituent edges, with the found mechanism
pinned by unit tests. **E2E-gated change: no MR until the operator's local
E2E run on this branch is green** — the sandbox has no docker; compose E2E
validation is operator-side.

## Evidence (from the issue; read it first)

`quarantine/proxy-multiarch-zero-window` failed 3/3 on the `v0.11.0-beta.1`
release gate (slow GitHub runners) and passes locally: after Step 2's
authenticated child-manifest GET returns 200, the child's `oci_config` /
`oci_layer` `content_references` edges are absent (count=0, single-shot
asserts), so the zero-window carve-out never fires. The
`oci_index_member` edge from the index IS present; both artifact rows
exist. Same signature on develop 2026-08-10 (`72b4bb75`, pre-0.11.0).
Timing-dependent ⇒ a race decides whether the edges get written.

## Deliverable 1 — harness: preserve the deciding evidence on FAIL

In `scripts/native-tests/run.sh`: when a scenario FAILs, dump the
`hort-server` and `hort-worker` compose logs (bounded — last ~2000 lines
each, clearly delimited per scenario) to stdout BEFORE teardown, so a CI
failure carries its own server-side diagnosis. FAIL only (not
skip/quarantined); `--keep` behavior unchanged; pass-path output
unchanged. Shell-only change; `bash -n` + a forced-failure smoke of the
dump path (e.g. temporarily invert one assert locally, verify the dump
renders, revert) — document how you smoked it in the report.

## Deliverable 2 — root-cause the edge race in the pull path

The edge write for a digest-ref child-manifest pull lives in
`crates/hort-http-oci/src/manifests.rs` (~905–955): best-effort
`register_membership_edges_from_pull` after `ingest_verified`, fed by a
tempfile re-read (failure ⇒ WARN + skip BOTH edges and warming,
non-fatal). Analysis so far rules out the index-side blob warming as an
alternate child-manifest ingester (`parse_manifest_blob_digests` yields
nothing for an index).

Enumerate EVERY leg that can cause the child-manifest digest's content to
be in CAS / its artifact row to exist before or concurrently with the
foreground GET (single-flight coalescing followers, worker-side prefetch
jobs planned off the index tag move, the anonymous Step-0 leg, any
serve-from-CAS shortcut that skips the ingest closure), and answer for
each: does it register the membership edges? The race is real — the gate
failed 3/3 on slow runners — so one of these legs wins there and skips
the edge write.

Fix by making the edges **guaranteed** for a successfully served
digest-ref child manifest, whichever leg wins. Preferred shapes, in
order: (a) the winning leg also registers edges (idempotent — the
`content_references` PK/upsert semantics already tolerate re-writes);
(b) edge registration moves before/into the ingest completion so a
follower can't observe row-without-edges. NOT acceptable: papering over
with a scenario-side `bounded_poll` unless the analysis PROVES the edges
are eventually written by an already-running retry path (then poll +
document that path). If the clean fix requires an architectural change
(e.g. moving edge registration into the ingest transaction across the
port boundary), STOP after the analysis + pinning tests and report the
options instead of implementing the layering change.

Pin whatever mechanism you find with unit tests at the layer it lives
(the `hort-http-oci` handler tests have precedent for spawned-task
warming assertions — see `pull_through_by_digest_enabled_prefetch_policy_
warms_config_and_layer_blobs`).

## Constraints

- Spec authority: OCI Distribution Spec + the zero-window contract
  (descendants of a content_references target inherit a zero window;
  the index keeps the full window). E2E passing ≠ protocol-correct.
- Comment provenance rule: no issue/MR references in code or script
  comments — state invariants ("edges must exist for any served child
  manifest regardless of which leg ingested it"), not history.
- No `Cargo.toml`/dependency changes expected. Migrations out of scope.
- Scenario asserts: leave the single-shot edge asserts AS-IS unless
  deliverable 2's analysis concludes eventual-write (see above).

## Acceptance

- `run.sh` FAIL path dumps both services' logs bounded and delimited;
  pass path byte-identical output apart from the new failure-only block.
- The race mechanism is named in the report with the exact code path,
  and a unit test fails on the pre-fix code and passes post-fix.
- `cargo test --workspace` green; fmt/clippy clean; `cargo audit`/`deny`
  clean (no dep changes → attribution untouched).
- Operator-side: local `./scripts/native-tests/run.sh --hort=compose
  --scenario quarantine/proxy-multiarch-zero-window` stays green on the
  branch (the operator runs this; the report states it as pending).
