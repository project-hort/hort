# 117 — Backfill membership edges on legacy OCI manifest rows

Issue: #162. One reviewable unit: finder port method + backfill task
handler + delivery + tests. Not release-gating.

## Why

The coalesced-follower fix guarantees `content_references` membership
edges for newly minted per-repo manifest rows. Rows minted before it are
permanently incomplete: an OCI **image** manifest row with no
`oci_config` / `oci_layer` edges gives its config and layer blobs no GC
keepalive, so a blob referenced only by that row is collectable and a
later GC pass breaks pulls from that repository.

The second symptom of those rows — a full quarantine window instead of
the descendant carve-out — is explicitly OUT of scope: it self-heals once
`quarantineDuration` elapses. Only the edges are durable damage.

## Design: mirror `wheel_metadata_backfill` one-for-one

`crates/hort-app/src/task_handlers/wheel_metadata_backfill.rs` solved this
exact problem class already (a `content_references` projection retrofit
for artifacts ingested before a hook existed). Follow its shape; do not
invent a new one.

1. **Finder** — new `ArtifactRepository` method mirroring
   `find_pypi_wheels_without_kind(kind, limit)`: return OCI artifacts
   whose coords are a manifest path and which have no
   `content_references` row of kind `oci_config` sourced from them.
   - **Image manifests only.** An index legitimately has no config/layer
     edges (it carries `oci_index_member`), so index rows must never be
     returned. Discriminate on the stored media type — verify how it is
     persisted (payload metadata vs `content_type`) before choosing the
     predicate, and say which you used and why in the report.
   - Add the same trait shape-pin test `find_pypi_wheels_without_kind`
     has (`…_has_documented_shape`) so a rename cannot silently break the
     handler.
   - The adapter query is DB-gated: it needs `#[serial(hort_pg_db)]` per
     the parallel-safety contract.
2. **Task handler** `oci-membership-edge-backfill` in `hort-app`,
   modelled on the wheel handler: per hit, stream the manifest from CAS,
   re-derive its descriptor set, insert the missing edges. Idempotent by
   the projection's upsert-on-PK contract — a second run over a repaired
   row writes nothing.
3. **Layering** — stay inside `hort-app` over ports, exactly as the wheel
   handler does (it calls a `FormatHandler` port method). The OCI
   projection must be reachable through a port; `hort-http-oci`'s
   `register_membership_edges_from_pull` is NOT callable from here and
   must not be made so. If no suitable port method exists, add one
   mirroring `extract_wheel_metadata_bytes`' shape, and honour the
   ADR 0026 streaming contract (`&mut dyn Read`, no buffering helper).
4. **Delivery** — manual operator invocation through the admin-tasks
   route, kind gated by `ADMIN_INVOKABLE_TASK_KINDS`. No CronJob: unlike
   the wheel retrofit this is a one-shot repair for a defect that can no
   longer occur, so a recurring schedule would be permanent scaffolding.
   State that reasoning in the handler's module doc.
5. **Reporting** — `result_summary` carries rows scanned, rows repaired,
   edges written, and rows skipped **with reason** (CAS content missing,
   manifest unparseable). An operator must be able to distinguish
   "nothing to repair" from "could not repair".

## Constraints

- Comment provenance rule: invariants, never tracker references.
- No migration. No change to the ingest or pull-through paths.
- `hort-app` is a 100 %-coverage crate: every branch, including both
  skip reasons and the empty-result case.

## Acceptance

- The finder returns exactly image-manifest rows lacking `oci_config`
  edges — never index rows, never already-complete rows.
- A seeded incomplete row is repaired by one invocation; a second
  invocation reports zero repairs.
- `cargo test --workspace` green; fmt/clippy/audit/deny clean.
