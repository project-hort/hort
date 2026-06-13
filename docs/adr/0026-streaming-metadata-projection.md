# 0026 — Streaming metadata projection (no whole-body buffering on pull-through)

- **Status:** Accepted
- **Enforced by:** the structural guard test `crates/hort-domain/tests/streaming_metadata_port.rs` (part of the per-push DB-free guard gate): it pins the `FormatHandler` metadata-method signatures to `&mut dyn std::io::Read` and red-tests any reintroduced call to the deleted `metadata_body_bytes` / `manifest_body_bytes` buffering helpers. The port signatures themselves make a buffered swap a compile-visible API change, not a silent drift.
- **Supersedes:** —

## Context

Upstream metadata bodies are not small. An npm packument for a popular package
reaches ~50 MiB (`@types/node`); the original pull-through path buffered the
whole body into a `Vec<u8>` before parsing, then cached the raw bytes as a
single value in the ephemeral (Redis) store. That design had three failure
modes:

1. **Memory scales with body size × concurrency.** Peak fetch-path RSS was
   bounded only by the body cap times the number of in-flight fetches.
2. **Hardcoded "anything bigger is malicious" caps misclassified real
   packages.** A 10 MiB metadata cap and a 4 MiB manifest cap rejected
   legitimate upstream content and surfaced it as a sanitized HTTP 500.
3. **Multi-MB values in Redis are a big-key anti-pattern** — head-of-line
   blocking on single-threaded `GET`/`SET`, RAM cost, eviction churn and
   re-fetch stampedes.

The sibling decision for artifact bytes (ADR 0003 — streaming, enforced CAS)
had already established that whole-body buffering does not survive real-world
content sizes. This decision extends the same principle to the metadata and
manifest pull-through surfaces.

## Decision

**The format-handler metadata path streams; it never materializes the whole
upstream body in memory.**

1. **The `FormatHandler` metadata methods take a streaming reader.** In
   `crates/hort-domain/src/ports/format_handler.rs`, `parse_upstream_checksum`,
   `extract_upstream_versions`, and `extract_dependency_specs` all take their
   body/content parameter as `&mut dyn std::io::Read` — never `&[u8]`. The
   no-buffering guarantee is structural at the port boundary: a consumer
   cannot hand the handler a whole-body slice it never built.
2. **Metadata pull-through is two streaming passes over a local tempfile.**
   The upstream adapter streams the response body to a tempfile
   (`CachedBodyHandle` in `crates/hort-domain/src/ports/upstream_proxy.rs`).
   PASS 1 streams the tempfile through a per-format streaming projector
   (`crates/hort-formats/src/{npm,pypi,cargo}/projection.rs`) — malformed or
   over-cap input rejects fail-closed and commits nothing. PASS 2 (valid input
   only) streams the raw tempfile into the logical-keyed, overwrite
   `MetadataMirrorStore` (`crates/hort-domain/src/ports/metadata_mirror_store.rs`
   — deliberately not the immutable CAS `StoragePort`, because metadata is
   overwritten on refresh). Only the small typed projection is cached in the
   ephemeral store. The orchestrator is `fetch_and_project` in
   `crates/hort-app/src/project.rs`.
3. **OCI manifest pull-through streams to CAS and broadcasts a hash, not
   bytes.** The tag-pull leg wraps fetch + ingest in
   `PullDedup::coalesce_to_hash` (`crates/hort-app/src/pull_dedup.rs`): the
   leader streams the fetch tempfile into CAS and broadcasts the resolved
   `ContentHash`; coalesced followers receive the hash and re-read from CAS.
   Manifest bytes never transit Redis. See the tag-ref branch in
   `crates/hort-http-oci/src/manifests.rs`.
4. **The deleted whole-body buffering helpers must not return.**
   `metadata_body_bytes` and `manifest_body_bytes` (which recovered the
   full-`Vec<u8>` shape behind the streaming port) are gone; reintroducing
   either — or a `body: &[u8]` / `content: &[u8]` parameter on the metadata
   methods — is a regression the guard test turns into a red test before the
   change even builds in CI.
5. **Cap taxonomy — streaming caps and buffered caps are different objects
   and must not be conflated:**
   - **Streaming caps are large plausibility/storage bounds.** They bound disk
     writes, not memory: `HORT_UPSTREAM_METADATA_CACHE_MAX_SIZE` (64 MiB
     default) and `HORT_UPSTREAM_MANIFEST_CACHE_MAX_SIZE` (16 MiB default)
     trip on the cache-writer half of the stream and surface an honest
     `UpstreamBodyTooLarge` classification — never the generic
     "upstream unavailable" envelope.
   - **Buffered caps are small memory-safety bounds.** Any place that must
     hold a bounded object in memory does so under a small explicit cap: the
     per-version-object projector cap
     (`HORT_UPSTREAM_PROJECTOR_VERSION_OBJECT_MAX_SIZE`, 2 MiB default, sized
     against the largest observed real version object ~1.37 MB) is the
     sanctioned buffered exception inside the streaming projectors. Bounded
     buffered reads go through cap-enforcing helpers
     (`project_with_byte_cap` in `crates/hort-formats/src/stream_helpers.rs`);
     an uncapped `read_to_end` on upstream-controlled input is forbidden.
   - **Corollary:** when a buffered surface is converted to streaming, its old
     small memory cap must not be carried over as the new streaming bound —
     the streaming bound is a storage/plausibility decision made fresh, not an
     inherited memory limit.
6. **Fail-closed, validate-before-commit.** A malformed body or a cap trip
   mid-stream returns a validation error; the tempfile is deleted, the mirror
   is never written, the cache is unchanged, and the prior cached state
   stands. No graceful partials.

## Consequences

- Peak ingest memory is bounded by the per-version-object cap, independent of
  body size: a ~50 MiB packument projects into a few hundred KB of typed
  entries.
- Serve renders the cached projection with no re-parse; the raw mirror exists
  only off the hot path (stale-while-error / air-gapped fallback).
- Raw multi-MB bodies leave the ephemeral store entirely; only small
  projection values remain in Redis.
- Format handlers and projectors must be written against `Read` streams;
  convenience whole-body parsing is unavailable by design, which makes some
  parser code (custom `Visitor::visit_map` over `versions{}` / `releases{}`)
  more involved than a one-shot `serde_json::from_slice`.
- Any new metadata consumer must thread through `fetch_and_project` (or the
  streaming `FormatHandler` port methods for format-generic callers such as
  the prefetch task handlers); there is no sanctioned shortcut that yields the
  raw body as a `Vec<u8>`.

## Alternatives considered

- **Buffer-then-parse with a hard byte cap.** Rejected: the cap was a memory
  band-aid whose premise ("anything past the cap is malicious") is empirically
  false for real registries, and memory still scaled with cap × concurrency.
- **Keep the raw body in the ephemeral store and re-parse per serve.**
  Rejected: Redis big-key anti-pattern plus a redundant parse on every serve;
  the projection cache is both smaller and faster.
- **Mirror the raw body into the CAS `StoragePort`.** Rejected: metadata is
  mutable (overwritten on upstream refresh); an immutable CAS would mint a new
  orphan blob on every refresh. A logical-keyed overwrite store is less
  machinery and the correct primitive.
- **Skip-and-continue on malformed entries (graceful partial).** Rejected in
  favour of fail-closed rejection: a silently truncated index is worse than an
  honest error, and validate-before-commit keeps the prior good state
  servable.
- **A type-level trick instead of a guard test for the no-reintroduction
  rule.** Rejected: a `&[u8]` vs `&mut dyn Read` parameter is a coding-time
  choice with no runtime artifact to assert against; a source-scan of the port
  definition and the consumer call sites is the durable, non-flaky proof.

## References

- `crates/hort-domain/tests/streaming_metadata_port.rs` — the enforcing guard
  (port-signature pin + deleted-helper scan), listed in the pre-push
  structural-guard gate in `CLAUDE.md`.
- `crates/hort-domain/src/ports/format_handler.rs` — the streaming metadata
  method signatures.
- `crates/hort-domain/src/ports/metadata_mirror_store.rs` — the
  `MetadataMirrorStore` port; implementations in
  `crates/hort-adapters-storage/src/metadata_mirror.rs`.
- `crates/hort-app/src/project.rs` — `fetch_and_project` (PASS 1 / PASS 2
  orchestration); `crates/hort-app/src/pull_dedup.rs` — `coalesce_to_hash`.
- `crates/hort-formats/src/{npm,pypi,cargo}/projection.rs` — per-format
  streaming projectors; `crates/hort-formats/src/stream_helpers.rs` —
  `project_with_byte_cap`.
- ADR 0003 — streaming, enforced CAS: the sibling decision for artifact bytes;
  this ADR applies the same no-whole-body-buffering principle to the metadata
  and manifest surfaces.
- Full design history: preserved in the frozen pre-1.0 development history
  (git).
