# 106 — Maven leaf prefetch: warm exact GAV versions through the verified pull

**Issue:** #153 · **Branch:** `agent/153-maven-prefetch-leaf` · **Scope:**
`crates/hort-app/src/task_handlers/prefetch_ingest.rs`, `crates/hort-formats`
(maven handler normalize/validate path if needed), tests. No HTTP-crate change
expected; if one becomes necessary, stop and report.

## Why

`PrefetchIngestHandler`'s per-format dispatch implements leaf pulls for
Pypi/Cargo/Npm and short-circuits every other format as "no compose-style
download URL". For Maven that rationale is inverted — the layout
`{group-path}/{artifact}/{version}/{filename}` composed verbatim onto
`mapping.upstream_url` is the most composable URL in the system, and
`hort-http-maven/src/upstream_pull.rs` already documents and performs exactly
that two-leg verified pull. The arm predates the Maven adapter.

Consequence (dogfood, 2026-08-13): a Maven build's first touch of fresh BOM
versions fails against the quarantining proxy with no warm-ahead option — the
red build is currently Maven's only warm mechanism. The fail-closed serve
itself is correct and out of scope.

## Change

1. **New `RepositoryFormat::Maven` arm** in the leaf dispatch. `package`
   carries GAV group+artifact as `group:artifact`; compose
   `{group-path}/{artifact}/{version}/{artifact}-{version}.pom` and fetch
   **POM always**; fetch `{artifact}-{version}.jar` **when present** (a 404 on
   the jar after a successful POM ingest is a completed outcome, not a
   failure — BOM/parent packagings have no jar). Record both fetches in the
   `LeafSummary` counters.
2. **Reuse the verified-pull discipline**: checksum sidecar preference
   `sha512 → sha256 → sha1` with fall-through on malformed bodies, then
   `ingest_verified` with the winning algorithm — mirror
   `upstream_pull.rs`'s documented contract. Prefer extracting/delegating to
   shared logic over re-implementing IF the dependency direction allows
   (hort-app must not grow an hort-http-maven dependency; if sharing means
   moving the two-leg fetch helper into an app-layer-reachable home, propose
   it in the report rather than forcing it).
3. **Input validation**: the maven format handler's `normalize_name` must
   accept `group:artifact` coordinates on the self-service POST path; reject
   coordinates that compose into path traversal (`..`, absolute, empty
   segments) — fail the item as rejected, not enqueue-then-500.
4. **Version-less items** (`version: null` → "latest") are OUT of scope:
   return a per-item failure naming the constraint (release warms always pin
   versions). `transitive_deps` for Maven is a separate future issue.
5. The `other =>` short-circuit arm remains for formats with genuinely no
   composable URL (OCI); its log line stays.

## Tests

- Job-level end-to-end against a stub upstream: POM+jar GAV ingests both
  files verified-quarantined; BOM-style GAV (no jar) completes with POM only.
- Sidecar preference and fall-through per the upstream_pull contract (reuse
  its test shapes).
- Traversal-shaped coordinates rejected at validation.
- The truthful-envelope property: re-POST of a warmed GAV reports
  `skipped_already_held` (held-check works for maven's real repo rows).
- Existing Pypi/Cargo/Npm arms: regression-pinned untouched.

## Verification

`cargo test --workspace` green; coverage ≥85% (hort-app changes at the 100%
tier — mock the ports); no new dependency expected.

## Out of scope

Serve-path behavior, transitive Maven prefetch, `maven-metadata.xml` version
resolution, and the internal instance's policy windows.
