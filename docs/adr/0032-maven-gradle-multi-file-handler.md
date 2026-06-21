# 0032 — Maven / Gradle multi-file format handler

- **Status:** Accepted — shipped (compiled-in `hort-formats::maven` +
  `hort-http-maven`, like cargo/npm/pypi/oci; WASM remains the post-v1 target).
- **Enforced by:** the `MavenFormatHandler` `FormatHandler` impl
  (`crates/hort-formats/src/maven/`) and the adapter-free `hort-http-maven`
  inbound crate (`crates/hort-server/src/http.rs` nests it under `/maven` for
  `RepositoryFormat::{Maven, Gradle}`); the `maven_overrides_multifile_defaults_tests`
  guard in `crates/hort-formats/src/lib.rs` (pins that Maven OVERRIDES
  `classify_group_member` + `resolve_mutable_version` while pypi/cargo/npm
  inherit the inert defaults); the per-file group-membership push model on
  `ArtifactGroup` (migration `003`, reused unchanged).
- **Supersedes:** —
- **Relates:** [0005](0005-wasm-format-modules-capability-taxonomy.md) (the
  MultiFileArtifact capability group this realises),
  [0006](0006-mandatory-upstream-verification.md),
  [0008](0008-per-format-adapter-free-http-crates.md),
  [0033](0033-sha1-upstream-transfer-verification-floor.md) (the SHA-1 floor the
  Maven pull-through depends on).

## Context

Maven is the first **MultiFileArtifact** format Hort ships. Unlike npm / PyPI /
Cargo — one published unit is one (or a small fixed set of) immutable
file(s) keyed by a single coordinate — a Maven release publishes a *group* of
sibling files under one `groupId:artifactId:version` (GAV) coordinate: the
`.pom`, the main `.jar` (or `.war` / `.aar` / …), `-sources.jar`,
`-javadoc.jar`, the Gradle `.module` GMM descriptor, plus a checksum sidecar
(`.sha1` / `.md5` / `.sha256` / `.sha512`) per file and the generated
`maven-metadata.xml`. SNAPSHOT versions are additionally **mutable** — a base
`X-SNAPSHOT` resolves to a set of timestamped, immutable builds.

ADR 0005's capability taxonomy named **MultiFileArtifact** as a future group and
sketched its members as `{artifact_files, primary_file, resolve_mutable_version}`
(and an even earlier `hort-formats` module-doc sketch said
`{file_group_key, artifact_is_complete, resolve_mutable_version}`). Both sketches
predate the implementation. The realised model is different — and the as-built
realisation is the authority here (the sketches are reconciled in
`docs/architecture/explanation/format-handlers.md` and the
`hort-formats/src/lib.rs` module-doc).

This ADR records the realisation so it survives the deletion of the branch-local
design doc.

## Decision

Maven (and Gradle — see below) is a compiled-in handler in two crates,
exactly like the four shipped formats, with WASM still the post-v1 boundary
(ADR 0005). The MultiFileArtifact capability is realised on the existing flat
`FormatHandler` trait + the existing `ArtifactGroup` aggregate. The concrete
decisions:

1. **MultiFileArtifact = the `classify_group_member` → `GroupMembership` →
   `ArtifactGroup` push model, NOT an `artifact_files` / `primary_file` pull.**
   Each uploaded file is ingested independently (`ingest_direct`) as its own
   immutable CAS artifact, then the ingest path's **post-commit** hook
   (`IngestUseCase::ingest_inner`) calls
   `handler.classify_group_member(coords, path)`. The Maven handler returns
   `Some(GroupMembership { group_coords, role, is_primary })` for real content
   files (`pom` / `jar` / `sources` / `javadoc` / `module`) and **`None`** for
   checksum sidecars and `maven-metadata.xml` (neither is a group member). The
   membership is pushed to `ArtifactGroupUseCase::add_member`, which creates the
   group on first member and attaches thereafter (race-handling +
   primary-role assignment are the aggregate's, reused unchanged). The group
   is therefore a *projection built bottom-up from members*, never a manifest
   the handler enumerates top-down. The members can arrive in **any PUT
   order** (a sidecar before its artifact, a `.pom` before the `.jar`) because
   each file's grouping is independent.

   - **`group_coords` canonicalisation:** carries ONLY the GAV identity
     fields (`name`, `name_as_published`, `version`, `format`) with `path`
     empty and `metadata` Null — the trait's canonicalisation contract. A
     SNAPSHOT's group version is the **base** `X-SNAPSHOT` (not the
     timestamped form), so every timestamped build collapses into one group.
   - **`is_primary` = `true` only for the `jar` role** (any binary packaging
     — `.war` / `.aar` / `.ear` — classifies as the binary `jar` role). A
     `pom` is never path-marked primary: packaging is not knowable from the
     path alone (it lives inside the POM XML, which this pure path-level
     handler does not parse), and PUT order is not guaranteed, so marking a
     pom primary would mis-set `primary_role` for the common jar+pom case.
     A pom-only artifact (parent POM, BOM) simply has no primary member —
     the aggregate tolerates an unset `primary_role` until a `jar` arrives.

2. **Identity = `groupId:artifactId`, case-sensitive.** `Artifact.name` is the
   colon form (`"com.google.guava:guava"`); `version` is the Maven version
   (`"31.1-jre"`, `"1.0-SNAPSHOT"`). `normalize_name` is the **identity
   function** (Maven is case-sensitive — no case or separator folding) and
   `collision_key` stays at the default `None`. `build_artifact_logical_path`
   (filename REQUIRED) and `parse_download_path` are exact inverses: GAV +
   filename ⇄ `{group-path}/{artifact}/{version}/{filename}` (groupId dots →
   slashes, filename verbatim). The HTTP layer routes a single wildcard tail
   (`/maven/:repo_key/*artifact_path`, GET + HEAD + PUT, like OCI's `/v2/*`),
   distinguishing three path shapes by a `maven_path_kind` marker the parser
   tags on `ArtifactCoords.metadata` (`file` / `metadata_a` / `metadata_v`).
   Per-format grammar validation (`validate_maven_coordinate`) runs in the
   handler **before** any persistence, rejecting traversal / control chars /
   over-length, error-prefixed `maven.coordinate:` and never echoing bytes.

3. **Server-GENERATED `maven-metadata.xml` (A-level + V-level), never trusted
   from the client.** GET regenerates the document from the artifact-group
   version set through the shared Source → Filter → Builder index pipeline
   (the same `IndexBuilder` spine npm / PyPI / Cargo use). The new
   `MavenMetadataXmlBuilder` consumes post-filter `VersionEntry`s
   (`NonServableStatusFilter` drops quarantined / rejected / indeterminate
   versions; `IndexModeFilter` applies the repo's index mode) sorted by
   `MavenVersionOrdering`:

   - **A-level** (`g/a/maven-metadata.xml`): `<versioning>` with `<latest>`
     (highest by ordering), `<release>` (highest non-`-SNAPSHOT`, omitted when
     all versions are snapshots), `<versions>`, `<lastUpdated>`.
   - **V-level** (`g/a/X-SNAPSHOT/maven-metadata.xml`): `<snapshot>` (highest
     `(timestamp, buildNumber)` build) + `<snapshotVersions>` (the
     most-recent build per `(classifier, extension)`).

   One builder dispatches on the `PerVersionPayload::Maven` case
   (`MavenVersionPayload::Artifact` → A-level, `::Snapshot` → V-level). The
   builder is **pure**: no I/O, no tracing, and **no system clock** —
   `<lastUpdated>` is derived from the inputs (max of per-entry timestamps,
   falling back to a caller-supplied data-derived value). Two timestamp
   formats are deliberately NOT unified: `<snapshot><timestamp>` =
   `yyyyMMdd.HHmmss` (dotted); `<updated>` / `<lastUpdated>` =
   `yyyyMMddHHmmss` (no separators). No `xmlns` is emitted (matches real
   Central files; parse is namespace-agnostic). A client-PUT
   `maven-metadata.xml` is accepted (`200`) and **discarded** — serving the
   client's copy would advertise quarantined versions, defeating the gate.

4. **On-demand server-generated checksum sidecars.** A GET of
   `<file>.{sha1,sha256,sha512,md5}` returns the digest of the **stored**
   file, never a client-uploaded copy:

   - `.sha256` short-circuits to the CAS `ContentHash` (free — no read, no
     compute, no cache entry).
   - `.sha1` / `.sha512` / `.md5` stream the stored blob from CAS through the
     hasher, memoised in a new **Evictable** ephemeral keyspace
     `mavensum:{content_hash}:{algorithm}` (registered in `KEYSPACE_REGISTRY`,
     pinned by the `ephemeral_keyspace_exhaustive` guard, mirroring the
     `cargo_index_proj:` pattern). The digest of immutable content is itself
     immutable, so the cache is purely recomputable — loss under memory
     pressure costs a re-hash, never correctness — and it bounds a re-hash
     CPU-amplification vector.
   - **No precompute at ingest, nothing persisted on the artifact, no
     `payload_metadata` write, no per-format branch in the shared ingest
     path** — sidecars are purely a serve-path concern (this deliberately
     diverges from an earlier "multi-hash-at-ingest" sketch; conflating
     server-computed digests into the client-supplied ingest input was the
     bug it would have introduced).
   - Client sidecar PUTs are accepted (`200`) and **discarded** — the
     generated value is authoritative, so a sidecar always matches the served
     bytes for any algorithm a client requests (the Nexus / Artifactory
     model).
   - A sidecar GET **inherits the target file's quarantine status** — a
     quarantined file's sidecar 503s, a rejected file's sidecar 403s, only
     `Released` / `None` serves the digest. The gate runs before any CAS read,
     so a held version's digest is never computed and never leaked.

5. **SNAPSHOT mutable-version resolution via `resolve_mutable_version`.** A
   `-SNAPSHOT` deploy uploads unique timestamped files
   (`foo-1.0-20231201.120000-3.jar` + sidecars + `.pom`) stored as group
   members under the **base** version `1.0-SNAPSHOT`. A GET of the unresolved
   base form (`foo-1.0-SNAPSHOT.jar`) loads the base version's stored
   timestamped paths and calls the new
   `FormatHandler::resolve_mutable_version(requested_path, available_paths)`,
   which picks the highest `(timestamp, buildNumber)` build matching the
   requested `(classifier, extension)` — the `(classifier, extension)` is the
   unique resolution key, not the base version (different classifiers can
   carry different timestamps). The resolved concrete path is then served
   through the normal exact-path lookup + quarantine gate (so a resolved-but-
   held build still 503s / 403s). The trait method's default is `Ok(None)`
   (immutable-version formats never resolve); Maven is the only v1 implementer.

6. **Gradle = Maven-handler alias.** `RepositoryFormat::Gradle` was previously
   vestigial dead surface (enum + `Display` only, no handler). Gradle
   publishes to Maven-layout repos with the identical wire protocol, so the
   Maven handler + `/maven` mount accept repos of format `Maven` **or**
   `Gradle`. The only Gradle-specific addition is the Gradle Module Metadata
   `.module` member (role `module`, classified by `GroupMemberRole::Module`).
   Gradle repos report `format="maven"` at the handler (one wire protocol);
   `gradle` is documented as an alias of `maven` in the format reference.

7. **Gradle GMM `.module` is OPAQUE store-and-serve pass-through.** The
   `.module` descriptor is stored and served by exact path as a group member
   with server-generated sidecars, round-tripping publish → download. There is
   **no variant parsing**, no GMM-driven prefetch, no variant-aware
   resolution (deferred — see ADR 0000 open-items). The POM Gradle marker
   comment (`<!-- do_not_remove: published-with-gradle-metadata -->`) is
   client-authored and stored verbatim inside the POM bytes — Hort neither
   synthesises nor strips it.

8. **Pull-through verification depends on the SHA-1 floor (ADR 0033).** The
   serve-path pull-through (`hort-http-maven/src/upstream_pull.rs`, coalesced
   through `PullDedup`) fetches the checksum sidecar preferring strength
   (`.sha512` → `.sha256` → `.sha1`, the universal floor), verifies the
   streamed bytes against whichever digest won via `ingest_verified`, and
   stores under the independently-computed SHA-256 CAS key. All three sidecars
   absent / malformed → `502` (unproxiable per ADR 0006 — no soft-fail). The
   full rationale and threat model for permitting SHA-1 here is
   [ADR 0033](0033-sha1-upstream-transfer-verification-floor.md).

## Consequences

- Maven joins cargo / npm / pypi / oci as a fully-shipped compiled-in format;
  `RepositoryFormat::{Maven, Gradle}` both serve through the same handler. The
  MultiFileArtifact capability ADR 0005 anticipated is now realised — by the
  artifact-group push model, not the original sketch.
- The handler stays a pure path/identity/group strategy: it parses coordinates,
  classifies members, resolves snapshots, and emits the metadata builder's
  per-version payload. All I/O (CAS, group persistence, metadata fetch) lives in
  the use cases and the inbound crate.
- The metadata + sidecar serve paths never trust client uploads, so the
  quarantine gate cannot be bypassed by a crafted `maven-metadata.xml` or a
  lying sidecar.
- **WIT-forward containment (review gate, satisfied).** All Maven-specific logic
  is concentrated behind the `FormatHandler` trait (`hort-formats/src/maven/`)
  and the `hort-http-maven` inbound crate — the two units that become a WASM
  module + its host adapter under the ADR 0005 refactor. The generic-layer
  touches are held to two permitted, format-agnostic kinds:
  - **Format-agnostic primitives** (zero format coupling): `HashAlgorithm::Sha1`
    + `ingest_verified_sha1` (dispatched on the *algorithm*, never the format);
    `FormatHandler::resolve_mutable_version` (a named member of ADR 0005's
    MultiFileArtifact group — anticipated by the WIT design, WIT-mappable as
    `func(requested-path: string, available-paths: list<string>) -> result<option<string>, string>`,
    strings only, no Maven structs cross the boundary).
  - **Nth-of-an-existing-axis** (Maven adds one instance to an axis
    npm/pypi/cargo already established): `MavenVersionOrdering` ↔
    `NpmSemverOrdering` / `Pep440Ordering`; `PerVersionPayload::Maven` ↔
    `Npm` / `Pypi` / `Cargo`; the `mavensum:` Evictable keyspace ↔
    `cargo_index_proj:`; `GroupMemberRole::Module` ↔ the existing roles.

  A new Maven-shaped abstraction, or a `match format { Maven => … }` arm in
  shared dispatch, was an explicit hard-block — none was introduced. In
  particular there is **no** Maven arm in `prefetch_tick` /
  `self_service_prefetch_use_case` `ordering_for_format`, no Maven branch in
  `hort-formats-upstream` dispatch, and no Maven branch in the shared ingest
  core. The future WIT boundary therefore maps cleanly.
- Maven introduces no new operator opt-in that influences a release-gate
  computation (ADR 0016): the SHA-1 floor is a fixed format behaviour, not an
  opt-in, and `upstream_published_at` is best-effort (`Last-Modified`), so
  `trust_upstream_publish_time` adds no new matrix row.

### Scope limitations

- **SNAPSHOT / upstream-metadata proxy discovery is deferred.** SNAPSHOT
  resolution (`hort-formats/src/maven/snapshot.rs` and the Item-8/9 serve path)
  is **filename-based over the already-stored builds** — it picks the latest
  timestamped build *from the set Hort has already cached*. Hort does **not**
  parse the upstream `maven-metadata.xml`: there is no XML parser in the tree,
  which is a deliberate XXE-safety posture (untrusted upstream XML is never fed
  to an entity-expanding parser). The consequence for a **proxy** repo:
  - **Pinned-version RELEASE pull-through is unaffected** — a request maps 1:1
    onto the upstream Maven layout via an exact path, so a not-yet-cached
    release is fetched, verified (ADR 0006 / 0033), and ingested on demand.
  - **Discovering a not-yet-cached upstream SNAPSHOT** (or resolving
    version-range / `LATEST` / `RELEASE` against the upstream) **is limited to
    the cached set**, because that resolution would require parsing the
    upstream `maven-metadata.xml`. Restoring it means lifting the no-XML-parser
    posture (a hardened parser with entity expansion disabled), tracked as an
    open item in the decision index.

## Alternatives considered

- **`artifact_files` / `primary_file` pull model (the ADR 0005 sketch).**
  Rejected: it presumes the handler can enumerate a group's files up front,
  which is false for an order-independent per-file PUT protocol where sidecars
  and siblings arrive separately. The push model (classify each file as it
  lands, let the aggregate assemble the group) matches the wire reality and
  reuses the existing `ArtifactGroup` aggregate / events / Postgres adapter
  (migration 003) without change.
- **Store the client-uploaded `maven-metadata.xml` and sidecars.** Rejected:
  a client copy can advertise quarantined versions and can carry a digest that
  disagrees with the stored bytes. Server generation (filtered metadata,
  on-demand digests over stored bytes) is the only way the quarantine gate and
  serve-bytes ↔ sidecar consistency hold.
- **Precompute all four digests at ingest and persist them.** Rejected: it adds
  a per-format branch to the shared ingest path and writes server-computed data
  into the client-supplied `payload_metadata` input — surface the on-demand,
  serve-path-only model eliminates. Digests of immutable content are a
  recomputable property; an Evictable cache is the right home.
- **A separate `RepositoryFormat::Gradle` handler.** Rejected: Gradle's wire
  protocol IS Maven's. A second handler would duplicate every path / group /
  snapshot rule. Aliasing `Gradle` to the Maven handler retires the vestigial
  variant and adds only the `.module` member role.
- **Parse Gradle Module Metadata variants in v1.** Rejected as out of scope —
  opaque pass-through round-trips correctly today; variant-aware resolution is
  deferred (ADR 0000 open-items) and would add WIT-refactor surface.

## References

- `crates/hort-formats/src/maven/` — `mod.rs` (handler + `classify_group_member`
  + `resolve_mutable_version`), `coords.rs` (path build/parse + validation),
  `snapshot.rs` (timestamped-filename grammar + resolution), `metadata.rs`
  (`MavenMetadataXmlBuilder`).
- `crates/hort-http-maven/` — `lib.rs` (routes + hosted PUT/GET + dispatch),
  `serve.rs` (metadata Source → Filter → Builder), `sidecar.rs` (on-demand
  checksum sidecars), `upstream_pull.rs` (verified pull-through, ADR 0033).
- `crates/hort-domain/src/ports/format_handler.rs` —
  `classify_group_member` / `GroupMembership` / `resolve_mutable_version`.
- `crates/hort-domain/src/entities/artifact_group.rs` — the `ArtifactGroup`
  aggregate (reused unchanged).
- `crates/hort-app/src/use_cases/index_serve.rs` — `PerVersionPayload::Maven`
  / `MavenVersionPayload` / `MavenSnapshotArtifact`.
- `crates/hort-app/src/use_cases/index_serve_filter.rs` —
  `MavenVersionOrdering` (ComparableVersion port).
- `crates/hort-app/src/metrics.rs` — `GroupMemberRole::Module`.
- ADR 0005 (MultiFileArtifact capability group), ADR 0006 (mandatory upstream
  verification), ADR 0033 (SHA-1 transfer-verification floor).
