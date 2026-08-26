# npm format — entity reference

Information-oriented catalog of the npm registry entities as hort handles
them: for each, its wire shape, whether hort **stores**, **derives**, or
**discards** it, and why. Kept in lockstep with `crates/hort-http-npm/`,
`crates/hort-formats/src/npm/`, and the npm payload types in
`crates/hort-app/src/use_cases/index_serve.rs`.

> **Scope.** This page describes the as-built model. It is the reference
> an initiative must update **when it changes an entity's class** — e.g.
> moving a derived entity to a stored one — so the entity model stays
> explicit rather than drifting as folklore across handlers. The
> protocol-authority rule applies: where this page, the code, and the npm
> registry convention disagree, the registry convention wins and the
> divergence is a bug in one of the other two.

## Classification at a glance

| Entity | Class | Where |
|---|---|---|
| Tarball | **Stored** (CAS artifact) | `artifacts` row + CAS blob |
| Version entry | **Stored (projected, install-v1 whitelist)** | `NpmVersionPayload` |
| Packument | **Derived** (built per request, never stored) | `NpmIndexBuilder::build` |
| `dist` object | **Derived** from stored fields | builder |
| `dist-tags` | **Derived** — only `latest`; upstream map discarded | builder |
| Scope / name | **Normalised** at the edge | format handler |
| Publish envelope | **Consumed** (subset), not stored | streaming publish parser |
| Upstream packument | **Cached projection**, not served verbatim | `CachedNpmProjection` |

## Entities

### Tarball — stored

The only entity hort stores as content. Ingested through the CAS
(`StoragePort::put(stream) → ContentHash`, SHA-256 of the raw bytes) on
pull-through or publish; served by the tarball routes (literal `-` path
segment). Artifact lifecycle (quarantine, scan, release) applies to this
entity and only this entity — everything else on this page is metadata
about it.

### Version entry — stored, whitelisted to the install-v1 field set

`NpmVersionPayload` (`crates/hort-app/src/use_cases/index_serve.rs`):
`name_as_published`, `tarball_basename`, `integrity: Option<String>`,
`shasum`, plus `manifest` — the npm registry API's **abbreviated
metadata** (`application/vnd.npm.install-v1+json`) field set, named once
by `NPM_INSTALL_V1_MANIFEST_KEYS` (`crates/hort-formats/src/npm.rs`):

    dependencies, optionalDependencies, peerDependencies,
    peerDependenciesMeta, bundledDependencies, bin, directories,
    engines, os, cpu, libc, deprecated, hasInstallScript, funding

The invariant is **whitelist over verbatim pass-through**: each key's
value is copied unaltered from the authoritative source — the upstream
packument for proxy repositories (captured by the streaming projector
into `NpmVersionEntry.manifest`), the stored publish block for hosted
ones (read back from the `artifact_metadata` projection, following the
`metadata_blob` CAS reference when the block spilled past npm's 256 KB
inline threshold) — and a key absent at the source is **absent on the
wire**, never synthesised and never emitted as `null`. Both the packument
`versions{}` entries and the abbreviated per-version route emit the set,
composed by the single `version_entry_json`.

The whitelist is the boundary, not a step toward full packument
equality: `description`, `scripts`, `devDependencies`, `time`,
`maintainers`, `readme` and everything else outside the list stay
dropped. Widening the list is an entity-class change and must update this
page.

Consequence: hort's served metadata answers dependency-tree resolution
for a fresh, non-lockfile install, and carries the `engines`/`os`/`cpu`
filtering, `deprecated` warnings, and install-script detection npm
clients act on.

### Packument — derived, never stored

Built per request by `NpmIndexBuilder::build`
(`crates/hort-formats/src/npm/index.rs`) from the **filtered served set**:
source adapter (`crates/hort-http-npm/src/index_source.rs`) assembles
entries, then the filter pipeline (`NonServableStatusFilter`,
`IndexModeFilter`) drops quarantined/rejected/non-ingested versions. The
packument therefore never advertises a version hort would refuse to serve
— the load-bearing invariant of the whole serve path. An empty served set
yields empty `versions{}` and **no** `dist-tags` block.

### `dist` object — derived from stored fields

Per version: `tarball` (URL composed from the per-request base URL +
`name_as_published` + `tarball_basename` — never stored, so the packument
is host-relative), `shasum` (always emitted, empty when unknown),
`integrity` (emitted only when known — omitted, never `null`, matching
npm convention for absent SRI).

### `dist-tags` — derived; upstream map discarded

The served packument carries exactly one tag: `latest`, **derived** as the
max over non-prerelease served versions per `NpmSemverOrdering`
(`VersionOrdering::is_prerelease`), falling back to the max prerelease
only when the served set contains nothing else. A prerelease never wins
`latest` while a release is served — the npm ecosystem contract.

The upstream `dist-tags` **map** is discarded at ingest with one
exception: `latest` survives into the cached projection
(`NpmProjection.dist_tag_latest`) solely to drive the
`on_dist_tag_move` prefetch trigger — it is never threaded into the
served packument. Consequences: maintainer-set `latest` is not honored
(the served `latest` is an inference over the served set), and
`next`/`beta`/`rc`/`canary` cannot be installed through hort by tag.
Restoring the map — intersected with the served set so a tag can never
point at a non-servable version — is the planned pass-through initiative;
it flips this entity's class from *derived* to *stored-and-intersected*
(with the derivation above remaining as the fallback), and updates this
section when it lands.

### Scope / package name — normalised at the edge

Unscoped names are normalised via the format handler
(`NpmFormatHandler::normalize_name`) before dispatch; scoped requests
compose `scope/name` after the handler's `@` guard, without
normalisation. Route disambiguation is by segment count plus the `@`
prefix of the second segment; tarball routes are anchored by their
literal `-` segment.

### Publish envelope — consumed subset, not stored

`npm publish` PUTs a packument-shaped envelope. The streaming parser
(`crates/hort-http-npm/src/streaming_publish.rs`) recognises exactly
`name`, `versions` (the published version's entry → payload metadata),
and `_attachments` (the tarball, into CAS). Everything else in the
envelope — including any `dist-tags` the client sends — is **not
captured**. There is no `npm dist-tag add` route
(`/-/package/{pkg}/dist-tags/{tag}` is absent from the route table).

### Upstream packument — cached projection, not served

Proxy repositories cache a projection of the upstream packument
(`CachedNpmProjection`, `crates/hort-http-npm/src/packument.rs`) used for
upstream-checksum verification (the mandatory-verification invariant) and
prefetch planning. It is never served verbatim — serving always goes
through the version-entry → filter → builder path above, which is what
keeps "never advertise what we won't serve" structurally true for proxy
and hosted repositories alike.

## Content negotiation

The npm surface performs none: requests are served `application/json`
regardless of `Accept` (hort's packument is already abbreviated-metadata
shaped, so `application/vnd.npm.install-v1+json` receives a semantically
conforming body). The lenient posture mirrors the PyPI Simple API's
Accept handling; the strict 406 posture is OCI-specific.
