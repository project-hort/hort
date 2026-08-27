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
| `dist-tags` | **Stored and intersected** — full map, ∩ served set | proxy: cached projection · hosted: `mutable_refs` |
| Scope / name | **Normalised** at the edge | format handler |
| Publish envelope | **Consumed** (subset; `dist-tags` → refs), not stored | streaming publish parser |
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

### `dist-tags` — stored and intersected

The whole tag map is passed through, **intersected with the served set**.
hort is not the map's author; it is the map's gate.

**Where the stored map lives, per repository type.** Proxy: upstream's
map, captured by the streaming projector into
`NpmProjection.dist_tags` and cached with the rest of the projection —
CRUD, no events, since hort did not author it. Hosted: the maintainer's
own map, held as `mutable_refs` rows (namespace = the package name as
stored, `ref_name` = the tag, target = `RefTarget::Version`) and
therefore event-sourced through `RefMoved` / `RefRetired` like every
other ref. Virtual: the members' maps merged in priority order — the
first surviving member to define a tag name owns it, and a `Proxy`
member contributes neither versions nor tags once a non-proxy member
owns the name (ADR 0031 rule 2b, tag dimension: a public `next` can
never shadow an internal package's tags).

**The four-point serving contract**, identical for every repository
type:

1. Served map = stored map ∩ post-filter served set. A tag whose target
   version is not served is **dropped, never rewritten** — rewriting it
   to a nearby served version would hand a client a different artifact
   than the tag names.
2. `latest` verbatim when it survives the intersection. Only a dropped
   or absent `latest` is **derived**: the max over non-prerelease served
   versions per `NpmSemverOrdering` (`VersionOrdering::is_prerelease`),
   falling back to the max prerelease when the served set contains
   nothing else — a prerelease never wins `latest` while a release is
   served. The derivation is a fallback, never an override. No other tag
   has a fallback: present or absent.
3. Empty served set → no `dist-tags` block at all.
4. The per-version route (`GET /npm/{repo}/{pkg}/{version_or_tag}`)
   resolves any tag in the served map, so `pkg@next` installs. An
   unknown tag returns the standard anti-enumeration 404 — indistinguishable
   from an unknown version or an unknown package.

Under a null gate (nothing filtered) the intersection degrades to
identity: hort's `dist-tags` is upstream's, byte for byte.

The intersection lives in `intersect_dist_tags`
(`crates/hort-formats/src/npm/index.rs`), computed once per request in
`crates/hort-http-npm/src/serve.rs` so the packument builder and the
per-version route resolve tags through the same map;
`resolve_served_latest` remains the single derivation site.

`NpmProjection.dist_tags` also drives the `on_dist_tag_move` prefetch
trigger, which reads its `latest` entry.

### Scope / package name — normalised at the edge

Unscoped names are normalised via the format handler
(`NpmFormatHandler::normalize_name`) before dispatch; scoped requests
compose `scope/name` after the handler's `@` guard, without
normalisation. Route disambiguation is by segment count plus the `@`
prefix of the second segment; tarball routes are anchored by their
literal `-` segment.

### Publish envelope — consumed subset, not stored

`npm publish` PUTs a packument-shaped envelope. The streaming parser
(`crates/hort-http-npm/src/streaming_publish.rs`) reconstructs it minus
the base64 `_attachments[*].data`, and the publish handler consumes
exactly `name`, `versions` (the published version's entry → payload
metadata), `_attachments` (the tarball, into CAS), and `dist-tags`
(→ `mutable_refs`, one `RefMoved` per changed tag, written after a
successful ingest so a tag can never point at a version that failed to
land). Everything else in the envelope is discarded. A malformed tag
entry is skipped with a warn rather than failing a publish whose
artifact has already landed.

Maintainer tags are also writable directly:
`PUT` / `DELETE /npm/{repo_key}/-/package/{pkg}/dist-tags/{tag}` — the
npm CLI's `dist-tag add` / `dist-tag rm`, thin wrappers over
`RefUseCase::set` / `retire`. `{pkg}` arrives URL-encoded for scoped
names (`@scope%2fname`). Authorization is the publish requirement
(`Write` on the repo), and both routes are **hosted-only**: a proxy's
tags belong to its upstream and a virtual's to its members, so neither
has an authorable tag store and the write is rejected with the same
validation error a publish to a virtual gets.

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
