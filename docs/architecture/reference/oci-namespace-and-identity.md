# OCI namespace and identity

Information-oriented reference for **what identifies an OCI artifact in hort,
and which namespace that identity lives in**. Kept in lockstep with
`crates/hort-http-oci/src/coords.rs`, `crates/hort-http-oci/src/manifests.rs`,
`crates/hort-http-oci/src/manifests_write.rs` and
`crates/hort-domain/src/entities/mutable_ref.rs`.

> **Scope.** This page records a decision and its conformance state. The
> protocol-authority rule applies ([ADR
> 0011](../../adr/0011-authority-hierarchy-and-api-versioning.md)): where this page, the
> code and the OCI Distribution Specification disagree, the specification wins
> and the divergence is a bug in one of the other two. The §Conformance
> section says which parts of the model the code holds today.

## Why the word "repository" is the whole problem

The specification uses **"repository"** and **`<name>`** synonymously. Its
manifest rule reads *"If the manifest is not found in the repository, the
response code MUST be `404 Not Found`"*, and blob pulls use the same namespace.
A manifest's `subject` is a digest reference that may name content the
repository does not yet hold — *"A registry MUST initially accept an otherwise
valid manifest with a `subject` field that references a manifest that does not
exist in the repository"* — and the referrers list is scoped by the **referring**
manifests' `<name>`: *"Each descriptor is of an image manifest or index in the
same `<name>` namespace with a `subject` field that specifies the value of
`<digest>`."* So the list's namespace rule is the spec's own, and the subject's
namespace is not part of it. For a client, the repository is the full string it
writes into the path.

hort splits that string in two. The URL is

```
/v2/private-repo/library/nginx/referrers/sha256:…
    └ repo_key ┘ └──── name ────┘
```

where `repo_key` selects hort's configured `Repository` aggregate — the thing
that carries the upstream mapping, the policies and the visibility rules — and
`name` is the rest. So a client's one repository is two things here, and the
pair `repo_key/name` is what the specification means by "repository".

## The decision

**The OCI wire `<name>` — in hort, `repo_key` plus `name` — is the namespace
for artifact identity.** A hort `Repository` is a *container of namespaces*,
not a namespace itself.

The namespace scopes the **whole** OCI surface: manifest identity, blob
identity, the resolution of a tag's target, the referrers list, and the `from`
parameter of a cross-repository blob mount. It is drawn at one place rather
than at some, because the specification draws it the same way for manifests,
for blobs and for `subject` references, and because *cross-repository blob
mount exists as an explicit mechanism precisely so that blobs do not travel
between namespaces on their own*. A boundary enforced for manifests and not for
blobs leaves the same class of defect one level down.

This is not a new rule in hort. It is the rule the rest of the system already
follows, applied to the one format that does not:

- The namespace concept is **domain-level, not OCI-level**.
  `MutableRef` (`crates/hort-domain/src/entities/mutable_ref.rs`) is keyed
  `(repository_id, namespace, ref_name)` and states that a repository has many
  namespaces and a ref lives in exactly one. Its own convention table binds
  `namespace` to the image name for OCI, the package name for npm and
  `<group>:<artifact>` for Maven.
- Four of the five compiled-in format handlers already put the name **in the
  identity path**: cargo `crates/{name}/{version}/{name}-{version}.crate`, npm
  `{name}/-/{filename}`, PyPI `{name}/{filename}`, Maven the GAV path. OCI is
  the only one whose identity path omits it.

## Identity per surface

The resolution key for an artifact row is `(repository_id, path)`
(`ArtifactRepository::find_by_path`). The table is about what goes into `path`
and into the namespace column beside it.

| Surface | Before this model | Under this model |
|---|---|---|
| Manifest | `manifests/sha256:<hex>`, the name absent from the key | `manifests/<name>/sha256:<hex>` — identity is scoped to the name |
| Blob | `blobs/sha256:<hex>`, the name only on the row | `blobs/<name>/sha256:<hex>` — identity is scoped to the name |
| Tag | `mutable_refs (repository_id, namespace, ref_name)`, `namespace` = the name — **already scoped at the key** | unchanged at the key; its content-hash **target** must resolve inside that name |
| Referrers | the list is assembled from `oci_subject` edges, which carry no namespace of their own | the list belongs to the name that was asked |
| Mount `from=` | read as a hort repository key | an OCI namespace |

Two consequences of the name-free shape are what the model corrects, and they
are worth stating because they are the reason it exists: a digest-addressed
manifest `GET` — and the digest-addressed `DELETE` — resolved across every name
in one hort repository, and multi-naming of one artifact was unrepresentable,
because an artifact row carried exactly one name (the one from the first push).
Under this model the same bytes under two names are two artifact rows, and the
role segment comes first so a row's role stays readable without parsing the
name: `blobs` and `manifests` are both legal OCI image names.

## CAS is untouched — the bytes are not duplicated

Namespace scoping is an **identity** decision, not a storage one. Content stays
addressed by hash ([ADR 0003](../../adr/0003-streaming-enforced-cas.md)), so two
names over the same bytes are **two rows and one blob**. Membership in a
namespace is a row; it is not a copy. This is exactly what content-addressed
storage is for, and it is why the decision costs no storage.

## The name is recorded at write time or it is lost

The name is derivable from **no** payload. That distinguishes it from the other
values the referrers projection carries: a referring manifest's config
`mediaType` and its annotations are derivable from the manifest bytes, so CAS
stays their source of truth and storing them is a **cache** — a missing key
there means *not cached*, and the reader reads through. A missing `name` means
*unknown*; it never means *none*. Reading the two absences the same way would
invert the specification's `artifactType` fallback, which turns on
empty-or-missing versus present.

## Legacy data is readable now and rewritten at the contract step

Rows written before this model are name-independent. A reader of such a row
learns that its namespace is **unknown**, not that it has none, and **no read
upgrades it** — not a same-digest re-push, not a fallback that resolved it. The
remedy for a namespace that matters before the contract step is to push into
it.

**The contract step rewrites those paths** (maintainer decision, 2026-11-23).
The rewrite is a pure function of `(name, old path)`, so it is a single
`UPDATE` with no lookups. One consequence is not lossless and belongs in the
release notes rather than in a fix: an artifact that two names pushed exists as
**one** row under the name of the first push, because the name-free key
admitted only one. After the rewrite it is reachable under that name alone, so
a client that had been pulling a digest under a name it never pushed starts
getting `404`. That cross-name reachability is the defect this model closes,
not a feature being withdrawn.

## Conformance

The decision is recorded here ahead of the code; this section is the honest
difference, and it is the part to update as units land (tracked by issue #459).

**Held today:** new manifest and blob rows carry the name in the identity path
(`manifests/<name>/sha256:<hex>` and `blobs/<name>/sha256:<hex>`). Digest
GET/HEAD and digest DELETE resolve inside that name. A tag's key carries the
name (`mutable_refs`), and its target resolves through the named manifest path
for new rows. The referrers list includes only referrers whose identity path
carries the asked name. The subject's own namespace is deliberately not
consulted: the `oci_subject` edge targets a content hash, not a namespaced
artifact row, and a referrer may be pushed before its subject exists here. The
edge also records a projected name. During the expand window,
digest reads fall back to name-free legacy rows; those rows still have unknown
namespace and are not rewritten by a read, so a legacy referrer remains listed
under every asked name.

A blob mount's `from` is read as an OCI namespace, `<repository>/<name>`: a
`from` with no `/`, or whose name half fails the wire grammar, falls through to
an ordinary upload rather than mounting, and a blob held only under a different
name in the source repository is not mounted. Manifest admission resolves a
child manifest, and a single-image manifest's config and layer blobs, inside
the pushing name. A pull-through resolves the row for the bytes it just fetched
inside the asked name, so it mints that name's own row rather than serving
another name's.

Every one of those reads tries the scoped path first and the name-free legacy
path on a miss, including the mount's source lookup. A legacy row admitted
through a fallback is admitted with its namespace **unknown**, never as a row
belonging to the asked name — so the fallback widens what is reachable by one
case (a row with no name) and never by the case the model exists to close (a
row with a different name).

**Not yet held:** nothing on the read side. What remains is the contract step,
which removes the fallbacks and drops the projected name key.

The contract step is **not due yet** and is not scheduled here: per ADR 0030 it
ships one release after unit 460, which ships in 0.18.1. Expand and contract are
separated by a release so a rolling upgrade never has the previous release's
code building name-free paths against rewritten rows.

## What this model asks of other records

- **[ADR 0043](../../adr/0043-oci-image-index-support.md)** requires an index's
  children to resolve through a *"same-repo existence check"*. In OCI terms
  "same repository" is "same `<name>`", so that check narrows under this model.
  The ADR's own wording is amended separately; this page is not that amendment.
- **The format-handler contract** states that OCI has no logical-path
  projection, which is why `FormatHandler::build_artifact_logical_path` has a
  fail-loud default (`crates/hort-domain/src/ports/format_handler.rs`, and the
  interface table in
  [add-a-format-handler.md](../how-to/add-a-format-handler.md)). A name-scoped
  OCI identity **is** such a projection, so OCI gains the override the other
  four handlers already have. The trait's method set does not change.
- **OCI's role classifier reads the path.** `scan_kind` and
  `is_provenance_constituent` (`crates/hort-formats/src/oci.rs`) distinguish a
  blob from a manifest by the path's prefix. Whatever layout carries the name
  must keep that role segment findable, or the classifier parses instead of
  matching a prefix. The choice belongs to the implementing change; this page
  records that it has to be made.
