# 460 — the OCI identity path carries the name

**Issue:** #459 · **Branch:** `agent/459-oci-namespace-identity` · Unit 1 of 6 — the expand half.

## What is decided before this unit starts

`docs/architecture/reference/oci-namespace-and-identity.md` is the specification
and it is on `develop`. The OCI wire `<name>` is the namespace for artifact
identity; the reach is the whole OCI surface (maintainer, 2026-11-21). This unit
does the manifest and blob half.

## The shape, and why it is the path rather than a column

hort already answers this question four times. cargo stores
`crates/{name}/{version}/{name}-{version}.crate`, npm `{name}/-/{filename}`,
PyPI `{name}/{filename}`, Maven the GAV path — the name goes **in the logical
path**, and `(repository_id, path)` is the resolution key. A new `namespace`
column on `artifacts` would be a second mechanism for a thing the codebase
already has one of, and it would make the uniqueness key a three-column key for
every format to carry the OCI case. So: the name goes in the path, and there is
**no schema change in this unit at all**.

The role segment stays **first**, because the role is what two production
predicates classify an OCI row by — `OciFormatHandler::scan_kind`
(`crates/hort-formats/src/oci.rs:67-73`) and `is_provenance_constituent`
(`:156-158`). So

```
blobs/<name>/sha256:<hex>          (was blobs/sha256:<hex>)
manifests/<name>/sha256:<hex>      (was manifests/sha256:<hex>)
```

The two role segments stay disjoint, which is what keeps a manifest and a blob
that share bytes from colliding on one key. Role-first is load-bearing against a
crafted name, too: an OCI `<name>` may legitimately be `blobs` or `manifests`,
and because the role is written first, a blob under the name `manifests` is
`blobs/manifests/sha256:…` and still classifies as a blob.

## The path has a grammar now, so it gets one definition

Today the shape is spelled out in six places — two builders in
`hort-http-oci::coords`, two re-derived builders in `hort-app`, and the role
prefix again in the classifier and in SQL. That was tolerable while the shape
was a constant prefix plus a digest. It is not tolerable once the shape has an
**interior variable segment**, because reading the path now means *parsing* it,
and a parser re-typed per consumer is the defect this issue exists to remove one
level up.

So the grammar gets a single definition in `hort-domain::oci` — a builder and a
parser, beside the constants that are already there — and every consumer reads
it:

- the builders in `hort-http-oci::coords` call it,
- `hort-app`'s `child_manifest_coords` / `child_blob_coords` call it (which
  **removes** the ADR 0008 re-derivation their doc comments currently apologize
  for: the domain is where both layers may depend, and the duplication only
  existed because no domain-level builder was offered),
- the role classifier parses with it,
- the derived SQL selectors below interpolate its role prefixes.

**This is also what keeps a security property the current test suite asserts.**
`constituent_classification_is_prefix_anchored`
(`crates/hort-formats/src/oci.rs:413-423`) asserts that `blobs/sha512:<hex>` is
**not** a blob row — a digest algorithm outside hort's CAS keyspace is not an
OCI blob projection — and that a path merely *containing* the blob prefix is not
one either, *"accepting it would let a crafted path suppress a subject's
rejection."* `is_provenance_constituent` returning `true` means *this row can
never carry its own attestation and takes its clearance from its subject*, so a
false positive there is an attestation requirement silently dropped. Simply
shortening `OCI_BLOB_PATH_PREFIX` from `"blobs/sha256:"` to `"blobs/"` would
make `blobs/sha512:<hex>` classify as a blob and delete half of that assertion
without any test going red. A parser that validates all three segments keeps it;
a shortened prefix does not. Keep both halves of that test alive, with the
sha512 case re-expressed against the new shape.

`OCI_BLOB_PATH_PREFIX` (`crates/hort-domain/src/oci.rs:93`) is the only
role prefix that exists as a constant today; the manifest role prefix is a bare
`"manifests/"` literal at `crates/hort-formats/src/oci.rs:70` and inside two SQL
statements. Give the manifest role the same standing as the blob role — the
asymmetry is what let the literal spread.

The split back out is unambiguous: an OCI name's grammar admits no colon, so the
`sha256:` segment can only be the digest.

## The name is already in hand at every write site — measured against `develop` f0bfdba1

This is the finding that makes the unit tractable. Every production builder
already receives the name, so no call signature and no task payload has to grow;
the name is dropped on the floor today and this unit stops dropping it.

| Site | Call |
|---|---|
| `hort-http-oci/src/blobs.rs:420`, `:996`, `:1171` | `oci_blob_coords(name, …)` |
| `hort-http-oci/src/uploads.rs:341`, `:418` | `oci_blob_coords(name, …)` |
| `hort-http-oci/src/upload_session.rs:1231` | `oci_blob_coords(name, …)` |
| `hort-http-oci/src/manifests_write.rs:857` | `oci_manifest_coords(name, …)` |
| `hort-http-oci/src/manifests_write.rs:2094` | `oci_manifest_coords(name, …)` — `delete_by_digest` |
| `hort-http-oci/src/manifests_write.rs:1947` | `oci_group_coords(&name, …)` |
| `hort-http-oci/src/manifests.rs:228` | `oci_manifest_coords(name, …)` — the serve path |
| `hort-http-oci/src/manifests.rs:1445`, `:2100` | `oci_manifest_coords(name, …)` — proxy pull |
| `hort-http-oci/src/manifests.rs:1755` | `oci_manifest_coords(&meta_name, …)` — `meta_name` is `name.to_string()` (`:1617`), i.e. the requested name |
| `hort-app/src/task_handlers/oci_index_child_ingest.rs:1023`, `:1230` | `child_manifest_coords(&parsed.requested_name, …)` |
| `hort-app/src/task_handlers/oci_index_child_ingest.rs:1316` | `child_blob_coords(&parsed.requested_name, …)` |
| `hort-app/src/task_handlers/oci_index_child_ingest.rs:839` | `existing.path == child_manifest_coords(&parsed.requested_name, …).path` — a **stored-path comparison**, so it is a read site as much as a write site and the fallback has to reach it |

The background worker is the one that looked doubtful and is not: its task
payload carries `requested_name` (`OciIndexChildIngestParams`), and a grandchild
inherits its parent's requested name (`oci_index_child_ingest.rs:1471`).

**The one signature that cannot stay as it is:** `oci_manifest_path(digest)`
(`coords.rs:102`) builds a path with no name, so after this unit it can only
build a **legacy** path. Its single production caller is the index-child
existence check (`manifests_write.rs:2694`), which is unit 462's scope and stays
on the legacy resolution for one unit on purpose — the fallback keeps it
working. Leave the helper's behaviour alone and rename or re-document it so it
cannot be mistaken for the current builder; a helper named like the live path
builder that silently builds the old shape is how the next unit inherits a bug.

Read `oci_index_child_ingest.rs:505-556` before touching it: both helpers' doc
comments state the exactness of the path as load-bearing in two directions — the
client `GET` resolves the path, and `is_provenance_constituent` reads the
prefix. Both halves move in this unit, so those comments move with them or they
become lies that argue for the old shape.

## The derived selectors — the half that was missing from this item

Two **production SQL statements** match the manifest path shape as a literal.
Neither errors after the shape changes; both silently select **zero rows**,
which is the failure mode no test and no pipeline reports:

- `crates/hort-adapters-postgres/src/rescan_candidates.rs:559` —
  `AND a.path LIKE 'manifests/sha256:%'`, the **composite-scan rescan candidate**
  selector. Going empty means OCI image manifests stop being picked up for
  rescan, with every surrounding gate still green.
- `crates/hort-adapters-postgres/src/artifact_repo.rs:1076` —
  `WHERE path LIKE 'manifests/sha256:%'` in
  `find_oci_image_manifests_without_kind`, the `oci_config` content-reference
  **backfill** candidacy. Going empty means the backfill reports success having
  done nothing.
- `crates/hort-app/src/use_cases/test_support.rs:1367` —
  `a.path.starts_with("manifests/sha256:")`, the mock that **mirrors** that
  selector (`:1338` documents the mirroring in those words). It moves with the
  query, or every test standing on it proves a behaviour the adapter no longer
  has.

Both SQL comments (`artifact_repo.rs:1058-1060`, `rescan_candidates.rs:452`)
state the path convention and name `hort-http-oci::coords` as its owner — a
cross-layer coupling held only by prose. Interpolate the domain role prefix
instead of re-typing the literal, so the next change to the shape reaches the
selector through the compiler.

During the expand window **both** shapes must be selected: a predicate on the
role prefix alone (`manifests/%`) matches the legacy and the new shape, and
today's data makes it exactly equivalent to the current predicate.

## Reading the old rows — the half that is not optional

Existing rows keep the name-free path. Changing only the builders makes every
stored manifest and blob unreachable by its own route, and the next client `GET`
mints a **second** row for the same bytes — the exact hazard
`oci_index_child_ingest.rs:539-543` already warns about.

So this unit is the **expand** half of ADR 0030's expand/contract: a read that
misses at the new path falls back to the legacy path, and a write only ever
produces the new one. The fallback is what lets the previous release keep
serving during a rolling upgrade, which is the reason the policy exists and is
not deference to legacy data.

The three production read sites it has to cover:

| Site | Call |
|---|---|
| `hort-http-oci/src/manifests.rs:234` | `find_visible_by_path(repo_key, &coords.path, actor)` — manifest `GET`/`HEAD` |
| `hort-http-oci/src/blobs.rs:423` | `find_visible_by_path(repo_key, &coords.path, actor)` — blob `GET`/`HEAD` |
| `hort-http-oci/src/manifests_write.rs:2103` | `find_visible_by_path(repo_key, &coords.path, Some(principal))` — digest-addressed `DELETE` |

plus the stored-path comparison at `oci_index_child_ingest.rs:839`.

The migration that rewrites the rows and the removal of the fallback are
unit 464, one release later. Do not do them here.

## Acceptance

- A push and a pull under one name round-trip through the new path, for a
  manifest and for a blob; the stored `path` is asserted literally, because that
  string is the identity.
- **The defect this closes, as a test:** a manifest pushed under `library/nginx`
  and fetched by digest under `other/thing` in the **same** hort repository
  answers `404 MANIFEST_UNKNOWN`. Today it is served. The same for the
  digest-addressed `DELETE` (`delete_by_digest`, `manifests_write.rs:2067`, whose lookup is `:2103`)
  and for a blob `GET`.
- A legacy-path row is still served, and a read that fell back does **not**
  rewrite it (that is unit 464's job, and a read path that writes is a different
  decision).
- `scan_kind` and `is_provenance_constituent` classify a new-shape blob and a
  new-shape manifest correctly, and a **legacy**-shape row too — both predicates
  see both shapes during the expand window. The prefix-anchoring assertions
  survive: a path that merely contains a role segment is not that role, and a
  non-`sha256:` digest segment is not a blob projection.
- Both derived selectors match a new-shape row and a legacy-shape row, asserted
  against a database. The rescan selector's existing tests must be extended
  rather than relied on — they seed legacy-shape paths, so they stay green
  while the new shape goes unselected.
- A name containing a slash (`library/nginx`) round-trips, and so does a
  single-segment name; a name that is literally `blobs` or `manifests`
  round-trips and classifies by its role segment.
- The change adds no uncovered lines (intersect the diff's added line numbers
  with `cargo llvm-cov --show-missing-lines`, per touched file).

## Explicitly not in this unit

- The **index-child existence check** (`manifests_write.rs:2694`,
  `find_in_repo_by_path(repo, &oci_manifest_path(&r.hash))`) narrows to the
  parent's name — that is unit 462, paired with the ADR 0043 wording change
  that landed in !1001. Leaving it on the legacy resolution for one unit is
  coherent: the fallback makes it keep working.
- The referrers narrowing (unit 461), mount `from=` (unit 463), the migration
  and the fallback removal (unit 464).

## What this unit subsumes, measured — so nobody writes a unit for it

**Tag target resolution needs no unit of its own.** `mutable_refs` is keyed
`(repository_id, namespace, ref_name)` with `namespace` = the OCI name, so the
tag key is already name-scoped; what crossed names was its *target*, resolved
through the name-free manifest path. The serve path builds that lookup as
`oci_manifest_coords(name, &hash)` with the **requested** name already in hand
(`crates/hort-http-oci/src/manifests.rs:228`), so the moment the path carries
the name, a tag's content-hash target resolves inside its own name and a tag
pointing at a manifest pushed under another name stops resolving. Assert that
as a test here rather than deferring it — it is this unit's behaviour, not a
future one.

## Census provenance

Every line number above was re-measured against `develop` at `f0bfdba1`
(2026-11-22). The first version of this item was written against `6a38bdec`;
three of its line citations had moved, six production write sites were missing
from its table, and the derived-selector section did not exist.
