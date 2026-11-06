# 397 — The tree warms at the source

**Issue:** #312 · **Branch:** `agent/312-the-tree-warms-at-the-source` · single
item.

**Governing decisions:** ADR 0007 (the observation window, untouched here —
including its referenced-tree-descendant carve-out, see *The anchor, correctly
stated*) · ADR 0008 (the layering that rules out the obvious shortcut — see
*The shortcut that does not exist*).

## The property

**A child manifest ingested by `oci_index_child_ingest` leaves its config and
layer blobs ingested, not merely their edges.** Today the handler writes the
`oci_config` and `oci_layer` rows — so it knows exactly which blobs they are —
and fetches none of them. They stay absent until someone asks, and for a
quarantined parent nobody can ask: a 503 carries no body, and the body is the
only place those digests are published.

## Why the operator switch is not an alternative

`prefetch_policy.enabled` is off on the OCI proxies, and turning it on would
not help here: the client-path warm is a **no-op for an index**, which the call
site says in as many words — *"An OCI index has no config/layers, so
`warm_manifest_blobs` is a safe no-op for the index-by-digest case"*
(`crates/hort-http-oci/src/manifests.rs:1349`). A multi-arch image's blobs hang
off its **children**, and the handler is the only path that ingests those. So
this unit is the only route to a warm multi-arch tree.

## Ungated, and the precedent is three lines up

The warm is **not** gated on `prefetch_policy.enabled`. Immediately above the
gated blob warm, in the same function, `enqueue_declared_children` takes the
index's children into ingest **ungated**, justified by letting the children's
windows run concurrently with the index's. That is the same activity — finish
ingesting the tree a client named — and the project already treats it as not
requiring the prefetch opt-in. What the switch governs is different: hort
deciding by itself to fetch something nobody asked for.

Confirmed by Tom, Matrix 2026-11-06: *"Nein, kein Widerspruch. Setze das so
um."*

## The shortcut that does not exist

**Do not try to call `hort_http_oci::prefetch::warm_manifest_blobs`.** Three
reasons, each sufficient:

1. It is `pub(crate)` in `crates/hort-http-oci/src/prefetch.rs:225`.
2. It spawns `crate::blobs::try_upstream_blob_pull` — the OCI adapter's own
   upstream pull-through, riding `PullDedup` inside `coalesce_blob`. That is
   protocol work and belongs in the adapter.
3. `hort-app` does not depend on `hort-http-oci` and must not: the dependency
   runs the other way (`hort-http-oci/Cargo.toml` depends on `hort-app`), and
   ADR 0008 makes that graph load-bearing.

The issue's acceptance line *"Kein zweiter Mechanismus: der Fan-out ist
derselbe Codepfad, keine Kopie"* therefore has to be read as **"do not invent a
third way"**, because the literal reading is architecturally impossible. The
handler's own ingest path is not a third way — it is the one it already uses
for the child manifest itself.

**Nor is `prefetch_ingest` the vehicle.** That handler is keyed on
`(repository_id, package, version)` and drives format-native metadata parsing;
an OCI blob is a digest, not a package coordinate. The handler already imports
only `is_upstream_not_found` from it, and that is all it should take.

## The shape

The handler already holds everything needed and already uses it for the child
manifest: `UpstreamProxy` for the upstream fetch, `IngestUseCase` /
`VerifiedIngestRequest` for the ingest, `StoragePort`, `ArtifactRepository`,
`ContentReferenceClaim`. Extend that to the blobs it is already naming.

- Take the digests from the **already-parsed** child manifest — the same values
  the `oci_config` / `oci_layer` edges are written from. Do not re-parse and do
  not re-fetch the manifest body.
- Ingest **in the same handler run**. The issue's acceptance says *"nach dem
  Handler-Lauf sind Config und Layer des Kindes eingezogen"*, which a
  fire-and-forget spawn cannot promise: a task that completes while spawned work
  outlives it has no retry accounting and no observable result.
- **Per blob, best-effort:** a blob that cannot be fetched is logged and
  skipped; it does **not** fail the child row. The child manifest's own ingest
  already succeeded, and failing the row would re-do that work to retry a blob
  that the lazy pull path still covers — which is exactly where it sat before
  this unit existed.
- An upstream 404 for a blob is the `is_upstream_not_found` case the handler
  already imports, not an error.

### What the ingest call looks like

Mirror the client path's blob ingest (`crates/hort-http-oci/src/blobs.rs`
around `:1010-1045`) — it is the same operation one layer out, and matching it
is what keeps a warmed blob indistinguishable from a lazily pulled one:

- `VerifiedIngestRequest::ProtocolNative`, `content_type:
  "application/octet-stream"`, `upstream_digest` = the blob's hash,
  `upstream_published_at` = `BlobFetch::last_modified`,
  `trust_upstream_publish_time` from the resolved mapping.
- `claimed_edges: &[]` — a pulled blob claims only its own content; the
  manifest that references it carries the `oci_config` / `oci_layer` claims,
  and this handler has just written them.
- The stream bridge is `tokio_util::io::StreamReader::new(fetch.stream)` boxed
  as `Box<dyn AsyncRead + Send + Unpin>`. `tokio-util` is already a `hort-app`
  dependency; nothing new goes in `Cargo.toml`.

### Coords: re-derive, and from the domain constant

The blob's `ArtifactCoords.path` must be exactly what the read path resolves,
`blobs/sha256:<hex>`, or the warmed row is unreachable and the next client GET
mints a second one. Re-derive it in the handler — `hort-app` must not reach
into `hort_http_oci::coords` (ADR 0008), which is the same reason
`child_manifest_coords` exists — but take the prefix from
**`hort_domain::oci::OCI_BLOB_PATH_PREFIX`**, which both layers may use. The
manifest sibling had to hardcode its prefix because none exists for manifests;
this one must not, and a test pins the resulting path shape.

### No `PullDedup`

Do **not** add `PullDedup` to the handler. `PrefetchIngestHandler` — the
sibling task handler doing the same fetch-then-ingest in the same layer — holds
`repositories`, `upstream_proxy`, `upstream_mappings`, `format_handlers`,
`ingest` and no dedup, and this handler already fetched the child manifest
without one. The window a dedup would close is a redundant upstream GET whose
two ingests converge on the same content hash; the cost of closing it is a new
constructor argument through the composition root and every test construction
site. The established shape is the design's own answer here.

## Already held, and still warmed

The warm has **two** call sites, not one.

1. On the ingest path, after `ingest_verified` mints the child and its edges.
2. On the **already-present** path, after `reconcile_claimed_edges`.

The second one is nearly free and is where an operator's existing cold tree
gets fixed: that branch already reads the stored manifest body back from CAS
through `StoragePort::get` and already runs `derive_claims` over it to reassert
missing edges, so the blob digests are in hand, and `UpstreamResolver::resolve`
has already produced the mapping above it. A child minted before this unit
existed has edges and no blobs — exactly the state the claim repair there was
built for, one level down.

That branch's log line currently reads *"no upstream request, no re-mint, no
re-anchor"*, and its `ChildOutcome::AlreadyPresent` doc says the same.
**Amend both** to scope the claim to the manifest: after this unit a blob fetch
can happen there. A doc line that has quietly stopped being true is worse than
no doc line.

## Counters

`ChildSummary` and the `result_summary` JSON both carry per-child counts
already (`membership_edges_written`, `grandchildren_*`). Add the blob warm's
own — attempted, ingested, already present, failed — in the same style, so an
operator reading `result_summary` can tell a warm tree from a cold one without
reading logs. Extend the module doc's *Behaviour, in order* and *Outcome
shape* sections to match.

## The anchor, correctly stated

**Corrected after implementation.** An earlier version of this item said each
warmed blob is anchored by `first_seen_for_checksum` (ADR 0054), exactly as a
lazily pulled one would be. The second half is true and the first is not, and
the implementation found it with a failing test.

The anchor is the **minimum** over several sources, and for a config or layer
blob of a manifest whose `oci_config` / `oci_layer` edges have already
committed, the dominant source is ADR 0007's **referenced-tree-descendant
carve-out**: `ingested_at - effective_duration`, a window that is already
over. The carve-out names exactly these kinds, and the edge that makes the
blob a descendant is written by the child manifest's own ingest one step
earlier — not by the warm.

So the property this item needs still holds, for a different reason than
stated:

- The warm supplies no anchor and no window arithmetic of its own.
- A blob a client pulls lazily a day later lands on the **same** anchor,
  because it is a descendant by the same edge. Warmed and lazily pulled are
  indistinguishable.
- The release predicate is untouched. The carve-out removes the timer and
  nothing else: the blob is minted `Quarantined` and still needs its own clean
  scan verdict, so the warm carries no release authority.

Do not restate the `first_seen_for_checksum` version of this.

## Out of scope

- No change to the time gate, to `check_quarantine`, or to the zero-window
  anchor for referenced-tree descendants.
- No change to the client path in `hort-http-oci`, including its gate. It keeps
  warming single-image digest pulls exactly as now.
- No new task kind, and therefore no `cli_advertises_only_routed_task_kinds`
  surface to extend.
- No `Cargo.toml` change in any crate. If one seems necessary, stop and say so
  in the report.

## Acceptance

- After a handler run over a child manifest, the child's config and layer
  blobs have artifact rows — not only `oci_config` / `oci_layer` edges. A test
  shows it.
- The same holds on the **already-present** path: a child already minted whose
  blobs are absent gets them. A test shows it, and the two amended doc lines
  no longer claim that branch makes no upstream request.
- A blob whose upstream fetch fails leaves the child row **completed**, with
  the failure logged; a test shows that too, because the alternative silently
  turns one bad layer into an endlessly retried child.
- An upstream 404 on a blob is not an error and not a retry.
- The warm fires regardless of `prefetch_policy.enabled`. A test pins it with
  the flag **off**, since that is the configuration every OCI proxy is in.
- The warmed blob's coords path is `blobs/sha256:<hex>`, derived from
  `OCI_BLOB_PATH_PREFIX`. A test pins it.
- `result_summary` carries the blob counters.
- The client path's gated behaviour is unchanged — its existing tests at
  `crates/hort-http-oci/src/prefetch.rs:868/909/937` still pass untouched.
- `#[serial(hort_pg_db)]` on every DB-backed test.
- Gate green, workspace suite run **once**.
