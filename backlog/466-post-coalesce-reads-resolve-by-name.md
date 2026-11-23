# 466 — the post-coalesce reads resolve by name, not by bare hash

**Issue:** #459 · **Branch:** `agent/459-oci-namespace-identity` · Unit 6 of 7.
**Found 2026-11-23** by the bare-hash census unit 465's directive asked for.
That census is the reason this exists; it is the one deliverable of 465 that was
not in its own acceptance.

## The two sites

Both are the **post-coalesce read**: after a pull-through window closes, leader
and follower re-resolve the row for the bytes that were just fetched.

| Site | Call | `name` in scope |
|---|---|---|
| `crates/hort-http-oci/src/blobs.rs:1157` (in `try_upstream_blob_pull`, `:956`) | `find_in_repo_by_hash(repo.id, &content_hash)` | **yes** (`name: &str`) |
| `crates/hort-http-oci/src/manifests.rs:2074` (in `finalise_manifest_pull`, `:2064`) | `find_in_repo_by_hash(repo.id, &content_hash)` | **yes** (`name: &str`) |

## This violates a rule the port already states

`ArtifactRepository`'s own documentation
(`crates/hort-domain/src/ports/artifact_repository.rs:118-130`) says it in as
many words:

> that method answers `LIMIT 1`, which is right for "does this repository hold
> these bytes at all" and **wrong for any caller that has to *act* on the row**.
> Identical bytes can be ingested at several paths in one repository — an OCI
> blob also pushed as a manifest, a wheel re-uploaded under a second name — so a
> decision addressed by digest has to see every candidate row before it picks,
> or refuse to pick.

Both sites act on the row: they return it as the pull's outcome and the handler
serves from it.

**This is not a regression unit 460 introduced — it is a latent defect whose
reachability 460 multiplied.** Before 460 two rows per `(repository_id, hash)`
required the same bytes to be both a blob and a manifest, which is rare. After
460 it happens whenever **two image names in one hort repository share a
blob** — which is the ordinary case for images built on a common base.

## What goes wrong, in order

With a row for those bytes already present under another name in the same
repository:

1. `find_in_repo_by_hash` returns **that** row (`LIMIT 1`, name-blind).
2. The handler serves the blob or manifest under the **asked** name from a row
   belonging to another name — the cross-name serve unit 460 exists to
   prevent, re-entering through the proxy path.
3. The `Ok(None)` arm that would have minted this name's own row never runs, so
   **nothing is written for the asked name** and the next request pulls
   upstream again. The pull never sticks.

## The fix is local — no port change, no new method

Both functions already carry `name`. Resolve the scoped path and fall back to
the legacy name-free one, exactly as units 460, 462 and 465 do everywhere else
(`oci_blob_coords(name, &hash).path` / `oci_manifest_coords(name, &hash).path`,
then `legacy_oci_artifact_path`). A miss then correctly reaches the existing
`Ok(None)` arm, which already reconstructs coords from `(name, hash)` — its
comment says so.

The plural `ChecksumMatchRow` sibling the port offers is **not** what this
needs: these callers know which row they want, they are not choosing among
candidates.

## Acceptance

- A pull-through of a blob whose bytes already exist under **another** name in
  the same repository mints this name's own row and serves it; the other name's
  row is untouched. Assert both rows exist afterwards, with their literal paths.
- The same for a manifest.
- A second request for the same `(name, digest)` is served from the row,
  **without** a second upstream fetch — assert the upstream was called once.
  That is the "pull never sticks" half and it is the one a reader will not
  think to check.
- A legacy name-free row still satisfies the post-coalesce read during the
  expand window, with a named test.
- The follower path that joins a window whose leader ingested into a
  **different repository** still reaches `register_existing_cas_blob` and does
  not fail closed — that behaviour is documented at the site and is not this
  unit's to change.
- The change adds no uncovered lines.

## Not in this unit — two open questions the same census raised

Both are recorded on #459 rather than groomed, because each needs a decision
about whether an OCI identity or the bytes are the subject:

- **`ManifestDeliverabilityUseCase::terminal_constituents`** takes hashes only
  and its catalog is repository/hash scoped across names, so a terminal row
  under one name can decide the verdict for another. It fails **closed** (it
  reports more terminal, never fewer), so there is no urgency, and whether a
  verdict should follow name or byte identity is the question.
- **`provenance_cascade.rs:323,843`** select the clearance root and
  constituents by repository/hash, with the same question about what a
  clearance event is about.
