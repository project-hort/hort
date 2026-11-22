# 461 — the referrers list belongs to the name that was asked

**Issue:** #459 · **Branch:** `agent/459-oci-namespace-identity` · Unit 2 of 5.
**Supersedes** `backlog/428-the-list-belongs-to-the-name-that-was-asked.md`, which asked the question before the namespace was decided.

## Why unit 460 does not already fix this

460 scopes identity through the **path**. The referrers index does not read a
path: `content_references` is keyed
`(repository_id, source_artifact_id, target_content_hash, kind)`
(`migrations/013_content_references_multivalue_pk.sql:81`) and the handler asks
`find_by_visible_target(repo_key, &target_hash, Some("oci_subject"), actor)`
(`crates/hort-http-oci/src/referrers.rs:226`). The query is **hash**-keyed,
so it crosses every name in the hort repository no matter what the path says.

Two narrowings are owed, and they are different questions:

1. **The subject must resolve inside the asked name.** `GET
   /v2/<repo_key>/<name>/referrers/<digest>` is a question about a subject in
   `<name>`. Today the digest is taken as a bare hash.
2. **Each referrer must itself live in the asked name.** A signature pushed
   under `other/thing` must not appear in `library/nginx`'s list.

## Where the name comes from — and why the projected key is not the answer

After 460 the source artifact's own `path` carries its name, and the handler
already hydrates every candidate's `Artifact`
(`referrers.rs:274`, through `find_visible_by_id`). So the referrer's name is
derivable from data the handler holds, with no new query and no new column.

Unit 430 also projected a `name` key onto the edge, which was the right answer
while identity was name-free. It is now **redundant** — identity carries the
name, and a projected copy is a second source of truth for the same fact that
can disagree with the path. Do not read it here. Removing it is unit 464's
cleanup, not this unit's.

**Prefer the path over the projection deliberately, and say so in the code.** A
projected name is as complete as whatever wrote it; a path is the identity the
read resolved through. When the two can disagree, the one the lookup used wins.

## The cost question a reviewer will raise

Filtering after hydration means a list is hydrated and censused before rows are
dropped. ADR 0062 chose projection data for list closure precisely to keep this
route cheap. Two honest answers to weigh and one to pick:

- Filter in the adapter, by narrowing the query — needs the name to be a
  queryable column or a path predicate on the joined artifact row.
- Filter in the handler, after hydration — no schema or query change, costs the
  hydrations of rows that will be dropped.

Referrer counts per subject are small (signatures, SBOMs, attestations — single
digits in practice), so the second is defensible; but **measure the shape of the
query you end up with and say which you chose and why**. Do not pick the
cheaper-to-write one silently.

## Acceptance

- A signature pushed under `library/nginx` with a subject in `library/nginx`
  appears in `library/nginx`'s referrers list. The same signature does **not**
  appear in `other/thing`'s list for the same digest, and `other/thing`'s answer
  is `200` with an empty `manifests` array — not `404`, which would make the
  omission an enumeration oracle (the handler's step 7 comment already states
  that rule; keep it true).
- A subject digest that exists only under another name answers `200` with an
  empty list for the asked name.
- A referrer under the asked name whose subject is under another name does not
  appear.
- The projected `name` key on the edge is **not** read by the handler; assert
  that a row whose projected `name` disagrees with its path is listed according
  to the **path**. That test is the one that stops the redundant key from
  quietly becoming authoritative again.
- The existing ADR 0062 terminal-omission behaviour and the withheld-census
  debug line are unchanged.
- The change adds no uncovered lines (intersect the diff's added line numbers
  with `cargo llvm-cov --show-missing-lines`, per touched file).

## Not in this unit

What the list may **withhold** — the spec's *Enabling the Referrers API* item 3
`MUST` against ADR 0062's terminal omission and ADR 0055's audience reservation
— is `backlog/429-what-the-list-may-withhold.md` and waits on a maintainer
decision. This unit changes *which name* a row belongs to, never *whether* a row
may be hidden.
