# 326 — The list surfaces omit what they will not serve

**Issue:** #348 · **Branch:** `agent/348-list-surfaces-omit-withheld`
**Governing decisions:** ADR 0062 (the rule and its two enforcement shapes) ·
ADR 0043 (`:277` membership edges commit with the claiming artifact; the
2026-10-13 narrowing) · ADR 0055 (diagnosability lives on the direct request) ·
ADR 0021 / ADR 0045 (repository anti-enumeration, **not** reopened) ·
ADR 0007 (fail-closed) · ADR 0008 (the format crate does not reach past the
use case).

**Confirmed by the maintainer 2026-10-14** (#348 moved to `ready`). The
decision, the measurement behind it and the rejected alternatives are in #348's
description; this item is the implementation contract.

## What is true today — measured 2026-10-13

Two hort-**built** OCI documents advertise a terminally rejected artifact and
then refuse it on the pull.

**`GET /v2/<name>/tags/list`** applies no status filter of any kind.
`crates/hort-http-oci/src/tags.rs` contains no status predicate (its only
`status` occurrences are HTTP codes), and the query behind it is a bare
`SELECT … FROM mutable_refs WHERE repository_id = $1 AND namespace = $2 ORDER
BY ref_name` (`crates/hort-adapters-postgres/src/ref_registry_repo.rs:155`).
Nor is a tag withdrawn when its target goes terminal: `RefUseCase::retire` has
exactly two production callers — `hort-http-oci/src/manifests_write.rs:1443`
and `hort-http-npm/src/lib.rs:1115` — both explicit client deletes.

**`GET /v2/<name>/referrers/<digest>`** contains the string `quarantine` zero
times (`crates/hort-http-oci/src/referrers.rs`). Its per-row loop skips only a
tombstoned or invisible source (`:251-261`).

## One thing that is already free, and it changes the shape

**The referrers loop already holds each candidate's `quarantine_status`.** It
hydrates every row through `ArtifactUseCase::find_visible_by_id` (`:251`) to
recover `sha256` and `size`, and after items 324/325 that load hydrates the
artifact fully. So the *own-status* half of the referrers filter costs **one
match on data already in hand** — no query, no read.

Only the **closure** half needs new machinery. That matters because the closure
half is the one that catches the real population: a referrer manifest whose own
status is fine and whose shared config blob is terminal.

`tags/list` has no such freebie — it never loads an artifact at all — so both
halves there come from the new resolution.

## What to build

**1. A census, not a per-entry resolution.** One port answering, for a
repository and a **set** of manifest content hashes, which of them are
non-deliverable:

```rust
async fn non_deliverable_in(
    &self,
    repository_id: Uuid,
    candidates: &[ContentHash],
) -> DomainResult<HashSet<ContentHash>>;
```

A hash is non-deliverable when its **own** status is terminal, or when any
member of its closure carries a terminal status. `is_terminal`
(`crates/hort-domain/src/entities/artifact.rs:146`) is the one definition of
terminal — item 293 put it there and item 294 already derives its SQL status
list from it. Do not write a second list.

**2. The closure comes from the membership projection here, and only here.**
One recursive statement over `content_references` (PK
`(repository_id, source_artifact_id, target_content_hash, kind)` since
migration 013, descent indexed by `idx_content_references_source`) joined to
`artifacts`. **Zero CAS reads.**

This is a **deliberate divergence from item 294's authority choice, and it is
the whole reason #348 exists** — read #348's description before you argue with
it. In short: on the manifest route a GET already holds the bytes, so reading
them costs nothing and the projection would be a second source of truth for
free; on a list surface the same bytes are N round trips. Same question,
different input cost, different answer. ADR 0062 gains the sentence that says
so (task 5).

**The one weakness, and it must be in the rustdoc, not just here.** Rows minted
before ADR 0043's 2026-10-07 amendment can carry incomplete edges
(`oci_membership_edge_backfill` exists for them). An incomplete edge set
**under**-reports, so such an entry stays listed and refuses on the pull —
which is exactly today's behaviour, so no regression, and it fails **open**
rather than hiding something servable. The converse cannot happen: edges are
built only from a complete resolution, so the projection cannot invent a
constituent. Write that where the query lives.

**3. Referrers filters first — it is the surface that matters.** Drop a
descriptor whose source manifest is non-deliverable. Use the already-loaded
`artifact.quarantine_status` for the own-status half (free, see above) and the
census for the closure half, batched over the surviving rows in **one** call —
not one call per row.

**4. `tags/list` filters too.** Resolve each tag's `target_hash`, ask the census
once for the whole set, and omit the tags whose target is non-deliverable. A
tag whose `target_kind` is `version` rather than `hash` is not an OCI manifest
pointer; leave it alone rather than guessing.

**5. ADR 0062 gains one paragraph** saying the authority depends on the
document's input cost — bytes where the reader already holds them, the
projection where they would be N round trips — plus the dated legacy-edge
weakness. That is the generalisation this unit rests on, and leaving it
implicit is how the next reader re-derives it wrongly.

**6. One commit per surface**, plus the ADR. Referrers first.

## What must not change

- **Repository anti-enumeration** (ADR 0021 / 0045). A caller the read gate
  refuses sees exactly what it sees today, and those regression groups must
  pass untouched.
- **The manifest read path** (item 294). Its closure authority stays the
  bytes. Do not route it through the census, and do not "unify" the two.
- **An entry whose target is merely not ingested stays listed.** "Not local
  yet" is not terminal, and a cold pull-through must keep working.
- The **direct** answers: `GET …/manifests/<tag>` and a referrer fetched by
  digest keep naming their verdict with the axis. The diagnosis must not move
  with the listing — that is what keeps ADR 0055 intact while the list omits.
- `IndexMode` is not extended and no operator knob is added.

## Tests

- A tag whose target manifest is **itself** terminal: absent from `tags/list`.
- A tag whose target's **constituent** is terminal: absent. This is the case a
  cheap own-status-only filter would miss, so it is the one that proves the
  closure half works.
- A referrer manifest that is itself terminal: absent from the referrers index.
- A referrer whose **constituent** is terminal: absent.
- An entry whose target is **not ingested**: still listed. Show the test red
  under the inversion that treats absence as terminal.
- A `Quarantined` (not terminal) target: still listed — a hold is "not yet",
  and ADR 0062 leaves the per-child model standing for holds.
- **The direct route still answers its verdict** for an omitted entry, asserted
  in the same test so the pair cannot drift: omitted from the list **and**
  `403` with the axis when named.
- **One statement per list call**, asserted in the adapter test, and no `= ANY`
  over a hash list (a pooled `= ANY($1::array)` degrades to a per-row scan at
  the sixth execution; 64.2 s against 1.7 s, measured).
- A guard test pinning the census's status list against `is_terminal` over
  **every** `QuarantineStatus` variant, with a counter-assertion that the guard
  still finds the real call sites — the `crates/*/tests/` family has the shape.
- A negative control: revert the production change and show the new tests fail.
  If a plain revert leaves some passing, mutate instead and report the matrix.

## Acceptance

- Both surfaces omit what they would refuse, including the constituent case.
- Zero CAS reads on either list path; one statement per call.
- A not-ingested target stays listed; a `Quarantined` target stays listed.
- The direct routes' verdicts are unchanged and asserted.
- ADR 0021 / 0045 regression groups green, untouched.
- ADR 0062 carries the input-cost paragraph and the dated legacy-edge note; the
  query's rustdoc carries the weakness.
- Gate: the **unit gate**, `bash handover/gate-unit.sh -p <the crates touched>`,
  judged by output and never by the rc. Measure the set rather than guessing.
- This changes an OCI serve path, so the branch goes to the human for the
  compose E2E before any merge request.
