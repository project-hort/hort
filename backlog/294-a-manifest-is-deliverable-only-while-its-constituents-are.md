# 294 — A manifest is deliverable only while its constituents are

**Issue:** #342 · **Branch:** `agent/342-referenced-blob-deliverability`
**Governing decisions:** ADR 0043 (OCI membership: the manifest's claims and
its constituents, as amended 2026-10 — membership edges commit with their
artifact), ADR 0007 (fail-closed) and ADR 0055 / ADR 0039 §10 (the
write-authorized hold-read, which this unit deliberately does **not** extend).
This unit **amends ADR 0043**; the amendment lands only with the human's
confirmation recorded on #342.

**Decided by item 296 (ADR 0062) — read it first. Depends on items 291, 292 and 293** — 293 for the predicate, and 291+292
because of the rollout order below. **Do not implement this unit until the
sequencing decision on #342 is recorded.**

## What is true today

Nobody owns the property *"a manifest is deliverable only while all its
referenced blobs are"*. The manifest read path gates on the **manifest's own**
`quarantine_status` through an exhaustive match
(`crates/hort-http-oci/src/manifests.rs:313-336`) and then serves the body; the
constituents are never consulted. The edge that could answer it —
`content_references`, kinds `oci_config` / `oci_layer` / `oci_index_member` —
exists, is indexed by source, and is not read for this purpose.

The result is the reported defect: five manifests served 200 while a referenced
layer answered 404 `BLOB_UNKNOWN`, which containerd surfaces as
`failed to pull and unpack … not found` after it has already committed to the
pull. Twelve HelmRelease attempts, each burning a 15-minute timeout, with
nothing on the wire that distinguishes "this layer was rejected" from "this
registry is broken".

**And hort already holds this rule everywhere else.** `IndexMode`'s default
`ReleasedOnly` is documented so that a resolution "can never resolve to a
version that would `503` on download", and `index_filters.rs` drops
`Rejected` / `ScanIndeterminate` under **both** index modes — so npm, PyPI,
Cargo and Maven never advertise a terminally-held version. The OCI manifest
path is the only place in hort that does. This unit is therefore the
generalisation of a standing default to the one format that lacks it, not a
new posture; ADR 0062 (item 296) is where that is stated.

The decided form is **read time** (human decision, 2026-10-10): answer the
question from the document and the catalog when it is asked. No new event, no new terminal
transition, no backfill. The precedent is audit block 2's resolving primitive
(`crates/hort-app/src/use_cases/event_visibility.rs` + its
`event_repository_resolver` port + `event_visibility_is_single_sourced.rs`):
one resolution, every caller through it, fail-closed, pinned by a guard.

## What to do

1. **Lift the constituent's answer to the manifest — do not flatten it.** The
   manifest handler already has all three answer shapes for its *own* state;
   the rule picks the arm the constituent's state would take:
   - a `Rejected` constituent ⇒ `403 DENIED` with `{subject, axis}`, where
     `subject` is the **constituent's** digest and not the client's reference.

     **Corrected 2026-10-13.** This arm read "`MANIFEST_UNKNOWN` (404), the
     hidden-404 that keeps the reason opaque", which contradicted
     determination 3 in this same document and described a posture that no
     longer exists on this route: unit 295 retired the manifest route's
     `404 MANIFEST_UNKNOWN` precisely because it was byte-identical to "no such
     thing", and replaced it with `OciError::ArtifactRejected` → `403 DENIED` +
     `{subject, axis}`. "In 295's answer shape" can only mean the envelope 295
     actually ships. The `subject` field is also what tells the two refusals
     apart: the manifest's own names the client's reference, a constituent's
     names a different digest;
   - a `ScanIndeterminate` constituent ⇒ `check_scan_indeterminate()` (503, no
     `Retry-After`), because that hold is not a statement that the content does
     not exist.
   Reuse 293's single terminal predicate for the class and the existing
   helpers for the envelopes; no new error variants.
2. **One statement, and never a hash fan-out.** Resolve the **statuses** with a
   single SQL statement over the closure the caller already holds, returning the
   strongest hold found as a domain-level class — not artifact rows.

   **Corrected 2026-10-13.** This paragraph said to join "the edge rows for this
   source" — the membership-projection read determination 2 forbids, which is
   where an implementer looks for the query shape. The closure comes from the
   manifest's **bytes** (determination 2, settled); this statement answers only
   how those constituents stand. The same revision withdrew the out-of-scope
   bullet that carried the same contradiction; this sentence was missed and is
   corrected now. Do **not** enumerate edges and then look up statuses by hash
   list: a pooled `= ANY($1::…[])` lookup flips to a generic
   plan at the sixth execution and degrades to a per-row scan (measured
   elsewhere in this codebase at 64.2 s against 1.7 s). Pin the query shape in
   the adapter test the way `find_by_sources_and_kind`'s contract does ("MUST
   execute exactly ONE SQL statement").
3. **Absence is not a hold — and here that is not a fail-open.** A missing
   `artifacts` row for an edge target means the blob is *not local yet*, which
   is the normal state of a pull-through manifest: those edges are registered
   by digest with no existence check, deliberately (see
   `ContentReferenceClaim`'s doc in `manifests_write.rs` — gating them would
   mean never claiming them, and the claim is what gives a descendant its
   zero-window carve-out). A manifest whose constituents are not yet ingested
   must keep answering as it does today; the blob GET pulls them through. Only
   a **present** row in a terminal state changes the answer. An **error**
   resolving the question fails closed (no body served).
4. **Leave `Quarantined` constituents alone, deliberately.** The client's own
   blob fetch already answers 503 with the deadline, so propagating it would
   add no information while changing the answer for every fresh push and every
   pull-through index whose children arrive later — behaviour this ticket has
   not measured and does not need. The same reasoning excludes the
   indefinite-provenance-hold case from this unit: distinguishing it requires a
   bounded event-stream read **per constituent per manifest pull** on the
   hottest path in the registry, to produce a 503 the client gets anyway one
   request later. Items 291/292 remove that population instead of paying for it
   here.
5. **No write-authorized exemption.** ADR 0039 §10 / ADR 0055 let a
   write-granted principal read a *held* manifest so a subject can be signed.
   That exception does not extend here: a terminal constituent will not become
   deliverable by the pusher completing their workflow, and 293 now refuses the
   push that would create this shape in the first place. State that in the
   handler comment — the next reader will ask.
6. **Make it diagnosable.** The server-side log line on this path names the
   manifest digest, the constituent digest and the constituent's status. The
   Referrers API keeps reporting the signature as present (200) while the
   manifest fetch now fails — from outside, that reads like a registry fault
   rather than a held artifact. Record that asymmetry in the ADR amendment and
   in the operator-facing docs; it is the cost of the hidden 404, and it is the
   reason the log line is not optional.

## The rollout order is part of this unit

"No backfill" has a reverse side: the rule applies to the **whole existing
inventory** from the first request after deploy, and there is no migration step
where an implementer would notice. Measured against production, shipped before
291+292 have taken effect it makes this many signature manifests undeliverable:

| Repository | signature manifests |
|---|---|
| `lila-fues` | 8,603 |
| `ffw-apps` | 160 |
| `ci` | 74 |
| `lila-radiocomm` | 7 |
| `openwebui-matrix-bot` | 1 |
| **total** | **8,845** |

Each repository's signature manifests share one rejected `{}` config row, so
the config blob alone is enough; the ~2.5k with an additionally rejected
payload are a subset, not an extension.

**Settled 2026-10-13 (human decision): item 292 is withdrawn and this
sequencing requirement is void.** The earlier text said this unit's code must
reach production only after 292's repair run reported zero remaining rows,
because between deploy and repair the rule would 404 the whole signature
inventory. That was written for the case where the inventory had to survive. It
does not: the figures above come from the dogfood instance, which carries dev
builds and tests, and the decision was *"weg damit … dafür bauen wir doch jetzt
keine Sonderlösungen"*. So there is no repair run and no window to sequence
around — the second of the two options the earlier text named, an **accepted
window**, is the one chosen, and it is accepted indefinitely rather than for a
gap between two deploys.

The measurement stays in this item because it is the price, and whoever reads
this unit later should see what was knowingly spent: **8,845** signature
manifests stop being deliverable in that instance, caused by six rejected `{}`
config rows rather than by the ~2.5k rejected payloads. A signature check
against the instance's **existing** signatures fails; **new** signatures do
not, because item 291 closed the forward path and no payload has been
terminally rejected since 2026-08-15; and **image pulls** are unaffected,
because a signature manifest hangs off its subject as a referrer and is not in
the closure a pull walks. **Do not build a migration, a backfill or a repair
instrument for this population** — that is the thing the decision refused.

## Four determinations this unit inherits from the decision

The case **against** this unit was built before it was approved, and three of
its points are binding here rather than merely noted. Read them before writing
code; each one is a place where the obvious implementation is the wrong one.

1. **Claim and enforce the same thing — and the question is transitive.**
   "Can I pull this image" is a property of the whole tree, while the gate sits
   per node, so a rule that answers one hop down is an arbitrary cut: an index
   over a child whose *layers* are terminal would still answer 200 and then 404
   at the child, which is the same contradiction one level up. The cut is not
   forced by cost. Membership is immutable per digest (content-addressed) —
   only the statuses move — so "does any artifact in this manifest's closure
   carry a terminal status" is one **depth-bounded recursive** statement,
   reusing the existing index-child depth cap (five platforms × ten layers is
   ~55 rows). Build it transitively, and the claim in the ADR amendment is then
   true as written. **Settled (human decision, 2026-10-10):** build it
   transitively. The earlier one-hop scope was my own conservatism, not a
   domain limit, and read cost is explicitly subordinate to correctness here.
2. **The authority is the bytes, not the edges — settled, not open.** The
   cheap query would join the `content_references` edges, but that projection
   is mutable and repairable rather than guaranteed
   (`oci_membership_edge_backfill` exists for manifest rows minted before the
   write path carried its edges), and hort's provenance cascade refuses it as
   authority in writing: edges "nominate", the bytes decide. The closure is
   therefore derived from the manifest's own content — which a GET already
   holds and a HEAD must read from the CAS — plus the catalog's statuses,
   exactly as the index pipeline does for every other format. Read cost is
   subordinate (human decision, 2026-10-10); do not reintroduce a projection
   read as an optimisation without reopening ADR 0062.

   **What this costs, and why the acceptance's "exactly one SQL statement" is
   not in tension with it (clarified 2026-10-13).** That criterion constrains
   **SQL**, not CAS reads. Resolving the closure from bytes means reading
   bytes: for an image manifest the config and layer digests are in the
   manifest a GET already holds, so there is nothing further to read; for an
   **index**, each child's own closure lives in that child's bytes, so a
   transitive answer reads those from the CAS. Gather every digest that way
   first, then ask the catalog **once** for their statuses — one statement,
   anti-join shaped, no `= ANY` over a hash list (a pooled `= ANY($1::array)`
   degrades to a per-row scan at the sixth execution, measured at 64.2 s
   against 1.7 s). So: CAS reads to learn *what* the constituents are, one SQL
   to learn *how they stand*.

   Note what the amendment to ADR 0043 at `:277` ("Membership edges commit with
   the artifact that claims them", 2026-10-07) does **not** change here. It
   makes an edge atomic with its claiming artifact and built only from a
   complete resolution — so the projection is no longer the lagging thing
   determination 2's objection described — and the 2026-10-10 decision was
   nevertheless taken with that amendment already in place. It therefore stands
   as decided. Do not re-open it by citing the amendment; if the measured cost
   of the byte reads is the problem, report the measurement.

3. **Name the offending constituent in the refusal — item 295 makes that
   allowed.** Today a failing pull names the offending **blob** digest, and
   that digest identified the cause in the incident behind this issue:
   identical across repeated pulls of one manifest, different across
   manifests, which is how the reporter ruled out a shared base layer. A bare
   concealed 404 would delete that signal for everyone who cannot read hort's
   logs, and a shared base layer would then make N unrelated images fail with
   nothing in common. Since 295 establishes that whoever may read the artifact
   may learn why it is withheld, this refusal carries the facts 295's envelope
   carries — the axis and the **constituent's** digest as `subject` — and the
   server-side log line stays mandatory alongside it. A silent refusal is not
   acceptable for this unit.

   **Corrected 2026-10-13: "policy" is struck.** This read "the same three
   facts — axis, policy, and the constituent's digest", but policy is the one
   fact 295's envelope deliberately excludes: a `RejectionReason` carries none,
   and resolving the repository's effective policy would mean a new read on a
   fail-closed answer plus a disclosure of operator configuration. Asking for
   it here asked for a field the decision this determination defers to
   forbids.

4. **Decide whether a manifest with a terminal constituent should be minted at
   all — the PUT leaves that open on purpose.** Item 293 refuses the push
   (`MANIFEST_BLOB_UNKNOWN`) but still commits the manifest artifact first,
   because that is the pre-existing contract for an *absent* reference: the
   mint is what makes a client retry after pushing the missing blobs
   idempotent. For a **terminal** reference that commit buys the client
   nothing — the row exists, a re-push deduplicates onto it, and no retry can
   help — so the registry is left holding a manifest it has already decided it
   will not deliver. That is this unit's question rather than 293's, because
   the read path is what decides whether such a row is ever servable: if the
   deliverability rule holds at read time, the stray mint is inert and may
   stay (fewer moving parts, and the retry contract keeps one shape); if it
   does not, the mint is an advertisement of something that will never be
   served, and then it is the mint that has to go. Answer it explicitly in the
   report, with which of the two the implementation chose and why — a silent
   inheritance of today's behaviour is not an answer.

## Explicitly out of scope

- The Referrers API's own answer (it keeps reporting the signature; see 6).
- Write-time propagation at `ArtifactRejected`. It was weighed and rejected
  with the read-time decision: it needs a new transition and an inventory
  migration.
- Walking past the depth cap the index-child ingest already enforces.

  **Withdrawn 2026-10-13 — the second half of this bullet contradicted
  determination 2 and is gone.** It read "and any attempt to resolve the
  closure from manifest **bytes** per request rather than from the membership
  projection", then deferred to determination 2 for which of the two to read —
  but determination 2 settles it the other way and is marked settled by a dated
  decision. It is a leftover from the revision in which the projection was the
  plan. The authority is the bytes; see the clarification under determination 2.
- Any cache or memoisation of the resolution. If the single statement turns out
  to be too expensive, that is a measurement to report, not a cache to add.

## Acceptance

- A manifest with a `Rejected` layer answers `403 DENIED` naming the
  constituent's digest as `subject` plus its axis (corrected 2026-10-13, see
  §1); with a `ScanIndeterminate` layer, 503 without `Retry-After`; with a
  `Quarantined` layer, exactly what it answers today. One test per arm, plus the terminal
  **config** blob case — that is the shape the production population has.
- A pull-through manifest whose constituents are **not ingested** still answers
  200. Show it red when absence is treated as a hold; that inversion would
  break every cold pull-through and is the single most likely way to get this
  unit wrong.
- GET and HEAD agree on every arm.
- A write-granted principal gets the same answers as everyone else.
- Exactly one SQL statement per manifest read, asserted in the adapter test,
  and no `= ANY` over a hash or id list.
- The resolution is defined once and both the read path and 293's PUT path
  derive their class from 293's single predicate; a guard test pins the SQL's
  status list against that predicate over **every** `QuarantineStatus` variant,
  so adding a variant cannot leave the SQL silently narrower. Carry a
  counter-assertion that the guard still finds the real call sites — a rename
  must not make it vacuously green.
- ADR 0043 carries the amendment, including the Referrers asymmetry.
- Gate: the **unit gate** — `bash handover/gate-unit.sh -p <the crates this
  unit touches>`, judged by its output and never by the rc, with the full
  workspace suite, `cargo audit`, `cargo deny` and the attribution script left
  to the architect on the same tree (they outlast a worker's foreground tool
  window). Because the OCI ingest/serve composition changes, hand the human
  the **branch** for the compose E2E before any merge request.
