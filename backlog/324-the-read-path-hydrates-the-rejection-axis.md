# 324 — The read path hydrates the rejection axis, and the double stops serving a state production cannot

**Issue:** #342 · **Branch:** `agent/342-referenced-blob-deliverability`
**Predecessor to items 295, 322 and 323.** All three deliver an axis in a
refusal body; none of them can, because the axis is `None` on every read path.
This unit is what makes it available, once, for all five formats.

**Governing decisions:** ADR 0008 (the format crate reads a field, never a
stream — unchanged by this unit), ADR 0039 D5 (the precedent: a transient,
stream-derived field resolved for the read path at this same site), ADR 0039 D6
(the illegal state this unit's error branch finally detects correctly), ADR
0041 (the re-evaluation path that already hydrates this field, from the same
helper). No new decision.

## What is true today — measured 2026-10-13 at `dc0a1b9c`

`Artifact.rejection_reason` exists on the entity and is **unconditionally
`None`** everywhere a download handler sees it. Three independent legs, each
sufficient on its own:

1. **The projection mapper hardcodes it.**
   `crates/hort-adapters-postgres/src/mappers.rs:324` is the only
   `row → Artifact` mapper and reads `rejection_reason: None` as a constant,
   with the contract stated in its own comment: *"a fresh projection load
   always carries `None`, the same transient-hydration contract as
   `quarantine_deadline`."*
2. **The read-path hydration never sets it.**
   `ArtifactUseCase::hydrate_quarantine_deadline`
   (`crates/hort-app/src/use_cases/artifact_use_case.rs:721-745`) is the single
   read-path hydration point. Its `let … else` takes the early return for every
   status except `Quarantined`, setting only `quarantine_deadline` and
   `provenance_hold_indefinite` — so a `Rejected` artifact never reaches the
   stream-reading half.
3. **The codebase already says so, in prose, three times.**
   `crates/hort-app/src/use_cases/scan_history.rs:100-103` — *"the artifact
   entity loaded via `ArtifactRepository::find_by_id` does not carry it
   (rejection reason is not a stored column; it is reconstructed from the event
   log on demand)"*; `crates/hort-domain/src/entities/artifact.rs:1232-1240`;
   and `crates/hort-app/src/use_cases/curation_use_case.rs:2047-2053`, which
   notes a mock *"would hand back `None`"* where Postgres does.

The derivation already exists and is single-sourced:
`scan_history::last_rejection_reason` (`scan_history.rs:104`, `pub(crate)` in
`hort-app`). The OCI crate cannot call it and must not re-derive it —
`crates/hort-http-oci/src/quarantine.rs:75-79` states the boundary for the
sibling field: *"the format crate computes neither, and cannot — resolving a
`ScanPolicy` or reading the artifact's event stream from here would reach past
the use case (ADR 0008)."*

**And the test double serves the impossible state.**
`sample_artifact(QuarantineStatus::Rejected)` sets
`rejection_reason: Some(RejectionReason::Scanner)`
(`crates/hort-app/src/use_cases/test_support.rs:4014-4017`) and
`MockArtifactRepository` returns the stored entity verbatim. So a read-path
axis test written today **passes over a state no producer in the system can
write** — CLAUDE.md's *"A test double that round-trips must refuse what
production refuses"*. Without closing that, this unit's own tests would prove
nothing and the feature would ship broken behind a green gate.

## What to build

### 1. Hydrate the axis at the existing site

In `hydrate_quarantine_deadline`'s early-return branch, when the status is
`Rejected`, read the artifact's stream through the existing bounded reader and
set the field from the existing helper:

- `read_artifact_stream` (`crates/hort-app/src/use_cases/mod.rs:401-410`) — it
  goes through the one audited `STREAM_EVENT_CAP + 1` read, so
  **`capped_stream_reads` stays green with no new budget site.** Do not open a
  new read with its own budget.
- `scan_history::last_rejection_reason` for the derivation. One definition.

This site and no other: it is already where a transient stream-derived read-path
field is resolved (`provenance_hold_indefinite`, ADR 0039 D5), the handle is
already held, and ADR 0008 stays intact because the format crate still reads a
field.

### 2. The four decisions — decided; implement them, do not re-open them

**(D1) Rename the port handle; do not add a second field.**
`provenance_clearance_events: Option<Arc<dyn EventStore>>`
(`artifact_use_case.rs:109`) becomes **`artifact_stream_events`**, and
`with_provenance_clearance_events` becomes
**`with_artifact_stream_events`**. Two call sites —
`crates/hort-server/src/composition.rs:2870` and
`crates/hort-http-core/src/test_support.rs:2124` — plus the field's doc
comment, which must stop describing a provenance-only purpose. Reason: the
type is a plain `EventStore` and both consumers do the same thing — read this
artifact's own stream for a transient read-path field. A second field would
wire the identical handle twice and let the two drift.

**(D2) A failed read degrades; it never turns a refusal into a 500.** The unit
exists to stop a consumer guessing; answering a blocked pull with `500` would
replace one guessing game with another. So three outcomes, each distinguishable
**in the log**:

| Stream read | Result | Answer | Log |
|---|---|---|---|
| ok, `ArtifactRejected` found | axis known | 403 + axis | — |
| ok, **no** `ArtifactRejected` on the stream | ADR 0039 **D6 illegal state** | 403, no axis | `tracing::error!` |
| `Err` / over-cap `Invariant` | could not look | 403, no axis | `tracing::warn!` naming the read failure |

The middle row is the point: **today's `None` says nothing about the stream**,
so a D6 detector keyed on it would fire on every healthy rejection at `error`
level and bury the one real violation. Only after this hydration is that branch
a correct detector, and that is the argument for doing the hydration before
anything keys on the field.

**(D3) Hydrate for `Rejected` only.** The cost — one bounded read, on a path
that is already not serving bytes — belongs where the answer is needed. A
`Quarantined` read has no use for an axis, and `ScanIndeterminate` is not a
`RejectionReason` at all. The `None`/`Released` hot path pays nothing.

**(D4) The double must refuse what production refuses.** Clear
`rejection_reason` to `None` in `MockArtifactRepository`'s **read** methods, so
the double's `find_by_*` mirrors `mappers.rs:324`. Leave `sample_artifact`
populating it: the ADR 0041 re-evaluation fixtures legitimately need a seeded
reason and those paths hydrate from the stream before use. The nulling belongs
at the **repository boundary**, which is exactly where Postgres does it.

A read-path axis test must then seed the **stream**, via the helper that
already exists for it: `persisted_artifact_rejected`
(`test_support.rs:4179`). The wiring precedent is
`hort_http_core::test_support::with_provenance_hold_hydration`
(`test_support.rs:2112-2127`), which already attaches the event store to a mock
`AppContext` for this same class of read-path hydration; the OCI default
`harness()` wires neither projections nor event store, so the consumers must
opt in — which is the feature, not an obstacle.

**This change has a blast radius and that is its purpose.** Any existing test
that reads a populated `rejection_reason` back through the mock repository was
standing on the impossible state. Fix each one by seeding the stream, and
**list every test you touched with its resolution** — that list is the evidence
the hazard was real.

## Explicitly out of scope

- Any refusal-body or status-code change. 295/322/323 own the wire. This unit
  only makes the field true; nothing observable changes for a client.
- Denormalising `rejection_reason` onto the `artifacts` projection. That is a
  schema change with an expand/contract obligation, to buy a read this unit
  does on a path that is already refusing. If you think the read is too
  expensive, say so with a measurement rather than adding a column.
- The `ScanIndeterminate` status-code divergence (collector).
- `ArtifactUseCase`'s write paths and the ADR 0041 re-evaluation path, which
  already hydrate correctly.

## Acceptance

- A `Rejected` artifact loaded through `find_visible_by_path` carries its axis,
  derived from the stream via `last_rejection_reason`, for all five formats'
  load paths — asserted at the use-case level, over a **seeded stream**.
- The three D2 outcomes each have a test, including that the D6 `error!` fires
  **only** when the stream genuinely carries no `ArtifactRejected`.
- A store failure and an over-cap stream both yield an artifact with no axis
  and do not propagate an error to the caller.
- `MockArtifactRepository`'s reads return `rejection_reason: None`; a test pins
  that the double and `mappers.rs` agree, so the next person cannot
  reintroduce the divergence.
- Every test adjusted by D4 is listed in the report with its resolution.
- `capped_stream_reads` is green with **no new budget site** — the scan still
  finds exactly its audited reads.
- The `Quarantined` path is unchanged: `quarantine.rs`'s two `Retry-After`
  tests stay green unmodified, and `provenance_hold_indefinite` still hydrates.
- Gate: the **unit gate**, judged by output and never by rc. The double is
  shared, so name every crate whose tests touch it:
  `bash handover/gate-unit.sh -p hort-app -p hort-http-core -p hort-http-oci
  -p hort-http-cargo -p hort-http-npm -p hort-http-pypi -p hort-http-maven`.
  Measure that list rather than trusting it, and if a crate outside it has
  tests over the double, add it and say so.
- No composition change to any serve path, so this unit does not itself gate on
  the compose E2E — but it ships on the branch that does.
