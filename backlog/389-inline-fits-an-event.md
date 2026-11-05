# 389 — What stays inline fits in an event

**Issue:** #416 · **Branch:** `agent/416-inline-fits-an-event` · single item:
one measurement, two corrections.

**Governing decisions:** ADR 0007 (the cap as an enforced invariant) and ADR
0026 (the metadata strategy). **No ADR change** — the cap stays where it is and
the strategy is aligned to it. Whether the cap itself should rise stays with
#329, because that is a decision about the **product** of the event cap and the
stream cap, not about npm.

Decided with the maintainer: the coherence is established on the **split side**.
The event cap stays at 64 KB, the `pg_column_size` constraint is untouched, and
the product of the two caps does not grow.

## The property that should hold and does not

**What stays inline fits in an event.** Two places break it.

### Half 1 — the inline threshold is above the event cap

`crates/hort-app/src/use_cases/ingest_use_case.rs:1216` decides
`bytes.len() <= inline_threshold_bytes` → `MetadataDecision::Inline(payload_metadata)`,
so the **whole** payload rides the `ArtifactIngested` event. npm's threshold is
**256 KB** (`crates/hort-formats/src/npm.rs:616`); the event cap is **64 KB**
(`hort_domain::events::MAX_EVENT_JSON_BYTES`).

The band **64 KB – 256 KB** is therefore "small enough to inline" and "too big
for an event" at once. The 5 MB cap's own doc comment cites a measured npm
packument p99 of **~141 KB**, inside that band.

### Half 2 — the summary can exceed the cap too

After a split the **summary** rides the event (`NPM_SUMMARY_KEYS`,
`npm.rs:418`). A summary over 64 KB — dependency maps of roughly 1,500–2,000
entries — is refused anyway. Found in #411, where a test was green on exactly
that because the double did not enforce the cap.

**The summary's key list is not negotiable:** its doc comment names npm's
abbreviated-metadata document as the authority, and the consequence of serving
less — *"Serving less makes every version look dependency-free to a fresh,
non-lockfile install."* Trimming the summary is not an option.

## Step one: measure, do not build

Half 1 is **read off the path, not measured.** The first step is an ingest with
an inline payload between 64 KB and 256 KB:

- If it is refused with `exceeds 64 KB limit`, half 1 is a real defect with
  production effect and the item proceeds as written.
- If it does something else, **report what saves the path today** before
  changing anything. It is possible that a publish payload (one version block)
  sits far below the p99 of whole packuments, or that a path in between
  replaces the payload.

The result belongs in the report either way.

## What to build

The maintainer's framing, and it is the better one: **where the metadata lives
is transparent above the storage boundary — no use case cares.** That accessor
already exists and is documented with its three cases:
`ArtifactUseCase::load_full_metadata` (`crates/hort-app/src/use_cases/artifact_use_case.rs:639`)
— `metadata_blob = None` returns `row.metadata`, `Some(hash)` fetches from CAS
and deserialises, a malformed blob is an `AppError::Storage`.

So the correction is **not** "keep the payload small enough to stay inline". It
is:

1. **The spill decision is made where it can see the event cap.** An `Inline`
   decision must imply "this fits in an event", so the decision point reads the
   cap rather than a per-handler number that can disagree with it. A handler's
   `inline_threshold_bytes` then means what its comment claims — a read-path
   optimisation, a value that may be *lower* than the cap and never higher.
   One place holds that relation.
2. **The summary is not a special case.** After the change it is simply another
   payload that may be too large: same decision, same accessor, no second
   trigger for anyone to remember. That is what removes the #411 case rather
   than patching it.
3. **Every reader goes through the accessor.** One caller does not:
   `crates/hort-http-npm/src/index_source.rs:315-319` re-implements the
   accessor's `None` arm —

   ```rust
   let block = if row.metadata_blob.is_some() {
       ctx.artifact_use_case.load_full_metadata(row).await?
   } else {
       row.metadata.clone()
   };
   ```

   and buys nothing by it: that arm performs the same clone with no I/O. It is
   the only such branch on the read side; the census is part of this item, and
   if the scan finds others they are listed with their reason.

   Consider whether this is worth a guard in the family of the existing
   structural ones — no production reader outside the accessor branches on
   `metadata_blob`. Say whether you built one and why; a census that holds
   today and nothing keeping it is how it came back.
4. **Correct `docs/architecture/explanation/event-sourcing.md`**: its claim
   that per-format caps sit below the 64 KB event ceiling holds for the inline
   formats and not for this path.

Explicitly **not** in scope: raising the event cap, touching the
`pg_column_size` constraint, trimming the summary.

## Acceptance

1. The measurement is reported, with the observed behaviour in the 64–256 KB
   band.
2. An inline decision implies "fits in an event" — shown by a test that checks
   the boundary from both sides.
3. A summary above the cap yields a **successful** ingest rather than a
   refusal — shown with the #411 case.
4. For a spilled summary the read path serves the same fields as for an inline
   one — shown through the route an installer uses. The test must not know
   which side of the threshold it is on except by arranging the payload size.
5. No production reader outside `load_full_metadata` branches on
   `metadata_blob`; the npm read path goes through the accessor.
6. The cap still has one definition; no second number, including as a threshold
   literal, and the handler threshold/cap relation is stated in one place.
7. No test green today has to be rewritten; if one does, that is a finding.

## Read first

- `crates/hort-app/src/use_cases/ingest_use_case.rs:1195-1260` — the
  inline-vs-spill decision and the blob safety cap beside it.
- `crates/hort-formats/src/npm.rs:400-640` — the summary key list with its
  protocol authority, the threshold, and the 5 MB cap's doc comment with the
  corpus figures.
- `crates/hort-domain/src/ports/format_handler.rs:660-700` — the cap taxonomy
  table, which is where the clamp has to read correctly.
- `crates/hort-domain/src/events/domain_event.rs` —
  `MAX_EVENT_JSON_BYTES` and the two validation entry points from !829.
- `crates/hort-app/src/use_cases/artifact_use_case.rs:600-660` —
  `load_full_metadata`, the accessor the whole item is built around.
