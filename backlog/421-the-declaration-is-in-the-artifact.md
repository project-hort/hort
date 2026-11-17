# 421 — The dependency declaration is in the artifact, so read the artifact

**Issue:** #424 · **Branch:** `agent/424-the-declaration-is-in-the-artifact` ·
the only item. **No ADR change** — this adopts a capability group ADR 0005
already defines, for the one format that does not declare it.

**Governing decisions:** ADR 0005 (format handlers declare capability groups;
structural non-participation over defaulted no-ops), ADR 0026 (the metadata
and payload methods' streaming contract), ADR 0006 (upstream verification —
why the artifact's own bytes outrank an upstream assertion about them),
ADR 0007 (fail-closed release authority — which is why `SbomResolution` may
not overstate what was derived).

## The property

**PyPI is the one proxied format whose dependency declaration lives inside
the artifact and which does not declare `PayloadSbom`.**

`CargoFormatHandler` (`crates/hort-formats/src/cargo.rs:650`) and
`MavenFormatHandler` (`crates/hort-formats/src/maven/mod.rs:854`) implement
the group and read `Cargo.lock` / the POM out of the payload.
`PyPiFormatHandler` does not, and `pypi.rs:931-936` shows the consequence in
its own signature: `extract_sbom(&self, coords, format_metadata,
_payload: PayloadAccess<'_>)` — the payload parameter is **discarded**.

**And it must be discarded, because there is nothing in it.** The scan
orchestrator branches on the declaration before it opens any I/O
(`crates/hort-app/src/use_cases/scan_orchestration.rs:1594-1611`): a handler
with `payload_sbom() == Some(_)` gets its bytes streamed out of CAS; a
handler without one is called with **`PayloadAccess::Bytes(&[])`** — an empty
slice, and the comment there says so: *"the empty-payload call the handlers
have always ignored."* So PyPI cannot read its own distribution today, by
construction rather than by omission, and declaring the group is the only way
in.

## Why that is the whole defect

A proxied PyPI distribution's dependencies never reach the scan subject. Both
upstream ingest sites write exactly `{"source": "pypi_upstream_pull",
"upstream_url": …}` — `crates/hort-http-pypi/src/upstream_pull.rs:446`
(leader) and `:547` (cross-repo follower) — so `format_metadata` carries no
`requires_dist`, and the metadata-only path is all PyPI has.

**The hosted path is already fine, and that bounds this item.** The
direct-upload publish handler writes `payload_metadata: {"pkg_info":
metadata_fields}` (`crates/hort-http-pypi/src/lib.rs:443`) with the twine
multipart harvest's `requires_dist` inside, pinned by a test at `:4213-4226`;
`pypi_requires_dist` (`crates/hort-formats/src/pypi.rs:1744-1753`) reads that
shape. **#373 (`b7668bae`) is the commit that taught it that shape**, and it
is on `develop` — so the sibling finding this one was once contrasted against
("hosted: stored but never read") is closed. Do not re-fix it.

**hort already extracts the declaration — for another purpose.** The ingest
hook pulls every newly-ingested wheel's `<dist-info>/METADATA` into CAS and
records a `content_references` row of kind `wheel_metadata`, so the simple
index can advertise PEP 658 to pip
(`crates/hort-app/src/task_handlers/wheel_metadata_backfill.rs:1-19` describes
hook and retrofit). So the authoritative bytes are already in hand and
digest-verified; only the SBOM path does not read them.

## What to build

**`PyPiFormatHandler` declares `PayloadSbom` and derives its components from
the artifact's own bytes** — `<dist-info>/METADATA` in a wheel, `PKG-INFO` in
an sdist.

- `payload_sbom()` returns `Some(self)`; `extract_sbom_from_payload` is the
  one method.
- Reuse what exists rather than re-deriving it: `extract_wheel_metadata_bytes`
  already locates and caps a wheel's `METADATA` (1 MiB, enforced inside), and
  `parse_requires_dist_into_spec` (`pypi.rs:1580`) and
  `parse_pep_508_requirement` already turn a requirement line into
  `(name, Option<version>)`.
- **`format_metadata` stays a consulted input, not a discarded one.** The port
  says so and cargo is the precedent (it reads the registry index's `deps` to
  learn dev-only edges). Keep the hosted `pkg_info` path working; the
  artifact's bytes take precedence where both exist, because the bytes are
  verified (ADR 0006) and the metadata is an assertion about them.
- **`payload_contains_components` is already correct and stays untouched.**
  PyPI overrides it at `pypi.rs:744` — it is one of the four formats whose BOM
  is a declaration rather than a shipped closure.

### Corrected 2026-11-09 by an outside review of this approach

**Three of five questions came back needing work, and one of them is a
fail-open against ADR 0007 that this item itself specified.** The approach is
unchanged — PyPI declaring the group is the only way to its own bytes, and the
upstream-JSON detour is correctly rejected — but the contract below is
rewritten. What follows replaces the earlier prescription, it does not
annotate it.

#### The fail-open, which is this item's primary hazard

The earlier wording said an unreadable payload degrades to a **subject-only
BOM with `UnusableLockfile`**. On the payload branch that silently grants a
**clean scan** under an SBOM-only policy:

`extract_sbom_from_stored_payload` turns **any** `Some(sbom)` into
`SbomExtraction::Extracted` regardless of its resolution
(`crates/hort-app/src/use_cases/scan_orchestration.rs:1695-1724`), so
`absence()` is `None` (`:394-416`). The OSV backend abstains only on
`sbom: None`; over a `Some(subject-only)` it **executes** and returns
`Analysed(findings)` (`crates/hort-adapters-scanner-osv/src/lib.rs:472-527`).
An empty finding set becomes `ScanRunOutcome::Completed`
(`scan_orchestration.rs:765-769,1077-1103,1207-1213`) and is recorded as a
clean scan (`:1334-1381`) — while the artifact's dependency declaration was
never read.

**So: an unreadable declaration stays a gating absence for SBOM-only
authority, even when the subject is retained.** Either keep the subject and
make the absence explicit, or use the existing no-BOM/error path, whose
fail-closed behaviour is already pinned
(`crates/hort-app/src/use_cases/scan_orchestration_tests.rs:3591-3621`). The
test that proves it is a **scan-disposition** test, not a handler-result
test.

#### Three more effects of changing branch, each to be stated and asserted

1. **An operator-visible metric changes meaning for every PyPI scan**,
   including rescans of existing hosted artifacts:
   `hort_sbom_resolution_total{format="pypi"}` moves from `not_applicable`
   (`scan_orchestration.rs:1601-1605`) to the extraction's resolution
   (`:1710`), and the catalog's own statement that `not_applicable` covers
   PyPI stops being true (`crates/hort-app/src/metrics.rs:3288-3325`).
   `payload_unavailable` appears in **both** counters where the metadata
   branch had no such outcome (`:1651-1662,1685-1725`). The catalog's
   assertion that every non-`resolved` result means a subject-only BOM is
   falsified by a declaration result and must be rewritten in the same
   change.
2. **CAS unavailability becomes a release-authority state, not a metric.** It
   yields `SbomAbsence::Unavailable` (`:1651-1662`); for an SBOM-only backend
   returning `NotApplicable` the orchestrator counts a backend failure
   (`:803-835`), retries (`:1077-1103,1509-1519`), and at exhaustion holds a
   quarantined artifact or records `ScanIndeterminate` (`:1433-1508`). A
   payload-reading sibling that still supplies a verdict completes the run
   (`:765-769`). The metadata branch had no CAS-unavailable outcome at all.
   Describe **both** policy configurations and assert their dispositions.
3. **`ComponentRelation` moves release authority.** PyPI returns
   `payload_contains_components() == false` (`crates/hort-formats/src/pypi.rs:740-746`),
   so a joined dependency finding is `NotContained` and an unjoined one is
   `NotEstablished` (`scan_orchestration.rs:1875-1897`) —
   `Finding::may_condemn_artifact` **denies** authority to the first and
   **grants** it to the second (`crates/hort-domain/src/types/finding.rs:844-854`).
   Newly discovered proxied dependencies therefore change which findings can
   condemn. The components also reach advisory enrichment (`:657-679`) and the
   persisted SBOM projection (`:1201-1213,1363-1377`). State that these are
   deliberate, and assert finding disposition for a matching and a
   non-matching PURL. The Boolean override alone does not explain the change.

#### A hard input cap is required and cannot be inherited

The 1 MiB cap is on the **extracted METADATA member** (`pypi.rs:1008-1015`),
not on the archive. On the exact `PayloadAccess::ReadStream` the orchestrator
supplies, `extract_wheel_metadata_bytes` calls an **unbounded `read_to_end`
before opening the ZIP** (`:1033-1060`). PyPI's other artifact reader caps
compressed input at 32 MiB before parsing (`:1251-1282`) — that is the shape
to follow. Specify a hard cap on the streamed distribution, or a bounded
seekable spool, and **test a stream above it.** An acceptance line saying
"the input cap is set" is not satisfied by the member cap.

#### `Requires-Dist` may be declared dynamic, and absence then means unknown

The earlier wording treated a missing `Requires-Dist` as "no dependencies".
[PEP 643](https://peps.python.org/pep-0643/) permits the field to be
**`Dynamic: Requires-Dist`** in metadata 2.2+, and says a dynamic field's
sdist value is not canonical — so an absent dynamic field is **unknown**, not
an empty dependency set. The current header reader scans only
`Requires-Dist` and stops at the first blank line; it inspects neither
`Metadata-Version` nor `Dynamic` (`pypi.rs:1487-1521`), and the sdist path
already warns that `PKG-INFO` frequently carries no declaration
(`:1232-1238,1302-1309`). Distinguish the three cases — dynamic, pre-2.2, and
a genuinely static empty declaration — and assert their scan **and** release
dispositions. A subject-only BOM must not silently stand for complete
dependency assessment under an SBOM-only policy.

### `SbomResolution`: PyPI is never `Resolved`, and the earlier rule was wrong
### — this is the item's one real design decision

`SbomResolution::Resolved`'s own doc is *"every component … carries an exact
version"* (`crates/hort-domain/src/ports/format_handler.rs:512-524`), and
`Requires-Dist` carries PEP 508 **specifiers**: `requests (==2.31.0)` is
exact, `click (>=8.0)` is not. `parse_pep_508_requirement` already returns
`Option<version>` and emits a purl without `@version` when there is none, so
an inexact component is an established shape here — what is missing is a way
to *say* so.

The three existing values are each a lie for this case: `Resolved` overstates
(and ADR 0007 is why overstating is the dangerous direction), `NoLockfile`
says *"carried no resolved-dependency document"* which would be paired with a
non-empty component list, and `UnusableLockfile` says the document failed.

**So: a fourth variant**, named for the fact rather than the format — the
payload carried a dependency **declaration**, components are named, versions
are constraints. Its cost is bounded and must be paid in full: one more
`SbomResolutionResult` metric label value (a fixed value, no cardinality
hazard), and the no-wildcard matches over the enum updated so a future
variant still cannot slip through.

**The earlier rule — all-`==` ⇒ `Resolved` — is false, and the review showed
why.** `Resolved` promises a resolved-dependency document *and* a successful
closure walk. PyPI reads only the **direct** `Requires-Dist` lines and strips
environment markers (`pypi.rs:960-979,1643-1649`); it never resolves a
transitive closure. So a fully pinned wheel is still not a resolve, and
**`Resolved` is never the right value for PyPI** — the declaration variant is
the value for every successful PyPI extraction, pinned requirements included,
unless a separate closure resolve actually happens.

**And a second defect in the same area, to fix rather than inherit:** the
parser promotes the **first `==` clause** without proving the whole specifier
is one exact version (`pypi.rs:1699-1716`), so `==1.*` and `==1.0,!=1.0` are
labelled exact and reach a versioned PURL. Validate that a specifier is a
single exact version before putting it in one.

**Maven is a pre-existing overstatement, not a precedent.** It reports
`Resolved` (`crates/hort-formats/src/maven/mod.rs:889-896,1109-1116`) while
`maven_sbom_components` copies only direct `DependencySpec`s (`:936-957`) and
the POM reader cannot reach parent or imported-BOM contents, counting those
as skips (`crates/hort-formats/src/maven/pom.rs:7-45`). Its emitted versions
are usually literal because it filters ranges, but no built closure is
established. **Name that mismatch in the report; do not broaden it** — and do
not change Maven here.

### The three honest outcomes besides that

- an sdist whose `PKG-INFO` carries a **genuinely static** empty declaration
  → subject-only BOM, `NoLockfile`;
- an **unknown** declaration — `Dynamic: Requires-Dist`, or metadata older
  than 2.2 where absence proves nothing — → **a gating absence**, not a clean
  subject-only pass (see the fail-open above);
- a payload that is not a readable wheel ZIP / sdist archive, or one over the
  archive cap → **a gating absence** on the same grounds;
- `Err` stays reserved for a handler that can produce no BOM at all, per the
  port's contract — but fail-soft must not be implemented as a *clean* scan.
  Fail-soft about the **BOM** is not fail-soft about the **verdict**.

### Two reader branches lose their last excuse

`pypi_requires_dist` accepts three shapes; after this item the `pkg_info` one
has a producer and the artifact path covers the rest. `info.requires_dist` and
top-level `requires_dist` have **no producer anywhere in the workspace** —
measured 2026-11-09. Decide them: removed, or kept as a deliberate tolerance
for a mirror shape, with the reason at the site. Do not leave them
undiscussed; an accepted-but-unproduced branch is the shape this very ticket
is about.

## Explicitly not in scope

No new field in `payload_metadata` on the upstream path, and no change to the
file-scoped version-JSON projection (`PypiVersionFileInfo`,
`crates/hort-formats/src/pypi/projection.rs:287-302`, carries `urls[i]`
fields while `info.requires_dist` is release-scoped) — that detour is what
this item replaces, and it would bind the SBOM to upstream's word about bytes
we can read ourselves. No change to `extract_wheel_metadata_bytes`, the PEP
658 advertisement, or the `wheel_metadata` retrofit. No other format: cargo
and maven declare the group already; npm was not examined here.

## Acceptance

- `PyPiFormatHandler::payload_sbom()` is `Some`, and
  `extract_sbom_from_payload` builds the component list from the artifact's
  own `Requires-Dist`. One test per shape: wheel (`<dist-info>/METADATA`) and
  sdist (`PKG-INFO`).
- **The reported defect, as a test:** a proxied wheel whose `format_metadata`
  is exactly `{"source": "pypi_upstream_pull", "upstream_url": …}` yields a
  component list.
- The new `SbomResolution` variant exists with its metric label value, the
  metric catalog's non-`resolved`/subject-only semantics are rewritten in the
  same change, and **a fully pinned wheel reports the declaration variant,
  not `Resolved`** — asserted, because the opposite was this item's own
  earlier rule.
- A specifier that is not a single exact version (`==1.*`, `==1.0,!=1.0`)
  does **not** reach a versioned PURL — one test per shape.
- **An unreadable or unknown declaration does not produce a clean scan.**
  The decisive test is a **scan disposition** under an SBOM-only policy, not
  a handler-result assertion: the artifact must not be recorded clean.
- The three branch effects are asserted: the resolution metric's new values
  for PyPI, the CAS-unavailable disposition under both policy
  configurations, and finding disposition for a matching and a non-matching
  PURL given `payload_contains_components() == false`.
- A streamed distribution above the archive cap is refused without an
  unbounded read — tested with a stream over the cap.
- An sdist with no `Requires-Dist` → subject-only BOM + `NoLockfile`. A
  corrupt wheel ZIP → subject-only BOM + `UnusableLockfile`. Neither returns
  `Err`.
- The hosted path loses nothing: a direct-upload artifact carrying
  `pkg_info.requires_dist` still yields the same list, asserted — and where
  both the bytes and the metadata are present, the bytes win, asserted.
- The extraction streams (ADR 0026) and the **archive** input cap is set and
  tested — the existing 1 MiB METADATA-member cap does not satisfy this.
- The two producerless reader branches are decided, with the reason recorded
  at the site.
- Gate green; `hort-domain`/`hort-app` add no uncovered lines; no ticket
  numbers in code comments.
