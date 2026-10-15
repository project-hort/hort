# 339 — The scan path sets the fact where the SBOM and the findings meet

**Issue:** #351 · **Branch:** `agent/351-a-finding-condemns-only-its-own-artifact`
**Governing decisions:** ADR 0056 (as amended 2026-10-15) · ADR 0040 · ADR 0008
(layering — the scanner adapters depend on `hort-domain` alone and cannot ask
`hort-formats`).

**Depends on item 338** (the field and its predicate). This item populates the
fact. It still changes no verdict — item 340 does that.

## 1. The fact is already in the types; it is discarded in transit

`Sbom` (`crates/hort-domain/src/types/sbom.rs:65`) separates the two things
this needs:

```rust
pub struct Sbom {
    pub subject: Option<SbomComponent>,
    pub components: Vec<SbomComponent>,
}
```

and `SbomComponent`'s own rustdoc names the join key used to match a finding
back to a component: *"`Finding.purl == SbomComponent.purl`"*.

So the subject is cleanly separated at the source. What loses the distinction
is the flattening for the scanner — `Sbom::all_components_owned()` returns
subject-first-then-components as one list, after which a returned finding is
only "about this artifact", never "about this component of this artifact".

## 2. Where to set it

**One site, in the application layer, where both halves are in scope.**
`ScanOrchestrationUseCase` (`crates/hort-app/src/use_cases/scan_orchestration.rs`)
holds the `sbom` and receives the findings from **both** producers:

- `:404` — `let advisory_findings: Vec<Finding> = match sbom.as_ref() { … }`
- `:511` — `let scan_result = scanner.scan(&target, sbom.as_ref()).await;`

Both flow back into the orchestrator with the same `sbom` still in hand, so a
single tagging step after they converge covers both producers. **Do not tag
inside the adapters**: there are two of them (`hort-adapters-scanner-osv`,
`hort-adapters-scanner-trivy`) plus the advisory path, and a rule typed once
per producer is the shape `https_rule_is_single_sourced` exists to prevent —
that rule had been re-typed five times before a sixth consumer turned out to
carry no copy at all.

Derive the fact by matching the finding's `purl` against `sbom.subject`'s
`purl`, using the join the type's rustdoc already declares. Where the SBOM has
**no** subject (`subject: None`), the relation cannot be established — set the
`not established` default from item 338 and do not guess.

## 3. The format question, and why it is not a list

Whether the artifact contains its closure is a property of the **format**, not
of the repository or of an operator setting:

- a cargo `.crate` is a source distribution — it contains only its own
  sources, never its dependencies' code;
- an OCI image contains its layers, so every component in its BOM *is* in the
  artifact.

Today the only `PayloadSbom` producers that walk a dependency closure are
cargo (the embedded `Cargo.lock`) and maven (the POM's `<dependencies>`) —
see the evidence table in `crates/hort-adapters-scanner-osv/src/lib.rs:228-234`.
Express the containment property where the handler already declares its
capabilities (ADR 0005 capability groups), so a new format answers it by
construction. **Do not add a hardcoded list of format keys** — a maintained
list ages silently and the missing entry is invisible until an artifact is
wrongly condemned.

## 4. Constraints

- `hort-app` requires **100 % coverage**. Mock the outbound ports; the
  existing doubles live in `crates/hort-app/src/use_cases/test_support.rs`.
- Note the round-trip contract on `MockEventStore` in that file: a double that
  serves `read_stream` from what it accepted calls `validate()` on append. Do
  not seed an event the production adapter would reject.
- No file under `migrations/` changes in this item.
- No issue, MR or backlog reference in any code comment.

## Acceptance

- Every `Finding` leaving the orchestrator carries the fact set, from both the
  advisory path and the scanner path — pinned by a test per path.
- A finding whose `purl` equals the SBOM subject's `purl` is tagged as the
  subject; one that matches a non-subject component is tagged as not
  contained, for a format that does not contain its closure.
- An SBOM with `subject: None` yields the `not established` default, pinned.
- Still **no verdict change**: a test asserts the same artifacts are
  released/rejected before and after this item. That assertion is what makes
  item 340 reviewable on its own.

## 5. The `not established` case must be visible, not absorbed

**Measured 2026-10-15, and it changes what this item owes.** Every production
SBOM builder sets a subject — cargo (`crates/hort-formats/src/cargo.rs:566,599,754,768`),
maven (`maven/mod.rs:573,649,766`), pypi (`pypi.rs:747,776`), npm. The only
`subject: None` sites in the tree are in `crates/hort-domain/src/types/sbom.rs`
at 194/213/230, and that file's `#[cfg(test)]` begins at line 179 — they are
test fixtures.

The reason is a rule the codebase already states, in `npm.rs:666-671`:

> *"Build the subject regardless of whether the manifest is parseable — for an
> npm artifact ingested under known `coords.name`/`coords.version`, the subject
> is well-defined even when format_metadata is null."*

The subject is derived from the artifact's **coordinates**, which always exist
— not from the payload, which may not parse. So for a scan running after this
item, `not established` should be **structurally unreachable**: it is a
migration artefact for rows written before item 338, shrinking toward zero as
rows are rescanned, not a resting state of the design.

That is exactly what makes item 338's condemning default safe — and it is only
safe while it stays true. A fail-closed default is defensible when it is rare,
recognisable after persistence, and correctable; it is dangerous when it
quietly becomes the normal path. The `Unassessed → Critical` severity floor in
`crates/hort-adapters-scanner-osv/src/parse.rs:375` is the cautionary case in
this same codebase: it is the *common* path for its backend, it is not
recoverable after persistence (`severity_basis` reaches neither
`ScanFindingRecord` nor the table), and in a single-backend policy nothing can
out-inform it.

**So this item owes an observable.** Emit a counter over the relation the
tagging step assigns, with a closed taxonomy matching item 338's enum and a
`format` label — the shape `hort_sbom_resolution_total{format, result}`
already uses (`docs/metrics-catalog.md:2781`). Add its row to the catalog,
naming the domain enum as the source of truth for the label values, exactly as
that entry does.

A non-zero `not established` count on **new** scans is a defect in this item —
a format whose subject is not being derived — and must be read that way. It is
not something the default absorbs silently.

## Acceptance (addition)

- The relation counter exists, is emitted on every tagged finding, and carries
  a `docs/metrics-catalog.md` row naming the domain enum as source of truth.
- A test asserts that a scan over each production SBOM shape yields **no**
  `not established` findings — the assertion that keeps §5's claim true rather
  than assumed.

## 6. A finding whose purl matches nothing in the BOM

Unit 338's report raised this and it is a real gap in §2 as written: matching
the finding's `purl` against `sbom.subject` answers the subject case, but says
nothing about a finding whose purl matches **neither** the subject nor any
listed component. Both readings are expressible with 338's four variants and
they produce **opposite verdicts** after item 340, so this item must decide it
rather than leave it to the implementer.

**It is decided by which producer emitted the finding, and the two are not
alike:**

- **A payload-scanning backend.** The Trivy adapter *"materialises the
  artifact's bytes"* from `StoragePort`
  (`crates/hort-adapters-scanner-trivy/src/lib.rs:5,76`) and scans what it
  unpacked. Anything it reports was therefore physically present in the
  artifact. Such a finding is `Subject` when it matches the subject and
  **`Contained`** otherwise — including when the BOM never listed it, which is
  a normal outcome rather than an anomaly, because the BOM and the
  materialised tree are derived differently.
- **An SBOM-driven backend.** The osv adapter consumes only the SBOM —
  *"this workspace does NOT pull bytes from `StoragePort` … the raw artifact
  payload is irrelevant"* (`crates/hort-adapters-scanner-osv/src/workspace.rs:7-10`)
  — and the advisory-enrichment path is likewise derived from the BOM. For
  these the BOM is the whole input, so a purl matching nothing in it is not a
  package discovered elsewhere; it is a join that failed. Tag it
  **`NotEstablished`** and let the §5 counter show it, because a non-zero
  count here means the join is broken, not that the artifact is odd.

Deriving this from **how the producer obtained its findings**, rather than
from a per-backend name list, is what keeps it correct when a backend is
added: the question "did this come from the payload or from the BOM?" has an
answer for any future scanner, while a name list silently omits it.

## Acceptance (addition)

- A payload-scanned finding that matches no BOM component is `Contained`, not
  `NotEstablished` — pinned by a test, because the opposite reading would
  silently disarm every Trivy finding the BOM happens not to list.
- An SBOM-driven finding that matches no BOM component is `NotEstablished`
  and increments the §5 counter — pinned by a test.
