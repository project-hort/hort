# 0056 — Resolved-component SBOMs are read from the stored payload, for hosted publishes

- **Status:** Accepted
- **Enforced by:** `FormatHandler::payload_sbom()` — a format that does not
  return a `&dyn PayloadSbom` never sees a payload byte, structurally rather
  than by convention (ADR 0005 capability groups); the literal
  `RepositoryType::Hosted` match in `ScanOrchestrationUseCase::try_extract_sbom`
  (pinned by test against a "simplification" into `RepositoryType::is_hosted`,
  which would silently widen the class to `Staging`); the
  `hort_sbom_resolution_total{format, result}` counter, whose `hosted_only`
  and `no_lockfile` arms make every non-resolved outcome observable rather
  than silent.
- **Supersedes:** —
- **Relates:** [0005](0005-wasm-format-modules-capability-taxonomy.md) (the
  capability-group shape this reuses),
  [0007](0007-fail-closed-quarantine-release-predicate.md) and
  [0041](0041-continuous-scan-policy-enforcement.md) (the release predicate and
  the `enforcement` vocabulary — **not restated here**),
  [0026](0026-streaming-metadata-projection.md) (the streaming contract the
  extraction honours), [0034](0034-public-dogfood-deployment.md) (the Class A
  posture this makes scannable), [0040](0040-osv-informational-negligible-lane.md)
  ("persist the fact, derive the interpretation"),
  [0053](0053-dependency-ranges-resolve-and-pin.md) (ranges are resolved and
  pinned, never propagated — this is the same principle applied to the SBOM).

## Context

A scan verdict is only as good as the SBOM it is computed over. For cargo, the
SBOM was derived from the metadata captured at ingest — the publish body's
declared dependency specs — and a declared spec is a **range**, not a version.
`serde = "1"` produced the component `pkg:cargo/serde@1`.

That is not a version anybody ever built against, and asking an advisory
database about it is worse than asking nothing: `1` matches every advisory ever
filed against the 1.x line, including the ones fixed years before the crate was
published. The result is a finding that is real-looking, unactionable, and —
under the default `enforcement: reject` — load-bearing.

**This is production evidence, not a hypothetical.** It is exactly why
scanning was switched off on `hort-crates` (`scanBackends: []`): the findings
the registry produced against hort's own crates were range-floor artefacts, and
a first-party publish being rejected by one is a release-chain outage caused by
the registry's own imprecision. Turning the scanner off removed the false
positives and the verdict together.

The dependency closure was in the payload the whole time. A published `.crate`
embeds a `Cargo.lock`, and every entry in it is an exact version with (from
lockfile v3) a registry checksum.

## Decision

**A format may derive its SBOM components from the artifact's stored payload at
scan time. Cargo does, for artifacts in a `Hosted` repository, by reading the
`Cargo.lock` the `.crate` embeds. Declared-dependency ranges never feed a
verdict again.**

### Scan time, from CAS — not ingest time

The payload is read out of CAS when the scan runs, not captured at publish.

- **The precedent is trivy, and it is exact.** The trivy backend already pulls
  artifact bytes from `StoragePort::get` and scans them. Reading a payload
  during a scan is the established shape here; what is new is that a *format
  handler* interprets those bytes into components, rather than an external
  scanner binary being handed the whole file.
- **Zero publish-path change.** `cargo publish` is untouched: no new field is
  captured, no new metadata is stored, no ingest-time work is added. The
  publish path cannot regress because it is not on the path.
- **Retroactive by construction.** The verdict is derived at scan time from
  bytes that are already in CAS, so a **rescan** of an artifact published
  months ago produces resolved components. There is no backfill job, no
  migration, and no "artifacts published before version X keep the old SBOM"
  cohort. This is [ADR 0040](0040-osv-informational-negligible-lane.md)'s
  "persist the fact, derive the interpretation" applied one level down: the
  payload is the persisted fact; the SBOM is an interpretation, so it improves
  retroactively when the interpreter does.

### `PayloadSbom` is a capability group, not a widened `extract_sbom`

Participation is declared, not defaulted:
`FormatHandler::payload_sbom() -> Option<&dyn PayloadSbom>`. This is the shape
[ADR 0005](0005-wasm-format-modules-capability-taxonomy.md) established for
`VersionDiscovery`, and it is chosen for the same reasons plus one new one:

- The orchestrator can ask whether a CAS read is warranted **before** paying
  for one. npm and PyPI scans do zero storage I/O; that is asserted by test,
  not assumed.
- Non-participation is **structural**. A defaulted no-op on a widened
  `extract_sbom` would be indistinguishable from "not implemented yet" — the
  precise failure ADR 0005 was extracted to close.
- `extract_sbom` is untouched, so the metadata-only branch that the index and
  publish paths depend on cannot regress.
- The three-way outcome (resolved / no lockfile / unusable lockfile) has
  somewhere to live. `extract_sbom`'s return type has no channel for it, and
  the distinction is only observable inside the handler — while `hort-formats`
  holds no `metrics` dependency by design, so the handler returns the outcome
  as **data** and the orchestration layer owns the counter.

The payload flows through `PayloadAccess::ReadStream` under
[ADR 0026](0026-streaming-metadata-projection.md): `StoragePort::get` yields an
`AsyncRead`, a `SyncIoBridge` adapts it to the sync `Read` the format port
speaks, and the extraction runs under `spawn_blocking`. No whole-body buffer,
and the archive walk runs under the audited `archive_bounds` caps.

### The lockfile is the crate's own re-resolve — the corrected D2 rationale

The design that opened this work assumed the embedded lockfile was the
*workspace* lockfile, and therefore over-broad: it would name sibling crates
and dependencies the published crate never touches, so a closure walk was
needed to cut it down to the crate's own subtree.

**That premise is false, and it was checked rather than argued.** Measured
against cargo 1.94: `cargo package` does **not** embed the workspace lockfile.
It re-resolves the packaged crate alone. Packaging one member of this
730-package workspace produced a **163-package** lockfile containing no
sibling-only crates. The embedded lockfile is already the crate's own resolve.

The walk is still there, and it earns its place on two different grounds:

1. **It strips the root's dev-dependency tree.** What the embedded lockfile
   *does* over-report is the packaged crate's own dev dependencies —
   **22 of 162** reachable packages in the measured case (`proptest`, `rand`,
   `rustix`, `tempfile`, `zerocopy` and their trees) were reachable only
   through dev edges. Nobody consuming the crate compiles those, so a finding
   against one is a false positive of a different flavour. The published
   crate's registry-index metadata carries `kind` per dependency, which seeds
   the walk with the non-dev first hop. Only the root needs this seed: cargo
   ignores the dev-dependencies of non-root packages, so everything below the
   first hop is already dev-free.
2. **It makes the published crate the subject.** A flat lockfile-to-components
   translation has no root; the walk starts at the crate's own `[[package]]`
   node, which is what makes the emitted BOM a statement *about this artifact*
   and lets the first-hop set mark direct dependencies.

Registry-sourced packages only (`registry+` / `sparse+`). Path- and
git-sourced entries have no registry coordinates to ask an advisory database
about, so they are skipped and **counted**
(`hort_sbom_components_skipped_total`) rather than silently dropped.

### The declared-deps branch is deleted, not demoted

A payload with **no** lockfile yields a **subject-only** BOM — the crate itself
is still scanned, and the dependency list is simply absent. It does **not**
fall back to declared dependency specs.

This is the load-bearing half of the decision. A fallback would reintroduce
range-floor components on exactly the artifacts where the resolved path could
not run, which is the least-observed and least-expected place for them to
appear. "No evidence" and "bad evidence" are not interchangeable, and only one
of them can produce a wrong verdict.

A lockfile that is *present but unusable* (unparseable, or not a
self-consistent resolve) is reported **distinctly** from one that is absent —
`unusable_lockfile` vs `no_lockfile`. The two have different causes and
different fixes, and collapsing them would hide a parser regression inside a
population of legitimately lockfile-less crates.

### Resolved components claim no licence

Every resolved component carries an **empty** licence list.

The lockfile records no licence, and the subject's own SPDX expression
describes the *published crate*, not the third-party code it resolves. Copying
the subject's licence onto each dependency would assert a licence fact that
nothing in the payload supports — and it would feed a `licensePolicy`
evaluation, so the fabricated fact would have gate power. An empty list is the
honest encoding of "the payload does not say".

Third-party licence facts are obtainable (each dependency's own registry
metadata carries one) but obtaining them means N registry lookups per scan for
a question this artifact's payload cannot answer. That is a separate decision,
not a silent default.

### The payload path is hosted-only

`RepositoryType::Hosted` — a literal match, and deliberately **not**
`RepositoryType::is_hosted()`, which also counts `Staging`.

A `.crate` does not contain its dependencies' code. An SBOM component derived
from its embedded lockfile is therefore a claim about code that is **not in the
artifact** — unlike a container image, where the scanner reads the vulnerable
bytes themselves. The weight of that claim depends on who wrote the lockfile:

- **Hosted** — the lockfile is the authenticated publisher's own build witness.
  They resolved those versions and they shipped them; holding their release
  gate to it is the point.
- **Proxy / virtual / staging** — the lockfile is the upstream author's
  dev-time resolve. A consumer of a library re-resolves and never runs it, so
  a stale upstream resolve would carry gate power (`crates-proxy` ships
  `enforcement: reject` with a multi-day window) over a crate every consumer
  would resolve safely. That is the same false-positive-with-gate-power class
  this decision exists to remove, reintroduced on the other face.

Those scans produce exactly the metadata-only SBOM they produced before, and
pay no CAS read.

### Fail-soft, because SBOM enrichment is not release authority

A CAS read failure, a handler error, and a panicked extraction task all degrade
to the pre-existing no-SBOM arm, with the metric saying which happened.
[ADR 0007](0007-fail-closed-quarantine-release-predicate.md)'s fail-closed rule
governs release *authority*; an SBOM is enrichment, and letting a storage
hiccup abort a scan would trade a thinner BOM for no scan at all.

### What this does not decide

The **enforcement vocabulary** — what a blocking verdict does to an artifact,
and how a change to that decision re-judges the existing population — is
[ADR 0007](0007-fail-closed-quarantine-release-predicate.md) (the `ScanRecorded`
release authority) and
[ADR 0041](0041-continuous-scan-policy-enforcement.md) (both directions of
re-derivation). This ADR decides what the verdict is computed *over*. The two
compose on `hort-crates` — resolved components under `enforcement: record` —
but neither implies the other, and a scope could adopt either alone.

## Explicitly out of scope / open

Two questions are **decided to be deferred**, which is not the same as decided.

**The proxy lockfile.** The payload path ships hosted-only because a proxied
library's embedded lockfile is the upstream author's dev-time resolve, which
consumers re-resolve and never run — findings from it would be hearsay with
gate power under the default `enforcement: reject`. The counter-nuance is real
and unresolved: a **binary** crate installed via `cargo install --locked` DOES
run the embedded resolve, so for bins the upstream signal is genuine, and
bin-vs-lib cannot be told apart cheaply at scan time. Open: whether proxy
lockfile scanning happens at all, and under what enforcement if it does.

**Staging.** The publisher-witness argument covers a staging upload exactly as
it covers a hosted one — a staging publish is still the authenticated
publisher's own build witness. But no staging-type repository exists in any
live configuration (gitops, compose, native-tests), so extending the gate now
would fix scan semantics for a dormant class nothing exercises. Include
`Staging` when a staging flow materializes, and revisit the `hosted_only`
metric label's name at that moment — it would then be a misnomer.

## Alternatives considered

- **Capture the lockfile at publish time.** Rejected: it changes the publish
  path (the one path a registry cannot afford to regress), it is not
  retroactive, and it stores a derived artefact alongside the payload that
  already contains it.
- **Widen `extract_sbom` to take a payload for every format.** Rejected: ~60
  call sites, a defaulted no-op for non-participating formats that is
  indistinguishable from "unimplemented", no channel for the three-way outcome,
  and a CAS read decided *after* it has been paid for. See the capability-group
  section above.
- **Keep the declared-deps branch as a fallback when no lockfile is present.**
  Rejected — see *deleted, not demoted*. It would reintroduce the exact
  false-positive class in the least-expected place.
- **Copy the subject's licence onto resolved components.** Rejected: a
  fabricated licence fact with `licensePolicy` gate power.
- **Resolve licences by querying each dependency's registry metadata.**
  Deferred, not rejected: N lookups per scan, and a separate decision about
  what the registry is willing to spend a scan on.
- **Apply the payload path everywhere and rely on `enforcement: record` to
  defuse proxy false positives.** Rejected: it makes the correctness of one
  decision depend on an operator setting a *different* policy field, and
  `crates-proxy` ships `reject`. A default that is only safe under a non-default
  configuration is not a safe default.

## Consequences

- Hosted cargo verdicts are computed over the versions that actually ship, so
  `hort-crates` can be scanned at all — which is what
  [ADR 0034](0034-public-dogfood-deployment.md)'s Class A amendment takes up.
- The improvement is retroactive: rescanning old publishes upgrades their SBOMs
  with no backfill.
- Cargo scans of hosted artifacts now perform one CAS read each. npm, PyPI and
  every proxied cargo scan perform none.
- A crate published without an embedded lockfile is scanned as its subject
  alone. That is visible (`no_lockfile`), not silent, and it is a weaker
  verdict rather than a wrong one.
- `hort-formats` gained a lockfile parser that must read v1 through v4
  (unknown top-level keys are tolerated by design) and terminate on dependency
  cycles.
- A future format that wants payload-derived components implements
  `PayloadSbom`; nothing else in the pipeline changes for it.

## References

- `crates/hort-formats/src/cargo/lockfile.rs` — the streaming extraction and
  the closure walk.
- `crates/hort-formats/src/cargo.rs` — the `PayloadSbom` implementation and the
  three-way outcome.
- `crates/hort-domain/src/ports/format_handler.rs` — the `PayloadSbom`
  capability group.
- `crates/hort-app/src/use_cases/scan_orchestration.rs`
  (`try_extract_sbom`) — the CAS read, the hosted-only gate, and the
  fail-soft arms.
- `docs/metrics-catalog.md` — `hort_sbom_resolution_total`,
  `hort_sbom_components_skipped_total`.
- `docs/architecture/explanation/scanning-pipeline.md` — where this sits in
  the pipeline.
