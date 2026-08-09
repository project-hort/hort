# 0053 — Dependency ranges are resolved and pinned, never propagated

- **Status:** Accepted
- **Enforced by:** `FormatHandler::resolve_range_max`
  (`crates/hort-domain/src/ports/format_handler.rs`) — the single port method
  every range-bearing format implements, returning *one concrete version
  string* for a declared range. The `prefetch` leaf-ingest job's params carry
  `{ repository_id, package, version }` with `version` always concrete: a range
  never reaches an ingest. A format with no range concept (OCI tags are exact
  pointers) simply does not implement `VersionDiscovery`, so there is no
  fall-through path that ingests an unresolved range. The transitive cascade
  (`prefetch-dependencies`, `crates/hort-app/src/task_handlers/`) calls
  `resolve_range_max` per declared dependency and enqueues the resolved
  version — it never passes a range forward.
- **Relates:** [0006](0006-mandatory-upstream-verification.md) (every fetched
  artifact is checksum-verified — resolution is what gives that check a
  concrete target); [0007](0007-fail-closed-quarantine-release-predicate.md)
  (the resolved artifact enters quarantine and is scanned like any other, which
  is the point of resolving); [0015](0015-policy-field-enforcement.md)
  (prefetch-policy fields must be enforced or rejected, the discipline this
  stance is configured through); the prefetch-pipeline explanation
  (`docs/architecture/explanation/prefetch-pipeline.md`) holds the mechanism
  detail this ADR records the reasoning for; issue #140 (the decision), issue
  #139 (the CI-dogfooding thread it arose in).

## Context

A dependency range (`^1.2`, `~=2.0`, `[1.0,2.0)`) defers the choice of which
bytes get executed to resolution time. Whoever answers the registry at that
moment decides what a build consumes, and the same manifest yields different
artifacts on different days. That is precisely the property a supply-chain
attack needs, and it is invisible in review: the manifest looks unchanged.

Hort's whole model is built on the opposite premise. An artifact is ingested,
quarantined, scanned, and released as *a specific set of bytes with a specific
hash* (ADR 0006, ADR 0007). A range has no hash. It cannot be quarantined,
scanned, released, or attested — there is nothing concrete to gate.

This left an unrecorded question at the seam where hort meets ranges: the
prefetch cascade reads declared dependencies out of an ingested artifact's
manifest, and those declarations are ranges. Something must decide what a range
means. The mechanism has always existed (`resolve_range_max`); the *stance* it
implements was never written down, so nothing prevented a future change from
treating range propagation as a feature to be added.

## Decision

**D1 — A range is a hazard to be resolved, not a value to be carried.** Hort
resolves every declared range to a concrete version at the moment it acts on
it, and only ever ingests, stores, gates and serves concrete versions. No hort
subsystem passes a range onward as a range.

**D2 — Resolution picks the range maximum, at ingest time.** The chosen version
is the highest version satisfying the range among those upstream actually
offers, resolved when the parent artifact is ingested. It then enters the
normal lifecycle: quarantine, scan, release. A range that upstream cannot
satisfy is skipped and logged, never guessed at.

**D3 — Two complementary warming paths, deliberately not merged.** The
transitive cascade serves consumers who work with ranges: hort resolves them
and hands back what it has vetted. The batch prefetch of a complete lockfile
serves consumers who pin: every exact version they will actually build with is
warmed. These answer different questions and neither substitutes for the other.

**D4 — The cascade does not serve pinned consumption, and that is correct.**
A lockfile pins versions that are frequently *older* than the range maximum, so
cascade-warmed sets and lock-pinned sets legitimately differ. Consumers who pin
must warm from their lockfile. Concretely: `cargo install --locked <tool>` is
not, and should not become, something the cascade makes work — it additionally
needs `[build-dependencies]`, which the cascade excludes by design. Tool
bootstrapping belongs in a prebuilt image, not in the cascade.

**D5 — The stance is cross-format.** cargo `[dependencies]`, npm
`dependencies`, PyPI `requires-dist`, Maven compile scope: runtime declaration
classes only, resolved the same way. This is the same boundary the cascade
already enforces to keep dev/test closures out of the fan-out.

### Rejected alternatives that specifically must stay rejected

**Serving ranges through to clients unresolved.** Rejected: it makes hort a
transparent conduit for the exact deferral the registry exists to eliminate,
and produces artifacts no gate has seen.

**Resolving to the range *minimum*, or to a "known-good" pin.** Rejected: the
minimum is usually the most vulnerable member of the range, and a
hort-invented pin that upstream never intended is a silent behaviour change no
consumer can audit against their own manifest.

**Making the cascade satisfy `--locked` installs** (by also walking build
dependencies, or by warming a tool's bundled lockfile). Rejected: it inflates
the fan-out by the whole build-time closure of every dependency, to serve a
case the lockfile warm already serves precisely.

## Consequences

- Consumers who use ranges get reproducibility they did not ask for: what hort
  resolved, quarantined and released, rather than whatever upstream serves at
  build time.
- Consumers who pin are served by warming their lockfile, and should be told so
  — the cascade is not a substitute.
- A range that upstream cannot satisfy surfaces as a skipped dependency in the
  logs, not as a failed ingest of the parent.
- Adding a format with a range concept means implementing `resolve_range_max`;
  there is no opt-out that ingests ranges verbatim.
- Tooling that resolves its own dependency graph at install time (`cargo
  install`, `npx`, `pipx`) is outside this model and must be satisfied by
  prebuilt artifacts.
