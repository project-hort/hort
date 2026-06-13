# Index Construction

Every package format that resolves versions does it against an index
document: npm's packument JSON, PyPI's simple index (PEP 503 HTML and
PEP 691 JSON), cargo's sparse-index NDJSON. The index is where a
client decides *which* version to download — which makes it a
security surface in its own right. An index that advertises a version
the download path refuses is worse than useless: the client resolves
to the advertised version, the download 503s, and the build breaks on
an artifact the registry already knew was bad. Worse, the advertised
entry leaks the existence and metadata of a quarantined or rejected
artifact that the rest of the system is deliberately withholding.

Hort therefore builds every index document through one shared
pipeline rather than per-format ad-hoc code. The uniform pipeline is
what guarantees that quarantine-aware filtering applies identically
to every format and every repository type — a format handler cannot
accidentally advertise a non-servable version, because the filtering
happens in a layer the format-specific code never bypasses. Before
this shape existed, hosted and proxy serve paths were independent
implementations per format, and the hosted paths simply lacked the
filter the proxy paths had: a hosted artifact rejected by a re-scan
kept appearing in the index while its download 503ed. Collapsing the
two paths into one pipeline closed that asymmetry structurally rather
than by remembering to wire the filter in six places.

## Source → Filter → Builder

The pipeline has three stages with sharply separated knowledge:

- A **source** produces the version set. Each format's HTTP crate
  supplies two implementations of its crate-private `IndexSource`
  trait: a hosted source that reads the local artifact projection
  through `ArtifactUseCase` (e.g. `HostedNpmSource` in
  `crates/hort-http-npm/src/index_source.rs`), and a proxy source
  that fetches and parses the upstream document, hydrating each
  upstream version with hort's known quarantine status via
  `ArtifactUseCase::package_version_status` (e.g. `ProxyNpmSource`
  in the same module). Sources know where versions come from; they
  apply no policy.
- A **filter pipeline** drops entries. Filters implement
  `IndexFilter` (`crates/hort-app/src/use_cases/index_serve.rs`) and
  operate only on the spine fields described below — they are pure
  transforms with no I/O, and the per-format payload is opaque to
  them. Filters know policy; they know nothing about wire shapes.
- A **builder** emits the bytes. Each format ships an `IndexBuilder`
  implementation that turns the post-filter entries into the
  format's wire document. Builders format; they never re-filter.

The type all three stages share is `VersionEntry`
(`crates/hort-app/src/use_cases/index_serve.rs`): a `version` string,
a `status: Option<QuarantineStatus>`, and a per-format `payload`. The
`Option` is load-bearing. `None` means hort has no projection row for
this version at all — the "never ingested" tier that only proxy
sources produce, because an upstream catalog naturally advertises
versions hort has never pulled. Hosted sources never produce `None`;
every hosted entry comes from a projection row with an explicit
status. The payload is a closed sum (`PerVersionPayload` with `Npm`,
`Pypi`, and `Cargo` variants) so each builder gets typed access to
exactly its own variant's fields — no downcasting, and a builder
structurally cannot read another format's data.

The trait definitions and spine types live in `hort-app` because the
dependency edge runs `hort-formats → hort-app`; the
`hort_formats::index_serve` module
(`crates/hort-formats/src/index_serve.rs`) is a re-export façade that
gives format-crate consumers a single import path. The sources stay
in the per-format HTTP crates — which, like all inbound-HTTP format
crates, carry no adapter dependencies
([ADR 0008](../../adr/0008-per-format-adapter-free-http-crates.md)) —
and reach data only through use cases.

## The filter pipeline and its order

Each per-format serve handler composes the same two filters, in the
same order (`crates/hort-http-npm/src/serve.rs`,
`crates/hort-http-pypi/src/serve.rs`,
`crates/hort-http-cargo/src/serve.rs`):

```rust
let filters: Vec<Arc<dyn IndexFilter>> = vec![
    Arc::new(NonServableStatusFilter),
    Arc::new(IndexModeFilter::new(repo.index_mode)),
];
```

`NonServableStatusFilter`
(`crates/hort-app/src/use_cases/index_filters.rs`) is universal: it
drops every entry whose status is `Quarantined`, `Rejected`, or
`ScanIndeterminate`, unconditionally — regardless of repository
type, regardless of index mode. This is the filter that makes a
re-scan verdict visible at the resolution layer: when a scan
transitions a long-served hosted artifact to `Rejected`, the version
disappears from the index on the next serve, on every format. An
end-to-end test pins this per format
(`crates/hort-server/tests/rescan_rejection_visibility.rs`).

`IndexModeFilter` then makes the mode-specific decision about the
"never ingested" tier — and only that tier (its truth table is in the
`index_filters` module documentation).

The ordering convention is `[universal, mode-specific,
operator-defined]`, and the universal filter holding the first slot
is what makes the no-data-leak property independent of everything
behind it. Because `NonServableStatusFilter` is unconditional and
runs ahead of any mode- or operator-shaped filtering, no downstream
filter — present or future — ever sees a non-servable entry, so no
mode value and no future operator-exclusion filter can re-admit one.
With today's two filters the result happens to be order-independent
(both drop known-non-servable entries; only the never-ingested column
differs between modes, and the universal filter never touches it),
but the slot convention is what every appended filter inherits, and
it is the premise the cross-opt-in safety analysis below rests on.

## IndexMode: a deliberately bounded knob

`IndexMode` (`crates/hort-domain/src/entities/repository.rs`) is the
per-repository choice of how much of the upstream catalog the served
index exposes:

- **`ReleasedOnly`** (the default) is build-safe by construction.
  The served set is hort-held versions in a servable status
  (`Released`, or `None` for permissive-mode repositories). A
  never-ingested upstream version is not advertised, so a range
  resolution, a bare install, or a `latest` lookup can never land on
  a version whose download would 503. New versions enter the index
  via explicit pull or prefetch.
- **`IncludePending`** trades that guarantee for discoverability.
  The served set is upstream's full catalog minus versions hort
  *knows* are non-servable. A never-ingested version stays
  advertised; resolving to it triggers a pull, quarantine, and a 503
  until the quarantine clears.

The bounded part is what the mode can *add*: the additive set under
`IncludePending` is exactly the `Unknown` tier — upstream-advertised,
never-ingested versions — and never `Quarantined`, `Rejected`, or
`ScanIndeterminate` ones, because the universal filter has already
removed those before the mode filter runs. That bound is why the
mode's interactions with the other release-gate-influencing opt-ins
(`trust_upstream_publish_time`, `scan_backends: []`) are documented
as benign in the cross-opt-in interaction matrix
([ADR 0016](../../adr/0016-cross-opt-in-interaction-matrix.md)): the
versions the mode adds were never gate-eligible to begin with, and
the verdicts the gate produces
([ADR 0007](../../adr/0007-fail-closed-quarantine-release-predicate.md))
are enforced upstream of the mode's decision.

On hosted repositories the two modes collapse: every hosted entry
has a known status, the `Unknown` tier is empty, and both modes
reduce to "serve `{Released, None}`" — which the universal filter
already produced. The knob differentiates behaviour only where an
upstream catalog exists to differ over.

## Per-format builders

Builders receive a `BuildContext` (package name, base URL, the
repository's `IndexMode`, and a per-format `VersionOrdering`) plus
the post-filter entries, and return wire bytes:

- **`NpmIndexBuilder`** (`crates/hort-formats/src/npm/index.rs`)
  emits the packument JSON. `dist-tags.latest` points at the maximum
  of the *served* set under the ordering — computed after filtering,
  so a quarantined newest version can never be the advertised
  `latest`. An empty served set yields empty `versions{}` and no
  `dist-tags` block at all, never a dangling pointer.
- **`PypiHtmlIndexBuilder`** and **`PypiJsonIndexBuilder`**
  (`crates/hort-formats/src/pypi/index.rs`) emit PEP 503 HTML and
  PEP 691 JSON from the same payload; the serve handler picks one
  from the request's `Accept` header. PyPI's structural quirk — one
  version is a *list* of files (sdist plus wheels) — lives entirely
  in `PypiVersionPayload`, so the spine and filters stay
  version-shaped while the builder fans out one anchor or `files[]`
  row per file, including the PEP 658 wheel-metadata hash when one
  is held.
- **`CargoIndexBuilder`** (`crates/hort-formats/src/cargo/index.rs`)
  emits one NDJSON line per entry. Cargo's `yanked` flag is
  deliberately orthogonal to quarantine: yanked versions pass
  through the filter pipeline and appear in the served set with
  `yanked: true`, because cargo clients treat yanked-but-present
  differently from absent — that distinction is the protocol's, not
  hort's, to erase.

The orderings (`NpmSemverOrdering`, `Pep440Ordering`,
`CargoSemverOrdering` in
`crates/hort-app/src/use_cases/index_serve_filter.rs`) compare
version strings the way the format's own resolver would, and degrade
to a lexicographic fallback on malformed input rather than panicking
— one weird upstream version string must never take down the serve
path.

## Filtering happens at serve time

Proxy sources cache upstream state (the npm packument projection, the
PyPI simple-index projection, cargo's sparse-index entries), but the
cached value is the *raw upstream* picture — filtering applies after
the source returns, on every serve. A quarantine-status change is
therefore reflected on the next request without waiting out a cache
TTL. For the inverse direction — a rejection that should also stop a
cached *projection* from being served stale — the rejection event
drives explicit cache invalidation
(`crates/hort-app/src/use_cases/upstream_index_cache_invalidator.rs`).
The serve path is also where the hot-path prefetch trigger observes
the upstream version set (see [the prefetch
pipeline](prefetch-pipeline.md)): the proxy source fires the trigger
after a successful fetch, so index serving and prefetch planning read
the same parsed upstream picture.

Access control sits in front of all of it: the serve handler resolves
the repository through `RepositoryAccessUseCase` with the caller
principal threaded through both sources, and denied, invisible, and
missing repositories all collapse to the same 404 envelope — the
index surface does not confirm the existence of repositories the
caller cannot read.

## The WASM seam

`IndexBuilder` is the trait realisation of the *SimpleIndex*
capability group in the format-capability taxonomy
([Format handlers](format-handlers.md),
[ADR 0005](../../adr/0005-wasm-format-modules-capability-taxonomy.md)):
formats that serve a version-list index — npm, PyPI, cargo, and the
wider cohort that follows them — declare SimpleIndex, and the trait
is what a declaration binds to. WASM format modules implement
`IndexBuilder` at the WIT boundary: the host walks the pipeline
exactly as the compiled-in path does, and hands the post-filter
entries across the component boundary for wire-shape emission. The
closed `PerVersionPayload` sum is the compiled-in shape's contract;
the WIT boundary is the deliberate seam where that closed-set
assumption changes. What does not change at the seam is the filter
pipeline — it runs host-side, before any module code sees the
entries, so a module cannot opt out of quarantine-aware filtering
any more than a compiled-in builder can.

## Related pages

- [Format handlers](format-handlers.md) — the capability taxonomy
  that SimpleIndex belongs to, and the WASM hosting model.
- [The prefetch pipeline](prefetch-pipeline.md) — the consumer of
  the upstream version picture the proxy sources parse.
- [ADR 0007](../../adr/0007-fail-closed-quarantine-release-predicate.md)
  — how a version comes to hold the status the filters read.
- [ADR 0016](../../adr/0016-cross-opt-in-interaction-matrix.md) —
  why `IndexMode`'s interactions with the other gate-influencing
  opt-ins are enumerated and bounded.
- [ADR 0008](../../adr/0008-per-format-adapter-free-http-crates.md)
  — the dep-graph rule the index sources live under.
