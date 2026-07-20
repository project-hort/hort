# VersionDiscovery capability group — design (issue #58)

Branch-local planning doc (D7). Distil into an ADR 0005 amendment before merge; delete this file.

Decision answered on #58 (`agent:decision`, Tom 2026-07-20: *"Recommendation confirmed"*). ADR-affecting work may proceed.

## §1 — Deferred-items sweep (architect Step 0)

Run 2026-07-20 against `develop` @ `5c8bdc15`.

- `docs/plans/` — three files present, all merged and all awaiting D7 distillation under **#59** (`coalesce-leader-liveness{,-backlog}.md`, `eager-index-child-prefetch.md`). **Decision: carry forward** — #59 owns their cleanup; this initiative adds a fourth and joins that queue.
- ADR open-items register — the ***Maven Phase-2 prefetch*** row is directly implicated. It records that enabling Maven prefetch must touch **five** sites in one change, and warns that `self_service_prefetch_use_case`'s `_ => &NpmSemverOrdering` wildcard would otherwise **silently mis-order Maven with npm semver, hidden from every test**. **Decision: absorb the *structural* half now.** This design deletes that footgun as a side effect (§4.4); the Maven prefetch *feature* stays deferred.
- ***OCI image-index child-status rollup*** / ***promotion cascade*** — unrelated. Carry forward.

### Inherited-rationale re-validation

**Reused claim (ADR 0005):** *"Format handlers are modules selected by a capability taxonomy… a flat 'implement everything' interface is rejected."*

**Verdict: still valid — and it is precisely what has eroded.** The ADR's rejected alternative was a *"lowest-common-denominator interface that lies about capabilities."* `FormatHandler` is now 59 methods, eight of them defaulted no-ops serving a capability the taxonomy never named. The rationale did not expire; the implementation drifted from it, one defaulted method at a time. Recorded so a future sweep sees the erosion documented rather than rediscovering it.

## §2 — Group membership (corrected)

**Eight methods, not the nine first proposed on #58.**

| Method | Group |
|---|---|
| `extract_upstream_versions` | **VersionDiscovery** |
| `upstream_metadata_path` | **VersionDiscovery** |
| `upstream_metadata_accept` | **VersionDiscovery** |
| `resolve_range_max` | **VersionDiscovery** |
| `download_config_path` | **VersionDiscovery** |
| `compose_download_url_from_config` | **VersionDiscovery** |
| `resolve_download_url_from_metadata` | **VersionDiscovery** |
| `extract_dependency_specs` | **VersionDiscovery** (per #58: folded in, not split) |
| ~~`resolve_mutable_version`~~ | **MultiFileArtifact — already declared** |

`resolve_mutable_version` was in my original list and does not belong. ADR 0005's own realisation note names it a MultiFileArtifact member alongside `classify_group_member` and `build_artifact_logical_path`, and its only production consumer is `hort-http-maven/src/lib.rs:454` (Maven SNAPSHOT resolution) — nothing in the prefetch cascade touches it.

**That mis-assignment is itself the argument for this work.** With a flat interface there is no way to tell which capability a method serves; I got one wrong on first inspection, from the same file the ADR is about.

## §3 — Participation, measured

| Format | VersionDiscovery methods implemented (of 8) |
|---|---|
| cargo | 6 |
| npm | 5 |
| pypi | 4 |
| **OCI** | **0** |
| Maven | 0 (feature deferred) |
| Helm | 0 |

OCI's apparent hits are `#[cfg(test)]` functions *asserting it inherits the defaults* — `resolve_range_max_inherits_default_none` ("OCI tags are not ranges") and `extract_dependency_specs_inherits_default_empty_vec`. The non-participation is already deliberate and already tested; this design only makes it **declared**.

The 4–6 spread among the three participants is itself worth a look once participation is explicit — but that is a follow-on, not this item.

## §4 — Design

### §4.1 — A separate trait, not a flag

```rust
/// Discovering upstream versions and resolving their download URLs.
/// A format that cannot do this does not implement the trait — absence
/// is the declaration.
pub trait VersionDiscovery: Send + Sync {
    fn extract_upstream_versions(&self, body: &mut dyn std::io::Read) -> DomainResult<Vec<String>>;
    fn upstream_metadata_path(&self, package: &str) -> Option<String>;
    fn upstream_metadata_accept(&self) -> Vec<String>;
    fn resolve_range_max(&self, range: &str, available: &[&str]) -> DomainResult<Option<String>>;
    fn download_config_path(&self) -> Option<String>;
    fn compose_download_url_from_config(/* … */) -> DomainResult<Option<String>>;
    fn resolve_download_url_from_metadata(/* … */) -> DomainResult<Option<String>>;
    fn extract_dependency_specs(&self, body: &mut dyn std::io::Read) -> DomainResult<Vec<DependencySpec>>;
}

pub trait FormatHandler: Send + Sync {
    // … the remaining ~51 methods, unchanged …

    /// `Some` iff this format declares the VersionDiscovery group.
    fn version_discovery(&self) -> Option<&dyn VersionDiscovery> { None }
}
```

**Why an accessor returning `Option<&dyn …>` rather than a `capabilities() -> &[Group]` flag:** a flag can disagree with reality — a format could declare the group and still inherit no-op defaults, reproducing today's problem with extra ceremony. An accessor makes the declaration and the implementation the same fact. `None` is not a default that lies; it is the honest answer.

**Why the default is `None` and not a required method:** every non-participating format (OCI, Maven, Helm, and any future Tier-C) would otherwise need a boilerplate `None`. The default is safe here precisely because it is *one* method whose meaning is "I do not participate" — unlike eight defaults each of which silently fakes a behaviour.

### §4.2 — Consumer migration

The consumer set is tight — all in `hort-app` task handlers plus the upstream-metadata adapter:

- `crates/hort-app/src/task_handlers/prefetch_tick.rs`
- `crates/hort-app/src/task_handlers/prefetch_dependencies.rs`
- `crates/hort-app/src/task_handlers/prefetch_ingest.rs`
- `crates/hort-formats-upstream/src/lib.rs` (dispatch)

Each becomes `handler.version_discovery()` + an early return when `None`. That early return is behaviourally identical to today's "defaults returned empty/None so nothing happened" — but now it is explicit and greppable.

### §4.3 — WIT boundary

ADR 0005 targets deploy-time WASM with declared capability groups. A separate trait maps directly onto an optional WIT interface: a module either exports `version-discovery` or it does not. Eight defaulted methods on one flat interface do not map onto anything a module author can reason about. Fixing this before the boundary freezes is the point — afterwards it is a breaking change for every module author.

### §4.4 — The `ordering_for_format` footgun dies with it

`prefetch_tick.rs:619`'s `ordering_for_format` returns `None` for Maven/OCI/Helm, and `self_service_prefetch_use_case`'s `_ => &NpmSemverOrdering` wildcard would silently mis-order any format reaching it. Once participation is structural, a non-participant never reaches an ordering lookup at all — there is no participation to inherit. Delete the wildcard as part of this work and let the type system carry what a code comment currently carries.

## §5 — Explicitly out of scope

- **The 4–6 participation spread.** cargo implements 6 of 8, pypi 4. Whether the gaps are deliberate or accidental is a real question — and answerable only *after* participation is explicit. Carried forward.
- **Enabling Maven prefetch.** The ADR register's Maven Phase-2 row stays deferred; this design removes its structural trap, not its feature work.
- **Splitting `extract_dependency_specs` into a `DependencyCascade` group.** #58 folded it in. Revisit only if a format wants one without the other.
- **Touching OCI's prefetch.** It never used these methods and is not on the port. Unchanged.

## §6 — Observability

No new metrics, no new logs. This is a compile-time restructuring of an interface; it changes no runtime behaviour and should be provable by the existing suite passing unchanged. If a metric moves, something has gone wrong.

## §7 — Testing

The load-bearing property is **behavioural equivalence** — the suite must pass unchanged, since every early-return replaces a default that already produced the same outcome.

Plus:

1. A structural guard test asserting OCI / Maven / Helm return `None` from `version_discovery()`, and npm / cargo / pypi return `Some`. This replaces the two OCI `*_inherits_default_*` tests, which lose their subject.
2. A test that a `None` participant is skipped by each of the four consumers rather than silently producing an empty result.
3. Exhaustiveness: a match over `RepositoryFormat` in the guard so a new format must consciously declare participation — the same shape as `ephemeral_keyspace_exhaustive` and `retention_registration_guard`.

## §8 — ADR

Amend **ADR 0005**: add `VersionDiscovery` to the declared taxonomy with its eight members, and a realisation note in the same shape as the existing MultiFileArtifact one — naming the trait, the accessor, and the participating formats. Note explicitly that `resolve_mutable_version` belongs to MultiFileArtifact, since that is the mis-assignment this initiative had to correct.
