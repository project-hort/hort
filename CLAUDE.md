# Hort Development Guidelines

Auto-generated from all feature plans. Last updated: 011

## Active Technologies
- Rust 1.94+ (backend) + wasmtime 21.0+, wasmtime-wasi, wit-bindgen, git2, axum
- PostgreSQL (existing), filesystem for WASM binaries
- Rust 1.94+ + axum, sqlx, tokio, reqwest
- Rust 1.94+ + axum, serde, serde_json

## Architectural Direction

Hort's architecture is the as-built, authoritative design described below — a shipped, hexagonal/onion-layered, event-sourced artifact registry. The architecture decision records in `docs/adr/` encode the standing decisions and carry more authority than any single implementation detail, which may have drifted from them. Where the implementation and an official specification (protocol RFC, registry API docs, or an ADR) conflict, the specification takes precedence — passing E2E tests prove the implementation is self-consistent, not that it is protocol-correct.

**Do not erode the layering with piecemeal changes.** Architecture-affecting work follows the architect-skill workflow below.

### Target Architecture (summary)

- **Hexagonal / onion layering**: Domain layer (pure Rust, zero I/O) → application layer → outbound port traits → adapters (Postgres, S3, scanner, WASM host)
- **Event-sourced artifact lifecycle**: All artifact state transitions produce immutable domain events (`ArtifactIngested`, `ArtifactQuarantined`, `ScanCompleted`, `ArtifactReleased`, `ArtifactPromoted`, etc.). Repository config, users, and RBAC stay CRUD.
- **Enforced CAS**: `StoragePort::put(stream) → ContentHash`. Streaming — SHA-256 computed incrementally, no buffering. Callers never supply storage keys. Content hash is always SHA-256 of the raw bytes.
- **Mandatory upstream verification**: every pull-through fetch verifies a checksum (protocol-native digest for OCI, parsed upstream metadata for Cargo / PyPI / npm). No operator opt-in; a format that cannot verify cannot proxy. See ADR 0006.
- **WASM format modules**: Format handlers (npm, PyPI, Maven, OCI, etc.) are deploy-time WASM modules loaded from `$WASM_PLUGIN_DIR`. Each declares capability groups in a manifest. OCI/Git LFS (stateful upload) may stay compiled-in as Tier C.
- **Externalised timeseries**: Download counts and other high-frequency metrics leave the relational store; only summary endpoints remain.

Full analysis: the architecture decision records in `docs/adr/` (start at the decision index, `docs/adr/0000-historical-decisions-index.md`) and the Diátaxis set under `docs/architecture/`.

### Agentic Coder Workflow

**Always use the hort-architect skill for architecture-affecting work:**

```
/hort-architect
```

The skill encodes the domain model, event vocabulary, format capability taxonomy, port contracts, anti-patterns checklist, and the mandatory step-by-step workflow. Read it before writing any spec or implementation that touches the layering, ports, or domain model.

Key rule: **the official protocol spec is authoritative over the implementation.** When extending a format handler or pull-through path, verify behavior against the protocol RFC / registry API docs rather than assuming the current code is correct. If the implementation and the spec conflict, the spec wins. E2E tests passing means the implementation is self-consistent; it does not guarantee protocol compliance.

## Project Structure

```text
Cargo.toml                  — workspace root
migrations/                 — SQL migrations (workspace root)
crates/
  hort-domain/                — domain layer: pure Rust, zero I/O
  hort-app/                   — application layer: orchestrates domain + ports
  hort-adapters-postgres/     — PostgreSQL outbound port implementations
  hort-adapters-storage/      — storage backend implementations
  hort-http-core/             — shared inbound-HTTP primitives (AppContext,
                              ApiError, middleware, authz, admin handler)
  hort-http-cargo/            — Cargo registry HTTP adapter
  hort-http-npm/              — npm registry HTTP adapter
  hort-http-pypi/             — PyPI registry HTTP adapter
  hort-http-oci/              — OCI Distribution Spec HTTP adapter
  hort-formats/               — WASM host, module loader, format dispatch
  hort-server/                — service binary (composition root, top-level
                              router assembly in `src/http.rs`)
docs/adr/                   — architecture decision records (standing decisions)
docs/architecture/          — Diátaxis docs (explanation / how-to / reference / tutorial)
.claude/commands/           — architect skill and smoke test commands
```

### Implementation history

All code lives under `crates/`, organised by hexagonal layer (see the structure above). New work extends the existing crates in place — the spec/RFC, not historical implementation, is the authority on correct behavior.


## Commands

### Fast CI (Tier 1) — every push/PR
```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --lib
cargo audit --deny warnings
```
The full local gate — including the DB-free structural guard tests — is in
*Pre-push Quality Checklist* below.

### Integration Tests (Tier 2) — main & release branches only
```bash
# requires PostgreSQL (DATABASE_URL); see TESTING.md
cargo test --workspace
```

### E2E (Tier 3) — release/manual only
```bash
# Canonical E2E harness: the native-tests runner builds one client image (all
# client tools + hort-cli baked in), brings up deploy/compose, runs each
# self-describing scenario as a throwaway container in-network, tears down.
./scripts/native-tests/run.sh --hort=compose

# Subsets / inventory / external hort:
./scripts/native-tests/run.sh --hort=compose --group clients
./scripts/native-tests/run.sh --list
HORT_URL=… KEYCLOAK_URL=… ./scripts/native-tests/run.sh --hort=external --group clients
```

Some smokes can't run as containerized clients (they restart the stack with
config overlays or mint server-signed svc-tokens via `compose exec hort-server`)
— those are host-side suites: `scripts/host-tests/run.sh` (orchestration smokes)
and `scripts/k8s-tests/` (kind). See `TESTING.md` for the full tier/command
reference and `scripts/native-tests/README.md` for the scenario contract. CI:
GitLab `.gitlab-ci.yml` is canonical for everything except E2E (buildah/K8s
runners, no docker daemon); the compose E2E runs on GitHub `e2e.yml` via
`scripts/native-tests/run.sh --hort=compose` — on pushes/PRs to `main` and
`release/**`, on `v*` tags, and (via `workflow_call`) as `release.yml`'s
release gate.

## Code Style

Rust 1.94+ with the following project configuration:

- **Line width:** 100 characters (see `rustfmt.toml`)
- **MSRV:** 1.94.0 (see `.clippy.toml`)
- **`unsafe` is forbidden workspace-wide** via `[workspace.lints.rust] unsafe_code = "forbid"` in the root `Cargo.toml`. This cannot be overridden with `#[allow]` — it is a compile error. All dependencies that need `unsafe` handle it within their own crates; no application code in this workspace has a legitimate need for it. If a future edge case requires revisiting this, the change must be made in `Cargo.toml` and reviewed as a policy change.
- **Clippy lints** are configured in `[workspace.lints.clippy]` in the root `Cargo.toml`. Every crate inherits these via `[lints] workspace = true`. Do not override workspace lints in individual crates without justification.
- **SonarCloud quality gate** runs on every PR and enforces >= 85% coverage on new code and <= 1% duplication on new code. PRs that fail the gate will be blocked.

### Test Coverage Tiers

Coverage requirements vary by crate layer. Core crates contain the security-critical domain logic (artifact lifecycle, quarantine invariants, CAS guarantees, policy evaluation) and must be exhaustively tested.

| Crate | Required coverage | Rationale |
|---|---|---|
| `hort-domain` | **100%** | Pure Rust, zero I/O — every branch is testable and must be tested. This is the security boundary. |
| `hort-app` | **100%** | Orchestration logic that enforces invariants across ports. Mock all outbound ports. |
| `hort-adapters-postgres` | **>= 85%** | Integration tests against a real database. |
| `hort-adapters-storage` | **>= 85%** | Integration tests against real backends. |
| `hort-http-core` | **>= 85%** | Shared inbound-HTTP primitives; middleware + extractors have test coverage per initiative. |
| `hort-http-<format>` | **>= 85%** | Per-format HTTP handler tests. |
| `hort-formats` | **>= 85%** | WASM host tests. |

**Enforcement:** `hort-domain` and `hort-app` coverage is checked by the `coverage` CI job. Any new public function or branch in these crates without a corresponding test is a blocking review finding. The 100% target means every match arm, every error path, and every boundary condition — not just happy paths.

**DB-backed test isolation (parallel-safety contract).** The `hort-adapters-postgres` and `hort-adapters-storage` test suites — inline `#[cfg(test)]` `--lib` tests *and* `crates/*/tests/` integration tests — run **in parallel against one shared database/backend with no per-test isolation** (no transaction rollback, no schema-per-test, no truncation). The `cargo test --tests` CI job (`test:integration`) builds the lib as a unittest target, so inline tests run there too. Several adapters do global-scope work (e.g. the `save_managed` gitops-partition full-reconcile, `pg_stat_activity` probes, unfiltered `COUNT`/`list_*` reads). Coverage % is necessary but **not sufficient**: a DB-backed test that is correct serially but interferes with a concurrently-running sibling is a defect, not passing. Production tolerates this because the only writer of these partitions is single-flight by design (gitops apply is single-process per boot lock); tests must honour that same contract. **Therefore: every new `hort-adapters-postgres` test that acquires a real connection (calls `maybe_pool()` / touches the shared DB) MUST carry the crate-wide `#[serial(hort_pg_db)]` key** (or an equivalent per-test isolation mechanism); a DB-gated test without it is a **blocking review finding** — it silently reintroduces the identity-shifting flake fixed in `ed79360a`. There is no compile-time or lint enforcement of this yet, so it is a mandatory review check (see the architect Implementation Review Checklist).

### Anti-Patterns Checklist

The architect skill (`/.claude/commands/hort-architect.md`) maintains the canonical anti-patterns checklist used during review. The bullets below are mirrored here for the rules whose enforcement is structural (compile errors / dep-graph) rather than convention; the architect doc has the full list.

- **Format crate references `ctx.repositories` / `ctx.artifacts` / `ctx.refs` / `ctx.artifact_groups` / `ctx.content_references` / `ctx.artifact_metadata` / `ctx.storage`** — these `AppContext` fields are `pub(crate)` (ADR 0008); format crates must call the corresponding use case (`RepositoryAccessUseCase`, `ArtifactUseCase`, `ContentReferenceUseCase`, etc.). Direct access is a compile error and that is intentional.
- **Adapter import inside an `hort-http-<format>` crate** — the per-format inbound-HTTP crates must not depend on `hort-adapters-*`, `sqlx`, or `reqwest`. The dep graph is load-bearing (ADR 0008): an adapter import is an unresolved-import compile error, not a review finding.
- **`reqwest::Client::new()` in any adapter** — every adapter that opens TLS must build via `reqwest::Client::builder()` so the composition root can layer `apply_to_reqwest_builder` onto it. `Client::new()` is a *compile-time-allowed but architecturally-forbidden* pattern; the review checklist enforces it. Exception: `cfg(test)` test fixtures. (see ADR 0010)
- **Reintroducing `*_INSECURE_TLS` knobs** — no `S3_INSECURE_TLS`, `LDAP_INSECURE_TLS`, `OIDC_INSECURE_TLS`, `HORT_TLS_INSECURE`, etc. The supported way to trust internal certs is `HORT_EXTRA_CA_BUNDLE`. If a future need genuinely requires this, it amends the decision in a new ADR first. (see ADR 0010)
- **Re-introducing a long-default CLI session lifetime (>24 h) or removing the ≤1 h admin cap** — short-lived full-authority tokens with refresh replaced long-lived limited tokens; reversing one half without the other re-opens the blast-radius concern the trade-off was designed to prevent. (see ADR 0013)
- **`ServiceAccount` with empty `federatedIdentities[].claims`** — apply-time validation rejects this; if a code path accepts an envelope with an empty `claims` map, that's a bug. Empty claims = "any JWT from this issuer can assume me" — a privilege-escalation footgun on a misconfigured issuer. (see ADR 0018)
- **`OidcIssuer` trusts an unverified JWKS** — JWKS must be fetched over TLS verified against the system trust store + `HORT_EXTRA_CA_BUNDLE`. No `insecure_jwks_url` knob. Mirrors the reqwest-builder rule. The HTTP client for JWKS fetches is the shared `internal::build_http_client` in `hort-adapters-oidc`, which means the no-`reqwest::Client::new()` rule applies here too. (see ADR 0018)
- **Policy field accepted at apply, inert at runtime** — a new field on `PrefetchPolicy` / `ScanPolicy` / `RetentionPolicy` / `RepositoryUpstreamMapping` etc. must be either enforced by the consuming use case or rejected at gitops apply. Accepting the field while the consumer silently ignores it is a hard block — operators set risk-significant values (e.g. `max_age_days: 90`) and make threat-model decisions on the assumption the field is load-bearing. Structural enforcement is an apply-time linter rejection that points the operator at the future enforcement work; `max_age_days` is the canonical exemplar (apply-time linter rejects any non-`None` value). The alternative model is to *remove* the operator surface until the feature is functional. (see ADR 0015)
- **Cross-opt-in collapse of a Gate-2-style invariant** — any new operator-opt-in that lets untrusted input influence the release-gate computation (`trust_upstream_publish_time`-shaped, `scan_backends:[]`-shaped, `IndexMode`-shaped) must enumerate its interaction with every other such opt-in in its design doc *before* implementation, via the architect doc's "Cross-opt-in interaction matrix". The canonical exemplar: `trust_upstream_publish_time = true` × `scan_backends: []` together collapse the Gate-2 observation window to ≤ sweep-tick latency (apply-time linter rejects the combination, `trust_upstream_publish_time_requires_scan_backends` rule). The structural close is fail-closed apply-time rejection of the dangerous combination, never a runtime "fallback to a degraded authority" path. (see ADR 0016)

## Implementation Discipline — when to deviate from the design

**The design wins by default.** An implementation may deviate from the design — a plan document, an initiative backlog item, an explicit "mirror X" instruction, or established codebase precedent — only when the alternative is **objectively better than the design**. Not merely possible, not merely arguable.

What "objectively better" is *not*:

- **"Defensible," "plausible," "I can construct an argument for it."** These are hedges, not verdicts. If that is all you can say, the design wins.
- **"It works."** Most alternatives work. The bar is *better*, not *workable*.
- **A choice the design left open.** Picking between two unspecified alternatives is a coding judgement, not a deviation.

What "objectively better" *is*:

- A concrete advantage the design did not have (e.g., the design pays N permanent files forever for a property that one in-place file plus a 3-second merge resolve also provides — the migration ALTER chain pre-1.0).
- A measurable cost reduction (latency, memory, cardinality, blast radius, surface area) on a cost the design acknowledged.
- A correctness fix where the design was wrong — flag it, get the design amended, then implement.

### Implementer's discipline

If you deviate, declare it in the commit body **and** the PR description: what the design said, what you did, why your choice is *objectively better* (concrete advantage, not plausibility). If you cannot make the "objectively better" case, follow the design.

### Reviewer's discipline

Before calling something a deviation, verify both:

1. **It is actually a deviation.** A choice that mirrors a codebase convention the design explicitly named — e.g., a new task handler "mirroring `CronRescanTickHandler`" follows the established port-only shape (every `hort-app` task handler depends on `Arc<dyn _Port>`s, not concrete use cases) — is the design's own answer. Flagging it is a misread, not a finding.
2. **The cited alternative exists in the layer being criticised.** `hort-http-core::test_support::build_mock_ctx` is the harness for `AppContext`-shaped HTTP / middleware handler tests; `hort-app` task handlers use `crates/hort-app/src/use_cases/test_support.rs` mocks instead. The two are not interchangeable; citing one for the other is layer-conflation, not a finding.

Hedging language on the reviewer side ("defensible," "I can see arguments for it," "probably fine") is the same warning sign as on the implementer side. If you cannot land a clear verdict — withdraw or keep investigating, but don't ship a deviation label you can only hedge into.

## Git & GitHub

### Branch Protection — NEVER push directly to main

All changes must go through pull requests:

1. **Create a feature branch** from main:
   ```bash
   git checkout main && git pull
   git checkout -b feat/short-description   # or fix/, chore/, docs/
   ```

2. **Make changes and commit** to the feature branch

3. **Push and create PR**:
   ```bash
   git push -u origin feat/short-description
   gh pr create --fill   # or with --title and --body
   ```

4. **Merge via GitHub** after CI passes (squash merge preferred)

### Merge Requirements (MANDATORY)

**NEVER merge a PR unless ALL of the following are true:**

1. **CI workflow fully green.** Every check must pass: Rust check (clippy), unit tests, code coverage gate, duplication gate, security audit, CodeQL. No exceptions.
2. **Code coverage >= 70%** on new/changed lines. The CI coverage gate enforces this. If it fails, add tests until it passes.
3. **Code duplication <= 3%** on changed files. The CI duplication gate (jscpd) enforces this. If it fails, refactor duplicated code into shared helpers.
4. **No `--admin` bypass.** Do not use `gh pr merge --admin` to skip failing checks. If a gate is genuinely wrong (not a code issue), fix the gate first, get that fix merged, then rebase the PR.

If a CI gate is blocking a PR due to a systemic issue (e.g., the gate itself has a bug), **ask the user before bypassing.** Document why the bypass was needed and create a follow-up issue to fix the gate. This rule exists because bypassing gates erodes trust in the CI pipeline.

Branch naming conventions:
- `feat/` — new features
- `fix/` — bug fixes
- `chore/` — maintenance, dependencies, CI
- `docs/` — documentation only

### Parallel Agent Work (git worktrees)

When dispatching multiple agents to work on separate features or fixes in parallel, use **git worktrees in a sibling directory** (e.g. `../hort-<short-task-id>/`). Worktrees share `.git/objects` with the primary, so agent commits are trivially accessible from the primary working directory — no fetching, no remote setup, no risk of losing work to filesystem cleanup.

**Pattern for each agent:**
```bash
WORK_DIR="../hort-<short-task-id>"
git worktree add -b <feat-branch> "$WORK_DIR" <base-branch>
cd "$WORK_DIR"
# ... make changes, run cargo fmt/clippy/test, commit ...
# DO NOT push from the worktree; orchestrator handles that from primary
```

After the agent completes, in the primary working directory:
```bash
git cherry-pick <agent-commit-sha>     # SHA already in .git/objects — no fetch
git worktree remove ../hort-<short-task-id>
```

**Discipline rules (mandatory) — these are why worktrees historically caused problems:**
- The agent must `cd` into the worktree directory and stay there — never `cd` back to the primary.
- The agent must not run `git checkout`, `git switch`, or any write op against the primary's working tree. Each worktree has its own HEAD; switching branches in the primary is a corruption hazard.
- The agent must not push from the worktree. Push is orchestrated from primary after stacking.
- The agent's commit lands in shared `.git/objects` immediately — there is no separate fetch step.
- Each worktree gets its own `target/` (default cargo behaviour). Sharing `CARGO_TARGET_DIR` across worktrees causes lock contention; the disk savings are not worth it. With several parallel agents, this means N copies of `target/` — dispatch in waves if `/home` is constrained.

**Why not shallow clones in `/tmp/`** (prior practice, abandoned 2026-05-09):
- `/tmp` partitions are typically small (5–20 GB) and N × cargo target dirs exhaust them silently — when `/tmp` fills, even bash redirects fail in opaque ways, and an in-flight agent can lose its work after the commit but before fetching.
- `/tmp` is subject to system cleanup, which has erased completed agent work between commit and orchestrator fetch.
- Cross-clone fetching requires extra `remote add` or path-fetch steps, with the same TLS/SSH credential issues that `git clone` against the real origin would hit.
- Worktrees avoid all three because everything stays under the primary's `.git/` tree.

### Pre-push Quality Checklist

Every commit must pass these checks locally before pushing. Do NOT use "push and see if CI passes" as a strategy.

```bash
cargo fmt --check                                          # formatting
cargo clippy --workspace --all-targets -- -D warnings      # linting
cargo test --workspace --lib                               # unit tests
cargo test -p hort-server --test ephemeral_keyspace_exhaustive   # keyspace-registry guard
cargo test -p hort-app --test no_bcrypt                          # "no bcrypt" invariant guard
cargo test -p hort-config --test alpha_fixtures                  # alpha gitops fixtures parse + cross-validate
cargo test -p hort-domain --test streaming_metadata_port         # streaming-metadata port contract (no &[u8] body / no metadata_body_bytes)
cargo test -p hort-app --test no_sensitive_drops                 # migration sensitive-table drop guard
cargo test -p hort-app --test retention_registration_guard       # eventstore-retention permitted-category guard
cargo test -p hort-app --test no_retired_config_names            # retired env-var / Helm-key straggler guard
cargo audit --deny warnings                                # advisories (ALWAYS — see note)
cargo deny check                                           # advisories+bans+licenses+sources (ALWAYS — see note)
```

**The seven `--test` lines are structural guard rails, not ordinary integration
tests.** `cargo test --workspace --lib` deliberately excludes `tests/` integration
targets — most need a database, which is Tier-2 (`cargo test --workspace`,
main/release only). But `ephemeral_keyspace_exhaustive` (keyspace-registry
exhaustiveness), `no_bcrypt` ("Argon2id, not bcrypt" invariant, ADR 0028-adjacent),
`alpha_fixtures` (alpha-fixture gitops-tree parse + cross-validate
regression guard), `streaming_metadata_port`
(ADR 0026 — pins the `FormatHandler` metadata methods' `&mut dyn Read`
streaming contract and bans reintroducing the deleted `metadata_body_bytes`
buffering helper on the metadata consumers), `no_sensitive_drops` (ADR 0030 —
token-aware source-scan of `migrations/` that rejects `DROP TABLE` /
`DROP TABLE IF EXISTS` / `ALTER TABLE … DROP CONSTRAINT` against a maintained
sensitive-table list: the authorization model, credential store, event store,
repository config, and task queue), `retention_registration_guard` (ADR 0030 —
asserts the code-held eventstore-retention rule set
(`canonical_retention_rules`) only ever registers the permitted categories
`{Artifact, AuthAttempts, DownloadAudit, TokenUse}`, with a no-wildcard
exhaustiveness match over every `StreamCategory` so a future variant — or an
accidentally-seeded privileged category — cannot silently become eligible for
automated stream deletion), `no_retired_config_names` (ADR 0029 —
whole-token, breadcrumb-aware source-scan of `crates/` + `deploy/` + `scripts/` +
`docs/architecture/` that rejects any reintroduced retired `HORT_*` env-var name
or retired Helm `values` key from the hard-rename normalization: a retired env var
is silently ignored at boot and a retired Helm key now fails the strict
`values.schema.json`, so a `name` regression — which coverage % cannot catch —
becomes a red test; the upgrade note and the deliberate-typo Helm
fixtures are the only allowed homes for the old names) are pure source-/fixture-scan
guards — no database, sub-second — enforcing structural invariants that a
rename or a stray `use` silently breaks. They belong in the per-push gate, not
Tier-2-only (a stale keyspace registry once shipped undetected exactly because
this gate ran only `--lib`).
**Any new DB-free structural guard test added under `crates/*/tests/` must
be added to this list too.**

**`cargo audit` is an unconditional pre-push check — NOT conditional on touching
`Cargo.toml`/`Cargo.lock`.** It scans the locked dependency graph against the
**live RustSec advisory DB**, which updates continuously: a newly-published
advisory against an already-pinned crate flips the blocking CI security gate
(`cargo audit --deny warnings`) red with **zero code or `Cargo.lock`
changes**. Inferring the gate's result from "no dependency change" is a known
blind spot — actually run the command; do not report the gate satisfied without
its output. The CI security stage is `main`/`release`/`tags`-gated, so a
feature-branch push will not surface this for you — this local check is the only
thing that will. On a hit, prefer upgrading the flagged crate (`cargo update -p
<crate> --precise <fixed-version>`, `Cargo.lock`-only) over an ignore; an ignore
must be added to **both** `.cargo/audit.toml` and `deny.toml` (the
`security:advisory-sync` job enforces parity) and is a deliberate, justified risk
acceptance, not a default.

**`cargo deny check` is ALSO unconditional — and is NOT redundant with `cargo
audit`.** The two tools walk the dependency graph differently: `cargo audit`
scans the **full `Cargo.lock`**; `cargo deny` walks the **active build graph**
(it excludes crates reachable only through unused optional features). They also
read **separate ignore lists** (`.cargo/audit.toml` vs `deny.toml`). The CI
`security:cargo-deny` job runs `cargo deny check` and the `security:cargo-deny`
gate is `main`/`release`/`tags`-gated, so a feature-branch push will not surface a
cargo-deny-only failure — this local check is the only thing that will. The
canonical trap (rc.10, RUSTSEC-2023-0071): an advisory ignored AUDIT-ONLY in
`.cargo/audit.toml` (deliberately not mirrored to `deny.toml` because the crate
was reachable only via an inactive feature) **silently became a cargo-deny
failure** when a new dependency (sigstore → openidconnect → rsa) pulled the crate
into the active graph — `cargo audit` stayed green, `cargo deny` went red. **So:
when you add a dependency, run `cargo deny check`, and re-check every `# AUDIT-ONLY`
marker in `.cargo/audit.toml` with `cargo tree -i <crate> -e normal` — if the
previously-inactive crate is now active-graph-reachable, drop the marker and
mirror the ID into `deny.toml`.** See the architect doc's "re-validate an
inherited rationale when the threat surface changes" rule.

Additionally, before pushing:
- Check for code duplication: if structurally similar blocks appear 3+ times in new code, refactor into a shared helper
- Check test coverage: `hort-domain` and `hort-app` require 100% coverage; all other crates require 85%+ (see Test Coverage Tiers above)
- Check migration numbering: verify the migration number is not already taken (`ls migrations/ | tail -5`)

### Maintenance Branches

Long-lived `release/X.Y.x` branches exist for shipping bug fixes to older release series:

- **`release/1.0.x`** — maintenance branch for the 1.0 series (created from `v1.0.0-rc.5`)
- **`release/1.1.x`** — maintenance branch for the 1.1 series (created from `v1.1.2`)
- **`main`** — continues with 1.2.x (and beyond) development

**Bug fix workflow for maintenance branches:**
1. Create a fix branch from the maintenance branch:
   ```bash
   git checkout release/1.1.x && git pull
   git checkout -b fix/short-description
   ```
2. Push and create a PR **targeting `release/1.1.x`** (not main):
   ```bash
   git push -u origin fix/short-description
   gh pr create --base release/1.1.x --fill
   ```
3. Tag releases from the maintenance branch:
   ```bash
   git checkout release/1.1.x && git pull
   git tag v1.1.3 && git push origin v1.1.3
   ```
4. Cherry-pick fixes between maintenance and `main` so both lines stay in sync. Bug fixes typically land on the maintenance branch first, then cherry-pick forward to main.

**Docker image tags** (set by `docker/metadata-action` in `docker-publish.yml`):
Images are built and published **only on `v*` release tags** (and manual
`workflow_dispatch`) — there is no longer a `:dev` build on `main` pushes.
- Version tags **strip the `v` prefix**: git tag `v1.1.0-rc.2` → Docker tag `:1.1.0-rc.2`
- `:latest` is only set for stable releases (no `-rc`, `-beta`, etc.)
- `:1.0`, `:1.1` series tags are set automatically via semver parsing
- `:sha-<commit>` is set for every (tag) build

### Releases

- Release notes are **auto-generated by GitHub** (`generate_release_notes: true` in `release.yml`). They show the actual changelog (PRs merged, commits) since the previous tag.
- **Do NOT hardcode static release notes** in the workflow. No product descriptions, feature lists, or format counts in release bodies.
- The release workflow is at `.github/workflows/release.yml`, triggered by `v*` tags.

### Changelog and Release Notes

- Follow the [Keep a Changelog](https://keepachangelog.com/) format: record changes under `### Added` / `### Changed` / `### Fixed` / `### Security` / `### Removed` beneath the `## [Unreleased]` heading, then stamp a dated version heading at release time.
- GitHub Release notes are **auto-generated** (`generate_release_notes: true` in `release.yml`) — do NOT hardcode static product descriptions, feature lists, or format counts in release bodies.
- Hort has a single author and no external contributors or sponsors at present, so changelog entries and release notes carry no `### Thank You` / `### Sponsors` recognition sections. If external contributors or sponsors appear later, reintroduce those sections at that point.

### Other Git Rules

- **Always use `gh` CLI** for GitHub operations (PRs, issues, workflows, etc.)
  - Use `gh pr create` for pull requests
  - Use `gh issue` for issues
  - Use `gh workflow` for workflow operations
  - Do not use raw git commands for GitHub-specific features

## Infrastructure

- **Docker images** are published to `ghcr.io/project-hort/hort-{server,worker}` by the Docker Publish CI workflow on every push to main and on release tags. The canonical service image is `ghcr.io/project-hort/hort-server`.
- **GitHub Pages site** (`/site/` directory): Combined landing page + Starlight docs, deployed to `hort.rs`.
