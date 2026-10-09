# Hort Development Guidelines

Auto-generated from all feature plans. Last updated: 011

## Active Technologies
- Rust 1.94+ (backend) + git2, axum
- Rust 1.94+ + axum, sqlx, tokio, reqwest
- Rust 1.94+ + axum, serde, serde_json
- Planned, post-v1 (not wired into the build today — see
  `hort-formats/README.md`): wasmtime 21.0+, wasmtime-wasi, wit-bindgen,
  filesystem for WASM binaries. Format handlers are currently compiled-in
  Rust structs behind `FormatHandler` (ADR 0005), not `$WASM_PLUGIN_DIR`
  modules.
- PostgreSQL (existing)

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

**DB-backed test isolation (parallel-safety contract).** The DB-backed suites have **three modes**, and a reviewer has to know which one a test is in:

- **`test_support::isolated_db_from`** — creates and migrates a fresh `hort_test_<epoch>_<uuid>` database per call. This is the overwhelming majority of the harness: **66 files** (58 in `hort-adapters-postgres`, 8 in `hort-server`) as measured on 2026-10-08, usually reached through a module-local `maybe_pool()`. The figure moves whenever a DB test is added or relocated, so re-measure rather than trusting it:
  ```bash
  grep -rl 'isolated_db_from(' crates/*/src crates/*/tests --include='*.rs' \
    | grep -v 'test_support\|db_tests_are_serialized\|db_gate_not_silent'
  ```
  (the two excluded guards name the helper as a pattern to scan for, not as a call).
- **`test_support::shared_migrated_pool`** — connects to and migrates the shared `DATABASE_URL` target, for the few tests that deliberately exercise shared-DB behaviour (isolating them would defeat the point of the test): **4 files**, all in `hort-adapters-postgres`.
- **A hand-rolled throwaway database on the `DATABASE_URL` target** — an `admin_pool()` (now `test_support::connect_or_panic`) plus the file's own `create_temp_db` / `drop_temp_db`, because these tests drive the migrator itself and so cannot be handed an already-migrated database: **5 files**, `hort-server/tests/migrate_{assert_current,harden_events,schema_compat,fleet_fence}.rs` and `hort-worker/tests/schema_compat_boot.rs`, 35 DB-backed tests. All 35 carry `#[serial(hort_pg_db)]`; until the sweep that added the guard below, only `migrate_fleet_fence.rs`'s 6 did, and the other 29 ran their `CREATE DATABASE` + full migration set (cluster-global `CREATE ROLE` included) unkeyed — they fell through the *wording* of the old rule, which named `hort-adapters-postgres` and so did not reach `hort-server` / `hort-worker`. There is also one test in a sixth file that hand-rolls a throwaway database inside an otherwise `isolated_db_from` file (`hort-adapters-postgres/tests/api_tokens_migration.rs::idempotent_after_rollback`, whose `DROP TABLE … CASCADE` cannot be let near a database anything else will reuse); a mode-by-file listing will not find it, which is why the guard scans functions.

Two tests sit outside all three modes and are worth knowing about as a reviewer: `hort-adapters-postgres/tests/api_tokens_migration.rs::idempotent_after_rollback` (above) and `hort-worker/tests/composition_smoke.rs::build_app_context_registers_seed_import_handler`, which drives the worker's composition root against the configured `DATABASE_URL` itself and so migrates that shared target through `connect_or_panic` + `migrate_or_panic` before calling in. Both carry the key.

Either way every DB-backed test in the workspace runs against **one Postgres server** — inline `#[cfg(test)]` `--lib` tests *and* `crates/*/tests/` integration tests — and within a binary libtest runs tests on many threads at once. The `cargo test --tests` CI job (`test:integration`) builds the lib as a unittest target, so inline tests run there too.

**What the key actually reaches, measured — and what that rests on.** The workspace declares `serial_test = "4"` with default features and `Cargo.lock` contains **no `fslock`**, so the `file_locks` feature is off and `#[serial(key)]` is a **process-local** lock (`once_cell` + `parking_lot`), not a file lock. It therefore orders tests **within one test binary** and nothing else. That is enough today only because cargo runs test binaries **strictly sequentially**: measured on the pinned toolchain (cargo 1.97.1, and again on 1.98.1), three targets sleeping 3 s each ran back to back — binary `a` ended at `…940.077247` and `b` started at `…940.078832`, 1.6 ms later, with no overlap. So the protection against cross-binary collision is a property of **the runner's scheduling**, not of the key: a file-local mutex would reach exactly as far. **`cargo nextest` runs test binaries in parallel by default** — adopting it would void this assumption silently, with every DB-backed test still wearing a key that no longer orders it against the binary next door. Any move to a parallel test runner has to re-establish cross-process serialization first (`serial_test`'s `file_locks` feature is the cheap route) and amend this section.

**Therefore: every test in the workspace that acquires a real Postgres connection — whatever the crate, and whether it reaches the server through `maybe_pool()` / `shared_migrated_pool()` / `connect_or_panic()` or through a hand-rolled `PgPool::connect` — MUST carry the workspace-wide `#[serial(hort_pg_db)]` key.** A DB-gated test without it is a **blocking review finding**: it silently reintroduces the identity-shifting flake fixed in `ed79360a`. The rationale is crate-agnostic, and the old crate-scoped wording is exactly how 29 `hort-server` / `hort-worker` tests ran unkeyed for as long as they did.

**The key is the *only* serialization mechanism — no file-local mutex beside it.** In reach a file-local `Mutex` is the key's equal (see the measurement above), so this is not an argument about coverage; it is about composition. Two independent serializations do not compose into one order: a test holding only the mutex and a test holding only the key run concurrently, and a reviewer cannot rule that out by reading either test alone. Five files carried such a mutex (`jobs_repository`, `rescan_candidates`, `scanner_registry_repository`, `user_deactivation_notify`, `api_tokens_migration`); all five now carry the key alone.

The rule holds on both paths, for two different reasons, and both halves are load-bearing:

- On the **shared** path there is no per-test isolation at all: no transaction rollback, no schema-per-test, no truncation. Several adapters do global-scope work (e.g. the `save_managed` gitops-partition full-reconcile, `pg_stat_activity` probes, unfiltered `COUNT`/`list_*` reads), so a concurrently-running sibling reads and deletes another test's rows. Production tolerates this because the only writer of these partitions is single-flight by design (gitops apply is single-process per boot lock); tests must honour that same contract.
- On the **isolated** path a per-test database is **not** isolation from cluster-global work. `CREATE ROLE` (the migration set creates roles), `pg_stat_activity` probes, `CREATE`/`DROP DATABASE` and the shared catalogs the stale-database sweeper touches are all **server-wide**: a test in its own database still collides with a sibling through the cluster, and the serial key is what keeps that collision from happening.

Coverage % is necessary but **not sufficient**: a DB-backed test that is correct serially but interferes with a concurrently-running sibling is a defect, not passing.

**Enforcement: `crates/hort-app/tests/db_tests_are_serialized.rs`**, a DB-free sub-second source scan in the same family as `db_gate_not_silent` — so `cargo test --workspace` runs it automatically. It reports every test function (inline `#[cfg(test)]` *and* `crates/*/tests/`) that reaches `test_support::{isolated_db_from, shared_migrated_pool, connect_or_panic}` — directly or through a same-file helper, transitively — or opens a raw `PgPool::connect` / `PgConnection::connect*`, and carries no `#[serial(hort_pg_db)]`. **It has no allow-list, by design**: a site that genuinely should not carry the key is a review conversation, not an exemption entry. Its blind spot is the one every source scan has — a helper in *another* file, or a connection opened through a macro — so the review check survives alongside it (see the architect Implementation Review Checklist).

### Code comments: state the invariant, never the provenance

**No references to issues, merge requests, or backlog items in code comments** —
no `#137`, no `backlog 097`, no `item 089`, no "found during the #137 review".
Code is the persistent artifact; issues and backlog items are ephemeral
coordination records that outlive their usefulness and rot in place. A reader
five years from now can read the code, not a closed tracker.

Write what a future reader needs in order not to break the thing:

- **Instead of** `# Skip the enqueue here (issue #131).`
  **write** `# Skip the enqueue: a parent-gated blob can never carry its own
  attestation, so the verify it would enqueue has no reachable outcome.`
- Name durable anchors freely: ADRs (`ADR 0007`), file paths, type and function
  names, env vars, and commit SHAs when a specific change is the evidence.
- Git history keeps the provenance. Put the issue/MR/backlog reference in the
  **commit message** and the **MR description**, where it belongs.

This applies to every commentable artifact in the repository — Rust, shell,
YAML (CI, compose, Helm, gitops envelopes), SQL migrations, Dockerfiles. It
does **not** apply to `CHANGELOG.md` (issue references are the changelog's
own convention) or to ADRs and other `docs/` prose, which are themselves the
durable decision record.

Enforcement is a review check: grep the diff's added comment lines before
pushing. Legacy references predating this rule are not swept opportunistically
— removing one is fine when you are already editing that comment for another
reason.

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
- **Destructive DDL in the same release that removed the last code reference** — a migration that drops/renames/narrows a schema identifier ships only in a release strictly *after* the last release whose code referenced it (expand/contract). `expand_contract_guard` rejects it via `migrations/CONTRACTIONS.toml` version arithmetic; the fix is to schedule the contraction one release later, never to edit the manifest into passing. New manifest entries carry a mandatory reviewer step (`git grep <identifier> v<reference_removed_in>` — the hermetic guard cannot see past releases). (see ADR 0030 amendment (c))
- **Cross-opt-in collapse of a Gate-2-style invariant** — any new operator-opt-in that lets untrusted input influence the release-gate computation (`trust_upstream_publish_time`-shaped, `scan_backends:[]`-shaped, `IndexMode`-shaped) must enumerate its interaction with every other such opt-in in its design doc *before* implementation, via the architect doc's "Cross-opt-in interaction matrix". The canonical exemplar: `trust_upstream_publish_time = true` × `scan_backends: []` together collapse the Gate-2 observation window to ≤ sweep-tick latency (apply-time linter rejects the combination, `trust_upstream_publish_time_requires_scan_backends` rule). The structural close is fail-closed apply-time rejection of the dangerous combination, never a runtime "fallback to a degraded authority" path. (see ADR 0016)

## Implementation Discipline — when to deviate from the design

**The design wins by default.** An implementation may deviate from the design — a plan document, an initiative backlog item, an explicit "mirror X" instruction, or established codebase precedent — only when the alternative is **objectively better than the design**. Not merely possible, not merely arguable.

What "objectively better" is *not*:

- **"Defensible," "plausible," "I can construct an argument for it."** These are hedges, not verdicts. If that is all you can say, the design wins.
- **"It works."** Most alternatives work. The bar is *better*, not *workable*.
- **A choice the design left open.** Picking between two unspecified alternatives is a coding judgement, not a deviation.

What "objectively better" *is*:

- A concrete advantage the design did not have (e.g., an alternative that removes a per-request allocation or a network round-trip the design's structure otherwise forces).
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
cargo test --workspace                                     # full suite: lib + ALL tests/ integration targets (DB-gated tests self-skip w/o DATABASE_URL)
cargo audit --deny warnings                                # advisories (ALWAYS — see note)
cargo deny check                                           # advisories+bans+licenses+sources (ALWAYS — see note)
```

**`cargo test --workspace` is the default pre-push test command — NOT `--lib`.**
It runs the full local suite — every crate's `--lib` unit tests AND every
`tests/` integration target. DB-gated tests self-skip without `DATABASE_URL`,
so no database is needed: a bare `cargo test --workspace` runs every DB-free
test and early-returns from the rest (measured: 12,368 passed / 9 ignored /
0 failed, identical to the same command *with* `DATABASE_URL` set).
**A self-skipped DB-gated test reports `ok`, not `ignored`** — libtest has no
dynamic-ignore verdict, so the skip is an early `return` from a test that counts
as passed. The `ignored` column therefore says nothing about how many DB tests
ran: none of those 9 is DB-gated (5 slow-seeding, 2 broker test-infra TODOs,
2 doc-tests). An earlier wording here promised
`ignored, requires DATABASE_URL`; that described the pre-self-skip `#[ignore]`
world, which the conversion to runtime self-skip retired.

**A `DATABASE_URL` that is set but unreachable is a hard failure, not a skip.**
The self-skip is the `env::var` read and nothing else: once a URL is in hand the
operator has declared a database, so
`test_support::{isolated_db_from, connect_or_panic, shared_migrated_pool}` panic
rather than hand back a `None` the caller cannot tell apart from "no database
configured". Before that, a closed-port `DATABASE_URL` produced 12,350 passed /
1 failed / 7 ignored — 488 of the 489 tests that touch the database claiming
`ok` without opening a connection — and burned ten minutes of `acquire_timeout`
doing it. Never
reintroduce a `.ok()` on a Postgres connect in a fixture; `db_gate_not_silent`
rejects it. This SUPERSEDES the old
`--lib`-only gate, which silently excluded **every** `tests/` integration target
— including the DB-free mock-based ones (the per-format HTTP-handler tests under
`hort-http-*/tests/`, *and* the structural guards below). That blind spot let a
change pass the local gate but fail CI's integration job — exactly how the
read-path auth fix's masked admin-security handler test slipped through. Among
the structural guard rails `--workspace` now runs automatically: `ephemeral_keyspace_exhaustive` (keyspace-registry
exhaustiveness), `no_bcrypt` ("Argon2id, not bcrypt" invariant, ADR 0028-adjacent),
`alpha_fixtures` (alpha-fixture gitops-tree parse + cross-validate
regression guard), `streaming_metadata_port`
(ADR 0026 — pins the `FormatHandler` metadata methods' `&mut dyn Read`
streaming contract and bans reintroducing the deleted `metadata_body_bytes`
buffering helper on the metadata consumers), `no_sensitive_drops` (ADR 0030 —
token-aware source-scan of `migrations/` that rejects `DROP TABLE` /
`DROP TABLE IF EXISTS` / `ALTER TABLE … DROP CONSTRAINT` against a maintained
sensitive-table list: the authorization model, credential store, event store,
repository config, and task queue), `expand_contract_guard` (ADR 0030 —
enforces the expand/contract policy: destructive DDL (`DROP COLUMN` /
`DROP TABLE` / table-or-column `RENAME` / column type change / `SET NOT NULL`)
ships only in a release strictly after the last one whose code referenced the
identifier. Cross-checks every migration's destructive DDL against the
checked-in manifest `migrations/CONTRACTIONS.toml`, requires the workspace
version to exceed each entry's `reference_removed_in`, and rejects a
still-referenced identifier in `crates/*/src`), `capped_stream_reads` (ADR 0007 —
pins that a **bounded** `EventStore::read_stream` exists in exactly one
production file: every `.read_stream(` call in `crates/*/src` passes either
`u64::MAX` (an unbounded category, no budget to truncate), a forwarded
`max_count` inside a `fn read_stream(` (an `EventStore` decorator delegating),
or `STREAM_EVENT_CAP + 1` and only in `hort-app/src/use_cases/mod.rs`. Any
other budget is a read that cannot tell a complete stream from a truncated
one — a reverse scan over it silently answers about the *oldest* N events, so
a superseded scan verdict reads as current and the `ArtifactRejected` after it
is invisible to the release authorization. The correct idiom predated the
guard and convention alone did not hold it: ten capped-read sites across seven
files got it wrong, nine of them reading exactly `200` with no overflow
detection. Carries a counter-assertion that the scan still
finds both audited reads, so a rename cannot make it vacuously green),
`retention_registration_guard` (ADR 0030 —
asserts the code-held eventstore-retention rule set
(`canonical_retention_rules`) only ever registers the permitted categories
`{Artifact, AuthAttempts, DownloadAudit, TokenUse}`, with a no-wildcard
exhaustiveness match over every `StreamCategory` so a future variant — or an
accidentally-seeded privileged category — cannot silently become eligible for
automated stream deletion), `db_tests_are_serialized` (the parallel-safety
contract above — reports every test function reaching a real Postgres
connection without `#[serial(hort_pg_db)]`, with no allow-list),
`db_gate_not_silent` (rejects any
`PgPool`/`PgConnection` connect whose error is discarded with `.ok()`, and pins
`hort-adapters-postgres`'s isolation harness to a single `?`-shaped skip — the
`DATABASE_URL` read. A DB-gated fixture only reaches a connect because the
variable was set, so a swallowed connect error is a configured database that
did not work being reported as no database at all, and the test then says `ok`
without having run), `status_decode_fails_closed` (the same hazard class
carried from a discarded Postgres *connect* to a discarded
quarantine-**status** read or decode: rejects `.ok()` / `unwrap_or*` wherever
the receiver it throws away or the fallback it substitutes names the
quarantine status. `QuarantineStatus::None` is the most permissive state in
the system — `Artifact::is_downloadable` admits it and the default
`ReleasedOnly` index mode serves it — AND the state a swallowed decode
naturally defaults to, so a discarded error there does not degrade a serving
decision, it inverts it. The predicate is receiver-scoped rather than
statement-scoped, which is what lets it run with **no allow-list**: a
discarded *artifact load* beside a status read, or a fallback on the field
next to a status cell, are not hits. Carries a counter-assertion that the
corpus is real, that the one codec
(`hort_adapters_postgres::quarantine_status_sql`) still defines both halves of
its encode/decode pair, and that the read paths still decode through it — so a
rename cannot make the scan vacuously green. Same blind spot as its siblings:
a decode reached through a differently-named local helper),
`cas_reads_are_verified` (ADR 0003's read-verification amendment — asserts
that every `impl StoragePort for` under `crates/hort-adapters-*/src`
constructs a `VerifyingReader` inside its own `get`. The wrap was hand-written
at two sites with nothing holding it: a third adapter returning its backend's
raw stream compiles, passes clippy and passes the suite, and the only thing it
breaks is a guarantee no test stated — `VerifyingReader::poll_read` is the
single production construction point of `CasIntegrityFailure`, so an adapter
without the wrap makes at-rest corruption indistinguishable from a clean read
for every consumer and `CasScrubUseCase` sweeps corrupt storage reporting
success. **Function-scoped**, which is load-bearing rather than fastidious:
both adapters carry a `get_range` doc comment naming `VerifyingReader` in
order to say it does *not* apply there, so a file-scoped scan stays green
after the wrap itself is deleted. The scope is derived — an outbound adapter
lives in an `hort-adapters-*` crate (ADR 0008) and a `#[cfg(test)]` test
double is excluded by how it is compiled, not by an entry — so there is **no
allow-list**. Carries a counter-assertion pinning the two known production
implementations by type and file, so renaming the port, the method or the
reader cannot make it vacuously green. Blind spot: a `get` that delegates the
wrap to a helper reads as unverified — a false positive, and a review
conversation about where the wrap belongs) are pure
source-/fixture-scan guards — no database, sub-second — enforcing structural invariants that a
rename or a stray `use` silently breaks. (A stale keyspace registry once shipped
undetected because the gate then ran only `--lib`.) Because `cargo test --workspace`
now runs every `tests/` target automatically, a new DB-free structural guard
under `crates/*/tests/` needs **no** manual gate-list entry — it runs by virtue
of being a `tests/` target. Keep such guards DB-free (or `DATABASE_URL`-self-
skipping) so the gate stays runnable without a database.

**`cargo audit` is an unconditional pre-push check — NOT conditional on touching
`Cargo.toml`/`Cargo.lock`.** It scans the locked dependency graph against the
**live RustSec advisory DB**, which updates continuously: a newly-published
advisory against an already-pinned crate flips the blocking CI security gate
(`cargo audit --deny warnings`) red with **zero code or `Cargo.lock`
changes**. Inferring the gate's result from "no dependency change" is a known
blind spot — actually run the command; do not report the gate satisfied without
its output. `security:cargo-audit` runs via `.rules-code-changed` — every
code-changing MR/branch push, not just `main`/release/tags — but its
`changes:` trigger fires on a *diff*, not on the live advisory DB gaining a
new entry: a docs-only or otherwise non-code-changed push won't even run the
job, so a freshly-published advisory against your already-pinned deps stays
invisible until something next touches a code path. This local check is the
only thing that catches that window. On a hit, prefer upgrading the flagged crate (`cargo update -p
<crate> --precise <fixed-version>`, `Cargo.lock`-only) over an ignore; an ignore
must be added to **both** `.cargo/audit.toml` and `deny.toml` (the
`security:advisory-sync` job enforces parity) and is a deliberate, justified risk
acceptance, not a default.

**`cargo deny check` is ALSO unconditional — and is NOT redundant with `cargo
audit`.** The two tools walk the dependency graph differently: `cargo audit`
scans the **full `Cargo.lock`**; `cargo deny` walks the **active build graph**
(it excludes crates reachable only through unused optional features). They also
read **separate ignore lists** (`.cargo/audit.toml` vs `deny.toml`). The CI
`security:cargo-deny` job runs `cargo deny check`, also via
`.rules-code-changed` (every code-changing MR/branch push, same trigger as
`security:cargo-audit` — not `main`/release/tags-only). Same blind spot as
above applies: the `changes:` trigger needs a diff, so a build-graph shift
caused purely by a newly-published advisory or a change elsewhere in the
dependency resolution (not a `Cargo.lock` edit in *this* push) won't
necessarily re-run the job — this local check is the only thing that will
catch it. The canonical trap (rc.10, RUSTSEC-2023-0071): an advisory ignored AUDIT-ONLY in
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
- **Regenerate third-party attribution on ANY dependency-graph change** — if the
  change adds/removes/re-versions a **non-workspace** crate in `Cargo.lock` (a dep
  bump, `cargo update -p`/`-w`, adding/removing a dep or a crate-pulling feature),
  run `scripts/regenerate-attribution.sh` and commit the updated
  `THIRD-PARTY-LICENSES.{md,json}` **in the same change**. The
  `security:attribution-sync` gate is **release-scoped** (tags + `main`/`release/*`
  + MRs targeting them — issue #30), so it will **not** flag stale attribution on a
  feature/`develop` pipeline — it is the fail-closed release backstop, not the
  per-MR check. A dep-changing commit without the regen leaves `develop` stale and
  fails the next release-relevant pipeline (this is exactly how the `spin 0.9.8 →
  0.9.9` bump broke the `v0.9.9-beta.4` cut). A release **workspace-version-only**
  bump (`X.Y.Z-dev → X.Y.Z-<pre>`) is exempt (no third-party change) but still runs
  `check-attribution` as part of the cut. (see ADR 0049 / ADR 0047)

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
- `:latest` is only set for stable releases (no `-rc`, `-beta`, `-alpha`, etc.)
- `:1.0`, `:1.1` series tags are set automatically via semver parsing
- `:sha-<commit>` is set for every (tag) build
- **`-alpha.N` tags are excluded from this whole public ghcr publish** — an
  internal pre-release (see *Releases* below and
  [ADR 0048](docs/adr/0048-release-branch-staging-strategy.md)) is
  build/published only to the internal registry via the GitLab pipeline,
  never to ghcr. `-beta`/`-rc` are unaffected (reserved for a possible
  future public pre-release track, not currently used).

### Releases

**Pre-releases are throwaway-branch tags cut off `develop`; final releases are
tagged on `main`.** See **`RELEASING.md`** and
[ADR 0048](docs/adr/0048-release-branch-staging-strategy.md) (also
[the glossary](docs/glossary.md)) for the full model and the exact
step-by-step. In short:

- **`develop` carries an `X.Y.Z-dev` marker** (bumped once per cycle via a normal
  MR, so a build off `develop` reports the honest unreleased-next version). An
  **internal pre-release** (`vX.Y.Z-alpha.N`) is a **version-bump commit cut on
  a `test/vX.Y.Z-alpha.N` branch off `develop`, tagged, and NOT merged back**
  — unlike a one-off pre-release tag, this branch **is pushed** (so staging
  can deploy it continuously), but its version-bump commit must never land on
  `develop` or `main`. The bump touches `Cargo.toml` workspace version +
  `Cargo.lock` + `deploy/helm/hort-server/Chart.yaml` (`version`/`appVersion`)
  and **does not touch `CHANGELOG.md`**. This keeps `develop`/`main` free of
  per-alpha bumps while the tagged commit stays version-honest (binary +
  chart both report the pre-release version). Trade-off: alpha tags are off
  `develop`'s line, so `git describe` from `develop` won't find them — fine
  for internal builds. Alpha artifacts (images + Helm chart) build and
  publish to the **internal registry only** — see *Docker image tags* above
  and [ADR 0048](docs/adr/0048-release-branch-staging-strategy.md) D4;
  `beta`/`rc` naming stays reserved for a possible future *public*
  pre-release track (not in use today).
- **Staging deploys from published artifacts only**: `test/*` alpha tags and
  `main` — never from bare `develop` merges, since `develop` publishes no
  image or chart. It is not gated on a `main` cut, but it is gated on the
  next (on-demand) alpha
  ([ADR 0048](docs/adr/0048-release-branch-staging-strategy.md) D3).
- A **final** release (`vX.Y.Z`, no suffix) is the **`develop → main`
  promotion**. That single promotion MR is where the changelog is stamped, the
  version drops any pre-release suffix, and the `Closes #…` keywords ride.
  The `vX.Y.Z` tag is pushed on the `main` merge commit. **Issues auto-close
  only on merges to the default branch (`main`)**, so a fix's issue references
  belong on the promotion MR, not on the feature MR into `develop` — this is
  why a fix merged to `develop` leaves its issue open until the promotion.

Release-note mechanics:

- Release notes are **auto-generated by GitHub** (`generate_release_notes: true` in `release.yml`). They show the actual changelog (PRs merged, commits) since the previous tag.
- **Do NOT hardcode static release notes** in the workflow. No product descriptions, feature lists, or format counts in release bodies.
- The release workflow is at `.github/workflows/release.yml`, triggered by `v*` tags.

### Changelog and Release Notes

- Follow the [Keep a Changelog](https://keepachangelog.com/) format: record changes under `### Added` / `### Changed` / `### Fixed` / `### Security` / `### Removed` beneath the `## [Unreleased]` heading.
- **`[Unreleased]` accumulates across the entire pre-release (`-alpha`, and any future `-beta`/`-rc`) series and is stamped `## [X.Y.Z] - <date>` exactly once — at the final `develop → main` promotion.** Pre-release commits do **not** stamp or fold the changelog. (The old per-pre-release fold is retired: it produced stale section dates — a `[0.9.8] - 2026-07-03` heading that kept accreting later entries — and a manual, error-prone move at every pre-release.) An alpha's "changelog" is simply the current `[Unreleased]` at that tag; per-alpha traceability comes from the git tags plus the auto-generated GitHub release notes.
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
