# Testing Guide

How testing works for Hort: unit tests, DB-backed integration tests, the
structural guard rails, and the end-to-end (E2E) harness. Coverage targets
per crate layer live in `CLAUDE.md` → *Test Coverage Tiers*.

## Tiers

| Tier | Command | Needs |
|------|---------|-------|
| **1 — unit (every push)** | `cargo test --workspace --lib` | nothing |
| **1 — lint** | `cargo fmt --all -- --check` + `cargo clippy --workspace --all-targets -- -D warnings` | nothing |
| **1 — structural guards** | see below | nothing (source/fixture scans) |
| **2 — integration (DB)** | `cargo test --workspace` | PostgreSQL (`DATABASE_URL`) |
| **3 — E2E (native clients)** | `./scripts/native-tests/run.sh --hort=compose` | Docker (brings up `deploy/compose/`) |

### Unit + lint (Tier 1)

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --lib
cargo audit --deny warnings
```

### Structural guard rails (Tier 1 — DB-free source/fixture scans)

```bash
cargo test -p hort-server --test ephemeral_keyspace_exhaustive   # keyspace registry
cargo test -p hort-app    --test no_bcrypt                       # Argon2id-not-bcrypt
cargo test -p hort-config --test alpha_fixtures                  # alpha gitops fixtures
cargo test -p hort-domain --test streaming_metadata_port         # ADR 0026 streaming-metadata contract
cargo test -p hort-app    --test no_sensitive_drops              # ADR 0030 sensitive-table drop guard
cargo test -p hort-app    --test retention_registration_guard    # ADR 0030 eventstore-retention permitted-category guard
cargo test -p hort-app    --test no_retired_config_names         # ADR 0029 retired env-var / Helm-key straggler guard
```

### Integration tests (Tier 2 — requires PostgreSQL)

```bash
docker compose -f scripts/alpha-fixtures/compose-deps.yml up -d postgres
DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
  cargo test --workspace
```

`hort-adapters-postgres` / `hort-adapters-storage` DB-backed tests run in
parallel against one shared database — every test touching the DB must carry
the crate-wide `#[serial(hort_pg_db)]` key (see `CLAUDE.md` → DB-backed test
isolation).

## End-to-end (E2E) — the native-tests runner

The canonical E2E harness is `scripts/native-tests/run.sh`. It builds **one
client image** carrying every client tool (twine/pip, npm, cargo, skopeo, psql,
`hort-cli`), then runs each self-describing scenario as a throwaway container
against a hort stack — either one it brings up from
`deploy/compose/docker-compose.yml` itself, or an external hort you point it at.

```bash
# compose mode: bring up deploy/compose, run every available scenario
# in-network, tear down. This is the CI gate.
./scripts/native-tests/run.sh --hort=compose

# A subset (by group or scenario; both `--flag value` and `--flag=value` work):
./scripts/native-tests/run.sh --hort=compose --group clients
./scripts/native-tests/run.sh --hort=compose --scenario pypi

# external mode: against an already-running hort (no stack management):
HORT_URL=https://hort.example.com \
KEYCLOAK_URL=https://idp.example.com/realms/hort \
  ./scripts/native-tests/run.sh --hort=external --group clients

# Inventory with per-mode availability (runs nothing):
./scripts/native-tests/run.sh --list
```

Scenarios live at `scripts/native-tests/scenarios/<group>/<name>.sh`, each
declaring its infrastructure needs in a `# requires:` header (empty ⇒ only
hort+keycloak; tokens: `db`, `worker`, `egress`, `compose`, `compose:<overlay>`).
Exit codes: `0` pass, `1` fail, `77` self-skip. See
`scripts/native-tests/README.md` for the full contract and how to add a scenario.
Groups today: `clients` (pypi, npm, cargo, oci), `proxy` (oci-mirror,
oci-mirror-name-prefix, pull-dedup), `gitops`, `quarantine` (patch-candidate).

## Host-side + kind suites

Some smokes can't run as containerized clients — they restart the compose stack
with config overlays, or mint server-signed service tokens via
`docker compose exec hort-server`. Those live in sibling host-side suites:

- **`scripts/host-tests/`** — host-orchestration smokes (gitops-policies,
  vulnerability-scan, rescanning, task-framework, notifications ×2,
  machine-identity federation). Run on the host:
  `bash scripts/host-tests/run.sh` (or any script individually, or `--list`).
  See `scripts/host-tests/README.md`.
- **`scripts/k8s-tests/`** — kind-cluster smokes (gitops-k8s-configmap,
  k8s-rotation). Need a `kind` cluster, not the compose stack. See
  `scripts/k8s-tests/README.md`.
- **`scripts/e2e/curation/run.sh`** — the curator-surface smoke.

## CI

- **GitLab (`.gitlab-ci.yml`) — canonical for everything except E2E.** Lint,
  unit, coverage, integration, `cargo audit` / `cargo deny`, the SonarQube gate,
  image builds (hort-server + hort-worker via **buildah**), Helm publish, release
  SBOM. Its runners are buildah/Kubernetes-based (no docker daemon), so the
  compose-based E2E does **not** run here.
- **GitHub Actions — runs the E2E gate.** `e2e.yml` runs
  `scripts/native-tests/run.sh --hort=compose` on `ubuntu-latest` (which has
  docker + compose) for pushes/PRs to `main` and `release/**`, for `v*` tags,
  and — via `workflow_call` — as `release.yml`'s release gate. `ci.yml`
  (lint/unit/coverage/integration/audit/deny), `codeql.yml`,
  `docker-publish.yml` (images on `v*` tags), `release.yml`, and the weekly
  `scheduled-container-scan.yml` also live here.

## Coverage targets

See `CLAUDE.md` → *Test Coverage Tiers*: `hort-domain` and `hort-app` require
100%; all other crates require ≥ 85% on new code. Enforced by the coverage
gate in CI.
