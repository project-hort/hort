# hort-adapters-postgres — PostgreSQL Outbound Adapters

## Layer

Outbound adapter — the only crate in the workspace permitted to depend on
`sqlx` (its own module doc states this explicitly). Requires >= 85%
coverage (integration tests against a real database).

## Responsibility

Implements ~40 PostgreSQL-backed repositories and readers covering the
artifact/repository/user/RBAC domain plus the append-only event store.

## Ports

- **Implements:** a large slice of `hort-domain::ports`, including
  `ArtifactRepository`, `RepositoryRepository`, `UserRepository`,
  `EventStore`, `ApiTokenRepository`, `ArtifactLifecyclePort`,
  `RefLifecyclePort`, `PurgeGcPort`, `JobsRepository`,
  `SubscriptionRepository`, and ~30 more.
- **Consumes:** `hort_app::metrics::client_ip_bucket` (IP bucketing before
  writing `last_used_ip`) — otherwise a leaf adapter with respect to the
  application layer.

## Key types

- One `Pg<Name>Repository`/`Pg<Name>Store` struct per implemented port
  (e.g. `PgArtifactRepository`, `PgEventStore`, `PgUserRepository`,
  `PgRepositoryRepository`).
- `mappers::{RepositoryRow, ArtifactRow, ...}` — the `TryFrom` row-mapping
  layer between SQL rows and domain types.

## Rules

- **Parallel-safety contract (mandatory, not optional):** this crate's test
  suites — inline `#[cfg(test)]` and `tests/` integration tests alike — run
  in parallel against one shared database with no per-test isolation. Every
  new test that touches a real connection MUST carry
  `#[serial(hort_pg_db)]`; a DB-gated test without it is a blocking review
  finding (CLAUDE.md). `save_managed`'s global gitops-partition reconcile
  additionally carries the narrower `#[serial(gitops_partition)]` key.
- SQL lives here and only here for Postgres — no other crate issues raw SQL.
