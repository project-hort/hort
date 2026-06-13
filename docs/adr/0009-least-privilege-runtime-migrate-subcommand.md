# 0009 — Least-privilege runtime; migrations are a separate subcommand

- **Status:** Accepted
- **Enforced by:** the serve path may **check** `_sqlx_migrations` (via `migrate::assert_current`) to refuse to start against a stale schema, but must not call `sqlx::migrate!().run()` / `migrate::run()`. Schema changes belong to the dedicated `migrate` subcommand. The architect anti-pattern *runtime-process applies schema migrations* is a review hard-block.
- **Supersedes:** —

## Context

If the long-running service connects with a role that can run DDL, then a bug or a compromise of the serving process can `DROP`/`ALTER` the schema. The prototype ran migrations from the serving process with a high-privilege DSN — the runtime had far more authority than its job (serving requests = DML) required.

## Decision

The runtime DSN is **least-privilege (DML only)**. Schema migrations run from a dedicated `migrate` subcommand under a separate role that has DDL. The serve path is allowed to *read* `_sqlx_migrations` through `migrate::assert_current` and **refuse to boot** against a stale schema — but it never applies migrations itself.

DB-only subcommands (`migrate`, `reconcile-groups`) parse a `MinimalConfig`, not the full `Config`, so they do not drag in storage / public-base-url configuration they do not need.

## Consequences

- A compromised or buggy serving process cannot alter the schema — it lacks DDL rights.
- Deployment runs migrations as an explicit, separately-privileged step (e.g. a Kubernetes Job), decoupled from rolling out the service.
- Boot still fails loudly on a schema/binary mismatch (`assert_current`), so a stale deploy is caught, not silently run against the wrong schema.
- A new DB-only subcommand must use `MinimalConfig`; reaching for `Config::from_env` re-introduces the storage/base-url tax.

## Alternatives considered

- **Runtime auto-migrates on boot (prototype behaviour).** Rejected: gives the serving role DDL, which is the privilege the whole ADR removes.
- **No boot-time schema check.** Rejected: a stale binary against a newer schema (or vice versa) would run silently; `assert_current` makes it fail fast without granting DDL.

## References

- `crates/hort-server/src/migrate.rs` (`assert_current`), `crates/hort-server/src/cli/migrate.rs`.
- The architect skill → anti-patterns *runtime-process applies schema migrations*, *subcommand uses full `Config` when only DB is needed*.
