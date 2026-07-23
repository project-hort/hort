# hort-app — Application Layer

## Layer

Application — orchestrates domain entities and outbound port traits from
`hort-domain` into use cases. No SQL, no HTTP-framework imports, no storage
driver imports; the only `hort-*` dependency is `hort-domain` (plus
`hort-config`, itself zero-I/O, for `ApplyConfigUseCase`). Requires 100%
test coverage (CLAUDE.md Test Coverage Tiers) with all outbound ports
mocked.

## Responsibility

Implements the use cases that inbound adapters (`hort-http-core` and every
`hort-http-<format>` crate) and the composition root (`hort-server`) call
into: artifact ingest/promotion/quarantine/curation, RBAC and API-token
issuance/validation, gitops apply (`ApplyConfigUseCase`), the CAS-scrub and
retention/purge sweeps, the WASM-side task handlers driven by
`hort-server`'s scheduler (`task_handlers/`), event-store publishing and
per-subscription notification dispatch (`dispatcher/`,
`event_store_publisher.rs` — see
`docs/architecture/explanation/event-notifications.md`), and the
gitops-config apply-time linter (`lint/`, ADR 0015). It calls port traits
from `hort-domain`; it never imports a concrete adapter type (`sqlx`, S3,
`wasmtime`) — those are wired at startup in `hort-server`.

## Ports

- **Implements:** none — this layer sits above the port traits, it does not
  satisfy them.
- **Declares:** one additional port whose contract composes domain
  primitives with async/I/O concerns that don't belong in the zero-I/O
  domain crate — `ports::upstream_metadata::UpstreamMetadataPort`.
- **Consumes:** the full `hort-domain::ports` set via `Arc<dyn _Port>`
  fields injected into each use case / task handler at construction. Every
  new task handler mirrors this shape — depends on ports, not concrete
  use cases (see CLAUDE.md's `CronRescanTickHandler`-mirroring rule).

## Key types

- `use_cases/` (59 files) — one use case per file, e.g. `ArtifactUseCase`,
  `QuarantineUseCase` (`quarantine_use_case.rs`), `PromotionUseCase`
  (`promotion_use_case.rs`), `ApplyConfigUseCase`
  (`apply_config_use_case.rs`), `PatValidationUseCase`.
- `task_handlers/` — the `TaskHandler` port implementations
  `hort-server`'s cron scheduler invokes (`cron_rescan_tick`,
  `retention_evaluate`, `retention_purge`, `scan`, `staging_sweep`, …).
- `argon2_hash.rs` — the single Argon2id facade shared by PAT and
  user/admin-bootstrap password hashing (the "Argon2id, not bcrypt"
  invariant — see `no_bcrypt` guard test).
- `cli_session_signing.rs` / `oci_token_signing.rs` — Ed25519 JWT
  signers for CLI session tokens (ADR 0013) and OCI Distribution-Spec
  token exchange, sharing one signing primitive with distinct `aud` /
  `token_kind` claims.
- `dispatcher/` — per-subscription notification delivery consuming the
  `event_store_publisher` broadcast channel.
- `lint/` — the apply-time linter enforcing secure-by-default rejection
  rules over gitops-desired permission grants and claim mappings.

## Rules

- No SQL, no HTTP-framework, no storage-driver imports — I/O happens only
  behind the port traits this layer consumes.
- 100% branch coverage required, with every outbound port mocked (CLAUDE.md
  Test Coverage Tiers) — this crate enforces invariants across ports.
- New task handlers depend on `Arc<dyn _Port>`s only, mirroring the
  established handler shape — not concrete use cases (CLAUDE.md Reviewer's
  discipline example).
- A new field on a gitops policy type must be either enforced by the
  consuming use case here or rejected at apply time by `lint/` — an
  accepted-but-inert field is a blocking finding (ADR 0015).
