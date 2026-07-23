# hort-http-core — Shared Inbound-HTTP Primitives

## Layer

Inbound HTTP — shared base every per-format `hort-http-<format>` crate
depends on. Deps: `hort-domain`, `hort-app`, `hort-config`, `axum`, `tower`,
`tower-http`, `governor`, `tokio`, `dashmap`, `metrics`, and similar
framework/utility crates — no `hort-adapters-*`, `sqlx`, or `reqwest` on the
production edge (the optional `hort-adapters-ephemeral-memory` dep is
`test-support`-feature-gated, "never on the production dependency edge" per
its own `Cargo.toml` comment). Requires >= 85% coverage.

## Responsibility

Hosts the primitives every inbound-HTTP crate is built on: `AppContext` (the
composition-root-assembled struct holding every use case + a handful of
`pub(crate)` infrastructure fields), the axum middleware stack
(`wrap_with_middleware`), `ApiError`/`AppError` mapping, the authz extractors
(`AdminPrincipal`, `AuthenticatedCaller`, `WriteRepoAccess`,
`ReadRepoAccess`, `DeleteRepoAccess`, …), and shared admin/metrics handlers.
This crate is not itself a protocol adapter — it defines the shape every
protocol adapter is expressed against.

## Ports

- **Implements:** none — this crate consumes and re-exposes `hort-app` use
  cases, it does not itself satisfy an outbound port.
- **Consumes:** the full use-case surface via `Arc<dyn ...UseCase>` fields
  on `AppContext` (`ApiTokenUseCase`, `ArtifactUseCase`, `ArtifactGroupUseCase`,
  `AuthenticateUseCase`, `ContentReferenceUseCase`, `CurationUseCase`,
  `DiscoveryUseCase`, `EffectivePermissionsUseCase`, `IngestUseCase`,
  `ManualRescanUseCase`, `OciTokenExchangeUseCase`, `PatchCandidateUseCase`,
  `RepositoryAccessUseCase`, `SubscriptionUseCase`, `TaskUseCase`, and more).

## Key types

- `context::AppContext` / `AppContextParts` — the shared context struct
  every handler extracts from axum state.
- `context::AuthContext` — `.authenticate()` / `.rbac()` / `.has_auth()`.
- `error::ApiError(pub AppError)` — the shared error-to-HTTP-response
  mapping.
- `router::wrap_with_middleware` — the shared middleware stack every
  format's router is wrapped in.
- `authz::extractors::{AdminPrincipal, CurateOrAdminPrincipal,
  AuthenticatedCaller, WriteRepoAccess, ReadRepoAccess, DeleteRepoAccess}`.

## Rules

- ADR 0008: no `hort-adapters-*` / `sqlx` / `reqwest` on the production
  dependency edge — an adapter import here is an unresolved-import compile
  error, not a review finding.
- The infrastructure fields on `AppContext` (`storage`, `artifacts`,
  `repositories`, `refs`, `artifact_groups`, `content_references`,
  `artifact_metadata`, …) are `pub(crate)` — even a crate that depends on
  `hort-http-core` cannot reach them directly; every format crate must call
  the corresponding use case (ADR 0008, CLAUDE.md Anti-Patterns Checklist).
