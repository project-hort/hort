# 0008 — Per-format inbound-HTTP crates with a compile-time adapter-free guarantee

- **Status:** Accepted
- **Enforced by:** the dependency graph. `hort-http-core` and every `hort-http-<format>` crate carry no `hort-adapters-*`, `sqlx`, or `reqwest` dependency; an adapter import inside a format crate is an unresolved-import **compile error**. `AppContext`'s infrastructure fields are `pub(crate)`, so a format crate that reaches for `ctx.repositories`/`ctx.storage`/etc. also fails to compile.
- **Supersedes:** —

## Context

Inbound HTTP for ~18 formats could have lived as modules inside one crate that also imported the database and HTTP-client adapters. That arrangement makes it trivially easy for a format handler to "just run a query" or "just fetch upstream directly", re-creating the prototype's entanglement and bypassing the application layer's invariants (authorization, CAS, event emission).

## Decision

Split inbound HTTP into `hort-http-core` (shared primitives: `AppContext`, `ApiError`, middleware, authz) plus one `hort-http-<format>` crate per format, with composition isolated to `hort-server`. The dependency graph is **load-bearing**: per-format crates must not depend on `hort-adapters-*`, `sqlx`, or `reqwest`. A format handler obtains data only by calling a use case on `AppContext` (`RepositoryAccessUseCase`, `ArtifactUseCase`, `ContentReferenceUseCase`, …), never by touching an adapter or a `pub(crate)` infrastructure field directly.

`AppContext` may only gain `Arc<dyn Port>` fields or plain config — never a concrete `PgPool`/`FilesystemStorage`. `build_app_context` lives only in `hort-server` (the one crate that imports both adapters and inbound-HTTP types).

## Consequences

- A format handler physically cannot bypass the application layer to reach infrastructure — the violation does not compile, it is not a review judgement call.
- Adding a format means a new `hort-http-<format>` crate (not a module in `hort-http-core` or `hort-server`), keeping the guarantee intact.
- The cost is more crates and an explicit use case for each data need; that explicitness is the point.

## Consequences for review

`cargo tree -p hort-http-<format> --edges normal --prefix none` must show no `hort-adapters-*`/`sqlx`/`reqwest` edge. A missing such edge means the structural guarantee holds, not that an advisory rule was followed.

## Alternatives considered

- **One inbound-HTTP crate with format modules + adapter deps.** Rejected: makes bypassing the application layer a one-line temptation; the whole guarantee rests on the deps not being reachable.
- **Convention/review-only ban on adapter imports in handlers.** Rejected: conventions erode; a compile error does not.

## References

- `crates/hort-http-core/`, `crates/hort-http-<format>/`, `crates/hort-server/src/http.rs` + composition.
- `docs/architecture/how-to/add-a-format-handler.md`.
- The architect skill → anti-patterns *adapter import inside an `hort-http-<format>` crate*, *`AppContext` gaining a concrete adapter type field*, *format crate references `ctx.repositories`/…*.
