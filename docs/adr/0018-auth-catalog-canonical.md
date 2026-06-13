# 0018 — The authentication catalog is canonical

- **Status:** Accepted
- **Enforced by:** `docs/auth-catalog.md` is the single source of truth for every inbound authentication mechanism and inbound-gating trust anchor; a mechanism not in the catalog, or an auth change that does not update the catalog in the same PR, is a review hard-block. On inbound-auth conflicts the catalog outranks any other design document (protocol specs still outrank it).
- **Supersedes:** —

## Context

Authentication is the highest-stakes surface and it accreted many mechanisms over time (PAT bearer, federated exchange, OCI bearer challenge, CLI sessions, refresh, service accounts). Without one reconciled view it is impossible to answer "what are all the ways a caller can prove identity, and what guards each?" — and a `Deprecated`/`Forbidden-in-release` path can quietly gain a new call site.

## Decision

Every way a caller proves identity to the system, and every trust anchor that gates inbound auth, has **exactly one schema-complete entry** in `docs/auth-catalog.md`. A not-in-catalog mechanism is a hard block (mirrors [0017](0017-metrics-catalog-canonical.md)). Any PR that adds, removes, or alters an auth path, token kind, credential form, cap, or trust anchor updates the catalog in the same change.

Catalogued status is load-bearing: a `Forbidden-in-release` mechanism must not be reachable in a release build; a `Deprecated` mechanism (whose entry names its replacement) must not gain a new call site; a federation/exchange path must meet its catalogued ship-gate guardrails (`jti` replay defence, `aud`→SA binding, non-empty claims) before it is `Active`.

The catalog is an **engineering control spec + traceability map only** — it is explicitly not evidence of regulatory conformity, and may not be cited as such.

## Consequences

- The complete inbound-auth surface is enumerable and each entry's guards are explicit.
- A deprecated/forbidden mechanism cannot silently spread; the catalog gates it.
- Distinct mechanisms with similar names (e.g. `AuthenticateUseCase::lockout` vs `PatValidationUseCase::pat_lockout`) stay disambiguated — a PR "extending the lockout policy" must name which it touches.

## Alternatives considered

- **Document auth per-change only (scattered design docs).** Rejected: no reconciled cross-cutting view; conflicts between scattered documents have no tie-breaker, and the full surface is never enumerable.
- **Treat the catalog as a compliance attestation.** Rejected explicitly: it is an engineering control spec; citing it for regulatory conformity is forbidden by its own §1.1.

## References

- `docs/auth-catalog.md`.
- The architect skill → Authentication Guardrails (catalog-enforced).
