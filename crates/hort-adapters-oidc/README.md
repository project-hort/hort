# hort-adapters-oidc — OIDC Identity Provider Adapter

## Layer

Outbound adapter — no `hort-app` dependency (leaf adapter over
`hort-domain` + `hort-config`). Requires >= 85% coverage.

## Responsibility

Validates IdP-issued JWTs via JWKS fetched over OIDC discovery, with an
in-memory JWKS cache (TTL + rotation-aware invalidation) and multi-issuer
federation support.

## Ports

- **Implements:** `IdentityProvider` (`OidcProvider`),
  `FederatedJwtValidator` (`MultiIssuerJwksValidator`). (Any
  `OidcIssuerRepository`/`EventStore` impls found in this crate are
  test-only stubs, not production implementations.)
- **Consumes:** none — leaf adapter.

## Key types

- `OidcProvider`.
- `MultiIssuerJwksValidator`.
- `ExtraCaApplyError`.

## Rules

- `reqwest::Client::builder()` only, never `Client::new()` (ADR 0010) — the
  internal HTTP client is built explicitly citing this rule.
- JWKS is fetched over TLS verified against the system trust store plus
  `HORT_EXTRA_CA_BUNDLE` — no `insecure_jwks_url` knob exists or may be
  added (ADR 0018).
