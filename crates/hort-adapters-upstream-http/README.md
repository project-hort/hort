# hort-adapters-upstream-http — Upstream Pull-Through HTTP Adapter

## Layer

Outbound adapter — depends on `hort-domain`, `hort-app`, `hort-config`, and
`hort-net-egress`; kept out of the `hort-http-*` inbound crates so
`reqwest` never lands on their dependency edge (ADR 0008, viewed from the
adapter side). Requires >= 85% coverage.

## Responsibility

HTTP-based pull-through upstream proxy: streams blob/manifest bytes from a
configured upstream registry into local CAS, with three auth strategies
(anonymous, Docker-token-spec bearer challenge, HTTP Basic via
`SecretPort`).

## Ports

- **Implements:** `UpstreamProxy` (`HttpUpstreamProxy`),
  `UpstreamResolver` (`CachingResolver`). (Any `SecretPort` impls in this
  crate are test-only stubs.)
- **Consumes:** `hort_app::metrics::UpstreamErrorKind` — the shared
  metrics-label enum, not a use case.

## Key types

- `HttpUpstreamProxy`, `HttpUpstreamProxyConfig`.
- `CachingResolver`.
- `classify_error`, `Challenge` / `parse_www_authenticate`.

## Rules

- `reqwest::Client::builder()` only, never `Client::new()` (ADR 0010) — the
  base client is built via `base_client_builder`, with
  `.use_preconfigured_tls(rustls_config)` for the mTLS/cert-pinning path.
- SSRF/DNS-rebind defense: routability classification lives in the shared
  `hort-net-egress` crate and is consumed here (`GuardedDnsResolver`), not
  duplicated locally.
