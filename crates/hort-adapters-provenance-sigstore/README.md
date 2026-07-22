# hort-adapters-provenance-sigstore — Sigstore/Cosign Provenance Adapter

## Layer

Outbound adapter — leaf adapter with respect to the application layer
(`hort-app` used only for `UpstreamErrorKind` error classification on the
trust-root-refresh path). Requires >= 85% coverage.

## Responsibility

Implements offline Sigstore/cosign bundle verification (ADR 0027):
validates the Fulcio cert chain, embedded SCT, signature, digest binding,
and Rekor Merkle-inclusion proof against a cached, TUF-refreshed trust
root. The `verify` path makes **no live Rekor/Fulcio call** — the only live
network call in the crate is the periodic TUF trust-root refresh, kept
deliberately separate from `verify`.

## Ports

- **Implements:** `ProvenancePort` (`SigstoreProvenanceAdapter` —
  `verify`, `health_check`).
- **Consumes:** `hort_app::metrics::UpstreamErrorKind`, on the trust-root
  refresh path only.

## Key types

- `SigstoreProvenanceAdapter` — `new(trust_root: CachedTrustRoot)`.
- `CachedTrustRoot` — `from_trusted_root_json`, `rekor_keys`, `is_fresh`.
- `refresh_trusted_root_json`, `DEFAULT_REFRESH_WINDOW_HOURS`.

## Rules

- `reqwest::Client::builder()` only for the one live-HTTP path (TUF
  trust-root refresh) — ADR 0010. The upstream `sigstore` crate's own
  internal `reqwest::Client::new()` is deliberately bypassed in favor of
  this adapter's own builder-based client, precisely to avoid the ADR 0010
  anti-pattern that dependency would otherwise introduce transitively.
