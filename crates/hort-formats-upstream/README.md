# hort-formats-upstream — Upstream Metadata Composition Seam

## Layer

Formats/WASM (upstream dispatch) — the one non-server crate other than
`hort-server` itself that imports multiple `hort-http-<format>` inbound
crates as a normal dependency: `hort-http-npm`, `hort-http-pypi`,
`hort-http-cargo` (deliberately **not** `hort-http-oci` — see below).
Requires >= 85% coverage.

## Responsibility

Implements `UpstreamMetadataPort` by dispatching to each format's own
`fetch_raw_with_cache` helper: `"npm"` -> `hort_http_npm::packument`,
`"pypi"` -> `hort_http_pypi::simple_index`, `"cargo"` ->
`hort_http_cargo::index_cache`; `"oci"` and any other format string returns
`UpstreamFetchError::UnsupportedFormat`. This is a deliberate, single,
reviewed composition seam kept separate from `hort-server`'s full
composition root, so the three-crate import concentrates in one place
rather than spreading across the server binary.

## Ports

- **Implements:** `UpstreamMetadataPort` (`UpstreamMetadataAdapter`),
  holding `Arc<dyn UpstreamResolver>` + `Arc<dyn EphemeralStore>` +
  `Arc<dyn UpstreamProxy>` + `Arc<PullDedup>` — deliberately never
  `Arc<AppContext>`, to avoid a construction cycle.
- **Consumes:** the per-format `fetch_raw_with_cache` helpers listed above.

## Key types

- `UpstreamMetadataAdapter`.

## Rules

- This crate's import of multiple `hort-http-<format>` crates is the
  sanctioned exception to the rule that nothing outside `hort-server`
  composes multiple format crates together — do not add a similar
  multi-format import anywhere else without updating this README and the
  architecture docs.
- Construction takes explicit `Arc`s, never `Arc<AppContext>`, specifically
  to avoid a construction-order cycle with the composition root.
