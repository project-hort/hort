# 057 — #92: OCI read path serves `scan_indeterminate` as 503 (GET+HEAD parity, manifests + blobs)

**Issue:** #92 (spec approved on the issue, 2026-07-31 — including Tom's refinement: 503 only
for read-eligible callers; ineligible callers keep the existing ADR 0045 anti-enumeration
envelope, which already fires before the state gate).
**Read first:** `crates/hort-http-oci/src/manifests.rs` (state gate ~290-307, HEAD
short-circuit ~333, download-error branch ~345-360); `crates/hort-http-oci/src/blobs.rs`
(state gate ~525-560, range path below it); `crates/hort-http-oci/src/quarantine.rs`
(`check_quarantine` — the 503 envelope to mirror); `crates/hort-domain/src/entities/artifact.rs`
(`is_downloadable`, ~1065); ADR 0039 §10 (the deliberate Quarantined hold-read/probe scope —
must stay untouched); ADR 0045 (access-gate ordering); `docs/adr/0025` (no opaque 500 for
caller-reachable state).

## Defect (settled on #92)

`ScanIndeterminate` falls through both state gates in the OCI read handlers: HEAD returns
**200 to every caller** (short-circuit before the download call) while GET falls into
`ArtifactUseCase::download`, fails `is_downloadable()`, and maps to **500** `OciError::Internal`
plus an `error!`-level log — a policy hold miscategorized as a server fault, and a HEAD/GET
parity break the module doc itself forbids (`manifests.rs:98-99`).

## Work

1. Restructure the state gate in **both** `manifests.rs::serve` and `blobs.rs` into an
   **exhaustive `match` on `QuarantineStatus`** (no wildcard arm), so a future status variant
   is a compile error at the gate, not a fall-through 500. Behavior per state is UNCHANGED
   for `None`/`Released` (200), `Quarantined` (503 + Retry-After; ADR 0039 write-authorized
   hold-read on manifests HEAD+GET and blob HEAD-only probe — preserved exactly), and
   `Rejected` (hidden 404).
2. `ScanIndeterminate` → **503 `UNAVAILABLE` on GET and HEAD alike, for all callers that
   reach the gate** (read-eligible by construction — the ADR 0045 access gate already 404/401s
   everyone else). Two deliberate differences from `Quarantined`, per the approved spec:
   **no `Retry-After` header** (no self-resolving deadline; exit is admin action), and
   **no ADR 0039 hold-read/probe extension** (fail closed for every caller including
   write-granted). Reuse the `quarantine.rs` 503 envelope with a scan-indeterminate detail
   message; no new OCI error code.
3. The GET path for `ScanIndeterminate` must no longer reach `download` (the `error!` log
   disappears with it). `ArtifactUseCase::download`'s own `is_downloadable` denial stays as
   defense-in-depth, untouched.
4. Range requests on a `scan_indeterminate` blob: the state gate fires before Range parsing
   (mirroring the existing "quarantine before Range" ordering), so 503 wins over 416/206.

## Scope / acceptance

- Handler tests (via `hort_http_core::test_support::build_mock_ctx`) pin the full matrix:
  state × {GET, HEAD} × {manifest, blob} × {anonymous, pull-scoped, write-granted}, including:
  `scan_indeterminate` → 503 with **no** `Retry-After` for all three caller classes on both
  surfaces; `Quarantined` write-granted manifest GET still 200 and blob GET still 503
  (ADR 0039 scope pinned); `Rejected` still hidden-404.
- The gate is an exhaustive match — adding a `QuarantineStatus` variant fails compilation
  in both handlers.
- No change to `hort-app`/domain; `hort-http-oci` ≥ 85% coverage on changed code.
- No new metric names/labels (existing `hort_http_*` covers 503s).
- Gate: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, `cargo audit --deny warnings`, `cargo deny check`.

**Model hint:** small model ok (tight approved spec; mechanical gate restructure + test matrix).
