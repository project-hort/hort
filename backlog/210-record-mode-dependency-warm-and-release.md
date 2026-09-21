# 210 — `registry-supply-chain` (h): the advisory dependency is warmed and released through `crates-proxy` before the record-mode publish

**Issue:** #268 · **Branch:** `agent/268-client-image-cargo` (continues 195/204) · single item · scenario only.

## Defect (measured on the compose harness, tip `0bccb93b`)

(a)–(g) green for the first time. (h1) `cargo publish` of the record-mode lib fails:
`no matching package named rustc-serialize found — location searched: hort-cargo-virtual index
(which is replacing registry crates-io)`. Server log for that request:
`cargo unified sparse-index serve completed crate_name=rustc-serialize repository=cargo-virtual
index_source=virtual index_mode=released_only upstream_versions=48 served_versions=0
filtered_versions=48 held_visibility=Hidden`. The virtual serves **released** versions only
(ADR 0031: composition over the members' gated serve paths); `crates-proxy` had never ingested
`rustc-serialize`, and a fresh pull-through lands in its 3-day quarantine, so the aggregation
hides every version and cargo cannot resolve the lockfile even with `--no-verify`. Step (h) was
written without the warm-and-release choreography that (b)/(c) already perform for `serde`, and
it had never executed anywhere (the cargo gate masked it), so nothing caught it.

## Change

1. Before (h1), a step **(h0)** warms and releases the advisory dependency exactly the way (b) +
   (c) do for the probe crate: authenticated GET of
   `${CRATES_PROXY_URL}/api/v1/crates/${RECORD_VULN_CRATE}/${RECORD_VULN_VERSION}/download`
   (200 = already released, 503 = ingested and quarantined), locate the artifact row via `psql`
   by `(repository_id, name, version)`, `POST /api/v1/admin/quarantine/<id>/release` with the
   admin token, then confirm one authenticated re-download returns 200. Factor the (b)/(c)
   mechanics into a helper (`warm_and_release_via_proxy <crate> <version>`) used by both (c) and
   (h0) — three copies would be the duplication the guidelines forbid.
2. After (h0), confirm the virtual index now serves the version: authenticated GET of the
   sparse-index path for `rustc-serialize` on `${CARGO_VIRTUAL_URL}` contains `"vers":"0.3.24"`
   (a one-line assertion that pins the ADR 0031 released-only composition explicitly).
3. The header comment for (h) states why the dependency must be released first (the virtual
   composes gated member paths; a pending version is hidden) — no issue numbers.
4. Nothing else changes: `crates-proxy`'s window, `cargo-virtual`'s `indexMode`, and the
   `--no-verify` publish stay as they are (the fixtures mirror the dogfood posture).

## Acceptance

- `dogfood/registry-supply-chain` PASS through (h2) on the reporter's harness; (h2) then
  proves the record-mode OSV finding on the resolved lockfile for the first time.
- `bash -n` clean; comments state invariants; audit/deny unconditional (harness-only).
