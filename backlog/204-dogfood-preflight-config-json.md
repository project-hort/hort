# 204 — `dogfood/registry-supply-chain` preflight reads presence from `config.json`, not from an anonymous 404

**Issue:** #268 · **Branch:** `agent/268-client-image-cargo` (continues item 195) · single item · harness-only.

## Defect (measured on the compose harness with item 195's image)

With cargo now in the client image the scenario passes its toolchain check and stops at the next
gate: `SKIP: crates-proxy sparse-index returned 404 — repo not configured on this instance`. The
repository IS configured (`deploy/compose/example-config/repositories/crates-proxy.yaml`,
`isPublic: false`). `_probe_repo` (`registry-supply-chain.sh:104`) sends an anonymous
`GET /cargo/<key>/` and reads 404 as "absent" — but the cargo adapter collapses an anonymous read
of a private repository to `NotFound { entity: "Repository" }` (`hort-http-cargo/src/serve.rs:131`)
by design, so a private repo is indistinguishable from a missing one on that probe. The
`hort-crates-chain-e2e` sibling (`dogfood/publish-chain.sh:145-153`) already uses the right
presence signal: `/cargo/<key>/config.json`, the anonymous bootstrap document every cargo client
reads, served for private repositories too.

## Change

1. `_probe_repo` for the three cargo repositories probes `${URL}/config.json` (200 = present;
   keep 401/403 as present for an instance that gates even the bootstrap); the OCI probe stays on
   `/v2/`. Update the helper's comment to state the invariant (anonymous 404 on a private cargo
   repo is the refusal shape, not absence).
2. Run the scenario on the compose harness (human, branch-first) and fix, in the same item, every
   further compose-vs-dogfood mismatch it reveals that is a scenario or fixture defect — not a
   product defect. Known candidates to check before the run: (e) expects `hort-crates` to serve an
   anonymous fetch after publish (`quarantineDuration: 0s` in `hort-crates-scan.yaml`?); (h)
   expects `hort-crates` under `enforcement: record` with `osv` in `scanBackends` and a resolved
   SBOM; (g) expects `cargo-virtual` to aggregate `hort-crates` + `crates-proxy`. Anything that
   turns out to be a product defect becomes its own issue and the step skips with a named reason.
3. `scripts/native-tests/README.md`: one line that the dogfood scenarios detect repository
   presence via `config.json`.

## Acceptance

- A full compose run lists `dogfood/registry-supply-chain` under PASS (executed through (h)), on
  the human's harness; then the GitHub run on `develop` after merge.
- Gate: harness-only (`bash -n` on touched scripts, YAML parse of touched fixtures), audit/deny
  unconditional. Comments state invariants; no issue numbers.
