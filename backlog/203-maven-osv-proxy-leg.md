# 203 — `dogfood/maven-osv-scan`: the Maven **proxy** leg proves the payload SBOM on a pull-through

**Issue:** #266 · **Branch:** `agent/266-payload-sbom-all-repo-classes` (continues item 196; point 4 of that item, deferred until the base scenario reached `develop`) · single item · E2E scenario + compose fixtures only.

## Change

1. Fixtures under `deploy/compose/example-config/`: repository `maven-osv-proxy-e2e` (Maven proxy →
   Maven Central, mirror the upstream mapping of `maven-central-e2e`; private read grant for the
   dev identity like `maven-trivy-e2e`'s), scan policy `maven-osv-proxy-e2e-scan`
   (`scanBackends: ["osv"]`, `enforcement: record`, `quarantineDuration: 20s`, `provenanceMode: off`).
2. `scripts/native-tests/scenarios/dogfood/maven-osv-scan.sh`: a second leg after the hosted one
   — authenticated pull-through of `org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.pom`
   through the proxy (200 or 503 both mean "ingested"), locate the artifact by
   (repository_id, path) via `psql` (private repo → anonymous 404 is not "absent"), await
   `last_scan_at`, then assert: the SBOM carries ≥ 1 declared component of that pom and a
   `scan_findings` row with `source_scanner='osv'` exists for the artifact (log4j-core 2.14.1's
   pom declares vulnerable dependencies; assert on ≥ 1 osv finding for the artifact, not on a
   specific CVE, since the declared set is upstream's). Under `record` the artifact is not
   rejected — assert `quarantine_status` is not `rejected`.
3. Header comment states the invariant (payload SBOM on every repository class); no issue numbers.

## Acceptance

- Hosted leg unchanged and green; proxy leg green on the human's harness (branch-first); the
  worker log shows `hort_sbom_resolution_total{format="maven"}` firing `resolved` for the proxy
  artifact (or the scenario asserts the SBOM component, which is the same fact).
- Gate: harness-only (`bash -n`, fixture YAML parses via the alpha-fixtures guard if it covers
  compose example-config; otherwise `cargo test --workspace` unchanged), audit/deny unconditional.
