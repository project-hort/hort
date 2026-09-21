# 196 — Payload SBOM for every repository class (ADR 0056 amendment): the scanner can deliver the declared threat level on proxies too

**Issue:** #266 · **Branch:** `agent/266-payload-sbom-all-repo-classes` · single item · ADR amendment authorised (decision on #266, 2026-09-17).

## Governing decisions

ADR 0056 (introduced the hosted-only payload path; amended by this item), ADR 0034 (verdict at the
gate), ADR 0007 (fail-closed release authority). The human's rule for the whole scan axis: *a
repository configuration that declares no artifact above a threat level is delivered obliges the
scanner to be able to deliver that information — do what is necessary for that, and no more.*

## Change

1. `ScanOrchestrationUseCase::try_extract_sbom` reads the stored payload for **every** repository
   class once the handler declares `payload_sbom()`; the `RepositoryType::Hosted` gate and
   `SbomResolutionResult::HostedOnly` (+ its `hosted_only` label in `docs/metrics-catalog.md`) go
   away. The doc comment states the invariant (payload SBOM wherever the format derives components
   from the payload) and carries ADR 0056's evidence argument as the operator-facing note: on
   proxied lockfile formats, findings against embedded resolves describe code not in the artifact,
   so `enforcement: record` is the recommended mode there; binary crates remain the open nuance.
2. ADR 0056: dated amendment section — decision, rationale reversal, what stays (record mode,
   resolution metrics), the operator note; head "Enforced by" updated (gate removed, test renamed).
3. Tests (hort-app 100 %): `hort_sbom_resolution_total_fires_hosted_only_for_a_non_hosted_repository`
   becomes its inverse (proxy × payload handler ⇒ payload read, SBOM returned, `resolved`/
   `no_lockfile` label as for hosted); a `Staging` case too, since the old gate excluded it on
   purpose.
4. E2E: second leg in `scripts/native-tests/scenarios/dogfood/maven-osv-scan.sh` — a Maven **proxy**
   fixture (`maven-osv-proxy-e2e` → Maven Central, `scanBackends: ["osv"]`, `enforcement: record`),
   pull `org.apache.logging.log4j:log4j-core:2.14.1` `.pom` through it ⇒ `ScanCompleted` with ≥ 1
   osv finding for the subject. Branch-first on the human's harness.
5. `CHANGELOG.md` `### Changed`: SBOM extraction from the stored payload now runs for proxy,
   virtual and staging repositories as well; `record` recommended on proxied lockfile formats.
6. #259 follow-through (not here): the map's `maven × osv` cell covers all classes; a warn-rule
   `reject × proxy × payload-resolve format` at apply.

## Must not change

Gate semantics, `enforcement`, the policy schema, the OSV/Trivy adapters, SBOM extractors.

## Acceptance

- Proxy leg green on the harness; unit tests above green; gate green.
- ADR 0056 carries the amendment; `hosted_only` gone from code and catalog.
