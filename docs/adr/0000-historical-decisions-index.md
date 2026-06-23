# 0000 — Decision index and open-items register

- **Status:** Accepted
- **Enforced by:** this page is the entry point to the ADR set and the durable
  home of the open hardening items and accepted risk postures; each decision's
  own "Enforced by" line names its live mechanism.
- **Supersedes:** the previous revision of this file (the historical-decisions
  index).

This is an index page, not a decision record. It answers two questions: *which
ADR covers what?* and *which known items are open, closed, or deliberately
accepted?*

## Decision index

### Layering and domain model

| ADR | Decision |
|---|---|
| [0001](0001-hexagonal-zero-io-domain.md) | Hexagonal architecture with a zero-I/O domain layer |
| [0008](0008-per-format-adapter-free-http-crates.md) | Per-format inbound-HTTP crates with a compile-time adapter-free guarantee |

### Storage and CAS

| ADR | Decision |
|---|---|
| [0003](0003-streaming-enforced-cas.md) | Streaming, enforced content-addressable storage |
| [0026](0026-streaming-metadata-projection.md) | Streaming metadata projection (no whole-body buffering on pull-through) |

### Event sourcing and lifecycle data

| ADR | Decision |
|---|---|
| [0002](0002-event-sourced-artifact-lifecycle.md) | Event-sourced artifact lifecycle |
| [0004](0004-pluggable-eventstore-port.md) | Backend-agnostic EventStore port |
| [0014](0014-externalised-timeseries.md) | Externalised high-frequency timeseries |

### Quarantine and release gating

| ADR | Decision |
|---|---|
| [0007](0007-fail-closed-quarantine-release-predicate.md) | Fail-closed quarantine release predicate |
| [0015](0015-apply-time-linter-inert-fields-and-naming.md) | Apply-time rejection of inert policy fields and misleading config names |
| [0016](0016-cross-opt-in-interaction-matrix.md) | Cross-opt-in interaction matrix for release-gate-influencing knobs |
| [0027](0027-artifact-provenance-verification.md) | Artifact provenance verification (Sigstore/cosign, offline, policy-gated) |

### Formats, index serving, and the API surface

| ADR | Decision |
|---|---|
| [0005](0005-wasm-format-modules-capability-taxonomy.md) | WASM format modules with a capability-group taxonomy |
| [0006](0006-mandatory-upstream-verification.md) | Mandatory upstream checksum verification |
| [0011](0011-authority-hierarchy-and-api-versioning.md) | Authority hierarchy, and first-party API versioning |
| [0025](0025-state-precondition-violations-return-409.md) | Caller-reachable state-precondition violations return 409, not 500 |
| [0031](0031-virtual-repository-aggregation.md) | Virtual (aggregated) repository resolution: composition over members' gated serve paths, authoritative-member rule |
| [0032](0032-maven-gradle-multi-file-handler.md) | Maven/Gradle multi-file format handler: MultiFileArtifact via the `classify_group_member`/`ArtifactGroup` push model; server-generated metadata + on-demand sidecars; SNAPSHOT resolution; Gradle = Maven alias |
| [0033](0033-sha1-upstream-transfer-verification-floor.md) | SHA-1 permitted as an upstream transfer-verification floor (Maven), never a CAS key, never a relaxation where a stronger signal exists |

### Auth, RBAC, and sessions

| ADR | Decision |
|---|---|
| [0012](0012-claim-based-rbac-claimless-static-tokens.md) | Claim-based RBAC; long-lived static tokens stay claimless |
| [0013](0013-idp-authoritative-cli-sessions.md) | IdP-authoritative, short-lived CLI sessions |
| [0018](0018-auth-catalog-canonical.md) | The authentication catalog is canonical |
| [0021](0021-read-handler-anonymous-by-default.md) | Read handlers are anonymous-by-default; per-resource visibility is the only gate |
| [0035](0035-cargo-config-json-anon-readable-auth-required.md) | Cargo `config.json` is anonymously readable and advertises `auth-required` for gated proxies (bounded anti-enum give-up; index/download stay gated; RFC 3231) |

### TLS and trust

| ADR | Decision |
|---|---|
| [0010](0010-tls-builder-no-insecure-knobs.md) | Centralised TLS construction; no insecure-TLS knobs |

### Operations and configuration

| ADR | Decision |
|---|---|
| [0009](0009-least-privilege-runtime-migrate-subcommand.md) | Least-privilege runtime; migrations are a separate subcommand |
| [0020](0020-single-flight-seal-pool-backstop.md) | Single-flight backstop for the unbounded seal/retention append |
| [0028](0028-destructive-task-idempotency.md) | Durable single-flight idempotency for destructive task kinds |
| [0029](0029-operator-config-hard-rename.md) | Operator-config renames are hard renames |
| [0034](0034-public-dogfood-deployment.md) | Public dogfood deployment and supply-chain hardening posture: three repo classes, CI OIDC federation with claim-bound SAs, no-IdP operator tokens, non-empty `scan_backends` + no-`trust_upstream_publish_time` posture, two deployment flavors |

### Process and structural guards

| ADR | Decision |
|---|---|
| [0017](0017-metrics-catalog-canonical.md) | The metrics catalog is canonical |
| [0019](0019-db-test-serial-isolation.md) | DB-backed tests share one database and must serialize |
| [0022](0022-pre-1.0-edit-existing-migrations.md) | Pre-1.0, edit existing migrations in place |
| [0023](0023-implementation-discipline-objectively-better.md) | The design wins by default; deviations require an "objectively better" case |
| [0024](0024-architect-skill-as-enforcement-index.md) | The architect skill is the enforcement index for these ADRs |
| [0030](0030-sensitive-surface-structural-guards.md) | Fail-closed structural guards over the sensitive schema and retention registration |

## Open-items register

Known hardening items and risk postures, recorded so they survive document
churn. Status is **OPEN** unless stated otherwise. Closing an OPEN row, or
revisiting an ACCEPTED one, goes through the normal design process — none of
these rows is moot.

### OPEN

| Item | Detail |
|---|---|
| GitLab CI `project_path` placeholder | `deploy/ansible/files/gitops/auth/service-accounts/gitlab-ci.yaml` contains `project_path: REPLACE_ME/hort` — substitute the real GitLab project path before enabling the proxy in production. Without this, GitLab CI OIDC tokens will not match the `gitlab-ci` ServiceAccount. (ADR 0034, Task 2 M1) |
| GitLab issuer `requireJti` caveat | The `gitlab` OidcIssuer uses `requireJti: true` (the default). If the self-hosted GitLab instance predates v15.7 (which introduced `jti` in CI tokens), set `requireJti: false` in `deploy/ansible/files/gitops/auth/issuers/gitlab.yaml`. Cannot be verified without a live GitLab instance. (ADR 0034, Task 2 M2) |
| GitLab CI error-path token leak | In `.gitlab-ci.yml`, the `echo "${_hort_response}"` line in the `.hort_auth` error path can print the `access_token` in cleartext if the exchange response is malformed (a valid JSON object with an unexpected shape). Sanitize the error output before enabling `HORT_PROXY_ENABLED` in production. (ADR 0034, Task 6 M3) |
| Proxy quarantine path coverage (warm-instance) | The dogfood smoke scenario (b) soft-passes on a pre-existing released artifact — the quarantine path is not exercised on a long-lived instance. Consider a nonce-versioned probe artifact to exercise the full ingest → quarantine → release path. (ADR 0034, Task 7 follow-up) |
| `cargo-virtual` aggregation dependency | The `cargo-virtual` build endpoint depends on ADR 0031 serve-time member aggregation. Until that is available in the deployed version, builds resolve against `crates-proxy` directly. Track the ADR 0031 rollout and update the `.cargo/config.toml` source replacement when the virtual aggregation path lands. (ADR 0034) |
| Rescan-amplification rate cap | The manual rescan trigger surface has no per-repo fairness cap or `429` response. Mitigated by the worker per-kind concurrency=1 queue serialisation (`crates/hort-worker/src/composition.rs:539`) and the generic IP-keyed rate limit (`crates/hort-http-core/src/middleware/rate_limit.rs`). |
| Claim-grant linter residual | The gitops apply-time linter for single-claim grants is fan-out-bypassable and not claim-mapping-provenance-aware. The durable fix is IdP-authoritative refresh, not a linter patch (relates [0012](0012-claim-based-rbac-claimless-static-tokens.md), [0013](0013-idp-authoritative-cli-sessions.md), [0015](0015-apply-time-linter-inert-fields-and-naming.md)). Do not close as moot. |
| Second authenticated advisory feed (GHSA) | Only OSV adapters exist (`crates/hort-adapters-advisory-osv`). A second, authenticated feed remains unscheduled hardening for advisory-source diversity. |
| Combined real-verifier provenance E2E | Provenance verification is composition-proven (in-crate fixture tests + offline cosign smoke), but no live-stack worker-to-release-gate E2E exists (relates [0027](0027-artifact-provenance-verification.md)). |
| Virtual-repo per-name routing patterns | Virtual aggregation ([0031](0031-virtual-repository-aggregation.md)) closes new-version dependency confusion in v1 via name-level pinning (a name owned by any non-proxy member is unreachable from proxy members). The deferred enhancement is finer-grained operator-specified per-name include/exclude *patterns* (e.g. pin `@acme/*` to a member) beyond the repo-type ownership signal. Not a vulnerability. Revisit trigger: an operator needs name-pattern routing that repo-type ownership cannot express. |
| `ScanIndeterminate` proxy-status mapping | Both OCI (`crates/hort-http-oci/src/quarantine.rs:46`) and npm (`crates/hort-http-npm/src/lib.rs:314-330`) return `503 + Retry-After` for `Quarantined` and `403` for `Rejected`. However, the terminal `ScanIndeterminate` status has no defined proxy-facing mapping — npm currently returns `403` for it (same shape as `Rejected`), but the correct client-visible contract for a scanner failure is unspecified. |
| Maven Phase-2 prefetch | Scheduled/transitive prefetch for Maven is **deferred** ([0032](0032-maven-gradle-multi-file-handler.md)). `MavenVersionOrdering` exists but is consumed only by the Maven serve/builder path; Maven is unreachable in `self_service_prefetch_use_case` today (the `hort-formats-upstream` `UnsupportedFormat` guard), and `prefetch_tick::ordering_for_format` returns `None` for Maven. **Coupling — enabling it MUST move together, or self-service silently mis-orders Maven with npm-semver:** add the Maven arm to **BOTH** `ordering_for_format` sites (`crates/hort-app/src/task_handlers/prefetch_tick.rs` *and* `crates/hort-app/src/use_cases/self_service_prefetch_use_case.rs` — the latter's `_ => &NpmSemverOrdering` wildcard would otherwise hide the mis-order from every test), **plus** the `hort-formats-upstream` dispatch, **plus** the handler version-discovery methods (`extract_upstream_versions` / `upstream_metadata_path` / `build_pull_url`), in one change. A code comment at the `self_service` wildcard records the trap. |
| Gradle Module Metadata variant resolution | The Gradle `.module` GMM descriptor is **opaque store-and-serve pass-through** today ([0032](0032-maven-gradle-multi-file-handler.md)) — stored + served by exact path as a group member, round-tripping publish→download, with no variant parsing. Variant-aware resolution (selecting an artifact by GMM variant/capability) is deferred. Revisit trigger: an operator needs Hort to resolve a Gradle variant rather than serve the requested file verbatim. |
| Maven G-level plugin-prefix `maven-metadata.xml` | The group-level (`<plugins><plugin>` plugin-prefix → artifactId) `maven-metadata.xml` index is **deferred** ([0032](0032-maven-gradle-multi-file-handler.md)). Only the A-level (artifact version list) and V-level (snapshot build list) documents are generated today. Revisit trigger: a Maven-plugin-resolution workflow that needs the G-level plugin-prefix index. |
| Cargo served-index name case fidelity (Low) | Hosted index entries emit the stored name (`crates/hort-http-cargo/src/index_source.rs:173`) rather than the re-normalised request parameter; spec-fidelity question. |
| Subscription update-path SSRF denial audit asymmetry (Low) | Update-path refusals emit only a metric (`crates/hort-app/src/use_cases/subscription_use_case.rs:839`), where the create path appends a durable denial event. |
| Scanner-registry read side orphaned (H20) — RESOLVED | H20 removed the apply-time consumer of `ScannerRegistryRepository::list_live`, orphaning the read side. The revisit trigger's **wire-a-reader** branch is now taken: the `scanner_registry` read side is consumed by the admin worker-list — `ScannerWorkerQueryUseCase` behind `GET /api/v1/admin/workers` / `hort admin workers list` (`crates/hort-app/src/use_cases/scanner_worker_query_use_case.rs`). The port method was renamed `list_live(window)` → `list_all()`: the ~5-minute liveness threshold moved up to the use case as a *presentation policy*, so dead/stale workers stay visible with a last-heartbeat age rather than being filtered out. The worker heartbeat write path now has a reader again. (A k8s-probe / automated wedged-worker-detection consumer remains future work — the admin list is an operator-driven read.) |
| 2026-06-15 security audit — disposition | The Medium/Low/Info findings from the 2026-06-15 audit were triaged and remediated across Waves 1–3 (the working audit report + remediation backlog under `docs/security/` were branch-local scaffolding, removed at release per the doc-lifecycle rule; their durable dispositions live here). The High (SUP-1, Rekor inclusion verification) is closed ([0027](0027-artifact-provenance-verification.md)); INJ-1 is closed in Wave 1 (row below). The two *risk-accepted* deferrals (CRYP-1, SUP-6) are the rows below. |
| Upstream-fetch SSRF / DNS-rebind TOCTOU (Medium, INJ-1) — CLOSED | Fixed in Wave 1 (`89c203ba`): a connect-time `GuardedDnsResolver` bound to the upstream artifact/metadata clients re-runs `is_routable` on every dial-time resolution, closing the TOCTOU between `check_ssrf_safe` and the initial dial (fail-closed; reuses the `parse_error` classification, mirrors the webhook guard). Previously interim-risk-accepted here. (audit INJ-1) |
| OCI/CLI shared signing key (Low, CRYP-1) — ACCEPTED | One Ed25519 key signs both OCI `/v2/auth` and full-authority CliSession tokens; separation is verify-time (`aud`+`token_kind`), not cryptographic (`crates/hort-app/src/oci_token_signing.rs:216-239`). Key is `Zeroizing`/`Debug`-redacted; verify-time separation tested. Cryptographic keypair separation is an ADR-level change. Revisit trigger: a new token family sharing the key, or a key-rotation initiative. (audit CRYP-1) |
| Range-read at-rest integrity (Low, SUP-6) — ACCEPTED | `get_range` (OCI blob resume) returns raw bytes without the streaming `VerifyingReader` (`crates/hort-adapters-storage/src/filesystem.rs:387-456`). Bounded: the first non-range GET trips the verifier; the out-of-band CAS scrubber re-hashes. Revisit trigger: range reads becoming a primary serve path, or at-rest tampering entering the modeled threat set. (audit SUP-6) |
| Maven SNAPSHOT / upstream-metadata proxy discovery (Info) | Deferred ([0032](0032-maven-gradle-multi-file-handler.md)). SNAPSHOT resolution (`crates/hort-formats/src/maven/snapshot.rs` + the Item-8/9 serve path) is filename-based over the **already-stored** builds; Hort does not parse the upstream `maven-metadata.xml`. Consequence on a **proxy** repo: discovering a not-yet-cached upstream SNAPSHOT (or version-range / `LATEST` / `RELEASE`) is limited to the cached set. Pinned-version release pull-through works via exact path and is unaffected. Restoring upstream discovery requires parsing untrusted upstream `maven-metadata.xml`, gated by the deliberate **no-XML-parser XXE-safety posture**. |
| Upstream metadata-leg parse-time SSRF symmetry (Info) | The upstream metadata leg (`hort-adapters-upstream-http` `compose_url`, ~`lib.rs:1836`) lacks the parse-time `check_ssrf_safe` the artifact leg has (~`lib.rs:1781`). Pre-existing and **not Maven-exploitable** (Maven paths are relative; the connect-time `GuardedDnsResolver` backstops the dial), but the metadata leg now has a second consumer (the Maven metadata leg), so restore the parse-time symmetry as tracked hardening. Do not change `hort-adapters-upstream-http` in the Maven initiative — doc-only. |

### CLOSED (kept for the audit trail)

| Item | Detail |
|---|---|
| Durable destructive-task idempotency | The `jobs` idempotency partial-unique index landed (commits `851dac1e` + `f87ebd0a`; [0028](0028-destructive-task-idempotency.md)). Previously tracked here as open. |

### ACCEPTED postures (deliberate, permanent)

Recorded so the acceptance survives; revisiting one requires a new design
decision, not a silent change.

| Posture | Detail |
|---|---|
| Single additive CA bundle | `HORT_EXTRA_CA_BUNDLE` is process-wide additive trust with no per-surface scoping; documented with its blast-radius guidance in [the security-hardening checklist](../architecture/how-to/deploy/security-hardening-checklist.md). |
| OSV bulk-feed content integrity unsatisfiable | No signed manifest exists for the OSV bulk feed. Compensating controls: the enqueue-only advisory-watch path and diff-volume alarms — see [the scanning-pipeline explanation](../architecture/explanation/scanning-pipeline.md). |
| Admin-amplification structural fix declined | The active controls are the cap-AND rule (IdP `admin` claim **and** server-side `is_admin` must both hold) plus the persisted `AdminStatusChanged` audit event. |

## Archaeology

The full pre-1.0 development history — including every design document that
preceded these ADRs — is preserved in git on the frozen pre-1.0 history
branch. The ADRs above are the standing decisions distilled from that history;
the `docs/architecture/` Diátaxis set is the what/how documentation. Nothing
in the history outranks an ADR or a protocol specification.
