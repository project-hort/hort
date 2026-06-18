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

### Auth, RBAC, and sessions

| ADR | Decision |
|---|---|
| [0012](0012-claim-based-rbac-claimless-static-tokens.md) | Claim-based RBAC; long-lived static tokens stay claimless |
| [0013](0013-idp-authoritative-cli-sessions.md) | IdP-authoritative, short-lived CLI sessions |
| [0018](0018-auth-catalog-canonical.md) | The authentication catalog is canonical |
| [0021](0021-read-handler-anonymous-by-default.md) | Read handlers are anonymous-by-default; per-resource visibility is the only gate |

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
| Rescan-amplification rate cap | The manual rescan trigger surface has no per-repo fairness cap or `429` response. Mitigated by the worker per-kind concurrency=1 queue serialisation (`crates/hort-worker/src/composition.rs:539`) and the generic IP-keyed rate limit (`crates/hort-http-core/src/middleware/rate_limit.rs`). |
| Claim-grant linter residual | The gitops apply-time linter for single-claim grants is fan-out-bypassable and not claim-mapping-provenance-aware. The durable fix is IdP-authoritative refresh, not a linter patch (relates [0012](0012-claim-based-rbac-claimless-static-tokens.md), [0013](0013-idp-authoritative-cli-sessions.md), [0015](0015-apply-time-linter-inert-fields-and-naming.md)). Do not close as moot. |
| Second authenticated advisory feed (GHSA) | Only OSV adapters exist (`crates/hort-adapters-advisory-osv`). A second, authenticated feed remains unscheduled hardening for advisory-source diversity. |
| Combined real-verifier provenance E2E | Provenance verification is composition-proven (in-crate fixture tests + offline cosign smoke), but no live-stack worker-to-release-gate E2E exists (relates [0027](0027-artifact-provenance-verification.md)). |
| `ScanIndeterminate` proxy-status mapping | Both OCI (`crates/hort-http-oci/src/quarantine.rs:46`) and npm (`crates/hort-http-npm/src/lib.rs:314-330`) return `503 + Retry-After` for `Quarantined` and `403` for `Rejected`. However, the terminal `ScanIndeterminate` status has no defined proxy-facing mapping — npm currently returns `403` for it (same shape as `Rejected`), but the correct client-visible contract for a scanner failure is unspecified. |
| Cargo served-index name case fidelity (Low) | Hosted index entries emit the stored name (`crates/hort-http-cargo/src/index_source.rs:173`) rather than the re-normalised request parameter; spec-fidelity question. |
| Subscription update-path SSRF denial audit asymmetry (Low) | Update-path refusals emit only a metric (`crates/hort-app/src/use_cases/subscription_use_case.rs:839`), where the create path appends a durable denial event. |
| Scanner-registry read side orphaned (H20) — RESOLVED | H20 removed the apply-time consumer of `ScannerRegistryRepository::list_live`, orphaning the read side. The revisit trigger's **wire-a-reader** branch is now taken: the `scanner_registry` read side is consumed by the admin worker-list — `ScannerWorkerQueryUseCase` behind `GET /api/v1/admin/workers` / `hort admin workers list` (`crates/hort-app/src/use_cases/scanner_worker_query_use_case.rs`). The port method was renamed `list_live(window)` → `list_all()`: the ~5-minute liveness threshold moved up to the use case as a *presentation policy*, so dead/stale workers stay visible with a last-heartbeat age rather than being filtered out. The worker heartbeat write path now has a reader again. (A k8s-probe / automated wedged-worker-detection consumer remains future work — the admin list is an operator-driven read.) |
| 2026-06-15 security audit — disposition | The Medium/Low/Info findings from the 2026-06-15 audit were triaged and remediated across Waves 1–3 (the working audit report + remediation backlog under `docs/security/` were branch-local scaffolding, removed at release per the doc-lifecycle rule; their durable dispositions live here). The High (SUP-1, Rekor inclusion verification) is closed ([0027](0027-artifact-provenance-verification.md)); INJ-1 is closed in Wave 1 (row below). The two *risk-accepted* deferrals (CRYP-1, SUP-6) are the rows below. |
| Upstream-fetch SSRF / DNS-rebind TOCTOU (Medium, INJ-1) — CLOSED | Fixed in Wave 1 (`89c203ba`): a connect-time `GuardedDnsResolver` bound to the upstream artifact/metadata clients re-runs `is_routable` on every dial-time resolution, closing the TOCTOU between `check_ssrf_safe` and the initial dial (fail-closed; reuses the `parse_error` classification, mirrors the webhook guard). Previously interim-risk-accepted here. (audit INJ-1) |
| OCI/CLI shared signing key (Low, CRYP-1) — ACCEPTED | One Ed25519 key signs both OCI `/v2/auth` and full-authority CliSession tokens; separation is verify-time (`aud`+`token_kind`), not cryptographic (`crates/hort-app/src/oci_token_signing.rs:216-239`). Key is `Zeroizing`/`Debug`-redacted; verify-time separation tested. Cryptographic keypair separation is an ADR-level change. Revisit trigger: a new token family sharing the key, or a key-rotation initiative. (audit CRYP-1) |
| Range-read at-rest integrity (Low, SUP-6) — ACCEPTED | `get_range` (OCI blob resume) returns raw bytes without the streaming `VerifyingReader` (`crates/hort-adapters-storage/src/filesystem.rs:387-456`). Bounded: the first non-range GET trips the verifier; the out-of-band CAS scrubber re-hashes. Revisit trigger: range reads becoming a primary serve path, or at-rest tampering entering the modeled threat set. (audit SUP-6) |

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
