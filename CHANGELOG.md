# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.2] - 2026-06-17

Beta release. The feature set is described in the documentation under `docs/`.

### Added

- **`hort admin workers list` / `GET /api/v1/admin/workers`** — an admin-only
  read of the scanner-worker registry showing each worker's advertised
  backends and liveness (`live` flag + last-heartbeat age). A worker that has
  stopped heartbeating stays in the listing as `LIVE=NO` rather than being
  filtered out, so operators can distinguish "my trivy worker died" from "I
  never had one". This wires a reader for the worker heartbeat, which had been
  orphaned when H20 moved `scanBackends` validation off the live registry (the
  `ScannerRegistryRepository::list_live(window)` port method becomes
  `list_all()` — the ~5-minute liveness threshold moves up to the use case as
  a presentation policy). Admin-gated; reuses the existing admin auth.
- **`scanner-registry-prune` housekeeping task** — a default-enabled worker
  CronJob (hourly) that deletes `scanner_registry` rows whose last heartbeat is
  older than 7 days, so pod churn (rollouts, HPA scaling) cannot grow the
  worker-coordination table without bound. Degrades safe (a missed prune only
  grows the table; liveness is recomputed on read). The admin worker-list read
  is also defensively bounded (`ORDER BY last_heartbeat DESC LIMIT 1000`).

### Fixed

- **Gitops boot no longer parks not-ready on a fresh deployment with a correct
  `scanBackends` policy (regression H20).** Apply-time `ScanPolicy.scanBackends`
  validation now checks each entry against the binary's compiled-in scanner set
  (`hort_app::scanning::KNOWN_SCAN_BACKENDS` = `trivy`, `osv`) instead of the
  live `scanner_registry` worker table. The previous live-registry check was a
  boot-ordering hazard: on a fresh DB the server applies config before any
  `hort-worker` has registered its first heartbeat, so a correct
  `scanBackends: [trivy]` policy was rejected fail-closed, parking the server
  not-ready (`/healthz` 200, so the kubelet never restarted it) until an
  operator manually bounced the pod. A backend name is a permanent property of
  the build, independent of worker-registration timing; whether a worker
  advertising it is *running* is a runtime-liveness concern for metrics/health,
  not a config-validity error. Typos / unsupported backends are still rejected
  at apply. (ADR 0007 `ScanWaived` empty-list waiver and the ADR 0016
  `trust_upstream_publish_time_requires_scan_backends` linter are unaffected.)
- **OCI manifest pull-through no longer 404s against strict content-negotiation
  registries (e.g. `registry.k8s.io` / Artifact Registry).** Two fixes: (1) the
  inbound handler now reads **all** `Accept` header lines (`get_all`), not just
  the first — a client that splits its `Accept` across multiple header lines
  (Go's `http.Header.Add`, as containerd's resolver uses) was being silently
  narrowed to its first type; and (2) the upstream manifest fetch now always
  advertises the full canonical manifest media-type set (OCI manifest/index +
  Docker manifest/list) regardless of the client's `Accept`, so a pull-through
  fetches the canonical manifest it will store rather than a per-client
  projection. Previously, a Docker manifest-list image (e.g. `pause:3.9`)
  fetched with an OCI-only `Accept` made the backing registry return 404, which
  hort surfaced as "manifest unknown". Narrow clients are still negotiated at
  serve time (`406` with manifest-pair leniency), and the cached representation
  is now `Accept`-independent.

### Security

- Provenance verification now cryptographically verifies the Rekor **Merkle
  inclusion proof** and the **checkpoint signature**, fully offline, against
  the pinned trust root's Rekor key (Sigstore v0.3 bundle format) — closing
  the `sigstore-rs#285` gap where `sigstore` 0.14's `verify_digest` left those
  steps unimplemented. A bundle whose transparency-log entry is not provably
  in the log is now rejected (`RekorNotFound`) instead of being accepted on
  the strength of the Fulcio chain + signature alone. (ADR 0027)
- The container-image publish pipeline now **fails closed on fixable CRITICAL
  CVEs**: the release Trivy scan runs with `exit-code: 1`, `severity: CRITICAL`,
  and `ignore-unfixed: true`, so a newly-disclosed fixable CRITICAL blocks the
  publish until it is patched or explicitly accepted in `.trivyignore`. (audit
  INFRA-3)
- `HORT_BEARER_ALLOW_OVER_HTTP=true` together with an `https://`
  `HORT_PUBLIC_BASE_URL` is now a **boot hard-fail**
  (`ConfigError::BearerOverHttpContradictsTls`): a TLS-terminated deployment has
  no legitimate need to relax the bearer-token transport guard, so the
  self-contradictory pair is rejected at startup rather than silently widening
  the bearer-token exposure surface. A genuinely plaintext-internal deploy
  (`http://` or unset public base URL) is unaffected. (audit INFRA-13)
