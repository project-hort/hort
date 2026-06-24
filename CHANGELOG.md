# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.4] - 2026-06-21

Beta release. The feature set is described in the documentation under `docs/`.

### Added

- **Maven / Gradle format handler.** Pull-through proxying for Maven Central and
  Gradle repositories, covering the multi-file artifact shape (POM, JAR, and the
  per-file `.sha1` / `.md5` sidecars) and Gradle module metadata. Upstream
  transfers are checksum-verified against a SHA-1 floor — a Maven artifact whose
  upstream checksum cannot be verified is not served (ADR 0032 *Maven/Gradle
  multi-file handler*, ADR 0033 *SHA-1 upstream transfer-verification floor*).
- **Public supply-chain deployment for `registry.hort.rs` (dogfood).** An
  Ansible-based deployment (rootless-podman and native-systemd flavours) plus the
  gitops config — repositories, upstream mappings, policies, service-account
  federation — and CI workflows that run hort as its own public pull-through
  registry (ADR 0034 *public dogfood deployment*).

### Changed

- **Federated CI OIDC token exchange is now independent of interactive-OIDC
  configuration.** `POST /api/v1/auth/exchange` serves the federated-JWT branch
  (GitHub Actions / GitLab CI → gitops `OidcIssuer` rows) with
  `HORT_AUTH_PROVIDER=disabled`, requiring only `HORT_NATIVE_TOKENS_ENABLED=true`
  — no interactive identity provider (`HORT_OIDC_ISSUER_URL` /
  `HORT_OIDC_CLI_CLIENT_ID` / Keycloak) is needed. The interactive device-flow
  path and its `/.well-known/hort-client-config` discovery doc stay gated on
  `HORT_AUTH_PROVIDER=oidc`. The three federation ship-gate guardrails
  (JWT-replay seen-set, `aud`→ServiceAccount binding, empty-claims fail-closed)
  are unchanged.

### Fixed

- **OCI registry is now usable by the standard clients (`crane`, `docker`,
  `oras`).** The Distribution-Spec `/v2/auth` token endpoint declared its
  repeatable `scope` query parameter as a list but parsed it with an extractor
  that cannot decode repeated query keys, so every *scoped* token request — i.e.
  every real pull or push — failed query deserialization with
  `400 "expected a sequence"` and no bearer was ever issued. Scoped requests now
  decode correctly (single and repeated `scope=`), and a per-request scope-count
  cap bounds the (credential-gated) authorization work.
- **OCI pull-through and hosted push now work for gated / private
  repositories.** The `/v2/auth` scope→repository mapping resolved the full
  Distribution-Spec name `<repo_key>/<image>` as a repository key, which never
  matched the first-path-segment repo key, so a scoped token carried an empty
  grant set and the consume-side cap denied every pull/push on a non-public
  repo. The scope now resolves the owning repository by its first path segment,
  matching the `/v2/*` request path; public-repo anonymous pulls were
  unaffected.
- **PyPI virtual (aggregated) repositories are now installable with `pip`.** A
  `pip install` through a `type: virtual` PyPI repo failed on pip's PEP 658
  `.metadata` fetch — the metadata endpoint served against the virtual repo
  (which owns no artifacts) and returned `404`, which modern pip treats as a
  hard error. The `.metadata` endpoint now routes through the same authoritative
  member the wheel download resolves, so the served metadata always matches the
  served wheel (ADR 0031 *virtual-repository dependency-confusion defences*).
- **Gated cargo proxies are now reachable by a plain `cargo build`.** A gated
  (`isPublic: false`) cargo pull-through proxy could not be used by the stock
  `cargo` client: cargo only sends its token once it has read `auth-required`
  from `config.json`, but the handler omitted that field and returned
  `NotFound` to anonymous callers, so cargo's bootstrap failed with
  `config.json not found in registry`. The cargo `config.json` endpoint is now
  anonymously readable and advertises `auth-required: <!is_public>`; the crate
  index and download endpoints stay gated (anonymous requests still collapse to
  `NotFound`). This is a deliberate, bounded anti-enumeration give-up for
  `config.json` only — repo existence + `dl`/`api` URLs become visible, never
  crate content (ADR 0035 *cargo config.json anon-readable + auth-required*).
  npm and pypi are unaffected (their clients always send credentials). Closes
  #1.
- **The config-scrub CronJob now mounts the gitops-config volume.** The Helm
  scrub job started without the directory `HORT_CONFIG_DIR` points at; it now
  mounts the same gitops-config volume the server uses, so the directory exists.
- **OCI push no longer fails on the blob-existence pre-check under a quarantine
  policy.** During an OCI push, a write-authorized client's blob-existence `HEAD`
  was routed through the quarantine read-gate and returned `503`, blocking the
  push. The existence pre-check for a write-authorized push is now exempt from
  the quarantine gate, so pushes to a quarantined repository proceed while reads
  stay gated.

## [0.9.3] - 2026-06-21

Beta release. The feature set is described in the documentation under `docs/`.

### Added

- **Virtual (aggregated) repositories** for npm, PyPI, and Cargo (ADR 0031). A
  `type: virtual` repository aggregates several member repositories — for
  example a private hosted member plus the public pull-through mirror — behind a
  single registry URL. Serve-time resolution merges the members' indexes
  (packument / simple-index / sparse-index) and resolves concrete downloads
  *first-authoritative*: the highest-priority member that holds a coordinate
  serves it, and that member's release/quarantine gate is surfaced verbatim.
  Name-level pinning is a dependency-confusion defence — a package name owned by
  a higher-priority (e.g. private) member is never shadowed or substituted by a
  lower-priority public proxy. Per-member visibility is enforced on every read
  (ADR 0021): a caller who cannot see a private member never learns it exists,
  so a public virtual cannot leak a private member's contents. Virtuals are
  read-only; publishing to one is rejected.

### Fixed

- **Authenticated reads of private repositories returned 404.** Authenticated
  callers — admins included — were wrongly denied read access to private
  repositories: npm packuments and tarballs, PyPI simple indexes and files,
  Cargo config / sparse-index and crate downloads, and the admin security-score
  endpoints. The GET read path resolved the request principal from the wrong
  request-extension slot (the write-path "bare" slot instead of the optional
  slot the read middleware populates), so every authenticated read silently fell
  back to anonymous and a private repository appeared absent. Fail-closed —
  authenticated users were denied and no private data was disclosed — but it
  broke legitimate authenticated access (and blocked the virtual-repository
  feature, whose private member could never be read). Write paths
  (publish / upload) were unaffected.
- **GitHub release pipeline now ships assets.** Releases are created as a draft
  and then published, so they succeed under GitHub's "Immutable releases"
  setting; earlier releases could publish with zero assets. The multi-arch
  (amd64 / arm64) `hort-worker` image and the Helm chart are now published on
  release, and the CI coverage and `cargo-deny` jobs were repaired.

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
