# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.12] - 2026-07-21

### Added

- **Self-contained Helm chart + `registry.hort.rs` hosting for the full cold-start
  chain.** A single `global.imageRegistry` chart value rewrites every image
  reference (server, worker, dex) to a sovereign registry, and a second chart
  flavor published to `registry.hort.rs/hort-charts/hort-server` ships that preset
  packaged. An operator can now run hort as the sole in-cluster registry and pull
  the entire cold-start chain — `hort-server`, `hort-worker`, `dex`, `postgres`,
  and the chart itself — from `registry.hort.rs` with **no** per-node
  `registries.yaml` (direct-upstream remains only the containerd fallback). Base
  images are mirrored to a hosted `hort-base` repo whose scan bar is
  `critical` (upstream base-image CVEs are not locally remediable, so a `high`
  bar would flap the mirror for a hold no operator can action). The default
  (`global.imageRegistry: ""`) renders byte-identically to the previous chart, so
  existing ghcr consumers are untouched. (#60)

### Changed

- **A proxied image index eagerly registers and prefetches its children on
  pull-through.** The index ingest now warms its child manifests and blobs up
  front instead of ingesting descendants sequentially on first access, removing
  the per-child sequential-ingest latency on multi-arch pulls. The release
  predicate is unchanged — each descendant still requires its own scan authority
  (ADR 0007). (#51)

- **Prefetch ingest now flows through the pull-dedup coalescer.** `prefetch_ingest`
  bypassed `PullDedup` despite its module doc claiming coverage; a concurrent
  prefetch and on-demand pull of the same content now coalesce to a single
  upstream fetch, as documented. (#57)

### Fixed

- **A wedged pull-dedup coalesce leader no longer poisons its followers
  indefinitely.** A stalled leader left every follower blocked until process
  restart (a root cause behind #53-class ingest stalls). The leader now runs under
  a bounded deadline (`HORT_PULL_DEDUP_LEADER_TIMEOUT_SECS`, default 600 s) with
  RAII cleanup that evicts the coalesce entry and releases waiting followers, and
  emits `leader_timeout` / `leader_cancelled` metrics. (#55)

- **Federation token-exchange no longer 500s on concurrent mints for the same
  service account.** Simultaneous token mints raced on the service-account
  event-stream append and the loser returned an unretried version conflict as a
  500. The append now retries under a bounded CAS loop, and a genuinely contended
  mint returns `503` with `Retry-After` rather than a 500. (#62)

- **GitHub Actions federation: the CI and release identities are now disjoint.** A
  release-environment OIDC token matched **both** `gha-ci` and `gha-release`, so
  the federated exchange failed closed on `multiple_sa_match` (401) and blocked
  every release-publish path under `HORT_PROXY_ENABLED`. `gha-ci` is now scoped to
  a non-gating `ci` deployment environment, making the two identities disjoint by
  construction (positive-claim scoping, the standard for GitHub-Actions OIDC
  federation). (#64)

### Security

- **The GitHub `hort-auth` action no longer echoes the token-exchange response
  body to CI logs.** On a failed exchange the action printed the raw response body
  (the GitHub twin of the previously-fixed GitLab leak), which could surface a
  bearer token in public Actions logs. The failure path is now sanitized. (#61)

## [0.9.11] - 2026-07-19

### Added

- **`HORT_STORAGE_PUT_TIMEOUT_SECS`** (default `300`) — an overall bound on the
  S3/object-store `put` multipart sequence (init + parts + complete + copy +
  staging delete). `object_store` bounds each individual HTTP call but nothing
  capped the aggregate, so a degraded backend could stall a pull-through
  ingest for tens of minutes with no error. The whole operation now fails fast
  at the configured bound.

### Fixed

- **Anonymous `docker pull` of a public pull-through repository now completes
  its token handshake.** `GET /v2/auth` unconditionally `401`'d without a
  `Authorization: Basic` credential, dead-ending the challenge-driven flow used
  by skopeo, buildah, podman and cosign. Per the OCI Distribution Spec token
  flow, the mint endpoint now issues a token for an anonymous request, granting
  `pull` exactly when the repository is public — byte-identical to the
  consume-side read gate. Private repositories, `push`/`delete` actions and
  `registry:catalog` are never anonymously granted; an all-private request
  mints a valid token with an empty `access[]` rather than a `401`. (#48)

- **A proxied multi-arch image index now releases together with its children.**
  Manifest ingest records `content_references` edges to the config and layer
  blobs it references (previously only index→child edges existed), and an
  artifact that is already a referenced descendant gets a zero-length
  quarantine window instead of waiting out a window in which no additional
  observation happens. The release predicate itself is unchanged — a descendant
  still requires its own scan authority (ADR 0007). These edges were initially
  written only on the hosted-push path; the pull-through ingest path now writes
  them too, which is what makes the behavior reach proxied images at all. (#46)

- **Purging a manifest or index no longer strands its `oci_*` reference edges.**
  Purge tombstones the artifact row rather than hard-deleting it, so the
  `ON DELETE CASCADE` never fired, and purge itself swept only the
  `primary_content`/`metadata_blob` refcount kinds. The dangling
  `oci_index_member`/`oci_subject`/`oci_config`/`oci_layer` source-edges then
  kept every blob they pointed at permanently ineligible for GC. Purge now
  sweeps all kinds, matching the manifest-DELETE path. (#49)

- **A pull-through blob that genuinely does not exist upstream now returns a
  terminal `BLOB_UNKNOWN` 404 instead of a `502`.** Every `fetch_blob` failure —
  including an upstream `404` — collapsed into a "upstream unavailable" `502`,
  which containerd treats as retryable: a pod with an absent layer sat in
  `PodInitializing` indefinitely with no `ErrImagePull`. (#53)

- **The clearance-gating provenance-verify jobs are enqueued at elevated
  priority.** For a repository that waives scanning, the signature-arrival
  provenance-verify is the only job gating release, and at priority 0 it queued
  behind the entire bulk ingest backlog — so `ProvenanceVerified` landed too
  late and the release sweep kept skipping for lack of clearance. The two
  clearance-gating enqueues (signature-arrival and expiry-backstop) now preempt
  bulk ingest work. Scheduling order only; the fail-closed release-authority
  gate (ADR 0007) is untouched. (#44)

- **The public Helm chart (`ghcr.io/project-hort/charts/hort-server`) is
  signed.** It was pushed unsigned, leaving Flux `.spec.chart.spec.verify`
  consumers with no legacy `.sig` tag to gate against. It is now keyless-signed
  (Fulcio OIDC — the same trust anchor as the public images) in legacy `.sig`
  mode, which is what Flux's source-controller discovers, and the release fails
  if the signature tag is missing. `install.md` §5.0 documents the `cosign
  verify` command and a Flux `matchOIDCIdentity` verify block. (#47)

### Changed

- **The storage `put` timeout reports which phase stalled.** On elapse it names
  the backend, the phase (init-multipart / reading / uploading-part /
  final-part / head-dedup / complete / copy / delete-staging), bytes read and
  parts uploaded, so a stalled ingest yields evidence rather than a bare
  timeout. An optional per-part debug timeline is available under
  `RUST_LOG=debug`. Pure observability — no change to multipart behavior. (#53)

## [0.9.10] - 2026-07-16

_Release-pipeline verification + CI / test-harness hardening; no user-facing
product changes. Restores and verifies the public release pipeline that failed
on v0.9.9, and hardens CI: GitLab pipeline scope (#38), podman-runner pinning
for the long test jobs (#39), `test:unit`/`test:coverage` parallelization (#43),
an OCI provenance-E2E read-grant fix (#41), E2E worker throughput (#44), and
`build-binaries` apt-retry hardening against transient mirror outages (#45)._

## [0.9.9] - 2026-07-15

### Added

- **`HORT_RATELIMIT_EXEMPT_CIDRS`** (Helm `rateLimitExemptCidrs`) — source CIDRs
  whose resolved client IP bypasses both rate-limit buckets. For first-party CI
  that shares one egress IP (or sits behind one ingress) and would otherwise
  collapse into a single per-IP bucket and `429` on legitimate publish bursts.
  Keyed on the trust-resolved client IP (not a spoofable header). Note: this
  also removes the per-IP anti-credential-stuffing limit on the token-mint
  paths for that range — list only fully trusted CI egress ranges.

### Fixed

- **A gitops boot-apply with an upstream host outside
  `HORT_UPSTREAM_ALLOWLIST_HOSTS` now parks the pod not-ready (`/readyz` 503)
  with a clear reason instead of writing some rows and then crashlooping.** The
  allowlist was enforced only in the write stage (after repository rows were
  already persisted), so a config gap left the config half-applied and the pod
  in `CrashLoopBackOff`. The check now runs in the pre-write validation pass, so
  the same violation is caught before any write and fails closed — the
  documented apply-time scope (create/update only; deletes and unchanged rows
  exempt) is unchanged.

- **The inbound rate limiter now sustains its configured per-minute rate.** The
  auth (`HORT_RATELIMIT_AUTH_PER_MIN`, default 60) and write
  (`HORT_RATELIMIT_WRITE_PER_MIN`, default 300) token buckets replenished one
  token per minute regardless of the cap, so after the initial burst, sustained
  traffic was throttled to ~1 request/minute — roughly 60×/300× tighter than
  documented — which persistently `429`'d automated writers such as CI pushing
  multi-layer images. Tokens now replenish at the configured per-minute rate.
- **Rate-limit `429` responses no longer advertise `Retry-After: 0`.** A
  sub-second wait is rounded up to at least 1 second, so a throttled client
  backs off for a beat instead of hot-looping on an immediate retry.

### Security

- Bumped `crossbeam-epoch` to 0.9.20 (transitive, via the Prometheus metrics
  exporter) to clear RUSTSEC-2026-0204 (invalid pointer dereference in the
  `fmt::Pointer` impl for `Atomic`/`Shared`). Bumped the `serial_test`
  dev-dependency to 3.5.0, which drops the unsound `scc` (RUSTSEC-2026-0205);
  `scc` was test-only and never shipped.

## [0.9.8] - 2026-07-05

Headlines: OCI **image-index / manifest-list (multi-arch) push**; **working
push-then-sign under `provenance_mode: Required`** end to end — an unsigned
image (index-shaped included) is held for the quarantine window, keyed cosign
v3 signatures verify against the pinned key, and a verified signature clears
the signed tree so the released image pulls (issues #13, #14, #15);
**identity-only service accounts** — authority comes exclusively from explicit
`PermissionGrant`s and issued-token caps snapshot the effective grants
(ADR 0044); OCI **chunked blob-upload push** (buildah / podman / skopeo stream
layers via HTTP `Transfer-Encoding: chunked`, no `Content-Length`, streamed and
bounded by the publish-body limit); and an authoritative, self-pruning
per-`(repo, principal)` OCI **upload-session cap**.

### Added

- **OCI image-index / manifest-list (multi-arch) support.** Hosted OCI repos
  accept `application/vnd.oci.image.index.v1+json` and Docker manifest-list
  PUTs (previously rejected `MANIFEST_INVALID`), so `skopeo copy --all`,
  buildah/podman multi-arch pushes, and cosign signing of the index digest
  work. An index is stored as a generic manifest artifact riding the normal
  quarantine/scan/release/provenance lifecycle; each child manifest is
  validated to exist in-repo on PUT, the declared media type is cross-checked
  against the manifest shape, and index→child membership keeps every child's
  content alive under GC. (issue #15, ADR 0043)
- A `hort-sweep-ticker` sidecar in the reference compose deployment enqueues
  the quarantine-release sweep periodically — compose's stand-in for the Helm
  `scheduledTasks` CronJobs / native `hort_timers`, so release and expiry
  decisions happen without a surrounding scheduler. (issue #14)

### Changed

- **The `ServiceAccount` gitops envelope is identity-only** — it declares who
  may assume the account (`federatedIdentities[].claims`, `fallbackRotation`)
  and confers no authority. A service account's authority is exclusively its
  explicit `PermissionGrant`s (`serviceAccount`-subject grants, ADR 0037), and
  the two unattended issuance sites — the federation `/exchange` and the
  fallback-rotation mint — derive the issued token's cap as a snapshot of the
  effective grants at issuance (the exchange additionally intersects the
  RFC 8693 `scope` parameter; rotated fallback tokens now carry the SA's real
  granted authority instead of an empty, deny-all cap). Grants added apply at
  the next exchange or rotation; revocations bite outstanding tokens
  immediately through the live grants leg. (issue #13, ADR 0044)
- A **write-authorized** caller may now `GET` (not just `HEAD`) a held
  manifest: keyed `cosign sign` resolves the subject manifest by GET before
  attaching a signature, so the HEAD-only exemption blocked in-place
  push-then-sign. A manifest is a routing document — layer blobs stay gated
  (503) for every caller while held, and non-writers still receive 503 for
  both verbs. (issue #14, ADR 0039)
- **Keyed cosign signing against a hosted repo must use
  `--registry-referrers-mode=oci-1-1`** (subject-based referrers); the legacy
  `sha256-<hex>.sig` tag mode is not linked to its subject on the push path, so
  a signature pushed that way stays invisible to the verifier.

### Removed

- The `role:` and `repositories:` fields of the `ServiceAccount` gitops
  envelope. An envelope still declaring them fails apply at parse; migration
  014 drops the columns. (ADR 0044)

### Fixed

- **An anonymous OCI read denied at the repository level now returns `401` +
  a mode-appropriate `WWW-Authenticate` challenge instead of a bare `404`.**
  A standard `docker pull` / kubelet pull of a private image presents no
  credential on its first request and only retries with its
  `imagePullSecrets` credential when challenged; a `404` gave it nothing to
  react to, so the pull failed even with a correctly configured Secret. The
  new challenge is byte-identical (modulo the request's own echoed scope)
  whether the repository is private or does not exist at all, so no new
  existence oracle opens; an authenticated caller without read access still
  gets the unchanged `404 NAME_UNKNOWN` anti-enumeration response. Anonymous
  writes on `/v2/*` now advertise the same mode-appropriate challenge scheme
  instead of a hardcoded legacy one.
- **A native `hort_pat_*` / `hort_svc_*` token presented directly on `/v2/*`
  now validates under `HORT_AUTH_PROVIDER=disabled` +
  `HORT_NATIVE_TOKENS_ENABLED=true` deployments, matching behavior already
  in place when an IdP is configured.** Such a token was previously rejected
  at the OCI auth middleware before it ever reached token validation.
- **The quarantine hold-read exemption keys on the principal's granted write
  authority, so native-token cosign signing completes.** The exemption
  (held-manifest HEAD/GET, held-blob HEAD existence probe) resolved `Write`
  through the grants leg **and** the presented token's cap. Standard OCI
  clients scope a subject read as `pull`, so under native tokens cosign's
  subject read rides a read-only capability token and the cap leg failed the
  exemption's `Write` check — the held-manifest GET `503`d and `cosign sign`
  aborted. The exemption now consults the grants leg alone (the read itself
  stays cap-gated); a bounded, documented exception to the ADR 0036
  cap-intersection invariant (ADR 0039 §10), with the fail-closed admin-claim
  guard preserved. The push-then-sign E2E gains a native-token-mode run where
  cosign's subject read rides a pull-scoped capability token. (issue #13)
- **The `GET /v2/` auth-discovery probe advertises the Bearer `/v2/auth`
  challenge when native tokens are enabled.** The probe hardcoded
  `WWW-Authenticate: Basic realm="hort"`, so OCI clients (skopeo, docker,
  podman, cosign) cached Basic for the session and never minted a capability
  token at `/v2/auth` — an opaque `hort_pat_*`/`hort_svc_*` credential then
  rode the Basic password slot, which no read-path validator accepts, and
  every read degraded to anonymous (private repos anti-enumerate to 404:
  pushes succeeded, the pushed image could not be read back or signed). The
  probe now emits the same challenge the `/v2/*` middleware selects: `Bearer
  realm="<base>/v2/auth",service="<host>"` with the signing key wired, legacy
  Basic otherwise. (issues #13, #16)
- **cosign v3 keyed signatures now verify.** `cosign sign --key
  --registry-referrers-mode=oci-1-1` (cosign v3) emits a Sigstore v0.3 bundle
  referrer carrying a DSSE envelope, not the legacy `simplesigning` layer the
  `cosign-key` backend consumed — a validly keyed-signed image was judged
  `NoAttestation` and rejected `Unsigned`. The keyed verifier now extracts the
  DSSE PAE signing input, signature, and subject-digest binding from a keyed
  bundle (no Fulcio chain) and verifies it against the pinned P-256 key,
  rejecting a signature over a different digest. The legacy `simplesigning`
  carriage and keyless (Fulcio-chain) bundle routing are unchanged.
  (issue #14, ADR 0039)
- **A validly signed image is now consumable under `provenanceMode: required`
  (provenance-clearance cascade).** cosign signs only the top-level digest, so
  the per-artifact provenance gate terminally rejected every constituent of a
  signed image — child manifests and config/layer blobs can never carry their
  own signature — leaving a released multi-arch index unpullable (child GETs
  404). A verified signature now cascades the provenance clearance to the
  constituents bound by the verified content: the index's signed bytes carry
  the child-manifest digests and each manifest's bytes carry its config/layer
  digests, so the signature over the root covers exactly that tree. The
  cascade is repository-scoped, applies only to held artifacts (a terminally
  rejected constituent stays rejected), clears only the provenance gate (scan
  and quarantine-window gates remain per-artifact), and records each cascaded
  clearance as a `ProvenanceVerified` attributed to the root digest via
  `cascaded_from`; the cascade append retries once on a version conflict and a
  re-verify of a directly-cleared subject re-drives it, so re-signing heals a
  partial cascade. A never-signed image and its constituents still reject
  `Unsigned` at window expiry. (ADR 0039 §11, ADR 0043)
- **`provenance_mode: Required` supports the push-then-sign CI flow.** An
  unsigned artifact is held for its quarantine window and re-verified when the
  cosign signature arrives; it is rejected `Unsigned` only if still unsigned at
  window expiry (issue #13).
- **OCI chunked blob-upload push now works (buildah / podman / skopeo).** The OCI
  blob-upload `PATCH` and finalize `PUT` handlers hard-required a `Content-Length`
  header and rejected its absence with `BLOB_UPLOAD_INVALID`. Clients that stream a
  layer via HTTP `Transfer-Encoding: chunked` send no `Content-Length` (RFC 7230
  §3.3.2 forbids it alongside chunked TE), so every such push failed
  deterministically. `Content-Length` is now optional on both handlers: when absent
  the body is streamed and bounded in-stream by the publish-body limit (an
  over-limit body is rejected `SIZE_INVALID` with staging capped), and the actual
  bytes staged are authoritative; when present the declared-length cross-check is
  unchanged. (issues 11, 12)
- **OCI blob-upload-session cap no longer leaks (issue 9).** The
  per-`(repo, principal)` cap on concurrent OCI upload sessions was a
  free-floating counter that only decremented on explicit release: an abandoned
  upload (POST with no final PUT and no DELETE) never decremented it, and its TTL
  refreshed on every increment, so a retry storm could pin the counter at the cap
  and raising the cap could not clear it. The cap is now an authoritative,
  self-pruning live-session **set**, keyed per `(format, repo, principal)` and
  reconciled on every admit: it age-prunes members older than the session max-age
  (catching both POST-only and PATCHed abandons), rejects at cap with no write
  (so a rejection never refreshes the TTL — the leak is structurally gone), and
  fails closed on CAS-loop exhaustion. Pathological write contention now surfaces
  as a transient `503 Service Unavailable` + short `Retry-After` (never a `500`).
  Adds the `HORT_OCI_SESSION_MAX_AGE_SECS` config knob (1..=604800 s, default
  3600; previously a hardcoded constant), a bounded cap-exceeded `Retry-After`
  (15 s), and the OCI-spec `DELETE /v2/<name>/blobs/uploads/<uuid>` cancel route.

### Security

- **`quick-xml` DoS advisories RUSTSEC-2026-0194 / -0195 accepted as a bounded
  risk.** `quick-xml` (transitive via `object_store`) has no `object_store`-
  compatible fixed release. It is reachable only through `object_store` parsing
  XML from the TLS-verified, operator-configured S3/Azure backend, not the
  artifact push/pull path. Ignored in `.cargo/audit.toml` + `deny.toml`; revisit
  when `object_store` adopts `quick-xml >= 0.41.0`.

## [0.9.7] - 2026-06-30

Headlines: ingest now commits the scan and
provenance-verify enqueues **atomically** with the artifact transition, closing
a dual-write window that could leave an artifact ingested-but-unscanned; a clean
re-scan of a terminal (rejected) artifact no longer loops the worker job; and a
RustSec advisory fix (anyhow → 1.0.103).

### Security

- **anyhow upgraded to 1.0.103 (RUSTSEC-2026-0190).** Fixes an unsoundness in
  `anyhow::Error::downcast_mut()` — adding context via `Error::context` and then
  calling `downcast_mut` constructed a mutable reference through a shared borrow,
  violating Rust's aliasing rules (undefined behavior). The patched release
  reworks how the reference is built.

### Fixed

- **Ingest commits its scan and provenance-verify enqueues atomically with the
  artifact transition.** The auto-scan and provenance-gate `jobs` rows now land
  in the **same transaction** as the `ArtifactIngested` / `ScanRequested` events,
  so a crash or failure between the two can no longer strand an artifact with the
  event but no job — which previously left it quarantined and unscanned until a
  manual rescan. The no-strand guarantee is backend-agnostic: the Postgres
  adapter fulfils it with one transaction; a native event-store backend must use
  a transactional outbox.
- **A clean re-scan of a terminal (rejected) artifact no longer loops the worker
  job.** Recording a now-clean scan onto an already-`rejected` artifact now
  records the fresh findings without attempting the illegal state transition,
  instead of failing and retrying the job to exhaustion. The artifact stays
  `rejected` (only an exclusion re-evaluation clears it); the refreshed findings
  enable an honest later recovery.

## [0.9.6] - 2026-06-27

Beta release (`0.9.6-beta.5`). Headlines: scan-policy is now **continuously
enforced** — a gate-affecting policy change re-derives every in-scope artifact's
verdict from its stored findings in **both directions**, closing a fail-open
where a tightened policy left already-decided artifacts un-re-evaluated (ADR 0041);
and OSV **informational** advisories (`unmaintained` / `unsound` / `notice`) no
longer over-block — they ride a non-enforcing **negligible** lane, operator-steered
per policy (ADR 0040). Plus a keyed cosign-key provenance backend.

### Security

- **Scan-policy is continuously enforced — the fail-open tightening gap is
  closed.** A gate-affecting `ScanPolicy` change (raising a severity threshold,
  adding a blocked class, `negligibleAction: block`, or adding/removing an
  exclusion) now re-derives every in-scope artifact's verdict from its **stored
  scan findings** under the new policy, in **both directions** — releasing
  now-passing rejections and re-holding now-failing releases — via an async
  worker pass off the request path. Previously a *tightening* re-evaluated
  nothing, leaving artifacts the operator had just declared unacceptable still
  downloadable. No scanner is re-run (the stored findings are the evidence) and
  no new release authority is added: a re-release fires only on the full
  cross-axis conjunction scan ∧ curation ∧ provenance, preserving the fail-closed
  release predicate. (ADR 0041)

### Added

- **OSV informational advisories ride the negligible lane, operator-steered.**
  RustSec `unmaintained` / `unsound` / `notice` advisories — which carry no
  CVSS — no longer map to Critical and reject an artifact; they route to the
  non-enforcing negligible tier. The new `ScanPolicy.negligibleAction`
  (`ignore`, the default — never block; `warn` — record only; `block` — reject)
  steers them per policy. The raw OSV class is persisted, so an
  exclusion-triggered re-evaluation respects the current policy; a finding with
  no CVSS **and** no recognised informational class still fails closed to
  Critical. (ADR 0040)
- **Keyed (cosign-key) provenance backend** — verify artifact provenance against
  a pinned cosign public key, alongside the existing keyless path.
- **gitlab-ci federation `ServiceAccount`** — a gitops `ServiceAccount` for
  GitLab CI OIDC federation against a hort instance.

### Changed

- **`cron-rescan-tick` is enabled by default** in the native `hort_timers`
  Ansible role, so proxied artifacts are rescanned on a cadence out of the box.

### Fixed

- **Native osv-scanner pinned to v2.3.8** (with a pin-sync guard against the
  worker container's `OSV_SCANNER_VERSION`). The native deploy had drifted to
  v1.9.1, which lacks the v2 `scan source` CLI the scanner adapter invokes — so
  every scan failed and proxied artifacts stranded in quarantine.
- **GitLab CI hort-auth federation** — install `curl` before the OIDC exchange,
  trust the internal-PKI CA before it, and configure the cargo
  credential-provider + HTTP-Basic token, so federated CI works against a hort
  instance behind an internal CA.
- **Prefetch resolves cargo/npm download URLs from authoritative upstream
  metadata.** Proxied cargo/npm dependency prefetch now derives each download URL
  from the package's authoritative upstream metadata, so prefetched artifacts
  fetch from the correct location.

## [0.9.5] - 2026-06-26

Beta release (`0.9.5-beta.1`). Headline: the OCI `/v2/auth` authorization model
is reworked into a per-identity **capability token**, service accounts are made
**strictly non-admin**, and a first-class **no-IdP admin-bootstrap** path is added.

### Security

- **OCI `/v2/auth` is a per-identity capability token.** The token-exchange mint
  no longer confers ambient admin (the mint principal carries `claims: []`);
  authority is the caller's `User`-subject `PermissionGrant`s intersected with the
  token cap — the same basis the consume side re-evaluates — closing the over-grant
  where the mint granted `pull`/`push` scopes that the `/v2/*` resource gate then
  denied. Admin is not an OCI scope and the token never carries it. (ADR 0036)
- **Service accounts are strictly non-admin — no exception.** `issue-svc-token`
  rejects `--permission=admin` and requires a pre-existing gitops `ServiceAccount`;
  a gitops `serviceAccount`-subject `PermissionGrant` may not carry `admin`; and the
  apply-time RBAC linter no longer exempts SA-owned `Admin` grants from the
  high-privilege reject. (ADR 0037, ADR 0038)
- **Fail-closed cap backstop.** A cap-bound native token (`Pat` / `ServiceAccount`)
  presenting the `admin` claim with a `None` cap is denied; OIDC and CliSession
  principals, which legitimately carry no cap, are unaffected. (ADR 0036)

### Added

- **gitops `PermissionGrant` may target a ServiceAccount by name** —
  `subject: { kind: serviceAccount, name: … }` resolves at apply to a `User`-subject
  grant on the SA's backing user, so a non-admin service account can hold scoped
  `read` / `curate` / `admin_task_invoke` / global authority without an `is_admin`
  bit (the domain `GrantSubject` taxonomy is unchanged). (ADR 0037)
- **`hort-server admin bootstrap-session`** — a DSN-gated, short-lived (≤1 h),
  non-service-account admin token for the no-IdP / first-admin / break-glass path,
  gated by `HORT_TOKEN_ALLOW_ADMIN`. (ADR 0038)
- **Optional Dex IdP sidecar** (Helm + Ansible) wiring the human-admin
  OIDC → CliSession path; **off by default**. (ADR 0038)
- **Native systemd timers** for the periodic worker tasks (`hort_timers` Ansible
  role) — the native-flavour equivalent of the Helm CronJobs.

### Changed

- **Admin-identity model — IdP-assumed, zero standing privilege.** Human admin is
  OIDC (Dex / the organisation's SSO) → CliSession, or the DSN-gated
  `bootstrap-session`; the deployment de-admins the operator/cron service accounts
  (`maintainer-dev` → `read`, `maintainer-curator` → `curate`, `cronjob-tasks` →
  `admin_task_invoke`, all non-admin via standalone `serviceAccount` grants).
  Destructive scheduled tasks (`eventstore-archive` / `retention-purge` /
  `retention-evaluate`) are **off by default** — they require a fresh admin session
  and are run on demand (a propose→confirm→execute approval workflow is the tracked
  follow-on). (ADR 0038)
- **`HORT_TRUSTED_PROXY_CIDRS`** is set in the deployment so `hort-server` observes
  the real client IP behind the edge (nginx) proxy.

### Fixed

- **`issue-svc-token` could not find a gitops-declared service account**
  (`0.9.5-beta.2`). `svc_username` looked up `hort-svc-<name>` while a gitops
  `ServiceAccount` apply creates its backing user as `sa:<name>`, so the
  "requires a pre-existing gitops ServiceAccount" mint flow — the Ansible
  `maintainer-dev`/`maintainer-curator` tokens and the Helm `cronjob-tasks` token
  — was non-functional in `0.9.5-beta.1`. The convention is now single-sourced as
  `hort_domain::entities::service_account::backing_username` and every
  construct/parse site (CLI lookup, gitops apply, auth parse, k8s payload) routes
  through it, guarded by a cross-convention test.
- **Server parked (registry served `503`) when the IdP was disabled**
  (`0.9.5-beta.2`). The Ansible gitops tree shipped the `admins` `ClaimMapping`
  unconditionally, but the native/podman flavors default
  `HORT_AUTH_PROVIDER=disabled`; `hort-server`'s gitops preflight then refuses the
  dormant ClaimMapping and parks (`/readyz=503`, status-only). The deploy now
  gates the ClaimMapping on the IdP being enabled (`hort_dex_enabled`) and removes
  it otherwise — which also un-parks a host previously synced with it present.
  Admin without an IdP remains the DSN-gated `bootstrap-session` (ADR 0038).

## [0.9.4] - 2026-06-21

Beta release. The feature set is described in the documentation under `docs/`.

### Added

- **Maven / Gradle format handler.** Pull-through proxying for Maven Central and
  Gradle repositories, covering the multi-file artifact shape (POM, JAR, and the
  per-file `.sha1` / `.md5` sidecars) and Gradle module metadata. Upstream
  transfers are checksum-verified against a SHA-1 floor — a Maven artifact whose
  upstream checksum cannot be verified is not served (ADR 0032 *Maven/Gradle
  multi-file handler*, ADR 0033 *SHA-1 upstream transfer-verification floor*).
- **Maven / Gradle virtual (aggregated) repositories.** `type: virtual`
  aggregation now covers Maven/Gradle (joining npm / PyPI / Cargo), so a single
  virtual repo can front several Maven members under the same
  dependency-confusion defences (ADR 0031).
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
- **OCI `/v2/auth` no longer rejects the credential before the token exchange.**
  The `/v2/*` bearer-auth middleware (`oci_bearer_auth`) also ran on the
  `/v2/auth` token endpoint and treated the inbound `Basic <PAT>` as a bearer
  JWT — which a PAT (or a federated token) is not — so it was rejected with
  `401` before the PAT→token-exchange handler could run, breaking push/pull and
  proxy pull-through for every credentialed client. The middleware now
  path-skips `/v2/auth`, so the handler's PAT validation and bearer mint run.
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
