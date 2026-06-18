# `security-hardening-checklist.md` — the chart's security controls

> **This is the chart's hardening posture** — operator-facing controls that
> the chart toggles or enforces, with verification commands an operator can
> run post-install. It is **not** the regulator-facing `SECURITY.md` /
> GDPR retention-and-erasure documentation: those live with the
> compliance-docs track (`docs/compliance/`). The two docs
> serve distinct audiences:
>
> - **This doc** = SecOps reviewers and platform operators. *"Did the chart
>   ship the security control? Where do I see it? What's the override?"*
> - **`SECURITY.md` / GDPR docs** = product leadership,
>   customer security teams, EU/UK regulators. *"What is the product's
>   security posture? How does it handle personal data? What's the
>   disclosure process?"*
>
> Keep them separate. Do not let one substitute for the other.

This checklist enumerates every security-audit control
that has a deployment-side toggle the chart either flips by default or
exposes as a `values.yaml` key. Source-only fixes (refactors, removed
deps, log redactions, internal newtypes) are intentionally omitted —
they ship with the binary and an operator cannot meaningfully verify
them post-install.

## How to read this checklist

Each entry has the same shape:

- **Control** — what the security audit found.
- **Chart default** — what the chart ships out of the box.
- **Operator action required** — `yes`, `no`, or `conditional`, and on
  what condition.
- **Verify post-install** — a `kubectl` / `curl` / `helm` one-liner that
  proves the control is active.
- **Relaxation** — what the values key + caveat looks like if the
  operator must opt out, or `none` if the control is unconditional.

If a control needs no operator action AND the chart enforces it
unconditionally, the entry is short (4-5 lines). Operator-tunable
controls run longer (10-15 lines).

In the verification commands, substitute `<ns>` with the install
namespace, `<release>` with the Helm release name, and
`<svc-or-ingress>` with the cluster-internal service URL or the
public hostname of the operator's edge.

---

## First-audit controls (deployment-side surface)

### `AuthContext::Disabled` is fail-closed in OCI

- **Control:** When `auth.provider: disabled`, no synthetic admin
  principal is injected by the OCI middleware. Anonymous OCI requests
  fail closed with 401 instead of being treated as admin.
- **Chart default:** `auth.provider: oidc`. The chart's
  `values.schema.json` accepts `disabled` but `templates/NOTES.txt`
  emits a prominent warning post-install.
- **Operator action required:** no — the binary does the right thing
  unconditionally.
- **Verify post-install:**
  ```bash
  curl -i http://<svc-or-ingress>/v2/anything/manifests/latest
  # Expect: HTTP/1.1 401 Unauthorized (NOT 200, NOT 403 with admin role)
  ```
- **Relaxation:** none. Setting `auth.provider: disabled` does not
  re-introduce the synthetic admin; it only suppresses authentication
  on routes that voluntarily skip `authorize()`.

### Per-request deadline + slowloris timeout

- **Control:** HTTP/1 header-read timeout (15s default), request
  deadline (300s default, 3600s for OCI blob uploads), keep-alive
  timeout. Slowloris connections close before reaching the rate
  limiter.
- **Chart default:** `http.headerReadTimeoutSeconds: 15`,
  `http.requestTimeoutSeconds: 300`, `oci.uploadTimeoutSeconds: 3600`.
- **Operator action required:** no — chart ships sane defaults.
- **Verify post-install:**
  ```bash
  kubectl exec -n <ns> deploy/<release>-hort-server -- env \
    | grep -E '^HORT_HTTP_(HEADER_READ|REQUEST|OCI_UPLOAD)_TIMEOUT'
  ```
- **Relaxation:** raise the values to accommodate large pushes; do not
  set them to 0. The OCI upload timeout is the upper bound on a single
  blob PUT — sized for multi-GB image layers.

### `/metrics` requires authentication

- **Control:** `/metrics` is bound on a separate listener by default
  (chart binds it to loopback inside the pod) and requires admin
  authentication regardless of which listener serves it. Anonymous
  scraping is refused. The dedicated listener also refuses to bind to
  unspecified addresses (`0.0.0.0` / `::`) without an explicit
  operator opt-in (`metrics.allowUnspecifiedBind: true`).
- **Chart default:** `metrics.bindAddr: "127.0.0.1:9090"`,
  `metrics.allowUnspecifiedBind: false`, `metrics.requireAuth: true`.
  The chart renders the dedicated listener on port 9090, scoped to
  in-pod / sidecar-scrape access.
- **Operator action required:** no for default config; conditional
  yes if scraping from outside the pod (configure a `ServiceMonitor`
  with bearer-token auth, see `install.md` Appendix).
- **Verify post-install:**
  ```bash
  curl -i http://<svc-or-ingress>/metrics
  # Expect: HTTP/1.1 401 Unauthorized on the main listener (or 404
  #         when metrics.bindAddr is non-empty — /metrics is only on
  #         the dedicated listener in that mode).
  # A 200 means metrics.requireAuth=false — re-check values.
  ```
- **Relaxation:** `metrics.requireAuth: false` re-enables anonymous
  scraping; the chart emits a `NOTES.txt` warning. Keep
  `metrics.bindAddr` non-empty (default `127.0.0.1:9090`, or set to a
  pod-internal interface) so the surface stays inside the pod even
  when unauthenticated. Setting `metrics.bindAddr: ""` mounts
  `/metrics` on the main 8080 router (dev mode); production
  deployments leave the dedicated listener in place.
- **Single-tenant pattern (explicitly supported relaxation):** in a
  single-tenant cluster where access to the metrics port is gated by
  a `NetworkPolicy` that the operator ships alongside the
  `ServiceMonitor`, `metrics.requireAuth: false` is an acceptable
  trade. What `/metrics` reveals if reached (repository names from
  the `repository` label, auth-failure rates, request-rate shape) is
  reconnaissance value, not a direct compromise — no secrets, no
  artifact bytes, no tokens. The trade is defence-in-depth: with auth
  on, a misconfigured / removed NP shows up as 401 errors in
  Prometheus (a visible near-miss); with auth off, the same operator
  error means the endpoint becomes reachable from anywhere on the
  pod network. Two operational disciplines make the relaxation safe:
  (1) the NP and the `ServiceMonitor` live in the same
  operator-owned overlay so they cannot drift apart across changes,
  and (2) Prometheus alerts on `up{job="hort-server"} == 0` so a
  scrape-broken-by-NP-change is detected within minutes, not weeks.
  Do **not** apply this relaxation in multi-tenant clusters or
  clusters where NP is not part of the versioned deployment
  artefact.

### SSRF redirect-hop revalidation

- **Control:** Outbound `reqwest::Client` revalidates each redirect
  hop's resolved IP against the SSRF predicate before following.
- **Chart default:** unconditional in the binary; no values key.
- **Operator action required:** no.
- **Verify post-install:** no observable signal — the predicate is
  internal. The cargo-test gate at CI is the regression lock; the
  image tag is the proof of inclusion.
- **Relaxation:** none.

### Connect-time DNS pinning (removed)

- **Status:** **No longer enforced.** The `GuardedDnsResolver` was
  removed from `hort-adapters-upstream-http`,
  matching the earlier revert in `hort-adapters-oidc`. S3 was
  never wired. The disposition has shifted from "closed by code"
  to **"accept with layered-defence rationale"**.
- **Why the reversal:** the guard false-positived on every internal-
  mirror topology resolving to RFC 1918 / ULA / link-local — internal
  Artifactory, in-cluster verdaccio, on-prem npm proxy. The threat it
  closed (DNS-rebind to IMDS during a redirect chain) is gated by
  three load-bearing layers that remain in force:
  1. **Cross-origin Authorization-strip** — credentials
     do not leak to a rebound target.
  2. **Upstream checksum verification** (ADR 0006) — content
     returned by a rebound target does not match the expected digest;
     the artifact is rejected at content-hash time.
  3. **TLS certificate validation** — a rebound target serves either no
     cert or a different cert; the connection fails before any content
     transits.
- **Operator action required:** no, but be aware that upstream URLs
  resolving to private IPs are now reachable. The previous
  `loopback_test_allowlist` workaround in `Config` has been deleted;
  no allowlist is needed.
- **Verify post-install:** an upstream URL whose hostname resolves to
  an RFC 1918 address now connects normally; previously this returned
  `upstream host … resolves to no routable address`.
- **Relaxation:** N/A — the guard is gone. Re-introducing it is an
  architecture-level decision, not a values toggle.

### HTTPS-only realm + upstream URL scheme

- **Control:** `WWW-Authenticate: Bearer realm=...` URLs and
  `RepositoryUpstreamMapping.upstream_url` reject any scheme other
  than `https://` at value-object construction time. Plaintext
  upstreams require an explicit per-mapping `insecure_upstream_url`
  opt-in flag (gitops only).
- **Chart default:** unconditional in the binary.
- **Operator action required:** no, unless deliberately mirroring
  internal plaintext upstreams.
- **Verify post-install:** an `apply` that includes a mapping with an
  `http://` upstream will be rejected at gitops apply time:
  ```bash
  kubectl logs -n <ns> job/<release>-hort-server-migrate \
    | grep -i 'upstream.*scheme'
  ```
- **Relaxation:** per-mapping `insecure_upstream_url: true` in the
  gitops YAML. Every fetch then emits `WARN` and increments
  `hort_upstream_insecure_total`.

### Operating behind an egress (forward) proxy

- **What uses the proxy:** Hort builds every outbound `reqwest` client
  with the `system-proxy` feature, so **all** outbound HTTP(S) — upstream
  pull-through, the Bearer realm/token exchange, OIDC discovery + JWKS,
  webhook delivery, and (where applicable) object storage — honours the
  standard `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` (+ lowercase) and
  `NO_PROXY` environment variables. Hort does **not** force `.no_proxy()`
  on any client: a forward proxy is a legitimate egress control and is
  often the only route out, so Hort defers to the operator's proxy config.
- **SSRF guards are delegated to the proxy when one is set (load-bearing).**
  Hort's in-process connect-time SSRF checks — the webhook
  `GuardedDnsResolver`, the realm-fetch routability check, and
  the JWKS host check — can only inspect the address Hort *dials*. Behind a
  proxy, Hort dials the **proxy** and the proxy resolves/connects to the
  real target, so these in-process guards no longer see the destination.
  **The proxy therefore becomes the SSRF boundary and MUST enforce an
  egress allowlist that blocks link-local (`169.254.0.0/16`, IMDS), RFC1918,
  ULA, and loopback destinations** for webhook/upstream targets. If the
  proxy is a dumb forwarder with no allowlist, the webhook DNS-rebind /
  upstream-poisoning SSRF surface is reopened *at the proxy*.
- **Hort warns when this delegation is active.** On startup the webhook
  notifier emits a `WARN` (`proxy_env=[…]`) when a proxy env var is set,
  stating that the in-process SSRF guard is delegated to the proxy's
  allowlist. Treat that line as a prompt to confirm the proxy's egress
  policy. **Verify post-install:**
  ```bash
  kubectl logs -n <ns> deploy/<release>-hort-server \
    | grep -i 'routes through an egress proxy'
  ```
- **Webhook subscription *create/update* and `HORT_WEBHOOK_ALLOWLIST_HOSTS`.**
  The create-time SSRF guard (`WebhookTargetGuard::check`,
  run when a subscription is created or its target is changed) consults the
  **same** `HORT_WEBHOOK_ALLOWLIST_HOSTS` allowlist the delivery-path
  `GuardedDnsResolver` honours. A host (or CIDR) explicitly on the allowlist
  passes create-time validation **by name, without a direct DNS resolve** —
  so a legitimate internal/proxy-reached receiver registers successfully on
  a proxy-only pod (one with no direct outbound DNS/egress), where a direct
  resolve would otherwise fail or bypass the proxy. **List your legitimate
  receiver hosts/CIDRs here** — e.g.
  `HORT_WEBHOOK_ALLOWLIST_HOSTS=internal-receiver.svc,10.0.0.0/8`. Do **not**
  reach for the blanket `HORT_WEBHOOK_ALLOW_NONROUTABLE_TARGETS` to make one
  allowlisted receiver register: that knob disables the SSRF host check for
  **all** subscriptions and re-opens the IMDS/RFC1918 SSRF surface (its blast
  radius is stated below). The allowlist is the targeted, control-preserving
  alternative; a literal IMDS/RFC1918 IP *not* on the allowlist is still
  rejected at create time, and a non-allowlisted hostname still goes through
  the routability resolve. **Hort does NOT auto-skip this guard when a proxy
  env var is present** — proxy *presence* does not imply the proxy *filters*,
  and `NO_PROXY` hosts still egress directly, so an auto-skip would re-create
  the silent SSRF bypass the egress proxy fix removed.
- **Exclude in-cluster service traffic via `NO_PROXY`.** Postgres, Redis,
  an in-cluster Keycloak/OIDC issuer, and internal S3/MinIO are reached
  directly, not through an internet egress proxy. Put their hosts/CIDRs in
  `NO_PROXY` (e.g. `.svc`, `.svc.cluster.local`, the cluster pod/service
  CIDRs) so they are not misrouted — otherwise OIDC/JWKS or storage calls
  to internal endpoints will fail or be sent to the proxy.
- **TLS-intercepting proxies + `HORT_EXTRA_CA_BUNDLE`.** If the
  proxy terminates and re-issues TLS (inspection), its signing CA must be
  added to `HORT_EXTRA_CA_BUNDLE` or every outbound TLS handshake fails
  (the system trust store will not contain it). **Be aware** that
  `HORT_EXTRA_CA_BUNDLE` is process-wide *additive* trust applied to **all**
  outbound TLS surfaces at once (upstream, OIDC/JWKS, storage, NATS, webhook),
  so adding the proxy's CA widens trust on every surface,
  not just the proxied path. Prefer a proxy that does **not** intercept TLS
  for the registry's egress where possible; if interception is mandatory,
  scope the proxy CA tightly and treat it as a high-value trust anchor.
- **Relaxation / opt-out:** none shipped. There is intentionally no
  `HORT_WEBHOOK_NO_PROXY` knob — with no proxy configured the in-process
  guard already applies; with a proxy configured the proxy is the control.

### Two-role Postgres model

- **Control:** `hort-server` runs migrations as `hort_admin` (DDL allowed)
  and runtime as `hort_app_role` (`INSERT, SELECT` only on `events`).
  `PgEventStore::new` probes `has_table_privilege` at startup and
  refuses to start if the runtime role can `UPDATE`/`DELETE`/`TRUNCATE`
  on `events`.
- **Chart default:** `values.schema.json` requires both
  `postgres.app.existingSecret` and `postgres.admin.existingSecret`
  to be non-empty. The migrations Job uses the admin DSN; the
  Deployment uses the app DSN.
- **Operator action required:** yes — provision both roles + grants
  out-of-band per `install.md` § 2 SQL runbook.
- **Verify post-install:**
  ```bash
  # Confirm the Deployment uses the app role, not admin.
  # The chart injects the DSN as HORT_DATABASE_URL.
  kubectl exec -n <ns> deploy/<release>-hort-server -- \
    sh -c 'echo $HORT_DATABASE_URL' | grep -E '^postgres://hort_app_role@'
  # And confirm the runtime privilege probe accepted startup:
  kubectl logs -n <ns> deploy/<release>-hort-server | grep -i 'event_store.*ready'
  ```
- **Relaxation:** none. If both secrets resolve to the same admin DSN
  the control is defeated silently — the runtime role check is
  satisfied by the wrong role. The chart does not currently warn on
  this; that's a known, recorded limitation.

### Per-username brute-force lockout — **REMOVED**

The `authenticate_local` per-username + per-IP lockout was removed
along with the HTTP-Basic-against-local-admin-row
identity path it protected (see `docs/auth-catalog.md` Entry 8).
The PAT-side bearer-path brute-force
protection (`PatValidationUseCase::pat_lockout` via `HORT_PAT_LOCKOUT_*`,
distinct mechanism) is unchanged.

### Concurrency limit + load-shed

- **Control:** Tower `ConcurrencyLimitLayer` + `LoadShedLayer` cap
  total in-flight requests; per-IP cap prevents single-source
  saturation. Shed responses are 503 with no body.
- **Chart default:** `http.maxInflight: 0` (binary default 512),
  `http.maxInflightPerIp: 0` (binary default 32). The chart leaves the
  values at binary defaults so operators raising them know the trade-off.
- **Operator action required:** no.
- **Verify post-install:**
  ```bash
  kubectl exec -n <ns> deploy/<release>-hort-server -- \
    sh -c 'echo "${HORT_MAX_INFLIGHT:-default}"'
  # Load-test: 600 concurrent connections; observe
  # hort_http_responses_total{result="shed"} ticking on the metrics surface.
  ```
- **Relaxation:** raise via `http.maxInflight` / `http.maxInflightPerIp`
  for high-throughput deployments. Lowering below ~64 will cause
  legitimate-looking CI workloads to shed.

### HSTS + bind-default + `HORT_REQUIRE_HTTPS`

- **Control:** `Strict-Transport-Security: max-age=15552000; includeSubDomains`
  emitted only when `RequestTrust::public_url.scheme() == "https"`.
  Binary refuses to start if `HORT_REQUIRE_HTTPS=true` AND
  `HORT_PUBLIC_BASE_URL` is `http://` AND `HORT_TRUSTED_PROXY_CIDRS` is empty.
  Default API bind is `127.0.0.1:8080` in the binary; the chart flips
  to `0.0.0.0:8080` because kubelet probes need non-loopback.
- **Chart default:** `api.bindAddr: "0.0.0.0:8080"`, `requireHttps: true`,
  `trustedProxyCidrs: []`, `publicBaseUrl: ""` (required).
- **Operator action required:** yes — set `publicBaseUrl` to the
  edge's https URL OR populate `trustedProxyCidrs` for an
  in-cluster TLS-terminating proxy.
- **Verify post-install:**
  ```bash
  curl -sI -H 'X-Forwarded-Proto: https' http://<svc-or-ingress>/healthz \
    | grep -i strict-transport-security
  # Expect: Strict-Transport-Security: max-age=15552000; includeSubDomains
  # If absent: the trust middleware does NOT see the request as https
  # — re-check trustedProxyCidrs covers the edge's pod IP range.
  ```
- **Relaxation:** `requireHttps: false` re-permits plaintext startup;
  this is intended only for in-cluster eval where the operator owns
  the entire path between client and Service.

### Mounted-file secret containment + mode

- **Control:** `MountedFileSecretAdapter` rejects any resolved secret
  path outside `HORT_SECRETS_FILE_ROOT`; refuses files with overly
  permissive mode bits (`mode & 0o077 != 0` triggers a `WARN`).
- **Chart default:** `secrets.fileRoot: /etc/hort-server/secrets`. All
  entries in `secrets.mounts` mount under this root.
- **Operator action required:** yes — wire each upstream credential
  through `secrets.mounts` rather than `extraVolumeMounts` so the
  containment root applies.
- **Verify post-install:**
  ```bash
  kubectl exec -n <ns> deploy/<release>-hort-server -- \
    ls -la /etc/hort-server/secrets/
  # Expect: each file owned by uid 65532, mode 0400/0440. Kubernetes'
  # default 0644 triggers WARN; set defaultMode: 0400 to silence.
  ```
- **Relaxation:** override `secrets.fileRoot` only if the cluster has
  pre-existing volume conventions. The containment check itself is
  unconditional.

### Graceful shutdown deadline

- **Control:** `with_graceful_shutdown` wrapped in
  `tokio::time::timeout(HORT_SHUTDOWN_GRACE_SECS)`. On timeout, in-flight
  handlers are aborted and a `WARN` records the count. Predictable
  shutdown for orchestrators.
- **Chart default:** `shutdown.gracefulSeconds: 60`.
- **Operator action required:** no, unless OCI upload timeout has been
  raised — the shutdown grace must allow the longest legitimate
  in-flight request to complete.
- **Verify post-install:**
  ```bash
  kubectl exec -n <ns> deploy/<release>-hort-server -- env \
    | grep HORT_SHUTDOWN_GRACE_SECS
  # Expect: HORT_SHUTDOWN_GRACE_SECS=60 (or your override).
  ```
- **Relaxation:** raise to ≥ `oci.uploadTimeoutSeconds` for
  deployments that legitimately push multi-GB image layers; otherwise
  rolling restarts will abort uploads in flight.

### Per-principal OCI upload-session cap

- **Control:** Per-`(repo_id, principal)` outstanding-session counter
  in the ephemeral store; new sessions beyond the cap return 429.
- **Chart default:** `oci.maxSessionsPerPrincipal: 0` (binary default
  32).
- **Operator action required:** no.
- **Verify post-install:** drive 33 concurrent
  `/v2/<repo>/blobs/uploads/` POSTs from one user; the 33rd returns 429.
  `hort_oci_session_cap_rejections_total` ticks on the admin listener.
- **Relaxation:** raise via `oci.maxSessionsPerPrincipal` for CI
  populations that legitimately parallelise pushes from one service
  account.

### Pod-level securityContext (CIS K8s alignment)

- **Control:** Pod runs as non-root UID 65532 (distroless `nonroot`);
  read-only root filesystem; capabilities `drop: [ALL]`;
  `seccompProfile: RuntimeDefault`; `allowPrivilegeEscalation: false`.
  Aligns the chart with PSS-restricted v1.30 and CIS K8s v1.10.
- **Chart default:** `podSecurityContext` and
  `containerSecurityContext` populate the above values directly.
- **Operator action required:** no.
- **Verify post-install:**
  ```bash
  kubectl get pod -n <ns> -l app.kubernetes.io/name=hort-server \
    -o jsonpath='{.items[0].spec.containers[0].securityContext}{"\n"}'
  # Expect a JSON object with allowPrivilegeEscalation:false,
  # readOnlyRootFilesystem:true, capabilities.drop:["ALL"],
  # runAsNonRoot:true (inherited from podSecurityContext).
  ```
- **Relaxation:** none recommended. Operators MUST NOT loosen
  `runAsNonRoot` or `readOnlyRootFilesystem`. If a sidecar genuinely
  needs writeable scratch, use `extraVolumes` with an `emptyDir`
  rather than disabling the chart-level lock.

---

## Second-audit controls (2026-04-30) — deployment-side surface

### IPv4-mapped IPv6 in SSRF predicate

- **Control:** `is_routable()` recurses into the v4 routability filter
  for `::ffff:a.b.c.d` and `::a.b.c.d` forms. Closes a redirect-policy
  bypass that allowed `http://[::ffff:169.254.169.254]/...` to reach
  the IMDS endpoint despite the connect-time DNS guard.
- **Chart default:** unconditional in the binary; no values key.
- **Operator action required:** no.
- **Verify post-install:** no observable signal — predicate is internal.
  Operator confidence comes from the image tag corresponding to a
  release that includes the fix.
- **Relaxation:** none.

### Authz audit events on gitops apply

- **Control:** Every `apply_*` use case (Role, GroupMapping,
  PermissionGrant, RepositoryUpstreamMapping) appends a domain event
  to the audit stream alongside the CRUD save. NIS2 Art. 21(2)(h)
  tamper-resistant trail for authz mutations.
- **Chart default:** unconditional in the binary; the chart's
  `gitopsConfig` ConfigMap is the input that triggers these events.
- **Operator action required:** no.
- **Verify post-install:** drive a known authz mutation via
  `gitopsConfig` (e.g. update a Role); then read the authz stream:
  ```bash
  curl -fsS -H "Authorization: Bearer $TOKEN" \
    'http://<svc-or-ingress>/admin/events?stream=authz:gitops&limit=10'
  # Expect at least one RoleDefined / RoleUpdated / RoleArchived row.
  ```
- **Relaxation:** none. Direct admin endpoints that mutate any authz
  kind without emitting these events are explicitly out of scope for
  this release; if/when added they MUST emit the matching event.

### `ArtifactReleased` carries `admin_id` + justification

- **Control:** Manual quarantine release requires a `justification`
  body field (≤ 512 bytes) and stamps the `admin_id` of the releasing
  caller into the `ArtifactReleased` event. Auditors can reconstruct
  who released what and why.
- **Chart default:** unconditional in the binary.
- **Operator action required:** no — the HTTP DTO change is
  client-side; the chart only needs the binary version.
- **Verify post-install:**
  ```bash
  # Empty body -> 400; with justification -> 200, event carries admin_id.
  curl -i -X POST -H "Authorization: Bearer $TOKEN" \
    -d '{"justification":"SOC ticket #123"}' \
    http://<svc-or-ingress>/quarantine/<id>/release
  ```
- **Relaxation:** none. The validator rejects empty / oversize
  justifications at the use-case boundary.

### Streaming metadata fetch + parse-bomb cap

- **Control:** `do_fetch_metadata` streams the upstream body and bails
  mid-stream when over `METADATA_BODY_CAP_BYTES`. Pre-parse size
  assertion in npm/PyPI parsers caps the JSON the deserialiser sees;
  serde's recursion limit (default 128) bounds parse-tree depth.
- **Chart default:** unconditional in the binary; no values key.
- **Operator action required:** no.
- **Verify post-install:** the `hort_upstream_metadata_*` family carries
  a `BodyTooLarge` result label when triggered (visible on the metrics
  surface).
- **Relaxation:** none.

### OCI manifest blob-reference cap

- **Control:** `parse_manifest_blobs` rejects manifests referencing
  more than 1024 distinct blob digests. The 1 MiB body cap admits
  ~10k pathologically dense entries; this stops the lookup-loop
  amplification.
- **Chart default:** unconditional (constant `MAX_BLOB_REFERENCES`).
- **Operator action required:** no.
- **Verify post-install:** pushing a synthetic 1025-blob manifest via
  `PUT /v2/<repo>/manifests/v1` returns 400 with error code
  `MANIFEST_INVALID`.
- **Relaxation:** none.

### mTLS / custom CA / cert pinning per upstream

- **Control:** `RepositoryUpstreamMapping` carries optional fields for
  client cert + key (`mtls_cert_ref`, `mtls_key_ref`), custom CA bundle
  (`ca_bundle_ref`), and pinned cert thumbprint (`pinned_cert_sha256`).
  Each is a `SecretPort` ID resolved via the mounted-file adapter at
  fetch time.
- **Chart default:** zero-trust knobs are off by default — system CA,
  no client cert, no pinning. Operator opts in per-mapping via gitops.
- **Operator action required:** conditional — yes for zero-trust
  internal mirrors, no for public upstreams.
- **Verify post-install:**
  ```bash
  # mTLS secret files mounted under fileRoot, mode 0400:
  kubectl exec -n <ns> deploy/<release>-hort-server -- \
    ls -la /etc/hort-server/secrets/upstream/<name>/
  # Per-mapping handshake outcomes on the metrics surface:
  # hort_upstream_tls_handshake_total{result=success|pin_mismatch|ca_unknown|...}
  ```
- **Relaxation:** the four fields are independently optional. Set
  `pinned_cert_sha256` only after the handshake succeeds against the
  intended cert; auto-rotation is not wired — operator updates the
  pin via gitops apply on cert rollover.

### Upstream allowlist policy

- **Control:** `HORT_UPSTREAM_ALLOWLIST_HOSTS` env var is parsed at gitops
  apply time. Three modes: unset (no enforcement, default), literal
  sentinel `__deny_all__` (strict — bootstrap-only), comma-list (only
  matching hosts accepted at apply). Empty-string is treated as unset
  to guard against ConfigMap default footgun.
- **Chart default:** unset — no allowlist, existing posture preserved.
  Surface via `extraEnv: [{name: HORT_UPSTREAM_ALLOWLIST_HOSTS, value: ...}]`.
- **Operator action required:** conditional — yes for production
  deployments that should restrict upstream pulls to an enumerated
  registry set.
- **Verify post-install:**
  ```bash
  kubectl exec -n <ns> deploy/<release>-hort-server -- env \
    | grep HORT_UPSTREAM_ALLOWLIST_HOSTS
  # An out-of-list host at apply: AppError::Domain(Validation(...))
  # plus hort_gitops_object_total{result="rejected_not_in_allowlist"}.
  ```
- **Relaxation:** unsetting the env var is the documented default.
  Tightening (removing a host then re-applying) does NOT re-validate
  existing mappings — only diff entries are rechecked. Operators
  wanting a strict refresh must touch every mapping.

### OIDC algorithm gate

- **Control:** OIDC adapter constructor refuses HMAC-family (`HS*`)
  and `none` algorithms. Adapter-level test pins this in CI; port
  doc-comment declares the contract for any future second adapter.
- **Chart default:** unconditional in the binary; the chart's
  `auth.oidc.issuerUrl` / `auth.oidc.audience` go through the gated
  constructor.
- **Operator action required:** no — IdP must publish RS256 / ES256 /
  EdDSA JWKS; HS-family IdPs are refused at startup.
- **Verify post-install:** successful pod startup = the gate accepted
  the JWKS algorithms. An IdP with HS256 fails startup with a clear
  `OidcConfigError`; the pod will `CrashLoopBackOff`.
- **Relaxation:** none — switch the IdP, do not loosen the gate.

### CI advisory gating + workspace MSRV

- **Control:** `cargo audit` is a blocking CI check; advisory ignore
  list is single-source-of-truth in `.cargo/audit.toml`; workspace
  `rust-version = "1.94"` pins MSRV. The chart inherits this through
  the `rust:${RUST_VERSION}-bookworm` builder.
- **Chart default:** N/A — this is a build-pipeline control, not a
  runtime knob. The chart benefits because the image was built with a
  hardened pipeline.
- **Operator action required:** no.
- **Verify post-install:** image labels record the build pipeline:
  `skopeo inspect docker://<image> | jq '.Labels["org.opencontainers.image.source"]'`.
- **Relaxation:** none — this control lives in CI, not in the cluster.

---

## 2026-05-03 audit controls — deployment-side surface

This round closed nine Medium-severity findings from the 2026-05-03 audit.
The connect-time DNS pinning disposition flip is documented above under
"Connect-time DNS pinning (removed)"; the remaining items appear below.
Several are in-binary correctness gates with no operator-tunable surface.

### `is_routable` range extension

- **Control:** `is_routable()` (`crates/hort-net-egress/src/ssrf.rs`) now
  rejects RFC 6598 CGNAT (`100.64.0.0/10`), RFC 5737 documentation
  ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), the
  full `0.0.0.0/8` "this network" range, and IPv6 documentation
  (`2001:db8::/32`). Closes a class of SSRF bypasses that exploited
  ranges every cloud VPC treats as routable.
- **Chart default:** unconditional in the binary; no values key.
- **Operator action required:** no, **but** internal mirrors whose
  hostnames legitimately resolve into one of these ranges (most
  commonly CGNAT in cloud VPCs) will fail to fetch. Move them onto a
  routable range or front them with a TLS-terminating proxy on a
  non-CGNAT IP.
- **Verify post-install:** no observable signal — predicate is internal.
- **Relaxation:** none.

### Rightmost-untrusted `X-Forwarded-For`

- **Control:** The trust middleware
  (`crates/hort-http-core/src/middleware/trust.rs`) replaces the
  leftmost-XFF reading with `rightmost_untrusted_forwarded_for(headers,
  peer_ip, trusted_cidrs)`. Walks the comma-separated header
  right-to-left and returns the rightmost hop **not** in
  `HORT_TRUSTED_PROXY_CIDRS`. The leftmost reading is forgeable — a
  client can prepend an arbitrary IP — and produced the wrong
  `client_ip` in any chain longer than one trusted proxy. Folded with
  IPv4-mapped IPv6 normalisation: `Ipv6Addr::to_canonical()` runs
  before `IpNet::contains` so `::ffff:10.0.0.5` matches the same
  allowlist entry as `10.0.0.5`.
- **Chart default:** unconditional in the binary. The values key
  `app.trustedProxyCidrs` (existing) is the operator input the new
  parser consumes.
- **Operator action required:** **review your `trustedProxyCidrs`
  value.** The semantic of the setting is unchanged — list the CIDRs
  of every proxy hop you control — but a misconfigured-but-previously-
  benign list (e.g. trusting your CDN's full edge range without
  trusting the in-cluster ingress) may now produce a different
  `client_ip` for the same request. Audit `client_ip` in
  `hort_auth_attempts_total{result=...}` after rollout.
  Two configure-it-right actions, both load-bearing:
  1. **Scope the CIDR to the gateway/ingress pods, never the cluster
     pod network.** `trustedProxyCidrs` authorises a peer to forge
     `client_ip` via `X-Forwarded-For`; a whole-pod-CIDR entry
     (e.g. a `/16`) lets **any pod** — including a hostile tenant
     workload — spoof its source IP past rate-limiting, fail2ban, and
     audit attribution. Trust the narrowest CIDR covering the
     ingress-controller/gateway pods' own addresses (find them with
     `kubectl -n <ingress-ns> get pods -l <ingress-selector> -o wide`),
     or the external proxy's source range for a `LoadBalancer`/off-
     cluster edge. See `app.trustedProxyCidrs` in the
     [values reference](values-reference.md#trustedproxycidrs).
  2. **Ensure the edge proxy actually sets `X-Forwarded-For`.**
     Trusting a peer does not synthesise the header. A trusted peer
     reaching the binary without `X-Forwarded-For` degrades `client_ip`
     to the `0.0.0.0` **sentinel** (`XFF_MISSING_SENTINEL`) with a throttled `WARN` —
     all callers through that proxy then share one attribution bucket.
     Confirm the ingress sets `X-Forwarded-For` (most controllers do
     by default; re-verify after any custom `proxy_set_header` /
     header-rewrite) and alert on the
     `trusted peer with missing X-Forwarded-For` WARN.
- **Verify post-install:** drive a request through your full proxy
  chain with a known external client IP; assert the auth-attempt log
  records the external IP, not a proxy-hop IP.
- **Relaxation:** none.

### `GroupMappingUpdated` audit event

- **Control:** Closes the authz-audit-event framework's gap where
  in-place
  edits to a `GroupMapping` row fired silent UPDATEs without an
  authz-stream event. The `GroupMappingUpdated` event is now emitted
  on every retarget; pre-existing `GroupMappingAdded` /
  `GroupMappingRemoved` ticks are unchanged.
- **Chart default:** unconditional in the binary.
- **Operator action required:** no — the audit trail is now complete
  by default.
- **Verify post-install:** drive a known mapping retarget via gitops
  apply; query the authz stream for `GroupMappingUpdated`:
  ```bash
  curl -fsS -H "Authorization: Bearer $TOKEN" \
    'http://<svc-or-ingress>/admin/events?stream=authz:gitops&limit=10' \
    | jq '[.[] | select(.event_type == "GroupMappingUpdated")] | length'
  ```
- **Relaxation:** none.

### `Permission::Delete` separated from `Write`

- **Control:** New permission variant + new `DeleteRepoAccess`
  inbound extractor. The OCI manifest-delete endpoint (`DELETE
  /v2/<name>/manifests/<reference>`) now requires
  `Permission::Delete`, not `Permission::Write`. A grant that gives
  push-only access (CI service account) no longer implicitly grants
  the ability to wipe artifacts.
- **Chart default:** unconditional in the binary.
- **Operator action required:** **review existing
  `PermissionGrant`s.** Before the split, granting `write` was the
  only way to allow push, and that grant carried delete by accident.
  Service accounts that should retain delete need an explicit
  `Permission::Delete` grant; service accounts that should not need
  no change.
- **Verify post-install:** with a push-only token, `docker push`
  succeeds and `docker manifest delete` returns 403.
- **Relaxation:** none — the granularity is by design.

---

## 2026-05-15 audit controls — deployment-side surface

### Three-tier topology + control-plane listener + default-on NetworkPolicy

- **Control:** the intended three-tier topology (public artifact
  plane / public token-gen plane / internal-only control plane) is now
  a shipped, default, documented control rather than an operator
  assumption. (1) An optional internal-only control-plane listener
  (`HORT_CONTROL_BIND`) carries the `/admin`, `/api/v1/admin/*`, and
  `/api/v1/subscriptions` management routes and removes them from the
  public listener, mirroring the metrics-listener split exactly
  (same middleware stack, same 0.0.0.0-footgun guard via
  `HORT_CONTROL_PUBLIC_BIND`). (2) The Helm `networkPolicy` defaults
  **on** (previously off) with a documented escape hatch. The
  token-generation and artifact-pull planes are **never** moved onto
  the control tier — they are public by requirement and hardened
  at the application layer.
- **Chart default:** `control.bindAddr: ""` (control on the main
  listener — **byte-identical to the no-split behaviour, no migration**),
  `control.allowUnspecifiedBind: false`, `service.controlPort: 9443`,
  **`networkPolicy.enabled: true`** (default on; escape hatch
  `networkPolicy.enabled: false`).
- **Operator action required:** no for default config (zero behaviour
  change when `control.bindAddr` is empty); recommended yes for
  production — set `control.bindAddr` and supply `networkPolicy`
  ingress/egress rules per the worked example in
  [`control-plane-tiers.md`](./control-plane-tiers.md).
- **Verify post-install:**
  ```bash
  # NetworkPolicy renders by default.
  kubectl get networkpolicy -n <ns> -l app.kubernetes.io/name=hort-server
  # With control.bindAddr set: /admin must NOT be reachable on the
  # public 8080 listener (expect connection scoped off / 404 there).
  curl -i http://<svc-or-ingress>:8080/admin/repositories/<key>
  ```
- **Relaxation:** `networkPolicy.enabled: false` (documented escape
  hatch); `control.bindAddr: ""` keeps control on the main listener
  (acceptable for single-tier dev clusters; not recommended for
  multi-tenant / internet-exposed production). This control is
  **defense-in-depth on top of — never instead of** — the
  admin-gate (claim-based RBAC) and the webhook allowlist.
  Network position never substitutes for authz. Full model:
  [`control-plane-tiers.md`](./control-plane-tiers.md).

### `HORT_EXTRA_CA_BUNDLE` is an auth-critical asset

- **Control:** `HORT_EXTRA_CA_BUNDLE` is additive across all four TLS
  surfaces **including OIDC discovery + JWKS**, with no per-surface
  scoping. An unconstrained CA in the bundle can impersonate the IdP
  (auth-bypass-grade blast radius — not merely registry-proxy MITM);
  whoever can write the bundle source can mint IdP trust. The bundle
  is therefore an auth-critical asset. This is a doc/threat-model
  control (no code change — fail-closed boot is already part of the
  extra-CA design, ADR 0010); the operator owns the bundle's RBAC and
  integrity.
- **Operator action required:** yes for production — (1) source the
  bundle from a Kubernetes `ClusterTrustBundle` (or equivalently
  RBAC-restricted source), **not** a namespace `ConfigMap` (a
  namespace ConfigMap is editable by anyone with namespace `edit`);
  (2) RBAC on the bundle source at least as tight as the OIDC
  client-secret Secret; (3) prefer a name-constrained intermediate
  (RFC 5280 `NameConstraints`) over an unconstrained root CA so a
  compromised bundle source still cannot issue for the IdP hostname.
- **Reference:**
  [ADR 0010](../../../adr/0010-tls-builder-no-insecure-knobs.md) and
  [`extra-ca-bundle.md`](./extra-ca-bundle.md); rating
  recorded in `docs/auth-catalog.md` Entry 11.

## 2026-06-02 audit controls — deployment-side surface

### Schedule + observe the event-chain verifier

- **Control:** the event-chain tamper-evidence verifier
  (`hort-server verify-event-chain`) is correct crypto but ships
  CLI-only — without a schedule it never runs, so audit-log tamper
  **detection** never happens by default. The chart closes that with
  (1) a `verify-event-chain` CronJob that runs
  `hort-server verify-event-chain --format json` on a configurable
  cadence (default daily), and (2) a boot-emitted
  `hort_event_chain_verify_overdue` boolean gauge that flips to `1` when
  no verify run has completed within
  `HORT_EVENT_CHAIN_VERIFY_STALENESS_MULTIPLIER ×
  HORT_EVENT_CHAIN_VERIFY_EXPECTED_INTERVAL_SECS` (defaults `3 ×
  86400 s`), so a verifier that was enabled and then stopped is
  alarmable. The verifier runs as an in-process reader (runtime DML DSN
  + the anchor object store) — **not** a worker-dispatched task, so it
  needs no service-account PAT.
- **Chart default:** **`scheduledTasks.verifyEventChain.enabled: false`**
  (default-disabled, like its admin-task CronJob siblings); the master
  toggle `scheduledTasks.adminTasksEnabled` must also be `true`. Default
  schedule `scheduledTasks.verifyEventChain.schedule: "0 2 * * *"` (daily) —
  keep it consistent with `HORT_EVENT_CHAIN_VERIFY_EXPECTED_INTERVAL_SECS`.
- **Operator action required:** recommended yes for production — set
  `scheduledTasks.adminTasksEnabled: true` and
  `scheduledTasks.verifyEventChain.enabled: true`
  (paired with `scheduledTasks.eventstoreCheckpoint` + an S3 Object-Lock anchor
  bucket for full external-anchor attestation; on a filesystem backend
  the anchor cross-check resolves to `missing_checkpoint`, exit 3). Alarm
  on `max_over_time(hort_event_chain_verify_overdue[2d]) > 0`.
- **Verify post-install:**
  ```bash
  # The CronJob renders only when both toggles are true.
  kubectl get cronjob -n <ns> \
    -l hort-server.io/job=verify-event-chain
  # The boot gauge is scraped from /metrics; 0 = a recent verify run, 1
  # = overdue/never-ran.
  curl -fsS -H "Authorization: Bearer $TOKEN" \
    http://<svc-or-ingress>/metrics | grep hort_event_chain_verify_overdue
  ```
- **Relaxation:** disabling the CronJob is the default; doing so means
  tamper detection is not running and the gauge will read `1` after the
  next boot once the staleness window elapses — an accepted posture only
  if an out-of-band verifier covers the same cadence. This control is
  **observability + detection, not a fail-closed gate**: a verify run or
  the liveness recording failing never blocks boot or any request path.

---

## Quick verification command set

Aggregated post-install block. Overlaps with `install.md` § 7 Verify
and adds the security-hardening checks specific to the controls above.
Substitute `<ns>`, `<release>`, and `<svc-or-ingress>` as before.

```bash
# 1. Pods + migrations Job (install baseline).
kubectl get pods -n <ns>
kubectl get job -n <ns> <release>-hort-server-migrate \
  -o jsonpath='{.status.conditions[?(@.type=="Complete")].status}{"\n"}'

# 2. /healthz + /readyz.
curl -fsS http://<svc-or-ingress>/healthz
curl -fsS http://<svc-or-ingress>/readyz

# 3. /metrics requires auth — expect 401.
curl -i http://<svc-or-ingress>/metrics | head -1

# 4. Two-role Postgres — expect hort_app_role.
# The chart injects the DSN as HORT_DATABASE_URL.
kubectl exec -n <ns> deploy/<release>-hort-server -- \
  sh -c 'echo $HORT_DATABASE_URL' | grep -E '^postgres://hort_app_role@'

# 5. Pod securityContext (CIS K8s) — expect non-root, RO root, drop ALL.
kubectl get pod -n <ns> -l app.kubernetes.io/name=hort-server \
  -o jsonpath='{.items[0].spec.containers[0].securityContext}{"\n"}'

# 6. HSTS conditional emission.
curl -sI -H 'X-Forwarded-Proto: https' http://<svc-or-ingress>/healthz \
  | grep -i strict-transport-security

# 7. HTTP timeouts plumbed.
kubectl exec -n <ns> deploy/<release>-hort-server -- env \
  | grep -E '^HORT_HTTP_(HEADER_READ|REQUEST|OCI_UPLOAD)_TIMEOUT'

# 8. Mounted-file secrets.
kubectl exec -n <ns> deploy/<release>-hort-server -- \
  ls -la /etc/hort-server/secrets/ 2>/dev/null || echo "(no secrets mounted)"

# 9. NetworkPolicy presence when enabled.
kubectl get networkpolicy -n <ns> -l app.kubernetes.io/instance=<release>

# 10. OIDC admin request (install baseline) — expect 200.
curl -fsS -H "Authorization: Bearer $TOKEN" \
  http://<svc-or-ingress>/admin/repositories
```

If any check returns the unexpected outcome, consult the matching
entry above for the relaxation story and the `values.yaml` keys
involved.

---

## Cross-links

- [`install.md`](./install.md) — install path; § 7 carries the baseline
  verification commands this checklist extends.
- [`values-reference.md`](./values-reference.md) — per-key reference
  with the audit-code cross-walk table and security defaults
  inline.
- [`examples-overlays.md`](./examples-overlays.md) — edge-shape
  overlays. The chart's edge does **not** terminate TLS;
  operator-edge controls (cert-manager, Gateway API) are documented
  there.
- [`../wire-secrets.md`](../wire-secrets.md) — `SecretPort` + mTLS
  mount surface.
- [`../declare-gitops-config.md`](../declare-gitops-config.md) —
  `gitopsConfig` mount path and apply semantics (incl. the
  authz audit-event coverage).
- [`control-plane-tiers.md`](./control-plane-tiers.md) — the
  three-tier exposure model, the `HORT_CONTROL_BIND` control-plane
  listener, the egress posture, the `HORT_TOKEN_BIND` P1 sketch, and the
  defense-in-depth framing.
- [security.md](../../explanation/security.md) — the system-level
  security model the per-chart controls plug into.
