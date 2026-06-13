# Configure OCI pull-through with verified upstream

This guide is for operators who want a Remote OCI repository in
`hort` that proxies Docker Hub, GHCR, Quay, Harbor, or any
upstream OCI Distribution Spec registry, and serves manifests and
blobs to `docker pull` / `skopeo copy` / `podman pull` / `containerd`.
It covers verified pull-through, the `503` quarantine response, and
the digest-pin mitigation for the moved-tag case under
quarantine-by-default.

For the underlying design see
[ADR 0006 — mandatory upstream verification](../../adr/0006-mandatory-upstream-verification.md),
[ADR 0007 — fail-closed quarantine release](../../adr/0007-fail-closed-quarantine-release-predicate.md),
and the [prefetch pipeline](../explanation/prefetch-pipeline.md)
explanation.

---

## 1. What pull-through verification means

Every blob and manifest that an OCI client fetches through a Remote
OCI repository is SHA-256-verified before it is admitted to local
CAS. The verification target is the protocol-native digest each side
of an OCI transaction sends:

- **Blobs:** the digest the request itself carries — `GET
  /v2/<name>/blobs/sha256:<hex>`. The proxy fetches from upstream,
  streams bytes through `Sha256HashingRead`, and rejects the cache
  write if the streamed digest disagrees with the URL digest.
- **Manifests by digest:** same as blobs, against the URL digest.
- **Manifests by tag:** the upstream's `Docker-Content-Digest`
  response header is the verification target. **A tag pull whose
  upstream response omits a parseable `Docker-Content-Digest` is
  refused at the proxy** with `502 Bad Gateway` (a self-hash
  fallback would make `ChecksumVerified` a tautology). The metric
  `hort_upstream_checksum_total{format="oci", result="checksum_missing"}`
  ticks on every refusal.

Verification produces a `ChecksumVerified` event on the artifact
stream, in the same append batch as `ArtifactIngested`, with
`algorithm = HashAlgorithm::Sha256`. A tampered blob (one whose bytes
do not hash to the requested digest) produces a `502 Bad Gateway`, a
`ChecksumMismatch` event on the repository stream, and **never
reaches local CAS**.

---

## 2. Quarantine-by-default + the `503` response

Quarantine is the default for every freshly-ingested
artifact (configurable per repo via `ScanPolicy.quarantineDuration` —
see [ADR 0007](../../adr/0007-fail-closed-quarantine-release-predicate.md)).
The settled OCI read-path response for a quarantined manifest:

> **A pull of a tag whose currently-referenced manifest is in
> quarantine returns `503 Service Unavailable` with a `Retry-After:
> <seconds>` header — NOT a substitute manifest.**

The response body is the canonical OCI error envelope:

```json
{
  "errors": [{
    "code": "UNAVAILABLE",
    "message": "manifest is quarantined; retry after the indicated interval",
    "detail": { "retry_after_seconds": 3540 }
  }]
}
```

The `Retry-After` value is the computed seconds-until-quarantine-
deadline (clamped to ≥ 1; default 1 hour when no deadline is set).

### Why not a silent substitution to the prior tag target?

The design weighed and **explicitly rejected** the "deferred move"
alternative — hold the new manifest as a `pending_target`, serve the
previous target until quarantine clears, swap on
`ArtifactReleased`. The rejection rationale, reinforced under
quarantine-by-default:

- It **hides the quarantine gate from operators.** A CI pipeline that
  pushes to `:prod` and gets an eventual silent rejection (because
  the scanner found a CVE in the push) sees no visible failure —
  `:prod` keeps serving the old image, the push appears "successful",
  and the defence-in-depth layer runs invisibly. Correlating "push
  happened → quarantine ran → it passed/failed" requires that the
  effect of the push is visible on the read path.
- Quarantine-by-default made the quarantined-new-manifest case the
  *common* case rather than the rare one. The "hide the gate" harm is
  strictly larger now than when the alternative was first weighed.

The `503` + `Retry-After` is the right signal: "a new image was
published but hasn't cleared verification yet — wait and retry."

---

## 3. The moved-tag mitigation: pin by digest

A client pulling `:latest` (or any tag) during a genuine new-image
quarantine window sees the `503`. The operationally-correct
mitigation is **digest pinning**:

```bash
# Floating-tag pull — vulnerable to the quarantine window.
docker pull hort.example.com/oci-mirror/library/nginx:latest

# Digest-pinned pull — resolves to a specific manifest forever.
docker pull hort.example.com/oci-mirror/library/nginx@sha256:abc...
```

Once a manifest is ingested AND released (its quarantine window has
elapsed and its scan has cleared), pulls by `@sha256:<digest>` resolve
to those exact bytes for the lifetime of the cache — no subsequent
quarantine flip is possible because the digest IS the content. This
is the standard OCI supply-chain hygiene recommendation
(reproducibility, sigstore signatures, attested SBOMs all rest on
digest pinning); the hort quarantine layer simply makes
the cost of ignoring it immediate and visible rather than latent.

**Where this matters most:**

- CI pipelines that pull base images during build (`FROM nginx:1.27`
  in a Dockerfile) — switch to `FROM nginx@sha256:abc...` and pin
  the digest in your CI script or via Dependabot-managed pins.
- Kubernetes deployment manifests — set `image:
  nginx@sha256:abc...` rather than `image: nginx:latest`.
- `helm install` charts that pull images — most modern charts accept
  an `image.digest` value alongside `image.tag`.

---

## 4. Prefetch shrinks the exposure window

The OCI prefetch wires `OnDistTagMove` into the
manifest-fetch hot path: when a tag pull resolves a new upstream
digest that differs from hort's previously-held digest for that tag,
the proxy spawns background pull-throughs for the new manifest's
referenced blobs (config + every layer). The blobs ingest +
quarantine + scan in parallel with whatever the client is doing, so
by the time anyone *actually* pulls the new image's bytes the
quarantine window has either closed or is very close to closing.

Prefetch never **skips** the window — it only moves it earlier. The
worst-case still requires a window to elapse before the first client
pull succeeds; the typical case shifts that wait off the build's
critical path.

Operator opt-in (per repository, declared via gitops):

```yaml
# repositories/oci-public.yaml
apiVersion: project-hort.de/v1beta1
kind: ArtifactRepository
metadata:
  name: oci-mirror
spec:
  format: oci
  type: proxy
  prefetchPolicy:
    enabled: true
    triggers: [on_dist_tag_move]
    depth: 5
    transitive_depth: 5
    max_age_days: 30
```

The `on_dist_tag_move` trigger fires only on detected tag-target
changes (held digest != upstream digest, or first-time pull of a
tag). It rides `PullDedup` inside the existing blob
pull-through, so a racing client pull for the same blob collapses to
a single upstream fetch.

Observability — the prefetch metrics fire with `format="oci"` /
`trigger="on_dist_tag_move"` labels:

- `hort_prefetch_enqueued_total{trigger,repository}` — bumps once per
  planned prefetch (one tag move = one tick under the single-upstream
  call shape OCI uses).
- `hort_prefetch_skipped_total{reason,repository}` — bumps on each
  early-exit reason (`disabled`, `trigger_not_enabled`).

---

## 5. What does NOT apply to OCI

### `IndexMode::ReleasedOnly` is meaningless for OCI

`Repository.index_mode` has two settings:
`ReleasedOnly` (the default, hides non-released versions from the
served index) and `IncludePending` (advertises upstream's full
catalog minus known-quarantined). These apply to formats whose
clients **resolve a range** to a concrete version — `npm install
foo@^1.2.0`, `pip install foo`, `cargo build`, `mvn install` —
because filtering the catalog rewrites what the resolver picks.

An OCI tag is **not** a range. `docker pull foo:latest` is an exact
pointer; an OCI registry CAN'T answer it with anything other than
the manifest that tag points at (substitution is precisely the
hide-the-gate rejection from §2). So `IndexMode::ReleasedOnly` is
**explicitly excluded** from OCI by design. There is no operator
knob to enable it for OCI — this is settled, and the
[`tests::oci_manifest_serve_path_must_not_consult_index_mode`]
regression guard in `crates/hort-http-oci/src/prefetch.rs` enforces
it at test time. The `index_mode` column on an OCI repository is
present for schema uniformity but inert.

If a future operational need genuinely requires range-style filtering
on OCI (e.g. a curated multi-version mirror), the design document
must be amended FIRST and the guardrail test retired in the same
change. Do not paper over this with a quiet code patch.

### Per-artifact quarantine opt-out → `quarantineDuration: 0s`

Operators who run OCI under quarantine-by-default but cannot tolerate
the `:latest`-pull `503` for a specific upstream can set
`quarantineDuration: 0s` on a `ScanPolicy` scoped to that repository:

```yaml
# policies/oci-trusted-upstream.yaml
apiVersion: project-hort.de/v1beta1
kind: ScanPolicy
metadata:
  name: oci-trusted-upstream
spec:
  appliesTo:
    repositories: ["oci-trusted-mirror"]
  quarantineDuration: 0s          # bypass the observation window
  scanBackends: [trivy, osv]      # scan is NOT bypassed
```

This bypasses the observation **window** (the time-based aging) but
NOT the scan gate — a freshly-published image with a known-CVE layer
is still rejected on import. See
[`declare-gitops-config.md`](declare-gitops-config.md) → *kind:
ScanPolicy* → "Hosted-repo recommendation" (which applies to proxy
too) for the full operator surface.

The `quarantineDuration: 0s` knob is the documented per-repo
operator opt-out from quarantine-window friction. The repo-wide
`Permissive` posture is a more invasive sledgehammer.

---

## 6. Declare a Remote OCI repository

```yaml
# repositories/oci-public.yaml
apiVersion: project-hort.de/v1beta1
kind: ArtifactRepository
metadata:
  name: oci-mirror
spec:
  format: oci
  type: proxy
  isPublic: true
  storageBackend: filesystem
  storagePath: /data/repos/oci-mirror
  # Optional but recommended — see §4.
  prefetchPolicy:
    enabled: true
    triggers: [on_dist_tag_move]
    depth: 5
```

```yaml
# upstreams/oci-public.yaml
apiVersion: project-hort.de/v1beta1
kind: UpstreamMapping
metadata:
  name: oci-public
spec:
  repository: oci-mirror
  pathPrefix: dockerhub/
  upstreamUrl: https://registry-1.docker.io
  upstreamNamePrefix: ""
  auth:
    type: anonymous
  # Opt-in publish-time anchoring. When true, the
  # quarantine window is anchored on the upstream's Last-Modified
  # rather than hort's ingest time. Useful for high-latency mirrors of
  # already-aged images.
  trustUpstreamPublishTime: false
```

Apply via the standard gitops flow —
[`declare-gitops-config.md`](declare-gitops-config.md) §5 covers the
boot sequence.

---

## 7. Point an OCI client at the proxy

### Docker

```bash
docker pull hort.example.com/oci-mirror/dockerhub/library/nginx:1.27
```

The path components after the host map to:
`<oci-repo-key>/<upstream-mapping-prefix>/<upstream-image-name>:<tag>`.

For automated builds, prefer digest pins:

```dockerfile
FROM hort.example.com/oci-mirror/dockerhub/library/nginx@sha256:abc...
```

### skopeo / podman / containerd

All three speak OCI Distribution Spec verbatim. Replace the host
component with `hort.example.com/<oci-repo-key>/...` in
whatever reference your tool accepts.

### Authentication

Anonymous pulls work on public OCI repositories. For private repos:

```bash
docker login hort.example.com
# Username: <your-username>
# Password: <PAT issued via hort-cli>
```

The OCI client's `Authorization: Basic <base64>` is decoded by
hort's `oci_bearer_auth` middleware; the password slot
carries an hort PAT (the same twine-compatible flow the other
formats use).

---

## 8. Diagnose `503` and `502` from the proxy

### `503 Service Unavailable` + `Retry-After`

The manifest is quarantined. Either wait the indicated number of
seconds and retry, OR switch to a digest-pinned pull (§3) for a
previously-released digest, OR adjust the repository's `ScanPolicy`
(§5).

### `502 Bad Gateway`

Two failure modes; check the response body `detail.reason`:

- **`upstream manifest digest did not match request digest`** — a
  digest-pinned pull where the upstream served bytes that did not
  hash to the requested digest. The proxy refuses to cache mismatched
  bytes by design. Cause: upstream mirror compromised, transparent
  proxy on the path, withdraw-republish race. Validate the upstream
  URL; the fix is upstream.
- **`upstream did not supply Docker-Content-Digest for tag pull`** —
  the upstream returned a tag manifest with no parseable
  `Docker-Content-Digest` header. The proxy refuses
  rather than self-hash (which would produce a tautological
  `ChecksumVerified` event). Cause: a non-compliant upstream
  registry. Switch to a compliant upstream.
- **`upstream manifest fetch failed`** — generic upstream
  unavailability (5xx, timeout, network error). Retry; check upstream
  health.

The metric `hort_upstream_checksum_total{format="oci",
result=<reason>}` ticks on every verification failure; alerting on a
non-zero rate is recommended.

---

## 9. See also

- [Prefetch pipeline](../explanation/prefetch-pipeline.md) — quarantine-aware index + prefetch
- [ADR 0006](../../adr/0006-mandatory-upstream-verification.md) — upstream verification framework
- [ADR 0007](../../adr/0007-fail-closed-quarantine-release-predicate.md) — quarantine release predicate
- [`declare-gitops-config.md`](declare-gitops-config.md) — full operator surface for `Repository`, `UpstreamMapping`, and `ScanPolicy`
- [`quarantine-patch-release.md`](quarantine-patch-release.md) — emergency `admin_release` flow for an unaged quarantined artifact
