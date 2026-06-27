# Enable Sigstore/cosign provenance verification

This guide is for operators who want hort to **verify supply-chain
provenance** (Sigstore/cosign signatures and attestations) for OCI
artifacts and, optionally, **gate release** on a verified attestation.

Provenance verification extends hort's "Origin" pillar from checksum to
signature: at ingest, hort verifies a cryptographic claim about *where an
artifact came from* against a set of allowed signer identities. In Tier 1
the verifiers are **cosign → OCI** (keyless Sigstore bundle) and **cosign-key →
OCI** (keyed pinned-public-key, ADR 0039 — see the keyed section in §1); other
formats (npm/PyPI/cargo Sigstore, Maven PGP) are Tier 2.

Verification works on **both hosted and proxy/pull-through OCI repos**.
For a proxy repo, the worker fetches the image's Sigstore signature from
upstream (the OCI v1.1 Referrers API, with a cosign `.sig` tag-scheme
fallback), ingests it into local CAS, and verifies it offline against the
pinned trust root — so `verify_if_present` and `required` are both
meaningful on a proxy, not just on hosted content. See §2's mode
descriptions for the per-mode behavior. The keyless verifier's one named
limitation — legacy `simplesigning` signatures — is now covered, **only for
scopes that select the keyed `cosign-key` backend** (ADR 0039).

For the design rationale see
[ADR 0027 — artifact provenance verification](../../adr/0027-artifact-provenance-verification.md)
(the verifier + policy, the proxy referrer fetch, and the bundle
plumbing).

---

## The two halves you must configure

Provenance verification has a **worker half** (the verifier) and a
**policy half** (when to verify, and whose signatures to trust). Both are
required to enforce anything:

1. **Worker:** enable the cosign verifier and mount a pinned Sigstore
   trust root (`worker.provenance.cosign.enabled` + `trustedRootFile`).
2. **Policy:** set `provenanceMode` (and, for enforcement,
   `provenanceIdentities`) on a `ScanPolicy` in your gitops config.

> **Read this before setting `provenanceMode: required`.** Apply-time
> validation accepts `required` on a statically-verifiable format (cosign
> → OCI) **regardless of whether the verifier is enabled on the worker** —
> the server cannot see the worker's deploy config. If you declare
> `required` but leave `worker.provenance.cosign.enabled: false`, ingested
> OCI artifacts will never get a `ProvenanceVerified` event and will stay
> **`Pending` forever — they never timer-release**. This is fail-closed
> (safe) but operationally surprising. **`required` needs the matching
> verifier enabled on the worker.**

---

## 1. Enable the verifier on the worker (Helm)

The cosign verifier is **off by default** and is **load-bearing**: when
disabled, the worker registers no verifier and the `provenance-verify`
job dispatches to nothing.

```yaml
# values.yaml
worker:
  enabled: true
  provenance:
    cosign:
      enabled: true
      # A PINNED Sigstore trusted_root.json, mounted into the worker
      # container. The verify path is OFFLINE — there is no live
      # TUF/Rekor/Fulcio fetch. Rotate this file through your Hort
      # image/release pipeline.
      trustedRootFile: /etc/hort/provenance/trusted_root.json
```

When `enabled: true`, `trustedRootFile` is **required** — `helm install`
fails if it is unset, and the worker **refuses to boot** if the file is
missing, unreadable, or stale (outside its refresh window). A boot-time
`health_check` verifies the trust root is loaded and fresh; it does
**not** probe live Rekor/Fulcio (verification is offline).

### Keyed cosign (`cosign-key`) — a pinned public key, for sovereign first-party signing (ADR 0039)

A second, **independent** verifier backend (`cosign-key`) verifies a keyed cosign
signature (`cosign sign --key`, the legacy `simplesigning` shape) against an
**operator-pinned public key** — no Fulcio, no Rekor, no trust root, fully
offline. It is for the sovereign operator who signs **first-party OCI images**
with a long-lived key (e.g. a self-hosted CI that no public Fulcio will issue
for), where Hort is the verifier. See
[ADR 0039](../../adr/0039-keyed-provenance-verification.md).

Its enabling gate is the **presence of a pinned-key file** (independent of
`cosign.enabled`, which gates the keyless backend) — mount a file of one or more
PEM public keys and point the worker at it:

```yaml
worker:
  provenance:
    cosign:
      # Keyed backend (ADR 0039): a mounted file of one or more
      # `-----BEGIN PUBLIC KEY-----` ECDSA P-256 blocks (cosign `cosign.pub`).
      # Multiple keys = a rotation-overlap window.
      publicKeysFile: /etc/hort/provenance/cosign-keys.pem
```

> The chart key above lands with the keyed-backend Helm wiring; until then set
> the env var directly on the worker:
> `HORT_PROVENANCE_COSIGN_PUBLIC_KEYS_FILE=/etc/hort/provenance/cosign-keys.pem`.

The worker **refuses to boot** if the file is set but unreadable or contains no
parseable P-256 public key. A `ScanPolicy` then selects the backend with
`provenanceBackends: [cosign-key]` (no `provenanceIdentities` — they are **inert**
for the keyed backend, and a `cosign-key`-only scope that sets them is rejected
at apply).

> **A keyed signature is a WEAKER assertion than a keyless bundle — never
> public-grade provenance.** It carries **no transparency-log inclusion, no
> OIDC-identity binding, no public verifiability, and no trusted timestamp**. It
> attests only "signed by the holder of key K", trusted solely because *you*
> pinned K. It is the correct control for an **internal-audience** deployment
> where Hort is the verifier — never present it as equivalent to a Sigstore
> bundle.
>
> **Key compromise = re-sign everything.** With no trusted timestamp there is no
> way to distinguish pre- from post-compromise signatures, so revoking a
> compromised key means removing it from the pinned set **and re-signing every
> legitimate artifact** — not a rotation overlap.

> **A worker runs every verifier it has configured.** Dispatch is worker-level,
> not per-scope: a `ScanPolicy`'s `provenanceBackends` is validated at apply but
> does **not** select which verifier runs at ingest. So if a worker has BOTH the
> keyless trust root and the keyed key file, every OCI artifact is checked by
> both — the fold is OR (either a valid keyless bundle **or** a valid keyed
> signature clears the gate). This is safe: the two verifiers partition by
> signature shape (each ignores the other's), and a keyed signature **requires
> your pinned key** — an attacker cannot forge one to bypass keyless checks. **To
> enforce a single backend** (e.g. keyless-only on a public proxy), configure only
> that verifier on the worker — set the trust root XOR the keyed `publicKeysFile`,
> not both. Mixing both on one worker is fine for first-party-keyed +
> third-party-keyless content (each image carries one shape).

### Mounting the pinned trust root

The chart does not bundle a trust root — you provide it. The simplest
path is a ConfigMap (or Secret) projected into the worker pod via the
worker's `extraVolumes` / `extraVolumeMounts`:

```yaml
worker:
  provenance:
    cosign:
      enabled: true
      trustedRootFile: /etc/hort/provenance/trusted_root.json
  extraVolumes:
    - name: provenance-trust-root
      configMap:
        name: hort-sigstore-trusted-root   # contains key: trusted_root.json
  extraVolumeMounts:
    - name: provenance-trust-root
      mountPath: /etc/hort/provenance
      readOnly: true
```

Obtain `trusted_root.json` from the Sigstore TUF repository (the standard
TUF `trusted_root` target — e.g. via `cosign` / `tuf` tooling) and pin it
in your release pipeline. Treat a trust-root update like any other
release artifact: review, pin, roll out. Because the verify path never
fetches it live, a stale or compromised TUF mirror cannot silently swap
your trust root at runtime.

---

## 2. Choose a `provenanceMode` per scope (gitops)

Set `provenanceMode` on a `kind: ScanPolicy` envelope. The mode is
per-scope (global, or per-repository), defaulting to `verify_if_present`.

### `verify_if_present` (the default — proxy-safe, never blocks)

Verify a signature **if one is present**, reject a **forged or untrusted**
signature, but **allow unsigned** artifacts and **never gate release**.
This is the fail-safe default: a free tamper-detection win where signatures
exist, a no-op where they don't.

On a **proxy/pull-through** scope this now does real work: when the local
CAS has no signature for a pulled image, the worker fetches the upstream
Sigstore referrer(s) (Referrers API + `.sig` tag fallback), ingests the
referrer manifest and its bundle blob, and verifies. The `docker-proxy`
example below is therefore truthful — it can return a real `verified` /
`rejected` verdict, not only `no_attestation`. An upstream fetch error
**degrades to `no_attestation`** under `verify_if_present` (never
fail-closed — the proxy stays available on upstream flakiness).

> **Tier-1 verifies the Sigstore *new bundle format* (v0.3) only.** The
> verifier parses
> `application/vnd.dev.sigstore.bundle.v0.3+json` — the bundle cosign
> emits with `--new-bundle-format`. An image signed **only** with **legacy
> cosign `simplesigning`** (the pre-`--new-bundle-format`, annotation-based
> `.sig`) is **not** verified: it yields `no_attestation` (allowed under
> `verify_if_present`; rejected `Unsigned` under `required`). This is a
> real, named limitation — reconstructing a v0.3 bundle from the legacy
> `.sig` annotations is explicitly out of scope. A `verified` verdict
> requires the upstream to publish a
> v0.3 bundle.

```yaml
apiVersion: project-hort.de/v1beta1
kind: ScanPolicy
metadata:
  name: oci-verify-if-present
spec:
  scope:
    repository: docker-proxy
  provenanceMode: verify_if_present
  provenanceBackends: [cosign]
  provenanceIdentities:
    - issuer: https://token.actions.githubusercontent.com
      san: https://github.com/acme/*/.github/workflows/release.yml@refs/heads/main
```

> Under `verify_if_present`, an **empty** `provenanceIdentities` is
> accepted but **apply-time warns**: with no allowed signers, hort can
> only detect tampering (a structurally broken bundle), not an *untrusted*
> signer. Supply at least one identity to get untrusted-signer rejection.

### `required` (block unsigned/unverified — for scopes you control)

Require a verified attestation from an allowed signer. Provenance becomes
an **AND-precondition on the timer release arm**: an OCI artifact only
timer-releases once a `ProvenanceVerified` event exists (the scan/time
gate still applies). Unsigned, untrusted, or unverified artifacts stay
quarantined. `required` never overrides an explicit Admin/Curator release.

```yaml
apiVersion: project-hort.de/v1beta1
kind: ScanPolicy
metadata:
  name: oci-required
spec:
  scope:
    repository: internal-images
  provenanceMode: required
  provenanceBackends: [cosign]
  provenanceIdentities:
    - issuer: https://token.actions.githubusercontent.com
      san: https://github.com/acme/internal-images/.github/workflows/release.yml@refs/heads/main
```

`required` is meaningful **on a proxy too**: the worker verifies the
upstream signature when present and emits `ProvenanceRejected{Unsigned}`
(terminal) when the upstream genuinely ships no Sigstore v0.3 bundle —
which is exactly what `required` asks for. There is **no** apply-time
"reject `required` on a proxy" guard: now that the fetch capability ships,
the mode is correct on a proxy, not a footgun. An
image carrying only a legacy `simplesigning` signature is **not** verified
(see the limitation above) and is therefore rejected `Unsigned` under
`required`.

Apply-time validation **rejects** a policy that would be impossible to
satisfy:

- `provenanceMode: required` on a scope whose format has **no** verifier
  (Tier 1: anything that is not OCI/cosign) — there is nothing to satisfy
  the gate.
- `provenanceMode != off` with an empty `provenanceBackends`.
- `provenanceMode: required` with an empty `provenanceIdentities` (the
  any-signer footgun).

`provenanceIdentities` entries are `{issuer, san}` patterns — an exact
match or a bounded glob (`*`). The `issuer` is the OIDC issuer the Fulcio
certificate was minted against (e.g.
`https://token.actions.githubusercontent.com`); the `san` is the signer's
subject (e.g. the GitHub Actions workflow identity).

### `off`

Disable provenance for the scope (the field is inert — no verification,
no enqueue, no release gate).

---

## Pushing cosign signatures to a hosted repo

When you push a cosign signature to a **hosted** OCI repo (`cosign sign
$HORT/image`), the signature is **not quarantined**. A pushed manifest
that is a *pure* Sigstore-bundle referrer (a `subject` plus layers that are
**all** Sigstore bundle blobs — no runnable filesystem layer) is ingested
with status `None`: immediately servable, never scanned, and with no
self-referential provenance job. So `cosign verify $HORT/image` against a
hosted repo works **on day one** — there is no 24h quarantine wait for the
signature.

This exemption is **narrow and safe**: a *mixed* manifest (a bundle layer
**plus** a runnable `tar+gzip` layer) does **not** match the
all-layers-bundle predicate — it stays on the normal ingest path and **is
scanned/quarantined** as usual. The exemption removes only the needless
quarantine of a signature, which carries no runnable content; it does not
widen any scan-evasion surface.

---

## 3. Verify it is working

- Worker boot log: `cosign provenance verifier health check OK (pinned
  trust root loaded + fresh)` and `ProvenanceVerifyHandler registered`.
  If the flag is off you'll instead see `ProvenanceVerifyHandler not
  registered: HORT_PROVENANCE_COSIGN_ENABLED is false`.
- Metrics (see `docs/metrics-catalog.md`):
  - `hort_provenance_verify_total{backend="cosign", mode, result}` —
    `result ∈ {verified, rejected, no_attestation}`.
  - `hort_provenance_reject_total{backend="cosign", reason}` — the
    per-reason breakdown of rejections.
  These are emitted by the **worker** and are scrapeable from the worker's
  `/metrics` listener — see *Worker metrics* below.
- Per-job verdict: the `provenance-verify` job records a compact
  `result_summary` on its job row, one of
  `{"result": "verified"}`,
  `{"result": "rejected:<reason>"}` (e.g. `rejected:unsigned`,
  `rejected:untrusted_identity`),
  `{"result": "no_attestation"}`, or
  `{"result": "skipped:<why>"}`. This is the per-artifact forensic trail —
  in particular the only durable record of the `no_attestation` case
  (which intentionally emits **no** per-artifact `info!` log, to avoid a
  firehose at proxy scale).
- Audit: each verdict emits an `info!` line (`provenance verified` /
  `provenance rejected` with the `reason`) and a durable
  `ProvenanceVerified` / `ProvenanceRejected` domain event on the
  artifact stream.

### Worker metrics (`worker.metrics`)

The `hort_provenance_*` series — and every other worker metric (scan
metrics, queue depth, …) — are emitted by the **worker**, which now
exposes a `GET /metrics` Prometheus scrape listener. It is
**disabled by default (opt-in)**.

Enabling the listener and its network control is **one structural action**:
the chart's `worker.metrics` knob, when enabled, (a) sets the listener bind,
(b) exposes the container port, **and** (c) co-renders a worker-scoped
NetworkPolicy that admits only your Prometheus scraper to the port. You do
**not** wire the env or author the NetworkPolicy by hand.

```yaml
# values.yaml
worker:
  enabled: true
  metrics:
    enabled: true   # sets HORT_WORKER_METRICS_BIND=0.0.0.0:<port>,
                    # exposes the container port, and co-renders the
                    # worker NetworkPolicy with the scrape allowance.
    port: 9090
    # scrapeFrom: verbatim k8s NetworkPolicyPeer objects (the ingress
    # from[]) — the ONLY sources allowed to scrape the port. REQUIRED when
    # enabled:true: the schema rejects an empty scrapeFrom, because a
    # NetworkPolicy rule with `from: []` means ALL sources (fail-OPEN) per
    # the k8s spec — so you must name your scrapers, never leave it blank.
    scrapeFrom:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: monitoring
        podSelector:
          matchLabels:
            app.kubernetes.io/name: prometheus
```

Why this is structured as one knob, not two:

- **The listener has no per-request auth.** The worker is a background
  processor with no inbound-HTTP auth stack, so the metrics route is
  unauthenticated. The `repository` metric labels carry repo names, so a
  world-reachable worker `/metrics` is a minor info-leak + cardinality
  surface. The **NetworkPolicy is the access control** that replaces
  per-request auth (the standard pod-metrics pattern).
- **The default-on server NetworkPolicy already DENIES this port.** With
  `networkPolicy.enabled: true` (the chart default), the shipped app-pod
  policy selects the worker pods too and renders a deny-all-ingress — so the
  metrics port is default-denied. The `worker.metrics` knob renders an
  **additive** worker NetworkPolicy (`<release>-worker-metrics`) that
  selects only `component: worker` pods and adds the single Ingress scrape
  allowance from `scrapeFrom`. Kubernetes unions ingress across policies, so
  this opens only the metrics port to only your scrapers; nothing else
  changes.
- Disabling is explicit: `worker.metrics.enabled: false` (the default)
  renders no listener, no container port, and no NetworkPolicy. A malformed
  bind is a **loud boot-path config error**, never a silent fallback.

> If you run with `networkPolicy.enabled: false` (the documented escape hatch),
> the worker NetworkPolicy is **not** rendered and the server policy's
> deny-all is also gone — you then own the metrics port's reachability via
> your own L3/L4 or mesh controls.

---

## Common pitfalls

| Symptom | Cause | Fix |
|---|---|---|
| OCI artifacts stuck `Pending`, never release | `provenanceMode: required` but `worker.provenance.cosign.enabled: false` | Enable the verifier on the worker (§1). |
| Worker crashes on boot | `cosign.enabled: true` but `trustedRootFile` missing/unreadable/stale | Mount a current pinned `trusted_root.json` (§1). |
| `helm install` fails with "trustedRootFile is required" | `cosign.enabled: true` with no `trustedRootFile` | Set `worker.provenance.cosign.trustedRootFile`. |
| apply rejects `required` policy | The scope's format has no Tier-1 verifier (non-OCI) | Use `verify_if_present`, or wait for the Tier-2 verifier for that format. |
| Untrusted signatures not rejected under `verify_if_present` | empty `provenanceIdentities` (tampering-only detection) | Add the allowed `{issuer, san}` patterns. |
| Proxy image always `no_attestation` despite an upstream signature | The upstream signed only with **legacy `simplesigning`** (no `--new-bundle-format`) — not verified in Tier 1 | Re-sign upstream with a v0.3 Sigstore bundle (`cosign sign --new-bundle-format`); the legacy `.sig` is not reconstructed. |
| No `hort_provenance_*` series in Prometheus | The worker `/metrics` listener is disabled (default) | Set `worker.metrics.enabled: true` + a `worker.metrics.scrapeFrom` Prometheus selector — the chart sets the bind, exposes the port, and co-renders the scrape NetworkPolicy (*Worker metrics* above). |
| `cosign verify $HORT/image` 503s right after push (older builds) | Signature was quarantined — fixed: pushed Sigstore-bundle signatures land status `None` now | Upgrade to a build with the pure-bundle signature-manifest exemption; no quarantine wait for pure-signature pushes. |
