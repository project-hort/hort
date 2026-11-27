# 483 — the TLS sidecar serves a rotated certificate without a rollout

**Issue:** #462 · **Branch:** `agent/462-sidecar-half-surface`.

## What is wrong

The chart mounts the TLS Secret as a whole directory at `/etc/nginx/tls`
(`deploy/helm/hort-server/templates/deployment.yaml:510-512,525-533`) and the
rendered config names `ssl_certificate` / `ssl_certificate_key` as **literal**
paths (`templates/tls-sidecar-configmap.yaml:20-23`). A single nginx process
runs with no watcher (`deployment.yaml:488-535`), and the deployment's
`checksum` annotation covers the ConfigMap, not a changed Secret
(`deployment.yaml:43-47`).

nginx reads certificates at start and on `SIGHUP`. The kubelet replaces the
projected files without signalling it. So after a rotation the sidecar serves a
certificate that no longer exists in the Secret until someone re-rolls the
Deployment — and the HTTPS readiness request (`deployment.yaml:441-458`) proves
reachability, not that the served leaf matches the Secret. The pod reports
`Ready` while serving a stale certificate.

## What to build

**Variable certificate filenames with a constant `map`.** In `http` context,
map `$ssl_server_name` to a **fixed** path for the certificate and another for
the key, use those variables in `ssl_certificate` / `ssl_certificate_key` on
**every** TLS listener the sidecar has, and set `ssl_certificate_cache off`.
nginx loads a variable filename per new full handshake.

**The map's constancy is the security property, not an implementation detail.**
A map that interpolated SNI into the path would turn a client-controlled
handshake field into a filesystem path. Every arm resolves to the same literal
path; a test pins that.

This needs no root, no added capability and no writable root filesystem — the
constraints at `deployment.yaml:498-502` stay exactly as they are. The price is
loading and parsing the certificate and key on each new full handshake, plus
the kubelet's propagation delay. An invalid new pair produces a handshake
failure and an nginx error line rather than a successful handshake with the old
certificate, which is the correct direction for this failure to fall.

**Rejected: a same-UID `SIGHUP` watcher.** Workable, since `/tmp` is writable,
but it adds process supervision and an ambiguity about whether a signal was
acted on. The variable path has neither.

Also in this unit, because it is the same guidance surface: `values.yaml`
suggests `tlsNotRequiredFrom: 127.0.0.1/32` (`values.yaml:156-158,493-505`),
which **cannot** take effect once the sidecar is enabled — the chart then also
trusts loopback as a proxy (`templates/deployment.yaml:130-135`) and the scoped
waiver only fires for a peer that is *not* trusted
(`crates/hort-http-core/src/middleware/trust.rs:412-414`). Remove the
suggestion; the sidecar is the shape ADR 0068's amendment chose.

## Acceptance

- The Secret is **actually replaced** while the pod keeps the **same UID**;
  after projection, a **new full TLS handshake** on every TLS port serves the
  new leaf, compared by fingerprint or serial against the Secret. A
  config-reading test or one that restarts the pod does not satisfy this.
- The counter-case: an invalid new certificate or key produces a handshake
  failure with a logged nginx error. It must not produce a successful handshake
  with the previous certificate.
- nginx runs under the rendered UID/GID/fsGroup with
  `readOnlyRootFilesystem: true` and `capabilities.drop: [ALL]`, reads the
  `0440` Secret files and starts its listeners — proven by a **run**, with the
  fields additionally asserted on the rendered pod.
- A test pins that every arm of the certificate `map` resolves to the same
  literal path.
- `values.yaml` no longer suggests a waiver that the sidecar makes inert.

**The run belongs in `scripts/k8s-tests/` (kind).** `helm template` cannot
establish either half of this; a rendering test that claims to is worse than no
test.

## Not in scope

In-process TLS termination (ADR 0068, *Future evidence sources*), the hop from
a gateway into the pod, and the metrics listener (unit 484).
