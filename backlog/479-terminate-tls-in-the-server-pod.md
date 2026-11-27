# 479 — terminate TLS inside the server pod

**Issue:** #457 · **Branch:** `agent/457-tls-sidecar` · Unit 1 of 2.
**Decision:** ADR 0068, amendment 2026-11-25 (the Kubernetes shape is a
TLS-terminating proxy in the server's own pod, trusting `127.0.0.1/32`).

## Why this exists

Measured on the first real deployment: the chart's admin-task CronJobs are
refused `426`, and declaring their peer range cannot lift the refusal, because
the installation trusts the pod network as a proxy range and the declared scope
waives only an *untrusted* peer. Where the ingress and those pods draw from one
range — unavoidable on a single-node cluster — no CIDR separates them and no
waiver configuration exists. The amendment's answer is to stop having a
plaintext hop at all, which also makes this chart structurally identical to the
Ansible flavour (nginx on loopback, hort trusting `127.0.0.1/32`).

**Opt-in, `enabled: false` by default.** A chart must not start requiring a
certificate on upgrade. The guidance has to state plainly what an operator who
leaves it off is choosing.

**nginx, not envoy** — it mirrors `deploy/ansible/roles/nginx/templates/
registry.hort.rs.conf.j2`, so one config shape and one mental model cover both
flavours, and that file is the reference for the directives below. Pin the image
by tag the way `values.yaml` already pins `ghcr.io/dexidp/dex:v2.46.1`.

## Three requirements that are not obvious, and each is load-bearing

**1. hort must bind loopback inside the pod.** `HORT_API_BIND=127.0.0.1:<port>`
when the sidecar is enabled, and the Service must target only the sidecar's TLS
port. Otherwise a pod in the cluster reaches hort's plaintext port *around* the
sidecar, and because that pod's address is inside the operator's trusted-proxy
range it can assert `X-Forwarded-Proto: https` and manufacture `Tls` evidence.
This is ADR 0068's second precondition — "prevent callers from reaching the
listener around it" — and without it the sidecar is decoration.

**2. The sidecar overwrites the scheme header; the edge must not forward a
plaintext client request.** `proxy_set_header X-Forwarded-Proto https`
overwrites, so no caller can assert its own scheme. But the sidecar can only
attest *its own* hop: a client that reached the ingress over plaintext, which
then forwarded over TLS, would be reported as `https`. The chart guidance must
therefore state that the edge has to redirect or refuse plaintext client
requests — prod satisfies this with its `80 → 443` redirect. Record it as a
precondition, not as something the chart can enforce.

**3. The sidecar must NOT overwrite `X-Forwarded-For`.** It appends or
preserves. Prod's nginx sets `X-Forwarded-For $remote_addr` because it *is* the
edge; a sidecar behind an ingress is not, and overwriting there replaces the
real client with the ingress's address. hort resolves the client as the
**rightmost-untrusted** entry (`rightmost_untrusted_forwarded_for`,
`crates/hort-http-core/src/middleware/trust.rs:670`), so for attribution to
land on the client, `HORT_TRUSTED_PROXY_CIDRS` must contain loopback **and**
the edge's range. Say that in the guidance.

That last point is the one worth understanding before writing a line: trusting
the edge's range is still needed for *attribution*, but it no longer decides
whether a credential is accepted — the scheme now comes from loopback. Getting
the range too wide degrades attribution instead of admitting plaintext
credentials, which is the whole point of the amendment.

## Scope

- A `tlsSidecar` block in `values.yaml` (enabled, image, ports, the Secret name
  holding `tls.crt`/`tls.key`, resources). Every **top-level** key needs a
  `#` comment above it or `scripts/check-values-comments.sh` fails.
- The container, its config as a ConfigMap, and the cert mounted from the
  Secret, in `templates/deployment.yaml`.
- `templates/service.yaml` targeting the sidecar port when enabled.
- `HORT_API_BIND` set to loopback when enabled.
- `values.schema.json` entries.
- Guidance in `values.yaml` and the deploy how-to covering: the cert is the
  operator's to provide, the two preconditions above, and what trusting
  `127.0.0.1/32` plus the edge range means.
- Assertions in `scripts/test-helm-templates.sh` **in both directions**, as
  unit 478 did: enabled renders the container, the loopback bind and the
  sidecar-targeted Service; disabled renders none of them and leaves today's
  plaintext Service intact.

## Not in scope

The admin-task CronJobs — unit 480, which depends on this. Do not touch their
`HORT_SERVER`.

## Acceptance

- With the sidecar disabled, the rendered manifests are byte-identical to today.
- With it enabled: the container is present, hort binds loopback, the Service
  targets the sidecar, and the nginx config overwrites `X-Forwarded-Proto`
  while leaving `X-Forwarded-For` to append.
- `scripts/test-helm-templates.sh` covers both directions and fails if either
  is broken. Verify by breaking each assertion once and watching it go red.
- `bash scripts/run-shell-guards.sh` passes, including the values-comments gate.
- One `CHANGELOG.md` entry under the #457 entry, naming what an operator must
  do — not the mechanism.
