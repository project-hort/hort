# 481 — the TLS sidecar starts, and the probes resolve their port

**Issue:** #460 · **Branch:** `agent/460-sidecar-starts-and-probes-resolve`.
**Decision:** ADR 0068, amendment 2026-11-25 (the Kubernetes shape).

Two independent defects shipped in `0.18.1-alpha.3` make `tlsSidecar.enabled`
unusable. Both were reported with reproductions and both are verified against
the chart. Neither has an operator workaround that keeps the feature intact.

## 1. nginx cannot start under a read-only root filesystem

`templates/tls-sidecar-configmap.yaml` redirects `client_body_temp_path` and
`proxy_temp_path` to `/tmp` and leaves three alone. The image's compiled
defaults put `fastcgi_temp`, `uwsgi_temp` and `scgi_temp` under
`/var/cache/nginx`, which is empty and root-owned, and the container runs with
`readOnlyRootFilesystem: true` (`templates/deployment.yaml:500`). **nginx
creates every registered temp path at startup, not on first use**, so the
first unredirected one is a fatal `[emerg]`.

**Fix: redirect all five paths into `/tmp`.** This is the reported remedy that
needs no extra volume. The alternative — an `emptyDir` on `/var/cache/nginx` —
additionally requires the directory to be writable by the pod UID (an
`fsGroup`), so a root-owned mount turns `EROFS` into `EACCES` and fails just
the same. Do not take it.

## 2. The probes name a port the probed container does not declare

`templates/deployment.yaml:444`, `:450` and `:456` merge
`(dict "port" "https" "scheme" "HTTPS")` into the three probes. The name
`https` is declared only on the sidecar container (`:495`); the hort container
declares `http`, `metrics` and `control`. The kubelet resolves a **named**
probe port only within the probed container's own ports, so all three probes
fail permanently and the startup probe kills the container after roughly five
minutes.

**Fix: render the integer `.Values.tlsSidecar.httpsPort` instead of the name.**

**Do not instead add a `containerPort` named `https` to the hort container.**
Port names must be unique within a pod and the sidecar already uses that one,
so it would be rejected; under a different name it does not solve anything.

Routing these probes through the sidecar is still correct and must stay: with
the sidecar enabled hort binds loopback, so the sidecar's listener is the only
one the kubelet can reach, and `proxy_pass` answering `502` on a dead backend
is a correct probe failure.

## 3. The guidance must name the bare Service name

`docs/architecture/how-to/deploy/inbound-credential-transport.md` says only
"the Service DNS name used by in-cluster clients". The CronJobs use the
**bare** name (`https://<fullname>:<port>`), so a certificate issued only for
the `.svc` forms repairs none of them. Say that explicitly — it is the single
most consequential detail for the operator, and it was reported as missing.

## Scope

The two fixes, the doc sentence, and assertions for both in
`scripts/test-helm-templates.sh`:

- the rendered `nginx.conf` redirects all five temp paths under `/tmp`;
- the rendered probes carry an integer port, and no probe carries the string
  `https`.

Write the second as a negative assertion as well, since that is the shape that
regressed: a probe whose port is a name is the defect, so assert its absence.

## Acceptance

- With the sidecar disabled, rendered manifests stay byte-identical to today.
- With it enabled, no probe references a port by name, and the nginx config
  redirects all five temp paths.
- `scripts/test-helm-templates.sh` covers both; break each assertion once to
  prove it can fail.
- One `CHANGELOG.md` entry. The `### Added` entry for the sidecar is still
  unreleased, so fold this into it rather than adding a second line — an
  operator never saw the broken shape.

## What this unit cannot prove, and must say so

`helm template` renders; it starts nothing. The render passed on the broken
chart. So state in the report that the start-up behaviour is unproven here and
name what would prove it — a container actually running with the rendered
config under the same security context, which is what the reporter did.
