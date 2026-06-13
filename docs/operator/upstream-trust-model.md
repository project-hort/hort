# Upstream Trust Model — `HORT_UPSTREAM_ALLOWLIST_HOSTS`

**Audience:** operators deploying hort as a pull-through proxy.
**Related:** [per-upstream mTLS / cert-pinning](../architecture/how-to/deploy/security-hardening-checklist.md)
(paired with this gate for zero-trust internal mirrors).

## Why this exists

Without this gate, any operator with `gitops` write permission could declare
an `UpstreamMapping` pointing at any HTTP(S) host on the public internet.
That is an implicit-allowlist posture: nothing
in the apply pipeline asserted the upstream URL belonged to a sanctioned set,
so a compromised gitops branch (or a careless YAML edit) could silently
re-target a proxy at an attacker-controlled mirror.

`HORT_UPSTREAM_ALLOWLIST_HOSTS` is an **opt-in, enumerated, server-side allowlist**
that gates the gitops apply path. It is enforced once at apply time. The default
posture (`HORT_UPSTREAM_ALLOWLIST_HOSTS` unset) preserves historical behaviour so
existing deployments are not broken on upgrade.

## The three modes

| `HORT_UPSTREAM_ALLOWLIST_HOSTS` value | Mode | Behaviour |
|---|---|---|
| **Unset** OR set to **the empty string** | `Disabled` (default) | No enforcement. Every host accepted. Existing deployments stay green. |
| `__deny_all__` (literal sentinel, exact match) | `Strict` | Every upstream mapping rejected at apply. Bootstrap-only. |
| `host1,host2,...` (comma-separated host list) | `Hosts` | Only mapping URLs whose host is **exactly** in the list pass apply-time validation. |

### Why empty string is `Disabled`, not `Strict`

The empty string is too easy to set accidentally:

- Kubernetes `ConfigMap` defaults — `data:` keys with no value land as `""`.
- Docker Compose — `${VAR:-}` substitutes to the empty string when `VAR` is unset.
- Shell — `export HORT_UPSTREAM_ALLOWLIST_HOSTS=` is a one-character typo away from
  the same outcome.

If empty-string meant `Strict`, any of those would silently turn every upstream
pull into a hard reject. We treat empty-string identically to unset to guard
against this footgun. **The literal sentinel `__deny_all__` is the only way
to opt into strict mode** — it is conspicuous, intentional, and grep-friendly
in operator scripts.

The same guard applies to a list that reduces to zero non-empty hosts after
trimming (e.g. `HORT_UPSTREAM_ALLOWLIST_HOSTS=,,,`). That collapses to `Disabled`
rather than `Hosts(vec![])`.

## Examples

### Production deployment (recommended)

Enumerate the public registries you actually use, plus any internal mirrors:

```yaml
# kubernetes ConfigMap snippet
apiVersion: v1
kind: ConfigMap
metadata:
  name: hort-env
data:
  HORT_UPSTREAM_ALLOWLIST_HOSTS: "registry.npmjs.org,pypi.org,crates.io,ghcr.io,registry-1.docker.io,mirror.internal.example.com"
```

```bash
# docker-compose.yml or .env
HORT_UPSTREAM_ALLOWLIST_HOSTS=registry.npmjs.org,pypi.org,crates.io,ghcr.io,registry-1.docker.io,mirror.internal.example.com
```

A subsequent gitops apply that declares an `UpstreamMapping` pointing at any
host outside this list aborts non-zero with:

```
gitops apply failed: upstream host 'evil.attacker.test' not in HORT_UPSTREAM_ALLOWLIST_HOSTS
```

The Prometheus counter `hort_gitops_objects_total{kind="upstream_mapping",result="rejected_not_in_allowlist"}`
increments once per rejected mapping — alert on it.

### Strict (bootstrap-only)

For freshly-staged deployments where no upstream mapping should exist yet:

```bash
HORT_UPSTREAM_ALLOWLIST_HOSTS=__deny_all__
```

Every gitops apply that includes an `UpstreamMapping` envelope fails
loud-and-fast. Useful while you wire up internal-mirror DNS, mTLS material,
or CA bundles before granting any pull-through path.

### Local development

Leave `HORT_UPSTREAM_ALLOWLIST_HOSTS` unset — the default open posture
applies. The allowlist is a production hardening control.

## Match shape

**Exact host match** is the only supported mode. A URL whose host is
`subdomain.registry.npmjs.org` does NOT match `registry.npmjs.org` in the
allowlist; you must list `subdomain.registry.npmjs.org` explicitly.

Suffix wildcards (`*.example.com`) are deliberately NOT implemented in this
release. Wildcards silently widen the trust boundary and are easy to abuse;
if you genuinely need a wildcard the design must be re-opened (file an issue
with the concrete deployment that motivates it).

The match is case-sensitive — `Pypi.org` does not match `pypi.org` in the
allowlist. URL hosts are lowercase by convention; if an operator types the
wrong case they get a loud miss rather than a silent normalisation that
papers over the typo.

## Apply-time-only enforcement (known limitation)

The host check fires **inside `apply_upstream_mappings`**, on the rows that
the apply diff classifies as `create` or `update`. Two implications operators
need to know:

1. **Tightening the allowlist does NOT re-validate existing mappings.** If
   you remove `evil.attacker.test` from `HORT_UPSTREAM_ALLOWLIST_HOSTS` and re-run
   the gitops apply, an existing mapping pointing at that host stays in place
   — its row produces no diff entry because the YAML did not change, so the
   gate never sees it.

   **Workaround:** to force re-validation, touch every mapping (e.g. bump a
   version comment in each YAML file) so the diff classifier sees them as
   updates. The next apply will then run them through the gate.

2. **Delete rows are exempt.** Removing a mapping that was previously
   permitted under a looser allowlist always succeeds, regardless of current
   allowlist state. This is intentional: tightening the allowlist must not
   also block GC of mappings the operator wants gone.

A re-validating gate at fetch time (every artifact pull pays a hot-path
allowlist lookup) was considered and rejected — it would mean a misconfigured
allowlist silently fails every download instead of producing one loud error
at apply, and the cardinality of the hot-path lookup is wrong for the threat
model this gate addresses (gitops branch compromise, not run-time tampering).

## Pairing with mTLS / cert pinning

Per-mapping mTLS client certificates and pinned
upstream cert SHA-256 thumbprints are also available (see the
[security hardening checklist](../architecture/how-to/deploy/security-hardening-checklist.md)).
The two gates compose well for zero-trust internal mirrors:

- `HORT_UPSTREAM_ALLOWLIST_HOSTS` says *which hosts may be configured at all*.
- `pinned_cert_sha256` on the mapping says *the host must present this exact
  cert* — defends against TLS-MitM by a compromised CA.
- `mtls_cert_ref` / `mtls_key_ref` say *the upstream must present a client
  cert chain anchored at our internal CA*.

Production deployments that mirror sensitive internal registries should
enable all three.

## Observability

| Signal | Where |
|---|---|
| Boot exit code | `gitops apply failed: upstream host '<host>' not in HORT_UPSTREAM_ALLOWLIST_HOSTS` on stderr; non-zero exit. Orchestrator (systemd / Kubernetes) escalates. |
| Prometheus counter | `hort_gitops_objects_total{kind="upstream_mapping",result="rejected_not_in_allowlist"}` increments once per rejected mapping. |
| Catalog | [`docs/metrics-catalog.md`](../metrics-catalog.md) lists the new `result` label value. |

## Recommendation

For production: **set `HORT_UPSTREAM_ALLOWLIST_HOSTS` to an explicit comma-separated
host list.** Treat the list as a security boundary; rotate it through the
same review process as RBAC roles.

For staging / pre-production: same as production. The allowlist costs nothing
at run time (it is checked once per apply) and catches misconfiguration
before it lands in prod.

For local dev: leave it unset. The footgun guards mean an accidental
empty-string from a `.env` file does not break your dev loop.
