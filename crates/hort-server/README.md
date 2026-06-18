# hort-server — service binary

Minimal axum-based service that wires the library crates
(`hort-domain`, `hort-app`, `hort-adapters-postgres`, `hort-adapters-storage`,
`hort-http-core`, and the per-format `hort-http-<format>` crates) into a
running process.

Design: [`docs/architecture/explanation/layers.md`](../../docs/architecture/explanation/layers.md).

## What this binary IS

- The composition root — installs the tracing subscriber, the
  Prometheus recorder, opens the Postgres pool, builds storage, applies
  migrations, and binds axum routers.
- The E2E-test target for `twine`, `pip`, `cargo`, `npm`.

## What it is NOT (yet)

The following are **out of scope** and not yet implemented:

- **Format handlers beyond PyPI, cargo, npm, and OCI.** Those four
  formats are wired; every other URL is a 404. Repositories for any
  supported format are declared via gitops YAML (`HORT_CONFIG_DIR`) —
  there is no REST create endpoint.
- **WASM host.** No `$WASM_PLUGIN_DIR`, no dynamic module loading.
- **Hot config reload.** A `SIGHUP` is not handled; restart the process
  to pick up new env vars.
- **Scanner integration, gRPC, CLI surfaces.**
- **Readiness / liveness probe split.** Kubernetes deployments can
  point probes at `/metrics` (when on the main listener in dev mode)
  or the root 404 until a dedicated endpoint lands.

## Required environment variables

| Var | Required | Notes |
|-----|----------|-------|
| `HORT_DATABASE_URL` | yes¹ | Canonical Postgres DSN, tried first. e.g. `postgres://registry:registry@localhost:5432/artifact_registry` |
| `DATABASE_URL` | yes¹ | Fallback DSN (sqlx-cli / Tier-2 tests / 12-factor). Used when `HORT_DATABASE_URL` is unset. |
| `HORT_STORAGE_BACKEND` | no (default `filesystem`) | `filesystem` or `s3` |
| `HORT_STORAGE_FILESYSTEM_PATH` | yes for filesystem | Root directory for CAS, e.g. `/var/lib/hort-server/cas` |
| `HORT_STORAGE_S3_BUCKET` | yes for s3 | |
| `AWS_REGION` | yes for s3 | |
| `AWS_ENDPOINT_URL_S3` | no | Set for MinIO/Garage/non-AWS |
| `HORT_STORAGE_S3_FORCE_PATH_STYLE` | no (default `false`) | Set `true` for MinIO/Garage |
| `AWS_ACCESS_KEY_ID` | yes for s3 | |
| `AWS_SECRET_ACCESS_KEY` | yes for s3 | |
| `HORT_API_BIND` | no (default `127.0.0.1:8080`) | Main API listener. Set to `0.0.0.0:8080` inside a container so kubelet probes reach the pod IP. |
| `HORT_METRICS_BIND` | no | When set, `/metrics` is served **only** on this address; the main router drops the scrape endpoint. Leave unset in dev. |
| `HORT_LOG_FORMAT` | no (default `pretty`) | `pretty` or `json` |
| `METRICS_INCLUDE_REPOSITORY_LABEL` | no (default `true`) | Set `false` at scale to emit the `_all` sentinel and keep series cardinality bounded |
| `RUST_LOG` | no (default `info`) | `EnvFilter` directive — e.g. `hort_server=debug,hort_app=info` |

¹ `HORT_DATABASE_URL` is the canonical operator DSN var;
bare `DATABASE_URL` is honored as a compat fallback (for sqlx-cli, the Tier-2
`maybe_pool()` test helpers, and 12-factor tooling). Exactly one is required;
the server prefers `HORT_DATABASE_URL`, identical to `hort-worker`. The Helm
chart wires `HORT_DATABASE_URL`.

## Local-dev quickstart

```bash
# 1. Postgres
docker run --rm -d --name hort-pg -p 5432:5432 \
  -e POSTGRES_USER=registry -e POSTGRES_PASSWORD=registry \
  -e POSTGRES_DB=artifact_registry postgres:15

# 2. Server (HORT_DATABASE_URL is canonical; bare DATABASE_URL also works)
HORT_DATABASE_URL='postgres://registry:registry@localhost:5432/artifact_registry' \
HORT_STORAGE_BACKEND=filesystem \
HORT_STORAGE_FILESYSTEM_PATH=/tmp/hort-server-cas \
cargo run -p hort-server

# 3. Declare a repo via gitops YAML (REST create is not supported —
#    configuration is gitops-only). Point HORT_CONFIG_DIR at a tree
#    containing one or more `kind: ArtifactRepository` envelopes
#    and restart hort-server. See
#    docs/architecture/how-to/declare-gitops-config.md.
mkdir -p /tmp/hort-config/repositories
cat > /tmp/hort-config/repositories/pypi-dev.yaml <<'YAML'
apiVersion: project-hort.de/v1beta1
kind: ArtifactRepository
metadata:
  name: pypi-dev
spec:
  name: pypi-dev
  format: pypi
  type: hosted
  storage: { backend: filesystem, path: /tmp/hort-server-cas/pypi-dev }
  isPublic: true
  replicationPriority: local_only
YAML
# Re-run with `HORT_CONFIG_DIR=/tmp/hort-config` set; the boot apply
# creates the row before the listener binds.

# 4. Hit a format endpoint
curl -sf http://localhost:8080/pypi/pypi-dev/simple/
```

Kill with `Ctrl+C` — the server logs `beginning graceful shutdown`,
finishes in-flight requests, and exits 0.

## Minimal-setup bring-up (no IdP)

When deploying without an OIDC IdP (single-user on-prem, local dev, CI
fixtures), set `HORT_AUTH_PROVIDER=disabled` with
`HORT_NATIVE_TOKENS_ENABLED=true` and issue a service-account token from
the running pod / process. The inbound auth surface is the native-token
validator (`Bearer hort_<kind>_*`); HTTP Basic is accepted only as a
token *carrier* (the password field carries the native token; the
username field is ignored).

```bash
# 1. Issue a service-account token from inside the deployment:
hort-server admin issue-svc-token --name <logical-name>
# Prints `hort_svc_*` once. Capture it; it is not stored anywhere
# recoverable.

# 2. On the operator workstation:
hort-cli auth login --paste
# Paste the `hort_svc_*` at the prompt; the CLI stores it in the
# operating-system keychain.
```

For multi-user / federated deployments, set `HORT_AUTH_PROVIDER=oidc` and
drop a `GroupMapping` / `ClaimMapping` YAML in `$HORT_CONFIG_DIR` mapping
the IdP admin group / claim to the seeded `admin` role. The first user
matching the mapping has admin privilege from the first request —
gitops boot applies the mapping before HTTP starts. On a 401 the server
emits `WWW-Authenticate: Bearer realm="<issuer-url>"` so Bearer-aware
clients can do OIDC discovery without registry-side wire-up.

The prior HTTP-Basic-against-local-admin-row identity path (the
`hort-server admin bootstrap` CLI + `users.password_hash`) was removed
end-to-end in a hard cutover (no compat shim). See `docs/auth-catalog.md`
Entry 8.
