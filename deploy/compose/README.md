# Compose stack

Local stack that boots Postgres, Keycloak (OIDC), and `hort-server`. Used as the target for
the native-client E2E tests and for manual experimentation with the
`hort-server` binary against real package managers.

Binary scope limits: [`../../crates/hort-server/README.md`](../../crates/hort-server/README.md).

## Quickstart

```bash
# From the repo root
docker compose -f deploy/compose/docker-compose.yml up -d --build

# Wait for migrations (a dedicated hort-server-migrate one-shot runs first;
# hort-server serve refuses to start if the schema is stale)
docker compose -f deploy/compose/docker-compose.yml logs -f hort-server
# ... look for "API listening"; Ctrl+C once seen

# Scrape metrics
curl -s http://localhost:25090/metrics | grep hort_http_requests_received_total

# Repositories are declared as YAML in deploy/compose/example-config/ and
# applied at boot — see docs/architecture/how-to/declare-gitops-config.md.
# Add a YAML, restart hort-server, the row appears.
ls deploy/compose/example-config/repositories/

# Look up an existing repo's UUID + provenance (admin-authenticated).
# Repository CRUD via REST is intentionally not exposed — every
# repo comes from a YAML envelope. This GET endpoint exists so tooling
# (e.g. test-oci-mirror.sh) can resolve a stable key to the freshly-
# minted UUID without grovelling in the database.
TOKEN=...   # Bearer JWT from your IdP
curl -sf -H "Authorization: Bearer $TOKEN" \
  http://localhost:25080/admin/repositories/pypi-internal

# Hit the PyPI Simple index for one of the example-config repos
curl -sf http://localhost:25080/pypi/pypi-internal/simple/

# Upload via twine (the stack requires a valid bearer token — use __token__ as
# the username and a hort native token or Keycloak access token as the password)
twine upload --repository-url http://localhost:25080/pypi/pypi-internal/ \
             --username __token__ --password <token> \
             dist/*
```

## Ports

| Host | Container | Purpose |
|------|-----------|---------|
| `25080` | `hort-server:8080` | Main API — format handlers + `/admin` |
| `25082` | `keycloak:8080` | Keycloak realm — OIDC discovery/token |
| `25090` | `hort-server:9090` | Admin listener — `/metrics` only |

Postgres is NOT exposed on the host to avoid clashing with a system
install. For ad-hoc `psql` use:

```bash
docker compose -f deploy/compose/docker-compose.yml exec postgres \
  psql -U registry -d artifact_registry
```

`/metrics` is deliberately off the main listener — the main API never
serves the scrape endpoint in this stack. Point Prometheus at `:9090`.

## Env vars

Full list in [`../../crates/hort-server/README.md`](../../crates/hort-server/README.md).
The compose file pins sensible defaults for local dev.

## Teardown

```bash
docker compose -f deploy/compose/docker-compose.yml down -v
```

Postgres data lives on a tmpfs (see `docker-compose.yml`), so the
database is always wiped between `compose down` and `compose up` —
this stops `_sqlx_migrations` checksum drift after a branch switch
or migration edit. `down -v` additionally deletes the named `cas`
volume, so the CAS root also starts empty on the next `up -d`. Omit
`-v` to preserve cached artifact bytes across restarts; the DB is
ephemeral either way.

## What's out of scope

- **Auth configuration.** Routes are authenticated via the bundled Keycloak
  (realm at `localhost:25082`). `developer` and `reader` roles hold zero
  implicit grants; permissions are declared per-repo via
  `kind: PermissionGrant`. See `example-config/auth/dev-write-pypi-e2e.yaml`
  for the canonical shape and
  [`../../docs/architecture/how-to/declare-gitops-config.md`](../../docs/architecture/how-to/declare-gitops-config.md)
  §`kind: PermissionGrant` for full semantics.
- **TLS, ingress, secrets management.** Plain HTTP on localhost only.
- **Non-PyPI/npm/cargo/OCI formats.** Those four are wired; handlers for
  other formats 404.
