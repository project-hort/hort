# native-tests — the real-client smoke harness

One runner (`run.sh`) drives every native-client scenario inside one purpose-built
client image, against either a runner-managed `deploy/compose` stack **or** an
external hort you point it at. Scenarios are self-describing (a folder group plus
a `# requires:` header), so the runner selects a subset and skips what a mode
can't provide instead of failing.

This replaces the old split of `run-all.sh` (host-toolchain) + `scripts/run-e2e.sh`
(in-network) with a single command that CI and local runs share.

## Quick start

```bash
# Runner-managed compose stack (the CI gate): cycle deploy/compose, run every
# available scenario in-network, tear down.
./run.sh --hort=compose

# Just one scenario / one group:
./run.sh --hort=compose --scenario pypi
./run.sh --hort=compose --group clients

# Against an already-running hort (no stack management). Env vars, not args:
HORT_URL=https://hort.example.com \
KEYCLOAK_URL=https://idp.example.com/realms/hort \
  ./run.sh --hort=external --group clients

# What would run, and what each mode can/can't provide:
./run.sh --list --hort=compose
./run.sh --list --hort=external
```

## The client image

`Dockerfile.client` carries every client tool a scenario needs — python +
`build`/`twine`, node 20 + npm, cargo, skopeo, `psql`, `jq`, `curl` — so scenarios
never depend on host toolchains. `run.sh` builds it (cached) as
`hort-test-client:dev` and runs each scenario as a throwaway container. It is based
on `python:3.12-slim` specifically so venvs created by scenarios inherit a modern
pip (Debian's stock pip 23.0.1 crashes on hort's PEP 658/714 simple-index
metadata).

## Modes

| | `--hort=compose` (default) | `--hort=external` |
|---|---|---|
| Stack | runner cycles `deploy/compose` (`down -v` → `up -d --build` → readiness wait → tear down unless `--keep`) | you supply a running hort; runner manages nothing |
| Client network | attached to the `hort_default` compose network (in-network DNS) | own container; reaches a host-published hort via `host.docker.internal` |
| Endpoints | derived automatically | from `HORT_URL` / `KEYCLOAK_URL` (env) |
| `/metrics` | `http://hort-server:9090/metrics` (fresh stack → metric assertions are meaningful) | only if you set `METRICS_URL`; otherwise metric assertions **skip**, never fail |

### External-mode env

- `HORT_URL` (required) — base URL of the registry API.
- `KEYCLOAK_URL` (required) — realm base, e.g. `…/realms/hort` (the lib appends
  `/protocol/openid-connect/token`).
- `METRICS_URL` (optional) — Prometheus `/metrics`; usually an internal
  control-plane port, so leave it unset and the ingest-metric assertions skip.
- `HORT_DB_DSN` (optional) — enables `requires: db` scenarios against an external
  hort.

**Local stack via external mode:** pointing external mode at your own
`deploy/compose` stack works, but the hort must emit host-reachable absolute URLs
(the npm/cargo/pip download legs follow them). Start it with
`HORT_PUBLIC_BASE_URL=http://host.docker.internal:25080`. A remote hort with a real
public URL needs no such override.

## Selecting scenarios

- `--group <g>` (repeatable) — restrict to a folder group (`clients`, `proxy`, …).
- `--scenario <n>` (repeatable) — a bare name (`pypi`) or `group/name`
  (`clients/pypi`).
- `--compose-overlay <o>` (repeatable) — layer `deploy/compose/docker-compose.<o>.yml`
  and provide its token (`federation`).
- `--list` — print the inventory with per-mode availability; runs nothing.
- `--keep` — don't tear the compose stack down at the end (debugging).

Both `--flag value` and `--flag=value` forms are accepted.

## The scenario contract

Each scenario is `scenarios/<group>/<name>.sh`:

- The **folder is the group**.
- First content line is `# requires: <space-separated tokens>` (empty ⇒ needs only
  hort + keycloak).
- It `source`s `lib/common.sh` for the shared helpers: `fetch_token <user> <pass>`
  (Keycloak ROPC), `pass`/`fail`/`skip`/`log`, `summary`, `psql_one`/`psql_exec`
  (when `requires: db`), and `assert_metric_ingest <format>`.
- The runner passes `HORT_URL`, `KEYCLOAK_URL`, `METRICS_URL`,
  `KEYCLOAK_CLIENT_ID`/`SECRET`, `FIXTURES=/work/fixtures`, and (when available)
  `HORT_DB_DSN` via env.
- **Exit codes:** `0` all-pass, `1` some assertion failed, `77` self-skip (the
  `skip` helper — environment unmet). The runner maps `0`→pass, `77`→skip, and
  **anything else (including a tool that aborts with exit 2)** → fail, so a crashed
  client tool can never be mistaken for a skip.

### `requires:` tokens

| token | provided by |
|---|---|
| *(empty)* | always (any reachable hort + keycloak) |
| `egress` | the host having internet (probed) |
| `db` | compose always; external only if `HORT_DB_DSN` is set |
| `compose` | compose mode only (the runner-managed stack + its mounted gitops config) |
| `worker`, `scanner` | compose mode — the runner starts `--profile worker` on demand |
| `compose:<o>` / bare `<o>` | the matching `--compose-overlay <o>` (`federation`) |

A scenario whose `requires` aren't all provided is reported **SKIP (needs: …)**,
never a failure.

### Adding a scenario

Drop `scenarios/<group>/<name>.sh`, give it a `#!/usr/bin/env bash` shebang, a
`# requires:` line, `source ../../lib/common.sh`, route each check through
`pass`/`fail` (never an unconditional `pass` after a `… || fail`), and end with
`summary`. Mount fixtures from `fixtures/` (exposed at `$FIXTURES`).

## Notes

- **Upstream-verification tests** (`test-{cargo,npm,pypi}-upstream-*.sh` in
  `scripts/native-tests/`) are standalone scripts, not `run.sh` scenarios.
  They depend on wiremock and are out of CI scope until the SSRF guard gains
  a test-only escape hatch; run them manually when needed.
- **Kubernetes** scenarios (configmap gitops, cert rotation) live in a separate
  `scripts/k8s-tests/` suite — they need a `kind` cluster, not the compose stack.
