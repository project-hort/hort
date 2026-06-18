# Alpha testing runbook — local stack

End-to-end runbook for an alpha tester verifying the hort binaries
(`hort-server`, `hort-worker`, `hort-cli`) locally on a single host.

## Two tracks

The binaries support two authentication postures. This runbook covers both;
each phase below is tagged with the track(s) it applies to.

- **Track A — no OIDC (PAT-only).** `HORT_AUTH_PROVIDER=disabled`, native
  tokens on. The operator credential is a **service-account svc-token**
  (`hort-server admin issue-svc-token`). Fast to stand up — Postgres + Redis
  only. Covers everything that does **not** require admin-claim authority or
  an OIDC CLI session.
- **Track B — OIDC (full features).** `HORT_AUTH_PROVIDER=oidc` against a
  bundled Keycloak (realm `hort`). Unlocks the claim-gated surfaces: OCI
  push/pull, admin quarantine release, patch-candidate listing, and the
  discovery/prefetch endpoints. Track B is a superset — everything in
  Track A still works, plus the OIDC-only features.

Pick a track at §1/§3/§4; §0, §2, §5, §6 are shared.

### Feature × track support matrix

| Surface | Track A (PAT) | Track B (OIDC) |
|---|:---:|:---:|
| npm / PyPI / Cargo publish + proxy install | ✅ | ✅ |
| Quarantine → scan → release lifecycle | ✅ | ✅ |
| Index filtering | ✅ | ✅ |
| `hort-cli admin task invoke <kind>` | ✅ | ✅ |
| Curator workflow (waive/block/exclude) | ✅¹ | ✅ |
| Admin tasks / event-chain / scrub (§12/§13) | ✅ | ✅ |
| **OCI proxy / hosted** (§7.4) | ❌ | ✅ |
| **Admin quarantine release** (§8.4) | ❌ | ✅ |
| **Patch-candidate listing** (§11) | ❌ | ✅ |
| **Discovery / prefetch** (§9) | ❌ | ✅² |

¹ Curator authority is reachable under PAT once a `PermissionGrant
{subject: User(<svc-user>), permission: curate}` is applied — see §11.5.1.
² Discovery/prefetch require a `TokenKind::CliSession` minted by
`hort-cli auth login` against the OIDC provider, not a raw bearer.

**Why OCI / admin-release / patch-candidate are Track-B-only:** PATs from
`hort-server admin issue-svc-token` top out at `[write, read, delete,
admin_task_invoke]` — there is **no way to mint a PAT with
`Permission::Admin`** (by design: long-lived static tokens stay
under-privileged for admin claim authority). The OCI handler likewise rejects
a raw svc-token PAT (`NotOurToken`) and needs an OCI-minted JWT or an OIDC
bearer. Those surfaces therefore require Track B.

**Scope:**

- **Formats:** npm, PyPI, Cargo, OCI (the four with `hort-http-*` crates).
  The other formats (Maven, Debian, RPM, Helm, NuGet, Go, Conda, RubyGems,
  Composer, Hex, Pub, Terraform, Ansible, Alpine, CRAN, Git LFS) are **out of
  scope** for the alpha.
- **Scanners:** real Trivy + osv-scanner CLIs invoked from `$PATH`.
- **Topology:** binaries run natively from `cargo run` (or
  `./target/release/…`); Postgres, Redis, and (Track B) Keycloak are
  containerised via `docker compose`. No compose for the binaries, no Helm.

**What the runbook covers** (one phase per feature surface):

| §  | Phase | Track | What it pins |
|----|-------|-------|---|
| 0  | Prerequisites + tooling | A+B | Required CLIs and versions |
| 1  | Bring up dependencies | A+B | Postgres + Redis (+ Keycloak for B) |
| 2  | Build binaries + apply migrations | A+B | `cargo build` + `hort-server migrate` |
| 3  | Credentials | A / B | svc-token (A) or OIDC tokens (B) |
| 4  | Start `hort-worker` **then** `hort-server` | A+B | Process lifecycle + `/healthz` + `/readyz` |
| 5  | Configure hort-cli + login | A+B | `hort-cli auth login` + `auth status` |
| 6  | Verify gitops `$HORT_CONFIG_DIR` applied | A+B | 8 repos (+ claim mappings for B) |
| 7  | Per-format smoke | A+B / B | Hosted publish + proxy pull + CAS integrity |
| 8  | Quarantine + scanner lifecycle | A+B | Quarantine → Scan → Release/Reject |
| 9  | Discovery + prefetch | B | `on_dist_tag_move` + `hort-cli prefetch` |
| 10 | Index integrity | A+B | Filter pipeline + PEP 658 |
| 11 | Patch-candidate admin surface | B | Cross-tenant listing |
| 11.5 | Curator workflow | A+B | Grant + waive + block + exclusion cascade |
| 12 | Admin tasks via the worker | A+B | Cron-style task dispatch |
| 13 | Retention + event-chain integrity | A+B | `eventstore-archive` + `verify-event-chain` |
| 14 | Teardown + reset | A+B | Clean state |

---

## §0 — Prerequisites  *(Track A+B)*

### Host

- Linux or macOS (Windows under WSL2 should work but is untested).
- ≥ 16 GB RAM, ≥ 20 GB free disk.
- Outbound HTTPS to `registry.npmjs.org`, `pypi.org`, `crates.io`,
  `index.docker.io`, `ghcr.io`, the RustSec advisory DB
  (`github.com/RustSec/advisory-db`), the OSV vulnerability DB
  (`api.osv.dev`), and Trivy's CVE feeds. Behind a corporate proxy,
  set `HTTP_PROXY`/`HTTPS_PROXY` before launching binaries.

### One-shot setup script

```bash
./scripts/alpha-fixtures/setup-alpha-env.sh
```

It checks that `docker`, `cargo` (≥ 1.94), `curl`, `jq`, and `python3`
(≥ 3.11) are present, then installs nvm + Node LTS, a Python venv at
`./.alpha-venv/` with `twine` + `build`, and `crane` / `trivy` /
`osv-scanner` to `~/.local/bin/`. Re-running is safe.

After running it, every fresh terminal needs:

```bash
source ~/.nvm/nvm.sh && nvm use
source ./.alpha-venv/bin/activate
source ./scripts/alpha-fixtures/alpha.env          # Track A and B
# Track B only — layer OIDC on top:
# source ./scripts/alpha-fixtures/alpha.env.oidc
```

Minimum-version cheatsheet if installing tools yourself:

| Tool | Minimum | Used in |
|------|---------|---------|
| `cargo` | 1.94 | §2, §4 |
| `docker` + `docker compose` v2 | 25+ | §1 |
| `node` + `npm` | 22 LTS | §7, §9 |
| `python3` + `pip` + `twine` + `build` | 3.11+ | §7, §10 |
| `crane` (or `skopeo`/`regctl`) | 0.20+ | §7 (OCI, Track B) |
| `trivy` | 0.50+ | §8 |
| `osv-scanner` | 1.7+ | §8, §10 |
| `jq`, `curl` | any | many |

### Repository layout assumed

You are at the workspace root (`pwd` ends in `hort`). All paths below
are relative to that root.

---

## §1 — Bring up dependencies  *(Track A+B)*

The runbook ships `scripts/alpha-fixtures/compose-deps.yml`: Postgres
(`30432`) + Redis (`30379`), plus a **profile-gated Keycloak** (`25380`,
Track B only).

> **⚠ Port collision:** a previous alpha run's container may still hold
> `30432`. Stop the conflicting container (`docker stop hort-alpha-postgres`)
> or edit `compose-deps.yml` + `alpha.env` to a different port.

**Track A — Postgres + Redis:**

```bash
docker compose -f scripts/alpha-fixtures/compose-deps.yml up -d
until docker exec hort-alpha-postgres pg_isready -U registry -q 2>/dev/null; do sleep 1; done
until docker exec hort-alpha-redis redis-cli ping | grep -q PONG; do sleep 1; done
echo "deps ready"
```

**Track B — also bring up Keycloak (realm `hort`):**

```bash
docker compose -f scripts/alpha-fixtures/compose-deps.yml --profile oidc up -d
# Wait for the realm import to finish (discovery doc returns 200):
until curl -fsS http://localhost:25380/realms/hort/.well-known/openid-configuration >/dev/null 2>&1; do sleep 2; done
echo "keycloak realm hort ready"
```

The bundled Keycloak reuses `deploy/compose/keycloak/realm.json` — realm `hort`,
client `hort-server` (secret `hort-server-secret-dev-only`,
`directAccessGrantsEnabled`), public client `hort-cli`, and three users:
`admin`/`admin` (group `hort-admins` → `admin` claim), `dev-user`/`dev`
(group `test-developers` → `developer` + `ci-pusher`), `reader-user`/`reader`
(group `hort-readers` → `reader`).

**Assertion (§1.a):** `docker ps --filter name=hort-alpha-` shows the expected
containers `Up`/`healthy` (2 for Track A, 3 for Track B).

To wipe state between passes: `… --profile oidc down -v`.

---

## §2 — Build binaries + apply migrations  *(Track A+B)*

```bash
cargo build --release -p hort-server -p hort-worker -p hort-cli

source ./scripts/alpha-fixtures/alpha.env
./target/release/hort-server migrate
```

Both `hort-server` and `hort-worker` read `HORT_DATABASE_URL` first, falling
back to bare `DATABASE_URL` (uniform across both binaries).
`alpha.env` exports both, so either name resolves the DSN.

**Assertion (§2.a):** `migrate` exits 0; last log line `migrations complete`
(preceded by `events role hardening re-asserted`).

**Assertion (§2.b):** latest applied migration version:

```bash
docker exec hort-alpha-postgres psql -U registry -d artifact_registry \
    -c "SELECT max(version) FROM _sqlx_migrations WHERE success;"
```

> **Migration-checksum drift** — if `migrate` fails with *"migration N was
> previously applied but has been modified"*, a prior run left a stale schema
> (migrations are edited in place pre-1.0). Recreate the DB and re-migrate:
> ```bash
> docker exec hort-alpha-postgres psql -U registry -d postgres \
>     -c "DROP DATABASE IF EXISTS artifact_registry WITH (FORCE); CREATE DATABASE artifact_registry OWNER registry;"
> ./target/release/hort-server migrate
> ```
> (The plain `down -v` volume wipe in §1 also works but discards every DB on
> the instance.)

---

## §3 — Credentials

### §3·A — Track A: issue the operator svc-token  *(Track A)*

`hort-server` ships no `bootstrap` subcommand. The
PAT-only operator credential is a service-account svc-token.

```bash
mkdir -p ./data/alpha
./target/release/hort-server admin issue-svc-token \
    --name alpha-operator \
    --permission write --permission read --permission delete --permission admin_task_invoke \
    --output "file:./data/alpha/svc-token.txt"
export ADMIN_PAT="$(cat ./data/alpha/svc-token.txt)"
test -n "$ADMIN_PAT"
```

`--permission admin` is **rejected** (system-mint refuses to self-declare
admin). For admin surfaces, use Track B.

**Assertion (§3·A.a):** the file is ~40 bytes, starts with `hort_svc_`. Server
log: `service-account token issued, … name: alpha-operator, kind:
ServiceAccount, user_id: <uuid>`. **Save the `user_id`** — §11.5.1 needs it.
The svc-token expires after 1 h (admin cap); re-issue + re-export for
a long pass.

### §3·B — Track B: OIDC tokens from Keycloak  *(Track B)*

Layer the OIDC env on top of `alpha.env`:

```bash
source ./scripts/alpha-fixtures/alpha.env
source ./scripts/alpha-fixtures/alpha.env.oidc   # HORT_AUTH_PROVIDER=oidc + issuer + full HORT_CONFIG_DIR
```

Fetch bearer tokens directly from Keycloak (ROPC — fine for a test harness;
the password never touches hort-server):

```bash
get_token() {  # usage: get_token <user> <pass>
  curl -s -X POST http://localhost:25380/realms/hort/protocol/openid-connect/token \
    -d grant_type=password -d client_id=hort-server \
    -d client_secret=hort-server-secret-dev-only \
    -d "username=$1" -d "password=$2" | jq -r .access_token
}
export ADMIN_TOKEN="$(get_token admin admin)"      # group hort-admins → admin claim (full authority)
export DEV_TOKEN="$(get_token dev-user dev)"        # test-developers → developer + ci-pusher
export READER_TOKEN="$(get_token reader-user reader)"
```

Use `$ADMIN_TOKEN` wherever the Track-A steps use `$ADMIN_PAT`. For the
discovery/prefetch endpoints (§9), which require a `TokenKind::CliSession`,
use `hort-cli auth login` (§5·B) instead of a raw bearer.

**Assertion (§3·B.a):** `get_token` returns a non-empty JWT; decoding its
payload shows `iss: http://localhost:25380/realms/hort`, `aud: hort-server`,
and a `groups` claim.

> A svc-token (§3·A) still works in Track B for the non-admin
> write/read/delete path and is handy alongside the OIDC tokens.

---

## §4 — Start `hort-worker`, then `hort-server`  *(Track A+B)*

> **Order matters on a fresh DB.** The default scan policy declares
> `scan_backends: [trivy, osv]`, and gitops apply at server boot **fail-closes**
> unless a live worker has registered those backends in `scanner_registry`.
> Start the **worker first** so it registers `trivy`/`osv`, then the server.

```bash
# Terminal B — worker (start first)
source ./scripts/alpha-fixtures/alpha.env
# Track B: also `source ./scripts/alpha-fixtures/alpha.env.oidc`
./target/release/hort-worker 2>&1 | tee /tmp/hort-worker.log
```

Wait for `hort-worker ready, scanners: ["trivy", "osv"]`. Then:

```bash
# Terminal A — server
source ./scripts/alpha-fixtures/alpha.env
# Track B: also `source ./scripts/alpha-fixtures/alpha.env.oidc`
./target/release/hort-server serve 2>&1 | tee /tmp/hort-server.log
```

**Assertion (§4.a):** server logs `gitops boot: parse complete` (Track A:
`claim_mappings_desired: 0, permission_grants_desired: 0`; Track B:
`claim_mappings_desired: 3, permission_grants_desired: 6`), then
`gitops apply complete`, `AppContext built`, and `API listening, addr:
127.0.0.1:8080`. Track A also logs `AuthContext::BearerOnly wired
(HORT_AUTH_PROVIDER=disabled with native tokens)`; Track B wires the OIDC
provider.

**Assertion (§4.b):** `curl -fsS http://localhost:8080/healthz` and `…/readyz`
both return `200`.

**Assertion (§4.c):** worker logs `task dispatcher` registration for `scan`,
`cron-rescan-tick`, `advisory-watch-tick`, `quarantine-release-sweep`,
`prefetch-*`, `seed-import`, etc. (a couple are skipped on a non-k8s /
filesystem host: `ServiceAccountRotation`, `EventstoreCheckpoint` — expected).

**Assertion (§4.d):** `curl -s http://localhost:8080/metrics | grep '^hort_'`
returns a non-empty list (e.g. `hort_http_requests_total`,
`hort_event_store_*`, `hort_storage_*`). `alpha.env` sets
`HORT_METRICS_REQUIRE_AUTH=false` so this scrape is anonymous; without it the
endpoint returns `401` and you must pass `-H "Authorization: Bearer <token>"`.

If §4.a–d don't all pass, **stop and triage** — most often a stale schema
(re-run `hort-server migrate`, see §2) or the worker not started first.

---

## §5 — Configure hort-cli and login  *(Track A+B)*

### §5·A — Track A: paste the svc-token

```bash
echo "$ADMIN_PAT" | ./target/release/hort-cli auth login \
    --server http://localhost:8080 --paste
./target/release/hort-cli auth status
```

Pipe via `--paste`; the `--token <X>` flag is ignored in the paste-fallback
path (OIDC discovery returns 404 in Track A). Config persists to
`~/.hort/config.toml`.

**Assertion (§5·A.a):** `auth login` prints `Logged in as <service account>
(kind=svc_account)` (with an informational warning that the token kind isn't
`hort_cli_*`/`hort_pat_*` — expected for the svc-token path).

**Assertion (§5·A.b):** `auth status` shows `token_kind: svc_account` +
`permissions: write, read, delete, admin_task_invoke`. `user_id`/`username`
are `<null>` (svc-account whoami shape).

### §5·B — Track B: OIDC CLI session

```bash
./target/release/hort-cli auth login --server http://localhost:8080
```

With `HORT_AUTH_PROVIDER=oidc`, the CLI discovers the issuer and runs the OIDC
device / loopback flow against the `hort-cli` public client, exchanging the
result for a `TokenKind::CliSession` (a claims-carrying hort-signed JWT). This
session is what the discovery/prefetch endpoints (§9) require. See
`docs/architecture/how-to/federate-ci-oidc.md` for the full flow.

**Assertion (§5·B.a):** `auth status` shows `token_kind: cli_session` and the
resolved claims (`admin` for the `admin` user, `developer`+`ci-pusher` for
`dev-user`).

---

## §6 — Verify gitops `$HORT_CONFIG_DIR` applied  *(Track A+B)*

`hort-server` walked `$HORT_CONFIG_DIR` at boot (§4) and applied it before
binding. The fixture tree is split so each track applies the right set:

```
scripts/alpha-fixtures/gitops-config/
├── base/              # Track A → HORT_CONFIG_DIR=…/gitops-config/base
│   ├── repositories/  # 8 repos: hosted + proxy × 4 formats
│   ├── upstreams/      # 4 UpstreamMappings
│   └── policies/       # default scan policy
└── auth/              # Track B only (full tree) — ClaimMappings + claim grants
```

`alpha.env` defaults `HORT_CONFIG_DIR` to `…/base` (Track A). `alpha.env.oidc`
overrides it to the full `…/gitops-config` so the `auth/` ClaimMappings apply
(Track B). They live above `base/` because hort-server fail-closes if
ClaimMappings are declared while `HORT_AUTH_PROVIDER=disabled` — Track A must
exclude them.

```bash
grep "gitops boot: parse complete" /tmp/hort-server.log
docker exec hort-alpha-postgres psql -U registry -d artifact_registry \
    -c "SELECT key, repo_type, format, index_mode FROM repositories ORDER BY key;"
```

**Assertion (§6.a):** all 8 repos present. Hosted → `index_mode =
released_only`; proxy → `index_mode = include_pending` (load-bearing for proxy
installs — `released_only` on a proxy hides never-ingested upstream versions
so pip/npm/cargo can't bootstrap).

**Assertion (§6.b):** a proxy repo resolves upstream:

```bash
# Track A: $ADMIN_PAT ; Track B: $ADMIN_TOKEN
curl -fsS -H "Authorization: Bearer ${ADMIN_PAT:-$ADMIN_TOKEN}" \
    http://localhost:8080/npm/npm-proxy/lodash | jq '.name'   # → "lodash"
```

**Assertion (§6.c, Track B):** the boot log shows `claim_mappings_desired: 3,
permission_grants_desired: 6`, and
`hort-cli admin users effective-permissions` for the `dev-user` shows the
read+prefetch grants.

To re-apply after editing YAML: restart `hort-server` (files-in, startup-only).

---

## §7 — Per-format smoke

Throughout §7, the bearer is `$ADMIN_PAT` (Track A) or `$ADMIN_TOKEN`
(Track B). The `${ADMIN_PAT:-$ADMIN_TOKEN}` shell idiom picks whichever is set.

### §7.1 — npm  *(Track A+B)*

**Proxy pull** (the cleanest end-to-end: pull-through → CAS → quarantine):

```bash
mkdir -p /tmp/hort-alpha-npm && cd /tmp/hort-alpha-npm
TOKEN="${ADMIN_PAT:-$ADMIN_TOKEN}"
cat > .npmrc <<EOF
registry=http://localhost:8080/npm/npm-proxy/
//localhost:8080/npm/npm-proxy/:_authToken=${TOKEN}
EOF
npm install --no-save --no-audit lodash@4.17.21
```

**Assertions (§7.1.a):**

- The **first** install returns `503 Service Unavailable — artifact is
  quarantined` (quarantine-by-default; never `409`). The artifact is
  ingested (CAS objects appear under `./data/alpha/storage`) but held.
- Drive it through release (§8.2): run the worker scan + the release sweep,
  then re-run `npm install` — it succeeds (`added 1 package`).
- `curl … /npm/npm-proxy/lodash | jq '.versions["4.17.21"].dist.tarball'`
  shows a hort-rewritten URL pointing at `localhost:8080`.

**Hosted publish:**

```bash
mkdir -p /tmp/hort-alpha-npm-pub && cd /tmp/hort-alpha-npm-pub
cat > package.json <<'EOF'
{ "name": "hort-alpha-smoke", "version": "1.0.0", "main": "index.js" }
EOF
echo "module.exports = {};" > index.js
cat > .npmrc <<EOF
registry=http://localhost:8080/npm/npm-hosted/
//localhost:8080/npm/npm-hosted/:_authToken=${ADMIN_PAT:-$ADMIN_TOKEN}
EOF
npm publish --registry http://localhost:8080/npm/npm-hosted/
```

Immediately after publish the packument `versions` is empty and the tarball
returns `503` — quarantine-by-default. Run §8 to release.

### §7.2 — PyPI  *(Track A+B)*

**Proxy pull:**

```bash
pip install --quiet --index-url http://localhost:8080/pypi/pypi-proxy/simple/ \
    --trusted-host localhost requests==2.32.3
```

**Hosted publish (twine):**

```bash
cd /tmp && mkdir -p hort-alpha-pypi && cd hort-alpha-pypi
cat > pyproject.toml <<'EOF'
[build-system]
requires = ["setuptools>=64"]
build-backend = "setuptools.build_meta"
[project]
name = "hort-alpha-smoke"
version = "1.0.0"
EOF
mkdir -p src/hort_alpha_smoke && : > src/hort_alpha_smoke/__init__.py
python -m build --sdist --wheel
twine upload --repository-url http://localhost:8080/pypi/pypi-hosted/ \
    --username __token__ --password "${ADMIN_PAT:-$ADMIN_TOKEN}" dist/*
```

**Assertions (§7.2.a):** the hosted simple-index lists both artifacts; the
wheel anchor carries `data-dist-info-metadata="sha256=<HEX>"` (PEP 658);
the PEP 691 JSON variant carries `"dist-info-metadata"`; and the
`.metadata` sibling serves the `METADATA` bytes whose SHA-256 matches.

### §7.3 — Cargo  *(Track A+B)*

> **Fixture URL must be correct.** Cargo's sparse-index host is
> `index.crates.io`, not `crates.io`
> (`…/gitops-config/base/upstreams/13-cargo-proxy.yaml`). A 403 on metadata
> fetch means the YAML still points at `crates.io`.

```bash
mkdir -p ~/.cargo && cat >> ~/.cargo/config.toml <<EOF
[registries.alpha-proxy]
index = "sparse+http://localhost:8080/cargo/cargo-proxy/"
EOF
cd /tmp && mkdir -p hort-alpha-cargo && cd hort-alpha-cargo && cargo init --bin
echo 'serde = "1"' >> Cargo.toml
cargo fetch --registry alpha-proxy
```

**Assertions (§7.3.a):** `cargo fetch` succeeds; each sparse-index NDJSON line
carries `"cksum":"<64-hex>"` and `"yanked":false`.

### §7.4 — OCI  *(Track B only)*

> Requires an OIDC bearer — a raw svc-token PAT is rejected as `NotOurToken`.
> Run this in Track B with `$ADMIN_TOKEN`.

```bash
echo "$ADMIN_TOKEN" | crane auth login localhost:8080 --username admin --password-stdin
crane pull --insecure localhost:8080/oci-proxy/library/alpine:latest /tmp/alpine.tar
crane push --insecure /tmp/alpine.tar localhost:8080/oci-hosted/test-img:v1
crane manifest localhost:8080/oci-hosted/test-img:v1 | jq '.'
```

**Assertions (§7.4.a):** pull/push succeed; blob digests are CAS-keyed in
`./data/alpha/storage`; the manifest digest matches the v2-protocol
`Docker-Content-Digest` header (ProtocolNativeIntegrity invariant).

---

## §8 — Quarantine + scanner lifecycle  *(Track A+B)*

### §8.1 — Scanners available

```bash
trivy --version          # ≥ 0.50
osv-scanner --version    # ≥ 1.7
```

The default policy (`…/base/policies/20-default-scan-policy.yaml`) declares
`scan_backends: [trivy, osv]`, `severity_threshold: Critical`,
`quarantine_duration_secs: 60`.

### §8.2 — A clean artifact's lifecycle

1. Ingest a clean artifact (any §7 proxy pull or hosted publish).
2. Server emits `ArtifactIngested → ArtifactQuarantined`
   (`quarantine_window_start` set); worker claims the `scan` job within ~1 s
   and runs Trivy + OSV.
3. **While quarantined**, downloading the tarball returns `503` +
   `Retry-After` (never `409`).
4. `ScanCompleted(clean)` leaves the artifact `quarantined` — scan success
   alone does **not** release (the timer must also elapse).
5. **Local alpha has no cron** — enqueue the release sweep manually:
   ```bash
   ./target/release/hort-server enqueue-quarantine-release-sweep
   ```
   The worker logs `quarantine-release-sweep tick complete, candidates: N,
   released: N` for every artifact whose window has elapsed **and** has a
   release authority (`scan_succeeded`).
6. Download now returns `200`.

**Assertions (§8.2.a):** status transitions `quarantined → released` after
both gates; the effective deadline = `quarantine_window_start +
ScanPolicy.quarantine_duration_secs`:

```bash
docker exec hort-alpha-postgres psql -U registry -d artifact_registry -c \
  "SELECT version, quarantine_status, quarantine_window_start FROM artifacts WHERE name='lodash' ORDER BY version;"
```

### §8.3 — A vulnerable artifact's rejection  *(Track A+B)*

```bash
npm pack --registry http://localhost:8080/npm/npm-proxy/ event-stream@3.3.6
```

The scanner flags `GHSA-mh6f-8j2x-4483` (the malicious `flatmap-stream` dep):

**Assertions (§8.3.a):** `quarantine_status` flips to `rejected`
(`ScanCompleted(findings) → ArtifactRejected`); download returns `404`
(anti-enumeration); the version disappears from the served
packument (the `NonServableStatusFilter`).

### §8.4 — Admin release  *(Track B only)*

Needs `Permission::Admin`. In Track B with `$ADMIN_TOKEN` (admin user):

```bash
hort-cli admin quarantine release "$ARTIFACT_ID" \
    --justification "Alpha test — reviewed CVE manually, accepting risk."
```

**Assertions (§8.4.a):** emits `ArtifactReleased { authority: AdminOverride,
released_by_user_id: <admin>, justification }`; artifact becomes downloadable;
empty / > 512-byte justification rejected client-side.

> For the curator equivalent reachable under PAT, see §11.5.2.

### §8.5 — Advisory-watch + rescan  *(Track A+B)*

```bash
hort-cli admin task invoke advisory-watch-tick
hort-cli admin task invoke cron-rescan-tick
```

(`admin task invoke` works under the svc-token's `admin_task_invoke`
permission, so this is Track A+B.) The advisory-watch task syncs the OSV
daily-diff; `cron-rescan-tick` enqueues rescans for held artifacts.

---

## §9 — Discovery + prefetch  *(Track B only)*

The discovery/prefetch endpoints require **both** an OIDC-backed CLI
session (`TokenKind::CliSession`, §5·B) **and** a `Permission::Prefetch` grant
— both supplied in Track B (the `auth/` fixtures grant `[developer,
ci-pusher] → prefetch` per proxy repo; the `dev-user` has those claims).

```bash
# As dev-user via an OIDC CLI session (hort-cli auth login --server … with DEV creds)
hort-cli prefetch npm-proxy lodash --version 4.17.20
```

The hot-path trigger is `on_dist_tag_move`: it fires when upstream's
`dist-tags.latest` points at a
version hort does not hold.

**Assertions (§9.a):**

```bash
curl -s http://localhost:8080/metrics | grep hort_prefetch_enqueued_total
#   hort_prefetch_enqueued_total{trigger="on_dist_tag_move",…} > 0   (tag-move induced)
#   hort_prefetch_self_service_total{…,result="enqueued"} > 0        (hort-cli prefetch)
```

Ingested artifacts go through the same quarantine lifecycle as §7.1.

---

## §10 — Index integrity  *(Track A+B)*

The Source → Filter → Builder pipeline guarantees that
`Quarantined` / `Rejected` / `ScanIndeterminate` artifacts never appear in any
served index, in either repo mode.

**Assertion (§10.a) — Quarantined filtered:** during the §8.2 window the new
artifact's version is absent from the served index; after release it reappears.

**Assertion (§10.b) — Rejected filtered:** after §8.3, `event-stream@3.3.6` is
absent across packument / simple-index / sparse-index:

```bash
curl -s -H "Authorization: Bearer ${ADMIN_PAT:-$ADMIN_TOKEN}" \
    http://localhost:8080/npm/npm-proxy/event-stream | jq '.versions | keys'   # no "3.3.6"
```

**Assertion (§10.c) — PEP 658:** the `.metadata` sibling serves
bytes for a proxy wheel (cache-miss triggers the strategy-2 full-wheel pull),
and its SHA-256 matches the advertised hash (see §7.2.a).

**Assertion (§10.d) — Index-mode:** toggle a proxy repo's
`index_mode` in `…/base/repositories/0X-*.yaml`, restart hort-server, and
verify the served packument changes: `released_only` DROPS never-ingested
upstream versions (build-safe); `IncludePending` KEEPS them (clients trigger
pull-through). Both modes drop `Quarantined / Rejected / ScanIndeterminate`.

---

## §11 — Patch-candidate admin surface  *(Track B only)*

Needs `Permission::Admin` (cross-tenant). In Track B:

```bash
hort-cli admin quarantine list-patch-candidates --output table
```

**Assertions (§11.a):** after §8.3 produced a rejected `event-stream@3.3.6`
and a newer clean version exists, the listing surfaces the pair;
`--justification` is required for `hort-cli admin quarantine release`.

---

## §11.5 — Curator workflow  *(Track A+B)*

`Permission::Curate` is reachable under **PAT** (Track A) once a
`PermissionGrant {subject: User(<svc-user>), permission: curate}` is applied —
curator is the day-to-day per-artifact decision role, deliberately not gated
on admin claim authority. In Track B it's also reachable via the admin/OIDC
path. See [`curator-workflow.md`](curator-workflow.md).

### §11.5.1 — Grant `Permission::Curate` (Track A svc-token)

Use the `user_id` from §3·A's server log; or look it up:

```bash
SVC_USER_ID="$(docker exec hort-alpha-postgres psql -U registry -d artifact_registry \
    -tAc "SELECT id FROM users WHERE username = 'svc_alpha-operator';")"
mkdir -p "$HORT_CONFIG_DIR/permissions"
cat > "$HORT_CONFIG_DIR/permissions/alpha-curator.yaml" <<EOF
apiVersion: project-hort.de/v1beta1
kind: PermissionGrant
metadata:
  name: alpha-svc-curator
spec:
  subject:
    kind: user
    userId: $SVC_USER_ID
  permission: curate
EOF
```

Restart `hort-server` to apply (boot-time gitops). **Note:** in Track A,
`$HORT_CONFIG_DIR` is `…/gitops-config/base`, so write the grant under
`base/permissions/`; in Track B it is the full tree.

**Assertions (§11.5.1.a):** boot log shows `permission_grant … created`;
`hort-cli admin users effective-permissions "$SVC_USER_ID"` lists a `curate`
grant rendered as `user:<uuid>`.

### §11.5.2 — Waive a `Quarantined` artifact

```bash
hort-cli curation queue --status quarantined --repo npm-proxy --output table
hort-cli curation waive "$ARTIFACT_ID" \
    --justification "Alpha test — clean scan, accepting advisory lag."
```

**Assertions (§11.5.2.a):** emits `ArtifactReleased { authority: CuratorWaiver,
released_by_user_id: $SVC_USER_ID, justification }`; artifact downloadable;
`hort-cli curation decisions --type waive …` lists it; empty / > 512-byte
justification rejected client-side. **Source-state guard:** waiving a
`ScanIndeterminate` artifact returns `400` (that state is admin-only, §8.4).

### §11.5.3 — Block (single + bulk)

```bash
hort-cli curation block artifact "$ARTIFACT_ID" --justification "Alpha — single block."
hort-cli curation block versions --repo npm-proxy --package event-stream \
    --versions 3.3.6,9.9.9-nonexistent --justification "Alpha — bulk + not_found."
```

**Assertions (§11.5.3.a):** the bulk call returns **`200`** with the
`BlockOutcome` envelope (continue-on-error; partial success is not an HTTP
error); `blocked_artifact_ids` has `3.3.6`, `not_found_versions` has
`9.9.9-nonexistent`; re-running is an idempotent no-op
(`already_rejected_ids`); ANSI bytes suppressed when piped
(`… | cat | od -c | grep -c '033'` → 0).

### §11.5.4 — Finding-exclusion cascade

```bash
hort-cli curation exclude-finding --policy "$POLICY_ID" --cve "$CVE_ID" \
    --justification "Alpha — vulnerable path not reachable."
```

**Assertions (§11.5.4.a):** `ExclusionAdded` appended with the curator's
user_id on the envelope; rejected artifacts whose *only* blocking finding is
the excluded CVE transition `Rejected → Quarantined` (window still future) or
`Rejected → Released` (window elapsed), emitting `ArtifactReleased { authority:
PolicyReEvaluation }`. The server log shows
`exclusion-added re-evaluation pass complete, count_reset_released: N`.

`unexclude-finding` is **asymmetric by design**: it appends `ExclusionRemoved`
and drops the exclusion projection, so the CVE blocks **future** evaluations
again — but it runs **no reverse re-evaluation**, so artifacts already
`Released` by the forward cascade **stay released** (re-rejecting a released
artifact is the "don't retroactively un-review" / rescan-amplification
concern). Do not expect a released artifact to flip back to `Rejected`.

### §11.5.5 — Read-surface validation

`--reason corruption` on the queue → `400`; `--type unknown_decision` on
decisions → client-side `valid:` hint; `--since 2026-05-32T00:00:00Z` →
client-side date rejection.

---

## §12 — Admin tasks via the worker  *(Track A+B)*

`admin task invoke` works under the svc-token's `admin_task_invoke`
permission, so all task kinds are Track A+B.

| Kind | How to invoke | Observe |
|------|---------------|---------|
| `scan` | automatic per §8 | `ScanCompleted` event |
| `cron-rescan-tick` | `hort-cli admin task invoke cron-rescan-tick` | worker iterates held artifacts |
| `advisory-watch-tick` | `hort-cli admin task invoke advisory-watch-tick` | OSV diff fetched |
| `quarantine-release-sweep` | `hort-server enqueue-quarantine-release-sweep` | quarantine release sweep |
| `prefetch-tick` | `hort-server enqueue-prefetch-tick` | per-repo upstream walk |
| `prefetch-row-retention-sweep` | `hort-server enqueue-prefetch-row-retention-sweep` | terminal prefetch rows deleted |
| `seed-import` | `hort-server seed-import --tsv path/to/seed.tsv` | bulk-register pre-vetted artifacts |
| `wheel-metadata-backfill` | `hort-server enqueue-wheel-metadata-backfill` | existing wheels get PEP 658 metadata |

**Assertion (§12.a):** each `jobs` row transitions `pending → claimed →
completed` and the worker logs the task's `info!` summary.

---

## §13 — Retention + event-chain integrity  *(Track A+B)*

```bash
# On the filesystem alpha there is no S3 WORM checkpoint anchor, so the
# verifier returns exit 3 `missing_checkpoint` — the hash chain IS intact,
# only the external-anchor attestation is absent. Pass the flag for exit 0:
./target/release/hort-server verify-event-chain --fail-on-missing-checkpoint=false
./target/release/hort-server scrub                # "checked=N mismatches=0 missing=0 read_errors=0"
```

**Assertions (§13.a):** exit codes are deterministic — `0=ok`, `2=broken`
(tamper — escalate immediately), `3=missing_checkpoint`, `1=operational
error`. The **chain integrity** check (`streams`/`rows` verified, no `broken`)
is the security property and passes on the alpha. **`missing_checkpoint`
(exit 3 by default) is EXPECTED here** — external anchoring needs S3
Object-Lock WORM + the `eventstore-checkpoint` CronJob, neither present in
the filesystem alpha; `--fail-on-missing-checkpoint=false` makes that a
clean exit 0 (CI keeps the default `true` so a real coverage gap is caught).
The scrub reports zero `mismatches`/`missing`/`read_errors` (any non-zero is
a real defect — capture and escalate). Retention sweep (`hort-cli admin task
invoke retention-purge`) is informational unless a `kind: RetentionPolicy`
is declared.

---

## §14 — Teardown + reset  *(Track A+B)*

```bash
# Stop hort-server (Ctrl-C in A) and hort-worker (Ctrl-C in B)

# Track A:
docker compose -f scripts/alpha-fixtures/compose-deps.yml down -v
# Track B (also removes Keycloak):
docker compose -f scripts/alpha-fixtures/compose-deps.yml --profile oidc down -v

rm -rf ./data/alpha
unset HORT_TOKEN ADMIN_PAT ADMIN_TOKEN DEV_TOKEN READER_TOKEN \
      HORT_DATABASE_URL HORT_REDIS_URL HORT_REDIS_URL_EVICTABLE HORT_AUTH_PROVIDER
```

---

## Triage cheatsheet

| Symptom | Likely cause |
|---------|---|
| `hort-server serve` exits `gitops validation failed: … scanBackends … <no live worker registered>` | Start `hort-worker` **before** `hort-server` (§4) so it registers `trivy`/`osv`. |
| `hort-server serve` exits `… GroupMapping object(s) are declared … HORT_AUTH_PROVIDER=disabled` | Track A is pointed at the full tree. Use `HORT_CONFIG_DIR=…/gitops-config/base` (alpha.env default), or switch to Track B (`alpha.env.oidc`). |
| `migrate` fails "previously applied but has been modified" | Stale schema — recreate the DB (§2 drift note). |
| `/metrics` returns `401` | `HORT_METRICS_REQUIRE_AUTH` not false — `source alpha.env`, or pass a bearer. |
| `503` on every artifact download | Quarantine working; release via §8.2 sweep, §11.5.2 waive, or §8.4 admin-release. |
| `404` on `/api/v1/...` for a repo you created | Restart `hort-server` after editing `$HORT_CONFIG_DIR` (startup-only). |
| OCI `crane` fails `unauthorized` / `NotOurToken` | OCI needs Track B (`$ADMIN_TOKEN`), not a svc-token PAT (§7.4). |
| Keycloak token `iss` mismatch / JWKS unreachable | `KC_HOSTNAME` and `HORT_OIDC_ISSUER_URL` must both be `http://localhost:25380/realms/hort`. |
| `hort-cli curation waive …` returns `403` | svc-token lacks `Permission::Curate` — apply the §11.5.1 grant and restart. |
| Trivy / OSV not invoked | Check `HORT_SCANNER_TRIVY_BIN` / `HORT_SCANNER_OSV_BIN`; `which trivy` / `which osv-scanner`. |

---

## What this runbook does NOT cover

- **Service-account federation** and **claim-based RBAC apply**
  beyond the bundled fixtures — see `federate-ci-oidc.md` /
  `federate-k8s-workload-identity.md`.
- **Webhooks**, **replication / mesh peering** (`scripts/mesh-e2e/`),
  **gRPC SBOM** (`scripts/native-tests/test-grpc-sbom.sh`),
  **Dependency-Track** (`scripts/native-tests/test-dependency-track.sh`).
- **Helm chart + production deployment** — see `deploy/helm/`.
