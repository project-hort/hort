# Install `hort-server` + `hort-worker` on a single Linux host

This guide takes operators from "I have a Linux host with a Postgres
instance reachable from it" to "`hort-server` is serving traffic,
`hort-worker` is processing tasks, and host cron is invoking the
scheduled jobs". It is the no-Kubernetes counterpart to
[`install.md`](install.md).

When to pick this guide over the Kubernetes install:

- **Local development on a workstation.** Iterating on `hort-server`
  itself, exercising the bring-up path without the k8s overhead.
- **Single-host evaluation / lab deployments.** Running on one
  beefy VM where the operational discipline of `systemd` + host cron
  is preferable to a one-node `kind` cluster.
- **Air-gapped / appliance deployments** where bringing in k8s
  would be disproportionate to the load.

When NOT to pick this guide:

- Production deployments that need HA, rolling upgrades, in-cluster
  TLS, or a managed-Postgres backend. Use the Kubernetes install
  ([`install.md`](install.md)) — every primitive in this guide has a
  charted equivalent.

Design rationale: the two binaries (`hort-server`, `hort-worker`) are
identical between deployment topologies; only the surrounding
plumbing changes. The minimal-setup recipe is the canonical bring-up
shape (the HTTP-Basic identity path is removed end-to-end — see
`docs/auth-catalog.md` Entry 8).

---

## 1. Prerequisites

Before you start:

- **Linux host, kernel ≥ 5.x.** Tested on Debian 12, Ubuntu 22.04+,
  Rocky / Alma 9. Anything modern enough to run `systemd` and a
  current `glibc` works.
- **`hort-server` and `hort-worker` binaries.** Either built from source
  (`cargo build --release -p hort-server -p hort-worker`) or downloaded
  from the GitHub release artifacts. Place them on `$PATH`
  (`/usr/local/bin/` is conventional).
- **PostgreSQL 14+.** Reachable from the host. Local Postgres
  (`postgresql.service` on the same host) is fine; remote Postgres
  works identically — just point the DSN at it.
- **OpenSSL ≥ 3.0** (or any tool that can produce an Ed25519 PEM —
  `ssh-keygen -t ed25519` is also acceptable). Needed for §3.
- **`curl` and `jq`** for the verification step (§9). Optional but
  recommended.
- **Shell with `cron`** OR **`systemd` ≥ 245**. Either is fine for
  task scheduling (§7); `systemd` timers give better failure
  semantics and observability via `journalctl`.

You do **not** need:

- An OIDC identity provider. This guide deliberately uses the
  no-IdP "BearerOnly" bring-up path (`HORT_AUTH_PROVIDER=disabled` +
  `HORT_NATIVE_TOKENS_ENABLED=true`).
- Container runtime. `hort-server` and `hort-worker` are native binaries.
  If you want them containerised, use the Helm chart
  ([`install.md`](install.md)) — that's its purpose.
- TLS infrastructure on the host. For workstation dev you can serve
  plain HTTP on `localhost`; for any host reachable beyond `localhost`
  you front it with a reverse proxy (§8).

### Storage caveat — same as k8s install

The filesystem storage backend documented here requires **strong
range-read integrity** on the underlying filesystem. ext4, xfs, btrfs,
and zfs all qualify. Network filesystems (NFS, SMB, S3-as-fuse) do not
— they break the CAS invariant under concurrent writes. Use a local
block device or the S3 backend (which this guide does not cover; see
[`install.md`](install.md) §3.3 for S3 setup — the env-var equivalents
are listed in [`values-reference.md`](values-reference.md)).

---

## 2. Provision the Postgres role(s)

For local-dev convenience, a single superuser-equivalent role works
fine — `hort-server` will use it for both migrations (DDL) and runtime
(DML).

```bash
sudo -u postgres createuser hort_dev --pwprompt
sudo -u postgres createdb -O hort_dev hort
```

For single-host **production** (e.g. an appliance deployment),
follow [`postgres-roles.md`](postgres-roles.md) and provision the
three roles (`hort_admin` for DDL, `hort_app_role` for runtime DML,
`hort_retention_role` for the retention sweep). The DSN convention
this guide uses (a single `HORT_DATABASE_URL`) generalises to that
shape — set a separate `HORT_RETENTION_DATABASE_URL` and supply two
DSNs in the systemd `Environment=` block in §6.

Set the connection string in the operator's shell once:

```bash
export HORT_DATABASE_URL="postgres://hort_dev:hunter2@localhost/hort"
```

You will paste this value into the systemd units in §6; export-ing
now lets you run the bring-up commands (§4, §5) without re-typing.

---

## 3. Generate the OCI token signing key

This step is **mandatory** even if you never serve OCI/Docker
artifacts. Whenever `HORT_NATIVE_TOKENS_ENABLED=true` (which is the
recipe here — without it there is no inbound auth path), the binary
boot-fails with `ConfigError::OciTokenSigningKeyMissing` unless an
Ed25519 PEM is supplied via `HORT_OCI_TOKEN_SIGNING_KEY_FILE` (or its
inline `HORT_OCI_TOKEN_SIGNING_KEY` equivalent).

```bash
sudo mkdir -p /var/lib/hort-server
sudo chown $(id -u):$(id -g) /var/lib/hort-server

openssl genpkey -algorithm Ed25519 \
    -out /var/lib/hort-server/oci-signing.pem
chmod 0600 /var/lib/hort-server/oci-signing.pem
```

If you anticipate rotating the signing key during a running
deployment, also generate a `prev` key and wire
`HORT_OCI_TOKEN_SIGNING_KEY_PREV_FILE` so JWTs minted under the
previous key still validate during the rotation window. For initial
bring-up you can skip this.

---

## 4. Apply migrations

`hort-server` deliberately does **not** apply migrations from the
`serve` path
([ADR 0009](../../../adr/0009-least-privilege-runtime-migrate-subcommand.md)
— the runtime DSN is least-privilege DML
only, refuses DDL). Run the dedicated `migrate` subcommand once at
bring-up and again on every binary upgrade.

```bash
hort-server migrate
```

Output should end with `migrations applied` and exit 0. If you split
your roles per [`postgres-roles.md`](postgres-roles.md), set
`HORT_DATABASE_URL` to the `hort_admin` DSN for this command — only the
`migrate` subcommand needs DDL.

---

## 5. Mint the operator and cron tokens

`hort-server admin issue-svc-token` is the only path to mint long-lived
service-account tokens. It is **DSN-authorised**: the command needs
operator-level Postgres access (which you have, since you're running
it locally), not a caller-principal Bearer token. No HTTP, no
authentication.

```bash
# 5.1 — workstation operator token. Used by hort-cli on your workstation
#       for `admin task invoke <kind>` and any future HTTP admin work.
hort-server admin issue-svc-token \
    --name=ops \
    --permission=admin \
    --output=stdout
# → hort_svc_<48-chars>  (paste into `hort-cli auth login --paste`)
```

If you do not yet need an operator workstation token, skip 5.1 — the
cron-job tokens below are independent.

```bash
# 5.2 — cron-job tokens. One per scheduled task. Write to mode-0600
#       files; the systemd timer's `EnvironmentFile=` reads them.

sudo mkdir -p /var/run/hort
sudo chown $(id -u):$(id -g) /var/run/hort

hort-server admin issue-svc-token \
    --name=cron-staging-sweep \
    --permission=admin_task_invoke \
    --output=file:/var/run/hort/staging-sweep-token

hort-server admin issue-svc-token \
    --name=cron-rescan \
    --permission=admin_task_invoke \
    --output=file:/var/run/hort/rescan-token

hort-server admin issue-svc-token \
    --name=cron-advisory-watch \
    --permission=admin_task_invoke \
    --output=file:/var/run/hort/advisory-watch-token

hort-server admin issue-svc-token \
    --name=cron-eventstore-archive \
    --permission=admin_task_invoke \
    --output=file:/var/run/hort/eventstore-archive-token
```

The command is **idempotent**: re-running with the same `--name`
exits 0 without changing the token. Force re-issue (e.g. on
suspected compromise) with `--rotate` — this revokes the existing
token and writes a fresh value.

Token-cap permission notes:

- `admin_task_invoke` is the right cap for cron-job tokens. It gates
  `POST /api/v1/admin/tasks/:kind` and nothing else.
- `admin` would over-grant. Only use it on the workstation operator
  token in 5.1 if you need HTTP admin endpoints (token-mint, user
  management, gitops apply).
- For cron-job tokens to actually authorise the task they invoke,
  the matching `PermissionGrant` row must also exist for the SA's
  user. See §7.3.

---

## 6. systemd units for the daemons

`hort-server` is the HTTP service; `hort-worker` is the task runner.
They communicate only through Postgres (the `jobs` table). Both need
the same DSN and the same storage path; only `hort-server` needs the
OCI signing key and the public base URL.

### 6.1 `hort-server.service`

```ini
# /etc/systemd/system/hort-server.service
[Unit]
Description=Hort HTTP service
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=hort-svc
Group=hort-svc

# Database
Environment=HORT_DATABASE_URL=postgres://hort_dev:hunter2@localhost/hort

# Storage backend (filesystem). Path must be writable and 0o700-chmod-able
# by the runtime UID (fail-loud boot check).
Environment=HORT_STORAGE_BACKEND=filesystem
Environment=HORT_STORAGE_FILESYSTEM_PATH=/var/lib/hort-server/storage

# Public-facing URL embedded in OCI tokens' `iss` claim and the
# discovery doc. For laptop-only dev this can be `http://localhost:8080`;
# for any host reachable beyond localhost, set the real URL and TLS-
# terminate at the reverse proxy (§8).
Environment=HORT_PUBLIC_BASE_URL=http://localhost:8080
Environment=HORT_REQUIRE_HTTPS=false

# Auth surface: no IdP wired; native tokens are the only inbound path.
Environment=HORT_AUTH_PROVIDER=disabled
Environment=HORT_NATIVE_TOKENS_ENABLED=true
Environment=HORT_OCI_TOKEN_SIGNING_KEY_FILE=/var/lib/hort-server/oci-signing.pem

# Gitops config dir (§7.3). Optional but recommended — without it the
# PermissionGrant rows for the cron-job SAs must be inserted manually.
Environment=HORT_CONFIG_DIR=/etc/hort-server/config

ExecStart=/usr/local/bin/hort-server
Restart=on-failure
RestartSec=5s

# Hardening — these match the chart's PodSecurityContext defaults.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/hort-server /var/run/hort

[Install]
WantedBy=multi-user.target
```

### 6.2 `hort-worker.service`

```ini
# /etc/systemd/system/hort-worker.service
[Unit]
Description=Hort task worker
After=network-online.target postgresql.service hort-server.service
Wants=network-online.target

[Service]
Type=simple
User=hort-svc
Group=hort-svc

Environment=HORT_DATABASE_URL=postgres://hort_dev:hunter2@localhost/hort

# Worker reads SBOMs / writes scan blobs via the storage backend. Same
# path as the server — they share the filesystem CAS.
Environment=HORT_STORAGE_BACKEND=filesystem
Environment=HORT_STORAGE_FILESYSTEM_PATH=/var/lib/hort-server/storage

ExecStart=/usr/local/bin/hort-worker
Restart=on-failure
RestartSec=5s

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/hort-server

[Install]
WantedBy=multi-user.target
```

### 6.3 Start them

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin hort-svc
sudo chown -R hort-svc:hort-svc /var/lib/hort-server /var/run/hort

sudo systemctl daemon-reload
sudo systemctl enable --now hort-server.service hort-worker.service
sudo systemctl status hort-server.service hort-worker.service
```

Both units should show `active (running)`. If `hort-server` fails to
start, `journalctl -u hort-server.service -b` will show the
`ConfigError` chain — most common is `OciTokenSigningKeyMissing`
(skipped §3) or `StorageFilesystemPathMissing` (forgot
`HORT_STORAGE_FILESYSTEM_PATH`).

---

## 7. Schedule the cron tasks

`hort-worker` does **not** schedule its own tasks (there is
deliberately no internal scheduler). An external scheduler — host cron
or systemd timers — calls `POST /api/v1/admin/tasks/:kind` with the
matching cron-job SA token. `hort-server` enqueues a row in the `jobs`
table; `hort-worker` picks it up and runs it.

### 7.1 systemd timers (recommended — better failure semantics)

One `.service` + one `.timer` per scheduled task.

```ini
# /etc/systemd/system/hort-task-rescan.service
[Unit]
Description=Hort rescan sweep
After=hort-server.service
Requires=hort-server.service

[Service]
Type=oneshot
User=hort-svc
EnvironmentFile=/var/run/hort/rescan-token.env
ExecStart=/usr/bin/curl -sf \
    -H "Authorization: Bearer ${TOKEN}" \
    -X POST http://localhost:8080/api/v1/admin/tasks/cron-rescan
```

```ini
# /etc/systemd/system/hort-task-rescan.timer
[Unit]
Description=Nightly rescan at 02:00

[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

Convert the bare token file written in §5.2 into an `EnvironmentFile`
shape (`TOKEN=hort_svc_...`):

```bash
for name in staging-sweep rescan advisory-watch eventstore-archive; do
    echo "TOKEN=$(cat /var/run/hort/${name}-token)" \
        | sudo tee /var/run/hort/${name}-token.env > /dev/null
    sudo chmod 0640 /var/run/hort/${name}-token.env
    sudo chown root:hort-svc /var/run/hort/${name}-token.env
    sudo rm /var/run/hort/${name}-token  # remove the bare-token file
done
```

Repeat the `.service` + `.timer` pattern above for each task. The
canonical cadence (matches the Helm chart's CronJob defaults — see
[`values-reference.md`](values-reference.md) `worker.cronjobs.*`):

| Task | Schedule | Notes |
|------|----------|-------|
| `staging-sweep` | `*:0/15` (every 15 minutes) | Cleans abandoned stateful-upload sessions |
| `cron-rescan` | `*-*-* 02:00:00` (nightly) | Re-scans artifacts against current advisory DB |
| `advisory-watch` | `*-*-* 03:00:00` (nightly) | Pulls fresh advisory feed |
| `eventstore-archive` | `Sun *-*-* 04:00:00` (weekly) | Eventstore retention sweep — runs `seal_and_remove` under the per-day idempotency key |

Enable:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now \
    hort-task-staging-sweep.timer \
    hort-task-rescan.timer \
    hort-task-advisory-watch.timer \
    hort-task-eventstore-archive.timer
sudo systemctl list-timers --all
```

### 7.2 Host cron (simpler, less observable)

`/etc/cron.d/hort-tasks`:

```cron
# Run as hort-svc; environment-load the per-task token before curl.
*/15 * * * * hort-svc TOKEN=$(cat /var/run/hort/staging-sweep-token)      curl -sf -H "Authorization: Bearer $TOKEN" -X POST http://localhost:8080/api/v1/admin/tasks/staging-sweep
0    2 * * * hort-svc TOKEN=$(cat /var/run/hort/rescan-token)             curl -sf -H "Authorization: Bearer $TOKEN" -X POST http://localhost:8080/api/v1/admin/tasks/cron-rescan
0    3 * * * hort-svc TOKEN=$(cat /var/run/hort/advisory-watch-token)     curl -sf -H "Authorization: Bearer $TOKEN" -X POST http://localhost:8080/api/v1/admin/tasks/advisory-watch
0    4 * * 0 hort-svc TOKEN=$(cat /var/run/hort/eventstore-archive-token) curl -sf -H "Authorization: Bearer $TOKEN" -X POST http://localhost:8080/api/v1/admin/tasks/eventstore-archive
```

Failures go to the local mailer (or wherever cron mail is routed).
For production use prefer §7.1 — systemd timers' `OnFailure=` hooks
let you alert on a failed invocation without parsing mail.

### 7.3 PermissionGrant rows for the cron tokens

Each cron-job SA token's HTTP authority is the **intersection** of
its declared-permissions cap (set at issuance — `admin_task_invoke`)
and the user-leg's `PermissionGrant` rows for `subject = User(sa.id)`.
Without a matching grant, the task invocation 403s even with the
correct token.

The chart's gitops layer ships these via `$HORT_CONFIG_DIR/grants/`.
Locally, do the same:

```bash
sudo mkdir -p /etc/hort-server/config/grants
```

```yaml
# /etc/hort-server/config/grants/cron-rescan.yaml
apiVersion: project-hort.de/v1beta1
kind: PermissionGrant
metadata:
  name: cron-rescan-can-invoke
spec:
  subject:
    kind: User
    username: hort-svc-cron-rescan      # resolved by the apply use case
  permission: admin_task_invoke
  scope: global
```

Repeat for each cron-job SA. The `username` field follows the
`hort-svc-<name>` convention enforced by `admin issue-svc-token`
([§5.2](#5-mint-the-operator-and-cron-tokens)).

`hort-server` applies the directory on startup; restart the service
to pick up new files:

```bash
sudo systemctl restart hort-server.service
```

`PermissionGrantLintConfig` exists if you want to
opt out of the strict-author claim-mapping requirement — see
[`../operate/claim-based-rbac.md`](../operate/claim-based-rbac.md)
for the syntax. For local-dev convenience the default is fine.

---

## 8. Wire the edge (only if reachable beyond `localhost`)

If `hort-server` is only ever reached from `localhost` (laptop dev),
skip this section.

For any host reachable on a LAN or the public internet, terminate
TLS at a reverse proxy and tell `hort-server` to trust that proxy's
`X-Forwarded-*` headers. Three example shapes:

### 8.1 Caddy

```caddy
# /etc/caddy/Caddyfile
hort.internal.example {
    reverse_proxy localhost:8080 {
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto https
    }
}
```

Update `hort-server.service`:

```
Environment=HORT_REQUIRE_HTTPS=true
Environment=HORT_PUBLIC_BASE_URL=https://hort.internal.example
Environment=HORT_TRUSTED_PROXY_CIDRS=127.0.0.1/32
```

**Critical security note**: `HORT_TRUSTED_PROXY_CIDRS` must be the
**precise** CIDR of the proxy peer, not a permissive range. Trusting
a broad CIDR lets any host in that range forge `client_ip` via
`X-Forwarded-For` past rate-limit / fail2ban / audit attribution
(see [`security-hardening-checklist.md`](security-hardening-checklist.md)
M-A3). Co-locating Caddy and `hort-server` on the same host makes
`127.0.0.1/32` the right answer; if you ever move the proxy to a
separate host, narrow this to that host's IP.

### 8.2 nginx + cert-manager-style ACME

Same shape; see [`install.md`](install.md) §6 for the
nginx-specific config. The chart's
`deploy/helm/hort-server/examples/ingress-nginx-cert-manager/` is the
authoritative example — adapt the annotations/values to the host
nginx.

### 8.3 No edge — direct exposure (NOT recommended)

If you must expose `hort-server`'s plain-HTTP listener directly
(workstation dev only), at minimum bind it to a specific interface
rather than `0.0.0.0`:

```
Environment=HORT_API_BIND=127.0.0.1:8080
```

This is workstation-dev-only — never expose plain-HTTP `hort-server`
on a LAN where untrusted clients can reach it.

---

## 9. Verify

Six commands from a fresh deploy to confirm the stack is live.

### 9.1 Server health

```bash
curl -sf http://localhost:8080/healthz
# → 200 OK
```

### 9.2 Server version

```bash
curl -sf http://localhost:8080/version | jq .
# → {"version":"2.0.0-rc.23",...}
```

### 9.3 Worker health (via the worker's healthcheck binary)

```bash
hort-worker healthcheck
# Exit code 0 + a one-line confirmation. Non-zero exit + a stderr
# error means the worker's env / DB / storage path are wrong.
```

### 9.4 Token-protected endpoint round-trip

Use the workstation operator token from §5.1 (or one of the cron
tokens if you skipped 5.1):

```bash
TOKEN=hort_svc_...   # paste

curl -sf -H "Authorization: Bearer $TOKEN" \
    http://localhost:8080/api/v1/auth/whoami | jq .
# → {"user_id":"...","username":"hort-svc-ops","claims":["admin"],...}
```

If this returns 401 with `WWW-Authenticate: Bearer realm="..."`, the
token is invalid (bad paste? expired? wrong server?). If it returns
403, the token authenticated but doesn't have the permission the
endpoint requires — re-check the token's `--permission` cap and the
`PermissionGrant` row.

### 9.5 Schedule pulse

```bash
sudo systemctl list-timers hort-task-*.timer
# Should show four timers with NEXT firing times in the future.
```

### 9.6 Manual task invocation

Test the full path before waiting for the timer:

```bash
TOKEN=$(cat /var/run/hort/rescan-token.env | cut -d= -f2)
curl -sf -H "Authorization: Bearer $TOKEN" \
    -X POST http://localhost:8080/api/v1/admin/tasks/cron-rescan
# → 202 Accepted (or 200 with the enqueued job id)

# Check the job got picked up by hort-worker:
psql "$HORT_DATABASE_URL" \
    -c "SELECT kind, status, locked_until FROM jobs ORDER BY created_at DESC LIMIT 5;"
# → Most recent row's status transitions from 'queued' → 'running' → 'completed'
```

If the job stays at `'queued'`, `hort-worker` is not picking it up —
check `journalctl -u hort-worker.service` for poll-loop errors.

---

## 10. Publishing artifacts from a CI pipeline

The cron-job pattern in §7 covers tokens for internal admin tasks. A
different shape applies when a CI pipeline (GitHub Actions, GitLab CI,
Jenkins, Drone, Buildkite, …) needs to **publish artifacts** — npm
packages, Python wheels, Maven JARs, Cargo crates, Docker images,
Helm charts, etc. — to your `hort-server`. The recipe is similar but
the permissions, scope, consumer plumbing, and rotation cadence
differ.

This section assumes you've already wired the edge (§8) so the CI
runner can reach `hort-server` over TLS. If the runner is on the same
host (workstation dev), `http://localhost:8080` works without edge.

### 10.1 Mint the publishing token

The pipeline needs `Permission::Write` against the target
repository. Mint via the same `admin issue-svc-token` CLI used for
cron tokens, but with a different cap and a shorter expiry:

```bash
hort-server admin issue-svc-token \
    --name=ci-publish-internal-libs \
    --permission=write \
    --expires-in-days=90 \
    --output=stdout
# → hort_svc_<48-chars>
```

Naming + scoping choices:

- **`--name`** identifies the SA in audit events and provisions the
  backing user `hort-svc-<name>`. Use a descriptive name that names
  the consumer (`ci-publish-<thing>`, `gh-actions-<repo>`,
  `gitlab-<group>-<project>`). One SA per pipeline gives clean
  audit attribution; avoid sharing one SA across pipelines unless
  they truly share the same authority scope.
- **`--permission=write`** is the right cap for publishing. The
  `write` permission alone authorises artifact upload — `admin`
  would over-grant, and other caps like `admin_task_invoke` don't
  authorise publish at all.
- **`--expires-in-days=90`** is a sensible cadence. The 365-day max
  is reasonable for cron tokens (which only daemons hold) but
  excessive for CI tokens (which travel through more systems, log
  files, secret stores). Shorter rotation cadence is operationally
  cheap because CI secret stores absorb rotation well.

The `admin issue-svc-token` CLI does **not** carry a
`--repository-ids` flag — the token's declared-permissions cap is
"global write". To narrow the effective authority to a specific
repository, use the user-leg's `PermissionGrant` rows (§10.2) — the
intersection of (global write cap) ∩ (per-repo grant) = (write to
that specific repo). This is the architecturally cleaner shape than
per-repo token caps; the grant lives in the audited apply path
(see [`../operate/claim-based-rbac.md`](../operate/claim-based-rbac.md)).

### 10.2 Scope the SA via `PermissionGrant`

Each publishing SA needs a `PermissionGrant` row that limits its
effective authority to the repositories it should publish to. Same
shape as the cron-task grants (§7.3), different `permission` and
`scope`:

```yaml
# /etc/hort-server/config/grants/ci-publish-internal-libs.yaml
apiVersion: project-hort.de/v1beta1
kind: PermissionGrant
metadata:
  name: ci-publish-internal-libs-can-write-libs
spec:
  subject:
    kind: User
    username: hort-svc-ci-publish-internal-libs
  permission: write
  scope:
    repository_id: <uuid-of-internal-libs-repo>
```

Multiple grants stack — to allow the pipeline to publish to N
repositories, add N grants. `scope: global` is rare for publishing
SAs and worth a second look in review.

Resolve the repository UUID once:

```bash
psql "$HORT_DATABASE_URL" \
    -c "SELECT id, key, format FROM repositories ORDER BY key;"
```

Restart `hort-server` to load the new grant (the gitops apply runs at
boot):

```bash
sudo systemctl restart hort-server.service
```

`PermissionGrantLintConfig` exists if you want to
opt out of the strict-author claim-mapping requirement — for CI
publishing tokens, you almost always want the default linter on
(the audit trail is what you're paying for).

### 10.3 Per-format client recipes

The token plaintext (`hort_svc_…`) is the same for every format; only
the transport differs. All recipes assume the token is in
`$HORT_PUBLISH_TOKEN`.

#### npm

```ini
# .npmrc (per-project or ~/.npmrc)
@your-scope:registry=https://hort.internal.example/npm/internal-libs/
//hort.internal.example/npm/internal-libs/:_authToken=${HORT_PUBLISH_TOKEN}
```

```bash
npm publish
```

#### PyPI / `twine`

The `__token__` username is a carrier sentinel; the password field
carries the actual token.

```bash
twine upload \
    --repository-url https://hort.internal.example/pypi/internal-libs/ \
    --username __token__ \
    --password "${HORT_PUBLISH_TOKEN}" \
    dist/*
```

Or via `~/.pypirc`:

```ini
[distutils]
index-servers = hort-internal

[hort-internal]
repository = https://hort.internal.example/pypi/internal-libs/
username = __token__
password = ${HORT_PUBLISH_TOKEN}
```

#### Cargo

```bash
# ~/.cargo/credentials.toml — or CARGO_REGISTRIES_HORT_TOKEN env var.
[registries.hort-internal]
token = "Bearer ${HORT_PUBLISH_TOKEN}"
```

```toml
# .cargo/config.toml
[registries.hort-internal]
index = "sparse+https://hort.internal.example/cargo/internal-libs/"
```

```bash
cargo publish --registry hort-internal
```

#### Maven

```xml
<!-- ~/.m2/settings.xml -->
<servers>
  <server>
    <id>hort-internal</id>
    <username>__token__</username>
    <password>${env.HORT_PUBLISH_TOKEN}</password>
  </server>
</servers>
```

```xml
<!-- pom.xml -->
<distributionManagement>
  <repository>
    <id>hort-internal</id>
    <url>https://hort.internal.example/maven/internal-libs/</url>
  </repository>
</distributionManagement>
```

```bash
mvn deploy
```

#### Docker / OCI

```bash
echo "${HORT_PUBLISH_TOKEN}" \
    | docker login hort.internal.example -u __token__ --password-stdin

docker tag myapp:latest hort.internal.example/internal/myapp:1.0.0
docker push hort.internal.example/internal/myapp:1.0.0
```

For OCI Helm chart pushes (same auth path, different CLI):

```bash
echo "${HORT_PUBLISH_TOKEN}" \
    | helm registry login hort.internal.example -u __token__ --password-stdin
helm push mychart-1.0.0.tgz oci://hort.internal.example/charts/internal-libs
```

#### Helm classic (chartmuseum-style)

```bash
helm repo add hort-internal https://hort.internal.example/helm/internal-libs/ \
    --username __token__ --password "${HORT_PUBLISH_TOKEN}"
helm cm-push mychart-1.0.0.tgz hort-internal
```

#### RubyGems / NuGet / Composer / Go modules / Conda / Hex / Pub / Alpine / Debian / RPM

Same Basic-as-token-carrier pattern — the per-format client tool
documents its credentials file shape. The username is either
`__token__` (the carrier sentinel) or any value (clients that ignore
the username field); the password is the SA token plaintext. See
[`docs/auth-catalog.md`](../../../auth-catalog.md) Entry 8 for the
canonical statement of the carrier-only contract.

### 10.4 CI system integration

Different CI systems have different secret-store conventions. The
constraint is constant: the token plaintext must never appear in
git, shell history, container labels, or unmasked job logs.

#### GitHub Actions

Add as a repository or organisation secret named `HORT_PUBLISH_TOKEN`:

```yaml
jobs:
  publish:
    runs-on: ubuntu-latest
    env:
      HORT_PUBLISH_TOKEN: ${{ secrets.HORT_PUBLISH_TOKEN }}
    steps:
      - uses: actions/checkout@v4
      - name: Publish to hort-server
        run: |
          echo "//hort.internal.example/npm/internal-libs/:_authToken=${HORT_PUBLISH_TOKEN}" >> ~/.npmrc
          npm publish
```

For organisations: scope the secret to the publishing repositories
only (not org-wide) so a compromise of one repository's runner
doesn't leak the token to unrelated repos.

#### GitLab CI

Add as a **masked**, **protected** project / group variable named
`HORT_PUBLISH_TOKEN`. Masking hides the value from job logs;
protected limits it to protected branches/tags:

```yaml
publish:
  stage: deploy
  only:
    - tags
  script:
    - echo "${HORT_PUBLISH_TOKEN}" | docker login hort.internal.example -u __token__ --password-stdin
    - docker push "${CI_REGISTRY_IMAGE}:${CI_COMMIT_TAG}"
```

#### Jenkins

Use the Credentials Plugin to store as **Secret Text** named
`hort-publish-token`:

```groovy
pipeline {
  agent any
  environment {
    HORT_PUBLISH_TOKEN = credentials('hort-publish-token')
  }
  stages {
    stage('Publish') {
      steps {
        sh '''
          echo "//hort.internal.example/npm/internal-libs/:_authToken=${HORT_PUBLISH_TOKEN}" >> ~/.npmrc
          npm publish
        '''
      }
    }
  }
}
```

The `credentials('…')` binding automatically marks the value for
log-redaction.

#### Drone / Buildkite / Tekton / generic

Set `HORT_PUBLISH_TOKEN` in the build environment via whatever
secret-store mechanism the CI provides (Drone `secrets`, Buildkite
`agent secrets`, Tekton `Secret` mounted as env). The same
hygiene applies: masked in logs, never committed.

### 10.5 Rotation

CI tokens rotate more often than cron tokens. Recommend ≤ 90-day
cadence + on-demand rotation if a leak is suspected. The mechanics
are mechanical:

```bash
# 1. Mint a new token under the same name. --rotate revokes the old
#    one and writes a fresh value.
hort-server admin issue-svc-token \
    --name=ci-publish-internal-libs \
    --permission=write \
    --expires-in-days=90 \
    --rotate \
    --output=stdout
# → hort_svc_<new>

# 2. Update the CI secret store with the new value (GitHub / GitLab /
#    Jenkins / …). Pipeline runs that already started will fail at the
#    next publish step (their cached token is now revoked); new runs
#    pick up the new token from the secret store.
```

For **zero-downtime rotation**, the SA-token model does not have a
prev-key window (unlike the OCI signing key §11.3). The discipline:
mint the new token, push to the CI secret store, run a no-op
smoke pipeline to confirm the new token works, **then** revoke the
old via `--rotate`. (The `--rotate` flag does the revoke atomically,
so a fully zero-downtime rotation needs you to mint without
`--rotate` first, smoke, then revoke the old explicitly via
`DELETE /api/v1/admin/tokens/:id` — which needs an admin token; the
single-step `--rotate` is acceptable for most CI cadences.)

### 10.6 Audit and verification

Every artifact publish emits an `ArtifactIngested` event attributed
to the SA's `Actor::Api { user_id }`. The audit trail:

```bash
psql "$HORT_DATABASE_URL" -c "
  SELECT
    e.created_at,
    e.event_type,
    e.payload->>'repository_key' AS repo,
    e.payload->>'content_hash' AS hash,
    u.username AS actor
  FROM events e
  LEFT JOIN users u
    ON (e.payload->'actor'->>'user_id')::uuid = u.id
  WHERE e.event_type = 'ArtifactIngested'
  ORDER BY e.created_at DESC
  LIMIT 20;
"
```

Before debugging a publish failure, verify the token's effective
authority:

```bash
curl -sf -H "Authorization: Bearer ${HORT_PUBLISH_TOKEN}" \
    http://localhost:8080/api/v1/auth/whoami | jq '{
        username,
        claims,
        token_kind,
        token_cap
    }'
# {
#   "username": "hort-svc-ci-publish-internal-libs",
#   "claims": [],                       ← SA tokens carry no synthetic claims
#                                         (long-lived static tokens are
#                                         under-privileged for
#                                         claim-based RBAC)
#   "token_kind": "service_account",
#   "token_cap": {"permissions": ["write"], "repository_ids": null}
# }
```

- **401** → token is invalid (paste error, revoked, expired, wrong
  server URL).
- **200 with the right username + cap** → authentication works, but
  this does NOT confirm the publish will succeed. The publish
  endpoint also enforces the user-leg `PermissionGrant` (§10.2).
  Test that:

```bash
# Test write authority on the target repo. If this 403s, the
# PermissionGrant is missing or scoped to the wrong repository_id.
curl -sf -H "Authorization: Bearer ${HORT_PUBLISH_TOKEN}" \
    http://localhost:8080/api/v1/repositories/internal-libs | jq .
```

### 10.7 What NOT to do

A short list, all corresponding to either anti-pattern bullets in
[`docs/auth-catalog.md`](../../../auth-catalog.md) or to the
architect-skill review-only rules:

- **Don't reuse the workstation operator token (§5.1) for CI.** That
  token has `admin` cap — a CI compromise gives admin authority on
  the whole instance. Mint per-pipeline `write`-capped tokens.
- **Don't share one token across multiple pipelines.** Cheap to mint
  one per pipeline; audit attribution is then per-consumer.
- **Don't put the token in `Authorization: Bearer` headers logged
  by an outbound HTTP debug helper.** Most clients log the
  *request line* but not the *Authorization header*; verify your
  client's logging discipline before scaling out.
- **Don't grant `Permission::Admin` to a publishing SA.** Write is
  what you need. The admin cap unlocks token-mint, user-management,
  and gitops-apply endpoints which a publishing pipeline has no use
  for.
- **Don't store the token plaintext in container image layers** (build
  args / `LABEL` fields are baked in and shipped). Use the CI's
  secret-injection mechanism so the token only appears in the
  ephemeral build environment.
- **Don't synthesise an `admin` permission grant for the SA "just in
  case"** — the claim-based RBAC invariants forbid it
  ([ADR 0012](../../../adr/0012-claim-based-rbac-claimless-static-tokens.md)).
  The only synthetic
  `admin` claim is the one derived from `user.is_admin=true`, and SA
  users provisioned by `admin issue-svc-token --permission=write`
  do not get that bit.

---

## 11. Maintenance

### 11.1 Token rotation

Cron-job tokens default to 365 days. Rotate before expiry:

```bash
# Rotate the rescan token (issues a fresh one, revokes the old):
hort-server admin issue-svc-token \
    --name=cron-rescan \
    --permission=admin_task_invoke \
    --output=file:/var/run/hort/rescan-token \
    --rotate

# Re-derive the EnvironmentFile shape:
echo "TOKEN=$(cat /var/run/hort/rescan-token)" \
    | sudo tee /var/run/hort/rescan-token.env > /dev/null

# Restart the matching timer's service so the next invocation picks
# up the new value (timers re-read the EnvironmentFile per-invocation,
# so this is only needed if you want to confirm the file is well-formed):
sudo systemctl daemon-reload
```

Workstation operator tokens are paste-tokens, so rotation is:
re-mint, paste into `hort-cli auth login --paste` on the workstation,
discard the old value. The old token is invalidated server-side as
soon as `--rotate` runs.

### 11.2 Binary upgrade

```bash
# 1. Stop the daemons.
sudo systemctl stop hort-server.service hort-worker.service

# 2. Install the new binaries (`/usr/local/bin/hort-server`,
#    `/usr/local/bin/hort-worker`).

# 3. Apply migrations for the new version. The runtime DSN won't
#    accept DDL; this needs admin-DSN access (one role for local
#    dev; the `hort_admin` role in production).
hort-server migrate

# 4. Restart.
sudo systemctl start hort-server.service hort-worker.service
sudo systemctl status hort-server.service hort-worker.service
```

The `serve` path checks the schema version on startup via
`migrate::assert_current` and refuses to start against a stale
schema ([ADR 0009](../../../adr/0009-least-privilege-runtime-migrate-subcommand.md)).
So if you forget step 3, the server boot-fails
loudly rather than silently running on a mismatched schema.

### 11.3 OCI signing key rotation

In-flight tokens minted under the old key must still validate during
the rotation window. Wire the previous key alongside the new one:

```bash
# 1. Generate the new key.
openssl genpkey -algorithm Ed25519 \
    -out /var/lib/hort-server/oci-signing-new.pem
chmod 0600 /var/lib/hort-server/oci-signing-new.pem

# 2. Update hort-server.service to point at both keys.
#    HORT_OCI_TOKEN_SIGNING_KEY_FILE → the new key.
#    HORT_OCI_TOKEN_SIGNING_KEY_PREV_FILE → the OLD key (served from
#                                         the JWKS during the window).

# 3. Restart. New tokens are minted under the new key; old tokens
#    still validate against the prev key in the JWKS.
sudo systemctl restart hort-server.service

# 4. After the longest-lived old token expires (default 1 hour for
#    OCI JWTs; longer for cli sessions if you wired token-exchange),
#    drop the HORT_OCI_TOKEN_SIGNING_KEY_PREV_FILE line + restart.
```

### 11.4 Postgres maintenance

Standard `pg_dump` / `pg_basebackup` for backup. The `events` table
is append-only and dominates storage in long-running deployments;
the `eventstore-archive` task (§7.1) is what keeps it bounded.
Operators in production should monitor `pg_total_relation_size('events')`
and tune the archive retention if the table grows faster than
expected — see
[`../../reference/event-taxonomy.md`](../../reference/event-taxonomy.md)
and [ADR 0020](../../../adr/0020-single-flight-seal-pool-backstop.md)
for the retention contract.

---

## 12. Common failure modes

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `hort-server.service` fails to start with `ConfigError::OciTokenSigningKeyMissing` | §3 skipped or `HORT_OCI_TOKEN_SIGNING_KEY_FILE` points at a nonexistent path | Run §3; verify path with `ls -la $HORT_OCI_TOKEN_SIGNING_KEY_FILE` |
| `ConfigError::AuthDisabled` at boot | `HORT_AUTH_PROVIDER=disabled` set but `HORT_NATIVE_TOKENS_ENABLED` is unset / false | Set `HORT_NATIVE_TOKENS_ENABLED=true` (no inbound auth path otherwise) |
| Tasks queued but never run | `hort-worker.service` not running, or worker can't reach the same DB / storage | `systemctl status hort-worker.service`; `journalctl -u hort-worker.service -b` |
| Task invocation returns 403 | Token cap is correct but no `PermissionGrant` row | §7.3 — add the YAML, restart `hort-server` |
| Task invocation returns 401 with `WWW-Authenticate: Bearer realm="hort", Basic realm="hort"` | Token revoked / expired / mistyped | Mint a fresh token with `--rotate`; verify with §9.4 first |
| `npm publish` / `twine upload` / `docker push` returns 401 | Token plaintext is wrong (CI secret stale after a recent `--rotate`) | Re-mint with `--rotate`, push fresh value to CI secret store, re-run the pipeline; verify with `curl …/api/v1/auth/whoami` per §10.6 |
| `npm publish` / `twine upload` / `docker push` returns 403 | Token authenticated but `PermissionGrant` is missing or scoped to the wrong `repository_id` | §10.2 — add or fix the YAML, restart `hort-server`; verify with `curl …/api/v1/repositories/<name>` per §10.6 |
| Publish works locally but fails from CI runner with `connection refused` / TLS handshake errors | `hort-server` is only reachable on `localhost` (edge wiring §8 not done) or the runner doesn't trust the proxy's TLS cert | Wire the edge per §8; for self-signed certs in dev, distribute the issuing CA via the runner's trust store (do NOT use `*_INSECURE_TLS` knobs — none exist, by design; see [ADR 0010](../../../adr/0010-tls-builder-no-insecure-knobs.md)) |
| `hort-server admin issue-svc-token` fails with `connection refused` | `HORT_DATABASE_URL` points at a Postgres that isn't running, or the network blocks the port | Test with `psql $HORT_DATABASE_URL -c 'SELECT 1'` |
| Boot-fail with `ConfigError::Validation { kind: "STAGING_DIR" }` | Fail-loud boot check — staging dir isn't writable / not 0o700-chmod-able by the runtime UID | `chown hort-svc:hort-svc /var/lib/hort-server` (or whatever runs the service) |
| `cargo audit --deny warnings` red after `cargo update` on a self-built binary | A newly-published advisory matches a pinned crate — RustSec DB updates continuously | `cargo update -p <crate> --precise <fixed-version>` per the repository's Pre-push Quality Checklist (`CLAUDE.md`) |

---

## 13. Migrating to Kubernetes

When the deployment outgrows the single-host shape — HA needed,
multiple workers, managed Postgres, ingress with cert-manager — the
migration path is roughly:

1. **Snapshot Postgres.** `pg_dump` of `hort`.
2. **Snapshot the storage directory.** `rsync` `/var/lib/hort-server/storage/`
   to the destination (or migrate to S3 — see [`install.md`](install.md) §3.3).
3. **Move the OCI signing key into a k8s Secret.** `kubectl create secret generic`
   with the PEM as the data — chart consumes it via `signingKey.existingSecret`.
4. **Helm install per [`install.md`](install.md) §5.1 or §5.2.**
   Re-run `admin issue-svc-token` for the cron-job tokens against the
   new in-cluster DB — the same SA usernames preserve the
   `PermissionGrant` rows (which migrated with the `pg_dump`).
5. **Cutover.** Stop the systemd units, restore the snapshots,
   `helm install`, verify per §9. The two-binary processes are
   identical; only the surrounding plumbing changes.

The local-bringup shape is forward-compatible with the k8s
deployment shape — no schema migration, no API contract change, no
data transformation.

---

## See also

- [`install.md`](install.md) — Kubernetes install guide.
- [`postgres-roles.md`](postgres-roles.md) — three-role Postgres
  recipe (use for single-host production; this guide uses one role
  for local-dev convenience).
- [`values-reference.md`](values-reference.md) — full env-var
  catalog. Chart values map 1:1 to env vars; this guide names a
  subset; the reference is authoritative for the rest.
- [`security-hardening-checklist.md`](security-hardening-checklist.md) —
  required reading before exposing `hort-server` beyond `localhost`.
- [`extra-ca-bundle.md`](extra-ca-bundle.md) — operator-supplied CA
  bundle for trusting internal certs on the upstream / OIDC / S3
  paths.
- [`docs/auth-catalog.md`](../../../auth-catalog.md) Entry 8 — the
  canonical statement of the "Basic is a token-carrier only, never
  an identity source" contract that the §10.3 per-format recipes
  rely on (the `__token__` username sentinel and the password-field
  token-carrier convention); also the rationale for the no-IdP
  "BearerOnly" recipe this guide uses.
- [`../operate/claim-based-rbac.md`](../operate/claim-based-rbac.md) —
  the `PermissionGrant` apply path + the SA-token authority model
  (`subject = User(sa.id)` grants are the architecturally
  correct way to scope SA authority, not per-token caps).
