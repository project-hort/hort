# Using hort-cli for admin operations

This guide is for operators who hold admin authority on an hort
deployment and need to invoke admin commands (e.g. `hort-cli admin task
invoke`, service-account-token issuance, policy edits) from the command
line. It covers the `hort-cli auth login --admin` flow, the
`HORT_TOKEN_ALLOW_ADMIN` deployment gate, the ≤15 min admin-session lifetime
invariant, and what the operator-facing error messages mean.

For the design rationale see
[ADR 0013 — IdP-authoritative CLI sessions](../../adr/0013-idp-authoritative-cli-sessions.md).

---

## 1. The shape of an admin CLI session

CLI sessions originally carried `[Read, Write, Delete]` for 30
days under a hard "a CLI session never carries admin" invariant. Admin
operations had to be invoked via a hand-curled PAT against
`/api/v1/users/me/tokens` — a long-lived credential on a laptop with
worse ergonomics than the documented flow. The current design retires
the "admin-forbidden" half of that invariant by **shortening the
lifetime**: admin-cap CliSession tokens are now allowed, bounded to ≤15 min
by `clamp_lifetime`. The blast radius of a stolen 15 min admin token is
small enough that the trade-off has flipped versus a 30 d non-admin one.

The new defaults:

| Cap | Default lifetime | Max lifetime |
|---|---|---|
| `read`, `write`, `delete` | 15 min | 15 min |
| Includes `admin` | 15 min | 15 min |

Below 5 min (300 s) is rejected with `invalid_request`; above the
per-cap max is clamped silently and hort-cli surfaces a `note:` line.

---

## 2. The flow

### Prerequisites

1. The server is started with `HORT_TOKEN_ALLOW_ADMIN=true`. Without
   this flag the exchange handler returns `400 invalid_request` /
   `"admin tokens disabled by composition-root config"` and hort-cli
   surfaces the message verbatim.
2. Your IdP user holds the `admin` role (resolved through `kind:
   ClaimMapping`). The `principal_is_admin` check at issuance fires
   the same gate Pat uses; non-admin callers get `403 access_denied`
   with `"admin authority required to declare admin permission"`.
3. You have an existing OIDC login flow that already works for
   non-admin CLI use. The admin opt-in does not change the IdP
   handshake — only the `scope` and `requested_token_lifetime`
   fields on the `/exchange` form body.

### Issue an admin session

```sh
$ hort-cli auth login --admin
✓ Logged in to https://hort.example.com (token expires in 15m).
```

Optionally specify a shorter lifetime:

```sh
$ hort-cli auth login --admin --expires-in 10m
✓ Logged in to https://hort.example.com (token expires in 10m).
```

If you ask for longer than 15 min with `--admin`, hort-cli surfaces the
server-side clamp explicitly:

```sh
$ hort-cli auth login --admin --expires-in 4h
✓ Logged in to https://hort.example.com (token expires in 15m).
note: requested 4h but server issued 15m (per-cap-shape clamp —
      admin sessions are bounded to ≤15 min)
```

The `note:` line is rendered whenever the server-issued lifetime
differs from the requested value. For non-admin sessions the cap is
also 15 min, so `--expires-in 48h` (without `--admin`) produces a similar
clamp note pointing at the 15 min limit.

### Use the admin session

Any subsequent `hort-cli` invocation in the same shell uses the freshly
minted token. The session lifetime is the upper bound; you can always
re-login earlier if you finish the admin work and want to drop the
authority deliberately.

```sh
$ hort-cli admin task invoke staging-sweep
…
```

### Inspect scanner workers

`hort-cli admin workers list` shows every worker that has registered in
the `scanner_registry` — the scanner backends it advertises and whether it
is currently heartbeating. A worker that has stopped heartbeating stays in
the listing as `LIVE=NO` (it is **not** filtered out), so you can tell "my
trivy worker died" apart from "I never had one".

```sh
$ hort-cli admin workers list
WORKER_ID      BACKENDS   LIVE  LAST_SEEN  REGISTERED
worker-abc123  trivy,osv  yes   12s ago    3d ago
worker-def456  trivy      NO    47m ago    3d ago
```

- **LIVE** is `yes` when the last heartbeat is within ~5 minutes (the
  worker heartbeats every 60 s, so this tolerates four missed ticks); `NO`
  flags a stale/dead worker to investigate.
- **LAST_SEEN** is the age of the last heartbeat; **REGISTERED** is how
  long ago the worker first registered.
- `--output json` emits the raw rows (`worker_id`, `backends`,
  `registered_at`, `last_heartbeat`, `live`, `last_seen_secs_ago`) for
  scripting.

This is a read-only admin endpoint (`GET /api/v1/admin/workers`) and needs
the `admin` claim like the other `admin` subcommands.

Rows for workers that stopped heartbeating are garbage-collected
automatically: the default-enabled `scanner-registry-prune` CronJob deletes
any worker not seen for 7 days, so the listing shows roughly the last week
of churn and the table never grows without bound. (The read is also capped
at the 1000 most-recently-seen workers as a safety bound.)

### Re-login after expiry ("session expired")

A 15 min admin session expires quickly. Once the token crosses `expires_at`,
any `hort-cli` invocation returns `HTTP 401` with the body
`{"error":"invalid_token","error_description":"token expired"}` —
operators commonly describe this as their **session expired**. The
remediation is the same as the original login: re-run `hort-cli auth
login --admin` to mint a fresh 15 min session. A planned rotation-based
refresh-token phase (not yet shipped at the time of writing) will
suppress most of these prompts; see
[ADR 0013](../../adr/0013-idp-authoritative-cli-sessions.md) for the
direction.

---

## 3. Troubleshooting

### `403 access_denied: admin authority required to declare admin permission`

The IdP token validated cleanly but the resolved user is not an admin.
Check `kind: ClaimMapping` resolves your IdP group to a role with
`Permission::Admin` granted (per
[declare-gitops-config.md](declare-gitops-config.md)). The mapping is
applied JIT on each `/exchange`, so a freshly added admin grant takes
effect on the next login.

### `400 invalid_request: admin tokens disabled by composition-root config`

The server is running with `HORT_TOKEN_ALLOW_ADMIN=false` (or unset —
the default is off). This is a deployment-level decision; coordinate
with whoever runs the server.

### `400 invalid_request: requested_token_lifetime below 300-second minimum`

`--expires-in` resolved to fewer than 300 s. Use at least `5m`.

### `403 access_denied` from a non-admin operation, hint mentions `hort-cli auth login --admin`

The authorization layer (`crates/hort-http-core/src/authz/extractors.rs`)
surfaces a `--admin` re-login hint in the audit log when a cli_session
principal without admin cap is denied. The hint is a heuristic — it
fires for any deny on a cli_session principal whose cap lacks
`Permission::Admin`, including denials that are actually about
per-repo grant gaps. Try `hort-cli auth login --admin` first; if the
operation still fails, the underlying problem is a missing
`PermissionGrant` rather than a missing scope.

### Active sessions never expire on a single laptop

Admin authority revocation propagates to the user's grants but not to
already-issued tokens until they expire. Bounded 15 min lifetimes make
this near-instant: a revoked admin's existing session is gone within
15 minutes. If you need immediate revocation (e.g. laptop theft), use
`DELETE /api/v1/users/me/tokens/:id` — both the access token and
(once Phase 2 lands) the refresh token are in the same `api_tokens`
table.

---

## See also

- **[ADR 0013](../../adr/0013-idp-authoritative-cli-sessions.md)** —
  CLI-session design: lifetime bounds, the ≤15 min admin cap, and the
  refresh-token direction.
- **Workload identity**: k8s flux,
  GitHub Actions, and GitLab CI use OIDC federation rather than
  long-lived CLI sessions. The `--admin` flag is a **human-CLI**
  concept; workloads exchange their platform-minted JWT against the
  same `/api/v1/auth/exchange` endpoint with
  `subject_token_type=urn:ietf:params:oauth:token-type:jwt` and the
  resulting bearer is short-lived without needing a refresh token.
  See [`federate-ci-oidc.md`](./federate-ci-oidc.md) and
  [`federate-k8s-workload-identity.md`](./federate-k8s-workload-identity.md).
