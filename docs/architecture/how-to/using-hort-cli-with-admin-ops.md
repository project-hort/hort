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

### Inspect the effective config for a repository

`GET /api/v1/admin/repositories/{key}/effective-config` returns the
resolved, merged config a running server holds for one repository — the
repository row, its upstream mapping(s), and the scan policy actually bound
to it (repo-scoped > global > built-in default), as one projection. This is
the answer to "what config is this repository *actually* running", which
the gitops YAML alone cannot show since the YAML is the input to
resolution, not the resolved result.

```sh
$ curl -sS -H "Authorization: Bearer $TOKEN" \
    https://hort.example.com/api/v1/admin/repositories/npm-proxy/effective-config
```

The response is cross-repository (any admin can read any repository's
effective config, not only ones they hold a grant on) and **secrets are
hard omitted**: no `secret_ref`, `mtls_cert_ref`, `mtls_key_ref`, or
`ca_bundle_ref` field is ever present on an upstream mapping. Credential
presence is surfaced only as `has_credentials: bool`.

This is a read-only admin endpoint and needs the `admin` claim like the
other `admin` subcommands. Unknown repository key returns `404`.

### Inspect what this process applied at boot

`GET /api/v1/admin/gitops/apply-status` reports the gitops apply **this
running process** performed at boot — in-memory only, not persisted. During
a rolling upgrade, different pods can legitimately report different
results until the rollout converges; this endpoint answers "what did *this
process* apply", not "what was last applied cluster-wide".

```sh
$ curl -sS -H "Authorization: Bearer $TOKEN" \
    https://hort.example.com/api/v1/admin/gitops/apply-status
```

```json
{
  "status": "applied",
  "applied_at": "2026-08-23T09:14:02Z",
  "generation": "3f9a1c...  (64 hex chars)",
  "created": 1,
  "updated": 2,
  "deleted": 3,
  "unchanged": 4,
  "retro_warn_count": 5,
  "retro_block_count": 6,
  "per_kind": {
    "repositories": { "created": 0, "updated": 0, "deleted": 0, "unchanged": 0 },
    "upstream_mappings": { "created": 0, "updated": 0, "deleted": 0, "unchanged": 0 },
    "claim_mappings": { "created": 0, "updated": 0, "deleted": 0, "unchanged": 0 },
    "permission_grants": { "created": 0, "updated": 0, "deleted": 0, "unchanged": 0 },
    "curation_rules": { "created": 0, "updated": 0, "deleted": 0, "unchanged": 0 }
  }
}
```

- `generation` is a 64-hex-character fingerprint of the applied config. Two
  processes reporting the same `generation` applied the same config;
  different values mean the config differs between them (e.g. a rollout
  that has not converged yet). It is a fingerprint, not a counter — it does
  not order two generations against each other.
- **`per_kind` covers only the five CRUD kinds** listed above — it does
  **not** sum to the aggregate `created`/`updated`/`deleted`/`unchanged`
  counts, which also span event-sourced kinds (scan policies, retention
  policies, exclusions) and machine-identity kinds (OIDC issuers, service
  accounts).
- If no gitops apply has run this boot (e.g. a DSN-only boot, or no gitops
  config directory configured), the response is exactly
  `{"status":"no_apply_recorded"}` — every other field is omitted, not
  zeroed.

This is a read-only admin endpoint and needs the `admin` claim like the
other `admin` subcommands.

Both of the above endpoints are gated by the same `AdminPrincipal` check as
`GET /api/v1/admin/workers`; see
[ADR 0058](../../adr/0058-admin-config-inspection-surface.md) for the design
rationale behind the admin-only scope, the in-memory apply-status
semantics, and the secrets-exclusion mechanism.

### Preview and execute a retention cleanup

Retention deletes real content, so the CLI puts a readable proposal and a
confirmation between the operator and the sweep. Two subcommands:

```sh
# What would retention take if it ran right now? Read-only.
$ hort-cli admin retention preview

# Execute it, after re-measuring and showing what moved since that preview.
$ hort-cli admin retention apply --from-preview <task_job_id>
```

`preview` runs `retention-evaluate` in `dry_run` mode and renders the
result: artifact rows, distinct stored contents, the bytes a purge would
actually reclaim, a per-policy/per-repository rollup naming repositories
by the key you write into a policy, a capped sample, and — beside the
run and each group — a **proposal digest** identifying *which* rows the
run proposes to expire.

Four things about that output are deliberate:

- **Rows are not bytes.** One stored blob can back many artifact rows, so
  the row count and the byte figure will not agree. The output labels the
  counts as counts and gives no per-group byte column, because a blob is
  freed only when its last reference anywhere goes away.
- **An unmeasured size says so.** When the evaluator's byte accounting
  exceeds its exact-accounting bound it reports `omitted`, and the CLI
  prints `NOT MEASURED` with the reason. The reason names which of the two
  bounds was hit (the candidate artifacts handed to the simulation, or the
  reclaimable content targets it produced), what that bound is set to, and
  what this run reached — so you can tell whether a narrower scope brings
  the figure back. There is no estimate anywhere, and never a `0` standing
  in for "we did not look".
- **Partial coverage is in the header.** A sweep that stopped at its
  per-run batch cap undercounts every artifact outside the window it
  walked, so it is stated above the numbers rather than after them. It
  bounds the run, not the sweep: each execution records the position it
  stopped at, the next one resumes strictly after it, and a finished pass
  wraps to the beginning — so a registry larger than one run's cap is
  covered across consecutive runs rather than having its tail left
  permanently unevaluated. A preview reads that position without moving
  it, which is what makes it a preview of the window the next execution
  will act on.
- **The proposal has an identity, not just a size.** Every count in the
  output says *how much* would be expired; none of them says *what*. Two
  previews can agree on every figure and still name different rows — one
  artifact stopped matching and an equally sized one started — and among
  artifacts of the same kind that is not a rare coincidence. So each run
  also reports a `proposal_digest` over the `(policy, artifact)` pairs it
  matched, in canonical order, with a per-group digest beside it. It is a
  fixed-width field whatever the proposal's size, and it is **not** a
  content hash: it digests identifiers, never artifact bytes, and no
  storage path accepts one. The `scheme` tag beside each value says which
  construction produced it; two digests are comparable only under the
  same scheme.

`apply` always runs a **fresh** preview immediately before executing.
With `--from-preview` it compares that fresh preview against the earlier
one you name and renders the difference; if anything moved you are asked
to acknowledge the change and then to authorise the run — two separate
questions. `--yes` skips the questions and never the comparison. Without
`--from-preview` there is nothing to compare against and no delta is
invented: the fresh preview is presented on its own terms.

That comparison decides on the proposal's identity, so `NOTHING CHANGED
SINCE THE PREVIEW YOU NAMED` means *the same artifacts*, not *the same
totals*. Three answers are possible and the output distinguishes them,
because they ask for different judgement:

- **The same artifacts.** Both previews reported a comparable identity
  and the two agree. This is the only answer that skips the extra
  question.
- **Different artifacts.** The proposed rows moved. You are asked to
  acknowledge that before authorising the run, whether or not any figure
  moved with them.
- **Not compared.** One side reported no identity (a server older than
  the field), or the two were computed under different schemes (a server
  upgrade between the two runs). The output says so and still asks — a
  comparison that could not check must not sound like one that did.

`delta.proposal.comparison` in the JSON carries the same answers, with
the two causes of "not compared" kept apart: `same`, `different`,
`unreported`, `scheme_mismatch`. `delta.changed` is fail-closed — `true`
whenever sameness was not *established* — so a script gating an
unattended apply on `changed == false` stops rather than proceeding
blind.

**Partial coverage qualifies a difference, never a match.** Equal digests
mean the two previews name the same rows however much of the candidate
set each examined. Differing digests over a `partial` run are another
matter: two runs can legitimately walk different windows — an execution
between them moves the sweep's saved position — so the output says it
compared two windows and that the difference may be the window moving
rather than the world, instead of reporting it as the proposal changing.
`delta.proposal.window_limited` is the same fact for a script.

Authority: `preview` needs only the ordinary admin-task permission;
`apply`'s execute step additionally needs the `task:destructive` claim,
which the `--admin` session above carries. Nothing here introduces a new
permission, claim, or token lifetime.

**That authority is checked twice: once when the job is accepted, and
again when the worker is about to run it.** A destructive job is queued,
not executed inline, so the second check reads the live authority of the
user the job was enqueued under. If it was revoked in between — the
account demoted or deactivated, or its `admin_task_invoke` grant removed
— the handler is never called, nothing is destroyed, and the job becomes
a terminal `failed` row whose `last_error` begins `destructive task
refused at execution`. It reaches a scheduled run the same way, where a
deployment drives a destructive kind on a schedule: the CronJob invokes
through this same surface, so revoking the identity it authenticates as
stops scheduled retention too. See
[`enable-admin-task-cronjobs.md`](deploy/enable-admin-task-cronjobs.md)
§5.1 for the operator-facing detail. One consequence worth knowing
before you grant: the claim is resolved from your IdP at login and is not
persisted, so only an `admin` requester's destructive authority survives
the wait — a non-admin holder of a `task:destructive` `ClaimMapping` can
submit a job that is then refused at execution.

Exit codes worth scripting against: `0` ran and the result was read, `3`
the job outlived `--wait-timeout` (the job id is printed and nothing is
reported about its outcome), `4` the operator declined and nothing was
executed.

Three operational notes:

- **A `preview` is always a fresh sweep.** Run it as often as you like:
  an observation destroys nothing, so it takes no single-flight claim and
  is never deduplicated. That is what lets `apply --from-preview` compare
  its pre-execution re-measure against the proposal you named rather than
  against itself.
- **An `apply` execution is deduplicated per UTC day.** The first
  execution of a day owns the day; a second one gets that job back rather
  than sweeping again, and the CLI says so explicitly rather than
  presenting it as a fresh run. This is deliberate — the cron schedule is
  the retry mechanism, and re-firing a destructive sweep inside the day is
  what [ADR 0028](../../adr/0028-destructive-task-idempotency.md) exists
  to prevent. Recovering inside the same day means deleting the earlier
  `jobs` row, which is an explicit and audited operator action.
- Expiry marks artifact records. Reclaiming the bytes is the separate
  purge stage.

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

### Cutting a CLI session off before it expires

Admin authority revocation propagates to the user's grants but not to
already-issued tokens until they expire. Bounded 15 min lifetimes make
this near-instant: a revoked admin's existing session is gone within
15 minutes.

When 15 minutes is too long — a stolen laptop, a token pasted into the
wrong window — revoke the session directly. A CliSession is a signed
JWT with **no `api_tokens` row**, so `DELETE /api/v1/users/me/tokens/:id`
does not reach one (it answers `404 token_not_found`), and there is
nothing to list: hort keeps no registry of live sessions. Use one of
the two admin-gated revocation surfaces instead.

**You have the token** (pasted into a ticket, found in a log) — cut
exactly that session and leave the person's other sessions working:

```bash
# The token is read locally; only its `jti` and `exp` are sent.
# `--token -` keeps the credential out of shell history.
pbpaste | hort-cli admin cli-session revoke --token -
```

**You do not have the token** (the device is gone) — cut every session
that human holds:

```bash
hort-cli admin cli-session revoke-user <user_id>
```

This raises a cutoff: every CliSession for that user issued at or
before now is refused, and the cutoff lapses one session lifetime
later, by which point none of them could still be live. It is **not**
an account lockout — the user runs `hort-cli auth login` again and the
new session works immediately. To stop them logging back in at all,
deactivate the user; that is a separate, deliberate action.

Both commands need an admin session (`hort-cli auth login --admin`).
Service accounts are strictly non-admin
([ADR 0038](../../adr/0038-admin-identity-model.md)), so neither can be
driven from a pipeline. The underlying routes are
`POST /api/v1/admin/cli-sessions/revoke` and
`POST /api/v1/admin/users/{user_id}/cli-sessions/revoke`; both live on
the control plane, so they answer on `HORT_CONTROL_BIND` when the split
is on.

`DELETE /api/v1/users/me/tokens/:id` remains the self-revoke path for
PATs and service-account tokens, which *do* have rows.

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
