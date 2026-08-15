# Operator actions on session-gated endpoints without an IdP

This guide is for operators of a deployment that runs with no human
IdP wired (`hort_dex_enabled: false` — no Dex/OIDC, `HORT_AUTH_PROVIDER=disabled`)
who still need to drive endpoints that gate on token kind: the
self-service prefetch trigger and the curator decision surface. It
covers the token-kind contract those endpoints enforce, the
capture-safe token mint, the opt-in authority preflight, `--rotate`
semantics, and the write-token blast-radius trade-off.

For the design rationale behind claimless native tokens and IdP-backed
CLI sessions, see [ADR 0012](../../adr/0012-claim-based-rbac-claimless-static-tokens.md)
and [ADR 0013](../../adr/0013-idp-authoritative-cli-sessions.md).

---

## 1. Why there is no IdP here

A deployment that hosts no general user activity and maintains no
human accounts has nothing for an IdP to authenticate — wiring Dex/OIDC
would add a dependency and an attack surface with no corresponding
need. The designed operator path instead is a pair of PAT-only,
non-admin `ServiceAccount`s minted host-side by the deploy tooling:
their tokens are the operator's only credential, standing in for the
CliSession a human admin would otherwise mint through an IdP login.

## 2. The token-kind contract

Every native token carries a `TokenKind`: `CliSession` (IdP-backed,
human, ≤15 min — see
[using-hort-cli-with-admin-ops.md](./using-hort-cli-with-admin-ops.md)),
`ServiceAccount` (gitops-declared, minted by `issue-svc-token`), `Pat`
(self-service, minted by an already-authenticated human principal via
`/api/v1/users/me/tokens`), and `Refresh`. With no IdP, no `CliSession`
is obtainable in steady state, and no `Pat` is either — minting a `Pat`
requires an existing human principal to already be logged in, and this
deployment has none. (The one exception is `hort-server admin
bootstrap-session`, a DSN- and `HORT_TOKEN_ALLOW_ADMIN`-gated,
≤1 h admin-capable `Pat` reserved for first-wiring / break-glass, not a
standing credential — see the module doc in
`crates/hort-server/src/cli/admin.rs`.) That leaves the `ServiceAccount`
token as the only practical session-free credential.

The two gated endpoints enforce this differently:

- **Self-service prefetch** — `POST /api/v1/repositories/{repo_key}/prefetch`.
  `SelfServicePrefetchUseCase` runs an explicit token-kind gate
  *before* any RBAC check: the caller's `token_kind` must be
  `CliSession` or `ServiceAccount`, or the request is denied
  `403 Forbidden` regardless of what permissions it carries. A `Pat`
  is rejected here by construction — see
  `crates/hort-app/src/use_cases/self_service_prefetch_use_case.rs`
  (module doc, "Gate order", and `docs/auth-catalog.md` Entry 4's
  self-service prefetch note). Passing the gate grants no authority by
  itself — `Permission::Read ∧ Permission::Prefetch` on the resolved
  repository is still required (Gate 2, same use case).
- **Curator decisions** — everything under `/api/v1/admin/curation/`
  (waive, block, block-versions, exclusions, the queue listing). These
  routes are gated by `CurateOrAdminPrincipal`
  (`crates/hort-http-core/src/authz/extractors.rs`), which authorizes
  `Permission::Curate ∨ Permission::Admin` and does **not** inspect
  `token_kind` — see [curator-workflow.md](./curator-workflow.md) for
  the full authority model. A `ServiceAccount` token is still the
  operator's path here, not because the endpoint rejects `Pat`
  tokens by kind, but because none exists to present: this
  deployment mints no human principal that could self-service one.

## 3. The mint: capture-safe form

`issue-svc-token` prints the plaintext token to stdout by default —
convenient for a Helm hook piping into `kubectl create secret`, a
trap on an interactive host shell where stdout is easy to
scroll-capture into a log or a terminal multiplexer's history. Use
`--output=file:<path>` instead and read the file, never the process
output:

```sh
TF=$(mktemp)
hort-server admin issue-svc-token --name=maintainer-dev \
  --permission=read --permission=prefetch --output=file:"$TF"
TOK=$(cat "$TF"); rm -f "$TF"
```

`--name` selects the target `ServiceAccount` by its gitops
`metadata.name` — the command requires the envelope to already exist
(applied via gitops) and never fabricates one
(`resolve_svc_user` in `crates/hort-server/src/cli/admin.rs`). This
deployment declares two operator SAs:

| SA | Grants (see §5) | Used for |
|---|---|---|
| `maintainer-dev` | global `read`, `prefetch`, `write` | pulls, the self-service prefetch endpoint, the manual per-artifact rescan |
| `maintainer-curator` | global `curate` | the curator decision endpoints |

`--permission` may repeat; `issue-svc-token` always rejects
`--permission=admin` (service accounts are strictly non-admin —
[ADR 0038](../../adr/0038-admin-identity-model.md)).

## 4. The authority preflight: `--require-authority`

A bare mint performs **no** grant check — it happily mints a token for
a declared permission the SA has no backing grant for, and every
request that token later makes fails at runtime RBAC instead. Pass
`--require-authority` to catch that at mint time instead:

```sh
hort-server admin issue-svc-token --name=maintainer-dev \
  --permission=read --permission=prefetch \
  --require-authority --output=file:"$TF"
```

Each declared `--permission` must be backed by a live `PermissionGrant`
on the SA **at the checked scope**: global by default, or the scope
named by `--repository <name>` — and a global grant satisfies a
repo-scoped check too (the same global-⊇-repo evaluator semantics
runtime RBAC uses; see `check_require_authority` in
`crates/hort-server/src/cli/admin.rs`). An unbacked permission fails
the mint with a message naming every unbacked permission and a
copy-paste `PermissionGrant` YAML block per permission.

`--repository` also scopes the **minted token's own capability**, not
just the preflight: with the flag, the token's cap carries
`repository_ids = [<resolved id>]` instead of the default global
`None`. Both mint shapes are legitimate — pick the one matching the
job:

```sh
# Global identity: usable against any repository the underlying
# grants cover.
hort-server admin issue-svc-token --name=maintainer-dev \
  --permission=read --permission=prefetch \
  --require-authority --output=file:"$TF"

# Repository-scoped identity: the token itself cannot be used outside
# npm-proxy, even if the SA holds broader grants elsewhere.
hort-server admin issue-svc-token --name=maintainer-dev \
  --permission=read --permission=prefetch --repository=npm-proxy \
  --require-authority --output=file:"$TF"
```

`issue-svc-token` is strictly non-admin end to end: it rejects
`--permission=admin` regardless of `--require-authority`, and never
mints for a user whose `is_admin` bit is set.

### Grant files backing the operator SAs

The preflight above checks against these standalone
`serviceAccount`-subject grants (`deploy/ansible/files/gitops/auth/grants/`):

- `maintainer-dev-read.yaml` — global `read`.
- `maintainer-dev-prefetch.yaml` — global `prefetch`. Enables the
  self-service prefetch mint shown in §3; the endpoint's own RBAC gate
  (§2, Gate 2) still applies per resolved repository.
- `maintainer-dev-write.yaml` — global `write`. See §6 before minting
  a write-capable token.
- `maintainer-curator-curate.yaml` — global `curate`, on the separate
  `maintainer-curator` SA.

All four are global (no `repository:` field) — see
[declare-gitops-config.md](./declare-gitops-config.md) `kind:
PermissionGrant` for the omit-the-field-for-global convention.

## 5. `--rotate` and the row-without-Secret trap

Re-running the mint command for a token name that already exists is
idempotent by default: `issue-svc-token` exits `0`, logs an
`info:` line on stderr, and — because it never re-emits a plaintext it
cannot un-hash — **writes nothing to the output file**. If a
provisioning script blindly reads that file next, it either reuses a
stale empty file or silently proceeds with no token at all.

**Always check the output file is non-empty before storing or
exporting it as a credential:**

```sh
TF=$(mktemp)
hort-server admin issue-svc-token --name=maintainer-dev \
  --permission=read --output=file:"$TF"
if [ ! -s "$TF" ]; then
  echo "no new token minted (row already exists) — pass --rotate to replace" >&2
fi
```

Pass `--rotate` to force replacement: the existing token is revoked
first, then a fresh one is minted and written.

```sh
hort-server admin issue-svc-token --name=maintainer-dev \
  --permission=read --permission=prefetch --rotate --output=file:"$TF"
```

Rotation changes which token is valid; it does not change what the
token can do at request time. `Permission::Read ∧ Permission::Prefetch`
on the resolved repository is still evaluated on every prefetch call
against the SA's live grants, independent of which token happened to
present them.

## 6. Blast radius: mint write-capable tokens per action

`maintainer-dev-write.yaml` grants **global** write — deliberately, to
avoid per-repository grant upkeep for a single trusted operator
identity, but with an unavoidable trade-off: a leaked `write`-capable
`maintainer-dev` token can push to every hosted repository this
instance serves. Bound the exposure by minting write capability only
for the action at hand, not as a standing credential:

```sh
TF=$(mktemp)
hort-server admin issue-svc-token --name=maintainer-dev \
  --permission=read --permission=write --rotate \
  --expires-in-days=1 --output=file:"$TF"
TOK=$(cat "$TF"); rm -f "$TF"
# ... perform the write-gated action (e.g. a manual per-artifact
# rescan, POST /api/v1/artifacts/:id/rescan) ...
```

Prefer the day-to-day `read` (+ `prefetch` where needed) mint from §3
for routine operator work, and reserve a `write`-capable mint for the
specific action that needs it.

## See also

- [curator-workflow.md](./curator-workflow.md) — the `Permission::Curate`
  authority model the curation endpoints enforce.
- [using-hort-cli-with-admin-ops.md](./using-hort-cli-with-admin-ops.md) —
  the IdP-backed CliSession admin path, for deployments that do wire
  an IdP.
- [rotating-service-account-tokens.md](./rotating-service-account-tokens.md) —
  the worker-driven periodic rotation reconciler for workloads that
  can't federate; a different mechanism from the one-shot
  `issue-svc-token` mint documented here (see that guide's "See also"
  section for how the two paths relate).
- [declare-gitops-config.md](./declare-gitops-config.md) — `kind:
  ServiceAccount` and `kind: PermissionGrant` envelope reference.
- `docs/auth-catalog.md` — the canonical auth-surface catalog
  (Entry 4, `ServiceAccount`).
