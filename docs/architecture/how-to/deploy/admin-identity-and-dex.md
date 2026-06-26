# Admin identity and the Dex bootstrap

This page is the operator recipe for **who is a Hort admin and how they prove
it**. The standing decision is ADR 0038 (admin-identity model); this is the
how-to.

## The model in one paragraph

Human admin is **IdP-assumed**: a maintainer logs in through your OIDC IdP and
Hort mints a short-lived admin **CliSession** (auth-catalog Entries 1/3). Hort
derives `is_admin` from the IdP **`groups`** claim via a group→`admin`
`ClaimMapping`. Service accounts are **strictly non-admin** (Entry 4) — admin is
never a service-account or OCI-token authority. The **only** no-IdP / first-admin
/ break-glass admin path is the DSN-gated `bootstrap-session` CLI.

## Critical: Dex `staticPasswords` emit NO `groups` claim

Hort's admin determination needs the IdP to put a `groups` claim in the token.
**Dex's `staticPasswords` connector does not emit `groups`** (confirmed across
Dex v2.41–2.44). A Dex `staticPasswords`-only deployment therefore yields
**non-admin** OIDC humans — the static admin can log in and get a CliSession, but
it resolves to no `admin` claim.

To get a live, group-based human admin you need **one** of:

1. **A group-capable IdP** — your org's real SSO, **or Dex fronting a
   group-capable connector** (LDAP, GitHub, an upstream OIDC). Point Dex at the
   connector, have it emit your admin group (e.g. `hort-admins`), and map it.
2. **The DSN-gated `bootstrap-session`** — for the first admin, the one-time IdP
   wire-up, or break-glass when the IdP is down.

## Recipe A — group-capable IdP → CliSession (steady state)

1. **Point Hort at your IdP.** Set `HORT_AUTH_PROVIDER=oidc`,
   `HORT_OIDC_ISSUER_URL=<your IdP issuer>`, and `HORT_OIDC_CLI_CLIENT_ID=<public
   CLI client id>`. On the Helm chart these are `auth.provider: oidc`,
   `auth.oidc.issuerUrl`, and `auth.tokenExchange.cliClientId`.

   The chart can also run a minimal **Dex** sidecar (`auth.dex.enabled: true`,
   `auth.dex.issuerUrl`) and point `auth.oidc.issuerUrl` at it. Dex is the
   recommended *minimal* IdP **only if you give it a group-capable connector** —
   replace the `staticPasswords` block in the Dex config with an LDAP / GitHub /
   OIDC connector that emits your admin group.

2. **Map the group to `admin`.** Apply a `ClaimMapping` in the gitops tree:

   ```yaml
   apiVersion: project-hort.de/v1beta1
   kind: ClaimMapping
   metadata:
     name: admins
   spec:
     idpGroup: hort-admins      # your IdP's admin group claim value
     claim: admin
   ```

3. **Log in.** `hort-cli auth login` runs the PKCE loopback flow; a maintainer in
   the `hort-admins` group gets an admin CliSession (≤15 min, ADR 0013).

## Recipe B — first admin / break-glass: `bootstrap-session`

Use this once to wire the IdP + the `admin` `ClaimMapping`, or when the IdP is
down. It is **doubly gated**: it needs operator-level Postgres (DSN) access
**and** `HORT_TOKEN_ALLOW_ADMIN=true` (it refuses otherwise).

```bash
# Operator shell with the DSN configured and HORT_TOKEN_ALLOW_ADMIN=true:
hort-server admin bootstrap-session --ttl 1h
```

It mints a **short-lived (≤1 h)**, **full-cap** admin PAT for the reserved
non-service-account user `bootstrap-admin`, revoking any prior bootstrap token
first (single active token). Paste it into the CLI
(`hort-cli auth login --paste`) and use it only to apply the IdP +
`ClaimMapping` gitops config, then switch to Recipe A. Do not treat it as a
standing admin credential.

> The full cap is mandatory: the ADR 0036 B1 backstop denies an admin-claim PAT
> that carries no cap, so a cap-less bootstrap token would fail closed.

## What you do NOT do

- **Do not mint an admin service account.** `hort-server admin issue-svc-token`
  rejects `--permission=admin` and requires a pre-existing gitops
  `ServiceAccount`. Non-admin SA authority (read / curate / global
  `admin_task_invoke`) is granted via `serviceAccount`-subject `PermissionGrant`s
  (ADR 0037), not by making the SA an admin.
- **Do not rely on an OCI registry token for admin.** The OCI `/v2/auth` token is
  a per-identity capability token (ADR 0036) — admin is not an OCI scope.
- **Do not expect a `staticPasswords`-only Dex admin to be a Hort admin.** It is
  not (no `groups` claim). Use a real connector or the bootstrap-session.

## Destructive housekeeping (retention / archive)

Destructive tasks (`retention-purge`, `eventstore-archive`,
`retention-evaluate`) require the `task:destructive` *claim*, satisfiable only by
a **fresh admin CliSession** — there is intentionally no unattended machine admin
(ADR 0038). A non-admin cron SA with `admin_task_invoke` can enqueue
*non-destructive* admin tasks but not these. Until the destructive-op approval
workflow lands (ADR 0038 follow-on), run destructive housekeeping by hand with a
Dex CliSession, or keep those CronJobs disabled (the deploy default).

## See also

- ADR 0038 — admin-identity model (the standing decision).
- ADR 0036 — OCI capability token; admin off the OCI surface.
- ADR 0037 — gitops `serviceAccount`-subject grants for non-admin SA authority.
- `docs/auth-catalog.md` — Entries 1 (OIDC), 3 (CliSession), 4 (ServiceAccount),
  the bootstrap-session note, and the deployment/IdP cross-cutting note.
- [Federate CI OIDC](federate-ci-oidc.md) and
  [federate k8s workload identity](../federate-k8s-workload-identity.md) — the
  keyless non-admin machine-identity paths.
