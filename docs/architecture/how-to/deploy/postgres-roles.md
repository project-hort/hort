# postgres-roles.md — Provisioning the Postgres roles

Canonical SQL recipe operators run during database provisioning so the
hort-server chart's role split actually behaves as
least-privilege. The runtime Deployment binds with a role that **cannot
create tables in `public`**; the migrations Job binds with a role that
**owns** the schema. The least-privilege runtime design
([ADR 0009](../../../adr/0009-least-privilege-runtime-migrate-subcommand.md))
makes the runtime DSN's lack of DDL permission load-bearing — the serve
process no longer calls `sqlx::migrate!().run()`, so a missing grant
here is now the failure mode this how-to exists to prevent.

> **The role split is now effectively three roles, but only two are
> operator-provisioned.** There is a
> third role, **`hort_retention_role`**, that is **created by a migration**,
> not by this recipe. An operator does **not** pre-create it. The one
> operator-side consequence is a single new prerequisite on the
> migrations-Job role (`hort_admin`): because a migration now issues
> `CREATE ROLE`, `hort_admin` must hold `CREATEROLE`. The recipe below adds
> exactly that one line. See "The role contract" and "Canonical SQL
> recipe" for the grounded detail.

This is operator documentation, not a chart template. The chart
deliberately does not ship a Postgres-init Job; operators
provision the roles via psql, an init-container, terraform, gitops, or
their database-as-a-service tooling. The recipe below is what those
mechanisms must produce.

---

## The role contract

| Role | Provisioned by | Used by | DDL? | DML on `public` tables | `CREATE` on `public`? |
|---|---|---|---|---|---|
| `hort_admin` | **operator** (this recipe) | `helm` pre-install/-upgrade migrations Job (`args: ["migrate"]`) | yes — owns `public`; runs `sqlx::migrate!()` | yes (as owner) | yes (as owner) |
| `hort_app_role` | **operator** (this recipe) | runtime Deployment (`args: ["serve"]`) and the runtime CLI subcommands (`admin issue-svc-token`, `reconcile-groups`) | **no** | yes | **no** — deliberately revoked |
| `hort_retention_role` | **a migration** (`migrations/004_events.sql`, `CREATE ROLE hort_retention_role NOLOGIN;`) — **not** this recipe; do **not** pre-create it | the sanctioned retention sweep's transaction-scoped `SET LOCAL ROLE` (the worker assumes it for the whole-stream `DELETE FROM events`). `NOLOGIN` — never connected to directly. | n/a | **`SELECT, DELETE` on `events` only** (NO `INSERT`/`UPDATE`/`TRUNCATE`) | **no** |

> **`hort_retention_role` is migration-created — leave it to the migration.**
> `migrations/004_events.sql` creates it conditionally, inside a
> `DO $$ … END $$;` block, guarded by
> `IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'hort_retention_role') THEN CREATE ROLE hort_retention_role NOLOGIN; END IF;`
> (Postgres has no `CREATE ROLE IF NOT EXISTS`, so the migration emulates
> it with the `pg_roles` guard — the create is therefore idempotent and
> re-run-safe). An operator who pre-creates `hort_retention_role` by hand
> is not *wrong* (the guard makes the migration's `CREATE` a no-op), but
> it is unnecessary and is **not** what this recipe asks for — the
> recipe's only obligation for this role is to give `hort_admin` the
> `CREATEROLE` privilege the migration's `CREATE ROLE` needs. The same
> `DO` block also (re)creates `hort_admin` and `hort_app_role` under the same
> `IF NOT EXISTS` guard, which is why this recipe creating them up front
> is also safe — the migration's creates become no-ops.

`hort_retention_role` is the dedicated, `DELETE`-capable role the
sanctioned whole-stream retention path connects as; the
`events_immutable` trigger (which otherwise blocks every `DELETE`)
lets *only this role's* `DELETE` through and is **never disabled** by
application code. The rationale for the role-scoped exemption (rather
than disabling the trigger around the sweep): a trigger-disable window
would suspend the immutability guarantee for *every* concurrent
session, while the dedicated `NOLOGIN` role bounds deletion authority
to the sanctioned, transaction-scoped `SET LOCAL ROLE` path — the
trigger stays armed at all times. Wiring the worker's retention DSN to
a login user that is a member of `hort_retention_role` is the worker
operator's concern, not this recipe's — this how-to only ensures
the role itself comes into existence by ensuring the migration that
creates it can run.

The runtime role's lack of `CREATE ON SCHEMA public` is the security
property; the recipe below preserves it. Postgres 15+ removed the
implicit `CREATE` that pre-15 deployments silently inherited from the
`PUBLIC` pseudo-role, so a recipe that worked on Postgres 14 may
silently regress on 15+ without the explicit `REVOKE CREATE ON SCHEMA
public FROM PUBLIC` line below.

### Why `hort_admin` needs `CREATEROLE`

A migration in the shipped chain (`migrations/004_events.sql`)
runs `CREATE ROLE hort_retention_role NOLOGIN;` (inside the
`pg_roles`-guarded `DO` block above). In Postgres a non-superuser may
issue `CREATE ROLE` **only if it holds the `CREATEROLE` attribute**.
The migrations Job binds as `hort_admin`; without `CREATEROLE` on
`hort_admin`, `hort-server migrate` aborts with
`permission denied to create role` and the install never reaches the
app. `CREATEROLE` is therefore a hard prerequisite on `hort_admin`,
added by the recipe below. (It is *not* needed on `hort_app_role` — the
runtime never creates roles; only the migrating role does.)

The deferred upshot: the serve binary calls
`migrate::assert_current` (read-only `SELECT` on `_sqlx_migrations`),
not `migrate::run`. A runtime role with `INSERT, SELECT, UPDATE,
DELETE` on the bookkeeping table is enough; **no DDL is ever attempted
on the runtime DSN**.

---

## Why `hort_app_role` deliberately lacks `CREATE ON SCHEMA public`

The chart correctly wires two secrets and routes them at template
time. The Postgres init script (operator-side) correctly does NOT
grant `hort_app_role` `CREATE` on `public`. Historically the binary
silently violated the boundary by calling `migrate::run` on the
runtime pool — `sqlx::migrate!()` issues `CREATE TABLE IF NOT EXISTS
_sqlx_migrations` on the first call even when there is nothing to
apply. That DDL fails with `permission denied for schema public` and
the runtime pod crashloops (the incident behind
[ADR 0009](../../../adr/0009-least-privilege-runtime-migrate-subcommand.md)).

The fix is the assertion-only path (`migrate::assert_current`) plus
this how-to: with the runtime role permanently DDL-less, an
accidental future `migrate::run` regression on the serve path will
fail loud at boot rather than silently work in a permissive
environment and break only when an operator finally provisions a
properly-scoped role.

---

## Canonical SQL recipe

Run as a Postgres superuser — `postgres`, an RDS master user, a Cloud
SQL admin, etc. The recipe is idempotent on the role-creation lines
only if you guard with `IF NOT EXISTS` (Postgres 9.5+); the grant
lines are themselves idempotent. Substitute the two passwords (psql
variable substitution shown; replace `:'admin_password'` /
`:'app_password'` with literals if you are not using psql with `-v`).

```sql
-- ROLES
-- hort_admin needs CREATEROLE: a migration (migrations/004_events.sql)
-- runs `CREATE ROLE hort_retention_role NOLOGIN;`, and `hort-server migrate`
-- binds as hort_admin. Without CREATEROLE the migrate Job aborts with
-- `permission denied to create role` and the install never reaches the
-- app. CREATEROLE lets hort_admin create the migration-owned retention
-- role; it does NOT grant CREATEDB/SUPERUSER. hort_app_role gets no such
-- attribute (the runtime never creates roles).
CREATE ROLE hort_admin    WITH LOGIN CREATEROLE PASSWORD :'admin_password';
CREATE ROLE hort_app_role WITH LOGIN            PASSWORD :'app_password';

-- DATABASE
CREATE DATABASE hort OWNER hort_admin;
\c hort

-- SCHEMA OWNERSHIP — hort_admin owns public; runtime cannot create.
-- This REVOKE is the runtime role's security property and is intact:
-- CREATEROLE on hort_admin is a *role-management* privilege, entirely
-- orthogonal to schema CREATE — hort_app_role still has no CREATE on
-- public after this recipe.
ALTER SCHEMA public OWNER TO hort_admin;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT  USAGE  ON SCHEMA public TO hort_app_role;

-- DEFAULT PRIVILEGES — applies to FUTURE objects hort_admin creates.
-- This is the one operators most often miss; without it, every new
-- migration ships tables the runtime cannot read. The migrate Job
-- runs as hort_admin and creates every schema object, so these
-- defaults flow to the runtime automatically.
ALTER DEFAULT PRIVILEGES FOR ROLE hort_admin IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES    TO hort_app_role;
ALTER DEFAULT PRIVILEGES FOR ROLE hort_admin IN SCHEMA public
    GRANT USAGE,  SELECT, UPDATE         ON SEQUENCES TO hort_app_role;
```

### Retrofit: an existing `hort_admin` provisioned without `CREATEROLE`

If `hort_admin` already exists from an earlier provisioning that
predates the `CREATEROLE` prerequisite (it was created
`WITH LOGIN PASSWORD …` but no
`CREATEROLE`), the `ROLES` block above is a no-op under an
`IF NOT EXISTS` guard and the missing attribute is **not** added — the
next `hort-server migrate` will still abort with
`permission denied to create role`. The one-line, idempotent fix,
run as a superuser:

```sql
-- Idempotent: re-running ALTER ROLE … CREATEROLE on a role that
-- already has it is a no-op. Run as a Postgres superuser.
ALTER ROLE hort_admin CREATEROLE;
```

`ALTER ROLE … CREATEROLE` only flips the role-management attribute; it
does **not** touch schema grants, so the
`REVOKE CREATE ON SCHEMA public FROM PUBLIC` security property is
unaffected. After this, `hort-server migrate` can create
`hort_retention_role` and the install proceeds.

### Run this recipe against a fresh database only

The recipe is a provisioning step, not a fix-up step.
`ALTER DEFAULT PRIVILEGES` carries runtime grants forward to every
future schema object `hort_admin` creates — so once provisioning is
done, the migrate Job and every subsequent schema migration require
no further operator action.

Do **not** add a bulk
`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO hort_app_role`
to retrofit a running DB. That bulk grant lands on the append-only
`events` table and re-grants `UPDATE`/`DELETE`, which breaks the
audit invariant; `PgEventStore::new`'s startup probe then refuses
to boot the runtime. If you need to grant on an already-populated DB,
do it table-by-table and explicitly skip `events`.

### What about `_sqlx_migrations`?

The bookkeeping table is created by `hort_admin` on the first migrate
run, so it inherits the `ALTER DEFAULT PRIVILEGES` grant
automatically. No separate `GRANT SELECT ON _sqlx_migrations` is
needed.

### Defense-in-depth: the chart re-hardens `events` automatically

Even on a correctly-provisioned DB, an operator (or a reconcile
loop, or an out-of-band fix-up) running a future bulk
`GRANT … ON ALL TABLES … TO hort_app_role` would silently re-grant
`UPDATE`/`DELETE` on `events`. The chart's migrate Job runs
`hort-server migrate`, which (in addition to applying any pending
schema migrations) re-asserts
`REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON events
FROM hort_app_role` idempotently as `hort_admin`. Operators do not need
to wire this into their own provisioning — the binary owns it.

---

## Verification

After the recipe runs (and after the migrate Job has executed at
least once), confirm the role split is correct.

**Role membership and login:**

```sql
\du
-- Expected before the migrate Job:
--   hort_admin    — `Cannot login: false`, attributes include `Create role`
--   hort_app_role — `Cannot login: false`, no `Create role`
-- Expected AFTER the migrate Job has run at least once (the migration
-- creates it — do NOT pre-create it):
--   hort_retention_role — `Cannot login: true` (NOLOGIN), no `Create role`
```

`hort_admin` must show `Create role` in its attribute list **before** the
first migrate run, or `CREATE ROLE hort_retention_role` inside
`004_events.sql` fails. `hort_retention_role` appears only *after* a
successful migrate; its absence before the migrate Job is expected, not
a defect.

**Grants on `public.*`:**

```sql
\dp public.*
-- Expected after migrate Job: every table shows
--   `hort_admin=arwdDxt/hort_admin` (owner)
--   `hort_app_role=arwd/hort_admin`  (DML granted)
```

(`a`=INSERT, `r`=SELECT, `w`=UPDATE, `d`=DELETE, `D`=TRUNCATE,
`x`=REFERENCES, `t`=TRIGGER. The runtime role gets `arwd`; lack of
`D`/`x`/`t` is intentional.)

**Default privileges (the gotcha):**

```sql
\ddp
-- Expected: one row per ALTER DEFAULT PRIVILEGES statement run above
--   Owner: hort_admin
--   Schema: public
--   Type: table     | Access privileges: hort_app_role=arwd/hort_admin
--   Type: sequence  | Access privileges: hort_app_role=rwU/hort_admin
```

If `\ddp` returns zero rows, default privileges were not set — every
future migration will ship tables the runtime can't touch and the
serve pod will start crashlooping after each new release. Re-run the
two `ALTER DEFAULT PRIVILEGES` lines.

**Runtime can read `_sqlx_migrations` (the `assert_current` invariant):**

```bash
psql "postgres://hort_app_role:${HORT_APP_PASSWORD}@<host>:5432/hort" \
    -c "SELECT MAX(version) FROM _sqlx_migrations;"
# Expected: a single integer (the highest applied migration version).
```

If this errors with `permission denied for table _sqlx_migrations`,
the runtime will refuse to start — `migrate::assert_current` will
bail with `permission denied reading _sqlx_migrations — grant SELECT
on _sqlx_migrations to the runtime role`. Cause: the recipe was run
*after* the migrate Job created `_sqlx_migrations`, so the
`ALTER DEFAULT PRIVILEGES` lines (which apply only to *future*
objects) didn't reach the bookkeeping table. Fix: run an explicit
`GRANT SELECT ON _sqlx_migrations TO hort_app_role;` as `hort_admin`
(or a superuser) — the table now exists, so the grant lands.

**Runtime cannot create tables (the security property):**

```bash
psql "postgres://hort_app_role:${HORT_APP_PASSWORD}@<host>:5432/hort" \
    -c "CREATE TABLE _runtime_should_fail (id int);"
# Expected: ERROR: permission denied for schema public
```

If this CREATE succeeds, the role split is broken — `hort_app_role` has
`CREATE` on `public`. Run `REVOKE CREATE ON SCHEMA public FROM
hort_app_role;` and re-test. The runtime will crashloop the next time
it tries `migrate::assert_current` only if `_sqlx_migrations` ends up
created by the serve pod, but the security boundary has been
violated regardless.

---

## Common failure modes

### 0. `permission denied to create role` (migrate Job aborts)

The pre-install/-upgrade migrate Job exits non-zero and the install
never reaches the app. Cause: `hort_admin` lacks `CREATEROLE`, so the
`CREATE ROLE hort_retention_role NOLOGIN;` statement in
`migrations/004_events.sql` is refused. This
happens on a DB provisioned with an older recipe (no
`CREATEROLE` on `hort_admin`) or where the operator's DB-as-a-service
strips role-management attributes by default.

```bash
kubectl logs -l hort-server.io/job=migrate
# ... ERROR: permission denied to create role
```

Fix (idempotent, run as a superuser):

```sql
ALTER ROLE hort_admin CREATEROLE;
```

Then re-run the migrate Job (`helm upgrade --install`, or
`kubectl delete job …/migrate` to let the pre-install hook re-fire).
This does not weaken the schema-`CREATE` revocation (see the recipe's
`CREATEROLE`-vs-schema-`CREATE` note).

### 1. `_sqlx_migrations not found — run hort-server migrate ...`

The serve pod logs this and exits non-zero on first boot. Cause: the
migrate Job has not run yet (or it failed) and the bookkeeping table
does not exist. The runtime path is read-only, so it cannot create
the table itself.

```bash
kubectl logs -l hort-server.io/job=migrate
```

If the migrate Job failed with `permission denied for schema public`,
the `hort_admin` DSN is wrong — it's pointing at the runtime role
instead. Check `postgres.admin.existingSecret` references the admin
DSN, not the app DSN.

If no migrate Job pod exists, the chart's pre-install hook didn't
fire — likely the chart was applied with `--no-hooks`. Re-run
`helm upgrade --install` without that flag.

### 2. `permission denied reading _sqlx_migrations — grant SELECT ...`

The serve pod logs this and exits non-zero. Cause: the migrate Job
ran successfully (`hort_admin` created `_sqlx_migrations`), but the
recipe was applied to a fresh DB without setting `ALTER DEFAULT
PRIVILEGES`. The new table doesn't carry a SELECT grant for
`hort_app_role`.

Fix: connect as `hort_admin` (or a superuser) and run:

```sql
GRANT SELECT ON _sqlx_migrations TO hort_app_role;
ALTER DEFAULT PRIVILEGES FOR ROLE hort_admin IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO hort_app_role;
```

The first line fixes the immediate boot; the second prevents the
same gap from recurring on the next migration.

### 3. `permission denied for table <new_table>` (after a release)

The serve pod boots fine on the current schema, but logs this on a
specific query path after a chart upgrade introduces a new
migration. Cause: same as failure mode 2 — `ALTER DEFAULT PRIVILEGES`
was never set, so the new migration's tables shipped without a
runtime grant.

Fix: connect as `hort_admin` and run:

```sql
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public
    TO hort_app_role;
ALTER DEFAULT PRIVILEGES FOR ROLE hort_admin IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO hort_app_role;
```

The first line covers the new table; the second covers all future
migrations.

---

## See also

- [ADR 0009](../../../adr/0009-least-privilege-runtime-migrate-subcommand.md)
  — the least-privilege runtime / `migrate` subcommand decision that
  motivates this how-to (the `assert_current` contract; the boundary
  this recipe protects).
- [ADR 0002](../../../adr/0002-event-sourced-artifact-lifecycle.md) — the
  immutable event log the `events_immutable` trigger +
  `hort_retention_role` exemption protect.
- `docs/architecture/how-to/deploy/install.md` §2 — the operator playbook
  this how-to is the canonical reference for.
