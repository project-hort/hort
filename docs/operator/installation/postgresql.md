# Prepare PostgreSQL for hort

hort uses PostgreSQL for metadata and operational state. A production installation separates the **migration account** from the **runtime account** so the running API server and worker cannot create application tables.

## Required role split

| Account | Used for | Access |
| --- | --- | --- |
| Migration role (commonly `hort_admin`) | `hort-server migrate` and Helm migration Job | Schema ownership and required migration privileges |
| Runtime role (commonly `hort_app_role`) | `hort-server serve`, `hort-worker`, runtime CLI operations | Application data access, **no general schema CREATE** |

Do **not** pre-create `hort_retention_role` as part of standard provisioning: it is managed by a migration. The migration role must have the required `CREATEROLE` privilege for migrations that create internal roles; coordinate this with your database administrator or managed-PostgreSQL provider.

## Provision and store credentials

1. Create the database and login roles using your approved PostgreSQL provisioning mechanism (DBA, IaC, or automation).
2. Grant the migration role schema ownership and the privileges required by the shipped migrations.
3. Grant the runtime role only the privileges required for serving; remove general `CREATE` on the `public` schema.
4. Store both credentials in your deployment secret manager; **never** commit passwords or full DSNs to Git.
5. Make both accounts reachable from their respective services, including the migration Job if using Helm.

For native Linux, provide distinct environment files for the migration and runtime systemd units. The worker uses runtime credentials. See [Native Linux](native-linux.md).

For Helm, provide the existing secrets used by the chart:

```yaml
postgres:
  app:
    existingSecret: hort-postgres-app
  admin:
    existingSecret: hort-postgres-admin
```

Ensure the referenced Secrets contain the keys required by your chart version. The installation guide describes its default `HORT_DATABASE_URL` key.

## Migrate and verify

The migration entry point is:

```bash
hort-server migrate
```

Run it **only** with the migration role, via the deployment's migration mechanism. When using Helm, review the migration Job status and logs. Confirm the server/worker start only after migration success and do not silently substitute an admin DSN for the application runtime.

If migration fails with `permission denied to create role`, inspect the migration role's `CREATEROLE` attribute. If it fails on schema permissions, review ownership and grants rather than elevating the runtime role.

**Scope:** This guide describes the role contract and deployment wiring. The full SQL provisioning recipe remains in the existing database-role reference until it has been reduced and independently verified for supported PostgreSQL versions.

Related: [Upgrade hort](upgrade.md) · [Kubernetes with Helm](kubernetes-helm.md).
