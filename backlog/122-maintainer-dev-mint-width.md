# 122 — Widen the maintainer-dev token mint to match its documented grants

Issue: #171. Operator decision (2026-08-20): **widen the mint**, not narrow
the documentation. Single unit, deployment tooling only — no production
code, no runtime surface.

## What is wrong

`docs/architecture/how-to/mint-operator-tokens-without-idp.md` §3 tells an
operator that `maintainer-dev` holds global `read`, `prefetch` and `write`,
and names it as the identity for "the manual per-artifact rescan". The
Ansible gitops role mints it with `--permission read` only:

```yaml
# deploy/ansible/roles/gitops/tasks/main.yml
- name: Issue maintainer-dev service-account token (read permission)
  cmd: >-
    {{ gitops_admin_cmd }} issue-svc-token
    --name maintainer-dev
    --permission read
    --output file:/run/secrets/hort-dev.token
```

`POST /api/v1/artifacts/{id}/rescan` requires `Permission::Write` on the
parent repository (`hort-http-admin-security::handlers::rescan`, ADR 0008),
so the documented path returns `403` with the token the deployment actually
provisions. Hit live during the #172 remediation.

This is a **token-width** gap, not an authority gap: the grants already
exist and are applied — `maintainer-dev-read.yaml`, `maintainer-dev-prefetch.yaml`
and `maintainer-dev-write.yaml` are all in
`deploy/ansible/files/gitops/auth/grants/`, and the write grant's own comment
states its purpose is "WRITE so `issue-svc-token --permission=write` can be
minted". The deployment declares the authority and then mints a token too
narrow to use it.

## What

1. **Widen the mint** to `--permission read --permission prefetch --permission write`,
   so the token matches the three grants the same repository already
   declares and the how-to already promises. Update the task name, which
   currently says "(read permission)".

2. **Handle the existing-token case — this is the part that is easy to miss.**
   `issue-svc-token` is idempotent *by name*: if a token for
   `maintainer-dev` already exists it exits 0 **without reissuing**
   (`crates/hort-server/src/cli/admin.rs`, "Idempotent: if the named token
   already exists it is NOT rotated (operator forces rotation by passing
   `--rotate`)"). So changing the permission flags alone leaves every
   existing install on the old read-only token, and the playbook reports
   success. A fresh install would get the wide token; an upgraded one
   silently would not — the worst kind of divergence, because it is
   invisible until someone runs a rescan.

   Do **not** simply add `--rotate` to the task: that would reissue the
   token on *every* playbook run and break anything still holding the
   previous value. Pick one and say why in the task comment:
   - a one-time rotation guarded so it cannot re-fire (e.g. keyed on the
     token file's absence, or an explicit `-e` flag the operator passes
     once), or
   - leave the task idempotent and document the one-time
     `--rotate` command in the how-to as an upgrade step.

   Either is defensible; an unguarded `--rotate` in the standing task is
   not.

3. **Reconcile the how-to** with whatever step 2 chooses. §3's table is
   already correct about the grants; what it lacks is the upgrade note for
   installs provisioned before this change.

## Out of scope

`maintainer-curator` — its `--permission curate` matches its single grant
and its documented role. Leave it alone.

## Done when

A freshly provisioned host, and an upgraded one that has followed the
documented step, can both run `hort-cli admin rescan <artifact-id>` with
`/run/secrets/hort-dev.token` and get `202` rather than `403`.
