# 0067 — Destructive authority is a permission, split by reversibility

- **Status:** Accepted
- **Enforced by:** `Permission::{DestroyContent, DestroyRecord}` and the
  kind-to-authority pairing that names them — two constants whose union is
  `DESTRUCTIVE_TASK_KINDS`, so "is this kind destructive?" and "under which
  authority?" cannot drift apart. The orthogonality to `Admin` is one
  declaration, `ADMIN_ORTHOGONAL_PERMISSIONS` with
  `Permission::is_admin_orthogonal()`, rather than a comparison each reader
  writes for itself.
- **Supersedes:** the `task:destructive`-as-claim property recorded in
  [0038](0038-admin-identity-model.md) §4, whose heading and reasoning this
  decision rewrites while leaving 0038's own decisions intact.
- **Relates:** [0028](0028-destructive-task-idempotency.md) (the task-row
  lifecycle a destructive kind moves through),
  [0038](0038-admin-identity-model.md) (the admin identity model this splits
  authority away from), [0046](0046-admintasks-operator-provisioned-sa-loud-preflight.md)
  (operator-provisioned service accounts, D3),
  [0052](0052-scoped-metrics-read-capability.md) (the first admin-orthogonal
  permission, whose carve-out this declaration subsumes).

## Context

Destructive housekeeping — purging artifact content, deleting an audit record —
was gated by a `task:destructive` **claim**. A claim is carried by a session,
so the gate read as "a fresh, claim-bearing admin session, never a static
token", and that reading was load-bearing in two places: it justified refusing
a machine identity the authority at all, and it stood in for a freshness
guarantee.

Both halves were weaker than they read. An admin PAT carried the synthetic
`admin` claim and passed the gate, so "never a static token" was never true.
What the claim actually bought was not freshness but the CLI-session lifetime
cap — a real property, and a different one.

Meanwhile the authority itself was one undifferentiated thing. Purging an
artifact's bytes leaves `ArtifactPurged` and a row that says what was removed;
deleting an audit record leaves nothing that reconstructs it. Those are not the
same risk, and one permission cannot express the difference.

## Decision

### 1. Destructive authority is a permission, not a claim

`Permission::DestroyContent` and `Permission::DestroyRecord` are grantable
permissions in the ordinary RBAC model. A claim is how an identity provider
describes a person; a permission is what this system grants. Destructive
authority is the second kind of statement, and modelling it as the first is
what made a machine identity unable to hold it.

### 2. The split runs along reversibility

- **`destroy_content`** — artifact content. Its removal is recorded:
  `ArtifactPurged` names what went, so the system can still answer what it
  used to hold.
- **`destroy_record`** — the audit record itself. Nothing reconstructs it.

Reversibility is the axis because it is the axis the operator's risk follows.
A grant that covers both is then a deliberate act rather than an accident of
one name covering two consequences.

### 3. Both are orthogonal to `Admin`

Neither permission is implied by `Admin`, and neither implies it. An admin
without the grant cannot run a destructive task, and an identity holding the
grant is not thereby an admin. This is the same shape
[0052](0052-scoped-metrics-read-capability.md) established for `ReadMetrics`
and for the same reason: an authority that is dangerous in a different
direction from administration should not ride along with it.

**0052's carve-out is now expressed by this declaration rather than by its own
comparisons.** `ReadMetrics` is the third member of
`ADMIN_ORTHOGONAL_PERMISSIONS`; 0052's decision is unchanged and only the
mechanism is shared. Both records say so, so neither reads as owning the rule
alone.

## What this decision does not say

**It does not grant anyone the authority.** It says what the authority is and
how it is shaped. Who holds it is a grant, and a grant is gitops the operator
writes.

**It does not loosen the apply linter, and that is a decision rather than an
omission.** Destructive task authority must be **global** — the gate asks at
`repository = None` — and the linter rejects every *humanly reachable* shape
of such a grant: a global `User`-subject grant of an admin-class permission
trips `direct-user-grant-without-justification`, and a global `Claims`-subject
grant trips `wildcard-repo-non-admin` (which exempts only `Permission::Admin`
itself), with a single claim additionally tripping `single-claim-grant`, not
allowlistable for `admin`.

So the only lint-clean holder is a `serviceAccount`-subject grant, and a human
operator who wants the authority must pair it with an audited
`PermissionGrantLintConfig` downgrade. **That consequence is documented rather
than designed away.** The human case is the exception — an operator triggering
a destructive task by hand — and blessing a global user-subject grant of an
admin-class permission would weaken a rule that exists for good reason. It
aligns with 0052's own recorded asymmetry: *"a scrape capability should be
bound to one declared identity, not to whoever currently carries a claim."*
Teaching the linter this shape is a separate unit if it is ever wanted.

**It does not promise that every grant survives to execution.** A destructive
task is authorised at the API and re-checked at execution, and the re-check
builds the requester from the `users` row, which persists no IdP claims. A
`User`-subject grant survives the wait; so does a `Claims(["admin"])` grant
while its holder is still an admin. A destructive grant bound to **any other
claim** is accepted at the API and refused at execution, every time. The rule
is therefore that only an **identity-reachable** destructive authority survives
the wait — not, as an earlier formulation had it, only an admin's.

## Consequences

A machine identity can hold destructive authority through the ordinary grant
path, which is what makes unattended destructive housekeeping expressible at
all. [0038](0038-admin-identity-model.md) §4's standing point survives in its
new form — destructive authority is never *ambient* admin authority — and the
claim-shaped reasoning that used to carry it is retired there with a note
saying which half of it had already been false.

[0046](0046-admintasks-operator-provisioned-sa-loud-preflight.md) D3's
alternative "auto-provision a destructive-authority service account" loses its
*impossible* half; its core rejection — the chart writes no gitops — stands on
its own and is unaffected.

The token-issuance bracket inherits the orthogonality without a reader of its
own: it calls `rbac.authorize` per declared cell, so an admin without the grant
cannot mint a PAT carrying `destroy_content`. That is the obvious place for a
bypass, it was searched for, and the absence is recorded here so the next
reader does not have to search again.
