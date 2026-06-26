# 0037 — gitops `PermissionGrant` may target a ServiceAccount by name

- **Status:** Accepted
- **Enforced by:** `GrantSubjectSpec::ServiceAccount { name }` in
  `crates/hort-config/src/permission_grant.rs`, resolved at apply to the domain
  `GrantSubject::User(backing_user_id)` by the apply pipeline
  (`crates/hort-app/src/use_cases/apply_config_use_case.rs`); the apply-time
  linter in `crates/hort-app/src/lint/static_validate.rs`; diff/desired handling
  in `crates/hort-config/src/diff.rs` and `crates/hort-config/src/desired.rs`.
  Domain invariant: the `GrantSubject` enum stays **two-variant**
  (`Claims | User`) — there is no `GrantSubject::ServiceAccount`. Alpha-fixture
  linter regression: `crates/hort-server/tests/alpha_fixture_linter.rs`.
- **Supersedes:** —
- **Relates:** [0012](0012-claim-based-rbac-claimless-static-tokens.md) (the
  `GrantSubject` taxonomy and the SA-authority-via-`User`-grants rule — **not
  reopened** by this ADR), [0018](0018-auth-catalog-canonical.md) (auth-catalog
  Entry 4, ServiceAccount), [0038](0038-admin-identity-model.md) (the de-admin
  reset this grant shape enables).

## Context

A `ServiceAccount` gitops envelope confers authority through its `role`
(`reader` / `developer`) and `repositories` list — a per-repo `Read` /
`Read+Write` shape. That envelope **cannot express** several authorities a
non-admin SA legitimately needs:

- **Global (non-repo-scoped) capabilities** — e.g. `admin_task_invoke` (may
  enqueue an admin task) is a global capability, not a per-repo one, and is not a
  field on the SA envelope.
- **`curate`** — releasing quarantined artifacts — is not a `reader`/`developer`
  role.
- **A grant scoped differently from the envelope's repo list.**

Before this ADR a `PermissionGrant` subject could only be `Claims` (an IdP group)
or `User` (a concrete user id). A service account has a backing user id, but it
is allocated at apply time — an operator writing gitops YAML does not know it and
must not hardcode it. So expressing "this named SA holds `admin_task_invoke`
globally" was impossible without either inventing an admin-backed SA (the
anti-pattern ADR 0038 retires) or hand-resolving the backing user id.

This shape is foundational for the de-admin reset (ADR 0038): once
`issue-svc-token` refuses `--permission=admin`, the cron/maintainer SAs need a
way to hold scoped non-admin authority (`admin_task_invoke` for task-invoke,
`curate` for early-release, global `read`) declaratively in the audited gitops
tree.

## Decision

**Add `GrantSubjectSpec::ServiceAccount { name }` — a gitops-spec sugar that the
apply pipeline resolves to the domain `GrantSubject::User(backing_user_id)`.**

- The new variant lives only in the **config/spec** layer
  (`hort-config`). It is YAML the operator writes:

  ```yaml
  kind: PermissionGrant
  spec:
    subject:
      kind: serviceAccount
      name: cronjob-tasks
    permission: admin_task_invoke   # no repository: -> global
  ```

- At apply time the pipeline looks up the named SA's backing user id and persists
  the grant as `GrantSubject::User(backing_user_id)` — exactly the row a
  `User`-subject grant would produce. The grant becomes effective the moment the
  SA aggregate exists.
- **The domain `GrantSubject` taxonomy is UNCHANGED — still `Claims | User`.**
  There is no `GrantSubject::ServiceAccount`. ADR 0012's two-variant closure and
  its "SA authority flows exclusively through `GrantSubject::User`" rule are
  preserved; this is sugar at the apply boundary, not a new domain concept.
- Apply-time linting validates the named SA exists (a grant naming an absent SA
  is rejected at apply, not silently inert — ADR 0015 discipline).

## Consequences

- A **non-admin** service account can hold scoped `Read` / `Curate` /
  `AdminTaskInvoke` / global grants declaratively in the gitops tree, all through
  the audited apply path. This is what lets the reset's cron and maintainer SAs
  drop `is_admin` entirely (ADR 0038): `cronjob-tasks` gets a standalone
  `admin_task_invoke` grant, `maintainer-curator` a `curate` grant,
  `maintainer-dev` a global `read` grant — none of them admin.
- The domain stays minimal: one apply-boundary resolution, no new domain variant,
  no migration to a third `GrantSubject` arm, no change to the RBAC evaluator
  (which still sees `User`-subject grants).
- A grant naming an SA that does not exist fails apply rather than persisting an
  unmatched/inert row.
- ADR 0012 is **not reopened** — this ADR explicitly preserves its taxonomy and
  its SA-authority-via-`User`-grants rule.

## Alternatives considered

- **Add `GrantSubject::ServiceAccount` to the domain.** Rejected — it widens the
  domain taxonomy (a new match arm everywhere `GrantSubject` is consumed, a new
  persisted shape, a third arm in the RBAC evaluator) to express something the
  existing `User` arm already models once the backing user id is resolved.
  Apply-boundary sugar is the smaller, ADR-0012-preserving change.
- **Require operators to hardcode the backing user id in a `User`-subject
  grant.** Rejected — the backing user id is apply-time-allocated and not knowable
  when authoring gitops; hardcoding it is brittle and couples the YAML to an
  internal id.
- **Keep using admin-backed SAs for global capabilities.** Rejected — that is
  precisely the standing-privilege anti-pattern ADR 0038 retires; this grant shape
  is the non-admin replacement for it.

## References

- `crates/hort-config/src/permission_grant.rs` — `GrantSubjectSpec::ServiceAccount`.
- `crates/hort-app/src/use_cases/apply_config_use_case.rs` — apply-time resolution
  to `GrantSubject::User(backing_user_id)`.
- `crates/hort-app/src/lint/static_validate.rs` — apply-time validation.
- `deploy/ansible/files/gitops/auth/grants/` — the cron/maintainer
  serviceAccount-subject grants the reset ships (ADR 0038).
- [0012](0012-claim-based-rbac-claimless-static-tokens.md) — the unchanged
  `GrantSubject` taxonomy and SA-authority rule.
- [0038](0038-admin-identity-model.md) — the admin-identity reset this enables.
