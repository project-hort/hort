# Operating claim-based RBAC

This guide is for operators who manage authorization on an
hort deployment under the **claim-based RBAC** model.
It covers the mental model, the gitops
YAML you write, how gitops ServiceAccounts behave under this
model, the PATCH-via-PAT snapshot wrinkle, the apply-config linter and
how to tune it, the effective-permissions audit endpoint, and how to
translate the old `roles:` / `group_mappings:` YAML.

For the design rationale — *why* additive-claims over structural
`(role, org)` RBAC, the invariants, and the audit tooling — see
[ADR 0012](../../../adr/0012-claim-based-rbac-claimless-static-tokens.md).

---

## 1. The mental model

There is no `roles` table any more. Authority is the composition of
two operator-declared tables plus a sum-typed grant subject:

| Concept | Shape | What it does |
|---|---|---|
| `claim_mappings` | `(idp_group, claim)` rows | At OIDC / CLI-session login, the caller's IdP `groups` claim is resolved into a flat **set of claim names** via these rows. One IdP group can map to several claims; several IdP groups can map to the same claim. |
| `permission_grants` (Claims subject) | `(required_claims[], repository_id?, permission)` | The caller satisfies the grant when `required_claims ⊆ caller.claims`. Multi-dimensional scoping is just a longer claim list — `[developer, team-alpha]` requires *both*. |
| `permission_grants` (User subject) | `(user_id, repository_id?, permission)` | A direct binding to one user-id. Bypasses claims entirely. This is how service accounts and one-off break-glass escalations are expressed. |
| `GrantSubject` sum type | `Claims(Vec<String>) \| User(Uuid)` | A grant is *either* claim-gated or user-bound. The two-variant taxonomy is deliberately closed; adding a third variant requires re-opening the design (ADR 0012). |

Key rules an operator must internalise:

- **There are no roles in the data layer.** A "role" you used to
  declare is now a *claim name*. Whatever you used to call
  `developer` becomes a `claim_mappings` row mapping your IdP's
  developer group to the claim `developer`, plus N grant rows
  requiring that claim.
- **`is_admin` and the synthetic `admin` claim are kept in sync by
  construction.** A user who is admin (bootstrap-admin Local user, or
  an OIDC user whose mapped claims include `admin`) carries a
  synthetic `admin` claim in *every* principal-build path. Auditors
  can query the bit or the claim and get the same answer (an
  ADR 0012 invariant).
- **Long-lived static tokens are deliberately under-privileged.** A
  PAT (or any machine-identity bearer) carries `claims: []`,
  or `claims: ["admin"]` only when `user.is_admin=true`. PATs never
  consult `claim_mappings`. This is a permanent design choice
  (ADR 0012), not a limitation — see §3 below
  for how to grant a long-lived-token actor non-admin authority.
- **Empty `required_claims` is rejected.** The DB `claims_nonempty`
  CHECK and the linter both refuse a zero-element claim set (it would
  be an everyone-grant).

---

## 2. Operator YAML examples

The gitops surface (`$HORT_CONFIG_DIR/auth/`) gains `kind: ClaimMapping`
and a rewritten `kind: PermissionGrant`. `kind: Role` and
`kind: GroupMapping` are **removed** — declaring them is a fatal apply
error.

### `kind: ClaimMapping` — map an IdP group to a claim

```yaml
apiVersion: project-hort.de/v1beta1
kind: ClaimMapping
metadata:
  name: developers
spec:
  idpGroup: hort-developers   # verbatim match against the OIDC groups claim
  claim: developer                       # the resolved claim name
---
apiVersion: project-hort.de/v1beta1
kind: ClaimMapping
metadata:
  name: team-alpha
spec:
  idpGroup: team-alpha
  claim: team-alpha
---
apiVersion: project-hort.de/v1beta1
kind: ClaimMapping
metadata:
  name: admins
spec:
  idpGroup: hort-admins
  claim: admin                           # the admin claim — see §5 reserved names
```

### `kind: PermissionGrant` — claim-gated grant

```yaml
apiVersion: project-hort.de/v1beta1
kind: PermissionGrant
metadata:
  name: alpha-devs-write-pypi-alpha
spec:
  subject:
    kind: claims
    required: [developer, team-alpha]    # caller must carry BOTH claims
  permission: write
  repository: pypi-alpha
```

This is the direct expression of the classic per-repo example
"`team-alpha → developer` only for `pypi-alpha`": one grant on
`pypi-alpha` requiring the two-element claim set. No `GroupMapping.repositories`
field, no second dimension column — the flat claim set is the
scoping mechanism.

### `kind: PermissionGrant` — direct user grant (break-glass)

```yaml
apiVersion: project-hort.de/v1beta1
kind: PermissionGrant
metadata:
  name: incident-2026-05-bob-admin
spec:
  subject:
    kind: user
    userId: "8b1f...-...-..."            # a concrete users.id
  permission: admin
  # OMIT `repository` for a global grant
```

A `User`-subject `admin` grant with no justification is **rejected**
by the linter (§5). Bind it to an explicit, audited annotation or use
a claim-gated grant instead unless this is a genuine break-glass case.

### Bundle-via-templating (the replacement for roles)

There is no server-side role bundle. Express a "role" as a claim plus
the set of grants that claim implies, using your gitops tool's
templating (Helm anchors, Kustomize, Terraform locals, a pre-processor):

```yaml
# Helm-style YAML anchor: "developer" expands to read+write on two repos
_developerGrants: &developerGrants
  - { permission: read,  repository: pypi-internal }
  - { permission: write, repository: pypi-internal }
  - { permission: read,  repository: npm-internal }
  - { permission: write, repository: npm-internal }
# ... then emit one PermissionGrant per entry with
#     subject: { kind: claims, required: [developer] }
```

The verbosity cost is operator-side and deliberate
("roles-as-permission-bundles in the data layer" is closed
indefinitely). The benefit is one fewer entity and one fewer join in
the evaluator.

---

## 3. ServiceAccounts under claim-based RBAC

ServiceAccounts declared via `kind: ServiceAccount`
(see [`../federate-ci-oidc.md`](../federate-ci-oidc.md) and
[`../federate-k8s-workload-identity.md`](../federate-k8s-workload-identity.md))
are declared with `role:` and
`repositories:`:

```yaml
apiVersion: project-hort.de/v1beta1
kind: ServiceAccount
metadata:
  name: ci-deployer
spec:
  role: developer            # fixed enum: developer | reader
  repositories: [pypi-internal, npm-internal]
  federatedIdentities:
    - issuer: github-actions
      claims:
        repository: my-org/my-repo
        ref: refs/heads/main
```

What happens *underneath*:

- The SA's authority is materialised as **`User`-subject permission
  grants** bound to the SA's backing user (`is_service_account=true`,
  `username = "sa:" || name`). It is **not** a `claim_mappings`
  entry, and `sa.role` is **not** an operator claim-taxonomy name.
- `sa.role` (`developer` / `reader`) is expanded to a concrete
  `Permission` by a code-level function
  (`service_account_permission_for_role`) over the fixed two-value
  enum — the only sanctioned role-name→permission mapping, exempt
  from the "no runtime-invented claims" invariant.
- **Federated and fallback-rotated SA bearers carry `claims: []`.**
  A federated workload's foreign-JWT
  `groups` claim is **never** run through `claim_mappings`. An admin
  ServiceAccount is forbidden at apply time, so SA `claims`
  is always exactly `[]`.

Operator takeaway: **grant ServiceAccount authority via the SA CRD's
`role` / `repositories`, never via `claim_mappings`.** Adding a
`claim_mappings` row in an attempt to widen an SA's authority does
nothing — the SA bearer never resolves claims. To change what a
ServiceAccount can do, edit its `role` / `repositories` in the
`kind: ServiceAccount` envelope.

### 3.1 Prefer a durable `User`-subject Admin grant for `HORT_TOKEN_ALLOW_ADMIN` deployments

`is_admin` is recomputed from the IdP `groups` claim and **persisted**
onto the user row on *every* OIDC login. That is the
intended mechanism — the IdP group is the admin source of truth, not a
stale DB row. The accompanying observability: every persisted `is_admin` **flip** emits an
`AdminStatusChanged` audit event on the per-user stream
(`StreamId::user(user_id)`) plus the
`hort_is_admin_transition_total{result ∈ {granted, revoked}}` metric.
JIT-create and an idempotent recompute that does not change the bit are
silent — the signal is the *transition*, so a spurious flip stands
out.

Why this matters for one deployment class: a transient IdP outage or an
empty-`groups` response recomputes `is_admin=false` for a legitimate
admin (and a spurious resolve persists a wrong `true`). In the default
posture this is largely contained — the token-cap AND
means a normal PAT held by a user whose bit was spuriously flipped
**cannot** exercise admin (the cap leg independently requires
`Permission::Admin`). The bounded residual is the
**`HORT_TOKEN_ALLOW_ADMIN=true`** deployment class: admin-capable PATs
exist (≤30 d clamp), so a single bad login can yield durable admin for
up to the PAT's life.

**Operator recommendation.** If you run with
`HORT_TOKEN_ALLOW_ADMIN=true`:

1. **Alert on `hort_is_admin_transition_total`.** A flip outside a
   planned access change — especially a burst of `revoked` during an
   IdP incident, or an unexpected `granted` — is the signal to act on.
   Correlate with the per-user `AdminStatusChanged` events for
   who/which `sub`.
2. **Make a durable `User`-subject `Admin` grant the admin source of
   truth**, not the purely-IdP-derived persisted bit. Declare a
   `kind: PermissionGrant` with `subject: User(<uuid>)`,
   `permission: admin`, and a justification annotation (the linter
   **rejects** an unjustified `User`-subject admin grant — see §5),
   exactly as the break-glass example in §2 (`kind: PermissionGrant`
   — direct user grant). A `User`-subject grant does not evaporate on
   the next empty-`groups` login, so admin authority survives an IdP
   wobble that would otherwise flip the IdP-derived bit.

This is a defense-in-depth recommendation, not a forced code change:
the cap-AND is the primary control and the design preserves it. The
recommendation is mirrored as a mandatory guardrail on
`docs/auth-catalog.md` Entry 1.

---

## 4. The PATCH-via-PAT-clears-snapshot wrinkle

Event-notification subscriptions
(see [event-notifications.md](../../explanation/event-notifications.md))
capture the owner's resolved claim set in `subscription.snapshot_claims`
**at create and on every update**. The
dispatcher delivers events under the snapshot's authority floor.

The wrinkle: **the snapshot is whatever the *authenticating principal*
carried at the time of the create/update call.**

- If you create or PATCH a subscription while authenticated via
  **OIDC** (a fresh session), the snapshot captures your resolved
  claims (`[developer, team-alpha, …]`). Delivery works for the
  scopes those claims authorize.
- If you PATCH (or create) the same subscription while authenticated
  via a **PAT**, the PAT path carries only `claims: []` (or
  `["admin"]` if you are an admin). The full-replace snapshot
  semantics mean the PATCH **overwrites** the previous rich snapshot
  with the PAT's thin one. A non-admin PAT-driven PATCH therefore
  **clears the subscription's delivery authority** — subsequent
  non-privileged-scope deliveries stop.

This is intentional and safe-by-construction: privileged-category
deliveries re-check live owner-admin status at dispatch,
so a PAT cannot *escalate* a subscription. But it
*can* inadvertently *downgrade* one.

**Operator guidance:** manage subscriptions interactively via an OIDC
session (or `hort-cli` with an OIDC-backed session), not via a bare PAT,
unless you intend the subscription to run under admin-only authority.
If a subscription "stopped delivering after a config script touched
it," check whether the script authenticated with a PAT — re-PATCH it
from an OIDC session to restore the snapshot.

---

## 5. The apply-config linter and tuning strictness

The `ApplyConfigUseCase` linter runs over every `PermissionGrant`
before commit during gitops apply. It is the load-bearing mitigation
for additive-claims' deliberate loss of *server-enforced* structure
(ADR 0012) — it is **secure-by-default**: suspicious
shapes `reject` the whole apply unless the operator has explicitly,
visibly opted out in audited gitops config. CI fails on `reject`.

| Rule | Trigger | Default action |
|---|---|---|
| `single-claim-grant` | A `Claims(_)` grant whose `required_claims` has exactly one element, and that claim is **not** in `single_claim_allowlist`. | **`reject`** — the allowlist is the opt-out |
| `wildcard-repo-non-admin` | A `Claims(_)` grant with no `repository` (global) and `permission != admin`. | **`reject`** |
| `direct-user-grant-without-justification` | A `User(_)` grant with no justification annotation. | **`reject`** when `permission == admin` OR (global AND `permission ∈ {write, delete}`); else **`warn`** |
| `claim-name-collision` | A `ClaimMapping` whose `claim` collides with a reserved name. | **`reject`** |

> **Reserved-name note (as-built).** The reserved set the
> `claim-name-collision` rule enforces is **`{service_account,
> cli_session}`**, not `admin`. `admin` is *deliberately* a
> configurable claim: §5.2 derives `is_admin` from a
> `claim_mappings → admin` row, so rejecting an `admin` claim mapping
> would make the admin-via-IdP-group path un-configurable. Map your
> IdP admin group to the `admin` claim freely; you may **not** map a
> group to `service_account` or `cli_session` (those are token-kind
> facts, not claims).

> **Justification note (as-built).** "Justification" for
> `direct-user-grant-without-justification` means a
> **ServiceAccount-provenance exemption** — SA-owned
> `User`-subject grants are expected and pass. A bare operator-authored
> `User`-subject grant (a hand-written break-glass row) with no SA
> provenance is the shape this rule flags. Do not rely on the presence
> of a `managed_by_digest` value alone to satisfy this rule — every
> gitops-applied grant carries one, so that reading would make the
> rule dead. The faithful reading exempts SA-owned grants and flags
> hand-authored privileged `User` grants.

**Tuning strictness.** Operators tune the linter **only** through
explicit, audited gitops config — there is no env var and no global
`warn` switch (that would re-open the secure-by-default hole). The
escape hatch is the singleton gitops kind
`kind: PermissionGrantLintConfig` (at most one cluster-wide; a second
declaration is a named apply error, never a silent last-wins):

```yaml
apiVersion: project-hort.de/v1beta1
kind: PermissionGrantLintConfig
metadata:
  name: rbac-lint
spec:
  # Each listed claim's single-claim grants downgrade to `pass`
  # (the per-claim opt-out). A claim name must be syntactically
  # valid and must NOT be a reserved name (`admin`,
  # `service_account`, `cli_session`) — those are rejected at apply.
  singleClaimAllowlist: [oncall, platform-readers]
  # Optional per-rule downgrades. A rule may only be *relaxed*
  # (reject → warn / pass); restating or raising the default is a
  # no-op the validator rejects (drop the field instead). Omit a
  # rule to keep its secure default. `claim-name-collision` has no
  # knob (always reject). Every downgrade shows up in the apply
  # diff for the auditor.
  ruleOverrides:
    singleClaimGrant: warn          # default reject
    wildcardRepoNonAdmin: warn      # default reject
    # directUserGrant: pass         # default reject (high-priv arm)
```

> **Reachability (as-built).** This kind is the
> opt-out. It did not always exist (`kind: LintConfig` would
> fail boot with `UnknownKind`, and the production apply path was
> hardwired to the secure default, so *every* single-claim grant
> rejected unconditionally). It is now parsed by
> `hort-config` and resolved **before** the grant linter runs in the
> same apply, so you can add an allowlist entry **and** a
> single-claim grant using that claim **in one commit** and the
> apply succeeds. A bundle with **no** `PermissionGrantLintConfig`
> keeps the secure default (every suspicious shape rejects) — a
> missing kind is **not** a downgrade.

Adding a claim to `singleClaimAllowlist` downgrades **only that
claim's** single-claim grants to `pass` — it is not a global
relaxation. Every downgrade is visible in the gitops diff and audited.

> **Atomicity caveat (known follow-on).** The
> `claim-name-collision` check is **not** strict-atomic with the
> grant linter: `apply_claim_mappings` commits its partition before
> the `apply_permission_grants` linter seam runs. The CI-gate
> property still holds — a bundle containing a reserved-claim mapping
> *does* fail the overall apply, so the operator's CI goes red and
> the bad config never fully succeeds — but the claim-mapping
> partition is not rolled back in the same transaction. A future
> follow-on hoists `claim-name-collision` to a
> pre-`apply_claim_mappings` strict-atomic check. Until then: treat a
> failed apply as "fix the YAML and re-apply," not "partial state is
> safe to leave."

Linter outcomes emit `hort_apply_config_linter_total{rule, result}`
(`result ∈ {pass, warn, reject}`) — alert on `reject > 0` in your CI
apply step.

---

## 6. Auditing effective permissions

To answer "what can Alice actually do?" use the admin endpoint or the
`hort-cli` subcommand — do not reconstruct it by hand from the grant
table.

```
GET /api/v1/admin/users/{user_id}/effective-permissions
  Authorization: <admin token>
```

```json
{
  "user_id": "...",
  "claims": ["developer", "team-alpha", "admin"],
  "is_admin": true,
  "grants": [
    { "repository_id": "...",  "permission": "write", "source": { "kind": "claims", "required": ["developer", "team-alpha"] } },
    { "repository_id": null,   "permission": "admin", "source": { "kind": "claims", "required": ["admin"] } },
    { "repository_id": "...",  "permission": "write", "source": { "kind": "user" } }
  ]
}
```

CLI equivalent (table or JSON output):

```bash
hort-cli admin users effective-permissions <user_id>
hort-cli admin users effective-permissions <user_id> --output json
```

Notes:

- Admin-only (`Permission::Admin`).
- `claims` reflects the user's resolved claims **from their last
  successful OIDC login** — empty if they have never logged in via
  OIDC. A user who only ever authenticates via PAT shows the PAT
  path's effective set (synthetic-`admin` only, or empty).
- The `grants` list is every grant that *currently* matches the
  user — claim-gated grants the user's resolved claims satisfy, plus
  every `User`-subject grant bound to them.
- This is the operator-discipline mitigation: the trade for losing
  server-enforced structure is that you can always ask one endpoint
  the question an auditor cares about.

---

## 7. Migrating from the old `roles:` / `group_mappings:` YAML

The old shape **fails apply** under claim-based RBAC (pre-v1.0; the
cutover is hard, no feature flag). Translate it mechanically:

### Old `kind: GroupMapping` → `kind: ClaimMapping`

```yaml
# OLD
kind: GroupMapping
spec:
  group: hort-developers
  role: developer
```

```yaml
# NEW — the `role` name becomes a `claim` name verbatim
kind: ClaimMapping
spec:
  idpGroup: hort-developers
  claim: developer
```

### Old `kind: Role` → deleted

There is no replacement object. A `kind: Role` declaration is removed
entirely. The role's *meaning* survives as: (a) the claim name (from
the translated `ClaimMapping`), and (b) the set of `PermissionGrant`
rows that used to reference the role by `role:`, rewritten to require
the claim.

### Old `kind: PermissionGrant` (role-referencing) → claim-subject grant

```yaml
# OLD — references the role by name; Cartesian product of arrays
kind: PermissionGrant
spec:
  role: developer
  permissions: [read, write]
  repositories: [pypi-internal, npm-internal]
```

```yaml
# NEW — one grant per (permission, repository); subject is the claim set.
# (Use templating to avoid hand-expanding the Cartesian product.)
kind: PermissionGrant
metadata: { name: developer-read-pypi-internal }
spec:
  subject: { kind: claims, required: [developer] }
  permission: read
  repository: pypi-internal
---
kind: PermissionGrant
metadata: { name: developer-write-pypi-internal }
spec:
  subject: { kind: claims, required: [developer] }
  permission: write
  repository: pypi-internal
# ... and the two npm-internal grants likewise
```

Translation checklist:

1. Every `GroupMapping` → a `ClaimMapping` with `claim` = the old
   `role` value, `idpGroup` = the old `group` value.
2. Delete every `kind: Role` object.
3. Every role-referencing `PermissionGrant` → one `subject: { kind:
   claims, required: [<role-name>] }` grant per
   `(permission, repository)` pair (use gitops templating for the
   product).
4. Anything that was a per-user override → `subject: { kind: user,
   userId: <uuid> }`, and expect the linter to want a justification
   for privileged ones.
5. Run the apply in a non-production environment first. The linter is
   `reject`-by-default — a `single-claim-grant` like
   `required: [developer]` will be rejected unless you add `developer`
   to `singleClaimAllowlist`. This is expected: decide per claim
   whether a single-claim grant is intended (most are — that is what
   a "role" was) and allowlist it explicitly.
6. Dev environments running the prior `001` / subscriptions schema
   must drop the affected tables and re-migrate (pre-v1.0, in-place
   migration edits —
   [ADR 0022](../../../adr/0022-pre-1.0-edit-existing-migrations.md)).
   There is no data migration path.
