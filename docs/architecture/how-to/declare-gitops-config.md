# Declare configuration via `$HORT_CONFIG_DIR` (gitops)

This guide is for operators who want to manage `hort`
configuration as YAML files instead of via the admin REST API.

The model is **files-in, startup-only**: hort-server reads a directory
of YAML at boot, validates everything, and applies the diff against
the database before binding the listener. The API then refuses
writes against any object that came from `$HORT_CONFIG_DIR` —
modifications happen by editing YAML and restarting the process.

hort-server has no git client, no poller, and no reconciliation loop.
How the YAML files reach the directory (`git clone`, Flux, a volume
mount, an init container that bakes them into the image) is the
operator's choice.

For the apply-time linter and naming rules see
[ADR 0015](../../adr/0015-apply-time-linter-inert-fields-and-naming.md);
for cross-opt-in interaction rules see
[ADR 0016](../../adr/0016-cross-opt-in-interaction-matrix.md).

---

## 1. Directory layout

```
$HORT_CONFIG_DIR/
├── repositories/
│   ├── npm-public.yaml
│   ├── pypi-internal.yaml
│   └── all-npm.yaml
└── auth/
    ├── admins.yaml
    └── readers.yaml
```

One object per file. The `repositories/` and `auth/` subdirectories
are convention only — hort-server walks `$HORT_CONFIG_DIR` recursively
and dispatches by the YAML's top-level `kind:` field. Hidden files
and hidden directories (anything starting with `.`) are skipped, so
you can keep `.git/` next to your config without poisoning the
apply.

`$HORT_CONFIG_DIR` is the **only** loader path for declarable
configuration. The legacy `HORT_GROUP_MAPPINGS_PATH`
single-file loader, the multi-object `mappings: [...]` root shape, and
the synthetic `<group>-to-<role>` filename pattern were removed
pre-v1.0; operators upgrading from older builds must migrate any
remaining single-file group-mappings YAML into one canonical envelope
per file under `$HORT_CONFIG_DIR/auth/`. A file declaring the legacy
`mappings:` root shape now fails the boot apply with
`ParseError::UnsupportedShape`.

---

## 2. Envelope shape

Every object shares the same four-field envelope:

```yaml
apiVersion: project-hort.de/v1
kind: <ArtifactRepository | ClaimMapping | PermissionGrant | CurationRule | ScanPolicy | Exclusion | UpstreamMapping | OidcIssuer | ServiceAccount | RetentionPolicy | PermissionGrantLintConfig>
metadata:
  name: <unique-within-kind>
spec:
  <kind-specific>
```

The canonical list of kinds lives in `crates/hort-config/src/envelope.rs`
(`Kind::KNOWN`); each per-kind section below documents the spec
shape and apply semantics. The claim-based RBAC cutover retired
`kind: GroupMapping` (and `kind: Role`) and replaced the
IdP-group → role mapping with `kind: ClaimMapping` (IdP-group →
registry-claim). Declaring a retired kind is a fatal boot-apply
error — `ParseError::UnknownKind` with the current allow-list
rendered in the message.

`apiVersion: project-hort.de/v1` is the only accepted version. The
`v1alpha1` suffix signals "subject to change without a deprecation
window" — re-emit your YAML when a new variant lands.

Unknown fields anywhere in `spec` fail validation: typos surface at
boot, not as silent defaults.

---

## 3. `kind: ArtifactRepository`

```yaml
apiVersion: project-hort.de/v1
kind: ArtifactRepository
metadata:
  name: npm-public
spec:
  name: "npm Public Mirror"
  description: "Pull-through cache for the public npmjs.org registry"
  format: npm
  type: proxy
  storage:
    backend: filesystem
    path: /var/lib/hort-server/cas/npm-public
  proxy:
    upstreamUrl: "https://registry.npmjs.org"
  isPublic: true
  replicationPriority: immediate
```

Fields map 1:1 to the persisted `Repository` shape. Notable rules:

- `metadata.name` becomes `Repository.key`. Must match
  `^[a-z][a-z0-9-]{0,62}$`.
- `type` is one of `hosted | proxy | virtual | staging`.
- `proxy:` block is **required** when `type: proxy`, **forbidden**
  otherwise. Symmetric for `virtualMembers:` and `type: virtual`.
- `storage:` block is **optional**. Omit it to
  inherit the deployment's effective global backend — per-repo
  `storage` is not routing-effective in v2 (the single global CAS is
  authoritative); a per-repo `backend` differing from the deployment's
  global backend is rejected at apply. `backend` (when present) must
  be `filesystem` or `s3`.
- `proxy.credentials` is **forbidden forever** as a plaintext
  anti-pattern (`ParseError::CredentialsFieldForbidden`). Use
  `proxy.secretRef:` — references a secret resolved
  from an env var or mounted file at runtime; see
  `docs/architecture/how-to/wire-secrets.md` for examples. A
  malformed `secretRef.location` (non-absolute file path; non-POSIX
  env-var name) returns `ParseError::SecretRefLocationInvalid` at
  parse time.
- For multi-upstream proxy repositories (OCI mirrors fronting
  multiple registries under different path prefixes), declare per-
  upstream credentials via the standalone `kind: UpstreamMapping`
  envelope. See §6 for the gitops writer status; the YAML schema
  lives in `crates/hort-config/src/upstream_mapping.rs`.
- `${ENV_VAR}` interpolation works in `description`, `storage.path`,
  and `proxy.upstreamUrl`. Use `$$` for a literal `$`. Missing vars
  fail loudly.

### Virtual repositories

A `type: virtual` repository aggregates several **member** repositories
behind a single URL (one registry endpoint serving your private packages
*and* a public mirror). It is **read-only**: it has no own store and
resolves every request by composing its members' existing, already-gated
serve paths (ADR 0031).

```yaml
spec:
  name: "npm (private + public)"
  format: npm
  type: virtual
  virtualMembers:
    - npm-internal     # private hosted owner (highest priority)
    - npm-public       # public pull-through proxy (lowest priority)
  isPublic: true
  replicationPriority: on_demand
```

**Serve-supported formats: `npm`, `pypi`, `cargo`, `maven`, `gradle`.** A
`type: virtual` repo on any other format (`oci`, …) is **rejected at
apply** — its `virtualMembers` would be accepted but never served (the
ADR 0015 inert-field guard). The supported set is the single source of
truth in `crates/hort-config/src/repository.rs`
(`VIRTUAL_SERVE_SUPPORTED_FORMATS`).

Members must reference other ArtifactRepository objects in the same
`$HORT_CONFIG_DIR`. Mixing a managed virtual with `Local` (API-created)
members is rejected — keep the gitops surface self-contained, or keep the
virtual itself `Local`. A member that is itself `type: virtual` is rejected
(no nested virtuals in v1).

**Every member must declare the virtual's own `format`.** A member on
another format is an apply-time rejection
(`virtual_member_format_not_enforced`): there is no
format-compatibility model — neither apply nor serve-time member
resolution compared the two — so such a member is resolved for the
virtual's format regardless, and a non-proxy one additionally **owns**
the names it holds there (the pinning rule below), suppressing the
virtual's other members for every one of them while serving nothing the
client can install. A cross-format aggregate is one virtual per format,
not one virtual over several.

> **⚠️ Member order is load-bearing — and repo type is the ownership
> signal.** `virtualMembers` is an **ordered priority list** (index 0 =
> highest priority). Two security-critical rules follow, both designed to
> stop dependency-confusion substitution; understand them before composing
> a virtual:
>
> - **Same-version (authoritative member).** For a coordinate that exists
>   in more than one member, the **highest-priority member that has it
>   wins — in any quarantine status**. A version held (quarantined /
>   rejected) in a higher-priority member is *never* silently replaced by
>   a lower-priority member's released copy; the held member's gate is
>   surfaced (503 / 403) instead. Put your trusted/private members first.
> - **New-version (name-level pinning).** A package **name** owned by any
>   **non-proxy** member (a `hosted`/`staging` member with ≥1 version of
>   that name) is **never served from a proxy member, for any version** —
>   index *or* download. So an attacker publishing `internal-pkg@9.9.9` to
>   a public registry cannot have it served through a virtual that includes
>   your private `internal-pkg` owner: the proxy is excluded for that name
>   entirely. Repo type (non-proxy = owner) is the ownership signal.
> - **Fail-closed.** If a non-proxy member's fetch *errors* (an
>   infrastructure failure, distinct from a clean "absent"), it is treated
>   as a *potential owner* and proxies stay suppressed for that name — a
>   transient outage of the trusted owner cannot re-open the confusion
>   window.
>
> Quarantine + scan is the *backstop*, not the substitution defence —
> pinning is. A clean-scanning typosquat would pass a scan; pinning stops
> it from ever being served under an owned name.

Auth composes per member: a caller needs Read on the virtual, and each
member is resolved with the *same* caller. A member the caller cannot Read
is **skipped** (not errored) — so a public virtual that includes a private
member never leaks the private member's contents to an anonymous client.

Reordering `virtualMembers` **does** change serving — it re-pins the
resolution priority on the next apply (the member-edge reconcile compares
declared order against the persisted order and re-pins deterministically).
Note that a *pure reorder* (same set, different order) is reported as
`unchanged` for the repository object itself, because the repo-spec digest
sorts the member list before hashing; the priority is still re-pinned by
the unconditional member reconcile.

---

## 4. `kind: ClaimMapping`

The claim-based RBAC cutover retired the older `kind: GroupMapping` and
`kind: Role` envelopes along with the `roles` / `group_mappings`
tables. `kind: ClaimMapping` replaces them: instead of mapping an
external IdP group to a server-side **role**, the operator declares
which IdP group resolves to which registry **claim** name. Grants
that require that claim are then satisfied for any caller whose
resolved claim set contains it. Roles no longer exist as a
server-side entity — operator-side YAML templating owns permission
bundling (see [`operate/claim-based-rbac.md`](./operate/claim-based-rbac.md)
§2 "Bundle-via-templating").

Declaring a retired `kind: GroupMapping` or `kind: Role` envelope
under `$HORT_CONFIG_DIR` is a **fatal boot-apply error**
(`ParseError::UnknownKind`); the parser rejects the envelope before
any DB write. Migration guidance for legacy YAML is in
[`operate/claim-based-rbac.md`](./operate/claim-based-rbac.md) §7
"Migrating from the old `roles:` / `group_mappings:` YAML".

The canonical schema lives in `crates/hort-config/src/claim_mapping.rs`.

**Spec shape (two required fields):**

- `spec.idpGroup: String` — the external identity-provider
  group-claim value. Matched verbatim against an entry of the
  caller's JWT `groups` claim at authentication time. Must be
  non-blank after trimming.
- `spec.claim: String` — the registry claim name the IdP group
  resolves to. `ClaimMapping` is the only declarable source of
  resolved claim names (an
  [ADR 0012](../../adr/0012-claim-based-rbac-claimless-static-tokens.md)
  invariant) — code paths must
  not invent claim names at runtime. The single synthetic exception
  is the `admin` claim derived from `user.is_admin = true`. Must
  be non-blank after trimming.

`metadata.name` is operator-cosmetic envelope identity; the
mapping's logical identity is `(idp_group, claim)`. Renaming a
file or `metadata.name` while keeping the spec fields fixed is a
no-op.

### Example — IdP group → registry claim

```yaml
apiVersion: project-hort.de/v1
kind: ClaimMapping
metadata:
  name: security-team
spec:
  idpGroup: hort-security-team   # verbatim match against the OIDC groups claim
  claim: curate                             # the resolved registry claim name
```

A caller whose OIDC `groups` JWT claim contains
`hort-security-team` picks up the registry claim
`curate`. A `kind: PermissionGrant` whose
`spec.subject.required` contains `curate` is then satisfied for
that caller — across all repositories if `repository:` is omitted,
or scoped to a single repo if it is present (see §4a's
`PermissionGrant` section).

### Example — multiple groups resolving to the same claim

Several IdP groups can map to the same registry claim (one envelope
per IdP group; `metadata.name` distinguishes the envelopes). This
is the canonical "any of these IdP groups grants this claim" shape:

```yaml
apiVersion: project-hort.de/v1
kind: ClaimMapping
metadata:
  name: developers-from-platform-eng
spec:
  idpGroup: platform-eng
  claim: developer
---
apiVersion: project-hort.de/v1
kind: ClaimMapping
metadata:
  name: developers-from-app-team
spec:
  idpGroup: app-team
  claim: developer
```

A caller in either IdP group resolves the `developer` claim;
combine with `kind: PermissionGrant` envelopes (§4a) to gate
permissions on that claim. The inverse shape — one IdP group
resolving to several claims — is also supported (declare multiple
envelopes with the same `idpGroup` and different `claim` values).

**What apply does:** inserts (or updates) one row in
`claim_mappings` carrying `managed_by = 'gitops'`. The apply emits
`ClaimMappingApplied` on first apply or in-place retarget, and
`ClaimMappingRevoked` when the envelope is removed. Both events
land on the global
`StreamCategory::Authorization` stream — see §7 for the audit-trail
metric coverage and `crates/hort-domain/src/events/authorization_events.rs`
for the payload shapes. Counter:
`hort_gitops_objects_total{kind=claim_mapping,result=created|updated|unchanged|deleted}`.

**Idempotency:** reapplying the identical YAML emits zero writes
and ticks `result=unchanged`. The diff layer keys on
`(idp_group, claim)`.

`HORT_AUTH_PROVIDER=disabled` plus any declared `ClaimMapping` is a
**fatal startup error**. Either remove the mapping declarations or
set `HORT_AUTH_PROVIDER=oidc`.

---

## 4a. The four policy/RBAC kinds

The policy/RBAC surface once carried five kinds: three CRUD
(`Role`, `PermissionGrant`, `CurationRule`) and
two event-sourced (`ScanPolicy`, `Exclusion`). The claim-based RBAC
cutover **retired `kind: Role`** (see the retirement callout below) and
rewrote `kind: PermissionGrant` to a sum-typed claim/user subject
that emits `PermissionGrantApplied` / `PermissionGrantRevoked` on the
`Authorization` event stream — so what was a CRUD kind is now
event-sourced, and the current surface is four extant kinds:
`PermissionGrant`, `CurationRule`, `ScanPolicy`, `Exclusion`. This
section also documents `RetentionPolicy` and the `UpstreamMapping`
knobs, which are policy-shaped but not part of the RBAC surface. The
RBAC model is documented in
[`operate/claim-based-rbac.md`](./operate/claim-based-rbac.md) and
[ADR 0012](../../adr/0012-claim-based-rbac-claimless-static-tokens.md).
This section documents the operator-facing YAML and apply semantics
for each.

CRUD kinds use the same `created` / `updated` / `unchanged` / `deleted`
outcome counter (`hort_gitops_objects_total`) the core kinds use.
Event-sourced kinds additionally tick
`hort_gitops_events_emitted_total{kind=...,event_type=...}` per emitted
domain event — a single envelope can fan out into multiple events
(e.g. a `ScanPolicy` whose YAML touches two fields emits one
`PolicyUpdated` per changed field, but only one
`hort_gitops_objects_total{kind=scan_policy,result=updated}` tick).

The smoke test exercising the extant kinds end-to-end is at
`scripts/host-tests/test-gitops-policies.sh`.

### `kind: Role` — retired

The claim-based RBAC cutover dropped `kind: Role` along with the
`roles` table.
The role concept was replaced by direct `PermissionGrant` rows plus
claim-based bundling: operators bundle permissions on the **operator
side** (YAML templating / generator), not on the server side. There
is no longer a server-side `Role` entity, no `role.rs` under
`crates/hort-config/src/`, and no `Role` variant in the `Kind` enum
(`crates/hort-config/src/envelope.rs`).

Declaring `kind: Role` under `$HORT_CONFIG_DIR` today is a **fatal
boot-apply error** (`ParseError::UnknownKind`) — the same class as
the retired `kind: GroupMapping` documented in §4 above. The parser
rejects the envelope before any DB write.

Migration guidance for legacy YAML — the recipe for converting
`kind: Role` (and the role-referencing `kind: PermissionGrant`
shape) into the claim-mapping + claim-subject grant
shape — is in
[`operate/claim-based-rbac.md`](./operate/claim-based-rbac.md) §7
"Migrating from the old `roles:` / `group_mappings:` YAML". For the
"bundle-via-templating" replacement pattern see §2 of that document.

### `kind: PermissionGrant`

The claim-based RBAC cutover replaced the older role-referencing
Cartesian-
product form with a **sum-typed subject** plus singular `permission`
and singular optional `repository`. One envelope declares exactly one
grant row. References to a role by name, plural `permissions[]`, and
plural `repositories[]` are removed — the parser uses
`deny_unknown_fields` and rejects the legacy shape outright (a stale
file with `role:` fails apply with a YAML error naming the field).

The full concept guide is
[`operate/claim-based-rbac.md`](./operate/claim-based-rbac.md); this
section documents the operator-facing YAML and apply semantics.

**Subject** is a discriminated union on `kind`:

- `kind: claims` — the caller must carry **every** claim in
  `required` (subset match). `required` must be non-empty (an empty
  set would be an unintended wildcard — rejected by validation and
  by the DB `claims_nonempty` CHECK).
- `kind: user` — direct binding to one `users.id` UUID. Bypasses
  the claim mechanism entirely. The natural fit for audited
  break-glass escalations.
- `kind: serviceAccount` — names a `ServiceAccount` envelope by
  `metadata.name`; the apply pipeline resolves it to
  `GrantSubject::User(backing_user_id)`
  ([ADR 0037](../../adr/0037-gitops-service-account-grant.md)). This
  is how service accounts hold authority — the SA envelope itself
  carries none
  ([ADR 0044](../../adr/0044-service-accounts-identity-only.md)). A
  grant naming an absent SA fails apply (dangling reference). A
  `serviceAccount` subject with `permission: admin` is rejected at
  parse — service accounts are strictly non-admin
  ([ADR 0038](../../adr/0038-admin-identity-model.md)).

**Permission** is a single string, one of
`read | write | delete | admin | admin_task_invoke | curate | prefetch`.

**Repository** is a single optional `ArtifactRepository.metadata.name`
reference. **Omit the field entirely** for a global grant; a blank
string is rejected (the two shapes mean different things and the
parser refuses to silently equate them).

#### Claim-gated grant

```yaml
apiVersion: project-hort.de/v1
kind: PermissionGrant
metadata:
  name: security-team-curate-global
spec:
  subject:
    kind: claims
    required:
      - org:security-team        # caller must carry this claim
  permission: curate
  # repository omitted = global authority across all repositories
```

A multi-claim grant tightens the requirement — the caller must carry
**all** listed claims:

```yaml
apiVersion: project-hort.de/v1
kind: PermissionGrant
metadata:
  name: alpha-devs-write-pypi-alpha
spec:
  subject:
    kind: claims
    required: [developer, team-alpha]   # caller must carry BOTH
  permission: write
  repository: pypi-alpha
```

#### ServiceAccount-subject grant (the SA authority mechanism)

```yaml
apiVersion: project-hort.de/v1
kind: PermissionGrant
metadata:
  name: ci-rotation-bot-read-npm-proxy
spec:
  subject:
    kind: serviceAccount
    name: ci-rotation-bot        # ServiceAccount metadata.name
  permission: read
  repository: npm-proxy
```

#### User-bound grant (break-glass)

```yaml
apiVersion: project-hort.de/v1
kind: PermissionGrant
metadata:
  name: oncall-read-npm-proxy
spec:
  subject:
    kind: user
    userId: 11111111-2222-3333-4444-555555555555   # concrete users.id UUID
  permission: read
  repository: npm-proxy
```

**What apply does:** inserts (or updates) **one row** in
`permission_grants` per envelope (no Cartesian fan-out — one envelope,
one row). Counter:
`hort_gitops_objects_total{kind=permission_grant,result=created|updated|unchanged|deleted}`.

**Identity:** subject-dependent. The diff layer keys on
`(sorted required_claims, repository, permission)` for a `Claims`
subject and `(user_id, repository, permission)` for a `User` subject.
`metadata.name` is **operator-cosmetic** and does not participate in
identity — renaming a CRD whose other fields are unchanged is a no-op;
two CRDs that produce the same identity are a conflict the operator
must resolve. Reordering `required:` in a `Claims` grant is a no-op
(the identity sorts the list before hashing).

**Idempotency:** reapply with no YAML changes emits zero writes
(`result=unchanged`). Removing the envelope deletes the row.

**Linter (secure-by-default).** The `ApplyConfigUseCase` linter runs
over every `PermissionGrant` before commit. Suspicious shapes —
single-claim grants for non-allowlisted claims, global non-admin claim
grants, hand-authored `User`-subject grants for privileged permissions
— reject the whole apply by default. The opt-out is an audited
`kind: PermissionGrantLintConfig` envelope (singleton); see
[`operate/claim-based-rbac.md`](./operate/claim-based-rbac.md) §5 for
the full ruleset and tuning surface.

**Audit trail.** The apply emits a `PermissionGranted` event with
full actor attribution (who applied; from which gitops commit). The
admin short-circuit in `RbacEvaluator::authorize` means admin-claim
holders are not affected by missing grants; non-admin callers see
403 immediately on the next request after restart.

### `kind: CurationRule`

A standalone curation rule, attached to one or more repositories via
`ArtifactRepository.spec.curationRules`. The rule was lifted
out of the embedded `Repository.curation` field — there is no
equivalent inline form on a managed repository today.

```yaml
apiVersion: project-hort.de/v1
kind: CurationRule
metadata:
  name: block-known-bad-1
spec:
  format: any                   # `any` or a known format key
  pattern: "evil-package*"      # glob; matched by the policy engine
  action: block                 # block | warn | allow
  reason: "CVE-2024-9999 — recorded on every match"
```

Attach to a repository via the junction list:

```yaml
apiVersion: project-hort.de/v1
kind: ArtifactRepository
metadata:
  name: pypi-curated
spec:
  # ... format/storage/etc as usual ...
  curationRules:
    - block-known-bad-1
```

**What apply does:** inserts (or updates) one row in `curation_rules`
plus junction rows in the repository ↔ rule mapping table for each
referencing repo. Counter:
`hort_gitops_objects_total{kind=curation_rule,result=...}`.

**Idempotency:** reapply with no YAML change emits zero writes.
Reordering the `curationRules:` list on a repository is a no-op
(the junction set sorts before hashing).

### `kind: ScanPolicy`

Event-sourced. The state of every policy lives in the per-policy
event stream (`StreamCategory::Policy`); the gitops apply diffs the
desired YAML against the current `ScanPolicyProjection` and emits
one event per changed field (plus `PolicyCreated` on first apply,
`PolicyArchived` when the YAML disappears).

```yaml
apiVersion: project-hort.de/v1
kind: ScanPolicy
metadata:
  name: default-quarantine
spec:
  scope: global                 # `global` or `{ repository: <key> }`
  severityThreshold: high       # critical | high | medium | low
  quarantineDuration: 24h       # humantime duration
  requireApproval: true
  provenanceMode: verify_if_present   # optional; off | verify_if_present | required
  negligibleAction: ignore      # optional; ignore | warn | block — informational (unmaintained/unsound) advisory handling; default ignore
  enforcement: reject           # optional; reject | record — what a blocking verdict DOES; default reject
  compositeVerdictMode: observed # optional; observed | promoted — whether a composed OCI image's verdict gates its manifest; default observed
  # maxArtifactAge: omit it — declaring any cap is an apply-time rejection (not evaluated)
  licensePolicy: {}             # optional; `{}` or omitted are the only accepted values
```

**`scope: { repository: … }` names a repository; it never carries an id.**
The name is an `ArtifactRepository.metadata.name`, resolved to a UUID by
the apply pipeline through the same map the `RetentionPolicy` scope
resolves through — so the same two consequences hold: the repository must
be declared in the same `$HORT_CONFIG_DIR` (one declared in the *same*
apply is fine, resolution happens after the repository rows are written),
and a name that resolves to nothing is a pre-write rejection naming the
offending value, not a half-applied bundle. A repository UUID is read as
a name, matches nothing and is rejected.

**What apply emits:**
- First apply: one `PolicyCreated` event; one row inserted into
  `policy_projections`. Counters:
  `hort_gitops_objects_total{kind=scan_policy,result=created}` and
  `hort_gitops_events_emitted_total{kind=scan_policy,event_type=PolicyCreated}`.
- Field edit: one `PolicyUpdated` event per changed field (the diff
  is field-level, not envelope-level); the projection row updates
  inside the same DB transaction as the event append.
  `hort_gitops_objects_total{kind=scan_policy,result=updated}` ticks
  once regardless of how many fields changed.
- YAML removed: one `PolicyArchived` event;
  `policy_projections.archived` flips to `true`. The row stays in the
  table — re-declaring the same `metadata.name` later requires a
  fresh `policy_id`, which is a manual operational step (not a
  silent re-create).

**Idempotency:** reapply with no YAML change emits zero events and
no projection writes. The `unchanged` counter ticks instead.

#### `licensePolicy` — apply rejects any declared licence rule

**Licence enforcement is not implemented, and declaring it is now an
apply-time rejection** (`scan_policy_license_policy_not_implemented`).
No port surfaces an artifact's licences, so the scan path evaluates the
policy against an **empty** licence list: a well-formed
`{denied_licenses: [GPL-3.0], action: Block}` compares its denied set
against zero licences, produces zero violations, and leaves the scan
clean whatever the artifact is licensed under. The only thing such a
value can still produce is a non-blocking `license-policy-shape`
advisory against a malformed one.

The two accepted values are `{}` and omitting the field — both are the
evaluator's own "no policy declared" short-circuit, so a tree that never
claimed licence enforcement applies exactly as before. A different
*value* does not help; the rejection is about the missing control, not
the shape:

```text
ScanPolicy `block-gpl` is invalid: `licensePolicy` enforcement is not implemented
(the scan path evaluates the policy against an empty licence list, so every rule
in it matches nothing and the scan stays clean whatever the artifact is licensed
under). Remove the field — or write `licensePolicy: {}` — to apply; a different
value does not change this. (scan policy: `block-gpl`)
```

A projection stored before this rule shipped keeps its value — nothing
rewrites those rows — and keeps deciding nothing. `hort-server
validate-config` catches the declaration offline.

#### `maxArtifactAge` — apply rejects any declared staleness cap

**Age enforcement is not implemented, and declaring a cap is an
apply-time rejection** (`scan_policy_max_artifact_age_not_implemented`).
The duration is parsed, converted to `max_artifact_age_secs`, diffed
field-by-field, event-sourced onto the policy stream, persisted and
written into the config snapshot — and read by nothing that decides. The
evaluator exists (`hort_domain::policy::evaluate_age_gates`, which would
raise a `Medium` `max-artifact-age` violation) and has **no production
caller**: no scan-result evaluation, no release decision and no retention
pass ever asks the question, so no artifact is ever flagged for age.

Unlike `licensePolicy` there is no accepted *value*: the field is an
optional duration whose absence the evaluator reads as "no cap", so
omitting it is the only inert state, and `0s` is refused exactly like
`90d` — the rejection is about the missing consumer, not the number:

```text
ScanPolicy `stale-cap` is invalid: `maxArtifactAge` enforcement is not implemented:
the cap is stored on the policy and never evaluated (the age evaluator has no
caller on any scan, release or retention path), so no artifact is ever flagged for
age however old it is. Remove the field to apply; a different duration does not
change this. (scan policy: `stale-cap`, declared cap: `90d`)
```

The humantime format check stays beside the row, so a malformed duration
is still a row-0 error naming the parse failure. There is no equivalent
control to reach for instead — the nearest *enforced* age mechanism is a
`RetentionPolicy` with an `AgeExceeds` predicate, which **deletes** the
artifact rather than raising a policy violation against it, so it is a
different decision and not a substitute. A projection stored before this
rule shipped keeps its `max_artifact_age_secs` and keeps deciding
nothing. `hort-server validate-config` catches the declaration
offline.

#### `compositeVerdictMode` — who decides an OCI image manifest's release

The unit of filesystem assessment for an OCI image is the **image
manifest**, not a layer: hort materialises the config and the ordered
layers as one OCI layout and scans them as one image, because the package
surface belongs to the composition. A layer carrying a complete package
database and no OS marker reports *nothing* scanned on its own — the
analyzers recognise no operating system and never run the package check
([ADR 0064](../../adr/0064-a-filesystem-finding-is-about-the-composed-filesystem.md)
D1).

That composition is assessed on **every** manifest scan whatever this
field says, and every assessment is recorded as a
`composite_scan_observations` row carrying the composite verdict beside
the counterfactual — what the release gate would have decided had that
verdict carried authority. What the field decides is whether the verdict
reaches the artifact:

- **`observed`** (the default, and the behaviour of every policy that
  predates the field) — the manifest's own assessment is byte-for-byte
  what it would be with no composite path at all. Nothing an operator
  has released becomes withheld, and nothing withheld becomes released.
- **`promoted`** — the composition's findings **are** the manifest row's
  findings: they reach the release gate under the same predicate a
  backend's findings over the manifest's own bytes would, and the
  policy's `enforcement` governs what a blocking verdict does. A
  composition that could **not** be produced — a constituent missing or
  unreadable, an unsupported layer media type, the whole-image budget
  tripped, an upstream that stayed unreachable for the scan job's whole
  attempt budget — is the absent verdict the scan axis fails closed on,
  and holds the manifest `scan_indeterminate`.

**`promoted` also moves the obligation off the layers.** Once the
composition carries the filesystem verdict, an individual OCI blob's own
filesystem findings stop deciding that blob's release, and a layer
hort has no decoder for (`tar+zstd`, `xz`, `bzip2` — which the scanner
composes without difficulty in image mode) stops being withheld for
that reason. This is the half of the decision that *unblocks* images: a
package an upper layer deletes no longer condemns the lower layer, and
a clean image no longer has a withheld constituent underneath it.

What stays put:

- The findings stay in the record — the per-finding rows, the stored
  findings blob and the scan's severity summary are unchanged. What
  changes is only which findings the policy thresholds are walked
  against.
- A finding about the layer's **bytes** still blocks the layer. No
  scanner hort ships produces one today (Trivy's vulnerability findings
  are all claims about an installed package set); the distinction is in
  place so a future secrets or malware backend is not silently disarmed.
- Every **other** reason a layer's scan can produce no verdict still
  withholds it — a tripped extraction bound, an entry that tried to
  escape the workspace, an archive that could not be read, a backend
  that found nothing to analyse.
- Non-OCI repositories are untouched, whatever this field says. A
  **global** policy with `compositeVerdictMode: promoted` does not
  loosen anything for npm, PyPI, cargo or Maven: ADR 0064 decides the
  OCI image and explicitly leaves the other formats open.
- An already-**rejected** layer is not released. Recovering that estate
  is an explicit curation re-evaluation
  (`POST /api/v1/admin/curation/quarantine/{artifact_id}/reevaluate`),
  for the same reason promotion drives no re-evaluation pass of its own.

It also stops for a blob that is **not** part of an image — an OCI
artifact's layer, or a blob nothing in the registry references — and
there no composition takes the obligation over. That is intended rather
than a gap. A package-vulnerability finding is a statement about an
installed package tree that runs; a chart tarball or a pushed archive
has none, so a finding read out of it is a statement about nothing.
Under `observed` such a blob is assessed today only because every
tar-shaped blob is materialised as a root filesystem — right for an
image layer, incidental for anything else.

Two things narrow this further, and both are worth knowing before you
promote:

- Blobs that are not archives are **unaffected either way**. A cosign
  signature and an SBOM attachment are JSON, which carries no package
  surface, so they neither gate today nor change under `promoted`.
- The field is per **policy**, and a policy can be scoped to one
  repository. If you keep images and other OCI artifacts in separate
  repositories, promote on the image ones and the question does not
  arise for the rest.

**Promote deliberately, not by default.** A composite verdict adds
rejections across an existing estate, `Rejected` is terminal, and the
periodic rescan never revisits it — so a wrong verdict from a new
analysis path on its first production run leaves an estate only an
explicit curation re-evaluation can recover. The field is per **policy**
so an operator can promote on one repository first and watch it; the
observation rows and
`hort_scan_composite_assessment_total{result,authority}` are what that
watching reads.

Two things promotion deliberately does **not** change:

- **An image index, and an artifact manifest, are unaffected.** An index
  binds references rather than a runnable filesystem (ADR 0064 D5) and a
  cosign signature / SBOM attachment / Helm chart declares no layered
  root filesystem; both resolve to "nothing to compose", which is a
  legitimate population and not an unassessed image, so promotion must
  not make either gate on a composition it does not have.
- **No already-assessed artifact is re-evaluated, in either
  direction.** Unlike `enforcement`, a change to this field enqueues no
  continuous-enforcement pass: that pass re-derives verdicts from
  *stored* findings, and a composite verdict's findings come from
  scanning an assembled image. Demoting `promoted → observed` that way
  would un-reject the population a promoted composite had correctly
  rejected with no fresh assessment. Promotion takes effect on the next
  scan of each manifest — its ordinary rescan, or an explicit one.

##### `promoted` with `scanBackends: []` is an apply-time rejection

The two opt-ins cancel. An empty backend list is the explicit scan
waiver: the scan returns before a composed image is resolved, so no
manifest the policy governs ever carries a composite assessment — and
the promotion then grants release authority to a verdict that is never
produced. Apply rejects the combination
(`composite_verdict_promoted_requires_scan_backends`) rather than
silently treating `promoted` as `observed`, because an operator reading
the policy back would otherwise see a promotion that is not in effect:

```text
ScanPolicy `waived-but-promoted` is invalid: `compositeVerdictMode: promoted` with
an empty `scanBackends` promotes a verdict that is never produced: an empty backend
list waives scanning for every artifact this policy governs, and the scan returns
before a composed image is resolved — so no manifest ever carries a composite
assessment for the promotion to act on. Declare the backends that should assess the
composition (`scanBackends: [trivy]`), or leave `compositeVerdictMode: observed`
while the scan stays waived. (scan policy: `waived-but-promoted`)
```

`hort-server validate-config` catches it offline. Note that a policy
governing an OCI repository cannot name `osv` *instead* of `trivy`
either — `osv` reads only the payload SBOM and `oci` exposes none, so
row 7c below rejects that pairing on its own.

#### `scanBackends` — apply rejects a backend that cannot analyse the format

A backend's coverage is a compiled-in fact of the build, not an operator
choice: `trivy` reads the payload and covers every format whose artifacts
it can materialise; `osv` reads only the payload SBOM, so it covers every
format whose handler exposes one — `oci` exposes none. The full table
with per-cell evidence is
[*The scanner capability map*](../explanation/scanning-pipeline.md#the-scanner-capability-map).

Apply-time validation (`scan_backend_capability`) rejects a pairing that
would accept here and analyse nothing at runtime. **The unit is the
effective pairing, not the declared scope**: repo-scoped policy wins over
global at resolution time, so a global policy is checked only against
the repositories that declare no policy of their own.

Two rejection shapes:

```text
ScanPolicy `alpha-default`: scanBackends entry `osv` cannot analyse repository
`oci-proxy` (format `oci`) — static scanner capability map; `osv` produces no
verdict for any oci artifact, so this pairing would accept at apply and analyse
nothing at runtime. Use a backend that covers oci (`trivy`), remove `osv` from
this policy, or scope a separate policy to this repository. Coverage per format:
docs/architecture/explanation/scanning-pipeline.md.
```

```text
ScanPolicy `p-gradle`: repository `gradle-hosted` (format `gradle`) has no
compiled-in scanner coverage — every gradle artifact would record a
not-applicable assessment, never a scan. Waive scanning explicitly for it
(`scanBackends: []` in a policy scoped to `gradle-hosted`) or exclude it from
this policy's scope.
```

The first shape's canonical trigger is a **global** `[trivy, osv]` over a
deployment that also serves OCI repositories. Split it: a global
`[trivy]`, plus per-repository policies adding `osv` where the format has
an SBOM (`npm`, `pypi`, `cargo`, `maven`) —
`scripts/alpha-fixtures/gitops-config/base/policies/` is the worked
example. Remember that a repo-scoped policy *replaces* the global one
rather than merging with it, so the scoped policy repeats every setting.

`scanBackends: []` never trips this rule: it is the explicit operator
waiver, a decision rather than an inert pairing. `hort-server
validate-config` catches both shapes offline.

#### `enforcement: reject | record` — what a blocking verdict *does*

`severityThreshold` and `negligibleAction` decide **which** findings are
enforcement-worthy. (`licensePolicy` does not: it decides nothing, which
is why declaring it is an apply-time rejection — see above.)
`enforcement` decides what the resulting verdict is allowed to **do**:

| Value | The scan | The findings | The verdict | The artifact |
|---|---|---|---|---|
| `reject` (default) | runs | persisted | `PolicyEvaluated(Fail)` | transitions to `Rejected`; downloads blocked |
| `record` | runs | persisted | `PolicyEvaluated(Fail)` | **untouched** — publication proceeds |

Omitting the field parses to `reject`, which is the behaviour of every
policy written before the field existed — an existing tree needs no
edit. An unknown value is an apply-time rejection naming the field and
both valid values (a typo must never silently fall back to either
mode).

`record` is for the "publish proceeds with findings; blocking at
retrieval is the consuming policy's job" posture. It is **not** a way
to stop scanning — use `scanBackends: []` for that — and it is **not**
a way to hide findings: the per-finding rows, the findings blob and
the `PolicyEvaluated(Fail)` audit event are written exactly as under
`reject`, so every API and metrics surface reports the violations
identically. What changes is the absence of the `ArtifactRejected`
transition.

Because a `record`-mode artifact's own `ScanCompleted` carries
findings, it cannot release through the `ScanSucceeded` authority; it
releases through the distinct `ScanRecorded` authority instead, which
is visible on the release log line (`authority=scan_recorded`). Every
other release conjunct is unchanged: `record` un-gates the **scan**
axis only, so `provenanceMode: required` still holds an unverified
artifact, an active curation rule still blocks, and the observation
window still applies.

**Changing the field re-judges the existing population**
(ADR 0041), in both directions and asynchronously:

- `record` → `reject` re-derives every in-scope artifact's verdict from
  its **stored** findings and re-holds the now-non-compliant ones
  (including already-`Released` ones — future downloads are blocked;
  already-served bytes cannot be recalled);
- `reject` → `record` un-rejects the scan-rejected population through
  release authority #5 (policy re-evaluation). The remaining
  observation window is preserved — loosening removes the scan block,
  not the time hold.

No scanner is re-run in either direction; both re-read the stored
evidence.

**Hosted-repo recommendation — `quarantineDuration: 0s` is the
documented opt-out for "publish + immediately install" flows.**
Under quarantine-by-default, every ingest — proxy *and* hosted —
goes to `Quarantined` for the resolved window (24 h under
`DefaultPolicy`). For proxy repos the served index filters
quarantined versions, so clients don't try to
download them until they're released. **For hosted repos the index
does NOT filter** (deliberately out of scope) — every
ingested version appears in the simple/JSON index from the moment
it lands. An operator-published artifact that a client then tries
to `pip install` / `cargo build` / `npm install` against will
receive `503 Service Unavailable` + `Retry-After: <window-in-secs>`
from the format-crate quarantine branch until the
window elapses or a scan releases it inline.

The two operator-facing postures:

| If your hosted repo... | Set on a per-repo `ScanPolicy`... | Effect |
|---|---|---|
| ...needs publish → immediately install (CI building its own packages, dev loops, e2e harnesses) | `quarantineDuration: 0s` | The quarantine-by-default window is overridden per-repo; uploads stay servable, `quarantine_status` stays `NULL`, no `503` on download. The rest of the deployment still honours quarantine-by-default. |
| ...wants the secure default (defense-in-depth against own-CI supply-chain attacks; the scan completes before clients can pull) | (omit `quarantineDuration`, or set explicitly to `24h`) | Uploads quarantine for the window. The `503 + Retry-After` is the contract; clients fail fast and retry once the scan releases the artifact (a clean scan fast-paths the release the moment it lands; the timer is a fallback). |

Example permissive override scoped to a single hosted repo:

```yaml
apiVersion: project-hort.de/v1
kind: ScanPolicy
metadata:
  name: ci-builds-permissive
spec:
  scope:
    repository: ci-builds
  severityThreshold: critical
  quarantineDuration: 0s
  requireApproval: false
  provenanceMode: off       # optional; off | verify_if_present | required
  scanBackends: []          # explicit empty — no scanner required
  licensePolicy: {}
```

This mirrors the per-repo fixtures the v2 e2e harness ships under
`deploy/compose/example-config/policies/` (commit `2f7071bf`).

### `kind: Exclusion`

Event-sourced sub-state of a parent `ScanPolicy` (same stream).
Identity is `(policy_name, cve_id, package_pattern_or_null)`.

```yaml
apiVersion: project-hort.de/v1
kind: Exclusion
metadata:
  name: cve-2024-3094-on-old-xz
spec:
  policy: default-quarantine          # ref by ScanPolicy.metadata.name
  cveId: CVE-2024-3094
  packagePattern: "xz-utils@<5.6.2"   # optional
  scope: global
  reason: "Patched in container layer; not exploitable here"
  expiresAt: "2026-12-31T23:59:59Z"   # optional RFC3339
```

**`scope: global` is the only accepted value.** A
`scope: { repository: <name> }` is an apply-time rejection
(`exclusion_scope_not_implemented`), and so is the same shape issued
through `POST /api/v1/admin/policies/:id/exclusions`. The reason is not
the reference but the field: the finding filter never reads an
exclusion's scope — the artifact coordinates it matches against carry no
repository identity — so an exclusion narrowed to one repository
suppresses its CVE for **every** repository the parent policy governs.
The operator's edit looks like a narrowing and acts like a widening,
which is why it fails closed rather than warning:

```text
Exclusion `cve-on-one-repo` is invalid: `spec.scope` names repository `npm-internal`,
but a repository-scoped exclusion is not enforced: … Write `scope: global` if clearing
this CVE everywhere the policy governs is what was meant, or drop the exclusion until
per-repository scoping is implemented.
```

To waive a CVE for one repository only, scope the **parent
`ScanPolicy`** to that repository and hang the exclusion off it — the
policy scope *is* enforced.

A row stored before this rule shipped keeps its scope; nothing rewrites
it, and it keeps acting globally. Removing it is not refused anywhere —
only writing one is. Drop its envelope from the tree and the apply
removes it as usual; so does
`DELETE /api/v1/admin/policies/:id/exclusions/:cve`. The removal is the
direction that *withdraws* an assurance nothing honoured, so there is
nothing to fail closed about. What it does do is re-reject findings in
every repository the parent policy governs rather than only the one the
scope named, and the server logs exactly that — the policy id, the CVE,
the stored repository id and the rationale — as it removes the row.

**What apply emits:**
- First apply: one `ExclusionAdded` event on the parent policy's
  stream; one row inserted into `exclusion_projections`. Counters:
  `hort_gitops_events_emitted_total{kind=exclusion,event_type=ExclusionAdded}`.
- Field edit (reason, expiry): one `ExclusionRemoved` +
  one `ExclusionAdded` on the same stream — the events crate has
  no `ExclusionUpdated`, and remove-and-add is the canonical update
  form. (The scope is not among the editable fields: only `global` is
  accepted, so there is nothing to change it to.)
- YAML removed: one `ExclusionRemoved` event with
  `reason = "removed by gitops apply"`; the projection row is
  deleted.

**Idempotency:** reapply with no YAML change emits zero events. The
parent `ScanPolicy` must exist in the same `$HORT_CONFIG_DIR` (or as a
prior projection) — the cross-spec validator rejects orphan
exclusions before any DB write.

### `kind: RetentionPolicy`

Event-sourced kind, gitops-authored only — there is no imperative HTTP
API. The apply pipeline diffs each envelope against the current
`retention_policy_projections` row and emits
`RetentionPolicyChanged(Created | Updated | Archived)`.

`spec.predicate` and `spec.scope` are written in the **JSON-shaped
externally-tagged form** (`{AgeExceeds: 2592000}`), not YAML's
`!AgeExceeds` tag form.

```yaml
apiVersion: project-hort.de/v1
kind: RetentionPolicy
metadata:
  name: retain-90d-npm-and-pypi
spec:
  predicate:
    AgeExceeds: 7776000                 # seconds
  scope:
    Repos: [npm-internal, pypi-internal]  # ArtifactRepository metadata.name
```

**`scope` names repositories; it never carries ids.** Each `Repos`
entry is an `ArtifactRepository.metadata.name`, resolved to a UUID by
the apply pipeline exactly once, through the same map the `ScanPolicy`
scope resolves through. That means:

- Every named repository must be declared in the same
  `$HORT_CONFIG_DIR` — including one declared in the *same* apply, since
  resolution happens after the repository rows are written. A name that
  resolves to nothing is a pre-write rejection naming the offending
  value, not a half-applied bundle.
- A repository UUID is not a supported value. It is read as a name,
  matches no repository, and is rejected. A UUID in gitops YAML is
  worthless the moment the instance is rebuilt against a fresh database,
  which is why the surface takes names.

The other scopes carry no repository reference:

```yaml
  scope: AllRepos                       # every repository
  scope: { Format: Npm }                # every repository of a format
  scope: { PackageNamePattern: "xz-*" } # `*`-only glob on the artifact name
  scope: { IngestSource: Proxied }      # pull-through artifacts only
```

**What apply emits:**
- New name: one `RetentionPolicyChanged(Created)`; one row inserted into
  `retention_policy_projections`. Counters:
  `hort_gitops_events_emitted_total{kind=retention_policy,event_type=RetentionPolicyCreated}`.
- Predicate or scope edit: one `RetentionPolicyChanged(Updated)`.
- YAML removed: one `RetentionPolicyChanged(Archived)`; the row is
  marked archived, not deleted. Archive is terminal — re-declaring an
  archived name mints a **fresh** policy, it does not reactivate the old
  one, and the archived stream stays as audit history.

**Idempotency:** reapply with no YAML change emits zero events.

**`UnusedFor` is rejected at apply.** The predicate is refused — at the
root of `spec.predicate` or nested anywhere inside a `Composite` — with
an error naming the policy, and the apply fails (`hort-server
validate-config` rejects the same tree offline). Nothing supplies a
last-download timestamp today, so the evaluator measures the interval
from the artifact's creation time: `UnusedFor(N)` would expire exactly
what `AgeExceeds(N)` expires, including an artifact pulled an hour ago.
On a hosted repository that inverts the intent — a year-old,
daily-pulled artifact is the last thing "unused" should reach and the
first thing "old" does. Write `AgeExceeds` if age is what was meant.
The rejection is lifted when a real usage signal is wired.

**Direct-upload advisory.** A security-driven predicate
(`HasFixAvailable`, `HasFindingAboveSeverity`, …) under a scope that does
not exclude `IngestSource(Direct)` logs an apply-time `info!`. It is
advisory, not a reject — the policy applies. The point is that a
directly-uploaded artifact may be the only build of that version
anywhere, while a proxied one is restorable by re-pull. If the intent is
"clean up vulnerable *mirrored* packages", say
`scope: { IngestSource: Proxied }` and the advisory goes away.

### `kind: UpstreamMapping` — `spec.upstreamNamePrefix`

Outbound OCI path-prefix injection. The full `kind: UpstreamMapping`
schema (envelope shape, `(repository, pathPrefix)` identity, `auth`
enum, `secretRef`, `insecureUpstreamUrl`, mTLS knobs) is defined in
`crates/hort-config/src/upstream_mapping.rs`; this section documents
only the `upstreamNamePrefix` knob because it has operator-visible
consequences for the upstream URL shape.

`spec.upstreamNamePrefix: Option<String>` (default absent) splices
one or more path segments between `/v2/` and `<name>` in upstream OCI
requests. Use it when the upstream registry's path layout includes
an extra segment that a spec-compliant OCI client would not produce:

- Zot's multi-storage paths (`/v2/docker.io/library/alpine/...`)
- Artifactory's `/artifactory/<repo>/v2/...` rewrite
- GitLab Container Registry per-project URLs
- Harbor proxy caches with prefixed routes
- hort-server federation when one hort-server proxies through another
  that mounts repositories under a prefix

```yaml
apiVersion: project-hort.de/v1
kind: UpstreamMapping
metadata:
  name: docker-io-via-zot
spec:
  repository: docker-io          # must be an `oci` repository
  pathPrefix: ''
  upstreamUrl: http://zot.zot-system.svc.cluster.local:5000
  upstreamNamePrefix: docker.io  # outbound path-prefix
  insecureUpstreamUrl: true      # in-cluster plaintext Service
  auth:
    type: anonymous
```

With this mapping, an outbound pull for `library/alpine:3.19` hits
`http://zot.zot-system.svc.cluster.local:5000/v2/docker.io/library/alpine/manifests/3.19`
— the Zot multi-storage layout — rather than the spec-default
`/v2/library/alpine/manifests/3.19`. Inbound (downstream-client)
shape is unchanged; this knob is outbound-only.

**Format-effective for OCI only.** The cross-spec validator
(`push_upstream_mapping_format_compatibility_errors`) rejects this
field on non-OCI repositories at apply-config parse time. Other
format adapters (npm, PyPI, Cargo, Maven, …) compose outbound URLs
with no fixed root segment, so an operator who needs the same shape
on those formats can include the prefix in `upstreamUrl` directly.

**Validation.** The constructor regex
`^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$` plus two extra guards (no
`..` substring, no segment of one-or-more dots) is mirrored 1:1 in
the schema CHECK constraint
`chk_repository_upstream_mappings_name_prefix`. Malformed values
surface at apply-config parse time with `upstreamNamePrefix` named
in the error message, not at fetch time.

The knob exists for registry-of-registries layouts (it obsoletes
URL-rewriting sidecars): when one registry mounts another's content
under a path prefix, the prefix belongs in declarative config, not in
a proxy rewrite layer.

### `kind: UpstreamMapping` — `spec.allowedRealmHosts`

`spec.allowedRealmHosts: [String]` (default empty) names the hosts that
may be given this mapping's credential as the `WWW-Authenticate` realm
of a `bearer_challenge` exchange. **The mapping's own origin is always
allowed and is never listed.**

```yaml
apiVersion: project-hort.de/v1
kind: UpstreamMapping
metadata:
  name: dockerhub-authenticated
spec:
  repository: dockerhub-proxy
  pathPrefix: ""
  upstreamUrl: https://registry-1.docker.io
  auth:
    type: bearer_challenge
  secretRef:                      # the credential this list guards
    source: file
    location: /run/secrets/dockerhub-pat
  allowedRealmHosts:
    - auth.docker.io              # Docker Hub's token service
```

**Why the operator has to answer this.** The realm arrives verbatim in
the upstream's `WWW-Authenticate` response header, so it is
upstream-controlled data — and the realm exchange is the one request
that carries the credential, as
`Authorization: Basic base64("oauth2:<secret>")`. hort already refuses a
non-`https` realm and a realm resolving to a non-routable host, but
those bound *where* the credential may travel, not *to whom*: a
compromised or hijacked upstream can answer `401` naming any https,
routable host it likes. Binding the realm silently to the mapping's own
origin is not available as the fix, because off-origin realms are
normal — `auth.docker.io` for `registry-1.docker.io`, and a GitLab
container registry's `/jwt/auth` on its own host. So the allowance is
the operator's to state.

**It applies only to a credentialed exchange.** The list is consulted
if and only if the mapping also carries a `secretRef`. An exchange with
no credential has nothing a nominated realm could receive, so it keeps
exactly its previous behaviour (the `https` and routability gates
alone). That is why every anonymous pull-through proxy — including the
`bearer_challenge` Docker Hub mappings shipped in this repository, whose
realm is off-origin — needs no entry and is unaffected.

**What breaks on upgrade, and for whom.** A mapping that is **both**
credentialed **and** has an off-origin realm stops working until that
realm's host is listed: the fetch fails with
`hort_upstream_fetch_total{result="parse_error"}` and a server log line
naming the mapping and the refused realm host. **Authenticated Docker
Hub is the canonical case** — `registry-1.docker.io` with a PAT, whose
realm is `auth.docker.io`. The remedy is the one line above:
`allowedRealmHosts: [auth.docker.io]`. Nothing else changes: an
anonymous mapping, and a credentialed mapping whose realm is on its own
origin (most self-hosted registries — Harbor's `/service/token`, Zot, a
registry serving `/token` itself), are untouched.

**Validation.** Entries are bare hostnames: ASCII letters, digits, `.`
and `-`, no empty label, no leading or trailing `.` or `-`. A scheme, a
port, a path or an empty string is rejected at apply-config parse time
with the accepted form in the message — those shapes could never match
the host hort compares against, so accepting them would hand you a
control you wrote and did not get. The field is also rejected on a
mapping whose `auth.type` is not `bearer_challenge`, because no realm
exists in those flows for it to govern
([ADR 0015](../../adr/0015-apply-time-linter-inert-fields-and-naming.md)).
It is **accepted** on a `bearer_challenge` mapping with no `secretRef`:
its consumer comes into being the moment you add one, so the allowance
may be declared first. The schema CHECK constraints
`chk_repository_upstream_mappings_allowed_realm_hosts` and
`chk_repository_upstream_mappings_realm_hosts_auth` mirror both rules.
`hort-server validate-config` catches all of them offline.

**The allowance is for a host, not for whatever that host redirects
to.** A credentialed exchange at a listed realm runs on a client whose
redirect policy refuses any hop that leaves the realm's own origin, so a
listed realm answering `302` to somewhere else cannot carry the
credential onward.

---

### `kind: UpstreamMapping` — `spec.trustUpstreamPublishTime`

`spec.trustUpstreamPublishTime: bool` (default `false`) admits this
upstream's asserted publish time as an **optional second source** for
the quarantine-window anchor.

The quarantine window is a proxy for elapsed *ecosystem exposure* — the
assumption that content available in the world for the window's
duration has had the ecosystem's scanners, advisories and researchers
looking at it. So the anchor is the **earliest defensible evidence of
the content's age**: the minimum over the applicable sources
([ADR 0054](../../adr/0054-content-level-age-evidence-anchors-quarantine.md)).

**The primary source needs no opt-in and is always in play**: the
earliest moment hort itself observed those exact bytes, in any of its
own repositories. That is an observation hort generates, not a claim by
a third party, so it cannot be backdated — the most an attacker
achieves by influencing it is making hort see the content *earlier*,
which requires the content to genuinely have existed that much earlier,
during which the ecosystem had precisely the exposure the window stands
in for. It is also structurally conservative: hort cannot observe
content before it is published, so first-seen is always a *late*
estimate of real publication.

Two operator-visible consequences of the primary source, both intended:

- Content hort saw long ago and is now registering into a **second**
  repository can land with a zero-length window. It has already had its
  ecosystem exposure; holding it another full window adds no observation
  the world has not already had.
- Content whose last row is purged and which is later re-fetched loses
  its original age evidence and re-anchors at the new ingest — the
  evidence is derived from the artifact rows, not stored separately. The
  resulting window is *longer* than the truth requires, never shorter.

**What this flag adds** is `upstream_published_at` — an *assertion by
the upstream* — to that same minimum. It can therefore only move the
anchor earlier, never later, and a claimed publish time after the
ingest instant is clamped away (physically impossible). It is opt-in
because it is the one attacker-influenceable input: a claimed *ancient*
publish time is bounded nowhere and collapses the window immediately.
Freshly uploaded malware carrying forged old metadata is exactly the
case the opt-in exists to bound — enable it only for upstreams whose
metadata you are willing to treat as true. The case it exists for is a
high-latency mirror of already-aged content, where hort's own first
observation is far later than real publication.

**It is per-mapping, and it does not transit repositories.** A value
observed through one repository's mapping never shortens another
repository's window. Without that scoping, a repository proxying an
untrusted mirror could shorten the window of one proxying the genuine
upstream — the collapse pattern
[ADR 0016](../../adr/0016-cross-opt-in-interaction-matrix.md) exists to
prevent.

**Cross-opt-in constraint.** Combining `trustUpstreamPublishTime: true`
with an empty `scanBackends` is rejected at apply time
(`trust_upstream_publish_time_requires_scan_backends`): together they
collapse the observation window to sweep-tick latency with no scan
behind it. `hort-server validate-config` catches this offline.

The window is a **timer, never an authority**: release still requires
this artifact's own `ScanSucceeded` / `ScanWaived`
([ADR 0007](../../adr/0007-fail-closed-quarantine-release-predicate.md)),
whatever the anchor resolves to.

---

## 4b. The two machine-identity kinds

Two CRUD kinds (`OidcIssuer` and
`ServiceAccount`) declare non-human identities and their
trust relationships with external OIDC issuers. The design
rationale is in
[ADR 0018](../../adr/0018-auth-catalog-canonical.md) and
[`docs/auth-catalog.md`](../../auth-catalog.md) — this
section documents the operator-facing YAML and apply semantics.

Both kinds use the standard
`hort_gitops_objects_total{kind=...,result=...}` counter for apply
outcomes. Cross-kind FK resolution
(`ServiceAccount.federatedIdentities[].issuer` references a
declared `OidcIssuer.metadata.name`) runs in
`ApplyConfigUseCase::validate_against` after both kinds are
parsed; orphan references fail apply with a clear error before
any DB write.

The three operator how-to guides covering these kinds end to end:

- [`federate-k8s-workload-identity.md`](./federate-k8s-workload-identity.md)
  — Flux / projected SA tokens.
- [`federate-ci-oidc.md`](./federate-ci-oidc.md)
  — GitHub Actions + GitLab CI.
- [`rotating-service-account-tokens.md`](./rotating-service-account-tokens.md)
  — fallback PAT rotation for non-OIDC workloads.

### `kind: OidcIssuer`

Declares a trusted external OIDC issuer for workload identity
federation (`/api/v1/auth/exchange`'s federation branch). One
envelope per issuer; `metadata.name` is the envelope identity.

Apply-time validation rejects HTTP URLs, empty `audiences`, and
algorithms outside the asymmetric set (no `HS*` — symmetric
algorithms have no JWKS to verify against). `jwksRefreshInterval`
is bounded `[1m, 24h]`.

```yaml
apiVersion: project-hort.de/v1
kind: OidcIssuer
metadata:
  name: github-actions
spec:
  issuerUrl: https://token.actions.githubusercontent.com
  audiences: [hort-server]
  jwksRefreshInterval: 1h           # default; bounded [1m, 24h]
  allowedAlgorithms: [RS256, ES256] # default [RS256]
```

**What apply does:** inserts (or updates) one row in
`oidc_issuers`. Counter:
`hort_gitops_objects_total{kind=oidc_issuer,result=created|updated|unchanged|deleted}`.

**Identity:** the diff layer keys on `metadata.name`. Changing
`issuerUrl` on an existing envelope is treated as an update, not
a delete + create, so audit continuity is preserved across
issuer-URL migrations (e.g. self-hosted GitLab URL changes).

**Idempotency:** reapply with no YAML change emits zero writes
(`result=unchanged`). Removing the envelope deletes the row, but
any `ServiceAccount.federatedIdentities[]` referencing the issuer
must be removed in the same apply pass (cross-spec validator
catches orphans before delete).

See: [`federate-ci-oidc.md`](./federate-ci-oidc.md),
[`federate-k8s-workload-identity.md`](./federate-k8s-workload-identity.md).

### `kind: ServiceAccount`

Declares a non-human identity. The envelope is **identity +
federation binding only** — `metadata.name`, `federatedIdentities`,
`fallbackRotation` — and confers **no authority**
([ADR 0044](../../adr/0044-service-accounts-identity-only.md)). The
SA's authority is exactly its explicit `PermissionGrant`s, declared
alongside with a `serviceAccount` subject (§4a,
[ADR 0037](../../adr/0037-gitops-service-account-grant.md)). Tokens
issued for the SA — the federation exchange and the fallback-rotation
mint — carry a cap that snapshots those grants at issuance, so an SA
with no grants holds a token that authorizes nothing. Apply the
envelope **and** its grants together.

Three valid shapes — federation only, rotation only, or both. The
"neither" case (no `federatedIdentities:` and no `fallbackRotation:`)
is also valid and represents a PAT-only identity an operator mints
via `hort-cli admin token issue`.

**Federation only** — most common for OIDC-capable workloads. The
envelope binds the identity; the grants beside it confer read+write
on one repository:

```yaml
apiVersion: project-hort.de/v1
kind: ServiceAccount
metadata:
  name: gha-myorg-myrepo-pypi
spec:
  federatedIdentities:
    - issuer: github-actions
      claims:
        repository: my-org/my-repo
        environment: production
---
apiVersion: project-hort.de/v1
kind: PermissionGrant
metadata:
  name: gha-myorg-myrepo-pypi-write
spec:
  subject:
    kind: serviceAccount
    name: gha-myorg-myrepo-pypi
  permission: write
  repository: pypi-internal
---
apiVersion: project-hort.de/v1
kind: PermissionGrant
metadata:
  name: gha-myorg-myrepo-pypi-read
spec:
  subject:
    kind: serviceAccount
    name: gha-myorg-myrepo-pypi
  permission: read
  repository: pypi-internal
```

Permissions are flat — `write` does not imply `read`. A publisher
that also reads back what it pushed (e.g. push-then-sign, or twine's
post-upload check) needs both grants.

**Rotation only** — for workloads that cannot do OIDC. A pull-only
consumer needs just the `read` grant:

```yaml
apiVersion: project-hort.de/v1
kind: ServiceAccount
metadata:
  name: legacy-docker-puller
spec:
  fallbackRotation:
    targetSecret:
      name: hort-pull-secret
      namespace: ci-system
      format: dockerconfigjson      # or `opaque`
    rotationInterval: 6h
    validity: 24h
---
apiVersion: project-hort.de/v1
kind: PermissionGrant
metadata:
  name: legacy-docker-puller-read
spec:
  subject:
    kind: serviceAccount
    name: legacy-docker-puller
  permission: read
  repository: oci-internal
```

**Both** — federation as primary path, rotation as fallback for
non-OIDC clients in the same identity scope. The grants are shared:
whichever path issued the token, the cap snapshots the same grant
set:

```yaml
apiVersion: project-hort.de/v1
kind: ServiceAccount
metadata:
  name: ci-pypi-pusher
spec:
  federatedIdentities:
    - issuer: github-actions
      claims:
        repository: my-org/my-repo
        environment: production
  fallbackRotation:
    targetSecret:
      name: ci-hort-token
      namespace: ci-system
      format: opaque
    rotationInterval: 6h
    validity: 24h
---
apiVersion: project-hort.de/v1
kind: PermissionGrant
metadata:
  name: ci-pypi-pusher-write
spec:
  subject:
    kind: serviceAccount
    name: ci-pypi-pusher
  permission: write
  repository: pypi-internal
```

Apply-time validation rules:

- `role:` and `repositories:` are **not fields** — the envelope
  carries no authority, and the parser
  (`deny_unknown_fields`) fails the apply for an envelope declaring
  them. Authority is the SA's `PermissionGrant`s; a
  `serviceAccount`-subject grant with `permission: admin` is
  rejected at parse — service accounts are strictly non-admin
  ([ADR 0038](../../adr/0038-admin-identity-model.md)).
- `federatedIdentities[].issuer` must reference an existing
  `OidcIssuer` (cross-spec FK).
- `federatedIdentities[].claims` **non-empty**. Empty claims
  means "any JWT from this issuer can assume me" — a
  privilege-escalation footgun. **Hard reject.**
- `fallbackRotation.targetSecret.format` ∈
  `{dockerconfigjson, opaque}`.
- `fallbackRotation.rotationInterval` ≥ `1h` (humantime).
- `fallbackRotation.validity` ≥ 2 × `rotationInterval`. The
  factor-of-2 is the safety margin for consumer-side Secret
  reload latency.
- `fallbackRotation.targetSecret` is **unique across
  ServiceAccounts**. A target's identity is `(namespace, name)`, so
  the same Secret name in two namespaces is fine. Two
  ServiceAccounts on one target is a **hard reject** — the
  reconciler's ownership barrier refuses one of them on every tick,
  so its declared rotation never happens, and without the barrier
  the two would overwrite each other's credential and leave
  consumers holding the wrong identity.
- `fallbackRotation.targetSecret.namespace` is **not** validated
  against `worker.rotation.targetNamespaces` at apply time — the
  chart's allow-list is a runtime concern. Mismatches surface as
  reconciler warnings, not apply-time rejection.

**What apply does:** inserts (or updates) one row in
`service_accounts`, plus rows in `federated_identities` and the
`fallback_rotation` sub-table. On first apply the use case also
ensures a backing `users` row exists with
`is_service_account = true` and `username = "sa:<metadata.name>"`.
The SA's `serviceAccount`-subject grants resolve to that backing
user (`GrantSubject::User(backing_user_id)`) in the same apply.
Counter: `hort_gitops_objects_total{kind=service_account,result=...}`.

**Identity:** the diff layer keys on `metadata.name`. Renaming an
envelope produces a delete + create, which mints a fresh backing
user — only do this deliberately (the old SA's audit events stay
linked to the old user).

**Idempotency:** reapply with no YAML change emits zero writes.

See: [`federate-k8s-workload-identity.md`](./federate-k8s-workload-identity.md),
[`federate-ci-oidc.md`](./federate-ci-oidc.md),
[`rotating-service-account-tokens.md`](./rotating-service-account-tokens.md).

---

## 5. The boot sequence

```text
parse Config (env vars)
→ verify schema version (migrate::assert_current — refuses to start
  against a stale schema)
→ if $HORT_CONFIG_DIR is set:
       walk every *.yaml under it
       parse + validate (collect ALL errors, never first-error-wins)
       apply via managed-write port methods (strict-atomic)
       emit hort_gitops_apply_total{result=ok|...}
→ build_app_context (sees the post-apply state)
→ bind() and serve
```

DDL is split out of the runtime
([ADR 0009](../../adr/0009-least-privilege-runtime-migrate-subcommand.md)):
`serve` connects under
the least-privilege app DSN (DML only, no DDL on `public`) and only
*verifies* the schema version. Migration application is owned by the
dedicated `hort-server migrate` subcommand running under the admin DSN
— deploy this as a separate Job before rolling the runtime
Deployment. See the operator how-to at
`docs/architecture/how-to/deploy/postgres-roles.md`.

Apply runs **before** `build_app_context`, so `AuthenticateUseCase`
is constructed once with the post-apply group mappings. There is
no live-refresh path; restart-to-apply is the contract.

Failure exits non-zero with the rendered errors in `tracing::error!`.

---

## 5a. Validate your config before applying (`hort-server validate-config`)

`hort-server validate-config` runs the **snapshot-free** subset of the
boot-time apply pass **offline** — parse, the per-envelope domain and
cross-document rules, and the static-linter rows; no database, no running
server — so a CI job can reject a bad config tree *before* it is merged or
rolled out. It is a pre-merge gate, not a substitute for apply.

```text
hort-server validate-config            # exit 0 = clean
hort-server validate-config --strict   # CI: warnings (incl. "0 config files") also fail
```

**Config comes from the same env as server boot — not from flags.** There is
no positional `<dir>` and no config-input flag; the command reads two
**required** env vars (plus one optional):

| Env var | Meaning | If unset / invalid |
|---|---|---|
| `HORT_CONFIG_DIR` | the gitops tree to validate (the exact var `serve` reads at boot) | **exit 2** |
| `HORT_STORAGE_BACKEND` | the storage backend **kind** (`filesystem` \| `s3`), used by the per-repo storage-backend check. **Kind only** — never the S3 bucket / endpoint / credentials, so **no secrets in CI**. **No `filesystem` default** (unlike `serve`): the offline check must not *guess* the backend. | **exit 2** |
| `HORT_UPSTREAM_USER_AGENT` *(optional)* | the outbound User-Agent override for pull-through fetches. Unset/empty ⇒ the binary's built-in default (no finding). A non-empty value that is **not a valid HTTP header value** (control characters) is linted as a **warning** — the server would silently fall back to the default at boot, so CI surfaces the silently-inert override. | **warning** (exit 1 only under `--strict`) |

The only flag is `--strict` (a CI **behaviour** toggle — warnings become
failures; config inputs stay env-only). `validate-config` reads **no**
`DATABASE_URL` and never connects to anything — it is the offline guarantee.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | clean (no errors; warnings present only when not `--strict`) |
| `1` | a validation error — a parse error, a row-0 error (per-envelope domain or cross-document rule), or any reject rule (including the per-repo storage-backend mismatch) — **or** (`--strict` and any warning, including the "0 config files" warning) |
| `2` | a required env var (`HORT_CONFIG_DIR` / `HORT_STORAGE_BACKEND`) is missing or invalid |
| `3` | operational — the config directory is unreadable |

A directory that exists but holds **0 YAML files** is a valid (empty) config
— exit `0` — but it emits `validated 0 config files — is HORT_CONFIG_DIR
correct?`. Because the CI checkout path differs from the in-cluster mount
path, a typo'd-but-existing `HORT_CONFIG_DIR` would otherwise read as a green
gate; **run CI with `--strict`** so the 0-files warning (and any rule
warning) fails the job.

### What it does NOT check (necessary, not sufficient)

A clean `validate-config` does **not** guarantee a clean apply. It runs the
parse, the per-envelope domain and cross-document rules (row 0 — the same
`DesiredState::validate` the apply path delegates to), and the static-linter
rows. Of apply's pre-write pass it does **not** run four checks:

1. the **current-state** check — a name declared in your tree that already
   exists as a `managed_by=local` row. Needs the live snapshot.
2. the **`HORT_UPSTREAM_ALLOWLIST_HOSTS`** check. Apply enforces it over the
   *create+update* slice of the `UpstreamMapping` diff, so it also needs the
   current state, to know which mappings are new.
3. the **auth-provider** check — `HORT_AUTH_PROVIDER=disabled` while
   `ClaimMapping` envelopes are declared. This needs only the deployment's
   `HORT_AUTH_PROVIDER` value, which the command does not read; not the
   running deployment.
4. the `scanBackends` supported-**name** check, which needs nothing the
   command lacks — apply validates each entry against the binary's
   compiled-in scanner set, `KNOWN_SCAN_BACKENDS`, not the live worker
   registry. Like (3), simply not wired here yet.

Only (1) and (2) are blocked on the running deployment.

The `scanBackends` **capability** rule above (`scan_backend_capability`) is a
different check and *does* run offline; it happens to catch most typos too,
because a name this build does not compile in analyses nothing — but it
reports the pairing rather than the typo, and it says nothing at all about a
policy whose scope reaches no declared repository. Checks inside apply's
write stages are likewise not represented. The command prints a one-line
footer saying all of this.

The validating binary **is** the version validated against: the
provenance-capable format set and the linter defaults are baked into the same
binary, so `hort-server:1.2.3 validate-config` validates exactly what
`hort-server:1.2.3` would enforce at boot. No `--version` flag is needed.

### CI recipe — derive the env from your Helm values

The env the cluster runs is rendered from the operator's Helm values; derive
the CI gate's env from the **same** values so the gate is faithful, overriding
only `HORT_CONFIG_DIR` (in-cluster it is the mounted ConfigMap path,
`/etc/hort-server/config`; in CI it is the repo checkout):

```bash
# Render the Deployment and lift its container HORT_* env into this shell.
helm template <release> deploy/helm/hort-server -f values.yaml \
  | yq 'select(.kind == "Deployment")
        | .spec.template.spec.containers[0].env[]
        | select(.name | test("^HORT_"))
        | .name + "=" + (.value // "")' \
  | while IFS= read -r kv; do export "$kv"; done

# In-cluster HORT_CONFIG_DIR is the ConfigMap mount; in CI it is the checkout.
export HORT_CONFIG_DIR="$CI_PROJECT_DIR/config"

hort-server validate-config --strict   # fail the MR on any error OR warning
```

The chart already renders `HORT_STORAGE_BACKEND` explicitly into the
Deployment env (`templates/deployment.yaml` / `templates/_helpers.tpl`, from
`.Values.storage.backend`), so the `helm template` derivation carries the
backend kind — do **not** rely on the binary's `filesystem` default, which
`validate-config` deliberately does not have. The operator's Helm values stay
the single source both the cluster and the CI gate derive from.

Exhaustive flag / env / exit-code tables and the full list of checks run
vs. not run:
[server-and-worker-configuration.md § `validate-config`](../reference/server-and-worker-configuration.md#validate-config).

---

## 6. What the v2 admin surface looks like

Repository creation, update, and delete via REST are intentionally
NOT exposed in v2 — every repository comes from a YAML envelope
under `$HORT_CONFIG_DIR`. The admin tree is deliberately minimal:

| Verb | Path | Purpose |
|------|------|---------|
| `GET` | `/admin/repositories/<key>` | Look up `{id, key, managed_by}` for a managed repo. Used by tooling that needs the row's freshly-minted UUID — for example `scripts/native-tests/scenarios/proxy/oci-mirror.sh` resolves the OCI mirror's UUID before driving downstream calls. |

Upstream-mapping CRUD is gitops-only: there is no
admin REST surface for `repository_upstream_mappings`. The gitops
writer for it is a first-class envelope —
`kind: UpstreamMapping` — that emits `RepositoryUpstreamMappingChanged`
events and writes `repository_upstream_mappings` rows. The schema is
documented in `crates/hort-config/src/upstream_mapping.rs` (YAML body
shape, `(repository, pathPrefix)` identity, `auth.type` enum,
optional `secretRef`, `insecureUpstreamUrl` opt-in for plaintext
upstreams). The `apply_upstream_mappings` pass runs alongside the
other gitops kinds and shares their `hort_gitops_objects_total` counter
under `kind="upstream_mapping"`; mappings whose URL host is not in
`HORT_UPSTREAM_ALLOWLIST_HOSTS` are rejected
at apply time and tick `result="rejected_not_in_allowlist"`. The
credentialed pull-through path is live in production; the OCI
multi-upstream pull-through smoke test exercises it end-to-end.

The `RepositoryUseCase::update` and `delete` methods still live in
`hort-app` and the `ManagedByConfiguration` rejection lives on
them; they're load-bearing for any future inbound (gRPC, CLI, a
later REST surface) that mounts them. They're just not addressable
from HTTP today.

If you want to change a repository, edit the YAML file and restart
the server.

### `ManagedByConfiguration` (when reachable)

The `RepositoryUseCase` mutators return `DomainError::ManagedByConfiguration`
for any write attempt against a `managed_by = gitops` row. The HTTP
boundary maps that to RFC 9457 problem+json:

```http
HTTP/1.1 409 Conflict
Content-Type: application/problem+json

{
  "type": "about:blank",
  "title": "Managed by configuration",
  "status": 409,
  "detail": "repository 'npm-public' is declared in configuration. Modify the configuration source and restart to apply.",
  "managedBy": "gitops"
}
```

Automation can route on the `managedBy` field. The mapping is in
`hort-http-core::error::ApiError::into_response`; once an inbound
surface mounts the affected use case methods, the 409 fires
without further wiring.

---

## 7. Observability

Four metrics. The first three are emitted by `hort-server::gitops_boot`;
`hort_gitops_events_emitted_total` is emitted by
`hort-app::ApplyConfigUseCase` for the event-sourced kinds.

| Metric | Labels | Meaning |
|---|---|---|
| `hort_gitops_apply_total` | `result` ∈ {`ok`, `parse_error`, `validation_error`, `apply_error`} | Boot-apply outcome — fires once per call |
| `hort_gitops_objects_total` | `kind` ∈ {`repository`, `claim_mapping`, `permission_grant`, `curation_rule`, `scan_policy`, `exclusion`, `upstream_mapping`, `oidc_issuer`, `service_account`, `retention_policy`, `permission_grant_lint_config`}, `result` ∈ {`created`, `updated`, `deleted`, `unchanged`, `rejected_not_in_allowlist`} | Per-envelope outcome counter — sum matches the boot log summary. For event-sourced kinds, counts envelopes (a multi-field update ticks once with `result=updated`). `result="rejected_not_in_allowlist"` is exclusive to `kind="upstream_mapping"` — fires when a mapping's URL host is not in `HORT_UPSTREAM_ALLOWLIST_HOSTS` and aborts the apply. The canonical label set is `Kind::label()` in `crates/hort-config/src/envelope.rs`; the retired labels `group_mapping` and `role` are NOT emitted (the kinds no longer exist). |
| `hort_gitops_events_emitted_total` | `kind` ∈ {`scan_policy`, `exclusion`}, `event_type` ∈ {`PolicyCreated`, `PolicyUpdated`, `ExclusionAdded`, `ExclusionRemoved`, `PolicyArchived`} | Per-event counter for the event-sourced policy kinds. A `ScanPolicy` whose YAML changes two fields emits two `event_type=PolicyUpdated` ticks (and one envelope-level `objects_total{result=updated}` tick). |
| `hort_gitops_apply_duration_seconds` | none | Histogram of wall-time per apply |

The full schema lives in `docs/metrics-catalog.md`.

**Authorization events are out of `hort_gitops_events_emitted_total`'s
scope.** The gitops apply path emits four authorization audit
events: `ClaimMappingApplied` / `ClaimMappingRevoked` (the
additive-claims rename of the retired `GroupMappingAdded` /
`GroupMappingUpdated` / `GroupMappingRemoved`; a create and an
in-place retarget both emit `ClaimMappingApplied`, so there is
deliberately no separate `*Updated` event) and `PermissionGrantApplied`
/ `PermissionGrantRevoked` (the rename of the
retired `PermissionGrantAdded` / `PermissionGrantRemoved`, now
carrying a sum-typed `GrantSubjectRecord` payload instead of the
dropped `role_id`). `ClaimMapping*` events always land on the global
`StreamCategory::Authorization` stream; `PermissionGrant*` events
route per-grant — `Some(repository_id)` lands on
`StreamCategory::Repository(r)` and `None` lands on the global
`StreamCategory::Authorization` stream. These are
intentionally **not** counted by `hort_gitops_events_emitted_total`
(which is reserved for the per-event-sourced-kind counter — `scan_policy`
and `exclusion`). To audit them, query the event log directly — for
example
`SELECT event_type, event_data FROM events WHERE event_type LIKE 'ClaimMapping%' OR event_type LIKE 'PermissionGrant%' ORDER BY global_position DESC LIMIT 50;`
— or read `crates/hort-domain/src/events/authorization_events.rs` for
the event-payload shapes. `hort_gitops_objects_total{kind=claim_mapping}`
and `hort_gitops_objects_total{kind=permission_grant}` still tick per
envelope outcome.

In `tracing` logs the apply emits `info!` lines on entry and exit
plus per-object outcomes; failures are `error!` with the rendered
`ParseErrors` / `ValidationErrors` / `ApplyError` body.

---

## 7a. Enforcement examples

§4a documented what the gitops apply pipeline writes when each kind
lands. The policy engine wires those declarations into the artifact
lifecycle: scan-result evaluation, exclusion-driven re-evaluation,
ingest-time curation blocking, and retroactive curation. This
section maps each decision point to a minimal YAML example and the
queryable evidence operators can use to confirm enforcement is
live.

The decision-point taxonomy and the result-label vocabulary are
canonical in `docs/metrics-catalog.md`
(`hort_policy_evaluation_total{decision_point, result}`). The
end-to-end smoke covering these examples is
`scripts/host-tests/test-gitops-policies.sh` phase 6.

### Scan-result enforcement (`decision_point=scan_result`)

```yaml
apiVersion: project-hort.de/v1
kind: ScanPolicy
metadata:
  name: prod-default
spec:
  scope: global
  severityThreshold: high
  quarantineDuration: 24h
  requireApproval: false
  provenanceMode: off       # optional; off | verify_if_present | required
```

**What this changes.** Every `ScanCompleted` event flowing through
`QuarantineUseCase::record_scan_result` is evaluated against the
resolved policy (repo-scoped → global → hardcoded `block_on_critical`
default). With `severityThreshold: high`, findings of severity
`critical` or `high` reject; `medium` / `low` / `negligible` leave
the artifact in `Quarantined` to ride out the time hold.

**Lifecycle on Reject.** The use case appends, atomically on the
artifact stream:
1. `ScanCompleted { scanner, finding_count, severity_summary }`
2. `PolicyEvaluated { policy_id, result: Fail, violations: [PolicyViolation { rule: "cve-severity-threshold", … }, …] }`
3. `ArtifactRejected { reason: "scan-policy violation: …", rejected_by: Scanner }`

`artifacts.quarantine_status` flips to `rejected` in the same
transaction.

**Lifecycle on Clean.** Only `ScanCompleted` is appended.
`quarantine_status` stays `quarantined`; the time-based sweep
governs release per architect-skill quarantine invariant 2 — a
clean scan does NOT release early.

**Queryable evidence:**
- `hort_policy_evaluation_total{decision_point="scan_result", result="reject"}` ticks once per reject.
- `hort_policy_evaluation_total{decision_point="scan_result", result="pass"}` ticks once per Clean (the result vocabulary normalises Allow to `pass`, NOT `allow`).
- `hort_policy_violations_total{decision_point="scan_result", rule="cve-severity-threshold"}` ticks once per reject pass; the `rule` label maps to the violation's typed rule name.
- SQL: `SELECT event_data->>'rejected_by' FROM events WHERE event_type='ArtifactRejected' AND stream_id=:artifact_id ORDER BY global_position DESC LIMIT 1;` — returns a JSON object whose discriminant is `"Scanner"` for scan-driven rejections.

**v1 dormancy disclaimer.** `record_scan_result` has no inbound
HTTP route in v2 — scan results land via the not-yet-built
`ScannerPort` adapter (architect-skill: "Scan results are only
injectable from internal system processes (C3)"). The
metric-fires-on-reject assertion is therefore exercised by
unit-test coverage, not by the scripts/native-tests smoke. The
decision point is fully wired in `hort-app`; what's missing is the
adapter that produces `ScanCompleted` events from a real Trivy /
Grype / OSV-scanner integration. The `[6/6]` banner in the smoke
records the explicit gap.

### Re-evaluation after exclusion added (`decision_point=re_evaluation`)

```yaml
apiVersion: project-hort.de/v1
kind: Exclusion
metadata:
  name: cve-2024-3094-on-old-xz
spec:
  policy: prod-default
  cveId: CVE-2024-3094
  packagePattern: "xz-utils@<5.6.2"
  scope: global
  reason: "Patched in container layer; not exploitable here"
  expiresAt: "2026-12-31T23:59:59Z"
```

**What this changes.** The gitops apply path's
`PolicyUseCase::add_exclusion` re-evaluation pass
walks every artifact currently `rejected` against the parent
`prod-default` policy and replays its last `ScanCompleted` against
the now-updated exclusion set.

**Lifecycle cascade per match (architect-skill quarantine
invariant 3):**
- If all blocking findings are now excluded AND `quarantine_until` is still in the future → emit `ArtifactReEvaluated { outcome: ResetToQuarantined, … }` + `ArtifactQuarantined { release_reason: PolicyReEvaluation }`. The artifact returns to `quarantined`; the remaining time hold still applies.
- If all blocking findings are now excluded AND `quarantine_until` has elapsed → emit `ArtifactReEvaluated { outcome: ResetToReleased, … }` + `ArtifactReleased { release_reason: PolicyReEvaluation }`. Direct release; the operator's exclusion plus an already-completed time hold combined.
- If blocking findings remain after exclusion → no events; metric ticks `result=still_rejected` only.

**Queryable evidence:**
- `hort_policy_evaluation_total{decision_point="re_evaluation", result="reset_to_quarantined" | "reset_to_released" | "still_rejected"}` ticks once per evaluated artifact.
- SQL: `SELECT COUNT(*) FROM events WHERE event_type='ArtifactReEvaluated' AND event_data->>'trigger_exclusion_id' = :exclusion_id;` — exact count of artifacts the new exclusion re-evaluated.

**v1 dormancy disclaimer.** Same as the scan-result path: no
inbound surface produces the `Rejected` artifacts this pass operates
on. The pipeline is fully wired and unit-tested; live-stack
exercise lands when a `ScannerPort` adapter ships.

### Curation ingest-time blocking (`decision_point=curation`)

```yaml
apiVersion: project-hort.de/v1
kind: CurationRule
metadata:
  name: block-known-bad-1
spec:
  format: any
  pattern: "evil-package*"
  action: block
  reason: "CVE-2024-9999 — recorded on every match"
---
apiVersion: project-hort.de/v1
kind: ArtifactRepository
metadata:
  name: pypi-curated
spec:
  name: "PyPI Curated"
  format: pypi
  type: hosted
  storage:
    backend: filesystem
    path: /var/lib/hort-server/cas/pypi-curated
  isPublic: true
  replicationPriority: local_only
  curationRules:
    - block-known-bad-1
```

**What this changes.** `IngestUseCase::ingest` runs the curation
gate BEFORE `storage.put()` — the artifact bytes never
land in CAS. The pure evaluator iterates the rules linked to the
target repo in declaration order; the first rule whose `format`
matches (`any` or the repo's specific format) AND whose `pattern`
glob matches `coords.name` returns the rule's action.

**Format-specific HTTP responses to `DomainError::CurationBlocked`:**
| Format | Path type | Status | Rationale |
|---|---|---|---|
| OCI/Docker | Pull-through proxy (`GET /v2/.../blobs/sha256:…`) | `404 BLOB_UNKNOWN` | Mirrors upstream "blob doesn't exist"; clean `docker pull` UX with no spurious 403. |
| OCI/Docker | Hosted upload (`POST /v2/.../blobs/uploads/…`) | `403 Forbidden` | Operator deliberately blocked this push; client SHOULD see the rejection. |
| PyPI | Hosted upload (`POST /pypi/<repo>/`, twine path) | `403 Forbidden` | PyPI has no pull-through path in v2; default `CurationBlocked` → 403 mapping applies. Body carries `rule_name` + `reason`. |
| npm / Cargo / others | Hosted upload | `403 Forbidden` | Same default mapping; per-format pull-through paths apply it as they land. |

**Lifecycle on Block at ingest.** One event lands —
`CurationApplied { repository_id, coords, rule_id, rule_name, action: Block, reason, trigger: Ingest }` —
on `StreamCategory::Curation` keyed by `StreamId::curation_per_repo(repository_id)`.
NO event lands on the artifact stream (the artifact was rejected
pre-ingest; no `ArtifactIngested` ever fires for it). On Allow, no
event lands at all (high-volume path; `ArtifactIngested` carries
the success-path audit trail).

**Queryable evidence:**
- `hort_policy_evaluation_total{decision_point="curation", result="block"}` ticks per Block decision.
- `hort_policy_evaluation_total{decision_point="curation", result="pass"}` ticks per Allow ingest (the result vocabulary normalises curation `Allow` to `pass` so dashboards aggregate happy-path traffic under one label across decision points).
- `hort_policy_evaluation_total{decision_point="curation", result="warn"}` ticks per Warn match — the artifact is ingested but a `CurationApplied { action: Warn, … }` event lands.
- `hort_policy_violations_total{decision_point="curation", rule="curation-block"}` / `curation-warn` ticks per non-Allow.
- SQL: `SELECT COUNT(*) FROM events WHERE event_type='CurationApplied' AND stream_id=:repo_id AND event_data->>'trigger'='Ingest';` — count of non-Allow ingest decisions per repo.

### Retroactive curation (`decision_point=curation_retroactive`)

Same `CurationRule` shape as above. The retroactive trigger is the
gitops apply pipeline: when a rule is
**newly created** OR its **action tightens** (Allow → Warn → Block)
OR its **pattern broadens**, the apply path schedules a retroactive
evaluation pass for that rule. Active artifacts in repos linked to
the rule are walked and re-evaluated.

**Asymmetric semantics — this is not optional.** Rule **deletion**
or **weakening** (Block → Warn → Allow) does NOT auto-unblock
artifacts that were retroactively rejected. Nothing *automatic* reverses
a rejection: the rule change applies to what is evaluated after it, and
the already-rejected artifacts stay rejected until a human decides
otherwise. What a human may do is the curator's manual release, which as
of ADR 0007's 2026-10-11 amendment reaches a `curation_retroactive`
rejection — the curator owns that axis, so an authority that may block
may unblock — with attribution and a justification on the event. A
corruption tombstone is never reachable that way (architect-skill
quarantine invariant
3). The smoke at
`scripts/host-tests/test-gitops-policies.sh` phase 6c asserts
this explicitly — a Block→Allow rewrite must produce zero
`curation_retroactive` metric ticks AND leave previously-rejected
artifacts in `quarantine_status = rejected`.

**Lifecycle on RetroBlock per matching artifact:**
- `CurationApplied { action: Block, trigger: Retroactive, rule_id, rule_name, reason, … }` lands on `StreamCategory::Curation` for the repo.
- `ArtifactRejected { reason: "<rule reason>", rejected_by: CurationRetroactive { rule_id } }` lands atomically on the artifact stream via `commit_transition`. `artifacts.quarantine_status` flips to `rejected` in the same DB transaction.

**Lifecycle on RetroWarn:** only the `CurationApplied` event lands;
no artifact-stream change.

**Lifecycle on NoChange:** no events.

**Queryable evidence:**
- `hort_policy_evaluation_total{decision_point="curation_retroactive", result="retro_block" | "retro_warn" | "no_change"}` ticks once per evaluated artifact per linked repo.
- SQL: `SELECT id, name FROM curation_rules WHERE name = :rule_name;` — resolve the freshly-applied rule's UUID.
- SQL: `SELECT event_data->>'rejected_by' FROM events WHERE event_type='ArtifactRejected' AND stream_id=:artifact_id ORDER BY global_position DESC LIMIT 1;` — the latest reject's `rejected_by` is a JSON object whose discriminant is `"CurationRetroactive"` with the matching `rule_id`.
- Strict-atomic concurrency: the retroactive append is optimistic-concurrency-checked against the artifact's current version. A concurrent ingest / promotion that bumps the artifact's version while the apply pass runs causes the apply to abort `strict-atomic` per the apply pipeline's semantics; the operator restarts and the second pass re-resolves.

---

## 8. Limitations (v1)

- **Mixed persistence across the policy kinds.** `ScanPolicy` and
  `Exclusion` are event-sourced;
  `PermissionGrant` (a sum-typed subject)
  emits `PermissionGrantApplied` / `PermissionGrantRevoked` on
  the `Authorization` stream; `CurationRule` remains a CRUD shape.
  `kind: Role` is retired — see §4a's
  retirement callout. See §4a for the operator-facing surface. The
  dormancy disclaimer for the policy-evaluation pipeline (§7a) still
  applies — the policy engine consumes these
  declarations.
- **No `User` / `ApiToken` kinds.** Users JIT-provision from
  Keycloak; API tokens require the secrets backend.
- **No reload signals.** No `SIGHUP`, no
  `POST /admin/config/reload`. Restart-to-apply.
- **No drift detection.** API-side enforcement (the 409) is the
  only contract; out-of-band SQL writes are unsupported and
  invisible.
- **No multi-tenant subtree RBAC.** Single flat `$HORT_CONFIG_DIR`;
  extensible to subtrees in a later release without breaking the
  schema.

These limits are deliberate scope decisions, not oversights: the
restart-to-apply contract keeps the loader free of pollers, signal
handlers, and reconciliation loops, and the missing kinds each have a
safer existing path (IdP JIT-provisioning for users; the token API for
tokens).
