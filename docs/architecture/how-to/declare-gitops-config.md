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
apiVersion: project-hort.de/v1beta1
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

`apiVersion: project-hort.de/v1beta1` is the only accepted version. The
`v1alpha1` suffix signals "subject to change without a deprecation
window" — re-emit your YAML when a new variant lands.

Unknown fields anywhere in `spec` fail validation: typos surface at
boot, not as silent defaults.

---

## 3. `kind: ArtifactRepository`

```yaml
apiVersion: project-hort.de/v1beta1
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

**Serve-supported formats: `npm`, `pypi`, `cargo`.** A `type: virtual`
repo on any other format (`oci`, `maven`, …) is **rejected at apply** —
its `virtualMembers` would be accepted but never served (the ADR 0015
inert-field guard). The supported set is the single source of truth in
`crates/hort-config/src/repository.rs` (`VIRTUAL_SERVE_SUPPORTED_FORMATS`).

Members must reference other ArtifactRepository objects in the same
`$HORT_CONFIG_DIR`. Mixing a managed virtual with `Local` (API-created)
members is rejected — keep the gitops surface self-contained, or keep the
virtual itself `Local`. A member that is itself `type: virtual` is rejected
(no nested virtuals in v1).

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
apiVersion: project-hort.de/v1beta1
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
apiVersion: project-hort.de/v1beta1
kind: ClaimMapping
metadata:
  name: developers-from-platform-eng
spec:
  idpGroup: platform-eng
  claim: developer
---
apiVersion: project-hort.de/v1beta1
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
`PermissionGrant`, `CurationRule`, `ScanPolicy`, `Exclusion`. The
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
  the claim mechanism entirely. The natural fit for service-account
  grants and audited break-glass escalations.

**Permission** is a single string, one of
`read | write | delete | admin | admin_task_invoke | curate`.

**Repository** is a single optional `ArtifactRepository.metadata.name`
reference. **Omit the field entirely** for a global grant; a blank
string is rejected (the two shapes mean different things and the
parser refuses to silently equate them).

#### Claim-gated grant

```yaml
apiVersion: project-hort.de/v1beta1
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
apiVersion: project-hort.de/v1beta1
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

#### User-bound grant (service accounts, break-glass)

```yaml
apiVersion: project-hort.de/v1beta1
kind: PermissionGrant
metadata:
  name: curator-ci-rotation-bot
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
apiVersion: project-hort.de/v1beta1
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
apiVersion: project-hort.de/v1beta1
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
apiVersion: project-hort.de/v1beta1
kind: ScanPolicy
metadata:
  name: default-quarantine
spec:
  scope: global                 # `global` or `{ repository: <key> }`
  severityThreshold: high       # critical | high | medium | low
  quarantineDuration: 24h       # humantime duration
  requireApproval: true
  provenanceMode: verify_if_present   # optional; off | verify_if_present | required
  maxArtifactAge: 90d           # optional humantime
  licensePolicy:                # optional JSON; defaults to no license policy when omitted
    allowed: [Apache-2.0, MIT]
    denied: [GPL-3.0]
```

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
apiVersion: project-hort.de/v1beta1
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
apiVersion: project-hort.de/v1beta1
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

**What apply emits:**
- First apply: one `ExclusionAdded` event on the parent policy's
  stream; one row inserted into `exclusion_projections`. Counters:
  `hort_gitops_events_emitted_total{kind=exclusion,event_type=ExclusionAdded}`.
- Field edit (scope, reason, expiry): one `ExclusionRemoved` +
  one `ExclusionAdded` on the same stream — the events crate has
  no `ExclusionUpdated`, and remove-and-add is the canonical update
  form.
- YAML removed: one `ExclusionRemoved` event with
  `reason = "removed by gitops apply"`; the projection row is
  deleted.

**Idempotency:** reapply with no YAML change emits zero events. The
parent `ScanPolicy` must exist in the same `$HORT_CONFIG_DIR` (or as a
prior projection) — the cross-spec validator rejects orphan
exclusions before any DB write.

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
apiVersion: project-hort.de/v1beta1
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
apiVersion: project-hort.de/v1beta1
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

Declares a non-human identity. Three valid shapes — federation
only, rotation only, or both. The "neither" case (no
`federatedIdentities:` and no `fallbackRotation:`) is also valid
and represents a PAT-only identity an operator mints via `hort-cli
admin token issue`.

**Federation only** — most common for OIDC-capable workloads:

```yaml
apiVersion: project-hort.de/v1beta1
kind: ServiceAccount
metadata:
  name: gha-myorg-myrepo-pypi
spec:
  role: developer
  repositories: [pypi-internal]
  federatedIdentities:
    - issuer: github-actions
      claims:
        repository: my-org/my-repo
        environment: production
```

**Rotation only** — for workloads that cannot do OIDC:

```yaml
apiVersion: project-hort.de/v1beta1
kind: ServiceAccount
metadata:
  name: legacy-docker-puller
spec:
  role: reader
  repositories: [oci-internal]
  fallbackRotation:
    targetSecret:
      name: hort-pull-secret
      namespace: ci-system
      format: dockerconfigjson      # or `opaque`
    rotationInterval: 6h
    validity: 24h
```

**Both** — federation as primary path, rotation as fallback for
non-OIDC clients in the same identity scope:

```yaml
apiVersion: project-hort.de/v1beta1
kind: ServiceAccount
metadata:
  name: ci-pypi-pusher
spec:
  role: developer
  repositories: [pypi-internal]
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
```

Apply-time validation rules:

- `role` ∈ `{developer, reader}`. **`admin` is forbidden** —
  admin authority is reserved for short-lived interactive
  sessions ([ADR 0013](../../adr/0013-idp-authoritative-cli-sessions.md)).
- `repositories` non-empty (no global service-account grants).
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
- `fallbackRotation.targetSecret.namespace` is **not** validated
  against `worker.rotation.targetNamespaces` at apply time — the
  chart's allow-list is a runtime concern. Mismatches surface as
  reconciler warnings, not apply-time rejection.

**What apply does:** inserts (or updates) one row in
`service_accounts`, plus rows in `federated_identities` and the
`fallback_rotation` sub-table. On first apply the use case also
ensures a backing `users` row exists with
`is_service_account = true` and `username = "sa:<metadata.name>"`,
and emits `PermissionGrant` rows for `role × repositories`.
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

`hort-server validate-config` runs the **structural + domain + static-linter**
subset of the boot-time apply pass **offline** — no database, no running
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
| `1` | a validation error — a parse / cross-validate error, or any reject rule (including the per-repo storage-backend mismatch) — **or** (`--strict` and any warning, including the "0 config files" warning) |
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
structural (parse + cross-validate), per-envelope domain, and static-linter
checks. It does **not** run the **current-state** checks (managed-by
ownership, immutable-field changes — they need the live `ManagedBy=Local`
snapshot), which run at apply/boot against the running deployment. It also
does not currently run the `scanBackends` supported-backend check (apply
validates each entry against the binary's compiled-in scanner set,
`KNOWN_SCAN_BACKENDS` — a static set the offline validator could check but
does not yet). The command prints a one-line footer saying so.

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
apiVersion: project-hort.de/v1beta1
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
apiVersion: project-hort.de/v1beta1
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
apiVersion: project-hort.de/v1beta1
kind: CurationRule
metadata:
  name: block-known-bad-1
spec:
  format: any
  pattern: "evil-package*"
  action: block
  reason: "CVE-2024-9999 — recorded on every match"
---
apiVersion: project-hort.de/v1beta1
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
artifacts that were retroactively rejected. Rejection is sticky;
admin explicit release via `POST /quarantine/:artifact_id/release`
is the only way to un-reject (architect-skill quarantine invariant
3, mirroring scan-driven rejection). The smoke at
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
