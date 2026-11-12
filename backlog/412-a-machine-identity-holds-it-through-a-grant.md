# 412 — A machine identity holds it through the grant path that exists

**Issue:** #285 · **Branch:** `agent/285-destructive-authority-is-a-permission` ·
item 2 of 2. **Depends on item 1** (there is no permission to grant until it
exists). **This item amends `docs/auth-catalog.md` Entry 4; the issue carries
`no-auto-merge`.**

**Read this first — item 1 has landed and this item's quotes predate it.**
Item 1 (`5ef2d802`) removed `DESTRUCTIVE_TASK_CLAIM` and rewrote the CronJob
template comments, the SA declaration notes and several how-to passages that
this item quotes — including *"no token can be made to carry the claim"*,
which is no longer the mechanism. **Where a quote below and the tree
disagree, the tree is right and the quote is this item's pre-change
record.** Re-read every anchor against the branch tip before changing it; the
*decisions* this item states are unaffected, only the surrounding wording
moved. `backlog/236` names the claim too and was deliberately left alone.

**Governing decisions:** **#281 D6** (a machine identity may run destructive
tasks, **via a grant** — decided), ADR 0037 (`serviceAccount`-subject grants
resolve to `GrantSubject::User(backing_user_id)` at apply), ADR 0012 (the
grant path for a long-lived static token; the cap is frozen at mint),
ADR 0038 (a service account is strictly non-admin),
`docs/auth-catalog.md` Entry 4 (**amended here**).

## The property

**The mechanism already exists, and this item's job is to let exactly one of
the two new permissions through it.**

An earlier grooming specified a new claim-declaration field on the
`ServiceAccount` envelope. There is no new field. Entry 4 of the auth catalog
states the envelope's contract: *"the `kind: ServiceAccount` envelope is
**identity + federation binding only** (`metadata.name`,
`federatedIdentities`, `fallbackRotation` — no `role`, no `repositories`; an
envelope still carrying those fields fails apply at parse via
`deny_unknown_fields`)"*, and authority arrives *"exclusively via explicit
`GrantSubject::User(backing_user_id)` grants (ADR 0012) — scoped
`Read`/`Write`/`Curate`/global `AdminTaskInvoke` expressed as gitops
`serviceAccount`-subject `PermissionGrant`s that resolve to
`GrantSubject::User(backing_user_id)` at apply (ADR 0037)."*

So a machine identity holding the content permission is one more entry in
that list, declared the way the other four already are. The envelope is not
touched, `deny_unknown_fields` keeps protecting it, and the naming hazard the
earlier grooming spent a section on — `federatedIdentities[].claims` already
means something else and an empty one is a documented
privilege-escalation footgun — **disappears with the field**.

## D1 — one of the two, and the other is refused at apply

A service account may hold **`destroy_content`**. It may not hold
**`destroy_record`**: `eventstore-archive` removes the record itself and
nothing reconstructs it, so standing machine authority over it is not what
#281 D6 decided. The issue's acceptance says the same from the token's side —
a token minted for the SA authorises `retention-purge` and does **not**
authorise `eventstore-archive`.

**Fail-closed at declaration, not merely absent from the docs.** The shape to
mirror is how `admin` is refused for a `serviceAccount` subject, which Entry 4
describes as *"forbidden at three independent points"*:

1. `validate_permission_grant` hard-rejects it at apply-parse
   (`crates/hort-config/src/permission_grant.rs`),
2. the apply linter denies the SA-provenance exemption
   (`crates/hort-app/src/lint/permission_grants.rs`; `admin`'s case is pinned
   by `direct_user_sa_owned_admin_is_rejected`),
3. `issue-svc-token` rejects it on the mint path.

Read all three before deciding how many `destroy_record` needs. The
refusal message names *why* — that the record has no reconstruction behind
it — rather than only *what*, because an operator who reaches for it is
trying to automate something and needs to know what to automate instead.

## D2 — the `cronjob-tasks` identity is the live case

The gitops tree already carries the service account these CronJobs run as,
and both halves say today that it cannot do this:

- `deploy/ansible/files/gitops/auth/service-accounts/cronjob-tasks.yaml` and
  its grant `…/auth/grants/cronjob-tasks-task-invoke.yaml` (factor 1 only),
- the three chart CronJob templates
  (`deploy/helm/hort-server/templates/cronjob-{retention-evaluate,retention-purge,eventstore-archive}.yaml`).

**Read their operator notes before writing anything — they are more precise
than this item's earlier draft was, and they already state the mechanism.**
`cronjob-retention-purge.yaml:38-47` says the shipped non-admin
`cronjob-tasks` svc-token *"cannot satisfy `task:destructive` and this
CronJob fails if run with it"*, and then goes further: *"**No token can be
made to carry the claim**: a native token resolves no IdP claims at all, so
the only token that passes the gate is an admin user's, **which passes it by
the admin short-circuit**."* That is the same short-circuit this issue's
item 1 rests on, already written down in the chart.

So the honest statement of today's position is **not** "automatable with a
broader credential" — it is **not automatable at all**. Both documented
routes are manual break-glass: *"run them by hand with a Dex-backed admin
CliSession or a narrow `HORT_TOKEN_ALLOW_ADMIN`-gated token"*
(`deploy/ansible/files/gitops/auth/service-accounts/cronjob-tasks.yaml:19-21`
— that is where the `HORT_TOKEN_ALLOW_ADMIN` note lives, not in the CronJob
template), and `api_token_use_case.rs:104` calls the latter a
*"break-glass mechanism"* in those words. Replacing a documented break-glass
with a narrow standing grant on the job's own identity is the point of the
whole issue, and it is a stronger case than the earlier draft made.

So this item ships the content grant for `cronjob-tasks` in the Ansible
gitops tree, and corrects those template comments to name the grant instead
of the admin-token workaround. **`eventstore-archive`'s template keeps
pointing at the human path**, and now says why: the record half is not
grantable to a machine.

Leave both CronJobs `enabled: false`. Turning them on is the issue's own
"not in this ticket", and it follows the preview and purge-quiescence work.

## D2b — the shipped identity is PAT-only, so a grant alone does nothing

**An outside review corrected this item's central operational claim.** I
wrote that the fallback-rotation reconciler re-snapshots the SA's grants
every `rotationInterval`, so the grant would land on its own, and asked only
which interval the shipped declaration uses.

**There is no interval.** `cronjob-tasks` is a **PAT-only** ServiceAccount —
no `fallbackRotation` block
(`deploy/ansible/files/gitops/auth/service-accounts/cronjob-tasks.yaml:23-25`),
so the reconciler never touches it
(`crates/hort-app/src/task_handlers/service_account_rotation.rs:119-124`).
And its Ansible mint declares **only** `admin_task_invoke`
(`deploy/ansible/roles/hort_timers/tasks/main.yml:37-52`), so with the cap
frozen at issuance the token cannot pass factor 2 however the grants read
(`crates/hort-domain/src/entities/api_token.rs:309-313`). The CLI also exits
without reminting an existing token unless `--rotate` is given
(`crates/hort-server/src/cli/admin.rs:592-605`).

**So this item owes two more things**, and without them the retention
CronJobs stay exactly as unable to run as they are today: the shipped Ansible
mint cap gains the content permission, and an **idempotent rotation of the
existing token** is specified — a grant plus an unchanged cap is the
frozen-cap trap this project has already paid for once.

## D2c — declaration-form refusal is not identity-wide; the backstop is at runtime

The item refuses the record permission for a `serviceAccount`-subject
envelope at apply, plus the linter exemption and `issue-svc-token`. **That
does not make "an SA may not hold it" true**, and the hole is real:

- a syntactically valid **direct `User`-subject** grant naming the SA's
  **backing user** is accepted by the per-spec validator and materialised
  unchanged by apply (`crates/hort-config/src/permission_grant.rs:256-289`;
  `apply_config_use_case/permission_grants.rs:105-119`);
- the linter's high-privilege rejection is **configurable down to `Pass`**,
  and its SA-owned exemption derives from the **subject form** rather than
  from a user-row identity check
  (`crates/hort-app/src/lint/permission_grants.rs:455-481`);
- such a grant then enters the rotation / federation snapshot and the runtime
  evaluator, and **both SA mint functions reject only `Admin`**.

**So add a hard refusal of the record permission for a ServiceAccount-kind
caller at the runtime gate**, as a backstop to all three declaration and mint
checks. Refusing a *form of declaration* is not refusing an *identity*, and
the identity is what was decided.

## D3 — the rotation consequence belongs where the operator edits

The cap is frozen at mint (ADR 0012), so **a grant added after a token was
issued is inert for that token until it is rotated**. This has already cost a
diagnosis round: on #257 a correctly applied grant was live in the DB and in
the evaluator snapshot and the endpoint still answered `403`, and it read as
an authorisation defect.

Two things make it survivable rather than a trap, and both are facts to state
rather than guesses:

- The server's own denial hint already names it — *"a grant added after
  issuance enters the cap on the next exchange or rotation."*
- `GET /api/v1/auth/whoami` is the surface that answers "what can **this**
  token do": its `effective_grants` is `grants ∩ claims ∩ cap` rendered per
  repository, and `permissions` is the frozen set.

For `cronjob-tasks` specifically the fallback-rotation reconciler re-snapshots
the SA's effective grants every `rotationInterval` (Entry 4's Issuance caps),
so the grant lands on its own within that interval — say which interval the
shipped declaration uses, rather than "after rotation".

## D4 — the catalog amendment

`docs/auth-catalog.md` Entry 4 is the canonical inbound-auth spec and this
changes what a service account may hold, so it is amended **in this MR**:

- **Restrictions & caps** — the grantable list becomes
  `Read`/`Write`/`Curate`/`AdminTaskInvoke` **plus the content-destructive
  permission**, and the record-destructive permission is named as refused,
  beside `admin`, with its refusal points.
- **Mandatory guardrails** — *"no `claims:[…]` ever"* **stays exactly as it
  is.** This item does not weaken it; it is the reason the design looks like
  this. Say that in the amendment, so the next reader does not have to
  reconstruct why a destructive authority arrived as a grant.

Nothing else in Entry 4 moves: SA self-mint stays a hard reject, admin stays
forbidden at three points, the envelope stays identity + federation binding
only.

## Acceptance

- A `ServiceAccount` holds the content-destructive authority through an
  ordinary gitops `serviceAccount`-subject `PermissionGrant`, with **no new
  envelope field** and `deny_unknown_fields` untouched.
- A token minted for that SA authorises `retention-purge` and
  `retention-evaluate` in execute mode, and does **not** authorise
  `eventstore-archive` — the latter refused **at the runtime gate for a
  ServiceAccount-kind caller**, asserted with a grant that reached the
  identity through a direct `User` subject rather than a `serviceAccount`
  one, because that is the path the declaration checks do not close.
- The shipped `cronjob-tasks` mint cap carries the content permission and an
  **idempotent rotation** of the existing token is specified; a test or a
  stated command proves a grant alone does not suffice.
- A grant of the record-destructive permission to a `serviceAccount` subject
  is **rejected at apply**, with a message naming why, at the same points
  `admin` is rejected — asserted at each point, not only end-to-end.
- The SA remains non-admin; the `GrantSubject` taxonomy is unchanged.
- The `cronjob-tasks` grant ships in the gitops tree; the two content-side
  CronJob templates and the SA declaration name the grant instead of the
  break-glass routes, and `eventstore-archive`'s template plus the SA note
  say why that one still has only the manual path.
- Both CronJobs stay `enabled: false`.
- A grant applied after a token was minted is inert for that token until
  rotation, documented where an operator edits the declaration — and stating
  that `cronjob-tasks` is **PAT-only with no `fallbackRotation`**, so no
  interval will do it for them.
- `docs/auth-catalog.md` Entry 4 is amended: the grantable list, the named
  refusal, and the unchanged `claims` guardrail with the reason it is
  unchanged.
- Gate green; `hort-domain`/`hort-app` add no uncovered lines; no ticket
  numbers in code comments.
