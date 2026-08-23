# 0058 — The admin config-inspection surface is read-only, admin-gated, and answers for *this* process

- **Status:** Accepted
- **Enforced by:** the `AdminPrincipal` extractor on both routes (401
  anonymous / 403 non-admin, pinned per-endpoint by test); the
  hand-projected response DTOs — `EffectiveUpstreamMappingDto` omits
  every `SecretRef` field and surfaces only `has_credentials`, guarded by
  a test that greps the serialized body for each secret locator, and the
  apply-status response is pinned to an exact top-level key set so a new
  field is a deliberate, reviewed addition; the endpoints living in
  `hort-http-core` (ADR 0008), which is the one inbound crate permitted
  to read `AppContext`'s `pub(crate)` data ports; the boot-only,
  in-memory `Arc<ArcSwap<Option<GitopsApplyStatus>>>` field, which has no
  persistence path to drift into.
- **Supersedes:** —
- **Relates:** [0008](0008-per-format-adapter-free-http-crates.md) (the
  crate topology this sits inside, and the `pub(crate)` `AppContext` data
  ports the format crates may not touch),
  [0012](0012-claim-based-rbac.md) (the `admin` claim these routes gate
  on — no new scope is introduced),
  [0009](0009-least-privilege-runtime.md) (gitops apply is a boot step
  run with the runtime DSN; this surface only reads what it produced),
  [0015](0015-apply-time-linter-inert-fields-and-naming.md) (the naming
  discipline behind `no_apply_recorded` being a distinct discriminator
  rather than a zeroed body).

## Context

Two questions an operator could not ask a running hort-server:

1. **"What config did you actually resolve for this repository?"** The
   effective view of a repository is assembled at request time from the
   repository row, its upstream mappings, and a scan policy resolved
   through a precedence chain (repo-scoped > global > built-in default).
   None of that is visible from the gitops YAML alone — the YAML is the
   input, not the resolution — and reading it out of Postgres by hand
   reproduces the precedence logic in a psql session, which is exactly
   the place it will be reproduced wrong.

2. **"Which config are you running?"** Gitops apply happens at boot. Mid
   rollout, some pods have applied the new bundle and some have not, and
   there was no way to tell them apart from the outside. The boot log
   line carries the counts, but logs are not a queryable surface and a
   pod that has been running for a week has rotated it away.

Both are inspection, not control. Gitops remains the only writer of
configuration; nothing here changes that.

## Decision

**Two read-only, admin-gated endpoints. No new authz scope, no new
persistence, no write surface.**

- `GET /api/v1/admin/repositories/{key}/effective-config` — the
  repository aggregate, its upstream mappings, and the *resolved* scan
  policy, as one projection.
- `GET /api/v1/admin/gitops/apply-status` — the gitops apply **this
  process** performed at boot.

### Admin-only, reusing the existing gate

Both routes are gated by the `AdminPrincipal` extractor — the same gate
`GET /api/v1/admin/workers` and the patch-candidate surface already use.
**No new scope, permission or claim was introduced.**

That is a deliberate choice rather than an omission. The effective-config
view spans every repository, including ones the caller has no grant on,
and it discloses the resolved policy binding — the shape of the release
gate — for all of them. A narrower "read your own repository's config"
scope would be a genuinely different feature with a per-repository authz
check; inventing one here to make an admin-shaped read look
finer-grained would produce a scope that is not actually enforced at the
resource level. Adding a claim is also not free: ADR 0012 closed the
claim vocabulary to what `claim_mappings` declares, and a runtime-minted
inspection claim is precisely the shape that anti-pattern forbids.

The gate lives at the request edge. `hort-http-core`'s router sends every
`GET` through `extract_optional_principal`, so a read handler that
forgets to enforce is silently world-readable — the `AdminPrincipal`
extractor is what makes these two endpoints not that, and each has a
401-anonymous and a 403-non-admin test pinning it.

### Apply status is in-memory, since boot

`AppContext` carries `Arc<ArcSwap<Option<GitopsApplyStatus>>>`, written
once by the composition root from the boot apply's outcome. It is **not
persisted**.

The reason is that a persisted row would answer a different question than
the one asked. "What did this server apply?" is a fact about the process
answering; "what does the `gitops_apply_status` table say?" is a fact
about whichever process wrote last. During a rolling upgrade those differ
routinely, and the reader cannot tell which pod's boot it is looking at —
so the persisted answer is not merely less useful, it is misleading in
exactly the situation the endpoint exists for. Two pods reporting two
different generations is the correct output: it says the rollout has not
converged.

It also costs nothing to keep it in memory. There is no migration, no
write path on the serving DSN, and no row to garbage-collect when a pod
dies. And because the read touches no port, the endpoint keeps answering
when the database does not — which is when an operator is most likely to
be asking what config the process is running.

`None` means no apply ran: a DSN-only boot, or `HORT_CONFIG_DIR` unset.
It is surfaced as its own `status: "no_apply_recorded"` discriminator
with every other field omitted, **not** as a zeroed body. A genuine no-op
apply — the common steady-state case, where the config has not changed
since the last boot — also produces all-zero counters, and the two must
not be confusable. The generation is the field that distinguishes them,
and its absence is the discriminator's job to make unmissable.

The `ArcSwap` mirrors the existing `Arc<ArcSwap<RbacEvaluator>>`: a
lock-free read on the request path, and a seam for a future re-apply path
to replace the snapshot. No such path exists today — gitops apply is a
boot step and restart-to-apply is the contract — so in practice the cell
is written once at composition and only read afterwards.

### `generation` is a digest of the applied desired state

`generation` is the hex SHA-256 of the `DesiredState` that was applied
(`hort_config::diff::desired_state_digest`), computed once, at the apply
call site, on the state about to be applied. Apply is strict-atomic, so a
successful apply means exactly that state landed.

Equal generations across two processes mean they applied the same
configuration; different generations mean the configuration changed. It
is a fingerprint, **not a counter** — nothing orders two generations, and
a rollback to an earlier bundle correctly reproduces that bundle's
earlier generation rather than minting a higher number.

The canonical serialization is the one the diff already uses. The fold
hashes the **per-kind spec digests** (`spec_digest_repository`,
`spec_digest_claim_mapping`, …) — canonical JSON with lexicographically
sorted keys at every level, several of which additionally normalise
order-insensitive collections before hashing (repository virtual members,
OIDC issuer audiences, service-account federated identities). Reusing
them is what makes the generation agree with the diff about what
"unchanged" means: hashing a fresh serialization instead would flip the
generation on a YAML reordering that produces zero row updates, i.e. it
would report "the config changed" for a config that did not.

Entries are `(kind, name, spec digest)` triples, sorted before hashing,
so neither the directory-walk order nor the order of envelopes within a
file affects the result. A `Vec` is sorted rather than collected into a
set, so a duplicate `(kind, name)` — a validation failure that runs
before apply — cannot be silently collapsed here. Kinds without a
diff-time digest (scan policies, retention policies, exclusions, and the
singleton lint config) use the same canonical-JSON algorithm directly;
all of them participate, because a lint-config change is a real config
change even though it writes no row of its own. A domain-separation
prefix is hashed first, so bumping the fold invalidates every previously
computed generation — which is what a change to the fold should do.

**Source paths are excluded.** `DesiredState::source_files` and
`lint_config_sources` record which file declared what; moving a
declaration between files changes neither the applied configuration nor
the resulting rows, and so must not change the generation.

### Per-kind counts are projected from the plan, not recomputed

The apply plan already computes per-kind create/update/delete/unchanged
lists, and every CRUD kind's apply increments the rolled-up counters by
walking those very lists. The counts were then discarded with the plan.
They are now projected onto `ApplyReport::per_kind` inside `apply()`, so
the breakdown is the *same numbers* the aggregate is built from rather
than a second computation that could disagree with it.

The breakdown covers five kinds — repositories, upstream mappings, claim
mappings, permission grants, curation rules. The aggregate additionally
spans the event-sourced kinds (scan policies, retention policies,
exclusions) and the machine-identity kinds (OIDC issuers, service
accounts), so **the per-kind counts do not sum to the aggregate**. That
is documented on the type, on the DTO, and in the response's own field
docs, because a breakdown that silently fails to reconcile is worse than
no breakdown.

### No secrets, structurally

Neither response carries a secret, and the mechanism that keeps it that
way is hand projection rather than good intentions.

`RepositoryUpstreamMapping` carries four `SecretRef` fields
(`secret_ref`, `mtls_cert_ref`, `mtls_key_ref`, `ca_bundle_ref`) and
`SecretRef` derives `Serialize` — so a `#[serde(flatten)]` or a raw
domain row in a response body would emit the credential locator (an env
var name, a mounted file path) into the admin surface. The response DTO
is therefore constructed only through an explicit `from_domain`
projection that names each field it carries, surfacing at most an opaque
`has_credentials: bool`, and a test greps the serialized body for every
secret locator value.

Apply status has no secret to omit — it is counts, a timestamp and a
digest. It is hand-projected anyway, and its test pins the exact
top-level key set, so a field added to `GitopsApplyStatus` later cannot
reach the wire without someone deciding it should.

## Rejected alternatives

**Persisting apply status to a table.** Answers "what did the last writer
apply?", which mid-rollout is a different pod. Costs a migration and a
write path on the serving DSN to become less accurate. See above.

**A dedicated inspection scope or claim.** The effective-config view is
cross-repository and discloses release-gate shape; a scope that reads as
narrower than `admin` without a per-resource check would misrepresent
what it grants. ADR 0012 also closes the claim vocabulary to declared
`claim_mappings`, so a runtime-invented inspection claim would reopen it.

**A zeroed body for "no apply ran".** Indistinguishable from a genuine
no-op apply, which is the steady state. Own discriminator instead.

**A write surface (re-apply, edit) on these routes.** Gitops is the only
configuration writer. An inspection endpoint that can also mutate is a
different feature with a different threat model.

**Serializing the domain types directly.** Removes the one structural
barrier between a `SecretRef` gaining a serializer and it appearing in an
admin response.

## Consequences

- Operators can diff two pods' `generation` during a rollout and see
  convergence directly; equal generations across a fleet is a clean
  "everyone is on the same config" signal.
- The generation is comparable but not orderable. Tooling that wants
  "which is newer" must use `applied_at`, and even that is per-process.
- Restarting a pod re-runs the apply and produces a fresh `applied_at`
  with (for unchanged config) the same generation. That is the intended
  reading: the generation tracks the config, the timestamp tracks the
  process.
- `ApplyReport` grew a `per_kind` field. It stays `Copy` and its
  `Default` is still all-zeros, so an apply that changes nothing still
  compares equal to `ApplyReport::default()`.
- The per-kind breakdown stops at five kinds. Extending it to the
  remaining plan kinds is mechanical if the gap proves confusing in
  practice; it would still not make the breakdown sum to the aggregate,
  because the event-sourced kinds have no plan of this shape.
