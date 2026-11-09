# 404 — A decision is addressed by what was reviewed

**Issue:** #176 · **Branch:** `agent/176-a-decision-binds-to-the-bytes` ·
item 2 of 3. Part B of the issue spec, server side.

**Governing decisions:** ADR 0007 (`CuratorWaiver` release authority, reused
unchanged and never widened), ADR 0025 (state-precondition violations → 409),
ADR 0038 (service accounts are strictly non-admin — this is why the authority
stays `Permission::Curate` and does not climb to Admin), ADR 0060
(append-conflict reaction contract — governs the apply loop). No standing
decision governs bulk-release addressing; the issue spec sets it.

## The property

**A curator writes down what they reviewed, and the system resolves it.**
Today `block` can be addressed by artifact UUID and by version list, and
`waive` only by UUID
(`crates/hort-app/src/use_cases/curation_use_case.rs:618` — `waive` takes a
bare `artifact_id`; `BlockTarget` at `:110` has `Artifact` and `VersionList`
and nothing else). A UUID is neither writable by a human nor stable across
re-ingestion, so the waive side has no addressing a reviewed decision can be
expressed in.

## What to build

**Three routes, one resolver each, sharing the digest resolver.**

- `POST /api/v1/admin/curation/waive-versions` —
  `{ repository, package, versions[], justification }`. Resolution mirrors
  `BlockTarget::VersionList`: `find_by_name_in_repo`
  (`crates/hort-adapters-postgres/src/artifact_repo.rs:478`), per-version
  match. For the formats where `artifacts.version` is populated and
  immutable.
- `POST /api/v1/admin/curation/waive-digests` —
  `{ repository, digests[], justification }`. For OCI and anything
  content-addressed. A digest may carry a `sha256:` prefix, which is
  normalised away; any other algorithm prefix is a validation error.
  Resolution is repo-scoped by `artifacts.checksum_sha256`. **A digest that
  resolves to more than one live row in the repository is a validation error
  naming the ambiguous artifact ids** — identical bytes can be ingested at
  several paths, and fail-closed beats guessing which row was reviewed.
- `POST /api/v1/admin/curation/block-digests` — the symmetric sibling,
  sharing that resolver, with `BlockTarget::VersionList`'s batch semantics
  unchanged (continue-on-error, cap `MAX_VERSIONS_PER_CALL` = 100, and a
  `not_found_digests[]` mirroring `not_found_versions`,
  `crates/hort-http-core/src/handlers/admin/curation/block_versions.rs:92`).

**The waive batch does NOT copy block's contract, and that asymmetry is the
point.** Bulk block is fail-safe; bulk waive is fail-open, because
`ArtifactReleased` is history that cannot be retracted. So:

1. **Cap 25** (`MAX_WAIVE_ENTRIES_PER_CALL`), against block's 100. The
   over-broad waive list is the footgun this bounds. Enforced at the handler
   and in the use case, as the block cap already is
   (`crates/hort-http-core/src/handlers/admin/curation/mod.rs:106`,
   `crates/hort-app/src/use_cases/curation_use_case.rs:89`).
2. **Strict pre-validation, then apply.** Every entry is resolved and checked
   before any event is appended. An entry that is unresolvable, ambiguous, or
   in any state other than `Quarantined` or `Released` **aborts the whole
   batch** — 409 per ADR 0025, a per-entry error report, zero releases
   applied.
   The state set is deliberately narrower than the per-artifact route, which
   also reaches `ScanIndeterminate` and, under its `required_triggers`,
   `Rejected` (`crates/hort-domain/src/entities/quarantine_transitions.rs`,
   the `Release` row). The reason is #419: a `scan_indeterminate` hold now
   has an exit that is not a curator override — the `cron-rescan-tick`'s
   stranded-candidate sweep re-picks it and the arriving verdict releases or
   rejects it — so a fail-open bulk surface has no reason to reach that
   population. `waive artifact` remains available for the one-off.
3. **`Released` entries are idempotent successes**, reported as
   `already_released_ids` with no event, mirroring block's
   `already_rejected_ids`. A re-apply of the same decision has to converge
   rather than fail forever.
4. **Apply is sequential and honestly reported.** Appends across N artifact
   streams are not one transaction. A state change between validate and
   apply surfaces as an append or guard failure handled per ADR 0060: re-read,
   already-`Released` ⇒ idempotent success, otherwise the entry lands in
   `failed[]` — reported, never silently skipped, and never retried into a
   release the curator did not review.
5. **One `ArtifactReleased` per artifact, one shared `correlation_id` per
   call**, each event carrying `released_by_user_id` and the justification
   (the `Curator` validate arm already requires both). One justification per
   call, 512 bytes, stamped verbatim on every event
   (`crates/hort-domain/src/events/artifact_events.rs:580`).

**Authority: `Permission::Curate` via `CurateOrAdminPrincipal`, unchanged.**
A batch entry's authority is identical to a single waive — same
`CuratorWaiver` release authority, same per-entry transition guard. The
safety margin is the structural controls above, not a permission tier; an
Admin gate would also collide with ADR 0038 and lock the gitops pipeline
this addressing exists for out of applying its own decisions.

## Acceptance

- `waive-digests` with one valid and one non-`Quarantined` entry releases
  **nothing** and reports both entries.
- Re-running a fully applied `waive-digests` call succeeds with every id in
  `already_released_ids` and emits no event.
- `waive-digests` on a digest matching two live rows fails naming both
  artifact ids.
- A `sha256:`-prefixed and a bare digest for the same bytes resolve
  identically; a `sha512:` prefix is a validation error.
- Cap 25 rejected at the handler and in the use case; the justification limit
  is unchanged at 512 bytes.
- One correlation id across the call, one `ArtifactReleased` per released
  artifact, each carrying curator and justification.
- No tag is accepted as an addressing key on any of the three routes.
- 100 % coverage on the new `hort-app` / `hort-domain` branches — every
  abort arm, every resolver error, the ambiguity arm and the ADR 0060
  re-read arm included.
