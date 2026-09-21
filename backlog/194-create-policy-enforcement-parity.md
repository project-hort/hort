# 194 — `create_policy` writes the command's `enforcement` into the projection (parity test command ↔ projection)

**Issue:** #267 · **Branch:** `agent/267-create-policy-enforcement` · single item · hort-app only.

## Defect

`PolicyUseCase::create_policy` (`crates/hort-app/src/use_cases/policy_use_case.rs` ~397–460) builds
the `ScanPolicyProjection` from the `CreatePolicyCommand` field by field — except
`enforcement: ScanEnforcement::Reject`, hard-coded. The `PolicyCreated` event's `config_snapshot`
already carries `cmd.enforcement` (`build_config_snapshot`, ~2324), so the event is right and the
projection lies. The update path (`FieldChange::Set`, ~703–711) honours the field, which is why a
long-running deployment self-heals on a later apply and a fresh compose stack never does.

Governing decisions: ADR 0056 / ADR 0034 (record vs reject at the gate). Pure correction.

## Change

1. `enforcement: cmd.enforcement` in `create_policy`'s projection literal.
2. Tests (hort-app, 100 % on touched branches):
   - `create_policy` with `enforcement: Record` ⇒ `projections.find_by_id(...).enforcement == Record`;
     with `Reject` ⇒ `Reject`.
   - Parity: the projection written by `create_policy` equals, field by field, what
     `build_config_snapshot(&cmd)` records (deserialise the snapshot and compare each field, or
     compare against a projection built by one shared helper from the command) — so the next
     omitted line fails a test instead of shipping.
3. `CHANGELOG.md` `### Fixed`: a policy created with `enforcement: record` now records from its
   first apply; previously it enforced until a later apply corrected it.

## Must not change

Event shape, policy schema, gate semantics, the update path.

## Acceptance

- Unit tests above green; `cargo test --workspace`, fmt, clippy, audit, deny green.
- E2E (human, branch-first, after this merges and #265 rebases): `dogfood/maven-osv-scan` 6/6.
