# 220 — A retention policy must name repositories, not UUIDs

**Issue:** #282 · **Branch:** `agent/282-retention-scope-by-name`
**Governing decisions:** the retention concept's unit A (it blocks every other
retention unit) · ADR 0015's rule turned around: a field an operator can only
fill with unusable values is as inert as a field nobody reads.

## Why

`RetentionScope::Repos` carries UUIDs, and the module says so itself
(`crates/hort-config/src/retention_policy.rs:19-21`): *"resolving repo
`metadata.name` → id is a planned DSL follow-on not yet implemented."*

Writing a repository UUID into gitops YAML contradicts every other reference in
that tree, and the policy is worthless the moment the instance is rebuilt with
fresh ids.

To be precise about what is broken and what is not: `AllRepos`, `Format`,
`PackageNamePattern` and `IngestSource` are writable today
(`crates/hort-domain/src/retention/scope.rs:47-63`), so it is not the case that no
retention policy can be authored at all. What cannot be authored is a policy that
names a repository — and that is the scope a first cleanup needs, because the
142 GB are not spread evenly and the decision is per repository. The production
instance holds **zero** retention policies against 51 535 artifacts; this unit is
one of the reasons, not the only one (the candidate reader and the inert
count-based predicates are the others), and it is the one that has to fall first.

## Read first

- `crates/hort-config/src/scan_policy.rs` — `ScopeSpec`, the name-carrying
  shape (line 40) and the cross-spec rule that a scope's repository must
  resolve to a declared repo (line 202). **This is the precedent to mirror.**
- `crates/hort-app/src/use_cases/apply_config_use_case.rs:1718` —
  `resolve_scope`, the single resolution point, and `repo_id_by_name`, the map
  the apply pipeline fills from DesiredState before dispatching policy applies.
- `crates/hort-config/src/retention_policy.rs` — the spec, its validation, and
  the module docs to correct.
- `crates/hort-domain/src/retention.rs` (`RetentionScope`, `matches`) — the
  resolved, UUID-carrying domain form, which does **not** change.

## Scope

1. **The spec takes names.** The repos variant in `hort-config` carries
   `Vec<String>` (each a `metadata.name`). The domain enum keeps
   `Repos(Vec<Uuid>)` — that is the resolved form, and the split (names at the
   operator surface, ids in the domain, resolution exactly once in apply) is the
   same one `ScanPolicy` already uses.
2. **Cross-spec validation** mirroring the scan-policy rule: every named
   repository must be declared in the same desired state, or the apply linter
   rejects the envelope naming the offending value. The existing non-empty rule
   for the list stays.
3. **Resolution in apply** through the same `repo_id_by_name` map, under the
   same ordering guarantee (repositories resolved before policies). Do not add a
   second resolution path, and do not resolve at evaluation time.
4. **Remove the UUID branch rather than keeping both.** There is nothing to
   migrate — the projection table is empty in production and the UUID form was
   never usable. Carrying both shapes would preserve a form no operator should
   write.
5. **Docs:** add a named example to the gitops how-to that covers retention, and
   drop the "not yet implemented" sentence from the module header once it is no
   longer true.

## Acceptance

- An envelope naming repositories by `metadata.name` is accepted, resolved, and
  the projection carries the UUIDs.
- An envelope naming an undeclared repository is rejected at apply, and the
  message names the value.
- No code path accepts a UUID from the spec any more.
- A policy naming a repository declared in the *same* apply resolves correctly
  (ordering test).
- Gate green (`cargo fmt --check`, `cargo clippy --workspace --all-targets -D
  warnings`, `cargo test --workspace`, `cargo audit`, `cargo deny`);
  `hort-domain` and `hort-app` stay at 100 %; no issue, MR or backlog numbers in
  code comments.

## Explicitly not in this item

No dry run (that is the next unit), no state opt-in for the evidence class, no
change to predicates, to the candidate reader, or to the purge path.
