# 042 — GitOps schema `project-hort.de/v1` (keep supporting `v1beta1`)

**Issue:** #67
**Read first:** `crates/hort-config/src/envelope.rs` (the `ApiVersion` enum, `FromStr`/`Display`,
lines ~19-51 + its tests), `crates/hort-config/src/error.rs` (the unsupported-apiVersion message,
~line 26), `deploy/ansible/files/gitops/**` (shipped examples), `scripts/alpha-fixtures/**`.

## Context

Pre-v1.0: promote the gitops config schema from `project-hort.de/v1beta1` to a stable
**`project-hort.de/v1`**, while **continuing to accept `v1beta1`** (no forced operator migration).
Domain confirmed `project-hort.de` (version bump, not a rename).

## Scope

**1. Parser (`crates/hort-config/src/envelope.rs`)**
- Add `ApiVersion::V1` accepting/emitting `project-hort.de/v1`; **keep** `V1Beta1`
  (`project-hort.de/v1beta1`). Update `FromStr` (both parse), `Display` (each emits its own
  literal), and the enum's doc comments (V1 = stable; V1Beta1 = supported/deprecated).
- Decide the **emitted default** for anything that constructs a fresh envelope: `V1`.

**2. Error message (`crates/hort-config/src/error.rs`)**
- The "only `project-hort.de/v1beta1` is accepted in v1" message → "accepts `project-hort.de/v1`
  (current) and `project-hort.de/v1beta1` (supported; deprecated)". Keep the fail-closed reject for
  anything else (e.g. `project-hort.de/v2`).

**3. Migrate shipped examples to `v1`** (parser still dual-accepts, so this is cosmetic-but-honest)
- `deploy/ansible/files/gitops/**/*.yaml` — bump every `apiVersion: project-hort.de/v1beta1` → `…/v1`.
- `scripts/alpha-fixtures/**` gitops fixtures — same.
- **Doc snippets** — `apiVersion:` examples across `docs/**` (coordinates with #68's note that the
  operator docs currently show `v1beta1`; update them to `v1`). Grep-drive it:
  `grep -rl 'project-hort.de/v1beta1' deploy docs scripts crates/hort-config/src/*.rs` — migrate the
  example/fixture/doc occurrences; **leave the parser's own `V1Beta1` literal + its tests** (they must
  keep testing that `v1beta1` still parses).

**4. Tests**
- `envelope.rs`: `project-hort.de/v1` parses to `V1`; `v1beta1` still parses to `V1Beta1`; each
  round-trips through `Display`; `project-hort.de/v2` still errors with the improved message.
- A **mixed tree** (some objects `v1`, some `v1beta1`) parses + cross-validates.
- The `public_deploy_gitops_tree` / `alpha_fixtures` guards pass with the migrated (now-`v1`) trees.

## Acceptance

- Both `project-hort.de/v1` and `project-hort.de/v1beta1` parse + apply; unknown versions fail
  closed with the improved message.
- Shipped gitops examples + alpha fixtures + doc snippets are on `v1`; the parser still accepts
  `v1beta1` (proven by a retained test).
- Full gate green (`cargo test --workspace`, fmt, clippy, audit, deny).

Gates the v1.0-alpha cut. Independent of the #69/#70 doc phases.

### Starter prompt

```
/hort-architect

Implement backlog item 042 (issue #67) on branch agent/67-gitops-schema-v1. IMPORTANT: run
`git checkout agent/67-gitops-schema-v1` and verify with `git branch --show-current` before EVERY
commit — commits must land on this branch, never on develop. Read envelope.rs + error.rs first.
Add ApiVersion::V1 (project-hort.de/v1) keeping V1Beta1; update the error message; migrate the
shipped gitops examples + alpha fixtures + doc apiVersion snippets from v1beta1 to v1 (but keep the
parser accepting v1beta1, with a retained test). Add tests: both versions parse, a mixed tree
applies, v2 still errors, and the gitops-tree guards pass. Run the full gate and report per the
handover protocol.
```
