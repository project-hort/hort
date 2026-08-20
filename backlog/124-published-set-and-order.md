# 124 — Fix the published crate set and derive its publish order

Issue: #175. Second of two units; **depends on backlog 123** (manifests must
be publishable before the order matters). Do not start before 123 merges.

## Three defects, one step of the release workflow

### 1. The declared order contradicts the dependency graph

`.github/workflows/release.yml`:

```bash
publish_crate crates/hort-domain
# hort-app: depends on hort-domain
publish_crate crates/hort-app
# hort-config: depends on hort-domain + hort-app
publish_crate crates/hort-config
```

Both comments are wrong. `hort-config` depends only on `hort-domain`;
`hort-app` depends on `hort-config`. The true order is
**domain → config → app → http-core → formats**.

A hand-maintained topological comment has already drifted once, silently.
**Derive the order** (`cargo metadata` exposes the dependency graph) rather
than restating it, so it cannot drift again.

### 2. The published set is not dependency-closed

`hort-http-core` declares:

```toml
# Optional — enabled by the `test-support` feature …
hort-adapters-ephemeral-memory = { path = "../hort-adapters-ephemeral-memory", optional = true }
```

`hort-adapters-ephemeral-memory` is **not published**. An optional
dependency still requires a version requirement at publish time and still
appears in the published manifest, so a consumer enabling `test-support`
from the registry cannot resolve it.

Decide deliberately between:

- **publish it too** — the set grows to six, the `test-support` feature
  works for registry consumers; or
- **remove the edge from the published crate** — move the `build_mock_ctx`
  wiring so `hort-http-core` does not carry it, and the feature becomes
  workspace-only.

Whichever wins, state it in the workflow comment. The first is smaller; the
second keeps a test-only adapter out of the public surface, which may be
the point.

### 3. Nothing is marked `publish = false`

**No crate in the workspace sets `publish = false`** — 37 crates, of which
5 are intentionally published. The other 32 are publishable by accident:
one stray `cargo publish` in the wrong directory, or a future loop over
workspace members, puts an internal adapter on the registry, and a
published version cannot be withdrawn, only yanked.

Set `publish = false` on every crate not in the published set. This also
gives the release workflow an unambiguous, machine-readable definition of
that set — which pairs with the derived order in defect 1: enumerate
members, drop the ones marked unpublishable, publish the rest in
topological order. No hand-maintained list at all.

## Note on quarantine

`v0.11.0-beta.4` logged `timed out waiting for hort-domain … to be
available` after a successful upload — the crate was quarantined, hence
absent from the `released_only` index. Under `--no-verify` that was a
warning only. Whether a later crate's publish *resolves* its just-published
sibling, and so hard-fails on a quarantined dependency, becomes observable
for the first time once this unit lands. If it does, the chain needs the
same warm/waive choreography the dependency set needs — do not design that
in speculatively, but report it if the run shows it.

## Done when

A release run publishes the closed set in a derived topological order, with
no crate outside that set publishable, and the workflow contains no
hand-maintained ordering comment.
