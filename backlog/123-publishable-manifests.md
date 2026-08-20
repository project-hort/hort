# 123 — Make the published crates' manifests publishable

Issue: #175. First of two units; **124 depends on this one** (fixing the
publish order is pointless while every manifest after the first is
rejected). Do not start 124 before this merges.

## What is wrong

`cargo publish` rejects a manifest whose dependencies carry no version
requirement, because the published form drops `path` and must resolve
through the registry:

```
error: failed to verify manifest at `/…/crates/hort-app/Cargo.toml`
Caused by:
  all dependencies must have a version requirement specified when publishing.
  dependency `hort-config` does not specify a version
```

Across `crates/*/Cargo.toml`, **30 of 37 crates** declare intra-workspace
dependencies as `hort-x = { path = "../hort-x" }`, and **not one** carries a
version. `hort-domain` published successfully on `v0.11.0-beta.4` only
because it is the single crate with no intra-workspace dependencies at all.

## What

1. **Consolidate into `[workspace.dependencies]`.** Declare each
   intra-workspace crate once in the root `Cargo.toml` with both `path` and
   `version`, and have members inherit (`hort-domain.workspace = true`).
   This turns ~49 edit sites into one block, which is what makes step 2
   tractable.

2. **Keep the version requirements in lockstep with the release version.**
   The release cut currently bumps `[workspace.package] version` (plus
   `Chart.yaml` and the lockfile) and must now also move the
   `[workspace.dependencies]` version strings.

   **A static `0.11.0-dev` requirement does not work** — under semver
   pre-release ordering `0.11.0-beta.4 < 0.11.0-dev`, because `beta` sorts
   before `dev`, so a beta build would not satisfy its own workspace
   requirement. Verify this against the versions actually in use rather
   than assuming the direction; it decides whether the bump can be a single
   sed or needs to understand pre-release ordering.

   `RELEASING.md`'s procedure has to change with it, or the next cut
   produces manifests whose requirements point at the previous version.

3. **Add a structural guard test.** Assert that every intra-workspace
   dependency carries a version requirement equal to the workspace version.
   Follow the crate's existing pattern (`no_sensitive_drops`,
   `ephemeral_keyspace_exhaustive`, `retention_registration_guard`): a
   DB-free, sub-second source scan under `crates/*/tests/`, which
   `cargo test --workspace` picks up with no gate-list entry.

   This is the part that stops the defect recurring. It would have failed
   the first time anyone added a path-only dependency, instead of surfacing
   at a release three versions later.

## Scope

Every crate that declares an intra-workspace dependency, not only the five
currently published — a crate that becomes publishable later should not
reintroduce the problem, and the guard test will demand it anyway.

## Out of scope

The publish order and the published set (unit 124). Do not edit
`.github/workflows/release.yml` here.

## Done when

`cargo publish --dry-run --registry hort-crates` verifies the manifest for
each of the five published crates without a version-requirement error, and
the guard test fails if a path-only intra-workspace dependency is
reintroduced.
