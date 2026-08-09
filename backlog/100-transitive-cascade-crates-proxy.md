# 100 — Enable the transitive prefetch cascade on crates-proxy

**Issue:** #139 (item F) · **Branch:** `agent/139-instance-parameterisation` · **Scope:** one gitops envelope

## Why

The cascade is a shipped hort feature that this deployment does not use:
`crates-proxy`'s `prefetchPolicy` declares `triggers: [on_dist_tag_move]`
only. Enabling it is a deliberate dogfooding decision — hort should exercise
the mechanism its own users rely on.

It is genuinely implemented for cargo: the format handler is archive-aware, so
it opens the `.crate` tarball, reads `[dependencies]` from the contained
`Cargo.toml`, and resolves each range through `resolve_range_max`
(ADR 0053).

## Change

`deploy/ansible/files/gitops/repositories/crates-proxy.yaml`:

- add `transitive_deps` to `triggers` (keep `on_dist_tag_move`),
- set `maxDescendants` **explicitly** rather than inheriting the default —
  depth bounds a single walk, this bounds the fan-out, and an implicit breadth
  cap on a newly-enabled cascade is exactly the value an operator should see,
- leave `transitiveDepth` at its default of 5 (appropriate for cargo; changing
  it is a separate, deliberate "I accept a wider fan-out" decision),
- extend the envelope's header comment with what the trigger now does and the
  breadth/depth relationship.

## Expectations, honestly stated

For hort's **own** CI this changes little: the lockfile warm already posts the
complete 692-entry closure. The cascade pays off for consumers who do not hand
hort a complete lockfile — ad-hoc `cargo add`, unlocked builds, third-party
projects. It also does **not** make `cargo install --locked <tool>` work; that
needs `[build-dependencies]`, which the cascade excludes by design (ADR 0053).

Cost: more upstream traffic to crates.io and more ingests per pulled crate.

## Acceptance

- The envelope parses under the apply-time linter — verify with the repository's
  own gitops validation path rather than by eye.
- Takes effect only on the operator's Ansible apply; nothing in CI depends on
  it, so the change is inert until then.
