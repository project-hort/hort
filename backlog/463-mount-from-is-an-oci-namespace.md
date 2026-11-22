# 463 — `from=` on a blob mount is an OCI namespace, not a repository key

**Issue:** #459 · **Branch:** `agent/459-oci-namespace-identity` · Unit 4 of 5.
**Security-relevant**: the site carries a documented privilege-escalation control. Read the whole doc comment before changing a line of it.

## The site and the control

`handle_cross_mount` (`crates/hort-http-oci/src/uploads.rs:253-300`) takes
`from: &str` and resolves it as a hort **repo_key** through
`RepositoryAccessUseCase::resolve`. Its doc comment states why:

> Without the authz check on the source repo, any caller with `Write` on
> `target-repo` could clone any blob from any other repo in the registry — even
> a private one they had no `Read` grant on — by submitting
> `?mount=<sha>&from=<other-repo>`.

On the wire, `from` is an OCI `<name>` — which in hort is `repo_key` plus
`name`. So `from=library/nginx` is being read today as a repository key called
`library/nginx`, and a mount that names a namespace inside the caller's own
repository cannot be expressed at all.

## What must not change

1. **The `Read` authz check stays on the source *repository*.** The name
   narrows *further*; it never replaces the repository-level grant. A split that
   checks only the name would re-open exactly the escalation the comment
   describes.
2. **The OCI §2.3 fall-through stays.** An unreadable source currently collapses
   to "initiate a normal blob upload" with `202 Accepted`, because the spec
   requires a registry that cannot mount to fall back, and a 4xx breaks
   docker/skopeo retry loops. That must now also cover an **unparseable** or
   **unknown** `from`, and it must stay anti-enumerating: a caller must not be
   able to tell "no such name" from "name you may not read".
3. The per-`(repo, principal)` session cap on the fall-through path.

## The parse

`from` is one string and hort needs two values out of it. The repository key is
the first segment and the name is the rest — the same split the `/v2/` router
already performs on the request path. **Find that splitter and reuse it**; a
second, differently-behaving parse of the same grammar is how the two drift.
If the router's split is not reusable from here, say so and state what you did
instead rather than hand-rolling a near-copy.

## Acceptance

- `from=<repo_key>/<name>` mounts a blob the caller may read, from that name.
- A blob that exists in the source repository but under a **different** name is
  not mounted: the answer is the §2.3 fall-through, not a 4xx and not a mount.
- A `from` naming a repository the caller cannot read still falls through with
  `202`, indistinguishably from a `from` naming a repository that does not
  exist — assert both answers are identical, because that identity is the
  anti-enumeration control.
- An unparseable `from` falls through rather than erroring.
- A mount between two names **inside one hort repository** works — the case that
  is unrepresentable today.
- The change adds no uncovered lines.
