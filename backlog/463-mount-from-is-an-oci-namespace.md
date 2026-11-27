# 463 — `from=` on a blob mount is an OCI namespace, not a repository key

**Issue:** #459 · **Branch:** `agent/459-oci-namespace-identity` · Unit 4 of 7.
**Security-relevant**: the site carries a documented privilege-escalation control. Read the whole doc comment before changing a line of it.

## The site and the control

`handle_cross_mount` (`crates/hort-http-oci/src/uploads.rs:274`, re-measured
against `develop` at `18865f1f`) takes
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
2. **The OCI §2.3 fall-through stays.** An unreadable source collapses to
   "initiate a normal blob upload" with `202 Accepted`. **Corrected
   2026-11-23:** this said the spec *requires* the fall-back. It does not —
   *"Alternatively, if a registry does not support cross-repository mounting or
   is unable to mount the requested blob, it **SHOULD** return a `202`."* So it
   is hort's choice, and it has three supports rather than an obligation: the
   spec recommends it, a `4xx` breaks docker/skopeo retry loops, and it is what
   makes the surface anti-enumerating. That must now also cover an
   **unparseable** or **unknown** `from`: a caller must not be able to tell "no
   such name" from "name you may not read".
3. The per-`(repo, principal)` session cap on the fall-through path.

## The parse — there is no splitter to reuse, measured 2026-11-23

`from` is one string and hort needs two values out of it: the repository key is
the **first segment** and the OCI name is the **rest**
(`/v2/private-repo/library/nginx/…` → `repo_key = private-repo`,
`name = library/nginx`).

This item first said *"the same split the `/v2/` router already performs —
find that splitter and reuse it"*. **There is no such splitter.** Measured:

- the router splits **declaratively**, through axum's path pattern
  `"/v2/{repo_key}/{*tail}"` (`crates/hort-http-oci/src/lib.rs:444`), so the
  split is performed by the framework and there is no function to call;
- the one inline `rest.split_once('/')` on this grammar is inside
  `path_to_scope` (`crates/hort-http-oci/src/v2_auth.rs:369`), which consumes a
  **URL path** and returns an auth **scope string** — a different input and a
  different output, not a `(repo_key, name)` helper;
- `strip_oci_suffix` solves the other half (tail → name) and a `from` value
  carries no suffix to strip.

So this unit writes the **first** application-code parse of that grammar. Give
it **one** definition with the grammar stated beside it, so the second caller
has something to call rather than something to copy. Say in the report where you
put it and why there.

## Acceptance

- `from=<repo_key>/<name>` mounts a blob the caller may read, from that name.
- A blob that exists in the source repository but under a **different** name is
  not mounted: the answer is the §2.3 fall-through, not a 4xx and not a mount.
- A `from` naming a repository the caller cannot read still falls through with
  `202`, indistinguishably from a `from` naming a repository that does not
  exist. **Corrected 2026-11-23:** this said "assert both answers are
  identical", and raw byte-identity is impossible — each `202` mints a fresh
  upload session and must carry its own UUID in `Location` and
  `Docker-Upload-UUID`. The property is indistinguishability **up to that
  nonce**: every status, header and body field equal once the two session IDs
  are normalised, which is what the implementation asserts.
- An unparseable `from` falls through rather than erroring.
- A mount between two names **inside one hort repository** works — the case that
  is unrepresentable today.
- The change adds no uncovered lines.

## The one race, measured and answered (2026-11-23)

The implementing run asked whether the window between the name-scoped existence
check and `register_by_hash`'s checksum-based source lookup needs a follow-on:
if the named row is deleted in between, registration can find a different row
with the same hash under a different name in that repository.

**It does not, and the reason is worth recording so nobody re-opens it as a
security question.**

- **The name is not an authorisation boundary on the source side.** The `Read`
  grant is resolved against the source **repository** and covers every name in
  it, so a mount resolved from a sibling name is one the caller could have
  asked for directly by naming it. The race hands them nothing.
- **The status axis is closed independently.**
  `IngestUseCase::register_by_hash` carries its own anti-laundering refusal —
  a source row whose `quarantine_status.is_terminal()` collapses to the same
  `NotFound` the "no such blob" arm returns — evaluated against whichever row
  registration actually resolves. So the gate cannot be smuggled past by
  swapping the row underneath.

What remains is identity correctness in a window, with no observable
consequence for anyone able to open it. An atomic name-bound source lookup
would widen an application port to buy that; not worth it. The reasoning now
sits in the handler beside the check, because the check reads redundant next to
`register_by_hash`'s gate and deleting it would silently restore cross-name
mounting.