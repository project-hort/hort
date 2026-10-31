# 352 — The CLI advertises only task kinds the server routes

**Issue:** #388 · **Branch:** `agent/388-scan-obligation`
**Governing decisions:** ADR 0008 (layering — the CLI does not depend on an
inbound-HTTP adapter crate) · none governing the help text.

## What is true today

`hort-cli admin task invoke --help` prints a v1 allowlist that includes
`scan` (`crates/hort-cli/src/admin/mod.rs:129`). The server routes eleven
task kinds and `scan` is not among them
(`crates/hort-http-admin-tasks/src/lib.rs:83-115`), so the advertised call
lands on the `GET /{id}` pattern:

```
POST /api/v1/admin/tasks/noop  -> 202 {"task_job_id": "…"}
POST /api/v1/admin/tasks/scan  -> 405 Method Not Allowed
```

Measured on a live instance by the reporter.

A scan is enqueued per artifact (`POST /api/v1/artifacts/<id>/rescan`), never
as a bare task kind, so the help text is what is wrong — not the route.

## Why this is a defect

An operator reaching for a documented recovery instrument during an incident
gets a `405` and no hint of where the real one is. The reporter's §5 — no
identity can rescan a proxy artifact — was reached partly through this door.

## The change

1. Remove `scan` from the advertised allowlist and point the same help text
   at `hort-cli admin rescan` for the per-artifact path.
2. **The structural close**, because a hand-maintained list in one crate
   describing routes in another is exactly what drifted: a DB-free source
   scan under `crates/*/tests/` asserting that every kind named in the CLI's
   allowlist text has a `post` route in `hort-http-admin-tasks`, and that
   every routed kind is either advertised or explicitly listed as
   deliberately unadvertised with a reason in the scan itself. No
   allow-list file — a kind that should not be advertised says so where the
   assertion stands.

A shared constant **imported from the router crate** is rejected: `hort-cli`
deliberately carries no domain, app or adapter dependency
(`crates/hort-cli/Cargo.toml:17-32`) while the router depends on both
(`crates/hort-http-admin-tasks/Cargo.toml:14-16`), so that direction is
unsound. A third, dependency-free crate holding the advertised list would
*also* work and is not forbidden — the source scan is chosen over it because
it adds no crate and keeps the list where a reader of either side will look,
not because the graph leaves no alternative.

**The guard must account for the four deliberately-unadvertised routed
kinds** — `service-account-rotation`, `eventstore-checkpoint`,
`replay-seen-prune`, `scanner-registry-prune`
(`hort-http-admin-tasks/src/lib.rs:99-114`) — and must compare against the
eleven `post(invoke::<…>)` routes, **not** against
`ADMIN_INVOKABLE_TASK_KINDS` (`lib.rs:25-37`), which is deliberately broader
than the router.

## Acceptance

1. The help text names no kind the server does not route.
2. The guard fails when a kind is added to the help text without a route.
3. The guard fails when a route is added without being advertised or
   declared.
4. **Counter-assertion.** The guard finds the real lists — a rename of the
   help text's heading or of the router file must break it loudly rather than
   make it vacuously green.
5. The help text names the per-artifact rescan path.

## Out of scope

- Adding a `scan` task route. A scan is per artifact by design.
- The rescan route's permission gate. Decided on #388 §5: it keeps
  repository `write`.

## What the independent review changed

`codex/gpt-6-sol` found the dep-graph argument overstated (a neutral crate is
possible, so the source scan is a choice rather than a necessity) and supplied
the two facts the guard needs to be satisfiable: the four intentionally
unadvertised routed kinds, and that `ADMIN_INVOKABLE_TASK_KINDS` is the wrong
list to compare against.
