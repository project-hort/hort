# 183 — aim the authority preflight instead of switching it off

**Issue:** #238 · **Branch:** `agent/238-aimable-authority-preflight` · single item.

## Problem

`svc-token-bootstrap` emits `--require-authority` for every
`scheduledTasks.svcTokens` entry. That preflight checks authority at
**global** scope unless `--repository` is also passed — and `--repository`
additionally scopes the minted token's **cap**.

An identity needing an **unscoped cap with repo-scoped grants** therefore has
no expressible configuration:

- Omit `repository` → the preflight checks global scope, finds no grant,
  fails the hook.
- Set `repository` → the preflight passes, but the cap is scoped too. A
  repo-scoped cap and a repo-scoped grant produce the same `404`, so a
  denial becomes ambiguous about which mechanism produced it — destroying
  the property such an identity exists to demonstrate.

## The defect is the conflation

One flag drives two independent decisions: how wide the minted cap is, and
at what scope the grant preflight looks.

The internals already keep them apart — `check_require_authority` takes its
scope as a separate parameter, and the call site passes a local
`repository_scope`. Only the CLI surface welds them together.

## What to build

Give `--require-authority` an optional value naming the scope to check:

```
--require-authority              # unchanged: check at global scope
--require-authority=<repo-key>   # check the declared permissions at that scope
```

`--repository` keeps governing the cap alone. The bare form must stay
byte-compatible — every existing invocation behaves identically.

Resolve an unknown repository key the same way `--repository` already does:
**before any DB write**, with the same shape of error.

The chart then exposes the scope per entry as
`scheduledTasks.svcTokens[].authorityRepository`, leaving the preflight
**always on**. An entry omitting it renders byte-identically to today.

## The alternative that is rejected, and must stay rejected

A per-entry `requireAuthority: false` switches the guard off rather than
aiming it. That guard exists to catch exactly the failure that would then
return: an identity whose grant is missing or misspelled mints a token that
succeeds at install time and `403`s on every request afterwards, with no
install-time signal — a genuinely nasty thing to debug, because nothing
points at it.

Do not add a boolean that disables the preflight, and do not let
`authorityRepository` become one by accepting an empty string as "skip".

## Read first

- `crates/hort-server/src/cli/admin.rs` — the `require_authority` field, the
  `repository` arg doc (which states the coupling), `check_require_authority`
  and its `scope` parameter, and the call site's `repository_scope`.
- `deploy/helm/hort-server/templates/svc-token-bootstrap-job.yaml` — the
  `range` over `svcTokens` and the unconditional flag.
- `deploy/helm/hort-server/values.yaml` + `values.schema.json` — the entry
  shape.

## Acceptance

- `--require-authority=<repo-key>` checks the declared permissions at that
  repository's scope while the cap stays global unless `--repository` says
  otherwise.
- Bare `--require-authority` is unchanged; existing invocations behave
  identically.
- An unknown repository key fails before any DB write.
- The chart exposes the scope per entry; an entry omitting it renders
  byte-identically to today.
- A chart fixture and expectation row cover an entry that sets it.
- Unit tests cover three cases: global preflight passes on a global grant;
  scoped preflight passes on a matching scoped grant; scoped preflight
  **fails** when only a differently-scoped grant exists.
- The values comment says what the field is for, and why the preflight is
  not disableable.
