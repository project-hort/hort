# 346 — The discovery surface admits the identity it was specified for

**Issue:** #358 · **Branch:** `agent/358-discovery-token-kind`
**Governing decisions:** `docs/ci/hort-quarantine-integration.md` (the
specification the current gate diverges from) · issue #80 (the identical
correction, already made on the sibling route) · ADR 0013 (token kinds) ·
ADR 0038 (service accounts are strictly non-admin — untouched; this is
`Read`) · ADR 0055 (resolvability vs diagnosability).

## What is true today

`GET /api/v1/repositories/:repo_key/discovery/versions/:package_name` is the
one read surface that *names* a withheld version instead of omitting it. It
returns a per-version `DiscoveryVersionStatus`
(`crates/hort-domain/src/entities/discovery.rs:87`) with variants `Released`,
`Quarantined { quarantine_until }`, `QuarantinedAwaitingRelease`, `Rejected`,
`ScanIndeterminate`, `Unknown`.

It admits a `CliSession` and nothing else:

```rust
// crates/hort-app/src/use_cases/discovery_use_case.rs:188
if caller.token_kind != Some(TokenKind::CliSession) {
```

PATs and service-account tokens get `403` from that gate, before the RBAC gate
behind it is consulted.

## Why that is a divergence and not a hardening

`docs/ci/hort-quarantine-integration.md` specifies this surface's reader as a
**service account**. The triage job it describes works *"keyed on hort's
authoritative discovery status (`DiscoveryVersionStatus.kind`)"*, and the
grant the same document prescribes is:

```yaml
kind: PermissionGrant
spec:
  subject: { kind: serviceAccount, name: github-ci }
  permission: read         # pull + discovery; no curate/admin
```

The same document describes the `403` an under-granted caller gets as the
consequence of *missing grants* — *"the exchange mints a bearer that
authorizes nothing — discovery + prefetch fail closed with a `403`"* — not of
the token's kind. With the present gate that job cannot run its own
specification: it is refused **with** correct grants.

The sibling route carried the identical gate and lost it in #80. Its module
doc records what that was:

> the prior blanket CliSession-only gate on this endpoint was implementation
> drift from that spec (issue #80)

#80 corrected the `POST` and left the `GET`.

## What to build

Mirror the sibling's shape — `crates/hort-app/src/use_cases/self_service_prefetch_use_case.rs:270`
is the reference implementation, including how it logs and which metric
result it ticks:

- the token-kind gate admits `CliSession` **or** `ServiceAccount`;
- everything behind it is unchanged: the `Permission::Read` check on the
  resolved repository, the anti-enumeration `NotFound` for an unknown
  repository with no metric tick, the OCI short-circuit, and the metric
  result vocabulary;
- **PATs stay refused**, mirroring the sibling. Do not widen them here: that
  is a question about ADR 0013's token-kind hierarchy and it would have to be
  answered for both routes at once.

The gate stays **inside the use case** — the handler is a thin wrapper and the
architect doc's "emission by layer" rule puts the metric tick at `hort-app`.

## Acceptance

1. A `ServiceAccount` bearer with `Permission::Read` on the target repository
   gets the listing, with every status variant it would have got as a
   `CliSession` — `Rejected` and `QuarantinedAwaitingRelease` included.
2. A `ServiceAccount` bearer **without** the Read grant gets `403` from the
   **RBAC** gate, not the token-kind gate. The two denials are distinguishable
   at the metric: `permission_denied`, not `token_kind_denied`.
3. A `CliSession` behaves exactly as before.
4. A PAT still gets `403` from the token-kind gate.
5. An anonymous caller still gets `401`.
6. An unknown repository is still `NotFound` with no metric tick, for every
   admitted token kind.
7. `hort-app` requires 100% coverage: every arm of the widened gate, including
   the `None` token-kind case, which stays refused.

## Out of scope

- The prefetch route — already correct since #80.
- PATs, on either route.
- Any change to what the listing contains. This unit changes who may ask, not
  what the answer is.
