# 171 — reject at apply the prefetch triggers a format cannot honour

**Issue:** #233 · **Branch:** `agent/233-maven-version-discovery` · Item 1 of 3.
Independent of items 172 and 173 — land it first.

## Problem

`prefetchPolicy.triggers: [transitive_deps]` on a Maven proxy is **accepted at
gitops apply and inert at runtime**. `validate_prefetch_policy_bounds` checks
the numeric caps; nothing cross-checks a repository's format against the
triggers it declares. The operator gets configuration that looks like it does
something.

This is the anti-pattern ADR 0015 makes a hard block: a policy field must be
either enforced by the consuming use case or rejected at apply, because
operators make decisions on the assumption that a field they set is
load-bearing. The canonical exemplar is `max_age_days`, whose structural close
is an apply-time rejection pointing at the future work.

Not Maven-specific. Every format whose handler declares no `VersionDiscovery`
is in the same position — `maven`, `oci`, `helm`.

## Governing decisions

- **ADR 0015** — the rule being applied, and the shape of its structural close:
  fail-closed apply-time rejection, never a runtime fallback to a degraded
  behaviour.
- **ADR 0005** — the capability-group model that makes `VersionDiscovery` the
  right thing to key on.

## Which triggers, exactly — get this right

Only two of the three require `VersionDiscovery`. Verified in the consumers:

| trigger | requires `VersionDiscovery` | evidence |
|---|---|---|
| `transitive_deps` | **yes** | `prefetch_dependencies` completes as a structural no-op without it |
| `scheduled` | **yes** | `prefetch_tick` skips with a log line when `handler.version_discovery()` is `None`; the newest-N walk needs a version listing |
| `on_dist_tag_move` | **no** | OCI fires it today (`hort-http-oci::prefetch`) and OCI has no `VersionDiscovery` |

**Rejecting `on_dist_tag_move` would break a working OCI feature.** Scope the
rejection to the first two.

## What to build

An apply-time validation that rejects a repository declaring `transitive_deps`
or `scheduled` when its format's handler does not declare `VersionDiscovery`.

- **Key on the capability, never on a format list.** A hard-coded
  `["maven","oci","helm"]` would have to be edited when item 172 lands and
  would silently go stale for any format added later. Keying on the handler's
  own declaration means the rejection lifts itself for Maven the moment item 172
  ships, with no second edit.
- **The message is the deliverable.** Name the repository, the format, the
  offending trigger, and what the operator should do instead — for Maven today
  that is the scheduled warm-up they are already running. A rejection an
  operator cannot act on is worse than the silent no-op it replaces.
- Nothing else about `prefetchPolicy` changes: the caps, the other fields and
  `on_dist_tag_move` behave exactly as before.

## Compatibility check, already done

No envelope in this repository sets `prefetchPolicy` on a format without
`VersionDiscovery`. The only one setting it at all is `crates-proxy` (cargo,
which participates), so this rejects nothing that exists here and needs no
accompanying envelope fix. **Re-verify against the operator's own gitops tree
before this merges** — a real `prefetchPolicy` on a Maven proxy out there would
need a migration note rather than a bare rejection.

## Explicitly not in this item

- Any Maven parsing. That is item 172.
- Any change to `on_dist_tag_move`, the caps, or the runtime behaviour of a
  policy that passes validation.
- Any format list anywhere.

## Acceptance

- A repository with a non-`VersionDiscovery` format declaring `transitive_deps`
  or `scheduled` is rejected at apply, naming the repository, the format and the
  trigger.
- The same repository declaring only `on_dist_tag_move` still applies.
- A `VersionDiscovery` format declaring any trigger still applies.
- The check reads the handler's declaration; a grep for a format name in the new
  validation code finds nothing.
- Full local gate green per the pre-push checklist, `cargo test --workspace`.
