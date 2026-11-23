# 467 — manifest admission decides presence per name and deliverability per hash

**Issue:** #459 · **Branch:** `agent/459-oci-namespace-identity`.
**Measured in staging 2026-11-23** on `0.18.1-alpha.1`, by the UAT round for
this series — not inferred. This was the first of the two open questions 465's
census raised, and it is no longer theoretical.

## What was observed

A blob was pushed under `a/one` and `a/two` in one hosted OCI repository. Under
`a/five` the same digest answers `404 BLOB_UNKNOWN` — correctly, it was never
pushed there. A manifest naming that digest as its config and layer, pushed to
`a/five`, answered:

```
503  {"code":"UNAVAILABLE","message":"artifact scan result is indeterminate"}
```

rather than the `MANIFEST_BLOB_UNKNOWN` a name-scoped admission owes. The only
row in `scan_indeterminate` was the one under **`a/two`**; `a/one`'s row was
`quarantined` at the same instant. A control in the same round proves the
refusal path is reachable: a manifest naming a digest present **nowhere**
answered `400 MANIFEST_BLOB_UNKNOWN` with the digest in `detail.blobs`.

## The seam, in the code

Admission answers two questions about the same reference with **two different
identities**:

- **Presence** — `resolve_referenced_blobs`
  (`crates/hort-http-oci/src/manifests_write.rs:2627`) resolves
  `oci_blob_coords(name, …).path` with a legacy fallback. **Name-scoped**, as
  units 462 and 465 made it.
- **Deliverability** — `blob_constituent_verdicts` (`:2849`) collects the
  declared Config/Layer **hashes only** and calls
  `ManifestDeliverabilityUseCase::terminal_constituents(repo, &hashes)`
  (`crates/hort-app/src/use_cases/manifest_deliverability.rs:269`).
  **Repository/hash scoped, name-blind.**

And a terminal verdict **wins over an absent reference** by design
(`manifests_write.rs:1225`, which notes the also-absent count while returning
the terminal answer). So for a reference that is *absent under the asked name*
and *terminal under a sibling name*, the name-blind half decides, and the
name-scoped refusal unit 465 built is masked.

`blob_constituent_verdicts`'s own doc comment states the hazard — for the index
case it declines to ask the question precisely because it would be *"asking
about whatever row happens to share their bytes"*. The blob case does that.

## Severity: fail-closed, and misleading

It **refuses**, so nothing unsafe is admitted and there is no urgency of the
dangerous kind. Two real costs:

1. **The client is told the wrong thing.** A pusher under `a/five` is told the
   scan result of a blob that does not exist in `a/five`, about a row they may
   have no access to and certainly cannot see. `MANIFEST_BLOB_UNKNOWN` names a
   digest the client can act on — push it here. `UNAVAILABLE` names a state
   they cannot change.
2. **A sibling name can block a push.** One name's terminal row refuses every
   other name's manifest over the same bytes, permanently for a terminal state.
   Under the decided identity model those are different artifacts.

## The question this unit must answer before it changes anything

**Is a scan verdict about the bytes or about the artifact?** Both readings are
defensible and they are not the same question as presence:

- **About the bytes** — then the hash-scoped catalog is right and the *error*
  is the defect: it should say "this content is not deliverable here" with a
  code a client can act on, and presence should be reported first when the
  reference is absent in the asked name.
- **About the artifact** — then `terminal_constituents` needs the name, the
  catalog becomes `(repository, name, hash)`, and a terminal row under one name
  stops deciding for another.

The second is the larger change and the one consistent with #459's decided
model. The first is cheaper and may be sufficient. **This is a decision, not a
coding judgement** — it governs what a scan verdict is *about*, which also
reaches `provenance_cascade.rs:323,843` (the second open question from 465's
census, still ungroomed, same subject).

## Not in scope

Reordering presence before deliverability as a *presentation* fix without
answering the question above. It would make this probe produce
`MANIFEST_BLOB_UNKNOWN` and leave the sibling-blocks-sibling case intact for
every reference that *is* present under the asked name.

## Governing decisions

ADR 0007 (fail-closed deliverability), ADR 0062, and
`docs/architecture/reference/oci-namespace-and-identity.md` (identity is
`(repository, name, digest)`; reach is the whole OCI surface).
