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
(`manifests_write.rs`, which notes the also-absent count while returning the
terminal answer). So for a reference that is *absent under the asked name* and
*terminal under a sibling name*, the content-scoped half decides. The
resolution below records why that is correct rather than a masking.

One clarification, because an earlier reading of this file had it backwards:
`blob_constituent_verdicts`'s doc comment declines to ask this question of an
**index**'s children — *"asking about whatever row happens to share their
bytes"* — and that is not a statement against content-scoped asking. An index's
children are *documents*, whose deliverability is their own closure's, so the
index resolves them by path and then walks that closure, which asks the content
question of the **blobs**, where it belongs. Both paths ask it at the same
level; only the level differs from the reference being resolved.

## Resolved 2026-11-26 — no change. The measured behaviour is the design.

**The question this unit was written to answer** — *is a scan verdict about the
bytes or about the artifact?* — is answered: **about the bytes.** One verdict
per content, narrowed to the most precise and strictest available, folded at
read time. A rendered verdict beats a non-verdict; among rendered verdicts the
strictest wins. That is the same fold hort already applies across scan
backends, which union their findings while keeping an abstention distinct from
"found nothing".

Under that answer each of this item's complaints dissolves, and all three
behaviours it proposed to change turn out to be documented decisions that are
right:

**1. The terminal-over-absent precedence is deliberate, and inverting it would
regress.** `crates/hort-http-oci/src/manifests_write.rs` states it where it
happens: *"A document naming both answers the terminal one. The publisher can
fix an absent reference by pushing it and cannot fix a terminal one, so naming
the absent one first would walk them through a push into a second refusal."*
And with one verdict per content, `MANIFEST_BLOB_UNKNOWN` is not merely
unhelpful here but **false**: the repository holds those bytes and has decided
about them. A publisher sent to push them would meet the same refusal
afterwards.

**2. The `503 UNAVAILABLE` shape is correct, and the message is an
information-disclosure control.** `crates/hort-http-oci/src/error.rs` documents
`ScanIndeterminate` as carrying **no** `retry_after_seconds` and emitting no
`Retry-After`, because the hold has no self-resolving deadline — its exits are
a curator's waive or a rescan that reaches a verdict, *"and never the passage of
time"*. So it is not "terminal" in the sense of unrecoverable; it is a hold
whose exit is not the clock, which is exactly what `503` without `Retry-After`
says. Code, status **and message** are deliberately identical to `Quarantined`
so that *"which hold an artifact is in stays opaque to the client"*. A refusal
reworded to name the content's state would undo that, in the same family as the
discovery-existence-oracle finding.

**3. "A sibling name can block a push"** describes the invariant working, not a
defect. No sibling decides anything: the content is not deliverable in this
repository, equally for every name that binds it.

So this item closes as **works as designed**, with the reading recorded rather
than the code changed.

## What the reading does leave open — measured, and not this item

The fold exists in exactly one place. `ConstituentStatusReader`'s two methods
fold over content for manifest admission and manifest delivery. The **serving**
decision does not: `crates/hort-http-oci/src/blobs.rs` says so in its own module
header — *"The handler inspects `Artifact.quarantine_status` DIRECTLY"* — and
the download gate is `Artifact::is_downloadable()` on that one row
(`crates/hort-app/src/use_cases/artifact_use_case.rs`), as is
`is_promotable()` beside it.

Because OCI blob rows are name-scoped (units 462 and 465), identical content can
therefore be `Released` and served under one name while `Rejected` under
another — reachable exactly where the two rows were last scanned at different
times against an advisory database that moved between them. An advisory lookup
is keyed by `(ecosystem, name, version)` and never by content hash, so that
divergence is expected rather than exotic.

Closing the asymmetry is the work the reading creates, and it is a narrowing on
the hottest read path in the system. It is deliberately **not** folded into this
item: it needs its own specification and its own decision about scheduling.

## Governing decisions

ADR 0007 (fail-closed deliverability), ADR 0039 and ADR 0055 (hold reads),
ADR 0062, and
`docs/architecture/reference/oci-namespace-and-identity.md` (identity is
`(repository, name, digest)`; reach is the whole OCI surface).
