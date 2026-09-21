# 163 — record eager child ingest as an ADR 0043 amendment

**Issue:** #229 · **Branch:** `agent/229-eager-child-ingest` · Item 3 of 3
(depends on items 161 and 162; one MR carries all three).

## Problem

Items 161 and 162 change *when* a proxied index's children begin their
quarantine window. That is a lifecycle-timing decision with a security-adjacent
rationale, and it must be recorded where a future reader looks for it —
otherwise the next person to touch the pull path sees eager network fan-out
with no decision behind it and treats it as incidental.

## Governing decisions

The decision belongs to **ADR 0043** (OCI image-index support), which already
governs how an index and its children relate. This is an **amendment to 0043**,
not a new ADR: inventing a new decision record for a timing detail inside an
existing decision's scope is precisely the "complexity added to avoid touching
an ADR" the architect guide rejects.

No **ADR 0016** cross-opt-in row is needed. Eager child ingest introduces no
operator opt-in (issue #229 D8), so it cannot combine with another opt-in to
collapse an invariant.

## Read first

- `docs/adr/0043-oci-image-index-support.md` — in particular D4 (releasing an
  index does not release a held child) and the layer-level-safety rationale.
- `docs/adr/0054-content-level-age-evidence-anchors-quarantine.md` — the
  amendment's load-bearing cross-reference.
- `docs/adr/0007-fail-closed-quarantine-release-predicate.md`.
- `docs/architecture/` — locate the existing how-to or reference page covering
  pull-through quarantine behaviour and add the operator-facing note there.

## What to write

An amendment section on ADR 0043 recording:

- **What changed.** On pull-through ingest of an image index, hort eagerly
  ingests the children the index declares, so index and children run their
  quarantine windows concurrently instead of back to back.
- **Why it is not a shortcut.** ADR 0054 derives the anchor from
  `first_seen_for_checksum`, so an eagerly ingested child receives exactly the
  anchor a later lazy pull would have given it. No window is shortened. A
  window that would have started tomorrow starts today.
- **What is unchanged.** ADR 0007's release predicate; D4 (a released index
  still does not release a held child); per-child and per-layer consumption
  gating; the answer a client gets when it asks for a held child.
- **Why it is unconditional.** An index's children are the declared membership
  of an artifact a client just requested, not speculation. The bound is the
  index's own `manifests[]`, hard-capped at `MAX_INDEX_CHILDREN`. No
  `PrefetchPolicy` field was added, because ADR 0015 requires an
  operator-visible field to be load-bearing on the day it ships.
- **Why attestation manifests are included**, and **how nested indexes are
  bounded**: they recurse without any operator-visible knob, but under a hard
  internal depth cap alongside the existing `MAX_INDEX_CHILDREN` breadth cap.
  Record both bounds and the reason they are constants rather than
  configuration (see item 167, which amends the issue's D10 on this point).

Plus a short operator-facing note in the appropriate `docs/architecture/` page:
after this change, the first pull of a fresh multi-arch image starts every
platform's window at once, so the practice of manually warming children in
parallel at merge time is no longer needed.

## Explicitly not in this item

- A new ADR number.
- An ADR 0016 matrix row.
- Any code change.

## Acceptance

- ADR 0043 carries a dated amendment covering all six points above, with
  cross-references to 0054, 0007 and 0015.
- The operator-facing note lands on an existing `docs/architecture/` page; no
  new page is created for it.
- No `docs/plans/` file is added (the issue description is the design record).
- Prose only — no code, no test changes.
