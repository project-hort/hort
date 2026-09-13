# 185 — the catalog says "held", not "absent"

**Issue:** #251 · **Branch:** `agent/251-packument-held-block` · single item.

## Problem

Two surfaces of the same registry contradict each other.

The tarball route already tells the truth: `crates/hort-http-npm/src/lib.rs`
answers a held version with `503` **and** a `Retry-After` computed from the
artifact's deadline.

The catalog does not. `crates/hort-http-npm/src/serve.rs`'s filter pipeline
drops `Quarantined` entries from `filtered`, and the next step intersects
`dist-tags` with that same set. A client asking "what versions exist?" is told
the version does not exist; a client asking for that exact version is told it
is held. In production this cost two days of misdiagnosis: a pinned
`package-lock.json` install failed, and every human who checked the packument
read "this version does not exist on hort".

The filter's rationale is sound and stays:

> the served index lists only versions Hort holds in a servable status, so a
> range / bare install / `latest` resolution can never resolve to a version
> that would `503`

That property is about **resolution**. Nothing in it requires the catalog to be
*silent about why* a version is missing. The two are separable and are today
conflated.

## Correction

Emit held versions as metadata that is **not** part of the resolution surface:

```json
{
  "name": "@babel/helper-string-parser",
  "versions": { … servable versions, unchanged … },
  "dist-tags": { … unchanged … },
  "hort": {
    "held": [
      { "version": "7.29.7", "status": "quarantined",
        "available_after": "2026-08-26T08:18:00Z" }
    ]
  }
}
```

- `versions{}` and `dist-tags` are **byte-identical** to today. No resolver can
  reach a held version.
- The block is **omitted entirely** when nothing is held.
- `status` distinguishes the reasons a version is withheld at least as far as
  the existing filter does. A version withheld because it is *rejected* must not
  be presented as if it were waiting — naming it held-until-T is a lie in the
  other direction.
- `available_after` comes from the same deadline the tarball `503`'s
  `Retry-After` is computed from, so the two surfaces cannot drift. When the
  deadline is not available, omit the field — an absent field is honest, a
  guessed timestamp is not.

## Client tolerance — settled

The npm registry API documentation is silent on unknown top-level fields: it
explicitly permits extra *version-level* fields and says nothing either way
about the top level.

The reference registry answers it in practice. `GET
https://registry.npmjs.org/@babel/helper-string-parser` returns 15 top-level
keys, including `_id`, `_rev`, `users` and `readmeFilename` — CouchDB and
registry artifacts, not a designed schema. Every npm client consumes that
daily. A top level carrying incidental storage internals is not validated, so a
namespaced `hort` key is consistent with what the canonical registry already
does.

Residual risk, stated rather than hidden: this shows clients tolerate those
specific long-standing keys, not strictly that none allowlists them by name.
Unlikely, since `_rev` and `users` are leakage rather than design — but confirm
with one real `npm ci` against a repository serving the block before calling the
change done.

## Rejected alternative

Listing held versions inside `versions{}` under `include_pending`. It trades a
correctness property for a diagnostic one: a range or `latest` resolution could
then land on a version that `503`s, hitting every consumer of the repository
rather than only the pinned ones. As a per-repository knob it also falls under
the cross-opt-in rule and would need a full interaction matrix before
implementation. The additive block costs none of that.

## Constraint discovered while specifying

`VersionEntry` (`crates/hort-app/src/use_cases/index_serve.rs`) carries
`version` and `status: Option<QuarantineStatus>` — enough to name a held
version — but **not** the quarantine deadline. `available_after` therefore needs
the deadline plumbed to the builder.

Priority between the two halves: **naming the held version is the fix**;
`available_after` is the improvement. If carrying the deadline turns out to
require reshaping the shared cross-format index pipeline rather than adding an
optional field, emit the block without `available_after` and say so. Do not
redesign the pipeline for the optional half.

## Acceptance

- `versions{}` and `dist-tags` for a package with held versions are identical to
  the current output — asserted by a test, not by inspection.
- The packument names the held version, and when the deadline is available, when
  it becomes available.
- A rejected version is not presented as pending.
- No `hort` key when nothing is held.
- The npm proxy docs distinguish held from missing: a pinned install of a version
  inside its window fails hard with `503` and that is intended; how to tell it
  apart from a version upstream genuinely lacks; that it is temporary.
