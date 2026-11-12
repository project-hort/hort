# 423 — A folded header is still a declaration

**Issue:** #424 (follow-up to the merged unit; the issue stays open until the
promotion) · **Branch:** `agent/424-a-folded-header-is-still-a-declaration` ·
the only item. **No ADR change.** No migration.

**Governing decisions:** ADR 0007 (fail-closed release authority — why reading
a withheld declaration as an empty one is the dangerous direction), ADR 0006
(the artifact's own bytes are the authority, so they must be read correctly).

## The property

**Core Metadata is an RFC 5322 header block, so a value may be folded onto a
continuation line — and both of `pypi.rs`'s header readers classify per
*physical* line and silently drop the continuation.**

Measured, not inferred. Python's `email.parser` with `compat32` — the parser
the [Core Metadata specification](https://packaging.python.org/en/latest/specifications/core-metadata/)
names — unfolds it:

```
$ python3 -c "from email.parser import Parser; from email.policy import compat32; \
    print(Parser(policy=compat32).parsestr('Metadata-Version: 2.2\nName: demo\nDynamic:\n Requires-Dist\n\n').get_all('Dynamic'))"
['Requires-Dist']
```

hort reads the same document as declaring nothing dynamic.

## The two affected readers — this is the whole census

1. **`classify_requires_dist`'s loop (`pypi.rs:1532-1556`)** — the PEP 643 /
   SBOM classification path. `rfc5322_header` returns `None` for a
   continuation line (correctly: a continuation is not a new header, and the
   test at `:5104` pins that), and the loop then `continue`s, so the
   continuation is **dropped** rather than appended to the header in progress.
2. **`parse_wheel_metadata_into_specs` (`pypi.rs:2110-2118`)** — the
   dependency-spec path, same shape: `line.strip_prefix("Requires-Dist:")` per
   physical line, continuation dropped.

**The bug is in the loops, not in `rfc5322_header`.** Its contract — "is this
physical line a new header?" — is right and its test stays. What is missing is
the unfolding step above it.

## Why it is a fail-open and not only a parsing nit

**Half one, the fail-open.** A folded `Dynamic:` leaves
`requires_dist_is_dynamic` false, so the gating `PypiDeclaration::NotCanonical`
arm never fires. Metadata 2.2 with no *visible* `Requires-Dist` is then
classified as a **static empty declaration**, which becomes
`SbomResolution::NoLockfile` and a subject-only BOM that `try_extract_sbom`
treats as usable. Under a policy whose only backend adjudicates the component
list, OSV answers `Analysed([])` over that BOM and the run records a clean
`ScanCompleted` — release authority over a distribution that explicitly
withheld its dependency declaration. That is the same shape as the fail-open
the merged unit closed; this is the sibling that reaches it through the
*reader* rather than the resolution.

**Half two, silent loss on a conforming document.** A folded `Requires-Dist`
value disappears from the component list in **both** readers. Nothing is
withheld and nothing errors — the dependency simply is not there, so advisory
matching never asks about it.

## What to build

**Unfold the header block before classifying it, at both sites.** RFC 5322
unfolding: a line beginning with SP or HTAB continues the preceding header's
value. Implement it once and use it in both loops rather than twice.

- **The blank-line terminator still ends the block.** Both loops break at the
  first empty line because what follows is the long description, which
  commonly contains indented prose. Unfolding must not reach past that break —
  an indented line in the description must never become a continuation.
- **Fail closed on an uninterpretable continuation of an authority-bearing
  field.** If `Dynamic` or `Requires-Dist` carries a continuation that cannot
  be read as part of its value, that is not an empty declaration; it is an
  unreadable one, and `SbomResolution::UnusableLockfile` is the arm that holds
  the artifact. Do not reach for the empty-declaration arm.
- `is_extras_gated_requirement` and the rest of the requirement handling apply
  to the **unfolded** value.

## Acceptance

1. A `Metadata-Version: 2.2` sdist whose `Dynamic:` value is folded onto a
   continuation line is classified **not canonical** and **gates** — asserted
   as a scan disposition, not only as a handler result, because the handler
   result is not what grants release authority.
2. A folded `Requires-Dist` value is read **whole** in both readers, asserted
   separately for `classify_requires_dist` and
   `parse_wheel_metadata_into_specs`, including a continuation that carries an
   extras marker so the gating applies to the unfolded text.
3. A multi-line continuation (two or more continuation lines) is read whole.
4. A description body containing indented lines after the blank line is
   unaffected — pinned by a test, because this is the regression the unfolding
   could introduce.
5. A tab-indented continuation is treated the same as a space-indented one.
6. The existing `rfc5322_header` unit tests, including
   `assert!(rfc5322_header("  continued: value").is_none())`, still pass
   unchanged — the line classifier's contract is not what changes.
7. The change adds no uncovered lines.
