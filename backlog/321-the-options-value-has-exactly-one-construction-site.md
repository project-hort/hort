# 321 — The `Options` value has exactly one construction site, and a guard says so

**Issue:** #347 · **Branch:** `agent/347-yaml-parser-ohne-verlassenes-transliterat`
**Governing decisions:** ADR 0008 (layering — the parse decision belongs to
`hort-config`), and the structural-guard family CLAUDE.md lists.

## Why this exists

The swap put five non-default settings into one `Options` value
(`crates/hort-config/src/yaml.rs::gitops_options`). One of them —
`with_snippet: false` plus `crop_radius: 0` — is a **security control**: at the
parser's stock options a syntax error echoes the offending line plus context
into the rendered error, and that error reaches the boot log and the apply-time
linter. A measured case reproduced `password: pinned-plaintext-value` verbatim.

**Nothing stops a second `Options` literal appearing.** A new parse call beside
a new `serde_saphyr::options! { … }` would compile, pass clippy and pass the
suite, and simply not carry any of the five settings — including the one that
keeps passwords out of the log. The module doc states the single-definition
invariant in prose, and prose is a compensating control, not a close.

This repository has five guards in exactly this family, and the closest
analogue is instructive: `https_rule_is_single_sourced` exists because one rule
had been re-typed per consumer five times and the **sixth** consumer carried no
copy at all. The same shape is available here, before it has a chance to
happen.

## What to build

A DB-free source-scan guard under `crates/hort-config/tests/`, in the siblings'
family — sub-second, **no allow-list**, running by virtue of being a `tests/`
target.

**The assertion:** across `crates/*/src`, a `serde_saphyr::Options` value is
constructed in exactly one place, and that place is `gitops_options`.

Derive the predicate from the source rather than from a path list, so it
survives the function or the file moving. Read the siblings first and follow
their shape — `https_rule_is_single_sourced` for a scoped single-source rule,
`cas_reads_are_verified` for the function-scope decision and its stated reason,
`dedup_success_is_funnelled` for the self-tested scanner. Say in the module doc
which scoping you chose and why.

**The counter-assertion**, as every sibling carries: prove the corpus is real.
`gitops_options` still exists, still sets the five settings by name (so a
hollowed-out definition is not vacuously green), and the scan still finds that
one construction. A rename must not be able to make the guard pass by finding
nothing.

**Non-vacuity, demonstrated not claimed:** plant a second `Options`
construction in a scratch file inside the scanned scope, show the guard red,
quote the output, remove it.

## Explicitly out of scope

- Any change to `gitops_options`'s settings or to production parse paths.
- A guard over the *values* of the five settings — that is what the behavioural
  tests do (the snippet test already fails if `with_snippet` is removed). This
  guard is about there being **one** place, not about what it says.
- Test code: a `#[cfg(test)]` construction is a test's own business and must not
  be a hit. Exclude it by how it is compiled, not by an entry.

## Acceptance

- Green on the current tree, finding exactly one construction site.
- The counter-assertion pins `gitops_options` by name and its five settings.
- The non-vacuity demonstration is in the report, verbatim.
- No allow-list and no gate-list entry (it runs as a `tests/` target).
- **No tracker references in code comments.**
- Gate: the **unit gate**, one-shot capture,
  `bash handover/gate-unit.sh -p hort-config`. Judge by the output, not the rc.
