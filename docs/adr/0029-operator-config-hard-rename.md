# 0029 — Operator-config renames are hard renames

- **Status:** Accepted
- **Enforced by:** `Config::from_env` reading only canonical names (a retired
  env-var name has no parse site) **and** the strict
  `deploy/helm/hort-server/values.schema.json` (`additionalProperties: false` on
  the top-level object and every chart-owned nested block, so a retired or
  mistyped key fails `helm install`/`helm template`; regression-pinned by the
  deliberate-retired-key fixture `test-values-strict-schema-typo.yaml` in
  `scripts/test-helm-templates.sh`). The "no live surface still names the old
  key" acceptance check is a rename-PR review step (grep the old name → the
  upgrade note is its only allowed home).
- **Supersedes:** —

## Context

The operator config surface (the `HORT_*` environment variables and the
`hort-server` Helm chart `values` keys) was normalized to a single set of naming
conventions before the v1.0 surface freeze: subsystem-first names, booleans by
intent (`*_ENABLED` for on/off, `<SUB>_ALLOW_*` / `<SUB>_REQUIRE_*` for policy),
`_SECS` durations, and human-readable size strings (`"64Mi"` via
`parse_byte_size`, names ending `_MAX_SIZE`/`_SIZE`) for byte caps. The
authoritative OLD→NEW mapping lives in the upgrade note.

Renaming an operator knob has a failure mode unlike renaming code: **a retired
env-var name is silently ignored at boot.** `Config::from_env` reads only the
new name, so an operator who sets the old one gets the default — for an auth or
quarantine knob that is a silent security misconfiguration, and test-coverage
percentages cannot catch a *name* regression (the code that reads the new name
is fully covered whether or not a stale parse site for the old name creeps back
in). Helm had the mirror-image problem: before the schema was made strict, an
unknown key was silently accepted and ignored, so a retired key (or a typo)
looked configured while doing nothing.

A choice was forced between carrying compatibility aliases (dual-read of old
and new names) into v1.0 or breaking the alpha deployments once, with a
mapping note, inside the pre-v1.0 window where no stable installations exist
yet.

## Decision

**Operator-surface renames are hard renames.** No aliases, no dual-reading of
old and new names, no deprecation shims.

1. **Env vars:** the binary reads only the canonical name. A retired name has
   no parse site. Because the runtime therefore *cannot* warn about a retired
   name (it is simply ignored), every rename PR carries the "grep for the old
   name → 0 hits on live surfaces" acceptance check at review time; the
   upgrade note is the only allowed home for the old names. Reintroducing a
   retired name on a live surface is a blocking review finding.
2. **Helm keys:** a retired key fails validation at `helm install` /
   `helm template`, because `values.schema.json` sets
   `additionalProperties: false` on the top-level object and every nested
   block whose shape the chart owns (free-form Kubernetes passthrough blocks
   such as `resources`, `probes.*`, `affinity`, and the verbatim array entries
   intentionally stay permissive). The fixture
   `deploy/helm/hort-server/test-values-strict-schema-typo.yaml` carries
   retired keys on purpose and `scripts/test-helm-templates.sh` asserts the
   render **fails** on them.
3. **The single sanctioned fallback is the database DSN.** `HORT_DATABASE_URL`
   is the canonical operator variable; bare `DATABASE_URL` is honored as a
   compat fallback —
   `require("HORT_DATABASE_URL").or_else(|_| require("DATABASE_URL"))` in
   `crates/hort-server/src/config.rs:1757` (`MinimalConfig::from_env`, shared
   by the serve path and every DB-only subcommand) and identically in
   `crates/hort-worker/src/config.rs:318`. Bare `DATABASE_URL` stays
   load-bearing because sqlx-cli, the Tier-2 `maybe_pool()` test helpers, and
   12-factor tooling read it; that external-tooling contract is the reason
   this one fallback exists and why no other knob gets one.
4. **Old names live only in sanctioned homes:** breadcrumb prose on live doc
   surfaces ("renamed from `X`", `X → Y` — the guard's `is_breadcrumb_line`
   markers), the deliberate-retired-key Helm fixtures, and the guard test's own
   lists. Anywhere else, a retired name is a defect the guard turns red.

## Consequences

- Operators get exactly one behavior per name: a knob either works under its
  canonical name or fails loudly (Helm) / is provably absent from the tree
  (env, via the guard). There is no "old name still half-works" state.
- The cost is a breaking upgrade step: every deployment must apply the OLD→NEW
  mapping from the upgrade note when crossing the rename. This was paid once,
  pre-v1.0, instead of carrying alias code and a deprecation cycle into the
  stable series.
- Every future rename carries a three-part obligation: rename the read site,
  enumerate the new key in the strict schema, and append the retired names to
  the guard's lists. Skipping the third silently re-opens the
  ignored-at-boot hole the guard exists to close.
- Dual-read ambiguity (old and new names set to conflicting values, with
  precedence rules to document and test) never exists — except for the one
  documented DSN fallback, where precedence is fixed and tested: canonical
  first, bare fallback second.

## Alternatives considered

- **Compatibility aliases / dual-read (old name honored alongside new).**
  Rejected: it carries permanent alias code and a both-names-set precedence
  contract into v1.0 for the benefit of pre-stable deployments only, and it
  perpetuates the silent-divergence risk (the old name keeps "working" so
  documentation and operator habits never converge on the canonical name).
- **A deprecation cycle (warn on old name, remove later).** Rejected for the
  same reason the schema-edit policy in [0022](0022-pre-1.0-edit-existing-migrations.md)
  edits migrations in place pre-1.0: there were no stable installations to
  protect, so a multi-release warning window buys nothing and delays the
  freeze of the canonical surface. A warning also requires keeping a parse
  site for the old name — exactly the code the hard rename deletes.
- **One-shot grep at rename time, no committed guard.** Rejected: a grep
  proves the tree is clean at the moment of the rename and never again. A
  later edit reintroducing a retired parse site or values key would sail
  through CI — coverage cannot catch a name regression. The committed
  source-scan test makes the zero-straggler property permanent.
- **Lenient Helm schema with documentation only.** Rejected: a schema that
  exists but does not set `additionalProperties: false` is the worst of both
  worlds — it looks validated while silently accepting retired and mistyped
  keys.

## References

- `deploy/helm/hort-server/values.schema.json` — strict schema
  (`additionalProperties: false` top-level and on every chart-owned block).
- `deploy/helm/hort-server/test-values-strict-schema-typo.yaml` +
  `scripts/test-helm-templates.sh` — render-failure regression proving the
  schema rejects retired keys.
- `crates/hort-server/src/config.rs:1757`, `crates/hort-worker/src/config.rs:318`
  — the sanctioned `HORT_DATABASE_URL` → `DATABASE_URL` fallback.
- [0015](0015-apply-time-linter-inert-fields-and-naming.md) — the related
  naming decision: misleading config names are fixed by in-place rename
  pre-v1.0, and a config surface must never accept input it does not enforce —
  the same accepted-but-inert hazard this ADR closes for retired names.
