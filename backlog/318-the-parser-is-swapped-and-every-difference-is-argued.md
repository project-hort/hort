# 318 — The parser is swapped, and every difference is argued rather than absorbed

**Issue:** #347 · **Branch:** `agent/347-yaml-parser-ohne-verlassenes-transliterat`
**Depends on:** 316 (harness green on both) and 317 (the six answers pinned).

## What to do

Replace `serde_yaml_ng` with **`serde_saphyr`** behind `hort-config`'s existing
call sites — 13 `from_slice` sites plus the `to_string` sites — leaving the
envelope types unchanged.

**Version `1.3.0`, not the `0.0.29` already in the graph** — see unit 317's
correction for why, and expect the API to differ from what unit 316 first wired.

**Default features only.** `serde_saphyr`'s sole required dependency is
`serde_core`; `serialize` + `deserialize` add `granit-parser`, `num-traits`,
`annotate-snippets`, `smallvec`, `encoding_rs_io`, all pure Rust. Do **not**
enable `figment`, `figment2`, `validator`, `garde` or `miette`: hort validates
its envelopes itself and a second validation framework in the control path is
surface, not help. If a feature looks necessary, that is a finding for the
report, not a flag to flip.

**`serde_norway` is not an option, and the reason is the whole point of this
ticket:** it carries the same C transliteration renamed
(`unsafe-libyaml-norway`), so it would turn both gates green while leaving the
abandoned component in the control path. If the swap to `serde_saphyr` runs
into something that looks fatal, stop and report it — do not reach for the
rename.

## The flags are decided (architect, 2026-10-12, on unit 317's measurements)

Unit 317 measured the divergences on `1.3.0` and found that most have a
one-flag close. **The swap preserves today's semantics; it does not take the
opportunity to change them.** Removing an abandoned component is the ticket;
re-deciding what an operator's file means is not, and nobody approved it.

**One `Options` value in `hort-config`, used by every parse entry point** — not
a literal per call site. The gitops parse has one meaning and it is defined
once, for the same reason the provenance leg lives in one place.

| flag | setting | why |
|---|---|---|
| `strict_booleans` | **`true`** | Today `requireApproval: no` is an error; under the default it resolves to `false`. That field decides whether a release needs a human, and the same resolution turns a plain `NO` into `false` in any untyped position. Preserve the rejection. |
| `merge_keys` | **`AsOrdinary`** | Reproduces today's behaviour exactly — `<<` stays an ordinary key, so a strict spec rejects it and `PrefetchPolicy` ignores it as it does now. This also removes the only *silent value* divergence found, without touching a domain type. |
| `with_snippet` | **`false`** (and `crop_radius: 0` if that is the operative knob) | **Security, not taste.** The default echoes the offending line plus context into the rendered error, which lands in the boot log and the apply-time linter output. Measured: a syntax error two lines below `password: pinned-plaintext-value` reproduces that line. The repository entry point's forbidden-field pre-scan cannot help — it is itself a parse, so a syntax error defeats it and the parse error is what surfaces. Rich diagnostics belong on a CLI, not in a service log. |
| alias/anchor ratio | **keep the default** | The only row where the replacement is *stricter* (one anchor backing ≥ 100 aliases is rejected; today there is no limit). No gitops envelope uses an anchor at all, so no tree is affected, and loosening a bound to accommodate a hypothetical file is the wrong direction. |

**Two loosenings cannot be closed by configuration, and are accepted
deliberately:**

1. **`1_000` into an `i64`** — an error today, `1000` after. The operator meant
   1000 and the field is typed; the risk is low and there is no flag.
2. **Untyped `serde_json::Value` scalars** — `yes` → `Bool(true)`, `1_000` →
   `Number(1000)`, `0755` → `Number(755.0)` (a float). Reached only by
   `ScanPolicySpec::license_policy`, whose blast radius is bounded **today** by
   `validate_scan_policy_license_policy_not_implemented` rejecting anything
   richer than `null` / `{}` at apply. It becomes live the day that rejection
   is deleted.

Both go in `CHANGELOG.md` under `### Changed` in this unit, because they are
operator-visible. So does the new alias/anchor bound.

## One thing the swap fixes, and it must be proved here

A duplicate key in a **map-typed** spec field (`FederatedIdentitySpec::claims`)
silently last-wins today — serde's duplicate-field rejection does not reach
inside a map, so the YAML layer decides. That claim set is the exact-match
condition under which a JWT may assume a service account (ADR 0018). The
replacement **rejects** it. Pin that with a test here: after the swap, a
`claims` map with a repeated key is an error. It is the clearest security
argument for the migration and it must not land unmeasured.

## The discipline for differences

Unit 316's harness and unit 317's six tests are the contract. Every failure
they produce is one of exactly two things, and the report must say which:

- **A difference we accept** — then the test is updated, the new behaviour is
  stated in the test name or doc, and the report argues why the new answer is
  as strict or stricter. "Stricter" is acceptable and often desirable; a
  **looser** answer on duplicate keys or unknown fields is a blocking failure
  of this unit, not a trade-off.
- **A difference we do not accept** — then it is a reason to stop, and the
  fallback named in the issue (a thin layer over `saphyr` / `yaml-rust2`) comes
  back on the table. Say so plainly; do not engineer around it silently.

Keep the harness **green at the end** of this unit. A harness turned off "for
now" is the migration losing its only proof.

## The lockfile is the resolver's, not ours

Unit 317 hand-minimised the `Cargo.lock` delta and verified it with
`cargo metadata --locked`. **Replace it with the resolver's own output.** The
rule against hand-editing generated files is not about whether the result
works today — `--locked` proves only that — but about whether the file is
reproducible by the tool on another machine and after the next `cargo update`.
A release-bound lockfile has to be the resolver's. Take the larger diff.

## Acceptance

- Every production parse and serialise site in `hort-config` goes through the
  new parser; `grep -rn serde_yaml_ng crates/*/src` shows only what unit 319
  will remove (the dev-dependency wiring of the harness).
- Unit 316's harness green; unit 317's six tests green, with every changed
  answer argued in the report.
- `cargo test --workspace` would be the architect's gate; **this** unit runs
  the unit gate on the touched crates, one-shot capture, judged by output.
- `deny_unknown_fields` still rejects a typo'd field in all four shapes from
  unit 317 — demonstrate it, do not assert it.
- No change to the envelope types, no new operator-visible knob, no new YAML
  feature supported that was not supported before.
