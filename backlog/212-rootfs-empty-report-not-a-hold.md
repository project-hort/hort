# 212 — An empty Trivy report over a fully materialised root filesystem is "nothing to assess", not a hold

**Issue:** #274 · **Branch:** `agent/274-rootfs-empty-report-not-a-hold` · single item · `hort-adapters-scanner-trivy` + E2E + docs.

## Defect (staging UAT on `v0.14.0-beta.2`)

`nginx:alpine` through a Trivy-policy proxy: manifests → `not_applicable`; base layer →
`scan completed kind=oci_blob subcommand=rootfs analysed_targets=1` → released; the
CA-certificate layer (21 `.crt` files, 333 skipped links, no package database) →
`report carries no analysed target; no verdict` → `no_analyzer_matched` → `scan_indeterminate`,
never released (503, no `Retry-After`, no rescan). Nearly every multi-layer image carries such a
layer, so every such image hangs under a Trivy policy. The compose scenario used a single-layer
`alpine:3.19` and could not see it.

## Invariant

Trivy's `rootfs` target runs every OS-package, language and binary analyzer over the whole tree;
an empty report there states "no package surface in this filesystem" — the artifact has nothing
to assess (ADR 0007 clarification of 2026-09-18, decision B on #264). In `fs` mode the target is
one artifact whose analyzer either engages or does not; an empty report there still means the
expected surface was not assessed → hold. `UnusableArchive` (extraction refused) stays a hold in
both modes.

## Change

1. `hort-adapters-scanner-trivy/src/lib.rs` `scan()`: on `report.results.is_empty()`, branch on
   `mode`: `ScanMode::Rootfs` → `Ok(ScanAnalysis::NothingAnalysable(NotAnalysable::NotApplicable))`
   with an `info!` "root filesystem walked, no package surface — nothing to assess" carrying
   `kind`, `entries`, `bytes`, `skipped_links` (and the `materialised` listing at `debug!`);
   `ScanMode::Fs` → today's `warn!` + `NoAnalyzerMatched`. The `NotAnalysable::NotApplicable` doc
   gains the rootfs case.
2. Tests: `lib.rs` — empty report + `Rootfs` ⇒ `NotApplicable`; empty report + `Fs` ⇒
   `NoAnalyzerMatched`; non-empty unchanged. `tests/materialisation_evidence.rs` — a
   package-less layer fixture (`usr/share/ca-certificates/x.crt` + one symlink) under real
   `trivy rootfs` ⇒ `NotApplicable`. Orchestrator tests need no change (`NotApplicable` already
   records `not_applicable`), but add one end-to-end unit test through `run_scan` with a mock
   scanner returning the rootfs-empty outcome to pin the release.
3. E2E `quarantine/trivy-oci-not-applicable`: the source image becomes a **multi-layer** image
   with at least one package-less layer — `nginx:alpine` as observed (or a two-layer fixture
   built in the scenario from `alpine:3.19` + a layer holding one `.crt`), and step (2)/(3)
   assert every layer row records a completed scan and is released; the log assertion
   distinguishes `analysed` (base) from `not_applicable` (package-less) per layer.
4. Docs: ADR 0007 clarification paragraph — one sentence that a `rootfs` target's surface is the
   whole tree; `scanning-pipeline.md` "Nothing analysable" section; `CHANGELOG.md`
   `[Unreleased] → ### Fixed` (new bullet; the beta.2 hold is user-visible) and the "Operators
   should expect new holds" paragraph loses the package-less-layer case.

## Acceptance

- The multi-layer E2E green on the reporter's harness; unit + evidence tests as above; gate
  green; no issue numbers in code.
- After merge: `beta.3` cut from `develop`; UAT repeats the `nginx:alpine` pull and expects
  every layer released.
