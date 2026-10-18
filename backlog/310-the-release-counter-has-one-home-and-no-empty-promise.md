# 310 — The release counter has one home, and no empty promise

**Issue:** #345 · **Branch:** `agent/345-curation-owns-the-manual-release`
**Governing decisions:** `docs/metrics-catalog.md` is the canonical metric
contract — a label value in the catalog that no code emits is a mismatch in
one of the two, exactly as a value in code that the catalog omits is.

**Depends on item 306**, which made the manual release tick the counter and
measured both problems below.

## What is true today

Item 306 closed the curator half and surfaced two things it could not take
without a decision:

1. **`policy_re_evaluation` is declared and nothing emits it.** Measured: the
   only `emit_release` call sites in the workspace are the manual one
   (`curation_use_case.rs:733`) and the two timer ones
   (`quarantine_use_case.rs:898`, `:2143`). `REASON_POLICY_RE_EVALUATION`
   (`metrics.rs:226`) is referenced by its own definition and its string test,
   nothing else. The production re-evaluation release is
   `PolicyUseCase::commit_re_evaluation` (~`:1996`), which appends
   `ArtifactReleased { PolicyReEvaluation }` and emits
   `hort_policy_evaluation_total` / `hort_policy_reevaluation_result` — never
   the release counter. So a counter named `quarantine_released_total` still
   misses a release kind, and the catalog row carries an annotation saying so.
2. **`emit_release` lives in another use case's file and is reached across
   modules.** It is `pub(crate)` in `use_cases/quarantine_use_case.rs` and
   imported by `use_cases/curation_use_case.rs`. Every *other* emitter shared
   across modules in this crate is a `pub fn emit_*` in
   `crates/hort-app/src/metrics.rs` — including `emit_curation_decision`, which
   `waive` calls two lines earlier — and the shared `pub(crate)` helpers under
   `use_cases/` live in small dedicated modules, not inside a 9 000-line
   sibling.

## What to do

1. **Move `emit_release` into `crates/hort-app/src/metrics.rs`**, beside the
   other `emit_*` functions and the `labels::REASON` / `values::REASON_*`
   constants it already uses. Same body, same behaviour, `pub fn`. Drop the
   `pub(crate)` reach-across and fix both import sites. The metric-name literal
   stays spelled **exactly once** — a second `counter!("hort_quarantine_released_total", …)`
   anywhere is how a typo becomes a silently separate series.
2. **Tick the counter on the re-evaluation release.** `commit_re_evaluation`
   handles **one artifact per call** and has two arms: it appends either
   `ArtifactQuarantined` (re-quarantine) or
   `ArtifactReleased { PolicyReEvaluation }`. Emit
   `emit_release(values::REASON_POLICY_RE_EVALUATION)` **only on the release
   arm, and only after the append succeeds** — the function returns `false` on
   a conflicting append, and a tick before the commit would count a release
   that did not happen.
   **The intent, decided (architect, 2026-10-11):** the counter counts
   *released artifacts*, one tick each, exactly as the timer sweep already
   ticks per artifact rather than per pass. A bulk re-evaluation that releases
   seven artifacts ticks seven times.
3. **Then the catalog row states the plain truth.** With all three values
   emitted, drop item 306's "declared but nothing emits it" annotation for
   `policy_re_evaluation` and keep the retired-`admin` note. Same for both
   Grafana panel descriptions and the constant's doc comment.
4. **Correct `metrics.rs`'s module doc.** It claims the module *"intentionally
   contains no emission code — only canonical string constants and enums"*
   (`:4`–`:5`) while the file holds **53** `pub fn emit_*` functions. Say what
   the module is: the canonical vocabulary **and** the emitters that spell it.
   One paragraph, no restructuring, and nothing else in that file.

## Explicitly out of scope

- Any new metric, label or label value; any alerting rule.
- The re-quarantine arm — it is not a release and ticks nothing here.
- Changing what `commit_re_evaluation` does, its signature, or its return
  contract.
- Moving or renaming any other `emit_*` function, or sweeping the other 53.

## Acceptance

- `emit_release` is `pub fn` in `metrics.rs`; `grep -rn 'fn emit_release' crates/`
  finds exactly one definition, and no `use_cases` module exports it.
- A re-evaluation that **releases** an artifact ticks
  `hort_quarantine_released_total{reason="policy_re_evaluation"}` exactly once;
  a re-evaluation that **re-quarantines** ticks it zero times; a release whose
  append **fails** ticks it zero times. Three assertions, mirroring item 306's
  pair.
- The catalog row reads `reason ∈ timer, curator, policy_re_evaluation` with
  only the retired-`admin` note, and both dashboard descriptions agree.
- `metrics.rs`'s module doc no longer contradicts its own contents.
- Gate: the **unit gate**, one-shot capture:
  `bash handover/gate-unit.sh -p hort-app` — judge by the output, not the rc,
  and quote the totals. Do **not** run `cargo test --workspace`, `cargo audit`,
  `cargo deny` or the attribution script: together they outlast a worker's
  foreground tool window, so the harness backgrounds them and the run ends with
  the gate killed and the report lost. The architect runs the full gate on the
  same tree before any MR.
