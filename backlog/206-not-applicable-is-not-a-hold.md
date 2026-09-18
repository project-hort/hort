# 206 — "Not applicable" is a completed assessment, not a hold: an artifact without a package surface is outside the scan axis

**Issue:** #264 · **Branch:** `agent/264-trivy-materialisation` (continues items 190/191/202) · single item · hort-app + hort-domain event + ADR 0007 clarification. Authorised by the human's decision on #264 (option B).

## Defect (by construction on the branch; not exercised by the E2E suite)

Every OCI row is scanned on its own. An OCI manifest row and a non-tar OCI blob (the image
config JSON) yield `NotAnalysable::NotApplicable` (`hort-domain/src/ports/scanner.rs:71`; the
adapter logs "artifact kind carries no analysable surface" / "blob is not layer content"). The
orchestrator treats every abstention alike (`scan_orchestration.rs:518-552`): all-abstained →
`ScanRunOutcome::NothingAnalysable` → `record_scan_indeterminate` → the row holds. So a Trivy-
policed OCI repository holds every image it ingests, forever. Two classes are conflated:

- `UnusableArchive`, `NoAnalyzerMatched`: a surface was expected and could not be assessed —
  fail-closed is right (ADR 0007).
- `NotApplicable`: the artifact structurally carries no package surface; no scanner can find a
  threat level in it. Holding it is a category error, not caution.

## Governing decisions

ADR 0007 (fail-closed scan axis — clarified, not amended: an artifact with no scannable surface is
outside the axis; the release gate's scan authority for it is "nothing to assess", recorded as
such). ADR 0034 (verdict at the gate). Precedent in code: `ScanRunOutcome::SkippedNoBackends`
already records a completed result with scanner `"(none)"` and no findings
(`scan_orchestration.rs:607-616`) — "nothing to assess" is an existing shape.

## Change

1. **Orchestrator:** partition abstentions by reason. If every backend abstained and every
   abstention is `NotApplicable` → `ScanRunOutcome::Completed { scanner: <backends>, findings:
   vec![], sbom, not_applicable: true }` (or an equivalent explicit variant) → recorded through
   `record_scan_result` so scan authority exists and the gate opens. Any `UnusableArchive` /
   `NoAnalyzerMatched` among the abstentions keeps today's `NothingAnalysable` → indeterminate.
   Mixed with an analysed backend: unchanged (the analysed verdict wins, as today).
2. **Trail is honest:** `ScanCompleted` (`hort-domain/src/events/artifact_events.rs:249`) gains
   an additive, `#[serde(default)]` field (e.g. `assessment: Assessment::{Analysed,
   NotApplicable}` or `not_applicable: bool`) so a reader can tell "analysed, clean" from
   "nothing to assess". Old events deserialise as `Analysed`. The curation-queue/status
   projections that show a scan verdict show it too (`git grep -n finding_count crates/hort-http-core/src/handlers`).
3. **Metrics:** `hort_scan_terminal_total` gets a `not_applicable` result value (closed
   taxonomy updated in `docs/metrics-catalog.md`); `emit_scan_failure(NothingAnalysable)` is no
   longer emitted for `NotApplicable`.
4. **Domain:** `NotAnalysable` doc comments state the split (which variants gate, which do not);
   the OCI handler's `scan_kind`/adapter classification stays as is.
5. **ADR 0007:** one dated clarification paragraph (no new authority): the scan axis applies to
   artifacts with a scannable surface; for the rest the recorded assessment is "not applicable"
   and the time gate alone governs. Point at `NotAnalysable` as the code-level definition.
6. **Tests (hort-app 100 %):** all-`NotApplicable` → `record_scan_result` with empty findings and
   the marker, no `record_scan_indeterminate`; one `NoAnalyzerMatched` among them → indeterminate;
   `UnusableArchive` → indeterminate; mixed analysed+not-applicable → analysed result; event
   round-trip with and without the new field; `SkippedNoBackends` unchanged.
7. **E2E:** extend `clients/oci` (or the scenario the reporter prefers) with a post-window
   release assertion on `hort-oci` (Trivy policy, `quarantineDuration: 1h` is too long — use a
   repository fixture with a short window or the existing zero-window proxy scenario with a
   Trivy policy) so a Trivy-policed image's config blob and manifest are released and the pull
   succeeds; layers still carry their findings. Branch-first on the reporter's harness.
8. `CHANGELOG.md`: fold into this branch's existing `[Unreleased]` bullet (one MR); the
   "Operators should expect new holds" paragraph drops the OCI config/manifest sentence.

Out of scope: image-level scanning (manifest as subject, cascade) — filed as its own issue.

## Acceptance

- A Trivy-policed OCI image is releasable: manifest and config rows record a not-applicable
  assessment, layers record analysed verdicts; unit tests above green; the trail distinguishes
  the two; the E2E release assertion green on the reporter's harness.
- `UnusableArchive` and `NoAnalyzerMatched` still hold (tests pin it).
- Gate green (fmt, clippy, `cargo test --workspace`, audit, deny); no issue numbers in code.
