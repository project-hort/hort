# 0007 — Fail-closed quarantine release predicate

- **Status:** Accepted
- **Enforced by:** the background sweep releases an artifact only when `quarantine_until <= now()` **AND** the application layer can supply a recognised release authority; the predicate accepts exactly five `(reason, authority)` pairs and denies every other. The predicate is implemented in `Artifact::release` (`crates/hort-domain/src/entities/artifact.rs`) with exhaustive per-authority tests; the architect anti-pattern *scanner clean → immediate release* is a review hard-block.
- **Supersedes:** —

## Context

Quarantine is the observation window that lets a scan run and lets a malicious package's reputation catch up before it can be downloaded or promoted. Two failure modes must be impossible: (1) a clean scan releasing an artifact *early* (before the window elapses), and (2) a never-successfully-scanned artifact releasing on the timer alone when its window expires. Both would let an unvetted artifact through.

`quarantine_until <= now()` answers "is the window over?" — it must never, by itself, answer "may this be released?".

## Decision

Downloads are blocked while `quarantine_status = 'quarantined'`, regardless of the timestamp — the **status** is the gate, the **timestamp** is only the sweep's candidacy filter.

The background sweep transitions an artifact to `released` only when `quarantine_until <= now()` **AND** a release authority is available. The release predicate accepts **exactly five authorities** and denies every other `(reason, authority)` pair:

1. `ScanSucceeded` — a successful `ScanCompleted` on the artifact stream.
2. `ScanWaived` — the resolved `ScanPolicy` declares `scan_backends: []`.
3. `AdminOverride` — explicit admin release.
4. `CuratorWaiver` — curator waive (`Quarantined`-state only).
5. `PolicyReEvaluation` — post-exclusion policy re-evaluation.

`ScanCompleted(clean)` does **not** clear `quarantine_until` or set `released`. `ScanCompleted(findings)` immediately sets `rejected` (time never reverses this). A scan job that exhausts retries fails closed — see the exhaustion split below.

### Scan-execution failure vs ambiguous result on retry-exhaustion (issue #6, amended 2026-07-14)

A `ScanRunOutcome::Failed` that exhausts `HORT_SCANNER_MAX_ATTEMPTS` is a scanner-**execution** failure (every configured backend errored — the scan could not run), which is operationally distinct from a genuinely ambiguous scan **result**. On exhaustion, `ScanOrchestrationUseCase::record_outcome` splits by the artifact's **current** `quarantine_status`:

- **`quarantined`** (mid-observation-window) → the artifact **stays `quarantined`**. No `ScanIndeterminate` event and **no `quarantine_status` UPDATE at all** — the failed `jobs` row (`status='failed'`, `last_error`) is the persisted "last scan errored" signal. It is re-picked by `RescanCandidatesRepository::select_stranded` + `CronRescanTickHandler` and re-scanned once the scanner recovers, self-healing without operator intervention.
- **any other status** (`None` — the permissive default, no window to fall back into; or an already-terminal status) → terminal **`scan_indeterminate`**, exactly as before this amendment. A best-effort artifact-load failure resolves to `None` here and therefore also fails to `scan_indeterminate` (safe direction).

**Why staying `quarantined` is still fail-closed.** The two impossible failure modes in *Context* are unchanged. A `quarantined`, never-successfully-scanned artifact is **not** releasable by the timer: release still requires one of the five enumerated authorities, and the only one the sweep can synthesize is `ScanSucceeded` — derived from a `ScanCompleted` **event on the artifact stream**, which a stranded artifact does not have. `resolve_release_authority` returns `None`, the sweep skips it (`skipped_no_authority`), and `Artifact::release` re-denies deny-by-default. Window expiry remains candidacy-only. This amendment adds **no new release authority** and changes **no** release path; it only avoids escalating a recoverable outage to the stricter terminal state, so the artifact can heal via the *existing* `ScanSucceeded` path instead of requiring an admin override.

### Referenced-tree descendant zero-window carve-out (issue #46, amended 2026-07-17)

A **scoped carve-out**, NOT a reversal of the rejected "clean scan releases immediately" alternative below: a scanned-clean artifact that is a `content_references` **target** of an already-ingested parent (a referenced-tree descendant — e.g. an OCI image-index child manifest, or a manifest's config/layer blob) releases on its own `ScanSucceeded` **without re-applying the observation window**; forward observation is the standard released-artifact rescan.

**Why this loses no protection:**

1. **No in-window rescan (verified).** `RescanCandidatesRepository::select_eligible` rescans only `released`/`NULL` artifacts on the 24h interval — the window never re-scans a `quarantined` artifact. So for *every* artifact, quarantined or not, the window is a single-scan-at-ingest + timer, not a rescan mechanism; it does not itself realise "reputation catch-up."
2. **Fresher scan.** The descendant is scanned at first-touch against the *current* CVE database — strictly more recent than the parent's ingest-time scan the operator already trusted at release.
3. **Identical forward observation.** On release the descendant enters the same 24h released-artifact rescan pool as everything else; post-release CVEs are caught identically to any other released artifact.

**Explicitly narrow.** This is *not* the general "clean scan releases immediately" alternative (below), which stays rejected. Only `content_references` **targets** qualify — an artifact with no parent referencing it keeps the full window, unchanged. A blob touched before its referencing manifest exists (no edge yet) takes the normal window; a later re-touch after the edge appears is a non-issue because the pull flow ingests the manifest before its blobs.

**The two impossible failure modes from *Context* are preserved verbatim:**

1. A clean scan cannot release *early*: the release predicate is completely untouched (`Artifact::release`'s deny-by-default `(reason, authority)` match) — a descendant still needs its own `ScanSucceeded`; releasing purely because the window collapsed to zero, with no scan, remains impossible.
2. A never-successfully-scanned artifact cannot release on the timer alone: the carve-out changes only the ingest-time **anchor** (`quarantine_window_start`), never the authority check — `resolve_release_authority` still requires a real `ScanCompleted` event on the artifact's own stream.

**As-built:** the anchor-backdating lives in `IngestUseCase::ingest_inner` (`crates/hort-app/src/use_cases/ingest_use_case.rs`) — a referenced-tree-descendant artifact's `quarantine_window_start` is set to `ingested_at - effective_duration` instead of `ingested_at`, so the live-computed deadline (`effective_quarantine_deadline(anchor, duration)`) equals `ingested_at`. The target-check excludes the self-referencing refcount kinds `primary_content` / `metadata_blob` — every artifact's own ingest writes a `primary_content` row targeting its own hash, so an unfiltered "is this hash a target of any kind" check would misidentify every artifact as its own descendant; this exclusion is load-bearing for the carve-out to stay correctly scoped.

## Consequences

- A missing or failed scan **fails closed**: the artifact does not leak out when its timer expires. A never-scanned (`None`-status) or already-terminal artifact lands in `scan_indeterminate`; an artifact still `quarantined` when its scan exhausts retries stays `quarantined` and is auto-rescanned once the scanner recovers (issue #6, above) — in both cases the timer cannot release it.
- Adding any new release path means adding an authority to the enumerated predicate, with its own guard — there is no "fall through to released".
- The `scan_backends: []` waiver is an explicit, audited authority, not an accidental gap.
- Re-evaluation after an exclusion does not skip the remaining observation window: it removes the scan block, not the time hold.

## Alternatives considered

- **Release on `quarantine_until` expiry alone.** Rejected: this is precisely the hole the fail-closed predicate exists to plug — an artifact that never passed a scan would auto-release on the timer.
- **Clean scan releases immediately.** Rejected: collapses the observation window the quarantine exists to provide. This general reversal stays rejected; do not conflate it with the *narrow* referenced-tree-descendant carve-out above (issue #46) — that carve-out applies only to `content_references` targets and does not touch the release predicate.
- **A boolean "releasable" flag set by various code paths.** Rejected: a single mutable flag with many writers is exactly the ambiguity the enumerated `(reason, authority)` predicate removes.

## References

- `crates/hort-domain/src/entities/artifact.rs` (`Artifact::release`) and `crates/hort-domain/src/ports/quarantine_release.rs` — the release predicate and `ScanIndeterminate` status.
- The architect skill → Quarantine Invariants; anti-pattern *scanner clean → immediate release*.
- `docs/architecture/how-to/curator-workflow.md` — the curator-waiver authority in practice.
- `docs/architecture/how-to/recover-stranded-artifacts.md`; `ScanOrchestrationUseCase::record_outcome` and `RescanCandidatesRepository::select_stranded` — the issue #6 exhaustion-split / stranded-scan recovery amended in above (commit `55a93e40`; ratified by decision issue #32, 2026-07-14).
- `crates/hort-app/src/use_cases/ingest_use_case.rs` (`IngestUseCase::ingest_inner`) — the referenced-tree-descendant zero-window anchor-backdating (issue #46, amended above); `docs/adr/0043-oci-image-index-support.md` — the `content_references` membership graph (`oci_index_member` / `oci_subject` / `oci_config` / `oci_layer`) the target-check reads.
