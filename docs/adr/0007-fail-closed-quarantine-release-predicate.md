# 0007 — Fail-closed quarantine release predicate

- **Status:** Accepted
- **Enforced by:** the background sweep releases an artifact only when `quarantine_until <= now()` **AND** the application layer can supply a recognised release authority; the predicate accepts exactly six `(reason, authority)` pairs (five as originally decided, plus `ScanRecorded` — see the 2026-08-21 amendment) and denies every other. The predicate is implemented in `Artifact::release` (`crates/hort-domain/src/entities/artifact.rs`) with exhaustive per-authority tests; the architect anti-pattern *scanner clean → immediate release* is a review hard-block.
- **Supersedes:** —

## Context

Quarantine is the observation window that lets a scan run and lets a malicious package's reputation catch up before it can be downloaded or promoted. Two failure modes must be impossible: (1) a clean scan releasing an artifact *early* (before the window elapses), and (2) a never-successfully-scanned artifact releasing on the timer alone when its window expires. Both would let an unvetted artifact through.

`quarantine_until <= now()` answers "is the window over?" — it must never, by itself, answer "may this be released?".

## Decision

Downloads are blocked while `quarantine_status = 'quarantined'`, regardless of the timestamp — the **status** is the gate, the **timestamp** is only the sweep's candidacy filter.

The background sweep transitions an artifact to `released` only when `quarantine_until <= now()` **AND** a release authority is available. The release predicate accepts **exactly five authorities** (six as of the 2026-08-21 `ScanRecorded` amendment below) and denies every other `(reason, authority)` pair:

1. `ScanSucceeded` — a successful `ScanCompleted` on the artifact stream.
2. `ScanWaived` — the resolved `ScanPolicy` declares `scan_backends: []`.
3. `AdminOverride` — explicit admin release.
4. `CuratorWaiver` — curator waive (`Quarantined`-state only).
5. `PolicyReEvaluation` — post-exclusion policy re-evaluation.
6. `ScanRecorded` — the artifact was scanned and the resolved `ScanPolicy` declares `enforcement: record` (added by the 2026-08-21 amendment below; not part of the original five).

`ScanCompleted(clean)` does **not** clear `quarantine_until` or set `released`. `ScanCompleted(findings)` immediately sets `rejected` (time never reverses this). A scan job that exhausts retries fails closed — see the exhaustion split below.

### "A successful `ScanCompleted`" means the latest verdict, not mere presence (issue #108, amended 2026-08-05; human-approved via `workflow::ready`)

Authority 1 above reads "a successful `ScanCompleted` on the artifact stream" — this was under-specified enough to have been misimplemented as *any* `ScanCompleted`, full stop. That is wrong: the **rejecting** scan branch (the `ScanCompleted(findings)` → `rejected` path noted above) itself commits a `ScanCompleted` event — with a nonzero `finding_count` — immediately before the `ArtifactRejected` that makes the verdict terminal. A presence-only reading of authority 1 therefore treated a dirty scan's own rejection record as a release authority for the very artifact it had just condemned, defeating the `rejected` status it landed in the same commit (issue #108 H3 — closed by hardening the two verdict-commit paths that made the resulting timer-release *reachable*, items 1–2 of the same issue; this clarification closes the authority predicate itself as defense-in-depth, so the amplifier cannot resurface even if a future write path reopens the underlying race).

**"Successful" is defined precisely as:** the artifact's **latest** `ScanCompleted` on the stream carries `finding_count == 0`, **AND** no `ArtifactRejected` appears **later** on the stream than that `ScanCompleted`. Both clauses matter and are independent failure modes:

- A stream whose latest `ScanCompleted` is dirty (`finding_count > 0`) never authorizes release, regardless of how many earlier clean scans preceded it — the latest verdict governs, not any-verdict-ever.
- A stream whose latest `ScanCompleted` is clean but is followed by a later `ArtifactRejected` (an admin/curation rejection landing after the scan, for instance) also never authorizes release — the clean scan is stale with respect to the subsequent rejection.
- Symmetrically, an earlier dirty scan + rejection followed by a genuinely later clean **rescan**, with no further rejection after it, DOES authorize release — the predicate is about the latest verdict on the stream, not "was there ever a rejection anywhere in this artifact's history".

This reads the SAME artifact stream `resolve_release_authority` already reads to check for presence; no new port, query shape, or release authority is introduced. The other four authorities (`ScanWaived`, `AdminOverride`, `CuratorWaiver`, `PolicyReEvaluation`) are unaffected — this clarification is scoped to authority 1 alone.

### Scan-execution failure vs ambiguous result on retry-exhaustion (issue #6, amended 2026-07-14)

A `ScanRunOutcome::Failed` that exhausts `HORT_SCANNER_MAX_ATTEMPTS` is a scanner-**execution** failure (every configured backend errored — the scan could not run), which is operationally distinct from a genuinely ambiguous scan **result**. On exhaustion, `ScanOrchestrationUseCase::record_outcome` splits by the artifact's **current** `quarantine_status`:

- **`quarantined`** (mid-observation-window) → the artifact **stays `quarantined`**. No `ScanIndeterminate` event and **no `quarantine_status` UPDATE at all** — the failed `jobs` row (`status='failed'`, `last_error`) is the persisted "last scan errored" signal. It is re-picked by `RescanCandidatesRepository::select_stranded` + `CronRescanTickHandler` and re-scanned once the scanner recovers, self-healing without operator intervention.

  **Amended (issue #115, 2026-08-05) — "failed **or no job row at all**".** The rescue path above keyed on a *failed* job row, which silently excluded a second, worse stranding shape: an artifact quarantined with **no `kind='scan'` job ever enqueued**. Such a row is invisible to `select_eligible` (which requires `released`/`NULL`) *and* to the original `select_stranded` (whose `JOIN LATERAL` on the most-recent scan job produces no join row at all when none exists) — so it stays `quarantined` and 503s indefinitely, and with no manual per-artifact rescan surface in the product there is no operator recovery. The concrete producer was the seed-import cutover path (`register_by_hash_inner`'s `quarantine_anchor_override` branch), which stamped the backdated anchor without enqueueing the scan; that inflow is now closed at the source (the branch enqueues scan + provenance atomically with the quarantine transition, the same `commit_transition_with_enqueues` shape `ingest_inner` uses). For the rows already stranded in deployed environments, `select_stranded` is widened to a `LEFT JOIN LATERAL` with predicate `(last_job.status = 'failed' OR last_job.status IS NULL)`.

  The widening carries a **scan-policy guard**, and it is load-bearing: candidacy additionally requires the artifact's resolved policy (repo-scoped-else-global-else-`DefaultPolicy`, the same resolution `select_eligible` uses) to actually scan — `COALESCE(cardinality(scan_backends), <default-len>) > 0`. A job-less quarantined artifact under a `scan_backends: []` (ScanWaived) policy is **not** stranded: it releases via the existing `ScanWaived` authority, and enqueueing a scan for it would contradict the operator's own explicit opt-out. Terminal states (`rejected`, `scan_indeterminate`) and `is_deleted` remain never selected, exactly as before. No new release authority is added — this only restores the *scan* that the existing authorities already required.
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

**As-built:** the anchor-backdating lives in `IngestUseCase::ingest_inner` (`crates/hort-app/src/use_cases/ingest_use_case.rs`) — a referenced-tree-descendant artifact's `quarantine_window_start` is set to `ingested_at - effective_duration` instead of `ingested_at`, so the live-computed deadline (`effective_quarantine_deadline(anchor, duration)`) equals `ingested_at`. The target-check excludes the self-referencing refcount kinds `primary_content` / `metadata_blob` — every artifact's own ingest writes a `primary_content` row targeting its own hash, so an unfiltered "is this hash a target of any kind" check would misidentify every artifact as its own descendant; this exclusion is load-bearing for the carve-out to stay correctly scoped. The predicate itself now lives in one shared helper (`hort_app::use_cases::referenced_descendant::is_referenced_tree_descendant`) used by both the ingest anchor decision and the provenance hold below, so the two definitions cannot drift.

#### The window is ALSO the `Required`-mode provenance hold predicate (issue #115, amended 2026-08-05)

The #46 rationale above was written against the **scan** release authority, and its "the window is pure latency for every artifact, not protection" claim is correct *on that axis*. It missed that `window_open` had since become load-bearing on a **second** axis: it is the HOLD predicate for the `NoAttestation × Required` provenance arm (issue #13). Collapsing the window to zero therefore did not merely remove a timer for descendants — it flipped "held pending signature" to "terminally rejected as `Unsigned`" the instant a descendant's ingest-enqueued `provenance-verify` ran.

That is a real, reachable failure: OCI pull-through writes `oci_config`/`oci_layer` edges *before* the blobs are pulled, so every layer ingests as a zero-window descendant; cosign signs only the top-level digest, so a layer has no attestation of its own and never will; under `Required` the verify resolved `NoAttestation × window_open == false` → terminal `Rejected{Unsigned}` — **before** the subject's signature cascade could clear the constituent. `cascade_provenance_clearance` refuses a rejected constituent ("terminal is terminal"), so a correctly-signed multi-layer image became permanently unpullable.

**Decision:** `Artifact::complete_provenance`'s `NoAttestation × Required` arm holds on `window_open || is_referenced_descendant`. A descendant's provenance authority **is its parent's signature** — delivered by the ADR 0039 cascade, not by an attestation of its own — so it must never be terminally rejected for lacking one. This is scoped exactly like `window_open`: **only** that arm consults the flag. A forged / untrusted / digest-mismatch signature on a descendant is position-independent (already wrong) and still rejects terminally, so the carve-out cannot launder a tampered layer.

**This strengthens fail-closed rather than relaxing it.** The held descendant stays `Quarantined` — not downloadable, 503 — until either the cascade clears it or an admin releases it under the ADR 0025 source-state rules. An unsigned parent under `Required` leaves its constituents held **forever**, which is the correct outcome and, unlike the terminal rejection it replaces, is recoverable: sign the parent, the S3 hook re-verifies the subject, the cascade clears the constituents. No release authority is added; `Pending` is the fail-closed reading at the release gate either way.

The carve-out is automatic (derived from the reference graph), not an operator opt-in, so it adds no ADR 0016 cross-opt-in matrix row — it is recorded here as a prose interaction between two existing mechanisms.

### `register_by_hash` is gated for every caller, not only the ingest path (issue #107, amended 2026-08-09; human-approved via `workflow::ready`)

The quarantine gate was applied by the ingest path, while `register_by_hash`
— the path that registers a blob already present in CAS — reached the same
artifact table without it. Two callers exercised that gap: the OCI cross-repo
blob **mount**, and a **pull-dedup follower** registering the leader's fetched
bytes. Both produced a target-repository row that had never been held and
never been scanned, and served it.

**The gate belongs to the artifact row, not to the code path that created
it.** `register_by_hash` resolves the target repository's active policy and,
for a non-zero effective duration, commits the `None → Quarantined`
transition together with its scan and provenance enqueues in one transition —
the same shape the ingest path uses. A freshly mounted or follower-registered
blob is therefore held for the target repository's window and scanned before
it serves. `quarantineDuration: 0` remains the single honoured permissive
opt-out, exactly as on the ingest path.

**Source-status refusal is anti-enumeration-shaped.** When registration names
a source row, a source in a terminal state (`Rejected` / `ScanIndeterminate`)
is refused **as `NotFound`**, so a caller cannot distinguish "no such blob"
from "terminally blocked blob"; the OCI handler then falls through to a
regular upload per the spec, with no handler-level special case. A
`Quarantined` source stays mountable on purpose: the target copy is itself
quarantined and scanned under the rule above, so no unscanned bytes serve,
and refusing it would break legitimate mid-window mounts for no gain.

### A sixth authority: `ScanRecorded` under `enforcement: record` (amended 2026-08-21)

`ScanPolicy` gained an `enforcement: reject | record` mode. Under `record`
the scan still runs, the findings and the `PolicyEvaluated(Fail)` verdict are
still persisted, and the artifact is **not** rejected — the operator has
declared that a scan verdict does not gate publication for that scope
("publish proceeds with findings; blocking at retrieval is the consuming
policy's job").

That declaration cannot be honoured without a release authority. Such an
artifact's own latest `ScanCompleted` carries `finding_count > 0`, so
authority 1 is by construction unavailable to it; with no authority the
artifact stays `Quarantined` and 503s forever — the operator's opt-in would
be inert (ADR 0015). The predicate therefore accepts a **sixth** authority:

6. `ScanRecorded` — the artifact was scanned, and its resolved `ScanPolicy`
   declares `enforcement: record`.

**Why a new variant rather than widening an existing one.** Both
alternatives were considered and are worse, for the same reason:

- *Widening `ScanSucceeded`* would make the "latest verdict, not mere
  presence" clause above (`finding_count == 0`) conditional on a policy
  field — softening a defence-in-depth hardening — and would stamp
  `authority = scan_succeeded` on a release of an artifact that did not
  pass, destroying the audit trail's ability to distinguish the two.
- *Reusing `ScanWaived`* would assert the operator declared the scope
  un-scanned, which is precisely what did **not** happen here: the scan ran
  and its evidence exists.

A distinct token keeps "released with recorded, over-threshold findings"
queryable, and leaves all five existing arms byte-identical. This is the
"adding any new release path means adding an authority to the enumerated
predicate, with its own guard" consequence below, applied as written.

**Its guard, and what it does not relax.** `ScanRecorded` is constructible
only by the application layer, from two verified facts: a `ScanCompleted`
exists on the artifact's own stream with **no later `ArtifactRejected`**, and
the resolved policy's `enforcement` is `record`. The `ScanCompleted`-must-
exist clause is load-bearing — it keeps the second impossible failure mode
from *Context* (a never-successfully-scanned artifact releasing on the timer
alone) true under `record` as well: the mode un-gates the *verdict*, never
the *observation*. It pairs only with `ReleaseReason::Timer` and carries the
**same** provenance AND-precondition as authorities 1 and 2, so a `Required`
-mode artifact with `Pending` clearance still does not release; the curation
conjunct and the observation window are likewise untouched. `record` un-gates
exactly one axis.

Per the bounded-await corollary below, the read-path candidacy gates were
re-validated against this authority: they consult `quarantine_status` and the
provenance clearance only, so a `record`-mode artifact is a wait candidate on
the same terms as a clean-scan one, and the inline fast-path release in
`record_scan_result` mints `ScanRecorded` (not `ScanSucceeded`) for it — the
same token the sweep's `resolve_release_authority` would mint for the same
artifact.

### Read-path bounded-await pattern (issue #65, amended 2026-07-20)

The zero-window carve-out above still leaves a **read-side** race: a cold pull-through blob GET resolves the just-ingested, still-`Quarantined` artifact and would 503 before that artifact's own async scan lands the `ScanSucceeded` that (per the carve-out) releases it almost immediately once it runs — the gap is the scan's own turnaround (~1–5s observed), not an observation window. `hort-http-oci::blobs::maybe_bounded_await_release` closes this by polling the artifact for up to a tunable bound (`HORT_OCI_PULLTHROUGH_RELEASE_WAIT_SECS`, default 10s, `0` = off) before falling through to the existing `check_quarantine` 503 decision.

**This pattern never touches the release predicate and is recorded here as the invariant future read paths adopting it must preserve:** a bounded-await helper may only ever *re-read* `quarantine_status` in a loop and return whatever it observes — it must never call `Artifact::release` or synthesize a release authority itself. It can only ever turn a would-be 503 into a 200 that the artifact's own scan pipeline had already, independently, authorized through the existing five-authority predicate; it can never turn a would-be 503 into an incorrectly-served blob. If the scan never completes, rejects, or the bound elapses first, the artifact is returned unchanged and the caller's existing 503 / hidden-404 handling runs exactly as before.

**Candidacy signal correctness matters as much as the wait mechanism.** The helper must gate the wait on the *real* effective deadline (`quarantine_window_start` anchor + the artifact's actually-matched `ScanPolicy` duration) — never on `ArtifactUseCase::hydrate_quarantine_deadline`'s approximation (`quarantine_deadline = quarantine_window_start`, used only for the `check_quarantine` `Retry-After` computation), which reads as "elapsed" for essentially every `Quarantined` artifact almost immediately because `ArtifactUseCase` holds no policy-projection port to resolve a real duration. Using that signal for the wait-candidacy gate would silently defeat the "never await a genuine, not-yet-elapsed time-quarantine" requirement — a still-running multi-minute (or longer) hold would get bounded-waited on every GET instead of 503ing immediately. `QuarantineUseCase::is_window_elapsed` (new, issue #65) resolves the real matched-policy duration via the same `resolve_active_policy_for_repo` + `effective_quarantine_deadline` computation the `record_scan_result` inline fast-path and the `release_expired` sweep already use, and is the only sanctioned source for this gate.

**Amended (issue #135): a provenance-blocked release is not a wait candidate.** The pattern's premise — "window elapsed ⇒ the only thing left is the artifact's own scan" — predates the provenance release authority (ADR 0039/0041). Under `provenance_mode: Required` with the artifact's clearance still `Pending`, release additionally requires an external signature plus verify/cascade, which cannot land inside the bound, and the inline fast-path release is suppressed for exactly this state — so the await was a guaranteed full-bound stall (measured: a constant 10s per cold blob GET) in front of the same 503. The candidacy gate therefore also consults `QuarantineUseCase::release_blocked_on_provenance`, which delegates to the SAME single-sourced clearance resolution (`release_clearance::resolve_provenance_clearance`) the fast-path suppression and the release sweep use — one authority, no drift; `Pending` ⇒ skip the wait entirely and fall through to the honest `503 + Retry-After` immediately. Both invariants above are untouched: the guard only *narrows* candidacy (it can never start a wait that today would not start, and it never synthesizes a release). A scan-pending artifact whose provenance is already `Cleared` — including a late-joining constituent self-cleared at ingest (ADR 0039 §12) — remains a wait candidate; that is the case the pattern exists for. Corollary for future read paths adopting the pattern: when a NEW release authority is added to the predicate above, every bounded-await candidacy gate must be re-validated against it — an await whose premise omits an authority degrades into a fixed-latency tax on exactly the requests that authority holds.

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
- `crates/hort-http-oci/src/blobs.rs` (`maybe_bounded_await_release`) and `crates/hort-app/src/use_cases/quarantine_use_case.rs` (`QuarantineUseCase::is_window_elapsed`) — the issue #65 read-path bounded-await pattern amended in above.
- `crates/hort-app/src/use_cases/ingest_use_case.rs` (`IngestUseCase::ingest_inner`) — the referenced-tree-descendant zero-window anchor-backdating (issue #46, amended above); `docs/adr/0043-oci-image-index-support.md` — the `content_references` membership graph (`oci_index_member` / `oci_subject` / `oci_config` / `oci_layer`) the target-check reads.
