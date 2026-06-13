# The Scanning Pipeline

Quarantine holds an artifact; scanning decides what happens to it.
This page is the **producer** side of that story — how hort turns a
quarantined artifact's bytes into a scan verdict: the ports, the two
shipped scanner families, SBOM extraction, the job lifecycle, and the
two externally-triggered sweeps that keep verdicts fresh after release.
The **consumer** side — how a verdict feeds the fail-closed release
predicate, and the policy kinds (`ScanPolicy`, `Exclusion`,
`CurationRule`) that define the gate — lives in
[ADR 0007](../../adr/0007-fail-closed-quarantine-release-predicate.md)
and the supply-chain-gate section of [security.md](security.md). The
split is real in the code: the producer runs in `hort-worker` and ends
at an atomic event-batch commit; the consumer reads those events and
never re-runs a scanner.

A consequence of the split worth stating up front: `hort-server`
contains no scan logic and no scheduler. Every scan executes in the
worker, claimed from the shared `jobs` table; every periodic sweep is
an admin-task endpoint an external cron invokes. The server's only
producer-side contribution is enqueueing.

## Ports and the two backend families

Two outbound ports cover everything that produces vulnerability data.

**`ScannerPort`** (`crates/hort-domain/src/ports/scanner.rs`) is the
content-adjudicating port: `scan(content_hash, sbom) ->
Vec<Finding>`, plus a `name()` that must match the identifier
operators write in `ScanPolicy.scan_backends`, and a `health_check()`
probed at worker boot. Scanner adapters live in their own crates and
depend only on `hort-domain`; the orchestrator treats them as opaque
hash-in, findings-out functions. Two families ship:

- **Trivy** (`crates/hort-adapters-scanner-trivy/`) pulls the artifact
  bytes from `StoragePort::get`, writes them into a `tempfile::TempDir`
  (removed on drop, including panic and error paths), shells out to
  `trivy fs --format json`, and parses the report. It ignores the
  supplied SBOM and rediscovers components from the payload itself —
  which is exactly what makes it the adjudicator of record against
  the actual bytes.
- **OSV-scanner** (`crates/hort-adapters-scanner-osv/`) goes the other
  way: it never touches the content bytes. It serialises the supplied
  `Sbom` into a CycloneDX 1.5 document and runs
  `osv-scanner scan source --sbom`. With no SBOM it logs and returns
  an empty finding set — a documented skip, not an error.

**`AdvisoryPort`** (`crates/hort-domain/src/ports/advisory.rs`) is the
feed port, with two methods serving two different moments. `query`
resolves a component list against OSV.dev's `/v1/querybatch`
(`crates/hort-adapters-advisory-osv/src/lib.rs`, cached per-component
in the evictable `advisory:osv:` keyspace) and is called once per scan
as pre-scan enrichment. `pull_diff_since` pulls the per-ecosystem OSV
bulk archives and powers the advisory watch (below); it never runs
inside a scan.

Backend selection is policy data, not deployment config. The
orchestrator resolves the active `ScanPolicy` (repository-scoped wins
over global) and reads its `scan_backends` list
(`crates/hort-app/src/use_cases/scan_orchestration.rs`,
`run_scan`). No policy resolved means the built-in default
`["trivy"]` (`DefaultPolicy::block_on_critical_default_backends`,
`crates/hort-domain/src/policy/scan.rs`) — out-of-the-box deployments
scan. An explicit `scan_backends: []` is the operator's opt-out: the
scan completes immediately with a clean zero-finding record, and the
release predicate accepts the `ScanWaived` authority for that artifact
([ADR 0007](../../adr/0007-fail-closed-quarantine-release-predicate.md)).
Because an empty backend list is a release authority, it participates
in the cross-opt-in interaction rules: the gitops apply-time linter
rejects combining it with `trust_upstream_publish_time`
(`trust_upstream_publish_time_requires_scan_backends` in
`crates/hort-app/src/lint/static_validate.rs`;
[ADR 0016](../../adr/0016-cross-opt-in-interaction-matrix.md)).

The worker refuses to boot half-armed: with both
`HORT_SCANNER_TRIVY_ENABLED` and `HORT_SCANNER_OSV_ENABLED` false,
composition fails with an explicit "nothing to scan" error, and every
enabled backend's `health_check` must pass before the dispatcher
starts (`health_check_all_or_fail` in
`crates/hort-worker/src/composition.rs`).

## SBOM extraction

`FormatHandler::extract_sbom`
(`crates/hort-domain/src/ports/format_handler.rs`) turns an ingested
artifact into a deterministic component list — the `Sbom` type
(`crates/hort-domain/src/types/sbom.rs`) carries an optional `subject`
(the artifact itself) plus its declared `components`. The trait
default returns `Ok(None)`: opaque formats have no machine-readable
dependency manifest. The npm, PyPI, and Cargo handlers override it
(`crates/hort-formats/src/{npm,pypi,cargo}.rs`), and all three are
pure functions over the format metadata the handler already extracted
at ingest time — the orchestrator threads the `ArtifactMetadata`
projection row onto the coordinates and passes an empty payload
handle, so scan-time SBOM extraction costs no payload I/O. A manifest
that exists but declares no dependencies yields
`Some(Sbom { components: [] })`; `None` is reserved for "this format
has no manifest concept at all".

Extraction is best-effort by design: a missing handler, a `None`, or
a parse error all degrade to scanning without an SBOM
(`try_extract_sbom` in `scan_orchestration.rs`), observable on
`hort_sbom_extraction_total{format, result}`. Trivy still adjudicates
the payload; only the SBOM-consuming backend and the advisory
enrichment lose their input.

One subtlety the enrichment step encodes: the advisory query runs over
`Sbom::all_components_owned()`, which includes the subject, not just
the dependencies. An advisory against the package itself (the leaf,
e.g. a vulnerable release of the very artifact under scan) must match
— iterating only `components` would silently exempt leaf packages.

## The scan job lifecycle

Scans ride the generalised `jobs` table as `kind='scan'` rows. Four
surfaces enqueue them, distinguishable forever after by
`trigger_source` and ordered by `priority` (claims drain
`priority DESC, created_at ASC`):

- **Ingest** — `IngestUseCase` appends `ScanRequested` in the same
  event batch as `ArtifactIngested` and enqueues with
  `trigger_source="ingest"`
  (`crates/hort-app/src/use_cases/ingest_use_case.rs`). Every fresh
  artifact gets its first scan this way.
- **Manual** — `POST /api/v1/artifacts/:id/rescan`
  (`crates/hort-http-admin-security/src/router.rs` →
  `ManualRescanUseCase`), priority 20. Write-gated on the parent
  repository with the standard anti-enumeration collapse, and
  conflict-checked: an in-flight scan for the artifact returns the
  existing job id as a conflict rather than stacking a duplicate.
- **Cron rescan** — priority 10 (below).
- **Advisory watch** — priority 5 (below). The deliberate ordering
  puts the cron safety-net above the advisory fan-out and manual
  operator intent above both.

A partial unique index on `(artifact_id) WHERE kind='scan'` over
non-terminal rows makes "one in-flight scan per artifact" a database
invariant; races between trigger sources surface as conflicts the
enqueueing handlers swallow per row.

The worker's `TaskDispatcher`
(`crates/hort-app/src/task_dispatcher.rs`) claims batches and routes
`kind='scan'` rows to `ScanTaskHandler`
(`crates/hort-app/src/task_handlers/scan.rs`), a thin adapter over the
real orchestration in
`ScanOrchestrationUseCase` (`crates/hort-app/src/use_cases/scan_orchestration.rs`).
`run_scan` is pure work — it loads the artifact, resolves the policy
chain, extracts the SBOM, runs the advisory enrichment (best-effort:
a failed query logs and proceeds empty), and invokes each configured
backend in declared order. A backend that fails while a sibling
succeeds is tolerated; the union of findings is deduplicated on
case-insensitive `(purl, vulnerability_id)` with the higher severity
winning a collision (`merge_findings`). `record_outcome` then hands
the merged finding list to the consumer boundary,
`QuarantineUseCase::record_scan_result`
(`crates/hort-app/src/use_cases/quarantine_use_case.rs`).

That handoff is the pipeline's single most load-bearing property:
**one Postgres transaction** commits the findings blob reference, the
per-finding `scan_findings` projection rows, the `sbom_components`
projection replace, the artifact's state transition, the
`repo_security_scores` delta, and the event batch. There is no state
in which the event log says one thing and a projection says another.

### Hash-referenced findings

`ScanCompleted` (`crates/hort-domain/src/events/artifact_events.rs`)
carries the fast aggregates inline — `finding_count` and a
`severity_summary` — and a `findings_blob: Option<ContentHash>`
pointing at the JSON-serialised `Vec<Finding>` written to CAS through
the same `StoragePort::put` path as artifact content. The event's
`validate()` enforces the shape as an invariant: a blob is present if
and only if `finding_count > 0`, and the severity counts must sum to
the finding count. Clean scans never reference a blob; dashboards and
CLIs render the inline summary and fetch the blob only when an
operator drills into per-finding detail.

### Newly-vulnerable detection

Inside the same transaction, the consumer hydrates the most recent
prior `ScanCompleted`'s findings from its blob and runs the pure delta
function `compute_added_findings`
(`crates/hort-domain/src/policy/scan_delta.rs`). When a prior scan
exists and the delta is non-empty, an `ArtifactBecameVulnerable` event
— carrying exactly the new `(purl, vulnerability_id)` pairs and the
timestamp of the scan the artifact was previously clean under — rides
the same batch as the `ScanCompleted`. A first-ever scan never fires
it: "always was vulnerable, just discovered" is not a transition, and
the event exists precisely so operators can alarm on transitions.

### Failure is terminal, not silent

When *every* configured backend errors, the outcome is `Failed` and
the retry machinery takes over: exponential backoff (one minute, then
5, 30, 60) up to a retry budget (default 5, `HORT_SCANNER_MAX_ATTEMPTS`).
Exhausting the budget does not abandon the artifact — it transitions
it, before the job row is marked failed, to the terminal
`scan_indeterminate` status via
`QuarantineUseCase::record_scan_indeterminate`, recording a distinct
`ScanIndeterminate` event (deliberately *not* a zero-finding
`ScanCompleted`, which would be indistinguishable from a clean scan).
A `scan_indeterminate` artifact is non-downloadable, non-promotable,
and **not releasable by the quarantine timer** — only an admin
override or a post-exclusion re-evaluation can move it
([ADR 0007](../../adr/0007-fail-closed-quarantine-release-predicate.md)).
The ordering is itself fail-closed: a crash between the artifact
transition and the job update leaves the job retryable, never the
artifact silently un-failed.

The same fail-closed path absorbs a hostile scanner output. Both
scanner adapters drain the child process's report pipes through a
bounded reader (`drain_capped`, capped by
`HORT_SCANNER_MAX_REPORT_SIZE`); a report that exceeds the cap kills
the child and fails that backend with a distinguishable marker
(`SCAN_REPORT_TOO_LARGE_MARKER`,
`crates/hort-domain/src/ports/scanner.rs`) so the orchestrator can
attribute `result="report_too_large"` on the failure metric — and the
failure then flows through the normal retry-then-indeterminate route.
A runaway report can cost a scan; it cannot OOM the worker or sneak an
artifact past the gate.

## Rescan and advisory watch

A verdict decays: a clean artifact released yesterday can be the
subject of a disclosure today. Two periodic sweeps keep the pipeline's
output current, and both are deliberately *not* in-process timers. The
worker registers them as `TaskHandler`s; an external Kubernetes
CronJob (or operator host cron) fires them through the admin-task
endpoints `POST /api/v1/admin/tasks/cron-rescan-tick` and
`POST /api/v1/admin/tasks/advisory-watch-tick`
(`crates/hort-http-admin-tasks/src/lib.rs`). The server binary stays
scheduler-free — scheduling is the operator's infrastructure, where
cadence, suspension, and observability already live, and the binary
never needs leader election to avoid double-firing.

**The cron rescan**
(`crates/hort-app/src/task_handlers/cron_rescan_tick.rs`,
`CronRescanTickHandler`) is the safety net. Per tick it selects up to
1000 released artifacts whose policy-derived rescan interval has
elapsed (`ScanPolicy.rescanIntervalHours`, default 24, `0` disables)
and that have no in-flight scan, and enqueues each at priority 10 with
`trigger_source="cron"`. It is interval-driven and
advisory-independent: even if every feed went silent, every released
artifact still gets re-adjudicated on its policy's cadence.

**The advisory watch**
(`crates/hort-app/src/task_handlers/advisory_watch_tick.rs`,
`AdvisoryWatchTickHandler`) is the targeted path. It reads the
per-feed `last_sync_at` checkpoint, calls
`AdvisoryPort::pull_diff_since` to fetch every advisory modified since
then across the configured ecosystems, and joins each affected
`(ecosystem, name, versions)` triple against the local
`sbom_components` reverse index
(`SbomComponentRepository::list_artifacts_by_match`,
`crates/hort-domain/src/ports/sbom_component_repository.rs`) — the
projection that `record_scan_result` replaces transactionally on every
scan, keyed `(artifact_id, purl)`. Matches become priority-5
`trigger_source="advisory"` scan jobs. The checkpoint advances only
when **every** ecosystem's pull succeeded
(`AdvisoryDiffResult::all_ecosystems_ok`); partial failure preserves
the prior timestamp so the next tick re-attempts the missed window
rather than silently skipping it.

## The bulk-feed integrity posture

The advisory watch ingests the per-ecosystem OSV bulk archives
(`HORT_ADVISORY_OSV_BULK_URL`, defaulting to the OSV GCS bucket;
`crates/hort-adapters-advisory-osv/src/bulk.rs`). Transport is
TLS-verified through the shared `reqwest::Client::builder()` path with
the system trust store plus `HORT_EXTRA_CA_BUNDLE`
([ADR 0010](../../adr/0010-tls-builder-no-insecure-knobs.md)) — but
OSV publishes **no signed manifest and no per-archive hash** for the
bulk zips, so there is nothing for the adapter to verify the
decompressed advisory set against. The feed content is
trusted-but-unauthenticated: integrity rests on OSV's publishing
pipeline and the bucket/CDN operator, not on a cryptographic check
hort performs.

The pipeline's structure bounds what that residual can do. The watch
handler **only enqueues scan jobs** — it emits no domain events and
never rejects, quarantines, or releases anything; its entire write
surface is `JobsRepository::enqueue_scan` plus the checkpoint. A
rejection can only be produced by the scan-result path
(`record_scan_result` → `evaluate_scan_result` →
`ArtifactRejected`), which runs against the artifact itself. A
poisoned or injected bulk-feed entry therefore cannot, by itself,
reject a clean artifact — the worst it can do is trigger re-scans
of the artifacts it claims to affect, which is a queue-amplification
problem, not a verdict problem. The companion control is
observational: per-ecosystem diff-volume metrics
(`hort_advisory_diff_processed_total{ecosystem, result}`,
`hort_advisory_diff_duration_seconds`, and the
`hort_advisory_ingest_count` efficacy floor) let operators alarm on
both directions of feed compromise — an injection spike and a
suppression collapse — with the alarm recipe documented in
[server-and-worker-configuration.md](../reference/server-and-worker-configuration.md).
Suppression is the harder direction: a silent feed and a broken feed
are indistinguishable from the advisory side, which is exactly why the
interval-driven cron rescan exists independently of the watch.

## The score projection

Every scan-result commit threads a signed `ScoreDelta` into the same
transaction, maintaining the per-repository `repo_security_scores`
projection
(`crates/hort-domain/src/ports/repo_security_score_repository.rs`):
per-status artifact counts, cumulative finding-severity counts, and
the repository's most recent scan time. The read side is
`GET /api/v1/security-score` and
`GET /api/v1/repositories/:name/security-score`
(`crates/hort-http-admin-security/src/router.rs`) — an O(1) row read,
never an event-log scan. Queue health is a worker heartbeat: the
`hort_scan_queue_depth` gauge
(`crates/hort-worker/src/heartbeat.rs`) is the operator's signal that
enqueue rate has outrun drain rate, whatever the trigger source.

## Related pages

- [Security](security.md) — the supply-chain gate this pipeline feeds:
  `ScanPolicy` thresholds, `Exclusion` overrides, curation rules.
- [ADR 0007](../../adr/0007-fail-closed-quarantine-release-predicate.md)
  — the consumer-side release predicate, including the `ScanWaived`
  authority and why `scan_indeterminate` is terminal.
- [Format handlers](format-handlers.md) — the `FormatHandler` port
  `extract_sbom` lives on.
- [Content-addressable storage](cas-storage.md) — where findings blobs
  land, via the same enforced-CAS path as artifact bytes.
- [Event sourcing](event-sourcing.md) — the append/projection
  discipline behind the atomic scan-result commit.
