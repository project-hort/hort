# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Read verification is a binding contract, not a convention at two sites**
  (#341). The CAS-scrub classification fix under *Fixed* below made a
  read-verification failure carry a typed
  `CasIntegrityFailure { expected, computed }` verdict; nothing made the
  verification itself mandatory. The wrap was hand-written in two files, and a
  third storage adapter returning its backend's raw stream from
  `StoragePort::get` compiled, passed clippy and passed the whole suite — while
  violating no recorded decision, because ADR 0003 stated that reads are
  content-addressed without ever stating that a failure is distinguishable from
  an I/O failure or that it carries the digest the delivered bytes hashed to.

  **ADR 0003 gains that half** (2026-10-08 amendment): the shape is
  `CasIntegrityFailure`, its single production construction point is
  `VerifyingReader::poll_read`, and a consumer may rely on exactly three
  things — a clean EOF means the bytes hash to the key, a failure carrying the
  payload is at-rest corruption with `computed` as the observed digest, and a
  failure without one says nothing about integrity.

  **`crates/hort-app/tests/cas_reads_are_verified.rs` holds it structurally**:
  every `impl StoragePort for` under `crates/hort-adapters-*/src` constructs
  the verifier inside its own `get`. DB-free, sub-second, no allow-list, and
  function-scoped rather than file-scoped — which is load-bearing here, because
  both adapters carry a `get_range` doc comment naming `VerifyingReader` in
  order to say it does *not* apply there, so a file-scoped scan would stay
  green after the wrap itself was deleted. One assertion covers both halves of
  the contract because the verifier is the only production producer of the
  verdict; a counter-assertion pins the two known implementations by type and
  file, so renaming the port, the method or the reader cannot make the guard
  vacuously green.

  The scrub's own independent re-hash is unchanged and stays. With the guard in
  place it is belt-and-braces rather than the load-bearing defence — removing
  it is a separate decision that needs a measurement of what a full sweep
  costs, and this change supplies none.

- **A job row abandoned in `running` is recovered** (#306). A worker that died
  holding a claim used to leave its row on `status = 'running'` forever: both
  claim statements select `status = 'pending'` only, their `locked_until IS
  NULL OR locked_until < now()` clause re-claims a *pending* row whose
  not-before has passed and never looks at a `running` one, and nothing
  anywhere requeued or reaped. For four kinds that was not clutter but a lost
  capability — `jobs_scan_unique` is `(artifact_id) WHERE kind = 'scan' AND
  status IN ('pending','running')`, so the artifact became permanently
  unscannable *and* unrescannable, silently; `provenance-verify`, `prefetch`
  and `prefetch-dependencies` have the same shape via
  `find_active_provenance_for_artifact`, `jobs_prefetch_unique` and
  `jobs_prefetch_dependencies_unique`.

  Two halves. **Lease renewal**: `JobsRepository::renew_lease` plus a renewal
  task the dispatcher holds across `TaskHandler::run`, ticking three times per
  lease. `TaskDispatcher::dispatch_one` is the single point every registered
  kind runs through and `claim_pending_by_kinds` is the only claim statement
  with a production caller, so one call site covers the whole kind vocabulary
  and every kind added later. **The sweep**: `requeue_abandoned`, run inline on
  the dispatcher's poll loop every 60 s on every replica (no leader election —
  the picking CTE is `FOR UPDATE SKIP LOCKED`), returning `running` rows whose
  lease lapsed more than one further lease ago to `pending`. Migration `028`
  adds the partial index `jobs_abandoned_lease_idx ON (locked_until) WHERE
  status = 'running'` so the sweep does not seq-scan the highest-churn table
  in the schema.

  Renewal is what makes the discriminator derivable rather than guessed:
  before it, `locked_until < now()` meant both "the worker died" and "the task
  is slower than its 15-minute lease", and no per-kind grace multiple is
  correct for a kind with no upper bound on runtime. A live worker renews
  three times a lease however long its task runs, so a lapsed lease already
  means three consecutive renewals failed to land; the extra full lease of
  grace is the margin for a renewal that is alive but late (a lost database
  race, a paused container, a rolling upgrade whose older replicas do not
  renew at all).

  The sweep is also where the retry budget is spent **for a row whose handler
  never returned** — the scan orchestrator's `attempts >= max_attempts` branch
  and the dispatcher's `TaskOutcome::Failed` arms both require the handler to
  come back, so neither of them ever sees such a row. (The dispatcher's arms
  now spend the same budget on the rows they *do* see; see *a returned failure
  becomes terminal* below.) A row at the attempt cap is failed terminally
  instead of re-driven; for `kind='scan'` that hands the artifact to the
  existing stranded-scan recovery, whose predicate is a newest scan job in
  `failed`. Rows are never deleted: a late
  completion from the original worker is an unconditional `UPDATE … WHERE id`
  and must still find a row. `attempts` is left alone by the sweep — the next
  claim charges it, exactly as for a `reschedule`d row.

  Which kinds are requeued is a decision per kind, not a default:
  `REQUEUE_ON_LEASE_EXPIRY_KINDS` / `NO_REQUEUE_ON_LEASE_EXPIRY_KINDS` in
  `hort-domain`, exhaustive over `EVENT_TASK_KINDS` under a guard test, each
  carrying its reason. The seven excluded kinds are excluded because a
  concurrent second execution of them is absorbed by nothing —
  `eventstore-archive` most sharply, whose unbounded `StreamSealed` append is
  safe only while at most one `seal_and_remove` is in flight cluster-wide and
  one of the three layers delivering that is a *per-process* semaphore — and
  the exclusion is free because none of them appears in an in-flight
  uniqueness predicate, so their next scheduled tick is the recovery. A renewal that
  reports the row is no longer this worker's is a **fencing token**, not just a
  log line: the dispatcher discards that handler's outcome rather than writing
  over the row's current holder, because the damaging write is not the lost
  result but a `reschedule` returning a row a live worker is mid-way through to
  `pending`. New metrics `hort_admin_tasks_lease_requeued_total{kind, result}`
  (worker health) and `hort_admin_tasks_lease_renew_failed_total{kind, result}`
  (the fence — one `lost` is one execution whose result was discarded).

- **`public.jobs` gets a general horizon, and the newest state row per kind
  survives it** (#297). New `jobs-row-retention-sweep` task kind (migration
  `027`, default-enabled daily CronJob at 03:30 UTC,
  `scheduledTasks.jobsRowRetentionSweep`) deleting terminal
  (`status IN ('completed', 'failed')`) `jobs` rows older than a configurable
  horizon (default 7 days) for every kind the two existing kind-specific
  sweeps do not reach — `kind NOT LIKE 'prefetch%' AND kind NOT IN ('scan',
  'oci-index-child-ingest')`. Nineteen of the twenty-five allow-listed kinds
  had no horizon at all; the highest-churn of them, `staging-sweep`, adds
  ~288 terminal rows a day at its five-minute cadence, and a production count
  found ~83,000 unreclaimed terminal rows.

  The sweep retains, per kind, **two** rows: the newest `completed` row and
  the newest terminal row. Retaining only the newest terminal row is not
  enough — both `last_completed_at_by_kind` (the boot-time
  `hort_staging_sweep_overdue` and `hort_event_chain_verify_overdue` gauges)
  and `last_result_summary_by_kind` (the `prefetch-tick` rotation cursor)
  filter `status = 'completed'`, so a kind whose newest terminal row is a
  failure would lose the `completed` row underneath it and report as having
  never run. The kind exclusions keep exactly one horizon in force per kind:
  a second sweep over the same rows would silently win whenever its horizon
  were the shorter of the two. Non-terminal rows — including a row abandoned
  in `running` by a crashed worker — are never deleted: an expired claim lease
  does not distinguish a dead worker from a task slower than its lease, so
  recovering those is a requeue rather than a retention concern.

- **A denial records which leg denied it** (#239). `RbacEvaluator` gains
  `authorize_explained`, returning `AuthzDecision` — `Allowed`,
  `DeniedGrants`, `DeniedCap`, `DeniedBoth` — beside the unchanged `authorize`
  predicate, which now delegates to it. Both legs of the cap-intersection AND
  were already evaluated unconditionally, so which one failed was computed and
  thrown away on every deny.

  Two structurally different faults used to produce one indistinguishable
  signal: an identity with no grant, and an identity that holds the permission
  presenting a token whose cap excludes the repository. They have disjoint
  remediations — declare a `PermissionGrant` versus widen or re-mint the token
  — so a configuration correct in gitops could stay unreachable with nothing
  saying why. The deny log now names the measured leg (`denial_reason`) and its
  hint states which surface is at fault *and* which is exonerated, in place of
  the "check both the token's scopes and the grant table" checklist it could
  only offer while the evaluator returned a bare `bool`. A CLI session is told
  to re-login with `--admin` only when the cap is genuinely what denied; an
  identity holding no admin authority is no longer sent on a mint that would
  be refused.

  New counter `hort_authz_denials_total{permission, reason}` with
  `reason ∈ {grants, cap, both}`, deny-only and with no `repository` label.
  `hort_authz_decisions_total` is unchanged and remains the complete decision
  count: the composite curate-or-admin gate evaluates two permissions and
  denies on the pair, so it emits no `reason` rather than an invented
  `unknown` one, and reports both decisions on its log line instead.

  The caller-visible contract is untouched — a cap reject and a missing grant
  still return the same status, since distinguishing them would disclose that
  an identity's grants are broader than the presented token's cap.

- **`hort-cli admin retention preview` / `apply` — the surface a cleanup
  actually happens on** (#289). `preview` runs the dry run, waits for it, and
  renders it for a person: rows and distinct stored contents named as the
  different quantities they are, the measured bytes that would be freed — or the
  words `NOT MEASURED` and the server's reason, never a number the server did
  not measure — a capped sample so the selection can be checked, and partial
  coverage stated in the header rather than a footnote. Repositories are named
  by the key an operator writes in a policy, not by UUID.

  `apply` re-runs the preview immediately before executing and shows the
  difference to the one it was pointed at, per figure and per group. When
  anything moved, it asks twice: once to confirm the difference was read, once
  to execute. Declining either exits without sending the execution. `--yes`
  skips the questions and still prints the difference. Both commands work with a
  fresh admin CLI session and need no new authority — a preview requires no
  destructive claim at all, an execution still does. `--output json` carries the
  same information, including the omission status and the coverage flag.

  Both commands state plainly that expiry marks artifact records and does not
  itself delete stored bytes; the separate purge reclaims a blob once its last
  reference is gone.

- **A retention policy can be previewed before it takes anything** (#283).
  `retention-evaluate` gains a dry-run mode that draws the same candidates
  through the same reader and the same predicates, appends no `ArtifactExpired`,
  advances no projection field, and writes its finding into its own job's
  `result_summary`. It is the same code path with one branch, not a second
  evaluator, so the preview cannot drift from the action it predicts. The mode
  defaults to execute, so a deployment that sends no mode behaves exactly as
  before.

  The report gives rows per policy and repository, distinct content hashes —
  rows are not bytes — a capped sample so the selection can be checked rather
  than a total believed, and the bytes that would actually be freed. That figure
  is **simulated, never estimated**: a blob falls only when its reference count
  reaches zero across the whole candidate set, so the simulation reproduces the
  purge's edge set term by term, including the OCI membership edges, and
  excludes any target a surviving artifact still references. Where the candidate
  set exceeds the simulation's bounds, or a size lookup fails, the figure is
  reported as **omitted** with a reason — against 142 GB, a plausible wrong
  number is worse than none.

  Preview and execution are independent jobs at **both** idempotency layers: the
  server-derived per-day key carries the mode, and the ephemeral
  `Idempotency-Key` cache now records what its entry was issued for, so the same
  header sent for a preview and an execution no longer returns the preview's
  job. `hort-cli`'s window-derived key carries the mode too — it is the normal
  path, and without it the shipped CronJob and an operator's preview would
  collide by construction. A preview needs no destructive claim; an execution
  still does, checked both at the HTTP boundary and inside the use case.

### Changed

- **The gitops YAML parser is `serde-saphyr`, and an operator's file means what
  it meant** (#347). The control path's envelope parse ran on a crate binding
  `unsafe-libyaml`, an unmaintained C transliteration carrying
  RUSTSEC-2024-0449 with no fixed version. It now runs on `serde-saphyr`, pure
  Rust and maintained. Every parse in `hort-config` goes through one call path
  with one options value, so the gitops parse has a single definition rather
  than one per call site.

  **The swap was configured to preserve semantics, not to take the opportunity
  to change them.** Strict booleans (only `true` / `false` resolve to a
  boolean, so `requireApproval: no` is still refused), merge keys as ordinary
  keys (`<<` is still an unknown field to a strict spec and still ignored by a
  spec struct without one), and no source echo in a rendered parse error are
  all pinned deliberately. A duplicate mapping key is refused, which the
  previous parser only did for keys naming a declared struct field — see
  *Security* below.

  **Operator impact.** Four behaviours differ, and a tree that parsed before
  parses now unless it relies on one of them:

  - **`quotaBytes: 1_000` now parses as `1000`.** A digit separator in an
    integer field used to fail the boot. There is no option that restores the
    rejection; the field is typed and the value is the one the grouping spells.
  - **Numeric scalars in an untyped position are now YAML-resolved.** The only
    such position is `ScanPolicy`'s `spec.licensePolicy`, a free-form map:
    `1_000` there becomes the number `1000` and `0755` becomes the float `755`,
    where both used to stay text. A YAML 1.1 boolean word there is
    **unaffected** — a bare `yes` stays the string `"yes"`, because strict
    booleans reach untyped positions too. Bounded today by the apply-time
    rejection of any `licensePolicy` richer than `null` / `{}`.
  - **One anchor backing 100 or more aliases is now rejected**, by a default
    alias-to-anchor budget the previous parser had no equivalent of (99 aliases
    on one anchor still parse). No checked-in gitops envelope uses an anchor at
    all. A tree that leans on a single heavily-reused anchor must spell the
    repeated value out or split it across anchors.
  - **Parse-error text changed.** A rejection now carries `at line N, column M`
    and no longer carries the serde field path (`spec.proxy: unknown field …`
    reads `unknown field \`usernme\`, expected one of … at line 13, column 5`),
    and a type mismatch names only the expected type rather than the value
    received (`invalid i64`, not `invalid type: string "notanumber"`). The
    offending field is still named in both. Log matching on the old field-path
    prefix needs updating; matching on the field name does not.

- **One authority owns the manual release: the curator** (#345). Releasing a
  held artifact by hand used to be two surfaces for one transition — an
  admin-gated `POST /api/v1/admin/quarantine/<id>/release` with
  `hort-cli admin quarantine release`, and the curator's
  `POST /api/v1/admin/curation/quarantine/<id>/waive` with
  `hort-cli curation waive`. They differed in exactly three things: the
  permission, the source state the curator's half refused
  (`ScanIndeterminate`, the stuck-scanner case), and the `released_by`
  discriminator. Effect, attribution, the event type and re-blockability were
  identical.

  **The admin route and CLI command are gone, and the curator's reach is
  wider.** Admin serves technical and operative actions; the curator holds the
  domain's authority, so the curator who may override findings a policy
  weighed may also act where no verdict was reached at all. `hort-cli curation
  waive <artifact_id> --justification '…'` now releases a `Quarantined`
  **and** a `ScanIndeterminate` artifact. `Rejected` stays terminal for it, and
  answers `409` as before (ADR 0025).

  **Operator impact.**

  - Replace any `hort-cli admin quarantine release <id> --justification '…'`
    with `hort-cli curation waive <id> --justification '…'`, and any
    `POST /api/v1/admin/quarantine/<id>/release` with
    `POST /api/v1/admin/curation/quarantine/<id>/waive`. There is no alias and
    no deprecation shim: the removed route answers `404`. One path is the
    point — a second surface is what this change removes.
  - **The release counter follows.** `hort_quarantine_released_total` now ticks
    `reason="curator"` for every manual release and no longer ticks
    `reason="admin"` — a curator waive previously incremented nothing on it, so
    an alert on total releases was under-counting manual ones. Historical
    `admin` series are untouched and still queryable: the series stops growing,
    it is not deleted. A rule that wants every manual release across the
    retention window should match `reason=~"curator|admin"`.
  - **The read that grounds the decision moved with it.**
    `GET /api/v1/admin/quarantine/patch-candidates` and
    `hort-cli admin quarantine list-patch-candidates` now accept
    `Permission::Curate` as well as `Admin`, so the four commands of the
    patch-release playbook run start to finish on one curator token. The path
    and the command name are unchanged. A denied request on that route no
    longer contributes to `hort_authz_denials_total` — the curate-or-admin gate
    produces two decisions and one denial, so no single `reason` label would be
    truthful; a dashboard keyed on its `permission="admin"` denials will read
    zero.
  - **No credential change is needed.** The waive gate is `Permission::Curate`
    **or** `Permission::Admin`, so an admin token that worked on the old route
    works on the new one. A `curate` grant is the narrower credential, and
    granting it to CI stays refused on the record (ADR 0055).
  - `hort-cli admin quarantine` keeps `list-patch-candidates`; only the
    `release` subcommand is gone. The patch-candidate queue is still the
    review surface — the release that acts on a listed row is now the waive.
  - **The break-glass admin-token procedure is retired.** The public
    supply-chain runbook's `ScanIndeterminate` case used to require minting a
    DSN-gated, ≤1 h `bootstrap-session` admin token, releasing, and revoking
    it. The standing `maintainer-curator` credential now covers that state, so
    the procedure is deleted rather than re-pointed, and the deployment still
    holds no standing full-admin token (ADR 0013).
  - **Nothing on the audit trail is rewritten.** The stream is append-only
    (ADR 0002): `ArtifactReleased { released_by: Admin }` events written before
    this change still read back as manual, human-attributed releases, and a
    fresh scan verdict still cannot re-block an artifact one of them released.
    `ReleaseReason::Admin` keeps its place in the vocabulary with no path that
    mints it; new manual releases record `Curator`. A dashboard or SIEM query
    that filters on `released_by = 'admin'` will stop matching new events and
    should also accept `curator`.

  Decision and rationale: ADR 0007, *"One authority owns the manual release"*.

- **A returned failure becomes terminal at the attempt cap** (#341). The task
  dispatcher called `reschedule` for every `TaskOutcome::Failed { retry: true }`
  and every handler `Err`, without consulting `job.attempts` and without
  consulting the kind. `compute_backoff` bounded the *delay*; nothing bounded
  the count. A job that failed the same way forever was re-driven forever and
  never became the persistent, operator-visible `failed` row ADR 0028
  describes to the operator — and for the destructive kinds the same accepted
  job re-ran inside the same UTC day, because the day-unique key bounds a
  second *enqueue* and not re-executions of the row that already exists.

  The dispatcher now spends the same five-attempt budget the abandoned-lease
  sweep and the scan orchestrator already shared, through the terminal
  transition it already had for `retry: false`: at the cap the row is
  `mark_failed` with the handler's own reason, counted as
  `hort_admin_tasks_completed_total{result="failed_terminal"}` and logged at
  ERROR with `attempts` and the cap. The budget is **uniform across kinds** —
  a returned failure has no in-flight duplicate to fear, because the handler
  returned, which is the question the sweep's kind list answers and this path
  does not have to. No new configuration.

- **A failing job's five attempts now span 96 minutes, not seven and a half**
  (#341). The dispatcher's attempt cap gave a `jobs` row five executions; its
  own backoff curve — 30 s, doubling — spent all five inside **7 m 30 s**. The
  scan orchestrator spends the *same five attempts* over 96 minutes, so one
  agreed number meant two windows an order of magnitude apart, and nothing in
  either file made the disagreement visible. Any failure mode outlasting eight
  minutes ended a row terminally: harmless for the tick kinds and the prefetch
  family, where the next tick or pull re-derives the work, intended for the
  destructive kinds, and permanent for the one-shot kinds that nothing
  re-enqueues (`seed-import`, `wheel-metadata-backfill`,
  `oci-membership-edge-backfill`, `service-account-rotation`,
  `eventstore-checkpoint`) — a ten-minute database hiccup ended those until an
  operator noticed.

  The dispatcher now waits out **the scan pipeline's own curve — 1, 5, 30, then
  60 minutes** — which is the same ~96 minutes for the same five attempts.
  Matching the shape and not merely the span is the point: a different shape
  reaching a similar total is exactly how two curves hid behind one shared
  number. No new configuration (ADR 0016), no per-kind curve, and the attempt
  cap is untouched at five.

  **The curve now has one definition**, `hort_app::retry_backoff::compute_backoff`,
  called by both the dispatcher and the scan orchestrator; the duplicate in
  `scan_orchestration` is gone. The unreachable 24-hour delay ceiling went with
  it — reaching it needed about twelve attempts, so it could not fire once the
  chain was bounded at five, and the four-step curve's flat last arm caps
  itself at 60 minutes by construction. The attempt budget, not a delay
  ceiling, is what ends a retry chain.

  What an operator sees: the first retry of a failed job moves from 30 s to
  60 s, and a persistently failing row sits in the jobs table with a growing
  retry delay for about an hour and a half before it goes `failed`, where it
  previously went `failed` in under ten minutes. The number of executions does
  not change.

- **`HORT_RETENTION_STREAM_MODE=archive` is refused at startup while no
  cold-storage writer exists** (#333). Both `hort-server` and `hort-worker` now
  fail config parsing on the value, with a message naming the deferred
  cold-storage write and `delete` as the way forward.
  `HORT_RETENTION_ARCHIVE_TARGET` is no longer consulted — no target could have
  made the mode archive anything, so demanding one first only walked the
  operator through a fix that changed nothing. `delete` and an unset variable
  are unchanged.

  The mode was not inert; it was mislabelled, which is the `UnusedFor` fault
  below rather than the milder `maxAgeDays` one.
  `PgEventStore::archive_stream` runs the same `DELETE FROM events WHERE
  stream_id = $1` as the delete path and carries the archive target no further
  than one `tracing` field — no INSERT, no copy, no cold-storage write — after
  which the sweep increments its `archived` counter and logs "stream sealed +
  archived". An operator who selected `archive` to *keep* audit events was
  having them removed and told they were kept. The existing non-empty-target
  requirement was justified in-tree as stopping a "silent degradation to delete
  = data loss"; that degradation was happening anyway, with the target set.

  `hort_event_store_streams_archived_total{result="archived"}` is consequently
  never emitted by a shipped deployment; the label value and the `Archive`
  routing stay in place for the change that gives the mode a real writer.

- **Retention policies using `HasFixAvailable` now expire matching artifacts**
  (#323). The scan findings projection now preserves advisory fix versions, so
  policies that previously did nothing can take effect without an operator
  change. Findings recorded before this change read as "no fix" until their
  artifact is rescanned; the scheduled rescan closes that gap over time.

- **`UnusedFor` is refused at gitops apply while no usage signal exists**
  (#299). A `RetentionPolicy` whose predicate uses `UnusedFor` — at the root
  of `spec.predicate` or nested anywhere inside a `Composite` — is now
  rejected by the apply-config linter and by the offline `hort-server
  validate-config` gate, with an error naming the policy, the reason, and
  `AgeExceeds` as the alternative.

  The predicate was not inert, which would have been the milder ADR 0015
  fault; it was mislabelled. No port supplies a last-download anchor, so the
  retention evaluator is handed `last_downloaded_at: None` on every artifact
  and its `None` arm measures the interval from the creation time —
  `UnusedFor(N)` decided exactly what `AgeExceeds(N)` decides. An operator
  writing `UnusedFor(90d)` was making a decision about usage and silently
  getting one about age, which on a hosted repository inverts the intent: a
  year-old artifact pulled daily is the last thing "unused" should reach and
  the first thing "old" does.

  New `hort_apply_config_linter_total` rule key
  `retention_unused_for_not_implemented`, one increment per offending
  envelope. The `UnusedFor` variant, `ExpirationReason::UnusedTtl` and the
  evaluator arm are unchanged — the rejection is the operator surface only,
  and it is retired in the same change that gives the evaluator a real
  last-download anchor.

- **The retention dry-run's byte accounting probes storage concurrently**
  (#293). The `freed_bytes` simulation issued one `StoragePort::size_of` per
  reclaimable target, one at a time. On a filesystem CAS that is a `stat`
  (5.5 µs, measured); on an object store it is an HTTP `HEAD`, so a preview at
  the 128 000-target ceiling cost 128 000 serialised round trips — over half an
  hour against a store answering in 15 ms, which is why the instances that most
  need the figure were the ones reading `freed_bytes: omitted`. The probes now
  fan out 64 at a time: 48.9× measured against an object store in the
  latency-dominated regime a real S3 sits in, 4.3× against a filesystem CAS.

  The width is a measured constant rather than a round one. The adapter's HTTP
  client imposes no ceiling of its own — `object_store`'s `ClientOptions`
  leaves `pool_max_idle_per_host` at `reqwest`'s `usize::MAX`, holds idle
  connections for 90 s, and pins `http1_only`, so one in-flight probe is one
  socket and a wider fan-out buys sockets rather than backpressure. The width
  is therefore sized to what the shipped worker's guaranteed CPU share can keep
  fed, with the measurement recorded beside the constant.

  **Visible only on a failing preview:** when more than one thing goes wrong,
  the reason is now ranked rather than raced — concurrently, "the first error"
  is a property of the scheduler. A failed probe outranks an overflowing total,
  because a sum missing an addend cannot be claimed to have overflowed. The
  outcome is unchanged: `omitted` with a reason, never a partial sum dressed as
  `exact`. `MAX_SIMULATION_TARGETS` is unchanged.

- **A `RetentionPolicy` scope names repositories, and a declared retention
  policy now actually applies** (#282). The `repos` scope carried repository
  **UUIDs** at the gitops surface — a form that contradicts every other
  reference in that tree and stops meaning anything the moment an instance is
  rebuilt against a fresh database, so the one scope a first cleanup needs could
  not be authored at all. It now carries `metadata.name` values, mirroring
  `ScanPolicy`: the apply resolves each name to an id exactly once, through the
  same map and under the same ordering guarantee, and a name that is not
  declared in the same desired state is rejected before anything is written,
  with the offending value named. The UUID form is gone rather than kept
  alongside — a tree still writing ids fails the declared-repository rule.

  The half that made all of this moot is also closed: the retention apply slot
  was never wired into the composition root, so every `RetentionPolicy` envelope
  was parsed, validated, logged as skipped, and dropped. It is now wired, and
  the slot is a required argument rather than an opt-in builder — the failure
  was omission by inheritance, so omission is now a compile error. A composition
  that genuinely has no projection still says so explicitly and still warns on
  every envelope it skips.

  **Operator action:** write `scope: { Repos: [<metadata.name>, …] }`. Nothing
  in a shipped configuration changes, because no retention policy could take
  effect before this.

### Fixed

- **An artifact whose findings the policy did not block is released** (#344).
  `ScanCompleted` carrying a non-empty finding list set `rejected` terminally,
  whatever the `PolicyEvaluated` verdict recorded beside it said — so a
  repository whose policy admits low-severity findings never released the
  artifacts those findings belonged to, and the only way out was an admin
  override. The finding list is evidence; the policy verdict is the decision.
  The release gate now derives its authority from **one** pure function that
  the fast path and the quarantine sweep share, and that function answers with
  the authority it actually checked: the new `ScanCleared` (findings exist, the
  verdict passed) beside `ScanSucceeded` (a finding-free scan), `ScanRecorded`
  (`enforcement: record`), `ScanWaived` (no scan backend configured *and* no
  observation standing), and the three manual authorities. A release the timer
  or a policy re-evaluation granted stays re-blockable by a later retroactive
  verdict; an admin or curator release does not, because a human weighed the
  same evidence. `MockEventStore` now validates on append like the production
  adapter, which is what made the divergence visible: the corpus behind the old
  agreement held `ScanCompleted` events no producer in the system can write.

- **The CAS scrub classifies a real hash mismatch as a mismatch** (#341). Both
  production storage adapters wrap every `get` in a streaming verifier, so a
  corrupted blob failed the read at EOF before `CasScrubUseCase` could finish
  its own re-hash. The scrub filed that as `read_errors`, which the CLI
  documents and pins as observability-only — so `hort-server scrub` **exited
  `0` over a present corrupted object**, the configured
  `HORT_CAS_SCRUB_ACTION_ON_MISMATCH=tombstone` response never ran, and the
  `CasIntegrityMismatch` audit event was never written. The scrub's own
  mismatch branch was reachable only through a reader that does not verify,
  i.e. not in the shipped composition at all; the test that appeared to cover
  it drove a test double handing back raw wrong bytes.

  The verifier's verdict now travels as data. A verifying read fails with an
  `io::Error` carrying a `hort_domain::ports::storage::CasIntegrityFailure`
  (`expected` + `computed`), and the scrub classifies from it: a corrupted blob
  is a `hash_mismatch` carrying the observed digest, emits
  `CasIntegrityMismatch`, and reaches the tombstone transition when the
  operator configured one. A read failure that carries no verdict stays a
  `read_error` — the discriminator is the typed payload, not
  `io::ErrorKind::InvalidData`, which a backend may raise for its own reasons
  and which cannot produce the observed digest the audit record needs.

  **The exit-code posture is unchanged**: `mismatches > 0` escalates and
  `missing` / `read_errors` / `shards_truncated` still do not. That decision
  was only ever unsafe because corruption was landing in `read_errors`.

  The scrub keeps hashing the bytes itself as well. It is not redundant with
  the verifier: it is the only check that survives a `StoragePort` that does
  not verify, because a verifier cannot detect its own absence. The test double
  (`MockStoragePort::inject_tampered`) now honours the production read contract
  — wrong bytes, then an EOF failure carrying the computed digest — so a future
  regression cannot pass the suite the way this one did; the non-verifying
  shape remains available as a separate, explicitly-named hook for the one test
  that needs it.

  This restores **one** of the two controls the standing CAS-integrity
  acceptance rests on. The serving path is still open: same-length corrupted
  bytes can complete as a successful HTTP/1 download because the verifier only
  fails on a later EOF poll.

- **The publish kill switch refuses the publish, not merely its body** (#341).
  With the switch reaching all four hosted formats, the refusal itself was
  still `DefaultBodyLimit::max(0)` — which rejects a body that has bytes in it
  and admits one that does not. A Maven `.jar` `PUT` has no envelope that
  could fail on empty input, so a zero-byte publish with the switch on was
  **ingested**: an artifact row, an `ArtifactIngested`, a quarantine timer and
  a scan job, out of a gate the operator believed shut. Cargo, npm and PyPI
  refused the same request only as a side effect of their payload grammars
  rejecting an empty envelope — a property of those grammars, never a promise
  the limit made. `413 Payload Too Large` was also simply the wrong answer: on
  a 0-byte request it tells the client something untrue.

  A zero limit is now an explicit administrative hold, defined once in
  `hort_http_core::limits::refuse_publishes_when_disabled` and applied by each
  publish subtree. It answers **`503 Service Unavailable`** — this project's
  recorded answer for "not serving this right now" — with **no `Retry-After`**,
  because the hold has no deadline to quote (it ends when the operator changes
  the configuration); the response body says so instead of a header implying
  otherwise. The guard discriminates by **method**, not by route tree: `GET` /
  `HEAD` keep serving artifacts while the switch is on, and `DELETE` keeps
  working so a client can still cancel an upload session it cannot finish. An
  over-size body against a configured non-zero ceiling is untouched and still
  `413`, through the body limit, as a deliberately separate path.

  **The switch now also closes the OCI push path** — the blob-upload
  `POST`/`PATCH`/`PUT` dance and the manifest `PUT` — because the same
  method-discriminating guard covers it; only a *size* leaves OCI alone (its
  upload path bounds each chunk through its own session accounting). The
  `/v2/*` refusal is served in the OCI Distribution `errors`-array envelope
  (`UNAVAILABLE`), so docker and the containerd resolver surface the message
  rather than an unexplained 503. `values.yaml`, `values.schema.json`, the
  values and configuration references, the security explanation and the
  add-a-format-handler how-to now describe this reach, and no operator-facing
  sentence claims "all four" any more.

  Observable changes beyond the Maven ingest: npm's and PyPI's limit-`0`
  refusal moves from `413` to `503`, cargo's from `413` to `503`, and an npm
  dist-tag `PUT` — whose own small per-route body limit previously won over
  the router-wide one — is now held with the rest (a dist-tag write retargets
  what `npm install` resolves to).

- **The documented publish kill switch now reaches every hosted format** (#341).
  `HORT_PUBLISH_BODY_MAX_SIZE=0` is documented — in the chart values, in the
  configuration reference, and in the parser's own rationale for not rejecting
  zero like every other optional size knob — as an explicit "refuse all
  publishes" switch. The composition root handed the parsed value to npm and
  PyPI only: cargo applied its own fixed 200 MiB ceiling and Maven hard-coded
  the shared 300 MiB *default constant* on its PUT, so an operator who set `0`
  during an incident closed two of the four hosted publish surfaces and left
  cargo and Maven open, with nothing saying so. A kill switch that cannot be
  trusted is worse than none: it changes what the operator does next — they
  stop looking for another way to halt writes.

  The fix splits the knob's two meanings and changes only the second. A
  **size** now reaches Maven as well (it had no recorded reason to ignore the
  override and already reached for the shared default), while cargo keeps its
  fixed 200 MiB ceiling against any non-zero value — the recorded decision
  that tuning the shared variable for Python wheels must not silently move
  cargo's ceiling, which is about magnitude and still holds. **Zero** now
  reaches all four, because zero is not a different ceiling. The split lives in
  one place, `hort_http_core::limits::cargo_publish_body_limit`, and both
  remaining formats gained the `*_routes_with_publish_limit(limit)` +
  `*_routes()` pair npm and PyPI already had. Refusal was still the existing
  body-limit path (`413`) on all four at this point — the next entry replaces
  it, and also extends the switch's reach to the OCI push path.

- **A stored quarantine status the domain cannot parse no longer decodes to the
  most permissive one** (#334). `artifacts.quarantine_status`'s CHECK accepts
  seven values; `QuarantineStatus` models five, and the adapter stores `None`
  as SQL `NULL` rather than as a literal — so three prototype-era spellings
  (`unscanned`, `clean`, `flagged`) were schema-legal and unparsable, and the
  domain's `none` was unstorable. The row mapper resolved the disagreement by
  discarding the parse error and substituting `QuarantineStatus::None`: at once
  the most permissive state in the system — `Artifact::is_downloadable` admits
  it, and the default `ReleasedOnly` index mode serves it — and a state the
  column cannot hold. A schema-valid `unscanned` row was therefore **advertised
  by the index and served on download** with no release authority behind it and
  no `ArtifactReleased` in its stream, and the mapper's own unit test asserted
  `'unscanned' -> None` as correct. The same substitution sat on the two hot
  index-serve reads (`package_version_status`, `package_version_anchors`), and
  again on the npm / PyPI / cargo **proxy** index sources as
  `unwrap_or_else(… Vec::new())` — "degrade to no status known", which under
  `IncludePending` re-advertises every version hort is deliberately holding
  back, because the filters there drop only what hort *knows* is non-servable.

  The column now has exactly one codec
  (`hort_adapters_postgres::quarantine_status_sql`), encoder and fail-closed
  decoder as an inverse pair: `NULL` is the stored spelling of `None` and the
  only input that decodes to it; anything else that does not round-trip is a
  `DomainError::Invariant`. A read that cannot classify an artifact no longer
  produces a classification — the request fails instead of serving. The same
  decode now backs the purge-GC mapper, which had been collapsing the three
  legacy spellings to "not GC-protected" on its own. Migration
  `030_artifacts_quarantine_status_legacy_backfill.sql` replaces the spellings
  in the data with the **held** state — `'quarantined'` plus a
  `quarantine_window_start` anchor derived from `created_at` — because a
  spelling the domain cannot classify means no scan verdict is on record, and
  the fail-closed reading of that is a hold rather than "nothing holds it".
  Writing `NULL` would have handed the affected rows back the permissive
  `QuarantineStatus::None` the new codec exists to deny them. `'quarantined'`
  rather than a terminal state because nothing incriminating is known about
  such a row: the stranded-rescan sweep (`select_stranded`) admits a
  `'quarantined'` artifact with no scan job, so the hold resolves itself once a
  verdict exists, which `'rejected'` and `'scan_indeterminate'` — both never
  auto-rescanned (ADR 0007) — would not. The anchor ships in the same statement
  because the release sweep's candidacy filter requires it; without it the hold
  would have no exit but an admin override. Affected rows stop being downloadable
  and stop being advertised, by the old fleet as well as the new one during a
  rolling upgrade — a deliberate availability change, since a legacy spelling the
  CHECK happens to accept is not an operator opt-out of the hold. Narrowing the CHECK to
  the storable set is a contraction under
  [ADR 0030](docs/adr/0030-sensitive-surface-structural-guards.md) and is
  scheduled for **0.14.2**, recorded under "Scheduled contractions" in
  `migrations/CONTRACTIONS.toml`. The structural guard
  `crates/hort-app/tests/status_decode_fails_closed.rs` — a sibling of
  `db_gate_not_silent`, which already refuses a discarded error on a Postgres
  connect for the same reason — rejects a discarded error on any
  quarantine-status read or decode across `crates/`, and carries a
  counter-assertion so a rename cannot make it vacuously green.

- **A `ScanPolicy` scoped to a repository no envelope declares is now rejected
  instead of crashlooping the pod** (#334). The apply pipeline resolves
  `scope: { repository: <name> }` to a repository id through a map built from
  the *declared* repositories, and treats a miss as an invariant violation —
  but nothing rejected an undeclared name: such a bundle passed the whole
  pre-write validation and then **panicked** in Stage 2. A panic is not a
  `GitopsBootError`, so the boot path could not park the pod not-ready on it;
  it crashlooped, and it did so after Stage 1 had already written. The trigger
  was a typo in a scope name. Cross-document validation carried the sibling
  rule for a `RetentionPolicy` scope, an `UpstreamMapping`'s repository, an
  `Exclusion`'s parent policy and a `PermissionGrant`'s repository and service
  account — and none for a `ScanPolicy`'s own scope. It now rejects the bundle
  before the first write with a dangling-reference error naming the policy, the
  field and the missing repository, identically from the boot preflight and
  from `hort-server validate-config`. A scope naming a declared repository
  applies exactly as before, including one declared in the same bundle. The
  panic stays where it is: with the rule in place it asserts an invariant the
  admission boundary already excludes.

- **A gitops bundle is no longer half-applied when a late check refuses it**
  (#334). The apply pipeline validates in stages and writes between them, and
  it ships no rollback, so any rejection raised from a stage left a partial
  apply behind. The reachable bad state was a refused *tightening* beside a
  committed *loosening* from the same bundle: a `PermissionGrant` the grant
  linter rejects, applied together with a `ScanPolicy` that drops
  `requireApproval` and moves `enforcement` to `record`, failed the apply —
  with the loosened policy already live and the grant never written. The
  operator's `apply` looked atomic and was not atomic at exactly the security
  boundary.

  Two checks were reachable only after a write, for two different reasons.
  The permission-grant linter (single-claim, wildcard-repo-non-admin,
  unjustified high-privilege direct-user, reserved-claim-name collision) ran
  inside the final grant stage, behind the repository, policy and mapping
  writes — although the rule already existed in the snapshot-free validator
  the offline `hort-server validate-config` uses, and its verdict is provably
  invariant to the resolved database ids. It is now consumed in the pre-write
  pass, so the rejection happens before the first write; the grant stage keeps
  its gate over the port-resolved set as defence-in-depth, and keeps being the
  single emitter of `hort_apply_config_linter_total`. The three TLS-material
  invariants on `kind: UpstreamMapping` (an mTLS pair must be complete, any
  TLS field requires an `https://` upstream, `pinnedCertSha256` must be 64
  lowercase hex characters) existed only in the domain constructor, which
  gitops reaches in its third stage; they are now also per-spec validation
  rules, which both the boot preflight and `validate-config` run. A custom CA
  alone, a pin alone and the full https combination stay accepted — the
  mirror matches the constructor's rejection set exactly.

  Which configurations are rejected is unchanged; only when. On the boot path
  the earlier rejection is also the difference between parking the pod
  not-ready (`GitopsBootError::PreflightValidate`) and crashlooping on a tree
  that has been partly written. The claim that no rejection is reachable only
  from a write-capable stage is now two tests rather than a comment: an
  exhaustive, wildcard-free match over every lint rule asserting the
  pre-write pass consumes each rejecting one, and a per-stage corpus
  asserting the preflight refuses every bundle a stage would.

- **A lifecycle decision can no longer be committed over a newer verdict**
  (#334). Several call sites derived an artifact's outcome from stored
  evidence and committed it behind an optimistic append, reading the
  expected stream version *after* deriving the decision. A verdict that
  committed in that window is already contained in the version just read,
  so the append does not conflict: it succeeds, and the paired projection
  write puts the stale decision's status over the newer one. In the loosen
  direction that released an artifact on scan evidence a later scan had
  already superseded; in the tighten direction it re-held an artifact over
  a clean verdict that landed after the evidence was read. The window was
  as long as whatever sat between the two reads — a policy and
  exclusion-set resolution, a findings-blob fetch from CAS, a
  signature-bundle round trip to an upstream, an event append on another
  stream.

  Eight of the fifteen affected sites read the version after the decision;
  the other seven read it first but through a second, separate read of the
  same stream. The correction is a primitive rather than a patch per site:
  `ArtifactAtVersion` returns the artifact, its complete bounded event
  stream and the `ExpectedVersion` from **one** capped read, so the
  evidence and the version are the same observation and there is no
  "before" left to get wrong. Every reader that asked the stream a question
  — the latest `ScanCompleted`, the latest rejection reason, the
  per-finding blob, the `ProvenanceVerified` behind the release gate, the
  prior-scan baseline for the clean → vulnerable delta, the ingest-source
  label — now takes that paired stream instead of fetching one of its own,
  which is what makes the wrong order inexpressible rather than merely
  avoided at the sites that were fixed.

  Reads go down, not up: four stream reads become one in
  `record_scan_result`, five become one in the curator re-evaluation
  endpoint and the policy-mutation loosen pass, three become one in the
  provenance-misrejection repair and in the timer-release sweep per
  candidate. `read_artifact_stream` and the append-version derivation also
  collapse onto a single bounded `read_stream`, so the workspace now holds
  exactly one.

- **The storage-GC purge locked the artifact, but the blob is what it
  destroys** (#320). `purge_gc` took `SELECT checksum_sha256 FROM artifacts
  WHERE id = $1 FOR UPDATE` — a lock on one artifact row — and then deleted a
  **CAS blob**, which by construction may belong to any number of artifacts;
  deduplication is the whole point. So the refcount-zero observation and the
  `StoragePort::delete` that acted on it were two unrelated moments, and the
  worklist's `refs_remaining` is a *snapshot* the delete can act on sweeps
  later. A concurrent ingest that deduplicated onto the same hash
  (`exists(hash)` true, nothing written) and recorded its reference in between
  left its new artifact pointing at bytes that no longer existed.

  Closed with a **hash-scoped Postgres advisory lock**
  (`hort-adapters-postgres/src/blob_lock.rs`) that both sides take. The sweep
  takes it with `try` and re-reads the cross-`kind` count under it immediately
  before deleting, holding it across the storage call (the guard *is* the open
  transaction, which is how the lock spans the commit boundary the reference
  bookkeeping ended at). Every production `content_references` write —
  `PgContentReferenceRepo::insert`, which every ingest / OCI / provenance /
  wheel-metadata / curation path funnels through, and
  `PgRefcountReconcile`'s repair upsert — takes the same lock in the same
  transaction as its write, so a re-reference is either committed before the
  re-count or blocked until the lease ends.

  **Skip when in doubt**, reusing the retry the sweep already had: contention
  defers (nothing deleted, no terminal event, the durable worklist row stands,
  the next run asks again) and surfaces as `blobs_deferred` in the
  `retention-purge` summary plus `hort_retention_purged_total{result="deferred"}`
  — which is what distinguishes *nothing to reclaim* from *reclamation being
  skipped every run*. A count that is no longer zero is a **keep**, not a
  deferral: the blob stays, the worklist row is corrected under the lock, the
  purge finishes, and the `ArtifactPurged` states the count that actually held
  instead of the stale zero.

  Also capped the sweep's first run, which was unbounded because the pending
  set's size is only known once it is fully loaded: `list_pending_purge` is now
  keyset-paged and the walk stops at `MAX_BATCHES_PER_TICK * BATCH_SIZE`
  (64 × 1000), retention-evaluate's shape and numbers. No cursor is persisted —
  unlike retention-evaluate's candidates, this sweep *consumes* its work set.

  Enforced by `crates/hort-app/tests/blob_reclaim_lock.rs` (DB-free source
  scan: every production `INSERT INTO content_references` is preceded by the
  lock helper in its own function, the advisory-lock SQL is spelled in exactly
  one file, and the sweep never takes the waiting form), alongside DB-backed
  proofs that the ingest write and the reconcile repair each block on the very
  lease the sweep holds.

- **The non-k8s deploy never reclaimed terminal `scan` job rows** (#308).
  `scan-row-retention-sweep` was the only default-on chart CronJob with no
  systemd counterpart in `hort_timers`, so on an Ansible-deployed instance
  every artifact scan — ingest plus every periodic rescan — left a terminal
  `jobs` row forever. Added the timer (daily 03:00, matching the chart), and
  added `crates/hort-config/tests/deploy_schedule_parity.rs`, a DB-free source
  scan that holds the chart's `cronjob-*.yaml` set against
  `hort_timers_tasks` in both directions, so the next task that ships on one
  flavour and not the other fails a test instead of standing for years. The
  one legitimate asymmetry (`noop`, a heartbeat for the k8s svc-token chain
  the native deploy does not have) is named in the test with its reason, and
  the test fails if that reason goes stale in either direction.

- **The prefetch rotation cursor sat in a sweep with no keep-newest clause**
  (#308). `delete_terminal_prefetch_rows_older_than` matched `kind LIKE
  'prefetch%'`, which also caught `prefetch-tick` — whose keyset rotation
  cursor lives in the `result_summary` of its newest `completed` row and is
  read back by `PrefetchTickHandler::read_cursor`. An instance whose
  `prefetch-tick` schedule was off (it is default-disabled) or failing for
  longer than the 7-day horizon lost the cursor and restarted the rotation
  from the beginning, so on a large instance the tail packages came up rarely
  or never. The kind is now carved out of the cascade predicate and swept by
  `jobs-row-retention-sweep`, which retains the newest `completed` row per
  kind. `prefetch-tick` is a scheduled tick, not cascade work; it matched the
  cascade only by name prefix.

- **Ten places documented a way to set a retention horizon that does not
  exist** (#308). The two row-retention CLI subcommands, four chart CronJob
  templates, five `scheduledTasks` blocks in `values.yaml`, three
  `values.schema.json` descriptions and several handler docs pointed operators
  at `hort-cli admin task invoke <kind>`. `hort-http-admin-tasks::router()`
  enumerates its invoke routes one by one and none of
  `quarantine-release-sweep`, `prefetch-tick`, `wheel-metadata-backfill` or the
  three row-retention sweeps is among them, so those requests answer 404;
  the `enqueue-*` subcommands behind the CronJobs and timers take no horizon
  argument and write `params` unconditionally empty. Every such comment now
  says what is true: the handler's 7-day `DEFAULT_HORIZON` is the horizon in
  force on every supported path. No route, flag or chart value was added —
  `horizon_seconds` and the 365-day cap stay as they are, now documented as
  what they are. The cap's stated justification was also invented: it claimed
  a wide horizon "falls off the `updated_at` index", and no migration creates
  an index on `jobs.updated_at`.

- **`NOTHING CHANGED SINCE THE PREVIEW YOU NAMED` compared totals, not the
  artifacts** (#326). `render::diff` had nothing else to compare with:
  `PreviewGroup` carried `rows` and `distinct_contents` and no statement of
  *which* rows, so the CLI could not detect an identity change even in
  principle. Between the baseline preview and the apply, artifact A could stop
  matching and an equally sized B start — same row count, same distinct
  contents, same byte total, same coverage — and the comparison reported that
  nothing had changed, **skipped the acknowledgement confirmation**, and the
  apply expired B instead of A. The sample could not close the gap either: it
  is capped server-side and may be empty. Among artifacts of the same kind,
  equal totals are not a rare coincidence, and the confirmation is the last
  place a human sees what disappears.

  The preview now carries the proposal's identity. `retention-evaluate`'s
  `build_preview` digests the `(policy_id, artifact_id)` pairs it matched —
  the proposal's own unit, since one artifact matched by two policies is two
  expiries — in ascending pair order, framed one pair per line and
  domain-separated from every other digest in the system, and emits it as
  `preview.proposal_digest` plus one per `(policy, repository)` group so a
  reader can say *which* group moved. It is fixed-width whatever the
  proposal's size, it is computed inside the walk the preview already
  performs, and it is not a content hash: it digests identifiers, never
  artifact bytes. A `scheme` tag rides with each value, so a baseline written
  before a server upgrade and a fresh preview written after it report "not
  comparable" instead of a false "the proposal changed".

  The comparison decides on that identity, and fails closed: `NOTHING
  CHANGED` is now earned only by matching identities, and every other
  outcome — different rows, no identity reported, two schemes — demands the
  acknowledgement and says which of the three it found. `delta.changed` in
  the JSON keeps that reading (`true` whenever sameness was not *established*),
  so a script gating an unattended apply on `changed == false` stops rather
  than proceeding blind; `delta.proposal.comparison` distinguishes the cases.

  **Partial coverage qualifies a difference, never a match.** Equal digests
  mean the same proposed rows however much of the candidate set each run
  examined. Differing digests over a `partial` run are another matter: the
  sweep persists its keyset position, so an execution between the two
  previews moves the window under them, and reporting that as "the proposal
  changed" would be a warning that fires when nothing moved — trained away,
  then missed on the run where something did. The output says it compared two
  windows and that the difference may be the window rather than the world;
  `delta.proposal.window_limited` carries the same fact for a script.

- **The retention expiry could push an artifact stream past the 200-event cap,
  and every capped reader then decided on the oldest 200 events** (#324).
  `STREAM_EVENT_CAP` is an enforced bound, not an estimate: it is what makes a
  single capped `ReadFrom::Start` read of an artifact stream equal to reading
  the whole stream, which is what `read_expected_version` relies on when it
  reads `cap + 1` events and refuses a stream longer than that. One writer sat
  outside that bound. `RetentionUseCase::append_expired` appends at
  `ExpectedVersion::Any`, the adapter treats `Any` as no version check at all,
  and the method took the stream length as `_stream_len` and discarded it — so
  the daily expiry sweep was the only writer able to grow an artifact stream
  without limit.

  Past the cap, every full-stream reader silently answered a question about the
  oldest 200 events instead of the stream. **The release authorization is the
  one that matters**: it resolves `ScanSucceeded` from the *latest*
  `ScanCompleted` plus the absence of an `ArtifactRejected` *later than it*, and
  both halves are wrong over a truncated prefix — a stale clean scan reads as
  current and the rejection that superseded it lies outside the read, so the
  timer sweep releases an artifact the scanner condemned. The same truncation
  reached the retention evaluation itself (an existing `ArtifactExpired` past
  position 199 is invisible, and since the append was unchecked another was
  added every pass), scan history, the provenance clearance, the provenance
  cascade's idempotency check *and* its derived append version, the
  misrejection-repair conjuncts, and the event-store retention terminal proof —
  which decides whether to **delete** a stream.

  Both sides are now closed. The expiry append refuses when the length it was
  already handed leaves no room under the cap. Every full-artifact-stream read
  goes through one helper, `read_artifact_stream`, which reads `cap + 1` events
  so that a read returning at most `cap` has provably reached the tail, and
  refuses one that has not rather than return a prefix; the six duplicated
  `STREAM_READ_LIMIT`/`READ_LIMIT`/`TERMINAL_PROOF_READ_LIMIT` constants that
  each carried their own copy of the number are gone with it. Raising the cap
  was explicitly not the fix — a larger number only moves the point at which
  the same silent truncation happens. A candidate whose stream cannot be read
  completely is skipped by the release sweep at `error!` level and stays
  quarantined (fail-closed), rather than failing the whole sweep tick and
  stalling every other candidate's release.

- **The `retention-purge` start-gate opened after a sweep that did not
  converge** (#321). `RefcountReconcileUseCase::sweep_drift` keeps sweeping
  past a repository it cannot scan or a repair it cannot apply, counts each
  failure in `ReconcileSummary::errors`, and returns `Ok` either way — by
  design, so one bad repository does not block the rest from converging. The
  worker's boot sweep read that `Ok` as convergence and opened the gate,
  logging `errors=1` and `converged — RetentionPurgeHandler gate OPEN` on the
  same line. The error count was logged and never read.

  The gate exists to keep the destructive storage-GC walk off an unconverged
  `content_references` refcount projection, and a partially-failed sweep is
  exactly an unconverged one: an artifact whose `primary_content` edge is
  missing (repair failed) or was never looked at (scan failed) contributes
  nothing to its hash's cross-`kind` count, so purging a retired sibling that
  shares the hash drives the count to zero and deletes the live artifact's
  bytes.

  The convergence verdict is now `ReconcileSummary::converged()`
  (`errors == 0`), read by the worker composition root; a partial failure
  takes the same fail-safe posture the whole-sweep failure already had — gate
  CLOSED, purge refuses and retries, boot does not abort — with a log line
  that no longer claims the convergence that did not happen. `hort-server`'s
  pre-traffic sweep keeps its own behaviour (it hosts no purge handler) and
  now reports `converged` alongside the counts.

  Because the gate is decided once per boot and holds for the life of the pod,
  a closed gate is now discoverable **while it persists**, not only at the
  instant it is decided: the worker's 60-second heartbeat tick restates it as
  a `warn!` carrying the worker id, the reason and the remediation, and sets
  the new `hort_refcount_reconcile_gate_closed` gauge (0/1, refreshed per
  tick). The log line is the primary signal deliberately — the worker
  `/metrics` listener is off by default, so a gauge alone can be unreadable in
  a real deployment. Every refused purge also continues to land its refusal in
  `jobs.last_error`, served by the always-on admin task API.

- **The retention evaluation restarted at the beginning of the keyset every
  run** (#322). `RetentionEvaluateHandler` walks at most
  `MAX_BATCHES_PER_TICK * BATCH_SIZE` = 64 x 1000 = 64,000 artifacts per run,
  and re-initialised its keyset cursor to `None` on every invocation. Since
  `RetentionCandidateReader::list_candidates` is paginated by `artifacts.id`
  (`a.id > $3 ORDER BY a.id`) and excludes nothing it has already looked at,
  every daily run re-walked the same leading 64,000 ids and stopped. The doc
  comment claimed "subsequent daily ticks drain the rest", which holds only if
  the candidate set shrinks — that needs the leading artifacts to expire *and*
  be purged, and purge is disabled by default. On a registry with more than
  64,000 eligible artifacts the tail was therefore never evaluated, with no
  error signal: the run reported success with `partial` coverage. This broke
  **logical** retirement (artifacts being marked expired and leaving service),
  independently of physical byte reclamation.

  The run now persists where it stopped and resumes there. The position rides
  the run's own `result_summary.cursor` and is read back by the next run's
  fresh `jobs` row through `JobsRepository::last_result_summary_by_kind` — the
  `prefetch-tick` rotation's mechanism, applied to a single-dimension keyset
  walk. No new table, no column on `artifacts`, no operator knob, and the
  jobs-row retention sweep already retains the newest `completed` row of every
  kind precisely because readers of this shape exist. A short or empty page
  means the walk reached the highest candidate id, so the pass is over and the
  cursor goes back to `null`: the next run starts from the beginning. Full
  coverage costs `ceil(candidates / 64,000)` runs, and a candidate set that
  fits inside one run behaves exactly as before — one page, pass complete,
  cursor `null`.

  Two properties are now stated rather than left to be rediscovered.
  **Coverage comes from the wrap, not from the ordering**: `artifacts.id` is a
  v4 UUID, so the walk traverses UUID space rather than time and a newly
  eligible artifact lands behind the saved cursor about half the time; the
  bound on when it is seen is two passes, delivered by the wrap. **A dry run
  leaves the rotation where it found it**: a preview takes no per-UTC-day
  single-flight claim (ADR 0028) and so may run any number of times a day, and
  it reads the cursor — which is what makes it a preview of the window the
  next execution will act on — and writes back exactly the value it read.
  Advancing on a preview would let previews walk the rotation past the one
  execution a day allows; writing `null` would reset it.

  `coverage` now answers for the run rather than for the enumeration:
  `complete` only when the run both started at the beginning and reached the
  end, so a run that resumed mid-pass and drained to the tail reports
  `partial` — the artifacts behind its start point are not in its figures. The
  CLI's `PARTIAL` header says what becomes of them instead of leaving "still
  unexamined" to read as a permanent blind spot.

- **`hort-server validate-config` ran no row-0 rule, and said the opposite**
  (#304). The offline gate parsed the tree and then went straight to the
  `StaticConfigValidator` rows: `DesiredState::validate()` — the per-envelope
  domain rules and the cross-document rules (duplicate `(kind, name)`,
  dangling references, singleton conflicts, virtual-member resolution) — was
  never called, and outside `validate_against` it was called nowhere in the
  binary. A tree with a `PermissionGrant` pointing at an undeclared
  repository, two envelopes sharing a `(kind, name)`, a `RetentionPolicy`
  scoped to a repository nothing declares, or a structurally invalid
  `spec.predicate` such as `{AgeExceeds: 0}` validated clean, exit 0, and then
  parked the pod not-ready at boot. Three places in the command claimed
  otherwise — the step-3 comment, the failure branch's "parse / cross-validate
  error(s)", and an honesty footer naming only rows 1 and 4 as missing — so an
  operator reading it concluded the coverage was there.

  The command now calls `DesiredState::validate()` between parse and the lint
  rows. That is the apply path's own row 0 (`validate_against` delegates to it
  before adding its snapshot/env rules), so this is a shared source rather
  than a second implementation, and the two verdicts cannot drift. The
  rejection is headed by a message saying the *gate* got stricter rather than
  the tree — these errors were already failing that operator's apply,
  invisibly. Every gitops tree this repository ships already passes row 0 and
  is now guarded against regressing (`gitops_trees_validate` covers all four,
  including `deploy/compose/s3/config`, which the three `hort-config` per-tree
  guards do not reach).

  The footer now names every apply pre-write check the command still skips,
  and why each is absent — a distinction the old wording flattened. Only two
  are blocked on the running deployment: the managed-by ownership rule and the
  `HORT_UPSTREAM_ALLOWLIST_HOSTS` gate (enforced over the create+update slice
  of the `UpstreamMapping` diff). The `HORT_AUTH_PROVIDER=disabled` ×
  `ClaimMapping` rule needs only that env var, and the `scanBackends`
  backend-**name** check (row 4) needs nothing at all; both are merely not
  wired here yet. Two standing claims were wrong and are corrected in the same
  change: there is no immutable-field-change check anywhere in the gitops
  apply path, and row 4 has validated against the compiled-in
  `KNOWN_SCAN_BACKENDS` rather than the live worker registry since regression
  H20.

- **A failed OCI manifest `DELETE` stranded a live manifest without its
  keepalive edges** (#301). The digest-`DELETE` handler swept the manifest's
  `content_references` rows *before* the lifecycle delete, non-transactionally
  and warn-on-fail, then called `ArtifactUseCase::delete`. A failure in the
  second step returned 500 and left a live, servable manifest whose
  `oci_config` / `oci_layer` / `oci_index_member` keepalive edges were
  permanently gone — `PgRefcountReconcile` re-creates only the single-target
  `primary_content` / `metadata_blob` kinds, so nothing repairs them. The
  manifest's config and layer blobs became GC-collectable while every read path
  still considered the manifest healthy, and at the next purge the bytes
  vanished underneath it. The two calls are now in the other order: the
  lifecycle delete commits first, so a failed delete returns 500 with every
  edge intact, and the sweep runs on the committed-transition side where a
  projection-write failure can only leave a tombstoned source whose edges
  stand until the purge clears them — the same eventual-consistency posture
  every other `content_references` write already has.

  The eager sweep was *not* dropped in favour of the transactional one in
  `purge_artifact_refs`, despite the two now deleting the same rows. The purge
  is only ever offered an artifact whose `quarantine_status` is outside the
  GC-protected set (`quarantined`, `rejected`, `scan_indeterminate`), and
  nothing stops a caller deleting a quarantined manifest — so for those
  statuses the purge never runs and the DELETE-time sweep is the *only* sweep.
  Promptness is load-bearing too: three live readers of the edge set (the OCI
  referrers projection, `IngestUseCase`'s referenced-tree-descendant
  quarantine anchor, and the release sweep's parent-gated-blob skip, whose own
  liveness argument names this sweep) must stop seeing a tombstoned source
  immediately rather than at the next purge interval.

- **A Postgres that was set but unreachable turned the DB-gated suite into
  silent passes** (#302). `test_support::isolated_db_from` returned `None` on
  every failure — URL parse, maintenance connection, `CREATE DATABASE`, pool
  connect — which is the same value its 60 call sites use for "no
  `DATABASE_URL`, no database, skip". The caller could not tell the two apart,
  early-returned, and libtest reported `ok`. Not an uncertain result, a false
  one: the state in which a green gate is most valuable — the server has a
  problem — was the state in which the gate inverted, and the `ignored` count
  was not even a lower bound on what had been skipped. Measured against a
  closed port, `cargo test --workspace --tests --no-fail-fast` reported 12,350
  passed / 1 failed / 7 ignored, the single failure being the one test in the
  workspace that hand-rolled `.expect()` on its own maintenance connection; a
  dead server also cost ten minutes of `acquire_timeout` stalls on the way to
  that green.

  The `DATABASE_URL` read stays where it is — unset still skips, and an unset
  workspace run is still green, because that is how the pre-push gate runs.
  What changed is everything after it: once a URL is in hand the operator has
  declared a database, so `isolated_db_from`, the new shared
  `test_support::connect_or_panic`, and `shared_migrated_pool` panic with a
  message naming the stage that failed and the credential-free target. The
  same command against an unreachable target now reports 489 failures across
  42 targets.

  The swallow was not confined to the isolation helpers: five hand-rolled
  `admin_pool()` fixtures (`hort-server`'s four `migrate_*` targets and
  `hort-worker`'s `schema_compat_boot`) carried their own
  `PgPool::connect(&url).await.ok()` and never touched `test_support` at all —
  35 further tests a helper-only fix would have left silent. They now route
  through `connect_or_panic`. A new DB-free source guard,
  `crates/hort-app/tests/db_gate_not_silent.rs`, rejects any
  `PgPool`/`PgConnection` connect whose error is discarded with `.ok()`, and
  pins the isolation harness to a single `?`-shaped skip: the `DATABASE_URL`
  read.

- **The response that triggers a quarantine reported a flat 3600 s
  `Retry-After`** (#240). A pull-through `GET` that ingested and quarantined
  an artifact answered `503 UNAVAILABLE` with `retry_after_seconds: 3600`
  whatever the policy's window, while a later read of the same row reported a
  correctly computed remaining time (observed against a 48-hour policy: 3600
  on the triggering response, 143914 on a later one). The computation was
  never wrong; `quarantine_deadline` is transient and non-persisted — the
  schema stores only the immutable anchor `quarantine_window_start` and the
  deadline is derived live, so the Postgres row mapper yields `None` — and
  nothing on the ingest path filled it in, so the consuming handler's
  deadline-unknown constant fired on the one response where Hort had just
  computed the window in order to create it. Wrong in the load-generating
  direction: a client honouring it returns after an hour on a 48-hour window
  and is refused again, roughly 47 times.

  Both halves of the ingest path now hydrate, at the use-case layer, so every
  format's quarantine response inherits the fix with no change of its own.
  `ArtifactUseCase::find_in_repo_by_hash` — the post-coalesce recovery read
  the OCI blob and manifest, Cargo, npm, PyPI and Maven pull-through tails all
  take, since the leg that fetched from upstream discards its own ingest
  outcome — hydrates through the same `hydrate_quarantine_deadline` a later
  read goes through. The two `IngestUseCase` mint paths stamp the pair from
  the anchor and duration already in hand (no extra policy resolution), which
  covers the cross-repo coalesced-follower row that has no later read to
  hydrate it. The shared arithmetic lives in one place
  (`use_cases::quarantine_hold`) so the two layers cannot report different
  remaining windows for one artifact.

  The deadline is measured from the **derived** anchor, never from `now`:
  ADR 0054's anchor may legitimately predate the ingest (in the observed case
  `library/hello-world` inherited an eight-hour-old anchor through the
  `first_seen` age source, which is why the correct later value was 143914 and
  not 172800), so reporting the policy duration would be wrong in the other
  direction — and wrong invisibly, since it looks right on any freshly-seen
  artifact. No change to the window, the release predicate, the past-deadline
  clamp, or the `Retry-After` suppression for a hold with no self-resolving
  deadline.

- **Notification subscribers never received the artifact lifecycle** (#296).
  Push delivery ran off an in-process `tokio::sync::broadcast` channel fed by
  `EventStorePublisher` after `EventStore::append`. But every event that must
  land atomically with a projection write goes through
  `PgEventStore::append_in_tx` instead — reached via `ArtifactLifecyclePort`,
  `RefLifecyclePort`, `ArtifactGroupLifecyclePort`, the artifact delete and
  the purge sweep — which sits *below* the publisher and therefore below the
  `send`. That is the whole subscribable artifact lifecycle: `ArtifactIngested`,
  `ChecksumVerified`, `ArtifactQuarantined`, `ScanRequested`, `ScanCompleted`,
  `ArtifactBecameVulnerable`, `ArtifactReleased`, `ArtifactRejected`,
  `ScanIndeterminate`, `ProvenanceVerified`, `ProvenanceRejected`,
  `ArtifactReEvaluated`, `PromotionRequested`, `PolicyEvaluated`,
  `ApprovalRequested`, `ApprovalDecided`, `ArtifactPromoted`,
  `PromotionRejected`, `ArtifactDeleted`, `ArtifactPurged` and
  `ArtifactCorrupted`, plus `RefMoved` / `RefRetired`
  and every `ArtifactGroup*` kind. Exactly two artifact-stream kinds reached the
  channel — `ArtifactExpired` and `CasIntegrityMismatch`, both appended through
  the publisher. The same channel is per-process and the dispatcher
  has no leader election, so at `replicaCount > 1` a replica also never saw any
  other replica's appends. This was not new with #286's atomicity work —
  `ArtifactDeleted` had behaved this way since the delete path existed (#281);
  #286 only made it visible on a second event.

  Catch-up did not save it. The read is `global_position > last_delivered_position`,
  so as soon as one *delivered* event checkpointed a higher position, every
  never-delivered event below it was below the mark and never revisited —
  permanent loss, from that moment rather than from the next restart. (The
  documentation claiming that marker was "operator visibility, not a delivery
  cursor" was simply false.)

  Delivery is now driven by reads of the event store
  ([ADR 0061](docs/adr/0061-store-driven-notification-delivery.md)): every event
  is delivered by `catch_up` — already the filter, dispatch and progress path —
  which runs on every 5-second `STORE_POLL_INTERVAL` tick and not only at
  startup and on `Lagged`. The broadcast becomes a **wake-up**: its
  `global_position` is discarded, and only its *category* is used, as the
  predicate deciding whether this subscription has anything to read at all.
  Delivering the payload directly is the tempting shortcut and is the same bug
  one layer up — the delivered position would advance the cursor over every
  transactional append below it, so a subscriber getting a publisher-path event
  at position 100 would skip the appends at 51..99. Only reads advance the
  cursor, which is what keeps the walk contiguous.

  **A pass reads the filter's categories as one ordered stream**, via a new
  `EventStore::read_categories`. The task holds one cursor over one
  `global_position`-ordered page rather than one cursor per category, which is
  what makes the single persisted `last_delivered_position` scalar correct
  instead of approximately correct — a per-category walk over one scalar loses
  events across a restart, because the scalar is seeded into every category at
  spawn and an advance driven by one category becomes the floor for all of
  them. The port ships a default that merges per-category reads (right for the
  ~20 in-memory implementations); Postgres overrides it with a `UNION ALL` of
  per-category keyset arms that the planner serves with a `Merge Append`. The
  shape is the deliverable: the obvious `stream_category = ANY($1)` spelling
  measures 160 641 buffers and 33.9 ms — 160 001 rows scanned and discarded to
  return nothing — against 9 buffers and 0.011 ms for what ships, on a seeded
  200 000-event table under both custom and generic plans. A source-scan guard
  pins it.

  **A failed delivery is no longer checkpointed past.** Previously the failed
  event's own position was written to `last_delivered_position` and reads
  resume strictly above it: one transport attempt, ever, and a 30-second
  receiver outage silently swallowed every event that arrived in it. The pass
  now stops at the failed event, leaves the cursor below it, persists the
  position *before* it, and retries on every subsequent tick — until it
  succeeds or the existing 100-failures-in-1h budget disables the subscription
  visibly. That is what makes "at-least-once" a statement about deliveries
  rather than about attempts, and the budget is what bounds the head-of-line
  block the in-order retry creates.

  No transaction gained, lost or reordered a statement, and
  `hort-adapters-postgres` still holds no broadcast sender — asserted both
  behaviourally (`event_delivery_visibility.rs`) and as a source-scan guard on
  the crate (`no_broadcast_in_adapter.rs`), since a sender reached through a
  setter would leave the behavioural test green. The stated guarantee moves
  from "best-effort, may drop" to **at-least-once for every event visible to a
  category read when the cursor passes it, duplicates possible**: a duplicate
  is the receiver's to drop (`X-Hort-Delivery-Id` + stable `global_position`),
  a gap is nobody's to recover.

  Three residuals are deliberate and named in the ADR.
  `events.global_position` is a `nextval` default evaluated at INSERT while a
  row becomes visible at COMMIT, so a later-committing transaction can hold a
  lower position and a bare high-water-mark cursor steps over it — pinned
  against a live database, and it bounds `GET /api/v1/events`'s `next_after`
  checkpoint at least as much as the dispatcher, so closing it is a change to
  the position model. It is *widened* here, measurably rather than slightly:
  the old live loop delivered whatever it received regardless of position, so
  publisher-path events were immune by accident, and the window is the whole
  transaction tail including lock waits (every transactional port appends first
  and writes projections after), not one commit latency. Second: the event
  store is swept on age, not on delivery, so a subscription paused across a
  retention sweep can miss events that were deleted — bounded by both sweeps
  being `enabled: false` by default and the floor defaulting to 1 080 days.
  Third: N replicas still deliver N times.

  A failed *read* is fail-closed the same way (the cursor does not move), which
  means a deterministic read failure — one row a replica cannot decode, as a
  mid-rollout version skew produces — stalls a subscription indefinitely rather
  than skipping. `hort_notify_store_read_errors_total` is the alertable signal;
  before it, the only signal was a `warn!` per tick.

- **Failure-budget exhaustion during catch-up did not stop the task** (#296).
  `catch_up` returned `()`, so its early exit on an exhausted budget ended only
  the pass: `run` carried on into the live loop and kept delivering to a
  subscription it had just transitioned to `Disabled`. Contradicted both the
  module documentation and the inline comment asserting the opposite. `catch_up`
  now reports the exit to its caller — load-bearing now that the pass runs on
  every poll tick.

- **A soft delete never released the content reference, so the bytes had no
  release path at all** (#295). `ArtifactUseCase::delete` is an event-sourced
  soft delete: the adapter appends `ArtifactDeleted` and sets
  `artifacts.deleted_at` in one transaction, and its doc comment stated that
  the CAS blob is left to refcount-gated GC "because another artifact may
  reference the same bytes". The intent was right and the mechanism never
  fired. The `content_references` source edge stood after the delete, so the
  refcount never fell, so the refcount-gated collector never saw the blob — no
  predicate reached those bytes, no policy selected them, and no configuration
  changed it.

  `ArtifactDeleted` is now a **byte-release work item** in its own right:
  `purge_gc::list_pending_purge` enumerates every artifact stream carrying an
  `ArtifactExpired` *or* an `ArtifactDeleted` with no following
  `ArtifactPurged`, and the existing storage-GC sweep releases the source
  edges, deletes the blob at cross-kind refcount zero, and appends the
  terminal event — unchanged, crash-safe, and still the only destructive path.
  The carrier is the event the delete already writes rather than a synthesised
  `ArtifactExpired` (which would have to invent a `policy_id`, a `policy_name`
  and an expiry reason for a decision no policy made) or a new work-item event
  (which would duplicate, on the same stream at the same instant, a fact
  `ArtifactDeleted` already records). It is also already durable in the same
  transaction as `deleted_at`, so the work item cannot come apart from the
  retirement that authorises it — no new transaction code was needed to get
  the atomicity.

  A delete does not inherit the `KeepLastN` tag exemption. That flag is
  vacuously true for an artifact carrying no expiry decision at all, so a
  tagged delete would otherwise have been skipped forever by a rule for a
  policy that never ran, its bytes held by a mutable ref pointing at a row no
  read path resolves. Invariant 1 is untouched: a quarantined, rejected or
  scan-indeterminate artifact keeps its bytes as evidence even when a caller
  deletes it — and unlike the retention path, which pre-filters those
  statuses, the delete verb is deliberately orthogonal to the quarantine axis,
  so the sweep's status filter is what holds there.

  Byte release is asynchronous, bounded by the `retention-purge` sweep
  interval (default `0 4 * * *`); the sweep summary gains
  `user_deletes_visited` so a deployment with no retention policy configured
  can still attribute the destructive work it does. On first run after
  upgrading, the sweep collects the bytes of artifacts deleted before this
  change — which is the point.

- **`KeepLastN(n)` could leave n artifacts and no downloadable one** (#292).
  The retention candidate reader ranked siblings over every live row of the
  `(repository, name)` group, while the candidate page itself excluded the
  GC-protected statuses. A quarantined, rejected or scan-indeterminate sibling
  could therefore never expire *and* still held a rank slot — the two halves of
  one query disagreeing about what a sibling is.

  That does not merely narrow the keep window, it can empty it. `KeepLastN(3)`
  over five siblings whose three newest went into quarantine together — one
  scan hit on a fresh build burst does exactly that — gave ranks 1–3 to the
  quarantined rows and expired both released siblings at ranks 4 and 5. What
  survived was three artifacts, none downloadable and none collectable, for an
  operator who had asked to keep the last three.

  The rank now counts **usable** siblings: `ranked` carries the identical
  predicate the page does, bound from the same protected-status set, so
  `KeepLastN(n)` means n artifacts a client can actually fetch. The accepted
  counter-cost is that a group holds n plus its protected siblings rather than
  n rows — a population `KeepLastN` could not have collected in any case.
  Releasing a protected sibling re-enters it in the rank and can push an older
  released sibling out of the window; that is the rule working, since release
  is what makes an artifact usable. A soft-deleted sibling still occupies no
  slot, and the tag exemption is unchanged.

- **A retention preview took the destructive single-flight key, so previewing
  first is what made the confirmation lie** (#291). `retention-evaluate` is a
  destructive *kind*, and the server derived its durable per-UTC-day
  idempotency key for every invocation of one — including a dry run. The second
  preview of a UTC day was therefore not a sweep at all: the server answered
  `200 OK` with the first one's job.

  That fires on the intended workflow, every time. `hort-cli admin retention
  apply --from-preview A` re-measures immediately before executing so it can
  show what moved since the proposal; that fresh preview was deduplicated back
  to A, so the delta was A against A and always empty. The execution *was*
  fresh, and expired what it found. The operator read "nothing changed since
  you looked" and then authorised a sweep computed from different data.

  The key is a single-flight claim on destroying something, so it is now
  derived per **invocation** rather than per kind, from the same domain answer
  that decides whether the caller needs the `task:destructive` claim — one
  decision, two consumers, and a test that fails if they ever come apart. A dry
  run takes no key and is repeatable; an execution keeps the key it has always
  had, mode segment and all, so a second execution in one UTC day is still
  deduplicated by design. Audit routing is unchanged: a dry run's `TaskInvoked`
  still lands on the never-deleted destructive-kind stream.

- **The preview's byte figure was bounded by a guess, on the wrong axis, and
  the query behind it had a 38× performance cliff** (#290). The simulation
  refused to compute a size above 10 000 candidate artifacts or 10 000 target
  blobs — round numbers, not measured ones — so a preview over a repository of
  any real size reported the figure as omitted, and said only that a bound had
  been exceeded.

  Measured, the cost sits on the **target** side: about 7 µs of walk per target
  against about 2 µs per candidate artifact. The bounds now reflect that — a
  100 000-artifact backstop above the sweep's own structural maximum, and a
  128 000-target operational ceiling — and both carry the measurement in their
  doc comments. The omission now names the bound it hit, its value and the
  observed count, so a narrower scope is a decision an operator can make rather
  than guess at.

  The measurement also turned up a latency cliff that would have surfaced only
  in production: the survivor probe filtered with `NOT (… = ANY($1::uuid[]))`,
  and PostgreSQL folds bound parameters into constants only while it is building
  custom plans. From the sixth execution on a pooled connection — the steady
  state for a worker that holds connections for days — the plan goes generic and
  the array becomes a linear scan per row, measured at 64.2 s against 1.7 s for
  identical input. The probe is now an anti-join against the candidate set,
  producing a verified-identical result, with a structural guard pinning the
  shape because only cost distinguishes the two forms.


- **`KeepLastN` never matched anything** (#287). The evaluator was handed no
  sibling ranking, and its fail-safe — correctly — refuses to expire an artifact
  whose position among its siblings is unknown, so a count-based retention policy
  was inert however it was written. The rank and the sibling total are now
  resolved in the candidate query itself, by a window function over
  `(repository, name)` computed across the **whole** sibling group rather than
  the current keyset page: a rank that shifted with the page boundary would have
  expired the wrong versions. Which N survive is now a documented part of the
  contract — newest first by creation time, ties broken by artifact id — so two
  artifacts created in the same instant cannot swap places between runs. Retired
  rows occupy no rank slot.

  **An artifact a tag points at does not expire under `KeepLastN`, however low
  its rank** — otherwise the first count-based policy would delete the image a
  pinned deployment is running. The exemption resolves per repository, because
  content hashes are shared across repositories by construction and a global
  lookup would protect the wrong artifacts in both directions; it covers both
  mutable-pointer forms, the content-hash target an OCI tag resolves to and the
  version target an npm dist-tag resolves to; and it is re-checked immediately
  before the purge deletes, because evaluation and purge are separate scheduled
  sweeps and a tag set in between would otherwise find the artifact already
  expired and unasked. A skipped artifact is reported in the sweep summary
  rather than disappearing from the work set.

- **A completed purge left the artifact broken instead of reclaiming space**
  (#286). The purge deleted an artifact's content references, deleted the blob
  once nothing else referenced it, and recorded `ArtifactPurged` — but never
  retired the row. With the blob gone the artifact kept answering `HEAD` with
  200 from a row whose bytes no longer existed, `GET` failed on the storage
  read, and re-pushing the same content could not heal it: the ingest dedup
  keys on path and checksum and returns before writing. Purge now retires the
  projection in the same transaction that writes the terminal events, whether
  or not the blob survived for another referent, and the refcount reconcile no
  longer recreates references for retired rows. The retirement is idempotent in
  the state rather than in the writer, so an artifact a person deleted between
  its expiry and the purge still completes and keeps its original deletion
  timestamp. Completion is now per artifact rather than per hash — a failure on
  one of several hashes no longer records the artifact as purged while part of
  its content survives — which needs durable state, so a new table records each
  target and its post-delete refcount in the same transaction that removes the
  edges. Without it a retry could not rediscover an OCI manifest's child
  targets at all.

- **Retention could never have enumerated a single artifact** (#284). Three
  faults in one query, all of which had to fall before any retention policy
  could do anything at all. The candidate reader selected
  `repositories.format` without casting the PostgreSQL enum to text, so
  decoding failed on the first row of every non-empty page — the sweep
  returned a retryable error and expired nothing. Its status filter was
  written as `quarantine_status NOT IN (…)`, which is *unknown* rather than
  *true* for the SQL `NULL` that an artifact without a quarantine status is
  stored as, so a quarter of a typical inventory was invisible to every
  policy. And it had no `deleted_at` predicate, so it offered soft-deleted
  rows as candidates. None of this was reachable before: the sweep
  short-circuits when no retention policy exists, and the only test over the
  reader enumerated an empty table. The eligible and GC-protected status sets
  now come from one definition shared by the candidate reader, the
  pending-purge reader, the refcount reconcile and the purge-path mapper,
  which is what kept them from drifting apart again.

### Security

- **An OCI manifest is served only while every artifact in its closure is**
  (#342). The manifest read path gated on the manifest's **own**
  `quarantine_status` and then served the body; its constituents were never
  consulted. Measured on the pushes that opened the issue: five manifests
  answered `200` while a referenced layer answered `404 BLOB_UNKNOWN` — which
  containerd surfaces as `failed to pull and unpack … not found` *after* it has
  committed to the pull, and which cost twelve HelmRelease attempts at a
  15-minute timeout each with nothing on the wire distinguishing "this layer was
  rejected" from "this registry is broken". Hort already held the rule
  everywhere else: the shared index pipeline drops a terminally-held version
  under both index modes, so npm, PyPI, Cargo and Maven never advertise one. The
  OCI paths were the only place that did not.

  A **terminal** status (`Rejected` / `ScanIndeterminate` —
  `QuarantineStatus::is_terminal`, the same predicate the manifest write path
  refuses a push on) anywhere in a manifest's closure now withholds the
  manifest, on `GET` and `HEAD` alike and for every caller. The closure is
  **transitive**: an index over a child whose layers are terminal is withheld
  too, because answering `200` and then failing at the child is the same
  contradiction one level up.

  **A hold is not a verdict and absence is not a hold.** A `Quarantined`
  constituent changes nothing — the client's own blob fetch answers it with the
  deadline — and a constituent that is simply **not ingested** changes nothing
  either, which is the ordinary state of every cold pull-through manifest. Only
  a present catalog row in a terminal state withdraws the manifest.

  **The refusal names the offending constituent**: its digest, and for a
  rejection its axis, in the same `403 DENIED` envelope the manifest's own
  rejection uses (a `ScanIndeterminate` constituent answers `503` with no
  `Retry-After`, as that state does for itself). The digest is the signal that
  identified the cause in the original incident — identical across repeated
  pulls of one manifest, different across manifests — and a server-side line
  carries the same three facts (which manifest, which constituent, which
  verdict) for the operator.

  **Operator impact, and it is not small.** The rule applies to the whole
  existing inventory from the first request after upgrade; there is no
  migration step and no backfill. Measured against the dogfood instance,
  **8,845 signature manifests stop being deliverable** — caused by six
  terminally rejected `{}` config blobs rather than by the ~2.5k rejected
  payloads — so a signature check against that instance's **existing**
  signatures fails. **New** signatures are unaffected (the forward path that
  created that population is closed and no payload has been terminally rejected
  since 2026-08-15), and **image pulls** are unaffected, because a signature
  manifest hangs off its subject as a referrer and is not in the closure a pull
  walks. This window is accepted deliberately and indefinitely: the affected
  population is discarded, not repaired, and no repair instrument ships.

  The Referrers API still reports such a signature as present while a fetch of
  it fails — from outside that reads like a registry fault rather than a
  withheld artifact. That asymmetry is the price of refusing an immutable
  document rather than editing it; it is recorded in ADR 0043's 2026-10-13
  amendment and is why the server-side log line is not optional.

  Decisions: [ADR 0062](docs/adr/0062-never-advertise-what-you-will-not-serve.md)
  is the rule; [ADR 0043](docs/adr/0043-oci-image-index-support.md) carries
  the OCI read-path amendment.

- **A repeated key in a `ServiceAccount`'s `claims` map no longer applies
  silently** (#347). `FederatedIdentitySpec.claims` is the exact-match
  condition under which a JWT may assume a service account (ADR 0018), and it
  is a map rather than a struct — so serde's duplicate-field rejection did not
  reach it and the YAML layer decided. The previous parser kept the **last**
  value and said nothing: an envelope reading
  `project_path: trusted/group` on one line and
  `project_path: attacker/group` on the next applied the second, with the
  discarded entry visible nowhere in parse, validate or the apply diff. The
  gitops parse now refuses a duplicate mapping key outright, wherever it
  appears.

  **Operator impact.** A tree carrying such a duplicate — in `claims` or in
  any other mapping — stops booting with
  `duplicate mapping key: <key> … at line N, column M` instead of applying one
  of the two values. That is the intended direction for this field: a trust
  policy that is not the one the file reads as must fail, not resolve. Audit
  any generated or templated `ServiceAccount` envelope before upgrading; a
  repeated key that was being tolerated is now a boot failure.

- **An upstream credential is bound to its mapping's own origin** (#343). On
  the artifact path the request URL is not always the operator's: `npm`'s
  `dist.tarball`, PyPI's `urls[].url` and the Cargo `dl`-composed URL are
  absolute URLs read out of *upstream metadata*, and `resolve_artifact_url`
  accepted them after `check_ssrf_safe` alone. That check is correct and
  answers a different question — "is this destination internal?" is not "may
  this destination have our credential?", and a public, upstream-nominated host
  passes the first. `authorization_header` then attached the mapping's Basic
  credential (or a cached bearer) with no URL in hand to object with.

  **Both legs are closed, because closing one only moves the secret.** A
  foreign `401` on a `BearerChallenge` mapping used to run the whole challenge
  dance against the *foreign* host's `WWW-Authenticate` realm and exchange the
  operator's secret there; suppressing the header on the initial request while
  leaving that dance reachable would have changed which request carried the
  secret, not whether one did. `fetch_with_challenge` now computes one
  `CredentialScope` per call from the request URL and `mapping.upstream_url`
  and gates both the header and the challenge branch on it. A cross-origin
  `401` surfaces as the plain `Unauthorized` classification the non-challenge
  path already produced.

  The comparison is the RFC 6454 §4 origin triple — scheme, host
  (ASCII-case-insensitive), port with default-port normalisation — and it fails
  closed: an unparseable URL on either side yields no credential.
  `upstream_url`'s parseability is a value-object invariant, so a failure there
  is a broken invariant rather than an input to accommodate. It is the same
  rule reqwest applies to a redirect hop (pinned by
  `cross_host_redirect_strips_authorization_header`), carried back onto the
  *initial* request.

  **The cross-origin fetch is not forbidden** — npm and PyPI serve artifact
  bytes from a different host than their metadata (`files.pythonhosted.org`
  against `pypi.org`) and pull-through depends on it. Only the credential stays
  behind. A withheld credential emits one `tracing::info!` carrying the
  mapping's `upstream_url` and the request target's **origin**; the
  metadata-supplied path and query are upstream-controlled and are not logged.
  No new metric, label or configuration knob.

- **An authority change commits with its audit event** (#341). Three gitops
  apply branches wrote a security-relevant row, committed it, and appended the
  attesting audit event in a *separate* call: permission grants
  (`PgPermissionGrantRepository::save_managed`, then
  `append_grouped_authorization_events` across possibly several streams), claim
  mappings (same whole-partition shape), and OIDC issuers (one independently
  committed `upsert` per issuer, with the event batch appended at the very
  end). An append failure — or a process termination — after the row commit
  left the grant, claim mapping or issuer **active with nothing in the
  authorization stream attesting it**. Issuer rows are the sharpest case: a
  serving validator reads `oidc_issuers` at validation time, so a surviving
  replica acts on the new trust state while the stream is silent about it.

  **The retry could not repair it**, which is what made this a defect rather
  than a gap. The next apply derives its events from the *prior rows*, which
  already hold the change, so it emits nothing — the claim-mapping branch said
  so in its own comment, as expected behaviour. For issuers a reapply might
  emit an `Updated` (the snapshot carries no persisted digest) but never the
  original `Created` / `Deleted`, nor the record that the change had been live
  without one.

  The fix adopts the primitive the artifact, ref and artifact-group lifecycle
  ports have used since `PgUnitOfWork` existed, at a fourth site:
  `AuthorityLifecyclePort` (`PgAuthorityLifecycle`) takes the desired rows and
  the audit batches in one call and commits both or neither. The
  prior-vs-desired diff that derives the events is unchanged; the
  whole-partition delete-and-reinsert is unchanged; the audit append simply
  joins that transaction, so `EventStore::append` grows no transaction
  parameter (ADR 0007) and the apply pipeline still sees only a port.

  **The grouped multi-stream append is atomic too.** A grant reconcile routes
  each row's event to its repository stream or to the global authorization
  stream, so one reconcile spans several batches; they are appended on the
  same unit of work, so a batch that fails part-way leaves **no** stream
  audited. Previously each stream was its own append transaction and a
  part-way failure left some repository streams audited and others not.

  **Behaviour change an operator will notice:** an event-store failure during
  a grant, claim-mapping or issuer apply now leaves the rows **unchanged** —
  the apply fails closed instead of half-done. The apply-time JWKS warm-up
  moves after the commit for the same reason (a cache warmed for an issuer
  whose row rolled back would be a trust state nothing persisted); its failure
  still does not fail the apply.

  Four operator-visible log lines claimed a commit that had not happened yet
  (`permission_grant` / `oidc_issuer` / `upstream_mapping` / `service_account`
  `audit events committed`, all emitted *before* the append). All four now
  emit after the append returns `Ok`.

- **The authority contract covers every write, and the old path stops
  compiling** (#341). Two gitops apply branches still carried the
  commit-then-append shape the `AuthorityLifecyclePort` closed for grants,
  claim mappings and issuers. **Upstream mappings** were the worst-shaped
  member of the family: one independently committed `save_managed` *per
  mapping*, and then a closing grouped append that was one transaction *per
  stream*, so a part-way failure could leave some repositories' mappings live
  and unattested while others were audited. A mapping names the upstream a
  proxy repository will trust and fetch from, with its credential reference
  and its TLS material, so a mapping that commits unattested is a changed
  trust anchor the authorization stream is silent about — and a re-point is
  invisible to the next apply, whose digest comparison reads the change as
  already applied. **Service accounts** had the same shape one aggregate at a
  time: a service account is a federated-identity trust anchor (ADR 0018),
  its `federated_identities[].claims` decide which JWTs may assume it, and the
  federation handler reads the aggregate at assume time. Both now commit their
  rows and their audit events in one transaction, via
  `commit_upstream_mappings` / `commit_service_accounts`.

  **And the replaced write methods are gone from their traits**, so the
  mistake is a compile error rather than a review rule — the same posture the
  `pub(crate)` `AppContext` fields take against a format crate.
  `PermissionGrantRepository`, `ClaimMappingRepository`,
  `OidcIssuerRepository` and `ServiceAccountRepository` are now read-only
  traits; `RepositoryUpstreamMappingRepository` keeps only its non-gitops
  `upsert` / `delete` pair, the `managed_by = 'local'` admin CRUD surface,
  which carries no digest, no provenance and no audit event. The statement
  bodies live on as the adapters' `*_in_tx` helpers, reachable from the
  authority adapter and each repository's own read path and nowhere else. A
  write method with no caller that re-opens a closed audit-integrity finding
  is not left reachable by convention.

  Two smaller things fall out. The upstream-mapping branch no longer reads
  `list_managed_by_gitops` three times per apply — one `list_all` snapshot
  taken *before* any write resolves each mapping's surrogate id from its
  `(repository_id, path_prefix)` identity, which is exactly what the adapter's
  `ON CONFLICT … DO UPDATE` preserves; the pre-port shape needed a *post*-write
  read to recover that id, and reading only the gitops partition would have
  minted a fresh id for a `managed_by = 'local'` row the upsert adopts. And an
  apply with an empty upstream-mapping or service-account plan now opens no
  transaction at all.

  **Behaviour change an operator will notice:** an event-store failure during
  an upstream-mapping or service-account apply now leaves the rows
  **unchanged** — the apply fails closed instead of half-done. The one write
  that stays outside the transaction is the backing `users` row for a declared
  `ServiceAccount`, which has to be durable before the SA row's FK can
  reference it; an orphan backing user confers nothing, because the grant
  reconcile materialises `GrantSubject::User(backing_user_id)` rows only for
  service accounts resolved from the persisted SA aggregate, and the next
  apply finds it by username and re-emits the same `ServiceAccountCreated`.

- **The chart's unrestricted-egress Job exception now selects only this
  release's Jobs** (#341). `networkpolicy-migrate-job.yaml` renders a
  NetworkPolicy granting unrestricted egress (`egress: - {}` — every
  destination, every port) to the pre-install migrate / bootstrap / pre-pull
  Jobs, which must reach Postgres and the kube-apiserver before the app pod
  and its deny-all egress policy exist. Its `podSelector` tested **only
  whether the `hort-server.io/job` label key exists**, and carried none of the
  chart's name/instance labels — so **any** pod in the namespace that set that
  label to anything at all was selected. A principal who may create or label a
  Pod but may *not* touch NetworkPolicies therefore took the unrestricted
  allowance by writing one label, and in a namespace whose own policy denies
  egress reached the destinations that policy meant to block; patching the
  label onto an existing restricted pod did the same. Two releases of this
  chart in one namespace also granted each other's Jobs egress.

  The `podSelector` now ANDs `hort-server.selectorLabels` (this release's
  `app.kubernetes.io/{name,instance}`) onto the existing `Exists` clause. No
  legitimate pod loses the allowance: every Job / CronJob / DaemonSet /
  `helm test` pod template in the chart already carries both labels, verified
  by evaluating the rendered selector against every rendered pod template —
  including under `nameOverride` / `fullnameOverride` and a non-default
  release name. The app pods are still excluded by the `Exists` clause alone,
  so their deny-all egress is untouched, and `networkPolicy.enabled: false`
  still disables both policies.

  **Whether this Job egress should be narrower than release scope is
  deliberately left open** — that is a chart-owner decision about CIDRs the
  chart does not know, not part of this fix.

  Two documentation claims the selector did not support are corrected rather
  than left standing: the template's "selects exactly the Job/CronJob pods"
  comment and `values.yaml`'s Job-only sentence both now say *this release's*.
  The advice both places gave an operator who wants tighter Job egress —
  layer a second, narrower policy over this one — was **wrong and is
  deleted**: NetworkPolicy allowances are additive (as the same file's own
  docstring explains twenty lines earlier), so a second policy can only add,
  never subtract this rule's `to: []`. The one real lever — narrowing `to:` on
  this rule itself, by a chart fork or a `--post-renderer` patch — is now what
  both places say, together with the note that the app `egress` posture never
  reaches these pods at all. The pointer into `control-plane-tiers.md` went
  with it: that document has no Job-egress narrowing guidance to find.

  **`scripts/test-helm-templates.sh` now asserts the scope rather than the
  label key.** The assertion that let this ship checked only that
  `key: hort-server.io/job` appeared in the rendered policy, which passes at
  every scope. The replacement derives both sides from the same render — it
  reads the rendered `podSelector` and a named pod template's rendered pod
  labels, then evaluates one against the other — so it fails in both
  directions: a selector carrying no release identity fails outright, the app
  Deployment and worker pod templates must come out *not* selected (which is
  what fails if the `Exists` clause is dropped), and the migrate,
  svc-token-bootstrap, pre-pull and CronJob pod templates must come out
  selected (which is what fails if the selector tightens past them — swapping
  `hort-server.selectorLabels` for `hort-server.labels` is one word and bricks
  `helm install`, and no count-based grep notices).
- **A running subscription delivers against its live row, not the one it was
  spawned with** (#341). `PATCH /api/v1/subscriptions/:id` persisted the new
  target and filter and notified the dispatcher, and the reconcile pass that
  followed walked every active subscription — but the row itself was read only
  at spawn and moved into the per-subscription task as an owned value. Every
  consumer inside the task read that copy: the category/event-type match, the
  wake predicate for a broadcast hint, and the target the send path resolved.
  So the PATCH was acknowledged, the new row was visible through the API, and
  delivery kept following the old one until the process restarted. A user
  rotating away from a **compromised webhook URL** kept delivering full events
  to the old receiver; a **narrowed** filter kept delivering the categories and
  event types it removed, which is the security-relevant direction.

  The fix is the one the owner principal already had: the reconcile pass
  publishes the freshly listed row's delivery-shaping fields into an `ArcSwap`
  the running task holds (`DeliveryShape` — `target` and `filter`), on every
  pass rather than only on change, and the task loads it per event where it
  already loads the principal and the RBAC evaluator. One event is therefore
  decided against one consistent snapshot of all three, and a PATCHed target
  or filter takes effect for the next delivered event — within one reconcile
  interval, with no cancel, no respawn and no restart.

  The published value is deliberately a projection of the row and not the row:
  a task owns its own progress, and a republished `last_delivered_position` is
  behind the task's in-memory cursor by up to the 5-minute progress debounce,
  so re-seeding from it would re-deliver that window on every reconcile tick.
  The cursor, the `state` column, the failure budget and the debouncer are not
  reachable from the published type. Unchanged, and now written down: a filter
  change applies **from the cursor forward** — narrowing takes effect for
  everything not yet walked, while widening does not retroactively deliver
  events the task already passed under the narrower filter (inherent to the
  cursor-driven walk, ADR 0061). The target is not re-validated inside the
  delivery walk either: the create/update path validates a webhook target,
  SSRF/DNS guard included, before it is persisted, so a row that reached the
  database was admitted and the hot path owes it no second DNS round trip.

- **A published hort image or chart is now gated on the checks that were
  supposed to secure it** (#339). The public publish path ran three workflows
  that a `v*` tag triggered independently, and none of the publishing jobs
  consumed the others' verdicts — so every gate the repository declared for
  this path was advisory in effect:
  - The container CVE scan declared itself blocking on fixable CRITICALs
    (`exit-code: 1`) and was a **leaf** in the dependency graph: nothing had a
    `needs:` edge onto it, so the manifest merge pushed the tags and
    `cosign sign`ed the digest beside a failing scan. The job's own run summary
    said "informational" while its step comment said "BLOCKING" — both true, of
    the step and of the system respectively. It also scanned only the server's
    amd64 digest, leaving three of the four published digests with no scan
    input at all. The scan is now a prerequisite of the merge, and runs once per
    published image and architecture.
  - `cargo audit`, `cargo deny` and the third-party attribution check ran on
    the tag and no publish job depended on them, so a tagged commit with stale
    attribution, a denied dependency or a fresh advisory could still publish and
    sign. Both public publish workflows now require them. A side effect worth
    knowing: trigger `paths-ignore` filters do not apply to a called workflow,
    so a docs-only tagged commit no longer skips the advisory check before
    publication.
  - A failed SBOM job produced a fully published release without the signed
    SBOM. The release gate now consults that result; a red SBOM leaves the
    release a draft.
  - **Nothing publishes from a ref that is not a release tag.** A manual
    workflow dispatch chose its own ref, and the image tag came from a
    free-form input defaulting to `latest`: a repository writer could build any
    branch and publish a cosign-signed public `latest`, plus a chart whose
    version came from that input with no comparison against the in-tree
    `Chart.yaml`. The release workflow's dispatch path went further — it was not
    ref-gated at all, so it created a real `v*` git tag on a branch commit and
    attached cosign-signed assets to it. Every signing and publishing job now
    requires a `refs/tags/v*` ref, versions are derived from the ref rather than
    from an input, and the surviving inputs are rejected unless they match it.
  - A structural guard (`crates/hort-app/tests/publish_chain_is_gated.rs`)
    holds those edges. It walks *effective* dependencies rather than declared
    ones, because a job whose condition contains `always()` runs even when a
    dependency failed — which is how the SBOM edge came to be listed and
    inert — and it asserts the ref condition per job, because a chain gated
    only at its root makes every removal downstream look correct.

- **A running subscription's admin authority now follows the owner's live
  state** (#339). The notification dispatcher synthesised the owner
  `CallerPrincipal` only when it *spawned* a task — the reconcile loop skipped
  any subscription that already had one — and moved it into the task as a plain
  owned value. The per-event delivery filter then authorized every event against
  two inputs of different ages: the `RbacEvaluator`, reloaded per event and
  swapped by the refresh task every `HORT_RBAC_REFRESH_SECS`, and that
  spawn-frozen principal. Since the privileged-category gate decides
  `Permission::Admin` from the principal's synthetic `"admin"` claim, revoking
  an owner's `User.is_admin` did not stop their running subscription from
  streaming `Policy` / `Admin` / `Authorization` / `User` / `AuthAttempts` /
  `DownloadAudit` / `TokenUse` / `RetentionPolicy` events off-box; nothing
  short of a cancel-and-respawn repaired it, and no reconcile tick caused one.
  Revoked *grants* did take effect, because those travel in the evaluator — the
  admin bit was the single stale input.
  - The principal is now an `ArcSwap` the task loads per event, immediately
    beside the evaluator it is handed to, and the reconcile re-synthesises it
    for every active subscription rather than only for new ones. Both inputs to
    the one authorization decision are now bounded by one refresh cadence — the
    reconcile interval for the principal, `HORT_RBAC_REFRESH_SECS` for the
    evaluator — instead of one of them being fixed for the task's lifetime. No
    new configuration: the existing cadence is adopted, not revised.
  - Revoking `User.is_admin` therefore stops privileged-category delivery to an
    **already-running** subscription within one reconcile interval, with the
    task neither cancelled nor respawned and its delivery cursor untouched.
  - Deactivating an owner (`is_active = false`) now **tears down** that owner's
    already-running subscription tasks at the next reconcile pass. Previously it
    only prevented new spawns, so a deactivated owner's existing tasks kept
    delivering indefinitely. The same teardown applies when the owner row is
    gone or unreadable — fail closed rather than deliver on authority nothing
    could confirm.
  - Cost: one owner read per active subscription per reconcile pass, where the
    loop previously did one per newly active subscription.
    `hort_dispatcher_principal_resolved_total` now increments at that rate, so
    its series track the active-subscription count rather than the spawn rate.

- **A failed OCI blob-upload `PATCH` can no longer grow the staging file past
  the upload cap** (#338). `append_chunk_core` wrote the body to staging and
  advanced the session record's `bytes_received` afterwards, via
  `compare_and_swap`. Three exits sat between the two and left the `.part` file
  longer than the record claimed: a short read on the declared-length path, an
  over-cap body on the unframed-length path, and — the sharpest — a CAS miss,
  where two concurrent `PATCH`es had both already appended and only one bumped
  the record. From then on every further `PATCH` computed the cap against the
  stale, smaller recorded offset, appended again, saw a physical total it could
  not explain and returned `500` — having enlarged the file once more. Repeating
  that drove a single session's staging file arbitrarily far past
  `HORT_OCI_MAX_UPLOAD_BYTES` while the recorded offset never moved; a writer
  authorised to push to one repository reached it with two competing `PATCH`es.
  The finalize-time digest check kept the wrong bytes out of CAS — it does
  nothing about the disk the session fills, which is a denial-of-service against
  every tenant sharing the volume.
  - The fix is at the root the three exits share, not on the three exits. The
    staging port's own concurrency contract already said the OCI use case
    "gates every `PATCH` on an optimistic-concurrency check … via
    `compare_and_swap`" — but the check ran *after* the append, so it gated
    nothing. The claim now comes first: the use case advances `bytes_received`
    to the ceiling of the `PATCH`'s byte budget before a byte reaches staging,
    so the loser of a race is rejected having written nothing and the winner's
    bytes are the only bytes in the file.
  - Because the record moves first it is never smaller than the file, which is
    what takes the physical length out of the authority chain for good: a failed
    `PATCH` leaves the record over-stating staging, and
    `StatefulUploadStagingPort::append_at` — which now writes at the caller's
    asserted offset instead of blindly at the end — refuses the next write as a
    gap rather than appending on top of it. An unframed body's claim reserves the
    remaining cap headroom and settles back down to the bytes that landed, so a
    `Transfer-Encoding: chunked` sequence still appends chunk by chunk.
  - The over-cap signal also left the file: `append_at` takes a byte budget,
    stops at it, and reports "the body wanted more" in its return value. The
    previous form encoded that bit by reading one byte past the cap and letting
    it land, so an over-cap `PATCH` left staging at `max_bytes + 1`.
  - Position-checked writing replaces the adapter's `O_APPEND` open mode, whose
    "every write lands at whatever the current end is" semantics were the
    mechanism the overrun ran on. It also repairs a staging file left long by
    the old ordering: the first write at a recorded offset drops the unaccounted
    tail, which the record never claimed and no finalize could have turned into
    content.

- **`hort-server admin --output=file:<path>` can no longer write a fresh bearer
  into a file whose permissions or type it did not set** (#338).
  `issue-svc-token` and `bootstrap-session` document a 0600 output file and
  opened the path with `create(true).truncate(true).mode(0o600)`.
  `OpenOptionsExt::mode` applies only when a file is *created*, so an existing
  group- or world-readable file at that path kept its own permissions and the
  plaintext token was written into it, and a symlink at that path was followed
  to wherever it pointed. Both states are reachable by any local user who can
  create the path before the mint runs. What leaked is a service-account bearer
  or a full-cap bootstrap admin PAT; the issuance gates (DSN access,
  `HORT_TOKEN_ALLOW_ADMIN`) guard the minting, not this sink.
  - The sink now places the token through an atomic
    `create_new(true).mode(0o600)` sibling temp file + `rename` over the
    target, so the secret only ever reaches an inode the process created at
    0600 and a symlink at the target is **replaced instead of followed**.
    Re-running against the same path still overwrites — what makes the
    overwrite safe is the atomic replace, not a refusal to overwrite.
  - One way, not two: that write form already existed in `hort-cli auth
    login`, which fixed the identical fault class for `~/.hort/config.toml`.
    It now lives once, in a new std-only zero-`hort-*`-dependency leaf crate
    `hort-secret-file` (the shape `hort-attribution` established, ADR 0047 D2 —
    `hort-cli` carries no `hort-domain`/`hort-app`/`hort-adapters-*`
    dependency, so a shared helper cannot live in either), and both sinks call
    it.
  - The shared writer deliberately does **not** create or `chmod` the target's
    parent directory, unlike the `~/.hort/` caller that still tightens its own.
    An operator-named path is not the process's to re-permission: the native
    deployment's default token location is `/etc/hort/tasks-token`, and
    `/etc/hort` is kept `root:hort` 0750 so `hort-server.service` can read the
    env files beside the token — pulling it to 0700 on a mint would break the
    service. The replaced file is owned by the writing process, so a deployment
    that needs another owner (the Ansible timers role chowns the token to its
    run user) still sets it after the write, as it already did.

- **The PyPI simple index no longer interpolates upstream text into the page
  unescaped** (#338). The PEP 503 HTML builder concatenated five dynamic values
  into the document and escaped one of them. An upstream serving a
  `hashes.sha256` shaped `a"></a><a href="https://attacker.example/…` closed the
  `href`, closed the anchor and opened a second one; a standard parser reads
  that as another download link, so the **client's** candidate set changes and
  can point outside Hort's artifact and quarantine path entirely. The same held
  for an upstream-supplied `filename`, which the builder interpolated twice —
  into the URL and into the anchor text. Reaching a proxy repository's index was
  the only prerequisite.
  - Every interpolated value is now escaped — filename (both positions),
    package name, base URL, the PEP 658 metadata hash and `requires-python` —
    so "nothing reaches the output unescaped" is a property a reader confirms
    from one function rather than from an invariant three crates away.
  - The upstream hash is additionally closed **by type**: the index-serving
    `PypiVersionFile::hash_sha256` is now a `ContentHash` rather than a verbatim
    `Option<String>`, so a value that is not a canonical SHA-256 digest cannot
    be represented, let alone served. This loses no verification a client could
    have passed — a non-digest can never match a `hexdigest()` — and an
    upstream that spells a real digest in uppercase is case-folded rather than
    dropped. The upstream-checksum verification path (ADR 0006) reads a
    different struct on the per-version JSON projection and is untouched.
  - `html_escape_attr` is renamed `html_escape`: the five-character set is a
    correct superset for element text too, and the `_attr` suffix made its
    (correct) use on the anchor text read as an oversight. Its inverse in the
    HTML projector is renamed and widened to match, so a Hort proxying a Hort
    recovers the upstream's filename instead of re-escaping an already-escaped
    one — which also fixes that mangling where it reached `files[].url` on the
    JSON arm.

- **Artifact-lifecycle events no longer bypass repository visibility** (#338).
  `GET /api/v1/events?category=artifact` and the subscription delivery filter
  both decided per-event visibility from an `Option<Uuid>` extractor whose
  `None` meant "no repository, therefore visible". Nineteen artifact-stream
  event types return no `repository_id` — they name the artifact, because the
  artifact aggregate owns exactly one repository — so an authenticated account
  with **no `Read` grant anywhere** could read every repository's scanner
  names, severity counts, findings-blob hashes, release justifications and
  operator ids, and an `OwnedByActor` subscription (which needs no read proof
  to create) delivered the same to an external webhook or NATS target. The
  same absent value had the opposite effect on an explicit
  `RepositoryScope::Some([repo])` subscriber, which silently lost that
  repository's entire lifecycle feed: an allow-list cannot match an event that
  names no repository. Both directions are closed by one change.
  - **Resolution, not payload extension.** `EventTypeKind::repository_id` is
    replaced by `EventTypeKind::disclosed_repositories`, which classifies a
    payload exhaustively into *global* (no repository association), one or two
    repository references (carried directly, or named through the artifact /
    artifact-group aggregate), or *unattributable*. Adding a `repository_id`
    field to the nineteen event types would have left every already-stored
    event unprotected and would have altered the canonical bytes of every
    event written before it (`ChainBreak::HashMismatch`, ADR 0002). The fix
    therefore applies to the existing store, with no migration.
  - **One primitive, both call sites.** `hort_app::use_cases::event_visibility`
    holds the classification, the batch resolution and the fail-closed
    dispositions; the read handler and the delivery filter consult it and
    differ only in the gate they then apply. The convention they each
    implemented locally is gone, not patched.
  - **One round trip per page, not per event.** A new
    `EventRepositoryResolver` port resolves a whole page's aggregates in a
    single statement — joins against unnested-array CTEs, never
    `= ANY($1::uuid[])`, whose pooled generic plan degrades to a row-by-row
    scan (1.3 s against 64.2 s on this project's corpus). Resolution is by
    identity and never filtered on liveness, so a purged artifact's events
    stay visible to its own repository's readers.
  - **The promotion chain needs both repositories.** `PromotionRequested` /
    `ApprovalRequested` / `ArtifactPromoted` / `PromotionRejected` disclose a
    source and a target and the served payload carries both identities, so
    `Read` on one of them is not authority to read it.
  - **Unresolvable is admin-only, not invisible.** `CasIntegrityMismatch` is
    keyed on a CAS content hash no single repository owns, and an aggregate
    whose repository was deleted has no row left to resolve; both now require
    live `Permission::Admin` instead of passing through.
  - Two tests that pinned the bypass as the intended contract
    (`non_privileged_category_none_repo_event_unchanged_for_non_admin`,
    `all_scope_event_without_repo_skips_authz`) are renamed and inverted
    rather than deleted, so the inversion is visible as one.

- **No path that mints an artifact writes a content-reference edge after the
  fact any more** (#335). The last three writers — the OCI manifest PUT's
  `oci_config` / `oci_layer` / `oci_index_member` membership edges, both
  pull-through leader legs, and the coalesced follower — now carry their edges
  into the minting transaction as claims. A `content_references` row is what
  keeps bytes out of the storage GC (it deletes a CAS blob exactly when no row
  targets its hash), and for a manifest's *tree* edges the target is another
  artifact's content, which nothing re-derives: the refcount-reconcile sweep
  converges `primary_content` / `metadata_blob` from the artifact row, and no
  relational row records what a manifest references. Every one of these was
  `warn!`-and-continue, so a failure served a live, servable manifest whose
  config, layers or children had one fewer claim.
  - **The manifest PUT** resolves its declared references **before** the mint
    and builds the membership claims only from a complete resolution. That
    answers the ordering question in full rather than trading one risk for
    another: an edge can never name a blob the repository does not hold (those
    kinds feed the referenced-tree-descendant predicate, so one that did would
    hand the blob's own later ingest a zero-window quarantine carve-out it did
    not earn), and the unknown-blob 400 still answers *after* the mint, so a
    manifest referencing blobs the client has not pushed yet stays committed
    for the retry exactly as ADR 0043 requires — it simply claims nothing.
  - **The two pull-through leader legs** read the cached manifest body once,
    into memory, **before** the ingest instead of re-reading the tempfile
    after it, derive the claims from that copy and hand them to
    `ingest_verified`. The eager child-ingest enqueue and the prefetch trigger
    read the same copy and stay post-commit — they are `jobs` rows and
    scheduling hints, not claims on bytes.
  - **The coalesced follower** reads the manifest out of CAS before minting
    its own per-repo row, keyed on the content hash rather than on an artifact
    id it does not have yet, and passes the claims on
    `RegisterExistingCasBlobRequest`.
  - Pull-through deliberately keeps claiming **by digest with no existence
    check**: that edge is the mechanism behind the zero-window anchor for a
    proxy descendant (ADR 0007), and a proxied constituent legitimately is not
    present yet. Only the atomicity changed, not when an edge is written.
  - One **observable change on an error path**: a manifest body whose
    reference parse fails (a malformed `config.digest`, an over-cap index) is
    no longer minted. The parse has to precede the mint for its claims to ride
    the transaction, and the client sees the same 400 `MANIFEST_INVALID`
    either way — what it no longer leaves behind is an artifact row for a body
    hort refused. The *unknown-blob* contract is untouched.
  Evidence per site is the rollback: an injected insert failure asserting that
  neither the referrer nor its events survive, each paired with a success pin
  showing one lifecycle call carries the referrer and its whole edge set. The
  two backfill handlers are now the only production callers that insert an edge
  after its referrer committed, which is their purpose — they repair referrers
  that committed edgeless in an earlier release. No backfill, no migration, no
  repair of existing edgeless rows.

- **The three remaining content-reference writers now commit their edge in the
  transaction that makes the claiming artifact live** (#335), completing the
  work the ingest-mint path started. A `content_references` row is not a
  projection that may lag: the storage GC deletes a CAS blob exactly when no
  row targets its hash, so an edge written after its referrer committed is a
  window in which the claim does not exist and the bytes are collectable, with
  the referrer already live and unable to re-assert it.
  - `register_by_hash_inner` (the OCI cross-repo blob mount, the coalesced
    pull-through follower, and the seed-import cutover) wrote its
    `primary_content` edge after a plain `commit_transition`, warn-and-continue
    on failure. It mints a per-repo row over a CAS blob the source
    repository's artifact already holds, so without that edge the new artifact
    counted **zero** against bytes CAS shares with the source: release and
    purge that sibling and the count reached zero with the new row still live
    and servable. The genesis commit now carries the edge.
  - The OCI manifest PUT's `oci_subject` edge is derived from the parsed body
    before the mint and handed to the ingest as a claim, so the referrer and
    the row that keeps its subject's bytes alive commit together. This one is
    sharper than `primary_content`: the target is **another** artifact's
    content, and the refcount-reconcile sweep cannot repair it — it converges
    `primary_content` / `metadata_blob` from the artifact row, and no
    relational row records what a manifest references.
  - The eager index-child ingest (`oci-index-child-ingest`) derived its
    `oci_config` / `oci_layer` / `oci_index_member` edges after the child
    manifest was committed and inserted them one at a time, non-fatally. The
    derivation moved ahead of the ingest — it only ever needed the fetched body
    and the digest the ingest is keyed on — and the edges now ride the child's
    transition. The handler no longer holds a content-reference port at all, so
    there is nothing there that could write one afterwards. A failed edge fails
    the unit; the `jobs` row is retried, where a committed manifest with a
    missing claim was only repairable by re-reading manifest bodies out of CAS.
  - `ingest_signature_manifest` also gains the `primary_content` edge it never
    wrote: a pushed cosign signature manifest commits status-`None`, outside
    the scan/quarantine lifecycle and therefore outside the GC's
    protected-evidence rule, so its own bytes counted zero against themselves
    until the next reconcile sweep converged them.
  - A fourth writer the sweep for this change turned up: the provenance
    orchestrator's upstream-referrer landing
    (`ProvenanceOrchestrationUseCase::commit_referrer_manifest`, the inlined
    twin of the primitive above) likewise minted its referrer manifest with no
    edge at all and inserted the `oci_subject` row afterwards. Both now ride
    its transition. It had no obstacle of its own, and leaving the inlined
    copy unconverted while converting the primitive it mirrors is exactly the
    drift this audit keeps finding.
  Evidence is the rollback, not the end state: per edge, a test injects an
  insert failure and asserts that **neither** the referrer **nor** its events
  survive, each paired with a success pin showing one lifecycle call carries
  both. No backfill, no migration, no repair of existing edgeless rows; the
  refcount reconcile and its in-process gate are untouched. **Still open and
  carrying the same hazard**: the OCI manifest PUT's membership edges
  (`oci_config` / `oci_layer` / `oci_index_member`) and the pull-through leg's
  post-ingest registration of the same. The manifest-PUT pair is blocked on a
  decision, not on mechanism: claiming those edges before the manifest's
  blob-existence gate would let an edge name a blob the repository does not
  hold, and those kinds feed the referenced-tree-descendant predicate, so the
  blob's own later ingest would take the zero-window quarantine carve-out —
  while moving the gate ahead of the mint reverses the deliberate contract that
  an unknown-blob manifest stays committed for the client's retry. Both
  functions now document that trade-off in place.

- **An ingested artifact's claim on its own bytes now commits in the same
  transaction as the artifact** (#335). The storage GC deletes a CAS blob
  exactly when no `content_references` row targets its hash, so the
  `primary_content` edge is not a projection that may lag — it is the claim
  that keeps the bytes alive. The ingest committed the artifact and wrote the
  edge **afterwards**, in a step allowed to fail without failing the ingest,
  and the comment over `write_ingest_refcounts` justified that with a claim
  that reads backwards: "a missing refcount row only delays GC, it doesn't
  break correctness". It delays nothing. The artifact counted **zero** against
  its own content, and because CAS deduplicates, a released sibling carrying
  the same bytes drove the observed count to zero — leaving a live, servable
  artifact pointing at bytes the sweep was authorised to delete. The bracket
  already existed: `commit_transition_with_enqueues` was writing four things
  atomically (events, artifact row, metadata, job-queue rows) behind the port
  boundary, with the edge standing just outside it. All three ingest-mint
  edges now ride it — `primary_content`, `metadata_blob`, and the PEP 658
  `wheel_metadata`, whose extraction moved **ahead** of the commit because it
  only ever needed the bytes the primary `storage.put` had already placed in
  CAS, so its edge belongs in the transition that creates the artifact
  claiming them rather than in a second one. A failed edge now fails the
  ingest: the upload is retriable, an edgeless committed artifact is not. The
  edge upsert is idempotent on the full primary key, which is what keeps the
  adapter's existing contention retry re-runnable, and the blob-reclamation
  locks for a transition's several targets are taken up front in one total
  order, so two overlapping ingests sharing targets cannot each hold the
  other's next lock. No backfill and no migration: existing edgeless rows stay
  the operator reconcile's business, and the reconcile and its in-process gate
  are untouched. **Still open, deliberately out of this change**:
  `register_by_hash_inner`'s own `primary_content` edge (the OCI cross-repo
  mount and pull-dedup follower path) and the two OCI manifest-write edges
  (`oci_subject`, `oci_index_member`) still write beside their transitions and
  carry the same hazard. The `register_by_hash_inner` comment, which deferred
  to the inverted rationale above, now states the hazard instead, so nothing
  in the tree claims a missing edge merely postpones collection.

- **An event-stream seal now carries the version its own proof was read at**
  (#335). `EventStoreRetentionUseCase` proves an artifact stream's tail is
  `ArtifactPurged` and that the retention floor has elapsed, then calls
  `delete_stream`, which opened a **new** transaction, re-read the head without
  `FOR UPDATE`, wrote the `StreamSealed` tombstone to the audit-meta stream and
  deleted every row of the target stream — without re-checking terminality or
  the floor at any point. A late `ArtifactExpired` (the retention evaluation
  appends with `ExpectedVersion::Any` against a candidate it read earlier) had
  two windows: landing before the seal's head read, a stream that was no longer
  terminal was deleted under a tombstone that described it perfectly; landing
  between that read and the `DELETE`, the tombstone recorded the old head while
  the new event was removed with the rest. ADR 0020 does not cover this — its
  single-flight serializes seal jobs against each other, not a seal against an
  append — and no lock could: the append path takes none either, relying on the
  `(stream_id, stream_position)` unique index that `004_events.sql` calls
  "Optimistic concurrency". Closed the way #334 closed the same shape one layer
  up, by pairing the decision with the version that authorizes it:
  `delete_stream` / `archive_stream` now take a `SealAuthority` — the
  `stream_position` of the tail the caller's proof read — and answer
  `SealOutcome::NotAtProvenVersion` instead of removing anything when the
  stream has moved. The `DELETE` itself carries the condition as a predicate,
  because a re-check phrased as its own statement cannot see an append that
  commits before it (read-committed gives every statement a fresh snapshot),
  and its row count is compared against the count the tombstone claims — the
  predicate stops the removal, the comparison is what turns the stop into a
  rolled-back refusal rather than a committed tombstone over an intact stream.
  The authority is one observation with the verdict it belongs to: the
  terminal-proof read's own tail row for `TerminalGated`, and the enumeration
  row's new `last_stream_position` for `AgeGated` categories, which perform no
  proof read and whose rotated audit streams were open to the same defect from
  the other end. The refusal is a skip (`skipped_stream_changed`), never an
  error: nothing failed and nothing was removed, so a late event must not make
  a healthy sweep read as broken. Deliberately still open and documented at the
  `seal_and_remove` chokepoint: an append committing *after* the `DELETE`'s
  snapshot survives as a live event following a `SealedGap`, because no
  mechanism inside one transaction reaches past its own commit.

- **The purge no longer decides from a page row it read before it started
  deleting** (#335). The storage-GC sweep reads a page of pending work items
  and then walks it, and both protection rules — retained scan evidence is
  never collected, a `KeepLastN` tag target is exempt — were evaluated against
  that page row. Between the page read and a given item's destructive step lies
  the complete processing of every item ahead of it, storage deletes included:
  the longest interval in the sweep, not the shortest. A scan verdict moving an
  artifact to `rejected` inside that window, or a tag landing on a `KeepLastN`
  target, was not seen. `purge_artifact_refs` already locked the artifact row
  (`SELECT … FOR UPDATE`) but read only `checksum_sha256` under it and deleted
  the `content_references` edges unconditionally — the lock was there, nothing
  load-bearing was read under it. Worse, the comment at the tag check claimed
  the fact was re-read "immediately before deleting" and that "the last reader
  before the destructive step is the one that decides"; neither was true, and a
  false assurance in a comment is the same defect as one in code with a longer
  half-life. Closed by reading all four facts in that same `FOR UPDATE`
  statement — `quarantine_status` against the one shared
  `gc_protected_quarantine_status_names`, the tag fact through the one shared
  `ARTIFACT_IS_TAG_TARGETED_SQL` the page query and the evaluator already use,
  and the two expiry-stream facts through predicates now likewise spelled once
  — and refusing there: the transaction ends with no `DELETE`, no worklist row
  and no event, so the work item stays pending and the next sweep re-reads
  everything. The composite rule is unchanged and now has exactly one author
  (`PendingPurge::is_gc_protected` / `::is_tag_exempt`, which both readers
  call). A refusal arrives as its own value on the new `PurgePreparation`
  outcome rather than as the empty worklist that already meant "there is no
  such artifact row", and the sweep counts the two readers apart
  (`skipped_protected_under_lock` / `skipped_tag_exempt_under_lock` beside the
  existing steady-state counters) because a protection holding inside the
  sweep's own window is a far rarer signal than a protected artifact being
  skipped again. The use case's checks over the page row stay, as what they
  always were: a pre-exit that saves taking the lock. Unchanged by design: once
  a worklist exists the edges are already gone, so a retry returns it without
  consulting the facts — declining then would strand a purge that can never
  finish, and from that point the hash-level claim check protects the bytes.

- **Garbage collection no longer deletes quarantined evidence's bytes through a
  released sibling** (#335). GC protection was a property of the *artifact* and
  reclamation a property of the *bytes*, with nothing joining the two.
  `GC_PROTECTED_QUARANTINE_STATUSES` (`quarantined` / `rejected` /
  `scan_indeterminate`) is bound at three sites and protected at only two:
  `list_pending_purge` never offers such an artifact as a purge candidate and
  the retention candidate reader never expires one — but `refcount_reconcile`
  deliberately mints it **no** `content_references` edge, precisely so a
  repaired refcount cannot make a quarantined blob look GC-protected for the
  wrong reason. Reclamation decides on hashes: `begin_blob_reclaim` counted
  `content_references` rows for the target hash, so a protected artifact
  contributed **zero** to the count of its own content. When a released sibling
  sharing that hash expired, the sweep read `0` under the blob lock, took a
  `Granted` lease and deleted the shared CAS object. The protected artifact was
  never a candidate for anything and its bytes were gone — retained scan
  evidence destroyed with every filter working as written. Closed by asking,
  under the already-held blob lock and only on the path that would otherwise
  delete, whether any non-deleted GC-protected artifact claims the hash — as
  its primary content (`artifacts.checksum_sha256`) **or** as its metadata blob
  (`artifact_metadata.metadata_blob`, a different table, trimmed the same way
  `refcount_reconcile` trims it), with the status list bound from the one
  shared `gc_protected_quarantine_status_names` rather than a second literal.
  A claim yields the new terminal `BlobReclaim::ProtectedClaim { claimants }`
  — a *keep*, not a deferral: a `rejected` artifact is permanent, so re-asking
  would never answer differently and the sibling's purge would never finish.
  The reconcile exclusion is untouched. `ArtifactPurged.refs_remaining`
  consequently means **claims on these bytes observed under the lock** —
  `content_references` rows, or, when there are none, the protected artifacts
  holding the hash — so `0 ⇒ the blob was deleted` stays true on every path
  that emits it; no event field was added.

- **A one-hour break-glass credential can no longer compose into a 30-day
  standing full-admin one** (#334). `admin bootstrap-session` is deliberately
  short: it demands operator-level Postgres (DSN) access *and*
  `HORT_TOKEN_ALLOW_ADMIN=true`, reuses the reserved non-service-account
  `bootstrap-admin` principal, revokes the prior bootstrap token, and clamps
  the full-cap admin PAT it issues to **one hour**. With the server process
  carrying the same `HORT_TOKEN_ALLOW_ADMIN=true`, that one-hour credential was
  accepted by the public authenticated self-mint route
  (`POST /api/v1/users/me/tokens`), whose admin gate checks only the flag and
  the admin principal — the break-glass user is deliberately not a service
  account, so the one refusal on that path did not reach it — and then permits
  an explicit admin-PAT expiry of **1 to 30 days**. The derived PAT carried an
  operator-chosen name, while the next bootstrap run looked only for the
  reserved name `bootstrap-session` in the *first page* of the principal's
  tokens, so nothing ever revoked it. Possession of the hour-long credential
  therefore yielded a 30-day full-admin credential needing no further DSN
  access. Each half was separately accepted and separately tested —
  `docs/auth-catalog.md` Entry 2 permits the 30-day admin PAT, ADR 0038
  describes bootstrap as the short-lived path with no standing admin — and the
  defect was the composition, which is what ADR 0016's cross-opt-in matrix
  exists to catch; the matrix had never been applied to the auth opt-ins and
  now carries a second axis for credential-authority gates. **ADR 0038 governs
  a bootstrap-derived PAT** (decided 2026-10-03): the shared issuance gates now
  refuse any issuance whose token *owner* is the reserved identity
  (`403 bootstrap_admin_mint_forbidden`) — a rejection, not a shortened expiry
  and not a warning, anchored on the owner rather than the route so a future
  issuance route inherits it, and keyed on the row's `UNIQUE`, unwritable
  username rather than on a token label. Independently, bootstrap rotation now
  revokes **every** live token the principal owns, across every page, instead of
  the one matching the reserved name: a name is operator-chosen and says nothing
  about ownership. The general admin-PAT feature, its 1-30 day window, and the
  bootstrap one-hour clamp are unchanged — only the break-glass principal's
  reach into the self-mint route. The `admin bootstrap-session` CLI mint is the
  one path that still issues for that identity, and it is the only one that
  carries both bounds.

- **An `Exclusion` scoped to a repository is now refused by every writer, not
  silently applied to all of them** (#334). `scope: { repository: <name> }` was
  accepted by the gitops apply and by
  `POST /api/v1/admin/policies/:id/exclusions`, recorded on the
  `ExclusionAdded` event, stored on the projection and rendered by the
  exclusions listing — and never read. The finding filter matches on
  `expires_at`, `cve_id` and `package_pattern` only; it could not read the
  scope, because the artifact coordinates it matches against carry no
  repository identity. So a CVE waiver an operator narrowed to one repository
  cleared that CVE for **every** repository the parent policy governed: the
  edit read as a narrowing and acted as a widening, with the
  post-exclusion re-evaluation cascade releasing artifacts across all of them.
  Both writers now refuse it — the gitops path before its first write
  (`exclusion_scope_not_implemented`, also reported offline by
  `hort-server validate-config`), and the HTTP path in
  `PolicyUseCase::add_exclusion`, which every inbound writer passes through.
  `scope: global` applies exactly as before. To waive a CVE for one repository,
  scope the parent `ScanPolicy` to it — a policy scope *is* enforced.
  **Rows stored before this release keep their scope and keep acting
  globally**; nothing rewrites them. Removing one is refused nowhere — only
  writing one is: dropping the envelope from the declared tree removes it, and
  so does the HTTP `DELETE`. The removal is the direction that withdraws an
  assurance nothing honoured, and it re-rejects findings in every repository
  the parent policy governs rather than only the one the scope named, which
  the server logs (policy id, CVE, the stored repository id, the rationale) as
  it removes the row.

- **A `ScanPolicy.licensePolicy` is now refused at apply instead of accepted
  and ignored** (#334). The scan path dispatches to the licence evaluator with
  a hard-coded **empty** licence list — no port surfaces an artifact's
  licences — so a well-formed `{denied_licenses: [GPL-3.0], action: Block}`
  compared its denied set against zero licences, produced zero violations, and
  left the scan clean whatever the artifact was licensed under, while the
  operator who wrote it believed releases were gated on licence compliance.
  The field is now rejected unless it is `{}` or omitted (the evaluator's own
  "no policy declared" short-circuit, and what every shipped example tree
  writes), with a message that says the control is not implemented so nobody
  retries with a different value
  (`scan_policy_license_policy_not_implemented`). A projection stored before
  this release keeps its value and keeps deciding nothing.

- **A `virtualMembers` entry on another format is now refused at apply**
  (#334). Nothing compared a member's `format` with its virtual repository's:
  cross-document validation required each member to be declared and
  non-virtual, the per-envelope validator checked only the virtual's *own*
  format, and serve-time `resolve_members` re-checked Read visibility and
  repository type. So a `pypi` hosted repository could be a member of an `npm`
  virtual — and because a non-proxy member *owns* the names it holds (ADR 0031
  name-level pinning), it would suppress the virtual's npm proxy for every name
  it held while serving nothing an npm client can install. Such a member is now
  rejected, naming both formats
  (`virtual_member_format_not_enforced`). A format-homogeneous virtual —
  every shipped example tree — applies exactly as before; a cross-format
  aggregate is one virtual per format.

- **A `ScanPolicy.maxArtifactAge` is now refused at apply instead of accepted
  and never read** (#334). The cap travelled the whole configuration path —
  parsed, format-validated, converted to `max_artifact_age_secs`, diffed
  field-by-field, event-sourced onto the policy stream, persisted, and written
  into both the config snapshot and drift detection — and was read by nothing
  that decides. The evaluator exists
  (`hort_domain::policy::evaluate_age_gates`, which turns an exceeded cap into
  a `Medium` `max-artifact-age` violation) and had **no production caller**:
  no scan-result evaluation, no release decision and no retention pass ever
  asked the question. So an operator who wrote `maxArtifactAge: 90d` declared
  a staleness cap, could read it back from the policy and saw it in the
  snapshot — while every artifact older than the cap kept passing every gate.
  Any declared duration is now rejected
  (`scan_policy_max_artifact_age_not_implemented`); the inert state is the
  absent field, and unlike `licensePolicy` there is no accepted *value*,
  because `None` is the only thing the evaluator reads as "no cap". `0s` is
  refused exactly like `90d` — the rejection is the missing consumer, not the
  number. The humantime format check stays, so a malformed duration is still a
  per-envelope error. The evaluator is deliberately **not** deleted: it is the
  implementation this row is held open for, and the row's retirement trigger
  names the condition that removes the row again. A projection stored before
  this release keeps its `max_artifact_age_secs` and keeps deciding nothing.
  The `max-artifact-age` policy-violation metric key stays in its closed label
  set — it is the domain's stable rule id — but the catalog no longer claims
  the promotion gate emits it.

All four are the [ADR 0015](docs/adr/0015-apply-time-linter-inert-fields-and-naming.md)
accepted-at-apply-inert-at-runtime block, closed the way that ADR prescribes:
a fail-closed apply-time rejection that points the operator at the missing
enforcement, rather than removing the operator surface. The full set of named
lint rows, each row's retirement trigger, and — separately — where the
surfaces with *no* named row are actually validated is now a reference page:
[`docs/architecture/reference/apply-time-linter-rows.md`](docs/architecture/reference/apply-time-linter-rows.md).
`maxArtifactAge` is the surface that page found with neither a row nor a
consumer, closed as its row 13.

## [0.14.0] - 2026-09-20

### Added

- **A scan policy can no longer pair a scanner with a format it cannot
  analyse** (#259). Which backend produces a verdict for which repository
  format is a fixed property of the build — `trivy` reads the payload and
  covers every format it can materialise; `osv` reads only the payload
  SBOM, so it covers `npm`, `pypi`, `cargo` and `maven`, but not `oci`,
  which exposes no SBOM. Until now a `ScanPolicy` could name `osv` over an
  OCI repository and Hort accepted it: the policy read as two scan
  authorities and one of them analysed nothing, every artifact there being
  held rather than scanned. That map is now written down, backed by a test
  per cell in which a known-vulnerable fixture yields a real finding, and a
  guard asserts the record and the scanners themselves can never disagree.

  **`hort validate-config` and gitops apply now reject the inert pairing**,
  in one of two shapes: a backend that cannot analyse a governed
  repository's format (the message names the pairing and the backends that
  *do* cover it), or a repository whose format no compiled-in backend
  covers at all (the message points at the explicit waiver). What is
  checked is the pairing the runtime will actually form: a repo-scoped
  policy wins over a global one, so a global policy is never rejected for a
  repository that declares its own. `scanBackends: []` is untouched — it is
  the operator's explicit "do not scan this repository", a decision rather
  than an inert pairing.

  **Operator action, one shape only:** a **global** `scanBackends: [trivy,
  osv]` over a deployment that also serves OCI repositories will be
  rejected at the next apply. Split it into a global `[trivy]` plus
  per-repository policies adding `osv` where the format has an SBOM
  (`npm` / `pypi` / `cargo` / `maven`); note that a repo-scoped policy
  replaces the global one rather than merging with it, so the scoped policy
  repeats the settings. The shipped alpha-fixture tree is the worked
  example. No other pairing in any shipped or documented configuration
  changes.

  At scan time the worker consults the same map before invoking a backend,
  which covers what apply-time rejection cannot reach — a repository with
  no policy at all falling back to the built-in default, or a policy that
  predates the rule. Such a backend is no longer invoked at all (no
  download, no unpack, no scanner process), and the run records why:
  `hort_scan_record_outcome_failures_total{result="inert_pairing"}` when
  another backend covers the format, which keeps the artifact held exactly
  as before while naming the pairing as the thing to fix.

- **Prefetch now works on Maven repositories** (#233). A Maven proxy could
  already be configured with `prefetchPolicy.triggers: [scheduled]` and the
  configuration was accepted, but nothing happened at run time: the scheduled
  tick had no way to compare two Maven versions, so it skipped the repository
  without a word. It now reads the upstream's `maven-metadata.xml`, compares
  versions with Maven's own version-ordering rules (so `1.10.0` is newer than
  `1.9.0`, which a naive text comparison gets backwards), and warms the newest
  releases like any other format. `hort-cli prefetch` against a Maven
  repository works the same way, including resolving "the latest version" when
  none is given — previously it was refused as an unsupported format.

  Which formats can be prefetched is now decided in exactly one place instead
  of three, and a test enforces that a format able to discover upstream
  versions can always order them. That pairing is what a repository's accepted
  prefetch policy rests on, so it can no longer be half-configured: a policy
  Hort accepts is a policy Hort acts on. In the impossible case that the two
  halves are ever changed apart, the tick now says so loudly and increments
  `hort_prefetch_ordering_missing_total` rather than skipping in silence.

- **A proxied multi-arch image index now starts its children's quarantine
  windows at index ingest, not at first client access** (#229). Pulling a
  multi-arch image through a proxy repository ingests the image index and
  records the child manifests it declares — but until now those children were
  fetched only when a client later asked for one, so the index's observation
  window and each child's ran back to back. A base-image bump therefore cost
  two full windows before the image was pullable. Every pull-through leg that
  mints an index artifact — a pull by digest, a pull by tag, and a
  request coalesced behind another repository's pull — now queues one
  background ingest per declared child, so the windows run concurrently and the
  image becomes pullable roughly a window sooner.

  **No window is shortened.** Each child is held on ingest exactly as it would
  have been on a later client pull, and its window is anchored the same way it
  would have been then; a window that would have started tomorrow simply starts
  today. Every child still needs its own window *and* its own scan verdict to
  release, and releasing an index still does not release a held child. The
  children are fetched by the worker, off the request path: an index pull's
  own response is unchanged, and if the queue is unavailable the child simply
  falls back to being fetched on first access as before. Eager child ingest is
  unconditional — an index's children are the declared contents of the artifact
  a client just asked for, not speculation — and adds no configuration.

  **The fan-out is bounded.** A child that is itself an index queues its own
  children, so a nested chain could otherwise grow without limit from a single
  client pull of a pathological upstream. Alongside the existing per-index
  child cap, the recursion now stops after four levels — real image trees nest
  one — and says so in the log; children below the cap are not lost, they are
  simply fetched on first access as before. Both bounds are fixed internal
  limits, not settings: there is nothing here for an operator to tune.

- **An npm packument now says which versions Hort is holding, instead of
  leaving them looking as if they never existed** (#251). Two surfaces of the
  same registry used to contradict each other. Asking for a held version's
  tarball returned `503` with a `Retry-After` — the truth. Asking the catalog
  what versions exist left it out of `versions{}` and out of `dist-tags`, so
  anyone checking concluded the version was missing upstream. In production
  that cost two days: a pinned `package-lock.json` install failed, and every
  human who then read the packument drew the wrong conclusion.

  The packument now carries an additional top-level `hort` block naming each
  withheld version, why it is withheld, and — for a version inside its
  observation window — when the hold lifts:

  ```json
  "hort": { "held": [ { "version": "7.29.7", "status": "quarantined",
                        "available_after": "2026-08-26T08:18:00Z" } ] }
  ```

  `status` distinguishes a version that is *waiting* (`quarantined`) from one a
  scan verdict went against (`rejected`, `scan_indeterminate`) — telling a
  client to wait for a rejected version would be a lie in the other direction,
  so those carry no deadline at all. `available_after` is computed from the
  same window the tarball route's `Retry-After` counts down to, so the two
  answers cannot drift; where Hort cannot compute it the field is absent rather
  than guessed. The whole block is omitted when nothing is held, so an ordinary
  packument does not grow a key.

  **Nothing about resolution changes.** `versions{}` and `dist-tags` come out
  byte-identical to before, and the per-version route still refuses a held
  version, so a version range, a bare `npm install` or `latest` still cannot
  resolve to something that would `503`. That is the reason the versions are
  withheld in the first place; the block only stops the catalog being silent
  about it. `npm-pull-through.md` now documents the whole diagnosis path,
  including how to tell a `503` (Hort has it, briefly) from a `404` (nobody
  published it).

### Changed

- **SBOM extraction from the stored payload now runs for proxy, virtual and
  staging repositories as well, not just hosted ones** (#266). A format that
  derives its SBOM from the artifact's own payload — cargo's embedded
  `Cargo.lock` today — previously read that payload only for artifacts in a
  `Hosted` repository, so a proxy with no metadata fallback (a Maven proxy,
  for instance) got no SBOM at all: `osv` scanned nothing while the
  repository's policy still claimed a threat level. The scanner now delivers
  what the repository configuration declares for every repository class the
  handler applies to; whether a finding against it blocks a release is
  `enforcement`'s decision, not the scanner's. `enforcement: record` is the
  recommended mode on proxied lockfile-resolving formats, since there a
  resolved component names the upstream author's dev-time resolve rather than
  the consumer's own build. See `docs/adr/0056-resolved-component-sboms-from-payload.md`'s
  amendment.

- **A signature that arrives late will no longer cost you the artifact**
  (#242) — recorded as a standing decision; the enforcement change follows. Under
  `provenanceMode: required`, an artifact whose signature had not reached Hort
  by the end of its observation window was rejected permanently, and no later
  successful verification could lift it — while with `cosign` the signature
  always follows the image it signs, so a short `quarantineDuration` (a
  sensible *exposure* choice for first-party CI, and nothing in its name says
  it also bounds how long signing may take) silently doubled as a signing
  deadline. The decision now says such an artifact is **held** — still
  unpullable, still fail-closed — for as long as it takes, and that only a
  signature which is present and invalid is ever terminal. See
  `docs/adr/0039-keyed-provenance-verification.md`.

- **Rolling a release back no longer requires rolling the schema back with
  it** (#226). Every start of `hort-server` and `hort-worker` re-runs the
  migration step with the installed binary, and the serving binary
  separately re-checked the schema version at boot. Both refused any schema
  newer than the binary, so a deployment that had applied even a purely
  additive migration could not be rolled back to the previous release: the
  older binary would not start, although the expand/contract discipline
  guarantees it serves that schema correctly. Both checks now ask the same
  question — is this schema one this binary supports? — and a schema that is
  merely newer is accepted, logged as a warning so an operator can see the
  fleet is not on the schema's own release.

  **The strictness that mattered is kept.** A schema *older* than the binary
  is still the normal upgrade path (the migrations get applied), and a
  genuinely broken history — a recorded migration the binary does not know
  sitting below ones it does, or a migration missing from the middle of the
  applied sequence — is still refused by both checks, now naming the
  offending versions in the refusal. Checksum verification of the migrations
  the two sides share is unchanged and still aborts a mismatch.

  **How far back a rollback may go is now answered from the schema itself,
  not assumed** (#226). An older binary fails against a newer schema for
  exactly one reason: one of the migrations it does not carry removed
  something it still references. Migrations that only add are harmless
  however many of them there are, so five releases without a removal are as
  safe as one, and a fixed "one release back" bound would refuse rollbacks
  that are provably fine. Applying a migration now records, in the database,
  the oldest release that migration tolerates — taken from the destructive-DDL
  manifest the applying release ships — and both boot checks read those
  records back for exactly the migrations they do not carry. A binary old
  enough to be affected is refused, and the refusal names the migration that
  blocks it and the version it would work from; anything else starts,
  whatever the distance. A migration with no record at all is treated as one
  that removed something: silence is not evidence. Every start also reports
  how far back the current schema tolerates a binary, alongside the schema
  versions it already logged — the question a rollback decision turns on and
  that nothing could answer before.

- **The prefetch-row retention sweep now also collects the background
  index-child ingest's finished rows** (#229). `prefetch-row-retention-sweep`
  previously covered only the transitive prefetch cascade, so the new
  per-child ingest rows would have been kept forever. They are the same kind
  of work — high-churn, best-effort, holding nothing durable — and re-running
  a collected one is a no-op rather than a re-fetch, so they ride the same
  sweep rather than getting one of their own.

- **The prefetch-row retention sweep now ships enabled** (#229).
  `scheduledTasks.prefetchRowRetentionSweep.enabled` defaulted to `false` on
  the reasoning that the transitive prefetch cascade is opt-in per repository,
  so a deployment that never opted in accumulated nothing for the sweep to
  collect. That stopped being true once the background index-child ingest's
  rows joined it: those accrue on any OCI proxy repository with no opt-in at
  all, one per declared child manifest per image-index pull. A retention fix
  that only reaches operators who had already enabled a sweep for an unrelated
  feature is not a fix, so the default flips — the same day-one-rows reasoning
  that has the scan-row sweep shipping enabled. **Both deployment flavours
  move**: the Helm chart's `scheduledTasks.prefetchRowRetentionSweep.enabled`
  and the Ansible role's `prefetch-row-retention-sweep` timer, which was
  disabled for the same reason and additionally filed under "needs extra
  infrastructure" although it needs none. An operator using neither feature
  gains one idle scheduled task whose delete matches nothing. Operators who had
  explicitly set the value keep whatever they set.

### Fixed

- **`osv` no longer returns a clean verdict for an artifact it never
  examined** (#259). The OSV backend adjudicates the payload SBOM and
  nothing else, and when no SBOM was available it returned an empty
  finding set — which is the value that *means* "examined, found nothing
  wrong". An `oci` artifact under a policy naming `osv` therefore earned a
  clean scan verdict from a backend that had read none of its bytes, and
  that verdict carried release authority. It now abstains instead: no
  verdict, recorded as not-applicable, and release rests on whatever
  backend actually looked (`trivy` for OCI). Deployments whose OCI policies
  name only `osv` will see those artifacts held rather than released — the
  apply-time rejection above is what stops that configuration being
  written in the first place.

- **An empty Trivy report over a fully materialised root filesystem is now
  "nothing to assess", not a hold** (#274). Staging UAT surfaced a
  `nginx:alpine` pull through a Trivy policy where the base layer scanned
  and released normally but a package-less layer (the image's
  CA-certificate files, no OS package database) never did: Trivy's
  `rootfs` target came back with no analysed target, which the adapter
  read the same way regardless of which target produced it — an
  *unassessed* surface, held `scan_indeterminate` forever. Nearly every
  real multi-layer image carries a layer like this, so every such image
  under a Trivy policy hung indefinitely. `rootfs` runs every OS-package,
  language and binary analyzer over the whole extracted tree, so an empty
  result there is those analyzers agreeing the tree has no package surface
  at all — the same completed "not applicable" fact an OCI manifest or
  config blob already records, reached this time by actually running the
  scan. An `fs`-mode empty report is unchanged: that target is one
  artifact whose analyzer either engages or does not, so it still holds as
  an unassessed surface.

- **A policy created with `enforcement: record` now records from its first
  apply** (#267). `create_policy` built the rest of the policy projection
  from the submitted command but hard-coded `enforcement` to `reject`, so a
  freshly-applied `record` policy enforced `reject` until a later apply
  diffed and corrected it. The projection now takes `enforcement` from the
  command like every other field.
- **OSV scanning now covers Maven artifacts** (#265). `scan_backends:
  ["osv"]` on a Maven repository was accepted at apply time but scanned
  nothing at run time — the Maven format handler had every piece the
  scanner needed (the POM reader, the coordinates, the `Maven` ecosystem,
  the `maven` purl type) but never wired them into an SBOM, so
  `OsvScanner::scan` always logged "scan skipped — no SBOM provided" and
  moved on. A published `.pom` now yields its declared compile- and
  runtime-scope dependencies as scannable components, and a `.jar`/`.war`
  yields the same from its embedded `META-INF/maven/{groupId}/{artifactId}/pom.xml`
  when present; either way the artifact's own coordinate is always in the
  SBOM as the subject, so osv-scanner can flag the artifact itself even
  when its dependency versions cannot be resolved from the POM alone (a
  version inherited from a parent POM or an imported BOM, for instance).

- **Trivy scans now examine the artifact's actual content, and a scan with
  nothing to examine no longer counts as clean** (#264). The Trivy adapter
  wrote every artifact to disk as `<sha256>.bin` and pointed `trivy fs` at the
  directory. Trivy chooses its analyzers by file name and directory layout and
  does not open archives, so a lone `.bin` matched nothing for every format:
  the report came back with no analysed target, the empty finding list was
  recorded as a clean scan, and the artifact was released on that basis. Since
  `["trivy"]` is the backend list a deployment gets without configuring a scan
  policy, this was the default path. A pull of a known-vulnerable
  `log4j-core-2.14.1.jar` through a Trivy-policy Maven proxy reported zero
  findings.

  Artifacts are now materialised the way the analyzers expect: a Java archive
  keeps its `.jar`/`.war`/`.ear`/`.par` name, a POM is written as `pom.xml`,
  wheels and sdists and `.crate` files are extracted, an npm tarball is
  extracted to `node_modules/<name>/` (the only place Trivy reads a
  `package.json`), and an OCI image layer is extracted as a root filesystem so
  its OS package database is read.

  Each kind is also scanned with the **subcommand its analyzer actually runs
  under**. Trivy's coverage matrix splits its analyzers between targets along
  the pre-build / post-build line: a built artifact — a Java archive, a Python
  wheel or egg, a `package.json` under `node_modules` — is analysed by the
  Image and Rootfs targets only, while a declaration such as `pom.xml` or
  `requirements.txt` is analysed by the Filesystem and Repository targets only.
  Pointing `trivy fs` at a JAR therefore runs no analyzer at all, which is why
  the `log4j-core` JAR still produced no verdict once it was correctly named:
  post-build kinds now use `trivy rootfs`, pre-build ones stay on `trivy fs`,
  and the same `log4j-core` pull reports CVE-2021-44228. When a report still
  comes back with no analysed target, the warning now carries Trivy's stderr
  tail and a listing of what was actually materialised, so the next such case
  is diagnosable from the log.

  **Second half, and the reason the first was invisible for so long:** a
  scanner that found nothing to analyse is no longer recorded as a scanner
  that found nothing wrong. Those were the same empty list; they are now
  different results. When no configured backend produces a verdict — the
  payload is an archive Hort refuses to unpack, or no analyzer claimed
  anything — the artifact is held `scan_indeterminate` (the existing
  fail-closed hold for a missing verdict) with a warning naming the format
  and the backend, and
  `hort_scan_record_outcome_failures_total{result="nothing_analysable"}`.

  **"Nothing to assess" is its own answer, and it is not a hold.** Some
  artifacts carry no package surface at all: an OCI image's manifest row and
  its config blob are metadata about the image, not content anyone could
  find a CVE in. Holding them would not be caution — no scan could ever
  clear them, so a Trivy-policed OCI repository would hold every image it
  ingested, forever. These now record a completed assessment with nothing
  assessed: the scan axis is satisfied, the observation window alone governs
  the release (it is not shortened or skipped), and the audit trail says
  *not applicable* rather than *analysed, clean* — a distinction the
  `ScanCompleted` event now carries explicitly, so the two can never be
  confused when reading an artifact's history.
  `hort_scan_terminal_total` gains a matching `not_applicable` result. A
  layer that carries an OS package database still gets a real, analysed
  verdict. Scan results recorded before this release read back as analysed,
  which is what they were.

  **Operators should expect new holds.** A Trivy-only policy on a cargo
  repository now holds a library crate rather than releasing it clean: a
  published `.crate` carries dependency ranges and, for a library, no
  `Cargo.lock`, so nothing can be attributed to a concrete version and there
  never was a real scan. The same applies to `zstd`-compressed image layers,
  which Hort cannot currently unpack. An npm tarball is now placed
  where Trivy's analyzer looks for it, so it may well come back as an
  analysed target — but read what that verdict means: a tarball pins no
  dependency versions, so a clean result there says the package's identity
  was read, not that its dependencies were checked against advisories. The
  fix in each case is the repository's `scanBackends`, not the scanner. See
  `docs/architecture/explanation/scanning-pipeline.md` for the per-format
  coverage table.

  Archive extraction is bounded and fail-closed — extracted-bytes,
  decompression-ratio and entry-count caps, entry-name path-traversal
  rejection, permissions stripped — and a tripped bound refuses the whole
  archive rather than scanning a fragment. One further latent bug fixed along
  the way: a Trivy report whose `Results` field was an explicit JSON `null`
  (what Go emits for an empty result set) failed to parse and was charged to
  the retry budget as a scanner malfunction.

  **A layer's own symlinks no longer hold it forever.** A symlink or hardlink
  entry is never materialised — it carries no bytes, so creating it would
  only hand the scanner another path to follow — but extraction still refused
  the *whole archive* whenever such a link's target was absolute or pointed
  outside the workspace. A root filesystem is full of exactly that shape
  (`/bin/sh -> /bin/busybox`, merged-usr `lib -> usr/lib`), so every real OCI
  layer under a Trivy policy held indefinitely: manifest and config recorded
  `not_applicable` and released, but the one layer that actually carries the
  package database never got a verdict. Since the target is never followed,
  an out-of-root target cannot write, read or expose anything either — link
  entries are now skipped and counted (surfaced in the adapter's logs)
  regardless of where they point, and only an entry's own escaping *name*
  remains a refusal.

- **A curator looking at an artifact the integrity scrubber condemned now sees
  why** (#245). When the CAS scrubber re-reads a stored blob and the bytes do
  not hash to their content hash, it tombstones the artifact — marks it
  `rejected` so nothing can download it again. It recorded the corruption
  itself, but not the rejection, and the curation queue reads a row's reason
  from the rejection record: the artifact showed up condemned with no
  explanation next to it, and no way to list exactly those artifacts. The
  tombstone now records the rejection alongside the corruption, in one write,
  so the queue shows the reason `corruption` and `?reason=corruption` (or
  `hort-cli curation queue --reason corruption`) lists them.

  Corruption is deliberately **not** clearable by a scan: a clean scan of
  corrupt bytes is a clean scan of somebody else's content. Recovering from a
  false positive — an operator restoring the blob from a known-good backup —
  is the admin release, as before. Artifacts tombstoned by an earlier version
  keep their old record, so they still show an empty reason and will not match
  the new filter; they remain condemned either way.

  `hort-cli curation queue --reason` no longer keeps its own list of accepted
  values. It had gone stale — the CLI refused `provenance`, `admin` and
  `scan_policy_retroactive` client-side while the server was serving rows
  carrying exactly those — so the value is now passed through and the server,
  which derives the list from the rejection reasons it can actually record,
  answers.

- **An image whose signature arrives a moment after it is pushed is no longer
  rejected for being unsigned** (#243). Under `provenanceMode: required`, hort
  verified provenance as soon as the manifest landed — but with cosign the
  signer must resolve the manifest before it can attach a signature to it, so
  the verify routinely ran first and found nothing. That was treated as a
  terminal verdict: the image went `rejected`, and the signature that arrived a
  second later changed nothing. A missing signature is a statement about a
  point in time, so it can never be terminal; it is now an indefinite **hold**
  instead, and the image clears and releases the moment the signature is seen,
  whether that is a second or a day later. Only a *positive disproof* — a
  signature that is present and invalid — still rejects, and it now writes the
  terminal event that every other rejection axis already wrote, so a rejected
  image can be audited from its own stream instead of from a status with
  nothing behind it.

  Two operator-facing consequences. A held image's `503` no longer carries
  `Retry-After`: the hold waits on an external event rather than on the clock,
  and advertising a retry schedule it does not have put well-behaved clients in
  an unbounded retry loop. And the standing held population is now visible —
  `hort_provenance_held_artifacts` and `hort_provenance_hold_oldest_age_seconds`
  report how many artifacts are waiting and how long the oldest has waited,
  split by whether they are waiting for their own signature or their parent's.

  For the images already stranded by the old behaviour there is a one-shot,
  admin-only repair — `POST /api/v1/admin/quarantine/provenance-misrejections/repair`,
  **dry-run by default** — that returns them to the hold so the ordinary
  release sweep can release them. It touches only artifacts whose own event
  stream contradicts their rejection, and leaves every genuine rejection alone;
  see *Recovering stranded artifacts* §5 in the docs. Relatedly, the curation
  queue's `?reason=` filter no longer answers `400` for discriminators the
  queue itself emits (`provenance`, `admin`, `scan_policy_retroactive`).

- **A proxied image index served under a single-image `Content-Type` now gets
  its membership rows written** (#229). The pull-through path decided whether a
  manifest was an index from the upstream's declared media type, while the rest
  of the OCI ingest path decides from the manifest body. Where an upstream
  mislabels an index — the bytes are an index, the header says single image —
  the two disagreed, and the index's child-membership rows were silently never
  recorded, which is the same incomplete-membership state the membership-edge
  backfill exists to repair. Digest verification cannot catch this: the bytes
  match their digest, only the header is wrong. The body now decides
  everywhere; the declared type is still checked against it and a disagreement
  is logged, but it no longer determines what is recorded.
- **The worker's ingest path now runs the late-joiner provenance clearance**
  (#263), so eager-ingested children of a signed proxied image index no longer
  stay held under `provenanceMode: required`.

### Removed

- **The provenance-hold population gauges**, `hort_provenance_held_artifacts`
  and `hort_provenance_hold_oldest_age_seconds` (#260). They were set from one
  release-sweep tick's candidate batch and could not describe the held
  population — no replacement metric; the operator's view of the held set is
  the admin curation queue.

## [0.13.0] - 2026-09-04

### Fixed

- **OCI blobs are no longer terminally rejected as `Unsigned` under
  `provenance_mode: required`** (#230). cosign signs only a manifest or index
  digest, so an image's config and layer blobs never carry an attestation of
  their own — their clearance arrives from their subject. When the quarantine
  observation window was shorter than the client's push took, a blob's first
  provenance verify ran with the window already closed *and* with no inbound
  reference edge yet (clients push blobs before the manifest that names them),
  and the verdict resolved to a terminal `Rejected{Unsigned}`. That state is
  unreachable by re-evaluation, waiver, admin override and the clearance
  cascade alike, so a correctly signed image became permanently unservable as
  a function of the client's push order.

  Classification is now made from the artifact's own identity — a new
  `FormatHandler::is_provenance_constituent` (default `false`; the OCI handler
  answers `true` for blob rows and `false` for manifests and indexes) — rather
  than from `content_references` edges, which record what has been ingested so
  far and are therefore absent in exactly the window that mattered. An unsigned
  constituent is **held** and cleared only by its subject (the existing
  verify-time cascade, or the ingest-time late-joiner self-clear); no new
  release authority is introduced, and a constituent whose subject never
  arrives stays held and ages out through retention. Subject semantics are
  unchanged: a manifest or index with a closed window and no signature is still
  terminally `Unsigned`, and a forged signature on any row is still rejected
  immediately.

### Added

- **`hort_provenance_verify_total{result="held_pending_subject"}`** (#230) — a
  new `result` label value, also surfaced as the `provenance-verify` job's
  `result_summary`, counting constituents held pending their subject's
  clearance. Distinct from `held_pending_signature`, which means an artifact
  that may still be signed; this population previously resolved to a silent
  terminal rejection. See `docs/metrics-catalog.md`.

### Changed

- **Rust toolchain 1.94.1 → 1.97.1** (#227): MSRV 1.97 (`.clippy.toml`, `Cargo.toml`,
  `rust-toolchain.toml`), builder and E2E client images on `rust:1.97.1-slim`
  (digest-pinned). Runtime-baseline move only; no behaviour change.
- **Credential-hashing and digest dependency stack moved to the RustCrypto
  new generation** (argon2 0.6, password-hash 0.6, sha2/sha1/md-5 0.11,
  hmac 0.13, p256 0.14; #199). Observable behaviour is unchanged: Argon2id
  parameters and the stored credential format are identical (existing
  credentials keep verifying), CAS SHA-256 digests are byte-identical, and
  webhook signatures keep their wire form.

## [0.12.3] - 2026-09-01

### Fixed

- **cargo sparse index: `pubtime` is now emitted in cargo's strict wire
  format** (`yyyy-mm-ddThh:mm:ssZ` — 20 characters, `Z` only, no fractional
  seconds). cargo ≥ 1.93 parses the field with a strict deserializer and
  treats the **whole index line** as invalid when it fails, so the RFC 3339
  offset format (plus microsecond precision on stored timestamps) served
  since 0.12.2 made every locally ingested version unresolvable for modern
  cargo clients — resolution failed with "version X's index entry is
  invalid" across hosted, proxy, and virtual cargo repositories. (#225)

## [0.12.2] - 2026-09-01

### Added

- **Expand/contract policy for schema migrations, enforced by a structural
  guard** (#214; incident record #215). Destructive DDL — `DROP COLUMN`,
  `DROP TABLE`, a table/column `RENAME`, a column type change, `SET NOT NULL`
  on an existing column — may now ship only in a release strictly *after* the
  last release whose code referenced the identifier; expand and contract never
  share a release. A migration set has to be applicable while the previous
  release's binaries are still serving, and migration
  `020_drop_artifacts_is_deleted.sql` was not: it dropped `artifacts.is_deleted`
  in the same release (0.12.0) that removed the last code reference, so the
  still-running 0.11.0 fleet failed every artifact query the moment the
  pre-upgrade hook completed.

  The policy is now mechanical. A new DB-free, git-free, sub-second guard
  (`cargo test -p hort-app --test expand_contract_guard`, part of
  `cargo test --workspace`) scans `migrations/` for destructive DDL and
  cross-checks it against a checked-in manifest,
  `migrations/CONTRACTIONS.toml`. It fails when a contraction is undeclared or
  declared inexactly, when the workspace version is not strictly greater than
  the entry's `reference_removed_in`, or when the workspace's production
  sources still name a removed identifier. The manifest is seeded with the
  tree's existing destructive migrations, with `020` recorded as the incident
  exemplar. See [ADR
  0030](docs/adr/0030-sensitive-surface-structural-guards.md).

- **`docs/architecture/how-to/deploy/upgrade.md`** — operator upgrade how-to:
  what the expand/contract guarantee buys on a routine upgrade, how to handle
  a release carrying a `### Migration notice` (two-step upgrade, or a
  maintenance window), why self-hosting deployments that mirror their own
  images have no safety net during an API-degrading window, and why automated
  Flux remediation must be suspended for a flagged release — an automatic
  chart rollback against a forward-only contraction pins the outage instead of
  clearing it.

- **Chart pre-upgrade image pre-pull hook.** A new `prePull.enabled`
  (default true) pre-install/pre-upgrade hook pre-pulls the release's
  `hort-server` / `hort-worker` images onto every node eligible to run
  those Deployments, strictly before the migrate hook runs. Closes the
  node-cache-miss window where the migrate hook pulls the new image onto
  its own node while a different node still needs it for the real
  Deployment pod, inside the degraded upgrade window.

- **Cargo sparse-index lines now carry an optional `pubtime`** (#217),
  the version's publish timestamp in RFC 3339 UTC — omitted, never
  invented, when hort has no timestamp for a version. Hosted repositories
  serve the artifact's own `created_at`; proxy repositories serve the
  upstream-asserted publish time when hort has it, else the artifact's
  own first-seen-here `created_at`, else omit the field entirely for a
  version hort has never pulled through; virtual repositories pass the
  winning member's value through unchanged. Closes the gap where
  Renovate's crate datasource, finding no `pubtime`, fell back to an
  unimplemented per-version API route and lost the timestamp
  `minimumReleaseAge`-style rules depend on. One-way outward only: the
  served field is derived from data hort already owns and is never read
  back into any release or quarantine decision.

- **Terminal scan-job rows are garbage-collected.** Every scan — each
  periodic rescan included — left a terminal row in the jobs table
  forever, and a scanner outage grew permanent `failed` rows at roughly
  one per stranded artifact per retry-exhaustion cycle, with no ceiling
  and no cleanup. A new `scan-row-retention-sweep` (worker task + daily
  Helm CronJob, enabled by default, `horizon_seconds` operator knob with
  a 7-day default) deletes terminal `kind='scan'` rows past the horizon —
  scoped to exactly that kind, because other kinds keep their newest
  terminal row as durable state (the event-chain verifier's checkpoint).
  Candidacy semantics are untouched: the rescan queries never read
  terminal rows, and a stranded artifact selects identically whether its
  last failed row exists or was swept. Migration 023 widens the
  jobs-kind check for the new task kind (additive only). (#216)

### Changed

- **`quality:sonar` reads back its own quality-gate verdict, and clippy
  findings now reach Sonar.** `sonar.qualitygate.wait=true` makes the
  scanner wait on the server-side gate computation, and a `quality:sonar-findings`
  job (still `allow_failure: true`) prints the gate's failing conditions, open
  issues, and unreviewed security hotspots to the log so a red gate is never
  silent. `test:lint` now emits `clippy-report.json`, which
  `sonar-project.properties` imports via `sonar.rust.clippyReport.reportPaths`.
  The scanner image is pinned by digest through the internal mirror instead of
  tracking `:latest`.
- **`quality:sonar` is now blocking.** The gate baseline is established and
  clean on the integration trunk, so `allow_failure` is removed: a red gate
  now fails the pipeline, and a dead/expired Sonar token fails it too (with
  `quality:sonar-findings` explaining it as an auth failure) instead of
  passing silently.
- **`RELEASING.md`'s promotion checklist gains a Migration-notice step.** A
  release whose migration set contains a contraction now carries a
  `### Migration notice` changelog entry naming the dropped or narrowed
  object, the minimum binary version that tolerates the change, and the
  operator action, so a maintenance window can be planned rather than
  discovered.

### Fixed

- **Chart CronJob schedules are now anchored to UTC by default instead of
  controller-local time.** None of the chart's 18 CronJob templates set
  `spec.timeZone`, so Kubernetes interpreted every `schedule:` in the
  kube-controller-manager's local time zone — a template comment promising
  "daily at 03:00 UTC" could fire at a different wall-clock hour depending on
  the cluster. Every chart CronJob now renders `spec.timeZone` from the new
  shared value `scheduledTasks.timeZone` (default `"Etc/UTC"`); operators
  relying on the old local-time behavior can set `scheduledTasks.timeZone` to
  their controller's zone.

- **The wheel-metadata and OCI membership-edge backfills no longer
  starve on permanent skips.** Both admin-task backfills walked
  candidates `ORDER BY id LIMIT batch_size` with no cursor, and a
  skipped item (corrupt wheel ZIP, no METADATA member, oversized
  METADATA; an OCI manifest whose bytes don't parse or carry no
  config-role reference) wrote nothing — so it never left candidacy nor
  its position at the batch head. A backlog of ≥ `batch_size`
  permanently-unprocessable rows with low ids meant the backfill never
  progressed past them, reporting `Completed` every invocation while a
  valid item behind them was never reached — the same starvation shape
  as the quarantine-release sweep fixed for `#208`, here without a
  release-authority stake. Each run now walks its full candidate set via
  an in-run keyset cursor (`WHERE id > $after ORDER BY id LIMIT
  $batch_size`, paged, cursor advanced after every page regardless of
  outcome), and a **structural** skip (one re-running cannot change,
  since CAS content is immutable) additionally writes a durable
  `content_references` marker (`wheel_metadata_skipped` /
  `oci_membership_skipped`) that permanently excludes the row from
  candidacy — a **transient** skip (CAS/DB error) writes no marker and
  is retried on the next invocation. New task param
  `ignore_skip_markers` (default `false`) re-surfaces marked rows, e.g.
  after a parser fix. Run-summary skip counters split into
  `skipped_structural` / `skipped_transient` for both tasks (replacing
  `skipped_no_metadata`/`errors` and
  `skipped_cas_missing`/`skipped_unparseable`/`errors` respectively). No
  migration — the marker rows use the existing `content_references`
  table. (#211)

- **The scheduled prefetch tick now rotates across the whole repo × package
  space instead of re-reading page 1 forever.** The walk read the first
  1000 prefetch-enabled repositories and the first 1000 package names per
  repository every tick, with no cross-tick cursor — deployments beyond
  either ceiling silently never refreshed the remainder (the doc comment's
  claimed multi-tick walk had no mechanism behind it). The tick now
  persists a keyset cursor (last fully-processed repository/package) in its
  completion summary and resumes strictly after it each tick, wrapping to
  the start after a full traversal, so a traversal of W plannable prefetches
  completes within ⌈W / 5000⌉ ticks and the per-tick caps are page sizes,
  not visibility ceilings. Budget semantics are unchanged: deduplicated
  enqueues still consume no budget. The summary's new `cursor` field makes
  the walk's progress operator-visible. (#212)

- **Concurrent OCI manifest/tag pushes no longer 500 on group/ref append
  races; Maven group links no longer silently lost on concurrent
  same-GAV uploads.** `ArtifactGroupUseCase::add_member` and
  `RefUseCase::set` now adopt the bounded read-decide-append contract
  (ADR 0060): a losing append conflict re-reads the refreshed state,
  succeeds idempotently if the caller's intent is already satisfied, and
  otherwise rebuilds and re-appends — bounded, with a busy signal on
  exhaustion instead of an unbounded loop. The OCI `group_attach_*` /
  `ref_set` sites map that exhaustion to `503` + `Retry-After` instead of
  `500`. (#221)

## [0.12.1] - 2026-08-29

### Fixed

- **The quarantine-release sweep no longer starves.** Candidacy was
  ordered oldest-first with a hard per-tick batch cap, and a candidate
  the sweep skips — no scan authority, or a provenance clearance still
  pending, the canonical case being a config/layer blob whose clearance
  can only ever arrive through its parent manifest's cascade — stays
  `quarantined` and therefore stays at the head of the next tick's
  selection. Once a whole batch of the oldest candidates was permanently
  unreleasable, **no artifact anywhere in the deployment was ever
  released again**, with nothing in the logs that looked like a failure
  (a live deployment hit this at 1482 quarantined artifacts against a
  batch of 1000, of which 964 of the oldest 1000 were parent-gated
  blobs). Candidacy now rotates: a new nullable
  `artifacts.release_attempt_at` column records when the sweep last
  *attempted* a row (scheduling metadata only — it records that a
  decision was attempted, never what it was, and is deliberately not
  event-sourced), the sweep stamps the whole batch each tick, and
  selection orders by that cursor `NULLS FIRST` before the window
  anchor. A never-attempted artifact is therefore served on the very
  next tick regardless of backlog size, and a backlog of N is fully
  re-attempted every ceil(N / 1000) ticks. Release authority is
  untouched: candidacy is still "window elapsed" and every release still
  goes through the fail-closed per-artifact check, so the cursor can
  only change *which* candidates a bounded batch re-checks first, never
  whether one may be released. Migration
  `022_artifacts_release_attempt_at.sql` adds the column and replaces
  the single-column candidacy index with the matching `(release_attempt_at
  NULLS FIRST, quarantine_window_start)` partial index. (#208)

### Changed

- **The sweep's per-tick accounting names the gate that is actually
  holding each candidate, and a saturated sweep is alertable.** The
  `quarantine-release-sweep` task's `result_summary` key
  `skipped_no_authority` — a fabricated `candidates - released` delta —
  is replaced by two true per-cause counts reported by the use case
  itself, `skipped_no_scan_authority` and `skipped_provenance_pending`
  (also the log line's fields). The old delta conflated a scan-authority
  hold, which drains once scanners catch up, with a provenance hold,
  which may never self-clear, and additionally counted candidates that
  are merely no longer releasable as though they were held. A tick that
  fills the batch and releases nothing now emits a `warn!`
  ("sweep saturated, nothing releasable this tick") carrying both
  counts, in place of the routine `info!` — the stall signature is an
  operator alert rather than a line that reads like a normal policy
  outcome. (#208)
- **The sweep's provenance-pending count now splits out structural
  parent-gated holds.** `skipped_provenance_pending` used to conflate
  two operator-distinct situations: an artifact whose own scan or
  signature is still outstanding (actionable — resolves per artifact or
  with time), and a config/layer blob constituent whose only clearance
  path is its parent manifest's cascade (structural — moves only when
  the root gets signed, and a never-signed root's blobs hold
  indefinitely by design). The `quarantine-release-sweep` task's
  `result_summary` gains a third count, `held_parent_gated`, carrying
  the parent-gated share of what used to be reported under
  `skipped_provenance_pending`; the log line's tick-complete and
  stall-warn fields gain the same field. On the production deployment
  that motivated this split, ~964 of 1000 candidates in a stalled batch
  are the structural kind — the split is what makes that stall warning
  readable rather than alarming. (#209)

## [0.12.0] - 2026-08-27

### Added

- **npm `dist-tags` are passed through, intersected with the served
  set.** hort served exactly one tag — `latest`, *inferred* as the
  semver-max of the served set — and discarded every other tag the
  authoritative source published. Consequences: a maintainer who pinned
  `latest` at an older release had that choice silently overridden, and
  `npm install <pkg>@next` / `@beta` / `@rc` could not resolve at all
  through hort. The whole tag map is now served, from the source that
  actually authors it: upstream's map for a proxy repository (widened
  into the cached projection, CRUD like the rest of it — hort is not its
  author), and the maintainer's own for a hosted one, held as
  `mutable_refs` rows and event-sourced through `RefMoved` /
  `RefRetired`. Hosted tags are written two ways: the `dist-tags` object
  in the `npm publish` envelope (captured after a successful ingest, so a
  tag can never point at a version that failed to land), and the npm
  CLI's own routes, `PUT` / `DELETE
  /npm/{repo_key}/-/package/{pkg}/dist-tags/{tag}` — `npm dist-tag add`
  and `npm dist-tag rm`, gated on the same Write permission as publish
  and rejected on proxy and virtual repositories, which have no
  authorable tag store. A virtual repository merges its members' maps in
  priority order under the existing dependency-confusion rules: the first
  surviving member to define a tag name owns it, and a proxy member
  contributes neither versions nor tags once a non-proxy member owns the
  name, so a public `next` can never shadow an internal package's tags.
  The gate is the intersection: **a tag whose target version is not
  served is dropped, never rewritten**, so a tag can no longer be a
  pointer to something hort would refuse to serve, and the per-version
  route resolves any surviving tag (`GET /npm/{repo}/{pkg}/next`) with an
  unknown tag returning the same anti-enumeration 404 as an unknown
  version. `latest` is verbatim when it survives; the previous derivation
  remains only as its fallback, never as an override. Under a null gate
  the intersection degrades to identity — hort's `dist-tags` is
  upstream's, byte for byte. No migration: the refs table, entity,
  events, and adapter already existed. Pre-widening cached projections
  decode to an empty map and heal on re-projection, so no cold-cache
  event on deploy. (#202)

### Changed

- **Artifact deletion is now an event-sourced soft delete.** Deleting an
  artifact — today reachable through the OCI manifest `DELETE` by digest —
  used to be a bare `DELETE FROM artifacts` with no domain event: the one
  terminal artifact-lifecycle transition that recorded nothing. It now
  emits a new `ArtifactDeleted { artifact_id, repository_id, path,
  content_hash }` event on the artifact's own stream
  (`StreamCategory::Artifact` — no new stream category), attributed to the
  authenticated caller, appended atomically with the state change so the
  projection can never be marked deleted without the event that records
  it. The `artifacts` row is **retained** with a new nullable `deleted_at`
  column instead of being removed, so an auditor can still answer "what
  content did this path hold, and who removed it?". Every live read
  filters `deleted_at IS NULL`; the content-age anchor
  (`first_seen_at = MIN(created_at)`) deliberately still counts deleted
  rows, because deletion cannot un-observe when the content was first
  seen and excluding them could only shorten an observation window. The
  table-wide `UNIQUE (repository_id, path)` constraint becomes a partial
  unique index predicated on `deleted_at IS NULL`, so a deleted row no
  longer reserves its path: a fresh ingest there succeeds and mints a new
  artifact (new id, new row, new stream). Deleting an absent or
  already-deleted artifact stays a no-op (`NotFound`) and appends no
  second terminal event. The CAS blob is untouched — blob lifetime
  remains refcount-gated GC, since another artifact may reference the same
  bytes. Migration `021_artifacts_soft_delete.sql`. (#145)

### Fixed

- **npm packuments now carry per-version install metadata.** Every
  `versions[v]` entry hort served was exactly `{name, version, dist}`:
  the proxy projector discarded the rest of the upstream per-version
  object, and although a hosted publish stored the full block nothing
  ever read it back. A fresh, non-lockfile install through hort
  (`npm install <pkg>` / `pnpm add <pkg>`) therefore saw every version as
  dependency-free and silently materialised a near-empty tree, while
  `engines`/`os`/`cpu` filtering, `deprecated` warnings and
  install-script detection were inert. Lockfile installs were unaffected
  (they carry their own resolved graph), which is why this went
  unnoticed. Both the packument and the abbreviated per-version route now
  emit the npm registry API's abbreviated-metadata (install-v1) field set
  — `dependencies`, `optionalDependencies`, `peerDependencies`,
  `peerDependenciesMeta`, `bundledDependencies`, `bin`, `directories`,
  `engines`, `os`, `cpu`, `libc`, `deprecated`, `hasInstallScript`,
  `funding` — passed through **verbatim** from the authoritative source
  (the upstream packument for proxy repositories, the stored publish
  block for hosted ones, following the CAS reference when the block
  spilled past the 256 KB inline threshold). A field absent at the source
  stays absent: nothing is synthesised and nothing is emitted as `null`.
  The set is a fixed whitelist, not a step toward full packument
  equality — `description`, `scripts`, `devDependencies`, `time` and the
  rest remain dropped. Pre-existing upstream-projection cache entries
  decode unchanged and simply carry no manifest fields until their next
  refresh. (#204)

### Added

- **npm abbreviated per-version / dist-tag route** —
  `GET /npm/{repo_key}/{name}/{version-or-tag}` (and the `@scope` variant)
  now serves the npm registry convention's per-version manifest:
  `{name, version, dist:{tarball, shasum[, integrity]}}` for an exact
  served version, or for the literal tag `latest` (resolved by the same
  prerelease-excluding derivation the packument uses — one shared
  definition). Previously the unscoped shape collided with the
  scoped-packument route and returned a misleading
  `"scoped npm name must start with '@'"` 400, which broke `corepack`
  package-manager activation against a hort registry
  (`COREPACK_NPM_REGISTRY`): corepack always issues
  `GET /<pkg>/<version-or-tag>`, so every cold `COREPACK_HOME` failed.
  Resolution runs against the same filtered served set as the packument,
  so a quarantined or otherwise non-servable version 404s
  indistinguishably from a nonexistent one; tarball routes are unaffected
  (their literal `-` segment keeps matcher precedence). Tags other than
  `latest` still resolve nowhere — upstream tag pass-through is tracked
  separately (#202). (#203)

- **`GET /api/v1/repositories/{repo_key}/prefetch/jobs/{job_id}`** — a
  read-only, id-addressed lookup of a self-service prefetch job's outcome
  (`status`, `attempts`, `last_error`, `result_summary`, `kind`,
  `created_at`, `completed_at`). Authz is identical to the
  `POST .../prefetch` that minted the id (`CliSession` or `ServiceAccount`
  token, `Permission::Read ∧ Permission::Prefetch` on the repository); a
  job that exists but belongs to a different repository, or is not a
  `prefetch` / `prefetch-dependencies` job, 404s indistinguishably from an
  unknown id — no cross-repo enumeration by id-probing. No list/filter/retry
  surface. (#158)

### Changed

- **Event-chain verification is now default-on, and a missing checkpoint
  anchor is no longer a daily failure where no anchor is expected.**
  `scheduledTasks.verifyEventChain.enabled` now defaults to `true`, so an
  **existing install gains this CronJob on upgrade** (it still sits under
  the `scheduledTasks.adminTasksEnabled` umbrella; set `enabled: false` to
  opt out). Tamper detection an operator has to opt into is tamper
  detection most deployments never get. Default-on is safe because the
  missing-anchor semantic is split at its source: whether an anchor is
  expected is derived from one shared predicate — S3 storage **and** a
  provisioned anchor public key — that the checkpoint writer and the
  verifier both consult, so a filesystem install (which can never host an
  S3 Object-Lock WORM anchor) verifies its chain, expects no anchor, and
  exits `0`. A real chain break still exits `2` everywhere; a
  missing/stale checkpoint where an anchor **is** expected still exits
  `3`. The verify job is never given the anchor private signing key —
  verification is a public-key operation. Metric semantics:
  unanchored-verified records `hort_event_chain_verify_total{result="ok"}`
  — the `{ok, broken, missing_checkpoint}` series set is unchanged, and
  the anchored-vs-unanchored distinction rides the exit code, the log line
  and the new `anchor_expected` field of the subcommand's JSON output.
  `--fail-on-missing-checkpoint` (and the chart's
  `failOnMissingCheckpoint`, now defaulting to `null`) became tri-state:
  unset derives, an explicit `true`/`false` forces. See ADR 0057. (#165)

- **Server-side upstream-fetch metrics now name the format that actually
  fetched.** The server built a single pull-through proxy with a
  hardcoded `format_label: "oci"` and handed it to all five inbound
  format crates, so every npm / PyPI / Maven / Cargo on-miss fetch
  reported `format="oci"` on `hort_upstream_fetch_total`,
  `hort_upstream_fetch_duration_seconds` and — security-relevant —
  `hort_upstream_insecure_total`, where an operator triaging "which
  upstream is plaintext?" was pointed at the wrong format. The server
  now builds one proxy instance per served format (`oci`, `npm`, `pypi`,
  `maven`, `cargo`), all sharing a single `reqwest::Client` and hence a
  single connection pool, and each inbound crate selects its own via a
  per-format registry on `AppContext`. There is no fallback instance: an
  incomplete composition fails at boot. No new label values — the closed
  set is unchanged; what changed is that the correct member of it is
  emitted. The worker's two deliberately subsystem-labelled instances
  (`prefetch_tick`, `provenance`) are untouched. `HttpUpstreamProxyConfig`
  lost its `Default` impl so an omitted `format_label` can no longer
  inherit `"oci"` silently. (#170)

### Fixed

- **npm `dist-tags.latest` no longer resolves to a prerelease while a
  release is served.** The served packument derived `latest` as a bare
  semver-max over the served set, so any package whose next version has a
  published prerelease (for React, a permanent condition) advertised that
  prerelease — e.g. `19.3.0-canary-…` over `19.2.8` — and a bare
  `npm i <pkg>` / `pnpm add <pkg>` installed a canary, under both
  `indexMode` arms. `latest` is now the max over the **non-prerelease**
  served versions; a served set consisting only of prereleases falls back
  to the max prerelease (a prerelease-only package still gets a usable
  tag); an empty served set still emits no `dist-tags` block, and build
  metadata (`1.2.3+build.5`) does not count as a prerelease. Lockfile
  installs, explicit versions, and range specs were never affected.
  Upstream `next`/`beta`/`rc` tag pass-through remains future work
  (#202); Maven's `<release>` derivation was verified correct for
  Maven's own model (only `SNAPSHOT` is special there). (#200)

- **A scan finding whose severity a backend could not read no longer
  discards another backend's correctly-scored reading of the same
  advisory.** When a backend cannot determine a severity it emits the
  fail-closed `Critical` floor — a record byte-identical to a genuine
  unscored `Critical` (same tier, no CVSS, no informational class). The
  cross-backend merge compared collisions on severity tier alone, so that
  floor won every time, including against a scored finding for the same
  advisory: `rsa 0.9.10` / `RUSTSEC-2023-0071` sat terminally rejected for
  six weeks on a verdict no backend had actually reached, reproducibly,
  because the merge was deterministic over unchanged inputs. `Finding`
  now carries `severity_basis` (`assessed` / `unassessed`), emitted
  `unassessed` at the three fail-closed sites and nowhere else, and the
  merge prefers a finding that carries a real reading — a CVSS score, a
  recognised informational class, or an `assessed` marker — over one that
  does not, **across severity tiers**. Two real readings still compare by
  tier, so a scored `Low` never talks down a scored `Critical`. Findings
  persisted before the field existed deserialise as `assessed`, the
  fail-safe: a legacy record cannot be proven to be a fail-closed default,
  so it keeps today's behaviour rather than becoming demotable. New
  break-glass switch `HORT_FINDING_MERGE_ALLOW_INFORMED_DOWNGRADE`
  (default `true`; Helm `worker.scanner.findingMerge.allowInformedDowngrade`)
  reverts the merge to strict always-fail-closed — engaging it makes the
  release gate stricter, not looser. See
  [ADR 0059](docs/adr/0059-finding-reconciliation.md). (#177)

- **One advisory returned under two ids no longer rejects a package
  twice over.** OSV returns a RustSec advisory *and* its GitHub-reviewed
  GHSA mirror as separate records in the same response. The mirror
  frequently carries neither a severity nor an informational marker, so
  it fell back to the fail-closed `Critical` and shadowed the sibling
  that does carry the advisory's metadata — and the cross-backend merge
  could not reconcile the pair, because the two records have **different
  advisory ids**. `rand 0.7.3` and `typemap 0.3.3` were rejected this
  way, on a verdict no backend reached, with `rejected` terminal for
  serving. Both OSV adapters now collapse mutually-aliased findings for
  a package into one finding per advisory, keeping the best-informed
  member: a real CVSS beats a recognised informational class, which
  beats a severity read without a score, which beats the fail-closed
  floor. A genuinely-scored advisory therefore still blocks —
  `traitobject 0.1.1` (CVSS 9.8) stays rejected. The collapsed-away
  identifiers are unioned onto the surviving finding's aliases, so an
  operator exclusion keyed by any of them still clears the advisory.
  Artifacts already in the terminal `rejected` state are not freed
  automatically; see
  [ADR 0059](docs/adr/0059-finding-reconciliation.md) for the operator
  paths. (#174)

- **The quarantine-release sweep no longer strands artifacts in a
  repository whose scan-policy row does not resolve.** Sweep candidacy was
  the only consumer of the quarantine window without a `DefaultPolicy`
  fallback, so a repository holding quarantined artifacts but with no
  resolvable non-archived policy row was silently dropped from the release
  sweep forever — its full-window artifacts stranded permanently while the
  API deadline read "expired". Candidacy now falls back to the default 24 h
  window like every other consumer; an explicit `quarantineDuration: 0`
  policy stays permissive (never a candidate), unchanged. (#190)

## [0.11.0] - 2026-08-22

### Added

- **`ScanPolicy` gained `enforcement: reject | record`** — a per-policy
  choice of what a blocking scan verdict *does*, orthogonal to the
  knobs that decide which findings are blocking (`severityThreshold`,
  `licensePolicy`, `negligibleAction`). Under the default `reject` —
  which an omitted field parses to, so no existing policy file needs an
  edit — nothing changes. Under `record` the scan still runs, the
  per-finding rows, the findings blob and the `PolicyEvaluated(Fail)`
  verdict are still written, and the artifact is **not** rejected:
  publication proceeds with findings, leaving retrieval-time blocking to
  the consuming policy. Every API and metrics surface reports the
  violations identically in both modes; the scan-result evaluation log
  line and the `hort_policy_evaluation_total{result}` label name which
  enforcement applied (`findings_recorded` vs `reject`), so an operator
  never has to infer it. Because a `record`-mode artifact's own
  `ScanCompleted` carries findings, it releases through a new, distinct
  `ScanRecorded` release authority rather than a widened
  `ScanSucceeded` — the release is auditable as "released with recorded,
  over-threshold findings", and the authority carries the same
  provenance precondition as the other timer authorities, so `record`
  un-gates the scan axis only (an unverified artifact under
  `provenanceMode: required`, an artifact matched by an active curation
  rule, and an artifact that was never scanned at all are all still
  held). Changing the field re-judges the existing population in both
  directions and without re-running a scanner: `record` → `reject`
  re-derives every in-scope artifact's verdict from its stored findings
  and re-holds the now-non-compliant ones, `reject` → `record`
  un-rejects the scan-rejected population while preserving the
  remaining observation window. An unknown value is an apply-time
  rejection naming the field and both valid values. (#191)

- **`hort_sbom_resolution_total{format, result}`** — how each scan's SBOM
  components were derived (`resolved` / `no_lockfile` /
  `unusable_lockfile` / `payload_unavailable` / `not_applicable` /
  `hosted_only`),
  alongside the existing `hort_sbom_extraction_total`, which gains a
  `payload_unavailable` result. `resolved / (resolved + no_lockfile +
  unusable_lockfile)` is the share of scans that examined dependencies at
  all — a registry scanning subjects only was previously indistinguishable
  from one scanning everything. **`hort_sbom_components_skipped_total{format}`**
  counts dependencies a resolved closure traversed but could not emit for
  having no registry coordinates (path- and git-sourced entries). (#191)

- **OCI membership-edge backfill.** The `oci-membership-edge-backfill`
  admin task repairs OCI image-manifest rows ingested before the
  pull-through path registered their `content_references` config/layer
  edges, restoring GC keepalive for blobs referenced only by such a row.
  One-shot, manually invoked, idempotent; reports rows scanned/repaired,
  edges written, and skips by reason. (#162)

- **Curator-invokable per-artifact re-evaluation.**
  `POST /api/v1/admin/curation/quarantine/:artifact_id/reevaluate` and
  `hort-cli curation reevaluate <artifact-id>` let a curator recompute a
  `Rejected` artifact's verdict from its stored findings under the
  currently active policy — no policy mutation, no forced outcome. (#152)

- **Maven artifacts can be prefetch-warmed.** The per-format prefetch
  dispatch implemented leaf pulls for PyPI, Cargo and npm and
  short-circuited everything else as "no compose-style download URL".
  For Maven that rationale was inverted — its layout
  (`{group-path}/{artifact}/{version}/{filename}`) is the most
  composable download URL in the system — so the only way to start a
  Maven quarantine clock was a build failing on first contact. Maven
  GAVs now warm through the same verified two-leg pull as the other
  leaf formats. (#153)

- **Chart: bootstrap service-account identities are a values-driven
  list.** The `svc-token-bootstrap` Job was hardwired to one identity
  (`cronjob-tasks`, `admin_task_invoke`) writing one Secret, so any
  further bootstrap identity needed a manual in-pod mint plus a
  hand-created Secret — unreproducible on rebuild, and dependent on a
  Secret name that RBAC `resourceNames` rules bind to. The Job now
  iterates `scheduledTasks.svcTokens`, minting every listed permission
  per identity (effective authority is cap ∩ grants, so a
  one-permission mint silently strands sibling grants) and writing each
  to its declared `secretName`. Per-identity idempotence keeps today's
  semantics, and an empty `secretName` resolves to the existing default
  — existing installs need no values change. (#155)

### Changed

- **Scans of hosted cargo crates now compute their verdict from the
  versions the crate was actually built against.** A published `.crate`
  embeds its own `Cargo.lock`; scan orchestration streams the stored
  artifact out of CAS and the cargo handler walks that lockfile's
  closure, so every SBOM component carries an exact resolved version
  instead of the declared range's floor (`serde = "1"` was scanned as
  version `1`, matching advisories that the built `serde 1.0.x` never
  had). A crate whose payload carries **no** lockfile now yields a
  subject-only SBOM — the crate itself is still scanned, but the
  range-floor dependency list is no longer produced at all, because it
  cannot feed an honest verdict. A lockfile that is present but unusable
  is reported distinctly from one that is absent. Extraction happens at
  scan time from the payload, which makes it **retroactive**: a rescan of
  an already-published artifact produces resolved components with no
  backfill and no ingest-path change. Dev-only dependency subtrees are
  excluded using the `kind` information in the stored index metadata —
  consumers never compile them. Formats that do not derive their SBOM
  from the payload (npm, PyPI, every opaque format) are unchanged and do
  not pay for a CAS read. **Proxied, virtual and staging repositories are
  unchanged too**: only a hosted publish's lockfile is the authenticated
  publisher's own build witness, whereas a proxied library's is the
  upstream author's dev-time resolve that consumers re-resolve and never
  run — findings against it would carry gate power over a crate every
  consumer would resolve safely. Those scans keep the metadata-only SBOM
  they had before, and cost no CAS read. (#191)

- **A principal with write authority on a cargo repository now resolves
  held versions in that repository's sparse index.** `cargo publish`
  resolves each crate's intra-workspace dependencies through the index
  even under `--no-verify`, so publishing a workspace into a hosted repo
  with a quarantine window failed at the second crate — mid-chain, with
  the earlier crates already uploaded and only yankable. This extends the
  existing OCI push-then-sign hold exemption (ADR 0039 §10) to the cargo
  index and records the generalised rule in **ADR 0055**: *a principal
  that may write to a repository may resolve held metadata there; held
  bytes never leave quarantine, for anyone.* Scope: `Quarantined` only
  (`Rejected` / `ScanIndeterminate` stay hidden from every caller,
  publisher included), metadata only (a held `.crate` is still `503` to
  its own publisher), keyed on **granted** write authority rather than
  the presented token's capability, and not applied to virtual
  (aggregating) repositories. Nothing is released earlier and the
  release predicate is unchanged. (#179)

- **The cargo sparse-index route emits `Cache-Control: private,
  no-store` and `Vary: Authorization`.** The served set now varies by
  principal, so a shared cache or reverse proxy must not store one
  caller's response and replay it to another. Unconditional — absent
  directives permit heuristic caching, so conditioning the headers on the
  hold-read having engaged would leave the ordinary responses cacheable
  under the same URL key. (#179)

- **Intra-workspace dependencies name the `hort-crates` registry.**
  Without the key they are crates.io dependencies, which the release
  job's `[source.crates-io] replace-with` sends to the read-only
  aggregation index — a repository the release identity cannot publish
  to, where the hold-read above correctly does not engage.
  `.cargo/config.toml` declares the matching `[registries.hort-crates]`
  index (cargo refuses to parse a manifest naming a registry it has no
  index for), and the `publishable_manifests` guard asserts both halves
  plus their agreement with each member's `publish` allow-list. (#179)

- **BREAKING (operators): the server and worker Deployment selectors now
  carry an `app.kubernetes.io/component` discriminator.** Previously both
  Deployments' `spec.selector.matchLabels` matched each other's pods, so
  the `hort-server` Service could route to worker pods and a PodDisruption
  Budget could count the wrong workload. `spec.selector` is immutable
  after create, so **`helm upgrade` fails against an existing release**
  with a `spec.selector is immutable` error. This is a one-time step per
  install; a fresh install needs no action. The chart README documents
  three migration paths — delete-then-upgrade, `--cascade=orphan`
  re-adoption for zero-downtime-sensitive installs, and a suspend/resume
  sequence for Flux-managed installs. (#159)

- **The quarantine window is now anchored on the earliest defensible
  evidence of the content's age**, not on whichever code path happened
  to mint the repository row. The anchor is the minimum over the ingest
  instant, hort's own earliest observation of that exact content in any
  of its repositories (derived live, no new schema), a trusted upstream
  publish time from *this* repository's own mapping, and the
  referenced-tree-descendant carve-out. Both minting paths share one
  derivation, so a pull-through coalesce no longer yields different
  windows depending on which caller won the dedup race, and content hort
  has already held for a while is no longer re-held for a full window on
  registration into a second repository. An upstream claim observed
  through another repository's mapping never shortens this repository's
  window. Release authority is unchanged — an artifact still needs its
  own `ScanSucceeded` / `ScanWaived` (ADR 0054, ADR 0007). (#163)

- **The zero-window quarantine carve-out now applies on the registration
  path as well as on ingest.** A referenced-tree descendant registered by
  content hash previously got a full quarantine window even though its
  parent's carve-out already applied to the same content, so the two
  minting paths disagreed about the same artifact. Both paths now share
  the carve-out decision. (#161)

### Fixed

- **Hosted cargo index entries now carry the crate's real dependencies
  and features.** Every hosted entry was synthesized with `deps: []` and
  `features: {}` because the publish handler kept only `name`/`vers` from
  cargo's publish body and discarded the rest. Cargo validates a feature
  edge against the *index entry*, not the dependency's own manifest, so
  publishing a workspace where one crate names a sibling's feature failed
  with "package `hort-http-core` depends on `hort-app` with feature
  `test-support` but `hort-app` does not have that feature" — which is
  what broke `v0.11.0-beta.8` after five of six crates had uploaded. More
  broadly, an entry claiming a crate has no dependencies hands any
  consumer an unbuildable graph. The publish handler now parses the whole
  metadata object and persists it in sparse-index shape (the publish
  API's `version_req` becomes the index's `req`, a renamed dependency's
  aliased name and original package name swap fields, and features using
  the namespaced `dep:` or weak `pkg?/feat` syntax are split into
  `features2` with `v: 2`), and the hosted index source serves it. The
  served `cksum` remains the stored CAS digest — a publisher-supplied
  checksum is neither trusted nor kept. A publish body whose metadata
  cannot be parsed is now rejected rather than ingested as an entry that
  silently claims no dependencies. Versions published before this change
  have nothing stored and keep serving exactly as they did; republishing
  is what fills them in. A cargo publish now also produces an SBOM with
  the crate's declared dependencies as components. (#188)

- **A crates publish that fails partway can now be re-run.** An upload is
  irreversible — a published version can be yanked, never replaced — so a
  release that broke on the third crate left the first two in the registry
  and cargo refused to republish them, killing the re-run at crate one.
  Every crate that never uploaded was then unshippable at that version and
  the whole tag had to be abandoned, which is what happened to
  `v0.11.0-beta.7`. The release job now checks each crate against the
  registry index *before* its attempt and skips the ones already there,
  logging each skip by name and version. The check is an index lookup, never
  an interpretation of cargo's exit status: after cargo has run, "refused to
  republish" and "the upload failed" are the same non-zero, so a loop that
  continued past it would ship a release with crates silently missing. Any
  genuine publish failure still aborts the release. (#186)

- **CVSS v3.x base scores are now computed from OSV severity vectors.**
  OSV frequently delivers severity as a bare vector with no
  pre-computed number — RustSec advisories almost always do. Severity
  extraction tried numeric `groups[].max_severity`, then a
  trailing-`/<float>` heuristic, then a text label; a pure vector
  survived none of them, so the advisory landed unscored and the SUP-4
  fail-closed rule recorded it as `Critical`. Fully-scored `Medium`
  advisories therefore tripped `severityThreshold: high` policies —
  concretely, `rsa 0.9.10` sat terminally `rejected` on `crates-proxy`
  and structurally blocked the vetted crates publish. Vectors are now
  parsed and scored per the CVSS specification, which is authoritative
  over the previous heuristics. Genuinely unscored advisories still
  fail closed to `Critical`. (#151)

- **CVSS-vector severity scoring is no longer inert on advisory
  enrichment.** The pre-scan enrichment queried OSV `/v1/querybatch`,
  which returns only each advisory's `id` and `modified` — no `severity`
  array, no `database_specific`. Every enrichment finding therefore fell
  through to the fail-closed `Critical` with a NULL CVSS score, which
  both made `severityThreshold` non-discriminating on affected
  repositories and let the manufactured `Critical` outrank the
  osv-scanner backend's correctly-scored finding in the dedup merge (the
  Marvin advisory RUSTSEC-2023-0071 scores 5.9 → `Medium`, but was
  recorded as `Critical`/unscored). Each distinct advisory id is now
  hydrated from `GET /v1/vulns/{id}` before severity is derived, cached
  on `(id, modified)` in the evictable `advisory:osv:vuln:` keyspace, one
  request per distinct id per scan. Hydration is fail-soft: a failure
  degrades that one advisory to the pre-existing unscored `Critical` and
  ticks the new `hort_advisory_hydration_total{result="failed"}` counter
  rather than failing the scan. New knob
  `HORT_ADVISORY_OSV_VULNS_URL` (default `https://api.osv.dev/v1/vulns`,
  Helm `worker.advisory.osvVulnsUrl`) — operators running an internal OSV
  mirror must point it there alongside `HORT_ADVISORY_OSV_API_URL`. The
  SUP-4 fail-closed default for genuinely unscored advisories is
  unchanged. (#172)

- **The worker's CAS volume is no longer mounted read-only on
  Kubernetes.** The chart mounted the shared CAS with `readOnly: true`
  on the worker Deployment, enforcing a consume-only contract that had
  already stopped being true: scan outcomes persist per-finding blobs as
  hash-referenced CAS objects, and worker-side prefetch ingest writes
  the blob it verified. Every worker-driven CAS write failed with
  `Read-only file system (os error 30)`. Compose had already dropped
  `:ro` for the same reason; the chart never followed. Operators on the
  filesystem backend need no action beyond the upgrade — the mount is
  now writable. (#157)

- **A just-ingested artifact is no longer re-pulled upstream on a
  prefetch re-POST.** The held-check treated a row with no quarantine
  lifecycle (`QuarantineStatus::None`) as "known upstream but not
  ingested" and re-enqueued it. That premise was structurally false:
  the query reads only `artifacts` rows, and every such row is ingested
  content — "known upstream, not ingested" manifests as the row being
  absent. `None` actually means ingested with no quarantine lifecycle,
  which is stamped by design for pure Sigstore-bundle referrers and for
  ingests matching no scan policy. Such rows are now classified held.
  Ingested-or-not and quarantine status are two dimensions and are no
  longer conflated. (#160)

- **Self-service prefetch against a virtual repository can see held
  state.** The held-check pre-flighted each item against the id of the
  repository named in the URL. A virtual repository owns no artifact
  rows — those are keyed by the member repository — so every warm
  reported `already_held: 0` and re-enqueued the full set, however much
  of it was already served. The check now walks the virtual's members in
  the ADR 0031 priority order. (#146)

- **`issue-svc-token --require-authority` is now scope-aware.** The
  preflight checked every declared permission against global-scope
  grants only, while runtime authorization checks the actual repository
  scope. A repository-scoped grant therefore satisfied runtime but
  failed the preflight, and the error text told the operator to create
  *global* grants — steering toward privilege widening exactly where
  narrow scoping was the point, and making repository-scoped bootstrap
  identities impossible without over-granting. The new optional
  `--repository <name>` checks each permission against that exact
  scope; omitting it keeps today's global check. (#156)

## [0.10.0] - 2026-08-09

### Security

- **Release-gate bypasses closed (audit package).** Three high-severity paths
  could serve or release content that had not passed the gate:
  `register_by_hash` (cross-repo blob mount and pull-dedup followers) skipped
  the scan gate entirely; a release-gate verdict commit could resurrect and
  release an already-rejected artifact from a stale snapshot; and the Events
  API skipped its admin-category check under bearer-only auth, exposing audit
  streams to any token. (#107, #108, #109)
- **Federated-identity and policy-resolution hardening.** A `ServiceAccount`
  whose `federatedIdentities` claims carried only a discriminator could be
  assumed by any subject from a shared issuer; duplicate-scope `ScanPolicy`
  envelopes resolved nondeterministically and could bypass the ADR 0016
  cross-opt-in linter. Both are now rejected at apply time. (#111, #112)
- **PyPI proxy input validation.** Serve paths no longer forward unvalidated
  request paths upstream, closing a path-traversal request-forgery against a
  credentialed upstream and an index-amplification vector. (#110)
- **Unknown-`kid` JWTs no longer force an unthrottled JWKS refetch**, which
  a caller could use to amplify load against the IdP and hold the refresh
  lock. (#114)
- **`/metrics` is now admin-listener-only and gated by a dedicated
  `read_metrics` grant, with no anonymous-scrape opt-out.** The main
  public listener no longer serves `/metrics` under any configuration
  (previously reachable there when `HORT_METRICS_BIND` was unset); the
  admin listener's `/metrics` route now requires
  `Permission::ReadMetrics` rather than bare authentication. (#113)
- **Rejected input is no longer echoed back** in OCI, npm and PyPI error
  messages. (#123)
- **Low-severity audit cleanup bundle** across TLS, secret handling,
  injection surfaces, OIDC and supply-chain documentation. (#117)

### Changed

- **Dependencies moved forward in one coordinated wave**, including
  `axum` 0.8, `sqlx` 0.9, `reqwest` 0.13, `jsonwebtoken` 11, `kube` 4 with
  `k8s-openapi` 0.28, the RustCrypto new generation (`rand` 0.10,
  `ed25519-dalek` 3) and a broad lockfile refresh. Auth- and adapter-facing
  majors were gated on validation- and error-classification parity before
  landing. (#95–#104, #128)
- **Dependency waves now ship as a minor release.** The policy and its
  rationale are recorded in `RELEASING.md`. (#121)
- **Pull-through proxy quarantine windows raised to three days** on the
  reference deployment, widening the supply-chain observation window.
  (#126)

### Fixed

- **Quarantine no longer strands or wrongly rejects artifacts under
  `provenance_mode: Required`.** Seed-imported artifacts stayed unscanned
  forever; zero-window OCI descendants were terminally rejected; a
  never-signed artifact could escape terminal rejection because its verify
  job starved; and a constituent ingested *after* its subject was verified
  (a later platform of a multi-arch image, for example) received no
  clearance at all and held indefinitely — it now clears itself against the
  signed subject at ingest. (#115, #131, #132, #135)
- **Upstream-registry parse failures are no longer reflected verbatim** to
  PyPI simple-index clients. (#124)

### Removed

- **`HORT_METRICS_REQUIRE_AUTH` / Helm `metrics.requireAuth`.** The
  anonymous-scrape escape hatch is retired end-to-end (config, chart,
  docs) — a caller must always present a bearer carrying the
  `read_metrics` grant. Setting the removed env var is silently
  ignored; a values file setting `metrics.requireAuth` is rejected by
  chart schema validation. (#113)
- **Inert `JwtAlg::Es512`.** The variant was accepted at apply time but
  could never match at runtime; it is gone rather than silently
  misleading. (#122)

## [0.9.15] - 2026-08-01

### Changed

- **`async-nats` 0.48 → 0.50.** Oversized event payloads now surface the
  new `MaxPayloadExceeded` error explicitly instead of a generic publish
  failure. (#89)

### Fixed

- **Freshly-pushed OCI artifacts are no longer terminally rejected by the
  provenance gate.** A race between the ingest transition and the
  provenance-verify worker let the verifier observe an artifact before its
  quarantine-window anchor was written; under `provenance_mode: Required`
  this terminally rejected a uniform ~25–31 % of first-party signed pushes
  as `Unsigned` within milliseconds of the push — manifest 404 by digest,
  dangling tags, failed `cosign sign` — with no API path to release them.
  Ingest now commits `ArtifactIngested` + `ArtifactQuarantined` in one
  transition (no enqueued job can observe an anchor-less artifact), the
  verifier requeues instead of rejecting when a young artifact still shows
  no anchor, and scan/provenance verdict commits are column-scoped so they
  can no longer overwrite a concurrent transition's quarantine columns
  with a stale snapshot. (#90)
- **`scan_indeterminate` artifacts serve an honest 503 on the OCI
  surface.** Previously HEAD returned 200 (to every caller) while GET
  failed with a 500 — a fail-closed policy hold miscategorized as a server
  fault, and a HEAD/GET parity break. Both OCI read gates now match
  exhaustively per artifact state; the 503 carries no `Retry-After` (the
  hold has no self-resolving deadline) and no write-authorized hold-read
  exemption. (#92)
- **Proxy 503 `Retry-After` reflects the real quarantine deadline** instead
  of clamping to ~1 second — the observation-window deadline is resolved
  against the active scan policy's configured duration. (#76)
- **CI token minting no longer fails with 503 "SA-stream append retry
  budget exhausted"** under concurrent service-account mints. (#87)
- **Versioned event-store appends on streams past 201 events no longer
  fail permanently** — expected-version derivation no longer reads a
  capped stream prefix; every unbounded-stream caller was audited and
  fixed. (#88)
- **Large image pushes complete** — chunked OCI blob uploads no longer die
  at the ~60 s gateway timeout. (#86)
- **hort.rs `/dl/` version-archive directories no longer return 403** for
  the archive page's download links. (#85)

### Security

- `event-listener` 5.4.1 → 5.4.2 (RUSTSEC-2026-0221). (#90, #92)

## [0.9.14] - 2026-07-27

### Added

- **Self-hosted project websites.** [project-hort.de](https://project-hort.de)
  (landing page + operator documentation) and [hort.rs](https://hort.rs)
  (hort-cli page + user documentation) now build from this repo
  (`scripts/build-site.sh`) and deploy via the `website` ansible role
  (`deploy/ansible/site-website.yml`) — self-contained static sites with no
  runtime dependency on hort-server. hort.rs additionally serves the
  permanent, append-only `/dl/` version archive of hort-cli release
  binaries; every archived asset is verified (SHA-256 + cosign keyless
  signature, the installer's own parameters) before it is placed, and a
  populated tag directory is never re-fetched or overwritten. (#77, #78)

### Changed

- **CI federation is discriminated by OIDC audience, not a GitHub
  `environment:`.** The `gha-ci` / `gha-release` service accounts now match
  on a dedicated `aud` claim (`hort-server-ci` / `hort-server-release`)
  requested per workflow; the CI jobs drop the non-gating `environment: ci`
  marker that minted a misleading GitHub deployment record on every routine
  run. `environment: release` stays on the release jobs, where the
  deployment records are meaningful. (#82)

### Fixed

- **The crates-publish release job can converge.** The vetted cargo proxy
  was warmed only by ad-hoc traffic, so `cargo publish` discovered hort's
  exact pinned dependency versions missing one 24-h quarantine window at a
  time. A `prefetch-warm` workflow now warms the proxy with the exact
  `Cargo.lock` on develop pushes and nightly (all misses quarantine in
  parallel, one window total), and the self-service prefetch endpoint
  accepts the spec-designed read+prefetch ServiceAccount caller instead of
  rejecting every CI run with a 403. (#80)

### Security

- **`lru` upgraded 0.12.5 → 0.18.1, removing RUSTSEC-2026-0002 outright**
  instead of accepting the advisory via build-side ignores or a registry
  Exclusion. The advisory-sync guard now treats registry-level `Exclusion`s
  as a hard-gated nuclear option (they waive a finding for *every* registry
  consumer, not just hort's own build) — any Exclusion without an explicit
  justification marker fails the gate. (#80)

## [0.9.13] - 2026-07-23

### Added

- **GitOps schema `project-hort.de/v1`.** The configuration schema is promoted
  to a stable `v1` ahead of the 1.0 release; every shipped example, fixture,
  and doc snippet now declares `apiVersion: project-hort.de/v1`. Existing
  `project-hort.de/v1beta1` trees continue to parse and apply identically —
  the bump is opt-in per file, with no forced operator migration. (#67)

### Changed

- **The auth-scope rate limiter now counts authentication *failures* only.**
  Previously every authenticated write drew down the anti-credential-stuffing
  bucket (`HORT_RATELIMIT_AUTH_PER_MIN`, default 60/min), so a bulk multi-arch
  `cosign copy` push would 429 regardless of the write limit — and no fixed
  ceiling could fit both workloads. Failed or anonymous credential attempts are
  still rejected at the configured rate *before* any token validation runs;
  valid-principal writes are now governed solely by the write scope
  (`HORT_RATELIMIT_WRITE_PER_MIN`, 300/min). (#66)
- **Hosted OCI manifest-PUT failures are now diagnosable.** The seven
  post-ingest write steps of the manifest/index PUT path previously collapsed
  any error into an opaque `500 INTERNAL` logged only at `warn!`; each now
  logs at `error!` naming the failing step, the underlying error, and the
  manifest/child digests. (#73)

### Fixed

- **The PyPI pull-through proxy is functional again.** The upstream simple
  index was fetched as HTML and hard-rejected over a 2 MiB cap, making any
  large package (e.g. `rapidfuzz`, whose HTML index is 5.3 MiB) permanently
  unresolvable; the fetch is now PEP 691 JSON via a streaming parser (with
  HTML fallback for non-compliant upstreams), and a `ReleasedOnly` proxy now
  enqueues a prefetch on a cold index request so `pip` can bootstrap instead
  of hard-failing on an empty index. (#72)
- **Cold pull-through blob downloads no longer 503 during the release
  handoff.** A freshly-fetched blob was always quarantined by ingest and
  released by its own scan a few seconds later — after the blocking GET had
  already returned 503, forcing a retry per cold layer. The GET now waits
  (bounded, `HORT_OCI_PULLTHROUGH_RELEASE_WAIT_SECS`, default 10 s) for the
  blob's own scan/release when its quarantine window has already elapsed, and
  serves 200 directly; genuine time-quarantines still 503 immediately, and
  the fail-closed release predicate is untouched. (#65)
- **Large-layer pull-through fetches no longer lose their coalesce leader.**
  A transient lock-store hiccup could lapse the 90 s leader lease mid-fetch
  (the heartbeat only retried on its next 30 s tick), abandoning an in-flight
  download and re-fetching from scratch. The heartbeat now retries within the
  tick, and the lease TTL is operator-tunable
  (`HORT_PULL_DEDUP_LEADER_LOCK_TTL_SECS`). (#65)
- **The `registry.hort.rs` chart-flavor publish has a target repository.** The
  self-contained-registry work shipped the publish job but never defined the
  `hort-charts` gitops repository, so the chart push 404'd; the repo (hosted,
  world-readable, release-gated push, no quarantine on the signed first-party
  chart) is now part of the shipped gitops tree. (#71)
- **Native-deploy worker scans work under the hardened systemd unit.** The
  worker unit's `ProtectSystem=strict` left trivy no writable cache directory,
  so every scan failed and scanned repositories never released anything; the
  unit now provisions a persistent `/var/cache/hort-worker` and points
  `TRIVY_CACHE_DIR`/`XDG_CACHE_HOME` at it. (#74)
- **Native-deploy scheduled-task tokens self-heal after a database rebuild.**
  The `cronjob-tasks` service-account token was only minted when its on-disk
  file was absent, so a DB recreate left every token-gated scheduled task
  silently failing with 401; the mint now runs on every deploy and re-mints
  exactly when the token row is missing. (#75)

## [0.9.12] - 2026-07-21

### Added

- **Self-contained Helm chart + `registry.hort.rs` hosting for the full cold-start
  chain.** A single `global.imageRegistry` chart value rewrites every image
  reference (server, worker, dex) to a sovereign registry, and a second chart
  flavor published to `registry.hort.rs/hort-charts/hort-server` ships that preset
  packaged. An operator can now run hort as the sole in-cluster registry and pull
  the entire cold-start chain — `hort-server`, `hort-worker`, `dex`, `postgres`,
  and the chart itself — from `registry.hort.rs` with **no** per-node
  `registries.yaml` (direct-upstream remains only the containerd fallback). Base
  images are mirrored to a hosted `hort-base` repo whose scan bar is
  `critical` (upstream base-image CVEs are not locally remediable, so a `high`
  bar would flap the mirror for a hold no operator can action). The default
  (`global.imageRegistry: ""`) renders byte-identically to the previous chart, so
  existing ghcr consumers are untouched. (#60)

### Changed

- **A proxied image index eagerly registers and prefetches its children on
  pull-through.** The index ingest now warms its child manifests and blobs up
  front instead of ingesting descendants sequentially on first access, removing
  the per-child sequential-ingest latency on multi-arch pulls. The release
  predicate is unchanged — each descendant still requires its own scan authority
  (ADR 0007). (#51)

- **Prefetch ingest now flows through the pull-dedup coalescer.** `prefetch_ingest`
  bypassed `PullDedup` despite its module doc claiming coverage; a concurrent
  prefetch and on-demand pull of the same content now coalesce to a single
  upstream fetch, as documented. (#57)

### Fixed

- **A wedged pull-dedup coalesce leader no longer poisons its followers
  indefinitely.** A stalled leader left every follower blocked until process
  restart (a root cause behind #53-class ingest stalls). The leader now runs under
  a bounded deadline (`HORT_PULL_DEDUP_LEADER_TIMEOUT_SECS`, default 600 s) with
  RAII cleanup that evicts the coalesce entry and releases waiting followers, and
  emits `leader_timeout` / `leader_cancelled` metrics. (#55)

- **Federation token-exchange no longer 500s on concurrent mints for the same
  service account.** Simultaneous token mints raced on the service-account
  event-stream append and the loser returned an unretried version conflict as a
  500. The append now retries under a bounded CAS loop, and a genuinely contended
  mint returns `503` with `Retry-After` rather than a 500. (#62)

- **GitHub Actions federation: the CI and release identities are now disjoint.** A
  release-environment OIDC token matched **both** `gha-ci` and `gha-release`, so
  the federated exchange failed closed on `multiple_sa_match` (401) and blocked
  every release-publish path under `HORT_PROXY_ENABLED`. `gha-ci` is now scoped to
  a non-gating `ci` deployment environment, making the two identities disjoint by
  construction (positive-claim scoping, the standard for GitHub-Actions OIDC
  federation). (#64)

### Security

- **The GitHub `hort-auth` action no longer echoes the token-exchange response
  body to CI logs.** On a failed exchange the action printed the raw response body
  (the GitHub twin of the previously-fixed GitLab leak), which could surface a
  bearer token in public Actions logs. The failure path is now sanitized. (#61)

## [0.9.11] - 2026-07-19

### Added

- **`HORT_STORAGE_PUT_TIMEOUT_SECS`** (default `300`) — an overall bound on the
  S3/object-store `put` multipart sequence (init + parts + complete + copy +
  staging delete). `object_store` bounds each individual HTTP call but nothing
  capped the aggregate, so a degraded backend could stall a pull-through
  ingest for tens of minutes with no error. The whole operation now fails fast
  at the configured bound.

### Fixed

- **Anonymous `docker pull` of a public pull-through repository now completes
  its token handshake.** `GET /v2/auth` unconditionally `401`'d without a
  `Authorization: Basic` credential, dead-ending the challenge-driven flow used
  by skopeo, buildah, podman and cosign. Per the OCI Distribution Spec token
  flow, the mint endpoint now issues a token for an anonymous request, granting
  `pull` exactly when the repository is public — byte-identical to the
  consume-side read gate. Private repositories, `push`/`delete` actions and
  `registry:catalog` are never anonymously granted; an all-private request
  mints a valid token with an empty `access[]` rather than a `401`. (#48)

- **A proxied multi-arch image index now releases together with its children.**
  Manifest ingest records `content_references` edges to the config and layer
  blobs it references (previously only index→child edges existed), and an
  artifact that is already a referenced descendant gets a zero-length
  quarantine window instead of waiting out a window in which no additional
  observation happens. The release predicate itself is unchanged — a descendant
  still requires its own scan authority (ADR 0007). These edges were initially
  written only on the hosted-push path; the pull-through ingest path now writes
  them too, which is what makes the behavior reach proxied images at all. (#46)

- **Purging a manifest or index no longer strands its `oci_*` reference edges.**
  Purge tombstones the artifact row rather than hard-deleting it, so the
  `ON DELETE CASCADE` never fired, and purge itself swept only the
  `primary_content`/`metadata_blob` refcount kinds. The dangling
  `oci_index_member`/`oci_subject`/`oci_config`/`oci_layer` source-edges then
  kept every blob they pointed at permanently ineligible for GC. Purge now
  sweeps all kinds, matching the manifest-DELETE path. (#49)

- **A pull-through blob that genuinely does not exist upstream now returns a
  terminal `BLOB_UNKNOWN` 404 instead of a `502`.** Every `fetch_blob` failure —
  including an upstream `404` — collapsed into a "upstream unavailable" `502`,
  which containerd treats as retryable: a pod with an absent layer sat in
  `PodInitializing` indefinitely with no `ErrImagePull`. (#53)

- **The clearance-gating provenance-verify jobs are enqueued at elevated
  priority.** For a repository that waives scanning, the signature-arrival
  provenance-verify is the only job gating release, and at priority 0 it queued
  behind the entire bulk ingest backlog — so `ProvenanceVerified` landed too
  late and the release sweep kept skipping for lack of clearance. The two
  clearance-gating enqueues (signature-arrival and expiry-backstop) now preempt
  bulk ingest work. Scheduling order only; the fail-closed release-authority
  gate (ADR 0007) is untouched. (#44)

- **The public Helm chart (`ghcr.io/project-hort/charts/hort-server`) is
  signed.** It was pushed unsigned, leaving Flux `.spec.chart.spec.verify`
  consumers with no legacy `.sig` tag to gate against. It is now keyless-signed
  (Fulcio OIDC — the same trust anchor as the public images) in legacy `.sig`
  mode, which is what Flux's source-controller discovers, and the release fails
  if the signature tag is missing. `install.md` §5.0 documents the `cosign
  verify` command and a Flux `matchOIDCIdentity` verify block. (#47)

### Changed

- **The storage `put` timeout reports which phase stalled.** On elapse it names
  the backend, the phase (init-multipart / reading / uploading-part /
  final-part / head-dedup / complete / copy / delete-staging), bytes read and
  parts uploaded, so a stalled ingest yields evidence rather than a bare
  timeout. An optional per-part debug timeline is available under
  `RUST_LOG=debug`. Pure observability — no change to multipart behavior. (#53)

## [0.9.10] - 2026-07-16

_Release-pipeline verification + CI / test-harness hardening; no user-facing
product changes. Restores and verifies the public release pipeline that failed
on v0.9.9, and hardens CI: GitLab pipeline scope (#38), podman-runner pinning
for the long test jobs (#39), `test:unit`/`test:coverage` parallelization (#43),
an OCI provenance-E2E read-grant fix (#41), E2E worker throughput (#44), and
`build-binaries` apt-retry hardening against transient mirror outages (#45)._

## [0.9.9] - 2026-07-15

### Added

- **`HORT_RATELIMIT_EXEMPT_CIDRS`** (Helm `rateLimitExemptCidrs`) — source CIDRs
  whose resolved client IP bypasses both rate-limit buckets. For first-party CI
  that shares one egress IP (or sits behind one ingress) and would otherwise
  collapse into a single per-IP bucket and `429` on legitimate publish bursts.
  Keyed on the trust-resolved client IP (not a spoofable header). Note: this
  also removes the per-IP anti-credential-stuffing limit on the token-mint
  paths for that range — list only fully trusted CI egress ranges.

### Fixed

- **A gitops boot-apply with an upstream host outside
  `HORT_UPSTREAM_ALLOWLIST_HOSTS` now parks the pod not-ready (`/readyz` 503)
  with a clear reason instead of writing some rows and then crashlooping.** The
  allowlist was enforced only in the write stage (after repository rows were
  already persisted), so a config gap left the config half-applied and the pod
  in `CrashLoopBackOff`. The check now runs in the pre-write validation pass, so
  the same violation is caught before any write and fails closed — the
  documented apply-time scope (create/update only; deletes and unchanged rows
  exempt) is unchanged.

- **The inbound rate limiter now sustains its configured per-minute rate.** The
  auth (`HORT_RATELIMIT_AUTH_PER_MIN`, default 60) and write
  (`HORT_RATELIMIT_WRITE_PER_MIN`, default 300) token buckets replenished one
  token per minute regardless of the cap, so after the initial burst, sustained
  traffic was throttled to ~1 request/minute — roughly 60×/300× tighter than
  documented — which persistently `429`'d automated writers such as CI pushing
  multi-layer images. Tokens now replenish at the configured per-minute rate.
- **Rate-limit `429` responses no longer advertise `Retry-After: 0`.** A
  sub-second wait is rounded up to at least 1 second, so a throttled client
  backs off for a beat instead of hot-looping on an immediate retry.

### Security

- Bumped `crossbeam-epoch` to 0.9.20 (transitive, via the Prometheus metrics
  exporter) to clear RUSTSEC-2026-0204 (invalid pointer dereference in the
  `fmt::Pointer` impl for `Atomic`/`Shared`). Bumped the `serial_test`
  dev-dependency to 3.5.0, which drops the unsound `scc` (RUSTSEC-2026-0205);
  `scc` was test-only and never shipped.

## [0.9.8] - 2026-07-05

Headlines: OCI **image-index / manifest-list (multi-arch) push**; **working
push-then-sign under `provenance_mode: Required`** end to end — an unsigned
image (index-shaped included) is held for the quarantine window, keyed cosign
v3 signatures verify against the pinned key, and a verified signature clears
the signed tree so the released image pulls (issues #13, #14, #15);
**identity-only service accounts** — authority comes exclusively from explicit
`PermissionGrant`s and issued-token caps snapshot the effective grants
(ADR 0044); OCI **chunked blob-upload push** (buildah / podman / skopeo stream
layers via HTTP `Transfer-Encoding: chunked`, no `Content-Length`, streamed and
bounded by the publish-body limit); and an authoritative, self-pruning
per-`(repo, principal)` OCI **upload-session cap**.

### Added

- **OCI image-index / manifest-list (multi-arch) support.** Hosted OCI repos
  accept `application/vnd.oci.image.index.v1+json` and Docker manifest-list
  PUTs (previously rejected `MANIFEST_INVALID`), so `skopeo copy --all`,
  buildah/podman multi-arch pushes, and cosign signing of the index digest
  work. An index is stored as a generic manifest artifact riding the normal
  quarantine/scan/release/provenance lifecycle; each child manifest is
  validated to exist in-repo on PUT, the declared media type is cross-checked
  against the manifest shape, and index→child membership keeps every child's
  content alive under GC. (issue #15, ADR 0043)
- A `hort-sweep-ticker` sidecar in the reference compose deployment enqueues
  the quarantine-release sweep periodically — compose's stand-in for the Helm
  `scheduledTasks` CronJobs / native `hort_timers`, so release and expiry
  decisions happen without a surrounding scheduler. (issue #14)

### Changed

- **The `ServiceAccount` gitops envelope is identity-only** — it declares who
  may assume the account (`federatedIdentities[].claims`, `fallbackRotation`)
  and confers no authority. A service account's authority is exclusively its
  explicit `PermissionGrant`s (`serviceAccount`-subject grants, ADR 0037), and
  the two unattended issuance sites — the federation `/exchange` and the
  fallback-rotation mint — derive the issued token's cap as a snapshot of the
  effective grants at issuance (the exchange additionally intersects the
  RFC 8693 `scope` parameter; rotated fallback tokens now carry the SA's real
  granted authority instead of an empty, deny-all cap). Grants added apply at
  the next exchange or rotation; revocations bite outstanding tokens
  immediately through the live grants leg. (issue #13, ADR 0044)
- A **write-authorized** caller may now `GET` (not just `HEAD`) a held
  manifest: keyed `cosign sign` resolves the subject manifest by GET before
  attaching a signature, so the HEAD-only exemption blocked in-place
  push-then-sign. A manifest is a routing document — layer blobs stay gated
  (503) for every caller while held, and non-writers still receive 503 for
  both verbs. (issue #14, ADR 0039)
- **Keyed cosign signing against a hosted repo must use
  `--registry-referrers-mode=oci-1-1`** (subject-based referrers); the legacy
  `sha256-<hex>.sig` tag mode is not linked to its subject on the push path, so
  a signature pushed that way stays invisible to the verifier.

### Removed

- The `role:` and `repositories:` fields of the `ServiceAccount` gitops
  envelope. An envelope still declaring them fails apply at parse; migration
  014 drops the columns. (ADR 0044)

### Fixed

- **An anonymous OCI read denied at the repository level now returns `401` +
  a mode-appropriate `WWW-Authenticate` challenge instead of a bare `404`.**
  A standard `docker pull` / kubelet pull of a private image presents no
  credential on its first request and only retries with its
  `imagePullSecrets` credential when challenged; a `404` gave it nothing to
  react to, so the pull failed even with a correctly configured Secret. The
  new challenge is byte-identical (modulo the request's own echoed scope)
  whether the repository is private or does not exist at all, so no new
  existence oracle opens; an authenticated caller without read access still
  gets the unchanged `404 NAME_UNKNOWN` anti-enumeration response. Anonymous
  writes on `/v2/*` now advertise the same mode-appropriate challenge scheme
  instead of a hardcoded legacy one.
- **A native `hort_pat_*` / `hort_svc_*` token presented directly on `/v2/*`
  now validates under `HORT_AUTH_PROVIDER=disabled` +
  `HORT_NATIVE_TOKENS_ENABLED=true` deployments, matching behavior already
  in place when an IdP is configured.** Such a token was previously rejected
  at the OCI auth middleware before it ever reached token validation.
- **The quarantine hold-read exemption keys on the principal's granted write
  authority, so native-token cosign signing completes.** The exemption
  (held-manifest HEAD/GET, held-blob HEAD existence probe) resolved `Write`
  through the grants leg **and** the presented token's cap. Standard OCI
  clients scope a subject read as `pull`, so under native tokens cosign's
  subject read rides a read-only capability token and the cap leg failed the
  exemption's `Write` check — the held-manifest GET `503`d and `cosign sign`
  aborted. The exemption now consults the grants leg alone (the read itself
  stays cap-gated); a bounded, documented exception to the ADR 0036
  cap-intersection invariant (ADR 0039 §10), with the fail-closed admin-claim
  guard preserved. The push-then-sign E2E gains a native-token-mode run where
  cosign's subject read rides a pull-scoped capability token. (issue #13)
- **The `GET /v2/` auth-discovery probe advertises the Bearer `/v2/auth`
  challenge when native tokens are enabled.** The probe hardcoded
  `WWW-Authenticate: Basic realm="hort"`, so OCI clients (skopeo, docker,
  podman, cosign) cached Basic for the session and never minted a capability
  token at `/v2/auth` — an opaque `hort_pat_*`/`hort_svc_*` credential then
  rode the Basic password slot, which no read-path validator accepts, and
  every read degraded to anonymous (private repos anti-enumerate to 404:
  pushes succeeded, the pushed image could not be read back or signed). The
  probe now emits the same challenge the `/v2/*` middleware selects: `Bearer
  realm="<base>/v2/auth",service="<host>"` with the signing key wired, legacy
  Basic otherwise. (issues #13, #16)
- **cosign v3 keyed signatures now verify.** `cosign sign --key
  --registry-referrers-mode=oci-1-1` (cosign v3) emits a Sigstore v0.3 bundle
  referrer carrying a DSSE envelope, not the legacy `simplesigning` layer the
  `cosign-key` backend consumed — a validly keyed-signed image was judged
  `NoAttestation` and rejected `Unsigned`. The keyed verifier now extracts the
  DSSE PAE signing input, signature, and subject-digest binding from a keyed
  bundle (no Fulcio chain) and verifies it against the pinned P-256 key,
  rejecting a signature over a different digest. The legacy `simplesigning`
  carriage and keyless (Fulcio-chain) bundle routing are unchanged.
  (issue #14, ADR 0039)
- **A validly signed image is now consumable under `provenanceMode: required`
  (provenance-clearance cascade).** cosign signs only the top-level digest, so
  the per-artifact provenance gate terminally rejected every constituent of a
  signed image — child manifests and config/layer blobs can never carry their
  own signature — leaving a released multi-arch index unpullable (child GETs
  404). A verified signature now cascades the provenance clearance to the
  constituents bound by the verified content: the index's signed bytes carry
  the child-manifest digests and each manifest's bytes carry its config/layer
  digests, so the signature over the root covers exactly that tree. The
  cascade is repository-scoped, applies only to held artifacts (a terminally
  rejected constituent stays rejected), clears only the provenance gate (scan
  and quarantine-window gates remain per-artifact), and records each cascaded
  clearance as a `ProvenanceVerified` attributed to the root digest via
  `cascaded_from`; the cascade append retries once on a version conflict and a
  re-verify of a directly-cleared subject re-drives it, so re-signing heals a
  partial cascade. A never-signed image and its constituents still reject
  `Unsigned` at window expiry. (ADR 0039 §11, ADR 0043)
- **`provenance_mode: Required` supports the push-then-sign CI flow.** An
  unsigned artifact is held for its quarantine window and re-verified when the
  cosign signature arrives; it is rejected `Unsigned` only if still unsigned at
  window expiry (issue #13).
- **OCI chunked blob-upload push now works (buildah / podman / skopeo).** The OCI
  blob-upload `PATCH` and finalize `PUT` handlers hard-required a `Content-Length`
  header and rejected its absence with `BLOB_UPLOAD_INVALID`. Clients that stream a
  layer via HTTP `Transfer-Encoding: chunked` send no `Content-Length` (RFC 7230
  §3.3.2 forbids it alongside chunked TE), so every such push failed
  deterministically. `Content-Length` is now optional on both handlers: when absent
  the body is streamed and bounded in-stream by the publish-body limit (an
  over-limit body is rejected `SIZE_INVALID` with staging capped), and the actual
  bytes staged are authoritative; when present the declared-length cross-check is
  unchanged. (issues 11, 12)
- **OCI blob-upload-session cap no longer leaks (issue 9).** The
  per-`(repo, principal)` cap on concurrent OCI upload sessions was a
  free-floating counter that only decremented on explicit release: an abandoned
  upload (POST with no final PUT and no DELETE) never decremented it, and its TTL
  refreshed on every increment, so a retry storm could pin the counter at the cap
  and raising the cap could not clear it. The cap is now an authoritative,
  self-pruning live-session **set**, keyed per `(format, repo, principal)` and
  reconciled on every admit: it age-prunes members older than the session max-age
  (catching both POST-only and PATCHed abandons), rejects at cap with no write
  (so a rejection never refreshes the TTL — the leak is structurally gone), and
  fails closed on CAS-loop exhaustion. Pathological write contention now surfaces
  as a transient `503 Service Unavailable` + short `Retry-After` (never a `500`).
  Adds the `HORT_OCI_SESSION_MAX_AGE_SECS` config knob (1..=604800 s, default
  3600; previously a hardcoded constant), a bounded cap-exceeded `Retry-After`
  (15 s), and the OCI-spec `DELETE /v2/<name>/blobs/uploads/<uuid>` cancel route.

### Security

- **`quick-xml` DoS advisories RUSTSEC-2026-0194 / -0195 accepted as a bounded
  risk.** `quick-xml` (transitive via `object_store`) has no `object_store`-
  compatible fixed release. It is reachable only through `object_store` parsing
  XML from the TLS-verified, operator-configured S3/Azure backend, not the
  artifact push/pull path. Ignored in `.cargo/audit.toml` + `deny.toml`; revisit
  when `object_store` adopts `quick-xml >= 0.41.0`.

## [0.9.7] - 2026-06-30

Headlines: ingest now commits the scan and
provenance-verify enqueues **atomically** with the artifact transition, closing
a dual-write window that could leave an artifact ingested-but-unscanned; a clean
re-scan of a terminal (rejected) artifact no longer loops the worker job; and a
RustSec advisory fix (anyhow → 1.0.103).

### Security

- **anyhow upgraded to 1.0.103 (RUSTSEC-2026-0190).** Fixes an unsoundness in
  `anyhow::Error::downcast_mut()` — adding context via `Error::context` and then
  calling `downcast_mut` constructed a mutable reference through a shared borrow,
  violating Rust's aliasing rules (undefined behavior). The patched release
  reworks how the reference is built.

### Fixed

- **Ingest commits its scan and provenance-verify enqueues atomically with the
  artifact transition.** The auto-scan and provenance-gate `jobs` rows now land
  in the **same transaction** as the `ArtifactIngested` / `ScanRequested` events,
  so a crash or failure between the two can no longer strand an artifact with the
  event but no job — which previously left it quarantined and unscanned until a
  manual rescan. The no-strand guarantee is backend-agnostic: the Postgres
  adapter fulfils it with one transaction; a native event-store backend must use
  a transactional outbox.
- **A clean re-scan of a terminal (rejected) artifact no longer loops the worker
  job.** Recording a now-clean scan onto an already-`rejected` artifact now
  records the fresh findings without attempting the illegal state transition,
  instead of failing and retrying the job to exhaustion. The artifact stays
  `rejected` (only an exclusion re-evaluation clears it); the refreshed findings
  enable an honest later recovery.

## [0.9.6] - 2026-06-27

Beta release (`0.9.6-beta.5`). Headlines: scan-policy is now **continuously
enforced** — a gate-affecting policy change re-derives every in-scope artifact's
verdict from its stored findings in **both directions**, closing a fail-open
where a tightened policy left already-decided artifacts un-re-evaluated (ADR 0041);
and OSV **informational** advisories (`unmaintained` / `unsound` / `notice`) no
longer over-block — they ride a non-enforcing **negligible** lane, operator-steered
per policy (ADR 0040). Plus a keyed cosign-key provenance backend.

### Security

- **Scan-policy is continuously enforced — the fail-open tightening gap is
  closed.** A gate-affecting `ScanPolicy` change (raising a severity threshold,
  adding a blocked class, `negligibleAction: block`, or adding/removing an
  exclusion) now re-derives every in-scope artifact's verdict from its **stored
  scan findings** under the new policy, in **both directions** — releasing
  now-passing rejections and re-holding now-failing releases — via an async
  worker pass off the request path. Previously a *tightening* re-evaluated
  nothing, leaving artifacts the operator had just declared unacceptable still
  downloadable. No scanner is re-run (the stored findings are the evidence) and
  no new release authority is added: a re-release fires only on the full
  cross-axis conjunction scan ∧ curation ∧ provenance, preserving the fail-closed
  release predicate. (ADR 0041)

### Added

- **OSV informational advisories ride the negligible lane, operator-steered.**
  RustSec `unmaintained` / `unsound` / `notice` advisories — which carry no
  CVSS — no longer map to Critical and reject an artifact; they route to the
  non-enforcing negligible tier. The new `ScanPolicy.negligibleAction`
  (`ignore`, the default — never block; `warn` — record only; `block` — reject)
  steers them per policy. The raw OSV class is persisted, so an
  exclusion-triggered re-evaluation respects the current policy; a finding with
  no CVSS **and** no recognised informational class still fails closed to
  Critical. (ADR 0040)
- **Keyed (cosign-key) provenance backend** — verify artifact provenance against
  a pinned cosign public key, alongside the existing keyless path.
- **gitlab-ci federation `ServiceAccount`** — a gitops `ServiceAccount` for
  GitLab CI OIDC federation against a hort instance.

### Changed

- **`cron-rescan-tick` is enabled by default** in the native `hort_timers`
  Ansible role, so proxied artifacts are rescanned on a cadence out of the box.

### Fixed

- **Native osv-scanner pinned to v2.3.8** (with a pin-sync guard against the
  worker container's `OSV_SCANNER_VERSION`). The native deploy had drifted to
  v1.9.1, which lacks the v2 `scan source` CLI the scanner adapter invokes — so
  every scan failed and proxied artifacts stranded in quarantine.
- **GitLab CI hort-auth federation** — install `curl` before the OIDC exchange,
  trust the internal-PKI CA before it, and configure the cargo
  credential-provider + HTTP-Basic token, so federated CI works against a hort
  instance behind an internal CA.
- **Prefetch resolves cargo/npm download URLs from authoritative upstream
  metadata.** Proxied cargo/npm dependency prefetch now derives each download URL
  from the package's authoritative upstream metadata, so prefetched artifacts
  fetch from the correct location.

## [0.9.5] - 2026-06-26

Beta release (`0.9.5-beta.1`). Headline: the OCI `/v2/auth` authorization model
is reworked into a per-identity **capability token**, service accounts are made
**strictly non-admin**, and a first-class **no-IdP admin-bootstrap** path is added.

### Security

- **OCI `/v2/auth` is a per-identity capability token.** The token-exchange mint
  no longer confers ambient admin (the mint principal carries `claims: []`);
  authority is the caller's `User`-subject `PermissionGrant`s intersected with the
  token cap — the same basis the consume side re-evaluates — closing the over-grant
  where the mint granted `pull`/`push` scopes that the `/v2/*` resource gate then
  denied. Admin is not an OCI scope and the token never carries it. (ADR 0036)
- **Service accounts are strictly non-admin — no exception.** `issue-svc-token`
  rejects `--permission=admin` and requires a pre-existing gitops `ServiceAccount`;
  a gitops `serviceAccount`-subject `PermissionGrant` may not carry `admin`; and the
  apply-time RBAC linter no longer exempts SA-owned `Admin` grants from the
  high-privilege reject. (ADR 0037, ADR 0038)
- **Fail-closed cap backstop.** A cap-bound native token (`Pat` / `ServiceAccount`)
  presenting the `admin` claim with a `None` cap is denied; OIDC and CliSession
  principals, which legitimately carry no cap, are unaffected. (ADR 0036)

### Added

- **gitops `PermissionGrant` may target a ServiceAccount by name** —
  `subject: { kind: serviceAccount, name: … }` resolves at apply to a `User`-subject
  grant on the SA's backing user, so a non-admin service account can hold scoped
  `read` / `curate` / `admin_task_invoke` / global authority without an `is_admin`
  bit (the domain `GrantSubject` taxonomy is unchanged). (ADR 0037)
- **`hort-server admin bootstrap-session`** — a DSN-gated, short-lived (≤1 h),
  non-service-account admin token for the no-IdP / first-admin / break-glass path,
  gated by `HORT_TOKEN_ALLOW_ADMIN`. (ADR 0038)
- **Optional Dex IdP sidecar** (Helm + Ansible) wiring the human-admin
  OIDC → CliSession path; **off by default**. (ADR 0038)
- **Native systemd timers** for the periodic worker tasks (`hort_timers` Ansible
  role) — the native-flavour equivalent of the Helm CronJobs.

### Changed

- **Admin-identity model — IdP-assumed, zero standing privilege.** Human admin is
  OIDC (Dex / the organisation's SSO) → CliSession, or the DSN-gated
  `bootstrap-session`; the deployment de-admins the operator/cron service accounts
  (`maintainer-dev` → `read`, `maintainer-curator` → `curate`, `cronjob-tasks` →
  `admin_task_invoke`, all non-admin via standalone `serviceAccount` grants).
  Destructive scheduled tasks (`eventstore-archive` / `retention-purge` /
  `retention-evaluate`) are **off by default** — they require a fresh admin session
  and are run on demand (a propose→confirm→execute approval workflow is the tracked
  follow-on). (ADR 0038)
- **`HORT_TRUSTED_PROXY_CIDRS`** is set in the deployment so `hort-server` observes
  the real client IP behind the edge (nginx) proxy.

### Fixed

- **`issue-svc-token` could not find a gitops-declared service account**
  (`0.9.5-beta.2`). `svc_username` looked up `hort-svc-<name>` while a gitops
  `ServiceAccount` apply creates its backing user as `sa:<name>`, so the
  "requires a pre-existing gitops ServiceAccount" mint flow — the Ansible
  `maintainer-dev`/`maintainer-curator` tokens and the Helm `cronjob-tasks` token
  — was non-functional in `0.9.5-beta.1`. The convention is now single-sourced as
  `hort_domain::entities::service_account::backing_username` and every
  construct/parse site (CLI lookup, gitops apply, auth parse, k8s payload) routes
  through it, guarded by a cross-convention test.
- **Server parked (registry served `503`) when the IdP was disabled**
  (`0.9.5-beta.2`). The Ansible gitops tree shipped the `admins` `ClaimMapping`
  unconditionally, but the native/podman flavors default
  `HORT_AUTH_PROVIDER=disabled`; `hort-server`'s gitops preflight then refuses the
  dormant ClaimMapping and parks (`/readyz=503`, status-only). The deploy now
  gates the ClaimMapping on the IdP being enabled (`hort_dex_enabled`) and removes
  it otherwise — which also un-parks a host previously synced with it present.
  Admin without an IdP remains the DSN-gated `bootstrap-session` (ADR 0038).

## [0.9.4] - 2026-06-21

Beta release. The feature set is described in the documentation under `docs/`.

### Added

- **Maven / Gradle format handler.** Pull-through proxying for Maven Central and
  Gradle repositories, covering the multi-file artifact shape (POM, JAR, and the
  per-file `.sha1` / `.md5` sidecars) and Gradle module metadata. Upstream
  transfers are checksum-verified against a SHA-1 floor — a Maven artifact whose
  upstream checksum cannot be verified is not served (ADR 0032 *Maven/Gradle
  multi-file handler*, ADR 0033 *SHA-1 upstream transfer-verification floor*).
- **Maven / Gradle virtual (aggregated) repositories.** `type: virtual`
  aggregation now covers Maven/Gradle (joining npm / PyPI / Cargo), so a single
  virtual repo can front several Maven members under the same
  dependency-confusion defences (ADR 0031).
- **Public supply-chain deployment for `registry.hort.rs` (dogfood).** An
  Ansible-based deployment (rootless-podman and native-systemd flavours) plus the
  gitops config — repositories, upstream mappings, policies, service-account
  federation — and CI workflows that run hort as its own public pull-through
  registry (ADR 0034 *public dogfood deployment*).

### Changed

- **Federated CI OIDC token exchange is now independent of interactive-OIDC
  configuration.** `POST /api/v1/auth/exchange` serves the federated-JWT branch
  (GitHub Actions / GitLab CI → gitops `OidcIssuer` rows) with
  `HORT_AUTH_PROVIDER=disabled`, requiring only `HORT_NATIVE_TOKENS_ENABLED=true`
  — no interactive identity provider (`HORT_OIDC_ISSUER_URL` /
  `HORT_OIDC_CLI_CLIENT_ID` / Keycloak) is needed. The interactive device-flow
  path and its `/.well-known/hort-client-config` discovery doc stay gated on
  `HORT_AUTH_PROVIDER=oidc`. The three federation ship-gate guardrails
  (JWT-replay seen-set, `aud`→ServiceAccount binding, empty-claims fail-closed)
  are unchanged.

### Fixed

- **OCI registry is now usable by the standard clients (`crane`, `docker`,
  `oras`).** The Distribution-Spec `/v2/auth` token endpoint declared its
  repeatable `scope` query parameter as a list but parsed it with an extractor
  that cannot decode repeated query keys, so every *scoped* token request — i.e.
  every real pull or push — failed query deserialization with
  `400 "expected a sequence"` and no bearer was ever issued. Scoped requests now
  decode correctly (single and repeated `scope=`), and a per-request scope-count
  cap bounds the (credential-gated) authorization work.
- **OCI pull-through and hosted push now work for gated / private
  repositories.** The `/v2/auth` scope→repository mapping resolved the full
  Distribution-Spec name `<repo_key>/<image>` as a repository key, which never
  matched the first-path-segment repo key, so a scoped token carried an empty
  grant set and the consume-side cap denied every pull/push on a non-public
  repo. The scope now resolves the owning repository by its first path segment,
  matching the `/v2/*` request path; public-repo anonymous pulls were
  unaffected.
- **OCI `/v2/auth` no longer rejects the credential before the token exchange.**
  The `/v2/*` bearer-auth middleware (`oci_bearer_auth`) also ran on the
  `/v2/auth` token endpoint and treated the inbound `Basic <PAT>` as a bearer
  JWT — which a PAT (or a federated token) is not — so it was rejected with
  `401` before the PAT→token-exchange handler could run, breaking push/pull and
  proxy pull-through for every credentialed client. The middleware now
  path-skips `/v2/auth`, so the handler's PAT validation and bearer mint run.
- **PyPI virtual (aggregated) repositories are now installable with `pip`.** A
  `pip install` through a `type: virtual` PyPI repo failed on pip's PEP 658
  `.metadata` fetch — the metadata endpoint served against the virtual repo
  (which owns no artifacts) and returned `404`, which modern pip treats as a
  hard error. The `.metadata` endpoint now routes through the same authoritative
  member the wheel download resolves, so the served metadata always matches the
  served wheel (ADR 0031 *virtual-repository dependency-confusion defences*).
- **Gated cargo proxies are now reachable by a plain `cargo build`.** A gated
  (`isPublic: false`) cargo pull-through proxy could not be used by the stock
  `cargo` client: cargo only sends its token once it has read `auth-required`
  from `config.json`, but the handler omitted that field and returned
  `NotFound` to anonymous callers, so cargo's bootstrap failed with
  `config.json not found in registry`. The cargo `config.json` endpoint is now
  anonymously readable and advertises `auth-required: <!is_public>`; the crate
  index and download endpoints stay gated (anonymous requests still collapse to
  `NotFound`). This is a deliberate, bounded anti-enumeration give-up for
  `config.json` only — repo existence + `dl`/`api` URLs become visible, never
  crate content (ADR 0035 *cargo config.json anon-readable + auth-required*).
  npm and pypi are unaffected (their clients always send credentials). Closes
  #1.
- **The config-scrub CronJob now mounts the gitops-config volume.** The Helm
  scrub job started without the directory `HORT_CONFIG_DIR` points at; it now
  mounts the same gitops-config volume the server uses, so the directory exists.
- **OCI push no longer fails on the blob-existence pre-check under a quarantine
  policy.** During an OCI push, a write-authorized client's blob-existence `HEAD`
  was routed through the quarantine read-gate and returned `503`, blocking the
  push. The existence pre-check for a write-authorized push is now exempt from
  the quarantine gate, so pushes to a quarantined repository proceed while reads
  stay gated.

## [0.9.3] - 2026-06-21

Beta release. The feature set is described in the documentation under `docs/`.

### Added

- **Virtual (aggregated) repositories** for npm, PyPI, and Cargo (ADR 0031). A
  `type: virtual` repository aggregates several member repositories — for
  example a private hosted member plus the public pull-through mirror — behind a
  single registry URL. Serve-time resolution merges the members' indexes
  (packument / simple-index / sparse-index) and resolves concrete downloads
  *first-authoritative*: the highest-priority member that holds a coordinate
  serves it, and that member's release/quarantine gate is surfaced verbatim.
  Name-level pinning is a dependency-confusion defence — a package name owned by
  a higher-priority (e.g. private) member is never shadowed or substituted by a
  lower-priority public proxy. Per-member visibility is enforced on every read
  (ADR 0021): a caller who cannot see a private member never learns it exists,
  so a public virtual cannot leak a private member's contents. Virtuals are
  read-only; publishing to one is rejected.

### Fixed

- **Authenticated reads of private repositories returned 404.** Authenticated
  callers — admins included — were wrongly denied read access to private
  repositories: npm packuments and tarballs, PyPI simple indexes and files,
  Cargo config / sparse-index and crate downloads, and the admin security-score
  endpoints. The GET read path resolved the request principal from the wrong
  request-extension slot (the write-path "bare" slot instead of the optional
  slot the read middleware populates), so every authenticated read silently fell
  back to anonymous and a private repository appeared absent. Fail-closed —
  authenticated users were denied and no private data was disclosed — but it
  broke legitimate authenticated access (and blocked the virtual-repository
  feature, whose private member could never be read). Write paths
  (publish / upload) were unaffected.
- **GitHub release pipeline now ships assets.** Releases are created as a draft
  and then published, so they succeed under GitHub's "Immutable releases"
  setting; earlier releases could publish with zero assets. The multi-arch
  (amd64 / arm64) `hort-worker` image and the Helm chart are now published on
  release, and the CI coverage and `cargo-deny` jobs were repaired.

## [0.9.2] - 2026-06-17

Beta release. The feature set is described in the documentation under `docs/`.

### Added

- **`hort admin workers list` / `GET /api/v1/admin/workers`** — an admin-only
  read of the scanner-worker registry showing each worker's advertised
  backends and liveness (`live` flag + last-heartbeat age). A worker that has
  stopped heartbeating stays in the listing as `LIVE=NO` rather than being
  filtered out, so operators can distinguish "my trivy worker died" from "I
  never had one". This wires a reader for the worker heartbeat, which had been
  orphaned when H20 moved `scanBackends` validation off the live registry (the
  `ScannerRegistryRepository::list_live(window)` port method becomes
  `list_all()` — the ~5-minute liveness threshold moves up to the use case as
  a presentation policy). Admin-gated; reuses the existing admin auth.
- **`scanner-registry-prune` housekeeping task** — a default-enabled worker
  CronJob (hourly) that deletes `scanner_registry` rows whose last heartbeat is
  older than 7 days, so pod churn (rollouts, HPA scaling) cannot grow the
  worker-coordination table without bound. Degrades safe (a missed prune only
  grows the table; liveness is recomputed on read). The admin worker-list read
  is also defensively bounded (`ORDER BY last_heartbeat DESC LIMIT 1000`).

### Fixed

- **Gitops boot no longer parks not-ready on a fresh deployment with a correct
  `scanBackends` policy (regression H20).** Apply-time `ScanPolicy.scanBackends`
  validation now checks each entry against the binary's compiled-in scanner set
  (`hort_app::scanning::KNOWN_SCAN_BACKENDS` = `trivy`, `osv`) instead of the
  live `scanner_registry` worker table. The previous live-registry check was a
  boot-ordering hazard: on a fresh DB the server applies config before any
  `hort-worker` has registered its first heartbeat, so a correct
  `scanBackends: [trivy]` policy was rejected fail-closed, parking the server
  not-ready (`/healthz` 200, so the kubelet never restarted it) until an
  operator manually bounced the pod. A backend name is a permanent property of
  the build, independent of worker-registration timing; whether a worker
  advertising it is *running* is a runtime-liveness concern for metrics/health,
  not a config-validity error. Typos / unsupported backends are still rejected
  at apply. (ADR 0007 `ScanWaived` empty-list waiver and the ADR 0016
  `trust_upstream_publish_time_requires_scan_backends` linter are unaffected.)
- **OCI manifest pull-through no longer 404s against strict content-negotiation
  registries (e.g. `registry.k8s.io` / Artifact Registry).** Two fixes: (1) the
  inbound handler now reads **all** `Accept` header lines (`get_all`), not just
  the first — a client that splits its `Accept` across multiple header lines
  (Go's `http.Header.Add`, as containerd's resolver uses) was being silently
  narrowed to its first type; and (2) the upstream manifest fetch now always
  advertises the full canonical manifest media-type set (OCI manifest/index +
  Docker manifest/list) regardless of the client's `Accept`, so a pull-through
  fetches the canonical manifest it will store rather than a per-client
  projection. Previously, a Docker manifest-list image (e.g. `pause:3.9`)
  fetched with an OCI-only `Accept` made the backing registry return 404, which
  hort surfaced as "manifest unknown". Narrow clients are still negotiated at
  serve time (`406` with manifest-pair leniency), and the cached representation
  is now `Accept`-independent.

### Security

- Provenance verification now cryptographically verifies the Rekor **Merkle
  inclusion proof** and the **checkpoint signature**, fully offline, against
  the pinned trust root's Rekor key (Sigstore v0.3 bundle format) — closing
  the `sigstore-rs#285` gap where `sigstore` 0.14's `verify_digest` left those
  steps unimplemented. A bundle whose transparency-log entry is not provably
  in the log is now rejected (`RekorNotFound`) instead of being accepted on
  the strength of the Fulcio chain + signature alone. (ADR 0027)
- The container-image publish pipeline now **fails closed on fixable CRITICAL
  CVEs**: the release Trivy scan runs with `exit-code: 1`, `severity: CRITICAL`,
  and `ignore-unfixed: true`, so a newly-disclosed fixable CRITICAL blocks the
  publish until it is patched or explicitly accepted in `.trivyignore`. (audit
  INFRA-3)
- `HORT_BEARER_ALLOW_OVER_HTTP=true` together with an `https://`
  `HORT_PUBLIC_BASE_URL` is now a **boot hard-fail**
  (`ConfigError::BearerOverHttpContradictsTls`): a TLS-terminated deployment has
  no legitimate need to relax the bearer-token transport guard, so the
  self-contradictory pair is rejected at startup rather than silently widening
  the bearer-token exposure surface. A genuinely plaintext-internal deploy
  (`http://` or unset public base URL) is unaffected. (audit INFRA-13)
