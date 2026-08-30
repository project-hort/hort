# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Changed

- **`RELEASING.md`'s promotion checklist gains a Migration-notice step.** A
  release whose migration set contains a contraction now carries a
  `### Migration notice` changelog entry naming the dropped or narrowed
  object, the minimum binary version that tolerates the change, and the
  operator action, so a maintenance window can be planned rather than
  discovered.

### Fixed

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
