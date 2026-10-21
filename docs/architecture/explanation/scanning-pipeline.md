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
content-adjudicating port: `scan(target, sbom) -> ScanAnalysis`, plus a
`name()` that must match the identifier operators write in
`ScanPolicy.scan_backends`, and a `health_check()` probed at worker boot.
Scanner adapters live in their own crates and depend only on
`hort-domain`.

The port is **format-aware**, and both halves of its signature are
load-bearing:

- `ScanTarget` carries the content hash *plus* the artifact's format key,
  its coordinates, and an `ArtifactKind` — what the bytes are
  (`MavenJar`, `MavenPom`, `NpmTarball`, `CargoCrate`, `PyWheel`,
  `PySdist`, `OciBlob`, `OciManifest`, `Other`). A content scanner
  selects its analyzers by file name and directory layout, so an adapter
  handed only a hash has no way to write the bytes down under a name any
  analyzer will look at. The kind comes from the artifact's own format
  handler (`FormatHandler::scan_kind`), classified from what that handler
  already knows about its layout — a Maven path's extension, an OCI row's
  path prefix, the single payload shape npm and cargo publish. A format
  with no registered handler gets `Other`, which is a refusal rather than
  a guess.
- `ScanAnalysis` separates **a verdict** (`Analysed(findings)`, empty or
  not) from **no verdict** (`NothingAnalysable(reason)`). See
  *["Nothing analysable" is not "clean"](#nothing-analysable-is-not-clean)*
  below for why a `Vec<Finding>` return type could not express that and
  what went wrong while it did not.

Two families ship:

- **Trivy** (`crates/hort-adapters-scanner-trivy/`) pulls the artifact
  bytes from `StoragePort::get`, **materialises them by kind** into a
  `tempfile::TempDir` (removed on drop, including panic and error paths),
  shells out to `trivy fs`, `trivy rootfs` or `trivy image --input` with
  `--format json`, and parses the report. It ignores the supplied SBOM and rediscovers
  components from the payload itself — which is exactly what makes it the
  adjudicator of record against the actual bytes, and exactly why the
  materialisation has to be right.
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

`querybatch` answers only *which* advisories affect a package: every
entry it returns carries an `id` and a `modified` timestamp and nothing
else — no CVSS vector, no severity label, no affected ranges. Deriving
severity straight off that record finds no signal and lands on the
fail-closed `Critical` with a NULL score for every advisory, which both
defeats `severityThreshold` filtering and lets the enrichment finding
outrank a correctly-scored scanner finding in the dedup merge. `query`
therefore resolves each **distinct** advisory id to its full
`/v1/vulns/{id}` record before building findings
(`crates/hort-adapters-advisory-osv/src/hydrate.rs`,
`HORT_ADVISORY_OSV_VULNS_URL`). Hydrated records are cached on
`(id, modified)` — `modified` is exactly the invalidation signal
`querybatch` hands back, so a record is re-fetched only when OSV changed
it. Hydration is best-effort like the enrichment around it: a failure
degrades that one advisory to unscored (hence `Critical`, per SUP-4) and
ticks `hort_advisory_hydration_total{result="failed"}` rather than
failing the scan.

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
case-insensitive `(purl, vulnerability_id)` (`merge_findings`).

A collision is won on **information quality first, severity tier
second** ([ADR 0059](../../adr/0059-finding-reconciliation.md)). Severity
tier alone cannot separate a genuine `Critical` from the SUP-4
fail-closed floor a backend emits when it cannot read a severity at all —
the two records are byte-identical — so the floor used to win every
collision and discard the correctly-scored reading. `Finding.severity_basis`
records which of the two it is (`Unassessed` at the three fail-closed
sites, `Assessed` everywhere else), and a finding that carries a real
reading — a CVSS score, a recognised informational class, or `Assessed` —
supersedes one that does not, **across tiers**. Two real readings still
compare by tier, so a scored `Low` never talks down a scored `Critical`
([ADR 0007](../../adr/0007-fail-closed-quarantine-release-predicate.md)).
`HORT_FINDING_MERGE_ALLOW_INFORMED_DOWNGRADE=false` reverts the merge to
strict always-fail-closed, which makes the gate stricter.

That merge reconciles two readings of one advisory **id**. One advisory
arriving under **two ids** is handled earlier, in the OSV adapters
themselves: OSV returns a RustSec advisory and its GitHub-reviewed GHSA
mirror as separate records in the same response, and the bare mirror would
otherwise shadow its better-informed sibling with a fail-closed `Critical`
the merge cannot reconcile. Both OSV adapters collapse mutually-aliased
findings for a package into one finding per advisory, keeping the
best-informed member — a real CVSS, then a recognised informational class,
then a severity read without a score, then the fail-closed floor — so a
genuinely-scored advisory still blocks. The collapsed-away identifiers ride
along on the survivor's `aliases`, so an operator exclusion keyed by any of
them still matches.

`record_outcome` then hands
the merged finding list to the consumer boundary,
`QuarantineUseCase::record_scan_result`
(`crates/hort-app/src/use_cases/quarantine_use_case.rs`).

That handoff is the pipeline's single most load-bearing property:
**one Postgres transaction** commits the findings blob reference, the
per-finding `scan_findings` projection rows, the `sbom_components`
projection replace, the artifact's state transition, the
`repo_security_scores` delta, and the event batch. There is no state
in which the event log says one thing and a projection says another.

### What the verdict does: `enforcement: reject | record`

`record_scan_result` computes the verdict through the one pure
evaluator (`evaluate_scan_result`) and then does what the resolved
policy's `enforcement` says. Under the default `reject`, a blocking
verdict commits the reject triple (`ScanCompleted` +
`PolicyEvaluated(Fail)` + `ArtifactRejected`). Under `record`, the
same evidence and the same audit event commit — the findings blob, the
per-finding rows and `PolicyEvaluated(Fail, violations)` are all
written identically — and the `ArtifactRejected` is withheld: the
artifact's quarantine status is untouched by the verdict.

That is deliberately the *only* difference. The enforcement branch
lives at the last step of the evaluator, after every rule has run, so
the recorded verdict is byte-identical across the two modes; the
tighten and loosen directions of continuous enforcement
([ADR 0041](../../adr/0041-continuous-scan-policy-enforcement.md))
therefore re-derive exactly the verdict the initial scan computed.

The consequence for release is that a `record`-mode artifact's own
latest `ScanCompleted` is dirty, so it cannot carry the
`ScanSucceeded` authority. It releases through the distinct
`ScanRecorded` authority instead
([ADR 0007](../../adr/0007-fail-closed-quarantine-release-predicate.md)),
which requires that a `ScanCompleted` exist on the artifact's stream —
`record` un-gates the *verdict*, never the *observation*, so a
never-scanned artifact is still held — and which carries the same
provenance AND-precondition as the other timer authorities.

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
That curve is not the scan pipeline's own any more — it lives in
`hort_app::retry_backoff` and the task dispatcher spends the same four waits
for every other job kind, so five attempts mean the same ~96-minute window
wherever the number appears. Change it in one place or not at all.
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

## Materialisation: how the bytes reach an analyzer

Trivy selects analyzers by **file name, extension and directory layout**,
and in filesystem mode it does not open archives. A directory holding one
opaque blob is therefore handing it nothing: no analyzer claims the file,
the report comes back with no analysed target, and — read as a finding
list — that is an empty one. So the Trivy adapter materialises each
artifact according to its `ArtifactKind`
(`crates/hort-adapters-scanner-trivy/src/workspace.rs`):

| kind | on disk | Trivy target | why that target |
|---|---|---|---|
| `MavenJar` | one file, keeping its `.jar` / `.war` / `.ear` / `.par` name | `rootfs` | a Java archive is post-build: Image and Rootfs only |
| `MavenPom` | one file named `pom.xml` | `fs` | `pom.xml` is pre-build: Filesystem and Repository only |
| `NpmTarball` | gzip-tar extracted to `node_modules/<name>/`, the archive's own root directory stripped | `rootfs` | a `package.json` is claimed only under `node_modules`, by the Image and Rootfs targets |
| `CargoCrate` | gzip-tar extracted into the workspace | `fs` | `Cargo.lock` is read by every target; `fs` also reads the pre-build side |
| `PySdist` | gzip-tar extracted into the workspace | `rootfs` | `*.egg-info/PKG-INFO` is post-build egg metadata: Image and Rootfs only |
| `PyWheel` | ZIP extracted into the workspace | `rootfs` | `*.dist-info/METADATA` is post-build: Image and Rootfs only |
| `OciBlob` — a tar layer | tar / gzip-tar extracted as a root filesystem | `rootfs` | a layer *is* a root filesystem |
| `OciBlob` — anything else | nothing; no invocation | — | an image config carries no package surface |
| `OciManifest` | nothing; no invocation **for the row's own bytes** — but see [the composed image](#the-composed-image-is-the-scan-unit) | — | the manifest document itself carries no package surface; the composition it names does |
| `Other` | nothing; no invocation | — | no handler claims these bytes |

**The target column is not a free choice.** Trivy's
[coverage matrix](https://trivy.dev/docs/latest/coverage/language/)
states, per analyzer, which of its four targets — Container Image,
Filesystem, Rootfs, Repository — runs it, and the split falls almost
exactly along the pre-build / post-build line. A **built artifact**
(`JAR`/`WAR`/`EAR`/`PAR`, a Python `egg`/`wheel`, a `package.json`
under `node_modules`, a cargo-auditable or Go binary) is analysed by
**Image and Rootfs only**; a **pre-build declaration** (`pom.xml`,
`package-lock.json`, `requirements.txt`, `poetry.lock`, `uv.lock`,
`gradle.lockfile`) by **Filesystem and Repository only**; `Cargo.lock`
by all four. Picking the wrong one is silent: the analyzer never runs,
the report names no analysed target, and the artifact can never get a
verdict. A JAR scanned with `trivy fs` produces exactly that non-result.

The table's target column is `rootfs` or `fs` because it is about **one
stored object**. The Container Image target was once written off here —
"hort has no container image to scan" — and that was a derivation rather
than a decision: hort holds the manifest, the config and every layer, and
the manifest's bytes name them in order. [ADR
0064](../../adr/0064-a-filesystem-finding-is-about-the-composed-filesystem.md)
assembles them; see [the composed image](#the-composed-image-is-the-scan-unit).

The layouts follow from what the analyzers read. A **Java archive**
needs only its extension: Trivy's JAR analyzer opens the archive itself
and reads the embedded `META-INF/maven/**/pom.properties` coordinates
([Trivy Java coverage](https://trivy.dev/latest/docs/coverage/language/java/)).
A **POM** is claimed by the Maven analyzer, which keys on the literal
name `pom.xml` — the artifact's own `log4j-core-2.14.1.pom` matches
nothing. **Wheels and sdists** are claimed through paths *inside* them
(`*.dist-info/METADATA`, `PKG-INFO` —
[Python coverage](https://trivy.dev/latest/docs/coverage/language/python/)),
so the container has to be opened. An **npm tarball** needs both the
extraction and the *installed* layout: Trivy claims a `package.json`
only under `node_modules`, so the package is planted at
`node_modules/<name>/` (a scoped name keeping its `@scope/` directory)
with the tarball's own root directory — conventionally `package/` —
stripped, which is what `npm install` does with the same bytes. An
**OCI layer** is a root filesystem whose evidence is the distro package
database (`var/lib/dpkg/status`, `lib/apk/db/installed`,
`var/lib/rpm/*`) plus any shipped lockfiles, and
[`trivy rootfs`](https://trivy.dev/latest/docs/target/rootfs/) is the
target documented for that shape.

**An OCI layer and an OCI image config are one kind on purpose.** Every
blob is stored with `content_type: application/octet-stream` whatever role
the manifest that names it assigns it, and the role lives in the
manifest's descriptor rather than on the blob's own row — so no
classification of the row can tell them apart. `OciBlob` states that
honestly and the materialiser decides by container: a tar (plain or gzip)
is a layer; anything else (the config JSON) has no package surface.

### The composed image is the scan unit

A layer scanned on its own is **evidence**, not a verdict. Measured on a
real multi-layer image: the base layer carried `/etc/os-release` and
produced 240 findings, while the next layer carried a *complete package
database with 25 more packages* and produced **zero** — without an OS
marker in those same bytes the scanner recognises no operating system and
never runs the package check. Twenty-five packages carrying 92 advisories
went unassessed, and the only reason that image was rejected at all was an
accident of provenance. [ADR
0064](../../adr/0064-a-filesystem-finding-is-about-the-composed-filesystem.md)
is that measurement's conclusion: **the unit of filesystem assessment for
an OCI image is the image manifest.**

So an `OciManifest` row now gets a second, separate assessment — of the
composition its bytes name:

1. **The application layer resolves what to scan — in the order a proxy
   can actually do it.** `hort_app::use_cases::composite_scan` reads the
   manifest document out of CAS and parses *it alone*
   (`hort_domain::oci::strict_manifest_nomination`): index-ness, the
   config descriptor, and every layer descriptor with its container. That
   is the **strict** parse, which accounts for every declared descriptor
   rather than skipping one it cannot resolve — a skipped layer would be a
   strict subset of the image that the scanner analyses and reports *as*
   the image: a clean verdict about the wrong subject. The constituent set
   and its order come from the manifest bytes, never from the
   `content_references` edges — the edges nominate, the bytes decide, and
   only the bytes carry the order.

   The config blob the manifest names is then **acquired before it is
   read** (step 2), because a composition's own description is a
   constituent too: on a pull-through manifest the config is as absent as
   the layers are. Only once its bytes are present does
   `ManifestNomination::complete_with_config` decide whether they describe
   a runnable image at all. There is deliberately no form of the parse that
   takes both documents at once: a caller holding one would reach for
   config bytes before anything had established they exist, which is the
   shape that made a cold proxy manifest unresolvable.
2. **The constituents are made present, fetching them on a proxy — the
   config first.** `hort_app::use_cases::constituent_acquisition` surveys
   each constituent in CAS and, for whatever is absent, fetches it from the
   repository's configured upstream through the same verified blob fetch a
   client pull uses — every fetch is digest-verified against what the
   manifest declared (ADR 0006), and a mismatch refuses the composition.
   This is for **proxy repositories only**: a hosted push already required
   every constituent to resolve before the manifest committed, so there is
   nothing to fetch, and a hosted repository's absent constituent is a real
   refusal. On a proxy the absence is the ordinary case — those edges are
   registered by digest with no existence check, deliberately — and waiting
   is not available, because the client pull that would warm the
   constituents *begins with the manifest whose verdict is being gated*. So
   hort fetches blobs no client has asked for.

   It runs in **two phases, the config and then the layers**, and the
   ordering is load-bearing rather than cosmetic: an *artifact* manifest —
   a cosign signature, an SBOM attachment, a Helm chart — is a large,
   legitimate population on a proxy, and its config says "no layered root
   filesystem". Acquiring the whole nominated set up front would fetch
   every one of their layers before learning there is nothing to compose —
   egress spent on bytes hort will never assess, which is the outcome
   "edges nominate and the bytes decide" exists to avoid.

   A blob already in CAS is never fetched again, which is also what makes a
   partly-done acquisition survive a retry: the completion criterion is
   "the bytes are in CAS", and CAS is the registry's own store, claimed
   against the GC by the manifest's own `oci_config` / `oci_layer` edges. No
   job state, no checkpoint, nothing to reconcile. An operator sees this as
   upstream egress and CAS growth a request did not ask for, attributed on
   `hort_upstream_fetch_*` under its own `format` label.
3. **The adapter materialises it as an OCI image layout.**
   `crates/hort-adapters-scanner-trivy/src/oci_layout.rs` writes
   `oci-layout`, `index.json` and `blobs/sha256/<digest>` for the
   manifest, the config and every layer, then runs
   `trivy image --input <dir>`. The blobs are copied **verbatim** —
   nothing here decompresses a layer, and it cannot: the layout path *is*
   the digest of those bytes, so decompressing on the way in would write a
   file whose name no longer described its contents. The scanner
   decompresses, and it composes `tar`, `tar+gzip` and `tar+zstd`
   identically (measured against the pinned Trivy 0.70.0).
4. **Completeness is a precondition of a verdict.** A constituent that is
   missing, unreadable, of a container the composition cannot be described
   with, or over the whole-image budget yields **no verdict** — never a
   partial layout, never a clean verdict over a subset. A refused assembly
   removes the directory it was building and reports
   `incomplete_composition`, which is deliberately *not* the same value as
   an assembled composition that reported nothing (`no_analyzer_matched`):
   "I could not build the image" and "I built it and it reported nothing"
   are facts about different things.

   **No verdict is not the same as no further attempt.** A refusal about the
   *image* — more constituents or more bytes than hort will assemble, a
   digest the upstream does not have, bytes that failed verification, a
   constituent absent with no upstream to acquire it from, a manifest
   document that is not in CAS at all — is deterministic and is never
   retried: re-running reads the same facts. A refusal about *availability*
   — an unreachable, timed-out, rate-limited or 5xx upstream, a storage
   backend that did not answer either a presence probe or one of the two
   document reads, a composition phase that exceeded its wall clock — is
   routed
   through the path the scan job already has for a retryable backend
   failure, bounded by that job's own attempt budget.
   Exhausting the budget lands back on the deterministic outcome: still no
   verdict, and now also no more tries. The classification is read off the
   upstream port's own error vocabulary and off the typed storage error,
   never off a rendered message.
5. **An empty report over a composition is a hold, not "not applicable".**
   The `rootfs` rule below exists because a *layer's* package surface
   belongs to the composition it is part of. A composition has no such
   excuse: it is the thing that was supposed to be assessed.

**The whole-image budget** is the image's, not each blob's — a
composition reads N blobs, and 1024 descriptors is a manifest the strict
parse calls well-formed, so a per-blob bound reused here would multiply by
the layer count. Three compile-time bounds, held in **one** place
(`hort_domain::oci::ImageBudget`) and read by **both** phases: 8 GiB across
every constituent (which for the layout *is* the scratch-disk footprint,
since nothing is staged or unpacked beside it), 256 constituents, and 300 s
of wall-clock per bounded **span** — that last one because the scanner's own
`--timeout` only starts once the layout exists, so without it a stalled
storage stream or upstream response could hold a worker slot indefinitely.
A composite scan has exactly two of those spans: the **composition phase**
and the layout write. A span is not a step: the composition phase's
manifest-document read, config phase, config-document read and layer phase
share **one** deadline between them, because what the bound protects is the
worker slot and the slot does not care how the work was divided. The two
document reads are inside it for a reason of their own — the read ceiling
bounds a document's *bytes*, so a store trickling a kilobyte-scale manifest
would otherwise hold a slot with no deadline at all.

Acquiring a blob and writing it into a layout are different mechanisms in
different crates, but they are bounded by the same quantities, and a second
copy of those numbers could disagree with a direction: a byte ceiling on the
fetch above the layout's would pull bytes over the network that the layout
is then guaranteed to refuse. So neither phase states them for itself.
Acquisition additionally charges the bytes *already* local, for the same
reason — the budget bounds what the composition costs, not what one phase
of it did. On top of them sits a per-constituent attempt bound of two, so a
flapping upstream cannot spend a whole acquisition on one layer; the scan
job's own attempt budget, not that two, is where an unavailable upstream is
waited out. The per-blob limits are unchanged and still govern the per-blob
path.

**Its release authority is an operator's to grant.** Every composite
assessment is produced, mapped, logged, counted
(`hort_scan_composite_assessment_total`, `hort_scan_composite_comparison_total`)
and recorded as a row in the `composite_scan_observations` projection
beside the primary axis's own gate decision over the same run. What
happens next is the resolved policy's `compositeVerdictMode`
(ADR 0064 D6):

- **`observed`** — the default, and the posture every policy that
  predates the field is in. The assessment transitions no artifact,
  writes no `ScanCompleted` and never reaches the release predicate; the
  manifest row's outcome is byte-for-byte what it would be with no
  composite path at all.
- **`promoted`** — the composition's findings **are** the manifest row's
  findings. They join the run's accumulator and reach the release
  predicate exactly as a second backend's findings over the manifest's
  own bytes would, under the policy's own `enforcement`; and a
  composition that could **not** be produced joins the run's
  abstentions as `incomplete_composition`, so the absent verdict holds
  the manifest `scan_indeterminate` fail-closed. "Nothing to compose" —
  an image index, or an artifact manifest whose config declares no
  layered root filesystem — stays non-gating under promotion: those are
  legitimate populations, not unassessed images.

**Promotion is also what moves the obligation off a constituent**
(ADR 0064 D2, ordered after the tightening by D6). Under `promoted`, an
OCI blob's own filesystem findings stop deciding its verdict and
`unsupported_container` stops holding it — the composition that binds it
is the unit of filesystem assessment, and a package an upper layer
deletes must not condemn the lower one. The findings stay in the record:
the findings blob, the `scan_findings` rows and
`ScanCompleted.severity_summary` are exactly what they were, and what
changes is only the aggregate the thresholds are walked against. A
statement about the layer's **bytes** — a leaked credential, a malware
signature — keeps gating it under every posture; no backend hort ships
produces one today, and the line is drawn now precisely so that the
first one that does is not disarmed by a decision taken before it
existed.

Two consequences worth stating. A constituent with no composition above
it — no parent manifest at all, or a parent that is an *artifact*
manifest rather than a runnable image — also stops gating on its
filesystem findings under promotion, with nothing taking the obligation
over; the exposure is to a client that addresses the blob by digest and
composes it outside hort, which is ADR 0064's accepted residual. And an
already-`Rejected` constituent is **not** un-rejected by the automatic
loosening pass, which pins `composite_verdict_mode: observed` when it
re-derives a verdict for exactly that reason. Recovering that estate is
the operator's, through the curation re-evaluation, which passes the
policy's resolved posture instead.

**What a finding carries, and what is derived from it.** The side of
D2's line a finding is on is the *producer's* fact — it read a report
section, and nothing downstream can recover which — so it persists on
the finding (`bytes` / `filesystem`, or absent where no producer stated
one). *Whose* filesystem a `filesystem` claim is about is not stored: it
is the row's own `ArtifactKind`, derivable at any time, and the release
predicate composes the two where it decides. So a verdict re-taken over
an artifact's stored findings reads the same fact the fresh scan read,
which is what makes the three paths agree:

| path | posture | why |
|---|---|---|
| fresh scan | resolved from the policy | the assessment the operator promoted |
| **tighten** (operator lowers a threshold) | resolved from the policy | or the first threshold change after a promotion would terminally re-reject every constituent the promotion had just released |
| **automatic loosen** (exclusion added, threshold raised) | pinned `observed` | ADR 0064 D6: promotion must not un-reject the existing estate by itself |
| operator's curation re-evaluation | resolved from the policy | the sanctioned, explicitly-requested recovery D6 points at |

The only asymmetry is the pinned row, and it is a property of the
*driver* rather than of the rule: all four put the identical predicate to
the identical finding list.

Promotion flows through the path the manifest's verdict already takes,
never through a release path that reads
`composite_scan_observations`. That table is the measurement surface,
and a structural guard
(`crates/hort-app/tests/shadow_observation_has_no_authority.rs`) is what
keeps it one — "no release path reads this" is asserted rather than
reviewed, promoted or not. The observation keeps being written either
way; once promoted, its `composite_findings_decision` stops being a
counterfactual and becomes a record of what also happened, which is how
an operator confirms the promotion is behaving as the measurement
predicted.

Why an operator and not a release: `Rejected` is terminal and the
periodic rescan never revisits it, so a new analysis path whose first
production act could be irreversible would leave an estate only an
explicit operator re-evaluation could recover. The named criteria are
baseline completion and coverage, error and indeterminate rates,
incremental findings and the images they affect, false-positive review,
and capacity. Promotion is **per policy** so one repository can be
promoted and watched first, and it drives **no** re-evaluation of the
already-assessed population in either direction — that pass re-derives
from stored findings, and demoting that way would un-reject what a
promoted composite had correctly rejected with nothing fresh having
looked at it.

### The Java vulnerability database

Trivy identifies a Java archive from the coordinates *inside* it — the
`META-INF/maven/**/pom.properties` written by the Maven build, or the
`MANIFEST.MF` attributes as a weaker fallback. When neither identifies
the archive, it falls back to matching the JAR's SHA-1 against
`trivy-java-db`, a **separate** database from the vulnerability DB that
it downloads on demand the first time it meets such a JAR.

The operational consequence is that the worker's Trivy cache directory
must be **writable**, not merely present: an artifact whose JAR carries
no usable identity turns a read-only cache into a scan failure rather
than a missing finding. That directory is
`HORT_SCANNER_TRIVY_DB_DIR` → Trivy's `--cache-dir`; when it is unset
Trivy uses its own default and the same requirement applies there. There
is no knob for the Java DB itself — it is Trivy's own fetch, on Trivy's
own schedule, and an air-gapped deployment warms the cache the same way
it warms the vulnerability DB.

### Empty-report diagnostics

When Trivy returns a report with no analysed target, the adapter's
`warn!` carries the artifact kind, the format, the subcommand it chose,
the **tail of Trivy's stderr** (last ~1 KiB, which under `--quiet` is
where DB and analyzer complaints still land) and **`materialised`** — up
to 20 relative file names from the workspace. Those last two are what
separate "no analyzer claimed this, correctly" from "this adapter built
the wrong tree", which are otherwise the same log line.

### The scanner capability map

Whether a backend can produce a verdict for a repository format is a
**compiled-in fact of this build**, not an operator choice. The backends
own it (`ScannerPort::applies_to`); `hort_app::scanning` mirrors it for
the apply path, which constructs no adapters; and the `hort-worker`
parity guard asserts the two never disagree.

| backend | `oci` | `maven` | `pypi` | `npm` | `cargo` | any other format |
|---|---|---|---|---|---|---|
| `trivy` | **yes** | **yes** | **yes** | **yes** | **yes** | no |
| `osv` | no | **yes** | **yes** | **yes** | **yes** | no |

**A cell is "yes" only where a test exists in which a known-vulnerable
fixture of that format yields at least one finding through that
backend.** Materialising bytes a scanner never claims is not evidence —
it produces the *absence* of a verdict, which is precisely the inert
pairing this map exists to name.

What each "yes" actually covers, and what proves it:

| cell | what is covered | evidence |
|---|---|---|
| `trivy` × `oci` | the layer's OS package database (`var/lib/dpkg/status`, `lib/apk/db/installed`, `var/lib/rpm/*`) and any lockfiles it ships | `an_oci_layer_with_an_os_package_database_yields_findings` (layer tar carrying `zlib1g 1:1.2.11.dfsg-2`); the compose e2e `oci-trivy-e2e` scenario |
| `trivy` × `maven` | a JAR's embedded coordinates, matched against `trivy-java-db` (SHA-1 fallback when the archive carries no usable identity); a `pom.xml`'s declared dependencies as far as their versions are literal | `a_known_vulnerable_jar_yields_its_cve` (`log4j-core 2.14.1`), `a_pom_is_analysed_rather_than_ignored`; the compose e2e `maven-trivy-e2e` scenario |
| `trivy` × `pypi` | the wheel's / sdist's own identity from `*.dist-info/METADATA` or `PKG-INFO` | `a_known_vulnerable_wheel_yields_at_least_one_finding` (`urllib3 1.26.4`) |
| `trivy` × `npm` | **the package's own `name@version` only.** A published tarball declares dependency *ranges*, never a resolved set, so nothing else in it is attributable | `a_known_vulnerable_npm_tarball_yields_its_own_advisory` (`lodash 4.17.20` → 5 advisories); `an_npm_tarball_is_analysed_with_nothing_to_attribute` pins the ceiling |
| `trivy` × `cargo` | **a shipped `Cargo.lock` only** — i.e. published *binary* crates. A library crate (`Cargo.toml` alone, the common case on crates.io) still yields nothing attributable under Trivy; `osv` × `cargo` is the cell that covers it | `a_binary_crate_with_a_lockfile_yields_a_dependency_advisory` (`smallvec 1.6.0`); `a_cargo_crate_is_analysed_with_nothing_to_attribute` pins the ceiling |
| `osv` × `npm` / `pypi` / `cargo` / `maven` | the payload SBOM the format handler extracts, subject **and** components ([ADR 0056](../../adr/0056-payload-sbom-extraction.md)) — which is what covers a library crate's declared dependency set where Trivy cannot | `a_known_vulnerable_{npm,pypi,cargo,maven}_sbom_yields_a_finding`; the compose e2e `maven-osv-e2e` scenario; the dogfood `hort-crates` / `npm-proxy` policies in production |
| `osv` × `oci` | — **no cell.** OCI exposes no SBOM source, so this backend has nothing to read. The parity guard asserts the OCI handler is not SBOM-capable, so the "no" cannot rot into a "yes" by accident | `oci_is_covered_by_trivy_alone_and_the_handler_confirms_it_has_no_sbom` |

Both new Trivy cells (`npm`, `cargo`) were proven against **Trivy
0.70.0**, the version `docker/Dockerfile.worker` pins, and neither rests
on a contractual upstream guarantee: `npm` rests on the Node analyzer
claiming a `package.json` under `node_modules/`, `cargo` on the Cargo
analyzer reading `Cargo.lock`. A Trivy release that *widens* attribution
turns the paired "nothing to attribute" tests red — which is the designed
signal to revisit this table, not a defect.

The map is deliberately **binary**. What a "yes" covers varies (the
column above), but a third "partial" state would attach a caveat to
nearly every non-OCI cell, which is noise rather than signal. The nuance
belongs here, in prose, not in the type.

**Two consumers, one record.**

- **At apply time**, the `StaticConfigValidator`'s row 7c rejects a
  `ScanPolicy.scanBackends` entry paired with a repository format it
  cannot analyse, naming the pairing and the backends that *do* cover
  the format. A format no backend covers is the other rejection shape,
  and points at the explicit waiver instead. The unit of evaluation is
  the **effective** pairing: runtime resolution is repo-scoped-wins-over-
  global, so a global policy is linted only against the repositories
  that declare no policy of their own. `hort-server validate-config`
  catches both offline. The one thing the row never rejects is
  `scanBackends: []` — that is the operator's explicit "this repository
  is not scanned", a decision rather than an inert pairing.
- **At scan time**, the orchestrator consults the same map before
  invoking a backend, which covers the paths apply-time rejection cannot
  reach: the built-in default backend list (no policy declared at all)
  and a policy that predates the row. A backend that does not apply is
  never invoked; the abstention it records instead is
  `no_analyzer_matched` when another backend covers the format (the
  pairing is wrong, so the surface stays unassessed and the artifact
  holds — see [*"Nothing analysable" is not "clean"*](#nothing-analysable-is-not-clean)),
  ticking `hort_scan_record_outcome_failures_total{result="inert_pairing"}`,
  and `not_applicable` when nobody covers it (there is no surface to
  assess, so a hold would have nothing to wait on).

The operator consequence of the `osv` × `oci` "no" is concrete: a
**global** `scanBackends: [trivy, osv]` over a deployment that also
serves OCI repositories is rejected at apply. The fix is to split it —
a global `[trivy]` plus per-repository policies adding `osv` where the
format has an SBOM — which is exactly what
`scripts/alpha-fixtures/gitops-config/base/policies/` models.

### Extraction is bounded and fail-closed

Extraction is the one place in the workspace that writes
attacker-supplied archive entries to a filesystem path, so every guard
lives in one module (`crates/hort-adapters-scanner-trivy/src/extract.rs`)
and every guard refuses the **whole archive** rather than skipping an
entry: extracted-bytes cap, decompression-ratio cap, entry-count cap, and
lexical path containment on the entry's own **name** (relative, no `..`,
checked before any filesystem call) — the one property that decides
whether extraction ever writes outside the root. Files and directories
land with permissions stripped to a fixed mode.

A symlink or hardlink entry is **never materialised**, so its **target**
is never validated and never a reason to refuse: a link carries no bytes
of its own, and since it is never created, an absolute or escaping target
cannot write, read or expose anything either. It is skipped and counted
instead (`skipped_links`, surfaced in the adapter's logs), because an
absolute target is the ordinary shape of a root filesystem
(`/bin/sh -> /bin/busybox`), not an attack — treating it as one refuses
every real OS layer.

A tripped guard yields `NothingAnalysable(UnusableArchive)`, never a
partially-extracted tree. A half-unpacked archive scanned as if it were
whole is a false-clean, which is worse than a refusal. A payload the
extractor never opened at all — a container it has no decoder for —
yields `UnsupportedContainer` instead; both refuse, and the next section
is why they are two values.

These caps are **not** an operator surface: they are safety bounds on
untrusted input, and an operator able to raise them could re-open the
bomb surface they close.

## "Nothing analysable" is not "clean"

An empty finding list is only a clean verdict **when something was
actually analysed.** `ScanAnalysis` exists to keep those apart, because
while the port returned a bare `Vec<Finding>` they were the same value —
and every Trivy scan of every format produced the second while being
recorded as the first.

A backend returns `NothingAnalysable(reason)` in five situations:

- `not_applicable` — the kind carries no package surface (an OCI manifest
  or image config, a payload no handler claims). No scanner is invoked and
  no CAS read is paid. The same reason also covers a Trivy `rootfs`-mode
  invocation that *was* run and came back with no `Results` section — a
  layer's package surface belongs to the composition it is part of (ADR
  0064, amending ADR 0007), so an empty result over one layer is not an
  unassessed pairing. Without that mapping a layer would never reach a
  release authority of its own.
- `unusable_archive` — the payload is an archive the adapter refused to
  materialise for a reason **about its own bytes**: a guard above
  tripped, an entry tried to escape the workspace, an entry name could
  not be decoded well enough to put to the containment rule, or the
  archive could not be read at all.
- `unsupported_container` — the payload is a container the adapter has
  **no decoder for**, identified positively from its leading bytes
  (`zstd`, `xz`, `bzip2`) rather than inferred from a failed read. The
  bytes inside were never reached, so this says nothing about them: it
  is a fact about hort's decoder inventory, and the same `tar+zstd`
  layer that is refused here is composed without difficulty by the
  scanner in `image` mode. ADR 0064 D2 places the statement with the
  composition for exactly that reason, so on an OCI blob under a policy
  that has **promoted** the composite verdict it no longer gates: the
  composition that binds the layer is assessed as one unit and carries
  its filesystem verdict. Under `observed` — the default — and on every
  other artifact kind it gates exactly as before. "The archive could not
  be read" stays on
  `unusable_archive` deliberately: the readers behind it cannot tell a
  container they have no decoder for from a corrupt archive of one they
  do decode, and an undecidable case goes to the gating side.
- `no_analyzer_matched` — the backend ran against a materialised tree and
  reported no analysed target at all (for Trivy, a report with no
  `Results` section — absent, `null`, or empty). In `fs` mode that targets
  one artifact whose analyzer either engages or does not, so an empty
  result stays an expected surface left unassessed. In `image` mode it is
  an assembled composition that reported nothing, which cannot be "no
  package surface by construction" — the composition *is* the thing that
  was supposed to be assessed.
- `incomplete_composition` — a composed image could not be assembled: a
  constituent was missing from storage, unreadable, the repository has no
  upstream to acquire it from, or the composition tripped the whole-image
  budget. No report about the image exists. Kept apart from
  `no_analyzer_matched` on purpose, and that distinction is carried
  through to what a promoted manifest inherits: an assembled composition
  that every backend abstained on reports `no_analyzer_matched`, because
  none of this value's causes is true of it. See [the composed
  image](#the-composed-image-is-the-scan-unit).

The orchestrator records `no_analyzer_matched` and `not_applicable` on a
backend's behalf in one case: when
[the scanner capability map](#the-scanner-capability-map) already says
this backend cannot analyse this format. The backend is
then never invoked at all — the answer is known, and paying a CAS read
and a subprocess for it would also lose the one fact an operator needs,
that the *pairing* is wrong. Another backend covers the format ⇒
`no_analyzer_matched` (plus `result="inert_pairing"`, which distinguishes
"never invoked" from "ran and found nothing"); nobody covers it ⇒
`not_applicable`.

The reasons do **not** all gate the artifact, and
`NotAnalysable::gates_release` is the single place that split is decided
— read it rather than an enumeration here, which is what goes stale when
a reason is added or split. It takes the artifact's kind and the resolved
`compositeVerdictMode` as well as the reason, because two of the three
answers are about the artifact rather than only about the refusal:

- `not_applicable` never gates, anywhere. It is the absence of a surface:
  no scanner could ever find a threat level in an OCI manifest row or an
  image config blob, so a hold has nothing to wait on and would never
  lift.
- `unsupported_container` does not gate an **OCI blob** under a
  **promoted** policy, and gates everywhere else. The surface is real and
  the composition that binds the layer assesses it (ADR 0064 D2).
- everything else always gates: an expected surface went unassessed,
  which is the absent verdict ADR 0007 holds on.

The orchestrator treats an abstention as **no contribution**. If any other
backend produced a verdict, that verdict stands and the abstention is a
`warn!` naming format × backend plus
`hort_scan_record_outcome_failures_total{result="nothing_analysable"}` —
the actionable fact is the *pairing*, because "this backend cannot
adjudicate this format" is a policy mismatch an operator fixes in policy.
(A `not_applicable` abstention asks nothing of anyone, so it logs at
`debug!` and emits no failure counter: it is the expected steady state for
every OCI push, and warning once per blob would bury the actionable half.)
If no backend produced a verdict:

- **Any backend errored** → the existing retryable `Failed` path. An error
  may be transient.
- **Every backend abstained, at least one of them gating** → the artifact
  transitions straight to the terminal `scan_indeterminate` status, with
  no retry budget spent. The artifact's kind and the backend's analyzers
  are both fixed, so the next attempt reaches the same answer; retrying
  would only delay the hold by the backoff schedule.
- **Every abstention was `not_applicable`** → a **completed assessment
  with nothing to assess.** The orchestrator records a `ScanCompleted`
  with no findings and `assessment = not_applicable`, so scan authority
  exists and the release gate opens on the time gate alone, and ticks
  `hort_scan_terminal_total{result="not_applicable"}`. This is what makes
  a Trivy-policed OCI repository work at all: an image's manifest row and
  config blob carry no package content, its layers do, and only the layers
  get an analysed verdict.

That hold is the same fail-closed state an absent verdict already
receives ([ADR 0007](../../adr/0007-fail-closed-quarantine-release-predicate.md)),
and it is deliberately *not* a zero-finding `ScanCompleted`: recording one
would hand release authority to a scan that never looked at the bytes. The
not-applicable arm is not an exception to that — it records a
`ScanCompleted` whose `assessment` field says, in the trail itself, that
nothing was examined, which is why it can never be read as "analysed,
clean". Events written before that field existed deserialise as
`analysed`, which is what they were. One guard rail on the arm: if
advisory enrichment produced a finding while every backend abstained,
something *did* have an opinion about this artifact, so the fail-closed
hold applies instead — "nothing to assess" would be a false statement and
would drop a real finding.

One consequence worth knowing when reading the database: an abstained
artifact's `artifacts.last_scan_at` is **not** advanced. The transition
goes through `commit_transition_with_score`, which writes the status and
the `ScanIndeterminate` event but not the scan timestamp — the same is
already true of the retry-exhausted path above. So "`last_scan_at` is
still NULL and `quarantine_status = 'scan_indeterminate'`" reads as *no
scan ever produced a verdict for this artifact*, which is exactly the
fact the hold rests on. A not-applicable artifact is the other way round:
it took the `record_scan_result` path, so `last_scan_at` **is** set and
the row reads as a completed scan — the `ScanCompleted.assessment` field
is what says which kind.

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
