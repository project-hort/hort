# 426 — An empty report over a complete layout is a fact, not an absence

**Issue:** #440 · **Branch:** `agent/440-an-empty-report-over-a-complete-layout-is-a-fact` ·
the only item. **No ADR change** — ADR 0007's fail-closed rule is not being
weakened; the case it protects does not reach the line being changed. No
migration.

**Governing decisions:** ADR 0007 (fail-closed when a surface went
unassessed — the rule this item keeps intact by narrowing what counts as
unassessed) · #428 (the composite verdict is the only authority, which is what
made this path release-relevant) · #427 (the abstention no longer logs as a
job failure; this item is the classification half).

**Release coupling.** This ships with #428 in the same release. #428 makes the
composite's abstention release-relevant; this item is the case where that
abstention is misclassified. Apart, the release carries a fail-closed on
correct artifacts *and* a migration step (`hort-cli admin task invoke
cron-rescan-tick`) that cannot be run on an instance holding from-scratch
images.

## Group A — the empty `ScanMode::Image` report

`report.results.is_empty()` on the `Image` arm returns
`NothingAnalysable(NoAnalyzerMatched)`
(`crates/hort-adapters-scanner-trivy/src/lib.rs:624-638`), and
`NotAnalysable::gates_release` maps `NoAnalyzerMatched` on a non-constituent
kind to `true` (`crates/hort-domain/src/ports/scanner.rs:572-578`), so a
manifest is held `scan_indeterminate`.

The arm's stated reason is that two facts are indistinguishable there —
"either the image genuinely holds no package surface anywhere … or the scanner
did not read what hort assembled". **The second is not reachable at that
line**, and that is the whole of this change's justification:

- `write_image_layout` returns `Ok(LayoutStats)` only when every declared
  constituent — manifest, config and each layer — was read from CAS and
  written into the layout. Every failure is a `LayoutRefusal` variant on the
  `Err` channel (`ConstituentUnreadable`, `TooManyConstituents`, `ByteBudget`,
  `TimeBudget`, `Unwritable` — `oci_layout.rs:140-220`); none of them yields
  `Ok` with a partial layout.
- The caller splits those: `refusal.is_transient()` → `Err`, which the
  orchestrator reschedules under the job's attempt budget; otherwise
  `Materialised::Nothing(NotAnalysable::IncompleteComposition)`
  (`workspace.rs:847`), which gates unconditionally and is a different
  outcome with a different name.
- So reaching the empty-report branch in `ScanMode::Image` already means the
  layout was complete. The `Rootfs` arm checks the same property explicitly
  (`ws.skipped_links() == 0`) because on that path a partial tree *is*
  returnable; on the image path the workspace sets `skipped_links: 0` with the
  comment "Nothing is unpacked on this path".

**What to build:** the empty `Image` report reads as
`NothingAnalysable(NotAnalysable::NotApplicable)`, with the reasoning the
`Rootfs` arm already states — the analyzers agreeing there is no package
surface is a completed fact about the artifact, not an unassessed one — and
with the upstream guarantee named at the site, because that guarantee is what
the reading rests on.

**The invariant this depends on has to be pinned, not assumed.** A future
change that made a partial layout returnable as `Ok` would silently re-open
the hole this arm was protecting. So the unit pins the three upstream
outcomes: an absent constituent lands `IncompleteComposition` (and still
gates), a transient read failure lands `Err` (and still reschedules), and a
complete layout is the only input the new arm can see. A comment alone does
not hold that; a test does.

Log level follows the classification: the `Rootfs` narrowing moved its
listing to `debug!` and emits one `info!` stating the fact. The `Image` arm's
`warn!` exists because the outcome was a hold; once it is not, the same shape
applies — the `materialised` listing stays available for an operator who
doubts the fact.

## Group B — WITHDRAWN: the premise does not hold

**This group was specified and then withdrawn, measured rather than argued.**
It asked the constituent scan path to consult
`layer_media_type_is_non_filesystem_payload` before materialising a blob as an
archive, so a cosign signature blob would be `NotApplicable` instead of
`UnusableArchive`. Three findings retire it:

1. **Such a blob is already `NotApplicable`, from its own bytes.** Every member
   of that media-type set is by its own specification a JSON document, and
   `sniff_container` identifies a JSON document **positively** —
   `Container::NoPackageSurface("json")` → `Ok(None)` →
   `Materialised::Nothing(NotApplicable)`, which does not gate. Such bytes are
   never handed to the extractor as an archive and never reach
   `UnusableArchive`, with or without a manifest.
2. **Where a declaration is readable, the resolver already answers it.**
   A nomination refusal maps to `Declaration::NotAnImageLayer` →
   `LayerRole::NotAnImageLayer` → `Plan::NotAnImageLayer` → `NotApplicable`,
   with no CAS read at all.
3. **In the residual case there is no media type to ask about.** A blob reaches
   `Plan::OciBlob` only under `LayerRole::Unknown`, and there hort holds no
   declared layer media type: the artifact row's `content_type` is the literal
   `application/octet-stream` at every OCI blob mint site, the `oci_layer`
   edge's `metadata.media_type` is the *manifest's* type rather than the
   layer's, and `ArtifactCoords::metadata` is `Null` for OCI.

So the change is a no-op wherever its premise is satisfiable, and in the
residue it is **permissive**: the only outcome it could move is a blob whose
declared type says "document" while its bytes are not one — push a runnable
`tar+gzip` layer, declare it `application/spdx+json`, and its own scan is
waved through on the declaration alone. That is the direction the predicate's
own doc refuses ("an entry added in error takes a runnable image out of the
gate, and the mistake is invisible") and the hazard
`refuse_misdeclared_signature_layers` exists to close.

**What survives from it, and is in this unit:** two guards that pin the
findings rather than change behaviour — a blob-level test driving realistic
payloads of all five media types through `materialise` and asserting
`NotApplicable` + non-gating, and the layer-role test extended from the
in-toto case to all five, so the set and the resolver cannot disagree
silently.

**The staging rows that motivated the group are therefore unexplained and
need a measurement, not a change.** `UnusableArchive` on an `OciBlob` is
reachable only through the extraction refusals, and the two candidate
mechanisms differ in whether anything is wrong: a JSON document behind a
byte-order mark (which `sniff_container` leaves `Unidentified` deliberately —
the cheap and *safe* fix there is widening the positive identification, a
byte-level narrowing) versus a real image layer tripping an extraction bound
or a pre-POSIX tar, where `UnusableArchive` is the correct answer. Each row's
own `warn!` carries `reason` and `abstention`, so the distinction is a
minutes-long read of the held set.

## Measurements this item is derived from

Staging, `0.17.4-beta.6`, window 2026-11-14 17:00:15Z–17:21:24Z with the tick
active every five minutes:

| rows | kind | backend verdicts |
|---|---|---|
| 170 | `oci_manifest` | `trivy=not_applicable, composite=no_analyzer_matched` |
| 30 | `oci_manifest` | `trivy=not_applicable, composite=incomplete_composition` |
| 120 | `oci_blob` | `trivy=unusable_archive` |

34 distinct manifests, each re-presented 9 times in 21 minutes: the outcome is
deterministic, so each tick repeats a CAS read, a materialisation and a trivy
subprocess for the same artifact. The hold does not land because
`Artifact::fail_scan_indeterminate` refuses a `Released` source state, which
is why nothing ever leaves the population.

Local reproduction with the adapter's own argv (trivy 0.70.0,
`trivy image --format json --quiet --input <OCI layout>`) — the positive
controls are the point, because they show the invocation is sound:

| reference | blobs | exit | result |
|---|---|---|---|
| `postgres:15-alpine` | 13 | 0 | `Results=2`, 62 vulns |
| `gcr.io/distroless/cc-debian13:nonroot` | 23 | 0 | `Results=1`, 53 vulns |
| `gcr.io/distroless/static-debian13:nonroot` | 15 | 0 | `Results=1`, 0 vulns |
| `registry.k8s.io/pause:3.10` | 3 | 0 | **`Results=null`, `OS=null`, empty stderr** |

## Acceptance

- A from-scratch image with no package surface and a complete layout is
  released rather than held: `NotApplicable`, `gates_release == false`. A test
  drives the adapter over a layout whose trivy report has no `Results`.
- The three upstream outcomes are pinned: absent constituent →
  `IncompleteComposition` and gating; transient read failure → `Err`;
  complete layout → the new arm. The first two must fail if the completeness
  guarantee is ever weakened.
- A cosign signature blob on the constituent path is `NotApplicable`, not
  `UnusableArchive` — satisfied already, and now pinned from the **bytes**
  rather than from the declaration. The predicate keeps **one** caller and one
  definition; a second caller is withdrawn with Group B.
- The change adds no uncovered lines (intersect the diff's added line numbers
  with `cargo llvm-cov --show-missing-lines`, per touched file).
- Gate green. No ticket, MR or backlog numbers in any code comment.

## Out of scope

- No change to `gates_release`'s mapping. Both groups change what outcome is
  *produced*, never what an outcome means — the table stays as it is.
- No change to #428's direction: the composite remains the only authority.
- No rescan-amplification change. `fail_scan_indeterminate` continues to
  refuse a `Released` source state; this item removes the reason the
  population exists rather than widening the retroactive path.
- The tick's re-presentation of a deterministic outcome is a selector
  question, not this item's. With both groups landed the population is empty,
  which is the cheaper fix; if it recurs for another reason, that is its own
  unit.
