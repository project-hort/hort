# 413 — The enqueue asks whether this artifact is the document

**Issue:** #421 · **Branch:** `agent/421-the-enqueue-asks-what-carries-deps` ·
the only item. **No ADR change.**

**Governing decisions:** ADR 0008 (per-format knowledge lives in
`hort-formats`, not in `hort-app`), ADR 0005 (format handlers are
compiled-in `FormatHandler` structs), ADR 0026 (the metadata methods'
streaming contract), ADR 0028 (the cascade root takes no DB-side
idempotency key). No new decision: this adds a predicate the port's own
contract already implies.

## The property

**A job is enqueued only when there is something for it to read.**

`IngestUseCase::enqueue_prefetch_cascade`
(`crates/hort-app/src/use_cases/ingest_use_case.rs:3789`) gates on exactly
two conditions and then enqueues:

```rust
if suppress_cascade_seed || !prefetch_transitive_deps_triggered {
    return;
}
```

There is **no predicate on the artifact's path, its media type, or on
whether the format's extractor can read this document at all.** So every
Maven ingest gets a root `prefetch-dependencies` job — `.jar`, `.pom`,
sources jars, `.asc`, `maven-metadata.xml`, whatever arrived — and the JAR
ones are guaranteed to fail: the Maven extractor is handed a ZIP and reports
its header as the XML root element.

Measured on the reporting instance over the whole of its history, with the
reporter's controls: **3 of 3 `.jar` ingests failed, 8 of 8 `.pom` ingests
completed, no mixed case in either direction.** The positive control is
`cargo`: **460 of 460** `.crate` ingests succeeded, because for cargo the
archive *is* the document. So the defect is not "archives break the
extractor" — it is that nobody asks whether this artifact is the document.

## The extractor is right, which is why the fix is not there

`crates/hort-formats/src/maven/mod.rs:746`'s own contract says so: `Err`
means the bytes are not a POM. Making it tolerate a JAR — `Ok(vec![])` on
unparseable input — would destroy the signal that made this diagnosable: a
genuinely corrupt POM would become indistinguishable from a file that was
never a POM.

The port says the same thing one level up
(`crates/hort-domain/src/ports/format_handler.rs:376-381`): *"well-formed
but unresolvable is `Ok`, not `Err`"* — a document the handler parses but
cannot fully interpret is valid input. A JAR is not that. It is not input at
all.

## What to build

**A `VersionDiscovery` predicate — "does an artifact at this path carry
dependency specs for this format?" — consulted before the enqueue.**

That placement is the point, not a detail:

- it keeps per-format knowledge in `hort-formats` where ADR 0008 puts it,
  rather than hardcoding `.pom` in `hort-app`;
- it answers the question for **every** participating format at once, so the
  next one added inherits the gate instead of re-earning this bug: Maven
  `*.pom` only, cargo the `.crate`, npm the tarball, PyPI's sdist/wheel;
- and it is a **total** function on the path, so "which artifacts are
  warmable" becomes readable in one place per format instead of being an
  emergent property of what the extractor happens to reject.

**It goes on `VersionDiscovery`, not on `FormatHandler`, and the trait's own
rule is the reason.** `extract_dependency_specs` is a `VersionDiscovery`
member (`crates/hort-domain/src/ports/format_handler.rs:382`, inside the
trait declared at `:231`), and that trait carries **"No default method
bodies. Every method here is required for any format that implements the
trait at all — the group either fully participates or is fully absent"**
(`:218-225`). So the acceptance criterion below — every format answers
deliberately, nobody inherits a default — is enforced by the compiler for
free, over the four formats that participate (`CargoFormatHandler`,
`NpmFormatHandler`, `PyPiFormatHandler`, `MavenFormatHandler`) plus the test
doubles that implement the group. On `FormatHandler` the same method would
need a default body (forty-odd implementors, most of them doubles) and the
default is exactly how the next format re-earns this defect — the trait's doc
records that history at `:213-217`: eight methods extracted out of
`FormatHandler` because *"defaulted no-ops [are] indistinguishable from 'not
yet implemented'"*.

**A format with no `VersionDiscovery` answers "no" structurally.** The call
reads `version_discovery()` first, so OCI, helm, rpm, debian and generic
contribute no enqueue at all — correct, and not a special case to write: a
format that cannot `extract_dependency_specs` has nothing for the job to
read. That is a second behaviour change beyond the JAR case, and it is the
same defect: today such a format with the trigger enabled enqueues a root
job whose handler cannot succeed.

**The call site already has what it needs.** `enqueue_prefetch_cascade`
takes `prefetch_transitive_deps_triggered` as a **precomputed** bool because
the caller holds `repo.format` before it is moved. The same caller — the
`ingest` tail at `ingest_use_case.rs:4384` — holds `format` and the
`artifact`, whose `path` field (`crates/hort-domain/src/entities/artifact.rs:252`)
is what carries the suffix. Precompute the predicate and pass it the same
way; do not reach for a new port inside the enqueue.

### Do not reuse `content_type_for`

`crates/hort-http-maven/src/lib.rs:841` already maps Maven suffixes, and it
looks like the answer. It is not, and its own doc comment says why: it is a
*"sensible default, not a contract"* for a `Content-Type` header, living in
the inbound-HTTP adapter. Binding a warming decision to a presentation
default makes the next person who adjusts a MIME type change which artifacts
get warmed. Nor may the predicate key on the **stored** media type for the
same reason — that string came from this helper.

### The skip is silent, not logged per artifact

A Maven repository ingests many more JARs than POMs, so a per-skip `info!`
turns the normal case into log volume. Count it if anything, and say in the
code why the absence of a job is correct rather than missing.

## Explicitly not in scope

**The second observation on the issue — two `trigger_source=prefetch`
failures on SNAPSHOT coordinates with `entity or character reference` — is
not in this item.** It is a different error class: a well-formedness failure
*inside* a document being parsed as XML, not a root-element mismatch, so
whatever the extractor had was XML-ish and was not a JAR. The jobs also ran
at `18:23:13` while the POMs of those coordinates were stored at `:19` and
`:21`, and the handler reads from CAS
(`crates/hort-app/src/task_handlers/mod.rs:58`) — so it read something
already stored, and what that was is the one fact nobody has. The reporter
was asked for the two jobs' `params.artifact_id` plus that artifact's `path`
and `checksum_sha256`; until that arrives there is no mechanism to specify,
and a fix aimed at a guess would be worse than none.

Also out: #418's missing `<parent>` edge (same surface, different cause),
any change to `extract_dependency_specs`' error semantics, and any widening
of what the cascade walks.

## Acceptance

- A Maven `.jar` ingest on a repository with `prefetch_enabled` and the
  `transitive_deps` trigger enqueues **no** `prefetch-dependencies` job; the
  `.pom` of the same coordinate still does. One test per direction.
- The predicate is a `VersionDiscovery` method with **no default body**, and
  `hort-app` contains no suffix literal for any format — asserted by a test
  or a grep stated in the report, not by inspection.
- All four participating formats implement it deliberately: cargo `.crate`,
  npm tarball, PyPI sdist/wheel, Maven `.pom` only. A format whose answer is
  "always true" says so in its own body; the trait admits no default to
  inherit.
- A format that does not implement `VersionDiscovery` enqueues nothing, with
  a test for one such format.
- `extract_dependency_specs` is unchanged in every handler, including its
  error semantics.
- No `info!` per skipped artifact.
- Gate green; `hort-domain`/`hort-app` add no uncovered lines; no ticket
  numbers in code comments.
