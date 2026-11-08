# 393 — A refused OCI read leaves a record

**Issue:** #258 · **Branch:** `agent/258-a-refusal-leaves-a-record` · single
item. **No behaviour change** — no status code moves, no new event.

**Governing decisions:** ADR 0007 / ADR 0027 (the holds whose refusal this
records) · ADR 0061's event vocabulary (why a refusal is not an event).

## Read the issue description, not the issue's history

Two of #258's three original claims did not hold against `develop` and the
description has been corrected. Do not restore them:

- A **successful** hosted OCI read is already durably audited — an
  `ArtifactDownloaded` event in a `StreamCategory::DownloadAudit` stream
  (`crates/hort-http-oci/src/manifests.rs:507` →
  `crates/hort-app/src/use_cases/artifact_use_case.rs:640`; blobs at
  `crates/hort-http-oci/src/blobs.rs:819`). **Nothing is wanted on that
  path.**
- The write-authz resolve does **not** fire on the hot read path.
  `manifests.rs:323-325` says so itself: *"the two `matches!` sets are
  disjoint, so at most one `resolve_granted_write` ever fires, and only on
  the narrow withheld-manifest path — the hot read path is unaffected."*

## The property

**A refusal leaves a record naming its reason.** The quarantine / provenance
gate runs *before* `download()` (`manifests.rs:349`), so a `503`, a `404` or a
provenance hold writes neither an event nor a log line. Success is audited;
refusal is invisible, and the refusal is the case an operator investigates.

One line per refused manifest **and** blob read, naming repository,
reference, resolved digest where one is known, the response status, and the
reason (`quarantined` / `rejected` / provenance-hold).

## A log line and not an event — decided, with the reason

The volume on the refusal path is **set by someone else**: a served download
is bounded by real artifacts, a refusal by whoever is retrying (the incident
behind the issue is 21 requests in two minutes from one deploy tool). A volume
another party controls does not belong in the event store, which is durable,
replicated and retention-governed. Secondarily: a refused read changes no
artifact state, and the event vocabulary is the artifact lifecycle.

So: **no new `DomainEvent` variant, and nothing added to `DownloadAudit`.**

## What to establish before writing the line

1. **Every refusal exit on the hosted read path**, manifest and blob, by its
   `return`. Census by the statement, not by the names the issue uses — the
   last two units were each short by writers nobody had named. Say in the
   report how many there are and whether any is unreachable.
2. **Which of them already logs.** Some may; a second line beside an existing
   one is noise, and a line that contradicts one is worse.
3. **What the hold-read exemption does.** `artifact_use_case.rs:1189-1196`
   already writes an `info!` for a served hold-read and documents why it is
   not an event. A refusal line must not read as its negation.

## Level, and where the line goes

Pick one level and justify it: a refusal is an ordinary, expected answer for a
quarantined artifact (so `info!`), while a provenance-hold or a `rejected` is
a security-relevant state an operator acts on (so arguably `warn!`). One
decision, stated — do not sprinkle three levels across the exits.

Put it where the status is decided, not in a wrapper: a line emitted by a
helper that does not know the status would have to be told it, and then the
status has two sources.

## Acceptance

- Every refusal exit on the hosted manifest and blob read paths emits one line
  naming repository, reference, digest where known, status and reason.
- Nothing is added to the success path.
- No new event, no new `DomainEvent` variant, no status code changed.
- The level choice is one decision with its reason stated in the code.
- A test per refusal class asserting the line's fields — the `tracing` test
  support this workspace already uses, not an eyeball.
- No issue, MR or backlog reference in any code comment.
- Gate green.
