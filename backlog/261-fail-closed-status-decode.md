# 261 — A status the domain cannot parse must not decode to the most permissive one

**Issue:** #334 · **Branch:** `agent/334-struktur-332`
**Governing decisions:** ADR 0007 (a held artifact under an active gate stays
unavailable until a release authority exists; `quarantineDuration: 0` is the
only operator opt-out) · the precedent set by `db_gate_not_silent`, which
already treats a discarded error as a hazard class.

## Why

The schema and the domain disagree about which quarantine statuses exist,
and the mapper resolves the disagreement in the most permissive direction.

- The CHECK accepts **seven** values — `unscanned`, `clean`, `flagged`,
  `quarantined`, `released`, `rejected`, `scan_indeterminate`
  (`migrations/003_artifacts_cas.sql:96-98`).
- `QuarantineStatus::from_str` accepts **five** — `none`, `quarantined`,
  `released`, `rejected`, `scan_indeterminate`
  (`crates/hort-domain/src/entities/artifact.rs:40-78`).
- Three schema-legal values cannot be parsed, and the domain's `none` cannot
  legally be stored at all. The mismatch runs both ways.

The full-row mapper then does
`.and_then(|s| s.parse().ok()).unwrap_or(QuarantineStatus::None)`
(`crates/hort-adapters-postgres/src/mappers.rs:282-291`), and the hot
package-status query repeats it (`artifact_repo.rs:653-713`). Every
unparsable value becomes the single most permissive state — the one the
schema forbids writing — and `Artifact::is_downloadable` accepts it
(`artifact.rs:1600-1612`). `download_inner` reads CAS on that predicate
(`artifact_use_case.rs:432-486`), and `filter_served_versions` serves it in
the default `ReleasedOnly` index mode (`index_serve_filter.rs:112-190`).

So a schema-valid `unscanned` row is advertised and served with no release
authority and no `ArtifactReleased` event. **The mapper's own unit test
asserts `'unscanned' -> None` as correct** (`mappers.rs:1640-1648`) — it is
not evidence, it is the defect written down.

This is the un-extended-mechanism shape a third time. The project already
rejects a swallowed error on a Postgres connect, by structural guard, for
exactly this reason: a discarded error reports "no state" where the truth is
"state not readable". The guard was never generalised to the decoding of
security-relevant state.

## What to do

1. **Make the decode fail closed.** An unparsable stored status is an error,
   not `None`. Which error surfaces where is a judgement call for the
   implementer: a read that cannot classify an artifact must not yield a
   downloadable one, and a request that cannot be answered safely fails
   rather than serves. Mirror `test_support`'s posture — a configured thing
   that does not work is not the same as an absent thing.
2. **Reconcile the two vocabularies.** Seven-versus-five is the root. Decide
   per value whether it is legacy to be migrated, legal to be parsed, or
   illegal to be rejected by the CHECK — and leave schema and domain
   agreeing. A narrowing CHECK is destructive DDL and falls under the
   expand/contract policy (ADR 0030): it ships one release after the last
   one whose code referenced the value, via `migrations/CONTRACTIONS.toml`,
   never by editing the manifest into passing. If that scheduling does not
   fit this item, land the decode fix and record the contraction for the
   next release.
3. **Extend the guard.** `db_gate_not_silent`'s reach stops at Postgres
   connects. Carry it, or a sibling in the same family, to a discarded parse
   error on a security-relevant status decode — at minimum the quarantine
   status, on every read path that feeds a serving decision.
4. **Replace the test that pins the fallback.**

## Explicitly out of scope

- No change to what any status *means*, and no new status.
- No backfill of existing rows beyond what step 2's decision requires.
- No change to `quarantineDuration: 0` — the documented permissive posture
  stays exactly as it is. A legacy spelling accepted by the CHECK is not an
  operator opt-out and must not become one.
- No widening of `from_str` to make the three legacy values parse as
  something serveable. That would close the symptom in the wrong direction.

## Acceptance

- A row carrying `unscanned`, `clean` or `flagged` is **not** downloadable
  and **not** served by any index source, proven by a test that writes the
  row and drives a real download and a real index response — not by a typed
  fixture.
- An unparsable status cannot reach `QuarantineStatus::None`.
- The schema and the domain agree on the value set, or the remaining
  difference is recorded in `migrations/CONTRACTIONS.toml` with the release
  it contracts in.
- The structural guard rejects a newly introduced `.ok()` on a status
  decode, with a counter-assertion that it still finds the sites it is meant
  to find, so a rename cannot make it vacuously green.
- Gate green: `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace`, `cargo-audit audit
  -D warnings`, `cargo-deny check`.
