# 131 — Persist cargo publish metadata and serve it in the hosted index

Issue: #188.

## Why

The hosted cargo index synthesizes every entry with `deps: []` and
`features: {}` (`crates/hort-http-cargo/src/index_source.rs`, hosted path).
Observed consequence, `v0.11.0-beta.8`: five crates published, then

```
error: failed to prepare local package for uploading
  package `hort-http-core` depends on `hort-app` with feature `test-support`
  but `hort-app` does not have that feature.
```

`hort-app` has the feature; cargo validates the edge against the **index
entry**, which claims none. Beyond the publish chain, an entry with empty
`deps` for a crate that has dependencies hands any real consumer an
unbuildable graph. The sparse-index format requires real per-version
`deps`/`features`; the spec is authoritative over the implementation
(CLAUDE.md). The proxy path is unaffected — it re-serves upstream index
documents. Only the hosted path synthesizes.

Root cause is one deliberate deferral: the publish handler parses
`PublishMetadata { name, vers }` and discards the rest of cargo's publish
body, storing `payload_metadata: serde_json::Value::Null`
(`crates/hort-http-cargo/src/lib.rs:637` and the ingest call around `:738`)
with the comment "extraction is deferred until the index read path consumes
it". The index read path now needs it; the deferral is over.

## The seam already exists — mirror npm, do not invent

- **Persist:** npm's publish handler builds a `payload_metadata` JSON and
  passes it into the same `ingest_direct` field cargo currently nulls
  (`crates/hort-http-npm/src/lib.rs:758-830`). `enforce_metadata_cap` in
  `hort-app` already handles size-capping and the HashReference spill for
  large payloads. Cargo's publish body carries everything needed (`deps`,
  `features`, `badges`, …) — parse it fully and thread it through.
- **Serve:** `ArtifactUseCase::batch_metadata`
  (`crates/hort-app/src/use_cases/artifact_use_case.rs:934`) and
  `load_full_metadata` (`:538`) exist precisely to hand stored metadata back
  to index/serve paths. The hosted `IndexSource` already goes through
  `list_by_raw_name_visible`; join the metadata in via the use case (ADR
  0008: format crates never touch `ctx.artifact_metadata` directly).

## Protocol traps — the item exists because of these, get them right

1. **Publish-body shape ≠ index-entry shape.** Cargo's publish JSON names the
   requirement `version_req` and its dep entries differ from the index
   schema's (`req`, `features`, `optional`, `default_features`, `target`,
   `kind`, `registry`, `package`). The translation is specified in the
   registry-web-API / index-format docs — implement it per spec, not by
   guessing from one example. Intra-workspace deps arriving with
   `registry` set (they name `hort-crates`) need the spec's rule for
   same-registry deps (the index omits `registry` for same-registry deps).
2. **`dep:`-syntax features go in `features2`.** `hort-app`'s
   `test-support = ["dep:metrics-util"]` uses the new syntax. Per the index
   format, entries carrying such features split them into `features2` with
   `"v": 2`; older syntax stays in `features`. The
   `CargoVersionPayload` struct already has `features2` and `v` fields —
   currently always `None`. Serve them per spec so both old and new cargo
   resolve correctly.
3. **Checksum stays the storage hash.** `cksum` already comes from
   `artifact.sha256_checksum`; the publish body's `cksum` must continue to be
   ignored as an input (the CAS hash is the authority — ADR 0006 posture).

## Versions published before the fix

Rows ingested with `payload_metadata: Null` have nothing stored
(`hort-app 0.11.0-beta.8` included). **Serve them exactly as today** — empty
`deps`/`features`, present in the index — so nothing regresses. The backfill
question (extract from the stored `.crate`, where
`extract_dependency_specs`-style tarball parsing already exists) is an **open
decision on #188** and out of scope here; the next pre-release republishes
the set fresh either way.

## Scope boundaries

- Proxy and virtual index paths: untouched. The virtual path aggregates member
  entries — it inherits the fix through the hosted member automatically.
- SBOM: **no new scanner code.** The already-tested `deps` branch of
  `extract_sbom` (`crates/hort-formats/src/cargo.rs:496-522`) reads the same
  stored metadata; it lights up by itself once ingest stores it. Add one test
  proving a cargo publish now yields an SBOM with components.
- Yank semantics, quarantine filtering, `IndexModeFilter`: unchanged.
- No error-path weakening in the publish handler: a publish body whose
  metadata fails to parse should fail the publish loudly, not ingest with
  `Null` — accepting-but-ignoring operator-relevant data is the ADR 0015
  anti-pattern.

## Done when

- A workspace publish where crate B's `[features]` references
  `crateA/feature` succeeds against a hort hosted repo: the served index
  entry for A carries its real `features`/`features2` and B packages cleanly.
  Pin this with a handler-level test (mock ctx) asserting the served NDJSON
  entry, feature split included.
- Served hosted entries carry spec-shaped `deps` translated from the publish
  body (`version_req` → `req`, same-registry `registry` omitted), pinned by
  test against a fixture publish body.
- Pre-fix rows (no stored metadata) still serve as today; pinned by test.
- A cargo publish ingest produces an SBOM with the crate's declared deps as
  components (one test).
- Coverage per tiers: `hort-app` 100% on touched code, `hort-http-cargo`
  ≥ 85%. Any new DB-touching test in `hort-adapters-postgres` carries
  `#[serial(hort_pg_db)]`.
- Full local gate: `cargo fmt --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace`, `cargo audit`,
  `cargo deny check`.
