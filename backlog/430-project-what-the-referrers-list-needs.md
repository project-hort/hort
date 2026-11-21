# 430 — project what the referrers list needs, at the two paths that write it

**Issue:** #456 · **Branch:** `agent/456-referrers-spec-conformance` · Item 0 of 3 — **this one goes first.**

## Why this item exists

The peer review established that three of #456's four findings cannot be fixed from what is stored today. The maintainer's decision (Matrix, 2026-11-21) is to **extend the projection** rather than work around its absence, on the standing principle that data we need is stored in its original granularity and derived values are computed at runtime.

That makes 427 and 428 **consumers** of one change rather than two changes to the same two functions. This item is that change, and it is deliberately a pure addition: it writes new keys and reads nothing differently, so it carries no read-path behaviour change at all.

## What is missing today

`subject_content_reference_claim` (`crates/hort-http-oci/src/manifests_write.rs:1596-1611`) writes exactly:

```rust
metadata: serde_json::json!({
    "artifact_type": artifact_type_opt,
    "media_type": media_type,
}),
```

So the `oci_subject` edge holds the referring manifest's **declared** `artifactType` and its **own** media type. It does not hold:

- **the OCI name the referrer was pushed under** — and `Artifact.name` cannot substitute, because `oci_manifest_path` is `manifests/sha256:<hex>` with *"the image name deliberately absent, so `(repository_id, path)` holds at most one manifest row per digest"* (`coords.rs:88-103`). Two names, one row, one name recorded.
- **the config descriptor's `mediaType`** — the spec's mandatory `artifactType` fallback for a manifest. The `oci_config` edge's own `media_type` is the *parent manifest's* type, not the config blob's.
- **the referring object's `annotations`** — the word appears nowhere in `manifests_write.rs` or `referrers.rs`.

## What to add

To the `oci_subject` edge metadata, written at **both** paths that create it — the hosted PUT and the pull-through/proxy path. **Find both before writing either**; a projection that only one path fills is worse than none, because the gap is then invisible rather than documented.

- `name` — the OCI name under which this referrer was pushed. This is the one that makes multi-naming representable at all.
- `config_media_type` — the config descriptor's `mediaType`, for an image manifest. Absent for an index, where the spec forbids the fallback.
- `annotations` — the referring manifest's or index's annotations, as the object declared them.

**Original granularity, no interpretation.** Do not compute the effective `artifactType` here and store it: store the declared value (already stored) and the config media type beside it, and let the read path apply the spec's fallback rule at runtime. If the rule ever changes, a stored verdict would be wrong and a stored input would not. This is ADR 0041's shape — *"the durable findings are the evidence; the policy is the interpretation"* — applied to a descriptor.

The metadata is a JSON column, so this needs no schema migration. Say so in the report rather than leaving a reader to wonder.

## Why projecting and not reading from CAS — the reason belongs in the record

ADR 0056 decided the **opposite** for SBOM components: *"A format may derive its SBOM components from the artifact's stored payload at scan time"*, *"no new field is captured, no new metadata is stored"*. Read flatly, that precedent argues for a bounded CAS read here too.

What distinguishes them is **who is waiting**. ADR 0066: *"work nobody waits on never displaces work someone waits on"*, and the classification axis is who waits. ADR 0056's reader is a scan — nobody is waiting, and trivy already pulls the bytes. This item's reader is a referrers list: one read per surviving row, per request, on a path a client is waiting on, with no cap in the chain (`fetch_all`, no `LIMIT`).

So the two decisions agree once the consumer's position is part of the question. Write that into the code comment, not just here — the next reader will find ADR 0056 and wonder why we did the other thing.

## The legacy rows

Decided: **document, do not backfill** (maintainer, same message). Every `oci_subject` edge written before this change lacks all three keys, and the read path must treat a missing key as "unknown", never as "absent by declaration" — those are different things and the spec's fallback rules turn on the difference.

Where the documentation goes is part of this item: the operator-facing note belongs where someone evaluating referrers conformance will look, not only in a code comment.

## Read first

- `crates/hort-http-oci/src/manifests_write.rs:1590-1700` — the subject and membership claims.
- The pull-through path that creates `oci_subject` edges. **It may not exist**; if a proxied manifest never gets a subject edge, that is a finding in itself and belongs in the report rather than being quietly worked around.
- `crates/hort-http-oci/src/coords.rs:70-103` — why `Artifact.name` is not the key.
- ADR 0041 (evidence versus interpretation), ADR 0056 (the opposite choice and its reason), ADR 0066 (who waits).

## Acceptance

- All three keys are written by **every** path that creates an `oci_subject` edge, with the paths named in the report.
- The declared `artifactType` is still stored as declared; no effective value is stored.
- A manifest pushed under two names in one repository produces an edge per name, or — if the edge is keyed such that it cannot — the report says so explicitly, because 428 then has no key either and must be re-decided.
- An index does not get a `config_media_type`.
- An object with no annotations does not grow an empty map; absent stays absent.
- The incomplete-legacy-row situation is documented where an operator looks.
- No read-path behaviour changes in this item. The referrers response is byte-identical before and after for a row written before the change.
- The change adds no uncovered lines.
