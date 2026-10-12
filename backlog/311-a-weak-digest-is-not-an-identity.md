# 311 — A weak digest is not a cross-origin identity

**Issue:** #346 · **Branch:** `agent/346-pullthrough-weaker-than-its-proof`
**Governing decisions:** **ADR 0033** (SHA-1 is a transfer-verification floor,
never an identity), ADR 0006 (mandatory upstream verification), ADR 0003 (the
CAS key is always SHA-256).

**Independent of items 312 and 313.** It is the high finding of the block.

## What is true today

`DedupKey::blob_by_hash(algorithm, hex)` (`crates/hort-app/src/pull_dedup.rs:324`)
coalesces a blob fetch **cross-repository and cross-format** — the metric
`format` label is the literal `"_any"` sentinel — and its rustdoc justifies
that reach with:

> *"Cross-repository AND cross-format: the content hash is the natural dedup
> boundary because two callers of any shape asking for the same bytes can share
> the result."*

That is true of SHA-256. It is **not** true of the SHA-1 floor, and the domain
already says so in as many words (`crates/hort-domain/src/types/checksum.rs:15`):

> *"SHA-1 (40 hex chars). **Transfer-verification target ONLY.** … It is
> **never** a `ContentHash` … SHA-1 is collision-broken; the floor catches
> transport corruption and casual tampering only"*

— and closes with the sentence this item exists to retire: *"This invariant is
a doc/review contract — there is no consumer in this module to enforce it."*

**Measured: exactly one call site can pass a weak algorithm.** Of the six
production constructions of `blob_by_hash`, five hardcode a strong digest —
PyPI `"sha256"` (`hort-http-pypi/src/upstream_pull.rs:398`), Cargo `"sha256"`
(`hort-http-cargo/src/upstream_pull.rs:355`), npm `"sha512"`
(`hort-http-npm/src/upstream_pull.rs:419`), OCI `"sha256"` twice
(`hort-http-oci/src/{manifests.rs:825,blobs.rs:819}`). The sixth,
**`hort-http-maven/src/upstream_pull.rs:183`**, passes `dedup_alg` — the
algorithm `fetch_strongest_sidecar` (`:356`) resolved, whose documented floor
is `.sha1` ("The floor must always be reachable").

So a caller able to produce a SHA-1 collision gets **another upstream's bytes
coalesced under its own identity**, and the follower repository registers them
with `register_existing_cas_blob`.

The sidecar floor itself is **not** the defect and is not touched: ADR 0033
decided that SHA-1 may verify a transfer. What this item removes is its use as
an *identity*.

## What to do

1. **Give the invariant a consumer, in the domain.** A predicate on
   `HashAlgorithm` answering *"may a digest of this algorithm serve as a
   cross-origin identity?"* — `Sha256` / `Sha512` yes, `Sha1` no. **Exhaustive
   and wildcard-free**, so a fourth algorithm is a compile error here rather
   than a silent yes. Its rustdoc cites ADR 0033 and replaces
   `checksum.rs`'s "no consumer in this module to enforce it" sentence with a
   pointer to this one.
2. **The cross-origin key is reached only through the predicate.** At the Maven
   site, a resolved algorithm the predicate refuses must not build
   `blob_by_hash`. Use the narrower existing key instead — `DedupKey::blob_by_url`,
   which is per-format and per-URL and therefore cannot carry another origin's
   bytes. Coalescing is then **kept where it is sound and dropped where it is
   not**, rather than removed wholesale.
3. **Say it at the key, not only at the call site.** `blob_by_hash`'s own
   rustdoc currently asserts the cross-everything boundary unconditionally.
   It must state the precondition it now has, so the next caller passing a
   variable algorithm reads the rule before writing the bug.

## Explicitly out of scope

- The `.sha1` sidecar floor and Maven's preference order. ADR 0033 stands;
  SHA-1 keeps verifying transfers.
- The five hardcoded-strong call sites. The predicate makes their correctness
  provable instead of coincidental; none of them changes.
- `ContentHash` / the CAS key — always SHA-256, untouched (ADR 0003).
- Any new metric or label. The `"_any"` sentinel keeps its meaning on the
  strong path.

## Acceptance

- The predicate exists in `hort-domain`, is exhaustive and wildcard-free, and
  cites ADR 0033.
- **Two Maven pulls declaring the same SHA-1 hex from different upstream
  mappings do not coalesce**; two declaring the same SHA-256 hex still do.
  Both asserted.
- A grep shows no `blob_by_hash` construction in `crates/*/src` reachable with
  an algorithm the predicate refuses. Report the per-site census with the
  algorithm each passes.
- **Non-vacuity: make the predicate admit `Sha1`, show the first test red,
  restore it.** Output in the report.
- The observable narrowing is stated for the release note: an upstream offering
  **only** `.sha1` sidecars loses cross-origin dedup (it still pulls and still
  verifies; it just no longer shares a fetch with another origin).
- Gate: the **unit gate**, one-shot capture:
  `bash handover/gate-unit.sh -p hort-domain -p hort-app -p hort-http-maven` —
  judge by the output, not the rc, and quote the totals. Do **not** run
  `cargo test --workspace`, `cargo audit`, `cargo deny` or the attribution
  script; the architect runs the full gate on the same tree before any MR.
