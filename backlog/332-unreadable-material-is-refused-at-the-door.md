# 332 — Unreadable material is refused at the door

**Issue:** #350 · **Branch:** `agent/350-terminality-only-from-disproof`
**Governing decisions:** ADR 0039 §8 (the push-path signature exemption) ·
ADR 0007 (fail-closed) · ADR 0006 (verified ingest) · ADR 0008.

**Depends on item 331** — the fallback lands first, because it is what covers
everything this item cannot reach.

## The maintainer's decision (#350, 2026-10-14)

> *"Wir müssen unlesbaren Müll **idealerweise direkt ablehnen**, so dass es
> garnicht in Betracht gezogen werden kann."*

This is the first of the two rules: do not accept the garbage at all.

## What is true today

A pushed manifest takes the narrow signature path when
`is_pure_signature_manifest` says so
(`crates/hort-http-oci/src/manifests_write.rs:568-575`), and that predicate
reads **only the manifest JSON**:

```rust
subject_digest_parsed.is_some()
    && (hort_domain::oci::is_pure_sigstore_bundle(body_bytes).unwrap_or(false)
        || hort_domain::oci::is_pure_simplesigning(body_bytes).unwrap_or(false))
```

Both predicates key on the **declared** per-layer `mediaType`
(`crates/hort-domain/src/oci.rs:173-182` and `:198`+). The rustdoc is explicit
that this is deliberate and that the pusher controls it:

> *"The exemption is gated on the manifest's declared media types, which a
> write-authed pusher fully controls — so it is deliberately AIRTIGHT: it fires
> **only** when the manifest carries a `subject.digest` AND EVERY layer is
> signature material."*

The "every layer" rule is a real anti-scan-evasion guard and stays. What is not
checked is whether the bytes behind those declared layers are the thing they
are declared to be.

## What this item adds

When — and only when — a manifest declares **every** layer to be a signature
media type Hort recognises, each declared layer's blob must parse as that
shape. Unparseable ⇒ the push is **refused**.

- Keyless (`SIGSTORE_BUNDLE_MEDIA_TYPE`): the bytes must parse as a Sigstore
  v0.3 bundle.
- Keyed (`COSIGN_SIMPLESIGNING_MEDIA_TYPE`): the bytes must parse as the
  simplesigning payload shape.

**Well-formedness only — not verification.** Whether a signature is *valid*
needs the trust root and the subject's bytes and stays in the verifier. The
door answers one question: *is this the kind of thing it claims to be?*

### Three properties this shape has, and each is load-bearing

**Forward compatibility is not lost.** An unrecognised media type already fails
both predicates, so such a manifest is not a signature manifest at all and
takes the generic ingest path — scanned and quarantined like any other content.
A future bundle version carrying a new media type is therefore **not** refused;
it simply is not treated as a signature, so an artifact relying on it holds as
unsigned. That is the correct direction, and it retires the cost I quoted on
#350 before reading the predicate.

**The bytes are normally in hand.** The push already resolves every referenced
blob to a same-repo, non-terminal row before the mint (module docs step 4,
answered with 400 `MANIFEST_BLOB_UNKNOWN` at step 7), and a signature manifest
carries one or two layers. So the check adds about one CAS read to a path that
is already doing per-layer lookups.

**It cannot be certain, and must not pretend to be.** Step 4 resolves **rows**,
not bytes: a row can exist while CAS does not hold the blob. If the bytes
cannot be read at push time, the push is **not** refused — the manifest lands
and item 331's rule covers it. Refusing on an unreadable CAS would turn a
storage fault into a client error and make pushes fail for a reason the client
cannot act on. This is precisely why the maintainer asked for both rules; the
report must state which branch each test exercises.

### The refusal

Reuse the existing vocabulary rather than inventing a code: the path already
answers an unsatisfiable reference with 400 `MANIFEST_BLOB_UNKNOWN` plus a
`detail` array. A layer that is present but is not the shape it declares is a
different complaint — the manifest is invalid, not the blob missing — so
`MANIFEST_INVALID` with a `detail` naming the offending layer digest is the
honest mapping. Confirm the wire shape against
`crates/hort-http-oci/src/error.rs` before choosing, and state the choice in
the report.

## Acceptance

- A test: a manifest declaring one `SIGSTORE_BUNDLE_MEDIA_TYPE` layer whose
  blob is not a bundle is **refused** at push, with the layer digest named.
- A test: the same manifest with a genuine bundle is accepted and still takes
  the narrow signature path — the exemption is not broken by the new check.
- A test: a keyed `simplesigning` manifest, both ways.
- A test: an unrecognised layer media type is **not** refused — it takes the
  generic scanned path, proving forward compatibility.
- A test: when the layer blob's bytes cannot be read, the push is accepted (the
  fallback owns that case) and the reason is logged.
- A test: a mixed manifest (a signature layer plus a `tar+gzip` layer) still
  fails `is_pure_*` and stays on the generic scanned path — the
  anti-scan-evasion guard is untouched.
- Full gate green. No issue/MR references in code comments.

## Out of scope

- Any change to the "every layer must be signature material" rule.
- Verifying signatures at push. The door checks shape, never validity.
- Referrers Hort lands itself from an upstream proxy: they do not come through
  this path at all, and item 331 is what covers them. Say so in the rustdoc so
  the next reader does not assume the door is total.
