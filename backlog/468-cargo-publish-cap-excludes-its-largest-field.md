# 468 — the cargo publish-frame cap is justified against a body that excludes its largest field

**Issue:** #458 · **Found 2026-11-24** by the F11-4 UAT probe, which measured
this cap instead of the one it was aimed at.

## What was measured

On `0.18.1-alpha.1`, `PUT /cargo/<repo>/api/v1/crates/new` with `uat-writer`:

```
metadata = 65 536 B  (64 KiB)      -> 200, published and released
metadata = 65 537 B  (64 KiB + 1)  -> 400 validation: publish metadata exceeds 64 KB cap
```

Bracketed to one byte: the bound is **65 536 and inclusive**. Both requests
were identical in shape — same route, identity, `.crate` payload and metadata
structure — differing only in the length of a padded free-form field.

## The cap is right in kind and its stated justification is false

`parse_publish_body` (`crates/hort-http-cargo/src/lib.rs:875-895`) caps the
**attacker-supplied `meta_len` prefix** before any slice.

**Correction 2026-11-24, after unit 469's run disputed this paragraph and was
half right.** The reason stated here — *"a bogus declaration cannot drive a
multi-MiB allocation"* — is **false**. The route buffers through
`DefaultBodyLimit::max(200 MiB)` into `body: Bytes`, so the bytes are already
allocated when this function runs, and `meta_len` reaches only
`split_at_checked`, which allocates nothing and refuses an overrun. The
declared length drives nothing.

**A bound must nevertheless stay, for a different reason: the slice it admits
is parsed.** `serde_json::from_slice(metadata_bytes)` runs one line later in
the caller (`:681`), and `PublishMetadata` retains `deps: Vec<PublishDep>` and
`features: BTreeMap<String, Vec<String>>`
(`crates/hort-http-cargo/src/publish_metadata.rs:68`, `:73`) — unbounded
collections that allocate **proportionally to the document**. So the cap
bounded the parse's allocation at 64 KiB; removing it raises that bound to the
body limit, and the parse product adds to the 200 MiB buffer rather than
sharing it. The body limit bounds the *buffer*; this bound limits the *parse
product*. They are two allocations and they sum.

Its value rests on a comparison stated in the same comment:

> Publish metadata in practice carries a single version's metadata, which is
> structurally comparable to a **sparse-index entry** — well under 64 KiB,
> measured per entry when this cap was chosen.

**A sparse-index entry does not carry the README. The publish body does.**
hort says so itself, one file away
(`crates/hort-http-cargo/src/publish_metadata.rs:41-47`):

> Publish-body fields that exist only to populate a registry's website —
> `description`, `readme`, `keywords`, `categories`, `badges`, … — are
> dropped: … **`readme` alone carries the crate's entire README text**, which
> would bloat every metadata row for data no served document reads.

So the two comments are each locally true and jointly inconsistent: the cap is
sized against the *post-drop* shape while it is applied to the *pre-drop*
body. The dominant term is excluded from the measurement that set the bound.

## The consequence, and its shape

A crate whose README exceeds roughly 64 KiB **cannot be published to hort**.
`cargo publish` fails with `validation: publish metadata exceeds 64 KB cap` —
a refusal naming a bound the publisher cannot influence and whose cause
(the README) the message does not name. A README of that size is ordinary for
a project that inlines API documentation or a changelog, and crates.io accepts
it, so this is a hort-specific rejection of a legitimate publish rather than a
protocol limit a client already expects.

## Measured 2026-11-24 — two real crates, one of them hort's own dependency

98 crates sampled: all **66 of hort's direct `[workspace.dependencies]`** plus
32 targeted candidates picked for long documentation. For each, the highest
stable version's `.crate` was fetched from `static.crates.io`, the **`readme`
field declared in its `Cargo.toml`** was resolved, and that file was measured
both raw and JSON-encoded — the encoded length being what the publish body
actually carries.

| crate | declared readme | raw | JSON-encoded | vs the 65 536 cap |
|---|---|---:|---:|---|
| **`serde-saphyr 2.2.0`** | `README.md` | 76 578 | **78 445** | **over by 12 909 (1.2×)** |
| **`cargo-make 0.37.24`** | `README.md` | 163 309 | **169 436** | **over by 103 900 (2.6×)** |

**`serde-saphyr` is one of hort's own direct dependencies.** hort could not
accept a publish of a crate it itself depends on.

**The JSON-encoded README is a lower bound on the publish body**, not the whole
of it: the other publish fields (`description`, `keywords`, `categories`,
`deps`, `features`, …) add more, so both rows understate the margin.

**A false positive the method caught, worth keeping as a warning:** `just
1.59.0`'s repository README is 162 532 bytes, but it declares
`readme = "etc/crates-io-readme.md"` — a **585-byte** crates.io-specific file.
So it is comfortably **under** the cap. Measuring repository READMEs rather
than the declared field overcounts, and the declared field is the only correct
source.

**What this is not:** a frequency estimate for the registry. Two of 98 sampled
crates exceed it, on a sample deliberately biased toward long documentation.

**Not affected:** hort's own crates — none declares a `readme` field and the
largest README anywhere under `crates/` is 6 287 bytes — and the proxy /
pull-through path, which fetches the `.crate` and never sees a publish body.

## What this unit should decide and do

The guard stays; the question is its value and its message.

- **A larger bound** that still bounds the parse — the README is the only
  field with no natural ceiling, so a cap in the low MiB keeps the property
  while admitting ordinary publishes. **1 MiB** gives roughly 6x headroom over
  the largest real crate measured below and keeps the parse two orders of
  magnitude under the body limit.
- **Configurable**, which it is not today: a function-local `const`, declared a
  second time in the test module. An operator meeting an unusual crate should
  not need a rebuild.
- **A refusal that names the cause.** The current message names the bound and
  not the field, so a publisher cannot act on it. Naming `readme` as the usual
  cause turns an opaque refusal into an actionable one.
- **Correct the comment either way.** Whatever the value becomes, the
  sparse-index comparison must go: it is the reason the bound reads as
  measured when it was measured against the wrong document.

## What this unit is NOT

**Not F11-4.** That cap is `enforce_metadata_cap` /
`effective_metadata_cap` in `IngestUseCase` (8 MiB for cargo per
`crates/hort-formats/src/cargo.rs:386`), and the comment here states the
decoupling deliberately. The adapter's guard fires **first**, so on the cargo
publish path F11-4's cap is unreachable from outside — which is why the UAT
probe could not verify F11-4 and verified this instead.

## Governing decisions

None found governing a publish-frame bound. ADR 0007's fail-closed posture is
not engaged: this is an input-size guard, not an assessment.

## Decided 2026-11-24, after a design peer review (unit 470)

The design was written out, peer-reviewed by a second reviewer, revised against
that review, and implemented. Durable decisions, distilled here because the
branch-lifetime design document does not reach `develop`:

- **A bound stays, applied to the actual metadata slice after the checked
  split** — not to the declared `meta_len`. A declaration beyond the available
  bytes is a *truncated frame* and keeps saying so, rather than being reported
  as a size violation.
- **Its reason is the input to an allocating parse and the projection after
  it** — not "the parse product". A 1 MiB input does not yield a 1 MiB
  product: the projection clones the collections and builds a
  `serde_json::Value` tree on top.
- **The value is a fixed absolute constant, 1 MiB, and deliberately not an
  operator knob.** The first design made it settable with a body-derived
  ceiling; the review called that wrong and it is. There is no measured need
  to raise it; a body-derived ceiling is not a safety argument, because the
  body limit bounds buffered wire bytes while the memory that matters depends
  on JSON shape, retained entries, projection copies and concurrency; and a
  fixed fraction of a fixed 200 MiB is another chosen constant wearing a
  derivation. A knob at a parser's memory boundary reopens what the bound
  closes.
- **1 MiB is provisional, and the gap is named rather than papered over.** The
  README measurements above are one-axis: they establish **compatibility** —
  how much valid input must be admitted — and say nothing about
  **amplification**, since `readme` is an *ignored* field that `PublishMetadata`
  never retains. Calling the number calibrated needs whole-object publish JSON
  from dependency-heavy crates plus a peak-allocation measurement on a compact
  adversarial `deps`/`features` document. Until then it stands as strictly
  better than 64 KiB, which refuses real crates, and than no bound at all.
- **The refusal uses cargo's `{"errors":[{"detail":…}]}` envelope.** The
  handler already documented that cargo does not display the generic
  `{"error":…}` body legibly, so a better message in the generic envelope is
  one the publisher never sees. The message names the metadata JSON segment and
  its limit, and mentions a large README only as an **example** — never as the
  diagnosed cause, because the retained `deps` and `features` can fill the
  segment themselves.

### What the per-request memory model actually is

The first design said "two allocations" and treated the 200 MiB buffer as the
baseline. The review found a third: the handler copies the crate slice with
`crate_bytes.to_vec()` **while the body is still in scope**, so a crate-heavy
request holds close to twice the route's allowance. And the downstream 8 MiB
cap checks **after** the projection has already cloned the collections and
built a `serde_json::Value`, which `enforce_metadata_cap` then serialises into
a further `Vec<u8>` to measure. The input bound reduces that exposure; it does
not cap the projection's peak.

### Two caps named "metadata", correctly distinguished

They do not substitute for one another, and both doc comments now say which
representation at which stage: the **publish JSON parse-input limit** (this
one, before `PublishMetadata` exists) and the **ingest payload-metadata output
limit** (`metadata_expected_max_bytes`, 8 MiB, on the serialised projection
*after* it). The old description of the latter as an "upstream body cap" was
wrong in both the design and the code; cargo's streamed upstream body has its
own separate 64 MiB plausibility cap.

### Carried forward, not done here

- **The calibration evidence** above.
- **Sharing the obligation rather than the number.** Every untrusted publish
  document parsed into owned, growing state needs a bound before that parse,
  with each format documenting which bytes or elements it bounds — cargo a
  framed JSON slice, npm a 32 MiB envelope excluding attachment data, PyPI a
  multipart body plus a 100-field count. A DB-free structural guard could
  census the publish parse entry points and assert each has a preceding bound,
  in the style the workspace already uses. It must inspect each format's flow
  rather than assume one number fits all.
- **`enforce_metadata_cap`'s timing**, which measures after allocating.
- **npm's 32 MiB envelope comment** claims typical envelopes are under 1 KiB;
  that was never independently measured.
