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
**attacker-supplied `meta_len` prefix** before any slice, so a bogus
declaration cannot drive a multi-MiB allocation. That guard is correct and
must stay.

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

**Not measured here:** how many real crates exceed it. The claim above is
about reachability and the refusal's wording, not about frequency.

## What this unit should decide and do

The guard stays; the question is its value and its message.

- **A larger bound** that still bounds the allocation — the README is the only
  field with no natural ceiling, so a cap in the low MiB keeps the anti-DoS
  property while admitting ordinary publishes. The number is a judgement about
  allocation risk, not a protocol constant.
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
