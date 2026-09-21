# 0055 — The write-authorized hold-read is a general rule, and it covers the cargo sparse index

- **Status:** Accepted
- **Generalises:** [0039](0039-keyed-provenance-verification.md) §10 — the
  push-then-sign hold exemption on the OCI manifest path. That ADR decided the
  rule for one call site while stating it in terms of that site's mechanics
  (cosign, subject manifests, layer blobs). This ADR names the rule itself and
  records its second call site. ADR 0039 is not amended: it is a decision about
  keyed provenance verification, and cargo publishing is not — folding this in
  would muddy a record that is currently precise.
- **Enforced by:**
  `hort_app::use_cases::repository_access::RepositoryAccessUseCase::resolve_granted_write`
  (the `AuthorityBasis::GrantedOnly` predicate, shared by every call site),
  `hort_app::use_cases::index_filters::HeldVisibility` (the served-status truth
  table, exhaustive over `QuarantineStatus` with no wildcard arm), the
  per-site predicates in `crates/hort-http-oci/src/{manifests,blobs}.rs` and
  `crates/hort-http-cargo/src/serve.rs`, and — for qualifier 3's
  resolution-document boundary on npm — `HeldReason` / `HeldVersion` in
  `crates/hort-formats/src/npm/index.rs` and `collect_held` in
  `crates/hort-http-npm/src/serve.rs`.
- **Relates:** [0007](0007-fail-closed-quarantine-release-predicate.md) (the
  quarantine window this reads across, unchanged),
  [0036](0036-oci-auth-capability-token.md) (the cap-intersection invariant this
  is a bounded exception to), [0031](0031-virtual-repository-aggregation.md)
  (why aggregated reads are excluded),
  [0035](0035-cargo-config-json-anon-readable-auth-required.md) (the cargo
  auth surface). Source decision: issue #179, operator's 2026-08-20 answer.

## The rule

> **A principal that may write to a repository may resolve held *metadata*
> there. Held *bytes* never leave quarantine, for anyone.**

Three qualifiers carry the whole security argument, and none is decorative:

1. **"May write"** means *granted* write authority — the grants leg alone,
   evaluated by `resolve_granted_write`, not the presented token's capability.
2. **"Metadata"** means the resolution document a client reads to learn a
   version exists and what its bytes hash to — an OCI manifest, a cargo
   sparse-index entry. Never the content.
3. **"Held"** means `Quarantined` — a hold *pending* a verdict, and this
   qualifier governs the **resolution document** qualifier 2 names — an OCI
   manifest, a cargo sparse-index entry, an npm packument's `versions{}` /
   `dist-tags` — not the refusal a caller receives when they ask for one
   directly. A verdict already reached (`Rejected`, `ScanIndeterminate`) is
   terminal: it makes the version unresolvable in that document, for
   everyone, publisher included, exactly as `Quarantined` does — neither
   status ever yields a manifest, an index entry, or a packument entry that
   resolves to bytes.

   Resolvability is gated by this qualifier; diagnosability is not. *Why* a
   version cannot be resolved is information, not access, and every byte
   route is free to say so to any caller holding `Read`. npm, Maven and
   Cargo do: `503 … quarantined` + `Retry-After` for the timed hold, `403 …
   rejected` / `403 … scan is indeterminate` for the terminal verdicts
   (`crates/hort-http-npm/src/lib.rs`, `crates/hort-http-maven/src/lib.rs`,
   `crates/hort-http-cargo/src/lib.rs`). OCI's `Rejected` and PyPI's
   `.metadata` route take the opposite, format-specific anti-enumeration
   choice instead — `MANIFEST_UNKNOWN` / `BLOB_UNKNOWN`
   (`crates/hort-http-oci/src/{manifests,blobs}.rs`) or a plain 404
   (`crates/hort-http-pypi/src/metadata_endpoint.rs`), collapsing the
   verdict into the same answer as "does not exist". Both choices satisfy
   this qualifier: it constrains what the resolution document resolves to,
   not whether the refusal names its reason.

   **Clarified 2026-09-17 — npm's packument enumerates withheld versions;
   the rule did not change.** `hort.held[]` names every withheld version and
   its reason (`HeldReason` / `HeldVersion`,
   `crates/hort-formats/src/npm/index.rs`; collected by `collect_held`,
   `crates/hort-http-npm/src/serve.rs`) — an accepted consequence (#251): a
   `Read` holder who previously needed a version number to ask about it can
   now read the list (upstream's numbers, on a proxy repository; the
   maintainer's own, on a hosted one). `hort.held[]` still never resolves a
   withheld version to a `versions{}` entry, so resolvability stays gated;
   only diagnosability widens, from "ask and be told" to "enumerated up
   front" — still the narrow reading, not the wide one rejected on #254
   (answering every hold and verdict alike with a plain `404`, which would
   replace "we withhold this" with "this does not exist").

## Context

ADR 0039 §10 decided this for OCI: under `provenance_mode: Required` a subject
image is held `Quarantined` until a signature arrives, but `cosign sign`
resolves the subject manifest *before* it can attach one. Without an exemption
the signature can never be produced and the artifact expires
`Rejected{Unsigned}` — the hold makes its own precondition unreachable.

Cargo publishing has the same shape, from a different direction. `cargo
publish` resolves each crate's intra-workspace dependencies through the
registry index, and it does so **even under `--no-verify`**. hort's first-party
`hort-crates` repository serves a `ReleasedOnly` index and quarantines a
freshly published crate for its observation window, so every publish after the
first fails to resolve the sibling it just uploaded. The failure lands
mid-chain, with the earlier crates already uploaded and only yankable — the
worst place in the operation to fail.

The mapping to the OCI case is one-to-one: a sparse-index entry is the
manifest, and the `.crate` download is the layer blob. The same principal is
mid-write to the same repository, and needs the same metadata resolution to
finish the write it already started.

**Update (2026-08-21) — the cargo half's scan posture moved; the rule did
not.** `hort-crates` now scans in record mode over resolved-version SBOMs
([ADR 0056](0056-resolved-component-sboms-from-payload.md), [ADR
0034](0034-public-dogfood-deployment.md)'s Class A amendment), so a scan verdict
on a first-party crate records findings instead of holding or rejecting it. That
narrows *when* a publisher meets a held sibling on this particular repository;
it changes nothing about the rule decided here, which keys on granted write
authority and `Quarantined` status alone and is deliberately not tied to any
one deployment's policy. The OCI half (ADR 0039 §10) is untouched.

**Measured, not assumed.** Against the live registry, using a real released
crate and an isolated `CARGO_HOME`, `cargo generate-lockfile` and `cargo
package --no-verify` each resolved the dependency through the index and fetched
**zero** `.crate` files. The exemption therefore stays strictly on the metadata
side of the line; nothing about the publish path needs held content.

## Decision

Generalise the rule as stated above, and apply it at the cargo sparse-index
serve path (`serve_index_unified`) as the second call site.

### Why granted authority and not the presented capability

A cap-intersected `resolve(_, Write)` **could never engage** at either site,
and would fail silently rather than loudly.

For OCI the reason is that clients scope a subject read as `pull` — spec-correct
and least-privilege — so the capability JWT presented on the read carries a
read-only cap even when the identity's grants carry Write.

For cargo the reason is structurally the same and arrives by a different route:
cargo presents one registry token for both index reads and uploads, so the
index read that must succeed is not the operation whose authority the token was
narrowed for. In both cases the identity holds Write; the presented credential,
correctly, does not assert it on this request.

So the held-visibility decision — and *only* that decision — evaluates the
grants leg alone (`RbacEvaluator::authorize_granted`, which preserves the B1
fail-closed admin-claim/no-cap arm). The read being exempted stays fully
cap-gated: it satisfies the ordinary `resolve(Read)` hop first, exactly as any
other read does.

This is the same bounded exception to ADR 0036's cap-intersection invariant
that ADR 0039 §10 opened, now with three sites instead of two. Every other
authorization decision keeps the two-leg AND.

### Scope, stated as what the exemption does not reach

- **Held bytes, for anybody.** The cargo download path
  (`render_cargo_crate_response`) gates on artifact status alone and never
  consults the caller; the OCI blob path keeps its existence probe `HEAD`-only.
  A held `.crate` is `503` to its own publisher. If a change ever makes held
  content downloadable, the exemption has been broken rather than extended.
- **Terminal verdicts.** `Rejected` and `ScanIndeterminate` are decisions, not
  holds. `HeldVisibility::admits` matches exhaustively over `QuarantineStatus`
  with no wildcard arm, so a future variant is a compile error at the truth
  table rather than a silent inheritance of either answer.
- **Aggregated reads.** The rule says a writer may resolve held metadata
  *there* — in the repository it may write. A virtual repository holds no
  artifacts of its own (ADR 0031); its entries belong to members. A Write grant
  on the aggregator is not write authority on the member the held entry lives
  in, so an aggregated read keeps the ordinary view even for a write-granted
  caller.
- **`IndexMode`.** Neither mode's behaviour changes. `IndexModeFilter` decides
  the fate of never-ingested versions; both modes already agreed on entries
  with a known status, and the exemption widens exactly one column of that
  agreement, identically in both.
- **The quarantine window itself.** Nothing is released earlier, and the
  release predicate (ADR 0007) is untouched. This changes who may *see* held
  metadata, nothing else.

### With authentication disabled the exemption engages for every caller

`RbacAccess::Disabled` — the single-node dev / bootstrap mode — admits every
caller, so `resolve_granted_write` succeeds for an anonymous request and held
index entries become visible to all.

This is deliberate, and it is not a property of this decision: the OCI hold-read
site shares the same use case and has behaved this way since ADR 0039 §10. In
that mode every caller can already write to any repository and release any
artifact, so held *metadata* visibility discloses nothing that is not already
obtainable — an anonymous caller could simply release the artifact and read it
outright.

A cargo-only special case was considered and rejected: it would make the two
hold-read sites disagree about a rule this ADR exists to state once, and buy no
security in a mode that has none by construction. Operators are reminded that
`Disabled` is a bootstrap posture, not a deployment one.

### The response becomes identity-dependent, so it stops being cacheable

The cargo index route previously emitted no `Cache-Control` and no `Vary`,
which was safe only because its response was identical for every reader. That
premise is exactly what this decision removes.

Absent directives are not "no caching": heuristic caching applies, and with no
`Vary` nothing tells an intermediary the body depends on identity — a shared
cache or reverse proxy could store a publisher's response, held entries
included, and replay it to an anonymous consumer. That is the one way this
change could produce the leak it exists to prevent, so closing it is part of
the same decision, not a follow-up: every response from the route carries
`Cache-Control: private, no-store` and `Vary: Authorization`, unconditionally.
Conditioning the headers on the exemption having engaged would leave the
ordinary responses heuristically cacheable under the same URL key.

### The exemption is a no-op unless the dependency names its registry

The publish job activates `[source.crates-io] replace-with = "hort"`, pointing
at the read-only aggregation index. An intra-workspace dependency with no
`registry` key is a crates.io dependency, so it is replaced and resolved
through that index — a repository the release identity holds no write grant on,
where the exemption correctly does not engage. `--registry` on the command line
does not change this; replacement is decided per dependency, from the manifest.

`[workspace.dependencies]` therefore pins every `hort-*` entry to
`registry = "hort-crates"`, which is exempt from source replacement and reaches
the repository where the identity holds write.
`crates/hort-server/tests/publishable_manifests.rs` asserts the key, the
`.cargo/config.toml` declaration it requires (cargo refuses to parse a manifest
naming a registry it has no index for), and that the `publish` allow-list names
the same registry.

## Alternatives rejected

- **`indexMode: includePending`.** Changes nothing here. `IndexModeFilter`'s
  mode arms only decide versions with no hort row; for a known status both
  modes drop `Quarantined`. `hort-crates` is `type: hosted`, so the
  never-ingested column has no rows at all.
- **`cargo publish --workspace`.** Packages in dependency order and
  auto-selects the registry, but still resolves each crate through an index —
  it fails at the second crate exactly like a sequential loop. Worth adopting
  for ordering hygiene; it is not a fix.
- **Shortening the quarantine window.** Would work, and weakens the guarantee
  for *every consumer* to solve a publisher-only problem. The exemption is
  strictly narrower: same window for everyone who is not already writing.
- **Granting `curate` to the release identity.** Would work, and hands CI
  standing authority over other people's artifacts to solve a problem about its
  own.
- **Polling until each crate is servable.** Correct, and costs hours of release
  wall clock per cut. The dependency graph is deep enough that parallelising
  saves one wait, not most of them.

## Consequences

- A publisher's view of an index it may write differs from every other
  caller's. Held entries are visible to it, and only to it.
- The blast radius of the ADR 0036 exception grows by one site and stays the
  same in kind: a stolen read-scoped token of a write-granted principal can
  observe held *metadata* in repositories that principal may write. It cannot
  fetch held content, and a stolen token of a non-writer gains nothing.
- The cargo index route is no longer cacheable by shared caches. It was not
  being cached deliberately before, so this costs nothing that was being
  relied on.
- The rule now has a name and a truth table (`HeldVisibility`) instead of two
  hand-written predicates. A third call site should reuse both rather than
  re-deriving the reasoning; a site that needs a *different* answer needs a new
  decision, not a new flag on this one.
