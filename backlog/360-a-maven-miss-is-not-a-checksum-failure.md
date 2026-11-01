# 360 — A Maven miss is a 404, not a checksum failure

**Issue:** #391 · **Branch:** `agent/391-maven-miss-is-not-a-checksum-failure` · single item.

## The defect is the order of operations, not the mapping

`map_upstream_pull_error` (`crates/hort-http-maven/src/upstream_pull.rs:572`)
is already right: `NotFoundUpstream` → **404**, `NoChecksumSidecar` → **502**
(ADR 0006's "unproxiable"). **Do not change that table.**

The 404 branch is unreachable for a missing coordinate. The pull is ordered
(`:166-175`):

1. resolve the upstream mapping;
2. **fetch the checksum sidecar** — `fetch_strongest_sidecar`, `.sha512` →
   `.sha256` → `.sha1`, where a not-found, a transport failure *or* a malformed
   body falls through to the next, and all three exhausted returns
   `NoChecksumSidecar` (`:402`);
3. *then* stream the artifact body.

The `fetch_artifact` 404 → `NotFoundUpstream` mapping lives at `:260-269`, in
step 3, which a sidecar-exhausted request never reaches. So hort answers 502
**without ever asking whether the artifact exists**, and "all sidecars absent"
is indistinguishable from "nothing is there". The metadata path returns a
correct 404 for the same coordinate precisely because it does not go through
this loop.

## Measured consequence (#391)

A virtual repository stops at the first member whose upstream lacks the
coordinate, because 502 is a transport error rather than a miss. Measured:
`maven-virtual` → `[ttrekkbar-maven, maven-central, maven-spring-snapshots]`,
requesting a Spring snapshot — member 2 answers 502 and member 3, which holds
it, is never consulted. No ingest is recorded for any member. Requested
directly, member 3 ingests it fine.

**This is not an edge case.** The reporter's own conclusion: *"A virtual
repository mixing a release upstream and a snapshot upstream therefore cannot
serve both"* — the ordinary Maven topology — and no member ordering avoids it,
which they demonstrated in both directions.

## The change

On sidecar exhaustion — **and only there** — ask whether the artifact exists
before classifying:

- artifact `404` → `NotFoundUpstream` → **404**, a miss, and a virtual
  repository continues to the next member;
- artifact fetch succeeds → `NoChecksumSidecar` → **502**, ADR 0006's genuine
  unproxiable case: the bytes are there and cannot be verified, so hort refuses
  rather than storing unverified.

### Use `fetch_artifact`, and do not add a port method

`UpstreamProxy` (`crates/hort-domain/src/ports/upstream_proxy.rs`) has **no**
HEAD/exists method — only `fetch_blob`, `fetch_manifest`, `fetch_artifact`,
`fetch_metadata`, `fetch_referrers`. Adding one would mean a new outbound port
method across every adapter and every test double, for a probe on an error
path. Don't.

`fetch_artifact` returns `ArtifactFetch { stream: BlobStream, .. }` (`:91-94`)
— a **stream**, so the call returns at the response headers and the body is
never read unless a consumer reads it. So on the exhausted path:

- call `fetch_artifact`; a 404 surfaces as the error the existing `:260-269`
  comment describes → `NotFoundUpstream`;
- on success, **drop the `ArtifactFetch` without reading the stream** →
  `NoChecksumSidecar`.

The miss case — the one this bug is about — costs one request that returns no
body. The success case costs one request whose body is discarded, and it is
both rare and already a refusal.

**Put the probe at the call site, not inside `fetch_strongest_sidecar`.** That
function is about sidecars; teaching it to fetch artifacts would blur the
concern and make its own tests ambiguous. A small named helper beside it that
takes the exhaustion and classifies it is the right shape.

### Do not change the virtual fall-through

Considered and rejected: after this fix a 502 means "the upstream has these
bytes and hort cannot verify them". Skipping that member would hand the client
a *different* artifact than the one the refusing member holds, and the refusal
— a security statement — would become invisible. Aborting on a genuine 502 is
correct. The reporter's scenario simply stops producing one.

## ADR 0006 is untouched

Verification still precedes any store; there is no soft-fail and no
store-without-verify. The probe stores nothing and changes no verification
rule — it only decides which of two existing errors describes the failure.

## Acceptance

- All sidecars absent **and** the artifact absent → **404**, envelope
  `artifact not found`, matching the metadata path's answer for the same
  coordinate.
- All sidecars absent **but** the artifact present → **502** with
  `X-Hort-Reason: upstream-no-checksum-sidecar`, unchanged from today.
- A sidecar that resolves → the happy path is byte-for-byte unchanged; prove it
  with the existing tests passing unmodified.
- The malformed-sidecar branch (`:920`) still reaches 502 when the artifact
  exists — a malformed body is not a miss.
- A virtual repository whose later member holds the coordinate now serves it.
  If that is reachable in a unit or integration test, assert it; if it needs the
  compose stack, say so and do not claim a result you did not observe.
- `CHANGELOG.md`: one `### Fixed` line. An operator can observe this — a virtual
  Maven repository starts resolving coordinates only a later member holds.
