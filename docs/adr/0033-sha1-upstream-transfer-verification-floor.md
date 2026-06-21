# 0033 — SHA-1 as an upstream transfer-verification floor

- **Status:** Accepted — shipped (Maven pull-through;
  `HashAlgorithm::Sha1` + `IngestUseCase::ingest_verified_sha1`).
- **Enforced by:** `HashAlgorithm::Sha1`
  (`crates/hort-domain/src/types/checksum.rs`, `hex_len() == 40`,
  serde-lowercase) is valid ONLY as a
  `VerifiedIngestRequest::UpstreamPublished` transfer target — never a
  `ContentHash` (CAS key) and never produced by a `ProtocolNative` request
  (a doc/review invariant, test-pinned in `checksum.rs` + `ingest_use_case.rs`);
  the Maven serve-path pull-through tries `.sha512` → `.sha256` → `.sha1`
  (`crates/hort-http-maven/src/upstream_pull.rs`) so SHA-1 is the *floor*, used
  only when nothing stronger is published; `ingest_verified_sha1`
  (`crates/hort-app/src/use_cases/ingest_use_case.rs`) computes SHA-1 over the
  streamed bytes alongside the CAS SHA-256 and rolls back on mismatch.
- **Supersedes:** —
- **Amends:** the *authority* of the no-SHA-1 rule for the Maven pull-through
  surface — see "Amendment to the no-SHA-1 rule" below.
- **Relates:** [0006](0006-mandatory-upstream-verification.md) (whose core
  "every pull-through verifies; a format that cannot verify cannot proxy" is
  **upheld** — the SHA-1 floor *is* the verification that lets Maven proxy),
  [0010](0010-tls-builder-no-insecure-knobs.md) (TLS is the real
  transport-integrity control), [0032](0032-maven-gradle-multi-file-handler.md).

## Context

ADR 0006 makes upstream-checksum verification a type-system invariant: every
pull-through fetch verifies a published digest before storage, with **no
operator opt-in** and **no soft-fail**. The `add-a-format-handler.md` guide
encodes a companion rule for the implementer: *"SHA-1 fallback is not added.
SHA-1 is collision-broken (SHAttered, 2017) and is not a supported verification
algorithm."* That rule was written for, and is correct for, **npm**: npm
publishes `dist.integrity` (Subresource Integrity — SHA-512) alongside the
legacy `dist.shasum` (SHA-1), so accepting SHA-1 for npm would be a *needless
downgrade from an available stronger signal*.

That rationale **reverses on the Maven surface.** Maven Central — and every
Maven-layout repository (Nexus, Artifactory, the Gradle plugin portal) —
guarantees only the `.sha1` (+ `.md5`) sidecar on every artifact. SHA-256 /
SHA-512 sidecars are per-publisher and **absent on the overwhelming majority of
artifacts**, including ubiquitous, current ones (Guava, Spring, Jackson, Apache
Commons, even 2024 releases — empirically verified). On Maven, SHA-1 is the
**only universally-available protocol-native digest**, not a downgrade from a
stronger one. Under the npm-shaped rule, Maven would be **unproxiable** — which
contradicts ADR 0006's own goal (a format that *can* verify, against the digest
its protocol actually publishes, should be allowed to proxy).

The choice is therefore between: (a) Maven cannot be a proxy format at all, or
(b) Maven verifies the upstream transfer against the digest the Maven ecosystem
universally publishes — SHA-1 — while never weakening the CAS guarantee or any
format that has a stronger signal. This ADR adopts (b), bounded precisely.

## Decision

SHA-1 is permitted **strictly as an upstream transfer-verification floor**, and
only for formats whose upstream guarantees only SHA-1 (Maven). Concretely:

1. **Floor, with opportunistic upgrade.** The Maven serve-path pull-through
   fetches the checksum sidecar **preferring strength**: `.sha512` → `.sha256`
   → `.sha1`. The strongest sidecar that fetches AND parses to a valid digest
   of the matching shape wins; an absent / unfetchable / malformed stronger
   sidecar falls through to the next. SHA-1 is used **only when nothing
   stronger is available** — it is the floor, not the default. All three absent
   or malformed → `502` (unproxiable per ADR 0006 — no soft-fail, no
   store-without-verify).

2. **Never a CAS key.** The content-addressable storage key is **always
   SHA-256**, computed independently over the streamed bytes, regardless of
   which sidecar verified the transfer (ADR 0003). `HashAlgorithm::Sha1` is
   valid solely as a `VerifiedIngestRequest::UpstreamPublished` transfer target;
   it is never a `ContentHash` and never produced by a `ProtocolNative`
   request. This is a hard, test-pinned invariant.

3. **Never a relaxation for a format with a stronger signal.** The npm
   `dist.shasum` no-SHA-1 rule is **unchanged**: npm has `dist.integrity`
   (SHA-512), so for npm SHA-1 remains a forbidden downgrade. The floor is a
   per-format, upstream-forced acceptance, scoped to formats whose protocol
   publishes nothing stronger.

4. **MD5 is not a verification algorithm.** `.md5` sidecars are *served*
   on demand (Maven clients request them), but Hort never *verifies* against
   `.md5` — it is weaker than SHA-1 and out of the preference list entirely.

5. **New domain surface.** This adds `HashAlgorithm::Sha1`
   (`hex_len() == 40`, serde-lowercase, `UpstreamPublishedChecksum::new`
   validates 40-char lowercase hex) and `IngestUseCase::ingest_verified_sha1`
   (a `Sha1HashingRead` wrapper computes SHA-1 over the streamed bytes
   alongside the CAS SHA-256, compares to the declared hex, and on mismatch
   rolls back the CAS blob → `DomainError::Conflict` with a `ChecksumMismatch`
   audit event — identical posture to the existing `ingest_verified_sha512`
   path). The SHA-1-floor verification logs an `info!` audit breadcrumb (the
   transfer was verified against the *weaker* floor), never an `err`.

## Threat model

This section is self-contained and auditable on its own — it does not assume the
reader has the Maven design context.

- **SHA-1 is cryptographically broken for collision resistance.** A practical
  chosen-prefix collision has existed since SHAttered (2017) and is cheaper
  every year. An adversary who can choose *both* artifacts can construct two
  distinct byte streams with the same SHA-1.

- **What the floor actually defends.** The SHA-1 transfer-verification floor
  catches **transport corruption** (a truncated / bit-flipped download) and
  **accidental or casual tampering** (a non-cryptographic mangling of the
  bytes in transit or at a careless mirror). It does **not** defend against a
  resourceful adversary who controls the upstream response and can serve a
  matching-malicious artifact + a matching-malicious `.sha1`: such an adversary
  can equally serve a matching `.sha512`, so the floor is not the control that
  stops them. SHA-1 verification is a **bounded, format-forced acceptance**,
  not a claim that SHA-1 is cryptographically adequate.

- **The real transport-integrity control is TLS.** Pull-through fetches run
  over TLS verified against the system trust store + `HORT_EXTRA_CA_BUNDLE`
  (ADR 0010 — there is no insecure-TLS knob). TLS authenticates the upstream
  and protects the bytes (and the sidecar) end to end against an
  in-the-middle attacker. The checksum floor is a *defence-in-depth* layer on
  top of TLS, not a substitute for it. The opportunistic upgrade means that
  whenever the upstream *does* publish a stronger digest, Hort uses it — so the
  floor is the *worst* case, taken only when the ecosystem offers nothing
  better.

- **This matches what every Maven client already does.** Maven Resolver (and
  Gradle) verify downloads against the same `.sha1` sidecar — a Hort proxy that
  verifies the SHA-1 floor is *no weaker* than direct upstream consumption, and
  strictly stronger when it upgrades to `.sha512`/`.sha256` and when it adds
  the TLS-authenticated channel a bare `wget` of a `.jar` would not have. The
  floor does not introduce a risk that the unproxied workflow lacks; it
  reproduces the ecosystem's own integrity contract behind Hort's TLS and CAS
  guarantees.

- **The fall-through is not a new attack.** A corrupt / malformed *stronger*
  sidecar (e.g. an empty `.sha512`) falls through to the next digest rather
  than blocking the proxy. An attacker who can corrupt the upstream's `.sha512`
  over the TLS channel can equally serve a matching-malicious `.sha512`, so
  forcing a downgrade to the floor is not a capability the attacker gains from
  this behaviour — it only keeps a valid floor reachable when a stronger
  sidecar is merely broken.

## Amendment to the no-SHA-1 rule

ADR 0006's authority is **upheld, not weakened**: every Maven pull-through still
verifies a published digest before storage, with no opt-in and no soft-fail —
the SHA-1 floor *is* that verification. What this ADR amends is the *authority*
of the companion implementer rule ("SHA-1 fallback is not added") **for the
Maven pull-through surface**: there, SHA-1 is not a fallback from a stronger
signal but the only universal one, so it is permitted as the floor. The rule
remains in force wherever a stronger signal exists (npm `dist.shasum`). The
`add-a-format-handler.md` verification matrix now records all three cases
(protocol-native, upstream-published-metadata, and the SHA-1 floor) so an
implementer reads the scoped exception rather than the absolute prohibition.

## Consequences

- Maven becomes proxiable under ADR 0006 without a soft-fail or an
  "unverified proxy" path: the floor is a real, enforced verification.
- The CAS guarantee is untouched — every stored blob's key is SHA-256,
  independent of the transfer floor. A SHA-1-verified pull and a SHA-512-verified
  pull of the same bytes produce the same CAS key.
- The exception is narrow and structural: SHA-1 is constrained at the type level
  to the transfer-target position, and the preference order makes it the
  last-resort digest. A future format that also publishes only SHA-1 (or only a
  weaker digest) must re-run this analysis in its own ADR — the floor is not a
  blanket licence to verify against weak digests.
- The audit `info!` on the floor path makes "this transfer was verified against
  the weaker floor" visible to operators without elevating it to an error.

## Alternatives considered

- **Refuse Maven as a proxy format (apply the npm rule verbatim).** Rejected:
  it makes the flagship Maven pull-through use case impossible, even though Maven
  *does* publish a protocol-native digest on every artifact — contradicting
  ADR 0006's intent ("verify against the digest the protocol publishes").
- **Verify against `.md5` when `.sha1` is absent.** Rejected: MD5 is weaker than
  SHA-1 and `.sha1` is genuinely universal on Maven, so there is no real case
  where MD5 is the only option. MD5 is served, never verified.
- **A soft-fail "skip verification when no checksum is published" path.**
  Rejected outright — this is exactly the hole ADR 0006 closes. The floor is the
  opposite: it *adds* a verification that lets Maven proxy, rather than skipping
  one.
- **Allow operators to opt into SHA-1 per repo.** Rejected: ADR 0006 forbids
  making the secure posture optional. The floor is a fixed, format-scoped
  behaviour, not a knob — there is no setting that turns verification off.

## References

- `crates/hort-domain/src/types/checksum.rs` — `HashAlgorithm::Sha1` +
  `UpstreamPublishedChecksum` (CAS-key prohibition documented + test-pinned).
- `crates/hort-app/src/use_cases/ingest_use_case.rs` — `ingest_verified_sha1`
  + `Sha1HashingRead` (the SHA-1 transfer-verify ingest path).
- `crates/hort-http-maven/src/upstream_pull.rs` — the
  `.sha512` → `.sha256` → `.sha1` strength-preferring negotiation +
  `NoChecksumSidecar` (unproxiable → 502).
- ADR 0006 (mandatory upstream verification), ADR 0010 (no insecure-TLS knobs),
  ADR 0032 (Maven/Gradle multi-file handler).
