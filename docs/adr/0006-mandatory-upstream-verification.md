# 0006 — Mandatory upstream checksum verification

- **Status:** Accepted
- **Enforced by:** pull-through ingest flows through `IngestUseCase::ingest_verified`; checksum verification is a type-system invariant, not an operator opt-in. A `ChecksumMismatch` rejects the artifact before it is stored. The architect anti-pattern *missing `verify_upstream_checksum` in a new format module* is a review hard-block.
- **Supersedes:** —

## Context

A pull-through cache that stores whatever an upstream returns is a supply-chain hole: a compromised or MITM'd upstream response gets cached and served to every downstream consumer as if it were authentic. The prototype treated checksum verification as optional/per-format and inconsistent. For a security-positioned registry, "we cached what we got" is not acceptable.

## Decision

**Every** pull-through fetch verifies a checksum before the bytes are stored, and the requirement is **not an operator opt-in** — a format that cannot verify cannot proxy. Verification uses the protocol-native digest where one exists (OCI content descriptor digest, npm `dist.integrity`, PyPI `digests.sha256`, Cargo `cksum`, Maven `.sha256` sidecar, Helm `index.yaml` digest, etc.).

Verification produces a domain event: `ChecksumVerified` on success, `ChecksumMismatch` on failure. A `ChecksumMismatch` **rejects the artifact immediately** — do not store, do not quarantine, do not scan. Ingest is funnelled through `IngestUseCase::ingest_verified` so the verification cannot be skipped by a code path.

## Consequences

- Adding a new format requires implementing its checksum source; a format with no verifiable digest cannot be a proxy format. This is a deliberate, permanent gate on format support, not a deferred task.
- Verification is structural (type-system / single ingest entry point), not a runtime flag an operator can disable.
- A tampered or corrupted upstream response is rejected at the door, never cached.

## Alternatives considered

- **Operator-toggleable verification (per-repo "verify upstream" flag).** Rejected: makes the secure posture optional, and the insecure setting is exactly the one an attacker (or a harried operator) benefits from. No opt-out.
- **Best-effort verification (verify when a digest is conveniently present, skip otherwise).** Rejected: "skip otherwise" is the hole; a format that cannot verify is not allowed to proxy at all.

## References

- `crates/hort-app/src/use_cases/ingest_use_case.rs` — `ingest_verified`.
- `crates/hort-domain/src/events/` — `ChecksumVerified` / `ChecksumMismatch`.
- The architect skill → Upstream Checksum Verification table; anti-pattern *missing `verify_upstream_checksum`*.
