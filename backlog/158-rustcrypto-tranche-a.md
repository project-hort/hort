# 158 — RustCrypto tranche A: coupled major bump (argon2 / password-hash / rand_core / p256 / sha-family / hmac)

**Contract:** this file. The RustCrypto ecosystem's new generation went stable;
tranche A is everything not type-coupled to the `sigstore` crate's pins.
(x509-cert 0.3 / const-oid 0.10 are tranche B, blocked until a sigstore release
builds on x509-cert ^0.3 — OUT of scope here.)

## The coupled set — bump together on ONE branch, no partial merge

| dep | from → to | where |
|---|---|---|
| `argon2` | 0.5 → 0.6 | credential store (Argon2id) |
| `password-hash` | 0.5 → 0.6 | same (workspace) |
| `rand_core` | 0.6 → 0.10 | `hort-adapters-provenance-cosign-key` |
| `p256` | 0.13 → 0.14 | `hort-adapters-provenance-cosign-key` |
| `sha2` / `sha1` / `md-5` | 0.10 → 0.11 | workspace (CAS path — see review lens) |
| `hmac` | 0.12 → 0.13 | workspace (moves with the digest-0.11 family) |

Scoped `cargo update` for the set + pulled-in transitives only — no unrelated
lockfile drift. Duplicate majors in the graph are expected and acceptable
(sigstore internally keeps the old generation; the cosign-key adapter has no
`sigstore::` type interop — verified, no `sigstore::` imports there).

If any member of the set cannot land green, STOP and report — no partial merge.

## Per-bump behaviour/security review (MANDATORY — the point of this ticket)

Adapting to a new API must produce **identical observable behaviour**. For EACH
crate, read the changelog and confirm no silent change to:

- validation strictness, default algorithms, RNG source/seeding,
  password-hash parameters/verification, or error surfaces hort branches on;
- **Argon2id parameters (memory/iterations/parallelism) and the stored-hash
  format** — a change here silently invalidates existing credentials. Existing
  stored hashes MUST still verify under the bumped stack (cover with a test
  against a fixture hash produced by the old stack if none exists). The
  `no_bcrypt` structural guard stays green.
- **SHA-256 CAS digests**: sha2 0.11 must produce byte-identical digests; the
  streaming `Digest` trait plumbing changes, so the CAS/`StoragePort`
  incremental-hash path and stored-hash comparisons are re-verified by the
  existing round-trip tests — not by inspection alone.

Record per crate in the report: "adapted to new API, behaviour identical" or
flag the deviation with its disposition.

## Gate (evidence in the report — one-shot log capture, `set -o pipefail`)

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace` (structural guards `no_bcrypt`,
  `streaming_metadata_port`, provenance-verify suites run here)
- `cargo-audit audit -D warnings` and `cargo-deny check`
- attribution regenerated in the same change
  (`scripts/regenerate-attribution.sh`, commit `THIRD-PARTY-LICENSES.{md,json}`)
- every `# AUDIT-ONLY` marker in `.cargo/audit.toml` re-checked against the
  shifted graph (`cargo tree -i <crate> -e normal`); if a marked crate became
  active-graph-reachable, say so in the report (do not edit deny.toml silently)

## Acceptance

All six rows bumped together, full gate green, structural guards intact,
per-crate review recorded, attribution regenerated, no unrelated lockfile
drift.
