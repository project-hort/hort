# hort-domain — Domain Layer

## Layer

Domain — pure Rust, zero I/O. No `axum`, no `sqlx`, no `reqwest`, no async
runtime dependency (`tokio` is present only for its `io-util` feature, used
for `AsyncRead` trait bounds on port signatures, not for spawning or I/O).
Requires 100% test coverage (CLAUDE.md Test Coverage Tiers) — this crate is
the security boundary for the artifact lifecycle.

## Responsibility

Defines the artifact-registry domain model: entities and aggregates
(`Artifact`, `Repository`, `User`, `ArtifactGroup`, service accounts, RBAC),
the immutable domain-event vocabulary for the event-sourced artifact
lifecycle (`ArtifactIngested`, `ArtifactQuarantined`, `ScanCompleted`,
`ArtifactPromoted`, and the rest — `src/events/`), pure policy-evaluation
functions (quarantine/scan/CVE/license/age gating, curation, retention —
`src/policy/`, `src/retention/`), and the tamper-evident per-stream event
chain (`src/events/chain.rs`). Nothing in this crate performs I/O; every
state transition is a pure function from current state + event to next
state.

## Ports

- **Declares** (does not implement or consume): the ~60 outbound port
  traits under `src/ports/` — `ArtifactRepository`, `StoragePort`,
  `EventStore`, `ScannerPort`, `FormatHandler`, `TaskHandler`, and every
  other trait an adapter crate implements. The domain layer is the sole
  origin of these contracts; it has no dependency on any implementation of
  them.

## Key types

- `events::domain_event` — the per-aggregate event enums and `PersistedEvent`
  envelope.
- `events::chain` — `event_hash = SHA-256(canonical_event_bytes)`, the
  tamper-evident chain primitive.
- `ports::storage::StoragePort` — streaming CAS: `put(stream) -> ContentHash`,
  caller never supplies a key (ADR 0003).
- `ports::event_store::EventStore` — backend-agnostic append/read/subscribe
  contract (ADR 0004).
- `ports::format_handler::FormatHandler` / `VersionDiscovery` — the WASM
  format-module contract.
- `policy::scan::{DefaultPolicy, evaluate_scan_result}` — quarantine/release
  gating.
- `types::checksum`, `types::sbom`, `types::finding` — value types shared
  across every layer above this one.

## Rules

- Zero I/O, enforced by review and by the crate's own dependency list (no
  `axum`/`sqlx`/`reqwest`; `tokio` is `io-util`-only). Any adapter-shaped
  dependency here is a layering violation.
- 100% branch coverage required — every match arm, error path, and boundary
  condition in this crate needs a test (CLAUDE.md Test Coverage Tiers).
- `unsafe_code = "forbid"` workspace-wide (root `Cargo.toml`); this crate has
  no exemption.
- Port trait signatures are the contract every adapter crate is bound to —
  changing one here is a cross-cutting change, not a local edit.
