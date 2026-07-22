# hort-config — Gitops Configuration

## Layer

Config — zero-I/O YAML parsing, validation, and diff. Depends only on
`hort-domain` (also zero-I/O — reusing its `RepositoryFormat`,
`RepositoryType`, `ReplicationPriority`, etc. avoids a parallel enum
surface). Deliberately excludes `tokio`, `tracing`, `sqlx`, `axum`, and
`reqwest` — file-walking lives in `hort-server::gitops_boot`, tracing in
that boot caller, and persistence in `hort-app`'s `ApplyConfigUseCase`.
Requires >= 85% coverage (CLAUDE.md Test Coverage Tiers).

## Responsibility

Parses and validates the gitops-declared desired state: every YAML file
under `$HORT_CONFIG_DIR` carries a 4-field envelope (`apiVersion`, `kind`,
`metadata`, `spec`); this crate owns that envelope type plus one module per
`kind` (`repository.rs`, `service_account.rs`, `permission_grant.rs`,
`claim_mapping.rs`, `oidc_issuer.rs`, `scan_policy.rs`, `retention_policy.rs`,
`curation_rule.rs`, `exclusion.rs`). `desired.rs` runs the two-phase
parse-then-cross-validate pipeline (`DesiredState::parse_files` +
`.validate()`); `diff.rs` computes the `ApplyPlan` a caller applies against
current state. `PermissionGrant` and `ClaimMapping` reuse the CRUD diff
machinery; `ScanPolicy` and `Exclusion` are event-sourced and route through
the `ApplyEventSourcedKind` trait (implemented one layer up, in `hort-app`).

## Ports

- **Implements:** none — this crate has no port traits of its own; it
  produces plain validated value types (`DesiredState`, `ApplyPlan`) for
  callers to act on.
- **Consumes:** none — no outbound ports; it is a pure parse/validate/diff
  library.

## Key types

- `envelope::{Envelope, ApiVersion, Kind}` — the kind-agnostic wrapper every
  gitops YAML file parses into. `ApiVersion` accepts both
  `project-hort.de/v1` (current) and `project-hort.de/v1beta1` (supported,
  deprecated) — see issue #67.
- `desired::DesiredState` — the parsed, cross-validated snapshot of an
  entire config tree.
- `diff::ApplyPlan` — the create/update/delete plan a caller (`hort-app`)
  executes against current persisted state.
- `error::ParseError` / per-kind spec error enums — every failure mode is
  named and fails closed (e.g. `ParseError::UnsupportedApiVersion`).
- `extra_ca::ExtraTrustAnchors` — PEM-parsed extra CA bundle support
  (`HORT_EXTRA_CA_BUNDLE`, ADR 0010).

## Rules

- Zero I/O: no `tokio`, `tracing`, `sqlx`, `axum`, `reqwest` — enforced by
  review, since adding any would couple parsing/validation to a runtime and
  slow the unit tests.
- A YAML field that is accepted here but not enforced by the consuming use
  case (or rejected at apply time) is a blocking finding, not a partial
  feature (ADR 0015) — this crate is where that apply-time rejection is
  implemented for policy fields like `RetentionPolicy.max_age_days`.
- A new operator opt-in that could let untrusted input influence release-
  gate computation must be checked against every other such opt-in via the
  cross-opt-in interaction matrix before landing (ADR 0016) — the
  `trust_upstream_publish_time` x `scan_backends: []` collision is the
  worked example, and its apply-time rejection lives in this crate.
