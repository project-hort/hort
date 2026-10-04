# 259 — Every rejection the apply can reach must be reachable before the first write

**Issue:** #334 · **Branch:** `agent/334-struktur-332`
**Governing decisions:** ADR 0015 (apply-time rejection is the structural
close) · ADR 0016 (fail-closed apply-time rejection, never a degraded
runtime path).

## Why

The apply pipeline validates in stages and writes between them, so **any**
late-stage rejection leaves a partial apply. The operator's atomic-looking
`apply` is not atomic across the security boundary: the reachable bad state
is a tightening grant refused while a loosening policy has already landed.

Two instances, two different causes.

**F15-1 — the rule exists and the preflight does not collect it.** The
pre-write validation enumerates the rules it consumes
(`crates/hort-app/src/use_cases/apply_config_use_case.rs:1104-1128`):
`TrustUpstreamPublishTimeRequiresScanBackends`,
`PrefetchMaxAgeDaysNotImplemented`,
`PrefetchTriggerRequiresVersionDiscovery`, `ProvenanceConfig`,
`RepoStorageBackendMismatch`, `ScanBackendCapability`,
`RetentionUnusedForNotImplemented` — plus `SaIssuerFk` (:985) and
`UnderConstrainedFederatedIdentities` (:1011) handled separately.
`LinterRule::PermissionGrant` — row 8, the grant lint — is in none of them.
Its rules (single-claim, wildcard non-admin, high-privilege direct user,
reserved claim collision) run only inside `apply_permission_grants`, after
the repository, policy and mapping writes.

That it *can* run earlier is already proven: `LinterRule::PermissionGrant`
exists in the offline `StaticConfigValidator` for `validate-config`, and
`static_validator_row8_and_apply_grant_linter_agree` shows the offline
verdict agrees with the real apply path and is invariant to the resolved
id values.

**F15b-3 — the rule exists only inside a domain constructor.** mTLS pair
completeness, any TLS field on a plaintext `http://` URL, and pin hex shape
are checked solely in `RepositoryUpstreamMapping::new`
(`crates/hort-domain/src/ports/repository_upstream_mapping_repository.rs:301-376`).
GitOps reaches that constructor only in Stage 3
(`crates/hort-app/src/use_cases/apply_config_use_case/upstream_mappings.rs:54-67,359-400`),
after the Stage 1 and Stage 2 writes. The YAML validator has no rule for any
of it, so preflight and `validate-config` both accept a bundle that Stage 3
will reject — and a policy loosened in the same bundle has already been
written when it does.

## What to do

1. **Consume row 8 in the pre-write validation.** The rejection moves
   forward; the metric stays where it is. Row 8 deliberately emits no
   `hort_apply_config_linter_total` from the validator because apply keeps
   its own load-bearing emission on the port-built desired set — that split
   is correct and must survive.
2. **Add a preflight row for the TLS combinations** that mirrors the
   constructor's rejection set exactly: half an mTLS pair, any TLS field
   with a plaintext URL, malformed pin. Custom CA alone, pin alone and the
   full HTTPS combination stay accepted. The constructor keeps enforcing the
   row invariant; the new row makes the same verdict reachable before a
   write.
3. **Turn the enumeration into a checked claim.** The comment listing the
   collected rows is the artifact on which row 8's absence became visible,
   and a comment cannot fail. Add a test in the shape of
   `static_validator_row8_and_apply_grant_linter_agree`: for each rejecting
   stage, the preflight must produce the same rejection. A stage that gains
   a rejection the preflight does not know about has to fail that test.

## Explicitly out of scope

- No transaction spanning the apply stages, and no rollback machinery. The
  fix is to reject before the first write, not to undo writes afterwards.
- No change to which configurations are rejected — only to when.
- No new operator-facing knob, and no bypass for either rule.
- The remaining stages' rejection sets are inventoried by the new test; any
  further gap it exposes is reported on #334, not fixed here.

## Acceptance

- A bundle carrying a grant row 8 rejects **and** a loosening scan policy
  leaves the policy projection unchanged: nothing is written.
- The same for an invalid TLS combination on a changed upstream mapping.
- `validate-config` and the boot preflight reject both bundles identically.
- The agreement test exists for both stages and fails if a stage rejection
  is not reachable from the preflight.
- The apply-path metric emission for row 8 is unchanged, and the validator
  still emits none.
- Gate green: `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace`, `cargo-audit audit
  -D warnings`, `cargo-deny check`.
