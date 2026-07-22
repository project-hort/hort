# hort-adapters-provenance-cosign-key — Keyed Cosign Provenance Adapter

## Layer

Outbound adapter — the leanest of the provenance adapters: no `hort-app`
dependency and no network stack of any kind (deps are `hort-domain`,
`serde`, `serde_json`, `tracing`, `p256`). Requires >= 85% coverage.

## Responsibility

Implements the `"cosign-key"` keyed provenance backend (ADR 0039):
verifies an operator-pinned-public-key ECDSA signature (legacy
`simplesigning`, or cosign-v3-keyed Sigstore-v0.3-bundle/DSSE carriage) and
binds the signed digest to the actually-served artifact manifest digest,
catching image re-tag attacks. Strictly more offline than the sigstore
adapter — no network, no Fulcio/Rekor/TUF at all, by design (a smaller
advisory surface on the keyed path).

## Ports

- **Implements:** `ProvenancePort` (`CosignKeyVerifier` — `verify`,
  `health_check`).
- **Consumes:** none — zero `hort-app` dependency, nothing consumed.

## Key types

- `CosignKeyVerifier` — `from_pem_keys(pems: &[String]) ->
  DomainResult<Self>`, `key_count()`.
- Re-exports `hort_domain::entities::scan_policy::COSIGN_KEY_BACKEND`.

## Rules

- ADR 0039's two mandatory checks, both required for either carriage
  format: digest-bind (re-tag defense) must run **before** ECDSA verify.
  An empty `simplesigning` payload naming a different digest than the one
  being served must be `Rejected`, never `Verified` — directly tested.
