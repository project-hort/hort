# hort-http-oci — OCI Distribution Spec HTTP Adapter

## Layer

Inbound HTTP — per-format adapter crate. No `hort-adapters-*`, `sqlx`, or
`reqwest` dependency (ADR 0008). Requires >= 85% coverage.

## Responsibility

Serves the OCI Distribution Spec v1.1 under `/v2`: version check, blobs,
manifests, tag listing, catalog, chunked upload, and referrers.

## Ports

- **Implements:** none — an inbound HTTP adapter.
- **Consumes:** `IngestUseCase` (`RegisterExistingCasBlobRequest`,
  `VerifiedIngestRequest`), `RepositoryAccessUseCase`/`AccessLevel`,
  `ArtifactUseCase`, `ArtifactGroupUseCase`, `ContentReferenceUseCase`,
  `OciTokenExchangeUseCase`, `OciUploadSessionUseCase`,
  `PatValidationUseCase`, `PrefetchUseCase`, `RefUseCase`,
  `RefcountReconcileUseCase`.

## Key types

- `oci_routes(ctx)` / `oci_routes_with_config(...)` — route table builders.
- `config::OciHttpConfig`, `error::OciError` — re-exported public types.
- Public submodules: `blobs`, `catalog`, `config`, `coords`, `error`,
  `manifests`, `manifests_write`, `middleware`, `referrers`, `tags`,
  `upload_session`, `uploads`, `v2_auth`, `version`.

## Rules

- ADR 0008: no `hort-adapters-*` / `sqlx` / `reqwest`; use-case-only data
  access.
- Protocol correctness is judged against the OCI Distribution Spec v1.1, not
  the pre-existing implementation. The `/v2/auth` bearer-token
  challenge/exchange flow follows ADR 0012.
