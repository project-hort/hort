# hort-adapters-storage — Content-Addressable Storage Adapters

## Layer

Outbound adapter — no `hort-app` dependency (leaf adapter over
`hort-domain` + `hort-config`). Requires >= 85% coverage (integration tests
against real backends).

## Responsibility

Implements enforced CAS: streaming `put()` with SHA-256 computed
incrementally, filesystem and S3 backends, plus filesystem-backed stateful
upload staging and metadata mirroring.

## Ports

- **Implements:** `StoragePort` (`FilesystemStorage`, `ObjectStoreStorage`),
  `StatefulUploadStagingPort` (`FilesystemStatefulUploadStaging`),
  `MetadataMirrorStore` (`FilesystemMetadataMirror`,
  `ObjectStoreMetadataMirror`).
- **Consumes:** none — pure leaf adapter.

## Key types

- `FilesystemStorage`, `ObjectStoreStorage`.
- `FilesystemMetadataMirror` / `ObjectStoreMetadataMirror`.
- `build_s3_object_store` / `build_s3_storage`, `SseMode`, `S3StorageOpts`.

## Rules

- `StoragePort::put` is streaming CAS — the caller supplies a stream, never
  a key; SHA-256 is computed incrementally (ADR 0003).
- S3 client construction routes through
  `extra_ca::apply_to_object_store_options` (ADR 0010's extra-CA posture).
- **Doc-vs-implementation gap, worth knowing before extending this crate:**
  the crate description advertises S3/GCS/Azure support and
  `ObjectStoreStorage` is generically backend-agnostic (`Arc<dyn
  ObjectStore>`), but the workspace-pinned `object_store` dependency only
  enables `features = ["aws"]`, and this crate ships only an S3 builder
  (`AmazonS3Builder`). GCS/Azure are not actually wired today despite being
  named in the crate description — do not assume they work without adding
  the builder + feature first.
