# Artifact lifecycle and content storage

hort separates **artifact lifecycle state** from **artifact bytes**. Contributors need to preserve this distinction when changing ingestion, scanning, policy evaluation or download behavior.

## Domain events and projections

Artifact lifecycle transitions are recorded as domain events. Mutable artifact rows are derived projections of this event history. This does **not** mean every repository configuration or identity record is event-sourced: those use conventional CRUD models.

Per-stream positions support optimistic concurrency. Global event positions are useful for ordering and processing, but are **not guaranteed to be gapless or to imply commit visibility**. Consumers must not build correctness assumptions from a numeric high-water mark alone.

## Content-addressed storage

Artifact bytes are addressed by SHA-256. The storage port accepts streaming input and returns the computed digest and size. It can deduplicate identical content without implying that every artifact referencing the blob owns an independent copy.

The storage backend is selected for the deployment (filesystem or S3-compatible object storage), **not per repository**. Do not add `storage.path` to repository definitions: the setting is being deprecated and does not select a repository-specific physical blob location.

## Boundaries to preserve

- Registry protocol handlers should use application use cases rather than directly mutate projections or blobs.
- Content deletion must account for all referencing artifacts; do not equate deleting an artifact reference with deleting the underlying blob.
- Scanning and retention run in separate worker processes. A request path must not assume scanner tools are available inside the API server.
- Event consumers and notification delivery have separate retry and ordering concerns; avoid describing delivery as exactly-once.

## Where to read deeper

The source documents [Event Sourcing](https://github.com/project-hort/hort/blob/main/docs/architecture/explanation/event-sourcing.md), [Content-Addressable Storage](https://github.com/project-hort/hort/blob/main/docs/architecture/explanation/cas-storage.md), and [Event Notifications](https://github.com/project-hort/hort/blob/main/docs/architecture/explanation/event-notifications.md) contain implementation-level details. Treat examples and historical decisions as context; review current Rust types when changing behavior.
