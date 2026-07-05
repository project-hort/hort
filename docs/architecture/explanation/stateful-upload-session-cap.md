# Stateful-upload session cap

hort bounds the number of concurrently-open stateful upload sessions per
`(repository, principal)` — a per-principal denial-of-service guard for the
`StatefulUpload` formats (OCI blob upload, Git LFS). See
[ADR 0042](../../adr/0042-authoritative-upload-session-cap.md) for the decision and
its history.

## The primitive

`hort-http-core::upload_session_cap` is a generic, **format-parameterized** cap. It
stores one **authoritative, self-pruning set of live sessions** per
`(repo, principal)` in the `EphemeralStore` Durable class:

- key `upload_sessions:{format}:{repo_id}:{principal_id}` — the `format` token
  (`oci`, `lfs`, …) keeps each format's cap in a disjoint keyspace, so an `oci`
  admit never counts against an `lfs` cap on the same `(repo, principal)`;
- value `SessionSet { version, members: [{ id, created_at_ms }] }`.

It touches only `AppContext` + `EphemeralStore`, so it stays adapter-free
([ADR 0008](../../adr/0008-per-format-adapter-free-http-crates.md)).

## Admit and release

- **`admit(format, repo, principal, cap)`** — on session initiate. A bounded
  get → prune → CAS loop: prune members older than the session max-age, then admit
  if the surviving count is under the cap (push the member + CAS), else reject. A
  **rejected admit writes nothing**, so it never refreshes the set's TTL — the reason
  the old free-floating counter never idled out is structurally gone. Pathological
  CAS contention returns `Contended` → a transient `503`, never fail-open.
- **`release(format, repo, principal, session_id)`** — on finalize success,
  declared-hash conflict, infra error, and the `DELETE`-cancel route. Removes the
  member by id; an already-pruned member is a no-op.

## Why age-based pruning

Members age out by their own `created_at_ms` (threshold
`HORT_OCI_SESSION_MAX_AGE_SECS`, default 3600 s), not by checking whether the upload
record still exists. This catches **both** abandon shapes — a `POST` with no
`PATCH`/`PUT`, and a `PATCH`ed-then-abandoned session — with no per-session record
reads.

The trade-off: a single session that legitimately stays open past the max-age is
pruned while still uploading, so the cap can soft-over-admit by the number of such
long-runners. That is acceptable for a DoS guard (not a hard quota); if real
long-runners appear, a follow-up can refresh `created_at_ms → last-activity` on each
`PATCH`.

## Observability

- `hort_upload_session_reconcile_pruned_total{format, repo, result}` — aged-out
  members reclaimed per admit (the leak-visibility signal — nothing previously
  revealed a climbing counter).
- `hort_upload_session_cap_rejections_total{format, repo, result=over_cap}` — 429s
  from a full cap.

Neither carries a `principal` label (cardinality rule); `format` is a closed,
non-operator-influenced set.
