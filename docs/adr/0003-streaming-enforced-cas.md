# 0003 — Streaming, enforced content-addressable storage

- **Status:** Accepted
- **Enforced by:** the `StoragePort` trait shape — `put(stream) -> PutResult` returns the content hash (plus size and a dedup flag); callers cannot supply a key. The architect anti-patterns *caller-supplied storage key* and *hardcoded storage path in handler* are review hard-blocks.
- **Supersedes:** —

## Context

The prototype let handlers construct storage keys from coordinates (`maven/<group>/<artifact>/<version>/…`) and write buffered byte blobs. Two problems: (1) the stored bytes were addressed by a logical path the caller chose, so there was no structural guarantee that identical content deduplicated or that a key matched its content; (2) buffering a whole artifact in memory to hash or store it does not survive multi-gigabyte OCI images.

## Decision

Storage is **content-addressable and enforced by the port signature**. The caller hands `put` a byte **stream** and receives back a `PutResult` — the caller never supplies the key:

```rust
fn put(&self, stream: Box<dyn AsyncRead + Send + Unpin>)
    -> BoxFuture<'_, DomainResult<PutResult>>;
```

`PutResult` carries the `ContentHash` (SHA-256 of the raw bytes), `size_bytes` (total bytes written), and a `created` flag that distinguishes a fresh write (`true`) from a deduplicated no-op (`false`).

SHA-256 is computed **incrementally** as chunks flow through `put`; a 2 GB image uses ~64 KB of memory, not 2 GB. `get(hash)` returns a stream too, so download handlers pipe straight to the HTTP response without buffering. Logical coordinates live only in the index/metadata layer; the bytes always live at their content hash.

## Consequences

- Deduplication is automatic and structural: identical content has identical keys.
- It is impossible by construction to store bytes under a key that does not match their hash, or to inject a caller-chosen path into storage.
- Memory use is bounded and independent of artifact size.
- Format handlers that think in coordinates must translate to/from content hashes at the index layer; they cannot pass a path to storage.

## Alternatives considered

- **`put(key, bytes)` (caller supplies key + buffered content).** Rejected on both axes: breaks the CAS guarantee and OOMs on large artifacts.
- **`put(bytes) -> ContentHash` (CAS but buffered).** Rejected: keeps the CAS guarantee but still buffers the whole artifact in memory; the streaming form is strictly better at no correctness cost.

## References

- `crates/hort-domain/src/ports/` — the `StoragePort` trait.
- `crates/hort-adapters-storage/` — filesystem/S3 implementations.
- The architect skill → Content-Addressable Storage section and the anti-patterns *caller-supplied storage key*, *hardcoded storage path in handler*.
