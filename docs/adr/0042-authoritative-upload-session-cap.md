# 0042 — Authoritative live-session upload cap (self-pruning session set)

- **Status:** Accepted
- **Relates to:** [0008](0008-per-format-adapter-free-http-crates.md) (the cap
  primitive stays adapter-free — it touches only `AppContext` + `EphemeralStore`);
  the `StatefulUpload` capability group (OCI blob upload, Git LFS).
- **Closes:** issue #9 — the per-`(repo, principal)` upload-session cap leaked on
  abandoned uploads.

## Context

The per-`(repo, principal)` OCI blob-upload-session cap
(`HORT_OCI_MAX_SESSIONS_PER_PRINCIPAL`) was a **free-floating integer counter** in
the `EphemeralStore` durable class (`oci:session_count:{repo}:{principal}`),
decoupled from the session records:

- `try_increment_counter` **refreshed the counter's TTL on every increment**, so
  during a retry burst the counter never idled out.
- The **abandoned-upload path** — `POST .../blobs/uploads/` then no final `PUT` and
  no `DELETE` — **never decremented** it (only explicit finalize/cancel did).

The counter therefore climbed monotonically to the cap and **raising the cap could
not clear it** — a persistent per-principal denial of upload (verified against
`crates/hort-http-oci/src/upload_session.rs`).

The issue's first-proposed fix ("have `staging_sweep` decrement per reaped
session") is infeasible: the sweep acts on a session only once its ephemeral record
is already gone, and that record is the *only* holder of `(repo, principal)` — so at
reap time the sweep has a bare `session_id` and cannot rebuild the counter key; a
`POST`-only abandon also writes no staging, so the sweep never enumerates it.

Constraints: `EphemeralStore` is a pure KV port — no prefix-scan, no per-key count,
silent TTL eviction; and `hort-app` must not depend on `hort-http-oci`.

## Decision

Replace the free-floating counter with an **authoritative, self-pruning live-session
set** — one serialized value per `(repo, principal)`, reconciled on every admit.

**Generic, format-parameterized primitive.** The cap lives in
`hort-http-core::upload_session_cap` (adapter-free — `AppContext` + `EphemeralStore`
only) and is parameterized by `format: &str`. OCI is the first consumer
(`format = "oci"`); Git LFS reuses it verbatim (`"lfs"`), with a disjoint keyspace
and metric series via the inline `format` token.

- **Keyspace:** `upload_sessions:{format}:{repo_id}:{principal_id}` (Durable class),
  replacing the removed `oci:session_count:` prefix in the `ephemeral_keyspace`
  registry.
- **Value:** `SessionSet { version, members: Vec<SessionMember{ id, created_at_ms }> }`
  (postcard); `version` mirrors the store version for CAS.
- **Admit** (on initiate — reconcile-and-check): a bounded get → prune → CAS loop.
  Prune members older than `session_max_age`; if the surviving count is `< cap`,
  push the new member and CAS; if `>= cap`, **reject with no write** — so a rejected
  admit never refreshes the set TTL, and the leak that made the old counter immortal
  is structurally gone. Loop exhaustion under pathological contention returns
  `AdmitOutcome::Contended`, mapped to a transient **503 + short `Retry-After`** —
  never fail-open, never a 500. Genuine store errors still propagate as `Err` → 500.
- **Release** (finalize success / declared-hash conflict / infra error / the new
  `DELETE`-cancel): remove the member by `id`; an already-pruned member is a no-op
  (no underflow).
- **Age-based pruning**, not record-existence — the set-value's own `created_at_ms`
  is the prune signal, so it catches both `POST`-only and `PATCH`ed abandons with no
  per-session record reads.

**Secondary decisions (in scope):**

- `OCI_SESSION_TTL` (hardcoded 3600 s) becomes the config knob
  `HORT_OCI_SESSION_MAX_AGE_SECS` (default 3600), used as both the set TTL and the
  age-prune threshold.
- The cap-exceeded 429 returns a **short bounded `Retry-After` (15 s)**, not the
  full session max-age — the cap is a transient live-count, not a per-session hold.
- Add the OCI-spec-standard **`DELETE /v2/:repo_key/blobs/uploads/:session_id`**
  cancel route (previously absent), giving well-behaved clients immediate release.
- Cap metrics renamed `hort_oci_session_*` → format-labelled `hort_upload_session_*`
  (`_reconcile_pruned_total`, `_cap_rejections_total`); `docs/metrics-catalog.md`
  updated in the same change. No `principal` label (cardinality); `format` is a
  closed set.

## Consequences

- The live count can never climb past reality: abandoned members age out on the next
  admit, so the cap self-heals — without a sweep, a record dependency, or a
  decrement the sweep cannot perform.
- **Trade-off (accepted):** a *single* session open longer than `session_max_age` is
  pruned from the set while still uploading, so the cap can soft-over-admit by the
  number of such long-runners. The cap is a per-principal DoS guard, not a hard
  quota; a `> session_max_age` single-blob upload is rare, and over-admitting one
  slot is harmless. A follow-up may refresh `created_at_ms → last-activity` on
  `PATCH` if real long-runners appear (one set-write per chunk) — out of scope here.
- New leak visibility: `hort_upload_session_reconcile_pruned_total` is the first
  signal of aged-out slots (nothing previously revealed a climbing counter).
- No `hort-domain` / adapter / `EphemeralStore`-trait changes.

## Alternatives considered

- **Sweep-decrements-per-reaped-session** (issue #9's first proposal) — infeasible:
  the sweep has no `(repo, principal)` at reap time and never sees `POST`-only
  abandons.
- **Raise / exempt the cap** — treats the symptom; the leaked counter climbs past
  any fixed ceiling and cannot touch the abandon path. (The cap raise also conflated
  with the *actual* first-party-CI push blocker, which was the per-IP rate limiter
  globalized by an XFF-collapse — a separate issue.)
- **Record-existence pruning** — needs N record-GETs per admit and misses
  `POST`-only abandons (no record to check).
