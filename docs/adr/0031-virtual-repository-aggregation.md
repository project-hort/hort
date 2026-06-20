# 0031 — Virtual (aggregated) repository resolution

- **Status:** Accepted — shipped for **npm, PyPI, and Cargo** (serve-time index
  aggregation, first-authoritative download, write-rejection, and the apply-time
  lift are all in tree). OCI/Maven and other formats remain apply-rejected.
- **Enforced by:** the gitops apply-time linter (rejects a `type: virtual` repo whose
  `format` is not yet serve-supported, and rejects a member that is itself `Virtual`);
  two per-format dependency-confusion regression tests — *same-version* (a coordinate held
  in a higher-priority member is not replaced by a lower-priority member's released copy)
  and *new-version* (a name owned by a non-proxy member is not served from a proxy member,
  any version); the ADR 0021 read-handler review check (member resolution threads the
  caller).
- **Supersedes:** —
- **Relates:** [0007](0007-fail-closed-quarantine-release-predicate.md),
  [0008](0008-per-format-adapter-free-http-crates.md),
  [0015](0015-apply-time-linter-inert-fields-and-naming.md),
  [0016](0016-cross-opt-in-interaction-matrix.md),
  [0021](0021-read-handler-anonymous-by-default.md)

## Context

The `Virtual` repository type — one repository that aggregates several member
repositories behind a single URL — was scaffolded across every layer but the last:
the domain enum variant (`RepositoryType::Virtual`), the `virtual_repo_members` table
with a `priority` column (migration 002), the `get/add/remove_virtual_member` port and
its Postgres adapter (`repository_repo.rs:315-389`), the gitops `virtualMembers` field
with apply-time validation, and the apply path that persists members — all exist and
work. **Only serve-time resolution is missing.** The npm/PyPI/Cargo serve dispatch
groups `Virtual` with `Hosted` (`serve.rs` in each crate), so a virtual repo serves only
its own (empty) projection and never consults its members.

This left `virtualMembers` as an **apply-accepted, runtime-inert field** — the exact
anti-pattern ADR 0015 marks a hard block: an operator declares an aggregator, apply
accepts it, and it silently serves nothing. The feature must be either completed or its
operator surface removed.

Virtual/group repositories are a common, workaround-poor use case (one registry URL
serving private + proxied packages). The client-side alternatives are partial (npm
scoped registries, Cargo source replacement) or actively insecure — pip's
`--extra-index-url` flattens indexes and is the canonical dependency-confusion vector,
the very supply-chain attack Hort exists to prevent. A server-side, priority-ordered
aggregator resolves names deterministically, so completing the feature is a
security improvement, not only a convenience — provided resolution is designed so
aggregation itself does not re-open substitution attacks.

## Decision

Complete the feature for **npm, PyPI, and Cargo** (the formats already on the shared
Source → Filter → Builder `VersionEntry` pipeline). Resolution obeys these standing
rules (the operator-facing mechanics are in
`docs/architecture/how-to/declare-gitops-config.md`).

1. **Composition over members' gated serve paths.** A virtual introduces no new
   direct-to-storage or gate-bypassing path. It resolves each coordinate through a
   member's *existing* source + filter (index) or `find_visible_by_path` +
   quarantine-status check (download). Every served byte therefore passes a member's own
   ADR 0007 gate by construction. **The aggregation is transparent to the inbound HTTP
   layer**: it is encapsulated behind the format's existing `IndexSource` abstraction (a
   `Virtual` source that recursively dispatches each member to that format's
   `Hosted`/`Proxy` source), so the per-format serve handler dispatches source-by-type and
   runs the unchanged filter + builder — it does **not** special-case `Virtual`. A single
   shared `hort-app` helper owns resolve → pin → merge; each format contributes only its
   per-member fetch closure. The download path is made transparent the same way (a
   virtual-aware resolver behind the existing `find_visible_by_path` seam), so neither the
   serve nor the download handler branches on `Virtual`.

2. **Substitution defences (dependency confusion) — load-bearing.**
   *(a) Same-version (authoritative-member rule):* for any coordinate the
   **highest-priority member that has it (in any quarantine status)** is authoritative.
   The index merge dedups by version with higher-priority-wins on the **raw, pre-filter**
   entries (including status); `NonServableStatusFilter` runs *after* the merge; the
   download resolves to the same authoritative member and surfaces its gate. A coordinate
   held in a higher-priority member is dropped from the served index and **never silently
   replaced** by a lower-priority member's released copy. (The merge operates on per-member
   entries for one requested name, so the dedup key is *that name + version*.)
   Filter-per-member-then-merge is rejected.
   *(b) New-version (name-level pinning):* a package name owned by any non-proxy member
   (Hosted/Staging with ≥1 version) is **never** served from a proxy member, for any
   version, on either the index or the download path. Pinning runs before the merge, on raw
   entries. This closes the canonical dependency-confusion attack (attacker publishes
   `internal-pkg@9.9.9` to a public registry; a virtual that includes the private
   `internal-pkg` owner excludes the proxy for that name entirely). Repo-type
   (non-proxy = owner) is the ownership signal. "Quarantine + scan" is **not** a substitute
   — that is detection (a clean-scanning malicious package or typosquat passes), not a
   substitution defence; it is the backstop, pinning is the defence. **Member-failure is
   fail-closed:** a non-proxy member whose fetch *errors* (an infrastructure failure,
   distinct from a clean "package absent here") is treated as a *potential owner* — proxies
   stay suppressed for that name — so a transient outage of the trusted owner cannot
   silently re-open the confusion window by making the name look unowned. A proxy member's
   failure is simply skipped. This rule lives once, in the shared aggregation helper.

3. **Priority = `virtualMembers` list order**, ascending (index 0 = highest). Apply must
   reconcile members deterministically so persisted `priority` tracks list order
   (`add_virtual_member` is `ON CONFLICT DO NOTHING`).

4. **Read-only.** Upload/publish to a `type: virtual` repo is rejected.

5. **No nested virtuals (v1).** A member must be non-`Virtual`; apply-time rejected.

6. **Auth composition (ADR 0021).** Caller needs Read on the virtual; each member is
   resolved with the same caller; a member the caller cannot Read is *skipped*
   (anti-enumeration), not errored — a public virtual cannot leak a private member.

7. **Inert-field close (ADR 0015).** A Phase-0 apply-time linter rejects `type: virtual`
   for any not-yet-serve-supported `format`, closing the violation immediately; the
   supported set grows per format as resolution ships, reaching the correct steady state
   (only unsupported formats rejected).

8. **Cross-opt-in (ADR 0016).** `virtualMembers` is not a release-gate-influencing
   opt-in — it selects which member serves, not what the release predicate computes; each
   member's gate and index-mode apply unchanged. Registered as a benign, non-rejecting
   interaction.

## Consequences

- Virtual repos for npm/PyPI/Cargo become functional aggregators; the ADR 0015 violation
  is closed. OCI/Maven and other formats remain rejected at apply until separately
  specced (OCI already has its own `path_prefix` multi-upstream model).
- The merge primitive is format-agnostic (operates on the shared `VersionEntry` spine),
  so per-format code is thin.
- **The substitution defences live once, in `hort-app`.** Both serve-path index
  aggregation (`VirtualResolutionUseCase::aggregate_virtual_index`) and the
  download-path resolver (`VirtualResolutionUseCase::resolve_download`) are
  closure-parameterized: each format crate supplies only its per-member fetch
  closure and a thin `Virtual*Source` shim, while the pinning + authoritative-merge
  + **fail-closed member-failure classification** (`Ok → Present`, `NotFound →
  Present(empty)`, any other error `→ Unavailable`) lives in exactly one place under
  the 100%-coverage requirement. This is deliberate and load-bearing: that
  classification *is* the dependency-confusion security boundary (rule 2b), and
  copy-pasting it per format would let a single transcription slip silently re-open
  the confusion window for one format with nothing structural to catch it. A new
  format joins by adding a shim + a `VIRTUAL_SERVE_SUPPORTED_FORMATS` entry — it
  must NOT re-implement the classification.
- **Ownership-first on both paths — no owned-name leak to upstreams.** Index
  aggregation (`aggregate_virtual_index`) probes the non-proxy members first and
  **skips proxy fetches entirely when the name is owned** — mirroring the
  download resolver. An owned/internal name therefore never drives a public
  proxy upstream GET just to be discarded by pinning (the original fetch-then-pin
  shape leaked the owned name to upstreams as a reconnaissance signal on every
  cache-cold index request; the dedup key is name+version so the short-circuit is
  semantics-preserving). This supersedes the spec's original §4.1 fetch-then-pin
  ordering.
- **Member reconcile is atomic** (`RepositoryRepository::replace_virtual_members`,
  one transaction). The prior remove-loop-then-add-loop was non-transactional: in
  a multi-replica rolling deploy that changes a member list, a booting replica's
  mid-reconcile window could transiently drop the owner edge, making an owned
  name momentarily look unowned and un-suppressing proxies. The atomic replace
  guarantees a concurrent reader sees either the old set or the new set, never a
  partial one.
- The new-version dependency-confusion class is **closed in v1 by name-level pinning**
  (rule 2b): a name owned by a non-proxy member is unreachable from proxy members. The
  remaining deferred enhancement is **finer-grained per-name routing** — operator-specified
  include/exclude *patterns* beyond the repo-type ownership signal (e.g. pin `@acme/*` to a
  specific member). Recorded as an open item, not a vulnerability. Revisit trigger: an
  operator needs name-pattern routing that repo-type ownership cannot express.
- **Index-mode-through-virtual (behavioural note).** Members produce raw entries; the
  merged surface is governed only by the *virtual's* `index_mode` plus the post-merge
  `NonServableStatusFilter`, not by each member's own `index_mode`. A proxy member's
  `Unknown`/pending versions are therefore advertised per the virtual's mode. Benign for
  data-leak (`NonServableStatusFilter` runs first; `IncludePending`'s additive set is only
  `Unknown`), but a surprise worth knowing.

## Alternatives considered

- **Remove the operator surface instead of completing the feature.** Rejected: the use
  case is common and workaround-poor, the feature is already fully scaffolded below the
  serve layer, and a correct server-side aggregator is a net supply-chain-security gain.
- **Filter-per-member-then-merge** (each member's `NonServableStatusFilter` runs before
  the merge). Rejected: lets a lower-priority member's released copy shadow a
  higher-priority member's held copy of the same coordinate — re-introduces substitution.
- **Availability-first download fall-through** (skip a held authoritative member, serve a
  lower-priority released copy). Rejected for the same substitution reason; surfacing the
  authoritative member's 503/403 is the safe behaviour.
- **Name-level pinning in v1.** Adopted (rule 2b) — it is the actual new-version
  substitution defence and is small atop the version-level merge; shipping the aggregator
  without it would make the flagship private+public-behind-one-URL use case the unsafe one.
  Only finer-grained operator-pattern routing is deferred.
- **"Quarantine + scan" as the new-version defence.** Rejected — detection, not a
  substitution defence (a clean-scanning malicious package or typosquat passes). It is a
  compensating backstop for ordinary pull-through, not a confusion defence.
