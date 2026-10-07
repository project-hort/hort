# Event Notifications and Subscriptions

Every state transition in the artifact lifecycle is already an immutable
domain event ([ADR 0002](../../adr/0002-event-sourced-artifact-lifecycle.md)).
The notification subsystem makes those events available to *external*
consumers — replication relays, SIEM shippers, SBOM indexers — as a
push signal, so that supply-chain reactions ("an artifact was promoted",
"a scan found a vulnerability", "something left quarantine") do not
require polling the database and the registry never holds integration
credentials for each downstream system.

The design rests on one load-bearing split: **the event store is the
source of truth; every delivery path is a read of it.** Push delivery is
at-least-once with duplicates, never exactly-once, and the pull surface
`GET /api/v1/events` exposes the same log over HTTP for consumers that
would rather drive the cursor themselves. Anything inside the server
that needs to *react* to an event reads the event store directly — the
notifier is a leaf consumer, never an input to further state.

## How events reach the dispatcher

Use cases do not talk to notifiers. They append to the event store
through `EventStorePublisher`
(`crates/hort-app/src/event_store_publisher.rs`), a thin wrapper that
implements `EventStore` itself and, after a successful append, fans the
persisted events out on a `tokio::sync::broadcast` channel. A send
error — no receivers, capacity exhausted — is silently dropped: the
append path never blocks on, retries for, or buffers toward a slow
notification consumer. When notifications are disabled
(`HORT_NOTIFICATIONS_ENABLED=false`), the publisher is built without a
sender and `append` is a transparent pass-through; routes stay mounted
and subscription rows persist, but nothing is delivered.

The `NotificationDispatcher`
(`crates/hort-app/src/dispatcher/dispatcher.rs`) subscribes to that
broadcast channel once per process and owns one tokio task per active
subscription. It reconciles the task set every 30 seconds and on
`subscription_changes` LISTEN/NOTIFY events, spawning tasks for newly
active subscriptions and cancelling tasks whose rows vanished or were
disabled.

**Delivery is driven by the event store, not by that channel**
([ADR 0061](../../adr/0061-store-driven-notification-delivery.md)). Each
per-subscription task
(`crates/hort-app/src/dispatcher/subscription_task.rs`) pages
`EventStore::read_categories` forward from its cursor in 1000-event pages
— at startup, on every 5-second `STORE_POLL_INTERVAL` tick, and whenever a
hint for one of its own categories arrives on the broadcast receiver — and
dispatches what it reads. The broadcast is a **wake-up**: it says
something landed, sooner than the next tick would. Its *category* is used
as the wake predicate, the same thing `GET /api/v1/events` does with it,
so an append to a category nobody here subscribes to costs no read. Its
*position* is discarded: delivering the payload directly would advance the
subscription's cursor to that `global_position` and resume above it,
skipping every transactional append below — which is precisely the set the
channel cannot carry.

`read_categories` returns **one `global_position`-ordered page across the
whole filter**, not one page per category. That is what makes the single
persisted `last_delivered_position` true rather than approximate: a
position at or below the mark has been read in every subscribed category,
so a task respawning from the mark cannot step over anything. Reading the
categories one at a time and checkpointing one scalar cannot say that — an
advance driven by the first category carries the mark over the second
category's unread events below it, and the respawn seeds every category
from the moved mark.

The channel cannot be the delivery path, for two reasons that are
properties of where it sits rather than bugs in it:

- **Transactional appends are below the sender.** An event that must land
  atomically with a projection write does not go through
  `EventStore::append` at all — it goes through
  `PgEventStore::append_in_tx` via a lifecycle port
  (`ArtifactLifecyclePort`, `RefLifecyclePort`,
  `ArtifactGroupLifecyclePort`, the artifact delete, the purge sweep),
  which sits below `EventStorePublisher` and therefore below the `send`.
  That covers the whole subscribable artifact lifecycle. Sending from
  inside the transaction would announce a write that may still roll back;
  sending from the adapter after commit would put a notification concern
  in `hort-adapters-postgres`.
- **The channel is per-process.** With `replicaCount > 1` each replica's
  sender carries only that replica's own appends, and there is no leader
  election over the dispatcher.

Reading the store is subject to neither: it sees every append, from every
process, from every write path, once it commits.

## The notifier port and its adapters

Delivery crosses an outbound port, `EventNotifier`
(`crates/hort-domain/src/ports/event_notifier.rs`): one `notify(target,
subscription_id, events)` call per delivery, returning a closed-enum
`NotifyOutcome` (`Delivered`, `DownstreamRejected`, `Failed`), plus a
`supports(target)` discriminator. The dispatcher holds a
`Vec<Arc<dyn EventNotifier>>` assembled at the composition root and
routes each subscription to the first adapter whose `supports` returns
true. Implementations must not retry, must not buffer beyond a single
transport send, and must not block the caller on downstream
unavailability.

Two first-party adapters exist, each in its own crate so a deployment
that does not enable NATS does not pull its dependency tree:

- **Webhook** (`crates/hort-notifier-webhook/src/lib.rs`) — POSTs a
  JSON body to the subscription's URL with an HMAC-SHA256 signature
  over the exact transmitted bytes (`X-Hort-Signature: sha256=<hex>`),
  plus `X-Hort-Subscription-Id`, `X-Hort-Schema-Version`, and a fresh
  `X-Hort-Delivery-Id` per attempt for receiver-side dedup. The signing
  key is resolved at delivery time through `SecretPort` from the
  `secret_ref` locator stored on the subscription row — the row carries
  a pointer to an operator-provisioned env var or file, never the
  secret material itself, so a reader of the subscription store or a
  backup holds a locator, not a forgeable signing key. The HTTP client
  is built via `reqwest::Client::builder()` with the process-wide extra
  CA bundle ([ADR 0010](../../adr/0010-tls-builder-no-insecure-knobs.md)),
  a 5s connect / 10s total timeout, and a `Policy::limited(0)` redirect
  policy — 3xx responses surface as `DownstreamRejected`, never get
  followed.
- **NATS JetStream** (`crates/hort-notifier-nats/src/lib.rs`) —
  publishes the *same* JSON body to the subscription's subject and
  awaits the JetStream ack with a 2s timeout. No NATS message headers
  are used: receivers parse one wire shape regardless of transport.
  The single per-process connection comes from `HORT_NATS_URL` at the
  composition root; connection credentials never live on subscription
  rows.

The wire body (`schema_version`, `delivery_id`, `subscription_id`,
`delivered_at`, `events[]`) embeds events in their persisted form —
positions, stream identity, actor, correlation — which makes the wire
format a public-API commitment tied to the domain event payloads. The
events themselves are catalogued in
[the public event taxonomy](../reference/event-taxonomy.md); this page
deliberately does not duplicate that vocabulary.

## The subscription model

Subscriptions are CRUD rows (not event-sourced aggregates) owned by a
user, managed over `/api/v1/subscriptions`
(`crates/hort-http-subscriptions/src/lib.rs`) with an admin-only
cross-owner listing at `/api/v1/admin/subscriptions`. The handlers are
thin; all rules live in `SubscriptionUseCase`
(`crates/hort-app/src/use_cases/subscription_use_case.rs`).

A subscription's filter is a closed structure — stream categories, a
closed-enum event-type list, a repository scope, and a named-predicate
hook that ships with zero variants — deliberately not an expression
language. High-volume event types (downloads, token use, authentication
attempts) are rejected at issuance; their volume is incompatible with a
hint channel.

Who may subscribe to what is decided three times, against live
authority each time, all delegating to the single
`StreamCategory::requires_admin` predicate in
`crates/hort-domain/src/events/mod.rs` (the privileged set: `Policy`,
`Admin`, `Authorization`, `User`, `AuthAttempts`, `DownloadAudit`,
`TokenUse`, `RetentionPolicy`):

- **At create and update**, `privileged_category_denied` refuses a
  filter touching a privileged category unless the acting principal
  satisfies `Permission::Admin` right then
  (`subscription_use_case.rs`, `privileged_category_denied`).
- **At read**, `GET /api/v1/events` requires `Permission::Admin` for
  the same categories (`crates/hort-http-events/src/handler.rs`,
  `category_requires_admin` — a pinned thin delegator).
- **At delivery**, the filter walk
  (`crates/hort-app/src/use_cases/subscription_filter.rs`) re-checks
  `Permission::Admin` for privileged-category events against the
  owner's live state, and intersects every repository-scoped event with
  the owner's *current* `Read` grants. The stored filter is the upper
  bound; live grants are the floor, so revoking a role cuts off
  delivery without touching the subscription.

### Which repository an event belongs to is resolved, not read off the payload

The read gate and the delivery filter both have to answer "which
repositories does this event disclose?", and for most of the artifact
lifecycle the payload does not say. `ArtifactIngested`,
`ChecksumMismatch`, `ArtifactDeleted` and `ArtifactDownloaded` carry a
`repository_id`; `ArtifactQuarantined`, `ScanRequested`,
`ScanCompleted`, `ArtifactBecameVulnerable`, `ArtifactReleased`,
`ArtifactRejected`, `ScanIndeterminate`, `ChecksumVerified`, the
provenance verdicts, `ArtifactReEvaluated`, `PolicyEvaluated`,
`ApprovalDecided`, `ArtifactExpired`, `ArtifactPurged` and
`ArtifactCorrupted` name the **artifact**, because the artifact
aggregate already owns exactly one repository. The payload is not
extended to add one: already-stored events would not gain the field, so
the gate would only work for events written after the change, and a
field appended to an event type alters the canonical bytes of every
event written before it (the chain verifier's `ChainBreak::HashMismatch`
— see [ADR 0002](../../adr/0002-event-sourcing.md)).

So the resolution happens on the read side, for stored and future events
alike, through one primitive both call sites use
(`hort_app::use_cases::event_visibility`):

1. `EventTypeKind::disclosed_repositories` classifies the payload —
   exhaustively, with no wildcard arm — into *global* (no repository
   association exists), a set of one or two repository references
   (carried directly, or named indirectly through the artifact /
   artifact-group aggregate), or *unattributable*.
2. `EventVisibilityUseCase::index` resolves every indirect reference on
   the page in a **single** round trip (`EventRepositoryResolver`). The
   read handler does this for the page it just read; the dispatcher does
   it for each catch-up page. Neither resolves per event — that would
   put a database round trip on each event of the read hot path.
3. Each call site then applies its own gate to the same answer: the read
   handler requires `Permission::Read` on **every** disclosed
   repository, the filter additionally intersects with the stored
   `RepositoryScope`.

Three properties of that design are load-bearing:

- **The conjunction.** The promotion chain (`PromotionRequested`,
  `ApprovalRequested`, `ArtifactPromoted`, `PromotionRejected`)
  discloses a source *and* a target, and the delivered payload carries
  both repository identities — so `Read` on one of them is not authority
  to receive it.
- **Resolution is by identity, never filtered on liveness.** Purge
  retires an artifact's projection row (`artifacts.deleted_at`) instead
  of removing it, and `ArtifactPurged` / `ArtifactExpired` are precisely
  the events a repository's own readers still need. A liveness filter in
  the resolver would hide a repository's retention history from the
  people entitled to it.
- **Unresolvable means admin-only, not invisible.**
  `CasIntegrityMismatch` is keyed on a CAS content hash that any number
  of repositories' artifacts may point at (its stream `entity_id` is
  derived from the hash, not from an artifact id), and an aggregate
  whose repository was deleted has no row left to resolve. Both fail
  closed onto live `Permission::Admin`: there is no repository to check,
  and an audit fact that no one can read is its own failure mode.

The symmetry is why both halves ship together. The same absent
`repository_id` that let a grantless account read every repository's
scanner names and release justifications **also** made a correctly
restricted `RepositoryScope::Some([repo])` subscriber lose that
repository's entire lifecycle feed: an allow-list cannot match an event
that names no repository. A change that only closed the disclosure
would have traded one silent failure for the other.

Each subscription also carries `snapshot_claims` — the creator's
resolved claim set captured at create/update time as the delivery
authority floor. The dispatcher synthesises the owner principal from
that snapshot at task spawn, with one critical exception: any `"admin"`
string in the snapshot is stripped and re-derived from the owner's live
`is_admin` bit (`dispatcher.rs`, `synthesise_principal`), so a snapshot
elevated by a then-admin actor cannot retroactively unlock privileged
categories for an owner whose admin was revoked.

Repository-capped API tokens cannot escape their cap through the
durable side-effect either: a capped token must name an explicit
repository list (a subset of its cap) rather than the dynamic
owned-by-actor scope, and updates may shrink but never widen that list.

Subscription lifecycle is itself audited on the owner's user stream:
`SubscriptionCreated`, `SubscriptionUpdated`, `SubscriptionPaused`,
`SubscriptionResumed`, `SubscriptionDeleted`, and
`SubscriptionDisabled` when the dispatcher exhausts a failure budget.
On the create path, every refusal — privileged category, unsupported
event type, plaintext URL, SSRF block, scope violations, duplicate
name — appends a durable `SubscriptionCreationDenied` event with a
closed-enum `denial_reason` (`subscription_use_case.rs`,
`emit_denial`): tracing logs rotate away, but the event log is the
security record a SIEM ingests. On the update path, a
privileged-category refusal appends the same denied event, while an
SSRF refusal returns the typed error and increments the
`hort_webhook_ssrf_block_total{reason}` counter
(`subscription_use_case.rs`, `emit_ssrf_block`) — this name superseded an
earlier `hort_subscription_ssrf_blocked_total` for the same emitter; there
is exactly one emitter and one name, no double-count.

## Webhook targets are an outbound trust boundary

Webhook URLs are submitted by any user with subscription-create
authority — unlike upstream URLs, which only operators configure. That
makes the webhook target the one place where untrusted input chooses
where the server connects, and it is guarded twice, on both sides of
the time-of-check/time-of-use gap:

- **At create and update**, the use case calls
  `WebhookTargetGuard::check` (implemented by the webhook adapter,
  `check_url_routable` in `crates/hort-notifier-webhook/src/lib.rs`).
  A host named on the `HORT_WEBHOOK_ALLOWLIST_HOSTS` allowlist is
  accepted by name without any resolve (so an internal, proxy-reached
  receiver works on a pod with no direct DNS). An IP-literal host must
  fall inside an allowlisted CIDR or be publicly routable per
  `hort_net_egress::is_routable` — link-local metadata endpoints and
  RFC 1918 space are rejected, including IPv4-mapped/compatible IPv6
  spellings. Any other DNS name gets a single-shot resolve and every
  returned address must pass the same check.
- **At delivery**, a `GuardedDnsResolver`
  (`crates/hort-notifier-webhook/src/dns_guard.rs`) is bound to the
  webhook client — and only the webhook client — re-running the same
  routability/allowlist decision on the addresses actually dialed.
  This closes the DNS-rebinding race between create-time validation
  and delivery. Both legs are fed from one `HostAllowlist::from_env`
  read, so they cannot drift. The zero-redirect policy closes the
  remaining hop: a compromised receiver cannot 3xx the delivery into
  IMDS.

When an egress proxy is configured, reqwest connects via the proxy and
the in-process connect-time guard cannot see the dialed target; the
adapter logs a loud warning that SSRF filtering is delegated to the
proxy's egress allowlist. Two operator opt-outs exist, both default-off
and both surfaced through the `hort_unsafe_config_active` gauge at boot
(`crates/hort-server/src/composition.rs`):
`HORT_WEBHOOK_ALLOW_PLAINTEXT` admits `http://` targets, and
`HORT_WEBHOOK_ALLOW_NONROUTABLE_TARGETS` skips the create-time guard
entirely.

## Delivery semantics: at-least-once, duplicates possible

**Every event visible to a category read when a subscription's cursor
passes it is delivered at least once.** Duplicates are expected and are
the receiver's to drop: each delivery carries a fresh
`X-Hort-Delivery-Id` and a stable `global_position`, and the same event
is re-sent on a restart (the persisted cursor is debounced up to 5
minutes behind) and once per server replica. The
asymmetry is deliberate — a duplicate costs a receiver one idempotent
write, while a gap is recoverable by nobody once every reader's cursor
has passed it and none of them looks back. Looking back is therefore the
consumer's lever, and it is the one this page's
[detection section](#detecting-a-late-commit-skip) hands you.

What is *not* promised, and why:

- **A single transport attempt per *pass*.** The notifier adapters try
  once and never retry internally. The dispatcher does: a failed delivery
  stops the pass at that event, the cursor is not advanced over it, and
  the position persisted alongside the failure is the position *before*
  it, so the next 5-second tick re-reads the same event and tries again.
  Retries therefore continue until the delivery succeeds or the failure
  budget below runs out — 100 failures in an hour, roughly eight minutes
  of ticks — and the budget is what bounds the head-of-line block the
  retry creates. A receiver that is down for thirty seconds loses nothing;
  a receiver that is down for an hour is disabled visibly. The publisher
  still drops on a full channel, and a receiver can still report `Lagged` —
  both cost only latency, because the wake-up they lost is also
  produced by the tick.
- **Exactly-once.** Nothing anywhere de-duplicates across restarts or
  replicas.
- **Completeness against an event whose transaction commits late.**
  `events.global_position` comes from a sequence evaluated at INSERT
  while a row becomes visible at COMMIT, so a transaction holding a
  lower position can commit after a reader has already passed it. A
  cursor that is a bare high-water mark cannot see it again. This bounds
  what *any* consumer of the log can promise, the `GET /api/v1/events`
  `next_after` checkpoint included. **It is accepted, not scheduled for a
  fix**: the reader-side horizons that look like they close it either do
  not close it (a `pg_snapshot_xmin` horizon — the position order and the
  transaction-id order are independent) or stall delivery without bound
  (a horizon sampled against the oldest running transaction, which one
  long-open transaction freezes entirely)
  ([ADR 0061](../../adr/0061-store-driven-notification-delivery.md), with
  `crates/hort-adapters-postgres/tests/event_delivery_visibility.rs` as
  the reproduction of both). What you can do about it is
  [detect it](#detecting-a-late-commit-skip), below — the loss is
  exactly detectable from what you already receive.
- **Completeness against retention.** The event store is the outbox, and
  it is swept on age rather than on delivery. An artifact stream whose
  *oldest* event is past the audit floor can be sealed and deleted within
  one sweep interval of its newest events being written, so a subscription
  that is paused or whose replicas are down across that interval never
  sees them. Bounded — both retention sweeps are `enabled: false` by
  default and the default floor is 1,080 days — but it is the one case
  where an undelivered event disappears rather than waiting
  ([ADR 0061](../../adr/0061-store-driven-notification-delivery.md)).
- **One delivery per event cluster-wide.** N replicas run N tasks per
  subscription and all N deliver.

Loss and degradation stay observable:

- The per-task progress marker (`last_delivered_position`) is persisted
  with a 5-minute debounce on success and immediately on failure
  (`subscription_task.rs`, `ProgressDebouncer`). It is both the operator
  signal and the cursor a restarting task resumes from — and because it
  lags, it resumes *behind* rather than ahead. It is one scalar per
  subscription, and the merged `read_categories` walk is what makes that
  exact for a multi-category filter rather than a position in whichever
  category was read last.
- A failed *read* — as opposed to a failed delivery — is fail-closed: the
  cursor does not move, so nothing is skipped, and the next tick retries
  the same page. A deterministic read failure (one row a replica cannot
  decode, which a mid-rollout version skew produces) therefore stalls the
  subscription indefinitely rather than losing anything, and
  `hort_notify_store_read_errors_total` is the alertable signal for it.
- A sliding-window failure budget
  (`crates/hort-app/src/dispatcher/failure_budget.rs`) counts
  consecutive failures; 100 within an hour transitions the subscription
  to `Disabled { DeliveryFailureBudgetExhausted }` and appends
  `SubscriptionDisabled` to the audit stream. A persistently broken
  receiver is disabled visibly, never muted silently; re-enabling is an
  explicit operator action.
- Consumers reconcile through `GET
  /api/v1/events?category=<cat>&after=<checkpoint>&max=<n>&wait_ms=<n>`
  (`crates/hort-http-events/src/handler.rs`), checkpointing on
  `global_position` and treating re-delivered positions as no-ops. That
  recovers a failed delivery, a receiver that was down, a subscription
  that was paused, and a push path you never wired up — but **not** an
  event whose transaction committed late. `next_after` is the same bare
  high-water mark the dispatcher's cursor is, over the same log, so
  re-reading forward from it steps over exactly what the push path
  stepped over; the pull surface is a second reader of the same log, not
  a second source. For that one class, use
  [the detectors below](#detecting-a-late-commit-skip) — a re-read of a
  *trailing* window recovers it, a re-read from your checkpoint does not.
  The long-poll variant uses the broadcast channel purely as a wake-up
  signal and re-reads the event store for the payload — so an event the
  channel does not carry costs a caller up to one `wait_ms` of latency,
  never the event. Per-event repository filtering applies to the
  response, but `next_after` is the unfiltered last-seen position, so a
  caller never replays events that were filtered out for them.

This is the same posture throughout: durable truth lives in the event
log, every delivery path is a read of that log, and the push channel is
a latency optimisation on top of it.

## Detecting a late-commit skip

If you are a replication relay, a SIEM shipper or an SBOM indexer — a
consumer for which a missing event is a correctness problem rather than a
latency one — a position cursor alone cannot give you completeness, for
the reason *Delivery semantics* above gives: the log's cross-stream
sequence is drawn at INSERT and becomes visible at COMMIT. It can give
you *detection*, exactly, from fields that are already in every payload
you receive. Both positions ride every event — in a webhook body, in a
NATS message and in a `GET /api/v1/events` page alike: `global_position`,
the cross-stream sequence, and `stream_position`, a counter within one
`stream_id`.

Three detectors, strongest first.

**Per-stream contiguity — exact.** `stream_position` is 0-based and
gapless within a stream. The server derives it as that stream's current
tail plus one, inside the same transaction that appends the event, and a
unique index on `(stream_id, stream_position)` rejects a second event at
the same position — so a concurrent appender loses the race rather than
creating a hole, and an append that rolls back leaves nothing behind to
skip over. Keep the last `stream_position` you handled per `stream_id`:
an event arriving more than one position above it means you missed
something, with certainty and not as a suspicion. A stream you first see
at a position above 0 is the same signal. This is the detector to build
on, and it has two limits that are not corner cases:

- **Anything that filters events out of your feed breaks it.** An
  `event_types` filter is the obvious one: you asked for a subset of each
  stream, so you are *supposed* to receive `stream_position` 0 and 4 and
  nothing between, and holes carry no information. Authorization
  filtering breaks it the same way and less visibly, because it is
  applied **per event, not per stream** — both the dispatcher
  (`crates/hort-app/src/use_cases/subscription_filter.rs`) and the pull
  surface drop an individual event whose disclosed repositories you lack
  `Read` on, or whose type is an authorization-model mutation or a
  privileged audit fact you are not admin for, while passing its
  stream-mates that have no repository association at all. So contiguity
  is a detector
  only when nothing between you and the log is removing events: no
  `event_types` filter, and a principal that can read everything in the
  categories you take. Where that does not hold, use the trailing-window
  re-read below and compare it against the same filtered view — it
  compares like with like, so a filter does not disturb it.
- **A skipped event that was its stream's last is never revealed.** The
  hole is exposed by the successor that arrives above it. If no successor
  is ever appended — an artifact's final lifecycle event, the last event
  of a retired ref — nothing arrives to expose it, and the stream simply
  looks shorter than it is. Nothing on this page closes that; a consumer
  that cannot tolerate it needs the trailing-window re-read below, which
  does not depend on a successor.

**A trailing-window re-read — exact, bounded, and the one that works
under a filter.** Do not only read forward from your current checkpoint.
Also keep the checkpoint value you held Δ ago, and periodically re-read
`GET /api/v1/events?category=<cat>&after=<that older checkpoint>` —
paging on `next_after` until `has_more` is false — comparing what comes
back against what you already handled. Anything that appears inside a
window you had already passed is precisely a late-committing append. The
read is a bounded range scan of the `(stream_category, global_position)`
index server-side, and it costs you nothing semantically: delivery is
at-least-once with duplicates already, so you may simply re-handle the
window rather than remember which positions were in it.

Δ is a *time* span, which is why the recipe is "the checkpoint you held Δ
ago" rather than a subtraction on the position number — positions are a
sequence, not a clock, and you cannot convert one to the other without
knowing the instance's append rate. Choose Δ larger than the longest
write transaction on the server. The bound Hort puts on that is the
worker pools' `lock_timeout` (`HORT_WORKER_LOCK_TIMEOUT_MS`, default
`120000` ms), so 120 seconds covers a default deployment; an operator who
raised that value — or set it to `0`, which disables the backstop — has
raised your floor with it, so confirm it rather than assuming. Round
generously: a Δ that is too large costs a few more duplicate events, a Δ
that is too small silently costs you the events it was meant to catch.

**A `global_position` gap — a trigger, never a verdict.** A missing
number in the sequence is worth a second look and is not by itself
evidence of anything. The sequence is not transactional: an append whose
transaction rolls back burns its number permanently, so gaps occur in
ordinary operation. Treat a gap as a reason to run one of the two
detectors above, never as a conclusion that an event was lost.

## Related pages

- [Event sourcing](event-sourcing.md) — the event store, streams,
  positions, and append semantics the notification substrate rides on.
- [Public event taxonomy](../reference/event-taxonomy.md) — the
  per-event payload and stability contracts external subscribers rely
  on.
- [Security model](security.md) — the wider authorization model the
  privileged-category gate and live-grant intersection plug into.
- [ADR 0002 — Event-sourced artifact lifecycle](../../adr/0002-event-sourced-artifact-lifecycle.md)
- [ADR 0061 — Store-driven notification delivery](../../adr/0061-store-driven-notification-delivery.md)
- [ADR 0010 — TLS via builder, no insecure knobs](../../adr/0010-tls-builder-no-insecure-knobs.md)
