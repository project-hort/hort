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
source of truth; the notification is a hint.** Push delivery is
best-effort and may drop events. Consumers that need completeness
reconcile through the pull surface, `GET /api/v1/events`, which exposes
the same event log over HTTP. Anything inside the server that needs to
*react* to an event reads the event store directly — the notifier is a
leaf consumer, never an input to further state.

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

Each per-subscription task
(`crates/hort-app/src/dispatcher/subscription_task.rs`) starts with a
**catch-up** pass — paging `EventStore::read_category` forward from the
subscription's `last_delivered_position` in 1000-event pages — and then
enters the live loop on the broadcast receiver. When the receiver
reports `Lagged` (the fixed-capacity channel overwrote events the task
had not consumed), the task drops back into catch-up against the event
store and re-enters the live loop once caught up. The broadcast channel
is therefore only a low-latency signal path; the event store remains the
backing read model even for live delivery.

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
`hort_subscription_ssrf_blocked_total` counter
(`subscription_use_case.rs:845-850`).

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

## Delivery semantics: best-effort, loudly

Delivery is **not at-least-once**. Every layer refuses to upgrade the
hint into a guarantee: the publisher drops on a full channel, the
adapters make exactly one attempt per event with no retry, and the
catch-up path exists to bound the drop volume after a restart or lag —
not to close it. What the system promises instead is that loss is
*recoverable and observable*:

- The per-task progress marker (`last_delivered_position`) is persisted
  with a 5-minute debounce on success and immediately on failure — it
  is operator visibility, not a delivery cursor
  (`subscription_task.rs`, `ProgressDebouncer`).
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
  `global_position` and treating re-delivered positions as no-ops. The
  long-poll variant uses the broadcast channel purely as a wake-up
  signal and re-reads the event store for the payload. Per-event
  repository filtering applies to the response, but `next_after` is the
  unfiltered last-seen position, so a caller never replays events that
  were filtered out for them.

This is the same posture throughout: durable truth lives in the event
log, push is an optimisation on top of it, and every degradation path
lands back on a pull from the log.

## Related pages

- [Event sourcing](event-sourcing.md) — the event store, streams,
  positions, and append semantics the notification substrate rides on.
- [Public event taxonomy](../reference/event-taxonomy.md) — the
  per-event payload and stability contracts external subscribers rely
  on.
- [Security model](security.md) — the wider authorization model the
  privileged-category gate and live-grant intersection plug into.
- [ADR 0002 — Event-sourced artifact lifecycle](../../adr/0002-event-sourced-artifact-lifecycle.md)
- [ADR 0010 — TLS via builder, no insecure knobs](../../adr/0010-tls-builder-no-insecure-knobs.md)
