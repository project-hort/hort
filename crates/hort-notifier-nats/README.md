# hort-notifier-nats — NATS JetStream Event Notifier

## Layer

Outbound adapter — structured as an event-delivery adapter (wraps a
message-broker client) rather than a repository/CRUD-style port. No
`hort-app` dependency at all — a pure leaf adapter over `hort-domain` +
`hort-config`. Requires >= 85% coverage.

## Responsibility

Implements `EventNotifier` for `SubscriptionTarget::NatsJetStream` —
best-effort, single-attempt JetStream publish with an explicit 2-second
ack-timeout wrapper and closed-enum failure classification (NAK family vs.
transport/connection-lost family).

## Ports

- **Implements:** `EventNotifier` (`NatsNotifier` — `notify`, `supports`).
- **Consumes:** none — no `hort-app` dependency at all.

## Key types

- `NatsNotifier` — `new(client: async_nats::Client)`,
  `connect(url: &str, extra_ca: Option<&ExtraTrustAnchors>) ->
  DomainResult<Self>`.

## Rules

- Extra-CA / no-insecure-TLS-knob discipline (ADR 0010) applied to the NATS
  TLS leg: `build_nats_rustls_config` builds the OS native trust store
  **plus** any extra anchors — system roots are never dropped — mirroring
  `hort-adapters-upstream-http`'s pattern. This crate never uses `reqwest`
  (it drives `rustls::ClientConfig` directly through `async-nats`), so the
  `Client::builder()` rule doesn't apply verbatim, but the same
  no-insecure-bypass principle does.
