# hort-notifier-webhook — Webhook Event Notifier + Target Guard

## Layer

Outbound adapter — structured as a dual-port notification+guard adapter:
one struct implements two distinct port traits for two distinct call sites
(delivery dispatcher vs. subscription-creation use case), rather than a
single CRUD port. Leaf adapter with respect to `hort-app` (used only for
`UpstreamErrorKind` error classification). Requires >= 85% coverage.

## Responsibility

Implements both `EventNotifier` (HMAC-signed webhook POST delivery,
`X-Hort-Signature` header, best-effort single-attempt, zero-redirect
policy) and `WebhookTargetGuard` (create/update-time SSRF check) in one
struct, so the same connect-time DNS-rebinding guard binds to the delivery
client that later sends the payload.

## Ports

- **Implements:** `EventNotifier` and `WebhookTargetGuard`, both on
  `WebhookNotifier`.
- **Consumes:** `hort_app::metrics::UpstreamErrorKind` for error
  classification; genuinely consumes `hort-net-egress::is_routable` as a
  library call (not merely a data-type import) for its SSRF guard.

## Key types

- `WebhookNotifier` — `new(extra_ca: Option<&ExtraTrustAnchors>,
  secret_port: Arc<dyn SecretPort>) -> DomainResult<Self>`.

## Rules

- `reqwest::Client::builder()` only, never `Client::new()` (ADR 0010).
- The SSRF/DNS-rebind guard (`GuardedDnsResolver`) is deliberately scoped to
  this crate's own webhook client builder only — reachable from nowhere
  else, and **not** re-globalized to the upstream-http/S3/OIDC clients. Do
  not assume this crate's egress guard covers any other adapter's network
  path.
