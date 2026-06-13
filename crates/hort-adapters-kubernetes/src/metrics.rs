//! Label-name constants shared across the adapter's tracing /
//! metric-emission sites.
//!
//! The metrics emitted by the reconciler
//! (`hort_rotation_total`, `hort_rotation_lag_seconds`) live in
//! `hort-app::tasks::service_account_rotation` — the adapter itself
//! emits no metrics; it is a pass-through write surface.
//!
//! This module exists so that any future adapter-local metric (e.g.
//! `hort_k8s_secret_upsert_total{result}`) has a single home for its
//! label-name constants without polluting `secret_writer.rs`.

// ---------------------------------------------------------------------------
// Label names written on every managed Secret. These are part of the
// `KubernetesSecretWriter` port contract (ADR 0018) — changing them is a
// wire-shape break observable by every consumer of the rotated Secret.
// Pinned as `pub(crate)` so the reconciler's `read_managed` projection
// stays string-key-aligned with the `upsert_managed` write side.
// ---------------------------------------------------------------------------

/// `project-hort.de/managed-by` — set to `"hort-worker"` on every managed Secret.
/// The reconciler refuses to manage Secrets whose label is absent or
/// set to a different value (collision detection — ADR 0018).
pub(crate) const LABEL_MANAGED_BY: &str = "project-hort.de/managed-by";

/// `project-hort.de/service-account` — set to the CRD `metadata.name` of the
/// [`ServiceAccount`](hort_domain::entities::service_account::ServiceAccount)
/// whose rotation produced this Secret.
pub(crate) const LABEL_SERVICE_ACCOUNT: &str = "project-hort.de/service-account";

/// `project-hort.de/last-rotated` — RFC 3339 timestamp of the most recent
/// successful upsert. Written as an **annotation**, not a label,
/// because Kubernetes label values must match the regex
/// `(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?` — colons (which
/// every RFC 3339 timestamp carries) are rejected by the apiserver.
/// Annotations have no such restriction. The reconciler's freshness
/// check parses this annotation and compares against
/// `now() - rotation_interval`.
pub(crate) const ANNOTATION_LAST_ROTATED: &str = "project-hort.de/last-rotated";

/// `project-hort.de/token-id` — UUID of the `api_tokens` row whose plaintext is
/// embedded in this Secret. Used for audit correlation.
pub(crate) const LABEL_TOKEN_ID: &str = "project-hort.de/token-id";

/// Value written into `project-hort.de/managed-by`. Pinned because the
/// reconciler's collision-check compares the label against this exact
/// literal.
pub(crate) const MANAGED_BY_VALUE: &str = "hort-worker";

/// Field-manager string passed to Kubernetes server-side apply.
/// Identifies this adapter as the owning controller for the four
/// reconciler-managed fields (the labels + the data keys). Any
/// foreign actor patching the same fields under a different
/// field-manager triggers an SSA conflict surface the operator can
/// resolve explicitly via `--force-conflicts`.
pub(crate) const FIELD_MANAGER: &str = "hort-worker";
