//! Mutable-ref lifecycle events.
//!
//! Emitted by the `RefLifecyclePort` write adapter. Streams live in
//! category [`StreamCategory::Ref`](super::StreamCategory::Ref); each
//! ref has one stream keyed by `ref_id`, so the full history of a ref
//! (every move plus its eventual retirement) is ordered within that
//! single stream. See design doc §2.4.
//!
//! **Idempotent re-pointing is NOT an event.** Setting a ref to its
//! current target is a no-op — no `RefMoved` emission. The domain
//! enforces this by rejecting `RefMoved` where `from == Some(to)` as
//! an `Invariant` violation. The event stream describes *change*, not
//! *request*.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::mutable_ref::RefTarget;
use crate::error::{DomainError, DomainResult};

use super::validation::validate_string;

// ---------------------------------------------------------------------------
// Validation constants
// ---------------------------------------------------------------------------

/// Maximum allowed length of `namespace` in a ref event payload.
///
/// 512 characters leaves generous headroom for format-scoped namespace
/// conventions (OCI image names, Maven `<group>:<artifact>` coordinates,
/// npm package names) while staying well under the 64 KB event-JSON
/// ceiling enforced by the Postgres adapter.
const MAX_NAMESPACE_LEN: usize = 512;

/// Maximum allowed length of `ref_name` in a ref event payload.
///
/// 512 characters matches the namespace bound — no real-world ref name
/// approaches this length (OCI tags are effectively under 128 chars,
/// npm dist-tags under 32), but a shared generous bound keeps the
/// validation surface simple.
const MAX_REF_NAME_LEN: usize = 512;

// ---------------------------------------------------------------------------
// RefMoved
// ---------------------------------------------------------------------------

/// Recorded every time a mutable ref is created or re-pointed at a new
/// target.
///
/// `from: None` models the first placement of a ref (creation); subsequent
/// moves carry `from: Some(prior_target)`. See §2.4 of the design doc.
///
/// **Invariant.** `from != Some(to)` — a move that does not change the
/// target is not an event. Idempotent re-pointing is a no-op at the
/// projection layer; if a caller ever reaches the append path with a
/// redundant move it is rejected as `DomainError::Invariant`. This keeps
/// the event stream a description of *change*, never of *request*.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RefMoved {
    pub ref_id: Uuid,
    pub repository_id: Uuid,
    pub namespace: String,
    pub ref_name: String,
    /// Prior target. `None` on first placement (ref creation).
    pub from: Option<RefTarget>,
    /// New target. Must differ from `from` when `from.is_some()`.
    pub to: RefTarget,
}

impl RefMoved {
    pub fn validate(&self) -> DomainResult<()> {
        validate_string("namespace", &self.namespace, MAX_NAMESPACE_LEN)?;
        validate_string("ref_name", &self.ref_name, MAX_REF_NAME_LEN)?;
        if let Some(prior) = &self.from {
            if prior == &self.to {
                return Err(DomainError::Invariant(
                    "RefMoved.from must differ from RefMoved.to — same-target moves are \
                     no-ops and must not produce events"
                        .into(),
                ));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RefRetired
// ---------------------------------------------------------------------------

/// Recorded when a mutable ref is retired (deleted).
///
/// `last_target` is the target the ref pointed at immediately before
/// retirement. Preserved in the event so replay can reconstruct the
/// ref's final state without consulting the projection — the event
/// stream alone is sufficient to tell "what did `library/nginx:latest`
/// point at when it was retired?". See §2.4 of the design doc.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RefRetired {
    pub ref_id: Uuid,
    pub repository_id: Uuid,
    pub namespace: String,
    pub ref_name: String,
    pub last_target: RefTarget,
}

impl RefRetired {
    pub fn validate(&self) -> DomainResult<()> {
        validate_string("namespace", &self.namespace, MAX_NAMESPACE_LEN)?;
        validate_string("ref_name", &self.ref_name, MAX_REF_NAME_LEN)?;
        Ok(())
    }
}
