//! Late-joiner provenance self-clear (ADR 0039 §11, constituent end).
//!
//! The verify-time (subject-end) cascade is exercised by
//! `provenance_orchestration_tests.rs`; these tests pin the OTHER trigger
//! end — a constituent that lands after its subject was already verified
//! and must clear itself.
//!
//! Every guard arm here defaults to "stays held": a missed clearance is
//! exactly today's fail-closed hold, so the tests assert *no event
//! committed* for each refusal, and assert the committed event's
//! `cascaded_from` attribution for each acceptance.

use std::sync::Arc;

use uuid::Uuid;

use hort_domain::entities::artifact::{Artifact, QuarantineStatus};
use hort_domain::error::DomainError;
use hort_domain::events::{system_actor, DomainEvent, PersistedEvent, StreamId};
use hort_domain::ports::content_reference_index::{ContentReference, ContentReferenceIndex};
use hort_domain::ports::provenance::SignerIdentity;
use hort_domain::types::ContentHash;

use super::ProvenanceCascade;
use crate::use_cases::test_support::{
    sample_artifact, MockArtifactLifecycle, MockArtifactRepository, MockContentReferenceIndex,
    MockEventStore, MockStoragePort,
};

/// A distinct, valid sha256 built from a repeating hex char. The mock
/// repos never verify bytes↔hash for seeded rows, so any 64-hex string
/// works.
fn hexhash(c: char) -> ContentHash {
    std::iter::repeat_n(c, 64)
        .collect::<String>()
        .parse()
        .expect("valid sha256")
}

fn signer() -> SignerIdentity {
    SignerIdentity {
        issuer: "https://token.actions.githubusercontent.com".into(),
        san: "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main".into(),
    }
}

struct Fixture {
    cascade: ProvenanceCascade,
    artifacts: Arc<MockArtifactRepository>,
    storage: Arc<MockStoragePort>,
    lifecycle: Arc<MockArtifactLifecycle>,
    events: Arc<MockEventStore>,
    refs: Arc<MockContentReferenceIndex>,
    repository_id: Uuid,
}

impl Fixture {
    fn new() -> Self {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let events = Arc::new(MockEventStore::new());
        let lifecycle = Arc::new(MockArtifactLifecycle::new(artifacts.clone()));
        let refs = Arc::new(MockContentReferenceIndex::new());
        let cascade = ProvenanceCascade::new(
            artifacts.clone(),
            storage.clone(),
            lifecycle.clone(),
            crate::event_store_publisher::wrap_for_test(events.clone()),
            refs.clone(),
        );
        Self {
            cascade,
            artifacts,
            storage,
            lifecycle,
            events,
            refs,
            repository_id: Uuid::new_v4(),
        }
    }

    /// Seed an artifact with `hash` in the fixture repo at `status`.
    fn seed_artifact(&self, hash: &ContentHash, status: QuarantineStatus) -> Artifact {
        self.seed_artifact_in(self.repository_id, hash, status)
    }

    fn seed_artifact_in(
        &self,
        repository_id: Uuid,
        hash: &ContentHash,
        status: QuarantineStatus,
    ) -> Artifact {
        let mut a: Artifact = sample_artifact(status);
        a.repository_id = repository_id;
        a.sha256_checksum = hash.clone();
        self.artifacts.insert(a.clone());
        a
    }

    /// Seed CAS bytes for `hash`.
    fn seed_bytes(&self, hash: &ContentHash, bytes: Vec<u8>) {
        self.storage.insert_content(hash.clone(), bytes);
    }

    /// Seed one inbound edge: `source` references `target_hash` as `kind`.
    async fn seed_edge(&self, source: Uuid, target_hash: &ContentHash, kind: &str) {
        self.refs
            .insert(ContentReference {
                source_artifact_id: source,
                target_content_hash: target_hash.clone(),
                kind: kind.to_string(),
                metadata: serde_json::Value::Object(serde_json::Map::new()),
                repository_id: self.repository_id,
                recorded_at: chrono::Utc::now(),
            })
            .await
            .expect("seed edge");
    }

    /// Put a `ProvenanceVerified` on `artifact_id`'s stream.
    fn seed_clearance(&self, artifact_id: Uuid, cascaded_from: Option<ContentHash>) {
        self.events.set_stream(
            &StreamId::artifact(artifact_id),
            vec![persisted_verified(artifact_id, cascaded_from)],
        );
    }

    /// Every cascaded `ProvenanceVerified` the lifecycle committed, as
    /// `(constituent artifact id, event)`.
    fn committed(&self) -> Vec<(Uuid, hort_domain::events::ProvenanceVerified)> {
        self.lifecycle
            .committed_transitions()
            .iter()
            .filter_map(|(artifact, batch, _)| match &batch.events[0].event {
                DomainEvent::ProvenanceVerified(e) => Some((artifact.id, e.clone())),
                _ => None,
            })
            .collect()
    }
}

fn persisted_verified(artifact_id: Uuid, cascaded_from: Option<ContentHash>) -> PersistedEvent {
    PersistedEvent {
        event_id: Uuid::new_v4(),
        stream_id: StreamId::artifact(artifact_id),
        stream_position: 0,
        global_position: 0,
        event: DomainEvent::ProvenanceVerified(hort_domain::events::ProvenanceVerified {
            artifact_id,
            content_hash: hexhash('9'),
            backend: "cosign".into(),
            signer: signer(),
            predicate_type: Some("https://slsa.dev/provenance/v1".into()),
            cascaded_from,
        }),
        correlation_id: Uuid::new_v4(),
        causation_id: None,
        actor: system_actor(),
        event_version: 1,
        stored_at: chrono::Utc::now(),
    }
}

/// A single-image manifest body referencing `config` + `layers`.
fn image_manifest_body(config: &ContentHash, layers: &[&ContentHash]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": format!("sha256:{config}"),
            "size": 7,
        },
        "layers": layers
            .iter()
            .map(|l| serde_json::json!({
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": format!("sha256:{l}"),
                "size": 42,
            }))
            .collect::<Vec<_>>(),
    }))
    .expect("manifest json")
}

/// An image-index body whose `manifests[]` children are `children`.
fn image_index_body(children: &[&ContentHash]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": hort_domain::oci::OCI_IMAGE_INDEX_MEDIA_TYPE,
        "manifests": children
            .iter()
            .map(|c| serde_json::json!({
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": format!("sha256:{c}"),
                "size": 528,
                "platform": { "architecture": "amd64", "os": "linux" },
            }))
            .collect::<Vec<_>>(),
    }))
    .expect("index json")
}

// ---------------------------------------------------------------------------
// The two acceptance shapes.
// ---------------------------------------------------------------------------

/// The headline case: a signed index verified earlier; a foreign-platform
/// child manifest arrives afterwards and self-clears against the index's
/// signed bytes. Attribution names the INDEX, not the edge.
#[tokio::test]
async fn late_joining_child_manifest_clears_from_its_directly_verified_index() {
    let f = Fixture::new();
    let (index_hash, child_hash) = (hexhash('1'), hexhash('2'));

    let index = f.seed_artifact(&index_hash, QuarantineStatus::Released);
    f.seed_bytes(&index_hash, image_index_body(&[&child_hash]));
    f.seed_clearance(index.id, None);

    let child = f.seed_artifact(&child_hash, QuarantineStatus::Quarantined);
    f.seed_edge(index.id, &child_hash, "oci_index_member").await;

    let cleared = f
        .cascade
        .resolve_late_joiner_clearance(&child)
        .await
        .expect("the late joiner clears");

    assert_eq!(cleared.subject, index_hash);
    assert_eq!(cleared.backend, "cosign");
    let committed = f.committed();
    assert_eq!(committed.len(), 1, "exactly one clearance appended");
    assert_eq!(committed[0].0, child.id);
    assert_eq!(
        committed[0].1.cascaded_from.as_ref(),
        Some(&index_hash),
        "attribution names the signed subject, never the nominating edge"
    );
    assert_eq!(
        committed[0].1.predicate_type.as_deref(),
        Some("https://slsa.dev/provenance/v1"),
        "the subject's signer + predicate ride the cascaded clearance verbatim"
    );
}

/// The case the literal edge-walk cannot reach: a late-joining LAYER
/// BLOB. Its only inbound edge is its parent child-manifest, which under
/// a signed multi-arch index is itself only cascade-cleared. The walk
/// continues to the directly-verified ROOT the parent's clearance names
/// and checks membership in the ROOT's signed bytes — the same digest the
/// verify-time cascade would have cleared had the blob been present then.
#[tokio::test]
async fn late_joining_layer_blob_clears_from_the_root_behind_a_cascaded_parent() {
    let f = Fixture::new();
    let (index_hash, child_hash) = (hexhash('1'), hexhash('2'));
    let (config_hash, layer_hash) = (hexhash('3'), hexhash('4'));

    let index = f.seed_artifact(&index_hash, QuarantineStatus::Released);
    f.seed_bytes(&index_hash, image_index_body(&[&child_hash]));
    f.seed_clearance(index.id, None);

    // The child manifest is present and CASCADE-cleared (not direct).
    let child = f.seed_artifact(&child_hash, QuarantineStatus::Quarantined);
    f.seed_bytes(
        &child_hash,
        image_manifest_body(&config_hash, &[&layer_hash]),
    );
    f.seed_clearance(child.id, Some(index_hash.clone()));

    let layer = f.seed_artifact(&layer_hash, QuarantineStatus::Quarantined);
    f.seed_edge(child.id, &layer_hash, "oci_layer").await;

    let cleared = f
        .cascade
        .resolve_late_joiner_clearance(&layer)
        .await
        .expect("the late-joining blob clears from the signed root");

    assert_eq!(
        cleared.subject, index_hash,
        "authority is the directly-verified root, not the cascade-cleared parent"
    );
    let committed = f.committed();
    assert_eq!(committed.len(), 1);
    assert_eq!(committed[0].0, layer.id);
    assert_eq!(committed[0].1.cascaded_from.as_ref(), Some(&index_hash));
}

// ---------------------------------------------------------------------------
// Guard arms — every one leaves exactly today's hold.
// ---------------------------------------------------------------------------

/// No verified parent: the nominating edge exists, the source carries no
/// clearance at all. Nothing clears.
#[tokio::test]
async fn a_parent_with_no_clearance_clears_nothing() {
    let f = Fixture::new();
    let (index_hash, child_hash) = (hexhash('1'), hexhash('2'));

    let index = f.seed_artifact(&index_hash, QuarantineStatus::Quarantined);
    f.seed_bytes(&index_hash, image_index_body(&[&child_hash]));

    let child = f.seed_artifact(&child_hash, QuarantineStatus::Quarantined);
    f.seed_edge(index.id, &child_hash, "oci_index_member").await;

    assert!(f
        .cascade
        .resolve_late_joiner_clearance(&child)
        .await
        .is_none());
    assert!(f.committed().is_empty(), "no clearance without a verdict");
}

/// **Projection is not authority.** The DB edge says "this index is my
/// parent" and the index IS directly verified — but its signed bytes do
/// not bind this digest. The edge alone must not clear anything.
#[tokio::test]
async fn an_edge_the_signed_bytes_do_not_bind_clears_nothing() {
    let f = Fixture::new();
    let (index_hash, child_hash, stranger) = (hexhash('1'), hexhash('2'), hexhash('7'));

    let index = f.seed_artifact(&index_hash, QuarantineStatus::Released);
    // The index binds `child_hash` — NOT `stranger`.
    f.seed_bytes(&index_hash, image_index_body(&[&child_hash]));
    f.seed_clearance(index.id, None);

    let outsider = f.seed_artifact(&stranger, QuarantineStatus::Quarantined);
    // A (stale / hand-written) edge nominating the index anyway.
    f.seed_edge(index.id, &stranger, "oci_index_member").await;

    assert!(f
        .cascade
        .resolve_late_joiner_clearance(&outsider)
        .await
        .is_none());
    assert!(
        f.committed().is_empty(),
        "membership is decided by the signed bytes, never by the edge"
    );
}

/// **One-level bound, inherited.** A grandchild of an index-of-indexes is
/// not inside the root's one-level walk, so it stays held — matching the
/// verify-time cascade exactly.
#[tokio::test]
async fn a_grandchild_of_an_index_of_indexes_stays_held() {
    let f = Fixture::new();
    let (root_hash, mid_hash, grandchild) = (hexhash('1'), hexhash('2'), hexhash('3'));

    let root = f.seed_artifact(&root_hash, QuarantineStatus::Released);
    f.seed_bytes(&root_hash, image_index_body(&[&mid_hash]));
    f.seed_clearance(root.id, None);

    // The middle artifact is itself an INDEX; `manifest_blob_digests`
    // yields nothing for it, so the grandchild is never in the root's
    // constituent set.
    let mid = f.seed_artifact(&mid_hash, QuarantineStatus::Quarantined);
    f.seed_bytes(&mid_hash, image_index_body(&[&grandchild]));
    f.seed_clearance(mid.id, Some(root_hash.clone()));

    let gc = f.seed_artifact(&grandchild, QuarantineStatus::Quarantined);
    f.seed_edge(mid.id, &grandchild, "oci_index_member").await;

    assert!(f.cascade.resolve_late_joiner_clearance(&gc).await.is_none());
    assert!(
        f.committed().is_empty(),
        "the signature over the root covers exactly one level of nesting"
    );
}

/// The walk terminates: a root whose OWN clearance is itself cascaded is
/// not a signature anchor, so it can never become authority.
#[tokio::test]
async fn a_root_whose_own_clearance_is_cascaded_is_not_authority() {
    let f = Fixture::new();
    let (root_hash, parent_hash, child_hash) = (hexhash('1'), hexhash('2'), hexhash('3'));

    let root = f.seed_artifact(&root_hash, QuarantineStatus::Quarantined);
    f.seed_bytes(&root_hash, image_index_body(&[&child_hash]));
    f.seed_clearance(root.id, Some(hexhash('8')));

    let parent = f.seed_artifact(&parent_hash, QuarantineStatus::Quarantined);
    f.seed_clearance(parent.id, Some(root_hash.clone()));

    let child = f.seed_artifact(&child_hash, QuarantineStatus::Quarantined);
    f.seed_edge(parent.id, &child_hash, "oci_index_member")
        .await;

    assert!(f
        .cascade
        .resolve_late_joiner_clearance(&child)
        .await
        .is_none());
    assert!(f.committed().is_empty());
}

/// A cascaded parent whose named root has no artifact row in this
/// repository resolves to no authority.
#[tokio::test]
async fn a_cascaded_parent_whose_root_row_is_absent_clears_nothing() {
    let f = Fixture::new();
    let (parent_hash, child_hash) = (hexhash('2'), hexhash('3'));

    let parent = f.seed_artifact(&parent_hash, QuarantineStatus::Quarantined);
    f.seed_clearance(parent.id, Some(hexhash('1'))); // no row for the root

    let child = f.seed_artifact(&child_hash, QuarantineStatus::Quarantined);
    f.seed_edge(parent.id, &child_hash, "oci_index_member")
        .await;

    assert!(f
        .cascade
        .resolve_late_joiner_clearance(&child)
        .await
        .is_none());
    assert!(f.committed().is_empty());
}

/// A cascaded parent whose named root exists but carries no clearance of
/// its own (a purged / re-created root) resolves to no authority.
#[tokio::test]
async fn a_cascaded_parent_whose_root_carries_no_clearance_clears_nothing() {
    let f = Fixture::new();
    let (root_hash, parent_hash, child_hash) = (hexhash('1'), hexhash('2'), hexhash('3'));

    f.seed_artifact(&root_hash, QuarantineStatus::Quarantined);
    f.seed_bytes(&root_hash, image_index_body(&[&child_hash]));

    let parent = f.seed_artifact(&parent_hash, QuarantineStatus::Quarantined);
    f.seed_clearance(parent.id, Some(root_hash.clone()));

    let child = f.seed_artifact(&child_hash, QuarantineStatus::Quarantined);
    f.seed_edge(parent.id, &child_hash, "oci_index_member")
        .await;

    assert!(f
        .cascade
        .resolve_late_joiner_clearance(&child)
        .await
        .is_none());
    assert!(f.committed().is_empty());
}

/// An artifact's own `primary_content` refcount row targets its own hash.
/// Self-clearing off it would be circular authority.
#[tokio::test]
async fn an_artifacts_own_refcount_row_is_never_a_clearance_source() {
    let f = Fixture::new();
    let child_hash = hexhash('2');

    let child = f.seed_artifact(&child_hash, QuarantineStatus::Quarantined);
    f.seed_clearance(child.id, None); // even a DIRECT clearance on itself
    f.seed_edge(child.id, &child_hash, "primary_content").await;

    assert!(f
        .cascade
        .resolve_late_joiner_clearance(&child)
        .await
        .is_none());
    assert!(f.committed().is_empty());
}

/// A DIFFERENT artifact row sharing this artifact's content hash (a
/// same-digest sibling) cannot become its own subject either — the
/// subject-equals-constituent guard refuses before any CAS read.
#[tokio::test]
async fn a_same_digest_sibling_is_not_a_clearance_source() {
    let f = Fixture::new();
    let shared = hexhash('2');

    let sibling = f.seed_artifact(&shared, QuarantineStatus::Released);
    f.seed_clearance(sibling.id, None);

    let late = f.seed_artifact(&shared, QuarantineStatus::Quarantined);
    f.seed_edge(sibling.id, &shared, "oci_index_member").await;

    assert!(f
        .cascade
        .resolve_late_joiner_clearance(&late)
        .await
        .is_none());
    assert!(f.committed().is_empty());
}

/// Clearance never crosses a repository boundary.
#[tokio::test]
async fn a_source_in_another_repository_clears_nothing() {
    let f = Fixture::new();
    let (index_hash, child_hash) = (hexhash('1'), hexhash('2'));

    let index = f.seed_artifact_in(Uuid::new_v4(), &index_hash, QuarantineStatus::Released);
    f.seed_bytes(&index_hash, image_index_body(&[&child_hash]));
    f.seed_clearance(index.id, None);

    let child = f.seed_artifact(&child_hash, QuarantineStatus::Quarantined);
    f.seed_edge(index.id, &child_hash, "oci_index_member").await;

    assert!(f
        .cascade
        .resolve_late_joiner_clearance(&child)
        .await
        .is_none());
    assert!(f.committed().is_empty());
}

/// A failed inbound-edge read attempts no clearance at all — the
/// artifact keeps exactly the hold it already had.
#[tokio::test]
async fn an_edge_read_failure_leaves_the_artifact_held() {
    let f = Fixture::new();
    let child = f.seed_artifact(&hexhash('2'), QuarantineStatus::Quarantined);
    f.refs
        .fail_next_find_by_target(DomainError::Invariant("pg down".into()));

    assert!(f
        .cascade
        .resolve_late_joiner_clearance(&child)
        .await
        .is_none());
    assert!(f.committed().is_empty());
}

/// One unresolvable candidate does not abort the walk: a later candidate
/// still clears. (The first edge names an artifact id with no row.)
#[tokio::test]
async fn an_unresolvable_candidate_is_skipped_and_the_walk_continues() {
    let f = Fixture::new();
    let (index_hash, child_hash) = (hexhash('1'), hexhash('2'));

    f.seed_edge(Uuid::new_v4(), &child_hash, "oci_index_member")
        .await;

    let index = f.seed_artifact(&index_hash, QuarantineStatus::Released);
    f.seed_bytes(&index_hash, image_index_body(&[&child_hash]));
    f.seed_clearance(index.id, None);

    let child = f.seed_artifact(&child_hash, QuarantineStatus::Quarantined);
    f.seed_edge(index.id, &child_hash, "oci_index_member").await;

    let cleared = f
        .cascade
        .resolve_late_joiner_clearance(&child)
        .await
        .expect("the resolvable candidate still clears");
    assert_eq!(cleared.subject, index_hash);
}

/// A subject whose CAS bytes cannot be read yields no membership proof,
/// so nothing clears.
#[tokio::test]
async fn a_subject_whose_cas_bytes_are_unreadable_clears_nothing() {
    let f = Fixture::new();
    let (index_hash, child_hash) = (hexhash('1'), hexhash('2'));

    let index = f.seed_artifact(&index_hash, QuarantineStatus::Released);
    f.seed_clearance(index.id, None);
    f.storage.fail_get_persistent(index_hash.clone());

    let child = f.seed_artifact(&child_hash, QuarantineStatus::Quarantined);
    f.seed_edge(index.id, &child_hash, "oci_index_member").await;

    assert!(f
        .cascade
        .resolve_late_joiner_clearance(&child)
        .await
        .is_none());
    assert!(f.committed().is_empty());
}

/// A subject whose bytes are not an OCI index/manifest binds nothing.
#[tokio::test]
async fn a_subject_whose_bytes_do_not_parse_clears_nothing() {
    let f = Fixture::new();
    let (index_hash, child_hash) = (hexhash('1'), hexhash('2'));

    let index = f.seed_artifact(&index_hash, QuarantineStatus::Released);
    f.seed_bytes(&index_hash, b"not json at all".to_vec());
    f.seed_clearance(index.id, None);

    let child = f.seed_artifact(&child_hash, QuarantineStatus::Quarantined);
    f.seed_edge(index.id, &child_hash, "oci_index_member").await;

    assert!(f
        .cascade
        .resolve_late_joiner_clearance(&child)
        .await
        .is_none());
    assert!(f.committed().is_empty());
}

/// The domain guard still rules: a constituent that is not held takes no
/// cascaded clearance (terminally rejected stays rejected).
#[tokio::test]
async fn a_terminally_rejected_constituent_takes_no_clearance() {
    let f = Fixture::new();
    let (index_hash, child_hash) = (hexhash('1'), hexhash('2'));

    let index = f.seed_artifact(&index_hash, QuarantineStatus::Released);
    f.seed_bytes(&index_hash, image_index_body(&[&child_hash]));
    f.seed_clearance(index.id, None);

    let child = f.seed_artifact(&child_hash, QuarantineStatus::Rejected);
    f.seed_edge(index.id, &child_hash, "oci_index_member").await;

    assert!(f
        .cascade
        .resolve_late_joiner_clearance(&child)
        .await
        .is_none());
    assert!(f.committed().is_empty());
}

/// Idempotent: a constituent already carrying a clearance takes no
/// duplicate (a re-ingest of the same digest re-runs the hook).
#[tokio::test]
async fn an_already_cleared_constituent_takes_no_duplicate() {
    let f = Fixture::new();
    let (index_hash, child_hash) = (hexhash('1'), hexhash('2'));

    let index = f.seed_artifact(&index_hash, QuarantineStatus::Released);
    f.seed_bytes(&index_hash, image_index_body(&[&child_hash]));
    f.seed_clearance(index.id, None);

    let child = f.seed_artifact(&child_hash, QuarantineStatus::Quarantined);
    f.seed_clearance(child.id, Some(index_hash.clone()));
    f.seed_edge(index.id, &child_hash, "oci_index_member").await;

    assert!(f
        .cascade
        .resolve_late_joiner_clearance(&child)
        .await
        .is_none());
    assert!(f.committed().is_empty());
}

/// The version-conflict retry: a concurrent append between the read and
/// the commit is retried ONCE with a fresh read, and the clearance lands.
#[tokio::test]
async fn a_version_conflict_retries_once_and_still_clears() {
    let f = Fixture::new();
    let (index_hash, child_hash) = (hexhash('1'), hexhash('2'));

    let index = f.seed_artifact(&index_hash, QuarantineStatus::Released);
    f.seed_bytes(&index_hash, image_index_body(&[&child_hash]));
    f.seed_clearance(index.id, None);

    let child = f.seed_artifact(&child_hash, QuarantineStatus::Quarantined);
    f.seed_edge(index.id, &child_hash, "oci_index_member").await;
    f.lifecycle
        .fail_next_commit(DomainError::Conflict("stream moved".into()));

    let cleared = f
        .cascade
        .resolve_late_joiner_clearance(&child)
        .await
        .expect("the retry commits");
    assert_eq!(cleared.subject, index_hash);
    assert_eq!(f.committed().len(), 1, "exactly one clearance, not two");
}

/// A SECOND conflict gives up — best-effort, the artifact stays held.
#[tokio::test]
async fn a_second_version_conflict_gives_up_and_leaves_the_artifact_held() {
    let f = Fixture::new();
    let (index_hash, child_hash) = (hexhash('1'), hexhash('2'));

    let index = f.seed_artifact(&index_hash, QuarantineStatus::Released);
    f.seed_bytes(&index_hash, image_index_body(&[&child_hash]));
    f.seed_clearance(index.id, None);

    let child = f.seed_artifact(&child_hash, QuarantineStatus::Quarantined);
    f.seed_edge(index.id, &child_hash, "oci_index_member").await;
    f.lifecycle
        .fail_next_commit(DomainError::Conflict("stream moved".into()));
    f.lifecycle
        .fail_next_commit(DomainError::Conflict("stream moved again".into()));

    assert!(f
        .cascade
        .resolve_late_joiner_clearance(&child)
        .await
        .is_none());
    assert!(f.committed().is_empty());
}

/// A NON-conflict append failure is not retried and never propagates —
/// the ingest that called this must not observe it.
#[tokio::test]
async fn a_non_conflict_append_failure_is_swallowed() {
    let f = Fixture::new();
    let (index_hash, child_hash) = (hexhash('1'), hexhash('2'));

    let index = f.seed_artifact(&index_hash, QuarantineStatus::Released);
    f.seed_bytes(&index_hash, image_index_body(&[&child_hash]));
    f.seed_clearance(index.id, None);

    let child = f.seed_artifact(&child_hash, QuarantineStatus::Quarantined);
    f.seed_edge(index.id, &child_hash, "oci_index_member").await;
    f.lifecycle
        .fail_next_commit(DomainError::Invariant("pg down".into()));

    assert!(f
        .cascade
        .resolve_late_joiner_clearance(&child)
        .await
        .is_none());
    assert!(f.committed().is_empty());
}

/// Two edges from the SAME source are one candidate: the source's stream
/// is read once, not once per edge.
#[tokio::test]
async fn duplicate_edges_from_one_source_resolve_that_source_once() {
    let f = Fixture::new();
    let (index_hash, child_hash) = (hexhash('1'), hexhash('2'));

    let index = f.seed_artifact(&index_hash, QuarantineStatus::Quarantined);
    // No clearance on the source, so the walk ends after the stream read
    // — which makes the read count the exact observable.
    let child = f.seed_artifact(&child_hash, QuarantineStatus::Quarantined);
    f.seed_edge(index.id, &child_hash, "oci_index_member").await;
    f.seed_edge(index.id, &child_hash, "oci_config").await;

    let before = f.events.read_stream_call_count();
    assert!(f
        .cascade
        .resolve_late_joiner_clearance(&child)
        .await
        .is_none());
    assert_eq!(
        f.events.read_stream_call_count() - before,
        1,
        "a candidate subject is resolved once regardless of how many edges name it"
    );
}

/// No inbound edges at all (a top-level artifact) — nothing to look up.
#[tokio::test]
async fn an_artifact_with_no_inbound_edges_clears_nothing() {
    let f = Fixture::new();
    let child = f.seed_artifact(&hexhash('2'), QuarantineStatus::Quarantined);

    assert!(f
        .cascade
        .resolve_late_joiner_clearance(&child)
        .await
        .is_none());
    assert!(f.committed().is_empty());
}

/// A single-image (non-index) signed manifest is authority for its own
/// config/layer blobs — the late-joiner walk handles the non-index shape
/// through the same `constituent_digests` branch.
#[tokio::test]
async fn a_late_joining_blob_clears_from_a_signed_single_image_manifest() {
    let f = Fixture::new();
    let (manifest_hash, config_hash, layer_hash) = (hexhash('1'), hexhash('3'), hexhash('4'));

    let manifest = f.seed_artifact(&manifest_hash, QuarantineStatus::Released);
    f.seed_bytes(
        &manifest_hash,
        image_manifest_body(&config_hash, &[&layer_hash]),
    );
    f.seed_clearance(manifest.id, None);

    let layer = f.seed_artifact(&layer_hash, QuarantineStatus::Quarantined);
    f.seed_edge(manifest.id, &layer_hash, "oci_layer").await;

    let cleared = f
        .cascade
        .resolve_late_joiner_clearance(&layer)
        .await
        .expect("a signed single-image manifest clears its own blobs");
    assert_eq!(cleared.subject, manifest_hash);
}
