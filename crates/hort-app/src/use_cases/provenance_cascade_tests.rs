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
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::content_reference_index::{ContentReference, ContentReferenceIndex};
use hort_domain::ports::provenance::{ProvenanceVerdict, SignerIdentity};
use hort_domain::types::ContentHash;

use super::{build_bundle, decode_simplesigning_signature, ProvenanceCascade};
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

// ---------------------------------------------------------------------------
// Bundle carriage — the two shapes `referrer_bundles` reads off a referrer
// manifest, and the wrapping that lets the keyed and keyless verifiers
// self-select. These moved here with the functions they pin, when the
// per-referrer extraction became shared between the verify path's bundle
// fetch and the D8 signature-material walk.
// ---------------------------------------------------------------------------

/// `decode_simplesigning_signature` (ADR 0039 §8): standard base64 → raw bytes;
/// whitespace trimmed; non-base64 → `None` (the carriage skips it).
#[test]
fn decode_simplesigning_signature_decodes_b64_and_rejects_garbage() {
    use base64::Engine as _;
    let raw: &[u8] = b"\x30\x45\x02\x21\x00sigbytes";
    let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
    assert_eq!(decode_simplesigning_signature(&b64).as_deref(), Some(raw));
    assert_eq!(
        decode_simplesigning_signature(&format!("  {b64}\n")).as_deref(),
        Some(raw),
        "annotation whitespace is trimmed"
    );
    assert_eq!(decode_simplesigning_signature("!!!not base64!!!"), None);
}

/// A minimal keyed cosign v3 Sigstore v0.3 bundle (bare `publicKey`, DSSE
/// envelope over an in-toto Statement binding `digest_hex`), signed opaquely.
fn keyed_v03_bundle_json(digest_hex: &str, sig_bytes: &[u8]) -> Vec<u8> {
    use base64::Engine as _;
    let eng = base64::engine::general_purpose::STANDARD;
    let statement = serde_json::json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [ { "digest": { "sha256": digest_hex }, "annotations": {} } ],
        "predicateType": "https://sigstore.dev/cosign/sign/v1"
    })
    .to_string();
    serde_json::json!({
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": { "publicKey": { "hint": "abc" } },
        "dsseEnvelope": {
            "payload": eng.encode(statement.as_bytes()),
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [ { "sig": eng.encode(sig_bytes) } ]
        }
    })
    .to_string()
    .into_bytes()
}

/// `build_bundle` (ADR 0039 §8): a cosign v3 keyed v0.3 bundle is wrapped
/// `new_signed` (the keyed verifier's) carrying the raw DSSE signature, so the
/// two verifiers self-select by signature-presence.
#[test]
fn build_bundle_wraps_keyed_v03_as_signed_with_the_dsse_signature() {
    let digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let raw_sig = vec![0x30, 0x44, 0x02, 0x20, 0xde, 0xad];
    let bundle_json = keyed_v03_bundle_json(digest, &raw_sig);
    let bundle = build_bundle(bundle_json.clone());
    assert_eq!(
        bundle.signature.as_deref(),
        Some(raw_sig.as_slice()),
        "a keyed v0.3 bundle carries its raw DSSE signature so the keyed verifier claims it"
    );
    assert_eq!(bundle.bytes, bundle_json, "bytes stay the full bundle blob");
}

/// A keyless (Fulcio-cert) v0.3 bundle is wrapped `new` (`signature == None`)
/// — the Sigstore verifier's, byte-for-byte the prior behaviour.
#[test]
fn build_bundle_wraps_keyless_cert_bundle_as_unsigned() {
    let keyless = br#"{
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": { "certificate": { "rawBytes": "AAAA" } },
        "dsseEnvelope": {
            "payload": "eyJzdWJqZWN0IjpbeyJkaWdlc3QiOnsic2hhMjU2IjoiYWEifX1dfQ==",
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [ { "sig": "AAAA" } ]
        }
    }"#
    .to_vec();
    let bundle = build_bundle(keyless.clone());
    assert_eq!(
        bundle.signature, None,
        "a keyless bundle stays unsigned (the Sigstore verifier's)"
    );
    assert_eq!(bundle.bytes, keyless);
}

/// A bundle the keyed extractor cannot claim (not a bundle at all, or a
/// keyed-shaped bundle with undecodable DSSE material) is wrapped `new` — the
/// Sigstore verifier folds a truly malformed one to BundleMalformed; a
/// non-keyed one is simply its shape. Never routed to the keyed verifier.
#[test]
fn build_bundle_wraps_unclaimable_bytes_as_unsigned() {
    // Not a bundle object at all.
    let b1 = build_bundle(b"not a bundle".to_vec());
    assert_eq!(b1.signature, None);
    // Keyed-shaped but the DSSE payload is not valid base64 → extractor errs →
    // routed unsigned (never keyed).
    let malformed_keyed = br#"{"verificationMaterial":{"publicKey":{"hint":"x"}},"dsseEnvelope":{"payload":"!!nob64!!","payloadType":"application/vnd.in-toto+json","signatures":[{"sig":"AA=="}]}}"#.to_vec();
    let b2 = build_bundle(malformed_keyed);
    assert_eq!(
        b2.signature, None,
        "an unparseable-as-keyed bundle is not routed to the keyed verifier"
    );
}

// ===========================================================================
// Signature-material end (ADR 0039 D8) — the constituents of the signature
// that verified a subject.
//
// Every arm but the acceptances leaves exactly today's hold: the artifact
// keeps the `NoAttestation` × `Required` hold it already had, and nothing is
// committed. The decoy arm is the security proof — a manifest that passes
// §8's purity classifiers and names an ordinary layer must clear nothing,
// because a blob has ONE row and ONE status per repository, so a clearance
// resolved from a pusher's declaration would serve an unsigned layer to every
// consumer of that repository.
// ===========================================================================

/// A verifier whose verdict is keyed on the **subject digest** it is
/// handed, which is what separates a real signature manifest from a decoy:
/// both are handed to the same port, and only the subject whose signature
/// this verifier actually holds is accepted.
struct SubjectKeyedVerifier {
    /// Subject content hashes this verifier accepts (`Verified`).
    accepts: Vec<ContentHash>,
    /// Behaviour for every other subject.
    otherwise: UnacceptedAs,
    /// `(subject hex, bundle count)` per `verify` call, in order.
    calls: std::sync::Mutex<Vec<(String, usize)>>,
}

/// What [`SubjectKeyedVerifier`] answers for a subject it does not accept.
#[derive(Clone, Copy)]
enum UnacceptedAs {
    /// "nothing here signed this" — the shape a real verifier produces for
    /// a bundle that does not bind the subject.
    NoAttestation,
    /// A positive disproof — present but invalid.
    Rejected,
    /// An adapter / infra fault.
    Error,
}

impl SubjectKeyedVerifier {
    fn accepting(subject: &ContentHash) -> Arc<Self> {
        Arc::new(Self {
            accepts: vec![subject.clone()],
            otherwise: UnacceptedAs::NoAttestation,
            calls: std::sync::Mutex::new(Vec::new()),
        })
    }

    fn answering(otherwise: UnacceptedAs) -> Arc<Self> {
        Arc::new(Self {
            accepts: Vec::new(),
            otherwise,
            calls: std::sync::Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> Vec<(String, usize)> {
        self.calls.lock().unwrap().clone()
    }
}

impl hort_domain::ports::provenance::ProvenancePort for SubjectKeyedVerifier {
    fn name(&self) -> &str {
        "cosign"
    }

    fn applies_to(&self, format: &str) -> bool {
        format == "oci"
    }

    fn verify<'a>(
        &'a self,
        subject: &'a hort_domain::ports::provenance::ProvenanceSubject<'a>,
        bundles: &'a [hort_domain::ports::provenance::AttestationBundle],
        _policy: &'a hort_domain::ports::provenance::ProvenanceRequirements<'a>,
    ) -> hort_domain::ports::BoxFuture<'a, hort_domain::error::DomainResult<ProvenanceVerdict>>
    {
        self.calls
            .lock()
            .unwrap()
            .push((subject.content_hash.as_ref().to_owned(), bundles.len()));
        let accepted = self.accepts.iter().any(|h| h == subject.content_hash);
        let otherwise = self.otherwise;
        Box::pin(async move {
            if accepted {
                return Ok(ProvenanceVerdict::verified(
                    signer(),
                    Some("https://sigstore.dev/cosign/sign/v1".to_string()),
                ));
            }
            match otherwise {
                UnacceptedAs::NoAttestation => Ok(ProvenanceVerdict::no_attestation()),
                UnacceptedAs::Rejected => Ok(ProvenanceVerdict::rejected(
                    hort_domain::ports::provenance::ProvenanceRejectReason::UntrustedIdentity,
                )),
                UnacceptedAs::Error => Err(DomainError::Invariant("verifier infra fault".into())),
            }
        })
    }

    fn health_check(
        &self,
    ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<()>> {
        Box::pin(async { Ok(()) })
    }
}

/// A cosign **signature manifest** body: the `{}` config blob, one layer
/// of signature material, and (when `subject` is `Some`) the `subject`
/// descriptor the Referrers flow carries. `layer_media_type` selects the
/// carriage — keyless Sigstore v0.3 bundle or keyed `simplesigning`.
fn signature_manifest_body(
    subject: Option<&ContentHash>,
    config: &ContentHash,
    layer: &ContentHash,
    layer_media_type: &str,
    layer_annotations: &serde_json::Value,
) -> Vec<u8> {
    let mut body = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        // The referrers-flow `artifactType` mirrors the carriage, as cosign
        // writes it — so the keyed shape is NOT also read as a keyless bundle
        // through `sigstore_bundle_layers`' artifactType fallback.
        "artifactType": layer_media_type,
        "config": {
            "mediaType": "application/vnd.oci.empty.v1+json",
            "digest": format!("sha256:{config}"),
            "size": 2,
        },
        "layers": [{
            "mediaType": layer_media_type,
            "digest": format!("sha256:{layer}"),
            "size": 512,
            "annotations": layer_annotations.clone(),
        }],
    });
    if let Some(s) = subject {
        body["subject"] = serde_json::json!({
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": format!("sha256:{s}"),
            "size": 528,
        });
    }
    serde_json::to_vec(&body).expect("signature manifest json")
}

/// The keyless shape, which is what `cosign sign` produces today.
fn keyless_signature_manifest_body(
    subject: Option<&ContentHash>,
    config: &ContentHash,
    bundle_layer: &ContentHash,
) -> Vec<u8> {
    signature_manifest_body(
        subject,
        config,
        bundle_layer,
        hort_domain::oci::SIGSTORE_BUNDLE_MEDIA_TYPE,
        &serde_json::json!({}),
    )
}

/// The whole keyless scenario, seeded: a verified-able subject image, a
/// signature manifest over it carrying one bundle layer, the `{}` config
/// blob and the payload layer as held blob rows, and the `oci_config` /
/// `oci_layer` edges the manifest PUT commits.
struct SignatureScene {
    subject_hash: ContentHash,
    manifest_hash: ContentHash,
    config: Artifact,
    bundle_layer: Artifact,
}

impl Fixture {
    /// Seed the keyless scene. `subject_in_manifest` controls whether the
    /// signature manifest declares its `subject` descriptor at all (a
    /// legacy tag-scheme `.sig` declares none).
    async fn seed_signature_scene(&self, subject_in_manifest: bool) -> SignatureScene {
        let (subject_hash, manifest_hash) = (hexhash('1'), hexhash('2'));
        let (config_hash, bundle_hash) = (hexhash('3'), hexhash('4'));

        // The subject image: its bytes are what the verifier is handed.
        self.seed_artifact(&subject_hash, QuarantineStatus::Quarantined);
        self.seed_bytes(&subject_hash, image_manifest_body(&hexhash('a'), &[]));

        // The signature manifest — status `None`, never provenance-verified
        // (ADR 0039 §8's narrow signature ingest), which is exactly why
        // neither of the other two cascade ends can reach its constituents.
        let manifest_bytes = keyless_signature_manifest_body(
            subject_in_manifest.then_some(&subject_hash),
            &config_hash,
            &bundle_hash,
        );
        let manifest = self.seed_artifact(&manifest_hash, QuarantineStatus::None);
        self.seed_bytes(&manifest_hash, manifest_bytes);

        // The bundle blob lives at its own content hash (= the layer digest).
        self.seed_bytes(&bundle_hash, b"the-sigstore-bundle-json".to_vec());

        // The two constituents, held, with the edges the PUT committed.
        let config = self.seed_artifact(&config_hash, QuarantineStatus::Quarantined);
        let bundle_layer = self.seed_artifact(&bundle_hash, QuarantineStatus::Quarantined);
        self.seed_edge(manifest.id, &config_hash, "oci_config")
            .await;
        self.seed_edge(manifest.id, &bundle_hash, "oci_layer").await;

        SignatureScene {
            subject_hash,
            manifest_hash,
            config,
            bundle_layer,
        }
    }

    /// Run the D8 resolution with `verifiers`, no allowed-identity
    /// patterns (the verifier mocks here do not consult them).
    async fn resolve_signature_material(
        &self,
        artifact: &Artifact,
        verifiers: &[&Arc<dyn hort_domain::ports::provenance::ProvenancePort>],
    ) -> Option<super::SignatureMaterialClearance> {
        let requirements = hort_domain::ports::provenance::ProvenanceRequirements {
            allowed_identities: &[],
        };
        self.cascade
            .resolve_signature_material_clearance(artifact, verifiers, &requirements)
            .await
    }
}

/// Collapse `Arc<SubjectKeyedVerifier>` into the borrowed port slice the
/// resolution takes, matching how `verify_artifact` builds `applicable`.
fn ports(
    v: &Arc<SubjectKeyedVerifier>,
) -> Vec<Arc<dyn hort_domain::ports::provenance::ProvenancePort>> {
    vec![v.clone() as Arc<dyn hort_domain::ports::provenance::ProvenancePort>]
}

// ---------------------------------------------------------------------------
// The acceptances.
// ---------------------------------------------------------------------------

/// The headline case: the signature **payload layer** of a manifest whose
/// bundle verifies the subject it names is cleared, with the signature
/// manifest as the recorded authority.
#[tokio::test]
async fn a_signature_payload_layer_clears_from_the_signature_that_verified_its_subject() {
    let f = Fixture::new();
    let scene = f.seed_signature_scene(true).await;
    let verifier = SubjectKeyedVerifier::accepting(&scene.subject_hash);
    let owned = ports(&verifier);

    let cleared = f
        .resolve_signature_material(&scene.bundle_layer, &owned.iter().collect::<Vec<_>>())
        .await
        .expect("the payload layer clears");

    assert_eq!(cleared.signature_manifest, scene.manifest_hash);
    assert_eq!(cleared.subject, scene.subject_hash);
    assert_eq!(cleared.backend, "cosign");

    let committed = f.committed();
    assert_eq!(committed.len(), 1, "exactly one clearance appended");
    assert_eq!(committed[0].0, scene.bundle_layer.id);
    assert_eq!(
        committed[0].1.cascaded_from.as_ref(),
        Some(&scene.manifest_hash),
        "attribution names the signature manifest whose bytes bind this digest, \
         not the subject it verified and not the nominating edge",
    );
    assert_eq!(
        committed[0].1.predicate_type.as_deref(),
        Some("https://sigstore.dev/cosign/sign/v1"),
        "the accepted signature's signer + predicate ride the clearance",
    );

    // The verifier was asked about the SUBJECT, over the manifest's one
    // bundle — not about the constituent, which can never be signed.
    assert_eq!(
        verifier.calls(),
        vec![(scene.subject_hash.as_ref().to_owned(), 1)],
    );
}

/// The `{}` config blob clears on the same authority — it is in the
/// manifest's config+layers set, and it is the row shared by every cosign
/// signature in the repository.
#[tokio::test]
async fn the_empty_config_blob_of_a_signature_manifest_clears_too() {
    let f = Fixture::new();
    let scene = f.seed_signature_scene(true).await;
    let verifier = SubjectKeyedVerifier::accepting(&scene.subject_hash);
    let owned = ports(&verifier);

    let cleared = f
        .resolve_signature_material(&scene.config, &owned.iter().collect::<Vec<_>>())
        .await
        .expect("the config blob clears");

    assert_eq!(cleared.signature_manifest, scene.manifest_hash);
    let committed = f.committed();
    assert_eq!(committed.len(), 1);
    assert_eq!(committed[0].0, scene.config.id);
    assert_eq!(
        committed[0].1.cascaded_from.as_ref(),
        Some(&scene.manifest_hash)
    );
}

/// The keyed `simplesigning` carriage reaches the same clearance: the
/// payload layer is read as the bundle and the detached signature comes
/// off the layer annotation.
#[tokio::test]
async fn the_keyed_simplesigning_carriage_clears_its_payload_layer() {
    use base64::Engine as _;
    let f = Fixture::new();
    let (subject_hash, manifest_hash) = (hexhash('1'), hexhash('2'));
    let (config_hash, payload_hash) = (hexhash('3'), hexhash('4'));

    f.seed_artifact(&subject_hash, QuarantineStatus::Quarantined);
    f.seed_bytes(&subject_hash, image_manifest_body(&hexhash('a'), &[]));

    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(b"\x30\x45raw-sig");
    let manifest_bytes = signature_manifest_body(
        Some(&subject_hash),
        &config_hash,
        &payload_hash,
        hort_domain::oci::COSIGN_SIMPLESIGNING_MEDIA_TYPE,
        &serde_json::json!({ hort_domain::oci::COSIGN_SIGNATURE_ANNOTATION: sig_b64 }),
    );
    let manifest = f.seed_artifact(&manifest_hash, QuarantineStatus::None);
    f.seed_bytes(&manifest_hash, manifest_bytes);
    f.seed_bytes(&payload_hash, b"{\"critical\":{}}".to_vec());

    let payload = f.seed_artifact(&payload_hash, QuarantineStatus::Quarantined);
    f.seed_edge(manifest.id, &payload_hash, "oci_layer").await;

    let verifier = SubjectKeyedVerifier::accepting(&subject_hash);
    let owned = ports(&verifier);
    let cleared = f
        .resolve_signature_material(&payload, &owned.iter().collect::<Vec<_>>())
        .await
        .expect("the keyed payload layer clears");

    assert_eq!(cleared.signature_manifest, manifest_hash);
    assert_eq!(
        verifier.calls(),
        vec![(subject_hash.as_ref().to_owned(), 1)],
        "the keyed carriage yields exactly one signed bundle",
    );
}

// ---------------------------------------------------------------------------
// The decoy — this rule's security proof.
// ---------------------------------------------------------------------------

/// **The decoy.** A manifest that passes §8's purity classifiers, declares
/// a subject, and names an ORDINARY layer as its constituent — but whose
/// bundle does not verify that subject. The layer stays held.
///
/// A blob has one artifact row and one quarantine status per hort
/// repository (`blobs/sha256:<hex>`, unique on `(repository_id, path)`,
/// with no OCI name component), so clearing it clears it for every image
/// in the repository. If the declaration were the authority, this push
/// would serve an unsigned layer to every consumer of that repository.
/// Delete the verification step from
/// `try_clear_from_signature_manifest` and this test is the one that
/// fails.
#[tokio::test]
async fn a_signature_shaped_manifest_whose_bundle_does_not_verify_clears_nothing() {
    let f = Fixture::new();
    let (subject_hash, manifest_hash) = (hexhash('1'), hexhash('2'));
    let (config_hash, victim_hash) = (hexhash('3'), hexhash('5'));

    // A real image the attacker does not have a signature for.
    f.seed_artifact(&subject_hash, QuarantineStatus::Quarantined);
    f.seed_bytes(&subject_hash, image_manifest_body(&hexhash('a'), &[]));

    // A pure-signature-shaped manifest naming the victim layer as its
    // "bundle" layer — every layer carries the bundle media type, so both
    // §8 purity classifiers accept it.
    let manifest_bytes =
        keyless_signature_manifest_body(Some(&subject_hash), &config_hash, &victim_hash);
    let manifest = f.seed_artifact(&manifest_hash, QuarantineStatus::None);
    f.seed_bytes(&manifest_hash, manifest_bytes);

    // The victim: an ordinary layer, present in CAS, held under Required.
    let victim = f.seed_artifact(&victim_hash, QuarantineStatus::Quarantined);
    f.seed_bytes(&victim_hash, b"malware.tar.gz".to_vec());
    f.seed_edge(manifest.id, &victim_hash, "oci_layer").await;

    // The verifier holds no signature for this subject — the only honest
    // answer a real one can give for a bundle that does not bind it.
    let verifier = SubjectKeyedVerifier::answering(UnacceptedAs::NoAttestation);
    let owned = ports(&verifier);

    assert!(
        f.resolve_signature_material(&victim, &owned.iter().collect::<Vec<_>>())
            .await
            .is_none(),
        "a manifest SHAPED like a signature clears nothing; only a verified \
         signature does",
    );
    assert!(f.committed().is_empty(), "the victim layer stays held");
    assert_eq!(
        verifier.calls().len(),
        1,
        "the verification really ran — the refusal is the verdict, not a \
         short-circuit before it",
    );
}

/// The same decoy with the verifier answering a positive disproof instead
/// of "unsigned": still no clearance, and still no retraction — the
/// artifact keeps exactly the hold it had.
#[tokio::test]
async fn a_bundle_the_verifier_rejects_clears_nothing() {
    let f = Fixture::new();
    let scene = f.seed_signature_scene(true).await;
    let verifier = SubjectKeyedVerifier::answering(UnacceptedAs::Rejected);
    let owned = ports(&verifier);

    assert!(f
        .resolve_signature_material(&scene.bundle_layer, &owned.iter().collect::<Vec<_>>())
        .await
        .is_none());
    assert!(f.committed().is_empty());
}

// ---------------------------------------------------------------------------
// Fail-closed arms — one per failure direction.
// ---------------------------------------------------------------------------

/// A verifier infra fault is "no clearance", never a clearance and never a
/// rejection.
#[tokio::test]
async fn a_verifier_error_clears_nothing() {
    let f = Fixture::new();
    let scene = f.seed_signature_scene(true).await;
    let verifier = SubjectKeyedVerifier::answering(UnacceptedAs::Error);
    let owned = ports(&verifier);

    assert!(f
        .resolve_signature_material(&scene.bundle_layer, &owned.iter().collect::<Vec<_>>())
        .await
        .is_none());
    assert!(f.committed().is_empty());
}

/// A candidate whose CAS bytes cannot be read: no purity decision is
/// possible, so no clearance.
#[tokio::test]
async fn a_candidate_whose_cas_bytes_are_unreadable_clears_nothing() {
    let f = Fixture::new();
    let scene = f.seed_signature_scene(true).await;
    f.storage.fail_get_persistent(scene.manifest_hash.clone());
    let verifier = SubjectKeyedVerifier::accepting(&scene.subject_hash);
    let owned = ports(&verifier);

    assert!(f
        .resolve_signature_material(&scene.bundle_layer, &owned.iter().collect::<Vec<_>>())
        .await
        .is_none());
    assert!(f.committed().is_empty());
    assert!(
        verifier.calls().is_empty(),
        "nothing is verified when the candidate cannot be classified",
    );
}

/// A candidate whose bytes do not parse as a manifest at all.
#[tokio::test]
async fn an_unparseable_candidate_clears_nothing() {
    let f = Fixture::new();
    let scene = f.seed_signature_scene(true).await;
    f.seed_bytes(&scene.manifest_hash, b"not json at all".to_vec());
    let verifier = SubjectKeyedVerifier::accepting(&scene.subject_hash);
    let owned = ports(&verifier);

    assert!(f
        .resolve_signature_material(&scene.bundle_layer, &owned.iter().collect::<Vec<_>>())
        .await
        .is_none());
    assert!(f.committed().is_empty());
}

/// A candidate that is NOT a pure signature manifest — an ordinary image
/// manifest, and the mixed manifest §8's purity requirement exists to
/// refuse (one bundle layer plus one runnable `tar+gzip` layer).
#[tokio::test]
async fn a_candidate_that_is_not_a_pure_signature_manifest_clears_nothing() {
    for manifest_bytes in [
        // An ordinary image manifest binding the same blob.
        image_manifest_body(&hexhash('3'), &[&hexhash('4')]),
        // Mixed: a bundle layer AND a runnable layer. Not pure.
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "subject": { "digest": format!("sha256:{}", hexhash('1')) },
            "config": { "digest": format!("sha256:{}", hexhash('3')) },
            "layers": [
                { "mediaType": hort_domain::oci::SIGSTORE_BUNDLE_MEDIA_TYPE,
                  "digest": format!("sha256:{}", hexhash('4')) },
                { "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                  "digest": format!("sha256:{}", hexhash('6')) },
            ],
        }))
        .expect("json"),
    ] {
        let f = Fixture::new();
        let scene = f.seed_signature_scene(true).await;
        f.seed_bytes(&scene.manifest_hash, manifest_bytes);
        let verifier = SubjectKeyedVerifier::accepting(&scene.subject_hash);
        let owned = ports(&verifier);

        assert!(f
            .resolve_signature_material(&scene.bundle_layer, &owned.iter().collect::<Vec<_>>())
            .await
            .is_none());
        assert!(f.committed().is_empty());
    }
}

/// **Projection is not authority**, carried to this rule: the edge
/// nominates a real, verifiable signature manifest, but that manifest's
/// bytes do not bind this artifact's digest. The edge alone clears
/// nothing.
#[tokio::test]
async fn a_candidate_whose_bytes_do_not_bind_the_digest_clears_nothing() {
    let f = Fixture::new();
    let scene = f.seed_signature_scene(true).await;

    // A stranger blob with a (stale / hand-written) edge from the very same
    // signature manifest, whose config+layers set does not contain it.
    let stranger = f.seed_artifact(&hexhash('7'), QuarantineStatus::Quarantined);
    f.seed_edge(
        f.artifacts
            .find_by_repo_and_checksum(f.repository_id, &scene.manifest_hash)
            .await
            .expect("lookup")
            .expect("the manifest row")
            .id,
        &hexhash('7'),
        "oci_layer",
    )
    .await;

    let verifier = SubjectKeyedVerifier::accepting(&scene.subject_hash);
    let owned = ports(&verifier);
    assert!(f
        .resolve_signature_material(&stranger, &owned.iter().collect::<Vec<_>>())
        .await
        .is_none());
    assert!(f.committed().is_empty());
}

/// A candidate declaring no `subject` descriptor — the legacy cosign
/// tag-scheme `.sig`, whose subject binding lives in the tag name. There
/// is nothing in the bytes to verify against, so nothing clears.
#[tokio::test]
async fn a_candidate_with_no_subject_descriptor_clears_nothing() {
    let f = Fixture::new();
    let scene = f.seed_signature_scene(false).await;
    let verifier = SubjectKeyedVerifier::accepting(&scene.subject_hash);
    let owned = ports(&verifier);

    assert!(f
        .resolve_signature_material(&scene.bundle_layer, &owned.iter().collect::<Vec<_>>())
        .await
        .is_none());
    assert!(f.committed().is_empty());
    assert!(
        verifier.calls().is_empty(),
        "no subject resolves, so no verification is attempted",
    );
}

/// A candidate whose declared subject's preimage is not in CAS: the
/// verifier cannot be handed the bytes its verdict is about.
#[tokio::test]
async fn a_subject_preimage_that_cannot_be_read_clears_nothing() {
    let f = Fixture::new();
    let scene = f.seed_signature_scene(true).await;
    f.storage.fail_get_persistent(scene.subject_hash.clone());
    let verifier = SubjectKeyedVerifier::accepting(&scene.subject_hash);
    let owned = ports(&verifier);

    assert!(f
        .resolve_signature_material(&scene.bundle_layer, &owned.iter().collect::<Vec<_>>())
        .await
        .is_none());
    assert!(f.committed().is_empty());
    assert!(verifier.calls().is_empty());
}

/// A candidate whose bundle blob the manifest references but CAS does not
/// hold: no bundle material, no clearance.
#[tokio::test]
async fn a_candidate_whose_bundle_blob_is_missing_clears_nothing() {
    let f = Fixture::new();
    let scene = f.seed_signature_scene(true).await;
    f.storage
        .fail_get_persistent(scene.bundle_layer.sha256_checksum.clone());
    let verifier = SubjectKeyedVerifier::accepting(&scene.subject_hash);
    let owned = ports(&verifier);

    assert!(f
        .resolve_signature_material(&scene.bundle_layer, &owned.iter().collect::<Vec<_>>())
        .await
        .is_none());
    assert!(f.committed().is_empty());
}

/// A pure `simplesigning` candidate whose layer carries no signature
/// annotation: the carriage yields no bundle at all, so there is nothing
/// to verify.
#[tokio::test]
async fn a_simplesigning_candidate_with_no_signature_annotation_clears_nothing() {
    let f = Fixture::new();
    let (subject_hash, manifest_hash) = (hexhash('1'), hexhash('2'));
    let (config_hash, payload_hash) = (hexhash('3'), hexhash('4'));

    f.seed_artifact(&subject_hash, QuarantineStatus::Quarantined);
    f.seed_bytes(&subject_hash, image_manifest_body(&hexhash('a'), &[]));
    let manifest_bytes = signature_manifest_body(
        Some(&subject_hash),
        &config_hash,
        &payload_hash,
        hort_domain::oci::COSIGN_SIMPLESIGNING_MEDIA_TYPE,
        &serde_json::json!({}),
    );
    let manifest = f.seed_artifact(&manifest_hash, QuarantineStatus::None);
    f.seed_bytes(&manifest_hash, manifest_bytes);
    f.seed_bytes(&payload_hash, b"{}".to_vec());
    let payload = f.seed_artifact(&payload_hash, QuarantineStatus::Quarantined);
    f.seed_edge(manifest.id, &payload_hash, "oci_layer").await;

    let verifier = SubjectKeyedVerifier::accepting(&subject_hash);
    let owned = ports(&verifier);
    assert!(f
        .resolve_signature_material(&payload, &owned.iter().collect::<Vec<_>>())
        .await
        .is_none());
    assert!(f.committed().is_empty());
    assert!(verifier.calls().is_empty());
}

/// No candidate parent at all — an ordinary blob nobody references. The
/// negative case of the whole rule.
#[tokio::test]
async fn an_artifact_with_no_candidate_parent_clears_nothing() {
    let f = Fixture::new();
    let orphan = f.seed_artifact(&hexhash('8'), QuarantineStatus::Quarantined);
    let verifier = SubjectKeyedVerifier::accepting(&hexhash('1'));
    let owned = ports(&verifier);

    assert!(f
        .resolve_signature_material(&orphan, &owned.iter().collect::<Vec<_>>())
        .await
        .is_none());
    assert!(f.committed().is_empty());
    assert!(verifier.calls().is_empty());
}

/// An empty verifier set (a composition-root mis-registration) clears
/// nothing — fail-closed, like every other direction.
#[tokio::test]
async fn no_applicable_verifier_clears_nothing() {
    let f = Fixture::new();
    let scene = f.seed_signature_scene(true).await;

    assert!(f
        .resolve_signature_material(&scene.bundle_layer, &[])
        .await
        .is_none());
    assert!(f.committed().is_empty());
}

/// A candidate in another repository clears nothing — a clearance never
/// crosses a repo boundary, because the blob row it would clear is
/// repo-scoped.
#[tokio::test]
async fn a_candidate_in_another_repository_clears_nothing() {
    let f = Fixture::new();
    let scene = f.seed_signature_scene(true).await;
    // Re-home the signature manifest into a foreign repository.
    let mut manifest = f
        .artifacts
        .find_by_repo_and_checksum(f.repository_id, &scene.manifest_hash)
        .await
        .expect("lookup")
        .expect("the manifest row");
    manifest.repository_id = Uuid::new_v4();
    f.artifacts.insert(manifest);

    let verifier = SubjectKeyedVerifier::accepting(&scene.subject_hash);
    let owned = ports(&verifier);
    assert!(f
        .resolve_signature_material(&scene.bundle_layer, &owned.iter().collect::<Vec<_>>())
        .await
        .is_none());
    assert!(f.committed().is_empty());
}

/// A constituent that is not held takes no clearance — the domain guard on
/// [`Artifact::cascade_provenance_clearance`] refuses every non-held
/// state, so a terminally rejected signature payload stays rejected (that
/// population is a separate decision) and a released one needs nothing.
#[tokio::test]
async fn a_constituent_that_is_not_held_takes_no_clearance() {
    for status in [
        QuarantineStatus::Rejected,
        QuarantineStatus::Released,
        QuarantineStatus::None,
    ] {
        let f = Fixture::new();
        let scene = f.seed_signature_scene(true).await;
        let mut layer = scene.bundle_layer.clone();
        layer.quarantine_status = status;
        f.artifacts.insert(layer.clone());

        let verifier = SubjectKeyedVerifier::accepting(&scene.subject_hash);
        let owned = ports(&verifier);
        assert!(
            f.resolve_signature_material(&layer, &owned.iter().collect::<Vec<_>>())
                .await
                .is_none(),
            "status {status} must take no clearance",
        );
        assert!(f.committed().is_empty());
    }
}

/// A candidate that declares ITSELF as its subject is circular authority,
/// and one that declares the artifact under resolution as its subject is
/// the direct verification the caller already ran and found unsigned.
/// Neither may stand in for a second artifact's signature.
#[tokio::test]
async fn a_self_referential_subject_clears_nothing() {
    for subject_is_the_constituent in [true, false] {
        let f = Fixture::new();
        let (manifest_hash, config_hash, layer_hash) = (hexhash('2'), hexhash('3'), hexhash('4'));
        let subject = if subject_is_the_constituent {
            layer_hash.clone()
        } else {
            manifest_hash.clone()
        };
        let manifest_bytes =
            keyless_signature_manifest_body(Some(&subject), &config_hash, &layer_hash);
        let manifest = f.seed_artifact(&manifest_hash, QuarantineStatus::None);
        f.seed_bytes(&manifest_hash, manifest_bytes);
        f.seed_bytes(&layer_hash, b"bundle".to_vec());
        let layer = f.seed_artifact(&layer_hash, QuarantineStatus::Quarantined);
        f.seed_edge(manifest.id, &layer_hash, "oci_layer").await;

        let verifier = SubjectKeyedVerifier::accepting(&subject);
        let owned = ports(&verifier);
        assert!(f
            .resolve_signature_material(&layer, &owned.iter().collect::<Vec<_>>())
            .await
            .is_none());
        assert!(f.committed().is_empty());
        assert!(verifier.calls().is_empty());
    }
}

/// An artifact's own refcount row (`primary_content`, targeting its own
/// hash) is never a clearance source — a self-clear would be circular.
#[tokio::test]
async fn an_artifacts_own_refcount_row_is_not_a_signature_material_source() {
    let f = Fixture::new();
    let hash = hexhash('4');
    let blob = f.seed_artifact(&hash, QuarantineStatus::Quarantined);
    f.seed_edge(blob.id, &hash, "primary_content").await;
    let verifier = SubjectKeyedVerifier::accepting(&hexhash('1'));
    let owned = ports(&verifier);

    assert!(f
        .resolve_signature_material(&blob, &owned.iter().collect::<Vec<_>>())
        .await
        .is_none());
    assert!(f.committed().is_empty());
}

/// One unresolvable candidate does not abort the walk: the next edge still
/// clears. (The first edge names an artifact id with no row.)
#[tokio::test]
async fn an_unresolvable_signature_material_candidate_is_skipped_and_the_walk_continues() {
    let f = Fixture::new();
    let scene = f.seed_signature_scene(true).await;
    // A dangling edge, inserted first so it is walked first.
    f.seed_edge(
        Uuid::new_v4(),
        &scene.bundle_layer.sha256_checksum,
        "oci_layer",
    )
    .await;

    let verifier = SubjectKeyedVerifier::accepting(&scene.subject_hash);
    let owned = ports(&verifier);
    let cleared = f
        .resolve_signature_material(&scene.bundle_layer, &owned.iter().collect::<Vec<_>>())
        .await;
    assert!(
        cleared.is_some(),
        "a dangling edge is warned about and skipped, not fatal"
    );
}

/// An edge read failure leaves the artifact exactly as held as it was.
#[tokio::test]
async fn a_signature_material_edge_read_failure_leaves_the_artifact_held() {
    let f = Fixture::new();
    let blob = f.seed_artifact(&hexhash('4'), QuarantineStatus::Quarantined);
    f.refs
        .fail_next_find_by_target(DomainError::Invariant("pg down".into()));
    let verifier = SubjectKeyedVerifier::accepting(&hexhash('1'));
    let owned = ports(&verifier);

    assert!(f
        .resolve_signature_material(&blob, &owned.iter().collect::<Vec<_>>())
        .await
        .is_none());
    assert!(f.committed().is_empty());
}
