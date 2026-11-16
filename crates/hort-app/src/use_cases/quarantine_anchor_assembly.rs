//! The **one** place an artifact's quarantine-window anchor is assembled
//! for a hold the artifact re-enters (ADR 0054).
//!
//! # What this module is for
//!
//! A quarantine begins at the point hort can prove the artifact was
//! already published — the period in which the artifact is known to the
//! public and can be checked. The anchor is therefore a property of **the
//! artifact**, never of the run that happens to look at it, and
//! [`derive_quarantine_anchor`] is the single rule that decides it: the
//! minimum over the applicable age evidence.
//!
//! That rule is pure, and every one of its inputs needs I/O. This module
//! owns that I/O, and it is the only module that does, so there are
//! exactly **two** [`AnchorEvidence`] assembly sites in the workspace and
//! both are here:
//!
//! * [`derive_mint_anchor`] — a row coming into existence. The caller
//!   supplies the evidence that exists only on a request: the mint
//!   instant, the resolved window, the seed-import override, and the
//!   upstream publish time *if* the serving mapping's
//!   `trust_upstream_publish_time` opt-in is on. Both minting paths
//!   ([`IngestUseCase::decide_and_apply_quarantine`] and
//!   `apply_register_gate`) call it, which is what keeps a leader and a
//!   dedup follower from deriving different anchors for the same content.
//! * [`QuarantineAnchorResolver::derive_for_re_entry`] — an artifact that
//!   already exists and is being returned to the hold. Nothing is
//!   supplied; every source is read from the artifact and the ports.
//!
//! Those are the only two situations there are, and the split is not
//! stylistic: a mint's evidence includes request data no later path can
//! recover, and a re-entry's evidence includes the row's own stored
//! columns, which do not exist yet at a mint. A third site would be a
//! third rule.
//! `crates/hort-app/tests/anchor_evidence_is_assembled_once.rs` holds
//! that count.
//!
//! # Every read degrades toward the FULL window
//!
//! None of these functions is fallible, and that is deliberate rather
//! than convenient. Each read's failure resolves the way *absent
//! evidence* resolves — to the mint instant, which the derivation always
//! carries as an unconditional candidate. Inventing an earlier instant
//! for content whose age hort cannot vouch for would shorten a security
//! window on no evidence; standing on the mint instant can only hold
//! content longer than the truth justifies. Propagating instead would
//! make a transient database blip a reason for an otherwise complete
//! hold to fail — the posture every other non-essential read on this
//! path already declines to take.
//!
//! # The upstream opt-in at a re-entry
//!
//! `trust_upstream_publish_time` is a per-**mapping** trust statement
//! about the upstream that served a fetch, and a re-entry has no fetch:
//! the row carries `upstream_published_at` as an audit column, but not
//! which mapping produced it (the stored `path` is not the format-native
//! request name the upstream resolver matches a `path_prefix` against).
//! So the opt-in is read as a property of the repository's whole mapping
//! set: the claim competes only when the repository has at least one
//! upstream mapping and **every** one of them has the opt-in enabled —
//! i.e. when no mapping that could have served these bytes carries an
//! un-opted-in trust statement.
//!
//! That is the fail-closed reading, and the direction matters: a
//! repository mixing a trusted upstream with an untrusted mirror
//! contributes nothing, so an untrusted mirror's claim can never shorten
//! the window of content the genuine upstream served. The permissive
//! reading — "any mapping opted in" — is exactly the ADR 0016
//! cross-opt-in collapse pattern in the weakening direction. For the
//! single-upstream formats (cargo, npm, PyPI, Maven: one mapping, empty
//! `path_prefix`) unanimity *is* the serving mapping's own opt-in; only a
//! multi-upstream OCI mirror can differ, and there the conservative
//! answer is the right one.
//!
//! [`IngestUseCase::decide_and_apply_quarantine`]: crate::use_cases::ingest_use_case::IngestUseCase

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use hort_domain::entities::artifact::Artifact;
use hort_domain::policy::{derive_quarantine_anchor, AnchorEvidence, DefaultPolicy, DerivedAnchor};
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::content_reference_index::ContentReferenceIndex;
use hort_domain::ports::policy_projection_repository::PolicyProjectionRepository;
use hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMappingRepository;
use hort_domain::types::ContentHash;

use crate::use_cases::policy_resolution::resolve_active_policy_for_repo;
use crate::use_cases::referenced_descendant::resolve_released_parent_trust_fail_safe;

/// Read the live content-level age evidence for `sha256` — the earliest
/// moment hort itself observed these bytes in any of its own repositories
/// (ADR 0054). One indexed `MIN(created_at)` per quarantining hold; every
/// path that takes a hold calls it, so no two of them can derive
/// different anchors for the same content.
///
/// **Fail-safe**: a port error resolves to `None`, exactly as "hort holds
/// no such observation" does. The two are deliberately indistinguishable
/// to the caller, because they warrant the same answer — the derivation
/// falls back on the mint instant and holds the content for a full
/// window. Inventing an earlier instant for content whose age hort cannot
/// vouch for would shorten a security window on no evidence; standing on
/// the mint instant can only hold content longer than the truth
/// justifies.
pub(crate) async fn read_content_age_evidence(
    artifacts: &dyn ArtifactRepository,
    sha256: &ContentHash,
) -> Option<DateTime<Utc>> {
    match artifacts.first_seen_for_checksum(sha256).await {
        Ok(evidence) => evidence,
        Err(e) => {
            tracing::warn!(
                sha256 = %sha256,
                error = %e,
                "content age-evidence read failed; anchoring the quarantine window on \
                 the mint instant (a full window, never a shorter one)"
            );
            None
        }
    }
}

/// The evidence a **mint** holds that no later path can recover: the
/// instant the row comes into existence, the window resolved in order to
/// decide the quarantine, the seed-import override, and the upstream
/// publish hint the serving mapping's opt-in admitted.
///
/// Everything else — the content-level age evidence and the
/// released-parent descendant carve-out — is read by
/// [`derive_mint_anchor`], because both are facts about the repository
/// rather than about the request, and the two minting paths must not
/// answer them differently.
pub(crate) struct MintEvidence<'a> {
    /// The instant this artifact row is being minted.
    pub minted_at: DateTime<Utc>,
    /// The resolved observation-window length in seconds — the matched
    /// `ScanPolicy.quarantineDuration` or the built-in default, already
    /// in hand because the caller resolved it in order to decide that a
    /// quarantine applies at all.
    pub window_secs: i64,
    /// The seed-import cutover's backdated anchor. `Some(_)` wins
    /// absolutely, and both probes below are skipped — they could only
    /// spend round-trips on values nothing reads.
    pub explicit_override: Option<DateTime<Utc>>,
    /// The upstream-asserted publish time, **already filtered** by the
    /// serving `RepositoryUpstreamMapping`'s `trust_upstream_publish_time`
    /// opt-in. Callers pass `None` whenever the opt-in is off, the format
    /// extracted no hint, or no upstream fetch is in scope.
    pub trusted_upstream_published_at: Option<DateTime<Utc>>,
    /// The repository this row is being minted into — the scope both
    /// probes run in. The descendant carve-out is repo-scoped by
    /// construction (`find_by_target` is), which is what keeps one
    /// repository's released parents out of another's anchor.
    pub repository_id: Uuid,
    /// The row being minted. Read by the descendant probe so a
    /// descendant cannot be its own referencing parent, and otherwise
    /// only logged.
    pub artifact_id: Uuid,
    /// The content whose age is in question. The age evidence is
    /// content-level, not row-level (ADR 0054), which is the whole
    /// reason a follower minting over already-resident bytes derives the
    /// same anchor the leader did.
    pub sha256: &'a ContentHash,
}

/// Assemble and derive the anchor for a row being **minted**.
pub(crate) async fn derive_mint_anchor(
    artifacts: &dyn ArtifactRepository,
    content_references: &dyn ContentReferenceIndex,
    evidence: MintEvidence<'_>,
) -> DerivedAnchor {
    // Both probes are skipped entirely when an explicit anchor is
    // supplied: the override wins absolutely, so they could only spend
    // round-trips on values nothing reads.
    let (inherits_released_parent_trust, first_seen_at) = match evidence.explicit_override {
        Some(_) => (false, None),
        None => (
            resolve_released_parent_trust_fail_safe(
                content_references,
                artifacts,
                evidence.repository_id,
                evidence.artifact_id,
                evidence.sha256,
            )
            .await,
            read_content_age_evidence(artifacts, evidence.sha256).await,
        ),
    };

    derive_quarantine_anchor(&AnchorEvidence {
        minted_at: evidence.minted_at,
        window: Duration::seconds(evidence.window_secs),
        explicit_override: evidence.explicit_override,
        first_seen_at,
        trusted_upstream_published_at: evidence.trusted_upstream_published_at,
        inherits_released_parent_trust,
    })
}

/// The ports [`Self::derive_for_re_entry`] reads, bundled so every use
/// case that returns an artifact to the hold takes one dependency rather
/// than four — and so there is one object to point at when asking "where
/// does this anchor come from".
///
/// Held by [`QuarantineUseCase`](crate::use_cases::QuarantineUseCase),
/// [`CurationUseCase`](crate::use_cases::CurationUseCase),
/// [`PolicyUseCase`](crate::use_cases::PolicyUseCase) and
/// [`ProvenanceMisrejectionRepairUseCase`](crate::use_cases::provenance_misrejection_repair::ProvenanceMisrejectionRepairUseCase)
/// — between them every caller of the three
/// [`Artifact`] methods that re-enter the hold.
pub struct QuarantineAnchorResolver {
    artifacts: Arc<dyn ArtifactRepository>,
    content_references: Arc<dyn ContentReferenceIndex>,
    /// Resolves the matched `ScanPolicy`, whose `quarantineDuration` is
    /// the window the descendant carve-out expresses "already over" in
    /// terms of. Not an optional dependency: a guessed window would make
    /// the carve-out mean something other than "a full window ago".
    policy_projections: Arc<dyn PolicyProjectionRepository>,
    /// The per-mapping `trust_upstream_publish_time` opt-in — see the
    /// module docs on how a re-entry reads it.
    upstream_mappings: Arc<dyn RepositoryUpstreamMappingRepository>,
}

impl QuarantineAnchorResolver {
    pub fn new(
        artifacts: Arc<dyn ArtifactRepository>,
        content_references: Arc<dyn ContentReferenceIndex>,
        policy_projections: Arc<dyn PolicyProjectionRepository>,
        upstream_mappings: Arc<dyn RepositoryUpstreamMappingRepository>,
    ) -> Self {
        Self {
            artifacts,
            content_references,
            policy_projections,
            upstream_mappings,
        }
    }

    /// Derive the anchor for an artifact **re-entering** the hold.
    ///
    /// Every source comes from the artifact and the ports: the row's own
    /// `created_at` is the `minted_at` evidence (the unconditional
    /// candidate, and the instant the retired
    /// `unwrap_or(self.created_at)` fallback used to reach for from
    /// outside the derivation), the content-level age evidence and the
    /// descendant carve-out are read, and the window comes from the
    /// matched policy. There is no `explicit_override`: the seed-import
    /// cutover mints rows, it does not return existing ones to the hold.
    ///
    /// The three entity methods compose the result with the window the
    /// artifact already carries
    /// ([`DerivedAnchor::re_entry_anchor`]), so this value can only ever
    /// move an anchor earlier.
    pub async fn derive_for_re_entry(&self, artifact: &Artifact) -> DerivedAnchor {
        let inherits_released_parent_trust = resolve_released_parent_trust_fail_safe(
            &*self.content_references,
            &*self.artifacts,
            artifact.repository_id,
            artifact.id,
            &artifact.sha256_checksum,
        )
        .await;
        // The window is consumed by the descendant carve-out and by
        // nothing else ([`AnchorEvidence::window`]), so it is resolved
        // only when the carve-out applies. Resolving it unconditionally
        // would spend a policy-projection scan per re-entry on a value
        // the derivation does not read — and the policy re-evaluation
        // pass re-enters the hold once per artifact in a whole
        // population. `Duration::zero()` is not a guess at the window:
        // it is the value whose carve-out contribution
        // (`minted_at - 0`) is exactly the mint instant, i.e. no
        // contribution, which is what "the carve-out does not apply"
        // already means on this branch.
        let window = if inherits_released_parent_trust {
            Duration::seconds(self.resolve_window_secs(artifact.repository_id).await)
        } else {
            Duration::zero()
        };

        derive_quarantine_anchor(&AnchorEvidence {
            minted_at: artifact.created_at,
            window,
            explicit_override: None,
            first_seen_at: read_content_age_evidence(&*self.artifacts, &artifact.sha256_checksum)
                .await,
            trusted_upstream_published_at: self.trusted_upstream_publish_time(artifact).await,
            inherits_released_parent_trust,
        })
    }

    /// The matched policy's `quarantineDuration`, or
    /// [`DefaultPolicy::quarantine_duration_secs`] when the repository has
    /// no resolved policy — the same resolution the minting paths run, so
    /// a mint and a re-entry measure the descendant carve-out against one
    /// window.
    ///
    /// A failed read resolves to `0`, which makes the carve-out's
    /// `minted_at - window` contribution tie with the mint instant and so
    /// contribute nothing: the FULL-window direction, like every other
    /// read here. A guessed duration is the one thing this must not do —
    /// the carve-out's whole meaning is "a window that is already over",
    /// and a wrong window makes it a window that is partly over.
    async fn resolve_window_secs(&self, repository_id: Uuid) -> i64 {
        match resolve_active_policy_for_repo(&*self.policy_projections, repository_id).await {
            Ok(matched) => matched
                .map(|p| p.quarantine_duration_secs)
                .unwrap_or_else(DefaultPolicy::quarantine_duration_secs),
            Err(e) => {
                tracing::warn!(
                    %repository_id,
                    error = %e,
                    "scan-policy resolution failed while deriving a quarantine anchor; \
                     the referenced-descendant carve-out contributes nothing this pass \
                     (a full window, never a shorter one)"
                );
                0
            }
        }
    }

    /// The artifact's own `upstream_published_at`, admitted only when
    /// every one of its repository's upstream mappings carries the
    /// `trust_upstream_publish_time` opt-in — see the module docs for why
    /// unanimity is the reading, and why the permissive one would be the
    /// ADR 0016 collapse pattern.
    ///
    /// `None` on a failed read, on a repository with no mappings (no
    /// upstream, so no upstream claim), and of course when the row holds
    /// no publish time at all.
    async fn trusted_upstream_publish_time(&self, artifact: &Artifact) -> Option<DateTime<Utc>> {
        let claimed = artifact.upstream_published_at?;
        let mappings = match self
            .upstream_mappings
            .list_for_repository(artifact.repository_id)
            .await
        {
            Ok(mappings) => mappings,
            Err(e) => {
                tracing::warn!(
                    artifact_id = %artifact.id,
                    repository_id = %artifact.repository_id,
                    error = %e,
                    "upstream-mapping read failed while deriving a quarantine anchor; \
                     the upstream publish claim does not compete this pass (a full \
                     window, never a shorter one)"
                );
                return None;
            }
        };
        let trusted =
            !mappings.is_empty() && mappings.iter().all(|m| m.trust_upstream_publish_time);
        trusted.then_some(claimed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::scan_policy::{
        NegligibleAction, ProvenanceMode, ScanEnforcement, ScanPolicyProjection, SeverityThreshold,
    };
    use hort_domain::error::DomainError;
    use hort_domain::events::PolicyScope;
    use hort_domain::policy::AnchorSource;
    use hort_domain::ports::content_reference_index::ContentReference;
    use hort_domain::ports::repository_upstream_mapping_repository::{
        RepositoryUpstreamMapping, RepositoryUpstreamMappingArgs, UpstreamAuth,
    };

    use crate::use_cases::test_support::{
        sample_artifact, MockArtifactRepository, MockContentReferenceIndex,
        MockPolicyProjectionRepository, MockRepositoryUpstreamMappingRepository,
    };

    const WINDOW_SECS: i64 = 86_400;

    struct Fixture {
        artifacts: Arc<MockArtifactRepository>,
        content_references: Arc<MockContentReferenceIndex>,
        policies: Arc<MockPolicyProjectionRepository>,
        mappings: Arc<MockRepositoryUpstreamMappingRepository>,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                artifacts: Arc::new(MockArtifactRepository::new()),
                content_references: Arc::new(MockContentReferenceIndex::new()),
                policies: Arc::new(MockPolicyProjectionRepository::new()),
                mappings: Arc::new(MockRepositoryUpstreamMappingRepository::new()),
            }
        }

        fn resolver(&self) -> QuarantineAnchorResolver {
            QuarantineAnchorResolver::new(
                self.artifacts.clone(),
                self.content_references.clone(),
                self.policies.clone(),
                self.mappings.clone(),
            )
        }
    }

    /// An artifact minted an hour ago, held, and present in the
    /// repository — the shape every re-entry path loads.
    fn held_artifact(fx: &Fixture) -> Artifact {
        let mut artifact = sample_artifact(QuarantineStatus::Quarantined);
        artifact.created_at = Utc::now() - Duration::hours(1);
        artifact.quarantine_window_start = Some(artifact.created_at);
        fx.artifacts.insert(artifact.clone());
        artifact
    }

    fn policy_for(repo: Uuid, quarantine_duration_secs: i64) -> ScanPolicyProjection {
        ScanPolicyProjection {
            policy_id: Uuid::new_v4(),
            name: format!("policy-{}", Uuid::new_v4()),
            scope: PolicyScope::Repository(repo),
            severity_threshold: SeverityThreshold::Critical,
            quarantine_duration_secs,
            require_approval: false,
            provenance_mode: ProvenanceMode::VerifyIfPresent,
            provenance_backends: vec!["cosign".to_string()],
            provenance_identities: Vec::new(),
            max_artifact_age_secs: None,
            license_policy: serde_json::Value::Null,
            archived: false,
            scan_backends: vec!["trivy".to_string()],
            rescan_interval_hours: 24,
            negligible_action: NegligibleAction::Ignore,
            enforcement: ScanEnforcement::Reject,
            stream_version: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn mapping_for(repo: Uuid, prefix: &str, trust: bool) -> RepositoryUpstreamMapping {
        RepositoryUpstreamMapping::new(RepositoryUpstreamMappingArgs {
            id: Uuid::new_v4(),
            repository_id: repo,
            path_prefix: prefix.to_string(),
            upstream_url: "https://upstream.example".to_string(),
            upstream_name_prefix: None,
            upstream_auth: UpstreamAuth::Anonymous,
            secret_ref: None,
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
            insecure_upstream_url: false,
            trust_upstream_publish_time: trust,
            mtls_cert_ref: None,
            mtls_key_ref: None,
            ca_bundle_ref: None,
            pinned_cert_sha256: None,
            allowed_realm_hosts: Vec::new(),
            not_found_cache_seconds: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
        .expect("a https mapping with no TLS material is valid")
    }

    /// Seed a `Released` referencing parent for the artifact's content,
    /// which is the carve-out's full condition.
    async fn released_parent_edge(fx: &Fixture, artifact: &Artifact) {
        let mut parent = sample_artifact(QuarantineStatus::Released);
        parent.repository_id = artifact.repository_id;
        parent.path = format!("parents/{}", parent.id);
        let parent_id = parent.id;
        fx.artifacts.insert(parent);
        fx.content_references
            .insert(ContentReference {
                source_artifact_id: parent_id,
                target_content_hash: artifact.sha256_checksum.clone(),
                kind: "oci_layer".to_string(),
                metadata: serde_json::Value::Object(serde_json::Map::new()),
                repository_id: artifact.repository_id,
                recorded_at: Utc::now(),
            })
            .await
            .expect("seeding an edge must succeed");
    }

    // -- derive_for_re_entry: the sources --------------------------------

    /// The unconditional candidate, and the answer when nothing else
    /// applies: the row's own ingest instant. This is where the retired
    /// `unwrap_or(self.created_at)` fallback went.
    #[tokio::test]
    async fn a_re_entry_with_no_other_evidence_anchors_on_the_mint_instant() {
        let fx = Fixture::new();
        let artifact = held_artifact(&fx);

        let derived = fx.resolver().derive_for_re_entry(&artifact).await;

        assert_eq!(derived.anchor(), artifact.created_at);
        assert_eq!(derived.source, AnchorSource::Mint);
        assert!(!derived.upstream_clamp_fired);
    }

    /// Content hort has held longer than this row knew moves the anchor
    /// earlier — the whole reason a re-entry derives instead of reading
    /// a stored column.
    #[tokio::test]
    async fn an_earlier_observation_of_the_same_content_moves_the_anchor_back() {
        let fx = Fixture::new();
        let artifact = held_artifact(&fx);
        let mut older = artifact.clone();
        older.id = Uuid::new_v4();
        older.repository_id = Uuid::new_v4();
        older.created_at = artifact.created_at - Duration::days(90);
        fx.artifacts.insert(older.clone());

        let derived = fx.resolver().derive_for_re_entry(&artifact).await;

        assert_eq!(derived.anchor(), older.created_at);
        assert_eq!(derived.source, AnchorSource::FirstSeen);
    }

    /// A failed age-evidence read is indistinguishable from no evidence,
    /// and resolves the same conservative way: the mint instant, i.e. a
    /// full window.
    #[tokio::test]
    async fn a_failed_age_evidence_read_anchors_on_the_mint_instant() {
        let fx = Fixture::new();
        let artifact = held_artifact(&fx);
        let mut older = artifact.clone();
        older.id = Uuid::new_v4();
        older.created_at = artifact.created_at - Duration::days(90);
        fx.artifacts.insert(older);
        fx.artifacts
            .fail_next_first_seen(DomainError::Invariant("age evidence read failed".into()));

        let derived = fx.resolver().derive_for_re_entry(&artifact).await;

        assert_eq!(
            derived.anchor(),
            artifact.created_at,
            "a read that failed must never be read as evidence of an earlier instant"
        );
        assert_eq!(derived.source, AnchorSource::Mint);
    }

    // -- derive_for_re_entry: the window -------------------------------

    /// The carve-out expresses "a window that is already over" as
    /// `minted_at - window`, so the window has to be the one the matched
    /// policy actually sets.
    #[tokio::test]
    async fn the_descendant_carve_out_uses_the_matched_policys_window() {
        let fx = Fixture::new();
        let artifact = held_artifact(&fx);
        fx.policies
            .insert(policy_for(artifact.repository_id, WINDOW_SECS));
        released_parent_edge(&fx, &artifact).await;

        let derived = fx.resolver().derive_for_re_entry(&artifact).await;

        assert_eq!(
            derived.anchor(),
            artifact.created_at - Duration::seconds(WINDOW_SECS)
        );
        assert_eq!(derived.source, AnchorSource::ReferencedDescendant);
    }

    /// With no policy configured the built-in default window applies —
    /// the same resolution the minting paths run, so a mint and a
    /// re-entry measure the carve-out against one window.
    #[tokio::test]
    async fn an_unconfigured_repository_falls_back_on_the_default_window() {
        let fx = Fixture::new();
        let artifact = held_artifact(&fx);
        released_parent_edge(&fx, &artifact).await;

        let derived = fx.resolver().derive_for_re_entry(&artifact).await;

        assert_eq!(
            derived.anchor(),
            artifact.created_at - Duration::seconds(DefaultPolicy::quarantine_duration_secs())
        );
        assert_eq!(derived.source, AnchorSource::ReferencedDescendant);
    }

    /// …and a re-entry that is not a descendant resolves no policy at
    /// all: the window has no other consumer, and the re-evaluation pass
    /// re-enters the hold once per artifact in a whole population.
    #[tokio::test]
    async fn a_re_entry_with_no_carve_out_resolves_no_policy() {
        let fx = Fixture::new();
        let artifact = held_artifact(&fx);
        fx.policies
            .insert(policy_for(artifact.repository_id, WINDOW_SECS));

        let derived = fx.resolver().derive_for_re_entry(&artifact).await;

        assert_eq!(derived.anchor(), artifact.created_at);
        assert_eq!(
            fx.policies.list_active_call_count(),
            0,
            "the window is consumed by the descendant carve-out and nothing else, so a \
             re-entry that is not a descendant must not spend a projection scan on it"
        );
    }

    /// A failed policy read invents no duration: the carve-out
    /// contributes nothing this pass and the mint instant stands, which
    /// is the full-window direction.
    #[tokio::test]
    async fn a_failed_policy_read_leaves_the_carve_out_contributing_nothing() {
        let fx = Fixture::new();
        let artifact = held_artifact(&fx);
        fx.policies
            .insert(policy_for(artifact.repository_id, WINDOW_SECS));
        released_parent_edge(&fx, &artifact).await;
        fx.policies
            .fail_next_list_active(DomainError::Invariant("policy read failed".into()));

        let derived = fx.resolver().derive_for_re_entry(&artifact).await;

        assert_eq!(derived.anchor(), artifact.created_at);
        assert_eq!(derived.source, AnchorSource::Mint);
    }

    /// A descendant whose parents are all still held inherits nothing —
    /// the resolver's own rule, threaded through here.
    #[tokio::test]
    async fn a_descendant_with_no_released_parent_keeps_the_full_window() {
        let fx = Fixture::new();
        let artifact = held_artifact(&fx);
        let mut parent = sample_artifact(QuarantineStatus::Quarantined);
        parent.repository_id = artifact.repository_id;
        parent.path = format!("parents/{}", parent.id);
        let parent_id = parent.id;
        fx.artifacts.insert(parent);
        fx.content_references
            .insert(ContentReference {
                source_artifact_id: parent_id,
                target_content_hash: artifact.sha256_checksum.clone(),
                kind: "oci_layer".to_string(),
                metadata: serde_json::Value::Object(serde_json::Map::new()),
                repository_id: artifact.repository_id,
                recorded_at: Utc::now(),
            })
            .await
            .expect("seeding an edge must succeed");

        let derived = fx.resolver().derive_for_re_entry(&artifact).await;

        assert_eq!(derived.anchor(), artifact.created_at);
        assert_eq!(derived.source, AnchorSource::Mint);
    }

    // -- derive_for_re_entry: the upstream opt-in ----------------------

    /// Every mapping opted in: the claim competes, and here it wins.
    #[tokio::test]
    async fn an_upstream_claim_competes_when_every_mapping_opted_in() {
        let fx = Fixture::new();
        let mut artifact = held_artifact(&fx);
        let published = artifact.created_at - Duration::days(200);
        artifact.upstream_published_at = Some(published);
        fx.artifacts.insert(artifact.clone());
        fx.mappings
            .upsert(mapping_for(artifact.repository_id, "", true))
            .await
            .expect("seeding a mapping must succeed");
        fx.mappings
            .upsert(mapping_for(artifact.repository_id, "mirror/", true))
            .await
            .expect("seeding a mapping must succeed");

        let derived = fx.resolver().derive_for_re_entry(&artifact).await;

        assert_eq!(derived.anchor(), published);
        assert_eq!(derived.source, AnchorSource::TrustedUpstreamPublish);
    }

    /// One un-opted-in mapping is enough to keep the claim out: a
    /// re-entry cannot tell which mapping served the bytes, so a
    /// repository mixing a trusted upstream with an untrusted mirror
    /// contributes nothing.
    #[tokio::test]
    async fn one_un_opted_in_mapping_keeps_the_upstream_claim_out() {
        let fx = Fixture::new();
        let mut artifact = held_artifact(&fx);
        artifact.upstream_published_at = Some(artifact.created_at - Duration::days(200));
        fx.artifacts.insert(artifact.clone());
        fx.mappings
            .upsert(mapping_for(artifact.repository_id, "", true))
            .await
            .expect("seeding a mapping must succeed");
        fx.mappings
            .upsert(mapping_for(artifact.repository_id, "mirror/", false))
            .await
            .expect("seeding a mapping must succeed");

        let derived = fx.resolver().derive_for_re_entry(&artifact).await;

        assert_eq!(derived.anchor(), artifact.created_at);
        assert_eq!(derived.source, AnchorSource::Mint);
    }

    /// A repository with no upstream mapping has no upstream, so there
    /// is nothing for the claim to have been observed through — the
    /// vacuous "all of none are opted in" reading must not admit it.
    #[tokio::test]
    async fn a_repository_with_no_mapping_admits_no_upstream_claim() {
        let fx = Fixture::new();
        let mut artifact = held_artifact(&fx);
        artifact.upstream_published_at = Some(artifact.created_at - Duration::days(200));
        fx.artifacts.insert(artifact.clone());

        let derived = fx.resolver().derive_for_re_entry(&artifact).await;

        assert_eq!(derived.anchor(), artifact.created_at);
        assert_eq!(derived.source, AnchorSource::Mint);
    }

    /// An unreadable mapping set is not an opted-in one.
    #[tokio::test]
    async fn a_failed_mapping_read_keeps_the_upstream_claim_out() {
        let fx = Fixture::new();
        let mut artifact = held_artifact(&fx);
        artifact.upstream_published_at = Some(artifact.created_at - Duration::days(200));
        fx.artifacts.insert(artifact.clone());
        fx.mappings
            .upsert(mapping_for(artifact.repository_id, "", true))
            .await
            .expect("seeding a mapping must succeed");
        fx.mappings
            .fail_next_list_for_repository(DomainError::Invariant("mapping read failed".into()));

        let derived = fx.resolver().derive_for_re_entry(&artifact).await;

        assert_eq!(derived.anchor(), artifact.created_at);
        assert_eq!(derived.source, AnchorSource::Mint);
    }

    /// A row with no publish time at all reads no mapping: there is
    /// nothing an opt-in could admit, so the round-trip is not spent.
    #[tokio::test]
    async fn a_row_with_no_publish_time_reads_no_mapping() {
        let fx = Fixture::new();
        let artifact = held_artifact(&fx);
        assert_eq!(artifact.upstream_published_at, None, "fixture precondition");
        fx.mappings
            .fail_next_list_for_repository(DomainError::Invariant("must not be reached".into()));

        let derived = fx.resolver().derive_for_re_entry(&artifact).await;

        assert_eq!(derived.anchor(), artifact.created_at);
        // The armed failure is one-shot, so it is still armed iff
        // `list_for_repository` was never called — which is the claim
        // this test makes, and the only way to observe it.
        assert!(
            fx.mappings
                .list_for_repository(artifact.repository_id)
                .await
                .is_err(),
            "the armed failure was consumed, so the mapping set WAS read for a row \
             carrying no publish time at all — a round-trip spent on a question with \
             no answer to admit"
        );
    }

    /// A future-dated claim is clamped before it competes, and the
    /// clamp is reported whether or not the clamped value went on to win
    /// — it is an operator signal about the upstream either way.
    #[tokio::test]
    async fn a_future_dated_upstream_claim_is_clamped_and_reported() {
        let fx = Fixture::new();
        let mut artifact = held_artifact(&fx);
        artifact.upstream_published_at = Some(artifact.created_at + Duration::days(1));
        fx.artifacts.insert(artifact.clone());
        fx.mappings
            .upsert(mapping_for(artifact.repository_id, "", true))
            .await
            .expect("seeding a mapping must succeed");

        let derived = fx.resolver().derive_for_re_entry(&artifact).await;

        assert_eq!(derived.anchor(), artifact.created_at);
        assert!(derived.upstream_clamp_fired);
    }

    // -- derive_mint_anchor -------------------------------------------

    /// The mint path's evidence, assembled here so both minting paths
    /// cannot drift: the probes run and the earliest source wins.
    #[tokio::test]
    async fn a_mint_reads_the_content_age_evidence() {
        let fx = Fixture::new();
        let artifact = held_artifact(&fx);
        let now = Utc::now();

        let derived = derive_mint_anchor(
            &*fx.artifacts,
            &*fx.content_references,
            MintEvidence {
                minted_at: now,
                window_secs: WINDOW_SECS,
                explicit_override: None,
                trusted_upstream_published_at: None,
                repository_id: artifact.repository_id,
                artifact_id: Uuid::new_v4(),
                sha256: &artifact.sha256_checksum,
            },
        )
        .await;

        assert_eq!(derived.anchor(), artifact.created_at);
        assert_eq!(derived.source, AnchorSource::FirstSeen);
    }

    /// An explicit override wins absolutely **and skips both probes** —
    /// they could only spend round-trips on values nothing reads. The
    /// armed age-evidence failure is how that is observed: a probe that
    /// ran would consume it, and its result would be ignored anyway.
    #[tokio::test]
    async fn an_explicit_override_short_circuits_both_probes() {
        let fx = Fixture::new();
        let artifact = held_artifact(&fx);
        released_parent_edge(&fx, &artifact).await;
        let seeded = Utc::now() - Duration::days(400);
        fx.artifacts
            .fail_next_first_seen(DomainError::Invariant("must not be reached".into()));

        let derived = derive_mint_anchor(
            &*fx.artifacts,
            &*fx.content_references,
            MintEvidence {
                minted_at: Utc::now(),
                window_secs: WINDOW_SECS,
                explicit_override: Some(seeded),
                trusted_upstream_published_at: None,
                repository_id: artifact.repository_id,
                artifact_id: Uuid::new_v4(),
                sha256: &artifact.sha256_checksum,
            },
        )
        .await;

        assert_eq!(derived.anchor(), seeded);
        assert_eq!(derived.source, AnchorSource::Override);
    }

    /// The mint path's upstream claim arrives **already filtered** by
    /// the serving mapping's opt-in, because only the request knows
    /// which mapping served it.
    #[tokio::test]
    async fn a_mint_takes_the_upstream_claim_its_caller_already_filtered() {
        let fx = Fixture::new();
        let now = Utc::now();
        let published = now - Duration::days(30);
        let artifact = sample_artifact(QuarantineStatus::None);

        let derived = derive_mint_anchor(
            &*fx.artifacts,
            &*fx.content_references,
            MintEvidence {
                minted_at: now,
                window_secs: WINDOW_SECS,
                explicit_override: None,
                trusted_upstream_published_at: Some(published),
                repository_id: artifact.repository_id,
                artifact_id: artifact.id,
                sha256: &artifact.sha256_checksum,
            },
        )
        .await;

        assert_eq!(derived.anchor(), published);
        assert_eq!(derived.source, AnchorSource::TrustedUpstreamPublish);
    }

    // -- read_content_age_evidence ------------------------------------

    /// The helper's two indistinguishable answers, stated directly: no
    /// observation, and a read that failed.
    #[tokio::test]
    async fn absent_and_unreadable_age_evidence_are_the_same_answer() {
        let fx = Fixture::new();
        let artifact = sample_artifact(QuarantineStatus::None);

        assert_eq!(
            read_content_age_evidence(&*fx.artifacts, &artifact.sha256_checksum).await,
            None,
            "hort holds no observation of this content"
        );

        fx.artifacts.insert(artifact.clone());
        fx.artifacts
            .fail_next_first_seen(DomainError::Invariant("age evidence read failed".into()));
        assert_eq!(
            read_content_age_evidence(&*fx.artifacts, &artifact.sha256_checksum).await,
            None,
            "a failed read resolves exactly as absent evidence does"
        );
    }
}
