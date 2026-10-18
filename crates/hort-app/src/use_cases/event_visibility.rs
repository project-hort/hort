//! The repository-visibility primitive shared by the events-read gate
//! and the subscription delivery filter.
//!
//! # Why one primitive and not two answers
//!
//! `GET /api/v1/events` (`hort-http-events`) and
//! [`subscription_filter::matches`](crate::use_cases::subscription_filter::matches)
//! are two call sites of the same question: *which repositories does
//! this event disclose, and may this principal read all of them?* They
//! previously each answered it locally from a single `Option<Uuid>`
//! extractor, and each read its `None` as "visible". That is one rule
//! implemented twice, and both copies were wrong the same way.
//!
//! Everything about the answer now lives here and in
//! [`EventTypeKind::disclosed_repositories`]: the payload
//! classification, the batch resolution of aggregate ids, the
//! fail-closed dispositions, and the all-disclosed-repositories
//! conjunction. The two call sites differ only in what they do with an
//! [`EventDisclosure`] — the read gate checks `Permission::Read` per
//! disclosed repository, the filter additionally intersects the
//! subscription's stored [`RepositoryScope`](hort_domain::entities::subscription::RepositoryScope).
//!
//! # The three dispositions, and why none of them is "visible"
//!
//! - [`EventDisclosure::Global`] — the event has no repository
//!   association at all (policy / auth / token / subscription / identity
//!   lifecycle). The repository gate has nothing to say; the category
//!   and event-type admin gates, which run independently of this
//!   primitive, are what govern these.
//! - [`EventDisclosure::Repositories`] — the concrete repositories the
//!   event discloses. A caller sees it only if it may read **every** one
//!   of them; the promotion chain discloses a source and a target, and
//!   the reader gets both identities.
//! - [`EventDisclosure::Unresolved`] — the event is repository-scoped
//!   but no repository could be established, either because no single
//!   one owns it (`CasIntegrityMismatch` is keyed on a CAS hash that any
//!   number of repositories' artifacts may point at) or because the
//!   aggregate's projection row is gone (deleting a repository cascades
//!   its artifacts away). Consumers require live `Permission::Admin`
//!   here rather than dropping the event outright: an unresolvable event
//!   is still an audit fact an operator must be able to read, and
//!   "admin only" is the fail-closed answer that keeps it reachable
//!   without guessing a repository.

use std::collections::HashMap;
use std::sync::Arc;

use uuid::Uuid;

use hort_domain::entities::subscription::{EventTypeKind, RepositoryRef};
use hort_domain::error::DomainResult;
use hort_domain::events::{DomainEvent, PersistedEvent};
use hort_domain::ports::event_repository_resolver::EventRepositoryResolver;

/// The repositories one event discloses, resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventDisclosure {
    /// No repository association exists.
    Global,
    /// Exactly these repositories; a caller needs all of them.
    Repositories(DisclosedRepositoryIds),
    /// Repository-scoped, but no repository could be established.
    /// Fail closed.
    Unresolved,
}

/// One or two concrete repository ids, allocation-free.
///
/// Two is the widest disclosure in the event vocabulary; see
/// [`hort_domain::entities::subscription::MAX_DISCLOSED_REPOSITORIES`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisclosedRepositoryIds {
    first: Uuid,
    second: Option<Uuid>,
}

impl DisclosedRepositoryIds {
    /// The disclosed ids, in disclosure order.
    pub fn iter(&self) -> impl Iterator<Item = Uuid> + '_ {
        std::iter::once(self.first).chain(self.second)
    }

    /// `true` when `predicate` holds for **every** disclosed
    /// repository.
    ///
    /// The conjunction, not a disjunction: an event that names two
    /// repositories hands the reader both identities, so authority over
    /// one of them is not authority to read it. This is the single
    /// implementation of that rule — both call sites go through here.
    pub fn all<P: FnMut(Uuid) -> bool>(&self, mut predicate: P) -> bool {
        self.iter().all(&mut predicate)
    }
}

/// Resolved aggregate→repository lookups for one page of events.
///
/// Built once per page by
/// [`EventVisibilityUseCase::index`] and then consulted per event
/// without further I/O. A page whose every event carries its repository
/// in the payload resolves to an empty index and costs no round trip.
#[derive(Debug, Clone, Default)]
pub struct EventRepositoryIndex {
    artifacts: HashMap<Uuid, Uuid>,
    artifact_groups: HashMap<Uuid, Uuid>,
}

impl EventRepositoryIndex {
    /// An index that resolves nothing.
    ///
    /// Correct only for a page with no indirect disclosures; an event
    /// that needs a lookup resolves to [`EventDisclosure::Unresolved`]
    /// against this, which fails closed rather than fails open.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Resolve what an event discloses.
    #[must_use]
    pub fn disclosure(&self, event: &DomainEvent) -> EventDisclosure {
        let disclosed = EventTypeKind::disclosed_repositories(event);
        if disclosed.is_unattributable() {
            return EventDisclosure::Unresolved;
        }
        if disclosed.is_global() {
            return EventDisclosure::Global;
        }
        let mut ids: Option<DisclosedRepositoryIds> = None;
        for reference in disclosed.refs() {
            let Some(repo) = self.resolve(reference) else {
                return EventDisclosure::Unresolved;
            };
            ids = Some(match ids {
                None => DisclosedRepositoryIds {
                    first: repo,
                    second: None,
                },
                // A pair that resolves to one repository (a promotion
                // between two aggregates of the same repo, a group
                // member in its group's repo) is one disclosure.
                Some(existing) if existing.first == repo => existing,
                Some(existing) => DisclosedRepositoryIds {
                    first: existing.first,
                    second: Some(repo),
                },
            });
        }
        match ids {
            // Unreachable: `disclosed` is neither global nor
            // unattributable, so it carries at least one ref. Fail
            // closed anyway rather than invent a pass-through.
            None => EventDisclosure::Unresolved,
            Some(ids) => EventDisclosure::Repositories(ids),
        }
    }

    fn resolve(&self, reference: RepositoryRef) -> Option<Uuid> {
        match reference {
            RepositoryRef::Direct(repo) => Some(repo),
            RepositoryRef::OfArtifact(id) => self.artifacts.get(&id).copied(),
            RepositoryRef::OfArtifactGroup(id) => self.artifact_groups.get(&id).copied(),
        }
    }
}

/// Builds an [`EventRepositoryIndex`] for a page of events.
///
/// Held by both consumers: `AppContext::event_visibility_use_case` for
/// the HTTP read path, and `SubscriptionTaskDeps::event_visibility` for
/// the notification dispatcher.
pub struct EventVisibilityUseCase {
    resolver: Arc<dyn EventRepositoryResolver>,
}

impl EventVisibilityUseCase {
    #[must_use]
    pub fn new(resolver: Arc<dyn EventRepositoryResolver>) -> Self {
        Self { resolver }
    }

    /// Resolve every indirect disclosure on the page in one round trip.
    ///
    /// Collects the distinct aggregate ids the page's payloads name,
    /// hands both id sets to the port in a single call, and returns the
    /// lookup index. Events whose payload carries the repository
    /// directly contribute no id, so a page made only of those skips the
    /// port entirely.
    ///
    /// An infrastructure failure surfaces as `Err`: the caller must fail
    /// the request rather than continue with an index that would resolve
    /// everything to [`EventDisclosure::Unresolved`] and silently
    /// degrade a page to admin-only.
    pub async fn index(&self, events: &[PersistedEvent]) -> DomainResult<EventRepositoryIndex> {
        let mut artifact_ids: Vec<Uuid> = Vec::new();
        let mut group_ids: Vec<Uuid> = Vec::new();
        for event in events {
            for reference in EventTypeKind::disclosed_repositories(&event.event).refs() {
                match reference {
                    RepositoryRef::Direct(_) => {}
                    RepositoryRef::OfArtifact(id) => push_distinct(&mut artifact_ids, id),
                    RepositoryRef::OfArtifactGroup(id) => push_distinct(&mut group_ids, id),
                }
            }
        }
        if artifact_ids.is_empty() && group_ids.is_empty() {
            return Ok(EventRepositoryIndex::empty());
        }
        let resolved = self
            .resolver
            .resolve_event_aggregates(&artifact_ids, &group_ids)
            .await?;
        Ok(EventRepositoryIndex {
            artifacts: resolved.artifacts,
            artifact_groups: resolved.artifact_groups,
        })
    }
}

/// Append `id` unless it is already present.
///
/// A linear scan rather than a `HashSet`: a page holds at most a few
/// hundred events, the ids of one page are overwhelmingly distinct, and
/// the vectors are what the port binds — building a set only to collect
/// it back into a vector costs more than the scan it saves.
fn push_distinct(ids: &mut Vec<Uuid>, id: Uuid) {
    if !ids.contains(&id) {
        ids.push(id);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use chrono::Utc;
    use hort_domain::events::{
        Actor, ApiActor, ArtifactGroupMemberAdded, ArtifactPromoted, ArtifactQuarantined,
        ArtifactReleased, CasIntegrityMismatch, ReleaseReason, StreamId,
    };
    use hort_domain::ports::event_repository_resolver::EventAggregateRepositories;
    use hort_domain::ports::BoxFuture;
    use hort_domain::types::ContentHash;

    use super::*;

    fn sha256() -> ContentHash {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap()
    }

    /// Records the id slices it was asked about so a test can assert the
    /// page was resolved in ONE call, and answers from a seeded map.
    #[derive(Default)]
    struct SpyResolver {
        artifacts: HashMap<Uuid, Uuid>,
        groups: HashMap<Uuid, Uuid>,
        calls: Mutex<Vec<(Vec<Uuid>, Vec<Uuid>)>>,
    }

    impl EventRepositoryResolver for SpyResolver {
        fn resolve_event_aggregates<'a>(
            &'a self,
            artifact_ids: &'a [Uuid],
            artifact_group_ids: &'a [Uuid],
        ) -> BoxFuture<'a, DomainResult<EventAggregateRepositories>> {
            self.calls
                .lock()
                .unwrap()
                .push((artifact_ids.to_vec(), artifact_group_ids.to_vec()));
            let artifacts = artifact_ids
                .iter()
                .filter_map(|id| self.artifacts.get(id).map(|r| (*id, *r)))
                .collect();
            let artifact_groups = artifact_group_ids
                .iter()
                .filter_map(|id| self.groups.get(id).map(|r| (*id, *r)))
                .collect();
            Box::pin(async move {
                Ok(EventAggregateRepositories {
                    artifacts,
                    artifact_groups,
                })
            })
        }
    }

    fn persisted(event: DomainEvent, stream: StreamId, position: u64) -> PersistedEvent {
        PersistedEvent {
            event_id: Uuid::new_v4(),
            stream_id: stream,
            stream_position: 0,
            global_position: position,
            event,
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(ApiActor {
                user_id: Uuid::new_v4(),
            }),
            event_version: 1,
            stored_at: Utc::now(),
        }
    }

    fn quarantined(artifact_id: Uuid, position: u64) -> PersistedEvent {
        persisted(
            DomainEvent::ArtifactQuarantined(ArtifactQuarantined {
                artifact_id,
                quarantine_window_start: Utc::now(),
            }),
            StreamId::artifact(artifact_id),
            position,
        )
    }

    #[tokio::test]
    async fn a_page_of_artifact_events_resolves_in_one_round_trip() {
        let repo = Uuid::new_v4();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let resolver = Arc::new(SpyResolver {
            artifacts: HashMap::from([(a, repo), (b, repo)]),
            ..SpyResolver::default()
        });
        let uc = EventVisibilityUseCase::new(resolver.clone());

        // Five events over two artifacts — the duplicate ids must
        // collapse so the port is asked about each artifact once.
        let page = vec![
            quarantined(a, 1),
            quarantined(a, 2),
            quarantined(b, 3),
            quarantined(a, 4),
            quarantined(b, 5),
        ];
        let index = uc.index(&page).await.expect("resolution must succeed");

        let calls = resolver.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 1, "the whole page must cost ONE round trip");
        assert_eq!(calls[0].0, vec![a, b], "ids must be deduplicated");
        assert!(calls[0].1.is_empty(), "no group ids on this page");

        for event in &page {
            assert!(matches!(
                index.disclosure(&event.event),
                EventDisclosure::Repositories(ids) if ids.iter().eq([repo])
            ));
        }
    }

    #[tokio::test]
    async fn a_page_that_carries_its_repositories_costs_no_round_trip() {
        let resolver = Arc::new(SpyResolver::default());
        let uc = EventVisibilityUseCase::new(resolver.clone());
        let source = Uuid::new_v4();
        let target = Uuid::new_v4();
        let page = vec![persisted(
            DomainEvent::ArtifactPromoted(ArtifactPromoted {
                artifact_id: Uuid::new_v4(),
                source_repository_id: source,
                target_repository_id: target,
            }),
            StreamId::artifact(Uuid::new_v4()),
            1,
        )];

        let index = uc.index(&page).await.expect("resolution must succeed");
        assert!(
            resolver.calls.lock().unwrap().is_empty(),
            "a payload-carried disclosure must not reach the port"
        );
        match index.disclosure(&page[0].event) {
            EventDisclosure::Repositories(ids) => {
                assert!(ids.iter().eq([source, target]));
                assert!(ids.all(|r| r == source || r == target));
                assert!(
                    !ids.all(|r| r == source),
                    "the conjunction must fail when only one of the pair passes"
                );
            }
            other => panic!("expected both repositories, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_unknown_artifact_fails_closed() {
        let resolver = Arc::new(SpyResolver::default());
        let uc = EventVisibilityUseCase::new(resolver);
        let page = vec![quarantined(Uuid::new_v4(), 1)];
        let index = uc.index(&page).await.expect("resolution must succeed");
        assert_eq!(
            index.disclosure(&page[0].event),
            EventDisclosure::Unresolved,
            "an aggregate with no projection row must not resolve to 'no repository'"
        );
    }

    #[tokio::test]
    async fn a_cas_integrity_mismatch_is_unresolved_without_a_lookup() {
        let resolver = Arc::new(SpyResolver::default());
        let uc = EventVisibilityUseCase::new(resolver.clone());
        let page = vec![persisted(
            DomainEvent::CasIntegrityMismatch(CasIntegrityMismatch {
                content_hash: sha256(),
                backend: "filesystem".into(),
                observed_hash: sha256(),
            }),
            // The real emitter derives this entity id from the content
            // hash, NOT from an artifact id — which is exactly why there
            // is nothing to resolve.
            StreamId::artifact(Uuid::new_v4()),
            1,
        )];
        let index = uc.index(&page).await.expect("resolution must succeed");
        assert!(resolver.calls.lock().unwrap().is_empty());
        assert_eq!(
            index.disclosure(&page[0].event),
            EventDisclosure::Unresolved
        );
    }

    #[tokio::test]
    async fn a_group_member_event_resolves_both_aggregates() {
        let repo = Uuid::new_v4();
        let group = Uuid::new_v4();
        let artifact = Uuid::new_v4();
        let resolver = Arc::new(SpyResolver {
            artifacts: HashMap::from([(artifact, repo)]),
            groups: HashMap::from([(group, repo)]),
            ..SpyResolver::default()
        });
        let uc = EventVisibilityUseCase::new(resolver.clone());
        let page = vec![persisted(
            DomainEvent::ArtifactGroupMemberAdded(ArtifactGroupMemberAdded {
                group_id: group,
                role: "jar".into(),
                artifact_id: artifact,
            }),
            StreamId::artifact_group(group),
            1,
        )];
        let index = uc.index(&page).await.expect("resolution must succeed");

        let calls = resolver.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 1, "both aggregate kinds in ONE round trip");
        assert_eq!(calls[0].0, vec![artifact]);
        assert_eq!(calls[0].1, vec![group]);

        // Group and artifact live in the same repository, so the pair
        // collapses to one disclosure.
        match index.disclosure(&page[0].event) {
            EventDisclosure::Repositories(ids) => assert!(ids.iter().eq([repo])),
            other => panic!("expected one repository, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_group_member_whose_artifact_is_unknown_fails_closed() {
        let group = Uuid::new_v4();
        let resolver = Arc::new(SpyResolver {
            groups: HashMap::from([(group, Uuid::new_v4())]),
            ..SpyResolver::default()
        });
        let uc = EventVisibilityUseCase::new(resolver);
        let page = vec![persisted(
            DomainEvent::ArtifactGroupMemberAdded(ArtifactGroupMemberAdded {
                group_id: group,
                role: "jar".into(),
                artifact_id: Uuid::new_v4(),
            }),
            StreamId::artifact_group(group),
            1,
        )];
        let index = uc.index(&page).await.expect("resolution must succeed");
        assert_eq!(
            index.disclosure(&page[0].event),
            EventDisclosure::Unresolved,
            "one unresolvable reference of a pair must fail the whole disclosure closed"
        );
    }

    #[tokio::test]
    async fn a_global_event_is_global() {
        let resolver = Arc::new(SpyResolver::default());
        let uc = EventVisibilityUseCase::new(resolver);
        let page = vec![persisted(
            DomainEvent::OidcKeyRotated(hort_domain::events::OidcKeyRotated {
                kid_added: "kid-new".into(),
                kid_evicted: None,
                fetched_at: Utc::now(),
            }),
            StreamId::admin(Uuid::new_v4()),
            1,
        )];
        let index = uc.index(&page).await.expect("resolution must succeed");
        assert_eq!(index.disclosure(&page[0].event), EventDisclosure::Global);
    }

    #[tokio::test]
    async fn a_resolver_failure_is_reported_not_swallowed() {
        struct FailingResolver;
        impl EventRepositoryResolver for FailingResolver {
            fn resolve_event_aggregates<'a>(
                &'a self,
                _artifact_ids: &'a [Uuid],
                _artifact_group_ids: &'a [Uuid],
            ) -> BoxFuture<'a, DomainResult<EventAggregateRepositories>> {
                Box::pin(async {
                    Err(hort_domain::error::DomainError::Invariant(
                        "database error: pool exhausted".into(),
                    ))
                })
            }
        }
        let uc = EventVisibilityUseCase::new(Arc::new(FailingResolver));
        let page = vec![quarantined(Uuid::new_v4(), 1)];
        let err = uc
            .index(&page)
            .await
            .expect_err("an infrastructure failure must not silently degrade the page");
        assert!(err.to_string().contains("pool exhausted"));
    }

    /// The empty index is the one an unwired caller would hold. It must
    /// fail closed on an indirect disclosure rather than pass it through
    /// — and must still answer a payload-carried one, so a page with no
    /// lookups needs no resolver at all.
    #[test]
    fn the_empty_index_fails_closed_on_indirect_and_answers_direct() {
        let index = EventRepositoryIndex::empty();
        let artifact = Uuid::new_v4();
        assert_eq!(
            index.disclosure(&DomainEvent::ArtifactReleased(ArtifactReleased {
                artifact_id: artifact,
                released_by: ReleaseReason::Timer,
                released_by_user_id: None,
                justification: None,
            })),
            EventDisclosure::Unresolved
        );
        let repo = Uuid::new_v4();
        match index.disclosure(&DomainEvent::ArtifactPromoted(ArtifactPromoted {
            artifact_id: artifact,
            source_repository_id: repo,
            target_repository_id: repo,
        })) {
            EventDisclosure::Repositories(ids) => assert!(ids.iter().eq([repo])),
            other => panic!("expected the carried repository, got {other:?}"),
        }
    }
}
