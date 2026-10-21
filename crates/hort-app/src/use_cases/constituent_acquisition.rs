//! Acquiring the constituents of a **proxy** image manifest's composition,
//! so the composition can be assembled at all (ADR 0064 D1).
//!
//! # Why anything has to be fetched
//!
//! A hosted push cannot reach this module's reason for existing: the OCI
//! PUT path already requires every config and layer descriptor to resolve
//! to a deliverable same-repo row before the manifest commits, which is
//! the push order the distribution spec mandates. For a **pull-through**
//! manifest the opposite is the ordinary case. Its constituent edges are
//! registered by digest with **no existence check** — deliberately, since
//! that edge is what gives a proxy descendant the zero-window quarantine
//! carve-out on its own later ingest — so a cold proxy manifest nominates
//! a complete, well-formed composition **not one constituent of which is
//! here**. Its config blob included: the composition's own description is
//! a constituent like any other, which is why it is acquired as its own
//! phase before anything reads it (see [`AcquisitionRun`]).
//!
//! And waiting for them is not available: the client pull that would warm
//! those blobs **begins with the manifest whose verdict is being gated**.
//! So hort fetches blobs no client has asked for, for proxy repositories
//! only.
//!
//! # Acquisition is a dependency of the job, not a side effect of a request
//!
//! Nothing here runs on a request path. It runs inside the scan job, which
//! means it inherits that job's lease, its attempt budget and its
//! single-flight per artifact — and it means a transient failure has
//! somewhere to go (the orchestrator reschedules a backend error) instead
//! of having to be swallowed or retried in place.
//!
//! **What makes it durable is CAS itself.** A blob that landed survives a
//! worker restart, a lease expiry and a reschedule, because CAS is the
//! registry's own store and the manifest's `oci_config` / `oci_layer`
//! edges already claim those bytes against the storage GC — the same edges
//! the pull-through write path registered without checking existence. So
//! the next attempt's survey finds them present and does not fetch them
//! again, and acquisition never restarts from zero. No new table, no job
//! state, no checkpoint: the completion criterion is "the bytes are in
//! CAS", which is also exactly what the layout writer needs.
//!
//! # Every fetch is verified
//!
//! Bytes enter CAS through [`UpstreamProxy::fetch_blob`] — the one
//! upstream blob fetch in the system — and the hash `StoragePort::put`
//! computed from the streamed bytes is compared against the digest the
//! manifest declared. A disagreement refuses the constituent and is never
//! retried (ADR 0006: no fetch is unverified, and a mismatch is a
//! statement about the upstream's bytes that re-asking cannot change).
//! The put precedes the comparison because CAS keys on content, so the
//! real hash is only knowable after the streaming write; the bytes of a
//! refused fetch are content-addressed, claimed by nothing, never served,
//! and reaped by GC — the same put-then-verify trade the proxy
//! provenance-referrer path documents.
//!
//! # No release authority
//!
//! Acquisition writes bytes and nothing else: no `artifacts` row, no
//! event, no job, no quarantine window, no transition. It cannot make
//! anything downloadable that was not, and it cannot withhold anything
//! that was.
//!
//! The absence of a row is deliberate and it has one cost worth naming:
//! an acquired layer is CAS-present but not catalogued, so a client's own
//! later `GET` of that blob finds no row for its repository and pulls it
//! through again — one redundant upstream fetch, after which `put`
//! deduplicates on content and the row is created as it always was.
//! Minting the row here instead would mean committing an artifact, an
//! `ArtifactIngested` event, a quarantine window and a scan job as a side
//! effect of an assessment that carries no authority, which is a much
//! larger claim than warming the cache. The layout writer reads CAS, not
//! rows, so the row buys this path nothing.

use std::collections::HashSet;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use hort_domain::entities::artifact::Artifact;
use hort_domain::error::DomainError;
use hort_domain::oci::{ImageBudget, ImageDescriptorSlot, ManifestNomination};
use hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMapping;
use hort_domain::ports::scanner::ComposedImage;
use hort_domain::ports::storage::StoragePort;
use hort_domain::ports::upstream_proxy::UpstreamProxy;
use hort_domain::ports::upstream_resolver::UpstreamResolver;
use hort_domain::types::ContentHash;
use tokio::io::AsyncReadExt;
use tokio::time::error::Elapsed;
use tokio::time::Instant;
use tokio_util::io::StreamReader;

use crate::metrics::UpstreamErrorKind;

/// How many times one constituent is fetched within a single acquisition.
///
/// Two: the first attempt, plus one immediate retry for a **transient**
/// classification only. A deterministic answer — the upstream does not
/// have this digest, it refuses to serve it, or the bytes it served hash
/// to something else — is not retried at all, here or later.
///
/// The number is deliberately small, because this is the *inner* of two
/// retry budgets and they multiply. The outer one is the scan job's own
/// (`ScanOrchestrationConfig::max_attempts`), which is where a genuinely
/// unavailable upstream is waited out, on a backoff, with the whole estate
/// spending one attempt per image rather than one per layer. What the
/// inner retry buys that the outer cannot is the single dropped
/// connection: absorbing it costs one extra request instead of a 60-second
/// backoff. What it must not buy is a flapping upstream the chance to
/// spend the whole wall-clock budget on one layer, which is why it is
/// bounded rather than "retry until the budget runs out".
const MAX_ATTEMPTS_PER_CONSTITUENT: u32 = 2;

/// What acquiring one **phase** of a composition's constituents produced.
///
/// The two failure arms are the split this module exists for. They are not
/// degrees of the same thing: one is a statement about the **image** that
/// re-running reproduces exactly, the other a statement about the
/// **upstream's or the store's availability** that re-running may well
/// clear. Collapsing them — which is what a single "could not assemble"
/// value does — turns a momentary upstream hiccup into a
/// permanent-looking absence of assessment, and that is the direction that
/// matters, because an absence of assessment is what the release gate
/// reads.
///
/// `Complete` carries nothing because a *phase* completing is not the
/// acquisition completing — what the whole acquisition cost is on
/// [`AcquisitionRun::stats`], which accumulates across the phases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Acquisition {
    /// Every constituent this phase was asked for is in CAS. Says nothing
    /// about *how* it got there: a phase whose constituents were already
    /// local — every hosted image, and every proxy image a client has
    /// pulled — reaches this arm having fetched nothing.
    Complete,
    /// The composition cannot be completed, and re-running changes
    /// nothing: more constituents or more bytes than hort will assemble, a
    /// repository with no upstream to acquire from, a digest the upstream
    /// does not have, or bytes that failed verification.
    Deterministic(String),
    /// The composition is not complete *yet*, for a condition that may
    /// clear: the upstream was unreachable, timed out, rate-limited or
    /// returned a retryable status, or storage did not answer.
    Transient(String),
}

/// What an acquisition cost. Separating the two counts is what lets a log
/// line distinguish "this image was already local" from "hort pulled this
/// image", which is the difference an operator watching egress cares about.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AcquisitionStats {
    /// Constituents already in CAS when the survey ran.
    pub(crate) already_present: usize,
    /// Constituents fetched from the upstream by this acquisition.
    pub(crate) fetched: usize,
    /// Bytes written by those fetches.
    pub(crate) fetched_bytes: u64,
}

/// One constituent's fetch outcome, before the per-constituent attempt
/// bound is applied.
enum FetchFault {
    /// Re-asking gets the same answer.
    Deterministic(String),
    /// Re-asking may get a different one.
    Transient(String),
}

/// The composition phase's **one clock**.
///
/// A composite scan has two bounded spans — resolving-and-acquiring the
/// composition, and materialising it as a layout — and this is the first
/// of them. It is one span rather than four because what
/// `MAX_IMAGE_LAYOUT_DURATION` bounds is worker *occupancy*, and the slot
/// does not care how the work was divided: the manifest document's read,
/// the config phase, the config document's read and the layer phase all
/// run under this single deadline.
///
/// It exists as a value, created before the first of those steps and
/// handed to [`ConstituentAcquisition::begin`], because a deadline each
/// step created for itself would bound no step's *neighbour* — which is
/// exactly the gap it closes. Neither `read_cas_bounded` nor
/// `StoragePort::get` nor an upstream response carries a deadline of its
/// own: the read ceiling bounds a document's **bytes**, so a store that
/// trickles a one-kilobyte manifest can hold a worker slot indefinitely
/// without a single scanner ever being pointed at anything.
///
/// Started from the budget the acquisition itself runs under
/// ([`ConstituentAcquisition::start_span`] is the only constructor), so
/// the span and the phases inside it cannot be bounded by two different
/// numbers.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CompositionSpan {
    /// When the span ends.
    deadline: Instant,
    /// What it was given, for the refusal message — read from here rather
    /// than from the budget again, so the number a caller reports is the
    /// number the clock was actually set by.
    budget: Duration,
}

impl CompositionSpan {
    /// Run `work` under what is left of the span.
    ///
    /// `Err` means the span ran out, which is **transient** wherever it
    /// happens: a store or an upstream that is slow is an availability
    /// condition, nothing about the image changed, and the next attempt may
    /// well land.
    pub(crate) async fn bound<F: Future>(&self, work: F) -> Result<F::Output, Elapsed> {
        tokio::time::timeout_at(self.deadline, work).await
    }

    /// How the span words its own exhaustion, naming the step that was
    /// still running.
    ///
    /// One phrasing for every step, because a read that ran out of clock
    /// and a fetch that ran out of clock are the same fact about the same
    /// span — an operator correlating two log lines should not have to
    /// recognise two spellings of it.
    pub(crate) fn exhausted(&self, step: &str) -> String {
        format!(
            "{step} did not finish within the composition phase's wall-clock budget ({}s)",
            self.budget.as_secs()
        )
    }
}

/// Acquire the constituents of one composition.
///
/// A struct rather than a function with six arguments: the caller
/// assembles it from handles it already holds, and naming them at the call
/// site is what keeps "whose upstream?" and "which artifact?" answerable
/// by reading it.
pub(crate) struct ConstituentAcquisition<'a> {
    /// CAS: the presence survey, and where fetched bytes land.
    pub(crate) storage: &'a Arc<dyn StoragePort>,
    /// The one upstream blob fetch in the system.
    pub(crate) upstream_proxy: &'a Arc<dyn UpstreamProxy>,
    /// Resolves the repository's configured upstream for this name. A
    /// repository with no matching mapping cannot fetch, and that is read
    /// off the configuration rather than inferred from the row.
    pub(crate) upstream_resolver: &'a Arc<dyn UpstreamResolver>,
    /// The manifest row whose composition is being acquired — its
    /// repository and its client-facing name are what resolve the
    /// upstream, exactly as a client pull of the same name would.
    pub(crate) artifact: &'a Artifact,
    /// The whole-image bounds. The **same** value the layout writer runs
    /// under, so a byte or a constituent acquisition is willing to spend is
    /// one the layout can still hold.
    pub(crate) budget: ImageBudget,
}

impl<'a> ConstituentAcquisition<'a> {
    /// Start the composition phase's clock, from this acquisition's own
    /// budget.
    ///
    /// Called by the caller rather than by [`Self::begin`], and that is the
    /// whole point: by the time the count bound is spent, the span's first
    /// step — reading the manifest document out of CAS — has already run.
    /// A clock that started at `begin` would leave that read, and the
    /// config document's read between the two phases, bounded by nothing.
    pub(crate) fn start_span(&self) -> CompositionSpan {
        CompositionSpan {
            deadline: Instant::now() + self.budget.max_duration,
            budget: self.budget.max_duration,
        }
    }

    /// Begin acquiring the constituents `nomination` names, in the two
    /// phases the composition itself divides into, under the composition
    /// phase's already-running `span`.
    ///
    /// One thing happens here rather than inside a phase, and it is
    /// *because* there are two phases: **the constituent count is checked
    /// once, over the whole nominated set** — config and layers together,
    /// from the manifest bytes alone. It is the cheapest refusal and the one
    /// that keeps the other two bounds from being reached N times over, so
    /// an over-count image must cost zero round-trips: checking it per phase
    /// would spend a config fetch before refusing for a count the manifest
    /// had already stated. It is also the one bound that is spent **before
    /// any I/O**, so the span it is checked inside is immaterial to it.
    ///
    /// The wall clock is *not* started here — see [`Self::start_span`].
    /// Both phases run under the span the caller passes, so a composition
    /// acquired in more steps is not one hort waits longer for.
    ///
    /// `Err` is the deterministic refusal, worded for a caller to report:
    /// re-running reads the same manifest and counts the same descriptors.
    pub(crate) fn begin(
        self,
        nomination: &ManifestNomination,
        span: CompositionSpan,
    ) -> Result<AcquisitionRun<'a>, String> {
        let declared = nomination.constituent_count();
        if declared > self.budget.max_blobs {
            return Err(format!(
                "image declares {declared} constituents; the whole-image budget allows {}",
                self.budget.max_blobs
            ));
        }
        Ok(AcquisitionRun {
            span,
            acquisition: self,
            stats: AcquisitionStats::default(),
            charged: 0,
            seen: HashSet::new(),
        })
    }

    /// Fetch one constituent, under the per-constituent attempt bound.
    async fn fetch_constituent(
        &self,
        mapping: &RepositoryUpstreamMapping,
        upstream_name: &str,
        slot: ImageDescriptorSlot,
        hash: &ContentHash,
        remaining: u64,
    ) -> Result<u64, FetchFault> {
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            match self
                .fetch_attempt(mapping, upstream_name, slot, hash, remaining)
                .await
            {
                Ok(size) => return Ok(size),
                // Not retried, at either level: re-asking gets the same
                // answer, and a retry here would only delay saying so.
                Err(FetchFault::Deterministic(why)) => return Err(FetchFault::Deterministic(why)),
                Err(FetchFault::Transient(why)) if attempt >= MAX_ATTEMPTS_PER_CONSTITUENT => {
                    return Err(FetchFault::Transient(format!(
                        "{slot} (sha256:{hash}) could not be acquired in \
                         {MAX_ATTEMPTS_PER_CONSTITUENT} attempts: {why}"
                    )))
                }
                Err(FetchFault::Transient(why)) => tracing::debug!(
                    artifact_id = %self.artifact.id,
                    upstream_name,
                    constituent = %slot,
                    attempt,
                    max_attempts = MAX_ATTEMPTS_PER_CONSTITUENT,
                    reason = %why,
                    "constituent acquisition: transient upstream failure; retrying",
                ),
            }
        }
    }

    /// One upstream fetch, streamed into CAS and verified against the
    /// digest the manifest declared.
    async fn fetch_attempt(
        &self,
        mapping: &RepositoryUpstreamMapping,
        upstream_name: &str,
        slot: ImageDescriptorSlot,
        hash: &ContentHash,
        remaining: u64,
    ) -> Result<u64, FetchFault> {
        let fetch = self
            .upstream_proxy
            .fetch_blob(
                mapping.clone(),
                upstream_name.to_string(),
                format!("sha256:{hash}"),
            )
            .await
            .map_err(|e| classify_upstream_failure(&e, slot, hash))?;

        // One byte past the remaining budget, so "exactly at the ceiling"
        // and "over it" are distinguishable: a blob that fits lands whole,
        // and a blob that does not is recognised as over-budget rather
        // than arriving as a silently truncated body whose digest happens
        // not to match. (The same `+ 1` idiom the bounded event-stream
        // read uses, for the same reason.)
        let reader = StreamReader::new(fetch.stream).take(remaining.saturating_add(1));
        let put = self
            .storage
            .put(Box::new(reader))
            .await
            // CAS could not take the bytes: the object store or the disk,
            // not the image. Re-running may well succeed.
            .map_err(|e| {
                FetchFault::Transient(format!(
                    "{slot} (sha256:{hash}) was fetched but could not be written to storage: {e}"
                ))
            })?;

        if put.size_bytes > remaining {
            return Err(FetchFault::Deterministic(format!(
                "{slot} (sha256:{hash}) exceeded the whole-image byte budget ({} bytes)",
                self.budget.max_bytes
            )));
        }

        // ADR 0006. The hash is computed from the bytes that streamed, so
        // this compares what arrived against what the manifest declared —
        // and a disagreement is the upstream serving something else under
        // that digest, which re-asking does not change.
        if put.hash != *hash {
            return Err(FetchFault::Deterministic(format!(
                "upstream served bytes hashing to sha256:{} for {slot} (sha256:{hash}); \
                 refusing the composition rather than assembling an image hort cannot \
                 name",
                put.hash
            )));
        }

        Ok(put.size_bytes)
    }
}

/// One acquisition in flight, across its two phases.
///
/// **Why two phases and not one list.** A composition's own description is a
/// constituent like any other — on a pull-through manifest the config blob is
/// as absent as the layers are — and its bytes are what decide whether the
/// manifest describes a runnable filesystem at all. An **artifact** manifest
/// (a cosign signature, an SBOM attachment, a Helm chart) is a large,
/// legitimate population on a proxy, and its config says "no layered root
/// filesystem". Acquiring the whole nominated set up front would fetch every
/// one of their layers before learning there is nothing to compose — bytes
/// hort will not assess, which is exactly what ADR 0064 D1's "edges nominate
/// and the bytes decide" is there to avoid. So the config is acquired first,
/// read, and allowed to end the composition before a single layer is asked
/// for.
///
/// **What makes them one acquisition.** Three things cross the seam rather
/// than restarting at it, and each would be a defect if it did not:
///
/// - the **byte charge**, which accumulates across both phases and charges
///   the config once, so the budget bounds the composition and not a phase of
///   it;
/// - the **digests already surveyed**, because a manifest may name its config
///   digest again as a layer and CAS addresses one object either way;
/// - the **wall clock**, which is older than the acquisition: it is the
///   composition phase's [`CompositionSpan`], already running when
///   [`ConstituentAcquisition::begin`] was handed it, and it covers the two
///   document reads the caller makes around these phases as well.
pub(crate) struct AcquisitionRun<'a> {
    /// The handles and bounds every phase runs under.
    acquisition: ConstituentAcquisition<'a>,
    /// The composition phase's one clock, shared with both phases and with
    /// the caller's two document reads. A phase that trips it reports the
    /// whole span's budget, because that is what was spent.
    span: CompositionSpan,
    /// What the phases that have run so far cost.
    stats: AcquisitionStats,
    /// Bytes charged so far, across every phase and across present and
    /// fetched constituents alike.
    charged: u64,
    /// Digests already surveyed, so a digest named twice — in one phase or
    /// across both — is surveyed once, fetched once and charged once.
    seen: HashSet<ContentHash>,
}

impl AcquisitionRun<'_> {
    /// **Phase 1** — the composition's own description.
    ///
    /// One constituent, and it is first because its bytes decide whether
    /// there is a second phase at all. See [`AcquisitionRun`] for why that
    /// ordering is the point rather than an optimisation.
    pub(crate) async fn acquire_config(&mut self, nomination: &ManifestNomination) -> Acquisition {
        self.phase(&[(ImageDescriptorSlot::Config, nomination.config())])
            .await
    }

    /// **Phase 2** — the layers, once the config bytes have said there is a
    /// layered filesystem to compose.
    pub(crate) async fn acquire_layers(&mut self, image: &ComposedImage) -> Acquisition {
        let layers: Vec<(ImageDescriptorSlot, &ContentHash)> = image
            .layers()
            .iter()
            .enumerate()
            .map(|(index, layer)| (ImageDescriptorSlot::Layer(index), &layer.hash))
            .collect();
        self.phase(&layers).await
    }

    /// What this acquisition has cost across every phase that has run.
    ///
    /// Read by the caller's log line, which is why the two counts stay
    /// separate: "this image was already local" and "hort pulled this image"
    /// are the distinction an operator watching egress cares about.
    pub(crate) fn stats(&self) -> AcquisitionStats {
        self.stats
    }

    /// One phase, under the composition phase's shared wall clock.
    async fn phase(&mut self, constituents: &[(ImageDescriptorSlot, &ContentHash)]) -> Acquisition {
        let span = self.span;
        match span.bound(self.survey_and_fetch(constituents)).await {
            Ok(outcome) => outcome,
            // A stalled or trickling upstream, or a storage backend that
            // is not answering. Transient by the same reasoning as every
            // other availability condition: nothing about the image
            // changed, and the next attempt may well land.
            Err(_elapsed) => {
                Acquisition::Transient(span.exhausted("acquiring the composition's constituents"))
            }
        }
    }

    /// The survey, then the fetches, for one phase's constituents.
    ///
    /// The byte budget is charged across *every* constituent (not only the
    /// fetched ones), because the budget bounds what the composition costs
    /// and the layout writer will charge all of them too — an acquisition
    /// that only counted its own fetches would pull bytes over the network
    /// that the writer is then guaranteed to refuse. The charge omits the
    /// manifest blob, which the writer does count, so it is a **lower** bound
    /// on the composition's cost: this can never refuse an image the writer
    /// would have assembled, and the most it can over-fetch is one
    /// manifest's worth (kilobytes in practice, and bounded by the
    /// resolution's own read ceiling).
    ///
    /// The manifest is not surveyed for the same reason: its bytes were just
    /// read from CAS to resolve this composition, so probing it asks a
    /// question already answered. If it has gone since, the layout writer
    /// names it as an absent constituent, which is the right refusal.
    async fn survey_and_fetch(
        &mut self,
        constituents: &[(ImageDescriptorSlot, &ContentHash)],
    ) -> Acquisition {
        let mut missing: Vec<(ImageDescriptorSlot, ContentHash)> = Vec::new();
        for (slot, hash) in constituents {
            // A manifest may declare the same layer digest twice (a repeated
            // empty layer is the common case), and may name its config digest
            // again as a layer. CAS addresses a blob by its digest, so the
            // second occurrence is the same object: survey it once, fetch it
            // once, charge it once — the same dedup the layout writer applies
            // to the same list.
            if !self.seen.insert((*hash).clone()) {
                continue;
            }
            // `size_of` answers presence *and* size in one round-trip, and
            // reports absence as a typed `NotFound` — which is what makes
            // "not here yet" distinguishable from "the store failed"
            // without reading a message.
            match self.acquisition.storage.size_of(hash).await {
                Ok(size) => {
                    self.stats.already_present += 1;
                    self.charged = self.charged.saturating_add(size);
                    if self.charged > self.acquisition.budget.max_bytes {
                        return Acquisition::Deterministic(format!(
                            "the constituents already in storage exceed the whole-image byte \
                             budget ({} bytes) by {slot} (sha256:{hash}); nothing was fetched",
                            self.acquisition.budget.max_bytes
                        ));
                    }
                }
                Err(DomainError::NotFound { .. }) => missing.push((*slot, (*hash).clone())),
                Err(e) => {
                    return Acquisition::Transient(format!(
                        "storage could not be asked whether {slot} (sha256:{hash}) is \
                         present: {e}"
                    ))
                }
            }
        }

        if missing.is_empty() {
            return Acquisition::Complete;
        }

        // A hosted repository has no upstream, and neither has a proxy
        // whose mappings do not prefix this name. Either way there is
        // nowhere to acquire from, so the absence is a real refusal and
        // stays one — and no fetch is attempted to discover that.
        let Some((mapping, upstream_name)) = self.acquisition.upstream_resolver.resolve(
            self.acquisition.artifact.repository_id,
            &self.acquisition.artifact.name,
        ) else {
            let (slot, hash) = &missing[0];
            return Acquisition::Deterministic(format!(
                "the composition's {slot} (sha256:{hash}) is not in storage, and this \
                 repository has no configured upstream to acquire it from"
            ));
        };

        for (slot, hash) in &missing {
            let remaining = self
                .acquisition
                .budget
                .max_bytes
                .saturating_sub(self.charged);
            match self
                .acquisition
                .fetch_constituent(&mapping, &upstream_name, *slot, hash, remaining)
                .await
            {
                Ok(size) => {
                    self.stats.fetched += 1;
                    self.stats.fetched_bytes = self.stats.fetched_bytes.saturating_add(size);
                    self.charged = self.charged.saturating_add(size);
                }
                // The first failure ends the acquisition. Every
                // constituent is required — a composition missing one is
                // not a smaller image, it is a complete-looking image with
                // fewer layers — so continuing would spend the rest of the
                // budget on bytes that cannot produce a verdict.
                Err(FetchFault::Deterministic(why)) => return Acquisition::Deterministic(why),
                Err(FetchFault::Transient(why)) => return Acquisition::Transient(why),
            }
        }

        Acquisition::Complete
    }
}

/// Which side of the retry decision an upstream blob-fetch failure falls
/// on.
///
/// Read off the upstream port's **own** error vocabulary
/// ([`UpstreamErrorKind::from_domain_error`], the one decoder for the
/// sentinel the upstream adapter encodes), never off the rendered message.
/// The match over the kinds is exhaustive on purpose: a kind added later
/// has to state its side rather than inherit one, and inheriting the wrong
/// one here is invisible — a deterministic classification of a transient
/// condition shows up only as an image that never gets assessed.
///
/// The principle behind the split is "what is this condition *about*":
///
/// - **About the object, or about hort's configuration** — the upstream
///   does not have the digest, refuses to serve it to the credential
///   configured for this mapping, rejects the request, presents a
///   certificate hort will not trust, or serves bytes that fail
///   verification. Re-asking with the same digest, the same credential and
///   the same trust store gets the same answer, so a retry is pure delay.
/// - **About availability** — unreachable, timed out, rate-limited, 5xx.
///   These are precisely the conditions that clear by themselves, and they
///   are the routine case for an estate that proxies.
///
/// An error carrying **no** classification did not come from the fetch's
/// own taxonomy, so there is nothing to read: it is treated as transient,
/// because an unnamed failure is far more likely to be an infrastructure
/// condition than a statement about the image, and the cost of being wrong
/// is bounded by the scan job's attempt budget rather than open-ended.
fn classify_upstream_failure(
    err: &DomainError,
    slot: ImageDescriptorSlot,
    hash: &ContentHash,
) -> FetchFault {
    let subject = format!("{slot} (sha256:{hash})");
    match UpstreamErrorKind::from_domain_error(err) {
        Some(kind) => match kind {
            UpstreamErrorKind::NotFound => {
                FetchFault::Deterministic(format!("the upstream does not have {subject}: {err}"))
            }
            UpstreamErrorKind::Unauthorized
            | UpstreamErrorKind::Upstream4xx
            | UpstreamErrorKind::ParseError
            | UpstreamErrorKind::ChecksumMismatch
            | UpstreamErrorKind::PinMismatch
            | UpstreamErrorKind::CaUnknown
            | UpstreamErrorKind::BodyTooLarge
            | UpstreamErrorKind::MetadataTooLarge
            | UpstreamErrorKind::ManifestTooLarge
            | UpstreamErrorKind::VersionObjectTooLarge => {
                FetchFault::Deterministic(format!("the upstream refused to serve {subject}: {err}"))
            }
            UpstreamErrorKind::RateLimited
            | UpstreamErrorKind::Upstream5xx
            | UpstreamErrorKind::NetworkError
            | UpstreamErrorKind::Timeout => {
                FetchFault::Transient(format!("the upstream did not serve {subject}: {err}"))
            }
            // An error classified as success is a contradiction, so there
            // is no fact to act on — the same position an unclassified
            // error leaves us in, and it takes the same answer.
            UpstreamErrorKind::Success => FetchFault::Transient(format!(
                "the upstream fetch of {subject} failed without saying how: {err}"
            )),
        },
        None => FetchFault::Transient(format!(
            "the upstream fetch of {subject} failed with no upstream classification: {err}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use chrono::Utc;
    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::oci::strict_manifest_nomination;
    use hort_domain::ports::repository_upstream_mapping_repository::UpstreamAuth;
    use hort_domain::ports::upstream_proxy::BlobFetch;
    use hort_domain::ports::BoxFuture;
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    use crate::use_cases::test_support::{
        oci_image_config_bytes, oci_image_manifest_bytes, MockStoragePort, MockUpstreamProxy,
        MockUpstreamResolver,
    };

    const REPO_NAME: &str = "library/nginx";

    /// The real SHA-256 of `bytes`, so "the upstream served the declared
    /// digest" is a claim about the digest rather than a tautology about
    /// whatever string the fixture passed in. `MockStoragePort::put`
    /// hashes what streams through it exactly as a production adapter
    /// does, so the verification arm is genuinely exercised.
    fn sha256_of(bytes: &[u8]) -> ContentHash {
        hex::encode(Sha256::digest(bytes))
            .parse()
            .expect("a sha256 hex digest")
    }

    fn hash_of(seed: char) -> ContentHash {
        std::iter::repeat_n(seed, 64)
            .collect::<String>()
            .parse()
            .expect("synthetic sha256")
    }

    fn manifest_artifact(repository_id: Uuid) -> Artifact {
        let now = Utc::now();
        Artifact {
            id: Uuid::new_v4(),
            repository_id,
            name: REPO_NAME.to_string(),
            name_as_published: REPO_NAME.to_string(),
            version: Some("1.27".to_string()),
            path: "manifests/1.27".to_string(),
            size_bytes: 512,
            sha256_checksum: hash_of('a'),
            sha1_checksum: None,
            md5_checksum: None,
            content_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            quarantine_status: QuarantineStatus::Quarantined,
            rejection_reason: None,
            quarantine_window_start: None,
            quarantine_deadline: None,
            provenance_hold_indefinite: false,
            deleted_at: None,
            upstream_published_at: None,
            uploaded_by: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// The two values the composite sequence hands an acquisition: the
    /// manifest's own **nomination** (phase 1's input, which is all that
    /// exists before the config blob is here) and the **completed
    /// composition** (phase 2's).
    ///
    /// Both are derived from one manifest document, which is the point: a
    /// fixture that built them separately could disagree about which
    /// digests the image is made of, and this module — handed the two — has
    /// no way to notice.
    fn composition(
        config: &ContentHash,
        layers: &[&ContentHash],
    ) -> (ManifestNomination, ComposedImage) {
        let bytes = oci_image_manifest_bytes(config, layers);
        let nomination =
            strict_manifest_nomination(&bytes).expect("the fixture manifest nominates");
        let layout = nomination
            .clone()
            .complete_with_config(&oci_image_config_bytes(layers.len()))
            .expect("the fixture config completes the nomination");
        (nomination, ComposedImage::new(hash_of('a'), layout))
    }

    fn mapping(repository_id: Uuid) -> RepositoryUpstreamMapping {
        let now = Utc::now();
        RepositoryUpstreamMapping {
            id: Uuid::new_v4(),
            repository_id,
            path_prefix: String::new(),
            upstream_url: "https://registry.example".into(),
            upstream_name_prefix: None,
            upstream_auth: UpstreamAuth::Anonymous,
            secret_ref: None,
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
            insecure_upstream_url: false,
            trust_upstream_publish_time: false,
            mtls_cert_ref: None,
            mtls_key_ref: None,
            ca_bundle_ref: None,
            pinned_cert_sha256: None,
            allowed_realm_hosts: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// A resolver that answers for `repository_id` — the proxy shape.
    fn proxy_resolver(repository_id: Uuid) -> Arc<dyn UpstreamResolver> {
        Arc::new(MockUpstreamResolver::with_mappings(vec![mapping(
            repository_id,
        )]))
    }

    /// A resolver that answers for nothing — the hosted shape.
    fn hosted_resolver() -> Arc<dyn UpstreamResolver> {
        Arc::new(MockUpstreamResolver::new())
    }

    /// Seed the proxy so `digest` resolves to `body` under the catch-all
    /// mapping the fixtures use.
    fn seed_blob(proxy: &MockUpstreamProxy, hash: &ContentHash, body: &[u8]) {
        proxy.insert_blob(
            "",
            REPO_NAME,
            &format!("sha256:{hash}"),
            body.to_vec(),
            None,
        );
    }

    /// An upstream whose every blob fetch takes `delay` and then answers
    /// from `inner`.
    ///
    /// A wrapper rather than a fourth hand-rolled `UpstreamProxy` so that
    /// what the slow upstream *serves* is the same seeded fixture every
    /// other test uses — which is what lets one double drive both "a
    /// stalled upstream trips the clock" and "two phases that each fit the
    /// clock do not fit it together".
    struct SlowProxy {
        inner: Arc<MockUpstreamProxy>,
        delay: Duration,
    }

    impl UpstreamProxy for SlowProxy {
        fn fetch_blob(
            &self,
            mapping: RepositoryUpstreamMapping,
            upstream_name: String,
            digest: String,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<BlobFetch>> {
            // The inner call is made eagerly, because `MockUpstreamProxy`
            // records a fetch when it is *asked for* rather than when it
            // answers — which is what lets a test see a fetch the wall
            // clock then cut off mid-flight.
            let fetch = self.inner.fetch_blob(mapping, upstream_name, digest);
            let delay = self.delay;
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                fetch.await
            })
        }
        fn fetch_manifest(
            &self,
            _mapping: RepositoryUpstreamMapping,
            _upstream_name: String,
            _reference: String,
            _accept: Vec<String>,
        ) -> BoxFuture<
            '_,
            hort_domain::error::DomainResult<
                hort_domain::ports::upstream_proxy::ManifestFetchOutcome,
            >,
        > {
            Box::pin(async { unreachable!("a composition acquires blobs and nothing else") })
        }
        fn fetch_artifact(
            &self,
            _mapping: RepositoryUpstreamMapping,
            _path: String,
        ) -> BoxFuture<
            '_,
            hort_domain::error::DomainResult<hort_domain::ports::upstream_proxy::ArtifactFetch>,
        > {
            Box::pin(async { unreachable!("a composition acquires blobs and nothing else") })
        }
        fn fetch_metadata(
            &self,
            _mapping: RepositoryUpstreamMapping,
            _path: String,
            _accept: Vec<String>,
        ) -> BoxFuture<
            '_,
            hort_domain::error::DomainResult<
                hort_domain::ports::upstream_proxy::MetadataFetchOutcome,
            >,
        > {
            Box::pin(async { unreachable!("a composition acquires blobs and nothing else") })
        }
    }

    /// Drive a whole acquisition — the count bound, then phase 1, then
    /// phase 2 — in the same order and as the same single run that
    /// [`resolve_composition`](crate::use_cases::composite_scan) drives,
    /// with the two parse steps between the phases removed.
    ///
    /// The composition phase's span is started before `begin`, exactly as
    /// the sequence starts it: there the manifest document's read has
    /// already happened inside it, and here there is nothing before it, so
    /// the phases below get the whole budget. What this harness therefore
    /// pins is that the two **phases** share one clock; that the two
    /// document reads share it with them is pinned where those reads live
    /// (`composite_scan`).
    ///
    /// Returns the outcome together with what the run cost, because a
    /// *phase's* `Complete` carries no stats. A phase that does not reach
    /// `Complete` ends the acquisition, exactly as the sequence ends it:
    /// there is no composition left to acquire the rest of.
    async fn run(
        storage: &Arc<dyn StoragePort>,
        proxy: &Arc<dyn UpstreamProxy>,
        resolver: &Arc<dyn UpstreamResolver>,
        artifact: &Artifact,
        budget: ImageBudget,
        composition: &(ManifestNomination, ComposedImage),
    ) -> (Acquisition, AcquisitionStats) {
        let (nomination, image) = composition;
        let acquisition = ConstituentAcquisition {
            storage,
            upstream_proxy: proxy,
            upstream_resolver: resolver,
            artifact,
            budget,
        };
        let span = acquisition.start_span();
        let begun = acquisition.begin(nomination, span);
        let mut run = match begun {
            Ok(run) => run,
            // The count bound is the one refusal `begin` makes, and the
            // sequence reports it as deterministic.
            Err(why) => return (Acquisition::Deterministic(why), AcquisitionStats::default()),
        };
        match run.acquire_config(nomination).await {
            Acquisition::Complete => {}
            ended => return (ended, run.stats()),
        }
        let outcome = run.acquire_layers(image).await;
        (outcome, run.stats())
    }

    // -- the hosted shape -------------------------------------------------

    /// A hosted repository has no upstream, so an absent constituent is a
    /// real refusal — and no fetch is attempted to discover that. The
    /// proxy's call log is the assertion: it is the only observation that
    /// distinguishes "did not fetch" from "fetched and failed".
    #[tokio::test]
    async fn a_hosted_repository_refuses_an_absent_constituent_without_fetching() {
        let storage = MockStoragePort::new();
        let (config, layer) = (hash_of('c'), hash_of('1'));
        storage.insert_content(config.clone(), b"{config}".to_vec());
        let storage: Arc<dyn StoragePort> = Arc::new(storage);
        let mock_proxy = Arc::new(MockUpstreamProxy::new());
        let proxy: Arc<dyn UpstreamProxy> = mock_proxy.clone();
        let artifact = manifest_artifact(Uuid::new_v4());

        let (outcome, _) = run(
            &storage,
            &proxy,
            &hosted_resolver(),
            &artifact,
            ImageBudget::default_for_composite_scan(),
            &composition(&config, &[&layer]),
        )
        .await;

        let Acquisition::Deterministic(why) = outcome else {
            panic!("a hosted repository cannot acquire; got {outcome:?}");
        };
        assert!(why.contains("no configured upstream"), "{why}");
        assert!(why.contains("layers[0]"), "the refusal names a slot: {why}");
        assert!(
            mock_proxy.blob_fetches().is_empty(),
            "a hosted repository must not reach an upstream at all"
        );
    }

    /// The same refusal one phase earlier: a hosted row whose **config** is
    /// absent. It is the arm that could not be reached before the config
    /// became a constituent — resolution read the config blob first, so an
    /// absent one was reported as an unresolvable composition and the
    /// acquisition never ran. The refusal now names `config`, and the
    /// layers are not even probed: there is no composition to complete.
    #[tokio::test]
    async fn a_hosted_repository_with_an_absent_config_refuses_naming_the_config() {
        let storage_mock = Arc::new(MockStoragePort::new());
        let storage: Arc<dyn StoragePort> = storage_mock.clone();
        let mock_proxy = Arc::new(MockUpstreamProxy::new());
        let proxy: Arc<dyn UpstreamProxy> = mock_proxy.clone();
        let artifact = manifest_artifact(Uuid::new_v4());
        let (config, lower, upper) = (hash_of('c'), hash_of('1'), hash_of('2'));

        let (outcome, stats) = run(
            &storage,
            &proxy,
            &hosted_resolver(),
            &artifact,
            ImageBudget::default_for_composite_scan(),
            &composition(&config, &[&lower, &upper]),
        )
        .await;

        let Acquisition::Deterministic(why) = outcome else {
            panic!("a hosted repository cannot acquire its config either; got {outcome:?}");
        };
        assert!(why.contains("no configured upstream"), "{why}");
        assert!(
            why.contains("config") && !why.contains("layers["),
            "the refusal names the config, not a layer: {why}"
        );
        assert!(mock_proxy.blob_fetches().is_empty());
        assert_eq!(
            storage_mock.size_of_call_count(),
            1,
            "phase 1 probes the config and stops; the layers belong to a composition \
             the config has not established exists"
        );
        assert_eq!(stats, AcquisitionStats::default());
    }

    /// Every constituent already local — every hosted image, and every
    /// proxy image a client has pulled — is a survey and nothing more.
    #[tokio::test]
    async fn a_complete_composition_fetches_nothing() {
        let storage = MockStoragePort::new();
        let (config, lower, upper) = (hash_of('c'), hash_of('1'), hash_of('2'));
        for (hash, bytes) in [
            (&config, b"{config}".to_vec()),
            (&lower, b"lower".to_vec()),
            (&upper, b"upper".to_vec()),
        ] {
            storage.insert_content(hash.clone(), bytes);
        }
        let storage: Arc<dyn StoragePort> = Arc::new(storage);
        let mock_proxy = Arc::new(MockUpstreamProxy::new());
        let proxy: Arc<dyn UpstreamProxy> = mock_proxy.clone();
        let artifact = manifest_artifact(Uuid::new_v4());

        let (outcome, stats) = run(
            &storage,
            &proxy,
            &proxy_resolver(artifact.repository_id),
            &artifact,
            ImageBudget::default_for_composite_scan(),
            &composition(&config, &[&lower, &upper]),
        )
        .await;

        assert_eq!(outcome, Acquisition::Complete);
        assert_eq!(
            stats,
            AcquisitionStats {
                already_present: 3,
                fetched: 0,
                fetched_bytes: 0,
            },
            "the two phases' counts accumulate into one acquisition's"
        );
        assert!(mock_proxy.blob_fetches().is_empty());
    }

    // -- the proxy shape --------------------------------------------------

    /// Only the absent constituents go to the upstream. The present one is
    /// left alone — not re-fetched, not re-verified, not re-written.
    #[tokio::test]
    async fn a_proxy_fetches_only_the_absent_constituents() {
        let (lower_bytes, upper_bytes) = (b"lower layer".as_slice(), b"upper layer".as_slice());
        let (lower, upper) = (sha256_of(lower_bytes), sha256_of(upper_bytes));
        let config_bytes = b"{config}".as_slice();
        let config = sha256_of(config_bytes);

        let storage = MockStoragePort::new();
        // Config and the lower layer are already here; the upper is not.
        storage.insert_content(config.clone(), config_bytes.to_vec());
        storage.insert_content(lower.clone(), lower_bytes.to_vec());
        let storage_mock = Arc::new(storage);
        let storage: Arc<dyn StoragePort> = storage_mock.clone();

        let mock_proxy = Arc::new(MockUpstreamProxy::new());
        seed_blob(&mock_proxy, &upper, upper_bytes);
        let proxy: Arc<dyn UpstreamProxy> = mock_proxy.clone();
        let artifact = manifest_artifact(Uuid::new_v4());

        let (outcome, stats) = run(
            &storage,
            &proxy,
            &proxy_resolver(artifact.repository_id),
            &artifact,
            ImageBudget::default_for_composite_scan(),
            &composition(&config, &[&lower, &upper]),
        )
        .await;

        assert_eq!(outcome, Acquisition::Complete);
        assert_eq!(
            stats,
            AcquisitionStats {
                already_present: 2,
                fetched: 1,
                fetched_bytes: upper_bytes.len() as u64,
            }
        );
        assert_eq!(
            mock_proxy.blob_fetches(),
            vec![format!("sha256:{upper}")],
            "only the absent constituent is fetched"
        );
        assert_eq!(
            storage_mock.put_call_count(),
            1,
            "a present constituent is not rewritten"
        );
    }

    /// **The cold pull-through case, and the order is the point.** Nothing
    /// is local — which is the ordinary state of a proxy manifest, since
    /// its constituent edges are registered by digest with no existence
    /// check — so the config is acquired first, and only then the layers,
    /// in manifest order.
    #[tokio::test]
    async fn a_cold_proxy_acquires_the_config_before_any_layer() {
        let config_bytes = oci_image_config_bytes(2);
        let config = sha256_of(&config_bytes);
        let (lower_bytes, upper_bytes) = (b"lower layer".as_slice(), b"upper layer".as_slice());
        let (lower, upper) = (sha256_of(lower_bytes), sha256_of(upper_bytes));

        // Only the manifest row's own bytes would be in CAS, and this
        // module never reads them: nothing at all is seeded here.
        let storage: Arc<dyn StoragePort> = Arc::new(MockStoragePort::new());
        let mock_proxy = Arc::new(MockUpstreamProxy::new());
        seed_blob(&mock_proxy, &config, &config_bytes);
        seed_blob(&mock_proxy, &lower, lower_bytes);
        seed_blob(&mock_proxy, &upper, upper_bytes);
        let proxy: Arc<dyn UpstreamProxy> = mock_proxy.clone();
        let artifact = manifest_artifact(Uuid::new_v4());

        let (outcome, stats) = run(
            &storage,
            &proxy,
            &proxy_resolver(artifact.repository_id),
            &artifact,
            ImageBudget::default_for_composite_scan(),
            &composition(&config, &[&lower, &upper]),
        )
        .await;

        assert_eq!(outcome, Acquisition::Complete);
        assert_eq!(
            stats,
            AcquisitionStats {
                already_present: 0,
                fetched: 3,
                fetched_bytes: (config_bytes.len() + lower_bytes.len() + upper_bytes.len()) as u64,
            },
            "the config is a constituent and is counted as one"
        );
        assert_eq!(
            mock_proxy.blob_fetches(),
            vec![
                format!("sha256:{config}"),
                format!("sha256:{lower}"),
                format!("sha256:{upper}"),
            ],
            "the config comes first, because its bytes decide whether the layers are \
             worth fetching at all"
        );
    }

    /// The durability claim, as a test: a first attempt that lands one of
    /// two absent layers and then fails leaves those bytes in CAS, and the
    /// second attempt fetches only what is still missing. Nothing restarts
    /// from zero, and no state outside CAS records the progress.
    #[tokio::test]
    async fn a_second_attempt_does_not_refetch_what_already_landed() {
        let (lower_bytes, upper_bytes) = (b"lower layer".as_slice(), b"upper layer".as_slice());
        let (lower, upper) = (sha256_of(lower_bytes), sha256_of(upper_bytes));
        let config_bytes = b"{config}".as_slice();
        let config = sha256_of(config_bytes);

        let storage = MockStoragePort::new();
        storage.insert_content(config.clone(), config_bytes.to_vec());
        let storage: Arc<dyn StoragePort> = Arc::new(storage);

        let mock_proxy = Arc::new(MockUpstreamProxy::new());
        seed_blob(&mock_proxy, &lower, lower_bytes);
        // The upper layer fails on the first attempt: the upstream is
        // there but not serving this blob yet.
        mock_proxy.fail_blob_with(
            &format!("sha256:{upper}"),
            DomainError::Invariant("upstream:upstream_5xx:503 from the registry".to_string()),
        );
        let proxy: Arc<dyn UpstreamProxy> = mock_proxy.clone();
        let artifact = manifest_artifact(Uuid::new_v4());
        let composition = composition(&config, &[&lower, &upper]);
        let resolver = proxy_resolver(artifact.repository_id);

        let (first, _) = run(
            &storage,
            &proxy,
            &resolver,
            &artifact,
            ImageBudget::default_for_composite_scan(),
            &composition,
        )
        .await;
        assert!(
            matches!(first, Acquisition::Transient(_)),
            "a 5xx is retryable: {first:?}"
        );
        assert!(
            storage.exists(&lower).await.expect("exists"),
            "the lower layer landed before the upper failed, and CAS is what keeps it"
        );

        // The upstream recovers, and the second attempt asks only about
        // the layer that is still absent.
        let upper_key = format!("sha256:{upper}");
        let before = mock_proxy.blob_fetches().len();
        mock_proxy.clear_blob_error(&upper_key);
        mock_proxy.insert_blob("", REPO_NAME, &upper_key, upper_bytes.to_vec(), None);
        let (second, stats) = run(
            &storage,
            &proxy,
            &resolver,
            &artifact,
            ImageBudget::default_for_composite_scan(),
            &composition,
        )
        .await;

        assert_eq!(second, Acquisition::Complete);
        assert_eq!(
            stats,
            AcquisitionStats {
                already_present: 2,
                fetched: 1,
                fetched_bytes: upper_bytes.len() as u64,
            }
        );
        assert_eq!(
            mock_proxy.blob_fetches()[before..],
            *std::slice::from_ref(&upper_key),
            "the second attempt fetches the still-absent layer and nothing else"
        );
    }

    /// A manifest may name the same layer digest twice. CAS addresses a
    /// blob by its digest, so it is one object: surveyed once, fetched
    /// once, charged once.
    #[tokio::test]
    async fn a_repeated_layer_digest_is_fetched_once() {
        let layer_bytes = b"shared empty layer".as_slice();
        let layer = sha256_of(layer_bytes);
        let config_bytes = b"{config}".as_slice();
        let config = sha256_of(config_bytes);

        let storage = MockStoragePort::new();
        storage.insert_content(config.clone(), config_bytes.to_vec());
        let storage: Arc<dyn StoragePort> = Arc::new(storage);
        let mock_proxy = Arc::new(MockUpstreamProxy::new());
        seed_blob(&mock_proxy, &layer, layer_bytes);
        let proxy: Arc<dyn UpstreamProxy> = mock_proxy.clone();
        let artifact = manifest_artifact(Uuid::new_v4());

        let (outcome, stats) = run(
            &storage,
            &proxy,
            &proxy_resolver(artifact.repository_id),
            &artifact,
            ImageBudget::default_for_composite_scan(),
            &composition(&config, &[&layer, &layer, &layer]),
        )
        .await;

        assert_eq!(outcome, Acquisition::Complete);
        assert_eq!(
            stats,
            AcquisitionStats {
                already_present: 1,
                fetched: 1,
                fetched_bytes: layer_bytes.len() as u64,
            }
        );
        assert_eq!(mock_proxy.blob_fetches().len(), 1);
    }

    /// The same dedup **across the phase seam**: a manifest whose config
    /// digest reappears as a layer digest names one CAS object, so it is
    /// surveyed, fetched and charged once — in phase 1 — and phase 2 does
    /// not ask about it again. A `seen` set that restarted per phase would
    /// charge those bytes twice against the whole-image budget and fetch
    /// them twice over the network.
    #[tokio::test]
    async fn a_config_digest_repeated_as_a_layer_is_acquired_once_across_the_phases() {
        let shared_bytes = b"the same object in both slots".as_slice();
        let shared = sha256_of(shared_bytes);

        let storage_mock = Arc::new(MockStoragePort::new());
        let storage: Arc<dyn StoragePort> = storage_mock.clone();
        let mock_proxy = Arc::new(MockUpstreamProxy::new());
        seed_blob(&mock_proxy, &shared, shared_bytes);
        let proxy: Arc<dyn UpstreamProxy> = mock_proxy.clone();
        let artifact = manifest_artifact(Uuid::new_v4());

        let (outcome, stats) = run(
            &storage,
            &proxy,
            &proxy_resolver(artifact.repository_id),
            &artifact,
            ImageBudget::default_for_composite_scan(),
            &composition(&shared, &[&shared]),
        )
        .await;

        assert_eq!(outcome, Acquisition::Complete);
        assert_eq!(
            stats,
            AcquisitionStats {
                already_present: 0,
                fetched: 1,
                fetched_bytes: shared_bytes.len() as u64,
            },
            "one object, charged once"
        );
        assert_eq!(mock_proxy.blob_fetches().len(), 1);
        assert_eq!(
            storage_mock.size_of_call_count(),
            1,
            "phase 2 does not re-probe what phase 1 already surveyed"
        );
    }

    // -- verification -----------------------------------------------------

    /// Bytes that do not hash to the declared digest are a deterministic
    /// refusal, and they are **not retried**: the per-constituent attempt
    /// bound is two, and the log shows exactly one fetch. ADR 0006 — a
    /// mismatch is a statement about the upstream's bytes that re-asking
    /// cannot change.
    #[tokio::test]
    async fn a_verification_failure_is_deterministic_and_never_retried() {
        let config_bytes = b"{config}".as_slice();
        let config = sha256_of(config_bytes);
        let declared = hash_of('1');

        let storage = MockStoragePort::new();
        storage.insert_content(config.clone(), config_bytes.to_vec());
        let storage: Arc<dyn StoragePort> = Arc::new(storage);
        let mock_proxy = Arc::new(MockUpstreamProxy::new());
        // Served under the declared digest, but the bytes hash to
        // something else entirely.
        seed_blob(&mock_proxy, &declared, b"not the declared content");
        let proxy: Arc<dyn UpstreamProxy> = mock_proxy.clone();
        let artifact = manifest_artifact(Uuid::new_v4());

        let (outcome, _) = run(
            &storage,
            &proxy,
            &proxy_resolver(artifact.repository_id),
            &artifact,
            ImageBudget::default_for_composite_scan(),
            &composition(&config, &[&declared]),
        )
        .await;

        let Acquisition::Deterministic(why) = outcome else {
            panic!("a digest mismatch is never retryable; got {outcome:?}");
        };
        assert!(why.contains("hashing to sha256:"), "{why}");
        assert!(why.contains("layers[0]"), "{why}");
        assert_eq!(
            mock_proxy.blob_fetches().len(),
            1,
            "a deterministic refusal is not retried, at either level"
        );
    }

    // -- the split --------------------------------------------------------

    /// Every upstream condition, on the side it was placed. Driven through
    /// the sentinel the production adapter encodes, so the table is
    /// exercised via the decoder rather than by calling it directly.
    #[tokio::test]
    async fn each_upstream_condition_reaches_its_own_side_of_the_split() {
        let deterministic = [
            "not_found",
            "unauthorized",
            "upstream_4xx",
            "parse_error",
            "checksum_mismatch",
            "pin_mismatch",
            "ca_unknown",
            "body_too_large",
            "metadata_too_large",
            "manifest_too_large",
            "version_object_too_large",
        ];
        let transient = ["rate_limited", "upstream_5xx", "network_error", "timeout"];

        for (kinds, expect_transient) in [
            (deterministic.as_slice(), false),
            (transient.as_slice(), true),
        ] {
            for kind in kinds {
                let config_bytes = b"{config}".as_slice();
                let config = sha256_of(config_bytes);
                let layer = hash_of('1');
                let storage = MockStoragePort::new();
                storage.insert_content(config.clone(), config_bytes.to_vec());
                let storage: Arc<dyn StoragePort> = Arc::new(storage);
                let mock_proxy = Arc::new(MockUpstreamProxy::new());
                mock_proxy.fail_blob_with(
                    &format!("sha256:{layer}"),
                    DomainError::Invariant(format!("upstream:{kind}:the upstream said so")),
                );
                let proxy: Arc<dyn UpstreamProxy> = mock_proxy.clone();
                let artifact = manifest_artifact(Uuid::new_v4());

                let (outcome, _) = run(
                    &storage,
                    &proxy,
                    &proxy_resolver(artifact.repository_id),
                    &artifact,
                    ImageBudget::default_for_composite_scan(),
                    &composition(&config, &[&layer]),
                )
                .await;

                match (&outcome, expect_transient) {
                    (Acquisition::Transient(_), true) | (Acquisition::Deterministic(_), false) => {}
                    _ => {
                        panic!("upstream:{kind} landed on the wrong side of the split: {outcome:?}")
                    }
                }
                // Only a transient classification spends the
                // per-constituent retry.
                assert_eq!(
                    mock_proxy.blob_fetches().len(),
                    if expect_transient {
                        MAX_ATTEMPTS_PER_CONSTITUENT as usize
                    } else {
                        1
                    },
                    "upstream:{kind} spent the wrong number of attempts"
                );
            }
        }
    }

    /// An error that classified itself as *success* is a contradiction:
    /// there is no fact to act on, which is the same position an
    /// unclassified error leaves us in and takes the same answer.
    #[tokio::test]
    async fn an_error_classified_as_success_is_treated_as_unclassified() {
        let config_bytes = b"{config}".as_slice();
        let config = sha256_of(config_bytes);
        let layer = hash_of('1');
        let storage = MockStoragePort::new();
        storage.insert_content(config.clone(), config_bytes.to_vec());
        let storage: Arc<dyn StoragePort> = Arc::new(storage);
        let mock_proxy = Arc::new(MockUpstreamProxy::new());
        mock_proxy.fail_blob_with(
            &format!("sha256:{layer}"),
            DomainError::Invariant("upstream:success:a contradiction".to_string()),
        );
        let proxy: Arc<dyn UpstreamProxy> = mock_proxy.clone();
        let artifact = manifest_artifact(Uuid::new_v4());

        let (outcome, _) = run(
            &storage,
            &proxy,
            &proxy_resolver(artifact.repository_id),
            &artifact,
            ImageBudget::default_for_composite_scan(),
            &composition(&config, &[&layer]),
        )
        .await;
        let Acquisition::Transient(why) = outcome else {
            panic!("a contradiction is not a statement about the image; got {outcome:?}");
        };
        assert!(why.contains("failed without saying how"), "{why}");
    }

    /// An error carrying no upstream classification did not come from the
    /// fetch's taxonomy, so there is nothing to read off it. Transient:
    /// bounded by the job's attempt budget, and far more likely to be an
    /// infrastructure condition than a statement about the image.
    #[tokio::test]
    async fn an_unclassified_upstream_error_is_transient() {
        let config_bytes = b"{config}".as_slice();
        let config = sha256_of(config_bytes);
        let layer = hash_of('1');
        let storage = MockStoragePort::new();
        storage.insert_content(config.clone(), config_bytes.to_vec());
        let storage: Arc<dyn StoragePort> = Arc::new(storage);
        let mock_proxy = Arc::new(MockUpstreamProxy::new());
        mock_proxy.fail_blob_with(
            &format!("sha256:{layer}"),
            DomainError::Validation("something else entirely".to_string()),
        );
        let proxy: Arc<dyn UpstreamProxy> = mock_proxy.clone();
        let artifact = manifest_artifact(Uuid::new_v4());

        let (outcome, _) = run(
            &storage,
            &proxy,
            &proxy_resolver(artifact.repository_id),
            &artifact,
            ImageBudget::default_for_composite_scan(),
            &composition(&config, &[&layer]),
        )
        .await;
        let Acquisition::Transient(why) = outcome else {
            panic!("an unnamed failure is treated as transient; got {outcome:?}");
        };
        assert!(why.contains("no upstream classification"), "{why}");
    }

    /// A storage probe that **failed** is not an absence: reading it as
    /// one would send the acquisition to an upstream for a blob that may
    /// well be local, and reading it as a deterministic refusal would
    /// report an unassessed image on the strength of a store hiccup.
    #[tokio::test]
    async fn a_failed_presence_probe_is_transient_not_an_absence() {
        let storage = MockStoragePort::new();
        let (config, layer) = (hash_of('c'), hash_of('1'));
        storage.insert_content(config.clone(), b"{config}".to_vec());
        storage.fail_size_of(layer.clone());
        let storage: Arc<dyn StoragePort> = Arc::new(storage);
        let mock_proxy = Arc::new(MockUpstreamProxy::new());
        let proxy: Arc<dyn UpstreamProxy> = mock_proxy.clone();
        let artifact = manifest_artifact(Uuid::new_v4());

        let (outcome, _) = run(
            &storage,
            &proxy,
            &proxy_resolver(artifact.repository_id),
            &artifact,
            ImageBudget::default_for_composite_scan(),
            &composition(&config, &[&layer]),
        )
        .await;
        let Acquisition::Transient(why) = outcome else {
            panic!("a failed probe is retryable; got {outcome:?}");
        };
        assert!(why.contains("whether layers[0]"), "{why}");
        assert!(
            mock_proxy.blob_fetches().is_empty(),
            "a probe that did not answer must not be read as an absence"
        );
    }

    /// CAS could not take the bytes: the store, not the image.
    #[tokio::test]
    async fn a_cas_write_failure_is_transient() {
        let config_bytes = b"{config}".as_slice();
        let config = sha256_of(config_bytes);
        let layer_bytes = b"lower layer".as_slice();
        let layer = sha256_of(layer_bytes);
        let storage = MockStoragePort::new();
        storage.insert_content(config.clone(), config_bytes.to_vec());
        // Persistent, so the per-constituent retry does not absorb it:
        // the question here is which side of the split a store that is
        // actually down lands on.
        storage.fail_put_persistent(DomainError::Invariant(
            "object store unavailable".to_string(),
        ));
        let storage: Arc<dyn StoragePort> = Arc::new(storage);
        let mock_proxy = Arc::new(MockUpstreamProxy::new());
        seed_blob(&mock_proxy, &layer, layer_bytes);
        let proxy: Arc<dyn UpstreamProxy> = mock_proxy.clone();
        let artifact = manifest_artifact(Uuid::new_v4());

        let (outcome, _) = run(
            &storage,
            &proxy,
            &proxy_resolver(artifact.repository_id),
            &artifact,
            ImageBudget::default_for_composite_scan(),
            &composition(&config, &[&layer]),
        )
        .await;
        let Acquisition::Transient(why) = outcome else {
            panic!("a CAS write failure is retryable; got {outcome:?}");
        };
        assert!(why.contains("could not be written to storage"), "{why}");
    }

    // -- the bounds -------------------------------------------------------

    /// The constituent bound is spent **once, on the whole nominated set**
    /// — config and layers together — and refuses before any I/O. Asserted
    /// on the probe count and the fetch log, because an over-count image
    /// must cost zero round-trips: a per-phase check would have spent a
    /// config fetch before refusing for a count the manifest bytes already
    /// stated.
    #[tokio::test]
    async fn the_constituent_bound_refuses_before_any_probe_or_fetch() {
        let config = hash_of('c');
        let layers: Vec<ContentHash> = (0..4).map(|i| hash_of((b'1' + i) as char)).collect();
        let storage_mock = Arc::new(MockStoragePort::new());
        let storage: Arc<dyn StoragePort> = storage_mock.clone();
        let mock_proxy = Arc::new(MockUpstreamProxy::new());
        let proxy: Arc<dyn UpstreamProxy> = mock_proxy.clone();
        let artifact = manifest_artifact(Uuid::new_v4());
        let refs: Vec<&ContentHash> = layers.iter().collect();

        let (outcome, stats) = run(
            &storage,
            &proxy,
            &proxy_resolver(artifact.repository_id),
            &artifact,
            ImageBudget {
                max_blobs: 3,
                ..ImageBudget::default_for_composite_scan()
            },
            &composition(&config, &refs),
        )
        .await;

        let Acquisition::Deterministic(why) = outcome else {
            panic!("an over-count image is refused; got {outcome:?}");
        };
        assert!(
            why.contains("declares 6 constituents"),
            "the manifest, the config and four layers: {why}"
        );
        assert!(why.contains("allows 3"), "{why}");
        assert_eq!(storage_mock.size_of_call_count(), 0);
        assert!(mock_proxy.blob_fetches().is_empty());
        assert_eq!(stats, AcquisitionStats::default());
    }

    /// The byte budget is charged across **every** constituent, not only
    /// the fetched ones — so an image whose local bytes already exceed it
    /// is refused with nothing fetched. Charging only the fetches would
    /// pull bytes the layout writer is then guaranteed to refuse.
    #[tokio::test]
    async fn the_byte_budget_counts_what_is_already_local_and_fetches_nothing() {
        let config_bytes = vec![b'c'; 64];
        let config = sha256_of(&config_bytes);
        let layer = hash_of('1');
        let storage = MockStoragePort::new();
        storage.insert_content(config.clone(), config_bytes);
        let storage: Arc<dyn StoragePort> = Arc::new(storage);
        let mock_proxy = Arc::new(MockUpstreamProxy::new());
        let proxy: Arc<dyn UpstreamProxy> = mock_proxy.clone();
        let artifact = manifest_artifact(Uuid::new_v4());

        let (outcome, _) = run(
            &storage,
            &proxy,
            &proxy_resolver(artifact.repository_id),
            &artifact,
            ImageBudget {
                max_bytes: 16,
                ..ImageBudget::default_for_composite_scan()
            },
            &composition(&config, &[&layer]),
        )
        .await;

        let Acquisition::Deterministic(why) = outcome else {
            panic!("an over-budget composition is refused; got {outcome:?}");
        };
        assert!(why.contains("already in storage exceed"), "{why}");
        assert!(why.contains("config"), "the refusal names the slot: {why}");
        assert!(mock_proxy.blob_fetches().is_empty());
    }

    /// A config that alone exceeds the whole-image byte budget ends the
    /// acquisition in phase 1, deterministically — and no layer is fetched
    /// for an image whose description already does not fit.
    #[tokio::test]
    async fn a_fetched_config_that_alone_exceeds_the_byte_budget_is_deterministic() {
        let config_bytes = vec![b'c'; 64];
        let config = sha256_of(&config_bytes);
        let layer_bytes = b"lower layer".as_slice();
        let layer = sha256_of(layer_bytes);
        let storage: Arc<dyn StoragePort> = Arc::new(MockStoragePort::new());
        let mock_proxy = Arc::new(MockUpstreamProxy::new());
        seed_blob(&mock_proxy, &config, &config_bytes);
        seed_blob(&mock_proxy, &layer, layer_bytes);
        let proxy: Arc<dyn UpstreamProxy> = mock_proxy.clone();
        let artifact = manifest_artifact(Uuid::new_v4());

        let (outcome, _) = run(
            &storage,
            &proxy,
            &proxy_resolver(artifact.repository_id),
            &artifact,
            ImageBudget {
                max_bytes: 16,
                ..ImageBudget::default_for_composite_scan()
            },
            &composition(&config, &[&layer]),
        )
        .await;

        let Acquisition::Deterministic(why) = outcome else {
            panic!("an over-budget config is refused; got {outcome:?}");
        };
        assert!(
            why.contains("exceeded the whole-image byte budget"),
            "{why}"
        );
        assert!(why.contains("config"), "{why}");
        assert_eq!(
            mock_proxy.blob_fetches(),
            vec![format!("sha256:{config}")],
            "the layer is never asked for"
        );
    }

    /// A fetched blob that does not fit the remaining budget is refused,
    /// and the refusal says so — rather than arriving as a truncated body
    /// whose digest happens not to match.
    #[tokio::test]
    async fn a_fetched_constituent_over_the_remaining_budget_is_refused_as_over_budget() {
        let config_bytes = b"cc".as_slice();
        let config = sha256_of(config_bytes);
        let layer_bytes = vec![b'L'; 64];
        let layer = sha256_of(&layer_bytes);
        let storage = MockStoragePort::new();
        storage.insert_content(config.clone(), config_bytes.to_vec());
        let storage: Arc<dyn StoragePort> = Arc::new(storage);
        let mock_proxy = Arc::new(MockUpstreamProxy::new());
        seed_blob(&mock_proxy, &layer, &layer_bytes);
        let proxy: Arc<dyn UpstreamProxy> = mock_proxy.clone();
        let artifact = manifest_artifact(Uuid::new_v4());

        let (outcome, _) = run(
            &storage,
            &proxy,
            &proxy_resolver(artifact.repository_id),
            &artifact,
            ImageBudget {
                max_bytes: 10,
                ..ImageBudget::default_for_composite_scan()
            },
            &composition(&config, &[&layer]),
        )
        .await;

        let Acquisition::Deterministic(why) = outcome else {
            panic!("an over-budget fetch is refused; got {outcome:?}");
        };
        assert!(
            why.contains("exceeded the whole-image byte budget"),
            "an over-budget fetch must not be reported as a digest mismatch: {why}"
        );
        assert_eq!(mock_proxy.blob_fetches().len(), 1, "and it is not retried");
    }

    /// The off-by-one, **across the phase seam**: the config's bytes are
    /// charged in phase 1 and the layer is then measured against what is
    /// left, so a layer that fits the remainder **exactly** lands. The read
    /// takes one byte more than the budget so that "at the ceiling" and
    /// "over it" are distinguishable; this pins which side the boundary is
    /// on, and that the charge crossed the seam at all.
    #[tokio::test]
    async fn a_constituent_exactly_at_the_remaining_budget_lands() {
        let config_bytes = b"cc".as_slice();
        let config = sha256_of(config_bytes);
        let layer_bytes = vec![b'L'; 8];
        let layer = sha256_of(&layer_bytes);
        let storage = MockStoragePort::new();
        storage.insert_content(config.clone(), config_bytes.to_vec());
        let storage: Arc<dyn StoragePort> = Arc::new(storage);
        let mock_proxy = Arc::new(MockUpstreamProxy::new());
        seed_blob(&mock_proxy, &layer, &layer_bytes);
        let proxy: Arc<dyn UpstreamProxy> = mock_proxy.clone();
        let artifact = manifest_artifact(Uuid::new_v4());

        let (outcome, stats) = run(
            &storage,
            &proxy,
            &proxy_resolver(artifact.repository_id),
            &artifact,
            // 2 bytes of config, charged in phase 1, plus exactly 8 bytes
            // of layer in phase 2.
            ImageBudget {
                max_bytes: 10,
                ..ImageBudget::default_for_composite_scan()
            },
            &composition(&config, &[&layer]),
        )
        .await;

        assert_eq!(outcome, Acquisition::Complete);
        assert_eq!(
            stats,
            AcquisitionStats {
                already_present: 1,
                fetched: 1,
                fetched_bytes: 8,
            }
        );
    }

    /// The whole-acquisition wall clock. A stalled upstream is an
    /// availability condition, so the refusal is transient — a wall-clock
    /// trip is not a statement about the image.
    #[tokio::test]
    async fn the_wall_clock_budget_refuses_as_transient() {
        let storage = MockStoragePort::new();
        let (config, layer) = (hash_of('c'), hash_of('1'));
        storage.insert_content(config.clone(), b"{config}".to_vec());
        let storage: Arc<dyn StoragePort> = Arc::new(storage);
        // Nothing seeded on the inner proxy: the sleep outlives the budget,
        // so what it would have answered never matters.
        let proxy: Arc<dyn UpstreamProxy> = Arc::new(SlowProxy {
            inner: Arc::new(MockUpstreamProxy::new()),
            delay: Duration::from_secs(30),
        });
        let artifact = manifest_artifact(Uuid::new_v4());

        let (outcome, _) = run(
            &storage,
            &proxy,
            &proxy_resolver(artifact.repository_id),
            &artifact,
            ImageBudget {
                max_duration: Duration::from_millis(20),
                ..ImageBudget::default_for_composite_scan()
            },
            &composition(&config, &[&layer]),
        )
        .await;

        let Acquisition::Transient(why) = outcome else {
            panic!("a stalled upstream is retryable; got {outcome:?}");
        };
        assert!(why.contains("wall-clock budget"), "{why}");
    }

    /// **One clock for both phases.** Two fetches that each fit the budget
    /// comfortably do not fit it together, and the second phase is the one
    /// that trips — which is the whole claim: a composition acquired in two
    /// steps is not a composition hort will wait twice as long for, because
    /// what the bound protects is the worker slot.
    ///
    /// Virtual time, so the two deadlines are exact rather than racing the
    /// test host.
    #[tokio::test(start_paused = true)]
    async fn the_wall_clock_bounds_the_two_phases_together() {
        let config_bytes = oci_image_config_bytes(1);
        let config = sha256_of(&config_bytes);
        let layer_bytes = b"lower layer".as_slice();
        let layer = sha256_of(layer_bytes);

        let inner = Arc::new(MockUpstreamProxy::new());
        seed_blob(&inner, &config, &config_bytes);
        seed_blob(&inner, &layer, layer_bytes);
        let proxy: Arc<dyn UpstreamProxy> = Arc::new(SlowProxy {
            inner: inner.clone(),
            delay: Duration::from_millis(60),
        });
        let artifact = manifest_artifact(Uuid::new_v4());
        let resolver = proxy_resolver(artifact.repository_id);
        let composition = composition(&config, &[&layer]);

        // 60 ms + 60 ms against a 100 ms budget: phase 1 lands, phase 2
        // runs out of clock.
        let storage: Arc<dyn StoragePort> = Arc::new(MockStoragePort::new());
        let (outcome, stats) = run(
            &storage,
            &proxy,
            &resolver,
            &artifact,
            ImageBudget {
                max_duration: Duration::from_millis(100),
                ..ImageBudget::default_for_composite_scan()
            },
            &composition,
        )
        .await;
        let Acquisition::Transient(why) = outcome else {
            panic!("running out of clock is an availability condition; got {outcome:?}");
        };
        assert!(why.contains("wall-clock budget"), "{why}");
        assert_eq!(
            stats.fetched, 1,
            "phase 1 completed well inside the budget — it is the *sum* that did not fit"
        );
        assert_eq!(
            inner.blob_fetches(),
            vec![format!("sha256:{config}"), format!("sha256:{layer}")],
            "the layer fetch was started and then cut off by the shared deadline"
        );

        // The same two fetches, the same delays, a budget that covers both.
        let storage: Arc<dyn StoragePort> = Arc::new(MockStoragePort::new());
        let (outcome, stats) = run(
            &storage,
            &proxy,
            &resolver,
            &artifact,
            ImageBudget {
                max_duration: Duration::from_millis(200),
                ..ImageBudget::default_for_composite_scan()
            },
            &composition,
        )
        .await;
        assert_eq!(outcome, Acquisition::Complete);
        assert_eq!(stats.fetched, 2);
    }

    /// The per-constituent attempt bound, stated as a number rather than
    /// inferred: a persistently-transient constituent is asked exactly
    /// twice and no more, so a flapping upstream cannot spend the whole
    /// acquisition on one layer.
    #[tokio::test]
    async fn the_per_constituent_attempt_bound_is_two_and_is_spent_once() {
        assert_eq!(MAX_ATTEMPTS_PER_CONSTITUENT, 2);

        let config_bytes = b"{config}".as_slice();
        let config = sha256_of(config_bytes);
        let (first, second) = (hash_of('1'), hash_of('2'));
        let storage = MockStoragePort::new();
        storage.insert_content(config.clone(), config_bytes.to_vec());
        let storage: Arc<dyn StoragePort> = Arc::new(storage);
        let mock_proxy = Arc::new(MockUpstreamProxy::new());
        for hash in [&first, &second] {
            mock_proxy.fail_blob_with(
                &format!("sha256:{hash}"),
                DomainError::Invariant("upstream:network_error:connection reset".to_string()),
            );
        }
        let proxy: Arc<dyn UpstreamProxy> = mock_proxy.clone();
        let artifact = manifest_artifact(Uuid::new_v4());

        let (outcome, _) = run(
            &storage,
            &proxy,
            &proxy_resolver(artifact.repository_id),
            &artifact,
            ImageBudget::default_for_composite_scan(),
            &composition(&config, &[&first, &second]),
        )
        .await;

        let Acquisition::Transient(why) = outcome else {
            panic!("expected a transient refusal, got {outcome:?}");
        };
        assert!(why.contains("in 2 attempts"), "{why}");
        assert_eq!(
            mock_proxy.blob_fetches(),
            vec![format!("sha256:{first}"), format!("sha256:{first}")],
            "the first failure ends the acquisition: the second layer is never asked for, \
             because a composition missing one constituent is not a smaller image"
        );
    }

    /// **The config is a constituent on the retry axis too.** A transient
    /// failure acquiring it asks for another attempt and spends the same
    /// per-constituent bound as one acquiring a layer — the two slots
    /// differ in *when* they are acquired and in nothing else. Asserted as
    /// a pair, because "the config behaves like a layer here" is only
    /// visible against the layer.
    #[tokio::test]
    async fn a_transient_failure_acquiring_the_config_spends_the_same_bound_as_a_layer() {
        let config_bytes = oci_image_config_bytes(1);
        let config = sha256_of(&config_bytes);
        let layer_bytes = b"lower layer".as_slice();
        let layer = sha256_of(layer_bytes);

        for (failing_slot, failing_hash, expected_log) in [
            (
                "config",
                &config,
                vec![format!("sha256:{config}"), format!("sha256:{config}")],
            ),
            (
                "layers[0]",
                &layer,
                vec![
                    format!("sha256:{config}"),
                    format!("sha256:{layer}"),
                    format!("sha256:{layer}"),
                ],
            ),
        ] {
            let storage: Arc<dyn StoragePort> = Arc::new(MockStoragePort::new());
            let mock_proxy = Arc::new(MockUpstreamProxy::new());
            seed_blob(&mock_proxy, &config, &config_bytes);
            seed_blob(&mock_proxy, &layer, layer_bytes);
            mock_proxy.fail_blob_with(
                &format!("sha256:{failing_hash}"),
                DomainError::Invariant("upstream:network_error:connection reset".to_string()),
            );
            let proxy: Arc<dyn UpstreamProxy> = mock_proxy.clone();
            let artifact = manifest_artifact(Uuid::new_v4());

            let (outcome, _) = run(
                &storage,
                &proxy,
                &proxy_resolver(artifact.repository_id),
                &artifact,
                ImageBudget::default_for_composite_scan(),
                &composition(&config, &[&layer]),
            )
            .await;

            let Acquisition::Transient(why) = outcome else {
                panic!("{failing_slot}: a reset connection is retryable; got {outcome:?}");
            };
            assert!(why.contains("in 2 attempts"), "{failing_slot}: {why}");
            assert!(why.contains(failing_slot), "{failing_slot}: {why}");
            assert_eq!(
                mock_proxy.blob_fetches(),
                expected_log,
                "{failing_slot}: the same bound, spent on whichever slot failed"
            );
        }
    }

    /// A transient first attempt that succeeds on the retry: the inner
    /// bound exists for exactly this, and the acquisition completes
    /// without the job having to wait out a backoff.
    #[tokio::test]
    async fn a_constituent_that_succeeds_on_the_retry_completes_the_acquisition() {
        let config_bytes = b"{config}".as_slice();
        let config = sha256_of(config_bytes);
        let layer_bytes = b"lower layer".as_slice();
        let layer = sha256_of(layer_bytes);
        let storage = MockStoragePort::new();
        storage.insert_content(config.clone(), config_bytes.to_vec());
        let storage: Arc<dyn StoragePort> = Arc::new(storage);
        let mock_proxy = Arc::new(MockUpstreamProxy::new());
        seed_blob(&mock_proxy, &layer, layer_bytes);
        // One-shot: the first attempt fails, the second is served.
        mock_proxy.fail_next_blob_with(DomainError::Invariant(
            "upstream:network_error:connection reset by peer".to_string(),
        ));
        let proxy: Arc<dyn UpstreamProxy> = mock_proxy.clone();
        let artifact = manifest_artifact(Uuid::new_v4());

        let (outcome, stats) = run(
            &storage,
            &proxy,
            &proxy_resolver(artifact.repository_id),
            &artifact,
            ImageBudget::default_for_composite_scan(),
            &composition(&config, &[&layer]),
        )
        .await;

        assert_eq!(outcome, Acquisition::Complete);
        assert_eq!(
            stats,
            AcquisitionStats {
                already_present: 1,
                fetched: 1,
                fetched_bytes: layer_bytes.len() as u64,
            }
        );
        assert_eq!(mock_proxy.blob_fetches().len(), 2);
    }

    /// The upstream is reachable and simply does not have the digest —
    /// which for a content-addressed blob is final. Deterministic, named
    /// as such, and not retried.
    #[tokio::test]
    async fn a_constituent_the_upstream_does_not_have_is_deterministic() {
        let config_bytes = b"{config}".as_slice();
        let config = sha256_of(config_bytes);
        let layer = hash_of('1');
        let storage = MockStoragePort::new();
        storage.insert_content(config.clone(), config_bytes.to_vec());
        let storage: Arc<dyn StoragePort> = Arc::new(storage);
        // An unseeded key returns the mock's default
        // `upstream:not_found:…`, the same sentinel the production adapter
        // emits for a 404.
        let mock_proxy = Arc::new(MockUpstreamProxy::new());
        let proxy: Arc<dyn UpstreamProxy> = mock_proxy.clone();
        let artifact = manifest_artifact(Uuid::new_v4());

        let (outcome, _) = run(
            &storage,
            &proxy,
            &proxy_resolver(artifact.repository_id),
            &artifact,
            ImageBudget::default_for_composite_scan(),
            &composition(&config, &[&layer]),
        )
        .await;

        let Acquisition::Deterministic(why) = outcome else {
            panic!("an absent upstream blob is final; got {outcome:?}");
        };
        assert!(why.contains("does not have layers[0]"), "{why}");
        assert_eq!(mock_proxy.blob_fetches().len(), 1);
    }
}
