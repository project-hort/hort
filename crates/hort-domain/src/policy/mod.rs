//! Policy-evaluation primitives shared across decision points.
//!
//! `primitives` and `threshold` provide the shared aggregator
//! and severity-threshold mapping; the per-rule
//! sub-evaluators are `cve`, `license`, `age`, plus the `exclusion`
//! filter. (An inert `signature` sub-evaluator was retired —
//! the `requireSignature` bool it gated was never read by any
//! release gate. Provenance verification lives behind the
//! `provenance_mode` trio + `ProvenancePort`; see ADR 0027.)
//! The decision-point entry points composing them are `scan`,
//! `re_evaluation` (the post-exclusion-add pass), `curation`,
//! and `promotion`.
//!
//! The reshaped event payload [`crate::events::PolicyViolation`] —
//! `{ rule, severity, message, details }` — is the shared violation
//! record produced by every evaluator and consumed by the
//! [`ViolationsAccumulator`].

pub mod age;
pub mod curation;
pub mod cve;
pub mod event_chain_verify_liveness;
pub mod exclusion;
pub mod license;
pub mod primitives;
pub mod promotion;
pub mod re_evaluation;
pub mod scan;
pub mod scan_delta;
pub mod staging_sweep_liveness;
pub mod threshold;

pub use age::evaluate_age_gates;
pub use curation::{
    evaluate_curation, evaluate_curation_retroactive, CurationOutcome, RetroactiveCurationOutcome,
};
pub use cve::evaluate_cve_thresholds;
pub use event_chain_verify_liveness::{
    evaluate_event_chain_verify_liveness, EventChainVerifyLiveness,
};
pub use exclusion::{
    filter_excluded_findings, filter_excluded_summary, FilteredFindings, FilteredSummary,
};
pub use license::evaluate_license_policy;
pub use primitives::{
    escalate_action_by_policy, escalate_action_by_severity, PolicyAction, ViolationsAccumulator,
};
pub use promotion::{evaluate_promotion, PromotionOutcome};
pub use re_evaluation::{re_evaluate_after_exclusion, ReEvaluationOutcome};
pub use scan::{effective_quarantine_deadline, evaluate_scan_result, DefaultPolicy, ScanOutcome};
pub use scan_delta::compute_added_findings;
pub use staging_sweep_liveness::{evaluate_staging_sweep_liveness, StagingSweepLiveness};
pub use threshold::{count_findings_above_threshold, finding_exceeds_threshold};
