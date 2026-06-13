//! Shared policy-evaluation primitives.

use crate::entities::scan_policy::SeverityThreshold;
use crate::events::PolicyViolation;

/// Three-state action enum used by per-decision-point evaluators.
///
/// `Allow → Warn → Block` is monotonic — neither
/// [`escalate_action_by_severity`] nor [`escalate_action_by_policy`] may
/// downgrade. Once a violation pushes the running outcome to `Block`,
/// nothing later in the evaluation can return it to `Warn` or `Allow`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PolicyAction {
    Allow,
    Warn,
    Block,
}

/// Escalate `current` based on a violation's severity.
///
/// `critical` and `high` always escalate to [`PolicyAction::Block`].
/// `medium`, `low` escalate to [`PolicyAction::Warn`] unless `current`
/// is already `Block`.
pub fn escalate_action_by_severity(
    current: PolicyAction,
    severity: SeverityThreshold,
) -> PolicyAction {
    match severity {
        SeverityThreshold::Critical | SeverityThreshold::High => PolicyAction::Block,
        SeverityThreshold::Medium | SeverityThreshold::Low => match current {
            PolicyAction::Block => PolicyAction::Block,
            _ => PolicyAction::Warn,
        },
    }
}

/// Escalate `current` based on a policy's own configured action.
///
/// `Block` always wins. `Warn` upgrades `Allow` but does not downgrade
/// `Block`. `Allow` is a no-op.
pub fn escalate_action_by_policy(
    current: PolicyAction,
    policy_action: PolicyAction,
) -> PolicyAction {
    match policy_action {
        PolicyAction::Block => PolicyAction::Block,
        PolicyAction::Warn => match current {
            PolicyAction::Block => PolicyAction::Block,
            _ => PolicyAction::Warn,
        },
        PolicyAction::Allow => current,
    }
}

/// Aggregator used by all evaluators to collect violations and escalate
/// the running action through them.
///
/// Construct via [`ViolationsAccumulator::new`] (starts at `Allow` with no
/// violations); feed batches of violations via
/// [`Self::collect_with_severity_escalation`] or
/// [`Self::collect_with_policy_action`]; consume via [`Self::into_outcome`]
/// to obtain the final `(PolicyAction, Vec<PolicyViolation>)` pair that
/// per-decision-point entry points translate into outcome enums.
#[derive(Debug, Clone, PartialEq)]
pub struct ViolationsAccumulator {
    violations: Vec<PolicyViolation>,
    action: PolicyAction,
}

impl Default for ViolationsAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl ViolationsAccumulator {
    /// Construct an empty accumulator. Starts at [`PolicyAction::Allow`]
    /// with no violations.
    pub fn new() -> Self {
        Self {
            violations: Vec::new(),
            action: PolicyAction::Allow,
        }
    }

    /// Append `new` and escalate the running action via
    /// [`escalate_action_by_severity`] for each violation.
    pub fn collect_with_severity_escalation(&mut self, new: Vec<PolicyViolation>) {
        for v in new {
            self.action = escalate_action_by_severity(self.action, v.severity);
            self.violations.push(v);
        }
    }

    /// Append `new` and escalate the running action once via
    /// [`escalate_action_by_policy`] using the policy's own `action`.
    /// The escalation fires once for the whole batch — the policy's
    /// configured action is independent of how many violations it
    /// produced.
    pub fn collect_with_policy_action(&mut self, new: Vec<PolicyViolation>, action: PolicyAction) {
        if !new.is_empty() {
            self.action = escalate_action_by_policy(self.action, action);
            self.violations.extend(new);
        }
    }

    /// Consume the accumulator and return the final
    /// `(PolicyAction, Vec<PolicyViolation>)` pair.
    pub fn into_outcome(self) -> (PolicyAction, Vec<PolicyViolation>) {
        (self.action, self.violations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::scan_policy::SeverityThreshold;
    use crate::events::PolicyViolation;

    fn violation(severity: SeverityThreshold) -> PolicyViolation {
        PolicyViolation {
            rule: "test-rule".into(),
            severity,
            message: "test".into(),
            details: serde_json::Value::Null,
        }
    }

    // ---- escalate_action_by_severity ----

    #[test]
    fn severity_critical_from_allow_blocks() {
        assert_eq!(
            escalate_action_by_severity(PolicyAction::Allow, SeverityThreshold::Critical),
            PolicyAction::Block
        );
    }

    #[test]
    fn severity_critical_from_warn_blocks() {
        assert_eq!(
            escalate_action_by_severity(PolicyAction::Warn, SeverityThreshold::Critical),
            PolicyAction::Block
        );
    }

    #[test]
    fn severity_critical_from_block_stays_block() {
        assert_eq!(
            escalate_action_by_severity(PolicyAction::Block, SeverityThreshold::Critical),
            PolicyAction::Block
        );
    }

    #[test]
    fn severity_high_from_allow_blocks() {
        assert_eq!(
            escalate_action_by_severity(PolicyAction::Allow, SeverityThreshold::High),
            PolicyAction::Block
        );
    }

    #[test]
    fn severity_high_from_warn_blocks() {
        assert_eq!(
            escalate_action_by_severity(PolicyAction::Warn, SeverityThreshold::High),
            PolicyAction::Block
        );
    }

    #[test]
    fn severity_high_from_block_stays_block() {
        assert_eq!(
            escalate_action_by_severity(PolicyAction::Block, SeverityThreshold::High),
            PolicyAction::Block
        );
    }

    #[test]
    fn severity_medium_from_allow_warns() {
        assert_eq!(
            escalate_action_by_severity(PolicyAction::Allow, SeverityThreshold::Medium),
            PolicyAction::Warn
        );
    }

    #[test]
    fn severity_medium_from_warn_stays_warn() {
        assert_eq!(
            escalate_action_by_severity(PolicyAction::Warn, SeverityThreshold::Medium),
            PolicyAction::Warn
        );
    }

    #[test]
    fn severity_medium_from_block_stays_block_monotonic() {
        assert_eq!(
            escalate_action_by_severity(PolicyAction::Block, SeverityThreshold::Medium),
            PolicyAction::Block
        );
    }

    #[test]
    fn severity_low_from_allow_warns() {
        assert_eq!(
            escalate_action_by_severity(PolicyAction::Allow, SeverityThreshold::Low),
            PolicyAction::Warn
        );
    }

    #[test]
    fn severity_low_from_warn_stays_warn() {
        assert_eq!(
            escalate_action_by_severity(PolicyAction::Warn, SeverityThreshold::Low),
            PolicyAction::Warn
        );
    }

    #[test]
    fn severity_low_from_block_stays_block_monotonic() {
        assert_eq!(
            escalate_action_by_severity(PolicyAction::Block, SeverityThreshold::Low),
            PolicyAction::Block
        );
    }

    // ---- escalate_action_by_policy ----

    #[test]
    fn policy_block_overrides_allow() {
        assert_eq!(
            escalate_action_by_policy(PolicyAction::Allow, PolicyAction::Block),
            PolicyAction::Block
        );
    }

    #[test]
    fn policy_block_overrides_warn() {
        assert_eq!(
            escalate_action_by_policy(PolicyAction::Warn, PolicyAction::Block),
            PolicyAction::Block
        );
    }

    #[test]
    fn policy_block_keeps_block() {
        assert_eq!(
            escalate_action_by_policy(PolicyAction::Block, PolicyAction::Block),
            PolicyAction::Block
        );
    }

    #[test]
    fn policy_warn_upgrades_allow() {
        assert_eq!(
            escalate_action_by_policy(PolicyAction::Allow, PolicyAction::Warn),
            PolicyAction::Warn
        );
    }

    #[test]
    fn policy_warn_keeps_warn() {
        assert_eq!(
            escalate_action_by_policy(PolicyAction::Warn, PolicyAction::Warn),
            PolicyAction::Warn
        );
    }

    #[test]
    fn policy_warn_does_not_downgrade_block() {
        assert_eq!(
            escalate_action_by_policy(PolicyAction::Block, PolicyAction::Warn),
            PolicyAction::Block
        );
    }

    #[test]
    fn policy_allow_keeps_allow() {
        assert_eq!(
            escalate_action_by_policy(PolicyAction::Allow, PolicyAction::Allow),
            PolicyAction::Allow
        );
    }

    #[test]
    fn policy_allow_does_not_downgrade_warn() {
        assert_eq!(
            escalate_action_by_policy(PolicyAction::Warn, PolicyAction::Allow),
            PolicyAction::Warn
        );
    }

    #[test]
    fn policy_allow_does_not_downgrade_block() {
        assert_eq!(
            escalate_action_by_policy(PolicyAction::Block, PolicyAction::Allow),
            PolicyAction::Block
        );
    }

    // ---- ViolationsAccumulator ----

    #[test]
    fn new_starts_at_allow_no_violations() {
        let acc = ViolationsAccumulator::new();
        let (action, violations) = acc.into_outcome();
        assert_eq!(action, PolicyAction::Allow);
        assert!(violations.is_empty());
    }

    #[test]
    fn default_matches_new() {
        let lhs = ViolationsAccumulator::default();
        let rhs = ViolationsAccumulator::new();
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn severity_escalation_empty_batch_keeps_allow() {
        let mut acc = ViolationsAccumulator::new();
        acc.collect_with_severity_escalation(vec![]);
        let (action, violations) = acc.into_outcome();
        assert_eq!(action, PolicyAction::Allow);
        assert!(violations.is_empty());
    }

    #[test]
    fn severity_escalation_single_critical_blocks() {
        let mut acc = ViolationsAccumulator::new();
        acc.collect_with_severity_escalation(vec![violation(SeverityThreshold::Critical)]);
        let (action, violations) = acc.into_outcome();
        assert_eq!(action, PolicyAction::Block);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn severity_escalation_single_medium_warns() {
        let mut acc = ViolationsAccumulator::new();
        acc.collect_with_severity_escalation(vec![violation(SeverityThreshold::Medium)]);
        let (action, violations) = acc.into_outcome();
        assert_eq!(action, PolicyAction::Warn);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn severity_escalation_multi_keeps_block_after_critical() {
        // Critical first → Block; then Medium must NOT downgrade to Warn.
        let mut acc = ViolationsAccumulator::new();
        acc.collect_with_severity_escalation(vec![
            violation(SeverityThreshold::Critical),
            violation(SeverityThreshold::Medium),
        ]);
        let (action, violations) = acc.into_outcome();
        assert_eq!(action, PolicyAction::Block);
        assert_eq!(violations.len(), 2);
    }

    #[test]
    fn severity_escalation_warn_then_critical_blocks() {
        let mut acc = ViolationsAccumulator::new();
        acc.collect_with_severity_escalation(vec![
            violation(SeverityThreshold::Low),
            violation(SeverityThreshold::Critical),
        ]);
        let (action, _) = acc.into_outcome();
        assert_eq!(action, PolicyAction::Block);
    }

    #[test]
    fn policy_action_empty_batch_does_not_escalate() {
        // No violations → policy action should not fire (a policy that
        // produced no violations had nothing to flag, so its configured
        // action is irrelevant).
        let mut acc = ViolationsAccumulator::new();
        acc.collect_with_policy_action(vec![], PolicyAction::Block);
        let (action, violations) = acc.into_outcome();
        assert_eq!(action, PolicyAction::Allow);
        assert!(violations.is_empty());
    }

    #[test]
    fn policy_action_block_with_violations_blocks() {
        let mut acc = ViolationsAccumulator::new();
        acc.collect_with_policy_action(
            vec![violation(SeverityThreshold::Low)],
            PolicyAction::Block,
        );
        let (action, violations) = acc.into_outcome();
        assert_eq!(action, PolicyAction::Block);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn policy_action_warn_with_violations_warns() {
        let mut acc = ViolationsAccumulator::new();
        acc.collect_with_policy_action(vec![violation(SeverityThreshold::Low)], PolicyAction::Warn);
        let (action, _) = acc.into_outcome();
        assert_eq!(action, PolicyAction::Warn);
    }

    #[test]
    fn policy_action_allow_with_violations_keeps_allow() {
        // A policy whose action is Allow appends violations for audit but
        // does not escalate the running action — the operator declared
        // "log these but don't block."
        let mut acc = ViolationsAccumulator::new();
        acc.collect_with_policy_action(
            vec![violation(SeverityThreshold::High)],
            PolicyAction::Allow,
        );
        let (action, violations) = acc.into_outcome();
        assert_eq!(action, PolicyAction::Allow);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn policy_action_warn_does_not_downgrade_block() {
        let mut acc = ViolationsAccumulator::new();
        acc.collect_with_policy_action(
            vec![violation(SeverityThreshold::Low)],
            PolicyAction::Block,
        );
        acc.collect_with_policy_action(vec![violation(SeverityThreshold::Low)], PolicyAction::Warn);
        let (action, _) = acc.into_outcome();
        assert_eq!(action, PolicyAction::Block);
    }

    // ---- mixed scenario: severity then policy ----

    #[test]
    fn mixed_severity_and_policy_collection() {
        let mut acc = ViolationsAccumulator::new();
        acc.collect_with_severity_escalation(vec![violation(SeverityThreshold::Medium)]);
        acc.collect_with_policy_action(
            vec![violation(SeverityThreshold::Low)],
            PolicyAction::Block,
        );
        let (action, violations) = acc.into_outcome();
        assert_eq!(action, PolicyAction::Block);
        assert_eq!(violations.len(), 2);
    }

    // ---- PolicyAction trait derives ----

    #[test]
    fn policy_action_clone_copy_eq() {
        let a = PolicyAction::Allow;
        let b = a; // Copy
        #[allow(clippy::clone_on_copy)]
        let c = a.clone();
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(PolicyAction::Allow, PolicyAction::Warn);
        assert_ne!(PolicyAction::Warn, PolicyAction::Block);
    }

    #[test]
    fn policy_action_serde_round_trip() {
        for variant in [PolicyAction::Allow, PolicyAction::Warn, PolicyAction::Block] {
            let json = serde_json::to_string(&variant).unwrap();
            let parsed: PolicyAction = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, variant);
        }
    }
}
