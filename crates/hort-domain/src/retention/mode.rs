//! Invocation mode for the retention evaluator.
//!
//! The mode is a domain value because the HTTP adapter, application
//! authorization gate, worker handler, and idempotency derivation must all
//! agree on the same closed vocabulary.

use std::str::FromStr;

/// Whether retention evaluation records expiry decisions or only observes
/// the decisions it would make.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RetentionEvaluationMode {
    /// Append expiry decisions and preserve the evaluator's existing behavior.
    #[default]
    Execute,
    /// Run the same selection and predicates without appending expiry events.
    DryRun,
}

impl RetentionEvaluationMode {
    /// Stable value used in task params and idempotency keys.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Execute => "execute",
            Self::DryRun => "dry_run",
        }
    }

    /// Whether this invocation can create destructive retention work.
    #[must_use]
    pub const fn is_destructive(self) -> bool {
        matches!(self, Self::Execute)
    }
}

impl FromStr for RetentionEvaluationMode {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "execute" => Ok(Self::Execute),
            "dry_run" => Ok(Self::DryRun),
            _ => Err("mode must be one of: execute, dry_run"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_execute_and_destructive() {
        let mode = RetentionEvaluationMode::default();
        assert_eq!(mode, RetentionEvaluationMode::Execute);
        assert_eq!(mode.as_str(), "execute");
        assert!(mode.is_destructive());
    }

    #[test]
    fn dry_run_is_non_destructive() {
        let mode = RetentionEvaluationMode::from_str("dry_run").unwrap();
        assert_eq!(mode.as_str(), "dry_run");
        assert!(!mode.is_destructive());
    }

    #[test]
    fn parser_rejects_unknown_value() {
        assert_eq!(
            RetentionEvaluationMode::from_str("preview").unwrap_err(),
            "mode must be one of: execute, dry_run"
        );
    }
}
