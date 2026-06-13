//! Noop task handler for testing the end-to-end task framework.
//!
//! The handler computes a BLAKE3 hash of the `params` JSON and returns
//! `Completed` with a result summary containing the digest and timestamp.
//! This is used by the worker dispatcher's smoke test (Item 12) and the
//! E2E canary tick (Item 13).

use chrono::Utc;
use hort_domain::error::DomainResult;
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::BoxFuture;
use serde_json::json;

pub struct NoopTaskHandler;

impl TaskHandler for NoopTaskHandler {
    fn kind(&self) -> &'static str {
        "noop"
    }

    fn run<'a>(
        &'a self,
        params: &'a serde_json::Value,
        _ctx: TaskContext,
    ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
        Box::pin(async move {
            let body = params.to_string();
            let digest = blake3::hash(body.as_bytes()).to_hex();
            Ok(TaskOutcome::Completed {
                result_summary: json!({
                    "digest": digest.as_str(),
                    "received_at": Utc::now().to_rfc3339(),
                }),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use hort_domain::events::{Actor, InternalActor};
    use hort_domain::ports::jobs_repository::{JobRow, JobStatus, KindFields};
    use uuid::Uuid;

    fn make_actor() -> Actor {
        Actor::Internal(InternalActor::Timer)
    }

    fn test_job_row() -> JobRow {
        let now = Utc::now();
        JobRow {
            id: Uuid::new_v4(),
            kind: "noop".to_string(),
            status: JobStatus::Running,
            params: Some(serde_json::Value::Null),
            actor_id: None,
            priority: 0,
            trigger_source: "test".to_string(),
            attempts: 1,
            created_at: now,
            updated_at: now,
            completed_at: None,
            last_error: None,
            result_summary: None,
            kind_fields: KindFields::Other,
        }
    }

    fn make_context() -> TaskContext {
        TaskContext {
            task_job_id: Uuid::new_v4(),
            actor: make_actor(),
            correlation_id: Uuid::new_v4(),
            job_row: test_job_row(),
        }
    }

    /// Test 1: `kind()` returns "noop"
    #[test]
    fn kind_returns_noop() {
        let handler = NoopTaskHandler;
        assert_eq!(handler.kind(), "noop");
    }

    /// Test 2: `run()` with empty JSON object returns `Completed` with valid
    /// digest (64-char hex) and RFC3339 timestamp
    #[tokio::test]
    async fn run_with_empty_object_returns_completed_with_valid_digest() {
        let handler = NoopTaskHandler;
        let params = json!({});
        let ctx = make_context();

        let result = handler.run(&params, ctx).await.expect("run succeeded");

        match result {
            TaskOutcome::Completed { result_summary } => {
                // Check digest exists and is 64-char hex string
                let digest = result_summary["digest"]
                    .as_str()
                    .expect("digest is a string");
                assert_eq!(digest.len(), 64, "BLAKE3 digest must be 64 hex chars");
                assert!(
                    digest.chars().all(|c| c.is_ascii_hexdigit()),
                    "digest must be valid hex"
                );

                // Check timestamp exists and parses as RFC3339
                let received_at = result_summary["received_at"]
                    .as_str()
                    .expect("received_at is a string");
                chrono::DateTime::parse_from_rfc3339(received_at)
                    .expect("received_at parses as RFC3339");
            }
            _ => panic!("expected Completed variant"),
        }
    }

    /// Test 3: `run()` with identical inputs produces identical digests
    /// (deterministic hashing)
    #[tokio::test]
    async fn run_with_identical_input_produces_identical_digest() {
        let handler = NoopTaskHandler;
        let params = json!({
            "name": "test",
            "value": 42,
            "nested": { "key": "value" }
        });

        let ctx1 = make_context();
        let result1 = handler
            .run(&params, ctx1)
            .await
            .expect("first run succeeded");

        let ctx2 = make_context();
        let result2 = handler
            .run(&params, ctx2)
            .await
            .expect("second run succeeded");

        match (result1, result2) {
            (
                TaskOutcome::Completed {
                    result_summary: summary1,
                },
                TaskOutcome::Completed {
                    result_summary: summary2,
                },
            ) => {
                let digest1 = summary1["digest"].as_str().expect("digest1 is string");
                let digest2 = summary2["digest"].as_str().expect("digest2 is string");
                assert_eq!(
                    digest1, digest2,
                    "identical params must produce identical digest"
                );
            }
            _ => panic!("expected Completed variants"),
        }
    }

    /// Test 4: `run()` with distinct inputs produces distinct digests
    #[tokio::test]
    async fn run_with_distinct_inputs_produces_distinct_digests() {
        let handler = NoopTaskHandler;
        let params1 = json!({ "value": 1 });
        let params2 = json!({ "value": 2 });

        let ctx1 = make_context();
        let result1 = handler
            .run(&params1, ctx1)
            .await
            .expect("first run succeeded");

        let ctx2 = make_context();
        let result2 = handler
            .run(&params2, ctx2)
            .await
            .expect("second run succeeded");

        match (result1, result2) {
            (
                TaskOutcome::Completed {
                    result_summary: summary1,
                },
                TaskOutcome::Completed {
                    result_summary: summary2,
                },
            ) => {
                let digest1 = summary1["digest"].as_str().expect("digest1 is string");
                let digest2 = summary2["digest"].as_str().expect("digest2 is string");
                assert_ne!(
                    digest1, digest2,
                    "distinct params must produce distinct digests"
                );
            }
            _ => panic!("expected Completed variants"),
        }
    }

    /// Test 5: `run()` with complex nested object returns valid digest
    #[tokio::test]
    async fn run_with_complex_object_returns_valid_digest() {
        let handler = NoopTaskHandler;
        let params = json!({
            "array": [1, 2, 3],
            "string": "hello",
            "number": 42,
            "float": 1.5,
            "bool": true,
            "null": null,
            "nested": {
                "deep": {
                    "deeper": "value"
                }
            }
        });
        let ctx = make_context();

        let result = handler.run(&params, ctx).await.expect("run succeeded");

        match result {
            TaskOutcome::Completed { result_summary } => {
                let digest = result_summary["digest"]
                    .as_str()
                    .expect("digest is a string");
                assert_eq!(digest.len(), 64, "digest must be 64 hex chars");
                assert!(
                    digest.chars().all(|c| c.is_ascii_hexdigit()),
                    "digest must be valid hex"
                );
            }
            _ => panic!("expected Completed variant"),
        }
    }
}
