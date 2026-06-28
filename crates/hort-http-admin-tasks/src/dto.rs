//! Wire DTOs for the admin-task REST surface.
//!
//! All structs implement `Serialize` for outbound JSON. No `Deserialize`
//! — inputs use strongly-typed `TaskParams` impls or query-string
//! extractors.

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use hort_domain::ports::jobs_repository::JobRow;

/// Wire projection of a `jobs` table row.
///
/// Returned by both `GET /api/v1/admin/tasks` (list) and
/// `GET /api/v1/admin/tasks/:id` (single).
#[derive(Debug, Clone, Serialize)]
pub struct JobRowDto {
    pub id: Uuid,
    pub kind: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Uuid>,
    pub priority: i16,
    pub trigger_source: String,
    pub attempts: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// The completed handler's `result_summary` JSONB, surfaced as a
    /// structured value (the `jobs.result_summary` column is `jsonb`, not
    /// text). Omitted when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_summary: Option<serde_json::Value>,
}

impl From<JobRow> for JobRowDto {
    fn from(row: JobRow) -> Self {
        Self {
            id: row.id,
            kind: row.kind,
            status: row.status.as_str().to_string(),
            params: row.params,
            actor_id: row.actor_id,
            priority: row.priority,
            trigger_source: row.trigger_source,
            attempts: row.attempts,
            created_at: row.created_at,
            updated_at: row.updated_at,
            completed_at: row.completed_at,
            last_error: row.last_error,
            result_summary: row.result_summary,
        }
    }
}

/// Paginated list of task rows.
#[derive(Debug, Serialize)]
pub struct TaskListDto {
    pub tasks: Vec<JobRowDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Uuid>,
}
