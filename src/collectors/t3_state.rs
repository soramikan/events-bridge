//! T3 Code event derivation.
//!
//! The rules in this module are intentionally narrow:
//!
//! * A provider turn, run attempt or root node ending only updates
//!   `t3_runs.last_turn_status`. It never generates `t3.run.completed` or
//!   `t3.run.failed`.
//! * `run.updated` is the only source of run completion/failure events.
//! * `runtime-request.updated` is the only source of approval events.
//!
//! Event identifiers are deterministic over `(environment, kind, aggregate)`,
//! so replaying the same upstream sequence is idempotent.

use anyhow::Result;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    collectors::t3_sqlite::T3Source,
    store::{
        NewEvent, Repository, T3ApplyOutcome, T3Approval, T3Project, T3ProjectDeletion, T3Run,
        T3RunPatch, T3Thread, T3WriteBatch,
    },
    util::{format_rfc3339, now_rfc3339, parse_rfc3339},
};

/// One event read from T3 Code's `orchestration_events` log.
#[derive(Debug, Clone)]
pub struct T3SourceEvent {
    /// Monotonic upstream sequence.
    pub sequence: i64,
    /// Upstream event id (kept for diagnostics).
    pub event_id: String,
    /// Upstream event type, e.g. `run.updated`.
    pub event_type: String,
    /// Thread id (`stream_id` in T3 Code).
    pub stream_id: String,
    /// Aggregate version.
    pub stream_version: i64,
    /// Upstream occurrence time.
    pub occurred_at: String,
    /// Upstream payload.
    pub payload: Value,
}

/// Derives materialized state and bridge events from one upstream event.
pub struct T3Reducer<'a> {
    environment_id: &'a str,
    repo: &'a Repository,
    source: &'a T3Source,
    web_base_url: Option<&'a Url>,
}

impl<'a> T3Reducer<'a> {
    /// Create a reducer for one environment.
    pub fn new(
        environment_id: &'a str,
        repo: &'a Repository,
        source: &'a T3Source,
        web_base_url: Option<&'a Url>,
    ) -> Self {
        Self {
            environment_id,
            repo,
            source,
            web_base_url,
        }
    }

    /// Apply one upstream event atomically.
    pub fn process(&self, event: &T3SourceEvent) -> Result<T3ApplyOutcome> {
        let batch = self.reduce(event)?;
        self.repo.apply_t3_batch(&batch)
    }

    /// Derive one write batch without committing it.
    ///
    /// The hub's local collector applies the returned batch immediately; an
    /// edge collector forwards it to the hub and only applies it locally after
    /// the hub accepted it. Both paths therefore share exactly the same
    /// derivation rules.
    pub fn reduce(&self, event: &T3SourceEvent) -> Result<T3WriteBatch> {
        let occurred_at = normalize_timestamp(&event.occurred_at).unwrap_or_else(now_rfc3339);
        let mut batch = T3WriteBatch {
            environment_id: self.environment_id.to_string(),
            sequence: event.sequence,
            ..T3WriteBatch::default()
        };

        match event.event_type.as_str() {
            "project.created" | "project.metadata-updated" => {
                batch.project = self.project_from_payload(&event.payload, &occurred_at);
            }
            "project.deleted" => {
                if let Some(project_id) = text(&event.payload, "projectId") {
                    let deleted_at = timestamp(&event.payload, "deletedAt")
                        .unwrap_or_else(|| occurred_at.clone());
                    batch.project_deleted = Some(T3ProjectDeletion {
                        project_id,
                        deleted_at: deleted_at.clone(),
                        updated_at: deleted_at,
                    });
                }
            }
            "thread.created" | "thread.metadata-updated" | "thread.deleted" => {
                batch.thread = self.thread_from_payload(event, &occurred_at);
            }
            "run.created" | "run.updated" => {
                self.apply_run(event, &occurred_at, &mut batch)?;
            }
            "provider-turn.updated" => {
                let mut run_id = text(&event.payload, "runId");
                if run_id.is_none()
                    && let Some(node) = text(&event.payload, "nodeId")
                {
                    run_id = self.source.run_for_node(&node)?;
                }
                if run_id.is_none()
                    && let Some(attempt) = text(&event.payload, "runAttemptId")
                {
                    run_id = self.source.run_for_attempt(&attempt)?;
                }
                self.patch_turn(run_id, event, &occurred_at, &mut batch);
            }
            "run-attempt.updated" => {
                self.patch_turn(
                    text(&event.payload, "runId"),
                    event,
                    &occurred_at,
                    &mut batch,
                );
            }
            "node.updated" => {
                let is_root_turn = text(&event.payload, "kind").as_deref() == Some("root_turn");
                if is_root_turn {
                    self.patch_turn(
                        text(&event.payload, "runId"),
                        event,
                        &occurred_at,
                        &mut batch,
                    );
                }
            }
            "runtime-request.updated" => {
                self.apply_approval(event, &occurred_at, &mut batch)?;
            }
            _ => {}
        }

        Ok(batch)
    }

    fn project_from_payload(&self, payload: &Value, occurred_at: &str) -> Option<T3Project> {
        let project_id = text(payload, "projectId")?;
        Some(T3Project {
            environment_id: self.environment_id.to_string(),
            project_id,
            title: text(payload, "title").unwrap_or_default(),
            workspace_root: text(payload, "workspaceRoot").unwrap_or_default(),
            deleted_at: timestamp(payload, "deletedAt"),
            updated_at: timestamp(payload, "updatedAt").unwrap_or_else(|| occurred_at.to_string()),
        })
    }

    fn thread_from_payload(&self, event: &T3SourceEvent, occurred_at: &str) -> Option<T3Thread> {
        let payload = &event.payload;
        let thread_id = text(payload, "id")?;
        let deleted_at = timestamp(payload, "deletedAt")
            .or_else(|| (event.event_type == "thread.deleted").then(|| occurred_at.to_string()));
        Some(T3Thread {
            environment_id: self.environment_id.to_string(),
            thread_id,
            project_id: text(payload, "projectId").unwrap_or_default(),
            title: text(payload, "title").unwrap_or_else(|| "(untitled thread)".to_string()),
            branch: text(payload, "branch"),
            deleted_at,
            updated_at: timestamp(payload, "updatedAt").unwrap_or_else(|| occurred_at.to_string()),
        })
    }

    fn apply_run(
        &self,
        event: &T3SourceEvent,
        occurred_at: &str,
        batch: &mut T3WriteBatch,
    ) -> Result<()> {
        let payload = &event.payload;
        let Some(run_id) = text(payload, "id") else {
            return Ok(());
        };
        let previous = self
            .repo
            .get_t3_run(&run_id, Some(self.environment_id))?
            .map(|detail| detail.run);
        let previous_status = previous.as_ref().map(|run| run.status.clone());

        let thread_id = text(payload, "threadId")
            .or_else(|| previous.as_ref().map(|run| run.thread_id.clone()))
            .unwrap_or_default();
        let project_id = if thread_id.is_empty() {
            previous
                .as_ref()
                .map(|run| run.project_id.clone())
                .unwrap_or_default()
        } else {
            self.project_for_thread(&thread_id)?
        };
        let status = text(payload, "status")
            .or_else(|| previous.as_ref().map(|run| run.status.clone()))
            .unwrap_or_else(|| "running".to_string());
        let ordinal = integer(payload, "ordinal")
            .or_else(|| previous.as_ref().map(|run| run.ordinal))
            .unwrap_or(0);
        let thread_title = if thread_id.is_empty() {
            None
        } else {
            self.repo
                .get_t3_thread(self.environment_id, &thread_id)?
                .map(|thread| thread.title)
        };
        let summary = run_summary(&status, ordinal, thread_title.as_deref());
        let error = if status == "failed" {
            Some(
                extract_error(payload)
                    .or(self.source.failure_for_run(&run_id)?)
                    .or_else(|| previous.as_ref().and_then(|run| run.error.clone()))
                    .unwrap_or_else(|| "T3 run failed without a reported error".to_string()),
            )
        } else if status == "completed" {
            None
        } else {
            previous.as_ref().and_then(|run| run.error.clone())
        };

        let run = T3Run {
            environment_id: self.environment_id.to_string(),
            run_id: run_id.clone(),
            thread_id: thread_id.clone(),
            project_id: project_id.clone(),
            ordinal,
            provider_instance_id: text(payload, "providerInstanceId").or_else(|| {
                previous
                    .as_ref()
                    .and_then(|run| run.provider_instance_id.clone())
            }),
            status: status.clone(),
            last_turn_status: previous
                .as_ref()
                .and_then(|run| run.last_turn_status.clone()),
            checkpoint_id: text(payload, "checkpointId")
                .or_else(|| previous.as_ref().and_then(|run| run.checkpoint_id.clone())),
            error,
            summary: Some(summary),
            requested_at: timestamp(payload, "requestedAt")
                .or_else(|| previous.as_ref().and_then(|run| run.requested_at.clone())),
            started_at: timestamp(payload, "startedAt")
                .or_else(|| previous.as_ref().and_then(|run| run.started_at.clone())),
            completed_at: timestamp(payload, "completedAt")
                .or_else(|| previous.as_ref().and_then(|run| run.completed_at.clone())),
            updated_at: occurred_at.to_string(),
        };

        // Only `run.updated` is a final-state signal, and only the first
        // transition from a non-final status emits a bridge event.
        if event.event_type == "run.updated" {
            if run.status == "completed" && previous_status.as_deref() != Some("completed") {
                batch.events.push(self.completed_event(&run, occurred_at));
            } else if run.status == "failed" && previous_status.as_deref() != Some("failed") {
                batch.events.push(self.failed_event(&run, occurred_at));
            }
        }
        batch.run = Some(run);
        Ok(())
    }

    fn patch_turn(
        &self,
        run_id: Option<String>,
        event: &T3SourceEvent,
        occurred_at: &str,
        batch: &mut T3WriteBatch,
    ) {
        let (Some(run_id), Some(status)) = (run_id, text(&event.payload, "status")) else {
            return;
        };
        batch.run_patch = Some(T3RunPatch {
            run_id,
            last_turn_status: status,
            updated_at: occurred_at.to_string(),
        });
    }

    fn apply_approval(
        &self,
        event: &T3SourceEvent,
        occurred_at: &str,
        batch: &mut T3WriteBatch,
    ) -> Result<()> {
        let payload = &event.payload;
        let Some(approval_id) = text(payload, "id").or_else(|| text(payload, "runtimeRequestId"))
        else {
            return Ok(());
        };
        let previous = self
            .repo
            .get_t3_approval(self.environment_id, &approval_id)?;
        let previous_status = previous.as_ref().map(|approval| approval.status.clone());

        let node_id = text(payload, "nodeId");
        let mut thread_id = text(payload, "threadId");
        if thread_id.is_none()
            && let Some(node) = node_id.as_deref()
        {
            thread_id = self.source.thread_for_node(node)?;
        }
        if thread_id.is_none() {
            thread_id = previous.as_ref().map(|approval| approval.thread_id.clone());
        }
        let thread_id = thread_id.unwrap_or_default();

        let mut run_id = text(payload, "runId");
        if run_id.is_none()
            && let Some(node) = node_id.as_deref()
        {
            run_id = self.source.run_for_node(node)?;
        }
        if run_id.is_none() && !thread_id.is_empty() {
            run_id = self
                .repo
                .latest_t3_run_for_thread(self.environment_id, &thread_id)?
                .map(|run| run.run_id);
        }
        if run_id.is_none() {
            run_id = previous.as_ref().map(|approval| approval.run_id.clone());
        }
        let run_id = run_id.unwrap_or_default();
        let kind = text(payload, "kind")
            .or_else(|| previous.as_ref().map(|approval| approval.kind.clone()))
            .unwrap_or_else(|| "unknown".to_string());
        let status = text(payload, "status")
            .or_else(|| previous.as_ref().map(|approval| approval.status.clone()))
            .unwrap_or_else(|| "pending".to_string());
        let summary = text(payload, "summary")
            .or_else(|| text(payload, "title"))
            .or_else(|| text(payload, "reason"))
            .or_else(|| {
                previous
                    .as_ref()
                    .and_then(|approval| approval.summary.clone())
            })
            .unwrap_or_else(|| format!("{kind} approval required"));
        let decision = decision_text(payload.get("decision")).or_else(|| {
            previous
                .as_ref()
                .and_then(|approval| approval.decision.clone())
        });
        let created_at = timestamp(payload, "createdAt")
            .or_else(|| {
                previous
                    .as_ref()
                    .map(|approval| approval.created_at.clone())
            })
            .unwrap_or_else(|| occurred_at.to_string());
        let terminal = matches!(status.as_str(), "resolved" | "expired" | "cancelled");
        let previous_resolved_at = previous
            .as_ref()
            .and_then(|approval| approval.resolved_at.clone());
        let resolved_at = if terminal {
            timestamp(payload, "resolvedAt")
                .or(previous_resolved_at)
                .or_else(|| Some(occurred_at.to_string()))
        } else if status == "pending" {
            None
        } else {
            timestamp(payload, "resolvedAt").or(previous_resolved_at)
        };
        let approval = T3Approval {
            environment_id: self.environment_id.to_string(),
            approval_id: approval_id.clone(),
            thread_id: thread_id.clone(),
            run_id: run_id.clone(),
            node_id: node_id.clone(),
            kind: kind.clone(),
            status: status.clone(),
            summary: Some(summary.clone()),
            decision,
            created_at,
            resolved_at,
            updated_at: occurred_at.to_string(),
        };

        if approval.status == "pending" && previous_status.as_deref() != Some("pending") {
            batch
                .events
                .push(self.approval_event(&approval, occurred_at));
        }
        batch.approval = Some(approval);
        Ok(())
    }

    fn project_for_thread(&self, thread_id: &str) -> Result<String> {
        if let Some(thread) = self.repo.get_t3_thread(self.environment_id, thread_id)? {
            return Ok(thread.project_id);
        }
        Ok(self
            .source
            .project_for_thread(thread_id)?
            .unwrap_or_default())
    }

    fn completed_event(&self, run: &T3Run, occurred_at: &str) -> NewEvent {
        let mut payload = Map::new();
        payload.insert("environment_id".into(), json!(self.environment_id));
        payload.insert("project_id".into(), json!(run.project_id));
        payload.insert("thread_id".into(), json!(run.thread_id));
        payload.insert("run_id".into(), json!(run.run_id));
        let summary = bound_json_text(
            run.summary.as_deref().unwrap_or("T3 run completed"),
            WEBHOOK_SUMMARY_JSON_BYTES,
        );
        payload.insert("summary".into(), json!(summary));
        if let Some(url) = self.thread_url(&run.thread_id) {
            payload.insert("url".into(), json!(url));
        }
        NewEvent {
            id: Some(event_id(self.environment_id, &run.run_id, "completed")),
            source: Some("t3".into()),
            kind: "t3.run.completed".into(),
            payload: Value::Object(payload),
            occurred_at: Some(occurred_at.to_string()),
        }
    }

    fn failed_event(&self, run: &T3Run, occurred_at: &str) -> NewEvent {
        let mut payload = Map::new();
        payload.insert("environment_id".into(), json!(self.environment_id));
        payload.insert("project_id".into(), json!(run.project_id));
        payload.insert("thread_id".into(), json!(run.thread_id));
        payload.insert("run_id".into(), json!(run.run_id));
        let summary = bound_json_text(
            run.summary.as_deref().unwrap_or("T3 run failed"),
            WEBHOOK_SUMMARY_JSON_BYTES,
        );
        let error = bound_json_text(
            run.error
                .as_deref()
                .unwrap_or("T3 run failed without a reported error"),
            WEBHOOK_ERROR_JSON_BYTES,
        );
        payload.insert("summary".into(), json!(summary));
        payload.insert("error".into(), json!(error));
        if let Some(url) = self.thread_url(&run.thread_id) {
            payload.insert("url".into(), json!(url));
        }
        NewEvent {
            id: Some(event_id(self.environment_id, &run.run_id, "failed")),
            source: Some("t3".into()),
            kind: "t3.run.failed".into(),
            payload: Value::Object(payload),
            occurred_at: Some(occurred_at.to_string()),
        }
    }

    fn approval_event(&self, approval: &T3Approval, occurred_at: &str) -> NewEvent {
        let mut payload = Map::new();
        let project_id = self
            .run_project(&approval.run_id)
            .ok()
            .flatten()
            .filter(|id| !id.is_empty())
            .or_else(|| {
                (!approval.thread_id.is_empty())
                    .then(|| self.project_for_thread(&approval.thread_id).ok())
                    .flatten()
            })
            .unwrap_or_default();
        payload.insert("environment_id".into(), json!(self.environment_id));
        payload.insert("project_id".into(), json!(project_id));
        payload.insert("thread_id".into(), json!(approval.thread_id));
        payload.insert("run_id".into(), json!(approval.run_id));
        payload.insert("approval_id".into(), json!(approval.approval_id));
        let summary = bound_json_text(
            approval
                .summary
                .as_deref()
                .unwrap_or("T3 approval required"),
            WEBHOOK_SUMMARY_JSON_BYTES,
        );
        payload.insert("summary".into(), json!(summary));
        if let Some(url) = self.thread_url(&approval.thread_id) {
            payload.insert("url".into(), json!(url));
        }
        NewEvent {
            id: Some(event_id(
                self.environment_id,
                &approval.approval_id,
                "approval",
            )),
            source: Some("t3".into()),
            kind: "t3.approval.required".into(),
            payload: Value::Object(payload),
            occurred_at: Some(occurred_at.to_string()),
        }
    }

    fn run_project(&self, run_id: &str) -> Result<Option<String>> {
        if run_id.is_empty() {
            return Ok(None);
        }
        Ok(self
            .repo
            .get_t3_run(run_id, Some(self.environment_id))?
            .map(|detail| detail.run.project_id))
    }

    fn thread_url(&self, thread_id: &str) -> Option<String> {
        if thread_id.is_empty() {
            return None;
        }
        let mut url = self.web_base_url?.clone();
        {
            let mut segments = url.path_segments_mut().ok()?;
            segments.pop_if_empty();
            segments.push("threads");
            segments.push(thread_id);
        }
        Some(url.to_string())
    }
}

/// Short human-readable run summary.
pub fn run_summary(status: &str, ordinal: i64, thread_title: Option<&str>) -> String {
    let mut summary = format!("Run #{ordinal} {status}");
    if let Some(title) = thread_title {
        summary.push_str(" in \"");
        summary.push_str(&truncate(title, 120));
        summary.push('"');
    }
    truncate(&summary, 300)
}

/// Deterministic bridge event id for an upstream aggregate.
pub fn event_id(environment_id: &str, aggregate: &str, suffix: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(environment_id.as_bytes());
    hasher.update([0u8]);
    hasher.update(suffix.as_bytes());
    hasher.update([0u8]);
    hasher.update(aggregate.as_bytes());
    let digest = hex::encode(hasher.finalize());
    format!(
        "evt_t3_{}_{}_{}_{}",
        slug(environment_id, 24),
        slug(aggregate, 64),
        &digest[..10],
        suffix
    )
}

/// Extract a human-readable failure from a run, node, attempt or turn item.
pub fn extract_error(payload: &Value) -> Option<String> {
    let message = [
        "failure",
        "error",
        "errorMessage",
        "failureReason",
        "reason",
        "message",
    ]
    .iter()
    .find_map(|key| payload.get(*key).and_then(error_value));
    let title = text(payload, "title");
    let combined = match (title, message) {
        (Some(title), Some(message)) if !message.starts_with(&title) => {
            Some(format!("{title}: {message}"))
        }
        (_, Some(message)) => Some(message),
        (Some(title), None) => Some(title),
        (None, None) => None,
    };
    combined
        .map(|value| truncate(value.trim(), 4_000))
        .filter(|value| !value.is_empty())
}

fn error_value(value: &Value) -> Option<String> {
    match value {
        Value::String(text) if !text.trim().is_empty() => Some(text.trim().to_string()),
        Value::Object(map) => ["message", "error", "reason", "detail", "code"]
            .iter()
            .find_map(|key| map.get(*key).and_then(error_value)),
        _ => None,
    }
}

/// Normalize an RFC 3339 timestamp into the store's fixed-width UTC form.
pub fn normalize_timestamp(value: &str) -> Option<String> {
    parse_rfc3339(value).map(format_rfc3339)
}

fn timestamp(payload: &Value, key: &str) -> Option<String> {
    text(payload, key).and_then(|value| normalize_timestamp(&value))
}

fn text(payload: &Value, key: &str) -> Option<String> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn integer(payload: &Value, key: &str) -> Option<i64> {
    payload.get(key).and_then(|value| {
        value
            .as_i64()
            .or_else(|| value.as_str().and_then(|text| text.parse::<i64>().ok()))
    })
}

fn decision_text(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::Null => None,
        Value::String(text) if text.is_empty() => None,
        Value::String(text) => Some(text.clone()),
        other => serde_json::to_string(other).ok(),
    }
}

fn slug(value: &str, limit: usize) -> String {
    let slug: String = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                ch
            } else {
                '-'
            }
        })
        .take(limit)
        .collect();
    if slug.is_empty() { "x".into() } else { slug }
}

const WEBHOOK_SUMMARY_JSON_BYTES: usize = 4 * 1024;
const WEBHOOK_ERROR_JSON_BYTES: usize = 16 * 1024;

fn bound_json_text(value: &str, max_json_bytes: usize) -> String {
    if serde_json::to_string(value)
        .map(|serialized| serialized.len() <= max_json_bytes)
        .unwrap_or(false)
    {
        return value.to_string();
    }

    let suffix = "...";
    let mut boundaries: Vec<usize> = value.char_indices().map(|(idx, _)| idx).collect();
    boundaries.push(value.len());

    let mut low = 0usize;
    let mut high = boundaries.len() - 1;
    let mut best = String::new();
    while low <= high {
        let mid = low + (high - low) / 2;
        let candidate = format!("{}{suffix}", &value[..boundaries[mid]]);
        let fits = serde_json::to_string(&candidate)
            .map(|serialized| serialized.len() <= max_json_bytes)
            .unwrap_or(false);
        if fits {
            best = candidate;
            low = mid + 1;
        } else if mid == 0 {
            break;
        } else {
            high = mid - 1;
        }
    }
    if best.is_empty() {
        truncate(suffix, max_json_bytes.saturating_sub(2))
    } else {
        best
    }
}

fn truncate(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        value.to_string()
    } else {
        value.chars().take(limit).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_ids_are_deterministic_and_bounded() {
        let first = event_id("env-1", "run:thread:very-long-identifier", "completed");
        let second = event_id("env-1", "run:thread:very-long-identifier", "completed");
        assert_eq!(first, second);
        assert_ne!(
            first,
            event_id("env-2", "run:thread:very-long-identifier", "completed")
        );
        assert_ne!(
            first,
            event_id("env-1", "run:thread:very-long-identifier", "failed")
        );
        assert!(first.len() < 200);
        assert!(first.starts_with("evt_t3_"));
    }

    #[test]
    fn errors_are_extracted_from_nested_failure_objects() {
        let payload = json!({
            "status": "failed",
            "title": "Provider error",
            "failure": {"class": "provider_error", "message": "no API key", "code": "-32603"}
        });
        assert_eq!(
            extract_error(&payload).as_deref(),
            Some("Provider error: no API key")
        );
        assert!(extract_error(&json!({"status": "failed"})).is_none());
    }

    #[test]
    fn summaries_are_bounded() {
        let summary = run_summary("completed", 3, Some(&"x".repeat(1_000)));
        assert!(summary.chars().count() <= 300);
        assert!(summary.contains("Run #3 completed"));
    }
}
