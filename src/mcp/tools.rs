//! Read-oriented MCP tools (design §6).
//!
//! `ack_events` writes to the `acks` table only. It never marks a webhook
//! delivery as delivered: a receiver `2xx` and a user acknowledgement are
//! separate states.

use std::sync::{Arc, LazyLock};

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, JsonObject, Tool,
    ToolAnnotations,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::config::Config;
use crate::consumers::{ConsumerService, MAX_CONSUMER_POLL_LIMIT};
use crate::mcp::event_catalog;
use crate::store::{Event, EventQuery, GitHubStatusQuery, Repository, T3ApprovalQuery};
use crate::util::{format_rfc3339, parse_rfc3339};

/// Maximum page size for `list_events`.
const MAX_LIMIT: usize = 200;
const DEFAULT_LIMIT: usize = 50;

fn schema(value: Value) -> Arc<JsonObject> {
    Arc::new(
        value
            .as_object()
            .expect("tool schemas are JSON objects")
            .clone(),
    )
}

fn tool(name: &'static str, description: &'static str, input: Value, read_only: bool) -> Tool {
    let mut tool = Tool::new(name, description, schema(input));
    let mut annotations = ToolAnnotations::default();
    annotations.read_only_hint = Some(read_only);
    annotations.idempotent_hint = Some(true);
    annotations.open_world_hint = Some(false);
    tool.annotations = Some(annotations);
    tool
}

/// Tool definitions advertised by `tools/list`.
pub fn definitions() -> Vec<Tool> {
    static TOOLS: LazyLock<Vec<Tool>> = LazyLock::new(|| {
        vec![
            tool(
                "list_events",
                "List persisted T3 Code and GitHub events, optionally filtered by time, source, event name, or severity.",
                json!({
                    "type": "object",
                    "properties": {
                        "since": {"type": "string", "description": "Inclusive RFC 3339 lower bound on occurredAt."},
                        "until": {"type": "string", "description": "Inclusive RFC 3339 upper bound on occurredAt."},
                        "source": {"type": "string", "enum": ["t3", "github"]},
                        "kind": {"type": "string", "description": "Exact event name, e.g. t3.run.failed."},
                        "severity": {"type": "string", "enum": ["high", "normal"]},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 200},
                        "after": {"type": "integer", "minimum": 0, "description": "Return events with sequence strictly greater than this value."},
                        "cursor": {"type": "string", "description": "Opaque cursor from a previous response."}
                    },
                    "additionalProperties": false
                }),
                true,
            ),
            tool(
                "get_event",
                "Fetch one persisted event by id.",
                json!({
                    "type": "object",
                    "properties": {
                        "event_id": {"type": "string"}
                    },
                    "required": ["event_id"],
                    "additionalProperties": false
                }),
                true,
            ),
            tool(
                "get_t3_run",
                "Fetch the latest materialized state of a T3 Code run, including its pending approval count.",
                json!({
                    "type": "object",
                    "properties": {
                        "run_id": {"type": "string"},
                        "environment_id": {"type": "string"}
                    },
                    "required": ["run_id"],
                    "additionalProperties": false
                }),
                true,
            ),
            tool(
                "get_t3_approvals",
                "List T3 Code approvals. Defaults to pending approvals; pass status \"all\" for every state.",
                json!({
                    "type": "object",
                    "properties": {
                        "environment_id": {"type": "string"},
                        "project_id": {"type": "string"},
                        "thread_id": {"type": "string"},
                        "status": {
                            "type": "string",
                            "enum": ["pending", "resolved", "expired", "cancelled", "all"]
                        },
                        "limit": {"type": "integer", "minimum": 1, "maximum": 200}
                    },
                    "additionalProperties": false
                }),
                true,
            ),
            tool(
                "get_github_status",
                "Fetch materialized GitHub pull requests and CI runs, optionally filtered by repository, pull request, or head branch.",
                json!({
                    "type": "object",
                    "properties": {
                        "repository": {"type": "string", "description": "Repository in owner/repo form."},
                        "pull_number": {"type": "integer", "minimum": 1},
                        "branch": {"type": "string", "description": "Head branch (pull requests may also match the base branch)."},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 200}
                    },
                    "additionalProperties": false
                }),
                true,
            ),
            tool(
                "ack_events",
                "Record that the user has seen events. This is separate from webhook delivery confirmation.",
                json!({
                    "type": "object",
                    "properties": {
                        "event_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                            "minItems": 1,
                            "maxItems": 200
                        }
                    },
                    "required": ["event_ids"],
                    "additionalProperties": false
                }),
                false,
            ),
            tool(
                "probe_consumer",
                "Check whether a named polling consumer has unread events without fetching or consuming them.",
                json!({
                    "type": "object",
                    "properties": {
                        "consumer": {"type": "string", "description": "Consumer name, e.g. muse."}
                    },
                    "required": ["consumer"],
                    "additionalProperties": false
                }),
                true,
            ),
            tool(
                "poll_consumer_events",
                "Fetch unacknowledged events for a named polling consumer. Immediate events are returned individually, digest events are aggregated into time-window summaries, and polling does not advance the consumer cursor.",
                json!({
                    "type": "object",
                    "properties": {
                        "consumer": {"type": "string", "description": "Consumer name, e.g. muse."},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 200}
                    },
                    "required": ["consumer"],
                    "additionalProperties": false
                }),
                true,
            ),
            tool(
                "ack_consumer_events",
                "Advance a named polling consumer cursor after events were processed. This is separate from ack_events.",
                json!({
                    "type": "object",
                    "properties": {
                        "consumer": {"type": "string", "description": "Consumer name, e.g. muse."},
                        "up_to_sequence": {"type": "integer", "minimum": 0}
                    },
                    "required": ["consumer", "up_to_sequence"],
                    "additionalProperties": false
                }),
                false,
            ),
        ]
    });
    TOOLS.clone()
}

/// Look up a tool definition by name.
pub fn get(name: &str) -> Option<Tool> {
    definitions().into_iter().find(|tool| tool.name == name)
}

/// Executes pull tools against the store.
#[derive(Clone)]
pub struct ToolService {
    repo: Arc<Repository>,
    consumers: Arc<ConsumerService>,
}

impl ToolService {
    /// Create a tool service with built-in consumer profiles.
    ///
    /// Hub construction uses [`Self::with_consumers`] so configured profiles
    /// are visible to the consumer tools.
    pub fn new(repo: Arc<Repository>) -> Self {
        let consumers = Arc::new(ConsumerService::new(
            repo.clone(),
            Config::default().consumers,
        ));
        Self { repo, consumers }
    }

    /// Create a tool service sharing the hub's consumer service.
    pub fn with_consumers(repo: Arc<Repository>, consumers: Arc<ConsumerService>) -> Self {
        Self { repo, consumers }
    }

    /// Dispatch a `tools/call`.
    pub async fn call(
        &self,
        principal: &str,
        request: CallToolRequestParams,
    ) -> Result<CallToolResponse, rmcp::ErrorData> {
        let arguments = request
            .arguments
            .map(Value::Object)
            .unwrap_or_else(|| json!({}));

        let result = match request.name.as_ref() {
            "list_events" => self.list_events(arguments),
            "get_event" => self.get_event(arguments),
            "get_t3_run" => self.get_t3_run(arguments),
            "get_t3_approvals" => self.get_t3_approvals(arguments),
            "get_github_status" => self.get_github_status(arguments),
            "ack_events" => self.ack_events(principal, arguments),
            "probe_consumer" => self.probe_consumer(arguments),
            "poll_consumer_events" => self.poll_consumer_events(arguments),
            "ack_consumer_events" => self.ack_consumer_events(arguments),
            other => Err(format!("unknown tool `{other}`")),
        };

        match result {
            Ok(value) => {
                let text = serde_json::to_string(&value).unwrap_or_else(|_| "{}".into());
                let mut outcome = CallToolResult::success(vec![ContentBlock::text(text)]);
                outcome.structured_content = Some(value);
                Ok(outcome.into())
            }
            Err(message) => Ok(CallToolResult::error(vec![ContentBlock::text(message)]).into()),
        }
    }

    fn list_events(&self, arguments: Value) -> Result<Value, String> {
        let args: ListEventsArgs = serde_json::from_value(arguments)
            .map_err(|error| format!("invalid arguments: {error}"))?;

        let since = match args.since {
            Some(value) => Some(
                parse_rfc3339(&value)
                    .ok_or_else(|| "`since` must be an RFC 3339 timestamp".to_string())
                    .map(format_rfc3339)?,
            ),
            None => None,
        };
        let until = match args.until {
            Some(value) => Some(
                parse_rfc3339(&value)
                    .ok_or_else(|| "`until` must be an RFC 3339 timestamp".to_string())
                    .map(format_rfc3339)?,
            ),
            None => None,
        };

        let kinds = match args.severity.as_deref() {
            None => None,
            Some(severity @ ("high" | "normal")) => Some(
                event_catalog::EVENTS
                    .iter()
                    .filter(|event| event.severity.as_str() == severity)
                    .map(|event| event.name.to_string())
                    .collect::<Vec<_>>(),
            ),
            Some(other) => return Err(format!("unknown severity `{other}`")),
        };

        let after_sequence = match (args.after, args.cursor.as_deref()) {
            (Some(_), Some(_)) => {
                return Err("specify either `after` or `cursor`, not both".into());
            }
            (Some(after), None) => {
                if after < 0 {
                    return Err(format!("`after` must be at least 0, got {after}"));
                }
                Some(after)
            }
            (None, Some(cursor)) => Some(parse_cursor(cursor)?),
            (None, None) => None,
        };

        let limit = args.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
        let events = self
            .repo
            .list_events(&EventQuery {
                since,
                until,
                source: args.source,
                kind: args.kind,
                kinds,
                after_sequence,
                limit: limit as i64,
            })
            .map_err(|error| error.to_string())?;

        let next_cursor = if events.len() == limit {
            events.last().map(|event| format!("seq_{}", event.sequence))
        } else {
            None
        };

        Ok(json!({
            "events": events,
            "nextCursor": next_cursor,
        }))
    }

    fn get_event(&self, arguments: Value) -> Result<Value, String> {
        let args: GetEventArgs = serde_json::from_value(arguments)
            .map_err(|error| format!("invalid arguments: {error}"))?;
        let event = self
            .repo
            .get_event(&args.event_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("event `{}` not found", args.event_id))?;
        Ok(json!({"event": event}))
    }

    fn get_t3_run(&self, arguments: Value) -> Result<Value, String> {
        let args: GetT3RunArgs = serde_json::from_value(arguments)
            .map_err(|error| format!("invalid arguments: {error}"))?;
        let detail = self
            .repo
            .get_t3_run(&args.run_id, args.environment_id.as_deref())
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("T3 run `{}` not found", args.run_id))?;
        Ok(json!({"run": detail}))
    }

    fn get_t3_approvals(&self, arguments: Value) -> Result<Value, String> {
        let args: GetT3ApprovalsArgs = serde_json::from_value(arguments)
            .map_err(|error| format!("invalid arguments: {error}"))?;
        let status = args.status.unwrap_or_else(|| "pending".into());
        if !matches!(
            status.as_str(),
            "pending" | "resolved" | "expired" | "cancelled" | "all"
        ) {
            return Err(format!("unknown approval status `{status}`"));
        }
        let approvals = self
            .repo
            .list_t3_approvals(&T3ApprovalQuery {
                environment_id: args.environment_id,
                project_id: args.project_id,
                thread_id: args.thread_id,
                status: Some(status),
                limit: args.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT) as i64,
            })
            .map_err(|error| error.to_string())?;
        Ok(json!({"approvals": approvals}))
    }

    fn get_github_status(&self, arguments: Value) -> Result<Value, String> {
        let args: GetGitHubStatusArgs = serde_json::from_value(arguments)
            .map_err(|error| format!("invalid arguments: {error}"))?;
        if let Some(repository) = &args.repository {
            let mut parts = repository.split('/');
            let owner = parts.next().unwrap_or_default();
            let name = parts.next().unwrap_or_default();
            if owner.is_empty() || name.is_empty() || parts.next().is_some() {
                return Err("`repository` must have the form `owner/repo`".into());
            }
        }
        if let Some(pull_number) = args.pull_number
            && pull_number <= 0
        {
            return Err("`pull_number` must be a positive integer".into());
        }
        let limit = match args.limit {
            None => DEFAULT_LIMIT,
            Some(0) => {
                return Err(format!("`limit` must be between 1 and {MAX_LIMIT}, got 0"));
            }
            Some(limit) if limit > MAX_LIMIT => {
                return Err(format!(
                    "`limit` must be between 1 and {MAX_LIMIT}, got {limit}"
                ));
            }
            Some(limit) => limit,
        };
        let status = self
            .repo
            .github_status(&GitHubStatusQuery {
                repository: args.repository,
                pull_number: args.pull_number,
                branch: args.branch,
                limit: limit as i64,
            })
            .map_err(|error| error.to_string())?;

        let open_pull_requests = status
            .pull_requests
            .iter()
            .filter(|pull| pull.state == "open")
            .count();
        let merged_pull_requests = status
            .pull_requests
            .iter()
            .filter(|pull| pull.merged)
            .count();
        let failed_ci_runs = status
            .ci_runs
            .iter()
            .filter(|run| {
                run.status == "failed"
                    || matches!(
                        run.conclusion.as_deref(),
                        Some("failure" | "timed_out" | "action_required" | "startup_failure")
                    )
            })
            .count();

        Ok(json!({
            "pullRequests": status.pull_requests,
            "ciRuns": status.ci_runs,
            "summary": {
                "pullRequestCount": status.pull_requests.len(),
                "ciRunCount": status.ci_runs.len(),
                "openPullRequestCount": open_pull_requests,
                "mergedPullRequestCount": merged_pull_requests,
                "failedCiRunCount": failed_ci_runs,
            },
        }))
    }

    fn ack_events(&self, principal: &str, arguments: Value) -> Result<Value, String> {
        let args: AckEventsArgs = serde_json::from_value(arguments)
            .map_err(|error| format!("invalid arguments: {error}"))?;
        if args.event_ids.is_empty() {
            return Err("`event_ids` must contain at least one id".into());
        }
        let acknowledged = self
            .repo
            .ack_events(principal, &args.event_ids)
            .map_err(|error| error.to_string())?;
        Ok(json!({
            "acknowledged": acknowledged,
            "note": "This records user acknowledgement only; webhook delivery state is unchanged.",
        }))
    }

    fn probe_consumer(&self, arguments: Value) -> Result<Value, String> {
        let args: ConsumerArgs = serde_json::from_value(arguments)
            .map_err(|error| format!("invalid arguments: {error}"))?;
        let probe = self
            .consumers
            .probe(&args.consumer)
            .map_err(|error| error.to_string())?;
        serde_json::to_value(probe).map_err(|error| error.to_string())
    }

    fn poll_consumer_events(&self, arguments: Value) -> Result<Value, String> {
        let args: PollConsumerArgs = serde_json::from_value(arguments)
            .map_err(|error| format!("invalid arguments: {error}"))?;
        if let Some(limit) = args.limit
            && !(1..=MAX_CONSUMER_POLL_LIMIT).contains(&limit)
        {
            return Err(format!(
                "`limit` must be between 1 and {MAX_CONSUMER_POLL_LIMIT}, got {limit}"
            ));
        }
        let poll = self
            .consumers
            .poll(&args.consumer, args.limit)
            .map_err(|error| error.to_string())?;
        serde_json::to_value(poll).map_err(|error| error.to_string())
    }

    fn ack_consumer_events(&self, arguments: Value) -> Result<Value, String> {
        let args: AckConsumerArgs = serde_json::from_value(arguments)
            .map_err(|error| format!("invalid arguments: {error}"))?;
        if args.up_to_sequence < 0 {
            return Err("`up_to_sequence` must be greater than or equal to zero".into());
        }
        let ack = self
            .consumers
            .ack(&args.consumer, args.up_to_sequence)
            .map_err(|error| error.to_string())?;
        serde_json::to_value(ack).map_err(|error| error.to_string())
    }
}

fn parse_cursor(cursor: &str) -> Result<i64, String> {
    cursor
        .strip_prefix("seq_")
        .unwrap_or(cursor)
        .parse::<i64>()
        .map_err(|_| format!("invalid cursor `{cursor}`"))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ListEventsArgs {
    #[serde(default)]
    since: Option<String>,
    #[serde(default)]
    until: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    after: Option<i64>,
    #[serde(default)]
    cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetEventArgs {
    #[serde(alias = "eventId")]
    event_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetT3RunArgs {
    #[serde(alias = "runId")]
    run_id: String,
    #[serde(default, alias = "environmentId")]
    environment_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetT3ApprovalsArgs {
    #[serde(default, alias = "environmentId")]
    environment_id: Option<String>,
    #[serde(default, alias = "projectId")]
    project_id: Option<String>,
    #[serde(default, alias = "threadId")]
    thread_id: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetGitHubStatusArgs {
    #[serde(default)]
    repository: Option<String>,
    #[serde(default, alias = "pullNumber")]
    pull_number: Option<i64>,
    #[serde(default)]
    branch: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AckEventsArgs {
    #[serde(alias = "eventIds")]
    event_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConsumerArgs {
    consumer: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PollConsumerArgs {
    consumer: String,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AckConsumerArgs {
    consumer: String,
    #[serde(alias = "upToSequence")]
    up_to_sequence: i64,
}

/// Render an event for diagnostics.
#[allow(dead_code)]
pub fn summarize(event: &Event) -> String {
    format!("{} {} {}", event.id, event.kind, event.occurred_at)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_definitions_are_stable() {
        let tools = definitions();
        let names: Vec<_> = tools.iter().map(|tool| tool.name.to_string()).collect();
        assert_eq!(
            names,
            vec![
                "list_events",
                "get_event",
                "get_t3_run",
                "get_t3_approvals",
                "get_github_status",
                "ack_events",
                "probe_consumer",
                "poll_consumer_events",
                "ack_consumer_events",
            ]
        );
        assert_eq!(get("list_events").unwrap().name, "list_events");
        assert!(get("missing").is_none());
    }

    #[tokio::test]
    async fn list_and_get_round_trip() {
        let repo = Arc::new(Repository::open_in_memory().unwrap());
        repo.ingest_event(crate::store::NewEvent {
            id: Some("evt_tool".into()),
            source: None,
            kind: "t3.run.failed".into(),
            payload: json!({"environment_id": "linux-main"}),
            occurred_at: Some("2026-11-16T01:00:00Z".into()),
        })
        .unwrap();

        let service = ToolService::new(repo.clone());
        let listed = service
            .call(
                "local",
                CallToolRequestParams::new("list_events")
                    .with_arguments(json!({"severity": "high"}).as_object().unwrap().clone()),
            )
            .await
            .unwrap();
        let CallToolResponse::Complete(listed) = listed else {
            panic!("expected a complete tool response");
        };
        let value = listed.into_typed::<Value>().unwrap();
        assert_eq!(value["events"].as_array().unwrap().len(), 1);

        let fetched = service
            .call(
                "local",
                CallToolRequestParams::new("get_event")
                    .with_arguments(json!({"event_id": "evt_tool"}).as_object().unwrap().clone()),
            )
            .await
            .unwrap();
        let CallToolResponse::Complete(fetched) = fetched else {
            panic!("expected a complete tool response");
        };
        let value = fetched.into_typed::<Value>().unwrap();
        assert_eq!(value["event"]["id"], "evt_tool");
    }

    async fn call_list(service: &ToolService, arguments: Value) -> CallToolResponse {
        service
            .call(
                "local",
                CallToolRequestParams::new("list_events")
                    .with_arguments(arguments.as_object().unwrap().clone()),
            )
            .await
            .unwrap()
    }

    fn tool_text(response: &CallToolResponse) -> String {
        let CallToolResponse::Complete(result) = response else {
            panic!("expected a complete tool response");
        };
        result
            .content
            .iter()
            .filter_map(|content| content.as_text())
            .map(|text| text.text.clone())
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn seeded_service() -> ToolService {
        let repo = Arc::new(Repository::open_in_memory().unwrap());
        repo.ingest_event(crate::store::NewEvent {
            id: Some("evt_failed".into()),
            source: None,
            kind: "t3.run.failed".into(),
            payload: json!({
                "environment_id": "linux-main",
                "project_id": "lnako",
                "thread_id": "thread-42",
                "run_id": "run-1",
                "summary": "failed",
                "error": "boom"
            }),
            occurred_at: Some("2026-11-16T01:00:00Z".into()),
        })
        .unwrap();
        repo.ingest_event(crate::store::NewEvent {
            id: Some("evt_merged".into()),
            source: None,
            kind: "github.pr.merged".into(),
            payload: json!({
                "repository": "o/r",
                "pull_number": 7,
                "title": "Fix parser",
                "url": "https://github.com/o/r/pull/7"
            }),
            occurred_at: Some("2026-11-16T01:00:01Z".into()),
        })
        .unwrap();
        repo.ingest_event(crate::store::NewEvent {
            id: Some("evt_completed".into()),
            source: None,
            kind: "t3.run.completed".into(),
            payload: json!({
                "environment_id": "linux-main",
                "project_id": "lnako",
                "thread_id": "thread-42",
                "run_id": "run-2",
                "summary": "done"
            }),
            occurred_at: Some("2026-11-16T01:00:02Z".into()),
        })
        .unwrap();
        ToolService::new(repo)
    }

    #[tokio::test]
    async fn after_fetches_differentially_and_combines_with_filters() {
        let service = seeded_service();

        let page = call_list(&service, json!({"after": 1, "limit": 1})).await;
        let CallToolResponse::Complete(result) = page else {
            panic!("expected a complete tool response");
        };
        assert_eq!(result.is_error, Some(false));
        let value = result.into_typed::<Value>().unwrap();
        let events = value["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["sequence"], 2);
        assert_eq!(value["nextCursor"], "seq_2");

        let by_source = call_list(&service, json!({"after": 1, "source": "github"})).await;
        let CallToolResponse::Complete(by_source) = by_source else {
            panic!("expected a complete tool response");
        };
        let value = by_source.into_typed::<Value>().unwrap();
        let events = value["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["id"], "evt_merged");

        let by_severity = call_list(&service, json!({"after": 1, "severity": "normal"})).await;
        let CallToolResponse::Complete(by_severity) = by_severity else {
            panic!("expected a complete tool response");
        };
        let value = by_severity.into_typed::<Value>().unwrap();
        let events = value["events"].as_array().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["id"], "evt_merged");
        assert_eq!(events[1]["id"], "evt_completed");
    }

    #[tokio::test]
    async fn after_rejects_cursor_together_and_negative_values() {
        let service = seeded_service();

        let both = call_list(&service, json!({"after": 1, "cursor": "seq_1"})).await;
        let CallToolResponse::Complete(result) = &both else {
            panic!("expected a complete tool response");
        };
        assert_eq!(result.is_error, Some(true));
        assert!(
            tool_text(&both).contains("not both"),
            "{}",
            tool_text(&both)
        );

        let negative = call_list(&service, json!({"after": -1})).await;
        let CallToolResponse::Complete(result) = &negative else {
            panic!("expected a complete tool response");
        };
        assert_eq!(result.is_error, Some(true));
        assert!(
            tool_text(&negative).contains("after"),
            "{}",
            tool_text(&negative)
        );
    }
}
