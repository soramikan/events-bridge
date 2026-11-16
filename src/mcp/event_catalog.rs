//! The Phase 1 event catalog.
//!
//! `events/list` returns these descriptors, and event ingestion validates
//! payloads against them. Schemas are hand-written JSON for two reasons: the
//! protocol requires a concrete JSON Schema on the wire, and keeping them
//! literal makes the advertised contract easy to review.

use std::sync::LazyLock;

use serde_json::{Value, json};

/// Event priority advertised in `events/list` metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Events that usually need prompt attention.
    High,
    /// Events that are normally batched.
    Normal,
}

impl Severity {
    /// Lowercase wire representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Normal => "normal",
        }
    }
}

/// One advertised event type.
#[derive(Debug, Clone)]
pub struct EventDefinition {
    /// Event name used by `events/subscribe`.
    pub name: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// Priority hint.
    pub severity: Severity,
    /// Schema of subscription filter arguments.
    pub input_schema: Value,
    /// Schema of the delivered `data` object.
    pub payload_schema: Value,
}

impl EventDefinition {
    /// Wire descriptor for `events/list`.
    pub fn descriptor(&self) -> Value {
        json!({
            "name": self.name,
            "description": self.description,
            "delivery": ["webhook", "poll"],
            "inputSchema": self.input_schema,
            "payloadSchema": self.payload_schema,
        })
    }
}

fn t3_filter_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "environment_id": {"type": "string"},
            "project_id": {"type": "string"}
        },
        "required": ["environment_id"],
        "additionalProperties": false
    })
}

/// All Phase 1 event definitions, in the order advertised by `events/list`.
pub static EVENTS: LazyLock<Vec<EventDefinition>> = LazyLock::new(|| {
    vec![
        EventDefinition {
            name: "t3.run.completed",
            description: "A T3 Code coding-agent run has completed.",
            severity: Severity::Normal,
            input_schema: t3_filter_schema(),
            payload_schema: json!({
                "type": "object",
                "properties": {
                    "environment_id": {"type": "string"},
                    "project_id": {"type": "string"},
                    "thread_id": {"type": "string"},
                    "run_id": {"type": "string"},
                    "summary": {"type": "string"},
                    "url": {"type": "string"},
                    "title": {"type": "string"},
                    "project_name": {"type": "string"},
                    "thread_title": {"type": "string"},
                    "severity": {"type": "string", "enum": ["high", "normal"]},
                    "requires_action": {"type": "boolean"}
                },
                "required": [
                    "environment_id", "project_id", "thread_id", "run_id", "summary"
                ],
                "additionalProperties": false
            }),
        },
        EventDefinition {
            name: "t3.run.failed",
            description: "A T3 Code coding-agent run has failed.",
            severity: Severity::High,
            input_schema: t3_filter_schema(),
            payload_schema: json!({
                "type": "object",
                "properties": {
                    "environment_id": {"type": "string"},
                    "project_id": {"type": "string"},
                    "thread_id": {"type": "string"},
                    "run_id": {"type": "string"},
                    "summary": {"type": "string"},
                    "error": {"type": "string"},
                    "url": {"type": "string"},
                    "title": {"type": "string"},
                    "project_name": {"type": "string"},
                    "thread_title": {"type": "string"},
                    "severity": {"type": "string", "enum": ["high", "normal"]},
                    "requires_action": {"type": "boolean"},
                    "error_excerpt": {"type": "string"}
                },
                "required": [
                    "environment_id", "project_id", "thread_id", "run_id",
                    "summary", "error"
                ],
                "additionalProperties": false
            }),
        },
        EventDefinition {
            name: "t3.approval.required",
            description: "A T3 Code run is waiting for user approval or input.",
            severity: Severity::High,
            input_schema: t3_filter_schema(),
            payload_schema: json!({
                "type": "object",
                "properties": {
                    "environment_id": {"type": "string"},
                    "project_id": {"type": "string"},
                    "thread_id": {"type": "string"},
                    "run_id": {"type": "string"},
                    "approval_id": {"type": "string"},
                    "summary": {"type": "string"},
                    "url": {"type": "string"},
                    "title": {"type": "string"},
                    "project_name": {"type": "string"},
                    "thread_title": {"type": "string"},
                    "severity": {"type": "string", "enum": ["high", "normal"]},
                    "requires_action": {"type": "boolean"}
                },
                "required": [
                    "environment_id", "project_id", "thread_id", "run_id",
                    "approval_id", "summary"
                ],
                "additionalProperties": false
            }),
        },
        EventDefinition {
            name: "github.workflow.failed",
            description: "A GitHub Actions workflow run has failed.",
            severity: Severity::High,
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repository": {"type": "string"},
                    "workflow": {"type": "string"},
                    "branch": {"type": "string"}
                },
                "required": ["repository"],
                "additionalProperties": false
            }),
            payload_schema: json!({
                "type": "object",
                "properties": {
                    "repository": {"type": "string"},
                    "workflow": {"type": "string"},
                    "run_id": {"type": "string"},
                    "conclusion": {"type": "string"},
                    "branch": {"type": "string"},
                    "summary": {"type": "string"},
                    "url": {"type": "string"},
                    "title": {"type": "string"},
                    "severity": {"type": "string", "enum": ["high", "normal"]},
                    "requires_action": {"type": "boolean"},
                    "error_excerpt": {"type": "string"}
                },
                "required": ["repository", "workflow", "run_id", "conclusion", "url"],
                "additionalProperties": false
            }),
        },
        EventDefinition {
            name: "github.review.requested",
            description: "A pull request has requested a review.",
            severity: Severity::Normal,
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repository": {"type": "string"},
                    "reviewer": {"type": "string"}
                },
                "required": ["repository"],
                "additionalProperties": false
            }),
            payload_schema: json!({
                "type": "object",
                "properties": {
                    "repository": {"type": "string"},
                    "pull_number": {"type": "integer"},
                    "title": {"type": "string"},
                    "author": {"type": "string"},
                    "reviewer": {"type": "string"},
                    "summary": {"type": "string"},
                    "url": {"type": "string"},
                    "severity": {"type": "string", "enum": ["high", "normal"]},
                    "requires_action": {"type": "boolean"}
                },
                "required": ["repository", "pull_number", "title", "url"],
                "additionalProperties": false
            }),
        },
        EventDefinition {
            name: "github.pr.merged",
            description: "A GitHub pull request has been merged.",
            severity: Severity::Normal,
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repository": {"type": "string"},
                    "base_branch": {"type": "string"}
                },
                "required": ["repository"],
                "additionalProperties": false
            }),
            payload_schema: json!({
                "type": "object",
                "properties": {
                    "repository": {"type": "string"},
                    "pull_number": {"type": "integer"},
                    "title": {"type": "string"},
                    "author": {"type": "string"},
                    "merged_by": {"type": "string"},
                    "base_branch": {"type": "string"},
                    "summary": {"type": "string"},
                    "url": {"type": "string"},
                    "severity": {"type": "string", "enum": ["high", "normal"]},
                    "requires_action": {"type": "boolean"}
                },
                "required": ["repository", "pull_number", "title", "url"],
                "additionalProperties": false
            }),
        },
    ]
});

/// Look up an event definition by name.
pub fn get(name: &str) -> Option<&'static EventDefinition> {
    EVENTS.iter().find(|event| event.name == name)
}

/// Build the `events/list` result.
pub fn list_result() -> Value {
    json!({
        "events": EVENTS.iter().map(EventDefinition::descriptor).collect::<Vec<_>>()
    })
}

/// Validate subscription arguments against an event's `inputSchema`.
pub fn validate_arguments(definition: &EventDefinition, arguments: &Value) -> Result<(), String> {
    validate_object(&definition.input_schema, arguments)
        .map_err(|errors| format!("invalid subscription arguments: {}", errors.join("; ")))
}

/// Validate an event payload against its `payloadSchema`.
pub fn validate_payload(name: &str, payload: &Value) -> Result<(), String> {
    let definition = get(name).ok_or_else(|| format!("unknown event name `{name}`"))?;
    validate_object(&definition.payload_schema, payload)
        .map_err(|errors| format!("invalid `{name}` payload: {}", errors.join("; ")))
}

/// Minimal JSON Schema subset used by the catalog: object type, required
/// properties, primitive property types, and `additionalProperties: false`.
fn validate_object(schema: &Value, value: &Value) -> Result<(), Vec<String>> {
    let Some(object) = value.as_object() else {
        return Err(vec!["expected a JSON object".to_string()]);
    };

    let mut errors = Vec::new();
    let properties = schema.get("properties").and_then(Value::as_object);

    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        for name in required.iter().filter_map(Value::as_str) {
            if !object.contains_key(name) {
                errors.push(format!("missing required property `{name}`"));
            }
        }
    }

    if schema.get("additionalProperties") == Some(&Value::Bool(false))
        && let Some(properties) = properties
    {
        for key in object.keys() {
            if !properties.contains_key(key) {
                errors.push(format!("unexpected property `{key}`"));
            }
        }
    }

    if let Some(properties) = properties {
        for (key, property_schema) in properties {
            let Some(property_value) = object.get(key) else {
                continue;
            };
            if let Some(expected) = property_schema.get("type").and_then(Value::as_str)
                && !matches_json_type(property_value, expected)
            {
                errors.push(format!("property `{key}` must be of type `{expected}`"));
            }
            if let Some(allowed) = property_schema.get("enum").and_then(Value::as_array)
                && !allowed.contains(property_value)
            {
                let allowed = allowed
                    .iter()
                    .map(|value| value.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                errors.push(format!("property `{key}` must be one of {allowed}"));
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn matches_json_type(value: &Value, expected: &str) -> bool {
    match expected {
        "string" => value.is_string(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "null" => value.is_null(),
        // Unknown schema types are not enforced in Phase 1.
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn catalog_contains_the_six_phase_one_events() {
        let names: Vec<_> = EVENTS.iter().map(|event| event.name).collect();
        assert_eq!(
            names,
            vec![
                "t3.run.completed",
                "t3.run.failed",
                "t3.approval.required",
                "github.workflow.failed",
                "github.review.requested",
                "github.pr.merged",
            ]
        );
        for event in EVENTS.iter() {
            assert_eq!(event.descriptor()["delivery"], json!(["webhook", "poll"]));
            assert!(event.input_schema.is_object());
            assert!(event.payload_schema.is_object());
        }
    }

    #[test]
    fn arguments_are_validated_against_the_filter_schema() {
        let definition = get("t3.run.completed").unwrap();
        assert!(validate_arguments(definition, &json!({"environment_id": "linux-main"})).is_ok());
        assert!(validate_arguments(definition, &json!({})).is_err());
        assert!(
            validate_arguments(definition, &json!({"environment_id": 1})).is_err(),
            "environment_id must be a string"
        );
        assert!(
            validate_arguments(
                definition,
                &json!({"environment_id": "x", "surprise": true})
            )
            .is_err(),
            "unknown properties are rejected"
        );
    }

    #[test]
    fn payload_validation_requires_declared_fields() {
        assert!(
            validate_payload(
                "t3.run.completed",
                &json!({
                    "environment_id": "linux-main",
                    "project_id": "lnako",
                    "thread_id": "thread-42",
                    "run_id": "run-102",
                    "summary": "done"
                })
            )
            .is_ok()
        );
        assert!(validate_payload("t3.run.completed", &json!({"environment_id": "x"})).is_err());
        assert!(validate_payload("unknown.event", &json!({})).is_err());
    }

    #[test]
    fn optional_enrichment_fields_are_advertised_but_never_required() {
        let completed = get("t3.run.completed").unwrap();
        let failed = get("t3.run.failed").unwrap();
        let approval = get("t3.approval.required").unwrap();
        let workflow = get("github.workflow.failed").unwrap();
        let review = get("github.review.requested").unwrap();
        let merged = get("github.pr.merged").unwrap();

        for event in [completed, failed, approval, workflow, review, merged] {
            let properties = event.payload_schema["properties"].as_object().unwrap();
            assert!(properties.contains_key("severity"), "{}", event.name);
            assert!(properties.contains_key("requires_action"), "{}", event.name);
            let required = event.payload_schema["required"].as_array().unwrap();
            for optional in ["severity", "requires_action"] {
                assert!(
                    !required
                        .iter()
                        .any(|value| value.as_str() == Some(optional)),
                    "{} must not require {optional}",
                    event.name
                );
            }
            if !matches!(event.name, "github.review.requested" | "github.pr.merged") {
                assert!(
                    !required.iter().any(|value| value.as_str() == Some("title")),
                    "{} must not require title",
                    event.name
                );
            }
            assert!(
                !required
                    .iter()
                    .any(|value| value.as_str() == Some("error_excerpt")),
                "{} must not require error_excerpt",
                event.name
            );
        }
        let completed_properties = completed.payload_schema["properties"].as_object().unwrap();
        assert!(completed_properties.contains_key("title"));
        assert!(completed_properties.contains_key("project_name"));
        assert!(completed_properties.contains_key("thread_title"));
        let failed_properties = failed.payload_schema["properties"].as_object().unwrap();
        assert!(failed_properties.contains_key("error_excerpt"));
        let workflow_properties = workflow.payload_schema["properties"].as_object().unwrap();
        assert!(workflow_properties.contains_key("title"));
        assert!(workflow_properties.contains_key("error_excerpt"));
    }

    #[test]
    fn severity_enum_values_are_enforced_when_present() {
        let payload = json!({
            "environment_id": "linux-main",
            "project_id": "lnako",
            "thread_id": "thread-42",
            "run_id": "run-102",
            "summary": "done",
            "severity": "urgent"
        });
        let error = validate_payload("t3.run.completed", &payload).unwrap_err();
        assert!(error.contains("severity"), "{error}");

        let mut accepted = payload;
        accepted["severity"] = json!("high");
        assert!(validate_payload("t3.run.completed", &accepted).is_ok());
    }
}
