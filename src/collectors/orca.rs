//! Read-only observations from the Orca 1.4.273 CLI.

use std::{path::PathBuf, process::Stdio, time::Duration};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, de::DeserializeOwned};
use tokio::{io::AsyncReadExt, process::Command, time::timeout};

use crate::{
    config::OrcaCollectorConfig,
    edge_protocol::{OrcaEdgeEvent, OrcaEventKind, valid_edge_token},
    store::Repository,
};

const MAX_CLI_OUTPUT_BYTES: usize = 32 * 1024 * 1024;
const SESSION_PREFIX: &str = "orca_session_id:";

fn local_session_id(value: &str) -> Option<&str> {
    let id = value.strip_prefix(SESSION_PREFIX).unwrap_or(value);
    valid_edge_token(id).then_some(id)
}

pub(crate) struct OrcaSource {
    executable: PathBuf,
    timeout: Duration,
    edge_secret_env: String,
}

impl OrcaSource {
    pub(crate) fn new(config: &OrcaCollectorConfig, edge_secret_env: &str) -> Self {
        Self {
            executable: config.cli_path.clone(),
            timeout: Duration::from_secs(config.cli_timeout_secs),
            edge_secret_env: edge_secret_env.into(),
        }
    }

    pub(crate) async fn collect(&self, repo: &Repository, environment_id: &str) -> Result<usize> {
        let started_at = chrono::Utc::now().timestamp_millis();
        let page: WorktreePage = self
            .read(&["worktree", "ps", "--limit", "2000", "--agent-wait"])
            .await
            .context("reading Orca workspace status")?;
        ensure!(!page.truncated, "Orca workspace status was truncated");
        ensure!(
            page.host_scope.host_ids.iter().any(|host| host == "local"),
            "Orca workspace status did not cover the local host"
        );
        let baseline = repo.orca_edge_baseline(environment_id, started_at)?;
        let mut queued = 0;
        for workspace in page
            .worktrees
            .iter()
            .filter(|row| row.host_id.as_deref() == Some("local"))
        {
            for agent in &workspace.agents {
                let Some(session_id) = agent.session_id.as_deref().and_then(local_session_id)
                else {
                    continue;
                };
                for candidate in agent.observations() {
                    if candidate.at < baseline {
                        continue;
                    }
                    let event = OrcaEdgeEvent {
                        environment_id: environment_id.into(),
                        session_id: format!("{SESSION_PREFIX}{session_id}"),
                        project_id: workspace.repo_id.clone().filter(|id| valid_edge_token(id)),
                        kind: candidate.kind,
                        occurred_at_ms: candidate.at,
                    };
                    event.validate().map_err(anyhow::Error::msg)?;
                    if candidate.verify_reply {
                        if repo.orca_edge_has_event(&event.event_id())? {
                            continue;
                        }
                        match self.has_terminal_reply(&event.session_id).await {
                            Ok(true) => {}
                            Ok(false) => continue,
                            Err(error) => {
                                tracing::debug!(%error, "could not confirm Orca terminal reply");
                                continue;
                            }
                        }
                    }
                    queued += usize::from(repo.queue_orca_edge_event(&event)?);
                }
            }
        }
        Ok(queued)
    }

    async fn has_terminal_reply(&self, session_id: &str) -> Result<bool> {
        let reply: ReadResult = self
            .read(&["agent", "read", session_id, "--limit", "5"])
            .await?;
        Ok(
            local_session_id(&reply.session_id) == local_session_id(session_id)
                && reply.source == "transcript"
                && reply.state.as_deref() == Some("done"),
        )
    }

    async fn read<T: DeserializeOwned>(&self, args: &[&str]) -> Result<T> {
        timeout(self.timeout, async {
            let mut child = Command::new(&self.executable)
                .args(args)
                .args(["--environment", "local", "--json"])
                .env_remove("ORCA_ENVIRONMENT")
                .env_remove("ORCA_PAIRING_CODE")
                .env_remove("ORCA_REMOTE_PAIRING")
                .env_remove(&self.edge_secret_env)
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .stdout(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .context("starting the Orca CLI")?;
            let mut output = Vec::new();
            child
                .stdout
                .take()
                .expect("piped stdout")
                .take((MAX_CLI_OUTPUT_BYTES + 1) as u64)
                .read_to_end(&mut output)
                .await
                .context("reading the Orca CLI response")?;
            ensure!(
                output.len() <= MAX_CLI_OUTPUT_BYTES,
                "Orca CLI output exceeded the size limit"
            );
            let status = child.wait().await.context("waiting for the Orca CLI")?;
            ensure!(status.success(), "Orca CLI exited with {status}");
            // stdout can include conversations; keep CLI and JSON error text out of logs.
            let reply: CliReply<T> = serde_json::from_slice(&output).map_err(|error| {
                anyhow::anyhow!(
                    "invalid Orca CLI JSON at {}:{}",
                    error.line(),
                    error.column()
                )
            })?;
            ensure!(reply.ok, "Orca CLI did not return a successful result");
            reply
                .result
                .context("Orca CLI response is missing its result")
        })
        .await
        .context("Orca CLI timed out")?
    }
}

#[derive(Deserialize)]
struct CliReply<T> {
    ok: bool,
    result: Option<T>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WorktreePage {
    worktrees: Vec<Worktree>,
    host_scope: HostScope,
    truncated: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HostScope {
    host_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Worktree {
    host_id: Option<String>,
    repo_id: Option<String>,
    agents: Vec<Agent>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Agent {
    #[serde(rename = "orcaSessionId")]
    session_id: Option<String>,
    address: Option<String>,
    state: String,
    state_started_at: i64,
    interrupted: bool,
    main_agent: Option<MainAgent>,
    agent_wait: Option<AgentWait>,
    last_assistant_message: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MainAgent {
    state: String,
    state_started_at: i64,
    outcome: Option<String>,
}

#[derive(Deserialize)]
struct AgentWait {
    source: String,
    reason: Option<String>,
    since: Option<i64>,
}

#[derive(Deserialize)]
struct ReadResult {
    #[serde(rename = "orcaSessionId")]
    session_id: String,
    source: String,
    state: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct Observation {
    kind: OrcaEventKind,
    at: i64,
    verify_reply: bool,
}

impl Agent {
    fn observations(&self) -> impl Iterator<Item = Observation> {
        let chat = self
            .address
            .as_deref()
            .is_some_and(|addr| addr.starts_with(SESSION_PREFIX));
        let wait = self.interactive_wait_at(chat).map(|at| Observation {
            kind: OrcaEventKind::ApprovalRequired,
            at,
            verify_reply: false,
        });
        [wait, self.finished_turn(chat)]
            .into_iter()
            .flatten()
            .filter(|observation| observation.at > 0)
    }

    fn interactive_wait_at(&self, chat: bool) -> Option<i64> {
        let waiting = |state: &str| matches!(state, "waiting" | "blocked");
        if chat {
            return self
                .main_agent
                .as_ref()
                .filter(|lead| waiting(&lead.state))
                .map(|lead| lead.state_started_at);
        }
        let wait = self.agent_wait.as_ref()?;
        match wait.reason.as_deref() {
            Some(
                "agent-approval-prompt" | "agent-interactive-prompt" | "codex-interactive-prompt",
            ) => wait
                .since
                .or_else(|| waiting(&self.state).then_some(self.state_started_at)),
            None if matches!(wait.source.as_str(), "hook" | "title") && waiting(&self.state) => {
                Some(self.state_started_at)
            }
            _ => None,
        }
    }

    fn finished_turn(&self, chat: bool) -> Option<Observation> {
        let lead = self.main_agent.as_ref();
        if lead.map_or(self.state.as_str(), |lead| lead.state.as_str()) != "done" {
            return None;
        }
        let (kind, verify_reply) = match lead.and_then(|lead| lead.outcome.as_deref()) {
            Some("failure" | "interruption") => (OrcaEventKind::Failed, false),
            Some("success") if self.state == "done" => (OrcaEventKind::Completed, false),
            None if !chat
                && self.state == "done"
                && !self.interrupted
                && self
                    .last_assistant_message
                    .as_deref()
                    .is_some_and(|reply| !reply.trim().is_empty()) =>
            {
                (OrcaEventKind::Completed, true)
            }
            _ => return None,
        };
        Some(Observation {
            kind,
            at: lead.map_or(self.state_started_at, |lead| lead.state_started_at),
            verify_reply,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn agent_row(state: &str, outcome: Option<&str>) -> Value {
        json!({
            "orcaSessionId": "test-session",
            "address": "term_test",
            "state": state,
            "stateStartedAt": 2000,
            "interrupted": false,
            "mainAgent": {"state": state, "stateStartedAt": 1800, "outcome": outcome},
            "lastAssistantMessage": "a private test reply",
        })
    }

    fn observations(row: Value) -> Vec<Observation> {
        serde_json::from_value::<Agent>(row)
            .unwrap()
            .observations()
            .collect()
    }

    #[test]
    fn only_confirmed_or_verifiable_turn_outcomes_are_candidates() {
        use OrcaEventKind::{Completed, Failed};

        for (outcome, expected) in [
            ("success", Some(Completed)),
            ("failure", Some(Failed)),
            ("interruption", Some(Failed)),
            ("cancellation", None),
            ("superseded", None),
            ("unconfirmed", None),
        ] {
            assert_eq!(
                observations(agent_row("done", Some(outcome))),
                expected
                    .into_iter()
                    .map(|kind| Observation {
                        kind,
                        at: 1800,
                        verify_reply: false
                    })
                    .collect::<Vec<_>>()
            );
        }
        let mut row = agent_row("done", None);
        assert_eq!(
            observations(row.clone()),
            [Observation {
                kind: Completed,
                at: 1800,
                verify_reply: true
            }]
        );
        row["interrupted"] = json!(true);
        assert!(observations(row).is_empty());

        let mut row = agent_row("working", None);
        row["mainAgent"]["state"] = json!("done");
        row["mainAgent"]["outcome"] = json!("success");
        assert!(
            observations(row).is_empty(),
            "the worktree still shows active child work"
        );
    }

    #[test]
    fn approval_observations_require_prompt_evidence() {
        let mut row = agent_row("waiting", None);
        assert!(observations(row.clone()).is_empty());
        row["agentWait"] =
            json!({"source":"prompt-text","reason":"agent-sign-in-prompt","since":1700});
        assert!(observations(row.clone()).is_empty());
        row["agentWait"]["reason"] = json!("agent-approval-prompt");
        assert_eq!(
            observations(row.clone()),
            [Observation {
                kind: OrcaEventKind::ApprovalRequired,
                at: 1700,
                verify_reply: false
            }]
        );
        row["agentWait"] = Value::Null;
        row["address"] = json!("orca_session_id:test-session");
        assert_eq!(
            observations(row),
            [Observation {
                kind: OrcaEventKind::ApprovalRequired,
                at: 1800,
                verify_reply: false
            }]
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn local_snapshots_and_replies_queue_only_new_events_across_restarts() {
        use std::{fs, os::unix::fs::PermissionsExt};

        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("orca");
        fs::write(
            &executable,
            r#"#!/bin/sh
cd "$(dirname "$0")" || exit 1
case "$*" in
  'worktree ps --limit 2000 --agent-wait --environment local --json') cat worktrees.json ;;
  'agent read orca_session_id:test-session --limit 5 --environment local --json') cat reply.json ;;
  *) exit 1 ;;
esac
"#,
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let source = OrcaSource::new(
            &OrcaCollectorConfig {
                cli_path: executable,
                ..Default::default()
            },
            "ORCA_TEST_UNSET_SECRET",
        );
        let write_page = |row: Value, truncated| {
            fs::write(dir.path().join("worktrees.json"), json!({
                "ok": true, "result": {
                    "hostScope": {"hostIds": ["local", "ssh:other"]},
                    "truncated": truncated,
                    "worktrees": [
                        {"hostId":"ssh:other", "agents":[{
                            "orcaSessionId":"remote", "state":"done", "stateStartedAt":2000,
                            "interrupted":false,
                            "mainAgent":{"state":"done","stateStartedAt":4102444800000_i64,"outcome":"failure"}
                        }]},
                        {"hostId":"local","repoId":"project-1","agents":[row]}
                    ]
                }
            }).to_string()).unwrap();
        };
        let write_reply = |state| {
            fs::write(
                dir.path().join("reply.json"),
                json!({
                    "ok": true, "result": {
                        "source":"transcript","orcaSessionId":"test-session","state":state,
                        "entries":[{"kind":"message","text":"a private test reply"}]
                    }
                })
                .to_string(),
            )
            .unwrap();
        };
        let path = dir.path().join("outbox.db");
        let repo = Repository::open(&path).unwrap();
        write_page(agent_row("done", Some("success")), true);
        assert!(source.collect(&repo, "mini").await.is_err());
        write_page(agent_row("done", Some("success")), false);
        assert_eq!(source.collect(&repo, "mini").await.unwrap(), 0);

        let mut row = agent_row("done", None);
        row["mainAgent"]["stateStartedAt"] = json!(chrono::Utc::now().timestamp_millis() + 1000);
        write_page(row, false);
        write_reply("working");
        assert_eq!(source.collect(&repo, "mini").await.unwrap(), 0);
        write_reply("done");
        assert_eq!(source.collect(&repo, "mini").await.unwrap(), 1);
        let (id, body) = repo.next_orca_edge_event("mini").unwrap().unwrap();
        let event: OrcaEdgeEvent = serde_json::from_slice(&body).unwrap();
        assert_eq!(event.session_id, "orca_session_id:test-session");
        assert_eq!(event.project_id.as_deref(), Some("project-1"));
        assert_eq!(event.kind, OrcaEventKind::Completed);
        assert!(
            !String::from_utf8(body)
                .unwrap()
                .contains("private test reply")
        );
        drop(repo);

        let repo = Repository::open(&path).unwrap();
        assert_eq!(repo.next_orca_edge_event("mini").unwrap().unwrap().0, id);
        assert_eq!(source.collect(&repo, "mini").await.unwrap(), 0);
        repo.acknowledge_orca_edge_event(&id).unwrap();
        assert_eq!(source.collect(&repo, "mini").await.unwrap(), 0);
        assert!(repo.next_orca_edge_event("mini").unwrap().is_none());
    }
}
