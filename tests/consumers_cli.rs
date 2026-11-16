//! CLI coverage for the polling consumer commands.
//!
//! The binary is exercised as a subprocess so the tests assert the actual
//! stdout contract: exactly one JSON document and no log lines.

use std::{path::Path, process::Command};

use events_bridge::store::{NewEvent, Repository};
use serde_json::{Value, json};
use tempfile::TempDir;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_events-bridge")
}

fn failed_event() -> NewEvent {
    NewEvent {
        id: Some("evt_cli_failed".into()),
        source: None,
        kind: "t3.run.failed".into(),
        payload: json!({
            "environment_id": "linux-main",
            "project_id": "lnako",
            "thread_id": "thread-42",
            "run_id": "run-102",
            "summary": "failed",
            "error": "boom"
        }),
        occurred_at: Some("2026-11-16T01:00:00.000Z".into()),
    }
}

fn review_event() -> NewEvent {
    NewEvent {
        id: Some("evt_cli_review".into()),
        source: None,
        kind: "github.review.requested".into(),
        payload: json!({
            "repository": "soramikan/events-bridge",
            "pull_number": 7,
            "title": "Review me",
            "url": "https://github.com/soramikan/events-bridge/pull/7"
        }),
        occurred_at: Some("2026-11-16T01:00:01.000Z".into()),
    }
}

fn seed(path: &Path) {
    let repo = Repository::open(path).expect("open seed database");
    repo.ingest_event(failed_event()).unwrap();
    repo.ingest_event(review_event()).unwrap();
}

fn run(args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(binary());
    cmd.env_remove("EVENTS_BRIDGE_CONFIG");
    let _temp = if args.contains(&"--config") {
        None
    } else {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("empty.toml");
        std::fs::write(&config, "").unwrap();
        cmd.arg(args[0]);
        cmd.arg("--config").arg(&config);
        cmd.args(&args[1..]);
        Some(dir)
    };
    if _temp.is_none() {
        cmd.args(args);
    }
    cmd.output().expect("run events-bridge")
}

fn stdout_json(output: &std::process::Output) -> Value {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout is not pure JSON: {error}: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

#[test]
fn cli_probe_poll_and_ack_emit_stdout_json() {
    let temp = TempDir::new().unwrap();
    let db = temp.path().join("events.db");
    seed(&db);
    let db = db.to_str().unwrap();

    let probe = stdout_json(&run(&["poll", "--consumer", "muse", "--db", db, "--probe"]));
    assert_eq!(probe["consumer"], "muse");
    assert_eq!(probe["cursorSequence"], 0);
    assert_eq!(probe["latestSequence"], 2);
    assert_eq!(probe["unreadCount"], 2);
    assert_eq!(probe["hasUpdates"], true);

    let poll = stdout_json(&run(&["poll", "--consumer", "muse", "--db", db]));
    assert_eq!(poll["cursorSequence"], 0);
    assert_eq!(poll["nextCursorSequence"], 2);
    assert_eq!(poll["hasMore"], false);
    assert_eq!(poll["truncated"], false);
    let events = poll["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["eventId"], "evt_cli_failed");
    assert_eq!(events[0]["disposition"], "immediate");
    let digests = poll["digests"].as_array().unwrap();
    assert_eq!(digests.len(), 1);
    assert_eq!(digests[0]["count"], 1);
    assert_eq!(digests[0]["maxSequence"], 2);
    assert_eq!(digests[0]["countsByKind"]["github.review.requested"], 1);
    assert_eq!(digests[0]["eventIds"], json!(["evt_cli_review"]));
    assert_eq!(digests[0]["eventIdsTruncated"], false);

    // Polling is at-least-once: a second poll without an ack repeats events.
    let repeated = stdout_json(&run(&["poll", "--consumer", "muse", "--db", db]));
    assert_eq!(repeated["events"], poll["events"]);
    assert_eq!(repeated["digests"], poll["digests"]);
    assert_eq!(repeated["cursorSequence"], 0);

    let limited = stdout_json(&run(&[
        "poll",
        "--consumer",
        "muse",
        "--db",
        db,
        "--limit",
        "1",
    ]));
    assert_eq!(limited["events"].as_array().unwrap().len(), 1);
    assert_eq!(limited["digests"], json!([]));
    assert_eq!(limited["hasMore"], true);
    assert_eq!(limited["nextCursorSequence"], 1);

    let ack = stdout_json(&run(&[
        "poll",
        "--consumer",
        "muse",
        "--db",
        db,
        "--ack",
        "2",
    ]));
    assert_eq!(ack["previousCursorSequence"], 0);
    assert_eq!(ack["cursorSequence"], 2);
    assert_eq!(ack["advanced"], true);

    let after = stdout_json(&run(&["poll", "--consumer", "muse", "--db", db, "--probe"]));
    assert_eq!(after["unreadCount"], 0);
    assert_eq!(after["hasUpdates"], false);

    let alias = stdout_json(&run(&[
        "ack",
        "--consumer",
        "muse",
        "--up-to",
        "2",
        "--db",
        db,
    ]));
    assert_eq!(alias["advanced"], false);
    assert_eq!(alias["cursorSequence"], 2);
}

#[test]
fn cli_config_file_overrides_the_builtin_muse_profile() {
    let temp = TempDir::new().unwrap();
    let db = temp.path().join("events.db");
    seed(&db);
    let config = temp.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            "[database]\npath = {db:?}\n\
             [consumers.muse]\nmax_events_per_poll = 1\n\
             [consumers.muse.events]\n\"github.review.requested\" = \"off\"\n",
            db = db.to_str().unwrap()
        ),
    )
    .unwrap();
    let config = config.to_str().unwrap();

    let probe = stdout_json(&run(&[
        "poll",
        "--consumer",
        "muse",
        "--config",
        config,
        "--probe",
    ]));
    assert_eq!(probe["latestSequence"], 2);
    assert_eq!(probe["unreadCount"], 1);

    let poll = stdout_json(&run(&["poll", "--consumer", "muse", "--config", config]));
    let events = poll["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["name"], "t3.run.failed");
    assert_eq!(poll["hasMore"], false);
}

#[test]
fn cli_rejects_unknown_consumers_without_writing_stdout() {
    let temp = TempDir::new().unwrap();
    let db = temp.path().join("events.db");
    seed(&db);

    let output = run(&[
        "poll",
        "--consumer",
        "missing",
        "--db",
        db.to_str().unwrap(),
        "--probe",
    ]);
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "stdout must stay empty on errors: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown consumer"), "{stderr}");
}

#[test]
fn cli_rejects_conflicting_poll_flags() {
    let temp = TempDir::new().unwrap();
    let db = temp.path().join("events.db");
    seed(&db);

    let output = run(&[
        "poll",
        "--consumer",
        "muse",
        "--db",
        db.to_str().unwrap(),
        "--probe",
        "--ack",
        "1",
    ]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("cannot be used together"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let ack_with_limit = run(&[
        "poll",
        "--consumer",
        "muse",
        "--db",
        db.to_str().unwrap(),
        "--ack",
        "1",
        "--limit",
        "5",
    ]);
    assert!(!ack_with_limit.status.success());
    assert!(
        String::from_utf8_lossy(&ack_with_limit.stderr).contains("--limit is only valid for polls"),
        "{}",
        String::from_utf8_lossy(&ack_with_limit.stderr)
    );
}

fn seed_digest_backlog(path: &Path) {
    let repo = Repository::open(path).expect("open seed database");
    for index in 0..5 {
        repo.ingest_event(NewEvent {
            id: Some(format!("evt_digest_{index}")),
            source: None,
            kind: "t3.run.completed".into(),
            payload: json!({
                "environment_id": "linux-main",
                "project_id": "lnako",
                "thread_id": "thread-42",
                "run_id": format!("run-{index}"),
                "summary": "done"
            }),
            occurred_at: Some(format!("2026-11-16T01:0{index}:00.000Z")),
        })
        .unwrap();
    }
    repo.ingest_event(NewEvent {
        id: Some("evt_immediate".into()),
        source: None,
        kind: "t3.run.failed".into(),
        payload: json!({
            "environment_id": "linux-main",
            "project_id": "lnako",
            "thread_id": "thread-42",
            "run_id": "run-immediate",
            "summary": "failed",
            "error": "boom"
        }),
        occurred_at: Some("2026-11-16T01:06:00.000Z".into()),
    })
    .unwrap();
}

#[test]
fn cli_summarizes_digest_backlog_and_never_drops_immediate_events() {
    let temp = TempDir::new().unwrap();
    let db = temp.path().join("events.db");
    seed_digest_backlog(&db);
    let config = temp.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            "[database]\npath = {db:?}\n\
             [consumers.muse]\nmax_events_per_poll = 1\n\
             digest_window_secs = 600\nmax_digest_event_ids = 2\n",
            db = db.to_str().unwrap()
        ),
    )
    .unwrap();
    let config = config.to_str().unwrap();

    let poll = stdout_json(&run(&["poll", "--consumer", "muse", "--config", config]));
    assert_eq!(poll["nextCursorSequence"], 6);
    assert_eq!(poll["hasMore"], false);
    assert_eq!(poll["truncated"], true);

    let events = poll["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["eventId"], "evt_immediate");
    assert_eq!(events[0]["disposition"], "immediate");

    let digests = poll["digests"].as_array().unwrap();
    assert_eq!(digests.len(), 1);
    assert_eq!(digests[0]["count"], 5);
    assert_eq!(digests[0]["countsByKind"]["t3.run.completed"], 5);
    assert_eq!(digests[0]["maxSequence"], 5);
    assert_eq!(
        digests[0]["eventIds"],
        json!(["evt_digest_0", "evt_digest_1"])
    );
    assert_eq!(digests[0]["eventIdsTruncated"], true);

    let ack = stdout_json(&run(&[
        "poll",
        "--consumer",
        "muse",
        "--config",
        config,
        "--ack",
        "6",
    ]));
    assert_eq!(ack["previousCursorSequence"], 0);
    assert_eq!(ack["cursorSequence"], 6);

    let probe = stdout_json(&run(&[
        "poll",
        "--consumer",
        "muse",
        "--config",
        config,
        "--probe",
    ]));
    assert_eq!(probe["unreadCount"], 0);
    assert_eq!(probe["hasUpdates"], false);
}
