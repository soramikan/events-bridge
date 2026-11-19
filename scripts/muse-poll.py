#!/usr/bin/env python3
"""Run one Muse polling tick. See docs/CLAUDE-CONSUMER.md."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import urllib.error
import urllib.request


def tick(db, base_url, token, handler):
    def request(path, body=None):
        headers = {"Authorization": f"Bearer {token}"}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        request = urllib.request.Request(base_url + path, data=data, headers=headers)
        with http.open(request, timeout=10) as response:
            return json.load(response)

    http = urllib.request.build_opener(urllib.request.ProxyHandler({}), RejectRedirect())
    db.execute("CREATE TABLE IF NOT EXISTS pending (slot INTEGER PRIMARY KEY, page TEXT)")
    db.execute("CREATE TABLE IF NOT EXISTS processed (id TEXT PRIMARY KEY)")
    probe = request("/probe")
    pending = db.execute("SELECT page FROM pending WHERE slot = 1").fetchone()
    if pending:
        page = json.loads(pending[0])
    elif probe["hasUpdates"] or probe["unreadCount"] > 0:
        page = request("/poll?limit=50")
        if page["nextCursorSequence"] <= page["cursorSequence"]:
            return
        with db:
            db.execute("INSERT INTO pending VALUES (1, ?)", (json.dumps(page),))
    else:
        return

    def deliver(kind, item, key):
        if db.execute("SELECT 1 FROM processed WHERE id = ?", (key,)).fetchone():
            return
        child_env = os.environ.copy()
        child_env.pop("EVENTS_BRIDGE_TOKEN", None)
        subprocess.run(
            handler, input=json.dumps({"kind": kind, "id": key, "item": item}),
            text=True, check=True, timeout=40, env=child_env,
        )
        with db:
            db.execute("INSERT INTO processed VALUES (?)", (key,))

    for event in page["events"]:
        deliver("immediate", event, "event:" + event["eventId"])
    for digest in page["digests"]:
        key = ["digest", digest["eventIds"]]
        if digest["eventIdsTruncated"]:
            key.extend([digest["windowStart"], digest["maxSequence"]])
        deliver("digest", digest, json.dumps(key, separators=(",", ":")))
    sequence = page["nextCursorSequence"]
    if request("/ack", {"upToSequence": sequence})["cursorSequence"] < sequence:
        raise ValueError("ack cursor did not advance")
    with db:
        db.execute("DELETE FROM pending WHERE slot = 1")


class RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("handler", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.handler[:1] == ["--"]:
        args.handler.pop(0)
    if not args.handler:
        parser.error("supply a handler executable after --")
    token = os.environ.get("EVENTS_BRIDGE_TOKEN")
    if not token:
        parser.error("EVENTS_BRIDGE_TOKEN is required")
    base = os.environ.get("EVENTS_BRIDGE_MUSE_URL", "http://100.85.211.2:8788")
    os.umask(0o077)
    args.state_dir.mkdir(parents=True, exist_ok=True)
    with (args.state_dir / "poll.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0
        with sqlite3.connect(args.state_dir / "poll.sqlite") as db:
            tick(db, base.rstrip("/") + "/consumers/muse", token, args.handler)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except urllib.error.HTTPError as error:
        sys.exit(f"Muse poll failed: HTTP {error.code}")
    except (OSError, ValueError, KeyError, sqlite3.Error, subprocess.SubprocessError) as error:
        sys.exit(f"Muse poll failed: {type(error).__name__}")
