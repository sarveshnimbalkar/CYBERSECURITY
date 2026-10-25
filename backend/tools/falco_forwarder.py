"""Forward Falco JSON from stdin with a durable SQLite retry spool.

Example: falco --json-output | python backend/tools/falco_forwarder.py
"""
import json
from contextlib import closing
import os
from pathlib import Path
import socket
import sqlite3
import sys
from threading import Event, Thread
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import uuid4


MAX_ALERT_BYTES = 65536


class Spool:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self.connect()) as db, db:
            db.execute("CREATE TABLE IF NOT EXISTS pending (seq INTEGER PRIMARY KEY, payload TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS dead_letter (seq INTEGER PRIMARY KEY, payload TEXT NOT NULL, reason TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)")
            db.execute("CREATE TABLE IF NOT EXISTS counters (id INTEGER PRIMARY KEY CHECK (id = 1), sent INTEGER NOT NULL DEFAULT 0, dropped INTEGER NOT NULL DEFAULT 0, parse_failures INTEGER NOT NULL DEFAULT 0, restarts INTEGER NOT NULL DEFAULT 0)")
            existing = db.execute("SELECT id FROM counters WHERE id = 1").fetchone()
            if existing:
                db.execute("UPDATE counters SET restarts = restarts + 1 WHERE id = 1")
            else:
                db.execute("INSERT INTO counters (id) VALUES (1)")
        if os.name != "nt":
            os.chmod(path, 0o600)

    def connect(self):
        return sqlite3.connect(self.path, timeout=10)

    def enqueue(self, payload: dict):
        payload["event_id"] = str(uuid4())
        with closing(self.connect()) as db, db:
            db.execute("INSERT INTO pending (payload) VALUES (?)", (json.dumps(payload),))

    def oldest(self):
        with closing(self.connect()) as db, db:
            return db.execute("SELECT seq, payload FROM pending ORDER BY seq LIMIT 1").fetchone()

    def mark_sent(self, seq: int):
        with closing(self.connect()) as db, db:
            db.execute("DELETE FROM pending WHERE seq = ?", (seq,))
            db.execute("UPDATE counters SET sent = sent + 1 WHERE id = 1")

    def dead_letter(self, seq: int, payload: str, reason: str):
        with closing(self.connect()) as db, db:
            db.execute("INSERT INTO dead_letter (seq, payload, reason) VALUES (?, ?, ?)", (seq, payload, reason))
            db.execute("DELETE FROM pending WHERE seq = ?", (seq,))
            db.execute("UPDATE counters SET dropped = dropped + 1 WHERE id = 1")

    def increment(self, field: str):
        if field not in {"dropped", "parse_failures"}:
            raise ValueError("Invalid counter")
        with closing(self.connect()) as db, db:
            db.execute(f"UPDATE counters SET {field} = {field} + 1 WHERE id = 1")

    def metrics(self):
        with closing(self.connect()) as db, db:
            sent, dropped, parse_failures, restarts = db.execute("SELECT sent, dropped, parse_failures, restarts FROM counters WHERE id = 1").fetchone()
            depth = db.execute("SELECT COUNT(*) FROM pending").fetchone()[0]
        return {"sent_events": sent, "dropped_events": dropped, "parse_failures": parse_failures, "restarts": restarts, "queue_depth": depth}


def post_json(endpoint: str, api_key: str, payload: dict):
    request = Request(endpoint, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json", "X-API-Key": api_key}, method="POST")
    with urlopen(request, timeout=5) as response:
        response.read()


def run_worker(spool: Spool, endpoint: str, api_key: str, sensor_id: str, stop: Event):
    heartbeat_endpoint = (
        endpoint.rsplit("/falco/events", 1)[0] + "/sensors/heartbeat"
        if endpoint.endswith("/falco/events") else
        endpoint.rsplit("/ingest/falco", 1)[0] + "/ingest/heartbeat"
    )
    next_heartbeat = 0.0
    while True:
        if time.monotonic() >= next_heartbeat:
            try:
                post_json(heartbeat_endpoint, api_key, {"sensor_id": sensor_id, "hostname": socket.gethostname(), **spool.metrics()})
            except (HTTPError, URLError, TimeoutError, OSError) as exc:
                print(f"Sensor heartbeat failed: {exc}", file=sys.stderr)
            next_heartbeat = time.monotonic() + 30

        pending = spool.oldest()
        if pending:
            seq, raw = pending
            try:
                post_json(endpoint, api_key, json.loads(raw))
                spool.mark_sent(seq)
                continue
            except HTTPError as exc:
                if exc.code in {400, 413, 422}:
                    spool.dead_letter(seq, raw, f"HTTP {exc.code}")
                    print(f"Falco delivery moved to dead letter: HTTP {exc.code}", file=sys.stderr)
                    continue
                print(f"Falco delivery pending retry: HTTP {exc.code}", file=sys.stderr)
            except (URLError, TimeoutError, OSError) as exc:
                print(f"Falco delivery pending retry: {exc}", file=sys.stderr)
        if stop.is_set():
            break
        stop.wait(2)


def main() -> int:
    api_key = os.environ.get("CLOUDGUARD_SENSOR_API_KEY") or os.environ.get("CLOUDGUARD_API_KEY")
    endpoint = os.environ.get("CLOUDGUARD_FALCO_ENDPOINT", "http://127.0.0.1:8000/api/falco/events")
    sensor_id = os.environ.get("CLOUDGUARD_SENSOR_ID", socket.gethostname())
    spool_path = Path(os.environ.get("CLOUDGUARD_SPOOL_PATH", "./falco-spool.sqlite3"))
    if not api_key:
        print("CLOUDGUARD_SENSOR_API_KEY is required", file=sys.stderr)
        return 2
    if not endpoint.endswith(("/falco/events", "/ingest/falco")):
        print("CLOUDGUARD_FALCO_ENDPOINT must end with /falco/events or /ingest/falco", file=sys.stderr)
        return 2
    spool = Spool(spool_path)
    stop = Event()
    worker = Thread(target=run_worker, args=(spool, endpoint, api_key, sensor_id, stop), daemon=True)
    worker.start()
    for line in sys.stdin:
        if len(line.encode("utf-8")) > MAX_ALERT_BYTES:
            spool.increment("dropped")
            print("Falco alert exceeded size limit and was dropped", file=sys.stderr)
            continue
        try:
            payload = json.loads(line)
            if not isinstance(payload, dict):
                raise ValueError("Falco alert must be a JSON object")
            spool.enqueue(payload)
        except (json.JSONDecodeError, ValueError) as exc:
            spool.increment("parse_failures")
            print(f"Falco JSON parse failed: {exc}", file=sys.stderr)
    stop.set()
    worker.join(timeout=7)
    remaining = spool.metrics()["queue_depth"]
    if remaining:
        print(f"{remaining} Falco alerts remain in the local retry spool", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
