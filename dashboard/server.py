#!/usr/bin/env python3
"""
RFID scan log server + dashboard host.

Standard library only (no pip installs). Run:

    python3 server.py               # http://localhost:8080
    python3 server.py --demo        # also seeds a few sample scans
    python3 server.py --port 9000 --host 0.0.0.0   # reachable from the Pico on the LAN

Endpoints
    GET  /                 dashboard page
    GET  /readers.json     reader id -> name/lat/lon table
    GET  /api/scans        ?since=<ISO-8601 UTC>&limit=<n>   newest first
    POST /api/scans        {"reader_id": "rack-01", "uid": "DEADBEEF", "authorized": true}
                           optional "ts" (ISO-8601 UTC); defaults to server time
    DELETE /api/scans      clears the log (for testing)
"""
import argparse
import json
import os
import random
import sqlite3
import sys
import functools
from datetime import datetime, timedelta, timezone
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

print = functools.partial(print, flush=True)  # show log lines immediately even when piped

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(HERE, "scans.db")
READERS_PATH = os.path.join(HERE, "readers.json")


def utcnow_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def open_db():
    db = sqlite3.connect(DB_PATH)
    db.execute(
        """CREATE TABLE IF NOT EXISTS scans (
               id         INTEGER PRIMARY KEY AUTOINCREMENT,
               ts         TEXT NOT NULL,
               reader_id  TEXT NOT NULL,
               uid        TEXT NOT NULL,
               authorized INTEGER NOT NULL
           )"""
    )
    db.execute("CREATE INDEX IF NOT EXISTS idx_scans_ts ON scans(ts)")
    db.commit()
    return db


def load_readers():
    with open(READERS_PATH) as f:
        return {r["id"]: r for r in json.load(f)["readers"]}


def insert_scan(db, reader_id, uid, authorized, ts=None):
    ts = ts or utcnow_iso()
    cur = db.execute(
        "INSERT INTO scans (ts, reader_id, uid, authorized) VALUES (?, ?, ?, ?)",
        (ts, reader_id, uid.upper().replace(" ", ""), 1 if authorized else 0),
    )
    db.commit()
    return cur.lastrowid


def seed_demo(db):
    """Insert sample scans across the last 3 days so the dashboard has content."""
    readers = list(load_readers().keys())
    tags = ["DEADBEEF", "04A3B2C1", "1F2E3D4C", "A1B2C3D4", "7E8F9A0B"]
    now = datetime.now(timezone.utc)
    random.seed(7)
    for _ in range(60):
        ts = now - timedelta(minutes=random.randint(0, 3 * 24 * 60))
        uid = random.choice(tags)
        insert_scan(db, random.choice(readers), uid, uid == "DEADBEEF",
                    ts.replace(microsecond=0).isoformat())
    print("Seeded 60 demo scans")


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=HERE, **kwargs)

    # ---- helpers -----------------------------------------------------------
    def _json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        # Quieter log: skip the polling GETs
        if "GET /api/scans" in (args[0] if args else ""):
            return
        super().log_message(fmt, *args)

    # ---- routes ------------------------------------------------------------
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/api/scans":
            return self._get_scans(parse_qs(url.query))
        if url.path == "/api/readers":
            return self._json(200, {"readers": list(load_readers().values())})
        if url.path == "/":
            self.path = "/index.html"
        return super().do_GET()

    def _get_scans(self, q):
        since = q.get("since", [None])[0]
        limit = min(int(q.get("limit", ["2000"])[0]), 10000)
        db = open_db()
        if since:
            rows = db.execute(
                "SELECT id, ts, reader_id, uid, authorized FROM scans "
                "WHERE ts >= ? ORDER BY ts DESC, id DESC LIMIT ?", (since, limit)).fetchall()
        else:
            rows = db.execute(
                "SELECT id, ts, reader_id, uid, authorized FROM scans "
                "ORDER BY ts DESC, id DESC LIMIT ?", (limit,)).fetchall()
        db.close()
        scans = [{"id": r[0], "ts": r[1], "reader_id": r[2], "uid": r[3],
                  "authorized": bool(r[4])} for r in rows]
        return self._json(200, {"scans": scans, "server_time": utcnow_iso()})

    def do_POST(self):
        if urlparse(self.path).path != "/api/scans":
            return self._json(404, {"error": "not found"})
        length = int(self.headers.get("Content-Length", 0))
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
            reader_id = str(data["reader_id"]).strip()
            uid = str(data["uid"]).strip()
            authorized = bool(data.get("authorized", False))
            ts = data.get("ts")
        except (KeyError, ValueError, json.JSONDecodeError) as e:
            return self._json(400, {"error": f"bad request: {e}"})
        if not reader_id or not uid:
            return self._json(400, {"error": "reader_id and uid are required"})
        known = reader_id in load_readers()
        db = open_db()
        scan_id = insert_scan(db, reader_id, uid, authorized, ts)
        db.close()
        print(f"scan #{scan_id}: {reader_id} {uid} {'AUTHORIZED' if authorized else 'DENIED'}"
              + ("" if known else "  (reader not in readers.json)"))
        return self._json(201, {"id": scan_id, "known_reader": known})

    def do_DELETE(self):
        if urlparse(self.path).path != "/api/scans":
            return self._json(404, {"error": "not found"})
        db = open_db()
        db.execute("DELETE FROM scans")
        db.commit()
        db.close()
        return self._json(200, {"cleared": True})


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1", help="use 0.0.0.0 to accept posts from the Pico on your LAN")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--demo", action="store_true", help="seed sample scans on startup")
    args = ap.parse_args()

    db = open_db()
    if args.demo:
        seed_demo(db)
    db.close()

    if not os.path.exists(READERS_PATH):
        sys.exit(f"missing {READERS_PATH}")

    try:
        srv = HTTPServer((args.host, args.port), Handler)
    except OSError as e:
        sys.exit(f"Could not listen on port {args.port} ({e.strerror}). "
                 f"Another program is using it; try:  python3 server.py --port {args.port + 1}")
    print(f"Dashboard: http://{'localhost' if args.host in ('127.0.0.1', '0.0.0.0') else args.host}:{args.port}")
    print(f"Scans DB:  {DB_PATH}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
