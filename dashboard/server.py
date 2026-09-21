#!/usr/bin/env python3
"""
RFID scan log server + dashboard host.

Standard library only (no pip installs). Run:

    python3 server.py               # http://localhost:8080
    python3 server.py --demo        # also seeds sample tags, scans, heartbeats
    python3 server.py --port 9000 --host 0.0.0.0   # reachable from the Pico on the LAN

The server owns the tag registry: every incoming scan is judged against it
(registered + authorized => allowed; revoked or unknown => denied) and alerts
are raised for denied scans, repeated denials, unknown readers and readers
that stop sending heartbeats.

Endpoints
    GET    /                          dashboard (Activity / Readers / Alerts / Tags views)
    GET    /api/scans                 ?since=<ISO-8601>&limit=<n>   newest first
    POST   /api/scans                 {"reader_id": "rack-01", "uid": "DEADBEEF"}
                                      optional "ts" (ISO-8601), "device_authorized" (bool)
    DELETE /api/scans                 clears scans and alerts (testing)
    POST   /api/heartbeat             {"reader_id": "rack-01"}
    GET    /api/readers               readers.json entries + last_seen / online / counts
    GET    /api/tags                  registry with scan counts and last seen
    POST   /api/tags                  {"uid": "..", "owner": "..", "label": "..", "authorized": true}
    PUT    /api/tags/<uid>            any of owner / label / authorized / notes
    DELETE /api/tags/<uid>
    GET    /api/tags/unregistered     UIDs seen by readers that are not in the registry
    GET    /api/alerts                ?include_acked=1
    POST   /api/alerts/<id>/ack
    POST   /api/alerts/ack_all
"""
import argparse
import functools
import json
import os
import random
import re
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

print = functools.partial(print, flush=True)  # show log lines immediately even when piped

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(HERE, "scans.db")
READERS_PATH = os.path.join(HERE, "readers.json")

OFFLINE_AFTER_S = 120          # no heartbeat/scan for this long => reader offline
REPEAT_WINDOW_MIN = 10         # repeated-denial window
REPEAT_THRESHOLD = 3           # denials within the window that raise a critical alert


# --------------------------------------------------------------------------- utils
def utcnow():
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt):
    return dt.isoformat()


def parse_ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def norm_uid(uid):
    return re.sub(r"[^0-9A-F]", "", str(uid).upper())


def load_readers():
    with open(READERS_PATH) as f:
        return {r["id"]: r for r in json.load(f)["readers"]}


# --------------------------------------------------------------------------- database
SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,
    reader_id  TEXT NOT NULL,
    uid        TEXT NOT NULL,
    authorized INTEGER NOT NULL,
    reason     TEXT NOT NULL DEFAULT 'unregistered'
);
CREATE INDEX IF NOT EXISTS idx_scans_ts ON scans(ts);
CREATE INDEX IF NOT EXISTS idx_scans_uid ON scans(uid);

CREATE TABLE IF NOT EXISTS tags (
    uid        TEXT PRIMARY KEY,
    owner      TEXT NOT NULL DEFAULT '',
    label      TEXT NOT NULL DEFAULT '',
    authorized INTEGER NOT NULL DEFAULT 1,
    notes      TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT NOT NULL,
    type         TEXT NOT NULL,
    severity     TEXT NOT NULL,
    reader_id    TEXT,
    uid          TEXT,
    message      TEXT NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);

CREATE TABLE IF NOT EXISTS reader_status (
    reader_id TEXT PRIMARY KEY,
    last_seen TEXT NOT NULL
);
"""


def open_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.executescript(SCHEMA)
    # migrate a pre-registry database that lacks the reason column
    cols = [r["name"] for r in db.execute("PRAGMA table_info(scans)")]
    if "reason" not in cols:
        db.execute("ALTER TABLE scans ADD COLUMN reason TEXT NOT NULL DEFAULT 'unregistered'")
    db.commit()
    return db


def raise_alert(db, ts, type_, severity, message, reader_id=None, uid=None):
    db.execute(
        "INSERT INTO alerts (ts, type, severity, reader_id, uid, message) VALUES (?,?,?,?,?,?)",
        (ts, type_, severity, reader_id, uid, message))


def touch_reader(db, reader_id, ts):
    db.execute("INSERT INTO reader_status (reader_id, last_seen) VALUES (?, ?) "
               "ON CONFLICT(reader_id) DO UPDATE SET last_seen = excluded.last_seen "
               "WHERE excluded.last_seen > reader_status.last_seen", (reader_id, ts))
    # reader is back: close any open offline alerts for it
    db.execute("UPDATE alerts SET acknowledged = 1 WHERE type = 'reader_offline' "
               "AND reader_id = ? AND acknowledged = 0", (reader_id,))


def insert_scan(db, reader_id, uid, ts=None, readers=None):
    """Judge the scan against the registry, store it, raise alerts. Returns the scan row."""
    ts = ts or iso(utcnow())
    uid = norm_uid(uid)
    readers = readers if readers is not None else load_readers()
    tag = db.execute("SELECT * FROM tags WHERE uid = ?", (uid,)).fetchone()
    if tag and tag["authorized"]:
        authorized, reason = 1, "registered"
    elif tag:
        authorized, reason = 0, "revoked"
    else:
        authorized, reason = 0, "unregistered"

    cur = db.execute("INSERT INTO scans (ts, reader_id, uid, authorized, reason) VALUES (?,?,?,?,?)",
                     (ts, reader_id, uid, authorized, reason))
    scan_id = cur.lastrowid
    touch_reader(db, reader_id, ts)

    where = readers[reader_id]["name"] if reader_id in readers else reader_id
    if reader_id not in readers:
        raise_alert(db, ts, "unknown_reader", "serious",
                    f"Scan received from reader '{reader_id}', which is not in readers.json",
                    reader_id, uid)
    if not authorized:
        who = f"{tag['owner'] or 'unnamed'}'s revoked tag" if tag else "unregistered tag"
        raise_alert(db, ts, "denied", "serious" if tag else "warning",
                    f"Denied {who} {uid} at {where}", reader_id, uid)
        window_start = iso(parse_ts(ts) - timedelta(minutes=REPEAT_WINDOW_MIN))
        n = db.execute("SELECT COUNT(*) FROM scans WHERE uid = ? AND authorized = 0 AND ts >= ?",
                       (uid, window_start)).fetchone()[0]
        already = db.execute("SELECT COUNT(*) FROM alerts WHERE type = 'repeated_denied' AND uid = ? AND ts >= ?",
                             (uid, window_start)).fetchone()[0]
        if n >= REPEAT_THRESHOLD and not already:
            raise_alert(db, ts, "repeated_denied", "critical",
                        f"Tag {uid} denied {n} times in {REPEAT_WINDOW_MIN} minutes (last at {where})",
                        reader_id, uid)
    db.commit()
    return dict(db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone())


def check_offline(db, readers):
    """Raise an offline alert for any known reader whose last contact is stale."""
    cutoff = iso(utcnow() - timedelta(seconds=OFFLINE_AFTER_S))
    for row in db.execute("SELECT reader_id, last_seen FROM reader_status WHERE last_seen < ?", (cutoff,)):
        rid = row["reader_id"]
        if rid not in readers:
            continue
        open_ = db.execute("SELECT COUNT(*) FROM alerts WHERE type='reader_offline' AND reader_id=? AND acknowledged=0",
                           (rid,)).fetchone()[0]
        if not open_:
            raise_alert(db, iso(utcnow()), "reader_offline", "critical",
                        f"{readers[rid]['name']} ({rid}) has not reported since {row['last_seen']}", rid)
    db.commit()


# --------------------------------------------------------------------------- demo data
def seed_demo(db):
    readers = load_readers()
    now = utcnow()
    random.seed(7)
    tags = [
        ("DEADBEEF", "Kripal M.", "Blue Trek FX", 1),
        ("04A3B2C1", "Nihar R.", "Black Specialized", 1),
        ("1F2E3D4C", "Former student", "Returned bike", 0),   # revoked
    ]
    for uid, owner, label, auth in tags:
        db.execute("INSERT OR IGNORE INTO tags (uid, owner, label, authorized, created_at) VALUES (?,?,?,?,?)",
                   (uid, owner, label, auth, iso(now - timedelta(days=10))))
    db.commit()
    seen = ["DEADBEEF", "DEADBEEF", "DEADBEEF", "04A3B2C1", "04A3B2C1", "1F2E3D4C", "A1B2C3D4", "7E8F9A0B"]
    stamps = sorted(now - timedelta(minutes=random.randint(5, 3 * 24 * 60)) for _ in range(60))
    for ts in stamps:
        insert_scan(db, random.choice(list(readers)), random.choice(seen), iso(ts), readers)
    # a burst of denials from one unknown tag => repeated_denied alert
    for i in range(3):
        insert_scan(db, "rack-02", "7E8F9A0B", iso(now - timedelta(minutes=4 - i)), readers)
    # a scan from a reader that is not configured
    insert_scan(db, "rack-99", "A1B2C3D4", iso(now - timedelta(minutes=30)), readers)
    # heartbeats: three readers alive, rack-04 silent for an hour => offline alert
    for rid, age in (("rack-01", 5), ("rack-02", 12), ("rack-03", 20), ("rack-04", 3600)):
        touch_reader(db, rid, iso(now - timedelta(seconds=age)))
    db.commit()
    print("Seeded demo tags, scans, heartbeats")


# --------------------------------------------------------------------------- HTTP
class Handler(SimpleHTTPRequestHandler):
    # Browsers open idle "preconnect" sockets and keep-alive connections. With a
    # single-threaded server one idle socket blocks every other request, so the
    # dashboard appears frozen. Each connection therefore gets its own thread and
    # is dropped after a few idle seconds.
    timeout = 10
    protocol_version = "HTTP/1.1"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=HERE, **kwargs)

    # ---- helpers
    def _json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def end_headers(self):
        # Static files (index.html) and API responses alike: always revalidate, so an
        # updated dashboard is picked up on the next reload instead of a cached copy.
        self.send_header("Cache-Control", "no-cache")
        super().end_headers()

    def _body(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        return json.loads(raw or b"{}")

    def log_message(self, fmt, *args):
        line = str(args[0]) if args else ""
        if line.startswith("GET /api/"):      # skip the dashboard's polling
            return
        super().log_message(fmt, *args)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    # ---- routing
    ROUTES = [
        ("GET",    r"^/api/scans$",               "get_scans"),
        ("POST",   r"^/api/scans$",               "post_scan"),
        ("DELETE", r"^/api/scans$",               "delete_scans"),
        ("POST",   r"^/api/heartbeat$",           "post_heartbeat"),
        ("GET",    r"^/api/readers$",             "get_readers"),
        ("GET",    r"^/api/tags$",                "get_tags"),
        ("POST",   r"^/api/tags$",                "post_tag"),
        ("GET",    r"^/api/tags/unregistered$",   "get_unregistered"),
        ("PUT",    r"^/api/tags/([0-9A-Fa-f]+)$", "put_tag"),
        ("DELETE", r"^/api/tags/([0-9A-Fa-f]+)$", "delete_tag"),
        ("GET",    r"^/api/alerts$",              "get_alerts"),
        ("POST",   r"^/api/alerts/(\d+)/ack$",    "ack_alert"),
        ("POST",   r"^/api/alerts/ack_all$",      "ack_all"),
    ]

    def _dispatch(self, method):
        """Handle an API request. Returns True if a response was sent, False if
        the path is not an API path (so the caller may serve a static file)."""
        url = urlparse(self.path)
        for m, pattern, name in self.ROUTES:
            if m != method:
                continue
            match = re.match(pattern, url.path)
            if match:
                try:
                    getattr(self, name)(parse_qs(url.query), *match.groups())
                except (KeyError, ValueError, json.JSONDecodeError) as e:
                    self._json(400, {"error": f"bad request: {e}"})
                return True
        if url.path.startswith("/api/"):
            self._json(404, {"error": "not found"})
            return True
        return False

    def do_GET(self):
        if not self._dispatch("GET"):
            if urlparse(self.path).path == "/":
                self.path = "/index.html"
            super().do_GET()

    def _api_only(self, method):
        if not self._dispatch(method):
            self._json(404, {"error": "not found"})

    def do_POST(self):   self._api_only("POST")
    def do_PUT(self):    self._api_only("PUT")
    def do_DELETE(self): self._api_only("DELETE")

    # ---- scans
    def get_scans(self, q):
        since = q.get("since", [None])[0]
        limit = min(int(q.get("limit", ["2000"])[0]), 10000)
        db = open_db()
        sql = "SELECT id, ts, reader_id, uid, authorized, reason FROM scans "
        if since:
            rows = db.execute(sql + "WHERE ts >= ? ORDER BY ts DESC, id DESC LIMIT ?", (since, limit)).fetchall()
        else:
            rows = db.execute(sql + "ORDER BY ts DESC, id DESC LIMIT ?", (limit,)).fetchall()
        db.close()
        scans = [{**dict(r), "authorized": bool(r["authorized"])} for r in rows]
        self._json(200, {"scans": scans, "server_time": iso(utcnow())})

    def post_scan(self, q):
        data = self._body()
        reader_id = str(data["reader_id"]).strip()
        uid = norm_uid(data["uid"])
        if not reader_id or not uid:
            return self._json(400, {"error": "reader_id and uid are required"})
        readers = load_readers()
        db = open_db()
        scan = insert_scan(db, reader_id, uid, data.get("ts"), readers)
        db.close()
        verdict = "AUTHORIZED" if scan["authorized"] else f"DENIED ({scan['reason']})"
        note = "" if reader_id in readers else "  (reader not in readers.json)"
        print(f"scan #{scan['id']}: {reader_id} {uid} {verdict}{note}")
        dev = data.get("device_authorized")
        if dev is not None and bool(dev) != bool(scan["authorized"]):
            print(f"  ! firmware said {'AUTHORIZED' if dev else 'DENIED'} but registry says {verdict}")
        self._json(201, {"id": scan["id"], "authorized": bool(scan["authorized"]),
                         "reason": scan["reason"], "known_reader": reader_id in readers})

    def delete_scans(self, q):
        db = open_db()
        db.execute("DELETE FROM scans"); db.execute("DELETE FROM alerts")
        db.commit(); db.close()
        self._json(200, {"cleared": True})

    # ---- readers
    def post_heartbeat(self, q):
        reader_id = str(self._body()["reader_id"]).strip()
        db = open_db()
        touch_reader(db, reader_id, iso(utcnow()))
        db.commit(); db.close()
        self._json(200, {"ok": True, "known_reader": reader_id in load_readers()})

    def get_readers(self, q):
        readers = load_readers()
        db = open_db()
        check_offline(db, readers)
        status = {r["reader_id"]: r["last_seen"] for r in db.execute("SELECT * FROM reader_status")}
        day_start = iso(utcnow().replace(hour=0, minute=0, second=0))
        counts = {r["reader_id"]: (r["n"], r["denied"]) for r in db.execute(
            "SELECT reader_id, COUNT(*) AS n, SUM(authorized = 0) AS denied FROM scans WHERE ts >= ? GROUP BY reader_id",
            (day_start,))}
        db.close()
        cutoff = utcnow() - timedelta(seconds=OFFLINE_AFTER_S)
        out = []
        for r in readers.values():
            seen = status.get(r["id"])
            online = bool(seen) and parse_ts(seen) >= cutoff
            n, denied = counts.get(r["id"], (0, 0))
            out.append({**r, "last_seen": seen, "online": online,
                        "status": "online" if online else ("offline" if seen else "never seen"),
                        "scans_today": n, "denied_today": denied or 0})
        self._json(200, {"readers": out, "offline_after_s": OFFLINE_AFTER_S})

    # ---- tags
    def get_tags(self, q):
        db = open_db()
        rows = db.execute("""
            SELECT t.*, COUNT(s.id) AS scans, MAX(s.ts) AS last_seen
            FROM tags t LEFT JOIN scans s ON s.uid = t.uid
            GROUP BY t.uid ORDER BY t.created_at DESC""").fetchall()
        db.close()
        self._json(200, {"tags": [{**dict(r), "authorized": bool(r["authorized"])} for r in rows]})

    def post_tag(self, q):
        data = self._body()
        uid = norm_uid(data["uid"])
        if len(uid) not in (8, 14, 20):
            return self._json(400, {"error": "uid must be 4, 7 or 10 bytes of hex (8, 14 or 20 hex digits)"})
        db = open_db()
        if db.execute("SELECT 1 FROM tags WHERE uid = ?", (uid,)).fetchone():
            db.close()
            return self._json(409, {"error": f"tag {uid} is already registered"})
        db.execute("INSERT INTO tags (uid, owner, label, authorized, notes, created_at) VALUES (?,?,?,?,?,?)",
                   (uid, str(data.get("owner", "")).strip(), str(data.get("label", "")).strip(),
                    1 if data.get("authorized", True) else 0, str(data.get("notes", "")).strip(), iso(utcnow())))
        db.commit(); db.close()
        print(f"tag registered: {uid} ({data.get('owner', '')})")
        self._json(201, {"uid": uid})

    def put_tag(self, q, uid):
        uid = norm_uid(uid)
        data = self._body()
        fields, values = [], []
        for k in ("owner", "label", "notes"):
            if k in data:
                fields.append(f"{k} = ?"); values.append(str(data[k]).strip())
        if "authorized" in data:
            fields.append("authorized = ?"); values.append(1 if data["authorized"] else 0)
        if not fields:
            return self._json(400, {"error": "nothing to update"})
        db = open_db()
        cur = db.execute(f"UPDATE tags SET {', '.join(fields)} WHERE uid = ?", (*values, uid))
        db.commit(); db.close()
        if cur.rowcount == 0:
            return self._json(404, {"error": "tag not found"})
        self._json(200, {"uid": uid, "updated": [f.split(' ')[0] for f in fields]})

    def delete_tag(self, q, uid):
        db = open_db()
        cur = db.execute("DELETE FROM tags WHERE uid = ?", (norm_uid(uid),))
        db.commit(); db.close()
        self._json(200 if cur.rowcount else 404, {"deleted": bool(cur.rowcount)})

    def get_unregistered(self, q):
        db = open_db()
        rows = db.execute("""
            SELECT s.uid, COUNT(*) AS scans, MAX(s.ts) AS last_seen,
                   (SELECT reader_id FROM scans WHERE uid = s.uid ORDER BY ts DESC LIMIT 1) AS last_reader
            FROM scans s WHERE s.uid NOT IN (SELECT uid FROM tags)
            GROUP BY s.uid ORDER BY last_seen DESC LIMIT 50""").fetchall()
        db.close()
        self._json(200, {"unregistered": [dict(r) for r in rows]})

    # ---- alerts
    def get_alerts(self, q):
        include_acked = q.get("include_acked", ["0"])[0] == "1"
        db = open_db()
        check_offline(db, load_readers())
        sql = "SELECT * FROM alerts " + ("" if include_acked else "WHERE acknowledged = 0 ") + "ORDER BY ts DESC, id DESC LIMIT 500"
        rows = db.execute(sql).fetchall()
        open_count = db.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged = 0").fetchone()[0]
        db.close()
        self._json(200, {"alerts": [{**dict(r), "acknowledged": bool(r["acknowledged"])} for r in rows],
                         "open": open_count})

    def ack_alert(self, q, alert_id):
        db = open_db()
        cur = db.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (int(alert_id),))
        db.commit(); db.close()
        self._json(200 if cur.rowcount else 404, {"acknowledged": bool(cur.rowcount)})

    def ack_all(self, q):
        db = open_db()
        cur = db.execute("UPDATE alerts SET acknowledged = 1 WHERE acknowledged = 0")
        db.commit(); db.close()
        self._json(200, {"acknowledged": cur.rowcount})


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1", help="use 0.0.0.0 to accept posts from the Pico on your LAN")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--demo", action="store_true", help="seed sample data on startup")
    args = ap.parse_args()

    if not os.path.exists(READERS_PATH):
        sys.exit(f"missing {READERS_PATH}")
    db = open_db()
    if args.demo:
        seed_demo(db)
    db.close()

    try:
        srv = ThreadingHTTPServer((args.host, args.port), Handler)
        srv.daemon_threads = True
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
