#!/usr/bin/env python3
"""
RFID scan log server: staff dashboard, student portal and device API.

Standard library only, plus the optional pywebpush package for phone notifications. Run:

    python3 server.py                     # http://localhost:8080
    python3 server.py --demo              # also seeds demo users, tags, scans, alerts
    python3 server.py --create-user admin --role staff      # bootstrap a staff account
    python3 server.py --port 9000 --host 0.0.0.0            # reachable from the Pico on the LAN

Access control
    public   /api/auth/login, /api/auth/register
    device   POST /api/scans, POST /api/heartbeat   -> header X-Device-Key (dashboard/device_key.txt)
             (a logged-in staff session is accepted too, for testing with curl)
    user     everything else; students only see their own tags, scans and alerts
    staff    /api/users, /api/tags/unregistered, acknowledging alerts, assigning tag owners

Pages
    /login.html   sign in / create a student account
    /index.html   staff dashboard (Activity, Readers, Alerts, Tags, Users)
    /me.html      student portal (My bikes, My activity, My map)

Endpoints
    POST   /api/auth/login             {"username", "password"}      -> session cookie
    POST   /api/auth/logout
    POST   /api/auth/register          {"username", "password", "display_name"}  (student)
    GET    /api/auth/me
    POST   /api/auth/password          {"current_password", "new_password"}  change my own password
    PUT    /api/auth/email             {"email"}                               set my own email
    POST   /api/auth/forgot            {"username"}            email a 6-digit reset code (public)
    POST   /api/auth/reset             {"username", "code", "new_password"}     (public)
    GET    /api/push                   notifications: enabled?, VAPID public key, my subscriptions
    POST   /api/push/subscribe         {"subscription": <PushSubscription JSON>}
    DELETE /api/push/subscribe         {"endpoint"}
    POST   /api/push/test              send a test notification to my devices
    GET    /api/users                  staff
    POST   /api/users                  staff  {"username","password","display_name","role"}
    PUT    /api/users/<id>             staff  {"role" | "display_name" | "password"}
    DELETE /api/users/<id>             staff
    GET    /api/scans                  ?since=&limit=&owner=<user id>   (students: own only)
    POST   /api/scans                  device  {"reader_id", "uid", "device_authorized"?}
    DELETE /api/scans                  staff
    POST   /api/heartbeat              device  {"reader_id"}
    GET    /api/readers
    GET    /api/tags                   (students: own only)
    POST   /api/tags                   {"uid","label","owner_id"?}   students register to themselves
    PUT    /api/tags/<uid>             students: label/authorized on own tags; staff: anything incl. owner_id
    DELETE /api/tags/<uid>             students: own tags; staff: any
    GET    /api/tags/unregistered      staff
    GET    /api/alerts                 ?include_acked=1   (students: alerts about own tags)
    POST   /api/alerts/<id>/ack        staff
    POST   /api/alerts/ack_all         staff
"""
import argparse
import base64
import functools
import getpass
import hashlib
import hmac
import json
import os
import queue
import random
import re
import secrets
import smtplib
import sqlite3
import sys
import threading
from collections import deque
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from http.cookies import SimpleCookie
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

try:   # optional: phone/desktop notifications over Web Push (python3 -m pip install pywebpush)
    from pywebpush import webpush, WebPushException
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    PUSH_AVAILABLE = True
except ImportError:
    PUSH_AVAILABLE = False

print = functools.partial(print, flush=True)  # show log lines immediately even when piped

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(HERE, "scans.db")
READERS_PATH = os.path.join(HERE, "readers.json")
DEVICE_KEY_PATH = os.path.join(HERE, "device_key.txt")
MAIL_CONFIG_PATH = os.path.join(HERE, "mail_config.json")   # SMTP settings for password-reset codes, git-ignored
RESET_CODE_MINUTES = 10        # a password-reset code is valid for this long
RESET_MAX_ATTEMPTS = 5         # wrong guesses before the code is thrown away
RESET_RESEND_S = 60            # minimum gap between two codes for the same account
VAPID_KEY_PATH = os.path.join(HERE, "vapid_private.pem")   # Web Push signing key, created on first run, git-ignored
VAPID_CONTACT = "mailto:rfid-dashboard@example.edu"         # contact the push services may use to reach the operator

OFFLINE_AFTER_S = 30           # no heartbeat/scan for this long => reader offline (heartbeats are every 10 s)
REPEAT_WINDOW_MIN = 10         # repeated-denial window
REPEAT_THRESHOLD = 3           # denials within the window that raise a critical alert
SESSION_DAYS = 30
PBKDF2_ROUNDS = 200_000


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


def device_key():
    """The shared secret readers use to post scans. Created on first run."""
    if not os.path.exists(DEVICE_KEY_PATH):
        with open(DEVICE_KEY_PATH, "w") as f:
            f.write(secrets.token_hex(16) + "\n")
        os.chmod(DEVICE_KEY_PATH, 0o600)
    with open(DEVICE_KEY_PATH) as f:
        return f.read().strip()


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), PBKDF2_ROUNDS)
    return f"{salt}${digest.hex()}"


def check_password(password, stored):
    salt, _ = stored.split("$", 1)
    return hmac.compare_digest(hash_password(password, salt), stored)


# --------------------------------------------------------------------------- live event bus
# Every scan, heartbeat, alert and reader log line is published here and
# streamed to browsers over Server-Sent Events (GET /api/events). The last
# EVENT_HISTORY events are replayed to a client when it connects.
EVENT_HISTORY = 300
_events = deque(maxlen=EVENT_HISTORY)
_subscribers = set()
_bus_lock = threading.Lock()
_event_seq = 0


def publish(type_, reader_id=None, text="", **extra):
    global _event_seq
    with _bus_lock:
        _event_seq += 1
        ev = {"id": _event_seq, "ts": iso(utcnow()), "type": type_, "reader_id": reader_id, "text": text, **extra}
        _events.append(ev)
        for q in list(_subscribers):
            try:
                q.put_nowait(ev)
            except queue.Full:
                pass
    return ev


def subscribe():
    q = queue.Queue(maxsize=500)
    with _bus_lock:
        _subscribers.add(q)
        history = list(_events)
    return q, history


def unsubscribe(q):
    with _bus_lock:
        _subscribers.discard(q)


# --------------------------------------------------------------------------- database
SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,
    reader_id  TEXT NOT NULL,
    uid        TEXT NOT NULL,
    authorized INTEGER NOT NULL,
    reason     TEXT NOT NULL DEFAULT 'unregistered',
    event_id   TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_ts ON scans(ts);
CREATE INDEX IF NOT EXISTS idx_scans_uid ON scans(uid);

CREATE TABLE IF NOT EXISTS tags (
    uid        TEXT PRIMARY KEY,
    owner      TEXT NOT NULL DEFAULT '',
    label      TEXT NOT NULL DEFAULT '',
    authorized INTEGER NOT NULL DEFAULT 1,
    notes      TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    owner_id   INTEGER
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
    last_seen TEXT NOT NULL,
    meta      TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    display_name  TEXT NOT NULL DEFAULT '',
    role          TEXT NOT NULL DEFAULT 'student',
    created_at    TEXT NOT NULL,
    email         TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS password_resets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    code_hash  TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 0,
    used       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS push_subscriptions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    endpoint   TEXT NOT NULL UNIQUE,
    p256dh     TEXT NOT NULL,
    auth       TEXT NOT NULL,
    user_agent TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    last_sent  TEXT
);
"""


def open_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.executescript(SCHEMA)
    # migrations for databases created by earlier versions
    scan_cols = [r["name"] for r in db.execute("PRAGMA table_info(scans)")]
    if "reason" not in scan_cols:
        db.execute("ALTER TABLE scans ADD COLUMN reason TEXT NOT NULL DEFAULT 'unregistered'")
    if "event_id" not in scan_cols:
        db.execute("ALTER TABLE scans ADD COLUMN event_id TEXT")
    # event_id is the idempotency key for re-sent scans (reader-boot-seq); unique when present
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_scans_event ON scans(event_id) WHERE event_id IS NOT NULL")
    tag_cols = [r["name"] for r in db.execute("PRAGMA table_info(tags)")]
    if "owner_id" not in tag_cols:
        db.execute("ALTER TABLE tags ADD COLUMN owner_id INTEGER")
    if "notify" not in tag_cols:   # when to notify the owner: all | moves | lost | off
        db.execute("ALTER TABLE tags ADD COLUMN notify TEXT NOT NULL DEFAULT 'all'")
    user_cols = [r["name"] for r in db.execute("PRAGMA table_info(users)")]
    if "email" not in user_cols:
        db.execute("ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''")
    rs_cols = [r["name"] for r in db.execute("PRAGMA table_info(reader_status)")]
    if "meta" not in rs_cols:
        db.execute("ALTER TABLE reader_status ADD COLUMN meta TEXT NOT NULL DEFAULT '{}'")
    db.commit()
    return db


def valid_email(s):
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", s))


def create_user(db, username, password, display_name="", role="student", email=""):
    username = username.strip().lower()
    email = (email or "").strip().lower()
    if email and not valid_email(email):
        raise ValueError("that does not look like an email address")
    if not re.match(r"^[a-z0-9._@+-]{2,64}$", username):
        raise ValueError("username may contain letters, digits and . _ @ + - (2-64 chars)")
    if len(password) < 6:
        raise ValueError("password must be at least 6 characters")
    if role not in ("staff", "student"):
        raise ValueError("role must be staff or student")
    if db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
        raise ValueError(f"username '{username}' is taken")
    cur = db.execute("INSERT INTO users (username, password_hash, display_name, role, created_at, email) VALUES (?,?,?,?,?,?)",
                     (username, hash_password(password), display_name.strip() or username, role, iso(utcnow()), email))
    db.commit()
    return cur.lastrowid


def public_user(row):
    return {"id": row["id"], "username": row["username"], "display_name": row["display_name"],
            "role": row["role"], "created_at": row["created_at"], "email": row["email"] if "email" in row.keys() else ""}


def mask_email(e):
    """k***l@gmail.com, enough for the owner to recognise it and nobody else to copy it."""
    if "@" not in e:
        return ""
    name, dom = e.split("@", 1)
    return (name[0] + "***" + (name[-1] if len(name) > 1 else "")) + "@" + dom


# --------------------------------------------------------------------------- email (password-reset codes)
# Settings live in dashboard/mail_config.json (see mail_config.example.json). Without it,
# codes are printed on the server console so the flow can still be tried on the bench.
def mail_config():
    if not os.path.exists(MAIL_CONFIG_PATH):
        return None
    with open(MAIL_CONFIG_PATH) as f:
        return json.load(f)


def send_mail(to, subject, body):
    cfg = mail_config()
    if not cfg:
        print(f"MAIL not configured ({MAIL_CONFIG_PATH} missing). Would send to {to}: {subject} / {body.strip().splitlines()[0]}")
        return False
    msg = EmailMessage()
    msg["From"] = f"{cfg.get('from_name', 'RFID Scan Log')} <{cfg.get('from_addr', cfg['username'])}>"
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    port = int(cfg.get("smtp_port", 587))
    if port == 465:
        with smtplib.SMTP_SSL(cfg["smtp_host"], port, timeout=15) as s:
            s.login(cfg["username"], cfg["password"]); s.send_message(msg)
    else:
        with smtplib.SMTP(cfg["smtp_host"], port, timeout=15) as s:
            s.starttls(); s.login(cfg["username"], cfg["password"]); s.send_message(msg)
    return True


def raise_alert(db, ts, type_, severity, message, reader_id=None, uid=None):
    db.execute("INSERT INTO alerts (ts, type, severity, reader_id, uid, message) VALUES (?,?,?,?,?,?)",
               (ts, type_, severity, reader_id, uid, message))
    publish("alert", reader_id, message, severity=severity, alert_type=type_, uid=uid)
    if severity in ("serious", "critical"):
        notify(role="staff", title={"serious": "Alert", "critical": "Critical alert"}[severity], body=message,
               url="/index.html#/alerts", tag=f"alert-{type_}")


def touch_reader(db, reader_id, ts, meta=None):
    db.execute("INSERT INTO reader_status (reader_id, last_seen) VALUES (?, ?) "
               "ON CONFLICT(reader_id) DO UPDATE SET last_seen = excluded.last_seen "
               "WHERE excluded.last_seen > reader_status.last_seen", (reader_id, ts))
    if meta:
        db.execute("UPDATE reader_status SET meta = ? WHERE reader_id = ?", (json.dumps(meta), reader_id))
    cur = db.execute("UPDATE alerts SET acknowledged = 1 WHERE type = 'reader_offline' "
                     "AND reader_id = ? AND acknowledged = 0", (reader_id,))
    if cur.rowcount:
        publish("reader", reader_id, f"{reader_id} is back online")


# --------------------------------------------------------------------------- notifications (Web Push)
# Students and staff can let the portal send notifications to their phone or
# laptop. The browser hands us a push subscription; we sign messages with a
# VAPID key and the browser vendor's push service wakes the service worker
# (sw.js), even when the site is closed. Needs HTTPS in the browser (localhost
# or the Cloudflare tunnel, see tunnel.sh) and the pywebpush package here.
NOTIFY_CHOICES = ("all", "moves", "lost", "off")
_notify_q = queue.Queue()


def vapid_private_pem():
    if not os.path.exists(VAPID_KEY_PATH):
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
        with open(VAPID_KEY_PATH, "wb") as f:
            f.write(pem)
        os.chmod(VAPID_KEY_PATH, 0o600)
    with open(VAPID_KEY_PATH, "rb") as f:
        return f.read()


def vapid_public_key():
    """Base64url (no padding) of the uncompressed P-256 point, the form PushManager.subscribe() wants."""
    key = serialization.load_pem_private_key(vapid_private_pem(), password=None)
    raw = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def notify(user_ids=None, role=None, title="", body="", url="/me.html", tag="rfid"):
    """Queue a notification for specific users, or for every user with the given role."""
    if PUSH_AVAILABLE:
        _notify_q.put({"user_ids": list(user_ids or []), "role": role, "title": title, "body": body, "url": url, "tag": tag})


def _notify_worker():
    while True:
        job = _notify_q.get()
        try:
            _send_notification(job)
        except Exception as e:   # a failed notification must never take the server down
            print(f"notify: {type(e).__name__}: {e}")


def _send_notification(job):
    db = open_db()
    if job["role"]:
        subs = db.execute("SELECT s.*, u.display_name FROM push_subscriptions s JOIN users u ON u.id = s.user_id "
                          "WHERE u.role = ?", (job["role"],)).fetchall()
    elif job["user_ids"]:
        marks = ",".join("?" * len(job["user_ids"]))
        subs = db.execute(f"SELECT s.*, u.display_name FROM push_subscriptions s JOIN users u ON u.id = s.user_id "
                          f"WHERE s.user_id IN ({marks})", job["user_ids"]).fetchall()
    else:
        subs = []
    payload = json.dumps({"title": job["title"], "body": job["body"], "url": job["url"], "tag": job["tag"]})
    sent, gone = 0, 0
    for sub in subs:
        info = {"endpoint": sub["endpoint"], "keys": {"p256dh": sub["p256dh"], "auth": sub["auth"]}}
        try:
            webpush(info, payload, vapid_private_key=VAPID_KEY_PATH,
                    vapid_claims={"sub": VAPID_CONTACT}, ttl=120)
            db.execute("UPDATE push_subscriptions SET last_sent = ? WHERE id = ?", (iso(utcnow()), sub["id"]))
            sent += 1
        except WebPushException as e:
            status = getattr(e.response, "status_code", None)
            if status in (404, 410):   # the browser dropped this subscription; forget it
                db.execute("DELETE FROM push_subscriptions WHERE id = ?", (sub["id"],))
                gone += 1
            else:
                print(f"notify: push to {sub['display_name']} failed: {e}")
        except Exception as e:   # network trouble reaching the push service; try the next device
            print(f"notify: push to {sub['display_name']} failed: {type(e).__name__}: {e}")
    db.commit(); db.close()
    if sent or gone:
        who = job["role"] + " accounts" if job["role"] else ", ".join(sorted({s["display_name"] for s in subs}))
        publish("notify", None, f"Notified {who}: {job['title']} ({sent} device{'s' if sent != 1 else ''})")


def notify_owner_of_scan(db, tag, reader_id, where, ts, authorized):
    """Decide whether this scan should ping the tag's owner, per the tag's notify setting."""
    if not tag or not tag["owner_id"]:
        return
    pref = tag["notify"] if "notify" in tag.keys() else "all"
    name = tag["label"] or f"tag {tag['uid']}"
    when = parse_ts(ts).astimezone().strftime("%-I:%M %p")
    if not authorized:   # reported lost (revoked) and someone just tapped it
        if pref != "off":
            notify([tag["owner_id"]], title="Your lost bike was just scanned",
                   body=f"{name} was tapped at {where} at {when}. Staff have been alerted.",
                   url="/me.html#/activity", tag=f"lost-{tag['uid']}")
        return
    if pref == "all":
        send = True
    elif pref == "moves":
        prev = db.execute("SELECT reader_id FROM scans WHERE uid = ? AND ts < ? ORDER BY ts DESC, id DESC LIMIT 1",
                          (tag["uid"], ts)).fetchone()
        send = prev is None or prev["reader_id"] != reader_id
    else:   # lost, off
        send = False
    if send:
        notify([tag["owner_id"]], title="Your bike was seen",
               body=f"{name} at {where}, {when}", url="/me.html#/activity", tag=f"seen-{tag['uid']}")


def insert_scan(db, reader_id, uid, ts=None, readers=None, event_id=None):
    """Judge the scan against the registry, store it, raise alerts. Returns the scan row
    as a dict; if event_id was already stored, returns that existing row with
    "duplicate": True and changes nothing."""
    ts = ts or iso(utcnow())
    uid = norm_uid(uid)
    readers = readers if readers is not None else load_readers()
    if event_id:
        existing = db.execute("SELECT * FROM scans WHERE event_id = ?", (event_id,)).fetchone()
        if existing:
            return {**dict(existing), "duplicate": True}
    tag = db.execute("SELECT * FROM tags WHERE uid = ?", (uid,)).fetchone()
    if tag and tag["authorized"]:
        authorized, reason = 1, "registered"
    elif tag:
        authorized, reason = 0, "revoked"
    else:
        authorized, reason = 0, "unregistered"

    cur = db.execute("INSERT INTO scans (ts, reader_id, uid, authorized, reason, event_id) VALUES (?,?,?,?,?,?)",
                     (ts, reader_id, uid, authorized, reason, event_id or None))
    scan_id = cur.lastrowid
    touch_reader(db, reader_id, ts)

    where = readers[reader_id]["name"] if reader_id in readers else reader_id
    if reader_id not in readers:
        raise_alert(db, ts, "unknown_reader", "serious",
                    f"Scan received from reader '{reader_id}', which is not in readers.json", reader_id, uid)
    if not authorized:
        who = f"{tag['owner'] or 'unnamed'}'s revoked tag" if tag else "unregistered tag"
        raise_alert(db, ts, "denied", "serious" if tag else "warning", f"Denied {who} {uid} at {where}", reader_id, uid)
        window_start = iso(parse_ts(ts) - timedelta(minutes=REPEAT_WINDOW_MIN))
        n = db.execute("SELECT COUNT(*) FROM scans WHERE uid = ? AND authorized = 0 AND ts >= ?",
                       (uid, window_start)).fetchone()[0]
        already = db.execute("SELECT COUNT(*) FROM alerts WHERE type = 'repeated_denied' AND uid = ? AND ts >= ?",
                             (uid, window_start)).fetchone()[0]
        if n >= REPEAT_THRESHOLD and not already:
            raise_alert(db, ts, "repeated_denied", "critical",
                        f"Tag {uid} denied {n} times in {REPEAT_WINDOW_MIN} minutes (last at {where})", reader_id, uid)
    db.commit()
    row = {**dict(db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()), "duplicate": False}
    publish("scan", reader_id, f"{uid} {'AUTHORIZED' if authorized else 'DENIED (' + reason + ')'} at {where}",
            uid=uid, authorized=bool(authorized), reason=reason, scan_id=scan_id)
    notify_owner_of_scan(db, tag, reader_id, where, ts, authorized)
    return row


def check_offline(db, readers):
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
DEMO_USERS = [("admin", "admin123", "Campus Staff", "staff"),
              ("kripal", "pass123", "Kripal M.", "student"),
              ("nihar", "pass123", "Nihar R.", "student")]


def seed_demo(db):
    readers = load_readers()
    now = utcnow()
    random.seed(7)
    ids = {}
    for username, pw, name, role in DEMO_USERS:
        row = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        ids[username] = row["id"] if row else create_user(db, username, pw, name, role)
    tags = [("DEADBEEF", "Kripal M.", "Blue Trek FX", 1, ids["kripal"]),
            ("04A3B2C1", "Nihar R.", "Black Specialized", 1, ids["nihar"]),
            ("C0FFEE42", "Kripal M.", "Old commuter bike", 0, ids["kripal"]),   # reported lost
            ("1F2E3D4C", "Former student", "Returned bike", 0, None)]
    for uid, owner, label, auth, owner_id in tags:
        db.execute("INSERT OR IGNORE INTO tags (uid, owner, label, authorized, created_at, owner_id) VALUES (?,?,?,?,?,?)",
                   (uid, owner, label, auth, iso(now - timedelta(days=10)), owner_id))
    db.commit()
    seen = ["DEADBEEF", "DEADBEEF", "DEADBEEF", "04A3B2C1", "04A3B2C1", "1F2E3D4C", "C0FFEE42", "A1B2C3D4", "7E8F9A0B"]
    stamps = sorted(now - timedelta(minutes=random.randint(5, 3 * 24 * 60)) for _ in range(70))
    for ts in stamps:
        insert_scan(db, random.choice(list(readers)), random.choice(seen), iso(ts), readers)
    for i in range(3):
        insert_scan(db, "rack-02", "7E8F9A0B", iso(now - timedelta(minutes=4 - i)), readers)
    insert_scan(db, "rack-99", "A1B2C3D4", iso(now - timedelta(minutes=30)), readers)
    for rid, age in [(rid, 5) for rid in readers]:
        touch_reader(db, rid, iso(now - timedelta(seconds=age)), {"transport": "demo"})
    db.commit()
    print("Seeded demo users, tags, scans, heartbeats")
    print("Demo logins:  " + "   ".join(f"{u} / {p} ({r})" for u, p, _, r in DEMO_USERS))


# --------------------------------------------------------------------------- HTTP
class AuthError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


class Handler(SimpleHTTPRequestHandler):
    timeout = 10
    protocol_version = "HTTP/1.1"

    def __init__(self, *args, **kwargs):
        self.user = None
        super().__init__(*args, directory=HERE, **kwargs)

    def handle(self):
        # A browser closing its event stream (or any client going away mid-response)
        # is normal; don't let it print a traceback.
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass

    # ---- helpers
    def end_headers(self):
        self.send_header("Cache-Control", "no-cache")
        super().end_headers()

    def _json(self, status, payload, cookie=None):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        return json.loads(raw or b"{}")

    def log_message(self, fmt, *args):
        line = str(args[0]) if args else ""
        if line.startswith("GET /api/"):
            return
        super().log_message(fmt, *args)

    # ---- auth
    def _session_user(self, db):
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        if "session" not in cookie:
            return None
        row = db.execute("SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id "
                         "WHERE s.token = ? AND s.expires_at > ?", (cookie["session"].value, iso(utcnow()))).fetchone()
        return dict(row) if row else None

    def _require(self, access):
        """Resolve self.user and enforce the route's access level."""
        db = open_db()
        self.user = self._session_user(db)
        db.close()
        if access == "public":
            return
        if access == "device":
            key = self.headers.get("X-Device-Key", "")
            if hmac.compare_digest(key, device_key()) or (self.user and self.user["role"] == "staff"):
                return
            raise AuthError(401, "device key required (X-Device-Key header, see dashboard/device_key.txt)")
        if not self.user:
            raise AuthError(401, "login required")
        if access == "staff" and self.user["role"] != "staff":
            raise AuthError(403, "staff only")

    @property
    def is_staff(self):
        return bool(self.user) and self.user["role"] == "staff"

    def _owner_filter(self, q):
        """Returns (sql fragment, params) restricting tags to an owner, or ('', ()) for everything."""
        if not self.is_staff:
            return " uid IN (SELECT uid FROM tags WHERE owner_id = ?) ", (self.user["id"],)
        owner = q.get("owner", [None])[0]
        if owner:
            return " uid IN (SELECT uid FROM tags WHERE owner_id = ?) ", (int(owner),)
        return "", ()

    # ---- routing: (method, pattern, handler, access)
    ROUTES = [
        ("POST",   r"^/api/auth/login$",            "login",            "public"),
        ("POST",   r"^/api/auth/register$",         "register",         "public"),
        ("POST",   r"^/api/auth/logout$",           "logout",           "user"),
        ("GET",    r"^/api/auth/me$",               "me",               "user"),
        ("POST",   r"^/api/auth/password$",         "change_password",  "user"),
        ("PUT",    r"^/api/auth/email$",            "set_email",        "user"),
        ("POST",   r"^/api/auth/forgot$",           "forgot_password",  "public"),
        ("POST",   r"^/api/auth/reset$",            "reset_password",   "public"),
        ("GET",    r"^/api/push$",                  "get_push",         "user"),
        ("POST",   r"^/api/push/subscribe$",        "push_subscribe",   "user"),
        ("DELETE", r"^/api/push/subscribe$",        "push_unsubscribe", "user"),
        ("POST",   r"^/api/push/test$",             "push_test",        "user"),
        ("GET",    r"^/api/users$",                 "get_users",        "staff"),
        ("POST",   r"^/api/users$",                 "post_user",        "staff"),
        ("PUT",    r"^/api/users/(\d+)$",           "put_user",         "staff"),
        ("DELETE", r"^/api/users/(\d+)$",           "delete_user",      "staff"),
        ("GET",    r"^/api/scans$",                 "get_scans",        "user"),
        ("POST",   r"^/api/scans$",                 "post_scan",        "device"),
        ("DELETE", r"^/api/scans$",                 "delete_scans",     "staff"),
        ("POST",   r"^/api/heartbeat$",             "post_heartbeat",   "device"),
        ("POST",   r"^/api/log$",                   "post_log",         "device"),
        ("GET",    r"^/api/events$",                "get_events",       "user"),
        ("GET",    r"^/api/readers$",               "get_readers",      "user"),
        ("GET",    r"^/api/tags$",                  "get_tags",         "user"),
        ("POST",   r"^/api/tags$",                  "post_tag",         "user"),
        ("GET",    r"^/api/tags/unregistered$",     "get_unregistered", "staff"),
        ("PUT",    r"^/api/tags/([0-9A-Fa-f]+)$",   "put_tag",          "user"),
        ("DELETE", r"^/api/tags/([0-9A-Fa-f]+)$",   "delete_tag",       "user"),
        ("GET",    r"^/api/alerts$",                "get_alerts",       "user"),
        ("POST",   r"^/api/alerts/(\d+)/ack$",      "ack_alert",        "staff"),
        ("POST",   r"^/api/alerts/ack_all$",        "ack_all",          "staff"),
    ]

    def _dispatch(self, method):
        url = urlparse(self.path)
        if url.path == "/api/events":
            self.connection.settimeout(None)   # long-lived stream
        for m, pattern, name, access in self.ROUTES:
            if m != method:
                continue
            match = re.match(pattern, url.path)
            if match:
                try:
                    self._require(access)
                    getattr(self, name)(parse_qs(url.query), *match.groups())
                except AuthError as e:
                    self._json(e.status, {"error": str(e)})
                except (KeyError, ValueError, json.JSONDecodeError) as e:
                    self._json(400, {"error": f"bad request: {e}"})
                return True
        if url.path.startswith("/api/"):
            self._json(404, {"error": "not found"})
            return True
        return False

    def do_GET(self):
        if not self._dispatch("GET"):
            path = urlparse(self.path).path
            if path == "/":
                self.path = "/login.html"
            elif path.endswith((".db", ".txt", ".py", ".pyc", ".pem", ".sh")):   # never serve the database, keys or code
                return self._json(404, {"error": "not found"})
            elif path in ("/index.html", "/me.html"):
                # Send each role straight to its own page so a student never sees
                # the staff layout, not even for the moment before the page's own check.
                db = open_db()
                try: user = self._session_user(db)
                finally: db.close()
                if user and user["role"] != "staff" and path == "/index.html":
                    return self._redirect("/me.html")
                if user and user["role"] == "staff" and path == "/me.html":
                    return self._redirect("/index.html")
            super().do_GET()

    def _redirect(self, where):
        self.send_response(302)
        self.send_header("Location", where)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _api_only(self, method):
        if not self._dispatch(method):
            self._json(404, {"error": "not found"})

    def do_POST(self):   self._api_only("POST")
    def do_PUT(self):    self._api_only("PUT")
    def do_DELETE(self): self._api_only("DELETE")

    # ---- auth endpoints
    def _start_session(self, db, user_id):
        token = secrets.token_urlsafe(32)
        db.execute("INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,?,?)",
                   (token, user_id, iso(utcnow()), iso(utcnow() + timedelta(days=SESSION_DAYS))))
        db.commit()
        return f"session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_DAYS * 86400}"

    def login(self, q):
        data = self._body()
        username, password = str(data["username"]).strip().lower(), str(data["password"])
        db = open_db()
        row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if not row or not check_password(password, row["password_hash"]):
            db.close()
            return self._json(401, {"error": "wrong username or password"})
        cookie = self._start_session(db, row["id"])
        db.close()
        print(f"login: {username} ({row['role']})")
        self._json(200, {"user": public_user(row)}, cookie=cookie)

    def register(self, q):
        data = self._body()
        db = open_db()
        try:
            uid = create_user(db, str(data["username"]), str(data["password"]), str(data.get("display_name", "")), "student",
                              str(data.get("email", "")))
        except ValueError as e:
            db.close()
            return self._json(400, {"error": str(e)})
        row = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        cookie = self._start_session(db, uid)
        db.close()
        print(f"new student account: {row['username']}")
        self._json(201, {"user": public_user(row)}, cookie=cookie)

    def logout(self, q):
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        db = open_db()
        db.execute("DELETE FROM sessions WHERE token = ?", (cookie["session"].value,))
        db.commit(); db.close()
        self._json(200, {"ok": True}, cookie="session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")

    def me(self, q):
        self._json(200, {"user": public_user(self.user)})

    # ---- users (staff)
    def get_users(self, q):
        db = open_db()
        rows = db.execute("SELECT u.*, COUNT(t.uid) AS tags FROM users u LEFT JOIN tags t ON t.owner_id = u.id "
                          "GROUP BY u.id ORDER BY u.role, u.display_name").fetchall()
        db.close()
        self._json(200, {"users": [{**public_user(r), "tags": r["tags"]} for r in rows]})

    def post_user(self, q):
        data = self._body()
        db = open_db()
        try:
            uid = create_user(db, str(data["username"]), str(data["password"]),
                              str(data.get("display_name", "")), str(data.get("role", "student")), str(data.get("email", "")))
        except ValueError as e:
            db.close()
            return self._json(400, {"error": str(e)})
        row = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        db.close()
        self._json(201, {"user": public_user(row)})

    def put_user(self, q, user_id):
        data = self._body()
        fields, values = [], []
        if "display_name" in data:
            fields.append("display_name = ?"); values.append(str(data["display_name"]).strip())
        if "email" in data:
            email = str(data["email"]).strip().lower()
            if email and not valid_email(email):
                return self._json(400, {"error": "that does not look like an email address"})
            fields.append("email = ?"); values.append(email)
        if "role" in data:
            if data["role"] not in ("staff", "student"):
                return self._json(400, {"error": "role must be staff or student"})
            if int(user_id) == self.user["id"] and data["role"] != "staff":
                return self._json(400, {"error": "you cannot remove your own staff role"})
            fields.append("role = ?"); values.append(data["role"])
        if "password" in data:
            if len(str(data["password"])) < 6:
                return self._json(400, {"error": "password must be at least 6 characters"})
            fields.append("password_hash = ?"); values.append(hash_password(str(data["password"])))
        if not fields:
            return self._json(400, {"error": "nothing to update"})
        db = open_db()
        cur = db.execute(f"UPDATE users SET {', '.join(fields)} WHERE id = ?", (*values, int(user_id)))
        if "display_name = ?" in fields:   # keep the display text on tags in sync
            db.execute("UPDATE tags SET owner = ? WHERE owner_id = ?", (values[0], int(user_id)))
        db.commit(); db.close()
        self._json(200 if cur.rowcount else 404, {"updated": bool(cur.rowcount)})

    def delete_user(self, q, user_id):
        if int(user_id) == self.user["id"]:
            return self._json(400, {"error": "you cannot delete your own account"})
        db = open_db()
        db.execute("UPDATE tags SET owner_id = NULL WHERE owner_id = ?", (int(user_id),))
        db.execute("DELETE FROM sessions WHERE user_id = ?", (int(user_id),))
        cur = db.execute("DELETE FROM users WHERE id = ?", (int(user_id),))
        db.commit(); db.close()
        self._json(200 if cur.rowcount else 404, {"deleted": bool(cur.rowcount)})

    # ---- scans
    def get_scans(self, q):
        since = q.get("since", [None])[0]
        limit = min(int(q.get("limit", ["2000"])[0]), 10000)
        where, params = self._owner_filter(q)
        clauses = [c for c in [where, "ts >= ?" if since else ""] if c]
        params = params + ((since,) if since else ())
        sql = "SELECT id, ts, reader_id, uid, authorized, reason FROM scans "
        if clauses:
            sql += "WHERE " + " AND ".join(clauses) + " "
        sql += "ORDER BY ts DESC, id DESC LIMIT ?"
        db = open_db()
        rows = db.execute(sql, (*params, limit)).fetchall()
        db.close()
        self._json(200, {"scans": [{**dict(r), "authorized": bool(r["authorized"])} for r in rows],
                         "server_time": iso(utcnow())})

    def post_scan(self, q):
        data = self._body()
        reader_id = str(data["reader_id"]).strip()
        uid = norm_uid(data["uid"])
        if not reader_id or not uid:
            return self._json(400, {"error": "reader_id and uid are required"})
        readers = load_readers()
        event_id = str(data["event_id"]).strip()[:64] if data.get("event_id") else None
        db = open_db()
        scan = insert_scan(db, reader_id, uid, data.get("ts"), readers, event_id)
        db.close()
        verdict = "AUTHORIZED" if scan["authorized"] else f"DENIED ({scan['reason']})"
        if scan["duplicate"]:
            print(f"scan #{scan['id']}: duplicate of {event_id}, ignored")
            return self._json(200, {"id": scan["id"], "authorized": bool(scan["authorized"]),
                                    "reason": scan["reason"], "known_reader": reader_id in readers, "duplicate": True})
        print(f"scan #{scan['id']}: {reader_id} {uid} {verdict}" + ("" if reader_id in readers else "  (reader not in readers.json)"))
        dev = data.get("device_authorized")
        if dev is not None and bool(dev) != bool(scan["authorized"]):
            print(f"  ! firmware said {'AUTHORIZED' if dev else 'DENIED'} but registry says {verdict}")
        self._json(201, {"id": scan["id"], "authorized": bool(scan["authorized"]),
                         "reason": scan["reason"], "known_reader": reader_id in readers, "duplicate": False})

    def delete_scans(self, q):
        db = open_db()
        db.execute("DELETE FROM scans"); db.execute("DELETE FROM alerts")
        db.commit(); db.close()
        self._json(200, {"cleared": True})

    # ---- readers
    def post_heartbeat(self, q):
        data = self._body()
        reader_id = str(data["reader_id"]).strip()
        meta = {k: data[k] for k in ("transport", "ip", "pending", "dropped", "recoveries", "uptime_s", "fw", "rssi")
                if k in data}
        meta["from"] = self.client_address[0]
        db = open_db()
        touch_reader(db, reader_id, iso(utcnow()), meta)
        db.commit(); db.close()
        publish("heartbeat", reader_id,
                f"heartbeat via {meta.get('transport', '?')}" + (f", pending {meta['pending']}" if meta.get("pending") else "")
                + (f", {meta['recoveries']} recoveries" if meta.get("recoveries") else ""), **meta)
        self._json(200, {"ok": True, "known_reader": reader_id in load_readers()})

    def post_log(self, q):
        """Reader log lines (recoveries, antenna changes, Wi-Fi state...) for the Live tab."""
        data = self._body()
        reader_id = str(data.get("reader_id", "")).strip() or None
        lines = data.get("lines") or ([data["line"]] if "line" in data else [])
        for line in lines[:50]:
            publish("log", reader_id, str(line)[:300], transport=data.get("transport"))
        self._json(200, {"ok": True, "accepted": min(len(lines), 50)})

    def get_events(self, q):
        """Server-Sent Events stream of everything that happens, newest first replayed."""
        q_, history = subscribe()
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            # Chunked framing so proxies (the Cloudflare tunnel in particular)
            # forward each event as it is written instead of buffering an
            # unframed HTTP/1.1 body until the connection closes.
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()

            def chunk(b):
                return f"{len(b):X}\r\n".encode() + b + b"\r\n"

            for ev in history[-100:]:
                self.wfile.write(chunk(f"id: {ev['id']}\ndata: {json.dumps(ev)}\n\n".encode()))
            self.wfile.flush()
            while True:
                try:
                    ev = q_.get(timeout=15)
                    self.wfile.write(chunk(f"id: {ev['id']}\ndata: {json.dumps(ev)}\n\n".encode()))
                except queue.Empty:
                    self.wfile.write(chunk(b": keepalive\n\n"))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            unsubscribe(q_)

    def get_readers(self, q):
        readers = load_readers()
        db = open_db()
        check_offline(db, readers)
        status = {r["reader_id"]: r["last_seen"] for r in db.execute("SELECT * FROM reader_status")}
        metas = {r["reader_id"]: json.loads(r["meta"] or "{}") for r in db.execute("SELECT * FROM reader_status")}
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
            entry = {**r, "last_seen": seen, "online": online,
                     "status": "online" if online else ("offline" if seen else "never seen"),
                     "transport": metas.get(r["id"], {}).get("transport"), "meta": metas.get(r["id"], {})}
            if self.is_staff:
                entry.update({"scans_today": n, "denied_today": denied or 0})
            out.append(entry)
        self._json(200, {"readers": out, "offline_after_s": OFFLINE_AFTER_S})

    def change_password(self, q):
        """Anyone changes their own password; the current one is required and other devices are signed out."""
        data = self._body()
        current, new = str(data.get("current_password", "")), str(data.get("new_password", ""))
        if len(new) < 6:
            return self._json(400, {"error": "new password must be at least 6 characters"})
        db = open_db()
        row = db.execute("SELECT password_hash FROM users WHERE id = ?", (self.user["id"],)).fetchone()
        if not check_password(current, row["password_hash"]):
            db.close()
            return self._json(401, {"error": "current password is wrong"})
        token = SimpleCookie(self.headers.get("Cookie", ""))["session"].value
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(new), self.user["id"]))
        db.execute("DELETE FROM sessions WHERE user_id = ? AND token != ?", (self.user["id"], token))
        db.commit(); db.close()
        print(f"password changed: {self.user['username']}")
        self._json(200, {"ok": True})

    def set_email(self, q):
        email = str(self._body().get("email", "")).strip().lower()
        if email and not valid_email(email):
            return self._json(400, {"error": "that does not look like an email address"})
        db = open_db()
        db.execute("UPDATE users SET email = ? WHERE id = ?", (email, self.user["id"]))
        db.commit(); db.close()
        self._json(200, {"email": email})

    def forgot_password(self, q):
        """Step 1 of a self-service reset: email a one-time code to the address on the account."""
        username = str(self._body().get("username", "")).strip().lower()
        db = open_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if not user:
            db.close()
            return self._json(404, {"error": "no account with that username"})
        if not user["email"]:
            db.close()
            return self._json(400, {"error": "this account has no email on file; ask staff to reset the password"})
        recent = db.execute("SELECT created_at FROM password_resets WHERE user_id = ? ORDER BY id DESC LIMIT 1",
                            (user["id"],)).fetchone()
        if recent and (utcnow() - parse_ts(recent["created_at"])).total_seconds() < RESET_RESEND_S:
            db.close()
            return self._json(429, {"error": f"a code was sent less than {RESET_RESEND_S} seconds ago; check your inbox"})
        code = f"{secrets.randbelow(1_000_000):06d}"
        db.execute("UPDATE password_resets SET used = 1 WHERE user_id = ? AND used = 0", (user["id"],))
        db.execute("INSERT INTO password_resets (user_id, code_hash, created_at, expires_at) VALUES (?,?,?,?)",
                   (user["id"], hash_password(code), iso(utcnow()), iso(utcnow() + timedelta(minutes=RESET_CODE_MINUTES))))
        db.commit(); db.close()
        body = (f"Hi {user['display_name']},\n\nYour RFID Scan Log password reset code is:\n\n    {code}\n\n"
                f"It works for {RESET_CODE_MINUTES} minutes. If you did not ask for this, you can ignore this email; "
                f"your password has not changed.\n")
        try:
            sent = send_mail(user["email"], "Your password reset code", body)
        except Exception as e:
            print(f"mail: sending to {mask_email(user['email'])} failed: {type(e).__name__}: {e}")
            return self._json(502, {"error": "could not send the email; ask staff to reset the password"})
        if not sent:
            print(f"RESET CODE for {username}: {code}   (mail is not configured, see mail_config.example.json)")
        print(f"password reset code {'emailed' if sent else 'printed'} for {username}")
        self._json(200, {"sent": sent, "email": mask_email(user["email"]), "minutes": RESET_CODE_MINUTES,
                         "note": None if sent else "email is not configured on this server; the code was printed on the server console"})

    def reset_password(self, q):
        """Step 2: the code from the email plus the new password."""
        data = self._body()
        username, code, new = str(data.get("username", "")).strip().lower(), str(data.get("code", "")).strip(), str(data.get("new_password", ""))
        if len(new) < 6:
            return self._json(400, {"error": "new password must be at least 6 characters"})
        db = open_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        pr = db.execute("SELECT * FROM password_resets WHERE user_id = ? AND used = 0 ORDER BY id DESC LIMIT 1",
                        (user["id"],)).fetchone() if user else None
        if not pr or parse_ts(pr["expires_at"]) < utcnow():
            db.close()
            return self._json(400, {"error": "no valid code for this account; request a new one"})
        if pr["attempts"] >= RESET_MAX_ATTEMPTS:
            db.close()
            return self._json(429, {"error": "too many wrong codes; request a new one"})
        if not check_password(code, pr["code_hash"]):
            db.execute("UPDATE password_resets SET attempts = attempts + 1 WHERE id = ?", (pr["id"],))
            db.commit(); db.close()
            return self._json(401, {"error": f"wrong code ({RESET_MAX_ATTEMPTS - pr['attempts'] - 1} tries left)"})
        db.execute("UPDATE password_resets SET used = 1 WHERE id = ?", (pr["id"],))
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(new), user["id"]))
        db.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))
        db.commit(); db.close()
        print(f"password reset by email code: {username}")
        self._json(200, {"ok": True})

    # ---- notifications
    def get_push(self, q):
        db = open_db()
        mine = db.execute("SELECT endpoint, user_agent, created_at, last_sent FROM push_subscriptions WHERE user_id = ? "
                          "ORDER BY created_at", (self.user["id"],)).fetchall()
        db.close()
        self._json(200, {"enabled": PUSH_AVAILABLE, "public_key": vapid_public_key() if PUSH_AVAILABLE else None,
                         "subscriptions": [dict(r) for r in mine],
                         "hint": None if PUSH_AVAILABLE else "install pywebpush on the server: python3 -m pip install pywebpush"})

    def push_subscribe(self, q):
        if not PUSH_AVAILABLE:
            return self._json(503, {"error": "notifications are not enabled on this server (pip install pywebpush)"})
        data = self._body()
        sub = data["subscription"]
        endpoint, keys = str(sub["endpoint"]), sub["keys"]
        if not endpoint.startswith("https://"):
            return self._json(400, {"error": "bad subscription"})
        db = open_db()
        db.execute("INSERT INTO push_subscriptions (user_id, endpoint, p256dh, auth, user_agent, created_at) VALUES (?,?,?,?,?,?) "
                   "ON CONFLICT(endpoint) DO UPDATE SET user_id = excluded.user_id, p256dh = excluded.p256dh, "
                   "auth = excluded.auth, user_agent = excluded.user_agent",
                   (self.user["id"], endpoint, str(keys["p256dh"]), str(keys["auth"]),
                    str(data.get("user_agent", ""))[:200], iso(utcnow())))
        db.commit()
        n = db.execute("SELECT COUNT(*) FROM push_subscriptions WHERE user_id = ?", (self.user["id"],)).fetchone()[0]
        db.close()
        print(f"push: {self.user['username']} subscribed a device ({n} total)")
        self._json(201, {"ok": True, "subscriptions": n})

    def push_unsubscribe(self, q):
        data = self._body()
        db = open_db()
        cur = db.execute("DELETE FROM push_subscriptions WHERE user_id = ? AND endpoint = ?",
                         (self.user["id"], str(data.get("endpoint", ""))))
        db.commit(); db.close()
        self._json(200, {"removed": cur.rowcount})

    def push_test(self, q):
        if not PUSH_AVAILABLE:
            return self._json(503, {"error": "notifications are not enabled on this server"})
        notify([self.user["id"]], title="Notifications are on",
               body=f"Hi {self.user['display_name']}, this device will be told when your bikes are scanned.",
               url="/me.html" if self.user["role"] != "staff" else "/index.html#/alerts", tag="test")
        self._json(200, {"queued": True})

    # ---- tags
    def get_tags(self, q):
        where, params = self._owner_filter(q)
        where = where.replace("uid IN (SELECT uid FROM tags WHERE owner_id = ?)", "t.owner_id = ?") if where else ""
        db = open_db()
        rows = db.execute(f"""
            SELECT t.*, u.username AS owner_username, COUNT(s.id) AS scans, MAX(s.ts) AS last_seen
            FROM tags t LEFT JOIN scans s ON s.uid = t.uid LEFT JOIN users u ON u.id = t.owner_id
            {('WHERE ' + where) if where else ''}
            GROUP BY t.uid ORDER BY t.created_at DESC""", params).fetchall()
        db.close()
        self._json(200, {"tags": [{**dict(r), "authorized": bool(r["authorized"])} for r in rows]})

    def _resolve_owner(self, db, data):
        """Staff may set owner_id; students always own what they register."""
        if not self.is_staff:
            return self.user["id"], self.user["display_name"]
        owner_id = data.get("owner_id")
        if owner_id in (None, "", 0):
            return None, str(data.get("owner", "")).strip()
        row = db.execute("SELECT * FROM users WHERE id = ?", (int(owner_id),)).fetchone()
        if not row:
            raise ValueError("owner_id does not match a user")
        return row["id"], row["display_name"]

    def post_tag(self, q):
        data = self._body()
        uid = norm_uid(data["uid"])
        if len(uid) not in (8, 14, 20):
            return self._json(400, {"error": "uid must be 4, 7 or 10 bytes of hex (8, 14 or 20 hex digits)"})
        db = open_db()
        if db.execute("SELECT 1 FROM tags WHERE uid = ?", (uid,)).fetchone():
            db.close()
            return self._json(409, {"error": f"tag {uid} is already registered"})
        owner_id, owner = self._resolve_owner(db, data)
        db.execute("INSERT INTO tags (uid, owner, label, authorized, notes, created_at, owner_id) VALUES (?,?,?,?,?,?,?)",
                   (uid, owner, str(data.get("label", "")).strip(),
                    1 if data.get("authorized", True) else 0, str(data.get("notes", "")).strip(), iso(utcnow()), owner_id))
        db.commit(); db.close()
        print(f"tag registered: {uid} -> {owner or 'no owner'} (by {self.user['username']})")
        self._json(201, {"uid": uid})

    def _own_tag_or_403(self, db, uid):
        tag = db.execute("SELECT * FROM tags WHERE uid = ?", (uid,)).fetchone()
        if not tag:
            raise AuthError(404, "tag not found")
        if not self.is_staff and tag["owner_id"] != self.user["id"]:
            raise AuthError(403, "that tag is not yours")
        return tag

    def put_tag(self, q, uid):
        uid = norm_uid(uid)
        data = self._body()
        db = open_db()
        try:
            self._own_tag_or_403(db, uid)
            fields, values = [], []
            for k in ("label", "notes") + (("owner",) if self.is_staff else ()):
                if k in data:
                    fields.append(f"{k} = ?"); values.append(str(data[k]).strip())
            if "authorized" in data:
                fields.append("authorized = ?"); values.append(1 if data["authorized"] else 0)
            if "notify" in data:
                if data["notify"] not in NOTIFY_CHOICES:
                    return self._json(400, {"error": f"notify must be one of {', '.join(NOTIFY_CHOICES)}"})
                fields.append("notify = ?"); values.append(data["notify"])
            if self.is_staff and "owner_id" in data:
                owner_id, owner = self._resolve_owner(db, data)
                fields += ["owner_id = ?", "owner = ?"]; values += [owner_id, owner]
            if not fields:
                return self._json(400, {"error": "nothing to update"})
            db.execute(f"UPDATE tags SET {', '.join(fields)} WHERE uid = ?", (*values, uid))
            db.commit()
        except AuthError as e:
            return self._json(e.status, {"error": str(e)})
        finally:
            db.close()
        self._json(200, {"uid": uid, "updated": [f.split(' ')[0] for f in fields]})

    def delete_tag(self, q, uid):
        uid = norm_uid(uid)
        db = open_db()
        try:
            self._own_tag_or_403(db, uid)
            db.execute("DELETE FROM tags WHERE uid = ?", (uid,))
            db.commit()
        except AuthError as e:
            return self._json(e.status, {"error": str(e)})
        finally:
            db.close()
        self._json(200, {"deleted": True})

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
        where, params = self._owner_filter(q)
        clauses = [c for c in [where, "" if include_acked else "acknowledged = 0"] if c]
        db = open_db()
        check_offline(db, load_readers())
        sql = "SELECT * FROM alerts " + (("WHERE " + " AND ".join(clauses) + " ") if clauses else "") + "ORDER BY ts DESC, id DESC LIMIT 500"
        rows = db.execute(sql, params).fetchall()
        open_sql = "SELECT COUNT(*) FROM alerts WHERE acknowledged = 0" + ((" AND " + where) if where else "")
        open_count = db.execute(open_sql, params).fetchone()[0]
        db.close()
        self._json(200, {"alerts": [{**dict(r), "acknowledged": bool(r["acknowledged"])} for r in rows], "open": open_count})

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
    ap.add_argument("--demo", action="store_true", help="seed sample users, tags, scans and alerts on startup")
    ap.add_argument("--create-user", metavar="USERNAME", help="create an account (prompts for the password) and exit")
    ap.add_argument("--role", default="staff", choices=["staff", "student"], help="role for --create-user")
    args = ap.parse_args()

    if not os.path.exists(READERS_PATH):
        sys.exit(f"missing {READERS_PATH}")
    db = open_db()
    if args.create_user:
        pw = getpass.getpass(f"Password for {args.create_user}: ")
        try:
            create_user(db, args.create_user, pw, args.create_user, args.role)
        except ValueError as e:
            sys.exit(str(e))
        print(f"created {args.role} account '{args.create_user.lower()}'")
        return
    if args.demo:
        seed_demo(db)
    n_staff = db.execute("SELECT COUNT(*) FROM users WHERE role = 'staff'").fetchone()[0]
    db.close()
    if n_staff == 0:
        print("No staff account yet. Create one with:  python3 server.py --create-user admin --role staff")

    try:
        srv = ThreadingHTTPServer((args.host, args.port), Handler)
        srv.daemon_threads = True
    except OSError as e:
        sys.exit(f"Could not listen on port {args.port} ({e.strerror}). "
                 f"Another program is using it; try:  python3 server.py --port {args.port + 1}")
    print(f"Dashboard:  http://{'localhost' if args.host in ('127.0.0.1', '0.0.0.0') else args.host}:{args.port}")
    print(f"Scans DB:   {DB_PATH}")
    print(f"Device key: {DEVICE_KEY_PATH}  (readers / serial_bridge.py send it as X-Device-Key)")
    device_key()
    print(f"Email:      {'configured (' + mail_config()['smtp_host'] + ')' if mail_config() else 'not configured; reset codes print here (see mail_config.example.json)'}")
    if PUSH_AVAILABLE:
        vapid_private_pem()
        threading.Thread(target=_notify_worker, daemon=True, name="notify").start()
        print("Push notifications: enabled (browsers need HTTPS or localhost; run tunnel.sh for a public HTTPS link)")
    else:
        print("Push notifications: off (python3 -m pip install pywebpush to enable)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
