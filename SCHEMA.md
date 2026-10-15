# Data contract: RFID bike rack system

Sprint 8 intermediate product report. Last updated October 14, 2026.

This document describes the data that moves between the readers, the backend and
the dashboard. Everything marked **implemented** is what the code in this repository
does today (`blink_any.c`, `dashboard/server.py`, `dashboard/index.html`,
`dashboard/me.html`). Everything marked **planned** is the Sprint 8/9 contract for
reader integration over Wi-Fi and has not been built yet. We kept the two apart on
purpose so the report does not claim more than exists.

## Overview

A reader is a Raspberry Pi Pico 2 W with an MFRC522 module, mounted at a bike rack.
When a tag is tapped, the reader sends the tag UID and its own reader ID to the
backend. The backend checks the tag registry, stores the event, raises alerts if
needed, and the dashboard shows it.

```
 +------------------+      Wi-Fi (planned)        +---------------------+
 |  Reader          |  POST /api/v1/scans         |  Backend API        |
 |  Pico 2 W        | --------------------------> |  server.py          |
 |  + MFRC522       |  USB serial (today)         |  Python, SQLite     |
 |  READER_ID       | --> serial_bridge.py -----> |                     |
 +------------------+      POST /api/scans        +----------+----------+
                                                             |
                                                             v
                                                  +---------------------+
                                                  |  Validation         |
                                                  |  device key, fields |
                                                  |  tag registry check |
                                                  +----------+----------+
                                                             |
                                                             v
                                                  +---------------------+
                                                  |  Event log          |
                                                  |  scans, alerts,     |
                                                  |  reader_status      |
                                                  +----------+----------+
                                                             |
                                                             v
                                                  +---------------------+
                                                  |  Dashboard          |
                                                  |  staff: index.html  |
                                                  |  student: me.html   |
                                                  +---------------------+
```

Today the reader prints one line per event on its USB serial port and a laptop
script forwards it. The line formats are:

```
SCAN,<reader_id>,<uid hex>,<1|0>     one per tag read; last field is the firmware's own verdict
HB,<reader_id>                       every 30 seconds (HEARTBEAT_MS in blink_any.c)
```

Reader IDs in use come from `dashboard/readers.json`: `rack-01` Memorial Union,
`rack-02` Hayden Library, `rack-03` Engineering Center (ECG), `rack-04` Sun Devil
Fitness Complex. The coordinates there are approximate and still need to be measured
at the racks.

The reader firmware has no version string of its own yet. At startup it reads the
MFRC522 chip's version register and prints it (`Firmware Version: 0x91 = v1.0` or
`0x92 = v2.0`; `0x88` means a clone chip). Adding a `FIRMWARE_VERSION` define to
`blink_any.c` and sending it in the heartbeat is on the open items list.

## Entities

Types are SQLite column types as created in `server.py`. Timestamps are ISO 8601 in
UTC, for example `2026-10-14T06:14:43+00:00`.

### tag (table `tags`)

| Field | Type | Required | Notes |
| :--- | :--- | :--- | :--- |
| `uid` | TEXT, primary key | yes | Tag UID as uppercase hex, no spaces. 8, 14 or 20 hex digits (4, 7 or 10 byte UIDs). Example `DEADBEEF`. |
| `label` | TEXT | no | Bike description shown to the owner, for example `Blue Trek FX`. |
| `owner_id` | INTEGER | no | `users.id` of the owner. NULL when the tag was registered by name only. |
| `owner` | TEXT | no | Display name of the owner. Kept in sync with the user's display name. |
| `authorized` | INTEGER (0/1) | yes | 1 means the tag unlocks. 0 means revoked, or reported lost by the student. |
| `notes` | TEXT | no | Free text for staff. |
| `created_at` | TEXT | yes | When the tag was registered. |

Status is derived: `authorized = 1` shows as Authorized / Active, `authorized = 0`
shows as Revoked / Reported lost.

### user (table `users`)

| Field | Type | Required | Notes |
| :--- | :--- | :--- | :--- |
| `id` | INTEGER, primary key | yes | |
| `username` | TEXT, unique | yes | Lowercase. Letters, digits and `. _ @ + -`, 2 to 64 characters. An email address or ASURITE works. |
| `display_name` | TEXT | yes | Shown in the dashboard and copied to `tags.owner`. Defaults to the username. |
| `password_hash` | TEXT | yes | PBKDF2-HMAC-SHA256, 200,000 rounds, 16 byte salt. Never returned by the API. |
| `role` | TEXT | yes | `staff` or `student`. |
| `created_at` | TEXT | yes | |

There is no `email` or `phone` column. The username doubles as the email when a
student signs up with one. A separate `email` and `phone` field is **planned** if we
add notifications.

### reader (`readers.json` plus table `reader_status`)

Static facts about a reader live in `dashboard/readers.json` and are edited by hand.
Liveness is tracked in the `reader_status` table.

| Field | Type | Required | Notes |
| :--- | :--- | :--- | :--- |
| `id` | string | yes | Must equal `READER_ID` in that reader's firmware. Format `rack-NN`. |
| `name` | string | yes | Human readable location, for example `Hayden Library`. |
| `lat`, `lon` | number | yes | WGS 84 decimal degrees. |
| `last_seen` | TEXT | no | Latest heartbeat or scan time (`reader_status.last_seen`). NULL if never heard from. |
| `online` | boolean | derived | True when `last_seen` is within the last 120 seconds (`OFFLINE_AFTER_S`). |
| `status` | string | derived | `online`, `offline`, or `never seen`. |

### scan_event (table `scans`)

| Field | Type | Required | Notes |
| :--- | :--- | :--- | :--- |
| `id` | INTEGER, primary key | yes | **Implemented.** Auto-increment, assigned by the server. |
| `event_id` | TEXT, UUID v4 | yes | **Planned.** Generated on the reader; idempotency key for resends (see wire format). |
| `ts` | TEXT | yes | UTC time of the read. Today the server stamps it on arrival; a reader-supplied `ts` is accepted if present. |
| `reader_id` | TEXT | yes | The reader that saw the tag. Stored even if it is not in `readers.json` (that raises an alert). |
| `uid` | TEXT | yes | Tag UID, normalised like `tags.uid`. |
| `authorized` | INTEGER (0/1) | yes | Server's verdict from the registry. |
| `reason` | TEXT | yes | `registered`, `revoked` or `unregistered`. |
| `rssi` | INTEGER | no | **Planned.** Signal strength reported by the reader, dBm. The MFRC522 does not expose RSSI directly; we will use the RxGain setting and the retry count as a proxy until a better signal is found. |
| `read_quality` | TEXT | yes | **Planned.** `ok`, `marginal` or `failed`. Today only successful reads reach the server; failed UID reads are printed on serial as `Card present but UID read failed` and dropped. |
| `lat`, `lon` | REAL | no | **Planned.** Readers are fixed, so these are copied from `readers.json` at insert time rather than measured. |
| `buffered` | INTEGER (0/1) | no | **Planned.** 1 when the reader held the event during a network dropout and sent it later. |

### alert (table `alerts`)

| Field | Type | Required | Notes |
| :--- | :--- | :--- | :--- |
| `id` | INTEGER, primary key | yes | |
| `ts` | TEXT | yes | When the alert was raised. For scan-triggered alerts this equals the scan's `ts`. |
| `type` | TEXT | yes | `denied`, `repeated_denied`, `unknown_reader`, `reader_offline`. |
| `severity` | TEXT | yes | `warning`, `serious` or `critical`. |
| `reader_id` | TEXT | no | Reader involved, if any. |
| `uid` | TEXT | no | Tag involved, if any. Links the alert to the triggering scan together with `ts`. |
| `message` | TEXT | yes | Human readable text shown in the dashboard. |
| `acknowledged` | INTEGER (0/1) | yes | 0 is open. Staff acknowledge from the Alerts tab. `reader_offline` alerts clear themselves when the reader reports again. |

A direct `event_id` foreign key from alert to scan is **planned** once scans carry a
UUID. Today the pair (`uid`, `ts`) identifies the triggering scan.

Alert rules, as implemented in `server.py`:

| Type | Severity | Raised when |
| :--- | :--- | :--- |
| `denied` | `warning` (unregistered) or `serious` (revoked) | Any scan the registry rejects. |
| `repeated_denied` | `critical` | The same UID is denied 3 or more times within 10 minutes (`REPEAT_THRESHOLD`, `REPEAT_WINDOW_MIN`). Raised once per window. |
| `unknown_reader` | `serious` | A scan arrives from a `reader_id` that is not in `readers.json`. |
| `reader_offline` | `critical` | A known reader has sent nothing for 120 seconds. Checked whenever readers or alerts are listed. |

## Wire format

### Implemented today: one event per request

The serial bridge posts each line as it arrives. Authentication is a shared secret in
the `X-Device-Key` header, read from `dashboard/device_key.txt`.

```
POST /api/scans
Content-Type: application/json
X-Device-Key: <contents of device_key.txt>

{"reader_id": "rack-01", "uid": "DEADBEEF", "device_authorized": true}
```

```
201 Created
{"id": 61, "authorized": true, "reason": "registered", "known_reader": true}
```

`device_authorized` is optional. It is the firmware's own verdict from its hard-coded
UID; the server logs a warning when it disagrees with the registry.

Heartbeats use the same key:

```
POST /api/heartbeat
{"reader_id": "rack-01"}

200 OK
{"ok": true, "known_reader": true}
```

### Planned for Wi-Fi readers: batched events

When a reader loses Wi-Fi it keeps events in RAM and flushes them when the
connection returns, so the endpoint takes an array. A reader that is online sends
batches of one.

Request:

```
POST /api/v1/scans
Content-Type: application/json
X-Device-Key: <device key>

{
  "reader_id": "rack-02",
  "firmware_version": "0.3.0",
  "events": [
    {
      "event_id": "6f1c2a0e-5b7d-4e3a-9c21-0d8f4b2a7e10",
      "uid": "DEADBEEF",
      "ts": "2026-10-14T18:02:11Z",
      "rssi": -48,
      "read_quality": "ok",
      "buffered": false
    },
    {
      "event_id": "9b0e7d44-1c2f-4a6b-8e55-3f7a1c9d2b60",
      "uid": "C0FFEE42",
      "ts": "2026-10-14T17:58:40Z",
      "rssi": -71,
      "read_quality": "marginal",
      "buffered": true
    }
  ]
}
```

Response. The server answers per event so the reader knows exactly what to drop
from its buffer:

```
200 OK
{
  "accepted": 1,
  "rejected": 0,
  "duplicates": 1,
  "results": [
    {"event_id": "6f1c2a0e-5b7d-4e3a-9c21-0d8f4b2a7e10", "status": "accepted",
     "authorized": true, "reason": "registered"},
    {"event_id": "9b0e7d44-1c2f-4a6b-8e55-3f7a1c9d2b60", "status": "duplicate"}
  ]
}
```

`lat` and `lon` are not sent by the reader. The server fills them from
`readers.json` because the reader does not move.

## Validation rules

Rules 1 to 4 and 10 are enforced by `server.py` today. The rest apply to the batched
format and will be enforced with it.

1. `reader_id` and `uid` are required. A missing or empty value rejects the event
   with `missing_field`.
2. `uid` is normalised to uppercase hex with every non-hex character removed. After
   that it must be 8, 14 or 20 hex digits, otherwise `invalid_uid`.
3. The request must carry a valid `X-Device-Key`, otherwise the whole request is
   refused with HTTP 401 and nothing is stored. A signed-in staff session is accepted
   instead of the key, for testing with curl.
4. A `reader_id` that is not in `readers.json` is still stored, but raises an
   `unknown_reader` alert. It is not a rejection, because losing the event would
   hide a misconfigured reader.
5. `event_id` is required and must be a well-formed UUID (version 4), otherwise
   `invalid_event_id`.
6. `ts` must parse as ISO 8601. It may not be more than 5 minutes in the future and
   not more than 7 days in the past (the longest a reader could plausibly buffer),
   otherwise `invalid_timestamp`.
7. `read_quality` must be one of `ok`, `marginal`, `failed`, otherwise `invalid_enum`.
8. If `lat` and `lon` are sent they must be within -90..90 and -180..180, otherwise
   `invalid_coordinates`. They are ignored in favour of the reader's configured
   position anyway.
9. A batch holds at most 100 events. Larger batches are refused whole with
   `batch_too_large` so the reader splits them.
10. The request body must be valid JSON, otherwise HTTP 400 `bad_json`.

A batch is not all-or-nothing. Every valid event in it is stored and counted under
`accepted`; invalid ones are listed under `rejected` with their error code. Only
rules 3, 9 and 10 refuse the whole request.

`event_id` is the idempotency key. It is stored with a unique index, and an event
whose `event_id` already exists is reported as `duplicate` and otherwise ignored.
That makes buffered resends safe: if the reader sent a batch, lost the response, and
sends the same batch again, nothing is stored twice.

### Error codes

| HTTP | Code | Scope | Meaning |
| :--- | :--- | :--- | :--- |
| 400 | `bad_json` | request | Body is not valid JSON. |
| 400 | `missing_field` | event | A required field is absent or empty. |
| 400 | `invalid_uid` | event | UID is not 8, 14 or 20 hex digits after normalisation. |
| 400 | `invalid_event_id` | event | Not a UUID. |
| 400 | `invalid_timestamp` | event | Unparseable, or outside the sanity window. |
| 400 | `invalid_enum` | event | `read_quality` not in the allowed set. |
| 400 | `invalid_coordinates` | event | Out of range. |
| 400 | `batch_too_large` | request | More than 100 events. |
| 401 | `device_key_required` | request | Missing or wrong `X-Device-Key`. |
| 404 | `not_found` | request | Unknown path. |
| 409 | `duplicate` | event | `event_id` already stored. Reported in the results array, not as the HTTP status. |

Today the server returns errors as `{"error": "<message>"}` with the matching HTTP
status. The `code` field in the table is what the batched endpoint will add.

## Notes on failed reads

A tag read can fail part way: the reader sees a card but the anticollision or
select step times out. Today the firmware prints `Card present but UID read failed`
on serial and nothing reaches the server. After five failures in a row it
re-initialises the MFRC522.

With the batched format, `marginal` and `failed` reads are sent and stored like any
other event. `failed` events carry an empty `uid`. They appear in the staff Activity
log so a rack with a loose antenna or a bad tag can be spotted from the dashboard
instead of from the serial port. They do not count as taps for the student, do not
affect `authorized`, and do not raise alerts. Only an `ok` read goes through the
registry check.

## Open items

- **Auth on the scans endpoint.** The shared device key is the same for every reader
  and sits in a text file. A key per reader, stored in `readers.json`, would let us
  revoke one reader without reflashing the rest. HTTPS is also needed before the
  server leaves the lab network; the key is sent in clear text today.
- **Reader heartbeat endpoint.** `POST /api/heartbeat` exists and drives the
  online/offline status. The planned change is to add `firmware_version`,
  `uptime_s` and `buffered_events` to the heartbeat body so staff can see a reader
  that is alive but holding events it cannot deliver.
- **Retention policy.** Nothing is deleted. The scans and alerts tables grow without
  bound and the dashboard loads up to 5,000 scans per request. We need to decide a
  retention period for scans (90 days is the working proposal), whether failed reads
  should be kept for a shorter time, and whether to archive rather than delete for
  the end-of-year report.
- **Firmware version.** Add `FIRMWARE_VERSION` to `blink_any.c` and include it in
  the heartbeat, as above.
- **Reader coordinates.** Measure the real position of each rack and replace the
  approximate values in `readers.json`.
