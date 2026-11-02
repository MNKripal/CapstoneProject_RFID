#!/usr/bin/env python3
"""
Forwards scans and heartbeats from the Pico's USB serial output to the dashboard
server, and acknowledges each scan so the reader can drop it from its buffer.

Lines the firmware prints:
    BOOT,<reader_id>,<boot_id>,pending=<n>              at start-up and in reply to HELLO
    SCAN,<reader_id>,<uid hex>,<1|0>,<boot_id>,<seq>    one per tag read (re-sent every 3 s until acknowledged)
    HB,<reader_id>,pending=<n>,dropped=<n>              every 30 s
    WARN,<reader_id>,<text>                             buffer full, a scan was dropped
Lines this script writes back:
    HELLO                                               on connect, asks the reader to re-send what is pending
    ACK,<seq>                                           after a scan was stored by the server

Delivery guarantee: a scan is acknowledged only after the server has stored it.
If the server is down the reader keeps re-sending, and the server ignores a
repeat of the same <reader>-<boot>-<seq> event id, so nothing is lost or doubled.

The server only accepts scans that carry the device key (dashboard/device_key.txt,
created the first time server.py runs). The bridge reads that file automatically
when it runs from the dashboard folder; otherwise pass --key.

Requires pyserial:  python3 -m pip install pyserial

    python3 serial_bridge.py                       # auto-detects /dev/cu.usbmodem*
    python3 serial_bridge.py --port /dev/cu.usbmodem1101 --server http://localhost:8080
"""
import argparse
import functools
import glob
import json
import os
import sys
import time
import urllib.error
import urllib.request

print = functools.partial(print, flush=True)  # show lines immediately even when piped to a file

try:
    import serial
except ImportError:
    sys.exit("pyserial is not installed. Run:  python3 -m pip install pyserial")

DEVICE_KEY = ""


def find_port():
    candidates = sorted(glob.glob("/dev/cu.usbmodem*") + glob.glob("/dev/ttyACM*"))
    if not candidates:
        sys.exit("No Pico serial port found. Plug it in, or pass --port.")
    return candidates[0]


def post(server, path, payload):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(f"{server}{path}", data=body,
                                 headers={"Content-Type": "application/json", "X-Device-Key": DEVICE_KEY}, method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


def handle_line(line, server, ser, stored):
    """Process one line from the reader. `stored` is the set of event ids already
    confirmed by the server in this session; `ser` is used to write ACKs."""
    parts = line.split(",")
    kind = parts[0]
    if kind == "HB" and len(parts) >= 2:
        r = post(server, "/api/heartbeat", {"reader_id": parts[1].strip()})
        if not r.get("known_reader"):
            print(f"  ! reader '{parts[1].strip()}' is not in readers.json")
        extra = [p for p in parts[2:] if not p.startswith("pending=0") and not p.startswith("dropped=0")]
        if extra:
            print(f"  reader reports {', '.join(extra)}")
    elif kind == "SCAN" and len(parts) >= 4:
        reader_id, uid, auth = parts[1], parts[2], parts[3].strip() == "1"
        event_id = None
        seq = None
        if len(parts) >= 6:                      # new format with boot id and sequence number
            event_id = f"{reader_id}-{parts[4]}-{parts[5].strip()}"
            seq = parts[5].strip()
        if event_id and event_id in stored:       # a re-send of something we already stored: just ACK again
            ser.write(f"ACK,{seq}\n".encode())
            return
        payload = {"reader_id": reader_id, "uid": uid, "device_authorized": auth}
        if event_id:
            payload["event_id"] = event_id
        r = post(server, "/api/scans", payload)
        verdict = "AUTHORIZED" if r["authorized"] else f"DENIED ({r['reason']})"
        dup = "  (server already had it)" if r.get("duplicate") else ""
        print(f"  -> scan #{r['id']} {verdict}{dup}" + ("" if r.get("known_reader") else "  (reader id not in readers.json)"))
        if auth != r["authorized"]:
            print(f"  ! firmware said {'AUTHORIZED' if auth else 'DENIED'} but the registry says {verdict}. "
                  f"Update AUTHORIZED_UID in blink_any.c or the registry so they agree.")
        if event_id:
            stored.add(event_id)
            ser.write(f"ACK,{seq}\n".encode())
    elif kind == "BOOT":
        print(f"  reader {parts[1] if len(parts) > 1 else '?'} is up (boot {parts[2] if len(parts) > 2 else '?'}, {parts[3] if len(parts) > 3 else ''})")
    elif kind == "WARN":
        print(f"  ! reader warning: {','.join(parts[2:])}")
    else:
        print("  ! malformed line ignored")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", help="serial device (default: first /dev/cu.usbmodem*)")
    ap.add_argument("--server", default="http://localhost:8080")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--key", help="device key (default: read dashboard/device_key.txt next to this script)")
    args = ap.parse_args()

    global DEVICE_KEY
    key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "device_key.txt")
    if args.key:
        DEVICE_KEY = args.key
    elif os.path.exists(key_path):
        with open(key_path) as f:
            DEVICE_KEY = f.read().strip()
    else:
        sys.exit(f"No device key. Start server.py once (it creates {key_path}) or pass --key.")

    port = args.port or find_port()
    print(f"Listening on {port}, forwarding to {args.server}")
    stored = set()

    while True:
        try:
            with serial.Serial(port, args.baud, timeout=1) as ser:
                ser.write(b"HELLO\n")           # ask the reader to re-send anything it is still holding
                while True:
                    raw = ser.readline()
                    if not raw:
                        continue
                    line = raw.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    if not line.startswith("HB,"):
                        print(f"[pico] {line}")
                    if line.startswith(("SCAN,", "HB,", "BOOT,", "WARN,")):
                        try:
                            handle_line(line, args.server, ser, stored)
                        except urllib.error.HTTPError as e:
                            print(f"  ! server rejected it: {e.code} {e.read().decode(errors='replace')[:120]}")
                        except (urllib.error.URLError, OSError, KeyError, ValueError) as e:
                            print(f"  ! could not forward to server: {e}  (the reader will re-send it)")
        except serial.SerialException as e:
            print(f"Serial error: {e}. Retrying in 2 s...")
            stored.clear()
            time.sleep(2)
        except KeyboardInterrupt:
            print("\nBye")
            return


if __name__ == "__main__":
    main()
