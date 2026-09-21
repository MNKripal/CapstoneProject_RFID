#!/usr/bin/env python3
"""
Forwards scans and heartbeats from the Pico's USB serial output to the dashboard server.

The firmware prints:
    SCAN,<reader_id>,<uid hex>,<1|0>     one line per tag read (last field: firmware's own verdict)
    HB,<reader_id>                       every 30 s, so the server can tell the reader is alive
This script POSTs both to the server. The server's tag registry makes the
final authorized/denied decision; if it disagrees with the firmware's
hard-coded UID, a warning is printed here.

Requires pyserial:  python3 -m pip install pyserial

    python3 serial_bridge.py                       # auto-detects /dev/cu.usbmodem*
    python3 serial_bridge.py --port /dev/cu.usbmodem1101 --server http://localhost:8080
"""
import argparse
import glob
import json
import sys
import time
import urllib.error
import urllib.request

try:
    import serial
except ImportError:
    sys.exit("pyserial is not installed. Run:  python3 -m pip install pyserial")


def find_port():
    candidates = sorted(glob.glob("/dev/cu.usbmodem*") + glob.glob("/dev/ttyACM*"))
    if not candidates:
        sys.exit("No Pico serial port found. Plug it in, or pass --port.")
    return candidates[0]


def post(server, path, payload):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(f"{server}{path}", data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


def handle_line(line, server):
    parts = line.split(",")
    if parts[0] == "HB" and len(parts) == 2:
        r = post(server, "/api/heartbeat", {"reader_id": parts[1].strip()})
        if not r.get("known_reader"):
            print(f"  ! reader '{parts[1].strip()}' is not in readers.json")
    elif parts[0] == "SCAN" and len(parts) == 4:
        _, reader_id, uid, auth = parts
        device_auth = auth.strip() == "1"
        r = post(server, "/api/scans", {"reader_id": reader_id, "uid": uid, "device_authorized": device_auth})
        verdict = "AUTHORIZED" if r["authorized"] else f"DENIED ({r['reason']})"
        print(f"  -> scan #{r['id']} {verdict}" + ("" if r.get("known_reader") else "  (reader id not in readers.json)"))
        if device_auth != r["authorized"]:
            print(f"  ! firmware said {'AUTHORIZED' if device_auth else 'DENIED'} but the registry says {verdict}. "
                  f"Update AUTHORIZED_UID in blink_any.c or the registry so they agree.")
    else:
        print("  ! malformed line ignored")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", help="serial device (default: first /dev/cu.usbmodem*)")
    ap.add_argument("--server", default="http://localhost:8080")
    ap.add_argument("--baud", type=int, default=115200)
    args = ap.parse_args()

    port = args.port or find_port()
    print(f"Listening on {port}, forwarding to {args.server}")

    while True:
        try:
            with serial.Serial(port, args.baud, timeout=1) as ser:
                while True:
                    raw = ser.readline()
                    if not raw:
                        continue
                    line = raw.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    if not line.startswith("HB,"):
                        print(f"[pico] {line}")
                    if line.startswith(("SCAN,", "HB,")):
                        try:
                            handle_line(line, args.server)
                        except (urllib.error.URLError, OSError, KeyError, ValueError) as e:
                            print(f"  ! could not forward to server: {e}")
        except serial.SerialException as e:
            print(f"Serial error: {e}. Retrying in 2 s...")
            time.sleep(2)
        except KeyboardInterrupt:
            print("\nBye")
            return


if __name__ == "__main__":
    main()
