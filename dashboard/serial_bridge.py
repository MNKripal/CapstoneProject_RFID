#!/usr/bin/env python3
"""
Forwards scans from the Pico's USB serial output to the dashboard server.

The firmware prints one line per scan:
    SCAN,<reader_id>,<uid hex>,<1|0>
This script watches for those lines and POSTs them to /api/scans. Everything
else the Pico prints is echoed so you still see the normal log.

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


def post_scan(server, reader_id, uid, authorized):
    body = json.dumps({"reader_id": reader_id, "uid": uid, "authorized": authorized}).encode()
    req = urllib.request.Request(f"{server}/api/scans", data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


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
                    print(f"[pico] {line}")
                    if not line.startswith("SCAN,"):
                        continue
                    parts = line.split(",")
                    if len(parts) != 4:
                        print(f"  ! malformed SCAN line ignored")
                        continue
                    _, reader_id, uid, auth = parts
                    try:
                        r = post_scan(args.server, reader_id, uid, auth.strip() == "1")
                        note = "" if r.get("known_reader") else "  (reader id not in readers.json)"
                        print(f"  -> logged as scan #{r['id']}{note}")
                    except (urllib.error.URLError, OSError) as e:
                        print(f"  ! could not reach server: {e}")
        except serial.SerialException as e:
            print(f"Serial error: {e}. Retrying in 2 s...")
            time.sleep(2)
        except KeyboardInterrupt:
            print("\nBye")
            return


if __name__ == "__main__":
    main()
