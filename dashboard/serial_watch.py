#!/usr/bin/env python3
"""
Watch the reader's serial output with timestamps, without the server.

Prints every line the Pico sends with the seconds since start, acknowledges each
SCAN so the reader stops re-sending it, and shows the gap between consecutive
scans (handy for checking that two tags presented together are both read).

    python3 serial_watch.py                 # auto-detects /dev/cu.usbmodem*
    python3 serial_watch.py --port /dev/cu.usbmodem11301
Stop with Ctrl+C; a summary is printed.
"""
import argparse, glob, sys, time, collections
try:
    import serial
except ImportError:
    sys.exit("pyserial is not installed. Run:  python3 -m pip install pyserial")

ap = argparse.ArgumentParser()
ap.add_argument("--port"); ap.add_argument("--baud", type=int, default=115200)
args = ap.parse_args()
port = args.port or (sorted(glob.glob("/dev/cu.usbmodem*") + glob.glob("/dev/ttyACM*")) or [None])[0]
if not port:
    sys.exit("No Pico serial port found. Plug it in, or pass --port.")

counts = collections.Counter(); acked = set(); last_scan = None; t0 = time.time()
print(f"watching {port}  (Ctrl+C to stop)")
try:
    with serial.Serial(port, args.baud, timeout=0.2) as ser:
        ser.write(b"HELLO\n")
        while True:
            raw = ser.readline()
            if not raw:
                continue
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            t = time.time() - t0
            if line.startswith("SCAN,"):
                parts = line.split(","); seq = parts[-1]
                if seq in acked:
                    continue                      # a re-send we already saw
                acked.add(seq); ser.write(f"ACK,{seq}\n".encode())
                gap = f"   (+{(t - last_scan) * 1000:.0f} ms after previous scan)" if last_scan is not None else ""
                last_scan = t
                print(f"+{t:6.2f}s  SCAN  uid={parts[2]}  seq={seq}{gap}"); counts["scans"] += 1
            elif "recovery" in line:
                print(f"+{t:6.2f}s  {line}"); counts["recoveries"] += 1
            elif "UID read failed" in line:
                print(f"+{t:6.2f}s  {line}"); counts["uid read failed"] += 1
            elif line.startswith(">>>"):
                continue                          # the SCAN line carries the verdict
            else:
                print(f"+{t:6.2f}s  {line}")
except KeyboardInterrupt:
    pass
except serial.SerialException as e:
    sys.exit(f"serial error: {e}  (is the bridge or the serial monitor using the port?)")
print("\nsummary:", dict(counts) or "nothing received")
