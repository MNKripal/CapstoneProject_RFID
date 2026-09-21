# RFID Logging System (Pico 2 W)

A high-performance embedded logging system built for the Raspberry Pi Pico 2 W (RP2350). This project utilizes the MFRC522 RFID module to scan physical tags, process their unique identifiers (UIDs), and log the data.

# Features
- Hardware: Optimized for the RP2350 (Cortex-M33) architecture.
- Communication: SPI-based communication with the RC522 module.
- Logging: Real-time hex UID output via USB-CDC (Serial Monitor).
- Feedback: Visual confirmation of tag detection via internal hardware polling.

# Hardware Setup

Hardware Target
- Board: Raspberry Pi Pico 2 W
- RFID Reader Module: MFRC522 RFID Module
- Processor: RP2350 (Dual-core ARM Cortex-M33)

# Development Environment

This project was developed and tested under the following environment:
Host System
- IDE: Visual Studio Code
- Extensions:
  * Raspberry Pi Pico VS Code Extension
  * CMake Tools

# MFRC522 to Pico 2 W Wiring

The firmware's pin assignments are defined in one place, at the top of `blink_any.c`
(`PIN_CS`, `PIN_SCK`, `PIN_MOSI`, `PIN_MISO`, `PIN_RST`). They must match the physical
wiring below; if the serial output reports `RC522 not responding`, compare the two.

| MFRC522 Pin | Pico 2 W GPIO | Physical Pin |
| :--- | :--- | :--- |
| **SDA** | GPIO 1 | Pin 2 |
| **SCK** | GPIO 2 | Pin 4 |
| **MOSI** | GPIO 3 | Pin 5 |
| **MISO** | GPIO 4 | Pin 6 |
| **GND** | GND | Pin 38 |
| **RST** | GPIO 0 | Pin 1 |
| **3.3V** | 3V3 | Pin 36 | 


# Scan Dashboard

The `dashboard/` folder contains a small web dashboard that logs every tag read together
with the location of the reader that saw it. Readers are mounted at fixed bike racks, so
each reader ID maps to a known campus coordinate in `dashboard/readers.json`.

```
dashboard/
  server.py         HTTP server + SQLite log + REST API (Python 3 standard library only)
  index.html        Dashboard page: stat tiles, campus map, scans-over-time chart, scan table
  readers.json      Reader ID -> name / latitude / longitude
  serial_bridge.py  Forwards SCAN lines from the Pico's USB serial port to the server
```

## Running it

1. Start the server (creates `dashboard/scans.db` on first run):

   ```
   cd dashboard
   python3 server.py            # add --demo to seed sample data
   ```

   Open http://localhost:8080.

2. Plug in the Pico and start the serial bridge in a second terminal:

   ```
   python3 -m pip install pyserial     # once
   python3 serial_bridge.py
   ```

   Every tag read prints `SCAN,<reader_id>,<uid>,<1|0>` on the Pico's serial port; the
   bridge posts it to the server and it appears on the dashboard within a few seconds.

## Adding a reader

- Set `READER_ID` at the top of `blink_any.c` to a unique ID (for example `rack-02`) and
  flash that board.
- Add a matching entry with the rack's coordinates to `dashboard/readers.json`.

## API

| Method | Path | Body / query |
| :--- | :--- | :--- |
| `POST` | `/api/scans` | `{"reader_id": "rack-01", "uid": "DEADBEEF", "authorized": true}` |
| `GET` | `/api/scans` | `?since=<ISO-8601>&limit=<n>` |
| `GET` | `/api/readers` | |
| `DELETE` | `/api/scans` | clears the log |

Run the server with `--host 0.0.0.0` if a Pico on the same Wi-Fi network should post to it
directly instead of going through the serial bridge.
