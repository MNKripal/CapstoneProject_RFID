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

The `dashboard/` folder contains a web dashboard that logs every tag read together with the
location of the reader that saw it, keeps the registry of authorized tags, and raises alerts.
Readers are mounted at fixed bike racks, so each reader ID maps to a known campus coordinate
in `dashboard/readers.json`.

```
dashboard/
  server.py         HTTP server, SQLite database, REST API (Python 3 standard library only)
  index.html        Single-page dashboard with four views: Activity, Readers, Alerts, Tags
  readers.json      Reader ID -> name / latitude / longitude
  serial_bridge.py  Forwards SCAN and HB lines from the Pico's USB serial port to the server
docs/
  wireframes.html   Low-fidelity wireframes of the four views (wireframes.png is the rendered copy)
```

## Views

- **Activity**: stat tiles, campus map with a marker per reader sized by scan count, scans-over-time
  chart, and the scan history table. Filter by time range, reader and status.
- **Readers**: map with markers coloured by status, plus a table with last contact and today's counts.
  A reader is offline after 2 minutes without a heartbeat or scan.
- **Alerts**: denied scans, repeated denials (3 or more in 10 minutes), scans from unknown readers,
  and readers going offline. Alerts can be acknowledged one at a time or all at once; the open
  count is shown in the navigation bar.
- **Tags**: the registry. Register a tag with its owner and label, revoke or restore it, delete it.
  Tags that have been seen by a reader but are not registered are listed with a one-click
  Register button.

## How authorization works

The server owns the tag registry and makes the final decision for every scan: a registered,
authorized tag is accepted; a revoked or unregistered tag is denied and an alert is raised.
The firmware still carries its own `AUTHORIZED_UID` for the physical unlock; until the reader
talks to the server directly over Wi-Fi, keep the two in agreement. The serial bridge prints a
warning whenever they disagree.

## Running it

1. Start the server (creates `dashboard/scans.db` on first run):

   ```
   cd dashboard
   python3 server.py            # add --demo to seed sample tags, scans and alerts
   ```

   Open http://localhost:8080.

2. Plug in the Pico and start the serial bridge in a second terminal:

   ```
   python3 -m pip install pyserial     # once
   python3 serial_bridge.py
   ```

   The firmware prints `SCAN,<reader_id>,<uid>,<1|0>` for every tag read and `HB,<reader_id>`
   every 30 seconds. The bridge forwards both to the server.

## Adding a reader

- Set `READER_ID` at the top of `blink_any.c` to a unique ID (for example `rack-02`) and
  flash that board.
- Add a matching entry with the rack's coordinates to `dashboard/readers.json`.

## API

| Method | Path | Body / query |
| :--- | :--- | :--- |
| `POST` | `/api/scans` | `{"reader_id": "rack-01", "uid": "DEADBEEF", "device_authorized": true}` |
| `GET` | `/api/scans` | `?since=<ISO-8601>&limit=<n>` |
| `DELETE` | `/api/scans` | clears scans and alerts |
| `POST` | `/api/heartbeat` | `{"reader_id": "rack-01"}` |
| `GET` | `/api/readers` | readers with status, last seen and today's counts |
| `GET` | `/api/tags` | registry with scan counts |
| `POST` | `/api/tags` | `{"uid": "DEADBEEF", "owner": "Name", "label": "Bike"}` |
| `PUT` | `/api/tags/<uid>` | any of `owner`, `label`, `notes`, `authorized` |
| `DELETE` | `/api/tags/<uid>` | |
| `GET` | `/api/tags/unregistered` | UIDs seen by readers but not registered |
| `GET` | `/api/alerts` | `?include_acked=1` |
| `POST` | `/api/alerts/<id>/ack` | |
| `POST` | `/api/alerts/ack_all` | |

Run the server with `--host 0.0.0.0` if a Pico on the same Wi-Fi network should post to it
directly instead of going through the serial bridge.
