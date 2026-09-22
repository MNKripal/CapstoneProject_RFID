# Smart Bike Rack: RFID Access Logging on the Raspberry Pi Pico 2 W

**Capstone Project, Arizona State University (Tempe campus)**
Team: Kripal Mogala, Nihar Reddy

## What this project does

Bikes on campus get an RFID tag. Each bike rack gets a small reader built from a
Raspberry Pi Pico 2 W and an MFRC522 RFID module. When a student taps their tag,
the reader checks whether the tag is authorized and every tap is logged to a web
dashboard that shows **who** tapped, **when**, and **where** on campus.

Because the readers are bolted to fixed racks, the location of a scan is simply
the location of the reader that saw it. No GPS is needed.

## Features

- Reads ISO 14443-A tags (MIFARE Classic and similar) over SPI with the MFRC522.
- Recovers automatically if the reader chip loses its configuration.
- Prints every scan and a heartbeat over USB so a computer can log them.
- Web dashboard with four screens:
  - **Activity**: totals, campus map, scans-over-time chart, full scan history.
  - **Readers**: which readers are online, where they are, today's counts.
  - **Alerts**: denied scans, repeated denials, unknown readers, readers offline.
  - **Tags**: the registry of authorized tags, with revoke, restore and delete.
- Works on a laptop or a phone, in light or dark mode.

## Hardware

| Part | Notes |
| :--- | :--- |
| Raspberry Pi Pico 2 W | RP2350, dual-core Cortex-M33, Wi-Fi |
| MFRC522 RFID module | 13.56 MHz reader, SPI interface |
| RFID tags | MIFARE Classic 1K cards or key fobs |
| Jumper wires, breadboard | |

### Wiring

The pin numbers used by the firmware are defined in one place at the top of
`blink_any.c`. The table below matches those defaults.

| MFRC522 pin | Pico 2 W GPIO | Physical pin |
| :--- | :--- | :--- |
| SDA (NSS) | GPIO 5 | Pin 7 |
| SCK | GPIO 2 | Pin 4 |
| MOSI | GPIO 3 | Pin 5 |
| MISO | GPIO 4 | Pin 6 |
| RST | GPIO 15 | Pin 20 |
| 3.3V | 3V3 OUT | Pin 36 |
| GND | GND | Pin 38 |

Power the module from 3.3 V only. If the serial output says
`RC522 not responding`, compare the wires against this table first.

## Software you need

- Visual Studio Code with the **Raspberry Pi Pico** extension (installs the Pico SDK,
  CMake, Ninja and the ARM toolchain for you).
- Python 3.9 or newer for the dashboard.
- `pyserial` for the USB bridge: `python3 -m pip install pyserial`

## Getting started

### 1. Flash the firmware

1. Open this folder in VS Code and let the Pico extension configure the project.
2. Set `READER_ID` at the top of `blink_any.c` to a unique name for this rack, for
   example `rack-01`.
3. Set `AUTHORIZED_UID` to your tag's UID (you can read it from the serial output
   the first time you tap it).
4. Build, hold BOOTSEL while plugging the Pico in, and copy `blink_any.uf2` to it.

Open a serial monitor at 115200 baud. You should see the reader initialize and
then a line per tap, like:

```
Card UID: DE AD BE EF  (SAK 0x08, MIFARE 1KB)
>>> AUTHORIZED: Bicycle Unlocked!
SCAN,rack-01,DEADBEEF,1
```

### 2. Start the dashboard

```
cd dashboard
python3 server.py
```

Open http://localhost:8080 in a browser. Add `--demo` the first time to see
sample data. If the port is busy, add `--port 8081`.

### 3. Connect the reader to the dashboard

In a second terminal, with the Pico plugged in:

```
cd dashboard
python3 serial_bridge.py
```

The bridge reads the Pico's serial output and forwards each `SCAN` and heartbeat
line to the server. Taps show up on the dashboard within a few seconds.

### 4. Register tags and readers

- In the dashboard's **Tags** tab, tap a new card on a reader, then click
  **Register** next to it and enter the owner's name.
- Add each reader's rack location to `dashboard/readers.json` with its `READER_ID`.

## How authorization works

The server keeps the tag registry and makes the final decision on every scan:
a registered, authorized tag is accepted; a revoked or unregistered tag is denied
and an alert is raised. The firmware also has its own `AUTHORIZED_UID` for the
physical unlock. Until the reader talks to the server directly over Wi-Fi, keep
the two in agreement. The bridge prints a warning if they disagree.

## Project layout

```
blink_any.c            Firmware: reader loop, authorization, SCAN and HB serial lines
mfrc522.c / mfrc522.h  MFRC522 driver (SPI register access, anticollision, select)
CMakeLists.txt         Pico SDK build configuration
dashboard/
  server.py            Web server, SQLite database and REST API (standard library only)
  index.html           The dashboard page (HTML, CSS, JavaScript, Leaflet map)
  readers.json         Reader ID -> name, latitude, longitude
  serial_bridge.py     Forwards serial output from the Pico to the server
docs/
  wireframes.html      Wireframes of the four dashboard views (wireframes.png is rendered)
```

## REST API

| Method | Path | Purpose |
| :--- | :--- | :--- |
| `POST` | `/api/scans` | Log a scan: `{"reader_id": "rack-01", "uid": "DEADBEEF"}` |
| `GET` | `/api/scans` | List scans, newest first (`?since=`, `?limit=`) |
| `POST` | `/api/heartbeat` | Reader is alive: `{"reader_id": "rack-01"}` |
| `GET` | `/api/readers` | Readers with location, online status and today's counts |
| `GET` / `POST` | `/api/tags` | List the registry / register a tag |
| `PUT` / `DELETE` | `/api/tags/<uid>` | Update (`owner`, `label`, `authorized`) / remove a tag |
| `GET` | `/api/tags/unregistered` | UIDs seen by readers but not registered |
| `GET` | `/api/alerts` | Open alerts (`?include_acked=1` for all) |
| `POST` | `/api/alerts/<id>/ack` | Acknowledge one alert |
| `POST` | `/api/alerts/ack_all` | Acknowledge all |

## Problems we ran into

- **The reader worked only sometimes.** Three parts of the code disagreed about
  which GPIO pins were used, the firmware reset the chip every five seconds, and
  it did not wait for the chip's soft reset to finish before configuring it.
  Fixed by defining pins in one place, waiting for the reset, and re-initializing
  only when a health check shows the chip actually lost its settings.
- **The dashboard froze in a real browser.** Browsers keep spare idle connections
  open, which blocked the original single-threaded server. Fixed by handling each
  connection on its own thread.

## Future work

- Send scans from the Pico over Wi-Fi straight to the server, so the reader can ask
  the server whether to unlock instead of using a built-in UID.
- Measure the real coordinates of each rack and update `readers.json`.
- Drive a lock actuator or LED from the authorization result.

## Credits

The MFRC522 driver is adapted from Benjamin Modica's Pico port of the
[miguelbalboa/rfid](https://github.com/miguelbalboa/rfid) Arduino library, which is
in the public domain.
