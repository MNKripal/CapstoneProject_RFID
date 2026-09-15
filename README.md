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

