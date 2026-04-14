<p align="center">
 
</p>

<h1 align="center">Warning This Project is just starting! /n JANOS on NM-CYD-C5</h1>

<p align="center">
  <b>WiFi 6 security toolkit & wardriving device built on NerdMiner ESP32-C5 CYD</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/ESP--IDF-6.0-blue?logo=espressif" alt="ESP-IDF 6.0"/>
  <img src="https://img.shields.io/badge/MCU-ESP32--C5-red?logo=espressif" alt="ESP32-C5"/>
  <img src="https://img.shields.io/badge/UI-LVGL%208.x-green" alt="LVGL 8"/>
  <img src="https://img.shields.io/badge/Display-ILI9341%203.5%22-orange" alt="ILI9341"/>
  <img src="https://img.shields.io/badge/WiFi-802.11ax%20(WiFi%206)-blueviolet" alt="WiFi 6"/>
  <img src="https://img.shields.io/badge/BLE-5.0-informational" alt="BLE 5"/>
</p>

---

## Introduction

**Cheap Yellow Monster** is a portable, touchscreen-driven WiFi security toolkit running on the **NM-CYD-C5 ESP32-C5-WIFI6-KIT**. Inspired by Pancake, it combines a rich set of offensive and defensive WiFi tools with BLE scanning, GPS wardriving, and a beautiful Material-style dark UI — all packed into a handheld form factor with a 2.8" resistive touch display.

Built entirely on **ESP-IDF 6.0** with **LVGL 8.x** for the UI, the firmware leverages the ESP32-C5's RISC-V core and WiFi 6 capabilities for modern wireless security research and education.

---

## Table of Contents

- [Features Overview](#features-overview)
- [Screenshots](#screenshots)
- [Hardware](#hardware)
- [Pinout](#pinout)
- [Software Features — Detailed](#software-features--detailed)
  - [WiFi Scan & Attack](#1-wifi-scan--attack)
  - [Global WiFi Attacks](#2-global-wifi-attacks)
  - [Network Observer & Karma](#3-network-observer--karma)
  - [Deauth Monitor](#4-deauth-monitor)
  - [Bluetooth](#5-bluetooth)
  - [Wardriving](#6-wardriving)
  - [Settings](#7-settings)
- [Data & Storage](#data--storage)
- [Building & Flashing](#building--flashing)
- [Photos](#photos)
- [Disclaimer](#disclaimer)

---

## Features Overview

| Category | Features |
|----------|----------|
| **WiFi Scanning** | Active scan, per-channel analysis, RSSI, client enumeration |
| **WiFi Attacks** | Deauth, Evil Twin, Captive Portal, Blackout, Snifferdog, SAE Overflow |
| **Handshake Capture** | WPA/WPA2 4-way handshake capture (PCAP & HCCAPX) |
| **Karma AP** | Respond to probe requests, rogue access point |
| **Wardriving** | GPS + WiFi logging to SD card (CSV) |
| **BLE** | AirTag scanner, SmartTag detection, BLE Locator |
| **Deauth Monitor** | Passive detection of nearby deauth attacks |
| **Credentials** | Captive portal credential capture, WPA-SEC upload |
| **UI** | Material dark theme, touch gestures, screen dimming, screenshots |
| **Storage** | SD card for handshakes, wardrive logs, screenshots |

---

## Screenshots

<!-- Add your screenshots here -->

<p align="center">
  <img width="480" height="271" alt="image" src="https://github.com/user-attachments/assets/0200719c-85b7-4977-9a38-1ecb4defad9a" />

  <br/>
  <em>Main Menu</em>
</p>

<p align="center">
<img width="474" height="280" alt="image" src="https://github.com/user-attachments/assets/9df03b0c-f25b-4cb1-a049-0591c389a645" />

  <br/>
  <em>Selected Network Attack Panel</em>
</p>


<p align="center">
<img width="486" height="326" alt="image" src="https://github.com/user-attachments/assets/7e815b7b-0fa9-475e-91b2-4d14344a7f86" />
  <br/>
  <em>Global attacks</em>
</p>

<p align="center">
  <img width="486" height="321" alt="image" src="https://github.com/user-attachments/assets/ad768a74-ae52-4888-b43b-aab25ebc3222" />

  <br/>
  <em>Handshaker</em>
</p>

<p align="center">
<img width="485" height="317" alt="image" src="https://github.com/user-attachments/assets/8a7baecc-a08c-403f-bb76-f79dd3fe8b30" />

  <br/>
  <em>Kismet-style network observer & Karma attack</em>
</p>


---

## Hardware

| Component | Model | Interface |
|-----------|-------|-----------|
| **MCU** | ESP32-C5 (RISC-V, WiFi 6, BLE 5) | — |
| **Board** | Waveshare ESP32-C5-WIFI6-KIT | — |
| **Display** | 3.5" ILI9341 TFT (480×320, 16-bit RGB565) | SPI @ 40 MHz |
| **Touch** | FT6336U Capacitive Touch | I2C @ 0x38 |
| **SD Card** | MicroSD (shared SPI bus with display) | SPI |
| **GPS** | UART NMEA module (GGA, RMC) | UART @ 9600 baud |
| **LED** | WS2812 NeoPixel (single) | RMT / GPIO |
| **Battery** | LiPo with voltage divider (ADC monitoring) | ADC |

Screen link: https://pl.aliexpress.com/item/1005009570156903.html - remember to select 3.5" 


---

## Pinout

### Wiring Diagram

```
                     ESP32-C5 Waveshare
                    ┌──────────────────┐
                    │                  │
    Display ────────┤ GPIO 24  (MOSI)  │──────── SD Card
    (shared SPI)    │ GPIO 4   (MISO)  │         (shared SPI)
                    │ GPIO 23  (CLK)   │
                    │                  │
    LCD CS ─────────┤ GPIO 5           │
    LCD DC ─────────┤ GPIO 3   ⚠️      │
    LCD RST ────────┤ GPIO 2   ⚠️      │
                    │                  │
    BAT ADC ────────┤ GPIO 6   (ADC)   │──── Battery voltage divider
                    │                  │
    SD CS ──────────┤ GPIO 7           │
                    │                  │
    Touch SDA ──────┤ GPIO 9           │
    Touch SCL ──────┤ GPIO 10          │
    Touch INT ──────┤ GPIO 25          │
    Touch RST ──────┤ GPIO 8           │
                    │                  │
    GPS TX ─────────┤ GPIO 13          │
    GPS RX ─────────┤ GPIO 14          │
                    │                  │
    NeoPixel ───────┤ GPIO 27          │
                    │                  │
    Console ────────┤ GPIO 11/12 (USB) │
                    └──────────────────┘

    ⚠️ = Strapping pins — require gpio_reset_pin() before use
```

### Complete GPIO Table

| GPIO | Function | Interface | Notes |
|------|----------|-----------|-------|
| 2 | LCD Reset | Output | ⚠️ Strapping pin |
| 3 | LCD Data/Command | Output | ⚠️ Strapping pin |
| 4 | SPI MISO | SPI | Shared: LCD + SD |
| 5 | LCD Chip Select | SPI | Active LOW |
| 6 | Battery ADC | ADC1_CH5 | Voltage divider (ratio 3.2) |
| 7 | SD Card Chip Select | SPI | Active LOW |
| 8 | Touch Reset | Output | Active LOW |
| 9 | Touch SDA | I2C | FT6336U data |
| 10 | Touch SCL | I2C | FT6336U clock |
| 11 | Console TX | UART0 | USB serial |
| 12 | Console RX | UART0 | USB serial |
| 13 | GPS TX | UART1 | ESP → GPS |
| 14 | GPS RX | UART1 | GPS → ESP |
| 23 | SPI Clock | SPI | Shared: LCD + SD |
| 24 | SPI MOSI | SPI | Shared: LCD + SD |
| 25 | Touch Interrupt | Input | Touch detected |
| 27 | NeoPixel Data | RMT/GPIO | WS2812 LED |

### SPI Bus Architecture

```
SPI2_HOST (40 MHz)
├── LCD ILI9341     (CS = GPIO 5)
│   ├── MOSI = GPIO 24
│   ├── MISO = GPIO 4
│   ├── CLK  = GPIO 23
│   └── DC = GPIO 3, RST = GPIO 2
│
└── SD Card         (CS = GPIO 7)
    ├── MOSI = GPIO 24
    ├── MISO = GPIO 4
    └── CLK  = GPIO 23

Mutual exclusion via sd_spi_mutex
```

### Battery Monitoring

```
VBAT ──┤ R10 (200kΩ) ├──┬── GPIO 6 (ADC1_CH5)
                        │
                   R16 (100kΩ)
                        │
                       GND

Divider ratio: 3.0 (calibrated: 3.2)
```

---

## Software Features — Detailed

### 1. WiFi Scan & Attack

**Active WiFi scanning** with per-network details, followed by targeted attacks on selected networks.

| Feature | Description |
|---------|-------------|
| **WiFi Scan** | Scans all channels, shows SSID, BSSID, RSSI, channel, encryption |
| **Deauth Attack** | Sends deauthentication frames to disconnect clients from selected AP |
| **Evil Twin** | Creates a rogue AP cloning the target SSID to lure clients |
| **Captive Portal** | HTTP server presenting a fake login page to capture credentials |
| **Handshake Capture** | Captures WPA/WPA2 4-way handshakes and saves as PCAP/HCCAPX |
| **ARP Poisoning** | LwIP-based ARP spoofing for MitM scenarios |

### 2. Global WiFi Attacks

Attacks that operate on **all nearby networks** simultaneously.

| Feature | Description |
|---------|-------------|
| **Blackout** | Mass deauthentication of all detected networks in range |
| **Snifferdog** | Channel-hopping sniffer with automatic client deauthentication |
| **SAE Overflow** | WPA3 SAE authentication flood attack |

### 3. Network Observer & Karma

Passive network intelligence and rogue AP capabilities.

| Feature | Description |
|---------|-------------|
| **Network Observer** | Passive 802.11 sniffing in promiscuous mode |
| **Karma AP** | Automatically responds to client probe requests, creating matching rogue APs |

### 4. Deauth Monitor

**Passive detection** of deauthentication attacks happening in the area. Alerts when deauth frames are detected on nearby channels — useful for detecting hostile activity.

### 5. Bluetooth

BLE scanning features leveraging the ESP32-C5's BLE 5.0 radio.

| Feature | Description |
|---------|-------------|
| **AirTag Scanner** | Detects Apple Find My network devices |
| **SmartTag Scanner** | Detects Samsung SmartTag devices |
| **BLE Locator** | Generic BLE device scanner with signal strength |

> **Note:** WiFi and BLE share the same radio. The firmware automatically switches between `RADIO_MODE_WIFI` and `RADIO_MODE_BLE` as needed.

### 6. Wardriving

GPS-enabled WiFi logging for mapping wireless networks.

- Combines GPS coordinates (NMEA GGA/RMC) with WiFi scan results
- Logs to CSV files on the SD card
- Compatible with standard wardriving visualization tools

### 7. Settings

| Setting | Description |
|---------|-------------|
| **Screen Timeout** | Inactivity timer before display dimming |
| **Brightness** | Software brightness overlay (10–100%) |
| **Scan Duration** | Configurable WiFi scan time |

All settings are persisted via **NVS** (Non-Volatile Storage) across reboots.

### UI & System Features

| Feature | Description |
|---------|-------------|
| **LVGL Material Dark Theme** | Modern, touch-friendly dark UI |
| **6-Tile Main Menu** | Quick access to all feature categories |
| **Screenshot Capture** | Save screen to SD card (`/sdcard/screenshots/`) |
| **WPA-SEC Upload** | Upload captured handshakes to wpa-sec.stanev.org via HTTPS |
| **NeoPixel Status LED** | Visual feedback via WS2812 LED |
| **Battery Monitor** | Real-time battery voltage reading |

---

## Data & Storage

All data is stored on the SD card:

```
/sdcard/
├── lab/
│   └── handshakes/       # Captured WPA handshakes
│       ├── *.pcap        # Wireshark-compatible captures
│       └── *.hccapx      # Hashcat-compatible format
├── wardrive/             # GPS + WiFi logs (CSV)
├── screenshots/          # UI screenshots (BMP)
└── portal/               # Captured portal credentials
```

---

## Building & Flashing

### Prerequisites

- **ESP-IDF v6.0** (with ESP32-C5 support)
- **Waveshare ESP32-C5-WIFI6-KIT** (or compatible)

### Build

```bash
cd ESP32C5
idf.py set-target esp32c5
idf.py build
```

### Flash

```bash
idf.py -p /dev/ttyACM0 flash monitor
```

---

## Photos

<!-- Add your hardware photos here -->

<p align="center">
 <img width="737" height="470" alt="image" src="https://github.com/user-attachments/assets/3e6a371b-d864-4081-92d1-ef023e0059fe" />

  <br/>
  <em>Device — Front View</em>
</p>

<p align="center">
 <img width="734" height="424" alt="image" src="https://github.com/user-attachments/assets/d4498e30-c57c-4880-84b1-27252bd06779" />

  <br/>
  <em>Device — Back / Wiring</em>
</p>

<p align="center">
<img width="796" height="840" alt="image" src="https://github.com/user-attachments/assets/4a31ff44-e238-4f86-bf9c-5b0079c676f9" />

  <br/>
  <em>Home-made waveshare build</em>
</p>

---

## Project Structure

```
pancake/
├── ESP32C5/
│   ├── main/
│   │   ├── main.c                # Core application, UI, init
│   │   ├── attack_handshake.c    # Handshake capture logic
│   │   ├── ft6336.c              # FT6336U touch driver
│   │   └── lvgl_memory.c         # PSRAM allocator for LVGL
│   ├── components/
│   │   ├── wifi_cli/             # CLI, WiFi init, LED control
│   │   ├── wifi_scanner/         # WiFi scanning engine
│   │   ├── wifi_sniffer/         # Promiscuous mode sniffer
│   │   ├── wifi_attacks/         # Deauth, Evil Twin, Captive Portal, Karma
│   │   ├── wifi_wardrive/        # GPS + WiFi wardriving
│   │   ├── sniffer/              # Raw 802.11 frame capture
│   │   ├── frame_analyzer/       # EAPOL / beacon parsing
│   │   ├── pcap_serializer/      # PCAP file writer
│   │   └── hccapx_serializer/    # HCCAPX file writer (hashcat)
│   ├── sdkconfig
│   └── CMakeLists.txt
└── README.md
```

---

## Disclaimer

This project is intended for **educational and authorized security research purposes only**. Unauthorized access to computer networks is illegal. Always obtain proper authorization before testing on any network you do not own. The author assumes no liability for misuse of this software.

---

<p align="center">
  <b>Made with ☕ and ESP-IDF</b>
</p>
