<p align="center">
 
</p>

<h1 align="center">JANOS on NM-CYD-C5</h1>

<p align="center">
  <b>WiFi 6 security toolkit & wardriving device built on NerdMiner ESP32-C5 CYD</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/ESP--IDF-6.0-blue?logo=espressif" alt="ESP-IDF 6.0"/>
  <img src="https://img.shields.io/badge/MCU-ESP32--C5-red?logo=espressif" alt="ESP32-C5"/>
  <img src="https://img.shields.io/badge/UI-LVGL%208.x-green" alt="LVGL 8"/>
  <img src="https://img.shields.io/badge/Display-ST7789%202.8%22-orange" alt="ST7789"/>
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
  - [GPS Wiring — ATGM336H](#gps-wiring--atgm336h)
- [Software Features — Detailed](#software-features--detailed)
  - [WiFi Scan & Attack](#1-wifi-scan--attack)
  - [Global WiFi Attacks](#2-global-wifi-attacks)
  - [Network Observer & Karma](#3-network-observer--karma)
  - [Deauth Monitor](#4-deauth-monitor)
  - [Bluetooth](#5-bluetooth)
  - [Wardriving](#6-wardriving)
  - [Settings](#7-settings)
- [Data & Storage](#data--storage)
- [Touch Calibration](#touch-calibration)
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

> These are from Pancake — this port is portrait-oriented to fit the CYD form factor. Updated screenshots coming soon.

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
| **MCU** | ESP32-C5-WROOM-1-N168R (RISC-V 240 MHz, 16 MB flash, 8 MB PSRAM) | — |
| **Board** | NM-CYD-C5 (RockBase-iot NerdMiner CYD) | — |
| **Display** | 2.8" ST7789 TFT (240×320 portrait, 16-bit RGB565) | SPI @ 40 MHz |
| **Touch** | XPT2046 Resistive Touch (polling, T_IRQ not connected) | SPI @ 2 MHz |
| **SD Card** | MicroSD **FAT32, max 32 GB** (shared SPI2 bus with display and touch) | SPI @ 20 MHz |
| **GPS** | ATGM336H NMEA module (GGA, RMC sentences) | UART1 @ 9600 baud |
| **LED** | WS2812 NeoPixel (single, GPIO 27) | RMT / GPIO |

Board reference: https://github.com/RockBase-iot/NM-CYD-C5


---

## Pinout

### Wiring Diagram

```
                       ESP32-C5 NM-CYD-C5
                      ┌──────────────────┐
                      │                  │
    Display ──────────┤ GPIO 7   (MOSI)  │──────── Touch / SD Card
    (shared SPI2)     │ GPIO 2   (MISO)  │         (shared SPI2)
                      │ GPIO 6   (SCK)   │⚠️
                      │                  │
    LCD CS ───────────┤ GPIO 23          │
    LCD DC ───────────┤ GPIO 24          │
    LCD BL ───────────┤ GPIO 25          │⚠️ strapping, safe after boot
                      │                  │
    Touch CS ─────────┤ GPIO 1           │
                      │                  │
    SD CS ────────────┤ GPIO 10          │
                      │                  │
    GPS TX (ESP→GPS) ─┤ GPIO 5           │
    GPS RX (GPS→ESP) ─┤ GPIO 4           │
                      │                  │
    NeoPixel ─────────┤ GPIO 27          │
                      │                  │
    Console ──────────┤ USB (JTAG/CDC)   │
                      └──────────────────┘

    ⚠️ = Strapping pins — safe after boot completes
    GPIO 16–22 (excl. 21) = Flash/PSRAM — never use
```

### Complete GPIO Table

| GPIO | Function | Interface | Notes |
|------|----------|-----------|-------|
| 1 | XPT2046 Touch CS | SPI | Active LOW |
| 2 | SPI MISO | SPI2 | Shared: display + touch + SD |
| 4 | GPS RX (GPS→ESP) | UART | LP-UART |
| 5 | GPS TX (ESP→GPS) | UART | LP-UART |
| 6 | SPI SCK | SPI2 | ⚠️ Strapping pin; also ADC1_CH5 — **do not configure as ADC** (breaks SPI clock) |
| 7 | SPI MOSI | SPI2 | ⚠️ Strapping pin, safe after boot |
| 10 | SD Card CS | SPI | Active LOW |
| 16–22 (excl. 21) | Flash/PSRAM | — | **Never use** |
| 23 | ST7789 Display CS | SPI | Active LOW |
| 24 | ST7789 DC (Data/Cmd) | Output | |
| 25 | Backlight | Output | ⚠️ Strapping, HIGH=on |
| 27 | NeoPixel Data | RMT/GPIO | WS2812 LED |

> **GPIO 6 / ADC1_CH5 conflict:** The battery voltage ADC (`BATTERY_ADC_CHANNEL ADC_CHANNEL_5`) maps to GPIO 6, which is also SPI SCK. Calling `adc_oneshot_config_channel` on this pin silently reconfigures it away from SPI, killing SPI clock for display and touch. The battery ADC is **permanently disabled** in firmware for this board revision (`if (false && init_battery_adc()...)`).

> **XPT2046 Z1 pressure:** Touch detection uses Z1 pressure threshold (`> 400` raw counts). Z1 reads near 0 when untouched and rises above threshold when pressed — providing reliable touch detection even though explicit Z electrode PCB traces are not exposed.

### SPI Bus Architecture

```
SPI2_HOST
├── ST7789 Display  (CS = GPIO 23, 40 MHz)
│   ├── MOSI = GPIO 7
│   ├── MISO = GPIO 2
│   ├── SCK  = GPIO 6
│   └── DC = GPIO 24
│
├── XPT2046 Touch   (CS = GPIO 1, 2 MHz)
│
└── SD Card         (CS = GPIO 10, 20 MHz)

Mutual exclusion via sd_spi_mutex
```

### GPS Wiring — ATGM336H

The ATGM336H is a compact GPS/GNSS module that outputs standard NMEA 0183 sentences (GGA, RMC) at 9600 baud. It is wired directly to the NM-CYD-C5 LP-UART pins — no level shifter required as the module operates at 3.3 V.

```
ATGM336H Module          NM-CYD-C5 (ESP32-C5)
┌────────────┐           ┌──────────────────┐
│        VCC ├───────────┤ 3.3 V            │
│        GND ├───────────┤ GND              │
│         TX ├───────────┤ IO4  (UART1 RX)  │
│         RX ├───────────┤ IO5  (UART1 TX)  │
│        PPS │  (unused) │                  │
└────────────┘           └──────────────────┘
```

| Signal | ATGM336H pin | ESP32-C5 pin | Notes |
|--------|-------------|-------------|-------|
| Power | VCC | 3.3 V | Do **not** connect to 5 V — module is 3.3 V only |
| Ground | GND | GND | Common ground required |
| Data to ESP | TX | IO4 (UART1 RX) | Module transmits NMEA sentences |
| Data from ESP | RX | IO5 (UART1 TX) | Optional — only needed to send config commands |
| Timing pulse | PPS | — | Not connected; not used by firmware |

**Settings:** UART1 · 9600 baud · 8N1 · no flow control

The firmware parses GGA sentences for latitude, longitude, altitude, and satellite count, and RMC sentences for fix validity. Cold start to first fix typically takes 30–60 seconds with a clear sky view.

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

GPS-enabled WiFi logging for mapping wireless networks. Requires an **ATGM336H** (or compatible NMEA module) wired to IO4/IO5 — see [GPS Wiring](#gps-wiring--atgm336h).

- Combines GPS coordinates (NMEA GGA/RMC) with WiFi scan results
- Uses D-UCB channel hopping for thorough band coverage
- Logs SSID, BSSID, channel, RSSI, auth mode, and GPS coordinates to CSV on the SD card
- Compatible with standard wardriving visualization tools (Wigle, etc.)

### 7. Settings

| Setting | Description |
|---------|-------------|
| **Screen Timeout** | Inactivity timer before display dimming |
| **Brightness** | Software brightness overlay (10–100%) |
| **Scan Duration** | Configurable WiFi scan time |
| **SD Card** | Validate/provision, check free space, format |
| **GPS Info** | Live GPS fix status, latitude, longitude, altitude, satellite count, and UART config reference (IO4/IO5, 9600 baud, ATGM336H) |

All settings are persisted via **NVS** (Non-Volatile Storage) across reboots.

### UI & System Features

| Feature | Description |
|---------|-------------|
| **LVGL Material Dark Theme** | Modern, touch-friendly dark UI |
| **6-Tile Main Menu** | Quick access to all feature categories |
| **Screenshot Capture** | Save screen to SD card (`/sdcard/screenshots/`) |
| **WPA-SEC Upload** | Upload captured handshakes to wpa-sec.stanev.org via HTTPS |
| **NeoPixel Status LED** | Mode-based color indicator via WS2812 LED (GPIO 27) |

### NeoPixel LED Color Reference

| Color | Mode |
|-------|------|
| White | Idle / system ready |
| Blue | WiFi scanning |
| Green | Passive sniffer / SnifferDog |
| Cyan | Wardrive |
| Purple | BLE scan / AirTag / BT locator |
| Yellow | WPA handshake capture |
| Amber | Deauth monitor / MITM ARP |
| Orange | Karma attack / captive portal |
| Red | Deauth / blackout / SAE overflow |

---

## Data & Storage

> **SD card requirement:** MicroSD formatted as **FAT32, 32 GB or smaller**. exFAT and NTFS are not supported. SDXC cards (>32 GB) require manual FAT32 formatting before use.

All data is stored on the SD card:

```
/sdcard/
├── lab/
│   ├── white.txt         # MAC/SSID whitelist (one per line)
│   ├── handshakes/       # Captured WPA handshakes
│   │   ├── *.pcap        # Wireshark-compatible captures
│   │   └── *.hccapx      # Hashcat-compatible format (hashcat)
│   └── portal/           # Captive portal credential files
├── wardrive/             # GPS + WiFi logs (CSV)
├── screenshots/          # UI screenshots (BMP)
└── calibrate.txt         # ← Create this file to trigger touch re-calibration on next boot
```

---

## Touch Calibration

The XPT2046 resistive touch panel requires one-time calibration to map raw ADC values to screen coordinates. Calibration data is saved in NVS and survives reboots.

### First Boot

Calibration runs automatically the first time the firmware boots (when no NVS calibration is found). The sequence appears after the splash screen:

1. **"Do NOT touch screen"** — holds for 2 seconds while measuring the panel's resting (null) position.
2. **"Touch the [+] Top-Left (1/3)"** — a white crosshair appears at the top-left corner. Press it firmly and hold until the screen advances.
3. **"Touch the [+] Top-Right (2/3)"** — press the top-right crosshair.
4. **"Touch the [+] Bottom-Left (3/3)"** — press the bottom-left crosshair.
5. **"Calibration done!"** — calculated values are saved to NVS namespace `touch_cal` and applied immediately.

### Re-Calibrating

To re-run calibration after first boot, create a **trigger file** on the SD card:

```
/sdcard/calibrate.txt
```

The file content does not matter. On the next boot, the firmware detects it, deletes it, and runs the calibration UI before showing the home screen.

### What Is Stored (NVS namespace `touch_cal`)

| Key | Type | Description |
|-----|------|-------------|
| `x_min` / `x_max` | i32 | Raw ADC X range mapped to screen edges |
| `y_min` / `y_max` | i32 | Raw ADC Y range mapped to screen edges |
| `null_x` / `null_y` | i32 | Resting panel position (false-touch dead zone center) |
| `invert_x` / `invert_y` | u8 | Axis inversion flags (NM-CYD-C5: both typically `1`) |
| `swap_xy` | u8 | Axis swap (typically `0` for portrait) |
| `magic` | u16 | `0xCA11` — marks calibration as valid |

### Default Fallback

If NVS has no calibration (i.e., `magic` ≠ `0xCA11`), the firmware applies hardware-observed defaults for the NM-CYD-C5: **both axes inverted** (`invert_x = true`, `invert_y = true`). These are good enough for initial boot but may be off by ~20 pixels. Run calibration for accurate touch.

---

## Building & Flashing

### Prerequisites

- **ESP-IDF release/v6.0** branch tip (NOT the `v6.0` tag — it's missing critical post-release fixes)
- **NM-CYD-C5** board (ESP32-C5-WROOM-1-N168R)

### Build

```bash
cd ESP32C5
idf.py set-target esp32c5
idf.py build
```

After each build the compiled binaries are automatically copied to `ESP32C5/binaries-esp32c5/`.

### Flash — Web Browser (No Install Required)

Use **[ESPConnect](https://thelastoutpostworkshop.github.io/ESPConnect/)** to flash directly from Chrome or Edge via WebSerial. Flash each file at the address shown below.

| File | Address |
|------|---------|
| `bootloader.bin` | `0x2000` |
| `partition-table.bin` | `0x8000` |
| `CYM-NM28C5.bin` | `0x10000` |

> **[ESPTerminator](https://espterminator.com/)** is a newer web flash/terminal tool but does not yet identify the NM-CYD-C5 correctly and fails to flash the board reliably. Check back for future support.

### Flash — Command Line

```bash
idf.py -p /dev/ttyACM0 flash monitor
```

Or with esptool directly:

```bash
esptool.py --chip esp32c5 --port /dev/ttyACM0 --baud 460800 \
  --before default-reset --after hard-reset \
  write_flash --flash-mode dio --flash-freq 80m --flash-size 16MB \
  0x2000 bootloader.bin 0x8000 partition-table.bin 0x10000 CYM-NM28C5.bin
```

---

## Photos

<!-- Add your hardware photos here -->

<p align="center">


  <br/>
  <em>Device — Front View</em>
</p>

<p align="center">


  <br/>
  <em>Device — Back / Wiring</em>
</p>

<p align="center">


  <br/>
  <em>Home-made waveshare build</em>
</p>

---

## Project Structure

```
CYM-NM28C5/
├── ESP32C5/
│   ├── main/
│   │   ├── main.c                # Core application, all UI screens, boot sequence,
│   │   │                         #   touch calibration routine (run_touch_calibration)
│   │   ├── attack_handshake.c    # Handshake capture logic
│   │   ├── xpt2046.c/h           # XPT2046 SPI touch driver (polling, null-zone, calibration reads)
│   │   └── lvgl_memory.c         # PSRAM allocator for LVGL
│   ├── components/
│   │   ├── wifi_cli/             # CLI, WiFi init, LED control
│   │   ├── wifi_scanner/         # WiFi scanning engine
│   │   ├── wifi_sniffer/         # Promiscuous mode sniffer
│   │   ├── wifi_attacks/         # Deauth, Evil Twin, Captive Portal, Karma
│   │   ├── wifi_wardrive/        # SD card, GPS + WiFi wardriving
│   │   ├── sniffer/              # Raw 802.11 frame capture
│   │   ├── frame_analyzer/       # EAPOL / beacon parsing
│   │   ├── pcap_serializer/      # PCAP file writer
│   │   └── hccapx_serializer/    # HCCAPX file writer (hashcat)
│   ├── partitions.csv            # nvs(24K) phy_init(4K) factory(7MB) storage(960K)
│   ├── sdkconfig
│   └── CMakeLists.txt
├── NM-CYD-C5-pinmap.md          # Full pin map with migration notes
└── README.md
```

---

## BMorcelli Launcher Compatibility

This firmware is **not currently compatible** with [bmorcelli/Launcher](https://github.com/bmorcelli/Launcher).

| Issue | Detail |
|-------|--------|
| **ESP32-C5 not supported** | Tracked in [Issue #300](https://github.com/bmorcelli/Launcher/issues/300) — pending merge as of April 2026 |
| **Partition layout mismatch** | Launcher requires OTA-style partition slots; this build uses a single 7 MB `factory` partition at `0x10000` |
| **Custom bootloader conflict** | Launcher's bootloader switches apps via reset-reason detection; this firmware has no handoff logic |
| **Framework mismatch** | Launcher is Arduino; this firmware is ESP-IDF 6.0 — display/touch init sequences would conflict |

Flash this firmware standalone (see [Building & Flashing](#building--flashing)). Launcher integration can be revisited once Issue #300 is merged and an official NM-CYD-C5 board target exists upstream.

---

## Disclaimer

This project is intended for **educational and authorized security research purposes only**. Unauthorized access to computer networks is illegal. Always obtain proper authorization before testing on any network you do not own. The author assumes no liability for misuse of this software.

# **Don't Be A Skid!**

---

<p align="center">
  <b>Made with ☕ and ESP-IDF</b>
</p>

I love your Face!
