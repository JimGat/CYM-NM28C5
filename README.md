<p align="center">
 
</p>

<h1 align="center">Cheap Yellow Monster</h1>

<p align="center">
  <b>v2.6.46</b>
</p>

<p align="center">
  WiFi 6 &amp; BLE security toolkit with SigInt &amp; Wardriving built on NerdMiner ESP32-C5 CYD
</p>

<p align="center">
  <img src="https://img.shields.io/badge/ESP--IDF-6.0-blue?logo=espressif" alt="ESP-IDF 6.0"/>
  <img src="https://img.shields.io/badge/MCU-ESP32--C5-red?logo=espressif" alt="ESP32-C5"/>
  <img src="https://img.shields.io/badge/UI-LVGL%208.x-green" alt="LVGL 8"/>
  <img src="https://img.shields.io/badge/Display-ST7789%202.8%22-orange" alt="ST7789"/>
  <img src="https://img.shields.io/badge/WiFi-802.11ax%20(WiFi%206)-blueviolet" alt="WiFi 6"/>
  <img src="https://img.shields.io/badge/BLE-5.0-informational" alt="BLE 5"/>
</p>

<p align="center">
  <a href="https://jimgat.github.io/CYM-NM28C5/" target="_blank">
    <img src="https://img.shields.io/badge/⚡%20Web%20Flasher-Flash%20in%20Browser-39ff14?style=for-the-badge&logo=googlechrome&logoColor=black" alt="Web Flasher"/>
  </a>
</p>

<p align="center">
  <img src="docs/screenshots/Cheep%20Yellow%20Monster.jpg" alt="Cheap Yellow Monster" width="50%"/>
</p>

---

## Introduction

**Cheap Yellow Monster** is a portable, touchscreen-driven WiFi security toolkit running on the **NM-CYD-C5 ESP32-C5-WIFI6-KIT**. Originally inspired by Pancake, it combines a rich set of offensive and defensive WiFi tools with BLE scanning, GPS wardriving, and a beautiful Material-style dark UI — all packed into a handheld form factor with a 2.8" resistive touch display.

Built entirely on **ESP-IDF 6.0** with **LVGL 8.x** for the UI, the firmware leverages the ESP32-C5's RISC-V core and WiFi 6 capabilities for modern wireless security research and education.

> **Note:** While Pancake provided the original inspiration, this project has diverged substantially in target hardware (ESP32-C5 / NM-CYD-C5), build system (ESP-IDF vs Arduino), UI framework (LVGL 8), feature set, and architecture. It is a standalone project, not a fork.

The NM-CYD-C5 can be purchased at [nmminer.com](https://www.nmminer.com/product/nm-cyd-c5/). Additional purchase sources and full hardware documentation are available on the [official board repository](https://github.com/RockBase-iot/NM-CYD-C5).

---

## Table of Contents

- [Features Overview](#features-overview)
- [Menu Map](#menu-map)
- [Screenshots](#screenshots)
- [Hardware](#hardware)
- [Pinout](#pinout)
  - [GPS Wiring — ATGM336H](#gps-wiring--atgm336h)
- [Software Features — Detailed](#software-features--detailed)
  - [WiFi](#1-wifi)
    - [WiFi Scan & Attack](#wifi-scan--attack)
    - [Evil Portal Resources](#evil-portal-resources)
    - [Global WiFi Attacks](#global-wifi-attacks)
    - [WiFi Observer & Karma](#wifi-observer--karma)
    - [Deauth Monitor](#deauth-monitor)
  - [Bluetooth](#2-bluetooth)
    - [BLE PCAP — How It Works](#ble-pcap--how-it-works)
    - [BT Scan & Select — How It Works](#bt-scan--select--how-it-works)
    - [Multi-Session Counter-Surveillance Workflow](#multi-session-counter-surveillance-workflow)
    - [AirTag / SmartTag Locator — How It Works](#airtag--smarttag-locator--how-it-works)
    - [GATT Walker — How It Works](#gatt-walker--how-it-works)
    - [BT Observer — How It Works](#bt-observer--how-it-works)
    - [Bluetooth Lookout — How It Works](#bluetooth-lookout--how-it-works)
    - [BlueDuck — BLE HID Keyboard Injector](#blueduck--ble-hid-keyboard-injector)
    - [WhisperPair — CVE-2025-36911 Fast Pair Bypass](#whisperpair--cve-2025-36911-fast-pair-bypass)
  - [Wardriving](#3-wardriving)
    - [Starting a Wardrive](#starting-a-wardrive)
    - [Mark Button — GPS Waypoints](#mark-button--gps-waypoints)
    - [Options Screen](#options-screen)
    - [BLE Time-Sliced Wardriving](#ble-time-sliced-wardriving)
    - [Manage Data Screen](#manage-data-screen)
    - [Wardrive File Format](#wardrive-file-format)
    - [Wardriving Workflow — Field Use](#wardriving-workflow--field-use)
  - [Settings](#4-settings)
    - [TX Power Mode](#tx-power-mode)
    - [GATT Connect Timeout](#gatt-connect-timeout)
    - [Data Transfer](#data-transfer)
  - [Zigbee Scout](#6-zigbee-scout)
  - [NM-RF-HAT](#7-nm-rf-hat)
    - [Infrared (DIP 4)](#infrared-dip-4)
      - [Universal Remote](#universal-remote)
      - [TV-B-Gone](#tv-b-gone)
    - [RF433 OOK/ASK (DIP 5)](#rf433-ookask-dip-5)
    - [PN532 NFC/RFID (DIP 3)](#pn532-nfcrfid-dip-3)
      - [NTAG213/215/216 Full Dump](#ntag213215216-full-dump-workflow)
    - [CC1101 Sub-GHz (DIP 1)](#cc1101-sub-ghz-dip-1)
      - [Band Scope — SDR Frequency Marker](#band-scope)
      - [Fox Hunt](#fox-hunt)
      - [Z-Wave Scout](#z-wave-scout)
      - [TPMS Monitor](#tpms-monitor)
    - [nRF24L01+ 2.4 GHz (DIP 2)](#nrf24l01-24-ghz-dip-2)
      - [nRF24 Packet Sniffer](#nrf24-packet-sniffer)
      - [Fox Hunt (nRF24)](#fox-hunt-1)
- [3D Printable Cases](#3d-printable-cases)
- [Data & Storage](#data--storage)
- [Touch Calibration](#touch-calibration)
- [Building & Flashing](#building--flashing)
- [Photos](#photos)
- [On Signal Jamming](#on-signal-jamming)
- [Disclaimer](#disclaimer)

---

## Features Overview

| Category | Features |
|----------|----------|
| **WiFi Scanning** | Active scan, per-channel analysis, RSSI, client enumeration |
| **WiFi Attacks** | Deauth, Evil Twin, Captive Portal, Blackout, Snifferdog, SAE Overflow |
| **Handshake Capture** | WPA/WPA2 4-way handshake capture (PCAP & HCCAPX) |
| **Karma AP** | Respond to probe requests, rogue access point |
| **Chanalizer** | Wide 520 px WiFi channel map — auto-scrolling left/right with touch-drag pause; SSID color grouping, group legend, channel annotations; portrait 240 px viewport over 2.4 GHz + 5 GHz |
| **WiFi Band Scope** | Promiscuous RSSI per-channel waterfall (2.4 GHz 13-ch or 5 GHz 25-ch); band toggle updates axis label and resets peaks; 60 ms dwell / 0.8 s full 2.4 sweep |
| **Drone Detector** | Passive BLE scan for DJI/Remote ID drone advertisements |
| **Wardriving** | GPS + WiFi logging, dual-band filter (2.4 GHz / 5 GHz / Both), optional BLE time-sliced scanning, WiGLE CSV 1.6, upload log tracking, raw PCAP toggle, GPS mark waypoints (GPX output), WiGLE and WDG Wars upload; GPS last-known position hold with 150 m stale accuracy when signal is lost; live dashboard shows separate WiFi network count and BLE device count |
| **GPS** | NMEA RMC auto-syncs system clock (FAT timestamps); last-known position persisted to NVS (5-minute throttle); manual fallback editor in Settings → GPS Info; all data-collection features (wardrive, GATT Walker, marks) use best available GPS transparently |
| **BLE** | AirTag scanner, SmartTag detection, BLE Locator, GATT Walker fingerprinting, BT Observer multi-walk, Bluetooth Lookout, BLE Spam (8 modes incl. Sour Apple), Device Spoof (general + directed), BLE Disconnect (directed), BLE PCAP (Kismet PCAPNG raw capture; BLE 5.0 extended advertisement support), **BlueDuck** (BLE HID DuckyScript keyboard injector), **HoneyPair** (BLE persona honeypot), **WhisperPair** (CVE-2025-36911 Google Fast Pair KBP bypass — auto-scan, sequential run-all FP targets, AES-128-ECB exploit); BT Scan & Select supports **Save List** (GPS-tagged JSON snapshot of every device found); **Matter [M] detection** passive tagging of Thread/BLE Matter devices by GATT service `0xFFF6` |
| **Zigbee Scout** | IEEE 802.15.4 passive wardrive using the ESP32-C5's built-in PHY; logs PAN IDs, channel, RSSI, device addresses, and NWK/APS frame metadata to WiGLE-compatible CSV + PCAP; RSSI locator locks onto a specific PAN; logs to `/sdcard/lab/zigbee/` |
| **BlueDuck** | BLE HID keyboard injector — pairs as any of 9 device personas; executes DuckyScript payloads from SD card (preloaded into PSRAM at boot, immune to SD DMA OOM during BLE); HUMAN_MODE variable-speed typing; Android (Win+H/B/N), Windows (Win+R/L, Ctrl+Shift+Esc), and iOS (Cmd+H/Space) keyboard shortcut support; session JSONL log to SD card; 13-script library included |
| **HoneyPair** | Continuous BLE persona honeypot — cycles 9 consumer device personas every 5 min, logs all pairing attempts to JSONL; GATT/HID enumeration on any pairing device; persona MACs randomised and deduplicated |
| **Deauth Monitor** | Passive detection of nearby deauth attacks |
| **Credentials** | Captive portal credential capture, WPA-SEC upload |
| **TX Power Mode** | Selectable Normal / Max Power for WiFi and BLE — persisted across reboots |
| **Data Transfer** | Self-hosted AP file server (TheLab) and WiFi client file server — browse, upload, create directories, and recursively delete folders from any browser; client IP logged to serial; IP shown on screen |
| **NM-RF-HAT** | Hardware addon board for RF expansion -- IR capture/replay/Universal Remote/TV-B-Gone (Flipper .ir); RF433 OOK capture/replay/OOK Scan/Fox Hunt/Jammer (Flipper .sub); CC1101 Sub-GHz: Band Scope (SDR freq marker + Hunt), Fox Hunt (RSSI bug-hunter haptic, 300-928 MHz tunable), RAW Capture+Replay, Z-Wave Scout, TPMS 315+433 MHz, **Alarm Sensor decoder (EV1527)**, **Weather Station decoder (Fine Offset)** (Flipper .sub); nRF24L01+ 2.4 GHz: Ch Scan/Sniffer/Jammer/Futaba S-FHSS/Fox Hunt (Flipper .nrf24); PN532 NFC/RFID: scan+Read All, NTAG213/215/216 full page dump, Clone/Write to blank NTAG, MIFARE Classic key-dict test, save/emulate/.nfc import+export (Flipper .nfc); DIP switch per module |
| **Fox Hunt** | Ham radio-style RF proximity tracker on all three sub-GHz radios. CC1101: tunable 300-928 MHz, RSSI bar + peak hold, adjustable squelch, bug-hunter haptic (pulse rate scales from 1 pulse/1.5 s at threshold to continuous at strong signal — always 100% motor strength for reliable feel). nRF24: carrier-detect rate bar across 2400-2525 MHz in 1 MHz steps. RF433: GPIO edge-count activity bar at 433.92 MHz. All three use the vibrator for proximity feedback. Band Scope → Fox Hunt tap-through with SDR-style draggable yellow frequency marker. |
| **OOK Protocol Decoding** | CC1101 Alarm Sensor: decodes **EV1527** 315/433 MHz OOK alarm sensors (door contacts, PIR, smoke, flood) — 24-bit address + 4-bit channel, RSSI, trigger count, scrollable live list. CC1101 Weather Station: decodes **Fine Offset** 433.92 MHz weather sensors (WH65/WH57/WS80/WH31 and similar) — temperature (°C), humidity, battery, RSSI, scrollable list. RF433 OOK Scan: same EV1527 decoder using the R4A_433 superheterodyne receiver for higher sensitivity at exactly 433.92 MHz. |
| **SD Card Remount** | Settings → SD Card → Remount SD Card: unmounts and re-mounts at 20/10/5 MHz fallback without physical eject — useful after a crash or RF-HAT FPC contact issue. |
| **CC1101 Crystal Cal** | CC1101 HW Test → Crystal Calibration. Consumer 26 MHz crystals drift ±8.7-17 kHz at 433 MHz (±20-40 ppm). Error is proportional — the same ppm causes 2× more Hz deviation at 915 MHz vs 433 MHz. CAL TX 433 button transmits a continuous carrier for measurement. Set Offset popup accepts ±130 kHz (= ±300 ppm). Stored as PPM so it scales correctly to all bands automatically. Persists to NVS ("cc1101_ppm" key). |
| **UI** | Material dark theme, touch gestures, screen dimming, screenshots — all screens portrait 240×320 |
| **Storage** | SD card for handshakes, wardrive logs, GATT Walker JSON, screenshots, file tree browser |

---

## Menu Map

Complete navigation tree as of v2.4.44. Items marked `[stub]` are placeholders with "Coming in next version" screens. Items marked `[RF-HAT]` require the NM-RF-HAT expansion board enabled in Settings → Hardware Options.

```
Home
├── WiFi
│   ├── Scan & Attack
│   ├── WiFi Attacks
│   │   ├── Blackout (Evil Twin)
│   │   ├── Handshaker
│   │   └── Portal
│   ├── Deauth Monitor
│   ├── WiFi Observer (Sniffer / Karma)
│   ├── Drone Detect
│   ├── Chanalizer
│   └── WiFi Scope
├── Bluetooth
│   ├── BT Scan & Select
│   ├── BT Observer
│   ├── AirTag Scan
│   ├── BT Locator
│   ├── BT Lookout
│   ├── BT Attacks
│   │   ├── BLE Spam
│   │   ├── Device Spoof
│   │   ├── Blue Duck (BLE HID DuckyScript)
│   │   └── Whisper Pair (CVE-2025-36911)
│   ├── BLE PCAP
│   ├── Honey Pair
│   └── List Wizard
├── Wardrive
│   ├── Start Wardrive
│   ├── Options
│   └── Manage Data
├── Settings
│   ├── Compromised Data
│   │   ├── Evil Twin Passwords
│   │   ├── Portal Data
│   │   └── Handshakes
│   ├── Timing
│   ├── Download Mode
│   ├── Screen
│   │   └── Recalibrate Touch
│   ├── SD Card
│   │   ├── Validate & Provision
│   │   ├── Free Space
│   │   ├── File Tree
│   │   ├── New Folder
│   │   ├── Delete File
│   │   ├── Remount SD Card
│   │   └── Format SD Card
│   ├── GPS Info
│   ├── Hardware Options
│   │   └── NM-RF-HAT Enable / Disable
│   ├── Data Transfer
│   │   ├── AP File Server
│   │   ├── WiFi Client
│   │   └── Wardrive Upload [stub]
│   └── Vibrator Test
├── Go Dark (display off)
├── Zigbee Scout
├── Infrared [RF-HAT DIP 4]
│   ├── Capture
│   ├── Replay  →  <Remote>.ir  →  Signal list
│   ├── Universal Remote
│   ├── TV-B-Gone
│   └── IR Jammer
├── Radio [RF-HAT]
│   ├── CC1101 Sub-GHz [DIP 1]  — 2 pages
│   │   ├── Page 1
│   │   │   ├── HW Test  (crystal calibration offset + CAL TX 433 carrier)
│   │   │   ├── Band Scope (SDR freq marker + Hunt button)
│   │   │   ├── Fox Hunt (300-928 MHz tunable, RSSI+squelch, haptic)
│   │   │   ├── Capture RAW
│   │   │   ├── Replay RAW
│   │   │   ├── Saved Files
│   │   │   ├── Z-Wave Scout
│   │   │   ├── TPMS Monitor (315 / 433 MHz, 20 sensors)
│   │   │   └── Weather Station (Fine Offset decoder — temp/humidity/battery)
│   │   └── Page 2
│   │       ├── POCSAG Pager [stub]
│   │       ├── Alarm Sensor (EV1527 decoder — 315/433 MHz, 24-bit addr)
│   │       ├── RF Wardrive [stub]
│   │       ├── Decode Proto [stub]
│   │       ├── Jammer  (band: 315/433W/433N/868/915; 2-FSK ±381 kHz; 12-step sweep)
│   │       └── Brute Force [stub]
│   ├── nRF24L01+ 2.4 GHz [DIP 2]  — 2 pages
│   │   ├── Page 1
│   │   │   ├── HW Test
│   │   │   ├── Ch Scan (2400-2525 MHz, carrier detect)
│   │   │   ├── Sniffer
│   │   │   ├── Saved Files
│   │   │   ├── Jammer
│   │   │   ├── Futaba S-FHSS
│   │   │   └── Fox Hunt (channel tunable, haptic)
│   │   └── Page 2
│   │       ├── MouseJack [stub]
│   │       ├── Kb Inject [stub]
│   │       ├── Drone Scan [stub]
│   │       └── Game Pad [stub]
│   └── RF433 OOK/ASK [DIP 5]
│       ├── Capture
│       ├── Replay
│       ├── Jammer  (1 kHz OOK modulation, T2-433M transmitter)
│       ├── LBK Test (loopback)
│       ├── Fox Hunt (433.92 MHz fixed, edge-count activity, haptic)
│       └── OOK Scan (EV1527 decoder via R4A_433 superheterodyne RX)
└── RFID/NFC [RF-HAT DIP 3]
    ├── Scan & Read  →  Read All (full page dump)  →  Save / Export .nfc
    ├── Clone/Write  →  Select source  →  Clone to blank NTAG
    ├── Card Emulate →  Select saved card  →  Emulate / Stop
    ├── Key Test     →  MIFARE Classic dict attack
    ├── Saved Cards  →  load / emulate / Flipper .nfc import
    └── HW Test      →  PN532 I2C probe, I2C bus scan
```

---

## Screenshots

<p align="center">
  <img width="150" src="docs/screenshots/Main_Menu.bmp" alt="Main Menu" />
  &nbsp;
  <img width="150" src="docs/screenshots/WiFi_Menu.bmp" alt="WiFi Menu" />
  &nbsp;
  <img width="150" src="docs/screenshots/WiFi_ScanAttack.bmp" alt="WiFi Scan & Attack" />
</p>
<p align="center">
  <img width="150" src="docs/screenshots/WiFi_Select_Attack.bmp" alt="Select Attack Target" />
  &nbsp;
  <img width="150" src="docs/screenshots/WiFi_WarDrive.bmp" alt="Wardrive" />
</p>
<p align="center">
  <em>Main Menu &nbsp;·&nbsp; WiFi Menu &nbsp;·&nbsp; Scan & Attack &nbsp;·&nbsp; Select Target &nbsp;·&nbsp; Wardrive</em>
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
| **GPS** | [ATGM336H GPS+BDS Dual-Mode Module](https://www.amazon.com/dp/B09LQDG1HY) (Teyleten Robot, ASIN B09LQDG1HY; search "ATGM336H UART" if unavailable) — outputs NMEA 0183 GGA + RMC at 9600 baud, 3.3 V, onboard ceramic patch antenna | UART1 @ 9600 baud |
| **LED** | WS2812 NeoPixel (single, GPIO 27) | RMT / GPIO |
| **Vibrator** | ERM vibrator motor via SC8002B class-D amp (SPEAK header, GPIO 26) — optional add-on; requires 1N5819 + 1N4148 diode circuit; see Vibrator Motor Circuit section | LEDC PWM |

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
    SPEAK_IN (SC8002B)┤ GPIO 26          │ (vibrator motor driver)
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
| 26 | SPEAK_IN → SC8002B amp | LEDC PWM | Vibrator motor driver; 333 Hz / 50% duty max; see Vibrator Motor Circuit |
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

**Recommended module:** [Teyleten Robot ATGM336H GPS+BDS Dual-Mode Module](https://www.amazon.com/dp/B09LQDG1HY) (Amazon ASIN B09LQDG1HY, typically sold as a 2-pack)

> If the link above is unavailable, search Amazon or AliExpress for: **"ATGM336H GPS BDS module UART"** or **"Teyleten Robot ATGM336H"**. The module is also sold under other brand names (e.g. HiLetgo, KeeYees) — any ATGM336H-based board with a 4-pin header (VCC / GND / TX / RX) and a 3.3 V UART interface will work.

The ATGM336H is a compact GPS/BeiDou dual-mode GNSS module that outputs standard NMEA 0183 sentences (GGA, RMC) at 9600 baud over a 3.3 V UART interface. It is manufactured by ZHONGKEWEI (ATGM) and is a cost-effective drop-in replacement for the popular u-blox NEO-6M and NEO-M8N modules. The Teyleten Robot variant ships with an onboard passive ceramic patch antenna and a 5-pin 2.54 mm header (VCC / GND / TX / RX / PPS). No level shifter is required — the module operates natively at 3.3 V and connects directly to the NM-CYD-C5 LP-UART pins with just 4 wires.

**Wiring diagram — 4 wires only:**

```
ATGM336H Module          NM-CYD-C5 (ESP32-C5)
┌────────────┐           ┌──────────────────┐
│        VCC ├───────────┤ 3.3 V            │
│        GND ├───────────┤ GND              │
│         TX ├───────────┤ IO4  (UART1 RX)  │
│         RX ├───────────┤ IO5  (UART1 TX)  │
│        PPS │  (unused) │                  │
└────────────┘           └──────────────────┘

  ⚠️  Power from 3.3 V only — do NOT use the 5 V pin
  ⚠️  TX on the GPS module connects to RX on the ESP (and vice versa)
```

| Signal | ATGM336H pin | ESP32-C5 pin | Notes |
|--------|-------------|-------------|-------|
| Power | VCC | 3.3 V | Do **not** connect to 5 V — module is 3.3 V only |
| Ground | GND | GND | Common ground required |
| Data to ESP | TX | IO4 (UART1 RX) | Module transmits NMEA sentences |
| Data from ESP | RX | IO5 (UART1 TX) | Optional — only needed to send config commands |
| Timing pulse | PPS | — | Not connected; not used by firmware |

**Settings:** UART1 · 9600 baud · 8N1 · no flow control

The firmware parses **GGA** sentences for latitude, longitude, altitude, and satellite count, and **RMC** sentences for fix validity and date/time.

**System clock sync:** The first valid RMC sentence with an active fix (`status = A`) sets `settimeofday()` with the GPS UTC date and time. This corrects the ESP32's clock — which boots at epoch (1970-01-01) — so that files written to the SD card carry accurate FAT timestamps. The sync logic re-applies the time on every incoming RMC sentence until the system year reaches 2024 or later, meaning a late GPS fix (e.g. acquired 60 s into a wardrive) will still correct the timestamps of all files written afterward.

**Last-known position persistence:** Every valid GGA fix is snapshotted to a `g_gps_last_known` global. When GPS signal is lost (entering a building, underground parking, etc.) all data-collection features automatically fall back to the last-known coordinates and report an accuracy of **150 m** (approximately one city block) in the WiGLE CSV `AccuracyMeters` field and in GPX waypoints. This ensures wardrive sessions continue collecting data indoors rather than pausing or producing empty location entries.

The last-known position is also written to **NVS** (keys `gps_lat_i`, `gps_lon_i`, `gps_alt_i`, stored as integer micro-degrees ×10⁶) and reloaded at boot — so even if the first session of the day starts with no GPS fix, the device uses the last outdoor position from a prior session. Writes are throttled to at most once every five minutes to protect NVS flash life (~5+ years at that rate). An explicit save via **Settings → GPS Info → Set Position** bypasses the throttle.

In addition to the periodic throttled save, the firmware **force-saves immediately when GPS lock is lost** — detected by an RMC sentence with `status = V` (void) while `current_gps.valid` is `true`. This ensures the most recent fix survives a power cycle even if lock was lost before the next scheduled five-minute write.

Cold start to first fix typically takes 30–60 seconds with a clear sky view.

---

### Vibrator Motor Circuit

An ERM (eccentric rotating mass) vibrator motor can be added to the NM-CYD-C5 via the onboard **SC8002B class-D amp** on the SPEAK header (GPIO 26). Two diodes convert the BTL differential output into safe unidirectional motor drive:

| Role | Part | Notes |
|------|------|-------|
| Series rectifier | [1N5819 Schottky diode](https://a.co/d/0bnr0eiq) | Anode → VO1 (SPEAK pin 1), cathode → motor +. Half-wave rectifies the BTL output so current flows only in one direction. |
| Flyback / protection | [1N4148 signal diode](https://a.co/d/01jTSulE) | Cathode → motor +, anode → motor −. Suppresses back-EMF inductive spikes when the motor stops. |
| Motor | [Mini ERM Vibration Motor](https://a.co/d/00013Sqj) | Micro coin or cylindrical ERM, 3 V nominal. |
| SPEAK header connector | JST GH 1.25 mm 2-pin (HCZZ0015-2) | **1.25 mm pitch** — the 1.0 mm SH connector is too small and will not fit. |

**How it works:** GPIO 26 drives the SC8002B input with LEDC PWM at **333 Hz / 50% duty** (half-wave max = 50% duty). The 1N5819 rectifies the BTL output to give the motor a clean DC-biased drive. The 1N4148 across the motor clamps the inductive kick on every PWM off-cycle. Strength is adjustable 10–100% via **Settings → Vibrator Test** without reflashing.

**Why not drive the motor directly from GPIO:** ERM vibrator motors draw 100–200 mA at startup and 50–150 mA running — well beyond the ESP32-C5's safe GPIO limit of ~20 mA continuous (40 mA absolute maximum per pin, ~40 mA total chip budget across all outputs). Connecting a motor directly to a GPIO risks brownout or pin damage. The SC8002B acts as a current-buffered power stage: the GPIO sources only ~1 mA into the amplifier input, while the amp's BTL outputs can deliver up to ~1.5 A peak from the board's power rail. After half-wave rectification at 3.3 V supply (minus ~0.3 V Schottky drop = ~3.0 V motor drive), into a typical small ERM motor (~8–16 Ω), peak pulse current is **200–375 mA** and average current at 50% PWM duty is **100–180 mA** — roughly 10–15× what a GPIO could safely supply. The 1N4148 flyback diode is essential for the same reason: when the PWM pulse ends the motor's inductance produces a reverse voltage spike that would otherwise be absorbed by (and damage) the SC8002B output.

**Circuit photos:**

<p align="center">
  <img src="docs/screenshots/Vibrator Rectifier Circuit Closeup.jpg" width="480" alt="Vibrator rectifier circuit — diode detail"/>
  <br/><em>Rectifier circuit closeup — 1N5819 series + 1N4148 flyback</em>
</p>

<p align="center">
  <img src="docs/screenshots/Vibrator Wireup.jpg" width="480" alt="Vibrator motor wired to SPEAK header"/>
  <br/><em>Motor wired to SPEAK header with diode circuit</em>
</p>

<p align="center">
  <img src="docs/screenshots/Vibrator Wraped.jpg" width="480" alt="Vibrator assembly wrapped for installation"/>
  <br/><em>Assembly wrapped and ready to install</em>
</p>

<p align="center">
  <img src="docs/screenshots/Vibrator Installed.jpg" width="480" alt="Vibrator motor installed in device"/>
  <br/><em>Motor installed in device</em>
</p>

---

## 3D Printable Cases

The community has designed several enclosures for the NM-CYD-C5 with NM-RF-HAT. All three are designed to fit the full stack — board + RF-HAT + GPS module.

> **DIP switch access note:** Two of the cases below enclose the NM-RF-HAT's DIP switches inside the enclosure, requiring you to open or partially disassemble the case to switch between RF modules. If you plan to switch modules frequently, consider relocating the DIP switches to an external position — solder short extension wires to the switch pads and mount a panel-mount DIP switch on the case exterior — before printing your enclosure.

---

### Case 1 — NM-RF-HAT + CYD2USB + ATGM336H + 18650 Battery

**[MakerWorld — Case for NM-RF-HAT / CYD2USB / ATGM336H / 18650](https://makerworld.com/en/models/2670158-case-for-nm-rf-hat-cyd2usb-atgm336h-18650)**

Integrates the NM-CYD-C5, NM-RF-HAT, ATGM336H GPS module, and an 18650 lithium cell in a single enclosure. Designed for fully self-contained field use with onboard battery.

- 18650 cell bay for extended runtime
- ATGM336H GPS module compartment
- Note: DIP switches may require case access to switch modules

---

### Case 2 — Magnetic Enclosure (6×2mm Magnets)

**[Printables — CYD NM-RF-HAT Enclosure / Magnetic 6×2mm](https://www.printables.com/model/1638712-cyd-nm-rf-hat-enclosure-case-magnetic-6x2mm-magnet)**

Snap-together enclosure using six 6×2mm embedded magnets for tool-free opening. Good balance between protection and module accessibility.

- Magnetic lid opens without screws or clips
- Clean exterior with access provisions
- Note: DIP switches are internal — relocate if switching modules frequently

---

### Case 3 — The Cool One

**[Thingiverse — CYM-NM28C5 Enclosure](https://www.thingiverse.com/thing:7305463)**

Community favorite. Well-proportioned, solid construction, designed specifically for this project's use case.

- Designed with the CYM firmware in mind
- DIP switches accessible from exterior — no disassembly required to switch modules

---

## Software Features — Detailed

### 1. WiFi

The **WiFi** tile opens a sub-menu grouping all WiFi functions:

```
Main Menu
├── WiFi
│   ├── Scan & Attack
│   ├── WiFi Attacks
│   ├── Chanalizer
│   ├── WiFi Band Scope
│   ├── Deauth Mon.
│   └── WiFi Observer
├── Bluetooth
│   ├── BT Scan & Select
│   │   └── (select device) → Actions
│   │       ├── BT Locator
│   │       ├── GATT Walker
│   │       ├── Add to BT Lookout
│   │       └── BT Attacks (directed)    ← uses pre-selected device
│   │           ├── Device Spoof
│   │           └── BLE Disconnect
│   ├── BT Attacks                       ← general attacks
│   │   ├── BLE Spam
│   │   └── Device Spoof                 ← loads spooflist.csv
│   ├── BT Observer          ← scan + auto-GATT all visible devices
│   ├── AirTag Scan
│   ├── BT Locator
│   └── Bluetooth Lookout
│       ├── Edit Watchlist
│       └── OUI Groups
├── Wardrive
│   ├── Start Wardrive
│   ├── Options              ← band (2.4/5/Both), raw PCAP toggle, BLE wardrive toggle
│   └── Manage Data         ← CSV file list, upload-log color coding, delete, upload
├── Settings
│   ├── Compromised Data
│   ├── Timing
│   │   ├── WiFi Scan/Ch  (min/max dwell sliders)
│   │   └── GATT Timeout  (3–30 s slider)
│   ├── Download Mode
│   ├── Screen
│   │   ├── Timeout       (inactivity timer)
│   │   └── Brightness    (10–100% overlay)
│   ├── SD Card
│   ├── GPS Info            ← live status; amber display when using last-known
│   └── Set Position    ← manual lat/lon/alt editor, saves to NVS
├── Power Mode
│   └── Data Transfer
│       ├── AP File Server
│       ├── WiFi Client
│       └── Wardrive Upload
└── Go Dark
```

#### WiFi Scan & Attack

**Active WiFi scanning** with per-network details, followed by targeted attacks on selected networks.

| Feature | Description |
|---------|-------------|
| **WiFi Scan** | Scans all channels, shows SSID, BSSID, RSSI, channel, encryption |
| **Deauth Attack** | Sends deauthentication frames to disconnect clients from selected AP. Triggers a 3-second vibrator pulse on launch (requires vibrator hardware). |
| **Evil Twin** | Creates a rogue AP cloning the target SSID to lure clients |
| **Captive Portal** | HTTP server presenting a custom HTML login page to capture credentials |
| **Handshake Capture** | Captures WPA/WPA2 4-way handshakes and saves as PCAP/HCCAPX |
| **ARP Poisoning** | LwIP-based ARP spoofing for MitM scenarios |

#### Evil Portal Resources

The Captive Portal, Evil Twin, and Karma AP features all serve HTML pages from **`/sdcard/lab/htmls/`** as the captive login page. Drop any number of `.html` or `.htm` files there — each one appears as a selectable option in the portal dropdown when launching an attack. No recompilation needed.

**To add portals:**
1. Format your SD card and run **SD Card → Provision** to create the directory structure
2. Copy your `.html` / `.htm` files directly into `/sdcard/lab/htmls/` on the card
3. Reinsert the card and reboot — all files in that folder appear in the attack portal dropdown
4. Credentials submitted by victims are appended to `/sdcard/lab/eviltwin.txt`

The community has built extensive collections of pre-made portals styled to look like ISP login pages, hotel WiFi gates, popular service sign-ins, and more:

| Repository | Description |
|------------|-------------|
| [D3h420/Evil-Portals-Collection](https://github.com/D3h420/Evil-Portals-Collection) | Large multi-target collection of portal HTML files — ISPs, hotels, and brands |
| [DoobTheGoober/EvilPortalGenerator](https://github.com/DoobTheGoober/EvilPortalGenerator) | Generator tool for quickly creating custom portal pages from templates |
| [saintcrossbow/Evil-Cardputer-Portals](https://github.com/saintcrossbow/Evil-Cardputer-Portals) | Portal pages adapted for M5Stack Cardputer; most transfer directly |

> **Note:** Files must have a `.html` or `.htm` extension to appear in the dropdown. Any filename works — you can keep multiple portals on the card and switch between them per-attack.

#### Global WiFi Attacks

Attacks that operate on **all nearby networks** simultaneously.

| Feature | Description |
|---------|-------------|
| **Blackout** | Mass deauthentication of all detected networks in range |
| **Snifferdog** | Channel-hopping sniffer with automatic client deauthentication; exits cleanly and returns radio to normal WiFi scan mode |
| **SAE Overflow** | WPA3 SAE authentication flood attack |

#### WiFi Observer & Karma

Passive network intelligence and rogue AP capabilities.

| Feature | Description |
|---------|-------------|
| **WiFi Observer** | Passive 802.11 sniffing in promiscuous mode — shows APs, associated clients, and probe requests |
| **Karma AP** | Automatically responds to client probe requests, creating matching rogue APs |

#### Deauth Monitor

**Passive detection** of deauthentication attacks happening in the area. Alerts when deauth frames are detected on nearby channels — useful for detecting hostile activity.

#### Chanalizer

**WiFi channel visualization** — a 520 px wide portrait-mode channel map showing both 2.4 GHz (ch 1–13) and 5 GHz (ch 36–165) in a single scrollable view. All visible SSIDs are plotted as color-coded bar groups positioned at their operating channel, with a legend showing the group color → SSID mapping.

- **Auto-scroll:** The chart pans left/right automatically (2 px per tick, bouncing at each end) so the full band is always visible without interaction.
- **Touch drag:** Tap and drag to pause auto-scroll and manually scrub to any position. Releasing resumes auto-scroll.
- **SSID picker:** Tap any SSID in the legend to highlight that network's bar across all its channels.
- **Group color coding:** Up to 8 SSID groups are color-coded; legend shows group → SSID mapping.
- **Channel annotations:** Channel numbers annotate the x-axis at correct pixel positions.

#### WiFi Band Scope

**Per-channel RSSI spectrum and waterfall** using the WiFi promiscuous radio. Measures peak RSSI of received 802.11 frames per channel — reflects band activity and congestion, not raw RF noise floor.

| Band | Channels | Sweep time |
|------|----------|------------|
| 2.4 GHz | 13 channels (1–13) | ~0.8 s |
| 5 GHz | 25 channels (36–165) | ~1.5 s |

The spectrum bar chart (top) shows current peak RSSI per channel as a heat-color bar. The waterfall (bottom) scrolls down one row per completed sweep, building a time history of band activity. Tap **Band: 2.4GHz / Band: 5 GHz** to toggle — the axis label, peak arrays, and waterfall all reset cleanly on each switch.

### 2. Bluetooth

BLE scanning and fingerprinting features leveraging the ESP32-C5's BLE 5.0 radio.

```
Bluetooth
├── BT Scan & Select    ← start here
│   └── (select device) → Actions
│       ├── BT Locator      (RSSI tracking)
│       ├── GATT Walker     (full GATT fingerprint + JSON output)
│       ├── Add to BT Lookout
│       └── BT Attacks      ← directed attacks on pre-selected device
│           ├── Device Spoof    (clones target MAC + name, no selection needed)
│           └── BLE Disconnect  (flood target with TERMINATE_IND)
├── BT Attacks          ← general attacks (no target needed)
│   ├── BLE Spam        (Apple Prox. Pair / Samsung / Google / Windows / All / AirTag / SmartTag / Sour Apple)
│   ├── Device Spoof    (select from spooflist.csv or add new entry via keyboard)
│   └── WhisperPair     ← CVE-2025-36911 Fast Pair KBP pairing bypass (detect / probe / exploit)
├── BlueDuck            ← BLE HID keyboard injector + DuckyScript engine
│   ├── Script selector (scans /sdcard/lab/ble/blueduck/scripts/)
│   ├── Persona picker  (9 device identities + auto-rotate)
│   └── Live stats      (connects / payloads / disconnects)
├── BT Observer         ← 10 s scan then sequential GATT walk on all found devices
├── BLE PCAP            ← raw Kismet PCAPNG capture; streams to SD card
├── AirTag Scan
├── Drone Detector
├── BT Locator
├── List Wizard         ← multi-select btsc_*.json files → Unique / Common set ops
└── Bluetooth Lookout   ← continuous watchlist monitor
    ├── Edit Watchlist
    ├── Edit Blacklist
    └── OUI Groups
```

| Feature | Description |
|---------|-------------|
| **BT Scan & Select** | Active BLE scan — discovers all nearby devices; shows name or vendor (from OUI lookup), RSSI, partial MAC; tap to select a target; **Save List** saves the full scan to a GPS-tagged JSON file on SD; **Rescan** restarts the scan in-place; **Actions →** opens attack tiles on selected target. Devices advertising GATT service `0xFFF6` (Matter Commissioning) are tagged `[M]` — passive detection of Thread/BLE Matter IoT devices with no connection required. |
| **List Wizard** | Multi-file BT scan list analysis. Reads all `btsc_*.json` files from SD, sorted newest-first. Select up to 4 files, set an optional RSSI threshold, then compute **Unique** (devices exclusive to exactly one file, min RSSI) or **Common** (devices in every selected file, avg RSSI). Results sorted by RSSI descending with a live **Change** re-filter button; save as new scan file or push to BT Lookout. Per-row delete with confirm dialog. |
| **BT Blacklist** | Per-device suppression list at `/sdcard/lab/bluetooth/blacklist.csv`. Any device on the blacklist is silently ignored by BT Scan & Select, BT Lookout, BLE PCAP, and all other BT scan functions. Editor in the **BT Lookout** screen via the **Blacklist** button. |
| **BT Observer** | Configurable-duration BLE scan (default 10 s, set via Settings → Timing) followed by sequential GATT walks on every discovered device (5 s timeout per device). Results shown in a scrollable live list; tap any row to open the full GATT detail view |
| **BT Locator** | RSSI-based proximity tracking of a selected BLE device; updates every 10 s. Vibrator strength scales logarithmically with signal strength — silent below −69 dBm, 10% at −69 dBm, 100% at −40 dBm (requires vibrator hardware). |
| **GATT Walker** | Full BLE GATT inspection — walks all services, characteristics, and descriptors; reads attribute values; computes FNV-32 device fingerprint; saves enriched JSON to SD card with service/characteristic names, decoded properties, ASCII data preview, OUI manufacturer, and optional GPS geotag |
| **AirTag Scanner** | Passive BLE scan — detects Apple AirTags and Samsung SmartTags by manufacturer ID |
| **Tag Locator** | Per-tag RSSI tracking launched from the AirTag Scan found-tags list |
| **Bluetooth Lookout** | Continuous BLE monitor that alerts when a watchlisted device (by full MAC or OUI prefix) is detected nearby. Triggers 3 × 1-second vibrator pulses on each detection (requires vibrator hardware). |
| **BLE Spam** | Broadcasts fake BLE advertisements — Apple Prox. Pair (13 device types), Samsung Fast Connect (6 models), Google Fast Pair (12 model IDs), Windows Swift Pair, Apple Find My (AirTag), Samsung SmartTag, **Sour Apple** (Apple Nearby Action 0x0F — cycles 11 action types to flood iOS with system popups), or All simultaneously |
| **Drone Detector** | Passive BLE scan for DJI/Remote ID drone advertisements — detects drones broadcasting operator ID and location data |
| **Device Spoof (directed)** | Clones the MAC address and name of a device pre-selected in BT Scan & Select — no additional selection step required |
| **Device Spoof (general)** | Loads `/sdcard/lab/bluetooth/spooflist.csv`; select an entry or add new devices via on-screen keyboard, then START to begin spoofing |
| **BLE Disconnect (directed)** | Floods a BT Scan & Select pre-selected target with BLE TERMINATE_IND frames to force disconnection |
| **BLE PCAP** | Captures raw BLE advertising packets to SD card in Kismet PCAPNG format (link type 256 — `LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR`). Includes a 10-byte pseudo-header per packet: RF channel 37, RSSI, noise floor, and BLE access address. Queue-based write path keeps the SD bus free for the UI. Live packet count shown on screen. |
| **BlueDuck** | BLE HID keyboard injector. Pairs with any nearby BLE-capable device, then executes DuckyScript payloads — sending keystrokes as if from a Bluetooth keyboard. Nine built-in device personas (Wireless Keyboard, AirPods Pro, Fitbit, Galaxy Buds, Garmin Fenix, Apple Watch, JBL speaker, Logitech MX Keys, Samsung TV). Auto-rotate mode cycles personas every 5 minutes. Scripts are preloaded into PSRAM at scan time (immune to SD DMA OOM during BLE). HUMAN_MODE with SLOW/NORMAL/FAST variable-speed typing. Full Android (Win+H/B/N), Windows (Win+R/L, Ctrl+Shift+Esc, Win+Shift+S), and iOS (Cmd+H/Space) keyboard shortcut support — 13-script library in `resources/blueduck_scripts/`. Session stats shown live; all events logged to `/sdcard/lab/ble/blueduck/`. |
| **HoneyPair** | BLE persona honeypot. Continuously cycles through 9 consumer device personas (AirPods, Galaxy Buds, Garmin watch, etc.), logging every device that initiates a pairing request. Persona MACs are randomised and deduplicated across sessions; auto-rotate every 5 minutes prevents stale scan-response caching. GATT/HID enumeration runs on any device that completes pairing. All events logged to `/sdcard/lab/ble/honeypair/`. |
| **WhisperPair** | CVE-2025-36911 Google Fast Pair Key-Based Pairing (KBP) bypass scanner. Passively detects Fast Pair–capable devices during BLE scan (tagged `[FP]` in scan list). Three attack modes: **Detect** (passive advertisement fingerprinting), **Probe** (GATT connect + service enumeration, confirms 0xFE2C service presence), and **Exploit** (writes a crafted AES-128-ECB encrypted KBP packet to trigger unsolicited pairing on vulnerable devices). All results logged to `/sdcard/lab/ble/whisperpair/`. *For authorized security research only.* |

> **Note:** WiFi and BLE share the same radio. The firmware automatically switches between `RADIO_MODE_WIFI` and `RADIO_MODE_BLE` as needed.

#### BT Scan & Select — How It Works

**Step 1 — Scan:** Open **BT Scan & Select** from the Bluetooth menu. An active BLE scan runs (duration configurable via Settings → Timing → BT Scan, default 10 s), collecting all advertising devices. Each row shows device name (or vendor from OUI lookup, or `[Unknown]`), RSSI, and the last 3 octets of the MAC address. The list updates live every 500 ms during the scan.

**Step 2 — Select:** Tap any row to select a target device. The row highlights in cyan and the status bar shows the selection. Tap again to deselect. Only one device can be selected at a time. **Scrolling the list does not select a device** — only a clean tap (no scroll movement) counts as a selection.

**Step 3 — Actions:** Once a device is selected, tap **Actions →** to open the action tile screen. Available actions: **BT Locator** (RSSI proximity tracking), **GATT Walker** (full GATT inspection and JSON output), and **Add to BT Lookout** (add the device MAC to the continuous watchlist). The target name or MAC is shown in the screen title.

**Bottom button row** (always visible, no device selection needed):

- **Exit** — stop scan and return to Bluetooth menu
- **Save List** — opens a label dialog; writes the full scan list to SD as a numbered JSON file
- **Rescan** (amber) — stops the current scan, clears the device list, and immediately starts a fresh scan at the configured duration
- **Actions →** (cyan, appears after device selection) — opens attack tile screen for the selected target

**Save List — File format**

Scan files are saved to `/sdcard/lab/bluetooth/scans/`. The filename encodes a monotonically-incrementing scan counter (NVS-persisted across reboots), the UTC time, GPS coordinates if available, and the user label:

```
btsc_00001_HHMMSS_LAT_LON_label.json   (with GPS — live or last-known)
btsc_00001_HHMMSS_label.json           (no GPS ever recorded)
```

GPS location uses the persistent GPS subsystem: `gps_best()` returns the live fix when available, or the last-known location (saved to NVS on each valid fix and on shutdown) when GPS signal is lost. You always get the closest known position even after a dropout.

**JSON schema:**

```json
{
  "label": "JBL",
  "timestamp": "143022",
  "datetime": "2026-05-20 14:30:22",
  "gps_lat": 37.4219984,
  "gps_lon": -122.0840012,
  "gps_alt": 12.3,
  "gps_live": true,
  "fw_version": "v1.6.54",
  "scan_id": 3,
  "device_count": 12,
  "devices": [
    {
      "mac": "AA:BB:CC:DD:EE:FF",
      "addr_type": 0,
      "phy": 1,
      "rssi": -62,
      "name": "JBL Flip 6",
      "company_id": 0,
      "is_airtag": false,
      "is_smarttag": false,
      "is_possible_airtag": false,
      "is_fast_pair": false
    }
  ]
}
```

| Field | Description |
|-------|-------------|
| `label` | User-supplied label (alphanumeric + `-_`, defaults to `mark`) |
| `timestamp` | `HHMMSS` UTC — used in filename |
| `datetime` | `YYYY-MM-DD HH:MM:SS` UTC from GPS-synced system clock |
| `gps_lat/lon/alt` | GPS coordinates — live fix or last-known persistent position |
| `gps_live` | `true` if GPS was live at save time; `false` if using last-known |
| `scan_id` | Monotonically increasing counter (NVS-persisted) — matches `%05u` prefix in filename |
| `device_count` | Number of entries in `devices[]` |
| `rssi` | Peak RSSI seen during scan (dBm) |
| `addr_type` | 0 = public, 1 = random |
| `phy` | 1 = 1M, 2 = 2M, 3 = coded |

#### List Wizard — How It Works

List Wizard reads all saved `btsc_*.json` scan files from `/sdcard/lab/bluetooth/scans/` and lets you compare them across sessions.

**File list:** Files are displayed newest-first (by scan counter). Each row shows the user label, the full save date and time (`YYYY-MM-DD HH:MM`), and the device count. A small red trash button on the right of each row deletes the file after a confirm dialog.

**Selection:** Tap up to 4 rows to select them (highlighted cyan). The status bar shows how many are selected.

**RSSI Threshold popup:** Before computing a set operation, tap **Unique** or **Common** to open the RSSI threshold popup. A slider from −99 dBm (no filter, default) to 0 dBm lets you exclude weak/distant devices.

**Set operations:**
- **Unique** (cyan) — devices exclusive to exactly one of the selected files. A device that appears in two or more files is excluded. RSSI shown is the **minimum** (signal floor) across all sightings of that device.
- **Common** (green) — devices present in **every** selected file. RSSI shown is the **average** across all sightings in all selected files.

**Result overlay:** A scrollable list sorted by RSSI descending. Each row shows `RSSI  MAC  Name`. An orange **RSSI bar** at the top shows the active threshold with a **Change** button — tap it to open the threshold slider and instantly re-filter without re-reading the SD card (the accumulator stays live in PSRAM for the lifetime of the result overlay).

**Bottom button row in result overlay:**
- **Close** — dismiss the overlay, return to file list
- **New List** — opens a label dialog and saves the result as a new `btsc_*.json` scan file (same format as BT Scan & Select)
- **Lookout** — appends all result MACs to `/sdcard/lab/bluetooth/lookout.csv` and reloads the BT Lookout watchlist

**BT Blacklist**

The blacklist at `/sdcard/lab/bluetooth/blacklist.csv` contains devices that should be globally suppressed. Any device whose MAC (or OUI prefix if `oui_only=1`) appears in the blacklist is silently skipped by BT Scan & Select, BT Lookout, BLE PCAP, and all other BT scan paths.

**CSV format** (same as lookout.csv — no header row):
```
AA:BB:CC:DD:EE:FF,0   # full MAC match
AA:BB:CC,1            # OUI prefix match (first 3 octets only)
```

The editor is in the **BT Lookout** screen — tap the **Blacklist** button (dark red, below the Edit List / OUI Groups row). Rows are shown in a scrollable list with a delete button on each entry and an **Add** button for new entries.

#### Multi-Session Counter-Surveillance Workflow

Use **BT Scan & Select** + **List Wizard** to detect whether a specific person or vehicle is carrying a fixed-MAC BLE tracker — an AirTag, Oura Ring, Fitbit, Garmin watch, or any other BLE device that does not randomize its MAC. The technique is simple: scan the same target environment twice and look for devices that appear in both sessions.

**Step 1 — First scan**

Open **BT Scan & Select** from the Bluetooth tile. Let the scan run for the configured duration (default 10 s; increase to 30 s in Settings → Timing for better coverage). When done, tap **Save List**, enter a descriptive label (e.g. `coffee_shop_1030`), and tap **Save**. The file is written to `/sdcard/lab/bluetooth/scans/`.

**Step 2 — Second scan (different time or location)**

Move to a second location — or wait for the target to leave and return — then scan again. Save with a new label (e.g. `coffee_shop_1430`). Any legitimate ambient device (smart speaker, neighbor's phone) should *not* appear in both scans. A tracker that follows the person *will*.

**Step 3 — Common device analysis**

Open **List Wizard** from the Bluetooth tile. Select both saved scan files (tap each row to highlight cyan). Optionally raise the RSSI threshold to exclude weak devices you were not physically near. Tap **Common**.

List Wizard returns every device that appeared in **both** scans. Sort by RSSI descending — devices near the top were strong, nearby, and consistent across sessions.

**Step 4 — Identify the tracker**

Look for devices with recognizable characteristics:

| Device | MAC behavior | How to spot |
|--------|-------------|-------------|
| Apple AirTag | Rotates every ~24 h when unpaired from owner | Name `AirTag`, manufacturer `Apple`, `is_airtag: true` flag |
| Oura Ring | Static MAC | OUI `70:C8:8B` (Oura Health) or name `Oura Ring` |
| Fitbit | Static MAC | OUI `E8:AB:F3` / `EC:5C:68` (Google/Fitbit) or name `Charge`, `Versa`, `Sense` |
| Garmin watch | Static MAC | OUI `C4:5A:B1` / `58:93:D8` (Garmin) or name `fenix`, `vivosmart` |
| Tile tracker | Static MAC | OUI from Tile, Inc.; name `Tile` |
| General fixed-MAC | Static | Same full MAC across both sessions; not in OUI Groups above |

Devices that rotated their MAC between sessions will **not** appear in Common — they are not reliable tracking vectors.

**Step 5 — Add suspects to BT Lookout**

In the result overlay, tap **Lookout** to append all Common results to the BT Lookout watchlist. Then open **Bluetooth Lookout** and tap **Start**. From this point, any time the suspected tracker comes within BLE range, the device fires 3 × 1-second vibrator pulses and shows a popup with the device name, MAC, vendor, and RSSI.

**Tips**

- Set the RSSI threshold to −70 dBm or higher to exclude devices that were only marginally visible (passers-by, parked cars one block away).
- If the target is a vehicle, scan the same parking lot or route. BLE range is ~10–30 m — you need to be near the vehicle for the tracker to register.
- Use the **New List** button to save the Common result as a new scan file for later reference or comparison against a third session.
- OUI Groups in BT Lookout lets you monitor all devices from a specific manufacturer (e.g. all Garmin OUIs) without needing a specific MAC — useful when the tracker may have cycled its address.

---

#### AirTag / SmartTag Locator — How It Works

The AirTag Scanner and Tag Locator work together to let you find a hidden tracking device using only the NM-CYD-C5 — no phone required.

**Step 1 — Scan**

Open **AirTag Scan** from the Bluetooth tile. The device switches the radio to BLE and begins a passive scan. Detected Apple AirTags and Samsung SmartTags are counted on screen, separated from general BLE traffic:

```
Air Tags:   2
Smart Tags: 1

Other BT Devices: 14
Total BT devices: 17
```

Once at least one tag is found the **View Found Tags** button appears.

**Step 2 — View Found Tags**

Tap **View Found Tags** to open a scrollable list of every detected AirTag and SmartTag. Each entry shows:

- Type badge (orange **AirTag** or cyan **SmartTag**)
- MAC address
- Device name (if advertised)
- Last seen RSSI in dBm
- A blue **Track** button

**Step 3 — Track**

Tap **Track** on any device. The firmware locks onto that device's MAC address and starts the BT Locator tracking task, which rescans for that specific MAC every 10 seconds and updates the live RSSI reading on screen.

Use the RSSI value to home in on the tag — a higher (less negative) number means you are closer:

| RSSI | Approximate distance | Vibrator strength |
|------|----------------------|-------------------|
| −40 dBm or stronger | Very close (within ~1 m) | 100% |
| −55 dBm | Nearby (~1–3 m) | ~58% |
| −69 dBm | ~5 m range edge | 10% (threshold) |
| Below −69 dBm | Far away or obstructed | Silent |

Vibrator strength updates every 500 ms and scales linearly with dBm (which is already a log-scale of power), giving a natural haptic proximity feel. The strength used by **Settings → Vibrator Test** is saved on entry and fully restored when you exit the locator.

<p align="center">
  <img width="340" alt="AirTag Far Away" src="docs/screenshots/airtag_detection_far.jpg" />
  <br/>
  <em>AirTag Far Away</em>
</p>

<p align="center">
  <img width="340" alt="AirTag Found" src="docs/screenshots/airtag_detection_close.jpg" />
  <br/>
  <em>AirTag Found</em>
</p>

Tap **Exit** at any time to stop tracking and return to the main menu. The radio switches back to WiFi mode automatically.

#### GATT Walker — How It Works

<p align="center">
  <img width="200" src="docs/screenshots/GATT_Walker.bmp" alt="GATT Walker" />
  <br/>
  <em>GATT Walker — live progress during a BLE inspection walk</em>
</p>

**GATT Walker** connects to a selected BLE device and performs a full GATT inspection — enumerating every service, characteristic, and descriptor, reading all readable attribute values, and saving the result as a structured JSON file on the SD card.

**Why GATT walk a device?**

Reading a device name is just the surface. A full GATT walk is one of the richest passive fingerprinting and intelligence-gathering techniques in the BLE space.

**Rolling MAC defeat.** Modern BLE devices randomize their advertising MAC every 7–15 minutes (iOS, Android, and Windows all do this). The GATT service/characteristic layout does not rotate — it is fixed per device model and firmware version. The FNV-32 fingerprint computed over the ordered set of service and characteristic UUIDs creates a stable device signature that survives MAC rotation entirely. Two captures with different MACs but matching fingerprints are almost certainly the same physical device. Combined with `System ID (0x2A23)` — which is derived from the Bluetooth address and does not rotate — and `Serial Number (0x2A25)`, you get a tracking signature more robust than the advertising MAC.

**Gratuitous information leakage.** Many devices expose the Device Information Service (0x180A) completely unauthenticated:

| Characteristic | UUID | What leaks |
|---|---|---|
| Manufacturer Name | 0x2A29 | Brand + sometimes ODM source |
| Model Number | 0x2A24 | Exact device model |
| Serial Number | 0x2A25 | Unit-level identifier — unique per device |
| Firmware Revision | 0x2A26 | Exact build — maps to known CVEs |
| System ID | 0x2A23 | Derived from BT address — stable across MAC rotation |
| PnP ID | 0x2A50 | Bluetooth SIG vendor + product ID |

**Vendor-specific services (0xFF00+)** are where IoT devices hide configuration registers, telemetry, WiFi SSIDs (and on some early/cheap devices, plaintext WiFi passwords), OTA firmware update channels, and debug/diagnostic services left enabled in production firmware. Descriptor labels (`0x2901`) are written by vendors for internal tooling and frequently left in production — strings like `"factory_reset_trigger"` or `"debug_uart_passthrough"` appear in the clear.

**Commercial tracking infrastructure.** Google Fast Pair (`0xFE2C`), Microsoft Swift Pair, Tile, and AirTag-style trackers all have fixed GATT service layouts regardless of rotating MACs. The service layout alone identifies which tracking network a device belongs to and often reveals the device model.

**Security posture assessment.** A GATT walk immediately reveals which characteristics require authentication or encryption versus which are open. A writable control characteristic that requires no pairing is a weak security model regardless of what it controls — useful for auditing devices before deployment.

**Subscription data layer.** A static GATT read only captures what the device holds at that moment. Characteristics with **N (Notify)** or **I (Indicate)** properties only push data to subscribed clients — heart rate sensors, glucose monitors, environmental sensors, and wearables stream live telemetry only after a client writes `0x0001` to the associated CCCD descriptor (`0x2902`). This is the layer a passive walk alone never sees.

**Workflow:**

1. Open **BT Scan & Select**, let the scan run, tap a device to select it.
2. Tap **Actions →**, then **GATT Walker**.
3. The active BLE scan stops automatically and a GATT connection is initiated to the target.
4. The screen shows live progress through the walk stages:

```
Connecting...
Connected, discovering services...
Chr discovery: svc 2/5
Discovering descriptors...
Reading characteristics...
Saving results...
Walk complete
```

5. When complete, the screen automatically transitions to a **full scrollable detail view** showing the entire GATT tree: MAC + OUI vendor, FP, GPS, per-service UUID + name, per-characteristic UUID + name, decoded property flags, hex data, and ASCII preview.

**Output file:** `/sdcard/lab/gattwalker/YYYYMMDD_HHMMSS_AABBCCDDEEFF_gattwalk.json`

```json
{
  "version": 1,
  "timestamp": "20260429_142233",
  "mac": "AA:BB:CC:DD:EE:FF",
  "addr_type": 0,
  "name": "My BLE Device",
  "manufacturer": "Texas Instruments",
  "rssi": -67,
  "gps": { "valid": true, "lat": 37.1234567, "lon": -122.4567890 },
  "fingerprint": "0xA3F1C2B0",
  "services": [
    {
      "uuid": "0x1800",
      "name": "Generic Access",
      "start_handle": 1,
      "end_handle": 8,
      "characteristics": [
        {
          "uuid": "0x2A00",
          "name": "Device Name",
          "def_handle": 2,
          "val_handle": 3,
          "properties": 2,
          "props_str": "R",
          "read_data": "4D7920446576696365",
          "ascii": "My Device"
        }
      ]
    }
  ]
}
```

**Fingerprint:** An FNV-32 hash computed over all service UUIDs, characteristic UUIDs, and property flags in walk order. Identical device models typically produce the same fingerprint, making it useful for passive device-type identification across multiple captures.

**GPS geotagging:** GATT Walker uses the best available GPS position — live fix if locked, last-known fallback if not (see [GPS Info & Fallback Position](#gps-info--fallback-position)). The JSON `gps.valid` field is `true` whenever any position is available (live or stale). When the fallback position was used, the coordinates are still useful for approximate area-level mapping; the 150 m stale accuracy is reflected in the surrounding context even though the JSON does not currently include an accuracy field.

**Characteristic Properties (`props` / `props_str`):** Each characteristic has a bitmask that declares what operations it supports. The JSON includes both the raw integer (`"properties"`) and the decoded string (`"props_str"`). The on-device result screen shows both the compact flag string and the full human-readable expansion, e.g. `Props: R N (Read, Notify)`.

<p align="center">
  <img width="220" src="docs/screenshots/GATT%20Walker%20Info.bmp" alt="GATT Walker detail view showing properties and data" /><br>
  <em>GATT Walker detail view — service tree with decoded properties and ASCII data</em>
</p>

| Bit | Hex | Flag | Meaning |
|-----|-----|------|---------|
| 0 | `0x01` | **BC** | Broadcast — value can be included in advertising packets |
| 1 | `0x02` | **R** | Read — current value can be read |
| 2 | `0x04` | **WNR** | Write No Response — fire-and-forget write, no acknowledgement |
| 3 | `0x08` | **W** | Write — acknowledged write; server confirms receipt |
| 4 | `0x10` | **N** | Notify — server pushes updates to subscribed clients (no ACK) |
| 5 | `0x20` | **I** | Indicate — server pushes updates; client must ACK each one |
| 6 | `0x40` | **AS** | Authenticated Signed Write — write with MITM-protected signature |
| 7 | `0x80` | **EX** | Extended Properties — additional properties stored in descriptor `0x2900` |

Common combinations:

| Props string | Raw | Typical use |
|---|---|---|
| `R` | `0x02` | Read-only sensor or config value |
| `R N` | `0x12` | Live sensor — read current value + subscribe for streaming updates |
| `R I` | `0x22` | Like notify but reliable — server waits for client ACK |
| `R W` | `0x0A` | Read/write configuration register |
| `WNR` | `0x04` | Command channel — write commands with no response needed |
| `R W N` | `0x1A` | Full-featured — read, write, and subscribe |

> **Tip:** To receive live streaming data (e.g. a heart rate sensor), look for characteristics with **N** (Notify) or **I** (Indicate). A **CCCD descriptor** (`0x2902`) is always present alongside these and is what a client writes to in order to enable or disable the subscription.

**BLE data limits:** The Bluetooth Core Specification sets a hard ceiling of **512 bytes** per attribute value. The firmware negotiates the maximum possible ATT MTU on every connection so that large attributes are captured in full rather than truncated at the BLE default of 20 bytes.

| Limit | Value | Source |
|-------|-------|--------|
| Max attribute value | **512 bytes** | BLE Core Spec — hard ceiling |
| Default ATT MTU payload | **20 bytes** | BLE spec default (no negotiation) |
| Max ATT MTU payload | **514 bytes** | BLE spec maximum |
| Firmware capture buffer | **512 bytes** | `GW_READ_MAX` — matches spec ceiling |

Attributes longer than one MTU are read automatically in multiple chunks (`ATT_READ_BLOB_REQ` chaining). `GW_READ_MAX = 512` is therefore the correct and final limit — no BLE device can legitimately send more than 512 bytes per characteristic.

**Walk limits:** Up to 20 services, 16 characteristics per service, 6 descriptors per characteristic. PSRAM-allocated (~250 KB result struct + 128 KB JSON buffer).

**Connect timeout:** Configurable via **Settings → Timing → GATT Timeout** (3 s – 30 s slider, NVS-persisted). The default is 30 s. Use a shorter value for fast nearby devices; leave it long for distant or slow-to-respond targets. BT Observer uses a fixed 5 s timeout (not user-adjustable).

> **Note:** GATT Walker connects to the target — it is an active, deliberate inspection, not passive. The target device will see an incoming connection. Cancel at any time with the **Cancel Walk** button; the connection is cleanly terminated.

#### BT Observer — How It Works

**BT Observer** automates the scan-then-walk workflow: it runs a configurable-duration active BLE scan (default 10 s, set via Settings → Timing → BT Scan), captures all discovered devices, then attempts a sequential GATT walk on each one (5 s connect timeout). Results are displayed in a live scrollable list and saved as JSON files to `/sdcard/lab/gattwalker/` — identical format to manual GATT Walker.

**Workflow:**

1. Open **BT Observer** from the Bluetooth tile.
2. The device starts an active BLE scan (default 10 s). Discovered devices appear in the list with name/vendor and RSSI.
3. After the scan window closes, the observer walks each device in turn. The list updates live as each walk completes: green checkmark with service/chr counts on success, red on failure.
4. When all devices have been attempted (or the session is stopped), the status bar shows total enumerated count.
5. Tap any row with a successful walk to open the full GATT detail view (same scrollable tree as the single-walk result screen).

**Key differences from manual GATT Walker:**

| | GATT Walker | BT Observer |
|--|-------------|-------------|
| Target | One device (selected) | All devices in one scan session |
| Connect timeout | Configurable (3–30 s, NVS) | Fixed 5 s per device |
| Result screen | Auto-navigates to detail on complete | Tap-to-open per device |
| Scan pass | Continuous (relies on existing scan) | Single scan burst (10–30 s, configurable), no re-scan |

**Per-device JSON files** are saved using the same `/sdcard/lab/gattwalker/` path and enriched format as single walks (manufacturer, service/chr names, props_str, ascii).

---

#### GATT Walker — Extended Probe (CCCD Subscription)

The static walk captures every readable attribute value at the moment of connection. **Extended Probe** goes one layer deeper: after the walk completes, it reconnects to the target and iterates every characteristic with **N (Notify)** or **I (Indicate)** in its property flags, writes `0x0001` (or `0x0002` for Indicate) to the associated CCCD descriptor (`0x2902`), and collects whatever the device pushes back during the listen window. This is the live telemetry layer — heart rate streams, sensor readings, status updates — that a read-only walk never sees.

**How to run it:**

From the GATT result screen, tap the red **Ext. Probe** button at the bottom. The firmware reconnects to the same device, walks every N/I characteristic in sequence with an 8-second listen window each, then re-saves the JSON with the captured notification frames appended inline. A dedicated probe progress screen shows which characteristic is being subscribed in real time.

The probe only writes to CCCD descriptors — it never writes to value handles directly.

**JSON enrichment:**

The subscription data is written back into the same JSON file as a `"probe"` key on each characteristic that was attempted. Characteristics with no N/I flag are unchanged:

```json
{
  "uuid": "0x2A37",
  "name": "Heart Rate Measurement",
  "props_str": "N",
  "read_data": null,
  "ascii": null,
  "probe": {
    "cccd_written": true,
    "notify_count": 4,
    "notify_data": [
      "0048",
      "0049",
      "004B",
      "004A"
    ]
  }
}
```

Each string in `notify_data` is the raw bytes of one notification frame, concatenated as hex without separators (e.g. `"0048"` = flags byte `0x00` + heart rate `72 BPM`). `read_data` and `ascii` are `null` for notify/indicate-only characteristics that cannot be directly read.

This keeps all data from a device in a single enriched file — the initial static snapshot plus the live subscription layer — indexed by the same FNV-32 fingerprint for cross-session correlation.

**Handle gap scan *(stretch goal)*:** After the named service walk, probe attribute handles in the gaps between declared service ranges. Some devices hide characteristics from service discovery but still respond to direct handle reads. Any responding handles are appended to the JSON under `"hidden_handles"`.

---

#### Bluetooth Lookout — How It Works

**Bluetooth Lookout** runs a continuous background BLE scan and alerts you — visually and via NeoPixel LED — any time a watchlisted device is seen nearby. Useful for detecting known surveillance hardware, trackers, or specific devices by MAC address or manufacturer OUI prefix.

**Watchlist:** Devices are stored in `/sdcard/lab/bluetooth/lookout.csv`. The file is auto-created on first use (parent directories created automatically). Add devices three ways:

- **BT Scan & Select → Add to Lookout** — scans for BLE devices, select one, choose "Add to Lookout". The exact MAC is added.
- **OUI Groups** (see below) — adds all devices from a predefined manufacturer OUI block in one tap.
- **Edit List → + OUI** — manually type any 3-byte OUI (formats `AA:BB:CC`, `AABBCC`, or `AA-BB-CC`) and an optional label. Saved as an OUI-prefix entry that matches any device from that manufacturer.

**Matching modes:**
- **Full MAC** — triggers only when that exact 6-byte address is seen. Best for tracking a specific known device.
- **OUI prefix** — triggers when *any* device from that manufacturer's OUI block (`AA:BB:CC:*:*:*`) is seen. Best for detecting a category of hardware (e.g., any Axon body camera in range).

**Alert:** When a match is found the NeoPixel flashes red (3 × 250 ms on/off), the vibrator fires 3 × 1-second pulses (requires vibrator hardware), and a popup appears on screen showing the device name, MAC address, vendor (if OUI database is loaded), and RSSI. A 30-second per-device cooldown prevents repeated alerts for the same device.

**Controls on the Lookout screen:**

| Button | Action |
|--------|--------|
| Start / Stop | Toggle the continuous BLE scan loop |
| Blackout | Dim the screen to black while monitoring continues in the background |
| Edit List | Open the watchlist editor — mark entries for deletion, then Save |
| OUI Groups | Add predefined law-enforcement / tracking hardware groups to the watchlist |

#### OUI Groups

**OUI Groups** (accessible from the Bluetooth Lookout screen) lets you add entire manufacturer OUI blocks to the watchlist in one tap. The firmware will then alert whenever *any* BLE device from that manufacturer is detected.

Pre-loaded groups:

| Group | OUI Prefix(es) | Category |
|-------|---------------|----------|
| **Axon Body Cam** | `00:25:DF` | Law enforcement body-worn cameras |
| **Flock Safety ALPR** | `70:C9:4E`, `3C:91:80`, `D8:F3:BC` | Automated license plate readers |
| **Motorola Solutions** | `4C:CC:34` | Two-way radio / body cameras |
| **Samsung SmartTag** | `64:1B:2F` | Bluetooth trackers |

Tap **+ Add to Watchlist** on any group card. Each OUI is written to `lookout.csv` as an OUI-only entry (visible in the editor as `OUI: AA:BB:CC:*`). Entries added this way are preserved across reboots and editable via **Edit List**.

#### BLE PCAP — How It Works

**BLE PCAP** captures raw BLE advertising packets from the air and writes them to SD card in **Kismet PCAPNG format** — the same format used by Kismet Wireless, Wireshark, and other BLE analysis tools.

The ESP32-C5 uses BLE 5.0 extended advertising (`CONFIG_BT_NIMBLE_EXT_ADV=y`), so the scanner uses `ble_gap_ext_disc()` and handles `BLE_GAP_EVENT_EXT_DISC` events — capturing both legacy (1M PHY) and extended (Coded PHY) advertisements that legacy-only scanners would miss.

**Workflow:**
1. Open **BLE PCAP** from the Bluetooth tile.
2. A new `.pcapng` file is created in `/sdcard/lab/ble/captures/` (e.g. `ble_YYYYMMDD_HHMMSS.pcapng`).
3. The screen shows a live packet counter. All advertising packets detected by the radio are captured, including BLE 5.0 extended advertisements.
4. Tap **Stop** to flush and close the file cleanly.

**File format:** PCAPNG with:
- **Section Header Block (SHB)** — hardware, OS, and application metadata
- **Interface Description Block (IDB)** — link type 256 (`LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR`)
- **Enhanced Packet Block (EPB)** — one per advertising packet

Each EPB includes a **10-byte pseudo-header** preceding the reconstructed BLE LL PDU:

| Byte(s) | Field | Value |
|---------|-------|-------|
| 0 | RF channel | 37 |
| 1 | Signal power (dBm) | RSSI from radio |
| 2 | Noise power (dBm) | −128 (unknown) |
| 3–4 | Access address offenses | 0 |
| 5–8 | Reference access address | `0x8E89BED6` (BLE advertising AA) |
| 9 | Flags | `0x02` (dewhitened PDU) |

The reconstructed PDU contains the advertising PDU header (event type + address type + length), the 6-byte AdvA, and the AdvData payload. This format is directly openable in **Wireshark** with the `BTBREDR` or `BTLE` dissector, and in **Kismet** with its standard BLE plugin.

**Output path:** `/sdcard/lab/ble/captures/ble_YYYYMMDD_HHMMSS.pcapng`

> **Note:** The ESP32-C5's BLE radio captures advertising packets on channels 37/38/39. The pseudo-header records channel 37 for all packets; the actual advertising channel is determined by the PDU type and timing.

#### BlueDuck — BLE HID Keyboard Injector

**BlueDuck** pairs with nearby Bluetooth-capable devices as a BLE HID keyboard and executes DuckyScript payloads — sending keystrokes exactly as a real Bluetooth keyboard would. It is the wireless BLE equivalent of a USB Rubber Ducky.

**How it works:**

1. Open **Bluetooth → BlueDuck**. Select a DuckyScript file from the list (`.duck` files from `/sdcard/lab/ble/blueduck/scripts/`) and a device persona.
2. BlueDuck begins advertising as the chosen persona (e.g. "Wireless Keyboard — Microsoft"). Any nearby device with Bluetooth enabled that is looking for an input device will see it.
3. When a target connects and completes BLE pairing, BlueDuck waits 3 seconds for the OS to complete setup, then executes the script — typing keystrokes, pressing hotkeys, and adding delays as defined.
4. After the script completes, BlueDuck disconnects and immediately re-advertises for the next target.

**Device Personas** — 9 built-in identities:

| Persona | Spoofed as | BLE Appearance |
|---------|------------|----------------|
| Wireless Keyboard | Microsoft Surface Keyboard | HID Keyboard |
| AirPods Pro | Apple A2698 | Headset |
| Fitbit Inspire 3 | Fitbit FB422 | Fitness Tracker |
| Galaxy Buds2 Pro | Samsung SM-R510 | Headset |
| Garmin Fenix 7 | Garmin 010-02540-01 | Watch |
| Apple Watch | Apple A2976 | Watch |
| JBL Clip 4 | JBL JBLCLIP4 | Speaker |
| Logitech MX Keys | Logitech 920-009294 | HID Keyboard |
| Samsung 40" TV | Samsung UN40T5300 | Display |

**Auto-rotate** — cycles through all personas automatically every 5 minutes, randomizing the MAC address per persona to prevent denylisting.

**DuckyScript command support:**

| Command | Description |
|---------|-------------|
| `STRING` | Type literal text |
| `STRINGLN` | Type text + ENTER |
| `DELAY` | Wait N milliseconds |
| `DEFAULT_DELAY` | Insert delay after every subsequent command |
| `REPEAT` | Repeat the previous command N times |
| `GUI` / `CTRL` / `ALT` / `SHIFT` | Modifier keys |
| `ENTER`, `BACKSPACE`, `TAB`, `SPACE`, `ESCAPE`, `DELETE` | Special keys |
| `UP`, `DOWN`, `LEFT`, `RIGHT`, `HOME`, `END`, `PAGEUP`, `PAGEDOWN` | Navigation keys |
| `CAPS_LOCK`, `F1`–`F12` | Function and lock keys |
| `HUMAN_MODE ON/OFF` | Enable variable-speed typing for authenticity |
| `HUMAN_SPEED SLOW/NORMAL/FAST` | Set typing speed when human mode is active |
| `REM` | Comment — ignored |

**Script placement:** Copy `.duck` files to `/sdcard/lab/ble/blueduck/scripts/`. BlueDuck scans this directory on entry and loads all scripts into PSRAM at startup — scripts are cached before BLE is initialized to avoid SD card DMA exhaustion when the BLE stack is running.

**Session logging:** Every connect, payload, and disconnect is appended to a JSONL session file at `/sdcard/lab/ble/blueduck/blueduck_<timestamp>.jsonl` — including script name, LED state (CapsLock/NumLock), GPS coordinates, pairing status, and event type.

**Live stats panel** on the BlueDuck screen:

| Field | Description |
|-------|-------------|
| Connects | Number of devices that have connected |
| Payloads | Scripts successfully executed |
| Disconnects | Connection terminations |
| Persona | Current active persona name |

**Script library:** See [`resources/blueduck_scripts/`](resources/blueduck_scripts/README.md) for the included script collection and full DuckyScript reference.

---

#### WhisperPair — CVE-2025-36911 Fast Pair Bypass

> **Legal notice — authorized use only.** WhisperPair is a security research tool. Only run it against devices you own or have explicit written authorization to test. Unauthorized use may violate the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, or equivalent legislation in your jurisdiction. The authors provide this tool for authorized penetration testing, academic research, and defensive security education only.

**WhisperPair** implements detection and exploitation of **CVE-2025-36911**, a vulnerability in the Google Fast Pair Key-Based Pairing (KBP) protocol disclosed in January 2026 by COSIC/KU Leuven. The flaw allows any BLE device to trigger unsolicited pairing popups on Android phones and other Fast Pair–enabled devices without any user interaction on the target.

##### Background — CVE-2025-36911

Google Fast Pair uses a Key-Based Pairing (KBP) handshake to accelerate the Bluetooth pairing UX. The protocol is advertised via the `0xFE2C` BLE service UUID. The vulnerability: **Fast Pair providers (earbuds, speakers, accessories) accept KBP packets without verifying that the device is in explicit pairing mode.** An attacker can construct a valid-looking KBP packet encrypted with AES-128-ECB using the salt as the key and deliver it over BLE to any nearby Fast Pair device, triggering an Android pairing prompt on the victim's phone.

**Affected devices:** Any Google Fast Pair–enabled accessory (Google Pixel Buds, Samsung Galaxy Buds, Sony WF/WH series, Bose, JBL, and thousands of other accessories using the GFP SDK) running unpatched firmware.

**CVSS:** 6.5 Medium — does not require authentication, exploitable at BLE range (~10 m), results in unsolicited UI interaction on victim devices.

##### How It Works

Fast Pair providers broadcast a `0xFE2C` service UUID in their BLE advertisements. A KBP packet is 16 bytes:

```
Byte 0:   Type = 0x00 (Key-Based Pairing Request)
Byte 1:   Flags = 0x00
Bytes 2–7: Provider MAC address (target device address, big-endian)
Bytes 8–15: Salt (8 random bytes, attacker-chosen)
```

The packet is encrypted with AES-128-ECB where the key is `Salt || 0x00 × 8` (salt padded to 16 bytes). The provider decrypts and processes this packet — triggering the pairing flow — without checking whether it is in discoverable/pairing mode.

##### Access in CYM

WhisperPair is found under **Bluetooth → BT Attacks → WhisperPair**. The authorization disclaimer must be acknowledged before the screen opens.

**Passive detection** is automatic during any BLE scan. Devices advertising the `0xFE2C` Fast Pair service are tagged with `[FP]` in the BT Scan & Select list. GATT Walker also flags these devices with a `⚠ Fast Pair (CVE-2025-36911)` warning when the 0xFE2C service is discovered during a walk.

##### WhisperPair Screen

When opened, WhisperPair **automatically runs a BLE scan** to discover Fast Pair–capable devices. Any device advertising the `0xFE2C` service UUID is shown in the list. Each row shows:

- Device index
- Device name (truncated to 12 chars)
- RSSI
- Partial MAC (last 3 octets)
- `[FP]` badge

**Three action buttons:**

| Button | Mode | Description |
|--------|------|-------------|
| **Probe** | GATT connect | Connects to the selected device, discovers the `0xFE2C` service and the KBP characteristic (`fe2c1234-...`), confirms exploitability, disconnects cleanly |
| **Exploit** | KBP write | Connects, enables CCCD notifications, constructs and writes the crafted AES-128-ECB KBP packet, waits up to 5 s for a response notification |
| **Run All** | Sequential | Runs the selected action (Probe or Exploit) against **every Fast Pair device in the list**, one at a time, cycling through them automatically with a chained callback. Results for each device are logged as they complete. |

**Status and result display** update in real time below the device list. Results are also logged to SD.

##### Usage

1. Open **Bluetooth → BT Attacks → WhisperPair**. Acknowledge the authorization disclaimer.
2. WhisperPair auto-scans for Fast Pair devices. Wait for the scan to populate the list (typically 10 seconds).
3. To target a single device: tap a row to select it, then tap **Probe** or **Exploit**.
4. To target all found devices sequentially: tap **Run All** — the firmware chains through each `[FP]` device automatically.
5. Results are logged to `/sdcard/lab/ble/whisperpair/`.

##### Output Log

Each probe or exploit attempt produces a JSON entry in `/sdcard/lab/ble/whisperpair/`:

```json
{
  "timestamp": "20260518_193200",
  "mac": "AA:BB:CC:DD:EE:FF",
  "name": "Galaxy Buds2 Pro",
  "rssi": -54,
  "mode": "exploit",
  "kbp_chr_found": true,
  "result": "notify_received",
  "notify_hex": "1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D",
  "gps": { "valid": true, "lat": 37.1234567, "lon": -122.4567890 }
}
```

`result` values:

| Value | Meaning |
|-------|---------|
| `notify_received` | Provider responded with a KBP notification — device is vulnerable |
| `no_notify` | KBP packet written but no notification received within 5 s — may be patched |
| `chr_not_found` | 0xFE2C service present but KBP characteristic not found |
| `connect_failed` | BLE connection could not be established |
| `probe_ok` | Probe mode: KBP characteristic confirmed present |

##### Porting to Janos

The `ble_whisperpair.c/h` module is self-contained and portable. Dependencies:

- **NimBLE** — `ble_gap_connect`, `ble_gattc_disc_svc_by_uuid`, `ble_gattc_disc_chrs_by_uuid`, `ble_gattc_write_flat` (standard NimBLE API, available in ESP-IDF and Zephyr)
- **ROM AES** — `ets_aes_enable/setkey_enc/block/disable` from `esp32c5/rom/aes.h` — on other targets, substitute any AES-128-ECB implementation (mbedTLS `mbedtls_aes_crypt_ecb` or a bare-metal block cipher)
- **FreeRTOS** — task + semaphore for async BLE serialization (replaceable with any RTOS primitives or a state machine)
- **SD logging** — optional; the core exploit logic has no SD dependency

To port: copy `ble_whisperpair.c/h`, replace the AES calls with your platform's AES-128-ECB, replace the FreeRTOS semaphores with your RTOS equivalents, and wire `wp_init(mutex)` + `wp_start(target, mode, cb)` into your UI. The GATT client pattern is identical to `gatt_walker.c` and can share the same connection infrastructure.

---

### 3. Wardriving

GPS-enabled WiFi (and optionally BLE) mapping. Requires an **ATGM336H** (or compatible NMEA module) wired to IO4/IO5 — see [GPS Wiring](#gps-wiring--atgm336h).

```
Wardrive
├── Start Wardrive     ← launches the live dashboard
├── Options            ← band, PCAP, and BLE settings
└── Manage Data        ← file list with upload status, delete, and upload
```

#### Starting a Wardrive

Tap **Wardrive** from the main menu, then **Start Wardrive**. The firmware switches the radio to promiscuous mode, begins D-UCB channel hopping, and writes a new WiGLE CSV 1.6 file to `/sdcard/lab/wardrives/`.

**GPS at start-up:**
- If a live GPS fix is already active, wardrive starts immediately.
- If no live fix but a **last-known position is available** (from a prior session saved in NVS, or set manually), wardrive starts immediately using that position with 150 m accuracy — no blocking wait.
- If neither is available (first-ever boot, no GPS module), the firmware waits in a blocking loop until a fix is acquired. Set a manual position via **Settings → GPS Info → Set Position** to skip this wait.

**GPS loss during a session:**
- When signal is lost (entering a building, tunnel, underground garage), wardrive **continues scanning** using the last-known coordinates and reports `150 m` in the `AccuracyMeters` CSV field.
- Scanning only pauses if there is truly no position at all (no live fix, no last-known).
- When signal returns, live coordinates and accuracy resume automatically.

The live dashboard shows:

| Field | Description |
|-------|-------------|
| **D-UCB** (green box) | Current channel being scanned — shows **BLE** during a BLE time-slice pass |
| **WiFi** (cyan box) | Unique WiFi networks logged this session |
| **BLE** (purple box) | BLE devices collected across all BLE passes this session |
| **GPS bar** | Live coordinates (green) or last-known position (amber) with satellite count |

The three stat boxes span the full screen width below the GPS bar. The BLE counter increments in real time during each 8-second BLE pass so you can confirm BLE scanning is working.

**Stop** — ends the session, closes all open files, and returns to the Wardrive menu.

**Go Dark** — available from the title bar power icon on every screen. The display turns off while wardriving continues in the background. Double-press the **BOOT** button to wake the display. The NeoPixel stays cyan while active.

#### Mark Button — GPS Waypoints

A **Mark** button sits in the lower-right of the wardrive dashboard (amber, GPS icon). Use it to tag any point of interest during a drive:

| Gesture | Result |
|---------|--------|
| **Double-tap** (within 450 ms) | Quick waypoint — saves current GPS coordinates immediately with no note |
| **Single tap** | Opens a note dialog — enter a description, then **Save** to record the point with text |

Waypoints are saved in GPX format to `/sdcard/lab/wardrives/wdXXXXXX_marks.gpx` — one file per session, named to match the session's CSV file. The file is closed cleanly when you tap **Stop**.

**Stale position behavior:** If the live GPS fix is lost at the time a mark is saved, the device falls back to the last-known position (same 150 m accuracy rule as wardrive logging). The note dialog coordinate display shows the coordinates in **amber** with a `[stale]` label so you know the position is approximate. The saved `<wpt>` entry includes `[stale pos]` appended to the `<desc>` field so it's visible in any GPX viewer.

**GPX output:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<gpx version="1.1" creator="CYM-NM28C5">
  <wpt lat="37.123456" lon="-122.456789">
    <ele>42.0</ele>
    <time>2026-05-08T12:34:56Z</time>
    <name>Mark 1</name>
  </wpt>
  <wpt lat="37.123789" lon="-122.457012">
    <ele>42.0</ele>
    <time>2026-05-08T12:36:11Z</time>
    <name>Coffee shop on corner</name>
  </wpt>
</gpx>
```

GPX files can be loaded directly into QGIS, Google Earth, or any mapping tool that accepts the standard GPX format.

#### Options Screen

Tap **Options** from the Wardrive menu to configure the current session parameters. All settings are NVS-persisted.

| Option | Values | Default | Description |
|--------|--------|---------|-------------|
| **Band** | Both / 2.4 GHz / 5 GHz | Both | Restricts D-UCB channel hopping to the selected band |
| **Raw PCAP** | On / Off | Off | When enabled, writes a `.pcap` file alongside the CSV for each session |
| **BLE Wardrive** | On / Off | Off | Enables BLE time-sliced scanning (see below) |

#### BLE Time-Sliced Wardriving

When **BLE Wardrive** is enabled, the firmware periodically pauses WiFi scanning for a short BLE pass:

1. Every **30 seconds** of WiFi scanning, the promiscuous sniffer is paused.
2. The radio switches to BLE mode and runs an **8-second active BLE scan**.
3. All discovered BLE devices (deduplicated by MAC) are recorded with the current GPS fix.
4. The radio switches back to WiFi, D-UCB is rebuilt, and scanning resumes.

During the BLE pass, the D-UCB box shows **BLE** and the purple **BLE** counter increments as devices are discovered — confirming the scan is active even though the WiFi table is idle.

**BLE rows in the CSV** follow the same WiGLE 1.6 format as WiFi rows, with `Type=BLE`, `Channel=37`, `Frequency=2402`, and `[BLE]` as the auth mode:

```
AA:BB:CC:DD:EE:FF,"My Speaker",[BLE],2026-05-08 12:34:56,37,2402,-72,37.123456,-122.456789,42.0,0.00,,,BLE
```

This produces a single CSV file containing both WiFi and BLE sightings, uploadable directly to WiGLE which supports both types in the same file.

#### D-UCB Band Filtering

The D-UCB channel scheduler respects the **Band** option:

| Band setting | Channels hopped |
|---|---|
| **Both** | All 2.4 GHz channels (1–14) + 5 GHz channels (36, 40, 44, 48, 52, 56, 60, 64, 100–165) |
| **2.4 GHz only** | Channels 1–14 only |
| **5 GHz only** | 5 GHz channels only |

#### Manage Data Screen

**Manage Data** lists all wardrive CSV files in `/sdcard/lab/wardrives/`. Each row shows the filename and upload status read from `upload_log.csv`:

| Row color | Meaning |
|-----------|---------|
| **Green** | Uploaded successfully to all selected services |
| **Amber** | Partially uploaded (e.g. WiGLE OK, WDG Wars failed) |
| **White** | Not yet uploaded |

Each row has an **X** button to delete that file from the SD card. Tap **Upload** to proceed to the upload screen (which returns to Manage Data when done, so you can check updated statuses).

The upload log at `/sdcard/lab/wardrives/upload_log.csv` records one row per file per service:

```
wd000001.csv,WIGLE,OK
wd000001.csv,WDGWARS,OK
wd000002.csv,WIGLE,FAIL
```

#### Wardrive File Format

WiGLE CSV 1.6 — accepted directly by WiGLE and WDG Wars without conversion.

```
WigleWifi-1.6,appRelease=v1.0.4,model=NM-CYD-C5,...
MAC,SSID,AuthMode,FirstSeen,Channel,Frequency,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,RCOIs,MfgrId,Type
AA:BB:CC:DD:EE:FF,"MyNetwork",[WPA2_PSK],2026-05-08 12:34:56,6,2437,-65,37.123456,-122.456789,0.00,8.40,,,WIFI
11:22:33:44:55:66,"BLE Device",[BLE],2026-05-08 12:35:02,37,2402,-72,37.123456,-122.456789,0.00,150.00,,,BLE
```

`AccuracyMeters` is populated per-network from the GPS reading at discovery time. A live fix with HDOP 2.1 produces accuracy = `2.1 × 4 = 8.4 m`. A network logged from last-known fallback coordinates produces `150.00 m`. WiGLE uses this field to place the network on its map with an appropriate uncertainty radius.

#### Wardriving Workflow — Field Use

**Quick drive:**
1. Insert GPS module (ATGM336H) — fix typically arrives in 30–60 s with clear sky.
   - If last-known position is stored (NVS), wardrive starts immediately without waiting.
2. Wardrive → Start Wardrive. The NeoPixel turns cyan.
3. Drive. The AP count increments as new networks are logged. If you enter a building and GPS signal is lost, scanning continues using the last-known position (150 m accuracy in the CSV).
4. Tap **Stop** when done. Files are closed and ready to upload.
5. Wardrive → Manage Data → Upload.

**Indoor / no-GPS use:**
1. Settings → GPS Info → **Set Position** — enter your approximate location (e.g. city centre coordinates).
2. Tap **Save to NVS**. The position is stored immediately.
3. Start Wardrive — the device uses the entered position for all log entries.
4. Networks are logged with `AccuracyMeters = 150` indicating approximate coordinates.

**With BLE:**
1. Options → BLE Wardrive → On. Options → Band → Both.
2. Start Wardrive. Every 30 seconds the D-UCB box shows **BLE** for an 8-second pass; the purple BLE counter ticks up with each device found.
3. Both WiFi and BLE sightings appear in the same CSV.

**Marking a point of interest:**
- Double-tap **Mark** to silently drop a quick waypoint.
- Single-tap **Mark**, type a note (e.g. "camera on pole"), tap **Save**.
- GPX file is written alongside the CSV — load both into QGIS for a full picture.

**Upload after drive:**
1. Wardrive → Manage Data → check row colors.
2. Tap **Upload** → select WiGLE / WDG Wars / Both → API keys are pre-filled if you set them by file (recommended — see below) or from a prior on-device entry → Upload All.
3. Per-file status updates live. Green = accepted; amber = duplicate; red = failed.
4. Return to Manage Data — uploaded rows turn green.

> **Tip — avoid typing API keys on the device:** Put your keys in plain text files on the SD card before your first upload. The device loads them at boot and pre-fills the upload screen automatically — no on-screen keyboard needed.
> - **WiGLE:** create `/sdcard/lab/wigle.txt` — paste your WiGLE *"Encoded for use"* token on line 1 (get it from wigle.net → Account → API Token).
> - **WDG Wars:** create `/sdcard/lab/wdgwars.txt` — paste your WDG Wars API key on line 1 (from your wdgwars.pl profile page).
>
> Copy the files to the SD card from a PC, insert the card, and reboot. The upload screen will be pre-filled on every subsequent use.

### 4. Settings

```
Settings
├── Compromised Data    (WiFi credential monitor)
├── Timing              (WiFi scan dwell + BT scan duration + GATT connect timeout — combined popup)
│   ├── WiFi Scan/Ch    (min/max dwell time per channel — 50–1000 ms sliders)
│   ├── BT Scan         (BLE initial scan duration — 10–30 s slider, default 10 s)
│   └── GATT Timeout    (BLE connect timeout — 3–30 s slider)
├── Download Mode       (reboot into bootloader)
├── Screen              (screen timeout + brightness — combined popup)
│   ├── Timeout         (inactivity timer before dimming)
│   └── Brightness      (software brightness overlay 10–100%)
├── SD Card             (provision / file tree / free space)
├── GPS Info            (live fix status)
├── Hardware Options    ← hardware addon configuration
│   ├── Power Mode      (Normal / Max TX power)
│   └── NM-RF-HAT       (Enable / Disable the RF expansion board)
└── Data Transfer       (file server sub-menu)
    ├── AP File Server  (start TheLab AP, serve /sdcard/ on 192.168.4.1)
    ├── WiFi Client     (join a saved network, serve /sdcard/ on DHCP IP)
    └── Wardrive Upload (WiGLE + WDG Wars HTTPS upload)
```

All settings are persisted via **NVS** (Non-Volatile Storage) across reboots. The settings menu fits on a single screen (8 tiles, 3-column grid, no scrolling).

| Setting | Description |
|---------|-------------|
| **Timing** | Combined timing popup — WiFi scan dwell time sliders, BT scan duration slider (10–30 s), and GATT connect timeout slider |
| **Screen** | Combined screen popup — inactivity timeout dropdown and brightness overlay slider |
| **SD Card** | Validate/provision (creates `/sdcard/lab/` structure, shows completion status); browse file tree; check free space |
| **GPS Info** | Live GPS fix status — latitude, longitude, altitude, satellite count, UTC time, and UART reference. When no live fix, last-known coordinates are shown in amber with `*` suffix and `Accuracy: 150 m (stale)`. **Set Position** button opens manual coordinate editor (see below). Refreshes every second. |
| **Hardware Options** | Sub-menu for hardware addon configuration — **Power Mode** (Normal / Max TX power) and **NM-RF-HAT** enable/disable toggle. NVS-persisted. |
| **Data Transfer** | File server sub-menu — AP mode or WiFi client mode (see below) |
| **Vibrator Test** | Test tile for the vibrator motor — drives GPIO 26 (SPEAK_IN → SC8002B amp) at 333 Hz via LEDC PWM. Popup exposes ON / OFF buttons and a **Strength slider** (10–100%, where 100% = 50% duty cycle, the half-wave rectified maximum). Strength persists within the session. API: `vibrator_on()`, `vibrator_off()`, `vibrator_pulse(ms)`, `vibrator_burst(count, on_ms, gap_ms)`. Requires the 1N5819 + 1N4148 diode circuit on the SPEAK header — see Vibrator Motor Circuit section. |

#### GPS Info & Fallback Position

Accessible via **Settings → GPS Info**. Refreshes every second.

**Live fix (GPS module connected and locked):**

| Field | Description |
|-------|-------------|
| Fix | `YES` in green — active GNSS lock |
| UTC | Time string parsed from NMEA RMC sentence |
| Satellites | Count of tracked SVs from GGA |
| Lat / Lon / Alt | Live coordinates in white |
| Accuracy | Live HDOP × 4 in metres |

**No live fix (signal lost or module not connected):**

| Field | Display |
|-------|---------|
| Fix | `NO  (last known ↓)` in amber (or `NO` in orange if no fallback at all) |
| Lat / Lon / Alt | Last-known coordinates in amber followed by `*` |
| Accuracy | `150 m (stale)` in amber |

The `*`-suffix values are what the device is actually using as its GPS fallback for wardrive logging, GATT Walker geotags, and GPS waypoints.

**Set Position button (amber):**

Opens a modal overlay to manually enter fallback coordinates:

```
┌─ Set Fallback Position ──────────────────┐
│  Stored in NVS, used when GPS unavailable │
├───────────────────────────────────────────┤
│  Latitude (-90 to 90):   [ 37.421900    ] │
│  Longitude (-180 to 180):[-122.084058   ] │
│  Altitude (m, optional): [ 30.0         ] │
├───────────────────────────────────────────┤
│       [ ✓ Save to NVS ]  [ ✕ Cancel ]    │
└───────────────────────────────────────────┘
        [ on-screen keyboard ]
```

- Text areas are **pre-populated** with the best available position: live GPS if locked, last-known from NVS if not
- **Accepted characters:** `-0123456789.` only — the keyboard filters invalid input
- **Validation:** latitude must be in `[-90, 90]`, longitude in `[-180, 180]`; the null island `(0, 0)` is rejected. The lat field border flashes red on invalid input.
- **On Save:** `g_gps_last_known` is updated immediately in RAM **and** written to NVS unconditionally (bypasses the 5-minute auto-save throttle — this is a deliberate user action). All subsequent wardrive scans, GATT walks, and mark waypoints use the new position.
- **On Cancel:** no changes are written

**NVS keys written by GPS (namespace `settings`):**

| Key | Type | Description |
|-----|------|-------------|
| `gps_lat_i` | i32 | Latitude × 10⁶ (integer micro-degrees) |
| `gps_lon_i` | i32 | Longitude × 10⁶ |
| `gps_alt_i` | i32 | Altitude × 10 (integer deci-metres) |

Integer storage avoids NVS blob overhead and gives ~0.1 m altitude resolution and ~0.11 m position resolution — well within the 150 m stale accuracy the system reports.

**Write frequency and flash lifetime:**

| Write path | Frequency | Estimated NVS life |
|---|---|---|
| Auto (from GPS fix) | ≤ once per 5 minutes | ~5.7 years continuous use |
| Manual (Set Position) | On user tap only | Decades |

The NVS partition is 24 KB (≈6 flash pages × 100 K P/E cycles each). At one auto-write per 5 minutes, the effective write budget of ~600 K commits lasts roughly 5–6 years of daily wardriving. SD card writes (if used for logging) are handled by the SD FTL across gigabytes of storage — the per-minute rate would be trivial.

---

#### TX Power Mode

Accessible via **Settings → Power Mode**. Defaults to **Normal** on first boot.

| Mode | WiFi | BLE |
|------|------|-----|
| **Normal** | Default IDF TX power, modem-sleep enabled (`WIFI_PS_MIN_MODEM`) | Default controller TX power |
| **Max Power** | TX cap set to 82 (~20.5 dBm nominal), modem-sleep disabled (`WIFI_PS_NONE`) | All BLE power types set to P9 (+9 dBm) |

Switching modes takes effect immediately on the active radio and is re-applied automatically every time WiFi or BLE is started — including on attack start/stop and radio mode switches.

> **Note:** Actual radiated power (EIRP) is still bounded by the NM-CYD-C5's PCB antenna, PHY calibration data, and the country/regulatory settings loaded at boot. Max Power increases effective range but does not bypass regulatory limits enforced by the PHY layer.

#### Timing Settings

Accessible via **Settings → Timing**. A single popup contains three sections:

**WiFi Scan / Channel** — min and max dwell time sliders (50–1000 ms) control how long the WiFi scanner dwells on each channel during active scans. Both values are NVS-persisted.

**BT Scan Duration** — a slider (10–30 s, default 10 s, NVS key `bt_scan_dur`) sets how long the initial BLE scan runs when opening BT Scan & Select, BT Observer, or AirTag Scan. Longer values find more devices, especially in noisy or busy RF environments; shorter values make scans feel snappier.

**GATT Connect Timeout** — a single slider sets the BLE connection timeout used by GATT Walker. BT Observer uses a separate fixed 5 s timeout and is not affected by this setting.

| Slider position | Timeout | Best for |
|-----------------|---------|----------|
| Far left (3 s) | 3 000 ms | Fast, nearby devices that respond immediately |
| Default / far right (30 s) | 30 000 ms | Distant, intermittent, or slow-to-respond targets |

The value is saved to NVS key `gatt_tmo` and applied on every subsequent GATT Walker walk without needing a reboot.

> **Error descriptions:** When a connection fails, GATT Walker now shows a human-readable reason (e.g. *"No response — needs pairing or asleep"* for BLE timeout code 13, *"Radio busy — stop scan first"* for code 15) instead of a raw numeric code.

#### Data Transfer

Accessible via **Settings → Data Transfer**.

```
Settings → Data Transfer
├── AP File Server      ← device creates its own WiFi network
├── WiFi Client         ← device joins your existing network
└── Wardrive Upload     ← upload CSV logs to WiGLE and/or WDG Wars
```

**AP File Server**

The device starts a WPA2-secured access point and immediately serves `/sdcard/` on its default gateway address.

| Detail | Value |
|--------|-------|
| **SSID** | `TheLab` |
| **Password** | `Do not touch!` |
| **Server URL** | `http://192.168.4.1` |
| **Channel** | 6 |

Connect your phone or laptop to the `TheLab` network, then open `http://192.168.4.1` in a browser. You get a directory listing of the SD card with full file management capability. Tap **Stop** on the device to shut the server down and restore normal operation.

**File server capabilities:**

| Action | How |
|--------|-----|
| Browse | Click any folder to navigate in |
| Download | Click any file to download it |
| Upload | Use the upload form at the bottom of each directory listing |
| Create directory | Enter a name in the **New folder** field and click Create |
| Delete file | Click the **✕** button next to any file |
| Delete directory | Click the amber **✕** button next to any folder — requires double confirmation (recursive delete, irreversible) |

All client IP addresses are logged to serial output so you can see which device is browsing or uploading.

**WiFi Client Server**

The device joins an existing WiFi network as a station (STA) and serves files on the IP address assigned by your router's DHCP server. The IP is displayed prominently on screen as soon as a lease is obtained.

1. Tap **WiFi Client** — the screen shows pre-filled SSID and password fields (populated from the last saved connection).
2. Edit SSID / password if needed — tap either field to bring up the on-screen keyboard. Tap the **eye icon** on the password field to reveal/mask the password.
3. Tap **Connect** — the device connects to your network. Credentials are saved to NVS so next time the fields are pre-filled.
4. Once connected the screen shows the assigned IP: `IP: 192.168.x.x => http://192.168.x.x`
5. Open that URL on any device on the same network to browse, upload, create folders, or delete files.
6. Tap **Back** to disconnect and stop the server.

**First-connect reliability:** The firmware pins the regulatory domain to International (channels 1–13, MANUAL policy) immediately before and after each connect attempt. An auto-retry fires once at 1.5–5 s if the initial association is dropped by a country-IE-induced regdomain update — this is transparent and produces no visible delay.

> **Note:** The WiFi radio must be available (not in BLE mode) to use the file server. If BLE is active, the firmware switches radio modes automatically.

> **International channels:** The regulatory domain is set to `01` (ITU world region) with `nchan=13`, covering channels 1–11 (US) and 1–13 (EU/Poland/Australia) without restriction. All access points on channels 12–13 are accessible without any configuration change.

**Wardrive Upload**

Uploads all wardrive CSV files from `/sdcard/lab/wardrives/` to [WiGLE](https://wigle.net) and/or [WDG Wars](https://wdgwars.pl) over HTTPS. The device connects to WiFi automatically using your saved credentials (set via **WiFi Client**) before uploading.

**API key setup — two options (use either or both):**

| Option | How |
|--------|-----|
| **SD card file** | Create `/sdcard/lab/wigle.txt` and/or `/sdcard/lab/wdgwars.txt` — paste the key on the first line. Loaded at boot. |
| **On-device entry** | Tap **Wardrive Upload**, type the key into the text area, tap **Upload All**. Key is saved to NVS and persists across reboots. |

**WiGLE API token:** Go to [wigle.net](https://wigle.net) → Account → API Token → copy the **"Encoded for use"** value (already base64 encoded — looks like `dXNlcm5h...`).

**WDG Wars API key:** Obtain from your [wdgwars.pl](https://wdgwars.pl) profile page.

**Upload flow:**
1. Select service: **WiGLE**, **WDG Wars**, or **Both**
2. API key text areas are automatically pre-filled if `/sdcard/lab/wigle.txt` or `/sdcard/lab/wdgwars.txt` exist, or from a key saved on a previous visit. If neither source is present, type the key directly into the text area — it will be saved to NVS for next time.
3. Tap **Upload All** — the device connects to WiFi, walks every `.csv` file in `/sdcard/lab/wardrives/`, and uploads each one in sequence
4. The progress list shows per-file status: **OK** (green), **dup** (amber — already submitted), **FAIL** (red)
5. Each result is written to `/sdcard/lab/wardrives/upload_log.csv`; the **Manage Data** screen reads this file to color-code rows

> **Tip:** Use **Wardrive → Manage Data → Upload** instead of **Settings → Data Transfer → Wardrive Upload** when you want to see file status before and after uploading. Both paths use the same upload screen and log.

### 6. Zigbee Scout

**Zigbee Scout** uses the ESP32-C5's built-in IEEE 802.15.4 radio to passively scan and wardrive Zigbee networks — no external hardware required. It operates independently of the NM-RF-HAT.

```
Bluetooth → Zigbee Scout
├── Start Scan     -- passive receive on all 16 channels, rotates every 800 ms
├── PAN List       -- tap any PAN to lock onto it (RSSI locator mode)
├── Stop
└── (auto-logs to /sdcard/lab/zigbee/)
```

**What it captures:**

| Field | Description |
|-------|-------------|
| PAN ID | 16-bit Zigbee PAN identifier (e.g. `0x1A2B`) |
| Channel | IEEE 802.15.4 channel (11–26, 2405–2480 MHz) |
| RSSI | Signal strength in dBm |
| Coordinator | Extended address of the PAN coordinator (if seen in a beacon) |
| Node count | Number of unique device addresses seen in the PAN |
| Frame types | Beacon, Data, ACK, Command frame counts |
| NWK/APS metadata | Network/application layer frame type, destination address |
| GPS | Coordinates at time of reception |

**PAN List screen:**

After a scan, tap any row in the PAN List to open the PAN detail view:

- Full 64-bit extended coordinator address (if seen)
- Device short address list (16-bit node IDs seen transmitting)
- Frame type breakdown (Beacon / Data / ACK / Command)
- RSSI locator: locks the channel and shows live RSSI for that PAN — walk toward the coordinator using the RSSI reading

**RSSI Locator:**

Tap **Locate** on any PAN entry. Zigbee Scout locks the 802.15.4 radio to that PAN's channel and displays a live RSSI reading updated every 500 ms. Use it to find the physical location of a Zigbee hub or coordinator. Vibrator strength scales with RSSI when the vibrator motor is installed.

**Output files:**

```
/sdcard/lab/zigbee/
├── zgwd_YYYYMMDD_HHMMSS.csv       -- wardrive CSV (one row per PAN sighting)
└── zgwd_YYYYMMDD_HHMMSS.pcap      -- PCAP capture (Wireshark DLT 195 = IEEE 802.15.4)
```

**CSV columns:**

| Column | Description |
|--------|-------------|
| `timestamp` | UTC from GPS-synced clock |
| `pan_id` | 16-bit PAN ID in hex |
| `channel` | 802.15.4 channel number (11–26) |
| `rssi` | dBm at time of sighting |
| `coordinator` | Extended coordinator address or `unknown` |
| `lat`, `lon`, `alt` | GPS coordinates (last-known fallback if no fix) |
| `gps_live` | `1` if GPS was live; `0` if last-known |

The PCAP file uses **DLT 195** (`LINKTYPE_IEEE802_15_4_WITHFCS`) and can be opened directly in Wireshark with the IEEE 802.15.4 dissector. OTA frame bytes including the 2-byte FCS are preserved.

**IEEE 802.15.4 channels and Zigbee:**

| Channel | Frequency | Notes |
|---------|-----------|-------|
| 11 | 2405 MHz | First Zigbee channel |
| 15 | 2425 MHz | Common default for many Zigbee hubs |
| 20 | 2450 MHz | |
| 25 | 2475 MHz | |
| 26 | 2480 MHz | Last Zigbee channel; used by some Thread networks |

The Scout rotates through all 16 channels (11–26) with an 800 ms dwell per channel, completing a full sweep in ~13 seconds. Each PAN seen on any channel is de-duplicated by PAN ID in the live list.

> **Note:** Zigbee Scout uses the ESP32-C5's hardware 802.15.4 PHY (`esp_ieee802154_*` API). WiFi and BLE are disabled while Zigbee Scout is running. The radio switches back automatically when you exit the screen.

---

### 7. NM-RF-HAT

The **NM-RF-HAT** is an optional RF expansion board that connects to the NM-CYD-C5 via its FPC2 header. It provides five RF modules gated by a 6-position DIP switch — only one module is powered at a time (hardware exclusion via P-channel MOSFETs).

#### Enabling the NM-RF-HAT

The RF-HAT menu tiles are hidden by default and must be enabled once after connecting the board:

1. Connect the NM-RF-HAT to the NM-CYD-C5 via the FPC2 ribbon connector.
2. Set the DIP switch for the module you want to use (only one ON at a time).
3. On the device, go to **Settings → Hardware Options → NM-RF-HAT**.
4. Tap **Enable**.
5. A confirmation popup appears — tap **OK**.
6. The RF-HAT tiles (CC1101, nRF24, IR, RF433, PN532 NFC) now appear on the main menu.

The setting is saved to NVS and survives reboots — you only need to enable it once. To hide the tiles again, return to **Settings → Hardware Options → NM-RF-HAT** and tap **Disable**.

#### Modules

| DIP | Module | Frequency | GPIO9 (IO27) | GPIO8 (IO22) |
|-----|--------|-----------|-------------|-------------|
| 1 | CC1101 | Sub-1 GHz (300–928 MHz) | SPI CSN | GDO0 |
| 2 | nRF24L01 | 2.4 GHz | SPI CSN | CE |
| 3 | PN532 | 13.56 MHz NFC/RFID | I2C SDA | I2C SCL |
| 4 | IR Infrared | 36–40 kHz carrier | TX (IR LED) | RX (demod) |
| 5 | RF433 OOK/ASK | 433.92 MHz | TX | RX |
| 6 | Battery switch | — | — | — |

#### Infrared (DIP 4)

IR capture and replay using the ESP32-C5's RMT peripheral. Files use the **Flipper Zero `.ir` format** — directly portable between this device and a Flipper Zero (mount point differs; content is identical).

```
NM-RF-HAT IR
├── Capture       -- listen for any IR signal (5 s timeout), then save to a remote file
├── Replay        -- browse remote files -> signals -> transmit
│   ├── <Remote>.ir
│   │   ├── Signal 1
│   │   ├── Signal 2
│   │   └── ...
│   └── ...
├── Universal     -- multi-button remote: Power Search + Power/VOL/CH/Input/Mute buttons
├── TV-B-Gone     -- transmit built-in power-off sequence for 16 common TV brands (3x repeats)
└── IR Jammer     -- continuous 38 kHz carrier via LEDC hardware PWM
```

**SD card path:** `/sdcard/lab/infrared/`

---

##### .ir File Format

Each `.ir` file represents one remote (e.g. `Samsung_TV.ir`) and can contain any number of named signals separated by `#` lines:

```
Filetype: IR signals file
Version: 1
#
name: Power
type: raw
frequency: 38000
duty_cycle: 0.33
data: 9000 4500 560 1680 560 560 560 1680 560 560 ...
#
name: Vol_up
type: raw
frequency: 38000
duty_cycle: 0.33
data: 9000 4500 560 560 560 1680 560 560 ...
```

Signal values are alternating mark/space pulse durations in **microseconds**. `frequency` is the carrier in Hz (typically 38000). `duty_cycle` is typically 0.33 (ignored on raw TX — RMT uses fixed 33% duty).

---

##### Universal Remote

The Universal Remote screen provides six one-tap buttons for the most common TV functions — **Power, VOL-, VOL+, CH-, CH+, Input, Mute** — using signals loaded from a brand `.ir` file on the SD card. The active brand is saved to NVS and restored automatically every time you open the screen.

**Power Search** cycles through every `.ir` file in `/sdcard/lab/infrared/`, sends the `Power` signal from each brand, and asks "Did it work?" — tap **Yes** to lock in that brand, **Skip** to try the next, **Stop** to exit the search. The confirmed brand is saved immediately to NVS.

**Signal name convention — Universal Remote requires these exact names:**

| Button | Signal name in .ir file |
|--------|------------------------|
| Power  | `Power`                |
| VOL-   | `Vol_dn`               |
| VOL+   | `Vol_up`               |
| CH-    | `Ch_prev`              |
| CH+    | `Ch_next`              |
| Input  | `Input`                |
| Mute   | `Mute`                 |

Only `Power` is required for the Power Search to work. The other signals are optional — a "Not found" status is shown if a button's signal is missing from the file.

**The Flipper-IRDB already uses this naming convention.** Files downloaded from that database work directly with Universal Remote without any editing.

---

##### TV-B-Gone

Built-in power-off sequence covering 16 common TV brands. Each code is sent 3 times with 65 ms between repeats and 250 ms between brands. DIP 4 must be ON. No SD card files required.

---

##### Getting .ir Files onto the SD Card

**Compatible IR file sources:**
- Flipper-IRDB (most comprehensive, correct signal names): https://github.com/logickworkshop/Flipper-IRDB
- Flipper Zero built-in assets: https://github.com/flipperdevices/flipperzero-firmware/tree/dev/assets/infrared/assets
- IRDB community database: https://github.com/probonopd/irdb

Copy any `.ir` file directly into `/sdcard/lab/infrared/` — no conversion needed. Files appear in the **Replay** remote list immediately, and the Power Search scans them automatically.

> **Tip:** The Flipper-IRDB `TV` folder contains brand files with `Power`, `Vol_up`, `Vol_dn`, `Ch_next`, `Ch_prev`, `Mute`, and `Input` already named correctly for Universal Remote.

#### RF433 OOK/ASK (DIP 5)

433.92 MHz OOK/ASK capture and replay. Files use the **Flipper Zero `.sub` (SubGHz) format** — directly portable to/from Flipper Zero.

**Features:**
- **Capture:** records OOK signal transitions via GPIO9 (R4A_433 RX output); saves as Flipper `.sub`.
- **Replay:** plays back `.sub` files via the T2-433M OOK transmitter.
- **Jammer:** T2-433M OOK transmitter toggled at 1 kHz via esp_timer (500 µs half-period), creating OOK AM sidebands around 433.92 MHz — visible modulation on a spectrum analyzer, more effective at disrupting OOK demodulators than a pure CW carrier.
- **LBK Test:** loopback self-test verifying GPIO8 TX and GPIO9 RX path.
- **Fox Hunt:** proximity tracker at fixed 433.92 MHz. The R4A_433 module demodulates incoming OOK signals to a digital output — edge transitions per second are counted as a signal-activity proxy. Higher activity = stronger 433 MHz signal nearby. Haptic feedback: vibrator fires at 100% strength for reliable motor spin-up; pulse rate scales from ~1 pulse/1.5 s at low activity to 5 pulses/s at peak. Note: no true RSSI — this is activity-based only.
- **OOK Scan:** passive EV1527 protocol decoder using the R4A_433 superheterodyne receiver. Decodes 315/433 MHz OOK alarm sensors: 24-bit address, 4-bit channel/data, trigger count, last-seen time. Auto-aggregates repeat transmissions from the same sensor. Useful when CC1101 sensitivity isn't sufficient for distant sensors.

**SD card path:** `/sdcard/lab/rf433/`

**Compatible .sub file sources:**
- Flipper Zero Sub-GHz library: https://github.com/flipperdevices/flipperzero-firmware/tree/dev/assets/subghz
- UberGuidoZ collection: https://github.com/UberGuidoZ/Flipper/tree/main/Sub-GHz

#### PN532 NFC/RFID (DIP 3)

13.56 MHz NFC/RFID card scanning, saving, exporting, importing, and emulation via I2C (GPIO8=SCL, GPIO9=SDA). Supports ISO14443A cards: NTAG213/215/216, MIFARE Ultralight, MIFARE Classic.

**SD card paths:**
- `/sdcard/lab/rfid/hf/` -- saved card JSON files
- `/sdcard/lab/rfid/import/` -- drop Flipper Zero `.nfc` files here to import
- `/sdcard/lab/rfid/export/` -- Flipper Zero `.nfc` exports written here

**Screens:**

| Screen | Function |
|--------|----------|
| **Scan & Read** | Hold a card near the antenna — detected in under a second. Panel border turns green, card type and UID appear. **Auto-reads after 1 second** of stable detection (no button tap needed). If NDEF content is present, the URL or text is decoded and shown on screen. Read button turns green when card is ready; tap it to re-read manually. |
| **Clone / Write** | Read a source card on Scan & Read, then open Clone/Write. The source card's data is shown. Hold a **blank NTAG213/215/216** card on the antenna and tap **Clone to Blank Card** to write pages 4-44. MIFARE Classic cards are rejected with a clear error — they cannot receive NTAG data. Use a Magic/CUID blank card to clone all pages including UID. |
| **Card Emulate** | Select a saved card; PN532 enters `TgInitAsTarget` mode presenting the card's UID to any nearby reader. Responds to NTAG READ (0x30) commands using saved page data. MIFARE Classic CRYPTO1 auth is not supported in emulation. |
| **Key Test** | Present a MIFARE Classic 1K/4K card; runs default key dictionary against each sector; displays unlocked block data. For authorized testing on own cards only. |
| **Saved Cards** | Scrollable list of saved JSON cards. Drop Flipper `.nfc` files in `/sdcard/lab/rfid/import/` to import directly. |
| **HW Test** | PN532 I2C probe — reads IC identifier, firmware version, support bitmask. Full I2C bus scan on failure. |

**Scan & Read workflow:**
1. Open **Scan & Read**. Hold any NFC card near the antenna (nearly touching).
2. Panel border turns green within ~1 second. UID, ATQA, SAK, and card type appear.
3. After 1 further second of stable detection, **Read All fires automatically** — no tap required.
4. If the card contains an NDEF message (URL, text), it is decoded and shown in blue on the card panel.
5. Type label updates after read — e.g. if initially shown as "MIFARE Ultralight", may upgrade to "NTAG213 (45 pages)" once all pages are confirmed.
6. Tap **Save** to store as JSON, or **Export .nfc** for Flipper Zero format.

**NTAG type identification — how it works:**
The PN532 on the NM-RF-HAT runs firmware v1.6 which cannot forward the NXP GET_VERSION command (0x60) to the card. NTAG213, NTAG215, NTAG216, and MIFARE Ultralight all have identical ATQA and SAK values, so they cannot be distinguished from the initial scan alone. The firmware handles this automatically:
1. Initial scan classifies all SAK=0x00 cards as "MIFARE Ultralight" (safe 16-page default).
2. After reading 16 pages, the firmware probes page 16. A genuine 16-page Ultralight returns NAK (page doesn't exist). An NTAG213/215/216 returns data.
3. If page 16 is readable, the card is upgraded to NTAG213 and all remaining pages (up to 45) are read automatically.
4. The type label and page count update on screen after the read completes.

**Clone/Write compatibility:**
Only blank NTAG213, NTAG215, NTAG216, MIFARE Ultralight, and Magic/CUID cards can receive a clone. **MIFARE Classic cards are incompatible** — they use Crypto-1 sector authentication and do not accept NTAG WRITE commands. Presenting a Classic during Clone shows a red error: "Wrong card type! Need blank NTAG or Ultralight."

**Serial log messages — normal vs actionable:**

| Log message | Meaning | Action needed |
|-------------|---------|---------------|
| `scan: GET_VERSION failed — keeping heuristic type MIFARE Ultralight` | PN532 fw1.6 cannot forward GET_VERSION (0x60). Card identified by ATQA+SAK heuristic; NTAG auto-upgrade via page-16 probe handles the rest. | None — expected behavior |
| `page16 readable — upgrading Ultralight → NTAG213` | Card confirmed as NTAG213; reading all 45 pages | None — auto-upgrade working |
| `NDEF decoded: https://...` | URL extracted from card's NDEF message | None — URL shown on screen |
| `No NDEF URL/text found in 16 pages` | Card read successfully but contains no NDEF message (blank card or non-NDEF format) | None — card may be blank |
| `I2C write failed: ESP_ERR_INVALID_RESPONSE` | PN532 locked up after extended idle scanning. Recovery attempted automatically. | None if followed by recovery success |

**Flipper Zero .nfc compatibility:** export and import support NTAG213, NTAG215, NTAG216 — `NTAG/Ultralight type:` line preserves the exact type on re-import.

> **Note:** The PN532 on the NM-RF-HAT has shorter read range than a dedicated PN532 breakout board. Hold cards nearly touching the antenna. This is a hardware limitation of the RF-HAT PCB antenna geometry, not a firmware issue. The PN532 firmware is v1.6 and is not field-upgradeable — NXP does not distribute firmware update tools publicly.

#### CC1101 Sub-GHz (DIP 1)

Sub-1 GHz (300-928 MHz) OOK/ASK capture, replay, spectrum scan, and jamming. Uses a 2-page paged tile menu (prev/next navigation with page indicator).

**SD card path:** `/sdcard/lab/radio/` -- Flipper Zero `.sub` format

**Features:**
- **HW Test:** reads CC1101 PARTNUM (0x00) and VERSION (0x14) registers; shows MARCSTATE to confirm chip identity and SPI link. Also exposes **crystal calibration** (see below).
- **Freq Scan:** canvas-based spectrum view; RSSI bar per channel across the full 300-928 MHz tunable range; carrier detect; Start/Stop control.
- **RAW Capture:** 10-second OOK/ASK signal capture window; Save/Discard prompt after capture; saves to `/sdcard/lab/radio/` as Flipper Zero `.sub` format.
- **RAW Replay:** lists `.sub` files from SD; play at 1x/3x/5x speed.
- **Saved Files:** list with Play and Delete per file.
- **Jammer:** legal disclaimer screen required before activation. **Band-selectable** (315 / 433 Wide / 433 Narrow / 868 / 915 MHz). Uses **2-FSK at ±381 kHz deviation** with 250 kbps random PRBS → ~1 MHz noise bandwidth per hop. 12-step sweep at 31 ms/step (372 ms full cycle). 433 Narrow covers 433.840–434.005 MHz (±80 kHz around 433.920). Crystal calibration offset applied to every hop.
- **Band Scope:** 40-point spectrum + scrolling waterfall canvas; continuous sweep; live active-channel count. **SDR-style frequency marker:** a solid yellow vertical line appears at the center frequency on open; drag your finger across the canvas to move the line in real time (like SDRSharp or GQRX). Tap the canvas to show frequency + RSSI in the status label. **Hunt button** (right of Start/Stop) jumps directly to Fox Hunt at the marked frequency — tap a signal in the Band Scope, then tap Hunt to track it.
- **Fox Hunt:** ham radio-style proximity tracker tunable across 300-928 MHz. Four preset buttons (315 / 433 / 868 / 915 MHz) plus ±0.1/±1 MHz fine-tune buttons. RSSI bar with peak hold (tap Clear Peak to reset). Adjustable squelch (±5 dBm per tap). Haptic feedback in bug-hunter style: slow pulses (1 every 2 s) just above squelch, racing pulses (10/s) at strong signals — vibration intensity also scales with RSSI. Status label: `-- SILENT / > WEAK / >> MEDIUM / >>> STRONG - CLOSE!`
- **Z-Wave Scout:** passive wardrive on the Z-Wave frequency (908.42 MHz US / 868.42 MHz EU). Configures CC1101 for GFSK 9.6 kbps, sync word `0xAA01`. Logs frame metadata (node IDs, command class, RSSI, GPS coordinates) to `/sdcard/lab/zwave/` as a timestamped CSV. GPS-tagged entries are compatible with WiGLE for mapping Z-Wave device density.
- **TPMS Monitor:** receives Tire Pressure Monitoring System transmissions at 315 MHz (US) or 433.92 MHz (EU). Decodes Schrader-family OOK packets — identifies each sensor by its unique 32-bit ID, displays pressure in PSI and kPa, temperature in °C, battery-low and alarm flags, and RSSI. Tracks up to **20 unique sensors** in a scrollable grid. Logs all valid packets to `/sdcard/lab/tpms/` as a timestamped CSV.
- **Weather Station:** decodes **Fine Offset** protocol weather sensors (WH65, WH57, WS80, WH31, Froggit, Ecowitt, and compatible) at 433.92 MHz OOK. Extracts temperature (°C), humidity (%), battery status, and device ID. Displays a live scrollable list of up to 6 sensors with RSSI and last-seen age. Most Fine Offset sensors transmit every 30–60 seconds; just open the screen and wait.
- **Alarm Sensor:** decodes **EV1527** OOK alarm sensors at 315 MHz or 433.92 MHz (toggle buttons). EV1527 is the protocol used by ~90% of cheap wireless alarm products — door/window contacts, PIR motion detectors, smoke detectors, and flood sensors. Displays 24-bit unique address, 4-bit channel/button code, RSSI, trigger count, and last-seen age. Trigger a sensor (open a door, break a beam) to see its address appear instantly.

##### CC1101 Crystal Frequency Calibration

<a name="cc1101-calibration"></a>

Consumer-grade CC1101 modules use a 26 MHz crystal with ±20-40 ppm tolerance. At common ISM frequencies this produces the following absolute error:

| Frequency | ±20 ppm | ±40 ppm |
|-----------|---------|---------|
| 315 MHz   | ±6.3 kHz | ±12.6 kHz |
| 433 MHz   | ±8.7 kHz | ±17.3 kHz |
| 868 MHz   | ±17.4 kHz | ±34.7 kHz |
| 915 MHz   | ±18.3 kHz | ±36.6 kHz |

For most applications (TPMS decoding, wardrive scanning, general capture) this is acceptable — the CC1101's wide receive filter accommodates the drift. For precise frequency measurement, jamming experiments, or calibrated fox hunting, apply the crystal offset.

**Service monitor / spectrum analyzer settings for calibration:**

| Setting | Value |
|---------|-------|
| Center frequency | **433.920 MHz** |
| Span | 100 kHz (±50 kHz around center — covers worst-case crystal error) |
| Mode | CW / Carrier detect / Spectrum |
| Expected signal | Continuous OOK carrier (duty = 100% while CAL TX is active) |
| Peak hold | ON recommended — helps capture the carrier center |

The CAL TX emits a continuous RF carrier at exactly the programmed frequency (433.920 MHz ± current offset). Without any offset correction, expect to see the carrier peak 5–60 kHz away from 433.920 MHz on a typical module. Some boards with cheap crystals can be 100+ ppm off.

**Calibration workflow (HW Test → Crystal Calibration section):**

1. Fit DIP 1 (CC1101) ON and open **CC1101 → HW Test**.
2. In the Crystal Calibration panel at the bottom — current offset shown as "Offset: +138.3 ppm (+60.0 kHz @ 433 MHz)" — orange when non-zero.
3. Tap **CAL TX 433** — button turns red ("TX ACTIVE"). The CC1101 transmits a continuous OOK carrier. Keep DIP 1 ON.
4. On your service monitor / SDR (set to 433.920 MHz center, **2 MHz span**, peak hold ON):
   - Locate the carrier peak. Read the actual frequency.
5. Tap **Set Offset** — enter the kHz deviation measured at 433.920 MHz:
   - Carrier at **433.860 MHz** (chip 60 kHz LOW) → enter **+60.0**
   - Carrier at **433.980 MHz** (chip 60 kHz HIGH) → enter **-60.0**
   - Formula: `entry = measured_MHz × 1000 − 433920` (kHz at 433.920 reference)
6. Tap **Save** — stored as PPM in NVS and applied to CAL TX immediately.
7. Verify: CAL TX carrier should now appear at exactly **433.920 MHz** on the monitor.
8. Tap **CAL TX 433** again to stop.

**Quick verification:** Open Fox Hunt → set to 433.920 MHz → RSSI should now peak at the calibrated frequency. Band Scope center marker confirms visual alignment.

**How the offset works — PPM scaling:**

The crystal error is proportional (PPM), not a fixed Hz offset. The same ppm causes different Hz errors at different bands:

```
Correction: hardware_freq = desired_freq × (1 + ppm / 1,000,000)
```

Example: 60 kHz error at 433 MHz = 138 ppm. At 915 MHz the same crystal produces `915 × 138 / 1,000,000 × 1000 = 126 kHz` error. The PPM storage ensures the calibration is automatically correct at 315, 433, 868, and 915 MHz without re-calibrating per band.

- **Input**: kHz deviation at 433.920 MHz (range ±130 kHz = ±300 ppm)
- **Stored**: millippm (ppm × 1000) in NVS key `"cc1101_ppm"` (int32)
- **Applied**: `cc1101_freq_cal()` wraps every `cc1101_set_freq_mhz()` call

> **Note:** The FSCTRL0 hardware register also provides frequency offset correction (±202 kHz range, ~1.59 kHz/step). This firmware uses software PPM correction via `cc1101_freq_cal()` instead — it scales correctly to all frequencies and the offset is visible in displayed frequency values.

##### Z-Wave Scout

Z-Wave Scout puts the CC1101 into passive receive mode at the Z-Wave primary channel (908.42 MHz, 9.6 kbps GFSK, `0xAA01` sync word). All received frames are decoded at the link layer: source and destination node IDs, hop count, command class byte, and RSSI. Results are displayed live on screen and logged to `/sdcard/lab/zwave/zwave_YYYYMMDD_HHMMSS.csv`.

**CSV columns:**

| Column | Description |
|--------|-------------|
| `timestamp` | UTC from GPS-synced clock |
| `rssi` | Signal strength in dBm |
| `src_node` | Z-Wave source node ID (1–232) |
| `dst_node` | Z-Wave destination node ID or `0xFF` for broadcast |
| `hop_count` | Remaining hops in the routing header |
| `cmd_class` | First command class byte (e.g. `0x25` = Binary Switch, `0x26` = Multilevel Switch) |
| `lat`, `lon` | GPS coordinates at time of reception (last-known fallback if no fix) |
| `gps_live` | `1` if GPS was live; `0` if using last-known |

**Tap Stop** to close the log file cleanly. Entries without GPS use the last-known NVS position with `gps_live=0`.

> **Note:** Z-Wave uses 908.42 MHz in the US and 868.42 MHz in Europe/Australia. The Scout is pre-configured for the US frequency. Edit `ZWAVE_FREQ_MHZ` in `main.c` to change regions.

##### TPMS Monitor

<a name="tpms-monitor"></a>

The TPMS Monitor passively receives Tire Pressure Monitoring System (TPMS) sensor transmissions and decodes them in real time. Sensors are the small RF transmitters built into car wheels — they broadcast pressure, temperature, and status every 60–90 seconds at rest and more frequently while driving. Up to **20 unique sensors** are tracked per session in a scrollable grid; new sensors automatically scroll into view at the bottom.

**Frequency selection (on-screen):**

| Button | Band | Typical use |
|--------|------|-------------|
| **315 MHz** | OOK ~9.97 kbps | US-market vehicles |
| **433 MHz** | OOK ~9.97 kbps | EU/Asia-market vehicles |

Tap the active-frequency button (highlighted blue) to switch. If a scan is running, it stops automatically so the new frequency can be applied before the next Start.

**Operation:**

1. Fit DIP 1 (CC1101) ON.
2. Open **NM-RF-HAT → CC1101 → TPMS Monitor**.
3. Tap **315 MHz** or **433 MHz** to match your vehicle's market.
4. Tap **Start** — the status line shows *Listening…* and a packet counter updates live.
5. Drive or spin each tyre. Most sensors transmit within 30–60 seconds of the wheel moving. Stationary sensors transmit every 60–90 seconds.
6. Each unique sensor appears as its own row showing sensor ID, pressure, temperature, flags, and RSSI.
7. Tap **Stop** to end the session and close the log file cleanly.

**Decoded fields per sensor:**

| Field | Description |
|-------|-------------|
| Sensor ID | 32-bit hardcoded sensor ID (hex) — unique per tyre/sensor unit |
| Pressure | In both PSI and kPa |
| Temperature | In °C (raw − 40 offset) |
| Battery low | Bit 0 of flags byte — shown as `[BATT]` |
| Alarm | Bit 5 of flags byte — shown as `[ALARM]` |
| RSSI | Signal strength at time of last reception |
| CRC | `[OK]` = packet CRC matched; `[?]` = CRC mismatch (shown but not logged) |

**Display color coding:**

- **Amber label** — pressure below 28 PSI (low tyre warning)
- **Green ID** — last packet CRC passed
- **Grey ID** — last packet CRC failed (data shown as reference only)

**SD card logging:** `/sdcard/lab/tpms/tpms_YYYYMMDD_HHMMSS.csv`

| Column | Description |
|--------|-------------|
| `timestamp` | UTC from GPS-synced clock |
| `sensor_id` | 32-bit sensor ID in hex |
| `psi` | Pressure in PSI (1 decimal place) |
| `kpa` | Pressure in kPa (integer) |
| `temp_c` | Temperature in °C |
| `flags` | Raw flags byte (hex) |
| `rssi` | Signal strength in dBm |
| `crc_ok` | `1` = CRC passed, `0` = mismatch |

Only CRC-valid packets are written to CSV. CRC-fail rows are shown on screen (labelled `[?]`) so you can see when *something* was received, but they are excluded from the log.

> **Note:** The Schrader sync word (`D391`) covers the majority of US and EU OEM sensors. After-market sensors and some Asian-market brands may use different sync words and will not be decoded — the CRC-fail `[?]` row indicates a packet was received at that frequency but the format differs.

#### nRF24L01+ 2.4 GHz (DIP 2)

2.4 GHz channel scan, packet sniffing, and jamming. Uses a 2-page paged tile menu (same pattern as CC1101).

**SD card path:** `/sdcard/lab/nrf24/` -- Flipper-compatible `.nrf24` text format

**Features:**
- **HW Test:** reads STATUS, CONFIG, RF_CH, and RF_SETUP registers over SPI; confirms chip is responding.
- **Ch Scan:** 126-channel carrier-detect sweep (2400-2525 MHz); canvas shows spectrum bar + 8-row waterfall; Start/Stop; live active-channel count.
- **Packet Sniffer:** promiscuous-mode RX on channel 76 (2476 MHz) with CRC disabled and a 32-byte packet size. Uses the `AA:AA:AA` address trick — because the nRF24 preamble byte is always `0xAA` or `0x55` (matching the MSB of the first address byte), loading `AA:AA:AA` into the RX address makes the correlator treat any `0xAA`-preamble packet as an address match, giving a wide-open receive window that catches transmissions from unknown devices without knowing their addresses. Packets are accumulated across the session and auto-saved to `/sdcard/lab/nrf24/` in Flipper-compatible `.nrf24` text format on Stop.
- **Saved Files:** lists `.nrf24` files with Play and Delete per entry.
- **Jammer:** legal disclaimer required; rapid PTX channel sweep across all 126 channels.
- **Futaba S-FHSS:** scans 25 S-FHSS channels (2404-2504 MHz, 4 MHz steps) at 1 Mbps; decodes 10-byte payload; extracts up to 8 servo channel values (11-bit, 0-2047); displays result on screen.
- **Fox Hunt:** carrier-detect proximity tracker tunable across 2400-2525 MHz in 1 MHz steps (channels 0-125). Channel ±1/±10 step buttons plus quick presets (2400 / 2476 / 2500 MHz). Rolling 20-sample carrier-detect rate displayed as a bar + percentage. Haptic: vibrator pulses on each detection with intensity proportional to hit rate.
- **Stub screens** (with authorization disclaimers): MouseJack, Keyboard Inject, Drone, GamePad -- Coming Soon.

**nRF24 component:** `ESP32C5/components/nrf24/` (nrf24.c, nrf24.h, CMakeLists.txt)

##### nRF24 Packet Sniffer

<a name="nrf24-packet-sniffer"></a>

The Packet Sniffer puts the nRF24L01+ into a wide-open promiscuous receive mode that captures transmissions from devices whose addresses are unknown.

**How it works — the `AA:AA:AA` address trick:**

The nRF24 always prepends a 1-byte preamble before the address field. The preamble is `0xAA` (10101010) if the first bit of the address is 1, or `0x55` (01010101) if it is 0. By loading `AA:AA:AA` (all bits 1) as the receive address, the preamble flows seamlessly into the address bytes — the chip's correlator sees a continuous `10101010 10101010 10101010 10101010` pattern and treats *any* `0xAA`-preamble packet as an address match. Combined with CRC disabled, this gives the widest possible receive window without needing to know a target's address.

**Fixed parameters:**

| Parameter | Value | Reason |
|-----------|-------|--------|
| Channel | 76 (2476 MHz) | Centre of 2.4 GHz ISM, low WiFi overlap |
| Data rate | 1 Mbps | Broadest device compatibility |
| Packet size | 32 bytes | Maximum nRF24 payload |
| CRC | Disabled | Allows capture of partial / foreign-format frames |
| Address | `AA:AA:AA` | Preamble-alignment trick (see above) |

**Operation:**

1. Fit DIP 2 (nRF24L01+) ON.
2. Open **NM-RF-HAT → nRF24 → Packet Sniffer**.
3. Tap **Start** — the screen shows a live packet counter and hex dump of each received frame.
4. Bring target RF devices into range (other nRF24 modules, FHSS remotes, wireless keyboards/mice at rest between hops, etc.).
5. Tap **Stop** — all captured packets are saved automatically to `/sdcard/lab/nrf24/` in Flipper Zero-compatible `.nrf24` text format.

> **Note:** Because CRC is disabled, some captures will be noise artifacts or corrupted frames. Use the hex dump to inspect payload patterns. Devices that use frequency hopping (e.g. Futaba S-FHSS) are better served by the dedicated **Futaba S-FHSS** screen which follows each hop.

---

### UI & System Features

| Feature | Description |
|---------|-------------|
| **LVGL Material Dark Theme** | Modern, touch-friendly dark UI |
| **Portrait 240×320 Layout** | All screens designed and reflowed for the NM-CYD-C5's 240×320 portrait display |
| **5-Tile Main Menu** | WiFi, Bluetooth, Wardrive, Settings, Go Dark — WiFi expands to sub-menu |
| **Screenshot Capture** | Tap the **title bar** on any screen to save a BMP to `/sdcard/screenshots/` — works on every screen including all menus, feature pages, and live data views |
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

All data is stored on the SD card. `/sdcard/lab/` is the root for all project data:

```
/sdcard/
├── calibrate.txt             # Create this file to trigger touch re-calibration on next boot
└── lab/                      # Root for all project data
    ├── ouilist.bin           # OUI vendor table -- adds manufacturer names to BLE scan results
    ├── white.txt             # WiFi BSSID/SSID whitelist -- networks protected from all attacks (one per line, MAC or SSID)
    ├── eviltwin.txt          # Credentials captured by Evil Twin / Captive Portal (auto-appended)
    ├── portals.txt           # Captive portal config
    ├── wpa-sec.txt           # wpa-sec.org API key (paste key on line 1)
    ├── wigle.txt             # WiGLE API token -- base64(apiname:apitoken) from wigle.net Account page
    ├── wdgwars.txt           # WDG Wars API key from wdgwars.pl profile
    ├── alerts/
    │   ├── proximity.csv     # BLE proximity alert rules
    │   └── css_alerts.csv    # CSS alert definitions
    ├── ble/
    │   ├── captures/         # BLE PCAP files (Kismet PCAPNG, DLT 256)
    │   │   └── ble_<timestamp>.pcapng
    │   ├── honeypair/        # HoneyPair session logs
    │   │   └── honeypair_<timestamp>.jsonl
    │   ├── blueduck/         # BlueDuck session logs + DuckyScript payloads
    │   │   ├── scripts/      # Drop .duck scripts here (seeded: android_rickroll.duck)
    │   │   │   └── *.duck
    │   │   └── blueduck_<timestamp>.jsonl
    │   └── whisperpair/      # WhisperPair (CVE-2025-36911) probe/exploit logs
    │       └── wp_<timestamp>.json
    ├── bluetooth/
    │   ├── lookout.csv       # BT Lookout watchlist: MAC,name,rssi_threshold,oui_only
    │   ├── blacklist.csv     # BT Blacklist: MAC[,oui_only] — suppressed globally
    │   ├── spooflist.csv     # Device Spoof targets: MAC,Name (one per line)
    │   └── scans/            # BT Scan & Select saved snapshots
    │       └── btsc_00001_HHMMSS_LAT_LON_label.json   # GPS-tagged JSON; scan_id NVS-persisted
    ├── cellular/
    │   ├── tower_baseline.csv
    │   ├── tower_anomalies.csv
    │   └── raw_at.log
    ├── config/               # Optional config overrides (created by Provision)
    │   ├── detection.cfg
    │   └── provision.log
    ├── deauths/              # Deauth monitor PCAP captures
    │   └── deauth_<ts>.pcap
    ├── dronedetect/          # Drone / Remote ID detection logs
    ├── gattwalker/           # GATT Walker + BT Observer JSON fingerprints
    │   └── <name>_<MAC>_gattwalk.json
    ├── handshakes/           # Captured WPA handshakes
    │   ├── *.pcap            # Wireshark-compatible captures
    │   └── *.hccapx          # Hashcat-compatible format
    ├── htmls/                # Captive portal HTML pages
    │   ├── basic_portal.html # Seeded: dark-themed WiFi login page (posts to /login)
    │   └── *.html / *.htm    # Drop additional portal pages here -- each appears in the attack dropdown
    ├── infrared/             # NM-RF-HAT IR remotes (Flipper Zero .ir format)
    │   └── <Remote>.ir       # One file per remote — multiple named signals per file
    ├── pcaps/                # MITM/sniff PCAP captures
    │   └── mitm_<n>.pcap
    ├── nrf24/                # NM-RF-HAT nRF24L01+ captures (Flipper-compatible .nrf24 format)
    │   └── <capture>.nrf24
    ├── radio/                # NM-RF-HAT CC1101 captures (Flipper .sub format)
    │   └── <freq>MHz_<ts>.sub
    ├── rf433/                # NM-RF-HAT RF433 OOK captures (Flipper Zero .sub format)
    │   └── <Signal>.sub
    ├── zigbee/               # Zigbee Scout wardrive logs (ESP32-C5 802.15.4 PHY)
    │   ├── zgwd_<timestamp>.csv   # One row per PAN sighting (PAN ID, channel, RSSI, GPS)
    │   └── zgwd_<timestamp>.pcap  # PCAP DLT 195 (IEEE 802.15.4 with FCS)
    ├── zwave/                # Z-Wave Scout captures (CC1101 908.42 MHz)
    │   └── zwave_<timestamp>.csv  # One row per received frame (node IDs, cmd class, GPS)
    ├── tpms/                 # TPMS Monitor captures (CC1101 315/433 MHz)
    │   └── tpms_<timestamp>.csv   # One row per valid Schrader packet (sensor ID, PSI, kPa, temp, flags, RSSI)
    ├── rfid/                 # NM-RF-HAT NFC/RFID (PN532)
    │   ├── hf/               # 13.56 MHz card saves (JSON)
    │   │   └── <name>.json
    │   ├── import/           # Drop Flipper .nfc files here to import
    │   │   └── *.nfc
    │   ├── export/           # Flipper .nfc exports
    │   │   └── *.nfc
    │   ├── keys/             # (reserved)
    │   └── logs/             # (reserved)
    ├── screenshots/          # UI screenshots (BMP)
    │   └── screen_<n>.bmp
    └── wardrives/            # GPS + WiFi wardrive logs (WiGLE CSV 1.6 format)
        ├── wd<n>.csv         # One file per session -- uploaded via Wardrive Upload
        ├── wd<n>_marks.gpx   # GPS waypoints for that session (GPX 1.1)
        └── upload_log.csv    # Upload tracking: filename,SERVICE,STATUS per row
```

### Screenshot Capture

Tap the **title bar on any screen** to capture a screenshot. The image is saved as an uncompressed 24-bit BMP to `/sdcard/lab/screenshots/screen_N.bmp` with an auto-incrementing index. The write runs in a background task so the UI stays responsive, and the title bar is briefly disabled while the save is in progress to prevent double-captures. Requires a mounted SD card — a warning is logged if the card is unavailable.

Screenshots are captured at full 240×320 resolution and can be opened directly in any image viewer or graphics application.

### OUI Vendor Lookup

Adds manufacturer names to BLE scan results by matching each device's MAC OUI prefix against a compact vendor table loaded from SD card. Results appear as vendor names in the **BT Scan & Select** list (replacing `[Unknown]` for unidentified devices) and as an additional line in **Bluetooth Lookout** detection popups.

Requires a curated binary table at `/sdcard/lab/ouilist.bin`. Generate or refresh it whenever the IEEE OUI list changes:

1. Download the latest OUI CSV from IEEE Standards:
   ```
   https://standards-oui.ieee.org/oui/oui.csv
   ```
   Place it in the repository root (or any convenient location).

2. Run the converter:
   ```bash
   python tools/oui_convert.py oui.csv ouilist.bin
   ```

3. Copy `ouilist.bin` onto the SD card under `/lab/`:
   ```
   /sdcard/lab/ouilist.bin
   ```

The firmware loads the binary into PSRAM on first entry to any BT feature and searches it with binary search — no large stack allocations. If the file is missing, vendor lookup is skipped transparently and scan results show `[Unknown]` as before.

---

The **SD Card → File Tree** utility (Settings menu) lets you browse the SD card's directory tree directly on the device — useful for confirming handshakes and wardrive logs were saved without needing to remove the card.

**SD Card Provision** (Settings → SD Card → Provision) creates the full `/sdcard/lab/` folder structure in one tap. When complete, the screen shows a "Done — N created, M OK" summary in a status bar above the Back button.

---

## Touch Calibration

The XPT2046 resistive touch panel requires one-time calibration to map raw ADC values to screen coordinates. Calibration data is saved in NVS and survives reboots.

### First Boot

Calibration runs automatically the first time the firmware boots (when no NVS calibration is found). The sequence appears after the splash screen, with the lab background image displayed at high brightness and **yellow L-shaped corner brackets** marking each tap target:

1. **"Tap the corner: Top-Left (1/4)"** — tap firmly in the top-left corner of the screen where the yellow L-bracket is shown.
2. **"Tap the corner: Top-Right (2/4)"** — tap the top-right corner.
3. **"Tap the corner: Bottom-Left (3/4)"** — tap the bottom-left corner.
4. **"Tap the corner: Bottom-Right (4/4)"** — tap the bottom-right corner.
5. **Confirm step** — a small green **OK** button appears at screen center with a 5-second countdown. The new calibration is applied immediately. Tap the OK button using the new calibration:
   - **Tap lands on OK** → calibration is saved to NVS.
   - **Countdown expires or tap misses** → old calibration is restored and the 4-point sequence restarts from the beginning. NVS is never written until OK is successfully hit.

The 4-point corner method records raw ADC values at the actual screen edges (not inset positions), so the full pixel range maps accurately with no extrapolation error. Column and row averages are used directly as `x_min`/`x_max`/`y_min`/`y_max`.

### Re-Calibrating

Three ways to trigger re-calibration after first boot:

1. **Settings → Screen → Recalibrate Touch** — invalidates the NVS magic value and restarts the device; calibration runs on the next boot.
2. **SD card trigger file** — create `/sdcard/calibrate.txt` (content does not matter). On the next boot the firmware detects it, deletes it, and runs calibration before showing the home screen.
3. **NVS magic reset** — setting the `magic` key in namespace `touch_cal` to any value other than `0xCA15` will trigger recalibration on next boot.

### What Is Stored (NVS namespace `touch_cal`)

| Key | Type | Description |
|-----|------|-------------|
| `x_min` / `x_max` | i32 | Raw ADC X range — values at actual screen corners |
| `y_min` / `y_max` | i32 | Raw ADC Y range — values at actual screen corners |
| `null_x` / `null_y` | i32 | Reserved (set to 0; null-zone filtering disabled) |
| `invert_x` / `invert_y` | u8 | Axis inversion flags (NM-CYD-C5: both typically `1`) |
| `swap_xy` | u8 | Axis swap (typically `0` for portrait) |
| `magic` | u16 | `0xCA15` — marks calibration as valid |

### Default Fallback

If NVS has no valid calibration (i.e., `magic` ≠ `0xCA15`), the firmware applies hardware-observed defaults for the NM-CYD-C5: **both axes inverted** (`invert_x = true`, `invert_y = true`). These defaults allow basic interaction but will be inaccurate near the screen edges. Run calibration for accurate full-screen touch.

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

### Flash — Web Flasher (Easiest — No Install Required)

**[https://jimgat.github.io/CYM-NM28C5/](https://jimgat.github.io/CYM-NM28C5/)**

A custom-built browser flasher using Chrome or Edge WebSerial. No drivers, no terminal, no file selection — everything is fetched automatically. Click the LAB5 logo on the page to visit the store.

#### Channels

| Button | Source | When to use |
|--------|--------|-------------|
| **Stable** | `main` branch — GitHub Pages CDN | Production releases |
| **Dev** | `Jimgat_Dev` branch — raw GitHub | Latest dev builds |

#### Connection flow

1. Put the board in ROM mode: **hold BOOT → plug USB-C → release BOOT**
2. Click **Connect** — the flasher will:
   - Detect the ESP32 Native USB bridge
   - Sync with the ROM bootloader
   - Identify the chip (ESP32-C5 revision 1.0)
   - Upload the tasmota flash stub (required for the OPI PSRAM used on this board — standard esptool-js cannot communicate with flash while PSRAM is initialized)
3. The **Flash** button glows bright red when the board is connected and armed

#### Flash buttons

| Button | What it flashes | Time |
|--------|----------------|------|
| **Flash All** | bootloader (0x2000) + partition table (0x8000) + app (0x10000) | ~17 s |
| **Quick Flash** | app binary only (0x10000) | ~16 s |

**Quick Flash** is for routine dev-cycle updates when the bootloader and partition table have not changed. It connects, uploads the stub, and writes only `CYM-NM28C5.bin`. Use **Flash All** after any partition layout change or for a fresh board.

The **Erase** checkbox performs a full flash erase before writing — use only when recovering from bad partitions, bootloops, or stale NVS config. Normal updates do not need it.

After flashing the board auto-reboots. The flash progress bar sweeps 0-100% during the write.

#### Serial monitor

The flasher includes a built-in UART monitor. After the board reboots, click **Monitor** and select the same serial port — no separate terminal app needed. Useful for reading the boot log, GPS output, or any serial debug immediately after flashing.

#### Baud rate

Default is **115200 baud** which is reliable for all conditions. Higher rates (460800, 921600) are available but may fail on some USB hubs or cables.

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
│   │   ├── main.c                # Core application — all UI screens, boot sequence,
│   │   │                         #   WiFi/BLE logic, touch calibration, GPS, wardriving
│   │   ├── attack_handshake.c/h  # WPA handshake capture (PCAP & HCCAPX)
│   │   ├── ble_blueduck.c/h      # BlueDuck BLE HID keyboard — GATT service registration,
│   │   │                         #   HID report handle lifecycle, persona management
│   │   ├── ble_whisperpair.c/h   # WhisperPair CVE-2025-36911 — portable NimBLE GATT client,
│   │   │                         #   AES-128-ECB KBP packet construction, FreeRTOS task lifecycle
│   │   ├── bt_lookout.c/h        # Bluetooth Lookout — CSV watchlist, LED alerts, OUI matching
│   │   ├── oui_lookup.c/h        # OUI vendor lookup — PSRAM binary search over ouilist.bin
│   │   ├── gatt_walker.c/h       # GATT Walker — NimBLE GATT client, JSON output, FNV-32 fingerprint
│   │   ├── xpt2046.c/h           # XPT2046 SPI touch driver (polling, null-zone, calibration)
│   │   ├── lvgl_memory.c/h       # PSRAM allocator for LVGL
│   │   └── dexter_img.c/h        # Dexter mascot image data (splash screen, RGB565)
│   ├── components/
│   │   ├── wifi_cli/             # CLI, WiFi init, LED control; wifi_common.c/h (shared constants)
│   │   ├── wifi_scanner/         # Active WiFi scan engine, target BSSID tracking
│   │   ├── wifi_sniffer/         # Promiscuous sniffer, SnifferDog, probe request logging
│   │   ├── wifi_attacks/         # Deauth, Evil Twin, Captive Portal, Karma, SAE Overflow
│   │   ├── wifi_wardrive/        # GPS + WiFi wardriving, SD card CSV logging
│   │   ├── sniffer/              # Raw 802.11 frame capture
│   │   ├── frame_analyzer/       # EAPOL / beacon / probe frame parsing
│   │   ├── pcap_serializer/      # PCAP file writer (Wireshark-compatible)
│   │   ├── hccapx_serializer/    # HCCAPX file writer (hashcat)
│   │   ├── led_strip/            # Local WS2812 RMT driver (replaces legacy managed component)
│   │   ├── rfid/                 # NFC/RFID card management (PN532 I2C driver, Flipper .nfc file I/O, JSON card storage)
│   │   ├── nrf24/                # nRF24L01+ 2.4 GHz driver (SPI, channel scan, packet sniffer, S-FHSS decoder, Flipper .nrf24 I/O)
│   │   └── espressif__esp_lcd_ili9341/  # ST7789 LCD panel driver (Espressif component, local copy)
│   ├── binaries-esp32c5/         # Pre-built flashable binaries (bootloader, partition-table, app)
│   ├── docs/
│   │   ├── index.html            # Web flasher UI
│   │   └── manifest.json         # OTA / web flash manifest
│   ├── partitions.csv            # nvs(24K) phy_init(4K) factory(7MB) storage(960K)
│   ├── sdkconfig.defaults        # Default Kconfig values (PSRAM, dual-band WiFi, LVGL)
│   ├── post_build.cmake          # Copies build artifacts → binaries-esp32c5/ after each build
│   ├── sdkconfig
│   └── CMakeLists.txt
├── docs/
│   └── screenshots/              # Screenshot assets used in this README
├── NM-CYD-C5-pinmap.md          # Full GPIO pin map with migration notes
├── CLAUDE.md                     # Claude Code project instructions
└── README.md
```

---

## BMorcelli Launcher Compatibility

This firmware is compatible with [bmorcelli/Launcher](https://github.com/bmorcelli/Launcher) and is available in the **Beta Release channel** for the NM-CYD-C5.

### Flashing Launcher via Web Flasher

1. Open the [Launcher Web Flasher](https://bmorcelli.github.io/Launcher/webflasher.html) in Chrome or Edge
2. Select **Beta Release** as the release channel
3. Select **CYD** as the device category
4. Select **NM-CYD-C5** from the device list
5. Connect your NM-CYD-C5 via USB-C and follow the on-screen instructions

Once Launcher is running, place `CYM-NM28C5.bin` on the SD card and select it from the Launcher file manager to install this firmware.

### Installing via Launcher OTA Favorites

You can also install directly through the Launcher OTA screen without copying the binary manually. Add the following entry to `config.conf` on your SD card (create the file if it does not exist):

```json
{
  "favorite": [
    {
      "name": "Cheap Yellow Monster",
      "fid": "",
      "link": "https://github.com/JimGat/CYM-NM28C5/releases/latest/download/CYM-NM28C5.bin"
    }
  ]
}
```

This entry will appear in the Launcher OTA favorites list and install the latest release directly to the device.

---

## On Signal Jamming

Signal jamming features are included in the NM-RF-HAT menu (CC1101 Sub-GHz jammer, nRF24L01+ 2.4 GHz channel sweep jammer, IR jammer, RF433 jammer) for use in **authorized test environments only** -- for example, a Faraday cage or under a written test authorization from the operator of the frequency band. Every jammer entry point is gated behind an explicit legal disclaimer screen that must be acknowledged before activation.

Jamming operates at the physical RF layer and is inherently indiscriminate. Unlike protocol-layer attacks (deauth, BLE spam), it cannot be targeted, cannot be recalled once transmitting, and cannot distinguish a test device from emergency communications equipment. Use only in an environment where you have complete control over the RF spectrum -- a shielded room, an RF test chamber, or a hardware-isolated test bench. Never operate a jammer in a residential building, vehicle, public space, or any environment with uncontrolled RF exposure.

The [FCC is explicit](https://www.fcc.gov/enforcement/areas/jammers): *"The Communications Act of 1934, as amended, prohibits the operation, manufacture, importation, marketing, and sale of equipment designed to jam or otherwise interfere with authorized radio communications... These jamming devices pose significant risks to public safety and potentially compromise other radio communications services."*

The consequences are equally clear. Per the [FCC Jammer Enforcement](https://www.fcc.gov/general/jammer-enforcement) page: *"Signal jamming devices can prevent you and others from making 9-1-1 and other emergency calls and pose serious risks to public safety communications... The use or marketing of a jammer in the United States may subject you to substantial monetary penalties, seizure of the unlawful equipment, and criminal sanctions including imprisonment."*

This is not a uniquely American position. Every jurisdiction with a radio communications law -- which is effectively every country on Earth -- treats jamming as a serious criminal offense precisely because the harm is real and uncontrollable. The disclaimer screens exist to make the legal exposure clear; they do not make operation legal outside an authorized environment.

---

## Support This Project

If you find Cheap Yellow Monster useful and would like to support its continued development, consider buying me a coffee! Your support helps fund hardware, research, and development time.

<p align="center">
  <a href="https://buymeacoffee.com/wjvasxixlg" target="_blank">
    <img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-☕-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=black" alt="Buy Me a Coffee"/>
  </a>
</p>

---

## Disclaimer

This project is intended for **educational and authorized security research purposes only**. Unauthorized access to computer networks is illegal. Always obtain proper authorization before testing on any network you do not own. The author assumes no liability for misuse of this software.

# **Don't Be A Skid!**

---

<p align="center">

---

## 🙏 Thank You

This project wouldn't be where it is without the brilliant minds and generous time of the following people. They've tested the firmware under brutal conditions, caught bugs before they reached users, reviewed code with a critical eye, and submitted fixes that made everything better.

**Heartfelt thanks to:**
- **@Birolt29** — For relentless testing and valuable code review feedback
- **ᛕ ᛊ ߇ ᛙ ᚢ (Kevin)** — For deep technical testing and helping diagnose the toughest issues
- **sithwrld999** — For thorough testing and finding edge cases we missed
- **bkbroiler** — For hands-on testing and constructive feedback
- **HeavyButter** — For testing and just being Paranoid Butter
- **eCowboy** — For Hardware testing and design suggestons
- **OrdoOuroborus** — For testing, review, and contributions for feature ideas

Your help made this toolkit more robust, more reliable, and better for everyone. 💙

---

  <b>Made with ☕ and ESP-IDF</b>
</p>

<p align="center">KAL, I love your face!</p>
