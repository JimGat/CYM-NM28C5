# Cheap Yellow Monster — Research & Pen Test Wiki

CYM-NM28C5 is a pocket-sized WiFi 6 + BLE security toolkit and RF research platform built on the NerdMiner ESP32-C5 CYD board. With the optional NM-RF-HAT expansion board it covers sub-GHz, 2.4 GHz ISM, NFC/RFID, and infrared alongside its native dual-band WiFi 6 and Bluetooth 5.

> **Legal notice:** All techniques documented here are intended for use on networks, devices, and RF environments you own or have explicit written authorization to test. Unauthorized interception, injection, or jamming is illegal in most jurisdictions.

---

## Pages

### RF Attack Surface (requires NM-RF-HAT)
| Page | What it covers |
|------|---------------|
| [Sub-GHz RF Research](Sub-GHz-RF-Research) | CC1101: capture, replay, band scope, Z-Wave Scout, frequency scan |
| [2.4 GHz ISM Research](2.4GHz-ISM-Research) | nRF24: channel scan, protocol sniffer, Futaba S-FHSS RC analysis |
| [NFC & RFID](NFC-RFID) | PN532: card read, clone, emulate, key test |
| [Infrared](Infrared) | RMT capture, replay, LED strip control |

### Wireless Security Research
| Page | What it covers |
|------|---------------|
| [WiFi Security Research](WiFi-Security-Research) | Deauth, handshake capture, evil twin, ESP-NOW Scout, Chanalizer |
| [Wardriving & Geolocation](Wardriving) | Passive WiFi + BLE mapping, WiGLE / WDG Wars export |
| [BLE & Bluetooth Research](BLE-Research) | GATT Walker, BT Lookout, device enumeration, drone detection |

---

## Hardware at a Glance

| Component | Spec |
|-----------|------|
| SoC | ESP32-C5 · RISC-V 240 MHz · WiFi 6 (2.4 + 5 GHz) · BT 5 |
| Display | 2.8″ ST7789 240×320 touch |
| Storage | MicroSD (FAT32) for all captures |
| Sub-GHz | CC1101 (300–928 MHz) via NM-RF-HAT DIP 1 |
| 2.4 GHz ISM | nRF24L01+ + AT2401C PA/LNA (+20 dBm) via DIP 2 |
| NFC/RFID | PN532 (ISO14443A/B, ISO18092) via DIP 3 |
| IR | 940 nm TX LED + 38 kHz demod RX via DIP 4 |
| 433 MHz OOK | T2-433M TX + R4A_433 superheterodyne RX via DIP 5 |

All captures save to `/sdcard/lab/<feature>/` on the microSD card.

### Hardware Add-ons
| Page | What it covers |
|------|---------------|
| [Haptic Feedback](Haptic-Feedback) | ERM vibrator motor build, wiring, which features use it and how |
