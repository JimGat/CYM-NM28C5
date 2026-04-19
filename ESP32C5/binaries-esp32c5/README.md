# CYM-NM28C5 Pre-built Firmware Binaries

**Firmware version: v0.2.0**

This folder contains the latest compiled firmware for the **NM-CYD-C5 (ESP32-C5)** board.

---

## Flash Addresses

| File | Address | Description |
|------|---------|-------------|
| `bootloader.bin` | `0x2000` | 2nd-stage bootloader |
| `partition-table.bin` | `0x8000` | Partition table |
| `CYM-NM28C5.bin` | `0x10000` | Main application firmware |

**Flash settings:** Mode `DIO` · Frequency `80 MHz` · Size `16 MB`

---

## Flashing via Web Browser (Recommended)

Use **[ESPConnect](https://thelastoutpostworkshop.github.io/ESPConnect/)** — a browser-based flash tool that works without installing any software.

1. Connect the NM-CYD-C5 to your PC via USB-C
2. Open ESPConnect in Chrome or Edge (WebSerial required)
3. Select the correct COM port
4. Flash each binary at its address listed above

> **Note:** You may need to hold the **BOOT** button while clicking Connect on first flash.

---

## Flashing via esptool (Command Line)

```bash
esptool.py --chip esp32c5 --port /dev/ttyACM0 \
  --baud 460800 \
  --before default-reset --after hard-reset \
  write_flash \
  --flash-mode dio --flash-freq 80m --flash-size 16MB \
  0x2000  bootloader.bin \
  0x8000  partition-table.bin \
  0x10000 CYM-NM28C5.bin
```

---

## Known Flashing Tool Issues

### ESPTerminator (espterminator.com)

[ESPTerminator](https://espterminator.com/) is a promising web-based flash and terminal tool but **does not currently support the NM-CYD-C5 correctly** — it fails to identify the ESP32-C5 board and does not flash reliably. This is expected to be resolved in a future release. Use ESPConnect in the meantime.

---

## BMorcelli Launcher Compatibility

The firmware is **not currently compatible** with [bmorcelli/Launcher](https://github.com/bmorcelli/Launcher).

- **ESP32-C5 not yet supported** — tracked in [Issue #300](https://github.com/bmorcelli/Launcher/issues/300) (opened April 2026, pending merge)
- The Launcher uses a custom bootloader that switches between a Launcher partition and OTA app slots based on reset reason; this firmware has no awareness of that scheme
- The Launcher expects OTA-style partition slots; this build uses a single 7 MB `factory` partition at `0x10000`
- The Launcher is Arduino-based; this firmware is ESP-IDF 6.0 — hardware init sequences would conflict

Flash this binary standalone. Launcher integration can be revisited once Issue #300 lands and an official NM-CYD-C5 board target is available upstream.

---

## SD Card Requirement

The firmware requires a **FAT32-formatted MicroSD card, 32 GB or smaller**. exFAT (used on most cards >32 GB out of the box) is not supported. If no compatible SD card is detected after 3 attempts, the device halts and displays an error — insert a correct card and reset.
