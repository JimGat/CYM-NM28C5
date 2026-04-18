# CYM-NM28C5 Pre-built Firmware Binaries

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

## SD Card Requirement

The firmware requires a **FAT32-formatted MicroSD card, 32 GB or smaller**. exFAT (used on most cards >32 GB out of the box) is not supported. If no compatible SD card is detected after 3 attempts, the device halts and displays an error — insert a correct card and reset.
