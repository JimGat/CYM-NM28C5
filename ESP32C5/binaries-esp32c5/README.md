# CYM-NM28C5 Pre-built Firmware Binaries

**Firmware version: v0.8.9**

This folder contains the latest compiled firmware for the **NM-CYD-C5 (ESP32-C5)** board.

---

## Release Notes — v0.8.9

### GATT Walker — Full 512-Byte Attribute Capture

The firmware now negotiates the maximum possible BLE ATT MTU on every GATT connection and reads all attributes using chained `ATT_READ_BLOB_REQ` calls, eliminating the 20-byte default truncation. Captured data is now complete up to the BLE spec ceiling.

- MTU exchange added to every GATT connection before discovery begins
- `ble_gattc_read_long()` replaces single-shot reads — multi-chunk attributes are reassembled automatically
- Capture buffer raised from 128 B → **512 bytes** (`GW_READ_MAX`) — matches the BLE Core Spec hard limit
- Both the single-walk GATT Walker and BT Observer benefit from this fix

### GATT Walker — Expanded Properties Display

On-device result screens now decode the characteristic properties bitmask into a full human-readable string alongside the compact flag notation.

- Compact flags: `R N` (raw bitmask notation)
- Full expansion: `(Read, Notify)` — shown in parentheses on the same line
- Applies to both the GATT Walker result screen and the BT Observer detail view

### BT Observer — Crash Fix on Device Tap

Fixed a **stack overflow** that caused an immediate reboot when tapping any device row in BT Observer to open the detail view.

- Root cause: main task stack was only 3584 bytes — too small for LVGL UI construction
- `CONFIG_ESP_MAIN_TASK_STACK_SIZE` raised 3584 → **8192 bytes** (persisted in `sdkconfig.defaults`)
- Large local buffers in the detail renderer (`hexraw[1028]`, `ascii[516]`, `row[620]`) moved from the call stack to static storage
- Same fix applied to the GATT Walker result screen to prevent the same class of crash there

### BT Attacks — New Menu Tile

A new **BT Attacks** tile has been added as the sixth tile in the Bluetooth menu (bottom-right position), completing the two-row layout.

- Bluetooth menu now fills both rows: BT Scan & Select · BT Observer · AirTag Scan / BT Locator · BT Lookout · **BT Attacks**
- Opens a dedicated submenu containing Coming Soon placeholder tiles for future BLE offensive capabilities:
  - **BLE Spam** — advertising flood attack (in development)
  - **Device Spoof** — clone BLE device identity (in development)
  - **BLE Disconnect** — targeted BLE link disruption (in development)
- Each placeholder shows a "Coming Soon — under development" screen with a back button

### HTTP File Server — Rebranded & Enhanced Directory Listing

The AP File Server and WiFi Client web interface has been updated.

- Page title and footer changed from `JANOS` → **Cheap Yellow Monster**
- Each file entry now shows its **modification datetime** (`YYYY-MM-DD HH:MM`) in the listing
- File sizes are now **human-readable**: `512 B`, `1.4 KB`, `3.2 MB` instead of raw byte counts
- Directories show datetime without size

---

## Release Notes — v0.8.5

### GATT Walker — Full Detail Screen

After a walk completes, the progress screen automatically transitions to a **scrollable GATT tree** view showing the complete inspection result without requiring a file read:

- Header: MAC address, OUI manufacturer name (purple), FP hash, GPS coordinates, timestamp
- Per service: UUID + human-readable name (cyan separator)
- Per characteristic: UUID + name, decoded property flags (`R W N I` etc.), hex data + ASCII preview
- Per descriptor: UUID + name where known

### GATT Walker — Enriched JSON Output

JSON files saved to `/sdcard/gattwalker/` now include:

| New field | Location | Description |
|-----------|----------|-------------|
| `"manufacturer"` | device level | OUI vendor name from `ouilist.bin` |
| `"name"` | each service | Human-readable service name (e.g. `"Generic Access"`) |
| `"name"` | each characteristic | Human-readable characteristic name |
| `"props_str"` | each characteristic | Decoded property string (e.g. `"R W N"`) |
| `"ascii"` | each characteristic | Printable ASCII preview of `read_data` |
| `"name"` | each descriptor | Human-readable descriptor name where known |

Updated limits: **16 characteristics per service**, **6 descriptors per characteristic**.

### BT Observer

A new tile in the Bluetooth menu that automates the scan-then-walk workflow:

1. Runs a single 10-second active BLE scan, collecting all advertising devices
2. Attempts a sequential GATT walk on every discovered device (5 s connect timeout per device)
3. Results appear in a live scrollable list — green with svc/chr counts on success, red on failure
4. Tap any successful row to open the full GATT detail view
5. All walks saved as enriched JSON to `/sdcard/gattwalker/`

### BT Observer — Detail View

Tapping a successful row in BT Observer opens the same full GATT tree display used by the single-walk GATT Walker result screen.

---

## Release Notes — v0.7.7

### GPS UTC Time & System Clock Sync

The GPS Info screen now shows a live UTC time field (`HH:MM:SS`) parsed from NMEA RMC sentences, refreshing every second. The first valid GPS fix automatically syncs the device system clock via `settimeofday()` — all subsequent SD card writes (handshakes, wardrive logs, GATT JSON) receive accurate FAT timestamps.

### BT Observer (Initial Release)

Sequential GATT walk session over all devices discovered in one BLE scan. See v0.8.5 notes for the completed feature including the detail view.

### Settings Menu Restructure

Settings reduced from 10 tiles to 8 (fits on one screen, no scrolling required):

- **Timing** — combines WiFi scan dwell sliders + GATT connect timeout slider in one popup
- **Screen** — combines screen timeout dropdown + brightness slider in one popup

### Data Transfer — AP File Server & WiFi Client

New **Settings → Data Transfer** sub-menu:

- **AP File Server** — device creates `TheLab` WPA2 AP (password: `Do not touch!`) and serves `/sdcard/` at `http://192.168.4.1`
- **WiFi Client** — device joins an existing network; DHCP IP shown on screen for browser access; SSID/password saved to NVS

### GATT Connect Timeout

Configurable via **Settings → Timing → GATT Timeout** — a 3–30 s slider, NVS-persisted. Human-readable error messages on connection failure (e.g. "No response — needs pairing or asleep").

### OUI Groups

Predefined BLE watchlist groups accessible from the Bluetooth Lookout screen — add entire manufacturer OUI blocks (Axon body cameras, Flock ALPR, Motorola Solutions, Samsung SmartTag) to the lookout watchlist in one tap.

### SD File Tree

New **Settings → SD Card → File Tree** — browse the full SD card directory tree directly on the device.

---

## Release Notes — v0.6.2

### Bluetooth Lookout

Continuous BLE watchlist monitor with CSV persistence, LED alerts (3× red flash), blackout mode, and device-addition from BT Scan & Select. OUI-prefix and full-MAC matching modes.

### Wardrive Improvements

Frozen column headers; Stop button and table layout corrected for 240 px portrait.

### Navigation Fixes

BT Locator and AirTag Scanner back buttons return to Bluetooth screen. GATT Walker placeholder has Back button.

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

[ESPTerminator](https://espterminator.com/) is a promising web-based flash and terminal tool but **does not currently support the NM-CYD-C5 correctly** — it fails to identify the ESP32-C5 board and does not flash reliably. Use ESPConnect in the meantime.

---

## BMorcelli Launcher Compatibility

The firmware is **not currently compatible** with [bmorcelli/Launcher](https://github.com/bmorcelli/Launcher).

- **ESP32-C5 not yet supported** — tracked in [Issue #300](https://github.com/bmorcelli/Launcher/issues/300) (opened April 2026, pending merge)
- Single 7 MB `factory` partition at `0x10000` — incompatible with Launcher's OTA slot layout
- ESP-IDF 6.0 vs Launcher's Arduino framework — hardware init sequences would conflict

---

## SD Card Requirement

The firmware requires a **FAT32-formatted MicroSD card, 32 GB or smaller**. exFAT (used on most cards >32 GB out of the box) is not supported. If no compatible SD card is detected after 3 attempts, the device halts and displays an error — insert a correct card and reset.

---

## Power Requirements

The NM-CYD-C5 runs most reliably at **5.2 V @ 250 mA** (no peripherals attached, WiFi and Bluetooth transmit power at maximum). Use a clean, regulated 5 V USB supply capable of at least 500 mA to leave headroom for peripheral current spikes. Undervoltage at the USB input is the most common cause of random resets during active WiFi scanning.
