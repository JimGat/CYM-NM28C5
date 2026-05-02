# CYM-NM28C5 Pre-built Firmware Binaries

**Firmware version: v0.9.4**

This folder contains the latest compiled firmware for the **NM-CYD-C5 (ESP32-C5)** board.

> **Note:** The NM-CYD-C5 can be purchased at [nmminer.com](https://www.nmminer.com/product/nm-cyd-c5/). Additional purchase sources and full hardware documentation are available on the [official board repository](https://github.com/RockBase-iot/NM-CYD-C5).

---

## Release Notes — v0.9.4

### GATT Walker — Screen Lock Fix After Stuck Probe

Fixed a critical screen lock that occurred when a device went silent mid-GATT-operation (typically during MTU exchange) after a GATT walk + Extended Probe sequence.

- `gw_cancel()` now calls `ble_gap_terminate()` on the active connection handle when the state is anything other than `CONNECTING` — this forces the GAP disconnect event that drives state to a terminal value. Previously, cancel only set a flag that nothing would ever check if no GATT callback was firing.
- `gw_walk()` now explicitly handles `GW_STATE_PROBING`: if a stuck probe is detected when the user selects a new target from the Select screen, the connection is force-killed and state resets to IDLE so the new walk can proceed. Previously, every subsequent walk attempt returned false and the device showed "Failed to start walk" indefinitely until reset.

### BT Observer — Selection Blocked During Scan

Tapping a device row while the scan/walk sequence is still running is now silently ignored. Scrolling the list still works. Device rows become selectable only after the full walk sequence completes or Stop is pressed, preventing accidental navigation to a device that still shows "Queued" status mid-walk.

### BT Observer — Spinner Overlay

A small purple spinning progress indicator now appears in the top-right corner of the BT Observer screen while scanning and walking are in progress. It is placed on the LVGL overlay layer (transparent background) and is destroyed automatically when the scan completes or is stopped.

### BT Observer — Back Button Returns to Observer List

The Back button in the device detail view now returns to the existing BT Observer results list (preserving all walk results) instead of navigating to the Bluetooth menu. The probe result Back button also returns to the device detail rather than jumping to the top-level menu.

### BT Observer — Extended Probe Available for All Walked Devices

The Ext. Probe button in the BT Observer device detail is now enabled (red) for any device whose walk completed successfully — not just the most recently walked device. Previously, the button was greyed out for all but the last device in the list.

### GATT Walker — CCCD Probe Fix ("No subscribable characteristics found")

`s_find_cccd()` now falls back to `val_handle + 1` when no CCCD descriptor (UUID 0x2902) was captured during the walk. This is the standard BLE placement for the CCCD. Previously, devices that placed their CCCD at the spec-default offset but whose descriptor wasn't captured in the walk table would always report "no subscribable characteristics found" even though the `[~CCCD]` indicator appeared correctly on the result screen.

### GATT Walker / BT Observer — Extended Probe Improvements

- Dwell window extended from 3 s → **8 s** per characteristic — gives slow-reporting devices more time to send notification frames
- Notification frame capture expanded from 4×32 B → **8×64 B** per characteristic
- Probe result display shows byte count per frame alongside hex and ASCII preview

### UI — Ext. Probe Button Color

The Ext. Probe button is now **red** (`#C62828`) on both the GATT Walker result screen and the BT Observer device detail screen. Previously orange.

---

## Release Notes — v0.9.3

### Evil Portal — Path Fix + Multi-Portal Dropdown

The captive portal HTML directory was corrected from the phantom `/sdcard/lab/portal/` to the live path `/sdcard/lab/htmls/`. Any `.html` or `.htm` file placed in `/sdcard/lab/htmls/` now appears as a selectable option in the portal dropdown for Evil Twin, Karma AP, and Captive Portal attacks — no renaming to `index.html` required.

### SD Card — Provision Table Corrected

The Validate & Provision directory list was aligned with actual firmware file paths:

- `wardrive` corrected to `wardrives` (matches wardrive task output path)
- `pcap` corrected to `pcaps` (matches MITM logger output path)
- Phantom `portal/` directory removed
- Added: `htmls/`, `deauths/`, `gattwalker/`, `screenshots/`
- Added seed files: `eviltwin.txt`, `portals.txt`, `wpa-sec.txt` (with API key placeholder)

### README — Evil Portal Setup Instructions

Full portal setup guide added to README covering correct directory path, multi-file selection, and links to community portal collections (D3h420/Evil-Portals-Collection, DoobTheGoober/EvilPortalGenerator, saintcrossbow/Evil-Cardputer-Portals). Data & storage tree updated to reflect real directory layout.

---

## Release Notes — v0.9.0

### SD Card — Robust Initialization for Blank and Stubborn Cards

Boot-time SD card initialization completely overhauled to handle blank, freshly-formatted, and slow-responding cards without crashing or looping.

- **Progressive SPI frequency fallback**: attempt 1 at 20 MHz → attempt 2 at 10 MHz → attempt 3 at 5 MHz
- **CMD0 command timeout raised to 2 s** (`command_timeout_ms = 2000`) — cards that are slow to respond after power-on now get enough time
- **CS pin pre-assert**: GPIO 10 is driven HIGH for 200 ms before each mount attempt, ensuring the card is cleanly deselected before SPI init begins
- **500 ms power-on settle** at boot before first attempt (was 100 ms)
- **Interactive error screen** replaces crash loop: after all 3 attempts fail, shows Retry / Continue buttons instead of rebooting
- **Format confirmation flow**: if the card responded at hardware level but has an unreadable filesystem, a Format button appears; tapping it shows an "Are you sure?" confirmation before erasing anything

### SD Card — Main Task Stack Fix (Critical Crash Fix)

`CONFIG_ESP_MAIN_TASK_STACK_SIZE` raised from 3584 → **8192 bytes** (persisted in `sdkconfig.defaults`). The old stack size caused an immediate stack overflow panic when the SD error screen tried to build its LVGL UI, resulting in a reboot loop whenever SD card init failed.

### BT Attacks — New Submenu

A **BT Attacks** tile has been added to the Bluetooth menu (bottom-right). It opens a Coming Soon screen with placeholder tiles for BLE Spam, Device Spoof, and BLE Disconnect.

### HTTP File Server — Rebrand + Directory Improvements

- Page title and footer updated: **JANOS → Cheap Yellow Monster**
- File modification datetime shown alongside each entry (`YYYY-MM-DD HH:MM`)
- File sizes displayed in human-readable form (B / KB / MB)

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
4. Tap any successful row **after the scan completes** to open the full GATT detail view (tapping is blocked while the scan/walk sequence is running)
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

## Usage Guide — GATT Walker

GATT Walker performs a full Bluetooth GATT inspection of a single target device and saves the result as enriched JSON.

### Navigation path

**Bluetooth menu → BT Scan & Select → tap a device → BT Attack Tiles → tap GATT Walker**

### Walk procedure

1. The scan list shows all advertising BLE devices. Tap one — the BT Attack Tiles screen appears showing tools available for that device.
2. Tap **GATT Walker**. The progress screen opens, showing the target MAC, live status text, and a running count of discovered services and characteristics.
3. A **Cancel Walk** button is visible during the walk. It disappears and is replaced by **Back** when the walk finishes.
4. On completion the screen automatically transitions to the scrollable **GATT tree result view**.

### GATT tree result view

| Section | What is shown |
|---------|---------------|
| Header | MAC, OUI manufacturer name (purple), FP hash, GPS coordinates, timestamp |
| Per service | UUID + human-readable service name (cyan separator) |
| Per characteristic | UUID + name, decoded property flags (`R W N I` etc.), full expansion in parentheses, `[~CCCD]` indicator if subscribable, hex data + ASCII preview |
| Per descriptor | UUID + human-readable name where known |

The result is also saved to `/sdcard/gattwalker/` as enriched JSON.

### Extended Probe

The **Ext. Probe** button (red) on the result screen subscribes to every notifiable/indicatable characteristic, collects notification frames for **8 seconds** per characteristic, and re-saves the JSON with the captured frame data.

- Up to **8 frames × 64 bytes** are captured per characteristic.
- The probe result screen shows byte count, hex dump, and ASCII for each frame received.
- **Back** from the probe result returns to the GATT tree result screen.
- **Back** from the result screen returns to the BT Attack Tiles screen.

### GATT connect timeout

Configurable via **Settings → Timing → GATT Timeout** — a 3–30 s slider, NVS-persisted. Default is 10 s. Human-readable error messages are shown on connection failure.

---

## Usage Guide — BT Observer

BT Observer automates the scan-then-walk workflow: it scans for all nearby BLE devices, then attempts a sequential GATT walk on each one, displaying results as a live-updating list.

### Navigation path

**Bluetooth menu → BT Observer tile**

### Phases

| Phase | Duration | What happens |
|-------|----------|--------------|
| Scan | 10 s | Active BLE scan; up to 128 devices collected |
| Walk | ~5–10 s per device | Sequential GATT walks on up to 40 devices, sorted by RSSI (strongest first) |

- **Connect timeout**: 5 s per device (hardcoded for Observer, independent of the Settings slider).
- **Per-device poll window**: 10 s total (5 s connect + 5 s enumeration buffer). If a device does not complete within that window, the walk is cancelled and the next device starts.
- A 500 ms gap is inserted between connections.
- A small purple **spinner** in the top-right corner is visible while any phase is active.

### List display

Each row shows the device name, MAC, RSSI, and walk outcome:

| Colour | Meaning |
|--------|---------|
| Green | Walk succeeded — shows service count, characteristic count, FP hash |
| Red | Walk failed — shows reason (no response, refused, etc.) |
| Grey / "Queued" | Walk has not started yet |
| "Walking…" | Walk in progress |

**Scrolling is always available.** Tapping a row is blocked while the scan or walk sequence is running — rows only become selectable after the full sequence completes or **Stop** is pressed.

### After the scan completes

- Tap any **green** row to open the full GATT tree detail view for that device.
- **Ext. Probe** (red button in the detail view) is available for any successfully walked device.
- **Back** from the detail view returns to the Observer results list with all results preserved.
- **Back** from the list returns to the Bluetooth menu.

### Output

All successful walks are saved as enriched JSON to `/sdcard/gattwalker/` using the same format as the single-walk GATT Walker.

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

This firmware is compatible with [bmorcelli/Launcher](https://github.com/bmorcelli/Launcher) and is available in the **Beta Release channel** for the NM-CYD-C5.

To install Launcher, open the [Launcher Web Flasher](https://bmorcelli.github.io/Launcher/webflasher.html), select **Beta Release** channel, select **CYD**, then select **NM-CYD-C5** from the device list.

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

## SD Card Requirement

The firmware requires a **FAT32-formatted MicroSD card, 32 GB or smaller**. exFAT (used on most cards >32 GB out of the box) is not supported. If no compatible SD card is detected after 3 attempts, the device halts and displays an error — insert a correct card and reset.

---

## Power Requirements

The NM-CYD-C5 runs most reliably at **5.2 V @ 250 mA** (no peripherals attached, WiFi and Bluetooth transmit power at maximum). Use a clean, regulated 5 V USB supply capable of at least 500 mA to leave headroom for peripheral current spikes. Undervoltage at the USB input is the most common cause of random resets during active WiFi scanning.
