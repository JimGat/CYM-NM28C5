# CYM-NM28C5 Pre-built Firmware Binaries

**Firmware version: v1.8.85**

---

## Release Notes — v1.8.85

### nRF24L01+ 2.4 GHz Full Implementation

Full nRF24L01+ implementation under **NM-RF-HAT → 2.4 GHz (DIP 2)**. Requires NM-RF-HAT with DIP 2 on.

- **HW Test:** reads STATUS, CONFIG, RF_CH, RF_SETUP registers over SPI; confirms chip is responding.
- **Channel Scan:** 126-channel carrier-detect sweep (2400-2525 MHz); canvas shows spectrum bar + 8-row waterfall. Start/Stop button; live active-channel count.
- **Packet Sniffer:** promiscuous RX on configurable channel; captures packets; hex dump of last packet; auto-saves captures to `/sdcard/lab/nrf24/` in Flipper-compatible `.nrf24` text format.
- **Saved Files:** lists `.nrf24` files, Play/Delete per entry.
- **Jammer:** legal disclaimer required; rapid PTX channel sweep across all 126 channels.
- **Futaba S-FHSS decoder:** scans 25 S-FHSS channels (2404-2504 MHz, 4 MHz spacing) at 1 Mbps; decodes 10-byte payload; extracts up to 8 servo channels (11-bit values 0-2047).
- **Stub screens** (with authorization disclaimers): MouseJack, Keyboard Inject, Drone, GamePad.

Flipper `.nrf24` file format -- directly compatible with Flipper Zero nRF24 sub-GHz sniff captures.

---

## Release Notes — v1.8.80-83

### CC1101 Sub-GHz Full Implementation

Full CC1101 implementation under **NM-RF-HAT → Sub-GHz (DIP 1)**. Requires NM-RF-HAT with DIP 1 on.

Paged 2-page tile menu:

- **HW Test:** verifies PARTNUM (`0x00`) and VERSION (`0x14`) registers; shows MARCSTATE.
- **Freq Scan:** canvas-based spectrum -- RSSI bar per channel across the CC1101's full 300-928 MHz tunable range with carrier detect; live sweep with Start/Stop.
- **RAW Capture:** 10-second OOK/ASK signal capture window; Save/Discard prompt after; saves to `/sdcard/lab/radio/` as Flipper Zero `.sub` format.
- **RAW Replay:** lists `.sub` files from SD, play at 1x/3x/5x speed.
- **Saved Files:** lists `.sub` files, Play/Delete per entry.
- **Jammer:** legal disclaimer required; transmits on configurable frequency.
- **Band Scope:** 126-point spectrum + 8-row scrolling waterfall canvas; continuous sweep, 130 us dwell, active-channel count.

Files: `/sdcard/lab/radio/` -- Flipper Zero `.sub` format (compatible with Flipper Sub-GHz RAW captures).

---

## Release Notes — v1.8.70-77

### PN532 NFC/RFID Full Implementation

Full PN532 NFC/RFID card management under **NM-RF-HAT → NFC/RFID (DIP 3)**. Requires NM-RF-HAT with DIP 3 on and the PN532 module's I2C mode jumper set.

- **Card Scan:** detects ISO14443A cards -- NTAG213/215/216, MIFARE Ultralight, MIFARE Classic. Shows UID, ATQA, SAK, inferred card type.
- **Save:** name-at-save popup after each scan; card saved as JSON to `/sdcard/lab/rfid/hf/`.
- **Export .nfc:** exports scanned card in Flipper Zero `.nfc` text format to `/sdcard/lab/rfid/export/`.
- **Import .nfc:** drop Flipper Zero `.nfc` files in `/sdcard/lab/rfid/import/`; they appear in the Saved Cards list alongside locally scanned cards.
- **Card Emulation:** select a saved card from the list and present it to a reader via PN532 `TgInitAsTarget`. Works for UID-only readers; MIFARE Classic authentication is not emulated (PN532 target mode has no CRYPTO1 engine).
- **Saved Cards:** scrollable list -- Load, Emulate, Delete per card.

> **Note:** The PN532 module on the NM-RF-HAT has shorter read range than a dedicated PN532 breakout board. Hold cards very close (nearly touching the antenna) for reliable reads. This is a hardware limitation of the RF-HAT form factor.

---

## Release Notes — v1.6.16

### WhisperPair Scanner (CVE-2025-36911)

**FOR AUTHORIZED SECURITY RESEARCH ONLY.** Adds detection and exploitation of the WhisperPair vulnerability in Google's Fast Pair protocol, disclosed January 2026 by COSIC/KU Leuven. Affected devices (Sony, JBL, Jabra, Bose, Marshall, Xiaomi, Nothing, OnePlus, Soundcore, Logitech, Google) accept Key-Based Pairing requests without verifying pairing mode, allowing unauthorized pairing within ~14m.

**Detection (passive):** BLE scanner now flags devices advertising Fast Pair service UUID `0xFE2C` with a `[FP]` tag in the scan list. No connection required.

**WhisperPair screen** (`BT Attacks → WhisperPair`, behind authorization disclaimer):
- Shows all `[FP]` devices found in the most recent BLE scan
- **Probe (safe):** Connects via GATT, writes a plaintext KBP block to characteristic `fe2c1234-8366-4814-8eb0-01de32100bea`. If the device sends a notification response → **VULNERABLE**; no response within 5 s → patched. No pairing is established.
- **Exploit (AES):** Full CVE-2025-36911 attack — AES-128-ECB encrypted KBP packet (using ESP32-C5 ROM hardware AES, key = random Salt zero-padded to 128 bits) triggers unauthorized pairing bypass on vulnerable devices.

**GATT Walker integration:** If a GATT walk discovers the `0xFE2C` service, the result screen flags it with `⚠ Fast Pair (CVE-2025-36911)`.

**Janos portability:** `ble_whisperpair.c/h` is self-contained — no LVGL dependency. Swap `ets_aes_*` for `mbedtls_aes_crypt_ecb` and replace `heap_caps_malloc` with `malloc` for other platforms.

Results logged to `/sdcard/lab/ble/whisperpair/` as JSON with MAC, mode, result, KBP packet hex, and notification response hex.

---

## Release Notes — v1.6.15

### BlueDuck — Home Button Crash Fix (Heap Fragmentation)

**Root cause:** Pressing Home from the BlueDuck screen crashed with `esp_wifi_init failed (0x101)` and forced a device restart. The 600 ms BLE settle delay introduced in v1.6.12 was insufficient — the crash was still occurring 1.8 seconds after NimBLE stopped. The problem was heap fragmentation, not timing.

After BLE teardown, the internal SRAM heap is fragmented: total free bytes may be adequate but the WiFi driver needs 10 × 1700-byte contiguous DMA-capable blocks from internal SRAM, and fragmentation prevents those allocations from succeeding (only 7 of 10 rx buffers could be allocated).

**Fix:** When switching WiFi → BLE, `esp_wifi_deinit()` is no longer called. Only `esp_wifi_stop()` runs, leaving the WiFi driver initialized (with DMA buffers still allocated) but stopped. When returning from BLE, `esp_wifi_start()` restarts the already-initialized driver without any DMA reallocation. Heap fragmentation becomes irrelevant to the WiFi restart path.

The BLE settle delay is reduced from 600 ms → 200 ms (radio handover only; memory is no longer the constraint).

---

## Release Notes — v1.6.14

### BlueDuck — HID Key Timing & New Keys

`bd_key_tap()` post-keyup settle raised from 5 ms → 20 ms (matching the key-hold interval). The previous 5 ms was shorter than the BLE minimum connection interval of 7.5 ms, meaning the key-up HID report could be queued before the key-down had finished transmitting to the host. The longer settle gives the host a full connection interval to process each report before the next one is queued.

New named keys added to the DuckyScript parser: `PAUSE` / `BREAK` (HID 0x48), `PRINT_SCREEN` / `PRTSC` (HID 0x46), `SCROLL_LOCK` (HID 0x47). These enable `windows_sysinfo.duck` (`GUI PAUSE` → System Information) and snipping tool scripts.

Rick roll scripts updated with `&autoplay=1`. On Android, Chrome hands the URL directly to the YouTube app which autoplays fullscreen. On Windows the video autoplays in the default browser.

---

## Release Notes — v1.6.13

### BlueDuck — HID Modifier Key Fix + Working Android Shortcuts

**Root cause fixed:** Modifier keycodes (GUI, CTRL, ALT, SHIFT) in the range HID 0xE0–0xE7 were being placed in the key-array field of the HID report. The descriptor declares a Usage Maximum of 0x65 (101) for the key array — keycodes above this are silently dropped by Android. Only the modifier byte was going through, which alone has no effect. This is why `GUI` (alone) appeared to do nothing.

**Fix:** `bd_key_tap()` now zeroes the keycode when it is ≥ 0xE0, so modifier bits go only in the modifier byte. Combo keys such as `GUI h` (modifier=0x08, keycode=0x0B) are unaffected — their keycodes are well within range.

**Parser fix:** Bare `GUI` with no argument was unrecognised by the DuckyScript parser (falls through to "Unrecognised line"). Correct syntax is `GUI h`, `GUI b`, etc. — the modifier is always followed by a key.

**Confirmed Android keyboard shortcuts (Samsung One UI):**

| Script command | Shortcut | Effect |
|---------------|----------|--------|
| `GUI h` | Win+H | Home screen |
| `GUI b` | Win+B | Default browser |
| `GUI n` | Win+N | Notification shade |
| `GUI s` | Win+S | Messages |
| `GUI c` | Win+C | Contacts |

### BlueDuck — Android, Windows & iOS Script Library

Script library expanded with platform-specific payloads and a comprehensive keyboard shortcut reference:

**Android scripts:** `android_search`, `android_chrome_search`, `android_settings_search`, `android_browser_url`, `android_notifications`, `android_rickroll`

**Windows scripts:** `windows_rickroll` (Win+R→URL), `windows_lock` (Win+L), `windows_notepad_msg`, `windows_screenshot` (Win+Shift+S), `windows_sysinfo` (Win+Pause), `windows_task_manager` (Ctrl+Shift+Esc), `windows_open_browser`

Full shortcut reference for Android (Win/Ctrl/Alt keys, Samsung One UI confirmed), Windows 10/11 (Win/Ctrl/Alt/Fn keys, Run dialog command list), and iOS external keyboard in `resources/blueduck_scripts/README.md`.

> **Samsung note:** Win+Y opens Smart View (screen mirroring) on Samsung One UI — not YouTube. Use `GUI b` + `CTRL l` + `youtube.com` for YouTube.

---

## Release Notes — v1.6.12

### BlueDuck — BLE→WiFi Radio Switch Crash Fix

After a BlueDuck session ends (user presses Home or the connection drops and BLE is stopped), returning to WiFi mode was failing with `esp_wifi_init failed (0x101)` — no memory. Root cause: `nimble_port_deinit()` releases ~30 KB of DMA-capable internal RAM but does so asynchronously. Without a settle delay, `esp_wifi_init()` would race to claim DMA buffers before the BLE controller had returned them.

Fix: `vTaskDelay(600 ms)` added after `nimble_port_deinit()` in `bt_nimble_deinit()`. Internal DMA free rises from ~3 KB during BLE → ~39 KB after settle — well above the ~17 KB WiFi requires for its RX buffer pool.

### DuckyScript — HOME vs GUI h Correction

`HOME` (HID keycode 0x4A) is the cursor-home key (jump to beginning of line) — not the Android home button. All Android demo scripts updated from `HOME` to `GUI h` (Win+H). Bare `GUI` with no argument is unrecognised by the parser; combo syntax (`GUI h`, `GUI b`, etc.) is required.

---

## Release Notes — v1.6.11

### BlueDuck — Home Button Crash Fix (GAP Callbacks During NimBLE Deinit)

Pressing the device Home button while BlueDuck (or HoneyPair) was advertising caused an immediate crash. Root cause: `radio_reset_to_idle()` called `bt_nimble_deinit()` while BlueDuck's GAP event callbacks were still registered against the NimBLE stack. Tearing down the stack with active callbacks produces a fault.

Fix: `blueduck_stop()` and `honeypair_stop()` are now called before `bt_nimble_deinit()` in `radio_reset_to_idle()`, cleanly deregistering all GAP callbacks before the stack is torn down.

---

## Release Notes — v1.6.10

### BlueDuck — PSRAM Script Cache (SD DMA OOM Fix)

BlueDuck now preloads all `.duck` scripts into PSRAM during the script-scan phase (while WiFi is still active and DMA RAM is available). Previously, scripts were read via `fopen()` at execution time — but after NimBLE initialises, internal DMA-capable RAM drops below 1 KB, causing `sdmmc_read_blocks` to fail with `allocate_dma_buf 0x101` on every attempt. Scripts are now served from PSRAM on every pair event, making payload delivery reliable regardless of BLE/SD memory pressure.

- Startup log confirms: `Cached 'script_name' (NNN B) in PSRAM` for each discovered script
- Execution log: `Executing script from PSRAM cache: ...` instead of SD read errors
- Cache is freed and rebuilt whenever the script directory is re-scanned
- `fopen()` fallback retained for pre-BLE use cases (should never be reached in practice)

### LVGL Icon Library — Hacker / RF / RFID Toolkit

25 new FontAwesome icons added to the `lv_extra_symbols` custom font, all available as `MY_SYMBOL_*` macros in `main.c`:

| Category | Symbols added |
|----------|---------------|
| Arrows | `ARROW_DOWN` (↓), `ARROW_UP` (↑) |
| Access / Auth | `LOCK`, `LOCK_OPEN`, `FINGERPRINT`, `ID_BADGE`, `ID_CARD`, `SIM_CARD` |
| Hacking | `TERMINAL`, `CODE`, `BUG`, `SKULL`, `GHOST` |
| RF / RFID | `BIOHAZARD`, `RADIATION`, `ETHERNET`, `RSS`, `CIRCLE_NODES` |
| Interface | `FILTER`, `CIRCLE_INFO`, `FLAG`, `PLUG`, `TRASH`, `ROTATE` |

GPS "last known fix" indicator now renders the ↓ arrow correctly. NM-RF-HAT popup title now renders the microchip icon (U+F2DB) correctly. Both use mutable `lv_font_t` wrappers (`g_font_icon14`, `g_font_icon16`) that chain `lv_extra_symbols` as a fallback — required because Montserrat fonts live in const flash.

---

## Release Notes — v1.6.8

### WiFi First-Connect Dropout Fix

ESP32-C5 devices were disconnecting with error `0x2c0` (or `ASSOC_EXPIRE`) on the first association attempt after boot or mode switch. Root cause: `esp_wifi_set_country()` triggered an IEEE 802.11d regulatory domain update mid-association, causing the AP to deauthenticate the client.

Fix: `esp_wifi_set_country_code("01", false)` called after `esp_wifi_start()` (not before), combined with `ieee80211d_enabled: false` in the WiFi config. Region `"01"` is the international fallback that all APs accept without a country-specific domain update.

- Eliminates the first-connection dropout seen on all networks since v1.5.x
- WiFi reconnects reliably without requiring a second tap or a device reset

---

## Release Notes — v1.6.4

### AP File Server — Full File Manager

The AP file server (`TheLab` network, `http://192.168.4.1`) now supports a complete SD card file management workflow from the browser:

| Operation | How |
|-----------|-----|
| Browse | Click directories to navigate; path shown in header |
| Download | Click any file |
| Upload | Drag-and-drop or file picker on any directory page |
| Create folder | `[+ New Folder]` button on any directory page |
| Delete file | `[✕]` button per file with single confirm |
| Delete directory | `[✕]` on a directory — double confirm, recursive |

URL-encoded paths (spaces, special characters) are now decoded correctly throughout. Client IP address logged to serial on every HTTP request. All paths handle trailing slashes consistently.

---

## Release Notes — v1.5.52

### AP File Server — Working (DRAM / PSRAM Tuning)

The AP file server (`Settings → Data Transfer → AP File Server`) is now fully functional. Previous versions failed at `httpd_start()` with error `0xb008` due to DRAM exhaustion from WiFi static TX buffers.

Fix: `CONFIG_ESP_WIFI_STATIC_TX_BUFFER_NUM` reduced from 16 → 4, recovering ~19 KB of DRAM for LVGL draw buffers and the HTTP server. `SPIRAM_TRY_ALLOCATE_WIFI_LWIP=y` retained so lwIP pbufs continue to use PSRAM. HTTP GET handler stack raised from 4096 → 8192 bytes.

---

## Release Notes — v1.5.43

### BlueDuck — BLE HID Keyboard Injector

BlueDuck is a BLE HID keyboard device that pairs with nearby phones and tablets and automatically executes a DuckyScript payload on connection. Designed for authorized security testing and device compliance verification.

**Workflow:**
1. Place `.duck` script files in `/sdcard/lab/ble/blueduck/scripts/`
2. Open **Bluetooth → BlueDuck**, select a script, select a persona, and press **Start**
3. The device advertises as the chosen persona and waits for a target to pair
4. On successful pairing (3 s gate), the selected DuckyScript executes as keystrokes
5. Session events are logged to `/sdcard/lab/ble/blueduck/sessions/YYYYMMDD_HHMMSS.jsonl`

**9 device personas with MAC randomization:**

| Persona | Advertises as |
|---------|--------------|
| Wireless Keyboard | Generic HID keyboard |
| AirPods Pro | Apple audio accessory |
| Fitbit Sense | Fitbit wearable |
| Galaxy Buds Pro | Samsung audio |
| Garmin Fenix 7 | Garmin GPS watch |
| Apple Watch Series 8 | Apple wearable |
| JBL Flip 6 | JBL speaker |
| Logitech MX Keys | Logitech keyboard |
| Samsung Smart TV | Samsung display |

**DuckyScript commands supported:** `REM`, `DELAY`, `DEFAULT_DELAY`, `REPEAT`, `STRING`, `STRINGLN`, `HUMAN_MODE`, `HUMAN_SPEED`, `ENTER`, `TAB`, `SPACE`, `BACKSPACE`, `DELETE`, `ESCAPE`, `HOME`, `END`, `INSERT`, `PAGEUP`, `PAGEDOWN`, `UP`, `DOWN`, `LEFT`, `RIGHT`, `CAPS_LOCK`, `NUM_LOCK`, `PRINT_SCREEN`, `SCROLL_LOCK`, `PAUSE`, `F1`–`F12`

**Modifier combos** (syntax: `MODIFIER key` space-separated, chain multiple modifiers with dashes):
`GUI h` (Android home / Win voice typing), `GUI b` (browser), `GUI n` (notifications), `GUI r` (Windows Run), `GUI l` (lock), `GUI-SHIFT s` (Windows screenshot), `CTRL l` (address bar), `CTRL-SHIFT ESC` (Task Manager), `ALT TAB` (app switch), `ALT F4` (close), and all other modifier+key combinations

Scripts placed in the scripts directory are automatically discovered and listed on the script selector screen.

### HoneyPair — BLE Persona Honeypot

HoneyPair runs a continuous BLE persona cycle, advertising as popular consumer devices (AirPods, Galaxy Buds, etc.) to detect and log devices that initiate pairing requests. Useful for mapping Bluetooth activity and identifying devices that auto-connect to known peripherals.

- Up to 9 personas cycle automatically every 5 minutes
- Per-session JSONL logs saved to `/sdcard/lab/ble/honeypair/`
- Persona MACs are randomised and deduplicated across sessions
- GATT / HID service enumeration on any device that completes pairing
- Auto-rotate prevents stale scan-response caching on nearby phones
- Pair-gate timing tuned to avoid iOS popup dismissal race

**Navigation:** Bluetooth → HoneyPair

---

## Release Notes — v1.3.0

### Chanalizer — Wide Auto-Scrolling WiFi Channel Map

The WiFi Analyzer has been renamed **Chanalizer** and completely rewritten as a wide portrait-mode channel visualization tool.

- **520 px wide canvas** displays 2.4 GHz (ch 1–13) and 5 GHz (ch 36–165) side-by-side in a single portrait view — no device rotation required.
- **Auto-scroll:** The 240 px viewport pans left/right automatically, bouncing at each end so the full band is always visible.
- **Touch drag:** Tap and hold to pause auto-scroll; drag to scrub to any position; release to resume. No task watchdog issues — scroll is implemented via a manual pixel offset in the draw callback (`lv_obj_invalidate`) rather than LVGL's scroll container, which was causing WDT crashes at ~172 s.
- **SSID group color coding:** Up to 8 color-coded SSID groups with a legend panel below the chart.
- **Channel annotations:** Channel numbers drawn at correct pixel positions on the x-axis.

### WiFi Band Scope — Band Switch Fix + 2× Faster Sweep

- **Band toggle now works:** Switching 2.4 ↔ 5 GHz resets peak arrays under critical section, clears the full canvas, and updates the channel axis label. Previously stale 2.4 GHz bars persisted into 5 GHz view.
- **Axis label updates on toggle:** 2.4 GHz shows `1 2 3...13`; 5 GHz shows `36-64 | 100-144 | 149-165` band groups.
- **Dwell reduced 120 ms → 60 ms:** Full 2.4 GHz sweep now takes ~0.8 s (was 1.6 s); 5 GHz ~1.5 s (was 3.0 s). No loss of measurement quality.

### BLE Band Scope — Scan Start Fix

- `ble_gap_disc_cancel()` now called before `ble_gap_disc()` on entry, preventing a silent `EALREADY` failure if a prior BLE scan (BT Lookout, BT Observer) was still active. Scan start errors are surfaced in the status label.

### BLE Spam — Sour Apple Mode

New **Sour Apple (iOS Popups)** mode (mode 7) added to BLE Spam. Sends Apple **Nearby Action** (`0x0F`) advertisements — distinct from the existing Apple Proximity Pairing (`0x10`) mode. Cycles through 11 action types with a randomized 3-byte auth tag each packet, triggering iOS system popups (AirDrop, HomePod setup, Apple Watch pairing, Handoff, AirPlay, device setup flows). Included in the All Platforms rotation.

### Drone Detector

New **Drone Detector** screen under the Bluetooth menu. Passive BLE scan for DJI/Remote ID drone advertisement packets — detects drones broadcasting operator ID and location data without active probing.

### BLE Scope — Crash Fix on Entry

Fixed a crash and false-positive warning that fired when entering BLE Band Scope while no BLE scan was actually active. The check was incorrectly using `current_radio_mode == RADIO_MODE_WIFI` (always true at boot); corrected to `bt_lookout_is_active()` — matching the pattern used by all other BT features.

---

## Release Notes — v1.2.14

### Wardrive Upload — Reliability & UX Overhaul

HTTPS uploads to WiGLE and WDG Wars are now stable across all connection scenarios.

- **TLS memory exhaustion fixed** — mbedTLS switched to system allocator (PSRAM-capable) with dynamic SSL buffers; the previous static 16 KB buffer allocation exhausted internal RAM before a handshake could begin, causing every upload attempt to fail with an allocation error.
- **No WiFi? No problem** — tapping Upload when the device is not connected to a network now redirects to the WiFi Client screen to enter credentials. Once connected, the upload resumes automatically. Previously the screen showed a dead-end error with no path forward.
- **Per-file progress strip** — a fixed indicator bar sits above the scrolling log showing: file count (`3/5`), a live WiGLE tally (`✓OK / !DUP / ✗FAIL`), and a separate WDG Wars tally updating independently. The scrolling log continues to show the full per-file history for review.
- **SD card API keys** — keys placed in `/sdcard/lab/wigle.txt` and `/sdcard/lab/wdgwars.txt` now correctly override any key typed into the on-device form. Previously NVS always won, so SD-provisioned keys were silently ignored.
- **DHCP race eliminated** — upload no longer attempts DNS/TLS before DHCP has assigned an IP, which previously caused immediate connection failures on fast-associating networks.

### BLE During Wardrive — WDG Wars BLE Count

The **Wardrive → Options → BLE** toggle is now uploaded to WDG Wars automatically via the standard CSV endpoint. BLE devices discovered during time-sliced BLE passes are written to the wardrive `.csv` with `Type=BLE` in the WigleWifi-1.6 format — the same file sent to WiGLE and WDG Wars. No separate upload step or API change required; WDG Wars credits BLE entries to your BLE counter on receipt.

### GPS — Robustness Improvements

- **Last-known position** — when GPS signal is lost mid-drive the device holds the last valid fix (stored in PSRAM) and continues logging rather than pausing. Position is saved to NVS every 5 minutes and restored at boot so cold-start wardrives begin with a reasonable fallback immediately.
- **Go Dark now saves position** — activating Go Dark forces an immediate NVS GPS save, bypassing the 5-minute throttle, so the last fix survives an unexpected power cycle.
- **System clock re-sync** — the device re-synchronises `settimeofday()` on every valid GPS sentence until the first confirmed fix, ensuring SD card timestamps are accurate even if the very first sentence arrives during boot noise.
- **Manual fallback position editor** — GPS Info → Edit Position lets you type in a known lat/lon and save it as the NVS fallback. Useful for deploying to a fixed location or seeding position before driving into a GPS-dead zone.

### CPU_LOCKUP Fix — NVS GPS Save

`nvs_commit()` briefly disables the flash cache. Calling it from the GPS background task while the panic handler is also in flash caused a `CPU_LOCKUP` reboot every 5 minutes. GPS saves now happen exclusively from the main loop via a pending-flag handoff.

### BLE Spam — Stability

- Fixed a crash that occurred at approximately 1 400 packets into a BLE Spam session (buffer overrun in the advertising payload builder).
- Advertising MAC address now rotates every 30 packets, reducing AP-side deduplication and improving effective range.
- Samsung Fast Connect payload set expanded with additional registered model IDs.

### Wardrive File Management

**Wardrive → Manage Data** now supports multi-file selection: tap individual files to toggle selection, use Select All / Deselect All, then Delete Selected. File size and date shown per entry. Confirm-before-delete dialog prevents accidental data loss.

### Crash Diagnostics (sdkconfig)

- Panic handler pinned to IRAM (`CONFIG_ESP_PANIC_HANDLER_IRAM=y`) — prevents `CPU_LOCKUP` when a fault fires while the flash cache is dark.
- Task WDT panic enabled (`CONFIG_ESP_TASK_WDT_PANIC=y`) — converts silent watchdog reboots into full panic dumps with register state and backtrace for easier diagnosis.

### Release Workflow

GitHub Actions CI workflow (`esp32c5-build-master.yml`) updated: version is now read from `CMakeLists.txt` `PROJECT_VER` (was `JANOS_VERSION` in `wifi_common.h`); binary name updated from the old project name to `CYM-NM28C5`; GitHub Pages web-flasher manifest regenerated correctly on every release.

---

## Release Notes — v1.0.4

### Wardrive — Mark Button (GPS Waypoints / GPX Export)

A **Mark** button on the wardrive live screen lets you drop a named GPS waypoint mid-drive. Tapping it opens a note dialog; confirming saves the waypoint (with current GPS coordinates, timestamp, and your note) to a `.gpx` file alongside the wardrive CSV. Compatible with GPX-aware mapping software.

---

## Release Notes — v1.0.3

### BLE Wardrive (Time-Sliced)

Enable **Wardrive → Options → BLE** to interleave BLE advertising scans with WiFi channel-hopping. Every 30 seconds the radio pauses WiFi promiscuous mode, runs an 8-second BLE active scan, then resumes. Up to 200 unique BLE devices are captured per session and written to the wardrive CSV with `Type=BLE`. The channel indicator on the live screen shows `BLE` during each pass.

### BLE PCAP Capture

BLE advertisement frames can now be captured in Kismet PCAPNG format. Enable via Wardrive options; PCAP files are written to `/sdcard/lab/pcaps/`.

---

## Release Notes — v1.0.2

### Wardrive Submenu

Wardrive has been promoted from a single tile to a submenu with three entries:

- **Menu** — access to Start / Stop wardrive and the live dashboard
- **Options** — band filter (2.4 GHz / 5 GHz / Both), BLE toggle, PCAP toggle
- **Manage Data** — browse, inspect, and delete wardrive CSV files

### Wardrive Upload — WiGLE & WDG Wars

New **Settings → Data Transfer → Wardrive Upload** screen. Enter API keys on-device (saved to NVS) or provision them via SD card files (`/sdcard/lab/wigle.txt`, `/sdcard/lab/wdgwars.txt`). Uploads all wardrive CSV files in `/sdcard/lab/wardrives/` to WiGLE and/or WDG Wars over HTTPS. An upload log is appended to `/sdcard/lab/wardrives/upload_log.csv`.

### Band Filter

Wardrive → Options → Band: choose **2.4 GHz**, **5 GHz**, or **Both**. Setting is NVS-persisted.

---

**Firmware version: v1.0.1**

This folder contains the latest compiled firmware for the **NM-CYD-C5 (ESP32-C5)** board.

> **Note:** The NM-CYD-C5 can be purchased at [nmminer.com](https://www.nmminer.com/product/nm-cyd-c5/). Additional purchase sources and full hardware documentation are available on the [official board repository](https://github.com/RockBase-iot/NM-CYD-C5).

---

## Release Notes — v1.0.1

### BLE Attacks — General Device Spoof with spooflist.csv (new)

A **Device Spoof** tile has been added to the general **BT Attacks** menu (alongside BLE Spam), allowing device spoofing without requiring a prior BT Scan & Select session.

**Flow:** BT Attacks → Device Spoof → authorization warning → selection screen → pick or add device → START → attack.

- Loads `/sdcard/lab/bluetooth/spooflist.csv` on entry. CSV format: `XX:XX:XX:XX:XX:XX,Device Name` one entry per line.
- Scrollable list with tap-to-select (selected row highlights blue).
- **+ Add** button opens a full entry screen with MAC and name text areas and an on-screen uppercase keyboard — saves the new entry to `spooflist.csv` immediately.
- **START** — only active when an entry is selected — routes through the standard authorization warning popup, then launches the existing directed spoof task.
- Back from the attack returns to the spoof selection screen.
- File is created automatically (directory already provisioned by SD Provision).

### BLE Attacks — Directed Attack Menu Structure

The BT Attacks structure is now split into two tiers:

**General BT Attacks** (Bluetooth → BT Attacks):
- BLE Spam — broadcast advertising flood (Apple / Samsung / Google / Windows / All)
- Device Spoof — select from `spooflist.csv` or add new device

**Directed BT Attacks** (BT Scan & Select → Actions → BT Attacks):
- Device Spoof — uses the pre-selected BT Scan & Select device; no additional selection step
- BLE Disconnect — floods the pre-selected target with TERMINATE_IND frames

Both BT Attacks tiles are amber/yellow. All attacks require the authorization warning popup before proceeding.

### Bug Fix — BLE Spam / Spoof Back Without Start (crash)

Fixed a load-access-fault crash that occurred when pressing Back on the BLE Spam or Device Spoof screens without ever pressing START. `ble_gap_adv_stop()` was being called unconditionally even when the BLE stack had never been initialized. The call is now guarded by `current_radio_mode == RADIO_MODE_BLE`.

---

## Release Notes — v0.9.5

### BLE Attacks — BLE Spam, Device Spoof, BLE Disconnect (new)

Three BLE attack screens are now fully implemented under **Bluetooth → BT Attacks**:

- **BLE Spam**: Floods nearby devices with BLE advertisement packets. Five modes: Apple (Sour Apple — triggers iOS pairing popups), Samsung Fast Connect, Google Fast Pair, Windows Swift Pair, All Platforms (cycles all four). Start/Stop toggle with live packet counter.

- **Device Spoof**: Select a device from the last BLE scan, then broadcast an advertisement cloning its manufacturer data and name. Useful for testing device detection and identity.

- **BLE Disconnect**: Select a target connectable device from the last scan, then repeatedly connect and immediately terminate to flood the target's connection handling. Shows attempt counter.

All three attacks — and all WiFi attacks (Deauther, Evil Twin, Handshakes) — are now gated behind an **authorization warning popup** that requires explicit "I Understand" acceptance before proceeding.

### SD Card — All Files Under `/sdcard/lab/`

GATT Walker JSON output moved from `/sdcard/gattwalker/` to `/sdcard/lab/gattwalker/`. Screenshots moved from `/sdcard/screenshots/` to `/sdcard/lab/screenshots/`. All firmware-written files are now consistently under `/sdcard/lab/`.

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
