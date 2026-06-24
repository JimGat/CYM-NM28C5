# CYM-NM28C5 — AI Project Brief

**Purpose of this file:** Complete context document for AI agents (Claude, ChatGPT, Hermes, or any LLM) working on this project. Read this before touching any code. It covers every major decision made, the reasoning behind it, known hazards, and how everything fits together.

**Last updated:** 2026-06-02, v2.6.46

---

## 1. What This Project Is

**Cheap Yellow Monster (CYM-NM28C5)** is a portable, touchscreen-driven wireless security toolkit running on the **NM-CYD-C5** development board — a $15 ESP32-C5 WiFi 6 board with a 2.8" resistive touch display.

It is a security research and education tool, not a consumer product. Features include WiFi scanning and attacks, BLE intelligence gathering, IEEE 802.15.4 / Zigbee wardrive, Sub-GHz RF (CC1101), 2.4 GHz RF (nRF24L01+), NFC/RFID (PN532), IR capture/replay, GPS wardriving, and a BLE HID keyboard injector (BlueDuck).

**Target users:** Security researchers, penetration testers, RF enthusiasts. International — primary developer is US-based; users include people in Poland and EU. All features must work internationally.

**GitHub:** https://github.com/JimGat/CYM-NM28C5
**Active dev branch:** `Jimgat_Dev`
**Release branch:** `main`

---

## 2. Hardware

### Primary Board — NM-CYD-C5

| Component | Spec |
|-----------|------|
| SoC | ESP32-C5-WROOM-1-N168R |
| Architecture | RISC-V single-core 240 MHz |
| Flash | 16 MB |
| PSRAM | 8 MB (used for LVGL buffers, large arrays, task stacks) |
| Display | 2.8" ST7789 TFT, 240×320 portrait, SPI @ 40 MHz |
| Touch | XPT2046 resistive, polling only (T_IRQ not connected), SPI @ 2 MHz |
| SD Card | MicroSD FAT32 max 32 GB, SPI @ 20 MHz |
| LED | WS2812 NeoPixel on GPIO 27, driven via RMT |
| Vibrator | ERM motor via SC8002B class-D amp on GPIO 26 (SPEAK_IN header) — optional hardware add-on |
| WiFi | WiFi 6 (802.11ax) dual-band 2.4 + 5 GHz |
| BLE | BLE 5.0 |
| 802.15.4 | Built-in IEEE 802.15.4 PHY (used for Zigbee Scout) |

**Purchase:** https://www.nmminer.com/product/nm-cyd-c5/
**Board docs:** https://github.com/RockBase-iot/NM-CYD-C5

### Critical GPIO Assignments

| GPIO | Function | Notes |
|------|----------|-------|
| 1 | XPT2046 Touch CS | Active LOW |
| 2 | SPI MISO | Shared: display + touch + SD |
| 4 | GPS RX (GPS→ESP) | LP-UART |
| 5 | GPS TX (ESP→ESP) | LP-UART |
| 6 | SPI SCK | ⚠ Strapping pin; also ADC1_CH5 — DO NOT configure as ADC (breaks SPI clock) |
| 7 | SPI MOSI | ⚠ Strapping pin, safe after boot |
| 10 | SD Card CS | Active LOW |
| 16–22 excl. 21 | Flash/PSRAM | NEVER USE |
| 23 | ST7789 Display CS | Active LOW |
| 24 | ST7789 DC | |
| 25 | Backlight | ⚠ Strapping, HIGH=on |
| 26 | SPEAK_IN → SC8002B | Vibrator motor driver, LEDC PWM 333 Hz |
| 27 | WS2812 NeoPixel | RMT |

**GPIO 6 (ADC conflict):** Battery ADC (ADC_CHANNEL_5) maps to GPIO 6 which is SPI SCK. `adc_oneshot_config_channel` on GPIO 6 kills the SPI clock. Battery ADC is permanently disabled in firmware with `if (false && init_battery_adc()...)`.

### NM-RF-HAT Expansion Board

Optional 5-module RF expansion board connecting via 14-pin FPC2. DIP switches cut VCC to inactive modules via P-channel MOSFETs — hardware exclusion, no software mux needed.

| DIP | Module | GPIO8 (IO22) | GPIO9 (IO27) |
|-----|--------|--------------|--------------|
| 1 | CC1101 Sub-GHz | GDO0 interrupt | CSN |
| 2 | nRF24L01+ 2.4 GHz | CE | CSN |
| 3 | PN532 NFC/RFID I2C | SCL | SDA |
| 4 | IR Infrared | TX emitter | RX detector |
| 5 | RF433 OOK/ASK | TX drive | RX input |
| 6 | Battery switch | — | — |

**Enable:** Settings → Hardware Options → NM-RF-HAT → Enable. Saves to NVS. Tiles appear on home screen immediately without reboot.

**GPIO note:** IR and RF433 share the same GPIO nets (DIP 4 and 5 both use GPIO8/9). The schematic labels IR_DT/433_DT, but empirical LED observation confirmed: GPIO8 = TX emitter (green LED), GPIO9 = RX detector (blue LED).

**RMT constraint:** ESP32-C5 has 4 RMT channels (TX: ch0/ch1, RX: ch2/ch3). `SOC_RMT_MEM_WORDS_PER_CHANNEL = 48`. ALL three RMT users (WS2812 on GPIO27, IR TX on GPIO8, IR RX on GPIO9) must set `mem_block_symbols = 48`. Using 64 chains an adjacent channel and exhausts RX channels.

### Optional Hardware

- **GPS:** ATGM336H GPS+BDS module, NMEA 0183, 9600 baud, 3.3V UART. Wires: VCC→3.3V, GND→GND, TX→GPIO4, RX→GPIO5.
- **Vibrator:** ERM motor + 1N5819 Schottky (series rectifier) + 1N4148 flyback diode on SPEAK header. JST 1.25mm connector (NOT 1.0mm — ordered wrong once).

---

## 3. Build System

**Framework:** ESP-IDF 6.0, branch `release/v6.0` tip — NOT the `v6.0` tag.

**Why not the tag:** The v6.0 tag is missing IDF-15338, a hardware bug fix for ESP32-C5 eco2/rev1.0 silicon. The RF PLL frequency-hop register (`FECOEX_SET_FREQ_SET_CHAN_REG` at `0x600a001c`, `BIT(30)`) must be reset before any PHY blob call. Without this patch, `esp_wifi_start()` hangs forever after `phy_init: phy_version 108`. The fix was extended to the first-boot calibration path in `/home/dev/esp/esp-idf/components/esp_phy/src/phy_init.c` at ~line 948–954.

**Build commands:**
```bash
cd /home/dev/projects/CYM-NM28C5/ESP32C5
source /home/dev/esp/esp-idf/export.sh
idf.py build
```

**Version:** Set in `ESP32C5/CMakeLists.txt`:
```cmake
set(PROJECT_VER "v2.4.3")
```
This is the single source of truth — propagates to IDF boot log AND `FW_VERSION` compile definition used throughout firmware. Bump the PATCH digit (last number) before every build. Never bump MINOR or MAJOR without explicit user approval.

**Post-build:** CMakeLists.txt automatically copies binaries to `ESP32C5/binaries-esp32c5/` after every build.

**Flash workflow:** Use the custom web flasher at **https://jimgat.github.io/CYM-NM28C5/**  
(Chrome or Edge required — WebSerial API)

Flash addresses:
- `0x2000`  — `bootloader.bin`
- `0x8000`  — `partition-table.bin`
- `0x10000` — `CYM-NM28C5.bin`

**Flash buttons:** "Flash All" writes all three. "Quick Flash" writes only the app binary (0x10000) — for dev-cycle updates where bootloader/partitions are unchanged.

**NEVER run `idf.py -p /dev/ttyACM0 flash`.** User does not have local USB flash set up. Always commit binaries and push to GitHub.

**Custom flasher implementation (ESP32C5/docs/index.html):**  
Standard `esptool-js` cannot communicate with the NM-CYD-C5's SPI flash because the ESP32-C5 eco2 with OPI PSRAM leaves the MSPI controller in Octal-SPI mode after boot. esptool-js issue #217 (open). Fixed by using `tasmota-webserial-esptool@9.2.23` (the same library ESPConnect uses) via the esm.sh CDN. 

Correct connection sequence (tasmota API — NOT like esptool-js):
1. `connectWithPort(port, logger)` — factory only; creates ESPLoader, opens port
2. `esploader.initialize()` — initializes `__inputBuffer`, detects USB-serial chip
3. `esploader.connectWithResetStrategies()` — resets chip to ROM mode, syncs
4. `esploader.detectChip()` — identifies ESP32-C5 revision
5. **Manual stub upload** (bypasses esm.sh ESM JSON module bug): `await import("./esp32c5.json")` returns `{default:{...}}` in browser ESM but the library code accesses `.text` directly (undefined), making `atob(undefined)` = `atob("undefined")` fail. Fix: catch the `atob` error, fetch the stub JSON directly from `https://raw.githubusercontent.com/Jason2866/WebSerial_ESPTool/development/src/stubs/esp32c5.json`, decode manually, upload via `memBegin/memBlock/memFinish`, read "OHAI" handshake, set `IS_STUB = true`.
6. All flash operations use `flashData(buf, progressCb, address, false)` on the stub loader. `compress: false` avoids the compressed-flash code path that has a separate `_inputBuffer` initialization bug. After writing: `esploader.hardResetToFirmware()`.

**Quick Flash** filters the manifest parts to `address === 0x10000` before fetching — only the app binary is downloaded and flashed.

**After every build:**
1. `git add ESP32C5/CMakeLists.txt ESP32C5/binaries-esp32c5/ ESP32C5/main/main.c [other changed files]`
2. `git commit -m "v2.4.X: description"`
3. `git push origin Jimgat_Dev`

**For releases:** `git checkout main && git merge --no-ff Jimgat_Dev -m "Release vX.Y.Z — summary"` then `git push origin main` then `git checkout Jimgat_Dev`.

**Partition layout:**
```
nvs         0x9000    24 KB
phy_init    0xf000     4 KB
factory     0x10000    7 MB   ← firmware
storage     0x710000  960 KB  ← FAT (internal, not SD)
```

---

## 4. Code Architecture

### The One Big File Rule

Everything lives in `ESP32C5/main/main.c` (~42,000 lines as of v2.4.3). This is intentional — the user ships fast and the code has never been split. Do not propose splitting it unless explicitly asked.

Companion files in `main/`:
- `gatt_walker.c/h` — NimBLE GATT client; sequential service/chr/descriptor walk; FNV-32 fingerprint; enriched JSON (service/chr names, props_str, ascii, OUI manufacturer)
- `bt_lookout.c/h` — continuous BLE watchlist monitor; CSV persistence; OUI-prefix and full-MAC matching
- `ble_blueduck.c/h` — BLE HID keyboard injector (DuckyScript engine, 9 personas, PSRAM script cache)
- `ble_whisperpair.c/h` — CVE-2025-36911 Fast Pair KBP bypass (AES-128-ECB, NimBLE GATT client)
- `oui_lookup.c/h` — PSRAM binary-search OUI table loaded from `/sdcard/lab/ouilist.bin`
- `xpt2046.c/h` — touch driver (polling, Z1+4095-Z2 compensated pressure formula)
- `lvgl_memory.c/h` — PSRAM allocator for LVGL

Components in `ESP32C5/components/`:
- `wifi_cli/` — WiFi init, shared constants (`wifi_common.h`), GPIO/pin defines, LED control
- `wifi_scanner/`, `wifi_sniffer/`, `wifi_attacks/`, `wifi_wardrive/` — WiFi subsystems
- `cc1101/` — CC1101 SPI driver (Sub-GHz)
- `nrf24/` — nRF24L01+ SPI driver (2.4 GHz sniffer, S-FHSS decoder)
- `rfid/` — PN532 I2C driver, Flipper .nfc I/O, card storage
- `rf_hat/` — IR capture/replay (RMT), RF433 OOK

### UI Framework

**LVGL 8.4.0**, portrait 240×320. All screens are drawn in `main.c`. The UI is a direct-manipulation imperative LVGL code — no LVGL designer files.

**Threading:** LVGL is not thread-safe. ALL LVGL calls outside the main task must take `lvgl_mutex`. An `esp_timer` fires `lv_tick_inc(10)` every 10 ms. The main loop calls `lv_timer_handler()` inside `lvgl_mutex`.

**Flush path:** `lvgl_flush_cb` → takes `sd_spi_mutex` → `esp_lcd_panel_draw_bitmap` (DMA, async) → releases mutex → returns. DMA completion fires `on_color_trans_done` → `lv_disp_flush_ready()`.

**Screen container:** `function_page` is the current feature screen. `create_function_page_base(name)` creates it, and CRITICALLY calls `reset_function_page_children()` inside, which frees any `s_X` context struct where `s_X->task == NULL`. A freshly calloc'd context has `task = NULL`.

**CRITICAL invariant — always assign `s_X = ctx` AFTER `create_function_page_base()` returns, never before.** Pre-assignment causes immediate free of the new context → NULL deref crash (manifests as Store access fault with MTVAL = offset of first field, e.g. 0x3c = offset of `canvas`). This bit us in v1.8.95 across 4 screens. Fixed in v1.8.96.

**Brightness:** Software black overlay (`brightness_overlay`) on `lv_layer_top()` — not PWM. Backlight GPIO 25 is driven HIGH at boot and left on.

**Touch calibration:** 4-corner sequence, stores to NVS namespace `touch_cal`, magic `0xCA15`. Triggered on first boot, from `calibrate.txt` on SD, or Settings → Screen → Recalibrate Touch.

### Memory Model

- PSRAM used for: LVGL draw buffers, large task stacks, 1 MB captive-portal HTML buffer, OUI lookup table, GATT Walker result struct (~250 KB), all RF hat canvas buffers
- `heap_caps_malloc(MALLOC_CAP_SPIRAM)` for PSRAM allocations
- `CONFIG_SPIRAM_USE_MALLOC=y` puts PSRAM in malloc pool above 16 KB threshold
- Internal SRAM is scarce (~88 KB total). WiFi needs 10 × 1700-byte contiguous DMA blocks. BLE heap fragmentation can prevent WiFi reinit after BLE teardown.

**BlueDuck BLE→WiFi crash (fixed v1.6.15):** After BLE teardown, internal heap is fragmented — WiFi DMA alloc fails with `0x101`. Fix: skip `esp_wifi_deinit()` when switching to BLE; only call `esp_wifi_stop()`. Then WiFi reinit only needs `esp_wifi_start()` which doesn't reallocate DMA buffers.

### Radio Architecture

ESP32-C5 has one shared radio. Most screens use `radio_mode_t` (RADIO_MODE_NONE / WIFI / BLE) and `current_radio_mode` to arbitrate exclusive access.

**Exception — Wardrive coexistence:** `CONFIG_ESP_COEX_SW_COEXIST_ENABLE=y` + `CONFIG_SOC_COEX_HW_PTI=y` enables simultaneous WiFi+BLE with hardware arbitration. Wardrive uses **12.5% BLE duty cycle** (`itvl=0x0200 / window=0x0040` = 320 ms / 40 ms). Keeping BLE duty ≤ 12.5% is critical — 100% duty kills WiFi promiscuous.

**Zigbee Scout:** Uses `esp_ieee802154_*` API (ESP32-C5 built-in 802.15.4 PHY). WiFi and BLE must be stopped before enabling 802.15.4. LED RMT conflicts with 802.15.4 — LED must be cleared before `esp_ieee802154_enable()`.

---

## 5. WiFi Regulatory Domain — Critical Decision

**Decision:** Use `WIFI_COUNTRY_POLICY_MANUAL` with `cc="01"` (ITU world), `schan=1`, `nchan=13` everywhere. Never use `WIFI_COUNTRY_POLICY_AUTO` or `esp_wifi_set_country_code("01", false)`.

**Why:** The WiFi driver processes Country IEs from AP probe responses and triggers regulatory domain updates mid-association. This drops the first connection attempt (`assoc -> init, reason 0x2c0`). POLICY_MANUAL with explicit struct prevents all IE-triggered updates. `esp_wifi_set_country_code("01", false)` looks equivalent but defaults to `nchan=11`, blocking EU channels 12-13 (used in Poland/EU). nchan=13 covers US (1-11) and EU/Poland (1-13).

**Three-part implementation (v2.2.11–v2.2.12):**
1. Boot: `init_wifi()` in `wifi_cli.c` sets MANUAL country after `esp_wifi_start()`
2. Pre-connect: every connect path re-asserts the country struct immediately before `esp_wifi_connect()`
3. Auto-retry: poll timer fires once at 1.5–5 s after failed association, re-pins country, retries connect (flag `s_wcs_retried` prevents double retry)
4. `radio_reset_to_idle()` was using POLICY_AUTO — changed to MANUAL so reset doesn't undo boot setting

**Never revert this.** Any regression here shows as first-connect always failing, second always succeeding.

---

## 6. SD Card File System

All data lives under `/sdcard/lab/`. Settings → SD Card → Provision creates the full structure in one tap. The SD_ITEMS array in `main.c` defines every directory and seed file. **When adding a new feature that writes to SD, add its directory to SD_ITEMS or users with un-provisioned cards get write errors.**

```
/sdcard/
├── calibrate.txt             # Create to trigger touch re-calibration on next boot
└── lab/
    ├── ouilist.bin           # OUI vendor table (binary search, PSRAM-loaded)
    ├── white.txt             # WiFi BSSID/SSID whitelist — networks protected from all attacks
    ├── eviltwin.txt          # Credentials captured by Evil Twin / Captive Portal
    ├── wigle.txt             # WiGLE API token (line 1)
    ├── wdgwars.txt           # WDG Wars API key (line 1)
    ├── wpa-sec.txt           # wpa-sec.org API key (line 1)
    ├── alerts/               # proximity.csv, css_alerts.csv
    ├── ble/
    │   ├── captures/         # BLE PCAP .pcapng (Kismet DLT 256)
    │   ├── honeypair/        # HoneyPair session JSONL
    │   ├── blueduck/
    │   │   ├── scripts/      # DuckyScript .duck files (seeded: android_rickroll.duck)
    │   │   └── *.jsonl       # Session logs
    │   └── whisperpair/      # CVE-2025-36911 probe/exploit logs
    ├── bluetooth/
    │   ├── lookout.csv       # BT Lookout watchlist: MAC,name,rssi_threshold,oui_only
    │   ├── blacklist.csv     # Global BLE suppress list: MAC[,oui_only] (seeded with header)
    │   ├── spooflist.csv     # Device Spoof targets
    │   └── scans/            # BT Scan & Select snapshots: btsc_%05u_HHMMSS_LAT_LON_label.json
    ├── gattwalker/           # GATT Walker + BT Observer JSON fingerprints
    ├── handshakes/           # WPA PCAP + HCCAPX
    ├── htmls/                # Captive portal HTML pages (seeded: basic_portal.html)
    ├── infrared/             # Flipper .ir remote files
    ├── nrf24/                # nRF24L01+ captures (.nrf24 Flipper format)
    ├── pcaps/                # MITM PCAP
    ├── radio/                # CC1101 captures (Flipper .sub)
    ├── rf433/                # RF433 captures (Flipper .sub)
    ├── rfid/hf/              # PN532 card JSON saves
    ├── rfid/import/          # Drop Flipper .nfc files here to import
    ├── rfid/export/          # Flipper .nfc exports
    ├── screenshots/          # BMP screenshots (tap title bar to capture)
    ├── wardrives/            # WiGLE CSV 1.6 + GPX marks + upload_log.csv
    ├── zigbee/               # Zigbee Scout: CSV + PCAP DLT 195
    └── zwave/                # Z-Wave Scout: CSV (908.42 MHz node decodes)
```

**white.txt vs blacklist.csv:** `white.txt` = WiFi BSSID/SSID whitelist (protects networks from attack). `blacklist.csv` = BLE MAC blacklist (suppresses devices from all BLE scan functions globally).

---

## 7. Key Features and Their Decisions

### Touch (XPT2046)

**Use Z1+4095-Z2 compensated pressure formula, not Z1 alone.** Z1 is position-dependent (proportional to X-position × pressure). On the right side of the panel, Z1 reads 80–150 for real touches — below any reasonable threshold, creating a dead zone down the right side. Z2 is complementary; `Z1+4095-Z2` cancels position bias. Untouched ≈ 0, real touch anywhere ≈ 200+. Threshold is 100. Never revert to Z1-only.

Do NOT add raw ADC range checks (`> 100 && < 4000`) — screen edges legitimately produce values outside that range.

### Vibrator Motor

GPIO 26 → SC8002B class-D amp → 1N5819 Schottky (series rectifier) → motor. 1N4148 flyback across motor. Half-wave rectified means 50% duty = effective maximum motor drive. Higher duty gives no additional torque.

- Driver: `LEDC_TIMER_2 / LEDC_CHANNEL_4 / LEDC_TIMER_8_BIT`, 333 Hz fixed
- Duty formula: `strength_pct × 128 / 100` (100% → 128/255 → 50% duty)
- API: `vibrator_on()`, `vibrator_off()`, `vibrator_pulse(ms)`, `vibrator_burst(count, on_ms, gap_ms)`
- Haptic events: BT Lookout hit = `vibrator_burst(3, 1000, 500)`, Deauth launch = `vibrator_pulse(3000)`, BT Locator = continuous scaled by RSSI, Fox Hunt = **150 ms pulses at 100% strength** at variable rate (1 pulse/1.5 s near squelch → 5/s at strong signal). Fixed at 100% strength so ERM motor reliably reaches felt speed within the pulse.

**JST connector:** 1.25mm pitch (not 1.0mm — ordered wrong once, 1.0mm is too small and won't fit).

### LVGL Label Strings

**Never use Unicode characters** in LVGL label strings. The Montserrat bitmap fonts cover only basic Latin. Em dashes, curly quotes, ellipsis etc. render as solid block glyphs. Use plain ASCII substitutes. Only `LV_SYMBOL_*` macros are safe (they use the private-use area of the icon font).

### RF Hat Task Priorities

**All RF hat scan tasks must run at priority 2.** The main LVGL/WDT task runs at priority 1. A priority-5 task doing busy-wait (e.g. `esp_rom_delay_us × N channels`) starves main and triggers the task watchdog in ~8 seconds. `vTaskDelay(pdMS_TO_TICKS(1))` = 0 ticks at 100 Hz FreeRTOS — use `pdMS_TO_TICKS(20)` minimum in scan loops.

### TV-B-Gone Repeat Count

**Send 1 burst per brand, not multiple.** Multiple repeats cause TVs to toggle off then back ON — device ends up in the same state. Even at 45ms inter-repeat gap (below NEC de-bounce threshold of ~108ms), multiple TVs still recognized each repeat as a distinct command. `TVBG_REPEATS = 1` is correct.

### LVGL Persistent Nav Buttons (Hold-to-Scroll)

Hold-to-scroll requires `LV_EVENT_LONG_PRESSED_REPEAT` on a button that stays alive for the full hold duration. `lv_obj_clean()` deletes the button after first repeat, breaking the long-press state machine. Solution: store nav buttons in static globals, create once (guard with `if (nav_up == NULL)`), use selective delete loop that skips `LV_OBJ_FLAG_FLOATING` children instead of `lv_obj_clean()`, and call `lv_obj_move_foreground()` on nav buttons at end of each refresh.

### BLE Scan File Format (btsc_*.json)

Filename: `btsc_%05u_HHMMSS_LAT_LON_label.json` (with GPS) or `btsc_%05u_HHMMSS_label.json` (no GPS).  
`lw_file_info_t.filename` is `char[80]` — do NOT shrink. Path buffers in List Wizard are `char[120]`.

JSON parse: all fields written with `": "` (space after colon). `lw_parse_meta` searches `"\"key\": "` — NOT `"\"key\":"`. Mismatch = blank metadata in List Wizard.

### LVGL Custom Font (FA Icons)

Font file: `ESP32C5/main/lv_extra_symbols.c`. Generation command is in the file header comment.  
Two mutable wrapper fonts in main.c: `g_font_icon14` and `g_font_icon16` (memcopy of Montserrat + `.fallback = &lv_extra_symbols`). Labels mixing ASCII + FA icons must use `&g_font_iconXX`, not raw Montserrat.  
TTF source files: `/home/dev/projects/fonts/fa-solid-900.ttf` and `fa-brands-400.ttf`.

---

## 8. Settings Screen Architecture

```
Settings
├── Compromised Data    — WiFi credential monitor
├── Timing             — WiFi scan dwell + BT scan duration + GATT timeout (combined popup)
├── Download Mode      — reboot into bootloader
├── Screen             — screen timeout + brightness overlay (combined popup)
├── SD Card            — provision / file tree / free space
│   ├── Validate & Provision
│   ├── Free Space
│   ├── File Tree
│   ├── New Folder
│   ├── Delete File
│   ├── Remount SD Card  — unmount + retry 20/10/5 MHz without physical eject (v2.4.24)
│   └── Format SD Card
├── GPS Info           — live fix status; Set Position manual editor
├── Hardware Options   — sub-menu
│   ├── Power Mode     — Normal / Max TX power; persisted NVS
│   └── NM-RF-HAT     — Enable / Disable; tiles appear/disappear immediately
├── Data Transfer      — sub-menu
│   ├── AP File Server — TheLab AP (SSID: TheLab, PW: "Do not touch!", 192.168.4.1)
│   ├── WiFi Client    — join existing network, serve /sdcard/ on DHCP IP; eye button on PSK field
│   └── Wardrive Upload — WiGLE + WDG Wars HTTPS upload
└── Vibrator Test      — ON/OFF + strength slider (10-100%); NVS-persisted strength
```

**Old wrong path:** "Settings → NM-RF-HAT" — this does not exist. Correct path is "Settings → Hardware Options → NM-RF-HAT".

---

## 9. NVS Key Reference

Namespace `settings`:

| Key | Type | Description |
|-----|------|-------------|
| `gps_lat_i` | i32 | Latitude × 10⁶ (micro-degrees) |
| `gps_lon_i` | i32 | Longitude × 10⁶ |
| `gps_alt_i` | i32 | Altitude × 10 (deci-metres) |
| `gatt_tmo` | u32 | GATT connect timeout ms (default 30000) |
| `bt_scan_dur` | u32 | BT scan duration seconds (default 10) |
| `RF_HAT` | u8 | 1 = NM-RF-HAT enabled |
| `btsc_ctr` | u32 | BT scan file counter (monotonic) |
| `tx_power` | u8 | 0 = Normal, 1 = Max |

Namespace `touch_cal`: `x_min`, `x_max`, `y_min`, `y_max`, `invert_x`, `invert_y`, `swap_xy`, `magic` (0xCA15).

---

## 10. Feature Changelog — v2.4.3 → v2.4.28

Key features added since the previous HERMES version:

| Version | Feature |
|---------|---------|
| v2.4.6–v2.4.13 | CC1101 TPMS Monitor (315/433 MHz, Schrader OOK decode, MCSM1 stay-in-RX fix, FSK presets); scrollable 20-sensor grid; CC1101 Band Scope; Z-Wave Scout |
| v2.4.14–v2.4.20 | nRF24 jammer duty-cycle speedup (1.6%→33%); multi-packet sniffer accumulation; web-flasher Stable/Dev channel selector; TPMS nav-crash fixes (timer ordering, log_fp race); TPMS scroll direction fix |
| v2.4.21 | TPMS scroll reveals newest sensor at bottom (not top) |
| v2.4.22 | **NTAG213/215/216 full page dump** — GET_VERSION protocol ID, ntag_read_all(), ntag_write_page(), ntag_clone_to_blank(); rfid_manager_read_card_data() / rfid_manager_clone_ntag(); Scan & Read "Read All" button; **Clone/Write screen** implemented (was stub); Flipper .nfc NTAG215/216 import fixed; rfid_storage page_count save/load; pn532_target.c GET_VERSION now protocol-specific |
| v2.4.23 | Fix stack overflow crash (rfid_card_t ~5.7 KB on task stack) when reading MIFARE Classic; rfid_read and rfid_clone tasks stack 4096→6144 bytes; rfid_manager_clone_ntag uses PSRAM for blank card struct |
| v2.4.24 | **SD Remount**: Settings → SD Card → Remount SD Card — unmounts and retries 20/10/5 MHz without physical eject |
| v2.4.25 | Tile height 87→74 px globally; CC1101 menu 3 pages of 6 → 2 pages of 9; SD Card and WiFi menu padding fixed (no longer scrolls) |
| v2.4.26 | All tile-based menus standardized: pad=4, gap=4, CENTER align, SCROLLABLE cleared |
| v2.4.27 | **Fox Hunt** — CC1101 (tunable 300-928 MHz, RSSI+squelch, bug-hunter haptic, preset+fine-tune buttons); nRF24 (carrier-detect rate, channel ±1/±10); RF433 (GPIO9 edge count, ISR-based); Band Scope SDR freq marker (yellow line at center freq, drag to move, Hunt button in row with Start/Stop); CC1101/nRF24/RF433 menus updated with Fox Hunt tile |
| v2.4.28 | Fix: Unicode status chars (●▲★) → ASCII (--/>>/>>>); Band Scope line restricted to spectrum section only (no waterfall ghosting); hunt_btn always visible in action row; marker initialized at center freq on open |
| v2.4.29 | Fix: CC1101 Fox Hunt stuck at -98 dBm after Band Scope→Hunt (band scope task race with apply_preset); deferred CC1101 setup to first timer tick; Hunt button block char → plain text |
| v2.4.30 | **CC1101 Crystal Calibration**: HW Test Crystal Calibration panel — [Set Offset] numeric kHz popup, [CAL TX 433] continuous OOK carrier. Initial implementation used fixed Hz offset. |
| v2.4.37 | **PPM-based crystal calibration**: Changed from additive Hz to multiplicative PPM. `g_cc1101_freq_offset_millippm` (int32, ppm×1000). `cc1101_freq_cal(f) = f × (1 + millippm/1e9)` — scales correctly to 315/433/868/915 MHz. NVS key changed `"cc1101_off"` (Hz) → `"cc1101_ppm"` (millippm). Input range ±130 kHz at 433 = ±300 ppm. Display shows both ppm and kHz@433. Jammer frequencies also calibrated. |
| v2.4.37 | **CC1101 Jammer frequency sweep**: 6-step sweep across 433.1-434.1 MHz using continuous OOK carrier (PKTCTRL0=0x02 infinite, FIFO 0xFF fill). Band selector buttons added (315/433/868/915). |
| v2.4.41 | **Jammer modulation**: switched to CC1101 internal random PRBS TX mode (`PKTCTRL0=0x0A`, DATA_FORMAT=10). 250 kbps data rate → ~250 kHz OOK noise bandwidth per hop. |
| v2.4.42 | **Jammer 433N narrow sweep**: 5th band (433N) covers 433.840-434.005 MHz in 12 steps at 15 kHz. All sweep tables expanded to 12 steps. Timer 62ms/step. Default: 433N. |
| v2.4.43 | Jammer: 31ms/step (2× faster). |
| v2.4.44 | **Jammer 2-FSK**: MDMCFG2=0x00 (2-FSK), DEVIATN=0x77 (±381 kHz), FREND0=0x10 (FSK PA). Carson BW ≈1 MHz per hop — entire 433N range covered by one hop. Default: 433N + 2-FSK. |
| v2.4.45 | **OOK Protocol Decoders**: (1) **CC1101 Alarm Sensor** — EV1527 decoder at 315/433 MHz OOK. `ook_decode_ev1527()` extracts 24-bit address + 4-bit channel from preamble+sync+28 data bits (T≈350 µs). Background task runs `cc1101_raw_capture()` 600 ms windows; scrollable live sensor list with RSSI, count, age. (2) **CC1101 Weather Station** — Fine Offset decoder at 433.92 MHz OOK. `ook_decode_fineoffset()` / `ook_crc8_fo()` decode 40-bit PWM (500 µs preamble, 2 ms sync gap), CRC-8/POLY=0x31. Extracts temp/humidity/battery/ID. 800 ms capture windows. (3) **RF433 OOK Scan** — same EV1527 decoder using R4A_433 superheterodyne GPIO9 ISR capture (`s_rf433_ook_cap_isr` IRAM_ATTR, 2048-sample ring buffer). New 6th tile in RF433 menu. All shared alarm state (`s_ook_alarms[]`, `s_ook_alarm_count`) is declared early to avoid forward-reference in cleanup code. |
| v2.4.46 | **Fox Hunt haptic fix (all 3 radios)**: Root cause — 40 ms pulse duration is below ERM motor spin-up time (~80 ms minimum to reach felt speed); haptic strength was also scaled down to 10% at weak signals (motor inert at 10% duty). Fix: all three fox hunts now always fire at **100% strength** + **150 ms pulse**. Rate still scales with signal (CC1101: counter-based 50 ms timer, period 30→2 ticks; RF433: same pattern on 100 ms timer, 15→2 ticks; nRF24: fires every 100 ms tick). **Vibrator save/restore**: nRF24 and RF433 fox hunts had `(void)saved_vib` — captured `g_vibtest_strength_pct` but never restored. Fixed with `s_n24fox_saved_vib_pct` and `s_rf433_fox_saved_vib_pct` static vars, restored in cleanup. **RF433 Jammer modulation**: was `gpio_set_level HIGH` = pure CW carrier (single frequency). Now esp_timer periodic at 500 µs toggles GPIO8 → 1 kHz OOK modulation sidebands around 433.92 MHz. **RF433 OOK Scan**: replaced em-dash (U+2014) in status label with ASCII hyphen (U+2014 not in lv_font_montserrat_12 → block char). |

| v2.6.47 | **NFC/RFID improvements (v2.6.46→v2.6.47 dev cycle)**: (1) **Auto-read**: `s_rfid_autoread_tmr` (LVGL 1-shot, 1000 ms) fires after first stable card detection; calls `s_rfid_read_all_cb(NULL)`. Cancelled if card leaves field or read already in progress. (2) **NTAG213 auto-upgrade**: `ntag_read_all()` probes page 16 after reading 16 pages. If `ntag_read_pages(16)` returns RFID_OK → genuine NTAG213; upgrades `card->protocol`, `card->page_count=45`, continues reading pages 16-44. If NAK → confirmed 16-page Ultralight. Bypasses broken GET_VERSION (PN532 fw1.6 returns ERROR FRAME 7F 81 for 0x60 command). (3) **NDEF TLV decoder** (`s_ndef_extract()`): parses pages 4..page_count for TLV 0x03; decodes Well-Known URI ('U', 35-prefix table) and Text ('T') records; displayed in blue on Scan & Read screen. Bounds check relaxed for 0x03 TLV type to handle NTAG misidentified as Ultralight. (4) **Poll overwrite fix**: `s_rfid_scan_lvgl_cb` preserves `blocks[]` when same UID re-polled — previously overwrote all block data every 500ms poll cycle causing Clone to silently fail (has_pages=false). Same-UID: update only identity fields; different UID: full replace. (5) **Clone compatibility check**: `rfid_manager_clone_ntag()` checks `blank->sak != 0x00` after scanning target — MIFARE Classic (SAK=0x08) rejected with RFID_ERR_NOT_SUPPORTED and clear UI message before any writes attempted. (6) **PN532 ERROR FRAME silenced**: `pn532_read_response()` detects frame `LEN=0x01 LCS=0xFF data=0x7F DCS=0x81` (PN532 "command not supported") and logs at LOGD instead of LOGW — was firing every 300ms while card present. (7) **Green Read button**: turns `0x1B5E20` when card detected, resets to dark when card removed. Type label updated after read to reflect auto-upgrade. |

**Architecture notes for new features:**
- **Fox Hunt timers** are static file-scope (`s_fox_tmr`, `s_n24fox_tmr`, `s_rf433_fox_tmr`). They are cleaned up at the TOP of `show_cc1101_screen()`, `show_nrf24_screen()`, and `show_rf433_menu_screen()` respectively — not in `reset_function_page_children()`.
- **RF433 ISR** (`s_rf433_fox_isr`) uses `IRAM_ATTR` and `gpio_isr_handler_add(RF_HAT_RF433_RX_GPIO)`. Removed in `show_rf433_menu_screen()` cleanup and also in the fox hunt screen open guard.
- **Band Scope marker**: `cc1101_bs_ctx_t` now has `tap_freq_mhz`, `canvas_h`, `marker_set`, `hunt_btn` fields. Line drawn only in `y=0..CC1101_BS_SPEC_H-1` to prevent waterfall ghosting.
- **ntag.c / ntag.h**: new component under `ESP32C5/components/rfid/src/hf/`. Follow mifare_classic.c style.
- **LVGL status strings**: NEVER use Unicode (●▲★ etc.) — only LV_SYMBOL_* or plain ASCII. Montserrat bitmap fonts only cover basic Latin. Also avoid em-dash (U+2014) in any label — use ASCII hyphen instead.
- **OOK decoder shared state**: `s_ook_alarms[]` (max 20 entries, `ook_alarm_entry_t`), `s_ook_alarm_count`, and `ook_age_str()` are shared by CC1101 Alarm Sensor and RF433 OOK Scan. Declare early (before `show_cc1101_screen()` cleanup code references them). Timer callbacks use `lv_async_call` to update LVGL from task context.
- **Fox hunt haptic pattern**: All three fox hunts must use `g_vibtest_strength_pct = 100; vibrator_pulse(150)` — never scale strength down. Scale only pulse rate (counter-based timer ticks). Save/restore `g_vibtest_strength_pct` on open/exit using a static `s_Xfox_saved_vib_pct` variable (not a local — local is freed before the exit cleanup runs).
- **RF433 jammer modulation**: `rf433_hat_jam_start()` in `rf_hat/src/rf433_hat.c` creates a `s_jam_tmr` esp_timer periodic at 500 µs; `s_jam_timer_cb` toggles GPIO8. Stop calls `esp_timer_stop(s_jam_tmr)` then `gpio_set_level LOW`. Timer is created once and reused (create-once pattern).
- **NTAG213 auto-upgrade**: `ntag_read_all()` calls `ntag_read_pages(16, probe)` after reading 16 pages. RFID_OK → NTAG213 (upgrades protocol + page_count=45, reads pages 16-44). RFID_ERR_NAK → confirmed genuine 16-page Ultralight. Never call GET_VERSION for type detection on this PN532 — it always returns ERROR FRAME 7F 81 (fw1.6 limitation).
- **Poll overwrite prevention**: `s_rfid_scan_lvgl_cb` compares `ev->card.uid` to `s_rfid_last_card->uid`. Same UID → preserve `blocks[]`, only refresh identity fields. Different UID → full struct replace. Without this, the 500ms background poll erases all Read All block data and Clone silently fails (`has_pages=false`).
- **PN532 ERROR FRAME detection**: `pn532_read_response()` checks `raw[4]==0x01 && raw[5]==0xFF && raw[6]==0x7F` — this is the PN532 "syntax error / command unsupported" frame. Log at LOGD (not LOGW) since it fires every poll cycle for GET_VERSION on fw1.6.
- **Clone target compatibility**: `rfid_manager_clone_ntag()` checks `blank->sak != 0x00` after scanning. MIFARE Classic (SAK=0x08) returns RFID_ERR_NOT_SUPPORTED with message before any write attempt. Only SAK=0x00 (NTAG/Ultralight) targets allowed.

---

## 11. Known Hardware Issues / Permanent Workarounds

1. **Battery ADC disabled permanently:** `if (false && init_battery_adc()...)` — GPIO 6 conflict with SPI SCK.
2. **ESP32-C5 PHY hang (IDF-15338):** Manually patched in `/home/dev/esp/esp-idf/components/esp_phy/src/phy_init.c` ~line 948. If `idf.py fullclean` or IDF submodule update, verify patch is still present or `esp_wifi_start()` hangs.
3. **`ft6336.c/h`:** Old capacitive touch driver kept on disk but not compiled (removed from CMakeLists.txt). Ignore it.
4. **WiFi/BLE radio:** Single shared radio. Zigbee Scout requires both WiFi and BLE stopped before enabling 802.15.4.
5. **PN532 on NM-RF-HAT:** Shorter read range than a dedicated PN532 breakout board — hardware limitation of the RF-HAT PCB antenna geometry. Cards need to nearly touch the antenna.
6. **PN532 firmware v1.6 — known limitations (not upgradeable):** NXP does not distribute PN532 firmware update tools or binaries publicly. The chip is soldered on-board. Two commands always return ERROR FRAME `7F 81` on this firmware:
   - `RFConfiguration(0x0A)` — analog sensitivity settings. **Workaround**: removed the call; default 38 dB gain is sufficient.
   - `InDataExchange(GET_VERSION=0x60)` — NXP proprietary NTAG type ID. **Workaround**: probe page 16 after reading 16 pages — NTAG213 returns data, genuine 16-page Ultralight returns NAK.
   - Serial log `scan: GET_VERSION failed — keeping heuristic type MIFARE Ultralight` is **expected and normal**. The auto-upgrade path handles NTAG identification correctly without GET_VERSION.
7. **Battery ADC on GPIO 6:** Permanently disabled. Calling `adc_oneshot_config_channel` on GPIO 6 reconfigures it away from SPI, killing SPI clock.
7. **Wardrive Upload placeholder:** Settings → Data Transfer → Wardrive Upload is implemented and working (WiGLE + WDG Wars HTTPS). The in-code comment saying "placeholder" is outdated.

---

## 11. 3D Printable Cases

Three community enclosures for the full NM-CYD-C5 + NM-RF-HAT stack:

| Case | URL | Notes |
|------|-----|-------|
| MakerWorld (GPS + 18650) | https://makerworld.com/en/models/2670158-case-for-nm-rf-hat-cyd2usb-atgm336h-18650 | DIP switches internal — need to open case to switch modules |
| Printables (magnetic lid) | https://www.printables.com/model/1638712-cyd-nm-rf-hat-enclosure-case-magnetic-6x2mm-magnet | 6×2mm magnets; DIP switches internal |
| Thingiverse (community favorite) | https://www.thingiverse.com/thing:7305463 | DIP switches accessible from exterior |

**DIP switch relocation:** For cases with internal DIP switches, solder extension wires to switch pads and mount a panel-mount DIP switch on the case exterior.

**Immediate hardware TODO:** Jim needs to start printing a CYM case. Prefer the Thingiverse community-favorite enclosure first if exterior DIP access matters; otherwise evaluate the magnetic-lid Printables case or MakerWorld GPS/18650 case depending on battery/GPS plans. Before committing to a print, verify NM-CYD-C5 + NM-RF-HAT stack height, touch/display opening alignment, USB-C access, SD access, antenna clearance, and whether external DIP access or relocated DIP wiring is required.

---

## 12. Next Feature Idea — ESP-NOW Listener / Debugger

Jim wants to add an **ESP-NOW debugger/listener/controller** under the WiFi feature set so CYM can detect ESP-NOW traffic and collect useful intelligence. Treat this as a defensive/research/debug feature, not an injection/replay feature.

### Concept

ESP-NOW uses 802.11 vendor-specific action frames. CYM should provide a passive listener mode that can identify likely ESP-NOW frames, maintain a device/session table, and export observations for later analysis.

Useful metadata even without keys:
- source MAC and destination/broadcast MAC
- RSSI, channel, timestamp, packet count, packet rate
- frame length/range and sequence behavior
- Espressif/vendor OUI hints
- plaintext-vs-encrypted/opaque payload guess
- broadcast discovery vs unicast peer traffic indicators

### Proposed UI modes

- **Channel Hopper:** scan channels 1-13 with configurable dwell time; best for discovery.
- **Fixed Channel:** lock to one channel for deeper capture; best once ESP-NOW activity is found.
- **Device Table:** MAC, label, channel, RSSI, first seen, last seen, packet count, frame lengths.
- **Live Packet Log:** timestamp, channel, RSSI, src/dst, length, short hex preview when visible.
- **Export:** save CSV/JSON captures under `/sdcard/lab/espnow/` and add that directory to `SD_ITEMS` when implemented.
- **Known Device Labels:** allow user labels for MACs via NVS or SD-side config.

### Known-key decode feasibility

ESP-NOW does **not** negotiate a new ephemeral key per connection like TLS. It uses configured keys:
- PMK: Primary Master Key set via `esp_now_set_pmk()`
- LMK: per-peer Local Master Key in `esp_now_peer_info_t.lmk`
- encrypted unicast traffic uses the LMK
- broadcast ESP-NOW is not encrypted

If Jim knows the relevant per-peer LMK, CYM can plausibly decode traffic for that known peer relationship. PMK alone is probably not enough for passive decode; the LMK is the traffic key.

Recommended staged implementation:
1. **Passive Detect:** promiscuous/channel-hop identification and metadata only.
2. **Known-Key Profiles:** store peer MAC, LMK, optional PMK, label, expected protocol magic.
3. **Native ESP-NOW Receive/Decode:** when CYM is on the right channel and registered as a peer, let ESP-IDF decrypt frames addressed to CYM or broadcast/plaintext frames.
4. **Advanced Passive Decrypt:** later, parse raw 802.11/CCMP fields and attempt passive decrypt with known LMK. This is more complex because firmware must handle frame parsing, nonce/AAD/MIC, replay counters, and failure reporting itself.

### Radio architecture caveat

The ESP32-C5 has one shared WiFi radio. If CYM is connected to an AP, the radio is effectively pinned to that AP channel. For real cross-channel ESP-NOW discovery, use a dedicated listener mode that suspends/disconnects normal WiFi features while hopping channels. If WiFi stays connected, only expect to observe ESP-NOW on the current AP channel.

### Safety / scope

Start with passive detection and known-key decode for Jim's own devices. Do not implement injection, replay, or unauthorized traffic manipulation unless Jim explicitly scopes and authorizes that work later.

---

## 13. Development Workflow Summary

```bash
# 1. Bump version FIRST
nano ESP32C5/CMakeLists.txt   # increment last digit of PROJECT_VER

# 2. Make code changes in ESP32C5/main/main.c (and companion files)

# 3. Build
cd ESP32C5
source /home/dev/esp/esp-idf/export.sh
idf.py build

# 4. Commit and push (binaries auto-copied by CMakeLists.txt POST_BUILD)
git add ESP32C5/CMakeLists.txt ESP32C5/binaries-esp32c5/ ESP32C5/main/main.c [etc]
git commit -m "v2.4.X: description of change"
git push origin Jimgat_Dev

# 5. For releases only:
git checkout main
git merge --no-ff Jimgat_Dev -m "Release vX.Y.Z — summary"
git push origin main
git checkout Jimgat_Dev
```

**Never use `git push --force`.** Never run `idf.py flash`. Never bump MINOR/MAJOR version without user approval.

---

## 14. Secret

There is one undocumented easter egg. Do not mention it in commits, README, release notes, or any user-facing text. It is intentionally hidden. If you encounter `vibrator_pulse(55)` on a beat in a disco or party animation context — that is it. Leave it alone and keep it out of all documentation.

---

## 15. Contact / Attribution

**Developer:** Jim Gatwood (jim.gatwood@gmail.com)  
**Project:** https://github.com/JimGat/CYM-NM28C5  
**Board:** NM-CYD-C5 by RockBase-iot / NerdMiner  
**For:** Security research and education only. Authorized use only.

---

*This file is maintained for AI agent continuity. Update it when major decisions change.*
