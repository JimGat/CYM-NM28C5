# CYM-NM28C5 — AI Project Brief

**Purpose of this file:** Complete context document for AI agents (Claude, ChatGPT, Hermes, or any LLM) working on this project. Read this before touching any code. It covers every major decision made, the reasoning behind it, known hazards, and how everything fits together.

**Last updated:** 2026-06-02, v2.4.44

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

**Flash workflow:** User flashes via **ESPConnect** web flasher (Chrome/Edge, WebSerial):
https://thelastoutpostworkshop.github.io/ESPConnect/

Flash addresses:
- `0x2000` — `bootloader.bin`
- `0x8000` — `partition-table.bin`
- `0x10000` — `CYM-NM28C5.bin`

**NEVER run `idf.py -p /dev/ttyACM0 flash`.** User does not have local USB flash set up. Always commit binaries and push to GitHub.

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
- Haptic events: BT Lookout hit = `vibrator_burst(3, 1000, 500)`, Deauth launch = `vibrator_pulse(3000)`, BT Locator = continuous scaled by RSSI, Fox Hunt = 50 ms pulses at variable rate (2 s at squelch → 100 ms at 38 dB above)

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

**Architecture notes for new features:**
- **Fox Hunt timers** are static file-scope (`s_fox_tmr`, `s_n24fox_tmr`, `s_rf433_fox_tmr`). They are cleaned up at the TOP of `show_cc1101_screen()`, `show_nrf24_screen()`, and `show_rf433_menu_screen()` respectively — not in `reset_function_page_children()`.
- **RF433 ISR** (`s_rf433_fox_isr`) uses `IRAM_ATTR` and `gpio_isr_handler_add(RF_HAT_RF433_RX_GPIO)`. Removed in `show_rf433_menu_screen()` cleanup and also in the fox hunt screen open guard.
- **Band Scope marker**: `cc1101_bs_ctx_t` now has `tap_freq_mhz`, `canvas_h`, `marker_set`, `hunt_btn` fields. Line drawn only in `y=0..CC1101_BS_SPEC_H-1` to prevent waterfall ghosting.
- **ntag.c / ntag.h**: new component under `ESP32C5/components/rfid/src/hf/`. Follow mifare_classic.c style.
- **LVGL status strings**: NEVER use Unicode (●▲★ etc.) — only LV_SYMBOL_* or plain ASCII. Montserrat bitmap fonts only cover basic Latin.

---

## 11. Known Hardware Issues / Permanent Workarounds

1. **Battery ADC disabled permanently:** `if (false && init_battery_adc()...)` — GPIO 6 conflict with SPI SCK.
2. **ESP32-C5 PHY hang (IDF-15338):** Manually patched in `/home/dev/esp/esp-idf/components/esp_phy/src/phy_init.c` ~line 948. If `idf.py fullclean` or IDF submodule update, verify patch is still present or `esp_wifi_start()` hangs.
3. **`ft6336.c/h`:** Old capacitive touch driver kept on disk but not compiled (removed from CMakeLists.txt). Ignore it.
4. **WiFi/BLE radio:** Single shared radio. Zigbee Scout requires both WiFi and BLE stopped before enabling 802.15.4.
5. **PN532 on NM-RF-HAT:** Shorter read range than a dedicated PN532 breakout board — hardware limitation of the RF-HAT form factor. Cards need to nearly touch the antenna.
6. **Battery ADC on GPIO 6:** Permanently disabled. Calling `adc_oneshot_config_channel` on GPIO 6 reconfigures it away from SPI, killing SPI clock.
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

---

## 12. Development Workflow Summary

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

## 13. Secret

There is one undocumented easter egg. Do not mention it in commits, README, release notes, or any user-facing text. It is intentionally hidden. If you encounter `vibrator_pulse(55)` on a beat in a disco or party animation context — that is it. Leave it alone and keep it out of all documentation.

---

## 14. Contact / Attribution

**Developer:** Jim Gatwood (jim.gatwood@gmail.com)  
**Project:** https://github.com/JimGat/CYM-NM28C5  
**Board:** NM-CYD-C5 by RockBase-iot / NerdMiner  
**For:** Security research and education only. Authorized use only.

---

*This file is maintained for AI agent continuity. Update it when major decisions change.*
