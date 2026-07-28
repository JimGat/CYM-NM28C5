# CYM-NM28C5 — Firmware Memory Budget

> **Living reference.** The "Current build metrics" table below is rewritten automatically
> by `ESP32C5/tools/update_memory_map.py` after every successful `idf.py build`.
> Commit both the firmware binary **and** this file together so the numbers in the repo
> always match the binary in `binaries-esp32c5/`.
>
> The narrative sections (§2 onward) were written by @birolt29 from a from-scratch map
> analysis of v2.10.31. Update them manually when the architecture changes significantly.

---

## 1. Current build metrics  *(auto-updated — do not edit by hand)*

<!-- MEMORY_METRICS_START -->
| Metric | Value |
|--------|-------|
| Version | v2.11.17 |
| Build date | 2026-07-28 |
| .iram0.text | 138,892 B (135.6 KB) |
| .dram0.data | 23,841 B (23.3 KB) |
| .dram0.bss  (internal) | 125,224 B (122.3 KB) |
| .ext_ram.bss  (PSRAM) | 149,032 B (145.5 KB) |
| App binary size | 2,991,024 B (2920.9 KB) |
<!-- MEMORY_METRICS_END -->

### Top internal BSS consumers  *(auto-updated)*

<!-- BSS_TABLE_START -->
| Library / object | Internal BSS |
|-----------------|-------------|
| `libmain.a` | 89,185 B (87.1 KB) |
| `libnet80211.a` | 13,559 B (13.2 KB) |
| `librf_hat.a` | 11,352 B (11.1 KB) |
| `librfid.a` | 5,032 B (4.9 KB) |
| `libmesh.a` | 3,955 B (3.9 KB) |
| `liblwip.a` | 3,908 B (3.8 KB) |
| `libieee802154.a` | 3,590 B (3.5 KB) |
| `libpp.a` | 3,467 B (3.4 KB) |
| `libwifi_scanner.a` | 2,400 B (2.3 KB) |
| `libfreertos.a` | 2,148 B (2.1 KB) |
| `libwifi_attacks.a` | 1,935 B (1.9 KB) |
| `libwpa_supplicant.a` | 1,722 B (1.7 KB) |
| `liblvgl__lvgl.a` | 840 B |
| `libesp_libc.a` | 508 B |
| `libtfpsacrypto.a` | 428 B |
<!-- BSS_TABLE_END -->

---

## 2. Executive summary  *(@birolt29, baseline v2.10.31)*

- **SoC reality:** ESP32-C5 has 384 KB HP SRAM, but this firmware links **~305 KB of it
  statically** (IRAM code + DRAM data/bss), leaving only ~8.7 KB of linker heap tail.
  The runtime internal heap is ~15–20 KB assembled from scattered regions, and drops to
  **~7 KB after BLE init**. That ~7 KB floor is the number behind every DMA starvation
  symptom (BLE scan finds 1 device, SD `allocate_dma_buf` fails, LCD priv-TX-buffer freeze).

- **Who eats internal SRAM (measured from the map):**
  - `.iram0.text` = **140 KB** — Wi-Fi/PHY/HW code in IRAM via `*_IRAM_OPT` flags.
  - `.dram0.bss` = **148 KB** — of which **~97 KB is the application** (`libmain`);
    only ~1 KB is the Wi-Fi/BT libraries (they allocate at runtime).
  - `.dram0.data` = 24 KB.
  - `.ext_ram.bss` = **101 KB already in PSRAM** (25 × `EXT_RAM_BSS_ATTR` in the app).

- **Key insight:** The internal-SRAM / DMA crunch is dominated by the **application's own
  static globals** (~97 KB in internal RAM), not the Wi-Fi/BT stack or the toolchain.
  Moving ISR-safe globals to PSRAM is the highest-leverage, lowest-risk fix.

- **Board hard limits (unchangeable):** no USB-OTG, CC1101+nRF24 share FPC pins
  (one at a time), LCD has no independent reset, PSRAM is Quad @ 40 MHz.

---

## 3. Static internal-SRAM budget  *(measured from map, v2.10.31 baseline)*

```
HP SRAM total (datasheet)                         384 KB
Linker sram_seg  0x40800000 .. +0x4e5a0        ≈ 314 KB usable
  ├─ .iram0.text                                140,234 B  (~137 KB)  Wi-Fi/PHY/HW/FreeRTOS IRAM
  ├─ .dram0.data                                 23,609 B
  ├─ .dram0.bss   0x40828040 .. 0x4084c388      148,296 B  (~145 KB)
  │     └─ _bt_controller_bss  0x4084c248.. +320 B         (BT ctrl static is TINY)
  └─ _heap_start  0x4084c390                               → only ~8.7 KB tail before sram end
Runtime internal heap (from device logs):
  DMA-capable free  ~19.5 KB (idle)  →  ~7 KB (after BLE init)  →  fragmented
```

### Internal DRAM by library  *(v2.10.31)*

| Library | Internal DRAM (data+bss) | Note |
|---------|--------------------------|------|
| **libmain (the app)** | **~98.9 KB** | **dominant consumer** |
| libspi_flash | 8.2 KB | flash driver statics |
| librf_hat | 5.3 KB | IR/RF HAT |
| librfid | 5.1 KB | RC522 |
| libieee802154 | 3.6 KB | 802.15.4 (Zigbee scout) |
| Wi-Fi/BT libs combined | **~1 KB static** | they use runtime heap, not static BSS |

---

## 4. App globals — reclaim table  *(ISR/DMA safety checked per symbol)*

Selection rule: a buffer must stay in internal RAM only if it is written by a **hardware ISR**
or handed directly to a **DMA engine** (Wi-Fi TX/RX descriptors, SDMMC, SPI-DMA, RMT-DMA,
UART-DMA ring). Wi-Fi promisc / ESP-NOW / NimBLE callbacks run in **task context with cache
enabled** — their target arrays are PSRAM-safe.

| Symbol | Bytes | ISR/DMA? | PSRAM? | Status |
|--------|------:|----------|--------|--------|
| `assoc_ie_buf` | 8,272 | Passed to Wi-Fi driver | **Verify** | Internal (keep until verified) |
| `s_rf433_ook_buf` | 8,192 | RMT decode buffer | **Verify** | Internal (keep until verified) |
| `wdp_seen_networks` | 6,400 | Sniffer RX (task ctx) | YES | ✅ **Moved v2.10.32** |
| `bt_devices` | 6,400 | NimBLE GAP (task ctx) | YES | ✅ **Moved v2.10.32** |
| IR stores (`s_ur_sig`/`s_last_ir_signal`/`s_ir_replay_sig`) | 4,140 ×3 | IR store (RMT symbols separate) | Likely | Internal — verify not RMT DMA buf |
| `s_rfid_entries` | 3,920 | RC522 poll (task) | YES | ✅ **Moved v2.10.32** |
| `s_spoof_list` | 2,496 | UI/task | YES | ✅ **Moved v2.10.32** |
| `deauth_monitor_attacks` | 2,400 | task | YES | ✅ **Moved v2.10.32** |
| `espnow_devices` | 2,304 | ESP-NOW recv (task ctx) | YES | ✅ **Moved v2.10.32** |
| `s_rf433_replay_sig` | 2,088 | RF433 store | Likely | Internal — verify |
| Name/remote tables (IR/RF433/UR) ×~8 | 1,500–2,000 ea | UI strings | YES | Candidate — next pass |
| `wdp_ducb_channels` | 1,312 | task | YES | ✅ **Moved v2.10.32** |
| `wardrive_gps_buffer` / `gps_rx_buffer` | 1,024 ×2 | UART RX copy (task) | YES | Candidate — next pass |
| **Moved total (v2.10.32)** | **~22.4 KB** | | | **Internal .bss 98.9 → 76.5 KB** |
| **Remaining candidate** | **~40 KB** | | | Next pass when needed |

---

## 5. Fix history

| Version | Fix | Internal BSS Δ | Scan devices |
|---------|-----|---------------|-------------|
| v2.10.29 | Baseline before BLE parity work | ~76 KB | 10–15 |
| v2.10.31 | BLE Phases 2–5 (GATT interact / HID / Clone / MITM) | +22.4 KB → ~99 KB | ~1 ← **regression** |
| v2.10.32 | 7 arrays → PSRAM + ATT_MAX_PREP_ENTRIES 64→4 (@birolt29) | −22.4 KB → ~76 KB | 33 ✅ |

---

## 6. sdkconfig settings that affect memory

```ini
# Memory allocation
CONFIG_SPIRAM=y
CONFIG_SPIRAM_USE_MALLOC=y                   # PSRAM in malloc pool above 16 KB threshold
CONFIG_SPIRAM_ALLOW_BSS_SEG_EXTERNAL_MEMORY=y  # enables EXT_RAM_BSS_ATTR
CONFIG_SPIRAM_MALLOC_RESERVE_INTERNAL=61440  # ~60 KB reserved for DMA/ISR callers
CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL=16384    # allocs < 16 KB stay internal unless capped

# IRAM (each =y costs ~tens of KB of shared SRAM)
CONFIG_ESP_WIFI_IRAM_OPT=y
CONFIG_ESP_WIFI_RX_IRAM_OPT=y
CONFIG_ESP_WIFI_EXTRA_IRAM_OPT=y
CONFIG_ESP_WIFI_SLP_IRAM_OPT=y

# BLE host
CONFIG_BT_NIMBLE_MEM_ALLOC_MODE_INTERNAL=y   # host buffers in internal RAM
CONFIG_BT_NIMBLE_ATT_MAX_PREP_ENTRIES=4       # reduced from 64 in v2.10.32
CONFIG_BT_NIMBLE_MAX_CONNECTIONS=3
CONFIG_BT_NIMBLE_EXT_ADV=y
```

### Levers not yet pulled (in priority order)

| Lever | Est. gain | Risk | Notes |
|-------|-----------|------|-------|
| Move remaining 40 KB candidates (IR stores, GPS bufs, name tables) to PSRAM | ~15–20 KB internal | Low — all task-ctx | Verify each individually |
| `CONFIG_BT_CTRL_RUN_IN_FLASH_ONLY` | ~20 KB IRAM→DRAM | Medium — BLE latency | Espressif-documented |
| `CONFIG_BT_NIMBLE_MEM_ALLOC_MODE_EXTERNAL` | ~10–15 KB | Medium — regression risk (reverted v1.6.28) | Re-test BLE spam/GATT/scan |
| Disable `ESP_WIFI_*_IRAM_OPT` | ~20–40 KB IRAM→heap | Medium — sniffer perf | Measure capture-rate impact |
| Lazy-alloc RF433/IR/RFID buffers on screen entry | ~20 KB static | Low — stop-hook lifecycle | Best for features mutually exclusive with BLE |
| `SPIRAM_MALLOC_ALWAYSINTERNAL` 16384→4096 | Small | Low | More small allocs go to PSRAM |

---

## 7. How to verify a candidate array for PSRAM move

1. `grep -n 'array_name' ESP32C5/main/main.c` — find all write sites.
2. Check each write site: is it in a FreeRTOS task, an LVGL timer, or a BLE/WiFi task callback?
   → Task context = PSRAM safe.
3. Check: is the pointer ever passed to `esp_wifi_set_*`, `spi_device_transmit`, `rmt_transmit`,
   `uart_read_bytes` (DMA mode), or `sdmmc_host_do_transaction`? → If yes, keep internal.
4. Add `EXT_RAM_BSS_ATTR` before `static`, rebuild, and measure with `log_heap_stats()`.

---

## 8. References

- [Memory Types — ESP32-C5](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c5/api-guides/memory-types.html)
- [External RAM — ESP32-C5](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c5/api-guides/external-ram.html)
- [Minimize RAM usage — ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/performance/ram-usage.html)
- [Reduce RAM usage — ESP-Techpedia](https://docs.espressif.com/projects/esp-techpedia/en/latest/esp-friends/advanced-development/performance/reduce-ram-usage.html)
- [RF coexistence — ESP32-C5](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c5/api-guides/coexist.html)
- [LCD + PSRAM DMA — ESP-FAQ](https://docs.espressif.com/projects/esp-faq/en/latest/software-framework/peripherals/lcd.html)
