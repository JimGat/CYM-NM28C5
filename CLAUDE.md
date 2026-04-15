# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

**JANOS on NM-CYD-C5** — a WiFi 6 security toolkit and wardriving device.  
Build system: **ESP-IDF 6.0** (not Arduino). UI: **LVGL 8.4.0**. Target chip: `esp32c5`.

## Build & Flash

```bash
cd ESP32C5
source /home/dev/esp/esp-idf/export.sh   # must be done each shell session
idf.py set-target esp32c5                # only needed once / after clean
idf.py build
idf.py -p /dev/ttyACM0 flash monitor
```

There are no tests. The only validation is a successful `idf.py build`.

### IDF version — CRITICAL

We are on **`release/v6.0` branch tip** (not the `v6.0` tag). The tag is missing a required
ESP32-C5 PHY workaround. **Never switch back to the `v6.0` tag.**

```bash
cd /home/dev/esp/esp-idf
git checkout FETCH_HEAD   # after: git fetch origin release/v6.0
```

### ESP32-C5 PHY hang fix (IDF-15338)

The ESP32-C5 eco2 / rev1.0 silicon has a hardware bug where the RF PLL frequency-hop
register (`FECOEX_SET_FREQ_SET_CHAN_REG` at `0x600a001c`, `BIT(30)`) must be reset before
any call into the PHY blob. IDF-15338 added the fix to the wakeup re-enable path only.
We extended it to the **first-boot calibration path** in:

```
/home/dev/esp/esp-idf/components/esp_phy/src/phy_init.c
```

The patch (lines ~948–954) resets the register immediately before `register_chipv7_phy()`:

```c
// TODO: IDF-15338 - extend workaround to first-boot calibration path
#if CONFIG_IDF_TARGET_ESP32C5
    REG_CLR_BIT(FECOEX_SET_FREQ_SET_CHAN_REG, FECOEX_SET_FREQ_RESTEN);
    REG_SET_BIT(FECOEX_SET_FREQ_SET_CHAN_REG, FECOEX_SET_FREQ_RESTEN);
#endif
    esp_err_t ret = register_chipv7_phy(init_data, cal_data, calibration_mode);
```

**Without this patch `esp_wifi_start()` hangs forever after `phy_init: phy_version 108`.**
If you run `idf.py fullclean` or update IDF submodules, verify the patch is still present.

## Hardware: NM-CYD-C5

Board reference: https://github.com/RockBase-iot/NM-CYD-C5  
Full pin map with migration notes: `NM-CYD-C5-pinmap.md` (project root)

| Component | Spec |
|-----------|------|
| SoC | ESP32-C5-WROOM-1-N168R, RISC-V 240 MHz, 16 MB flash, 8 MB PSRAM |
| Display | 2.8″ ST7789, 240×320 portrait |
| Touch | XPT2046 resistive SPI — **polling only**, T_IRQ not connected |
| RGB LED | WS2812 on GPIO 27 |
| Backlight | GPIO 25 HIGH=on |

### GPIO quick-reference (non-obvious assignments)

| GPIO | Function |
|------|----------|
| 1 | XPT2046 Touch CS |
| 2 | SPI MISO (shared: display + touch + SD) |
| 6 | SPI SCK (shared) — strapping pin |
| 7 | SPI MOSI (shared) — strapping pin |
| 10 | SD Card CS |
| 16–22 excl. 21 | Flash/PSRAM — **never use** |
| 23 | ST7789 Display CS |
| 24 | ST7789 DC (Data/Command) |
| 25 | Backlight — strapping pin, safe after boot |
| 27 | WS2812 LED |

GPS LP-UART: `wifi_common.h` defines `GPS_TX_PIN 5` / `GPS_RX_PIN 4` (already corrected for NM-CYD-C5).

## Architecture

### Code layout
Everything lives in one large file: `ESP32C5/main/main.c` (~16 000 lines). It contains display init, LVGL setup, all UI screens, WiFi scanning/attacks, BLE scanning, GPS, wardriving, and screenshot capture. GPIO defines are at the top of `main.c`; SD/GPS/LED defines are in `ESP32C5/components/wifi_cli/include/wifi_common.h`.

### SPI bus sharing
Display (ST7789), touch (XPT2046), and SD card all share **SPI2_HOST** with separate CS lines. A `sd_spi_mutex` (defined in `main.c`, declared `extern` in `attack_handshake.c`) serialises SD card access. ESP-IDF switches the bus clock per device handle automatically — ST7789 runs at 40 MHz, XPT2046 at 2 MHz.

### WiFi — dual-band 2.4 GHz + 5 GHz

WiFi 6 is working on the NM-CYD-C5 (MAC `3C:DC:75:9D:5C:60`). Band mode defaults to
`WIFI_BAND_MODE_AUTO` (0x3 = 2.4 + 5 GHz). **Do not restrict to 2.4 GHz only** — the user
explicitly wants full dual-band operation.

`esp_wifi_set_band_mode()` requires WiFi to be **already started** (`esp_wifi_start()` must
have returned) before it can be called — calling it before start returns
`ESP_ERR_WIFI_NOT_STARTED` and has no effect.

### WiFi ↔ BLE radio switching
ESP32-C5 has a single shared radio. The firmware manages this with `radio_mode_t` (`RADIO_MODE_NONE / WIFI / BLE`) and `current_radio_mode`. Any BLE operation must stop WiFi first and vice versa.

### LVGL threading model
LVGL is not thread-safe. All LVGL calls outside the main task must take `lvgl_mutex`. An
`esp_timer` fires `lv_tick_inc(10)` every 10 ms (`lvgl_tick_task` callback). The main loop
calls `lv_timer_handler()` inside the `lvgl_mutex` to process timers and trigger display
flushes.

**Flush path:** `lvgl_flush_cb` → takes `sd_spi_mutex` → calls `esp_lcd_panel_draw_bitmap`
(DMA, async) → releases `sd_spi_mutex` → returns. When DMA completes, `on_color_trans_done`
callback fires `lv_disp_flush_ready()`. If `lv_disp_flush_ready` is never called (e.g. DMA
callback not registered), `lv_timer_handler()` will keep returning immediately without
processing any LVGL timers.

**Splash screen timing:** `show_splash_screen()` creates an LVGL timer at 100 ms intervals.
After 28 frames (~2.8 s) it creates a one-shot 700 ms timer that calls `detection_complete_cb`
→ `create_home_ui()`. The main loop must be running and calling `lv_timer_handler()` for this
transition to happen — it is NOT driven by the SD loading callbacks.

### Memory model
PSRAM is used for large allocations: LVGL draw buffers, task stacks (`heap_caps_malloc(MALLOC_CAP_SPIRAM)`), and the 1 MB captive-portal HTML buffer. `lvgl_memory.c` provides a custom LVGL allocator that targets PSRAM. `sdkconfig` sets `CONFIG_SPIRAM=y` and `CONFIG_SPIRAM_USE_MALLOC=y` (PSRAM is in the malloc pool above 16 KB threshold).

### Screen/brightness dimming
Brightness is a software black overlay (`brightness_overlay`) on `lv_layer_top()` — not PWM. The backlight GPIO (25) is driven HIGH at boot and left on; `screen_set_dimmed()` uses `esp_lcd_panel_disp_on_off()` for the full on/off.

### Touch (XPT2046)
Driver is `main/xpt2046.c`. Touch is detected by reading Z1 pressure (`> XPT2046_Z_THRESHOLD 400`). Default calibration constants (200–3900 raw ADC) will need tuning on real hardware via `xpt2046_set_calibration()`.

### NVS settings
User settings (screen timeout, brightness, scan timing, dark mode) are persisted in NVS namespace `"settings"`. Loaded at boot in `nvs_settings_load()`, saved on change. Keys are defined as `NVS_KEY_*` macros in `main.c`.

### Partition layout (`partitions.csv`)
```
nvs       0x9000   24 KB
phy_init  0xf000    4 KB
factory   0x10000   7 MB   ← firmware
storage   0x710000  960 KB ← FAT (internal, not SD card)
```

## Known issues / pending work

1. **LVGL splash → home transition stuck** — the main loop is alive (confirmed, 500 iter/5s)
   and `lv_timer_handler()` is called, but the splash timer never reaches frame 28. Root cause
   suspected: if `lv_disp_flush_ready()` is not called after the first `lv_refr_now(NULL)` at
   boot, LVGL treats the display as still flushing and `lv_timer_handler()` returns immediately
   without firing any timers. Investigate `on_color_trans_done` callback registration and
   whether DMA completion interrupt is reaching the callback.

2. **Touch calibration** — raw XPT2046 ADC defaults (200–3900) need real-hardware calibration.

3. **UI layout** — all screens were designed for landscape 480×320. Portrait 240×320 will clip many widgets; wardrive table column widths (130, 32, 42, 65, 130 = 399 px total) overflow the 240 px container.

4. **Battery ADC** — `BATTERY_ADC_CHANNEL ADC_CHANNEL_5` mapped to GPIO 6 (now SPI SCK). `init_battery_adc()` will fail gracefully; battery UI elements show nothing.

5. **`ft6336.c/h`** — old capacitive touch driver kept on disk but not compiled (removed from `CMakeLists.txt`).

6. **Debug scaffolding to remove** — once display is working, strip: DBG-XX macros in `main.c`,
   `[WIFI]`/`[DISP]` ESP_LOGE lines in `wifi_cli.c`, `esp_rom_printf` probes in
   `phy_init.c`, and the `[MAIN LOOP] Alive` log.
