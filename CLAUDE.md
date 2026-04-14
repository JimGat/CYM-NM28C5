# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

**JANOS on NM-CYD-C5** — a WiFi 6 security toolkit and wardriving device.  
Build system: **ESP-IDF 6.0** (not Arduino). UI: **LVGL 8.4.0**. Target chip: `esp32c5`.

## Build & Flash

```bash
cd ESP32C5
idf.py set-target esp32c5   # only needed once / after clean
idf.py build
idf.py -p /dev/ttyACM0 flash monitor
```

There are no tests. The only validation is a successful `idf.py build`.

If `esp_lcd_new_panel_st7789` is not found, add `espressif/esp_lcd_st7789: '*'` to `ESP32C5/main/idf_component.yml` and re-run build (the function should be in the built-in `esp_lcd` component for IDF 6.0, but may need the component manager package).

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

GPS LP-UART: `wifi_common.h` defines `GPS_TX_PIN`/`GPS_RX_PIN` — these still hold the **old Waveshare values (13/14)** and need updating to **GPIO 5/4** for NM-CYD-C5.

## Architecture

### Code layout
Everything lives in one large file: `ESP32C5/main/main.c` (~16 000 lines). It contains display init, LVGL setup, all UI screens, WiFi scanning/attacks, BLE scanning, GPS, wardriving, and screenshot capture. GPIO defines are at the top of `main.c`; SD/GPS/LED defines are in `ESP32C5/components/wifi_cli/include/wifi_common.h`.

### SPI bus sharing
Display (ST7789), touch (XPT2046), and SD card all share **SPI2_HOST** with separate CS lines. A `sd_spi_mutex` (defined in `main.c`, declared `extern` in `attack_handshake.c`) serialises SD card access. ESP-IDF switches the bus clock per device handle automatically — ST7789 runs at 40 MHz, XPT2046 at 2 MHz.

### WiFi ↔ BLE radio switching
ESP32-C5 has a single shared radio. The firmware manages this with `radio_mode_t` (`RADIO_MODE_NONE / WIFI / BLE`) and `current_radio_mode`. Any BLE operation must stop WiFi first and vice versa.

### LVGL threading model
LVGL is not thread-safe. All LVGL calls outside the main task must take `lvgl_mutex`. A FreeRTOS timer fires `lv_tick_inc(10)` every 10 ms. The LVGL flush callback (`lvgl_flush_cb`) checks `sd_spi_mutex` before calling `esp_lcd_panel_draw_bitmap` to avoid SPI contention.

### Memory model
PSRAM is used for large allocations: LVGL draw buffers (`spi_bus_dma_memory_alloc`), task stacks (`heap_caps_malloc(MALLOC_CAP_SPIRAM)`), and the 1 MB captive-portal HTML buffer. `lvgl_memory.c` provides a custom LVGL allocator that targets PSRAM. `sdkconfig` sets `CONFIG_SPIRAM=y` and `CONFIG_SPIRAM_USE_MALLOC=y` (PSRAM is in the malloc pool above 16 KB threshold).

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

1. **GPS pins in `wifi_common.h`** — `GPS_TX_PIN 13` / `GPS_RX_PIN 14` are the old Waveshare values; NM-CYD-C5 uses GPIO 5 (TX) / GPIO 4 (RX).
2. **Touch calibration** — raw XPT2046 ADC defaults (200–3900) need real-hardware calibration.
3. **UI layout** — all screens were designed for landscape 480×320. Portrait 240×320 will clip many widgets; wardrive table column widths (130, 32, 42, 65, 130 = 399 px total) overflow the 240 px container.
4. **Battery ADC** — `BATTERY_ADC_CHANNEL ADC_CHANNEL_5` mapped to GPIO 6 (now SPI SCK). `init_battery_adc()` will fail gracefully; battery UI elements show nothing.
5. **`ft6336.c/h`** — old capacitive touch driver kept on disk but not compiled (removed from `CMakeLists.txt`).
