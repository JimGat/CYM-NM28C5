# NM-CYD-C5 Hardware Specification & Pin Map

**Board**: NM-CYD-C5 — New Cheap Yellow Display with ESP32-C5  
**Official source**: https://github.com/RockBase-iot/NM-CYD-C5  
**Cross-checked against**: `Demos/Arduino/libraries/TFT_eSPI/User_Setup-NM-CYD-C5.h` (official RockBase-iot file)  
**Status**: All pins fully confirmed. No TBD entries remain.

---

## Hardware Overview

| Component          | Model / Spec                             | Interface      |
|--------------------|------------------------------------------|----------------|
| **SoC**            | ESP32-C5-WROOM-1 (RISC-V single-core)   | —              |
| **Clock**          | 240 MHz                                  | —              |
| **Flash**          | 16 MB (external)                         | SPI            |
| **PSRAM**          | 8 MB (external)                          | SPI            |
| **SRAM**           | 384 KB (on-chip)                         | —              |
| **Wi-Fi**          | 802.11ax WiFi 6 (2.4 GHz + 5 GHz)       | —              |
| **Bluetooth**      | BLE 5.3                                  | —              |
| **802.15.4**       | Thread 1.3 / Zigbee 3.0                  | —              |
| **Display**        | 2.8″ TFT, 240×320, ST7789               | SPI (shared)   |
| **Touch**          | XPT2046 resistive touchscreen            | SPI (shared)   |
| **SD Card**        | MicroSD slot                             | SPI (shared)   |
| **USB**            | 2× USB-C (CH340 UART + Native USB 2.0)  | —              |
| **RGB LED**        | Onboard WS2812 (IO27, module pin 18)     | GPIO / RMT     |
| **Operating Temp** | −20°C to +70°C                          | —              |

> The NM-CYD-C5 is **fully dimensionally and interface-compatible** with the ESP32-2432S028 (standard CYD), enabling drop-in replacement.

---

## Confirmed Pin Assignments

All pins confirmed from `User_Setup-NM-CYD-C5.h` and the official README pinout tables.

### SPI Bus — Shared by Display, Touch, and SD Card

| Signal | GPIO  | Notes                        |
|--------|-------|------------------------------|
| SCK    | **6** | Shared: Display + Touch + SD |
| MOSI   | **7** | Shared: Display + Touch + SD |
| MISO   | **2** | Shared: Display + Touch + SD |

### Display (ST7789 — 2.8″, 240×320)

| Signal         | GPIO   | Source                         | Notes                              |
|----------------|--------|--------------------------------|------------------------------------|
| SCK            | **6**  | README pinout table            | Shared SPI bus                     |
| MOSI           | **7**  | README pinout table            | Shared SPI bus                     |
| MISO           | **2**  | README pinout table            | Shared SPI bus                     |
| CS             | **23** | README + User_Setup            | Active LOW                         |
| DC (Data/Cmd)  | **24** | User_Setup `TFT_DC`            | Data/Command select                |
| RST (Reset)    | **-1** | User_Setup `TFT_RST = -1`      | Tied to board RST/EN — not a GPIO  |
| Backlight (BL) | **25** | User_Setup `TFT_BL`            | HIGH = backlight ON                |

> **Note on GPIO 25 (Backlight)**: GPIO 25 is a strapping pin on ESP32-C5. It is safe to use as output after boot completes, but it affects boot mode if held LOW at power-on. The board is designed to use it here — just be aware when probing.

> **Display notes**: ST7789 max SPI clock 62.5 MHz; run at 40–55 MHz in practice. Color depth: 16-bit RGB565. Resolution: 240 (H) × 320 (V) in portrait, 320 (H) × 240 (V) in landscape.

### Touch (XPT2046 — Resistive, 12-bit ADC)

| Signal      | GPIO      | Source                    | Notes                                   |
|-------------|-----------|---------------------------|-----------------------------------------|
| SCK         | **6**     | README pinout table       | Shared SPI bus                          |
| MOSI        | **7**     | README pinout table       | Shared SPI bus                          |
| MISO        | **2**     | README pinout table       | Shared SPI bus                          |
| CS (T_CS)   | **1**     | README + User_Setup       | Active LOW                              |
| IRQ (T_IRQ) | **NC**    | README shows `---`        | Not connected — polling only, no ISR    |

> **Touch notes**: XPT2046 SPI max clock is 2 MHz. Because T_IRQ is not wired, touch must be polled (read X/Y and check pressure Z1/Z2). Operating voltage 2.7–5.25V.

### SD Card (MicroSD — SPI shared bus)

| Signal | GPIO   | Notes                    |
|--------|--------|--------------------------|
| SCK    | **6**  | Shared SPI bus           |
| MOSI   | **7**  | Shared SPI bus           |
| MISO   | **2**  | Shared SPI bus           |
| CS     | **10** | Active LOW               |

### GPS Module — LP-UART (connector P5)

| Signal | GPIO  | Notes            |
|--------|-------|------------------|
| RX     | **4** | LP-UART receive  |
| TX     | **5** | LP-UART transmit |

> Plug-and-play with NM-ATGM336H GPS module via the P5 connector.

### I2C Extension — CN1 Connector

| Pin | GPIO  | Notes              |
|-----|-------|--------------------|
| 1   | 3.3V  | Power              |
| 2   | **9** | I2C SDA (IO9)      |
| 3   | **8** | I2C SCL (IO8)      |
| 4   | GND   | Ground             |

### Expansion Header — P1

| Pin | GPIO   | Notes   |
|-----|--------|---------|
| 1   | **4**  | IO4     |
| 2   | **8**  | IO8     |
| 3   | **26** | IO26    |
| 4   | GND    | Ground  |

### FPC2 — 12-Pin FPC Interface

| Pin | 1    | 2    | 3    | 4    | 5   | 6    | 7    | 8    | 9    | 10     | 11     | 12  |
|-----|------|------|------|------|-----|------|------|------|------|--------|--------|-----|
|     | IO2  | IO6  | IO7  | IO10 | GND | IO4  | IO8  | IO5  | IO9  | USB D− | USB D+ | GND |

---

## Complete GPIO Table

| GPIO | Function              | Dir    | Interface  | Notes                                |
|------|-----------------------|--------|------------|--------------------------------------|
| 0    | Boot Button           | Input  | GPIO       | Active LOW; internal pull-up         |
| 1    | Touch CS (XPT2046)    | Output | SPI        | Active LOW                           |
| 2    | SPI MISO              | Input  | SPI shared | Display + Touch + SD                 |
| 3    | (unassigned)          | —      | —          | Available                            |
| 4    | GPS RX / P1 pin 1     | Input  | LP-UART    | LP-UART receive; also on P1 header   |
| 5    | GPS TX                | Output | LP-UART    | LP-UART transmit                     |
| 6    | SPI SCK               | Output | SPI shared | ⚠️ Strapping pin — safe after boot   |
| 7    | SPI MOSI              | Output | SPI shared | ⚠️ Strapping pin — safe after boot   |
| 8    | I2C SCL / P1 pin 2    | I/O    | I2C (ext)  | CN1 pin 3; P1 pin 2; FPC2 pin 7      |
| 9    | I2C SDA               | I/O    | I2C (ext)  | CN1 pin 2; FPC2 pin 9                |
| 10   | SD Card CS            | Output | SPI        | Active LOW; FPC2 pin 4               |
| 11   | USB-JTAG              | —      | JTAG       | ⚠️ Default JTAG — avoid unless needed|
| 12   | USB-JTAG              | —      | JTAG       | ⚠️ Default JTAG — avoid unless needed|
| 13   | USB-JTAG              | —      | JTAG       | ⚠️ Default JTAG — avoid unless needed|
| 14   | USB-JTAG              | —      | JTAG       | ⚠️ Default JTAG — avoid unless needed|
| 15   | (unassigned)          | —      | —          | Available                            |
| 16   | Flash / PSRAM         | —      | SPI0/SPI1  | ⛔ RESERVED — never use              |
| 17   | Flash / PSRAM         | —      | SPI0/SPI1  | ⛔ RESERVED — never use              |
| 18   | Flash / PSRAM         | —      | SPI0/SPI1  | ⛔ RESERVED — never use              |
| 19   | Flash / PSRAM         | —      | SPI0/SPI1  | ⛔ RESERVED — never use              |
| 20   | Flash / PSRAM         | —      | SPI0/SPI1  | ⛔ RESERVED — never use              |
| 21   | (unassigned)          | —      | —          | Available                            |
| 22   | Flash / PSRAM         | —      | SPI0/SPI1  | ⛔ RESERVED — never use              |
| 23   | Display CS (ST7789)   | Output | SPI        | Active LOW                           |
| 24   | Display DC (ST7789)   | Output | GPIO       | Data/Command select                  |
| 25   | Display Backlight     | Output | GPIO/PWM   | HIGH = ON; ⚠️ strapping pin at boot  |
| 26   | P1 Expansion pin 3    | I/O    | GPIO       | P1 header                            |
| 27   | RGB LED (WS2812)      | Output | RMT/GPIO   | Module pin 18 on ESP32-C5-WROOM-1    |
| 28   | (strapping pin)       | —      | —          | ⚠️ Avoid using as output             |

---

## SPI Bus Architecture

```
SPI2_HOST
├── ST7789 Display    (CS = GPIO 23)
│   ├── SCK   = GPIO 6   (40–55 MHz)
│   ├── MOSI  = GPIO 7
│   ├── MISO  = GPIO 2
│   ├── DC    = GPIO 24  (not part of SPI bus — toggled via GPIO)
│   └── RST   = -1       (tied to board EN/RST — no GPIO needed)
│
├── XPT2046 Touch     (CS = GPIO 1)
│   ├── SCK   = GPIO 6   (≤ 2 MHz — ESP-IDF sets speed per device handle)
│   ├── MOSI  = GPIO 7
│   ├── MISO  = GPIO 2
│   └── IRQ   = NC       (not connected — use polling)
│
└── SD Card           (CS = GPIO 10)
    ├── SCK   = GPIO 6
    ├── MOSI  = GPIO 7
    └── MISO  = GPIO 2

Backlight: GPIO 25 (HIGH = on, PWM-dimmable)
```

> **SPI clock note**: ESP-IDF `spi_device_handle_t` reconfigures the bus clock speed automatically per device transaction. Set `clock_speed_hz = 2*1000*1000` on the XPT2046 handle and `clock_speed_hz = 40*1000*1000` on the ST7789 handle — they coexist on the same bus safely.

---

## Code Migration: Waveshare Build → NM-CYD-C5

Every define that must change, mapped file by file.

### `main.c` — SPI / Display Pins

| Define       | Current (Waveshare) | NM-CYD-C5  | Changed? |
|--------------|---------------------|------------|----------|
| `LCD_MOSI`   | GPIO 24             | GPIO **7** | YES      |
| `LCD_MISO`   | GPIO 4              | GPIO **2** | YES      |
| `LCD_CLK`    | GPIO 23             | GPIO **6** | YES      |
| `LCD_CS`     | GPIO 5              | GPIO **23**| YES      |
| `LCD_DC`     | GPIO 3              | GPIO **24**| YES      |
| `LCD_RST`    | GPIO 2              | **-1**     | YES      |
| `LCD_BL_IO`  | -1                  | GPIO **25**| YES      |
| `LCD_H_RES`  | 480                 | **240**    | YES      |
| `LCD_V_RES`  | 320                 | **320**    | No       |

### `main.c` — Touch Controller (full driver swap required)

| Item            | Current (Waveshare)       | NM-CYD-C5 Target           | Change?      |
|-----------------|---------------------------|----------------------------|--------------|
| Controller IC   | FT6336U (capacitive)      | **XPT2046 (resistive)**    | YES          |
| Interface       | I2C                       | **SPI (shared bus)**       | YES          |
| Driver file     | `ft6336.c` / `ft6336.h`  | Need **xpt2046.c/h**       | YES (rewrite)|
| `CTP_SDA`       | GPIO 9                    | Remove                     | Remove       |
| `CTP_SCL`       | GPIO 10                   | Remove                     | Remove       |
| `CTP_INT`       | GPIO 25                   | **NC — remove ISR**        | Remove       |
| `CTP_RST`       | GPIO 8                    | Remove (no RST on XPT2046) | Remove       |
| Touch CS        | (none — was I2C)          | Add: **GPIO 1**            | Add          |
| Touch IRQ       | GPIO 25 (interrupt)       | **NC — polling only**      | Change logic |

### `wifi_common.h` — SD Card Pins

| Define        | Current (Waveshare) | NM-CYD-C5   | Changed? |
|---------------|---------------------|-------------|----------|
| `SD_MISO_PIN` | GPIO 4              | GPIO **2**  | YES      |
| `SD_MOSI_PIN` | GPIO 24             | GPIO **7**  | YES      |
| `SD_CLK_PIN`  | GPIO 23             | GPIO **6**  | YES      |
| `SD_CS_PIN`   | GPIO 7              | GPIO **10** | YES      |

### `wifi_common.h` — GPS Pins

| Define       | Current (Waveshare) | NM-CYD-C5  | Changed? |
|--------------|---------------------|------------|----------|
| `GPS_TX_PIN` | GPIO 13             | GPIO **5** | YES      |
| `GPS_RX_PIN` | GPIO 14             | GPIO **4** | YES      |

### `wifi_common.h` — NeoPixel / RGB LED

| Define         | Current (Waveshare) | NM-CYD-C5  | Changed? |
|----------------|---------------------|------------|----------|
| `NEOPIXEL_GPIO`| GPIO 27             | GPIO **27**| No       |

> GPIO 27 is module pin 18 on the ESP32-C5-WROOM-1-N168R. The NeoPixel pin is the same as the current Waveshare build — no change needed.

---

## Driver Changes Required

### 1. Replace ILI9341 → ST7789

- Remove: `components/espressif__esp_lcd_ili9341/`
- Add: `esp_lcd_st7789` (built into ESP-IDF) — no extra component needed
- Update `idf_component.yml` to remove `espressif__esp_lcd_ili9341` dependency
- Change `#include "esp_lcd_ili9341.h"` → `#include "esp_lcd_st7789.h"`
- Init sequence changes: ST7789 uses `esp_lcd_new_panel_st7789()` instead of `esp_lcd_new_panel_ili9341()`
- Verify `CONFIG_LV_COLOR_16_SWAP` — ST7789 may need different byte-swap setting than ILI9341

### 2. Replace FT6336U (I2C capacitive) → XPT2046 (SPI resistive)

- Remove: `main/ft6336.c`, `main/ft6336.h`
- Remove: I2C driver init (`driver/i2c.h` calls)
- Add: new `main/xpt2046.c` + `main/xpt2046.h` using `spi_device_handle_t` on SPI2_HOST
- T_IRQ is NC → replace interrupt-driven touch detection with **periodic polling** (e.g., in LVGL tick task)
- Calibration required: raw 12-bit ADC values (0–4095) must map to screen pixels (0–239, 0–319)
- Touch is valid only when Z1 pressure reading is above threshold (typically > 400 raw counts)

### 3. Resolution and LVGL

- `LCD_H_RES`: 480 → **240**
- `LCD_V_RES`: 320 → **320** (no change in portrait)
- LVGL draw buffer: was `480 * 10 * 2` bytes → now `240 * 10 * 2` bytes (half the PSRAM)
- Re-check all hardcoded pixel coordinates and widget sizes in the UI

---

## XPT2046 SPI Protocol Reference

```
Transaction: 8-bit command → 16-bit response (24 clocks total per read)

Command byte format:  S | A2 | A1 | A0 | MODE | SER/DFR | PD1 | PD0
                      1    channel     |   0=12b  |  0=diff  |  power mode

Channel (A2:A1:A0):
  1 0 1 = X position   → command 0xD0 (diff, 12-bit, power on)
  0 0 1 = Y position   → command 0x90 (diff, 12-bit, power on)
  0 1 1 = Z1 pressure  → command 0xB0
  1 0 0 = Z2 pressure  → command 0xC0

Response: 16 bits returned, value is in bits [14:3] → shift right by 3
          Valid range: 0–4095 (12-bit)

SPI mode:  Mode 0 (CPOL=0, CPHA=0)
SPI clock: ≤ 2 MHz
CS:        GPIO 1 (active LOW, manual or SPI device handle)

Touch detection (no IRQ):
  1. Assert CS (LOW)
  2. Send 0xB0, read Z1 (16-bit)
  3. If Z1 > ~400: touch is active
  4. Send 0xD0, read X (16-bit), extract bits [14:3]
  5. Send 0x90, read Y (16-bit), extract bits [14:3]
  6. Deassert CS (HIGH)
  7. Map X/Y raw → screen pixels via calibration offsets
```

---

## ESP32-C5 GPIO Constraints

| Category                     | GPIOs              | Rule                                    |
|------------------------------|--------------------|-----------------------------------------|
| Flash / PSRAM reserved       | 16, 17, 18, 19, 20, 22 | **Never use — hardware conflict**   |
| Strapping pins               | 6, 7, 25, 26, 27, 28 | OK after boot; board uses 6, 7, 25   |
| USB-JTAG (default function)  | 11, 12, 13, 14     | Reuse disables USB-JTAG debugging       |
| Boot button                  | 0                  | Input only during boot sequence         |

---

## Version History

| Date       | Change                                                                    |
|------------|---------------------------------------------------------------------------|
| 2026-04-14 | Initial pin map created                                                   |
| 2026-04-14 | Cross-checked against `User_Setup-NM-CYD-C5.h` — all TBDs resolved:     |
|            | TFT_DC = GPIO 24, TFT_RST = -1, TFT_BL = GPIO 25, T_IRQ = NC (polling)  |
| 2026-04-14 | RGB LED confirmed: GPIO 27, module pin 18 on ESP32-C5-WROOM-1-N168R      |

---

*Sources: [RockBase-iot/NM-CYD-C5 GitHub](https://github.com/RockBase-iot/NM-CYD-C5) — `User_Setup-NM-CYD-C5.h`, `README.md` pinout tables; ESP32-C5 datasheet; XPT2046 datasheet.*
