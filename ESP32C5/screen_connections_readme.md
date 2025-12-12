# ESP32-C5 Display & Peripherals Connection Guide

## Overview

This document describes the hardware connections for the ESP32-C5 project with:
- 3.5" TFT SPI Display (480x320) with ILI9341 controller
- FT6336U Capacitive Touch Panel (I2C)
- SD Card (SPI, shared bus with display)
- GPS Module (UART)
- NeoPixel LED Strip

---

## Hardware Components

| Component | Controller/Driver | Interface | Library |
|-----------|-------------------|-----------|---------|
| Display | ILI9341 | SPI | `espressif/esp_lcd_ili9341` v1.2.0 |
| Touch Panel | FT6336U | I2C | Custom `ft6336.c` |
| SD Card | - | SPI (shared) | ESP-IDF `sdspi` |
| GPS | - | UART | Custom implementation |
| LED Strip | WS2812 | GPIO | `espressif/led_strip` |
| UI Framework | LVGL 8.x | - | `lvgl/lvgl` ^8.3.0 |

---

## Complete Pinout

### Display (ILI9341 - SPI)

| Signal | GPIO | Description |
|--------|------|-------------|
| MOSI (SDI) | **GPIO 24** | SPI Data Out (shared with SD) |
| MISO (SDO) | **GPIO 4** | SPI Data In (shared with SD) |
| SCK (CLK) | **GPIO 23** | SPI Clock (shared with SD) |
| CS | **GPIO 6** | Chip Select (active LOW) |
| DC (RS) | **GPIO 3** | Data/Command select |
| RST | **GPIO 2** | Hardware Reset (active LOW) |
| VCC | 3.3V | Power supply |
| GND | GND | Ground |
| LED | 3.3V | Backlight (directly connected) |

### Touch Panel (FT6336U - I2C)

| Signal | GPIO | Description |
|--------|------|-------------|
| SDA | **GPIO 9** | I2C Data |
| SCL | **GPIO 10** | I2C Clock |
| INT | **GPIO 25** | Interrupt (touch detected) |
| RST | **GPIO 8** | Hardware Reset |
| VCC | 3.3V | Power supply |
| GND | GND | Ground |

### SD Card (SPI - Shared Bus)

| Signal | GPIO | Description |
|--------|------|-------------|
| MOSI | **GPIO 24** | SPI Data Out (shared with LCD) |
| MISO | **GPIO 4** | SPI Data In (shared with LCD) |
| SCK | **GPIO 23** | SPI Clock (shared with LCD) |
| CS | **GPIO 7** | Chip Select (active LOW) |
| VCC | 3.3V | Power supply |
| GND | GND | Ground |

### GPS Module (UART)

| Signal | GPIO | Description |
|--------|------|-------------|
| TX | **GPIO 13** | UART TX (ESP → GPS) |
| RX | **GPIO 14** | UART RX (GPS → ESP) |
| VCC | 3.3V | Power supply |
| GND | GND | Ground |

### NeoPixel LED Strip

| Signal | GPIO | Description |
|--------|------|-------------|
| DATA | **GPIO 27** | WS2812 Data line |
| VCC | 5V | Power supply |
| GND | GND | Ground |

### Console UART (USB)

| Signal | GPIO | Description |
|--------|------|-------------|
| TX | **GPIO 11** | Console output |
| RX | **GPIO 12** | Console input |

---

## GPIO Summary Table

| GPIO | Function | Interface | Notes |
|------|----------|-----------|-------|
| 2 | LCD_RST | Output | ⚠️ Strapping pin - requires reset |
| 3 | LCD_DC | Output | ⚠️ Strapping pin - requires reset |
| 4 | MISO | SPI | Shared: LCD + SD |
| 6 | LCD_CS | SPI | Display Chip Select |
| 7 | SD_CS | SPI | SD Card Chip Select |
| 8 | CTP_RST | Output | Touch Reset |
| 9 | CTP_SDA | I2C | Touch Data |
| 10 | CTP_SCL | I2C | Touch Clock |
| 11 | UART_TX | UART | Console (USB) |
| 12 | UART_RX | UART | Console (USB) |
| 13 | GPS_TX | UART | GPS Module |
| 14 | GPS_RX | UART | GPS Module |
| 23 | SPI_CLK | SPI | Shared: LCD + SD |
| 24 | SPI_MOSI | SPI | Shared: LCD + SD |
| 25 | CTP_INT | Input | Touch Interrupt |
| 27 | NEOPIXEL | Output | LED Strip Data |

---

## Critical Fix: GPIO Reset for Waveshare ESP32-C5

### Problem

On **Waveshare ESP32-C5**, the display did not work despite:
- SD card working on the same SPI bus
- Touch panel working on I2C
- All SPI commands returning success

### Root Cause

GPIO 2 and GPIO 3 are **strapping pins** on ESP32-C5. On Waveshare boards, these pins may have:
- Default GPIO matrix configuration from bootloader
- Internal pull-up/pull-down resistors enabled
- Alternative function assignments

### Solution

Before configuring SPI for the display, **reset these GPIO pins** and perform hardware reset:

```c
// Reset pins before use - REQUIRED on Waveshare ESP32-C5!
gpio_reset_pin(LCD_RST);  // GPIO 2 - Strapping pin
gpio_reset_pin(LCD_DC);   // GPIO 3 - Strapping pin
gpio_reset_pin(LCD_CS);   // GPIO 6

gpio_set_direction(LCD_RST, GPIO_MODE_OUTPUT);
gpio_set_direction(LCD_DC, GPIO_MODE_OUTPUT);
gpio_set_direction(LCD_CS, GPIO_MODE_OUTPUT);

// Hardware reset LCD - CRITICAL!
gpio_set_level(LCD_RST, 0);
vTaskDelay(pdMS_TO_TICKS(100));
gpio_set_level(LCD_RST, 1);
vTaskDelay(pdMS_TO_TICKS(120));
```

### What `gpio_reset_pin()` Does

1. Disconnects pin from GPIO matrix (removes previous assignments)
2. Disables internal pull-up and pull-down resistors
3. Sets pin to floating input state
4. Clears any previous output driver configuration

### Why Hardware Reset is Required

After `gpio_reset_pin()`, you must:
1. Set pin directions with `gpio_set_direction()`
2. Perform LCD hardware reset by toggling RST pin LOW → HIGH
3. Wait for LCD to initialize (120ms after RST goes HIGH)

This sequence is **mandatory** on Waveshare ESP32-C5 - without it, the display stays blank.

---

## SPI Bus Configuration

The display and SD card share the same SPI bus (SPI2_HOST) with different Chip Select pins:

```
SPI2_HOST
├── LCD (CS = GPIO 6)
│   ├── MOSI = GPIO 24
│   ├── MISO = GPIO 4
│   ├── CLK  = GPIO 23
│   └── Additional: DC = GPIO 3, RST = GPIO 2
│
└── SD Card (CS = GPIO 7)
    ├── MOSI = GPIO 24
    ├── MISO = GPIO 4
    └── CLK  = GPIO 23
```

A mutex (`sd_spi_mutex`) is used to prevent simultaneous access to the SPI bus.

---

## Display Configuration

| Parameter | Value |
|-----------|-------|
| Resolution | 480 x 320 |
| Color Depth | 16-bit (RGB565) |
| SPI Clock | 40 MHz |
| Color Order | BGR |
| Byte Swap | Enabled (`CONFIG_LV_COLOR_16_SWAP=y`) |

### LVGL Configuration (sdkconfig)

```
CONFIG_LV_COLOR_DEPTH=16
CONFIG_LV_COLOR_16_SWAP=y
CONFIG_LV_MEM_CUSTOM=y
CONFIG_SPIRAM=y
```

---

## Wiring Diagram

```
                    ESP32-C5 Waveshare
                    ┌─────────────────┐
                    │                 │
    Display ────────┤ GPIO 24 (MOSI)  │──────── SD Card
    (shared)        │ GPIO 4  (MISO)  │         (shared)
                    │ GPIO 23 (CLK)   │
                    │                 │
    LCD CS ─────────┤ GPIO 6          │
    LCD DC ─────────┤ GPIO 3  ⚠️      │
    LCD RST ────────┤ GPIO 2  ⚠️      │
                    │                 │
    SD CS ──────────┤ GPIO 7          │
                    │                 │
    Touch SDA ──────┤ GPIO 9          │
    Touch SCL ──────┤ GPIO 10         │
    Touch INT ──────┤ GPIO 25         │
    Touch RST ──────┤ GPIO 8          │
                    │                 │
    GPS TX ─────────┤ GPIO 13         │
    GPS RX ─────────┤ GPIO 14         │
                    │                 │
    NeoPixel ───────┤ GPIO 27         │
                    │                 │
    Console ────────┤ GPIO 11/12 (USB)│
                    └─────────────────┘

⚠️ = Strapping pins - require gpio_reset_pin() before use
```

---

## Troubleshooting

### Display shows nothing but touch works

1. Check if `gpio_reset_pin()` is called for GPIO 2, 3, 6
2. Check if `gpio_set_direction()` is called for these pins
3. **Check if hardware reset is performed** (RST LOW 100ms, then HIGH, wait 120ms)
4. Verify SPI connections with multimeter
5. Check if backlight is connected to 3.3V

### Colors are inverted (red shows as blue)

- Verify `CONFIG_LV_COLOR_16_SWAP=y` in sdkconfig
- Check `rgb_ele_order` setting (should be `LCD_RGB_ELEMENT_ORDER_BGR`)

### SD card timeout

- SD card and LCD share SPI bus - ensure mutex is used
- Check SD_CS pin (GPIO 7) connection

### Touch not responding

- Verify I2C connections (SDA=GPIO9, SCL=GPIO10)
- Check touch controller with I2C scan
- FT6336U I2C address: 0x38

---

## Version History

- **December 2025**: Added GPIO reset fix for Waveshare ESP32-C5
- **December 2025**: Updated ILI9341 driver for ESP-IDF 6.0 compatibility

---

## Files Reference

| File | Description |
|------|-------------|
| `main/main.c` | Display & touch initialization |
| `main/ft6336.c` | Touch driver implementation |
| `components/espressif__esp_lcd_ili9341/` | Modified ILI9341 driver |
| `components/wifi_cli/include/wifi_common.h` | GPIO definitions |

