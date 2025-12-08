# ESP32-C5 WiFi Hacker V1.0

Professional WiFi security testing tool with LVGL touch interface.

## Hardware

- **MCU:** ESP32-C5
- **Display:** ILI9341 240x320 LCD (16-bit RGB565)
- **Touch:** XPT2046 resistive touch controller
- **Interface:** Shared SPI bus

## Pin Configuration

| Function | GPIO | Description |
|----------|------|-------------|
| LCD_MOSI | 24 | SPI MOSI (shared) |
| LCD_MISO | 4 | SPI MISO (shared) |
| LCD_CLK | 23 | SPI Clock (shared) |
| LCD_CS | 15 | LCD Chip Select |
| LCD_DC | 3 | LCD Data/Command |
| LCD_RST | 2 | LCD Reset |
| T_CS | 26 | Touch Chip Select |
| T_IRQ | 25 | Touch Interrupt |

## Features

- **Complex LVGL Menu** - Professional touch interface
- **WiFi Security Tools:**
  - Scanner & Targets - Network discovery
  - Sniffer - Packet capture
  - Attacks submenu:
    - Deauther - Deauthentication attacks
    - Evil Twin - Rogue AP
    - Blackout - Mass disruption
    - Snifferdog - Advanced packet analysis
    - Karma - Auto-connect exploitation
    - Portal - Captive portal
  - Wardrive - Mobile scanning
- **Stable Touch Input** - Race condition free initialization
- **Double Buffering** - Smooth 60 FPS rendering

## Menu Structure

```
WiFi Hacker (Root)
├── Scanner & Targets
├── Sniffer
├── Attacks
│   ├── Deauther
│   ├── Evil Twin
│   ├── Blackout
│   ├── Snifferdog
│   ├── Karma
│   └── Portal
└── Wardrive
```

## Building

```bash
. /path/to/esp-idf/export.sh
idf.py build
idf.py flash monitor
```

## Dependencies

Managed via `idf_component.yml`:
- `lvgl/lvgl: ^8.3.0` - Graphics library with Menu widget
- `espressif/esp_lcd_ili9341: ^1.0.0` - LCD driver
- `espressif/esp_lcd_touch: '*'` - Touch support

## Usage

1. Power on device
2. Touch screen will display main menu sidebar
3. Select tools from main menu
4. Touch "Attacks" to access submenu
5. Select specific attack type
6. Use back button to return to main menu

## Technical Details

- **LVGL 8.3** - Complex menu widget
- **RGB565 byte swapping** - Correct color rendering
- **Touch calibration** - 200-3900 ADC range mapped to screen
- **Initialization sequence** - 150ms delays prevent SPI race conditions
- **Binary size:** 470 KB (69% flash free)

## Security Notice

This tool is for **educational and authorized security testing only**. 
Unauthorized WiFi attacks are illegal in most jurisdictions.

---

**ESP32-C5 WiFi Hacker V1.0** - Professional WiFi Security Testing Platform
