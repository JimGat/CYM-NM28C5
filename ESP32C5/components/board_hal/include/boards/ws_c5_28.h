// Waveshare ESP32-C5-Touch-LCD-2.8 pin definitions.
//
// Board: Waveshare ESP32-C5-Touch-LCD-2.8
// SoC:   ESP32-C5-WROOM-1-N8, RISC-V 240 MHz
// Flash: 32 MB | PSRAM: 8 MB | WiFi 6 (2.4 + 5 GHz) | BT 5
// Ref:   https://github.com/waveshareteam/ESP32-C5-Touch-LCD-2.8
//        Key header: bsp/esp32_c5_touch_lcd_2.8.h
//
// CRITICAL: LCD CS and SD CS are SWAPPED vs NM-CYD-C5.
//   NM-CYD-C5: LCD_CS=23, SD_CS=10
//   Waveshare:  LCD_CS=10, SD_CS=23
//
// Phase 2 — board on order (tracking 2026-09-07). This file is a placeholder
// with confirmed values from BSP header; verify all values on board arrival.
#pragma once

// ── SPI bus ───────────────────────────────────────────────────────────────────
// SPI2_HOST shared by ST7789 (LCD) and SD card.
// Note: MISO is GPIO8 (SD only; LCD is write-only ST7789).
#define BOARD_SPI_HOST       SPI2_HOST
#define BOARD_SPI_SCK        6
#define BOARD_SPI_MOSI       7
#define BOARD_SPI_MISO       8    // SD only (vs GPIO2 on NM-CYD-C5)

// ── ST7789 display — NOTE SWAPPED CS vs NM-CYD-C5 ────────────────────────────
#define BOARD_LCD_CS         10   // ← WAS 23 on NM-CYD-C5
#define BOARD_LCD_DC         9
#define BOARD_LCD_RST        -1   // Driven via CH32V003 PIN_1 (IO expander)
#define BOARD_LCD_WIDTH      240
#define BOARD_LCD_HEIGHT     320
// Backlight: CH32V003 EXIO_PWM via I2C 0x24.
// Use custom_io_expander_set_pwm(io_expander, pwm_val) instead of GPIO.
// BOARD_BACKLIGHT_GPIO is intentionally -1 to force the HAL path.
#define BOARD_BACKLIGHT_GPIO -1   // Not a GPIO — controlled via IO expander

// ── CST3530 capacitive touch ──────────────────────────────────────────────────
// Interrupt-driven via GPIO5. No calibration needed.
// I2C address: 0x58. 4-byte register addresses.
// RST driven via CH32V003 PIN_0.
#define BOARD_TOUCH_CS       -1   // No CS — I2C device
#define BOARD_TOUCH_INT      5

// ── SD card — NOTE SWAPPED CS vs NM-CYD-C5 ────────────────────────────────────
#define BOARD_SD_CS          23   // ← WAS 10 on NM-CYD-C5

// ── CH32V003 IO Expander (I2C 0x24) ──────────────────────────────────────────
// Secondary RISC-V MCU controlling: LCD_RST (PIN1), Touch_RST (PIN0),
// Audio amp enable (PIN3), LCD backlight PWM (EXIO_PWM).
#define BOARD_IO_EXPANDER_I2C_ADDR  0x24

// ── I2C bus (shared: CST3530, CH32V003, QMI8658, SHTC3, PCF85063A, ES8311) ──
#define BOARD_I2C_SDA        0
#define BOARD_I2C_SCL        1

// ── RF-HAT control signals via JST 12-pin SH1.0 connector ────────────────────
// GPIO2 → RF-HAT signal A (replaces NM-CYD-C5's GPIO8)
// GPIO3 → RF-HAT signal B (replaces NM-CYD-C5's GPIO9)
// SPI bus comes via SD shim in the TF slot.
#define BOARD_RFHAT_PIN_A    2
#define BOARD_RFHAT_PIN_B    3

// ── GPS UART ──────────────────────────────────────────────────────────────────
// Available via UART header (GPIO11=TX, GPIO12=RX). Reassign if needed.
#define BOARD_GPS_UART_NUM   UART_NUM_1
#define BOARD_GPS_TX_GPIO    11
#define BOARD_GPS_RX_GPIO    12

// ── Boot button ───────────────────────────────────────────────────────────────
#define BOARD_BOOT_BTN_GPIO  28

// ── No vibrator or WS2812 on Waveshare ───────────────────────────────────────
#define BOARD_VIBRATOR_GPIO  -1
#define BOARD_RGB_LED_GPIO   -1
#define BOARD_RGB_LED_COUNT  0

// ── Board identifier string ───────────────────────────────────────────────────
#define BOARD_NAME           "WS-C5-28"
#define BOARD_DISPLAY_DRIVER "ST7789"
#define BOARD_TOUCH_DRIVER   "CST3530"
