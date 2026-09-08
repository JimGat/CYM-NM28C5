// NM-CYD-C5 (NerdMiner ESP32-C5 CYD) pin definitions and board constants.
//
// Board: NM-CYD-C5 with NM-RF-HAT FPC2 expansion connector
// SoC:   ESP32-C5-WROOM-1-N168R, RISC-V 240 MHz
// Flash: 16 MB | PSRAM: 8 MB | WiFi 6 (2.4 + 5 GHz) | BT 5
// Ref:   https://github.com/RockBase-iot/NM-CYD-C5
//        See also: NM-CYD-C5-pinmap.md (project root)
#pragma once

// ── SPI bus ───────────────────────────────────────────────────────────────────
// SPI2_HOST is shared by ST7789 (LCD), XPT2046 (touch), and SD card.
// Each device has its own CS line. sd_spi_mutex in main.c serializes SD access.
#define BOARD_SPI_HOST       SPI2_HOST
#define BOARD_SPI_SCK        6    // Strapping pin — safe after boot
#define BOARD_SPI_MOSI       7    // Strapping pin — safe after boot
#define BOARD_SPI_MISO       2    // SD + touch (display is write-only)

// ── ST7789 display ────────────────────────────────────────────────────────────
#define BOARD_LCD_CS         23
#define BOARD_LCD_DC         24
#define BOARD_LCD_RST        -1   // Tied to board RST/EN — not a GPIO
#define BOARD_LCD_WIDTH      240
#define BOARD_LCD_HEIGHT     320
// Backlight: GPIO25 HIGH = on. No PWM — software black overlay for dimming.
#define BOARD_BACKLIGHT_GPIO 25   // Strapping pin — safe after boot

// ── XPT2046 resistive touch ────────────────────────────────────────────────
// Polling only — T_IRQ is not connected on NM-CYD-C5.
// Calibration required on first boot (NVS namespace "touch_cal", magic 0xCA15).
// Use position-compensated pressure: Z1 + 4095 - Z2, threshold ≥ 100.
#define BOARD_TOUCH_CS       1
#define BOARD_TOUCH_INT      -1   // Not connected

// ── SD card ───────────────────────────────────────────────────────────────────
// Shares SPI2_HOST. Gated by sd_spi_mutex. GPIO10 also passes through FPC2.
#define BOARD_SD_CS          10

// ── WS2812 RGB LED (NeoPixel) ─────────────────────────────────────────────────
// Driven via RMT. Single LED. Color = status indicator.
#define BOARD_RGB_LED_GPIO   27
#define BOARD_RGB_LED_COUNT  1

// ── ERM vibrator motor ────────────────────────────────────────────────────────
// Driven via SC8002B audio amp BTL output. 50 % duty max (half-wave rectified).
// LEDC_TIMER_2 / LEDC_CHANNEL_4 / 333 Hz / 8-bit. See CLAUDE.md for circuit.
#define BOARD_VIBRATOR_GPIO  26

// ── Boot button ───────────────────────────────────────────────────────────────
// BOOT/GPIO28. Active-low (pulled up). Used as Go-Dark wake button.
#define BOARD_BOOT_BTN_GPIO  28

// ── GPS UART (LP-UART) ────────────────────────────────────────────────────────
// Optional external GPS module on LP-UART1.
#define BOARD_GPS_UART_NUM   UART_NUM_1
#define BOARD_GPS_TX_GPIO    5
#define BOARD_GPS_RX_GPIO    4

// ── NM-RF-HAT control signals ─────────────────────────────────────────────────
// GPIO8 (IO22) = signal A: GDO0 (CC1101), CE (nRF24), SCL (PN532), TX (IR/433)
// GPIO9 (IO27) = signal B: CSN (CC1101), CSN (nRF24), SDA (PN532), RX (IR/433)
// These ride on FPC2 and share GPIO8/GPIO9 with ALL five RF peripherals.
// DIP switches cut VCC to inactive peripherals — no software mux needed.
#define BOARD_RFHAT_PIN_A    8    // IO22 in board documentation
#define BOARD_RFHAT_PIN_B    9    // IO27 in board documentation

// ── I2C (not used natively on NM-CYD-C5 — PN532 on RF-HAT uses GPIO8/9) ─────
#define BOARD_I2C_SDA        -1   // No primary I2C bus on NM-CYD-C5
#define BOARD_I2C_SCL        -1

// ── Board identifier string ───────────────────────────────────────────────────
#define BOARD_NAME           "NM-CYD-C5"
#define BOARD_DISPLAY_DRIVER "ST7789"
#define BOARD_TOUCH_DRIVER   "XPT2046"
