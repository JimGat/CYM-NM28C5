#pragma once
// =============================================================================
// CYD2USB — ESP32-2432S028R "Cheap Yellow Display" (dual-USB variant)
// SoC:   ESP32 (Xtensa LX6 dual-core, 240 MHz), 4 MB flash, no PSRAM
// LCD:   ILI9341 2.8" 240x320 portrait, SPI on VSPI (SPI3_HOST)
// Touch: XPT2046 resistive SPI, CS on GPIO33, IRQ GPIO36 (input-only ADC pin)
// SD:    Separate HSPI (SPI2_HOST) bus — GPIO18/SCK, GPIO23/MOSI, GPIO19/MISO
// LED:   Common-anode RGB, active-LOW: R=GPIO4, G=GPIO16, B=GPIO17
// Note:  T_IRQ (GPIO36) is an input-only ADC pin — cannot drive it; touch uses
//        polling mode only (same as NM-CYD-C5, which has T_IRQ unconnected).
// =============================================================================

// ── Display (ILI9341 on VSPI / SPI3_HOST) ────────────────────────────────────
#define BOARD_LCD_CS            15
#define BOARD_LCD_DC             2
#define BOARD_LCD_RST           -1    // tied to EN via RC
#define BOARD_BACKLIGHT_GPIO    21    // HIGH = on
#define BOARD_SPI_HOST          SPI3_HOST   // VSPI: display + touch
#define BOARD_SPI_SCK           14
#define BOARD_SPI_MOSI          13
#define BOARD_SPI_MISO          12

// ── Touch (XPT2046 on same VSPI bus as display) ───────────────────────────────
#define BOARD_TOUCH_CS          33
// GPIO36 is input-only (SENSOR_VP); used as analog IRQ — not configured as GPIO
#define BOARD_TOUCH_IRQ         36

// ── SD card (HSPI / SPI2_HOST — separate bus) ────────────────────────────────
#define BOARD_SD_SPI_HOST       SPI2_HOST   // HSPI: SD card only
#define BOARD_SD_SCK            18
#define BOARD_SD_MOSI           23
#define BOARD_SD_MISO           19
#define BOARD_SD_CS              5

// ── RGB LED (common-anode, active-LOW) ────────────────────────────────────────
// All three channels idle HIGH (LED off). Drive LOW to light that color.
#define BOARD_LED_R_GPIO         4
#define BOARD_LED_G_GPIO        16
#define BOARD_LED_B_GPIO        17

// ── Misc ──────────────────────────────────────────────────────────────────────
#define BOARD_BOOT_BTN_GPIO      0    // boot / user button
#define BOARD_BUZZER_GPIO       26    // passive buzzer (GPIO26 = same as NM-CYD-C5 vibrator)

// ── Display dimensions ────────────────────────────────────────────────────────
#define BOARD_LCD_WIDTH        240
#define BOARD_LCD_HEIGHT       320

// ── NM-RF-HAT via SD Card Shim (CONFIG_BOARD_HAS_RF_HAT=y build only) ─────────
// The SD Card Shim sits in the Classic CYD's microSD slot and routes the HSPI
// SPI bus (GPIO18/SCK, GPIO23/MOSI, GPIO19/MISO, GPIO5/CS) to the NM-RF-HAT's
// FPC2 connector. SD card is relocated to the RF-HAT onboard SD socket.
//
// After the shim, BOARD_SD_SCK/MOSI/MISO/CS defined above become the RF-HAT SPI
// bus. The RF-HAT SPI host stays SPI2_HOST (HSPI).
//
// BOARD_RFHAT_PIN_A and BOARD_RFHAT_PIN_B are the GPIO equivalents of GPIO8
// (IO22) and GPIO9 (IO27) on NM-CYD-C5 — the two control lines shared by all
// five RF-HAT modules (CC1101, nRF24, PN532, IR, RF433). These route from
// FPC2 pins 7 and 9 through the shim to free GPIOs on the Classic CYD.
// *** GPIO ASSIGNMENTS PENDING CONFIRMATION FROM HALEHOUND SCHEMATIC ***
#define BOARD_RFHAT_PIN_A       -1    // TODO: confirm from Halehound shim wiring
#define BOARD_RFHAT_PIN_B       -1    // TODO: confirm from Halehound shim wiring

// ── Not present on CYD2USB ───────────────────────────────────────────────────
#define BOARD_VIBRATOR_GPIO     -1
#define BOARD_RGB_LED_GPIO      -1    // no WS2812; has discrete RGB instead
#define BOARD_RGB_LED_COUNT      0
#define BOARD_GPS_TX_GPIO       -1
#define BOARD_GPS_RX_GPIO       -1
#define BOARD_I2C_SDA           -1
#define BOARD_I2C_SCL           -1

// ── Board identifier strings ──────────────────────────────────────────────────
#define BOARD_NAME             "CYD2USB"
#define BOARD_DISPLAY_DRIVER   "ILI9341"
#define BOARD_TOUCH_DRIVER     "XPT2046"
