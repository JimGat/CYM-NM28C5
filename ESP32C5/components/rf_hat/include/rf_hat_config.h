#pragma once

// =============================================================================
// NM-RF-HAT — hardware pin configuration for NM-CYD-C5
// =============================================================================
// GPIO assignments verified against SCH_NM-RF-HAT_v1.0.pdf and
// SCH_NM-CYD-C5-v1.0.pdf (RockBase-iot GitHub).
//
// FPC2 connector (RF-HAT) → NM-CYD-C5 GPIO translation:
//
//  FPC2 Pin | RF-HAT label | NM-CYD-C5 GPIO | Role on RF-HAT
//  ---------+--------------+----------------+----------------------------
//      1    | IO19         | GPIO2          | SPI MISO (shared bus)
//      2    | IO18         | GPIO6          | SPI CLK  (shared bus)
//      3    | IO23         | GPIO7          | SPI MOSI (shared bus)
//      4    | IO5          | GPIO10         | SPI CS — SD card (always SD)
//      5    | GND          | GND            |
//      6    | IO21         | GPIO4          | not used by any HAT module
//      7    | IO22         | GPIO8          | multi-role (see DIP table)
//      8    | IO35         | GPIO5          | not used by any HAT module
//      9    | IO27         | GPIO9          | multi-role (see DIP table)
//     10    | USB D-       | USB D-         |
//     11    | USB D+       | USB D+         |
//    12-14  | GND          | GND            |
//
// GPIO8 (IO22) and GPIO9 (IO27) are the only data GPIOs for all 5 modules.
// DIP switches cut module power — mutual exclusion is enforced in hardware.
// The SPI shared bus (GPIO2/6/7) is also used by the on-board display and SD.
//
//  DIP | Module          | GPIO8 (IO22)        | GPIO9 (IO27)
//  ----+-----------------+---------------------+--------------------
//   1  | CC1101 Sub-GHz  | GDO0 (interrupt)    | CSN (SPI CS)
//   2  | nRF24L01 2.4GHz | CE (chip enable)    | CSN (SPI CS)
//   3  | PN532 NFC/RFID  | SCL (I2C clock)     | SDA (I2C data)  ← per schematic
//   4  | IR Infrared     | IR_DT (TX emitter)  | IR_DR (RX detector) ← confirmed by LED
//   5  | RF433 OOK/ASK   | 433_DT (TX to air)  | 433_DR (RX from air) ← same nets as IR
//   6  | Battery switch  | (not a module)      |
// =============================================================================

// ── IR (DIP 4) ───────────────────────────────────────────────────────────────
// IR_DT = IR transmit drive (ESP32→IR LED transistor), IR_DR = demodulated RX
// Empirically confirmed: emitter (green LED) is on GPIO8, detector (blue LED) on GPIO9.
// Swapped from initial guess: GPIO8=TX, GPIO9=RX.
#ifndef RF_HAT_IR_TX_GPIO
#define RF_HAT_IR_TX_GPIO    8   // FPC2 Pin 7 — emitter (confirmed by LED observation)
#endif
#ifndef RF_HAT_IR_RX_GPIO
#define RF_HAT_IR_RX_GPIO    9   // FPC2 Pin 9 — detector (confirmed by LED observation)
#endif

// ── RF433 OOK/ASK (DIP 5) ────────────────────────────────────────────────────
// 433_DT = OOK TX drive (ESP32→module), 433_DR = OOK RX output (module→ESP32)
// Shares GPIO8/9 with IR via DIP-enforced power exclusion — swapped to match IR.
#ifndef RF_HAT_RF433_TX_GPIO
#define RF_HAT_RF433_TX_GPIO 8   // FPC2 Pin 7 — same net as IR_DT (TX)
#endif
#ifndef RF_HAT_RF433_RX_GPIO
#define RF_HAT_RF433_RX_GPIO 9   // FPC2 Pin 9 — same net as IR_DR (RX)
#endif

// ── CC1101 Sub-GHz SPI (DIP 1) ───────────────────────────────────────────────
// Shares SPI bus (GPIO2/6/7) with display and SD. CS and GDO0 on GPIO9/8.
#ifndef RF_HAT_CC1101_CS_GPIO
#define RF_HAT_CC1101_CS_GPIO    9   // IO27, FPC2 Pin 9 (CSN_CC1101)
#endif
#ifndef RF_HAT_CC1101_GDO0_GPIO
#define RF_HAT_CC1101_GDO0_GPIO  8   // IO22, FPC2 Pin 7 (GDO0_CC1101)
#endif

// ── nRF24L01 SPI (DIP 2) ─────────────────────────────────────────────────────
// CSN shares GPIO9 with CC1101 — DIP-exclusive so no bus conflict.
// CE is GPIO8 (IO22 → NRF24_CE per schematic).
#ifndef RF_HAT_NRF24_CS_GPIO
#define RF_HAT_NRF24_CS_GPIO  9   // IO27, FPC2 Pin 9 (NRF24_CSN)
#endif
#ifndef RF_HAT_NRF24_CE_GPIO
#define RF_HAT_NRF24_CE_GPIO  8   // IO22, FPC2 Pin 7 (NRF24_CE)
#endif

// ── PN532 NFC/RFID I2C (DIP 3) ───────────────────────────────────────────────
// Matches schematic: GPIO8 (IO22, FPC2 Pin 7) = SCL, GPIO9 (IO27, FPC2 Pin 9) = SDA.
// Note: IR/RF433 nets are empirically swapped vs schematic, but PN532 follows schematic.
#ifndef RF_HAT_PN532_SCL_GPIO
#define RF_HAT_PN532_SCL_GPIO 8   // IO22, FPC2 Pin 7 — SCL (matches schematic)
#endif
#ifndef RF_HAT_PN532_SDA_GPIO
#define RF_HAT_PN532_SDA_GPIO 9   // IO27, FPC2 Pin 9 — SDA (matches schematic)
#endif

// ── SD card directories created by rf_hat modules ────────────────────────────
#define RF_HAT_IR_SAVE_DIR     "/sdcard/lab/infrared"
#define RF_HAT_RF433_SAVE_DIR  "/sdcard/lab/rf433"
#define RF_HAT_RADIO_SAVE_DIR  "/sdcard/lab/radio"
#define RF_HAT_RFID_SAVE_DIR   "/sdcard/lab/rfid"

// ── NVS ──────────────────────────────────────────────────────────────────────
// The rf_hat_enabled flag lives in the main "settings" NVS namespace so it
// loads with the rest of user settings in nvs_settings_load().
#define RF_HAT_NVS_NAMESPACE  "settings"
#define RF_HAT_NVS_KEY        "rf_hat"     // u8: 0=disabled, 1=enabled
