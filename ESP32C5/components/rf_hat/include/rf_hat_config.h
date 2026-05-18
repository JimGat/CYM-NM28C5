#pragma once

// =============================================================================
// NM-RF-HAT — hardware pin configuration for NM-CYD-C5
// =============================================================================
// The NM-RF-HAT connects to the NM-CYD-C5 via its expansion connector.
// TODO: Confirm GPIO assignments from NM-RF-HAT v1.0 schematic (SCH_NM-RF-HAT_v1.0.pdf).
//       These are placeholder assignments using free GPIOs on the NM-CYD-C5.
//       Free GPIOs: 3, 15, 21 (all others are occupied by SPI/display/LED/amp/GPS).
//
// Janos portability: override these defines in your board header before including
// this file, or edit here for your target platform.
// =============================================================================

// ── DIP switch mapping (informational — no GPIO read; user sets manually) ────
//   DIP 1 ON → CC1101 Sub-GHz
//   DIP 2 ON → nRF24L01 2.4 GHz
//   DIP 3 ON → PN532 NFC/RFID
//   DIP 4 ON → IR Infrared TX/RX
//   DIP 5 ON → RF433 OOK/ASK
//   DIP 6 ON → Battery power switch (not a module)

// ── IR (DIP 4) ───────────────────────────────────────────────────────────────
#ifndef RF_HAT_IR_TX_GPIO
#define RF_HAT_IR_TX_GPIO    3   // TODO: verify from schematic
#endif
#ifndef RF_HAT_IR_RX_GPIO
#define RF_HAT_IR_RX_GPIO    15  // TODO: verify from schematic
#endif

// ── RF433 OOK/ASK (DIP 5) ────────────────────────────────────────────────────
// IR and RF433 are mutually exclusive via DIP switch, so TX pins can be shared.
#ifndef RF_HAT_RF433_TX_GPIO
#define RF_HAT_RF433_TX_GPIO 3   // TODO: verify from schematic (may share with IR TX)
#endif
#ifndef RF_HAT_RF433_RX_GPIO
#define RF_HAT_RF433_RX_GPIO 15  // TODO: verify from schematic (may share with IR RX)
#endif

// ── CC1101 Sub-GHz SPI (DIP 1) ───────────────────────────────────────────────
// CC1101 uses SPI. On NM-CYD-C5 the SPI bus (GPIO 2/6/7) is shared with display/SD.
// CC1101 can share the bus with a dedicated CS pin.
#ifndef RF_HAT_CC1101_CS_GPIO
#define RF_HAT_CC1101_CS_GPIO 21  // TODO: verify from schematic
#endif
#ifndef RF_HAT_CC1101_GDO0_GPIO
#define RF_HAT_CC1101_GDO0_GPIO -1 // TODO: verify or leave unconnected
#endif

// ── nRF24L01 SPI (DIP 2) ─────────────────────────────────────────────────────
#ifndef RF_HAT_NRF24_CS_GPIO
#define RF_HAT_NRF24_CS_GPIO  21  // TODO: verify (distinct CS from CC1101)
#endif
#ifndef RF_HAT_NRF24_CE_GPIO
#define RF_HAT_NRF24_CE_GPIO  -1  // TODO: verify
#endif

// ── PN532 I2C (DIP 3) ────────────────────────────────────────────────────────
// PN532 uses I2C on the CN1 connector (GPIO 8/9 on NM-CYD-C5)
#ifndef RF_HAT_PN532_SDA_GPIO
#define RF_HAT_PN532_SDA_GPIO 9   // CN1 pin 2 — confirmed available
#endif
#ifndef RF_HAT_PN532_SCL_GPIO
#define RF_HAT_PN532_SCL_GPIO 8   // CN1 pin 3 — confirmed available
#endif

// ── SD card directories created by rf_hat modules ────────────────────────────
#define RF_HAT_IR_SAVE_DIR     "/sdcard/lab/ir"
#define RF_HAT_RF433_SAVE_DIR  "/sdcard/lab/rf433"
#define RF_HAT_RADIO_SAVE_DIR  "/sdcard/lab/radio"
#define RF_HAT_RFID_SAVE_DIR   "/sdcard/lab/rfid"

// ── NVS ──────────────────────────────────────────────────────────────────────
// The rf_hat_enabled flag lives in the main "settings" NVS namespace so it
// loads with the rest of user settings in nvs_settings_load().
#define RF_HAT_NVS_NAMESPACE  "settings"
#define RF_HAT_NVS_KEY        "rf_hat"     // u8: 0=disabled, 1=enabled
