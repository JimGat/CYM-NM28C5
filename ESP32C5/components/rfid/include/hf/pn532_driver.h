#pragma once
// =============================================================================
// pn532_driver — low-level PN532 I2C frame protocol (NM-RF-HAT DIP 3)
// =============================================================================
// GPIO: SCL = RF_HAT_PN532_SCL_GPIO (8), SDA = RF_HAT_PN532_SDA_GPIO (9)
// I2C address: 0x24, 100 kHz
//
// Frame format (write):
//   0x00 0x00 0xFF [LEN] [LCS] 0xD4 [CMD] [data...] [DCS] 0x00
//   LCS = ~LEN + 1, DCS = ~sum(0xD4 + CMD + data) + 1
//
// Frame format (read, prefixed by 1-byte RDY status):
//   [0x01] 0x00 0x00 0xFF [LEN] [LCS] 0xD5 [CMD+1] [data...] [DCS] 0x00
//
// ACK (6 bytes after RDY byte): 0x00 0x00 0xFF 0x00 0xFF 0x00
// =============================================================================

#include <stdint.h>
#include <stdbool.h>
#include "rfid_types.h"

// ── Lifecycle ─────────────────────────────────────────────────────────────────
rfid_err_t pn532_driver_init(void);
void       pn532_driver_deinit(void);
bool       pn532_driver_is_init(void);

// ── SAM configuration ─────────────────────────────────────────────────────────
// Must be called after init before any card operations.
// Normal mode (0x01), no timeout, no IRQ output.
rfid_err_t pn532_sam_configure(void);

// ── RF field control ──────────────────────────────────────────────────────────
rfid_err_t pn532_rf_field_on(void);
rfid_err_t pn532_rf_field_off(void);

// ── Firmware probe ────────────────────────────────────────────────────────────
typedef struct {
    uint8_t ic;       // IC identifier (always 3 for PN532)
    uint8_t ver;      // firmware version
    uint8_t rev;      // firmware revision
    uint8_t support;  // supported features bitmask
} pn532_fw_version_t;

rfid_err_t pn532_get_firmware_version(pn532_fw_version_t *out);

// ── Low-level frame I/O (used by pn532_reader / mifare_classic) ──────────────
#define PN532_MAX_FRAME_DATA  264

rfid_err_t pn532_send_command(const uint8_t *cmd, uint8_t cmd_len);
rfid_err_t pn532_read_response(uint8_t expected_cmd, uint8_t *buf, uint8_t *buf_len,
                                uint8_t buf_max, uint32_t timeout_ms);
