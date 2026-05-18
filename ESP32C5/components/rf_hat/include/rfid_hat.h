#pragma once
// =============================================================================
// rfid_hat — PN532 NFC/RFID scaffold for NM-RF-HAT (DIP switch position 3)
// =============================================================================
// PN532 connects via I2C on CN1 connector (GPIO 8 SCL, GPIO 9 SDA).
//
// Planned capabilities:
//   - Scan / read card (ISO14443A/B, Mifare Classic, Mifare Ultralight, NTAG, FeliCa)
//   - Dump UID and sector data
//   - Write / clone card
//   - Card emulation (virtual Mifare / NTAG)
//   - Brute-force Mifare Classic sector keys
//
// TODO: Implement PN532 I2C driver and card protocol handlers.
// =============================================================================

#include <stdint.h>
#include <stdbool.h>

typedef enum {
    RFID_HAT_OK = 0,
    RFID_HAT_ERR_NOT_IMPL,
    RFID_HAT_ERR_HW,
    RFID_HAT_ERR_NO_CARD,
    RFID_HAT_ERR_AUTH,
} rfid_hat_err_t;

typedef struct {
    uint8_t  uid[10];
    uint8_t  uid_len;
    uint16_t atqa;
    uint8_t  sak;
    char     type_str[16];   // "Mifare Classic", "NTAG213", etc.
} rfid_card_t;

rfid_hat_err_t rfid_hat_init(void);
void           rfid_hat_deinit(void);
bool           rfid_hat_is_impl(void);
rfid_hat_err_t rfid_hat_scan(rfid_card_t *card_out, uint32_t timeout_ms);
const char    *rfid_hat_err_str(rfid_hat_err_t err);
