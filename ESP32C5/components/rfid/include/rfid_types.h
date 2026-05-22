#pragma once
// =============================================================================
// rfid_types — canonical card representation for HF (13.56 MHz) and LF (125 kHz)
// =============================================================================
// Internal format.  Flipper .nfc / .rfid adapters in flipper_nfc_file.h
// and flipper_lf_file.h translate to/from this struct.
// =============================================================================

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// ── Band ─────────────────────────────────────────────────────────────────────
typedef enum {
    RFID_BAND_HF = 0,  // 13.56 MHz  (PN532, ISO14443, NFC)
    RFID_BAND_LF,      // 125 kHz    (EM4100, HID, etc. — future hardware)
} rfid_band_t;

// ── HF Technology (ISO layer) ─────────────────────────────────────────────────
typedef enum {
    RFID_TECH_NONE = 0,
    RFID_TECH_ISO14443A,    // NFC-A  (MIFARE, NTAG, many access cards)
    RFID_TECH_ISO14443B,    // NFC-B  (some bank/ID cards)
    RFID_TECH_FELICA,       // Sony FeliCa (Japan transit)
    RFID_TECH_ISO15693,     // NFC-V  (longer range tags)
    // LF types — add as hardware arrives
    RFID_TECH_EM4100,
    RFID_TECH_HID_PROX,
    RFID_TECH_INDALA,
} rfid_technology_t;

// ── Protocol (Application layer) ─────────────────────────────────────────────
typedef enum {
    RFID_PROTO_UNKNOWN = 0,
    // HF
    RFID_PROTO_ISO14443_UID_ONLY,   // plain UID, no higher protocol read
    RFID_PROTO_MIFARE_CLASSIC_1K,
    RFID_PROTO_MIFARE_CLASSIC_4K,
    RFID_PROTO_MIFARE_ULTRALIGHT,
    RFID_PROTO_MIFARE_PLUS,
    RFID_PROTO_NTAG213,
    RFID_PROTO_NTAG215,
    RFID_PROTO_NTAG216,
    RFID_PROTO_ISO14443_4,          // smart-card / ISO7816
    RFID_PROTO_DESFIRE,
    // LF
    RFID_PROTO_EM4100,
    RFID_PROTO_HID_26BIT,
    RFID_PROTO_HID_35BIT,
    RFID_PROTO_INDALA,
} rfid_protocol_t;

// ── Limits ───────────────────────────────────────────────────────────────────
#define RFID_MAX_UID_LEN       10   // bytes
#define RFID_MAX_BLOCKS       256   // MIFARE Classic 4K has 255 blocks (block 0..254)
#define RFID_BLOCK_LEN         16   // bytes per block (ISO14443A / MIFARE)
#define RFID_MAX_KEYS          32   // key entries stored per card
#define RFID_CARD_NAME_LEN     48   // user-visible save name
#define RFID_FILENAME_LEN      80   // full path
#define RFID_MAX_SAVED_CARDS   64

// ── MIFARE key ────────────────────────────────────────────────────────────────
typedef enum { MIFARE_KEY_A = 0, MIFARE_KEY_B = 1 } mifare_key_type_t;

typedef struct {
    uint8_t          sector;
    mifare_key_type_t type;
    uint8_t          key[6];
    bool             valid;
} rfid_sector_key_t;

// ── Block data store ──────────────────────────────────────────────────────────
typedef struct {
    uint8_t data[RFID_BLOCK_LEN];
    bool    valid;       // false if not yet read / auth failed
} rfid_block_t;

// ── Full card record ──────────────────────────────────────────────────────────
typedef struct {
    // Identity
    char              name[RFID_CARD_NAME_LEN];  // user label ("save name")
    rfid_band_t       band;
    rfid_technology_t technology;
    rfid_protocol_t   protocol;
    char              protocol_str[24];           // human-readable, e.g. "MIFARE Classic 1K"

    // ISO14443A fields
    uint8_t  uid[RFID_MAX_UID_LEN];
    uint8_t  uid_len;
    uint16_t atqa;       // ATQA response (2 bytes)
    uint8_t  sak;        // SAK byte

    // Memory image (HF only)
    uint16_t      block_count;
    rfid_block_t  blocks[RFID_MAX_BLOCKS];

    // NTAG/Ultralight pages (alias of blocks for page-oriented cards)
    uint16_t page_count;    // set if NTAG/UL; same storage as blocks[]

    // Discovered sector keys
    rfid_sector_key_t keys[RFID_MAX_KEYS];
    uint8_t           key_count;

    // LF raw data (placeholder)
    uint8_t  lf_raw[16];
    uint8_t  lf_raw_len;
    uint32_t lf_facility_code;
    uint32_t lf_card_number;

    // Provenance
    char     source[16];      // "scan", "import", "manual"
    char     timestamp[20];   // ISO8601
} rfid_card_t;

// ── Emulation status (used by pn532_target / rfid_manager) ───────────────────
typedef enum {
    RFID_EMU_WAITING,   // listening for reader
    RFID_EMU_ACTIVE,    // reader is interacting
    RFID_EMU_DONE,      // ended cleanly (stop requested)
    RFID_EMU_ERROR,     // hardware error
} rfid_emu_status_t;

typedef void (*rfid_emu_cb_t)(rfid_emu_status_t status, void *ctx);

// ── Error codes ───────────────────────────────────────────────────────────────
typedef enum {
    RFID_OK = 0,
    RFID_ERR_NOT_INIT,
    RFID_ERR_HW,           // I2C / PN532 communication error
    RFID_ERR_NO_CARD,      // scan timeout, no card in field
    RFID_ERR_COLLISION,    // multiple cards detected simultaneously
    RFID_ERR_AUTH,         // MIFARE auth failed (wrong key)
    RFID_ERR_NAK,          // card replied NAK
    RFID_ERR_IO,           // SD card read/write error
    RFID_ERR_NOT_FOUND,    // file or card not found
    RFID_ERR_FULL,         // storage full
    RFID_ERR_NOT_SUPPORTED,// feature/card type not yet supported
    RFID_ERR_TIMEOUT,
} rfid_err_t;

// ── Helpers ───────────────────────────────────────────────────────────────────
const char *rfid_band_str(rfid_band_t band);
const char *rfid_technology_str(rfid_technology_t tech);
const char *rfid_protocol_str(rfid_protocol_t proto);
const char *rfid_err_str(rfid_err_t err);

// Format UID bytes as "AB CD EF 12" (Flipper-style space-separated hex)
void rfid_format_uid(const uint8_t *uid, uint8_t uid_len, char *buf, size_t buf_size);

// Format UID as compact "ABCDEF12" for filenames
void rfid_format_uid_compact(const uint8_t *uid, uint8_t uid_len, char *buf, size_t buf_size);
