#pragma once
// =============================================================================
// mifare_classic — MIFARE Classic 1K/4K sector key auth, block read/write
// =============================================================================
// All operations require a card to be selected (pn532_scan_card called first).
// Auth must succeed for a sector before its blocks can be read or written.
//
// MIFARE Classic 1K:  16 sectors × 4 blocks  = 64 blocks  (blocks 0–63)
// MIFARE Classic 4K:  32 sectors × 4 blocks  = 128 blocks (sectors 0–31)
//                  +  8 sectors × 16 blocks  = 128 blocks (sectors 32–39)
//                  Total: 256 blocks (blocks 0–255)
// =============================================================================

#include "rfid_types.h"

// Number of sectors for each card type
#define MIFARE_1K_SECTORS   16
#define MIFARE_4K_SECTORS   40

// ── Authentication ────────────────────────────────────────────────────────────
// Authenticate a sector using Key A or Key B.
// uid[] / uid_len: from pn532_scan_card result.
rfid_err_t mifare_auth_sector(uint8_t sector, mifare_key_type_t key_type,
                               const uint8_t key[6],
                               const uint8_t *uid, uint8_t uid_len);

// ── Block I/O ─────────────────────────────────────────────────────────────────
rfid_err_t mifare_read_block(uint8_t block, uint8_t data[RFID_BLOCK_LEN]);
rfid_err_t mifare_write_block(uint8_t block, const uint8_t data[RFID_BLOCK_LEN]);

// ── Bulk read ─────────────────────────────────────────────────────────────────
// Attempt to read all blocks of the card using the given key dict.
// For each sector, tries Key A first then Key B across key_count entries.
// Populates card->blocks[] and card->keys[].
// Returns RFID_OK even if some sectors fail (check block.valid flags).
rfid_err_t mifare_read_all(rfid_card_t *card,
                            const uint8_t (*key_dict)[6], uint8_t key_count);

// ── Default key dictionary ────────────────────────────────────────────────────
// Standard factory/common keys for authorized testing on own cards.
extern const uint8_t MIFARE_DEFAULT_KEYS[][6];
extern const uint8_t MIFARE_DEFAULT_KEY_COUNT;

// ── Helpers ───────────────────────────────────────────────────────────────────
// Block number of the sector trailer (last block of sector).
uint8_t mifare_sector_trailer_block(uint8_t sector);

// First block of a sector.
uint8_t mifare_sector_first_block(uint8_t sector);

// Number of blocks in a sector (4 for sectors 0-31, 16 for sectors 32-39 on 4K).
uint8_t mifare_sector_block_count(uint8_t sector);

// Extract Key A, Key B, and access bits from a sector trailer block.
void mifare_parse_trailer(const uint8_t trailer[RFID_BLOCK_LEN],
                          uint8_t key_a[6], uint8_t key_b[6],
                          uint8_t access_bits[3]);
