#pragma once
// =============================================================================
// flipper_nfc_file — Flipper Zero .nfc format adapter
// =============================================================================
// Supports Flipper NFC device file format (Version 4):
//   - ISO14443-3A (UID-only)
//   - MIFARE Classic 1K / 4K (with block data if available)
//   - NTAG/Ultralight (page data if available)
//
// File example (UID-only):
//   Filetype: Flipper NFC device
//   Version: 4
//   Device type: ISO14443-3A
//   UID: AB CD EF 12
//   ATQA: 00 04
//   SAK: 08
//
// File example (MIFARE Classic 1K):
//   Filetype: Flipper NFC device
//   Version: 4
//   Device type: MIFARE Classic
//   UID: AB CD EF 12
//   ATQA: 00 04
//   SAK: 08
//   Mifare Classic type: 1K
//   Data format version: 2
//   Block 0: AB CD EF 12 34 56 78 90 AB CD EF 12 34 56 78 90
//   ...
//   Block 63: FF FF FF FF FF FF 08 77 8F 00 00 00 00 00 00 00
// =============================================================================

#include "rfid_types.h"

// Export card to Flipper .nfc format.
// path: full path including filename, e.g. "/sdcard/lab/rfid/export/MyCard.nfc"
rfid_err_t flipper_nfc_export(const rfid_card_t *card, const char *path);

// Import a Flipper .nfc file into a card struct.
// path: full path to .nfc file (in import/ or on SD anywhere).
rfid_err_t flipper_nfc_import(const char *path, rfid_card_t *card_out);

// Auto-generate a Flipper-compatible filename from the card UID.
// buf: caller-provided buffer, size >= 48.
void flipper_nfc_make_filename(const rfid_card_t *card, char *buf, size_t buf_size);
