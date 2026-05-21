#pragma once
// =============================================================================
// flipper_lf_file — Flipper Zero .rfid format adapter (LF 125 kHz)
// =============================================================================
// Flipper .rfid format:
//   Filetype: Flipper RFID key
//   Version: 1
//   Key type: HID26      (or EM4100, HID35, Indala64, Indala224, etc.)
//   Data: 00 00 00 00 00
//
// Stub only — no LF hardware present.
// Compile-time placeholder so LF paths exist in menus and storage without
// requiring a real reader.  Replace lf_stub.c with a real driver when hardware arrives.
// =============================================================================

#include "rfid_types.h"

// Export card to Flipper .rfid format.
// Returns RFID_ERR_NOT_SUPPORTED if band != RFID_BAND_LF.
rfid_err_t flipper_lf_export(const rfid_card_t *card, const char *path);

// Import a Flipper .rfid file.
// Returns RFID_ERR_NOT_SUPPORTED until a real LF reader is integrated.
rfid_err_t flipper_lf_import(const char *path, rfid_card_t *card_out);

// Auto-generate a filename from card data.
void flipper_lf_make_filename(const rfid_card_t *card, char *buf, size_t buf_size);
