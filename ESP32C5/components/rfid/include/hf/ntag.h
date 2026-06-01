#pragma once
// =============================================================================
// ntag — NTAG21x / Ultralight page read, write, and clone via PN532 InDataExchange
// =============================================================================
// All operations require a card to already be selected (pn532_scan_card returned RFID_OK).
// Follows the same style as mifare_classic.h.
//
// NTAG213 page layout (45 pages × 4 bytes = 180 bytes):
//   Pages 0–1 : UID + BCC (OTP on genuine NXP tags, writable on Magic/CUID)
//   Page  2   : BCC1, INT, LOCK0, LOCK1
//   Page  3   : Capability Container (CC) — OTP on genuine tags
//   Pages 4–39: User data (144 bytes)
//   Pages 40–44: CFG0, CFG1, PWD, PACK, reserved
//
// For clone to a genuine NTAG, skip_below=4 writes only user data pages.
// For Magic/CUID blank cards, skip_below=0 writes all pages including UID.
// =============================================================================

#include "rfid_types.h"

// ── Pure logic helpers (no I2C, fully unit-testable) ─────────────────────────

// Derive NTAG protocol from 8-byte GET_VERSION response.
// Returns RFID_PROTO_UNKNOWN if bytes do not match any known NTAG variant.
rfid_protocol_t ntag_protocol_from_version(const uint8_t version[8]);

// Return total page count for an NTAG/UL protocol value.
// Returns 0 for non-NTAG protocols.
uint16_t ntag_page_count_for_protocol(rfid_protocol_t proto);

// ── PN532 InDataExchange wrappers ─────────────────────────────────────────────

// GET_VERSION (0x60): reads 8-byte version info identifying NTAG213/215/216.
// Returns RFID_ERR_NAK if the card does not support this command (e.g. plain UL).
rfid_err_t ntag_get_version(uint8_t version[8]);

// READ (0x30): reads 4 pages (16 bytes) starting at start_page.
// out16 must point to a 16-byte buffer.
rfid_err_t ntag_read_pages(uint8_t start_page, uint8_t out16[16]);

// FAST_READ (0x3A): reads pages [start_page..end_page] in one command.
// out must be large enough for (end_page - start_page + 1) * 4 bytes.
// Falls back to repeated ntag_read_pages() on command failure (card NAK).
rfid_err_t ntag_fast_read(uint8_t start_page, uint8_t end_page,
                           uint8_t *out, uint16_t out_max, uint16_t *out_len);

// WRITE (0xA2): writes 4 bytes to one page.
// Pages 0–3 are OTP/manufacturer on genuine tags; use skip_below=4 to avoid them.
rfid_err_t ntag_write_page(uint8_t page, const uint8_t data[4]);

// READ_CNT (0x39): read one of the 3 NFC counter registers (counter_no 0–2).
// value_out receives the 24-bit counter value (LSB-first in wire format).
rfid_err_t ntag_read_counter(uint8_t counter_no, uint32_t *value_out);

// PWD_AUTH (0x1B): present a 4-byte password; on success pack_out[2] = PACK.
rfid_err_t ntag_pwd_auth(const uint8_t pwd[4], uint8_t pack_out[2]);

// ── Full card operations ──────────────────────────────────────────────────────

// Read all pages into card->blocks[].
// Calls GET_VERSION to confirm/refine card->protocol and card->page_count,
// then reads all pages with READ (0x30) in 4-page strides.
// card must already have uid/protocol populated by pn532_scan_card().
// Returns RFID_OK if at least the first read succeeds (partial reads are logged).
rfid_err_t ntag_read_all(rfid_card_t *card);

// Clone: write src pages [skip_below .. src->page_count) to the currently
// selected blank card. Pages with valid=false in src are skipped.
// skip_below=4 for genuine NTAG (skips OTP UID/lock pages 0–3).
// skip_below=0 for Magic/CUID writable blanks (writes all pages including UID).
// Returns RFID_OK if all attempted writes succeed.
rfid_err_t ntag_clone_to_blank(const rfid_card_t *src, uint8_t skip_below);
