#pragma once
// =============================================================================
// pn532_reader — ISO14443A card detection and UID/type identification
// =============================================================================
// Wraps PN532 InListPassiveTarget for ISO14443A.
// Fills rfid_card_t with uid, atqa, sak, and identifies protocol from SAK.
// Blocks up to timeout_ms waiting for a card to enter the field.
// =============================================================================

#include "rfid_types.h"

// Attempt to detect one ISO14443A card in the field.
// Fills card->uid, uid_len, atqa, sak, technology, protocol, protocol_str.
// Does NOT read block data — call mifare_classic_read_all() for that.
rfid_err_t pn532_scan_card(rfid_card_t *card, uint32_t timeout_ms);

// Release the currently selected card from the field.
rfid_err_t pn532_release_card(void);

// Identify card protocol from ATQA + SAK (pure logic, no I2C needed).
rfid_protocol_t pn532_identify_protocol(uint16_t atqa, uint8_t sak, uint8_t uid_len);
