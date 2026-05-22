#pragma once
#include "rfid_types.h"

// PN532 target (card emulation) mode via TgInitAsTarget (0x8C).
//
// Presents the card as an ISO14443-A target. NFCID1 in TgInitAsTarget is
// 3 bytes, so the emulated UID is always 4 bytes (uid[0..2] + PN532-BCC),
// regardless of the original card's uid_len. 7-byte UID cards are emulated
// with only their first 3 bytes visible to the reader.
//
// Handles READ (0x30) commands for NTAG/Ultralight cards using saved page
// data in card->blocks[]. Unknown commands receive a NAK (0x00).
//
// stop_flag: caller sets *stop_flag=true to abort. Max latency = 3 s
// (one TgInitAsTarget polling cycle). Function returns after that cycle.

rfid_err_t pn532_emulate_card(const rfid_card_t *card,
                               rfid_emu_cb_t cb, void *ctx,
                               volatile bool *stop_flag);
