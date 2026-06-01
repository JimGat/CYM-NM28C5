#pragma once
// =============================================================================
// rfid_manager — lifecycle, background poll, and top-level RFID operations
// =============================================================================
// Usage pattern:
//   rfid_manager_init()          — called on RFID menu entry (after DIP popup)
//   rfid_manager_probe()         — verify PN532 communication
//   rfid_manager_start_poll()    — begin background card detection
//   rfid_manager_stop_poll()     — stop polling (call before exiting UI)
//   rfid_manager_deinit()        — full teardown on menu exit
//
// All poll callbacks fire from the poll task context — use lv_async_call() to
// touch LVGL objects from within a poll callback.
// =============================================================================

#include "rfid_types.h"
#include <stdbool.h>

// ── Poll callback ─────────────────────────────────────────────────────────────
// card is owned by the manager and valid only for the duration of the callback.
// Copy what you need; do not cache the pointer.
typedef void (*rfid_poll_cb_t)(rfid_err_t result, const rfid_card_t *card, void *ctx);

// ── Probe result ─────────────────────────────────────────────────────────────
typedef struct {
    bool    found;           // PN532 responded
    uint8_t ic;              // PN532 IC identifier (always 3)
    uint8_t fw_ver;          // firmware version
    uint8_t fw_rev;          // firmware revision
    char    desc[32];        // human-readable, e.g. "PN532 v1.6 OK"
} rfid_probe_result_t;

// ── Lifecycle ─────────────────────────────────────────────────────────────────
// init: acquires I2C bus on GPIO8/9 (SCL/SDA), powers PN532 SAM, claims GPIO.
rfid_err_t rfid_manager_init(void);

// deinit: stops poll, turns off RF field, releases I2C bus and GPIO.
void       rfid_manager_deinit(void);

bool       rfid_manager_is_init(void);
// Returns true if the last init attempt found the PN532 ACKing at 0x24.
// False means not powered (DIP3 OFF) or wrong protocol mode.
bool       rfid_manager_is_addr_ok(void);

// ── PN532 probe ───────────────────────────────────────────────────────────────
rfid_err_t rfid_manager_probe(rfid_probe_result_t *out);

// ── Background poll ───────────────────────────────────────────────────────────
// Starts a FreeRTOS task that polls for cards every poll_interval_ms.
// cb fires on card detect (RFID_OK) or poll error; ctx is passed through.
// Calling start_poll while already polling replaces the callback.
rfid_err_t rfid_manager_start_poll(rfid_poll_cb_t cb, void *ctx,
                                    uint32_t poll_interval_ms);
void       rfid_manager_stop_poll(void);
bool       rfid_manager_is_polling(void);

// ── One-shot scan (blocking, no poll task) ────────────────────────────────────
rfid_err_t rfid_manager_scan_card(rfid_card_t *card_out, uint32_t timeout_ms);

// ── MIFARE key dictionary test ────────────────────────────────────────────────
// Progress cb: fired for each sector attempted.
typedef void (*rfid_key_progress_cb_t)(uint8_t sector, uint8_t total_sectors,
                                        bool found, void *ctx);

// Run default key dict against all sectors of an already-scanned MIFARE card.
// Fills card->blocks[] and card->keys[] for any sectors that authenticate.
// For authorized testing on own cards only.
rfid_err_t rfid_manager_test_mifare_keys(rfid_card_t *card,
                                          rfid_key_progress_cb_t progress_cb,
                                          void *ctx);

// ── Generic card memory read ──────────────────────────────────────────────────
// Read all memory for the detected card (blocks or pages depending on protocol).
// For NTAG/Ultralight: calls GET_VERSION to refine protocol, then reads all pages.
// For MIFARE Classic: reads all blocks using the default key dictionary.
// card must already have uid/protocol populated by rfid_manager_scan_card().
// Returns RFID_ERR_NOT_SUPPORTED for protocols without a read implementation.
rfid_err_t rfid_manager_read_card_data(rfid_card_t *card);

// ── NTAG clone ────────────────────────────────────────────────────────────────
// Write src card pages [skip_below .. src->page_count) to a currently-selected
// blank NTAG/UL card. Scans for a blank card first with a 5-second timeout.
// skip_below=4 for genuine NTAG (skips OTP UID/lock pages 0-3).
// skip_below=0 for Magic/CUID writable blanks (writes all pages).
// Returns RFID_ERR_NOT_SUPPORTED if src is not an NTAG/UL protocol.
rfid_err_t rfid_manager_clone_ntag(const rfid_card_t *src, uint8_t skip_below);

// ── Card emulation ────────────────────────────────────────────────────────────
// Starts a FreeRTOS task that puts the PN532 into target mode, presenting
// card's UID/ATQA/SAK to any nearby reader. cb fires on status changes.
// Stop with rfid_manager_stop_emulate(); max stop latency = 3 s.
rfid_err_t rfid_manager_start_emulate(const rfid_card_t *card,
                                       rfid_emu_cb_t cb, void *ctx);
void       rfid_manager_stop_emulate(void);
bool       rfid_manager_is_emulating(void);

// ── I2C bus diagnostic scan ───────────────────────────────────────────────────
// Probes all 127 I2C addresses. Returns device count; fills addrs_out[max].
// Logs results. Returns -1 if manager not initialised.
int rfid_manager_i2c_scan(uint8_t *addrs_out, int max_addrs);
