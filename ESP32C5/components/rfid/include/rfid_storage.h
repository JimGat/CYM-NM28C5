#pragma once
// =============================================================================
// rfid_storage — save/load/list RFID card records
// =============================================================================
// Internal format: JSON text file under RF_HAT_RFID_SAVE_DIR/hf/ or /lf/.
// Filenames: <UID>_<timestamp>.json or user-supplied name.json
// Flipper import/export in separate flipper_nfc_file.h / flipper_lf_file.h.
// =============================================================================

#include "rfid_types.h"

// ── Directory layout ──────────────────────────────────────────────────────────
#define RFID_DIR_HF      "/sdcard/lab/rfid/hf"
#define RFID_DIR_LF      "/sdcard/lab/rfid/lf"
#define RFID_DIR_KEYS    "/sdcard/lab/rfid/keys"
#define RFID_DIR_LOGS    "/sdcard/lab/rfid/logs"
#define RFID_DIR_IMPORT  "/sdcard/lab/rfid/import"
#define RFID_DIR_EXPORT  "/sdcard/lab/rfid/export"

// Ensure all subdirectories exist (called once at RFID app entry).
void rfid_storage_ensure_dirs(void);

// ── Save / Load ───────────────────────────────────────────────────────────────
// Save card as JSON. If name is NULL, auto-names from UID + timestamp.
// Returns RFID_OK and writes path into path_out (if non-NULL).
rfid_err_t rfid_storage_save(const rfid_card_t *card,
                              const char *name,
                              char *path_out, size_t path_out_size);

// Load card from a file path (absolute path).
rfid_err_t rfid_storage_load(const char *path, rfid_card_t *card_out);

// ── List ──────────────────────────────────────────────────────────────────────
typedef struct {
    char path[RFID_FILENAME_LEN];
    char display_name[RFID_CARD_NAME_LEN];
    char uid_str[24];         // formatted UID, e.g. "AB CD EF 12"
    char protocol_str[24];
    char timestamp[20];
} rfid_card_entry_t;

// List saved cards for the given band directory.
// Returns count found (<= max_count). Entries sorted by filename.
int rfid_storage_list(rfid_band_t band,
                       rfid_card_entry_t *entries, int max_count);

// ── Delete ────────────────────────────────────────────────────────────────────
rfid_err_t rfid_storage_delete(const char *path);
