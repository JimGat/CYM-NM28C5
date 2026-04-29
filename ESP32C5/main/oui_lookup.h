#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

/* Binary file format: magic "OUI1" + uint32_t count (LE) + N × 32-byte entries.
 * Each entry: uint8_t oui[3] (big-endian, standard notation) + char name[29].
 * Entries must be sorted ascending by oui for binary search.
 * Generate with tools/oui_convert.py from IEEE OUI CSV. */
#define OUI_DEFAULT_PATH  "/sdcard/lab/ouilist.bin"

/* Load OUI database from bin_path into PSRAM.
 * Returns ESP_OK on success, ESP_ERR_NOT_FOUND if file absent. */
esp_err_t   oui_lookup_init(const char *bin_path);

/* Look up a 3-byte OUI prefix in standard order {AA, BB, CC}.
 * For NimBLE addresses use {addr[5], addr[4], addr[3]}.
 * Returns vendor name string (valid until oui_lookup_deinit), or NULL. */
const char *oui_lookup(const uint8_t oui3[3]);

bool        oui_lookup_is_loaded(void);
uint32_t    oui_lookup_count(void);
void        oui_lookup_deinit(void);
