#include "flipper_lf_file.h"
#include "rfid_types.h"
#include "esp_log.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const char *TAG = "flipper_lf";

rfid_err_t flipper_lf_export(const rfid_card_t *card, const char *path)
{
    (void)path;
    if (!card) return RFID_ERR_HW;
    if (card->band != RFID_BAND_LF) return RFID_ERR_NOT_SUPPORTED;

    // Stub — LF hardware not yet present.
    // When a real LF reader is added, implement:
    //   Filetype: Flipper RFID key
    //   Version: 1
    //   Key type: <protocol>
    //   Data: <hex bytes>
    ESP_LOGW(TAG, "LF export not yet implemented");
    return RFID_ERR_NOT_SUPPORTED;
}

rfid_err_t flipper_lf_import(const char *path, rfid_card_t *card_out)
{
    (void)path;
    if (!card_out) return RFID_ERR_HW;

    // Stub — parse .rfid file header to at least identify the key type,
    // store raw bytes in lf_raw[], and set band=LF and technology.
    // Full decode deferred until real LF hardware is integrated.
    ESP_LOGW(TAG, "LF import not yet implemented");
    return RFID_ERR_NOT_SUPPORTED;
}

void flipper_lf_make_filename(const rfid_card_t *card, char *buf, size_t buf_size)
{
    if (card->lf_facility_code || card->lf_card_number) {
        snprintf(buf, buf_size, "%lu_%lu.rfid",
                 (unsigned long)card->lf_facility_code,
                 (unsigned long)card->lf_card_number);
    } else {
        snprintf(buf, buf_size, "lf_unknown.rfid");
    }
}
