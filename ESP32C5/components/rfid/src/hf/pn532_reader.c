#include "hf/pn532_reader.h"
#include "hf/pn532_driver.h"
#include "hf/ntag.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

static const char *TAG = "pn532_reader";

// InListPassiveTarget command byte
#define PN532_CMD_IN_LIST_PASSIVE  0x4A
#define PN532_CMD_IN_RELEASE       0x52

// InListPassiveTarget BrTy (baud rate / tag type) for ISO14443A at 106 kbps
#define BAUD_ISO14443A  0x00

// Normalise ATQA to a canonical little-endian uint16 regardless of how the
// PN532 byte-orders it.  The PN532 user manual says ATQA is two bytes
// "MSB first" in the InListPassiveTarget response, but observed behaviour on
// this NM-RF-HAT build returns the bytes in reverse order (LSB first).
// Accept both orderings by also checking the byte-swapped value so that
// NTAG213/215/216 (standard ATQA 0x0044) is recognised regardless of which
// byte comes back in resp[2] vs resp[3].
static inline uint16_t s_atqa_normalise(uint16_t raw_atqa)
{
    // Standard form: 0x0044 for NTAG/Ultralight, 0x0004 for MIFARE Classic 1K, etc.
    // If the value looks byte-swapped (high byte = known ATQA low byte), swap it.
    // Heuristic: if the low byte is 0x00 and high byte is non-zero, swap.
    if ((raw_atqa & 0x00FF) == 0x00 && (raw_atqa >> 8) != 0x00)
        return (raw_atqa >> 8) | ((raw_atqa & 0xFF) << 8);
    return raw_atqa;
}

rfid_protocol_t pn532_identify_protocol(uint16_t atqa, uint8_t sak, uint8_t uid_len)
{
    // Normalise ATQA byte ordering (PN532 returns bytes in a different order
    // than the ISO 14443A standard on this hardware).
    uint16_t a = s_atqa_normalise(atqa);
    ESP_LOGI("pn532_id", "ATQA raw=0x%04X norm=0x%04X SAK=0x%02X uid_len=%u",
             atqa, a, sak, uid_len);

    // SAK bit 5 (0x20) set = ISO14443-4 compliant (smart card layer)
    if (sak & 0x20) {
        if (a == 0x0344 || a == 0x03C4) return RFID_PROTO_DESFIRE;
        return RFID_PROTO_ISO14443_4;
    }
    // SAK bit 3 (0x08) set = MIFARE Classic
    if (sak & 0x08) {
        if (sak == 0x08) return RFID_PROTO_MIFARE_CLASSIC_1K;
        if (sak == 0x18) return RFID_PROTO_MIFARE_CLASSIC_4K;
        if (sak == 0x09) return RFID_PROTO_MIFARE_CLASSIC_1K;  // Mini
        return RFID_PROTO_MIFARE_CLASSIC_1K;
    }
    // SAK=0x00 = MIFARE Ultralight / NTAG family
    if (sak == 0x00) {
        // NTAG213/215/216 and MIFARE Ultralight both have ATQA=0x0044, SAK=0x00.
        // 7-byte UID → NTAG213 (refined to 215/216 by GET_VERSION later).
        // 4-byte UID → Ultralight.
        // Accept both the standard form (0x0044) and our observed byte-swapped
        // form (0x4400) to be robust against PN532 ATQA byte ordering.
        if (a == 0x0044 || a == 0x4400) {
            if (uid_len == 7) return RFID_PROTO_NTAG213;
            return RFID_PROTO_MIFARE_ULTRALIGHT;
        }
        // Other SAK=0x00 cards (e.g. some ISO15693 or proprietary)
        return RFID_PROTO_MIFARE_ULTRALIGHT;
    }
    // SAK=0x10 or 0x11 = MIFARE Plus
    if (sak == 0x10 || sak == 0x11) return RFID_PROTO_MIFARE_PLUS;

    return RFID_PROTO_ISO14443_UID_ONLY;
}

rfid_err_t pn532_scan_card(rfid_card_t *card, uint32_t timeout_ms)
{
    if (!card) return RFID_ERR_HW;

    // InListPassiveTarget: MaxTg=1, BrTy=ISO14443A 106 kbps
    uint8_t cmd[] = { PN532_CMD_IN_LIST_PASSIVE, 0x01, BAUD_ISO14443A };

    uint32_t elapsed  = 0;
    uint32_t step_ms  = 150;     // poll interval — shorter than old 200ms
    uint32_t attempt  = 0;
    uint32_t hw_errs  = 0;       // consecutive I2C/HW errors (triggers recovery)
    uint32_t field_cycle_next = 3000;  // cycle RF field after 3s with no card

    ESP_LOGD(TAG, "scan: start timeout=%lums", (unsigned long)timeout_ms);

    while (elapsed < timeout_ms) {
        attempt++;

        // Periodic RF field cycle: helps some cards that are slow to initialise
        // or have marginal coupling due to misalignment.
        if (elapsed >= field_cycle_next) {
            ESP_LOGD(TAG, "scan: field cycle at %lums (attempt %lu)",
                     (unsigned long)elapsed, (unsigned long)attempt);
            pn532_rf_field_cycle();
            field_cycle_next += 3000;
            vTaskDelay(pdMS_TO_TICKS(10));
        }

        rfid_err_t r = pn532_send_command(cmd, sizeof(cmd));
        if (r != RFID_OK) {
            hw_errs++;
            ESP_LOGW(TAG, "scan[%lu]: send_cmd failed (%s) hw_errs=%lu elapsed=%lums",
                     (unsigned long)attempt, rfid_err_str(r),
                     (unsigned long)hw_errs, (unsigned long)elapsed);

            if (hw_errs >= 3) {
                // Three consecutive I2C failures — PN532 has likely locked up.
                // Attempt recovery: bus reset + SAM configure + sensitivity config.
                ESP_LOGW(TAG, "scan: %lu consecutive HW errors — triggering recovery",
                         (unsigned long)hw_errs);
                rfid_err_t rec = pn532_recover();
                if (rec != RFID_OK) {
                    ESP_LOGE(TAG, "scan: recovery failed (%s) — aborting scan",
                             rfid_err_str(rec));
                    return RFID_ERR_HW;
                }
                hw_errs = 0;
                field_cycle_next = elapsed + 3000;
            }
            vTaskDelay(pdMS_TO_TICKS(step_ms));
            elapsed += step_ms;
            continue;
        }
        hw_errs = 0;  // reset error counter on successful command send

        uint8_t resp[20];
        uint8_t rlen = 0;
        r = pn532_read_response(PN532_CMD_IN_LIST_PASSIVE, resp, &rlen,
                                 sizeof(resp), 1000);
        if (r != RFID_OK || rlen < 1) {
            if (r == RFID_ERR_TIMEOUT) {
                ESP_LOGD(TAG, "scan[%lu]: no card in field (elapsed=%lums)",
                         (unsigned long)attempt, (unsigned long)elapsed);
            } else {
                ESP_LOGW(TAG, "scan[%lu]: read_resp err=%s rlen=%u elapsed=%lums",
                         (unsigned long)attempt, rfid_err_str(r), rlen,
                         (unsigned long)elapsed);
            }
            vTaskDelay(pdMS_TO_TICKS(step_ms));
            elapsed += step_ms;
            continue;
        }

        // resp[0] = NbTg (number of targets, 0 = none found)
        if (resp[0] == 0) {
            ESP_LOGD(TAG, "scan[%lu]: NbTg=0 (elapsed=%lums)",
                     (unsigned long)attempt, (unsigned long)elapsed);
            vTaskDelay(pdMS_TO_TICKS(step_ms));
            elapsed += step_ms;
            continue;
        }

        // Successful detection.
        // resp[1]=Tg, resp[2..3]=ATQA(LSB first), resp[4]=SAK,
        // resp[5]=NFCIDLength, resp[6..]=NFCID
        ESP_LOGI(TAG, "scan[%lu]: raw resp NbTg=%u rlen=%u: "
                 "%02X %02X %02X %02X %02X %02X %02X %02X",
                 (unsigned long)attempt, resp[0], rlen,
                 resp[0], resp[1], resp[2], resp[3],
                 resp[4], resp[5], (rlen > 6 ? resp[6] : 0),
                 (rlen > 7 ? resp[7] : 0));

        if (rlen < 6) {
            ESP_LOGW(TAG, "scan: response too short (rlen=%u, need >=6)", rlen);
            return RFID_ERR_HW;
        }

        uint16_t atqa    = (uint16_t)resp[2] | ((uint16_t)resp[3] << 8);
        uint8_t  sak     = resp[4];
        uint8_t  uid_len = resp[5];
        if (uid_len > RFID_MAX_UID_LEN) uid_len = RFID_MAX_UID_LEN;
        if (rlen < 6 + uid_len) {
            ESP_LOGW(TAG, "scan: uid truncated rlen=%u uid_len=%u", rlen, uid_len);
            return RFID_ERR_HW;
        }

        memset(card, 0, sizeof(*card));
        card->band       = RFID_BAND_HF;
        card->technology = RFID_TECH_ISO14443A;
        card->atqa       = atqa;
        card->sak        = sak;
        card->uid_len    = uid_len;
        memcpy(card->uid, resp + 6, uid_len);

        card->protocol = pn532_identify_protocol(atqa, sak, uid_len);
        strncpy(card->protocol_str, rfid_protocol_str(card->protocol),
                sizeof(card->protocol_str) - 1);

        // Block/page count by protocol
        if (card->protocol == RFID_PROTO_MIFARE_CLASSIC_1K) {
            card->block_count = 64;
        } else if (card->protocol == RFID_PROTO_MIFARE_CLASSIC_4K) {
            card->block_count = 256;
        } else {
            // NTAG/Ultralight: try GET_VERSION to distinguish 213/215/216
            if (card->protocol == RFID_PROTO_NTAG213 ||
                card->protocol == RFID_PROTO_MIFARE_ULTRALIGHT) {
                uint8_t version[8];
                ESP_LOGD(TAG, "scan: running GET_VERSION to refine NTAG type");
                if (ntag_get_version(version) == RFID_OK) {
                    ESP_LOGI(TAG, "GET_VERSION: %02X %02X %02X %02X %02X %02X %02X %02X",
                             version[0], version[1], version[2], version[3],
                             version[4], version[5], version[6], version[7]);
                    rfid_protocol_t refined = ntag_protocol_from_version(version);
                    if (refined != RFID_PROTO_UNKNOWN) {
                        card->protocol = refined;
                        strncpy(card->protocol_str, rfid_protocol_str(refined),
                                sizeof(card->protocol_str) - 1);
                        ESP_LOGI(TAG, "scan: protocol refined to %s", card->protocol_str);
                    } else {
                        ESP_LOGW(TAG, "scan: GET_VERSION returned unknown product "
                                 "(IC=%02X prod=%02X var=%02X v=%02X.%02X stor=%02X)",
                                 version[0], version[2], version[3],
                                 version[4], version[5], version[6]);
                    }
                } else {
                    ESP_LOGW(TAG, "scan: GET_VERSION failed — keeping heuristic type %s",
                             card->protocol_str);
                }
            }
            card->page_count = ntag_page_count_for_protocol(card->protocol);
            if (card->page_count == 0) card->page_count = 16;
        }

        char uid_str[32];
        rfid_format_uid(card->uid, card->uid_len, uid_str, sizeof(uid_str));
        ESP_LOGI(TAG, "Card found: UID=%s ATQA=%04X SAK=%02X proto=%s "
                 "pages=%u blocks=%u (attempt %lu, elapsed %lums)",
                 uid_str, atqa, sak, card->protocol_str,
                 card->page_count, card->block_count,
                 (unsigned long)attempt, (unsigned long)elapsed);
        return RFID_OK;
    }

    ESP_LOGD(TAG, "scan: timeout after %lu attempts, %lums",
             (unsigned long)attempt, (unsigned long)elapsed);
    return RFID_ERR_TIMEOUT;
}

rfid_err_t pn532_release_card(void)
{
    // InRelease: Rls=1 target
    uint8_t cmd[] = { PN532_CMD_IN_RELEASE, 0x01 };
    rfid_err_t r = pn532_send_command(cmd, sizeof(cmd));
    if (r != RFID_OK) return r;
    uint8_t resp[2]; uint8_t rlen = 0;
    return pn532_read_response(PN532_CMD_IN_RELEASE, resp, &rlen, sizeof(resp), 200);
}
