#include "hf/pn532_reader.h"
#include "hf/pn532_driver.h"
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

rfid_protocol_t pn532_identify_protocol(uint16_t atqa, uint8_t sak, uint8_t uid_len)
{
    // SAK bit 5 (0x20) set = ISO14443-4 compliant (smart card layer)
    if (sak & 0x20) {
        // Check for DESFire: SAK=0x20, ATQA=0x0344 or specific combos
        if ((sak & 0x20) && (atqa == 0x0344 || atqa == 0x03C4))
            return RFID_PROTO_DESFIRE;
        return RFID_PROTO_ISO14443_4;
    }
    // SAK bit 3 (0x08) set = MIFARE Classic
    if (sak & 0x08) {
        if (sak == 0x08) return RFID_PROTO_MIFARE_CLASSIC_1K;
        if (sak == 0x18) return RFID_PROTO_MIFARE_CLASSIC_4K;
        if (sak == 0x09) return RFID_PROTO_MIFARE_CLASSIC_1K;  // Mini
        return RFID_PROTO_MIFARE_CLASSIC_1K;
    }
    // SAK=0x00 = MIFARE Ultralight / NTAG
    if (sak == 0x00) {
        if (atqa == 0x0044) {
            // Differentiate NTAG by UID length (7-byte for NTAG, 4 for some UL)
            if (uid_len == 7) return RFID_PROTO_NTAG213;  // refined later by GET_VERSION
            return RFID_PROTO_MIFARE_ULTRALIGHT;
        }
        return RFID_PROTO_MIFARE_ULTRALIGHT;
    }
    // SAK=0x10 or 0x11 = MIFARE Plus
    if (sak == 0x10 || sak == 0x11) return RFID_PROTO_MIFARE_PLUS;

    return RFID_PROTO_ISO14443_UID_ONLY;
}

rfid_err_t pn532_scan_card(rfid_card_t *card, uint32_t timeout_ms)
{
    if (!card) return RFID_ERR_HW;

    // InListPassiveTarget: MaxTg=1, BrTy=ISO14443A
    uint8_t cmd[] = { PN532_CMD_IN_LIST_PASSIVE, 0x01, BAUD_ISO14443A };

    uint32_t elapsed = 0;
    uint32_t step_ms = 200;

    while (elapsed < timeout_ms) {
        rfid_err_t r = pn532_send_command(cmd, sizeof(cmd));
        if (r != RFID_OK) {
            ESP_LOGW(TAG, "scan: send_cmd failed: %s", rfid_err_str(r));
            vTaskDelay(pdMS_TO_TICKS(step_ms));
            elapsed += step_ms;
            continue;
        }

        uint8_t resp[20];
        uint8_t rlen = 0;
        r = pn532_read_response(PN532_CMD_IN_LIST_PASSIVE, resp, &rlen,
                                 sizeof(resp), 1000);
        if (r != RFID_OK || rlen < 1) {
            if (r != RFID_ERR_TIMEOUT)
                ESP_LOGW(TAG, "scan: read_resp failed: %s rlen=%u", rfid_err_str(r), rlen);
            else
                ESP_LOGD(TAG, "scan: no card (timeout)");
            vTaskDelay(pdMS_TO_TICKS(step_ms));
            elapsed += step_ms;
            continue;
        }

        ESP_LOGD(TAG, "scan: NbTg=%u rlen=%u", resp[0], rlen);

        // resp[0] = NbTg (number of targets found)
        if (resp[0] == 0) {
            vTaskDelay(pdMS_TO_TICKS(step_ms));
            elapsed += step_ms;
            continue;
        }

        // resp[1] = Tg (target number, 1-based)
        // resp[2..3] = ATQA (2 bytes, LSB first)
        // resp[4] = SAK
        // resp[5] = NFCIDLength
        // resp[6..] = NFCID (UID bytes)
        if (rlen < 6) return RFID_ERR_HW;

        uint16_t atqa = (uint16_t)resp[2] | ((uint16_t)resp[3] << 8);
        uint8_t  sak  = resp[4];
        uint8_t  uid_len = resp[5];
        if (uid_len > RFID_MAX_UID_LEN) uid_len = RFID_MAX_UID_LEN;
        if (rlen < 6 + uid_len) return RFID_ERR_HW;

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
        } else if (card->protocol == RFID_PROTO_NTAG213) {
            card->page_count = 45;
        } else if (card->protocol == RFID_PROTO_NTAG215) {
            card->page_count = 135;
        } else if (card->protocol == RFID_PROTO_NTAG216) {
            card->page_count = 231;
        } else if (card->protocol == RFID_PROTO_MIFARE_ULTRALIGHT) {
            card->page_count = 16;
        }

        char uid_str[32];
        rfid_format_uid(card->uid, card->uid_len, uid_str, sizeof(uid_str));
        ESP_LOGI(TAG, "Card: UID=%s ATQA=%04X SAK=%02X proto=%s",
                 uid_str, atqa, sak, card->protocol_str);
        return RFID_OK;
    }

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
