#include "hf/ntag.h"
#include "hf/pn532_driver.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

static const char *TAG = "ntag";

#define PN532_CMD_IN_DATA_EXCHANGE  0x40

// ── Pure logic (no I2C) ───────────────────────────────────────────────────────

// GET_VERSION response layout (8 bytes):
//   [0] fixed header 0x00
//   [1] vendor ID    0x04 (NXP)
//   [2] product type 0x04 (NTAG)
//   [3] major ver    0x02
//   [4] minor ver    0x01
//   [5] 0x00
//   [6] storage size: 0x0F=NTAG213, 0x11=NTAG215, 0x13=NTAG216
//   [7] protocol     0x03
#define NTAG_VER_VENDOR_IDX   1
#define NTAG_VER_PTYPE_IDX    2
#define NTAG_VER_STORAGE_IDX  6
#define NTAG_VER_STORAGE_213  0x0F
#define NTAG_VER_STORAGE_215  0x11
#define NTAG_VER_STORAGE_216  0x13
#define NTAG_VER_NXP_VENDOR   0x04
#define NTAG_VER_NFC_TYPE     0x04

rfid_protocol_t ntag_protocol_from_version(const uint8_t version[8])
{
    if (!version) return RFID_PROTO_UNKNOWN;
    // Require NXP vendor and NTAG product type for a confident match
    if (version[NTAG_VER_VENDOR_IDX] != NTAG_VER_NXP_VENDOR ||
        version[NTAG_VER_PTYPE_IDX]  != NTAG_VER_NFC_TYPE)
        return RFID_PROTO_UNKNOWN;

    switch (version[NTAG_VER_STORAGE_IDX]) {
        case NTAG_VER_STORAGE_213: return RFID_PROTO_NTAG213;
        case NTAG_VER_STORAGE_215: return RFID_PROTO_NTAG215;
        case NTAG_VER_STORAGE_216: return RFID_PROTO_NTAG216;
        default:                   return RFID_PROTO_UNKNOWN;
    }
}

uint16_t ntag_page_count_for_protocol(rfid_protocol_t proto)
{
    switch (proto) {
        case RFID_PROTO_NTAG213:         return 45;
        case RFID_PROTO_NTAG215:         return 135;
        case RFID_PROTO_NTAG216:         return 231;
        case RFID_PROTO_MIFARE_ULTRALIGHT: return 16;
        default:                           return 0;
    }
}

// ── InDataExchange helpers ────────────────────────────────────────────────────

rfid_err_t ntag_get_version(uint8_t version[8])
{
    uint8_t cmd[] = { PN532_CMD_IN_DATA_EXCHANGE, 0x01, 0x60 };
    rfid_err_t r = pn532_send_command(cmd, sizeof(cmd));
    if (r != RFID_OK) return r;

    uint8_t resp[10]; uint8_t rlen = 0;
    r = pn532_read_response(PN532_CMD_IN_DATA_EXCHANGE, resp, &rlen, sizeof(resp), 200);
    if (r != RFID_OK) return r;
    // resp[0] = PN532 error byte (0x00 = success), resp[1..8] = 8-byte version
    if (rlen < 9 || resp[0] != 0x00) {
        ESP_LOGD(TAG, "GET_VERSION NAK (status=0x%02X rlen=%u)", rlen ? resp[0] : 0xFF, rlen);
        return RFID_ERR_NAK;
    }
    if (version) memcpy(version, resp + 1, 8);
    ESP_LOGD(TAG, "GET_VERSION: %02X %02X %02X %02X %02X %02X %02X %02X",
             resp[1], resp[2], resp[3], resp[4], resp[5], resp[6], resp[7], resp[8]);
    return RFID_OK;
}

rfid_err_t ntag_read_pages(uint8_t start_page, uint8_t out16[16])
{
    uint8_t cmd[] = { PN532_CMD_IN_DATA_EXCHANGE, 0x01, 0x30, start_page };
    rfid_err_t r = pn532_send_command(cmd, sizeof(cmd));
    if (r != RFID_OK) return r;

    uint8_t resp[18]; uint8_t rlen = 0;
    r = pn532_read_response(PN532_CMD_IN_DATA_EXCHANGE, resp, &rlen, sizeof(resp), 200);
    if (r != RFID_OK) return r;
    // resp[0] = status, resp[1..16] = 16 data bytes (4 pages × 4 bytes)
    if (rlen < 17 || resp[0] != 0x00) {
        ESP_LOGD(TAG, "READ page %u NAK (status=0x%02X rlen=%u)", start_page,
                 rlen ? resp[0] : 0xFF, rlen);
        return RFID_ERR_NAK;
    }
    if (out16) memcpy(out16, resp + 1, 16);
    return RFID_OK;
}

rfid_err_t ntag_fast_read(uint8_t start_page, uint8_t end_page,
                           uint8_t *out, uint16_t out_max, uint16_t *out_len)
{
    if (end_page < start_page) return RFID_ERR_HW;
    uint8_t cmd[] = { PN532_CMD_IN_DATA_EXCHANGE, 0x01, 0x3A, start_page, end_page };
    rfid_err_t r = pn532_send_command(cmd, sizeof(cmd));
    if (r != RFID_OK) goto fallback;

    {
        uint8_t resp[256]; uint8_t rlen = 0;
        uint8_t max_resp = (uint8_t)((out_max > 254) ? 254 : out_max + 1);
        r = pn532_read_response(PN532_CMD_IN_DATA_EXCHANGE, resp, &rlen, max_resp, 500);
        if (r != RFID_OK || rlen < 1 || resp[0] != 0x00) goto fallback;
        uint8_t data_len = rlen - 1;
        if (out && data_len > 0) {
            if (data_len > out_max) data_len = (uint8_t)out_max;
            memcpy(out, resp + 1, data_len);
        }
        if (out_len) *out_len = data_len;
        return RFID_OK;
    }

fallback:
    ESP_LOGD(TAG, "FAST_READ not supported, falling back to page-by-page");
    if (!out || out_max == 0) return RFID_ERR_HW;
    uint16_t written = 0;
    for (uint8_t pg = start_page; pg <= end_page; pg++) {
        uint8_t tmp[16];
        if (ntag_read_pages(pg & 0xFC, tmp) == RFID_OK) {
            uint8_t offset = (pg & 0x03) * 4;
            if (written + 4 <= out_max) {
                memcpy(out + written, tmp + offset, 4);
                written += 4;
            }
        }
    }
    if (out_len) *out_len = written;
    return (written > 0) ? RFID_OK : RFID_ERR_HW;
}

rfid_err_t ntag_write_page(uint8_t page, const uint8_t data[4])
{
    uint8_t cmd[8] = { PN532_CMD_IN_DATA_EXCHANGE, 0x01, 0xA2, page };
    memcpy(cmd + 4, data, 4);

    rfid_err_t r = pn532_send_command(cmd, sizeof(cmd));
    if (r != RFID_OK) return r;

    uint8_t resp[3]; uint8_t rlen = 0;
    r = pn532_read_response(PN532_CMD_IN_DATA_EXCHANGE, resp, &rlen, sizeof(resp), 200);
    if (r != RFID_OK) return r;
    // resp[0] = PN532 status; resp[1] = card ACK (0x0A) or NAK (0x00)
    if (rlen < 1 || resp[0] != 0x00) {
        ESP_LOGD(TAG, "WRITE page %u: PN532 error 0x%02X", page, rlen ? resp[0] : 0xFF);
        return RFID_ERR_NAK;
    }
    // NTAG ACK is optional in the PN532 response framing; accept even if rlen==1
    if (rlen >= 2 && resp[1] != 0x0A) {
        ESP_LOGD(TAG, "WRITE page %u: card NAK 0x%02X", page, resp[1]);
        return RFID_ERR_NAK;
    }
    return RFID_OK;
}

rfid_err_t ntag_read_counter(uint8_t counter_no, uint32_t *value_out)
{
    uint8_t cmd[] = { PN532_CMD_IN_DATA_EXCHANGE, 0x01, 0x39, counter_no };
    rfid_err_t r = pn532_send_command(cmd, sizeof(cmd));
    if (r != RFID_OK) return r;

    uint8_t resp[5]; uint8_t rlen = 0;
    r = pn532_read_response(PN532_CMD_IN_DATA_EXCHANGE, resp, &rlen, sizeof(resp), 200);
    if (r != RFID_OK) return r;
    if (rlen < 4 || resp[0] != 0x00) return RFID_ERR_NAK;
    if (value_out)
        *value_out = (uint32_t)resp[1] | ((uint32_t)resp[2] << 8) | ((uint32_t)resp[3] << 16);
    return RFID_OK;
}

rfid_err_t ntag_pwd_auth(const uint8_t pwd[4], uint8_t pack_out[2])
{
    uint8_t cmd[7] = { PN532_CMD_IN_DATA_EXCHANGE, 0x01, 0x1B };
    memcpy(cmd + 3, pwd, 4);

    rfid_err_t r = pn532_send_command(cmd, sizeof(cmd));
    if (r != RFID_OK) return r;

    uint8_t resp[4]; uint8_t rlen = 0;
    r = pn532_read_response(PN532_CMD_IN_DATA_EXCHANGE, resp, &rlen, sizeof(resp), 200);
    if (r != RFID_OK) return r;
    if (rlen < 3 || resp[0] != 0x00) return RFID_ERR_AUTH;
    if (pack_out) memcpy(pack_out, resp + 1, 2);
    return RFID_OK;
}

// ── Full card operations ──────────────────────────────────────────────────────

rfid_err_t ntag_read_all(rfid_card_t *card)
{
    if (!card) return RFID_ERR_HW;

    // Try GET_VERSION to confirm/refine protocol.
    uint8_t version[8];
    rfid_err_t vr = ntag_get_version(version);
    if (vr == RFID_OK) {
        rfid_protocol_t refined = ntag_protocol_from_version(version);
        if (refined != RFID_PROTO_UNKNOWN) {
            card->protocol   = refined;
            card->page_count = ntag_page_count_for_protocol(refined);
            strncpy(card->protocol_str, rfid_protocol_str(refined),
                    sizeof(card->protocol_str) - 1);
        }
    }

    uint16_t page_count = card->page_count;
    if (page_count == 0) {
        // Fallback: assume NTAG213 if page_count was never set
        page_count = 45;
        card->page_count = page_count;
    }

    ESP_LOGI(TAG, "read_all: proto=%s page_count=%u", card->protocol_str, page_count);

    uint16_t pages_ok     = 0;
    uint16_t pages_failed = 0;
    uint16_t pages_retry_ok = 0;

    // READ returns 4 pages per call; stride by 4.
    // On failure, retry once after a short delay (helps with marginal RF coupling).
    for (uint16_t pg = 0; pg < page_count; pg += 4) {
        uint8_t tmp[16];
        rfid_err_t r = ntag_read_pages((uint8_t)pg, tmp);
        if (r != RFID_OK) {
            ESP_LOGW(TAG, "read_all: page %u READ failed (%s), retrying...",
                     pg, rfid_err_str(r));
            vTaskDelay(pdMS_TO_TICKS(10));
            r = ntag_read_pages((uint8_t)pg, tmp);
            if (r != RFID_OK) {
                ESP_LOGW(TAG, "read_all: page %u READ failed after retry (%s) — skipping",
                         pg, rfid_err_str(r));
                pages_failed++;
                for (uint16_t i = pg; i < pg + 4 && i < page_count && i < RFID_MAX_BLOCKS; i++)
                    card->blocks[i].valid = false;
                continue;
            }
            pages_retry_ok++;
            ESP_LOGI(TAG, "read_all: page %u recovered on retry", pg);
        }
        for (int i = 0; i < 4; i++) {
            uint16_t this_pg = pg + (uint16_t)i;
            if (this_pg >= page_count || this_pg >= RFID_MAX_BLOCKS) break;
            memcpy(card->blocks[this_pg].data, tmp + i * 4, 4);
            memset(card->blocks[this_pg].data + 4, 0, RFID_BLOCK_LEN - 4);
            card->blocks[this_pg].valid = true;
            pages_ok++;
            ESP_LOGD(TAG, "read_all: pg%u = %02X %02X %02X %02X",
                     this_pg,
                     card->blocks[this_pg].data[0], card->blocks[this_pg].data[1],
                     card->blocks[this_pg].data[2], card->blocks[this_pg].data[3]);
        }
    }

    // Auto-upgrade: if identified as MIFARE Ultralight (16 pages) but the NDEF
    // content claims to need more space, the card is likely an NTAG213 (45 pages)
    // that cannot be confirmed via GET_VERSION (fails on PN532 firmware 1.6).
    // Probe page 16 — a genuine 16-page Ultralight returns NAK; an NTAG213 returns data.
    if (card->protocol == RFID_PROTO_MIFARE_ULTRALIGHT && page_count == 16
        && pages_ok >= 12) {
        uint8_t probe[16];
        if (ntag_read_pages(16, probe) == RFID_OK) {
            ESP_LOGI(TAG, "read_all: page16 readable — upgrading Ultralight → NTAG213 (45 pages)");
            ESP_LOGI(TAG, "read_all: page16 = %02X %02X %02X %02X",
                     probe[0], probe[1], probe[2], probe[3]);
            card->protocol   = RFID_PROTO_NTAG213;
            card->page_count = 45;
            strncpy(card->protocol_str, rfid_protocol_str(RFID_PROTO_NTAG213),
                    sizeof(card->protocol_str) - 1);

            // Store pages 16-19 from probe
            for (int i = 0; i < 4 && 16 + i < RFID_MAX_BLOCKS; i++) {
                memcpy(card->blocks[16 + i].data, probe + i * 4, 4);
                memset(card->blocks[16 + i].data + 4, 0, RFID_BLOCK_LEN - 4);
                card->blocks[16 + i].valid = true;
                pages_ok++;
            }

            // Continue reading pages 20-44
            for (uint16_t pg = 20; pg < 45; pg += 4) {
                uint8_t tmp[16];
                rfid_err_t r = ntag_read_pages((uint8_t)pg, tmp);
                if (r != RFID_OK) {
                    ESP_LOGW(TAG, "read_all: NTAG213 page %u READ failed (%s)",
                             pg, rfid_err_str(r));
                    pages_failed++;
                    continue;
                }
                for (int i = 0; i < 4; i++) {
                    uint16_t this_pg = pg + (uint16_t)i;
                    if (this_pg >= 45 || this_pg >= RFID_MAX_BLOCKS) break;
                    memcpy(card->blocks[this_pg].data, tmp + i * 4, 4);
                    memset(card->blocks[this_pg].data + 4, 0, RFID_BLOCK_LEN - 4);
                    card->blocks[this_pg].valid = true;
                    pages_ok++;
                }
            }
            page_count = 45;
        } else {
            ESP_LOGI(TAG, "read_all: page16 NAK — confirmed genuine 16-page Ultralight");
        }
    }

    ESP_LOGI(TAG, "read_all done: %u/%u pages OK  (%u failed, %u recovered by retry)",
             pages_ok, page_count, pages_failed, pages_retry_ok);
    return (pages_ok > 0) ? RFID_OK : RFID_ERR_HW;
}

rfid_err_t ntag_clone_to_blank(const rfid_card_t *src, uint8_t skip_below)
{
    if (!src || src->page_count == 0) return RFID_ERR_HW;

    uint16_t pages_written = 0;
    uint16_t pages_failed  = 0;

    for (uint16_t pg = skip_below; pg < src->page_count && pg < RFID_MAX_BLOCKS; pg++) {
        if (!src->blocks[pg].valid) {
            ESP_LOGD(TAG, "clone: page %u not valid in src, skipping", pg);
            continue;
        }
        rfid_err_t r = ntag_write_page((uint8_t)pg, src->blocks[pg].data);
        if (r == RFID_OK) {
            pages_written++;
            ESP_LOGD(TAG, "clone: page %u written", pg);
        } else {
            pages_failed++;
            ESP_LOGW(TAG, "clone: page %u write failed: %s", pg, rfid_err_str(r));
        }
        // Brief yield between writes to keep FreeRTOS scheduler responsive
        vTaskDelay(pdMS_TO_TICKS(2));
    }

    ESP_LOGI(TAG, "clone done: %u written, %u failed (skip_below=%u)",
             pages_written, pages_failed, skip_below);

    if (pages_written == 0) return RFID_ERR_NAK;
    return (pages_failed == 0) ? RFID_OK : RFID_ERR_NAK;
}
