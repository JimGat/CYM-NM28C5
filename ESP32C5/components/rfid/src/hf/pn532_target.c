#include "hf/pn532_target.h"
#include "hf/pn532_driver.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

static const char *TAG = "pn532_tgt";

#define PN532_CMD_TG_INIT_AS_TARGET  0x8C
#define PN532_CMD_TG_GET_DATA        0x86
#define PN532_CMD_TG_SET_DATA        0x8E

// Max ms to wait for a reader each cycle; controls stop-button latency
#define EMULATE_POLL_MS  3000

static void s_ul_read_resp(const rfid_card_t *card, uint8_t page,
                            uint8_t *out, uint8_t *out_len)
{
    *out_len = 16;
    for (int i = 0; i < 4; i++) {
        int pg = (int)page + i;
        if (pg < RFID_MAX_BLOCKS && card->blocks[pg].valid)
            memcpy(out + i * 4, card->blocks[pg].data, 4);
        else
            memset(out + i * 4, 0x00, 4);
    }
}

rfid_err_t pn532_emulate_card(const rfid_card_t *card,
                               rfid_emu_cb_t cb, void *ctx,
                               volatile bool *stop_flag)
{
    if (!card || !stop_flag) return RFID_ERR_HW;

    // Build TgInitAsTarget command (same bytes every poll cycle)
    // Format: CMD, Mode, SENS_RES[2], NFCID1[3], SEL_RES, FeliCa[18], NFCID3[10], Gt(0), Tk(0)
    uint8_t init_cmd[40];
    uint8_t ci = 0;
    init_cmd[ci++] = PN532_CMD_TG_INIT_AS_TARGET;
    init_cmd[ci++] = 0x00;  // passive, 106 kbps, ISO14443A

    // SENS_RES = ATQA, LSB first
    init_cmd[ci++] = (uint8_t)(card->atqa & 0xFF);
    init_cmd[ci++] = (uint8_t)(card->atqa >> 8);

    // NFCID1: first 3 bytes of UID
    uint8_t n = card->uid_len < 3 ? card->uid_len : 3;
    memcpy(init_cmd + ci, card->uid, n);
    if (n < 3) memset(init_cmd + ci + n, 0, 3 - n);
    ci += 3;

    // SEL_RES = SAK
    init_cmd[ci++] = card->sak;

    // FeliCa params (18 bytes): unused, zero
    memset(init_cmd + ci, 0, 18); ci += 18;

    // NFCID3 (10 bytes): zero
    memset(init_cmd + ci, 0, 10); ci += 10;

    // Gt length 0, Tk length 0
    init_cmd[ci++] = 0x00;
    init_cmd[ci++] = 0x00;

    char uid_str[24];
    rfid_format_uid(card->uid, n, uid_str, sizeof(uid_str));
    ESP_LOGI(TAG, "Emulate start: ATQA=%04X SAK=%02X UID(3B)=%s", card->atqa, card->sak, uid_str);

    if (cb) cb(RFID_EMU_WAITING, ctx);

    while (!(*stop_flag)) {
        rfid_err_t r = pn532_send_command(init_cmd, ci);
        if (r != RFID_OK) {
            ESP_LOGW(TAG, "TgInitAsTarget send failed: %s", rfid_err_str(r));
            if (cb) cb(RFID_EMU_ERROR, ctx);
            return r;
        }

        uint8_t resp[64]; uint8_t rlen = 0;
        r = pn532_read_response(PN532_CMD_TG_INIT_AS_TARGET, resp, &rlen,
                                sizeof(resp), EMULATE_POLL_MS);

        if (*stop_flag) break;

        if (r == RFID_ERR_TIMEOUT) {
            continue;  // no reader yet
        }
        if (r != RFID_OK) {
            ESP_LOGW(TAG, "TgInitAsTarget error: %s", rfid_err_str(r));
            if (cb) cb(RFID_EMU_ERROR, ctx);
            return r;
        }

        ESP_LOGI(TAG, "Reader detected (mode=%02X)", rlen > 1 ? resp[1] : 0);
        if (cb) cb(RFID_EMU_ACTIVE, ctx);

        // Data exchange loop
        while (!(*stop_flag)) {
            uint8_t gcmd = PN532_CMD_TG_GET_DATA;
            r = pn532_send_command(&gcmd, 1);
            if (r != RFID_OK) { break; }

            uint8_t gdata[64]; uint8_t glen = 0;
            r = pn532_read_response(PN532_CMD_TG_GET_DATA, gdata, &glen, sizeof(gdata), 2000);
            if (r != RFID_OK) {
                ESP_LOGI(TAG, "Reader left or idle: %s", rfid_err_str(r));
                break;
            }

            // gdata[0] = status (0x00 = OK), gdata[1..] = reader command
            if (glen < 2 || gdata[0] != 0x00) break;

            uint8_t *rcmd     = gdata + 1;
            uint8_t  rcmd_len = glen - 1;

            uint8_t tresp[64]; uint8_t tresp_len = 0;

            if (rcmd_len >= 2 && rcmd[0] == 0x30) {
                // NTAG/Ultralight READ — 4 pages (16 bytes) starting at page rcmd[1]
                s_ul_read_resp(card, rcmd[1], tresp, &tresp_len);
                ESP_LOGD(TAG, "READ page %u", rcmd[1]);
            } else if (rcmd_len >= 1 && rcmd[0] == 0x60) {
                // GET_VERSION — return a minimal NTAG213 version response
                static const uint8_t ver[] = {0x00,0x04,0x04,0x02,0x01,0x00,0x0F,0x03};
                memcpy(tresp, ver, sizeof(ver));
                tresp_len = sizeof(ver);
            } else {
                // Unknown command — NAK
                tresp[0] = 0x00;
                tresp_len = 1;
                ESP_LOGD(TAG, "Unknown reader cmd 0x%02X, sending NAK", rcmd_len ? rcmd[0] : 0xFF);
            }

            uint8_t scmd[66];
            scmd[0] = PN532_CMD_TG_SET_DATA;
            memcpy(scmd + 1, tresp, tresp_len);
            r = pn532_send_command(scmd, 1 + tresp_len);
            if (r != RFID_OK) { break; }

            uint8_t sresp[4]; uint8_t srlen = 0;
            r = pn532_read_response(PN532_CMD_TG_SET_DATA, sresp, &srlen, sizeof(sresp), 1000);
            if (r != RFID_OK) { break; }
        }

        if (!(*stop_flag)) {
            ESP_LOGI(TAG, "Reader left, resuming listen");
            if (cb) cb(RFID_EMU_WAITING, ctx);
        }
    }

    ESP_LOGI(TAG, "Emulation stopped");
    if (cb) cb(RFID_EMU_DONE, ctx);
    return RFID_OK;
}
