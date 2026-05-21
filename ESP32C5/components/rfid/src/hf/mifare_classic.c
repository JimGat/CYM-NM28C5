#include "hf/mifare_classic.h"
#include "hf/pn532_driver.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

static const char *TAG = "mifare";

// InDataExchange command
#define PN532_CMD_IN_DATA_EXCHANGE  0x40

// MIFARE Classic commands (sent as data to card via InDataExchange)
#define MIFARE_CMD_AUTH_KEY_A   0x60
#define MIFARE_CMD_AUTH_KEY_B   0x61
#define MIFARE_CMD_READ_BLOCK   0x30
#define MIFARE_CMD_WRITE_BLOCK  0xA0

// ── Default key dictionary ────────────────────────────────────────────────────
// Standard factory and commonly found keys for authorized testing on own cards.
const uint8_t MIFARE_DEFAULT_KEYS[][6] = {
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },  // factory default
    { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5 },  // MAD sector Key A
    { 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5 },  // MAD sector Key B
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7 },  // NDEF Key A (common tag)
    { 0x4D, 0x3A, 0x99, 0xC3, 0x51, 0xDD },
    { 0x1A, 0x98, 0x2C, 0x7E, 0x45, 0x9A },
    { 0x71, 0x4C, 0x5C, 0x88, 0x6E, 0x97 },
    { 0x58, 0x7E, 0xE5, 0xF9, 0x35, 0x0F },
    { 0xA0, 0x47, 0x8C, 0xC3, 0x90, 0x91 },
    { 0x53, 0x3C, 0xB6, 0xC7, 0x23, 0xF6 },
    { 0x8F, 0xD0, 0xA4, 0xF2, 0x56, 0xE9 },
    { 0x6C, 0x78, 0x92, 0x8E, 0x13, 0x17 },
    { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
    { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 },
};
const uint8_t MIFARE_DEFAULT_KEY_COUNT =
    (uint8_t)(sizeof(MIFARE_DEFAULT_KEYS) / sizeof(MIFARE_DEFAULT_KEYS[0]));

// ── Sector geometry ───────────────────────────────────────────────────────────

uint8_t mifare_sector_block_count(uint8_t sector)
{
    return (sector < 32) ? 4 : 16;
}

uint8_t mifare_sector_first_block(uint8_t sector)
{
    if (sector < 32) return sector * 4;
    return 32 * 4 + (sector - 32) * 16;
}

uint8_t mifare_sector_trailer_block(uint8_t sector)
{
    return mifare_sector_first_block(sector) + mifare_sector_block_count(sector) - 1;
}

void mifare_parse_trailer(const uint8_t trailer[RFID_BLOCK_LEN],
                          uint8_t key_a[6], uint8_t key_b[6],
                          uint8_t access_bits[3])
{
    if (key_a)      memcpy(key_a, trailer, 6);
    if (access_bits) memcpy(access_bits, trailer + 6, 3);
    if (key_b)      memcpy(key_b, trailer + 10, 6);
}

// ── Authentication ────────────────────────────────────────────────────────────

rfid_err_t mifare_auth_sector(uint8_t sector, mifare_key_type_t key_type,
                               const uint8_t key[6],
                               const uint8_t *uid, uint8_t uid_len)
{
    uint8_t trailer = mifare_sector_trailer_block(sector);
    uint8_t auth_cmd = (key_type == MIFARE_KEY_A) ? MIFARE_CMD_AUTH_KEY_A
                                                   : MIFARE_CMD_AUTH_KEY_B;
    // InDataExchange payload: Tg=1, AuthCmd, Block#, Key[6], UID[0..3]
    // Most MIFARE Classic cards use 4-byte UID even if NfcId is 7 bytes (cascade)
    uint8_t effective_uid_len = (uid_len >= 4) ? 4 : uid_len;
    uint8_t cmd[2 + 2 + 6 + 4];  // max size
    uint8_t cmd_len = 0;
    cmd[cmd_len++] = PN532_CMD_IN_DATA_EXCHANGE;
    cmd[cmd_len++] = 0x01;         // Tg = 1 (first target)
    cmd[cmd_len++] = auth_cmd;
    cmd[cmd_len++] = trailer;
    memcpy(cmd + cmd_len, key, 6);       cmd_len += 6;
    memcpy(cmd + cmd_len, uid, effective_uid_len); cmd_len += effective_uid_len;

    rfid_err_t r = pn532_send_command(cmd, cmd_len);
    if (r != RFID_OK) return r;

    uint8_t resp[2]; uint8_t rlen = 0;
    r = pn532_read_response(PN532_CMD_IN_DATA_EXCHANGE, resp, &rlen, sizeof(resp), 500);
    if (r != RFID_OK) return r;
    // resp[0] = error byte from PN532: 0x00 = success
    if (rlen < 1 || resp[0] != 0x00) {
        ESP_LOGD(TAG, "Auth sector %d key%c failed (0x%02X)",
                 sector, key_type == MIFARE_KEY_A ? 'A' : 'B',
                 rlen ? resp[0] : 0xFF);
        return RFID_ERR_AUTH;
    }
    return RFID_OK;
}

// ── Block I/O ─────────────────────────────────────────────────────────────────

rfid_err_t mifare_read_block(uint8_t block, uint8_t data[RFID_BLOCK_LEN])
{
    uint8_t cmd[] = { PN532_CMD_IN_DATA_EXCHANGE, 0x01,
                      MIFARE_CMD_READ_BLOCK, block };
    rfid_err_t r = pn532_send_command(cmd, sizeof(cmd));
    if (r != RFID_OK) return r;

    uint8_t resp[18]; uint8_t rlen = 0;
    r = pn532_read_response(PN532_CMD_IN_DATA_EXCHANGE, resp, &rlen, sizeof(resp), 500);
    if (r != RFID_OK) return r;
    if (rlen < 17 || resp[0] != 0x00) return RFID_ERR_NAK;

    memcpy(data, resp + 1, RFID_BLOCK_LEN);
    return RFID_OK;
}

rfid_err_t mifare_write_block(uint8_t block, const uint8_t data[RFID_BLOCK_LEN])
{
    uint8_t cmd[4 + RFID_BLOCK_LEN] = {
        PN532_CMD_IN_DATA_EXCHANGE, 0x01, MIFARE_CMD_WRITE_BLOCK, block
    };
    memcpy(cmd + 4, data, RFID_BLOCK_LEN);

    rfid_err_t r = pn532_send_command(cmd, sizeof(cmd));
    if (r != RFID_OK) return r;

    uint8_t resp[2]; uint8_t rlen = 0;
    r = pn532_read_response(PN532_CMD_IN_DATA_EXCHANGE, resp, &rlen, sizeof(resp), 500);
    if (r != RFID_OK) return r;
    if (rlen < 1 || resp[0] != 0x00) return RFID_ERR_NAK;
    return RFID_OK;
}

// ── Bulk read ─────────────────────────────────────────────────────────────────

rfid_err_t mifare_read_all(rfid_card_t *card,
                            const uint8_t (*key_dict)[6], uint8_t key_count)
{
    if (!card || !key_dict) return RFID_ERR_HW;

    uint8_t num_sectors = (card->protocol == RFID_PROTO_MIFARE_CLASSIC_4K)
                          ? MIFARE_4K_SECTORS : MIFARE_1K_SECTORS;
    uint8_t key_slot = 0;  // next slot in card->keys[]

    for (uint8_t s = 0; s < num_sectors; s++) {
        bool authed = false;
        mifare_key_type_t found_key_type = MIFARE_KEY_A;
        uint8_t found_key[6];

        // Try Key A first, then Key B for each dictionary entry
        for (int ki = 0; ki < key_count && !authed; ki++) {
            for (int kt = 0; kt < 2 && !authed; kt++) {
                mifare_key_type_t ktype = (kt == 0) ? MIFARE_KEY_A : MIFARE_KEY_B;
                rfid_err_t r = mifare_auth_sector(s, ktype, key_dict[ki],
                                                   card->uid, card->uid_len);
                if (r == RFID_OK) {
                    authed = true;
                    found_key_type = ktype;
                    memcpy(found_key, key_dict[ki], 6);
                }
            }
        }

        if (!authed) {
            ESP_LOGD(TAG, "Sector %d: no key matched", s);
            continue;
        }

        // Store discovered key
        if (key_slot < RFID_MAX_KEYS) {
            card->keys[key_slot].sector = s;
            card->keys[key_slot].type   = found_key_type;
            memcpy(card->keys[key_slot].key, found_key, 6);
            card->keys[key_slot].valid  = true;
            key_slot++;
        }

        // Read all blocks in this sector
        uint8_t first = mifare_sector_first_block(s);
        uint8_t bcount = mifare_sector_block_count(s);
        for (uint8_t b = 0; b < bcount; b++) {
            // block index fits in uint8_t: 4K max block = 255 < 256 = RFID_MAX_BLOCKS
            uint8_t block = first + b;
            rfid_err_t r = mifare_read_block(block, card->blocks[block].data);
            card->blocks[block].valid = (r == RFID_OK);
            if (r != RFID_OK)
                ESP_LOGD(TAG, "Block %d read fail: %s", block, rfid_err_str(r));
        }
    }

    card->key_count = key_slot;
    return RFID_OK;
}
