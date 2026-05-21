#include "flipper_nfc_file.h"
#include "rfid_types.h"
#include "esp_log.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

static const char *TAG = "flipper_nfc";

// ── Filetype strings ──────────────────────────────────────────────────────────
#define NFC_FILETYPE  "Flipper NFC device"
#define NFC_VERSION   "4"

// Flipper device type strings
static const char *s_device_type(const rfid_card_t *card)
{
    switch (card->protocol) {
        case RFID_PROTO_MIFARE_CLASSIC_1K:
        case RFID_PROTO_MIFARE_CLASSIC_4K:  return "MIFARE Classic";
        case RFID_PROTO_MIFARE_ULTRALIGHT:
        case RFID_PROTO_NTAG213:
        case RFID_PROTO_NTAG215:
        case RFID_PROTO_NTAG216:             return "NTAG/Ultralight";
        case RFID_PROTO_ISO14443_4:          return "ISO14443-4A";
        case RFID_PROTO_DESFIRE:             return "MIFARE DESFire";
        default:                             return "ISO14443-3A";
    }
}

// ── Export ────────────────────────────────────────────────────────────────────

rfid_err_t flipper_nfc_export(const rfid_card_t *card, const char *path)
{
    if (!card || !path) return RFID_ERR_HW;

    FILE *f = fopen(path, "w");
    if (!f) return RFID_ERR_IO;

    // Header
    fprintf(f, "Filetype: %s\n", NFC_FILETYPE);
    fprintf(f, "Version: %s\n",  NFC_VERSION);
    fprintf(f, "Device type: %s\n", s_device_type(card));

    // UID (space-separated hex, Flipper style)
    fprintf(f, "UID:");
    for (int i = 0; i < card->uid_len; i++) fprintf(f, " %02X", card->uid[i]);
    fprintf(f, "\n");

    // ATQA (2 bytes, LSB first on wire but Flipper shows MSB first in file)
    fprintf(f, "ATQA: %02X %02X\n",
            (card->atqa >> 8) & 0xFF, card->atqa & 0xFF);
    fprintf(f, "SAK: %02X\n", card->sak);

    // MIFARE Classic block data
    if (card->protocol == RFID_PROTO_MIFARE_CLASSIC_1K ||
        card->protocol == RFID_PROTO_MIFARE_CLASSIC_4K) {
        const char *type_str = (card->protocol == RFID_PROTO_MIFARE_CLASSIC_4K)
                               ? "4K" : "1K";
        fprintf(f, "Mifare Classic type: %s\n", type_str);
        fprintf(f, "Data format version: 2\n");

        uint16_t num_blocks = (card->protocol == RFID_PROTO_MIFARE_CLASSIC_4K) ? 256 : 64;
        for (uint16_t b = 0; b < num_blocks; b++) {
            fprintf(f, "Block %u:", (unsigned)b);
            if (b < RFID_MAX_BLOCKS && card->blocks[b].valid) {
                for (int j = 0; j < RFID_BLOCK_LEN; j++)
                    fprintf(f, " %02X", card->blocks[b].data[j]);
            } else {
                // Unknown blocks filled with 0x00 per Flipper convention
                for (int j = 0; j < RFID_BLOCK_LEN; j++) fprintf(f, " 00");
            }
            fprintf(f, "\n");
        }
    }

    // NTAG / Ultralight page data
    else if (card->protocol == RFID_PROTO_NTAG213 ||
             card->protocol == RFID_PROTO_NTAG215 ||
             card->protocol == RFID_PROTO_NTAG216 ||
             card->protocol == RFID_PROTO_MIFARE_ULTRALIGHT) {
        const char *ul_type = "NTAG213";
        if (card->protocol == RFID_PROTO_NTAG215)        ul_type = "NTAG215";
        else if (card->protocol == RFID_PROTO_NTAG216)   ul_type = "NTAG216";
        else if (card->protocol == RFID_PROTO_MIFARE_ULTRALIGHT) ul_type = "Ultralight";
        fprintf(f, "Data format version: 1\n");
        fprintf(f, "NTAG/Ultralight type: %s\n", ul_type);
        fprintf(f, "Pages total: %u\n", (unsigned)card->page_count);
        fprintf(f, "Pages read: %u\n",  (unsigned)card->page_count);
        for (uint16_t pg = 0; pg < card->page_count && pg < RFID_MAX_BLOCKS; pg++) {
            fprintf(f, "Page %u:", (unsigned)pg);
            if (card->blocks[pg].valid) {
                for (int j = 0; j < 4; j++)
                    fprintf(f, " %02X", card->blocks[pg].data[j]);
            } else {
                fprintf(f, " 00 00 00 00");
            }
            fprintf(f, "\n");
        }
    }

    fclose(f);
    ESP_LOGI(TAG, "exported: %s", path);
    return RFID_OK;
}

// ── Import ────────────────────────────────────────────────────────────────────

rfid_err_t flipper_nfc_import(const char *path, rfid_card_t *card_out)
{
    if (!path || !card_out) return RFID_ERR_HW;

    FILE *f = fopen(path, "r");
    if (!f) return RFID_ERR_NOT_FOUND;

    memset(card_out, 0, sizeof(*card_out));
    card_out->band       = RFID_BAND_HF;
    card_out->technology = RFID_TECH_ISO14443A;
    strncpy(card_out->source, "import", sizeof(card_out->source) - 1);

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        // Strip newline
        int len = (int)strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) line[--len] = '\0';

        if (strncmp(line, "UID:", 4) == 0) {
            const char *p = line + 4;
            while (*p == ' ') p++;
            card_out->uid_len = 0;
            while (*p && card_out->uid_len < RFID_MAX_UID_LEN) {
                unsigned int byte;
                if (sscanf(p, "%2x", &byte) == 1) {
                    card_out->uid[card_out->uid_len++] = (uint8_t)byte;
                    p += 2;
                    while (*p == ' ') p++;
                } else break;
            }
        } else if (strncmp(line, "ATQA:", 5) == 0) {
            unsigned int b0, b1;
            if (sscanf(line + 5, " %2x %2x", &b0, &b1) == 2)
                card_out->atqa = (uint16_t)(b0 << 8 | b1);
        } else if (strncmp(line, "SAK:", 4) == 0) {
            unsigned int v;
            if (sscanf(line + 4, " %2x", &v) == 1)
                card_out->sak = (uint8_t)v;
        } else if (strncmp(line, "Device type:", 12) == 0) {
            const char *dt = line + 12;
            while (*dt == ' ') dt++;
            if (strstr(dt, "MIFARE Classic")) {
                card_out->protocol = RFID_PROTO_MIFARE_CLASSIC_1K;
            } else if (strstr(dt, "NTAG") || strstr(dt, "Ultralight")) {
                card_out->protocol = RFID_PROTO_NTAG213;
            }
        } else if (strncmp(line, "Mifare Classic type:", 20) == 0) {
            if (strstr(line + 20, "4K"))
                card_out->protocol = RFID_PROTO_MIFARE_CLASSIC_4K;
            else
                card_out->protocol = RFID_PROTO_MIFARE_CLASSIC_1K;
        } else if (strncmp(line, "Block ", 6) == 0) {
            int blk;
            if (sscanf(line + 6, "%d:", &blk) == 1 &&
                blk >= 0 && blk < RFID_MAX_BLOCKS) {
                const char *p = strchr(line + 6, ':');
                if (p) {
                    p++;
                    for (int j = 0; j < RFID_BLOCK_LEN; j++) {
                        while (*p == ' ') p++;
                        unsigned int byte;
                        if (sscanf(p, "%2x", &byte) == 1) {
                            card_out->blocks[blk].data[j] = (uint8_t)byte;
                            p += 2;
                        } else break;
                    }
                    card_out->blocks[blk].valid = true;
                    if ((uint16_t)(blk + 1) > card_out->block_count)
                        card_out->block_count = (uint16_t)(blk + 1);
                }
            }
        } else if (strncmp(line, "Page ", 5) == 0) {
            int pg;
            if (sscanf(line + 5, "%d:", &pg) == 1 &&
                pg >= 0 && pg < RFID_MAX_BLOCKS) {
                const char *p = strchr(line + 5, ':');
                if (p) {
                    p++;
                    for (int j = 0; j < 4; j++) {
                        while (*p == ' ') p++;
                        unsigned int byte;
                        if (sscanf(p, "%2x", &byte) == 1) {
                            card_out->blocks[pg].data[j] = (uint8_t)byte;
                            p += 2;
                        } else break;
                    }
                    card_out->blocks[pg].valid = true;
                    if ((uint16_t)(pg + 1) > card_out->page_count)
                        card_out->page_count = (uint16_t)(pg + 1);
                }
            }
        }
    }
    fclose(f);

    // Finalize protocol string
    strncpy(card_out->protocol_str, rfid_protocol_str(card_out->protocol),
            sizeof(card_out->protocol_str) - 1);

    ESP_LOGI(TAG, "imported: %s uid_len=%d proto=%s",
             path, card_out->uid_len, card_out->protocol_str);
    return (card_out->uid_len > 0) ? RFID_OK : RFID_ERR_IO;
}

void flipper_nfc_make_filename(const rfid_card_t *card, char *buf, size_t buf_size)
{
    char uid[24];
    rfid_format_uid_compact(card->uid, card->uid_len, uid, sizeof(uid));
    snprintf(buf, buf_size, "%s.nfc", uid);
}
