#include "rfid_storage.h"
#include "rfid_types.h"
#include "esp_log.h"
#include "esp_task_wdt.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <ctype.h>

static const char *TAG = "rfid_stor";

void rfid_storage_ensure_dirs(void)
{
    const char *dirs[] = {
        RFID_DIR_BASE,
        RFID_DIR_HF, RFID_DIR_LF, RFID_DIR_KEYS,
        RFID_DIR_LOGS, RFID_DIR_IMPORT, RFID_DIR_EXPORT,
    };
    struct stat st;
    for (int i = 0; i < (int)(sizeof(dirs)/sizeof(dirs[0])); i++) {
        esp_task_wdt_reset();   // mkdir on FAT can take >1s; keep watchdog fed
        if (stat(dirs[i], &st) != 0) {
            if (mkdir(dirs[i], 0755) == 0)
                ESP_LOGI(TAG, "created %s", dirs[i]);
        }
    }
    esp_task_wdt_reset();
}

// ── Minimal JSON writer ────────────────────────────────────────────────────────
// Writes one key:value pair per line. Valid JSON but no pretty-printing.

static void jw_str(FILE *f, const char *key, const char *val, bool comma)
{
    fprintf(f, "\"%s\":\"%s\"%s", key, val, comma ? "," : "");
}
static void jw_int(FILE *f, const char *key, int val, bool comma)
{
    fprintf(f, "\"%s\":%d%s", key, val, comma ? "," : "");
}

// ── Minimal JSON line-by-line parser ─────────────────────────────────────────
// Parses lines of the form: "key":"value" or "key":number
// Returns pointer to value string in line (static storage in line buffer).

static bool jp_str(const char *line, const char *key, char *val_buf, size_t val_size)
{
    // Find "key":
    char search[64];
    snprintf(search, sizeof(search), "\"%s\":", key);
    const char *p = strstr(line, search);
    if (!p) return false;
    p += strlen(search);
    while (*p == ' ') p++;
    if (*p == '"') {
        p++;
        const char *end = strchr(p, '"');
        if (!end) return false;
        size_t len = (size_t)(end - p);
        if (len >= val_size) len = val_size - 1;
        memcpy(val_buf, p, len);
        val_buf[len] = '\0';
        return true;
    }
    // Numeric value as string
    const char *end = p;
    while (*end && *end != ',' && *end != '}' && *end != '\n') end++;
    size_t len = (size_t)(end - p);
    if (len >= val_size) len = val_size - 1;
    memcpy(val_buf, p, len);
    val_buf[len] = '\0';
    return true;
}

// ── Save ──────────────────────────────────────────────────────────────────────

rfid_err_t rfid_storage_save(const rfid_card_t *card,
                              const char *name,
                              char *path_out, size_t path_out_size)
{
    if (!card) return RFID_ERR_HW;
    rfid_storage_ensure_dirs();

    char filename[RFID_FILENAME_LEN];
    if (name && name[0]) {
        snprintf(filename, sizeof(filename), "%s/%s.json", RFID_DIR_HF, name);
    } else {
        char uid_compact[24];
        rfid_format_uid_compact(card->uid, card->uid_len, uid_compact, sizeof(uid_compact));
        snprintf(filename, sizeof(filename), "%s/%s.json", RFID_DIR_HF, uid_compact);
    }

    FILE *f = fopen(filename, "w");
    if (!f) return RFID_ERR_IO;

    char uid_str[24];
    rfid_format_uid_compact(card->uid, card->uid_len, uid_str, sizeof(uid_str));

    char atqa_str[8]; snprintf(atqa_str, sizeof(atqa_str), "%04X", card->atqa);
    char sak_str[4];  snprintf(sak_str,  sizeof(sak_str),  "%02X", card->sak);

    fprintf(f, "{");
    jw_int(f, "version", 1, true);
    jw_str(f, "band",       rfid_band_str(card->band),           true);
    jw_str(f, "technology", rfid_technology_str(card->technology), true);
    jw_str(f, "protocol",   card->protocol_str,                   true);
    jw_str(f, "uid",        uid_str,                              true);
    jw_int(f, "uid_len",    card->uid_len,                        true);
    jw_str(f, "atqa",       atqa_str,                             true);
    jw_str(f, "sak",        sak_str,                              true);
    jw_str(f, "name",       card->name,                           true);
    jw_str(f, "source",     card->source[0] ? card->source : "scan", true);
    jw_str(f, "timestamp",  card->timestamp,                      true);

    // Blocks sub-object
    fprintf(f, "\"blocks\":{");
    bool first_blk = true;
    char key[8], hex[33];
    for (int b = 0; b < card->block_count && b < RFID_MAX_BLOCKS; b++) {
        if (!card->blocks[b].valid) continue;
        for (int j = 0; j < RFID_BLOCK_LEN; j++)
            snprintf(hex + j*2, 3, "%02X", card->blocks[b].data[j]);
        hex[32] = '\0';
        snprintf(key, sizeof(key), "%d", b);
        if (!first_blk) fprintf(f, ",");
        fprintf(f, "\"%s\":\"%s\"", key, hex);
        first_blk = false;
    }
    fprintf(f, "},");

    // Keys sub-object
    fprintf(f, "\"keys\":{");
    bool first_key = true;
    char kname[24], khex[13];
    for (int k = 0; k < card->key_count; k++) {
        if (!card->keys[k].valid) continue;
        snprintf(kname, sizeof(kname), "s%d_%c",
                 card->keys[k].sector,
                 card->keys[k].type == MIFARE_KEY_A ? 'A' : 'B');
        for (int j = 0; j < 6; j++)
            snprintf(khex + j*2, 3, "%02X", card->keys[k].key[j]);
        khex[12] = '\0';
        if (!first_key) fprintf(f, ",");
        fprintf(f, "\"%s\":\"%s\"", kname, khex);
        first_key = false;
    }
    fprintf(f, "}}");  // close keys and root object

    fclose(f);
    if (path_out) strncpy(path_out, filename, path_out_size - 1);
    ESP_LOGI(TAG, "saved: %s", filename);
    return RFID_OK;
}

// ── Load ──────────────────────────────────────────────────────────────────────

rfid_err_t rfid_storage_load(const char *path, rfid_card_t *card_out)
{
    if (!path || !card_out) return RFID_ERR_HW;

    FILE *f = fopen(path, "r");
    if (!f) return RFID_ERR_NOT_FOUND;

    memset(card_out, 0, sizeof(*card_out));
    card_out->band       = RFID_BAND_HF;
    card_out->technology = RFID_TECH_ISO14443A;

    char line[320];
    char val[128];

    // Read the whole JSON as a single line (we write it compact)
    // Fallback: scan token by token for key-value pairs
    while (fgets(line, sizeof(line), f)) {
        if (jp_str(line, "uid", val, sizeof(val))) {
            int vlen = (int)strlen(val);
            card_out->uid_len = 0;
            for (int i = 0; i + 1 < vlen && card_out->uid_len < RFID_MAX_UID_LEN; i += 2) {
                unsigned int byte;
                if (sscanf(val + i, "%2x", &byte) == 1)
                    card_out->uid[card_out->uid_len++] = (uint8_t)byte;
            }
        }
        if (jp_str(line, "atqa", val, sizeof(val))) {
            unsigned int v = 0; sscanf(val, "%x", &v); card_out->atqa = (uint16_t)v;
        }
        if (jp_str(line, "sak", val, sizeof(val))) {
            unsigned int v = 0; sscanf(val, "%x", &v); card_out->sak = (uint8_t)v;
        }
        if (jp_str(line, "name", val, sizeof(val)))
            strncpy(card_out->name, val, sizeof(card_out->name) - 1);
        if (jp_str(line, "protocol", val, sizeof(val)))
            strncpy(card_out->protocol_str, val, sizeof(card_out->protocol_str) - 1);
        if (jp_str(line, "source", val, sizeof(val)))
            strncpy(card_out->source, val, sizeof(card_out->source) - 1);
        if (jp_str(line, "timestamp", val, sizeof(val)))
            strncpy(card_out->timestamp, val, sizeof(card_out->timestamp) - 1);

        // Block data: look for "N":"<32 hex chars>" patterns
        // Since the whole file is one line, iterate through the "blocks":{} section
        const char *p = line;
        while ((p = strstr(p, "\":\"")) != NULL) {
            // Find the key before the ":"
            const char *kend = p;
            const char *kstart = kend - 1;
            while (kstart > line && *kstart != '"') kstart--;
            kstart++; // skip opening quote

            // Check if the key is a number (block index) or "sN_A/B" (key)
            char kbuf[24];
            size_t klen = (size_t)(kend - kstart);
            if (klen > 0 && klen < sizeof(kbuf)) {
                memcpy(kbuf, kstart, klen);
                kbuf[klen] = '\0';

                // Block index (pure digits)?
                bool is_digits = true;
                for (size_t di = 0; di < klen; di++)
                    if (!isdigit((unsigned char)kbuf[di])) { is_digits = false; break; }

                if (is_digits) {
                    int blk = atoi(kbuf);
                    // Value starts after the \":\" pattern
                    const char *vstart = p + 3;
                    const char *vend   = strchr(vstart, '"');
                    if (vend && blk >= 0 && blk < RFID_MAX_BLOCKS) {
                        int vl = (int)(vend - vstart);
                        for (int j = 0; j + 1 < vl && j/2 < RFID_BLOCK_LEN; j += 2) {
                            unsigned int byte;
                            if (sscanf(vstart + j, "%2x", &byte) == 1)
                                card_out->blocks[blk].data[j/2] = (uint8_t)byte;
                        }
                        if (vl >= RFID_BLOCK_LEN * 2) {
                            card_out->blocks[blk].valid = true;
                            if ((uint16_t)(blk + 1) > card_out->block_count)
                                card_out->block_count = (uint16_t)(blk + 1);
                        }
                    }
                }

                // Sector key "sN_A" or "sN_B"?
                else if (klen > 2 && kbuf[0] == 's' && card_out->key_count < RFID_MAX_KEYS) {
                    int sector; char type_c;
                    if (sscanf(kbuf, "s%d_%c", &sector, &type_c) == 2) {
                        const char *vstart = p + 3;
                        const char *vend   = strchr(vstart, '"');
                        if (vend) {
                            rfid_sector_key_t *sk = &card_out->keys[card_out->key_count];
                            sk->sector = (uint8_t)sector;
                            sk->type   = (type_c == 'B') ? MIFARE_KEY_B : MIFARE_KEY_A;
                            int vl = (int)(vend - vstart);
                            for (int j = 0; j + 1 < vl && j/2 < 6; j += 2) {
                                unsigned int byte;
                                if (sscanf(vstart + j, "%2x", &byte) == 1)
                                    sk->key[j/2] = (uint8_t)byte;
                            }
                            sk->valid = true;
                            card_out->key_count++;
                        }
                    }
                }
            }
            p += 3; // advance past current match
        }
    }
    fclose(f);
    return (card_out->uid_len > 0) ? RFID_OK : RFID_ERR_IO;
}

// ── List ──────────────────────────────────────────────────────────────────────

int rfid_storage_list(rfid_band_t band,
                       rfid_card_entry_t *entries, int max_count)
{
    if (!entries || max_count <= 0) return 0;
    const char *dir = (band == RFID_BAND_HF) ? RFID_DIR_HF : RFID_DIR_LF;

    DIR *d = opendir(dir);
    if (!d) return 0;

    int count = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL && count < max_count) {
        if (de->d_type != DT_REG) continue;
        const char *ext = strrchr(de->d_name, '.');
        if (!ext || strcmp(ext, ".json") != 0) continue;

        rfid_card_entry_t *e = &entries[count];
        memset(e, 0, sizeof(*e));
        snprintf(e->path, sizeof(e->path), "%s/%s", dir, de->d_name);

        strncpy(e->display_name, de->d_name, sizeof(e->display_name) - 1);
        char *dot = strrchr(e->display_name, '.');
        if (dot) *dot = '\0';

        rfid_card_t card;
        if (rfid_storage_load(e->path, &card) == RFID_OK) {
            rfid_format_uid(card.uid, card.uid_len, e->uid_str, sizeof(e->uid_str));
            strncpy(e->protocol_str, card.protocol_str, sizeof(e->protocol_str) - 1);
            strncpy(e->timestamp, card.timestamp, sizeof(e->timestamp) - 1);
            if (card.name[0]) strncpy(e->display_name, card.name, sizeof(e->display_name) - 1);
        }
        count++;
    }
    closedir(d);
    return count;
}

// ── Delete ────────────────────────────────────────────────────────────────────

rfid_err_t rfid_storage_delete(const char *path)
{
    if (!path) return RFID_ERR_HW;
    return (remove(path) == 0) ? RFID_OK : RFID_ERR_IO;
}
