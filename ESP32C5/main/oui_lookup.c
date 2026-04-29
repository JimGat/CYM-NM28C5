#include "oui_lookup.h"
#include <string.h>
#include <stdio.h>
#include "esp_heap_caps.h"
#include "esp_log.h"

static const char *TAG = "oui_lookup";

#define OUI_ENTRY_SIZE 32  /* oui[3] + name[29] */

typedef struct __attribute__((packed)) {
    uint8_t oui[3];
    char    name[29];
} oui_entry_t;

_Static_assert(sizeof(oui_entry_t) == OUI_ENTRY_SIZE, "oui_entry_t size mismatch");

static oui_entry_t *s_table = NULL;
static uint32_t     s_count = 0;

esp_err_t oui_lookup_init(const char *bin_path)
{
    oui_lookup_deinit();

    FILE *f = fopen(bin_path, "rb");
    if (!f) {
        ESP_LOGW(TAG, "Not found: %s", bin_path);
        return ESP_ERR_NOT_FOUND;
    }

    char magic[4];
    uint32_t count = 0;
    if (fread(magic, 1, 4, f) != 4 || memcmp(magic, "OUI1", 4) != 0 ||
        fread(&count, 4, 1, f) != 1 || count == 0) {
        ESP_LOGE(TAG, "Bad header in %s", bin_path);
        fclose(f);
        return ESP_ERR_INVALID_ARG;
    }

    size_t bytes = (size_t)count * OUI_ENTRY_SIZE;
    s_table = (oui_entry_t *)heap_caps_malloc(bytes, MALLOC_CAP_SPIRAM);
    if (!s_table) {
        ESP_LOGE(TAG, "PSRAM alloc failed (%u bytes)", (unsigned)bytes);
        fclose(f);
        return ESP_ERR_NO_MEM;
    }

    if (fread(s_table, OUI_ENTRY_SIZE, count, f) != count) {
        ESP_LOGE(TAG, "Short read from %s", bin_path);
        free(s_table);
        s_table = NULL;
        fclose(f);
        return ESP_FAIL;
    }
    fclose(f);
    s_count = count;
    ESP_LOGI(TAG, "Loaded %u OUI entries from %s", count, bin_path);
    return ESP_OK;
}

const char *oui_lookup(const uint8_t oui3[3])
{
    if (!s_table || s_count == 0) return NULL;
    int lo = 0, hi = (int)s_count - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        int cmp = memcmp(s_table[mid].oui, oui3, 3);
        if      (cmp == 0) return s_table[mid].name;
        else if (cmp < 0)  lo = mid + 1;
        else               hi = mid - 1;
    }
    return NULL;
}

bool     oui_lookup_is_loaded(void) { return s_table != NULL; }
uint32_t oui_lookup_count(void)     { return s_count; }

void oui_lookup_deinit(void)
{
    if (s_table) { free(s_table); s_table = NULL; }
    s_count = 0;
}
