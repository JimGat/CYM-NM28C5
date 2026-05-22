#include "rfid_manager.h"
#include "rfid_types.h"
#include "hf/pn532_driver.h"
#include "hf/pn532_reader.h"
#include "hf/pn532_target.h"
#include "hf/mifare_classic.h"
#include "lf/lf_stub.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_heap_caps.h"
#include <string.h>

static const char *TAG = "rfid_mgr";

// ── Poll task state ───────────────────────────────────────────────────────────
static TaskHandle_t   s_poll_task   = NULL;
static rfid_poll_cb_t s_poll_cb     = NULL;
static void          *s_poll_ctx    = NULL;
static uint32_t       s_poll_ms     = 500;
static volatile bool  s_poll_stop   = false;
static bool           s_mgr_init    = false;
static bool           s_addr_ok     = false;  // last pn532_probe_device() result

// Shared card buffer for poll task — PSRAM-allocated to keep s_poll_card out of DRAM
static rfid_card_t *s_poll_card = NULL;

static void s_poll_task_fn(void *arg)
{
    (void)arg;
    while (!s_poll_stop) {
        memset(s_poll_card, 0, sizeof(*s_poll_card));
        rfid_err_t r = pn532_scan_card(s_poll_card, s_poll_ms);
        if (s_poll_cb && !s_poll_stop) {
            s_poll_cb(r, (r == RFID_OK) ? s_poll_card : NULL, s_poll_ctx);
        }
        // Brief gap between polls to let LVGL process and card to be removed
        if (!s_poll_stop) vTaskDelay(pdMS_TO_TICKS(250));
    }
    s_poll_task = NULL;
    vTaskDelete(NULL);
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────

rfid_err_t rfid_manager_init(void)
{
    if (s_mgr_init) return RFID_OK;

    if (!s_poll_card) {
        s_poll_card = heap_caps_calloc(1, sizeof(rfid_card_t), MALLOC_CAP_SPIRAM);
        if (!s_poll_card) {
            ESP_LOGE(TAG, "PSRAM alloc failed for poll card");
            return RFID_ERR_HW;
        }
    }

    rfid_err_t r = pn532_driver_init();
    if (r != RFID_OK) {
        ESP_LOGE(TAG, "PN532 driver init failed: %s", rfid_err_str(r));
        return r;
    }
    // Retry SAM configure up to 5x with 200ms gaps. The ESP-IDF I2C master driver
    // sometimes rejects the first transaction after bus creation; a retry succeeds.
    r = RFID_ERR_HW;
    for (int attempt = 0; attempt < 5 && r != RFID_OK; attempt++) {
        if (attempt > 0) {
            ESP_LOGW(TAG, "SAM configure retry %d/5...", attempt + 1);
            vTaskDelay(pdMS_TO_TICKS(200));
        }
        r = pn532_sam_configure();
    }
    if (r != RFID_OK) {
        // Keep I2C bus up so the UI retry timer can call rfid_manager_init() again
        // without re-creating the bus. Do NOT deinit the driver here.
        s_addr_ok = (pn532_probe_device() == RFID_OK);
        if (s_addr_ok) {
            ESP_LOGW(TAG, "[DIAG] SAM configure failed — PN532 at 0x24 but not accepting commands"
                         " (I2C mode jumper? bus noise?)");
        } else {
            ESP_LOGW(TAG, "[DIAG] SAM configure failed — PN532 not at 0x24"
                         " (DIP3 OFF? wrong mode jumper?)");
        }
        return RFID_ERR_HW;
    }
    s_mgr_init = true;
    ESP_LOGI(TAG, "init OK");
    return RFID_OK;
}

void rfid_manager_deinit(void)
{
    rfid_manager_stop_poll();
    pn532_driver_deinit();
    if (s_poll_card) { free(s_poll_card); s_poll_card = NULL; }
    s_mgr_init = false;
    ESP_LOGI(TAG, "deinit");
}

bool rfid_manager_is_init(void)    { return s_mgr_init; }
bool rfid_manager_is_addr_ok(void) { return s_addr_ok; }

// ── Probe ─────────────────────────────────────────────────────────────────────

rfid_err_t rfid_manager_probe(rfid_probe_result_t *out)
{
    if (!s_mgr_init) return RFID_ERR_NOT_INIT;
    if (!out) return RFID_ERR_HW;

    memset(out, 0, sizeof(*out));
    pn532_fw_version_t fw;
    rfid_err_t r = pn532_get_firmware_version(&fw);
    if (r != RFID_OK) {
        snprintf(out->desc, sizeof(out->desc), "PN532 not responding");
        out->found = false;
        return r;
    }
    out->found  = true;
    out->ic     = fw.ic;
    out->fw_ver = fw.ver;
    out->fw_rev = fw.rev;
    snprintf(out->desc, sizeof(out->desc), "PN532 v%d.%d OK", fw.ver, fw.rev);
    return RFID_OK;
}

// ── Background poll ───────────────────────────────────────────────────────────

rfid_err_t rfid_manager_start_poll(rfid_poll_cb_t cb, void *ctx, uint32_t poll_interval_ms)
{
    if (!s_mgr_init) return RFID_ERR_NOT_INIT;

    rfid_manager_stop_poll();

    s_poll_cb   = cb;
    s_poll_ctx  = ctx;
    s_poll_ms   = poll_interval_ms ? poll_interval_ms : 500;
    s_poll_stop = false;

    BaseType_t rc = xTaskCreate(s_poll_task_fn, "rfid_poll", 4096, NULL,
                                 tskIDLE_PRIORITY + 2, &s_poll_task);
    return (rc == pdPASS) ? RFID_OK : RFID_ERR_HW;
}

void rfid_manager_stop_poll(void)
{
    if (!s_poll_task) return;
    s_poll_stop = true;
    // Give the task time to exit cleanly
    uint32_t wait = 0;
    while (s_poll_task && wait < 2000) {
        vTaskDelay(pdMS_TO_TICKS(50));
        wait += 50;
    }
    if (s_poll_task) {
        vTaskDelete(s_poll_task);
        s_poll_task = NULL;
    }
}

bool rfid_manager_is_polling(void) { return s_poll_task != NULL; }

// ── Card emulation ─────────────────────────────────────────────────────────────

static TaskHandle_t  s_emu_task = NULL;
static volatile bool s_emu_stop = false;
static rfid_emu_cb_t s_emu_cb   = NULL;
static void         *s_emu_ctx  = NULL;
static rfid_card_t   s_emu_card;

static void s_emu_task_fn(void *arg)
{
    (void)arg;
    pn532_emulate_card(&s_emu_card, s_emu_cb, s_emu_ctx, &s_emu_stop);
    s_emu_task = NULL;
    vTaskDelete(NULL);
}

rfid_err_t rfid_manager_start_emulate(const rfid_card_t *card,
                                       rfid_emu_cb_t cb, void *ctx)
{
    if (!s_mgr_init) return RFID_ERR_NOT_INIT;
    if (!card) return RFID_ERR_HW;
    rfid_manager_stop_emulate();
    memcpy(&s_emu_card, card, sizeof(rfid_card_t));
    s_emu_cb   = cb;
    s_emu_ctx  = ctx;
    s_emu_stop = false;
    BaseType_t rc = xTaskCreate(s_emu_task_fn, "rfid_emu", 4096, NULL,
                                 tskIDLE_PRIORITY + 2, &s_emu_task);
    return (rc == pdPASS) ? RFID_OK : RFID_ERR_HW;
}

void rfid_manager_stop_emulate(void)
{
    if (!s_emu_task) return;
    s_emu_stop = true;
    uint32_t wait = 0;
    // Allow up to 6 s (2× poll cycle) for task to exit cleanly
    while (s_emu_task && wait < 6000) {
        vTaskDelay(pdMS_TO_TICKS(50));
        wait += 50;
    }
    if (s_emu_task) {
        vTaskDelete(s_emu_task);
        s_emu_task = NULL;
    }
}

bool rfid_manager_is_emulating(void) { return s_emu_task != NULL; }

// ── One-shot scan ─────────────────────────────────────────────────────────────

rfid_err_t rfid_manager_scan_card(rfid_card_t *card_out, uint32_t timeout_ms)
{
    if (!s_mgr_init) return RFID_ERR_NOT_INIT;
    return pn532_scan_card(card_out, timeout_ms);
}

// ── MIFARE key dict test ──────────────────────────────────────────────────────

rfid_err_t rfid_manager_test_mifare_keys(rfid_card_t *card,
                                          rfid_key_progress_cb_t progress_cb,
                                          void *ctx)
{
    if (!s_mgr_init) return RFID_ERR_NOT_INIT;
    if (!card) return RFID_ERR_HW;
    int proto = (int)card->protocol;
    if (proto != (int)RFID_PROTO_MIFARE_CLASSIC_1K &&
        proto != (int)RFID_PROTO_MIFARE_CLASSIC_4K)
        return RFID_ERR_NOT_SUPPORTED;

    uint8_t num_sectors = (proto == (int)RFID_PROTO_MIFARE_CLASSIC_4K)
                          ? MIFARE_4K_SECTORS : MIFARE_1K_SECTORS;

    for (uint8_t s = 0; s < num_sectors; s++) {
        bool found = false;
        for (uint8_t ki = 0; ki < MIFARE_DEFAULT_KEY_COUNT && !found; ki++) {
            for (int kt = 0; kt < 2 && !found; kt++) {
                mifare_key_type_t ktype = (kt == 0) ? MIFARE_KEY_A : MIFARE_KEY_B;
                rfid_err_t r = mifare_auth_sector(s, ktype, MIFARE_DEFAULT_KEYS[ki],
                                                   card->uid, card->uid_len);
                if (r == RFID_OK) {
                    found = true;
                    if (card->key_count < RFID_MAX_KEYS) {
                        card->keys[card->key_count].sector = s;
                        card->keys[card->key_count].type   = ktype;
                        memcpy(card->keys[card->key_count].key,
                               MIFARE_DEFAULT_KEYS[ki], 6);
                        card->keys[card->key_count].valid = true;
                        card->key_count++;
                    }
                    // Read all blocks in this sector (blk fits uint8_t, always < RFID_MAX_BLOCKS)
                    uint8_t first = mifare_sector_first_block(s);
                    uint8_t bcount = mifare_sector_block_count(s);
                    for (uint8_t b = 0; b < bcount; b++) {
                        uint8_t blk = first + b;
                        if (mifare_read_block(blk, card->blocks[blk].data) == RFID_OK)
                            card->blocks[blk].valid = true;
                    }
                }
            }
        }
        if (progress_cb) progress_cb(s, num_sectors, found, ctx);
    }
    return RFID_OK;
}

// ── I2C diagnostic scan ───────────────────────────────────────────────────────

int rfid_manager_i2c_scan(uint8_t *addrs_out, int max_addrs)
{
    if (!s_mgr_init) return -1;
    return pn532_i2c_scan(addrs_out, max_addrs);
}
