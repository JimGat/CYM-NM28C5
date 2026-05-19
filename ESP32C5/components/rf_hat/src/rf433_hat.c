#include "rf433_hat.h"
#include "rf_hat_config.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_heap_caps.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>

static const char *TAG = "rf433_hat";

#define RF433_FRAME_GAP_US   30000
#define RF433_MIN_PULSE_US   100

// ── ISR state (IRAM) ─────────────────────────────────────────────────────────
static volatile bool     s_capturing    = false;
static volatile uint32_t s_pulse_count  = 0;
static volatile int64_t  s_last_edge_us = 0;
static bool              s_jamming      = false;

// ISR double-buffer in DRAM (ISR writes here; capped at 256 — enough for all
// standard OOK frames like garage/car-key/weather-station codes).
#define RF433_ISR_BUF_MAX 256
static uint32_t s_isr_buf[RF433_ISR_BUF_MAX];
static volatile bool s_frame_ready = false;

static TaskHandle_t      s_cap_task   = NULL;
static rf433_hat_cb_t    s_cap_cb     = NULL;
static void             *s_cap_ctx    = NULL;
static uint32_t          s_cap_tmo_ms = 5000;
static SemaphoreHandle_t s_frame_sem  = NULL;

// Signal buffer allocated from PSRAM at full init time (not DRAM static).
static rf433_signal_t   *s_cap_buf   = NULL;

static bool s_init    = false;  // full init (RX ISR + TX)
static bool s_tx_init = false;  // TX-only init (for jammer without full init)

// ── TX-only GPIO setup (called by both full init and jammer) ─────────────────

static void s_setup_tx(void)
{
    if (s_tx_init) return;
    gpio_config_t tx_cfg = {
        .pin_bit_mask = (1ULL << RF_HAT_RF433_TX_GPIO),
        .mode         = GPIO_MODE_OUTPUT,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&tx_cfg);
    gpio_set_level(RF_HAT_RF433_TX_GPIO, 0);
    s_tx_init = true;
}

// ── GPIO ISR handler (IRAM) ───────────────────────────────────────────────────

static void IRAM_ATTR s_gpio_isr(void *arg)
{
    if (!s_capturing) return;

    int64_t now = esp_timer_get_time();
    int64_t gap_us = now - s_last_edge_us;
    s_last_edge_us = now;

    if (gap_us < RF433_MIN_PULSE_US) return;

    if (gap_us > RF433_FRAME_GAP_US) {
        if (s_pulse_count > 4 && !s_frame_ready) {
            s_frame_ready = true;
            BaseType_t woken = pdFALSE;
            xSemaphoreGiveFromISR(s_frame_sem, &woken);
            if (woken) portYIELD_FROM_ISR();
        }
        s_pulse_count = 0;
        return;
    }

    if (s_pulse_count < RF433_ISR_BUF_MAX) {
        s_isr_buf[s_pulse_count++] = (uint32_t)gap_us;
    }
}

// ── Capture background task ───────────────────────────────────────────────────

static void s_capture_task(void *arg)
{
    s_last_edge_us = esp_timer_get_time();
    s_capturing    = true;
    s_frame_ready  = false;
    s_pulse_count  = 0;

    rf433_hat_err_t result = RF433_HAT_ERR_TIMEOUT;

    if (xSemaphoreTake(s_frame_sem, pdMS_TO_TICKS(s_cap_tmo_ms)) == pdTRUE && s_frame_ready) {
        uint32_t n = s_pulse_count;
        if (n > RF433_HAT_MAX_PULSES) n = RF433_HAT_MAX_PULSES;
        if (s_cap_buf) {
            memcpy(s_cap_buf->pulses_us, s_isr_buf, n * sizeof(uint32_t));
            s_cap_buf->count   = n;
            s_cap_buf->freq_hz = RF433_HAT_DEFAULT_FREQ_HZ;
            snprintf(s_cap_buf->name, RF433_HAT_NAME_LEN, "signal");
        }
        result = (n > 4 && s_cap_buf) ? RF433_HAT_OK : RF433_HAT_ERR_TIMEOUT;
    }

    s_capturing = false;
    if (s_cap_cb) s_cap_cb(result, result == RF433_HAT_OK ? s_cap_buf : NULL, s_cap_ctx);
    s_cap_task = NULL;
    vTaskDelete(NULL);
}

// ── Public API ────────────────────────────────────────────────────────────────

rf433_hat_err_t rf433_hat_init(void)
{
    if (s_init) return RF433_HAT_OK;

    // Signal buffer from PSRAM — keeps ~2 KB out of internal DRAM.
    if (!s_cap_buf) {
        s_cap_buf = heap_caps_malloc(sizeof(rf433_signal_t),
                                     MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!s_cap_buf) return RF433_HAT_ERR_HW;
    }

    s_frame_sem = xSemaphoreCreateBinary();
    if (!s_frame_sem) goto fail;

    gpio_config_t rx_cfg = {
        .pin_bit_mask = (1ULL << RF_HAT_RF433_RX_GPIO),
        .mode         = GPIO_MODE_INPUT,
        .pull_up_en   = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_ANYEDGE,
    };
    if (gpio_config(&rx_cfg) != ESP_OK) goto fail;
    gpio_install_isr_service(ESP_INTR_FLAG_IRAM);
    gpio_isr_handler_add(RF_HAT_RF433_RX_GPIO, s_gpio_isr, NULL);

    s_setup_tx();

    s_init = true;
    ESP_LOGI(TAG, "RF433 init OK (TX=GPIO%d, RX=GPIO%d)",
             RF_HAT_RF433_TX_GPIO, RF_HAT_RF433_RX_GPIO);
    return RF433_HAT_OK;

fail:
    ESP_LOGE(TAG, "RF433 init failed");
    rf433_hat_deinit();
    return RF433_HAT_ERR_HW;
}

void rf433_hat_deinit(void)
{
    rf433_hat_capture_cancel();
    s_capturing = false;
    if (RF_HAT_RF433_RX_GPIO >= 0) gpio_isr_handler_remove(RF_HAT_RF433_RX_GPIO);
    if (s_frame_sem) { vSemaphoreDelete(s_frame_sem); s_frame_sem = NULL; }
    if (s_cap_buf)   { free(s_cap_buf); s_cap_buf = NULL; }
    s_init    = false;
    s_tx_init = false;
}

bool rf433_hat_is_init(void) { return s_init; }

rf433_hat_err_t rf433_hat_capture_start(rf433_hat_cb_t cb, void *ctx, uint32_t timeout_ms)
{
    if (!s_init)    return RF433_HAT_ERR_NOT_INIT;
    if (s_cap_task) return RF433_HAT_ERR_BUSY;

    s_cap_cb     = cb;
    s_cap_ctx    = ctx;
    s_cap_tmo_ms = timeout_ms ? timeout_ms : 5000;
    xSemaphoreTake(s_frame_sem, 0);

    BaseType_t ok = xTaskCreate(s_capture_task, "rf433_cap", 4096, NULL,
                                 tskIDLE_PRIORITY + 2, &s_cap_task);
    return (ok == pdPASS) ? RF433_HAT_OK : RF433_HAT_ERR_HW;
}

void rf433_hat_capture_cancel(void)
{
    s_capturing = false;
    if (s_cap_task) { vTaskDelete(s_cap_task); s_cap_task = NULL; }
}

rf433_hat_err_t rf433_hat_replay(const rf433_signal_t *sig, uint8_t repeat)
{
    if (!s_init)  return RF433_HAT_ERR_NOT_INIT;
    if (!sig || sig->count == 0) return RF433_HAT_ERR_HW;
    if (repeat == 0) repeat = 1;

    for (uint8_t r = 0; r < repeat; r++) {
        for (uint32_t i = 0; i < sig->count; i++) {
            int level = (i % 2 == 0) ? 1 : 0;
            gpio_set_level(RF_HAT_RF433_TX_GPIO, level);
            int64_t end = esp_timer_get_time() + sig->pulses_us[i];
            while (esp_timer_get_time() < end) {}
        }
        gpio_set_level(RF_HAT_RF433_TX_GPIO, 0);
        if (r < repeat - 1) vTaskDelay(pdMS_TO_TICKS(10));
    }
    return RF433_HAT_OK;
}

// ── Storage — Flipper Zero .sub compatible ────────────────────────────────────

rf433_hat_err_t rf433_hat_save(const rf433_signal_t *sig, const char *filename)
{
    if (!sig || !filename) return RF433_HAT_ERR_IO;

    struct stat st;
    if (stat(RF_HAT_RF433_SAVE_DIR, &st) != 0) mkdir(RF_HAT_RF433_SAVE_DIR, 0755);

    char path[128];
    snprintf(path, sizeof(path), RF_HAT_RF433_SAVE_DIR "/%s" RF433_HAT_SAVE_EXT, filename);
    FILE *f = fopen(path, "w");
    if (!f) return RF433_HAT_ERR_IO;

    fprintf(f, "Filetype: Flipper SubGhz File\nVersion: 1\n");
    fprintf(f, "Frequency: %lu\n", (unsigned long)sig->freq_hz);
    fprintf(f, "Preset: FuriHalSubGhzPresetOokAsync\n");
    fprintf(f, "Protocol: RAW\nRAW_Data:");

    for (uint32_t i = 0; i < sig->count; i++) {
        int sign = (i % 2 == 0) ? 1 : -1;
        fprintf(f, " %d", sign * (int)sig->pulses_us[i]);
    }
    fprintf(f, "\n");
    fclose(f);
    return RF433_HAT_OK;
}

rf433_hat_err_t rf433_hat_load(rf433_signal_t *sig_out, const char *filename)
{
    if (!sig_out || !filename) return RF433_HAT_ERR_IO;

    char path[128];
    snprintf(path, sizeof(path), RF_HAT_RF433_SAVE_DIR "/%s" RF433_HAT_SAVE_EXT, filename);
    FILE *f = fopen(path, "r");
    if (!f) return RF433_HAT_ERR_IO;

    memset(sig_out, 0, sizeof(*sig_out));
    snprintf(sig_out->name, RF433_HAT_NAME_LEN, "%s", filename);
    sig_out->freq_hz = RF433_HAT_DEFAULT_FREQ_HZ;

    char line[8192];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Frequency:", 10) == 0)
            sig_out->freq_hz = (uint32_t)strtoul(line + 10, NULL, 10);
        else if (strncmp(line, "RAW_Data:", 9) == 0) {
            char *p = line + 9;
            uint32_t idx = 0;
            while (*p && idx < RF433_HAT_MAX_PULSES) {
                while (*p == ' ') p++;
                if (!*p || *p == '\n') break;
                long v = strtol(p, &p, 10);
                sig_out->pulses_us[idx++] = (uint32_t)labs(v);
            }
            sig_out->count = idx;
        }
    }
    fclose(f);
    return (sig_out->count > 0) ? RF433_HAT_OK : RF433_HAT_ERR_IO;
}

// ── Jammer ───────────────────────────────────────────────────────────────────
// Jammer only needs TX GPIO HIGH — no RX ISR, no semaphore, no DRAM pressure.
// Safe to call without rf433_hat_init() (works without HAT hardware too).

void rf433_hat_jam_start(void)
{
    if (s_jamming) return;
    s_setup_tx();                              // TX-only GPIO init, no RX ISR
    rf433_hat_capture_cancel();               // stop any in-progress capture
    gpio_set_level(RF_HAT_RF433_TX_GPIO, 1);  // continuous carrier
    s_jamming = true;
    ESP_LOGI(TAG, "RF433 jam start");
}

void rf433_hat_jam_stop(void)
{
    if (!s_jamming) return;
    gpio_set_level(RF_HAT_RF433_TX_GPIO, 0);
    s_jamming = false;
    ESP_LOGI(TAG, "RF433 jam stop");
}

bool rf433_hat_is_jamming(void) { return s_jamming; }

int rf433_hat_list_saved(char names[][RF433_HAT_NAME_LEN], int max_count)
{
    DIR *dir = opendir(RF_HAT_RF433_SAVE_DIR);
    if (!dir) return 0;
    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(dir)) && count < max_count) {
        char *dot = strrchr(ent->d_name, '.');
        if (dot && strcmp(dot, RF433_HAT_SAVE_EXT) == 0) {
            int len = (int)(dot - ent->d_name);
            if (len >= RF433_HAT_NAME_LEN) len = RF433_HAT_NAME_LEN - 1;
            strncpy(names[count], ent->d_name, len);
            names[count][len] = '\0';
            count++;
        }
    }
    closedir(dir);
    return count;
}
