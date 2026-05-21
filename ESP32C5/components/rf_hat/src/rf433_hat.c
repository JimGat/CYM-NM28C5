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

// ISR double-buffer in DRAM — capped at 256, enough for all standard OOK frames.
#define RF433_ISR_BUF_MAX 256
static uint32_t s_isr_buf[RF433_ISR_BUF_MAX];
static volatile bool s_frame_ready = false;

static TaskHandle_t      s_cap_task   = NULL;
static rf433_hat_cb_t    s_cap_cb     = NULL;
static void             *s_cap_ctx    = NULL;
static uint32_t          s_cap_tmo_ms = 5000;
static SemaphoreHandle_t s_frame_sem  = NULL;

// Signal capture buffer from PSRAM (~2 KB out of internal DRAM).
static rf433_signal_t   *s_cap_buf    = NULL;

static bool s_init    = false;
static bool s_tx_init = false;

// Large I/O buffer — PSRAM-allocated on first use (8 KB out of scarce internal DRAM).
#define S_IO_LINE_LEN 8192
static char *s_io_line = NULL;
static inline bool s_ensure_io_line(void) {
    if (s_io_line) return true;
    s_io_line = heap_caps_malloc(S_IO_LINE_LEN, MALLOC_CAP_SPIRAM);
    return s_io_line != NULL;
}

// ── Path helpers ──────────────────────────────────────────────────────────────

static void s_make_remote_dir(const char *remote_name, char *buf, size_t sz)
{
    snprintf(buf, sz, RF_HAT_RF433_SAVE_DIR "/%s", remote_name);
}

static void s_make_signal_path(const char *remote_name, const char *signal_name,
                                char *buf, size_t sz)
{
    snprintf(buf, sz, RF_HAT_RF433_SAVE_DIR "/%s/%s" RF433_HAT_SAVE_EXT,
             remote_name, signal_name);
}

static void s_ensure_root(void)
{
    struct stat st;
    if (stat(RF_HAT_RF433_SAVE_DIR, &st) != 0) mkdir(RF_HAT_RF433_SAVE_DIR, 0755);
}

// ── .sub file I/O ────────────────────────────────────────────────────────────

static void s_write_sub(FILE *f, const rf433_signal_t *sig)
{
    fprintf(f, "Filetype: Flipper SubGhz File\nVersion: 1\n");
    fprintf(f, "Frequency: %lu\n", (unsigned long)sig->freq_hz);
    fprintf(f, "Preset: FuriHalSubGhzPresetOokAsync\n");
    fprintf(f, "Protocol: RAW\nRAW_Data:");
    for (uint32_t i = 0; i < sig->count; i++) {
        int sign = (i % 2 == 0) ? 1 : -1;
        fprintf(f, " %d", sign * (int)sig->pulses_us[i]);
    }
    fprintf(f, "\n");
}

static rf433_hat_err_t s_read_sub(FILE *f, rf433_signal_t *sig_out)
{
    sig_out->freq_hz = RF433_HAT_DEFAULT_FREQ_HZ;
    sig_out->count   = 0;

    while (fgets(s_io_line, S_IO_LINE_LEN, f)) {
        if (strncmp(s_io_line, "Frequency:", 10) == 0)
            sig_out->freq_hz = (uint32_t)strtoul(s_io_line + 10, NULL, 10);
        else if (strncmp(s_io_line, "RAW_Data:", 9) == 0) {
            char *p = s_io_line + 9;
            uint32_t idx = 0;
            while (*p && idx < RF433_HAT_MAX_PULSES) {
                while (*p == ' ') p++;
                if (!*p || *p == '\n' || *p == '\r') break;
                long v = strtol(p, &p, 10);
                if (v == 0) break;
                sig_out->pulses_us[idx++] = (uint32_t)labs(v);
            }
            sig_out->count = idx;
        }
    }
    return (sig_out->count > 0) ? RF433_HAT_OK : RF433_HAT_ERR_IO;
}

// ── TX-only GPIO (called by both full init and jammer) ────────────────────────

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

    int64_t now    = esp_timer_get_time();
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

    if (s_pulse_count < RF433_ISR_BUF_MAX)
        s_isr_buf[s_pulse_count++] = (uint32_t)gap_us;
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

// ── Public API — Lifecycle ────────────────────────────────────────────────────

rf433_hat_err_t rf433_hat_init(void)
{
    if (s_init) return RF433_HAT_OK;

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
    // ESP_ERR_INVALID_STATE means the service is already installed (e.g. after a
    // deinit that didn't call gpio_uninstall_isr_service). That's fine — reuse it.
    esp_err_t isr_err = gpio_install_isr_service(ESP_INTR_FLAG_IRAM);
    if (isr_err != ESP_OK && isr_err != ESP_ERR_INVALID_STATE) goto fail;
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
    if (s_init && RF_HAT_RF433_RX_GPIO >= 0) gpio_isr_handler_remove(RF_HAT_RF433_RX_GPIO);
    if (s_frame_sem) { vSemaphoreDelete(s_frame_sem); s_frame_sem = NULL; }
    if (s_cap_buf)   { free(s_cap_buf); s_cap_buf = NULL; }
    s_init    = false;
    s_tx_init = false;
}

bool rf433_hat_is_init(void) { return s_init; }

// ── Public API — Capture ──────────────────────────────────────────────────────

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

// ── Public API — Replay ───────────────────────────────────────────────────────

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

// ── Public API — Storage (Flipper-compatible) ─────────────────────────────────

rf433_hat_err_t rf433_hat_create_remote(const char *remote_name)
{
    if (!remote_name) return RF433_HAT_ERR_IO;
    s_ensure_root();

    char dir[128];
    s_make_remote_dir(remote_name, dir, sizeof(dir));

    struct stat st;
    if (stat(dir, &st) == 0) return RF433_HAT_ERR_IO;  // already exists
    if (mkdir(dir, 0755) != 0) return RF433_HAT_ERR_IO;
    ESP_LOGI(TAG, "Created remote: %s", dir);
    return RF433_HAT_OK;
}

rf433_hat_err_t rf433_hat_append_signal(const char *remote_name, const rf433_signal_t *sig)
{
    if (!remote_name || !sig) return RF433_HAT_ERR_IO;
    s_ensure_root();

    char dir[128];
    s_make_remote_dir(remote_name, dir, sizeof(dir));
    struct stat st;
    if (stat(dir, &st) != 0) mkdir(dir, 0755);

    char path[160];
    s_make_signal_path(remote_name, sig->name, path, sizeof(path));

    FILE *f = fopen(path, "w");
    if (!f) return RF433_HAT_ERR_IO;
    s_write_sub(f, sig);
    fclose(f);
    ESP_LOGI(TAG, "Saved '%s' to %s", sig->name, remote_name);
    return RF433_HAT_OK;
}

rf433_hat_err_t rf433_hat_load_signal_by_index(const char *remote_name, int index,
                                                rf433_signal_t *sig_out)
{
    if (!remote_name || !sig_out || index < 0) return RF433_HAT_ERR_IO;
    if (!s_ensure_io_line()) return RF433_HAT_ERR_IO;

    char dir[128];
    s_make_remote_dir(remote_name, dir, sizeof(dir));
    DIR *d = opendir(dir);
    if (!d) return RF433_HAT_ERR_IO;

    int found_idx = -1;
    bool found    = false;
    struct dirent *ent;

    while ((ent = readdir(d))) {
        if (ent->d_type == DT_DIR) continue;
        char *dot = strrchr(ent->d_name, '.');
        if (!dot || strcmp(dot, RF433_HAT_SAVE_EXT) != 0) continue;
        found_idx++;
        if (found_idx == index) {
            int namelen = (int)(dot - ent->d_name);
            memset(sig_out, 0, sizeof(*sig_out));
            strncpy(sig_out->name, ent->d_name,
                    namelen < RF433_HAT_NAME_LEN ? namelen : RF433_HAT_NAME_LEN - 1);

            char path[160];
            s_make_signal_path(remote_name, sig_out->name, path, sizeof(path));
            FILE *f = fopen(path, "r");
            if (f) {
                s_read_sub(f, sig_out);
                fclose(f);
                found = true;
            }
            break;
        }
    }
    closedir(d);
    return found ? RF433_HAT_OK : RF433_HAT_ERR_NOT_FOUND;
}

rf433_hat_err_t rf433_hat_load_signal(const char *remote_name, const char *signal_name,
                                       rf433_signal_t *sig_out)
{
    if (!remote_name || !signal_name || !sig_out) return RF433_HAT_ERR_IO;
    if (!s_ensure_io_line()) return RF433_HAT_ERR_IO;

    char path[160];
    s_make_signal_path(remote_name, signal_name, path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (!f) return RF433_HAT_ERR_NOT_FOUND;

    memset(sig_out, 0, sizeof(*sig_out));
    strncpy(sig_out->name, signal_name, RF433_HAT_NAME_LEN - 1);
    rf433_hat_err_t r = s_read_sub(f, sig_out);
    fclose(f);
    return r;
}

int rf433_hat_list_signals(const char *remote_name,
                            char names[][RF433_HAT_NAME_LEN], int max_count)
{
    if (!remote_name || !names || max_count <= 0) return 0;

    char dir[128];
    s_make_remote_dir(remote_name, dir, sizeof(dir));
    DIR *d = opendir(dir);
    if (!d) return 0;

    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) && count < max_count) {
        if (ent->d_type == DT_DIR) continue;
        char *dot = strrchr(ent->d_name, '.');
        if (!dot || strcmp(dot, RF433_HAT_SAVE_EXT) != 0) continue;
        int len = (int)(dot - ent->d_name);
        if (len <= 0 || len >= RF433_HAT_NAME_LEN) continue;
        strncpy(names[count], ent->d_name, len);
        names[count][len] = '\0';
        count++;
    }
    closedir(d);
    return count;
}

int rf433_hat_list_remotes(char names[][RF433_HAT_REMOTE_NAME_LEN], int max_count)
{
    if (!names || max_count <= 0) return 0;

    DIR *d = opendir(RF_HAT_RF433_SAVE_DIR);
    if (!d) return 0;

    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) && count < max_count) {
        if (ent->d_type != DT_DIR) continue;
        if (ent->d_name[0] == '.') continue;  // skip . and ..
        strncpy(names[count], ent->d_name, RF433_HAT_REMOTE_NAME_LEN - 1);
        names[count][RF433_HAT_REMOTE_NAME_LEN - 1] = '\0';
        count++;
    }
    closedir(d);
    return count;
}

rf433_hat_err_t rf433_hat_delete_signal(const char *remote_name, int index)
{
    if (!remote_name || index < 0) return RF433_HAT_ERR_IO;

    // Resolve the filename at this index
    char dir[128];
    s_make_remote_dir(remote_name, dir, sizeof(dir));
    DIR *d = opendir(dir);
    if (!d) return RF433_HAT_ERR_IO;

    int found_idx = -1;
    char target[RF433_HAT_NAME_LEN] = {0};
    struct dirent *ent;

    while ((ent = readdir(d))) {
        if (ent->d_type == DT_DIR) continue;
        char *dot = strrchr(ent->d_name, '.');
        if (!dot || strcmp(dot, RF433_HAT_SAVE_EXT) != 0) continue;
        found_idx++;
        if (found_idx == index) {
            int len = (int)(dot - ent->d_name);
            strncpy(target, ent->d_name, len < RF433_HAT_NAME_LEN ? len : RF433_HAT_NAME_LEN - 1);
            break;
        }
    }
    closedir(d);

    if (target[0] == '\0') return RF433_HAT_ERR_NOT_FOUND;

    char path[160];
    s_make_signal_path(remote_name, target, path, sizeof(path));
    if (remove(path) != 0) return RF433_HAT_ERR_IO;
    ESP_LOGI(TAG, "Deleted signal %d (%s) from %s", index, target, remote_name);
    return RF433_HAT_OK;
}

// ── Public API — Jammer ───────────────────────────────────────────────────────

void rf433_hat_jam_start(void)
{
    if (s_jamming) return;
    s_setup_tx();
    rf433_hat_capture_cancel();
    gpio_set_level(RF_HAT_RF433_TX_GPIO, 1);
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
