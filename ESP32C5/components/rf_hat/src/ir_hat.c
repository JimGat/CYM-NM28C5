#include "ir_hat.h"
#include "rf_hat_config.h"
#include "driver/rmt_tx.h"
#include "driver/rmt_rx.h"
#include "driver/gpio.h"
#include "driver/ledc.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>

#define IR_JAM_LEDC_TIMER   LEDC_TIMER_3
#define IR_JAM_LEDC_CHANNEL LEDC_CHANNEL_5

static const char *TAG = "ir_hat";

// RMT resolution: 1 µs per tick
#define IR_RMT_RES_HZ      1000000
// Default 38 kHz carrier for IR protocols (NEC, RC5, Sony, etc.)
#define IR_CARRIER_HZ      38000
#define IR_CARRIER_DUTY    0.33f
// Gap longer than this marks end-of-frame (12 ms)
#define IR_FRAME_GAP_NS    12000000
// Minimum valid pulse (filter glitches shorter than 1.25 µs)
#define IR_MIN_PULSE_NS    1250

// Raw RMT symbol buffer: 2 symbols hold 4 timing entries
static rmt_symbol_word_t s_rx_buf[IR_HAT_MAX_PAIRS * 2];

static rmt_channel_handle_t s_tx_chan  = NULL;
static rmt_channel_handle_t s_rx_chan  = NULL;
static rmt_encoder_handle_t s_tx_enc  = NULL;
static QueueHandle_t        s_rx_queue = NULL;
static bool                 s_init     = false;
static bool                 s_jamming  = false;

// Capture task state
static TaskHandle_t   s_cap_task   = NULL;
static ir_hat_cb_t    s_cap_cb     = NULL;
static void          *s_cap_ctx    = NULL;
static uint32_t       s_cap_tmo_ms = 5000;
static ir_signal_t    s_cap_signal;

// ── RMT RX done callback (ISR context) ───────────────────────────────────────

static bool IRAM_ATTR s_rx_done_cb(rmt_channel_handle_t chan,
                                    const rmt_rx_done_event_data_t *edata,
                                    void *user_data)
{
    BaseType_t woken = pdFALSE;
    QueueHandle_t q = (QueueHandle_t)user_data;
    xQueueSendFromISR(q, edata, &woken);
    return (woken == pdTRUE);
}

// ── Capture background task ───────────────────────────────────────────────────

static void s_capture_task(void *arg)
{
    rmt_receive_config_t rx_cfg = {
        .signal_range_min_ns = IR_MIN_PULSE_NS,
        .signal_range_max_ns = IR_FRAME_GAP_NS,
    };

    esp_err_t ret = rmt_receive(s_rx_chan, s_rx_buf, sizeof(s_rx_buf), &rx_cfg);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "rmt_receive failed: %s", esp_err_to_name(ret));
        if (s_cap_cb) s_cap_cb(IR_HAT_ERR_HW, NULL, s_cap_ctx);
        s_cap_task = NULL;
        vTaskDelete(NULL);
        return;
    }

    rmt_rx_done_event_data_t rx_data;
    ir_hat_err_t result = IR_HAT_ERR_TIMEOUT;

    if (xQueueReceive(s_rx_queue, &rx_data, pdMS_TO_TICKS(s_cap_tmo_ms)) == pdTRUE) {
        uint32_t n = rx_data.num_symbols;
        if (n > IR_HAT_MAX_PAIRS * 2) n = IR_HAT_MAX_PAIRS * 2;

        // Unpack RMT symbol pairs into flat timing array
        uint32_t idx = 0;
        for (uint32_t i = 0; i < n && idx < IR_HAT_MAX_PAIRS * 2 - 1; i++) {
            const rmt_symbol_word_t *sym = &rx_data.received_symbols[i];
            if (sym->duration0) s_cap_signal.times_us[idx++] = sym->duration0;
            if (sym->duration1) s_cap_signal.times_us[idx++] = sym->duration1;
        }
        s_cap_signal.count   = idx;
        s_cap_signal.freq_hz = IR_CARRIER_HZ;
        snprintf(s_cap_signal.name, IR_HAT_NAME_LEN, "signal");
        result = (idx > 0) ? IR_HAT_OK : IR_HAT_ERR_TIMEOUT;
    }

    if (s_cap_cb) s_cap_cb(result, result == IR_HAT_OK ? &s_cap_signal : NULL, s_cap_ctx);
    s_cap_task = NULL;
    vTaskDelete(NULL);
}

// ── Public API ────────────────────────────────────────────────────────────────

ir_hat_err_t ir_hat_init(void)
{
    if (s_init) return IR_HAT_OK;

    s_rx_queue = xQueueCreate(4, sizeof(rmt_rx_done_event_data_t));
    if (!s_rx_queue) return IR_HAT_ERR_HW;

    // TX channel
    rmt_tx_channel_config_t tx_cfg = {
        .clk_src          = RMT_CLK_SRC_DEFAULT,
        .gpio_num         = RF_HAT_IR_TX_GPIO,
        .mem_block_symbols= 64,
        .resolution_hz    = IR_RMT_RES_HZ,
        .trans_queue_depth= 4,
        .flags.invert_out = false,
        .flags.with_dma   = false,
    };
    if (rmt_new_tx_channel(&tx_cfg, &s_tx_chan) != ESP_OK) goto fail;

    rmt_carrier_config_t carrier = {
        .frequency_hz = IR_CARRIER_HZ,
        .duty_cycle   = IR_CARRIER_DUTY,
    };
    rmt_apply_carrier(s_tx_chan, &carrier);

    rmt_copy_encoder_config_t enc_cfg = {};
    if (rmt_new_copy_encoder(&enc_cfg, &s_tx_enc) != ESP_OK) goto fail;
    rmt_enable(s_tx_chan);

    // RX channel
    rmt_rx_channel_config_t rx_cfg = {
        .clk_src          = RMT_CLK_SRC_DEFAULT,
        .gpio_num         = RF_HAT_IR_RX_GPIO,
        .mem_block_symbols= 128,
        .resolution_hz    = IR_RMT_RES_HZ,
        .flags.invert_in  = false,
        .flags.with_dma   = false,
    };
    if (rmt_new_rx_channel(&rx_cfg, &s_rx_chan) != ESP_OK) goto fail;

    rmt_rx_event_callbacks_t rx_cbs = { .on_recv_done = s_rx_done_cb };
    rmt_rx_register_event_callbacks(s_rx_chan, &rx_cbs, s_rx_queue);
    rmt_enable(s_rx_chan);

    s_init = true;
    ESP_LOGI(TAG, "IR init OK (TX=GPIO%d, RX=GPIO%d)", RF_HAT_IR_TX_GPIO, RF_HAT_IR_RX_GPIO);
    return IR_HAT_OK;

fail:
    ESP_LOGE(TAG, "IR init failed");
    ir_hat_deinit();
    return IR_HAT_ERR_HW;
}

void ir_hat_deinit(void)
{
    ir_hat_capture_cancel();
    if (s_tx_chan) { rmt_disable(s_tx_chan); rmt_del_channel(s_tx_chan); s_tx_chan = NULL; }
    if (s_rx_chan) { rmt_disable(s_rx_chan); rmt_del_channel(s_rx_chan); s_rx_chan = NULL; }
    if (s_tx_enc)  { rmt_del_encoder(s_tx_enc);  s_tx_enc  = NULL; }
    if (s_rx_queue){ vQueueDelete(s_rx_queue);    s_rx_queue = NULL; }
    s_init = false;
}

bool ir_hat_is_init(void) { return s_init; }

ir_hat_err_t ir_hat_capture_start(ir_hat_cb_t cb, void *ctx, uint32_t timeout_ms)
{
    if (!s_init)     return IR_HAT_ERR_NOT_INIT;
    if (s_cap_task)  return IR_HAT_ERR_BUSY;

    s_cap_cb     = cb;
    s_cap_ctx    = ctx;
    s_cap_tmo_ms = timeout_ms ? timeout_ms : 5000;

    UBaseType_t prio = tskIDLE_PRIORITY + 2;
    BaseType_t ok = xTaskCreate(s_capture_task, "ir_cap", 4096, NULL, prio, &s_cap_task);
    return (ok == pdPASS) ? IR_HAT_OK : IR_HAT_ERR_HW;
}

void ir_hat_capture_cancel(void)
{
    if (s_cap_task) {
        vTaskDelete(s_cap_task);
        s_cap_task = NULL;
    }
    xQueueReset(s_rx_queue);
}

ir_hat_err_t ir_hat_replay(const ir_signal_t *sig)
{
    if (!s_init)  return IR_HAT_ERR_NOT_INIT;
    if (!sig || sig->count == 0) return IR_HAT_ERR_HW;

    // Build RMT symbol array from flat timing list
    uint32_t n_pairs = (sig->count + 1) / 2;
    if (n_pairs > IR_HAT_MAX_PAIRS) n_pairs = IR_HAT_MAX_PAIRS;

    rmt_symbol_word_t *syms = malloc(n_pairs * sizeof(rmt_symbol_word_t));
    if (!syms) return IR_HAT_ERR_HW;

    for (uint32_t i = 0; i < n_pairs; i++) {
        uint32_t hi = sig->times_us[i * 2];
        uint32_t lo = (i * 2 + 1 < sig->count) ? sig->times_us[i * 2 + 1] : 0;
        syms[i].duration0 = hi;
        syms[i].level0    = 1;
        syms[i].duration1 = lo;
        syms[i].level1    = 0;
    }

    rmt_transmit_config_t tx_cfg = { .loop_count = 0 };
    esp_err_t ret = rmt_transmit(s_tx_chan, s_tx_enc, syms,
                                  n_pairs * sizeof(rmt_symbol_word_t), &tx_cfg);
    if (ret == ESP_OK) rmt_tx_wait_all_done(s_tx_chan, pdMS_TO_TICKS(2000));
    free(syms);
    return (ret == ESP_OK) ? IR_HAT_OK : IR_HAT_ERR_HW;
}

// ── Storage ───────────────────────────────────────────────────────────────────

ir_hat_err_t ir_hat_save(const ir_signal_t *sig, const char *filename)
{
    if (!sig || !filename) return IR_HAT_ERR_IO;

    struct stat st;
    if (stat(RF_HAT_IR_SAVE_DIR, &st) != 0) mkdir(RF_HAT_IR_SAVE_DIR, 0755);

    char path[128];
    snprintf(path, sizeof(path), RF_HAT_IR_SAVE_DIR "/%s" IR_HAT_SAVE_EXT, filename);
    FILE *f = fopen(path, "w");
    if (!f) return IR_HAT_ERR_IO;

    fprintf(f, "# CYM IR Signal\n");
    fprintf(f, "name: %s\n", sig->name);
    fprintf(f, "freq: %lu\n", (unsigned long)sig->freq_hz);
    fprintf(f, "count: %lu\n", (unsigned long)sig->count);
    fprintf(f, "data:");
    for (uint32_t i = 0; i < sig->count; i++) fprintf(f, " %lu", (unsigned long)sig->times_us[i]);
    fprintf(f, "\n");
    fclose(f);
    return IR_HAT_OK;
}

ir_hat_err_t ir_hat_load(ir_signal_t *sig_out, const char *filename)
{
    if (!sig_out || !filename) return IR_HAT_ERR_IO;

    char path[128];
    snprintf(path, sizeof(path), RF_HAT_IR_SAVE_DIR "/%s" IR_HAT_SAVE_EXT, filename);
    FILE *f = fopen(path, "r");
    if (!f) return IR_HAT_ERR_IO;

    memset(sig_out, 0, sizeof(*sig_out));
    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "name: ", 6) == 0)
            sscanf(line + 6, "%31s", sig_out->name);
        else if (strncmp(line, "freq: ", 6) == 0)
            sscanf(line + 6, "%lu", (unsigned long *)&sig_out->freq_hz);
        else if (strncmp(line, "count: ", 7) == 0)
            sscanf(line + 7, "%lu", (unsigned long *)&sig_out->count);
        else if (strncmp(line, "data:", 5) == 0) {
            char *p = line + 5;
            for (uint32_t i = 0; i < sig_out->count && i < IR_HAT_MAX_PAIRS * 2; i++) {
                while (*p == ' ') p++;
                sig_out->times_us[i] = (uint32_t)strtoul(p, &p, 10);
            }
        }
    }
    fclose(f);
    return IR_HAT_OK;
}

int ir_hat_list_saved(char names[][IR_HAT_NAME_LEN], int max_count)
{
    DIR *dir = opendir(RF_HAT_IR_SAVE_DIR);
    if (!dir) return 0;
    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(dir)) && count < max_count) {
        char *dot = strrchr(ent->d_name, '.');
        if (dot && strcmp(dot, IR_HAT_SAVE_EXT) == 0) {
            int len = (int)(dot - ent->d_name);
            if (len >= IR_HAT_NAME_LEN) len = IR_HAT_NAME_LEN - 1;
            strncpy(names[count], ent->d_name, len);
            names[count][len] = '\0';
            count++;
        }
    }
    closedir(dir);
    return count;
}

// ── TV-B-Gone ─────────────────────────────────────────────────────────────────
// A minimal set of common TV power-off IR codes.
// Each entry: {freq_hz, count, times_us[]}.
// Sourced from open IR databases (Flipper Zero / IRDB / Ken Shirriff).
// This is a starter set — add more .ir files to /sdcard/lab/ir/ for custom codes.

typedef struct { uint32_t freq; uint32_t count; uint32_t t[72]; } tvbg_code_t;

static const tvbg_code_t TVBG_CODES[] = {
    // Samsung generic power (NEC protocol)
    { 38000, 68, { 4500,4500, 560,1680, 560,1680, 560,560, 560,1680, 560,1680, 560,1680, 560,560,
                   560,560, 560,560, 560,1680, 560,560, 560,560, 560,560, 560,1680, 560,1680,
                   560,1680, 560,560, 560,560, 560,1680, 560,560, 560,560, 560,1680, 560,560,
                   560,1680, 560,1680, 560,560, 560,1680, 560,1680, 560,1680, 560,560, 560,560,
                   560,1680, 560,560, 560,40000 } },
    // LG generic power (NEC)
    { 38000, 68, { 9000,4500, 560,560, 560,1680, 560,1680, 560,560, 560,1680, 560,560, 560,1680,
                   560,560, 560,1680, 560,560, 560,560, 560,1680, 560,560, 560,1680, 560,560,
                   560,1680, 560,560, 560,1680, 560,560, 560,1680, 560,1680, 560,560, 560,1680,
                   560,1680, 560,560, 560,1680, 560,560, 560,1680, 560,1680, 560,560, 560,1680,
                   560,560, 560,40000 } },
    // Sony Bravia power (SIRC 20-bit)
    { 40000, 40, { 2400,600, 600,600, 1200,600, 1200,600, 1200,600, 600,600, 600,600, 600,600,
                   600,600, 600,600, 1200,600, 600,600, 600,600, 600,600, 1200,600, 600,600,
                   600,600, 600,600, 600,600, 600,45000 } },
    // Philips power (RC-5 protocol)
    { 36000, 26, { 889,889, 889,889, 889,889, 889,889, 889,1778, 889,889, 889,1778,
                   1778,889, 889,889, 889,889, 889,889, 889,1778, 889,89000 } },
};
#define TVBG_COUNT  (sizeof(TVBG_CODES)/sizeof(TVBG_CODES[0]))

void ir_hat_tvbgone(ir_hat_progress_cb_t progress_cb, void *ctx)
{
    ir_signal_t sig;
    for (int i = 0; i < (int)TVBG_COUNT; i++) {
        const tvbg_code_t *c = &TVBG_CODES[i];
        memset(&sig, 0, sizeof(sig));
        snprintf(sig.name, IR_HAT_NAME_LEN, "tvbg_%d", i);
        sig.freq_hz = c->freq;
        sig.count   = c->count;
        memcpy(sig.times_us, c->t, c->count * sizeof(uint32_t));
        ir_hat_replay(&sig);
        if (progress_cb) progress_cb(i, (int)TVBG_COUNT, ctx);
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

// ── Jammer ───────────────────────────────────────────────────────────────────

ir_hat_err_t ir_hat_jam_start(uint32_t freq_hz)
{
    if (s_jamming) return IR_HAT_OK;
    if (!freq_hz) freq_hz = 38000;

    // Release RMT TX so LEDC can drive the same GPIO
    ir_hat_capture_cancel();
    if (s_tx_chan) { rmt_disable(s_tx_chan); rmt_del_channel(s_tx_chan); s_tx_chan = NULL; }
    if (s_tx_enc)  { rmt_del_encoder(s_tx_enc); s_tx_enc = NULL; }
    s_init = false;  // force full re-init on jam_stop

    ledc_timer_config_t t = {
        .speed_mode      = LEDC_LOW_SPEED_MODE,
        .duty_resolution = LEDC_TIMER_8_BIT,
        .timer_num       = IR_JAM_LEDC_TIMER,
        .freq_hz         = freq_hz,
        .clk_cfg         = LEDC_AUTO_CLK,
    };
    if (ledc_timer_config(&t) != ESP_OK) return IR_HAT_ERR_HW;

    ledc_channel_config_t ch = {
        .gpio_num   = RF_HAT_IR_TX_GPIO,
        .speed_mode = LEDC_LOW_SPEED_MODE,
        .channel    = IR_JAM_LEDC_CHANNEL,
        .timer_sel  = IR_JAM_LEDC_TIMER,
        .duty       = 85,   // ~33% of 255
        .hpoint     = 0,
        .intr_type  = LEDC_INTR_DISABLE,
    };
    if (ledc_channel_config(&ch) != ESP_OK) return IR_HAT_ERR_HW;

    s_jamming = true;
    ESP_LOGI(TAG, "IR jam start @ %lu Hz", (unsigned long)freq_hz);
    return IR_HAT_OK;
}

void ir_hat_jam_stop(void)
{
    if (!s_jamming) return;
    ledc_stop(LEDC_LOW_SPEED_MODE, IR_JAM_LEDC_CHANNEL, 0);
    gpio_set_level(RF_HAT_IR_TX_GPIO, 0);
    s_jamming = false;
    ir_hat_init();  // restore RMT TX + RX
    ESP_LOGI(TAG, "IR jam stop");
}

bool ir_hat_is_jamming(void) { return s_jamming; }
