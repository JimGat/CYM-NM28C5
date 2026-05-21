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
#include "esp_attr.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>

#define IR_JAM_LEDC_TIMER   LEDC_TIMER_3
#define IR_JAM_LEDC_CHANNEL LEDC_CHANNEL_5

static const char *TAG = "ir_hat";

// RMT resolution: 1 µs per tick
#define IR_RMT_RES_HZ      1000000
// Default 38 kHz carrier (NEC, Samsung32, RC5, etc.)
#define IR_CARRIER_HZ      38000
#define IR_CARRIER_DUTY    0.33f
// End-of-frame silence threshold (12 ms)
#define IR_FRAME_GAP_NS    12000000
// Minimum valid pulse filter (1.25 µs)
#define IR_MIN_PULSE_NS    1250

// Raw RMT receive buffer
static rmt_symbol_word_t s_rx_buf[IR_HAT_MAX_TIMINGS / 2];

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

// Large line buffer for file I/O — allocated from PSRAM on first use to keep
// 8 KB out of scarce internal DRAM (BLE extended scan needs ~16 KB controller
// buffers that come from the same internal pool).
#define S_IO_LINE_LEN 8192
static char *s_io_line = NULL;
static inline bool s_ensure_io_line(void) {
    if (s_io_line) return true;
    s_io_line = heap_caps_malloc(S_IO_LINE_LEN, MALLOC_CAP_SPIRAM);
    return s_io_line != NULL;
}

// ── Internal helpers ──────────────────────────────────────────────────────────

static void s_make_path(const char *remote_name, char *buf, size_t buf_size)
{
    snprintf(buf, buf_size, RF_HAT_IR_SAVE_DIR "/%s" IR_HAT_SAVE_EXT, remote_name);
}

static void s_ensure_dir(void)
{
    struct stat st;
    if (stat(RF_HAT_IR_SAVE_DIR, &st) != 0) mkdir(RF_HAT_IR_SAVE_DIR, 0755);
}

static void s_strip_newline(char *s)
{
    int len = (int)strlen(s);
    while (len > 0 && (s[len-1] == '\n' || s[len-1] == '\r')) s[--len] = '\0';
}

// Write the Flipper-compatible file header to an open file.
static void s_write_header(FILE *f)
{
    fprintf(f, "Filetype: IR signals file\nVersion: 1\n");
}

// Write one signal block (separator + key-value pairs) to an open file.
static void s_write_signal_block(FILE *f, const ir_signal_t *sig)
{
    fprintf(f, "#\nname: %s\ntype: raw\nfrequency: %lu\nduty_cycle: %.2f\ndata:",
            sig->name,
            (unsigned long)sig->freq_hz,
            sig->duty_cycle > 0.0f ? sig->duty_cycle : IR_CARRIER_DUTY);
    for (uint32_t i = 0; i < sig->count; i++) {
        fprintf(f, " %lu", (unsigned long)sig->times_us[i]);
    }
    fprintf(f, "\n");
}

// Parse one signal from the file starting at the current position.
// Stops when it hits a new "name:" line (which it does NOT consume) or EOF.
// Expects to be called with the file positioned right after the signal's
// own "name:" line has been read by the caller (name already in sig_out->name).
static void s_read_signal_body(FILE *f, ir_signal_t *sig_out)
{
    sig_out->freq_hz    = IR_CARRIER_HZ;
    sig_out->duty_cycle = IR_CARRIER_DUTY;
    sig_out->count      = 0;

    long pos;
    while (true) {
        pos = ftell(f);
        if (!fgets(s_io_line, S_IO_LINE_LEN, f)) break;
        s_strip_newline(s_io_line);

        if (strncmp(s_io_line, "name: ", 6) == 0) {
            // Next signal starts — rewind so caller can read it
            fseek(f, pos, SEEK_SET);
            break;
        }
        if (s_io_line[0] == '#') continue;  // separator line, skip
        if (strncmp(s_io_line, "frequency: ", 11) == 0)
            sig_out->freq_hz = (uint32_t)strtoul(s_io_line + 11, NULL, 10);
        else if (strncmp(s_io_line, "duty_cycle: ", 12) == 0)
            sig_out->duty_cycle = strtof(s_io_line + 12, NULL);
        else if (strncmp(s_io_line, "data:", 5) == 0) {
            char *p = s_io_line + 5;
            uint32_t idx = 0;
            while (*p && idx < IR_HAT_MAX_TIMINGS) {
                while (*p == ' ') p++;
                if (!*p) break;
                sig_out->times_us[idx++] = (uint32_t)strtoul(p, &p, 10);
            }
            sig_out->count = idx;
        }
        // "type:" and "Filetype:"/"Version:" lines are silently skipped
    }
}

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
        if (n > IR_HAT_MAX_TIMINGS / 2) n = IR_HAT_MAX_TIMINGS / 2;

        uint32_t idx = 0;
        for (uint32_t i = 0; i < n && idx < IR_HAT_MAX_TIMINGS - 1; i++) {
            const rmt_symbol_word_t *sym = &rx_data.received_symbols[i];
            if (sym->duration0) s_cap_signal.times_us[idx++] = sym->duration0;
            if (sym->duration1) s_cap_signal.times_us[idx++] = sym->duration1;
        }
        s_cap_signal.count      = idx;
        s_cap_signal.freq_hz    = IR_CARRIER_HZ;
        s_cap_signal.duty_cycle = IR_CARRIER_DUTY;
        snprintf(s_cap_signal.name, IR_HAT_NAME_LEN, "signal");
        result = (idx > 0) ? IR_HAT_OK : IR_HAT_ERR_TIMEOUT;
    }

    if (s_cap_cb) s_cap_cb(result, result == IR_HAT_OK ? &s_cap_signal : NULL, s_cap_ctx);
    s_cap_task = NULL;
    vTaskDelete(NULL);
}

// ── Public API — Lifecycle ────────────────────────────────────────────────────

ir_hat_err_t ir_hat_init(void)
{
    if (s_init) return IR_HAT_OK;

    s_rx_queue = xQueueCreate(4, sizeof(rmt_rx_done_event_data_t));
    if (!s_rx_queue) return IR_HAT_ERR_HW;

    // ESP32-C5: mem_block_symbols must be <= 48 (SOC_RMT_MEM_WORDS_PER_CHANNEL).
    // 64 → mem_block_num=2 → borrows the adjacent RX slot in the occupy_mask,
    // leaving zero free RX channels.  48 → mem_block_num=1, no overflow.
    rmt_tx_channel_config_t tx_cfg = {
        .clk_src           = RMT_CLK_SRC_DEFAULT,
        .gpio_num          = RF_HAT_IR_TX_GPIO,
        .mem_block_symbols = 48,
        .resolution_hz     = IR_RMT_RES_HZ,
        .trans_queue_depth = 4,
        .flags.invert_out  = false,
        .flags.with_dma    = false,
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

    // 128 → mem_block_num=3, needs 3 consecutive RX slots (only 2 exist) → always fails.
    // 48 → mem_block_num=1, ping_pong_symbols=24; adequate for all common IR protocols.
    rmt_rx_channel_config_t rx_cfg = {
        .clk_src           = RMT_CLK_SRC_DEFAULT,
        .gpio_num          = RF_HAT_IR_RX_GPIO,
        .mem_block_symbols = 48,
        .resolution_hz     = IR_RMT_RES_HZ,
        .flags.invert_in   = false,
        .flags.with_dma    = false,
    };
    if (rmt_new_rx_channel(&rx_cfg, &s_rx_chan) != ESP_OK) goto fail;

    rmt_rx_event_callbacks_t rx_cbs = { .on_recv_done = s_rx_done_cb };
    rmt_rx_register_event_callbacks(s_rx_chan, &rx_cbs, s_rx_queue);
    rmt_enable(s_rx_chan);

    s_init = true;
    ESP_LOGI(TAG, "IR init OK  TX=GPIO%d  RX=GPIO%d", RF_HAT_IR_TX_GPIO, RF_HAT_IR_RX_GPIO);
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

// ── Public API — Capture ──────────────────────────────────────────────────────

ir_hat_err_t ir_hat_capture_start(ir_hat_cb_t cb, void *ctx, uint32_t timeout_ms)
{
    if (!s_init)    return IR_HAT_ERR_NOT_INIT;
    if (s_cap_task) return IR_HAT_ERR_BUSY;

    s_cap_cb     = cb;
    s_cap_ctx    = ctx;
    s_cap_tmo_ms = timeout_ms ? timeout_ms : 5000;

    BaseType_t ok = xTaskCreate(s_capture_task, "ir_cap", 4096, NULL,
                                tskIDLE_PRIORITY + 2, &s_cap_task);
    return (ok == pdPASS) ? IR_HAT_OK : IR_HAT_ERR_HW;
}

void ir_hat_capture_cancel(void)
{
    if (s_cap_task) { vTaskDelete(s_cap_task); s_cap_task = NULL; }
    if (s_rx_queue) xQueueReset(s_rx_queue);
    // vTaskDelete leaves the RMT RX channel in FSM_RUN; cycle it back to FSM_ENABLE
    // so the next rmt_receive() call does not fail with "channel not in enable state".
    if (s_rx_chan) { rmt_disable(s_rx_chan); rmt_enable(s_rx_chan); }
}

// ── Public API — Replay ───────────────────────────────────────────────────────

ir_hat_err_t ir_hat_replay(const ir_signal_t *sig)
{
    if (!s_init) return IR_HAT_ERR_NOT_INIT;
    if (!sig || sig->count == 0) return IR_HAT_ERR_HW;

    uint32_t n_pairs = (sig->count + 1) / 2;
    if (n_pairs > IR_HAT_MAX_TIMINGS / 2) n_pairs = IR_HAT_MAX_TIMINGS / 2;

    rmt_symbol_word_t *syms = malloc(n_pairs * sizeof(rmt_symbol_word_t));
    if (!syms) return IR_HAT_ERR_HW;

    // Apply per-signal carrier frequency if it differs from the init default
    if (sig->freq_hz && sig->freq_hz != IR_CARRIER_HZ) {
        rmt_carrier_config_t carrier = {
            .frequency_hz = sig->freq_hz,
            .duty_cycle   = sig->duty_cycle > 0.0f ? sig->duty_cycle : IR_CARRIER_DUTY,
        };
        rmt_apply_carrier(s_tx_chan, &carrier);
    }

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

    // Restore default carrier
    if (sig->freq_hz && sig->freq_hz != IR_CARRIER_HZ) {
        rmt_carrier_config_t carrier = { .frequency_hz = IR_CARRIER_HZ,
                                         .duty_cycle   = IR_CARRIER_DUTY };
        rmt_apply_carrier(s_tx_chan, &carrier);
    }

    return (ret == ESP_OK) ? IR_HAT_OK : IR_HAT_ERR_HW;
}

// ── Public API — Storage (Flipper-compatible) ─────────────────────────────────

ir_hat_err_t ir_hat_create_remote(const char *remote_name)
{
    s_ensure_dir();
    char path[160];
    s_make_path(remote_name, path, sizeof(path));

    struct stat st;
    if (stat(path, &st) == 0) return IR_HAT_ERR_IO;  // already exists

    FILE *f = fopen(path, "w");
    if (!f) return IR_HAT_ERR_IO;
    s_write_header(f);
    fclose(f);
    ESP_LOGI(TAG, "Created remote: %s", path);
    return IR_HAT_OK;
}

ir_hat_err_t ir_hat_append_signal(const char *remote_name, const ir_signal_t *sig)
{
    if (!remote_name || !sig) return IR_HAT_ERR_IO;
    s_ensure_dir();

    char path[160];
    s_make_path(remote_name, path, sizeof(path));

    struct stat st;
    bool exists = (stat(path, &st) == 0);

    FILE *f = fopen(path, exists ? "a" : "w");
    if (!f) return IR_HAT_ERR_IO;

    if (!exists) s_write_header(f);
    s_write_signal_block(f, sig);
    fclose(f);
    ESP_LOGI(TAG, "Appended '%s' to %s", sig->name, remote_name);
    return IR_HAT_OK;
}

ir_hat_err_t ir_hat_load_signal_by_index(const char *remote_name, int index,
                                          ir_signal_t *sig_out)
{
    if (!remote_name || !sig_out || index < 0) return IR_HAT_ERR_IO;
    if (!s_ensure_io_line()) return IR_HAT_ERR_IO;

    char path[160];
    s_make_path(remote_name, path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (!f) return IR_HAT_ERR_IO;

    memset(sig_out, 0, sizeof(*sig_out));
    int sig_idx = -1;
    bool found  = false;

    while (fgets(s_io_line, S_IO_LINE_LEN, f)) {
        s_strip_newline(s_io_line);
        if (strncmp(s_io_line, "name: ", 6) == 0) {
            sig_idx++;
            if (sig_idx == index) {
                strncpy(sig_out->name, s_io_line + 6, IR_HAT_NAME_LEN - 1);
                s_read_signal_body(f, sig_out);
                found = true;
                break;
            }
        }
    }
    fclose(f);
    return found ? IR_HAT_OK : IR_HAT_ERR_NOT_FOUND;
}

ir_hat_err_t ir_hat_load_signal(const char *remote_name, const char *signal_name,
                                 ir_signal_t *sig_out)
{
    if (!remote_name || !signal_name || !sig_out) return IR_HAT_ERR_IO;
    if (!s_ensure_io_line()) return IR_HAT_ERR_IO;

    char path[160];
    s_make_path(remote_name, path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (!f) return IR_HAT_ERR_IO;

    memset(sig_out, 0, sizeof(*sig_out));
    bool found = false;

    while (fgets(s_io_line, S_IO_LINE_LEN, f)) {
        s_strip_newline(s_io_line);
        if (strncmp(s_io_line, "name: ", 6) == 0) {
            if (strcmp(s_io_line + 6, signal_name) == 0) {
                strncpy(sig_out->name, signal_name, IR_HAT_NAME_LEN - 1);
                s_read_signal_body(f, sig_out);
                found = true;
                break;
            }
        }
    }
    fclose(f);
    return found ? IR_HAT_OK : IR_HAT_ERR_NOT_FOUND;
}

int ir_hat_list_signals(const char *remote_name,
                        char names[][IR_HAT_NAME_LEN], int max_count)
{
    if (!remote_name || !names || max_count <= 0) return 0;
    if (!s_ensure_io_line()) return 0;

    char path[160];
    s_make_path(remote_name, path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    int count = 0;
    while (fgets(s_io_line, S_IO_LINE_LEN, f) && count < max_count) {
        if (strncmp(s_io_line, "name: ", 6) == 0) {
            s_strip_newline(s_io_line);
            strncpy(names[count], s_io_line + 6, IR_HAT_NAME_LEN - 1);
            names[count][IR_HAT_NAME_LEN - 1] = '\0';
            count++;
        }
    }
    fclose(f);
    return count;
}

int ir_hat_list_remotes(char names[][IR_HAT_REMOTE_NAME_LEN], int max_count)
{
    if (!names || max_count <= 0) return 0;

    DIR *dir = opendir(RF_HAT_IR_SAVE_DIR);
    if (!dir) return 0;

    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(dir)) && count < max_count) {
        if (ent->d_type == DT_DIR) continue;
        char *dot = strrchr(ent->d_name, '.');
        if (!dot || strcmp(dot, IR_HAT_SAVE_EXT) != 0) continue;
        int len = (int)(dot - ent->d_name);
        if (len <= 0 || len >= IR_HAT_REMOTE_NAME_LEN) continue;
        strncpy(names[count], ent->d_name, len);
        names[count][len] = '\0';
        count++;
    }
    closedir(dir);
    return count;
}

ir_hat_err_t ir_hat_delete_signal(const char *remote_name, int del_index)
{
    if (!remote_name || del_index < 0) return IR_HAT_ERR_IO;
    if (!s_ensure_io_line()) return IR_HAT_ERR_IO;

    char src_path[160], tmp_path[160];
    s_make_path(remote_name, src_path, sizeof(src_path));
    snprintf(tmp_path, sizeof(tmp_path), RF_HAT_IR_SAVE_DIR "/_ir_tmp.ir");

    FILE *fin = fopen(src_path, "r");
    if (!fin) return IR_HAT_ERR_IO;
    FILE *fout = fopen(tmp_path, "w");
    if (!fout) { fclose(fin); return IR_HAT_ERR_IO; }

    s_write_header(fout);

    int sig_idx  = -1;
    bool skip    = false;
    bool in_sig  = false;

    while (fgets(s_io_line, S_IO_LINE_LEN, fin)) {
        // Skip the source header lines — we already wrote a fresh one
        if (strncmp(s_io_line, "Filetype:", 9) == 0 ||
            strncmp(s_io_line, "Version:",  8) == 0) continue;

        if (strncmp(s_io_line, "name: ", 6) == 0) {
            sig_idx++;
            skip   = (sig_idx == del_index);
            in_sig = true;
            if (!skip) fprintf(fout, "#\n");  // write separator for kept signals
        }

        // Skip "#" lines from source — we regenerate them above
        s_strip_newline(s_io_line);
        if (s_io_line[0] == '#') continue;

        if (!skip && in_sig) {
            fprintf(fout, "%s\n", s_io_line);
        }
    }

    fclose(fin);
    fclose(fout);
    remove(src_path);
    rename(tmp_path, src_path);
    ESP_LOGI(TAG, "Deleted signal %d from %s", del_index, remote_name);
    return IR_HAT_OK;
}

// ── TV-B-Gone ─────────────────────────────────────────────────────────────────
// Minimal built-in power-off codes. Sourced from open IR databases
// (Flipper Zero / IRDB / Ken Shirriff). Add more to /sdcard/lab/infrared/.

// t[] must hold at most 68 values (NEC: 2 header + 64 data + 2 trail).
// JVC/SIRC-12 need fewer; t[72] accommodates all current protocols.
typedef struct { uint32_t freq; uint32_t count; uint32_t t[72]; } tvbg_code_t;

// NEC bit encoding (LSB first): '0'=560,560  '1'=560,1680
// Samsung32: same timings, header=4500,4500 instead of 9000,4500; device byte repeated, no ~addr.
// JVC: header=8400,4200; bits '0'=525,525 '1'=525,1575; 16 bits (addr+cmd), no complement.
// SIRC-12 (Sony): header=2400,600; bits '0'=600,600 '1'=1200,600; 12 bits (7 cmd + 5 device).
static const tvbg_code_t TVBG_CODES[] = {
    // Samsung (Samsung32, 38 kHz) — device=0x07, cmd=0x02
    { 38000, 68, { 4500,4500,
                   560,1680, 560,1680, 560,560,  560,1680, 560,1680, 560,1680, 560,560,  560,560,
                   560,1680, 560,1680, 560,560,  560,1680, 560,1680, 560,1680, 560,560,  560,560,
                   560,560,  560,1680, 560,560,  560,560,  560,560,  560,560,  560,1680, 560,1680,
                   560,1680, 560,560,  560,1680, 560,1680, 560,1680, 560,1680, 560,560,  560,560,
                   560,40000 } },
    // LG (NEC, 38 kHz) — addr=0x20, cmd=0x10
    { 38000, 68, { 9000,4500,
                   560,560,  560,560,  560,560,  560,560,  560,560,  560,1680, 560,560,  560,560,
                   560,1680, 560,1680, 560,1680, 560,1680, 560,1680, 560,560,  560,1680, 560,1680,
                   560,560,  560,560,  560,560,  560,1680, 560,560,  560,560,  560,560,  560,560,
                   560,1680, 560,1680, 560,1680, 560,560,  560,1680, 560,1680, 560,1680, 560,1680,
                   560,40000 } },
    // Sony SIRC-20 (40 kHz) — Bravia and most post-2000 models
    { 40000, 40, { 2400,600,
                   600,600,  1200,600, 1200,600, 1200,600, 600,600,  600,600,  600,600,
                   600,600,  600,600,  1200,600, 600,600,  600,600,  600,600,  1200,600, 600,600,
                   600,600,  600,600,  600,600,  600,45000 } },
    // Sony SIRC-12 (40 kHz) — Trinitron and older models, cmd=0x15 device=0x01
    { 40000, 28, { 2400,600,
                   1200,600, 600,600,  1200,600, 600,600,  1200,600, 600,600,  600,600,
                   1200,600, 600,600,  600,600,  600,600,  600,600,
                   600,45000 } },
    // Philips (RC-5, 36 kHz)
    { 36000, 26, { 889,889,  889,889,  889,889,  889,889,  889,1778, 889,889,  889,1778,
                   1778,889, 889,889,  889,889,  889,889,  889,1778, 889,89000 } },
    // Toshiba variant A (NEC, 38 kHz) — addr=0x02, cmd=0x48  (older CRT/LCD models)
    { 38000, 68, { 9000,4500,
                   560,560,  560,1680, 560,560,  560,560,  560,560,  560,560,  560,560,  560,560,
                   560,1680, 560,560,  560,1680, 560,1680, 560,1680, 560,1680, 560,1680, 560,1680,
                   560,560,  560,560,  560,560,  560,1680, 560,560,  560,560,  560,1680, 560,560,
                   560,1680, 560,1680, 560,1680, 560,560,  560,1680, 560,1680, 560,560,  560,1680,
                   560,40000 } },
    // Toshiba variant B (NEC, 38 kHz) — addr=0x40, cmd=0x12  (pre-2010 LCD, Regza US)
    { 38000, 68, { 9000,4500,
                   560,560,  560,560,  560,560,  560,560,  560,560,  560,560,  560,1680, 560,560,
                   560,1680, 560,1680, 560,1680, 560,1680, 560,1680, 560,1680, 560,560,  560,1680,
                   560,560,  560,1680, 560,560,  560,560,  560,1680, 560,560,  560,560,  560,560,
                   560,1680, 560,560,  560,1680, 560,1680, 560,560,  560,1680, 560,1680, 560,1680,
                   560,40000 } },
    // Toshiba variant C (NEC, 38 kHz) — addr=0x14, cmd=0xCE  (2015+ Smart TV, Fire TV)
    { 38000, 68, { 9000,4500,
                   560,560,  560,560,  560,1680, 560,560,  560,1680, 560,560,  560,560,  560,560,
                   560,1680, 560,1680, 560,560,  560,1680, 560,560,  560,1680, 560,1680, 560,1680,
                   560,560,  560,1680, 560,1680, 560,1680, 560,560,  560,560,  560,1680, 560,1680,
                   560,1680, 560,560,  560,560,  560,560,  560,1680, 560,1680, 560,560,  560,560,
                   560,40000 } },
    // Hisense (NEC, 38 kHz) — addr=0x00, cmd=0x08
    { 38000, 68, { 9000,4500,
                   560,560,  560,560,  560,560,  560,560,  560,560,  560,560,  560,560,  560,560,
                   560,1680, 560,1680, 560,1680, 560,1680, 560,1680, 560,1680, 560,1680, 560,1680,
                   560,560,  560,560,  560,560,  560,1680, 560,560,  560,560,  560,560,  560,560,
                   560,1680, 560,1680, 560,1680, 560,560,  560,1680, 560,1680, 560,1680, 560,1680,
                   560,40000 } },
    // Panasonic (NEC, 38 kHz) — addr=0x40, cmd=0x4D; pre-2010 models
    { 38000, 68, { 9000,4500,
                   560,560,  560,560,  560,560,  560,560,  560,560,  560,560,  560,1680, 560,560,
                   560,1680, 560,1680, 560,1680, 560,1680, 560,1680, 560,1680, 560,560,  560,1680,
                   560,1680, 560,560,  560,1680, 560,1680, 560,560,  560,560,  560,1680, 560,560,
                   560,560,  560,1680, 560,560,  560,560,  560,1680, 560,1680, 560,560,  560,1680,
                   560,40000 } },
    // Vizio (NEC, 38 kHz) — addr=0x28, cmd=0x41
    { 38000, 68, { 9000,4500,
                   560,560,  560,560,  560,560,  560,1680, 560,560,  560,1680, 560,560,  560,560,
                   560,1680, 560,1680, 560,1680, 560,560,  560,1680, 560,560,  560,1680, 560,1680,
                   560,1680, 560,560,  560,560,  560,560,  560,560,  560,560,  560,1680, 560,560,
                   560,560,  560,1680, 560,1680, 560,1680, 560,1680, 560,1680, 560,560,  560,1680,
                   560,40000 } },
    // Haier/Changhong (NEC, 38 kHz) — addr=0x44, cmd=0x08
    { 38000, 68, { 9000,4500,
                   560,560,  560,560,  560,1680, 560,560,  560,560,  560,560,  560,1680, 560,560,
                   560,1680, 560,1680, 560,560,  560,1680, 560,1680, 560,1680, 560,560,  560,1680,
                   560,560,  560,560,  560,560,  560,1680, 560,560,  560,560,  560,560,  560,560,
                   560,1680, 560,1680, 560,1680, 560,560,  560,1680, 560,1680, 560,1680, 560,1680,
                   560,40000 } },
    // Hitachi (NEC, 38 kHz) — addr=0x80, cmd=0x40
    { 38000, 68, { 9000,4500,
                   560,560,  560,560,  560,560,  560,560,  560,560,  560,560,  560,560,  560,1680,
                   560,1680, 560,1680, 560,1680, 560,1680, 560,1680, 560,1680, 560,1680, 560,560,
                   560,560,  560,560,  560,560,  560,560,  560,560,  560,560,  560,1680, 560,560,
                   560,1680, 560,1680, 560,1680, 560,1680, 560,1680, 560,1680, 560,560,  560,1680,
                   560,40000 } },
    // Sanyo (NEC, 38 kHz) — addr=0x1C, cmd=0x47
    { 38000, 68, { 9000,4500,
                   560,560,  560,560,  560,1680, 560,1680, 560,1680, 560,560,  560,560,  560,560,
                   560,1680, 560,1680, 560,560,  560,560,  560,560,  560,1680, 560,1680, 560,1680,
                   560,1680, 560,1680, 560,1680, 560,560,  560,560,  560,560,  560,1680, 560,560,
                   560,560,  560,560,  560,560,  560,1680, 560,1680, 560,1680, 560,560,  560,1680,
                   560,40000 } },
    // TCL (NEC, 38 kHz) — addr=0x4C, cmd=0x47
    { 38000, 68, { 9000,4500,
                   560,560,  560,560,  560,1680, 560,1680, 560,560,  560,560,  560,1680, 560,560,
                   560,1680, 560,1680, 560,560,  560,560,  560,1680, 560,1680, 560,560,  560,1680,
                   560,1680, 560,1680, 560,1680, 560,560,  560,560,  560,560,  560,1680, 560,560,
                   560,560,  560,560,  560,560,  560,1680, 560,1680, 560,1680, 560,560,  560,1680,
                   560,40000 } },
    // JVC (JVC protocol, 38 kHz) — addr=0xC5, cmd=0xE1
    { 38000, 36, { 8400,4200,
                   525,1575, 525,525,  525,1575, 525,525,  525,525,  525,525,  525,1575, 525,1575,
                   525,1575, 525,525,  525,525,  525,525,  525,525,  525,1575, 525,1575, 525,1575,
                   525,40000 } },
};
#define TVBG_COUNT  (sizeof(TVBG_CODES)/sizeof(TVBG_CODES[0]))

void ir_hat_tvbgone(ir_hat_progress_cb_t progress_cb, void *ctx)
{
    // static: ir_signal_t is ~4140 bytes (1024 timings × 4 B) — too large for any task stack
    static ir_signal_t sig;
    for (int i = 0; i < (int)TVBG_COUNT; i++) {
        const tvbg_code_t *c = &TVBG_CODES[i];
        memset(&sig, 0, sizeof(sig));
        snprintf(sig.name, IR_HAT_NAME_LEN, "tvbg_%d", i);
        sig.freq_hz    = c->freq;
        sig.duty_cycle = IR_CARRIER_DUTY;
        sig.count      = c->count;
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

    ir_hat_capture_cancel();
    if (s_tx_chan) { rmt_disable(s_tx_chan); rmt_del_channel(s_tx_chan); s_tx_chan = NULL; }
    if (s_tx_enc)  { rmt_del_encoder(s_tx_enc); s_tx_enc = NULL; }
    s_init = false;

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
    ir_hat_init();
    ESP_LOGI(TAG, "IR jam stop");
}

bool ir_hat_is_jamming(void) { return s_jamming; }
