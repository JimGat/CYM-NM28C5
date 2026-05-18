#pragma once
// =============================================================================
// ir_hat — Infrared capture and replay for NM-RF-HAT (DIP switch position 4)
// =============================================================================
// Uses the ESP32-C5 RMT peripheral for both capture (38 kHz demodulated input)
// and replay (38 kHz modulated carrier output).
//
// Signal file format (.ir) is stored in /sdcard/lab/ir/.
// Compatible with the CYM IR file format; portable to Janos (headless) by
// removing the SD path dependency and feeding signals via ir_hat_replay() directly.
//
// Janos portability:
//   - Replace ir_hat_save/load/list with your file abstraction
//   - ir_hat_capture_start / ir_hat_replay have no UI dependency
// =============================================================================

#include <stdint.h>
#include <stdbool.h>

// Maximum number of RMT symbol pairs per captured frame.
// Each symbol encodes 2 pulse segments (duration + level).
// 256 pairs = 512 half-pulses — enough for all common IR protocols.
#define IR_HAT_MAX_PAIRS    256
#define IR_HAT_NAME_LEN     32
#define IR_HAT_SAVE_EXT     ".ir"

// A single captured IR signal: alternating high/low pulse durations in µs.
// times[0] = first HIGH pulse width µs
// times[1] = first LOW  pulse width µs
// times[2] = second HIGH, etc.
typedef struct {
    char     name[IR_HAT_NAME_LEN];
    uint32_t freq_hz;       // carrier frequency (typically 38000)
    uint32_t count;         // number of timing entries (high+low pairs)
    uint32_t times_us[IR_HAT_MAX_PAIRS * 2];
} ir_signal_t;

typedef enum {
    IR_HAT_OK = 0,
    IR_HAT_ERR_NOT_INIT,
    IR_HAT_ERR_TIMEOUT,     // no signal received within timeout
    IR_HAT_ERR_OVERFLOW,    // signal too long for buffer
    IR_HAT_ERR_HW,          // RMT driver error
    IR_HAT_ERR_IO,          // SD card read/write error
    IR_HAT_ERR_BUSY,        // capture already in progress
} ir_hat_err_t;

typedef void (*ir_hat_cb_t)(ir_hat_err_t result, const ir_signal_t *sig, void *ctx);

// ── Lifecycle ────────────────────────────────────────────────────────────────
// Call ir_hat_init() when entering the IR menu; ir_hat_deinit() on exit.
// Both functions are idempotent.
ir_hat_err_t ir_hat_init(void);
void         ir_hat_deinit(void);
bool         ir_hat_is_init(void);

// ── Capture ──────────────────────────────────────────────────────────────────
// Starts a background task that waits for an IR frame. Calls cb(result, sig, ctx)
// from a FreeRTOS task (NOT ISR context) when done or on timeout.
// timeout_ms: how long to wait before reporting IR_HAT_ERR_TIMEOUT.
ir_hat_err_t ir_hat_capture_start(ir_hat_cb_t cb, void *ctx, uint32_t timeout_ms);
void         ir_hat_capture_cancel(void);

// ── Replay ───────────────────────────────────────────────────────────────────
// Transmits a captured signal synchronously. Blocks until done (~100ms typical).
ir_hat_err_t ir_hat_replay(const ir_signal_t *sig);

// ── Storage ──────────────────────────────────────────────────────────────────
// filename: just the base name without path/ext (e.g. "tv_power").
ir_hat_err_t ir_hat_save(const ir_signal_t *sig, const char *filename);
ir_hat_err_t ir_hat_load(ir_signal_t *sig_out, const char *filename);

// Returns number of saved signals. Names filled into names[][IR_HAT_NAME_LEN].
int          ir_hat_list_saved(char names[][IR_HAT_NAME_LEN], int max_count);

// TV-B-Gone: blast through a library of common power-off IR codes.
// Calls progress_cb(index, total, ctx) after each code is sent (may be NULL).
typedef void (*ir_hat_progress_cb_t)(int index, int total, void *ctx);
void ir_hat_tvbgone(ir_hat_progress_cb_t progress_cb, void *ctx);

// ── Jammer ───────────────────────────────────────────────────────────────────
// Outputs continuous IR carrier via LEDC (hardware PWM — zero CPU overhead).
// Blinds all IR receivers in range for the duration.
// freq_hz: carrier frequency (0 = default 38000 Hz).
// jam_start releases the RMT TX channel and takes the GPIO via LEDC.
// jam_stop restores RMT TX by re-running ir_hat_init().
ir_hat_err_t ir_hat_jam_start(uint32_t freq_hz);
void         ir_hat_jam_stop(void);
bool         ir_hat_is_jamming(void);
