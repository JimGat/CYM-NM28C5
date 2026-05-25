#pragma once
// =============================================================================
// ir_hat — Infrared capture, replay, and storage for NM-RF-HAT (DIP switch 4)
// =============================================================================
// File format: Flipper Zero compatible (.ir)
//   Filetype: IR signals file
//   Version: 1
//   #
//   name: <signal_name>
//   type: raw
//   frequency: 38000
//   duty_cycle: 0.33
//   data: <t0> <t1> ... <tN>     (microseconds, alternating mark/space)
//
// One .ir file = one "remote" (e.g. Samsung_TV.ir).
// Multiple named signals per file (Power, Vol+, Vol-, Mute, …).
// Files live in RF_HAT_IR_SAVE_DIR (/sdcard/lab/infrared/).
// Files are directly portable to/from Flipper Zero (different mount point only).
// =============================================================================

#include <stdint.h>
#include <stdbool.h>

// ── Limits ───────────────────────────────────────────────────────────────────
#define IR_HAT_MAX_TIMINGS       1024  // max mark/space entries per signal (matches Flipper)
#define IR_HAT_NAME_LEN          32    // signal name max length (incl. null)
#define IR_HAT_REMOTE_NAME_LEN   64    // remote file basename max length (no path/ext)
#define IR_HAT_MAX_REMOTES       32    // max .ir files listed at once
#define IR_HAT_MAX_SIGNALS       64    // max signals listed per remote file
#define IR_HAT_SAVE_EXT          ".ir"

// ── Signal struct ─────────────────────────────────────────────────────────────
// A single captured IR signal: alternating mark/space pulse durations in µs.
// times_us[0] = first mark (carrier burst) duration
// times_us[1] = first space (gap) duration, etc.
typedef struct {
    char     name[IR_HAT_NAME_LEN];
    uint32_t freq_hz;       // carrier frequency Hz  (typically 38000)
    float    duty_cycle;    // PWM duty cycle 0.0–1.0 (typically 0.33)
    uint32_t count;         // number of timing entries (mark+space pairs × 2)
    uint32_t times_us[IR_HAT_MAX_TIMINGS];
} ir_signal_t;

// ── Error codes ───────────────────────────────────────────────────────────────
typedef enum {
    IR_HAT_OK = 0,
    IR_HAT_ERR_NOT_INIT,
    IR_HAT_ERR_TIMEOUT,     // no signal received within timeout
    IR_HAT_ERR_OVERFLOW,    // signal too long for buffer
    IR_HAT_ERR_HW,          // RMT driver error
    IR_HAT_ERR_IO,          // SD card read/write error
    IR_HAT_ERR_BUSY,        // capture already in progress
    IR_HAT_ERR_NOT_FOUND,   // signal name or index not in file
} ir_hat_err_t;

typedef void (*ir_hat_cb_t)(ir_hat_err_t result, const ir_signal_t *sig, void *ctx);
typedef void (*ir_hat_progress_cb_t)(int index, int total, void *ctx);

// ── Lifecycle ────────────────────────────────────────────────────────────────
// Call ir_hat_init() when entering the IR menu; ir_hat_deinit() on exit.
ir_hat_err_t ir_hat_init(void);
void         ir_hat_deinit(void);
bool         ir_hat_is_init(void);

// ── Capture ──────────────────────────────────────────────────────────────────
// Starts a background task. Calls cb(result, sig, ctx) when done or timed out.
ir_hat_err_t ir_hat_capture_start(ir_hat_cb_t cb, void *ctx, uint32_t timeout_ms);
void         ir_hat_capture_cancel(void);

// ── Replay ───────────────────────────────────────────────────────────────────
// Transmits sig synchronously. Blocks until TX complete (~100 ms typical).
ir_hat_err_t ir_hat_replay(const ir_signal_t *sig);

// ── Storage — Flipper-compatible .ir format ───────────────────────────────────
// remote_name: basename without path or extension  (e.g. "Samsung_TV")
// All files live in RF_HAT_IR_SAVE_DIR.

// Create a new empty remote file (header only). Fails if file already exists.
ir_hat_err_t ir_hat_create_remote(const char *remote_name);

// Append a signal to a remote file. Creates the file (with header) if absent.
ir_hat_err_t ir_hat_append_signal(const char *remote_name, const ir_signal_t *sig);

// Load a signal by zero-based index from a remote file.
ir_hat_err_t ir_hat_load_signal_by_index(const char *remote_name, int index, ir_signal_t *sig_out);

// Load a signal by name (first match) from a remote file.
ir_hat_err_t ir_hat_load_signal(const char *remote_name, const char *signal_name, ir_signal_t *sig_out);

// List signal names within a remote file. Returns count found (≤ max_count).
int ir_hat_list_signals(const char *remote_name,
                        char names[][IR_HAT_NAME_LEN], int max_count);

// List .ir remote file basenames in the save directory. Returns count found.
int ir_hat_list_remotes(char names[][IR_HAT_REMOTE_NAME_LEN], int max_count);

// Delete a signal by index (rewrites the file). Use sparingly — rewrites whole file.
ir_hat_err_t ir_hat_delete_signal(const char *remote_name, int index);

// ── TV-B-Gone ─────────────────────────────────────────────────────────────────
// Transmits a built-in set of common TV power-off IR codes in sequence.
// Call ir_hat_tvbgone_stop() from any context to abort mid-sequence.
void ir_hat_tvbgone(ir_hat_progress_cb_t progress_cb, void *ctx);
void ir_hat_tvbgone_stop(void);

// ── Jammer ───────────────────────────────────────────────────────────────────
// Outputs continuous IR carrier via LEDC (hardware PWM, zero CPU overhead).
// freq_hz = 0 → uses default 38000 Hz.
// jam_start releases RMT TX and drives the GPIO via LEDC.
// jam_stop restores RMT TX by re-running ir_hat_init().
ir_hat_err_t ir_hat_jam_start(uint32_t freq_hz);
void         ir_hat_jam_stop(void);
bool         ir_hat_is_jamming(void);
