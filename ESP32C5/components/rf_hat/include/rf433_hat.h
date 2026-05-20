#pragma once
// =============================================================================
// rf433_hat — 433 MHz OOK/ASK capture, replay, and storage for NM-RF-HAT (DIP 5)
// =============================================================================
// File format: Flipper Zero compatible (.sub)
//   Filetype: Flipper SubGhz File
//   Version: 1
//   Frequency: 433920000
//   Preset: FuriHalSubGhzPresetOokAsync
//   Protocol: RAW
//   RAW_Data: <+t0> <-t1> <+t2> ...   (µs; positive=HIGH, negative=LOW)
//
// Storage layout mirrors the IR module:
//   One subdirectory = one "remote" (e.g. /sdcard/lab/rf433/GarageDoor/)
//   One .sub file = one named signal  (e.g. GarageDoor/Open.sub)
//
// This keeps every .sub file as a pure, unmodified Flipper Zero file —
// copy any Flipper .sub directly into a remote subdirectory and it plays.
// Flipper files dropped into a remote subdir are visible immediately in the UI.
// =============================================================================

#include <stdint.h>
#include <stdbool.h>

// ── Limits ───────────────────────────────────────────────────────────────────
#define RF433_HAT_MAX_PULSES       512   // max pulse entries per signal
#define RF433_HAT_NAME_LEN         32    // signal name max length (incl. null)
#define RF433_HAT_REMOTE_NAME_LEN  48    // remote dir basename max length
#define RF433_HAT_MAX_REMOTES      32    // max remote dirs listed at once
#define RF433_HAT_MAX_SIGNALS      64    // max signals listed per remote dir
#define RF433_HAT_SAVE_EXT         ".sub"

// Default 433.92 MHz — the OOK module is fixed-frequency.
// CC1101 (DIP 1) can tune; use this constant for the OOK module.
#define RF433_HAT_DEFAULT_FREQ_HZ  433920000

// ── Signal struct ─────────────────────────────────────────────────────────────
// alternating HIGH/LOW pulse durations in microseconds.
// pulses_us[0] = first HIGH duration, pulses_us[1] = first LOW duration, etc.
typedef struct {
    char     name[RF433_HAT_NAME_LEN];
    uint32_t freq_hz;
    uint32_t count;
    uint32_t pulses_us[RF433_HAT_MAX_PULSES];
} rf433_signal_t;

// ── Error codes ───────────────────────────────────────────────────────────────
typedef enum {
    RF433_HAT_OK = 0,
    RF433_HAT_ERR_NOT_INIT,
    RF433_HAT_ERR_TIMEOUT,
    RF433_HAT_ERR_OVERFLOW,
    RF433_HAT_ERR_HW,
    RF433_HAT_ERR_IO,
    RF433_HAT_ERR_BUSY,
    RF433_HAT_ERR_NOT_FOUND,
} rf433_hat_err_t;

typedef void (*rf433_hat_cb_t)(rf433_hat_err_t result, const rf433_signal_t *sig, void *ctx);

// ── Lifecycle ────────────────────────────────────────────────────────────────
rf433_hat_err_t rf433_hat_init(void);
void            rf433_hat_deinit(void);
bool            rf433_hat_is_init(void);

// ── Capture ──────────────────────────────────────────────────────────────────
// Starts capture on RF_HAT_RF433_RX_GPIO. Calls cb when a frame is detected
// (inter-frame gap > 30 ms) or on timeout.
rf433_hat_err_t rf433_hat_capture_start(rf433_hat_cb_t cb, void *ctx, uint32_t timeout_ms);
void            rf433_hat_capture_cancel(void);

// ── Replay ───────────────────────────────────────────────────────────────────
// Transmits sig on RF_HAT_RF433_TX_GPIO. repeat=0 treated as 1.
rf433_hat_err_t rf433_hat_replay(const rf433_signal_t *sig, uint8_t repeat);

// ── Storage — Flipper-compatible .sub format ──────────────────────────────────
// remote_name : directory basename under RF_HAT_RF433_SAVE_DIR (e.g. "GarageDoor")
// signal_name : .sub file basename without extension           (e.g. "Open")
//
// Each remote is a subdirectory; each signal is an individual .sub file.
// Any Flipper Zero .sub file copied into a remote directory is immediately usable.

// Create a new empty remote directory. Fails if directory already exists.
rf433_hat_err_t rf433_hat_create_remote(const char *remote_name);

// Save sig as <remote_name>/<sig->name>.sub. Creates the remote dir if absent.
rf433_hat_err_t rf433_hat_append_signal(const char *remote_name, const rf433_signal_t *sig);

// Load a signal by zero-based index (readdir order) from a remote directory.
rf433_hat_err_t rf433_hat_load_signal_by_index(const char *remote_name, int index, rf433_signal_t *sig_out);

// Load a signal by name (filename without .sub) from a remote directory.
rf433_hat_err_t rf433_hat_load_signal(const char *remote_name, const char *signal_name, rf433_signal_t *sig_out);

// List signal basenames (without .sub) in a remote directory. Returns count found.
int rf433_hat_list_signals(const char *remote_name,
                           char names[][RF433_HAT_NAME_LEN], int max_count);

// List remote directory names under RF_HAT_RF433_SAVE_DIR. Returns count found.
int rf433_hat_list_remotes(char names[][RF433_HAT_REMOTE_NAME_LEN], int max_count);

// Delete a signal by index (removes the .sub file). No file rewrite needed.
rf433_hat_err_t rf433_hat_delete_signal(const char *remote_name, int index);

// ── Jammer ───────────────────────────────────────────────────────────────────
// Holds RF_HAT_RF433_TX_GPIO HIGH — outputs a continuous 433 MHz carrier.
// Safe to call without rf433_hat_init() (TX-only GPIO, no ISR needed).
void rf433_hat_jam_start(void);
void rf433_hat_jam_stop(void);
bool rf433_hat_is_jamming(void);
