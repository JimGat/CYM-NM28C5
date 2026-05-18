#pragma once
// =============================================================================
// rf433_hat — 433 MHz OOK/ASK capture and replay for NM-RF-HAT (DIP 5)
// =============================================================================
// Capture: GPIO interrupt edge-timing (µs precision via esp_timer).
// Replay:  GPIO toggle with busy-wait timing.
//
// File format: Flipper Zero .sub compatible — allows files to be replayed on
// a Flipper Zero and vice versa. Files saved to /sdcard/lab/rf433/.
//
// Janos portability:
//   - rf433_hat_capture_start / rf433_hat_replay have no UI dependency
//   - Replace file I/O helpers with your file abstraction
// =============================================================================

#include <stdint.h>
#include <stdbool.h>

// Maximum number of pulse timing entries per capture.
// Flipper .sub lines hold up to 512 values; we store up to 1024.
#define RF433_HAT_MAX_PULSES  1024
#define RF433_HAT_NAME_LEN    32
#define RF433_HAT_SAVE_EXT    ".sub"

// Default 433.92 MHz carrier frequency (informational — the RF433 OOK module
// is fixed-frequency; the CC1101 on DIP 1 can tune to different frequencies).
#define RF433_HAT_DEFAULT_FREQ_HZ  433920000

// A captured OOK/ASK signal.
// pulses_us: alternating high/low pulse widths in microseconds.
//   pulses_us[0] = first HIGH duration
//   pulses_us[1] = first LOW  duration
//   ...
// Flipper stores negative values for LOW in the file; we use unsigned + count.
typedef struct {
    char     name[RF433_HAT_NAME_LEN];
    uint32_t freq_hz;
    uint32_t count;                         // number of entries in pulses_us
    uint32_t pulses_us[RF433_HAT_MAX_PULSES];
} rf433_signal_t;

typedef enum {
    RF433_HAT_OK = 0,
    RF433_HAT_ERR_NOT_INIT,
    RF433_HAT_ERR_TIMEOUT,
    RF433_HAT_ERR_OVERFLOW,
    RF433_HAT_ERR_HW,
    RF433_HAT_ERR_IO,
    RF433_HAT_ERR_BUSY,
} rf433_hat_err_t;

typedef void (*rf433_hat_cb_t)(rf433_hat_err_t result, const rf433_signal_t *sig, void *ctx);

// ── Lifecycle ────────────────────────────────────────────────────────────────
rf433_hat_err_t rf433_hat_init(void);
void            rf433_hat_deinit(void);
bool            rf433_hat_is_init(void);

// ── Capture ──────────────────────────────────────────────────────────────────
// Starts capture on RF_RX_GPIO. Calls cb when a frame is detected (gap > 30ms)
// or on timeout.
rf433_hat_err_t rf433_hat_capture_start(rf433_hat_cb_t cb, void *ctx, uint32_t timeout_ms);
void            rf433_hat_capture_cancel(void);

// ── Replay ───────────────────────────────────────────────────────────────────
// Transmits signal on RF_TX_GPIO. repeat: how many times to send the frame.
rf433_hat_err_t rf433_hat_replay(const rf433_signal_t *sig, uint8_t repeat);

// ── Storage ──────────────────────────────────────────────────────────────────
rf433_hat_err_t rf433_hat_save(const rf433_signal_t *sig, const char *filename);
rf433_hat_err_t rf433_hat_load(rf433_signal_t *sig_out, const char *filename);
int             rf433_hat_list_saved(char names[][RF433_HAT_NAME_LEN], int max_count);
