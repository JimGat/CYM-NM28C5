/**
 * bt_lookout — BLE Watchlist Monitor ("Dee Dee Detector")
 *
 * Portable module: no LVGL, no board-specific peripherals except esp_timer.
 * LED output is driven via a caller-supplied function pointer so the caller
 * controls which physical LED is used.
 *
 * Alert pattern: 3 × (500 ms ON / 2500 ms OFF) = 9 s sequence.
 * Per-device cooldown: 30 s after the last alert for that MAC.
 *
 * Thread model (single-core ESP32):
 *   bt_lookout_on_adv() — called from NimBLE host task
 *   bt_lookout_tick()   — called from main task (drives LED)
 *   All other functions — called from main/LVGL task
 *   No explicit locking needed on single-core; struct fields are written
 *   atomically before the pending flag is raised.
 */
#pragma once
#include <stdint.h>
#include <stdbool.h>

/* ── Constants ─────────────────────────────────────────────────── */
#define BT_LOOKOUT_MAX_ENTRIES    64
#define BT_LOOKOUT_MAX_COOLDOWN   16
#define BT_LOOKOUT_CSV_PATH       "/sdcard/lab/bluetooth/lookout.csv"
#define BT_LOOKOUT_CSV_HEADER     "mac,name,rssi_threshold\n"
#define BT_LOOKOUT_RSSI_ANY       (-99)  /* trigger regardless of measured RSSI */

/* ── Types ─────────────────────────────────────────────────────── */

/** One entry in the watchlist. */
typedef struct {
    uint8_t mac[6];           /**< 6-byte BLE MAC (little-endian, as from NimBLE) */
    char    name[32];         /**< human-readable label from CSV or advertisement  */
    int     rssi_threshold;   /**< trigger when RSSI >= this; BT_LOOKOUT_RSSI_ANY = any */
} bt_lookout_entry_t;

/** Snapshot of the most-recent detection, consumed by the caller once. */
typedef struct {
    bool    valid;
    uint8_t mac[6];
    char    name[32];
    int     rssi;
} bt_lookout_detection_t;

/** Caller-supplied LED setter — r/g/b 0-255. */
typedef void (*bt_lookout_led_fn_t)(uint8_t r, uint8_t g, uint8_t b);

/* ── Lifecycle ─────────────────────────────────────────────────── */
void bt_lookout_start(void);
void bt_lookout_stop(void);
bool bt_lookout_is_active(void);

/* ── File I/O ──────────────────────────────────────────────────── */
/**
 * Load watchlist from csv_path.  If the file does not exist it is created
 * with the CSV header.  Returns number of entries loaded, or -1 on error.
 */
int  bt_lookout_load(const char *csv_path);

/**
 * Append one entry to csv_path and the in-memory list.
 * Safe to call at any time; opens/closes the file each call.
 */
bool bt_lookout_append(const char   *csv_path,
                       const uint8_t mac[6],
                       const char   *name,
                       int           rssi_threshold);

/* ── Scan-result integration ───────────────────────────────────── */
/**
 * Feed every BLE advertisement here (called from NimBLE host task).
 * Returns true when a watchlist hit is found and an alert sequence begins.
 * adv_name may be NULL.
 */
bool bt_lookout_on_adv(const uint8_t mac[6], int rssi, const char *adv_name);

/* ── Main-loop LED driver ──────────────────────────────────────── */
/**
 * Call once per main-loop iteration.  Drives the 3-flash alert sequence.
 * Returns true if it set the LED (caller should skip its own LED update).
 * led_fn is called with (0,0,0) at end-of-sequence to extinguish the LED.
 */
bool bt_lookout_tick(bt_lookout_led_fn_t led_fn);

/* ── Watchlist read-access ─────────────────────────────────────── */
int                        bt_lookout_count(void);
const bt_lookout_entry_t  *bt_lookout_get(int idx);

/* ── Detection result handoff ──────────────────────────────────── */
/**
 * Returns true and fills *out if a new detection is waiting.
 * Clears the pending flag so subsequent calls return false until the next hit.
 */
bool bt_lookout_poll_detection(bt_lookout_detection_t *out);
