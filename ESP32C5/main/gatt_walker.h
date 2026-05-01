#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

/* ── Limits ─────────────────────────────────────────────────────── */
#define GW_MAX_SVCS   20   /* max services per device */
#define GW_MAX_CHRS   16   /* max characteristics per service */
#define GW_MAX_DSCS    6   /* max descriptors per characteristic */
#define GW_READ_MAX  512   /* max bytes read per characteristic (BLE spec max attr length) */

/* ── State ──────────────────────────────────────────────────────── */
typedef enum {
    GW_STATE_IDLE = 0,
    GW_STATE_CONNECTING,
    GW_STATE_DISC_SVCS,
    GW_STATE_DISC_CHRS,
    GW_STATE_DISC_DSCS,
    GW_STATE_READING,
    GW_STATE_SAVING,
    GW_STATE_COMPLETE,
    GW_STATE_FAILED,
    GW_STATE_CANCELLED,
    GW_STATE_PROBING,
    GW_STATE_PROBE_DONE,
} gw_state_t;

/* ── Events ─────────────────────────────────────────────────────── */
typedef enum {
    GW_EVENT_STARTED,
    GW_EVENT_CONNECTED,
    GW_EVENT_SVC_FOUND,
    GW_EVENT_CHR_FOUND,
    GW_EVENT_READING,
    GW_EVENT_SAVED,
    GW_EVENT_COMPLETE,
    GW_EVENT_FAILED,
    GW_EVENT_CANCELLED,
    GW_EVENT_PROBE_STARTED,
    GW_EVENT_PROBE_DONE,
} gw_event_t;

/* ── Result structures ──────────────────────────────────────────── */
typedef struct {
    uint16_t def_handle;
    uint16_t val_handle;
    char     uuid_str[37];   /* ble_uuid_to_str() output */
    uint8_t  properties;
    uint8_t  read_data[GW_READ_MAX];
    uint16_t read_len;
    bool     read_ok;
    struct {
        uint16_t handle;
        char     uuid_str[37];
    } descs[GW_MAX_DSCS];
    int desc_count;
    /* ── CCCD Subscription Probe results ── */
    bool             probe_attempted;
    bool             probe_cccd_ok;
    uint8_t          probe_frames[8][64]; /* up to 8 notification frames, 64B each */
    uint8_t          probe_frame_lens[8];
    int              probe_frame_count;
} gw_chr_t;

typedef struct {
    uint16_t start_handle;
    uint16_t end_handle;
    char     uuid_str[37];
    gw_chr_t chrs[GW_MAX_CHRS];
    int      chr_count;
} gw_svc_t;

typedef struct {
    uint8_t  mac[6];
    uint8_t  addr_type;
    char     name[32];
    int8_t   rssi;
    double   lat, lon;
    bool     gps_valid;
    gw_svc_t svcs[GW_MAX_SVCS];
    int      svc_count;
    uint32_t fingerprint;
    char     timestamp[20];   /* "YYYYMMDD_HHMMSS" */
    char     filepath[80];    /* full SD path */
    bool     probe_done;
} gw_result_t;

/* ── Volatile UI state — safe to read from main loop ────────────── */
extern volatile gw_state_t gw_ui_state;
extern volatile int        gw_ui_svc_count;
extern volatile int        gw_ui_chr_count;
extern volatile char       gw_ui_status[96];
extern volatile bool       gw_ui_needs_update;

/* ── Callback — called from NimBLE context; NO LVGL calls here! ─── */
typedef void (*gw_event_cb_t)(gw_event_t event, const gw_result_t *result);

/* ── Public API ─────────────────────────────────────────────────── */

/* Call once after sd_spi_mutex is created. sd_mutex may be NULL. */
void gw_init(SemaphoreHandle_t sd_mutex);

/* Register event callback. Must be called before gw_walk(). */
void gw_set_callback(gw_event_cb_t cb);

/* Start a GATT walk. BLE must be active (NimBLE host running, scan stopped).
 * lat/lon/gps_valid: caller's GPS snapshot for geotagging.
 * Returns false if already walking or BLE connect fails. */
bool gw_walk(const uint8_t mac[6], uint8_t addr_type, const char *name,
             int8_t rssi, double lat, double lon, bool gps_valid);

/* Request cancellation of an in-progress walk (async). */
void gw_cancel(void);

/* Set BLE connect timeout (ms). Default 30000. Call before gw_walk(). */
void gw_set_timeout(uint32_t ms_timeout);

/* Current state (atomic read). */
gw_state_t gw_get_state(void);

/* Last completed result — valid after GW_STATE_COMPLETE. */
const gw_result_t *gw_get_result(void);

/* Decode properties bitmask into a compact string, e.g. "R W N".
 * buf must be at least 20 bytes. Returns buf. */
char *gw_chr_props_str(uint8_t props, char *buf, size_t bufsz);

/* Launch CCCD subscription probe against the last completed result.
 * Reconnects to the device, subscribes to every N/I characteristic,
 * collects frames for dwell_ms each, then re-saves the JSON.
 * Returns false if no result is available or probe already running. */
bool gw_probe_start(uint32_t dwell_ms);

/* Free probe task stack after GW_EVENT_PROBE_DONE fires. */
void gw_probe_free_stack(void);
