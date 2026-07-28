/*
 * chameleon_ble.h — Chameleon Ultra / Lite BLE client
 *
 * Concept: @bkbroiler | Protocol ref: ChameleonUltraGUI (GameTec-live)
 * Phase 1: Scan, connect, GATT discovery, device info
 *
 * Architecture: NimBLE callbacks fill an RX ring buffer; cham_poll() (called
 * from an LVGL timer every 50 ms) parses frames and drives the state machine.
 * All LVGL updates must happen in cham_poll() — never in NimBLE callbacks.
 */
#pragma once
#include <stdint.h>
#include <stdbool.h>

/* ── Connection state (simplified public view) ───────────────────────────── */
typedef enum {
    CHAM_STATE_DISCONNECTED = 0,
    CHAM_STATE_SCANNING,
    CHAM_STATE_CONNECTING,   /* disc_cancel + defer + ble_gap_connect */
    CHAM_STATE_PAIRING,      /* numeric comparison — waiting for user to confirm */
    CHAM_STATE_DISCOVERING,  /* MTU + service/char discovery + CCCD write */
    CHAM_STATE_HANDSHAKING,  /* reading device info */
    CHAM_STATE_READY,        /* fully connected, info valid */
    CHAM_STATE_ERROR,
} cham_state_t;

/* ── Scan results ─────────────────────────────────────────────────────────── */
#define CHAM_MAX_SCAN  6

typedef struct {
    char    name[32];
    uint8_t addr[6];       /* BLE address bytes */
    uint8_t addr_type;     /* BLE_ADDR_PUBLIC / BLE_ADDR_RANDOM */
    int8_t  rssi;
    bool    is_lite;       /* true = Chameleon Lite (HF only) */
} cham_scan_result_t;

/* ── Device info (valid when state == CHAM_STATE_READY) ──────────────────── */
typedef struct {
    bool     is_lite;          /* false = Ultra (LF+HF), true = Lite (HF only) */
    uint16_t fw_version;       /* raw version word from getAppVersion */
    char     ble_addr[18];     /* "AA:BB:CC:DD:EE:FF\0" */
    char     chip_id[17];      /* 16 hex chars + NUL */
    int      battery_pct;      /* 0-100 */
    int      battery_mv;       /* millivolts */
} cham_device_info_t;

/* ── Async command result callback ───────────────────────────────────────── */
typedef void (*cham_cmd_result_cb_t)(bool ok, const uint8_t *data, uint16_t dlen);

/* ── Public API ───────────────────────────────────────────────────────────── */

/* One-time module init — call from app_main before first use */
void cham_init(void);

/* Pairing (numeric comparison): call from LVGL task when state == CHAM_STATE_PAIRING */
uint32_t cham_get_passkey(void);   /* 6-digit number to display */
void     cham_passkey_accept(void); /* inject numcmp_accept=1 → pairing continues */
void     cham_passkey_reject(void); /* inject numcmp_accept=0 → peer will disconnect */

/* Scan for Chameleon devices; call cham_scan_result_get() to read results */
void cham_scan_start(void);
void cham_scan_stop(void);

/* Connect to scan result at index idx. Returns false if state is wrong. */
bool cham_connect(int idx);

/* Disconnect and return to DISCONNECTED */
void cham_disconnect(void);

/* State / info queries — safe to call any time */
cham_state_t              cham_get_state(void);
const char               *cham_get_status_msg(void);
const cham_device_info_t *cham_get_device_info(void);
int                       cham_scan_result_count(void);
const cham_scan_result_t *cham_scan_result_get(int idx);

/*
 * Poll — MUST be called from an LVGL timer every ~50 ms.
 * Drains the RX ring buffer, parses frames, drives state transitions,
 * and fires pending command callbacks.
 * Returns true if state or data changed (caller should refresh UI).
 */
bool cham_poll(void);

/*
 * Send a low-level command (async).
 * cb fires from within cham_poll() when the response arrives (or on timeout).
 * Returns false if not READY/HANDSHAKING, or if another command is in flight.
 * Phase 1 internal use only — higher-level wrappers will be added in later phases.
 */
bool cham_send_cmd(uint16_t cmd, const uint8_t *data, uint16_t dlen,
                   cham_cmd_result_cb_t cb);
