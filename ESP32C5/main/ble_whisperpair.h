/*
 * ble_whisperpair.h — WhisperPair (CVE-2025-36911) Google Fast Pair KBP bypass
 *
 * VULNERABILITY SUMMARY
 * ─────────────────────
 * Google Fast Pair devices accept Key-Based Pairing (KBP) requests regardless of
 * whether they are in pairing mode.  An attacker within Bluetooth range can initiate
 * an unauthorized pairing, gaining audio/microphone access and Find Hub tracking.
 * Disclosed January 2026 by COSIC/KU Leuven.  Affects Sony, JBL, Jabra, Bose,
 * Marshall, Xiaomi, Nothing, OnePlus, Soundcore, Logitech, and Google devices.
 *
 * LEGAL DISCLAIMER
 * ────────────────
 * This implementation is for AUTHORIZED SECURITY RESEARCH and CTF/lab environments
 * ONLY.  Do NOT use against devices you do not own or have written permission to
 * test.  Unauthorized use may violate local computer fraud and privacy laws.
 *
 * DETECTION (passive, advertisement)
 * ────────────────────────────────────
 *   Fast Pair devices advertise Service Data with UUID 0xFE2C.
 *   Call wp_is_fast_pair_adv() from your BLE scan callback to flag candidates.
 *
 * PROBE MODE (non-invasive vulnerability check)
 * ──────────────────────────────────────────────
 *   Connects via GATT, writes a plaintext dummy KBP block to the KBP characteristic
 *   (UUID fe2c1234-8366-4814-8eb0-01de32100bea) without encryption.  A VULNERABLE
 *   device responds with a GATT notification; a patched device stays silent or
 *   disconnects.  No pairing is established — safe for assessment.
 *
 * EXPLOIT MODE (full CVE-2025-36911 attack)
 * ──────────────────────────────────────────
 *   Builds a properly-formed KBP block: [Type(1)][Flags(1)][ProviderMAC(6)][Salt(8)],
 *   then encrypts it with AES-128-ECB using the Salt (zero-padded to 128 bits) as the
 *   key.  The encrypted packet is written to the KBP characteristic.  A vulnerable
 *   device accepts the pairing handshake without being in pairing mode.
 *
 * PORTING TO JANOS (or other platforms)
 * ──────────────────────────────────────
 *   Hard dependencies (swap for your platform equivalents):
 *     · NimBLE host API (host/ble_hs.h) — ble_gap_connect, ble_gattc_*
 *     · FreeRTOS — xTaskCreate, xSemaphoreCreateBinary, vTaskDelay
 *     · ESP ROM AES (esp32c5/rom/aes.h) — ets_aes_* for AES-128-ECB
 *       Janos: replace with mbedtls_aes_crypt_ecb, or any AES-128-ECB impl
 *     · esp_log.h — replace with your logger
 *     · esp_heap_caps.h — replace with malloc if no PSRAM
 *   No LVGL dependency in this file.  SD logging uses standard POSIX fopen/fwrite.
 *   SD mutex is optional (pass NULL to disable).
 */

#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "host/ble_hs_adv.h"   /* struct ble_hs_adv_fields */

/* ── Fast Pair constants ───────────────────────────────────────────── */
#define WP_SVC_UUID16          0xFE2Cu         /* Fast Pair service UUID */
#define WP_NOTIFY_TIMEOUT_MS   5000u           /* wait for KBP notification */
#define WP_CONNECT_TIMEOUT_MS  10000u

/* ── Result of a probe or exploit attempt ─────────────────────────── */
typedef enum {
    WP_RESULT_VULNERABLE,    /* Device accepted KBP without being in pairing mode */
    WP_RESULT_PATCHED,       /* Device rejected write / no notification within timeout */
    WP_RESULT_NO_SERVICE,    /* 0xFE2C service not found on device */
    WP_RESULT_CONNECT_FAIL,  /* Could not establish GATT connection */
    WP_RESULT_ERROR,         /* Protocol or internal error */
} wp_result_t;

/* ── Mode selection ────────────────────────────────────────────────── */
typedef enum {
    WP_MODE_PROBE,    /* Plaintext KBP write — confirms vulnerability, no pairing */
    WP_MODE_EXPLOIT,  /* AES-128-ECB KBP write — triggers unauthorized pairing bypass */
} wp_mode_t;

/* ── Result callback (called from wp task; NO LVGL calls) ─────────── */
typedef void (*wp_cb_t)(wp_result_t result, const char *detail,
                        const uint8_t mac[6], wp_mode_t mode);

/* ── Public API ───────────────────────────────────────────────────── */

/* Call once at startup.  sd_mutex may be NULL (disables SD logging). */
void wp_init(SemaphoreHandle_t sd_mutex);

/* Returns true if the advertisement fields contain a Fast Pair service data
 * record (UUID 0xFE2C).  Safe to call from BLE scan callback context. */
bool wp_is_fast_pair_adv(const struct ble_hs_adv_fields *fields);

/* Start a probe or exploit against mac/addr_type.  BLE must be active (NimBLE
 * running, scan stopped).  Returns false if already active or BLE not ready.
 * result_cb is called exactly once from the wp task when done. */
bool wp_start(const uint8_t mac[6], uint8_t addr_type, const char *name,
              int8_t rssi, wp_mode_t mode, wp_cb_t result_cb);

/* Request cancellation.  result_cb will be called with WP_RESULT_ERROR. */
void wp_cancel(void);

/* True while a probe/exploit task is running. */
bool wp_is_active(void);

/* Current status string for UI polling (up to 80 chars, always NUL-terminated). */
const char *wp_status(void);
