#include "gatt_walker.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "host/ble_hs.h"
#include "os/os_mbuf.h"

static const char *TAG = "gatt_walker";

/* ── Volatile UI exports ─────────────────────────────────────────── */
volatile gw_state_t gw_ui_state        = GW_STATE_IDLE;
volatile int        gw_ui_svc_count    = 0;
volatile int        gw_ui_chr_count    = 0;
volatile char       gw_ui_status[64]   = "";
volatile bool       gw_ui_needs_update = false;

/* ── Internal state ──────────────────────────────────────────────── */
static SemaphoreHandle_t  s_sd_mutex    = NULL;
static gw_event_cb_t      s_callback    = NULL;
static gw_result_t       *s_result      = NULL;
static volatile gw_state_t s_state      = GW_STATE_IDLE;
static uint16_t           s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
static volatile bool      s_cancel_req  = false;

/* Sequential walk cursors (one GATT op in flight at a time) */
static int s_cur_svc = 0;
static int s_cur_chr = 0;

/* ── State helpers ───────────────────────────────────────────────── */

static void s_set_state(gw_state_t st)
{
    s_state         = st;
    gw_ui_state     = st;
    gw_ui_needs_update = true;
}

static void s_notify_ui(const char *msg)
{
    strncpy((char *)gw_ui_status, msg, sizeof(gw_ui_status) - 1);
    gw_ui_status[sizeof(gw_ui_status) - 1] = '\0';
    gw_ui_needs_update = true;
}

static void s_fire_event(gw_event_t evt)
{
    if (s_callback) s_callback(evt, s_result);
}

static void s_disconnect(void)
{
    if (s_conn_handle != BLE_HS_CONN_HANDLE_NONE) {
        ble_gap_terminate(s_conn_handle, 0x13); /* Remote User Terminated Connection */
        s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
    }
}

static void s_fail(const char *reason)
{
    ESP_LOGE(TAG, "Walk failed: %s", reason);
    s_notify_ui(reason);
    s_set_state(GW_STATE_FAILED);
    s_disconnect();
    s_fire_event(GW_EVENT_FAILED);
}

/* ── FNV-32 fingerprint ──────────────────────────────────────────── */
#define FNV_OFFSET 0x811c9dc5u
#define FNV_PRIME  0x01000193u

static uint32_t s_fnv32(const uint8_t *data, size_t len, uint32_t h)
{
    for (size_t i = 0; i < len; i++) { h ^= data[i]; h *= FNV_PRIME; }
    return h;
}

static uint32_t s_compute_fingerprint(void)
{
    uint32_t h = FNV_OFFSET;
    for (int i = 0; i < s_result->svc_count; i++) {
        const gw_svc_t *svc = &s_result->svcs[i];
        h = s_fnv32((const uint8_t *)svc->uuid_str, strlen(svc->uuid_str), h);
        for (int j = 0; j < svc->chr_count; j++) {
            const gw_chr_t *chr = &svc->chrs[j];
            h = s_fnv32((const uint8_t *)chr->uuid_str, strlen(chr->uuid_str), h);
            h = s_fnv32(&chr->properties, 1, h);
        }
    }
    return h;
}

/* ── JSON builder ────────────────────────────────────────────────── */
typedef struct { char *buf; size_t size; size_t pos; bool overflow; } jb_t;

static void jb_raw(jb_t *j, const char *s)
{
    size_t n = strlen(s);
    if (j->pos + n >= j->size) { j->overflow = true; return; }
    memcpy(j->buf + j->pos, s, n);
    j->pos += n;
}

static void jb_rawc(jb_t *j, char c)
{
    if (j->pos + 1 >= j->size) { j->overflow = true; return; }
    j->buf[j->pos++] = c;
}

static void jb_key(jb_t *j, const char *k)
{
    jb_rawc(j, '"'); jb_raw(j, k); jb_raw(j, "\": ");
}

static void jb_str(jb_t *j, const char *k, const char *v)
{
    jb_key(j, k);
    jb_rawc(j, '"');
    while (v && *v) {
        char c = *v++;
        if      (c == '"')  jb_raw(j, "\\\"");
        else if (c == '\\') jb_raw(j, "\\\\");
        else if (c >= 0x20) jb_rawc(j, c);
    }
    jb_rawc(j, '"');
}

static void jb_int(jb_t *j, const char *k, int v)
{
    char t[16]; snprintf(t, sizeof(t), "%d", v);
    jb_key(j, k); jb_raw(j, t);
}

static void jb_bool(jb_t *j, const char *k, bool v)
{
    jb_key(j, k); jb_raw(j, v ? "true" : "false");
}

static void jb_double(jb_t *j, const char *k, double v)
{
    char t[24]; snprintf(t, sizeof(t), "%.7f", v);
    jb_key(j, k); jb_raw(j, t);
}

static void jb_comma(jb_t *j) { jb_raw(j, ",\n"); }

static void jb_hex(jb_t *j, const char *k, const uint8_t *data, int len)
{
    jb_key(j, k); jb_rawc(j, '"');
    for (int i = 0; i < len; i++) {
        char t[3]; snprintf(t, sizeof(t), "%02X", data[i]);
        jb_raw(j, t);
    }
    jb_rawc(j, '"');
}

/* ── JSON serialiser ─────────────────────────────────────────────── */
#define GW_JSON_BUF  65536

static bool s_write_json(void)
{
    const gw_result_t *r = s_result;
    char *jbuf = heap_caps_malloc(GW_JSON_BUF, MALLOC_CAP_SPIRAM);
    if (!jbuf) { ESP_LOGE(TAG, "No PSRAM for JSON"); return false; }

    jb_t j = { .buf = jbuf, .size = GW_JSON_BUF, .pos = 0, .overflow = false };

    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
             r->mac[5], r->mac[4], r->mac[3],
             r->mac[2], r->mac[1], r->mac[0]);

    jb_raw(&j, "{\n");
    jb_int(&j, "version", 1);              jb_comma(&j);
    jb_str(&j, "timestamp", r->timestamp); jb_comma(&j);
    jb_str(&j, "mac", mac_str);            jb_comma(&j);
    jb_int(&j, "addr_type", r->addr_type); jb_comma(&j);
    jb_str(&j, "name", r->name);           jb_comma(&j);
    jb_int(&j, "rssi", r->rssi);           jb_comma(&j);

    jb_key(&j, "gps"); jb_raw(&j, "{ ");
    jb_bool(&j, "valid", r->gps_valid);
    if (r->gps_valid) {
        jb_comma(&j); jb_double(&j, "lat", r->lat);
        jb_comma(&j); jb_double(&j, "lon", r->lon);
    }
    jb_raw(&j, " }"); jb_comma(&j);

    char fp[12]; snprintf(fp, sizeof(fp), "0x%08X", r->fingerprint);
    jb_str(&j, "fingerprint", fp); jb_comma(&j);

    jb_key(&j, "services"); jb_raw(&j, "[\n");
    for (int i = 0; i < r->svc_count; i++) {
        const gw_svc_t *svc = &r->svcs[i];
        if (i > 0) jb_raw(&j, ",\n");
        jb_raw(&j, "  {\n  ");
        jb_str(&j, "uuid", svc->uuid_str);               jb_comma(&j);
        jb_raw(&j, "  ");
        jb_int(&j, "start_handle", svc->start_handle);   jb_comma(&j);
        jb_raw(&j, "  ");
        jb_int(&j, "end_handle",   svc->end_handle);     jb_comma(&j);
        jb_raw(&j, "  ");
        jb_key(&j, "characteristics"); jb_raw(&j, "[\n");

        for (int ci = 0; ci < svc->chr_count; ci++) {
            const gw_chr_t *chr = &svc->chrs[ci];
            if (ci > 0) jb_raw(&j, ",\n");
            jb_raw(&j, "    {\n    ");
            jb_str(&j, "uuid",       chr->uuid_str);  jb_comma(&j);
            jb_raw(&j, "    ");
            jb_int(&j, "def_handle", chr->def_handle); jb_comma(&j);
            jb_raw(&j, "    ");
            jb_int(&j, "val_handle", chr->val_handle); jb_comma(&j);
            jb_raw(&j, "    ");
            jb_int(&j, "properties", chr->properties); jb_comma(&j);
            jb_raw(&j, "    ");
            if (chr->read_ok && chr->read_len > 0)
                jb_hex(&j, "read_data", chr->read_data, chr->read_len);
            else {
                jb_key(&j, "read_data"); jb_raw(&j, "null");
            }

            if (chr->desc_count > 0) {
                jb_comma(&j); jb_raw(&j, "    ");
                jb_key(&j, "descriptors"); jb_raw(&j, "[");
                for (int di = 0; di < chr->desc_count; di++) {
                    if (di > 0) jb_raw(&j, ", ");
                    jb_raw(&j, "{ ");
                    jb_str(&j, "uuid", chr->descs[di].uuid_str);
                    jb_raw(&j, ", ");
                    jb_int(&j, "handle", chr->descs[di].handle);
                    jb_raw(&j, " }");
                }
                jb_rawc(&j, ']');
            }
            jb_raw(&j, "\n    }");
        }
        jb_raw(&j, "\n  ]\n  }");
    }
    jb_raw(&j, "\n]\n}\n");
    jb_rawc(&j, '\0');

    bool ok = false;
    if (j.overflow) ESP_LOGE(TAG, "JSON buffer overflow");

    if (s_sd_mutex && xSemaphoreTake(s_sd_mutex, pdMS_TO_TICKS(3000)) == pdTRUE) {
        mkdir("/sdcard/gattwalker", 0755);
        FILE *f = fopen(r->filepath, "w");
        if (f) {
            fwrite(jbuf, 1, j.pos > 0 ? j.pos - 1 : 0, f); /* -1: exclude null */
            fclose(f);
            ok = true;
            ESP_LOGI(TAG, "Saved %s (%zu B)", r->filepath, j.pos);
        } else {
            ESP_LOGE(TAG, "Cannot open %s", r->filepath);
        }
        xSemaphoreGive(s_sd_mutex);
    } else {
        ESP_LOGE(TAG, "SD mutex timeout");
    }
    free(jbuf);
    return ok;
}

/* ── Forward declarations ────────────────────────────────────────── */
static void s_disc_chrs_for_svc(int svc_idx);
static void s_disc_dscs_advance(void);
static void s_read_next(void);
static void s_finish(void);

/* ── Finish / save ───────────────────────────────────────────────── */

static void s_finish(void)
{
    s_result->fingerprint = s_compute_fingerprint();
    s_set_state(GW_STATE_SAVING);
    s_notify_ui("Saving results...");
    s_fire_event(GW_EVENT_READING); /* final reading-done event */

    bool saved = s_write_json();
    s_disconnect();

    if (saved) {
        s_fire_event(GW_EVENT_SAVED);
        s_notify_ui("Walk complete");
        s_set_state(GW_STATE_COMPLETE);
        s_fire_event(GW_EVENT_COMPLETE);
    } else {
        s_notify_ui("Save failed");
        s_set_state(GW_STATE_FAILED);
        s_fire_event(GW_EVENT_FAILED);
    }
}

/* ── Read phase ──────────────────────────────────────────────────── */

static int s_read_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                     struct ble_gatt_attr *attr, void *arg)
{
    if (s_cancel_req) { s_fail("Cancelled"); return 0; }

    gw_chr_t *chr = &s_result->svcs[s_cur_svc].chrs[s_cur_chr];

    if (error->status == 0 && attr && attr->om) {
        uint16_t len = OS_MBUF_PKTLEN(attr->om);
        if (len > GW_READ_MAX) len = GW_READ_MAX;
        os_mbuf_copydata(attr->om, 0, len, chr->read_data);
        chr->read_len = (uint8_t)len;
        chr->read_ok  = true;
    }

    s_cur_chr++;
    s_read_next();
    return 0;
}

static void s_read_next(void)
{
    while (s_cur_svc < s_result->svc_count) {
        gw_svc_t *svc = &s_result->svcs[s_cur_svc];
        while (s_cur_chr < svc->chr_count) {
            gw_chr_t *chr = &svc->chrs[s_cur_chr];
            if (chr->properties & 0x02 /* BLE_GATT_CHR_PROP_READ */) {
                char msg[48];
                snprintf(msg, sizeof(msg), "Reading chr %d svc %d/%d",
                         s_cur_chr + 1, s_cur_svc + 1, s_result->svc_count);
                s_notify_ui(msg);
                int rc = ble_gattc_read(s_conn_handle, chr->val_handle, s_read_cb, NULL);
                if (rc == 0) return;
                /* read failed to initiate — skip */
                ESP_LOGW(TAG, "ble_gattc_read rc=%d, skipping", rc);
            }
            s_cur_chr++;
        }
        s_cur_svc++;
        s_cur_chr = 0;
    }
    /* All reads attempted */
    s_finish();
}

/* ── Descriptor discovery phase ──────────────────────────────────── */

static int s_dsc_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                    uint16_t chr_val_handle, const struct ble_gatt_dsc *dsc, void *arg)
{
    if (s_cancel_req) { s_fail("Cancelled"); return 0; }

    if (error->status == BLE_HS_EDONE) {
        s_cur_chr++;
        s_disc_dscs_advance();
        return 0;
    }
    if (error->status != 0) {
        ESP_LOGW(TAG, "DSC error svc[%d] chr[%d]: %d", s_cur_svc, s_cur_chr, error->status);
        s_cur_chr++;
        s_disc_dscs_advance();
        return 0;
    }

    gw_chr_t *chr = &s_result->svcs[s_cur_svc].chrs[s_cur_chr];
    if (chr->desc_count < GW_MAX_DSCS) {
        chr->descs[chr->desc_count].handle = dsc->handle;
        ble_uuid_to_str(&dsc->uuid.u, chr->descs[chr->desc_count].uuid_str);
        chr->desc_count++;
    }
    return 0;
}

static void s_disc_dscs_advance(void)
{
    while (s_cur_svc < s_result->svc_count) {
        gw_svc_t *svc = &s_result->svcs[s_cur_svc];
        while (s_cur_chr < svc->chr_count) {
            gw_chr_t *chr = &svc->chrs[s_cur_chr];
            /* descriptor range: [val_handle+1 .. next_chr.def_handle-1 or svc.end_handle] */
            uint16_t dsc_start = chr->val_handle + 1;
            uint16_t dsc_end   = (s_cur_chr < svc->chr_count - 1)
                                 ? svc->chrs[s_cur_chr + 1].def_handle - 1
                                 : svc->end_handle;
            if (dsc_start <= dsc_end) {
                int rc = ble_gattc_disc_all_dscs(s_conn_handle, dsc_start, dsc_end,
                                                  s_dsc_cb, NULL);
                if (rc == 0) return;
                ESP_LOGW(TAG, "disc_all_dscs rc=%d, skipping", rc);
            }
            s_cur_chr++;
        }
        s_cur_svc++;
        s_cur_chr = 0;
    }
    /* All DSCs done → reading phase */
    s_cur_svc = 0;
    s_cur_chr = 0;
    s_set_state(GW_STATE_READING);
    s_notify_ui("Reading characteristics...");
    s_fire_event(GW_EVENT_READING);
    s_read_next();
}

/* ── Characteristic discovery phase ─────────────────────────────── */

static int s_chr_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                    const struct ble_gatt_chr *chr, void *arg)
{
    if (s_cancel_req) { s_fail("Cancelled"); return 0; }

    int svc_idx = (int)(intptr_t)arg;

    if (error->status == BLE_HS_EDONE) {
        s_disc_chrs_for_svc(svc_idx + 1);
        return 0;
    }
    if (error->status != 0) {
        ESP_LOGW(TAG, "Chr error svc[%d]: %d", svc_idx, error->status);
        s_disc_chrs_for_svc(svc_idx + 1);
        return 0;
    }

    gw_svc_t *svc = &s_result->svcs[svc_idx];
    if (svc->chr_count >= GW_MAX_CHRS) return 0;

    gw_chr_t *gc = &svc->chrs[svc->chr_count++];
    gc->def_handle = chr->def_handle;
    gc->val_handle = chr->val_handle;
    gc->properties = chr->properties;
    gc->read_ok    = false;
    gc->read_len   = 0;
    gc->desc_count = 0;
    ble_uuid_to_str(&chr->uuid.u, gc->uuid_str);

    gw_ui_chr_count++;
    gw_ui_needs_update = true;
    s_fire_event(GW_EVENT_CHR_FOUND);
    return 0;
}

static void s_disc_chrs_for_svc(int svc_idx)
{
    if (svc_idx >= s_result->svc_count) {
        /* All chr discovery complete → DSC phase */
        s_cur_svc = 0;
        s_cur_chr = 0;
        s_set_state(GW_STATE_DISC_DSCS);
        s_notify_ui("Discovering descriptors...");
        s_disc_dscs_advance();
        return;
    }

    s_cur_svc = svc_idx;
    char msg[48];
    snprintf(msg, sizeof(msg), "Chr discovery: svc %d/%d",
             svc_idx + 1, s_result->svc_count);
    s_notify_ui(msg);

    gw_svc_t *svc = &s_result->svcs[svc_idx];
    int rc = ble_gattc_disc_all_chrs(s_conn_handle, svc->start_handle, svc->end_handle,
                                      s_chr_cb, (void *)(intptr_t)svc_idx);
    if (rc != 0) {
        ESP_LOGW(TAG, "disc_all_chrs svc[%d] rc=%d, skipping", svc_idx, rc);
        s_disc_chrs_for_svc(svc_idx + 1);
    }
}

/* ── Service discovery phase ─────────────────────────────────────── */

static int s_svc_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                    const struct ble_gatt_svc *svc, void *arg)
{
    if (s_cancel_req) { s_fail("Cancelled"); return 0; }

    if (error->status == BLE_HS_EDONE) {
        ESP_LOGI(TAG, "Svc discovery done: %d services", s_result->svc_count);
        s_cur_svc = 0;
        s_cur_chr = 0;
        s_set_state(GW_STATE_DISC_CHRS);
        s_notify_ui("Discovering characteristics...");
        s_disc_chrs_for_svc(0);
        return 0;
    }
    if (error->status != 0) {
        char msg[32]; snprintf(msg, sizeof(msg), "Svc error: %d", error->status);
        s_fail(msg);
        return 0;
    }
    if (s_result->svc_count >= GW_MAX_SVCS) return 0;

    gw_svc_t *gs = &s_result->svcs[s_result->svc_count++];
    gs->start_handle = svc->start_handle;
    gs->end_handle   = svc->end_handle;
    gs->chr_count    = 0;
    ble_uuid_to_str(&svc->uuid.u, gs->uuid_str);

    gw_ui_svc_count = s_result->svc_count;
    gw_ui_needs_update = true;
    s_fire_event(GW_EVENT_SVC_FOUND);
    return 0;
}

/* ── GAP connection event ────────────────────────────────────────── */

static int s_gap_cb(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status != 0) {
            char msg[32];
            snprintf(msg, sizeof(msg), "Connect failed: %d", event->connect.status);
            s_fail(msg);
            return 0;
        }
        s_conn_handle = event->connect.conn_handle;
        ESP_LOGI(TAG, "Connected, handle=%d", s_conn_handle);
        s_set_state(GW_STATE_DISC_SVCS);
        s_notify_ui("Connected, discovering services...");
        s_fire_event(GW_EVENT_CONNECTED);
        s_result->svc_count = 0;
        gw_ui_svc_count = 0;
        gw_ui_chr_count = 0;
        ble_gattc_disc_all_svcs(s_conn_handle, s_svc_cb, NULL);
        return 0;

    case BLE_GAP_EVENT_DISCONNECT:
        ESP_LOGI(TAG, "Disconnected reason=%d state=%d",
                 event->disconnect.reason, (int)s_state);
        if (s_state != GW_STATE_COMPLETE &&
            s_state != GW_STATE_FAILED   &&
            s_state != GW_STATE_CANCELLED) {
            if (s_cancel_req)
                s_fail("Cancelled");
            else
                s_fail("Disconnected unexpectedly");
        }
        s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
        return 0;

    default:
        return 0;
    }
}

/* ── Timestamp helper ────────────────────────────────────────────── */

static void s_make_timestamp(char *out, size_t len)
{
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    if (tm_info && now > 1700000000) /* sanity check: post-2023 */ {
        strftime(out, len, "%Y%m%d_%H%M%S", tm_info);
    } else {
        /* RTC not set — use uptime in seconds */
        uint32_t secs = (uint32_t)(esp_timer_get_time() / 1000000ULL);
        snprintf(out, len, "00000000_%06u", secs % 1000000u);
    }
}

/* ── Public API ──────────────────────────────────────────────────── */

void gw_init(SemaphoreHandle_t sd_mutex)
{
    s_sd_mutex = sd_mutex;
    ESP_LOGI(TAG, "Initialised (sd_mutex=%s)", sd_mutex ? "yes" : "no");
}

void gw_set_callback(gw_event_cb_t cb) { s_callback = cb; }

gw_state_t gw_get_state(void) { return s_state; }

const gw_result_t *gw_get_result(void) { return s_result; }

bool gw_walk(const uint8_t mac[6], uint8_t addr_type, const char *name,
             int8_t rssi, double lat, double lon, bool gps_valid)
{
    if (s_state != GW_STATE_IDLE) {
        ESP_LOGW(TAG, "Walk already in progress (state=%d)", (int)s_state);
        return false;
    }

    /* Allocate result in PSRAM */
    if (!s_result) {
        s_result = heap_caps_malloc(sizeof(gw_result_t), MALLOC_CAP_SPIRAM);
        if (!s_result) {
            ESP_LOGE(TAG, "Cannot allocate result struct");
            return false;
        }
    }
    memset(s_result, 0, sizeof(gw_result_t));

    memcpy(s_result->mac, mac, 6);
    s_result->addr_type = addr_type;
    strncpy(s_result->name, name ? name : "", sizeof(s_result->name) - 1);
    s_result->rssi      = rssi;
    s_result->lat       = lat;
    s_result->lon       = lon;
    s_result->gps_valid = gps_valid;

    s_make_timestamp(s_result->timestamp, sizeof(s_result->timestamp));

    snprintf(s_result->filepath, sizeof(s_result->filepath),
             "/sdcard/gattwalker/%s_%02X%02X%02X%02X%02X%02X_gattwalk.json",
             s_result->timestamp,
             mac[5], mac[4], mac[3], mac[2], mac[1], mac[0]);

    s_cancel_req  = false;
    s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
    s_cur_svc     = 0;
    s_cur_chr     = 0;

    gw_ui_svc_count = 0;
    gw_ui_chr_count = 0;

    s_set_state(GW_STATE_CONNECTING);
    s_notify_ui("Connecting...");
    s_fire_event(GW_EVENT_STARTED);

    ble_addr_t peer = { .type = addr_type };
    memcpy(peer.val, mac, 6);

    int rc = ble_gap_connect(BLE_OWN_ADDR_PUBLIC, &peer,
                             30000 /* ms timeout */, NULL,
                             s_gap_cb, NULL);
    if (rc != 0) {
        char msg[32]; snprintf(msg, sizeof(msg), "Connect init fail: %d", rc);
        s_fail(msg);
        return false;
    }
    ESP_LOGI(TAG, "Walk started: %02X:%02X:%02X:%02X:%02X:%02X type=%d",
             mac[5], mac[4], mac[3], mac[2], mac[1], mac[0], addr_type);
    return true;
}

void gw_cancel(void)
{
    if (s_state == GW_STATE_IDLE    ||
        s_state == GW_STATE_COMPLETE ||
        s_state == GW_STATE_FAILED   ||
        s_state == GW_STATE_CANCELLED) return;

    s_cancel_req = true;
    ESP_LOGI(TAG, "Cancel requested");

    if (s_state == GW_STATE_CONNECTING) {
        ble_gap_conn_cancel();
    }
    /* Other states: cancel_req is checked at next callback entry */
}
