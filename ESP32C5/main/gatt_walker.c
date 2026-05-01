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
#include "oui_lookup.h"

static const char *TAG = "gatt_walker";

/* ── Volatile UI exports ─────────────────────────────────────────── */
volatile gw_state_t gw_ui_state        = GW_STATE_IDLE;
volatile int        gw_ui_svc_count    = 0;
volatile int        gw_ui_chr_count    = 0;
volatile char       gw_ui_status[96]   = "";
volatile bool       gw_ui_needs_update = false;

/* ── Internal state ──────────────────────────────────────────────── */
static uint32_t           s_connect_timeout_ms = 30000;
static SemaphoreHandle_t  s_sd_mutex    = NULL;
static gw_event_cb_t      s_callback    = NULL;
static gw_result_t       *s_result      = NULL;
static volatile gw_state_t s_state      = GW_STATE_IDLE;
static uint16_t           s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
static volatile bool      s_cancel_req  = false;

/* Sequential walk cursors (one GATT op in flight at a time) */
static int s_cur_svc = 0;
static int s_cur_chr = 0;

/* ── Probe phase state ───────────────────────────────────────────── */
static SemaphoreHandle_t  s_probe_conn_sem  = NULL;
static SemaphoreHandle_t  s_probe_write_sem = NULL;
static int                s_probe_conn_rc   = 0;
static int                s_probe_write_rc  = 0;
static volatile gw_chr_t *s_probe_cur_chr   = NULL;
static StackType_t       *s_probe_stack     = NULL;
static StaticTask_t       s_probe_tcb;

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

/* ── BLE error descriptions ──────────────────────────────────────── */

static const char *s_ble_error_desc(int rc)
{
    /* NimBLE host-layer errors */
    switch (rc) {
    case 2:  return "Already connecting";
    case 6:  return "Out of memory — restart device";
    case 7:  return "Not connected";
    case 13: return "No response — needs pairing or asleep";
    case 15: return "Radio busy — stop scan first";
    case 21: return "No local BLE address";
    case 22: return "BLE stack not ready — restart BT";
    }
    /* HCI controller errors: BLE_HS_ERR_HCI_BASE = 0x200 */
    if (rc >= 0x200 && rc < 0x300) {
        switch (rc - 0x200) {
        case 0x05: return "Auth failure — device requires bonding";
        case 0x06: return "PIN missing — device requires pairing";
        case 0x08: return "Connection timeout — out of range";
        case 0x12: return "LMP timeout — not responding";
        case 0x16: return "Terminated by local host";
        case 0x22: return "LL timeout — link layer lost";
        case 0x3B: return "Failed to establish connection";
        case 0x3E: return "Connection rejected by device";
        }
    }
    return "Unknown error";
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

/* ── Local UUID name table ───────────────────────────────────────── */
typedef struct { uint16_t uuid16; const char *name; } s_uuid_entry_t;
static const s_uuid_entry_t s_uuid_table[] = {
    /* Services */
    { 0x1800, "Generic Access"       }, { 0x1801, "Generic Attribute"    },
    { 0x180A, "Device Information"   }, { 0x180F, "Battery"              },
    { 0x1810, "Blood Pressure"       }, { 0x1812, "HID"                  },
    { 0x1816, "Cycling Speed"        }, { 0x1818, "Cycling Power"        },
    { 0x181A, "Environmental Sensing"}, { 0x181C, "User Data"            },
    { 0x1820, "Internet Protocol"    }, { 0x1823, "HTTP Proxy"           },
    { 0x183A, "Insulin Delivery"     }, { 0x183E, "Physical Activity"    },
    { 0x1803, "Link Loss"            }, { 0x1804, "TX Power"             },
    { 0x1805, "Current Time"         }, { 0x1806, "Reference Time"       },
    { 0x1807, "Next DST Change"      }, { 0x180D, "Heart Rate"           },
    { 0x180E, "Phone Alert"          }, { 0x1813, "Scan Parameters"      },
    /* Characteristics */
    { 0x2A00, "Device Name"          }, { 0x2A01, "Appearance"           },
    { 0x2A04, "Peripheral Pref Conn" }, { 0x2A05, "Service Changed"      },
    { 0x2A06, "Alert Level"          }, { 0x2A07, "TX Power Level"       },
    { 0x2A08, "Date Time"            }, { 0x2A19, "Battery Level"        },
    { 0x2A24, "Model Number"         }, { 0x2A25, "Serial Number"        },
    { 0x2A26, "Firmware Revision"    }, { 0x2A27, "Hardware Revision"    },
    { 0x2A28, "Software Revision"    }, { 0x2A29, "Manufacturer Name"    },
    { 0x2A2A, "IEEE 11073"           }, { 0x2A37, "Heart Rate Measurement"},
    { 0x2A38, "Body Sensor Location" }, { 0x2A39, "Heart Rate Control"   },
    { 0x2A3F, "Alert Status"         }, { 0x2A46, "New Alert"            },
    { 0x2A4D, "HID Report"           }, { 0x2A4E, "HID Protocol Mode"    },
    { 0x2A6E, "Temperature"          }, { 0x2A6F, "Humidity"             },
    { 0x2A6D, "Pressure"             }, { 0x2A76, "UV Index"             },
    { 0x2A9B, "Body Composition Feat"}, { 0x2AA6, "MAC Address"          },
    { 0x2B29, "Client Support Feat"  }, { 0x2B2A, "Database Hash"        },
    /* Descriptors */
    { 0x2900, "Ext Properties"       }, { 0x2901, "User Description"     },
    { 0x2902, "CCCD"                 }, { 0x2903, "SCCD"                 },
    { 0x2904, "Presentation Format"  }, { 0x2905, "Aggregate Format"     },
};

static const char *s_uuid_name(const char *uuid_str)
{
    if (!uuid_str) return NULL;
    unsigned u = 0;
    if (strncmp(uuid_str, "0x", 2) == 0 || strncmp(uuid_str, "0X", 2) == 0)
        sscanf(uuid_str + 2, "%x", &u);
    else
        return NULL;
    for (size_t i = 0; i < sizeof(s_uuid_table) / sizeof(s_uuid_table[0]); i++)
        if (s_uuid_table[i].uuid16 == (uint16_t)u)
            return s_uuid_table[i].name;
    return NULL;
}

/* Find CCCD handle (0x2902) in a characteristic's descriptor list. Returns 0 if absent. */
static uint16_t s_find_cccd(const gw_chr_t *chr)
{
    for (int i = 0; i < chr->desc_count; i++) {
        const char *u = chr->descs[i].uuid_str;
        unsigned v = 0;
        if (strncmp(u, "0x", 2) == 0) sscanf(u + 2, "%x", &v);
        if (v == 0x2902) return chr->descs[i].handle;
    }
    /* CCCD not in descriptor table — fall back to val_handle+1 (BLE spec standard placement) */
    if (chr->val_handle > 0)
        return chr->val_handle + 1;
    return 0;
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
#define GW_JSON_BUF  131072

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

    uint8_t oui3[3] = { r->mac[5], r->mac[4], r->mac[3] };
    const char *vendor = oui_lookup_is_loaded() ? oui_lookup(oui3) : NULL;

    jb_raw(&j, "{\n");
    jb_int(&j, "version", 1);              jb_comma(&j);
    jb_str(&j, "timestamp", r->timestamp); jb_comma(&j);
    jb_str(&j, "mac", mac_str);            jb_comma(&j);
    jb_int(&j, "addr_type", r->addr_type); jb_comma(&j);
    jb_str(&j, "name", r->name);           jb_comma(&j);
    jb_str(&j, "manufacturer", vendor ? vendor : ""); jb_comma(&j);
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
        const char *svc_name = s_uuid_name(svc->uuid_str);
        jb_str(&j, "name", svc_name ? svc_name : "");    jb_comma(&j);
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
            jb_str(&j, "uuid", chr->uuid_str);           jb_comma(&j);
            jb_raw(&j, "    ");
            const char *chr_name = s_uuid_name(chr->uuid_str);
            jb_str(&j, "name", chr_name ? chr_name : ""); jb_comma(&j);
            jb_raw(&j, "    ");
            jb_int(&j, "def_handle", chr->def_handle);   jb_comma(&j);
            jb_raw(&j, "    ");
            jb_int(&j, "val_handle", chr->val_handle);   jb_comma(&j);
            jb_raw(&j, "    ");
            jb_int(&j, "properties", chr->properties);   jb_comma(&j);
            jb_raw(&j, "    ");
            char pstr[24];
            gw_chr_props_str(chr->properties, pstr, sizeof(pstr));
            jb_str(&j, "props_str", pstr);               jb_comma(&j);
            jb_raw(&j, "    ");
            if (chr->read_ok && chr->read_len > 0) {
                jb_hex(&j, "read_data", chr->read_data, chr->read_len);
                jb_comma(&j); jb_raw(&j, "    ");
                jb_key(&j, "ascii"); jb_rawc(&j, '"');
                for (int bi = 0; bi < chr->read_len; bi++) {
                    uint8_t b = chr->read_data[bi];
                    if (b >= 0x20 && b < 0x7F) jb_rawc(&j, (char)b);
                    else jb_rawc(&j, '.');
                }
                jb_rawc(&j, '"');
            } else {
                jb_key(&j, "read_data"); jb_raw(&j, "null");
                jb_comma(&j); jb_raw(&j, "    ");
                jb_key(&j, "ascii"); jb_raw(&j, "null");
            }

            if (chr->desc_count > 0) {
                jb_comma(&j); jb_raw(&j, "    ");
                jb_key(&j, "descriptors"); jb_raw(&j, "[");
                for (int di = 0; di < chr->desc_count; di++) {
                    if (di > 0) jb_raw(&j, ", ");
                    jb_raw(&j, "{ ");
                    jb_str(&j, "uuid", chr->descs[di].uuid_str);
                    jb_raw(&j, ", ");
                    const char *dsc_name = s_uuid_name(chr->descs[di].uuid_str);
                    if (dsc_name) { jb_str(&j, "name", dsc_name); jb_raw(&j, ", "); }
                    jb_int(&j, "handle", chr->descs[di].handle);
                    jb_raw(&j, " }");
                }
                jb_rawc(&j, ']');
            }
            if (chr->probe_attempted) {
                jb_comma(&j); jb_raw(&j, "    ");
                jb_key(&j, "probe"); jb_raw(&j, "{\n      ");
                jb_bool(&j, "cccd_written", chr->probe_cccd_ok);
                jb_comma(&j); jb_raw(&j, "      ");
                jb_int(&j, "notify_count", chr->probe_frame_count);
                if (chr->probe_frame_count > 0) {
                    jb_comma(&j); jb_raw(&j, "      ");
                    jb_key(&j, "notify_data"); jb_raw(&j, "[");
                    for (int fi = 0; fi < chr->probe_frame_count; fi++) {
                        if (fi > 0) jb_raw(&j, ", ");
                        jb_rawc(&j, '"');
                        for (int bi = 0; bi < chr->probe_frame_lens[fi]; bi++) {
                            char hx[3];
                            snprintf(hx, sizeof(hx), "%02X", chr->probe_frames[fi][bi]);
                            jb_raw(&j, hx);
                        }
                        jb_rawc(&j, '"');
                    }
                    jb_rawc(&j, ']');
                }
                jb_raw(&j, "\n    }");
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
static int  s_mtu_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                     uint16_t mtu, void *arg);

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

/* read_long callback — called once per chunk, then once with BLE_HS_EDONE */
static int s_read_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                     struct ble_gatt_attr *attr, void *arg)
{
    if (s_cancel_req) { s_fail("Cancelled"); return 0; }

    gw_chr_t *chr = &s_result->svcs[s_cur_svc].chrs[s_cur_chr];

    if (error->status == 0 && attr && attr->om) {
        /* Accumulate this chunk into read_data */
        uint16_t chunk = OS_MBUF_PKTLEN(attr->om);
        uint16_t space = GW_READ_MAX - chr->read_len;
        if (chunk > space) chunk = space;
        if (chunk > 0) {
            os_mbuf_copydata(attr->om, 0, chunk, chr->read_data + chr->read_len);
            chr->read_len += chunk;
            chr->read_ok   = true;
        }
        return 0; /* wait for BLE_HS_EDONE */
    }

    /* BLE_HS_EDONE or read error — advance to next characteristic */
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
                int rc = ble_gattc_read_long(s_conn_handle, chr->val_handle, 0, s_read_cb, NULL);
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
        char msg[96]; snprintf(msg, sizeof(msg), "Svc error (%d)\n%s",
                               error->status, s_ble_error_desc(error->status));
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

/* ── MTU exchange callback — kicks off service discovery ─────────── */

static int s_mtu_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                    uint16_t mtu, void *arg)
{
    ESP_LOGI(TAG, "MTU exchange: %d bytes (rc=%d)", mtu, error->status);
    if (s_state != GW_STATE_DISC_SVCS) return 0;
    if (s_cancel_req) { s_fail("Cancelled"); return 0; }
    s_notify_ui("Connected, discovering services...");
    s_fire_event(GW_EVENT_CONNECTED);
    s_result->svc_count = 0;
    gw_ui_svc_count = 0;
    gw_ui_chr_count = 0;
    ble_gattc_disc_all_svcs(conn_handle, s_svc_cb, NULL);
    return 0;
}

/* ── GAP connection event ────────────────────────────────────────── */

static int s_gap_cb(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (s_state == GW_STATE_PROBING) {
            s_probe_conn_rc = event->connect.status;
            if (event->connect.status == 0)
                s_conn_handle = event->connect.conn_handle;
            xSemaphoreGive(s_probe_conn_sem);
            return 0;
        }
        if (event->connect.status != 0) {
            char msg[96];
            snprintf(msg, sizeof(msg), "Connect failed (%d)\n%s",
                     event->connect.status,
                     s_ble_error_desc(event->connect.status));
            s_fail(msg);
            return 0;
        }
        s_conn_handle = event->connect.conn_handle;
        ESP_LOGI(TAG, "Connected, handle=%d", s_conn_handle);
        s_set_state(GW_STATE_DISC_SVCS);
        s_notify_ui("Connected, MTU exchange...");
        /* Negotiate larger MTU before discovery so reads can return up to 511 bytes */
        ble_gattc_exchange_mtu(s_conn_handle, s_mtu_cb, NULL);
        return 0;

    case BLE_GAP_EVENT_DISCONNECT:
        if (s_state == GW_STATE_PROBING) {
            s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
            /* Unblock probe task if waiting on write semaphore */
            xSemaphoreGive(s_probe_write_sem);
            return 0;
        }
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

    case BLE_GAP_EVENT_NOTIFY_RX:
        if (s_state == GW_STATE_PROBING && s_probe_cur_chr) {
            gw_chr_t *chr = (gw_chr_t *)s_probe_cur_chr;
            if (chr->probe_frame_count < 8) {
                int fi = chr->probe_frame_count;
                uint16_t len = OS_MBUF_PKTLEN(event->notify_rx.om);
                if (len > 64) len = 64;
                os_mbuf_copydata(event->notify_rx.om, 0, len, chr->probe_frames[fi]);
                chr->probe_frame_lens[fi] = (uint8_t)len;
                chr->probe_frame_count++;
            }
        }
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
    if (!s_probe_conn_sem)  s_probe_conn_sem  = xSemaphoreCreateBinary();
    if (!s_probe_write_sem) s_probe_write_sem = xSemaphoreCreateBinary();
    ESP_LOGI(TAG, "Initialised (sd_mutex=%s)", sd_mutex ? "yes" : "no");
}

void gw_set_callback(gw_event_cb_t cb) { s_callback = cb; }

void gw_set_timeout(uint32_t ms) { s_connect_timeout_ms = (ms < 1000) ? 1000 : ms; }

gw_state_t gw_get_state(void) { return s_state; }

const gw_result_t *gw_get_result(void) { return s_result; }

bool gw_walk(const uint8_t mac[6], uint8_t addr_type, const char *name,
             int8_t rssi, double lat, double lon, bool gps_valid)
{
    /* Allow restart from any terminal state */
    if (s_state == GW_STATE_COMPLETE  ||
        s_state == GW_STATE_PROBE_DONE ||
        s_state == GW_STATE_FAILED    ||
        s_state == GW_STATE_CANCELLED) {
        s_state     = GW_STATE_IDLE;
        gw_ui_state = GW_STATE_IDLE;
    }
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

    /* Request 512-byte ATT MTU so reads can return full BLE attribute payloads */
    ble_att_set_preferred_mtu(512);

    ble_addr_t peer = { .type = addr_type };
    memcpy(peer.val, mac, 6);

    int rc = ble_gap_connect(BLE_OWN_ADDR_PUBLIC, &peer,
                             (int32_t)s_connect_timeout_ms, NULL,
                             s_gap_cb, NULL);
    if (rc != 0) {
        char msg[96]; snprintf(msg, sizeof(msg), "Init failed (%d)\n%s",
                               rc, s_ble_error_desc(rc));
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

/* ── Probe write callback ────────────────────────────────────────── */

static int s_probe_write_cb(uint16_t ch, const struct ble_gatt_error *err,
                             struct ble_gatt_attr *attr, void *arg)
{
    (void)ch; (void)attr; (void)arg;
    s_probe_write_rc = err->status;
    xSemaphoreGive(s_probe_write_sem);
    return 0;
}

/* ── Probe task ──────────────────────────────────────────────────── */

static void s_probe_task(void *arg)
{
    uint32_t dwell_ms = (uint32_t)(uintptr_t)arg;
    s_notify_ui("Probe: reconnecting...");

    ble_att_set_preferred_mtu(512);
    ble_addr_t peer = { .type = s_result->addr_type };
    memcpy(peer.val, s_result->mac, 6);

    int rc = ble_gap_connect(BLE_OWN_ADDR_PUBLIC, &peer, 10000, NULL, s_gap_cb, NULL);
    if (rc != 0) {
        s_notify_ui("Probe: connect init failed");
        goto probe_done;
    }

    /* Wait for connection result */
    if (xSemaphoreTake(s_probe_conn_sem, pdMS_TO_TICKS(12000)) != pdTRUE
        || s_probe_conn_rc != 0) {
        s_notify_ui("Probe: connect failed");
        goto probe_done;
    }

    s_notify_ui("Probe: connected, subscribing...");

    for (int si = 0; si < s_result->svc_count; si++) {
        gw_svc_t *svc = &s_result->svcs[si];
        for (int ci = 0; ci < svc->chr_count; ci++) {
            if (s_conn_handle == BLE_HS_CONN_HANDLE_NONE) goto disconnected;

            gw_chr_t *chr = &svc->chrs[ci];
            if (!(chr->properties & (0x10 | 0x20))) continue; /* not N or I */

            uint16_t cccd = s_find_cccd(chr);
            if (!cccd) continue;

            chr->probe_attempted = true;

            char msg[64];
            snprintf(msg, sizeof(msg), "Probe: %.20s", chr->uuid_str);
            s_notify_ui(msg);

            /* Write CCCD enable — 0x0001 for Notify, 0x0002 for Indicate */
            uint16_t enable = (chr->properties & 0x10) ? 0x0001 : 0x0002;
            s_probe_cur_chr = chr;
            xSemaphoreTake(s_probe_write_sem, 0); /* drain */
            rc = ble_gattc_write_flat(s_conn_handle, cccd,
                                       &enable, sizeof(enable), s_probe_write_cb, NULL);
            if (rc == 0) {
                xSemaphoreTake(s_probe_write_sem, pdMS_TO_TICKS(2000));
                if (s_probe_write_rc == 0) {
                    chr->probe_cccd_ok = true;
                    vTaskDelay(pdMS_TO_TICKS(dwell_ms)); /* collect frames */
                }
            }

            /* Unsubscribe */
            s_probe_cur_chr = NULL;
            uint16_t disable = 0x0000;
            if (s_conn_handle != BLE_HS_CONN_HANDLE_NONE) {
                xSemaphoreTake(s_probe_write_sem, 0);
                ble_gattc_write_flat(s_conn_handle, cccd,
                                     &disable, sizeof(disable), s_probe_write_cb, NULL);
                xSemaphoreTake(s_probe_write_sem, pdMS_TO_TICKS(1000));
            }
        }
    }

disconnected:
    s_probe_cur_chr = NULL;
    s_disconnect();

probe_done:
    s_result->probe_done = true;
    s_write_json();           /* re-save with probe data */
    s_set_state(GW_STATE_PROBE_DONE);
    s_notify_ui("Probe complete");
    s_fire_event(GW_EVENT_PROBE_DONE);
    vTaskDelete(NULL);
}

/* ── Public probe API ────────────────────────────────────────────── */

bool gw_probe_start(uint32_t dwell_ms)
{
    if (!s_result || !s_probe_conn_sem || !s_probe_write_sem) return false;
    gw_state_t st = gw_get_state();
    if (st != GW_STATE_COMPLETE && st != GW_STATE_PROBE_DONE) return false;

    /* Reset probe fields on every chr so a re-probe starts fresh */
    for (int si = 0; si < s_result->svc_count; si++) {
        gw_svc_t *svc = &s_result->svcs[si];
        for (int ci = 0; ci < svc->chr_count; ci++) {
            gw_chr_t *chr = &svc->chrs[ci];
            chr->probe_attempted   = false;
            chr->probe_cccd_ok     = false;
            chr->probe_frame_count = 0;
            memset(chr->probe_frame_lens, 0, sizeof(chr->probe_frame_lens));
        }
    }
    s_result->probe_done = false;

    if (s_probe_stack) {
        heap_caps_free(s_probe_stack);
        s_probe_stack = NULL;
    }

    s_probe_stack = heap_caps_malloc(4096 * sizeof(StackType_t), MALLOC_CAP_SPIRAM);
    if (!s_probe_stack) return false;

    s_set_state(GW_STATE_PROBING);
    s_fire_event(GW_EVENT_PROBE_STARTED);

    TaskHandle_t h = xTaskCreateStatic(s_probe_task, "gw_probe", 4096,
                                        (void *)(uintptr_t)dwell_ms, 5,
                                        s_probe_stack, &s_probe_tcb);
    if (!h) {
        heap_caps_free(s_probe_stack);
        s_probe_stack = NULL;
        s_set_state(GW_STATE_COMPLETE);
        return false;
    }
    return true;
}

void gw_probe_free_stack(void)
{
    if (s_probe_stack) {
        heap_caps_free(s_probe_stack);
        s_probe_stack = NULL;
    }
}

char *gw_chr_props_str(uint8_t p, char *buf, size_t bufsz)
{
    /* BLE_GATT_CHR_PROP_* bits: Broadcast=0x01 Read=0x02 WriteNoRsp=0x04
       Write=0x08 Notify=0x10 Indicate=0x20 AuthSign=0x40 ExtProp=0x80 */
    snprintf(buf, bufsz, "%s%s%s%s%s%s%s%s",
             (p & 0x02) ? "R "  : "",
             (p & 0x08) ? "W "  : "",
             (p & 0x04) ? "WNR ": "",
             (p & 0x10) ? "N "  : "",
             (p & 0x20) ? "I "  : "",
             (p & 0x01) ? "BC " : "",
             (p & 0x40) ? "AS " : "",
             (p & 0x80) ? "EX " : "");
    /* trim trailing space */
    size_t len = strlen(buf);
    while (len > 0 && buf[len-1] == ' ') buf[--len] = '\0';
    if (len == 0) snprintf(buf, bufsz, "0x%02X", p);
    return buf;
}
