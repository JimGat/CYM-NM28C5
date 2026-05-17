#include "ble_honeypair.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"

#include "nimble/nimble_port.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "host/ble_uuid.h"
#include "host/ble_hs_adv.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"
#include "os/os_mbuf.h"

static const char *TAG = "HoneyPair";

// ── Persona table ─────────────────────────────────────────────────────────────

typedef struct {
    const char *name;
    const char *manufacturer;
    const char *model;
    uint8_t     battery_level;
    uint16_t    appearance;
} hp_persona_t;

static const hp_persona_t s_personas[] = {
    { "Wireless Keyboard",  "Microsoft", "Surface Keyboard",  85, 0x03C1 },
    { "AirPods Pro",        "Apple",     "A2698",             92, 0x0941 },
    { "Fitbit Inspire 3",   "Fitbit",    "FB422",             67, 0x0C40 },
    { "Galaxy Buds2 Pro",   "Samsung",   "SM-R510",           78, 0x0941 },
    { "Fenix 7",            "Garmin",    "010-02540-01",      55, 0x00C0 },
    { "Apple Watch",        "Apple",     "A2976",             41, 0x00C0 },
    { "JBL Clip 4",         "JBL",       "JBLCLIP4",          88, 0x0940 },
    { "Logitech MX Keys",   "Logitech",  "920-009294",        73, 0x03C1 },
    { "Samsung 40\" TV",   "Samsung Electronics", "UN40T5300",  0, 0x0180 },
};
#define HP_PERSONA_COUNT ((int)(sizeof(s_personas)/sizeof(s_personas[0])))

// ── Module state ──────────────────────────────────────────────────────────────

static SemaphoreHandle_t s_sd_mutex   = NULL;
static hp_gps_fn_t       s_gps_fn     = NULL;
static volatile bool     s_active     = false;
static volatile int      s_persona    = 0;
static volatile int      s_connects   = 0;
static volatile int      s_pairs      = 0;
static volatile int      s_reads      = 0;
static volatile int      s_disconnects = 0;
static uint16_t          s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
static char              s_log_path[72];

// ── GATT definitions ──────────────────────────────────────────────────────────

static uint16_t s_batt_lvl_handle;
static uint16_t s_hid_report_handle;

/* Standard keyboard HID report descriptor */
static const uint8_t s_hid_report_map[] = {
    0x05, 0x01,  /* Usage Page (Generic Desktop) */
    0x09, 0x06,  /* Usage (Keyboard) */
    0xA1, 0x01,  /* Collection (Application) */
    0x05, 0x07,  /*   Usage Page (Key Codes) */
    0x19, 0xE0,  /*   Usage Minimum (224) */
    0x29, 0xE7,  /*   Usage Maximum (231) */
    0x15, 0x00,  /*   Logical Minimum (0) */
    0x25, 0x01,  /*   Logical Maximum (1) */
    0x75, 0x01,  /*   Report Size (1) */
    0x95, 0x08,  /*   Report Count (8) */
    0x81, 0x02,  /*   Input (Data, Var, Abs) -- modifier keys */
    0x95, 0x01,  /*   Report Count (1) */
    0x75, 0x08,  /*   Report Size (8) */
    0x81, 0x01,  /*   Input (Const) -- reserved byte */
    0x95, 0x06,  /*   Report Count (6) */
    0x75, 0x08,  /*   Report Size (8) */
    0x15, 0x00,  /*   Logical Minimum (0) */
    0x25, 0x65,  /*   Logical Maximum (101) */
    0x05, 0x07,  /*   Usage Page (Key Codes) */
    0x19, 0x00,  /*   Usage Minimum (0) */
    0x29, 0x65,  /*   Usage Maximum (101) */
    0x81, 0x00,  /*   Input (Data, Array) -- key array */
    0xC0,        /* End Collection */
};

/* HID Information: bcdHID=1.11, country=0, flags=0x02 (normally connectable) */
static const uint8_t s_hid_info[]       = { 0x11, 0x01, 0x00, 0x02 };
/* Empty keyboard input report: modifier + reserved + 6 keycodes */
static const uint8_t s_hid_report[]     = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
/* Report Reference descriptor: report ID=0, type=Input(1) */
static const uint8_t s_report_ref[]     = { 0x00, 0x01 };
static       uint8_t s_protocol_mode    = 0x01; /* Report Protocol */

static int hp_chr_access_cb(uint16_t conn_handle, uint16_t attr_handle,
                             struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    (void)conn_handle; (void)attr_handle; (void)arg;
    if (ctxt->op != BLE_GATT_ACCESS_OP_READ_CHR) return 0;

    s_reads++;
    const hp_persona_t *p = &s_personas[s_persona];
    uint16_t uuid16 = ble_uuid_u16(ctxt->chr->uuid);

    if      (uuid16 == 0x2A19) os_mbuf_append(ctxt->om, &p->battery_level, 1);
    else if (uuid16 == 0x2A29) os_mbuf_append(ctxt->om, p->manufacturer, strlen(p->manufacturer));
    else if (uuid16 == 0x2A24) os_mbuf_append(ctxt->om, p->model, strlen(p->model));
    return 0;
}

static int hp_hid_access_cb(uint16_t conn_handle, uint16_t attr_handle,
                             struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    (void)conn_handle; (void)attr_handle; (void)arg;
    uint16_t uuid16 = ble_uuid_u16(ctxt->chr->uuid);

    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
        if      (uuid16 == 0x2A4A) os_mbuf_append(ctxt->om, s_hid_info, sizeof(s_hid_info));
        else if (uuid16 == 0x2A4B) os_mbuf_append(ctxt->om, s_hid_report_map, sizeof(s_hid_report_map));
        else if (uuid16 == 0x2A4D) os_mbuf_append(ctxt->om, s_hid_report, sizeof(s_hid_report));
        else if (uuid16 == 0x2A4E) os_mbuf_append(ctxt->om, &s_protocol_mode, 1);
    } else if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR) {
        if (uuid16 == 0x2A4E && OS_MBUF_PKTLEN(ctxt->om) == 1)
            os_mbuf_copydata(ctxt->om, 0, 1, &s_protocol_mode);
    }
    return 0;
}

static int hp_hid_dsc_access_cb(uint16_t conn_handle, uint16_t attr_handle,
                                 struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    (void)conn_handle; (void)attr_handle; (void)arg;
    os_mbuf_append(ctxt->om, s_report_ref, sizeof(s_report_ref));
    return 0;
}

static struct ble_gatt_dsc_def s_report_dscs[] = {
    {
        .uuid      = BLE_UUID16_DECLARE(0x2908), /* Report Reference */
        .att_flags = BLE_ATT_F_READ,
        .access_cb = hp_hid_dsc_access_cb,
    },
    { 0 }
};

static const struct ble_gatt_chr_def s_batt_chrs[] = {
    {
        .uuid       = BLE_UUID16_DECLARE(0x2A19),
        .access_cb  = hp_chr_access_cb,
        .val_handle = &s_batt_lvl_handle,
        .flags      = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY,
    },
    { 0 }
};

static const struct ble_gatt_chr_def s_dis_chrs[] = {
    {
        .uuid      = BLE_UUID16_DECLARE(0x2A29),
        .access_cb = hp_chr_access_cb,
        .flags     = BLE_GATT_CHR_F_READ,
    },
    {
        .uuid      = BLE_UUID16_DECLARE(0x2A24),
        .access_cb = hp_chr_access_cb,
        .flags     = BLE_GATT_CHR_F_READ,
    },
    { 0 }
};

static const struct ble_gatt_chr_def s_hid_chrs[] = {
    {   /* Protocol Mode */
        .uuid      = BLE_UUID16_DECLARE(0x2A4E),
        .access_cb = hp_hid_access_cb,
        .flags     = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE_NO_RSP,
    },
    {   /* Report Map */
        .uuid      = BLE_UUID16_DECLARE(0x2A4B),
        .access_cb = hp_hid_access_cb,
        .flags     = BLE_GATT_CHR_F_READ,
    },
    {   /* HID Information */
        .uuid      = BLE_UUID16_DECLARE(0x2A4A),
        .access_cb = hp_hid_access_cb,
        .flags     = BLE_GATT_CHR_F_READ,
    },
    {   /* HID Control Point */
        .uuid      = BLE_UUID16_DECLARE(0x2A4C),
        .access_cb = hp_hid_access_cb,
        .flags     = BLE_GATT_CHR_F_WRITE_NO_RSP,
    },
    {   /* Input Report */
        .uuid        = BLE_UUID16_DECLARE(0x2A4D),
        .access_cb   = hp_hid_access_cb,
        .val_handle  = &s_hid_report_handle,
        .flags       = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY,
        .descriptors = s_report_dscs,
    },
    { 0 }
};

static const struct ble_gatt_svc_def s_hp_svcs[] = {
    {
        .type            = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid            = BLE_UUID16_DECLARE(0x1812), /* HID Service */
        .characteristics = s_hid_chrs,
    },
    {
        .type            = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid            = BLE_UUID16_DECLARE(0x180F), /* Battery Service */
        .characteristics = s_batt_chrs,
    },
    {
        .type            = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid            = BLE_UUID16_DECLARE(0x180A), /* Device Information */
        .characteristics = s_dis_chrs,
    },
    { 0 }
};

// ── JSONL logging ─────────────────────────────────────────────────────────────

static void hp_log(const char *event, const char *addr, const char *extra_kv)
{
    if (!s_log_path[0] || !s_sd_mutex) return;

    const gps_data_t *gps = s_gps_fn ? s_gps_fn() : NULL;
    char ts[12] = "";
    if (gps && gps->time_utc[0])
        snprintf(ts, sizeof(ts), "%s", gps->time_utc);

    char line[256];
    int n = snprintf(line, sizeof(line),
                     "{\"ts\":\"%s\",\"event\":\"%s\",\"persona\":\"%s\"",
                     ts, event, s_personas[s_persona].name);
    if (addr && addr[0])
        n += snprintf(line + n, sizeof(line) - n, ",\"addr\":\"%s\"", addr);
    if (gps && gps->valid)
        n += snprintf(line + n, sizeof(line) - n, ",\"lat\":%.6f,\"lon\":%.6f",
                      (double)gps->latitude, (double)gps->longitude);
    if (extra_kv && extra_kv[0])
        n += snprintf(line + n, sizeof(line) - n, ",%s", extra_kv);
    snprintf(line + n, sizeof(line) - n, "}\n");

    if (xSemaphoreTake(s_sd_mutex, pdMS_TO_TICKS(400)) == pdTRUE) {
        FILE *f = fopen(s_log_path, "a");
        if (f) { fputs(line, f); fclose(f); }
        xSemaphoreGive(s_sd_mutex);
    }
}

static void hp_addr_str(const uint8_t *val, char *out18)
{
    snprintf(out18, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             val[5], val[4], val[3], val[2], val[1], val[0]);
}

static int hp_gap_cb(struct ble_gap_event *event, void *arg);

// ── Extended advertising helper ───────────────────────────────────────────────
// ble_gap_adv_start / ble_gap_adv_set_fields are compiled out when
// CONFIG_BT_NIMBLE_EXT_ADV=y.  Use the extended API with legacy_pdu=1
// so every phone (BT 4.0+) can see the advertisement.

#define HP_ADV_INSTANCE 0   /* only one ext-adv instance configured (MAX=1) */

static void hp_ext_adv_start(int persona_idx)
{
    static ble_uuid16_t s_hid_uuid = BLE_UUID16_INIT(0x1812);

    ESP_LOGI(TAG, "hp_ext_adv_start: persona=%d ('%s') synced=%d",
             persona_idx, s_personas[persona_idx].name, ble_hs_synced());

    /* Stop any running advertisement on our instance first */
    ble_gap_ext_adv_stop(HP_ADV_INSTANCE);

    ble_svc_gap_device_name_set(s_personas[persona_idx].name);
    ble_svc_gap_device_appearance_set(s_personas[persona_idx].appearance);

    /* Configure: legacy ADV_IND PDU (connectable+scannable) — BLE_HCI_LE_SET_EXT_ADV_PROP_LEGACY_IND=0x13.
     * Legacy PDUs require scannable=1 when connectable=1; omitting it yields props=0x11 which
     * is not a valid legacy PDU type and ble_gap_set_ext_adv_params() returns BLE_HS_EINVAL. */
    struct ble_gap_ext_adv_params p;
    memset(&p, 0, sizeof(p));
    p.connectable   = 1;
    p.scannable     = 1;
    p.legacy_pdu    = 1;
    p.own_addr_type = BLE_OWN_ADDR_PUBLIC;
    p.primary_phy   = BLE_HCI_LE_PHY_1M;
    p.secondary_phy = BLE_HCI_LE_PHY_1M;
    p.itvl_min      = BLE_GAP_ADV_ITVL_MS(200);
    p.itvl_max      = BLE_GAP_ADV_ITVL_MS(350);
    p.sid           = HP_ADV_INSTANCE;

    int rc = ble_gap_ext_adv_configure(HP_ADV_INSTANCE, &p, NULL, hp_gap_cb, NULL);
    ESP_LOGI(TAG, "ext_adv_configure: rc=%d", rc);
    if (rc != 0) { ESP_LOGE(TAG, "ext_adv_configure FAILED: %d", rc); return; }

    /* Build advertisement payload */
    struct ble_hs_adv_fields f;
    memset(&f, 0, sizeof(f));
    f.flags                 = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    f.uuids16               = &s_hid_uuid;
    f.num_uuids16           = 1;
    f.uuids16_is_complete   = 1;
    f.name                  = (const uint8_t *)s_personas[persona_idx].name;
    f.name_len              = (uint8_t)strlen(s_personas[persona_idx].name);
    f.name_is_complete      = 1;
    f.appearance            = s_personas[persona_idx].appearance;
    f.appearance_is_present = 1;

    struct os_mbuf *om = os_msys_get_pkthdr(BLE_HS_ADV_MAX_SZ, 0);
    if (!om) { ESP_LOGE(TAG, "ext_adv: no mbuf"); return; }

    rc = ble_hs_adv_set_fields_mbuf(&f, om);
    ESP_LOGI(TAG, "adv_set_fields_mbuf: rc=%d mbuf_len=%d", rc, OS_MBUF_PKTLEN(om));
    if (rc != 0) {
        ESP_LOGE(TAG, "adv_set_fields_mbuf FAILED: %d", rc);
        os_mbuf_free_chain(om);
        return;
    }

    rc = ble_gap_ext_adv_set_data(HP_ADV_INSTANCE, om);
    ESP_LOGI(TAG, "ext_adv_set_data: rc=%d", rc);
    if (rc != 0) { ESP_LOGE(TAG, "ext_adv_set_data FAILED: %d", rc); return; }

    rc = ble_gap_ext_adv_start(HP_ADV_INSTANCE, 0, 0);
    ESP_LOGI(TAG, "ext_adv_start: rc=%d", rc);
    if (rc == 0 || rc == BLE_HS_EALREADY) {
        uint8_t own_mac[6];
        uint8_t addr_type;
        if (ble_hs_id_infer_auto(0, &addr_type) == 0 &&
            ble_hs_id_copy_addr(addr_type, own_mac, NULL) == 0) {
            ESP_LOGI(TAG, "Advertising as '%s'  MAC %02X:%02X:%02X:%02X:%02X:%02X",
                     s_personas[persona_idx].name,
                     own_mac[5], own_mac[4], own_mac[3],
                     own_mac[2], own_mac[1], own_mac[0]);
        } else {
            ESP_LOGI(TAG, "Advertising as '%s'", s_personas[persona_idx].name);
        }
    } else {
        ESP_LOGE(TAG, "ext_adv_start: %d", rc);
    }
}

// ── GAP event callback ────────────────────────────────────────────────────────

static int hp_gap_cb(struct ble_gap_event *event, void *arg)
{
    (void)arg;
    char addr[18] = "";
    struct ble_gap_conn_desc desc;

    switch (event->type) {

    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status == 0) {
            s_conn_handle = event->connect.conn_handle;
            s_connects++;
            if (ble_gap_conn_find(s_conn_handle, &desc) == 0)
                hp_addr_str(desc.peer_ota_addr.val, addr);
            hp_log("connect", addr, NULL);
            ESP_LOGI(TAG, "Connected: %s", addr);
        }
        break;

    case BLE_GAP_EVENT_DISCONNECT:
        s_disconnects++;
        hp_addr_str(event->disconnect.conn.peer_ota_addr.val, addr);
        {
            char kv[32];
            snprintf(kv, sizeof(kv), "\"reason\":%d", event->disconnect.reason);
            hp_log("disconnect", addr, kv);
        }
        ESP_LOGI(TAG, "Disconnected: %s reason=%d", addr, event->disconnect.reason);
        s_conn_handle = BLE_HS_CONN_HANDLE_NONE;

        /* Re-advertise as same persona */
        if (s_active) hp_ext_adv_start(s_persona);
        break;

    case BLE_GAP_EVENT_ENC_CHANGE:
        s_pairs++;
        if (ble_gap_conn_find(event->enc_change.conn_handle, &desc) == 0)
            hp_addr_str(desc.peer_ota_addr.val, addr);
        {
            char kv[48];
            snprintf(kv, sizeof(kv), "\"enc_status\":%d,\"method\":\"Just Works\"",
                     event->enc_change.status);
            hp_log("pair", addr, kv);
        }
        ESP_LOGI(TAG, "Paired: %s status=%d", addr, event->enc_change.status);
        break;

    case BLE_GAP_EVENT_PASSKEY_ACTION:
        hp_log("passkey_request", NULL, "\"action\":\"display\"");
        break;

    case BLE_GAP_EVENT_SUBSCRIBE:
        hp_log("subscribe", NULL, NULL);
        break;

    default:
        break;
    }
    return 0;
}

// ── Public API ────────────────────────────────────────────────────────────────

void honeypair_register_services(void)
{
    ble_gatts_count_cfg(s_hp_svcs);
    ble_gatts_add_svcs(s_hp_svcs);
}

void honeypair_init(SemaphoreHandle_t sd_mutex, hp_gps_fn_t gps_fn)
{
    s_sd_mutex = sd_mutex;
    s_gps_fn   = gps_fn;
}

void honeypair_start(int persona_idx)
{
    if (persona_idx < 0 || persona_idx >= HP_PERSONA_COUNT) persona_idx = 0;
    s_persona = persona_idx;
    s_active  = true;

    /* Create log file on first start this session */
    if (!s_log_path[0]) {
        const char *dir = "/sdcard/lab/ble/honeypair";
        if (s_sd_mutex && xSemaphoreTake(s_sd_mutex, pdMS_TO_TICKS(500)) == pdTRUE) {
            mkdir("/sdcard/lab", 0755);
            mkdir("/sdcard/lab/ble", 0755);
            mkdir(dir, 0755);
            xSemaphoreGive(s_sd_mutex);
        }
        const gps_data_t *gps = s_gps_fn ? s_gps_fn() : NULL;
        char suffix[24];
        if (gps && gps->time_utc[0]) {
            snprintf(suffix, sizeof(suffix), "%s", gps->time_utc);
            for (int i = 0; suffix[i]; i++)
                if (suffix[i] == ':') suffix[i] = '-';
        } else {
            snprintf(suffix, sizeof(suffix), "%lu",
                     (unsigned long)(xTaskGetTickCount() / configTICK_RATE_HZ));
        }
        snprintf(s_log_path, sizeof(s_log_path), "%s/honeypair_%s.jsonl", dir, suffix);
        hp_log("start", NULL, NULL);
    } else {
        hp_log("persona_change", NULL, NULL);
    }

    hp_ext_adv_start(persona_idx);
}

void honeypair_stop(void)
{
    s_active = false;
    ble_gap_ext_adv_stop(HP_ADV_INSTANCE);
    if (s_conn_handle != BLE_HS_CONN_HANDLE_NONE) {
        ble_gap_terminate(s_conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
    }
    hp_log("stop", NULL, NULL);
    s_log_path[0] = '\0'; /* New log file on next session */
}

bool honeypair_is_active(void) { return s_active; }

void honeypair_get_stats(honeypair_stats_t *out)
{
    out->connects        = s_connects;
    out->pairs           = s_pairs;
    out->gatt_reads      = s_reads;
    out->disconnects     = s_disconnects;
    out->current_persona = s_persona;
    out->active          = s_active;
    strlcpy(out->persona_name, s_personas[s_persona].name, sizeof(out->persona_name));
    strlcpy(out->log_path, s_log_path, sizeof(out->log_path));
}

void honeypair_set_persona(int idx)
{
    if (idx < 0 || idx >= HP_PERSONA_COUNT) return;
    if (s_active)
        honeypair_start(idx);
    else
        s_persona = idx;
}

int         honeypair_persona_count(void) { return HP_PERSONA_COUNT; }
const char *honeypair_persona_name(int idx)
{
    if (idx < 0 || idx >= HP_PERSONA_COUNT) return "";
    return s_personas[idx].name;
}
