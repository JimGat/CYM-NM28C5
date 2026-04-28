#include "bt_lookout.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "esp_timer.h"
#include "esp_log.h"

static const char *TAG = "bt_lookout";

/* ── Alert timing ──────────────────────────────────────────────── */
#define FLASH_ON_US   250000LL          /* 250 ms LED on  */
#define FLASH_OFF_US  250000LL          /* 250 ms LED off → 0.5 s per blink */
#define FLASH_COUNT   3                 /* three flashes per alert */
#define COOLDOWN_US   (30LL * 1000000LL)/* 30 s per-device cooldown */

/* ── Internal state ────────────────────────────────────────────── */
typedef enum { ALERT_IDLE, ALERT_FLASH_ON, ALERT_FLASH_OFF } alert_state_t;

typedef struct { uint8_t mac[6]; int64_t last_us; } cooldown_slot_t;

static bt_lookout_entry_t s_entries[BT_LOOKOUT_MAX_ENTRIES];
static int                s_count        = 0;
static bool               s_active       = false;

static alert_state_t      s_state        = ALERT_IDLE;
static int                s_flash_count  = 0;
static int64_t            s_deadline_us  = 0;

static cooldown_slot_t    s_cooldown[BT_LOOKOUT_MAX_COOLDOWN];

static volatile bool      s_detection_pending = false;
static bt_lookout_detection_t s_detection;

/* ── Helpers ───────────────────────────────────────────────────── */

/* Ensure the directory containing csv_path exists (creates it if needed). */
static void ensure_parent_dir(const char *path)
{
    char dir[64];
    const char *slash = strrchr(path, '/');
    if (!slash || slash == path) return;
    size_t len = (size_t)(slash - path);
    if (len >= sizeof(dir)) return;
    memcpy(dir, path, len);
    dir[len] = '\0';
    mkdir(dir, 0755);   /* ignore error — EEXIST is fine */
}

static bool mac_eq(const uint8_t a[6], const uint8_t b[6])
{
    return memcmp(a, b, 6) == 0;
}

static bool mac_parse(const char *str, uint8_t out[6])
{
    return sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]) == 6;
}

static void mac_fmt(const uint8_t m[6], char *out, size_t len)
{
    snprintf(out, len, "%02X:%02X:%02X:%02X:%02X:%02X",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}

static bool is_in_cooldown(const uint8_t mac[6])
{
    int64_t now = esp_timer_get_time();
    for (int i = 0; i < BT_LOOKOUT_MAX_COOLDOWN; i++) {
        if (mac_eq(s_cooldown[i].mac, mac))
            return (now - s_cooldown[i].last_us) < COOLDOWN_US;
    }
    return false;
}

static void set_cooldown(const uint8_t mac[6])
{
    int64_t now = esp_timer_get_time();
    for (int i = 0; i < BT_LOOKOUT_MAX_COOLDOWN; i++) {
        if (mac_eq(s_cooldown[i].mac, mac)) { s_cooldown[i].last_us = now; return; }
    }
    /* evict oldest slot */
    int oldest = 0;
    for (int i = 1; i < BT_LOOKOUT_MAX_COOLDOWN; i++) {
        if (s_cooldown[i].last_us < s_cooldown[oldest].last_us) oldest = i;
    }
    memcpy(s_cooldown[oldest].mac, mac, 6);
    s_cooldown[oldest].last_us = now;
}

static void trigger_alert(const uint8_t mac[6], int rssi, const char *name)
{
    if (s_state != ALERT_IDLE) return;
    set_cooldown(mac);
    s_flash_count = 0;
    s_state       = ALERT_FLASH_ON;
    s_deadline_us = esp_timer_get_time() + FLASH_ON_US;

    /* fill detection snapshot — written before pending flag is raised */
    s_detection.valid = true;
    memcpy(s_detection.mac, mac, 6);
    strncpy(s_detection.name, name ? name : "Unknown", sizeof(s_detection.name) - 1);
    s_detection.name[sizeof(s_detection.name) - 1] = '\0';
    s_detection.rssi = rssi;
    s_detection_pending = true;          /* main-loop reads this last */
}

/* ── Public API ────────────────────────────────────────────────── */

void bt_lookout_start(void)
{
    s_active            = true;
    s_state             = ALERT_IDLE;
    s_detection_pending = false;
    ESP_LOGI(TAG, "Lookout started (%d entries)", s_count);
}

void bt_lookout_stop(void)
{
    s_active = false;
    s_state  = ALERT_IDLE;
    ESP_LOGI(TAG, "Lookout stopped");
}

bool bt_lookout_is_active(void) { return s_active; }

int bt_lookout_load(const char *csv_path)
{
    s_count = 0;
    ensure_parent_dir(csv_path);

    /* Use stat() to distinguish "file missing" from a transient read error.
     * Never overwrite an existing file just because fopen("r") failed. */
    struct stat st;
    bool file_exists = (stat(csv_path, &st) == 0);

    FILE *f = fopen(csv_path, "r");
    if (!f) {
        if (!file_exists) {
            /* File genuinely absent — seed with header only */
            f = fopen(csv_path, "w");
            if (!f) { ESP_LOGE(TAG, "Cannot create %s", csv_path); return -1; }
            fwrite(BT_LOOKOUT_CSV_HEADER, 1, strlen(BT_LOOKOUT_CSV_HEADER), f);
            fclose(f);
            ESP_LOGI(TAG, "Created empty watchlist: %s", csv_path);
        } else {
            ESP_LOGE(TAG, "Cannot read %s (exists but fopen failed)", csv_path);
        }
        return 0;
    }

    char line[96];
    bool first = true;
    while (fgets(line, sizeof(line), f) && s_count < BT_LOOKOUT_MAX_ENTRIES) {
        int len = (int)strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) line[--len] = '\0';
        if (len == 0) continue;
        if (first) { first = false; continue; }   /* skip header row */

        /* mac,name,rssi_threshold */
        char *tok = strtok(line, ",");
        if (!tok) continue;
        uint8_t mac[6];
        if (!mac_parse(tok, mac)) continue;

        tok = strtok(NULL, ",");
        const char *name = tok ? tok : "";

        tok = strtok(NULL, ",");
        int threshold = tok ? atoi(tok) : BT_LOOKOUT_RSSI_ANY;

        bt_lookout_entry_t *e = &s_entries[s_count++];
        memcpy(e->mac, mac, 6);
        strncpy(e->name, name, sizeof(e->name) - 1);
        e->name[sizeof(e->name) - 1] = '\0';
        e->rssi_threshold = threshold;
    }
    fclose(f);
    ESP_LOGI(TAG, "Loaded %d watchlist entries from %s", s_count, csv_path);
    return s_count;
}

bool bt_lookout_append(const char   *csv_path,
                       const uint8_t mac[6],
                       const char   *name,
                       int           rssi_threshold)
{
    /* update in-memory list */
    if (s_count < BT_LOOKOUT_MAX_ENTRIES) {
        bt_lookout_entry_t *e = &s_entries[s_count++];
        memcpy(e->mac, mac, 6);
        strncpy(e->name, name ? name : "", sizeof(e->name) - 1);
        e->name[sizeof(e->name) - 1] = '\0';
        e->rssi_threshold = rssi_threshold;
    }

    /* append row to CSV (create with header if absent) */
    ensure_parent_dir(csv_path);
    FILE *f = fopen(csv_path, "a");
    if (!f) {
        f = fopen(csv_path, "w");
        if (!f) return false;
        fwrite(BT_LOOKOUT_CSV_HEADER, 1, strlen(BT_LOOKOUT_CSV_HEADER), f);
        fclose(f);
        f = fopen(csv_path, "a");
        if (!f) return false;
    }
    char mac_str[18];
    mac_fmt(mac, mac_str, sizeof(mac_str));
    fprintf(f, "%s,%s,%d\n", mac_str, name ? name : "", rssi_threshold);
    fclose(f);
    ESP_LOGI(TAG, "Appended %s (%s) thr=%d to %s",
             mac_str, name ? name : "", rssi_threshold, csv_path);
    return true;
}

bool bt_lookout_on_adv(const uint8_t mac[6], int rssi, const char *adv_name)
{
    if (!s_active || s_count == 0) return false;

    for (int i = 0; i < s_count; i++) {
        const bt_lookout_entry_t *e = &s_entries[i];
        if (!mac_eq(e->mac, mac)) continue;
        /* RSSI check — BT_LOOKOUT_RSSI_ANY (-99) always passes */
        if (e->rssi_threshold != BT_LOOKOUT_RSSI_ANY && rssi < e->rssi_threshold)
            continue;
        if (is_in_cooldown(mac)) return false;
        /* pick best name: watchlist label > adv name > "Unknown" */
        const char *use_name = (e->name[0] != '\0') ? e->name :
                               (adv_name && adv_name[0]) ? adv_name : "Unknown";
        trigger_alert(mac, rssi, use_name);
        return true;
    }
    return false;
}

bool bt_lookout_tick(bt_lookout_led_fn_t led_fn)
{
    if (s_state == ALERT_IDLE) return false;

    int64_t now = esp_timer_get_time();

    if (now < s_deadline_us) {
        led_fn(s_state == ALERT_FLASH_ON ? 255 : 0, 0, 0);
        return true;
    }

    /* phase transition */
    if (s_state == ALERT_FLASH_ON) {
        s_flash_count++;
        if (s_flash_count >= FLASH_COUNT) {
            s_state = ALERT_IDLE;
            led_fn(0, 0, 0);
            return false;
        }
        s_state       = ALERT_FLASH_OFF;
        s_deadline_us = now + FLASH_OFF_US;
        led_fn(0, 0, 0);
    } else {
        s_state       = ALERT_FLASH_ON;
        s_deadline_us = now + FLASH_ON_US;
        led_fn(255, 0, 0);
    }
    return true;
}

int bt_lookout_count(void) { return s_count; }

const bt_lookout_entry_t *bt_lookout_get(int idx)
{
    if (idx < 0 || idx >= s_count) return NULL;
    return &s_entries[idx];
}

bool bt_lookout_poll_detection(bt_lookout_detection_t *out)
{
    if (!s_detection_pending) return false;
    s_detection_pending = false;
    if (out) *out = s_detection;
    return true;
}
